//! REQ: OPS-014, API-014 (ADR-167 §3) — the node's secrets key. One 32-byte key per node,
//! written `ttsk1:<base64url>`, from the first of:
//! 1. `TELLTALE_SECRETS_KEY`;
//! 2. `[node] secrets_key_file` (`TELLTALE_NODE_SECRETS_KEY_FILE`);
//! 3. `<data_dir>/secrets.key`, created (0600, never over an existing file) on first start.
//!
//! The previous key, during a rotation, comes from `TELLTALE_SECRETS_PREVIOUS_KEY` or
//! `[node] secrets_previous_key_file`. Purposes get their own subkeys (BLAKE3 `derive_key`): the
//! encrypted store (T23.3) and the keyed hashes `Idempotency-Key` records keep (T23.1). A
//! configured source that can't be read or parsed leaves the node without a key ("locked"):
//! nothing is generated in its place, and DNS is unaffected (02 §8).

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine as _;
use telltale_config::Config;

/// The data-directory key's file name.
pub(crate) const KEY_FILE: &str = "secrets.key";
/// The text form's prefix (the format's version).
const PREFIX: &str = "ttsk1:";
/// `TELLTALE_SECRETS_KEY` and `TELLTALE_SECRETS_PREVIOUS_KEY`.
pub(crate) const KEY_VAR: &str = "TELLTALE_SECRETS_KEY";
pub(crate) const PREVIOUS_KEY_VAR: &str = "TELLTALE_SECRETS_PREVIOUS_KEY";
/// Subkey contexts (ADR-167 §3).
const KEY_ID_CONTEXT: &str = "telltale secrets key-id v1";
const IDEMPOTENCY_CONTEXT: &str = "telltale secrets idempotency v1";

/// Where a key came from (shown in status, never the key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeySource {
    /// `TELLTALE_SECRETS_KEY` (or the previous-key variable).
    Env,
    /// `[node] secrets_key_file` (or `secrets_previous_key_file`).
    File(PathBuf),
    /// `<data_dir>/secrets.key`.
    DataDir(PathBuf),
}

impl fmt::Display for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env => f.write_str("the environment"),
            Self::File(p) | Self::DataDir(p) => write!(f, "{}", p.display()),
        }
    }
}

/// One node key. Its `Debug` never shows the bytes.
pub(crate) struct NodeKey {
    key: [u8; 32],
    source: KeySource,
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeKey")
            .field("key", &"<redacted>")
            .field("key_id", &hex(&self.key_id()))
            .field("source", &self.source)
            .finish()
    }
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

impl NodeKey {
    /// Parses the text form (`ttsk1:<base64url, no padding>`, surrounding space ignored).
    pub(crate) fn parse(text: &str, source: KeySource) -> Result<Self, String> {
        let body = text.trim().strip_prefix(PREFIX).ok_or_else(|| {
            format!("{source}: not a TelltaleDNS secrets key (expected `{PREFIX}...`)")
        })?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| format!("{source}: the key isn't base64url"))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("{source}: the key isn't 32 bytes"))?;
        Ok(Self { key, source })
    }

    /// A new random key's text form.
    pub(crate) fn generate() -> Result<String, String> {
        use ring::rand::SecureRandom as _;
        let mut key = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| "no randomness for a new secrets key".to_owned())?;
        Ok(format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key)
        ))
    }

    /// The first 8 bytes of the key-id subkey: names the key in rows and status, safely.
    pub(crate) fn key_id(&self) -> [u8; 8] {
        let d = blake3::derive_key(KEY_ID_CONTEXT, &self.key);
        let mut id = [0u8; 8];
        id.copy_from_slice(&d[..8]);
        id
    }

    /// A purpose's subkey.
    pub(crate) fn subkey(&self, context: &str) -> [u8; 32] {
        blake3::derive_key(context, &self.key)
    }

    pub(crate) fn source(&self) -> &KeySource {
        &self.source
    }

    /// REQ: API-014 (ADR-167 §4, AGT-003) — what an `Idempotency-Key` record keeps of a
    /// request: the hex keyed BLAKE3 of its canonical text under the idempotency subkey.
    pub(crate) fn idempotency_digest(&self, request: &[u8]) -> String {
        blake3::keyed_hash(&self.subkey(IDEMPOTENCY_CONTEXT), request)
            .to_hex()
            .to_string()
    }
}

/// The node's keys: the current one, and the previous one during a rotation.
#[derive(Debug)]
pub(crate) struct Keys {
    pub(crate) current: NodeKey,
    pub(crate) previous: Option<NodeKey>,
    /// Warnings found on the way (a key file others can read).
    pub(crate) warnings: Vec<String>,
}

/// Reads a key file, with a warning when others can read or change it (group read is fine:
/// Kubernetes `fsGroup` mounts give it).
fn read_key_file(
    path: &Path,
    source: KeySource,
    warnings: &mut Vec<String>,
) -> Result<NodeKey, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    if let Ok(meta) = std::fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode();
        if mode & 0o027 != 0 {
            warnings.push(format!(
                "{}: other users can read or change the secrets key (mode {:o}); make it 0600 or 0640",
                path.display(),
                mode & 0o777
            ));
        }
    }
    NodeKey::parse(&text, source)
}

/// Creates `path` with a new key, never partly written and never over an existing file: the key
/// goes to `<path>.tmp` (`O_CREAT|O_EXCL`, 0600), is synced, then hard-linked to `path` (which
/// fails if `path` exists: a race with another start reads that one instead), and the directory
/// is synced. A crash leaves at most the temporary file, which the next start replaces.
fn create_key_file(path: &Path) -> Result<(), String> {
    use std::io::Write as _;
    let err = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    let text = NodeKey::generate()?;
    let tmp = path.with_extension("key.tmp");
    if let Err(e) = std::fs::remove_file(&tmp)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(err(&tmp, e));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).map_err(|e| err(&tmp, e))?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.write_all(b"\n"))
        .and_then(|()| f.sync_all())
        .map_err(|e| err(&tmp, e))?;
    drop(f);
    let linked = match std::fs::hard_link(&tmp, path) {
        // A filesystem without hard links: rename, still never over an existing key.
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists && !path.exists() => {
            std::fs::rename(&tmp, path).map_err(|e| err(path, e))
        }
        // Linked, or a key is there already (another start's): that one is read.
        _ => Ok(()),
    };
    let _ = std::fs::remove_file(&tmp);
    linked?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| err(dir, e))?;
    }
    Ok(())
}

/// REQ: OPS-014 (ADR-167 §3) — the node's keys from `cfg` and the environment (`var`). `create`:
/// make the data-directory key when no other source is set and it doesn't exist (never on an
/// ephemeral resolver pod, which holds no secrets).
pub(crate) fn load(
    cfg: &Config,
    var: &dyn Fn(&str) -> Option<String>,
    create: bool,
) -> Result<Keys, String> {
    let mut warnings = Vec::new();
    let current = if let Some(text) = var(KEY_VAR).filter(|t| !t.trim().is_empty()) {
        NodeKey::parse(&text, KeySource::Env)?
    } else if !cfg.node.secrets_key_file.is_empty() {
        let p = PathBuf::from(cfg.node.secrets_key_file.as_str());
        read_key_file(&p, KeySource::File(p.clone()), &mut warnings)?
    } else {
        let p = Path::new(cfg.node.data_dir.as_str()).join(KEY_FILE);
        if !p.exists() {
            if !create {
                return Err(format!(
                    "{}: no secrets key on this node (set {KEY_VAR} or [node] secrets_key_file)",
                    p.display()
                ));
            }
            create_key_file(&p)?;
        }
        read_key_file(&p, KeySource::DataDir(p.clone()), &mut warnings)?
    };
    let previous = if let Some(text) = var(PREVIOUS_KEY_VAR).filter(|t| !t.trim().is_empty()) {
        Some(NodeKey::parse(&text, KeySource::Env)?)
    } else if !cfg.node.secrets_previous_key_file.is_empty() {
        let p = PathBuf::from(cfg.node.secrets_previous_key_file.as_str());
        Some(read_key_file(
            &p,
            KeySource::File(p.clone()),
            &mut warnings,
        )?)
    } else {
        None
    };
    Ok(Keys {
        current,
        previous,
        warnings,
    })
}

/// How long a failed load is kept before the next use tries again.
const RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

/// The keys, loaded on first use (`Sources::secrets_key`) and kept for the process; a failure is
/// kept only for [`RETRY_AFTER`], so a key mounted (or a `[node] secrets_key_file` set) after
/// the start is picked up without a restart.
#[derive(Debug, Default)]
pub(crate) struct KeySlot(Mutex<Option<Loaded>>);

#[derive(Debug)]
enum Loaded {
    Ok(Arc<Keys>),
    Failed(String, std::time::Instant),
}

impl KeySlot {
    /// The keys, or why there are none (the store is locked: T23.3).
    pub(crate) fn get(&self, cfg: &Config) -> Result<Arc<Keys>, String> {
        let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        match &*slot {
            Some(Loaded::Ok(k)) => return Ok(Arc::clone(k)),
            Some(Loaded::Failed(e, at)) if at.elapsed() < RETRY_AFTER => return Err(e.clone()),
            _ => {}
        }
        let r = load(cfg, &|k| std::env::var(k).ok(), !cfg.cluster.ephemeral);
        let (out, logged) = match r {
            Ok(k) => {
                for w in &k.warnings {
                    tracing::warn!("{w}");
                }
                tracing::info!(
                    source = %k.current.source(),
                    key_id = %hex(&k.current.key_id()),
                    previous = ?k.previous.as_ref().map(|p| hex(&p.key_id())),
                    "secrets key loaded"
                );
                let k = Arc::new(k);
                (Ok(Arc::clone(&k)), Loaded::Ok(k))
            }
            Err(e) => {
                // Logged when the reason first shows or changes, not at every retry.
                let again = matches!(&*slot, Some(Loaded::Failed(prev, _)) if *prev == e);
                if !again {
                    if cfg.cluster.ephemeral {
                        tracing::debug!("no secrets key on this resolver pod: {e}");
                    } else {
                        tracing::error!("no secrets key: {e}");
                    }
                }
                (Err(e.clone()), Loaded::Failed(e, std::time::Instant::now()))
            }
        };
        *slot = Some(logged);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &Path) -> Config {
        let mut c = Config::default();
        c.node.data_dir = telltale_config::SafeString::new(dir.to_str().unwrap()).unwrap();
        c
    }

    /// REQ: OPS-014 (ADR-167 §3) — the first start makes `secrets.key` (0600), the next start
    /// reads the same key; the variable, then `[node] secrets_key_file`, win over it; a
    /// configured source that's unreadable is an error, never a new key.
    #[test]
    #[allow(clippy::many_single_char_names)] // one load per source
    fn ops_014_node_key_sources_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let c = cfg(tmp.path());
        let none = |_: &str| None;
        let a = load(&c, &none, true).unwrap();
        let file = tmp.path().join(KEY_FILE);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(matches!(a.current.source(), KeySource::DataDir(_)));
        let b = load(&c, &none, true).unwrap();
        assert_eq!(a.current.key_id(), b.current.key_id(), "the same key again");
        assert!(a.warnings.is_empty(), "{:?}", a.warnings);

        let env_key = NodeKey::generate().unwrap();
        let from_env = |k: &str| (k == KEY_VAR).then(|| env_key.clone());
        let e = load(&c, &from_env, true).unwrap();
        assert_eq!(*e.current.source(), KeySource::Env);
        assert_ne!(e.current.key_id(), a.current.key_id());

        let mut with_file = c.clone();
        let kf = tmp.path().join("mounted.key");
        std::fs::write(&kf, NodeKey::generate().unwrap()).unwrap();
        with_file.node.secrets_key_file =
            telltale_config::SafeString::new(kf.to_str().unwrap()).unwrap();
        let f = load(&with_file, &none, true).unwrap();
        assert!(matches!(f.current.source(), KeySource::File(_)));
        assert_eq!(
            load(&with_file, &from_env, true).unwrap().current.key_id(),
            e.current.key_id(),
            "the variable wins over the file"
        );

        std::fs::write(&kf, "not a key").unwrap();
        assert!(load(&with_file, &none, true).is_err(), "unreadable: no key");
        let empty = tempfile::tempdir().unwrap();
        assert!(
            load(&cfg(empty.path()), &none, false).is_err(),
            "pods make none"
        );
        assert!(!empty.path().join(KEY_FILE).exists());
    }

    /// REQ: OPS-014 — the key file is made whole or not at all (a leftover temporary file from
    /// a crash is replaced; an existing key is never replaced), and a failed load is retried.
    #[test]
    fn ops_014_key_file_made_whole_and_failures_retried() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join(KEY_FILE);
        std::fs::write(tmp.path().join("secrets.key.tmp"), "ttsk1:trunc").unwrap();
        create_key_file(&file).unwrap();
        assert!(!tmp.path().join("secrets.key.tmp").exists());
        let first = std::fs::read_to_string(&file).unwrap();
        NodeKey::parse(&first, KeySource::DataDir(file.clone())).unwrap();
        create_key_file(&file).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            first,
            "never replaced"
        );

        // A configured key file that isn't there yet: an error, kept for a while, not for good.
        let mut c = cfg(tmp.path());
        let later = tmp.path().join("mounted.key");
        c.node.secrets_key_file =
            telltale_config::SafeString::new(later.to_str().unwrap()).unwrap();
        let slot = KeySlot::default();
        assert!(slot.get(&c).is_err());
        std::fs::write(&later, NodeKey::generate().unwrap()).unwrap();
        assert!(slot.get(&c).is_err(), "within the retry interval");
        if let Some(Loaded::Failed(_, at)) = &mut *slot.0.lock().unwrap() {
            *at = std::time::Instant::now().checked_sub(RETRY_AFTER).unwrap();
        }
        assert!(slot.get(&c).is_ok(), "picked up after the interval");
    }

    /// REQ: API-014 — the idempotency digest is keyed (another node's key gives another digest),
    /// and a key's `Debug` shows its ID, never its bytes.
    #[test]
    fn api_014_idempotency_digest_is_keyed() {
        let a = NodeKey::parse(&NodeKey::generate().unwrap(), KeySource::Env).unwrap();
        let b = NodeKey::parse(&NodeKey::generate().unwrap(), KeySource::Env).unwrap();
        let req = b"PUT /upstreams/x {\"headers\":{\"Authorization\":\"Bearer s3cret\"}}";
        assert_eq!(a.idempotency_digest(req), a.idempotency_digest(req));
        assert_ne!(a.idempotency_digest(req), b.idempotency_digest(req));
        assert_ne!(
            a.idempotency_digest(req),
            blake3::hash(req).to_hex().to_string()
        );
        let text = format!("{a:?}");
        assert!(text.contains("<redacted>"), "{text}");
        assert!(!text.contains(&format!("{:?}", a.key)), "{text}");
        assert_ne!(
            a.subkey("telltale secrets aead v1"),
            a.subkey(IDEMPOTENCY_CONTEXT)
        );
    }
}

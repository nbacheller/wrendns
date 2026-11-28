//! REQ: OPS-014, API-014 (ADR-903 §2–3) — secrets entered in the UI, and the node key that
//! encrypts them. One 32-byte key per node, written `ttsk1:<base64url>`, from the first of:
//! 1. `WRENDNS_SECRETS_KEY`;
//! 2. `[node] secrets_key_file` (`WRENDNS_NODE_SECRETS_KEY_FILE`);
//! 3. `<data_dir>/secrets.key`, created (0600, never over an existing file) on a full member's
//!    first start, and only while the `secrets` table is empty.
//!
//! The previous key, during a rotation, comes from `WRENDNS_SECRETS_PREVIOUS_KEY` or
//! `[node] secrets_previous_key_file`. Purposes get their own subkeys (BLAKE3 `derive_key`): the
//! encrypted store ([`store`]) and the keyed hashes `Idempotency-Key` records keep (T23.1). A
//! configured source that can't be read or parsed leaves the store locked: nothing is generated
//! in its place, and DNS is unaffected (02 §8).
//!
//! - [`value`]: `SecretValue`, printed `<redacted>`, wiped on drop.
//! - [`store`]: the encrypted table, its states (ready, locked, ephemeral) and rotation.
//! - [`credential`]: `Credential::resolve`, the one place a credential is read (inline, file, or
//!   stored), and the readable check.
//! - [`cli`]: `wrendns secrets status | rotate-key`.

pub(crate) mod cli;
pub(crate) mod credential;
#[cfg(test)]
mod replication_tests;
pub(crate) mod store;
pub(crate) mod sync;
#[cfg(test)]
mod tests;
pub(crate) mod value;

use std::fmt;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use wrendns_config::Config;
use zeroize::{Zeroize as _, Zeroizing};

pub(crate) use credential::{Credential, Source};
pub(crate) use store::{SecretStore, Unavailable};
pub(crate) use value::SecretValue;

/// The data-directory key's file name.
pub(crate) const KEY_FILE: &str = "secrets.key";
/// A rotation's new key, until it replaces `secrets.key` (ADR-903 §3).
pub(crate) const NEW_KEY_FILE: &str = "secrets.key.new";
/// The text form's prefix (the format's version).
const PREFIX: &str = "ttsk1:";
/// `WRENDNS_SECRETS_KEY` and `WRENDNS_SECRETS_PREVIOUS_KEY`.
pub(crate) const KEY_VAR: &str = "WRENDNS_SECRETS_KEY";
pub(crate) const PREVIOUS_KEY_VAR: &str = "WRENDNS_SECRETS_PREVIOUS_KEY";
/// REQ: OPS-014 (ADR-903, Helm persistence off) — set when the data directory isn't kept across
/// restarts (an `emptyDir`): stored secrets would be lost at every restart (`secrets_ephemeral`).
pub(crate) const DATA_EPHEMERAL_VAR: &str = "WRENDNS_DATA_EPHEMERAL";
/// Subkey contexts (ADR-903 §3).
const KEY_ID_CONTEXT: &str = "telltale secrets key-id v1"; // rebrand:keep
const IDEMPOTENCY_CONTEXT: &str = "telltale secrets idempotency v1"; // rebrand:keep
pub(crate) const AEAD_CONTEXT: &str = "telltale secrets aead v1"; // rebrand:keep

/// Where a key came from (shown in status, never the key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeySource {
    /// `WRENDNS_SECRETS_KEY` (or the previous-key variable).
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

/// One node key. Its `Debug` never shows the bytes, and they are wiped when it's dropped.
pub(crate) struct NodeKey {
    key: [u8; 32],
    source: KeySource,
}

impl Drop for NodeKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
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

pub(crate) fn hex(b: &[u8]) -> String {
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
            format!("{source}: not a WrenDNS secrets key (expected `{PREFIX}...`)")
        })?;
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(body)
                .map_err(|_| format!("{source}: the key isn't base64url"))?,
        );
        let mut key = [0u8; 32];
        if bytes.len() != key.len() {
            return Err(format!("{source}: the key isn't 32 bytes"));
        }
        key.copy_from_slice(&bytes);
        Ok(Self { key, source })
    }

    /// A new random key's text form.
    pub(crate) fn generate() -> Result<Zeroizing<String>, String> {
        use ring::rand::SecureRandom as _;
        let mut key = Zeroizing::new([0u8; 32]);
        ring::rand::SystemRandom::new()
            .fill(&mut *key)
            .map_err(|_| "no randomness for a new secrets key".to_owned())?;
        Ok(Zeroizing::new(format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*key)
        )))
    }

    /// The first 8 bytes of the key-id subkey: names the key in rows and status, safely.
    pub(crate) fn key_id(&self) -> [u8; 8] {
        let d = blake3::derive_key(KEY_ID_CONTEXT, &self.key);
        let mut id = [0u8; 8];
        id.copy_from_slice(&d[..8]);
        id
    }

    /// A purpose's subkey (wiped when dropped).
    pub(crate) fn subkey(&self, context: &str) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(blake3::derive_key(context, &self.key))
    }

    pub(crate) fn source(&self) -> &KeySource {
        &self.source
    }

    /// REQ: API-014 (ADR-903 §4, AGT-003) — what an `Idempotency-Key` record keeps of a
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
    let text = Zeroizing::new(
        std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?,
    );
    #[cfg(unix)]
    if let Ok(meta) = std::fs::metadata(path) {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let mode = meta.permissions().mode();
        if mode & 0o027 != 0 {
            warnings.push(format!(
                "{}: other users can read or change the secrets key (mode {:o}); make it 0600 or 0640",
                path.display(),
                mode & 0o777
            ));
        }
        // REQ: OPS-014 (ADR-903 §3, note 39) — owned by another user. The process's uid is read
        // from `/proc/self` (no `libc`); root is exempt (it can read the file anyway, and
        // kubelet's Secret mounts are root's).
        if let Some(me) = process_uid()
            && meta.uid() != me
            && meta.uid() != 0
        {
            warnings.push(format!(
                "{}: the secrets key is owned by another user (uid {}, this process runs as {me}); make it this user's",
                path.display(),
                meta.uid()
            ));
        }
    }
    NodeKey::parse(&text, source)
}

/// The process's uid, from the owner of `/proc/self` (Linux; `None` elsewhere).
#[cfg(unix)]
fn process_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

/// Writes `text` to a new file `path` (`O_CREAT|O_EXCL`, 0600) and syncs it.
pub(crate) fn write_new_key(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write as _;
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(err)?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.write_all(b"\n"))
        .and_then(|()| f.sync_all())
        .map_err(err)
}

/// Syncs the directory `dir`, so a link or rename in it survives a crash.
pub(crate) fn sync_dir(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Creates `path` with a new key, never partly written and never over an existing file: the key
/// goes to `<path>.tmp` (`O_CREAT|O_EXCL`, 0600), is synced, then hard-linked to `path` (which
/// fails if `path` exists: a race with another start reads that one instead), and the directory
/// is synced. A crash leaves at most the temporary file, which the next start replaces.
fn create_key_file(path: &Path) -> Result<(), String> {
    let err = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    let text = NodeKey::generate()?;
    let tmp = path.with_extension("key.tmp");
    if let Err(e) = std::fs::remove_file(&tmp)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(err(&tmp, e));
    }
    write_new_key(&tmp, &text)?;
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
    match path.parent() {
        Some(dir) => sync_dir(dir),
        None => Ok(()),
    }
}

/// Where a node's keys come from: the node-local settings the store reads (ADR-903 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyPaths {
    pub(crate) data_dir: PathBuf,
    /// `[node] secrets_key_file` (empty: not set).
    pub(crate) key_file: String,
    /// `[node] secrets_previous_key_file`.
    pub(crate) previous_file: String,
    /// A resolver pod (`[cluster] ephemeral`): it holds no secrets and makes no key.
    pub(crate) ephemeral: bool,
}

impl KeyPaths {
    pub(crate) fn of(cfg: &Config) -> Self {
        Self {
            data_dir: PathBuf::from(cfg.node.data_dir.as_str()),
            key_file: cfg.node.secrets_key_file.trim().to_owned(),
            previous_file: cfg.node.secrets_previous_key_file.trim().to_owned(),
            ephemeral: cfg.cluster.ephemeral,
        }
    }

    /// `<data_dir>/secrets.key`.
    pub(crate) fn data_key(&self) -> PathBuf {
        self.data_dir.join(KEY_FILE)
    }

    /// Whether the key is the data directory's (no variable, no `[node] secrets_key_file`): the
    /// only one this node makes, rotates or replaces.
    pub(crate) fn uses_data_key(&self, var: &dyn Fn(&str) -> Option<String>) -> bool {
        self.key_file.is_empty() && var(KEY_VAR).is_none_or(|t| t.trim().is_empty())
    }
}

/// REQ: OPS-014 (ADR-903 §3) — the node's keys from its settings and the environment (`var`).
/// `create`: make the data-directory key when no other source is set and it doesn't exist (the
/// store asks only while its table is empty, and never on an ephemeral resolver pod).
pub(crate) fn load(
    paths: &KeyPaths,
    var: &dyn Fn(&str) -> Option<String>,
    create: bool,
) -> Result<Keys, String> {
    let mut warnings = Vec::new();
    let current = if let Some(text) = var(KEY_VAR).filter(|t| !t.trim().is_empty()) {
        let text = Zeroizing::new(text);
        NodeKey::parse(&text, KeySource::Env)?
    } else if !paths.key_file.is_empty() {
        let p = PathBuf::from(&paths.key_file);
        read_key_file(&p, KeySource::File(p.clone()), &mut warnings)?
    } else {
        let p = paths.data_key();
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
        let text = Zeroizing::new(text);
        Some(NodeKey::parse(&text, KeySource::Env)?)
    } else if !paths.previous_file.is_empty() {
        let p = PathBuf::from(&paths.previous_file);
        if p.exists() {
            Some(read_key_file(
                &p,
                KeySource::File(p.clone()),
                &mut warnings,
            )?)
        } else {
            // REQ: OPS-014 (ADR-903 note 39) — removed after a rotation, as the docs say, with
            // the setting left: not a reason to lock (§3 locks for sources 1 and 2 only).
            warnings.push(format!(
                "{}: the previous secrets key ([node] secrets_previous_key_file) is gone; going on without one (remove the setting)",
                p.display()
            ));
            None
        }
    } else {
        None
    };
    Ok(Keys {
        current,
        previous,
        warnings,
    })
}

/// The process environment, as the store reads it.
pub(crate) fn process_env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

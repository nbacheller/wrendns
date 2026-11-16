//! REQ: OPS-014, NFR-005 (ADR-167 §2–3) — the encrypted secrets store: the `secrets` table of
//! `state.db`, its ciphertext kept in memory and decrypted at use.
//!
//! - **Encryption:** ChaCha20-Poly1305 (`ring`), a random 96-bit nonce per value, and associated
//!   data binding the ciphertext to its key, kind, name and stamp: a row copied over another (or
//!   given another stamp) fails to decrypt.
//! - **The key** is made only while the table is empty (no rows, no tombstones). A configured key
//!   that can't be read, a missing data-directory key while rows exist, or rows none of which
//!   decrypt, leave the store **locked**: nothing is generated, secret writes are refused (503
//!   `secrets_locked`), status reads work, health says `secrets_locked`, and DNS and `/readyz`
//!   are unaffected. A failed load is tried again after 30 s.
//! - **One exception, the replica's self-heal:** a replica whose rows are all the cluster's may
//!   drop them, make a new key and fetch them again ([`SecretStore::heal_as_replica`]).
//! - **Rotation:** at start, rows under the previous key are re-encrypted in one transaction and
//!   the WAL truncated; `telltale secrets rotate-key` replaces the data-directory key offline.
//! - **Resolver pods** (ephemeral members) hold no secrets, need no key and never lock.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use ring::aead;
use telltale_api::problem::{Code, Problem};
use telltale_store::state::{SecretRow, Stamp, State};
use zeroize::Zeroizing;

use super::value::{Kind, SecretValue, ValueError};
use super::{AEAD_CONTEXT, KeyPaths, Keys, NEW_KEY_FILE, NodeKey, hex};

/// At most this many live secrets (ADR-167 §2).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the write API (`PUT`/`DELETE /api/v1/secrets`, T23.4) and replication (T23.5) use it"
    )
)]
pub(crate) const MAX_SECRETS: usize = 128;
/// How long a failed load is kept before the next use tries again.
pub(crate) const RETRY_AFTER: Duration = Duration::from_secs(30);
/// The associated data's prefix (its version).
const AAD_PREFIX: &[u8] = b"telltale-secret\x01";

/// Reads an environment variable (tests give their own).
pub(crate) type EnvFn = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// How one row stands on this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowHealth {
    Readable,
    /// Encrypted with a key this node doesn't have.
    Unreadable,
    /// Encrypted with this node's key but fails its integrity check (damaged, or moved).
    Corrupt,
}

impl RowHealth {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Readable => "readable",
            Self::Unreadable => "unreadable",
            Self::Corrupt => "corrupt",
        }
    }
}

#[derive(Debug, Clone)]
struct Cached {
    row: SecretRow,
    health: RowHealth,
}

/// Why a secret's value isn't available on this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unavailable {
    NotSet,
    Locked(String),
    Unreadable,
    Corrupt,
    /// A resolver pod: stored secrets stay on full members.
    Ephemeral,
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSet => f.write_str("no secret of that name is stored"),
            Self::Locked(why) => write!(f, "the secrets store is locked: {why}"),
            Self::Unreadable => {
                f.write_str("it was encrypted with a key this node doesn't have; enter it again")
            }
            Self::Corrupt => f.write_str("it fails its integrity check; enter it again"),
            Self::Ephemeral => f.write_str(
                "stored secrets are kept on full members, not on resolver pods; use a file here",
            ),
        }
    }
}

/// Why a change to the store was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the write API (`PUT`/`DELETE /api/v1/secrets`, T23.4) and replication (T23.5) use it"
    )
)]
pub(crate) enum StoreError {
    Locked(String),
    Ephemeral,
    Invalid(ValueError),
    Full,
    Db(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked(why) => write!(f, "the secrets store is locked: {why}"),
            Self::Ephemeral => f.write_str("resolver pods hold no stored secrets"),
            Self::Invalid(e) => write!(f, "{e}"),
            Self::Full => write!(f, "at most {MAX_SECRETS} secrets are stored"),
            Self::Db(e) => write!(f, "the state database: {e}"),
        }
    }
}

impl StoreError {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the write API (`PUT`/`DELETE /api/v1/secrets`, T23.4) and replication (T23.5) use it"
        )
    )]
    /// REQ: OPS-014 — the API's answer: 503 `secrets_locked` while locked.
    pub(crate) fn problem(&self) -> Problem {
        match self {
            Self::Locked(_) => Problem::new(Code::SecretsLocked, self.to_string()).hint(
                "Fix the node's secrets key (TELLTALE_SECRETS_KEY, [node] secrets_key_file, or secrets.key in the data directory; docs/secrets.md), then try again. DNS is unaffected.",
            ),
            Self::Ephemeral => Problem::new(Code::Conflict, self.to_string())
                .hint("Set secrets on a full member (the primary)."),
            Self::Invalid(_) | Self::Full => Problem::invalid(self.to_string()),
            Self::Db(_) => Problem::internal(self.to_string()),
        }
    }
}

/// A stored secret, without its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretInfo {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) stamp: Stamp,
    pub(crate) deleted: bool,
    pub(crate) origin: String,
    pub(crate) updated: u64,
    pub(crate) updated_by: String,
    pub(crate) health: RowHealth,
}

/// The store's state on this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreState {
    /// Not loaded yet (the node is starting).
    Starting,
    Ready,
    Locked,
    /// A resolver pod.
    Ephemeral,
}

impl StoreState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Locked => "locked",
            Self::Ephemeral => "ephemeral",
        }
    }
}

/// What status reads show: never a value or a key.
#[derive(Debug, Clone)]
pub(crate) struct Status {
    pub(crate) state: StoreState,
    pub(crate) reason: Option<String>,
    /// Where the key came from, and its ID.
    pub(crate) key_source: Option<String>,
    pub(crate) key_id: Option<String>,
    pub(crate) previous_key_id: Option<String>,
    /// The data directory isn't kept across restarts (`TELLTALE_DATA_EPHEMERAL`).
    pub(crate) data_ephemeral: bool,
    /// Every row, tombstones included, by name.
    pub(crate) secrets: Vec<SecretInfo>,
}

impl Status {
    /// Live secrets in `health`.
    pub(crate) fn count(&self, health: RowHealth) -> usize {
        self.secrets
            .iter()
            .filter(|s| !s.deleted && s.health == health)
            .count()
    }

    pub(crate) fn live(&self) -> usize {
        self.secrets.iter().filter(|s| !s.deleted).count()
    }
}

#[derive(Debug, Default)]
struct Inner {
    /// A load ran (successful or not) at this time.
    loaded_at: Option<Instant>,
    state: Option<Arc<State>>,
    keys: Option<Arc<Keys>>,
    /// Why there are no keys.
    key_error: Option<String>,
    /// Why the store is locked.
    locked: Option<String>,
    rows: BTreeMap<String, Cached>,
    /// The last reason logged, so a lasting one is logged once.
    logged: Option<String>,
}

/// The node's secrets store. Cheap to make: nothing is read until first use.
pub(crate) struct SecretStore {
    paths: Mutex<KeyPaths>,
    var: EnvFn,
    /// Make the data-directory key when the table is empty (the server; `secrets status` never
    /// makes one).
    create: bool,
    data_ephemeral: bool,
    inner: Mutex<Inner>,
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.status();
        f.debug_struct("SecretStore")
            .field("state", &s.state)
            .field("key_id", &s.key_id)
            .field("secrets", &s.live())
            .finish_non_exhaustive()
    }
}

fn lock(m: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The associated data: `"telltale-secret\x01" ‖ key_id ‖ kind ‖ name ‖ be64(epoch) ‖
/// be64(seq)` (ADR-167 §3).
fn aad(key_id: &[u8], kind: &str, name: &str, stamp: Stamp) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_PREFIX.len() + 8 + kind.len() + name.len() + 16);
    a.extend_from_slice(AAD_PREFIX);
    a.extend_from_slice(key_id);
    a.extend_from_slice(kind.as_bytes());
    a.extend_from_slice(name.as_bytes());
    a.extend_from_slice(&stamp.epoch.to_be_bytes());
    a.extend_from_slice(&stamp.seq.to_be_bytes());
    a
}

fn cipher(key: &NodeKey) -> Result<aead::LessSafeKey, String> {
    let sub = key.subkey(AEAD_CONTEXT);
    aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &sub[..])
        .map(aead::LessSafeKey::new)
        .map_err(|_| "the secrets cipher couldn't start".to_owned())
}

/// A value encrypted for one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sealed {
    pub(crate) key_id: Vec<u8>,
    pub(crate) nonce: Vec<u8>,
    /// The ciphertext followed by the tag.
    pub(crate) ciphertext: Vec<u8>,
}

/// REQ: OPS-014 (ADR-167 §3) — `value` encrypted under `key` for the row `(kind, name, stamp)`.
pub(crate) fn seal(
    key: &NodeKey,
    kind: &str,
    name: &str,
    stamp: Stamp,
    value: &SecretValue,
) -> Result<Sealed, String> {
    use ring::rand::SecureRandom as _;
    let mut nonce = [0u8; aead::NONCE_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "no randomness for a nonce".to_owned())?;
    let id = key.key_id();
    // The plaintext is copied into the buffer that becomes the ciphertext, in place, with room
    // for the tag: appending it never moves (and leaves behind) the buffer.
    let plain = value.expose().as_bytes();
    let mut buf = Zeroizing::new(Vec::with_capacity(plain.len() + aead::MAX_TAG_LEN));
    buf.extend_from_slice(plain);
    cipher(key)?
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad(&id, kind, name, stamp)),
            &mut *buf,
        )
        .map_err(|_| "the value couldn't be encrypted".to_owned())?;
    Ok(Sealed {
        key_id: id.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext: std::mem::take(&mut *buf),
    })
}

/// REQ: OPS-014 (ADR-167 §3) — `row`'s value under `key`, or how it stands: `Unreadable` when
/// another key made it, `Corrupt` when it fails authentication (a damaged or moved row).
pub(crate) fn open(key: &NodeKey, row: &SecretRow) -> Result<SecretValue, RowHealth> {
    if row.key_id != key.key_id() {
        return Err(RowHealth::Unreadable);
    }
    let nonce: [u8; aead::NONCE_LEN] = row
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| RowHealth::Corrupt)?;
    let c = cipher(key).map_err(|_| RowHealth::Unreadable)?;
    let mut buf = Zeroizing::new(row.ciphertext.clone());
    let len = c
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad(&row.key_id, &row.kind, &row.name, row.stamp)),
            &mut buf,
        )
        .map_err(|_| RowHealth::Corrupt)?
        .len();
    buf.truncate(len);
    SecretValue::from_bytes(&buf).ok_or(RowHealth::Corrupt)
}

/// How a row stands under `keys`.
fn health_of(keys: &Keys, row: &SecretRow) -> RowHealth {
    if row.deleted {
        return RowHealth::Readable;
    }
    match open(&keys.current, row) {
        Ok(_) => RowHealth::Readable,
        Err(h) => h,
    }
}

/// REQ: OPS-014 (ADR-167 §3) — a rotation interrupted after it wrote `secrets.key.new`: when some
/// row is already under that key (the re-encryption committed), the rename is finished; otherwise
/// the new key was never used and goes. Only for the data-directory key.
pub(crate) fn recover_rotation(data_dir: &Path, rows: &[SecretRow]) -> Option<String> {
    let new = data_dir.join(NEW_KEY_FILE);
    if !new.exists() {
        return None;
    }
    let text = std::fs::read_to_string(&new).map(Zeroizing::new);
    let used = text
        .ok()
        .and_then(|t| NodeKey::parse(&t, super::KeySource::DataDir(new.clone())).ok())
        .is_some_and(|k| {
            let id = k.key_id();
            rows.iter().any(|r| !r.deleted && r.key_id == id)
        });
    let key = data_dir.join(super::KEY_FILE);
    let done = if used {
        std::fs::rename(&new, &key)
            .map(|()| "finished an interrupted key rotation (secrets.key.new is the key now)")
    } else {
        std::fs::remove_file(&new)
            .map(|()| "dropped the new key of an unfinished rotation (nothing was re-encrypted)")
    };
    let _ = super::sync_dir(data_dir);
    Some(match done {
        Ok(m) => m.to_owned(),
        Err(e) => format!("{}: {e}", new.display()),
    })
}

impl SecretStore {
    /// The server's store for `cfg` (the process environment).
    pub(crate) fn new(cfg: &telltale_config::Config) -> Self {
        let var: EnvFn = Arc::new(super::process_env);
        let ephemeral_dir = var(super::DATA_EPHEMERAL_VAR)
            .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes"));
        Self::with_env(cfg, var, true, ephemeral_dir)
    }

    /// A store reading `var` for its keys. `create`: make the data-directory key on an empty
    /// table. `data_ephemeral`: the data directory isn't kept across restarts.
    pub(crate) fn with_env(
        cfg: &telltale_config::Config,
        var: EnvFn,
        create: bool,
        data_ephemeral: bool,
    ) -> Self {
        Self {
            paths: Mutex::new(KeyPaths::of(cfg)),
            var,
            create,
            data_ephemeral,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// After a reload: new key settings are read at the next use.
    pub(crate) fn configure(&self, cfg: &telltale_config::Config) {
        let new = KeyPaths::of(cfg);
        let mut p = self.paths.lock().unwrap_or_else(PoisonError::into_inner);
        if *p != new {
            *p = new;
            lock(&self.inner).loaded_at = None;
        }
    }

    fn paths(&self) -> KeyPaths {
        self.paths
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The store, loaded (again, after a failure older than [`RETRY_AFTER`]).
    fn ready(&self) -> MutexGuard<'_, Inner> {
        let mut g = lock(&self.inner);
        let again = match g.loaded_at {
            None => true,
            Some(at) => {
                (g.locked.is_some() || g.key_error.is_some()) && at.elapsed() >= RETRY_AFTER
            }
        };
        if again {
            self.load_into(&mut g);
        }
        g
    }

    /// Loads (or reloads) the store now, whatever happened before (`secrets status`, tests).
    pub(crate) fn load_now(&self) {
        let mut g = lock(&self.inner);
        self.load_into(&mut g);
    }

    /// REQ: OPS-014 (ADR-167 §3) — opens the table, finds the keys (making one only for an empty
    /// table), re-encrypts rows under the previous key, and judges every row.
    #[allow(clippy::too_many_lines)] // the load's steps, in order
    fn load_into(&self, g: &mut Inner) {
        let paths = self.paths();
        g.loaded_at = Some(Instant::now());
        g.locked = None;
        g.key_error = None;
        let var = |k: &str| (self.var)(k);
        if paths.ephemeral {
            // Resolver pods: no table, no key made; a configured key still keys idempotency.
            g.rows.clear();
            match super::load(&paths, &var, false) {
                Ok(k) => g.keys = Some(Arc::new(k)),
                Err(e) => {
                    g.keys = None;
                    g.key_error = Some(e);
                }
            }
            return;
        }
        if g.state.is_none() {
            let db = paths.data_dir.join("state.db");
            match std::fs::create_dir_all(&paths.data_dir)
                .map_err(|e| e.to_string())
                .and_then(|()| State::open(&db).map_err(|e| e.to_string()))
            {
                Ok(s) => g.state = Some(Arc::new(s)),
                Err(e) => {
                    let why = format!("{}: {e}", db.display());
                    g.key_error = Some(why.clone());
                    Self::set_locked(g, why);
                    return;
                }
            }
        }
        let Some(state) = g.state.clone() else {
            return;
        };
        let mut rows = match state.secret_rows() {
            Ok(r) => r,
            Err(e) => {
                let why = format!("the secrets table: {e}");
                g.key_error = Some(why.clone());
                Self::set_locked(g, why);
                return;
            }
        };
        if paths.uses_data_key(&var)
            && let Some(note) = recover_rotation(&paths.data_dir, &rows)
        {
            tracing::warn!("secrets key: {note}");
        }
        let keys = match super::load(&paths, &var, self.create && rows.is_empty()) {
            Ok(k) => Arc::new(k),
            Err(e) => {
                let live = rows.iter().filter(|r| !r.deleted).count();
                let why = if !rows.is_empty()
                    && paths.uses_data_key(&var)
                    && !paths.data_key().exists()
                {
                    format!(
                        "{} is missing and {live} stored secret(s) were encrypted with it: no new key is made (put the key back; docs/secrets.md)",
                        paths.data_key().display()
                    )
                } else {
                    e
                };
                g.keys = None;
                g.key_error = Some(why.clone());
                g.rows = rows
                    .into_iter()
                    .map(|r| {
                        let health = if r.deleted {
                            RowHealth::Readable
                        } else {
                            RowHealth::Unreadable
                        };
                        (r.name.clone(), Cached { row: r, health })
                    })
                    .collect();
                Self::set_locked(g, why);
                return;
            }
        };
        if g.logged.is_some() || g.keys.is_none() {
            for w in &keys.warnings {
                tracing::warn!("{w}");
            }
            tracing::info!(
                source = %keys.current.source(),
                key_id = %hex(&keys.current.key_id()),
                previous = ?keys.previous.as_ref().map(|p| hex(&p.key_id())),
                "secrets key loaded"
            );
        }
        if let Some(prev) = &keys.previous {
            reencrypt(&state, &keys.current, prev, &mut rows);
        }
        g.rows = rows
            .into_iter()
            .map(|r| {
                let health = health_of(&keys, &r);
                (r.name.clone(), Cached { row: r, health })
            })
            .collect();
        g.keys = Some(Arc::clone(&keys));
        let live = g.rows.values().filter(|c| !c.row.deleted).count();
        let readable = g
            .rows
            .values()
            .filter(|c| !c.row.deleted && c.health == RowHealth::Readable)
            .count();
        if live > 0 && readable == 0 {
            let why = format!(
                "none of the {live} stored secret(s) decrypts with this node's key (key_id {}): the key was replaced; put the right one back, or give the old one as the previous key (docs/secrets.md)",
                hex(&keys.current.key_id())
            );
            Self::set_locked(g, why);
            return;
        }
        if g.logged.take().is_some() {
            tracing::info!("the secrets store is unlocked");
        }
    }

    fn set_locked(g: &mut Inner, why: String) {
        if g.logged.as_deref() != Some(why.as_str()) {
            tracing::error!("secrets store locked: {why} (DNS is unaffected)");
            g.logged = Some(why.clone());
        }
        g.locked = Some(why);
    }

    /// The node's keys (for the idempotency hashes too), loading them on first use.
    pub(crate) fn keys(&self) -> Result<Arc<Keys>, String> {
        let g = self.ready();
        match (&g.keys, &g.key_error) {
            (Some(k), _) => Ok(Arc::clone(k)),
            (None, Some(e)) => Err(e.clone()),
            (None, None) => Err("no secrets key".to_owned()),
        }
    }

    /// What status reads show (never loads: a node that is starting says so).
    pub(crate) fn status(&self) -> Status {
        let paths = self.paths();
        let g = lock(&self.inner);
        let state = if paths.ephemeral {
            StoreState::Ephemeral
        } else if g.loaded_at.is_none() {
            StoreState::Starting
        } else if g.locked.is_some() {
            StoreState::Locked
        } else {
            StoreState::Ready
        };
        Status {
            state,
            reason: g.locked.clone(),
            key_source: g.keys.as_ref().map(|k| k.current.source().to_string()),
            key_id: g.keys.as_ref().map(|k| hex(&k.current.key_id())),
            previous_key_id: g
                .keys
                .as_ref()
                .and_then(|k| k.previous.as_ref())
                .map(|p| hex(&p.key_id())),
            data_ephemeral: self.data_ephemeral,
            secrets: g
                .rows
                .values()
                .map(|c| SecretInfo {
                    name: c.row.name.clone(),
                    kind: c.row.kind.clone(),
                    stamp: c.row.stamp,
                    deleted: c.row.deleted,
                    origin: c.row.origin.clone(),
                    updated: c.row.updated,
                    updated_by: c.row.updated_by.clone(),
                    health: c.health,
                })
                .collect(),
        }
    }

    /// REQ: OPS-014 — a stored secret's value, decrypted now.
    pub(crate) fn get(&self, name: &str) -> Result<SecretValue, Unavailable> {
        if self.paths().ephemeral {
            return Err(Unavailable::Ephemeral);
        }
        let g = self.ready();
        let Some(c) = g.rows.get(name).filter(|c| !c.row.deleted) else {
            return Err(Unavailable::NotSet);
        };
        let Some(keys) = &g.keys else {
            return Err(Unavailable::Locked(
                g.locked.clone().unwrap_or_else(|| "no key".to_owned()),
            ));
        };
        match open(&keys.current, &c.row) {
            Ok(v) => Ok(v),
            Err(RowHealth::Corrupt) => Err(Unavailable::Corrupt),
            Err(_) => Err(Unavailable::Unreadable),
        }
    }

    /// REQ: OPS-014 (ADR-167 §4) — whether this node can read the secret `name`, judged from the
    /// row's state (nothing is decrypted for it).
    pub(crate) fn readable(&self, name: &str) -> Result<(), Unavailable> {
        if self.paths().ephemeral {
            return Err(Unavailable::Ephemeral);
        }
        let g = self.ready();
        let Some(c) = g.rows.get(name).filter(|c| !c.row.deleted) else {
            return Err(Unavailable::NotSet);
        };
        if g.keys.is_none() {
            return Err(Unavailable::Locked(
                g.locked.clone().unwrap_or_else(|| "no key".to_owned()),
            ));
        }
        match c.health {
            RowHealth::Readable => Ok(()),
            RowHealth::Unreadable => Err(Unavailable::Unreadable),
            RowHealth::Corrupt => Err(Unavailable::Corrupt),
        }
    }

    /// Whether a secret of that name is stored (readable or not).
    pub(crate) fn exists(&self, name: &str) -> bool {
        self.ready().rows.get(name).is_some_and(|c| !c.row.deleted)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the write API (`PUT`/`DELETE /api/v1/secrets`, T23.4) and replication (T23.5) use it"
        )
    )]
    /// REQ: OPS-014 (ADR-167 §2) — stores `value` as `name`, stamped in `epoch` (0 on a
    /// standalone node), as `origin` (`local` or `cluster`). Refused while locked.
    #[allow(clippy::too_many_arguments)] // a stored secret's parts, each a column
    pub(crate) fn put(
        &self,
        name: &str,
        kind: Kind,
        value: &SecretValue,
        epoch: u64,
        by: &str,
        origin: &str,
        now: u64,
    ) -> Result<SecretInfo, StoreError> {
        if !telltale_config::secret_refs::valid_name(name) {
            return Err(StoreError::Invalid(ValueError::Name));
        }
        if self.paths().ephemeral {
            return Err(StoreError::Ephemeral);
        }
        let mut g = self.ready();
        if let Some(why) = &g.locked {
            return Err(StoreError::Locked(why.clone()));
        }
        let (Some(keys), Some(state)) = (g.keys.clone(), g.state.clone()) else {
            return Err(StoreError::Locked(
                g.key_error.clone().unwrap_or_else(|| "no key".to_owned()),
            ));
        };
        let others = g
            .rows
            .values()
            .filter(|c| !c.row.deleted && c.row.name != name)
            .count();
        if others >= MAX_SECRETS {
            return Err(StoreError::Full);
        }
        let stamp = state
            .next_secret_stamp(epoch)
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let sealed =
            seal(&keys.current, kind.as_str(), name, stamp, value).map_err(StoreError::Db)?;
        let row = SecretRow {
            name: name.to_owned(),
            kind: kind.as_str().to_owned(),
            key_id: sealed.key_id,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            stamp,
            deleted: false,
            origin: origin.to_owned(),
            updated: now,
            updated_by: by.to_owned(),
        };
        state
            .put_secret_row(&row, now)
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let info = info_of(&row, RowHealth::Readable);
        g.rows.insert(
            row.name.clone(),
            Cached {
                row,
                health: RowHealth::Readable,
            },
        );
        Ok(info)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the write API (`PUT`/`DELETE /api/v1/secrets`, T23.4) and replication (T23.5) use it"
        )
    )]
    /// REQ: OPS-014 (ADR-167 §2) — deletes `name`, leaving a tombstone with a new stamp. `None`:
    /// nothing of that name was stored.
    pub(crate) fn delete(
        &self,
        name: &str,
        epoch: u64,
        by: &str,
        now: u64,
    ) -> Result<Option<SecretInfo>, StoreError> {
        if self.paths().ephemeral {
            return Err(StoreError::Ephemeral);
        }
        let mut g = self.ready();
        if let Some(why) = &g.locked {
            return Err(StoreError::Locked(why.clone()));
        }
        let Some(state) = g.state.clone() else {
            return Err(StoreError::Locked("no state database".to_owned()));
        };
        let Some(old) = g.rows.get(name).filter(|c| !c.row.deleted).cloned() else {
            return Ok(None);
        };
        let stamp = state
            .next_secret_stamp(epoch)
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let row = SecretRow {
            key_id: Vec::new(),
            nonce: Vec::new(),
            ciphertext: Vec::new(),
            stamp,
            deleted: true,
            updated: now,
            updated_by: by.to_owned(),
            ..old.row
        };
        state
            .put_secret_row(&row, now)
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let info = info_of(&row, RowHealth::Readable);
        g.rows.insert(
            row.name.clone(),
            Cached {
                row,
                health: RowHealth::Readable,
            },
        );
        // Pruned tombstones leave the cache too.
        if let Ok(rows) = state.secret_rows() {
            g.rows.retain(|n, _| rows.iter().any(|r| r.name == *n));
        }
        Ok(Some(info))
    }

    /// REQ: OPS-014 (ADR-167 §3, the one exception) — a locked replica whose rows are all the
    /// cluster's drops them and starts over with a working key, so it can fetch them again from
    /// the primary (T23.5). Only for the data-directory key: a configured key that can't be read
    /// is fixed by whoever configured it. Returns how many rows went, or why nothing was done.
    pub(crate) fn heal_as_replica(&self) -> Result<usize, String> {
        let paths = self.paths();
        let var = |k: &str| (self.var)(k);
        let mut g = self.ready();
        if g.locked.is_none() {
            return Err("the store isn't locked".to_owned());
        }
        if paths.ephemeral || !paths.uses_data_key(&var) {
            return Err("only a data-directory key is replaced".to_owned());
        }
        if g.rows.is_empty() || g.rows.values().any(|c| c.row.origin != "cluster") {
            return Err("some rows were made on this node: they aren't dropped".to_owned());
        }
        let Some(state) = g.state.clone() else {
            return Err("no state database".to_owned());
        };
        let n = state.clear_secret_rows().map_err(|e| e.to_string())?;
        tracing::warn!(
            dropped = n,
            "secrets store: this replica couldn't read the cluster's secrets; it dropped them and fetches them again from the primary"
        );
        g.rows.clear();
        self.load_into(&mut g);
        Ok(n)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the write API (`PUT`/`DELETE /api/v1/secrets`, T23.4) and replication (T23.5) use it"
        )
    )]
    /// REQ: OPS-014 (ADR-167 §2) — the secrets head: the highest stamp, and BLAKE3 over the
    /// sorted `(name, kind, stamp, deleted)` list (no value, no value hash).
    pub(crate) fn head(&self) -> (Stamp, [u8; 32]) {
        let g = lock(&self.inner);
        head_of(g.rows.values().map(|c| &c.row))
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the write API (`PUT`/`DELETE /api/v1/secrets`, T23.4) and replication (T23.5) use it"
    )
)]
fn info_of(r: &SecretRow, health: RowHealth) -> SecretInfo {
    SecretInfo {
        name: r.name.clone(),
        kind: r.kind.clone(),
        stamp: r.stamp,
        deleted: r.deleted,
        origin: r.origin.clone(),
        updated: r.updated,
        updated_by: r.updated_by.clone(),
        health,
    }
}

/// The head of a set of rows (they come sorted by name from the table and the cache).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the write API (`PUT`/`DELETE /api/v1/secrets`, T23.4) and replication (T23.5) use it"
    )
)]
pub(crate) fn head_of<'a>(rows: impl Iterator<Item = &'a SecretRow>) -> (Stamp, [u8; 32]) {
    let mut h = blake3::Hasher::new();
    let mut top = Stamp::default();
    let mut sorted: Vec<&SecretRow> = rows.collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    for r in sorted {
        top = top.max(r.stamp);
        for part in [r.name.as_bytes(), b"\0", r.kind.as_bytes(), b"\0"] {
            h.update(part);
        }
        h.update(&r.stamp.epoch.to_be_bytes());
        h.update(&r.stamp.seq.to_be_bytes());
        h.update(&[u8::from(r.deleted)]);
    }
    (top, *h.finalize().as_bytes())
}

/// REQ: OPS-014 (ADR-167 §3) — rows under the previous key, re-encrypted under the current one
/// (same stamp, new nonce) in one transaction, then the WAL truncated. `rows` is updated in place.
fn reencrypt(state: &State, current: &NodeKey, previous: &NodeKey, rows: &mut [SecretRow]) {
    let pid = previous.key_id();
    let mut redone = Vec::new();
    for r in rows.iter().filter(|r| !r.deleted && r.key_id == pid) {
        let Ok(v) = open(previous, r) else {
            continue;
        };
        match seal(current, &r.kind, &r.name, r.stamp, &v) {
            Ok(s) => redone.push(SecretRow {
                key_id: s.key_id,
                nonce: s.nonce,
                ciphertext: s.ciphertext,
                ..r.clone()
            }),
            Err(e) => {
                tracing::error!(name = %r.name, "a secret couldn't be re-encrypted: {e}");
                return;
            }
        }
    }
    if redone.is_empty() {
        return;
    }
    match state.replace_secret_rows(&redone) {
        Ok(()) => {
            tracing::info!(
                count = redone.len(),
                from = %hex(&pid),
                to = %hex(&current.key_id()),
                "re-encrypted stored secrets under the current key; the previous key can be removed"
            );
            for new in redone {
                if let Some(r) = rows.iter_mut().find(|r| r.name == new.name) {
                    *r = new;
                }
            }
        }
        Err(e) => tracing::error!("re-encrypting stored secrets failed (kept as they were): {e}"),
    }
}

/// REQ: OPS-014 (ADR-167 §3) — the store's upkeep on a full member: loaded at start (in a
/// blocking task: making the key syncs a file), then every [`RETRY_AFTER`] a locked store is
/// tried again (a key mounted after the start unlocks it), and a locked replica whose rows are
/// all the cluster's heals ([`SecretStore::heal_as_replica`]).
pub(crate) fn spawn_upkeep(
    src: Arc<crate::http::Sources>,
    cfg: telltale_config::Config,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let (s, c) = (Arc::clone(&src), cfg);
        let _ = tokio::task::spawn_blocking(move || {
            let _ = s.secrets.keys();
            super::credential::warn_missing(&c, &s.secrets);
        })
        .await;
        loop {
            tokio::select! {
                () = tokio::time::sleep(RETRY_AFTER) => {}
                _ = stop.wait_for(|s| *s) => return,
            }
            let replica = src
                .cluster
                .as_ref()
                .is_some_and(|c| c.role().0 == telltale_cluster::node::Role::Replica);
            let s = Arc::clone(&src);
            let _ = tokio::task::spawn_blocking(move || {
                let _ = s.secrets.keys();
                if replica && s.secrets.status().state == StoreState::Locked {
                    let _ = s.secrets.heal_as_replica();
                }
            })
            .await;
        }
    });
}

/// REQ: OPS-014, OBS-015 (ADR-167 §3) — the store's health reasons: `secrets_locked` while it
/// is locked, and `secrets_ephemeral` when secrets are stored in a data directory that isn't kept
/// across restarts. Both degrade; neither touches DNS or `/readyz`.
pub(crate) fn health_reasons(s: &Status) -> Vec<telltale_api::model::HealthReason> {
    let reason = |code: &str, summary: String| telltale_api::model::HealthReason {
        level: crate::health::DEGRADED.to_owned(),
        code: code.to_owned(),
        summary,
        node: None,
        link: Some("#/settings".to_owned()),
    };
    let mut out = Vec::new();
    if s.state == StoreState::Locked {
        out.push(reason(
            "secrets_locked",
            format!(
                "stored secrets can't be used on this node: {} (integrations that use one report \"not configured\"; DNS is unaffected)",
                s.reason.as_deref().unwrap_or("no key")
            ),
        ));
    }
    if s.data_ephemeral && s.live() > 0 {
        out.push(reason(
            "secrets_ephemeral",
            format!(
                "{} stored secret(s) live in a data directory that isn't kept across restarts (Helm persistence is off): they are lost at the next restart",
                s.live()
            ),
        ));
    }
    out
}

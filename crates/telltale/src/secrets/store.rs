//! REQ: OPS-014, NFR-005 (ADR-903 §2–3) — the encrypted secrets store: the `secrets` table of
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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Bound;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use ring::aead;
use telltale_api::problem::{Code, Problem};
use telltale_store::state::{SecretRow, Stamp, State};
use zeroize::Zeroizing;

use super::value::{Kind, SecretValue, ValueError};
use super::{AEAD_CONTEXT, KeyPaths, Keys, NEW_KEY_FILE, NodeKey, hex};

/// At most this many live secrets (ADR-903 §2).
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
    /// REQ: CLU-015 — stamped by an older primary after the current one took over: not used.
    Orphaned,
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
            Self::Orphaned => f.write_str(
                "it was changed by an earlier primary after the current one took over, so the cluster doesn't hold it; enter it again on the current primary",
            ),
        }
    }
}

/// Why a change to the store was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// REQ: CLU-015 — an orphan (see [`Unavailable::Orphaned`]).
    pub(crate) orphaned: bool,
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
    /// Live rows still under the previous key (a status read; the next start re-encrypts them).
    pub(crate) under_previous: usize,
    /// Every row, tombstones included, by name.
    pub(crate) secrets: Vec<SecretInfo>,
    /// REQ: CLU-015 — names whose local row a cluster row displaced (kept, not used). The
    /// Settings page's Conflicts list (T23.6) shows them.
    #[allow(dead_code)] // read by the tests now; by the Settings page with T23.6
    pub(crate) shadows: Vec<String>,
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
    /// The lock is one the replica's self-heal may clear: the data-directory key is missing, or
    /// none of the rows decrypts. Not a key or database that can't be read (ADR-903 note 39).
    healable: bool,
    /// Live rows still under the previous key (a status read: re-encrypted at the next start).
    under_previous: usize,
    /// REQ: CLU-015 — names of the shadowed local rows (see [`Status::shadows`]).
    shadows: BTreeSet<String>,
}

/// The node's secrets store. Cheap to make: nothing is read until first use.
///
/// Lock order: `inner` may be held while `paths` is taken, never the other way round
/// ([`SecretStore::configure`] takes only `paths`, and marks the store `stale`).
pub(crate) struct SecretStore {
    paths: Mutex<KeyPaths>,
    /// The key settings changed: the next use loads again.
    stale: AtomicBool,
    var: EnvFn,
    /// Make the data-directory key when the table is empty (the server; `secrets status` never
    /// makes one).
    create: bool,
    /// `secrets status`: nothing is written (no rotation finished or dropped, nothing
    /// re-encrypted, no database created); rows the previous key opens count as readable.
    read_only: bool,
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

/// The associated data: `"telltale-secret\x01" ‖ key_id ‖ be16(len kind) ‖ kind ‖
/// be16(len name) ‖ name ‖ be64(epoch) ‖ be64(seq)` (ADR-903 §3 and note 39: the lengths keep
/// the row `(text, x)` from reading as `(tex, tx)`).
fn aad(key_id: &[u8], kind: &str, name: &str, stamp: Stamp) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_PREFIX.len() + 8 + 4 + kind.len() + name.len() + 16);
    a.extend_from_slice(AAD_PREFIX);
    a.extend_from_slice(key_id);
    for part in [kind, name] {
        // Kinds are short words and names at most 63 bytes; a longer one never decrypts.
        let len = u16::try_from(part.len()).unwrap_or(u16::MAX);
        a.extend_from_slice(&len.to_be_bytes());
        a.extend_from_slice(part.as_bytes());
    }
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

/// REQ: OPS-014 (ADR-903 §3) — `value` encrypted under `key` for the row `(kind, name, stamp)`.
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

/// REQ: OPS-014 (ADR-903 §3) — `row`'s value under `key`, or how it stands: `Unreadable` when
/// another key made it, `Corrupt` when it fails authentication (a damaged or moved row).
pub(crate) fn open(key: &NodeKey, row: &SecretRow) -> Result<SecretValue, RowHealth> {
    if row.key_id != key.key_id() {
        return Err(RowHealth::Unreadable);
    }
    // REQ: NFR-005 — only the kinds a value is sealed as (a row given another one was moved).
    if !matches!(row.kind.as_str(), "text" | "pem") {
        return Err(RowHealth::Corrupt);
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

/// How a row stands under `keys` (`previous`: a row the previous key opens counts as readable,
/// since the next start re-encrypts it).
fn health_of(keys: &Keys, row: &SecretRow, previous: bool) -> RowHealth {
    if row.deleted {
        return RowHealth::Readable;
    }
    match open(&keys.current, row) {
        Ok(_) => RowHealth::Readable,
        Err(RowHealth::Unreadable) if previous => {
            keys.previous.as_ref().map_or(RowHealth::Unreadable, |p| {
                open(p, row).map_or_else(|h| h, |_| RowHealth::Readable)
            })
        }
        Err(h) => h,
    }
}

/// REQ: OPS-014 (ADR-903 §3) — a rotation interrupted after it wrote `secrets.key.new`: when some
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

    /// REQ: OPS-014 — `telltale secrets status`'s store: it writes nothing (ADR-903 note 39), so
    /// it may run beside the server or a `rotate-key`.
    pub(crate) fn read_only(cfg: &telltale_config::Config, var: EnvFn) -> Self {
        Self {
            read_only: true,
            ..Self::with_env(cfg, var, false, false)
        }
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
            stale: AtomicBool::new(false),
            var,
            create,
            read_only: false,
            data_ephemeral,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// After a reload: new key settings are read at the next use. Takes only `paths` (a load
    /// holds `inner`, then takes `paths`: holding `paths` while taking `inner` here deadlocked
    /// against it), so it never waits for a load either.
    pub(crate) fn configure(&self, cfg: &telltale_config::Config) {
        let new = KeyPaths::of(cfg);
        let changed = {
            let mut p = self.paths.lock().unwrap_or_else(PoisonError::into_inner);
            let changed = *p != new;
            if changed {
                *p = new;
            }
            changed
        };
        if changed {
            self.stale.store(true, Ordering::Release);
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
        let stale = self.stale.swap(false, Ordering::AcqRel);
        let again = stale
            || match g.loaded_at {
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
        self.stale.store(false, Ordering::Release);
        self.load_into(&mut g);
    }

    /// REQ: OPS-014 (ADR-903 §3) — opens the table, finds the keys (making one only for an empty
    /// table), re-encrypts rows under the previous key, and judges every row.
    #[allow(clippy::too_many_lines)] // the load's steps, in order
    fn load_into(&self, g: &mut Inner) {
        let paths = self.paths();
        g.loaded_at = Some(Instant::now());
        g.locked = None;
        g.key_error = None;
        g.healable = false;
        g.under_previous = 0;
        let var = |k: &str| (self.var)(k);
        let db = paths.data_dir.join("state.db");
        // Resolver pods: no table, no key made; a configured key still keys idempotency. A status
        // read of a node that has stored nothing yet creates no database.
        if paths.ephemeral || (self.read_only && g.state.is_none() && !db.exists()) {
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
        // REQ: CLU-015 (ADR-917 point 4) — shadows are sealed under the same keys as the rows, so
        // every rotation step below covers them too.
        let mut shadows = match state.secret_shadows() {
            Ok(v) => v,
            Err(e) => {
                let why = format!("the secrets shadow table: {e}");
                g.key_error = Some(why.clone());
                Self::set_locked(g, why);
                return;
            }
        };
        g.shadows = shadows.iter().map(|r| r.name.clone()).collect();
        if !self.read_only && paths.uses_data_key(&var) {
            let all: Vec<SecretRow> = rows.iter().chain(shadows.iter()).cloned().collect();
            if let Some(note) = recover_rotation(&paths.data_dir, &all) {
                tracing::warn!("secrets key: {note}");
            }
        }
        let keys = match super::load(&paths, &var, self.create && rows.is_empty()) {
            Ok(k) => Arc::new(k),
            Err(e) => {
                let live = rows.iter().filter(|r| !r.deleted).count();
                let missing =
                    !rows.is_empty() && paths.uses_data_key(&var) && !paths.data_key().exists();
                g.healable = missing;
                let why = if missing {
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
            if !self.read_only {
                reencrypt(&state, &keys.current, prev, &mut rows, &mut shadows);
            }
            let pid = prev.key_id();
            g.under_previous = rows
                .iter()
                .chain(shadows.iter())
                .filter(|r| !r.deleted && r.key_id == pid)
                .count();
        }
        let read_only = self.read_only;
        g.rows = rows
            .into_iter()
            .map(|r| {
                let health = health_of(&keys, &r, read_only);
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
            g.healable = true;
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
            under_previous: g.under_previous,
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
                    orphaned: c.row.orphaned,
                })
                .collect(),
            shadows: g.shadows.iter().cloned().collect(),
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
        if c.row.orphaned {
            return Err(Unavailable::Orphaned);
        }
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

    /// REQ: OPS-014 (ADR-903 §4) — whether this node can read the secret `name`, judged from the
    /// row's state (nothing is decrypted for it).
    pub(crate) fn readable(&self, name: &str) -> Result<(), Unavailable> {
        if self.paths().ephemeral {
            return Err(Unavailable::Ephemeral);
        }
        let g = self.ready();
        let Some(c) = g.rows.get(name).filter(|c| !c.row.deleted) else {
            return Err(Unavailable::NotSet);
        };
        if c.row.orphaned {
            return Err(Unavailable::Orphaned);
        }
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

    /// REQ: OPS-014 (ADR-903 §2) — stores `value` as `name`, stamped in `epoch` (0 on a
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
            orphaned: false,
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

    /// REQ: OPS-014 (ADR-903 §2) — deletes `name`, leaving a tombstone with a new stamp. `None`:
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
        let clean = state
            .put_secret_row(&row, now)
            .map_err(|e| StoreError::Db(e.to_string()))?;
        if !clean {
            warn_wal("a deleted secret's ciphertext");
        }
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

    /// REQ: OPS-014 (ADR-903 §3, the one exception) — a locked replica whose rows are all the
    /// cluster's drops them and starts over with a working key, so it can fetch them again from
    /// the primary (T23.5). Only for the data-directory key: a configured key that can't be read
    /// is fixed by whoever configured it. Returns how many rows went, or why nothing was done.
    pub(crate) fn heal_as_replica(&self) -> Result<usize, String> {
        let paths = self.paths();
        let var = |k: &str| (self.var)(k);
        if self.read_only {
            return Err("a status read changes nothing".to_owned());
        }
        let mut g = self.ready();
        if g.locked.is_none() {
            return Err("the store isn't locked".to_owned());
        }
        // A key file or database that can't be read is fixed, not replaced: a new key couldn't
        // be made beside the existing file, and the rows would be gone for nothing.
        if !g.healable {
            return Err(format!(
                "locked for a reason a new key doesn't fix: {}",
                g.locked.as_deref().unwrap_or("no key")
            ));
        }
        if paths.ephemeral || !paths.uses_data_key(&var) {
            return Err("only a data-directory key is replaced".to_owned());
        }
        if g.rows.is_empty() || g.rows.values().any(|c| c.row.origin != "cluster") {
            return Err("some rows were made on this node: they aren't dropped".to_owned());
        }
        // REQ: CLU-015 (ADR-917 points 4, 8) — an orphan isn't the primary's, so no fetch brings it
        // back, and a local shadow is this node's own value: neither is dropped.
        if g.rows.values().any(|c| c.row.orphaned) {
            return Err(
                "some rows are orphaned (kept, never dropped): they stay as they are".to_owned(),
            );
        }
        let Some(state) = g.state.clone() else {
            return Err("no state database".to_owned());
        };
        let shadows = state.secret_shadows().map_err(|e| e.to_string())?;
        if shadows.iter().any(|s| s.origin == "local") {
            return Err("a local value is shadowed by a cluster row: it isn't dropped".to_owned());
        }
        let n = state.clear_secret_rows().map_err(|e| e.to_string())?;
        tracing::warn!(
            dropped = n,
            stale_shadows = shadows.len(),
            "secrets store: this replica couldn't read the cluster's secrets; it dropped them (and the older copies it kept) and fetches them again from the primary"
        );
        g.rows.clear();
        self.load_into(&mut g);
        Ok(n)
    }

    /// REQ: OPS-014 (ADR-903 §2) — the secrets head: the highest stamp, and BLAKE3 over the
    /// sorted `(name, kind, stamp, deleted)` list (no value, no value hash).
    pub(crate) fn head(&self) -> (Stamp, [u8; 32]) {
        let g = lock(&self.inner);
        live_head(&g.rows)
    }
}

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
        orphaned: r.orphaned,
    }
}

/// The head of a set of rows (they come sorted by name from the table and the cache).
pub(crate) fn head_of<'a>(rows: impl Iterator<Item = &'a SecretRow>) -> (Stamp, [u8; 32]) {
    head_from(rows.map(|r| (r.name.as_str(), r.kind.as_str(), r.stamp, r.deleted)))
}

/// REQ: CLU-015 (ADR-903 §6) — the head of `(name, kind, stamp, deleted)` entries, in any order:
/// the highest stamp, and BLAKE3 over the sorted list. A receiver recomputes it from what it was
/// sent, so a changed or dropped entry shows.
pub(crate) fn head_from<'a>(
    rows: impl Iterator<Item = (&'a str, &'a str, Stamp, bool)>,
) -> (Stamp, [u8; 32]) {
    let mut h = blake3::Hasher::new();
    let mut top = Stamp::default();
    let mut sorted: Vec<(&str, &str, Stamp, bool)> = rows.collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (name, kind, stamp, deleted) in sorted {
        top = top.max(stamp);
        for part in [name.as_bytes(), b"\0", kind.as_bytes(), b"\0"] {
            h.update(part);
        }
        h.update(&stamp.epoch.to_be_bytes());
        h.update(&stamp.seq.to_be_bytes());
        h.update(&[u8::from(deleted)]);
    }
    (top, *h.finalize().as_bytes())
}

/// REQ: CLU-015 (ADR-903 §6) — one row as a replica, or a heal, receives it. `value` is set for a
/// live row the sender could read; `held` marks a row the sender holds but couldn't decrypt.
#[derive(Debug)]
pub(crate) struct Remote {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) stamp: Stamp,
    pub(crate) deleted: bool,
    pub(crate) held: bool,
    pub(crate) updated: u64,
    pub(crate) updated_by: String,
    pub(crate) value: Option<SecretValue>,
}

/// REQ: CLU-015 — one page of a sender's rows (sorted by name), with the head of all of them.
#[derive(Debug)]
pub(crate) struct Page {
    pub(crate) head: (Stamp, [u8; 32]),
    pub(crate) items: Vec<Remote>,
    pub(crate) more: bool,
}

/// REQ: CLU-015 — what applying a batch changed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Applied {
    pub(crate) changed: usize,
    pub(crate) tombstones: usize,
    pub(crate) held: usize,
    pub(crate) orphaned: usize,
    pub(crate) shadowed: usize,
    /// REQ: CLU-015 (ADR-917 point 10) — names a listing said were live but this node holds as a
    /// tombstone of an older epoch: the tombstone is kept (a revoked secret is not resurrected),
    /// and the name is reported as a conflict.
    pub(crate) conflicts: Vec<String>,
    /// The head after the batch.
    pub(crate) head: (Stamp, [u8; 32]),
}

/// REQ: CLU-015 (ADR-903 §6) — the sharing of rows between members. Everything here is under the
/// store's lock, and nothing here reads a value into a file or a blob: values exist in memory only.
impl SecretStore {
    /// REQ: CLU-015 — a page of this node's rows, by name after `after`, under `budget` encoded
    /// bytes (at least one row always goes). A live row this node can't read is `held`, with no
    /// value. Shadowed local rows are not part of the cluster's set and never go.
    pub(crate) fn export_page(
        &self,
        after: Option<&str>,
        budget: usize,
    ) -> Result<Page, Unavailable> {
        if self.paths().ephemeral {
            return Err(Unavailable::Ephemeral);
        }
        let g = self.ready();
        if let Some(why) = &g.locked {
            return Err(Unavailable::Locked(why.clone()));
        }
        let Some(keys) = g.keys.clone() else {
            return Err(Unavailable::Locked(
                g.key_error.clone().unwrap_or_else(|| "no key".to_owned()),
            ));
        };
        let head = live_head(&g.rows);
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut items = Vec::new();
        let mut used = 0usize;
        let mut more = false;
        // An orphan (REQ: CLU-015) isn't the cluster's: it's not sent, and not in the head.
        for c in g
            .rows
            .range::<str, _>((start, Bound::Unbounded))
            .map(|(_, c)| c)
            .filter(|c| !c.row.orphaned)
        {
            let row = &c.row;
            let value = if row.deleted || c.health != RowHealth::Readable {
                None
            } else {
                open(&keys.current, row).ok()
            };
            let is_held = !row.deleted && value.is_none();
            let size = 128
                + row.name.len()
                + row.kind.len()
                + row.updated_by.len()
                + value.as_ref().map_or(0, |v| v.expose().len());
            if !items.is_empty() && used + size > budget {
                more = true;
                break;
            }
            used += size;
            items.push(Remote {
                name: row.name.clone(),
                kind: row.kind.clone(),
                stamp: row.stamp,
                deleted: row.deleted,
                held: is_held,
                updated: row.updated,
                updated_by: row.updated_by.clone(),
                value,
            });
        }
        Ok(Page { head, items, more })
    }

    /// REQ: CLU-015 (ADR-903 §6) — applies a verified set of a primary's rows: each re-encrypted
    /// under this node's key, upserted by stamp (a higher stamp wins, a tombstone deletes), a
    /// local row displaced into the shadow table, and cluster rows the primary doesn't list and an
    /// older epoch stamped after `base` marked orphaned. Rows are never deleted by absence.
    ///
    /// `authoritative` is false for an emergency primary's answer (ADR-903 §4, ADR-917 point 11):
    /// it changes nothing it doesn't have to. A non-authoritative answer only fills rows by stamp:
    /// no displacement, no shadow, no orphan.
    pub(crate) fn apply_remote(
        &self,
        items: &[Remote],
        primary_epoch: u64,
        authoritative: bool,
        now: u64,
    ) -> Result<Applied, StoreError> {
        if self.paths().ephemeral {
            return Err(StoreError::Ephemeral);
        }
        let mut g = self.ready();
        apply_inner(&mut g, items, primary_epoch, authoritative, now)
    }

    /// REQ: CLU-015 (ADR-903 §6) — at `cluster init` (on the primary), a standalone node's rows
    /// become cluster rows. Returns how many.
    pub(crate) fn adopt_as_cluster(&self) -> Result<usize, String> {
        let mut g = self.ready();
        if let Some(why) = &g.locked {
            return Err(format!("the secrets store is locked: {why}"));
        }
        let Some(state) = g.state.clone() else {
            return Err("no state database".to_owned());
        };
        let n = state.adopt_secret_rows().map_err(|e| e.to_string())?;
        self.load_into(&mut g);
        Ok(n)
    }

    /// REQ: CLU-015 (ADR-903 §6, removal and leave) — the cluster's rows go, and each name a
    /// shadow covers comes back as the local row it displaced. Returns `(deleted, restored)`.
    pub(crate) fn purge_cluster(&self) -> Result<(usize, usize), String> {
        let mut g = self.ready();
        let Some(state) = g.state.clone() else {
            return Err("no state database".to_owned());
        };
        let out = state.purge_cluster_secrets().map_err(|e| e.to_string())?;
        self.load_into(&mut g);
        Ok(out)
    }

    /// REQ: CLU-015 — this node's own rows (made before it joined), decrypted for adoption by the
    /// primary. Shadowed and orphaned rows are not offered.
    pub(crate) fn local_rows(&self) -> Result<Vec<(String, Kind, SecretValue)>, String> {
        let g = self.ready();
        let Some(keys) = g.keys.clone() else {
            return Err(g.locked.clone().unwrap_or_else(|| "no key".to_owned()));
        };
        let mut out = Vec::new();
        for c in g.rows.values() {
            let r = &c.row;
            if r.deleted || r.origin != "local" || r.orphaned || c.health != RowHealth::Readable {
                continue;
            }
            if let (Ok(kind), Ok(v)) = (Kind::parse(&r.kind), open(&keys.current, r)) {
                out.push((r.name.clone(), kind, v));
            }
        }
        Ok(out)
    }

    /// REQ: CLU-015 — every row this node holds (tombstones too): `(name, stamp, deleted)`. A
    /// reverse heal needs each one from a replica at the same stamp.
    pub(crate) fn heal_needs(&self) -> Vec<(String, Stamp, bool)> {
        lock(&self.inner)
            .rows
            .values()
            .filter(|c| !c.row.orphaned)
            .map(|c| (c.row.name.clone(), c.row.stamp, c.row.deleted))
            .collect()
    }

    /// REQ: CLU-015 (ADR-903 §3, §6) — the primary's reverse heal: a locked store whose rows are
    /// all the cluster's (and a data-directory key that's missing) is replaced by a new key, and
    /// every row is filled from `items`, a replica's rows at the stamps the primary holds. Refused
    /// unless every row is covered, so no row is lost to a partial answer.
    pub(crate) fn heal_with(&self, items: &[Remote], now: u64) -> Result<Applied, String> {
        let paths = self.paths();
        let var = |k: &str| (self.var)(k);
        if self.read_only {
            return Err("a status read changes nothing".to_owned());
        }
        let mut g = self.ready();
        if g.locked.is_none() {
            return Err("the store isn't locked".to_owned());
        }
        if !g.healable {
            return Err(format!(
                "locked for a reason a new key doesn't fix: {}",
                g.locked.as_deref().unwrap_or("no key")
            ));
        }
        if paths.ephemeral || !paths.uses_data_key(&var) {
            return Err("only a data-directory key is replaced".to_owned());
        }
        if g.rows.values().any(|c| c.row.origin != "cluster") {
            return Err("some rows were made on this node: they aren't replaced".to_owned());
        }
        // REQ: CLU-015 (ADR-917 points 4, 8; L4) — orphans and local shadows are kept, never
        // dropped: an orphan isn't in any replica's listing, and a shadow is a local value.
        if g.rows.values().any(|c| c.row.orphaned) {
            return Err(
                "some rows are orphaned (kept, never dropped): they stay as they are".to_owned(),
            );
        }
        let Some(state) = g.state.clone() else {
            return Err("no state database".to_owned());
        };
        if state
            .secret_shadows()
            .map_err(|e| e.to_string())?
            .iter()
            .any(|s| s.origin == "local")
        {
            return Err("a local value is shadowed by a cluster row: it stays as it is".to_owned());
        }
        for c in g.rows.values().filter(|c| !c.row.orphaned) {
            let covered = items.iter().any(|it| {
                it.name == c.row.name
                    && it.stamp == c.row.stamp
                    && it.deleted == c.row.deleted
                    && (it.deleted || it.value.is_some())
            });
            if !covered {
                return Err(format!(
                    "no replica holds `{}` at its stamp, so the locked rows stay as they are",
                    c.row.name
                ));
            }
        }
        let n = state.clear_secret_rows().map_err(|e| e.to_string())?;
        tracing::warn!(
            dropped = n,
            "secrets store: this primary's rows were unreadable; a replica holds them, so they're filled in again under a new key"
        );
        g.rows.clear();
        self.load_into(&mut g);
        if let Some(why) = g.locked.clone() {
            return Err(format!("still locked after the new key: {why}"));
        }
        apply_inner(&mut g, items, 0, true, now).map_err(|e| e.to_string())
    }

    /// Live rows this node can't read (encrypted under a key it doesn't have, or damaged).
    pub(crate) fn unreadable_count(&self) -> usize {
        lock(&self.inner)
            .rows
            .values()
            .filter(|c| !c.row.deleted && c.health != RowHealth::Readable)
            .count()
    }
}

/// REQ: CLU-015 (ADR-903 §6) — [`SecretStore::apply_remote`] under the store's lock.
///
/// The primary's listing is the cluster's set. A listed name takes the primary's row when this
/// node holds none, holds a standalone row (shadowed), holds a row an older epoch stamped (the
/// primary's copy supersedes it, and the old one goes to its `cluster` shadow slot), or holds an
/// older stamp of the same epoch. A cluster tombstone of an older epoch is not resurrected by a
/// listing: it stays, and the name is a conflict (ADR-917 point 10). A cluster row this node holds,
/// from an older epoch, that the primary doesn't list is an orphan: kept, flagged, never used.
///
/// A non-authoritative answer (an emergency primary's, ADR-917 point 11) fills a name only where
/// this node holds no row, or an older cluster row, and changes nothing else.
#[allow(clippy::too_many_lines)] // the rules in the order the ADR states them
fn apply_inner(
    g: &mut Inner,
    items: &[Remote],
    primary_epoch: u64,
    authoritative: bool,
    now: u64,
) -> Result<Applied, StoreError> {
    if let Some(why) = &g.locked {
        return Err(StoreError::Locked(why.clone()));
    }
    let (Some(keys), Some(state)) = (g.keys.clone(), g.state.clone()) else {
        return Err(StoreError::Locked(
            g.key_error.clone().unwrap_or_else(|| "no key".to_owned()),
        ));
    };
    let mut out = Applied::default();
    let mut upserts: BTreeMap<String, SecretRow> = BTreeMap::new();
    let mut shadow: Vec<SecretRow> = Vec::new();
    let mut listed: BTreeSet<&str> = BTreeSet::new();
    for it in items {
        if !telltale_config::secret_refs::valid_name(&it.name) {
            return Err(StoreError::Invalid(ValueError::Name));
        }
        listed.insert(it.name.as_str());
        if it.held {
            // The sender holds it but couldn't read it: this node keeps its own row, as it is.
            out.held += 1;
            continue;
        }
        let kind = Kind::parse(&it.kind).map_err(StoreError::Invalid)?;
        let local = g.rows.get(&it.name).map(|c| c.row.clone());
        let (take, displaced) = if authoritative {
            // REQ: CLU-015 (ADR-917 point 10) — a tombstone of an older epoch is a revocation this
            // node has; a listing that calls the name live doesn't bring the value back.
            if local.as_ref().is_some_and(|l| {
                l.origin == "cluster" && l.deleted && !it.deleted && l.stamp.epoch < primary_epoch
            }) {
                out.conflicts.push(it.name.clone());
                continue;
            }
            let displaced = local.as_ref().is_some_and(|l| {
                // A standalone row, or a stale cluster row of an older epoch whose stamp differs.
                l.origin == "local" || (l.stamp.epoch < primary_epoch && l.stamp != it.stamp)
            });
            let take = match &local {
                None => true,
                Some(l) if l.origin == "local" => true,
                Some(l) if l.stamp.epoch < primary_epoch => l.stamp != it.stamp,
                Some(l) => it.stamp > l.stamp,
            };
            (take, displaced)
        } else {
            // A non-authoritative answer fills by stamp, and displaces nothing.
            let take = match &local {
                None => true,
                Some(l) => l.origin == "cluster" && it.stamp > l.stamp,
            };
            (take, false)
        };
        if !take {
            // The same change, or a newer one held here in this epoch: kept. A listed name is not
            // an orphan.
            if authoritative && let Some(mut l) = local.filter(|l| l.orphaned) {
                l.orphaned = false;
                upserts.insert(it.name.clone(), l);
            }
            continue;
        }
        if displaced && let Some(l) = local {
            // REQ: CLU-015 — a displaced row is kept, not dropped (`secrets_shadow`, one slot per
            // name and origin).
            shadow.push(l);
            out.shadowed += 1;
        }
        let row = if it.deleted {
            SecretRow {
                name: it.name.clone(),
                kind: kind.as_str().to_owned(),
                key_id: Vec::new(),
                nonce: Vec::new(),
                ciphertext: Vec::new(),
                stamp: it.stamp,
                deleted: true,
                origin: "cluster".to_owned(),
                updated: it.updated,
                updated_by: it.updated_by.clone(),
                orphaned: false,
            }
        } else {
            let Some(v) = it.value.as_ref() else {
                return Err(StoreError::Db(format!("no value sent for `{}`", it.name)));
            };
            let sealed = seal(&keys.current, kind.as_str(), &it.name, it.stamp, v)
                .map_err(StoreError::Db)?;
            SecretRow {
                name: it.name.clone(),
                kind: kind.as_str().to_owned(),
                key_id: sealed.key_id,
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext,
                stamp: it.stamp,
                deleted: false,
                origin: "cluster".to_owned(),
                updated: it.updated,
                updated_by: it.updated_by.clone(),
                orphaned: false,
            }
        };
        if it.deleted {
            out.tombstones += 1;
        }
        out.changed += 1;
        upserts.insert(it.name.clone(), row);
    }
    // REQ: CLU-015 (ADR-903 §6) — orphans: a live cluster row an older epoch stamped that the
    // primary doesn't list. Never deleted, never used. An emergency primary's answer says nothing
    // about what it doesn't list, so it flags nothing.
    if authoritative {
        for c in g.rows.values() {
            let r = &c.row;
            if r.deleted
                || r.origin != "cluster"
                || r.orphaned
                || listed.contains(r.name.as_str())
                || upserts.contains_key(&r.name)
            {
                continue;
            }
            if r.stamp.epoch < primary_epoch {
                let mut o = r.clone();
                o.orphaned = true;
                upserts.insert(r.name.clone(), o);
                out.orphaned += 1;
            }
        }
    }
    let rows: Vec<SecretRow> = upserts.into_values().collect();
    if !rows.is_empty() || !shadow.is_empty() {
        let clean = state
            .apply_secret_batch(&rows, &shadow, &[], now)
            .map_err(|e| StoreError::Db(e.to_string()))?;
        if !clean {
            warn_wal("replicated secrets");
        }
    }
    for s in &shadow {
        g.shadows.insert(s.name.clone());
    }
    for r in rows {
        let health = health_of(&keys, &r, false);
        let name = r.name.clone();
        g.rows.insert(name, Cached { row: r, health });
    }
    out.head = live_head(&g.rows);
    Ok(out)
}

// REQ: CLU-015 (ADR-903 §6) — the head of the cluster's rows held here: every row but the
/// orphans (a row the cluster doesn't hold is not part of what members share).
fn live_head(rows: &BTreeMap<String, Cached>) -> (Stamp, [u8; 32]) {
    head_of(rows.values().map(|c| &c.row).filter(|r| !r.orphaned))
}

/// REQ: OPS-014 (ADR-903 §3) — the WAL couldn't be truncated (another connection was reading
/// for longer than the busy timeout): `what` may stay in `state.db-wal` until a later checkpoint.
pub(crate) fn warn_wal(what: &str) {
    tracing::warn!(
        "secrets store: the write-ahead log couldn't be truncated (another connection was busy): {what} may stay in state.db-wal until the next checkpoint"
    );
}

/// REQ: OPS-014 (ADR-903 §3) — rows under the previous key, re-encrypted under the current one
/// (same stamp, new nonce) in one transaction, then the WAL truncated. `rows` is updated in place.
fn reencrypt(
    state: &State,
    current: &NodeKey,
    previous: &NodeKey,
    rows: &mut [SecretRow],
    shadows: &mut [SecretRow],
) {
    let pid = previous.key_id();
    let (Some(redone), Some(redone_shadows)) = (
        reseal(current, previous, rows, &pid),
        reseal(current, previous, shadows, &pid),
    ) else {
        return;
    };
    if redone.is_empty() && redone_shadows.is_empty() {
        return;
    }
    match state.replace_secret_rows(&redone, &redone_shadows) {
        Ok(clean) => {
            if !clean {
                warn_wal("ciphertext under the previous key");
            }
            tracing::info!(
                count = redone.len() + redone_shadows.len(),
                from = %hex(&pid),
                to = %hex(&current.key_id()),
                "re-encrypted stored secrets under the current key; the previous key can be removed"
            );
            for new in redone {
                if let Some(r) = rows.iter_mut().find(|r| r.name == new.name) {
                    *r = new;
                }
            }
            for new in redone_shadows {
                if let Some(r) = shadows
                    .iter_mut()
                    .find(|r| r.name == new.name && r.origin == new.origin)
                {
                    *r = new;
                }
            }
        }
        Err(e) => tracing::error!("re-encrypting stored secrets failed (kept as they were): {e}"),
    }
}

/// The live rows under `previous` (`pid`), re-sealed under `current`: same stamp, new nonce. `None`
/// (and nothing is written) when one of them can't be sealed.
fn reseal(
    current: &NodeKey,
    previous: &NodeKey,
    rows: &[SecretRow],
    pid: &[u8],
) -> Option<Vec<SecretRow>> {
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
                return None;
            }
        }
    }
    Some(redone)
}

/// REQ: OPS-014 (ADR-903 §3) — the store's upkeep on a full member: loaded at start (in a
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

/// REQ: OPS-014, OBS-015 (ADR-903 §3) — the store's health reasons: `secrets_locked` while it
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

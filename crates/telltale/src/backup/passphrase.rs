//! REQ: API-007, OPS-014, NFR-005 (T23.9, ADR-903 §8, ADR-965) — the secrets a backup carries
//! under a passphrase: `data/secrets.enc`.
//!
//! - **Plaintext:** the JSON list `{name, kind, value, updated, updated_by}` (`updated` in Unix
//!   seconds).
//! - **Key:** Argon2id v1.3 from the passphrase, with a 16-byte random salt, 32 bytes out. The
//!   parameters are recorded in the manifest (`kdf`) and bounded on restore.
//! - **Cipher:** ChaCha20-Poly1305 (`ring`), a 12-byte random nonce (recorded in the manifest),
//!   associated data `"telltale-backup-secrets v1" ‖ backup_id`.
//! - **One KDF at a time per process** ([`kdf_slot`]): a second request is refused (the API
//!   answers 429), so a burst of backups can't use more than one KDF's memory (`02 §8`).
//!
//! The passphrase and every value are wiped when dropped.

use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use argon2::{Algorithm, Argon2, Params, Version};
use ring::aead;
use ring::rand::{SecureRandom as _, SystemRandom};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

use crate::secrets::SecretValue;
use crate::secrets::store::MAX_SECRETS;
use crate::secrets::value::Kind;

/// A passphrase is at least this many characters.
pub(crate) const MIN_PASSPHRASE_CHARS: usize = 12;
/// The cost a backup is made with: Argon2's own defaults, the same as password hashing
/// (m = 19 MiB, t = 2, p = 1).
const KDF_M_KIB: u32 = 19_456;
const KDF_T: u32 = 2;
const KDF_P: u32 = 1;
/// What restore accepts (ADR-903 §8: m <= 256 MiB, t <= 10; ADR-965: p <= 8).
pub(crate) const MAX_M_KIB: u32 = 256 * 1024;
pub(crate) const MAX_T: u32 = 10;
pub(crate) const MAX_P: u32 = 8;
const SALT_LEN: usize = 16;
const AAD_PREFIX: &[u8] = b"telltale-backup-secrets v1";
pub(crate) const KDF_NAME: &str = "argon2id";
pub(crate) const AEAD_NAME: &str = "chacha20-poly1305";
/// The archive entry.
pub(crate) const ENTRY: &str = "data/secrets.enc";
/// What the check of a wrong passphrase (or a damaged file) says.
pub(crate) const WRONG: &str = "wrong passphrase or damaged archive";

/// Why a backup couldn't be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BackupError {
    /// Another passphrase backup is deriving its key (the API answers 429).
    Busy,
    Message(String),
}

impl fmt::Display for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => f.write_str(
                "another backup with a passphrase is running on this node; try again in a moment",
            ),
            Self::Message(m) => f.write_str(m),
        }
    }
}

impl From<String> for BackupError {
    fn from(m: String) -> Self {
        Self::Message(m)
    }
}

impl From<BackupError> for String {
    fn from(e: BackupError) -> Self {
        e.to_string()
    }
}

static KDF_BUSY: AtomicBool = AtomicBool::new(false);

/// The one key derivation a process runs at a time; freed when dropped.
pub(crate) struct KdfSlot;

impl Drop for KdfSlot {
    fn drop(&mut self) {
        KDF_BUSY.store(false, Ordering::Release);
    }
}

/// Tests that derive a key hold this, so two of them never meet in the one slot (the ones that
/// test the refusal hold the slot themselves).
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The slot, taken by a test that checks the refusal (waits for any other test holding it).
#[cfg(test)]
pub(crate) fn kdf_slot_for_tests() -> KdfSlot {
    loop {
        if let Some(s) = kdf_slot() {
            return s;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Takes the slot, or `None` while another derivation holds it.
pub(crate) fn kdf_slot() -> Option<KdfSlot> {
    KDF_BUSY
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| KdfSlot)
}

/// One secret on its way into a backup.
#[derive(Debug)]
pub(crate) struct ExportRow {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) value: SecretValue,
    /// Unix seconds.
    pub(crate) updated: u64,
    pub(crate) updated_by: String,
}

/// The secrets to put into a backup and the passphrase to seal them with.
pub(crate) struct SecretsExport {
    pub(crate) passphrase: Zeroizing<String>,
    pub(crate) rows: Vec<ExportRow>,
    /// Live secrets this node holds but couldn't read (another key, damaged): left out.
    pub(crate) unreadable: usize,
}

impl fmt::Debug for SecretsExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretsExport")
            .field("passphrase", &"<redacted>")
            .field("rows", &self.rows.len())
            .field("unreadable", &self.unreadable)
            .finish()
    }
}

/// The key derivation, as recorded in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Kdf {
    pub alg: String,
    /// Argon2's version number (19 = 1.3).
    pub version: u32,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    /// Hex.
    pub salt: String,
}

/// The manifest's `secrets` block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SecretsInfo {
    pub included: bool,
    /// Included: how many are in the archive. Left out: how many the node stored.
    pub count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omitted_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<Kdf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aead: Option<String>,
    /// Hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Random per archive; part of the associated data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<String>,
}

impl SecretsInfo {
    /// No secrets in the archive: `count` were stored on the node, left out for `reason`.
    pub(crate) fn omitted(count: usize, reason: &str) -> Self {
        Self {
            included: false,
            count,
            omitted_reason: Some(reason.to_owned()),
            kdf: None,
            aead: None,
            nonce: None,
            backup_id: None,
        }
    }
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// The passphrase rule (ADR-903 §8).
pub(crate) fn check_passphrase(p: &str) -> Result<(), String> {
    if p.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(format!(
            "the passphrase must be at least {MIN_PASSPHRASE_CHARS} characters"
        ));
    }
    Ok(())
}

/// REQ: API-007 — a recorded cost restore will run: at most 256 MiB, 10 passes and 8 lanes, with
/// a salt and a known algorithm. A manifest is data; it doesn't get to pick any cost.
pub(crate) fn check_kdf(k: &Kdf) -> Result<(), String> {
    if k.alg != KDF_NAME || k.version != 0x13 {
        return Err(format!(
            "the backup's key derivation `{} v{}` isn't one this build knows",
            k.alg, k.version
        ));
    }
    if k.m_kib > MAX_M_KIB || k.t > MAX_T || k.p > MAX_P {
        return Err(format!(
            "the backup asks for a key derivation of {} MiB, {} passes and {} lanes; this build runs at most {} MiB, {MAX_T} passes and {MAX_P} lanes",
            k.m_kib / 1024,
            k.t,
            k.p,
            MAX_M_KIB / 1024
        ));
    }
    if k.m_kib == 0 || k.t == 0 || k.p == 0 {
        return Err("the backup's key derivation has a zero cost".to_owned());
    }
    match unhex(&k.salt) {
        Some(s) if (8..=64).contains(&s.len()) => Ok(()),
        _ => Err("the backup's key derivation has no usable salt".to_owned()),
    }
}

fn derive(pass: &str, k: &Kdf) -> Result<Zeroizing<[u8; 32]>, String> {
    check_kdf(k)?;
    let salt = unhex(&k.salt).ok_or("the salt isn't hex")?;
    let params = Params::new(k.m_kib, k.t, k.p, Some(32)).map_err(|e| e.to_string())?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass.as_bytes(), &salt, &mut *out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

fn cipher(key: &[u8; 32]) -> Result<aead::LessSafeKey, String> {
    aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key)
        .map(aead::LessSafeKey::new)
        .map_err(|_| "the backup cipher couldn't start".to_owned())
}

fn aad(backup_id: &str) -> Vec<u8> {
    let mut a = AAD_PREFIX.to_vec();
    a.extend_from_slice(backup_id.as_bytes());
    a
}

#[derive(Serialize)]
struct RowOut<'a> {
    name: &'a str,
    kind: &'a str,
    value: &'a str,
    updated: u64,
    updated_by: &'a str,
}

/// A value read back: wiped when dropped.
pub(crate) struct Plain(Zeroizing<String>);

impl Plain {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Plain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<'de> Deserialize<'de> for Plain {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|s| Self(Zeroizing::new(s)))
    }
}

/// One secret read out of a backup.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlainRow {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) value: Plain,
    pub(crate) updated: u64,
    pub(crate) updated_by: String,
}

/// REQ: API-007 (ADR-903 §8) — `export` sealed under its passphrase: the bytes of
/// `data/secrets.enc` and the manifest block that describes them. Takes the process's one KDF
/// slot, or says [`BackupError::Busy`].
pub(crate) fn seal(export: &SecretsExport) -> Result<(Vec<u8>, SecretsInfo), BackupError> {
    check_passphrase(&export.passphrase)?;
    let _slot = kdf_slot().ok_or(BackupError::Busy)?;
    let rng = SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; aead::NONCE_LEN];
    let mut id = [0u8; 16];
    for b in [&mut salt[..], &mut nonce[..], &mut id[..]] {
        rng.fill(b)
            .map_err(|_| "no randomness for the backup's salt".to_owned())?;
    }
    let kdf = Kdf {
        alg: KDF_NAME.to_owned(),
        version: 0x13,
        m_kib: KDF_M_KIB,
        t: KDF_T,
        p: KDF_P,
        salt: hex(&salt),
    };
    let backup_id = hex(&id);
    let key = derive(&export.passphrase, &kdf)?;
    let out: Vec<RowOut<'_>> = export
        .rows
        .iter()
        .map(|r| RowOut {
            name: &r.name,
            kind: &r.kind,
            value: r.value.expose(),
            updated: r.updated,
            updated_by: &r.updated_by,
        })
        .collect();
    let plain = Zeroizing::new(serde_json::to_vec(&out).map_err(|e| e.to_string())?);
    let mut buf = Zeroizing::new(Vec::with_capacity(plain.len() + aead::MAX_TAG_LEN));
    buf.extend_from_slice(&plain);
    cipher(&key)?
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad(&backup_id)),
            &mut *buf,
        )
        .map_err(|_| "the secrets couldn't be encrypted".to_owned())?;
    let info = SecretsInfo {
        included: true,
        count: export.rows.len(),
        omitted_reason: None,
        kdf: Some(kdf),
        aead: Some(AEAD_NAME.to_owned()),
        nonce: Some(hex(&nonce)),
        backup_id: Some(backup_id),
    };
    Ok((std::mem::take(&mut *buf), info))
}

/// REQ: API-007 (ADR-903 §8) — the secrets in `ciphertext` (the bytes of `data/secrets.enc`),
/// opened with `passphrase`. A wrong passphrase and a damaged file are the same answer
/// ([`WRONG`]); a cost over the bounds is refused before any work.
pub(crate) fn open(
    ciphertext: &[u8],
    info: &SecretsInfo,
    passphrase: &str,
) -> Result<Vec<PlainRow>, String> {
    let (Some(kdf), Some(aead_name), Some(nonce), Some(id)) =
        (&info.kdf, &info.aead, &info.nonce, &info.backup_id)
    else {
        return Err("the backup's secrets block is incomplete".to_owned());
    };
    if aead_name != AEAD_NAME {
        return Err(format!(
            "the backup's cipher `{aead_name}` isn't one this build knows"
        ));
    }
    check_kdf(kdf)?;
    let nonce: [u8; aead::NONCE_LEN] = unhex(nonce)
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| WRONG.to_owned())?;
    let key = {
        let _slot = kdf_slot().ok_or("another key derivation is running; try again")?;
        derive(passphrase, kdf)?
    };
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let len = cipher(&key)?
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad(id)),
            &mut buf,
        )
        .map_err(|_| WRONG.to_owned())?
        .len();
    buf.truncate(len);
    let rows: Vec<PlainRow> = serde_json::from_slice(&buf).map_err(|_| WRONG.to_owned())?;
    if rows.len() != info.count {
        return Err(WRONG.to_owned());
    }
    Ok(rows)
}

/// REQ: API-007, OPS-014 (ADR-903 §8) — puts `rows` into the staged `state.db` at `db`, sealed
/// under `keys.current` and re-stamped from the start of epoch 0 (the restoring node is
/// standalone: a restored member's cluster identity isn't in the backup), as `local` rows. The
/// counter starts again from this database's, so no stamp repeats one it holds.
pub(crate) fn store_rows(
    db: &Path,
    rows: &[PlainRow],
    keys: &crate::secrets::Keys,
) -> Result<(), String> {
    if rows.len() > MAX_SECRETS {
        return Err(format!(
            "the backup holds {} secrets; at most {MAX_SECRETS} can be stored",
            rows.len()
        ));
    }
    // Check every one before the first is written.
    let mut staged = Vec::with_capacity(rows.len());
    let mut names = std::collections::BTreeSet::new();
    for r in rows {
        let kind = Kind::parse(&r.kind).map_err(|e| format!("secret `{}`: {e}", r.name))?;
        if !telltale_config::secret_refs::valid_name(&r.name) || !names.insert(r.name.clone()) {
            return Err(format!(
                "the backup holds a secret with an invalid or repeated name (`{}`)",
                r.name
            ));
        }
        let value = SecretValue::new(kind, Zeroizing::new(r.value.expose().to_owned()))
            .map_err(|e| format!("secret `{}`: {e}", r.name))?;
        staged.push((r, kind, value));
    }
    let state = telltale_store::state::State::open(db).map_err(|e| e.to_string())?;
    for (r, kind, value) in &staged {
        let stamp = state.next_secret_stamp(0).map_err(|e| e.to_string())?;
        let sealed =
            crate::secrets::store::seal(&keys.current, kind.as_str(), &r.name, stamp, value)?;
        state
            .put_secret_row(
                &telltale_store::state::SecretRow {
                    name: r.name.clone(),
                    kind: kind.as_str().to_owned(),
                    key_id: sealed.key_id,
                    nonce: sealed.nonce,
                    ciphertext: sealed.ciphertext,
                    stamp,
                    deleted: false,
                    origin: "local".to_owned(),
                    updated: r.updated,
                    updated_by: r.updated_by.clone(),
                    orphaned: false,
                },
                r.updated,
            )
            .map_err(|e| e.to_string())?;
    }
    drop(state);
    // The staged file is moved on its own: nothing may stay behind in a write-ahead log.
    let c = rusqlite::Connection::open(db).map_err(|e| e.to_string())?;
    c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .map_err(|e| e.to_string())?;
    Ok(())
}

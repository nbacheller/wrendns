// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: DNS-906, DNS-011 (T40.5, ADR-1108) — RFC 5011 automated update of the root trust anchors.
//!
//! The root zone rolls its key-signing key from time to time. A validator that only knows the
//! anchors compiled into its build stops validating once the old key is gone. RFC 5011 lets it
//! follow the change on its own: it reads the root's DNSKEY set now and then, and
//!
//! - a new key that appears (signed for by a key it already trusts) is only *pending*; it becomes
//!   a trust anchor after it has been seen for the add hold-down of 30 days without a break,
//! - a key that carries the REVOKE bit, with a signature made by that very key, stops being
//!   trusted at once,
//! - a trusted key that is absent from a reading is *missing*, and still trusted (a failed
//!   reading, or a root that has not published it, must not remove an anchor).
//!
//! This module is the state machine ([`apply`], pure and driven by an injected clock), the check
//! of a DNSKEY answer ([`read_answer`], pure), the state file in the data directory, and the
//! shared handle ([`Rollover`]) that holds the trusted set for every validator of the process.
//! Nothing here is on the query path: the validator reads one `Arc` per lookup.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hickory_net::proto::dnssec::rdata::{DNSKEY, DNSSECRData};
use hickory_net::proto::dnssec::{Algorithm, PublicKey as _, PublicKeyBuf, TBS, TrustAnchors};
use hickory_net::proto::op::Message;
use hickory_net::proto::rr::{DNSClass, RData, RecordType};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use wrendns_proto::NameBuf;

use crate::group::Group;
use crate::upstream::Question;

/// RFC 5011 §2.4.1: a new key is trusted after being seen for this long (30 days).
pub const ADD_HOLD_DOWN: u64 = 30 * 86_400;
/// A revoked key is reported (and the health reason shown) for this long (RFC 5011 §2.1's
/// remove hold-down, 30 days); the entry itself is kept so it is never trusted again.
pub const REVOKE_NOTICE: u64 = 30 * 86_400;
/// RFC 5011 §2.3: the shortest and longest time between two readings.
const MIN_REFRESH: u64 = 3_600;
const MAX_REFRESH: u64 = 15 * 86_400;
/// After a failed reading, try again in an hour.
const RETRY: u64 = 3_600;
/// The state file's name in the data directory.
pub const STATE_FILE: &str = "rfc5011.toml";

const FLAG_SEP: u16 = 0x0001;
const FLAG_ZONE: u16 = 0x0100;
const FLAG_REVOKE: u16 = 0x0080;

/// Where a tracked key is in its life (RFC 5011 §4.2; "removed" keys are not tracked).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    /// Seen, not yet trusted: the hold-down is running.
    AddPend,
    /// A trust anchor.
    Valid,
    /// A trust anchor that the last reading did not list. Still trusted.
    Missing,
    /// Revoked by the root. Never trusted again.
    Revoked,
}

impl KeyState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::AddPend => "add_pend",
            Self::Valid => "valid",
            Self::Missing => "missing",
            Self::Revoked => "revoked",
        }
    }

    const fn trusted(self) -> bool {
        matches!(self, Self::Valid | Self::Missing)
    }
}

/// One key the validator tracks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    pub algorithm: u8,
    /// The DNSKEY flags as last seen (257, or 385 once revoked).
    pub flags: u16,
    pub public: Vec<u8>,
    pub state: KeyState,
    /// When it entered this state (Unix seconds); 0 for a built-in anchor never changed.
    pub since: u64,
}

impl KeyEntry {
    /// The RFC 4034 key tag.
    pub fn key_tag(&self) -> u16 {
        tag(self.flags, self.algorithm, &self.public)
    }

    fn same_key(&self, algorithm: u8, public: &[u8]) -> bool {
        self.algorithm == algorithm && self.public == public
    }
}

fn tag(flags: u16, algorithm: u8, public: &[u8]) -> u16 {
    let mut rdata = Vec::with_capacity(4 + public.len());
    rdata.extend_from_slice(&flags.to_be_bytes());
    rdata.push(3);
    rdata.push(algorithm);
    rdata.extend_from_slice(public);
    DNSKEY::calculate_key_tag_internal(&rdata)
}

/// A key found in a DNSKEY reading that passed the checks in [`read_answer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub algorithm: u8,
    pub flags: u16,
    pub public: Vec<u8>,
    /// The REVOKE bit is set and the key signed the set itself (RFC 5011 §2.1).
    pub revoked: bool,
}

/// One tracked key's change, for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub key_tag: u16,
    pub from: Option<KeyState>,
    pub to: Option<KeyState>,
}

/// REQ: DNS-906 (RFC 5011 §4.2) — applies one authenticated reading of the root's keys to the
/// tracked keys at time `now` (Unix seconds); returns what changed. A pure function: the state
/// machine of the module.
pub fn apply(keys: &mut Vec<KeyEntry>, seen: &[Seen], now: u64) -> Vec<Change> {
    let mut changes = Vec::new();
    let mut keep = Vec::with_capacity(keys.len());
    for mut k in keys.drain(..) {
        let s = seen
            .iter()
            .find(|s| k.same_key(s.algorithm, &s.public))
            .cloned();
        let from = k.state;
        let drop_it = match (k.state, &s) {
            // A revoked key stays revoked, and stays on file so a later build that still
            // carries it as a built-in anchor can never trust it again.
            (KeyState::Revoked, _) => false,
            // Pending keys that vanish or are revoked are forgotten (RFC 5011 §4.2).
            (KeyState::AddPend, None) => true,
            (KeyState::AddPend, Some(s)) if s.revoked => true,
            (KeyState::AddPend, Some(_)) => {
                if now >= k.since.saturating_add(ADD_HOLD_DOWN) {
                    k.state = KeyState::Valid;
                    k.since = now;
                }
                false
            }
            (KeyState::Valid | KeyState::Missing, Some(s)) if s.revoked => {
                k.state = KeyState::Revoked;
                k.flags = s.flags;
                k.since = now;
                false
            }
            (KeyState::Valid, Some(_)) => false,
            (KeyState::Valid, None) => {
                k.state = KeyState::Missing;
                k.since = now;
                false
            }
            (KeyState::Missing, Some(_)) => {
                k.state = KeyState::Valid;
                k.since = now;
                false
            }
            (KeyState::Missing, None) => false,
        };
        if drop_it {
            changes.push(Change {
                key_tag: k.key_tag(),
                from: Some(from),
                to: None,
            });
        } else {
            if k.state != from {
                changes.push(Change {
                    key_tag: k.key_tag(),
                    from: Some(from),
                    to: Some(k.state),
                });
            }
            keep.push(k);
        }
    }
    // Keys never seen before start their hold-down (a revoked key we never knew is ignored).
    for s in seen {
        if s.revoked || keep.iter().any(|k| k.same_key(s.algorithm, &s.public)) {
            continue;
        }
        let k = KeyEntry {
            algorithm: s.algorithm,
            flags: s.flags,
            public: s.public.clone(),
            state: KeyState::AddPend,
            since: now,
        };
        changes.push(Change {
            key_tag: k.key_tag(),
            from: None,
            to: Some(KeyState::AddPend),
        });
        keep.push(k);
    }
    *keys = keep;
    changes
}

/// What a DNSKEY answer gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading {
    pub seen: Vec<Seen>,
    /// Seconds until the next reading is due (RFC 5011 §2.3: half the shorter of the records'
    /// TTL and the signatures' remaining life, between an hour and 15 days).
    pub refresh_after: u64,
}

fn serial_ok(now: u32, inception: u32, expiration: u32) -> bool {
    // RFC 1982 serial arithmetic on the 32-bit times.
    #[allow(clippy::cast_possible_wrap)]
    let (after, before) = (
        now.wrapping_sub(inception) as i32,
        expiration.wrapping_sub(now) as i32,
    );
    after >= 0 && before >= 0
}

/// REQ: DNS-906 (RFC 5011 §2.1, §2.2) — reads the root's DNSKEY set out of a response.
///
/// The set counts only if a signature over it verifies with a key in `trusted` (a key the
/// validator trusts now), within its validity times. A key with the REVOKE bit counts as revoked
/// only if a signature over the set verifies with that very key; one that is not self-signed is
/// ignored (a revoke bit set by someone else). Only keys with the SEP bit (key-signing keys)
/// are anchors; zone-signing keys in the set are left alone. `known` lists every tracked key so
/// a bad revoke bit on a key we track is read as "still there, not revoked".
pub fn read_answer(
    bytes: &[u8],
    trusted: &[(u8, Vec<u8>)],
    known: &[(u8, Vec<u8>)],
    now: u64,
) -> Result<Reading, String> {
    let msg = Message::from_vec(bytes).map_err(|e| format!("unreadable answer: {e}"))?;
    if msg.metadata.response_code != hickory_net::proto::op::ResponseCode::NoError {
        return Err(format!(
            "the root DNSKEY lookup answered {}",
            msg.metadata.response_code
        ));
    }
    let root = hickory_net::proto::rr::Name::root();
    let keys: Vec<&hickory_net::proto::rr::Record> = msg
        .answers
        .iter()
        .filter(|r| {
            r.record_type() == RecordType::DNSKEY
                && r.name == root
                && r.dns_class == DNSClass::IN
        })
        .collect();
    if keys.is_empty() {
        return Err("the answer has no root DNSKEY set".into());
    }
    let sigs: Vec<_> = msg
        .answers
        .iter()
        .filter(|r| r.name == root)
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::RRSIG(s)) if s.input().type_covered == RecordType::DNSKEY => {
                Some(s)
            }
            _ => None,
        })
        .collect();
    #[allow(clippy::cast_possible_truncation)] // RRSIG times are the low 32 bits
    let now32 = now as u32;
    // Does a signature over the set verify with this public key?
    let signed_by = |alg: u8, public: &[u8]| -> bool {
        let key = PublicKeyBuf::new(public.to_vec(), Algorithm::from_u8(alg));
        sigs.iter().any(|s| {
            let i = s.input();
            u8::from(i.algorithm) == alg
                && serial_ok(now32, i.sig_inception.get(), i.sig_expiration.get())
                && TBS::from_input(&root, DNSClass::IN, i, keys.iter().copied())
                    .is_ok_and(|tbs| key.verify(tbs.as_ref(), s.sig()).is_ok())
        })
    };
    if !trusted.iter().any(|(a, p)| signed_by(*a, p)) {
        return Err("no trusted key signed the root DNSKEY set; the reading is ignored".into());
    }
    let mut seen = Vec::new();
    let mut ttl = u32::MAX;
    for r in &keys {
        ttl = ttl.min(r.ttl);
        let RData::DNSSEC(DNSSECRData::DNSKEY(k)) = &r.data else {
            continue;
        };
        let flags = k.flags();
        if flags & FLAG_SEP == 0 || flags & FLAG_ZONE == 0 {
            continue;
        }
        let alg = u8::from(k.public_key().algorithm());
        let public = k.public_key().public_bytes().to_vec();
        let mut revoked = flags & FLAG_REVOKE != 0;
        if revoked {
            // The signature must be the revoked key's own (its tag includes the revoke bit).
            let own_tag = tag(flags, alg, &public);
            let own = sigs.iter().any(|s| s.input().key_tag == own_tag) && signed_by(alg, &public);
            if !own {
                if !known.iter().any(|(a, p)| *a == alg && *p == public) {
                    continue; // an unknown key that claims to be revoked: ignored
                }
                revoked = false;
            }
        }
        seen.push(Seen {
            algorithm: alg,
            flags,
            public,
            revoked,
        });
    }
    // The shortest signature life left.
    let mut life = u64::from(u32::MAX);
    for s in &sigs {
        let left = s.input().sig_expiration.get().wrapping_sub(now32);
        life = life.min(u64::from(left));
    }
    let refresh = (u64::from(ttl).min(life) / 2).clamp(MIN_REFRESH, MAX_REFRESH);
    Ok(Reading {
        seen,
        refresh_after: refresh,
    })
}

/// How this node's trust anchors are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Validation is off: nothing is followed.
    Off,
    /// `trust_anchors_file` is set: the file's keys are the anchors, rollover is off.
    File,
    /// The built-in anchors, followed by RFC 5011.
    Following,
}

impl Mode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::File => "file",
            Self::Following => "following",
        }
    }
}

/// One tracked key as shown (API, UI, health).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorView {
    pub key_tag: u16,
    pub algorithm: u8,
    pub flags: u16,
    pub state: KeyState,
    /// When it entered the state (0: built in, never changed).
    pub since: u64,
    /// For a pending key: when the hold-down ends.
    pub trusted_at: Option<u64>,
}

/// The whole state, for the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub mode: Mode,
    pub anchors: Vec<AnchorView>,
    pub last_reading: Option<u64>,
    pub last_error: Option<String>,
    pub next_reading: Option<u64>,
}

struct Inner {
    keys: Vec<KeyEntry>,
    mode: Mode,
    last_reading: Option<u64>,
    last_error: Option<String>,
    next: u64,
}

/// The trust anchors of this process: shared by every validator, kept across reloads.
pub struct Rollover {
    inner: Mutex<Inner>,
    path: Mutex<Option<PathBuf>>,
    /// Counts changes of the trusted set, so a validator can drop what it built on the old one.
    generation: AtomicU64,
    trusted: Mutex<Arc<TrustAnchors>>,
}

impl std::fmt::Debug for Rollover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rollover").finish_non_exhaustive()
    }
}

impl Default for Rollover {
    fn default() -> Self {
        Self::new()
    }
}

fn builtin() -> Vec<KeyEntry> {
    let a = TrustAnchors::default();
    (0..a.len())
        .filter_map(|i| a.get(i))
        .map(|k| KeyEntry {
            algorithm: u8::from(k.algorithm()),
            flags: FLAG_ZONE | FLAG_SEP,
            public: k.public_bytes().to_vec(),
            state: KeyState::Valid,
            since: 0,
        })
        .collect()
}

fn anchors_of(keys: &[KeyEntry]) -> TrustAnchors {
    let mut a = TrustAnchors::empty();
    for k in keys.iter().filter(|k| k.state.trusted()) {
        a.insert(&PublicKeyBuf::new(
            k.public.clone(),
            Algorithm::from_u8(k.algorithm),
        ));
    }
    a
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Rollover {
    /// The built-in anchors, nothing on disk.
    pub fn new() -> Self {
        let keys = builtin();
        let trusted = Arc::new(anchors_of(&keys));
        Self {
            inner: Mutex::new(Inner {
                keys,
                mode: Mode::Off,
                last_reading: None,
                last_error: None,
                next: 0,
            }),
            path: Mutex::new(None),
            generation: AtomicU64::new(0),
            trusted: Mutex::new(trusted),
        }
    }

    /// Exactly these keys, nothing on disk (tests, embedding).
    pub fn from_keys(keys: Vec<KeyEntry>) -> Self {
        let r = Self::new();
        let trusted = Arc::new(anchors_of(&keys));
        r.inner.lock().keys = keys;
        *r.trusted.lock() = trusted;
        r
    }

    /// Keeps the state in `dir` from now on, starting from what is there. A file that can't be
    /// read or understood is set aside (`.corrupt`), a warning is logged, and the built-in
    /// anchors are used.
    pub fn persist_to(&self, dir: &Path) {
        let path = dir.join(STATE_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => match parse_state(&text) {
                Ok(keys) => {
                    tracing::info!(path = %path.display(), keys = keys.len(), "DNSSEC: trust anchor state loaded");
                    self.replace_keys(keys);
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "DNSSEC: the trust anchor state file is not usable; using the built-in anchors");
                    let aside = dir.join(format!("{STATE_FILE}.corrupt"));
                    let _ = std::fs::rename(&path, aside);
                    self.replace_keys(builtin());
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "DNSSEC: can't read the trust anchor state file; using the built-in anchors");
            }
        }
        *self.path.lock() = Some(path);
    }

    fn replace_keys(&self, mut keys: Vec<KeyEntry>) {
        // Built-in anchors a file predates (a newer build) are trusted like the others; one the
        // file lists, revoked or not, keeps its state.
        for b in builtin() {
            if !keys.iter().any(|k| k.same_key(b.algorithm, &b.public)) {
                keys.push(b);
            }
        }
        let trusted = Arc::new(anchors_of(&keys));
        self.inner.lock().keys = keys;
        *self.trusted.lock() = trusted;
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    /// How the anchors are kept now (the validator sets it from `[dnssec]`).
    pub fn set_mode(&self, mode: Mode) {
        self.inner.lock().mode = mode;
    }

    pub fn mode(&self) -> Mode {
        self.inner.lock().mode
    }

    /// The trusted keys and the generation they belong to.
    pub fn current(&self) -> (u64, Arc<TrustAnchors>) {
        let t = self.trusted.lock();
        (self.generation.load(Ordering::Relaxed), Arc::clone(&t))
    }

    fn pairs(keys: &[KeyEntry], only_trusted: bool) -> Vec<(u8, Vec<u8>)> {
        keys.iter()
            .filter(|k| !only_trusted || k.state.trusted())
            .map(|k| (k.algorithm, k.public.clone()))
            .collect()
    }

    /// REQ: DNS-906 — takes one DNSKEY answer at time `now`: checks it, applies it, saves the
    /// state and swaps the trusted set if it changed. Returns what changed.
    pub fn ingest(&self, bytes: &[u8], now: u64) -> Result<Vec<Change>, String> {
        let (trusted, known) = {
            let g = self.inner.lock();
            (Self::pairs(&g.keys, true), Self::pairs(&g.keys, false))
        };
        let reading = match read_answer(bytes, &trusted, &known, now) {
            Ok(r) => r,
            Err(e) => {
                let mut g = self.inner.lock();
                g.last_error = Some(e.clone());
                g.next = now + RETRY;
                return Err(e);
            }
        };
        let (changes, snapshot, trusted_set) = {
            let mut g = self.inner.lock();
            let changes = apply(&mut g.keys, &reading.seen, now);
            g.last_reading = Some(now);
            g.last_error = None;
            g.next = now + reading.refresh_after;
            (changes, g.keys.clone(), anchors_of(&g.keys))
        };
        if !changes.is_empty() {
            // The trusted set is swapped only when it differs: a key in hold-down changes
            // nothing the validator uses.
            let differs = {
                let mut t = self.trusted.lock();
                if t.len() == trusted_set.len() && same_set(&t, &trusted_set) {
                    false
                } else {
                    *t = Arc::new(trusted_set);
                    true
                }
            };
            if differs {
                self.generation.fetch_add(1, Ordering::Relaxed);
            }
            for c in &changes {
                tracing::warn!(key_tag = c.key_tag, from = ?c.from, to = ?c.to, "DNSSEC: root trust anchor change (RFC 5011)");
            }
            self.save(&snapshot);
        }
        Ok(changes)
    }

    fn save(&self, keys: &[KeyEntry]) {
        let Some(path) = self.path.lock().clone() else {
            return;
        };
        if let Err(e) = write_state(&path, keys) {
            tracing::warn!(path = %path.display(), error = %e, "DNSSEC: can't save the trust anchor state");
        }
    }

    /// Whether a reading is due at `now` (the first one is due at once).
    pub fn due(&self, now: u64) -> bool {
        now >= self.inner.lock().next
    }

    /// REQ: DNS-906 — asks `group` for the root's DNSKEY set and applies it at `now`.
    pub async fn read_through(
        &self,
        group: &Arc<Group>,
        budget: Duration,
        now: u64,
    ) -> Result<Vec<Change>, String> {
        let question = Question {
            name: NameBuf::default(),
            qtype: 48,
            qclass: 1,
            dnssec_ok: true,
            checking_disabled: true,
            client_subnet: 0,
        };
        match group.resolve(question, budget).await {
            Ok(a) => self.ingest(&a.bytes, now),
            Err(e) => {
                let e = format!("the root DNSKEY lookup failed: {e}");
                let mut g = self.inner.lock();
                g.last_error = Some(e.clone());
                g.next = now + RETRY;
                Err(e)
            }
        }
    }

    pub fn status(&self) -> Status {
        let g = self.inner.lock();
        let following = g.mode == Mode::Following;
        Status {
            mode: g.mode,
            anchors: g
                .keys
                .iter()
                .map(|k| AnchorView {
                    key_tag: k.key_tag(),
                    algorithm: k.algorithm,
                    flags: k.flags,
                    state: k.state,
                    since: k.since,
                    trusted_at: (k.state == KeyState::AddPend)
                        .then(|| k.since.saturating_add(ADD_HOLD_DOWN)),
                })
                .collect(),
            last_reading: g.last_reading,
            last_error: g.last_error.clone(),
            next_reading: following.then_some(g.next),
        }
    }

    /// REQ: DNS-906 — the health reasons: `(code, text)`; empty unless following and a key is in
    /// hold-down or was revoked within [`REVOKE_NOTICE`].
    pub fn reasons(&self, now: u64) -> Vec<(&'static str, String)> {
        let g = self.inner.lock();
        if g.mode != Mode::Following {
            return Vec::new();
        }
        let mut out = Vec::new();
        for k in &g.keys {
            match k.state {
                KeyState::AddPend => out.push((
                    "dnssec_anchor_pending",
                    format!(
                        "the root published a new key (tag {}); it becomes a trust anchor after its 30-day hold-down ends ({} days left). DNS is unaffected",
                        k.key_tag(),
                        k.since.saturating_add(ADD_HOLD_DOWN).saturating_sub(now).div_ceil(86_400)
                    ),
                )),
                KeyState::Revoked if now < k.since.saturating_add(REVOKE_NOTICE) => out.push((
                    "dnssec_anchor_revoked",
                    format!(
                        "the root revoked the trust anchor with key tag {}; it is no longer trusted",
                        k.key_tag()
                    ),
                )),
                _ => {}
            }
        }
        out
    }
}

fn same_set(a: &TrustAnchors, b: &TrustAnchors) -> bool {
    (0..a.len()).all(|i| a.get(i).is_some_and(|k| b.contains(k)))
}

#[derive(Serialize, Deserialize)]
struct StateFile {
    version: u32,
    #[serde(default)]
    key: Vec<StateKey>,
}

#[derive(Serialize, Deserialize)]
struct StateKey {
    algorithm: u8,
    flags: u16,
    public: String,
    state: KeyState,
    since: u64,
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn parse_state(text: &str) -> Result<Vec<KeyEntry>, String> {
    let f: StateFile = toml::from_str(text).map_err(|e| e.to_string())?;
    if f.version != 1 {
        return Err(format!("unknown state file version {}", f.version));
    }
    if f.key.is_empty() {
        return Err("the state file lists no keys".into());
    }
    f.key
        .into_iter()
        .map(|k| {
            let public = unhex(&k.public).filter(|p| !p.is_empty());
            let public = public.ok_or_else(|| "a key is not valid hexadecimal".to_owned())?;
            Ok(KeyEntry {
                algorithm: k.algorithm,
                flags: k.flags,
                public,
                state: k.state,
                since: k.since,
            })
        })
        .collect()
}

fn write_state(path: &Path, keys: &[KeyEntry]) -> std::io::Result<()> {
    let f = StateFile {
        version: 1,
        key: keys
            .iter()
            .map(|k| StateKey {
                algorithm: k.algorithm,
                flags: k.flags,
                public: hex(&k.public),
                state: k.state,
                since: k.since,
            })
            .collect(),
    };
    let text = toml::to_string(&f).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hickory_net::proto::dnssec::crypto::Ed25519SigningKey;
    use hickory_net::proto::dnssec::rdata::RRSIG;
    use hickory_net::proto::dnssec::{DnssecSigner, SigningKey};
    use hickory_net::proto::rr::{Name, Record, RecordSet};

    const DAY: u64 = 86_400;
    /// An arbitrary "now".
    const T0: u64 = 1_800_000_000;

    fn der(b: &[u8]) -> rustls::pki_types::PrivatePkcs8KeyDer<'static> {
        rustls::pki_types::PrivatePkcs8KeyDer::from(b.to_vec())
    }

    struct Ksk {
        pkcs8: Vec<u8>,
        dnskey: DNSKEY,
    }

    fn ksk() -> Ksk {
        let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap().secret_pkcs8_der().to_vec();
        let key = Ed25519SigningKey::from_pkcs8(&der(&pkcs8)).unwrap();
        let dnskey = DNSKEY::new(true, true, false, key.to_public_key().unwrap());
        Ksk { pkcs8, dnskey }
    }

    impl Ksk {
        fn entry(&self, state: KeyState, since: u64) -> KeyEntry {
            KeyEntry {
                algorithm: u8::from(self.dnskey.public_key().algorithm()),
                flags: 257,
                public: self.dnskey.public_key().public_bytes().to_vec(),
                state,
                since,
            }
        }
        fn signer(&self, revoked: bool) -> DnssecSigner {
            let dk = if revoked {
                DNSKEY::with_flags(385, self.dnskey.public_key().clone())
            } else {
                self.dnskey.clone()
            };
            DnssecSigner::new(
                dk,
                Box::new(Ed25519SigningKey::from_pkcs8(&der(&self.pkcs8)).unwrap()),
                Name::root(),
                Duration::from_secs(14 * DAY),
            )
        }
    }

    /// A DNSKEY response at time `at` holding `keys` (`true`: with the REVOKE bit), signed by
    /// each of `signers` (`true`: as the revoked form of the key).
    fn answer(keys: &[(&Ksk, bool)], signers: &[(&Ksk, bool)], at: u64) -> Vec<u8> {
        let mut set = RecordSet::new(Name::root(), RecordType::DNSKEY, 0);
        let mut msg = Message::query();
        msg.metadata.message_type = hickory_net::proto::op::MessageType::Response;
        for (k, revoked) in keys {
            let dk = if *revoked {
                DNSKEY::with_flags(385, k.dnskey.public_key().clone())
            } else {
                k.dnskey.clone()
            };
            let r = Record::from_rdata(
                Name::root(),
                172_800,
                RData::DNSSEC(DNSSECRData::DNSKEY(dk)),
            );
            set.insert(r.clone(), 0);
            msg.add_answer(r);
        }
        let inception =
            time::OffsetDateTime::from_unix_timestamp(i64::try_from(at).unwrap() - 3_600).unwrap();
        for (s, revoked) in signers {
            let sig =
                RRSIG::from_rrset(&set, DNSClass::IN, inception, &s.signer(*revoked)).unwrap();
            msg.add_answer(Record::from_rdata(
                Name::root(),
                172_800,
                RData::DNSSEC(DNSSECRData::RRSIG(sig)),
            ));
        }
        msg.to_vec().unwrap()
    }

    fn state_of(r: &Rollover, k: &Ksk) -> Option<KeyState> {
        let want = k.dnskey.public_key().public_bytes().to_vec();
        r.inner
            .lock()
            .keys
            .iter()
            .find(|e| e.public == want)
            .map(|e| e.state)
    }

    fn trusts(r: &Rollover, k: &Ksk) -> bool {
        r.current().1.contains(k.dnskey.public_key())
    }

    /// REQ: DNS-906 (T40.5 AC1) - a key the root adds is trusted only after the 30-day
    /// hold-down, on a test clock; the old key keeps validating throughout.
    #[test]
    fn dns_906_a_new_key_is_trusted_only_after_the_hold_down() {
        let (old, new) = (ksk(), ksk());
        let r = Rollover::from_keys(vec![old.entry(KeyState::Valid, 0)]);
        let both = |at| answer(&[(&old, false), (&new, false)], &[(&old, false)], at);
        r.ingest(&both(T0), T0).unwrap();
        assert_eq!(state_of(&r, &new), Some(KeyState::AddPend));
        assert!(!trusts(&r, &new));
        assert!(trusts(&r, &old));
        // 29 days later, seen again: still pending.
        let t = T0 + 29 * DAY;
        r.ingest(&both(t), t).unwrap();
        assert_eq!(state_of(&r, &new), Some(KeyState::AddPend));
        assert!(!trusts(&r, &new));
        // The health reason names the hold-down while it runs (only while following).
        assert!(r.reasons(t).is_empty());
        r.set_mode(Mode::Following);
        assert_eq!(r.reasons(t)[0].0, "dnssec_anchor_pending");
        // 30 days: trusted, and the trusted set changed.
        let g = r.current().0;
        let t = T0 + 30 * DAY;
        r.ingest(&both(t), t).unwrap();
        assert_eq!(state_of(&r, &new), Some(KeyState::Valid));
        assert!(trusts(&r, &new) && trusts(&r, &old));
        assert!(
            r.current().0 > g,
            "validators drop what they built on the old set"
        );
        assert!(r.reasons(t).is_empty());
    }

    /// REQ: DNS-906 - a pending key that disappears starts over (it is forgotten).
    #[test]
    fn dns_906_a_pending_key_that_vanishes_is_forgotten() {
        let (old, new) = (ksk(), ksk());
        let r = Rollover::from_keys(vec![old.entry(KeyState::Valid, 0)]);
        r.ingest(
            &answer(&[(&old, false), (&new, false)], &[(&old, false)], T0),
            T0,
        )
        .unwrap();
        let t = T0 + DAY;
        r.ingest(&answer(&[(&old, false)], &[(&old, false)], t), t)
            .unwrap();
        assert_eq!(state_of(&r, &new), None);
    }

    /// REQ: DNS-906 (T40.5 AC2) - a key with the revoke bit that signed the set itself is
    /// removed from the anchors at once.
    #[test]
    fn dns_906_a_self_signed_revocation_removes_the_anchor() {
        let (a, b) = (ksk(), ksk());
        let r = Rollover::from_keys(vec![
            a.entry(KeyState::Valid, 0),
            b.entry(KeyState::Valid, 0),
        ]);
        r.set_mode(Mode::Following);
        // The set is signed by b (trusted) and by a, as the revoked form of itself.
        let msg = answer(&[(&a, true), (&b, false)], &[(&b, false), (&a, true)], T0);
        r.ingest(&msg, T0).unwrap();
        assert_eq!(state_of(&r, &a), Some(KeyState::Revoked));
        assert!(!trusts(&r, &a) && trusts(&r, &b));
        assert_eq!(r.reasons(T0 + DAY)[0].0, "dnssec_anchor_revoked");
        // The notice ends after 30 days; the entry stays so it is never trusted again.
        assert!(r.reasons(T0 + 31 * DAY).is_empty());
        assert_eq!(state_of(&r, &a), Some(KeyState::Revoked));
    }

    /// REQ: DNS-906 (T40.5 AC2) - a revoke bit on a key that did not sign the set is ignored.
    #[test]
    fn dns_906_a_revocation_that_is_not_self_signed_is_ignored() {
        let (a, b) = (ksk(), ksk());
        let r = Rollover::from_keys(vec![
            a.entry(KeyState::Valid, 0),
            b.entry(KeyState::Valid, 0),
        ]);
        // a carries the revoke bit but only b signed the set.
        let msg = answer(&[(&a, true), (&b, false)], &[(&b, false)], T0);
        r.ingest(&msg, T0).unwrap();
        assert_eq!(state_of(&r, &a), Some(KeyState::Valid));
        assert!(trusts(&r, &a));
        // An unknown key claiming to be revoked is not tracked at all.
        let c = ksk();
        let msg = answer(&[(&b, false), (&c, true)], &[(&b, false)], T0 + DAY);
        r.ingest(&msg, T0 + DAY).unwrap();
        assert_eq!(state_of(&r, &c), None);
    }

    /// REQ: DNS-906 - a trusted key the reading does not list is missing, and still trusted.
    #[test]
    fn dns_906_a_missing_key_stays_trusted() {
        let (a, b) = (ksk(), ksk());
        let r = Rollover::from_keys(vec![
            a.entry(KeyState::Valid, 0),
            b.entry(KeyState::Valid, 0),
        ]);
        r.ingest(&answer(&[(&b, false)], &[(&b, false)], T0), T0)
            .unwrap();
        assert_eq!(state_of(&r, &a), Some(KeyState::Missing));
        assert!(trusts(&r, &a));
        // Listed again: valid again.
        let t = T0 + DAY;
        r.ingest(
            &answer(&[(&a, false), (&b, false)], &[(&b, false)], t),
            t,
        )
        .unwrap();
        assert_eq!(state_of(&r, &a), Some(KeyState::Valid));
    }

    /// REQ: DNS-906 - a set that no trusted key signed changes nothing (a forged or stale
    /// answer can't start a hold-down).
    #[test]
    fn dns_906_an_unauthenticated_set_is_ignored() {
        let (old, evil) = (ksk(), ksk());
        let r = Rollover::from_keys(vec![old.entry(KeyState::Valid, 0)]);
        let msg = answer(&[(&evil, false)], &[(&evil, false)], T0);
        assert!(r.ingest(&msg, T0).is_err());
        assert_eq!(state_of(&r, &evil), None);
        assert!(r.status().last_error.is_some());
        // An expired signature is as good as none.
        let msg = answer(&[(&old, false), (&evil, false)], &[(&old, false)], T0);
        assert!(r.ingest(&msg, T0 + 20 * DAY).is_err());
        assert_eq!(state_of(&r, &evil), None);
        // A set that was changed after it was signed doesn't verify either.
        let mut m = Message::from_vec(&answer(&[(&old, false)], &[(&old, false)], T0)).unwrap();
        m.add_answer(Record::from_rdata(
            Name::root(),
            172_800,
            RData::DNSSEC(DNSSECRData::DNSKEY(evil.dnskey.clone())),
        ));
        assert!(r.ingest(&m.to_vec().unwrap(), T0).is_err());
        assert_eq!(state_of(&r, &evil), None);
    }

    /// REQ: DNS-906 (T40.5 AC3) - the state survives a restart; a corrupt file falls back to the
    /// built-in anchors.
    #[test]
    fn dns_906_state_survives_a_restart_and_a_corrupt_file_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let (old, new) = (ksk(), ksk());
        // The first run follows a fixture key set instead of the real root keys.
        let r = Rollover::from_keys(vec![old.entry(KeyState::Valid, 0)]);
        *r.path.lock() = Some(dir.path().join(STATE_FILE));
        r.ingest(
            &answer(&[(&old, false), (&new, false)], &[(&old, false)], T0),
            T0,
        )
        .unwrap();
        assert!(dir.path().join(STATE_FILE).exists());
        // A restart reads it back: the pending key and its start survive.
        let again = Rollover::new();
        again.persist_to(dir.path());
        assert_eq!(state_of(&again, &new), Some(KeyState::AddPend));
        assert_eq!(state_of(&again, &old), Some(KeyState::Valid));
        let pending = again
            .status()
            .anchors
            .into_iter()
            .find(|a| a.state == KeyState::AddPend)
            .unwrap();
        assert_eq!(pending.since, T0);
        assert_eq!(pending.trusted_at, Some(T0 + 30 * DAY));
        // The real built-in anchors stay trusted next to the fixture key.
        assert_eq!(again.current().1.len(), 3);

        // Corrupt: the built-in anchors, the bad file set aside.
        std::fs::write(dir.path().join(STATE_FILE), "this is [not toml").unwrap();
        let fresh = Rollover::new();
        fresh.persist_to(dir.path());
        assert_eq!(fresh.current().1.len(), 2);
        assert_eq!(state_of(&fresh, &new), None);
        assert!(dir.path().join("rfc5011.toml.corrupt").exists());
        // An empty key list is corrupt as well.
        std::fs::write(dir.path().join(STATE_FILE), "version = 1\n").unwrap();
        let fresh = Rollover::new();
        fresh.persist_to(dir.path());
        assert_eq!(fresh.current().1.len(), 2);
    }

    /// REQ: DNS-906 - a revoked built-in anchor stays revoked across a restart (the file wins
    /// over the build's own list).
    #[test]
    fn dns_906_a_revoked_builtin_is_not_resurrected() {
        let dir = tempfile::tempdir().unwrap();
        let mut keys = builtin();
        keys[0].state = KeyState::Revoked;
        keys[0].since = T0;
        write_state(&dir.path().join(STATE_FILE), &keys).unwrap();
        let r = Rollover::new();
        r.persist_to(dir.path());
        assert_eq!(r.current().1.len(), 1);
    }

    /// REQ: DNS-906 - the readings are spaced by RFC 5011 section 2.3 and a failure retries in an
    /// hour.
    #[test]
    fn dns_906_reading_schedule() {
        let old = ksk();
        let r = Rollover::from_keys(vec![old.entry(KeyState::Valid, 0)]);
        assert!(r.due(T0), "the first reading is due at once");
        r.ingest(&answer(&[(&old, false)], &[(&old, false)], T0), T0)
            .unwrap();
        // The records live 2 days, the signatures 14: half the shorter.
        assert!(!r.due(T0 + DAY - 1));
        assert!(r.due(T0 + DAY));
        assert!(r.ingest(b"junk", T0 + DAY).is_err());
        assert!(!r.due(T0 + DAY + 3_599));
        assert!(r.due(T0 + DAY + 3_600));
    }

    /// REQ: DNS-906 - the pure state machine, without signatures.
    #[test]
    fn dns_906_state_machine_transitions() {
        let a = ksk();
        let mut keys = vec![a.entry(KeyState::Valid, 0)];
        let seen = |revoked: bool| {
            vec![Seen {
                algorithm: u8::from(a.dnskey.public_key().algorithm()),
                flags: if revoked { 385 } else { 257 },
                public: a.dnskey.public_key().public_bytes().to_vec(),
                revoked,
            }]
        };
        assert!(apply(&mut keys, &seen(false), T0).is_empty());
        let c = apply(&mut keys, &[], T0 + 1);
        assert_eq!(c[0].to, Some(KeyState::Missing));
        let c = apply(&mut keys, &seen(true), T0 + 2);
        assert_eq!(c[0].to, Some(KeyState::Revoked));
        // Revoked is final.
        assert!(apply(&mut keys, &seen(false), T0 + 3).is_empty());
        assert_eq!(keys[0].state, KeyState::Revoked);
        assert_eq!(keys[0].flags, 385);
    }
}

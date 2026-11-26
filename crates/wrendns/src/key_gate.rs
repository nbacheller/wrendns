// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: DNS-901 (T36.2, spec/08 §6, ADR-1050 point 5) — the known-ID gate: a public listener
//! is never an open resolver. A stream in the gated context (`RequestMeta::gated`, set by a
//! listener with `require_client_id`, and later by relayed streams) is answered only when it
//! carries a known device key. The check is two hash lookups on the data the policy already
//! holds: no allocation on the path of a known key. Refusals are the slow path; they are
//! counted and rate limited per address and per key, with bounded memory.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash};
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use wrendns_net::{RequestMeta, Transport};
use wrendns_policy::ClientTable;

/// Refusals one address may cost per window before it is answered no more (an IPv6 /64 counts as
/// one address), and refusals one key may cost, from any address.
const PER_ADDRESS: u32 = 20;
const PER_KEY: u32 = 60;
const WINDOW: Duration = Duration::from_secs(60);
/// Entries kept per table; a full table is emptied (the limits restart), never grown.
const TABLE_CAP: usize = 4096;

/// What the gate decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// A known key: answer, whatever the source address.
    Known,
    /// Unknown, revoked or missing: refuse.
    Refuse,
    /// Refuse and say nothing more (over the per-address or per-key limit).
    Limited,
}

#[derive(Debug, Default)]
pub(crate) struct KeyGate {
    /// Refusals by transport: DoH (and DoH3), DoT, DoQ.
    refused: [AtomicU64; 3],
    /// Refusals over a limit, which got no answer on DoT and DoQ.
    limited: AtomicU64,
    by_address: Mutex<Table<u128>>,
    by_key: Mutex<Table<u64>>,
    seed: std::collections::hash_map::RandomState,
}

#[derive(Debug)]
struct Table<K>(HashMap<K, (Instant, u32)>);

impl<K> Default for Table<K> {
    fn default() -> Self {
        Self(HashMap::new())
    }
}

impl<K: Hash + Eq> Table<K> {
    /// Counts one refusal for `key`; `false` once it is over `limit` in the current window.
    fn within(&mut self, key: K, limit: u32, now: Instant) -> bool {
        if self.0.len() >= TABLE_CAP && !self.0.contains_key(&key) {
            self.0.clear();
        }
        let e = self.0.entry(key).or_insert((now, 0));
        if now.duration_since(e.0) >= WINDOW {
            *e = (now, 0);
        }
        e.1 = e.1.saturating_add(1);
        e.1 <= limit
    }
}

/// A device key: at least 128 random bits written as 26 or more base32 characters (`a-z`, `2-7`;
/// client IDs are lowercased on arrival). A short or readable ID such as `kids-tablet` is never
/// accepted by the gate, even when a device is configured with it.
pub(crate) fn key_shape(id: &str) -> bool {
    (26..=63).contains(&id.len()) && id.bytes().all(|c| matches!(c, b'a'..=b'z' | b'2'..=b'7'))
}

impl KeyGate {
    /// Decides a gated query. Call only when `meta.gated`.
    pub(crate) fn check(&self, meta: &RequestMeta, clients: &ClientTable) -> Verdict {
        if let Some(id) = &meta.client_id
            && key_shape(id.as_str())
            && clients.has_client_id(id.as_str())
        {
            return Verdict::Known;
        }
        let slot = match meta.transport {
            Transport::Doh => 0,
            Transport::Dot => 1,
            _ => 2,
        };
        self.refused[slot].fetch_add(1, Relaxed);
        let now = Instant::now();
        let addr = match meta.peer.ip().to_canonical() {
            IpAddr::V4(a) => u128::from(u32::from(a)),
            // A /64 is one client.
            IpAddr::V6(a) => u128::from(a) >> 64,
        };
        let ok_addr = lock(&self.by_address).within(addr, PER_ADDRESS, now);
        let ok_key = meta.client_id.as_ref().is_none_or(|id| {
            lock(&self.by_key).within(self.seed.hash_one(id.as_str()), PER_KEY, now)
        });
        if ok_addr && ok_key {
            Verdict::Refuse
        } else {
            self.limited.fetch_add(1, Relaxed);
            Verdict::Limited
        }
    }

    /// `[doh, dot, doq]` refusals and refusals over a limit.
    pub(crate) fn counts(&self) -> ([u64; 3], u64) {
        (
            [
                self.refused[0].load(Relaxed),
                self.refused[1].load(Relaxed),
                self.refused[2].load(Relaxed),
            ],
            self.limited.load(Relaxed),
        )
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

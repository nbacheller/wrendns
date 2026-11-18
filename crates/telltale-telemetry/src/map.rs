//! REQ: OBS-901 (T26.2, ADR-958) — the live network map's sampler: a bounded, weighted window
//! of the last 60 seconds of lookups, kept on the aggregator thread, never on the DNS path.
//!
//! The aggregator thread already drains the worker rings and folds each event into the
//! analytics after the privacy level and the workload keys have been applied. The sampler is
//! one more consumer of that stage: [`Sampler::offer`] is a counter increment for the events it
//! skips and a hash update for the ones it keeps, so the cost does not grow with the query rate.
//!
//! - **Selector.** Counter-based: every Nth event is kept and counts as N (the weight). N is
//!   worked out once per tick (about 250 ms) from the previous tick's total so that at most
//!   `event_rate / 4` events are kept per tick, with a carried remainder, so the run is
//!   deterministic and testable. A burst inside a tick doubles N at once.
//! - **Drops.** Events the worker rings could not take are counted ([`Sampler::tick`] is given
//!   the rings' running total of drops); they join the tick's total before N is computed and
//!   scale the weights, so an overload thins the sample but does not bias it down.
//! - **`min_sample` counts real events.** Every key keeps its unweighted `sampled` count next
//!   to the weighted ones; the classification's idle and confidence checks read that one.
//! - **Bounded.** 12 slots of 5 seconds, at most [`KEYS_PER_SLOT`] keys in a slot and
//!   [`MAX_BYTES`] of estimated entry memory in all; past it a key counts under `other`.
//! - **Privacy.** The level is applied here to what the sampler keeps, as the analytics do
//!   (ADR-102): at 2 and above no client address is kept at all (the key is zero), at 3 nothing
//!   finer than a resolver total (no group, answer kind or upstream).

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::event::Record;
use crate::{QueryEvent, Status};

/// Slots in the window, and seconds in each (12 x 5 s = 60 s).
pub const SLOTS: usize = 12;
pub const SLOT_SECS: u64 = 5;
/// The window the map shows, in seconds.
pub const WINDOW_SECS: u32 = 60;
const SLOTS_U64: u64 = 12;

/// The slot a slot index lands in.
fn slot_pos(idx: u64) -> usize {
    usize::try_from(idx % SLOTS_U64).unwrap_or(0)
}
/// Distinct keys one slot holds; the rest count under `other`.
pub const KEYS_PER_SLOT: usize = 1024;
/// About what one key costs with the hash table's overhead (ADR-958 section 2).
pub const ENTRY_BYTES: usize = 80;
/// The cap on the counters in total: a flood of distinct devices stops adding keys here.
pub const MAX_BYTES: usize = 1 << 20;
/// Lookups kept for the busiest edges' recent samples (64 edges of 20).
pub const RECENT_KEEP: usize = 64 * 20;
/// Most keys a window part carries to the API (the rest fold into `other`): a part must fit the
/// cluster channel's frame, and the snapshot draws 200 devices at most.
pub const PART_KEYS: usize = 512;
/// A tick is at least this long, in milliseconds.
pub const TICK_MS: u64 = 250;

/// What a lookup ended in, as far as the map's edges go.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum AnswerKind {
    /// Answered from the cache (fresh, stale or refreshed).
    Cache,
    /// Answered by an upstream (or failed after asking one).
    Upstream,
    /// A local record, or a special name.
    Local,
    /// Blocked by a filter.
    Blocked,
    /// Refused, rate limited or malformed: counted for the device, no answer edge.
    Other,
}

impl AnswerKind {
    /// The kind a status belongs to; `None` for a lookup that was never answered.
    pub const fn of(status: Status) -> Option<Self> {
        Some(match status {
            Status::Cached | Status::Stale | Status::Refreshed => Self::Cache,
            Status::Forwarded | Status::ServFail => Self::Upstream,
            Status::Local | Status::Special => Self::Local,
            Status::Blocked => Self::Blocked,
            Status::Refused | Status::RateLimited | Status::Malformed => Self::Other,
            Status::Dropped | Status::Drilled => return None,
        })
    }
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Upstream => "upstream",
            Self::Local => "local",
            Self::Blocked => "blocked",
            Self::Other => "other",
        }
    }
}

/// A client address as the sampler keys it (IPv4 mapped into IPv6; all zero when the privacy
/// level hides it). Serialized as 32 hex digits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientKey(pub [u8; 16]);

impl ClientKey {
    pub const HIDDEN: Self = Self([0; 16]);
    pub fn is_hidden(&self) -> bool {
        self.0 == [0; 16]
    }
    /// The address, with an IPv4-mapped one as IPv4.
    pub fn addr(&self) -> std::net::IpAddr {
        let v6 = std::net::Ipv6Addr::from(self.0);
        v6.to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4)
    }
}

impl Serialize for ClientKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(32);
        for b in self.0 {
            let _ = write!(out, "{b:02x}");
        }
        s.serialize_str(&out)
    }
}

impl<'de> Deserialize<'de> for ClientKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        if text.len() != 32 {
            return Err(serde::de::Error::custom("a client key is 32 hex digits"));
        }
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().enumerate() {
            *b = text
                .get(i * 2..i * 2 + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| serde::de::Error::custom("a client key is 32 hex digits"))?;
        }
        Ok(Self(out))
    }
}

/// What a key counted. `sampled` is the number of events actually kept (what `min_sample`
/// reads); every other field is weighted (an estimate of the real count).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    pub sampled: u32,
    pub weighted: u32,
    /// Answers slower than the threshold in force when they were kept.
    pub slow: u32,
    /// SERVFAIL or timeout.
    pub error: u32,
    pub blocked: u32,
    /// Rate-limited lookups.
    pub limited: u32,
}

impl Counts {
    pub fn add(&mut self, o: &Self) {
        self.sampled = self.sampled.saturating_add(o.sampled);
        self.weighted = self.weighted.saturating_add(o.weighted);
        self.slow = self.slow.saturating_add(o.slow);
        self.error = self.error.saturating_add(o.error);
        self.blocked = self.blocked.saturating_add(o.blocked);
        self.limited = self.limited.saturating_add(o.limited);
    }
    pub fn is_empty(&self) -> bool {
        self.sampled == 0
    }
}

/// One key of the window: a device (or the hidden one), its group, what the lookup ended in and
/// the upstream that answered (0: none).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Key {
    client: ClientKey,
    group: u16,
    upstream: u16,
    kind: AnswerKind,
}

/// One row of a [`Window`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub client: ClientKey,
    pub group: u16,
    pub upstream: u16,
    pub kind: AnswerKind,
    pub c: Counts,
}

/// One recently kept lookup (no name: the map never shows one).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recent {
    pub ts_us: u64,
    pub client: ClientKey,
    pub upstream: u16,
    pub kind: AnswerKind,
    /// Receive to send, in milliseconds.
    pub ms: u32,
    /// `Status` as its label's index.
    pub status: u8,
}

/// The window as one node reports it (summed over the slots): what the map is built from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    pub window_secs: u32,
    /// Every Nth event is kept: the current N (1 = nothing is thinned).
    pub sample_rate: u32,
    /// Events the worker rings dropped in the window and the sample was scaled for.
    pub dropped: u64,
    /// The privacy level the keys were kept under.
    pub privacy: u8,
    pub entries: Vec<Entry>,
    /// What did not fit (the key cap, or `PART_KEYS`).
    pub other: Counts,
    /// The last lookups of the busiest edges, oldest first.
    pub recent: Vec<Recent>,
}

/// Settings the sampler follows (from `[map]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Lookups per second to keep (10 to 2,000).
    pub event_rate: u32,
    /// Answers slower than this are slow, in microseconds.
    pub slow_us: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            event_rate: 200,
            slow_us: 250_000,
        }
    }
}

#[derive(Debug, Default)]
struct Slot {
    /// `ts_s / SLOT_SECS` this slot holds (a slot is reused every 60 s).
    start: u64,
    map: HashMap<Key, Counts>,
    other: Counts,
    dropped: u64,
}

/// The sampler. Owned by the aggregator thread behind a mutex ([`crate::Hub::set_map`]).
#[derive(Debug)]
pub struct Sampler {
    settings: Settings,
    /// Every `n`th event is kept; each counts as `n` (scaled for drops).
    n: u32,
    /// Events seen since the last one kept (the carried remainder).
    since: u32,
    /// Events offered, and kept, in this tick; drops folded in at the tick's end.
    tick_seen: u64,
    tick_kept: u32,
    last_tick_ms: u64,
    /// The rings' running drop total at the last tick.
    last_dropped: u64,
    /// Scale for the drops of the previous tick, (offered + dropped) / offered, in 1/65536ths.
    drop_scale: u64,
    /// Fraction of a weight not yet counted, in 1/65536ths (so weights add up exactly).
    carry: u64,
    slots: Vec<Slot>,
    entries: usize,
    recent: VecDeque<Recent>,
    privacy: u8,
    /// The newest slot index seen, for reading the window.
    newest: u64,
}

impl Sampler {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            n: 1,
            since: 0,
            tick_seen: 0,
            tick_kept: 0,
            last_tick_ms: 0,
            last_dropped: 0,
            drop_scale: 1 << 16,
            carry: 0,
            slots: (0..SLOTS).map(|_| Slot::default()).collect(),
            entries: 0,
            recent: VecDeque::new(),
            privacy: 0,
            newest: 0,
        }
    }

    pub fn settings(&self) -> Settings {
        self.settings
    }

    /// New settings from the next event on (the window is kept).
    pub fn configure(&mut self, settings: Settings) {
        self.settings = settings;
    }

    /// The privacy level from the next event on.
    pub fn set_privacy(&mut self, level: u8) {
        self.privacy = level;
    }

    /// Every Nth event is kept now.
    pub fn sample_rate(&self) -> u32 {
        self.n
    }

    /// Most events kept per tick.
    fn per_tick(&self) -> u64 {
        u64::from((self.settings.event_rate / 4).max(1))
    }

    /// One record from the aggregator's analytics stage (already privacy-applied for the name;
    /// the client and the finer keys are reduced here by the level). Upstream exchanges and
    /// unanswered lookups are not part of the map.
    pub fn offer_record(&mut self, r: &Record) {
        if let Record::Query(e, _) = r {
            self.offer(e);
        }
    }

    /// One lookup. A counter increment unless this one is kept.
    pub fn offer(&mut self, e: &QueryEvent) {
        let Some(kind) = AnswerKind::of(e.status) else {
            return;
        };
        self.tick_seen += 1;
        self.since += 1;
        if self.since < self.n {
            return;
        }
        self.since = 0;
        self.tick_kept += 1;
        // A burst inside a tick can't keep more than twice the cap: N doubles at once, and
        // the events kept from now on weigh it (each kept event weighs the N it was kept at).
        if u64::from(self.tick_kept) > self.per_tick().saturating_mul(2) {
            self.n = self.n.saturating_mul(2);
            self.tick_kept = 0;
        }
        let weight = self.weight();
        self.keep(e, kind, weight);
    }

    /// The weight of the event being kept: N scaled for the drops of the previous tick, with
    /// the fraction carried to the next one.
    fn weight(&mut self) -> u32 {
        let x = u64::from(self.n)
            .saturating_mul(self.drop_scale)
            .saturating_add(self.carry);
        self.carry = x & 0xFFFF;
        u32::try_from(x >> 16).unwrap_or(u32::MAX).max(1)
    }

    fn keep(&mut self, e: &QueryEvent, kind: AnswerKind, weight: u32) {
        let level = self.privacy;
        let (client, group, upstream, kind) = if level >= 3 {
            (ClientKey::HIDDEN, 0, 0, AnswerKind::Other)
        } else if level >= 2 {
            (ClientKey::HIDDEN, e.group, e.upstream, kind)
        } else {
            (ClientKey(e.client_ip), e.group, e.upstream, kind)
        };
        let ts_s = e.ts_us / 1_000_000;
        let idx = ts_s / SLOT_SECS;
        self.newest = self.newest.max(idx);
        let pos = slot_pos(idx);
        let slot = &mut self.slots[pos];
        if slot.start != idx {
            if idx < slot.start {
                // Older than the window: late, and of no use.
                return;
            }
            self.entries -= slot.map.len();
            // Gives a flood's memory back once its slot has gone round.
            if slot.map.capacity() > 256 && slot.map.len() < slot.map.capacity() / 4 {
                slot.map = HashMap::new();
            } else {
                slot.map.clear();
            }
            slot.other = Counts::default();
            slot.dropped = 0;
            slot.start = idx;
        }
        let mut c = Counts {
            sampled: 1,
            weighted: weight,
            ..Counts::default()
        };
        if e.status.answered() && e.t_total_us > self.settings.slow_us {
            c.slow = weight;
        }
        match e.status {
            Status::ServFail => c.error = weight,
            Status::Blocked => c.blocked = weight,
            Status::RateLimited => c.limited = weight,
            _ => {}
        }
        let key = Key {
            client,
            group,
            upstream,
            kind,
        };
        if let Some(cur) = slot.map.get_mut(&key) {
            cur.add(&c);
        } else if slot.map.len() < KEYS_PER_SLOT && (self.entries + 1) * ENTRY_BYTES <= MAX_BYTES {
            slot.map.insert(key, c);
            self.entries += 1;
        } else {
            slot.other.add(&c);
        }
        if level < 3 {
            self.recent.push_back(Recent {
                ts_us: e.ts_us,
                client,
                upstream,
                kind,
                ms: e.t_total_us / 1000,
                status: e.status as u8,
            });
            if self.recent.len() > RECENT_KEEP {
                self.recent.pop_front();
            }
        }
    }

    /// Called after each drain with a millisecond clock and the worker rings' running total of
    /// dropped events: at the end of a tick it works out the next N and the drop scale.
    pub fn tick(&mut self, now_ms: u64, dropped_total: u64) {
        if now_ms.saturating_sub(self.last_tick_ms) < TICK_MS {
            return;
        }
        self.last_tick_ms = now_ms;
        let dropped = dropped_total.saturating_sub(self.last_dropped);
        self.last_dropped = dropped_total;
        let offered = self.tick_seen;
        // The drops belong to the newest slot (they have no time of their own).
        if dropped > 0 {
            let pos = slot_pos(self.newest);
            self.slots[pos].dropped = self.slots[pos].dropped.saturating_add(dropped);
        }
        let total = offered.saturating_add(dropped);
        let cap = self.per_tick();
        self.n = u32::try_from(total.div_ceil(cap))
            .unwrap_or(u32::MAX)
            .max(1);
        // Drops scale the weights of the next tick, as far as this one says.
        self.drop_scale = if offered == 0 {
            1 << 16
        } else {
            // At most 64x: a tick that lost nearly everything can't blow the weights up.
            total
                .saturating_mul(1 << 16)
                .div_ceil(offered)
                .min(64 << 16)
        };
        self.tick_seen = 0;
        self.tick_kept = 0;
    }

    /// Estimated memory of the counters, in bytes (what the cap counts).
    pub fn entry_bytes(&self) -> usize {
        self.entries * ENTRY_BYTES
    }

    /// Distinct keys held now.
    pub fn keys(&self) -> usize {
        self.entries
    }

    /// The window as of `now_s` (Unix seconds): the slots from the last 60 seconds, summed per
    /// key; the busiest [`PART_KEYS`] keys, the rest in `other`.
    pub fn window(&self, now_s: u64) -> Window {
        let newest = now_s / SLOT_SECS;
        let oldest = newest.saturating_sub(SLOTS_U64 - 1);
        let mut sum: HashMap<Key, Counts> = HashMap::new();
        let mut other = Counts::default();
        let mut dropped = 0u64;
        for s in &self.slots {
            if s.start < oldest || s.start > newest || (s.map.is_empty() && s.other.is_empty()) {
                continue;
            }
            dropped = dropped.saturating_add(s.dropped);
            other.add(&s.other);
            for (k, c) in &s.map {
                sum.entry(*k).or_default().add(c);
            }
        }
        let mut rows: Vec<(Key, Counts)> = sum.into_iter().collect();
        rows.sort_by(|a, b| {
            b.1.weighted
                .cmp(&a.1.weighted)
                .then_with(|| a.0.client.cmp(&b.0.client))
                .then_with(|| a.0.kind.cmp(&b.0.kind))
                .then_with(|| a.0.upstream.cmp(&b.0.upstream))
        });
        for (_, c) in rows.split_off(rows.len().min(PART_KEYS)) {
            other.add(&c);
        }
        let entries = rows
            .into_iter()
            .map(|(k, c)| Entry {
                client: k.client,
                group: k.group,
                upstream: k.upstream,
                kind: k.kind,
                c,
            })
            .collect();
        let oldest_us = oldest.saturating_mul(SLOT_SECS).saturating_mul(1_000_000);
        Window {
            window_secs: WINDOW_SECS,
            sample_rate: self.n,
            dropped,
            privacy: self.privacy,
            entries,
            other,
            recent: self
                .recent
                .iter()
                .filter(|r| r.ts_us >= oldest_us)
                .copied()
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests;

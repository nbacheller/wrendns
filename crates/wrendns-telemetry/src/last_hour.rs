//! REQ: API-005, OBS-012 (ADR-158) — per-client query counts over the last hour, in 5-minute
//! slots: the Clients page's **Last hour** list (`/stats/top?kind=clients&hour=rolling`). The
//! hourly top lists reset on the clock hour, so a minute past it they showed a minute; this
//! moves with the clock instead.
//!
//! Updated on the telemetry thread with the analytics, never on the query path. One entry per
//! client that asked in the window, at most [`MAX_CLIENTS`] (past it, new clients aren't
//! counted until older ones age out); entries go once their newest slot leaves the window, and
//! the table gives memory back as they do.

use std::collections::HashMap;

/// Slot length (seconds).
pub const SLOT_S: u64 = 300;
/// Slots in the window: the one in progress and the 12 before it, so the window always holds
/// the last full hour (60–65 minutes, whole slots).
pub const SLOTS: usize = 13;
/// The window's longest span (seconds).
pub const WINDOW_S: u64 = SLOT_S * SLOTS_U64;
/// Most clients counted at once.
pub const MAX_CLIENTS: usize = 4_096;

const SLOTS_U64: u64 = SLOTS as u64;

#[derive(Debug, Clone)]
struct Entry {
    /// The newest slot counted (Unix seconds / [`SLOT_S`]).
    last: u64,
    /// Queries by `slot % SLOTS`, for slots `(last - SLOTS, last]`.
    counts: [u32; SLOTS],
}

impl Entry {
    /// Queries in slots `(now - SLOTS, now]`.
    fn total(&self, now: u64) -> u64 {
        (0..SLOTS_U64)
            .filter_map(|k| self.last.checked_sub(k))
            .filter(|s| s + SLOTS_U64 > now && *s <= now)
            .map(|s| u64::from(self.counts[slot_index(s)]))
            .sum()
    }
}

fn slot_index(slot: u64) -> usize {
    // `slot % SLOTS` is below SLOTS, which fits a usize.
    usize::try_from(slot % SLOTS_U64).unwrap_or(0)
}

/// Every client's queries over the last hour.
#[derive(Debug, Clone, Default)]
pub struct LastHour {
    clients: HashMap<[u8; 16], Entry>,
    /// The newest slot any live query landed in.
    newest: u64,
}

impl LastHour {
    /// Counts one live query from `client` at `ts_s`. Live queries come in time order, so one
    /// a whole window older than the newest means the clock was set back: what was counted is
    /// dated in the future and is dropped, and counting starts again from `ts_s`.
    pub fn add(&mut self, client: [u8; 16], ts_s: u64) {
        let slot = ts_s / SLOT_S;
        if slot + SLOTS_U64 <= self.newest {
            self.clients.clear();
            self.newest = slot;
        }
        self.count(client, slot);
    }

    /// Counts one query replayed from the query log after a restart (any order). One older
    /// than the window is ignored; it never moves the window back.
    pub fn add_replayed(&mut self, client: [u8; 16], ts_s: u64) {
        let slot = ts_s / SLOT_S;
        if slot + SLOTS_U64 > self.newest {
            self.count(client, slot);
        }
    }

    fn count(&mut self, client: [u8; 16], slot: u64) {
        if slot > self.newest {
            self.newest = slot;
            // Once per slot: drop clients the window has left behind, and give back the
            // memory a burst of clients took.
            self.clients.retain(|_, e| e.last + SLOTS_U64 > slot);
            if self.clients.capacity() > 4 * self.clients.len().max(16) {
                self.clients.shrink_to(2 * self.clients.len());
            }
        }
        let full = self.clients.len() >= MAX_CLIENTS;
        let e = match self.clients.get_mut(&client) {
            Some(e) => e,
            None if full => return,
            None => self.clients.entry(client).or_insert(Entry {
                last: slot,
                counts: [0; SLOTS],
            }),
        };
        if slot > e.last {
            // Clear the slots between, which this client didn't query in.
            for s in (e.last + 1..=slot).take(SLOTS) {
                e.counts[slot_index(s)] = 0;
            }
            e.last = slot;
        } else if slot + SLOTS_U64 <= e.last {
            return;
        }
        let c = &mut e.counts[slot_index(slot)];
        *c = c.saturating_add(1);
    }

    /// Every client's queries in the hour up to `now_s` (the window: 60–65 minutes), unsorted;
    /// clients without any are left out. Cheap enough to call under the aggregator's lock:
    /// rank with [`rank`] after releasing it.
    pub fn counts(&self, now_s: u64) -> Vec<([u8; 16], u64)> {
        let now = now_s / SLOT_S;
        self.clients
            .iter()
            .map(|(k, e)| (*k, e.total(now)))
            .filter(|(_, c)| *c > 0)
            .collect()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.clients.len()
    }
}

/// The `n` heaviest of `v`, most first, ties by address.
pub fn rank(mut v: Vec<([u8; 16], u64)>, n: usize) -> Vec<([u8; 16], u64)> {
    let by = |a: &([u8; 16], u64), b: &([u8; 16], u64)| b.1.cmp(&a.1).then(a.0.cmp(&b.0));
    if n < v.len() {
        v.select_nth_unstable_by(n, by);
        v.truncate(n);
    }
    v.sort_unstable_by(by);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[15] = last;
        a
    }

    fn top(h: &LastHour, now_s: u64, n: usize) -> Vec<([u8; 16], u64)> {
        rank(h.counts(now_s), n)
    }

    const T0: u64 = 1_800_000_000; // a slot boundary (divisible by 300)

    // REQ: API-005 — a minute past the clock hour still shows the hour before it.
    #[test]
    fn api_005_last_hour_spans_the_clock_hour() {
        let mut h = LastHour::default();
        let hour = T0 - T0 % 3600 + 3600; // a clock hour
        for _ in 0..5 {
            h.add(ip(1), hour - 600); // ten minutes before it
        }
        h.add(ip(2), hour + 30);
        assert_eq!(top(&h, hour + 60, 10), vec![(ip(1), 5), (ip(2), 1)]);
    }

    // REQ: API-005 — the window always holds the full hour: a query 59 minutes and 59 seconds
    // ago is in, whatever the time within the slot.
    #[test]
    fn api_005_last_hour_always_covers_sixty_minutes() {
        for offset in [0, 1, 150, 299] {
            let mut h = LastHour::default();
            let now = T0 + 3600 + offset;
            h.add(ip(1), now - 3599);
            h.add(ip(1), now);
            assert_eq!(top(&h, now, 10), vec![(ip(1), 2)], "offset {offset}");
        }
    }

    // REQ: API-005 — queries leave the list as they age past the window, slot by slot.
    #[test]
    fn api_005_last_hour_forgets_old_slots() {
        let mut h = LastHour::default();
        h.add(ip(1), T0);
        h.add(ip(1), T0 + 30 * 60);
        h.add(ip(1), T0 + 30 * 60);
        assert_eq!(top(&h, T0 + 64 * 60, 10), vec![(ip(1), 3)]);
        // 65 minutes after the first query its slot is out; the later two stay.
        assert_eq!(top(&h, T0 + 65 * 60, 10), vec![(ip(1), 2)]);
        assert_eq!(top(&h, T0 + 95 * 60, 10), Vec::<([u8; 16], u64)>::new());
        // A newer query from someone else prunes the stale client.
        h.add(ip(2), T0 + 2 * 3600);
        assert_eq!(h.len(), 1);
        assert_eq!(top(&h, T0 + 2 * 3600, 10), vec![(ip(2), 1)]);
    }

    // REQ: API-005 — a client's slots are cleared when it comes back, and late queries count.
    #[test]
    fn api_005_last_hour_reuses_slots_and_counts_late_queries() {
        let mut h = LastHour::default();
        let end = T0 + WINDOW_S;
        h.add(ip(1), T0);
        h.add(ip(1), T0 + SLOT_S);
        // Exactly SLOTS slots on lands in the first query's ring index: its count must go.
        h.add(ip(1), end);
        assert_eq!(top(&h, end, 10), vec![(ip(1), 2)]);
        // A late query from within the window counts; a replayed one from before it doesn't.
        h.add(ip(1), T0 + SLOT_S * 5);
        h.add_replayed(ip(1), T0);
        assert_eq!(top(&h, end, 10), vec![(ip(1), 3)]);
    }

    // REQ: API-005 — the clock set back by more than the window: the future-dated counts go
    // and new queries count at once instead of being ignored until the clock catches up.
    #[test]
    fn api_005_last_hour_survives_the_clock_going_back() {
        let mut h = LastHour::default();
        h.add(ip(1), T0 + 2 * 3600);
        h.add(ip(2), T0);
        assert_eq!(top(&h, T0 + 60, 10), vec![(ip(2), 1)]);
        assert_eq!(h.len(), 1);
        // A replayed query never moves the window back.
        let mut r = LastHour::default();
        r.add(ip(1), T0 + 2 * 3600);
        r.add_replayed(ip(2), T0);
        assert_eq!(top(&r, T0 + 2 * 3600, 10), vec![(ip(1), 1)]);
    }

    // REQ: API-005 — heaviest first, ties by address, `n` kept.
    #[test]
    fn api_005_last_hour_ranks_and_truncates() {
        let mut h = LastHour::default();
        for (c, n) in [(3u8, 2), (1, 5), (2, 2), (4, 1)] {
            for _ in 0..n {
                h.add(ip(c), T0);
            }
        }
        assert_eq!(top(&h, T0, 2), vec![(ip(1), 5), (ip(2), 2)]);
        assert_eq!(top(&h, T0, 10).len(), 4);
    }

    // REQ: API-005 — bounded: past the cap, new clients wait for room; the memory comes back.
    #[test]
    fn api_005_last_hour_is_bounded() {
        let mut h = LastHour::default();
        for i in 0..=MAX_CLIENTS {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&u32::try_from(i).unwrap_or(0).to_be_bytes());
            h.add(a, T0);
        }
        assert_eq!(h.len(), MAX_CLIENTS);
        // An hour on, the old ones are gone, there is room again, and the table shrank.
        h.add(ip(9), T0 + WINDOW_S);
        assert_eq!(h.len(), 1);
        assert!(h.clients.capacity() < 256, "{}", h.clients.capacity());
    }
}

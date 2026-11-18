//! REQ: OBS-901 (T26.2, ADR-958) — the sampler: unbiased at 5x the cap, unbiased under drops,
//! bounded under a flood of distinct devices, deterministic, private.

use super::*;
use crate::event::Name;
use crate::{Proto, Status};

/// A seeded generator (no `rand` in this crate): the same stream every run.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
}

fn ev(ts_us: u64, client: u8, status: Status, upstream: u16, t_total_us: u32) -> QueryEvent {
    let mut ip = [0u8; 16];
    ip[10] = 0xff;
    ip[11] = 0xff;
    ip[12..].copy_from_slice(&[192, 168, 1, client]);
    QueryEvent {
        ts_us,
        client_ip: ip,
        client_ref: 0,
        group: 1,
        qtype: 1,
        qclass: 1,
        rcode: Some(0),
        status,
        proto: Proto::Udp,
        flags: 0,
        rule: None,
        upstream,
        attempts: 1,
        t_total_us,
        t_upstream_us: 0,
        resp_size: 60,
        answers: 1,
    }
}

/// What a synthetic lookup is: a device, a status and an upstream, picked by weight.
fn pick(r: &mut Lcg) -> (u8, Status, u16) {
    // Devices: 1 gets 40%, 2 gets 25%, 3 gets 15%, the rest share 20%.
    let d = r.next() % 100;
    let client = match d {
        0..=39 => 1,
        40..=64 => 2,
        65..=79 => 3,
        _ => 4 + u8::try_from(r.next() % 6).unwrap_or(0),
    };
    let s = r.next() % 100;
    let (status, up) = match s {
        0..=54 => (Status::Cached, 0),
        55..=79 => (Status::Forwarded, 1),
        80..=89 => (Status::Forwarded, 2),
        90..=96 => (Status::Blocked, 0),
        _ => (Status::ServFail, 1),
    };
    (client, status, up)
}

type Truth = std::collections::HashMap<(u8, AnswerKind, u16), u64>;

/// Runs `secs` seconds of `per_sec` lookups through the sampler (a tick every 250 ms of
/// simulated time), `lose_pct` percent of them lost before the sampler (counted as drops).
/// Returns the true counts of every lookup, lost or not.
fn run(s: &mut Sampler, secs: u64, per_sec: u64, lose_pct: u64, seed: u64) -> Truth {
    let mut r = Lcg(seed);
    let mut truth = Truth::new();
    let mut lost = 0u64;
    let base_s = 1_700_000_000u64;
    let per_tick = per_sec / 4;
    for t in 0..secs * 4 {
        for i in 0..per_tick {
            let ts_us = (base_s * 1000 + t * 250 + i * 250 / per_tick) * 1000;
            let (c, st, up) = pick(&mut r);
            let kind = AnswerKind::of(st).unwrap_or(AnswerKind::Other);
            *truth.entry((c, kind, up)).or_default() += 1;
            if r.next() % 100 < lose_pct {
                lost += 1;
                continue;
            }
            s.offer(&ev(ts_us, c, st, up, 1_000));
        }
        s.tick((t + 1) * 250, lost);
    }
    truth
}

fn estimates(w: &Window) -> Truth {
    let mut out = Truth::new();
    for e in &w.entries {
        let c = e.client.0[15];
        *out.entry((c, e.kind, e.upstream)).or_default() += u64::from(e.c.weighted);
    }
    out
}

#[allow(clippy::cast_precision_loss)]
fn within(est: u64, truth: u64, pct: f64) -> bool {
    let (e, t) = (est as f64, truth as f64);
    ((e - t).abs() / t) <= pct / 100.0
}

/// A window of the last 60 s of a run that lasted exactly 60 s (so the truth is the whole run).
fn now_s() -> u64 {
    1_700_000_000 + 59
}

/// ADR-958 test plan: a synthetic stream at 5x the cap, counter-based selector: each large
/// edge's estimate is within 5% of the truth, and the total is nearly exact.
#[test]
fn obs_901_sampler_unbiased() {
    // 2,000/s cap = 500 kept per tick; 10,000/s is 5x. (At a cap of 200 an edge's sampling
    // noise alone is about 2%; a window this full brings it under 1%, so 5% tests bias.)
    let mut s = Sampler::new(
        Settings {
            event_rate: 2000,
            slow_us: 250_000,
        },
        0,
    );
    let truth = run(&mut s, 60, 10_000, 0, 7);
    let w = s.window(now_s());
    assert_eq!(s.sample_rate(), 5, "1 in 5 at 5x the cap");
    assert_eq!(w.sample_rate, 5);
    let est = estimates(&w);
    let total_truth: u64 = truth.values().sum();
    let total_est: u64 = est.values().sum::<u64>() + u64::from(w.other.weighted);
    assert!(
        within(total_est, total_truth, 1.0),
        "total {total_est} vs {total_truth}"
    );
    let mut checked = 0;
    for (k, &t) in &truth {
        if t * 100 / total_truth >= 5 {
            let e = est.get(k).copied().unwrap_or(0);
            assert!(within(e, t, 5.0), "{k:?}: estimate {e} vs truth {t}");
            checked += 1;
        }
    }
    assert!(checked >= 4, "the test looked at {checked} edges");
    // Kept events are what `min_sample` counts: about a fifth of the stream.
    let sampled: u64 = w.entries.iter().map(|e| u64::from(e.c.sampled)).sum();
    assert!(
        sampled * 50 < total_truth * 12 && sampled * 50 > total_truth * 8,
        "{sampled} kept of {total_truth}"
    );
}

/// The same selector is deterministic: two runs give the same window.
#[test]
fn obs_901_sampler_is_deterministic() {
    let go = || {
        let mut s = Sampler::new(Settings::default(), 0);
        run(&mut s, 20, 1000, 0, 3);
        let mut w = s.window(1_700_000_019);
        w.entries.sort_by_key(|e| (e.client, e.kind, e.upstream));
        w
    };
    assert_eq!(go(), go());
}

/// Events the rings dropped (counted, folded into N and the weights) thin the sample but do not
/// bias it down: 20% lost before the sampler, estimates still within 5% of the whole stream.
#[test]
fn obs_901_sampler_overload() {
    let mut s = Sampler::new(
        Settings {
            event_rate: 2000,
            slow_us: 250_000,
        },
        0,
    );
    let truth = run(&mut s, 60, 10_000, 20, 11);
    let w = s.window(now_s());
    assert!(w.dropped > 0, "the drops are reported");
    let est = estimates(&w);
    let total_truth: u64 = truth.values().sum();
    let total_est: u64 = est.values().sum::<u64>() + u64::from(w.other.weighted);
    assert!(
        within(total_est, total_truth, 5.0),
        "total {total_est} vs {total_truth} (dropped {})",
        w.dropped
    );
    for (k, &t) in &truth {
        if t * 100 / total_truth >= 5 {
            let e = est.get(k).copied().unwrap_or(0);
            assert!(within(e, t, 5.0), "{k:?}: estimate {e} vs truth {t}");
        }
    }
}

/// A flood of distinct devices stops adding keys at the cap, and what does not fit counts as
/// `other`: nothing is lost from the totals and the memory estimate stays at or under 1 MiB.
#[test]
fn obs_901_sampler_bounded() {
    let mut s = Sampler::new(
        Settings {
            event_rate: 2000,
            slow_us: 250_000,
        },
        0,
    );
    let base_s = 1_700_000_000u64;
    let mut offered = 0u64;
    let mut n = 0u32;
    // 60 s of 400 new devices every 250 ms: far past 1,024 keys a slot.
    for t in 0..60u64 * 4 {
        for _ in 0..400u32 {
            n += 1;
            let mut e = ev(
                (base_s * 1000 + t * 250) * 1000,
                0,
                Status::Forwarded,
                1,
                1000,
            );
            e.client_ip[12..].copy_from_slice(&n.to_be_bytes());
            s.offer(&e);
            offered += 1;
        }
        s.tick((t + 1) * 250, 0);
    }
    assert!(s.keys() <= SLOTS * KEYS_PER_SLOT, "{} keys", s.keys());
    assert!(s.entry_bytes() <= MAX_BYTES, "{} bytes", s.entry_bytes());
    let w = s.window(base_s + 59);
    assert!(w.entries.len() <= PART_KEYS, "a part is trimmed");
    assert!(w.other.sampled > 0, "the rest counts under other");
    let counted: u64 = w
        .entries
        .iter()
        .map(|e| u64::from(e.c.sampled))
        .sum::<u64>()
        + u64::from(w.other.sampled);
    // The first tick keeps every lookup; later ones keep the cap's share; weights make up the
    // difference, so what the window says it saw is what was offered.
    let weighted: u64 = w
        .entries
        .iter()
        .map(|e| u64::from(e.c.weighted))
        .sum::<u64>()
        + u64::from(w.other.weighted);
    assert!(counted <= offered);
    assert!(
        weighted * 100 >= offered * 98 && weighted * 100 <= offered * 102,
        "weighted {weighted} of {offered}"
    );
}

/// `sampled` counts the events actually kept: one kept SERVFAIL at N = 20 weighs 20 in `error`
/// but is one event for `min_sample`.
#[test]
fn obs_901_sampler_counts_real_events() {
    let mut s = Sampler::new(
        Settings {
            event_rate: 200,
            slow_us: 250_000,
        },
        0,
    );
    // 1,000 lookups per tick at a cap of 50 gives N = 20 from the second tick on.
    let base = 1_700_000_000_000_000u64;
    for t in 0..8u64 {
        for i in 0..1000u64 {
            s.offer(&ev(base + t * 250_000 + i, 9, Status::Cached, 0, 100));
        }
        s.tick((t + 1) * 250, 0);
    }
    assert_eq!(s.sample_rate(), 20);
    // Every lookup of device 5 fails; the counter keeps one in 20 of them.
    for i in 0..200u64 {
        s.offer(&ev(base + 3_000_000 + i, 5, Status::ServFail, 1, 100));
    }
    let w = s.window(1_700_000_003);
    let f = w
        .entries
        .iter()
        .find(|e| e.client.0[15] == 5)
        .map(|e| e.c)
        .unwrap_or_default();
    assert_eq!(f.sampled, 10, "200 failures at 1 in 20 is 10 real events");
    assert_eq!(f.error, 200, "and they weigh 200 together: {f:?}");
    assert_eq!(f.weighted, f.error);
}

/// ADR-958 section 7: privacy is applied before the sampler keeps anything. At 2 no client key
/// is held at all; at 3 nothing finer than a total.
#[test]
fn obs_901_sampler_privacy_levels() {
    for level in [2u8, 3] {
        let mut s = Sampler::new(Settings::default(), 0);
        s.set_privacy(level);
        for i in 0..200u64 {
            s.offer(&ev(
                1_700_000_000_000_000 + i,
                1 + u8::try_from(i % 9).unwrap_or(0),
                Status::Forwarded,
                2,
                10,
            ));
        }
        for slot in &s.slots {
            for (k, _) in &slot.rows {
                assert!(
                    k.client.is_hidden(),
                    "level {level}: a client key in the state"
                );
                if level >= 3 {
                    assert_eq!((k.group, k.upstream, k.kind), (0, 0, AnswerKind::Other));
                }
            }
        }
        assert!(s.recent.iter().all(|r| r.client.is_hidden()));
        if level >= 3 {
            assert!(s.recent.is_empty(), "no per-event data at level 3");
        }
        let w = s.window(1_700_000_000);
        assert_eq!(w.privacy, level);
        assert!(w.entries.len() == 1 || level >= 3, "{:?}", w.entries);
        assert!(w.entries.iter().all(|e| e.client.is_hidden()));
    }
    // Level 1 and below keep the address.
    let mut s = Sampler::new(Settings::default(), 0);
    s.set_privacy(1);
    s.offer(&ev(1_700_000_000_000_000, 7, Status::Cached, 0, 10));
    let w = s.window(1_700_000_000);
    assert!(!w.entries[0].client.is_hidden());
    assert_eq!(w.entries[0].client.addr().to_string(), "192.168.1.7");
}

/// Old slots leave the window; a late event older than the window is ignored.
#[test]
fn obs_901_sampler_window_rolls() {
    let mut s = Sampler::new(Settings::default(), 0);
    let t0 = 1_700_000_000u64;
    s.offer(&ev(t0 * 1_000_000, 1, Status::Cached, 0, 10));
    assert_eq!(s.window(t0 + 10).entries.len(), 1);
    assert!(s.window(t0 + 61).entries.is_empty(), "gone after 60 s");
    // A new second a minute later reuses the slot; the old counts are cleared.
    s.offer(&ev((t0 + 60) * 1_000_000, 2, Status::Cached, 0, 10));
    let w = s.window(t0 + 60);
    assert_eq!(w.entries.len(), 1);
    assert_eq!(w.entries[0].client.0[15], 2);
    // Late: older than the slot's current minute.
    s.offer(&ev(t0 * 1_000_000, 3, Status::Cached, 0, 10));
    assert_eq!(s.window(t0 + 60).entries.len(), 1);
}

/// Statuses map to the counts the classification reads: slow only for answered lookups over the
/// threshold, error for SERVFAIL, blocked, rate limited; never-answered ones are not kept.
#[test]
fn obs_901_sampler_counts_fields() {
    let mut s = Sampler::new(
        Settings {
            event_rate: 200,
            slow_us: 100_000,
        },
        0,
    );
    let t = 1_700_000_000_000_000u64;
    s.offer(&ev(t, 1, Status::Forwarded, 3, 150_000));
    s.offer(&ev(t, 1, Status::ServFail, 3, 10));
    s.offer(&ev(t, 1, Status::Blocked, 0, 10));
    s.offer(&ev(t, 1, Status::RateLimited, 0, 10));
    s.offer(&ev(t, 1, Status::Dropped, 0, 10));
    s.offer(&ev(t, 1, Status::Drilled, 0, 10));
    let w = s.window(1_700_000_000);
    let get = |k: AnswerKind| w.entries.iter().find(|e| e.kind == k).map(|e| e.c);
    let up = w
        .entries
        .iter()
        .find(|e| e.kind == AnswerKind::Upstream && e.upstream == 3)
        .map(|e| e.c)
        .unwrap_or_default();
    assert_eq!((up.sampled, up.slow, up.error), (2, 1, 1));
    assert_eq!(get(AnswerKind::Blocked).map(|c| c.blocked), Some(1));
    assert_eq!(get(AnswerKind::Other).map(|c| c.limited), Some(1));
    let all: u32 = w.entries.iter().map(|e| e.c.sampled).sum();
    assert_eq!(all, 4, "dropped and drilled aren't kept");
}

/// A window part crosses the cluster channel as JSON and comes back the same.
#[test]
fn obs_901_window_round_trips_as_json() {
    let mut s = Sampler::new(Settings::default(), 0);
    s.offer(&ev(1_700_000_000_000_000, 7, Status::Forwarded, 2, 90_000));
    let w = s.window(1_700_000_000);
    let text = serde_json::to_string(&w).unwrap();
    assert!(
        text.contains("\"client\":\"00000000000000000000ffff"),
        "{text}"
    );
    let back: Window = serde_json::from_str(&text).unwrap();
    assert_eq!(back, w);
    assert!(serde_json::from_str::<ClientKey>("\"12\"").is_err());
}

/// REQ: OBS-901 (T26.2 step 1, ADR-958 section 3) — the ring record's sizes, pinned. The answer
/// address (a 17-byte `Option<Addr>` in `QueryEvent`) was measured against them and not added
/// (ADR-970): it would grow every query record on the workers' hot path by 17 bytes, and the
/// ADR ships it only if the record does not grow.
#[test]
fn obs_901_record_sizes_are_pinned() {
    use std::mem::size_of;
    assert_eq!(size_of::<QueryEvent>(), SIZE_QUERY_EVENT);
    assert_eq!(size_of::<Record>(), SIZE_RECORD);
    assert_eq!(size_of::<Name>(), 256);
    assert_eq!(crate::event::MAX_RECORD, 316);
}

const SIZE_QUERY_EVENT: usize = 64;
const SIZE_RECORD: usize = 320;

/// Events through the hub reach the sampler after the privacy level; turning the map off drops
/// the state.
#[test]
fn obs_901_hub_feeds_and_stops_the_sampler() {
    let hub = crate::Hub::new(1 << 16);
    assert!(hub.map_window(1_700_000_000).is_none(), "off by default");
    hub.set_map(Some(Settings::default()));
    let mut d = hub.drainer();
    let name = Name::from_wire(b"\x07example\x03com\x00");
    for i in 0..10u64 {
        hub.emit_query(
            &ev(1_700_000_000_000_000 + i, 7, Status::Cached, 0, 20),
            name.as_wire(),
        );
    }
    hub.drain_once(&mut d);
    let w = hub.map_window(1_700_000_000).unwrap();
    assert_eq!(w.entries.iter().map(|e| e.c.sampled).sum::<u32>(), 10);
    assert!(!w.entries[0].client.is_hidden());
    hub.set_privacy(2);
    hub.emit_query(
        &ev(1_700_000_001_000_000, 8, Status::Cached, 0, 20),
        name.as_wire(),
    );
    hub.drain_once(&mut d);
    let w = hub.map_window(1_700_000_001).unwrap();
    assert_eq!(w.privacy, 2);
    assert!(
        w.entries.iter().all(|e| e.client.0[15] != 8),
        "the level-2 lookup has no client key"
    );
    // REQ: OBS-901 (review fix) — raising the level purges the real client keys already kept.
    assert!(
        w.entries.iter().all(|e| e.client.is_hidden()),
        "no device key survives the switch to level 2"
    );
    assert!(w.recent.iter().all(|r| r.client.is_hidden()));
    hub.set_map(None);
    assert!(hub.map_window(1_700_000_000).is_none());
}

/// REQ: OBS-901 (T26.2, ADR-958 test plan) — the aggregator's throughput with the sampler on and
/// off: 7 alternating runs, compared by their medians. The sampler passes when the on-median is
/// within 5% of the off-median (the noise band of this harness; the spread of the off runs is
/// printed with the result). Run with
/// `cargo test --release -p telltale-telemetry obs_901_sampler_throughput_ab -- --ignored --nocapture`.
#[test]
#[ignore = "a benchmark: run it with --release and --ignored"]
fn obs_901_sampler_throughput_ab() {
    throughput_ab(4, Settings::default());
}

/// REQ: OBS-901 (review fix) — the worst case of the same comparison: every lookup from one of
/// 60,000 distinct clients at `event_rate = 2000`, so the slots fill and each kept event scans
/// up to 1,024 rows.
#[test]
#[ignore = "a benchmark: run it with --release and --ignored"]
fn obs_901_sampler_throughput_ab_unique_clients() {
    throughput_ab(
        60_000,
        Settings {
            event_rate: 2000,
            ..Settings::default()
        },
    );
}

fn throughput_ab(clients: u64, settings: Settings) {
    use std::time::{Duration, Instant};
    let names: Vec<Vec<u8>> = (0..2000)
        .map(|i| {
            let host = format!("host{i}");
            let mut w = vec![u8::try_from(host.len()).unwrap_or(0)];
            w.extend_from_slice(host.as_bytes());
            w.extend_from_slice(b"\x07example\x03com\x00");
            w
        })
        .collect();
    let run = |on: bool| -> f64 {
        let hub = crate::Hub::new(16 << 20);
        hub.set_map(on.then_some(settings));
        let mut d = hub.drainer();
        let mut rng = Lcg(5);
        let base_us = 1_700_000_000_000_000u64;
        let mut seq = 0u64;
        let (mut drained, mut spent) = (0usize, Duration::ZERO);
        let begun = Instant::now();
        // 0.6 s untimed so N has settled, then 1.5 s timed, in drains of 20,000 events.
        while begun.elapsed() < Duration::from_millis(2100) {
            for _ in 0..20_000u32 {
                seq += 1;
                let (c, st, up) = pick(&mut rng);
                let name = &names[usize::try_from(rng.next() % 2000).unwrap_or(0)];
                let mut e = ev(base_us + seq, c, st, up, 1_000);
                let c = rng.next() % clients;
                e.client_ip[13] = u8::try_from((c >> 8) & 0xff).unwrap_or(0);
                e.client_ip[14] = u8::try_from(c & 0xff).unwrap_or(0);
                hub.emit_query(&e, name);
            }
            let t = Instant::now();
            let n = hub.drain_once(&mut d);
            if begun.elapsed() > Duration::from_millis(600) {
                drained += n;
                spent += t.elapsed();
            }
        }
        #[allow(clippy::cast_precision_loss)]
        let rate = drained as f64 / spent.as_secs_f64();
        rate
    };
    let (mut off, mut on) = (Vec::new(), Vec::new());
    let _ = run(false); // warm the allocator and the caches
    for _ in 0..7 {
        off.push(run(false));
        on.push(run(true));
    }
    let median = |v: &mut Vec<f64>| {
        v.sort_by(f64::total_cmp);
        v[v.len() / 2]
    };
    let spread = |v: &[f64]| {
        let (lo, hi) = (
            v.iter().copied().fold(f64::MAX, f64::min),
            v.iter().copied().fold(0.0, f64::max),
        );
        (hi - lo) / hi * 100.0
    };
    let (so, sn) = (spread(&off), spread(&on));
    let (mo, mn) = (median(&mut off), median(&mut on));
    println!(
        "aggregator throughput, sampler off: median {mo:.0} events/s (spread {so:.1}%); on: median {mn:.0} events/s (spread {sn:.1}%); on/off {:.3}",
        mn / mo
    );
    assert!(
        mn >= mo * 0.95,
        "the sampler costs more than 5%: {mn} vs {mo}"
    );
}

/// REQ: OBS-901 (review fix) — a sampler made after the rings dropped events does not count
/// that history as its first tick's drops.
#[test]
fn obs_901_new_sampler_ignores_earlier_ring_drops() {
    let mut s = Sampler::new(Settings::default(), 5_000_000);
    s.offer(&ev(1_700_000_000_000_000, 7, Status::Cached, 0, 20));
    s.tick(1_000, 5_000_000);
    s.offer(&ev(1_700_000_000_000_001, 7, Status::Cached, 0, 20));
    let w = s.window(1_700_000_000);
    assert_eq!(w.dropped, 0);
    assert!(w.entries.iter().all(|e| e.c.weighted < 100));
}

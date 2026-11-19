//! REQ: CLU-005 (T24.26, ADR-990) — a model of a slow ballot store.
//!
//! The owner's primary lost its lease every 10 to 20 minutes on SD cards. This drives the real
//! `Elector` (three voters, a primary, a replica, a witness) with a store that takes `delay` ms
//! per write, held on the node's election lock: an answer waits for the store of the vote it
//! carries, a primary's sends wait for the store of its own grant, and a reply that arrives more
//! than `ROUND_MS` after its ask is dropped (the network layer's 2 s deadline). Two policies run
//! over the same schedule: the base one stores whenever the ballot differs at all (every
//! renewal moves `lease_until_ms`), the fixed one stores what `Ballot::must_persist_since`
//! says (`Out::Persist`). It proves the mechanism, not the cause on the Pis: the model assumes
//! a store that slow, which only the Pis' `slow ballot store` warnings can confirm.

use wrendns_cluster::election::{Ask, Ballot, Elector, Out, ROUND_MS, Reply};

const STEP: u64 = 10;
const NET_MS: u64 = 5;
const SETTLE_MS: u64 = 60_000;
const SOAK_MS: u64 = 600_000;

enum Msg {
    Ask { ask: Ask, sent: u64 },
    Reply { reply: Reply, sent: u64 },
}

struct Net {
    /// (deliver at, from, to, message)
    flight: Vec<(u64, usize, usize, Msg)>,
}

/// Runs the cluster; returns how many times the primary's lease lapsed during the soak.
fn lapses(delay_ms: u64, base_policy: bool) -> usize {
    let ids: Vec<String> = (0..3).map(|i| format!("n{i}")).collect();
    let mut els: Vec<Elector> = (0..3)
        .map(|i| Elector::new(&ids[i], ids.clone(), i < 2, Ballot::default()))
        .collect();
    // The election lock: free again at this real time.
    let mut busy = [0u64; 3];
    let mut net = Net { flight: Vec::new() };
    let mut was_writable = false;
    let mut lapsed = 0;
    let mut real = 0;
    while real < SETTLE_MS + SOAK_MS {
        let delay = if real < SETTLE_MS { 0 } else { delay_ms };
        // Deliver what is due, in order.
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut net.flight)
            .into_iter()
            .partition(|(at, ..)| *at <= real);
        net.flight = later;
        for (at, from, to, m) in due {
            let start = at.max(busy[to]);
            match m {
                Msg::Ask { ask, sent } => {
                    let before = els[to].ballot.clone();
                    let (reply, outs) = els[to].on_ask(&ask, start);
                    let store = if base_policy {
                        els[to].ballot != before
                    } else {
                        outs.iter().any(|o| matches!(o, Out::Persist))
                    };
                    let done = if store { start + delay } else { start };
                    busy[to] = done;
                    net.flight
                        .push((done + NET_MS, to, from, Msg::Reply { reply, sent }));
                }
                Msg::Reply { reply, sent } => {
                    // The network layer's deadline: a late answer is no answer.
                    if at > sent + ROUND_MS {
                        continue;
                    }
                    let who = ids[from].clone();
                    let outs = els[to].on_reply(&who, &reply, start);
                    send(&mut net, &ids, to, outs, real, busy[to]);
                }
            }
        }
        for i in 0..3 {
            if busy[i] > real {
                continue;
            }
            let jitter = if i == 0 { 0 } else { 7_000 };
            let before = els[i].ballot.clone();
            let outs = els[i].tick(real, jitter);
            let store = if base_policy {
                els[i].ballot != before
            } else {
                outs.iter().any(|o| matches!(o, Out::Persist))
            };
            if store {
                busy[i] = real + delay;
            }
            send(&mut net, &ids, i, outs, real, busy[i]);
        }
        let w = els[0].writable(real);
        if real >= SETTLE_MS && was_writable && !w {
            lapsed += 1;
        }
        if real >= SETTLE_MS || w {
            was_writable = w;
        }
        real += STEP;
    }
    lapsed
}

/// Sends an elector's asks once its store (if any) is done.
fn send(net: &mut Net, ids: &[String], from: usize, outs: Vec<Out>, real: u64, free_at: u64) {
    for o in outs {
        if let Out::Send { to, ask } = o {
            let j = ids.iter().position(|x| *x == to).unwrap_or(0);
            let at = free_at.max(real);
            net.flight
                .push((at + NET_MS, from, j, Msg::Ask { ask, sent: at }));
        }
    }
}

#[test]
fn clu_005_t24_26_a_two_second_store_lapses_the_base_and_not_the_fix() {
    // Control: a fast store lapses nothing under either policy, so the model is not rigged.
    assert_eq!(lapses(0, true), 0, "base, instant store");
    assert_eq!(lapses(0, false), 0, "fixed, instant store");
    assert_eq!(lapses(300, true), 0, "base, 300 ms store");
    for delay in [2_000, 2_500, 4_000] {
        let base = lapses(delay, true);
        let fixed = lapses(delay, false);
        eprintln!("store {delay} ms: base lapsed {base} times, fixed {fixed}");
        assert!(base > 0, "base policy, {delay} ms store: expected lapses");
        assert_eq!(
            fixed, 0,
            "fixed policy, {delay} ms store lapsed {fixed} times"
        );
    }
}

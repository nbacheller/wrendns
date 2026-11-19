//! REQ: DSC-903 (T31.2, AC 3) - reconciling the same batches in any order gives the same links.
//!
//! A seeded generator makes a small world (devices with one to three MACs, some with a serial or
//! a stable key) and several sources that each report parts of it, including keyless records that
//! hold an address. The batches are delivered in the generated order and in shuffled orders (and
//! one of them twice); what is compared is which records share a device, which share an interface
//! and which proposals exist, never the random ids.

use std::collections::{BTreeMap, BTreeSet};

use super::engine::Engine;
use super::engine::test_support::{batch, engine};
use super::model::{RecKind, Record, SourceBatch};

/// A small deterministic generator (xorshift), so a failing seed can be replayed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

struct Dev {
    macs: Vec<String>,
    serial: Option<String>,
    key: Option<String>,
}

/// Records the generator reports, each tagged with the time it was first seen.
fn world(seed: u64) -> Vec<SourceBatch> {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let ndev = 3 + rng.below(4);
    let mut devs: Vec<Dev> = Vec::new();
    for d in 0..ndev {
        let nmac = 1 + rng.below(3);
        devs.push(Dev {
            macs: (0..nmac).map(|m| format!("aa:00:00:00:{d:02x}:{m:02x}")).collect(),
            serial: rng.chance(60).then(|| format!("sn-dev-{d:04}")),
            key: rng.chance(40).then(|| format!("ha:home|dev{d}")),
        });
    }
    let sources = ["unifi:home", "neighbor", "snmp:core", "home_assistant:ha"];
    let mut batches: Vec<SourceBatch> = Vec::new();
    let mut at = 1_000_000_i64;
    for (si, source) in sources.iter().enumerate() {
        let mut records: Vec<Record> = Vec::new();
        for (di, dev) in devs.iter().enumerate() {
            for (mi, mac) in dev.macs.iter().enumerate() {
                if !rng.chance(75) {
                    continue;
                }
                at += 1;
                let mut r = Record::new(source, &format!("{di}-{mi}"), RecKind::Device, at);
                r.text("mac", mac.clone());
                // A source reports a device's serial or key only some of the time, and a wrong
                // serial now and then (the conflict case).
                if rng.chance(55) {
                    if let Some(s) = &dev.serial {
                        let wrong = rng.chance(8);
                        r.text("serial", if wrong { "sn-dev-wrong".to_owned() } else { s.clone() });
                    }
                }
                if rng.chance(40)
                    && let Some(k) = &dev.key
                {
                    r.text("device_key", k.clone());
                }
                r.list("addresses", vec![format!("192.168.{si}.{}", 10 + di * 4 + mi)]);
                records.push(r);
            }
        }
        // Keyless records that hold one of the addresses (a query log or an mDNS answer).
        for di in 0..devs.len() {
            if rng.chance(50) {
                at += 1;
                let mut r = Record::new("queries", &format!("q{si}-{di}"), RecKind::Device, at);
                r.list("addresses", vec![format!("192.168.{si}.{}", 10 + di * 4)]);
                records.push(r);
            }
        }
        // Split a source's records over a few batches.
        while !records.is_empty() {
            let n = 1 + usize::try_from(rng.below(4)).unwrap_or(1);
            let rest = records.split_off(n.min(records.len()));
            let part = std::mem::replace(&mut records, rest);
            let src = if part.first().is_some_and(|r| r.source == "queries") {
                "queries".to_owned()
            } else {
                (*source).to_owned()
            };
            batches.push(batch(&src, part, false, at));
        }
    }
    batches
}

fn shuffled(mut b: Vec<SourceBatch>, rng: &mut Rng) -> Vec<SourceBatch> {
    for i in (1..b.len()).rev() {
        let j = usize::try_from(rng.below(u64::try_from(i + 1).unwrap_or(1))).unwrap_or(0);
        b.swap(i, j);
    }
    b
}

/// The links as sets of record keys: which records share a device, which share an interface, and
/// the proposals as pairs of such sets.
fn links(e: &Engine) -> (BTreeSet<BTreeSet<String>>, BTreeSet<BTreeSet<String>>, BTreeSet<String>) {
    let db = e.db();
    let mut by_dev: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut by_ici: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut unlinked: BTreeSet<String> = BTreeSet::new();
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for src in ["unifi:home", "neighbor", "snmp:core", "home_assistant:ha", "queries"] {
        for r in db.read(|o| o.records_of_source(src)).unwrap() {
            let name = format!("{}/{}", r.source, r.skey);
            match &r.dci {
                Some(d) => {
                    by_dev.entry(d.clone()).or_default().insert(name.clone());
                    names.insert(d.clone(), name.clone());
                }
                None => {
                    unlinked.insert(name.clone());
                }
            }
            if let Some(i) = &r.ici {
                by_ici.entry(i.clone()).or_default().insert(name);
            }
        }
    }
    let dev_sets: BTreeSet<BTreeSet<String>> = by_dev.values().cloned().collect();
    let ici_sets: BTreeSet<BTreeSet<String>> = by_ici.values().cloned().collect();
    // A proposal as the record sets of its two sides.
    let mut props: BTreeSet<String> = BTreeSet::new();
    for p in db.read(|o| o.proposals(Some("open"), None)).unwrap() {
        let side = |ci: &str| -> String {
            by_dev
                .get(ci)
                .map(|s| s.iter().cloned().collect::<Vec<_>>().join("+"))
                .unwrap_or_else(|| "?".to_owned())
        };
        let (mut a, mut b) = (side(&p.a), side(&p.b));
        if a > b {
            std::mem::swap(&mut a, &mut b);
        }
        props.insert(format!("{}:{a}|{b}", p.kind));
    }
    (dev_sets, ici_sets, props)
}

fn run(batches: &[SourceBatch]) -> (BTreeSet<BTreeSet<String>>, BTreeSet<BTreeSet<String>>, BTreeSet<String>) {
    let (_d, mut e) = engine();
    for b in batches {
        let at = b.at;
        e.ingest(b.clone(), at).unwrap();
    }
    links(&e)
}

/// REQ: DSC-903 (`dsc_903_any_order_gives_the_same_links`, AC 3) - forty generated worlds, each
/// delivered in its own order and in three shuffled orders (and once with a batch twice): the same
/// records end up on the same devices and interfaces, with the same proposals.
#[test]
fn dsc_903_any_order_gives_the_same_links() {
    for seed in 1..=40u64 {
        let base = world(seed);
        let want = run(&base);
        let mut rng = Rng(seed ^ 0xD1B5_4A32_D192_ED03);
        for round in 0..3 {
            let order = shuffled(base.clone(), &mut rng);
            let got = run(&order);
            assert_eq!(got.0, want.0, "seed {seed} round {round}: devices differ");
            assert_eq!(got.1, want.1, "seed {seed} round {round}: interfaces differ");
            assert_eq!(got.2, want.2, "seed {seed} round {round}: proposals differ");
        }
        let mut twice = base.clone();
        if let Some(first) = base.first() {
            twice.push(first.clone());
        }
        assert_eq!(run(&twice).0, want.0, "seed {seed}: a repeated batch changes the devices");
    }
}

#![allow(
    clippy::redundant_closure_for_method_calls,
    clippy::manual_assert,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::explicit_counter_loop,
    clippy::collapsible_if,
    clippy::map_unwrap_or,
    clippy::type_complexity,
    clippy::items_after_statements,
    dead_code
)]
//! REQ: DSC-901, DSC-906 (T31.2) - the caps and the eviction rules, retention, the write volume of a
//! stable network, and the containment of the CMDB's data (no policy, matching, `identify` or DNS
//! naming code reads it). The memory and disk figures at the caps are the ignored test
//! `dsc_906_figures_at_the_caps`, run on its own.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use wrendns_store::cmdb::{CmdbDb, Pin};

use super::engine::test_support::{batch, engine, host};
use super::engine::{Engine, INGEST_CHUNK};
use super::model::{Caps, SourceBatch};

const T0: i64 = 1_000_000;

fn ci_count(e: &Engine) -> i64 {
    e.db().read(|o| o.ci_count(None)).unwrap()
}

fn mac(n: u32) -> String {
    format!(
        "aa:00:00:{:02x}:{:02x}:{:02x}",
        (n >> 16) & 0xff,
        (n >> 8) & 0xff,
        n & 0xff
    )
}

fn ingest(e: &mut Engine, source: &str, recs: Vec<super::model::Record>, at: i64) {
    e.ingest(batch(source, recs, true, at), at).unwrap();
}

/// Two complete batches that list nothing: what is held from the source goes absent.
fn make_absent(e: &mut Engine, source: &str, at: i64) {
    ingest(e, source, Vec::new(), at);
    ingest(e, source, Vec::new(), at + 1);
}

/// REQ: DSC-906 (AC 5, ADR-1005 section 3) - at the CI cap the oldest CIs that nothing present
/// backs and nothing authored holds are evicted first; a registry row alone is never authored.
#[test]
fn dsc_906_ci_cap_evicts_derived_cis_with_no_present_record() {
    let (_d, mut e) = engine();
    e.caps = Caps {
        cis: 4,
        ..Caps::default()
    };
    ingest(
        &mut e,
        "neighbor",
        vec![
            host("neighbor", "a", &mac(1), T0),
            host("neighbor", "b", &mac(2), T0),
        ],
        T0,
    );
    assert_eq!(ci_count(&e), 4);
    make_absent(&mut e, "neighbor", T0 + 60);
    // A new device arrives at the cap: the oldest absent-only CIs make room.
    ingest(
        &mut e,
        "unifi:home",
        vec![host("unifi:home", "c", &mac(3), T0 + 200)],
        T0 + 200,
    );
    assert_eq!(e.counters.dropped_ci, 0, "nothing was refused");
    assert_eq!(ci_count(&e), 4, "the cap holds");
    let c = e
        .db()
        .read(|o| o.record_get("unifi:home", "c"))
        .unwrap()
        .unwrap();
    assert!(
        c.dci.is_some() && c.ici.is_some(),
        "the new record is linked"
    );
}

/// REQ: DSC-906 (AC 5) - when every CI left is authored (a pin names it) a new CI is refused and
/// counted in `wrendns_cmdb_dropped_total{kind="ci"}`, and the record stays unlinked.
#[test]
fn dsc_906_ci_cap_refuses_a_new_ci_when_the_rest_are_authored() {
    let (_d, mut e) = engine();
    e.caps = Caps {
        cis: 4,
        ..Caps::default()
    };
    ingest(
        &mut e,
        "neighbor",
        vec![
            host("neighbor", "a", &mac(1), T0),
            host("neighbor", "b", &mac(2), T0),
        ],
        T0,
    );
    // Authored: both interfaces are pinned to their devices (an owner's decision).
    let pairs: Vec<(String, String)> = ["a", "b"]
        .iter()
        .map(|k| {
            let r = e
                .db()
                .read(|o| o.record_get("neighbor", k))
                .unwrap()
                .unwrap();
            (r.mac.unwrap(), r.dci.unwrap())
        })
        .collect();
    e.db()
        .write(|o| {
            for (m, d) in &pairs {
                o.pin_set(&Pin {
                    kind: "nic_device".into(),
                    a: m.clone(),
                    b: d.clone(),
                    at: T0,
                    by: "alice".into(),
                    reason: "kept".into(),
                })?;
            }
            Ok(())
        })
        .unwrap();
    make_absent(&mut e, "neighbor", T0 + 60);
    ingest(
        &mut e,
        "unifi:home",
        vec![host("unifi:home", "c", &mac(3), T0 + 200)],
        T0 + 200,
    );
    assert!(e.counters.dropped_ci >= 1, "refused and counted");
    assert_eq!(ci_count(&e), 4);
    let c = e
        .db()
        .read(|o| o.record_get("unifi:home", "c"))
        .unwrap()
        .unwrap();
    assert_eq!(c.dci, None, "the record is left unlinked");
}

/// REQ: DSC-906 (AC 5) - at the record cap the oldest `absent` records go first; a new record that
/// finds none is dropped and counted.
#[test]
fn dsc_906_record_cap_evicts_absent_then_drops_new() {
    let (_d, mut e) = engine();
    e.caps = Caps {
        records: 4,
        ..Caps::default()
    };
    let four: Vec<_> = (1..=4)
        .map(|n| host("neighbor", &format!("n{n}"), &mac(n), T0))
        .collect();
    ingest(&mut e, "neighbor", four, T0);
    assert_eq!(e.record_counts().0, 4);
    // Two of them go absent (a complete batch lists the other two twice).
    let keep: Vec<_> = (3..=4)
        .map(|n| host("neighbor", &format!("n{n}"), &mac(n), T0))
        .collect();
    ingest(&mut e, "neighbor", keep.clone(), T0 + 60);
    ingest(&mut e, "neighbor", keep, T0 + 120);
    ingest(
        &mut e,
        "unifi:home",
        vec![
            host("unifi:home", "x", &mac(5), T0 + 130),
            host("unifi:home", "y", &mac(6), T0 + 130),
        ],
        T0 + 130,
    );
    assert_eq!(e.record_counts().0, 4, "the two absent records made room");
    assert_eq!(e.counters.dropped_record, 0);
    ingest(
        &mut e,
        "unifi:home",
        vec![
            host("unifi:home", "x", &mac(5), T0 + 190),
            host("unifi:home", "y", &mac(6), T0 + 190),
            host("unifi:home", "z", &mac(7), T0 + 190),
        ],
        T0 + 190,
    );
    assert_eq!(
        e.counters.dropped_record, 1,
        "no absent record left: the new one is dropped"
    );
    assert!(
        e.db()
            .read(|o| o.record_get("unifi:home", "z"))
            .unwrap()
            .is_none()
    );
}

/// REQ: DSC-906 (AC 5) - a CI keeps at most 8 records at its own level: past it the oldest `absent`
/// goes, else the newest is dropped and counted.
#[test]
fn dsc_906_per_ci_cap_counts_at_the_cis_own_level() {
    let (_d, mut e) = engine();
    e.caps = Caps {
        per_ci: 3,
        ..Caps::default()
    };
    // One interface seen by five sources: three fit.
    for (i, src) in [
        "unifi:home",
        "neighbor",
        "snmp:core",
        "home_assistant:ha",
        "mdns",
    ]
    .iter()
    .enumerate()
    {
        let at = T0 + i64::try_from(i).unwrap();
        ingest(&mut e, src, vec![host(src, "k", &mac(1), at)], at);
    }
    let held = e.db().read(|o| o.record_counts()).unwrap().0;
    assert_eq!(held, 3, "three at most");
    assert_eq!(e.counters.dropped_record, 2);
    // A device with three interfaces and one record each is three records at the device level? No:
    // each interface holds its own, so the device holds none at its level.
    let (_d2, mut e2) = engine();
    e2.caps = Caps {
        per_ci: 3,
        ..Caps::default()
    };
    ingest(
        &mut e2,
        "unifi:home",
        (1..=5)
            .map(|n| {
                let mut r = host("unifi:home", &format!("i{n}"), &mac(n), T0);
                r.text("serial", "SN-ONE-DEVICE");
                r
            })
            .collect(),
        T0,
    );
    assert_eq!(
        e2.record_counts().0,
        5,
        "five interfaces of one device are not capped at the device"
    );
    assert_eq!(e2.counters.dropped_record, 0);
}

/// REQ: DSC-906 (ADR-1005 section 5) - absent records age out (7 days; imports 30), an unconfirmed CI
/// with nothing left is removed after 30 days, a CI with authored data never is, aliases expire, and
/// the registry's last-seen outlives the records.
#[test]
fn dsc_906_retention_expires_records_and_unconfirmed_cis_but_not_authored_ones() {
    let (_d, mut e) = engine();
    let day = 86_400;
    // A weak record (an mDNS answer with an address only) becomes an unconfirmed CI; an import row too.
    let weak = |src: &str, key: &str, ip: &str| {
        let mut r = super::model::Record::new(src, key, super::model::RecKind::Device, T0);
        r.list("addresses", vec![ip.to_owned()]);
        r
    };
    ingest(
        &mut e,
        "mdns",
        vec![weak("mdns", "printer", "192.168.1.50")],
        T0,
    );
    ingest(
        &mut e,
        "import:scan",
        vec![weak("import:scan", "row1", "192.168.1.60")],
        T0,
    );
    ingest(
        &mut e,
        "neighbor",
        vec![host("neighbor", "n1", &mac(1), T0)],
        T0,
    );
    let printer = e
        .db()
        .read(|o| o.record_get("mdns", "printer"))
        .unwrap()
        .unwrap();
    let ci = printer.dci.clone().unwrap();
    assert_eq!(
        e.db().read(|o| o.ci_get(&ci)).unwrap().unwrap().flags
            & wrendns_store::cmdb::FLAG_UNCONFIRMED,
        1
    );
    for s in ["mdns", "import:scan", "neighbor"] {
        make_absent(&mut e, s, T0 + 60);
    }
    // Eight days on: the weak record is gone, the import is not (30 days), the CI stays until 30.
    e.maintain(T0 + 8 * day).unwrap();
    assert!(
        e.db()
            .read(|o| o.record_get("mdns", "printer"))
            .unwrap()
            .is_none()
    );
    assert!(
        e.db()
            .read(|o| o.record_get("import:scan", "row1"))
            .unwrap()
            .is_some()
    );
    assert!(e.db().read(|o| o.ci_get(&ci)).unwrap().is_some());
    e.maintain(T0 + 31 * day).unwrap();
    assert!(
        e.db()
            .read(|o| o.record_get("import:scan", "row1"))
            .unwrap()
            .is_none(),
        "imports after 30 days"
    );
    assert!(
        e.db().read(|o| o.ci_get(&ci)).unwrap().is_none(),
        "the unconfirmed CI went"
    );
    // The neighbour's device (confirmed by a presence source) stays in the registry with its times.
    let n1 = e.db().read(|o| o.record_get("neighbor", "n1")).unwrap();
    assert!(n1.is_none(), "its record aged out");
    let devs = e
        .db()
        .read(|o| o.ci_list(Some("device"), None, None, 10))
        .unwrap();
    assert_eq!(devs.len(), 1, "the registry row stays");
    let seen = e.db().read(|o| o.seen_get(&devs[0].id)).unwrap();
    assert!(seen.is_some(), "its last_seen outlives the record");
}

/// REQ: DSC-906 (AC 5) - on a stable network a day of batches writes nothing but the batched
/// `last_seen` flush: no record is rewritten, and the bytes written stay under 1 MiB per day per
/// 1,000 present records (the WAL, with its checkpoint turned off, is the bytes written).
#[test]
fn dsc_906_write_volume_of_a_stable_network() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(CmdbDb::open(&dir.path().join("cmdb.db")).unwrap());
    let mut e = Engine::open(&db, T0).unwrap();
    // 1,000 present records: 4 sources of 250 hosts, one device per MAC.
    let sources = ["unifi:home", "neighbor", "snmp:core", "home_assistant:ha"];
    let batches: Vec<(String, Vec<super::model::Record>)> = sources
        .iter()
        .enumerate()
        .map(|(si, s)| {
            let recs: Vec<_> = (0..250u32)
                .map(|n| {
                    let m = mac(u32::try_from(si).unwrap() * 250 + n);
                    let mut r = host(s, &m, &m, T0);
                    r.list("addresses", vec![format!("10.1.{si}.{}", n % 250)]);
                    r.text("name", format!("host-{si}-{n}"));
                    r
                })
                .collect();
            ((*s).to_owned(), recs)
        })
        .collect();
    let feed = |e: &mut Engine, at: i64| -> usize {
        let mut written = 0;
        for (s, recs) in &batches {
            let recs: Vec<_> = recs
                .iter()
                .cloned()
                .map(|mut r| {
                    r.seen = at;
                    r
                })
                .collect();
            let rep = e
                .ingest(
                    SourceBatch {
                        source: s.clone(),
                        complete: true,
                        records: recs,
                        at,
                    },
                    at,
                )
                .unwrap();
            written += rep.written;
        }
        written
    };
    assert_eq!(
        feed(&mut e, T0),
        1000,
        "the first sighting writes every record"
    );
    assert_eq!(e.record_counts(), (1000, 1000));
    db.checkpoint().unwrap();
    db.set_autocheckpoint(0).unwrap();
    let wal_before = db.disk_bytes();
    let changes_before = db.total_changes();
    // A day of one-minute batches, flushing as the thread does every 15 minutes.
    let mut rewritten = 0usize;
    for minute in 1..=1440i64 {
        let at = T0 + minute * 60;
        rewritten += feed(&mut e, at);
        e.flush(at, false).unwrap();
    }
    assert_eq!(rewritten, 0, "an unchanged record is never rewritten");
    let wal_after = db.disk_bytes();
    let changes = db.total_changes() - changes_before;
    let wal_bytes = wal_after - wal_before;
    eprintln!(
        "write volume: {changes} row changes ({} flushed rows), {wal_bytes} WAL bytes per day for 1,000 present records",
        e.counters.flushed_rows
    );
    assert!(
        wal_bytes <= 1024 * 1024,
        "{wal_bytes} bytes written in a day exceed 1 MiB per 1,000 present records"
    );
    // The flush wrote last_seen only: every row change is one of its rows (a record's, or a CI's
    // times), and no record was rewritten.
    assert!(
        changes <= e.counters.flushed_rows + 8,
        "{changes} row changes, but only {} were flushed rows",
        e.counters.flushed_rows
    );
    let rewritten_rows: i64 = db
        .read(|o| {
            Ok(o.records_of_source("neighbor")?
                .iter()
                .filter(|r| r.last_changed != T0)
                .count() as i64)
        })
        .unwrap();
    assert_eq!(rewritten_rows, 0, "no record's content was rewritten");
}

// -- containment (DSC-901) ---------------------------------------------------------------------

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// REQ: DSC-901 (`dsc_901_no_policy_code_reads_the_cmdb`, AC 6) - no code that answers a query,
/// matches a client, identifies a device, applies policy or names a device in DNS mentions the
/// CMDB: the crates of the DNS path, and the modules of this binary that serve them, are scanned.
#[test]
fn dsc_901_no_policy_code_reads_the_cmdb() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crates = root.parent().unwrap();
    let mut files: Vec<PathBuf> = Vec::new();
    for c in [
        "wrendns-policy",
        "wrendns-filter",
        "wrendns-cache",
        "wrendns-proto",
        "wrendns-upstream",
        "wrendns-recursor",
        "wrendns-net",
        "wrendns-telemetry",
    ] {
        rust_files(&crates.join(c).join("src"), &mut files);
    }
    let src = root.join("src");
    for m in [
        "identify.rs",
        "identify",
        "policy_view.rs",
        "device_dns.rs",
        "locations.rs",
        "devices.rs",
        "pipeline.rs",
        "forward.rs",
        "own_networks.rs",
        "mdns.rs",
        "profiles.rs",
        "group_sources.rs",
        "simulate.rs",
        "simulate",
        "explain.rs",
        "explain",
    ] {
        let p = src.join(m);
        if p.is_dir() {
            rust_files(&p, &mut files);
        } else if p.exists() {
            files.push(p);
        }
    }
    assert!(files.len() > 30, "the scan found {} files", files.len());
    let mut bad: Vec<String> = Vec::new();
    for f in &files {
        let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // A test file may name it (this one does not live there); forward.rs only forwards settings
        // writes of the `cmdb` kind, which is not CMDB data.
        let text = std::fs::read_to_string(f)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let allowed_kind_only = name == "forward.rs";
        let hits = text.matches("cmdb").count();
        let kind_hits =
            text.matches("managedkind::cmdb").count() + text.matches("\"cmdb\"").count();
        if hits > 0 && !(allowed_kind_only && hits == kind_hits) {
            bad.push(f.display().to_string());
        }
    }
    assert!(bad.is_empty(), "these files mention the CMDB: {bad:?}");
    // And nothing outside the module, the API glue and the start-up wiring reads its store.
    let mut all: Vec<PathBuf> = Vec::new();
    rust_files(&src, &mut all);
    let mut readers: Vec<String> = Vec::new();
    for f in all {
        let rel = f
            .strip_prefix(&src)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        if rel.starts_with("cmdb/") {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap_or_default();
        if text.contains("wrendns_store::cmdb") || text.contains("CmdbDb") {
            readers.push(rel);
        }
    }
    assert!(
        readers.is_empty(),
        "these files read the CMDB store: {readers:?}"
    );
}

// -- the figures at the caps (run by hand) -----------------------------------------------------

fn top_maps(label: &str) {
    let text = std::fs::read_to_string("/proc/self/smaps").unwrap_or_default();
    let mut rows: Vec<(u64, String)> = Vec::new();
    let mut cur = String::new();
    for l in text.lines() {
        if l.chars().next().is_some_and(|c| c.is_ascii_hexdigit())
            && l.contains('-')
            && l.split_whitespace().count() >= 5
        {
            cur = l.to_owned();
        } else if let Some(v) = l.strip_prefix("Rss:") {
            let kb: u64 = v.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0);
            rows.push((kb, cur.clone()));
        }
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.0));
    for (kb, m) in rows.iter().take(6) {
        eprintln!("{label}: {kb} KiB {m}");
    }
}

/// The anonymous part of the resident set (the heap): what the CMDB's data takes. The code pages of
/// the test binary (a debug build of a hundred megabytes, faulted in as it runs) are file-backed and
/// not the CMDB's data; the release binary's added code is reported with the image delta.
fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("RssAnon:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0)
}

/// A representative record of a real source (a UniFi or SNMP client): about a dozen attributes and
/// 500 bytes of JSON (addresses, names, a VLAN, the network, an access point or a switch port,
/// LLDP neighbours, a model, firmware and a role), not the minimum a MAC needs.
fn rich(r: &mut crate::cmdb::model::Record, i: u32) {
    r.list(
        "addresses",
        vec![
            format!(
                "10.{}.{}.{}",
                1 + ((i >> 16) & 0xff),
                (i >> 8) & 0xff,
                i & 0xff
            ),
            format!("fd00:{:x}::{:x}", (i >> 8) & 0xff, i & 0xff),
        ],
    );
    r.text("name", format!("host-{i}"));
    r.text("hostname", format!("host-{i}.home.arpa"));
    r.text("network", format!("vlan-{}-lan", i % 8));
    r.num("vlan", i64::from(10 + i % 8));
    r.text("ap", format!("access-point-living-room-{}", i % 12));
    r.text(
        "port",
        format!("core-switch-24-port-poe port {}", 1 + i % 24),
    );
    r.list(
        "lldp",
        vec![
            format!("core-switch-24-port-poe/{}", 1 + i % 24),
            format!("chassis-{:08x}", i.wrapping_mul(2_654_435_761)),
            "system-description: managed switch, firmware 7.2.1".to_owned(),
        ],
    );
    r.text("model", "US-24-250W managed PoE switch");
    r.text("firmware", format!("7.2.{}.15123", i % 10));
    r.text("role", "client");
    r.text(
        "description",
        format!("wired client {i}, kitchen, seen by the core switch and the access point"),
    );
}

/// REQ: DSC-906 (AC 5) - at the caps (16,384 CIs and 65,536 source records) the process holds at
/// most 8 MiB more than before the CMDB and the database is at most 64 MiB on disk. Run by hand, in
/// two fresh processes that share a directory, so the second one measures a restart at the caps
/// (the steady state) and the first the bulk load (the peak):
/// `CMDB_FIG_DIR=/tmp/cmdbfig cargo test -p wrendns --bin wrendns dsc_906_figures_at_the_caps
/// -- --ignored --nocapture --test-threads=1` (run it twice).
#[test]
#[ignore = "builds the database at its caps; run by hand for the figures"]
fn dsc_906_figures_at_the_caps() {
    let chunk_len = u32::try_from(INGEST_CHUNK).unwrap();
    let held = std::env::var_os("CMDB_FIG_DIR").map(PathBuf::from);
    let tmp = tempfile::tempdir().unwrap();
    let dir: PathBuf = held.clone().unwrap_or_else(|| tmp.path().to_path_buf());
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cmdb.db");
    let populated = path.exists() && std::fs::metadata(&path).map_or(0, |m| m.len()) > 1_000_000;
    // In the binary SQLite is in use already (state.db): warm it, so its own code and tables are
    // not counted as the CMDB's.
    {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE t (a INTEGER PRIMARY KEY, b TEXT); INSERT INTO t (b) VALUES ('x'), ('y');").unwrap();
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
    }
    let before = rss_kib();
    let db = Arc::new(CmdbDb::open(&path).unwrap());
    let opened = rss_kib();
    let mut e = Engine::open(&db, T0).unwrap();
    eprintln!(
        "stages: start {before} KiB, database opened {opened} KiB, index read {} KiB",
        rss_kib()
    );
    if !populated {
        // 8,192 MACs (an interface CI and a device CI each: 16,384 CIs) seen by 8 sources
        // (65,536 records).
        let sources = [
            "unifi:home",
            "neighbor",
            "snmp:core",
            "home_assistant:ha",
            "mdns",
            "lease",
            "opnsense:fw",
            "import:scan",
        ];
        for (si, s) in sources.iter().enumerate() {
            let mut at = T0 + i64::try_from(si).unwrap();
            for chunk in 0..64u32 {
                let recs: Vec<_> = (0..chunk_len)
                    .map(|n| {
                        let i = chunk * chunk_len + n;
                        let m = mac(i);
                        let mut r = host(s, &m, &m, at);
                        rich(&mut r, i);
                        r
                    })
                    .collect();
                e.ingest(
                    SourceBatch {
                        source: (*s).to_owned(),
                        complete: false,
                        records: recs,
                        at,
                    },
                    at,
                )
                .unwrap();
                at += 1;
            }
        }
        db.checkpoint().unwrap();
    }
    // A restart at the caps: the sources report everything again, unchanged, in the batches they
    // come in (the steady state of the thread: probe, compare, write nothing).
    let sources = [
        "unifi:home",
        "neighbor",
        "snmp:core",
        "home_assistant:ha",
        "mdns",
        "lease",
        "opnsense:fw",
        "import:scan",
    ];
    let mut cycle_written = 0usize;
    if populated {
        for cycle in 0..3i64 {
            for s in &sources {
                let at = T0 + 100_000 + cycle * 60;
                for chunk in 0..64u32 {
                    let recs: Vec<_> = (0..chunk_len)
                        .map(|n| {
                            let i = chunk * chunk_len + n;
                            let m = mac(i);
                            let mut r = host(s, &m, &m, at);
                            rich(&mut r, i);
                            r
                        })
                        .collect();
                    let rep = e
                        .ingest(
                            SourceBatch {
                                source: (*s).to_owned(),
                                complete: false,
                                records: recs,
                                at,
                            },
                            at,
                        )
                        .unwrap();
                    cycle_written += rep.written;
                }
                if cycle == 0 {
                    eprintln!("  after source {s}: RSS {} KiB", rss_kib());
                }
            }
            eprintln!("after cycle {cycle}: RSS {} KiB", rss_kib());
        }
    }
    let (total, _) = e.record_counts();
    let cis = db.read(|o| o.ci_count(None)).unwrap();
    let after = rss_kib();
    let disk = db.disk_bytes();
    eprintln!(
        "{}: {total} records, {cis} CIs; RSS {before} KiB -> {after} KiB (+{} KiB); {} KiB on disk; the engine keeps about {} KiB; {cycle_written} records rewritten in 3 unchanged cycles",
        if populated {
            "restart at the caps, then 3 full unchanged cycles"
        } else {
            "bulk load to the caps"
        },
        after.saturating_sub(before),
        disk / 1024,
        e.index_bytes() / 1024
    );
    assert_eq!(total, 65_536);
    assert_eq!(cis, 16_384);
    assert!(disk <= 64 * 1024 * 1024, "more than 64 MiB on disk");
    if populated {
        assert_eq!(cycle_written, 0, "an unchanged cycle writes no record");
        assert!(
            after.saturating_sub(before) <= 8 * 1024,
            "more than 8 MiB extra RSS"
        );
    }
}

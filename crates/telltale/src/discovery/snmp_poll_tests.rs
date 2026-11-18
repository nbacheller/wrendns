//! Tests of one poll (DSC-004, ADR-908): which tables answer, what is walked, and the caps and
//! pacing, against recorded-shape walks served by a fake agent on a virtual clock. No packet leaves
//! the test process.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::time::{Duration, Instant};

use telltale_config::SnmpTable;
use telltale_snmp::oid::Oid;
use telltale_snmp::pdu::{Value, VarBind};

use super::super::snmp_fixtures::{Behaviour, Clock, FakeMib, GATEWAY, SWITCH, parse_walk};
use super::super::snmp_job::{AuthSpec, Secret, SnmpRequest};
use super::super::snmp_tables::Row;
use super::*;

const ALL: [SnmpTable; 4] = [
    SnmpTable::Arp,
    SnmpTable::Ifmib,
    SnmpTable::Bridge,
    SnmpTable::Lldp,
];

fn request(tables: &[SnmpTable]) -> SnmpRequest {
    SnmpRequest {
        agent: "gateway".into(),
        address: std::net::Ipv4Addr::new(10, 0, 0, 1),
        port: 161,
        auth: AuthSpec::V2c {
            community: Secret::new(b"ttcomm".to_vec()),
        },
        tables: tables.to_vec(),
        max_repetitions: 10,
        known: None,
    }
}

fn choice<'a>(o: &'a Outcome, part: &str) -> Option<&'a str> {
    o.result
        .capability
        .as_ref()
        .and_then(|c| c.choices.iter().find(|c| c.part == part))
        .and_then(|c| c.alt.as_deref())
}

fn arp_rows(o: &Outcome) -> usize {
    o.rows
        .iter()
        .filter(|r| matches!(r, Row::Arp { .. }))
        .count()
}

/// REQ: DSC-004 (`dsc_004_arp_physical_then_media_fallback`) — ARP is read from
/// `ipNetToPhysicalTable`, and from `ipNetToMediaTable` only when the first one does not answer.
/// The owner's gateway shape: 108 IPv4 (98 with a MAC) and 81 IPv6 entries; the IPv6 ones are
/// counted and ignored, and the incomplete ones are skipped.
#[test]
fn dsc_004_arp_physical_then_media_fallback() {
    let clock = Clock::new();
    let mut mib = FakeMib::from_walk(GATEWAY, &clock);
    let o = run(
        &mut mib,
        &mut clock.clone(),
        &request(&[SnmpTable::Arp]),
        false,
    );
    assert_eq!(choice(&o, "arp"), Some("ipNetToPhysicalTable"));
    assert_eq!(arp_rows(&o), 98);
    assert_eq!(o.result.ipv6_ignored, 81);
    assert_eq!(
        o.result.skipped, 10,
        "the incomplete entries are not bindings"
    );
    assert_eq!(
        mib.requests_under("1.3.6.1.2.1.4.22"),
        0,
        "the media table is never asked when the physical one answers"
    );

    // A device that serves only ipNetToMediaTable: the probe of the physical table finds nothing,
    // and the media table is walked.
    let clock = Clock::new();
    let mut media_only = FakeMib::from_walk(GATEWAY, &clock).without("1.3.6.1.2.1.4.35");
    let o = run(
        &mut media_only,
        &mut clock.clone(),
        &request(&[SnmpTable::Arp]),
        false,
    );
    assert_eq!(choice(&o, "arp"), Some("ipNetToMediaTable"));
    assert_eq!(arp_rows(&o), 98);
    assert_eq!(o.result.skipped, 10, "type invalid(2) is not a binding");
    assert_eq!(
        media_only.requests_under("1.3.6.1.2.1.4.35"),
        1,
        "the physical table got its one probe and nothing more"
    );
    assert_eq!(o.result.ipv6_ignored, 0);
}

/// REQ: DSC-004 (`dsc_004_capabilities_probed_not_assumed`) — a poll probes first, with one GETNEXT on
/// each root; a table that does not answer is never walked. A later poll that is given the capability
/// record sends no probe at all. The round's keys are begun and ended once per poll.
#[test]
fn dsc_004_capabilities_probed_not_assumed() {
    let clock = Clock::new();
    let mut gw = FakeMib::from_walk(GATEWAY, &clock);
    let o = run(&mut gw, &mut clock.clone(), &request(&ALL), false);
    // The gateway has no BRIDGE, Q-BRIDGE or LLDP MIB.
    for part in ["forwarding", "ports", "vlans", "neighbours", "local_ports"] {
        assert_eq!(choice(&o, part), None, "{part}");
    }
    assert_eq!(choice(&o, "interfaces"), Some("ifTable"));
    assert_eq!(choice(&o, "addresses"), Some("ipAddressTable"));
    for prefix in ["1.3.6.1.2.1.17.", "1.0.8802."] {
        let kinds: Vec<&str> = gw
            .log
            .borrow()
            .iter()
            .filter(|(_, _, o)| o.starts_with(&Oid::parse(prefix.trim_end_matches('.')).unwrap()))
            .map(|(_, k, _)| *k)
            .collect();
        assert!(!kinds.is_empty(), "{prefix} was probed");
        assert!(
            kinds.iter().all(|k| *k == "next"),
            "only a GETNEXT probe goes to a table that does not answer: {kinds:?}"
        );
    }
    let skipped = o
        .result
        .walks
        .iter()
        .filter(|w| w.stop == "skipped")
        .count();
    assert_eq!(skipped, 5, "{:?}", o.result.walks);
    assert_eq!(gw.rounds(), (1, 1));
    let cap = o.result.capability.clone().unwrap();
    assert_eq!(cap.level, "v2c");
    assert_eq!(
        cap.sys_object_id.as_deref(),
        Some("1.3.6.1.4.1.8072.3.2.10")
    );

    // The second poll is told what answered, and probes nothing.
    let clock = Clock::new();
    let mut again = FakeMib::from_walk(GATEWAY, &clock);
    let mut req = request(&ALL);
    req.known = Some(cap.choices);
    let o2 = run(&mut again, &mut clock.clone(), &req, false);
    assert!(o2.result.capability.is_none());
    assert_eq!(again.requests_under("1.3.6.1.2.1.17"), 0);
    assert_eq!(again.requests_under("1.0.8802"), 0);
    assert!(
        again.log.borrow().iter().all(|(_, k, _)| *k == "bulk"),
        "no probe, no sysObjectID read"
    );
    assert_eq!(arp_rows(&o2), 98);

    // An agent that answers only the bridge and LLDP tables.
    let clock = Clock::new();
    let mut sw = FakeMib::from_walk(SWITCH, &clock)
        .without("1.3.6.1.2.1.4.35")
        .without("1.3.6.1.2.1.4.22");
    let o3 = run(&mut sw, &mut clock.clone(), &request(&ALL), false);
    assert_eq!(choice(&o3, "arp"), None);
    assert_eq!(choice(&o3, "forwarding"), Some("dot1qTpFdbTable"));
    assert_eq!(choice(&o3, "vlans"), Some("dot1qVlanCurrentTable"));
    assert_eq!(choice(&o3, "ports"), Some("dot1dBasePortIfIndex"));
    assert_eq!(choice(&o3, "neighbours"), Some("lldpRemTable"));
}

/// REQ: DSC-004 — a probe-only job sends no walk, and the VLAN table is probed only when the
/// forwarding table is the Q-BRIDGE one.
#[test]
fn dsc_004_probe_only_and_vlans_follow_qbridge() {
    let clock = Clock::new();
    let mut sw = FakeMib::from_walk(SWITCH, &clock);
    let o = run(
        &mut sw,
        &mut clock.clone(),
        &request(&[SnmpTable::Bridge]),
        true,
    );
    assert!(sw.log.borrow().iter().all(|(_, k, _)| *k != "bulk"));
    assert_eq!(o.rows.len(), 0);
    assert!(o.result.capability.is_some());
    // The BRIDGE-MIB forwarding table only: the VLAN table is not even probed.
    let clock = Clock::new();
    let mut d = FakeMib::from_walk(SWITCH, &clock).without("1.3.6.1.2.1.17.7.1.2");
    let o = run(
        &mut d,
        &mut clock.clone(),
        &request(&[SnmpTable::Bridge]),
        true,
    );
    assert_eq!(
        choice(&o, "forwarding"),
        None,
        "no dot1dTpFdbTable in the fixture"
    );
    assert_eq!(d.requests_under("1.3.6.1.2.1.17.7.1.4"), 0);
}

fn windowed_max(times: &[Instant], window: Duration) -> usize {
    let mut best = 0;
    for (i, t) in times.iter().enumerate() {
        let n = times[i..].iter().take_while(|u| **u < *t + window).count();
        best = best.max(n);
    }
    best
}

/// REQ: DSC-004 (`dsc_004_pacing_limits`) — at least 50 ms between any two requests (so at most 20 in
/// a second), 5,000 rows and 30 s per walk, a 100 s cap on the poll, and three timeouts in a row end
/// it. A whole poll of the switch is checked on a virtual clock.
#[test]
#[allow(clippy::too_many_lines)] // one story: gaps, then each cap in turn
fn dsc_004_pacing_limits() {
    // A whole poll: every gap is at least 50 ms and no second holds more than 20 requests.
    let clock = Clock::new();
    let mut sw = FakeMib::from_walk(SWITCH, &clock);
    let o = run(&mut sw, &mut clock.clone(), &request(&ALL), false);
    assert!(o.result.requests > 20, "a real poll: {}", o.result.requests);
    let times: Vec<Instant> = sw.log.borrow().iter().map(|(t, _, _)| *t).collect();
    for pair in times.windows(2) {
        assert!(
            pair[1] - pair[0] >= Duration::from_millis(50),
            "gap {:?}",
            pair[1] - pair[0]
        );
    }
    assert!(windowed_max(&times, Duration::from_secs(1)) <= 20);
    assert_eq!(o.result.requests as usize, times.len());

    // 5,000 rows per walk.
    let clock = Clock::new();
    let base = Oid::parse("1.3.6.1.2.1.4.35.1.4").unwrap();
    let rows: Vec<VarBind> = (1..=12_000u32)
        .map(|i| VarBind {
            oid: base
                .child(1)
                .and_then(|o| o.child(1))
                .and_then(|o| o.child(4))
                .and_then(|o| o.child(10))
                .and_then(|o| o.child(i >> 16))
                .and_then(|o| o.child((i >> 8) & 255))
                .and_then(|o| o.child(i & 255))
                .unwrap(),
            value: Value::OctetString(vec![2, 0, 0, 0, 0, 1]),
        })
        .collect();
    let mut big = FakeMib::new(rows, &clock);
    let o = run(
        &mut big,
        &mut clock.clone(),
        &request(&[SnmpTable::Arp]),
        false,
    );
    let w = o.result.walks.first().unwrap();
    assert_eq!((w.rows, w.stop.as_str()), (5_000, "row_cap"), "{w:?}");

    // 30 s per walk: each answer takes a second, so a walk ends at the cap.
    let clock = Clock::new();
    let rows: Vec<VarBind> = (1..=100_000u32)
        .map(|i| VarBind {
            oid: Oid::parse(&format!(
                "1.3.6.1.2.1.4.35.1.4.1.1.4.10.{}.{}.{}",
                i >> 16,
                (i >> 8) & 255,
                i & 255
            ))
            .unwrap(),
            value: Value::OctetString(vec![2, 0, 0, 0, 0, 1]),
        })
        .collect();
    let mut slow = FakeMib::new(rows, &clock);
    slow.behaviour = Behaviour::Slow(Duration::from_secs(1));
    let started = clock.now();
    let o = run(
        &mut slow,
        &mut clock.clone(),
        &request(&[SnmpTable::Arp]),
        false,
    );
    let w = o.result.walks.first().unwrap();
    assert_eq!(w.stop, "time_cap", "{w:?}");
    assert!(
        clock.now() - started <= Duration::from_secs(40),
        "a walk ends near its 30 s cap, not later: {:?}",
        clock.now() - started
    );

    // The poll's own cap: every answer takes 5 s, so no more is asked after 100 s.
    let clock = Clock::new();
    let mut crawl = FakeMib::from_walk(SWITCH, &clock);
    crawl.behaviour = Behaviour::Slow(Duration::from_secs(5));
    let started = clock.now();
    let o = run(&mut crawl, &mut clock.clone(), &request(&ALL), false);
    assert_eq!(
        o.result.aborted.as_deref(),
        Some("the poll's time cap was reached")
    );
    assert!(clock.now() - started <= Duration::from_secs(120));
    assert_eq!(
        crawl.rounds(),
        (1, 1),
        "the round ends even when the poll is cut short"
    );

    // Three timeouts in a row end the poll, and nothing is walked.
    let clock = Clock::new();
    let mut dead = FakeMib::from_walk(GATEWAY, &clock);
    dead.behaviour = Behaviour::Silent;
    let o = run(&mut dead, &mut clock.clone(), &request(&ALL), false);
    assert_eq!(o.result.aborted.as_deref(), Some("three timeouts in a row"));
    assert_eq!((o.result.timeouts, o.result.requests), (3, 3));
    assert_eq!(o.rows.len(), 0);
    assert_eq!(dead.rounds(), (1, 1));

    // A timeout that is followed by an answer does not count toward the three.
    let clock = Clock::new();
    let mut flaky = FakeMib::from_walk(GATEWAY, &clock);
    flaky.behaviour = Behaviour::SilentAfter(40);
    let o = run(
        &mut flaky,
        &mut clock.clone(),
        &request(&[SnmpTable::Arp]),
        false,
    );
    assert!(o.result.requests >= 4);
}

/// REQ: DSC-004 — the repetitions a request asks for are clamped to 5..=25 (ADR-908 sizes).
#[test]
fn dsc_004_max_repetitions_are_clamped() {
    assert_eq!(limits(0).max_repetitions, 5);
    assert_eq!(limits(10).max_repetitions, 10);
    assert_eq!(limits(1_000).max_repetitions, 25);
    assert_eq!(limits(10).gap, MIN_GAP);
}

/// REQ: DSC-004, DSC-003 — a walked fixture parses into the rows the interpretation needs: every
/// table of the switch is read, and the gateway's own addresses come from the old address table.
#[test]
fn dsc_004_every_part_of_the_switch_is_parsed() {
    let clock = Clock::new();
    let mut sw = FakeMib::from_walk(SWITCH, &clock);
    let o = run(&mut sw, &mut clock.clone(), &request(&ALL), false);
    let count = |f: fn(&Row) -> bool| o.rows.iter().filter(|r| f(r)).count();
    assert_eq!(count(|r| matches!(r, Row::Iface { .. })), 24);
    assert_eq!(count(|r| matches!(r, Row::PortIf { .. })), 24);
    assert_eq!(count(|r| matches!(r, Row::VlanFdb { .. })), 3);
    assert_eq!(count(|r| matches!(r, Row::Fdb { .. })), 4 + 12 + 2 + 2);
    assert_eq!(count(|r| matches!(r, Row::Lldp { .. })), 3);
    assert_eq!(count(|r| matches!(r, Row::LldpLoc { .. })), 24);
    assert_eq!(count(|r| matches!(r, Row::Arp { .. })), 3);
    // The text is device-supplied: it is cut and has no control characters.
    let mut rows = parse_walk(SWITCH);
    rows.push(VarBind {
        oid: Oid::parse("1.3.6.1.2.1.31.1.1.1.1.99").unwrap(),
        value: Value::OctetString(b"a\x1b[2J\nb".iter().chain(&[b'x'; 300]).copied().collect()),
    });
    rows.sort_by(|a, b| a.oid.cmp(&b.oid));
    let clock = Clock::new();
    let mut hostile = FakeMib::new(rows, &clock);
    let o = run(
        &mut hostile,
        &mut clock.clone(),
        &request(&[SnmpTable::Ifmib]),
        false,
    );
    let name = o
        .rows
        .iter()
        .find_map(|r| match r {
            Row::Iface {
                index: 99, name, ..
            } => Some(name.clone()),
            _ => None,
        })
        .unwrap();
    assert!(
        name.len() <= 64 && !name.chars().any(char::is_control),
        "{name:?}"
    );
}

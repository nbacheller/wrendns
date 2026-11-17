//! Tests for the inventory's merge, caps, retention, mutes and storage (DSC-008, DSC-015,
//! ADR-910, ADR-923). Requirement IDs are in the test names (`dsc_008_...`).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use telltale_net::Neighbor;

use crate::devices::{Lease, Leases};
use crate::discovery::inventory::*;
use crate::discovery::sources::{
    Ipv4Subnet, ifindex_names, lease_observations, neighbour_observations, parse_mac,
};
use crate::discovery::{store, thread};

const A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const B: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x66];
/// Locally administered (the randomised bit set).
const RND: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x77];

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn obs(source: Source, mac: Option<[u8; 6]>, addr: Option<&str>, seen: u64) -> Observation {
    let mut o = Observation::new(source, seen);
    o.mac = mac;
    o.ip = addr.map(ip);
    o
}

/// A distinct MAC per number, for filling the caps.
fn mac_n(i: u32) -> [u8; 6] {
    let [b0, b1, b2, b3] = i.to_be_bytes();
    [0x00, 0x11, b0, b1, b2, b3]
}

fn key_mac(m: [u8; 6]) -> Key {
    Key::Mac(m)
}

/// A count as a `u32`, saturating (the caps are far below it).
fn cap32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tt-inv-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn dsc_008_mac_keyed_precedence() {
    let mut inv = Inventory::new(0);
    inv.apply(
        &[obs(Source::Router, Some(A), Some("192.168.1.10"), 100)],
        100,
    );
    inv.apply(
        &[obs(Source::Neighbor, Some(A), Some("192.168.1.11"), 200)],
        200,
    );
    let rows = [obs(Source::Import, Some(A), Some("192.168.1.12"), 210)];
    inv.apply_import("scan", &rows, 210).unwrap();
    assert_eq!(inv.len(), 1, "one entry per MAC");
    let e = inv.get(&key_mac(A)).unwrap();
    // The router's class 1 binding is current even though the neighbour table is newer.
    assert_eq!(e.current().unwrap().ip, ip("192.168.1.10"));
    assert_eq!(e.addrs.len(), 3, "the others are kept as aliases");
    // A newer router answer for another address becomes current.
    inv.apply(
        &[obs(Source::Router, Some(A), Some("192.168.1.11"), 300)],
        300,
    );
    let e = inv.get(&key_mac(A)).unwrap();
    assert_eq!(e.current().unwrap().ip, ip("192.168.1.11"));
}

#[test]
fn dsc_008_same_ip_two_macs_flags_conflict() {
    let mut inv = Inventory::new(0);
    inv.apply(
        &[obs(Source::Router, Some(A), Some("192.168.1.50"), 100)],
        100,
    );
    inv.apply(
        &[obs(Source::Neighbor, Some(B), Some("192.168.1.50"), 200)],
        200,
    );
    let b = inv.get(&key_mac(B)).unwrap();
    assert!(b.conflict, "the newer claim is flagged");
    assert_eq!(b.current().unwrap().ip, ip("192.168.1.50"));
    let a = inv.get(&key_mac(A)).unwrap();
    assert!(a.conflict, "the displaced entry is flagged too");
    assert!(a.addrs.iter().all(|x| x.ip != ip("192.168.1.50")));
    assert_eq!(
        inv.visible_findings(&key_mac(B), 200),
        vec![FindingKind::IpConflict]
    );
    // Once the displaced claim is gone, the sweep clears the flag.
    inv.sweep(300, u64::MAX / 2, u64::MAX / 2);
    assert!(!inv.get(&key_mac(B)).unwrap().conflict);
}

#[test]
fn dsc_008_import_never_overrides_l2() {
    let mut inv = Inventory::new(0);
    inv.apply(
        &[obs(Source::Neighbor, Some(A), Some("192.168.1.20"), 100)],
        100,
    );
    let rows = [
        obs(Source::Import, Some(A), Some("192.168.1.99"), 110),
        obs(Source::Import, Some(B), Some("192.168.1.20"), 110),
    ];
    inv.apply_import("scan", &rows, 110).unwrap();
    let a = inv.get(&key_mac(A)).unwrap();
    assert_eq!(a.current().unwrap().ip, ip("192.168.1.20"));
    assert_eq!(a.current().unwrap().source, Source::Neighbor);
    // The import's claim on the same address does not take it from A.
    assert!(
        inv.snmp_eligible_address(ip("192.168.1.20")),
        "A keeps its class 2 binding"
    );
    assert!(inv.get(&key_mac(B)).unwrap().conflict);
}

#[test]
fn dsc_008_ip_only_merges_when_mac_arrives() {
    let mut inv = Inventory::new(0);
    inv.apply(&[obs(Source::Mdns, None, Some("192.168.1.30"), 100)], 100);
    assert!(inv.get(&Key::Ip(ip("192.168.1.30"))).is_some());
    inv.apply(
        &[obs(Source::Router, Some(A), Some("192.168.1.30"), 110)],
        110,
    );
    assert!(inv.get(&Key::Ip(ip("192.168.1.30"))).is_none());
    let e = inv.get(&key_mac(A)).unwrap();
    assert!(e.addrs.iter().any(|b| b.ip == ip("192.168.1.30")));
    assert_eq!(inv.len(), 1);
}

/// REQ: DSC-008 (review fix 2) — a known MAC absorbs an IP-only entry for its address, not only a
/// new MAC does.
#[test]
fn dsc_008_known_mac_absorbs_ip_only() {
    let mut inv = Inventory::new(0);
    inv.apply(
        &[obs(Source::Router, Some(A), Some("192.168.1.31"), 100)],
        100,
    );
    inv.apply(&[obs(Source::Mdns, None, Some("192.168.1.32"), 110)], 110);
    assert!(inv.get(&Key::Ip(ip("192.168.1.32"))).is_some());
    inv.apply(
        &[obs(Source::Neighbor, Some(A), Some("192.168.1.32"), 120)],
        120,
    );
    assert!(inv.get(&Key::Ip(ip("192.168.1.32"))).is_none());
    let e = inv.get(&key_mac(A)).unwrap();
    assert!(e.addrs.iter().any(|b| b.ip == ip("192.168.1.32")));
    assert!(e.addrs.iter().any(|b| b.ip == ip("192.168.1.31")));
    assert_eq!(inv.len(), 1);
}

/// REQ: DSC-008 (review fix 2) — an mDNS claim with no MAC for a router's address is the same
/// device: no conflict, and the router's binding stays current.
#[test]
fn dsc_008_mdns_ip_only_keeps_router_binding() {
    let mut inv = Inventory::new(0);
    inv.apply(
        &[obs(Source::Router, Some(A), Some("192.168.1.33"), 100)],
        100,
    );
    let mut m = obs(Source::Mdns, None, Some("192.168.1.33"), 200);
    m.name = Some((NameKind::Mdns, "printer".to_owned()));
    // Repeated every minute, as the thread does.
    for t in [200u64, 260, 320] {
        m.seen = t;
        inv.apply(std::slice::from_ref(&m), t);
    }
    assert_eq!(inv.len(), 1, "no second device for the address");
    let e = inv.get(&key_mac(A)).unwrap();
    assert_eq!(e.current().unwrap().ip, ip("192.168.1.33"));
    assert_eq!(e.current().unwrap().source, Source::Router);
    assert!(!e.conflict, "a claim without a MAC is not a conflict");
    assert!(
        e.names.iter().any(|n| n.kind == NameKind::Mdns),
        "its name lands on the device"
    );
}

/// REQ: DSC-008 (review fix 2) — a routed scan row (no MAC) for a known address joins that device.
#[test]
fn dsc_008_routed_import_joins_known_device() {
    let mut inv = Inventory::new(0);
    inv.apply(
        &[obs(Source::Router, Some(A), Some("192.168.1.34"), 100)],
        100,
    );
    let mut row = obs(Source::Import, None, Some("192.168.1.34"), 110);
    row.name = Some((NameKind::Import, "scan-host".to_owned()));
    inv.apply_import("scan.xml", &[row], 110).unwrap();
    assert_eq!(inv.len(), 1, "no duplicate IP-only entry");
    let e = inv.get(&key_mac(A)).unwrap();
    assert!(!e.conflict, "a routed row is not a second device");
    assert!(e.names.iter().any(|n| n.kind == NameKind::Import));
}

/// REQ: DSC-008 (review fix 2) — a claim from a source with no class never makes an address an
/// SNMP destination (ADR-907, ADR-923), even when it is the only source.
#[test]
fn dsc_008_mdns_and_ha_addresses_are_never_snmp_eligible() {
    let mut inv = Inventory::new(0);
    inv.apply(
        &[obs(Source::Mdns, Some(A), Some("192.168.1.35"), 100)],
        100,
    );
    inv.apply(
        &[obs(
            Source::HomeAssistant,
            Some(B),
            Some("192.168.1.36"),
            100,
        )],
        100,
    );
    assert!(!inv.snmp_eligible_address(ip("192.168.1.35")));
    assert!(!inv.snmp_eligible_address(ip("192.168.1.36")));
    assert!(!inv.get(&key_mac(A)).unwrap().snmp_eligible());
    assert!(!Source::Mdns.is_current());
    assert!(!Source::HomeAssistant.is_current());
    assert!(!Source::Snmp.is_current());
    assert!(!Source::Config.is_current());
    assert_eq!(Source::Router.class(), Some(1));
    assert_eq!(Source::Neighbor.class(), Some(2));
    assert_eq!(Source::SnmpArp.class(), Some(3));
    assert_eq!(Source::Import.class(), Some(4));
    assert_eq!(Source::History.class(), Some(5));
}

/// REQ: DSC-008 (review fix 4) — an import's claim on a neighbour's address keeps its own record,
/// so the neighbour's record still expires and the address stops being SNMP-eligible.
#[test]
fn dsc_008_import_does_not_refresh_neighbour_record() {
    let mut inv = Inventory::new(0);
    inv.apply(
        &[obs(Source::Neighbor, Some(A), Some("192.168.1.37"), 100)],
        100,
    );
    let rows = [obs(Source::Import, Some(A), Some("192.168.1.37"), 1_000)];
    inv.apply_import("scan", &rows, 1_000).unwrap();
    inv.expire_source(Source::Neighbor, 1_000, 120);
    assert!(
        !inv.snmp_eligible_address(ip("192.168.1.37")),
        "the stale neighbour binding expired"
    );
    assert!(inv.get(&key_mac(A)).is_some(), "the import keeps the entry");
}

/// REQ: DSC-008 (review fix 5) — a renamed device shows its new name, not its old one.
#[test]
fn dsc_008_rename_replaces_name() {
    let mut inv = Inventory::new(0);
    let mut a = obs(Source::Router, Some(A), Some("192.168.1.38"), 100);
    a.name = Some((NameKind::RouterAlias, "old".to_owned()));
    a.name_origin = Some("ucg".to_owned());
    inv.apply(std::slice::from_ref(&a), 100);
    a.name = Some((NameKind::RouterAlias, "new".to_owned()));
    a.seen = 200;
    inv.apply(std::slice::from_ref(&a), 200);
    let e = inv.get(&key_mac(A)).unwrap();
    assert_eq!(e.display_name().unwrap().label, "new");
    assert_eq!(e.names.len(), 1, "the old name is replaced, not kept");
    // A second router keeps its own alias beside the first.
    let mut b = obs(Source::Router, Some(A), Some("192.168.1.38"), 210);
    b.name = Some((NameKind::RouterAlias, "other".to_owned()));
    b.name_origin = Some("opnsense".to_owned());
    inv.apply(std::slice::from_ref(&b), 210);
    assert_eq!(inv.get(&key_mac(A)).unwrap().names.len(), 2);
}

#[test]
fn dsc_008_randomized_mac_flagged() {
    let mut inv = Inventory::new(0);
    let now = LEARNING_SECS + 1;
    let report = inv.apply(
        &[obs(Source::Router, Some(RND), Some("192.168.1.40"), now)],
        now,
    );
    assert!(inv.get(&key_mac(RND)).unwrap().randomized);
    assert_eq!(
        report.new_devices,
        Vec::<Key>::new(),
        "no stable-identity finding"
    );
    let report = inv.apply(
        &[obs(Source::Router, Some(A), Some("192.168.1.41"), now)],
        now,
    );
    assert_eq!(report.new_devices, vec![key_mac(A)]);
}

#[test]
fn dsc_008_empty_start_learning_period() {
    let mut inv = Inventory::new(1000);
    assert_eq!(inv.learning_until(), 1000 + LEARNING_SECS);
    assert!(inv.learning(1000));
    let during = inv.apply(
        &[obs(Source::Router, Some(A), Some("192.168.1.5"), 1000)],
        1000,
    );
    assert_eq!(
        during.new_devices,
        Vec::<Key>::new(),
        "no alerts while learning"
    );
    let after = inv.apply(
        &[obs(
            Source::Router,
            Some(B),
            Some("192.168.1.6"),
            1000 + LEARNING_SECS,
        )],
        1000 + LEARNING_SECS,
    );
    assert_eq!(after.new_devices, vec![key_mac(B)]);
    // A device learnt during the period never alerts later.
    let again = inv.apply(
        &[obs(
            Source::Router,
            Some(A),
            Some("192.168.1.5"),
            2 * LEARNING_SECS,
        )],
        2 * LEARNING_SECS,
    );
    assert_eq!(again.new_devices, Vec::<Key>::new());
}

#[test]
fn dsc_008_only_class_1_3_snmp_eligible() {
    let mut inv = Inventory::new(0);
    inv.apply(
        &[obs(Source::Neighbor, Some(A), Some("192.168.1.70"), 100)],
        100,
    );
    inv.apply(
        &[obs(Source::History, Some(B), Some("192.168.1.71"), 100)],
        100,
    );
    let rows = [obs(Source::Import, Some(RND), Some("192.168.1.72"), 100)];
    inv.apply_import("scan", &rows, 100).unwrap();
    assert!(
        inv.snmp_eligible_address(ip("192.168.1.70")),
        "class 2 is eligible"
    );
    assert!(
        !inv.snmp_eligible_address(ip("192.168.1.71")),
        "history never is"
    );
    assert!(
        !inv.snmp_eligible_address(ip("192.168.1.72")),
        "imports never are"
    );
    assert!(inv.get(&key_mac(A)).unwrap().snmp_eligible());
    assert!(!inv.get(&key_mac(B)).unwrap().snmp_eligible());
}

#[test]
fn dsc_008_caps_and_retention() {
    // 4,096 MAC entries: the least recently seen goes first.
    let mut inv = Inventory::new(0);
    for i in 1..=4_100u32 {
        let seen = u64::from(i);
        inv.apply(&[obs(Source::Neighbor, Some(mac_n(i)), None, seen)], seen);
    }
    assert_eq!(inv.len(), MAX_MAC_ENTRIES);
    assert!(inv.get(&key_mac(mac_n(1))).is_none());
    assert!(inv.get(&key_mac(mac_n(4_100))).is_some());

    // 1,024 IP-only entries.
    let mut ips = Inventory::new(0);
    for i in 0..1_100u32 {
        let seen = u64::from(i) + 1;
        let addr = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
        let mut o = Observation::new(Source::Mdns, seen);
        o.ip = Some(addr);
        ips.apply(&[o], seen);
    }
    let ip_only = ips.entries().filter(|e| e.mac().is_none()).count();
    assert_eq!(ip_only, MAX_IP_ONLY_ENTRIES);

    // 16 imports of 4,096 rows: at most 8,192 import rows survive, the oldest going first.
    let mut imp = Inventory::new(0);
    let rows: Vec<Observation> = (0..4_096u32)
        .map(|i| obs(Source::Import, Some(mac_n(i)), None, 10))
        .collect();
    for n in 0..16u64 {
        imp.apply_import("scan", &rows, 10 + n).unwrap();
    }
    assert!(imp.import_rows() <= MAX_IMPORT_ROWS);
    assert_eq!(imp.imports().len(), 2);
    assert!(imp.imports().iter().all(|r| r.at >= 24));
    let too_many: Vec<Observation> = (0..4_097u32)
        .map(|i| obs(Source::Import, Some(mac_n(i)), None, 1))
        .collect();
    assert_eq!(
        imp.apply_import("big", &too_many, 1),
        Err(ImportError::TooManyRows {
            rows: 4_097,
            max: MAX_ROWS_PER_IMPORT
        })
    );

    // Retention: an entry seen only by the neighbour table ages out; one with a router binding does not.
    let mut ret = Inventory::new(0);
    ret.apply(
        &[obs(Source::Neighbor, Some(A), Some("192.168.1.80"), 100)],
        100,
    );
    ret.apply(
        &[obs(Source::Router, Some(B), Some("192.168.1.81"), 100)],
        100,
    );
    let later = 100 + 7 * 86_400 + 1;
    ret.expire_source(Source::Neighbor, later, 120);
    ret.sweep(later, 7 * 86_400, 30 * 86_400);
    assert!(ret.get(&key_mac(A)).is_none());
    assert!(ret.get(&key_mac(B)).is_some());
}

#[test]
fn dsc_008_expire_source_tolerates_one_missed_poll() {
    let mut inv = Inventory::new(0);
    inv.apply(
        &[obs(Source::Neighbor, Some(A), Some("192.168.1.90"), 100)],
        100,
    );
    // Two poll intervals is 120 s: one missed poll keeps the host.
    inv.expire_source(Source::Neighbor, 200, 120);
    assert!(inv.get(&key_mac(A)).unwrap().current().is_some());
    inv.expire_source(Source::Neighbor, 221, 120);
    assert!(inv.get(&key_mac(A)).unwrap().current().is_none());
}

#[test]
fn dsc_008_remove_import_drops_its_rows() {
    let mut inv = Inventory::new(0);
    let rows = [obs(Source::Import, Some(A), Some("192.168.1.60"), 10)];
    let (bit, _) = inv.apply_import("scan", &rows, 10).unwrap();
    assert!(inv.get(&key_mac(A)).is_some());
    assert!(inv.remove_import(bit));
    assert!(inv.get(&key_mac(A)).is_none(), "an entry left empty goes");
    assert_eq!(inv.imports().len(), 0usize);
    assert!(!inv.remove_import(bit));
}

#[test]
fn dsc_008_mute_per_entry_and_kind() {
    let mut inv = Inventory::new(0);
    inv.apply(
        &[obs(Source::Router, Some(A), Some("192.168.1.95"), 100)],
        100,
    );
    inv.apply(
        &[obs(Source::Router, Some(B), Some("192.168.1.95"), 200)],
        200,
    );
    let key = key_mac(B);
    inv.mute(key, FindingKind::IpConflict, Some(500));
    assert_eq!(inv.visible_findings(&key, 100), Vec::<FindingKind>::new());
    assert_eq!(
        inv.visible_findings(&key, 600),
        vec![FindingKind::IpConflict]
    );
    assert!(inv.unmute(&key, FindingKind::IpConflict));
    assert_eq!(
        inv.visible_findings(&key, 100),
        vec![FindingKind::IpConflict]
    );
    // Muting one entry leaves the other alone.
    inv.mute(key, FindingKind::IpConflict, None);
    assert_eq!(
        inv.visible_findings(&key_mac(A), 100),
        vec![FindingKind::IpConflict],
        "the other entry keeps its finding"
    );
}

/// REQ: DSC-008 (review fix 12) — mutes are capped (oldest first), and pruned for entries that
/// are gone or have expired.
#[test]
fn dsc_008_mutes_capped_and_pruned() {
    let mut inv = Inventory::new(0);
    for i in 0..(cap32(MAX_MUTES) + 50) {
        inv.mute(key_mac(mac_n(i)), FindingKind::NewDevice, None);
    }
    assert_eq!(inv.mutes().len(), MAX_MUTES);
    assert_eq!(inv.mutes().first().map(|m| m.key), Some(key_mac(mac_n(50))));
    // No entries exist, so every mute is pruned by the sweep.
    inv.sweep(0, u64::MAX / 2, u64::MAX / 2);
    assert_eq!(inv.mutes().len(), 0);

    let mut kept = Inventory::new(0);
    kept.apply(&[obs(Source::Router, Some(A), Some("192.168.1.96"), 1)], 1);
    kept.mute(key_mac(A), FindingKind::IpConflict, Some(5));
    kept.mute(key_mac(A), FindingKind::NewDevice, None);
    kept.sweep(10, u64::MAX / 2, u64::MAX / 2);
    assert_eq!(kept.mutes().len(), 1, "the expired mute is pruned");
    let big: Vec<Mute> = (0..(cap32(MAX_MUTES) + 9))
        .map(|i| Mute {
            key: key_mac(mac_n(i)),
            kind: FindingKind::NewDevice,
            until: None,
        })
        .collect();
    assert_eq!(
        Inventory::restore(Vec::new(), Vec::new(), big, 0)
            .mutes()
            .len(),
        MAX_MUTES
    );
}

/// REQ: DSC-008 (review fix 12) — a stored file is untrusted: what its imports no longer cover is
/// cleared, and a bit past the mask is refused.
#[test]
fn dsc_008_restore_checks_import_bits() {
    let mut e = Entry::new(key_mac(A), 1);
    e.import_bits = (1 << 2) | (1 << 3);
    e.addrs.push(Binding {
        ip: ip("192.168.1.100"),
        source: Source::Import,
        seen: 1,
        import_bit: Some(2),
    });
    e.addrs.push(Binding {
        ip: ip("192.168.1.101"),
        source: Source::Import,
        seen: 1,
        import_bit: Some(3),
    });
    let imports = vec![
        ImportRecord {
            bit: 2,
            at: 1,
            rows: 1,
            label: "kept".to_owned(),
        },
        ImportRecord {
            bit: 40,
            at: 1,
            rows: 1,
            label: "refused".to_owned(),
        },
    ];
    let inv = Inventory::restore(vec![e], imports, Vec::new(), 0);
    assert_eq!(inv.imports().len(), 1, "a bit past 15 is refused");
    let got = inv.get(&key_mac(A)).unwrap();
    assert_eq!(
        got.import_bits,
        1 << 2,
        "bit 3 is not held by a kept import"
    );
    assert_eq!(got.addrs.len(), 1);
    assert_eq!(got.addrs.first().map(|b| b.ip), Some(ip("192.168.1.100")));
}

#[test]
fn dsc_015_device_strings_sanitized() {
    assert_eq!(
        sanitize("Kitchen\u{0007}\nTablet", NAME_MAX),
        "KitchenTablet"
    );
    let long: String = "é".repeat(100);
    let cut = sanitize(&long, NAME_MAX);
    assert!(cut.len() <= NAME_MAX);
    assert!(cut.chars().all(|c| c == 'é'));
    let mut inv = Inventory::new(0);
    let mut o = obs(Source::Router, Some(A), Some("192.168.1.99"), 1);
    o.name = Some((NameKind::RouterAlias, "tab\u{1b}[31mlet".to_owned()));
    inv.apply(&[o], 1);
    let shown = inv
        .get(&key_mac(A))
        .unwrap()
        .display_name()
        .unwrap()
        .label
        .clone();
    assert!(!shown.chars().any(char::is_control));
}

#[test]
fn dsc_008_neighbor_skips_container_interfaces() {
    let root = std::env::temp_dir().join(format!("tt-inv-ifindex-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for (name, idx) in [
        ("eth0", "2"),
        ("docker0", "3"),
        ("veth1a2b", "4"),
        ("lo", "1"),
    ] {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ifindex"), format!("{idx}\n")).unwrap();
    }
    let names = ifindex_names(&root);
    assert_eq!(names.get(&2).map(String::as_str), Some("eth0"));
    let subnets = [Ipv4Subnet::parse("192.168.1.0/24").unwrap()];
    let neigh = |ip: &str, ifindex, state| Neighbor {
        ip: ip.parse().unwrap(),
        mac: A,
        ifindex,
        state,
    };
    let table = [
        neigh("192.168.1.10", 2, 0x02), // kept: eth0, REACHABLE
        neigh("192.168.1.11", 3, 0x02), // docker0: skipped
        neigh("192.168.1.12", 4, 0x02), // veth: skipped
        neigh("192.168.1.13", 2, 0x80), // PERMANENT: not in the accepted states
        neigh("192.168.1.14", 2, 0x20), // FAILED
        neigh("10.0.0.5", 2, 0x02),     // outside the configured subnet
        neigh("fe80::1", 2, 0x02),      // IPv6 not in scope yet
    ];
    let out = neighbour_observations(&table, &names, &subnets, 5);
    assert_eq!(out.len(), 1);
    assert_eq!(out.first().and_then(|o| o.ip), Some(ip("192.168.1.10")));
    let _ = std::fs::remove_dir_all(&root);
}

/// REQ: DSC-008 (review fix 6) — a row whose interface name is unknown is refused (fails closed).
#[test]
fn dsc_008_neighbor_unknown_interface_fails_closed() {
    let subnets = [Ipv4Subnet::parse("192.168.1.0/24").unwrap()];
    let table = [Neighbor {
        ip: ip("192.168.1.10"),
        mac: A,
        ifindex: 2,
        state: 0x02,
    }];
    let none: HashMap<u32, String> = HashMap::new();
    assert_eq!(
        neighbour_observations(&table, &none, &subnets, 5),
        Vec::new()
    );
}

/// REQ: DSC-008 (review fix 11) — a lease past its expiry is not a current answer.
#[test]
fn dsc_008_expired_lease_is_skipped() {
    let mut view: Leases = HashMap::new();
    let mut add = |n: u8, expires: u64| {
        let addr = Ipv4Addr::new(192, 168, 1, n);
        view.insert(
            addr,
            Lease {
                mac: "AA:BB:CC:DD:EE:FF".to_owned(),
                ip: addr,
                hostname: None,
                expires,
                router: None,
            },
        );
    };
    add(201, 50); // expired at 100
    add(202, 0); // unknown expiry: kept
    add(203, 200); // still valid
    let out = lease_observations(&view, Source::Router, 100);
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|o| o.ip != Some(ip("192.168.1.201"))));
}

/// REQ: DSC-008 — the containment tests cover every discovery module, not only the model.
#[test]
fn dsc_008_never_in_neighbors_or_leases() {
    // No discovery module names the policy neighbour table, the lease maps DNS names come from,
    // the mDNS name map, or the identify chain (ADR-910). `devices::Leases` is read, never written.
    let modules = [
        ("inventory.rs", include_str!("inventory.rs")),
        ("sources.rs", include_str!("sources.rs")),
        ("store.rs", include_str!("store.rs")),
        ("thread.rs", include_str!("thread.rs")),
        ("mod.rs", include_str!("mod.rs")),
    ];
    for (file, src) in modules {
        for banned in [
            "telltale_policy",
            "Neighbors",
            "router_leases",
            "mdns_names",
            "peer_names",
            "identify::",
            "devices::Names",
        ] {
            assert!(!src.contains(banned), "{file} mentions {banned}");
        }
    }
}

/// REQ: DSC-008 (review fix 9) — a real backup of a data directory holding `inventory.json` does
/// not archive it. `anomaly.json` is archived in the same backup, as the control.
#[test]
fn dsc_008_inventory_file_not_in_backup() {
    let dir = temp_dir("backup");
    std::fs::write(dir.join(store::FILE_NAME), b"{}").unwrap();
    std::fs::write(dir.join("anomaly.json"), b"[]").unwrap();
    let mut cfg = telltale_config::Config::default();
    cfg.node.data_dir = telltale_config::SafeString::new(dir.to_string_lossy()).unwrap();
    let out = dir.join("out.ttbk");
    crate::backup::create(&[], &cfg, false, &out).unwrap();
    let manifest = crate::backup::show(&out).unwrap();
    assert!(
        manifest
            .entries
            .iter()
            .any(|e| e.path == "data/anomaly.json"),
        "control: a data file is archived"
    );
    assert!(
        manifest
            .entries
            .iter()
            .all(|e| !e.path.contains("inventory")),
        "inventory.json is never archived"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dsc_008_inventory_file_roundtrip_and_mode() {
    let mut inv = Inventory::new(500);
    inv.apply(
        &[obs(Source::Router, Some(A), Some("192.168.1.100"), 600)],
        600,
    );
    let rows = [obs(Source::Import, Some(B), Some("192.168.1.101"), 610)];
    inv.apply_import("scan.xml", &rows, 610).unwrap();
    inv.mute(key_mac(A), FindingKind::NewDevice, None);
    let mut want = inv.clone();
    want.clear_dirty();
    let bytes = store::to_json(&inv).unwrap();
    let back = store::from_json(&bytes).unwrap();
    assert_eq!(back, want, "the dirty flag is not stored");
    assert!(store::from_json(b"{\"version\":99}").is_none());

    let dir = temp_dir("store");
    store::save(&dir, &inv).unwrap();
    let loaded = store::load(&dir, 0);
    assert_eq!(loaded, want);
    assert!(!dir.join("inventory.json.tmp").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(store::path(&dir))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // A missing file is an empty start with a new learning period.
    let empty = store::load(&dir.join("nope"), 42);
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.learning_until(), 42 + LEARNING_SECS);
    let _ = std::fs::remove_dir_all(&dir);
}

/// REQ: DSC-008 (review fix 13) — a file this version cannot read is moved aside, not overwritten.
#[test]
fn dsc_008_unreadable_file_is_quarantined() {
    let dir = temp_dir("quarantine");
    std::fs::write(store::path(&dir), b"{\"version\":99}").unwrap();
    let inv = store::load(&dir, 7);
    assert!(inv.is_empty());
    assert_eq!(inv.learning_until(), 7 + LEARNING_SECS);
    assert!(!store::path(&dir).exists());
    let kept = std::fs::read(dir.join(store::QUARANTINE_NAME)).unwrap();
    assert_eq!(kept, b"{\"version\":99}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// REQ: DSC-008 (review fix 7) — an estimate of one copy of the inventory at the caps. The
/// estimate counts the entry structs and their heap buffers.
#[test]
fn dsc_008_entry_size_at_caps() {
    fn approx(e: &Entry) -> usize {
        let mut n = std::mem::size_of::<Entry>();
        n = n.saturating_add(
            e.addrs
                .capacity()
                .saturating_mul(std::mem::size_of::<Binding>()),
        );
        for nm in &e.names {
            n = n.saturating_add(std::mem::size_of::<NameEntry>());
            n = n.saturating_add(nm.label.capacity());
            n = n.saturating_add(nm.origin.as_ref().map_or(0, String::capacity));
        }
        n = n.saturating_add(e.ports.capacity().saturating_mul(2));
        n = n.saturating_add(e.port.as_ref().map_or(0, String::capacity));
        n
    }
    let mut entries: Vec<Entry> = Vec::new();
    for i in 1..=(cap32(MAX_MAC_ENTRIES) + cap32(MAX_IP_ONLY_ENTRIES)) {
        let mut e = if i <= cap32(MAX_MAC_ENTRIES) {
            Entry::new(key_mac(mac_n(i)), 1)
        } else {
            Entry::new(Key::Ip(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i))), 1)
        };
        for k in 0..cap32(MAX_ADDRS) {
            let a = IpAddr::V4(Ipv4Addr::from(0xc0a8_0000 + i * 4 + k));
            e.addrs.push(Binding {
                ip: a,
                source: Source::Router,
                seen: 1,
                import_bit: None,
            });
        }
        for k in 0..MAX_NAMES {
            e.names.push(NameEntry {
                kind: NameKind::RouterAlias,
                label: format!("device-{i}-{k}"),
                origin: Some("ucg".to_owned()),
            });
        }
        e.ports = (0..u16::try_from(MAX_PORTS).unwrap_or(0)).collect();
        entries.push(e);
    }
    let per_entry: usize = entries.iter().map(approx).sum::<usize>() / entries.len();
    assert!(
        per_entry <= 1_024,
        "a full entry estimates at {per_entry} B; the caps assume about 600 B"
    );
    let inv = Inventory::restore(entries, Vec::new(), Vec::new(), 0);
    assert_eq!(inv.len(), MAX_MAC_ENTRIES + MAX_IP_ONLY_ENTRIES);
    let json = store::to_json(&inv).unwrap();
    assert!(
        json.len() < 8 * 1024 * 1024,
        "the saved file is {} B",
        json.len()
    );
}

#[test]
fn dsc_008_write_cadence() {
    assert!(store::write_due(true, 1_000, 0, false));
    assert!(
        !store::write_due(true, 1_000, 500, false),
        "15 min ordinarily"
    );
    assert!(
        store::write_due(true, 1_000, 500, true),
        "a minute after an import"
    );
    assert!(!store::write_due(false, 5_000, 0, true), "nothing to save");
}

#[test]
fn dsc_008_tick_reads_router_view() {
    let mut view: Leases = HashMap::new();
    view.insert(
        Ipv4Addr::new(192, 168, 1, 120),
        Lease {
            mac: "AA:BB:CC:DD:EE:FF".to_owned(),
            ip: Ipv4Addr::new(192, 168, 1, 120),
            hostname: Some("printer".to_owned()),
            expires: 0,
            router: Some("ucg".to_owned()),
        },
    );
    let providers = thread::Providers {
        routers: Some(Arc::new(ArcSwap::from_pointee(view))),
        ..Default::default()
    };
    let mut inv = Inventory::new(0);
    thread::tick(&mut inv, &providers, 100);
    let m = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
    let e = inv.get(&key_mac(m)).unwrap();
    assert_eq!(e.current().unwrap().source, Source::Router);
    assert_eq!(e.display_name().unwrap().kind, NameKind::RouterAlias);
    assert!(inv.is_dirty());
}

#[test]
fn dsc_008_parse_mac_rejects_malformed() {
    assert_eq!(parse_mac("00-11-22-33-44-55"), Some(A));
    assert!(parse_mac("00:11:22:33:44").is_none());
    assert!(parse_mac("0:11:22:33:44:55").is_none());
    assert!(parse_mac("zz:11:22:33:44:55").is_none());
}

#[test]
fn dsc_008_restore_enforces_caps() {
    let entries: Vec<Entry> = (1..=5_000u32)
        .map(|i| {
            let mut e = Entry::new(key_mac(mac_n(i)), 1);
            e.last_seen = u64::from(i);
            e
        })
        .collect();
    let inv = Inventory::restore(entries, Vec::new(), Vec::new(), 0);
    assert_eq!(inv.len(), MAX_MAC_ENTRIES);
}

/// REQ: DSC-011 — a muted default-community finding is hidden like the others (ADR-909).
#[test]
fn dsc_011_default_community_finding_is_muteable() {
    let mut e = Entry::new(key_mac(A), 1);
    e.default_community = true;
    let mut inv = Inventory::restore(vec![e], Vec::new(), Vec::new(), 0);
    assert_eq!(
        inv.visible_findings(&key_mac(A), 0),
        vec![FindingKind::DefaultCommunity]
    );
    inv.mute(key_mac(A), FindingKind::DefaultCommunity, None);
    assert_eq!(
        inv.visible_findings(&key_mac(A), 0),
        Vec::<FindingKind>::new()
    );
}

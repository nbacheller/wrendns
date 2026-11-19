//! REQ: DSC-902, DSC-903, DSC-906 (T31.2) - the engine against a real database: each reconciliation
//! rule, ambiguity, the level disagreement, ports and aliases, the caps, retention and the
//! property that the same batches in any order give the same links.

use telltale_store::cmdb::{CiRow, RecordRow};

use super::engine::Engine;
use super::engine::test_support::{batch, engine, host};
use super::model::{RecKind, Record};

const T0: i64 = 1_000_000;

fn rec_of(e: &Engine, source: &str, key: &str) -> RecordRow {
    e.db()
        .read(|o| o.record_get(source, key))
        .unwrap()
        .unwrap_or_else(|| panic!("no record {source}/{key}"))
}

fn devices(e: &Engine) -> Vec<CiRow> {
    e.db().read(|o| o.ci_list(Some("device"), None, None, 500)).unwrap()
}

fn children(e: &Engine, device: &str) -> Vec<CiRow> {
    e.db().read(|o| o.ci_children(device)).unwrap()
}

fn proposals(e: &Engine, kind: &str) -> usize {
    e.db()
        .read(|o| o.proposals(Some("open"), None))
        .unwrap()
        .iter()
        .filter(|p| p.kind == kind)
        .count()
}

fn with(mut r: Record, name: &str, value: &str) -> Record {
    r.text(name, value);
    r
}

fn ingest(e: &mut Engine, source: &str, records: Vec<Record>, at: i64) {
    e.ingest(batch(source, records, true, at), at).unwrap();
}

/// REQ: DSC-903 (R2) - records of different sources with one MAC link to one interface CI inside
/// one device CI, and a second MAC is a second interface, not a second record of the first.
#[test]
fn dsc_903_r2_mac_links_sources_to_one_interface() {
    let (_d, mut e) = engine();
    ingest(&mut e, "unifi:home", vec![host("unifi:home", "c1", "AA:BB:CC:00:00:01", T0)], T0);
    ingest(&mut e, "neighbor", vec![host("neighbor", "n1", "aa:bb:cc:00:00:01", T0)], T0);
    ingest(&mut e, "neighbor", vec![host("neighbor", "n2", "aa:bb:cc:00:00:02", T0)], T0 + 1);
    let a = rec_of(&e, "unifi:home", "c1");
    let b = rec_of(&e, "neighbor", "n1");
    assert_eq!(a.ici, b.ici, "one MAC, one interface CI");
    assert_eq!(a.dci, b.dci);
    assert_eq!(a.link, "auto:R2");
    let c = rec_of(&e, "neighbor", "n2");
    assert_ne!(c.ici, a.ici);
    assert_ne!(c.dci, a.dci, "one MAC one device until told otherwise");
    assert_eq!(devices(&e).len(), 2);
}

/// REQ: DSC-903 (R3) - a serial joins two interfaces into one device with two interface CIs.
#[test]
fn dsc_903_r3_serial_joins_interfaces_into_one_device() {
    let (_d, mut e) = engine();
    ingest(
        &mut e,
        "unifi:home",
        vec![
            with(host("unifi:home", "w", "aa:bb:cc:00:00:01", T0), "serial", "SN-LAPTOP-1"),
            with(host("unifi:home", "e", "aa:bb:cc:00:00:02", T0), "serial", "sn-laptop-1"),
        ],
        T0,
    );
    let w = rec_of(&e, "unifi:home", "w");
    let r = rec_of(&e, "unifi:home", "e");
    assert_eq!(w.dci, r.dci, "the serial makes one device");
    assert_ne!(w.ici, r.ici, "and two interfaces");
    assert_eq!(w.link, "auto:R3");
    assert_eq!(devices(&e).len(), 1);
    assert_eq!(children(&e, w.dci.as_deref().unwrap()).len(), 2);
}

/// REQ: DSC-903 (R4) - a Home Assistant device with two MACs links to one device CI with an
/// interface CI per MAC; an SNMP chassis seen under a new MAC links to the same device with a new
/// interface CI, and an interface is never moved to another MAC.
#[test]
fn dsc_903_r4_stable_key_survives_a_mac_change() {
    let (_d, mut e) = engine();
    let ha = |key: &str, mac: &str| {
        with(host("home_assistant:ha", key, mac, T0), "device_key", "ha:ha|dev-tv")
    };
    ingest(
        &mut e,
        "home_assistant:ha",
        vec![ha("tv-wifi", "aa:bb:cc:00:00:11"), ha("tv-eth", "aa:bb:cc:00:00:12")],
        T0,
    );
    let w = rec_of(&e, "home_assistant:ha", "tv-wifi");
    let eth = rec_of(&e, "home_assistant:ha", "tv-eth");
    assert_eq!(w.dci, eth.dci, "a Home Assistant device with two MACs is one device");
    assert_eq!(w.link, "auto:R4");
    let dev = w.dci.clone().unwrap();
    assert_eq!(children(&e, &dev).len(), 2);

    // An SNMP agent's chassis shows up under a new MAC.
    let snmp = |mac: &str| with(host("snmp:sw1", "chassis", mac, T0), "device_key", "snmp:sw1|chassis");
    ingest(&mut e, "snmp:sw1", vec![snmp("aa:bb:cc:00:00:21")], T0 + 10);
    let first = rec_of(&e, "snmp:sw1", "chassis");
    let sw = first.dci.clone().unwrap();
    ingest(&mut e, "snmp:sw1", vec![snmp("aa:bb:cc:00:00:22")], T0 + 20);
    let second = rec_of(&e, "snmp:sw1", "chassis");
    assert_eq!(second.dci.as_deref(), Some(sw.as_str()), "the same device");
    assert_eq!(second.mac.as_deref(), Some("aa:bb:cc:00:00:22"));
    let kids = children(&e, &sw);
    assert_eq!(kids.len(), 2, "a new interface under it");
    // The first interface still has its own MAC (it was not moved to the new one).
    let macs: Vec<String> = kids
        .iter()
        .filter_map(|c| e.db().read(|o| o.mac_of(&c.id)).unwrap())
        .collect();
    assert!(macs.contains(&"aa:bb:cc:00:00:21".to_owned()) && macs.contains(&"aa:bb:cc:00:00:22".to_owned()));
}

/// REQ: DSC-903 (level disagreement) - a record whose MAC and serial point at different devices
/// links nothing at the device level and raises a merge proposal that nothing applies.
#[test]
fn dsc_903_level_disagreement_proposes_merge() {
    let (_d, mut e) = engine();
    ingest(
        &mut e,
        "unifi:home",
        vec![
            with(host("unifi:home", "a", "aa:bb:cc:00:00:01", T0), "serial", "SN-AAAA-1"),
            with(host("unifi:home", "b", "aa:bb:cc:00:00:02", T0 + 1), "serial", "SN-BBBB-2"),
        ],
        T0,
    );
    ingest(
        &mut e,
        "snmp:sw",
        vec![with(host("snmp:sw", "z", "aa:bb:cc:00:00:01", T0 + 5), "serial", "SN-BBBB-2")],
        T0 + 5,
    );
    let a = rec_of(&e, "unifi:home", "a");
    let b = rec_of(&e, "unifi:home", "b");
    let z = rec_of(&e, "snmp:sw", "z");
    assert_ne!(a.dci, b.dci, "two devices stay two");
    assert_eq!(z.dci, a.dci, "the record stays on its interface's device");
    assert_eq!(proposals(&e, "level_disagreement"), 1, "and a proposal is raised");
    assert_eq!(devices(&e).len(), 2);
}

/// REQ: DSC-903 (R5) - a host name and a network shared with exactly one other device only
/// proposes; two phones called `iphone` never do.
#[test]
fn dsc_903_r5_hostname_and_network_only_proposes() {
    let (_d, mut e) = engine();
    let h = |src: &str, key: &str, mac: &str, host_: &str| {
        with(with(host(src, key, mac, T0), "hostname", host_), "network", "Lan")
    };
    ingest(
        &mut e,
        "unifi:home",
        vec![
            h("unifi:home", "1", "aa:bb:cc:00:00:01", "kitchen-hub"),
            h("unifi:home", "2", "aa:bb:cc:00:00:02", "iphone"),
            h("unifi:home", "3", "aa:bb:cc:00:00:03", "iphone"),
        ],
        T0,
    );
    ingest(
        &mut e,
        "mdns",
        vec![h("mdns", "k", "aa:bb:cc:00:00:09", "Kitchen-Hub.local")],
        T0 + 1,
    );
    assert_eq!(devices(&e).len(), 4, "nothing was merged");
    assert_eq!(proposals(&e, "host_network"), 1, "one proposal, for the host name");
}

/// REQ: DSC-903 - a keyless record whose address two devices hold stays unlinked with a proposal; one
/// that one device holds attaches to it; one nobody holds becomes an unconfirmed CI of its own.
#[test]
fn dsc_903_keyless_records_attach_or_stay_unlinked() {
    let (_d, mut e) = engine();
    let with_ip = |mut r: Record, ip: &str| {
        r.list("addresses", vec![ip.to_owned()]);
        r
    };
    ingest(
        &mut e,
        "neighbor",
        vec![
            with_ip(host("neighbor", "n1", "aa:bb:cc:00:00:01", T0), "192.168.1.10"),
            with_ip(host("neighbor", "n2", "aa:bb:cc:00:00:02", T0), "192.168.1.11"),
            with_ip(host("neighbor", "n3", "aa:bb:cc:00:00:03", T0), "192.168.1.12"),
        ],
        T0,
    );
    ingest(
        &mut e,
        "unifi:home",
        vec![with_ip(host("unifi:home", "u3", "aa:bb:cc:00:00:04", T0), "192.168.1.12")],
        T0,
    );
    let keyless = |src: &str, key: &str, ip: &str| {
        with_ip(Record::new(src, key, RecKind::Device, T0 + 5), ip)
    };
    ingest(
        &mut e,
        "queries",
        vec![
            keyless("queries", "192.168.1.10", "192.168.1.10"),
            keyless("queries", "192.168.1.12", "192.168.1.12"),
            keyless("queries", "192.168.1.99", "192.168.1.99"),
        ],
        T0 + 5,
    );
    let one = rec_of(&e, "queries", "192.168.1.10");
    assert_eq!(one.dci, rec_of(&e, "neighbor", "n1").dci, "attached through its address");
    assert_eq!(one.link, "auto:addr");
    let two = rec_of(&e, "queries", "192.168.1.12");
    assert_eq!(two.dci, None, "two devices hold it: unlinked, never a guess");
    assert_eq!(proposals(&e, "ambiguous_record"), 1);
    let own = rec_of(&e, "queries", "192.168.1.99");
    let own_ci = e.db().read(|o| o.ci_get(own.dci.as_deref().unwrap())).unwrap().unwrap();
    assert_eq!(own_ci.flags & telltale_store::cmdb::FLAG_UNCONFIRMED, 1, "unconfirmed");
}

/// REQ: DSC-903 - a port seen by SNMP `ifName` and by UniFi `port_idx` is one port CI once aliased
/// (the device matched by serial); an unaliased one is `unmapped_port`, never a conflict.
#[test]
fn dsc_903_ports_alias_across_sources_or_stay_unmapped() {
    let (_d, mut e) = engine();
    // The switch: a UniFi device record with a serial and a key, an SNMP agent with the same serial.
    let sw_unifi = with(
        with(host("unifi:home", "sw", "aa:bb:cc:00:01:00", T0), "serial", "SN-SWITCH-1"),
        "device_key",
        "unifi:home|sw",
    );
    let sw_snmp = with(
        with(host("snmp:core", "device", "aa:bb:cc:00:01:00", T0), "serial", "SN-SWITCH-1"),
        "device_key",
        "snmp:core|device",
    );
    ingest(&mut e, "unifi:home", vec![sw_unifi], T0);
    ingest(&mut e, "snmp:core", vec![sw_snmp], T0);
    let port = |src: &str, key: &str, owner: &str, id: &str| {
        let mut r = Record::new(src, key, RecKind::Port, T0 + 1);
        r.text("owner", owner).text("port_id", id);
        r
    };
    ingest(
        &mut e,
        "snmp:core",
        vec![port("snmp:core", "p5", "snmp:core|device", "Gi1/0/5"), port("snmp:core", "p6", "snmp:core|device", "Gi1/0/6")],
        T0 + 1,
    );
    ingest(
        &mut e,
        "unifi:home",
        vec![port("unifi:home", "port5", "unifi:home|sw", "port5"), port("unifi:home", "port9", "unifi:home|sw", "port9")],
        T0 + 2,
    );
    let snmp5 = rec_of(&e, "snmp:core", "p5");
    let unifi5 = rec_of(&e, "unifi:home", "port5");
    assert_eq!(snmp5.ici, unifi5.ici, "one port CI once aliased");
    let dev = snmp5.dci.clone().unwrap();
    assert_eq!(rec_of(&e, "unifi:home", "port5").dci.as_deref(), Some(dev.as_str()));
    let unifi9 = rec_of(&e, "unifi:home", "port9");
    let p9 = e.db().read(|o| o.ci_get(unifi9.ici.as_deref().unwrap())).unwrap().unwrap();
    assert_eq!(p9.flags & telltale_store::cmdb::FLAG_UNMAPPED_PORT, 2, "unaliased: unmapped_port");
    let snmp6 = rec_of(&e, "snmp:core", "p6");
    let p6 = e.db().read(|o| o.ci_get(snmp6.ici.as_deref().unwrap())).unwrap().unwrap();
    assert_eq!(p6.flags & telltale_store::cmdb::FLAG_UNMAPPED_PORT, 2);
    assert!(proposals(&e, "level_disagreement") == 0, "never a conflict");
}

/// REQ: DSC-902 - a network, a node, a service and an upstream are CIs by their natural key, and a
/// second source with the same key adds a record to the same CI.
#[test]
fn dsc_902_natural_key_cis() {
    let (_d, mut e) = engine();
    let net = |src: &str, key: &str, name: &str| {
        let mut r = Record::new(src, key, RecKind::Network, T0);
        r.text("key", "network:192.168.1.0/24|0").text("name", name);
        r
    };
    ingest(&mut e, "config", vec![net("config", "subnet-1", "Home")], T0);
    ingest(&mut e, "unifi:home", vec![net("unifi:home", "lan", "Default LAN")], T0);
    let a = rec_of(&e, "config", "subnet-1");
    let b = rec_of(&e, "unifi:home", "lan");
    assert_eq!(a.dci, b.dci);
    let ci = e.db().read(|o| o.ci_get(a.dci.as_deref().unwrap())).unwrap().unwrap();
    assert_eq!(ci.ty, "network");
    assert_eq!(ci.name.as_deref(), Some("Home"), "the configured name ranks first");
}

/// REQ: DSC-902 (ADR-924) - a record a complete batch no longer lists goes absent after two missed
/// batches, comes back present, and an unchanged record writes nothing.
#[test]
fn dsc_902_absent_after_two_missed_complete_batches() {
    let (_d, mut e) = engine();
    let r = host("neighbor", "n1", "aa:bb:cc:00:00:01", T0);
    ingest(&mut e, "neighbor", vec![r.clone(), host("neighbor", "n2", "aa:bb:cc:00:00:02", T0)], T0);
    let again = e.ingest(batch("neighbor", vec![r.clone()], true, T0 + 60), T0 + 60).unwrap();
    assert_eq!(again.written, 0, "unchanged: no row written");
    assert_eq!(rec_of(&e, "neighbor", "n2").state, "present", "one miss is not absent");
    ingest(&mut e, "neighbor", vec![r.clone()], T0 + 120);
    assert_eq!(rec_of(&e, "neighbor", "n2").state, "absent");
    ingest(&mut e, "neighbor", vec![r, host("neighbor", "n2", "aa:bb:cc:00:00:02", T0 + 180)], T0 + 180);
    assert_eq!(rec_of(&e, "neighbor", "n2").state, "present");
}

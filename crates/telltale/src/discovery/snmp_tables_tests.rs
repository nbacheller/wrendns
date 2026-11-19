//! Tests of what a poll's rows mean (DSC-004, ADR-908, ADR-910): the FDB ID to VLAN ID map, the
//! uplink rule, LLDP neighbours, the ARP subnet filter, and the merge into the inventory.

#![allow(
    clippy::assert_is_empty,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::net::IpAddr;

use telltale_config::SnmpTable;

use super::super::inventory::{Inventory, Key};
use super::super::snmp_fixtures::{Clock, FakeMib, GATEWAY, SWITCH};
use super::super::snmp_job::{AuthSpec, Secret, SnmpRequest};
use super::super::snmp_poll;
use super::*;

const NOW: u64 = 1_800_000_000;

fn rows_of(text: &str, tables: &[SnmpTable]) -> Vec<Row> {
    let clock = Clock::new();
    let mut mib = FakeMib::from_walk(text, &clock);
    let req = SnmpRequest {
        agent: "a".into(),
        address: Ipv4Addr::new(10, 0, 0, 1),
        port: 161,
        auth: AuthSpec::V2c {
            community: Secret::new(b"c".to_vec()),
        },
        tables: tables.to_vec(),
        max_repetitions: 10,
        known: None,
    };
    snmp_poll::run(&mut mib, &mut clock.clone(), &req, false).rows
}

const ALL: [SnmpTable; 4] = [
    SnmpTable::Arp,
    SnmpTable::Ifmib,
    SnmpTable::Bridge,
    SnmpTable::Lldp,
];

fn subnets() -> Vec<Ipv4Subnet> {
    ["192.0.2.0/24", "192.168.20.0/24"]
        .iter()
        .map(|s| Ipv4Subnet::parse(s).unwrap())
        .collect()
}

fn cx<'a>(agent: &'a str, subnets: &'a [Ipv4Subnet], infra: &'a InfraSet) -> Context<'a> {
    Context {
        agent,
        subnets,
        infra,
        now: NOW,
    }
}

fn mac_of(m: &str) -> [u8; 6] {
    parse_mac(m).unwrap()
}

fn find<'a>(o: &'a Outcome, mac: &str) -> Vec<&'a Observation> {
    o.observations
        .iter()
        .filter(|x| x.mac == Some(mac_of(mac)))
        .collect()
}

/// REQ: DSC-004 (`dsc_004_bridge_ports_per_vlan`) — a forwarding entry's FDB ID is mapped to a VLAN
/// ID through the VLAN table (here FDB 2 is VLAN 10 and FDB 3 is VLAN 20: an FDB ID is not a VLAN
/// ID), and its bridge port is mapped to an interface and its name. Without the VLAN table the VLAN
/// is left unknown, never guessed from the FDB ID.
#[test]
fn dsc_004_bridge_ports_per_vlan() {
    let rows = rows_of(SWITCH, &ALL);
    let infra = InfraSet::default();
    let sn = subnets();
    let o = interpret(&rows, &cx("sw1", &sn, &infra));
    let a = find(&o, "3c:22:fb:01:00:01");
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].vlan, Some(10), "FDB 2 is VLAN 10");
    assert_eq!(
        a[0].port.as_deref(),
        Some("sw1 3"),
        "port 3, named by ifName"
    );
    let b = find(&o, "3c:22:fb:01:00:3c");
    assert_eq!(b[0].vlan, Some(20), "FDB 3 is VLAN 20");
    assert_eq!(b[0].port.as_deref(), Some("sw1 9"));
    assert_eq!(
        o.counts.fdb_located,
        4 + 2,
        "four access MACs and the two on port 23"
    );

    // Without dot1qVlanCurrentTable the VLAN is unknown.
    let no_vlans: Vec<Row> = rows
        .iter()
        .filter(|r| !matches!(r, Row::VlanFdb { .. }))
        .cloned()
        .collect();
    let o = interpret(&no_vlans, &cx("sw1", &sn, &infra));
    assert_eq!(find(&o, "3c:22:fb:01:00:01")[0].vlan, None);
    // Without dot1dBasePortIfIndex the port is named by its number.
    let no_ports: Vec<Row> = rows
        .iter()
        .filter(|r| !matches!(r, Row::PortIf { .. }))
        .cloned()
        .collect();
    let o = interpret(&no_ports, &cx("sw1", &sn, &infra));
    assert_eq!(
        find(&o, "3c:22:fb:01:00:01")[0].port.as_deref(),
        Some("sw1 port 3")
    );
}

/// REQ: DSC-004 (`dsc_004_uplink_ports_give_no_location`) — a port with more than 8 learned MACs, or
/// whose LLDP neighbour is a listed agent or a UniFi device, gives its MACs no location.
#[test]
fn dsc_004_uplink_ports_give_no_location() {
    let rows = rows_of(SWITCH, &ALL);
    let sn = subnets();
    // Port 24 has 12 learned MACs: an uplink on size alone.
    let none = InfraSet::default();
    let o = interpret(&rows, &cx("sw1", &sn, &none));
    for k in 11..=22 {
        let mac = format!("3c:22:fb:01:00:{k:02x}");
        assert!(find(&o, &mac).is_empty(), "{mac} was learned on the uplink");
    }
    assert_eq!(o.counts.fdb_uplink, 12);
    assert_eq!(o.counts.uplink_ports, 1);
    // Port 23 has two MACs and a neighbour nobody listed: a normal port.
    assert_eq!(find(&o, "3c:22:fb:01:00:1e").len(), 1);

    // The neighbour on port 23 is the gateway, found by its chassis MAC (a listed agent's own
    // interface MAC) ...
    let mut by_mac = InfraSet::default();
    by_mac.macs.insert(Mac(mac_of("70:a7:41:aa:00:01")));
    let o = interpret(&rows, &cx("sw1", &sn, &by_mac));
    assert!(
        find(&o, "3c:22:fb:01:00:1e").is_empty(),
        "port 23 is an uplink now"
    );
    assert!(find(&o, "3c:22:fb:01:00:1f").is_empty());
    assert_eq!(o.counts.uplink_ports, 2);
    // ... or by name ...
    let mut by_name = InfraSet::default();
    by_name.names.insert("unifi-gateway".to_owned());
    assert!(
        find(
            &interpret(&rows, &cx("sw1", &sn, &by_name)),
            "3c:22:fb:01:00:1e"
        )
        .is_empty()
    );
    // ... or as a UniFi device.
    let mut unifi = InfraSet::default();
    unifi.unifi_macs.insert(Mac(mac_of("70:a7:41:aa:00:01")));
    assert!(
        find(
            &interpret(&rows, &cx("sw1", &sn, &unifi)),
            "3c:22:fb:01:00:1e"
        )
        .is_empty()
    );
    // The access ports keep their location in every case.
    assert_eq!(find(&o, "3c:22:fb:01:00:01").len(), 1);
}

/// REQ: DSC-004 — exactly 8 learned MACs on a port is not an uplink; 9 is.
#[test]
fn dsc_004_uplink_limit_is_more_than_eight() {
    let fdb = |n: u32, port: u32| -> Vec<Row> {
        (0..n)
            .map(|i| Row::Fdb {
                mac: Mac([0x3c, 0x22, 0xfb, 0, 0, u8::try_from(i + 1).unwrap()]),
                port,
                fdb: None,
                status: Some(3),
            })
            .collect()
    };
    let infra = InfraSet::default();
    let o = interpret(&fdb(8, 1), &cx("sw", &[], &infra));
    assert_eq!((o.counts.fdb_located, o.counts.uplink_ports), (8, 0));
    let o = interpret(&fdb(9, 1), &cx("sw", &[], &infra));
    assert_eq!((o.counts.fdb_located, o.counts.uplink_ports), (0, 1));
}

/// REQ: DSC-004 — only learned entries give a location, and never the agent's own MAC.
#[test]
fn dsc_004_fdb_status_and_own_mac() {
    let rows = rows_of(SWITCH, &ALL);
    let infra = InfraSet::default();
    let o = interpret(&rows, &cx("sw1", &[], &infra));
    // The management entry (status 5) and the switch's own MAC (status 4) give nothing.
    assert!(find(&o, "3c:22:fb:01:00:63").is_empty());
    assert!(find(&o, "94:60:d5:bb:00:01").is_empty());
    assert_eq!(o.counts.fdb_skipped, 2);
}

/// REQ: DSC-004 (`dsc_004_lldp_neighbors`) — an LLDP neighbour whose chassis ID is a MAC becomes a
/// device with its system name and the port it hangs off; one whose chassis ID is not a MAC is
/// counted and left out; a port keeps at most four.
#[test]
fn dsc_004_lldp_neighbors() {
    let rows = rows_of(SWITCH, &ALL);
    let infra = InfraSet::default();
    let o = interpret(&rows, &cx("sw1", &[], &infra));
    let ap = find(&o, "b4:fb:e4:10:20:30");
    assert_eq!(ap.len(), 1);
    assert_eq!(ap[0].name.as_ref().map(|n| n.1.as_str()), Some("ap-lobby"));
    assert_eq!(ap[0].lldp, ["sw1 Port 5"]);
    assert_eq!(ap[0].source, Source::Snmp);
    assert!(ap[0].ip.is_none(), "LLDP carries no address here");
    let gw = find(&o, "70:a7:41:aa:00:01");
    assert_eq!(gw[0].lldp, ["sw1 Port 23"]);
    assert_eq!(o.counts.lldp_merged, 2);
    assert_eq!(o.counts.lldp_no_mac, 1, "printer-x has a local chassis ID");

    // At most four neighbours per port.
    let many: Vec<Row> = (1..=6u8)
        .map(|i| Row::Lldp {
            port: 7,
            chassis: Some(Mac([0x02 + 8, 0, 0, 0, 0, i])),
            port_id: "x".into(),
            port_desc: String::new(),
            sys_name: format!("n{i}"),
        })
        .collect();
    let o = interpret(&many, &cx("sw", &[], &infra));
    assert_eq!(o.counts.lldp_merged, 4);
}

/// REQ: DSC-004, ADR-910 — ARP entries become class 3 bindings inside the listed subnets only; the
/// rest are counted, not merged, and an address that names no host is never a binding.
#[test]
fn dsc_004_arp_is_filtered_to_the_listed_subnets() {
    let rows = rows_of(GATEWAY, &ALL);
    let infra = InfraSet::default();
    let sn = vec![Ipv4Subnet::parse("192.0.2.0/24").unwrap()];
    let o = interpret(&rows, &cx("gateway", &sn, &infra));
    // 60 hosts in 192.0.2.0/24; the 38 in 192.168.20.0/24 and the 10 incomplete (192.168.30.x,
    // skipped at parse) are not merged.
    assert_eq!(o.counts.arp_merged, 60);
    assert_eq!(o.counts.arp_outside_subnets, 38);
    let arp: Vec<&Observation> = o
        .observations
        .iter()
        .filter(|x| x.source == Source::SnmpArp && x.name.is_none())
        .collect();
    assert_eq!(arp.len(), 60);
    assert!(
        arp.iter().all(|x| x.source.is_current()),
        "class 3 is a current binding"
    );
    // With no subnet listed, nothing is merged (the neighbour table works the same way).
    let o = interpret(&rows, &cx("gateway", &[], &infra));
    assert_eq!(o.counts.arp_merged, 0);
    // Addresses that name no host and group MACs are refused.
    let odd = vec![
        Row::Arp {
            ip: Ipv4Addr::new(192, 0, 2, 255),
            mac: Mac([2, 0, 0, 0, 0, 1]),
            ifi: 1,
        },
        Row::Arp {
            ip: Ipv4Addr::new(192, 0, 2, 5),
            mac: Mac([0xff; 6]),
            ifi: 1,
        },
        Row::Arp {
            ip: Ipv4Addr::new(192, 0, 2, 6),
            mac: Mac([0; 6]),
            ifi: 1,
        },
    ];
    let o = interpret(&odd, &cx("g", &sn, &infra));
    assert_eq!(
        o.counts.arp_merged, 1,
        "only the .255 host address passes the host check"
    );
}

/// REQ: DSC-004 — the agent's own addresses come with its interface's MAC and its name; loopback
/// and addresses outside the listed subnets are left out. Its interface MACs are reported so
/// other agents' uplink rule can use them.
#[test]
fn dsc_004_the_agents_own_addresses() {
    let rows = rows_of(GATEWAY, &ALL);
    let infra = InfraSet::default();
    let o = interpret(&rows, &cx("gateway", &subnets(), &infra));
    let own: Vec<&Observation> = o
        .observations
        .iter()
        .filter(|x| x.name.as_ref().is_some_and(|n| n.1 == "gateway"))
        .collect();
    // 192.0.2.1 (br0) and 192.168.20.1 (br20); 192.168.30.1 is outside the listed subnets, and
    // 127.0.0.1 and 10.99.0.2 never are.
    assert_eq!(own.len(), 2, "{own:?}");
    assert!(
        own.iter()
            .all(|x| x.mac == Some(mac_of("70:a7:41:aa:00:01")))
    );
    assert_eq!(o.counts.own_merged, 2);
    assert!(o.own_macs.contains(&Mac(mac_of("70:a7:41:aa:00:01"))));
    assert!(o.own_macs.contains(&Mac(mac_of("70:a7:41:aa:00:02"))));
}

/// REQ: DSC-004, DSC-008 — a gateway's ARP and a switch's forwarding table merge into one device:
/// a class 3 binding for the address, and the VLAN, port and LLDP place from the switch.
#[test]
fn dsc_004_gateway_and_switch_merge_into_one_device() {
    let infra = InfraSet::default();
    let sn = subnets();
    let gw = interpret(&rows_of(GATEWAY, &ALL), &cx("gateway", &sn, &infra));
    let sw = interpret(&rows_of(SWITCH, &ALL), &cx("sw1", &sn, &infra));
    let mut inv = Inventory::new(NOW - 10 * 86_400);
    inv.apply(&gw.observations, NOW);
    inv.apply(&sw.observations, NOW);
    let e = inv.get(&Key::Mac(mac_of("3c:22:fb:01:00:01"))).unwrap();
    let cur = e.current().unwrap();
    assert_eq!(cur.ip, "192.0.2.10".parse::<IpAddr>().unwrap());
    assert_eq!(cur.source, Source::SnmpArp);
    assert!(e.snmp_eligible());
    assert_eq!(e.vlan, Some(10));
    assert_eq!(e.port.as_deref(), Some("sw1 3"));
    assert!(e.sources & Source::SnmpArp.bit() != 0);
    assert!(
        e.sources & Source::Snmp.bit() != 0,
        "a location comes from SNMP"
    );
    // The AP only the switch's LLDP knows: an entry with a name and where it hangs, no address.
    let ap = inv.get(&Key::Mac(mac_of("b4:fb:e4:10:20:30"))).unwrap();
    assert_eq!(ap.names[0].label, "ap-lobby");
    assert_eq!(ap.lldp, ["sw1 Port 5"]);
    assert!(ap.addrs.is_empty());
    // A second sighting from the same agent replaces its earlier place (the neighbour moved).
    let moved = Observation {
        lldp: vec!["sw1 Port 7".to_owned()],
        ..Observation::new(Source::Snmp, NOW + 60)
    };
    let moved = Observation {
        mac: Some(mac_of("b4:fb:e4:10:20:30")),
        ..moved
    };
    inv.apply(&[moved], NOW + 60);
    let ap = inv.get(&Key::Mac(mac_of("b4:fb:e4:10:20:30"))).unwrap();
    assert_eq!(ap.lldp, ["sw1 Port 7"]);
}

/// REQ: DSC-015, ADR-908 — device text is cut and cleaned however it arrives (the SNMP rows carry
/// device-supplied names): a name with control characters and 300 bytes is bounded in the entry.
#[test]
fn dsc_015_snmp_text_is_bounded_in_the_inventory() {
    let mut o = Observation::new(Source::Snmp, NOW);
    o.mac = Some(mac_of("02:00:00:00:00:09"));
    o.name = Some((NameKind::Snmp, format!("sw\u{1b}[2J{}", "x".repeat(300))));
    o.port = Some(format!("p\n{}", "y".repeat(300)));
    o.lldp = vec![format!("a\u{7}{}", "z".repeat(300))];
    let mut inv = Inventory::new(NOW);
    inv.apply(&[o], NOW);
    let e = inv.get(&Key::Mac(mac_of("02:00:00:00:00:09"))).unwrap();
    for t in [
        e.names[0].label.as_str(),
        e.port.as_deref().unwrap(),
        e.lldp[0].as_str(),
    ] {
        assert!(t.len() <= 64 && !t.chars().any(char::is_control), "{t:?}");
    }
}

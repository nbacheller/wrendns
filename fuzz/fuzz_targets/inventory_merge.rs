//! REQ: DSC-008, DSC-010, NFR-004 — the inventory merge must never panic, and its caps and
//! invariants must hold for any sequence of claims, imports, removals, expiries and sweeps.
//!
//! The merge code is included by path, so the fuzzer runs the same source the server builds.
//! Each 12-byte chunk of the input is one claim: a MAC (6 bytes), an address (4 bytes), a flag
//! byte, and a time step. The flag byte picks the source and, optionally, an import, a removal,
//! a source expiry or a sweep.
#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/telltale/src/discovery/inventory.rs"]
#[allow(dead_code)]
mod inventory;

use inventory::{
    Inventory, MAX_ADDRS, MAX_IMPORT_ROWS, MAX_IP_ONLY_ENTRIES, MAX_MAC_ENTRIES, MAX_NAMES,
    NameKind, Observation, Source,
};

fn source(b: u8) -> Source {
    match b % 9 {
        0 => Source::Router,
        1 => Source::HomeAssistant,
        2 => Source::Neighbor,
        3 => Source::SnmpArp,
        4 => Source::Mdns,
        5 => Source::Snmp,
        6 => Source::Import,
        7 => Source::History,
        _ => Source::Config,
    }
}

fn claim(chunk: &[u8], now: u64) -> Observation {
    let byte = |i: usize| chunk.get(i).copied().unwrap_or(0);
    let mac = [byte(0), byte(1), byte(2), byte(3), byte(4), byte(5)];
    let addr = Ipv4Addr::new(byte(6), byte(7), byte(8), byte(9));
    let flags = byte(10);
    let mut o = Observation::new(source(flags), now);
    if flags & 0x01 != 0 {
        o.mac = Some(mac);
    }
    if flags & 0x02 != 0 {
        o.ip = Some(IpAddr::V4(addr));
    }
    if flags & 0x04 != 0 {
        o.name = Some((NameKind::RouterAlias, format!("dev-{}\u{7}", byte(0))));
    }
    o
}

fuzz_target!(|data: &[u8]| {
    let mut inv = Inventory::new(0);
    let mut now = 0u64;
    for chunk in data.chunks(12) {
        let flags = chunk.get(10).copied().unwrap_or(0);
        let step = u64::from(chunk.get(11).copied().unwrap_or(0));
        now = now.saturating_add(step);
        let o = claim(chunk, now);
        if flags & 0x10 != 0 {
            let rows = [o.clone(), claim(chunk, now)];
            let _ = inv.apply_import("fuzz", &rows, now);
        } else {
            inv.apply(&[o], now);
        }
        if flags & 0x20 != 0 {
            inv.remove_import(flags >> 6);
        }
        if flags & 0x40 != 0 {
            inv.expire_source(source(flags), now, 120);
        }
        if flags & 0x80 != 0 {
            inv.sweep(now, 3_600, 7_200);
        }
        assert!(inv.import_rows() <= MAX_IMPORT_ROWS);
    }
    let ip_only = inv.entries().filter(|e| e.mac().is_none()).count();
    let macs = inv.len() - ip_only;
    assert!(macs <= MAX_MAC_ENTRIES);
    assert!(ip_only <= MAX_IP_ONLY_ENTRIES);
    for e in inv.entries() {
        assert!(e.addrs.len() <= MAX_ADDRS);
        assert!(e.names.len() <= MAX_NAMES);
    }
});

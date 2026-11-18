//! Tests for the extra UniFi and Home Assistant reads (DSC-009, T25.10, ADR-912). Requirement IDs
//! are in the test names (`dsc_009_...`). The console is an in-process fake that speaks HTTP on
//! 127.0.0.1; nothing here reaches a real device.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::unreachable
)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use serde_json::{Value, json};
use telltale_api::model::DiscoveryRead;

use super::*;
use crate::discovery::inventory::{Inventory, Key, NameKind, Source};
use crate::discovery::thread;
use crate::routers::{RawClients, SharedHa, SharedUnifi, UnifiAuth, UnifiSession};

const NOW: u64 = 10_000_000;
const A: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const X: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x09];

fn router(url: &str, kind: &str) -> RouterConfig {
    serde_json::from_value(json!({ "name": "udm", "type": kind, "url": url })).unwrap()
}

fn entry(inv: &Inventory, mac: [u8; 6]) -> &crate::discovery::inventory::Entry {
    inv.get(&Key::Mac(mac)).unwrap()
}

// -- parsing ---------------------------------------------------------------------------------

/// REQ: DSC-009 (`dsc_009_alluser_history_never_current`) — `stat/alluser` rows are class 5: they
/// never become a current address, never displace one, never make an address SNMP-eligible, and
/// raise no `new_device`. A row outside the window is dropped, and history ages out with its names.
#[test]
fn dsc_009_alluser_history_never_current() {
    let mut inv = Inventory::new(0);
    let mut live = Observation::new(Source::Router, NOW);
    live.mac = Some(A);
    live.ip = Some("192.168.1.10".parse().unwrap());
    inv.apply(&[live], NOW);
    let answer = json!({ "data": [
        { "mac": "02:00:00:00:00:01", "last_ip": "192.168.1.99", "name": "Old name", "last_seen": NOW - 3_600, "first_seen": 5_000 },
        // The address the live device holds: history takes nothing from it.
        { "mac": "02:00:00:00:00:02", "last_ip": "192.168.1.10", "hostname": "ghost", "last_seen": NOW - 100 },
        // Outside a 720 hour window.
        { "mac": "02:00:00:00:00:03", "last_ip": "192.168.1.77", "name": "ancient", "last_seen": NOW - 721 * 3_600 },
        { "mac": "not-a-mac", "last_ip": "192.168.1.78" },
    ]});
    let p = all_users(&answer, "udm", NOW, 720);
    assert_eq!(p.rows, 2, "the window and the bad MAC drop two rows");
    assert!(p.observations.iter().all(|o| o.source == Source::History));
    inv.apply(&p.observations, NOW);

    let a = entry(&inv, A);
    assert_eq!(
        a.current().unwrap().source,
        Source::Router,
        "the live binding stays first"
    );
    assert_eq!(
        a.current().unwrap().ip,
        "192.168.1.10".parse::<IpAddr>().unwrap()
    );
    assert!(
        a.addrs
            .iter()
            .any(|b| b.source == Source::History && b.ip.to_string() == "192.168.1.99")
    );
    assert!(!a.conflict, "history raises no conflict");
    assert!(
        !inv.snmp_eligible_address("192.168.1.99".parse().unwrap()),
        "never an SNMP destination"
    );
    assert_eq!(a.first_seen, 5_000, "UniFi's first_seen is kept");

    let b = entry(&inv, B);
    assert_eq!(b.current().unwrap().source, Source::History);
    assert!(!b.snmp_eligible(), "history alone is not current");
    assert!(
        !b.new_device,
        "a client UniFi remembers is not a new device"
    );
    assert!(
        inv.get(&Key::Mac([2, 0, 0, 0, 0, 3])).is_none(),
        "outside the window: not in"
    );
    assert!(
        inv.snmp_eligible_address("192.168.1.10".parse().unwrap()),
        "the live device still is"
    );
    assert_eq!(b.display_name().unwrap().kind, NameKind::History);

    // Aging: past the window the history, and its names, are gone; the live binding is not.
    inv.expire_source(Source::History, NOW + 721 * 3_600, 720 * 3_600);
    let b = entry(&inv, B);
    assert!(
        b.addrs.is_empty() && b.names.is_empty(),
        "history and its names age out together"
    );
    // With `all_users` off the thread expires history at once.
    let mut again = Inventory::new(0);
    again.apply(&p.observations, NOW);
    again.expire_source(Source::History, NOW + 1, 0);
    assert!(entry(&again, B).addrs.is_empty());
}

/// REQ: DSC-009 (`dsc_009_device_mac_table_locations`) — `stat/device`: the devices as infrastructure
/// with their LLDP neighbours, and the places clients plug in. An uplink port, a port with more than
/// 8 MACs and static entries give no place; a MAC on two ports takes the smaller table.
#[test]
fn dsc_009_device_mac_table_locations() {
    let big: Vec<Value> = (0..9)
        .map(|i| json!({ "mac": format!("02:00:00:00:01:{i:02x}"), "vlan": 1 }))
        .collect();
    let answer = json!({ "data": [
        {
            "mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.2", "name": "USW-Pro", "type": "usw",
            "uplink": { "port_idx": 24 },
            "lldp_table": [ { "chassis_id": "aa:bb:cc:00:00:09", "chassis_name": "USG", "port_id": "eth3", "local_port_idx": 24 } ],
            "port_table": [
                { "port_idx": 3, "mac_table": [
                    { "mac": "02:00:00:00:00:01", "vlan": 20, "age": 30 },
                    { "mac": "02:00:00:00:00:77", "vlan": 20, "static": true } ] },
                { "port_idx": 5, "is_uplink": true, "mac_table": [ { "mac": "02:00:00:00:00:55" } ] },
                { "port_idx": 7, "mac_table": big },
                { "port_idx": 8, "mac_table": [ { "mac": "02:00:00:00:00:09", "vlan": 30 } ] },
                { "port_idx": 24, "mac_table": [ { "mac": "02:00:00:00:00:66" } ] },
                { "port_idx": 9, "mac_table": [
                    { "mac": "02:00:00:00:00:09", "vlan": 30 }, { "mac": "02:00:00:00:00:0a", "vlan": 30 } ] },
            ],
        },
        { "mac": "aa:bb:cc:00:00:02", "ip": "192.168.1.3", "name": "AP-Lounge", "type": "uap" },
    ]});
    let p = devices(&answer, "udm", NOW);
    assert_eq!(
        p.device_names.get("aa:bb:cc:00:00:02").map(String::as_str),
        Some("AP-Lounge")
    );
    let mut inv = Inventory::new(0);
    inv.apply(&p.observations, NOW);
    // The switch: infrastructure, at its address, with its neighbour.
    let usw = entry(&inv, [0xaa, 0xbb, 0xcc, 0, 0, 1]);
    assert_eq!(usw.current().unwrap().source, Source::Router);
    assert_eq!(usw.display_name().unwrap().label, "USW-Pro");
    assert_eq!(usw.lldp, vec!["USG eth3 on port 24".to_owned()]);
    // Where clients plug in.
    let a = entry(&inv, A);
    assert_eq!(a.port.as_deref(), Some("USW-Pro port 3"));
    assert_eq!(a.vlan, Some(20));
    assert!(a.addrs.is_empty(), "a MAC table row carries no address");
    let x = entry(&inv, X);
    assert_eq!(
        x.port.as_deref(),
        Some("USW-Pro port 8"),
        "the smaller table wins"
    );
    assert_eq!(x.vlan, Some(30));
    for gone in [
        [2, 0, 0, 0, 0, 0x77],
        [2, 0, 0, 0, 0, 0x55],
        [2, 0, 0, 0, 0, 0x66],
        [2, 0, 0, 0, 1, 0],
    ] {
        assert!(
            inv.get(&Key::Mac(gone)).is_none(),
            "{gone:?} gives no location"
        );
    }
}

/// REQ: DSC-009 — `client_fields` adds the wired port or the access point, the VLAN, the network
/// and the first time seen to the clients the poll reads, with names from the `devices` read.
#[test]
fn dsc_009_client_fields_wired_wireless() {
    let sta = json!({ "data": [
        { "mac": "02:00:00:00:00:01", "is_wired": true, "sw_mac": "aa:bb:cc:00:00:01", "sw_port": 4, "vlan": 20, "network": "IoT" },
        { "mac": "02:00:00:00:00:02", "is_wired": false, "ap_mac": "aa:bb:cc:00:00:02", "network": "Default" },
        { "mac": "02:00:00:00:00:09", "ap_mac": "aa:bb:cc:00:00:77" },
    ]});
    let users = json!({ "data": [ { "mac": "02:00:00:00:00:02", "first_seen": 1234 } ] });
    let names: HashMap<String, String> = HashMap::from([
        ("aa:bb:cc:00:00:01".to_owned(), "USW-Pro".to_owned()),
        ("aa:bb:cc:00:00:02".to_owned(), "AP-Lounge".to_owned()),
    ]);
    let p = client_fields(&sta, Some(&users), &names, NOW);
    assert_eq!(p.rows, 3);
    let mut inv = Inventory::new(0);
    inv.apply(&p.observations, NOW);
    let a = entry(&inv, A);
    assert_eq!(
        (a.port.as_deref(), a.vlan, a.network.as_deref()),
        (Some("USW-Pro port 4"), Some(20), Some("IoT"))
    );
    let b = entry(&inv, B);
    assert_eq!(b.ap.as_deref(), Some("AP-Lounge"));
    assert_eq!(b.first_seen, 1234, "rest/user knows when it was first seen");
    assert_eq!(
        entry(&inv, X).ap.as_deref(),
        Some("aa:bb:cc:00:00:77"),
        "without a name the MAC stands"
    );
    assert!(
        a.addrs.is_empty(),
        "client_fields adds fields, not addresses"
    );
}

/// REQ: DSC-009 — answer and row caps: 8,192 rows per read, the rest left out and said so.
#[test]
fn dsc_009_row_cap() {
    let rows: Vec<Value> = (0..9_000u32)
        .map(|i| {
            json!({ "mac": format!("02:00:00:00:{:02x}:{:02x}", i >> 8, i & 0xff), "last_ip": "192.168.1.5", "last_seen": NOW })
        })
        .collect();
    let p = all_users(&json!(rows), "udm", NOW, 720);
    assert_eq!(p.rows, MAX_ROWS);
    assert!(p.truncated);
    assert_eq!(p.observations.len(), MAX_ROWS);
}

/// REQ: DSC-009 (`dsc_009_ha_entityless_inventory_only`) — the second Home Assistant template lists
/// devices with a MAC and no entity; they go into the inventory as names with no address, are never
/// SNMP-eligible, and the template is a fixed, read-only one.
#[test]
fn dsc_009_ha_entityless_inventory_only() {
    let t = HA_ENTITYLESS_TEMPLATE;
    assert!(t.contains("device_entities") && t.contains("device_attr"));
    for write in [
        "service",
        "set_state",
        "turn_on",
        "turn_off",
        "states.",
        "event",
    ] {
        assert!(!t.contains(write), "the template names `{write}`");
    }
    let answer = json!({ "devices": [
        { "name_by_user": "Hall hub", "name": "Hub", "macs": ["02:00:00:00:00:01"], "area": "Hall" },
        { "name_by_user": "", "name": "Bridge", "macs": ["02:00:00:00:00:02"], "area": "" },
        { "name_by_user": "no mac", "name": "x", "macs": [] },
    ]});
    let p = ha_entityless(&answer, NOW);
    assert_eq!(p.rows, 2);
    let mut inv = Inventory::new(0);
    inv.apply(&p.observations, NOW);
    let a = entry(&inv, A);
    assert_eq!(a.display_name().unwrap().kind, NameKind::HaUser);
    assert_eq!(a.display_name().unwrap().label, "Hall hub");
    assert_eq!(
        entry(&inv, B).display_name().unwrap().kind,
        NameKind::HaIntegration
    );
    assert!(a.addrs.is_empty() && !a.snmp_eligible());
    assert_eq!(a.sources, Source::HomeAssistant.bit());
}

/// REQ: DSC-009 (`dsc_009_refused_read_reported_once`) — a read is reported when its outcome changes:
/// a refusal twice is one report, a different failure another, a success after it another; a changing
/// row count is not a change.
#[test]
fn dsc_009_refused_read_reported_once() {
    let mut r = Reported::default();
    let refused = Ended::Refused("HTTP 403".into());
    assert!(
        r.changed("udm", READ_DEVICES, &refused),
        "the first refusal is reported"
    );
    assert!(
        !r.changed("udm", READ_DEVICES, &refused),
        "the same refusal again is not"
    );
    assert!(
        r.changed("udm", READ_ALL_USERS, &refused),
        "another read is its own report"
    );
    assert!(r.changed("udm", READ_DEVICES, &Ended::Failed("timed out".into())));
    assert!(r.changed(
        "udm",
        READ_DEVICES,
        &Ended::Ok {
            rows: 5,
            truncated: false
        }
    ));
    assert!(
        !r.changed(
            "udm",
            READ_DEVICES,
            &Ended::Ok {
                rows: 9,
                truncated: false
            }
        ),
        "row counts move"
    );
    assert!(
        r.changed("udm", READ_DEVICES, &refused),
        "a refusal after a success is reported"
    );
}

// -- a fake console --------------------------------------------------------------------------

type Log = Arc<Mutex<Vec<String>>>;

/// A route: method and path prefix, the status and the body to answer.
struct Route {
    method: &'static str,
    prefix: &'static str,
    status: u16,
    body: String,
}

/// Serves `routes` on 127.0.0.1; every request line, and the POST body after a `|`, is logged.
fn fake(routes: Vec<Route>) -> (u16, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (head_end, len) = loop {
                let n = s.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break (buf.len(), 0);
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..p]).to_ascii_lowercase();
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    break (p + 4, len);
                }
            };
            while buf.len() < head_end + len {
                let n = s.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let head = String::from_utf8_lossy(&buf[..head_end.min(buf.len())]).to_string();
            let line = head.lines().next().unwrap_or("").to_owned();
            let mut it = line.split(' ');
            let (method, path) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
            let body = String::from_utf8_lossy(&buf[head_end.min(buf.len())..]).to_string();
            let auth = head
                .lines()
                .find(|l| {
                    l.to_ascii_lowercase().starts_with("authorization:")
                        || l.to_ascii_lowercase().starts_with("x-api-key:")
                })
                .unwrap_or("")
                .to_owned();
            seen.lock()
                .unwrap()
                .push(format!("{method} {path} |{body}| {auth}"));
            let route = routes
                .iter()
                .find(|r| r.method == method && path.starts_with(r.prefix));
            let (status, out) =
                route.map_or((404, "{}".to_owned()), |r| (r.status, r.body.clone()));
            let resp = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}",
                out.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    (port, log)
}

fn shared_unifi(port: u16, raw: Option<RawClients>, at: u64) -> SharedUnifi {
    SharedUnifi {
        name: "udm".into(),
        config: router(&format!("http://127.0.0.1:{port}"), "unifi"),
        session: UnifiSession {
            root: format!("http://127.0.0.1:{port}/proxy/network"),
            site: "default".into(),
            auth: Arc::new(UnifiAuth::Key(zeroize::Zeroizing::new("test-key".into()))),
        },
        raw,
        at,
    }
}

fn input(shared: Shared, cfg: ReadsConfig) -> (ReadsInput, Arc<ArcSwap<Shared>>) {
    let share = Arc::new(ArcSwap::from_pointee(shared));
    (
        ReadsInput {
            share: Arc::clone(&share),
            cfg,
            status: Arc::new(ArcSwap::from_pointee(Vec::new())),
            resolver: None,
        },
        share,
    )
}

const ALL_ON: ReadsConfig = ReadsConfig {
    client_fields: true,
    all_users: true,
    devices: true,
    within_hours: 720,
    ha_all_devices: true,
};

/// Runs the reader on a current-thread runtime until `done` says so (or 10 s pass).
fn drive(reader: &mut Reader, inv: &mut Inventory, done: impl Fn(&Inventory, &Reader) -> bool) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let start = Instant::now();
        loop {
            // Each step may start the reads; the runtime runs them while we sleep.
            reader.step(inv, NOW);
            if done(inv, reader) || start.elapsed() > Duration::from_secs(10) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });
}

fn alluser_body() -> String {
    alluser_body_at(NOW)
}

fn alluser_body_at(now: u64) -> String {
    json!({ "data": [ { "mac": "02:00:00:00:00:02", "last_ip": "192.168.1.60", "name": "gone-phone", "last_seen": now - 60 } ] }).to_string()
}

fn device_body() -> String {
    json!({ "data": [ {
        "mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.2", "name": "USW-Pro",
        "port_table": [ { "port_idx": 3, "mac_table": [ { "mac": "02:00:00:00:00:01", "vlan": 20 } ] } ],
    } ] }).to_string()
}

/// REQ: DSC-009 — against a fake console: the reads use the router's own session (its key), make
/// `GET stat/device` and `POST stat/alluser` (a query, no change), and fill the inventory; the
/// client fields come from the poll's own answers with no request of their own.
#[test]
fn dsc_009_reads_against_a_fake_console() {
    let (port, log) = fake(vec![
        Route {
            method: "GET",
            prefix: "/proxy/network/api/s/default/stat/device",
            status: 200,
            body: device_body(),
        },
        Route {
            method: "POST",
            prefix: "/proxy/network/api/s/default/stat/alluser",
            status: 200,
            body: alluser_body(),
        },
    ]);
    let sta = json!({ "data": [ { "mac": "02:00:00:00:00:01", "is_wired": true, "sw_mac": "aa:bb:cc:00:00:01", "sw_port": 3, "network": "IoT" } ] });
    let raw = RawClients {
        sta: Arc::new(sta),
        users: None,
    };
    let (inp, _share) = input(
        Shared {
            unifi: vec![shared_unifi(port, Some(raw), 100)],
            ha: Vec::new(),
        },
        ALL_ON,
    );
    let mut reader = Reader::new(inp);
    let mut inv = Inventory::new(0);
    drive(&mut reader, &mut inv, |i, r| {
        i.get(&Key::Mac(B)).is_some() && r.statuses.len() == 3
    });
    let requests = log.lock().unwrap().clone();
    assert!(
        requests
            .iter()
            .any(|r| r.starts_with("GET /proxy/network/api/s/default/stat/device")),
        "{requests:?}"
    );
    let post = requests
        .iter()
        .find(|r| r.starts_with("POST /proxy/network/api/s/default/stat/alluser"))
        .expect("the history query");
    assert!(
        post.contains("\"within\":720"),
        "the window is sent: {post}"
    );
    assert!(
        requests.iter().all(|r| r.contains("test-key")),
        "every request carries the router's key: {requests:?}"
    );
    assert!(
        requests
            .iter()
            .all(|r| !r.starts_with("PUT") && !r.starts_with("DELETE") && !r.starts_with("PATCH")),
        "no write"
    );
    // `stat/sta` and `rest/user` are not asked again.
    assert!(
        requests
            .iter()
            .all(|r| !r.contains("stat/sta") && !r.contains("rest/user")),
        "{requests:?}"
    );
    let a = entry(&inv, A);
    assert_eq!(a.port.as_deref(), Some("USW-Pro port 3"));
    assert_eq!(a.network.as_deref(), Some("IoT"));
    assert_eq!(entry(&inv, B).current().unwrap().source, Source::History);
    let status = reader.input.status.load();
    assert!(status.iter().all(|s| s.state == "ok"), "{status:?}");
    assert_eq!(status.len(), 3);
}

/// REQ: DSC-009 (`dsc_009_refused_read_reported_once`) — a console that refuses `stat/device` is
/// reported once and the other reads still work; a later poll that is refused again adds no new
/// report (the status carries the refusal; the log line is the first only).
#[test]
fn dsc_009_refused_read_is_reported_and_the_rest_work() {
    let (port, _log) = fake(vec![
        Route {
            method: "GET",
            prefix: "/proxy/network/api/s/default/stat/device",
            status: 403,
            body: "{}".into(),
        },
        Route {
            method: "POST",
            prefix: "/proxy/network/api/s/default/stat/alluser",
            status: 200,
            body: alluser_body(),
        },
    ]);
    let (inp, share) = input(
        Shared {
            unifi: vec![shared_unifi(port, None, 100)],
            ha: Vec::new(),
        },
        ReadsConfig {
            client_fields: false,
            ..ALL_ON
        },
    );
    let mut reader = Reader::new(inp);
    let mut inv = Inventory::new(0);
    drive(&mut reader, &mut inv, |_, r| r.statuses.len() == 2);
    let status = reader.input.status.load();
    let dev = status.iter().find(|s| s.read == "devices").unwrap();
    assert_eq!(dev.state, "refused");
    assert!(dev.error.as_deref().unwrap().contains("403"), "{dev:?}");
    assert_eq!(
        status.iter().find(|s| s.read == "all_users").unwrap().state,
        "ok"
    );
    assert!(inv.get(&Key::Mac(B)).is_some(), "history still came in");
    // A second poll, refused again: the outcome is unchanged, so nothing new is reported.
    let again = Reported::default();
    drop(again);
    assert!(
        !reader.reported.changed(
            "udm",
            READ_DEVICES,
            &Ended::Refused(dev.error.clone().unwrap())
        ),
        "the same refusal is already on record"
    );
    drop(share);
}

/// REQ: DSC-009 — a read that answers more than 4 MiB fails (not truncated silently), and Home
/// Assistant's registry template more than 1 MiB.
#[test]
fn dsc_009_answer_cap_fails_the_read() {
    let big = format!("{{\"data\":[{{\"pad\":\"{}\"}}]}}", "x".repeat(4 << 20));
    let (port, _log) = fake(vec![Route {
        method: "GET",
        prefix: "/proxy/network/api/s/default/stat/device",
        status: 200,
        body: big,
    }]);
    let (inp, _share) = input(
        Shared {
            unifi: vec![shared_unifi(port, None, 100)],
            ha: Vec::new(),
        },
        ReadsConfig {
            client_fields: false,
            all_users: false,
            devices: true,
            within_hours: 720,
            ha_all_devices: false,
        },
    );
    let mut reader = Reader::new(inp);
    let mut inv = Inventory::new(0);
    drive(&mut reader, &mut inv, |_, r| !r.statuses.is_empty());
    let status = reader.input.status.load();
    assert_eq!(status[0].state, "failed");
    assert!(
        status[0].error.as_deref().unwrap().contains("larger than"),
        "{status:?}"
    );

    let big_ha = format!("{{\"devices\":[],\"pad\":\"{}\"}}", "x".repeat(1 << 20));
    let (port, _log) = fake(vec![Route {
        method: "POST",
        prefix: "/api/template",
        status: 200,
        body: big_ha,
    }]);
    let (inp, _share) = input(
        Shared {
            unifi: Vec::new(),
            ha: vec![shared_ha(port, 100)],
        },
        ReadsConfig {
            client_fields: false,
            all_users: false,
            devices: false,
            within_hours: 720,
            ha_all_devices: true,
        },
    );
    let mut reader = Reader::new(inp);
    let mut inv = Inventory::new(0);
    drive(&mut reader, &mut inv, |_, r| !r.statuses.is_empty());
    let status = reader.input.status.load();
    assert_eq!(status[0].read, "home_assistant_all_devices");
    assert_eq!(status[0].state, "failed");
}

fn shared_ha(port: u16, at: u64) -> SharedHa {
    SharedHa {
        name: "ha".into(),
        config: router(&format!("http://127.0.0.1:{port}"), "home_assistant"),
        token: Arc::new(zeroize::Zeroizing::new("ha-token".into())),
        raw: Arc::new((
            vec![crate::routers::HaDevice {
                macs: vec!["02:00:00:00:00:01".into()],
                name: "Porch light".into(),
                curated: true,
            }],
            HashMap::from([(
                "02:00:00:00:00:01".to_owned(),
                "192.168.1.31".parse().unwrap(),
            )]),
        )),
        at,
    }
}

/// REQ: DSC-009 — Home Assistant: the poll's own devices and tracker address feed the inventory (the
/// feed `sources::ha_observations` waited for), and the second template adds entity-less devices.
#[test]
fn dsc_009_ha_feed_and_entityless_read() {
    let body = json!({ "devices": [ { "name_by_user": "", "name": "Bridge", "macs": ["02:00:00:00:00:02"], "area": "Hall" } ] }).to_string();
    let (port, log) = fake(vec![Route {
        method: "POST",
        prefix: "/api/template",
        status: 200,
        body,
    }]);
    let (inp, _share) = input(
        Shared {
            unifi: Vec::new(),
            ha: vec![shared_ha(port, 100)],
        },
        ALL_ON,
    );
    let mut reader = Reader::new(inp);
    let mut inv = Inventory::new(0);
    drive(&mut reader, &mut inv, |i, _| i.get(&Key::Mac(B)).is_some());
    let a = entry(&inv, A);
    assert_eq!(a.display_name().unwrap().label, "Porch light");
    assert_eq!(a.current().unwrap().source, Source::HomeAssistant);
    assert!(
        !a.snmp_eligible(),
        "a Home Assistant address is a claim (ADR-923)"
    );
    assert_eq!(
        entry(&inv, B).display_name().unwrap().kind,
        NameKind::HaIntegration
    );
    let requests = log.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "one template request: {requests:?}");
    assert!(
        requests[0].contains("device_entities") && requests[0].contains("Bearer ha-token"),
        "{requests:?}"
    );
    // With the switch off, no request is made.
    let (inp, _s) = input(
        Shared {
            unifi: Vec::new(),
            ha: vec![shared_ha(port, 200)],
        },
        ReadsConfig {
            ha_all_devices: false,
            ..ALL_ON
        },
    );
    let mut reader = Reader::new(inp);
    let mut inv = Inventory::new(0);
    reader.step(&mut inv, NOW);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        log.lock().unwrap().len(),
        1,
        "no second request while the switch is off"
    );
}

/// A resolver that records which thread asks.
struct Recording(Arc<Mutex<Vec<String>>>);

impl telltale_filter::fetch::Resolve for Recording {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<IpAddr>, String>> + Send + 'a>>
    {
        let name = std::thread::current().name().unwrap_or("").to_owned();
        self.0.lock().unwrap().push(name);
        let ip: IpAddr = host
            .parse()
            .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
        Box::pin(async move { Ok(vec![ip]) })
    }
}

/// REQ: DSC-009 (`dsc_009_reads_off_main_runtime`) — the extra reads run on the `telltale-inventory`
/// thread, not on the router poll's runtime: the connection to the console is made from that thread;
/// and `routers.rs` itself holds no request for these reads (it only shares the session).
#[test]
fn dsc_009_reads_off_main_runtime() {
    let (port, _log) = fake(vec![
        Route {
            method: "GET",
            prefix: "/proxy/network/api/s/default/stat/device",
            status: 200,
            body: device_body(),
        },
        Route {
            method: "POST",
            prefix: "/proxy/network/api/s/default/stat/alluser",
            status: 200,
            body: alluser_body_at(crate::pipeline::unix_now()),
        },
    ]);
    let threads: Arc<Mutex<Vec<String>>> = Arc::default();
    // A host name, so the connection goes through the resolver that records the thread.
    let mut su = shared_unifi(port, None, 100);
    su.session.root = format!("http://localhost:{port}/proxy/network");
    su.config = router(&format!("http://localhost:{port}"), "unifi");
    let (mut inp, _share) = input(
        Shared {
            unifi: vec![su],
            ha: Vec::new(),
        },
        ALL_ON,
    );
    inp.resolver = Some(Arc::new(Recording(Arc::clone(&threads))));
    let dir = std::env::temp_dir().join(format!("tt-reads-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let handle = thread::spawn(
        dir.clone(),
        thread::Providers {
            reads: Some(inp.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    let start = Instant::now();
    while handle.shared.load().get(&Key::Mac(B)).is_none()
        && start.elapsed() < Duration::from_secs(10)
    {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        handle.shared.load().get(&Key::Mac(B)).is_some(),
        "the thread merged the reads"
    );
    handle.stop();
    let _ = std::fs::remove_dir_all(&dir);
    let names = threads.lock().unwrap().clone();
    assert!(!names.is_empty(), "the console was reached");
    assert!(
        names.iter().all(|n| n == "telltale-inventory"),
        "reads ran on {names:?}"
    );
    let routers_src = include_str!("../routers.rs");
    for banned in [
        "stat/alluser",
        "stat/device",
        "HA_ENTITYLESS_TEMPLATE",
        "READ_ALL_USERS",
    ] {
        assert!(!routers_src.contains(banned), "routers.rs names {banned}");
    }
}

/// REQ: DSC-009 (`dsc_009_never_in_router_leases_or_device_dns`) — the reads' module never names the
/// lease view, the mDNS or peer name maps, or the identify chain, and the DNS-name and lease modules
/// never name the discovery module: the reads reach the inventory only (ADR-910, ADR-912).
#[test]
fn dsc_009_never_in_router_leases_or_device_dns() {
    let reads = include_str!("reads.rs");
    for banned in [
        "router_leases",
        "mdns_names",
        "peer_names",
        "identify::",
        "devices::Names",
        "device_dns",
        "telltale_policy",
    ] {
        assert!(!reads.contains(banned), "reads.rs mentions {banned}");
    }
    for (file, src) in [
        ("device_dns.rs", include_str!("../device_dns.rs")),
        ("devices.rs", include_str!("../devices.rs")),
        ("identify.rs", include_str!("../identify.rs")),
    ] {
        assert!(
            !src.contains("discovery::"),
            "{file} reaches into the inventory"
        );
    }
}

/// REQ: DSC-009 — the router poll keeps a session and raw answers only when asked: nothing is shared
/// while discovery is off, and a raw answer only with `client_fields` (the `Keep` default keeps none).
#[test]
fn dsc_009_share_is_empty_unless_asked() {
    let keep = crate::routers::Keep::default();
    assert!(!keep.share && !keep.raw_clients);
    let s = Shared::default();
    assert!(s.unifi.is_empty() && s.ha.is_empty());
    // A credential never shows in a Debug print.
    let su = shared_unifi(1, None, 1);
    let shown = format!("{su:?}");
    assert!(!shown.contains("test-key"), "{shown}");
    let ha = format!("{:?}", shared_ha(1, 1));
    assert!(!ha.contains("ha-token"), "{ha}");
}

/// What the status shows when it is empty is nothing: no read, no row.
#[test]
fn dsc_009_status_is_empty_without_reads() {
    let inp = input(Shared::default(), ALL_ON).0;
    let mut reader = Reader::new(inp);
    let mut inv = Inventory::new(0);
    assert!(!reader.step(&mut inv, NOW));
    assert!(reader.input.status.load().is_empty());
    let none: Vec<DiscoveryRead> = Vec::new();
    assert_eq!(**reader.input.status.load(), none);
}

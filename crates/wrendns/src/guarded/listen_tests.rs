// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-902, DNS-001, DNS-901 (T27.14c; `docs/design/listener-editor.md` sections 1, 2.6 and 4) —
//! the `listen` row's applier: value parsing, the check table, the weakening table over host-fact
//! fixtures, the certificate rules, the gate lines, and the overlay order. Nothing here binds a
//! socket: the engine and the sockets are driven in `tests/listen_engine_tests.rs` and the server's
//! own tests.

#![allow(clippy::field_reassign_with_default, clippy::many_single_char_names)]

use serde_json::{Value, json};
use wrendns_api::problem::Code;
use wrendns_config::{Config, HostFacts, ListenProto, Listener};

use super::engine::Checked;
use super::host::Member;
use super::listen::{Env, evaluate, merged, merged_with, parse, weakening_reason};

const PUBLIC4: HostFacts = HostFacts {
    public_ipv4: Some(true),
    global_ipv6: false,
};
const PRIVATE4: HostFacts = HostFacts {
    public_ipv4: Some(false),
    global_ipv6: false,
};
const GLOBAL6: HostFacts = HostFacts {
    public_ipv4: Some(false),
    global_ipv6: true,
};

fn env(host: HostFacts) -> Env {
    Env {
        host,
        local: Some(vec![
            "127.0.0.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
            "203.0.113.9".parse().unwrap(),
        ]),
        supervisor: "systemd".to_owned(),
        now: 1_800_000_000,
    }
}

fn l(proto: &str, addr: &str) -> Value {
    json!({"proto": proto, "addr": addr})
}

fn value(list: &[Value]) -> Value {
    json!({"listeners": list})
}

/// A node that runs the defaults (UDP and TCP on port 53, IPv4 and IPv6) and moves nothing else.
fn defaults() -> Vec<Value> {
    vec![
        l("udp", "0.0.0.0:53"),
        l("tcp", "0.0.0.0:53"),
        l("udp", "[::]:53"),
        l("tcp", "[::]:53"),
    ]
}

fn run(cfg: &Config, v: &Value, host: HostFacts) -> Result<Checked, wrendns_api::problem::Problem> {
    evaluate(cfg, "pi-a", v, &[], "", &env(host), None)
}

fn err(cfg: &Config, v: &Value) -> String {
    run(cfg, v, PRIVATE4).unwrap_err().detail
}

fn with(extra: Vec<Value>) -> Value {
    let mut all = defaults();
    all.extend(extra);
    value(&all)
}

pub(super) struct Pki {
    dir: tempfile::TempDir,
}

impl Pki {
    pub(super) fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    pub(super) fn pair(&self, name: &str, names: &[&str]) -> (String, String) {
        let ck = rcgen::generate_simple_self_signed(
            names.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        )
        .unwrap();
        let (c, k) = (
            self.dir.path().join(format!("{name}.crt")),
            self.dir.path().join(format!("{name}.key")),
        );
        std::fs::write(&c, ck.cert.pem()).unwrap();
        std::fs::write(&k, ck.signing_key.serialize_pem()).unwrap();
        (
            c.to_string_lossy().into_owned(),
            k.to_string_lossy().into_owned(),
        )
    }
    fn expired(&self, name: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["old.example".to_owned()]).unwrap();
        p.not_before = rcgen::date_time_ymd(2019, 1, 1);
        p.not_after = rcgen::date_time_ymd(2020, 1, 1);
        let cert = p.self_signed(&key).unwrap();
        let (c, k) = (
            self.dir.path().join(format!("{name}.crt")),
            self.dir.path().join(format!("{name}.key")),
        );
        std::fs::write(&c, cert.pem()).unwrap();
        std::fs::write(&k, key.serialize_pem()).unwrap();
        (
            c.to_string_lossy().into_owned(),
            k.to_string_lossy().into_owned(),
        )
    }
}

pub(super) fn dot(addr: &str, cert: &str, key: &str) -> Value {
    json!({"proto": "dot", "addr": addr, "tls": {"cert": cert, "key": key}})
}

// ---- the value -------------------------------------------------------------------------

// Unknown fields are refused, and `proxyProtocol` and `requireClientId` each name where they are set.
#[test]
fn api_902_listen_value_refuses_unknown_and_foreign_fields() {
    let bad = |v: Value| parse(&v).unwrap_err().detail;
    assert!(bad(json!({"listeners": [], "extra": 1})).contains("`extra` isn't a field"));
    let mut a = l("udp", "0.0.0.0:53");
    a["colour"] = json!("red");
    assert!(bad(value(&[a])).contains("`colour` isn't a field"));
    let mut p = l("tcp", "0.0.0.0:53");
    p["proxyProtocol"] = json!(true);
    let d = bad(value(&[p]));
    assert!(
        d.contains("configuration file only") && d.contains("PROXY"),
        "{d}"
    );
    let mut g = l("dot", "0.0.0.0:853");
    g["requireClientId"] = json!(true);
    let d = bad(value(&[g]));
    assert!(
        d.contains("Listener access") && d.contains("listen-access"),
        "{d}"
    );
    // The snake_case spellings of the configuration file are refused the same way.
    let mut s = l("tcp", "0.0.0.0:53");
    s["proxy_protocol"] = json!(true);
    assert!(bad(value(&[s])).contains("configuration file only"));
}

// The listener rules of the configuration check, and the round trip of a good value.
#[test]
fn api_902_listen_value_rules_and_round_trip() {
    let bad = |v: Value| parse(&v).unwrap_err().detail;
    assert!(bad(json!({"listeners": 3})).contains("must be a list"));
    assert!(bad(value(&[l("smtp", "0.0.0.0:25")])).contains("`proto` must be"));
    assert!(bad(value(&[l("udp", "nowhere")])).contains("`addr` must look like"));
    assert!(bad(value(&[l("udp", "0.0.0.0:0")])).contains("port must be 1 to 65535"));
    assert!(bad(value(&[l("dot", "0.0.0.0:853")])).contains("`tls`"));
    assert!(bad(value(&[dot("0.0.0.0:853", "", "/k")])).contains("`tls.cert` must be a path"));
    let mut u = l("udp", "0.0.0.0:53");
    u["tls"] = json!({"cert": "/c", "key": "/k"});
    assert!(bad(value(&[u])).contains("only for dot"));
    let mut p = l("tcp", "0.0.0.0:53");
    p["path"] = json!("/x");
    assert!(bad(value(&[p])).contains("only for doh and doh3"));
    let mut h = json!({"proto": "doh", "addr": "0.0.0.0:443", "tls": {"cert": "/c", "key": "/k"}, "path": "dns"});
    assert!(bad(value(std::slice::from_ref(&h))).contains("must start with `/`"));
    h["path"] = json!("/dns-query");
    assert!(parse(&value(std::slice::from_ref(&h))).is_ok());
    let mut lim = l("udp", "0.0.0.0:53");
    lim["maxConnections"] = json!(5);
    assert!(bad(value(&[lim])).contains("limits aren't for udp"));
    let mut zero = l("tcp", "0.0.0.0:53");
    zero["maxConnections"] = json!(0);
    assert!(bad(value(&[zero])).contains("at least 1"));
    assert!(bad(value(&[l("udp", "0.0.0.0:53"), l("udp", "0.0.0.0:53")])).contains("twice"));
    // A good value survives parse and back.
    let mut t = l("tcp", "10.0.0.1:53");
    t["maxConnections"] = json!(8);
    t["maxConnectionsPerAddress"] = json!(2);
    let v = value(&[l("udp", "10.0.0.1:53"), t]);
    let list = parse(&v).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[1].max_connections, Some(8));
    assert_eq!(super::listen::to_value(&list), v);
}

// ---- the check table -------------------------------------------------------------------

#[test]
fn api_902_listen_check_table_internal_ports_and_overlaps() {
    let cfg = Config::default();
    // The web UI's port, the metrics endpoint's, the cluster's, and the redirect's, each named.
    let d = err(&cfg, &with(vec![l("udp", "192.168.1.2:8053")]));
    assert!(
        d.contains("port 8053 is the web UI's ([api] listen)"),
        "{d}"
    );
    let d = err(&cfg, &with(vec![l("tcp", "192.168.1.2:9153")]));
    assert!(d.contains("([telemetry.metrics] listen)"), "{d}");
    let d = err(&cfg, &with(vec![l("udp", "192.168.1.2:8443")]));
    assert!(d.contains("([cluster] listen)"), "{d}");
    let mut c = Config::default();
    c.api.http_redirect = Some("0.0.0.0:80".parse().unwrap());
    let d = err(&c, &with(vec![l("tcp", "192.168.1.2:80")]));
    assert!(d.contains("([api] http_redirect)"), "{d}");
    // A listener that stays on such a port is not judged: the running set is what it is.
    let mut c = Config::default();
    c.listen.push(
        parse(&value(&[l("tcp", "192.168.1.2:9153")]))
            .unwrap()
            .remove(0),
    );
    let mut kept = with(vec![l("tcp", "192.168.1.2:9153")]);
    assert!(run(&c, &kept, PRIVATE4).is_ok());
    kept = with(vec![]);
    assert!(run(&c, &kept, PRIVATE4).is_ok());
    // Two sockets that cannot share a port: TCP-based with TCP-based, QUIC with QUIC; UDP shares.
    let d = err(
        &cfg,
        &with(vec![l("tcp", "192.168.1.2:5300"), l("tcp", "0.0.0.0:5300")]),
    );
    assert!(d.contains("overlaps"), "{d}");
    let fine = with(vec![l("udp", "192.168.1.2:5300"), l("udp", "0.0.0.0:5300")]);
    assert!(
        run(&cfg, &fine, PRIVATE4).is_ok(),
        "plain UDP shares a port"
    );
    // Families do not overlap each other.
    let fam = with(vec![l("tcp", "192.168.1.2:5300"), l("tcp", "[::]:5300")]);
    assert!(run(&cfg, &fam, PRIVATE4).is_ok());
}

#[test]
fn api_902_listen_check_table_empty_and_port_53() {
    let cfg = Config::default();
    let none = run(&cfg, &value(&[]), PRIVATE4).unwrap();
    assert!(none.would_disconnect);
    assert!(none.disconnect_detail.unwrap().contains("no DNS listener"));
    // Each family and transport of the running port 53 must stay.
    for (drop, want) in [
        ("udp://0.0.0.0:53", "no UDP listener on port 53 for IPv4"),
        ("tcp://0.0.0.0:53", "no TCP listener on port 53 for IPv4"),
        ("udp://[::]:53", "no UDP listener on port 53 for IPv6"),
        ("tcp://[::]:53", "no TCP listener on port 53 for IPv6"),
    ] {
        let kept: Vec<Value> = defaults()
            .into_iter()
            .filter(|v| {
                format!(
                    "{}://{}",
                    v["proto"].as_str().unwrap(),
                    v["addr"].as_str().unwrap()
                ) != drop
            })
            .collect();
        let c = run(&cfg, &value(&kept), PRIVATE4).unwrap();
        assert!(c.would_disconnect, "{drop}");
        assert!(c.disconnect_detail.unwrap().contains(want), "{drop}");
    }
    // A specific address on port 53 stands in for the wildcard of its family.
    let moved = value(&[
        l("udp", "192.168.1.2:53"),
        l("tcp", "192.168.1.2:53"),
        l("udp", "[::]:53"),
        l("tcp", "[::]:53"),
    ]);
    assert!(!run(&cfg, &moved, PRIVATE4).unwrap().would_disconnect);
    // A node that does not run port 53 today is not held to it.
    let mut off53 = Config::default();
    off53.listen = parse(&value(&[
        l("udp", "0.0.0.0:5353"),
        l("tcp", "0.0.0.0:5353"),
    ]))
    .unwrap();
    let c = run(&off53, &value(&[l("udp", "0.0.0.0:5454")]), PRIVATE4).unwrap();
    assert!(!c.would_disconnect);
    // One family only on port 53 today: the other is not demanded.
    let mut v4only = Config::default();
    v4only.listen = parse(&value(&[l("udp", "0.0.0.0:53"), l("tcp", "0.0.0.0:53")])).unwrap();
    let c = run(
        &v4only,
        &value(&[
            l("udp", "0.0.0.0:53"),
            l("tcp", "0.0.0.0:53"),
            l("dot", "0.0.0.0:5353"),
        ]),
        PRIVATE4,
    );
    assert!(c.is_err(), "the dot listener needs a certificate");
}

#[test]
fn api_902_listen_check_table_witness_and_cluster_warning() {
    let cfg = Config::default();
    let w = Member {
        id: "pi-a".to_owned(),
        name: "pi-a".to_owned(),
        is_primary: false,
        up: true,
        site: "home".to_owned(),
        witness: true,
    };
    let e = evaluate(
        &cfg,
        "pi-a",
        &value(&defaults()),
        &[w],
        "home",
        &env(PRIVATE4),
        None,
    )
    .unwrap_err();
    assert_eq!(e.code, Code::InvalidConfig);
    assert!(e.detail.contains("witness serves no DNS"));
    // The only healthy resolver of its site is a warning.
    let other = |up: bool| Member {
        id: "pi-b".to_owned(),
        name: "pi-b".to_owned(),
        is_primary: true,
        up,
        site: "home".to_owned(),
        witness: false,
    };
    let c = evaluate(
        &cfg,
        "pi-a",
        &value(&defaults()),
        &[other(false)],
        "home",
        &env(PRIVATE4),
        None,
    )
    .unwrap();
    assert!(
        c.warnings
            .iter()
            .any(|w| w.contains("only healthy resolver in site home"))
    );
    let c = evaluate(
        &cfg,
        "pi-a",
        &value(&defaults()),
        &[other(true)],
        "home",
        &env(PRIVATE4),
        None,
    )
    .unwrap();
    assert!(
        !c.warnings
            .iter()
            .any(|w| w.contains("only healthy resolver"))
    );
}

#[test]
fn api_902_listen_warnings_platform_and_interface() {
    let cfg = Config::default();
    let v = with(vec![l("udp", "198.51.100.7:5300")]);
    let c = run(&cfg, &v, PRIVATE4).unwrap();
    assert!(
        c.warnings
            .iter()
            .any(|w| w.contains("198.51.100.7 is on no interface")),
        "{:?}",
        c.warnings
    );
    // An address the host holds, and a wildcard, do not warn.
    let c = run(&cfg, &with(vec![l("udp", "192.168.1.2:5300")]), PRIVATE4).unwrap();
    assert!(!c.warnings.iter().any(|w| w.contains("no interface")));
    // Docker and Kubernetes.
    let mut e = env(PRIVATE4);
    e.supervisor = "docker".to_owned();
    let c = evaluate(&cfg, "pi-a", &with(vec![]), &[], "", &e, None).unwrap();
    assert!(
        c.warnings
            .iter()
            .any(|w| w.contains("Docker or Kubernetes"))
    );
    // An unreadable interface list says nothing about interfaces.
    let mut e = env(PRIVATE4);
    e.local = None;
    let c = evaluate(&cfg, "pi-a", &v, &[], "", &e, None).unwrap();
    assert!(!c.warnings.iter().any(|w| w.contains("no interface")));
}

#[test]
fn api_902_listen_removed_address_is_said_out_loud() {
    let mut cfg = Config::default();
    cfg.listen.extend(
        parse(&value(&[
            l("udp", "192.168.1.2:53"),
            l("tcp", "192.168.1.2:53"),
        ]))
        .unwrap(),
    );
    let c = run(&cfg, &value(&defaults()), PRIVATE4).unwrap();
    let w = c
        .warnings
        .iter()
        .find(|w| w.contains("stop getting answers"))
        .unwrap();
    assert!(w.contains("192.168.1.2") && w.contains("DHCP"), "{w}");
    assert_eq!(
        c.warnings
            .iter()
            .filter(|w| w.contains("stop getting answers"))
            .count(),
        1,
        "once per address, not per protocol"
    );
    let removed: Vec<_> = c
        .listeners
        .iter()
        .filter(|x| x.change == "removed")
        .collect();
    assert_eq!(removed.len(), 2);
    assert!(
        c.effect
            .contains("Removes UDP on 192.168.1.2:53, TCP on 192.168.1.2:53 when you confirm"),
        "{}",
        c.effect
    );
    assert!(
        c.effect
            .contains("Keeps every current listener until you confirm")
    );
}

// ---- the weakening table ---------------------------------------------------------------

fn lst(list: &[Value]) -> Vec<Listener> {
    parse(&value(list)).unwrap()
}

fn weak(running: &[Value], new: &[Value], host: HostFacts) -> bool {
    let r = lst(running);
    weakening_reason(&r, &merged(lst(new), &r), host).is_some()
}

// REQ: API-902, DNS-901 (design 4; owner decision 2026-11-26) — rules (a), (b) and (c) over the host
// facts: public IPv4, private only, global IPv6 only, and an unreadable interface list.
#[test]
fn api_902_listener_weakening_table() {
    let base = defaults();
    let add = |x: Value| {
        let mut v = base.clone();
        v.push(x);
        v
    };
    let (c, k) = ("/c", "/k");
    let unread = HostFacts::UNKNOWN;
    // (c) plain UDP or TCP added on a public address weakens, on any host.
    for host in [PUBLIC4, PRIVATE4, GLOBAL6, unread] {
        assert!(
            weak(&base, &add(l("udp", "203.0.113.9:5300")), host),
            "udp {host:?}"
        );
        assert!(
            weak(&base, &add(l("tcp", "203.0.113.9:5300")), host),
            "tcp {host:?}"
        );
        // A private address never does.
        assert!(
            !weak(&base, &add(l("udp", "192.168.1.2:5300")), host),
            "lan {host:?}"
        );
        assert!(!weak(&base, &add(l("udp", "127.0.0.1:5300")), host));
    }
    // (c) an encrypted listener on a public address: the default gate is on, so it does not weaken.
    for host in [PUBLIC4, PRIVATE4, GLOBAL6, unread] {
        assert!(
            !weak(&base, &add(dot("203.0.113.9:853", c, k)), host),
            "gated {host:?}"
        );
    }
    // ... unless the gate is off there: a kept explicit setting is not this row's, so an added
    // listener always starts on its default; an encrypted one on a private address is off and not
    // reachable.
    assert!(!weak(&base, &add(dot("192.168.1.2:853", c, k)), PUBLIC4));
    // (c) a wildcard added: reachable on a host with a public IPv4 address or an unreadable list.
    let wild = |p: &str| l(p, "0.0.0.0:5300");
    assert!(weak(&base, &add(wild("udp")), PUBLIC4));
    assert!(weak(&base, &add(wild("udp")), unread));
    assert!(!weak(&base, &add(wild("udp")), PRIVATE4));
    assert!(!weak(&base, &add(wild("udp")), GLOBAL6));
    // A wildcard encrypted listener is gated by default where it is reachable, off where it is not,
    // and where it is off it is not reachable either.
    for host in [PUBLIC4, PRIVATE4, GLOBAL6, unread] {
        assert!(
            !weak(&base, &add(dot("0.0.0.0:853", c, k)), host),
            "wild dot {host:?}"
        );
    }
    // A kept listener never counts, even a public one on a public host.
    let with_public = {
        let mut v = base.clone();
        v.push(l("udp", "203.0.113.9:5300"));
        v
    };
    assert!(!weak(&with_public, &with_public, PUBLIC4));
    // A widened allowed_networks changes nothing: it is not in the value at all (the rule is judged
    // on the socket), so the same added socket gives the same answer.
    // (b) a gated encrypted listener replaced by an ungated one of its protocol.
    let gated = vec![l("udp", "0.0.0.0:53"), dot("203.0.113.9:853", c, k)];
    let to_wild = vec![l("udp", "0.0.0.0:53"), dot("0.0.0.0:853", c, k)];
    assert!(
        weak(&gated, &to_wild, GLOBAL6),
        "public dot to a wildcard on an IPv6-only host"
    );
    assert!(
        !weak(&gated, &to_wild, PUBLIC4),
        "the wildcard is gated where the host is public"
    );
    // Removing the gated listener without adding an ungated one is not (b); it is (a), because the
    // wildcard plain listener that stays serves that address without encryption.
    assert!(weak(&gated, &[l("udp", "0.0.0.0:53")], GLOBAL6));
    assert!(!weak(&gated, &[l("udp", "192.168.1.3:53")], GLOBAL6));
    // (a) the encrypted listener goes and plain DNS stays on the address.
    let enc = vec![l("udp", "192.168.1.2:53"), dot("192.168.1.2:853", c, k)];
    assert!(weak(&enc, &[l("udp", "192.168.1.2:53")], PRIVATE4));
    // ... but not when another encrypted listener serves it, or the address has no plain listener.
    let two = vec![
        l("udp", "192.168.1.2:53"),
        dot("192.168.1.2:853", c, k),
        json!({"proto": "doq", "addr": "192.168.1.2:853", "tls": {"cert": c, "key": k}}),
    ];
    assert!(!weak(
        &two,
        &[
            l("udp", "192.168.1.2:53"),
            json!({"proto": "doq", "addr": "192.168.1.2:853", "tls": {"cert": c, "key": k}})
        ],
        PRIVATE4
    ));
    assert!(!weak(&enc, &[l("udp", "192.168.1.3:53")], PRIVATE4));
    // (a) with a wildcard on either side: a specific encrypted address removed while a wildcard
    // plain listener stays, and a wildcard encrypted listener removed while a plain listener on a
    // specific address stays. A wildcard of the other family serves nothing there.
    let spec = vec![l("udp", "0.0.0.0:53"), dot("192.168.1.2:853", c, k)];
    assert!(weak(&spec, &[l("udp", "0.0.0.0:53")], PRIVATE4));
    let wild = vec![l("udp", "192.168.1.2:53"), dot("0.0.0.0:853", c, k)];
    assert!(weak(&wild, &[l("udp", "192.168.1.2:53")], PRIVATE4));
    assert!(!weak(&wild, &[l("udp", "[::]:53")], PRIVATE4));
    // ... and not when a wildcard encrypted listener still covers the address.
    assert!(!weak(
        &spec,
        &[l("udp", "0.0.0.0:53"), dot("0.0.0.0:853", c, k)],
        PRIVATE4
    ));
    // ... but a specific encrypted listener never covers a removed wildcard one: every other address
    // of the host loses encryption while plain DNS keeps serving it.
    let w4 = vec![l("udp", "0.0.0.0:53"), dot("0.0.0.0:853", c, k)];
    let s4 = vec![l("udp", "0.0.0.0:53"), dot("192.168.1.5:853", c, k)];
    let w6 = vec![l("udp", "[::]:53"), dot("[::]:853", c, k)];
    let s6 = vec![l("udp", "[::]:53"), dot("[fd00::5]:853", c, k)];
    for host in [PRIVATE4, GLOBAL6] {
        assert!(weak(&w4, &s4, host), "v4 {host:?}");
        assert!(weak(&w6, &s6, host), "v6 {host:?}");
    }
}

// The weakening reaches the preview: the red mark, and the rule is named.
#[test]
fn api_902_listen_weakening_is_in_the_preview() {
    let cfg = Config::default();
    let c = run(&cfg, &with(vec![l("udp", "203.0.113.9:5300")]), PRIVATE4).unwrap();
    assert!(c.weakening);
    assert!(
        c.warnings.iter().any(|w| w.contains("adds UDP on 203.0.113.9:5300, which answers anyone on the internet without a device key")),
        "{:?}",
        c.warnings
    );
    let c = run(&cfg, &with(vec![l("udp", "192.168.1.2:5300")]), PRIVATE4).unwrap();
    assert!(!c.weakening);
    let c = run(&cfg, &with(vec![l("udp", "0.0.0.0:5300")]), PUBLIC4).unwrap();
    assert!(c.weakening && c.warnings.iter().any(|w| w.contains("binds every address")));
}

// ---- certificates ----------------------------------------------------------------------

#[test]
fn api_902_listen_certificate_rules() {
    let cfg = Config::default();
    let pki = Pki::new();
    let (c, k) = pki.pair("good", &["dns.example"]);
    // A good pair: names and expiry shown, contents never returned.
    let ok = run(&cfg, &with(vec![dot("192.168.1.2:853", &c, &k)]), PRIVATE4).unwrap();
    let line = ok
        .listeners
        .iter()
        .find(|x| x.listener == "dot://192.168.1.2:853")
        .unwrap();
    let cert = line.certificate.clone().unwrap();
    assert!(
        cert.contains("dns.example") && cert.contains("expires in"),
        "{cert}"
    );
    let all =
        serde_json::to_string(&(&ok.effect, &ok.warnings, &ok.checks, &ok.listeners)).unwrap();
    assert!(!all.contains("BEGIN"), "no file contents in the answer");
    assert!(
        ok.checks
            .iter()
            .any(|x| x.name.starts_with("certificate ") && x.ok)
    );
    // A relative path, a missing file, a directory.
    let d = err(&cfg, &with(vec![dot("192.168.1.2:853", "dns.crt", &k)]));
    assert!(d.contains("must be absolute"), "{d}");
    let d = err(
        &cfg,
        &with(vec![dot("192.168.1.2:853", &format!("{c}.nope"), &k)]),
    );
    assert!(d.contains("can't be read"), "{d}");
    let dir = pki.dir.path().to_string_lossy().into_owned();
    let d = err(&cfg, &with(vec![dot("192.168.1.2:853", &dir, &k)]));
    assert!(d.contains("isn't a regular file"), "{d}");
    // A key that does not match the certificate.
    let (_, k2) = pki.pair("other", &["other.example"]);
    let d = err(&cfg, &with(vec![dot("192.168.1.2:853", &c, &k2)]));
    assert!(d.contains("can't be used together"), "{d}");
    // Not a certificate at all.
    let junk = pki.dir.path().join("junk.crt");
    std::fs::write(&junk, "not a certificate").unwrap();
    let d = err(
        &cfg,
        &with(vec![dot("192.168.1.2:853", &junk.to_string_lossy(), &k)]),
    );
    assert!(d.contains("can't be used together"), "{d}");
    // A path the T23.2 rules deny.
    let d = err(
        &cfg,
        &with(vec![dot("192.168.1.2:853", "/proc/self/environ", &k)]),
    );
    assert!(
        d.contains("no path set through the UI or API may name")
            || d.contains("can't be read")
            || d.contains("regular file"),
        "{d}"
    );
    let mut c2 = Config::default();
    c2.node.data_dir =
        wrendns_config::SafeString::new(pki.dir.path().to_string_lossy().into_owned()).unwrap();
    let d = err(&c2, &with(vec![dot("192.168.1.2:853", &c, &k)]));
    assert!(d.contains("data directory"), "{d}");
}

#[cfg(unix)]
#[test]
fn api_902_listen_certificate_symlink_refused() {
    let cfg = Config::default();
    let pki = Pki::new();
    let (c, k) = pki.pair("real", &["dns.example"]);
    let link = pki.dir.path().join("link.crt");
    std::os::unix::fs::symlink(&c, &link).unwrap();
    let d = err(
        &cfg,
        &with(vec![dot("192.168.1.2:853", &link.to_string_lossy(), &k)]),
    );
    assert!(d.contains("symbolic link"), "{d}");
}

#[test]
fn api_902_listen_certificate_expiry_warnings() {
    let pki = Pki::new();
    let (c, k) = pki.pair("fine", &["dns.example"]);
    // The expiry warning follows `[probe] cert_warn_days`.
    let mut cfg = Config::default();
    cfg.probe.cert_warn_days = 10_000_000;
    let ok = run(&cfg, &with(vec![dot("192.168.1.2:853", &c, &k)]), PRIVATE4).unwrap();
    assert!(
        ok.warnings.iter().any(|w| w.contains("expires in")),
        "{:?}",
        ok.warnings
    );
    let cfg = Config::default();
    let ok = run(&cfg, &with(vec![dot("192.168.1.2:853", &c, &k)]), PRIVATE4).unwrap();
    assert!(
        !ok.warnings
            .iter()
            .any(|w| w.contains("expires in") || w.contains("expired"))
    );
    let (ec, ek) = pki.expired("old");
    let old = run(
        &cfg,
        &with(vec![dot("192.168.1.2:853", &ec, &ek)]),
        PRIVATE4,
    )
    .unwrap();
    assert!(
        old.warnings.iter().any(|w| w.contains("has expired")),
        "{:?}",
        old.warnings
    );
}

// A listener the node already runs as it is, whose files can't be used now, is a warning: an
// unrelated change is not held up by it. Changing that listener (or adding one on the same files) is.
#[test]
fn api_902_listen_kept_listener_with_a_bad_certificate_is_a_warning() {
    let pki = Pki::new();
    let (c, k) = pki.pair("kept", &["dns.example"]);
    let mut cfg = Config::default();
    cfg.listen
        .extend(parse(&value(&[dot("192.168.1.2:853", &c, &k)])).unwrap());
    std::fs::remove_file(&c).unwrap();
    // Kept: warned about, and the rest of the change goes through.
    let same = with(vec![
        dot("192.168.1.2:853", &c, &k),
        l("udp", "192.168.1.2:5300"),
    ]);
    let ok = run(&cfg, &same, PRIVATE4).unwrap();
    assert!(
        ok.warnings
            .iter()
            .any(|w| w.contains("is kept, but its certificate can't be used now")),
        "{:?}",
        ok.warnings
    );
    // Another listener on the same broken files is added: refused.
    let more = with(vec![
        dot("192.168.1.2:853", &c, &k),
        dot("192.168.1.2:8853", &c, &k),
    ]);
    assert!(err(&cfg, &more).contains("can't be read"));
}

// ---- the gate lines --------------------------------------------------------------------

#[test]
fn api_902_listen_gate_lines_and_dropped_settings() {
    let pki = Pki::new();
    let (c, k) = pki.pair("g", &["dns.example"]);
    let mut cfg = Config::default();
    let mut old = parse(&value(&[dot("192.168.1.2:853", &c, &k)])).unwrap();
    old[0].require_client_id = Some(false);
    cfg.listen.extend(old);
    // Moved to the public address: starts on its default, the explicit setting is dropped and named.
    let v = with(vec![dot("203.0.113.9:853", &c, &k)]);
    let ck = run(&cfg, &v, PRIVATE4).unwrap();
    let added = ck
        .listeners
        .iter()
        .find(|x| x.listener == "dot://203.0.113.9:853")
        .unwrap();
    assert_eq!(added.change, "added");
    assert_eq!(
        added.gate.as_deref(),
        Some(
            "dot://203.0.113.9:853: answers only a known device key (default: on, because the address is public)"
        )
    );
    let gone = ck
        .listeners
        .iter()
        .find(|x| x.listener == "dot://192.168.1.2:853")
        .unwrap();
    assert_eq!(gone.change, "removed");
    let note = gone.note.clone().unwrap();
    assert!(
        note.contains("Listener access for dot://192.168.1.2:853 was set to off"),
        "{note}"
    );
    assert!(
        note.contains("dot://203.0.113.9:853 starts on its default (on)"),
        "{note}"
    );
    assert!(ck.warnings.iter().any(|w| w.contains("gated by default")));
    // A wildcard says why it is off or on.
    let v = with(vec![dot("0.0.0.0:853", &c, &k)]);
    let ck = run(&cfg, &v, GLOBAL6).unwrap();
    let w = ck
        .listeners
        .iter()
        .find(|x| x.listener == "dot://0.0.0.0:853")
        .unwrap();
    assert!(w.gate.as_deref().unwrap().contains("open to the allowed networks (default: off, because it binds every address and this host has no public IPv4 address"));
    // A kept listener keeps its explicit setting and is a `kept` line.
    let v = with(vec![dot("192.168.1.2:853", &c, &k)]);
    let ck = run(&cfg, &v, PRIVATE4).unwrap();
    let kept = ck
        .listeners
        .iter()
        .find(|x| x.listener == "dot://192.168.1.2:853")
        .unwrap();
    assert_eq!(kept.change, "kept");
    assert!(
        kept.gate
            .as_deref()
            .unwrap()
            .contains("set under Listener access")
    );
    // A changed certificate path is a `changed` line tried on a proof port.
    let (c2, k2) = pki.pair("g2", &["dns.example"]);
    let v = with(vec![dot("192.168.1.2:853", &c2, &k2)]);
    let ck = run(&cfg, &v, PRIVATE4).unwrap();
    let ch = ck
        .listeners
        .iter()
        .find(|x| x.listener == "dot://192.168.1.2:853")
        .unwrap();
    assert_eq!(ch.change, "changed");
    assert!(ch.note.as_deref().unwrap().contains("temporary port"));
}

// A specific address that replaces a wildcard on the same TCP port: the line says what the owner
// decided (closed for a few milliseconds, tried on a temporary port first).
#[test]
fn api_902_listen_overlap_with_a_wildcard_is_noted() {
    let pki = Pki::new();
    let (c, k) = pki.pair("o", &["dns.example"]);
    let mut cfg = Config::default();
    cfg.listen
        .extend(parse(&value(&[dot("0.0.0.0:853", &c, &k)])).unwrap());
    let ck = run(&cfg, &with(vec![dot("192.168.1.2:853", &c, &k)]), PRIVATE4).unwrap();
    let line = ck
        .listeners
        .iter()
        .find(|x| x.listener == "dot://192.168.1.2:853")
        .unwrap();
    let note = line.note.clone().unwrap();
    assert!(
        note.contains("overlaps dot://0.0.0.0:853") && note.contains("few milliseconds"),
        "{note}"
    );
}

// ---- the overlay order -----------------------------------------------------------------

// REQ: API-902 (design 4) — `listen` is overlaid before `listen-access`, whatever order the entries
// are stored in, so a kept listener keeps its explicit gate and a stale line is ignored.
#[test]
fn api_902_listen_overlay_order_is_listen_then_listen_access() {
    use super::appliers::overlay_with;
    use super::store::{EntryState, Stored};
    let pki = Pki::new();
    let (c, k) = pki.pair("ov", &["dns.example"]);
    let entry = |id: &str, v: Value| Stored {
        node: "pi-a".to_owned(),
        id: id.to_owned(),
        value: v,
        mode: String::new(),
        state: EntryState::Active,
        by: "alice".to_owned(),
        at: 1,
    };
    let listen = entry(
        "listen",
        value(&[
            l("udp", "192.168.1.2:53"),
            dot("192.168.1.2:853", &c, &k),
            dot("192.168.1.3:853", &c, &k),
        ]),
    );
    let access = entry(
        "listen-access",
        json!({"listeners": [
            {"proto": "dot", "addr": "192.168.1.2:853", "require_client_id": false},
            {"proto": "dot", "addr": "192.168.1.9:853", "require_client_id": true},
        ]}),
    );
    let own = Config::default();
    let defs = super::appliers::rows();
    // The access entry first, as a store could list it.
    for order in [
        vec![access.clone(), listen.clone()],
        vec![listen.clone(), access.clone()],
    ] {
        let mut cfg = Config::default();
        overlay_with(&mut cfg, &own, &order, None, &defs, "pi-a", false);
        assert_eq!(cfg.listen.len(), 3, "{order:?}");
        let by = |a: &str| cfg.listen.iter().find(|x| x.addr.to_string() == a).unwrap();
        assert_eq!(
            by("192.168.1.2:853").require_client_id,
            Some(false),
            "explicit gate kept"
        );
        assert_eq!(
            by("192.168.1.3:853").require_client_id,
            None,
            "a new one starts on its default"
        );
        assert_eq!(by("192.168.1.2:53").proto, ListenProto::Udp);
    }
    // A file that sets any [[listen]] locks the row: the overlay leaves the list alone.
    let mut own = Config::default();
    own.file_set = vec!["listen".to_owned()];
    let mut cfg = Config::default();
    overlay_with(&mut cfg, &own, &[listen], None, &defs, "pi-a", false);
    assert_eq!(cfg.listen.len(), 4, "the file's list stays");
}

// REQ: API-902 (T27.14c review) — the same warning is said once: UDP and TCP added on one address
// that is on no interface of this host, and two pairs that share a certificate.
#[test]
fn api_902_listen_warnings_are_not_repeated() {
    let cfg = Config::default();
    let v = with(vec![
        l("udp", "192.168.1.9:5300"),
        l("tcp", "192.168.1.9:5300"),
    ]);
    let c = run(&cfg, &v, PRIVATE4).unwrap();
    let n = c
        .warnings
        .iter()
        .filter(|w| w.contains("is on no interface"))
        .count();
    assert_eq!(n, 1, "{:?}", c.warnings);
    let mut seen = std::collections::HashSet::new();
    assert!(c.warnings.iter().all(|w| seen.insert(w.clone())));
}

// REQ: API-902, DNS-901 (T27.14c review) — a `listen-access` line outlives the listener it named; an
// address added again takes it, so the preview, the probe and the result judge the gate the reload
// will give it (a public DoT the admin once set off is not gated, and says so, and weakens).
#[test]
fn api_902_listen_readded_address_takes_the_stored_gate_line() {
    let pki = Pki::new();
    let (c, k) = pki.pair("a", &["dns.example"]);
    let cfg = Config::default();
    let v = with(vec![dot("203.0.113.5:853", &c, &k)]);
    // Without the stored line: gated by default, no weakening.
    let e = env(PRIVATE4);
    let plain = evaluate(&cfg, "pi-a", &v, &[], "", &e, None).unwrap();
    assert!(!plain.weakening);
    // With the stored line off: not gated, the red mark, the gate sentence says it was set.
    let stored = json!({"listeners": [
        {"proto": "dot", "addr": "203.0.113.5:853", "require_client_id": false}
    ]});
    let off = evaluate(&cfg, "pi-a", &v, &[], "", &e, Some(&stored)).unwrap();
    assert!(off.weakening, "{:?}", off.warnings);
    let line = off
        .listeners
        .iter()
        .find(|x| x.listener == "dot://203.0.113.5:853")
        .unwrap();
    assert!(
        line.gate
            .as_deref()
            .unwrap()
            .contains("set under Listener access"),
        "{:?}",
        line.gate
    );
    // A stored `on` line gates a LAN address that the default would leave open.
    let lan = with(vec![dot("192.168.1.2:853", &c, &k)]);
    let on = json!({"listeners": [
        {"proto": "dot", "addr": "192.168.1.2:853", "require_client_id": true}
    ]});
    let g = evaluate(&cfg, "pi-a", &lan, &[], "", &e, Some(&on)).unwrap();
    assert!(g.listeners.iter().any(|x| {
        x.gate
            .as_deref()
            .is_some_and(|s| s.contains("answers only a known device key"))
    }));
    // The listener the node runs keeps its own setting; the stored line is for new ones only.
    let parsed = merged_with(parse(&v).unwrap(), &[], Some(&stored));
    let dot_l = parsed.iter().find(|x| x.proto == ListenProto::Dot).unwrap();
    assert_eq!(dot_l.require_client_id, Some(false));
}

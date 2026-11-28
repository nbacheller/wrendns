// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904, CLD-919, DSC-908 (T36.10b step b5; ADR-1084 as amended 2026-11-27, ADR-1115) - the
//! `delegated` DNS-provider kind and the verification of its hand-made CNAME.
//!
//! The verification is tested against fake *authoritative* servers: real UDP (and TCP) sockets on
//! loopback that answer as a zone's own name servers would, found through a canned stand-in for the
//! configured upstreams. The node's own data is deliberately wrong or silent in these tests, so a
//! check that read it would give a different verdict.

#![allow(clippy::many_single_char_names)] // the tests' `h`, `s`, `v`, `p`, as the other API tests have

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, UdpSocket};
use wrendns_api::auth;
use wrendns_cluster::gate::Feature;
use wrendns_proto::{NameBuf, read_name, rtype};

use crate::authoritative::{Fut, Limits, Upstreams};
use crate::credential_tests::{harness, harness_in};
use crate::secrets_api_tests::{GATE, json_of, pair_features, req_from, token};

const CNAME_NAME: &str = "_acme-challenge.home.example.net";
const TARGET: &str = "home.acme-validation.example.org";

/// The two provider entries: the DNS host with no API, and the validation zone's provider.
const PROVIDERS: &str = r#"
[local]
device_domain = "example.net"

[[location]]
slug = "home"
networks = ["192.168.1.0/24"]

[[dns_provider]]
name = "godaddy-home"
kind = "delegated"
zone = "example.net"
delegated_to = "validation"

[[dns_provider]]
name = "validation"
kind = "cloudflare"
zone = "acme-validation.example.org"
credential_ref = "cf"
"#;

// ---------------------------------------------------------------------------------------------
// A DNS message builder for the fakes.

fn wire(n: &str) -> Vec<u8> {
    NameBuf::from_presentation(n).unwrap().as_wire().to_vec()
}

fn rr(owner: &str, rt: u16, rdata: &[u8]) -> Vec<u8> {
    let mut v = wire(owner);
    v.extend_from_slice(&rt.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&60u32.to_be_bytes());
    v.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    v.extend_from_slice(rdata);
    v
}

fn cname_rr(owner: &str, target: &str) -> Vec<u8> {
    rr(owner, rtype::CNAME, &wire(target))
}

#[allow(clippy::too_many_arguments)] // the header's fields, spelled out
fn message(
    id: u16,
    qname: &str,
    qtype: u16,
    aa: bool,
    tc: bool,
    rcode: u8,
    answers: &[Vec<u8>],
    additional: &[Vec<u8>],
) -> Vec<u8> {
    let mut flags = 0x8000u16 | u16::from(rcode);
    if aa {
        flags |= 0x0400;
    }
    if tc {
        flags |= 0x0200;
    }
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&flags.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&u16::try_from(answers.len()).unwrap().to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&u16::try_from(additional.len()).unwrap().to_be_bytes());
    m.extend_from_slice(&wire(qname));
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    for a in answers.iter().chain(additional) {
        m.extend_from_slice(a);
    }
    m
}

// ---------------------------------------------------------------------------------------------
// The fake authoritative server.

#[derive(Clone)]
enum Mode {
    /// Has the CNAME to this target, with authority.
    Cname(String),
    /// Authoritative, the name exists, no CNAME.
    Empty,
    /// Authoritative, no such name.
    NxDomain,
    /// Has the CNAME but without the AA flag (not serving the zone).
    NotAuth(String),
    /// Never answers.
    Silent,
    /// Truncated over UDP, the full answer over TCP.
    Truncated(String),
    /// Answers with another ID.
    WrongId(String),
    /// Answers with a CNAME to this target plus so many TXT strings that it passes the size bound.
    Big(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    qname: String,
    qtype: u16,
    rd: bool,
}

struct Fake {
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Fake {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn parse_query(q: &[u8]) -> Option<(u16, String, u16, bool)> {
    let id = u16::from_be_bytes([*q.first()?, *q.get(1)?]);
    let rd = q.get(2)? & 1 == 1;
    let mut n = NameBuf::default();
    let end = read_name(q, 12, &mut n).ok()?;
    let qt = u16::from_be_bytes([*q.get(end)?, *q.get(end + 1)?]);
    Some((id, n.display().to_string(), qt, rd))
}

fn answer_for(mode: &Mode, id: u16, qname: &str, qtype: u16, tcp: bool) -> Option<Vec<u8>> {
    let m = |aa, tc, rc, ans: &[Vec<u8>]| message(id, qname, qtype, aa, tc, rc, ans, &[]);
    Some(match mode {
        Mode::Cname(t) => m(true, false, 0, &[cname_rr(qname, t)]),
        Mode::Empty => m(true, false, 0, &[]),
        Mode::NxDomain => m(true, false, 3, &[]),
        Mode::NotAuth(t) => m(false, false, 0, &[cname_rr(qname, t)]),
        Mode::Silent => return None,
        Mode::Truncated(t) => {
            if tcp {
                m(true, false, 0, &[cname_rr(qname, t)])
            } else {
                m(true, true, 0, &[])
            }
        }
        Mode::WrongId(t) => message(
            id ^ 0x5555,
            qname,
            qtype,
            true,
            false,
            0,
            &[cname_rr(qname, t)],
            &[],
        ),
        Mode::Big(t) => {
            let mut ans = vec![cname_rr(qname, t)];
            for _ in 0..8 {
                let mut txt = Vec::new();
                for _ in 0..3 {
                    txt.push(255u8);
                    txt.extend(std::iter::repeat_n(b'x', 255));
                }
                ans.push(rr(qname, rtype::TXT, &txt));
            }
            m(true, false, 0, &ans)
        }
    })
}

/// Starts a fake authoritative server on `ip:port` (port 0 picks one) and returns it with the port.
async fn fake(ip: &str, port: u16, mode: Mode) -> (Fake, u16) {
    let sock = UdpSocket::bind((ip.parse::<IpAddr>().unwrap(), port))
        .await
        .unwrap();
    let port = sock.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let udp_mode = mode.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let Some((id, qname, qtype, rd)) = parse_query(&buf[..n]) else {
                continue;
            };
            log.lock().unwrap().push(Seen {
                qname: qname.clone(),
                qtype,
                rd,
            });
            if let Some(a) = answer_for(&udp_mode, id, &qname, qtype, false) {
                let _ = sock.send_to(&a, from).await;
            }
        }
    });
    if matches!(mode, Mode::Truncated(_)) {
        let l = TcpListener::bind((ip.parse::<IpAddr>().unwrap(), port))
            .await
            .unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let mode = mode.clone();
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    if let Some((id, qname, qtype, _)) = parse_query(&q)
                        && let Some(a) = answer_for(&mode, id, &qname, qtype, true)
                    {
                        let mut out = u16::try_from(a.len()).unwrap().to_be_bytes().to_vec();
                        out.extend_from_slice(&a);
                        let _ = s.write_all(&out).await;
                    }
                });
            }
        });
    }
    (Fake { seen }, port)
}

// ---------------------------------------------------------------------------------------------
// The canned stand-in for the configured upstreams.

struct Canned {
    zone: String,
    /// The zone's name servers and their addresses.
    ns: Vec<(String, IpAddr)>,
    /// Put the addresses in the answer as glue; otherwise they are asked for.
    glue: bool,
    /// Fail every question.
    down: bool,
    asked: Mutex<Vec<(String, u16)>>,
}

impl Canned {
    fn new(zone: &str, ns: &[(&str, &str)]) -> Arc<Self> {
        Arc::new(Self {
            zone: zone.to_owned(),
            ns: ns
                .iter()
                .map(|(n, a)| ((*n).to_owned(), a.parse().unwrap()))
                .collect(),
            glue: false,
            down: false,
            asked: Mutex::new(Vec::new()),
        })
    }

    fn asked(&self) -> Vec<(String, u16)> {
        self.asked.lock().unwrap().clone()
    }
}

fn addr_rr(owner: &str, a: IpAddr) -> Vec<u8> {
    match a {
        IpAddr::V4(v4) => rr(owner, rtype::A, &v4.octets()),
        IpAddr::V6(v6) => rr(owner, rtype::AAAA, &v6.octets()),
    }
}

impl Upstreams for Canned {
    fn ask<'a>(&'a self, name: &'a str, qtype: u16) -> Fut<'a, Result<Vec<u8>, String>> {
        Box::pin(async move {
            self.asked.lock().unwrap().push((name.to_owned(), qtype));
            if self.down {
                return Err("all upstreams failed".to_owned());
            }
            let m = |ans: &[Vec<u8>], extra: &[Vec<u8>]| {
                message(7, name, qtype, false, false, 0, ans, extra)
            };
            if qtype == rtype::NS && name == self.zone {
                let ans: Vec<Vec<u8>> = self
                    .ns
                    .iter()
                    .map(|(n, _)| rr(name, rtype::NS, &wire(n)))
                    .collect();
                let glue: Vec<Vec<u8>> = if self.glue {
                    self.ns.iter().map(|(n, a)| addr_rr(n, *a)).collect()
                } else {
                    Vec::new()
                };
                return Ok(m(&ans, &glue));
            }
            let want_v4 = qtype == rtype::A;
            let ans: Vec<Vec<u8>> = self
                .ns
                .iter()
                .filter(|(n, a)| n == name && a.is_ipv4() == want_v4)
                .map(|(n, a)| addr_rr(n, *a))
                .collect();
            Ok(m(&ans, &[]))
        })
    }
}

fn limits(port: u16) -> Limits {
    Limits {
        per_try: Duration::from_millis(300),
        tries: 2,
        total: Duration::from_secs(10),
        max_servers: 8,
        max_answer: 8 * 1024,
        port,
        allow_private: true,
    }
}

/// Plants the lookup a named entry's verification uses.
fn plant(name: &str, up: Arc<dyn Upstreams>, l: Limits) {
    let mut t = crate::dns_provider_ops::TEST_LOOKUP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    t.retain(|(n, _, _)| n != name);
    t.push((name.to_owned(), up, l));
}

async fn store_cf(h: &crate::credential_tests::Harness) {
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/secrets/cf",
            Some(&json!({"value": "planted-delegation-credential", "kind": "text"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// Two servers on 127.0.0.1 and 127.0.0.2 sharing a port.
async fn two(a: Mode, b: Mode) -> (Fake, Fake, u16) {
    let (fa, port) = fake("127.0.0.1", 0, a).await;
    let (fb, port2) = fake("127.0.0.2", port, b).await;
    assert_eq!(port, port2);
    (fa, fb, port)
}

async fn verify(h: &crate::credential_tests::Harness) -> (StatusCode, Value) {
    let (s, _, v) = h
        .call("POST", "/api/v1/dns-providers/godaddy-home/verify", None)
        .await;
    (s, v)
}

fn ns2(zone: &str) -> Arc<Canned> {
    Canned::new(
        zone,
        &[
            ("ns1.example.net", "127.0.0.1"),
            ("ns2.example.net", "127.0.0.2"),
        ],
    )
}

// ---------------------------------------------------------------------------------------------
// Tests.

/// Ends the process-wide start-up hold when a test ends, however it ends.
struct ClearHold;
impl Drop for ClearHold {
    fn drop(&mut self) {
        crate::upgrade_gate::HOLD.clear();
    }
}

/// REQ: CLD-904 (ADR-1115) - the check asks the zone's authoritative servers, found through the
/// upstreams, and not the node's own data: the node itself answers the CNAME locally here (so a
/// check that read its own data would pass), the authoritative servers are what decide, and the
/// upstreams are asked for the name servers only, never for the challenge name.
#[tokio::test]
async fn cld_904_delegation_verified_through_authoritative_not_local_data() {
    let _turn = GATE.lock().await;
    let (f1, f2, port) = two(Mode::Cname(TARGET.into()), Mode::Cname(TARGET.into())).await;
    let up = ns2("example.net");
    let local = format!(
        "{PROVIDERS}\n[[record]]\nname = \"{CNAME_NAME}\"\ntype = \"CNAME\"\nvalue = \"{TARGET}\"\n"
    );
    // The node's own pipeline answers the challenge name from local data.
    let pipe =
        crate::pipeline::tests_support::pipeline_from(&crate::credential_tests::config(&local));
    let own = crate::pipeline::tests_support::answer_bytes(&pipe, CNAME_NAME, "10.0.0.9").unwrap();
    assert!(
        String::from_utf8_lossy(&own).contains("acme-validation"),
        "the node answers the CNAME locally, so a check on its own data would pass"
    );
    let h = harness(&local);
    store_cf(&h).await;
    plant("godaddy-home", up.clone(), limits(port));

    let (s, v) = verify(&h).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], true, "{v}");
    let r = &v["records"][0];
    assert_eq!(r["location"], "home", "{v}");
    assert_eq!(r["name"], CNAME_NAME);
    assert_eq!(r["target"], TARGET);
    assert_eq!(r["verified"], true, "{v}");
    assert!(
        r["reason"]
            .as_str()
            .unwrap()
            .contains("All 2 authoritative name servers (ns1.example.net, ns2.example.net)"),
        "{v}"
    );
    // Both servers were asked the CNAME of the challenge name, without recursion; the upstreams
    // were asked for the zone's name servers and their addresses, never for the challenge name.
    for f in [&f1, &f2] {
        assert_eq!(
            f.seen(),
            vec![Seen {
                qname: CNAME_NAME.to_owned(),
                qtype: rtype::CNAME,
                rd: false
            }]
        );
    }
    let asked = up.asked();
    assert!(
        asked.contains(&("example.net".to_owned(), rtype::NS)),
        "{asked:?}"
    );
    assert!(
        asked.iter().all(|(n, _)| !n.starts_with("_acme-challenge")),
        "{asked:?}"
    );

    // The card shows the verdict, and the list has it too.
    let (s, _, list) = h
        .call("GET", "/api/v1/dns-providers/godaddy-home", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!(list["kind"], "delegated");
    assert_eq!(list["state"], "delegated");
    assert_eq!(list["delegation"]["validationProvider"], "validation");
    assert_eq!(
        list["delegation"]["validationZone"],
        "acme-validation.example.org"
    );
    assert_eq!(list["delegation"]["records"][0]["verified"], true, "{list}");
    assert!(list.get("credentialSecret").is_none());
    // The verification is audited; nothing is written at any DNS host (a delegated entry has no
    // provider at all).
    let audit = h.audit_text();
    assert!(
        audit.contains("dns_provider.verify godaddy-home"),
        "{audit}"
    );
    assert!(!audit.contains("planted-delegation-credential"));
    let failures = crate::dns_provider::delegation::failures_among(&h.src.config.load());
    assert_eq!(failures.len(), 0, "{failures:?}");
}

/// REQ: CLD-904 - the glue path: the addresses come with the NS answer and are not asked for.
#[tokio::test]
async fn cld_904_delegation_uses_glue_and_asks_every_address_once() {
    let _turn = GATE.lock().await;
    let (f1, f2, port) = two(Mode::Cname(TARGET.into()), Mode::Cname(TARGET.into())).await;
    let mut up = ns2("example.net");
    Arc::get_mut(&mut up).unwrap().glue = true;
    let h = harness(PROVIDERS);
    plant("godaddy-home", up.clone(), limits(port));
    let (s, v) = verify(&h).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(up.asked(), vec![("example.net".to_owned(), rtype::NS)]);
    assert_eq!(f1.seen().len() + f2.seen().len(), 2);
}

/// REQ: CLD-904 - the refusal and failure cases: each says why in words, none is a DNS answer, and
/// each is a degraded health reason (never severe) that clears when the record is right.
#[tokio::test]
async fn cld_904_delegation_not_verified_says_why_and_is_health_only() {
    let _turn = GATE.lock().await;
    let wrong = "elsewhere.example.org";
    // A name the node answers itself, through the harness node's own pipeline (the one whose
    // health and verdict store a failed check changes), before and after every failure.
    let node = "[[record]]
name = \"nas.example.net\"
type = \"A\"
value = \"10.0.0.10\"
";
    // (server 1, server 2, words the reason must contain)
    let cases: Vec<(Mode, Mode, &str)> = vec![
        (
            Mode::Cname(TARGET.into()),
            Mode::Empty,
            "1 of 2 authoritative name servers have the CNAME to home.acme-validation.example.org: ns2.example.net has no CNAME there",
        ),
        (
            Mode::Cname(TARGET.into()),
            Mode::NxDomain,
            "ns2.example.net does not know the name (NXDOMAIN)",
        ),
        (
            Mode::Cname(wrong.into()),
            Mode::Cname(TARGET.into()),
            "ns1.example.net has the CNAME pointing to elsewhere.example.org instead of home.acme-validation.example.org",
        ),
        (
            Mode::Cname(TARGET.into()),
            Mode::NotAuth(TARGET.into()),
            "ns2.example.net answered without authority",
        ),
        (
            Mode::Cname(TARGET.into()),
            Mode::Silent,
            "ns2.example.net could not be asked at 127.0.0.2",
        ),
        (
            Mode::Cname(TARGET.into()),
            Mode::WrongId(TARGET.into()),
            "the answer does not match the question",
        ),
        (
            Mode::Cname(TARGET.into()),
            Mode::Big(TARGET.into()),
            "larger than the 512 bytes this node reads",
        ),
    ];
    for (i, (a, b, want)) in cases.into_iter().enumerate() {
        let (_f1, _f2, port) = two(a, b).await;
        let h = harness(&format!(
            "{PROVIDERS}
{node}"
        ));
        crate::pipeline::tests_support::serve_config(&h.src.pipeline, &h.src.config.load());
        let before = crate::pipeline::tests_support::answer_bytes(
            &h.src.pipeline,
            "nas.example.net",
            "10.0.0.9",
        )
        .unwrap();
        assert!(
            String::from_utf8_lossy(&before).contains("nas"),
            "case {i}: the harness node serves the name"
        );
        let mut l = limits(port);
        if want.contains("512") {
            l.max_answer = 512;
        }
        plant("godaddy-home", ns2("example.net"), l);
        let (s, v) = verify(&h).await;
        assert_eq!(s, StatusCode::OK, "case {i}: {v}");
        assert_eq!(v["ok"], false, "case {i}: {v}");
        let r = &v["records"][0];
        assert_eq!(r["verified"], false, "case {i}: {v}");
        let reason = r["reason"].as_str().unwrap();
        assert!(reason.contains(want), "case {i}: {reason}");
        // Health: degraded, naming the entry, DNS answers unaffected.
        let failures = crate::dns_provider::delegation::failures_among(&h.src.config.load());
        assert_eq!(failures.len(), 1, "case {i}: {failures:?}");
        let reasons = crate::health::dns_delegation_reasons(&failures);
        assert_eq!(reasons[0].code, "dns_provider_delegation_unverified");
        assert_eq!(reasons[0].level, "degraded", "never severe");
        assert!(reasons[0].summary.contains("godaddy-home"));
        assert!(reasons[0].summary.contains("DNS answers are unaffected"));
        let (s, _, e) = h
            .call("GET", "/api/v1/dns-providers/godaddy-home", None)
            .await;
        assert_eq!(s, StatusCode::OK, "{e}");
        assert_eq!(e["delegation"]["records"][0]["verified"], false, "{e}");
        crate::dns_provider::delegation::record("godaddy-home", Vec::new());
        let during = crate::pipeline::tests_support::answer_bytes(
            &h.src.pipeline,
            "nas.example.net",
            "10.0.0.9",
        )
        .unwrap();
        assert_eq!(
            before, during,
            "case {i}: a failed check changed a DNS answer"
        );
    }
}

/// REQ: CLD-904 - a truncated UDP answer is asked again over TCP.
#[tokio::test]
async fn cld_904_delegation_follows_a_truncated_answer_over_tcp() {
    let _turn = GATE.lock().await;
    let (_f1, _f2, port) = two(
        Mode::Truncated(TARGET.into()),
        Mode::Truncated(TARGET.into()),
    )
    .await;
    let h = harness(PROVIDERS);
    plant("godaddy-home", ns2("example.net"), limits(port));
    let (s, v) = verify(&h).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], true, "{v}");
}

/// REQ: CLD-904 - when the upstreams cannot say, or the zone has no server this node may ask, the
/// check fails with that reason; and a name server at a private address is never asked.
#[tokio::test]
async fn cld_904_delegation_lookup_failures_are_reasons() {
    let _turn = GATE.lock().await;
    let h = harness(PROVIDERS);
    let mut down = ns2("example.net");
    Arc::get_mut(&mut down).unwrap().down = true;
    plant("godaddy-home", down, limits(53));
    let (s, v) = verify(&h).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        v["records"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("the upstreams could not say"),
        "{v}"
    );
    // The default bounds refuse a name server at loopback or a private address, so a hostile zone
    // cannot aim the node at its own network.
    let mut l = limits(53);
    l.allow_private = false;
    let (f1, _f2, _port) = two(Mode::Cname(TARGET.into()), Mode::Cname(TARGET.into())).await;
    plant("godaddy-home", ns2("example.net"), l);
    let (s, v) = verify(&h).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], false, "{v}");
    assert!(
        v["records"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("has a public address this node may ask"),
        "{v}"
    );
    assert!(f1.seen().is_empty(), "nothing was asked at loopback");
}

/// REQ: CLD-904 - with no location in the zone there is nothing to ask: the template is shown and
/// nothing is looked up.
#[tokio::test]
async fn cld_904_delegation_with_no_location_shows_the_template_and_asks_nothing() {
    let _turn = GATE.lock().await;
    let h = harness(
        "[[dns_provider]]\nname = \"godaddy-home\"\nkind = \"delegated\"\nzone = \"example.net\"\ndelegated_to = \"validation\"\n[[dns_provider]]\nname = \"validation\"\nkind = \"cloudflare\"\nzone = \"acme-validation.example.org\"\ncredential_ref = \"cf\"\n",
    );
    let up = ns2("example.net");
    plant("godaddy-home", up.clone(), limits(53));
    let (s, v) = verify(&h).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], false);
    assert_eq!(
        v["records"][0]["name"],
        "_acme-challenge.<slug>.example.net"
    );
    assert_eq!(
        v["records"][0]["target"],
        "<slug>.acme-validation.example.org"
    );
    assert!(
        v["note"]
            .as_str()
            .unwrap()
            .contains("No location uses this zone"),
        "{v}"
    );
    assert!(up.asked().is_empty(), "nothing was looked up");
}

/// REQ: CLD-904 - Test, Records and Adopt do not apply to a delegated entry (there is no account);
/// Verify is for delegated entries only.
#[tokio::test]
async fn cld_904_a_delegated_entry_has_no_account_to_test_and_only_it_verifies() {
    let h = harness(PROVIDERS);
    store_cf(&h).await;
    let (s, _, v) = h
        .call("POST", "/api/v1/dns-providers/godaddy-home/test", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], false);
    assert_eq!(v["supported"], false);
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("no account of its own"),
        "{v}"
    );
    let (s, _, v) = h
        .call("GET", "/api/v1/dns-providers/godaddy-home/records", None)
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, _, v) = h
        .call(
            "POST",
            "/api/v1/dns-providers/godaddy-home/records/adopt",
            Some(&json!({"name": CNAME_NAME, "recordType": "TXT"})),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    // A provider with an account has no CNAME to verify.
    let (s, _, v) = h
        .call("POST", "/api/v1/dns-providers/validation/verify", None)
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert!(
        v["detail"]
            .as_str()
            .unwrap()
            .contains("only a `delegated` provider"),
        "{v}"
    );
    let (s, _, _) = h
        .call("POST", "/api/v1/dns-providers/nope/verify", None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// REQ: CLD-904, AGT-004 - Verify is admin only: an operator and a viewer get 403, an agent token
/// whatever its owner's role and scopes gets 403 `agent_not_allowed`.
#[tokio::test]
async fn cld_904_only_an_admin_verifies_and_no_agent_does() {
    let h = harness(PROVIDERS);
    let every: Vec<&str> = auth::agent::SCOPES.iter().map(|(n, _)| *n).collect();
    let agent = token(&h, "bot-deleg", auth::Role::Admin, Some(&every.join(" ")));
    let op = token(&h, "olive-deleg", auth::Role::Operator, None);
    let viewer = token(&h, "vic-deleg", auth::Role::Viewer, None);
    for (who, bearer, status, code) in [
        ("operator", &op, StatusCode::FORBIDDEN, "forbidden"),
        ("viewer", &viewer, StatusCode::FORBIDDEN, "forbidden"),
        ("agent", &agent, StatusCode::FORBIDDEN, "agent_not_allowed"),
    ] {
        let (s, _, v) = json_of(
            &h,
            req_from(
                bearer,
                [127, 0, 0, 1],
                "POST",
                "/api/v1/dns-providers/godaddy-home/verify",
                None,
            ),
        )
        .await;
        assert_eq!((s, v["code"].clone()), (status, json!(code)), "{who}: {v}");
    }
    // Reads are open to any signed-in role: the viewer reads the card with the CNAME to create.
    let (s, _, v) = json_of(
        &h,
        req_from(
            &viewer,
            [127, 0, 0, 1],
            "GET",
            "/api/v1/dns-providers/godaddy-home",
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["delegation"]["records"][0]["name"], CNAME_NAME, "{v}");
    assert_eq!(v["delegation"]["records"][0]["target"], TARGET, "{v}");
}

/// REQ: CLD-904 - through the API: there is no `GoDaddy` kind; a delegated entry stores no credential
/// and names a provider that exists and holds another zone; the validation provider cannot be
/// removed while an entry delegates to it.
#[tokio::test]
async fn cld_904_there_is_no_godaddy_kind_and_a_delegated_entry_is_checked() {
    let h = harness("");
    store_cf(&h).await;
    let put = |name: &'static str, b: Value| {
        let h = &h;
        async move {
            h.call("PUT", &format!("/api/v1/dns-providers/{name}"), Some(&b))
                .await
        }
    };
    let (s, _, v) = put("g", json!({"kind": "godaddy", "zone": "example.net"})).await;
    assert!(
        s == StatusCode::UNPROCESSABLE_ENTITY || s == StatusCode::BAD_REQUEST,
        "{s} {v}"
    );
    assert!(v.to_string().contains("godaddy"), "{v}");
    // Delegating to a provider that is not there, with a credential, and to itself.
    let (s, _, v) = put(
        "g",
        json!({"kind": "delegated", "zone": "example.net", "delegated_to": "validation"}),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v.to_string().contains("delegated_to"), "{v}");
    let (s, _, v) = put("validation", json!({"kind": "cloudflare", "zone": "acme-validation.example.org", "credential_ref": "cf"})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = put(
        "g",
        json!({"kind": "delegated", "zone": "example.net", "delegated_to": "validation", "credential_ref": "cf"}),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v.to_string().contains("credential_ref"), "{v}");
    let (s, _, v) = put(
        "g",
        json!({"kind": "delegated", "zone": "example.net", "delegated_to": "validation"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The other kinds take no `delegated_to`.
    let (s, _, v) = put(
        "cf2",
        json!({"kind": "cloudflare", "zone": "example.org", "credential_ref": "cf", "delegated_to": "validation"}),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    // The validation provider is in use.
    let (s, _, v) = h
        .call("DELETE", "/api/v1/dns-providers/validation", None)
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v.to_string().contains("delegated_to"), "{v}");
    assert!(
        h.src
            .config
            .load()
            .dns_provider
            .iter()
            .any(|p| p.name.as_str() == "validation")
    );
    // The entry reads as delegated, with no credential and the template to create.
    let (s, _, e) = h.call("GET", "/api/v1/dns-providers/g", None).await;
    assert_eq!(s, StatusCode::OK, "{e}");
    assert_eq!(e["state"], "delegated");
    assert_eq!(e["credentialPresent"], false);
    assert_eq!(
        e["delegation"]["records"][0]["name"],
        "_acme-challenge.<slug>.example.net"
    );
    assert!(e["delegation"]["records"][0].get("verified").is_none());
}

/// REQ: DSC-908, CLD-904 (ADR-1115) - the compatibility gate: every member knows the table, but a
/// member that does not announce `dns_provider_delegation` would refuse the whole section on a
/// `kind = "delegated"` it cannot read, so the first delegated entry waits for it (API, dry runs
/// too, and the file loader), while a provider with an account is not held and removing a
/// delegated entry never is.
#[tokio::test]
async fn dsc_908_a_delegated_provider_waits_for_every_members_build() {
    let _turn = GATE.lock().await;
    let without: Vec<String> = Feature::ALL
        .iter()
        .filter(|f| **f != Feature::DnsProviderDelegation)
        .map(|f| f.name().to_owned())
        .collect();
    let old = pair_features("1.1.0", "1.1.0-edge.50", Some(without)).await;
    let ph = harness_in("", Some(Arc::clone(&old.primary)));
    crate::http::serve_peers(&ph.src);
    store_cf(&ph).await;
    // A provider with an account goes through: the member knows the table.
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/dns-providers/validation",
            Some(&json!({"kind": "cloudflare", "zone": "acme-validation.example.org", "credential_ref": "cf"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let body = json!({"kind": "delegated", "zone": "example.net", "delegated_to": "validation"});
    for dry in ["?dryRun=true", ""] {
        let (s, _, v) = ph
            .call("PUT", &format!("/api/v1/dns-providers/g{dry}"), Some(&body))
            .await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert_eq!(v["code"], "upgrade_required", "{v}");
        let d = v["detail"].as_str().unwrap();
        assert!(
            d.contains("version 1.1.0-edge.50")
                && d.contains("does not know delegated DNS providers"),
            "{v}"
        );
    }
    assert!(
        !ph.src
            .config
            .load()
            .dns_provider
            .iter()
            .any(|p| p.name.as_str() == "g"),
        "nothing was stored"
    );
    // The file loader's half.
    let none = crate::credential_tests::config("");
    let base = crate::credential_tests::config(
        "[[dns_provider]]\nname = \"validation\"\nkind = \"cloudflare\"\nzone = \"acme-validation.example.org\"\ncredential_ref = \"cf\"\n",
    );
    let with = crate::credential_tests::config(PROVIDERS);
    let why = crate::server::reload_gate(&ph.src, &base, &with).unwrap_err();
    assert!(
        why.contains("does not know delegated DNS providers"),
        "{why}"
    );
    assert!(
        crate::server::reload_gate(&ph.src, &with, &with).is_ok(),
        "unchanged: not held again"
    );
    assert!(
        crate::server::reload_gate(&ph.src, &with, &base).is_ok(),
        "removal is never held"
    );
    assert!(crate::upgrade_gate::enforce_dns_delegation(None, &none, &with).is_ok());
    assert!(crate::upgrade_gate::uses_dns_delegation(&with));
    assert!(!crate::upgrade_gate::uses_dns_delegation(&base));
    // A change to an existing delegated entry is judged too (it may be the first the old member sees
    // with a new field).
    let changed = crate::credential_tests::config(&PROVIDERS.replace(
        "zone = \"example.net\"\ndelegated_to",
        "zone = \"example.net\"\ndry_run = false\ndelegated_to",
    ));
    assert!(
        crate::upgrade_gate::enforce_dns_delegation(Some(&old.primary), &with, &changed).is_err()
    );
    let _ = old.stop.send(true);

    // Every member announces it: the same write goes through.
    let new = crate::secrets_api_tests::pair("1.1.0", "1.1.0").await;
    let ph = harness_in("", Some(Arc::clone(&new.primary)));
    crate::http::serve_peers(&ph.src);
    store_cf(&ph).await;
    for (n, b) in [
        (
            "validation",
            json!({"kind": "cloudflare", "zone": "acme-validation.example.org", "credential_ref": "cf"}),
        ),
        ("g", body),
    ] {
        let (s, _, v) = ph
            .call("PUT", &format!("/api/v1/dns-providers/{n}"), Some(&b))
            .await;
        assert_eq!(s, StatusCode::OK, "{n}: {v}");
    }
    let _ = new.stop.send(true);
    crate::upgrade_gate::forget_held();
}

/// REQ: DSC-908, CLD-904 (ADR-1104 point 5, ADR-1115) - the start-up hold keeps only the delegated
/// entries out when the cluster already runs providers, serves and publishes the others, says why,
/// and a restart of a cluster that already published a delegated entry holds nothing.
#[tokio::test]
async fn dsc_908_the_start_up_hold_keeps_only_the_delegated_entries_out() {
    let _turn = GATE.lock().await;
    let _clear = ClearHold;
    let file = crate::credential_tests::config(PROVIDERS);
    assert_eq!(
        crate::upgrade_gate::features_used(&file),
        vec![
            Feature::Locations,
            Feature::DnsProviders,
            Feature::DnsProviderDelegation
        ]
    );
    let hold = crate::upgrade_gate::Hold::new();
    let mut c = file.clone();
    assert!(hold.at_start_for(&mut c, true, &[Feature::Locations, Feature::DnsProviders]));
    assert_eq!(c.dns_provider.len(), 1, "{:?}", c.dns_provider);
    assert_eq!(c.dns_provider[0].name.as_str(), "validation");
    assert_eq!(hold.held_features(), vec![Feature::DnsProviderDelegation]);
    let published = wrendns_config::shared::shared_part(&c);
    assert!(
        !published.to_string().contains("delegated"),
        "the held entry is not published: {published}"
    );
    hold.clear();
    // A restart of a cluster whose last published version carried a delegated entry holds nothing.
    let mut all = file.clone();
    assert!(!hold.at_start_for(&mut all, true, &crate::upgrade_gate::HOLDABLE));
    assert_eq!(all.dns_provider.len(), 2);
    // What the replication reads from a published version: a delegated entry is named, so a
    // restart of a cluster that already published one is not held for it.
    let published = serde_json::to_value(wrendns_config::shared::shared_part(&file)).unwrap();
    assert!(crate::replication::shared_uses_dns_delegation(&published));
    let plain = serde_json::to_value(wrendns_config::shared::shared_part(
        &crate::credential_tests::config(
            &PROVIDERS
                .replace(
                    "kind = \"delegated\"",
                    "kind = \"cloudflare\"\ncredential_ref = \"cf\"",
                )
                .replace("delegated_to = \"validation\"\n", ""),
        ),
    ))
    .unwrap();
    assert!(!crate::replication::shared_uses_dns_delegation(&plain));
}

/// REQ: CLD-904, DSC-908 - an entry that rides the existing `dns_providers` and ledger features
/// would be misread by an older member: the kind is the field that does not, so the gate announces
/// it under its own name, and a build announces it.
#[test]
fn dsc_908_the_delegation_feature_is_announced_under_its_own_name() {
    assert_eq!(
        Feature::DnsProviderDelegation.name(),
        "dns_provider_delegation"
    );
    assert!(wrendns_cluster::gate::own_features().contains(&"dns_provider_delegation".to_owned()));
    assert!(wrendns_cluster::gate::knows(
        &wrendns_cluster::gate::own_features(),
        Feature::DnsProviderDelegation
    ));
    assert!(!wrendns_cluster::gate::knows(
        &["dns_providers".to_owned(), "dns_provider_ledger".to_owned()],
        Feature::DnsProviderDelegation
    ));
}

/// A fake configured upstream on loopback: answers the zone's `NS` and the server's `A` with canned
/// data (the server at a loopback address) and records every question.
async fn fake_upstream() -> (Arc<Mutex<Vec<(String, u16)>>>, std::net::SocketAddr) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&asked);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let Some((id, qname, qtype, _)) = parse_query(&buf[..n]) else {
                continue;
            };
            log.lock().unwrap().push((qname.clone(), qtype));
            let ans: Vec<Vec<u8>> = match (qname.as_str(), qtype) {
                ("example.net", t) if t == rtype::NS => {
                    vec![rr(&qname, rtype::NS, &wire("ns1.example.net"))]
                }
                ("ns1.example.net", t) if t == rtype::A => {
                    vec![rr(&qname, rtype::A, &[127, 0, 0, 1])]
                }
                _ => Vec::new(),
            };
            let _ = sock
                .send_to(
                    &message(id, &qname, qtype, false, false, 0, &ans, &[]),
                    from,
                )
                .await;
        }
    });
    (asked, addr)
}

/// REQ: CLD-904 (ADR-1115 point 3) - the production path, with no test seam planted: the name
/// servers are found through the node's configured default upstream group (a fake upstream on
/// loopback is asked for the zone's `NS` and the server's address, and never for the challenge
/// name), and the node's own record for the challenge name is not what decides. The default bounds
/// refuse the loopback name server the upstream names, so the verdict is that refusal.
#[tokio::test]
async fn cld_904_delegation_production_path_asks_the_configured_upstream() {
    let _turn = GATE.lock().await;
    let (asked, addr) = fake_upstream().await;
    let entry = "godaddy-prod";
    let cfg = format!(
        "{}\n[[record]]\nname = \"{CNAME_NAME}\"\ntype = \"CNAME\"\nvalue = \"{TARGET}\"\n[[upstream]]\nname = \"u\"\nurl = \"udp://{addr}\"\n[[upstream_group]]\nname = \"default\"\nmembers = [\"u\"]\n",
        PROVIDERS.replace("godaddy-home", entry)
    );
    let h = crate::credential_tests::harness_toml(
        &cfg,
        None,
        vec![wrendns_config::Cidr::parse("127.0.0.0/8").unwrap()],
        auth::Settings::default(),
    );
    crate::pipeline::tests_support::serve_config(&h.src.pipeline, &h.src.config.load());
    let (s, _, v) = h
        .call(
            "POST",
            &format!("/api/v1/dns-providers/{entry}/verify"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], false, "{v}");
    assert!(
        v["records"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("has a public address this node may ask"),
        "the upstream's answer decided: {v}"
    );
    let asked = asked.lock().unwrap().clone();
    assert!(
        asked.contains(&("example.net".to_owned(), rtype::NS)),
        "{asked:?}"
    );
    assert!(
        asked.iter().all(|(n, _)| !n.starts_with("_acme-challenge")),
        "{asked:?}"
    );
    crate::dns_provider::delegation::record(entry, Vec::new());
}

/// REQ: CLD-904 - a node with no upstream group cannot find the name servers: 503, nothing asked.
#[tokio::test]
async fn cld_904_delegation_with_no_upstream_is_unavailable() {
    let _turn = GATE.lock().await;
    let entry = "godaddy-none";
    let h = harness(&PROVIDERS.replace("godaddy-home", entry));
    let (s, _, v) = h
        .call(
            "POST",
            &format!("/api/v1/dns-providers/{entry}/verify"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    assert!(
        v["detail"]
            .as_str()
            .unwrap()
            .contains("no upstream to find the name servers through"),
        "{v}"
    );
}

/// REQ: CLD-904 - the health sentence reads as a sentence whether or not the reason ends in a stop.
#[test]
fn cld_904_the_health_summary_has_its_own_full_stop() {
    for why in ["a: could not look the record up: x", "a: no CNAME there."] {
        let r = crate::health::dns_delegation_reasons(&[("g".to_owned(), why.to_owned())]);
        let sum = &r[0].summary;
        assert!(sum.contains(". DNS answers are unaffected"), "{sum}");
        assert!(!sum.contains(".."), "{sum}");
    }
}

/// REQ: DSC-908, CLD-904 (ADR-1115 point 7) - while the start-up hold keeps only the delegated
/// entries out, a write of another provider is judged on its own (it is not refused for the held
/// entries the served configuration lacks), and a new delegated entry is still refused.
#[tokio::test]
async fn dsc_908_a_provider_write_during_the_delegation_hold_is_not_refused() {
    let _turn = GATE.lock().await;
    let _clear = ClearHold;
    let without: Vec<String> = Feature::ALL
        .iter()
        .filter(|f| **f != Feature::DnsProviderDelegation)
        .map(|f| f.name().to_owned())
        .collect();
    let old = pair_features("1.1.0", "1.1.0-edge.50", Some(without)).await;
    let ph = harness_in("", Some(Arc::clone(&old.primary)));
    crate::http::serve_peers(&ph.src);
    store_cf(&ph).await;
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/dns-providers/validation",
            Some(&json!({"kind": "cloudflare", "zone": "acme-validation.example.org", "credential_ref": "cf"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // A delegated entry the cluster already published, stored as a node that led it would hold it.
    ph.src
        .auth
        .get()
        .unwrap()
        .state()
        .put_managed(
            "dns_provider",
            "g",
            r#"{"name":"g","kind":"delegated","zone":"example.net","delegated_to":"validation"}"#,
            None,
            None,
            crate::pipeline::unix_now(),
            "test",
        )
        .unwrap();
    let full = crate::managed::merge(
        &ph.src.file_config.load(),
        &crate::managed::entries(ph.src.auth.get().unwrap().state()),
    )
    .unwrap();
    assert!(full.dns_provider.iter().any(|p| p.name.as_str() == "g"));
    ph.src.unheld.store(Some(Arc::new(full.clone())));
    crate::upgrade_gate::HOLD.begin_with(&[Feature::DnsProviderDelegation]);
    let mut served = full;
    crate::upgrade_gate::HOLD.apply(&mut served);
    assert!(!served.dns_provider.iter().any(|p| p.name.as_str() == "g"));
    ph.src.config.store(Arc::new(served));

    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/dns-providers/other",
            Some(
                &json!({"kind": "cloudflare", "zone": "other.example.org", "credential_ref": "cf"}),
            ),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "an unrelated provider is not held: {v}");
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/dns-providers/g2",
            Some(
                &json!({"kind": "delegated", "zone": "example.org", "delegated_to": "validation"}),
            ),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "a new delegated entry waits: {v}");
    assert_eq!(v["code"], "upgrade_required", "{v}");
    let _ = old.stop.send(true);
}

/// REQ: DSC-908, CLD-904 - the replica's half of the gate: a current replica forwarding a
/// `delegated` PUT to a primary that announces every feature but `dns_provider_delegation` is
/// refused (409 `upgrade_required`) before anything is sent, while a forwarded cloudflare PUT to the
/// same primary goes through.
#[tokio::test(flavor = "multi_thread")]
async fn dsc_908_a_delegated_write_is_not_forwarded_to_a_primary_that_lacks_the_kind() {
    let _turn = GATE.lock().await;
    crate::upgrade_gate::forget_held();
    let without: Vec<String> = Feature::ALL
        .iter()
        .filter(|f| **f != Feature::DnsProviderDelegation)
        .map(|f| f.name().to_owned())
        .collect();
    let (replica, primary) =
        crate::credential_tests::older_primary_and_replica_features("1.1.0", Some(without), None)
            .await;
    let h = harness_in("", Some(replica));
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/dns-providers/g",
            Some(
                &json!({"kind": "delegated", "zone": "example.net", "delegated_to": "validation"}),
            ),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "upgrade_required", "{v}");
    assert!(
        v["detail"]
            .as_str()
            .unwrap()
            .contains("does not know delegated DNS providers"),
        "{v}"
    );
    assert_eq!(primary.got.lock().unwrap().len(), 0, "not forwarded");
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/dns-providers/validation",
            Some(&json!({"kind": "cloudflare", "zone": "acme-validation.example.org", "credential_ref": "cf"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(!primary.got.lock().unwrap().is_empty(), "forwarded");
    let _ = primary.stop.send(true);
    crate::upgrade_gate::forget_held();
}

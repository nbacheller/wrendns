//! REQ: DNS-012 — the iterative resolver against a small fake DNS tree on loopback addresses
//! (127.0.0.2 = root, .3 = com, .4 = example.com, .5 = other.net, .6 = outside.com, whose
//! server name is under example.com, .7 = a lame server), all on one port.

#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use wrendns_proto::{HEADER_LEN, NameBuf, rcode, read_name, rtype};
use wrendns_recursor::{Recursor, Settings};

/// A zone: its records, its delegations (child, server name, glue), and quirks.
#[derive(Clone, Default)]
#[allow(clippy::struct_excessive_bools)] // independent quirks
struct Zone {
    origin: &'static str,
    records: Vec<(&'static str, u16, Vec<u8>)>,
    cuts: Vec<(&'static str, &'static str, Option<[u8; 4]>)>,
    /// Answers in lowercase whatever case was asked (breaks 0x20).
    lowercase: bool,
    /// Adds a record for another zone's name to every answer (a poisoning attempt).
    poison: bool,
    /// Always refers back to the root (lame).
    lame: bool,
    /// Answers REFUSED to everything (an authoritative server asked outside its zones).
    refuse: bool,
    /// Answers SERVFAIL to everything (a server whose zone failed to load, or expired).
    servfail: bool,
    /// Before every answer, sends a forged one first: the question in lowercase and the
    /// address 6.6.6.6 (an off-path spoofer who guessed the ID and port, but not the case).
    spoof: bool,
    /// Answers NXDOMAIN (with AA and the SOA) for empty non-terminals: the quirk RFC 8020
    /// and RFC 9156 describe.
    ent_nxdomain: bool,
    /// Milliseconds to wait before answering (changeable while running).
    delay_ms: Option<Arc<AtomicU64>>,
    /// REQ: DNS-903 — answers FORMERR to any query that carries an EDNS OPT record.
    formerr_edns: bool,
    /// REQ: DNS-903 — while set, answers nothing at all (changeable while running).
    down: Option<Arc<AtomicBool>>,
    /// REQ: DNS-903 — while set, answers nothing over UDP (TCP still answers).
    drop_udp: Option<Arc<AtomicBool>>,
    /// REQ: DNS-903 — while set, answers nothing over UDP to names at or under this one (TCP
    /// still answers): one server that fails for one zone only.
    drop_udp_under: Option<(Arc<AtomicBool>, &'static str)>,
    /// REQ: DNS-903 — echoes an OPT record in answers to queries that carry one (a server
    /// that does EDNS).
    edns: bool,
    /// REQ: DNS-903 — while set, answers FORMERR to the next EDNS query only, then clears.
    formerr_once: Option<Arc<AtomicBool>>,
    /// REQ: DNS-903 — answers with this rcode (and the data of the zone) to every query.
    rcode_all: Option<u16>,
    /// REQ: DNS-903 — also listens on TCP.
    tcp: bool,
    /// REQ: DNS-903 — what this server has seen.
    seen: Option<Arc<Seen>>,
}

/// REQ: DNS-903 — what a fixture server saw: queries with and without an OPT record, by
/// transport, and the addresses they came from.
#[derive(Default)]
struct Seen {
    edns: AtomicU64,
    plain: AtomicU64,
    udp: AtomicU64,
    tcp: AtomicU64,
    from: Mutex<Vec<IpAddr>>,
}

impl Seen {
    fn note(&self, q: &[u8], tcp: bool, from: IpAddr) {
        let opt = u16::from_be_bytes([q[10], q[11]]) > 0;
        let c = if opt { &self.edns } else { &self.plain };
        c.fetch_add(1, Ordering::Relaxed);
        let t = if tcp { &self.tcp } else { &self.udp };
        t.fetch_add(1, Ordering::Relaxed);
        self.from.lock().unwrap().push(from);
    }
}

/// A FORMERR answer to `q`: its question only.
fn formerr(q: &[u8]) -> Vec<u8> {
    let mut end = HEADER_LEN;
    let mut n = NameBuf::default();
    if let Ok(e) = read_name(q, HEADER_LEN, &mut n) {
        end = e + 4;
    }
    let mut out = q[..2].to_vec();
    out.extend((0x8000u16 | rcode::FORMERR).to_be_bytes());
    out.extend(1u16.to_be_bytes());
    out.extend([0u8; 6]);
    out.extend(&q[HEADER_LEN..end]);
    out
}

fn wire(name: &str) -> Vec<u8> {
    NameBuf::from_presentation(name).unwrap().as_wire().to_vec()
}

fn rr(out: &mut Vec<u8>, name: &str, t: u16, ttl: u32, rdata: &[u8]) {
    out.extend(wire(name));
    out.extend(t.to_be_bytes());
    out.extend(1u16.to_be_bytes());
    out.extend(ttl.to_be_bytes());
    out.extend(u16::try_from(rdata.len()).unwrap().to_be_bytes());
    out.extend(rdata);
}

fn soa(origin: &str) -> Vec<u8> {
    let mut d = wire(&format!("ns.{origin}"));
    d.extend(wire(&format!("admin.{origin}")));
    for v in [1u32, 3600, 600, 86400, 60] {
        d.extend(v.to_be_bytes());
    }
    d
}

fn under(name: &str, zone: &str) -> bool {
    zone.is_empty() || name == zone || name.ends_with(&format!(".{zone}"))
}

/// The response of `z` to `query`.
fn respond(z: &Zone, query: &[u8]) -> Vec<u8> {
    let mut n = NameBuf::default();
    let end = read_name(query, HEADER_LEN, &mut n).unwrap();
    let qtype = u16::from_be_bytes([query[end], query[end + 1]]);
    let qname = n.display().to_string();
    let qname = qname.trim_end_matches('.').to_owned();
    let mut question = query[HEADER_LEN..end + 4].to_vec();
    if z.lowercase {
        question.make_ascii_lowercase();
    }
    let (mut an, mut ns, mut ad) = (Vec::new(), Vec::new(), Vec::new());
    let (mut na, mut nn, mut nd) = (0u16, 0u16, 0u16);
    let mut aa = true;
    let mut rc = rcode::NOERROR;
    if z.servfail {
        aa = false;
        rc = rcode::SERVFAIL;
    } else if z.refuse {
        aa = false;
        rc = rcode::REFUSED;
    } else if z.lame {
        aa = false;
        rr(&mut ns, "", rtype::NS, 3600, &wire("a.root-servers.net"));
        nn += 1;
    } else if let Some(child) = z
        .cuts
        .iter()
        .map(|c| c.0)
        .filter(|c| under(&qname, c) && !(qtype == rtype::DS && qname == *c))
        .max_by_key(|c| c.len())
    {
        aa = false;
        for (c, server, glue) in z.cuts.iter().filter(|x| x.0 == child) {
            rr(&mut ns, c, rtype::NS, 3600, &wire(server));
            nn += 1;
            if let Some(g) = glue {
                rr(&mut ad, server, rtype::A, 3600, g);
                nd += 1;
            }
        }
    } else {
        let at: Vec<&(&str, u16, Vec<u8>)> = z.records.iter().filter(|r| r.0 == qname).collect();
        if let Some(c) = at
            .iter()
            .find(|r| r.1 == rtype::CNAME && qtype != rtype::CNAME)
        {
            rr(&mut an, c.0, rtype::CNAME, 300, &c.2);
            na += 1;
        } else if at.iter().any(|r| r.1 == qtype) {
            for r in at.iter().filter(|r| r.1 == qtype) {
                rr(&mut an, r.0, r.1, 300, &r.2);
                na += 1;
                // Glue for NS answers, from this zone's own records.
                if qtype == rtype::NS {
                    let mut target = NameBuf::default();
                    read_name(&r.2, 0, &mut target).unwrap();
                    let t = target.display().to_string();
                    let t = t.trim_end_matches('.');
                    for g in z.records.iter().filter(|g| g.0 == t && g.1 == rtype::A) {
                        rr(&mut ad, g.0, g.1, 300, &g.2);
                        nd += 1;
                    }
                }
            }
            if z.poison {
                rr(&mut an, "www.victim.net", rtype::A, 300, &[6, 6, 6, 6]);
                na += 1;
            }
        } else if !at.is_empty()
            || (!z.ent_nxdomain
                && z.records
                    .iter()
                    .any(|r| r.0.ends_with(&format!(".{qname}"))))
        {
            rr(&mut ns, z.origin, rtype::SOA, 60, &soa(z.origin));
            nn += 1;
        } else {
            rc = rcode::NXDOMAIN;
            rr(&mut ns, z.origin, rtype::SOA, 60, &soa(z.origin));
            nn += 1;
        }
    }
    let mut out = Vec::new();
    out.extend(&query[..2]);
    let flags: u16 = 0x8000 | if aa { 0x0400 } else { 0 } | rc;
    out.extend(flags.to_be_bytes());
    out.extend(1u16.to_be_bytes());
    out.extend(na.to_be_bytes());
    out.extend(nn.to_be_bytes());
    out.extend(nd.to_be_bytes());
    out.extend(question);
    out.extend(an);
    out.extend(ns);
    out.extend(ad);
    out
}

type Log = Arc<Mutex<Vec<(u8, String)>>>;

/// REQ: DNS-903 — the TCP side of a fixture server (`Zone::tcp`).
async fn serve_tcp(ip: u8, port: u16, zone: Zone) {
    let listener = TcpListener::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, ip)),
        port,
    ))
    .await
    .unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, from)) = listener.accept().await else {
                return;
            };
            let z = zone.clone();
            tokio::spawn(async move {
                let mut lb = [0u8; 2];
                if conn.read_exact(&mut lb).await.is_err() {
                    return;
                }
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(lb))];
                if conn.read_exact(&mut query).await.is_err() || query.len() < HEADER_LEN {
                    return;
                }
                if let Some(s) = &z.seen {
                    s.note(&query, true, from.ip());
                }
                if z.down.as_ref().is_some_and(|d| d.load(Ordering::Relaxed)) {
                    return;
                }
                let reply = respond(&z, &query);
                let _ = conn
                    .write_all(&u16::try_from(reply.len()).unwrap().to_be_bytes())
                    .await;
                let _ = conn.write_all(&reply).await;
            });
        }
    });
}

async fn serve(ip: u8, port: u16, z: Zone, log: Log) {
    if z.tcp {
        serve_tcp(ip, port, z.clone()).await;
    }
    let s = UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, ip)),
        port,
    ))
    .await
    .unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, from)) = s.recv_from(&mut buf).await else {
                return;
            };
            let q = &buf[..n];
            if let Some(s) = &z.seen {
                s.note(q, false, from.ip());
            }
            let mut name = NameBuf::default();
            if let Ok(end) = read_name(q, HEADER_LEN, &mut name) {
                // Raw bytes, case as asked.
                let raw: String = q[HEADER_LEN..end]
                    .iter()
                    .map(|b| {
                        if b.is_ascii_graphic() {
                            char::from(*b)
                        } else {
                            '.'
                        }
                    })
                    .collect();
                log.lock().unwrap().push((ip, raw));
            }
            if let Some(d) = &z.delay_ms {
                let ms = d.load(Ordering::Relaxed);
                if ms > 0 {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                }
            }
            let dropped_name = z.drop_udp_under.as_ref().is_some_and(|(d, zone)| {
                let q = name.display().to_string().to_ascii_lowercase();
                d.load(Ordering::Relaxed) && under(q.trim_end_matches('.'), zone)
            });
            if dropped_name
                || z.down.as_ref().is_some_and(|d| d.load(Ordering::Relaxed))
                || z.drop_udp
                    .as_ref()
                    .is_some_and(|d| d.load(Ordering::Relaxed))
            {
                continue;
            }
            let has_opt = u16::from_be_bytes([q[10], q[11]]) > 0;
            if has_opt
                && z.formerr_once
                    .as_ref()
                    .is_some_and(|f| f.swap(false, Ordering::Relaxed))
            {
                let _ = s.send_to(&formerr(q), from).await;
                continue;
            }
            if z.formerr_edns && has_opt {
                let _ = s.send_to(&formerr(q), from).await;
                continue;
            }
            if z.spoof {
                let mut fake = z.clone();
                fake.lowercase = true;
                for r in &mut fake.records {
                    if r.1 == rtype::A {
                        r.2 = a([6, 6, 6, 6]);
                    }
                }
                let _ = s.send_to(&respond(&fake, q), from).await;
            }
            let mut reply = respond(&z, q);
            if let Some(rc) = z.rcode_all {
                reply[3] = (reply[3] & 0xf0) | u8::try_from(rc).unwrap();
            }
            if z.edns && has_opt {
                // An OPT record (root name, type 41, 1232 bytes), counted in ARCOUNT.
                reply.extend([0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
                let ar = u16::from_be_bytes([reply[10], reply[11]]) + 1;
                reply[10..12].copy_from_slice(&ar.to_be_bytes());
            }
            let _ = s.send_to(&reply, from).await;
        }
    });
}

fn a(ip: [u8; 4]) -> Vec<u8> {
    ip.to_vec()
}

/// Starts the tree; returns the resolver's settings and the query log.
async fn tree(mutate: impl FnOnce(&mut Vec<(u8, Zone)>)) -> (Settings, Log) {
    // A free port on 127.0.0.2, used on every address.
    let probe = std::net::UdpSocket::bind("127.0.0.2:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut zones = vec![
        (
            2,
            Zone {
                origin: "",
                cuts: vec![
                    ("com", "ns.com", Some([127, 0, 0, 3])),
                    ("net", "ns.com", Some([127, 0, 0, 3])),
                ],
                ..Zone::default()
            },
        ),
        (
            3,
            Zone {
                origin: "com",
                cuts: vec![
                    ("example.com", "ns1.example.com", Some([127, 0, 0, 4])),
                    ("other.net", "ns.other.net", Some([127, 0, 0, 5])),
                    // Out of bailiwick for com: no glue, so the resolver looks it up.
                    ("outside.com", "ns.outside-dns.example.com", None),
                    ("lame.com", "ns.lame.com", Some([127, 0, 0, 7])),
                ],
                ..Zone::default()
            },
        ),
        (
            4,
            Zone {
                origin: "example.com",
                records: vec![
                    ("www.example.com", rtype::A, a([10, 0, 0, 1])),
                    ("alias.example.com", rtype::CNAME, wire("www.other.net")),
                    ("ns.outside-dns.example.com", rtype::A, a([127, 0, 0, 6])),
                    ("deep.ent.example.com", rtype::A, a([10, 0, 0, 9])),
                ],
                ..Zone::default()
            },
        ),
        (
            5,
            Zone {
                origin: "other.net",
                records: vec![("www.other.net", rtype::A, a([10, 0, 0, 2]))],
                ..Zone::default()
            },
        ),
        (
            6,
            Zone {
                origin: "outside.com",
                records: vec![("www.outside.com", rtype::A, a([10, 0, 0, 3]))],
                ..Zone::default()
            },
        ),
        (
            7,
            Zone {
                origin: "lame.com",
                lame: true,
                ..Zone::default()
            },
        ),
    ];
    mutate(&mut zones);
    let log: Log = Arc::default();
    for (ip, z) in zones {
        serve(ip, port, z, Arc::clone(&log)).await;
    }
    let s = Settings {
        roots: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))],
        port,
        server_timeout: Duration::from_millis(300),
        // The query-log assertions count every query: priming has its own test.
        prime: false,
        // REQ: DNS-902 — the fixture's servers are all on loopback: the explicit allow that
        // the refusal tests turn off again.
        allow_local_servers: true,
        ..Settings::default()
    };
    (s, log)
}

fn name(s: &str) -> NameBuf {
    NameBuf::from_presentation(s).unwrap()
}

fn addrs(r: &wrendns_recursor::Resolved) -> Vec<IpAddr> {
    r.answer
        .iter()
        .filter_map(wrendns_recursor::msg::Rr::addr)
        .collect()
}

/// REQ: DNS-012 — referrals from the root down, with QNAME minimization: the root sees only
/// `com`, com sees only `example.com`; the delegation is cached for the next name.
#[tokio::test]
async fn dns_012_resolves_with_qname_minimization() {
    let (s, log) = tree(|_| {}).await;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(
        (res.rcode, addrs(&res)),
        (rcode::NOERROR, vec![IpAddr::from([10, 0, 0, 1])])
    );
    let seen = log.lock().unwrap().clone();
    let at = |ip: u8| {
        seen.iter()
            .filter(|(i, _)| *i == ip)
            .map(|(_, n)| n.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        at(2),
        vec![".com.".to_owned()],
        "the root saw only com: {seen:?}"
    );
    assert_eq!(
        at(3),
        vec![".example.com.".to_owned()],
        "com saw only example.com: {seen:?}"
    );
    // The next name under example.com goes straight to its server.
    log.lock().unwrap().clear();
    let res = r
        .resolve(name("deep.ent.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 9])]);
    assert!(
        log.lock().unwrap().iter().all(|(ip, _)| *ip == 4),
        "{:?}",
        log.lock().unwrap()
    );
}

/// REQ: DNS-012 — a CNAME into another zone is chased from that zone's servers; an
/// out-of-bailiwick server name is looked up; NXDOMAIN and NODATA carry the SOA.
#[tokio::test]
async fn dns_012_cnames_server_names_and_negative_answers() {
    let (s, _) = tree(|_| {}).await;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("alias.example.com"), rtype::A, false)
        .await
        .unwrap();
    let types: Vec<u16> = res.answer.iter().map(|x| x.rtype).collect();
    assert_eq!(types, vec![rtype::CNAME, rtype::A]);
    assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 2])]);
    let res = r
        .resolve(name("www.outside.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(
        addrs(&res),
        vec![IpAddr::from([10, 0, 0, 3])],
        "via ns.outside-dns.example.com"
    );
    let res = r
        .resolve(name("nope.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(res.rcode, rcode::NXDOMAIN);
    assert_eq!(
        res.authority.iter().map(|x| x.rtype).collect::<Vec<_>>(),
        vec![rtype::SOA]
    );
    let res = r
        .resolve(name("www.example.com"), rtype::AAAA, false)
        .await
        .unwrap();
    assert_eq!(
        (res.rcode, res.answer.len(), res.authority.len()),
        (rcode::NOERROR, 0, 1)
    );
}

/// REQ: DNS-012 — records for names outside the answering server's zone are dropped
/// (cache poisoning), and a lame delegation fails instead of looping.
#[tokio::test]
async fn dns_012_bailiwick_and_lame_servers() {
    let (s, _) = tree(|z| z[2].1.poison = true).await;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert!(
        res.answer.iter().all(|x| x.name == name("www.example.com")),
        "{:?}",
        res.answer
    );
    let t0 = std::time::Instant::now();
    assert!(
        r.resolve(name("www.lame.com"), rtype::A, false)
            .await
            .is_err()
    );
    assert!(t0.elapsed() < Duration::from_secs(3));
}

/// REQ: DNS-012 — 0x20: names go out in mixed case; a server that doesn't echo the case is
/// asked again plainly and still answers.
#[tokio::test]
async fn dns_012_case_randomization() {
    let (mut s, log) = tree(|z| z[2].1.lowercase = true).await;
    s.case_randomization = true;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 1])]);
    let seen = log.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|(_, n)| n.chars().any(|c| c.is_ascii_uppercase())),
        "some letters went out uppercase: {seen:?}"
    );
}

/// REQ: DNS-012 — 0x20 holds against a spoofed reply: an answer whose letter case differs
/// is not the server's word, so the resolver keeps waiting for one with the case intact
/// instead of asking again plainly (which would let a spoofer who guessed the ID and port
/// win on the retry).
#[tokio::test]
async fn dns_012_case_mismatch_does_not_drop_0x20() {
    let (mut s, log) = tree(|z| z[2].1.spoof = true).await;
    s.case_randomization = true;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(
        addrs(&res),
        vec![IpAddr::from([10, 0, 0, 1])],
        "the server's answer, not the spoofed one"
    );
    let seen = log.lock().unwrap().clone();
    assert_eq!(
        seen.iter().filter(|(ip, _)| *ip == 4).count(),
        1,
        "asked once, never again plainly: {seen:?}"
    );
}

/// REQ: DNS-012, UPS-012 — `answer` returns a full response for the client's query: its
/// ID and question, RA, the records.
#[tokio::test]
async fn dns_012_answer_message() {
    let (s, _) = tree(|_| {}).await;
    let r = Recursor::new(s);
    let mut q = [0u8; 512];
    let len = wrendns_proto::build_query(
        &mut q,
        0x1234,
        &name("www.example.com"),
        rtype::A,
        1,
        true,
        None,
    )
    .unwrap();
    let resp = r.answer(&q[..len]).await.unwrap();
    let h = wrendns_proto::Header::parse(&resp).unwrap();
    assert_eq!(
        (h.id, h.flags.qr(), h.flags.ra(), h.flags.rd(), h.ancount),
        (0x1234, true, true, true, 1)
    );
    let s = wrendns_proto::summarize(&resp).unwrap();
    assert_eq!((s.rcode, s.answers), (rcode::NOERROR, 1));
}

/// REQ: DNS-012 (T9.8) — RFC 8109: the hints are only asked for the root's NS set; its
/// answer (with glue) becomes the root servers from then on.
#[tokio::test]
async fn dns_012_root_priming() {
    let (mut s, log) = tree(|zones| {
        // The real root also answers its own NS set: a.root.com at 127.0.0.2, with glue.
        zones[0].1.records.push(("", rtype::NS, wire("a.root.com")));
        zones[0]
            .1
            .records
            .push(("a.root.com", rtype::A, a([127, 0, 0, 2])));
        // A stand-in "hint" root at .9 with the same data.
        let hint = zones[0].1.clone();
        zones.push((9, hint));
    })
    .await;
    s.roots = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9))];
    s.prime = true;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 1])]);
    let seen = log.lock().unwrap().clone();
    let hint: Vec<&String> = seen
        .iter()
        .filter(|(ip, _)| *ip == 9)
        .map(|(_, n)| n)
        .collect();
    assert_eq!(
        hint,
        vec!["."],
        "the hint saw only the priming query: {seen:?}"
    );
    assert!(
        seen.iter().any(|(ip, n)| *ip == 2 && n == ".com."),
        "{seen:?}"
    );
}

/// REQ: DNS-012 (T9.8) — a server slower than usual is hedged: the next one answers first.
#[tokio::test]
async fn dns_012_hedged_queries() {
    let slow = Arc::new(AtomicU64::new(0));
    // 20 ms, not 5: on a busy CI runner a few ms of scheduling noise made the copy look as fast
    // as .4, so the "slow" lookup went to the copy first and never waited (arm, 2026-10-08/09).
    let other = Arc::new(AtomicU64::new(20));
    let (slow2, other2) = (Arc::clone(&slow), Arc::clone(&other));
    let (s, log) = tree(move |zones| {
        // example.com has two servers: .4 (made slow later) and .10, a copy.
        let com = &mut zones[1].1;
        com.cuts
            .push(("example.com", "ns2.example.com", Some([127, 0, 0, 10])));
        let mut copy = zones[2].1.clone();
        copy.delay_ms = Some(other2);
        zones[2].1.delay_ms = Some(slow2);
        zones.push((10, copy));
    })
    .await;
    let mut s = s;
    s.server_timeout = Duration::from_millis(1200);
    // One slow lookup with a fresh recursor: how long it took, and whether .4, the slow one, was
    // asked first (the only run that says anything about hedging).
    let measure = |hedge: bool| {
        let (s, slow, log) = (s.clone(), Arc::clone(&slow), Arc::clone(&log));
        async move {
            // The fake server answers one query at a time: let a slow one finish first.
            tokio::time::sleep(Duration::from_millis(800)).await;
            slow.store(0, Ordering::Relaxed);
            let mut st = s;
            st.hedge = hedge;
            let r = Recursor::new(st);
            // .4 answers at once, .10 after 20 ms, so .4 is tried first.
            for _ in 0..4 {
                r.resolve(name("www.example.com"), rtype::A, false)
                    .await
                    .unwrap();
                r.resolve(name("deep.ent.example.com"), rtype::A, false)
                    .await
                    .unwrap();
            }
            slow.store(700, Ordering::Relaxed);
            let mark = log.lock().unwrap().len();
            let t0 = std::time::Instant::now();
            let res = r
                .resolve(name("www.example.com"), rtype::A, false)
                .await
                .unwrap();
            let took = t0.elapsed();
            assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 1])]);
            let first = log.lock().unwrap()[mark..]
                .iter()
                .find(|(ip, _)| *ip == 4 || *ip == 10)
                .map(|(ip, _)| *ip);
            (took, first == Some(4))
        }
    };
    // A server the recursor has never asked sorts as a small random RTT, so each gets tried: now
    // and then (more on a busy runner, where .4's own RTT is a few ms) the copy sorts ahead of .4
    // at the last lookup and nothing waits for the slow server (arm, 2026-11: "not hedged:
    // 21ms"). That run says nothing about hedging, so it is measured again.
    let slow_first = |hedge: bool| {
        let measure = &measure;
        async move {
            for _ in 0..10 {
                let (took, asked_slow_first) = measure(hedge).await;
                if asked_slow_first {
                    return took;
                }
            }
            panic!("the slow server was never asked first in 10 tries");
        }
    };
    // The hedge goes after 150 ms (answered ~20 ms later); without it, the slow server's
    // attempt times out at its 250 ms floor before the copy is asked. The best of three runs each, so a busy machine (the whole suite runs in
    // parallel) doesn't decide.
    let (mut hedged, mut plain) = (Duration::MAX, Duration::MAX);
    for _ in 0..3 {
        hedged = hedged.min(slow_first(true).await);
        plain = plain.min(slow_first(false).await);
    }
    assert!(plain >= Duration::from_millis(240), "not hedged: {plain:?}");
    assert!(
        hedged + Duration::from_millis(60) < plain,
        "hedged {hedged:?} vs not hedged {plain:?}"
    );
}

/// The internal view of `corp.example.com` on .8 (the public example.com server, .4, knows
/// nothing of it), delegating `sub.corp.example.com` to .9.
fn corp(z: &mut Vec<(u8, Zone)>) {
    z.push((
        8,
        Zone {
            origin: "corp.example.com",
            records: vec![
                ("www.corp.example.com", rtype::A, a([10, 1, 0, 1])),
                (
                    "alias.corp.example.com",
                    rtype::CNAME,
                    wire("www.other.net"),
                ),
            ],
            cuts: vec![(
                "sub.corp.example.com",
                "ns.sub.corp.example.com",
                Some([127, 0, 0, 9]),
            )],
            ..Zone::default()
        },
    ));
    z.push((
        9,
        Zone {
            origin: "sub.corp.example.com",
            records: vec![("host.sub.corp.example.com", rtype::A, a([10, 1, 1, 1]))],
            ..Zone::default()
        },
    ));
}

fn corp_stub() -> Vec<wrendns_recursor::Stub> {
    vec![wrendns_recursor::Stub {
        zone: name("corp.example.com"),
        servers: vec![IpAddr::from([127, 0, 0, 8])],
    }]
}

/// REQ: DNS-022 — a stub zone starts at its own servers and follows the delegations they
/// give, even with the public example.com cut cached: neither the root nor the public
/// server sees its names, and its NXDOMAIN is the internal view's.
#[tokio::test]
async fn dns_022_stub_zone_follows_its_own_delegations() {
    let (mut s, log) = tree(corp).await;
    s.stubs = corp_stub();
    // The whole fixture tree is on loopback: this test is about the stub, not the scope.
    s.scope_local_to_stubs = false;
    let r = Recursor::new(s);
    assert_eq!(r.stub_zone(), Some(&name("corp.example.com")));
    r.resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    log.lock().unwrap().clear();
    for (n, want) in [
        ("www.corp.example.com", [10, 1, 0, 1]),
        ("host.sub.corp.example.com", [10, 1, 1, 1]),
    ] {
        let res = r.resolve(name(n), rtype::A, false).await.unwrap();
        assert_eq!(addrs(&res), vec![IpAddr::from(want)], "{n}");
    }
    let res = r
        .resolve(name("nope.corp.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(res.rcode, rcode::NXDOMAIN);
    let seen = log.lock().unwrap().clone();
    assert!(
        seen.iter().all(|(ip, _)| *ip == 8 || *ip == 9),
        "only the stub's servers: {seen:?}"
    );
    assert!(
        seen.iter().any(|(ip, _)| *ip == 9),
        "the delegation was followed: {seen:?}"
    );
}

/// REQ: DNS-022 — a stub zone's names don't prime the root, and a CNAME out of the zone is
/// chased from the root like any other name.
#[tokio::test]
async fn dns_022_stub_zone_cname_leaves_the_zone() {
    let (mut s, log) = tree(corp).await;
    s.stubs = corp_stub();
    // The whole fixture tree is on loopback: this test is about the stub, not the scope.
    s.scope_local_to_stubs = false;
    s.prime = true;
    let r = Recursor::new(s);
    r.resolve(name("www.corp.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert!(
        log.lock().unwrap().iter().all(|(ip, _)| *ip == 8),
        "no priming for a stub name: {:?}",
        log.lock().unwrap()
    );
    let res = r
        .resolve(name("alias.corp.example.com"), rtype::A, false)
        .await
        .unwrap();
    let types: Vec<u16> = res.answer.iter().map(|x| x.rtype).collect();
    assert_eq!(types, vec![rtype::CNAME, rtype::A]);
    assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 2])]);
    let seen = log.lock().unwrap().clone();
    assert!(
        seen.iter()
            .all(|(ip, n)| *ip == 8 || !n.to_ascii_lowercase().contains("corp")),
        "the zone's names stayed with its servers: {seen:?}"
    );
}

/// REQ: DNS-902 — the local-address allowance of a stub zone covers that zone only: its own
/// server (and what it delegates) is asked, but a CNAME out of the zone to a name whose zone
/// delegates to loopback is refused, with nothing sent there.
#[tokio::test]
async fn dns_902_local_allowance_stays_inside_the_stub_zone() {
    let (mut s, log) = tree(corp).await;
    s.stubs = corp_stub();
    assert!(s.scope_local_to_stubs, "the default");
    let r = Recursor::new(s);
    let own = r
        .resolve(name("host.sub.corp.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(addrs(&own), vec![IpAddr::from([10, 1, 1, 1])]);
    assert!(log.lock().unwrap().iter().any(|(ip, _)| *ip == 8));
    log.lock().unwrap().clear();
    // alias.corp.example.com -> www.other.net: com and other.net delegate to loopback.
    let out = r
        .resolve(name("alias.corp.example.com"), rtype::A, false)
        .await;
    assert!(
        out.as_ref().map_or(true, |x| addrs(x).is_empty()),
        "the out-of-zone target is not resolved: {out:?}"
    );
    assert!(
        log.lock()
            .unwrap()
            .iter()
            .all(|(ip, _)| *ip == 8 || *ip == 2),
        "nothing outside the stub's servers (and the root hint) was asked: {:?}",
        log.lock().unwrap()
    );
}

/// REQ: UPS-006, DNS-022 — a stub's health probe: a server that refuses the zone's apex is up
/// (it answered), one that never answers is down, and without a stub there's nothing to probe.
#[tokio::test]
async fn dns_022_stub_probe_counts_any_answer() {
    let (mut s, _) = tree(|z| {
        z.push((
            11,
            Zone {
                origin: "corp.example.com",
                refuse: true,
                ..Zone::default()
            },
        ));
    })
    .await;
    s.stubs = vec![wrendns_recursor::Stub {
        zone: name("corp.example.com"),
        servers: vec![IpAddr::from([127, 0, 0, 11])],
    }];
    assert_eq!(Recursor::new(s.clone()).probe_stub().await, Some(true));
    // Nothing listens on .12.
    s.stubs[0].servers = vec![IpAddr::from([127, 0, 0, 12])];
    assert_eq!(Recursor::new(s.clone()).probe_stub().await, Some(false));
    s.stubs.clear();
    assert_eq!(Recursor::new(s).probe_stub().await, None);
}

/// REQ: UPS-006, DNS-022 — a stub server that answers SERVFAIL for its own zone is failing (the
/// zone didn't load, or it expired), so unlike a refusal it doesn't make the stub up; a second
/// server that does answer does.
#[tokio::test]
async fn dns_022_stub_probe_servfail_is_down() {
    let (mut s, _) = tree(|z| {
        z.push((
            11,
            Zone {
                origin: "corp.example.com",
                servfail: true,
                ..Zone::default()
            },
        ));
        z.push((
            13,
            Zone {
                origin: "corp.example.com",
                refuse: true,
                ..Zone::default()
            },
        ));
    })
    .await;
    s.stubs = vec![wrendns_recursor::Stub {
        zone: name("corp.example.com"),
        servers: vec![IpAddr::from([127, 0, 0, 11])],
    }];
    assert_eq!(Recursor::new(s.clone()).probe_stub().await, Some(false));
    s.stubs[0].servers = vec![IpAddr::from([127, 0, 0, 11]), IpAddr::from([127, 0, 0, 13])];
    assert_eq!(Recursor::new(s).probe_stub().await, Some(true));
}

/// REQ: DNS-902 — the default refuses loopback servers: a delegation to 127.0.0.1 gets no
/// query and the lookup fails as refused (it becomes SERVFAIL with an EDE upstream); with
/// the explicit allow, the same fixture resolves.
#[tokio::test]
async fn dns_902_loopback_delegation_is_not_queried() {
    let fixture = |z: &mut Vec<(u8, Zone)>| {
        z[0].1.cuts.push(("loop", "ns.loop", Some([127, 0, 0, 1])));
        z.push((
            1,
            Zone {
                origin: "loop",
                records: vec![("www.loop", rtype::A, a([10, 0, 0, 7]))],
                ..Zone::default()
            },
        ));
    };
    let (mut s, log) = tree(fixture).await;
    s.allow_local_servers = false; // the default; the root hints stay asked
    let r = Recursor::new(s);
    let e = r
        .resolve(name("www.loop"), rtype::A, false)
        .await
        .unwrap_err();
    assert!(matches!(e, wrendns_recursor::Error::Refused(_)), "{e:?}");
    assert!(
        log.lock().unwrap().iter().all(|(ip, _)| *ip != 1),
        "nothing was sent to 127.0.0.1: {:?}",
        log.lock().unwrap()
    );
    let (s, log) = tree(fixture).await;
    let res = Recursor::new(s)
        .resolve(name("www.loop"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(
        addrs(&res),
        vec![IpAddr::from([10, 0, 0, 7])],
        "{res:?} {:?}",
        log.lock().unwrap()
    );
    assert!(log.lock().unwrap().iter().any(|(ip, _)| *ip == 1));
}

/// REQ: DNS-902 — which addresses count as local and private.
#[test]
fn dns_902_address_classes() {
    use wrendns_recursor::{is_local_address, is_private_address};
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    for local in [
        "127.0.0.1",
        "127.8.8.8",
        "::1",
        "0.0.0.0",
        "::",
        "169.254.1.1",
        "fe80::1",
        "224.0.0.1",
        "ff02::1",
        "255.255.255.255",
        "::ffff:127.0.0.1",
    ] {
        assert!(is_local_address(ip(local)), "{local}");
    }
    for private in [
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "fd00::1",
        "::ffff:10.0.0.1",
    ] {
        assert!(is_private_address(ip(private)), "{private}");
        assert!(!is_local_address(ip(private)), "{private}");
    }
    for public in [
        "198.41.0.4",
        "8.8.8.8",
        "100.128.0.1",
        "2001:503:ba3e::2:30",
    ] {
        assert!(
            !is_local_address(ip(public)) && !is_private_address(ip(public)),
            "{public}"
        );
    }
}

/// REQ: DNS-902 — a lame answer counts against the server, however fast it came: with a
/// quick lame server and a good one for the same zone, the good one is asked first.
#[tokio::test]
async fn dns_902_a_fast_lame_server_stops_coming_first() {
    let (mut s, log) = tree(|z| {
        z[2].1.refuse = true; // .4 answers REFUSED at once
        z[1].1
            .cuts
            .push(("example.com", "ns2.example.com", Some([127, 0, 0, 10])));
        z.push((
            10,
            Zone {
                origin: "example.com",
                records: vec![("www.example.com", rtype::A, a([10, 0, 0, 1]))],
                ..Zone::default()
            },
        ));
    })
    .await;
    s.hedge = false;
    let r = Recursor::new(s);
    // Until the lame server has been asked once (the order of unknown servers is random).
    let mut seen_lame = false;
    for _ in 0..30 {
        let res = r
            .resolve(name("www.example.com"), rtype::A, false)
            .await
            .unwrap();
        assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 1])]);
        if log.lock().unwrap().iter().any(|(ip, _)| *ip == 4) {
            seen_lame = true;
            break;
        }
    }
    assert!(seen_lame, "the lame server was never asked");
    log.lock().unwrap().clear();
    for _ in 0..3 {
        r.resolve(name("www.example.com"), rtype::A, false)
            .await
            .unwrap();
    }
    let seen = log.lock().unwrap().clone();
    assert!(
        seen.iter().all(|(ip, _)| *ip == 10),
        "the good server answered every time and the lame one was not asked: {seen:?}"
    );
}

/// REQ: DNS-902, DNS-012 (ADR-074) — an unsigned NXDOMAIN with AA and SOA for an empty
/// non-terminal does not end the walk: the full name is asked and resolves.
#[tokio::test]
async fn dns_902_unsigned_nxdomain_for_an_empty_non_terminal_still_resolves() {
    let (s, log) = tree(|z| z[2].1.ent_nxdomain = true).await;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("deep.ent.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(
        (res.rcode, addrs(&res)),
        (rcode::NOERROR, vec![IpAddr::from([10, 0, 0, 9])])
    );
    let seen = log.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|(ip, n)| *ip == 4 && n == ".deep.ent.example.com."),
        "the full name was asked: {seen:?}"
    );
}

/// REQ: DNS-905 (T40.4) — flushing the zone cuts makes the next lookup start from the root
/// again; flushing only the round-trip times leaves the cuts in place.
#[tokio::test]
async fn dns_905_flushing_cuts_restarts_from_the_root() {
    let (s, log) = tree(|_| {}).await;
    let r = Recursor::new(s);
    r.resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert!(r.cached_zones() > 0);
    // Round-trip times only: the cuts stay, so the root isn't asked.
    assert!(r.flush(false, true) > 0);
    log.lock().unwrap().clear();
    r.resolve(name("deep.ent.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert!(
        log.lock().unwrap().iter().all(|(ip, _)| *ip == 4),
        "{:?}",
        log.lock().unwrap()
    );
    // The cuts: the next lookup begins at the root.
    assert!(r.flush(true, false) > 0);
    assert_eq!(r.cached_zones(), 0);
    log.lock().unwrap().clear();
    r.resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    let roots = log
        .lock()
        .unwrap()
        .iter()
        .filter(|(ip, _)| *ip == 2)
        .count();
    assert_eq!(roots, 1, "{:?}", log.lock().unwrap());
}

/// What a test's example.com server shows: the fixture's `Seen`, counted from a mark.
fn count(c: &AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

/// REQ: DNS-903 — a server that timed out for a while and then recovers is asked again within
/// the lifetime of its entry (not after it) and comes back to first place.
#[tokio::test]
async fn dns_903_a_server_that_was_down_is_probed_and_returns_to_first_place() {
    let down = Arc::new(AtomicBool::new(false));
    // The sibling is slow enough that scheduling noise cannot put it ahead of a server that
    // answers at once (a stall of 150 ms or more would be needed).
    let slow = Arc::new(AtomicU64::new(150));
    let (down2, slow2) = (Arc::clone(&down), Arc::clone(&slow));
    let (mut s, log) = tree(move |zones| {
        zones[1]
            .1
            .cuts
            .push(("example.com", "ns2.example.com", Some([127, 0, 0, 10])));
        // .10 is a slower copy, so .4 is first while it is well.
        let mut copy = zones[2].1.clone();
        copy.delay_ms = Some(slow2);
        zones.push((10, copy));
        zones[2].1.down = Some(down2);
    })
    .await;
    s.hedge = false;
    s.infra_ttl = Duration::from_secs(30);
    s.infra_probe = Duration::from_secs(1);
    // So .10 (150 ms) never times out, and a probe of the silent .4 (which waits out this
    // timeout) ends before the next one is due: only .4 can be down.
    s.server_timeout = Duration::from_millis(600);
    let r = Recursor::new(s);
    let ask = || async {
        let res = r
            .resolve(name("www.example.com"), rtype::A, false)
            .await
            .unwrap();
        assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 1])]);
    };
    // Both are learned: .4 answers at once, .10 after 150 ms.
    for _ in 0..12 {
        ask().await;
    }
    // .4 stops answering: its lookups fall to .10, and it is marked down.
    down.store(true, Ordering::Relaxed);
    log.lock().unwrap().clear();
    let mut tried = 0;
    for _ in 0..20 {
        ask().await;
        tried = log
            .lock()
            .unwrap()
            .iter()
            .filter(|(ip, _)| *ip == 4)
            .count();
        if tried >= 2 {
            break;
        }
    }
    // The precondition: .4 was asked, did not answer, was asked again (so it is down), and
    // its last probe has only just gone (else the check below counts nothing, or a probe).
    assert!(
        tried >= 2,
        "the down server was asked and timed out: {tried}"
    );
    // While it is down and not due, it is not asked.
    log.lock().unwrap().clear();
    ask().await;
    ask().await;
    let seen = log.lock().unwrap().clone();
    assert!(
        seen.iter().filter(|(ip, _)| *ip == 4).count() <= 1,
        "a down server is probed, not asked every time: {seen:?}"
    );
    // It recovers; a probe within its lifetime finds that out.
    down.store(false, Ordering::Relaxed);
    // A bounded wait for the probe (due every second), well inside the lifetime of 30 s.
    let begun = Instant::now();
    let mut probed = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        log.lock().unwrap().clear();
        ask().await;
        if log.lock().unwrap().iter().any(|(ip, _)| *ip == 4) {
            probed = true;
            break;
        }
    }
    assert!(probed, "a probe reached the recovered server");
    assert!(begun.elapsed() < Duration::from_secs(20));
    log.lock().unwrap().clear();
    for _ in 0..3 {
        ask().await;
    }
    let seen = log.lock().unwrap().clone();
    assert!(
        seen.iter()
            .filter(|(ip, _)| *ip == 4 || *ip == 10)
            .all(|(ip, _)| *ip == 4),
        "the recovered server is first again and answers: {seen:?}"
    );
    assert!(seen.iter().any(|(ip, _)| *ip == 4), "{seen:?}");
}

/// REQ: DNS-903 — a server that answers FORMERR to any EDNS query and answers one without
/// resolves, and the next lookup sends it no EDNS query.
#[tokio::test]
async fn dns_903_formerr_to_edns_is_retried_plain_and_remembered() {
    let seen = Arc::new(Seen::default());
    let seen2 = Arc::clone(&seen);
    let (s, _log) = tree(move |zones| {
        zones[2].1.formerr_edns = true;
        zones[2].1.seen = Some(seen2);
    })
    .await;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 1])]);
    assert_eq!(
        count(&seen.edns),
        1,
        "one query with EDNS, which it refused"
    );
    assert!(count(&seen.plain) >= 1);
    let (edns, plain) = (count(&seen.edns), count(&seen.plain));
    let res = r
        .resolve(name("deep.ent.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 9])]);
    assert_eq!(count(&seen.edns), edns, "no EDNS query the second time");
    assert!(count(&seen.plain) > plain);
}

/// REQ: DNS-903 — a server that answered before and now drops UDP is asked over TCP after two
/// timeouts, and from then on TCP goes first.
#[tokio::test]
async fn dns_903_tcp_after_repeated_udp_timeouts() {
    let seen = Arc::new(Seen::default());
    let drop_udp = Arc::new(AtomicBool::new(false));
    let (seen2, drop2) = (Arc::clone(&seen), Arc::clone(&drop_udp));
    let (mut s, _log) = tree(move |zones| {
        zones[2].1.tcp = true;
        zones[2].1.seen = Some(seen2);
        zones[2].1.drop_udp = Some(drop2);
    })
    .await;
    s.hedge = false;
    let r = Recursor::new(s);
    r.resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(count(&seen.tcp), 0);
    drop_udp.store(true, Ordering::Relaxed);
    // The first timeouts fail the lookup; the second UDP timeout turns to TCP.
    let mut ok = false;
    for _ in 0..3 {
        if let Ok(res) = r.resolve(name("www.example.com"), rtype::A, false).await {
            assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 1])]);
            ok = true;
            break;
        }
    }
    assert!(ok, "never resolved");
    assert!(count(&seen.tcp) >= 1);
    // Now TCP goes first: no further UDP query.
    let udp = count(&seen.udp);
    r.resolve(name("deep.ent.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(count(&seen.udp), udp, "UDP was not tried again");
}

/// REQ: DNS-903 — the TCP note is kept per zone: one server that drops UDP for zone A is still
/// asked over UDP for zone B.
#[tokio::test]
async fn dns_903_one_zones_timeouts_do_not_move_another_zone_to_tcp() {
    let seen = Arc::new(Seen::default());
    let drop_a = Arc::new(AtomicBool::new(false));
    let (seen2, drop2) = (Arc::clone(&seen), Arc::clone(&drop_a));
    let (mut s, _log) = tree(move |zones| {
        zones[1]
            .1
            .cuts
            .push(("zoneb.com", "ns1.example.com", Some([127, 0, 0, 4])));
        let z = &mut zones[2].1;
        z.tcp = true;
        z.seen = Some(seen2);
        z.drop_udp_under = Some((drop2, "example.com"));
        z.records
            .push(("www.zoneb.com", rtype::A, a([10, 0, 0, 7])));
        z.records
            .push(("one.example.com", rtype::A, a([10, 0, 0, 1])));
        z.records
            .push(("two.example.com", rtype::A, a([10, 0, 0, 1])));
    })
    .await;
    s.hedge = false;
    let r = Recursor::new(s);
    // The server answers for both zones.
    r.resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    // Zone A goes silent over UDP: the second timeout turns that zone to TCP.
    drop_a.store(true, Ordering::Relaxed);
    let mut ok = false;
    for n in ["one.example.com", "two.example.com", "one.example.com"] {
        ok |= r.resolve(name(n), rtype::A, false).await.is_ok();
    }
    assert!(ok && count(&seen.tcp) >= 1, "zone A was moved to TCP");
    // Zone B on the same address is asked over UDP, as ever.
    let (tcp, udp) = (count(&seen.tcp), count(&seen.udp));
    let res = r
        .resolve(name("www.zoneb.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 7])]);
    assert_eq!(count(&seen.tcp), tcp, "zone B was not asked over TCP");
    assert!(count(&seen.udp) > udp, "zone B was asked over UDP");
}

/// REQ: DNS-903 — without an earlier answer a timeout is not a reason for TCP.
#[tokio::test]
async fn dns_903_no_tcp_for_a_server_that_never_answered() {
    let seen = Arc::new(Seen::default());
    let drop_udp = Arc::new(AtomicBool::new(true));
    let (seen2, drop2) = (Arc::clone(&seen), drop_udp);
    let (mut s, _log) = tree(move |zones| {
        zones[2].1.tcp = true;
        zones[2].1.seen = Some(seen2);
        zones[2].1.drop_udp = Some(drop2);
    })
    .await;
    s.hedge = false;
    let r = Recursor::new(s);
    for _ in 0..3 {
        assert!(
            r.resolve(name("www.example.com"), rtype::A, false)
                .await
                .is_err()
        );
    }
    assert_eq!(count(&seen.tcp), 0);
}

#[derive(Debug)]
struct Fixed(IpAddr);

impl wrendns_recursor::SourceAddr for Fixed {
    fn current(&self) -> std::io::Result<IpAddr> {
        Ok(self.0)
    }
    fn note(&self, _: Option<std::io::ErrorKind>) {}
}

/// REQ: DNS-903, UPS-013 — with a source address set, the servers see the queries from it
/// (over UDP and over TCP), and servers of the other IP version are not asked.
#[tokio::test]
async fn dns_903_queries_leave_from_the_source_address() {
    let seen = Arc::new(Seen::default());
    let seen2 = Arc::clone(&seen);
    let (mut s, log) = tree(move |zones| {
        zones[2].1.tcp = true;
        zones[2].1.seen = Some(seen2);
    })
    .await;
    let src: IpAddr = Ipv4Addr::new(127, 0, 0, 20).into();
    s.source = Some(Arc::new(Fixed(src)));
    let r = Recursor::new(s.clone());
    r.resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert!(count(&seen.udp) >= 1);
    assert!(seen.from.lock().unwrap().iter().all(|f| *f == src));
    // A source of the other family reaches none of the (IPv4) servers.
    s.source = Some(Arc::new(Fixed("::1".parse().unwrap())));
    let r = Recursor::new(s);
    log.lock().unwrap().clear();
    assert!(
        r.resolve(name("www.example.com"), rtype::A, false)
            .await
            .is_err()
    );
    assert!(log.lock().unwrap().is_empty(), "{:?}", log.lock().unwrap());
}

/// REQ: DNS-903 — with a healthy sibling and hedging on (the default), a server that stopped
/// answering is still noticed: it is marked down, sorts last, and lookups stop waiting for it.
#[tokio::test]
async fn dns_903_a_down_server_with_a_sibling_is_noticed_while_hedging() {
    let down = Arc::new(AtomicBool::new(false));
    let down2 = Arc::clone(&down);
    let slow = Arc::new(AtomicU64::new(20));
    let slow2 = Arc::clone(&slow);
    let (mut s, log) = tree(move |zones| {
        zones[1]
            .1
            .cuts
            .push(("example.com", "ns2.example.com", Some([127, 0, 0, 10])));
        let mut copy = zones[2].1.clone();
        copy.delay_ms = Some(slow2);
        zones.push((10, copy));
        zones[2].1.down = Some(down2);
    })
    .await;
    assert!(s.hedge, "hedging is the default");
    s.infra_ttl = Duration::from_secs(30);
    s.infra_probe = Duration::from_secs(20);
    let r = Recursor::new(s);
    let ask = || async {
        let t = std::time::Instant::now();
        let res = r
            .resolve(name("www.example.com"), rtype::A, false)
            .await
            .unwrap();
        assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 1])]);
        t.elapsed()
    };
    for _ in 0..12 {
        ask().await;
    }
    down.store(true, Ordering::Relaxed);
    // The first lookups that start with .4 wait for the hedge and are answered by .10.
    for _ in 0..4 {
        ask().await;
    }
    log.lock().unwrap().clear();
    let mut slowest = Duration::ZERO;
    for _ in 0..3 {
        slowest = slowest.max(ask().await);
    }
    let seen = log.lock().unwrap().clone();
    assert!(
        seen.iter().all(|(ip, _)| *ip != 4),
        "the down server is not asked ahead of its sibling: {seen:?}"
    );
    assert!(
        slowest < Duration::from_millis(140),
        "no lookup waits for the hedge any more: {slowest:?}"
    );
}

/// REQ: DNS-903 — with a healthy sibling and hedging on, a server whose UDP goes unanswered
/// (and which answered before) moves to TCP, so it is not dropped for good.
#[tokio::test]
async fn dns_903_tcp_after_udp_timeouts_while_hedging() {
    let seen = Arc::new(Seen::default());
    let drop_udp = Arc::new(AtomicBool::new(false));
    let (seen2, drop2) = (Arc::clone(&seen), Arc::clone(&drop_udp));
    let slow = Arc::new(AtomicU64::new(150));
    let (mut s, _log) = tree(move |zones| {
        zones[1]
            .1
            .cuts
            .push(("example.com", "ns2.example.com", Some([127, 0, 0, 10])));
        let mut copy = zones[2].1.clone();
        copy.delay_ms = Some(slow);
        zones.push((10, copy));
        zones[2].1.tcp = true;
        zones[2].1.seen = Some(seen2);
        zones[2].1.drop_udp = Some(drop2);
    })
    .await;
    assert!(s.hedge);
    s.infra_probe = Duration::from_millis(300);
    let r = Recursor::new(s);
    for _ in 0..12 {
        r.resolve(name("www.example.com"), rtype::A, false)
            .await
            .unwrap();
    }
    assert_eq!(count(&seen.tcp), 0);
    drop_udp.store(true, Ordering::Relaxed);
    // Every lookup resolves (through the sibling); the dropped server is probed over TCP.
    for _ in 0..40 {
        let res = r
            .resolve(name("www.example.com"), rtype::A, false)
            .await
            .unwrap();
        assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 1])]);
        if count(&seen.tcp) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(count(&seen.tcp) >= 1, "it was asked over TCP");
}

/// REQ: DNS-903 — one FORMERR to a query with EDNS from a server that has answered EDNS
/// queries does not turn EDNS off for it.
#[tokio::test]
async fn dns_903_a_stray_formerr_does_not_disable_edns_for_an_edns_server() {
    let seen = Arc::new(Seen::default());
    let once = Arc::new(AtomicBool::new(false));
    let (seen2, once2) = (Arc::clone(&seen), Arc::clone(&once));
    let (mut s, _log) = tree(move |zones| {
        zones[2].1.edns = true;
        zones[2].1.seen = Some(seen2);
        zones[2].1.formerr_once = Some(once2);
    })
    .await;
    s.hedge = false;
    let r = Recursor::new(s);
    r.resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(count(&seen.plain), 0, "EDNS answered, EDNS kept");
    once.store(true, Ordering::Relaxed);
    // The glitch: that lookup may fail, but the server is not downgraded.
    let _ = r
        .resolve(name("deep.ent.example.com"), rtype::A, false)
        .await;
    assert_eq!(
        count(&seen.plain),
        0,
        "no plain query after the stray FORMERR"
    );
    r.resolve(name("deep.ent.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(count(&seen.plain), 0, "EDNS is still on for it");
}

/// REQ: DNS-903 — a FORMERR to EDNS followed by a REFUSED to the plain query proves nothing
/// about EDNS: the server is not remembered as taking none.
#[tokio::test]
async fn dns_903_a_refused_plain_query_does_not_mark_the_server_no_edns() {
    let seen = Arc::new(Seen::default());
    let seen2 = Arc::clone(&seen);
    let (mut s, _log) = tree(move |zones| {
        zones[2].1.formerr_edns = true;
        zones[2].1.rcode_all = Some(rcode::REFUSED);
        zones[2].1.seen = Some(seen2);
    })
    .await;
    s.hedge = false;
    let r = Recursor::new(s);
    let _ = r.resolve(name("www.example.com"), rtype::A, false).await;
    let edns = count(&seen.edns);
    let _ = r.resolve(name("www.example.com"), rtype::A, false).await;
    assert!(
        count(&seen.edns) > edns,
        "EDNS is still tried: the plain REFUSED proved nothing"
    );
}

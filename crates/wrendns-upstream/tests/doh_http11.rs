// SPDX-License-Identifier: AGPL-3.0-or-later
//! UPS-001, UPS-008 — DoH to a server that only speaks HTTP/1.1 (fork #83): an in-process TLS
//! server that accepts only `http/1.1` in ALPN and answers RFC 8484 requests by hand.

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wrendns_proto::{NameBuf, ResponseBuilder, parse_query, rcode, rtype, summarize};
use wrendns_upstream::{Endpoint, Question, TlsOptions, Upstream, UpstreamOptions};

struct Cert {
    der: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn cert() -> Cert {
    let c =
        rcgen::generate_simple_self_signed(vec!["dns.test".into(), "127.0.0.1".into()]).unwrap();
    Cert {
        der: c.cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.signing_key.serialize_der())),
    }
}

fn answer(req: &[u8]) -> Vec<u8> {
    let q = parse_query(req).unwrap();
    let mut out = [0u8; 512];
    let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
    b.answer_a(300, Ipv4Addr::new(192, 0, 2, 7)).unwrap();
    let len = b.finish(None).unwrap();
    out[..len].to_vec()
}

fn acceptor(c: &Cert, alpn: &[&[u8]]) -> tokio_rustls::TlsAcceptor {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![c.der.clone()], c.key.clone_key())
        .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
}

fn b64url_decode(s: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        _ => 63,
    };
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for c in s.bytes() {
        acc = (acc << 6) | u32::from(val(c));
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).unwrap());
        }
    }
    out
}

/// How the server answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `Content-Length`, keep-alive.
    Length,
    /// `Transfer-Encoding: chunked`, keep-alive.
    Chunked,
    /// `Connection: close` after each answer.
    Close,
    /// Closes the connection after each answer without saying so.
    Drop,
    /// `Content-Length`, keep-alive, and the same answer sent a second time 50 ms later: an
    /// extra response nobody asked for.
    Double,
    /// 70,000 bytes of body.
    Oversize,
    /// Not HTTP.
    Garbage,
    /// 503.
    Unavailable,
}

#[derive(Default)]
struct Seen {
    conns: AtomicUsize,
    reqs: AtomicUsize,
    /// Requests that were not what RFC 8484 asks for.
    wrong: AtomicUsize,
    gets: AtomicUsize,
    live: AtomicUsize,
    peak: AtomicUsize,
}

/// A TLS server that speaks only HTTP/1.1, one request at a time per connection.
async fn h1_server(
    c: &Cert,
    alpn: &[&[u8]],
    mode: Mode,
    delay: Duration,
) -> (SocketAddr, Arc<Seen>) {
    let tls = acceptor(c, alpn);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Seen::default());
    let s2 = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            let (tls, seen) = (tls.clone(), Arc::clone(&s2));
            tokio::spawn(async move {
                let Ok(mut s) = tls.accept(tcp).await else {
                    return;
                };
                seen.conns.fetch_add(1, Ordering::SeqCst);
                let live = seen.live.fetch_add(1, Ordering::SeqCst) + 1;
                seen.peak.fetch_max(live, Ordering::SeqCst);
                serve(&mut s, &seen, mode, delay).await;
                seen.live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (addr, seen)
}

async fn serve<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    s: &mut S,
    seen: &Seen,
    mode: Mode,
    delay: Duration,
) {
    let mut buf = Vec::new();
    loop {
        // The request head.
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let mut tmp = [0u8; 1024];
            match s.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        let lower = head.to_ascii_lowercase();
        let len = lower
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .map_or(0, |v| v.trim().parse::<usize>().unwrap());
        while buf.len() < end + len {
            let mut tmp = [0u8; 1024];
            match s.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
        let body = buf[end..end + len].to_vec();
        buf.drain(..end + len);
        seen.reqs.fetch_add(1, Ordering::SeqCst);

        let line = head.lines().next().unwrap();
        let (query, ok) = if let Some(rest) = line.strip_prefix("GET /dns-query?dns=") {
            seen.gets.fetch_add(1, Ordering::SeqCst);
            let v = rest.strip_suffix(" HTTP/1.1").unwrap_or_default();
            (b64url_decode(v), lower.contains("\r\nhost: "))
        } else {
            let ok = line == "POST /dns-query HTTP/1.1"
                && lower.contains("\r\nhost: ")
                && lower.contains("\r\ncontent-type: application/dns-message\r\n")
                && lower.contains("\r\naccept: application/dns-message\r\n");
            (body, ok)
        };
        if !ok {
            seen.wrong.fetch_add(1, Ordering::SeqCst);
        }
        tokio::time::sleep(delay).await;
        let msg = if ok { answer(&query) } else { Vec::new() };
        let out: Vec<u8> = match mode {
            Mode::Length | Mode::Drop | Mode::Close | Mode::Double => {
                let conn = if mode == Mode::Close {
                    "Connection: close\r\n"
                } else {
                    ""
                };
                let mut o = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n{conn}Content-Length: {}\r\n\r\n",
                    msg.len()
                )
                .into_bytes();
                o.extend_from_slice(&msg);
                o
            }
            Mode::Chunked => {
                let (a, b) = msg.split_at(msg.len() / 2);
                let mut o = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
                for part in [a, b] {
                    o.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                    o.extend_from_slice(part);
                    o.extend_from_slice(b"\r\n");
                }
                o.extend_from_slice(b"0\r\n\r\n");
                o
            }
            Mode::Oversize => {
                let mut o = b"HTTP/1.1 200 OK\r\nContent-Length: 70000\r\n\r\n".to_vec();
                o.extend_from_slice(&vec![0u8; 70_000]);
                o
            }
            Mode::Garbage => b"this is not http\r\n\r\n".to_vec(),
            Mode::Unavailable => {
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec()
            }
        };
        if s.write_all(&out).await.is_err() {
            return;
        }
        let _ = s.flush().await;
        if mode == Mode::Double {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if s.write_all(&out).await.is_err() {
                return;
            }
            let _ = s.flush().await;
        }
        if matches!(mode, Mode::Close | Mode::Drop) {
            let _ = s.shutdown().await;
            return;
        }
    }
}

fn question(name: &str) -> Question {
    Question {
        name: NameBuf::from_presentation(name).unwrap(),
        qtype: rtype::A,
        qclass: 1,
        dnssec_ok: false,
        checking_disabled: false,
        client_subnet: 0,
    }
}

fn upstream(c: &Cert, addr: SocketAddr, tweak: impl FnOnce(&mut UpstreamOptions)) -> Upstream {
    let mut o = UpstreamOptions {
        timeout: Duration::from_secs(2),
        pool_size: 1,
        tls_server_name: Some("dns.test".into()),
        ..UpstreamOptions::default()
    };
    tweak(&mut o);
    let ep = Endpoint::parse(&format!("https://{addr}/dns-query")).unwrap();
    Upstream::build(
        1,
        "doh11",
        ep,
        &o,
        &TlsOptions {
            extra_roots: vec![c.der.clone()],
        },
    )
    .unwrap()
}

async fn ask(up: &Upstream, name: &str) -> Result<usize, String> {
    let r = up
        .exchange(&question(name), Duration::from_secs(5))
        .await
        .map_err(|e| e.to_string())?;
    Ok(usize::from(summarize(&r).unwrap().answers))
}

/// REQ: UPS-001 — a server that accepts only `http/1.1` in ALPN (as the `CleanBrowsing` endpoints
/// do) is queried with RFC 8484 POSTs, and a second query reuses the connection.
#[tokio::test]
async fn ups_001_doh_http11_only_server_resolves_and_reuses_the_connection() {
    let c = cert();
    let (addr, seen) = h1_server(&c, &[b"http/1.1"], Mode::Length, Duration::ZERO).await;
    let up = upstream(&c, addr, |_| {});
    assert_eq!(ask(&up, "one.example").await, Ok(1));
    assert_eq!(ask(&up, "two.example").await, Ok(1));
    assert_eq!(seen.reqs.load(Ordering::SeqCst), 2);
    assert_eq!(
        seen.conns.load(Ordering::SeqCst),
        1,
        "one connection, kept alive"
    );
    assert_eq!(
        seen.wrong.load(Ordering::SeqCst),
        0,
        "well-formed RFC 8484 requests"
    );
    assert_eq!(up.connections().snapshot().opened, 1);
}

/// REQ: UPS-001 — a server that selects no protocol at all is spoken to as HTTP/1.1.
#[tokio::test]
async fn ups_001_doh_http11_when_the_server_selects_no_protocol() {
    let c = cert();
    let (addr, seen) = h1_server(&c, &[], Mode::Length, Duration::ZERO).await;
    let up = upstream(&c, addr, |_| {});
    assert_eq!(ask(&up, "none.example").await, Ok(1));
    assert_eq!(seen.wrong.load(Ordering::SeqCst), 0);
}

/// REQ: UPS-001 — a chunked body is read as well as a `Content-Length` one; `doh_method = "get"`
/// puts the query in `?dns=`.
#[tokio::test]
async fn ups_001_doh_http11_chunked_bodies_and_get() {
    let c = cert();
    let (addr, seen) = h1_server(&c, &[b"http/1.1"], Mode::Chunked, Duration::ZERO).await;
    let up = upstream(&c, addr, |_| {});
    assert_eq!(ask(&up, "chunk.example").await, Ok(1));
    assert_eq!(ask(&up, "chunk2.example").await, Ok(1));
    let get = upstream(&c, addr, |o| o.doh_get = true);
    assert_eq!(ask(&get, "get.example").await, Ok(1));
    assert_eq!(seen.gets.load(Ordering::SeqCst), 1);
    assert_eq!(seen.wrong.load(Ordering::SeqCst), 0);
}

/// REQ: UPS-001 — over-size, malformed and failing responses are errors, quickly, with no panic.
#[tokio::test]
async fn ups_001_doh_http11_bad_responses_are_refused() {
    let c = cert();
    for mode in [Mode::Oversize, Mode::Garbage, Mode::Unavailable] {
        let (addr, _) = h1_server(&c, &[b"http/1.1"], mode, Duration::ZERO).await;
        let up = upstream(&c, addr, |_| {});
        let start = std::time::Instant::now();
        assert!(ask(&up, "bad.example").await.is_err());
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "refused, not waited out"
        );
    }
}

/// REQ: UPS-001 — `Connection: close` is honoured (a new connection per query), and a kept-alive
/// connection the server dropped is replaced once, invisibly.
#[tokio::test]
async fn ups_001_doh_http11_connection_close_and_dropped_keepalive() {
    let c = cert();
    let (addr, seen) = h1_server(&c, &[b"http/1.1"], Mode::Close, Duration::ZERO).await;
    let up = upstream(&c, addr, |_| {});
    for i in 0..3 {
        assert_eq!(ask(&up, &format!("c{i}.example")).await, Ok(1));
    }
    assert_eq!(seen.conns.load(Ordering::SeqCst), 3);

    let (addr, seen) = h1_server(&c, &[b"http/1.1"], Mode::Drop, Duration::ZERO).await;
    let up = upstream(&c, addr, |_| {});
    for i in 0..3 {
        assert_eq!(ask(&up, &format!("d{i}.example")).await, Ok(1));
    }
    assert_eq!(seen.reqs.load(Ordering::SeqCst), 3);
}

/// REQ: UPS-008 — an HTTP/1.1 upstream opens at most `pool_size` connections; the queries beyond
/// that wait for a free one and all still resolve.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ups_008_doh_http11_connections_are_bounded_by_pool_size() {
    let c = cert();
    let (addr, seen) = h1_server(&c, &[b"http/1.1"], Mode::Length, Duration::from_millis(60)).await;
    let up = Arc::new(upstream(&c, addr, |o| o.pool_size = 2));
    let mut tasks = Vec::new();
    for i in 0..8 {
        let up = Arc::clone(&up);
        tasks.push(tokio::spawn(async move {
            ask(&up, &format!("p{i}.example")).await
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), Ok(1));
    }
    assert!(
        seen.peak.load(Ordering::SeqCst) <= 2,
        "at most two connections at once"
    );
    assert!(seen.conns.load(Ordering::SeqCst) <= 2);
    assert_eq!(seen.reqs.load(Ordering::SeqCst), 8);
}

/// REQ: UPS-001 — a server that offers neither `h2` nor `http/1.1` fails the handshake: an error
/// at once, not a hang. And `http_version = "2"` offers only `h2`, so an HTTP/1.1-only server
/// fails there too.
#[tokio::test]
async fn ups_001_doh_without_a_shared_protocol_fails_cleanly() {
    let c = cert();
    let (addr, _) = h1_server(&c, &[b"foo"], Mode::Length, Duration::ZERO).await;
    let up = upstream(&c, addr, |_| {});
    let start = std::time::Instant::now();
    assert!(ask(&up, "neither.example").await.is_err());
    assert!(start.elapsed() < Duration::from_secs(2));

    let (addr, _) = h1_server(&c, &[b"http/1.1"], Mode::Length, Duration::ZERO).await;
    let up = upstream(&c, addr, |o| o.doh_h2_only = true);
    assert!(ask(&up, "h2only.example").await.is_err());
}

/// REQ: UPS-001, UPS-011 — certificate verification and SPKI pins apply on the HTTP/1.1 path.
#[tokio::test]
async fn ups_001_doh_http11_verifies_certificates_and_pins() {
    let c = cert();
    let (addr, _) = h1_server(&c, &[b"http/1.1"], Mode::Length, Duration::ZERO).await;
    // No trusted root: refused.
    let ep = Endpoint::parse(&format!("https://{addr}/dns-query")).unwrap();
    let o = UpstreamOptions {
        timeout: Duration::from_secs(2),
        tls_server_name: Some("dns.test".into()),
        ..UpstreamOptions::default()
    };
    let up = Upstream::build(1, "doh11", ep, &o, &TlsOptions::default()).unwrap();
    assert!(ask(&up, "untrusted.example").await.is_err());
    // The right pin passes; another key fails.
    let pin = wrendns_upstream::spki_pin(c.der.as_ref()).unwrap();
    let good = upstream(&c, addr, |o| o.tls.pins = vec![pin]);
    assert_eq!(ask(&good, "pinned.example").await, Ok(1));
    let bad = upstream(&c, addr, |o| {
        o.tls.pins = vec!["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()];
    });
    assert!(ask(&bad, "wrongpin.example").await.is_err());
}

/// REQ: UPS-001 — a server that sends two responses to one request leaves nothing behind: the
/// connection is checked before it is reused (unread bytes) and after the answer (it must match
/// the query), so a later query is answered by its own response on a new connection, and no query
/// is ever handed another query's answer (`ask` is `Ok` only for a response that matched).
#[tokio::test]
async fn ups_001_doh_http11_extra_response_does_not_poison_the_connection() {
    let c = cert();
    // The extra response has arrived by the time the next query starts: the connection is
    // dropped before use.
    let (addr, seen) = h1_server(&c, &[b"http/1.1"], Mode::Double, Duration::ZERO).await;
    let up = upstream(&c, addr, |_| {});
    assert_eq!(ask(&up, "a.example").await, Ok(1));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(ask(&up, "b.example").await, Ok(1));
    assert_eq!(
        seen.conns.load(Ordering::SeqCst),
        2,
        "the second query used a new connection"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(ask(&up, "c.example").await, Ok(1));

    // The next query goes out before the extra response arrives: it is read as the answer to the
    // wrong question and refused, never returned, and the connection is closed, so the query
    // after that succeeds on a new one.
    let (addr, seen) = h1_server(&c, &[b"http/1.1"], Mode::Double, Duration::ZERO).await;
    let up = upstream(&c, addr, |_| {});
    assert_eq!(ask(&up, "first.example").await, Ok(1));
    assert!(
        ask(&up, "second.example").await.is_err(),
        "the stale answer is refused"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    for i in 0..3 {
        assert_eq!(ask(&up, &format!("later{i}.example")).await, Ok(1));
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(seen.conns.load(Ordering::SeqCst) >= 2);
}

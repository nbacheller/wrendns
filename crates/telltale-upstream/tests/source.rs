//! REQ: UPS-013 (T24.31, ADR-997) — an upstream's `source`: its sockets are bound to that
//! address before they connect, and one the node doesn't hold is refused at start.

#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use telltale_proto::{NameBuf, ResponseBuilder, parse_query, rcode, rtype};
use telltale_upstream::{Endpoint, Question, Router, TlsOptions, Upstream, UpstreamOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn question() -> Question {
    Question {
        name: NameBuf::from_presentation("example.test.").unwrap(),
        qtype: rtype::A,
        qclass: 1,
        dnssec_ok: false,
        checking_disabled: false,
        client_subnet: 0,
    }
}

fn reply(req: &[u8]) -> Vec<u8> {
    let q = parse_query(req).unwrap();
    let mut out = [0u8; 512];
    let mut b = ResponseBuilder::new(&q, &mut out, rcode::NOERROR).unwrap();
    b.answer_a(300, Ipv4Addr::new(192, 0, 2, 1)).unwrap();
    let n = b.finish(None).unwrap();
    out[..n].to_vec()
}

/// A UDP server that answers and reports the peer it heard from.
async fn udp_server() -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<SocketAddr>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            tx.send(peer).ok();
            sock.send_to(&reply(&buf[..n]), peer).await.ok();
        }
    });
    (addr, rx)
}

/// A TCP server that answers one query per connection and reports the peer.
async fn tcp_server() -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<SocketAddr>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut s, peer)) = l.accept().await {
            tx.send(peer).ok();
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut req = vec![0; usize::from(u16::from_be_bytes(len))];
                    if s.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    let r = reply(&req);
                    let mut out = u16::try_from(r.len()).unwrap().to_be_bytes().to_vec();
                    out.extend_from_slice(&r);
                    if s.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, rx)
}

fn upstream(url: &str, source: Option<IpAddr>) -> Upstream {
    let opts = UpstreamOptions {
        timeout: Duration::from_secs(2),
        source,
        ..UpstreamOptions::default()
    };
    Upstream::build(
        1,
        "u",
        Endpoint::parse(url).unwrap(),
        &opts,
        &TlsOptions::default(),
    )
    .unwrap()
}

/// REQ: UPS-013 — a UDP query leaves from the source address (any port).
#[tokio::test]
async fn ups_013_udp_binds_the_source_address() {
    let (addr, mut seen) = udp_server().await;
    let src: IpAddr = "127.0.0.2".parse().unwrap();
    let up = upstream(&format!("udp://{addr}"), Some(src));
    up.exchange(&question(), Duration::from_secs(2))
        .await
        .unwrap();
    let peer = seen.recv().await.unwrap();
    assert_eq!(peer.ip(), src);
    assert_ne!(peer.port(), 0);
    assert_eq!(up.source(), Some(src));
    assert!(up.source_problem().is_none());
}

/// REQ: UPS-013 — a TCP connection is bound before it connects, and is pooled and reused.
#[tokio::test]
async fn ups_013_tcp_binds_the_source_address() {
    let (addr, mut seen) = tcp_server().await;
    let src: IpAddr = "127.0.0.3".parse().unwrap();
    let up = upstream(&format!("tcp://{addr}"), Some(src));
    up.exchange(&question(), Duration::from_secs(2))
        .await
        .unwrap();
    up.exchange(&question(), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(seen.recv().await.unwrap().ip(), src);
    // The second query reused the pooled connection (this pool is this source's).
    assert!(seen.try_recv().is_err());
}

/// REQ: UPS-013 — without a source nothing changes.
#[tokio::test]
async fn ups_013_no_source_uses_the_default_route() {
    let (addr, mut seen) = udp_server().await;
    let up = upstream(&format!("udp://{addr}"), None);
    up.exchange(&question(), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        seen.recv().await.unwrap().ip(),
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
    assert!(up.source().is_none());
}

/// REQ: UPS-013 — an address that leaves the node later is a health reason, not a crash, and
/// clears once queries bind again.
#[tokio::test]
async fn ups_013_lost_source_is_a_problem_not_a_crash() {
    let (addr, _seen) = udp_server().await;
    // TEST-NET-1: no interface holds it.
    let src: IpAddr = "192.0.2.77".parse().unwrap();
    let up = upstream(&format!("udp://{addr}"), Some(src));
    assert!(
        up.exchange(&question(), Duration::from_millis(500))
            .await
            .is_err()
    );
    let p = up.source_problem().unwrap();
    assert!(p.contains("192.0.2.77"), "{p}");
}

/// REQ: UPS-013 — the server and the source must be the same IP version.
#[test]
fn ups_013_family_mismatch_is_refused() {
    let opts = UpstreamOptions {
        source: Some("::1".parse().unwrap()),
        ..UpstreamOptions::default()
    };
    let e = Upstream::build(
        1,
        "u",
        Endpoint::parse("udp://192.0.2.1").unwrap(),
        &opts,
        &TlsOptions::default(),
    )
    .unwrap_err();
    assert!(e.contains("same IP version"), "{e}");
}

fn config(toml: &str) -> telltale_config::Config {
    telltale_config::Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .map_err(|e| format!("{e:?}"))
        .unwrap()
        .config
}

/// REQ: UPS-013 (ADR-997 §4), CLU-004 — a stored config whose `source` this node doesn't hold
/// still starts: that upstream is degraded (a problem, queries fail fast) and the others serve.
#[tokio::test]
async fn ups_013_foreign_source_degrades_that_upstream_only() {
    let (addr, _seen) = udp_server().await;
    let r = Router::from_config(&config(&format!(
        "[[upstream]]\nname = \"vlan\"\nurl = \"udp://192.0.2.1\"\nsource = \"203.0.113.9\"\n\
         [[upstream]]\nname = \"other\"\nurl = \"udp://{addr}\"\n"
    )))
    .unwrap_or_else(|e| panic!("must start: {e:?}"));
    let ups = r.upstreams();
    let p = ups[0].source_problem().unwrap();
    assert!(p.contains("holds no such address"), "{p}");
    assert!(ups[0].source().is_none());
    let t = std::time::Instant::now();
    assert!(
        ups[0]
            .exchange(&question(), Duration::from_secs(2))
            .await
            .is_err()
    );
    assert!(t.elapsed() < Duration::from_secs(1), "fails fast");
    ups[1]
        .exchange(&question(), Duration::from_secs(2))
        .await
        .unwrap();
    assert!(ups[1].source_problem().is_none());
    // `config check` names it.
    let w = telltale_upstream::source_warnings(&config(
        "[[upstream]]\nname = \"vlan\"\nurl = \"udp://192.0.2.1\"\nsource = \"203.0.113.9\"\n",
    ));
    assert!(
        w.iter().any(|l| l.contains("holds no such address")),
        "{w:?}"
    );
}

/// REQ: UPS-013 — a hostname upstream is reached over the source's IP version: a v6 source
/// with only a v4 answer is a stated problem, not a bind across families.
#[tokio::test]
async fn ups_013_source_family_picks_the_matching_address() {
    use telltale_upstream::Bootstrap;
    // A bootstrap that answers A only.
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bs_addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            sock.send_to(&reply(&buf[..n]), peer).await.ok();
        }
    });
    let opts = UpstreamOptions {
        timeout: Duration::from_secs(2),
        source_spec: Some("::1".into()),
        bootstrap: Some(std::sync::Arc::new(Bootstrap::new(vec![bs_addr]))),
        ..UpstreamOptions::default()
    };
    let up = Upstream::build(
        1,
        "u",
        Endpoint::parse("udp://dns.example.test").unwrap(),
        &opts,
        &TlsOptions::default(),
    )
    .unwrap();
    assert!(
        up.exchange(&question(), Duration::from_secs(2))
            .await
            .is_err()
    );
    let p = up.source_problem().unwrap();
    assert!(p.contains("has no IPv6 address"), "{p}");
}

/// REQ: UPS-013 — start accepts an address the node holds (an address, `address:0`, or the
/// network it is in).
#[test]
fn ups_013_router_accepts_a_held_source() {
    for src in ["127.0.0.1", "127.0.0.1:0", "127.0.0.0/8"] {
        let r = Router::from_config(&config(&format!(
            "[[upstream]]\nname = \"a\"\nurl = \"udp://192.0.2.1\"\nsource = \"{src}\"\n"
        )))
        .unwrap_or_else(|e| panic!("{src}: {e:?}"));
        assert_eq!(
            r.upstreams()[0].source(),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "{src}"
        );
    }
}

/// REQ: UPS-013 — the configuration refuses `source` on schemes that don't bind it, with a
/// proxy, and with a port.
#[test]
fn ups_013_source_only_where_it_binds() {
    let load = |extra: &str| {
        telltale_config::Loader::new()
            .toml_str(
                "t.toml",
                format!(
                    "[[upstream]]
name = \"a\"
{extra}
"
                ),
            )
            .env(Vec::<(String, String)>::new())
            .load()
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    };
    let quic = load(
        "url = \"quic://192.0.2.1\"
source = \"127.0.0.1\"",
    );
    assert!(quic.unwrap_err().contains("only for udp://"));
    let proxied = load(
        "url = \"tcp://192.0.2.1\"
proxy = \"socks5://127.0.0.1:1080\"
source = \"127.0.0.1\"",
    );
    assert!(proxied.unwrap_err().contains("not with a proxy"));
    let port = load(
        "url = \"udp://192.0.2.1\"
source = \"127.0.0.1:53\"",
    );
    assert!(port.unwrap_err().contains("port must be 0"));
    assert!(
        load(
            "url = \"https://192.0.2.1/dns-query\"
source = \"127.0.0.0/8\""
        )
        .is_ok()
    );
}

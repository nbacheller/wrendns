// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-902, CLU-004, DNS-001 (T27.14a) — process tests of stage, adoption, commit and abort on
//! real loopback sockets with the live handler.

use std::sync::atomic::Ordering;
use std::time::Duration;

use wrendns_proto::{NameBuf, build_query, rtype};

use super::*;
use crate::server::tests::{gate_fixture, test_listeners};

fn udp(addr: SocketAddr) -> Listener {
    Listener {
        proto: ListenProto::Udp,
        addr,
        path: None,
        tls: None,
        proxy_protocol: false,
        max_connections: None,
        max_connections_per_address: None,
        require_client_id: None,
    }
}

fn tcp(addr: SocketAddr) -> Listener {
    Listener {
        proto: ListenProto::Tcp,
        ..udp(addr)
    }
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// Whether a `localhost A` query to `addr` over UDP gets an answer.
async fn answers(addr: SocketAddr) -> bool {
    let bind = if addr.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    };
    let sock = tokio::net::UdpSocket::bind(bind).await.unwrap();
    let name = NameBuf::from_presentation("localhost").unwrap();
    let mut q = [0u8; 512];
    let len = build_query(&mut q, 7, &name, rtype::A, 1, true, None).unwrap();
    if sock.send_to(&q[..len], addr).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    matches!(
        tokio::time::timeout(Duration::from_millis(700), sock.recv_from(&mut buf)).await,
        Ok(Ok(_))
    )
}

async fn connects(addr: SocketAddr) -> bool {
    tokio::net::TcpStream::connect(addr).await.is_ok()
}

// REQ: API-902, CLU-004 (T27.14a) — a stage binds an added listener next to the old one, and the
// live handler answers on it, before anything is released.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_listener_change_binds_before_release() {
    let _one = crate::gate_host::isolate();
    let mut l = test_listeners();
    let old = udp(loopback(free_udp_port()));
    l.apply(std::slice::from_ref(&old)).await.unwrap();
    let new = udp(loopback(free_udp_port()));
    let staged = l.stage(std::slice::from_ref(&new)).await.unwrap();
    assert_eq!(staged.len(), 1);
    assert!(!staged[0].proof);
    assert_eq!(staged[0].bound, new.addr);
    assert!(answers(new.addr).await, "the staged socket is served");
    assert!(answers(old.addr).await, "the old socket still answers");
    assert_eq!(
        l.udp.len(),
        1,
        "the staged socket is not in the running set"
    );
    l.abort_staged().await;
    crate::gate_host::clear_listeners_for_test();
}

// REQ: API-902 — what the new list removes keeps answering until the commit, and goes with it.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_old_listener_kept_until_confirmed() {
    let _one = crate::gate_host::isolate();
    let mut l = test_listeners();
    let old = udp(loopback(free_udp_port()));
    l.apply(std::slice::from_ref(&old)).await.unwrap();
    let new = udp(loopback(free_udp_port()));
    l.stage(std::slice::from_ref(&new)).await.unwrap();
    for _ in 0..3 {
        assert!(answers(old.addr).await, "kept for the whole window");
    }
    // The confirm: the reload, then the commit.
    l.apply(std::slice::from_ref(&new)).await.unwrap();
    l.commit_staged().await.unwrap();
    assert!(answers(new.addr).await);
    assert!(!answers(old.addr).await, "closed at the commit");
    crate::gate_host::clear_listeners_for_test();
}

// REQ: API-902 — a reload in the window runs on the running configuration and leaves the staged
// sockets alone.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_reload_in_window_keeps_staged_sockets() {
    let _one = crate::gate_host::isolate();
    let mut l = test_listeners();
    let old = udp(loopback(free_udp_port()));
    l.apply(std::slice::from_ref(&old)).await.unwrap();
    let new = udp(loopback(free_udp_port()));
    l.stage(std::slice::from_ref(&new)).await.unwrap();
    l.apply(std::slice::from_ref(&old)).await.unwrap();
    assert!(answers(new.addr).await, "staged socket untouched");
    assert!(answers(old.addr).await);
    assert!(l.staged.is_some());
    l.abort_staged().await;
    assert!(l.staged.is_none());
    assert!(!answers(new.addr).await);
    assert!(answers(old.addr).await, "abort leaves the running set");
    crate::gate_host::clear_listeners_for_test();
}

// REQ: API-902, CLU-004 — the replicated reload may run `apply` before the engine's commit: it
// adopts the staged sockets (not a second bind) and the commit then passes. A commit while a
// socket is still staged fails.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_replicated_reload_adopts_staged_sockets() {
    let _one = crate::gate_host::isolate();
    let mut l = test_listeners();
    let old = udp(loopback(free_udp_port()));
    l.apply(std::slice::from_ref(&old)).await.unwrap();
    let new_udp = udp(loopback(free_udp_port()));
    let new_tcp = tcp(loopback(free_tcp_port()));
    let list = [old.clone(), new_udp.clone(), new_tcp.clone()];
    l.stage(&list).await.unwrap();
    assert!(connects(new_tcp.addr).await, "staged and served");
    let early = l.commit_staged().await.unwrap_err();
    assert_eq!(early.reason, COMMIT_FAILED);
    assert!(early.detail.contains("not adopted"), "{}", early.detail);
    // The reload adopts; the commit passes. A second bind would have failed on the held port.
    l.apply(&list).await.unwrap();
    assert_eq!(l.udp.len(), 2);
    assert_eq!(l.streams.len(), 1);
    assert!(
        l.staged
            .as_ref()
            .is_some_and(|s| s.udp.is_empty() && s.streams.is_empty())
    );
    l.commit_staged().await.unwrap();
    assert!(l.staged.is_none());
    assert!(answers(new_udp.addr).await);
    assert!(connects(new_tcp.addr).await);
    crate::gate_host::clear_listeners_for_test();
}

// REQ: API-902 — a changed listener is bound on a proof port (the real port is held by the old
// socket); the commit swaps it onto the real port and closes the proof port.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_changed_listener_probed_on_proof_port_then_swapped() {
    let _one = crate::gate_host::isolate();
    let (_dir, _cert, listen) = gate_fixture();
    let mut l = test_listeners();
    let old = listen(Some(false));
    l.apply(std::slice::from_ref(&old)).await.unwrap();
    let old_port = l.streams[0].1.local_addr();
    let changed = Listener {
        max_connections: Some(7),
        ..listen(Some(false))
    };
    let staged = l.stage(std::slice::from_ref(&changed)).await.unwrap();
    assert_eq!(staged.len(), 1);
    assert!(
        staged[0].proof,
        "a changed listener is staged on a proof port"
    );
    assert_ne!(staged[0].bound, old_port);
    assert_eq!(staged[0].bound.ip(), old.addr.ip());
    assert!(connects(staged[0].bound).await, "the proof port answers");
    assert!(connects(old_port).await, "the old socket is untouched");
    assert_eq!(l.streams[0].0.max_connections, None);
    // The swap and the commit.
    l.apply(std::slice::from_ref(&changed)).await.unwrap();
    assert_eq!(l.streams[0].0.max_connections, Some(7));
    l.commit_staged().await.unwrap();
    assert!(!connects(staged[0].bound).await, "the proof port is closed");
    assert!(connects(l.streams[0].1.local_addr()).await);
    crate::gate_host::clear_listeners_for_test();
}

// REQ: API-902, DNS-001 — a TCP listener beside a wildcard on the same port cannot bind (only
// SO_REUSEADDR is set): it is staged on a loopback proof port, and the commit binds it for real
// after the removed wildcard has been closed.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_tcp_overlap_staged_on_proof_port() {
    let _one = crate::gate_host::isolate();
    let mut l = test_listeners();
    let port = free_tcp_port();
    let wild = tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    l.apply(std::slice::from_ref(&wild)).await.unwrap();
    let specific = tcp(loopback(port));
    let staged = l.stage(std::slice::from_ref(&specific)).await.unwrap();
    assert!(staged[0].proof);
    assert_eq!(staged[0].bound.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(staged[0].bound.port(), port);
    assert!(connects(staged[0].bound).await);
    l.apply(std::slice::from_ref(&specific)).await.unwrap();
    l.commit_staged().await.unwrap();
    assert_eq!(l.streams.len(), 1);
    assert_eq!(l.streams[0].0.addr, specific.addr);
    assert!(connects(specific.addr).await);
    assert!(!connects(staged[0].bound).await);
    crate::gate_host::clear_listeners_for_test();
}

// REQ: API-902 — a bind that fails closes everything staged so far and says which address and
// why; nothing running changes.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_failed_bind_closes_everything_staged() {
    let _one = crate::gate_host::isolate();
    let mut l = test_listeners();
    let old = udp(loopback(free_udp_port()));
    l.apply(std::slice::from_ref(&old)).await.unwrap();
    let good = udp(loopback(free_udp_port()));
    // An address that is on no interface.
    let bad = tcp("203.0.113.9:5353".parse().unwrap());
    let e = l
        .stage(&[old.clone(), good.clone(), bad.clone()])
        .await
        .unwrap_err();
    assert_eq!(e.reason, BIND_FAILED);
    assert!(e.detail.contains("tcp 203.0.113.9:5353"), "{}", e.detail);
    assert!(l.staged.is_none());
    assert!(!answers(good.addr).await, "the staged socket was closed");
    assert!(answers(old.addr).await);
    assert_eq!(l.udp.len(), 1);
    crate::gate_host::clear_listeners_for_test();
}

// REQ: API-902 — a file that now sets `[[listen]]` cancels the window: the staged sockets close
// and the commit answers `cancelled`.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_file_taking_over_cancels_the_window() {
    let _one = crate::gate_host::isolate();
    let mut l = test_listeners();
    let old = udp(loopback(free_udp_port()));
    l.apply(std::slice::from_ref(&old)).await.unwrap();
    let new = udp(loopback(free_udp_port()));
    l.stage(std::slice::from_ref(&new)).await.unwrap();
    l.cancel_window_for_file().await;
    assert!(l.staged.is_none());
    assert!(!answers(new.addr).await);
    let e = l.commit_staged().await.unwrap_err();
    assert_eq!(e.reason, CANCELLED);
    assert_eq!(e.detail, "the file now sets the listeners");
    assert!(answers(old.addr).await);
    // Without a pending change it changes nothing.
    let mut idle = test_listeners();
    idle.cancel_window_for_file().await;
    assert!(idle.commit_staged().await.is_ok());
    crate::gate_host::clear_listeners_for_test();
}

// REQ: API-902 (ADR-956 section 4) — a restart in the window starts with the previous list: the
// pending change was held in memory only, so a new process knows nothing of the staged sockets.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_restart_in_window_starts_with_old_listeners() {
    let _one = crate::gate_host::isolate();
    let old = udp(loopback(free_udp_port()));
    let new = udp(loopback(free_udp_port()));
    {
        let mut first = test_listeners();
        first.apply(std::slice::from_ref(&old)).await.unwrap();
        first.stage(std::slice::from_ref(&new)).await.unwrap();
        assert!(answers(new.addr).await);
    }
    // The process is gone; the next start reads the previous list.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut second = test_listeners();
    second.apply(std::slice::from_ref(&old)).await.unwrap();
    assert!(second.staged.is_none());
    assert!(answers(old.addr).await);
    assert!(!answers(new.addr).await);
    crate::gate_host::clear_listeners_for_test();
}

// REQ: API-902 — an abort closes the staged and proof-port sockets and nothing else.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_abort_closes_only_staged_sockets() {
    let _one = crate::gate_host::isolate();
    let (_dir, _cert, listen) = gate_fixture();
    let mut l = test_listeners();
    let old = listen(Some(false));
    let extra = udp(loopback(free_udp_port()));
    l.apply(&[old.clone(), extra.clone()]).await.unwrap();
    let old_port = l.streams[0].1.local_addr();
    let new = udp(loopback(free_udp_port()));
    let changed = Listener {
        max_connections: Some(3),
        ..listen(Some(false))
    };
    let staged = l
        .stage(&[changed, extra.clone(), new.clone()])
        .await
        .unwrap();
    assert_eq!(staged.len(), 2, "the unchanged listener is not staged");
    l.abort_staged().await;
    assert!(!answers(new.addr).await);
    assert!(!connects(staged.iter().find(|s| s.proof).unwrap().bound).await);
    assert!(connects(old_port).await);
    assert!(answers(extra.addr).await);
    crate::gate_host::clear_listeners_for_test();
}

// REQ: API-902, DNS-001 (design 2.3) — a UDP socket on a specific address binds next to a
// wildcard on the same port (SO_REUSEPORT), and on this kernel the more specific socket gets the
// datagrams sent to its address. The behaviour depends on the kernel, so it is checked here.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_udp_overlap_with_a_wildcard_binds_and_delivers_to_the_specific() {
    let _one = crate::gate_host::isolate();
    let mut l = test_listeners();
    let port = free_udp_port();
    let wild = udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    l.apply(std::slice::from_ref(&wild)).await.unwrap();
    let specific = udp(loopback(port));
    let staged = l.stage(&[wild.clone(), specific.clone()]).await.unwrap();
    assert_eq!(staged.len(), 1);
    assert!(!staged[0].proof, "UDP needs no proof port");
    for _ in 0..4 {
        assert!(answers(specific.addr).await);
    }
    let got = |s: &[std::sync::Arc<wrendns_net::WorkerStats>]| {
        s.iter()
            .map(|w| w.received.load(Ordering::Relaxed))
            .sum::<u64>()
    };
    let on_specific = got(l.staged.as_ref().unwrap().udp[0].1.stats());
    let on_wild = got(l.udp[0].1.stats());
    assert_eq!(on_specific, 4, "the specific socket got them");
    assert_eq!(on_wild, 0, "the wildcard got none");
    l.abort_staged().await;
    crate::gate_host::clear_listeners_for_test();
}

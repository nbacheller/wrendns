// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-902, OBS-020, DNS-901 (T27.14b) — the node's own probe against real staged sockets: the
//! live handler answers through the evidence wrapper, a gated listener is proved by its refusal, and
//! a closed port gives no answer.

use std::time::Duration;

use super::*;
use crate::guarded::dns_proof::{Kind, probes_for};
use crate::probes::ask_proof;
use crate::server::tests::{gate_fixture, test_listeners};

const WAIT: Duration = Duration::from_secs(3);

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

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// A staged plain UDP socket answers the node's own probe through the evidence wrapper, and the
// node's own query is not counted as another host.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_probe_answered_on_a_staged_udp_socket() {
    let _one = crate::gate_host::isolate();
    let mut l = test_listeners();
    let new = udp(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        free_udp_port(),
    ));
    let staged = l.stage(std::slice::from_ref(&new)).await.unwrap();
    let probes = probes_for(
        &staged,
        std::slice::from_ref(&new),
        crate::gate_host::read(),
    );
    assert_eq!(probes.len(), 1);
    assert!(!probes[0].gated);
    assert_eq!(probes[0].listener(), format!("udp://{}", new.addr));
    let kind = ask_proof(&probes[0].url(), probes[0].gated, WAIT)
        .await
        .unwrap();
    assert_eq!(kind, Kind::Answered);
    let ev = probes[0].evidence.as_ref().unwrap();
    assert_eq!(ev.others(), 0, "the node's own query is not another host");
    l.abort_staged().await;
    crate::gate_host::clear_listeners_for_test();
}

// A gated DoT listener is proved by the gate's own refusal (REFUSED with extended error 18); an
// ungated one answered as a normal listener is not what a gated listener should do.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_gated_dot_proved_by_its_refusal() {
    let _one = crate::gate_host::isolate();
    let (_dir, _cert, listen) = gate_fixture();
    let mut l = test_listeners();
    let gated = listen(Some(true));
    let staged = l.stage(std::slice::from_ref(&gated)).await.unwrap();
    let probes = probes_for(
        &staged,
        std::slice::from_ref(&gated),
        crate::gate_host::read(),
    );
    assert!(probes[0].gated, "the stage bound it with the gate on");
    let url = probes[0].url();
    assert!(url.starts_with("tls://127.0.0.1:"), "{url}");
    assert_eq!(
        ask_proof(&url, true, WAIT).await.unwrap(),
        Kind::RefusedByGate
    );
    // Judged as an ungated listener, any well-formed answer counts (ADR-107), the refusal too.
    assert_eq!(ask_proof(&url, false, WAIT).await.unwrap(), Kind::Answered);
    l.abort_staged().await;

    let open = listen(Some(false));
    let staged = l.stage(std::slice::from_ref(&open)).await.unwrap();
    let probes = probes_for(
        &staged,
        std::slice::from_ref(&open),
        crate::gate_host::read(),
    );
    assert!(!probes[0].gated);
    let err = ask_proof(&probes[0].url(), true, WAIT).await.unwrap_err();
    assert!(err.contains("the gate is not on"), "{err}");
    assert_eq!(
        ask_proof(&probes[0].url(), false, WAIT).await.unwrap(),
        Kind::Answered
    );
    l.abort_staged().await;
    crate::gate_host::clear_listeners_for_test();
}

// A gated DoH listener is proved by HTTP 404 (the same answer as for a missing client ID).
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_gated_doh_proved_by_its_404() {
    let _one = crate::gate_host::isolate();
    let (_dir, _cert, listen) = gate_fixture();
    let mut l = test_listeners();
    let gated = Listener {
        proto: ListenProto::Doh,
        ..listen(Some(true))
    };
    let staged = l.stage(std::slice::from_ref(&gated)).await.unwrap();
    let probes = probes_for(
        &staged,
        std::slice::from_ref(&gated),
        crate::gate_host::read(),
    );
    assert!(probes[0].gated);
    assert!(probes[0].url().ends_with("/dns-query"));
    assert_eq!(
        ask_proof(&probes[0].url(), true, WAIT).await.unwrap(),
        Kind::RefusedByGate
    );
    l.abort_staged().await;
    crate::gate_host::clear_listeners_for_test();
}

// A gated DoH3 listener is proved by HTTP 404 too: the client reports the status, as for DoH.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_gated_doh3_proved_by_its_404() {
    let _one = crate::gate_host::isolate();
    let (_dir, _cert, listen) = gate_fixture();
    let mut l = test_listeners();
    let gated = Listener {
        proto: ListenProto::Doh3,
        ..listen(Some(true))
    };
    let staged = l.stage(std::slice::from_ref(&gated)).await.unwrap();
    let probes = probes_for(
        &staged,
        std::slice::from_ref(&gated),
        crate::gate_host::read(),
    );
    assert!(probes[0].gated);
    assert!(probes[0].url().starts_with("h3://"));
    assert_eq!(
        ask_proof(&probes[0].url(), true, WAIT).await.unwrap(),
        Kind::RefusedByGate
    );
    l.abort_staged().await;
    crate::gate_host::clear_listeners_for_test();
}

// A gated DoQ listener is proved by REFUSED with extended error 18.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_gated_doq_proved_by_its_refusal() {
    let _one = crate::gate_host::isolate();
    let (_dir, _cert, listen) = gate_fixture();
    let mut l = test_listeners();
    let gated = Listener {
        proto: ListenProto::Doq,
        ..listen(Some(true))
    };
    let staged = l.stage(std::slice::from_ref(&gated)).await.unwrap();
    let probes = probes_for(
        &staged,
        std::slice::from_ref(&gated),
        crate::gate_host::read(),
    );
    assert!(probes[0].gated);
    assert!(probes[0].url().starts_with("quic://"));
    assert_eq!(
        ask_proof(&probes[0].url(), true, WAIT).await.unwrap(),
        Kind::RefusedByGate
    );
    l.abort_staged().await;
    crate::gate_host::clear_listeners_for_test();
}

// The probe asks the path the bound server serves: a trailing slash in the listener's `path` is
// dropped by the server, so it is dropped in the probe too (else the gate's 404 would prove a path
// that is not served).
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn api_902_probe_uses_the_path_the_server_serves() {
    let _one = crate::gate_host::isolate();
    let (_dir, _cert, listen) = gate_fixture();
    let mut l = test_listeners();
    let gated = Listener {
        proto: ListenProto::Doh,
        path: Some(wrendns_config::SafeString::new("/q/").unwrap()),
        ..listen(Some(true))
    };
    let staged = l.stage(std::slice::from_ref(&gated)).await.unwrap();
    let probes = probes_for(
        &staged,
        std::slice::from_ref(&gated),
        crate::gate_host::read(),
    );
    assert!(probes[0].url().ends_with("/q"), "{}", probes[0].url());
    l.abort_staged().await;
    crate::gate_host::clear_listeners_for_test();
}

// A port nothing listens on gives no answer, with a reason.
#[tokio::test]
async fn api_902_probe_of_a_closed_port_gets_no_answer() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), free_udp_port());
    let err = ask_proof(&format!("udp://{addr}"), false, Duration::from_millis(600))
        .await
        .unwrap_err();
    assert_ne!(err, String::new());
}

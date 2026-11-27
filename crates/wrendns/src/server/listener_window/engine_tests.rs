// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-902, CLU-004, DNS-001 (T27.14c; design 2.5) — the guarded engine and the `listen` row
//! driving the real `Listeners` over loopback sockets: a UDP query loop runs across a failed bind, a
//! cancelled change, a confirmed change and a removal, and not one query is lost on a listener that
//! stays.

#![allow(clippy::field_reassign_with_default, clippy::many_single_char_names)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use wrendns_api::BoxFuture;
use wrendns_api::auth::Actor;
use wrendns_api::guarded::{GuardedApplyRequest, GuardedCaller, GuardedPreviewRequest, Supervisor};
use wrendns_api::problem::Code;
use wrendns_config::{Config, ListenProto, Listener};
use wrendns_proto::{NameBuf, build_query, rtype};
use wrendns_store::state::State;

use super::{ListenerCmd, ListenerHandle};
use crate::guarded::engine::Engine;
use crate::guarded::host::{Host, StubHost};
use crate::guarded::listen::{merged, parse};
use crate::server::tests::test_listeners;

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

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn answers(addr: SocketAddr) -> bool {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
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

fn admin() -> GuardedCaller {
    GuardedCaller {
        actor: Actor {
            name: "alice".to_owned(),
            kind: "session",
            remote: Some("192.0.2.10".to_owned()),
            reason: None,
        },
        username: "alice".to_owned(),
        session: Some("sess-alice".to_owned()),
        signed_in_at: Some(crate::guarded::now_secs()),
        arrived_on: None,
        remote: Some("192.0.2.10".parse().unwrap()),
        remote_under_pending: None,
        peer: None,
        tls: false,
    }
}

fn value(list: &[SocketAddr]) -> Value {
    json!({"listeners": list.iter().map(|a| json!({"proto": "udp", "addr": a.to_string()})).collect::<Vec<_>>()})
}

async fn preview_apply(
    e: &Arc<Engine>,
    c: &GuardedCaller,
    v: Value,
) -> Result<wrendns_api::guarded::GuardedApplied, wrendns_api::problem::Problem> {
    let p = e
        .preview(
            c,
            "listen",
            GuardedPreviewRequest {
                node: None,
                value: v.clone(),
                options: Value::Null,
            },
        )
        .await?;
    e.apply(
        c,
        "listen",
        GuardedApplyRequest {
            preview_id: p.preview_id.clone(),
            confirm: p.phrase.clone(),
            reason: Some("test".to_owned()),
            value: v,
            options: Value::Null,
            node: None,
            acknowledge: p.acknowledgements,
        },
    )
    .await
}

type Apply = (Vec<Listener>, oneshot::Sender<bool>);

// REQ: API-902, CLU-004 (design 2.5; AC 2) — a bad listener rolls back and DNS keeps answering: a UDP
// query loop on the listener that stays runs across a failed bind, a cancelled change and a
// confirmed change, and not one query is lost; the confirmed change adopts the staged socket and the
// removal closes only what the change removed.
#[tokio::test]
#[allow(clippy::await_holding_lock, clippy::too_many_lines)]
async fn api_902_bad_listener_rolls_back_and_dns_keeps_answering() {
    let _one = crate::gate_host::isolate();
    let mut l = test_listeners();
    let old = udp(loopback(free_udp_port()));
    l.apply(std::slice::from_ref(&old)).await.unwrap();
    // The node's main loop: the engine's commands and the reload's apply.
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<ListenerCmd>(8);
    let (apply_tx, mut apply_rx) = mpsc::channel::<Apply>(2);
    let main_loop = tokio::spawn(async move {
        loop {
            tokio::select! {
                c = cmd_rx.recv() => match c {
                    Some(c) => l.window_cmd(c).await,
                    None => break,
                },
                a = apply_rx.recv() => match a {
                    Some((list, reply)) => {
                        let ok = l.apply(&list).await.is_ok();
                        let _ = reply.send(ok);
                    }
                    None => break,
                },
            }
        }
        l
    });
    let base = vec![old.clone()];
    let hook = {
        let tx = apply_tx.clone();
        let base = base.clone();
        Arc::new(move |entry: Option<Value>| -> BoxFuture<bool> {
            let list = match entry {
                Some(v) => merged(parse(&v).unwrap(), &base),
                None => base.clone(),
            };
            let tx = tx.clone();
            Box::pin(async move {
                let (reply, answer) = oneshot::channel();
                if tx.send((list, reply)).await.is_err() {
                    return false;
                }
                answer.await.unwrap_or(false)
            })
        })
    };
    let mut cfg = Config::default();
    cfg.listen = base.clone();
    cfg.api.confirm_window_secs = 60;
    let host = Arc::new(StubHost {
        listeners: Some(ListenerHandle::new(cmd_tx)),
        cfg: Mutex::new(Some(Arc::new(cfg.clone()))),
        on_reload: Some(hook),
        entry: Mutex::default(),
    });
    let engine = Engine::new(
        "pi-a".to_owned(),
        Arc::new(State::in_memory().unwrap()),
        Arc::clone(&host) as Arc<dyn Host>,
        crate::guarded::appliers::rows(),
        Supervisor {
            kind: "systemd".to_owned(),
            how: "test".to_owned(),
        },
    );
    let a = admin();
    // The query loop on the listener that stays.
    let (lost, stop) = (
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicBool::new(false)),
    );
    let sent = Arc::new(AtomicUsize::new(0));
    let looper = {
        let (lost, stop, sent) = (Arc::clone(&lost), Arc::clone(&stop), Arc::clone(&sent));
        let addr = old.addr;
        tokio::spawn(async move {
            while !stop.load(Ordering::SeqCst) {
                sent.fetch_add(1, Ordering::SeqCst);
                if !answers(addr).await {
                    lost.fetch_add(1, Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    };
    // 1. A bind that fails (an address this host does not hold): nothing changes, nothing is pending.
    let bad = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 5300);
    let e = preview_apply(&engine, &a, value(&[old.addr, bad]))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::Conflict, "{e:?}");
    assert!(engine.status_local().pending.is_none());
    assert!(answers(old.addr).await);
    // 2. A good new listener is staged and served; the admin cancels and it closes.
    let new = loopback(free_udp_port());
    let r = preview_apply(&engine, &a, value(&[old.addr, new]))
        .await
        .unwrap();
    assert_eq!(r.status, "pending");
    assert!(
        answers(new).await,
        "the staged socket answers during the window"
    );
    assert!(answers(old.addr).await);
    engine
        .cancel(&a, r.pending_id.as_deref().unwrap())
        .await
        .unwrap();
    assert!(!answers(new).await, "closed when the change rolled back");
    assert!(answers(old.addr).await);
    // 3. The same change confirmed: the staged socket is adopted, the old one stays.
    let r = preview_apply(&engine, &a, value(&[old.addr, new]))
        .await
        .unwrap();
    let done = engine
        .confirm(&a, r.pending_id.as_deref().unwrap(), r.confirm_token)
        .await
        .unwrap();
    assert_eq!(done.outcome, "confirmed");
    assert!(answers(new).await);
    assert!(answers(old.addr).await);
    stop.store(true, Ordering::SeqCst);
    looper.await.unwrap();
    assert!(
        sent.load(Ordering::SeqCst) > 5,
        "the loop ran across all of it"
    );
    assert_eq!(
        lost.load(Ordering::SeqCst),
        0,
        "not one query lost on the listener that stayed"
    );
    // 4. Removing the first listener closes it, and only it.
    let mut after = cfg.clone();
    after.listen = vec![old.clone(), udp(new)];
    *host.cfg.lock().unwrap() = Some(Arc::new(after));
    let r = preview_apply(&engine, &a, value(&[new])).await.unwrap();
    engine
        .confirm(&a, r.pending_id.as_deref().unwrap(), r.confirm_token)
        .await
        .unwrap();
    assert!(answers(new).await);
    assert!(
        !answers(old.addr).await,
        "the removed listener is closed at the commit"
    );
    drop(apply_tx);
    drop(engine);
    drop(host);
    let mut l = main_loop.await.unwrap();
    l.abort_staged().await;
    crate::gate_host::clear_listeners_for_test();
}

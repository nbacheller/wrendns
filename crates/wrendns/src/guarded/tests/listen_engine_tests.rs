// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-902, DNS-001, CLU-004 (T27.14c; `docs/design/listener-editor.md` sections 2.3 to 2.6) —
//! the `listen` row through the engine, driven with the tests' fake node: the stage and the proof, the
//! commit, the rollback reasons, the lock with `listen-access`, `would_disconnect_you`, and the
//! `preview_stale` at confirm. The sockets themselves are the server's own tests (T27.14a).

use super::*;

fn l(proto: &str, addr: &str) -> Value {
    json!({"proto": proto, "addr": addr})
}

fn defaults() -> Vec<Value> {
    vec![
        l("udp", "0.0.0.0:53"),
        l("tcp", "0.0.0.0:53"),
        l("udp", "[::]:53"),
        l("tcp", "[::]:53"),
    ]
}

fn value(extra: &[Value]) -> Value {
    let mut all = defaults();
    all.extend(extra.iter().cloned());
    json!({"listeners": all})
}

fn ids(a: &GuardedApplied) -> (String, Option<String>) {
    (a.pending_id.clone().unwrap(), a.confirm_token.clone())
}

fn access_value() -> Value {
    json!({"listeners": defaults().into_iter().map(|mut v| { v["require_client_id"] = Value::Null; v }).collect::<Vec<_>>()})
}

// A listener change is staged next to the running ones, proved by the node's own query to the new
// socket (no request has to arrive anywhere), and committed: the entry written, the reload run, the
// staged sockets kept.
#[tokio::test(start_paused = true)]
async fn api_902_listen_change_staged_proved_and_committed() {
    let n = solo();
    let a = admin("alice", 5);
    let p = preview(
        &n.engine,
        &a,
        "listen",
        value(&[l("udp", "127.0.0.1:5300")]),
    )
    .await
    .unwrap();
    assert_eq!(p.mode, "window");
    assert_eq!(p.phrase, "pi-a listen");
    assert!(!p.weakening);
    assert!(
        p.listeners
            .iter()
            .any(|x| x.change == "added" && x.listener == "udp://127.0.0.1:5300")
    );
    let r = n
        .engine
        .apply(
            &a,
            "listen",
            apply_req(&p, value(&[l("udp", "127.0.0.1:5300")])),
        )
        .await
        .unwrap();
    assert_eq!(r.status, "pending");
    assert_eq!(r.proof.as_deref(), Some("new_socket"));
    assert!(
        r.new_address.is_none(),
        "nothing to open: the API did not move"
    );
    let lists = n.host.staged_lists.lock().unwrap().clone();
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].len(), 5);
    assert!(
        lists[0]
            .iter()
            .all(|x| x.require_client_id.is_none() && !x.proxy_protocol)
    );
    assert!(
        store::for_node(&n.engine.state, "pi-a").is_empty(),
        "nothing is written yet"
    );
    let (pid, token) = ids(&r);
    tokio::task::yield_now().await;
    let view = n.engine.pending_view(&a, &pid, None).unwrap();
    assert_eq!(view.probes.len(), 1);
    assert_eq!(view.probes[0].listener, "udp://127.0.0.1:5300");
    let done = n.engine.confirm(&a, &pid, token).await.unwrap();
    assert_eq!(done.outcome, "confirmed");
    assert_eq!(n.host.commits.load(Ordering::SeqCst), 1);
    assert!(
        n.host.reloads.load(Ordering::SeqCst) >= 1,
        "the reload adopts the staged sockets"
    );
    assert_eq!(n.host.aborts.load(Ordering::SeqCst), 0);
    let e = store::for_node(&n.engine.state, "pi-a");
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].id, "listen");
    assert_eq!(n.audits("settings.guarded").len(), 1);
}

// A cancel closes only what the change opened and writes nothing.
#[tokio::test(start_paused = true)]
async fn api_902_listen_cancel_aborts_the_staged_sockets() {
    let n = solo();
    let a = admin("alice", 5);
    let r = change(
        &n.engine,
        &a,
        "listen",
        value(&[l("udp", "127.0.0.1:5300")]),
    )
    .await
    .unwrap();
    let (pid, _) = ids(&r);
    let res = n.engine.cancel(&a, &pid).await.unwrap();
    assert_eq!(res.reason.as_deref(), Some("cancelled"));
    assert_eq!(n.host.aborts.load(Ordering::SeqCst), 1);
    assert_eq!(n.host.commits.load(Ordering::SeqCst), 0);
    assert!(store::for_node(&n.engine.state, "pi-a").is_empty());
}

// Expiry rolls it back the same way.
#[tokio::test(start_paused = true)]
async fn api_902_listen_expiry_rolls_back() {
    let n = solo();
    let a = admin("alice", 5);
    change(
        &n.engine,
        &a,
        "listen",
        value(&[l("udp", "127.0.0.1:5300")]),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(61)).await;
    assert!(n.engine.status_local().pending.is_none());
    assert_eq!(n.host.aborts.load(Ordering::SeqCst), 1);
    assert_eq!(
        n.audits("settings.guarded_rolled_back")[0]["reason"],
        "expired"
    );
}

// A failed bind changes nothing: the apply answers with the address and the OS error, audits
// `bind_failed`, and no change is pending.
#[tokio::test(start_paused = true)]
async fn api_902_listen_bind_failure_changes_nothing() {
    let n = solo();
    let a = admin("alice", 5);
    *n.host.stage_error.lock().unwrap() = Some(crate::server::WindowError {
        reason: "bind_failed",
        detail: "udp 203.0.113.9:5300: Cannot assign requested address".to_owned(),
    });
    let e = change(
        &n.engine,
        &a,
        "listen",
        value(&[l("udp", "127.0.0.1:5300")]),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, Code::Conflict);
    assert!(
        e.detail.contains("Cannot assign requested address"),
        "{}",
        e.detail
    );
    assert!(n.engine.status_local().pending.is_none());
    assert_eq!(
        n.audits("settings.guarded_rolled_back")[0]["reason"],
        "bind_failed"
    );
    assert!(store::for_node(&n.engine.state, "pi-a").is_empty());
}

// A commit the node could not keep (the file took the listeners over, or a swap failed) rolls back
// under the reason the server gave, removes the entry, and reloads so the previous list is put back.
#[tokio::test(start_paused = true)]
async fn api_902_listen_commit_failure_maps_the_reason() {
    for (reason, detail) in [
        ("cancelled", "the file now sets the listeners"),
        ("commit_failed", "dot 203.0.113.9:853: address in use"),
    ] {
        let n = solo();
        let a = admin("alice", 5);
        let r = change(
            &n.engine,
            &a,
            "listen",
            value(&[l("udp", "127.0.0.1:5300")]),
        )
        .await
        .unwrap();
        let (pid, token) = ids(&r);
        *n.host.commit_error.lock().unwrap() = Some(crate::server::WindowError {
            reason: if reason == "cancelled" {
                "cancelled"
            } else {
                "commit_failed"
            },
            detail: detail.to_owned(),
        });
        let reloads = n.host.reloads.load(Ordering::SeqCst);
        let e = n.engine.confirm(&a, &pid, token).await.unwrap_err();
        assert_eq!(e.code, Code::Internal, "{reason}");
        assert!(n.engine.status_local().pending.is_none(), "{reason}");
        assert!(
            store::for_node(&n.engine.state, "pi-a").is_empty(),
            "{reason}: the entry is removed"
        );
        assert!(
            n.host.reloads.load(Ordering::SeqCst) >= reloads + 2,
            "{reason}: reloaded to apply and again to put the previous list back"
        );
        assert_eq!(
            n.audits("settings.guarded_rolled_back").last().unwrap()["reason"],
            reason
        );
        assert!(
            n.audits("settings.guarded").is_empty(),
            "{reason}: nothing confirmed"
        );
    }
}

// A reload that fails at commit keeps the old listeners and rolls back as commit_failed.
#[tokio::test(start_paused = true)]
async fn api_902_listen_failed_reload_at_commit_rolls_back() {
    let n = solo();
    let a = admin("alice", 5);
    let r = change(
        &n.engine,
        &a,
        "listen",
        value(&[l("udp", "127.0.0.1:5300")]),
    )
    .await
    .unwrap();
    let (pid, token) = ids(&r);
    n.host.reload_ok.store(false, Ordering::SeqCst);
    assert!(n.engine.confirm(&a, &pid, token).await.is_err());
    assert_eq!(
        n.audits("settings.guarded_rolled_back")[0]["reason"],
        "commit_failed"
    );
    assert!(store::for_node(&n.engine.state, "pi-a").is_empty());
}

// A removal-only change binds nothing: the proof is that the listeners that stay still answer.
#[tokio::test(start_paused = true)]
async fn api_902_listen_removal_only_probes_the_listeners_that_stay() {
    let n = solo();
    let a = admin("alice", 5);
    let mut cfg = Config::default();
    cfg.api.confirm_window_secs = 60;
    cfg.listen.extend(
        super::super::listen::parse(&json!({"listeners": [l("udp", "127.0.0.1:5300")]})).unwrap(),
    );
    *n.host.cfg.lock().unwrap() = Arc::new(cfg);
    let r = change(&n.engine, &a, "listen", value(&[])).await.unwrap();
    let (pid, token) = ids(&r);
    tokio::task::yield_now().await;
    let view = n.engine.pending_view(&a, &pid, None).unwrap();
    assert_eq!(view.probes.len(), 4, "every listener that stays");
    n.host
        .probe_answers
        .lock()
        .unwrap()
        .insert("udp://127.0.0.1:53".to_owned(), Err("never".to_owned()));
    // A wildcard is asked on loopback; the one that stays failing refuses the confirm.
    let e = n.engine.confirm(&a, &pid, token.clone()).await.unwrap_err();
    assert_eq!(e.code, Code::Forbidden);
    assert!(e.detail.contains("udp://127.0.0.1:53"), "{}", e.detail);
    n.host.probe_answers.lock().unwrap().clear();
    let done = n.engine.confirm(&a, &pid, token).await.unwrap();
    assert_eq!(done.outcome, "confirmed");
}

// `would_disconnect_you`: no DNS listener at all, and no UDP or TCP listener on port 53 for a family
// the node answers on today. The detail says which.
#[tokio::test(start_paused = true)]
async fn api_902_would_disconnect_refused() {
    let n = solo();
    let a = admin("alice", 5);
    let e = preview(&n.engine, &a, "listen", json!({"listeners": []}))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::WouldDisconnectYou);
    assert!(e.detail.contains("no DNS listener"), "{}", e.detail);
    let no_udp4: Vec<Value> = defaults().into_iter().skip(1).collect();
    let e = preview(&n.engine, &a, "listen", json!({"listeners": no_udp4}))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::WouldDisconnectYou);
    assert!(
        e.detail.contains("no UDP listener on port 53 for IPv4"),
        "{}",
        e.detail
    );
    assert!(n.engine.status_local().pending.is_none());
}

// `listen-access` is refused (409 `guarded_change_pending`) while a `listen` window is pending, at
// the preview, and goes through again when the window ends.
#[tokio::test(start_paused = true)]
async fn api_902_listen_access_refused_during_a_listen_window() {
    let n = solo();
    let a = admin("alice", 5);
    // Before the window it is fine.
    assert!(
        preview(&n.engine, &a, "listen-access", access_value())
            .await
            .is_ok()
    );
    let r = change(
        &n.engine,
        &a,
        "listen",
        value(&[l("udp", "127.0.0.1:5300")]),
    )
    .await
    .unwrap();
    let (pid, _) = ids(&r);
    assert_eq!(
        code(preview(&n.engine, &a, "listen-access", access_value()).await),
        Code::GuardedChangePending
    );
    n.engine.cancel(&a, &pid).await.unwrap();
    assert!(
        preview(&n.engine, &a, "listen-access", access_value())
            .await
            .is_ok()
    );
}

// A preview made before the window opened cannot sneak in at apply either.
#[tokio::test(start_paused = true)]
async fn api_902_listen_access_apply_refused_during_a_listen_window() {
    let n = solo();
    let a = admin("alice", 5);
    let early = preview(&n.engine, &a, "listen-access", access_value())
        .await
        .unwrap();
    change(
        &n.engine,
        &a,
        "listen",
        value(&[l("udp", "127.0.0.1:5300")]),
    )
    .await
    .unwrap();
    assert_eq!(
        code(
            n.engine
                .apply(&a, "listen-access", apply_req(&early, access_value()))
                .await
        ),
        Code::GuardedChangePending
    );
}

// A second change while one is pending is refused as for any window row.
#[tokio::test(start_paused = true)]
async fn api_902_listen_one_pending_change_per_node() {
    let n = solo();
    let a = admin("alice", 5);
    change(
        &n.engine,
        &a,
        "listen",
        value(&[l("udp", "127.0.0.1:5300")]),
    )
    .await
    .unwrap();
    assert_eq!(
        code(
            preview(
                &n.engine,
                &a,
                "listen",
                value(&[l("udp", "127.0.0.1:5301")])
            )
            .await
        ),
        Code::GuardedChangePending
    );
}

// A value that is not the row's is a 422 at the preview, with the sentence that names where the field
// is set.
#[tokio::test(start_paused = true)]
async fn api_902_listen_preview_refuses_foreign_fields() {
    let n = solo();
    let a = admin("alice", 5);
    let mut v = value(&[]);
    v["listeners"][1]["proxyProtocol"] = json!(true);
    let e = preview(&n.engine, &a, "listen", v).await.unwrap_err();
    assert_eq!(e.code, Code::InvalidConfig);
    assert!(e.detail.contains("configuration file only"), "{}", e.detail);
}

// ---- preview_stale at confirm ------------------------------------------------------------

struct StaleGuard {
    stale: AtomicBool,
}

impl WindowGuard for StaleGuard {
    fn commit(&self) -> BoxFuture<Result<(), Problem>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn abort(&self) -> BoxFuture<()> {
        Box::pin(std::future::ready(()))
    }
    fn stale(&self) -> Option<String> {
        self.stale
            .load(Ordering::SeqCst)
            .then(|| "this host's addresses changed since the preview".to_owned())
    }
}

struct StaleApplier(Arc<StaleGuard>);

impl Applier for StaleApplier {
    fn current(&self, _cfg: &Config) -> Value {
        Value::Null
    }
    fn check(&self, _cx: &CheckCx<'_>) -> Result<Checked, Problem> {
        Ok(Checked::default())
    }
    fn stage(
        &self,
        _host: Arc<dyn Host>,
        _node: String,
        _value: Value,
    ) -> BoxFuture<Result<Staged, Problem>> {
        let guard = Arc::clone(&self.0);
        Box::pin(std::future::ready(Ok(Staged {
            guard,
            proof_addr: None,
            new_address: None,
            pending_proxies: None,
            dns_probes: vec![DnsProbe {
                proto: wrendns_config::ListenProto::Udp,
                addr: "192.0.2.1:53".parse().unwrap(),
                path: None,
                gated: false,
                evidence: None,
            }],
        })))
    }
}

// REQ: API-902 (design 4) — when the host's facts changed between the stage and the confirm, the
// confirm is 409 `preview_stale`, nothing is written, and the window runs on until cancelled.
#[tokio::test(start_paused = true)]
async fn api_902_listen_preview_stale_when_the_host_changed() {
    let n = solo();
    let a = admin("alice", 5);
    let guard = Arc::new(StaleGuard {
        stale: AtomicBool::new(false),
    });
    let engine = Engine::new(
        "pi-a".to_owned(),
        Arc::clone(&n.engine.state),
        Arc::clone(&n.host) as Arc<dyn Host>,
        vec![
            RowDef {
                row: R_WIN,
                applier: Arc::new(StaleApplier(Arc::clone(&guard))),
            },
            RowDef {
                row: R_RESTART,
                applier: Arc::new(NoOp),
            },
        ],
        Supervisor {
            kind: "systemd".to_owned(),
            how: "test".to_owned(),
        },
    );
    let r = change(&engine, &a, "t-win", json!({"label": "x"}))
        .await
        .unwrap();
    let (pid, token) = ids(&r);
    guard.stale.store(true, Ordering::SeqCst);
    let e = engine.confirm(&a, &pid, token.clone()).await.unwrap_err();
    assert_eq!(e.code, Code::PreviewStale);
    assert!(e.detail.contains("addresses changed"), "{}", e.detail);
    assert!(
        engine.status_local().pending.is_some(),
        "the window runs on"
    );
    assert!(store::for_node(&engine.state, "pi-a").is_empty());
    // The host is back to what the stage saw: the same confirm now works.
    guard.stale.store(false, Ordering::SeqCst);
    assert_eq!(
        engine.confirm(&a, &pid, token).await.unwrap().outcome,
        "confirmed"
    );
}

// REQ: API-902, CLU-006 (design 3) — a listener change made at the primary for another node is
// staged, probed and confirmed at that node: the window, the staged sockets and the probes live on
// the target, the entry is written through the primary under the target's name, and the primary
// stages nothing.
#[tokio::test(start_paused = true)]
async fn api_902_listener_change_on_another_node_confirmed_at_that_node() {
    let (a, b, _c) = cluster();
    let alice = admin("alice", 5);
    let v = value(&[l("udp", "127.0.0.1:5300")]);
    let p = preview_for(&a.engine, &alice, "pi-b", "listen", v.clone())
        .await
        .unwrap();
    assert_eq!(p.node, "pi-b");
    assert_eq!(p.phrase, "pi-b listen");
    assert!(p.listeners.iter().any(|x| x.change == "added"));
    let r = apply_for(&a.engine, &alice, "pi-b", "listen", &p, v)
        .await
        .unwrap();
    assert_eq!(r.status, "pending");
    assert_eq!(r.node, "pi-b");
    assert_eq!(
        b.host.staged_lists.lock().unwrap().len(),
        1,
        "staged on the target"
    );
    assert!(
        a.host.staged_lists.lock().unwrap().is_empty(),
        "not on the primary"
    );
    let (pid, token) = ids(&r);
    // The confirmation goes to the target.
    let done = b.engine.confirm(&alice, &pid, token).await.unwrap();
    assert_eq!(done.outcome, "confirmed");
    assert_eq!(b.host.commits.load(Ordering::SeqCst), 1);
    assert_eq!(a.host.commits.load(Ordering::SeqCst), 0);
    let pstate = a.engine.state.clone();
    assert!(
        store::for_node(&pstate, "pi-b")
            .iter()
            .any(|e| e.id == "listen")
    );
    assert!(store::for_node(&pstate, "pi-a").is_empty());
    assert_eq!(b.audits("settings.guarded").len(), 1);
}

// The real guard compares the facts the stage used with a fresh reading.
#[test]
fn api_902_listen_guard_notices_changed_host_facts() {
    use wrendns_config::HostFacts;
    fn private() -> HostFacts {
        HostFacts {
            public_ipv4: Some(false),
            global_ipv6: false,
        }
    }
    fn public() -> HostFacts {
        HostFacts {
            public_ipv4: Some(true),
            global_ipv6: false,
        }
    }
    let n = solo();
    let host = Arc::clone(&n.host) as Arc<dyn Host>;
    let g = super::super::listen::ListenGuard::new(
        Arc::clone(&host),
        "pi-a".to_owned(),
        String::new(),
        private(),
        private,
    );
    assert!(g.stale().is_none());
    let g = super::super::listen::ListenGuard::new(
        host,
        "pi-a".to_owned(),
        String::new(),
        private(),
        public,
    );
    assert!(g.stale().unwrap().contains("addresses changed"));
}

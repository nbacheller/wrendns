// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-902, OBS-020 (T27.14b; ADR-956 section 3, ADR-107; `docs/design/listener-editor.md`
//! sections 2.2 and 2.4) — the DNS probe proof in the engine, driven with the tests' fake node.

use super::*;

const UDP_PROBE: &str = "udp://192.0.2.1:53";

fn probe_value() -> Value {
    json!({"probes": [{"proto": "udp", "addr": "192.0.2.1:53"}]})
}

fn fail_probe(n: &Node, why: &str) {
    n.host
        .probe_answers
        .lock()
        .unwrap()
        .insert(UDP_PROBE.to_owned(), Err(why.to_owned()));
}

fn ids(pending: &GuardedApplied) -> (String, Option<String>) {
    (
        pending.pending_id.clone().unwrap(),
        pending.confirm_token.clone(),
    )
}

// A change with probes and no proof socket is confirmed when every probe answers: refused while one
// fails (403 naming the listener and the error), not counted toward the failure block, accepted once
// it answers; no request has to arrive on a new socket.
#[tokio::test(start_paused = true)]
async fn api_902_listener_proof_is_the_nodes_own_probe() {
    let n = solo();
    let a = admin("alice", 5);
    fail_probe(&n, "timed out");
    let r = change(&n.engine, &a, "t-win", probe_value()).await.unwrap();
    assert_eq!(r.status, "pending");
    assert!(r.new_address.is_none(), "no socket to confirm through");
    let (pid, token) = ids(&r);
    // Six refusals in a row: none counts toward the block of five, so the session is never locked.
    for _ in 0..6 {
        let err = n.engine.confirm(&a, &pid, token.clone()).await.unwrap_err();
        assert_eq!(err.code, Code::Forbidden);
        assert!(
            err.detail
                .contains("udp://192.0.2.1:53 got no answer: timed out"),
            "{}",
            err.detail
        );
    }
    assert!(
        n.engine.status_local().pending.is_some(),
        "the window runs on"
    );
    assert!(store::for_node(&n.engine.state, "pi-a").is_empty());
    // It answers now: the same confirm is accepted.
    n.host.probe_answers.lock().unwrap().clear();
    let done = n.engine.confirm(&a, &pid, token).await.unwrap();
    assert_eq!(done.outcome, "confirmed");
    assert_eq!(store::for_node(&n.engine.state, "pi-a").len(), 1);
}

// On a gated listener the gate's own refusal is the answer.
#[tokio::test(start_paused = true)]
async fn api_902_gated_listener_proved_by_its_refusal() {
    let n = solo();
    let a = admin("alice", 5);
    n.host
        .probe_answers
        .lock()
        .unwrap()
        .insert("dot://192.0.2.1:853".to_owned(), Ok(Kind::RefusedByGate));
    let v = json!({"probes": [{"proto": "dot", "addr": "192.0.2.1:853", "gated": true}]});
    let r = change(&n.engine, &a, "t-win", v).await.unwrap();
    let (pid, token) = ids(&r);
    tokio::task::yield_now().await;
    let view = n.engine.pending_view(&a, &pid, None).unwrap();
    assert_eq!(view.probes.len(), 1);
    assert_eq!(view.probes[0].listener, "dot://192.0.2.1:853");
    assert_eq!(view.probes[0].state, "refused_by_gate");
    assert_eq!(
        n.engine.confirm(&a, &pid, token).await.unwrap().outcome,
        "confirmed"
    );
}

// The evidence from other hosts is shown and never required (owner decision, 2026-11-26): Confirm is
// accepted with every probe answering and no other host seen.
#[tokio::test(start_paused = true)]
async fn api_902_listener_confirm_does_not_wait_for_evidence() {
    let n = solo();
    let a = admin("alice", 5);
    let r = change(&n.engine, &a, "t-win", probe_value()).await.unwrap();
    let (pid, token) = ids(&r);
    let view = n.engine.pending_view(&a, &pid, None).unwrap();
    assert_eq!(view.probes[0].other_hosts, 0);
    assert_eq!(
        n.engine.confirm(&a, &pid, token).await.unwrap().outcome,
        "confirmed"
    );
}

// The pending read counts distinct other hosts, leaves the node's own addresses out, and drops the
// table when the window ends (design 2.4).
#[tokio::test(start_paused = true)]
async fn api_902_listener_evidence_counts_other_hosts() {
    let n = solo();
    let a = admin("alice", 5);
    let r = change(&n.engine, &a, "t-win", probe_value()).await.unwrap();
    let (pid, _) = ids(&r);
    let ev = EVIDENCE.with(|e| e.borrow().last().cloned().unwrap());
    ev.note("127.0.0.1".parse().unwrap());
    ev.note("198.51.100.7".parse().unwrap());
    ev.note("198.51.100.7".parse().unwrap());
    ev.note("198.51.100.8".parse().unwrap());
    let view = n.engine.pending_view(&a, &pid, None).unwrap();
    assert_eq!(view.probes[0].other_hosts, 2);
    n.engine.cancel(&a, &pid).await.unwrap();
    assert_eq!(ev.others(), 0, "the table is dropped when the window ends");
}

// The read of a pending change takes the confirm token or the same admin's session; another admin
// and a wrong token are refused and counted; the status listing never names the staged address.
#[tokio::test(start_paused = true)]
async fn api_902_pending_read_checks_who_asks() {
    let n = solo();
    let a = admin("alice", 5);
    let r = change(&n.engine, &a, "t-win", probe_value()).await.unwrap();
    let (pid, token) = ids(&r);
    assert!(
        n.engine.pending_view(&a, &pid, None).is_ok(),
        "the same admin"
    );
    let mut nobody = admin("alice", 5);
    nobody.username = String::new();
    nobody.session = None;
    let v = n
        .engine
        .pending_view(&nobody, &pid, token.as_deref())
        .unwrap();
    assert_eq!(v.setting, "t-win");
    assert!(v.deadline_secs <= 60);
    let wrong =
        |c: &GuardedCaller, t: Option<&str>| n.engine.pending_view(c, &pid, t).unwrap_err().code;
    assert_eq!(wrong(&nobody, Some("wrong")), Code::Forbidden);
    assert_eq!(wrong(&nobody, None), Code::Forbidden);
    assert_eq!(wrong(&admin("bob", 5), None), Code::Forbidden);
    assert_eq!(
        n.engine.pending_view(&a, "nope", None).unwrap_err().code,
        Code::NotFound
    );
    let listing = serde_json::to_string(&n.engine.status_local()).unwrap();
    assert!(!listing.contains("192.0.2.1"), "{listing}");
    // Wrong tries count toward the block like a wrong confirm.
    for _ in 0..3 {
        let _ = wrong(&nobody, Some("wrong"));
    }
    assert_eq!(wrong(&nobody, token.as_deref()), Code::RateLimited);
}

// The probe runs right after the stage and then on every interval while the window is open, shows
// its last result, and stops when the window ends.
#[tokio::test(start_paused = true)]
async fn api_902_probe_runs_in_the_window_and_stops_after() {
    let n = solo();
    n.engine.set_probe_every(Duration::from_secs(5));
    let a = admin("alice", 5);
    fail_probe(&n, "connection refused");
    let r = change(&n.engine, &a, "t-win", probe_value()).await.unwrap();
    let (pid, _) = ids(&r);
    tokio::task::yield_now().await;
    assert_eq!(
        n.host.probe_calls.load(Ordering::SeqCst),
        1,
        "right after the bind"
    );
    let v = n.engine.pending_view(&a, &pid, None).unwrap();
    assert_eq!(v.probes[0].state, "no_answer");
    assert_eq!(v.probes[0].error.as_deref(), Some("connection refused"));
    assert!(v.probes[0].at.is_some());
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    assert_eq!(n.host.probe_calls.load(Ordering::SeqCst), 2);
    n.host.probe_answers.lock().unwrap().clear();
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    let v = n.engine.pending_view(&a, &pid, None).unwrap();
    assert_eq!(v.probes[0].state, "answered");
    n.engine.cancel(&a, &pid).await.unwrap();
    let after = n.host.probe_calls.load(Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(20)).await;
    tokio::task::yield_now().await;
    assert_eq!(n.host.probe_calls.load(Ordering::SeqCst), after, "stopped");
}

// A change with a proof socket and no probes behaves as before, and the window's temporary listener
// serves no read of a pending change.
#[test]
fn api_902_proof_listener_does_not_serve_the_pending_read() {
    use axum::http::Method;
    assert!(!super::super::prod::proof_allowed(
        &Method::GET,
        "/api/v1/guarded/pending/abc"
    ));
}

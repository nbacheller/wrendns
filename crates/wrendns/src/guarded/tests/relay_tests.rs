// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-904, API-902, CLU-004 (T27.14g; ADR-956 §5 as amended, ADR-1098 point 3, ADR-1116) - the
//! confirm the primary relays for a `listen` change on another node, driven on the tests' fake
//! cluster: a primary `pi-a` and two replicas. The node's checks run on the node's engine with
//! assertions built here, so each refusal is the node's own; the real two-node channel is the
//! three-node run on `main`.

use super::*;
use crate::guarded::assertion::{RELAY_PURPOSE, RelayAssertion, RelayToken, SignedRelay};
use crate::guarded::engine::value_digest;

fn l(proto: &str, addr: &str) -> Value {
    json!({"proto": proto, "addr": addr})
}

fn value(extra: &[Value]) -> Value {
    let mut all = vec![
        l("udp", "0.0.0.0:53"),
        l("tcp", "0.0.0.0:53"),
        l("udp", "[::]:53"),
        l("tcp", "[::]:53"),
    ];
    all.extend(extra.iter().cloned());
    json!({"listeners": all})
}

/// A `listen` change for `pi-b`, applied through the primary and waiting for its confirm.
struct Case {
    a: Node,
    b: Node,
    _c: Node,
    alice: GuardedCaller,
    pid: String,
    token: String,
    preview_id: String,
    digest: String,
}

async fn case_with(extra: &[Value]) -> Case {
    let (a, b, c) = cluster();
    let alice = admin("alice", 5);
    let v = value(extra);
    let p = preview_for(&a.engine, &alice, "pi-b", "listen", v.clone())
        .await
        .unwrap();
    let r = apply_for(&a.engine, &alice, "pi-b", "listen", &p, v.clone())
        .await
        .unwrap();
    assert_eq!(r.status, "pending");
    Case {
        a,
        b,
        _c: c,
        alice,
        pid: r.pending_id.unwrap(),
        token: r.confirm_token.unwrap(),
        preview_id: p.preview_id,
        digest: value_digest(&v),
    }
}

async fn case() -> Case {
    case_with(&[l("udp", "127.0.0.1:5300")]).await
}

/// What the primary would sign for this change, ready to be altered.
fn assertion(c: &Case) -> RelayAssertion {
    RelayAssertion {
        purpose: RELAY_PURPOSE.to_owned(),
        setting: "listen".to_owned(),
        node: "pi-b".to_owned(),
        pending_id: c.pid.clone(),
        preview_id: c.preview_id.clone(),
        value_digest: c.digest.clone(),
        admin: "alice".to_owned(),
        role: "admin".to_owned(),
        session_digest: "s1".to_owned(),
        signed_in_at: Some(now().saturating_sub(5)),
        remote: Some("192.0.2.10".to_owned()),
        issuer: "pi-a".to_owned(),
        issued_at: now(),
        expires_at: now() + 30,
        nonce: crate::guarded::random_id(16),
    }
}

fn sign_as(signer: &str, a: RelayAssertion) -> SignedRelay {
    let sig = blake3::keyed_hash(&key_of(signer), &a.canonical())
        .as_bytes()
        .to_vec();
    SignedRelay { assertion: a, sig }
}

/// Sends a relayed confirm to `pi-b` as `sender`.
async fn send(c: &Case, sender: &str, signed: SignedRelay, token: &str) -> ForwardedAnswer {
    c.b.engine
        .handle_forwarded(
            sender,
            Forwarded {
                op: ForwardedOp::ConfirmRelay {
                    pending: c.pid.clone(),
                    token: RelayToken(token.to_owned()),
                    relay: signed,
                },
                assertion: None,
            },
        )
        .await
}

/// The reason and whether it is counted, of a refused relay.
fn refused(a: &ForwardedAnswer) -> (String, bool) {
    match a {
        ForwardedAnswer::RelayRefused {
            detail, counted, ..
        } => (detail.clone(), *counted),
        other => panic!("expected a refused relay, got {other:?}"),
    }
}

fn confirmed(a: &ForwardedAnswer) -> bool {
    matches!(a, ForwardedAnswer::Result(r) if r.outcome == "confirmed")
}

// The primary relays the admin's confirm: the node confirms (its own probe answers), the entry is
// written through the primary under the node's name, both nodes audit, and the node's audit record
// says how it arrived. No record holds the token.
#[tokio::test(start_paused = true)]
async fn api_902_relayed_listen_confirm_accepted() {
    let c = case().await;
    let r =
        c.a.engine
            .relay_confirm(&c.alice, &c.pid, &c.token)
            .await
            .unwrap();
    assert_eq!(r.outcome, "confirmed");
    assert_eq!(r.node, "pi-b");
    assert_eq!(c.b.host.commits.load(Ordering::SeqCst), 1);
    assert_eq!(
        c.a.host.commits.load(Ordering::SeqCst),
        0,
        "not on the primary"
    );
    assert!(
        store::for_node(&c.a.engine.state, "pi-b")
            .iter()
            .any(|e| e.id == "listen"),
        "written through the primary"
    );
    // The primary's records: one before the send, one after.
    let on_a = c.a.audits("settings.guarded_confirm_relayed");
    assert_eq!(on_a.len(), 2);
    assert_eq!(on_a[0]["outcome"], "sent");
    assert_eq!(on_a[1]["outcome"], "confirmed");
    assert_eq!(on_a[0]["pendingId"], c.pid.as_str());
    assert_eq!(on_a[0]["valueDigest"], c.digest.as_str());
    // The node's: `settings.guarded` with the way it arrived.
    let on_b = c.b.audits("settings.guarded");
    assert_eq!(on_b.len(), 1);
    assert_eq!(on_b[0]["outcome"], "confirmed");
    assert_eq!(on_b[0]["confirmedVia"], "primary");
    assert_eq!(on_b[0]["relayedBy"], "pi-a");
    assert_eq!(on_b[0]["relayNonce"].as_str().unwrap().len(), 32);
    assert_eq!(on_a[0]["nonce"], on_b[0]["relayNonce"]);
    // The token is in no audit record on either node.
    for node in [&c.a, &c.b] {
        let all = format!("{:?}", node.host.audits.lock().unwrap());
        assert!(!all.contains(&c.token), "the token is in an audit record");
    }
    // The primary forgot it: a second relay is not found.
    assert_eq!(
        code(c.a.engine.relay_confirm(&c.alice, &c.pid, &c.token).await),
        Code::NotFound
    );
}

// Only `listen`: the primary refuses any other window row (and sends nothing), and the node refuses
// an assertion built for one, and one built for `listen` against a pending change of another row.
#[tokio::test(start_paused = true)]
async fn api_902_relay_refused_for_other_rows() {
    let (a, b, _c) = cluster();
    let alice = admin("alice", 5);
    for (row, v) in [
        ("t-win", json!({"port": 0, "label": "x"})),
        ("t-proxy", json!({"proxies": ["10.0.0.1"]})),
        ("trusted-proxies", json!({"proxies": ["10.0.0.0/8"]})),
    ] {
        let p = preview_for(&a.engine, &alice, "pi-b", row, v.clone())
            .await
            .unwrap();
        let r = apply_for(&a.engine, &alice, "pi-b", row, &p, v.clone())
            .await
            .unwrap();
        let (pid, token) = (r.pending_id.unwrap(), r.confirm_token.unwrap());
        let before = a.host.net.forwarded.lock().unwrap().len();
        // The primary refuses it and sends nothing.
        let e = a
            .engine
            .relay_confirm(&alice, &pid, &token)
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::RelayRefused, "{row}");
        assert_eq!(
            a.host.net.forwarded.lock().unwrap().len(),
            before,
            "{row}: nothing was sent"
        );
        // The node refuses an assertion that names this row, and one that says `listen` for it.
        for setting in [row, "listen"] {
            let mut asr = RelayAssertion {
                purpose: RELAY_PURPOSE.to_owned(),
                setting: setting.to_owned(),
                node: "pi-b".to_owned(),
                pending_id: pid.clone(),
                preview_id: p.preview_id.clone(),
                value_digest: value_digest(&v),
                admin: "alice".to_owned(),
                role: "admin".to_owned(),
                session_digest: "s".to_owned(),
                signed_in_at: Some(now()),
                remote: None,
                issuer: "pi-a".to_owned(),
                issued_at: now(),
                expires_at: now() + 30,
                nonce: crate::guarded::random_id(16),
            };
            asr.setting = setting.to_owned();
            let ans = b
                .engine
                .handle_forwarded(
                    "pi-a",
                    Forwarded {
                        op: ForwardedOp::ConfirmRelay {
                            pending: pid.clone(),
                            token: RelayToken(token.clone()),
                            relay: sign_as("pi-a", asr),
                        },
                        assertion: None,
                    },
                )
                .await;
            let (why, counted) = refused(&ans);
            assert!(why.contains("DNS listeners"), "{row}/{setting}: {why}");
            assert!(counted, "{row}/{setting}");
        }
        // Still pending: a relay did not confirm it, and a direct confirm still can.
        assert!(b.engine.staged_ids().is_empty());
        b.engine
            .cancel(&alice, &pid)
            .await
            .unwrap_or_else(|e| panic!("{row}: {e:?}"));
    }
    // An immediate row has no window and nothing pending: there is nothing to relay.
    let v = json!({"label": "x"});
    let p = preview_for(&a.engine, &alice, "pi-b", "t-imm", v.clone())
        .await
        .unwrap();
    let r = apply_for(&a.engine, &alice, "pi-b", "t-imm", &p, v)
        .await
        .unwrap();
    assert_eq!(r.status, "applied");
    assert_eq!(
        code(a.engine.relay_confirm(&alice, "nope", "tok").await),
        Code::NotFound
    );
}

// A replica never relays (421), and a replica's signature is not the primary's: the node refuses an
// assertion signed by another member, one that names the primary but was sent by a replica, and one
// whose signature does not verify under the primary's key.
#[tokio::test(start_paused = true)]
async fn api_902_relay_from_replica_refused() {
    let c = case().await;
    let ok_token = c.token.clone();
    // A replica built by another member, sent as that member.
    let forged = sign_as("pi-c", {
        let mut a = assertion(&c);
        a.issuer = "pi-c".to_owned();
        a
    });
    let (why, counted) = refused(&send(&c, "pi-c", forged, &ok_token).await);
    assert!(why.contains("only the primary relays"), "{why}");
    assert!(
        !counted,
        "a sender that is not the primary counts against no change"
    );
    // Naming the primary as the issuer while sending as a replica.
    let (why, _) = refused(&send(&c, "pi-c", sign_as("pi-a", assertion(&c)), &ok_token).await);
    assert!(why.contains("only the primary relays"), "{why}");
    // The primary's name on an assertion a replica signed with its own key.
    let (why, _) = refused(&send(&c, "pi-a", sign_as("pi-c", assertion(&c)), &ok_token).await);
    assert!(why.contains("signature"), "{why}");
    assert_eq!(c.b.host.commits.load(Ordering::SeqCst), 0);
    // The nonce of none of them was used: the primary's real relay is accepted.
    assert!(confirmed(
        &send(&c, "pi-a", sign_as("pi-a", assertion(&c)), &ok_token).await
    ));
}

#[tokio::test(start_paused = true)]
async fn api_902_relay_on_replica_answers_not_primary() {
    let c = case().await;
    let e =
        c.b.engine
            .relay_confirm(&c.alice, &c.pid, &c.token)
            .await
            .unwrap_err();
    assert_eq!(e.code, Code::NotPrimary);
    // A standalone node confirms its own: nothing to relay.
    let n = solo();
    let e = n
        .engine
        .relay_confirm(&admin("alice", 5), "p", "t")
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::RelayRefused);
}

// A relayed confirm is good once: the same assertion replayed is refused, even when the first time
// ended at a probe that had not answered yet.
#[tokio::test(start_paused = true)]
async fn api_902_relay_assertion_single_use() {
    let c = case().await;
    c.b.host.probe_answers.lock().unwrap().insert(
        "udp://127.0.0.1:5300".to_owned(),
        Err("no answer".to_owned()),
    );
    let asr = sign_as("pi-a", assertion(&c));
    let (why, counted) = refused(&send(&c, "pi-a", asr.clone(), &c.token).await);
    assert!(why.starts_with("the node's own query"), "{why}");
    assert!(!counted);
    c.b.host.probe_answers.lock().unwrap().clear();
    let (why, counted) = refused(&send(&c, "pi-a", asr, &c.token).await);
    assert!(why.contains("already used"), "{why}");
    assert!(counted);
    assert!(confirmed(
        &send(&c, "pi-a", sign_as("pi-a", assertion(&c)), &c.token).await
    ));
}

// Stale: an expired assertion, one that lives longer than 30 seconds, one dated ahead, and a change
// that is no longer pending.
#[tokio::test(start_paused = true)]
async fn api_902_relay_assertion_stale_refused() {
    let c = case().await;
    let mut old = assertion(&c);
    old.issued_at = now() - 100;
    old.expires_at = now() - 70;
    let (why, counted) = refused(&send(&c, "pi-a", sign_as("pi-a", old), &c.token).await);
    assert!(why.contains("expired"), "{why}");
    assert!(!counted);
    let mut long = assertion(&c);
    long.expires_at = long.issued_at + 31;
    let (why, _) = refused(&send(&c, "pi-a", sign_as("pi-a", long), &c.token).await);
    assert!(why.contains("30 seconds"), "{why}");
    let mut ahead = assertion(&c);
    ahead.issued_at = now() + 60;
    ahead.expires_at = now() + 80;
    let (why, _) = refused(&send(&c, "pi-a", sign_as("pi-a", ahead), &c.token).await);
    assert!(why.contains("future"), "{why}");
    // Within the 5-second allowance on the node's clock, an assertion just past is accepted.
    let mut edge = assertion(&c);
    edge.issued_at = now() - 33;
    edge.expires_at = now() - 3;
    assert!(confirmed(
        &send(&c, "pi-a", sign_as("pi-a", edge), &c.token).await
    ));
    // The change is gone: nothing is pending under that ID.
    let ans = send(&c, "pi-a", sign_as("pi-a", assertion(&c)), &c.token).await;
    let (why, counted) = refused(&ans);
    assert!(why.contains("no change is pending"), "{why}");
    assert!(!counted);
}

// The binding: another pending ID, preview ID, value digest or admin, and another node.
#[tokio::test(start_paused = true)]
async fn api_902_relay_binding_checked() {
    let c = case().await;
    type Alter = fn(&mut RelayAssertion);
    let alter: [(&str, Alter); 4] = [
        ("pending", |a| a.pending_id = "other".to_owned()),
        ("preview", |a| a.preview_id = "other".to_owned()),
        ("digest", |a| a.value_digest = "00".to_owned()),
        ("admin", |a| a.admin = "bob".to_owned()),
    ];
    for (what, f) in alter {
        let mut a = assertion(&c);
        f(&mut a);
        let (why, counted) = refused(&send(&c, "pi-a", sign_as("pi-a", a), &c.token).await);
        assert!(why.contains("not for this change"), "{what}: {why}");
        assert!(counted, "{what}");
    }
    // Another node: refused before the pending change is looked at, so not counted.
    let mut other = assertion(&c);
    other.node = "pi-c".to_owned();
    let (why, counted) = refused(&send(&c, "pi-a", sign_as("pi-a", other), &c.token).await);
    assert!(why.contains("another node"), "{why}");
    assert!(!counted);
    // The change itself is untouched, and the right assertion is accepted.
    assert!(confirmed(
        &send(&c, "pi-a", sign_as("pi-a", assertion(&c)), &c.token).await
    ));
}

// The session alone does not do it: the node and the primary both need the change's token.
#[tokio::test(start_paused = true)]
async fn api_902_relay_needs_the_confirm_token() {
    let c = case().await;
    let (why, counted) = refused(&send(&c, "pi-a", sign_as("pi-a", assertion(&c)), "wrong").await);
    assert!(why.contains("token"), "{why}");
    assert!(counted);
    let before = c.a.host.net.forwarded.lock().unwrap().len();
    let e =
        c.a.engine
            .relay_confirm(&c.alice, &c.pid, "wrong")
            .await
            .unwrap_err();
    assert_eq!(e.code, Code::RelayRefused);
    assert!(e.detail.contains("token"));
    assert_eq!(
        c.a.host.net.forwarded.lock().unwrap().len(),
        before,
        "the primary does not send a wrong token"
    );
    // Another admin's session at the primary is refused too.
    let e =
        c.a.engine
            .relay_confirm(&admin("bob", 5), &c.pid, &c.token)
            .await
            .unwrap_err();
    assert_eq!(e.code, Code::RelayRefused);
    assert!(e.detail.contains("another admin"));
    assert!(c.a.audits("settings.guarded_confirm_relayed").is_empty());
}

// The node's own probe is still the proof: refused while it fails (not counted, the primary does not
// count it either), accepted once it answers.
#[tokio::test(start_paused = true)]
async fn api_902_relay_still_needs_the_nodes_own_probe() {
    let c = case().await;
    c.b.host.probe_answers.lock().unwrap().insert(
        "udp://127.0.0.1:5300".to_owned(),
        Err("no answer".to_owned()),
    );
    // More than the five failures a session may make and the five refusals a change takes: none of
    // these is counted.
    for _ in 0..7 {
        let e =
            c.a.engine
                .relay_confirm(&c.alice, &c.pid, &c.token)
                .await
                .unwrap_err();
        assert_eq!(e.code, Code::RelayRefused);
        assert!(
            e.detail.starts_with("the node's own query to "),
            "{}",
            e.detail
        );
    }
    assert_eq!(c.b.host.commits.load(Ordering::SeqCst), 0);
    c.b.host.probe_answers.lock().unwrap().clear();
    let r =
        c.a.engine
            .relay_confirm(&c.alice, &c.pid, &c.token)
            .await
            .unwrap();
    assert_eq!(r.outcome, "confirmed");
}

// A weakening change needs a sign-in within 10 minutes at both ends.
#[tokio::test(start_paused = true)]
async fn api_902_relay_weakening_needs_recent_sign_in() {
    // A plain UDP listener on a public address weakens (ADR-1098 point 2).
    let c = case_with(&[l("udp", "8.8.8.8:5300")]).await;
    // The primary: the same admin, signed in 11 minutes ago, is asked to sign in again.
    let old = admin("alice", 660);
    let e =
        c.a.engine
            .relay_confirm(&old, &c.pid, &c.token)
            .await
            .unwrap_err();
    assert_eq!(e.code, Code::ReauthRequired);
    assert!(c.a.audits("settings.guarded_confirm_relayed").is_empty());
    // The node: an assertion that says the sign-in is old is refused on its own account.
    let mut stale = assertion(&c);
    stale.signed_in_at = Some(now() - 660);
    let (why, counted) = refused(&send(&c, "pi-a", sign_as("pi-a", stale), &c.token).await);
    assert!(why.contains("10 minutes"), "{why}");
    assert!(counted);
    let mut none = assertion(&c);
    none.signed_in_at = None;
    let (why, _) = refused(&send(&c, "pi-a", sign_as("pi-a", none), &c.token).await);
    assert!(why.contains("10 minutes"), "{why}");
    // Signed in recently, it goes through.
    let r =
        c.a.engine
            .relay_confirm(&c.alice, &c.pid, &c.token)
            .await
            .unwrap();
    assert_eq!(r.outcome, "confirmed");
}

// Five refused relays and the node stops looking at them for that change; the direct confirm stays.
#[tokio::test(start_paused = true)]
async fn api_902_relay_attempts_capped() {
    let c = case().await;
    for i in 0..5 {
        let mut a = assertion(&c);
        a.value_digest = format!("bad{i}");
        let (_, counted) = refused(&send(&c, "pi-a", sign_as("pi-a", a), &c.token).await);
        assert!(counted);
    }
    // Even a correct relay is now refused, without being looked at.
    let (why, counted) = refused(&send(&c, "pi-a", sign_as("pi-a", assertion(&c)), &c.token).await);
    assert!(why.contains("too many"), "{why}");
    assert!(!counted);
    assert_eq!(c.b.host.commits.load(Ordering::SeqCst), 0);
    // The direct confirm at the node still works.
    let done =
        c.b.engine
            .confirm(&c.alice, &c.pid, Some(c.token.clone()))
            .await
            .unwrap();
    assert_eq!(done.outcome, "confirmed");
    // A refusal at the node was audited (no values, no token) as a refusal.
    let refusals = c.b.audits("settings.guarded_refused");
    assert_eq!(refusals.len(), 6);
    assert_eq!(refusals[0]["code"], "relay_refused");
}

// No relay arrives: the window runs out and the change rolls back at the node, which the primary
// cannot change, and a relay that comes after finds nothing; and a node that cannot reach the
// primary to write the entry answers `primary_unreachable` and the window runs on.
#[tokio::test(start_paused = true)]
async fn api_902_relayed_change_rolls_back_at_expiry() {
    let c = case().await;
    c.a.host.net.primary_down.store(true, Ordering::SeqCst);
    let e =
        c.a.engine
            .relay_confirm(&c.alice, &c.pid, &c.token)
            .await
            .unwrap_err();
    assert_eq!(e.code, Code::PrimaryUnreachable);
    assert_eq!(c.b.host.commits.load(Ordering::SeqCst), 0);
    // Nobody confirms; the window ends.
    tokio::time::sleep(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    let rolled = c.b.audits("settings.guarded_rolled_back");
    assert_eq!(rolled.len(), 1);
    assert_eq!(rolled[0]["reason"], "expired");
    assert!(c.b.audits("settings.guarded").is_empty());
    assert!(store::for_node(&c.a.engine.state, "pi-b").is_empty());
    let e =
        c.a.engine
            .relay_confirm(&c.alice, &c.pid, &c.token)
            .await
            .unwrap_err();
    assert!(
        matches!(e.code, Code::RelayRefused | Code::NotFound),
        "{:?}",
        e.code
    );
}

// Mixed cluster (CLU-010): a member whose build does not announce the relay is refused 409
// `upgrade_required` naming it, before the audit row and before anything is sent.
#[tokio::test(start_paused = true)]
async fn api_902_relay_to_a_member_without_the_feature_is_upgrade_required() {
    let c = case().await;
    for m in c.a.host.net.members.lock().unwrap().iter_mut() {
        if m.name == "pi-b" {
            m.relay = false;
        }
    }
    let before = c.a.host.net.forwarded.lock().unwrap().len();
    let e =
        c.a.engine
            .relay_confirm(&c.alice, &c.pid, &c.token)
            .await
            .unwrap_err();
    assert_eq!(e.code, Code::UpgradeRequired);
    assert!(e.detail.contains("pi-b"), "{}", e.detail);
    assert!(
        e.detail.contains("the confirm relayed by the primary"),
        "{}",
        e.detail
    );
    assert_eq!(c.a.host.net.forwarded.lock().unwrap().len(), before);
    assert!(c.a.audits("settings.guarded_confirm_relayed").is_empty());
    // The direct confirm is unaffected.
    assert_eq!(
        c.b.engine
            .confirm(&c.alice, &c.pid, Some(c.token.clone()))
            .await
            .unwrap()
            .outcome,
        "confirmed"
    );
}

// The primary does not relay to itself: a change it holds is confirmed here, directly.
#[tokio::test(start_paused = true)]
async fn api_902_relay_refused_for_the_primarys_own_change() {
    let (a, _b, _c) = cluster();
    let alice = admin("alice", 5);
    let v = value(&[l("udp", "127.0.0.1:5300")]);
    let p = preview(&a.engine, &alice, "listen", v.clone())
        .await
        .unwrap();
    let r = a
        .engine
        .apply(&alice, "listen", apply_req(&p, v))
        .await
        .unwrap();
    let (pid, token) = (r.pending_id.unwrap(), r.confirm_token.unwrap());
    let e = a
        .engine
        .relay_confirm(&alice, &pid, &token)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::RelayRefused);
    assert!(e.detail.contains("this node itself"), "{}", e.detail);
}

// No audit row, no relay: when the primary cannot write its record, nothing is sent.
#[tokio::test(start_paused = true)]
async fn api_902_relay_is_not_sent_when_the_audit_cannot_be_written() {
    let c = case().await;
    c.a.host.audit_ok.store(false, Ordering::SeqCst);
    let before = c.a.host.net.forwarded.lock().unwrap().len();
    let e =
        c.a.engine
            .relay_confirm(&c.alice, &c.pid, &c.token)
            .await
            .unwrap_err();
    assert_eq!(e.code, Code::Unavailable);
    assert_eq!(c.a.host.net.forwarded.lock().unwrap().len(), before);
    assert_eq!(c.b.host.commits.load(Ordering::SeqCst), 0);
}

// A forwarding assertion's signature never verifies as a relayed confirm, and the token never prints.
#[test]
fn api_902_relay_assertion_has_its_own_signing_domain_and_the_token_is_hidden() {
    let asr = RelayAssertion {
        purpose: RELAY_PURPOSE.to_owned(),
        setting: "listen".to_owned(),
        node: "pi-b".to_owned(),
        pending_id: "p".to_owned(),
        preview_id: "v".to_owned(),
        value_digest: "d".to_owned(),
        admin: "alice".to_owned(),
        role: "admin".to_owned(),
        session_digest: "s".to_owned(),
        signed_in_at: None,
        remote: None,
        issuer: "pi-a".to_owned(),
        issued_at: 1,
        expires_at: 2,
        nonce: "n".to_owned(),
    };
    let bytes = asr.canonical();
    assert!(bytes.starts_with(b"wrendns/guarded/relayed-confirm/v1"));
    // The JSON body alone (what a forwarding assertion's signature would cover) is not what is signed.
    let body = serde_json::to_vec(&asr).unwrap();
    assert_ne!(bytes, body);
    let t = RelayToken("super-secret-token".to_owned());
    assert!(!format!("{t:?}").contains("secret"));
    let op = ForwardedOp::ConfirmRelay {
        pending: "p".to_owned(),
        token: t.clone(),
        relay: sign_as("pi-a", asr),
    };
    assert!(!format!("{op:?}").contains("super-secret"));
    // On the wire it is a plain string, and the operation round-trips.
    let json = serde_json::to_string(&op).unwrap();
    assert!(json.contains("\"op\":\"confirm_relay\""), "{json}");
    assert!(json.contains("\"token\":\"super-secret-token\""), "{json}");
    let back: ForwardedOp = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, ForwardedOp::ConfirmRelay { token, .. } if token == t));
}

// ---- the per-node public address (`api-public-url`; owner decision 2026-11-27, ADR-1116) -------

fn url_value(u: &str) -> Value {
    json!({ "url": u })
}

// Set from the primary for another node: weakening (a sign-in within 10 minutes), judged and stored
// for that node, applied there and overlaid into its configuration, which is what it announces.
#[tokio::test(start_paused = true)]
async fn api_902_public_url_is_set_for_another_node_and_overlaid() {
    let (a, b, _c) = cluster();
    let alice = admin("alice", 5);
    let v = url_value("https://pi-b.example.com");
    let p = preview_for(&a.engine, &alice, "pi-b", "api-public-url", v.clone())
        .await
        .unwrap();
    assert_eq!(p.mode, "immediate");
    assert!(p.weakening, "pointing the confirm link elsewhere weakens");
    assert!(
        p.effect.contains("https://pi-b.example.com"),
        "{}",
        p.effect
    );
    assert!(p.warnings.iter().any(|w| w.contains("single-use token")));
    // A sign-in older than 10 minutes cannot apply it.
    let stale = admin("alice", 700);
    let e = apply_for(&a.engine, &stale, "pi-b", "api-public-url", &p, v.clone())
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ReauthRequired);
    let r = apply_for(&a.engine, &alice, "pi-b", "api-public-url", &p, v)
        .await
        .unwrap();
    assert_eq!(r.status, "applied");
    assert_eq!(r.node, "pi-b");
    assert_eq!(b.audits("settings.guarded").len(), 1);
    let entries = store::for_node(&a.engine.state, "pi-b");
    assert!(entries.iter().any(|e| e.id == "api-public-url"));
    assert!(store::for_node(&a.engine.state, "pi-a").is_empty());
    // The overlay puts it into the node's configuration, where the announcement reads it.
    let mut cfg = Config::default();
    super::super::appliers::overlay_with(
        &mut cfg,
        &Config::default(),
        &entries,
        None,
        &defs(true),
        "pi-b",
        false,
    );
    assert_eq!(
        cfg.api
            .public_url
            .as_ref()
            .map(wrendns_config::SafeString::as_str),
        Some("https://pi-b.example.com")
    );
    assert_eq!(
        crate::api_url::announced(&cfg, &["https://192.0.2.7:8443".to_owned()]),
        "https://pi-b.example.com"
    );
}

// An address that is not a plain web address is refused at the preview, with the rule named, and
// nothing is stored; clearing is not weakening.
#[tokio::test(start_paused = true)]
async fn api_902_public_url_is_checked_like_the_announced_address() {
    let n = solo();
    let alice = admin("alice", 5);
    for bad in [
        "https://user:pw@pi-a.example.com",
        "javascript:alert(1)",
        "https://pi-a.example.com/ui",
        "ftp://pi-a.example.com",
        &format!("https://{}", "a".repeat(300)),
    ] {
        let e = preview(&n.engine, &alice, "api-public-url", url_value(bad))
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::InvalidConfig, "{bad}");
        assert!(e.detail.starts_with("`url`: "), "{}", e.detail);
    }
    assert!(store::for_node(&n.engine.state, "pi-a").is_empty());
    let p = preview(&n.engine, &alice, "api-public-url", url_value(""))
        .await
        .unwrap();
    assert!(!p.weakening);
    assert!(p.effect.contains("works out"), "{}", p.effect);
}

// A file that sets `[api] public_url` locks the control (the file wins, ADR-040).
#[tokio::test(start_paused = true)]
async fn api_902_public_url_set_by_file_is_locked() {
    let n = solo();
    let mut file = Config::default();
    file.file_set.push("api.public_url".to_owned());
    *n.host.file_cfg.lock().unwrap() = Arc::new(file);
    let e = preview(
        &n.engine,
        &admin("alice", 5),
        "api-public-url",
        url_value("https://pi-a.example.com"),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, Code::SetByFile);
}

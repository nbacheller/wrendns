// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: OBS-007, API-905 (T40.13, ADR-1107) - the dnstap settings through the real write path
//! (route, plan, store, audit): `[telemetry.dnstap]` as one admin-only, node-managed entry. A
//! viewer, an operator and an agent are refused; a change that copies more out of the process needs
//! a sign-in within the last 10 minutes; the file's bounds hold; the files win; the entry says "restart
//! needed" while the running tap differs; and a member that does not announce the feature holds it.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use wrendns_api::auth::{self, Role};
use wrendns_config::Config;

use crate::credential_tests::{Harness, harness, harness_in, older_primary_and_replica};
use crate::settings_kinds_tests::{call_as, token};

const URL: &str = "/api/v1/dnstap-settings/default";
const ENTRY: &str = "/api/v1/config/entries?kind=dnstap_settings";

fn merged(h: &Harness) -> Config {
    crate::managed::merge(
        &h.src.file_config.load_full(),
        &crate::managed::entries(h.auth.state()),
    )
    .expect("the merged configuration validates")
}

fn with_toml(toml: &str) -> Harness {
    crate::credential_tests::harness_toml(
        toml,
        None,
        vec![wrendns_config::Cidr::parse("127.0.0.0/8").unwrap()],
        auth::Settings::default(),
    )
}

/// A request from the admin's signed-in session, whose sign-in was `age` seconds ago.
fn from_session(
    h: &Harness,
    age: u64,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> Request<Body> {
    let user = h.auth.state().user(h.admin_id).unwrap().unwrap();
    let now = crate::pipeline::unix_now().saturating_sub(age);
    let s = h
        .auth
        .start_session(&user, "127.0.0.1".parse().unwrap(), now)
        .unwrap();
    // The session is idle-fresh: only its creation time is old.
    h.auth
        .state()
        .touch_session(
            &auth::crypto::secret_hash(&s.cookie),
            crate::pipeline::unix_now(),
        )
        .unwrap();
    Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", format!("{}={}", auth::routes::COOKIE, s.cookie))
        .header("x-csrf-token", &s.csrf)
        .header("content-type", "application/json")
        .extension(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            40000,
        ))))
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap()
}

async fn session_call(
    h: &Harness,
    age: u64,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (s, _, t) = h.send(from_session(h, age, method, uri, body)).await;
    (s, serde_json::from_str(&t).unwrap_or(Value::String(t)))
}

fn on() -> Value {
    json!({ "socket": "/run/dnstap.sock", "sample_every": 10, "buffer": 5000 })
}

/// REQ: OBS-007, API-905 (T40.13, AC1) - an admin reads and writes the section; an operator, a
/// viewer and an agent (whatever its scope) are refused, a dry run too; the change is stored,
/// audited with the old and the new values, and read back.
#[tokio::test]
async fn obs_007_dnstap_settings_are_an_admins_as_a_whole() {
    let h = harness("");
    // A change that does not widen the copy (no tap, a smaller queue) needs no sign-in.
    let body = json!({ "buffer": 5000 });
    let op = token(&h, "ops", Role::Operator, None);
    let (s, _, v) = call_as(&h, &op, "PUT", URL, Some(&body), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, _, _) = call_as(&h, &op, "PUT", URL, Some(&json!({})), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "not even a change of nothing");
    let viewer = token(&h, "view", Role::Viewer, None);
    let (s, _, _) = call_as(&h, &viewer, "PUT", URL, Some(&body), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let bot = token(
        &h,
        "bot-owner",
        Role::Admin,
        Some("config:read config:write:special"),
    );
    let (s, _, v) = call_as(&h, &bot, "PUT", URL, Some(&body), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let dry = format!("{URL}?dryRun=true");
    let (s, _, _) = call_as(&h, &bot, "PUT", &dry, Some(&body), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "not even as a dry run");
    assert_eq!(h.auth.state().managed("dnstap_settings").unwrap().len(), 0);

    let (s, _, v) = h.call("PUT", URL, Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(merged(&h).telemetry.dnstap.buffer, 5000);
    assert_eq!(h.auth.state().managed("dnstap_settings").unwrap().len(), 1);
    let (s, _, _) = call_as(&h, &op, "DELETE", URL, None, &[]).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "an operator cannot hand it back either"
    );
    assert_eq!(h.auth.state().managed("dnstap_settings").unwrap().len(), 1);
    let audit = h.audit_text();
    assert!(audit.contains("dnstap_settings.put"), "{audit}");
    assert!(
        audit.contains("before")
            && audit.contains("after")
            && audit.contains("10000")
            && audit.contains("5000"),
        "the old and the new values: {audit}"
    );
    let (s, _, e) = h.call("GET", ENTRY, None).await;
    assert_eq!(s, StatusCode::OK, "{e}");
    assert_eq!(e["items"][0]["source"], "override", "{e}");
    assert_eq!(e["items"][0]["definition"]["buffer"], 5000, "{e}");
    // A viewer may read the entry.
    let (s, _, e) = call_as(&h, &viewer, "GET", ENTRY, None, &[]).await;
    assert_eq!(s, StatusCode::OK, "{e}");
    let (s, _, v) = h.call("DELETE", URL, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(merged(&h).telemetry.dnstap.buffer, 10_000);
}

/// REQ: OBS-007, API-905 (T40.13, AC1, ADR-914) - a change that weakens privacy (the tap turned
/// on, a new target, a kind of exchange added, sampling more often) goes the guarded way: a sign-in
/// within the last 10 minutes. A token never has one; a dry run says so; a change that copies no
/// more (turning it off, a smaller queue) needs none.
#[tokio::test]
async fn obs_007_dnstap_widening_needs_a_recent_sign_in() {
    let h = harness("");
    let dry = format!("{URL}?dryRun=true");
    // The preview goes through and says what the write will need.
    let (s, _, v) = h.call("PUT", &dry, Some(&on())).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let warnings = v["warnings"].to_string();
    assert!(warnings.contains("10 minutes"), "{v}");
    assert!(warnings.contains("restart"), "{v}");
    // A token (even an admin's) cannot do it.
    let (s, _, v) = h.call("PUT", URL, Some(&on())).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "reauth_required", "{v}");
    // A session signed in 11 minutes ago cannot, one signed in 9 minutes ago can.
    let (s, v) = session_call(&h, 11 * 60, "PUT", URL, Some(on())).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "reauth_required", "{v}");
    assert_eq!(h.auth.state().managed("dnstap_settings").unwrap().len(), 0);
    let (s, v) = session_call(&h, 9 * 60, "PUT", URL, Some(on())).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        merged(&h).telemetry.dnstap.socket.as_deref(),
        Some("/run/dnstap.sock")
    );
    // Now every widening needs the sign-in again; the reverse does not.
    let widen = |f: &dyn Fn(&mut Value)| {
        let mut b = on();
        f(&mut b);
        b
    };
    for b in [
        widen(&|b| b["socket"] = json!("/run/other.sock")),
        widen(&|b| {
            b["socket"] = Value::Null;
            b["address"] = json!("tcp://192.0.2.5:6000");
        }),
        widen(&|b| b["forwarder"] = json!(true)),
        widen(&|b| b["resolver"] = json!(true)),
        widen(&|b| b["sample_every"] = json!(1)),
    ] {
        let (s, _, v) = h.call("PUT", URL, Some(&b)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{b}: {v}");
        assert_eq!(v["code"], "reauth_required", "{b}: {v}");
    }
    let (s, _, v) = h
        .call(
            "PUT",
            URL,
            Some(&json!({ "socket": "/run/dnstap.sock", "sample_every": 100, "buffer": 9000 })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "sampling less and a bigger queue: {v}");
    let (s, _, v) = h.call("PUT", URL, Some(&json!({}))).await;
    assert_eq!(s, StatusCode::OK, "the tap turned off: {v}");
    assert!(merged(&h).telemetry.dnstap.socket.is_none());
    // A DELETE that brings a file's tap back is a widening too.
    let h = with_toml("[telemetry.dnstap]\nsocket = \"/run/file.sock\"\n");
    let (s, _, _) = h
        .call(
            "PUT",
            URL,
            Some(&json!({ "socket": "/run/file.sock", "buffer": 500 })),
        )
        .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "same target as the file's, a smaller queue"
    );
    let (s, _, v) = h.call("DELETE", URL, None).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "back to the file's own values: no change in the target: {v}"
    );
}

/// REQ: OBS-007, API-905 (T40.13, AC1) - the values are bounded as the file's validation bounds
/// them (and `buffer` at 1,000,000: the queue is allocated at its full size), a socket and an
/// address together are refused, an unknown field is refused, and nothing is stored.
#[tokio::test]
async fn obs_007_dnstap_values_are_bounded() {
    let h = harness("");
    for (body, needle) in [
        (json!({ "buffer": 99 }), "buffer"),
        (json!({ "buffer": 1_000_001 }), "buffer"),
        (json!({ "sample_every": 0 }), "sample_every"),
        (
            json!({ "socket": "/run/a.sock", "address": "tcp://192.0.2.5:6000" }),
            "not both",
        ),
        (json!({ "address": "192.0.2.5" }), "tcp://host:port"),
        (json!({ "colour": "red" }), "colour"),
        (json!({ "buffer": -1 }), "u32"),
    ] {
        let (s, _, v) = h.call("PUT", URL, Some(&body)).await;
        assert!(
            s == StatusCode::UNPROCESSABLE_ENTITY || s == StatusCode::BAD_REQUEST,
            "{body}: {s} {v}"
        );
        assert!(v.to_string().contains(needle), "{body}: {v}");
    }
    assert_eq!(h.auth.state().managed("dnstap_settings").unwrap().len(), 0);
    for ok in [100, 1_000_000] {
        let (s, _, v) = h.call("PUT", URL, Some(&json!({ "buffer": ok }))).await;
        assert_eq!(s, StatusCode::OK, "{ok}: {v}");
    }
}

/// REQ: OBS-007, API-905 (T40.13, ADR-040) - a field the files set wins: a different value is 409
/// `set_by_file`, a body that leaves it out keeps the file's, and the entry says so.
#[tokio::test]
#[allow(clippy::many_single_char_names)] // h, s, v, e, c: the harness and its answers
async fn obs_007_dnstap_the_files_win() {
    let h = with_toml("[telemetry.dnstap]\nsocket = \"/run/file.sock\"\nbuffer = 2000\n");
    let (s, _, v) = h
        .call("PUT", URL, Some(&json!({ "socket": "/run/other.sock" })))
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "set_by_file", "{v}");
    let (s, _, v) = h.call("PUT", URL, Some(&json!({ "resolver": true }))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(
        v["code"], "reauth_required",
        "a widening, even with the file's target: {v}"
    );
    let (s, _, v) = h
        .call("PUT", URL, Some(&json!({ "sample_every": 20 })))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let c = merged(&h);
    assert_eq!(c.telemetry.dnstap.socket.as_deref(), Some("/run/file.sock"));
    assert_eq!(c.telemetry.dnstap.buffer, 2000);
    assert_eq!(c.telemetry.dnstap.sample_every, 20);
    let (_, _, e) = h.call("GET", ENTRY, None).await;
    let set: Vec<&str> = e["items"][0]["setByFile"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(set.contains(&"socket") && set.contains(&"buffer"), "{e}");
    assert!(!set.contains(&"sample_every"), "{e}");
}

/// REQ: OBS-007, API-905 (T40.13, AC2) - the tap is read when a node starts, so a change is stored
/// at once and the entry says "restart needed" until the node runs with it. End to end for
/// `resolver` and `forwarder`: after the change the configuration a restart reads has both on; the
/// entry then reads `restart_needed` false once the node started with that configuration.
#[tokio::test]
#[allow(clippy::many_single_char_names)] // h, s, v, e, c: the harness and its answers
async fn obs_007_dnstap_a_change_needs_a_restart_and_says_so() {
    let h = with_toml("[telemetry.dnstap]\nsocket = \"/run/file.sock\"\n");
    let started = |h: &Harness| {
        let c = merged(h);
        crate::settings_kinds::section_json(wrendns_api::ManagedKind::TelemetryDnstap, &c)
    };
    // The node started with the files' tap.
    h.src.dnstap_started.store(Some(Arc::new(started(&h))));
    let restart_needed = |e: &Value| e["items"][0]["definition"]["restart_needed"].clone();
    let (_, _, e) = h.call("GET", ENTRY, None).await;
    assert_eq!(restart_needed(&e), json!(false), "{e}");

    // Widening: a signed-in session; the answer says a restart is needed.
    let body = json!({ "socket": "/run/file.sock", "forwarder": true, "resolver": true });
    let (s, v) = session_call(
        &h,
        0,
        "PUT",
        &format!("{URL}?dryRun=true"),
        Some(body.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["impact"].as_str().unwrap().contains("restart"), "{v}");
    let (s, v) = session_call(&h, 0, "PUT", URL, Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let c = merged(&h);
    assert!(c.telemetry.dnstap.forwarder && c.telemetry.dnstap.resolver);
    // The tap the node runs has not changed: restart needed, and the card can say so.
    let (_, _, e) = h.call("GET", ENTRY, None).await;
    assert_eq!(restart_needed(&e), json!(true), "{e}");
    assert_eq!(e["items"][0]["definition"]["forwarder"], json!(true), "{e}");
    assert_eq!(e["items"][0]["definition"]["resolver"], json!(true), "{e}");
    // After the restart the node runs it: nothing pending.
    h.src.dnstap_started.store(Some(Arc::new(started(&h))));
    let (_, _, e) = h.call("GET", ENTRY, None).await;
    assert_eq!(restart_needed(&e), json!(false), "{e}");
    // Taking the API's values away puts the file's back, and that needs a restart too.
    let (s, _, v) = h.call("DELETE", URL, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["impact"].as_str().unwrap().contains("restart"), "{v}");
    let (_, _, e) = h.call("GET", ENTRY, None).await;
    assert_eq!(restart_needed(&e), json!(true), "{e}");
    // The entry read back is accepted as a PUT body (the read-only field is dropped).
    let mut back = e["items"][0]["definition"].clone();
    back["buffer"] = json!(4000);
    let (s, _, v) = h.call("PUT", URL, Some(&back)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: OBS-007, API-905, CLU-015 (T40.13, AC1) - the kind is node-managed: its row is in the
/// node-managed blob a primary publishes (so a promoted replica keeps it), a build that does not
/// know the kind skips it, and the kind is classified once.
#[tokio::test]
async fn obs_007_dnstap_settings_replicate_in_the_node_managed_blob() {
    let h = harness("");
    let (s, _, v) = h.call("PUT", URL, Some(&json!({ "buffer": 7000 }))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let blob = crate::node_managed::export(h.auth.state());
    let entries = crate::node_managed::parse(&blob).unwrap();
    let row = entries
        .iter()
        .find(|e| e.kind == crate::managed::DNSTAP_SETTINGS)
        .expect("the blob carries the dnstap row");
    assert_eq!(row.body["buffer"], 7000, "{:?}", row.body);
    // An older build reads the blob without it, and keeps its file values.
    let old_kinds: Vec<&str> = crate::node_managed::KINDS
        .iter()
        .copied()
        .filter(|k| *k != crate::managed::DNSTAP_SETTINGS)
        .collect();
    let old = crate::node_managed::parse_kinds(&blob, &old_kinds).unwrap();
    assert!(
        old.iter()
            .all(|e| e.kind != crate::managed::DNSTAP_SETTINGS)
    );
}

/// REQ: OBS-007, API-905, CLU-010 (T40.13, AC7) - the kind is gated by the feature every member
/// announces, not by a version number: a primary that carries the same number as this build but
/// announces no features is refused before forwarding (409 `upgrade_required`, naming it), nothing
/// is sent; a primary that announces it gets the write.
#[tokio::test(flavor = "multi_thread")]
async fn obs_007_primary_without_the_dnstap_feature_is_refused_before_forwarding() {
    let body = json!({ "buffer": 5000 });
    let (replica, older) = crate::credential_tests::older_primary_and_replica_features(
        "1.1.0-edge.40",
        Some(Vec::new()),
        None,
    )
    .await;
    let h = harness_in("", Some(replica));
    let (s, _, v) = h.call("PUT", URL, Some(&body)).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "upgrade_required", "{v}");
    assert!(
        v["detail"].as_str().unwrap().contains("1.1.0-edge.40"),
        "{v}"
    );
    assert!(v["detail"].as_str().unwrap().contains("dnstap"), "{v}");
    assert_eq!(older.got.lock().unwrap().len(), 0, "not forwarded");
    let _ = older.stop.send(true);

    let (replica, current) = older_primary_and_replica("1.1.0").await;
    let h = harness_in("", Some(replica));
    let (s, _, v) = h.call("PUT", URL, Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(!current.got.lock().unwrap().is_empty(), "forwarded");
    let _ = current.stop.send(true);
}

/// REQ: OBS-007, API-905, CLU-010 (T40.13, AC7) - where the write is applied: a primary with a
/// member that does not announce the kind refuses the first write (409 `upgrade_required`, dry run
/// too, naming the member), stores nothing and keeps the file's values; a DELETE is not held; once
/// every member announces it, the write goes through.
#[tokio::test(flavor = "multi_thread")]
async fn obs_007_dnstap_write_waits_for_every_members_build() {
    let body = json!({ "buffer": 5000 });
    let (replica, old) = crate::credential_tests::older_primary_and_replica_features(
        "1.1.0",
        None,
        Some(Vec::new()),
    )
    .await;
    let member = replica.identity.meta.node_id.clone();
    let h = harness_in("", Some(Arc::clone(&old.primary)));
    for target in [format!("{URL}?dryRun=true"), URL.to_owned()] {
        let (s, _, v) = h.call("PUT", &target, Some(&body)).await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert_eq!(v["code"], "upgrade_required", "{v}");
        let detail = v["detail"].as_str().unwrap();
        assert!(
            detail.contains("dnstap settings") && detail.contains(&member),
            "{v}"
        );
    }
    let (s, _, v) = h.call("DELETE", URL, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    assert_ne!(v["code"], "upgrade_required", "{v}");
    assert_eq!(h.auth.state().managed("dnstap_settings").unwrap().len(), 0);
    assert_eq!(
        merged(&h).telemetry.dnstap.buffer,
        10_000,
        "the file's values stay"
    );
    let _ = old.stop.send(true);

    let (_replica, new) = older_primary_and_replica("1.1.0").await;
    let h = harness_in("", Some(Arc::clone(&new.primary)));
    let (s, _, v) = h.call("PUT", URL, Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(h.auth.state().managed("dnstap_settings").unwrap().len(), 1);
    let _ = new.stop.send(true);
}

/// REQ: OBS-007, API-905 (T40.13, AC5) - the read is open to agents through MCP, and there is no
/// agent write: the catalog has the read tool and no tool that writes the dnstap settings.
#[test]
fn obs_007_mcp_reads_the_dnstap_settings_and_never_writes_them() {
    let read = wrendns_api::mcp::tools()
        .into_iter()
        .find(|t| t.name == "get_dnstap_settings")
        .expect("the read tool");
    let calls = (read.calls)(&json!({})).unwrap();
    assert_eq!(calls[0].1, "/api/v1/config/entries?kind=dnstap_settings");
    assert!(
        wrendns_api::mcp::write_tools()
            .iter()
            .all(|t| !t.name.contains("dnstap")),
        "no agent write"
    );
}

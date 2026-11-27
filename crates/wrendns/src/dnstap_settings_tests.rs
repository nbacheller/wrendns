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

/// The guarded entry of the dnstap row for this node, active, as a confirmed change leaves it (the
/// node's name is the one the guarded tests use).
fn put_guarded(h: &Harness, value: Value, state: crate::guarded::store::EntryState) {
    crate::guarded::set_this_node("pi-a");
    let entry = crate::guarded::store::Stored {
        node: "pi-a".to_owned(),
        id: "dnstap-output".to_owned(),
        value,
        mode: "staged".to_owned(),
        state,
        by: "admin".to_owned(),
        at: crate::guarded::now_secs(),
    };
    crate::guarded::store::put(h.auth.state(), &entry, entry.at, "admin").unwrap();
}

fn guarded_entries(h: &Harness) -> usize {
    crate::guarded::store::all(h.auth.state())
        .iter()
        .filter(|e| e.id == "dnstap-output")
        .count()
}

/// REQ: OBS-007, API-905 (T40.13, AC1, ADR-1107 point 4; owner decision, 2026-11-27) - a change that
/// widens the copy (the tap turned on, a new target, a kind of exchange added, sampling more often) is
/// not an ordinary write: it is refused, a dry run too, with 409 `guarded_only` and the server's own
/// words, whatever the caller signed in with, and nothing is stored. A change that copies no more
/// (the tap off, sampling less often, a feed off, a smaller queue) is still an ordinary admin write.
#[tokio::test]
#[allow(clippy::many_single_char_names)] // h, s, v, e, f: the harness and its answers
async fn obs_007_dnstap_widening_is_the_guarded_flows() {
    let h = harness("");
    let dry = format!("{URL}?dryRun=true");
    for target in [dry.as_str(), URL] {
        let (s, _, v) = h.call("PUT", target, Some(&on())).await;
        assert_eq!(s, StatusCode::CONFLICT, "{target}: {v}");
        assert_eq!(v["code"], "guarded_only", "{v}");
        let detail = v["detail"].as_str().unwrap();
        assert!(
            detail.contains("copies more") && detail.contains("phrase"),
            "{v}"
        );
        // A fresh sign-in does not make it an ordinary write.
        let (s, v) = session_call(&h, 0, "PUT", target, Some(on())).await;
        assert_eq!(s, StatusCode::CONFLICT, "{target}: {v}");
        assert_eq!(v["code"], "guarded_only", "{v}");
    }
    assert_eq!(h.auth.state().managed("dnstap_settings").unwrap().len(), 0);
    assert!(merged(&h).telemetry.dnstap.socket.is_none());
    // Every widening is refused alike: a new target, a feed on, sampling more often.
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
        json!({ "forwarder": true, "socket": "/run/dnstap.sock" }),
        json!({ "resolver": true, "socket": "/run/dnstap.sock" }),
        widen(&|b| b["sample_every"] = json!(1)),
    ] {
        let (s, _, v) = h.call("PUT", URL, Some(&b)).await;
        assert_eq!(s, StatusCode::CONFLICT, "{b}: {v}");
        assert_eq!(v["code"], "guarded_only", "{b}: {v}");
    }
    // Narrowing is ordinary: a smaller queue, sampling less often (a field left out takes its
    // default, so a body that lowers the sampling says so), the tap off.
    let (s, _, v) = h
        .call(
            "PUT",
            URL,
            Some(&json!({ "buffer": 9000, "sample_every": 100 })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        v["warnings"].to_string().contains("restart"),
        "restart needed: {v}"
    );
    let (s, _, v) = h.call("PUT", URL, Some(&json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // A DELETE that would bring a wider value back (the file's tap, sampling every query) is judged
    // too: the way back to the file is not a way round the review.
    let f = with_toml(
        "[telemetry.dnstap]
socket = \"/run/file.sock\"
",
    );
    let (s, _, v) = f
        .call(
            "PUT",
            URL,
            Some(&json!({ "socket": "/run/file.sock", "sample_every": 100 })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = f.call("DELETE", URL, None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "guarded_only", "{v}");
    // An operator is refused before any of it, as before.
    let op = token(&h, "ops", Role::Operator, None);
    let (s, _, _) = call_as(&h, &op, "PUT", URL, Some(&on()), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

/// REQ: OBS-007, API-905 (T40.13, ADR-1107 point 4) - the two entries of the section agree on
/// which is in force: a guarded value that was confirmed is in force over the ordinary one, and an
/// ordinary write that narrows removes the guarded entries (so the newer value wins, and a stale
/// widening can never hide a narrowing); a staged guarded entry waits for the next start.
#[tokio::test]
#[allow(clippy::many_single_char_names)] // h, s, v, e, f: the harness and its answers
async fn obs_007_dnstap_the_newer_of_the_two_entries_is_in_force() {
    let h = harness("");
    // Staged: waits for the next start, the section is what the ordinary entries say.
    put_guarded(
        &h,
        json!({ "socket": "/run/dnstap.sock", "sample_every": 5, "forwarder": true }),
        crate::guarded::store::EntryState::Staged,
    );
    assert!(merged(&h).telemetry.dnstap.socket.is_none());
    // Active (the node started with it): in force, over an older ordinary entry.
    let (s, _, v) = h.call("PUT", URL, Some(&json!({ "buffer": 7000 }))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(guarded_entries(&h), 0, "an ordinary write replaces it");
    put_guarded(
        &h,
        json!({ "socket": "/run/dnstap.sock", "sample_every": 5, "forwarder": true }),
        crate::guarded::store::EntryState::Active,
    );
    let d = merged(&h).telemetry.dnstap;
    assert_eq!(d.socket.as_deref(), Some("/run/dnstap.sock"));
    assert!(d.forwarder);
    assert_eq!(d.buffer, 10_000, "the guarded value is the whole section");
    // The entry says the API (not the file) set it.
    let (_, _, e) = h.call("GET", ENTRY, None).await;
    assert_eq!(e["items"][0]["source"], "override", "{e}");
    // A narrowing write, judged against what is in force, replaces it: the tap is off now.
    let (s, _, v) = h.call("PUT", URL, Some(&json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(guarded_entries(&h), 0);
    assert!(
        merged(&h).telemetry.dnstap.socket.is_none(),
        "{:?}",
        merged(&h).telemetry.dnstap
    );
    // A dry run removes nothing.
    put_guarded(
        &h,
        json!({ "socket": "/run/dnstap.sock", "sample_every": 5 }),
        crate::guarded::store::EntryState::Active,
    );
    let (s, _, v) = h
        .call("PUT", &format!("{URL}?dryRun=true"), Some(&json!({})))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(guarded_entries(&h), 1);
    // A file's setting wins over a guarded entry.
    let f = with_toml(
        "[telemetry.dnstap]
socket = \"/run/file.sock\"
",
    );
    put_guarded(
        &f,
        json!({ "socket": "/run/dnstap.sock", "sample_every": 5 }),
        crate::guarded::store::EntryState::Active,
    );
    assert_eq!(
        merged(&f).telemetry.dnstap.socket.as_deref(),
        Some("/run/file.sock")
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
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(
        v["code"], "guarded_only",
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
/// at once and the entry says "restart needed" until the node runs with it (owner decision,
/// 2026-11-27: a saved change takes effect after a restart of each node, not on a reload); the entry
/// then reads `restart_needed` false once the node started with that configuration.
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

    // A change that narrows: the answer says a restart is needed.
    let body = json!({ "socket": "/run/file.sock", "sample_every": 100, "buffer": 4000 });
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
    assert!(v["warnings"].to_string().contains("restart needed"), "{v}");
    let (s, v) = session_call(&h, 0, "PUT", URL, Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let c = merged(&h);
    assert_eq!(
        (c.telemetry.dnstap.sample_every, c.telemetry.dnstap.buffer),
        (100, 4000)
    );
    // The tap the node runs has not changed: restart needed, and the card can say so.
    let (_, _, e) = h.call("GET", ENTRY, None).await;
    assert_eq!(restart_needed(&e), json!(true), "{e}");
    assert_eq!(
        e["items"][0]["definition"]["sample_every"],
        json!(100),
        "{e}"
    );
    // After the restart the node runs it: nothing pending.
    h.src.dnstap_started.store(Some(Arc::new(started(&h))));
    let (_, _, e) = h.call("GET", ENTRY, None).await;
    assert_eq!(restart_needed(&e), json!(false), "{e}");
    // Taking the API's values away puts the file's back, and that needs a restart too; here the
    // file samples every query, which copies more than the stored one did, so it is the review's.
    let (s, _, v) = h.call("DELETE", URL, None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "guarded_only", "{v}");
    let (_, _, e) = h.call("GET", ENTRY, None).await;
    // The entry read back is accepted as a PUT body (the read-only field is dropped).
    let mut back = e["items"][0]["definition"].clone();
    back["buffer"] = json!(4000);
    let (s, _, v) = h.call("PUT", URL, Some(&back)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: OBS-007, API-905 (T40.13, AC2, review) - the start-up path picks up what the API stored: the
/// configuration a node loads at start (`server::load`: the files, then the stored settings) has the
/// tap's target, sampling, queue, `forwarder` and `resolver` as saved, and `dnstap::start`, which the
/// node calls with it, builds the tap and the exchange observers from them.
#[tokio::test]
async fn obs_007_dnstap_start_up_reads_what_the_api_stored() {
    let h = harness("");
    // What a confirmed guarded change leaves: the whole section, on probation after the start that
    // read it (a staged entry is read at the next start, and the start moves it on).
    put_guarded(
        &h,
        json!({
            "socket": "/run/wrendns-test-tap.sock",
            "sample_every": 7,
            "buffer": 200,
            "forwarder": true,
            "resolver": true,
        }),
        crate::guarded::store::EntryState::Probation,
    );
    // A node's own file: nothing about dnstap, the data directory the stored settings live in.
    let data = h.src.file_config.load_full().node.data_dir.to_string();
    let file = std::path::Path::new(&data).join("wrendns.toml");
    std::fs::write(&file, format!("[node]\ndata_dir = \"{data}\"\n")).unwrap();
    let cfg = crate::server::load(&[file]).expect("the node's configuration loads");
    let d = &cfg.telemetry.dnstap;
    assert_eq!(d.socket.as_deref(), Some("/run/wrendns-test-tap.sock"));
    assert_eq!((d.sample_every, d.buffer), (7, 200));
    assert!(d.forwarder && d.resolver, "both exchange observers are on");
    let tap = crate::dnstap::start(&cfg).expect("the tap starts from the stored settings");
    assert_eq!(tap.sample_every(), 7);
}

/// REQ: OBS-007, API-905 (T40.13, review) - a file whose `buffer` is above the API's ceiling (it was
/// valid before the ceiling) still loads, with a warning, and a write that leaves `buffer` out or
/// sends the file's value back still works; only a new value above the ceiling is refused.
#[tokio::test]
async fn obs_007_dnstap_a_large_buffer_in_the_file_still_loads() {
    let loaded = wrendns_config::Loader::new()
        .toml_str("t.toml", "[telemetry.dnstap]\nbuffer = 2000000\n")
        .env(Vec::<(String, String)>::new())
        .load()
        .expect("the file loads");
    assert!(
        loaded
            .warnings
            .iter()
            .any(|w| w.contains("telemetry.dnstap.buffer")),
        "{:?}",
        loaded.warnings
    );
    let h = with_toml("[telemetry.dnstap]\nbuffer = 2000000\n");
    let (s, _, v) = h
        .call("PUT", URL, Some(&json!({ "sample_every": 20 })))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(merged(&h).telemetry.dnstap.buffer, 2_000_000);
    let (s, _, v) = h
        .call("PUT", URL, Some(&json!({ "buffer": 2_000_000 })))
        .await;
    assert_eq!(s, StatusCode::OK, "the file's own value, sent back: {v}");
    let plain = harness("");
    let (s, _, v) = plain
        .call("PUT", URL, Some(&json!({ "buffer": 1_000_001 })))
        .await;
    assert!(
        s == StatusCode::UNPROCESSABLE_ENTITY || s == StatusCode::BAD_REQUEST,
        "{s} {v}"
    );
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
    // The refusals a gate records are process-wide (`upgrade_gate::standing`): take the turn the
    // other gate tests take, and leave nothing standing behind.
    let _turn = crate::secrets_api_tests::GATE.lock().await;
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
    crate::upgrade_gate::forget_held();
}

/// REQ: OBS-007, API-905, CLU-010 (T40.13, AC7) - where the write is applied: a primary with a
/// member that does not announce the kind refuses the first write (409 `upgrade_required`, dry run
/// too, naming the member), stores nothing and keeps the file's values; a DELETE is not held; once
/// every member announces it, the write goes through.
#[tokio::test(flavor = "multi_thread")]
async fn obs_007_dnstap_write_waits_for_every_members_build() {
    // The refusals a gate records are process-wide (`upgrade_gate::standing`): take the turn the
    // other gate tests take, and leave nothing standing behind.
    let _turn = crate::secrets_api_tests::GATE.lock().await;
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
    crate::upgrade_gate::forget_held();
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

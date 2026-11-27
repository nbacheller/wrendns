// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: OBS-007, API-905 (T40.13, ADR-1107) - the dnstap settings through the real write path
//! (route, plan, store, audit): `[telemetry.dnstap]` as one admin-only, node-managed entry. A
//! viewer, an operator and an agent are refused; a change that copies more out of the process is
//! refused with `guarded_only` (it goes through `/api/v1/guarded/dnstap-output`); the file's bounds hold; the files win; the entry says "restart
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
    // The node's entries carry its name (the name the guarded tests use).
    crate::guarded::set_this_node("pi-a");
    crate::credential_tests::harness_toml(
        toml,
        None,
        vec![wrendns_config::Cidr::parse("127.0.0.0/8").unwrap()],
        auth::Settings::default(),
    )
}

/// A standalone primary with no dnstap in its files, named as the guarded tests name a node.
fn node_a() -> Harness {
    crate::guarded::set_this_node("pi-a");
    harness("")
}

/// The section the card shows (what the node will run after its next start), with `restart_needed`.
async fn card(h: &Harness) -> Value {
    let (s, _, e) = h.call("GET", ENTRY, None).await;
    assert_eq!(s, StatusCode::OK, "{e}");
    e["items"][0].clone()
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
    let h = node_a();
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
    assert!(entry_of(&h, "pi-a").is_none());

    let (s, _, v) = h.call("PUT", URL, Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["node"], "pi-a", "the answer names the node: {v}");
    // The node's own entry holds it, staged: the tap is read when the node starts.
    let e = entry_of(&h, "pi-a").expect("the node's entry");
    assert_eq!(e.value["buffer"], 5000, "{:?}", e.value);
    assert_eq!(e.state, crate::guarded::store::EntryState::Staged);
    let (s, _, _) = call_as(&h, &op, "DELETE", URL, None, &[]).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "an operator cannot hand it back either"
    );
    assert!(entry_of(&h, "pi-a").is_some());
    let audit = h.audit_text();
    assert!(audit.contains("dnstap_settings.put"), "{audit}");
    assert!(
        audit.contains("\"node\":\"pi-a\"") || audit.contains("\"node\": \"pi-a\""),
        "the record names the node the change was for: {audit}"
    );
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
    assert!(entry_of(&h, "pi-a").is_none());
    assert_eq!(card(&h).await["definition"]["buffer"], 10_000);
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

/// REQ: OBS-007, API-905 (T40.13, AC1, ADR-1107 point 4; owner decision, 2026-11-27) - a change that
/// widens the copy (the tap turned on, a new target, a kind of exchange added, sampling more often) is
/// not an ordinary write: it is refused, a dry run too, with 409 `guarded_only` and the server's own
/// words, whatever the caller signed in with, and nothing is stored. A change that copies no more
/// (the tap off, sampling less often, a feed off, a smaller queue) is still an ordinary admin write.
#[tokio::test]
#[allow(clippy::many_single_char_names)] // h, s, v, e, f: the harness and its answers
async fn obs_007_dnstap_widening_is_the_guarded_flows() {
    let h = node_a();
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
        // REQ: API-905 (review) - the hint names routes that exist: the preview, then the change.
        let hint = v["hint"].as_str().unwrap();
        assert!(
            hint.contains("/api/v1/guarded/dnstap-output/preview")
                && hint.contains("previewId")
                && !hint.contains("/apply"),
            "{v}"
        );
        // A fresh sign-in does not make it an ordinary write.
        let (s, v) = session_call(&h, 0, "PUT", target, Some(on())).await;
        assert_eq!(s, StatusCode::CONFLICT, "{target}: {v}");
        assert_eq!(v["code"], "guarded_only", "{v}");
    }
    assert!(entry_of(&h, "pi-a").is_none());
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

/// REQ: OBS-007, API-905 (T40.13, ADR-1107 point 4) - a node's dnstap value is one entry of its own,
/// whoever wrote it (the review, or an ordinary narrowing): a staged entry waits for the next start
/// but is what the card shows (the node will run it) and what a change is judged against; an ordinary
/// narrowing replaces the node's entry with the narrower whole section; a change that copies more than
/// the entry is the review's; an entry in force is what the node runs; a file's setting wins field by
/// field; and another node's entry is never this node's.
#[tokio::test]
#[allow(clippy::many_single_char_names)] // h, s, v, e, f: the harness and its answers
async fn obs_007_dnstap_a_nodes_value_is_its_own_entry() {
    use crate::guarded::store::EntryState;
    let h = node_a();
    // Staged: waits for the next start (the node runs no tap now), and the card shows what it will run.
    put_guarded(
        &h,
        json!({ "socket": "/run/dnstap.sock", "sample_every": 5, "forwarder": true }),
        EntryState::Staged,
    );
    assert!(merged(&h).telemetry.dnstap.socket.is_none());
    let c = card(&h).await;
    assert_eq!(c["definition"]["socket"], "/run/dnstap.sock", "{c}");
    assert_eq!(c["source"], "override", "{c}");
    // A change that copies more than the entry it replaces is the review's.
    let (s, _, v) = h
        .call(
            "PUT",
            URL,
            Some(&json!({ "socket": "/run/dnstap.sock", "sample_every": 1, "forwarder": true })),
        )
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("guarded_only")),
        "{v}"
    );
    // A narrowing replaces it with the narrower whole section (the feed off, a smaller queue).
    let (s, _, v) = h
        .call(
            "PUT",
            URL,
            Some(&json!({ "socket": "/run/dnstap.sock", "sample_every": 5, "buffer": 7000 })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let e = entry_of(&h, "pi-a").expect("the entry");
    assert_eq!(e.value["buffer"], 7000, "{:?}", e.value);
    assert_eq!(e.value["forwarder"], false, "{:?}", e.value);
    assert_eq!(e.value["socket"], "/run/dnstap.sock");
    // Active (the node started with it): in force.
    put_guarded(
        &h,
        json!({ "socket": "/run/dnstap.sock", "sample_every": 5, "forwarder": true }),
        EntryState::Active,
    );
    let d = merged(&h).telemetry.dnstap;
    assert_eq!(d.socket.as_deref(), Some("/run/dnstap.sock"));
    assert!(d.forwarder);
    assert_eq!(d.buffer, 10_000, "the entry is the whole section");
    // A narrowing that turns the tap off removes the entry; the card then shows the files' section.
    let (s, _, v) = h.call("PUT", URL, Some(&json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(entry_of(&h, "pi-a").is_none());
    assert!(card(&h).await["definition"]["socket"].is_null());
    // A dry run removes nothing.
    put_guarded(
        &h,
        json!({ "socket": "/run/dnstap.sock", "sample_every": 5 }),
        EntryState::Active,
    );
    let (s, _, v) = h
        .call("PUT", &format!("{URL}?dryRun=true"), Some(&json!({})))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(entry_of(&h, "pi-a").is_some());
    // Another node's entry is not this node's: it changes nothing here.
    let other = node_a();
    put_guarded_on(
        "pi-b",
        &other,
        json!({ "socket": "/run/b.sock", "sample_every": 2 }),
    );
    assert!(merged(&other).telemetry.dnstap.socket.is_none());
    assert!(card(&other).await["definition"]["socket"].is_null());
    // A file's setting wins over an entry.
    let f = with_toml(
        "[telemetry.dnstap]
socket = \"/run/file.sock\"
",
    );
    put_guarded(
        &f,
        json!({ "socket": "/run/dnstap.sock", "sample_every": 5 }),
        EntryState::Active,
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
    let h = node_a();
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
    assert!(entry_of(&h, "pi-a").is_none());
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
    // What the node will run: the files' fields as they are, the sampling as asked.
    let e = card(&h).await;
    let d = &e["definition"];
    assert_eq!(d["socket"], "/run/file.sock", "{e}");
    assert_eq!(d["buffer"], 2000, "{e}");
    assert_eq!(d["sample_every"], 20, "{e}");
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
    let h = with_toml(
        "[telemetry.dnstap]
socket = \"/run/file.sock\"
",
    );
    let pending = |e: &Value| {
        let mut d = e["definition"].clone();
        d.as_object_mut().unwrap().remove("restart_needed");
        d
    };
    // The node started with the files' tap.
    let start = card(&h).await;
    h.src.dnstap_started.store(Some(Arc::new(pending(&start))));
    let restart_needed = |e: &Value| e["definition"]["restart_needed"].clone();
    assert_eq!(restart_needed(&card(&h).await), json!(false));

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
    // The tap the node runs has not changed: restart needed, and the card shows what it will run.
    let e = card(&h).await;
    assert_eq!(restart_needed(&e), json!(true), "{e}");
    assert_eq!(e["definition"]["sample_every"], json!(100), "{e}");
    assert_eq!(e["definition"]["buffer"], json!(4000), "{e}");
    // After the restart the node runs it: nothing pending.
    h.src.dnstap_started.store(Some(Arc::new(pending(&e))));
    assert_eq!(restart_needed(&card(&h).await), json!(false));
    // Taking the API's values away puts the file's back, and that needs a restart too; here the
    // file samples every query, which copies more than the stored one did, so it is the review's.
    let (s, _, v) = h.call("DELETE", URL, None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "guarded_only", "{v}");
    // The entry read back is accepted as a PUT body (the read-only field is dropped), and a change of
    // nothing writes nothing.
    let back = card(&h).await["definition"].clone();
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
        .call(
            "PUT",
            URL,
            Some(&json!({ "buffer": 2_000_000, "sample_every": 20 })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "the file's own value, sent back: {v}");
    let plain = node_a();
    let (s, _, v) = plain
        .call("PUT", URL, Some(&json!({ "buffer": 1_000_001 })))
        .await;
    assert!(
        s == StatusCode::UNPROCESSABLE_ENTITY || s == StatusCode::BAD_REQUEST,
        "{s} {v}"
    );
}

/// REQ: OBS-007, API-905, CLU-015 (T40.13, AC1) - a node's dnstap value is its entry of the guarded
/// store, which the node-managed blob a primary publishes carries (so a promoted replica keeps it);
/// there is no row of the kind itself, so a build that does not know the dnstap settings reads the
/// blob as before and keeps its file values (the guarded kind it knows, with a row it ignores).
#[tokio::test]
async fn obs_007_dnstap_settings_replicate_in_the_node_managed_blob() {
    let h = node_a();
    let (s, _, v) = h.call("PUT", URL, Some(&json!({ "buffer": 7000 }))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let blob = crate::node_managed::export(h.auth.state());
    let entries = crate::node_managed::parse(&blob).unwrap();
    assert!(
        entries
            .iter()
            .all(|e| e.kind != crate::managed::DNSTAP_SETTINGS),
        "no row of the kind itself"
    );
    let row = entries
        .iter()
        .find(|e| e.kind == crate::guarded::KIND && e.name == "pi-a/dnstap-output")
        .expect("the blob carries the node's entry");
    assert_eq!(row.body["value"]["buffer"], 7000, "{:?}", row.body);
    assert!(
        !crate::node_managed::KINDS.contains(&crate::managed::DNSTAP_SETTINGS),
        "the kind is not a node-managed row"
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
    crate::guarded::set_this_node("pi-a");
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
    assert!(entry_of(&h, "pi-a").is_none());
    assert_eq!(
        merged(&h).telemetry.dnstap.buffer,
        10_000,
        "the file's values stay"
    );
    let _ = old.stop.send(true);

    let (_replica, new) = older_primary_and_replica("1.1.0").await;
    crate::guarded::set_this_node("pi-a");
    let h = harness_in("", Some(Arc::clone(&new.primary)));
    let (s, _, v) = h.call("PUT", URL, Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(entry_of(&h, "pi-a").is_some());
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

pub(crate) fn put_guarded_on(node: &str, h: &Harness, value: Value) {
    let entry = crate::guarded::store::Stored {
        node: node.to_owned(),
        id: "dnstap-output".to_owned(),
        value,
        mode: "staged".to_owned(),
        state: crate::guarded::store::EntryState::Active,
        by: "admin".to_owned(),
        at: crate::guarded::now_secs(),
    };
    crate::guarded::store::put(h.auth.state(), &entry, entry.at, "admin").unwrap();
}

pub(crate) fn entry_of(h: &Harness, node: &str) -> Option<crate::guarded::store::Stored> {
    crate::guarded::store::all(h.auth.state())
        .into_iter()
        .find(|e| e.id == "dnstap-output" && e.node == node)
}

/// What a replica sends with the write it forwards: its files, the fields they set, and what it will
/// run after its next start.
#[allow(clippy::needless_pass_by_value)] // built inline by the callers
pub(crate) fn view(file: Value, file_set: &[&str], pending: Value) -> Value {
    json!({ "file": file, "file_set": file_set, "pending": pending })
}

/// The section with no tap, as a node without dnstap in its files has it.
fn none() -> Value {
    json!({
        "socket": null, "address": null, "sample_every": 1, "buffer": 10000,
        "forwarder": false, "resolver": false
    })
}

/// A section with a tap at `socket`, sampling one query in `every`.
fn tap(socket: &str, every: u32) -> Value {
    json!({
        "socket": socket, "address": null, "sample_every": every, "buffer": 10000,
        "forwarder": false, "resolver": false
    })
}

type Outcome = Result<wrendns_api::model::ConfigChange, wrendns_api::problem::Problem>;

/// A write for `node`, as the primary receives it from that replica (`origin` is the connection's node).
async fn forwarded(
    h: &Harness,
    node: &str,
    body: Option<Value>,
    node_view: Option<Value>,
    dry_run: bool,
) -> Outcome {
    use wrendns_api::Backend;
    let b = crate::api_backend::ApiBackend {
        src: Arc::clone(&h.src),
    };
    b.write_managed(wrendns_api::ManagedWrite {
        kind: wrendns_api::ManagedKind::TelemetryDnstap,
        name: "default".into(),
        body,
        dry_run,
        expect: None,
        by: "alice".into(),
        simulate: None,
        role: Some(Role::Admin),
        agent: None,
        origin: Some(node.to_owned()),
        node_view,
    })
    .await
}

fn code(r: &Outcome) -> String {
    match r {
        Ok(_) => "ok".to_owned(),
        Err(p) => format!("{:?}", p.code),
    }
}

/// REQ: OBS-007, API-905 (T40.13, review 4; owner decision, 2026-11-27) - a write is for one node and is
/// judged on that node's own view, which the node sends (the primary cannot see its files). (1) A
/// replica that taps through its own file narrows that tap: an ordinary write, stored as that
/// replica's entry, though the primary has no tap. (2) A replica with a confirmed tap narrows it
/// while the primary's file sets another socket: the replica's entry is rewritten, on its own socket.
/// A write is not judged without the node's view.
#[tokio::test]
#[allow(clippy::many_single_char_names)] // h, v, c, e, r: the harness, the view, the answers
async fn obs_007_dnstap_a_write_is_judged_on_the_node_it_is_for() {
    let h = node_a();
    // (1) pi-b's file sets the tap; it has no entry; the primary has no tap.
    let file = tap("/run/b.sock", 1);
    let v = view(file.clone(), &["socket"], file.clone());
    let narrow = json!({ "socket": "/run/b.sock", "sample_every": 10 });
    let dry = forwarded(&h, "pi-b", Some(narrow.clone()), Some(v.clone()), true).await;
    assert_eq!(code(&dry), "ok", "{dry:?}");
    assert!(entry_of(&h, "pi-b").is_none(), "a dry run stores nothing");
    let c = forwarded(&h, "pi-b", Some(narrow), Some(v.clone()), false)
        .await
        .expect("a narrowing of the node's own file tap is an ordinary write");
    assert_eq!(c.node.as_deref(), Some("pi-b"));
    assert_eq!(
        c.before.as_ref().unwrap()["socket"],
        "/run/b.sock",
        "before is pi-b's own section: {c:?}"
    );
    let e = entry_of(&h, "pi-b").expect("pi-b's entry");
    assert_eq!(e.value["sample_every"], 10, "{:?}", e.value);
    assert_eq!(e.state, crate::guarded::store::EntryState::Staged);
    assert!(
        entry_of(&h, "pi-a").is_none(),
        "the primary's own is untouched"
    );
    // Another socket is the file's field: 409 set_by_file, never a guess.
    let other = json!({ "socket": "/run/other.sock", "sample_every": 10 });
    let r = forwarded(&h, "pi-b", Some(other), Some(v), false).await;
    assert_eq!(code(&r), "SetByFile", "{r:?}");

    // (2) pi-c has a confirmed tap; the primary's file sets another socket.
    let h = with_toml("[telemetry.dnstap]\nsocket = \"/run/a.sock\"\n");
    put_guarded_on("pi-c", &h, json!({ "socket": "/run/c.sock" }));
    let v = view(none(), &[], tap("/run/c.sock", 1));
    let r = forwarded(
        &h,
        "pi-c",
        Some(json!({ "socket": "/run/c.sock", "sample_every": 10 })),
        Some(v),
        false,
    )
    .await;
    assert_eq!(code(&r), "ok", "{r:?}");
    let e = entry_of(&h, "pi-c").unwrap();
    assert_eq!(
        e.value["socket"], "/run/c.sock",
        "never the primary's socket: {:?}",
        e.value
    );
    assert_eq!(e.value["sample_every"], 10);
    assert_eq!(e.state, crate::guarded::store::EntryState::Staged);
    // Without its view, a node's write is not judged on a guess.
    let r = forwarded(&h, "pi-c", Some(json!({})), None, false).await;
    assert_eq!(code(&r), "UpgradeRequired", "{r:?}");
}

/// REQ: OBS-007, API-905 (T40.13, review 4) - a node's confirmed tap clears only that node: a write for
/// a node with no tap that turns the tap on at another node's socket is a widening on that node (409
/// `guarded_only`), whoever else confirmed the same path, and neither rewrites nor removes the other
/// node's entry. The same path on two hosts is two settings.
#[tokio::test]
async fn obs_007_dnstap_another_nodes_confirmed_tap_clears_nothing() {
    let h = node_a();
    let b_value = json!({ "socket": "/run/dnstap.sock", "sample_every": 1 });
    put_guarded_on("pi-b", &h, b_value.clone());
    // pi-c has no tap and no entry; it asks for B's socket, sampling less often than B does.
    let v = view(none(), &[], none());
    let ask = json!({ "socket": "/run/dnstap.sock", "sample_every": 10 });
    for dry in [true, false] {
        let r = forwarded(&h, "pi-c", Some(ask.clone()), Some(v.clone()), dry).await;
        assert_eq!(code(&r), "GuardedOnly", "{r:?}");
    }
    assert!(entry_of(&h, "pi-c").is_none());
    assert_eq!(
        entry_of(&h, "pi-b").unwrap().value,
        b_value,
        "pi-b untouched"
    );
    // The same from the primary's own card.
    let (s, _, v) = h.call("PUT", URL, Some(&ask)).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("guarded_only")),
        "{v}"
    );
    assert_eq!(entry_of(&h, "pi-b").unwrap().value, b_value);
    // pi-b narrowing its own tap rewrites its own entry and no other (pi-d holds the same path).
    put_guarded_on(
        "pi-d",
        &h,
        json!({ "socket": "/run/dnstap.sock", "sample_every": 1 }),
    );
    let r = forwarded(
        &h,
        "pi-b",
        Some(ask),
        Some(view(none(), &[], tap("/run/dnstap.sock", 1))),
        false,
    )
    .await;
    assert_eq!(code(&r), "ok", "{r:?}");
    assert_eq!(entry_of(&h, "pi-b").unwrap().value["sample_every"], 10);
    assert_eq!(
        entry_of(&h, "pi-d").unwrap().value["sample_every"],
        1,
        "pi-d untouched"
    );
}

/// REQ: OBS-007, API-905 (T40.13, review 4) - a DELETE is judged on its node like any change, with no
/// regard to who else is in the cluster (a primary that has just restarted knows no member, and a
/// witness holds no tap): back to files that copy no more is an ordinary write that removes that
/// node's entry, and back to files that copy more is the review's (409 `guarded_only`, dry run too).
#[tokio::test(flavor = "multi_thread")]
async fn obs_007_dnstap_a_delete_is_judged_on_its_own_node() {
    let _turn = crate::secrets_api_tests::GATE.lock().await;
    let (_replica, up) = older_primary_and_replica("1.1.0").await;
    crate::guarded::set_this_node("pi-a");
    let h = harness_in("", Some(Arc::clone(&up.primary)));
    let (s, _, v) = h
        .call("PUT", URL, Some(&json!({ "sample_every": 10 })))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = h.call("DELETE", URL, None).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "files with no tap: ordinary, in a cluster too: {v}"
    );
    assert!(entry_of(&h, "pi-a").is_none());
    // A replica whose files tap at every query: its narrowed entry cannot be deleted back to them.
    let file = tap("/run/b.sock", 1);
    let narrowed = tap("/run/b.sock", 10);
    put_guarded_on("pi-b", &h, narrowed.clone());
    let v = view(file, &["socket"], narrowed);
    for dry in [true, false] {
        let r = forwarded(&h, "pi-b", None, Some(v.clone()), dry).await;
        assert_eq!(code(&r), "GuardedOnly", "{r:?}");
    }
    assert!(entry_of(&h, "pi-b").is_some());
    // A replica whose files have no tap: the delete is ordinary and removes only its entry.
    put_guarded_on("pi-c", &h, json!({ "sample_every": 10, "buffer": 5000 }));
    let mut pending_c = none();
    pending_c["sample_every"] = json!(10);
    pending_c["buffer"] = json!(5000);
    let r = forwarded(&h, "pi-c", None, Some(view(none(), &[], pending_c)), false).await;
    assert_eq!(code(&r), "ok", "{r:?}");
    assert!(entry_of(&h, "pi-c").is_none());
    assert!(entry_of(&h, "pi-b").is_some(), "another node's entry stays");
    // Nothing to delete is a 404, not a guess.
    let r = forwarded(&h, "pi-e", None, Some(view(none(), &[], none())), false).await;
    assert_eq!(code(&r), "NotFound", "{r:?}");
    let _ = up.stop.send(true);
    crate::upgrade_gate::forget_held();
}

/// REQ: OBS-007, API-905 (T40.13, review 4) - the card shows what the node will run: after an ordinary
/// narrowing of an entry that is in force (the node runs it), the card reads the narrowed tap (the
/// staged value), not the files' "off", and says a restart is needed.
#[tokio::test]
async fn obs_007_dnstap_a_narrowed_entry_in_force_shows_the_narrowed_tap() {
    let h = node_a();
    put_guarded(
        &h,
        json!({ "socket": "/run/b.sock", "sample_every": 1 }),
        crate::guarded::store::EntryState::Active,
    );
    let mut started = card(&h).await["definition"].clone();
    started.as_object_mut().unwrap().remove("restart_needed");
    h.src.dnstap_started.store(Some(Arc::new(started)));
    let (s, _, v) = h
        .call(
            "PUT",
            URL,
            Some(&json!({ "socket": "/run/b.sock", "sample_every": 10 })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let c = card(&h).await;
    assert_eq!(c["definition"]["socket"], "/run/b.sock", "{c}");
    assert_eq!(c["definition"]["sample_every"], 10, "{c}");
    assert_eq!(c["definition"]["restart_needed"], true, "{c}");
}

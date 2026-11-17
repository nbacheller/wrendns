//! REQ: API-016 (T23.7, T23.8, ADR-921, ADR-922) — router integrations: the API writes through the
//! real path (the route, the plan, the reload), the poll loop reads the live list against local fake
//! routers (plain HTTP and TLS on 127.0.0.1), and the failure, debounce, skip and replica rules hold.
//! Nothing here reaches a real device.

#![allow(clippy::many_single_char_names)] // listeners and harnesses are short names in tests

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use serde_json::{Value, json};
use telltale_api::auth::Role;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::credential_tests::{Harness, harness};
use crate::secrets::value::Kind;
use crate::settings_kinds_tests::{call_as, token};
use telltale_config::RouterConfig;

const ROUTERS: &str = "/api/v1/routers";

/// The Home Assistant template's answer: one named device with a tracker address.
const HA_ANSWER: &str = r#"{"devices":[{"name_by_user":"Shelly Plug","name":"","macs":["AA:BB:CC:00:00:09"],"area":"Office"}],"trackers":[{"mac":"AA:BB:CC:00:00:09","ip":"192.168.1.50"}]}"#;

/// Reads one HTTP request (its headers and `Content-Length` body) off `s`.
async fn read_request<S: AsyncReadExt + Unpin>(s: &mut S) {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let mut want: Option<usize> = None;
    loop {
        let n = s.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            return;
        }
        got.extend_from_slice(buf.get(..n).unwrap_or_default());
        if want.is_none()
            && let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n")
        {
            let head =
                String::from_utf8_lossy(got.get(..end).unwrap_or_default()).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| {
                    l.strip_prefix("content-length:")
                        .and_then(|v| v.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            want = Some(end + 4 + len);
        }
        if want.is_some_and(|w| got.len() >= w) {
            return;
        }
    }
}

/// A fake router on 127.0.0.1 answering every request with `body` as JSON.
async fn fake_router(body: &'static str) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                read_request(&mut s).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

/// An address nothing listens on (a refused connection).
async fn closed_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

/// A standalone node with a stored secret `ha` (a Home Assistant token) and the planted routers.
fn with_secret(extra: &str) -> Harness {
    let h = harness(extra);
    h.src
        .secrets
        .put(
            "ha",
            Kind::Text,
            &crate::secrets::SecretValue::new(
                Kind::Text,
                zeroize::Zeroizing::new("tok-planted".to_owned()),
            )
            .unwrap(),
            0,
            "root",
            "local",
            1,
        )
        .unwrap();
    h
}

fn ha_body(url: &str) -> Value {
    json!({"type": "home_assistant", "url": url, "api_key_ref": "ha", "interval_secs": 60})
}

/// Waits until `f` holds, up to five seconds.
async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    f()
}

/// REQ: API-016 — the device a router reports, by its address.
fn leased(h: &Harness, ip: Ipv4Addr) -> Option<String> {
    h.src
        .pipeline
        .router_leases
        .load()
        .get(&ip)
        .and_then(|l| l.hostname.clone())
}

/// REQ: API-016 (T23.7) — `PUT` applies through the reload: the new router is in the live
/// configuration at once, and `GET` lists it with its settings, its source and its status.
#[tokio::test]
async fn api_016_router_put_applies_without_restart() {
    let h = with_secret("");
    let url = "http://127.0.0.1:9";
    let (s, _, body) = h
        .call("PUT", "/api/v1/routers/lab", Some(&ha_body(url)))
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(
        h.src
            .config
            .load()
            .router
            .iter()
            .any(|r| r.name.as_str() == "lab")
    );
    let (s, _, list) = h.call("GET", ROUTERS, None).await;
    assert_eq!(s, StatusCode::OK);
    let item = &list["items"][0];
    assert_eq!(item["name"], "lab");
    assert_eq!(item["kind"], "home_assistant");
    assert_eq!(item["source"], "api");
    assert_eq!(item["definition"]["api_key_ref"], "ha");
    assert_eq!(item["credentials"][0]["source"], "stored");
    assert_eq!(item["credentials"][0]["readable"], true);
    assert_eq!(item["status"]["state"], "waiting");
    // The token never appears in the answer.
    assert!(!list.to_string().contains("tok-planted"));
}

/// REQ: API-016 (T23.7) — a router the files define is read-only through the API: 409 `set_by_file`.
#[tokio::test]
async fn api_016_file_router_read_only() {
    let h = with_secret(
        "[[router]]\nname = \"filed\"\ntype = \"home_assistant\"\nurl = \"http://127.0.0.1:9\"\napi_key_ref = \"ha\"\n",
    );
    let (s, _, body) = h
        .call(
            "PUT",
            "/api/v1/routers/filed",
            Some(&ha_body("http://127.0.0.1:10")),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "set_by_file");
    let (s, _, _) = h.call("DELETE", "/api/v1/routers/filed", None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    // The file's entry is what the list shows, as file-defined.
    let (_, _, list) = h.call("GET", ROUTERS, None).await;
    assert_eq!(list["items"][0]["source"], "file");
    assert!(
        list["items"][0]["setByFile"]
            .as_array()
            .is_some_and(|a| a.iter().any(|f| f == "api_key_ref"))
    );
}

/// REQ: API-016 (T23.7, ADR-921) — writes need an admin: an operator is refused with 403.
#[tokio::test]
async fn api_016_router_write_needs_admin() {
    let h = with_secret("");
    let op = token(&h, "ops", Role::Operator, None);
    let (s, _, body) = call_as(
        &h,
        &op,
        "PUT",
        "/api/v1/routers/lab",
        Some(&ha_body("http://127.0.0.1:9")),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert!(
        !h.src
            .config
            .load()
            .router
            .iter()
            .any(|r| r.name.as_str() == "lab")
    );
}

/// REQ: API-016 (T23.7, ADR-921) — an agent token never writes a router, whatever its scopes.
#[tokio::test]
async fn api_016_router_agent_refused() {
    let h = with_secret("");
    let agent = token(&h, "bot", Role::Admin, Some("config:write:upstreams"));
    let (s, _, body) = call_as(
        &h,
        &agent,
        "PUT",
        "/api/v1/routers/lab",
        Some(&ha_body("http://127.0.0.1:9")),
        &[],
    )
    .await;
    assert_ne!(s, StatusCode::OK, "{body}");
    assert!(
        !h.src
            .config
            .load()
            .router
            .iter()
            .any(|r| r.name.as_str() == "lab")
    );
}

/// REQ: API-016 (T23.8, ADR-903 §5) — the checks are admin-only, and agents are refused by their
/// forbidden list whatever their scopes.
#[tokio::test]
async fn api_016_router_checks_need_admin_and_refuse_agents() {
    let h = with_secret("");
    let op = token(&h, "ops", Role::Operator, None);
    let (s, _, _) = call_as(
        &h,
        &op,
        "POST",
        "/api/v1/checks/router",
        Some(&ha_body("http://127.0.0.1:9")),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call_as(
        &h,
        &op,
        "POST",
        "/api/v1/checks/router-certificate",
        Some(&json!({"url": "https://127.0.0.1:9"})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let agent = token(&h, "bot", Role::Admin, Some("config:read"));
    let (s, _, _) = call_as(
        &h,
        &agent,
        "POST",
        "/api/v1/checks/router",
        Some(&ha_body("http://127.0.0.1:9")),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

/// REQ: API-016 (T23.7, ADR-921) — a body naming a secret that isn't stored is 422 `secret_missing`,
/// and a file path is refused (the files set those).
#[tokio::test]
async fn api_016_router_references_and_paths() {
    let h = with_secret("");
    let (s, _, body) = h
        .call(
            "PUT",
            "/api/v1/routers/lab",
            Some(&json!({"type": "home_assistant", "url": "http://127.0.0.1:9", "api_key_ref": "nope"})),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "secret_missing");
    let (s, _, body) = h
        .call(
            "PUT",
            "/api/v1/routers/lab",
            Some(&json!({"type": "home_assistant", "url": "http://127.0.0.1:9", "api_key_file": "/etc/x"})),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

/// REQ: API-016 (T23.7) — the configuration entries list routers by kind, with their source, and a
/// router the files define shows as the files' (`config_entries` kind `router`).
#[tokio::test]
async fn api_016_routers_are_config_entries() {
    let h = with_secret("");
    let (s, _, _) = h
        .call(
            "PUT",
            "/api/v1/routers/lab",
            Some(&ha_body("http://127.0.0.1:9")),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, list) = h
        .call("GET", "/api/v1/config/entries?kind=router", None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let items = list["items"].as_array().cloned().unwrap_or_default();
    assert_eq!(items.len(), 1, "{list}");
    assert_eq!(items[0]["kind"], "router");
    assert_eq!(items[0]["name"], "lab");
    assert_eq!(items[0]["source"], "added");
    assert!(!list.to_string().contains("tok-planted"));
}

/// REQ: API-016 (review of T23.7, API-014) — a password in a router's URL is redacted everywhere a
/// body leaves the node: the `PUT` answer, the config entries, `GET /routers`, the audit record and
/// the TOML kept in Git. The stored URL still keeps it for the poll.
#[tokio::test]
async fn api_016_router_url_password_redacted() {
    const PW: &str = "UrlPw4242";
    let h = with_secret("");
    let body = json!({
        "type": "home_assistant",
        "url": format!("https://ro:{PW}@127.0.0.1:9"),
        "api_key_ref": "ha",
        "interval_secs": 60
    });
    let (s, _, answer) = h.call("PUT", "/api/v1/routers/leak", Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{answer}");
    assert!(!answer.to_string().contains(PW), "{answer}");
    assert!(answer.to_string().contains("<redacted>"), "{answer}");
    let (_, _, entries) = h
        .call("GET", "/api/v1/config/entries?kind=router", None)
        .await;
    assert!(!entries.to_string().contains(PW), "{entries}");
    let (_, _, routers) = h.call("GET", ROUTERS, None).await;
    assert!(!routers.to_string().contains(PW), "{routers}");
    assert!(!h.audit_text().contains(PW), "{}", h.audit_text());
    // The TOML kept in Git, from the redacted body the write path builds it from.
    let shown = crate::redact::body(telltale_api::ManagedKind::Router, Some(&body))
        .unwrap_or_default()
        .to_string();
    assert!(!shown.contains(PW), "{shown}");
    // The stored URL keeps the password: the poll still needs it.
    let stored = h
        .src
        .config
        .load()
        .router
        .iter()
        .find(|r| r.name.as_str() == "leak")
        .map(|r| r.url.as_str().to_owned())
        .unwrap_or_default();
    assert!(stored.contains(PW), "{stored}");
}

/// REQ: API-016 (review of T23.7, ADR-921) — `tls_insecure_skip_verify` is file-only: the API
/// refuses `true` (422), and takes the default `false`.
#[tokio::test]
async fn api_016_insecure_is_file_only() {
    let h = with_secret("");
    let mut body = ha_body("https://127.0.0.1:9");
    body["tls_insecure_skip_verify"] = json!(true);
    let (s, _, answer) = h.call("PUT", "/api/v1/routers/lab", Some(&body)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(answer["code"], "invalid_config");
    assert!(
        !h.src
            .config
            .load()
            .router
            .iter()
            .any(|r| r.name.as_str() == "lab")
    );
    body["tls_insecure_skip_verify"] = json!(false);
    let (s, _, answer) = h.call("PUT", "/api/v1/routers/lab", Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{answer}");
}

/// REQ: API-016 (T23.7) — `DELETE` of an API router drops it; its leases go with it at the next
/// read, and the routers that stay keep their names.
#[tokio::test]
async fn api_016_router_delete_drops_leases() {
    let addr = fake_router(HA_ANSWER).await;
    let h = with_secret("");
    let (s, _, _) = h
        .call(
            "PUT",
            "/api/v1/routers/lab",
            Some(&ha_body(&format!("http://{addr}"))),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let src = Arc::clone(&h.src);
    tokio::spawn(super::run(src, stop_rx));
    // The reload that applied the PUT wakes the loop; the device is named when read.
    h.src.routers_changed.notify_one();
    assert!(
        eventually(|| leased(&h, Ipv4Addr::new(192, 168, 1, 50)).is_some()).await,
        "lab was not read"
    );
    assert_eq!(
        leased(&h, Ipv4Addr::new(192, 168, 1, 50)).as_deref(),
        Some("Shelly Plug")
    );
    let (s, _, _) = h.call("DELETE", "/api/v1/routers/lab", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        eventually(|| leased(&h, Ipv4Addr::new(192, 168, 1, 50)).is_none()).await,
        "lab's leases stayed"
    );
    let _ = stop_tx.send(true);
}

/// REQ: API-016 (T23.7, ADR-922) — a failing router keeps the other routers' names, and DNS's
/// view of them is unchanged; the failure is shown on the router's status.
#[tokio::test]
async fn api_016_router_failure_isolated() {
    let good = fake_router(HA_ANSWER).await;
    let bad = closed_port().await;
    let h = with_secret(&format!(
        "[[router]]\nname = \"good\"\ntype = \"home_assistant\"\nurl = \"http://{good}\"\napi_key_ref = \"ha\"\ninterval_secs = 60\n[[router]]\nname = \"bad\"\ntype = \"home_assistant\"\nurl = \"http://{bad}\"\napi_key_ref = \"ha\"\ninterval_secs = 60\n"
    ));
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(super::run(Arc::clone(&h.src), stop_rx));
    assert!(eventually(|| leased(&h, Ipv4Addr::new(192, 168, 1, 50)).is_some()).await);
    assert!(
        eventually(|| h
            .src
            .routers
            .snapshot()
            .get("bad")
            .is_some_and(|s| s.state == "failing"))
        .await
    );
    let snap = h.src.routers.snapshot();
    assert_eq!(snap["good"].state, "ok");
    assert_eq!(snap["good"].devices, 1);
    assert!(snap["bad"].error.as_deref().is_some_and(|e| !e.is_empty()));
    let _ = stop_tx.send(true);
}

/// REQ: API-016 (T23.8) — a check reads a draft without saving it; a stored credential is sent only
/// to the address and TLS settings it was saved with.
#[tokio::test]
async fn api_016_check_does_not_send_ref_to_new_url() {
    let saved = fake_router(HA_ANSWER).await;
    let other = fake_router(HA_ANSWER).await;
    let h = with_secret(&format!(
        "[[router]]\nname = \"lab\"\ntype = \"home_assistant\"\nurl = \"http://{saved}\"\napi_key_ref = \"ha\"\n"
    ));
    let mut same_body = ha_body(&format!("http://{saved}"));
    same_body["name"] = json!("lab");
    let same = super::check_draft(&h.src, same_body).await.unwrap();
    assert!(same.ok && same.credential_sent, "{same:?}");
    assert_eq!(same.devices, 1);
    let moved = super::check_draft(&h.src, {
        let mut v = ha_body(&format!("http://{other}"));
        v["name"] = json!("lab");
        v
    })
    .await
    .unwrap();
    assert!(!moved.credential_sent);
    assert!(
        !moved.ok,
        "a check without the credential must not read: {moved:?}"
    );
    // The check saved nothing.
    assert_eq!(h.src.config.load().router.len(), 1);
}

/// REQ: API-016 (T23.7, ADR-922) — a changed router is read again after a debounce, an unchanged one
/// keeps its state, and a router whose stored credential changed is debounced too.
#[test]
fn api_016_unchanged_router_keeps_state() {
    let cfg = |url: &str| -> Vec<RouterConfig> {
        let c = crate::router_settings::parse("lab", &ha_body(url)).unwrap();
        vec![c]
    };
    let board = super::Board::default();
    let mut slots = HashMap::new();
    let mut order = Vec::new();
    let mut generation = 0;
    let now = Instant::now();
    super::reconcile(
        &mut slots,
        &mut order,
        &cfg("http://127.0.0.1:9"),
        false,
        now,
        &mut generation,
        &board,
    );
    let s = slots.get_mut("lab").unwrap();
    s.part.seen.push((
        super::RANK_ROUTER,
        (
            "aa:bb:cc:00:00:09".to_owned(),
            Ipv4Addr::new(192, 168, 1, 50),
            Some("kept".to_owned()),
        ),
    ));
    s.last = Some(now);
    // The same settings: the state is kept.
    super::reconcile(
        &mut slots,
        &mut order,
        &cfg("http://127.0.0.1:9"),
        false,
        now,
        &mut generation,
        &board,
    );
    assert_eq!(
        slots["lab"].part.seen.len(),
        1,
        "an unchanged router lost its read"
    );
    // A changed address: its read is dropped and it is due again, debounced after the last read.
    super::reconcile(
        &mut slots,
        &mut order,
        &cfg("http://127.0.0.1:10"),
        false,
        now,
        &mut generation,
        &board,
    );
    assert_eq!(slots["lab"].part.seen.len(), 0);
    assert!(
        slots["lab"].due >= now + Duration::from_secs(5),
        "a changed router isn't debounced"
    );
    // A stored secret that changed: the router is due, debounced too.
    let mut slots2 = HashMap::new();
    let mut order2 = Vec::new();
    let cfg2 = crate::router_settings::parse(
        "lab",
        &json!({"type": "home_assistant", "url": "http://127.0.0.1:9", "api_key_ref": "ha"}),
    )
    .unwrap();
    super::reconcile(
        &mut slots2,
        &mut order2,
        std::slice::from_ref(&cfg2),
        false,
        now,
        &mut generation,
        &board,
    );
    slots2.get_mut("lab").unwrap().last = Some(now);
    super::reconcile(
        &mut slots2,
        &mut order2,
        std::slice::from_ref(&cfg2),
        true,
        now,
        &mut generation,
        &board,
    );
    assert!(
        slots2["lab"].due >= now + Duration::from_secs(5),
        "a secret change isn't debounced"
    );
    // A removed router leaves the slots and the board.
    super::reconcile(
        &mut slots,
        &mut order,
        &[],
        false,
        now,
        &mut generation,
        &board,
    );
    assert!(slots.is_empty());
    assert!(board.snapshot().is_empty());
}

/// REQ: API-016 (T23.7, ADR-903 §1, ADR-922) — a router whose credential is stored is read on the
/// primary (or a standalone node) only; a replica waits for the primary's names, and the read starts
/// as soon as the node becomes the primary (failover).
#[tokio::test]
async fn api_016_stored_credential_router_polls_on_primary_only() {
    let stored = crate::router_settings::parse("lab", &ha_body("http://127.0.0.1:9")).unwrap();
    let board = super::Board::default();
    let mut slots = HashMap::new();
    let mut order = Vec::new();
    let mut generation = 0;
    let now = Instant::now();
    super::reconcile(
        &mut slots,
        &mut order,
        std::slice::from_ref(&stored),
        false,
        now,
        &mut generation,
        &board,
    );
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let resolver: Arc<dyn telltale_filter::fetch::Resolve> =
        Arc::new(telltale_filter::fetch::SystemResolver);
    let store = Arc::new(crate::secrets::SecretStore::read_only(
        &telltale_config::Config::default(),
        Arc::new(|_: &str| None),
    ));
    // A replica: skipped, reported as the primary's to read.
    super::start_due(&mut slots, now, false, false, &resolver, &store, &tx);
    assert_eq!(slots["lab"].skipped, Some("primary"));
    assert!(!slots["lab"].in_flight);
    super::publish(&slots, &board);
    assert_eq!(board.snapshot()["lab"].polled_by, "the primary");
    // Failover: this node is the primary now, and the router is due at once.
    super::start_due(&mut slots, now, false, true, &resolver, &store, &tx);
    assert_eq!(slots["lab"].skipped, None);
    assert!(
        slots["lab"].in_flight,
        "a new primary didn't start the read"
    );
}

/// REQ: API-016 (T23.7, ADR-921) — a resolver pod reads no router, and a router with a stored
/// credential is read on the primary only (a replica gets its names through the primary's leases).
#[test]
fn api_016_ephemeral_member_skips_routers() {
    let stored = crate::router_settings::parse("lab", &ha_body("http://127.0.0.1:9")).unwrap();
    let file: RouterConfig = serde_json::from_value(json!({"name": "fl", "type": "home_assistant", "url": "http://127.0.0.1:9", "api_key_file": "/run/secrets/ha"})).unwrap();
    assert!(
        !super::read_here(&stored, false),
        "a replica read a stored credential"
    );
    assert!(super::read_here(&stored, true));
    assert!(
        super::read_here(&file, false),
        "a file credential stopped polling on a replica"
    );
    // An ephemeral member starts no read and reports why.
    let board = super::Board::default();
    let mut slots = HashMap::new();
    let mut order = Vec::new();
    let mut generation = 0;
    let now = Instant::now();
    super::reconcile(
        &mut slots,
        &mut order,
        &[stored, file],
        false,
        now,
        &mut generation,
        &board,
    );
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let resolver: Arc<dyn telltale_filter::fetch::Resolve> =
        Arc::new(telltale_filter::fetch::SystemResolver);
    let store = Arc::new(crate::secrets::SecretStore::read_only(
        &telltale_config::Config::default(),
        Arc::new(|_: &str| None),
    ));
    super::start_due(&mut slots, now, true, true, &resolver, &store, &tx);
    assert!(
        slots
            .values()
            .all(|s| !s.in_flight && s.skipped == Some("resolver pod"))
    );
    super::publish(&slots, &board);
    assert!(
        board
            .snapshot()
            .values()
            .all(|s| s.polled_by == "skipped: resolver pod" && s.state == "skipped")
    );
}

/// REQ: API-016 (T23.7) — an API router with no credential set still gets its state kept; the
/// Board keeps one status per router.
#[test]
fn api_016_board_holds_one_status_per_router() {
    let board = super::Board::default();
    let mut slots = HashMap::new();
    let mut order = Vec::new();
    let mut generation = 0;
    let c = crate::router_settings::parse("lab", &ha_body("http://127.0.0.1:9")).unwrap();
    let now = Instant::now();
    super::reconcile(
        &mut slots,
        &mut order,
        std::slice::from_ref(&c),
        false,
        now,
        &mut generation,
        &board,
    );
    super::publish(&slots, &board);
    super::publish(&slots, &board);
    assert_eq!(board.snapshot().len(), 1);
    assert_eq!(board.snapshot()["lab"].state, "waiting");
}

/// REQ: API-016 (T23.8, ADR-120) — the console's own certificate is read from a TLS handshake and
/// trusted by its PEM, with no `tls_insecure_skip_verify`: the same certificate, as the form saves
/// it, makes the read work.
#[tokio::test]
async fn api_016_trust_the_console_certificate() {
    let cert =
        rcgen::generate_simple_self_signed(vec!["unifi.local".to_owned(), "localhost".to_owned()])
            .unwrap();
    let der = cert.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(s).await {
                    read_request(&mut tls).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{HA_ANSWER}",
                        HA_ANSWER.len()
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    let url = format!("https://127.0.0.1:{}", addr.port());
    let found = crate::router_cert::fetch(&url).await.unwrap();
    assert!(
        found.names.iter().any(|n| n == "unifi.local"),
        "{:?}",
        found.names
    );
    assert!(found.pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(found.fingerprint_sha256.contains(':'));
    // Saved as tls_ca_pem: the name is the one the certificate carries, and the read succeeds.
    let h = with_secret("");
    let mut body = ha_body(&url);
    body["tls_ca_pem"] = json!(found.pem);
    body["tls_server_name"] = json!("localhost");
    let (s, _, out) = h.call("PUT", "/api/v1/routers/lab", Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let c = h
        .src
        .config
        .load()
        .router
        .iter()
        .find(|r| r.name.as_str() == "lab")
        .cloned()
        .unwrap();
    let r = super::check_draft(&h.src, serde_json::to_value(&c).unwrap())
        .await
        .unwrap();
    assert!(r.ok, "{:?}", r.error);
    assert_eq!(r.devices, 1);
    // Without the certificate the same console is refused.
    let mut no_trust = serde_json::to_value(&c).unwrap();
    no_trust["tls_ca_pem"] = Value::Null;
    let refused = super::check_draft(&h.src, no_trust).await.unwrap();
    assert!(!refused.ok);
}

/// REQ: API-016 — the certificate check needs an https address.
#[tokio::test]
async fn api_016_certificate_needs_https() {
    let h = with_secret("");
    let (s, _, _) = h
        .call(
            "POST",
            "/api/v1/checks/router-certificate",
            Some(&json!({"url": "http://192.168.1.1"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

/// A fake router answering every request with `body` exactly as given (not checked as JSON), and
/// counting the requests it gets.
async fn fake_raw(body: Vec<u8>) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let body = Arc::new(body);
    let seen = Arc::clone(&count);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let (body, seen) = (Arc::clone(&body), Arc::clone(&seen));
            tokio::spawn(async move {
                read_request(&mut s).await;
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (addr, count)
}

/// Waits until `f` holds, up to `limit`.
async fn eventually_within(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    f()
}

/// Stores `value` as the secret `name` on the harness's node.
fn store_secret(h: &Harness, name: &str, value: &str) {
    h.src
        .secrets
        .put(
            name,
            Kind::Text,
            &crate::secrets::SecretValue::new(
                Kind::Text,
                zeroize::Zeroizing::new(value.to_owned()),
            )
            .unwrap(),
            0,
            "root",
            "local",
            2,
        )
        .unwrap();
}

/// REQ: API-016 (T23.7, ADR-922) — a stored credential that changes wakes the loop, and its router
/// is read again only after the debounce (five seconds from its last read), not at once.
#[tokio::test]
async fn api_016_router_secret_change_polls_debounced() {
    let (addr, reads) = fake_raw(HA_ANSWER.as_bytes().to_vec()).await;
    let h = with_secret(&format!(
        "[[router]]\nname = \"lab\"\ntype = \"home_assistant\"\nurl = \"http://{addr}\"\napi_key_ref = \"ha\"\ninterval_secs = 60\n"
    ));
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(super::run(Arc::clone(&h.src), stop_rx));
    assert!(eventually(|| reads.load(std::sync::atomic::Ordering::SeqCst) == 1).await);
    store_secret(&h, "ha", "tok-rotated");
    h.src.routers_changed.notify_one();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        reads.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the router was read again before the debounce"
    );
    assert!(
        eventually_within(Duration::from_secs(10), || reads
            .load(std::sync::atomic::Ordering::SeqCst)
            == 2)
        .await,
        "the router wasn't read again after the debounce"
    );
    let _ = stop_tx.send(true);
}

/// REQ: API-016 (review of T23.7, ADR-922) — a router whose answer isn't JSON, or is larger than the
/// answer limit, fails on its own: it keeps its last answer, shows the failure, and the others are
/// read as before (their names and leases stay).
#[tokio::test]
async fn api_016_malformed_and_oversized_answers_isolated() {
    let good = fake_router(HA_ANSWER).await;
    let (malformed, _) = fake_raw(b"<html>not json</html>".to_vec()).await;
    let (oversized, _) = fake_raw(vec![b'x'; (16 << 20) + 1]).await;
    let h = with_secret(&format!(
        "[[router]]\nname = \"good\"\ntype = \"home_assistant\"\nurl = \"http://{good}\"\napi_key_ref = \"ha\"\ninterval_secs = 60\n[[router]]\nname = \"malformed\"\ntype = \"home_assistant\"\nurl = \"http://{malformed}\"\napi_key_ref = \"ha\"\ninterval_secs = 60\n[[router]]\nname = \"oversized\"\ntype = \"home_assistant\"\nurl = \"http://{oversized}\"\napi_key_ref = \"ha\"\ninterval_secs = 60\n"
    ));
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(super::run(Arc::clone(&h.src), stop_rx));
    assert!(
        eventually_within(Duration::from_secs(10), || leased(
            &h,
            Ipv4Addr::new(192, 168, 1, 50)
        )
        .is_some())
        .await
    );
    assert!(
        eventually_within(Duration::from_secs(10), || {
            let snap = h.src.routers.snapshot();
            snap.get("malformed").is_some_and(|s| s.state == "failing")
                && snap.get("oversized").is_some_and(|s| s.state == "failing")
        })
        .await,
        "{:?}",
        h.src.routers.snapshot()
    );
    let snap = h.src.routers.snapshot();
    assert_eq!(snap["good"].state, "ok");
    assert_eq!(snap["good"].devices, 1);
    assert!(
        snap["malformed"]
            .error
            .as_deref()
            .is_some_and(|e| e.contains("JSON") || e.contains("expected")),
        "{:?}",
        snap["malformed"].error
    );
    assert!(
        snap["oversized"]
            .error
            .as_deref()
            .is_some_and(|e| !e.is_empty()),
        "{:?}",
        snap["oversized"].error
    );
    assert!(
        leased(&h, Ipv4Addr::new(192, 168, 1, 50)).is_some(),
        "the good router's lease went"
    );
    let _ = stop_tx.send(true);
}

/// REQ: API-016 (review of T23.8, ADR-922) — a check sends a stored secret only where it was saved
/// for: the saved router's own secret at its own address, or the secret named for this router
/// (`<kind>.<name>.<field>`) when no other router uses it. Any other secret is dropped, and the
/// answer says so (`credential_sent: false`).
#[tokio::test]
async fn api_016_check_sends_only_its_own_secret() {
    let addr = fake_router(HA_ANSWER).await;
    let h = with_secret(&format!(
        "[[router]]\nname = \"lab\"\ntype = \"home_assistant\"\nurl = \"http://{addr}\"\napi_key_ref = \"ha\"\n"
    ));
    store_secret(&h, "alert-token", "planted-alert-token");
    store_secret(&h, "home_assistant.fresh.api_key", "tok-fresh");
    let draft = |name: &str, url: &str, reference: &str| {
        let mut v = ha_body(url);
        v["name"] = json!(name);
        v["api_key_ref"] = json!(reference);
        v
    };
    let here = format!("http://{addr}");
    // Another kind's secret, at the saved address: dropped.
    let other = super::check_draft(&h.src, draft("lab", &here, "alert-token"))
        .await
        .unwrap();
    assert!(!other.credential_sent, "{other:?}");
    // The saved router's own secret, at the saved address: sent.
    let own = super::check_draft(&h.src, draft("lab", &here, "ha"))
        .await
        .unwrap();
    assert!(own.credential_sent && own.ok, "{own:?}");
    // A new router named for its secret: sent.
    let fresh = super::check_draft(
        &h.src,
        draft("fresh", &here, "home_assistant.fresh.api_key"),
    )
    .await
    .unwrap();
    assert!(fresh.credential_sent, "{fresh:?}");
    // A new router that names another router's secret: dropped.
    let borrowed = super::check_draft(&h.src, draft("newer", &here, "ha"))
        .await
        .unwrap();
    assert!(!borrowed.credential_sent, "{borrowed:?}");
    // The saved secret, sent to a new address: dropped.
    let moved = super::check_draft(&h.src, draft("lab", "http://127.0.0.1:9", "ha"))
        .await
        .unwrap();
    assert!(!moved.credential_sent && !moved.ok, "{moved:?}");
    // The check saved nothing.
    assert_eq!(h.src.config.load().router.len(), 1);
}

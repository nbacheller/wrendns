//! REQ: API-902, API-006, AGT-009, AGT-004 (T27.13; ADR-914, ADR-956 §3, §7) — the guarded routes
//! through a running node's router: who may call them (an admin's interactive session, nobody
//! else), what the generic kind routes refuse, and what the listing never says. The engine behind
//! the routes is the tests' fake node (`tests::install`); the sockets of a confirmation window are
//! simulated by the extension the real proof listener puts on a request.

#![allow(
    clippy::many_single_char_names,
    clippy::items_after_statements,
    clippy::assert_is_empty,
    clippy::too_many_lines,
    clippy::manual_assert_eq,
    clippy::assertions_on_constants
)]

use std::net::SocketAddr;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use wrendns_api::auth::{self, Role};
use wrendns_api::guarded::ArrivedOn;

use super::tests::install;
use crate::credential_tests::{Harness, harness};
use crate::settings_kinds_tests::{call_as, token};

/// A request from the admin's session, signed in `age` seconds ago, optionally arriving on `on`
/// (the confirmation window's socket).
fn session_req(
    h: &Harness,
    age: u64,
    method: &str,
    uri: &str,
    body: Option<&Value>,
    on: Option<SocketAddr>,
) -> Request<Body> {
    let user = h.auth.state().user(h.admin_id).unwrap().unwrap();
    let now = crate::pipeline::unix_now().saturating_sub(age);
    let s = h
        .auth
        .start_session(&user, "127.0.0.1".parse().unwrap(), now)
        .unwrap();
    // Only the creation time is old: the idle limit counts from now.
    let id_hash = auth::crypto::secret_hash(&s.cookie);
    h.auth
        .state()
        .touch_session(&id_hash, crate::pipeline::unix_now())
        .unwrap();
    let mut r = Request::builder()
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
        .unwrap();
    if let Some(a) = on {
        r.extensions_mut().insert(ArrivedOn(a));
    }
    r
}

async fn json_of(h: &Harness, req: Request<Body>) -> (StatusCode, Value) {
    let resp = h.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned())),
    )
}

fn unauthenticated(
    method: &str,
    uri: &str,
    body: Option<&Value>,
    on: Option<SocketAddr>,
) -> Request<Body> {
    let mut r = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .extension(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            40001,
        ))))
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    if let Some(a) = on {
        r.extensions_mut().insert(ArrivedOn(a));
    }
    r
}

/// The guarded routes a caller can reach, with bodies the engine would accept.
fn routes() -> Vec<(&'static str, String, Value)> {
    let apply = json!({"previewId": "x", "confirm": "pi-a restart", "value": null});
    let prev = json!({"value": null});
    vec![
        ("POST", "/api/v1/guarded/restart-now/preview".into(), prev),
        ("POST", "/api/v1/guarded/restart-now".into(), apply),
        (
            "POST",
            "/api/v1/guarded/pending/abc/confirm".into(),
            json!({"confirmToken": "t"}),
        ),
        (
            "POST",
            "/api/v1/guarded/pending/abc/cancel".into(),
            json!({}),
        ),
    ]
}

// REQ: API-902 (ADR-956 §3, ADR-914), AGT-004 — table-driven over the routes: an agent token is
// refused whatever its scopes (403 `agent_not_allowed`), an operator and a viewer are 403, any other
// API token is 403 `reauth_required`, no credential is 401, and an admin session gets through.
#[tokio::test]
async fn api_902_guarded_change_needs_admin_and_refuses_agents() {
    let h = harness("");
    let _n = install(&h);
    let every: Vec<&str> = auth::agent::SCOPES.iter().map(|(n, _)| *n).collect();
    let agent = token(&h, "bot", Role::Admin, Some(&every.join(" ")));
    let op = token(&h, "olive", Role::Operator, None);
    let viewer = token(&h, "vic", Role::Viewer, None);
    let admin_token = h.bearer.clone();
    for (method, uri, body) in routes() {
        let (s, _, v) = call_as(&h, &agent, method, &uri, Some(&body), &[]).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "agent {uri}: {v}");
        assert_eq!(v["code"], "agent_not_allowed", "agent {uri}: {v}");
        for (who, t) in [("operator", &op), ("viewer", &viewer)] {
            let (s, _, v) = call_as(&h, t, method, &uri, Some(&body), &[]).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{who} {uri}: {v}");
            assert_eq!(v["code"], "forbidden", "{who} {uri}: {v}");
        }
        let (s, _, v) = call_as(&h, &admin_token, method, &uri, Some(&body), &[]).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "admin token {uri}: {v}");
        assert_eq!(v["code"], "reauth_required", "admin token {uri}: {v}");
    }
    // No credential at all: 401 (the confirm route too, since it has no token to check).
    for (method, uri, body) in routes() {
        let (s, v) = json_of(&h, unauthenticated(method, &uri, Some(&json!({})), None)).await;
        let _ = body;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{uri}: {v}");
    }
    // An admin session reaches the engine: the preview answers, the others fail on their own terms.
    let (s, v) = json_of(
        &h,
        session_req(
            &h,
            5,
            "POST",
            "/api/v1/guarded/restart-now/preview",
            Some(&json!({"value": null})),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["phrase"], "pi-a restart");
    let (s, v) = json_of(
        &h,
        session_req(
            &h,
            5,
            "POST",
            "/api/v1/guarded/pending/abc/cancel",
            None,
            None,
        ),
    )
    .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found")),
        "{v}"
    );
    // An unknown setting is 404, not a 403: the role check came first and passed.
    let (s, v) = json_of(
        &h,
        session_req(
            &h,
            5,
            "POST",
            "/api/v1/guarded/nope/preview",
            Some(&json!({"value": 1})),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    // The same table, each agent scope on its own: none of them reaches the routes.
    for scope in &every {
        let t = token(
            &h,
            &format!("bot-{}", scope.replace([':', '-'], "")),
            Role::Admin,
            Some(scope),
        );
        let (s, _, v) = call_as(
            &h,
            &t,
            "POST",
            "/api/v1/guarded/restart-now/preview",
            Some(&json!({})),
            &[],
        )
        .await;
        assert_eq!(
            (s, v["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("agent_not_allowed")),
            "{scope}: {v}"
        );
    }
}

// REQ: API-902 (ADR-914) — API tokens of any kind get 403 `reauth_required` with a hint naming the
// file or the CLI; a weakening change on a stale session says so before anything changes.
#[tokio::test]
async fn api_902_tokens_refused_for_guarded_changes() {
    let h = harness("");
    let _n = install(&h);
    let (s, _, v) = call_as(
        &h,
        &h.bearer,
        "POST",
        "/api/v1/guarded/restart-now/preview",
        Some(&json!({})),
        &[],
    )
    .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("reauth_required")),
        "{v}"
    );
    let hint = v["hint"].as_str().unwrap();
    assert!(
        hint.contains("configuration file") && hint.contains("wrendns guarded list"),
        "{hint}"
    );
    // A session whose sign-in is old can preview a restart but not apply it (the restart needs a
    // sign-in in the last 10 minutes), and a fresh one can.
    let (s, p) = json_of(
        &h,
        session_req(
            &h,
            3600,
            "POST",
            "/api/v1/guarded/restart-now/preview",
            Some(&json!({})),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{p}");
    let body = json!({"previewId": p["previewId"], "confirm": p["phrase"], "value": null});
    let (s, v) = json_of(
        &h,
        session_req(
            &h,
            3600,
            "POST",
            "/api/v1/guarded/restart-now",
            Some(&body),
            None,
        ),
    )
    .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("reauth_required")),
        "{v}"
    );
}

// REQ: API-902 (ADR-956 §3) — the window over HTTP: apply answers 202 with the single-use token and
// the new address; the confirm route takes the token with no session, only from the new socket; a
// wrong token and a request on the old address are refused and the window runs on.
#[tokio::test(flavor = "multi_thread")]
async fn api_902_window_over_http_confirms_with_token_on_new_socket() {
    let h = harness("");
    let n = install(&h);
    let (s, p) = json_of(
        &h,
        session_req(
            &h,
            5,
            "POST",
            "/api/v1/guarded/t-win/preview",
            Some(&json!({"value": {"port": 40_200}})),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{p}");
    assert_eq!(p["mode"], "window");
    let body = json!({"previewId": p["previewId"], "confirm": p["phrase"], "reason": "test", "value": {"port": 40_200}});
    let (s, a) = json_of(
        &h,
        session_req(&h, 5, "POST", "/api/v1/guarded/t-win", Some(&body), None),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{a}");
    assert_eq!(a["status"], "pending");
    let (pid, tok) = (
        a["pendingId"].as_str().unwrap().to_owned(),
        a["confirmToken"].as_str().unwrap().to_owned(),
    );
    let new: SocketAddr = a["newAddress"]
        .as_str()
        .unwrap()
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .parse()
        .unwrap();
    let confirm = format!("/api/v1/guarded/pending/{pid}/confirm");
    // The token on the old address (no arrival tag) proves nothing; a wrong token on the new one.
    let (s, v) = json_of(
        &h,
        unauthenticated("POST", &confirm, Some(&json!({"confirmToken": tok})), None),
    )
    .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden")),
        "{v}"
    );
    let (s, v) = json_of(
        &h,
        unauthenticated(
            "POST",
            &confirm,
            Some(&json!({"confirmToken": "wrong"})),
            Some(new),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    // The status shows it pending (no token, no value), and the window hasn't rolled back.
    let (s, _, v) = h.call("GET", "/api/v1/guarded", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["nodes"][0]["pending"]["id"], pid.as_str());
    assert!(!v.to_string().contains(&tok) && !v.to_string().contains("40200"));
    // The right token, on the new socket, with no session.
    let (s, v) = json_of(
        &h,
        unauthenticated(
            "POST",
            &confirm,
            Some(&json!({"confirmToken": tok})),
            Some(new),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["outcome"], "confirmed");
    // The entry is written, audited, and the change is no longer pending; a second confirm is 404.
    assert_eq!(
        crate::guarded::store::for_node(h.auth.state(), "pi-a").len(),
        1
    );
    let audit = h.audit_text();
    assert!(
        audit.contains("settings.guarded ") || audit.contains("settings.guarded pi-a"),
        "{audit}"
    );
    let (s, v) = json_of(
        &h,
        unauthenticated(
            "POST",
            &confirm,
            Some(&json!({"confirmToken": tok})),
            Some(new),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    let _ = &n;
}

// REQ: API-902, OBS-020 (T27.14b) — `GET /api/v1/guarded/pending/{id}`: the same admin's session or
// the confirm token (header `X-Confirm-Token`) reads the pending change with its probe lines; a wrong
// token, no credential, another token kind and an agent token do not; the listing still names no
// address.
#[tokio::test]
async fn api_902_pending_read_over_http() {
    let h = harness("");
    let _n = install(&h);
    let body = json!({"probes": [{"proto": "udp", "addr": "192.0.2.1:53"}]});
    let (s, p) = json_of(
        &h,
        session_req(
            &h,
            5,
            "POST",
            "/api/v1/guarded/t-win/preview",
            Some(&json!({"value": body})),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{p}");
    let apply = json!({"previewId": p["previewId"], "confirm": p["phrase"], "value": body});
    let (s, a) = json_of(
        &h,
        session_req(&h, 5, "POST", "/api/v1/guarded/t-win", Some(&apply), None),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{a}");
    assert!(
        a["newAddress"].is_null(),
        "no socket to confirm through: {a}"
    );
    let (pid, tok) = (
        a["pendingId"].as_str().unwrap().to_owned(),
        a["confirmToken"].as_str().unwrap().to_owned(),
    );
    let uri = format!("/api/v1/guarded/pending/{pid}");
    // The admin's session.
    let (s, v) = json_of(&h, session_req(&h, 5, "GET", &uri, None, None)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["setting"], "t-win");
    assert_eq!(v["probes"][0]["listener"], "udp://192.0.2.1:53");
    assert_eq!(v["probes"][0]["otherHosts"], 0);
    // The token, with no session (the new-address case).
    let mut req = unauthenticated("GET", &uri, None, None);
    req.headers_mut()
        .insert("x-confirm-token", tok.parse().unwrap());
    let (s, v) = json_of(&h, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["id"], pid.as_str());
    // A wrong token, and nothing at all.
    let mut req = unauthenticated("GET", &uri, None, None);
    req.headers_mut()
        .insert("x-confirm-token", "wrong".parse().unwrap());
    let (s, v) = json_of(&h, req).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, v) = json_of(&h, unauthenticated("GET", &uri, None, None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    // An agent token (whatever its scopes) and another API token kind.
    let every: Vec<&str> = auth::agent::SCOPES.iter().map(|(n, _)| *n).collect();
    let agent = token(&h, "bot", Role::Admin, Some(&every.join(" ")));
    let (s, _, v) = call_as(&h, &agent, "GET", &uri, None, &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, _, v) = call_as(&h, &h.bearer.clone(), "GET", &uri, None, &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    // The listing names neither the token nor the staged address.
    let (s, _, v) = h.call("GET", "/api/v1/guarded", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!v.to_string().contains(&tok) && !v.to_string().contains("192.0.2.1"));
    // A pending change on this node only: another ID is 404.
    let (s, v) = json_of(
        &h,
        session_req(&h, 5, "GET", "/api/v1/guarded/pending/nope", None, None),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
}

// REQ: API-902 (ADR-956 §2) — the reserved kind `guarded` is refused by the generic kind routes
// (409 `guarded_only`), is not a kind a forwarded write can name, and never shows in a listing.
#[tokio::test]
async fn api_902_guarded_kind_refused_by_generic_routes() {
    let h = harness("");
    let _n = install(&h);
    crate::guarded::store::put(
        h.auth.state(),
        &crate::guarded::store::Stored {
            node: "pi-a".into(),
            id: "secrets-key".into(),
            value: json!({"key_file": "/keys/x"}),
            mode: "staged".into(),
            state: crate::guarded::store::EntryState::Staged,
            by: "alice".into(),
            at: 1,
        },
        1,
        "alice",
    )
    .unwrap();
    let (s, _, v) = h
        .call("GET", "/api/v1/config/entries?kind=guarded", None)
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("guarded_only")),
        "{v}"
    );
    // The unfiltered listing doesn't carry it either.
    let (s, _, v) = h.call("GET", "/api/v1/config/entries", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        !v.to_string().contains("secrets-key") && !v.to_string().contains("/keys/x"),
        "{v}"
    );
    // There is no kind route for it: a PUT under any plausible path is a 404 (the fallback), and a
    // forwarded write naming the kind doesn't deserialize.
    for path in [
        "/api/v1/guarded-entries/pi-a",
        "/api/v1/config/entries/guarded/pi-a",
    ] {
        let (s, _, _) = h.call("PUT", path, Some(&json!({"value": {}}))).await;
        assert!(
            s == StatusCode::NOT_FOUND || s == StatusCode::METHOD_NOT_ALLOWED,
            "{path}: {s}"
        );
    }
    assert!(serde_json::from_str::<wrendns_api::ManagedKind>("\"guarded\"").is_err());
    let forged = r#"{"write":"managed","kind":"guarded","name":"pi-a/listen","body":{},"dry_run":false,"expect":null,"by":"x"}"#;
    assert!(serde_json::from_str::<crate::forward::Write>(forged).is_err());
}

// REQ: API-902 (ADR-956 §7), AGT-001 — the listing needs only `config:read`, agent tokens included,
// and holds no value, preview ID or token: only that a change is pending, which setting, and the
// seconds left.
#[tokio::test]
async fn api_902_listing_readable_by_agent_without_values() {
    let h = harness("");
    let _n = install(&h);
    let agent = token(&h, "reader", Role::Admin, Some("config:read"));
    let (s, _, v) = call_as(&h, &agent, "GET", "/api/v1/guarded", None, &[]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["nodes"][0]["node"], "pi-a");
    assert_eq!(v["nodes"][0]["supervisor"]["kind"], "systemd");
    let ids: Vec<&str> = v["nodes"][0]["settings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"restart-now"));
    // Without the scope an agent can't read it.
    let blind = token(&h, "blind", Role::Admin, Some("analytics:read"));
    let (s, _, _) = call_as(&h, &blind, "GET", "/api/v1/guarded", None, &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // A viewer reads it too; the OpenAPI document describes it.
    let viewer = token(&h, "vic2", Role::Viewer, None);
    let (s, _, _) = call_as(&h, &viewer, "GET", "/api/v1/guarded", None, &[]).await;
    assert_eq!(s, StatusCode::OK);
}

// REQ: API-902 — the test registry rows and the simulated restart are not in a build without the
// cargo feature `e2e`, and no environment variable turns a restart into a no-op there.
#[cfg(not(feature = "e2e"))]
#[test]
fn api_902_test_row_absent_in_release() {
    assert!(!std::hint::black_box(
        wrendns_config::guarded::TEST_ROWS_COMPILED
    ));
    let ids: Vec<&str> = crate::guarded::appliers::rows()
        .iter()
        .map(|d| d.row.id)
        .collect();
    assert_eq!(
        ids,
        [
            "restart-now",
            "api-http-redirect",
            "listen-access",
            "dnstap-output"
        ],
        "only the real rows have appliers"
    );
    assert!(wrendns_config::guarded::rows().iter().all(|r| !r.test_only));
    // The restart's hook is named only behind the feature, so the variable can't reach it.
    let src = include_str!("restart.rs");
    for line in src.lines().filter(|l| l.contains("E2E_HOOK_ENV")) {
        let _ = line;
    }
    assert!(src.contains("#[cfg(feature = \"e2e\")]"));
    let prod = include_str!("prod.rs");
    let gated = prod.matches("#[cfg(feature = \"e2e\")]").count();
    assert!(gated >= 1, "the simulated restart is behind the feature");
    assert!(prod.contains("super::e2e::simulate_restart"));
    // `e2e.rs` is a module only under the feature.
    let m = include_str!("mod.rs");
    let lines: Vec<&str> = m.lines().collect();
    let at = lines.iter().position(|l| l.contains("mod e2e;")).unwrap();
    assert!(lines[at - 1].contains("#[cfg(feature = \"e2e\")]"));
}

// REQ: API-902, AGT-004 — the restart routes alone: agents (any scope) and every other token are
// refused, viewers and operators are 403.
#[tokio::test]
async fn api_902_restart_now_refuses_agents_and_tokens() {
    let h = harness("");
    let _n = install(&h);
    let every: Vec<&str> = auth::agent::SCOPES.iter().map(|(n, _)| *n).collect();
    let agent = token(&h, "bot", Role::Admin, Some(&every.join(" ")));
    let op = token(&h, "olive", Role::Operator, None);
    let viewer = token(&h, "vic", Role::Viewer, None);
    for (method, uri, body) in routes().into_iter().take(2) {
        let (s, _, v) = call_as(&h, &agent, method, &uri, Some(&body), &[]).await;
        assert_eq!(
            (s, v["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("agent_not_allowed"))
        );
        for t in [&op, &viewer] {
            let (s, _, v) = call_as(&h, t, method, &uri, Some(&body), &[]).await;
            assert_eq!(
                (s, v["code"].as_str()),
                (StatusCode::FORBIDDEN, Some("forbidden"))
            );
        }
        let (s, _, v) = call_as(&h, &h.bearer, method, &uri, Some(&body), &[]).await;
        assert_eq!(
            (s, v["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("reauth_required"))
        );
    }
}

// REQ: API-902 (ADR-956 §3) — cookies aren't scoped to a port: on a same-host address change the
// browser also sends the old session's cookie. A confirmation that carries its `confirmToken` is
// judged by the token alone, so a stale cookie (or a missing CSRF header) doesn't fail it.
#[tokio::test(flavor = "multi_thread")]
async fn api_902_confirm_token_is_not_failed_by_a_stale_cookie() {
    let h = harness("");
    let _n = install(&h);
    let (_, p) = json_of(
        &h,
        session_req(
            &h,
            5,
            "POST",
            "/api/v1/guarded/t-win/preview",
            Some(&json!({"value": {"port": 40_210}})),
            None,
        ),
    )
    .await;
    let body =
        json!({"previewId": p["previewId"], "confirm": p["phrase"], "value": {"port": 40_210}});
    let (s, a) = json_of(
        &h,
        session_req(&h, 5, "POST", "/api/v1/guarded/t-win", Some(&body), None),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{a}");
    let (pid, tok) = (
        a["pendingId"].as_str().unwrap().to_owned(),
        a["confirmToken"].as_str().unwrap().to_owned(),
    );
    let new: SocketAddr = a["newAddress"]
        .as_str()
        .unwrap()
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .parse()
        .unwrap();
    let mut req = unauthenticated(
        "POST",
        &format!("/api/v1/guarded/pending/{pid}/confirm"),
        Some(&json!({"confirmToken": tok})),
        Some(new),
    );
    // The browser's cookie for this host from the old address: expired, and no CSRF header.
    req.headers_mut().insert(
        "cookie",
        format!("{}=expired-or-stale", auth::routes::COOKIE)
            .parse()
            .unwrap(),
    );
    let (s, v) = json_of(&h, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["outcome"], "confirmed");
}

// REQ: API-902 (ADR-956 §3) — a `proxy_list` proof is a real one: the request has to pass under the
// new list (its peer is one of the new proxies, and the client address it shows is not the peer's).
// A request with no forwarded address, or from a peer outside the new list, proves nothing.
#[tokio::test(flavor = "multi_thread")]
async fn api_902_proxy_list_proof_needs_a_real_forwarded_client() {
    let h = harness("");
    let _n = install(&h);
    let start = |list: Value| {
        let h = &h;
        async move {
            let (_, p) = json_of(
                h,
                session_req(
                    h,
                    5,
                    "POST",
                    "/api/v1/guarded/t-proxy/preview",
                    Some(&json!({"value": {"proxies": list}})),
                    None,
                ),
            )
            .await;
            let body = json!({"previewId": p["previewId"], "confirm": p["phrase"], "value": {"proxies": list}});
            let (s, a) = json_of(
                h,
                session_req(h, 5, "POST", "/api/v1/guarded/t-proxy", Some(&body), None),
            )
            .await;
            assert_eq!(s, StatusCode::ACCEPTED, "{a}");
            a["pendingId"].as_str().unwrap().to_owned()
        }
    };
    let confirm = |pid: &str, xff: Option<&str>| {
        let mut r = session_req(
            &h,
            5,
            "POST",
            &format!("/api/v1/guarded/pending/{pid}/confirm"),
            Some(&json!({})),
            None,
        );
        if let Some(x) = xff {
            r.headers_mut()
                .insert("x-forwarded-for", x.parse().unwrap());
        }
        r
    };
    // The test peer is 127.0.0.1. A list that names it, and a request that shows a client behind it.
    let pid = start(json!(["127.0.0.1"])).await;
    let (s, v) = json_of(&h, confirm(&pid, None)).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "no forwarded address proves nothing: {v}"
    );
    let (s, v) = json_of(&h, confirm(&pid, Some("203.0.113.7"))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["seenClient"], "203.0.113.7");
    // A list that doesn't name the peer: the request can't pass under it, whatever it claims.
    let pid = start(json!(["198.51.100.1"])).await;
    let (s, v) = json_of(&h, confirm(&pid, Some("203.0.113.7"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
}

// REQ: DNS-901, API-902, AGT-004 (T27.14; ADR-914, ADR-956 §3) — the listener gate through the
// routes: agent tokens, operators, viewers and plain API tokens are refused on the preview and the
// apply; an admin's session gets a preview, a value the node can't take is refused as 422 before
// anything is written, a stale sign-in can't apply a weakening, and a fresh one applies it and the
// audit log records it.
#[tokio::test]
async fn dns_901_gate_routes_admin_only_validation_and_audit() {
    let h = harness("");
    let _n = install(&h);
    let listeners = wrendns_config::Config::default().listen;
    let line = |gate: Value, i: usize| {
        let l = &listeners[i];
        json!({"proto": serde_json::to_value(l.proto).unwrap(), "addr": l.addr.to_string(), "require_client_id": gate})
    };
    let all_default: Vec<Value> = (0..listeners.len()).map(|i| line(Value::Null, i)).collect();
    let body = json!({"value": {"listeners": all_default}});
    let every: Vec<&str> = auth::agent::SCOPES.iter().map(|(n, _)| *n).collect();
    let agent = token(&h, "bot", Role::Admin, Some(&every.join(" ")));
    let op = token(&h, "olive", Role::Operator, None);
    let viewer = token(&h, "vic", Role::Viewer, None);
    for uri in [
        "/api/v1/guarded/listen-access/preview",
        "/api/v1/guarded/listen-access",
    ] {
        let (s, _, v) = call_as(&h, &agent, "POST", uri, Some(&body), &[]).await;
        assert_eq!(
            (s, v["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("agent_not_allowed")),
            "{uri}: {v}"
        );
        for t in [&op, &viewer] {
            let (s, _, v) = call_as(&h, t, "POST", uri, Some(&body), &[]).await;
            assert_eq!(
                (s, v["code"].as_str()),
                (StatusCode::FORBIDDEN, Some("forbidden")),
                "{uri}: {v}"
            );
        }
        let (s, _, v) = call_as(&h, &h.bearer, "POST", uri, Some(&body), &[]).await;
        assert_eq!(
            (s, v["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("reauth_required")),
            "{uri}: {v}"
        );
        let (s, _) = json_of(&h, unauthenticated("POST", uri, Some(&body), None)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{uri}");
    }
    // An admin's session: a preview that says what the defaults resolve to.
    let (s, p) = json_of(
        &h,
        session_req(
            &h,
            5,
            "POST",
            "/api/v1/guarded/listen-access/preview",
            Some(&body),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{p}");
    assert_eq!(p["phrase"], "pi-a listen-access");
    assert_eq!(p["mode"], "immediate");
    assert_eq!(p["weakening"], false);
    // A key on a plain transport is refused as invalid config, whatever the transport.
    let mut bad: Vec<Value> = (0..listeners.len()).map(|i| line(Value::Null, i)).collect();
    bad[0] = line(json!(true), 0);
    let (s, v) = json_of(
        &h,
        session_req(
            &h,
            5,
            "POST",
            "/api/v1/guarded/listen-access/preview",
            Some(&json!({"value": {"listeners": bad}})),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["code"], "invalid_config", "{v}");
    assert!(
        !v["detail"].as_str().unwrap().contains("require_client_id"),
        "{v}"
    );
    // The apply, with the phrase, is accepted and recorded.
    let apply = json!({"previewId": p["previewId"], "confirm": p["phrase"], "value": body["value"], "reason": "test"});
    let (s, v) = json_of(
        &h,
        session_req(
            &h,
            5,
            "POST",
            "/api/v1/guarded/listen-access",
            Some(&apply),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "applied");
    let audit = h.audit_text();
    assert!(audit.contains("settings.guarded"), "{audit}");
    assert!(audit.contains("listen-access"), "{audit}");
}

// REQ: OBS-007, API-905, API-902 (T40.13; ADR-1107 point 4, ADR-914, ADR-956 §3; owner decision,
// 2026-11-27) - a widening dnstap change through the guarded routes: only an admin's session gets a
// preview (the phrase names the node and the setting, the mode is `staged`, it weakens), a value the
// section refuses is 422 before anything is written, a wrong phrase and a sign-in older than 10
// minutes cannot apply it, a fresh one stages it for the next start, and the audit log records it.
#[tokio::test]
async fn obs_007_dnstap_widening_goes_through_the_guarded_flow() {
    let h = harness("");
    let _n = install(&h);
    let value = json!({"socket": "/run/dnstap.sock", "sample_every": 10, "buffer": 5000});
    let body = json!({ "value": value });
    let every: Vec<&str> = auth::agent::SCOPES.iter().map(|(n, _)| *n).collect();
    let agent = token(&h, "bot", Role::Admin, Some(&every.join(" ")));
    let op = token(&h, "olive", Role::Operator, None);
    for uri in [
        "/api/v1/guarded/dnstap-output/preview",
        "/api/v1/guarded/dnstap-output",
    ] {
        let (s, _, v) = call_as(&h, &agent, "POST", uri, Some(&body), &[]).await;
        assert_eq!(
            (s, v["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("agent_not_allowed")),
            "{uri}: {v}"
        );
        let (s, _, v) = call_as(&h, &op, "POST", uri, Some(&body), &[]).await;
        assert_eq!(
            (s, v["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("forbidden")),
            "{uri}: {v}"
        );
        let (s, _, v) = call_as(&h, &h.bearer, "POST", uri, Some(&body), &[]).await;
        assert_eq!(
            (s, v["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("reauth_required")),
            "{uri}: {v}"
        );
    }
    // The ordinary route refuses the same change and says where it goes.
    let (s, _, v) = h
        .call("PUT", "/api/v1/dnstap-settings/default", Some(&value))
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("guarded_only")),
        "{v}"
    );
    let preview = |b: Value| {
        session_req(
            &h,
            5,
            "POST",
            "/api/v1/guarded/dnstap-output/preview",
            Some(&b),
            None,
        )
    };
    let (s, p) = json_of(&h, preview(body.clone())).await;
    assert_eq!(s, StatusCode::OK, "{p}");
    assert_eq!(p["phrase"], "pi-a dnstap-output");
    assert_eq!(p["mode"], "staged");
    assert_eq!(p["weakening"], true, "{p}");
    assert_eq!(p["needsRecentSignIn"], true, "{p}");
    assert_eq!(p["restartRequired"], true, "{p}");
    assert!(p["effect"].as_str().unwrap().contains("/run/dnstap.sock"));
    // A value the section refuses is 422 and nothing is written.
    for bad in [
        json!({"socket": "/a", "address": "tcp://192.0.2.5:6000"}),
        json!({"socket": "/a", "buffer": 1_000_001}),
        json!({"socket": "/a", "sample_every": 0}),
        json!({"colour": "red"}),
    ] {
        let (s, v) = json_of(&h, preview(json!({ "value": bad }))).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {v}");
        assert_eq!(v["code"], "invalid_config", "{bad}: {v}");
    }
    let stored = || {
        crate::guarded::store::for_node(h.auth.state(), "pi-a")
            .into_iter()
            .find(|e| e.id == "dnstap-output")
    };
    let apply = |age: u64, confirm: &str| {
        let b = json!({"previewId": p["previewId"], "confirm": confirm, "value": value, "reason": "test"});
        session_req(
            &h,
            age,
            "POST",
            "/api/v1/guarded/dnstap-output",
            Some(&b),
            None,
        )
    };
    // A wrong phrase, and a sign-in 11 minutes old, cannot apply it.
    let (s, v) = json_of(&h, apply(5, "pi-a restart")).await;
    assert_ne!(s, StatusCode::OK, "{v}");
    assert!(stored().is_none());
    let (s, v) = json_of(&h, apply(11 * 60, "pi-a dnstap-output")).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("reauth_required")),
        "{v}"
    );
    assert!(stored().is_none());
    // A fresh one stages it for the next start, and the audit log records it.
    let (s, v) = json_of(&h, apply(5, "pi-a dnstap-output")).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["status"], "staged", "{v}");
    let e = stored().expect("the staged entry");
    assert_eq!(e.state, crate::guarded::store::EntryState::Staged);
    assert_eq!(e.value["socket"], "/run/dnstap.sock");
    let audit = h.audit_text();
    assert!(audit.contains("settings.guarded"), "{audit}");
    assert!(audit.contains("dnstap"), "{audit}");
    // The running tap has not changed: the node reads it at its next start.
    assert!(
        crate::managed::merge(
            &h.src.file_config.load_full(),
            &crate::managed::entries(h.auth.state())
        )
        .unwrap()
        .telemetry
        .dnstap
        .socket
        .is_none()
    );
}

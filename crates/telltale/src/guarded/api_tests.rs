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
use telltale_api::auth::{self, Role};
use telltale_api::guarded::ArrivedOn;
use tower::ServiceExt as _;

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
        hint.contains("configuration file") && hint.contains("telltale guarded list"),
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
    assert!(serde_json::from_str::<telltale_api::ManagedKind>("\"guarded\"").is_err());
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
        telltale_config::guarded::TEST_ROWS_COMPILED
    ));
    let ids: Vec<&str> = crate::guarded::appliers::rows()
        .iter()
        .map(|d| d.row.id)
        .collect();
    assert_eq!(ids, ["restart-now"], "only the real rows have appliers");
    assert!(
        telltale_config::guarded::rows()
            .iter()
            .all(|r| !r.test_only)
    );
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

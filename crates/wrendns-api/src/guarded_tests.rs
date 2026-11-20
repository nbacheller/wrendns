//! REQ: API-902, AGT-009 (T27.13; ADR-956 §3, §7) — the guarded framework against the agent
//! surfaces (MCP, plans, the agent route policy) and the proxy-list rule of the confirm route.

use std::sync::Arc;

use axum::http::Method;
use serde_json::{Value, json};

use crate::auth::agent::{Need, never_for_agents, required};
use crate::guarded::is_guarded_path;

const GUARDED_IDS: &[&str] = &[
    "listen",
    "api-address",
    "api-tls",
    "api-http-redirect",
    "trusted-proxies",
    "secret-file-dirs",
    "allow-secrets-over-http",
    "allow-insecure-basic",
    "secrets-key",
    "node-identity",
    "data-dir",
    "watchdog",
    "file-paths",
    "cluster-init",
    "cluster-join",
    "cluster-leave",
    "cluster-git",
    "restart-now",
];

fn sample_args() -> Value {
    json!({
        "domain": "guarded.example", "reason": "r", "name": "x", "client": "1.1.1.1",
        "devices": ["a"], "groups": ["g"], "url": "https://x.example/list", "match": ["1.1.1.1"],
    })
}

// REQ: API-902 (ADR-956 §7), AGT-009 — no registry row, route or setting is reachable by an agent:
// no MCP tool names a guarded path or setting, no write tool's REST write is a guarded path, the
// agent policy refuses every change to `/api/v1/guarded...` (and allows only the listing, under
// `config:read`), and the plan store never keeps a plan for one.
#[test]
fn api_902_guarded_routes_not_in_mcp_or_plans() {
    let ids: Vec<&str> = wrendns_config::guarded::rows()
        .iter()
        .map(|r| r.id)
        .chain(wrendns_config::guarded::PLANNED.iter().map(|p| p.id))
        .collect();
    for id in &ids {
        assert!(
            GUARDED_IDS.contains(id) || id.starts_with("e2e-"),
            "`{id}` is guarded but not in this test's list"
        );
    }
    let catalog = crate::mcp::catalog().to_string();
    assert!(
        !catalog.contains("/api/v1/guarded"),
        "a tool names a guarded route"
    );
    for t in crate::mcp::tools() {
        assert!(
            !GUARDED_IDS.iter().any(|id| t.name.contains(id)),
            "{}",
            t.name
        );
        for args in [sample_args(), json!({})] {
            if let Ok(calls) = (t.calls)(&args) {
                assert!(calls.iter().all(|(_, p)| !is_guarded_path(p)), "{}", t.name);
            }
        }
    }
    for w in crate::mcp::write_tools() {
        assert!(
            !GUARDED_IDS.iter().any(|id| w.name.contains(id)),
            "{}",
            w.name
        );
        for args in [sample_args(), json!({})] {
            if let Ok(write) = (w.write)(&args) {
                assert!(
                    !is_guarded_path(&write.path),
                    "{} writes a guarded path",
                    w.name
                );
            }
        }
    }
    // The agent policy: every route of the framework, for every method but the listing.
    let mut paths: Vec<String> = GUARDED_IDS
        .iter()
        .flat_map(|id| {
            [
                format!("/api/v1/guarded/{id}"),
                format!("/api/v1/guarded/{id}/preview"),
            ]
        })
        .collect();
    paths.extend([
        "/api/v1/guarded/pending/p1/confirm".to_owned(),
        "/api/v1/guarded/pending/p1/cancel".to_owned(),
    ]);
    for p in &paths {
        for m in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            assert!(never_for_agents(&m, p), "{m} {p}");
            assert_eq!(required(&m, p), Need::Forbidden, "{m} {p}");
        }
    }
    assert!(!never_for_agents(&Method::GET, "/api/v1/guarded"));
    assert_eq!(
        required(&Method::GET, "/api/v1/guarded"),
        Need::Scope("config:read")
    );
    // The plan store: a plan for a guarded path comes back discarded and is never kept.
    let plans = crate::plans::Plans::default();
    let mut p = crate::plans::tests_plan("g1", "token:a", "ready", crate::plans::now() + 600);
    p.method = "POST".into();
    p.path = "/api/v1/guarded/restart-now".into();
    p.write_body = Some(json!({"confirm": "x"}));
    let out = plans.add(p);
    assert_eq!(out.state, "discarded");
    assert!(out.write_body.is_none());
    assert!(plans.get("g1").is_none(), "nothing was stored");
    assert!(is_guarded_path("/api/v1/guarded?x=1") && is_guarded_path("/api/v1/guarded/a/preview"));
    assert!(!is_guarded_path("/api/v1/guardedx") && !is_guarded_path("/api/v1/rules/guarded"));
}

// REQ: API-902 (ADR-956 §3) — a pending `trusted-proxies` list changes the address the confirm
// route sees and nothing else: `remote` (break-glass networks, rate limits, the audit source,
// loopback checks) keeps the list in force.
#[test]
fn api_902_remote_under_pending_list_only_for_the_confirm_route() {
    use std::net::{IpAddr, SocketAddr};
    let auth = crate::auth::Auth::new(
        Arc::new(wrendns_store::state::State::in_memory().unwrap()),
        crate::auth::Settings::default(),
    );
    let mut ext = axum::http::Extensions::new();
    ext.insert(axum::extract::ConnectInfo(SocketAddr::from((
        [10, 0, 0, 5],
        1234,
    ))));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
    // The list in force is empty: the proxy's own address is the client, whatever it forwards.
    let now = crate::auth::routes::remote(&auth, &ext, &headers);
    assert_eq!(now, "10.0.0.5".parse::<IpAddr>().unwrap());
    // Under the pending list the node would see the forwarded client.
    let list = vec![("10.0.0.0".parse::<IpAddr>().unwrap(), 8)];
    let under = crate::auth::routes::remote_under(&auth, &ext, &headers, &list);
    assert_eq!(under, "203.0.113.9".parse::<IpAddr>().unwrap());
    // A host that isn't in the pending list can't forge its address with the header.
    let mut far = axum::http::Extensions::new();
    far.insert(axum::extract::ConnectInfo(SocketAddr::from((
        [192, 0, 2, 1],
        1,
    ))));
    assert_eq!(
        crate::auth::routes::remote_under(&auth, &far, &headers, &list),
        "192.0.2.1".parse::<IpAddr>().unwrap()
    );
    // And asking again changes nothing about what is in force.
    assert_eq!(crate::auth::routes::remote(&auth, &ext, &headers), now);
}

// REQ: API-902 — the problem codes ADR-956 adds are stable, with their statuses.
#[test]
fn api_902_problem_codes_and_statuses() {
    use crate::problem::{Code, Problem};
    let table = [
        (Code::GuardedOnly, 409, "guarded_only"),
        (Code::GuardedChangePending, 409, "guarded_change_pending"),
        (Code::PreviewStale, 409, "preview_stale"),
        (Code::PrimaryUnreachable, 409, "primary_unreachable"),
        (Code::WouldDisconnectYou, 409, "would_disconnect_you"),
        (Code::NoSupervisor, 409, "no_supervisor"),
        (Code::Restarting, 409, "restarting"),
        (Code::NotPrimary, 421, "not_primary"),
        (Code::AgentNotAllowed, 403, "agent_not_allowed"),
        (Code::ReauthRequired, 403, "reauth_required"),
    ];
    for (code, status, name) in table {
        let p = Problem::new(code, "x");
        assert_eq!(p.status, status, "{name}");
        assert_eq!(serde_json::to_value(code).unwrap(), name);
    }
}

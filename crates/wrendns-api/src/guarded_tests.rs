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
    "api-public-url",
    "listen-access",
    "dnstap-output",
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
        "/api/v1/guarded/pending/p1/confirm-relay".to_owned(),
    ]);
    for p in &paths {
        for m in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            assert!(never_for_agents(&m, p), "{m} {p}");
            assert_eq!(required(&m, p), Need::Forbidden, "{m} {p}");
        }
    }
    assert!(!never_for_agents(&Method::GET, "/api/v1/guarded"));
    // The read of one pending change names the staged addresses: never for an agent (T27.14b).
    assert!(never_for_agents(&Method::GET, "/api/v1/guarded/pending/p1"));
    assert_eq!(
        required(&Method::GET, "/api/v1/guarded/pending/p1"),
        Need::Forbidden
    );
    assert_eq!(
        required(&Method::GET, "/api/v1/guarded"),
        Need::Scope("config:read")
    );
    // REQ: API-902 (T27.14g0) - another node's own settings are an admin's: never an agent's.
    assert!(never_for_agents(
        &Method::GET,
        "/api/v1/guarded/nodes/pi-b/api"
    ));
    assert_eq!(
        required(&Method::GET, "/api/v1/guarded/nodes/pi-b/api"),
        Need::Forbidden
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

// REQ: API-902 (ADR-977 point 12; T27.14c) — a plan step that names `listen`, or a path inside it, in
// its REST path or as a key of its body is refused: discarded, never stored or replayed. A step that
// only has the word inside another name is not.
#[test]
fn api_902_plan_naming_listen_is_refused() {
    use crate::guarded::names_listen_setting as names;
    assert!(names("/api/v1/config/listen", None));
    assert!(names("/api/v1/config/listen/0/addr?x=1", None));
    assert!(names("/api/v1/config/listen.tls", None));
    assert!(names(
        "/api/v1/x",
        Some(&json!({"listen": [{"proto": "udp"}]}))
    ));
    assert!(names(
        "/api/v1/x",
        Some(&json!({"listen.addr": "0.0.0.0:53"}))
    ));
    assert!(!names("/api/v1/clients/listening", None));
    assert!(!names(
        "/api/v1/config/entries/upstream",
        Some(&json!({"listening": 1}))
    ));
    assert!(!names("/api/v1/x", Some(&json!([{"listen": 1}]))));
    let plans = crate::plans::Plans::default();
    for (path, body) in [
        ("/api/v1/config/listen", None),
        ("/api/v1/config/x", Some(json!({"listen": []}))),
    ] {
        let mut p = crate::plans::tests_plan("l1", "token:a", "ready", crate::plans::now() + 600);
        p.method = "PUT".into();
        p.path = path.into();
        p.write_body = body;
        let out = plans.add(p);
        assert_eq!(out.state, "discarded", "{path}");
        assert!(out.write_body.is_none());
        assert!(plans.get("l1").is_none(), "nothing was stored");
    }
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

// REQ: API-902 (ADR-956 §3, ADR-977 point 7 as amended 2026-11-27) - the `proxy_list` proof. A
// request passes through the new list (its peer is a new proxy and a client differs from it), or
// directly (its peer is in neither the list in force nor the new one). It does not pass when its peer
// is in the old list but not the new one, or is in the new list with no forwarded client.
#[test]
fn api_902_proxy_list_proof_through_the_new_list_or_directly() {
    use std::net::{IpAddr, SocketAddr};
    let auth = crate::auth::Auth::new(
        Arc::new(wrendns_store::state::State::in_memory().unwrap()),
        crate::auth::Settings::default(),
    );
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let from = |peer: [u8; 4]| {
        let mut e = axum::http::Extensions::new();
        e.insert(axum::extract::ConnectInfo(SocketAddr::from((peer, 4000))));
        e
    };
    let xff = |v: Option<&str>| {
        let mut h = axum::http::HeaderMap::new();
        if let Some(v) = v {
            h.insert("x-forwarded-for", v.parse().unwrap());
        }
        h
    };
    let list = |s: &[&str]| s.iter().map(|a| (ip(a), 32)).collect::<Vec<_>>();
    let proven = |peer: [u8; 4], h: Option<&str>, new: &[&str], old: &[&str]| {
        crate::auth::routes::remote_under_proven(
            &auth,
            &from(peer),
            &xff(h),
            &list(new),
            &list(old),
        )
    };
    // Through the new list: a proxy that forwards a client.
    assert_eq!(
        proven([10, 0, 0, 2], Some("203.0.113.7"), &["10.0.0.2"], &[]),
        Some(ip("203.0.113.7"))
    );
    // ... but with no forwarded client the new list proves nothing.
    assert_eq!(proven([10, 0, 0, 2], None, &["10.0.0.2"], &[]), None);
    // Directly: a peer in neither list (a direct admin adding, or removing, proxies).
    assert_eq!(
        proven([192, 0, 2, 5], None, &["10.0.0.2"], &["10.0.0.3"]),
        Some(ip("192.0.2.5"))
    );
    assert_eq!(
        proven([192, 0, 2, 5], Some("198.51.100.1"), &[], &[]),
        Some(ip("192.0.2.5")),
        "a header from an unlisted peer is ignored: the peer is the client"
    );
    // The proxy this request came through is in the old list and not in the new one: refused (the
    // node would see the proxy, not the admin).
    assert_eq!(
        proven(
            [10, 0, 0, 2],
            Some("203.0.113.7"),
            &["10.0.0.9"],
            &["10.0.0.2"]
        ),
        None
    );
    assert_eq!(
        proven([10, 0, 0, 2], Some("203.0.113.7"), &[], &["10.0.0.2"]),
        None
    );
    // Through a proxy that stays: judged under the new list as before.
    assert_eq!(
        proven(
            [10, 0, 0, 2],
            Some("203.0.113.7"),
            &["10.0.0.2", "10.0.0.9"],
            &["10.0.0.2"]
        ),
        Some(ip("203.0.113.7"))
    );
    // No peer at all (not a connection): nothing is proven.
    assert_eq!(
        crate::auth::routes::remote_under_proven(
            &auth,
            &axum::http::Extensions::new(),
            &xff(None),
            &[],
            &[]
        ),
        None
    );
}

// REQ: API-902 (T27.14f) - the list in force is swappable: `remote` follows `set_trusted_proxies` at
// once, and a list swapped in is what every reader sees.
#[test]
fn api_902_trusted_proxy_list_is_swappable() {
    use std::net::{IpAddr, SocketAddr};
    let auth = crate::auth::Auth::new(
        Arc::new(wrendns_store::state::State::in_memory().unwrap()),
        crate::auth::Settings {
            trusted_proxies: vec![("192.0.2.1".parse().unwrap(), 32)],
            ..crate::auth::Settings::default()
        },
    );
    assert_eq!(
        auth.trusted_proxies().len(),
        1,
        "it starts with the settings' list"
    );
    let mut ext = axum::http::Extensions::new();
    ext.insert(axum::extract::ConnectInfo(SocketAddr::from((
        [10, 0, 0, 5],
        1234,
    ))));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
    let peer = "10.0.0.5".parse::<IpAddr>().unwrap();
    assert_eq!(crate::auth::routes::remote(&auth, &ext, &headers), peer);
    auth.set_trusted_proxies(vec![("10.0.0.0".parse().unwrap(), 8)]);
    assert_eq!(
        crate::auth::routes::remote(&auth, &ext, &headers),
        "203.0.113.9".parse::<IpAddr>().unwrap()
    );
    auth.set_trusted_proxies(Vec::new());
    assert_eq!(crate::auth::routes::remote(&auth, &ext, &headers), peer);
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
        (Code::RelayRefused, 403, "relay_refused"),
    ];
    for (code, status, name) in table {
        let p = Problem::new(code, "x");
        assert_eq!(p.status, status, "{name}");
        assert_eq!(serde_json::to_value(code).unwrap(), name);
    }
}

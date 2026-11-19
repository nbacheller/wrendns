//! REQ: OBS-901 (T26.2, ADR-958) — the live network map over HTTP: roles, the snapshot, the
//! stream's cap and its ticker, a dead peer, and the per-peer cache.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use super::*;
use crate::map::{MapPart, MapParts, MapSettings, PartUpstream, Thresholds};
use telltale_telemetry::map::{AnswerKind, ClientKey, Counts, Entry, Window};

fn settings(enabled: bool) -> MapSettings {
    MapSettings {
        enabled,
        event_rate: 200,
        thresholds: Thresholds::default(),
    }
}

pub(super) fn part(node: &str) -> MapPart {
    let mut ip = [0u8; 16];
    ip[10] = 0xff;
    ip[11] = 0xff;
    ip[12..].copy_from_slice(&[192, 168, 1, 7]);
    MapPart {
        node: node.to_owned(),
        window: Window {
            window_secs: 60,
            sample_rate: 1,
            dropped: 0,
            privacy: 0,
            entries: vec![Entry {
                client: ClientKey(ip),
                group: 0,
                upstream: 1,
                kind: AnswerKind::Upstream,
                c: Counts {
                    sampled: 30,
                    weighted: 300,
                    slow: 0,
                    error: 0,
                    blocked: 0,
                    limited: 0,
                },
            }],
            other: Counts::default(),
            recent: Vec::new(),
        },
        upstreams: vec![PartUpstream {
            id: 1,
            name: "quad9".into(),
            breaker: "closed".into(),
            ..PartUpstream::default()
        }],
        level: "healthy".into(),
        reasons: Vec::new(),
        groups: vec!["default".into()],
        anomalous: Vec::new(),
        answers_recorded: false,
        answers: Vec::new(),
    }
}

pub(super) fn setup(fake: &Fake, enabled: bool) {
    *fake.map.lock().unwrap() = (
        Some(settings(enabled)),
        MapParts {
            parts: vec![part("pi1")],
            missing: Vec::new(),
            unseen: Vec::new(),
            pending: Vec::new(),
        },
    );
}

pub(super) fn bearer_for(app: &TestApp, name: &str, role: auth::Role, level: &str) -> String {
    let u = app
        .auth
        .create_user(name, "a long enough password", role, false, NOW)
        .unwrap();
    let (tid, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
    app.auth
        .state()
        .create_token(
            &tid,
            u.id,
            name,
            &auth::crypto::secret_hash(&secret),
            level,
            None,
            NOW,
        )
        .unwrap();
    format!("tt_{tid}_{secret}")
}

pub(super) fn get_with(uri: &str, bearer: &str) -> Request<Body> {
    Request::get(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap()
}

/// The map's routes are in the OpenAPI document, with the error codes they answer.
#[tokio::test]
async fn obs_901_openapi_lists_the_map_routes() {
    let (app, _) = app();
    let (_, _, v) = send(
        &app,
        Request::get("/api/v1/openapi.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    for p in [
        "/api/v1/map",
        "/api/v1/map/stream",
        "/api/v1/map/world",
        "/api/v1/map/health",
        "/api/v1/map-settings/default",
    ] {
        assert!(v["paths"][p].is_object(), "{p}");
    }
    let codes = v["components"]["schemas"]["Code"].to_string();
    assert!(codes.contains("map_disabled") && codes.contains("map_streams_busy"));
}

/// The snapshot over HTTP, with its filters, and `map_disabled` when the map is off.
#[tokio::test]
async fn obs_901_snapshot_over_http() {
    let (app, fake) = app();
    // No map on this backend, or off: 404 with the code, on every route.
    for uri in [
        "/api/v1/map",
        "/api/v1/map/stream",
        "/api/v1/map/world",
        "/api/v1/map/health",
    ] {
        let (s, _, v) = get(&app, uri).await;
        assert_eq!(
            (s, v["code"].as_str()),
            (StatusCode::NOT_FOUND, Some("map_disabled")),
            "{uri}"
        );
    }
    setup(&fake, false);
    let (s, _, v) = get(&app, "/api/v1/map").await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("map_disabled"))
    );
    setup(&fake, true);
    let (s, _, v) = get(&app, "/api/v1/map").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["windowSecs"], 60);
    assert_eq!(v["sampleRate"], 1);
    assert_eq!(v["partial"], false);
    let nodes = v["nodes"].as_array().unwrap();
    let ids: Vec<&str> = nodes.iter().map(|n| n["id"].as_str().unwrap()).collect();
    for id in [
        "gateway",
        "dev:192.168.1.7",
        "res:pi1",
        "up:quad9",
        "ans:pi1:cache",
    ] {
        assert!(ids.contains(&id), "{id} in {ids:?}");
    }
    let dev = nodes.iter().find(|n| n["id"] == "dev:192.168.1.7").unwrap();
    assert_eq!(dev["health"], "green");
    assert_eq!(dev["count"], 300);
    // A filter on a node nothing is called by leaves no flows.
    let (s, _, v) = get(&app, "/api/v1/map?node=nope").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        v["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|n| n["kind"] != "device")
    );
    let (s, _, v) = get(&app, "/api/v1/map/health").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["health"], "green");
    assert_eq!(v["busiest"].as_array().unwrap().len(), 5);
    let (s, _, v) = get(&app, "/api/v1/map/world").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["available"], false);
    // The test backend has no GeoIP database: off (T26.4); the address (ADR-970) is T26.5's.
    assert_eq!(v["reason"], "geoip_off");
    assert_eq!(v["unlocated"]["count"], 300);
}

/// ADR-958 test plan: viewers read the map, operators write the thresholds, agents need
/// `analytics:read` to read it and `config:write:map` to change it; the MCP `network_health`
/// tool is a read with `analytics:read`.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one flow per role
async fn obs_901_roles() {
    let (app, fake) = app();
    setup(&fake, true);
    let viewer = bearer_for(&app, "vic", auth::Role::Viewer, "read");
    let operator = bearer_for(&app, "oscar", auth::Role::Operator, "write");
    let put = |bearer: &str, body: &str| {
        Request::put("/api/v1/map-settings/default")
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    };
    // Viewers read, and may not write.
    for uri in ["/api/v1/map", "/api/v1/map/health", "/api/v1/map/world"] {
        let (s, _, v) = send(&app, get_with(uri, &viewer)).await;
        assert_eq!(s, StatusCode::OK, "{uri}: {v}");
    }
    // The settings are read on the same path they are written on: a viewer reads, and may not write.
    let (s, _, v) = send(&app, get_with("/api/v1/map-settings/default", &viewer)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["kind"], "map");
    assert_eq!(v["definition"]["event_rate"], 200);
    assert_eq!(v["source"], "file");
    let (s, _, _) = send(&app, put(&viewer, r#"{"event_rate": 300}"#)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a viewer can't change thresholds");
    // An operator's write reaches the backend as the map's managed kind.
    let (s, _, v) = send(&app, put(&operator, r#"{"event_rate": 300}"#)).await;
    assert_eq!(
        s,
        StatusCode::SERVICE_UNAVAILABLE,
        "recorded by the fake: {v}"
    );
    let seen = fake.seen.lock().unwrap().clone();
    assert!(
        seen.iter().any(|l| l.starts_with("managed Map default")),
        "{seen:?}"
    );
    let (s, _, _) = send(
        &app,
        Request::delete("/api/v1/map-settings/default")
            .header("authorization", format!("Bearer {viewer}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Agents.
    let token = |name: &str, scopes: &str| {
        Request::post("/api/v1/tokens")
            .header("cookie", &app.cookie)
            .header("x-csrf-token", &app.csrf)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"name":"{name}","kind":"agent","scopes":[{scopes}]}}"#
            )))
            .unwrap()
    };
    let (s, _, v) = send(&app, token("reader", r#""analytics:read""#)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let reader = v["token"].as_str().unwrap().to_owned();
    let (s, _, v) = send(&app, token("cfg", r#""config:read""#)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let cfg = v["token"].as_str().unwrap().to_owned();
    let (s, _, v) = send(&app, token("writer", r#""config:write:map""#)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let writer = v["token"].as_str().unwrap().to_owned();
    for uri in ["/api/v1/map", "/api/v1/map/health", "/api/v1/map/world"] {
        let (s, _, v) = send(&app, get_with(uri, &reader)).await;
        assert_eq!(s, StatusCode::OK, "{uri}: {v}");
        let (s, _, v) = send(&app, get_with(uri, &cfg)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{uri}: {v}");
        assert!(
            v["detail"].as_str().unwrap().contains("analytics:read"),
            "{v}"
        );
    }
    let (s, _, _) = send(&app, put(&reader, r#"{"event_rate": 300}"#)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "analytics:read can't write");
    // The settings are config: `config:read` reads them, `analytics:read` alone doesn't.
    let (s, _, v) = send(&app, get_with("/api/v1/map-settings/default", &cfg)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, _) = send(&app, get_with("/api/v1/map-settings/default", &reader)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let req = Request::put("/api/v1/map-settings/default")
        .header("authorization", format!("Bearer {writer}"))
        .header("x-telltale-reason", "the map is too thin")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"event_rate": 400}"#))
        .unwrap();
    let (s, _, v) = send(&app, req).await;
    assert_eq!(
        s,
        StatusCode::SERVICE_UNAVAILABLE,
        "past the scope check, recorded by the fake: {v}"
    );
    // The MCP tool is a thin read over the health route.
    let rpc = |bearer: &str, body: serde_json::Value| {
        Request::post("/mcp")
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let call = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "network_health", "arguments": {}}});
    let (_, _, v) = send(&app, rpc(&reader, call.clone())).await;
    assert_eq!(v["result"]["isError"], false, "{v}");
    assert_eq!(
        v["result"]["structuredContent"]["networkHealth"]["health"], "green",
        "{v}"
    );
    let (_, _, v) = send(&app, rpc(&cfg, call)).await;
    assert_eq!(v["result"]["isError"], true, "needs analytics:read: {v}");
    let (_, _, v) = send(
        &app,
        rpc(
            &reader,
            serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        ),
    )
    .await;
    let tools = v["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"network_health"), "{names:?}");
    // The tool says what it leaves out at privacy level 2 and above.
    let desc = tools
        .iter()
        .find(|t| t["name"] == "network_health")
        .unwrap()["description"]
        .as_str()
        .unwrap();
    assert!(desc.contains("privacy levels 0 and 1"), "{desc}");
}

/// ADR-958 test plan: at most 8 streams per node (429 on the ninth, with `Retry-After`), and a
/// seat is free again once a stream closes.
#[tokio::test]
async fn obs_901_stream_cap_and_stop() {
    let (app, fake) = app();
    setup(&fake, true);
    let mut open = Vec::new();
    // Each viewer may hold 2 streams: four viewers fill the node's 8 seats.
    let viewers: Vec<String> = (0..4)
        .map(|i| bearer_for(&app, &format!("v{i}"), auth::Role::Viewer, "read"))
        .collect();
    let third = bearer_for(&app, "extra", auth::Role::Viewer, "read");
    for i in 0..crate::map_api::MAX_STREAMS {
        let resp = app
            .router
            .clone()
            .oneshot(get_with("/api/v1/map/stream", &viewers[i / 2]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "stream {i}");
        assert_eq!(resp.headers()["content-type"], "text/event-stream");
        open.push(resp);
    }
    let resp = app
        .router
        .clone()
        .oneshot(get_with("/api/v1/map/stream", &third))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "the ninth");
    assert!(resp.headers().contains_key("retry-after"));
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["code"], "map_streams_busy");
    // Closing one frees its seat.
    drop(open.pop());
    let resp = app
        .router
        .clone()
        .oneshot(get_with("/api/v1/map/stream", &third))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "a seat is free again");
    // One viewer's third stream is refused although seats are free elsewhere.
    drop(open.pop());
    let resp = app
        .router
        .clone()
        .oneshot(get_with("/api/v1/map/stream", &viewers[0]))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a third stream of one user"
    );
}

/// One ticker serves every subscriber, builds one unfiltered snapshot per interval, and is idle
/// at zero subscribers (it stops, and starts again for the next one).
#[tokio::test]
#[allow(clippy::many_single_char_names)]
async fn obs_901_ticker_serves_all_and_stops_at_zero() {
    let fake = Arc::new(Fake::default());
    setup(&fake, true);
    let hub = crate::map_api::MapHub::new(Arc::clone(&fake) as Shared, Duration::from_millis(40));
    assert!(!hub.running(), "nothing runs before the first stream");
    let mut a = hub.subscribe().unwrap();
    let mut b = hub.subscribe().unwrap();
    assert_eq!(hub.subscribers(), 2);
    let (x, y) = (a.next(true).await.unwrap(), b.next(true).await.unwrap());
    let v: serde_json::Value = serde_json::from_str(&x).unwrap();
    assert_eq!(v["windowSecs"], 60);
    assert!(!y.is_empty());
    // It keeps ticking while somebody listens: the next snapshot arrives by itself.
    let t0 = hub.ticks();
    a.next(false).await.unwrap();
    assert!(hub.ticks() > t0);
    drop(a);
    assert!(hub.running(), "one stream is left");
    drop(b);
    assert_eq!(hub.subscribers(), 0);
    // Idle at zero: the ticker ends within an interval or two, and stops counting.
    let mut waited = 0;
    while hub.running() && waited < 100 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        waited += 1;
    }
    assert!(!hub.running(), "the ticker stopped with nobody listening");
    let frozen = hub.ticks();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(hub.ticks(), frozen, "no snapshots are built for nobody");
    // And a new stream starts it again.
    let mut c = hub.subscribe().unwrap();
    assert!(c.next(true).await.is_some());
    assert!(hub.running());
}

/// A backend in a cluster: it reads its peers only through the cache (as the real one does).
struct Clustered {
    fake: Fake,
    cache: Arc<crate::map_api::PeerCache>,
    demand: Arc<crate::map_api::Demand>,
    peers: Vec<crate::map_api::PeerRef>,
}

impl Backend for Clustered {
    fn now_unix_seconds(&self) -> u64 {
        NOW
    }
    fn system_info(&self) -> SystemInfo {
        self.fake.system_info()
    }
    fn map_settings(&self) -> Option<MapSettings> {
        Some(settings(true))
    }
    fn map_part(&self) -> Option<MapPart> {
        Some(part("pi1"))
    }
    // Only reads the cache: a hung peer can't hold it.
    fn map_parts(&self) -> MapParts {
        let _ = self.demand.touch(Instant::now());
        let mut v = self.cache.view(&self.peers, Instant::now());
        v.parts.insert(0, part("pi1"));
        v
    }
    fn timeseries(&self, s: Step, f: u64, t: u64) -> Vec<TimeBucket> {
        self.fake.timeseries(s, f, t)
    }
    fn top(&self, k: TopKind, h: Hour, l: usize, c: Option<IpAddr>) -> Vec<TopItem> {
        self.fake.top(k, h, l, c)
    }
    fn latency(&self, b: LatencyBy, h: Hour) -> Vec<LatencyRow> {
        self.fake.latency(b, h)
    }
    fn queries(&self, p: &QueryParams, f: u64, t: u64, l: usize) -> Result<QueryPage, Problem> {
        self.fake.queries(p, f, t, l)
    }
    fn explain(&self, p: &ExplainParams) -> Result<Explanation, Problem> {
        self.fake.explain(p)
    }
    fn lists(&self) -> Vec<ListInfo> {
        Vec::new()
    }
    fn groups(&self) -> Vec<GroupInfo> {
        Vec::new()
    }
    fn clients(&self) -> Vec<ClientInfo> {
        Vec::new()
    }
    fn upstreams(&self) -> Vec<UpstreamInfo> {
        Vec::new()
    }
}

/// ADR-958 test plan: a dead peer sets `partial` and does not delay the stream: the ticker keeps
/// its interval while the peer's call hangs, the peer is a red resolver after the stale window,
/// and a live peer's data arrives.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one scenario: gather task, ticker, three peers
async fn obs_901_dead_peer_keeps_tick() {
    use crate::map_api::{Demand, PeerCache, PeerRef};
    let start = Instant::now();
    let cache = Arc::new(PeerCache::with_stale(start, Duration::from_millis(300)));
    let demand = Arc::new(Demand::new(start));
    let peers = vec![
        PeerRef {
            id: "dead".into(),
            label: "pi-dead".into(),
            connected: true,
            relayed_up: false,
        },
        PeerRef {
            id: "live".into(),
            label: "pi-live".into(),
            connected: true,
            relayed_up: false,
        },
        PeerRef {
            id: "gone".into(),
            label: "pi-gone".into(),
            connected: false,
            relayed_up: false,
        },
    ];
    let backend = Arc::new(Clustered {
        fake: Fake::default(),
        cache: Arc::clone(&cache),
        demand: Arc::clone(&demand),
        peers: peers.clone(),
    });
    // The gather task: the live peer answers at once, the dead one never does.
    let list = peers.clone();
    tokio::spawn(crate::map_api::gather(
        Arc::clone(&cache),
        Arc::clone(&demand),
        move || list.clone(),
        |peer: String| async move {
            if peer == "live" {
                Some(part("pi-live"))
            } else {
                std::future::pending::<Option<MapPart>>().await
            }
        },
        Duration::from_millis(40),
        Duration::from_secs(30),
        Duration::from_secs(5),
    ));
    let hub = crate::map_api::MapHub::new(backend as Shared, Duration::from_millis(40));
    let mut sub = hub.subscribe().unwrap();
    let first = Instant::now();
    let text = sub.next(true).await.unwrap();
    assert!(
        first.elapsed() < Duration::from_millis(250),
        "the first snapshot didn't wait for the dead peer: {:?}",
        first.elapsed()
    );
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    // The disconnected peer is missing at once; the silent one is given its stale window.
    assert_eq!(v["missingNodes"], serde_json::json!(["pi-gone"]), "{v}");
    assert_eq!(v["partial"], true);
    // Ticks keep their pace while the dead peer's call hangs.
    let t0 = hub.ticks();
    let begun = Instant::now();
    while hub.ticks() < t0 + 5 {
        sub.next(false).await.unwrap();
        assert!(
            begun.elapsed() < Duration::from_secs(3),
            "the stream stalled"
        );
    }
    // After the stale window the silent peer is a red resolver too; the live one has data.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let text = sub.next(false).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        v["missingNodes"],
        serde_json::json!(["pi-dead", "pi-gone"]),
        "{v}"
    );
    let nodes = v["nodes"].as_array().unwrap();
    let res = |id: &str| nodes.iter().find(|n| n["id"] == id).unwrap();
    assert_eq!(res("res:pi-dead")["health"], "red");
    assert_eq!(res("res:pi-dead")["reasons"][0]["code"], "unreachable");
    assert_ne!(
        res("res:pi-live")["health"],
        "red",
        "the live peer's part arrived"
    );
    assert_eq!(res("res:pi1")["count"], 300);
    assert_eq!(v["health"], "red");
}

/// The cache's rules on their own: fresh answers show, stale ones are missing, a peer not heard
/// from yet is given its grace, a disconnected one is missing at once, and each peer holds at
/// most one poll.
#[test]
fn obs_901_peer_cache_rules() {
    use crate::map_api::{PeerCache, PeerRef};
    let t0 = Instant::now();
    let c = PeerCache::with_stale(t0, Duration::from_secs(6));
    let peers = [
        PeerRef {
            id: "a".into(),
            label: "pi-a".into(),
            connected: true,
            relayed_up: false,
        },
        PeerRef {
            id: "b".into(),
            label: "pi-b".into(),
            connected: true,
            relayed_up: false,
        },
        PeerRef {
            id: "c".into(),
            label: "pi-c".into(),
            connected: false,
            relayed_up: false,
        },
    ];
    c.put("a", part("whatever"), t0);
    let v = c.view(&peers, t0 + Duration::from_secs(1));
    assert_eq!(v.parts.len(), 1);
    assert_eq!(
        v.parts[0].node, "pi-a",
        "labelled by the cluster, not by the peer"
    );
    assert_eq!(v.missing, ["pi-c"]);
    assert_eq!(v.pending, ["pi-b"], "b is still within its grace");
    let v = c.view(&peers, t0 + Duration::from_secs(7));
    assert!(v.parts.is_empty(), "a's answer is 7 s old");
    assert_eq!(v.missing, ["pi-a", "pi-b", "pi-c"]);
    assert!(c.begin("a"));
    assert!(!c.begin("a"), "one poll at a time per peer");
    c.end("a");
    assert!(c.begin("a"));
}

/// REQ: OBS-901 (review fix) — a cache made long before the first demand gives its peers a
/// fresh grace when the gather starts: nobody is red on the first read after an idle spell, and
/// a member the relay reports up is idle, not red (ADR-971).
#[test]
fn obs_901_grace_restarts_with_the_gather_and_relayed_members_are_unseen() {
    use crate::map_api::{PeerCache, PeerRef};
    let t0 = Instant::now();
    let c = PeerCache::with_stale(t0, Duration::from_secs(6));
    let peer = |id: &str, connected: bool, relayed_up: bool| PeerRef {
        id: id.into(),
        label: format!("pi-{id}"),
        connected,
        relayed_up,
    };
    let peers = [
        peer("a", true, false),
        peer("b", true, false),
        peer("r", false, true),
    ];
    c.put("a", part("old"), t0);
    let late = t0 + Duration::from_secs(60);
    c.restart(late);
    let v = c.view(&peers, late + Duration::from_secs(1));
    assert_eq!(v.parts.len(), 0);
    assert!(
        v.missing.is_empty(),
        "pending, not missing: {:?}",
        v.missing
    );
    assert_eq!(v.pending, ["pi-a", "pi-b"], "named, never dropped");
    assert_eq!(v.unseen, ["pi-r"]);
    let v = c.view(&peers, late + Duration::from_secs(7));
    assert_eq!(v.missing, ["pi-a", "pi-b"]);
    assert_eq!(v.unseen, ["pi-r"]);
}

/// REQ: OBS-901 (review fix) — one user or token holds at most 2 streams, and the seat comes
/// back when a stream ends.
#[tokio::test]
async fn obs_901_one_owner_holds_two_streams() {
    let fake = Arc::new(Fake::default());
    setup(&fake, true);
    let hub = crate::map_api::MapHub::new(Arc::clone(&fake) as Shared, Duration::from_millis(40));
    let a = hub.subscribe_as("token:1").unwrap();
    let _b = hub.subscribe_as("token:1").unwrap();
    let err = hub.subscribe_as("token:1").unwrap_err();
    assert_eq!(err.code, crate::problem::Code::MapStreamsBusy);
    let _other = hub.subscribe_as("token:2").unwrap();
    assert_eq!(hub.subscribers(), 3, "the refused one took no seat");
    drop(a);
    assert!(hub.subscribe_as("token:1").is_ok());
}

/// REQ: OBS-901 (review fix) — turning the map off while a stream is open tells it so.
#[tokio::test]
async fn obs_901_stream_is_told_when_the_map_goes_off() {
    let fake = Arc::new(Fake::default());
    setup(&fake, true);
    let hub = crate::map_api::MapHub::new(Arc::clone(&fake) as Shared, Duration::from_millis(40));
    let mut a = hub.subscribe().unwrap();
    assert!(!a.next(true).await.unwrap().is_empty());
    setup(&fake, false);
    let mut saw_off = false;
    for _ in 0..20 {
        let t = tokio::time::timeout(Duration::from_millis(500), a.next(false))
            .await
            .unwrap()
            .unwrap();
        if t.is_empty() {
            saw_off = true;
            break;
        }
    }
    assert!(saw_off, "an empty text is the end-of-stream marker");
}

/// REQ: OBS-901 (review fix) - a cold one-shot read, with peers still inside their grace, is not
/// `partial: false` showing no peers: it is partial, with each pending peer shown idle.
#[tokio::test]
async fn obs_901_cold_read_is_partial_not_complete() {
    let (app, fake) = app();
    setup(&fake, true);
    fake.map.lock().unwrap().1.pending = vec!["pi-b".into(), "pi-c".into()];
    let reader = bearer_for(&app, "cold", auth::Role::Viewer, "read");
    let req = Request::get("/api/v1/map")
        .header("authorization", format!("Bearer {reader}"))
        .body(Body::empty())
        .unwrap();
    let (s, _, v) = send(&app, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["partial"], true, "{v}");
    assert_eq!(v["missingNodes"].as_array().unwrap().len(), 0, "{v}");
    let pend: Vec<&serde_json::Value> = v["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|n| n["reasons"].to_string().contains("pending"))
        .collect();
    assert_eq!(pend.len(), 2, "{v}");
    assert!(pend.iter().all(|n| n["health"] == "idle"), "{v}");
}

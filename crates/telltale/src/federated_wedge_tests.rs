//! REQ: CLU-004, CLU-002, API-002 (upstream #7) — a federated read never stops a runtime
//! worker. A replica whose primary never answers serves concurrent requests on a two-worker
//! runtime; each one must finish within the bound instead of wedging the runtime.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use telltale_cluster::net::{Cluster, dial, join, serve};
use telltale_cluster::node::{Identity, JoinRequest, TokenGrants};
use tower::ServiceExt;

use crate::credential_tests::{Harness, harness_in};
use telltale_api::{Backend, Shared};

/// How long any one request may take. Far above the federated read deadlines (2 s and 1 s),
/// so only a wedged runtime can miss it.
const BOUND: Duration = Duration::from_secs(10);

/// A two-node cluster: a primary whose RPC handler never answers (a wedged peer), and a
/// replica joined to it and connected. The returned primary keeps its stream alive.
async fn replica_of_a_silent_primary() -> (
    Arc<Cluster>,
    Arc<Cluster>,
    tokio::sync::watch::Sender<bool>,
    (tempfile::TempDir, tempfile::TempDir),
) {
    // Every read is accepted and never answered: the handler's future doesn't complete.
    replica_of(Arc::new(move |_peer, _kind, _body| {
        Box::pin(std::future::pending::<Result<Vec<u8>, String>>())
    }))
    .await
}

/// A two-node cluster whose primary answers peers' reads with `handler`, and a replica joined
/// to it and connected.
async fn replica_of(
    handler: telltale_cluster::net::RpcHandler,
) -> (
    Arc<Cluster>,
    Arc<Cluster>,
    tokio::sync::watch::Sender<bool>,
    (tempfile::TempDir, tempfile::TempDir),
) {
    let (pdir, rdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let url = format!("https://{addr}");
    let pid = Identity::init(pdir.path(), "home", vec![url.clone()], "k8s").unwrap();
    let token = pid
        .create_token_for(
            600,
            Some(vec![url.clone()]),
            TokenGrants {
                eligible: true,
                witness: false,
            },
        )
        .unwrap();
    let primary = Cluster::new(pid, crate::build_info::VERSION);
    primary.set_rpc_handler(handler);
    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    tokio::spawn(serve(Arc::clone(&primary), addr, stop.clone()));
    // Wait until the listener accepts (a fixed sleep races the tests running in parallel).
    for _ in 0..200 {
        if std::net::TcpStream::connect(addr).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let key = telltale_cluster::pki::new_node_key().unwrap();
    let req = JoinRequest {
        witness: false,
        ephemeral: false,
        secret: token.secret.clone(),
        csr_pem: key.csr_pem.clone(),
        advertise: vec![],
        site: "pi".into(),
        eligible: true,
        version: crate::build_info::VERSION.into(),
    };
    let resp = join(&token, &req).await.unwrap();
    let rid = Identity::save_joined(rdir.path(), &key.key_pem, &resp, "pi", true, vec![]).unwrap();
    let replica = Cluster::new(rid, crate::build_info::VERSION);
    tokio::spawn(dial(Arc::clone(&replica), stop));
    for _ in 0..400 {
        if replica.reachable_primary().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        replica.reachable_primary().is_some(),
        "the replica connects"
    );
    (replica, primary, stop_tx, (pdir, rdir))
}

/// The routes each replica request asks, once each: a peer read from `clients`, the `ETag` reads
/// (`config_version`) and `config_entries`.
const PATHS: [&str; 5] = [
    "/api/v1/clients",
    "/api/v1/records",
    "/api/v1/forwards",
    "/api/v1/rules",
    "/api/v1/config/entries",
];

/// How long a whole test body may take, setup included. The setup polls for the join (up to
/// about 15 s) and each request has `BOUND`, so only a wedged runtime can reach this.
const LIMIT: Duration = Duration::from_secs(60);

/// Runs `body` on its own thread and returns its value, panicking if it doesn't finish within
/// `LIMIT`. The wait is a plain channel, not a runtime task, so it still fires when a handler
/// has wedged the runtime's workers. A body that hangs is left behind on its thread.
fn finish_within<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(body());
    });
    match rx.recv_timeout(LIMIT) {
        Ok(value) => value,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("the test hung: a federated read blocked the runtime")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!("the test body panicked"),
    }
}

/// A multi-thread runtime with `workers` workers.
fn multi_thread_runtime(workers: usize) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .unwrap()
}

/// A silent primary's replica with an API on it: the harness, the replica and the primary.
async fn api_on_a_silent_primary() -> (
    Harness,
    Arc<Cluster>,
    Arc<Cluster>,
    tokio::sync::watch::Sender<bool>,
    (tempfile::TempDir, tempfile::TempDir),
) {
    let (replica, primary, stop, dirs) = replica_of_a_silent_primary().await;
    let h = harness_in("", Some(Arc::clone(&replica)));
    (h, replica, primary, stop, dirs)
}

/// Each of [`PATHS`] asked once, concurrently, against a replica of a silent primary on `rt`.
/// The answers are in the order the requests finish; `None` is one that didn't finish within
/// `BOUND`.
fn wedged_reads(rt: &tokio::runtime::Runtime) -> Vec<Option<StatusCode>> {
    let (h, replica, primary, stop, dirs) = rt.block_on(api_on_a_silent_primary());
    let answers = rt.block_on(async {
        let mut set = tokio::task::JoinSet::new();
        for path in PATHS {
            let req = h.request("GET", path, None);
            let app = h.app.clone();
            set.spawn(async move { app.oneshot(req).await.map(|r| r.status()).ok() });
        }
        let mut out = Vec::new();
        let _ = tokio::time::timeout(BOUND, async {
            while let Some(joined) = set.join_next().await {
                out.push(joined.ok().flatten());
            }
        })
        .await;
        out
    });
    let _ = stop.send(true);
    drop((h, replica, primary, dirs));
    answers
}

/// [`wedged_reads`] on `rt`, then the runtime is shut down without waiting: dropping a runtime
/// waits for its workers, which a wedged read holds.
fn answers_on(rt: tokio::runtime::Runtime) -> Vec<Option<StatusCode>> {
    let answers = wedged_reads(&rt);
    rt.shutdown_background();
    answers
}

/// Every request finished, and each one was 200.
fn assert_all_ok(answers: &[Option<StatusCode>]) {
    assert!(
        answers.len() == PATHS.len() && answers.iter().all(Option::is_some),
        "a request hung: a federated read blocked the runtime ({answers:?})"
    );
    for status in answers.iter().flatten() {
        assert_eq!(*status, StatusCode::OK);
    }
}

/// REQ: CLU-004 (upstream #7) — `clients` and the `ETag` reads call the federated backend, which
/// waits on the cluster stream. Concurrent requests on two workers all finish within the bound:
/// none of them holds a runtime worker while it waits for the wedged peer.
#[test]
fn clu_004_concurrent_reads_on_a_wedged_peer_all_finish() {
    let answers = finish_within(|| answers_on(multi_thread_runtime(2)));
    assert_all_ok(&answers);
}

/// REQ: CLU-004 — a current-thread runtime (the tests' and `ctl`'s) still answers the same reads.
#[test]
fn clu_004_a_current_thread_runtime_still_answers() {
    let answers = finish_within(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        answers_on(rt)
    });
    assert_all_ok(&answers);
}

/// REQ: CLU-004 — a federated read a handler didn't move to `blocking()` (a direct call on a
/// runtime worker, as `config_version` is here) doesn't hold that worker. Three such calls on
/// two workers run together and finish in about one `VERSION_DEADLINE`; held workers would
/// run them two at a time, in about twice that.
#[test]
fn clu_004_a_direct_federated_read_leaves_the_worker_free() {
    let elapsed = finish_within(|| {
        let rt = multi_thread_runtime(2);
        let (h, replica, primary, stop, dirs) = rt.block_on(api_on_a_silent_primary());
        let local: Shared = Arc::new(crate::api_backend::ApiBackend {
            src: Arc::clone(&h.src),
        });
        let fed = Arc::new(crate::federated::Federated::new(
            local,
            Arc::clone(&replica),
        ));
        let started = std::time::Instant::now();
        rt.block_on(async {
            let tasks: Vec<_> = (0..3)
                .map(|_| {
                    let fed = Arc::clone(&fed);
                    tokio::spawn(async move { fed.config_version() })
                })
                .collect();
            for t in tasks {
                let _ = t.await;
            }
        });
        let elapsed = started.elapsed();
        let _ = stop.send(true);
        rt.shutdown_background();
        drop((h, replica, primary, dirs));
        elapsed
    });
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_millis(1900),
        "three direct federated reads took {elapsed:?}, not about one deadline: a worker was held, or a read panicked"
    );
}

/// REQ: CLU-003, FLT-004 (T24.11) — concurrent requests on one shared backend each name only the
/// nodes their own reads missed. The replica's `GET /lists` read misses its silent primary; a
/// second request on the same backend answers from this node alone, and its `missingNodes` must
/// stay empty even after the first request has recorded its miss.
#[test]
fn clu_003_concurrent_requests_name_only_their_own_missing_nodes() {
    let (own, other) = finish_within(|| {
        let rt = multi_thread_runtime(2);
        let (h, replica, primary, stop, dirs) = rt.block_on(api_on_a_silent_primary());
        let local: Shared = Arc::new(crate::api_backend::ApiBackend {
            src: Arc::clone(&h.src),
        });
        let shared: Shared = Arc::new(crate::federated::Federated::new(
            local,
            Arc::clone(&replica),
        ));
        let out = rt.block_on(async {
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
            let first = telltale_api::request_backend(&shared);
            let second = telltale_api::request_backend(&shared);
            let a = tokio::spawn(async move {
                let answer = first.lists_and_hits();
                let own = first.missing_nodes();
                let _ = done_tx.send(());
                (answer.missing, own)
            });
            let b = tokio::spawn(async move {
                // A read that answers from this node alone, while the first request is in flight.
                let _ = second.system_info();
                let _ = done_rx.await;
                second.missing_nodes()
            });
            let a = a.await.unwrap_or_default();
            let b = b.await.unwrap_or_default();
            (a, b)
        });
        let _ = stop.send(true);
        rt.shutdown_background();
        drop((h, replica, primary, dirs));
        out
    });
    assert_eq!(
        own.0, own.1,
        "the request's answer and its missingNodes differ"
    );
    assert_eq!(
        own.0.len(),
        1,
        "the first request names its silent primary: {own:?}"
    );
    assert!(
        other.is_empty(),
        "a request that missed nothing names {other:?}, another request's missing node"
    );
}

/// The router read a primary answers, as JSON: the UniFi router's networks and clients, and its
/// state. An older primary answers every read it doesn't know with an error.
fn router_view_handler(old: bool) -> telltale_cluster::net::RpcHandler {
    Arc::new(move |_peer, _kind, body| {
        let known = !old && String::from_utf8_lossy(&body).contains("router_view");
        Box::pin(async move {
            if !known {
                return Err("unknown read".to_owned());
            }
            let net = |name: &str, subnet: &str, vlan: Option<u16>| {
                serde_json::json!({"name": name, "subnet": subnet, "vlan": vlan,
                    "gateway": "192.168.1.1", "source": "router", "router": "udm",
                    "addresses": 254, "devices": 2, "usedPercent": 0.8, "outsidePool": 0})
            };
            let view = serde_json::json!({
                "networks": [net("LAN", "192.168.1.0/24", None),
                    net("vlan-30", "192.168.30.0/24", Some(30)),
                    net("vlan-40", "192.168.40.0/24", Some(40))],
                "leases": [{"mac": "aa:bb:cc:00:00:01", "ip": "192.168.30.7",
                    "hostname": "kids-tablet", "expiresUnixSeconds": 0, "source": "router",
                    "router": "udm", "offline": false}],
                "statuses": [["udm", {"polledBy": "this node", "state": "ok", "lastPoll": 1234,
                    "devices": 12, "networks": 3, "intervalSecs": 300}]],
            });
            serde_json::to_vec(&view).map_err(|e| e.to_string())
        })
    })
}

/// A router with a stored credential, which a replica doesn't read.
const STORED_ROUTER: &str = "[[router]]\nname = \"udm\"\ntype = \"home_assistant\"\nurl = \"http://127.0.0.1:9\"\napi_key_ref = \"ha\"\n";

/// The replica's own status of it (what its poll loop writes).
fn replica_status() -> telltale_api::model::RouterStatus {
    telltale_api::model::RouterStatus {
        polled_by: "the primary".into(),
        state: "skipped".into(),
        last_poll: None,
        error: None,
        devices: 0,
        networks: 0,
        interval_secs: 300,
        read_by: None,
    }
}

/// What a replica's Networks, DHCP and Routers reads answer: each the JSON body.
fn router_reads(handler: telltale_cluster::net::RpcHandler) -> [serde_json::Value; 4] {
    finish_within(move || {
        let rt = multi_thread_runtime(2);
        let (replica, primary, stop, dirs) = rt.block_on(replica_of(handler));
        let h = rt.block_on(async { harness_in(STORED_ROUTER, Some(Arc::clone(&replica))) });
        h.src.routers.put("udm", replica_status());
        let out = rt.block_on(async {
            let mut out = Vec::new();
            for path in [
                "/api/v1/networks",
                "/api/v1/dhcp/leases",
                "/api/v1/routers",
                "/api/v1/profiles/devices",
            ] {
                let (status, _, text) = h.send(h.request("GET", path, None)).await;
                assert_eq!(status, StatusCode::OK, "{path}: {text}");
                out.push(serde_json::from_str::<serde_json::Value>(&text).unwrap());
            }
            out
        });
        let _ = stop.send(true);
        rt.shutdown_background();
        drop((h, replica, primary, dirs));
        [
            out[0].clone(),
            out[1].clone(),
            out[2].clone(),
            out[3].clone(),
        ]
    })
}

fn names(v: &serde_json::Value) -> Vec<&str> {
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["name"].as_str().unwrap_or_default())
        .collect()
}

/// REQ: API-013, API-010, API-016 (T24.41) - a replica's Networks, DHCP clients and Routers reads
/// come from the primary that reads the router: the router's networks (with VLANs), its clients,
/// and its state, labelled as read by the primary. Nothing is missing.
#[test]
fn api_013_a_replica_shows_the_primarys_router_data() {
    let [nets, leases, routers, picker] = router_reads(router_view_handler(false));
    // The category picker lists the primary's router networks and clients too.
    let p = picker.to_string();
    assert!(p.contains("vlan-30") && p.contains("vlan-40"), "{p}");
    assert!(p.contains("kids-tablet"), "{p}");
    let n = names(&nets);
    for want in ["LAN", "vlan-30", "vlan-40"] {
        assert!(n.contains(&want), "{want} missing from {n:?}");
    }
    let kids = nets["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == "vlan-30")
        .unwrap();
    assert_eq!(kids["vlan"], 30);
    assert_eq!(kids["gateway"], "192.168.1.1");
    assert!(nets.get("missingNodes").is_none(), "{nets}");
    assert!(
        leases["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["hostname"] == "kids-tablet" && l["router"] == "udm"),
        "{leases}"
    );
    let r = &routers["items"][0];
    assert_eq!(r["status"]["state"], "ok");
    assert_eq!(r["status"]["devices"], 12);
    assert_eq!(r["status"]["networks"], 3);
    assert_eq!(r["status"]["lastPoll"], 1234);
    assert_eq!(r["status"]["polledBy"], "the primary");
    assert!(r["status"]["readBy"].is_string(), "{r}");
    assert!(routers.get("missingNodes").is_none(), "{routers}");
}

/// REQ: API-013, API-016 (T24.41, N-1) - a primary that is away (silent) or too old to know the
/// read leaves the replica's own answer, with the primary named in `missingNodes`: no error, and
/// the router shows as not read here.
#[test]
fn api_013_a_replica_answers_without_the_primarys_router_data() {
    let silent: telltale_cluster::net::RpcHandler =
        Arc::new(|_p, _k, _b| Box::pin(std::future::pending::<Result<Vec<u8>, String>>()));
    for (label, handler) in [
        ("older primary", router_view_handler(true)),
        ("silent primary", silent),
    ] {
        let [nets, leases, routers, _] = router_reads(handler);
        assert!(!names(&nets).contains(&"LAN"), "{label}: {nets}");
        for v in [&nets, &leases, &routers] {
            assert_eq!(
                v["missingNodes"].as_array().map(Vec::len),
                Some(1),
                "{label}: {v}"
            );
        }
        let r = &routers["items"][0];
        assert_eq!(r["status"]["state"], "skipped", "{label}");
        assert!(r["status"].get("readBy").is_none(), "{label}: {r}");
    }
}

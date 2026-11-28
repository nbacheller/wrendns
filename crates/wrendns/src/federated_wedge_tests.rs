//! REQ: CLU-004, CLU-002, API-002 (upstream #7) — a federated read never stops a runtime
//! worker. A replica whose primary never answers serves concurrent requests on a two-worker
//! runtime; each one must finish within the bound instead of wedging the runtime.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use tower::ServiceExt;
use wrendns_cluster::net::{Cluster, dial, join, serve};
use wrendns_cluster::node::{Identity, JoinRequest, TokenGrants};

use crate::credential_tests::{Harness, harness_in};
use wrendns_api::{Backend, Shared};

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
    handler: wrendns_cluster::net::RpcHandler,
) -> (
    Arc<Cluster>,
    Arc<Cluster>,
    tokio::sync::watch::Sender<bool>,
    (tempfile::TempDir, tempfile::TempDir),
) {
    replica_of_announcing(handler, None).await
}

/// [`replica_of`] with a primary that announces `features` in its Hello instead of this build's
/// (`Some(vec![])`: a build from before the gated features).
async fn replica_of_announcing(
    handler: wrendns_cluster::net::RpcHandler,
    features: Option<Vec<String>>,
) -> (
    Arc<Cluster>,
    Arc<Cluster>,
    tokio::sync::watch::Sender<bool>,
    (tempfile::TempDir, tempfile::TempDir),
) {
    replica_of_announcing_url(handler, features, "").await
}

/// [`replica_of_announcing`] with a primary that announces `api_url` as its web UI and API address
/// from its first Hello (REQ: API-902, T27.14g0).
async fn replica_of_announcing_url(
    handler: wrendns_cluster::net::RpcHandler,
    features: Option<Vec<String>>,
    api_url: &str,
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
    if let Some(f) = features {
        primary.set_features(f);
    }
    primary.set_api_url(api_url);
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
    let key = wrendns_cluster::pki::new_node_key().unwrap();
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
            let first = wrendns_api::request_backend(&shared);
            let second = wrendns_api::request_backend(&shared);
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
fn router_view_handler(old: bool) -> wrendns_cluster::net::RpcHandler {
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
fn replica_status() -> wrendns_api::model::RouterStatus {
    wrendns_api::model::RouterStatus {
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
fn router_reads(handler: wrendns_cluster::net::RpcHandler) -> [serde_json::Value; 4] {
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
    let silent: wrendns_cluster::net::RpcHandler =
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

/// REQ: API-013, API-016 (T24.41 recheck, T24.42) - with no primary known (an election: no member
/// reports itself primary) the routers read still names "the primary" as missing, and answers
/// 200 from the replica's own data.
#[test]
fn api_013_no_known_primary_still_names_the_primary() {
    let silent: wrendns_cluster::net::RpcHandler =
        Arc::new(|_p, _k, _b| Box::pin(std::future::pending::<Result<Vec<u8>, String>>()));
    let body = finish_within(move || {
        let rt = multi_thread_runtime(2);
        let (replica, primary, stop, dirs) = rt.block_on(replica_of(silent));
        let h = rt.block_on(async { harness_in(STORED_ROUTER, Some(Arc::clone(&replica))) });
        h.src.routers.put("udm", replica_status());
        // The old primary steps down: no member says it is the primary any more.
        primary
            .set_role(wrendns_cluster::node::Role::Replica, 99)
            .unwrap();
        let known = rt.block_on(async {
            for _ in 0..600 {
                if replica.members().iter().all(|m| !m.primary) {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            true
        });
        let out = rt.block_on(async {
            let (status, _, text) = h.send(h.request("GET", "/api/v1/routers", None)).await;
            assert_eq!(status, StatusCode::OK, "{text}");
            serde_json::from_str::<serde_json::Value>(&text).unwrap()
        });
        let _ = stop.send(true);
        rt.shutdown_background();
        drop((h, replica, primary, dirs));
        (known, out)
    });
    let (still_known, routers) = body;
    // The role change reaches the replica with a heartbeat; when it has not within the wait the
    // primary is still "known" and the label names it instead.
    let missing = routers["missingNodes"].as_array().expect("missingNodes");
    assert_eq!(missing.len(), 1, "{routers}");
    if !still_known {
        assert_eq!(missing[0], "the primary", "{routers}");
    }
}

/// How many requests reached the primary's handler for `read` (a substring of the read's JSON).
fn counting_handler(
    read: &'static str,
    count: Arc<std::sync::atomic::AtomicUsize>,
    answer: bool,
) -> wrendns_cluster::net::RpcHandler {
    Arc::new(move |_peer, _kind, body| {
        let hit = String::from_utf8_lossy(&body).contains(read);
        if hit {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Box::pin(async move {
            if hit && !answer {
                // A primary that is away: the call waits out its deadline.
                std::future::pending::<()>().await;
            }
            Err("unknown read".to_owned())
        })
    })
}

/// REQ: API-013 (T24.42, T24.41 recheck L1) - a failed read of the primary's routers is
/// remembered for a few seconds: a page that makes several reads (Networks, leases, the profile
/// picker) asks the away primary once, not once per read.
#[test]
fn api_013_a_failed_primary_router_read_is_cached() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handler = counting_handler("router_view", Arc::clone(&count), false);
    let reads = router_reads(handler);
    for v in &reads[..3] {
        assert_eq!(v["missingNodes"].as_array().map(Vec::len), Some(1), "{v}");
    }
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "three reads, one call to the away primary"
    );
}

/// REQ: API-013, CLU-004 (T24.42) - the groups the category and list pages and the support
/// package use come from this node alone: with the primary away they ask it nothing.
#[test]
fn api_013_internal_group_reads_never_wait_on_the_primary() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handler = counting_handler("router_view", Arc::clone(&count), false);
    let (took, n) = finish_within(move || {
        let rt = multi_thread_runtime(2);
        let (replica, primary, stop, dirs) = rt.block_on(replica_of(handler));
        let h = rt.block_on(async { harness_in(STORED_ROUTER, Some(Arc::clone(&replica))) });
        h.src.routers.put("udm", replica_status());
        let local: Shared = Arc::new(crate::api_backend::ApiBackend {
            src: Arc::clone(&h.src),
        });
        let fed = Arc::new(crate::federated::Federated::new(
            local,
            Arc::clone(&replica),
        ));
        let started = std::time::Instant::now();
        let f2 = Arc::clone(&fed);
        let n = rt.block_on(async move {
            tokio::task::spawn_blocking(move || f2.groups_local().len())
                .await
                .unwrap()
        });
        let took = started.elapsed();
        // The user-facing list does ask the primary (the contrast that gives the test its point).
        rt.block_on(async move {
            tokio::task::spawn_blocking(move || fed.groups().len())
                .await
                .unwrap()
        });
        let _ = stop.send(true);
        rt.shutdown_background();
        drop((h, replica, primary, dirs));
        (took, n)
    });
    assert!(n >= 1, "the default group is listed");
    assert!(took < Duration::from_millis(1500), "waited {took:?}");
    // Only the user-facing `groups()` asked: one call, after the local read had finished.
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

use wrendns_api::secrets_api::{SecretMeta, SecretNode, SecretStamp, SecretsStatus};

fn meta(name: &str, seq: u64, health: &str) -> SecretMeta {
    SecretMeta {
        name: name.into(),
        kind: "text".into(),
        set: true,
        stamp: SecretStamp { epoch: 1, seq },
        updated: None,
        updated_by: None,
        origin: Some("cluster".into()),
        health: Some(health.into()),
        used_by: Vec::new(),
        nodes: vec![SecretNode {
            node: "x".into(),
            applied: true,
            unreadable: health != "readable",
            state: String::new(),
            stamp: None,
        }],
    }
}

fn roster(
    label: &str,
    kind: crate::secrets_api::MemberKind,
    items: Option<Vec<SecretMeta>>,
) -> crate::secrets_api::RosterNode {
    crate::secrets_api::RosterNode {
        label: label.into(),
        kind,
        items,
    }
}

/// REQ: API-015, CLU-002 (T24.42) - every full member is listed for each secret with the stamp it
/// holds and a state (applied, missing, behind, unreadable, unknown); a resolver pod and a witness
/// are listed as not holding any, by design; warnings name each full member that lacks one; the
/// answer carries stamps and health only.
#[test]
fn api_015_t24_42_every_member_is_listed_with_what_it_holds() {
    use crate::secrets_api::MemberKind::{Full, Resolver, Witness};
    let canonical = SecretsStatus {
        items: vec![
            meta("router-key", 3, "readable"),
            meta("hook", 2, "readable"),
        ],
        ..SecretsStatus::default()
    };
    let members = [
        roster(
            "node-b",
            Full,
            Some(vec![
                meta("router-key", 3, "readable"),
                meta("hook", 2, "readable"),
            ]),
        ),
        roster(
            "node-a",
            Full,
            Some(vec![meta("router-key", 3, "readable")]),
        ),
        roster(
            "node-c",
            Full,
            Some(vec![
                meta("router-key", 2, "readable"),
                meta("hook", 2, "unreadable"),
            ]),
        ),
        roster("node-d", Full, None),
        roster("pod-a", Resolver, None),
        roster("w", Witness, None),
    ];
    let out = crate::secrets_api::with_members(canonical, &members);
    let state = |item: usize, node: &str| {
        out.items[item]
            .nodes
            .iter()
            .find(|n| n.node == node)
            .map(|n| (n.state.clone(), n.stamp.map(|s| s.seq)))
            .unwrap()
    };
    assert_eq!(state(0, "node-b"), ("applied".into(), Some(3)));
    assert_eq!(state(0, "node-a"), ("applied".into(), Some(3)));
    assert_eq!(state(0, "node-c"), ("behind".into(), Some(2)));
    assert_eq!(state(0, "node-d"), ("unknown".into(), None));
    assert_eq!(state(1, "node-a"), ("missing".into(), None));
    assert_eq!(state(1, "node-c"), ("unreadable".into(), Some(2)));
    // Only full members are per-secret rows.
    assert_eq!(out.items[0].nodes.len(), 4);
    let kinds: Vec<(&str, &str, u32)> = out
        .members
        .iter()
        .map(|m| (m.kind.as_str(), m.state.as_str(), m.held))
        .collect();
    assert_eq!(
        kinds,
        [
            ("full", "answered", 2),
            ("full", "answered", 1),
            ("full", "answered", 2),
            ("full", "unknown", 0),
            ("resolver", "not_held", 0),
            ("witness", "not_held", 0),
        ]
    );
    assert_eq!(out.missing_nodes, ["node-d"]);
    let w = out.warnings.join("\n");
    assert!(w.contains("`hook` is missing on node-a"), "{w}");
    assert!(
        w.contains("node-c holds an older version of `router-key`"),
        "{w}"
    );
    assert!(w.contains("node-c holds `hook` but can't read it"), "{w}");
    assert!(!w.contains("pod-a") && !w.contains("node-d"), "{w}");
    // No value, ciphertext or hash can be in it: the type has no such field.
    let json = serde_json::to_string(&out).unwrap();
    assert!(
        !json.contains("value") && !json.contains("cipher"),
        "{json}"
    );
}

/// REQ: API-015 (T24.42) - the same list whichever node is asked: the order of the roster does
/// not change what each secret shows per member.
#[test]
fn api_015_t24_42_the_list_is_the_same_on_every_node() {
    use crate::secrets_api::MemberKind::Full;
    let canon = || SecretsStatus {
        items: vec![meta("router-key", 3, "readable")],
        ..SecretsStatus::default()
    };
    let forward = [
        roster(
            "node-a",
            Full,
            Some(vec![meta("router-key", 3, "readable")]),
        ),
        roster(
            "node-b",
            Full,
            Some(vec![meta("router-key", 3, "readable")]),
        ),
    ];
    let reversed = [forward[1].clone(), forward[0].clone()];
    let (from_one, from_two) = (
        crate::secrets_api::with_members(canon(), &forward),
        crate::secrets_api::with_members(canon(), &reversed),
    );
    let sorted = |s: &SecretsStatus| {
        let mut rows: Vec<(String, String)> = s.items[0]
            .nodes
            .iter()
            .map(|n| (n.node.clone(), n.state.clone()))
            .collect();
        rows.sort();
        rows
    };
    assert_eq!(sorted(&from_one), sorted(&from_two));
    let members = |s: &SecretsStatus| {
        let mut rows: Vec<(String, String, String, u32)> = s
            .members
            .iter()
            .map(|m| (m.node.clone(), m.kind.clone(), m.state.clone(), m.held))
            .collect();
        rows.sort();
        rows
    };
    assert_eq!(members(&from_one), members(&from_two));
    assert_eq!(from_one.warnings.len(), from_two.warnings.len());
    assert!(from_one.warnings.is_empty() && from_one.missing_nodes.is_empty());
}

/// What a primary answers to a secrets read: one stored secret, stamp 1.3, readable.
fn secrets_handler(answer: bool) -> wrendns_cluster::net::RpcHandler {
    Arc::new(move |_peer, _kind, body| {
        let hit = answer && String::from_utf8_lossy(&body).contains("secrets_status");
        Box::pin(async move {
            if !hit {
                return Err("unknown read".to_owned());
            }
            let st = SecretsStatus {
                items: vec![meta("router-key", 3, "readable")],
                ..SecretsStatus::default()
            };
            serde_json::to_vec(&st).map_err(|e| e.to_string())
        })
    })
}

fn secrets_list(handler: wrendns_cluster::net::RpcHandler) -> serde_json::Value {
    finish_within(move || {
        let rt = multi_thread_runtime(2);
        let (replica, primary, stop, dirs) = rt.block_on(replica_of(handler));
        let h = rt.block_on(async { harness_in("", Some(Arc::clone(&replica))) });
        let out = rt.block_on(async {
            let (status, _, text) = h.send(h.request("GET", "/api/v1/secrets", None)).await;
            assert_eq!(status, StatusCode::OK, "{text}");
            serde_json::from_str::<serde_json::Value>(&text).unwrap()
        });
        let _ = stop.send(true);
        rt.shutdown_background();
        drop((h, replica, primary, dirs));
        out
    })
}

/// REQ: API-015, CLU-002 (T24.42) - on a replica of a real two-node cluster the list shows both
/// full members for the primary's secret: the primary applied, this replica (which has none)
/// missing, with a warning.
#[test]
fn api_015_t24_42_a_replica_lists_every_full_member() {
    let v = secrets_list(secrets_handler(true));
    let item = &v["items"][0];
    assert_eq!(item["name"], "router-key", "{v}");
    let nodes = item["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 2, "{v}");
    let by = |n: &str| nodes.iter().find(|x| x["node"] == n).unwrap();
    assert_eq!(by("k8s")["state"], "applied", "{v}");
    assert_eq!(by("pi")["state"], "missing", "{v}");
    assert_eq!(v["members"].as_array().unwrap().len(), 2, "{v}");
    assert!(
        v["warnings"][0].as_str().unwrap().contains("missing on pi"),
        "{v}"
    );
    assert!(v.get("missingNodes").is_none(), "{v}");
}

/// REQ: API-015, CLU-002 (T24.42, N-1) - a primary that does not answer (or is too old to know
/// the read) is shown as unknown and named in `missingNodes`; the list is this node's own, marked
/// stale, and the answer is still a 200.
#[test]
fn api_015_t24_42_a_member_that_does_not_answer_is_unknown() {
    let v = secrets_list(secrets_handler(false));
    assert_eq!(v["stale"], true, "{v}");
    assert_eq!(v["missingNodes"], serde_json::json!(["k8s"]), "{v}");
    let primary = v["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["node"] == "k8s")
        .unwrap();
    assert_eq!(primary["state"], "unknown", "{v}");
}

/// REQ: API-015 (T24.42) - an `ahead` member warns that the list is stale, and a member still
/// holding a name the list no longer has set is named.
#[test]
fn api_015_t24_42_ahead_and_deleted_secrets_warn() {
    use crate::secrets_api::MemberKind::Full;
    let canon = SecretsStatus {
        items: vec![meta("router-key", 3, "readable")],
        ..SecretsStatus::default()
    };
    let out = crate::secrets_api::with_members(
        canon,
        &[
            roster(
                "node-a",
                Full,
                Some(vec![meta("router-key", 3, "readable")]),
            ),
            roster(
                "node-b",
                Full,
                Some(vec![
                    meta("router-key", 4, "readable"),
                    meta("gone", 1, "readable"),
                ]),
            ),
        ],
    );
    let w = out.warnings.join(
        "
",
    );
    assert!(
        w.contains("node-b holds a newer version of `router-key`"),
        "{w}"
    );
    assert!(w.contains("node-b still holds `gone`"), "{w}");
}

/// A primary that answers the trust anchor read with one following node holding a key in its
/// hold-down; every other read it refuses.
fn anchors_handler() -> wrendns_cluster::net::RpcHandler {
    Arc::new(|_peer, _kind, body| {
        let known = String::from_utf8_lossy(&body).contains("trust_anchors");
        Box::pin(async move {
            if !known {
                return Err("unknown read".to_owned());
            }
            let rows = vec![wrendns_api::model::TrustAnchorStatus {
                node: None,
                mode: "following".into(),
                keys: vec![
                    wrendns_api::model::TrustAnchorKey {
                        key_tag: 20326,
                        algorithm: 8,
                        flags: 257,
                        state: "valid".into(),
                        since_s: None,
                        trusted_at_s: None,
                    },
                    wrendns_api::model::TrustAnchorKey {
                        key_tag: 11111,
                        algorithm: 8,
                        flags: 257,
                        state: "add_pend".into(),
                        since_s: Some(1_000),
                        trusted_at_s: Some(1_000 + 2_592_000),
                    },
                ],
                last_reading_s: Some(2_000),
                next_reading_s: None,
                last_error: None,
            }];
            serde_json::to_vec(&rows).map_err(|e| e.to_string())
        })
    })
}

/// `GET /api/v1/dnssec/anchors` on a replica whose primary runs `features`.
fn anchors_read(features: Option<Vec<String>>) -> serde_json::Value {
    finish_within(move || {
        let rt = multi_thread_runtime(2);
        let (replica, primary, stop, dirs) =
            rt.block_on(replica_of_announcing(anchors_handler(), features));
        let h = rt.block_on(async { harness_in("", Some(Arc::clone(&replica))) });
        let v = rt.block_on(async {
            let (status, _, text) = h
                .send(h.request("GET", "/api/v1/dnssec/anchors", None))
                .await;
            assert_eq!(status, StatusCode::OK, "{text}");
            serde_json::from_str::<serde_json::Value>(&text).unwrap()
        });
        let _ = stop.send(true);
        rt.shutdown_background();
        drop((h, replica, primary, dirs));
        v
    })
}

/// REQ: DNS-906 (T40.5 AC4) - each node keeps its own trust anchors, and the API shows every
/// node's: this node's own entry and the primary's, each labelled with its node and its own
/// keys (one has a key in hold-down; the other's list is this node's, with no peer's keys mixed in).
#[test]
fn dns_906_the_api_shows_every_nodes_anchors() {
    let v = anchors_read(None);
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "this node and the primary: {v}");
    assert!(items.iter().all(|i| i["node"].is_string()), "{v}");
    let theirs = items
        .iter()
        .find(|i| i["keys"].as_array().is_some_and(|k| k.len() == 2))
        .unwrap_or_else(|| panic!("the primary's keys are listed: {v}"));
    assert_eq!(theirs["mode"], "following");
    assert!(
        theirs["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k["state"] == "add_pend" && k["keyTag"] == 11111),
        "{v}"
    );
    let mine = items.iter().find(|i| !std::ptr::eq(*i, theirs)).unwrap();
    assert_ne!(mine["node"], theirs["node"], "{v}");
    assert!(v.get("missingNodes").is_none(), "{v}");
}

/// REQ: DNS-906 (T40.5), DSC-908 (the gate) - a mixed cluster: a member whose build does not
/// announce the `rfc5011` feature is not asked (it would refuse the read), and is listed as
/// `unsupported` instead of failing the whole read or being counted as missing.
#[test]
fn dns_906_an_older_member_is_listed_as_not_supported() {
    let v = anchors_read(Some(Vec::new()));
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{v}");
    let old = items.iter().find(|i| i["mode"] == "unsupported").unwrap();
    assert_eq!(old["keys"].as_array().unwrap().len(), 0);
    assert!(old["node"].is_string());
    assert!(
        items.iter().any(|i| i["mode"] != "unsupported"),
        "this node still answers: {v}"
    );
    assert!(
        v.get("missingNodes").is_none(),
        "not missing, not failed: {v}"
    );
}

/// REQ: API-902 (T27.14g0, ADR-1113), CLU-010 - a member announces its API URL in its Hello, the
/// member list carries it, and a change of the address reaches the others in a heartbeat, without
/// a reconnect. A member announcing no URL is listed with none; the gate feature is announced.
#[test]
fn api_902_a_members_api_url_is_announced_in_the_hello_and_refreshed_in_heartbeats() {
    finish_within(|| {
        let rt = multi_thread_runtime(2);
        let (replica, primary, stop, dirs) = rt.block_on(replica_of_announcing_url(
            anchors_handler(),
            None,
            "https://192.0.2.10:8443",
        ));
        let theirs = |c: &Arc<Cluster>| {
            c.members()
                .into_iter()
                .find(|m| m.primary)
                .map(|m| (m.api_url, m.features))
        };
        // The Hello carried it, and the gate feature with it.
        let (url, features) = theirs(&replica).expect("the primary is a member");
        assert_eq!(url, "https://192.0.2.10:8443");
        assert!(wrendns_cluster::gate::knows(
            &features,
            wrendns_cluster::gate::Feature::MemberApiAddress
        ));
        // The cluster view lists it (this node's own, and the member's).
        let view = crate::cluster::view(&replica, &crate::host::HostMonitor::default());
        let primary_row = view.nodes.iter().find(|n| !n.this_node).unwrap();
        assert_eq!(
            primary_row.api_url.as_deref(),
            Some("https://192.0.2.10:8443")
        );
        // A moved address (a confirmed change) is announced by the next heartbeat.
        primary.set_api_url("https://192.0.2.10:9443");
        let mut seen = String::new();
        for _ in 0..400 {
            seen = theirs(&replica).map(|t| t.0).unwrap_or_default();
            if seen == "https://192.0.2.10:9443" {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(seen, "https://192.0.2.10:9443", "a heartbeat refreshes it");
        // No URL: announced as empty, listed as none.
        primary.set_api_url("");
        for _ in 0..400 {
            seen = theirs(&replica).map(|t| t.0).unwrap_or_default();
            if seen.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(seen.is_empty(), "an emptied URL is emptied: {seen}");
        let _ = stop.send(true);
        rt.shutdown_background();
        drop((replica, primary, dirs));
    });
}

/// REQ: API-902 (T27.14g0, AC 2), CLU-010 - a mixed cluster: a member whose feature list lacks
/// `member_api_address` (an older build) announces no URL even when one is set, is listed with
/// none, does not satisfy the gate, and so is not asked for its settings.
#[test]
fn api_902_a_member_without_the_feature_announces_no_url_and_is_not_asked() {
    finish_within(|| {
        let rt = multi_thread_runtime(2);
        let old: Vec<String> = wrendns_cluster::gate::own_features()
            .into_iter()
            .filter(|f| f != wrendns_cluster::gate::Feature::MemberApiAddress.name())
            .collect();
        let (replica, primary, stop, dirs) = rt.block_on(replica_of_announcing_url(
            anchors_handler(),
            Some(old),
            "https://192.0.2.10:8443",
        ));
        let (url, features) = replica
            .members()
            .into_iter()
            .find(|m| m.primary)
            .map(|m| (m.api_url, m.features))
            .expect("the primary is a member");
        assert_eq!(url, "", "an older build announces none");
        assert!(!wrendns_cluster::gate::knows(
            &features,
            wrendns_cluster::gate::Feature::MemberApiAddress
        ));
        let view = crate::cluster::view(&replica, &crate::host::HostMonitor::default());
        let row = view.nodes.iter().find(|n| !n.this_node).unwrap();
        assert_eq!(row.api_url, None, "listed with no address");
        let _ = stop.send(true);
        rt.shutdown_background();
        drop((replica, primary, dirs));
    });
}

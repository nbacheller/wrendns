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
    // Every read is accepted and never answered: the handler's future doesn't complete.
    primary.set_rpc_handler(Arc::new(move |_peer, _kind, _body| {
        Box::pin(std::future::pending::<Result<Vec<u8>, String>>())
    }));
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
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_millis(1500),
        "three direct federated reads took {elapsed:?}, not about one deadline: a worker was held, or a read panicked"
    );
}

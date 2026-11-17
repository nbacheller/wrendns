//! REQ: CLU-004, CLU-002, API-002 (upstream #7) — a federated read never stops a runtime
//! worker. A replica whose primary never answers serves concurrent requests on a two-worker
//! runtime; each one must finish within the bound instead of wedging the runtime.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use telltale_cluster::net::{Cluster, dial, join, serve};
use telltale_cluster::node::{Identity, JoinRequest, TokenGrants};
use tower::ServiceExt;

use crate::credential_tests::harness_in;

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

/// Concurrent requests in each test.
const REQUESTS: usize = 3;

/// `REQUESTS` concurrent `GET /api/v1/clients` on `rt`, against a replica of a silent primary,
/// all finishing within `BOUND`. The wait runs on a blocking thread, since a wedged runtime
/// can't fire its own timers. A request that doesn't finish leaks `rt` rather than dropping
/// it: dropping would wait for the stuck workers and hang the test run.
fn reads_finish_within_bound(rt: tokio::runtime::Runtime) {
    let (replica, primary, stop, dirs, h) = rt.block_on(async {
        let (replica, primary, stop, dirs) = replica_of_a_silent_primary().await;
        let h = harness_in("", Some(Arc::clone(&replica)));
        (replica, primary, stop, dirs, h)
    });
    let (tx, rx) = std::sync::mpsc::channel::<Option<StatusCode>>();
    let answers = rt.block_on(async move {
        for _ in 0..REQUESTS {
            let req = h.request("GET", "/api/v1/clients", None);
            let (app, tx) = (h.app.clone(), tx.clone());
            tokio::spawn(async move {
                let status = app.oneshot(req).await.map(|r| r.status()).ok();
                let _ = tx.send(status);
            });
        }
        drop(tx);
        let until = std::time::Instant::now() + BOUND;
        tokio::task::spawn_blocking(move || {
            (0..REQUESTS)
                .map(|_| {
                    rx.recv_timeout(until.saturating_duration_since(std::time::Instant::now()))
                        .ok()
                        .flatten()
                })
                .collect::<Vec<Option<StatusCode>>>()
        })
        .await
        .unwrap_or_default()
    });
    if answers.len() != REQUESTS || answers.iter().any(Option::is_none) {
        std::mem::forget((rt, replica, primary, stop, dirs));
        panic!("a request hung: a federated read blocked the runtime ({answers:?})");
    }
    for status in answers.into_iter().flatten() {
        assert_eq!(status, StatusCode::OK);
    }
    rt.block_on(async {
        let _ = stop.send(true);
    });
    drop((replica, primary, dirs));
    drop(rt);
}

/// REQ: CLU-004 (upstream #7) — `clients` and the `ETag` reads call the federated backend, which
/// waits on the cluster stream. Concurrent requests on two workers all finish within the bound:
/// none of them holds a runtime worker while it waits for the wedged peer.
#[test]
fn clu_004_concurrent_reads_on_a_wedged_peer_all_finish() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    reads_finish_within_bound(rt);
}

/// REQ: CLU-004 — a current-thread runtime (the tests' and `ctl`'s) still answers the same reads.
#[test]
fn clu_004_a_current_thread_runtime_still_answers() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    reads_finish_within_bound(rt);
}

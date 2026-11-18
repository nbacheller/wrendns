//! REQ: API-902, CLU-004 (T27.13; ADR-956) — the guarded engine's [`Host`] on a running node: the
//! node's configuration and reload, its `state.db`, its cluster channel, and the confirmation
//! window's proof listener.
//!
//! Two peer calls travel the cluster channel (the ADR-946 pattern, mTLS-authenticated peers):
//! [`KIND_FORWARD`], the primary's forwarded guarded request for another node, and
//! [`KIND_ENTRY`], a replica's write of its own guarded entry through the primary (the single
//! writer, ADR-005).

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use axum::Router as HttpRouter;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use telltale_api::BoxFuture;
use telltale_api::auth::{Actor, Auth};
use telltale_api::guarded::ArrivedOn;
use telltale_api::problem::{Code, Problem};
use telltale_cluster::net::Cluster;
use telltale_config::Config;
use telltale_store::state::{NewAudit, State};
use tokio::net::TcpListener;
use tracing::warn;

use super::assertion::{Forwarded, ForwardedAnswer};
use super::engine::Engine;
use super::host::{Host, Member, ProofSocket};
use super::store::{self, Stored};
use crate::http::Sources;

/// The primary forwards a guarded request for another node to that node.
pub(crate) const KIND_FORWARD: &str = "guarded.forward";
/// A replica writes (or removes) its own guarded entry through the primary.
pub(crate) const KIND_ENTRY: &str = "guarded.entry";
/// A forwarded request waits this long for the target (a window apply binds sockets).
const FORWARD_TIMEOUT: Duration = Duration::from_secs(20);

/// The node's side of the engine.
pub(crate) struct ProdHost {
    src: Arc<Sources>,
    /// The API's app (the router with its middleware), for the proof listener.
    app: HttpRouter,
    state: Arc<State>,
    /// The engine this host serves (set once, after both exist); only the end-to-end build's
    /// simulated restart reads it.
    #[cfg_attr(not(feature = "e2e"), allow(dead_code))]
    engine: OnceLock<Weak<Engine>>,
}

impl ProdHost {
    pub(crate) fn new(src: Arc<Sources>, app: HttpRouter, auth: &Arc<Auth>) -> Arc<Self> {
        Arc::new(Self {
            src,
            app,
            state: Arc::clone(auth.state()),
            engine: OnceLock::new(),
        })
    }

    pub(crate) fn set_engine(&self, e: &Arc<Engine>) {
        let _ = self.engine.set(Arc::downgrade(e));
    }

    fn cluster(&self) -> Option<&Arc<Cluster>> {
        self.src.cluster.as_ref()
    }
}

/// A listener that serves the API for the confirmation window, tagging every request with the
/// address it was reached on (a client can't set the tag).
struct ProofListener {
    addr: SocketAddr,
    stop: tokio::sync::watch::Sender<bool>,
}

impl ProofSocket for ProofListener {
    fn addr(&self) -> SocketAddr {
        self.addr
    }
    fn close(&self) {
        let _ = self.stop.send(true);
    }
}

impl Drop for ProofListener {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

async fn bind_proof(app: HttpRouter, addr: SocketAddr) -> Result<Arc<dyn ProofSocket>, String> {
    let listener = TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    let app = app.layer(axum::middleware::map_request(
        move |mut req: axum::extract::Request| async move {
            req.extensions_mut().insert(ArrivedOn(bound));
            req
        },
    ));
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = stopped.wait_for(|v| *v).await;
        })
        .await;
    });
    Ok(Arc::new(ProofListener { addr: bound, stop }))
}

fn wire_problem(p: &Problem) -> ForwardedAnswer {
    ForwardedAnswer::Refused {
        code: p.code,
        detail: p.detail.clone(),
        hint: p.hint.clone(),
        retry_after: p.retry_after,
    }
}

/// A replica's request to the primary: write or remove `entry`.
#[derive(Debug, Serialize, Deserialize)]
struct EntryWrite {
    node: String,
    id: String,
    entry: Option<Stored>,
    by: String,
}

impl Host for ProdHost {
    fn running_config(&self) -> Arc<Config> {
        self.src.config.load_full()
    }

    fn file_config(&self) -> Arc<Config> {
        self.src.file_config.load_full()
    }

    fn reload(&self) -> BoxFuture<bool> {
        let tx = self.src.reload.clone();
        Box::pin(async move {
            let (done, rx) = tokio::sync::oneshot::channel();
            tx.send(done).await.is_ok() && rx.await.unwrap_or(false)
        })
    }

    fn write_entry(
        &self,
        node: &str,
        id: &str,
        entry: Option<Stored>,
        by: &str,
    ) -> BoxFuture<Result<(), Problem>> {
        let (state, cluster) = (Arc::clone(&self.state), self.cluster().cloned());
        let (node, id, by) = (node.to_owned(), id.to_owned(), by.to_owned());
        Box::pin(async move {
            let local = |state: &State| -> Result<(), Problem> {
                let now = super::now_secs();
                match &entry {
                    Some(e) => store::put(state, e, now, &by),
                    None => store::delete(state, &node, &id),
                }
                .map_err(|e| Problem::internal(format!("the guarded entry can't be stored: {e}")))
            };
            // The data-dir pointer is local to the node and never replicated.
            if store::is_local(&id) {
                return local(&state);
            }
            match cluster {
                Some(c) if !c.is_primary() => {
                    // A node never runs a guarded value that no one will replicate: through the
                    // primary, or not at all.
                    let Some(primary) = c.reachable_primary() else {
                        return Err(Problem::new(
                            Code::PrimaryUnreachable,
                            "this node can't reach the primary to record the change",
                        ));
                    };
                    let body = serde_json::to_vec(&EntryWrite {
                        node: node.clone(),
                        id: id.clone(),
                        entry,
                        by: by.clone(),
                    })
                    .map_err(|e| Problem::internal(e.to_string()))?;
                    let answer = c
                        .call(&primary, KIND_ENTRY, body, Duration::from_secs(10))
                        .await
                        .map_err(|e| {
                            Problem::new(
                                Code::PrimaryUnreachable,
                                format!("the primary didn't take the entry: {e}"),
                            )
                        })?;
                    match serde_json::from_slice::<Option<String>>(&answer) {
                        Ok(None) => Ok(()),
                        Ok(Some(why)) => Err(Problem::new(Code::PrimaryUnreachable, why)),
                        Err(e) => Err(Problem::internal(format!("bad answer: {e}"))),
                    }
                }
                _ => local(&state),
            }
        })
    }

    fn is_primary(&self) -> bool {
        self.cluster().is_none_or(|c| c.is_primary())
    }

    fn clustered(&self) -> bool {
        self.cluster().is_some()
    }

    fn members(&self) -> Vec<Member> {
        let Some(c) = self.cluster() else {
            return Vec::new();
        };
        c.members()
            .into_iter()
            .map(|m| Member {
                name: if m.site.is_empty() {
                    m.node_id.clone()
                } else {
                    m.site.clone()
                },
                id: m.node_id,
                is_primary: m.primary,
                up: m.connected,
            })
            .collect()
    }

    fn primary_name(&self) -> Option<String> {
        let c = self.cluster()?;
        if c.is_primary() {
            let m = &c.identity.meta;
            return Some(if m.site.is_empty() {
                m.node_id.clone()
            } else {
                m.site.clone()
            });
        }
        let id = c.connected_primary().or_else(|| c.reachable_primary())?;
        c.members()
            .into_iter()
            .find(|m| m.node_id == id)
            .map(|m| if m.site.is_empty() { m.node_id } else { m.site })
    }

    fn primary_url(&self) -> Option<String> {
        let c = self.cluster()?;
        c.primary_urls().into_iter().next()
    }

    fn sign(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let c = self.cluster()?;
        if !c.is_primary() {
            return None;
        }
        let key = c.identity.ca_key_pem().ok()?;
        telltale_cluster::sync::sign_bytes(bytes, &key).ok()
    }

    fn verify(&self, _node: &str, bytes: &[u8], sig: &[u8]) -> bool {
        self.cluster()
            .is_some_and(|c| telltale_cluster::sync::verify_bytes(bytes, sig, &c.identity.ca_pem))
    }

    fn forward(&self, node: &str, req: Forwarded) -> BoxFuture<Result<ForwardedAnswer, Problem>> {
        let cluster = self.cluster().cloned();
        let id = self
            .members()
            .into_iter()
            .find(|m| m.name == node || m.id == node)
            .map(|m| m.id);
        Box::pin(async move {
            let (Some(c), Some(id)) = (cluster, id) else {
                return Err(Problem::new(Code::NodeUnknown, "no such cluster node"));
            };
            let body = serde_json::to_vec(&req).map_err(|e| Problem::internal(e.to_string()))?;
            let answer = c
                .call(&id, KIND_FORWARD, body, FORWARD_TIMEOUT)
                .await
                .map_err(|e| {
                    Problem::new(
                        Code::NodeUnreachable,
                        format!("the node didn't answer the guarded request: {e}"),
                    )
                })?;
            serde_json::from_slice(&answer)
                .map_err(|e| Problem::internal(format!("bad answer from the node: {e}")))
        })
    }

    fn audit(
        &self,
        actor: &Actor,
        action: &str,
        target: &str,
        detail: &Value,
    ) -> Result<(), String> {
        let d = detail.to_string();
        self.state
            .audit_append(&NewAudit {
                ts: super::now_secs(),
                actor: &actor.name,
                actor_kind: actor.kind,
                remote: actor.remote.as_deref(),
                action,
                target,
                detail: &d,
                reason: actor.reason.as_deref(),
            })
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn restart(&self) -> BoxFuture<()> {
        #[cfg(feature = "e2e")]
        if std::env::var_os(super::restart::E2E_HOOK_ENV).is_some() {
            let engine = self.engine.get().and_then(Weak::upgrade);
            return Box::pin(async move {
                if let Some(e) = engine {
                    super::e2e::simulate_restart(e);
                }
            });
        }
        Box::pin(async {
            super::restart::request_exit();
        })
    }

    fn proof_socket(&self, addr: SocketAddr) -> BoxFuture<Result<Arc<dyn ProofSocket>, String>> {
        let app = self.app.clone();
        Box::pin(bind_proof(app, addr))
    }
}

/// The primary's side of [`KIND_ENTRY`]: a replica writes its own entry through here.
pub(crate) fn handle_entry(
    src: &Sources,
    cluster: &Cluster,
    peer: &str,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let answer: Option<String> = entry_write(src, cluster, peer, body);
    serde_json::to_vec(&answer).map_err(|e| e.to_string())
}

fn entry_write(src: &Sources, cluster: &Cluster, peer: &str, body: &[u8]) -> Option<String> {
    if !cluster.is_primary() {
        return Some("this node isn't the primary any more".to_owned());
    }
    let w: EntryWrite = match serde_json::from_slice(body) {
        Ok(w) => w,
        Err(e) => return Some(format!("bad entry: {e}")),
    };
    // A node writes only its own entries: the peer is authenticated by its certificate.
    let member = cluster.members().into_iter().find(|m| m.node_id == peer);
    let named = member
        .as_ref()
        .is_some_and(|m| w.node == m.node_id || (!m.site.is_empty() && w.node == m.site));
    if !named
        || w.entry
            .as_ref()
            .is_some_and(|e| e.node != w.node || e.id != w.id)
    {
        return Some("a node can only write its own guarded entries".to_owned());
    }
    let Some(auth) = src.auth.get() else {
        return Some("the primary's state isn't open".to_owned());
    };
    let state = auth.state();
    let now = super::now_secs();
    let by = format!("{} via {}", w.by, w.node);
    let done = match &w.entry {
        Some(e) => store::put(state, e, now, &by),
        None => store::delete(state, &w.node, &w.id),
    };
    match done {
        Ok(()) => None,
        Err(e) => {
            warn!("a replica's guarded entry can't be stored: {e}");
            Some(e)
        }
    }
}

/// The target's side of [`KIND_FORWARD`].
pub(crate) async fn handle_forward(
    src: Arc<Sources>,
    cluster: Arc<Cluster>,
    peer: String,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let f: Forwarded = serde_json::from_slice(&body).map_err(|e| format!("bad request: {e}"))?;
    let sender = cluster
        .members()
        .into_iter()
        .find(|m| m.node_id == peer)
        .map_or_else(
            || peer.clone(),
            |m| if m.site.is_empty() { m.node_id } else { m.site },
        );
    let answer = match src.guarded.get() {
        Some(e) => e.handle_forwarded(&sender, f).await,
        None => wire_problem(&Problem::unavailable(
            "guarded settings aren't available on this node",
        )),
    };
    serde_json::to_vec(&answer).map_err(|e| e.to_string())
}

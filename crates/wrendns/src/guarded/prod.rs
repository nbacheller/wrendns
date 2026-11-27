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
use tokio::net::TcpListener;
use tracing::{info, warn};
use wrendns_api::BoxFuture;
use wrendns_api::auth::{Actor, Auth};
use wrendns_api::guarded::ArrivedOn;
use wrendns_api::problem::{Code, Problem};
use wrendns_cluster::net::Cluster;
use wrendns_config::Config;
use wrendns_store::state::{NewAudit, State};

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
/// A replica waits this long for the primary's new version (with its entry) to reach it.
const REPLICATION_WAIT: Duration = Duration::from_secs(20);

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
    /// The write of [`Host::write_entry`]; `check` makes the primary compare the time of the entry
    /// it holds with `expect_at`, the one the node saw (the dnstap row).
    fn write_entry_checked(
        &self,
        node: &str,
        id: &str,
        entry: Option<Stored>,
        by: &str,
        check: bool,
        expect_at: Option<u64>,
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
                        check,
                        expect_at,
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
                        Ok(Some(why)) if why == STALE => Err(Problem::new(
                            Code::PreviewStale,
                            "the node's dnstap settings changed since the preview",
                        )
                        .hint("Preview the change again.")),
                        Ok(Some(why)) => Err(Problem::new(Code::PrimaryUnreachable, why)),
                        Err(e) => Err(Problem::internal(format!("bad answer: {e}"))),
                    }
                }
                _ => {
                    // The primary or a standalone node holds the entry itself: the same comparison.
                    if check
                        && store::for_node(&state, &node)
                            .into_iter()
                            .find(|e| e.id == id)
                            .map(|e| e.at)
                            != expect_at
                    {
                        return Err(Problem::new(
                            Code::PreviewStale,
                            "the node's dnstap settings changed since the preview",
                        )
                        .hint("Preview the change again."));
                    }
                    local(&state)
                }
            }
        })
    }

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

/// REQ: API-902, API-003 (ADR-956 §3, ADR-149) — what the confirmation window's listener serves:
/// the confirm route, the web UI's own files (the page that sends the confirmation) and the read of
/// the sign-in status the page starts with, nothing else.
/// It is a second way into the node for a few minutes, so it carries no sign-in, session, token or
/// settings route, and never answers a request the main listener would refuse.
pub(crate) fn proof_allowed(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    if method == Method::POST {
        let mut seg = path.trim_end_matches('/').split('/');
        // /api/v1/guarded/pending/{id}/confirm
        return matches!(
            (seg.next(), seg.next(), seg.next(), seg.next(), seg.next(), seg.next(), seg.next()),
            (Some(""), Some("api"), Some("v1"), Some("guarded"), Some("pending"), Some(id), Some("confirm"))
                if !id.is_empty()
        ) && seg.next().is_none();
    }
    if method == Method::GET || method == Method::HEAD {
        // The page asks who is signed in before it draws (it sees nobody here, and says so): the
        // read of the sign-in status, which signs nothing in.
        if path == "/api/v1/auth/status" {
            return true;
        }
        let first = path.trim_start_matches('/').split('/').next().unwrap_or("");
        return !matches!(
            first,
            "api" | "mcp" | "metrics" | "admin" | "auth" | ".well-known"
        );
    }
    false
}

async fn restrict_proof(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    if proof_allowed(req.method(), req.uri().path()) {
        return next.run(req).await;
    }
    Problem::not_found("this temporary listener serves only the confirmation of a pending change")
        .into_response()
}

async fn bind_proof(
    app: HttpRouter,
    addr: SocketAddr,
    tls: Option<crate::api_tls::ApiTlsSetup>,
) -> Result<Arc<dyn ProofSocket>, String> {
    let app = app.layer(axum::middleware::from_fn(restrict_proof));
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    if let Some(tls) = tls {
        // The main listener's TLS (or the new certificate): a `new_cert` proof reads the marker the
        // TLS listener sets, and a HTTPS-only API never serves a page in the clear here either.
        let bound = if addr.port() == 0 {
            let probe = TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
            probe.local_addr().map_err(|e| e.to_string())?
        } else {
            addr
        };
        let app = app.layer(axum::middleware::map_request(
            move |mut req: axum::extract::Request| async move {
                req.extensions_mut().insert(ArrivedOn(bound));
                req
            },
        ));
        let rx = stop.subscribe();
        let bound = crate::api_tls::serve_with(
            bound,
            app,
            &tls,
            async move {
                let mut rx = rx;
                let _ = rx.wait_for(|v| *v).await;
            },
            false,
        )
        .await
        .map_err(|e| e.to_string())?;
        return Ok(Arc::new(ProofListener { addr: bound, stop }));
    }
    let listener = TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    let app = app.layer(axum::middleware::map_request(
        move |mut req: axum::extract::Request| async move {
            req.extensions_mut().insert(ArrivedOn(bound));
            req
        },
    ));
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
pub(crate) struct EntryWrite {
    pub(crate) node: String,
    pub(crate) id: String,
    pub(crate) entry: Option<Stored>,
    pub(crate) by: String,
    /// The time of the entry the replica saw when it wrote (`None`: none), checked for the dnstap
    /// row only. A sender that does not send it (`check` false) is not checked.
    #[serde(default)]
    pub(crate) check: bool,
    #[serde(default)]
    pub(crate) expect_at: Option<u64>,
}

/// REQ: OBS-007, API-905 (T40.13, review) - whether the entry the primary holds is not the one the
/// replica saw when it was asked for the phrase.
pub(crate) fn entry_stale(held: Option<&Stored>, w: &EntryWrite) -> bool {
    w.check && held.map(|e| e.at) != w.expect_at
}

/// What the primary answers a replica whose guarded write found the entry changed.
pub(crate) const STALE: &str = "preview_stale: the node's entry changed since the preview";

/// Whether the node `peer` (authenticated by its certificate: a node ID, never a site label) may
/// write `w`: only its own entries, under its own ID, and only the entry it names.
pub(crate) fn entry_allowed(peer: &str, w: &EntryWrite) -> bool {
    w.node == peer
        && w.entry
            .as_ref()
            .is_none_or(|e| e.node == w.node && e.id == w.id)
}

impl Host for ProdHost {
    fn running_config(&self) -> Arc<Config> {
        self.src.config.load_full()
    }

    fn file_config(&self) -> Arc<Config> {
        self.src.file_config.load_full()
    }

    fn pending_config(&self) -> Arc<Config> {
        match self.src.auth.get() {
            Some(a) => Arc::new(crate::dnstap_plan::pending_config(&self.src, a.state())),
            None => self.running_config(),
        }
    }

    fn reload(&self) -> BoxFuture<bool> {
        let tx = self.src.reload.clone();
        Box::pin(async move {
            let (done, rx) = tokio::sync::oneshot::channel();
            tx.send(done).await.is_ok() && rx.await.unwrap_or(false)
        })
    }

    fn listeners_not_applied(&self) -> Vec<String> {
        crate::gate_host::mismatched(&self.src.config.load().listen)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    fn write_entry(
        &self,
        node: &str,
        id: &str,
        entry: Option<Stored>,
        by: &str,
    ) -> BoxFuture<Result<(), Problem>> {
        self.write_entry_checked(node, id, entry, by, false, None)
    }

    fn write_entry_expecting(
        &self,
        node: &str,
        id: &str,
        entry: Option<Stored>,
        by: &str,
        expect_at: Option<u64>,
    ) -> BoxFuture<Result<(), Problem>> {
        self.write_entry_checked(node, id, entry, by, true, expect_at)
    }

    fn wait_applied(&self, node: &str, id: &str, digest: Option<String>) -> BoxFuture<bool> {
        if self.is_primary() || store::is_local(id) {
            return Box::pin(std::future::ready(true));
        }
        let (cfg, node, id) = (self.src.config.load_full(), node.to_owned(), id.to_owned());
        Box::pin(async move {
            let deadline = std::time::Instant::now() + REPLICATION_WAIT;
            loop {
                let have = crate::node_managed::applied_guarded(&cfg, &node)
                    .into_iter()
                    .find(|e| e.id == id)
                    .map(|e| e.digest());
                if have == digest {
                    return true;
                }
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
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
        // A witness only votes: the registry (set at join) knows which members are.
        let witnesses: std::collections::BTreeSet<String> = c
            .identity
            .registry()
            .into_iter()
            .filter(|n| n.witness)
            .map(|n| n.node_id)
            .collect();
        c.members()
            .into_iter()
            .map(|m| Member {
                name: m.node_id.clone(),
                site: m.site,
                witness: witnesses.contains(&m.node_id),
                id: m.node_id,
                is_primary: m.primary,
                up: m.connected,
            })
            .collect()
    }

    fn site(&self) -> String {
        self.cluster()
            .map(|c| c.identity.meta.site.clone())
            .unwrap_or_default()
    }

    fn primary_name(&self) -> Option<String> {
        let c = self.cluster()?;
        if c.is_primary() {
            return Some(c.identity.meta.node_id.clone());
        }
        let id = c.connected_primary().or_else(|| c.reachable_primary())?;
        c.members()
            .into_iter()
            .find(|m| m.node_id == id)
            .map(|m| m.node_id)
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
        wrendns_cluster::sync::sign_bytes(bytes, &key).ok()
    }

    fn verify(&self, _node: &str, bytes: &[u8], sig: &[u8]) -> bool {
        self.cluster()
            .is_some_and(|c| wrendns_cluster::sync::verify_bytes(bytes, sig, &c.identity.ca_pem))
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
        self.proof_socket_with(addr, None)
    }

    fn probe_dns(
        &self,
        probe: &super::dns_proof::DnsProbe,
    ) -> BoxFuture<Result<super::dns_proof::Kind, String>> {
        let (url, gated, ev) = (probe.url(), probe.gated, probe.evidence.clone());
        Box::pin(async move {
            crate::probes::ask_proof(&url, gated, ev.as_deref(), super::dns_proof::TIMEOUT).await
        })
    }

    fn stage_listeners(
        &self,
        list: Vec<wrendns_config::Listener>,
    ) -> BoxFuture<Result<Vec<crate::server::StagedListener>, crate::server::WindowError>> {
        let h = self.src.listeners.clone();
        Box::pin(async move { h.stage(list).await })
    }

    fn commit_listeners(&self) -> BoxFuture<Result<(), crate::server::WindowError>> {
        let h = self.src.listeners.clone();
        Box::pin(async move { h.commit().await })
    }

    fn abort_listeners(&self) -> BoxFuture<()> {
        let h = self.src.listeners.clone();
        Box::pin(async move { h.abort().await })
    }

    fn proof_socket_with(
        &self,
        addr: SocketAddr,
        tls: Option<&wrendns_config::ApiTls>,
    ) -> BoxFuture<Result<Arc<dyn ProofSocket>, String>> {
        let app = self.app.clone();
        // The new certificate for a `new_cert` row, else whatever the main API listener serves.
        let cfg = self.src.config.load_full();
        let wanted = tls.cloned().or_else(|| cfg.api.tls.clone());
        Box::pin(async move {
            let setup = match wanted {
                None => None,
                Some(t) => Some(crate::api_tls::setup(&cfg, &t).map_err(|e| e.to_string())?),
            };
            bind_proof(app, addr, setup).await
        })
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
    let member = cluster.members().into_iter().any(|m| m.node_id == peer);
    // The node's ID, never its site label (shared by every node of a site).
    if !member || !entry_allowed(peer, &w) {
        return Some("a node can only write its own guarded entries".to_owned());
    }
    let Some(auth) = src.auth.get() else {
        return Some("the primary's state isn't open".to_owned());
    };
    let state = auth.state();
    let now = super::now_secs();
    let by = format!("{} via {}", w.by, w.node);
    let held = store::for_node(state, &w.node)
        .into_iter()
        .find(|e| e.id == w.id);
    if entry_stale(held.as_ref(), &w) {
        return Some(STALE.to_owned());
    }
    let done = match &w.entry {
        Some(e) => store::put(state, e, now, &by),
        None => store::delete(state, &w.node, &w.id),
    };
    match done {
        Ok(()) => {
            // A removal the replica asked for (an offline clear there) is on the primary's log too.
            if w.entry.is_none() {
                let detail = serde_json::json!({"setting": w.id, "node": w.node, "via": "replica"})
                    .to_string();
                let _ = state.audit_append(&NewAudit {
                    ts: now,
                    actor: &w.by,
                    actor_kind: "system",
                    remote: None,
                    action: "settings.guarded_cleared",
                    target: &super::entry_name(&w.node, &w.id),
                    detail: &detail,
                    reason: None,
                });
            }
            None
        }
        Err(e) => {
            warn!("a replica's guarded entry can't be stored: {e}");
            Some(e)
        }
    }
}

/// REQ: API-902 (ADR-957 step 10) — sends the removals an offline `wrendns guarded clear` queued
/// on this node (a replica) to the primary, as soon as it can be reached; each one is dropped from
/// the queue when the primary has taken it. DNS never waits for it (CLU-004).
pub(crate) fn spawn_removals(
    host: Arc<ProdHost>,
    state: Arc<State>,
    node: String,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    if store::removals(&state).is_empty() {
        return;
    }
    tokio::spawn(async move {
        loop {
            for r in store::removals(&state) {
                let sent = host.write_entry(&node, &r.id, None, &r.by).await;
                if sent.is_ok() {
                    if let Err(e) = store::removal_done(&state, &r.id) {
                        warn!("a sent guarded removal can't be dequeued: {e}");
                    }
                    info!(setting = %r.id, "the primary removed the guarded entry cleared offline on this node");
                }
            }
            if store::removals(&state).is_empty() {
                return;
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(5)) => {}
                _ = stop.changed() => return,
            }
        }
    });
}

/// The target's side of [`KIND_FORWARD`].
pub(crate) async fn handle_forward(
    src: Arc<Sources>,
    _cluster: Arc<Cluster>,
    peer: String,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let f: Forwarded = serde_json::from_slice(&body).map_err(|e| format!("bad request: {e}"))?;
    // The mTLS-authenticated peer's node ID (never its shared site label).
    let sender = peer.clone();
    let answer = match src.guarded.get() {
        Some(e) => e.handle_forwarded(&sender, f).await,
        None => wire_problem(&Problem::unavailable(
            "guarded settings aren't available on this node",
        )),
    };
    serde_json::to_vec(&answer).map_err(|e| e.to_string())
}

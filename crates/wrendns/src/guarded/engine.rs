//! REQ: API-902, API-006, AGT-009, CLU-004 (T27.13; ADR-914, ADR-956) — the guarded engine.
//!
//! One engine per node. It owns the two-request flow (preview, then apply with the phrase), the
//! confirmation window's state machine, the per-node operation lock, the failure counter and the
//! audit. It knows nothing about any one setting: a registry row (`wrendns_config::guarded`) says
//! what the setting is and an [`Applier`] says what it does to this node, so T27.14 to T27.17 add
//! a row, a dry-run check and an apply step each and nothing here.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::time::Instant;
use tracing::{info, warn};
use wrendns_api::BoxFuture;
use wrendns_api::auth::Actor;
use wrendns_api::guarded::{
    GuardedApplied, GuardedApplyRequest, GuardedCaller, GuardedCheck, GuardedListenerLine,
    GuardedNodeStatus, GuardedOutcome, GuardedPending, GuardedPendingView, GuardedPreview,
    GuardedPreviewRequest, GuardedProbeLine, GuardedResult, GuardedSetting, GuardedStatus,
    Supervisor,
};
use wrendns_api::problem::{Code, Problem};
use wrendns_config::Config;
use wrendns_config::guarded::{Mode, Proof, RESTART_NOW, Row};
use wrendns_store::state::State;

use super::assertion::{
    ASSERTION_SECS, Assertion, Expect, Forwarded, ForwardedAnswer, ForwardedOp, Refusal, Signed,
};
use super::dns_proof::{self, DnsProbe, ProbeLoop, ProbeSet};
use super::host::{Host, Member, ProofSocket};
use super::store::{self, EntryState, Stored};
use super::{PREVIEW_SECS, ct_eq, hex, random_id};

/// Requests (previews, applies, confirmations) one admin may make per minute: previews are
/// rate-limited with the same limiter as writes (ADR-956 §6).
pub(crate) const RATE_PER_MIN: usize = 30;
/// Failed confirmations (wrong phrase, wrong token) before a session is blocked, in the window.
pub(crate) const FAILURES_ALLOWED: usize = 5;
/// The window the failures are counted in, in seconds.
pub(crate) const FAILURE_WINDOW_SECS: u64 = 600;

/// What a dry run found.
#[derive(Debug, Clone, Default)]
pub(crate) struct Checked {
    /// What the change does, in words.
    pub(crate) effect: String,
    pub(crate) restart_required: bool,
    /// Refused as `would_disconnect_you` when it is true (ADR-956 §3).
    pub(crate) would_disconnect: bool,
    pub(crate) warnings: Vec<String>,
    pub(crate) checks: Vec<GuardedCheck>,
    /// A temporary parallel listener's port, when the change needs one (a TLS-only change).
    pub(crate) proof_port: Option<u16>,
    /// Extra acknowledgements the change needs before it is accepted.
    pub(crate) acknowledgements: Vec<String>,
    /// The change is weaker than the current value for a reason `weakens` can't see (for example
    /// no admin accounts afterwards); it adds to the row's own rule.
    pub(crate) weakening: bool,
    /// What `would_disconnect` says it is (the generic sentence when `None`).
    pub(crate) disconnect_detail: Option<String>,
    /// REQ: API-902 (T27.14c) — a listener change's line-by-line diff, for the review step.
    pub(crate) listeners: Vec<GuardedListenerLine>,
    /// REQ: API-902 (T27.14c) — the host facts the verdict was judged with; an apply whose check
    /// reads other facts is `preview_stale`.
    pub(crate) host_facts: Option<wrendns_config::HostFacts>,
}

/// What an [`Applier`] is given to check a value.
pub(crate) struct CheckCx<'a> {
    /// The configuration the node runs.
    pub(crate) cfg: &'a Config,
    pub(crate) node: &'a str,
    pub(crate) value: &'a Value,
    pub(crate) options: &'a Value,
    pub(crate) caller: &'a GuardedCaller,
    /// The node around the engine (the cluster's members, for the checks that name them).
    pub(crate) host: &'a dyn Host,
    /// REQ: API-902 (T27.14c) — this node's stored `listen-access` value that is in force, for a
    /// listener change to judge an address the node once gated (its lines outlive the listener).
    pub(crate) access: Option<&'a Value>,
}

/// What staging a window change bound.
pub(crate) struct Staged {
    pub(crate) guard: Arc<dyn WindowGuard>,
    /// The socket the confirming request must arrive on, for a `new_socket` or `new_cert` proof.
    pub(crate) proof_addr: Option<SocketAddr>,
    /// Where to confirm, in words (the new address).
    pub(crate) new_address: Option<String>,
    /// For a `proxy_list` proof: the list that applies only to the confirm route until confirmed.
    pub(crate) pending_proxies: Option<Vec<(std::net::IpAddr, u8)>>,
    /// REQ: API-902, OBS-020 (T27.14b) — the DNS sockets the node asks itself while the window is
    /// open. With probes and no `proof_addr`, "every probe answers" is the proof (no request has to
    /// arrive on a socket); with both, both are needed.
    pub(crate) dns_probes: Vec<DnsProbe>,
}

/// What stays open while a window change waits: it commits (closes the old sockets, keeps the new)
/// or aborts (closes the new, keeps the old).
pub(crate) trait WindowGuard: Send + Sync {
    fn commit(&self) -> BoxFuture<Result<(), Problem>>;
    fn abort(&self) -> BoxFuture<()>;
    /// REQ: API-902 (T27.14c) — why what the preview promised no longer holds (the host's addresses
    /// changed since the stage), checked at confirm before anything is written. `None`: still holds.
    fn stale(&self) -> Option<String> {
        None
    }
    /// The rollback reason of a failed [`commit`](Self::commit) (`commit_failed`, or `cancelled` when
    /// the file took the listeners over).
    fn failure_reason(&self) -> &'static str {
        "commit_failed"
    }
}

/// What one setting does to a node. T27.14 to T27.17 implement it for their rows.
pub(crate) trait Applier: Send + Sync {
    /// The value now in force, as JSON in the shape `Row::weakens` compares.
    fn current(&self, cfg: &Config) -> Value;
    /// The dry run: refuses a value that is invalid or forbidden, and says what it would do.
    fn check(&self, cx: &CheckCx<'_>) -> Result<Checked, Problem>;
    /// Puts a stored value into a merged configuration (immediate and confirmed entries, and the
    /// ones on probation). The file's fields win: the engine doesn't call it for those.
    fn overlay(&self, cfg: &mut Config, value: &Value) {
        let _ = (cfg, value);
    }
    /// A `window` row: binds what the change needs next to the old sockets. A failed bind changes
    /// nothing and says why.
    fn stage(
        &self,
        _host: Arc<dyn Host>,
        _node: String,
        _value: Value,
        _access: Option<Value>,
        _facts: Option<wrendns_config::HostFacts>,
    ) -> BoxFuture<Result<Staged, Problem>> {
        Box::pin(std::future::ready(Err(Problem::unavailable(
            "this setting has no confirmation window",
        ))))
    }
    /// A dropped entry's replacement, after two failed starts (ADR-956 §4): `secrets-key` returns
    /// the new key as the previous key once any row was re-encrypted, so every row still opens.
    /// `None` (the default) just drops the entry.
    fn failed_start(&self, _dropped: &Stored, _state: &State) -> Option<Stored> {
        None
    }
    /// An `action` row other than `restart-now` (T27.16).
    fn act(
        &self,
        _host: Arc<dyn Host>,
        _node: String,
        _value: Value,
        _options: Value,
    ) -> BoxFuture<Result<String, Problem>> {
        Box::pin(std::future::ready(Err(Problem::unavailable(
            "this action isn't available",
        ))))
    }
}

/// A registry row and what it does here.
#[derive(Clone)]
pub(crate) struct RowDef {
    pub(crate) row: Row,
    pub(crate) applier: Arc<dyn Applier>,
}

/// An applier for a row that has nothing to do beyond being stored (the framework's own
/// `restart-now`, which the engine handles itself).
pub(crate) struct NoOp;

impl Applier for NoOp {
    fn current(&self, _cfg: &Config) -> Value {
        Value::Null
    }
    fn check(&self, _cx: &CheckCx<'_>) -> Result<Checked, Problem> {
        Ok(Checked::default())
    }
}

/// A preview the node has handed out.
pub(crate) struct Preview {
    admin: String,
    node: String,
    setting: String,
    binding: [u8; 32],
    version: u64,
    expires: Instant,
    phrase: String,
    weakening: bool,
    /// The host facts the preview was judged with (`None` for a row that does not read them).
    host_facts: Option<wrendns_config::HostFacts>,
    needs_recent: bool,
    acknowledgements: Vec<String>,
    /// For `restart-now`: the staged entries it listed.
    staged_listed: Vec<String>,
}

/// What a confirm reads from the pending change before it takes the operation lock: the setting, its
/// proof, the admin, the token's hash, the proof socket and the DNS probes.
type ConfirmSnapshot = (
    String,
    Option<Proof>,
    String,
    [u8; 32],
    Option<SocketAddr>,
    Option<Arc<ProbeSet>>,
);

/// A window change waiting to be confirmed (held in memory only, on the target node).
struct Pending {
    id: String,
    setting: String,
    mode: Mode,
    proof: Option<Proof>,
    admin: String,
    actor: Actor,
    reason: Option<String>,
    token_hash: [u8; 32],
    deadline: Instant,
    window_secs: u64,
    value: Value,
    before: Value,
    weakening: bool,
    guard: Arc<dyn WindowGuard>,
    proof_addr: Option<SocketAddr>,
    proxies: Option<Vec<(std::net::IpAddr, u8)>>,
    /// The node's own probes of the staged DNS sockets (T27.14b), when the change has any.
    probes: Option<Arc<ProbeSet>>,
    /// The task that runs them every few seconds; dropping it stops it.
    probe_loop: Option<ProbeLoop>,
    /// The expiry task; dropped (aborted) when the change ends.
    expiry: Option<tokio::task::JoinHandle<()>>,
}

impl Pending {
    /// The window ended: the probes stop and the evidence counters are dropped.
    fn end_probes(&mut self) {
        self.probe_loop = None;
        if let Some(p) = &self.probes {
            p.stop_evidence();
        }
    }
}

#[derive(Default)]
struct Inner {
    previews: HashMap<String, Preview>,
    pending: Option<Pending>,
    /// A guarded operation holds the node's lock (applying, committing, restarting).
    busy: bool,
    restarting: bool,
    limiter: HashMap<String, VecDeque<Instant>>,
    failures: HashMap<String, VecDeque<Instant>>,
    /// Forwarded assertions already used: nonce to the time they stop mattering.
    nonces: HashMap<String, u64>,
}

/// The guarded engine of one node.
pub(crate) struct Engine {
    pub(crate) node: String,
    pub(crate) state: Arc<State>,
    pub(crate) host: Arc<dyn Host>,
    pub(crate) rows: Vec<RowDef>,
    pub(crate) supervisor: Supervisor,
    inner: Mutex<Inner>,
    /// Tests and the end-to-end build set the window; production reads `[api] confirm_window_secs`.
    window_override: Mutex<Option<u64>>,
    /// Milliseconds between the probes of a pending change (design 2.2: 5 seconds); tests shorten it.
    probe_every_ms: std::sync::atomic::AtomicU64,
    /// The end-to-end build's simulated restart outcome (see `restart.rs`).
    pub(crate) now: fn() -> u64,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

/// REQ: API-902 — the end-to-end build's window, from `TT_E2E_CONFIRM_WINDOW_SECS` (compiled only
/// under the cargo feature `e2e`).
#[cfg(feature = "e2e")]
fn e2e_window() -> Option<u64> {
    std::env::var("TT_E2E_CONFIRM_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
}

#[cfg(not(feature = "e2e"))]
const fn e2e_window() -> Option<u64> {
    None
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A secret-looking key's value is never kept in an audit record or a log (ADR-914).
pub(crate) fn redact(v: &Value) -> Value {
    const MARK: &str = "<redacted>";
    fn secretish(k: &str) -> bool {
        let k = k.to_ascii_lowercase();
        ["secret", "password", "passphrase", "token", "psk"]
            .iter()
            .any(|w| k.contains(w))
            && !k.ends_with("_file")
            && !k.ends_with("_ref")
            && !k.ends_with("_path")
    }
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| {
                    if secretish(k) && !x.is_null() {
                        (k.clone(), Value::String(MARK.to_owned()))
                    } else {
                        (k.clone(), redact(x))
                    }
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(redact).collect()),
        other => other.clone(),
    }
}

fn binding(admin: &str, node: &str, setting: &str, value: &Value, options: &Value) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for part in [admin, node, setting] {
        h.update(part.as_bytes());
        h.update(&[0]);
    }
    h.update(&serde_json::to_vec(value).unwrap_or_default());
    h.update(&[0]);
    h.update(&serde_json::to_vec(options).unwrap_or_default());
    *h.finalize().as_bytes()
}

fn problem_of(code: Code, detail: String, hint: Option<String>, retry: Option<u64>) -> Problem {
    let mut p = Problem::new(code, detail);
    if let Some(h) = hint {
        p = p.hint(h);
    }
    if let Some(r) = retry {
        p = p.retry_after(r);
    }
    p
}

/// Where a request is for.
enum Target {
    Local,
    Remote(Member),
}

impl Engine {
    /// Builds the engine of the node named `node`.
    pub(crate) fn new(
        node: String,
        state: Arc<State>,
        host: Arc<dyn Host>,
        rows: Vec<RowDef>,
        supervisor: Supervisor,
    ) -> Arc<Self> {
        Arc::new(Self {
            node,
            state,
            host,
            rows,
            supervisor,
            inner: Mutex::new(Inner::default()),
            // The end-to-end build shortens the window so a test can watch a rollback (a release
            // build has no such code: `[api] confirm_window_secs` is the only source).
            window_override: Mutex::new(e2e_window()),
            probe_every_ms: std::sync::atomic::AtomicU64::new(
                u64::try_from(dns_proof::EVERY.as_millis()).unwrap_or(5_000),
            ),
            now: super::now_secs,
        })
    }

    /// Tests shorten the time between probes.
    #[cfg(test)]
    pub(crate) fn set_probe_every(&self, every: Duration) {
        self.probe_every_ms.store(
            u64::try_from(every.as_millis()).unwrap_or(5_000),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// The rows of this build (the registry's), each with the applier that does it here.
    pub(crate) fn defs(&self) -> &[RowDef] {
        &self.rows
    }

    pub(crate) fn row(&self, id: &str) -> Option<&RowDef> {
        self.rows.iter().find(|r| r.row.id == id)
    }

    fn window_secs(&self) -> u64 {
        if let Some(w) = *lock(&self.window_override) {
            return w;
        }
        u64::from(self.host.running_config().api.confirm_window_secs).clamp(30, 600)
    }

    /// Tests and the end-to-end build shorten (or fix) the window.
    #[cfg(any(test, feature = "e2e"))]
    pub(crate) fn set_window_secs(&self, secs: u64) {
        *lock(&self.window_override) = Some(secs);
    }

    // ---- small helpers -------------------------------------------------------------------

    fn audit(
        &self,
        actor: &Actor,
        action: &str,
        target: &str,
        detail: &Value,
    ) -> Result<(), String> {
        self.host.audit(actor, action, target, detail)
    }

    fn audit_best_effort(&self, actor: &Actor, action: &str, target: &str, detail: &Value) {
        if let Err(e) = self.audit(actor, action, target, detail) {
            warn!(action, target, "audit log write failed: {e}");
        }
    }

    pub(crate) fn target_name(&self, id: &str) -> String {
        super::entry_name(&self.node, id)
    }

    /// Audits a refusal (past the role check; no value in it) and hands the problem back.
    fn refuse(&self, c: &GuardedCaller, id: &str, p: Problem) -> Problem {
        let actor = Self::actor_of(c);
        self.audit_best_effort(
            &actor,
            "settings.guarded_refused",
            &self.target_name(id),
            &json!({"setting": id, "node": self.node, "code": p.code}),
        );
        p
    }

    /// The audit actor for a caller; a token-only confirmation takes the pending change's actor.
    fn actor_of(c: &GuardedCaller) -> Actor {
        c.actor.clone()
    }

    fn row_def(&self, id: &str) -> Result<&RowDef, Problem> {
        self.row(id).ok_or_else(|| {
            Problem::not_found(format!("no guarded setting named `{id}`"))
                .hint("GET /api/v1/guarded lists the guarded settings this node has.")
        })
    }

    /// Whether a file sets any path of the row (and so wins).
    pub(crate) fn set_by_file(&self, row: &Row) -> bool {
        let file = self.host.file_config();
        row.paths.iter().any(|p| {
            file.file_set
                .iter()
                .any(|k| k == p || k.strip_prefix(p).is_some_and(|r| r.starts_with('.')))
        })
    }

    fn resolve(&self, node: Option<&str>) -> Result<Target, Problem> {
        let Some(n) = node.map(str::trim).filter(|n| !n.is_empty()) else {
            return Ok(Target::Local);
        };
        if n == self.node {
            return Ok(Target::Local);
        }
        match self
            .host
            .members()
            .into_iter()
            .find(|m| m.id == n || m.name == n)
        {
            Some(m) if m.name == self.node || m.id == self.node => Ok(Target::Local),
            Some(m) => Ok(Target::Remote(m)),
            None => Err(Problem::new(
                Code::NodeUnknown,
                format!("no cluster node `{n}`"),
            )),
        }
    }

    /// Only the primary forwards a request for another node: a replica says who to ask (421).
    fn must_forward(&self) -> Result<(), Problem> {
        if self.host.is_primary() {
            return Ok(());
        }
        let who = self
            .host
            .primary_url()
            .or_else(|| self.host.primary_name())
            .unwrap_or_else(|| "the primary".to_owned());
        Err(Problem::new(
            Code::NotPrimary,
            format!("only the primary forwards a guarded change for another node; ask {who}"),
        )
        .hint("Open the UI on the primary node, choose the node there, and make the change."))
    }

    fn rate_limit(&self, c: &GuardedCaller) -> Result<(), Problem> {
        let now = Instant::now();
        let key = if c.username.is_empty() {
            format!("remote:{:?}", c.remote)
        } else {
            c.username.clone()
        };
        let mut g = lock(&self.inner);
        let q = g.limiter.entry(key).or_default();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            q.pop_front();
        }
        if q.len() >= RATE_PER_MIN {
            let wait = q.front().map_or(1, |t| {
                60u64
                    .saturating_sub(now.duration_since(*t).as_secs())
                    .max(1)
            });
            return Err(Problem::new(
                Code::RateLimited,
                "too many guarded requests; wait a moment",
            )
            .retry_after(wait));
        }
        q.push_back(now);
        Ok(())
    }

    fn failure_key(c: &GuardedCaller, fallback: &str) -> String {
        c.session
            .clone()
            .map_or_else(|| format!("pending:{fallback}"), |s| format!("session:{s}"))
    }

    fn blocked(&self, key: &str) -> Result<(), Problem> {
        let now = Instant::now();
        let mut g = lock(&self.inner);
        let Some(q) = g.failures.get_mut(key) else {
            return Ok(());
        };
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(FAILURE_WINDOW_SECS))
        {
            q.pop_front();
        }
        if q.len() >= FAILURES_ALLOWED {
            let wait = q.front().map_or(60, |t| {
                FAILURE_WINDOW_SECS
                    .saturating_sub(now.duration_since(*t).as_secs())
                    .max(1)
            });
            return Err(Problem::new(
                Code::RateLimited,
                "too many failed confirmations from this session; try again later",
            )
            .retry_after(wait));
        }
        Ok(())
    }

    fn failed(&self, key: &str) {
        let mut g = lock(&self.inner);
        g.failures
            .entry(key.to_owned())
            .or_default()
            .push_back(Instant::now());
    }

    // ---- status --------------------------------------------------------------------------

    /// This node's guarded settings and what is pending. No value, preview ID or token.
    pub(crate) fn status_local(&self) -> GuardedNodeStatus {
        let entries = self.effective_entries();
        let suppressed = store::suppressed(&self.state);
        let g = lock(&self.inner);
        let settings = self
            .rows
            .iter()
            .map(|d| {
                let e = entries.iter().find(|e| e.id == d.row.id);
                GuardedSetting {
                    id: d.row.id.to_owned(),
                    label: d.row.label.to_owned(),
                    mode: d.row.mode.as_str().to_owned(),
                    proof: d.row.proof.map(|p| p.as_str().to_owned()),
                    paths: d.row.paths.iter().map(|p| (*p).to_owned()).collect(),
                    set_by_file: self.set_by_file(&d.row),
                    has_entry: e.is_some(),
                    pending_restart: e.is_some_and(|e| e.state == EntryState::Staged),
                    on_probation: e.is_some_and(|e| e.state == EntryState::Probation),
                    suppressed: suppressed.contains_key(d.row.id),
                }
            })
            .collect();
        let pending = g.pending.as_ref().map(|p| GuardedPending {
            id: p.id.clone(),
            setting: p.setting.clone(),
            node: self.node.clone(),
            deadline_secs: remaining(p.deadline),
            by: p.admin.clone(),
        });
        GuardedNodeStatus {
            node: self.node.clone(),
            supervisor: self.supervisor.clone(),
            settings,
            pending,
            pending_restart: entries
                .iter()
                .filter(|e| e.state == EntryState::Staged)
                .map(|e| e.id.clone())
                .collect(),
            outcomes: store::outcomes(&self.state),
            restarting: g.restarting,
            ignored: super::ignored(),
            confirm_window_secs: u32::try_from(self.window_secs()).unwrap_or(120),
        }
    }

    /// `GET /api/v1/guarded`: this node, then the members the primary can see.
    pub(crate) async fn status(self: &Arc<Self>) -> GuardedStatus {
        let mut nodes = vec![self.status_local()];
        // In a cluster each member says its own (its supervisor, what is pending on it): a read with
        // no value in it, so no assertion is needed. A member that doesn't answer is left out (an
        // older one doesn't know the read: it isn't listed either).
        for m in self.host.members().into_iter().filter(|m| m.up) {
            let ask = Forwarded {
                op: ForwardedOp::Status,
                assertion: None,
            };
            if let Ok(ForwardedAnswer::Status(s)) = self.host.forward(&m.name, ask).await {
                nodes.push(s);
            }
        }
        GuardedStatus { nodes }
    }

    /// The pending `trusted-proxies` list, for the confirm route's own address evaluation.
    pub(crate) fn pending_proxies(&self) -> Option<Vec<(std::net::IpAddr, u8)>> {
        lock(&self.inner)
            .pending
            .as_ref()
            .and_then(|p| p.proxies.clone())
    }

    // ---- preview -------------------------------------------------------------------------

    /// The dry run (ADR-956 §3): checks and a phrase, and changes nothing.
    pub(crate) async fn preview(
        self: &Arc<Self>,
        c: &GuardedCaller,
        id: &str,
        req: GuardedPreviewRequest,
    ) -> Result<GuardedPreview, Problem> {
        match self.resolve(req.node.as_deref()) {
            Err(e) => Err(e),
            Ok(Target::Remote(m)) => {
                self.must_forward().map_err(|e| self.refuse(c, id, e))?;
                self.forward_preview(c, &m, id, req).await
            }
            Ok(Target::Local) => self.preview_local(c, id, &req),
        }
    }

    fn preview_local(
        &self,
        c: &GuardedCaller,
        id: &str,
        req: &GuardedPreviewRequest,
    ) -> Result<GuardedPreview, Problem> {
        let def = self.row_def(id)?;
        self.rate_limit(c)?;
        self.not_restarting()?;
        let r = self
            .preview_checked(c, def, req)
            .map_err(|e| self.refuse(c, id, e))?;
        Ok(r)
    }

    /// The node is on its way down: every guarded route answers 409 `restarting` from now on.
    pub(crate) fn set_restarting(&self) {
        lock(&self.inner).restarting = true;
    }

    /// The end-to-end build's simulated restart finished: the routes answer again.
    #[cfg(feature = "e2e")]
    pub(crate) fn clear_restarting(&self) {
        lock(&self.inner).restarting = false;
    }

    fn not_restarting(&self) -> Result<(), Problem> {
        if lock(&self.inner).restarting {
            return Err(Problem::new(
                Code::Restarting,
                "the node is restarting: guarded requests wait until it is back",
            ));
        }
        Ok(())
    }

    fn preview_checked(
        &self,
        c: &GuardedCaller,
        def: &RowDef,
        req: &GuardedPreviewRequest,
    ) -> Result<GuardedPreview, Problem> {
        let row = &def.row;
        if self.set_by_file(row) {
            return Err(Problem::new(
                Code::SetByFile,
                format!(
                    "a configuration file sets `{}` and wins; change it in the file",
                    row.id
                ),
            )
            .hint("Remove it from the file (and restart) to change it here."));
        }
        let cfg = self.host.running_config();
        let access = self.stored_access();
        let (checked, before) = if row.id == RESTART_NOW {
            (self.restart_checked()?, Value::Null)
        } else {
            let cx = CheckCx {
                cfg: &cfg,
                node: &self.node,
                value: &req.value,
                options: &req.options,
                caller: c,
                host: self.host.as_ref(),
                access: access.as_ref(),
            };
            (def.applier.check(&cx)?, def.applier.current(&cfg))
        };
        if checked.would_disconnect {
            return Err(Problem::new(
                Code::WouldDisconnectYou,
                checked.disconnect_detail.clone().unwrap_or_else(|| "the change would leave this node without an API or DNS listener, or remove the listener this request came in on".to_owned()),
            )
            .hint("Add the new listener first, then remove the old one in a second change."));
        }
        self.pending_conflict(row.mode, row.id)?;
        let weakening = (row.weakens)(&before, &req.value) || checked.weakening;
        let needs_recent = weakening || row.id == RESTART_NOW;
        let version = self.state.config_version().unwrap_or(0);
        let phrase = wrendns_config::guarded::phrase(&self.node, row.id);
        let preview_id = random_id(16);
        let window_secs = self.window_secs();
        {
            let mut g = lock(&self.inner);
            let now = Instant::now();
            g.previews.retain(|_, p| p.expires > now);
            g.previews.insert(
                preview_id.clone(),
                Preview {
                    admin: c.username.clone(),
                    node: self.node.clone(),
                    setting: row.id.to_owned(),
                    binding: binding(&c.username, &self.node, row.id, &req.value, &req.options),
                    version,
                    expires: now + Duration::from_secs(PREVIEW_SECS),
                    phrase: phrase.clone(),
                    weakening,
                    host_facts: checked.host_facts,
                    needs_recent,
                    acknowledgements: checked.acknowledgements.clone(),
                    staged_listed: if row.id == RESTART_NOW {
                        self.staged_ids()
                    } else {
                        Vec::new()
                    },
                },
            );
        }
        Ok(GuardedPreview {
            preview_id,
            phrase,
            setting: row.id.to_owned(),
            node: self.node.clone(),
            mode: row.mode.as_str().to_owned(),
            effect: checked.effect,
            nodes: vec![self.node.clone()],
            weakening,
            restart_required: checked.restart_required || row.mode == Mode::Staged,
            would_disconnect: false,
            listeners: checked.listeners,
            warnings: checked.warnings,
            checks: checked.checks,
            proof_port: checked.proof_port,
            acknowledgements: checked.acknowledgements,
            window_secs: u32::try_from(window_secs).unwrap_or(120),
            needs_recent_sign_in: needs_recent,
            set_by_file: false,
        })
    }

    /// One pending change per node: a window or staged change is refused while another waits
    /// (ADR-956 §3, §4), and nothing starts while an operation holds the lock.
    fn pending_conflict(&self, mode: Mode, id: &str) -> Result<(), Problem> {
        let g = lock(&self.inner);
        if g.restarting {
            return Err(Problem::new(
                Code::Restarting,
                "the node is restarting: guarded requests wait until it is back",
            ));
        }
        let busy = || {
            Problem::new(
                Code::GuardedChangePending,
                "this node already has a guarded change in progress",
            )
            .hint("Confirm or cancel the pending change (or wait for its window to end) first.")
        };
        if g.busy || (g.pending.is_some() && id != RESTART_NOW && mode != Mode::Immediate) {
            return Err(busy());
        }
        // REQ: API-902 (T27.14c, design 4) — a gate change during a `listen` window would change the
        // gate of sockets already staged, so the preview would no longer describe them.
        if id == wrendns_config::guarded::LISTEN_ACCESS
            && g.pending
                .as_ref()
                .is_some_and(|p| p.setting == wrendns_config::guarded::LISTEN)
        {
            return Err(Problem::new(
                Code::GuardedChangePending,
                "a listener change is pending on this node: change the listener access after it is confirmed or rolled back",
            )
            .hint("Confirm or cancel the pending listener change first."));
        }
        if id == RESTART_NOW && g.pending.is_some() {
            return Err(Problem::new(
                Code::GuardedChangePending,
                "a window change is pending on this node: a restart would drop it from memory",
            )
            .hint("Confirm or cancel it first."));
        }
        if mode == Mode::Staged {
            drop(g);
            if !self.staged_ids().is_empty() {
                return Err(Problem::new(
                    Code::GuardedChangePending,
                    "another change is already staged for the next start",
                )
                .hint("Restart the node (or clear the staged change) before staging another."));
            }
        }
        Ok(())
    }

    /// This node's entries as in force: its own rows, and on a replica what the primary replicated
    /// (a replica has no row of its own for it), with the state this node has for each.
    fn effective_entries(&self) -> Vec<Stored> {
        store::effective(&self.host.running_config(), &self.state, &self.node)
            .into_iter()
            .map(|(e, _)| e)
            .filter(|e| !self.suppressed_entry(e))
            .collect()
    }

    /// This node's `listen-access` value that is in force (active or on probation), if it has one.
    pub(crate) fn stored_access(&self) -> Option<Value> {
        self.effective_entries()
            .into_iter()
            .find(|e| {
                e.id == wrendns_config::guarded::LISTEN_ACCESS
                    && matches!(e.state, EntryState::Active | EntryState::Probation)
            })
            .map(|e| e.value)
    }

    /// REQ: API-902, DNS-901 (T27.14c) — after a `listen` change is kept, this node's stored
    /// `listen-access` loses the lines of the listeners that are gone, so a listener added again on
    /// the same protocol and address starts on its default gate and not on a setting the admin made
    /// for the listener that was removed. A failed write is logged: the change itself is kept.
    async fn prune_gate_lines(&self, listen: &Value, by: &str) {
        let Ok(kept) = super::listen::parse(listen) else {
            return;
        };
        let Some(entry) = self.effective_entries().into_iter().find(|e| {
            e.id == wrendns_config::guarded::LISTEN_ACCESS
                && matches!(e.state, EntryState::Active | EntryState::Probation)
        }) else {
            return;
        };
        let Ok(lines) = super::appliers::ListenAccess::lines(&entry.value) else {
            return;
        };
        let Some(all) = entry.value.get("listeners").and_then(Value::as_array) else {
            return;
        };
        let left: Vec<Value> = all
            .iter()
            .zip(&lines)
            .filter(|(_, line)| {
                kept.iter()
                    .any(|l| l.proto == line.proto && l.addr == line.addr)
            })
            .map(|(v, _)| v.clone())
            .collect();
        if left.len() == all.len() {
            return;
        }
        let pruned = Stored {
            value: json!({"listeners": left}),
            by: by.to_owned(),
            at: (self.now)(),
            ..entry
        };
        if let Err(e) = self
            .host
            .write_entry(
                &self.node,
                wrendns_config::guarded::LISTEN_ACCESS,
                Some(pruned),
                by,
            )
            .await
        {
            warn!("dropping the device key lines of removed listeners failed: {e:?}");
        }
    }

    /// Whether a local clear is suppressing this replicated entry.
    fn suppressed_entry(&self, e: &Stored) -> bool {
        store::suppressed(&self.state)
            .get(&e.id)
            .is_some_and(|d| *d == e.digest())
    }

    pub(crate) fn staged_ids(&self) -> Vec<String> {
        self.effective_entries()
            .into_iter()
            .filter(|e| e.state == EntryState::Staged)
            .map(|e| e.id)
            .collect()
    }

    // ---- apply ---------------------------------------------------------------------------

    /// Makes the change (ADR-956 §3): checks the preview, the phrase, the sign-in recency, then
    /// does what the setting's mode says.
    pub(crate) async fn apply(
        self: &Arc<Self>,
        c: &GuardedCaller,
        id: &str,
        req: GuardedApplyRequest,
    ) -> Result<GuardedApplied, Problem> {
        match self.resolve(req.node.as_deref()) {
            Err(e) => Err(e),
            Ok(Target::Remote(m)) => {
                self.must_forward().map_err(|e| self.refuse(c, id, e))?;
                self.forward_apply(c, &m, id, req).await
            }
            Ok(Target::Local) => self.apply_local(c, id, req).await,
        }
    }

    async fn apply_local(
        self: &Arc<Self>,
        c: &GuardedCaller,
        id: &str,
        req: GuardedApplyRequest,
    ) -> Result<GuardedApplied, Problem> {
        let def = self.row_def(id)?.clone();
        self.rate_limit(c)?;
        let key = Self::failure_key(c, &req.preview_id);
        self.blocked(&key)?;
        self.not_restarting()?;
        let accepted = self
            .accept(c, &def, &req, &key)
            .map_err(|e| self.refuse(c, id, e))?;
        // From here the node's guarded-operation lock is held until the change is final.
        let result = self.run(c, &def, req, accepted).await;
        lock(&self.inner).busy = false;
        match result {
            Ok(a) => Ok(a),
            Err(e) => Err(self.refuse(c, id, e)),
        }
    }

    /// The checks that come before anything changes, ending with taking the operation lock
    /// atomically with the pending check (ADR-956 §4a). The preview is consumed here.
    #[allow(clippy::too_many_lines)] // one ordered list of checks
    fn accept(
        &self,
        c: &GuardedCaller,
        def: &RowDef,
        req: &GuardedApplyRequest,
        key: &str,
    ) -> Result<Preview, Problem> {
        let row = &def.row;
        let now = Instant::now();
        let (rec, version_now) = {
            let g = lock(&self.inner);
            let rec = g.previews.get(&req.preview_id);
            let fresh = rec.is_some_and(|p| p.expires > now);
            if !fresh {
                return Err(Problem::new(
                    Code::PreviewStale,
                    "that preview doesn't exist, was already used, or is older than 5 minutes",
                )
                .hint("Preview the change again."));
            }
            (
                rec.map(|p| {
                    (
                        p.admin.clone(),
                        p.node.clone(),
                        p.setting.clone(),
                        p.binding,
                        p.version,
                        p.phrase.clone(),
                    )
                }),
                self.state.config_version().unwrap_or(0),
            )
        };
        let Some((admin, node, setting, bind, version, phrase)) = rec else {
            return Err(Problem::new(Code::PreviewStale, "unknown preview"));
        };
        if admin != c.username
            || node != self.node
            || setting != row.id
            || !ct_eq(
                &bind,
                &binding(&c.username, &self.node, row.id, &req.value, &req.options),
            )
            || version != version_now
        {
            return Err(Problem::new(
                Code::PreviewStale,
                "the value, the configuration or the admin changed since the preview",
            )
            .hint("Preview the change again."));
        }
        // The phrase is compared here, on the server: a script or forged request can't skip it.
        if !ct_eq(req.confirm.as_bytes(), phrase.as_bytes()) {
            self.failed(key);
            return Err(Problem::invalid(format!(
                "the confirmation doesn't match: type exactly `{phrase}`"
            )));
        }
        if self.set_by_file(row) {
            return Err(Problem::new(
                Code::SetByFile,
                "a configuration file now sets it",
            ));
        }
        let mut g = lock(&self.inner);
        let Some(rec) = g.previews.get(&req.preview_id) else {
            return Err(Problem::new(Code::PreviewStale, "unknown preview"));
        };
        // The extra acknowledgements the preview named.
        if let Some(missing) = rec
            .acknowledgements
            .iter()
            .find(|a| !req.acknowledge.iter().any(|x| x == *a))
        {
            return Err(Problem::new(
                Code::AcknowledgementRequired,
                format!("this change needs the acknowledgement `{missing}`"),
            ));
        }
        // A weakening change (and a restart) needs a sign-in within the last 10 minutes.
        if rec.needs_recent {
            let t = (self.now)();
            let ok = c
                .signed_in_at
                .is_some_and(|s| t.saturating_sub(s) <= wrendns_api::auth::RECENT_SIGN_IN_SECS);
            if !ok {
                return Err(Problem::new(
                    Code::ReauthRequired,
                    if rec.weakening {
                        "this change weakens security: it needs a sign-in within the last 10 minutes"
                    } else {
                        "this needs a sign-in within the last 10 minutes"
                    },
                )
                .hint("Sign in again (for single sign-on, repeat the provider's sign-in), then apply the change."));
            }
        }
        // The pending check and the lock are one step.
        if g.restarting {
            return Err(Problem::new(Code::Restarting, "the node is restarting"));
        }
        if g.busy {
            return Err(Problem::new(
                Code::GuardedChangePending,
                "another guarded operation holds this node",
            ));
        }
        if row.id == RESTART_NOW {
            if g.pending.is_some() {
                return Err(Problem::new(
                    Code::GuardedChangePending,
                    "a window change is pending on this node",
                ));
            }
        } else if (row.mode != Mode::Immediate && g.pending.is_some())
            || (row.id == wrendns_config::guarded::LISTEN_ACCESS
                && g.pending
                    .as_ref()
                    .is_some_and(|p| p.setting == wrendns_config::guarded::LISTEN))
        {
            return Err(Problem::new(
                Code::GuardedChangePending,
                "this node already has a pending change",
            ));
        }
        g.busy = true;
        g.previews
            .remove(&req.preview_id)
            .ok_or_else(|| Problem::new(Code::PreviewStale, "unknown preview"))
    }

    async fn run(
        self: &Arc<Self>,
        c: &GuardedCaller,
        def: &RowDef,
        req: GuardedApplyRequest,
        pre: Preview,
    ) -> Result<GuardedApplied, Problem> {
        let row = def.row;
        if row.id == RESTART_NOW {
            return self.restart_apply(c, &req, &pre).await;
        }
        let cfg = self.host.running_config();
        let access = self.stored_access();
        // The same checks again: what was true at preview may not be now (ADR-956 §3).
        let cx = CheckCx {
            cfg: &cfg,
            node: &self.node,
            value: &req.value,
            options: &req.options,
            caller: c,
            host: self.host.as_ref(),
            access: access.as_ref(),
        };
        let checked = def.applier.check(&cx)?;
        // REQ: API-902 (T27.14c, design 4) — what the admin reviewed no longer holds: the host's
        // facts moved, or the change now weakens and the preview said it did not. Judged again
        // from a fresh preview, never on the old one's gates and confirm requirements.
        if checked.host_facts != pre.host_facts || (checked.weakening && !pre.weakening) {
            return Err(Problem::new(
                Code::PreviewStale,
                "this host's addresses changed since the preview, so the review no longer holds",
            )
            .hint("Preview the change again."));
        }
        if checked.would_disconnect {
            return Err(Problem::new(
                Code::WouldDisconnectYou,
                checked
                    .disconnect_detail
                    .unwrap_or_else(|| "the change would now cut this node off".to_owned()),
            ));
        }
        let before = def.applier.current(&cfg);
        match row.mode {
            Mode::Immediate => self.apply_immediate(c, &row, &req, &pre, before).await,
            Mode::Staged => self.apply_staged(c, &row, &req, &pre, before).await,
            Mode::Window => self.apply_window(c, def, &req, &pre, before).await,
            Mode::Action => {
                let msg = def
                    .applier
                    .act(
                        Arc::clone(&self.host),
                        self.node.clone(),
                        req.value.clone(),
                        req.options.clone(),
                    )
                    .await?;
                self.finish_audit(c, &row, &req, &before, "applied", pre.weakening);
                Ok(self.applied("applied", &row, false, msg))
            }
        }
    }

    fn applied(
        &self,
        status: &str,
        row: &Row,
        pending_restart: bool,
        message: String,
    ) -> GuardedApplied {
        GuardedApplied {
            status: status.to_owned(),
            setting: row.id.to_owned(),
            node: self.node.clone(),
            pending_restart,
            pending_id: None,
            deadline_secs: None,
            confirm_token: None,
            new_address: None,
            proof: None,
            message,
        }
    }

    fn stored(&self, row: &Row, req: &GuardedApplyRequest, state: EntryState, by: &str) -> Stored {
        Stored {
            node: self.node.clone(),
            id: row.id.to_owned(),
            value: req.value.clone(),
            mode: row.mode.as_str().to_owned(),
            state,
            by: by.to_owned(),
            at: (self.now)(),
        }
    }

    fn finish_audit(
        &self,
        c: &GuardedCaller,
        row: &Row,
        req: &GuardedApplyRequest,
        before: &Value,
        outcome: &str,
        weakening: bool,
    ) {
        self.audit_best_effort(
            &c.actor,
            "settings.guarded",
            &self.target_name(row.id),
            &json!({
                "setting": row.id,
                "node": self.node,
                "mode": row.mode.as_str(),
                "outcome": outcome,
                "before": redact(before),
                "after": redact(&req.value),
                "reason": req.reason.clone().or_else(|| c.actor.reason.clone()),
                "weakening": weakening,
                "sessionKey": c.session,
                "remote": c.remote.map(|r| r.to_string()),
            }),
        );
        store::record_outcome(
            &self.state,
            GuardedOutcome {
                setting: row.id.to_owned(),
                node: self.node.clone(),
                outcome: outcome.to_owned(),
                reason: None,
                at: (self.now)(),
            },
        );
    }

    async fn apply_immediate(
        self: &Arc<Self>,
        c: &GuardedCaller,
        row: &Row,
        req: &GuardedApplyRequest,
        pre: &Preview,
        before: Value,
    ) -> Result<GuardedApplied, Problem> {
        let previous = self
            .effective_entries()
            .into_iter()
            .find(|e| e.id == row.id);
        let entry = self.stored(row, req, EntryState::Active, &c.username);
        let digest = entry.digest();
        self.host
            .write_entry(&self.node, row.id, Some(entry), &c.username)
            .await?;
        // On a replica the entry reaches this node through the primary's next version: the reload
        // below applies it only once it is here (an `applied` answer is never given before).
        if !self
            .host
            .wait_applied(&self.node, row.id, Some(digest))
            .await
        {
            self.audit_best_effort(
                &c.actor,
                "settings.guarded",
                &self.target_name(row.id),
                &json!({"setting": row.id, "node": self.node, "outcome": "recorded_not_yet_applied"}),
            );
            return Err(Problem::unavailable(
                "the primary recorded the change, but this node hasn't received it yet; it applies when it arrives",
            )
            .hint("Check the setting again in a moment; nothing is lost."));
        }
        // Applied by the same reload the API uses; a failed reload keeps the previous
        // configuration (CLU-004), and the entry goes back to what it was.
        let reloaded = self.host.reload().await;
        // REQ: DNS-901 — a listen-access change counts as applied only when every configured
        // encrypted listener is bound as configured, by the listener's recorded state. On a
        // replica the replication path has already applied the entry (and closed the old socket)
        // before this reload, so the reload alone cannot report that the gate did not arrive.
        let unapplied = if reloaded && row.id == wrendns_config::guarded::LISTEN_ACCESS {
            self.host.listeners_not_applied()
        } else {
            Vec::new()
        };
        if !reloaded || !unapplied.is_empty() {
            let back = self
                .host
                .write_entry(&self.node, row.id, previous, &c.username)
                .await;
            if back.is_ok() {
                let _ = self.host.reload().await;
            }
            self.audit_best_effort(
                &c.actor,
                "settings.guarded_rolled_back",
                &self.target_name(row.id),
                &json!({"setting": row.id, "node": self.node, "reason": "commit_failed"}),
            );
            // After the rollback: a listener the failed gate-on closed (an unreadable
            // certificate) stays closed, so "kept the previous configuration" alone is untrue.
            let still = if row.id == wrendns_config::guarded::LISTEN_ACCESS {
                self.host.listeners_not_applied()
            } else {
                Vec::new()
            };
            let msg = if still.is_empty() {
                "the node couldn't apply the change, so it kept the previous configuration"
                    .to_owned()
            } else {
                format!(
                    "the node couldn't apply the change; the previous configuration is restored, but {} is closed until its certificate can be read (see the health report, reason listener_not_applied)",
                    still.join(", ")
                )
            };
            return Err(Problem::new(Code::InvalidConfig, msg));
        }
        self.finish_audit(c, row, req, &before, "applied", pre.weakening);
        info!(setting = row.id, node = %self.node, "guarded setting applied");
        Ok(self.applied(
            "applied",
            row,
            false,
            format!("`{}` was applied on {}", row.id, self.node),
        ))
    }

    async fn apply_staged(
        self: &Arc<Self>,
        c: &GuardedCaller,
        row: &Row,
        req: &GuardedApplyRequest,
        pre: &Preview,
        before: Value,
    ) -> Result<GuardedApplied, Problem> {
        let entry = self.stored(row, req, EntryState::Staged, &c.username);
        self.host
            .write_entry(&self.node, row.id, Some(entry), &c.username)
            .await?;
        self.finish_audit(c, row, req, &before, "staged", pre.weakening);
        Ok(self.applied(
            "staged",
            row,
            true,
            format!(
                "`{}` is staged on {}: it takes effect at the node's next start",
                row.id, self.node
            ),
        ))
    }

    async fn apply_window(
        self: &Arc<Self>,
        c: &GuardedCaller,
        def: &RowDef,
        req: &GuardedApplyRequest,
        pre: &Preview,
        before: Value,
    ) -> Result<GuardedApplied, Problem> {
        let row = def.row;
        let staged = match def
            .applier
            .stage(
                Arc::clone(&self.host),
                self.node.clone(),
                req.value.clone(),
                self.stored_access(),
                pre.host_facts,
            )
            .await
        {
            Ok(s) => s,
            Err(e) => {
                // A failed bind (or validation) changes nothing, and says why.
                self.audit_best_effort(
                    &c.actor,
                    "settings.guarded_rolled_back",
                    &self.target_name(row.id),
                    &json!({"setting": row.id, "node": self.node, "reason": "bind_failed"}),
                );
                self.outcome(row.id, "rolled_back", Some("bind_failed"));
                return Err(e);
            }
        };
        let window = self.window_secs();
        let pending_id = random_id(8);
        let token = random_id(24);
        let deadline = Instant::now() + Duration::from_secs(window);
        let expiry = {
            let me: Weak<Self> = Arc::downgrade(self);
            let pid = pending_id.clone();
            tokio::spawn(async move {
                tokio::time::sleep_until(deadline).await;
                if let Some(e) = me.upgrade() {
                    e.rollback(&pid, "expired").await;
                }
            })
        };
        let proof = row.proof;
        let new_address = staged.new_address.clone();
        // REQ: API-902, OBS-020 (T27.14b) — the node's own probe of each staged DNS socket, at once
        // and then every few seconds while the window is open.
        let (probes, probe_loop) = if staged.dns_probes.is_empty() {
            (None, None)
        } else {
            let set = Arc::new(ProbeSet::new(staged.dns_probes, self.now));
            let every = self
                .probe_every_ms
                .load(std::sync::atomic::Ordering::Relaxed);
            let lp = ProbeLoop::spawn(
                Arc::clone(&set),
                Arc::clone(&self.host),
                Duration::from_millis(every.max(10)),
            );
            (Some(set), Some(lp))
        };
        {
            let mut g = lock(&self.inner);
            g.pending = Some(Pending {
                id: pending_id.clone(),
                setting: row.id.to_owned(),
                mode: row.mode,
                proof,
                admin: c.username.clone(),
                actor: c.actor.clone(),
                reason: req.reason.clone().or_else(|| c.actor.reason.clone()),
                token_hash: *blake3::hash(token.as_bytes()).as_bytes(),
                deadline,
                window_secs: window,
                value: req.value.clone(),
                before,
                weakening: pre.weakening,
                guard: staged.guard,
                proof_addr: staged.proof_addr,
                proxies: staged.pending_proxies,
                probes,
                probe_loop,
                expiry: Some(expiry),
            });
        }
        info!(setting = row.id, node = %self.node, window, "guarded change pending confirmation");
        Ok(GuardedApplied {
            status: "pending".to_owned(),
            setting: row.id.to_owned(),
            node: self.node.clone(),
            pending_restart: false,
            pending_id: Some(pending_id),
            deadline_secs: Some(window),
            confirm_token: Some(token),
            new_address,
            proof: proof.map(|p| p.as_str().to_owned()),
            message: format!(
                "Confirm within {window} seconds through the new address, or the change rolls back."
            ),
        })
    }

    fn outcome(&self, id: &str, outcome: &str, reason: Option<&str>) {
        store::record_outcome(
            &self.state,
            GuardedOutcome {
                setting: id.to_owned(),
                node: self.node.clone(),
                outcome: outcome.to_owned(),
                reason: reason.map(str::to_owned),
                at: (self.now)(),
            },
        );
    }

    // ---- confirm, cancel, expire -----------------------------------------------------------

    /// Confirms the pending change `pending_id` (ADR-956 §3).
    pub(crate) async fn confirm(
        self: &Arc<Self>,
        c: &GuardedCaller,
        pending_id: &str,
        token: Option<String>,
    ) -> Result<GuardedResult, Problem> {
        let key = Self::failure_key(c, pending_id);
        self.blocked(&key)?;
        self.rate_limit(c)?;
        // Look at the pending change; keep the lock short.
        let snapshot = {
            let mut g = lock(&self.inner);
            if g.busy {
                return Err(Problem::new(
                    Code::GuardedChangePending,
                    "this node is finishing another guarded operation",
                ));
            }
            match g.pending.as_ref() {
                Some(p) if p.id == pending_id => {
                    let snap = (
                        p.setting.clone(),
                        p.proof,
                        p.admin.clone(),
                        p.token_hash,
                        p.proof_addr,
                        p.probes.clone(),
                    );
                    g.busy = true;
                    snap
                }
                _ => {
                    return Err(Problem::not_found(
                        "no change is pending under that ID (it may have rolled back)",
                    ));
                }
            }
        };
        let result = self
            .confirm_inner(c, pending_id, token, &key, snapshot)
            .await;
        lock(&self.inner).busy = false;
        result
    }

    #[allow(clippy::too_many_lines)]
    async fn confirm_inner(
        self: &Arc<Self>,
        c: &GuardedCaller,
        pending_id: &str,
        token: Option<String>,
        key: &str,
        snap: ConfirmSnapshot,
    ) -> Result<GuardedResult, Problem> {
        let (setting, proof, admin, token_hash, proof_addr, probes) = snap;
        // Who: the single-use token (bound to the admin, node and change), or a session of the
        // same admin. Another admin's session, or a token for another change, is refused.
        let token_ok = token
            .as_deref()
            .is_some_and(|t| ct_eq(blake3::hash(t.as_bytes()).as_bytes(), &token_hash));
        let session_ok = !c.username.is_empty() && c.username == admin;
        if !c.username.is_empty() && c.username != admin {
            self.failed(key);
            return Err(self.refuse(
                c,
                &setting,
                Problem::new(
                    Code::Forbidden,
                    "this change was made by another admin: only they can confirm it",
                ),
            ));
        }
        if !token_ok && !session_ok {
            self.failed(key);
            return Err(self.refuse(
                c,
                &setting,
                Problem::new(
                    Code::Forbidden,
                    "the confirmation token is wrong, and this isn't the admin's session",
                ),
            ));
        }
        // What: the request must prove it came through the new address (ADR-956 §3).
        // A change with DNS probes and no proof socket is proved by "every probe answers" (judged
        // below): no request has to arrive on a new socket (T27.14b, design 2.2).
        let by_probe = probes.is_some() && proof_addr.is_none();
        let proved = by_probe
            || match proof {
                Some(Proof::NewSocket) => proof_addr.is_some() && c.arrived_on == proof_addr,
                Some(Proof::NewCert) => c.tls && proof_addr.is_some() && c.arrived_on == proof_addr,
                Some(Proof::ProxyList) => c.remote_under_pending.is_some(),
                None => true,
            };
        if !proved {
            self.failed(key);
            return Err(self.refuse(
                c,
                &setting,
                Problem::new(
                    Code::Forbidden,
                    "this request didn't arrive through the new address: open the new address and confirm there",
                )
                .hint("The change is still pending; it rolls back when the window ends."),
            ));
        }
        // The node's own probe of every staged DNS socket must answer, now. A failing probe refuses
        // the confirm and the window runs on; it is not counted toward the failure block, because
        // the admin did nothing wrong (design 2.2).
        if let Some(set) = &probes {
            let failures = set.run(&self.host).await;
            if !failures.is_empty() {
                info!(setting = %setting, failures = ?failures, "guarded confirm refused: the node's own probe got no answer");
                return Err(Problem::new(
                    Code::Forbidden,
                    format!("the node's own query to {}", failures.join("; ")),
                )
                .hint("The change is still pending; it rolls back when the window ends. Check the address and the certificate, then confirm again."));
            }
        }
        // Commit: write the entry (through the primary on a replica), then keep the new sockets.
        let (value, before, weakening, guard, mode, actor, reason) = {
            let g = lock(&self.inner);
            let Some(p) = g.pending.as_ref().filter(|p| p.id == pending_id) else {
                return Err(Problem::not_found("the change is no longer pending"));
            };
            (
                p.value.clone(),
                p.before.clone(),
                p.weakening,
                Arc::clone(&p.guard),
                p.mode,
                p.actor.clone(),
                p.reason.clone(),
            )
        };
        // REQ: API-902 (T27.14c, design 4) — the host's addresses changed since the stage: the gates
        // the staged sockets were bound with may no longer be the default. The window runs on.
        if let Some(why) = guard.stale() {
            return Err(Problem::new(Code::PreviewStale, why).hint(
                "Cancel the change and review it again; it rolls back when the window ends.",
            ));
        }
        let def = self.row_def(&setting)?;
        // The entry in force before this change: a failed commit puts it back (not removes it).
        let previous = self.effective_entries().into_iter().find(|e| {
            e.id == setting && matches!(e.state, EntryState::Active | EntryState::Probation)
        });
        let entry = Stored {
            node: self.node.clone(),
            id: setting.clone(),
            value: value.clone(),
            mode: mode.as_str().to_owned(),
            state: EntryState::Active,
            by: admin.clone(),
            at: (self.now)(),
        };
        if let Err(e) = self
            .host
            .write_entry(&self.node, &setting, Some(entry), &admin)
            .await
        {
            if e.code == Code::PrimaryUnreachable {
                // The window runs on and rolls back: a node never runs a value no one replicates.
                return Err(e);
            }
            self.rollback_locked(pending_id, "commit_failed").await;
            return Err(e);
        }
        if let Err(e) = guard.commit().await {
            warn!(setting = %setting, "committing the new sockets failed: {e:?}");
            let removed = self
                .host
                .write_entry(&self.node, &setting, previous, &admin)
                .await;
            // The reload puts the previous list back where the entry had already been applied.
            if removed.is_ok() {
                let _ = self.host.reload().await;
            }
            self.rollback_locked(pending_id, guard.failure_reason())
                .await;
            return Err(Problem::new(
                Code::Internal,
                "the node couldn't keep the new sockets, so the change was rolled back",
            ));
        }
        let _ = def;
        if setting == wrendns_config::guarded::LISTEN {
            self.prune_gate_lines(&value, &admin).await;
        }
        let seen = c.remote_under_pending.map(|a| a.to_string());
        {
            let mut g = lock(&self.inner);
            if let Some(mut p) = g.pending.take() {
                p.end_probes();
                if let Some(h) = p.expiry.take() {
                    h.abort();
                }
            }
        }
        let mut who = actor.clone();
        who.reason.clone_from(&reason);
        self.audit_best_effort(
            &who,
            "settings.guarded",
            &self.target_name(&setting),
            &json!({
                "setting": setting, "node": self.node, "mode": mode.as_str(),
                "outcome": "confirmed",
                "before": redact(&before), "after": redact(&value),
                "reason": reason, "weakening": weakening,
                "confirmedFrom": c.remote.map(|r| r.to_string()),
            }),
        );
        self.outcome(&setting, "confirmed", None);
        Ok(GuardedResult {
            setting,
            node: self.node.clone(),
            outcome: "confirmed".to_owned(),
            reason: None,
            seen_client: seen,
        })
    }

    /// REQ: API-902, OBS-020 (T27.14b) — `GET /api/v1/guarded/pending/{id}`: the seconds left and,
    /// per staged DNS socket, the node's last probe and the evidence counter. The confirm route's own
    /// who-checks apply (the single-use token, or the same admin's session; another admin and a
    /// wrong token are refused and counted toward the failure block). Not rate-limited: the web UI
    /// reads it every few seconds while the window is open.
    pub(crate) fn pending_view(
        &self,
        c: &GuardedCaller,
        pending_id: &str,
        token: Option<&str>,
    ) -> Result<GuardedPendingView, Problem> {
        let key = Self::failure_key(c, pending_id);
        self.blocked(&key)?;
        let (setting, admin, token_hash, deadline, probes) = {
            let g = lock(&self.inner);
            match g.pending.as_ref().filter(|p| p.id == pending_id) {
                Some(p) => (
                    p.setting.clone(),
                    p.admin.clone(),
                    p.token_hash,
                    p.deadline,
                    p.probes.clone(),
                ),
                None => {
                    return Err(Problem::not_found(
                        "no change is pending under that ID on this node (it may have rolled back)",
                    ));
                }
            }
        };
        let token_ok =
            token.is_some_and(|t| ct_eq(blake3::hash(t.as_bytes()).as_bytes(), &token_hash));
        if !c.username.is_empty() && c.username != admin {
            self.failed(&key);
            return Err(Problem::new(
                Code::Forbidden,
                "this change was made by another admin: only they can read it",
            ));
        }
        if !token_ok && c.username.is_empty() {
            self.failed(&key);
            return Err(Problem::new(
                Code::Forbidden,
                "the confirmation token is wrong, and this isn't the admin's session",
            ));
        }
        let probes = probes
            .map(|set| {
                set.lines()
                    .into_iter()
                    .map(|(p, last)| GuardedProbeLine {
                        listener: p.listener(),
                        state: last
                            .as_ref()
                            .map_or("waiting", |l| l.kind.as_str())
                            .to_owned(),
                        error: last.as_ref().and_then(|l| l.error.clone()),
                        at: last.as_ref().map(|l| l.at),
                        other_hosts: p.evidence.as_ref().map_or(0, |e| e.others()),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(GuardedPendingView {
            id: pending_id.to_owned(),
            setting,
            node: self.node.clone(),
            deadline_secs: remaining(deadline),
            probes,
        })
    }

    /// Cancels the pending change `pending_id`.
    pub(crate) async fn cancel(
        self: &Arc<Self>,
        c: &GuardedCaller,
        pending_id: &str,
    ) -> Result<GuardedResult, Problem> {
        self.rate_limit(c)?;
        let here = {
            let g = lock(&self.inner);
            g.pending
                .as_ref()
                .filter(|p| p.id == pending_id)
                .map(|p| p.setting.clone())
        };
        let Some(setting) = here else {
            // Not here: on the primary, the change may be a member's (the admin is looking at the
            // cluster through this node), so each member is asked with a signed, single-use
            // assertion; the one that holds it answers.
            if self.host.is_primary() && self.host.clustered() {
                for m in self.host.members().into_iter().filter(|m| m.up) {
                    if let Ok(r) = self.forward_cancel(c, &m.name, pending_id).await {
                        return Ok(r);
                    }
                }
            }
            return Err(Problem::not_found("no change is pending under that ID"));
        };
        self.rollback(pending_id, "cancelled").await;
        Ok(GuardedResult {
            setting,
            node: self.node.clone(),
            outcome: "rolled_back".to_owned(),
            reason: Some("cancelled".to_owned()),
            seen_client: None,
        })
    }

    /// Ends the pending change `pending_id` without keeping it: the new sockets close, the old ones
    /// were never touched, nothing was written; the reason is audited and shown (ADR-956 §3).
    pub(crate) async fn rollback(self: &Arc<Self>, pending_id: &str, reason: &str) {
        // The operation lock: a rollback doesn't run in the middle of a commit.
        loop {
            {
                let mut g = lock(&self.inner);
                let ours = g.pending.as_ref().is_some_and(|p| p.id == pending_id);
                if !ours {
                    return;
                }
                if !g.busy {
                    g.busy = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.rollback_locked(pending_id, reason).await;
        lock(&self.inner).busy = false;
    }

    /// [`Engine::rollback`] when the caller already holds the operation lock.
    async fn rollback_locked(&self, pending_id: &str, reason: &str) {
        let p = {
            let mut g = lock(&self.inner);
            if g.pending.as_ref().is_some_and(|p| p.id == pending_id) {
                g.pending.take()
            } else {
                None
            }
        };
        let Some(mut p) = p else { return };
        p.end_probes();
        if let Some(h) = p.expiry.take() {
            // The expiry task may be the caller: let it finish by not awaiting it.
            h.abort();
        }
        p.guard.abort().await;
        self.audit_best_effort(
            &p.actor,
            "settings.guarded_rolled_back",
            &self.target_name(&p.setting),
            &json!({"setting": p.setting, "node": self.node, "reason": reason, "windowSecs": p.window_secs}),
        );
        self.outcome(&p.setting, "rolled_back", Some(reason));
        info!(setting = %p.setting, reason, "guarded change rolled back");
    }

    // ---- forwarding (ADR-956 §5) -----------------------------------------------------------

    fn assertion_for(
        &self,
        c: &GuardedCaller,
        node: &str,
        action: &str,
        setting: &str,
        preview_id: &str,
    ) -> Result<Signed, Problem> {
        let a = Assertion {
            admin: c.username.clone(),
            actor: c.actor.name.clone(),
            role: "admin".to_owned(),
            signed_in_at: c.signed_in_at,
            remote: c.remote.map(|r| r.to_string()),
            issuer: self.node.clone(),
            node: node.to_owned(),
            action: action.to_owned(),
            setting: setting.to_owned(),
            preview_id: preview_id.to_owned(),
            nonce: random_id(16),
            expires: (self.now)() + ASSERTION_SECS,
        };
        self.host.assertion(&a).ok_or_else(|| {
            Problem::new(
                Code::NotPrimary,
                "only the primary can sign a forwarded guarded request",
            )
        })
    }

    async fn forward_preview(
        &self,
        c: &GuardedCaller,
        m: &Member,
        id: &str,
        req: GuardedPreviewRequest,
    ) -> Result<GuardedPreview, Problem> {
        self.rate_limit(c)?;
        let a = self.assertion_for(c, &m.name, "preview", id, "")?;
        let fwd = Forwarded {
            op: ForwardedOp::Preview {
                id: id.to_owned(),
                req,
            },
            assertion: Some(a),
        };
        match self.host.forward(&m.name, fwd).await? {
            ForwardedAnswer::Preview(p) => Ok(p),
            ForwardedAnswer::Refused {
                code,
                detail,
                hint,
                retry_after,
            } => Err(problem_of(code, detail, hint, retry_after)),
            _ => Err(Problem::internal("unexpected answer from the node")),
        }
    }

    async fn forward_apply(
        &self,
        c: &GuardedCaller,
        m: &Member,
        id: &str,
        req: GuardedApplyRequest,
    ) -> Result<GuardedApplied, Problem> {
        self.rate_limit(c)?;
        let a = self.assertion_for(c, &m.name, "apply", id, &req.preview_id)?;
        let fwd = Forwarded {
            op: ForwardedOp::Apply {
                id: id.to_owned(),
                req,
            },
            assertion: Some(a),
        };
        match self.host.forward(&m.name, fwd).await? {
            ForwardedAnswer::Applied(p) => Ok(p),
            ForwardedAnswer::Refused {
                code,
                detail,
                hint,
                retry_after,
            } => Err(problem_of(code, detail, hint, retry_after)),
            _ => Err(Problem::internal("unexpected answer from the node")),
        }
    }

    /// Cancels a pending change on another node (the primary forwards it).
    pub(crate) async fn forward_cancel(
        &self,
        c: &GuardedCaller,
        node: &str,
        pending: &str,
    ) -> Result<GuardedResult, Problem> {
        self.must_forward()?;
        let m = self
            .host
            .members()
            .into_iter()
            .find(|m| m.name == node || m.id == node)
            .ok_or_else(|| Problem::new(Code::NodeUnknown, format!("no cluster node `{node}`")))?;
        let a = self.assertion_for(c, &m.name, "cancel", pending, "")?;
        let fwd = Forwarded {
            op: ForwardedOp::Cancel {
                pending: pending.to_owned(),
            },
            assertion: Some(a),
        };
        match self.host.forward(&m.name, fwd).await? {
            ForwardedAnswer::Result(r) => Ok(r),
            ForwardedAnswer::Refused {
                code,
                detail,
                hint,
                retry_after,
            } => Err(problem_of(code, detail, hint, retry_after)),
            _ => Err(Problem::internal("unexpected answer from the node")),
        }
    }

    /// The target's side of a forwarded request: every check is made again here, on this node
    /// (ADR-956 §5): the assertion's signature, its issuer (the primary), its node, action and
    /// preview, its expiry and that it has not been used; then the same engine runs as for a local
    /// request, with the admin the assertion names.
    pub(crate) async fn handle_forwarded(
        self: &Arc<Self>,
        sender: &str,
        f: Forwarded,
    ) -> ForwardedAnswer {
        let refused = |p: &Problem| ForwardedAnswer::Refused {
            code: p.code,
            detail: p.detail.clone(),
            hint: p.hint.clone(),
            retry_after: p.retry_after,
        };
        if matches!(f.op, ForwardedOp::Status) {
            return ForwardedAnswer::Status(self.status_local());
        }
        let Some(signed) = f.assertion.as_ref() else {
            return refused(&Problem::new(
                Code::Forbidden,
                "a forwarded guarded request needs an assertion",
            ));
        };
        let (action, setting, preview_id) = match &f.op {
            ForwardedOp::Preview { id, .. } => ("preview", id.clone(), String::new()),
            ForwardedOp::Apply { id, req } => ("apply", id.clone(), req.preview_id.clone()),
            ForwardedOp::Cancel { pending } => ("cancel", pending.clone(), String::new()),
            ForwardedOp::Status => return refused(&Problem::internal("unreachable")),
        };
        let now = (self.now)();
        let want = Expect {
            sender,
            now,
            me: &self.node,
            action,
            setting: &setting,
            preview_id: &preview_id,
        };
        let a = match signed.check(&*self.host, &want) {
            Ok(a) => a.clone(),
            Err(r) => {
                self.audit_best_effort(
                    &Actor::system("cluster"),
                    "settings.guarded_refused",
                    &self.target_name(&setting),
                    &json!({"setting": setting, "node": self.node, "code": "forbidden", "assertion": r.why()}),
                );
                return refused(&Problem::new(Code::Forbidden, r.why()));
            }
        };
        // Single use: the nonce is kept until the assertion would have expired anyway.
        {
            let mut g = lock(&self.inner);
            g.nonces.retain(|_, exp| *exp >= now);
            if g.nonces.insert(a.nonce.clone(), a.expires).is_some() {
                drop(g);
                return refused(&Problem::new(Code::Forbidden, Refusal::Replayed.why()));
            }
        }
        let caller = GuardedCaller {
            actor: Actor {
                name: format!("{} via {}", a.actor, a.issuer),
                kind: "session",
                remote: a.remote.clone(),
                reason: None,
            },
            username: a.admin.clone(),
            session: Some(format!("fwd:{}", a.admin)),
            signed_in_at: a.signed_in_at,
            arrived_on: None,
            remote: a.remote.as_deref().and_then(|r| r.parse().ok()),
            remote_under_pending: None,
            tls: false,
        };
        match f.op {
            ForwardedOp::Preview { id, mut req } => {
                req.node = None;
                match self.preview_local(&caller, &id, &req) {
                    Ok(p) => ForwardedAnswer::Preview(p),
                    Err(e) => refused(&e),
                }
            }
            ForwardedOp::Apply { id, mut req } => {
                req.node = None;
                match self.apply_local(&caller, &id, req).await {
                    Ok(p) => ForwardedAnswer::Applied(p),
                    Err(e) => refused(&e),
                }
            }
            ForwardedOp::Cancel { pending } => match self.cancel(&caller, &pending).await {
                Ok(r) => ForwardedAnswer::Result(r),
                Err(e) => refused(&e),
            },
            ForwardedOp::Status => refused(&Problem::internal("unreachable")),
        }
    }
}

/// Seconds left until `deadline` on the monotonic clock, rounded up.
fn remaining(deadline: Instant) -> u64 {
    let left = deadline.saturating_duration_since(Instant::now());
    left.as_secs() + u64::from(left.subsec_nanos() > 0)
}

/// Hex of a digest, for logs that must not hold the value.
#[allow(dead_code)]
pub(crate) fn short(bytes: &[u8]) -> String {
    hex(&bytes[..bytes.len().min(4)])
}

/// The rows a production node has, each with its applier (T27.14 to T27.17 add theirs here).
pub(crate) fn production_rows() -> Vec<RowDef> {
    super::appliers::rows()
}

/// Lets `ProofSocket`s be named by the engine's callers.
#[allow(dead_code)]
pub(crate) type ProofHandle = Arc<dyn ProofSocket>;

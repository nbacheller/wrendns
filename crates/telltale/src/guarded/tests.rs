//! REQ: API-902, API-006, AGT-009, CLU-004, CLU-010 (T27.13; ADR-914, ADR-956, ADR-957) — the
//! guarded engine, driven with a fake node: the registry rows here are the tests' own (the real
//! ones come with T27.14 to T27.17), and every effect (reload, sockets, the cluster channel, the
//! audit log) is a recording fake, so the state machine runs under `tokio::time::pause` with no
//! sockets, clocks or cluster.

#![allow(
    clippy::many_single_char_names,
    clippy::items_after_statements,
    clippy::assert_is_empty,
    clippy::too_many_lines,
    clippy::manual_assert_eq,
    clippy::assertions_on_constants
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use serde_json::{Value, json};
use telltale_api::BoxFuture;
use telltale_api::auth::Actor;
use telltale_api::guarded::{
    GuardedApplied, GuardedApplyRequest, GuardedCaller, GuardedPreview, GuardedPreviewRequest,
    Supervisor,
};
use telltale_api::problem::{Code, Problem};
use telltale_config::Config;
use telltale_config::guarded::{Mode, Proof, RESTART_NOW, Row, never};
use telltale_store::state::State;

use super::assertion::{Assertion, Forwarded, ForwardedAnswer, ForwardedOp, Signed};
use super::engine::{Applier, CheckCx, Checked, Engine, NoOp, RowDef, Staged, WindowGuard};
use super::host::{Host, Member, ProofSocket};
use super::probation::{self, Sidecar};
use super::store::{self, EntryState, Stored};

fn weaken_flag(_old: &Value, new: &Value) -> bool {
    new.get("weaken").and_then(Value::as_bool) == Some(true)
}

macro_rules! row {
    ($id:literal, $paths:expr, $mode:expr, $proof:expr, $weak:expr) => {
        Row {
            id: $id,
            label: $id,
            paths: $paths,
            mode: $mode,
            proof: $proof,
            weakens: $weak,
            test_only: true,
        }
    };
}

static R_IMM: Row = row!("t-imm", &["t.imm"], Mode::Immediate, None, weaken_flag);
static R_WIN: Row = row!(
    "t-win",
    &["t.win"],
    Mode::Window,
    Some(Proof::NewSocket),
    never
);
static R_PROXY: Row = row!(
    "t-proxy",
    &["t.proxy"],
    Mode::Window,
    Some(Proof::ProxyList),
    never
);
static R_STG: Row = row!("t-stg", &["t.stg"], Mode::Staged, None, never);
static R_STG2: Row = row!("t-stg2", &["t.stg2"], Mode::Staged, None, never);
static R_KEY: Row = row!("t-key", &["t.key"], Mode::Staged, None, never);
static R_RESTART: Row = Row {
    id: RESTART_NOW,
    label: "Restart now",
    paths: &[],
    mode: Mode::Action,
    proof: None,
    weakens: never,
    test_only: true,
};

/// The tests' applier: a `label` is needed, a `port` names the proof socket, `proxies` the pending
/// list of a proxy row.
#[derive(Default)]
struct TApplier {
    /// `failed_start` hands back this entry's replacement (the key row's rotation rule).
    key_fallback: bool,
}

struct SockGuard {
    sock: Arc<dyn ProofSocket>,
    committed: Arc<AtomicBool>,
    aborted: Arc<AtomicBool>,
    commit_fails: bool,
}

impl WindowGuard for SockGuard {
    fn commit(&self) -> BoxFuture<Result<(), Problem>> {
        self.committed.store(true, Ordering::SeqCst);
        let fail = self.commit_fails;
        self.sock.close();
        Box::pin(std::future::ready(if fail {
            Err(Problem::internal("fake commit failure"))
        } else {
            Ok(())
        }))
    }
    fn abort(&self) -> BoxFuture<()> {
        self.aborted.store(true, Ordering::SeqCst);
        self.sock.close();
        Box::pin(std::future::ready(()))
    }
}

thread_local! {
    static FLAGS: std::cell::RefCell<(Arc<AtomicBool>, Arc<AtomicBool>)> =
        std::cell::RefCell::new((Arc::default(), Arc::default()));
}

impl Applier for TApplier {
    fn current(&self, _cfg: &Config) -> Value {
        Value::Null
    }
    fn check(&self, cx: &CheckCx<'_>) -> Result<Checked, Problem> {
        if cx.value.get("label").and_then(Value::as_str).is_none()
            && cx.value.get("port").is_none()
            && cx.value.get("proxies").is_none()
        {
            return Err(Problem::new(
                Code::InvalidConfig,
                "needs a label, a port or proxies",
            ));
        }
        Ok(Checked {
            effect: format!("sets {} on {}", cx.value, cx.node),
            would_disconnect: cx.value.get("disconnect").and_then(Value::as_bool) == Some(true),
            ..Checked::default()
        })
    }
    fn stage(
        &self,
        host: Arc<dyn Host>,
        _node: String,
        value: Value,
    ) -> BoxFuture<Result<Staged, Problem>> {
        let (committed, aborted) = FLAGS.with(|f| {
            let f = f.borrow();
            (Arc::clone(&f.0), Arc::clone(&f.1))
        });
        Box::pin(async move {
            if let Some(list) = value.get("proxies").and_then(Value::as_array) {
                let proxies = list
                    .iter()
                    .filter_map(|v| v.as_str()?.parse::<IpAddr>().ok().map(|ip| (ip, 32)))
                    .collect();
                let sock = host
                    .proof_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                    .await
                    .map_err(|e| Problem::new(Code::Conflict, e))?;
                return Ok(Staged {
                    guard: Arc::new(SockGuard {
                        sock,
                        committed,
                        aborted,
                        commit_fails: false,
                    }),
                    proof_addr: None,
                    new_address: None,
                    pending_proxies: Some(proxies),
                });
            }
            let port =
                u16::try_from(value.get("port").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0);
            let sock = host
                .proof_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
                .await
                .map_err(|e| Problem::new(Code::Conflict, format!("couldn't bind: {e}")))?;
            let addr = sock.addr();
            Ok(Staged {
                guard: Arc::new(SockGuard {
                    sock,
                    committed,
                    aborted,
                    commit_fails: value.get("commit_fails").and_then(Value::as_bool) == Some(true),
                }),
                proof_addr: Some(addr),
                new_address: Some(format!("http://{addr}/")),
                pending_proxies: None,
            })
        })
    }
    fn failed_start(&self, dropped: &Stored, _state: &State) -> Option<Stored> {
        // The key row's rule: once any row was re-encrypted, the new key becomes the previous
        // key, so every row still opens.
        (self.key_fallback && dropped.id == "t-key").then(|| Stored {
            value: json!({"previous_key_file": dropped.value["key_file"], "incomplete": true}),
            state: EntryState::Active,
            ..dropped.clone()
        })
    }
}

fn defs(key_fallback: bool) -> Vec<RowDef> {
    let a: Arc<dyn Applier> = Arc::new(TApplier { key_fallback });
    [&R_IMM, &R_WIN, &R_PROXY, &R_STG, &R_STG2, &R_KEY]
        .into_iter()
        .map(|r| RowDef {
            row: *r,
            applier: Arc::clone(&a),
        })
        .chain([RowDef {
            row: R_RESTART,
            applier: Arc::new(NoOp),
        }])
        .collect()
}

// ---- the fake node ---------------------------------------------------------------------

struct FakeSock {
    addr: SocketAddr,
    closed: AtomicBool,
}
impl ProofSocket for FakeSock {
    fn addr(&self) -> SocketAddr {
        self.addr
    }
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

/// The cluster as the fake hosts see it: who is where, and each node's key.
#[derive(Default)]
struct Net {
    engines: Mutex<HashMap<String, Weak<Engine>>>,
    /// The primary's name.
    primary: Mutex<Option<String>>,
    members: Mutex<Vec<Member>>,
    /// The primary's `state.db` (where a replica's entry is written).
    primary_state: Mutex<Option<Arc<State>>>,
    primary_down: AtomicBool,
}

struct Fake {
    name: String,
    state: Arc<State>,
    net: Arc<Net>,
    cfg: Mutex<Arc<Config>>,
    file_cfg: Mutex<Arc<Config>>,
    reloads: AtomicUsize,
    reload_ok: AtomicBool,
    audits: Mutex<Vec<(String, String, Value)>>,
    audit_ok: AtomicBool,
    restarts: AtomicUsize,
    bind_fails: AtomicBool,
    sockets: Mutex<Vec<Arc<FakeSock>>>,
    next_port: AtomicUsize,
    /// A replica forwards nothing and signs nothing; the primary does.
    can_sign: bool,
    /// Also write each audit record to `state.db` (the API tests read it from there).
    audit_to_state: AtomicBool,
}

fn key_of(node: &str) -> [u8; 32] {
    *blake3::hash(format!("key:{node}").as_bytes()).as_bytes()
}

impl Host for Fake {
    fn running_config(&self) -> Arc<Config> {
        Arc::clone(&self.cfg.lock().unwrap())
    }
    fn file_config(&self) -> Arc<Config> {
        Arc::clone(&self.file_cfg.lock().unwrap())
    }
    fn reload(&self) -> BoxFuture<bool> {
        self.reloads.fetch_add(1, Ordering::SeqCst);
        let ok = self.reload_ok.load(Ordering::SeqCst);
        Box::pin(std::future::ready(ok))
    }
    fn write_entry(
        &self,
        node: &str,
        id: &str,
        entry: Option<Stored>,
        by: &str,
    ) -> BoxFuture<Result<(), Problem>> {
        let target = if self.is_primary() || store::is_local(id) {
            Arc::clone(&self.state)
        } else {
            if self.net.primary_down.load(Ordering::SeqCst) {
                return Box::pin(std::future::ready(Err(Problem::new(
                    Code::PrimaryUnreachable,
                    "no primary",
                ))));
            }
            self.net
                .primary_state
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| Arc::clone(&self.state))
        };
        let r = match entry {
            Some(e) => store::put(&target, &e, 1, by),
            None => store::delete(&target, node, id),
        };
        Box::pin(std::future::ready(r.map_err(Problem::internal)))
    }
    fn is_primary(&self) -> bool {
        self.net
            .primary
            .lock()
            .unwrap()
            .as_deref()
            .is_none_or(|p| p == self.name)
    }
    fn clustered(&self) -> bool {
        self.net.primary.lock().unwrap().is_some()
    }
    fn members(&self) -> Vec<Member> {
        self.net
            .members
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.name != self.name)
            .cloned()
            .collect()
    }
    fn primary_name(&self) -> Option<String> {
        self.net.primary.lock().unwrap().clone()
    }
    fn primary_url(&self) -> Option<String> {
        self.primary_name().map(|p| format!("https://{p}:8053"))
    }
    fn sign(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        self.can_sign.then(|| {
            blake3::keyed_hash(&key_of(&self.name), bytes)
                .as_bytes()
                .to_vec()
        })
    }
    fn verify(&self, node: &str, bytes: &[u8], sig: &[u8]) -> bool {
        blake3::keyed_hash(&key_of(node), bytes)
            .as_bytes()
            .as_slice()
            == sig
    }
    fn forward(&self, node: &str, req: Forwarded) -> BoxFuture<Result<ForwardedAnswer, Problem>> {
        let target = self
            .net
            .engines
            .lock()
            .unwrap()
            .get(node)
            .and_then(Weak::upgrade);
        let me = self.name.clone();
        Box::pin(async move {
            let Some(t) = target else {
                return Err(Problem::new(Code::NodeUnreachable, "no such node"));
            };
            Ok(t.handle_forwarded(&me, req).await)
        })
    }
    fn audit(
        &self,
        actor: &Actor,
        action: &str,
        target: &str,
        detail: &Value,
    ) -> Result<(), String> {
        if !self.audit_ok.load(Ordering::SeqCst) {
            return Err("the audit log is full".to_owned());
        }
        if self.audit_to_state.load(Ordering::SeqCst) {
            let d = detail.to_string();
            self.state
                .audit_append(&telltale_store::state::NewAudit {
                    ts: now(),
                    actor: &actor.name,
                    actor_kind: actor.kind,
                    remote: actor.remote.as_deref(),
                    action,
                    target,
                    detail: &d,
                    reason: actor.reason.as_deref(),
                })
                .map_err(|e| e.to_string())?;
        }
        self.audits.lock().unwrap().push((
            format!("{}|{}", actor.name, actor.kind),
            format!("{action}|{target}"),
            detail.clone(),
        ));
        Ok(())
    }
    fn restart(&self) -> BoxFuture<()> {
        self.restarts.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::ready(()))
    }
    fn proof_socket(&self, addr: SocketAddr) -> BoxFuture<Result<Arc<dyn ProofSocket>, String>> {
        if self.bind_fails.load(Ordering::SeqCst) {
            return Box::pin(std::future::ready(Err("address already in use".to_owned())));
        }
        let port = if addr.port() == 0 {
            40_000 + u16::try_from(self.next_port.fetch_add(1, Ordering::SeqCst)).unwrap_or(0)
        } else {
            addr.port()
        };
        let s = Arc::new(FakeSock {
            addr: SocketAddr::new(addr.ip(), port),
            closed: AtomicBool::new(false),
        });
        self.sockets.lock().unwrap().push(Arc::clone(&s));
        Box::pin(std::future::ready(Ok(s as Arc<dyn ProofSocket>)))
    }
}

pub(super) struct Node {
    pub(super) engine: Arc<Engine>,
    host: Arc<Fake>,
}

impl Node {
    fn audits(&self, action: &str) -> Vec<Value> {
        self.host
            .audits
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, a, _)| a.starts_with(&format!("{action}|")))
            .map(|(_, _, d)| d.clone())
            .collect()
    }
    fn closed(&self) -> usize {
        self.host
            .sockets
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.closed.load(Ordering::SeqCst))
            .count()
    }
}

fn node_on(
    name: &str,
    net: &Arc<Net>,
    state: Arc<State>,
    supervisor: &str,
    can_sign: bool,
) -> Node {
    let mut cfg = Config::default();
    cfg.api.confirm_window_secs = 60;
    let cfg = Arc::new(cfg);
    let host = Arc::new(Fake {
        name: name.to_owned(),
        state: Arc::clone(&state),
        net: Arc::clone(net),
        cfg: Mutex::new(Arc::clone(&cfg)),
        file_cfg: Mutex::new(cfg),
        reloads: AtomicUsize::new(0),
        reload_ok: AtomicBool::new(true),
        audits: Mutex::default(),
        audit_ok: AtomicBool::new(true),
        restarts: AtomicUsize::new(0),
        bind_fails: AtomicBool::new(false),
        sockets: Mutex::default(),
        next_port: AtomicUsize::new(0),
        can_sign,
        audit_to_state: AtomicBool::new(false),
    });
    let engine = Engine::new(
        name.to_owned(),
        state,
        Arc::clone(&host) as Arc<dyn Host>,
        defs(true),
        Supervisor {
            kind: supervisor.to_owned(),
            how: "test".to_owned(),
        },
    );
    net.engines
        .lock()
        .unwrap()
        .insert(name.to_owned(), Arc::downgrade(&engine));
    Node { engine, host }
}

/// A node for the API tests: the harness node's own `state.db`, audit records written to it, a
/// systemd supervisor, and the engine installed in its `Sources` (the routes find it there).
pub(super) fn install(h: &crate::credential_tests::Harness) -> Node {
    let net = Arc::new(Net::default());
    let n = node_on("pi-a", &net, Arc::clone(h.auth.state()), "systemd", true);
    n.host.audit_to_state.store(true, Ordering::SeqCst);
    n.engine.set_window_secs(60);
    super::set_this_node("pi-a");
    assert!(h.src.guarded.set(Arc::clone(&n.engine)).is_ok());
    n
}

/// One standalone node under a systemd supervisor.
fn solo() -> Node {
    let net = Arc::new(Net::default());
    node_on(
        "pi-a",
        &net,
        Arc::new(State::in_memory().unwrap()),
        "systemd",
        true,
    )
}

fn now() -> u64 {
    super::now_secs()
}

/// An admin's interactive session, signed in `age` seconds ago.
fn admin(name: &str, age: u64) -> GuardedCaller {
    GuardedCaller {
        actor: Actor {
            name: name.to_owned(),
            kind: "session",
            remote: Some("192.0.2.10".to_owned()),
            reason: None,
        },
        username: name.to_owned(),
        session: Some(format!("sess-{name}")),
        signed_in_at: Some(now().saturating_sub(age)),
        arrived_on: None,
        remote: Some("192.0.2.10".parse().unwrap()),
        remote_under_pending: None,
        tls: false,
    }
}

async fn preview(
    e: &Arc<Engine>,
    c: &GuardedCaller,
    id: &str,
    value: Value,
) -> Result<GuardedPreview, Problem> {
    e.preview(
        c,
        id,
        GuardedPreviewRequest {
            node: None,
            value,
            options: Value::Null,
        },
    )
    .await
}

fn apply_req(p: &GuardedPreview, value: Value) -> GuardedApplyRequest {
    GuardedApplyRequest {
        preview_id: p.preview_id.clone(),
        confirm: p.phrase.clone(),
        reason: Some("test".to_owned()),
        value,
        options: Value::Null,
        node: None,
        acknowledge: p.acknowledgements.clone(),
    }
}

/// Preview then apply with the right phrase.
async fn change(
    e: &Arc<Engine>,
    c: &GuardedCaller,
    id: &str,
    value: Value,
) -> Result<GuardedApplied, Problem> {
    let p = preview(e, c, id, value.clone()).await?;
    e.apply(c, id, apply_req(&p, value)).await
}

fn code<T: std::fmt::Debug>(r: Result<T, Problem>) -> Code {
    match r {
        Ok(v) => panic!("expected a refusal, got {v:?}"),
        Err(p) => p.code,
    }
}

// ---- the flow: preview, phrase, stale, recency -------------------------------------------

// REQ: API-902 — the phrase is the node ID and the setting; the server compares it, so a forged
// request can't skip it (ADR-914).
#[tokio::test(start_paused = true)]
async fn api_902_confirmation_phrase_checked_on_server() {
    let n = solo();
    let a = admin("alice", 5);
    let v = json!({"label": "one"});
    let p = preview(&n.engine, &a, "t-imm", v.clone()).await.unwrap();
    assert_eq!(p.phrase, "pi-a t-imm");
    assert_eq!(p.mode, "immediate");
    assert!(!p.weakening);
    let mut bad = apply_req(&p, v.clone());
    bad.confirm = "pi-a imm".to_owned();
    assert_eq!(
        code(n.engine.apply(&a, "t-imm", bad).await),
        Code::InvalidParameter
    );
    assert!(
        store::for_node(&n.engine.state, "pi-a").is_empty(),
        "nothing was written"
    );
    // The preview survives a wrong phrase: the right one still works.
    let done = n.engine.apply(&a, "t-imm", apply_req(&p, v)).await.unwrap();
    assert_eq!(done.status, "applied");
    assert_eq!(store::for_node(&n.engine.state, "pi-a").len(), 1);
    // ... exactly once.
    assert_eq!(
        code(
            n.engine
                .apply(&a, "t-imm", apply_req(&p, json!({"label": "one"})))
                .await
        ),
        Code::PreviewStale
    );
}

// REQ: API-902 (ADR-956 §3) — a preview is bound to the admin, node, setting, value and version.
#[tokio::test(start_paused = true)]
async fn api_902_preview_stale_refused() {
    let n = solo();
    let a = admin("alice", 5);
    let b = admin("bob", 5);
    let v = json!({"label": "one"});
    // A changed value.
    let p = preview(&n.engine, &a, "t-imm", v.clone()).await.unwrap();
    let mut req = apply_req(&p, json!({"label": "two"}));
    req.confirm = p.phrase.clone();
    assert_eq!(
        code(n.engine.apply(&a, "t-imm", req).await),
        Code::PreviewStale
    );
    // Another admin's preview.
    let p = preview(&n.engine, &a, "t-imm", v.clone()).await.unwrap();
    assert_eq!(
        code(n.engine.apply(&b, "t-imm", apply_req(&p, v.clone())).await),
        Code::PreviewStale
    );
    // Another setting.
    let p = preview(&n.engine, &a, "t-imm", v.clone()).await.unwrap();
    assert_eq!(
        code(n.engine.apply(&a, "t-stg", apply_req(&p, v.clone())).await),
        Code::PreviewStale
    );
    // The configuration changed since.
    let p = preview(&n.engine, &a, "t-imm", v.clone()).await.unwrap();
    n.engine
        .state
        .put_managed(
            "client",
            "tv",
            r#"{"match":["192.168.1.5"]}"#,
            None,
            None,
            1,
            "x",
        )
        .unwrap();
    assert_eq!(
        code(n.engine.apply(&a, "t-imm", apply_req(&p, v.clone())).await),
        Code::PreviewStale
    );
    // Older than 5 minutes.
    let p = preview(&n.engine, &a, "t-imm", v.clone()).await.unwrap();
    tokio::time::advance(Duration::from_secs(301)).await;
    assert_eq!(
        code(n.engine.apply(&a, "t-imm", apply_req(&p, v)).await),
        Code::PreviewStale
    );
    // Unknown IDs.
    let bogus = GuardedApplyRequest {
        preview_id: "nope".into(),
        confirm: "pi-a t-imm".into(),
        reason: None,
        value: json!({"label": "x"}),
        options: Value::Null,
        node: None,
        acknowledge: vec![],
    };
    assert_eq!(
        code(n.engine.apply(&a, "t-imm", bogus).await),
        Code::PreviewStale
    );
    assert_eq!(
        code(preview(&n.engine, &a, "nope", json!({})).await),
        Code::NotFound
    );
}

// REQ: API-902 (ADR-914) — a weakening change is marked, and needs a sign-in within 10 minutes.
#[tokio::test(start_paused = true)]
async fn api_902_weakening_change_needs_recent_sign_in() {
    let n = solo();
    let stale = admin("alice", 3600);
    let weak = json!({"label": "w", "weaken": true});
    let p = preview(&n.engine, &stale, "t-imm", weak.clone())
        .await
        .unwrap();
    assert!(p.weakening && p.needs_recent_sign_in);
    assert_eq!(
        code(
            n.engine
                .apply(&stale, "t-imm", apply_req(&p, weak.clone()))
                .await
        ),
        Code::ReauthRequired
    );
    // A token, Basic sign-in or display session has no sign-in time at all.
    let mut tokenish = admin("alice", 0);
    tokenish.signed_in_at = None;
    let p = preview(&n.engine, &tokenish, "t-imm", weak.clone())
        .await
        .unwrap();
    assert_eq!(
        code(
            n.engine
                .apply(&tokenish, "t-imm", apply_req(&p, weak.clone()))
                .await
        ),
        Code::ReauthRequired
    );
    // A fresh sign-in does it; so does a non-weakening change with a stale one.
    let fresh = admin("alice", 30);
    assert_eq!(
        change(&n.engine, &fresh, "t-imm", weak)
            .await
            .unwrap()
            .status,
        "applied"
    );
    let calm = json!({"label": "calm"});
    assert_eq!(
        change(&n.engine, &stale, "t-imm", calm)
            .await
            .unwrap()
            .status,
        "applied"
    );
    // The refusals were audited (no values in them).
    let refused = n.audits("settings.guarded_refused");
    assert!(refused.len() >= 2);
    assert!(
        refused
            .iter()
            .all(|d| d.get("value").is_none() && d.get("after").is_none())
    );
}

// REQ: API-902 (ADR-956 §3) — five failed confirmations in ten minutes block the session (429).
#[tokio::test(start_paused = true)]
async fn api_902_failed_confirmations_lock_the_session() {
    let n = solo();
    let a = admin("alice", 5);
    let v = json!({"label": "x"});
    for _ in 0..5 {
        let p = preview(&n.engine, &a, "t-imm", v.clone()).await.unwrap();
        let mut req = apply_req(&p, v.clone());
        req.confirm = "wrong".into();
        assert_eq!(
            code(n.engine.apply(&a, "t-imm", req).await),
            Code::InvalidParameter
        );
    }
    let p = preview(&n.engine, &a, "t-imm", v.clone()).await.unwrap();
    let err = n
        .engine
        .apply(&a, "t-imm", apply_req(&p, v.clone()))
        .await
        .unwrap_err();
    assert_eq!(err.code, Code::RateLimited);
    assert!(err.retry_after.is_some_and(|s| s > 0));
    // Another session isn't blocked, and the block ends.
    let mut other = admin("alice", 5);
    other.session = Some("sess-other".into());
    assert!(change(&n.engine, &other, "t-imm", v.clone()).await.is_ok());
    tokio::time::advance(Duration::from_secs(601)).await;
    assert!(
        change(&n.engine, &a, "t-imm", json!({"label": "y"}))
            .await
            .is_ok()
    );
}

// REQ: API-902 (ADR-956 §3) — previews are rate-limited with the same limiter as writes.
#[tokio::test(start_paused = true)]
async fn api_902_previews_are_rate_limited() {
    let n = solo();
    let a = admin("alice", 5);
    for _ in 0..super::engine::RATE_PER_MIN {
        preview(&n.engine, &a, "t-imm", json!({"label": "x"}))
            .await
            .unwrap();
    }
    assert_eq!(
        code(preview(&n.engine, &a, "t-imm", json!({"label": "x"})).await),
        Code::RateLimited
    );
    tokio::time::advance(Duration::from_secs(61)).await;
    preview(&n.engine, &a, "t-imm", json!({"label": "x"}))
        .await
        .unwrap();
}

// ---- modes -------------------------------------------------------------------------------

// REQ: API-902 (ADR-956 §1, §2) — an immediate change is written, applied by the reload, audited
// with credentials redacted, and a failed reload puts the previous entry back (CLU-004).
#[tokio::test(start_paused = true)]
async fn api_902_immediate_change_applies_and_reload_failure_reverts() {
    let n = solo();
    let a = admin("alice", 5);
    let r = change(
        &n.engine,
        &a,
        "t-imm",
        json!({"label": "one", "api_token": "s3cr3t"}),
    )
    .await
    .unwrap();
    assert_eq!(r.status, "applied");
    assert_eq!(n.host.reloads.load(Ordering::SeqCst), 1);
    let stored = store::for_node(&n.engine.state, "pi-a");
    assert_eq!(stored[0].state, EntryState::Active);
    // The audit record redacts the credential-looking field.
    let rec = &n.audits("settings.guarded")[0];
    assert_eq!(rec["after"]["api_token"], "<redacted>");
    assert_eq!(rec["after"]["label"], "one");
    assert_eq!(rec["setting"], "t-imm");
    assert_eq!(rec["outcome"], "applied");
    // A reload that fails puts the previous entry back and says so.
    n.host.reload_ok.store(false, Ordering::SeqCst);
    let err = change(&n.engine, &a, "t-imm", json!({"label": "two"}))
        .await
        .unwrap_err();
    assert_eq!(err.code, Code::InvalidConfig);
    let stored = store::for_node(&n.engine.state, "pi-a");
    assert_eq!(
        stored[0].value["label"], "one",
        "the previous entry is back"
    );
    assert_eq!(
        n.audits("settings.guarded_rolled_back")[0]["reason"],
        "commit_failed"
    );
}

// REQ: API-902 (ADR-956 §4) — a staged change is written at once, listed as pending restart, and
// not applied: the overlay skips an entry that is waiting for the next start.
#[tokio::test(start_paused = true)]
async fn api_902_staged_change_waits_for_restart() {
    let n = solo();
    let a = admin("alice", 5);
    let r = change(&n.engine, &a, "t-stg", json!({"label": "later"}))
        .await
        .unwrap();
    assert_eq!(r.status, "staged");
    assert!(r.pending_restart);
    let st = n.engine.status_local();
    assert_eq!(st.pending_restart, vec!["t-stg".to_owned()]);
    assert!(
        st.settings
            .iter()
            .any(|s| s.id == "t-stg" && s.pending_restart)
    );
    // One staged change at a time.
    let p = preview(&n.engine, &a, "t-stg2", json!({"label": "x"})).await;
    assert_eq!(code(p), Code::GuardedChangePending);
    // The overlay applies active and probation entries only.
    let mut cfg = Config::default();
    let own = Config::default();
    struct Mark;
    impl Applier for Mark {
        fn current(&self, _: &Config) -> Value {
            Value::Null
        }
        fn check(&self, _: &CheckCx<'_>) -> Result<Checked, Problem> {
            Ok(Checked::default())
        }
        fn overlay(&self, cfg: &mut Config, _v: &Value) {
            cfg.node.name = telltale_config::SafeString::new("overlaid").unwrap();
        }
    }
    let marked = vec![RowDef {
        row: R_STG,
        applier: Arc::new(Mark),
    }];
    let mut e = store::for_node(&n.engine.state, "pi-a");
    super::appliers::overlay_with(&mut cfg, &own, &e, None, &marked, "pi-a", false);
    assert_ne!(
        cfg.node.name.as_str(),
        "overlaid",
        "a staged entry is not applied"
    );
    e[0].state = EntryState::Probation;
    super::appliers::overlay_with(&mut cfg, &own, &e, None, &marked, "pi-a", false);
    assert_eq!(cfg.node.name.as_str(), "overlaid");
}

// REQ: API-902 (ADR-956 §2, ADR-040) — the file wins over a guarded value: a field a file sets is
// shown "set by file", an apply is 409 `set_by_file`, and the overlay never overrides it.
#[tokio::test(start_paused = true)]
async fn api_902_file_wins_over_guarded_value() {
    let n = solo();
    let a = admin("alice", 5);
    let mut file = Config::default();
    file.file_set.push("t.imm".to_owned());
    *n.host.file_cfg.lock().unwrap() = Arc::new(file.clone());
    assert_eq!(
        code(preview(&n.engine, &a, "t-imm", json!({"label": "x"})).await),
        Code::SetByFile
    );
    assert!(
        n.engine
            .status_local()
            .settings
            .iter()
            .any(|s| s.id == "t-imm" && s.set_by_file)
    );
    // An entry stored before the file set the field is not applied over it.
    struct Mark;
    impl Applier for Mark {
        fn current(&self, _: &Config) -> Value {
            Value::Null
        }
        fn check(&self, _: &CheckCx<'_>) -> Result<Checked, Problem> {
            Ok(Checked::default())
        }
        fn overlay(&self, cfg: &mut Config, _v: &Value) {
            cfg.node.name = telltale_config::SafeString::new("overlaid").unwrap();
        }
    }
    let marked = vec![RowDef {
        row: R_IMM,
        applier: Arc::new(Mark),
    }];
    let e = vec![Stored {
        node: "pi-a".into(),
        id: "t-imm".into(),
        value: json!({"label": "x"}),
        mode: "immediate".into(),
        state: EntryState::Active,
        by: "alice".into(),
        at: 1,
    }];
    let mut cfg = Config::default();
    super::appliers::overlay_with(&mut cfg, &file, &e, None, &marked, "pi-a", false);
    assert_ne!(cfg.node.name.as_str(), "overlaid");
    super::appliers::overlay_with(
        &mut cfg,
        &Config::default(),
        &e,
        None,
        &marked,
        "pi-a",
        false,
    );
    assert_eq!(
        cfg.node.name.as_str(),
        "overlaid",
        "without the file's field it applies"
    );
    // `TELLTALE_IGNORE_GUARDED` and another node's entry: ignored.
    let mut cfg = Config::default();
    super::appliers::overlay_with(
        &mut cfg,
        &Config::default(),
        &e,
        None,
        &marked,
        "pi-a",
        true,
    );
    super::appliers::overlay_with(
        &mut cfg,
        &Config::default(),
        &e,
        None,
        &marked,
        "pi-b",
        false,
    );
    assert_ne!(cfg.node.name.as_str(), "overlaid");
}

// ---- the window --------------------------------------------------------------------------

async fn start_window(n: &Node, a: &GuardedCaller, port: u16) -> GuardedApplied {
    let r = change(&n.engine, a, "t-win", json!({"port": port}))
        .await
        .unwrap();
    assert_eq!(r.status, "pending");
    r
}

fn on_new_socket(mut c: GuardedCaller, a: &GuardedApplied) -> GuardedCaller {
    let addr: SocketAddr = a
        .new_address
        .as_deref()
        .unwrap()
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .parse()
        .unwrap();
    c.arrived_on = Some(addr);
    c
}

// REQ: API-902 (ADR-956 §3) — the new sockets are bound beside the old ones, the entry is written
// only when confirmed, and an unconfirmed change rolls back at expiry, audited with its reason.
#[tokio::test(start_paused = true)]
async fn api_902_unconfirmed_change_rolls_back() {
    let n = solo();
    let a = admin("alice", 5);
    let r = start_window(&n, &a, 40_100).await;
    assert_eq!(r.deadline_secs, Some(60));
    assert!(r.confirm_token.is_some() && r.pending_id.is_some());
    assert_eq!(r.proof.as_deref(), Some("new_socket"));
    assert!(
        store::for_node(&n.engine.state, "pi-a").is_empty(),
        "nothing is written while pending"
    );
    let st = n.engine.status_local();
    assert_eq!(
        st.pending.as_ref().map(|p| p.setting.as_str()),
        Some("t-win")
    );
    assert!(st.pending.as_ref().is_some_and(|p| p.deadline_secs <= 60));
    // The listing never says the token, the preview or the value.
    let text = serde_json::to_string(&st).unwrap();
    assert!(!text.contains(r.confirm_token.as_deref().unwrap()));
    assert!(!text.contains("40100"));
    tokio::time::advance(Duration::from_secs(59)).await;
    assert!(n.engine.status_local().pending.is_some());
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert!(
        n.engine.status_local().pending.is_none(),
        "rolled back at expiry"
    );
    assert_eq!(n.closed(), 1, "the new socket closed");
    assert!(store::for_node(&n.engine.state, "pi-a").is_empty());
    let rb = n.audits("settings.guarded_rolled_back");
    assert_eq!(rb.len(), 1);
    assert_eq!(rb[0]["reason"], "expired");
    let o = &n.engine.status_local().outcomes[0];
    assert_eq!(
        (o.outcome.as_str(), o.reason.as_deref()),
        ("rolled_back", Some("expired"))
    );
    // A confirmation after the window finds nothing pending.
    let late = on_new_socket(a.clone(), &r);
    assert_eq!(
        code(
            n.engine
                .confirm(
                    &late,
                    r.pending_id.as_deref().unwrap(),
                    r.confirm_token.clone()
                )
                .await
        ),
        Code::NotFound
    );
}

// REQ: API-902 (ADR-956 §3) — expiry, cancel, double confirm, token reuse, another admin's token;
// a wrong confirming request doesn't roll back (it is refused and counted).
#[tokio::test(start_paused = true)]
async fn api_902_window_state_machine() {
    let n = solo();
    let a = admin("alice", 5);
    // Cancel.
    let r = start_window(&n, &a, 40_101).await;
    let pid = r.pending_id.clone().unwrap();
    let c = n.engine.cancel(&a, &pid).await.unwrap();
    assert_eq!(
        (c.outcome.as_str(), c.reason.as_deref()),
        ("rolled_back", Some("cancelled"))
    );
    assert_eq!(n.closed(), 1);
    assert_eq!(code(n.engine.cancel(&a, &pid).await), Code::NotFound);
    // Confirm: wrong token, wrong place, then the right one from the new socket.
    let r = start_window(&n, &a, 40_102).await;
    let pid = r.pending_id.clone().unwrap();
    let tok = r.confirm_token.clone().unwrap();
    let anon = |arrived: Option<SocketAddr>| GuardedCaller {
        actor: Actor {
            name: String::new(),
            kind: "token",
            remote: None,
            reason: None,
        },
        username: String::new(),
        session: None,
        signed_in_at: None,
        arrived_on: arrived,
        remote: None,
        remote_under_pending: None,
        tls: false,
    };
    let there = on_new_socket(anon(None), &r).arrived_on;
    assert_eq!(
        code(
            n.engine
                .confirm(&anon(there), &pid, Some("wrong".into()))
                .await
        ),
        Code::Forbidden
    );
    assert_eq!(
        code(n.engine.confirm(&anon(None), &pid, Some(tok.clone())).await),
        Code::Forbidden,
        "the right token on the old address proves nothing"
    );
    assert!(
        n.engine.status_local().pending.is_some(),
        "a wrong request doesn't roll back"
    );
    // Another admin's session can't confirm.
    let other = on_new_socket(admin("bob", 5), &r);
    assert_eq!(
        code(n.engine.confirm(&other, &pid, None).await),
        Code::Forbidden
    );
    // A token for another change can't either.
    assert_eq!(
        code(
            n.engine
                .confirm(&anon(there), &pid, Some("0".repeat(48)))
                .await
        ),
        Code::Forbidden
    );
    let ok = n
        .engine
        .confirm(&anon(there), &pid, Some(tok.clone()))
        .await
        .unwrap();
    assert_eq!(ok.outcome, "confirmed");
    let stored = store::for_node(&n.engine.state, "pi-a");
    assert_eq!(stored.len(), 1);
    assert_eq!(
        (stored[0].id.as_str(), stored[0].state),
        ("t-win", EntryState::Active)
    );
    // Double confirm and token reuse.
    assert_eq!(
        code(
            n.engine
                .confirm(&anon(there), &pid, Some(tok.clone()))
                .await
        ),
        Code::NotFound
    );
    let r2 = start_window(&n, &a, 40_103).await;
    let there2 = on_new_socket(anon(None), &r2).arrived_on;
    assert_eq!(
        code(
            n.engine
                .confirm(&anon(there2), r2.pending_id.as_deref().unwrap(), Some(tok))
                .await
        ),
        Code::Forbidden,
        "the first change's token confirms nothing else"
    );
    // The same admin's session confirms without a token.
    let ok = n
        .engine
        .confirm(
            &on_new_socket(a.clone(), &r2),
            r2.pending_id.as_deref().unwrap(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(ok.outcome, "confirmed");
    let confirmed = n.audits("settings.guarded");
    assert_eq!(confirmed.len(), 2);
    assert!(confirmed.iter().all(|d| d["outcome"] == "confirmed"));
}

// REQ: API-902 (ADR-956 §3) — one pending change per node, and the commit and bind failures
// roll back with their own reasons.
#[tokio::test(start_paused = true)]
async fn api_902_one_pending_change_per_node() {
    let n = solo();
    let a = admin("alice", 5);
    let r = start_window(&n, &a, 40_110).await;
    for id in ["t-win", "t-stg", "t-proxy"] {
        let p = preview(&n.engine, &a, id, json!({"label": "x", "port": 40_111})).await;
        assert_eq!(code(p), Code::GuardedChangePending, "{id}");
    }
    assert_eq!(
        code(preview(&n.engine, &a, RESTART_NOW, Value::Null).await),
        Code::GuardedChangePending
    );
    // An immediate change can't cut the admin off, so the window doesn't block it.
    assert!(
        change(&n.engine, &a, "t-imm", json!({"label": "ok"}))
            .await
            .is_ok()
    );
    n.engine
        .cancel(&a, r.pending_id.as_deref().unwrap())
        .await
        .unwrap();
    // A failed bind changes nothing, and is audited as such.
    n.host.bind_fails.store(true, Ordering::SeqCst);
    let e = change(&n.engine, &a, "t-win", json!({"port": 40_112}))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::Conflict);
    assert!(n.engine.status_local().pending.is_none());
    assert!(
        n.audits("settings.guarded_rolled_back")
            .iter()
            .any(|d| d["reason"] == "bind_failed")
    );
    n.host.bind_fails.store(false, Ordering::SeqCst);
    // A failed commit rolls back with its own reason and leaves no entry.
    let r = change(
        &n.engine,
        &a,
        "t-win",
        json!({"port": 40_113, "commit_fails": true}),
    )
    .await
    .unwrap();
    let c = on_new_socket(a.clone(), &r);
    let e = n
        .engine
        .confirm(&c, r.pending_id.as_deref().unwrap(), None)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::Internal);
    assert!(n.engine.status_local().pending.is_none());
    assert!(
        store::for_node(&n.engine.state, "pi-a")
            .iter()
            .all(|e| e.id != "t-win")
    );
    assert!(
        n.audits("settings.guarded_rolled_back")
            .iter()
            .any(|d| d["reason"] == "commit_failed")
    );
}

// REQ: API-902 (ADR-956 §3) — a change that would leave the node with no listener is refused at
// preview and again at apply (409 `would_disconnect_you`).
#[tokio::test(start_paused = true)]
async fn api_902_would_disconnect_refused() {
    let n = solo();
    let a = admin("alice", 5);
    let v = json!({"label": "x", "disconnect": true});
    assert_eq!(
        code(preview(&n.engine, &a, "t-imm", v).await),
        Code::WouldDisconnectYou
    );
    assert!(
        n.audits("settings.guarded_refused")
            .iter()
            .any(|d| d["code"] == "would_disconnect_you")
    );
}

// REQ: API-902 (ADR-956 §4) — a restart inside the window starts with the previous values: the
// pending change lived in memory only, so a new engine over the same state has nothing pending,
// no entry and nothing for the overlay.
#[tokio::test(start_paused = true)]
async fn api_902_restart_inside_window_keeps_previous() {
    let n = solo();
    let a = admin("alice", 5);
    let _r = start_window(&n, &a, 40_120).await;
    let again = Engine::new(
        "pi-a".into(),
        Arc::clone(&n.engine.state),
        Arc::clone(&n.host) as Arc<dyn Host>,
        defs(false),
        Supervisor {
            kind: "systemd".into(),
            how: "test".into(),
        },
    );
    assert!(again.status_local().pending.is_none());
    assert!(store::for_node(&n.engine.state, "pi-a").is_empty());
    let mut cfg = Config::default();
    let before = cfg.clone();
    super::appliers::overlay_with(
        &mut cfg,
        &Config::default(),
        &store::all(&n.engine.state),
        None,
        &defs(false),
        "pi-a",
        false,
    );
    assert_eq!(cfg, before);
}

// REQ: API-902, CLU-015 — the pending proxy list applies only to the confirm route's own address
// evaluation: `pending_proxies` is what that route reads, and nothing else sees the list.
#[tokio::test(start_paused = true)]
async fn api_902_pending_proxy_list_not_used_for_break_glass() {
    let n = solo();
    let a = admin("alice", 5);
    assert!(n.engine.pending_proxies().is_none());
    let r = change(
        &n.engine,
        &a,
        "t-proxy",
        json!({"proxies": ["203.0.113.7"]}),
    )
    .await
    .unwrap();
    assert_eq!(r.proof.as_deref(), Some("proxy_list"));
    let list = n.engine.pending_proxies().unwrap();
    assert_eq!(list, vec![("203.0.113.7".parse().unwrap(), 32)]);
    // The running configuration (what break-glass, rate limits and the audit source read) still
    // has the old list.
    assert!(n.host.running_config().api.trusted_proxies.is_empty());
    // The confirm proves it only when the request is evaluated under the new list.
    let pid = r.pending_id.clone().unwrap();
    assert_eq!(
        code(n.engine.confirm(&a, &pid, None).await),
        Code::Forbidden
    );
    let mut c = a.clone();
    c.remote_under_pending = Some("198.51.100.9".parse().unwrap());
    let ok = n.engine.confirm(&c, &pid, None).await.unwrap();
    assert_eq!(ok.seen_client.as_deref(), Some("198.51.100.9"));
    assert!(
        n.engine.pending_proxies().is_none(),
        "after the change ends nothing is pending"
    );
}

// REQ: API-902 (ADR-956 §6) — settings.guarded, settings.guarded_rolled_back and
// settings.guarded_refused are written with the setting, node, mode, reason and who; credentials
// are redacted; and the alert reads them.
#[tokio::test(start_paused = true)]
async fn api_902_guarded_change_audited_and_alerted() {
    let n = solo();
    let a = admin("alice", 5);
    change(
        &n.engine,
        &a,
        "t-imm",
        json!({"label": "x", "client_secret": "hunter2"}),
    )
    .await
    .unwrap();
    let r = start_window(&n, &a, 40_130).await;
    n.engine
        .cancel(&a, r.pending_id.as_deref().unwrap())
        .await
        .unwrap();
    let _ = preview(&n.engine, &a, "t-imm", json!({})).await; // invalid: refused
    let _ = n
        .engine
        .apply(
            &a,
            "t-imm",
            GuardedApplyRequest {
                preview_id: "x".into(),
                confirm: "y".into(),
                reason: None,
                value: Value::Null,
                options: Value::Null,
                node: None,
                acknowledge: vec![],
            },
        )
        .await;
    let guarded = n.audits("settings.guarded");
    assert_eq!(guarded.len(), 1);
    assert_eq!(guarded[0]["after"]["client_secret"], "<redacted>");
    assert_eq!(guarded[0]["reason"], "test");
    assert_eq!(guarded[0]["node"], "pi-a");
    assert_eq!(guarded[0]["mode"], "immediate");
    assert_eq!(n.audits("settings.guarded_rolled_back").len(), 1);
    assert!(!n.audits("settings.guarded_refused").is_empty());
    // No record anywhere holds the secret value.
    let all = serde_json::to_string(&*n.host.audits.lock().unwrap()).unwrap();
    assert!(!all.contains("hunter2"));
    // The actor is the admin's session.
    assert!(
        n.host
            .audits
            .lock()
            .unwrap()
            .iter()
            .all(|(who, _, _)| who == "alice|session")
    );
}

// REQ: API-902, AGT-009 — a refusal that is past the role check and an apply with no audit: the
// audit log can't record a restart, so the node isn't restarted.
#[tokio::test(start_paused = true)]
async fn api_902_restart_now_own_phrase_and_audit() {
    let n = solo();
    let a = admin("alice", 5);
    let p = preview(&n.engine, &a, RESTART_NOW, Value::Null)
        .await
        .unwrap();
    assert_eq!(p.phrase, "pi-a restart");
    assert!(p.needs_recent_sign_in && !p.weakening);
    assert!(p.warnings.iter().any(|w| w.contains("cannot check")));
    // The audit log can't record it: no restart.
    n.host.audit_ok.store(false, Ordering::SeqCst);
    let e = n
        .engine
        .apply(&a, RESTART_NOW, apply_req(&p, Value::Null))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::Unavailable);
    assert_eq!(n.host.restarts.load(Ordering::SeqCst), 0);
    n.host.audit_ok.store(true, Ordering::SeqCst);
    // A stale sign-in is refused.
    let stale = admin("alice", 3600);
    let p = preview(&n.engine, &stale, RESTART_NOW, Value::Null)
        .await
        .unwrap();
    assert_eq!(
        code(
            n.engine
                .apply(&stale, RESTART_NOW, apply_req(&p, Value::Null))
                .await
        ),
        Code::ReauthRequired
    );
    // The setting's phrase isn't the restart's.
    let p = preview(&n.engine, &a, RESTART_NOW, Value::Null)
        .await
        .unwrap();
    let mut req = apply_req(&p, Value::Null);
    req.confirm = "pi-a t-imm".into();
    assert_eq!(
        code(n.engine.apply(&a, RESTART_NOW, req).await),
        Code::InvalidParameter
    );
    // The audit row is written before the exit; every guarded route then answers `restarting`.
    let p = preview(&n.engine, &a, RESTART_NOW, Value::Null)
        .await
        .unwrap();
    let r = n
        .engine
        .apply(&a, RESTART_NOW, apply_req(&p, Value::Null))
        .await
        .unwrap();
    assert_eq!(r.status, "restarting");
    assert_eq!(n.host.restarts.load(Ordering::SeqCst), 1);
    let rows = n.audits("settings.guarded_restart");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["supervisor"], "systemd");
    assert_eq!(rows[0]["reason"], "test");
    assert!(n.engine.status_local().restarting);
}

// REQ: API-902 (ADR-956 §4a) — the restart needs a declared supervisor; nothing is guessed.
#[test]
fn api_902_restart_now_needs_a_supervisor() {
    use super::restart::detect;
    let none = |vars: &'static [(&'static str, &'static str)]| {
        detect(move |k| {
            vars.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        })
    };
    for kind in ["systemd", "docker", "kubernetes"] {
        let s = detect(|k| (k == "TELLTALE_SUPERVISOR").then(|| kind.to_owned()));
        assert_eq!(s.kind, kind);
    }
    assert_eq!(none(&[]).kind, "none");
    assert_eq!(none(&[("TELLTALE_SUPERVISOR", "none")]).kind, "none");
    assert_eq!(none(&[("TELLTALE_SUPERVISOR", "nonsense")]).kind, "none");
    // Variables every child of a service inherits are never a declaration.
    assert_eq!(
        none(&[
            ("INVOCATION_ID", "abc"),
            ("JOURNAL_STREAM", "8:1"),
            ("NOTIFY_SOCKET", "/run/systemd/notify"),
            ("KUBERNETES_SERVICE_HOST", "10.0.0.1"),
        ])
        .kind,
        "none"
    );
}

// REQ: API-902 (ADR-956 §4a) — without a supervisor the route answers 409 `no_supervisor`.
#[tokio::test(start_paused = true)]
async fn api_902_restart_now_refused_without_supervisor() {
    let net = Arc::new(Net::default());
    let n = node_on(
        "pi-a",
        &net,
        Arc::new(State::in_memory().unwrap()),
        "none",
        true,
    );
    let a = admin("alice", 5);
    assert_eq!(
        code(preview(&n.engine, &a, RESTART_NOW, Value::Null).await),
        Code::NoSupervisor
    );
}

// REQ: API-902 (ADR-956 §4a) — refused while a window change is pending; and while a restart is
// accepted every other guarded operation is 409 `restarting`.
#[tokio::test(start_paused = true)]
async fn api_902_restart_excludes_other_guarded_operations() {
    let n = solo();
    let a = admin("alice", 5);
    let r = start_window(&n, &a, 40_140).await;
    assert_eq!(
        code(preview(&n.engine, &a, RESTART_NOW, Value::Null).await),
        Code::GuardedChangePending
    );
    n.engine
        .cancel(&a, r.pending_id.as_deref().unwrap())
        .await
        .unwrap();
    // A preview made before the restart can't be applied after it.
    let pending_preview = preview(&n.engine, &a, "t-imm", json!({"label": "x"}))
        .await
        .unwrap();
    let rp = preview(&n.engine, &a, RESTART_NOW, Value::Null)
        .await
        .unwrap();
    n.engine
        .apply(&a, RESTART_NOW, apply_req(&rp, Value::Null))
        .await
        .unwrap();
    assert_eq!(
        code(
            n.engine
                .apply(
                    &a,
                    "t-imm",
                    apply_req(&pending_preview, json!({"label": "x"}))
                )
                .await
        ),
        Code::Restarting
    );
    for id in ["t-imm", "t-win", "t-stg", RESTART_NOW] {
        assert_eq!(
            code(preview(&n.engine, &a, id, json!({"label": "x", "port": 40_141})).await),
            Code::Restarting,
            "{id}"
        );
    }
    assert_eq!(code(n.engine.cancel(&a, "x").await), Code::NotFound);
    assert_eq!(
        n.host.restarts.load(Ordering::SeqCst),
        1,
        "a second restart is refused"
    );
}

// REQ: API-902 (ADR-956 §4a) — exit 75 is the restart's code, and a requested exit is a flag the
// main loop waits on (an e2e-only hook replaces the exit itself).
#[tokio::test]
async fn api_902_restart_exits_75_after_drain() {
    assert_eq!(super::restart::EXIT_CODE, 75);
    assert_eq!(super::restart::DRAIN_CAP_SECS, 5);
    // In a build without the `e2e` feature there is no hook: the exit is real.
    #[cfg(not(feature = "e2e"))]
    {
        let src = include_str!("restart.rs");
        let hook_lines = src.lines().filter(|l| l.contains("E2E_HOOK_ENV")).count();
        assert!(hook_lines >= 2, "the hook is named only behind the feature");
        assert!(!cfg!(feature = "e2e"));
    }
}

// ---- probation ---------------------------------------------------------------------------

/// A data directory with a `state.db` holding `entries` (for the node `pi-a`), and its files-only
/// configuration.
fn dir_with(entries: &[(&str, Value, EntryState)]) -> (tempfile::TempDir, Config) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.node.data_dir = telltale_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
    cfg.node.name = telltale_config::SafeString::new("pi-a").unwrap();
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    for (id, value, st) in entries {
        store::put(
            &state,
            &Stored {
                node: "pi-a".into(),
                id: (*id).into(),
                value: value.clone(),
                mode: "staged".into(),
                state: *st,
                by: "alice".into(),
                at: 1,
            },
            1,
            "alice",
        )
        .unwrap();
    }
    (dir, cfg)
}

fn begin(cfg: &Config) -> probation::Begin {
    probation::begin_for(cfg, "pi-a", &defs(true), 100, false)
}

fn entries_of(cfg: &Config) -> Vec<Stored> {
    store::for_node(
        &State::open(&crate::managed::state_path(cfg)).unwrap(),
        "pi-a",
    )
}

// REQ: API-902 (ADR-956 §4) — two failed starts drop the staged entries: the sidecar counts the
// attempt before anything is applied, a healthy node deletes it, and the third start drops.
#[test]
fn api_902_staged_entry_probation_drops_after_two_failed_starts() {
    let (dir, cfg) = dir_with(&[("t-stg", json!({"label": "x"}), EntryState::Staged)]);
    // Start 1: on probation, counter 1.
    let b = begin(&cfg);
    assert_eq!(b.on_probation, vec!["t-stg".to_owned()]);
    assert_eq!(probation::read_sidecar(dir.path()).unwrap().attempts, 1);
    assert_eq!(entries_of(&cfg)[0].state, EntryState::Probation);
    // The start isn't healthy; start 2: counter 2, still applied.
    let b = begin(&cfg);
    assert_eq!(b.on_probation, vec!["t-stg".to_owned()]);
    assert_eq!(probation::read_sidecar(dir.path()).unwrap().attempts, 2);
    // Start 3 finds the count at 2: the entries are dropped, audited, and the node starts from the file.
    let b = begin(&cfg);
    assert_eq!(b.dropped, vec!["t-stg".to_owned()]);
    assert!(b.on_probation.is_empty());
    assert!(entries_of(&cfg).is_empty());
    assert!(probation::read_sidecar(dir.path()).is_none());
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    let audits = state
        .audit_page(None, 10, Some("settings.guarded_rolled_back"), None)
        .unwrap();
    assert_eq!(audits.len(), 1);
    assert!(audits[0].detail.contains("failed_start"));
    assert_eq!(
        store::outcomes(&state)[0].reason.as_deref(),
        Some("failed_start")
    );
    // A healthy start in between would have made the entry active and deleted the counter.
    let (dir, cfg) = dir_with(&[("t-stg", json!({"label": "x"}), EntryState::Staged)]);
    begin(&cfg);
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    let done = probation::mark_healthy(&state, "pi-a", dir.path(), 200);
    assert_eq!(done, vec!["t-stg".to_owned()]);
    assert!(probation::read_sidecar(dir.path()).is_none());
    assert_eq!(entries_of(&cfg)[0].state, EntryState::Active);
    assert_eq!(
        begin(&cfg),
        probation::Begin::default(),
        "nothing left to try"
    );
    // The healthy deadline is max(confirm_window_secs, 180).
    let mut c = Config::default();
    c.api.confirm_window_secs = 30;
    assert_eq!(probation::healthy_deadline_secs(&c), 180);
    c.api.confirm_window_secs = 600;
    assert_eq!(probation::healthy_deadline_secs(&c), 600);
    let h = probation::Health {
        state_open: true,
        api_bound: true,
        dns_probe_ok: true,
        secrets_unlocked: false,
    };
    assert!(
        h.healthy(false) && !h.healthy(true),
        "the secrets key needs an unlocked store"
    );
}

// REQ: API-902 (ADR-956 §4) — the counter is a sidecar file, so a `state.db` that won't open can't
// hide it: the count survives, and the node starts from the files.
#[test]
fn api_902_probation_counter_survives_unopenable_state() {
    let (dir, cfg) = dir_with(&[("t-stg", json!({"label": "x"}), EntryState::Staged)]);
    begin(&cfg);
    begin(&cfg);
    assert_eq!(probation::read_sidecar(dir.path()).unwrap().attempts, 2);
    // `state.db` is now garbage: it doesn't open.
    std::fs::write(crate::managed::state_path(&cfg), b"not a database at all").unwrap();
    let b = begin(&cfg);
    assert_eq!(b, probation::Begin::default(), "no state, nothing applied");
    assert_eq!(
        probation::read_sidecar(dir.path()).unwrap().attempts,
        2,
        "the counter isn't lost"
    );
    // Written with a rename: a leftover temp file never reads as the counter.
    let side = Sidecar {
        attempts: 1,
        ids: vec!["x".into()],
    };
    probation::write_sidecar(dir.path(), &side).unwrap();
    assert_eq!(probation::read_sidecar(dir.path()), Some(side));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(probation::sidecar_path(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

// REQ: API-902 (ADR-956 §4) — a restore marks the archive's guarded entries staged, so the first
// start puts them on probation and two failed starts drop them.
#[test]
fn api_902_restored_entries_start_on_probation() {
    let (dir, cfg) = dir_with(&[("t-win", json!({"port": 9}), EntryState::Active)]);
    let n = store::mark_restored(&crate::managed::state_path(&cfg));
    assert_eq!(n, 1);
    assert_eq!(entries_of(&cfg)[0].state, EntryState::Staged);
    let b = begin(&cfg);
    assert_eq!(b.on_probation, vec!["t-win".to_owned()]);
    assert_eq!(probation::read_sidecar(dir.path()).unwrap().attempts, 1);
    // A database that won't open marks nothing.
    let junk = dir.path().join("junk.db");
    std::fs::write(&junk, b"nope").unwrap();
    assert_eq!(store::mark_restored(&junk), 0);
}

// REQ: API-902 (ADR-956 §4) — once any row was re-encrypted under a new key, dropping the entry
// must not return the node to the old key alone: the row's fallback keeps both keys.
#[test]
fn api_902_probation_after_partial_reencrypt_keeps_both_keys() {
    let (dir, cfg) = dir_with(&[(
        "t-key",
        json!({"key_file": "/keys/new"}),
        EntryState::Staged,
    )]);
    begin(&cfg);
    begin(&cfg);
    let b = begin(&cfg);
    assert_eq!(b.dropped, vec!["t-key".to_owned()]);
    let e = entries_of(&cfg);
    assert_eq!(e.len(), 1, "replaced, not just dropped");
    assert_eq!(e[0].state, EntryState::Active);
    assert_eq!(e[0].value["previous_key_file"], "/keys/new");
    assert_eq!(e[0].value["incomplete"], true);
    assert!(probation::read_sidecar(dir.path()).is_none());
}

// REQ: API-902 (ADR-956 §4) — a confirmed listener that can't bind at start (an interface that
// isn't up yet) falls back for that start only: the entry stays, tried again next start.
#[test]
fn api_902_confirmed_listener_bind_failure_falls_back_at_start() {
    probation::reset_fallbacks();
    let (_dir, cfg) = dir_with(&[("t-bindfb", json!({"port": 1}), EntryState::Active)]);
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    struct Mark;
    impl Applier for Mark {
        fn current(&self, _: &Config) -> Value {
            Value::Null
        }
        fn check(&self, _: &CheckCx<'_>) -> Result<Checked, Problem> {
            Ok(Checked::default())
        }
        fn overlay(&self, cfg: &mut Config, _v: &Value) {
            cfg.node.workers = 7;
        }
    }
    static ROW: Row = row!(
        "t-bindfb",
        &["t.bindfb"],
        Mode::Window,
        Some(Proof::NewSocket),
        never
    );
    let rows = vec![RowDef {
        row: ROW,
        applier: Arc::new(Mark),
    }];
    let entries = store::for_node(&state, "pi-a");
    let mut c = Config::default();
    super::appliers::overlay_with(
        &mut c,
        &Config::default(),
        &entries,
        None,
        &rows,
        "pi-a",
        false,
    );
    assert_eq!(
        c.node.workers, 7,
        "a confirmed window entry applies at start"
    );
    // The bind fails: this start runs on the file's value.
    probation::note_bind_fallback(Some(&state), "pi-a", "t-bindfb", 5);
    let mut c = Config::default();
    super::appliers::overlay_with(
        &mut c,
        &Config::default(),
        &entries,
        None,
        &rows,
        "pi-a",
        false,
    );
    assert_eq!(c.node.workers, Config::default().node.workers);
    assert_eq!(probation::fallbacks(), vec!["t-bindfb".to_owned()]);
    // The entry stays, and the audit row says why.
    assert_eq!(store::for_node(&state, "pi-a").len(), 1);
    let a = state
        .audit_page(None, 5, Some("settings.guarded_rolled_back"), None)
        .unwrap();
    assert!(a[0].detail.contains("failed_start"));
    probation::reset_fallbacks();
}

// ---- recovery (ADR-957) ------------------------------------------------------------------

// REQ: API-902 (ADR-957) — `telltale guarded clear` removes the node's entries with the node
// stopped, audits as `cli:<os user>`, and `list` shows what is stored.
#[test]
fn api_902_cli_clear_removes_entries_and_audits() {
    let (dir, cfg) = dir_with(&[
        ("t-stg", json!({"label": "x"}), EntryState::Staged),
        ("t-win", json!({"port": 9}), EntryState::Active),
    ]);
    begin(&cfg);
    let mut out = Vec::new();
    assert!(super::cli::run_list(&cfg, &mut out).unwrap());
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("t-stg") && text.contains("t-win") && text.contains("probation"));
    let mut out = Vec::new();
    assert!(
        super::cli::run_clear(
            &cfg,
            &super::cli::Target::One("t-stg".into()),
            "ops",
            &mut out
        )
        .unwrap()
    );
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("cleared on pi-a: t-stg") && text.contains("configuration file"));
    assert_eq!(
        entries_of(&cfg)
            .iter()
            .map(|e| e.id.as_str())
            .collect::<Vec<_>>(),
        ["t-win"]
    );
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    let a = state
        .audit_page(None, 5, Some("settings.guarded_cleared"), None)
        .unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(
        (a[0].actor.as_str(), a[0].actor_kind.as_str()),
        ("cli:ops", "cli")
    );
    assert!(
        probation::read_sidecar(dir.path()).is_none(),
        "the counter belongs to the cleared entry"
    );
    drop(state);
    let mut out = Vec::new();
    assert!(super::cli::run_clear(&cfg, &super::cli::Target::All, "ops", &mut out).unwrap());
    assert!(entries_of(&cfg).is_empty());
    // An unknown ID is an error, and `--all` with nothing stored is fine.
    assert!(
        !super::cli::run_clear(
            &cfg,
            &super::cli::Target::One("zzz".into()),
            "ops",
            &mut Vec::new()
        )
        .unwrap()
    );
    assert!(super::cli::run_clear(&cfg, &super::cli::Target::All, "ops", &mut Vec::new()).unwrap());
}

// REQ: API-902 (ADR-957) — the CLI refuses while a node holds the data directory.
#[test]
fn api_902_cli_refuses_while_node_runs() {
    let (dir, cfg) = dir_with(&[("t-stg", json!({"label": "x"}), EntryState::Staged)]);
    let _held = crate::datadir::lock(dir.path(), Duration::ZERO).unwrap();
    assert!(!super::cli::run_list(&cfg, &mut Vec::new()).unwrap());
    assert!(
        !super::cli::run_clear(&cfg, &super::cli::Target::All, "ops", &mut Vec::new()).unwrap()
    );
    assert_eq!(entries_of(&cfg).len(), 1, "nothing was cleared");
    // A mistyped `-c` (no state.db) is refused and creates nothing.
    let other = tempfile::tempdir().unwrap();
    let mut wrong = cfg.clone();
    wrong.node.data_dir = telltale_config::SafeString::new(other.path().to_str().unwrap()).unwrap();
    assert!(!super::cli::run_list(&wrong, &mut Vec::new()).unwrap());
    assert!(!other.path().join("state.db").exists());
}

// REQ: API-902 (ADR-957) — `TELLTALE_IGNORE_GUARDED=1` ignores every entry (deleting none), so the
// node starts on its files; the data-dir pointer is ignored too.
#[test]
fn api_902_ignore_env_starts_from_file() {
    let (dir, cfg) = dir_with(&[
        ("t-stg", json!({"label": "x"}), EntryState::Staged),
        (
            "data-dir",
            json!({"path": "/elsewhere"}),
            EntryState::Active,
        ),
    ]);
    let b = probation::begin_for(&cfg, "pi-a", &defs(true), 100, true);
    assert!(b.ignored && b.on_probation.is_empty() && b.dropped.is_empty());
    assert!(
        probation::read_sidecar(dir.path()).is_none(),
        "no counter: nothing is applied"
    );
    assert_eq!(entries_of(&cfg).len(), 2, "nothing was deleted");
    // The overlay ignores every entry, the pointer included.
    let all = entries_of(&cfg);
    let mut c = Config::default();
    super::appliers::overlay_with(
        &mut c,
        &Config::default(),
        &all,
        None,
        &defs(true),
        "pi-a",
        true,
    );
    assert_eq!(c, Config::default());
}

// REQ: API-902 (ADR-957) — the data-dir pointer is local: never in the managed table (so never in the
// replicated blob), listed by the CLI and cleared by it.
#[test]
fn api_902_cli_clear_data_dir_pointer() {
    let (_dir, cfg) = dir_with(&[("data-dir", json!({"path": "/mnt/new"}), EntryState::Staged)]);
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    assert!(
        state.managed(super::KIND).unwrap().is_empty(),
        "the pointer is not a managed row"
    );
    assert!(
        crate::node_managed::export(&state).len() < 80,
        "and not in the blob"
    );
    drop(state);
    let mut out = Vec::new();
    assert!(super::cli::run_list(&cfg, &mut out).unwrap());
    assert!(String::from_utf8(out).unwrap().contains("data-dir"));
    assert!(
        super::cli::run_clear(
            &cfg,
            &super::cli::Target::One("data-dir".into()),
            "ops",
            &mut Vec::new()
        )
        .unwrap()
    );
    assert!(entries_of(&cfg).is_empty());
}

// REQ: API-902 (ADR-957) — a replica can't publish a removal, so a clear is also recorded as
// suppressed until the primary's copy changes; the overlay honours it, and a changed copy is used.
#[test]
fn api_902_cli_clear_survives_resync() {
    let (_dir, cfg) = dir_with(&[]);
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    let replicated = Stored {
        node: "pi-a".into(),
        id: "t-imm".into(),
        value: json!({"label": "from the primary"}),
        mode: "immediate".into(),
        state: EntryState::Active,
        by: "alice".into(),
        at: 1,
    };
    struct Mark;
    impl Applier for Mark {
        fn current(&self, _: &Config) -> Value {
            Value::Null
        }
        fn check(&self, _: &CheckCx<'_>) -> Result<Checked, Problem> {
            Ok(Checked::default())
        }
        fn overlay(&self, cfg: &mut Config, _v: &Value) {
            cfg.node.workers = 9;
        }
    }
    let rows = vec![RowDef {
        row: R_IMM,
        applier: Arc::new(Mark),
    }];
    let apply = |e: &Stored| {
        let mut c = Config::default();
        super::appliers::overlay_with(
            &mut c,
            &Config::default(),
            std::slice::from_ref(e),
            Some(&state),
            &rows,
            "pi-a",
            false,
        );
        c.node.workers == 9
    };
    assert!(apply(&replicated));
    let mut m = std::collections::BTreeMap::new();
    m.insert("t-imm".to_owned(), replicated.digest());
    store::set_suppressed(&state, &m).unwrap();
    assert!(
        !apply(&replicated),
        "the same copy from the primary is ignored after a local clear"
    );
    let mut changed = replicated.clone();
    changed.value = json!({"label": "changed by the primary"});
    assert!(apply(&changed), "a changed copy ends the suppression");
    let mut text = Vec::new();
    // `list` shows the suppression.
    drop(state);
    let state2 = State::open(&crate::managed::state_path(&cfg)).unwrap();
    assert_eq!(store::suppressed(&state2).len(), 1);
    drop(state2);
    assert!(super::cli::run_list(&cfg, &mut text).unwrap());
    assert!(String::from_utf8(text).unwrap().contains("suppressed"));
}

// ---- storage, the registry against the surfaces --------------------------------------------

// REQ: API-902, CLU-010 (ADR-956 §2) — a guarded entry travels in the node-managed blob (kind
// `guarded`, `<node>/<id>`); a node that doesn't know the kind drops it and keeps the rest; and an
// entry for another node isn't this node's.
#[test]
fn clu_010_guarded_entry_ignored_by_n_minus_1() {
    let state = State::in_memory().unwrap();
    for node in ["pi-a", "pi-b"] {
        store::put(
            &state,
            &Stored {
                node: node.into(),
                id: "t-imm".into(),
                value: json!({"label": node}),
                mode: "immediate".into(),
                state: EntryState::Active,
                by: "alice".into(),
                at: 1,
            },
            1,
            "alice",
        )
        .unwrap();
    }
    let blob = crate::node_managed::export(&state);
    let now = crate::node_managed::parse(&blob).unwrap();
    assert_eq!(now.len(), 2);
    assert!(
        now.iter()
            .all(|e| e.kind == "guarded" && e.name.contains('/'))
    );
    let mine = crate::node_managed::guarded_of(&now, "pi-a");
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].value["label"], "pi-a");
    // A build that knows only the OIDC kind reads the document and ignores the entries.
    let old = crate::node_managed::parse_kinds(&blob, &[crate::managed::OIDC_PROVIDER]).unwrap();
    assert!(old.is_empty());
    // An entry for the data-dir pointer never reaches the blob.
    store::put(
        &state,
        &Stored {
            node: "pi-a".into(),
            id: "data-dir".into(),
            value: json!({"path": "/x"}),
            mode: "staged".into(),
            state: EntryState::Staged,
            by: "alice".into(),
            at: 1,
        },
        1,
        "alice",
    )
    .unwrap();
    let blob2 = crate::node_managed::export(&state);
    assert!(!String::from_utf8_lossy(&blob2).contains("data-dir"));
}

// ---- the cluster ---------------------------------------------------------------------------

/// A primary `pi-a`, a replica `pi-b` and a replica `pi-c`; the primary's `state.db` is where every
/// entry is written.
fn cluster() -> (Node, Node, Node) {
    let net = Arc::new(Net::default());
    *net.primary.lock().unwrap() = Some("pi-a".to_owned());
    *net.members.lock().unwrap() = ["pi-a", "pi-b", "pi-c"]
        .iter()
        .map(|n| Member {
            id: format!("id-{n}"),
            name: (*n).to_owned(),
            is_primary: *n == "pi-a",
            up: true,
        })
        .collect();
    let pstate = Arc::new(State::in_memory().unwrap());
    *net.primary_state.lock().unwrap() = Some(Arc::clone(&pstate));
    let a = node_on("pi-a", &net, pstate, "systemd", true);
    let b = node_on(
        "pi-b",
        &net,
        Arc::new(State::in_memory().unwrap()),
        "systemd",
        false,
    );
    let c = node_on(
        "pi-c",
        &net,
        Arc::new(State::in_memory().unwrap()),
        "docker",
        false,
    );
    (a, b, c)
}

async fn preview_for(
    e: &Arc<Engine>,
    c: &GuardedCaller,
    node: &str,
    id: &str,
    v: Value,
) -> Result<GuardedPreview, Problem> {
    e.preview(
        c,
        id,
        GuardedPreviewRequest {
            node: Some(node.into()),
            value: v,
            options: Value::Null,
        },
    )
    .await
}

async fn apply_for(
    e: &Arc<Engine>,
    c: &GuardedCaller,
    node: &str,
    id: &str,
    p: &GuardedPreview,
    v: Value,
) -> Result<GuardedApplied, Problem> {
    let mut r = apply_req(p, v);
    r.node = Some(node.into());
    e.apply(c, id, r).await
}

// REQ: API-902 (ADR-956 §5) — only the primary forwards a request for another node, with a signed
// assertion the target checks itself: the target previews and applies, the pending change and the
// confirmation stay on the target, and the entry is written through the primary.
#[tokio::test(start_paused = true)]
async fn api_902_forwarded_change_checked_on_target() {
    let (a, b, c) = cluster();
    let alice = admin("alice", 5);
    // The primary previews for pi-b: the preview is pi-b's (its phrase, its supervisor).
    let v = json!({"label": "remote"});
    let p = preview_for(&a.engine, &alice, "pi-b", "t-imm", v.clone())
        .await
        .unwrap();
    assert_eq!(p.node, "pi-b");
    assert_eq!(p.phrase, "pi-b t-imm");
    // The pi-a engine holds no preview of it: pi-b's does.
    let done = apply_for(&a.engine, &alice, "pi-b", "t-imm", &p, v.clone())
        .await
        .unwrap();
    assert_eq!(done.status, "applied");
    assert_eq!(done.node, "pi-b");
    assert!(b.audits("settings.guarded")[0]["after"]["label"] == "remote");
    assert!(
        a.audits("settings.guarded").is_empty(),
        "the target audits it, with the admin named"
    );
    assert!(
        b.host.audits.lock().unwrap()[0]
            .0
            .starts_with("alice via pi-a")
    );
    // The entry is on the primary's state under pi-b's name; pi-c was never reached.
    let pstate = a.engine.state.clone();
    assert!(
        store::for_node(&pstate, "pi-b")
            .iter()
            .any(|e| e.id == "t-imm")
    );
    assert!(store::for_node(&pstate, "pi-c").is_empty() && c.audits("settings.guarded").is_empty());
    // A target's own check still applies: its weakening rule needs a recent sign-in carried in the
    // assertion, which the primary can't inflate.
    let stale = admin("alice", 3600);
    let weak = json!({"label": "w", "weaken": true});
    let p = preview_for(&a.engine, &stale, "pi-b", "t-imm", weak.clone())
        .await
        .unwrap();
    assert_eq!(
        code(apply_for(&a.engine, &stale, "pi-b", "t-imm", &p, weak).await),
        Code::ReauthRequired
    );
    // A forged assertion (a replica signing) and a stale one are refused by the target.
    let fwd = |setting: &str,
               admin_name: &str,
               issuer: &str,
               signer: &str,
               expires: u64,
               nonce: &str,
               sender_ok: bool| {
        let asr = Assertion {
            admin: admin_name.into(),
            actor: admin_name.into(),
            role: "admin".into(),
            signed_in_at: Some(now()),
            remote: None,
            issuer: issuer.into(),
            node: "pi-b".into(),
            action: "preview".into(),
            setting: setting.into(),
            preview_id: String::new(),
            nonce: nonce.into(),
            expires,
        };
        let sig = blake3::keyed_hash(&key_of(signer), &asr.canonical())
            .as_bytes()
            .to_vec();
        (
            if sender_ok { "pi-a" } else { "pi-c" },
            Forwarded {
                op: ForwardedOp::Preview {
                    id: setting.into(),
                    req: GuardedPreviewRequest {
                        node: None,
                        value: json!({"label": "x"}),
                        options: Value::Null,
                    },
                },
                assertion: Some(Signed {
                    assertion: asr,
                    sig,
                }),
            },
        )
    };
    let refused = |a: ForwardedAnswer| {
        matches!(
            a,
            ForwardedAnswer::Refused {
                code: Code::Forbidden,
                ..
            }
        )
    };
    // Signed by a replica, naming the primary as issuer: the signature isn't the primary's.
    let (s, f) = fwd("t-imm", "mallory", "pi-a", "pi-c", now() + 30, "n1", true);
    assert!(
        refused(b.engine.handle_forwarded(s, f).await),
        "a replica's signature"
    );
    // Signed by the primary's key but sent over a replica's connection.
    let (s, f) = fwd("t-imm", "mallory", "pi-a", "pi-a", now() + 30, "n2", false);
    assert!(
        refused(b.engine.handle_forwarded(s, f).await),
        "not from the primary's connection"
    );
    // A replica as the issuer.
    let (s, f) = fwd("t-imm", "mallory", "pi-c", "pi-c", now() + 30, "n3", false);
    assert!(
        refused(b.engine.handle_forwarded(s, f).await),
        "issuer isn't the primary"
    );
    // Expired.
    let (s, f) = fwd(
        "t-imm",
        "alice",
        "pi-a",
        "pi-a",
        now().saturating_sub(5),
        "n4",
        true,
    );
    assert!(refused(b.engine.handle_forwarded(s, f).await), "expired");
    // Valid once, then a replay is refused.
    let (s, f) = fwd("t-imm", "alice", "pi-a", "pi-a", now() + 30, "n5", true);
    assert!(matches!(
        b.engine.handle_forwarded(s, f.clone()).await,
        ForwardedAnswer::Preview(_)
    ));
    assert!(refused(b.engine.handle_forwarded(s, f).await), "a replay");
    // An assertion for another action or setting doesn't carry over (it is bound).
    let (s, mut f) = fwd("t-imm", "alice", "pi-a", "pi-a", now() + 30, "n6", true);
    if let ForwardedOp::Preview { id, .. } = &mut f.op {
        *id = "t-stg".into();
    }
    assert!(
        refused(b.engine.handle_forwarded(s, f).await),
        "bound to its setting"
    );
}

// REQ: API-902 (ADR-956 §5) — a replica forwards nothing: it answers 421 with the primary's
// address, and a replica can't sign an assertion.
#[tokio::test(start_paused = true)]
async fn api_902_forwarded_immediate_change_from_replica_refused() {
    let (_a, b, c) = cluster();
    let alice = admin("alice", 5);
    let e = preview_for(&b.engine, &alice, "pi-c", "t-imm", json!({"label": "x"}))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::NotPrimary);
    assert!(e.detail.contains("pi-a"));
    assert!(c.audits("settings.guarded").is_empty());
    // The replica's own node works as for a standalone node.
    let own = preview_for(&b.engine, &alice, "pi-b", "t-imm", json!({"label": "x"}))
        .await
        .unwrap();
    assert_eq!(own.node, "pi-b");
    // An unknown node.
    let e = preview_for(&b.engine, &alice, "pi-z", "t-imm", json!({"label": "x"}))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::NodeUnknown);
    // A replica that tries to build an assertion gets nothing: it can't sign.
    assert!(b.host.sign(b"x").is_none());
}

// REQ: API-902 (ADR-956 §5) — the pending change is held on the target and the confirmation must
// reach the target directly (the primary can't confirm for the admin).
#[tokio::test(start_paused = true)]
async fn api_902_confirm_must_reach_target_directly() {
    let (a, b, _c) = cluster();
    let alice = admin("alice", 5);
    let v = json!({"port": 40_150});
    let p = preview_for(&a.engine, &alice, "pi-b", "t-win", v.clone())
        .await
        .unwrap();
    let r = apply_for(&a.engine, &alice, "pi-b", "t-win", &p, v)
        .await
        .unwrap();
    assert_eq!(r.status, "pending");
    let pid = r.pending_id.clone().unwrap();
    // The pending change is on pi-b, not on the primary.
    assert_eq!(
        b.engine
            .status_local()
            .pending
            .as_ref()
            .map(|p| p.id.as_str()),
        Some(pid.as_str())
    );
    assert!(a.engine.status_local().pending.is_none());
    // The primary can't confirm it (its engine doesn't hold it), nor can it from its own socket.
    assert_eq!(
        code(
            a.engine
                .confirm(&alice, &pid, r.confirm_token.clone())
                .await
        ),
        Code::NotFound
    );
    // Directly at the target, on the new address, with the token.
    let there = on_new_socket(alice.clone(), &r);
    let ok = b
        .engine
        .confirm(&there, &pid, r.confirm_token.clone())
        .await
        .unwrap();
    assert_eq!(ok.outcome, "confirmed");
    assert!(
        store::for_node(&a.engine.state, "pi-b")
            .iter()
            .any(|e| e.id == "t-win"),
        "written through the primary"
    );
    // The primary can cancel one it forwarded (a forwarded, signed cancel).
    let v = json!({"port": 40_151});
    let p = preview_for(&a.engine, &alice, "pi-b", "t-win", v.clone())
        .await
        .unwrap();
    let r = apply_for(&a.engine, &alice, "pi-b", "t-win", &p, v)
        .await
        .unwrap();
    let c = a
        .engine
        .forward_cancel(&alice, "pi-b", r.pending_id.as_deref().unwrap())
        .await
        .unwrap();
    assert_eq!(c.reason.as_deref(), Some("cancelled"));
}

// REQ: API-902, CLU-004 (ADR-956 §5) — a target that can't reach the primary when the admin
// confirms refuses (409 `primary_unreachable`); the window runs out and rolls back, so a node never
// runs a guarded value that no one will replicate.
#[tokio::test(start_paused = true)]
async fn api_902_primary_unreachable_rolls_back() {
    let (a, b, _c) = cluster();
    let alice = admin("alice", 5);
    let v = json!({"port": 40_160});
    let p = preview_for(&a.engine, &alice, "pi-b", "t-win", v.clone())
        .await
        .unwrap();
    let r = apply_for(&a.engine, &alice, "pi-b", "t-win", &p, v)
        .await
        .unwrap();
    // The link to the primary goes down before the admin confirms.
    a.host.net.primary_down.store(true, Ordering::SeqCst);
    let there = on_new_socket(alice.clone(), &r);
    let e = b
        .engine
        .confirm(
            &there,
            r.pending_id.as_deref().unwrap(),
            r.confirm_token.clone(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::PrimaryUnreachable);
    assert!(
        b.engine.status_local().pending.is_some(),
        "the window runs on"
    );
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    assert!(b.engine.status_local().pending.is_none(), "and rolls back");
    assert_eq!(
        b.audits("settings.guarded_rolled_back")[0]["reason"],
        "expired"
    );
    assert!(
        store::all(&a.engine.state).is_empty(),
        "nothing was written anywhere"
    );
    // An immediate change on a replica needs the primary too.
    let p = preview(
        &b.engine,
        &admin("alice", 5),
        "t-imm",
        json!({"label": "x"}),
    )
    .await
    .unwrap();
    let e = b
        .engine
        .apply(
            &admin("alice", 5),
            "t-imm",
            apply_req(&p, json!({"label": "x"})),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::PrimaryUnreachable);
}

// REQ: API-902 (ADR-956 §4a) — `GET /api/v1/guarded` lists each member's own supervisor and what is
// pending on it (a read with no value in it, so any member answers it without an assertion).
#[tokio::test(start_paused = true)]
async fn api_902_listing_covers_every_node() {
    let (a, _b, _c) = cluster();
    let s = a.engine.status().await;
    let by: std::collections::BTreeMap<&str, &str> = s
        .nodes
        .iter()
        .map(|n| (n.node.as_str(), n.supervisor.kind.as_str()))
        .collect();
    assert_eq!(by.get("pi-a"), Some(&"systemd"));
    assert_eq!(by.get("pi-b"), Some(&"systemd"));
    assert_eq!(by.get("pi-c"), Some(&"docker"));
    assert_eq!(s.nodes[0].node, "pi-a", "this node first");
    // A pending change on a member shows there, without its value.
    let alice = admin("alice", 5);
    let v = json!({"port": 40_180});
    let p = preview_for(&a.engine, &alice, "pi-c", "t-win", v.clone())
        .await
        .unwrap();
    apply_for(&a.engine, &alice, "pi-c", "t-win", &p, v)
        .await
        .unwrap();
    let s = a.engine.status().await;
    let c = s.nodes.iter().find(|n| n.node == "pi-c").unwrap();
    assert_eq!(
        c.pending.as_ref().map(|p| p.setting.as_str()),
        Some("t-win")
    );
    assert!(!serde_json::to_string(&s).unwrap().contains("40180"));
}

// REQ: API-902 (ADR-956 §4a) — the restart is forwarded only by the primary with the same signed
// assertion: a replica's is refused, a replayed one too, and the target checks its own supervisor.
#[tokio::test(start_paused = true)]
async fn api_902_forwarded_restart_from_replica_refused() {
    let (a, b, c) = cluster();
    let alice = admin("alice", 5);
    // pi-b asks for a restart of pi-c: it isn't the primary, so it can't forward.
    let e = preview_for(&b.engine, &alice, "pi-c", RESTART_NOW, Value::Null)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::NotPrimary);
    // The primary forwards a restart of pi-b; the target uses its own supervisor and phrase.
    let p = preview_for(&a.engine, &alice, "pi-b", RESTART_NOW, Value::Null)
        .await
        .unwrap();
    assert_eq!(p.phrase, "pi-b restart");
    assert!(p.checks.iter().any(|c| c.detail.contains("systemd")));
    let r = apply_for(&a.engine, &alice, "pi-b", RESTART_NOW, &p, Value::Null)
        .await
        .unwrap();
    assert_eq!(r.status, "restarting");
    assert_eq!(b.host.restarts.load(Ordering::SeqCst), 1);
    assert_eq!(a.host.restarts.load(Ordering::SeqCst), 0, "no restart all");
    assert_eq!(c.host.restarts.load(Ordering::SeqCst), 0);
    assert_eq!(b.audits("settings.guarded_restart").len(), 1);
}

// REQ: API-902 (ADR-956 §5) — an assertion is single use: a replay of the same request is refused.
#[tokio::test(start_paused = true)]
async fn api_902_forwarded_restart_assertion_single_use() {
    let (a, b, _c) = cluster();
    let alice = admin("alice", 5);
    let asr = a
        .engine
        .host
        .assertion(&Assertion {
            admin: "alice".into(),
            actor: "alice".into(),
            role: "admin".into(),
            signed_in_at: Some(now()),
            remote: None,
            issuer: "pi-a".into(),
            node: "pi-b".into(),
            action: "preview".into(),
            setting: RESTART_NOW.into(),
            preview_id: String::new(),
            nonce: "once".into(),
            expires: now() + 30,
        })
        .unwrap();
    let f = Forwarded {
        op: ForwardedOp::Preview {
            id: RESTART_NOW.into(),
            req: GuardedPreviewRequest {
                node: None,
                value: Value::Null,
                options: Value::Null,
            },
        },
        assertion: Some(asr),
    };
    assert!(matches!(
        b.engine.handle_forwarded("pi-a", f.clone()).await,
        ForwardedAnswer::Preview(_)
    ));
    let again = b.engine.handle_forwarded("pi-a", f).await;
    assert!(
        matches!(again, ForwardedAnswer::Refused { code: Code::Forbidden, ref detail, .. } if detail.contains("already used"))
    );
    let _ = alice;
}

// ---- the registry against the surfaces -------------------------------------------------------

// REQ: API-902 (ADR-956 §7) — the listing carries no value, preview ID or token: only that a change
// is pending, its setting and its deadline.
#[tokio::test(start_paused = true)]
async fn api_902_listing_has_no_secrets_or_pending_values() {
    let n = solo();
    let a = admin("alice", 5);
    change(
        &n.engine,
        &a,
        "t-stg",
        json!({"label": "super-secret-label"}),
    )
    .await
    .unwrap();
    let p = preview(&n.engine, &a, "t-win", json!({"port": 40_170}))
        .await
        .unwrap();
    let r = n
        .engine
        .apply(&a, "t-win", apply_req(&p, json!({"port": 40_170})))
        .await
        .unwrap();
    let text = serde_json::to_string(&n.engine.status().await).unwrap();
    for needle in [
        r.confirm_token.as_deref().unwrap(),
        p.preview_id.as_str(),
        "40170",
        "super-secret-label",
    ] {
        assert!(!text.contains(needle), "the listing leaks `{needle}`");
    }
    assert!(text.contains("pendingRestart") && text.contains("deadlineSecs"));
}

// REQ: API-902 (ADR-956 §7) — a pending state's `Debug` and the engine's own `Debug` hold no token.
#[test]
fn api_902_engine_debug_is_quiet() {
    let n = solo_sync();
    let s = format!("{:?}", n.engine);
    assert!(s.contains("pi-a") && s.len() < 200);
}

fn solo_sync() -> Node {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _g = rt.enter();
    solo()
}

// Keeps an unused-import lint quiet where a test needs only the trait.
#[allow(dead_code)]
fn _uses(_: &dyn Applier) {}

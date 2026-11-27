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
use wrendns_api::BoxFuture;
use wrendns_api::auth::Actor;
use wrendns_api::guarded::{
    GuardedApplied, GuardedApplyRequest, GuardedCaller, GuardedPreview, GuardedPreviewRequest,
    Supervisor,
};
use wrendns_api::problem::{Code, Problem};
use wrendns_config::Config;
use wrendns_config::guarded::{Mode, Proof, RESTART_NOW, Row, never};
use wrendns_store::state::State;

use super::assertion::{Assertion, Forwarded, ForwardedAnswer, ForwardedOp, Signed};
use super::dns_proof::{DnsProbe, Kind};
use super::engine::{Applier, CheckCx, Checked, Engine, NoOp, RowDef, Staged, WindowGuard};
use super::host::{Host, Member, ProofSocket};
use super::probation::{self, Sidecar};
use super::store::{self, EntryState, Stored};
use crate::server::Evidence;

fn weaken_flag(_old: &Value, new: &Value) -> bool {
    new.get("weaken").and_then(Value::as_bool) == Some(true)
}

mod dns_proof_tests;
mod listen_engine_tests;

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
    /// The evidence counters of the probes the last `probes` change staged.
    static EVIDENCE: std::cell::RefCell<Vec<Arc<Evidence>>> = const { std::cell::RefCell::new(Vec::new()) };
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
            && cx.value.get("probes").is_none()
        {
            return Err(Problem::new(
                Code::InvalidConfig,
                "needs a label, a port, proxies or probes",
            ));
        }
        // A test that moves the host's facts between preview and apply (`gate_host::set_facts`).
        let facts = crate::gate_host::read();
        let weak_on_public = cx.value.get("weak_on_public").and_then(Value::as_bool) == Some(true);
        Ok(Checked {
            effect: format!("sets {} on {}", cx.value, cx.node),
            would_disconnect: cx.value.get("disconnect").and_then(Value::as_bool) == Some(true),
            host_facts: weak_on_public.then_some(facts),
            weakening: weak_on_public && facts.public_ipv4 == Some(true),
            ..Checked::default()
        })
    }
    fn stage(
        &self,
        host: Arc<dyn Host>,
        _node: String,
        value: Value,
        _access: Option<Value>,
        _facts: Option<wrendns_config::HostFacts>,
    ) -> BoxFuture<Result<Staged, Problem>> {
        let (committed, aborted) = FLAGS.with(|f| {
            let f = f.borrow();
            (Arc::clone(&f.0), Arc::clone(&f.1))
        });
        Box::pin(async move {
            // A change proved by the node's own probes: one per entry, `{proto, addr, gated?}`, with
            // an evidence counter each (the tests read them back through `EVIDENCE`).
            if let Some(list) = value.get("probes").and_then(Value::as_array) {
                let sock = host
                    .proof_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                    .await
                    .map_err(|e| Problem::new(Code::Conflict, e))?;
                let probes = list
                    .iter()
                    .map(|p| {
                        let ev = Evidence::new(Vec::new());
                        EVIDENCE.with(|e| e.borrow_mut().push(Arc::clone(&ev)));
                        DnsProbe {
                            proto: serde_json::from_value(p["proto"].clone()).unwrap(),
                            addr: p["addr"].as_str().unwrap().parse().unwrap(),
                            path: None,
                            gated: p["gated"].as_bool() == Some(true),
                            evidence: Some(ev),
                        }
                    })
                    .collect();
                return Ok(Staged {
                    guard: Arc::new(SockGuard {
                        sock,
                        committed,
                        aborted,
                        commit_fails: false,
                    }),
                    proof_addr: None,
                    new_address: None,
                    pending_proxies: None,
                    dns_probes: probes,
                });
            }
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
                    dns_probes: Vec::new(),
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
                dns_probes: Vec::new(),
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
        .chain([
            RowDef {
                row: R_RESTART,
                applier: Arc::new(NoOp),
            },
            RowDef {
                row: *wrendns_config::guarded::row(wrendns_config::guarded::LISTEN_ACCESS).unwrap(),
                applier: Arc::new(super::appliers::ListenAccess),
            },
            RowDef {
                row: *wrendns_config::guarded::row(wrendns_config::guarded::LISTEN).unwrap(),
                applier: Arc::new(super::listen::Listen),
            },
            RowDef {
                row: *wrendns_config::guarded::row(wrendns_config::guarded::DNSTAP).unwrap(),
                applier: Arc::new(super::dnstap::Dnstap),
            },
        ])
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
    /// The listeners the recorded state says are closed or mismatched after an apply.
    unapplied: Mutex<Vec<String>>,
    audits: Mutex<Vec<(String, String, Value)>>,
    audit_ok: AtomicBool,
    restarts: AtomicUsize,
    bind_fails: AtomicBool,
    /// What the node's own probe of a listener (`proto://addr`) answers; a listener not named
    /// answers.
    probe_answers: Mutex<HashMap<String, Result<Kind, String>>>,
    probe_calls: AtomicUsize,
    sockets: Mutex<Vec<Arc<FakeSock>>>,
    next_port: AtomicUsize,
    /// A replica forwards nothing and signs nothing; the primary does.
    can_sign: bool,
    /// Also write each audit record to `state.db` (the API tests read it from there).
    audit_to_state: AtomicBool,
    /// Whether a replica's entry reaches it in time (`Host::wait_applied`).
    arrives: AtomicBool,
    /// What the node will run after its next start, when it differs from `cfg` (a staged entry).
    pending: Mutex<Option<Arc<Config>>>,
    /// T27.14c: the lists `stage_listeners` was given, and what the staged sockets are made to do.
    staged_lists: Mutex<Vec<Vec<wrendns_config::Listener>>>,
    stage_error: Mutex<Option<crate::server::WindowError>>,
    commit_error: Mutex<Option<crate::server::WindowError>>,
    commits: AtomicUsize,
    aborts: AtomicUsize,
    /// Once a commit has failed, writing an entry fails too (the primary went away).
    writes_down: AtomicBool,
    writes_down_after_commit_error: AtomicBool,
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
    fn pending_config(&self) -> Arc<Config> {
        let p = self.pending.lock().unwrap().clone();
        p.unwrap_or_else(|| self.running_config())
    }
    fn reload(&self) -> BoxFuture<bool> {
        self.reloads.fetch_add(1, Ordering::SeqCst);
        let ok = self.reload_ok.load(Ordering::SeqCst);
        Box::pin(std::future::ready(ok))
    }
    fn listeners_not_applied(&self) -> Vec<String> {
        self.unapplied.lock().unwrap().clone()
    }
    fn write_entry(
        &self,
        node: &str,
        id: &str,
        entry: Option<Stored>,
        by: &str,
    ) -> BoxFuture<Result<(), Problem>> {
        if self.writes_down.load(Ordering::SeqCst) {
            return Box::pin(std::future::ready(Err(Problem::new(
                Code::PrimaryUnreachable,
                "no primary",
            ))));
        }
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
    fn write_entry_expecting(
        &self,
        node: &str,
        id: &str,
        entry: Option<Stored>,
        by: &str,
        expect_at: Option<u64>,
    ) -> BoxFuture<Result<(), Problem>> {
        if !self.is_primary() {
            let target = self
                .net
                .primary_state
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| Arc::clone(&self.state));
            let held = store::for_node(&target, node)
                .into_iter()
                .find(|e| e.id == id);
            let w = super::prod::EntryWrite {
                node: node.to_owned(),
                id: id.to_owned(),
                entry: entry.clone(),
                by: by.to_owned(),
                check: true,
                expect_at,
            };
            if super::prod::entry_stale(held.as_ref(), &w) {
                return Box::pin(std::future::ready(Err(Problem::new(
                    Code::PreviewStale,
                    "the entry changed",
                ))));
            }
        }
        self.write_entry(node, id, entry, by)
    }
    fn wait_applied(&self, _node: &str, _id: &str, _digest: Option<String>) -> BoxFuture<bool> {
        Box::pin(std::future::ready(
            self.is_primary() || self.arrives.load(Ordering::SeqCst),
        ))
    }
    fn site(&self) -> String {
        self.net
            .members
            .lock()
            .unwrap()
            .iter()
            .find(|m| m.name == self.name)
            .map(|m| m.site.clone())
            .unwrap_or_default()
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
                .audit_append(&wrendns_store::state::NewAudit {
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
    fn probe_dns(&self, probe: &DnsProbe) -> BoxFuture<Result<Kind, String>> {
        self.probe_calls.fetch_add(1, Ordering::SeqCst);
        let r = self
            .probe_answers
            .lock()
            .unwrap()
            .get(&probe.listener())
            .cloned()
            .unwrap_or(Ok(Kind::Answered));
        Box::pin(std::future::ready(r))
    }
    fn stage_listeners(
        &self,
        list: Vec<wrendns_config::Listener>,
    ) -> BoxFuture<Result<Vec<crate::server::StagedListener>, crate::server::WindowError>> {
        if let Some(e) = self.stage_error.lock().unwrap().clone() {
            return Box::pin(std::future::ready(Err(e)));
        }
        let running = self.running_config();
        let staged = list
            .iter()
            .filter(|l| {
                !running
                    .listen
                    .iter()
                    .any(|r| r.proto == l.proto && r.addr == l.addr)
            })
            .map(|l| crate::server::StagedListener {
                proto: l.proto,
                addr: l.addr,
                bound: l.addr,
                proof: false,
                evidence: Evidence::new(Vec::new()),
            })
            .collect();
        self.staged_lists.lock().unwrap().push(list);
        Box::pin(std::future::ready(Ok(staged)))
    }
    fn commit_listeners(&self) -> BoxFuture<Result<(), crate::server::WindowError>> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        let r = self.commit_error.lock().unwrap().clone();
        if r.is_some() && self.writes_down_after_commit_error.load(Ordering::SeqCst) {
            self.writes_down.store(true, Ordering::SeqCst);
        }
        Box::pin(std::future::ready(r.map_or(Ok(()), Err)))
    }
    fn abort_listeners(&self) -> BoxFuture<()> {
        self.aborts.fetch_add(1, Ordering::SeqCst);
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
        unapplied: Mutex::default(),
        audits: Mutex::default(),
        audit_ok: AtomicBool::new(true),
        restarts: AtomicUsize::new(0),
        bind_fails: AtomicBool::new(false),
        probe_answers: Mutex::default(),
        probe_calls: AtomicUsize::new(0),
        sockets: Mutex::default(),
        next_port: AtomicUsize::new(0),
        can_sign,
        audit_to_state: AtomicBool::new(false),
        arrives: AtomicBool::new(true),
        pending: Mutex::new(None),
        staged_lists: Mutex::default(),
        stage_error: Mutex::default(),
        commit_error: Mutex::default(),
        commits: AtomicUsize::new(0),
        aborts: AtomicUsize::new(0),
        writes_down: AtomicBool::new(false),
        writes_down_after_commit_error: AtomicBool::new(false),
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
            cfg.node.name = wrendns_config::SafeString::new("overlaid").unwrap();
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
            cfg.node.name = wrendns_config::SafeString::new("overlaid").unwrap();
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
    // `WRENDNS_IGNORE_GUARDED` and another node's entry: ignored.
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
        let s = detect(|k| (k == "WRENDNS_SUPERVISOR").then(|| kind.to_owned()));
        assert_eq!(s.kind, kind);
    }
    assert_eq!(none(&[]).kind, "none");
    assert_eq!(none(&[("WRENDNS_SUPERVISOR", "none")]).kind, "none");
    assert_eq!(none(&[("WRENDNS_SUPERVISOR", "nonsense")]).kind, "none");
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

// REQ: CLU-004, API-902 (ADR-956 §4) — a start that fails after the DNS listeners bound (the API or
// metrics listener couldn't) stops its UDP workers, so the bind fallback's second start isn't
// sharing the port (SO_REUSEPORT) with orphaned workers whose runtime is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn api_902_failed_start_leaves_no_udp_workers_behind() {
    // `serve` records the listener table for the whole process: no other test may read it now.
    let _table = crate::gate_host::isolate();
    use wrendns_config::{ListenProto, Listener};
    let dir = tempfile::tempdir().unwrap();
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = probe.local_addr().unwrap();
    drop(probe);
    let mut cfg = Config::default();
    cfg.node.data_dir = wrendns_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
    cfg.node.name = wrendns_config::SafeString::new("pi-a").unwrap();
    cfg.api.enabled = false;
    cfg.cache.persist = false;
    cfg.telemetry.metrics.enabled = true;
    cfg.telemetry.metrics.listen = busy.local_addr().unwrap();
    cfg.listen = vec![Listener {
        proto: ListenProto::Udp,
        addr: udp_addr,
        path: None,
        tls: None,
        proxy_protocol: false,
        max_connections: None,
        max_connections_per_address: None,
        require_client_id: None,
    }];
    let r = Box::pin(crate::server::serve(Vec::new(), cfg)).await;
    let e = r.expect_err("the metrics listener can't bind");
    assert!(probation::is_bind_failure(&e), "{e:?}");
    // A plain (non-REUSEPORT) bind on the DNS port only works if every worker socket is closed.
    std::net::UdpSocket::bind(udp_addr).expect("the failed start's UDP workers are gone");
}

// REQ: API-902 (ADR-956 §4a) — a requested restart drains and exits 75: the node is driven through
// `server::serve` (listeners bound on ephemeral ports), the restart is requested the way the engine
// does it, `serve` returns within the drain cap (it does not wait for the 10 s hard cap, which would
// end the process), and the process's exit status is 75. The hard cap's own exit is a recorder here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn api_902_restart_exits_75_after_drain() {
    let _table = crate::gate_host::isolate();
    use wrendns_config::{ListenProto, Listener};
    assert_eq!(super::restart::EXIT_CODE, 75);
    assert_eq!(super::restart::DRAIN_CAP_SECS, 5);
    super::restart::reset_for_tests();
    assert_eq!(
        super::restart::exit_status(),
        0,
        "no request: a normal exit"
    );

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.node.data_dir = wrendns_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
    cfg.node.name = wrendns_config::SafeString::new("pi-a").unwrap();
    cfg.node.drain_delay_secs = 30; // a restart must not wait for this
    cfg.api.enabled = false;
    cfg.telemetry.metrics.enabled = false;
    cfg.cache.persist = false;
    let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let plain = |proto| Listener {
        proto,
        addr: any,
        path: None,
        tls: None,
        proxy_protocol: false,
        max_connections: None,
        max_connections_per_address: None,
        require_client_id: None,
    };
    cfg.listen = vec![plain(ListenProto::Udp), plain(ListenProto::Tcp)];

    let capped = Arc::new(AtomicBool::new(false));
    let served = tokio::spawn(crate::server::serve(Vec::new(), cfg));
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert!(!served.is_finished(), "the node is running");
    let flag = Arc::clone(&capped);
    let started = std::time::Instant::now();
    super::restart::request_exit_with(super::restart::DRAIN_CAP_SECS + 5, move || {
        flag.store(true, Ordering::SeqCst);
    });
    let done = tokio::time::timeout(
        std::time::Duration::from_secs(super::restart::DRAIN_CAP_SECS),
        served,
    )
    .await
    .expect("the node drained within the cap")
    .unwrap();
    assert!(done.is_ok(), "{done:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(super::restart::DRAIN_CAP_SECS),
        "the 30 s drain delay is skipped for a restart"
    );
    assert!(
        !capped.load(Ordering::SeqCst),
        "it finished before the hard cap"
    );
    assert_eq!(super::restart::exit_status(), 75);
    super::restart::reset_for_tests();
}

// ---- probation ---------------------------------------------------------------------------

/// A data directory with a `state.db` holding `entries` (for the node `pi-a`), and its files-only
/// configuration.
fn dir_with(entries: &[(&str, Value, EntryState)]) -> (tempfile::TempDir, Config) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.node.data_dir = wrendns_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
    cfg.node.name = wrendns_config::SafeString::new("pi-a").unwrap();
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
    let _g = FALLBACK_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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

/// The bind-fallback set is process-wide: the tests that use it take turns.
static FALLBACK_LOCK: Mutex<()> = Mutex::new(());

// ---- recovery (ADR-957) ------------------------------------------------------------------

// REQ: API-902 (ADR-957) — `wrendns guarded clear` removes the node's entries with the node
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
    wrong.node.data_dir = wrendns_config::SafeString::new(other.path().to_str().unwrap()).unwrap();
    assert!(!super::cli::run_list(&wrong, &mut Vec::new()).unwrap());
    assert!(!other.path().join("state.db").exists());
}

// REQ: API-902 (ADR-957) — `WRENDNS_IGNORE_GUARDED=1` ignores every entry (deleting none), so the
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
            site: String::new(),
            witness: false,
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

// REQ: API-902 (ADR-956 §4a) — a restart is refused while a window change is pending, and the
// pending change is untouched by the refusal.
#[tokio::test(start_paused = true)]
async fn api_902_restart_refused_while_window_pending() {
    let n = solo();
    let a = admin("alice", 5);
    let r = start_window(&n, &a, 40_150).await;
    assert_eq!(
        code(preview(&n.engine, &a, RESTART_NOW, Value::Null).await),
        Code::GuardedChangePending
    );
    assert_eq!(n.host.restarts.load(Ordering::SeqCst), 0);
    // The window is still there to cancel.
    n.engine
        .cancel(&a, r.pending_id.as_deref().unwrap())
        .await
        .unwrap();
}

// REQ: API-902 (ADR-957) — WRENDNS_IGNORE_GUARDED ignores the `data-dir` pointer too: the node
// starts in the file-named directory, and the pointer entry is kept, not deleted.
#[test]
fn api_902_ignore_env_ignores_data_dir_pointer() {
    let (_dir, cfg) = dir_with(&[(
        "data-dir",
        json!({"path": "/elsewhere"}),
        EntryState::Active,
    )]);
    let b = probation::begin_for(&cfg, "pi-a", &defs(true), 100, true);
    assert!(b.ignored && b.on_probation.is_empty() && b.dropped.is_empty());
    assert_eq!(entries_of(&cfg).len(), 1, "the pointer is kept");
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

// ---- review fixes: identity, start-path fallback, replicas, proofs ---------------------------

// REQ: API-902, CLU-004 (ADR-956 §5) — a node goes by its unique node ID, never the site label that
// every pod of a chart shares: two nodes in site `k8s` have two names, so an entry, a phrase and a
// forwarded request can't be confused between them (and a replica can't write its neighbour's).
#[test]
fn api_902_two_nodes_in_one_site_have_their_own_names() {
    let dirs: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
    let mut names = Vec::new();
    for (i, d) in dirs.iter().enumerate() {
        wrendns_cluster::node::Identity::init(
            d.path(),
            "home",
            vec![format!("https://127.0.0.1:{}", 1000 + i)],
            "k8s",
        )
        .unwrap();
        let mut cfg = Config::default();
        cfg.node.data_dir = wrendns_config::SafeString::new(d.path().to_str().unwrap()).unwrap();
        names.push(super::node_label(&cfg));
    }
    assert_ne!(names[0], names[1], "one site, two nodes, two names");
    assert!(names.iter().all(|n| n != "k8s"), "{names:?}");
    // The entry of one is not the other's.
    let w = |node: &str| super::prod::EntryWrite {
        node: node.to_owned(),
        id: "t-imm".to_owned(),
        entry: None,
        by: "alice".to_owned(),
        check: false,
        expect_at: None,
    };
    assert!(super::prod::entry_allowed(&names[0], &w(&names[0])));
    assert!(
        !super::prod::entry_allowed(&names[0], &w(&names[1])),
        "a replica writes only its own entries, not its site-mate's"
    );
    assert!(
        !super::prod::entry_allowed(&names[0], &w("k8s")),
        "nor one named by the shared site label"
    );
}

// REQ: API-902 (ADR-956 §5) — a replica in the primary's own site can't be taken for the primary:
// the sender is the connection's node ID, and it has to be the primary's ID.
#[test]
fn api_902_replica_in_primarys_site_is_not_the_primary() {
    let net = Arc::new(Net::default());
    *net.primary.lock().unwrap() = Some("id-a".to_owned());
    let host = node_on(
        "id-b",
        &net,
        Arc::new(State::in_memory().unwrap()),
        "systemd",
        false,
    );
    let a = Assertion {
        admin: "alice".into(),
        actor: "alice via id-a".into(),
        role: "admin".into(),
        signed_in_at: Some(now()),
        remote: None,
        issuer: "id-a".into(),
        node: "id-b".into(),
        action: "apply".into(),
        setting: "t-imm".into(),
        preview_id: "p".into(),
        nonce: "n".into(),
        expires: now() + 30,
    };
    let sig = blake3::keyed_hash(&key_of("id-a"), &a.canonical())
        .as_bytes()
        .to_vec();
    let signed = Signed { assertion: a, sig };
    let want = |sender| super::assertion::Expect {
        sender,
        now: now(),
        me: "id-b",
        action: "apply",
        setting: "t-imm",
        preview_id: "p",
    };
    assert!(signed.check(host.host.as_ref(), &want("id-a")).is_ok());
    // A replica of the same site holding the cluster key sends it: not the primary's connection.
    assert_eq!(
        signed.check(host.host.as_ref(), &want("id-c")).unwrap_err(),
        super::assertion::Refusal::NotFromPrimary
    );
}

// REQ: API-902 (ADR-956 §4) — the bind fallback covers a replica too: a confirmed listener entry
// that reached it in the primary's blob (not a row of its own) is set aside when it can't bind.
#[test]
fn api_902_bind_fallback_covers_a_replicated_entry() {
    let _g = FALLBACK_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    probation::reset_fallbacks();
    let (_dir, cfg, me) = replica_with(&[("t-bindfb3", json!({"port": 1}), EntryState::Active)]);
    super::set_this_node(&me);
    static ROW: Row = row!(
        "t-bindfb3",
        &["t.bindfb3"],
        Mode::Window,
        Some(Proof::NewSocket),
        never
    );
    let rows = vec![RowDef {
        row: ROW,
        applier: Arc::new(NoOp),
    }];
    let done = probation::fall_back_after_bind_failure(&cfg, &rows, 10);
    assert_eq!(done, vec!["t-bindfb3".to_owned()]);
    assert!(probation::fell_back("t-bindfb3"));
    probation::reset_fallbacks();
}

// REQ: API-902 (ADR-956 §4) — the start path: a listener that can't bind with a confirmed guarded
// entry behind it starts again, once, on the file's value; the entry stays for the next start; a
// bind failure with no such entry, or any other failure, is returned as it is.
#[test]
fn api_902_bind_failure_at_start_runs_again_on_the_files_value() {
    let _g = FALLBACK_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    probation::reset_fallbacks();
    super::set_this_node("pi-a");
    let (_dir, cfg) = dir_with(&[("t-bindfb2", json!({"port": 1}), EntryState::Active)]);
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
        "t-bindfb2",
        &["t.bindfb2"],
        Mode::Window,
        Some(Proof::NewSocket),
        never
    );
    let rows = vec![RowDef {
        row: ROW,
        applier: Arc::new(Mark),
    }];
    let build = || {
        let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
        let mut c = cfg.clone();
        super::appliers::overlay_with(
            &mut c,
            &cfg,
            &store::for_node(&state, "pi-a"),
            None,
            &rows,
            "pi-a",
            false,
        );
        c
    };
    let seen = std::cell::RefCell::new(Vec::new());
    let addr_gone = || std::io::Error::from(std::io::ErrorKind::AddrNotAvailable);
    let r = super::serve_with_fallback(
        build(),
        || Some(build()),
        || Some(cfg.clone()),
        &rows,
        |c| {
            seen.borrow_mut().push(c.node.workers);
            if seen.borrow().len() == 1 {
                Err(addr_gone())
            } else {
                Ok(())
            }
        },
    );
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(
        *seen.borrow(),
        vec![7, Config::default().node.workers],
        "the second start runs on the file's value"
    );
    assert_eq!(probation::fallbacks(), vec!["t-bindfb2".to_owned()]);
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    assert_eq!(store::for_node(&state, "pi-a").len(), 1, "the entry stays");
    // Another failure is not retried.
    probation::reset_fallbacks();
    let calls = std::cell::Cell::new(0);
    let r = super::serve_with_fallback(
        build(),
        || Some(build()),
        || Some(cfg.clone()),
        &rows,
        |_| {
            calls.set(calls.get() + 1);
            Err(std::io::Error::other("invalid configuration"))
        },
    );
    assert!(r.is_err() && calls.get() == 1);
    // A bind failure with no confirmed listener entry is returned too (nothing to fall back from).
    let (_d2, cfg2) = dir_with(&[]);
    let calls = std::cell::Cell::new(0);
    let r = super::serve_with_fallback(
        cfg2.clone(),
        || Some(cfg2.clone()),
        || Some(cfg2.clone()),
        &rows,
        |_| {
            calls.set(calls.get() + 1);
            Err(addr_gone())
        },
    );
    assert!(r.is_err() && calls.get() == 1);
    probation::reset_fallbacks();
}

// REQ: API-902, CLU-004 (T27.14c; ADR-956 §4, design 2.5 `failed_start`) — with the real `listen` row:
// a confirmed listener list that can't bind at start (a VIP the other node holds, an interface that
// isn't up) falls back for that start only to the file's listeners; the entry stays, and the next
// start tries it again.
#[test]
fn api_902_confirmed_listener_bind_failure_falls_back_at_start_with_the_listen_row() {
    let _g = FALLBACK_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    probation::reset_fallbacks();
    super::set_this_node("pi-a");
    let stored = json!({"listeners": [
        {"proto": "udp", "addr": "0.0.0.0:53"}, {"proto": "tcp", "addr": "0.0.0.0:53"},
        {"proto": "udp", "addr": "[::]:53"}, {"proto": "tcp", "addr": "[::]:53"},
        {"proto": "udp", "addr": "198.51.100.7:53"},
    ]});
    let (_dir, cfg) = dir_with(&[("listen", stored, EntryState::Active)]);
    let rows = vec![RowDef {
        row: *wrendns_config::guarded::row(wrendns_config::guarded::LISTEN).unwrap(),
        applier: Arc::new(super::listen::Listen),
    }];
    let build = || {
        let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
        let mut c = cfg.clone();
        super::appliers::overlay_with(
            &mut c,
            &cfg,
            &store::for_node(&state, "pi-a"),
            None,
            &rows,
            "pi-a",
            false,
        );
        c
    };
    assert_eq!(build().listen.len(), 5, "the entry is overlaid");
    let seen = std::cell::RefCell::new(Vec::new());
    let r = super::serve_with_fallback(
        build(),
        || Some(build()),
        || Some(cfg.clone()),
        &rows,
        |c| {
            seen.borrow_mut().push(c.listen.len());
            if seen.borrow().len() == 1 {
                Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))
            } else {
                Ok(())
            }
        },
    );
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(
        *seen.borrow(),
        vec![5, 4],
        "the second start runs the file's listeners"
    );
    assert_eq!(probation::fallbacks(), vec!["listen".to_owned()]);
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    assert_eq!(store::for_node(&state, "pi-a").len(), 1, "the entry stays");
    probation::reset_fallbacks();
}

/// A node directory that follows a primary as a replica, with `entries` for it in the node-managed
/// blob of the version it last applied. Returns the node's own name (its cluster node ID).
fn replica_with(entries: &[(&str, Value, EntryState)]) -> (tempfile::TempDir, Config, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.node.data_dir = wrendns_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
    let mut id = wrendns_cluster::node::Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    id.save_role(wrendns_cluster::node::Role::Replica, 1)
        .unwrap();
    let me = id.meta.node_id.clone();
    let rows: Vec<(String, String, String)> = entries
        .iter()
        .map(|(eid, v, st)| {
            let s = Stored {
                node: me.clone(),
                id: (*eid).into(),
                value: v.clone(),
                mode: "staged".into(),
                state: *st,
                by: "alice".into(),
                at: 1,
            };
            (
                super::KIND.to_owned(),
                super::entry_name(&me, eid),
                serde_json::to_string(&s).unwrap(),
            )
        })
        .collect();
    let blob = crate::node_managed::encode(&rows);
    let blobs = wrendns_cluster::sync::BlobStore::open(dir.path()).unwrap();
    let r = wrendns_cluster::sync::blob_ref(crate::node_managed::BLOB, &blob);
    blobs.put(&r, &blob).unwrap();
    let m = wrendns_cluster::sync::ClusterManifest {
        cluster_id: "c".into(),
        epoch: 1,
        seq: 3,
        primary: "primary".into(),
        node_managed: Some(r),
        ..wrendns_cluster::sync::ClusterManifest::default()
    };
    std::fs::write(
        wrendns_cluster::node::dir_of(dir.path()).join(crate::replication::APPLIED),
        serde_json::to_vec(&m).unwrap(),
    )
    .unwrap();
    // The node's state database exists, as it does on a node that has run.
    drop(State::open(&crate::managed::state_path(&cfg)).unwrap());
    (dir, cfg, me)
}

// REQ: API-902 (ADR-956 §4) — a staged entry the primary replicated is the replica's to start with:
// the replica reads it from the blob it applied, tracks probation locally (the primary's copy is
// untouched), shows it as pending, and makes it active once the node is healthy.
#[test]
fn api_902_staged_entry_takes_effect_on_a_replica() {
    let (dir, cfg, me) = replica_with(&[("t-stg", json!({"label": "x"}), EntryState::Staged)]);
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    let eff = store::effective(&cfg, &state, &me);
    assert_eq!(eff.len(), 1);
    assert!(eff[0].1, "it came from the primary");
    assert_eq!(eff[0].0.state, EntryState::Staged);
    assert!(store::for_node(&state, &me).is_empty(), "no local row");
    // The start: probation, counted in the sidecar.
    let b = probation::begin_for(&cfg, &me, &defs(true), 100, false);
    assert_eq!(b.on_probation, vec!["t-stg".to_owned()]);
    assert_eq!(probation::read_sidecar(dir.path()).unwrap().attempts, 1);
    let eff = store::effective(&cfg, &state, &me);
    assert_eq!(eff[0].0.state, EntryState::Probation);
    assert!(
        store::for_node(&state, &me).is_empty(),
        "still no local row"
    );
    // Healthy: active, and the outcome is recorded.
    let done = probation::mark_healthy_of(&state, &me, dir.path(), 200, eff);
    assert_eq!(done, vec!["t-stg".to_owned()]);
    assert_eq!(
        store::effective(&cfg, &state, &me)[0].0.state,
        EntryState::Active
    );
    assert_eq!(store::outcomes(&state)[0].outcome, "applied");
    // The primary changes the value: a note about the old one doesn't apply to it.
    let (_d2, cfg2, me2) = replica_with(&[("t-stg", json!({"label": "y"}), EntryState::Staged)]);
    let s2 = State::open(&crate::managed::state_path(&cfg2)).unwrap();
    let old = Stored {
        node: me2.clone(),
        id: "t-stg".into(),
        value: json!({"label": "x"}),
        mode: "staged".into(),
        state: EntryState::Staged,
        by: String::new(),
        at: 0,
    };
    store::transition(&s2, &old, true, EntryState::Active, 1, "system").unwrap();
    assert_eq!(
        store::effective(&cfg2, &s2, &me2)[0].0.state,
        EntryState::Staged,
        "a note about another value doesn't apply"
    );
}

// REQ: API-902 (ADR-956 §4) — two failed starts of a replicated staged entry drop it on the replica
// by ignoring it (the primary keeps it): the local suppression hides that copy until it changes.
#[test]
fn api_902_replicated_staged_entry_dropped_after_two_failed_starts() {
    let (dir, cfg, me) = replica_with(&[("t-stg", json!({"label": "x"}), EntryState::Staged)]);
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    for at in [1, 2] {
        let b = probation::begin_for(&cfg, &me, &defs(true), at, false);
        assert_eq!(b.on_probation.len(), 1);
    }
    let b = probation::begin_for(&cfg, &me, &defs(true), 3, false);
    assert_eq!(b.dropped, vec!["t-stg".to_owned()]);
    assert!(store::suppressed(&state).contains_key("t-stg"));
    assert!(probation::read_sidecar(dir.path()).is_none());
}

// REQ: API-902 (ADR-957 step 10) — an offline clear on a replica leaves a removal request for the
// primary, sent when the node is back and connected; the primary's removal ends the suppression.
#[test]
fn api_902_replica_clear_queues_a_removal_for_the_primary() {
    let (_dir, cfg, _me) = replica_with(&[("t-stg", json!({"label": "x"}), EntryState::Staged)]);
    let mut out = Vec::new();
    assert!(super::cli::run_clear(&cfg, &super::cli::Target::All, "alex", &mut out).unwrap());
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    let q = store::removals(&state);
    assert_eq!(q.len(), 1);
    assert_eq!((q[0].id.as_str(), q[0].by.as_str()), ("t-stg", "cli:alex"));
    assert!(store::suppressed(&state).contains_key("t-stg"));
    // The removal the primary took (its own blob no longer has the entry): queue and suppression go.
    store::removal_done(&state, "t-stg").unwrap();
    assert!(store::removals(&state).is_empty());
    // The suppression stays while the replicated blob still holds the entry, and goes once it doesn't.
    assert!(store::suppressed(&state).contains_key("t-stg"));
    store::prune_suppressed(&state, &[]);
    assert!(store::suppressed(&state).is_empty());
}

// REQ: API-902 (ADR-956 §3) — a replica's immediate change isn't answered `applied` until the
// primary's version carrying it has reached the node: the entry is the primary's, the answer says
// it isn't here yet, and nothing is reloaded early.
#[tokio::test(start_paused = true)]
async fn api_902_replica_immediate_change_waits_for_the_primary_version() {
    let (a, b, _c) = cluster();
    let alice = admin("alice", 5);
    b.host.arrives.store(false, Ordering::SeqCst);
    let before = b.host.reloads.load(Ordering::SeqCst);
    let r = change(&b.engine, &alice, "t-imm", json!({"label": "late"})).await;
    assert_eq!(code(r), Code::Unavailable);
    assert_eq!(
        b.host.reloads.load(Ordering::SeqCst),
        before,
        "no early reload"
    );
    assert_eq!(
        store::for_node(a.host.state.as_ref(), "pi-b").len(),
        1,
        "the primary has it"
    );
    // When it arrives in time the change is answered applied.
    b.host.arrives.store(true, Ordering::SeqCst);
    let done = change(&b.engine, &alice, "t-imm", json!({"label": "on time"}))
        .await
        .unwrap();
    assert_eq!(done.status, "applied");
}

// REQ: API-902 (ADR-956 §4a) — the restart's warning counts resolvers of this node's own site that
// are up: a witness isn't one, and another site's resolver doesn't answer this site's clients.
#[test]
fn api_902_restart_warning_counts_resolvers_of_the_same_site() {
    let net = Arc::new(Net::default());
    *net.primary.lock().unwrap() = Some("pi-a".to_owned());
    let member = |n: &str, site: &str, witness: bool| Member {
        id: format!("id-{n}"),
        name: n.to_owned(),
        is_primary: n == "pi-a",
        up: true,
        site: site.to_owned(),
        witness,
    };
    // pi-a (site home) has a witness in its site and a resolver in another site: neither counts.
    *net.members.lock().unwrap() = vec![
        member("pi-a", "home", false),
        member("w", "home", true),
        member("far", "office", false),
    ];
    let a = node_on(
        "pi-a",
        &net,
        Arc::new(State::in_memory().unwrap()),
        "systemd",
        true,
    );
    let w = a.engine.restart_checked().unwrap().warnings.join(" | ");
    assert!(w.contains("No other resolver in site `home`"), "{w}");
    // A resolver of its own site that is up: no such warning.
    net.members
        .lock()
        .unwrap()
        .push(member("pi-b", "home", false));
    let w = a.engine.restart_checked().unwrap().warnings.join(" | ");
    assert!(!w.contains("No other resolver"), "{w}");
}

// REQ: API-902, API-003 (ADR-956 §3, ADR-149) — the confirmation window's listener serves the
// confirm route and the UI's files, and nothing else: no sign-in, no session, no settings.
#[test]
fn api_902_proof_listener_serves_only_the_confirmation() {
    use axum::http::Method;
    let ok = super::prod::proof_allowed;
    assert!(ok(&Method::POST, "/api/v1/guarded/pending/abc123/confirm"));
    assert!(ok(&Method::GET, "/"));
    assert!(ok(&Method::GET, "/assets/index-abc.js"));
    assert!(ok(&Method::HEAD, "/favicon.ico"));
    assert!(
        ok(&Method::GET, "/api/v1/auth/status"),
        "the page's first read"
    );
    assert!(!ok(&Method::POST, "/api/v1/auth/status"));
    for path in [
        "/api/v1/auth/login",
        "/api/v1/settings/api",
        "/api/v1/guarded",
        "/api/v1/guarded/pending/abc/cancel",
        "/api/v1/guarded/pending//confirm",
        "/api/v1/guarded/pending/abc/confirm/extra",
        "/mcp",
        "/metrics",
        "/admin/api.php",
    ] {
        assert!(!ok(&Method::POST, path), "POST {path}");
        assert!(!ok(&Method::GET, path), "GET {path}");
    }
    assert!(!ok(&Method::DELETE, "/"));
    assert!(!ok(&Method::PUT, "/api/v1/guarded/pending/abc/confirm"));
}

/// REQ: API-003 (T24.44, ADR-1053 §5) — a redirect listener that can't bind never fails a staged
/// entry's probation; a failing DNS listener still does.
#[test]
fn api_003_a_failing_redirect_probe_does_not_block_probation() {
    use wrendns_api::model::ProbeResult;
    let probe = |proto: &str, ok: bool| ProbeResult {
        target: "probe".to_owned(),
        proto: proto.to_owned(),
        listener: true,
        ok,
        ..ProbeResult::default()
    };
    let redirect = crate::probes::REDIRECT_PROTO;
    assert!(super::probation::dns_probes_ok(&[
        probe("udp", true),
        probe(redirect, false),
        probe(redirect, false),
    ]));
    assert!(!super::probation::dns_probes_ok(&[
        probe("udp", false),
        probe(redirect, true),
    ]));
}

// ---- T27.14: the listener access row (DNS-901) -------------------------------------------------

/// A node whose listeners are the ones the `listen-access` tests use (a public DoT listener, a LAN
/// DoH one, a wildcard DoQ one and plain UDP), with the real row and applier added.
fn gate_node() -> Node {
    let n = solo();
    let c = super::appliers::listen_access_tests::cfg();
    let mut cfg = (*n.host.running_config()).clone();
    cfg.listen = c.listen;
    *n.host.cfg.lock().unwrap() = Arc::new(cfg);
    n
}

fn gate_value(dot: Value, doh: Value, doq: Value) -> Value {
    super::appliers::listen_access_tests::value(dot, doh, doq)
}

// REQ: DNS-901, API-902 (T27.14; ADR-956 §1, ADR-1090 point 1) — the gate is a guarded `immediate`
// row: the preview says what each listener's default resolves to and why, an admin's change is
// written and applied by a reload, the audit record holds the before and after, and a tightening is
// not marked as weakening.
#[tokio::test(start_paused = true)]
async fn dns_901_gate_change_is_guarded_applied_and_audited() {
    let n = gate_node();
    let a = admin("alice", 5);
    let v = gate_value(json!(true), Value::Null, Value::Null);
    let p = preview(&n.engine, &a, "listen-access", v.clone())
        .await
        .unwrap();
    assert_eq!(p.phrase, "pi-a listen-access");
    assert_eq!(p.mode, "immediate");
    assert!(!p.weakening);
    assert!(
        p.effect
            .contains("the default is on, because the address is public")
    );
    assert!(p.effect.contains("dot://203.0.113.5:853: default"));
    // The phrase is the server's to check.
    let mut bad = apply_req(&p, v.clone());
    bad.confirm = "pi-a listen".to_owned();
    assert_eq!(
        code(n.engine.apply(&a, "listen-access", bad).await),
        Code::InvalidParameter
    );
    let r = n
        .engine
        .apply(&a, "listen-access", apply_req(&p, v.clone()))
        .await
        .unwrap();
    assert_eq!(r.status, "applied");
    assert_eq!(n.host.reloads.load(Ordering::SeqCst), 1);
    let stored = store::for_node(&n.engine.state, "pi-a");
    assert_eq!(stored[0].id, "listen-access");
    assert_eq!(stored[0].state, EntryState::Active);
    assert_eq!(stored[0].value, v);
    let rec = &n.audits("settings.guarded")[0];
    assert_eq!(rec["setting"], "listen-access");
    assert_eq!(rec["outcome"], "applied");
    assert_eq!(rec["weakening"], false);
    assert_eq!(
        rec["before"]["listeners"][0]["require_client_id"],
        Value::Null
    );
    assert_eq!(
        rec["after"]["listeners"][0]["require_client_id"],
        json!(true)
    );
}

// REQ: DNS-901 (ADR-1090 point 2, fail closed) — a gate-on whose listener is closed after the apply
// is not "applied", even when the reload itself answered true (on a replica the replication path
// applied the entry first): the decision rests on the listener's recorded state. The entry goes
// back, and the message does not claim the node "kept" a configuration whose listener is closed.
#[tokio::test(start_paused = true)]
async fn dns_901_gate_on_with_a_closed_listener_is_not_applied() {
    let n = gate_node();
    let a = admin("alice", 5);
    let v = gate_value(json!(true), Value::Null, Value::Null);
    let p = preview(&n.engine, &a, "listen-access", v.clone())
        .await
        .unwrap();
    // The reload answered true, but the table says the listener is closed.
    n.host
        .unapplied
        .lock()
        .unwrap()
        .push("dot://203.0.113.5:853".to_owned());
    let err = n
        .engine
        .apply(&a, "listen-access", apply_req(&p, v.clone()))
        .await
        .unwrap_err();
    assert_eq!(err.code, Code::InvalidConfig);
    assert!(err.detail.contains("previous configuration is restored"));
    assert!(err.detail.contains("dot://203.0.113.5:853 is closed"));
    assert!(err.detail.contains("certificate"));
    assert!(
        !err.detail.contains("so it kept the previous configuration"),
        "{}",
        err.detail
    );
    assert!(
        store::for_node(&n.engine.state, "pi-a").is_empty(),
        "the entry is rolled back"
    );
    assert_eq!(
        n.audits("settings.guarded_rolled_back")[0]["reason"],
        "commit_failed"
    );
    assert!(n.audits("settings.guarded").is_empty());
    // With every listener bound as configured, the same change is applied.
    n.host.unapplied.lock().unwrap().clear();
    let p = preview(&n.engine, &a, "listen-access", v.clone())
        .await
        .unwrap();
    let r = n
        .engine
        .apply(&a, "listen-access", apply_req(&p, v))
        .await
        .unwrap();
    assert_eq!(r.status, "applied");
}

// REQ: DNS-901 — a failed reload with every listener bound keeps the plain message.
#[tokio::test(start_paused = true)]
async fn dns_901_failed_reload_without_a_closed_listener_keeps_the_plain_message() {
    let n = gate_node();
    let a = admin("alice", 5);
    let v = gate_value(json!(true), Value::Null, Value::Null);
    let p = preview(&n.engine, &a, "listen-access", v.clone())
        .await
        .unwrap();
    n.host.reload_ok.store(false, Ordering::SeqCst);
    let err = n
        .engine
        .apply(&a, "listen-access", apply_req(&p, v))
        .await
        .unwrap_err();
    assert_eq!(
        err.detail,
        "the node couldn't apply the change, so it kept the previous configuration"
    );
}

// REQ: DNS-901 (ADR-1090 point 1, ADR-956 §3) — turning the gate off on a public listener weakens
// it: a red mark, the open-resolver warning, and a sign-in within the last 10 minutes at apply.
#[tokio::test(start_paused = true)]
async fn dns_901_gate_off_on_public_listener_needs_recent_sign_in() {
    let n = gate_node();
    let v = gate_value(json!(false), Value::Null, Value::Null);
    let stale = admin("alice", 3600);
    let p = preview(&n.engine, &stale, "listen-access", v.clone())
        .await
        .unwrap();
    assert!(p.weakening);
    assert!(p.warnings.iter().any(|w| w.contains("open resolver")));
    assert_eq!(
        code(
            n.engine
                .apply(&stale, "listen-access", apply_req(&p, v.clone()))
                .await
        ),
        Code::ReauthRequired
    );
    assert!(store::for_node(&n.engine.state, "pi-a").is_empty());
    let fresh = admin("alice", 5);
    let p = preview(&n.engine, &fresh, "listen-access", v.clone())
        .await
        .unwrap();
    n.engine
        .apply(&fresh, "listen-access", apply_req(&p, v))
        .await
        .unwrap();
    assert_eq!(n.audits("settings.guarded")[0]["weakening"], true);
}

// REQ: DNS-901 (ADR-956 §3) — a value that names a listener this node doesn't run, or a key on a
// plain transport, is refused at the preview and never written.
#[tokio::test(start_paused = true)]
async fn dns_901_gate_validation_errors_are_refused_at_preview() {
    let n = gate_node();
    let a = admin("alice", 5);
    let mut v = gate_value(Value::Null, Value::Null, Value::Null);
    v["listeners"][3]["require_client_id"] = json!(true);
    assert_eq!(
        code(preview(&n.engine, &a, "listen-access", v).await),
        Code::InvalidConfig
    );
    assert_eq!(
        code(
            preview(
                &n.engine,
                &a,
                "listen-access",
                json!({"listeners": [{"proto": "dot", "addr": "203.0.113.9:853"}]})
            )
            .await
        ),
        Code::InvalidConfig
    );
    assert!(store::for_node(&n.engine.state, "pi-a").is_empty());
}

// REQ: DNS-901, API-902 (ADR-040) — a configuration file that sets `require_client_id` wins: the
// preview is 409 `set_by_file`, the listing shows the row locked, and the overlay doesn't apply a
// stored value over it.
#[tokio::test(start_paused = true)]
async fn dns_901_gate_file_wins_over_the_stored_value() {
    let n = gate_node();
    let a = admin("alice", 5);
    let mut file = Config::default();
    file.file_set.push("listen.require_client_id".to_owned());
    *n.host.file_cfg.lock().unwrap() = Arc::new(file.clone());
    assert_eq!(
        code(
            preview(
                &n.engine,
                &a,
                "listen-access",
                gate_value(json!(true), Value::Null, Value::Null)
            )
            .await
        ),
        Code::SetByFile
    );
    assert!(
        n.engine
            .status_local()
            .settings
            .iter()
            .any(|s| s.id == "listen-access" && s.set_by_file)
    );
    let defs = vec![RowDef {
        row: *wrendns_config::guarded::row("listen-access").unwrap(),
        applier: Arc::new(super::appliers::ListenAccess),
    }];
    let e = vec![Stored {
        node: "pi-a".into(),
        id: "listen-access".into(),
        value: gate_value(json!(false), Value::Null, Value::Null),
        mode: "immediate".into(),
        state: EntryState::Active,
        by: "alice".into(),
        at: 1,
    }];
    let mut cfg = super::appliers::listen_access_tests::cfg();
    super::appliers::overlay_with(&mut cfg, &file, &e, None, &defs, "pi-a", false);
    assert_eq!(cfg.listen[0].require_client_id, None, "the file wins");
    super::appliers::overlay_with(&mut cfg, &Config::default(), &e, None, &defs, "pi-a", false);
    assert_eq!(cfg.listen[0].require_client_id, Some(false));
}

// REQ: OBS-007, API-905 (T40.13; owner decision, 2026-11-27) - the dnstap row is locked per field
// by the files, not as a whole: with the reader's socket in the file, the feeds and the sampling
// still go through the preview and the phrase (the file's socket stays, whatever the value says), and a
// value that changes the file's socket is 409 `set_by_file`.
#[tokio::test(start_paused = true)]
async fn obs_007_dnstap_a_file_socket_locks_that_field_only() {
    let n = solo();
    let a = admin("alice", 5);
    let mut file = Config::default();
    file.telemetry.dnstap.socket = Some("/run/file.sock".into());
    file.file_set.push("telemetry.dnstap.socket".to_owned());
    *n.host.file_cfg.lock().unwrap() = Arc::new(file.clone());
    *n.host.cfg.lock().unwrap() = Arc::new(file.clone());
    // Another socket: the file wins.
    assert_eq!(
        code(
            preview(
                &n.engine,
                &a,
                "dnstap-output",
                json!({"socket": "/run/other.sock"})
            )
            .await
        ),
        Code::SetByFile
    );
    // The file's socket with a feed turned on: a weakening review, and it applies.
    let v = json!({"socket": "/run/file.sock", "forwarder": true});
    let p = preview(&n.engine, &a, "dnstap-output", v.clone())
        .await
        .unwrap();
    assert!(p.weakening, "{p:?}");
    n.engine
        .apply(&a, "dnstap-output", apply_req(&p, v))
        .await
        .unwrap();
    assert!(
        !n.engine
            .status_local()
            .settings
            .iter()
            .any(|s| s.id == "dnstap-output" && s.set_by_file),
        "the listing is not locked"
    );
    // The stored value never overrides the file's socket, and a feed confirmed for another reader is
    // not carried to it (T40.13, review 5): only an entry confirmed with the file's own reader keeps it.
    let defs = vec![RowDef {
        row: *wrendns_config::guarded::row(wrendns_config::guarded::DNSTAP).unwrap(),
        applier: Arc::new(super::dnstap::Dnstap),
    }];
    let e = vec![Stored {
        node: "pi-a".into(),
        id: "dnstap-output".into(),
        value: json!({"socket": "/run/other.sock", "forwarder": true}),
        mode: "staged".into(),
        state: EntryState::Active,
        by: "alice".into(),
        at: 1,
    }];
    let mut cfg = file.clone();
    super::appliers::overlay_with(&mut cfg, &file, &e, None, &defs, "pi-a", false);
    assert_eq!(
        cfg.telemetry.dnstap.socket.as_deref(),
        Some("/run/file.sock")
    );
    assert!(
        !cfg.telemetry.dnstap.forwarder,
        "the feed was confirmed for another socket"
    );
    let mut same = e.clone();
    same[0].value = json!({"socket": "/run/file.sock", "forwarder": true});
    let mut cfg = file.clone();
    super::appliers::overlay_with(&mut cfg, &file, &same, None, &defs, "pi-a", false);
    assert!(
        cfg.telemetry.dnstap.forwarder,
        "the feed is the stored value's, confirmed with the file's socket"
    );
}

// REQ: OBS-007, API-905 (T40.13, review) - the review judges "widening" against what the node will run
// after its next start, as the ordinary write does: the tap is on at /a, an ordinary write staged
// "off", and a review that sets /a again turns the tap on at the next start, so it weakens (a recent
// sign-in, the warning, `weakening` in the preview).
#[tokio::test(start_paused = true)]
async fn obs_007_dnstap_review_is_judged_on_what_the_node_will_run() {
    let n = solo();
    let a = admin("alice", 5);
    let mut running = Config::default();
    running.telemetry.dnstap.socket = Some("/a".into());
    *n.host.cfg.lock().unwrap() = Arc::new(running);
    let v = json!({"socket": "/a"});
    // Judged on the running tap alone, the same value changes nothing.
    let p = preview(&n.engine, &a, "dnstap-output", v.clone())
        .await
        .unwrap();
    assert!(!p.weakening, "nothing changes from the running tap");
    // A staged "off": the next start has no tap, so /a again turns it on.
    *n.host.pending.lock().unwrap() = Some(Arc::new(Config::default()));
    let p = preview(&n.engine, &a, "dnstap-output", v).await.unwrap();
    assert!(p.weakening, "{p:?}");
    assert!(p.needs_recent_sign_in, "{p:?}");
}

// REQ: OBS-007, API-905 (T40.13, review) - the reader is one field: a file that sets the address
// takes the entry's socket away (and the other way round), so the merged section has one reader and
// validates; the node does not fall back to its files alone.
#[test]
fn obs_007_dnstap_the_reader_is_one_field() {
    let defs = vec![RowDef {
        row: *wrendns_config::guarded::row(wrendns_config::guarded::DNSTAP).unwrap(),
        applier: Arc::new(super::dnstap::Dnstap),
    }];
    let entry = |value: Value| {
        vec![Stored {
            node: "pi-a".into(),
            id: "dnstap-output".into(),
            value,
            mode: "staged".into(),
            state: EntryState::Active,
            by: "alice".into(),
            at: 1,
        }]
    };
    for (file_field, file_value, entry_value) in [
        (
            "address",
            "tcp://192.0.2.5:6000",
            json!({"socket": "/run/a.sock", "forwarder": true}),
        ),
        (
            "socket",
            "/run/f.sock",
            json!({"address": "tcp://192.0.2.9:6000", "forwarder": true}),
        ),
    ] {
        let mut file = Config::default();
        if file_field == "address" {
            file.telemetry.dnstap.address = Some(file_value.into());
        } else {
            file.telemetry.dnstap.socket = Some(file_value.into());
        }
        file.file_set.push(format!("telemetry.dnstap.{file_field}"));
        let mut cfg = file.clone();
        super::appliers::overlay_with(
            &mut cfg,
            &file,
            &entry(entry_value),
            None,
            &defs,
            "pi-a",
            false,
        );
        let d = &cfg.telemetry.dnstap;
        assert_eq!(
            (d.socket.is_some(), d.address.is_some()),
            (file_field == "socket", file_field == "address"),
            "one reader, the file's: {d:?}"
        );
        assert!(
            !d.forwarder,
            "a feed confirmed for another reader is not carried to the file's"
        );
        assert!(wrendns_config::validate_config(&cfg).is_ok(), "{d:?}");
        // A value that changes the reader the file does not name is still the file's field.
        assert!(
            super::dnstap::changes_file_field(&file, &json!({"socket": "/run/zzz.sock"}))
                || file_field == "socket"
        );
        assert!(
            super::dnstap::changes_file_field(&file, &json!({"address": "tcp://192.0.2.77:1"}))
                || file_field == "address"
        );
    }
}

// REQ: OBS-007, API-905 (T40.13, review) - an entry an ordinary write stored (`narrowed`, never
// confirmed with the phrase) is applied only while it copies no more than the files: when the files
// have dropped the tap or added a feed since, it is not applied.
#[test]
fn obs_007_dnstap_an_unconfirmed_entry_never_widens_the_files() {
    let defs = vec![RowDef {
        row: *wrendns_config::guarded::row(wrendns_config::guarded::DNSTAP).unwrap(),
        applier: Arc::new(super::dnstap::Dnstap),
    }];
    let entry = |mode: &str, value: Value| {
        vec![Stored {
            node: "pi-a".into(),
            id: "dnstap-output".into(),
            value,
            mode: mode.into(),
            state: EntryState::Active,
            by: "alice".into(),
            at: 1,
        }]
    };
    let run = |file: &Config, e: &[Stored]| {
        let mut cfg = file.clone();
        super::appliers::overlay_with(&mut cfg, file, e, None, &defs, "pi-a", false);
        cfg.telemetry.dnstap
    };
    // The entry as an ordinary write leaves it: a sampling change and a feed, no reader.
    let value = json!({"sample_every": 5, "resolver": true});
    // The files have no tap: a feed with no target copies nothing, so it is applied.
    let none = Config::default();
    assert!(run(&none, &entry("narrowed", value.clone())).resolver);
    // The files then add a socket: the feed would copy exchanges nobody confirmed.
    let mut with_tap = Config::default();
    with_tap.telemetry.dnstap.socket = Some("/run/x.sock".into());
    with_tap.file_set.push("telemetry.dnstap.socket".to_owned());
    let d = run(&with_tap, &entry("narrowed", value.clone()));
    assert!(!d.resolver && d.sample_every == 1, "not applied: {d:?}");
    assert_eq!(d.socket.as_deref(), Some("/run/x.sock"));
    // A reviewed entry with no reader confirmed nothing for the file's socket (T40.13, review 5): it
    // is not applied either.
    assert!(!run(&with_tap, &entry("staged", value)).resolver);
    // One that was confirmed with the file's own socket is applied.
    let same = json!({"socket": "/run/x.sock", "resolver": true});
    assert!(run(&with_tap, &entry("staged", same)).resolver);
}

// REQ: OBS-007, API-905 (T40.13, review) - the file had the tap on, an admin narrowed the sampling by
// an ordinary write (an entry with no reader, `narrowed`), then the file took the tap out and added a
// feed: at the next start nothing is applied that copies more than the files (no tap, no feed), the
// entry is dropped, and the drop is audited as a rollback.
#[test]
fn obs_007_dnstap_restart_drops_an_unconfirmed_entry_the_files_now_widen() {
    let (_dir, mut cfg) = dir_with(&[]);
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    store::put(
        &state,
        &Stored {
            node: "pi-a".into(),
            id: "dnstap-output".into(),
            value: json!({"sample_every": 5, "buffer": 10000, "forwarder": false, "resolver": true}),
            mode: "narrowed".into(),
            state: EntryState::Staged,
            by: "alice".into(),
            at: 1,
        },
        1,
        "alice",
    )
    .unwrap();
    // The files now set a socket: the entry's feed would copy what nobody confirmed.
    cfg.telemetry.dnstap.socket = Some("/run/x.sock".into());
    cfg.file_set.push("telemetry.dnstap.socket".to_owned());
    let b = begin(&cfg);
    assert!(b.on_probation.is_empty(), "{b:?}");
    assert!(entries_of(&cfg).is_empty(), "dropped");
    let audits = state
        .audit_page(None, 10, Some("settings.guarded_rolled_back"), None)
        .unwrap();
    assert_eq!(audits.len(), 1);
    assert!(audits[0].detail.contains("would_widen"));
}

// REQ: OBS-007, API-905 (T40.13, review 7) - the files never widen a confirmed entry: a file that
// adds a feed or a faster sampling (no reader) after the entry was confirmed does not turn them on
// for the entry's reader.
#[test]
fn obs_007_dnstap_a_file_edit_never_widens_a_confirmed_entry() {
    let defs = vec![RowDef {
        row: *wrendns_config::guarded::row(wrendns_config::guarded::DNSTAP).unwrap(),
        applier: Arc::new(super::dnstap::Dnstap),
    }];
    let e = vec![Stored {
        node: "pi-a".into(),
        id: "dnstap-output".into(),
        value: json!({"socket": "/a", "sample_every": 10}),
        mode: "staged".into(),
        state: EntryState::Active,
        by: "alice".into(),
        at: 1,
    }];
    let mut file = Config::default();
    file.telemetry.dnstap.forwarder = true;
    file.telemetry.dnstap.sample_every = 1;
    file.file_set.push("telemetry.dnstap.forwarder".to_owned());
    file.file_set
        .push("telemetry.dnstap.sample_every".to_owned());
    let mut cfg = file.clone();
    super::appliers::overlay_with(&mut cfg, &file, &e, None, &defs, "pi-a", false);
    let d = &cfg.telemetry.dnstap;
    assert!(
        d.socket.is_none() && !(d.forwarder && d.socket.is_some()),
        "nothing is copied to /a that was not confirmed: {d:?}"
    );
    // A file that only repeats what was confirmed leaves the entry applied.
    let mut same = Config::default();
    same.telemetry.dnstap.sample_every = 10;
    same.file_set
        .push("telemetry.dnstap.sample_every".to_owned());
    let mut cfg = same.clone();
    super::appliers::overlay_with(&mut cfg, &same, &e, None, &defs, "pi-a", false);
    assert_eq!(cfg.telemetry.dnstap.socket.as_deref(), Some("/a"));
    assert_eq!(cfg.telemetry.dnstap.sample_every, 10);
}

// REQ: OBS-007, API-905 (T40.13, review 7) - a start never deletes a confirmed entry: a file reader
// that displaces it only keeps it from being applied, and it comes back when the file stops.
#[test]
fn obs_007_dnstap_restart_keeps_a_confirmed_entry_a_file_reader_displaces() {
    let (_dir, mut cfg) = dir_with(&[(
        "dnstap-output",
        json!({"socket": "/a", "forwarder": true}),
        EntryState::Active,
    )]);
    let files = cfg.clone();
    cfg.telemetry.dnstap.socket = Some("/f".into());
    cfg.file_set.push("telemetry.dnstap.socket".to_owned());
    let b = begin(&cfg);
    assert!(b.on_probation.is_empty(), "{b:?}");
    assert_eq!(entries_of(&cfg).len(), 1, "the confirmed entry stays");
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    assert!(
        state
            .audit_page(None, 10, Some("settings.guarded_rolled_back"), None)
            .unwrap()
            .is_empty()
    );
    // The file reader goes away: the entry is applied again.
    let defs = vec![RowDef {
        row: *wrendns_config::guarded::row(wrendns_config::guarded::DNSTAP).unwrap(),
        applier: Arc::new(super::dnstap::Dnstap),
    }];
    let mut back = files.clone();
    super::appliers::overlay_with(
        &mut back,
        &files,
        &entries_of(&files),
        None,
        &defs,
        "pi-a",
        false,
    );
    assert_eq!(back.telemetry.dnstap.socket.as_deref(), Some("/a"));
    assert!(back.telemetry.dnstap.forwarder);
}

// REQ: OBS-007, API-905 (T40.13, review 9) - a confirmed entry that is still Staged and that the
// file displaces at the start is not "pending a restart": an outcome and an audit record say it was
// kept but not applied, and the listing marks it displaced.
#[test]
fn obs_007_dnstap_staged_entry_a_file_reader_displaces_is_recorded_not_pending() {
    let (_dir, mut cfg) = dir_with(&[(
        "dnstap-output",
        json!({"socket": "/a", "forwarder": true}),
        EntryState::Staged,
    )]);
    cfg.telemetry.dnstap.socket = Some("/b".into());
    cfg.file_set.push("telemetry.dnstap.socket".to_owned());
    let b = begin(&cfg);
    assert!(b.on_probation.is_empty(), "{b:?}");
    let state = State::open(&crate::managed::state_path(&cfg)).unwrap();
    let outs = store::outcomes(&state);
    assert!(
        outs.iter().any(|o| o.setting == "dnstap-output"
            && o.outcome == "not_applied"
            && o.reason.as_deref() == Some("file_displaces")),
        "{outs:?}"
    );
    assert_eq!(
        state
            .audit_page(None, 10, Some("settings.guarded_not_applied"), None)
            .unwrap()
            .len(),
        1
    );
    // A second start says it once.
    begin(&cfg);
    assert_eq!(store::outcomes(&state).len(), outs.len());
    // The entry stays, and the engine does not list it as pending a restart.
    let held = entries_of(&cfg);
    assert_eq!(held.len(), 1);
    assert!(super::dnstap::not_applied(
        &cfg,
        &held[0].mode,
        &held[0].value
    ));
}

// REQ: OBS-007, API-905 (T40.13, review 9) - the listing does not say "restart needed" for a staged
// dnstap entry the file displaces.
#[tokio::test]
async fn obs_007_dnstap_displaced_staged_entry_is_not_listed_pending_restart() {
    let n = solo();
    let a = admin("alice", 5);
    let v = json!({"socket": "/a", "forwarder": true});
    let p = preview(&n.engine, &a, "dnstap-output", v.clone())
        .await
        .unwrap();
    n.engine
        .apply(&a, "dnstap-output", apply_req(&p, v))
        .await
        .unwrap();
    assert_eq!(
        n.engine.status_local().pending_restart,
        vec!["dnstap-output".to_owned()]
    );
    // The file gains another reader before the restart.
    let mut file = Config::default();
    file.telemetry.dnstap.socket = Some("/b".into());
    file.file_set.push("telemetry.dnstap.socket".to_owned());
    *n.host.file_cfg.lock().unwrap() = Arc::new(file);
    let st = n.engine.status_local();
    assert!(st.pending_restart.is_empty(), "{st:?}");
    let s = st
        .settings
        .iter()
        .find(|s| s.id == "dnstap-output")
        .unwrap();
    assert!(s.displaced_by_file && !s.pending_restart && s.has_entry);
}

// REQ: OBS-007, API-905 (T40.13, review 10) - an ordinary (narrowed) dnstap entry the file outgrows is
// dropped at the next start, so the status says that and not "displaced" (kept until the file changes
// back), and does not list it as pending a restart.
#[tokio::test]
async fn obs_007_dnstap_a_narrowed_entry_the_file_outgrows_is_dropped_not_displaced() {
    let n = solo();
    store::put(
        &n.host.state,
        &Stored {
            node: "pi-a".into(),
            id: "dnstap-output".into(),
            value: json!({"sample_every": 10, "forwarder": true}),
            mode: "narrowed".into(),
            state: EntryState::Staged,
            by: "bob".into(),
            at: 7,
        },
        7,
        "bob",
    )
    .unwrap();
    let mut file = Config::default();
    file.telemetry.dnstap.socket = Some("/f".into());
    file.file_set.push("telemetry.dnstap.socket".to_owned());
    *n.host.file_cfg.lock().unwrap() = Arc::new(file);
    let st = n.engine.status_local();
    assert!(st.pending_restart.is_empty(), "{st:?}");
    let s = st
        .settings
        .iter()
        .find(|s| s.id == "dnstap-output")
        .unwrap();
    assert!(
        s.dropped_at_next_start && !s.displaced_by_file && !s.pending_restart && s.has_entry,
        "{s:?}"
    );
}

// REQ: OBS-007, API-905 (T40.13, review 7) - a replica's phrase-confirmed write is refused with
// `preview_stale` when the primary holds an entry the replica had not seen (an ordinary narrowing
// answered with success meanwhile), and goes through when it saw the same one.
#[tokio::test(start_paused = true)]
async fn obs_007_dnstap_a_confirmed_write_does_not_overwrite_an_unseen_narrowing() {
    let (a, b, _c) = cluster();
    let alice = admin("alice", 5);
    let v = json!({"socket": "/a"});
    let p = preview_for(&b.engine, &alice, "pi-b", "dnstap-output", v.clone())
        .await
        .unwrap();
    // Meanwhile an ordinary write stored an entry on the primary.
    store::put(
        &a.host.state,
        &Stored {
            node: "pi-b".into(),
            id: "dnstap-output".into(),
            value: json!({"sample_every": 5}),
            mode: "narrowed".into(),
            state: EntryState::Staged,
            by: "bob".into(),
            at: 7,
        },
        7,
        "bob",
    )
    .unwrap();
    let e = apply_for(&b.engine, &alice, "pi-b", "dnstap-output", &p, v.clone())
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::PreviewStale, "{e:?}");
    let held = store::for_node(&a.host.state, "pi-b");
    assert_eq!(held[0].mode, "narrowed", "the narrowing is still there");
    let w = |expect_at| super::prod::EntryWrite {
        node: "pi-b".into(),
        id: "dnstap-output".into(),
        entry: None,
        by: "x".into(),
        check: true,
        expect_at,
    };
    assert!(super::prod::entry_stale(held.first(), &w(None)));
    assert!(!super::prod::entry_stale(held.first(), &w(Some(7))));
    assert!(!super::prod::entry_stale(None, &w(None)));
}

fn dnstap_entry(node: &str, value: Value, at: u64) -> Stored {
    Stored {
        node: node.into(),
        id: "dnstap-output".into(),
        value,
        mode: "staged".into(),
        state: EntryState::Active,
        by: "bob".into(),
        at,
    }
}

// REQ: OBS-007, API-905 (T40.13, review 8) - a review is judged on the node's entry as the admin saw
// it: when that entry is deleted by an ordinary narrowing (answered with success) after the preview,
// the confirm is `preview_stale` even though the replica's own version did not move and the section
// the node will run is the same, and the stored entry is not rewritten.
#[tokio::test(start_paused = true)]
async fn obs_007_dnstap_a_confirm_after_the_entry_was_removed_is_stale() {
    let (a, b, _c) = cluster();
    let alice = admin("alice", 5);
    let e1 = dnstap_entry("pi-b", json!({"socket": "/a"}), 100);
    store::put(&a.host.state, &e1, 100, "bob").unwrap();
    store::put(&b.host.state, &e1, 100, "bob").unwrap();
    let mut pending = Config::default();
    pending.telemetry.dnstap.socket = Some("/a".into());
    *b.host.pending.lock().unwrap() = Some(Arc::new(pending));
    let v = json!({"socket": "/a"});
    let p = preview_for(&b.engine, &alice, "pi-b", "dnstap-output", v.clone())
        .await
        .unwrap();
    assert!(!p.weakening, "the same tap: no widening at preview");
    // An ordinary narrowing removes the entry meanwhile; the section the node runs is unchanged here.
    store::delete(&a.host.state, "pi-b", "dnstap-output").unwrap();
    store::delete(&b.host.state, "pi-b", "dnstap-output").unwrap();
    let e = apply_for(&b.engine, &alice, "pi-b", "dnstap-output", &p, v)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::PreviewStale, "{e:?}");
    assert!(store::for_node(&a.host.state, "pi-b").is_empty());
}

// REQ: OBS-007, API-905 (T40.13, review 8) - the same for the section the node will run (a file edit
// and reload do not move the version): a confirm after it changed is `preview_stale`, also when it
// still widens.
#[tokio::test(start_paused = true)]
async fn obs_007_dnstap_a_confirm_after_the_pending_section_changed_is_stale() {
    let n = solo();
    let a = admin("alice", 5);
    let v = json!({"socket": "/a"});
    let p = preview(&n.engine, &a, "dnstap-output", v.clone())
        .await
        .unwrap();
    assert!(p.weakening);
    let mut now = Config::default();
    now.telemetry.dnstap.socket = Some("/b".into());
    *n.host.pending.lock().unwrap() = Some(Arc::new(now));
    let e = n
        .engine
        .apply(&a, "dnstap-output", apply_req(&p, v.clone()))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::PreviewStale, "{e:?}");
    // A fresh review on the new state goes through.
    let p = preview(&n.engine, &a, "dnstap-output", v.clone())
        .await
        .unwrap();
    n.engine
        .apply(&a, "dnstap-output", apply_req(&p, v))
        .await
        .unwrap();
}

// REQ: OBS-007, API-905 (T40.13, review 8) - the review of a widening that carries a field the files
// set says the node keeps the saved values whatever the file later does; and a confirmed entry that
// holds the file's reader keeps it when the file drops its section (pinned: it was named in the
// phrase the admin typed).
#[tokio::test(start_paused = true)]
async fn obs_007_dnstap_review_names_the_file_values_it_saves() {
    let n = solo();
    let a = admin("alice", 5);
    let mut file = Config::default();
    file.telemetry.dnstap.socket = Some("/run/f.sock".into());
    file.file_set.push("telemetry.dnstap.socket".to_owned());
    *n.host.file_cfg.lock().unwrap() = Arc::new(file.clone());
    *n.host.cfg.lock().unwrap() = Arc::new(file.clone());
    let v = json!({"socket": "/run/f.sock", "forwarder": true});
    let p = preview(&n.engine, &a, "dnstap-output", v.clone())
        .await
        .unwrap();
    assert!(
        p.warnings
            .iter()
            .any(|w| w.contains("config file sets socket") && w.contains("the file's value wins")),
        "{:?}",
        p.warnings
    );
    n.engine
        .apply(&a, "dnstap-output", apply_req(&p, v))
        .await
        .unwrap();
    // After the restart the staged entry is in force.
    let mut held = store::for_node(&n.host.state, "pi-a");
    assert_eq!(held.len(), 1);
    held[0].state = EntryState::Active;
    let defs = vec![RowDef {
        row: *wrendns_config::guarded::row(wrendns_config::guarded::DNSTAP).unwrap(),
        applier: Arc::new(super::dnstap::Dnstap),
    }];
    // The file drops its section: the node keeps what was confirmed with the phrase.
    let none = Config::default();
    let mut cfg = none.clone();
    super::appliers::overlay_with(&mut cfg, &none, &held, None, &defs, "pi-a", false);
    assert_eq!(cfg.telemetry.dnstap.socket.as_deref(), Some("/run/f.sock"));
    assert!(cfg.telemetry.dnstap.forwarder);
}

/// REQ: OBS-007, API-905 (T40.13, review 9) - the warning says the file's value wins while the
/// file sets a field: after the file changes the socket, the node runs the file's socket and no
/// forwarder (the confirmed entry would copy more than both sides), not the confirmed values.
#[tokio::test]
async fn obs_007_dnstap_file_value_wins_over_a_confirmed_entry_when_the_file_changes() {
    let n = solo();
    let a = admin("alice", 5);
    let mut file = Config::default();
    file.telemetry.dnstap.socket = Some("/run/f.sock".into());
    file.file_set.push("telemetry.dnstap.socket".to_owned());
    *n.host.file_cfg.lock().unwrap() = Arc::new(file.clone());
    *n.host.cfg.lock().unwrap() = Arc::new(file.clone());
    let v = json!({"socket": "/run/f.sock", "forwarder": true});
    let p = preview(&n.engine, &a, "dnstap-output", v.clone())
        .await
        .unwrap();
    n.engine
        .apply(&a, "dnstap-output", apply_req(&p, v))
        .await
        .unwrap();
    let mut held = store::for_node(&n.host.state, "pi-a");
    held[0].state = EntryState::Active;
    let defs = vec![RowDef {
        row: *wrendns_config::guarded::row(wrendns_config::guarded::DNSTAP).unwrap(),
        applier: Arc::new(super::dnstap::Dnstap),
    }];
    let mut changed = Config::default();
    changed.telemetry.dnstap.socket = Some("/run/g.sock".into());
    changed.file_set.push("telemetry.dnstap.socket".to_owned());
    let mut cfg = changed.clone();
    super::appliers::overlay_with(&mut cfg, &changed, &held, None, &defs, "pi-a", false);
    assert_eq!(cfg.telemetry.dnstap.socket.as_deref(), Some("/run/g.sock"));
    assert!(!cfg.telemetry.dnstap.forwarder);
}

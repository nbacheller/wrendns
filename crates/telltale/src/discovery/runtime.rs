//! REQ: DSC-001, DSC-002, DSC-014 (T25.2, T25.3, ADR-907, ADR-908, ADR-925) — the network inventory
//! on this node: whether it runs here, its `telltale-inventory` thread, and the discovery workers
//! that thread supervises. Started and stopped by [`Runtime::reconcile`] at start-up and on every
//! reload, so `[discovery] enabled` and `node` take effect without a restart. Off by default: when
//! the node isn't designated, or the section is off, no thread and no worker exists.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;
use telltale_api::model::{DiscoveryStatus, DiscoveryWorker};
use telltale_config::{Config, DiscoveryConfig};

use super::gate::{self, Me};
use super::poller::{self, AgentsBoard, PollerCtx};
use super::snmp_job::OP_PROBE;
use super::supervisor::{Board, Requests, Spec};
use super::thread::{self, Providers, SnmpSetup};
use crate::devices::Leases;

/// Who this node is, owned, so the gate can borrow it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Own {
    pub(crate) node_id: String,
    pub(crate) name: String,
    pub(crate) primary: bool,
    pub(crate) ephemeral: bool,
    pub(crate) witness: bool,
}

/// This node, as the gate sees it: a cluster member's identity and role, or the standalone node
/// (which is its own primary).
pub(crate) fn own_of(cluster: Option<&telltale_cluster::net::Cluster>, cfg: &Config) -> Own {
    let name = crate::http::node_name(cfg);
    match cluster {
        Some(c) => Own {
            node_id: c.identity.meta.node_id.clone(),
            name,
            primary: c.is_primary(),
            ephemeral: c.is_ephemeral(),
            witness: c.identity.meta.witness,
        },
        None => Own {
            node_id: name.clone(),
            name,
            primary: true,
            ephemeral: false,
            witness: false,
        },
    }
}

impl Own {
    pub(crate) fn me(&self) -> Me<'_> {
        Me {
            node_id: &self.node_id,
            name: &self.name,
            primary: self.primary,
            ephemeral: self.ephemeral,
            witness: self.witness,
        }
    }
}

/// A running inventory: its thread, the section it was started with, and the flag that stops its
/// workers.
struct Running {
    handle: thread::Handle,
    section: DiscoveryConfig,
    workers_stop: Arc<AtomicBool>,
}

/// The network inventory's runtime on this node.
pub(crate) struct Runtime {
    /// Whether discovery is on here, and whether this node is the designated one.
    header: ArcSwap<(bool, bool, Option<String>)>,
    /// The workers' state, written by their supervisors and read by the API and metrics.
    board: Board,
    /// Jobs queued for the SNMP worker: the poller's polls and the Test button's probes.
    requests: Requests,
    /// REQ: DSC-004 (T25.6) - the SNMP agents' board: each agent's last poll and capability record.
    agents: Arc<AgentsBoard>,
    /// The poller's configuration while it runs (the Test button reads agents from it).
    test_ctx: ArcSwap<Option<Arc<PollerCtx>>>,
    running: Mutex<Option<Running>>,
    /// The last generation handed out by [`Runtime::next_generation`].
    generation: AtomicU64,
    /// The newest generation applied so far. A reconcile that started earlier than it is skipped.
    applied: Mutex<u64>,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("discovery::Runtime")
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            header: ArcSwap::from_pointee((false, false, None)),
            board: Arc::new(ArcSwap::from_pointee(Vec::new())),
            requests: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            agents: Arc::new(AgentsBoard::default()),
            test_ctx: ArcSwap::from_pointee(None),
            running: Mutex::new(None),
            generation: AtomicU64::new(0),
            applied: Mutex::new(0),
        }
    }
}

impl Runtime {
    /// The status the API shows: enabled, designated, and each worker.
    pub(crate) fn status(&self) -> DiscoveryStatus {
        let (enabled, designated, node) = (**self.header.load()).clone();
        DiscoveryStatus {
            enabled,
            designated,
            node,
            workers: (**self.board.load()).clone(),
            agents: self.agents.snapshot(),
        }
    }

    /// The worker board, for tests.
    #[cfg(test)]
    pub(crate) fn board(&self) -> Board {
        Arc::clone(&self.board)
    }

    /// The agents' board, for tests.
    #[cfg(test)]
    pub(crate) fn agents_for_tests(&self) -> Arc<AgentsBoard> {
        Arc::clone(&self.agents)
    }

    /// Sets the runtime up as a designated node that runs the poller's side, without starting the
    /// thread or a worker: a test stands in for the worker and answers the queue (T25.6).
    #[cfg(test)]
    pub(crate) fn designate_for_tests(&self, cfg: &Config) {
        self.header.store(Arc::new((true, true, None)));
        let ctx = Arc::new(PollerCtx::of(cfg));
        self.agents.configure(&ctx.agents);
        self.test_ctx.store(Arc::new(Some(ctx)));
        self.board.store(Arc::new(vec![DiscoveryWorker {
            worker: "snmp".to_owned(),
            up: true,
            ..DiscoveryWorker::default()
        }]));
    }

    /// The jobs queue of the SNMP worker, for tests.
    #[cfg(test)]
    pub(crate) fn requests(&self) -> Requests {
        Arc::clone(&self.requests)
    }

    /// REQ: DSC-001 — a new generation for one reconcile. It is taken where the reload is handled,
    /// not where the reconcile runs, so reconciles that run late can be ordered (see [`reconcile`]).
    pub(crate) fn next_generation(&self) -> u64 {
        self.generation
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1)
    }

    /// Starts, stops or restarts the inventory so that it runs exactly when the configuration
    /// says this node should run it (DSC-001). `routers` and `mdns` are the lease views the thread
    /// reads; `None` leaves a source out.
    ///
    /// REQ: DSC-001 (ADR-928) — reconciles run one at a time, and a reconcile whose `generation` is
    /// older than the newest applied one is skipped: two quick reloads (on, then off) can't leave
    /// the inventory running when the configuration says off.
    pub(crate) fn reconcile(
        &self,
        generation: u64,
        cfg: &Config,
        data_dir: &Path,
        own: &Own,
        routers: Option<Arc<ArcSwap<Leases>>>,
        mdns: Option<Arc<ArcSwap<Leases>>>,
    ) {
        let mut applied = self.applied.lock().unwrap_or_else(PoisonError::into_inner);
        if generation < *applied {
            return;
        }
        *applied = generation;
        let me = own.me();
        let want = gate::should_run(&cfg.discovery, me);
        let designated = gate::designated(&cfg.discovery, me);
        self.header.store(Arc::new((
            cfg.discovery.enabled,
            designated,
            cfg.discovery.node.as_ref().map(|n| n.as_str().to_owned()),
        )));
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(r) = running.as_ref()
            && want
            && r.section == cfg.discovery
        {
            return;
        }
        if let Some(r) = running.take() {
            stop_running(r, &self.board);
        }
        self.agents.clear();
        self.test_ctx.store(Arc::new(None));
        if !want {
            return;
        }
        // REQ: DSC-004 - the poller's configuration and the agents' board, set before the thread
        // starts so the first status already lists the agents.
        let ctx = Arc::new(PollerCtx::of(cfg));
        self.agents.configure(&ctx.agents);
        self.test_ctx.store(Arc::new(Some(Arc::clone(&ctx))));
        let snmp = (!ctx.agents.is_empty()).then(|| SnmpSetup {
            ctx: Arc::clone(&ctx),
            board: Arc::clone(&self.agents),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let providers = Providers {
            routers,
            mdns,
            subnets: cfg
                .discovery
                .subnets
                .iter()
                .filter_map(|s| super::sources::Ipv4Subnet::parse(&s.cidr.to_string()))
                .collect(),
            neighbours: true,
            ifindex_root: None,
            workers: vec![Spec::snmp(cfg.discovery.worker_memory_mib)],
            board: Some(Arc::clone(&self.board)),
            requests: Arc::clone(&self.requests),
            workers_stop: Arc::clone(&stop),
            snmp,
        };
        match thread::spawn(data_dir.to_path_buf(), providers) {
            Ok(handle) => {
                tracing::info!(node = %own.node_id, "network inventory started on this node");
                *running = Some(Running {
                    handle,
                    section: cfg.discovery.clone(),
                    workers_stop: stop,
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "network inventory could not start; DNS is unaffected");
            }
        }
    }

    /// Stops the inventory, if it runs (shutdown).
    pub(crate) fn stop(&self) {
        self.agents.clear();
        self.test_ctx.store(Arc::new(None));
        let r = self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(r) = r {
            stop_running(r, &self.board);
        }
    }

    /// The Prometheus series of the workers (DSC-014): `telltale_discovery_worker_up` and
    /// `telltale_discovery_worker_restarts_total`, one sample per worker. Nothing when no worker
    /// has started on this node.
    pub(crate) fn render_metrics(&self, w: &mut telltale_telemetry::prom::PromWriter) {
        let board = self.board.load();
        self.render_agent_metrics(w);
        if board.is_empty() {
            return;
        }
        w.family(
            "telltale_discovery_worker_up",
            "gauge",
            "Whether a discovery worker process is running and answered its handshake.",
        );
        for x in board.iter() {
            w.sample(
                "telltale_discovery_worker_up",
                &[("worker", &x.worker)],
                u8::from(x.up),
            );
        }
        w.family(
            "telltale_discovery_worker_restarts_total",
            "counter",
            "Times a discovery worker process has been restarted.",
        );
        for x in board.iter() {
            w.sample(
                "telltale_discovery_worker_restarts_total",
                &[("worker", &x.worker)],
                x.restarts,
            );
        }
    }
}

impl Runtime {
    /// REQ: DSC-014 (T25.6) - the infrastructure poller's series, one sample per agent (and per
    /// table): whether the last poll worked, polls and failures, when it last worked, how long it
    /// took, and the rows it read. Nothing when no agent is configured.
    fn render_agent_metrics(&self, w: &mut telltale_telemetry::prom::PromWriter) {
        let agents = self.agents.snapshot();
        if agents.is_empty() {
            return;
        }
        w.family(
            "telltale_discovery_agent_up",
            "gauge",
            "Whether the last SNMP poll of an agent worked (1) or failed or hasn't run (0).",
        );
        for a in &agents {
            w.sample(
                "telltale_discovery_agent_up",
                &[("agent", &a.name)],
                u8::from(a.state == "ok"),
            );
        }
        w.family(
            "telltale_discovery_agent_polls_total",
            "counter",
            "SNMP polls made of an agent since start.",
        );
        for a in &agents {
            w.sample(
                "telltale_discovery_agent_polls_total",
                &[("agent", &a.name)],
                a.polls,
            );
        }
        w.family(
            "telltale_discovery_agent_poll_failures_total",
            "counter",
            "SNMP polls of an agent that failed since start.",
        );
        for a in &agents {
            w.sample(
                "telltale_discovery_agent_poll_failures_total",
                &[("agent", &a.name)],
                a.failures,
            );
        }
        w.family(
            "telltale_discovery_agent_last_success_timestamp_seconds",
            "gauge",
            "When an SNMP poll of an agent last worked (Unix seconds); 0 when it never has.",
        );
        for a in &agents {
            w.sample(
                "telltale_discovery_agent_last_success_timestamp_seconds",
                &[("agent", &a.name)],
                a.last_success_unix.unwrap_or(0),
            );
        }
        w.family(
            "telltale_discovery_agent_poll_duration_seconds",
            "gauge",
            "How long the last SNMP poll of an agent took.",
        );
        for a in &agents {
            #[allow(clippy::cast_precision_loss)]
            let secs = (a.last_duration_ms.unwrap_or(0) as f64) / 1000.0;
            w.sample(
                "telltale_discovery_agent_poll_duration_seconds",
                &[("agent", &a.name)],
                secs,
            );
        }
        w.family(
            "telltale_discovery_agent_table_rows",
            "gauge",
            "Rows the last SNMP poll read from a table of an agent.",
        );
        for a in &agents {
            for t in &a.tables {
                w.sample(
                    "telltale_discovery_agent_table_rows",
                    &[("agent", &a.name), ("table", &t.table)],
                    t.rows.unwrap_or(0),
                );
            }
        }
        if agents
            .iter()
            .all(|a| a.tables.iter().all(|t| t.state == "unprobed"))
        {
            return;
        }
        w.family(
            "telltale_discovery_agent_table_answered",
            "gauge",
            "Whether an agent answered a table when it was probed (1), or not (0); absent until probed.",
        );
        for a in &agents {
            for t in a.tables.iter().filter(|t| t.state != "unprobed") {
                w.sample(
                    "telltale_discovery_agent_table_answered",
                    &[("agent", &a.name), ("table", &t.table)],
                    u8::from(t.state == "answered"),
                );
            }
        }
    }

    /// REQ: DSC-004 (T25.6, ADR-1002) - **Test**: probes one configured agent now, or with
    /// `dry_run` lists the OIDs it would query. The agent is named, never addressed. A test waits
    /// 60 s after the last test of the same agent. The probe is queued ahead of the polls and run
    /// by the SNMP worker; its capability record replaces the agent's.
    #[allow(clippy::too_many_lines)] // one flow: gate, dry run, cooldown, probe, record
    pub(crate) async fn snmp_test(
        &self,
        w: telltale_api::SnmpTestWrite,
    ) -> Result<telltale_api::model::SnmpTestResult, telltale_api::problem::Problem> {
        use telltale_api::model::SnmpTestResult;
        use telltale_api::problem::{Code, Problem};
        let (enabled, designated, node) = (**self.header.load()).clone();
        let ctx = self.test_ctx.load_full();
        let (true, Some(ctx)) = (enabled && designated, ctx.as_ref().as_ref()) else {
            return Err(telltale_api::discovery_api::not_here(
                enabled,
                node.as_deref(),
            ));
        };
        let Some(agent) = ctx.agent(&w.agent) else {
            let names: Vec<&str> = ctx.agents.iter().map(|a| a.name.as_str()).collect();
            let hint = if names.is_empty() {
                "No SNMP agents are configured: add one in Settings, Network inventory.".to_owned()
            } else {
                format!("Agents: {}.", names.join(", "))
            };
            return Err(
                Problem::not_found(format!("no SNMP agent named `{}`", w.agent)).hint(hint),
            );
        };
        let made = SnmpTestResult {
            agent: w.agent.clone(),
            dry_run: w.dry_run,
            ok: true,
            oids: poller::test_oids(agent),
            capability: None,
            error: None,
            duration_ms: None,
            node: node.clone(),
            note: String::new(),
        };
        if w.dry_run {
            return Ok(SnmpTestResult {
                note: "Nothing was sent (dry run). A test sends one GETNEXT on the first column of each table listed, and one GET of sysObjectID; the first alternative of a part that answers is used.".to_owned(),
                ..made
            });
        }
        let now = unix_now();
        if let Err(wait) = self.agents.begin_test(&w.agent, now) {
            return Err(Problem::new(
                Code::RateLimited,
                format!("`{}` was tested less than a minute ago", w.agent),
            )
            .hint(format!("Try again in {wait} seconds."))
            .retry_after(wait));
        }
        if !self.board.load().iter().any(|x| x.worker == "snmp" && x.up) {
            return Err(Problem::unavailable(
                "the SNMP worker isn't running (it restarts with a delay after a crash)",
            )
            .hint("Settings, Network inventory shows the worker's state."));
        }
        let started = std::time::Instant::now();
        let ctx = Arc::clone(ctx);
        let name = w.agent.clone();
        let req = tokio::task::spawn_blocking(move || {
            let agent = ctx.agent(&name).cloned();
            agent.map(|a| ctx.request(&a, None))
        })
        .await
        .ok()
        .flatten();
        let ms = |t: std::time::Instant| u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX);
        let fail = |why: String, t: std::time::Instant| SnmpTestResult {
            ok: false,
            error: Some(why),
            duration_ms: Some(ms(t)),
            note: "The test failed: the poller keeps its earlier capability record.".to_owned(),
            ..made.clone()
        };
        let req = match req {
            Some(Ok(r)) => r,
            Some(Err(why)) => return Ok(fail(why, started)),
            None => {
                return Ok(fail(
                    "the agent is no longer configured".to_owned(),
                    started,
                ));
            }
        };
        let reply = match poller::run_job(
            &self.requests,
            OP_PROBE,
            req,
            true,
            std::time::Duration::from_secs(90),
        )
        .await
        {
            Ok(r) => r,
            Err(why) => return Ok(fail(why, started)),
        };
        let Some(result) = reply.result.snmp.as_ref().filter(|_| reply.result.ok) else {
            let why = reply
                .result
                .error
                .clone()
                .unwrap_or_else(|| "the agent did not answer".to_owned());
            return Ok(fail(why, started));
        };
        let capability = self.agents.record_probe(&w.agent, result, unix_now());
        Ok(SnmpTestResult {
            capability,
            duration_ms: Some(ms(started)),
            note: "Capabilities updated: the poller reads the tables that answered, and skips the others until the next test.".to_owned(),
            ..made
        })
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Stops a running inventory: its workers first, then its thread (which saves and exits).
fn stop_running(r: Running, board: &Board) {
    r.workers_stop.store(true, Ordering::Release);
    r.handle.stop();
    board.store(Arc::new(Vec::<DiscoveryWorker>::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DSC-001 (`dsc_001_off_by_default_starts_nothing`) — a node with the section off reports
    /// it off and starts no thread, so the status has no workers.
    #[test]
    fn dsc_001_off_by_default_starts_nothing() {
        let rt = Runtime::default();
        let dir = tempfile::tempdir().unwrap();
        let own = Own {
            node_id: "n".into(),
            name: "n".into(),
            primary: true,
            ephemeral: false,
            witness: false,
        };
        let generation = rt.next_generation();
        rt.reconcile(generation, &Config::default(), dir.path(), &own, None, None);
        let s = rt.status();
        assert!(!s.enabled);
        assert!(
            s.designated,
            "the standalone node would run it if it were enabled"
        );
        assert!(s.workers.is_empty(), "no worker starts while it is off");
        assert!(!dir.path().join("inventory.json").exists());
    }

    /// REQ: DSC-001 (`dsc_001_reconciles_apply_in_order`, ADR-928) — two reloads whose reconciles run
    /// out of order: the older one (on) arrives last and is skipped, so the newer (off) stands.
    #[test]
    fn dsc_001_reconciles_apply_in_order() {
        let rt = Runtime::default();
        let dir = tempfile::tempdir().unwrap();
        let own = Own {
            node_id: "n".into(),
            name: "n".into(),
            primary: true,
            ephemeral: false,
            witness: false,
        };
        let on = telltale_config::Loader::new()
            .toml_str("t", "[discovery]\nenabled = true\n")
            .load()
            .unwrap()
            .config;
        let g_on = rt.next_generation();
        let g_off = rt.next_generation();
        rt.reconcile(g_off, &Config::default(), dir.path(), &own, None, None);
        rt.reconcile(g_on, &on, dir.path(), &own, None, None);
        let s = rt.status();
        assert!(!s.enabled, "the older reconcile was skipped");
        assert!(s.workers.is_empty(), "nothing was started");
    }

    /// REQ: DSC-002 (DSC-014) — the metrics name each worker's up and restart series.
    #[test]
    fn dsc_002_metrics_name_each_worker() {
        let rt = Runtime::default();
        rt.board().store(Arc::new(vec![DiscoveryWorker {
            worker: "snmp".into(),
            up: true,
            restarts: 3,
            ..DiscoveryWorker::default()
        }]));
        let mut w = telltale_telemetry::prom::PromWriter::new();
        rt.render_metrics(&mut w);
        let out = w.finish();
        assert!(
            out.contains("telltale_discovery_worker_up{worker=\"snmp\"} 1"),
            "{out}"
        );
        assert!(
            out.contains("telltale_discovery_worker_restarts_total{worker=\"snmp\"} 3"),
            "{out}"
        );
    }
}

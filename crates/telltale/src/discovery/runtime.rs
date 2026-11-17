//! REQ: DSC-001, DSC-002, DSC-014 (T25.2, T25.3, ADR-907, ADR-908, ADR-925) — the network inventory
//! on this node: whether it runs here, its `telltale-inventory` thread, and the discovery workers
//! that thread supervises. Started and stopped by [`Runtime::reconcile`] at start-up and on every
//! reload, so `[discovery] enabled` and `node` take effect without a restart. Off by default: when
//! the node isn't designated, or the section is off, no thread and no worker exists.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;
use telltale_api::model::{DiscoveryStatus, DiscoveryWorker};
use telltale_config::{Config, DiscoveryConfig};

use super::gate::{self, Me};
use super::supervisor::{Board, Requests, Spec};
use super::thread::{self, Providers};
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
    /// Jobs queued for the SNMP worker (T25.4 queues its walks here).
    requests: Requests,
    running: Mutex<Option<Running>>,
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
            running: Mutex::new(None),
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
        }
    }

    /// The worker board, for tests.
    #[cfg(test)]
    pub(crate) fn board(&self) -> Board {
        Arc::clone(&self.board)
    }

    /// The jobs queue of the SNMP worker, for the tasks that queue jobs (T25.4) and for tests.
    pub(crate) fn requests(&self) -> Requests {
        Arc::clone(&self.requests)
    }

    /// Starts, stops or restarts the inventory so that it runs exactly when the configuration
    /// says this node should run it (DSC-001). `routers` and `mdns` are the lease views the thread
    /// reads; `None` leaves a source out.
    pub(crate) fn reconcile(
        &self,
        cfg: &Config,
        data_dir: &Path,
        own: &Own,
        routers: Option<Arc<ArcSwap<Leases>>>,
        mdns: Option<Arc<ArcSwap<Leases>>>,
    ) {
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
        if !want {
            return;
        }
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
        rt.reconcile(&Config::default(), dir.path(), &own, None, None);
        let s = rt.status();
        assert!(!s.enabled);
        assert!(
            s.designated,
            "the standalone node would run it if it were enabled"
        );
        assert!(s.workers.is_empty(), "no worker starts while it is off");
        assert!(!dir.path().join("inventory.json").exists());
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

//! REQ: DSC-901, DSC-906 (T31.2, ADR-1005 sections 1 and 13) - the CMDB on this node: whether it runs
//! here, its `telltale-cmdb` thread, the sink the feeds push to, its status and its metrics. Started
//! and stopped by [`Runtime::reconcile`] at start-up and on every reload, so `[cmdb] enabled` takes
//! effect without a restart. It runs on the node `[discovery]` designates (the named node, else the
//! primary or the standalone node, never an ephemeral pod or a witness), even when `[discovery]`
//! itself is off. With a **named** node down nothing runs and there is no failover; the CMDB's
//! writes answer 503 with a hint until an admin clears or changes the name, and DNS is unaffected.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

use arc_swap::ArcSwap;
use telltale_api::cmdb_api::{
    CmdbCaps, CmdbChange, CmdbCount, CmdbDropped, CmdbMove, CmdbOp, CmdbSourceStatus, CmdbStatus,
    CmdbWrite,
};
use telltale_api::problem::{Code, Problem};
use telltale_config::{CmdbConfig, Config};
use telltale_store::cmdb::CmdbDb;

use super::inbox::{Cmd, Inbox, SinkSlot};
use super::manual::{ManualError, ManualOp, RecRef};
use super::model::{MAX_CIS, MAX_RECORDS, MAX_RECORDS_PER_CI};
use super::thread::{self, Feeds, Snapshot};
use crate::discovery::gate::{self, Me};
use crate::discovery::runtime::Own;

/// What the reconcile knows about this node.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Header {
    enabled: bool,
    designated: bool,
    node: Option<String>,
}

struct Running {
    inbox: Arc<Inbox>,
    join: JoinHandle<()>,
    section: CmdbConfig,
}

/// The CMDB's runtime on this node.
pub(crate) struct Runtime {
    header: ArcSwap<Header>,
    /// Where the other feeds find the queue (empty while the CMDB doesn't run here).
    sink: Arc<SinkSlot>,
    snapshot: Arc<ArcSwap<Snapshot>>,
    /// The database while the thread runs, for the API's reads.
    db: Arc<ArcSwap<Option<Arc<CmdbDb>>>>,
    /// The configuration the thread reads once a minute (`config` records).
    cfg: Arc<ArcSwap<Config>>,
    /// The privacy level the API shows names at (0 or 1: the CMDB cannot be on above).
    level: Arc<AtomicU64>,
    running: Mutex<Option<Running>>,
    generation: AtomicU64,
    applied: Mutex<u64>,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cmdb::Runtime")
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            header: ArcSwap::from_pointee(Header::default()),
            sink: Arc::new(SinkSlot::default()),
            snapshot: Arc::new(ArcSwap::from_pointee(Snapshot::default())),
            db: Arc::new(ArcSwap::from_pointee(None)),
            cfg: Arc::new(ArcSwap::from_pointee(Config::default())),
            level: Arc::new(AtomicU64::new(0)),
            running: Mutex::new(None),
            generation: AtomicU64::new(0),
            applied: Mutex::new(0),
        }
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

impl Runtime {
    /// The queue the feeds push to (the discovery thread's SNMP, UniFi and Home Assistant reads).
    pub(crate) fn sink(&self) -> Arc<SinkSlot> {
        Arc::clone(&self.sink)
    }

    /// A new generation for one reconcile, taken where the reload is handled so that reconciles
    /// that run late can be ordered.
    pub(crate) fn next_generation(&self) -> u64 {
        self.generation
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1)
    }

    /// Starts, stops or restarts the CMDB so that it runs exactly when the configuration says this
    /// node should run it. Reconciles run one at a time, and one older than the newest applied is
    /// skipped (two quick reloads, on then off, cannot leave it running).
    pub(crate) fn reconcile(
        &self,
        generation: u64,
        cfg: &Config,
        data_dir: &Path,
        own: &Own,
        feeds: Feeds,
    ) {
        let mut applied = self.applied.lock().unwrap_or_else(PoisonError::into_inner);
        if generation < *applied {
            return;
        }
        *applied = generation;
        let me: Me<'_> = own.me();
        // The CMDB shares `[discovery]`'s gate: its node, else the primary, never a pod or a witness.
        let designated = gate::designated(&cfg.discovery, me);
        let want = cfg.cmdb.enabled && designated;
        self.header.store(Arc::new(Header {
            enabled: cfg.cmdb.enabled,
            designated,
            node: cfg.discovery.node.as_ref().map(|n| n.as_str().to_owned()),
        }));
        self.cfg.store(Arc::new(cfg.clone()));
        self.level.store(
            u64::from(cfg.telemetry.qlog.privacy_level),
            Ordering::Relaxed,
        );
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(r) = running.as_ref()
            && want
            && r.section == cfg.cmdb
        {
            // The configuration may have changed under it (a client, a subnet, an upstream): read
            // the feeds now, not at the next minute.
            r.inbox.command(Cmd::Tick);
            return;
        }
        if let Some(r) = running.take() {
            self.stop_running(r);
        }
        if !want {
            return;
        }
        let inbox = Arc::new(Inbox::default());
        let args = thread::Args {
            data_dir: data_dir.to_path_buf(),
            inbox: Arc::clone(&inbox),
            snapshot: Arc::clone(&self.snapshot),
            db: Arc::clone(&self.db),
            cfg: Arc::clone(&self.cfg),
            feeds,
            node: crate::http::node_name(cfg),
            clock: None,
        };
        match thread::spawn(args) {
            Ok(join) => {
                self.sink.set(Some(Arc::clone(&inbox)));
                tracing::info!(node = %own.node_id, "the CMDB started on this node");
                *running = Some(Running {
                    inbox,
                    join,
                    section: cfg.cmdb.clone(),
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "the CMDB could not start; DNS is unaffected");
            }
        }
    }

    fn stop_running(&self, r: Running) {
        // Feeds stop pushing first, then the thread flushes and exits, then the API's handle goes.
        self.sink.set(None);
        r.inbox.stop();
        let _ = r.join.join();
        self.db.store(Arc::new(None));
        self.snapshot.store(Arc::new(Snapshot::default()));
    }

    /// Stops the CMDB, if it runs (shutdown).
    pub(crate) fn stop(&self) {
        let r = self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(r) = r {
            self.stop_running(r);
        }
    }

    /// The database, while the CMDB runs here.
    pub(crate) fn db(&self) -> Option<Arc<CmdbDb>> {
        (**self.db.load()).clone()
    }

    /// The privacy level names are shown at.
    pub(crate) fn level(&self) -> u8 {
        u8::try_from(self.level.load(Ordering::Relaxed)).unwrap_or(0)
    }

    /// The problem a request gets when the CMDB does not run on this node (503 with a hint).
    pub(crate) fn not_here(&self) -> Problem {
        let h = (**self.header.load()).clone();
        telltale_api::cmdb_api::not_here(h.enabled, h.node.as_deref())
    }

    /// The database for a request, or the 503 that says where the CMDB is.
    pub(crate) fn db_or_503(&self) -> Result<Arc<CmdbDb>, Problem> {
        self.db().ok_or_else(|| self.not_here())
    }

    /// The status the API shows.
    pub(crate) fn status(&self) -> CmdbStatus {
        let h = (**self.header.load()).clone();
        let s = self.snapshot.load();
        let running = self.db().is_some();
        CmdbStatus {
            enabled: h.enabled,
            designated: h.designated,
            node: h.node,
            running,
            learning_until: (running && s.learning_until > unix_now()).then_some(s.learning_until),
            cis: s
                .cis
                .iter()
                .map(|(ty, n)| CmdbCount {
                    ty: ty.clone(),
                    count: *n,
                })
                .collect(),
            records: s.records,
            records_present: s.records_present,
            proposals_open: s.proposals_open,
            sources: s
                .sources
                .iter()
                .map(|x| CmdbSourceStatus {
                    source: x.source.clone(),
                    records: x.records,
                    held: x.held,
                    last_batch_unix: x.last_at,
                    complete: x.complete,
                    batches: x.batches,
                })
                .collect(),
            queue_depth: s.queue_depth,
            dropped: CmdbDropped {
                ci: s.dropped_ci,
                record: s.dropped_record,
                batch: s.dropped_batch,
            },
            caps: CmdbCaps {
                cis: u64::try_from(MAX_CIS).unwrap_or(0),
                records: u64::try_from(MAX_RECORDS).unwrap_or(0),
                records_per_ci: u64::try_from(MAX_RECORDS_PER_CI).unwrap_or(0),
            },
            disk_bytes: s.disk_bytes,
            index_bytes: s.index_bytes,
            head_epoch: s.head.0,
            head_seq: s.head.1,
            last_error: s.last_error.clone(),
        }
    }

    /// REQ: DSC-906 - the Prometheus series (`telltale_cmdb_*`): CIs by type, records by source,
    /// merge proposals, what was dropped and how long the last batch took. Nothing when the CMDB
    /// does not run on this node.
    pub(crate) fn render_metrics(&self, w: &mut telltale_telemetry::prom::PromWriter) {
        if self.db().is_none() {
            return;
        }
        let s = self.snapshot.load();
        w.family("telltale_cmdb_cis", "gauge", "Configuration items by type.");
        for (ty, n) in &s.cis {
            w.sample("telltale_cmdb_cis", &[("type", ty)], *n);
        }
        w.family(
            "telltale_cmdb_records",
            "gauge",
            "Source records held, by source instance.",
        );
        for x in &s.sources {
            w.sample("telltale_cmdb_records", &[("source", &x.source)], x.held);
        }
        w.family(
            "telltale_cmdb_proposals_open",
            "gauge",
            "Merge proposals waiting for a person.",
        );
        w.sample("telltale_cmdb_proposals_open", &[], s.proposals_open);
        w.family(
            "telltale_cmdb_dropped_total",
            "counter",
            "Things dropped at a cap: a CI refused, a record dropped, a batch the sink dropped.",
        );
        w.sample(
            "telltale_cmdb_dropped_total",
            &[("kind", "ci")],
            s.dropped_ci,
        );
        w.sample(
            "telltale_cmdb_dropped_total",
            &[("kind", "record")],
            s.dropped_record,
        );
        w.sample(
            "telltale_cmdb_dropped_total",
            &[("kind", "batch")],
            s.dropped_batch,
        );
        w.family(
            "telltale_cmdb_queue_depth",
            "gauge",
            "Source batches waiting in the CMDB's sink.",
        );
        w.sample("telltale_cmdb_queue_depth", &[], s.queue_depth);
        w.family(
            "telltale_cmdb_batch_seconds",
            "gauge",
            "How long the last ingested batch took.",
        );
        #[allow(clippy::cast_precision_loss)]
        let secs = (s.batch_micros as f64) / 1_000_000.0;
        w.sample("telltale_cmdb_batch_seconds", &[], secs);
    }

    /// REQ: DSC-903 - a manual change on the CMDB's thread (a dry run only previews). The API asks
    /// the thread, which does it between batches, and waits at most 20 seconds.
    pub(crate) async fn manual(&self, w: CmdbWrite) -> Result<CmdbChange, Problem> {
        let inbox = {
            let r = self.running.lock().unwrap_or_else(PoisonError::into_inner);
            r.as_ref().map(|r| Arc::clone(&r.inbox))
        };
        let Some(inbox) = inbox else {
            return Err(self.not_here());
        };
        let op = match w.op {
            CmdbOp::Link { source, key, to } => ManualOp::Link {
                record: RecRef { source, key },
                to,
            },
            CmdbOp::Unlink { source, key, .. } => ManualOp::Unlink {
                record: RecRef { source, key },
            },
            CmdbOp::Merge { from, into } => ManualOp::Merge { from, into },
            CmdbOp::Split { device, records } => ManualOp::Split {
                device,
                records: records
                    .into_iter()
                    .map(|r| RecRef {
                        source: r.source,
                        key: r.key,
                    })
                    .collect(),
            },
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        inbox.command(Cmd::Manual {
            op,
            by: w.by,
            reason: w.reason.unwrap_or_default(),
            dry_run: w.dry_run,
            reply: tx,
        });
        let out = tokio::time::timeout(std::time::Duration::from_secs(20), rx)
            .await
            .map_err(|_| {
                Problem::unavailable("the CMDB did not answer in time")
                    .hint("It is busy ingesting; try again in a moment. DNS is unaffected.")
            })?
            .map_err(|_| self.not_here())?;
        match out {
            Ok(o) => Ok(CmdbChange {
                op: o.preview.op,
                applied: o.applied,
                moves: o
                    .preview
                    .moves
                    .into_iter()
                    .map(|m| CmdbMove {
                        source: m.source,
                        key: m.key,
                        from: m.from,
                        to: m.to,
                        why: m.why.to_owned(),
                    })
                    .collect(),
                devices: o.preview.devices,
                notes: o.preview.notes,
                result: o.result,
            }),
            Err(ManualError::NotFound(s)) => Err(Problem::not_found(s)),
            Err(ManualError::Invalid(s)) => Err(Problem::new(Code::Conflict, s).hint(
                "Preview it first with ?dryRun=true, and pick a record or device it applies to.",
            )),
            Err(ManualError::Db(s)) => Err(Problem::internal(s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own(primary: bool) -> Own {
        Own {
            node_id: "n1".into(),
            name: "n1".into(),
            primary,
            ephemeral: false,
            witness: false,
        }
    }

    fn cfg(toml: &str) -> Config {
        telltale_config::Loader::new()
            .toml_str("t", toml)
            .load()
            .unwrap()
            .config
    }

    /// REQ: DSC-901 (`dsc_901_off_by_default_starts_nothing`) - a node with the section off reports it
    /// off, starts no thread and writes no file; asking it for CIs is 503 with a hint.
    #[test]
    fn dsc_901_off_by_default_starts_nothing() {
        let rt = Runtime::default();
        let dir = tempfile::tempdir().unwrap();
        let g = rt.next_generation();
        rt.reconcile(
            g,
            &Config::default(),
            dir.path(),
            &own(true),
            Feeds::default(),
        );
        let s = rt.status();
        assert!(!s.enabled && !s.running);
        assert!(
            s.designated,
            "the standalone node would run it if it were enabled"
        );
        assert!(!dir.path().join("cmdb.db").exists());
        let e = rt.db_or_503().unwrap_err();
        assert_eq!(e.status, 503);
    }

    /// REQ: DSC-901, DSC-906 (ADR-1005 section 1) - the CMDB shares `[discovery]`'s gate: with a node
    /// named, only that node runs it; with none, the primary; `[discovery]` need not be on.
    #[test]
    fn dsc_906_runs_on_the_node_discovery_designates() {
        let on = "[cmdb]\nenabled = true\n";
        let dir = tempfile::tempdir().unwrap();
        // A replica with no node named does not run it.
        let rt = Runtime::default();
        let g = rt.next_generation();
        rt.reconcile(g, &cfg(on), dir.path(), &own(false), Feeds::default());
        assert!(!rt.status().designated && !rt.status().running);
        // The primary does, with discovery itself off.
        let g = rt.next_generation();
        rt.reconcile(g, &cfg(on), dir.path(), &own(true), Feeds::default());
        for _ in 0..100 {
            if rt.status().running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let s = rt.status();
        assert!(s.designated && s.running, "{s:?}");
        assert!(dir.path().join("cmdb.db").exists());
        // Naming another node stops it here, and the 503 names that node.
        let named = format!("{on}[discovery]\nnode = \"pi-b\"\n");
        let g = rt.next_generation();
        rt.reconcile(g, &cfg(&named), dir.path(), &own(true), Feeds::default());
        let s = rt.status();
        assert!(!s.designated && !s.running);
        assert_eq!(s.node.as_deref(), Some("pi-b"));
        let e = rt.db_or_503().unwrap_err();
        assert!(
            e.hint.as_deref().is_some_and(|h| h.contains("pi-b")),
            "{e:?}"
        );
        rt.stop();
    }

    /// REQ: DSC-901 - two reloads whose reconciles run out of order: the older one (on) is skipped.
    #[test]
    fn dsc_901_reconciles_apply_in_order() {
        let rt = Runtime::default();
        let dir = tempfile::tempdir().unwrap();
        let g_on = rt.next_generation();
        let g_off = rt.next_generation();
        rt.reconcile(
            g_off,
            &Config::default(),
            dir.path(),
            &own(true),
            Feeds::default(),
        );
        rt.reconcile(
            g_on,
            &cfg("[cmdb]\nenabled = true\n"),
            dir.path(),
            &own(true),
            Feeds::default(),
        );
        assert!(!rt.status().enabled && !rt.status().running);
        rt.stop();
    }
}

//! REQ: DSC-901, DSC-906 (T31.2, ADR-1005 sections 1 to 4) - the `telltale-cmdb` thread. An OS thread
//! of its own, so the reconciliation never runs on the query runtime. Once a minute it reads the
//! feeds that are in this process already (the router and mDNS lease views, the neighbour table, the
//! configuration, the cluster's member list, the aggregator's snapshot, the Kubernetes table) and
//! ingests them; between times it takes the batches the discovery thread pushes (SNMP, the extra
//! UniFi and Home Assistant reads) and the API's manual changes. It flushes `last_seen` in one
//! batch every 15 minutes and sweeps retention hourly. A failure here only logs (CLU-004). No
//! module that answers a query calls into it.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use arc_swap::ArcSwap;
use telltale_config::Config;
use telltale_store::cmdb::{CmdbDb, FILE_NAME};

use super::adapters::{self, NetRow, NodeRow, WorkloadRow};
use super::engine::Engine;
use super::inbox::{Cmd, Inbox};
use super::manual::ManualOp;
use crate::devices::Leases;
use crate::discovery::inventory::Source;

/// How often the in-process feeds are read.
pub(crate) const TICK_SECS: i64 = 60;
/// How often retention is swept.
pub(crate) const MAINTAIN_SECS: i64 = 3_600;
/// How often the status is rebuilt.
const PUBLISH_SECS: i64 = 5;

/// The aggregator's last-hour client counts, a snapshot (the argument is the time, Unix seconds).
type ClientsFeed = Arc<dyn Fn(i64) -> Vec<([u8; 16], u64)> + Send + Sync>;

/// What the thread reads, besides the batches pushed to it. A `None` is not read.
#[derive(Clone, Default)]
pub(crate) struct Feeds {
    pub(crate) routers: Option<Arc<ArcSwap<Leases>>>,
    pub(crate) mdns: Option<Arc<ArcSwap<Leases>>>,
    pub(crate) networks: Option<Arc<ArcSwap<Vec<crate::routers::Network>>>>,
    /// The aggregator's last-hour client counts (a snapshot, once a minute).
    pub(crate) clients: Option<ClientsFeed>,
    /// The Kubernetes workload table, when the feature is on.
    pub(crate) workloads: Option<Arc<dyn Fn() -> Vec<WorkloadRow> + Send + Sync>>,
    /// The cluster's members.
    pub(crate) nodes: Option<Arc<dyn Fn() -> Vec<NodeRow> + Send + Sync>>,
    /// Read the kernel's neighbour table.
    pub(crate) neighbours: bool,
    /// Read the networks this node is on (its interfaces).
    pub(crate) own_networks: bool,
    pub(crate) ifindex_root: Option<PathBuf>,
}

impl std::fmt::Debug for Feeds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cmdb::Feeds")
    }
}

/// One source instance in the snapshot.
#[derive(Debug, Clone, Default)]
pub(crate) struct SourceSnap {
    pub(crate) source: String,
    pub(crate) records: u64,
    pub(crate) held: u64,
    pub(crate) last_at: i64,
    pub(crate) complete: bool,
    pub(crate) batches: u64,
}

/// What the status and the metrics read, rebuilt by the thread.
#[derive(Debug, Clone, Default)]
pub(crate) struct Snapshot {
    pub(crate) cis: Vec<(String, u64)>,
    pub(crate) records: u64,
    pub(crate) records_present: u64,
    pub(crate) proposals_open: u64,
    pub(crate) sources: Vec<SourceSnap>,
    pub(crate) queue_depth: u64,
    pub(crate) dropped_ci: u64,
    pub(crate) dropped_record: u64,
    pub(crate) dropped_batch: u64,
    pub(crate) batch_micros: u64,
    pub(crate) disk_bytes: u64,
    pub(crate) index_bytes: u64,
    pub(crate) head: (i64, i64),
    pub(crate) learning_until: i64,
    pub(crate) last_error: Option<String>,
}

/// What the thread is started with.
pub(crate) struct Args {
    pub(crate) data_dir: PathBuf,
    pub(crate) inbox: Arc<Inbox>,
    pub(crate) snapshot: Arc<ArcSwap<Snapshot>>,
    pub(crate) db: Arc<ArcSwap<Option<Arc<CmdbDb>>>>,
    pub(crate) cfg: Arc<ArcSwap<Config>>,
    pub(crate) feeds: Feeds,
    pub(crate) node: String,
    /// A clock for tests (Unix seconds); `None` is the real one.
    pub(crate) clock: Option<Arc<dyn Fn() -> i64 + Send + Sync>>,
}

fn real_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Starts the thread. The database is opened on it, so a slow disk never holds a reload.
pub(crate) fn spawn(args: Args) -> io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("telltale-cmdb".into())
        .spawn(move || {
            telltale_net::background_thread();
            run(&args);
        })
}

fn run(args: &Args) {
    let now_fn = |a: &Args| a.clock.as_ref().map_or_else(real_now, |c| c());
    let path = args.data_dir.join(FILE_NAME);
    let db = match CmdbDb::open(&path) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            tracing::warn!(error = %e, "the CMDB's database could not be opened; it is not running (DNS is unaffected)");
            publish_error(args, &e.to_string());
            return;
        }
    };
    // A node that becomes designated seeds its database from the authored data it holds as a
    // standby (ADR-1005 section 6, ADR-1021).
    if let Err(e) = super::replication::promote(&db, &args.data_dir, now_fn(args)) {
        tracing::warn!(error = %e, "the CMDB's standby copy could not be applied; the sources rebuild the rest");
    }
    let mut engine = match Engine::open(&db, now_fn(args)) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "the CMDB could not read its index; it is not running (DNS is unaffected)");
            publish_error(args, &e.to_string());
            return;
        }
    };
    args.db.store(Arc::new(Some(Arc::clone(&db))));
    let mut next_tick = 0i64;
    let mut next_maintain = now_fn(args).saturating_add(MAINTAIN_SECS);
    let mut next_publish = 0i64;
    let mut last_error: Option<String> = None;
    let mut last_logged = 0i64;
    loop {
        let taken = args.inbox.take(Duration::from_millis(500));
        let now = now_fn(args);
        let mut note = |what: &str, e: &dyn std::fmt::Display, last_error: &mut Option<String>| {
            *last_error = Some(format!("{what}: {e}"));
            // Logged at most once a minute: a failing disk must not fill the log.
            if now.saturating_sub(last_logged) >= 60 {
                last_logged = now;
                tracing::warn!(error = %e, "the CMDB: {what}; DNS is unaffected");
            }
        };
        for b in taken.batches {
            if let Err(e) = engine.ingest(b, now) {
                engine.counters.errors = engine.counters.errors.saturating_add(1);
                note("a batch could not be ingested", &e, &mut last_error);
            }
        }
        for c in taken.cmds {
            match c {
                Cmd::Tick => next_tick = 0,
                Cmd::Manual {
                    op,
                    by,
                    reason,
                    dry_run,
                    reply,
                } => {
                    let out = engine.manual(&op, &by, &reason, now, dry_run);
                    if let (false, Ok(o)) = (dry_run, &out) {
                        tracing::info!(op = ManualOp::name(&op), by = %by, moved = o.preview.moves.len(), "the CMDB: a manual change was applied");
                    }
                    let _ = reply.send(out);
                }
            }
        }
        if taken.stop {
            if let Err(e) = engine.flush(now, true) {
                tracing::warn!(error = %e, "the CMDB's last-seen times could not be flushed");
            }
            break;
        }
        if now >= next_tick {
            next_tick = now.saturating_add(TICK_SECS);
            for b in tick_batches(args, now) {
                if let Err(e) = engine.ingest(b, now) {
                    engine.counters.errors = engine.counters.errors.saturating_add(1);
                    note("a feed could not be ingested", &e, &mut last_error);
                }
            }
        }
        if let Err(e) = engine.flush(now, false) {
            note("last-seen times could not be flushed", &e, &mut last_error);
        }
        if now >= next_maintain {
            next_maintain = now.saturating_add(MAINTAIN_SECS);
            if let Err(e) = engine.maintain(now) {
                note("retention could not run", &e, &mut last_error);
            }
        }
        if now >= next_publish {
            next_publish = now.saturating_add(PUBLISH_SECS);
            args.snapshot.store(Arc::new(snapshot(
                &engine,
                &args.inbox,
                &db,
                last_error.clone(),
            )));
        }
    }
}

fn publish_error(args: &Args, why: &str) {
    args.snapshot.store(Arc::new(Snapshot {
        last_error: Some(why.to_owned()),
        ..Snapshot::default()
    }));
}

/// Builds the status snapshot: counts from the database, counters from the engine.
fn snapshot(engine: &Engine, inbox: &Inbox, db: &CmdbDb, last_error: Option<String>) -> Snapshot {
    let mut s = Snapshot {
        queue_depth: u64::try_from(inbox.depth()).unwrap_or(u64::MAX),
        dropped_ci: engine.counters.dropped_ci,
        dropped_record: engine.counters.dropped_record,
        dropped_batch: inbox.dropped(),
        batch_micros: engine.counters.batch_micros,
        disk_bytes: db.disk_bytes(),
        index_bytes: u64::try_from(engine.index_bytes()).unwrap_or(u64::MAX),
        learning_until: engine.learning_until(),
        last_error,
        ..Snapshot::default()
    };
    let held = db.read(|o| {
        let mut cis = Vec::new();
        for ty in [
            "device",
            "interface",
            "network",
            "node",
            "service",
            "upstream",
        ] {
            cis.push((
                ty.to_owned(),
                u64::try_from(o.ci_count(Some(ty))?).unwrap_or(0),
            ));
        }
        let (total, present) = o.record_counts()?;
        let by_source = o.record_counts_by_source()?;
        Ok((
            cis,
            total,
            present,
            o.proposal_count()?,
            by_source,
            o.head()?,
        ))
    });
    if let Ok((cis, total, present, proposals, by_source, head)) = held {
        s.cis = cis;
        s.records = u64::try_from(total).unwrap_or(0);
        s.records_present = u64::try_from(present).unwrap_or(0);
        s.proposals_open = u64::try_from(proposals).unwrap_or(0);
        s.head = head;
        let mut m: BTreeMap<String, SourceSnap> = BTreeMap::new();
        for (src, n, _) in by_source {
            let e = m.entry(src.clone()).or_default();
            e.held = u64::try_from(n).unwrap_or(0);
            e.source = src;
        }
        for (src, st) in engine.sources() {
            let e = m.entry(src.clone()).or_default();
            e.source.clone_from(src);
            e.records = u64::try_from(st.records).unwrap_or(0);
            e.last_at = st.last_at;
            e.complete = st.complete;
            e.batches = st.batches;
        }
        s.sources = m.into_values().collect();
    }
    s
}

/// The batches of the feeds this process holds, once a minute (ADR-1005 section 4). Every one is
/// read from memory the other tasks keep, apart from the neighbour table (the kernel's, as the
/// inventory reads it) and the interface list: no packet goes out.
pub(crate) fn tick_batches(args: &Args, now: i64) -> Vec<super::model::SourceBatch> {
    let cfg = args.cfg.load_full();
    let feeds = &args.feeds;
    let mut out = Vec::new();
    let unow = u64::try_from(now).unwrap_or(0);
    if feeds.neighbours {
        match telltale_net::neighbors() {
            Ok(neigh) => {
                let root = feeds
                    .ifindex_root
                    .clone()
                    .unwrap_or_else(|| PathBuf::from(crate::discovery::thread::SYS_NET));
                let names = crate::discovery::sources::ifindex_names(&root);
                let subnets: Vec<_> = cfg
                    .discovery
                    .subnets
                    .iter()
                    .filter_map(|s| {
                        crate::discovery::sources::Ipv4Subnet::parse(&s.cidr.to_string())
                    })
                    .collect();
                let obs = crate::discovery::sources::neighbour_observations(
                    &neigh, &names, &subnets, unow,
                );
                out.push(adapters::batch_from_observations(&obs, "neighbor", now));
            }
            Err(e) => tracing::debug!(error = %e, "the CMDB: the neighbour table is unreadable"),
        }
    }
    if let Some(view) = &feeds.routers {
        out.extend(adapters::from_lease_view(
            &view.load(),
            &adapters::router_kinds(&cfg),
            now,
        ));
    }
    if let Some(view) = &feeds.mdns {
        let obs = crate::discovery::sources::lease_observations(&view.load(), Source::Mdns, unow);
        out.push(adapters::batch_from_observations(&obs, "mdns", now));
    }
    out.push(adapters::from_config(&cfg, &args.node, now));
    let nodes = feeds.nodes.as_ref().map_or_else(
        || {
            vec![NodeRow {
                id: args.node.clone(),
                address: cfg.api.listen.to_string(),
                primary: true,
                version: crate::build_info::VERSION.to_owned(),
            }]
        },
        |f| f(),
    );
    out.push(adapters::from_cluster(&nodes, now));
    let mut nets: Vec<NetRow> = Vec::new();
    if let Some(n) = &feeds.networks {
        let kinds = adapters::router_kinds(&cfg);
        for r in n.load().iter() {
            let kind = kinds.get(&r.router).copied().unwrap_or("unifi");
            nets.push(NetRow {
                source: format!("{kind}:{}#networks", r.router),
                name: r.name.clone(),
                cidr: format!("{}/{}", r.subnet, r.prefix),
                vlan: r.vlan,
                gateway: r.gateway.map(|g| g.to_string()),
                domain: r.domain.clone(),
                purpose: r.purpose.clone(),
            });
        }
    }
    if feeds.own_networks {
        for n in &crate::own_networks::current() {
            nets.push(NetRow {
                source: "cluster".to_owned(),
                name: n.name.clone(),
                cidr: format!("{}/{}", n.subnet, n.prefix),
                vlan: n.vlan,
                gateway: None,
                domain: None,
                purpose: None,
            });
        }
    }
    out.extend(adapters::from_networks(&nets, now));
    // The queries are read at privacy levels 0 and 1 only (ADR-1005 section 12).
    if cfg.telemetry.qlog.privacy_level < 2
        && let Some(f) = &feeds.clients
    {
        out.push(adapters::from_queries(&f(unow_secs(now)), &cfg, now));
    }
    if cfg.kubernetes.enabled
        && let Some(f) = &feeds.workloads
    {
        out.push(adapters::from_workloads(&f(), now));
    }
    out
}

fn unow_secs(now: i64) -> i64 {
    now
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::redundant_closure_for_method_calls,
        clippy::manual_assert,
        clippy::type_complexity
    )]
    use super::*;
    use crate::cmdb::model::{RecKind, Record, SourceBatch};

    fn args(
        dir: &std::path::Path,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> (
        Args,
        Arc<Inbox>,
        Arc<ArcSwap<Snapshot>>,
        Arc<ArcSwap<Option<Arc<CmdbDb>>>>,
    ) {
        let inbox = Arc::new(Inbox::default());
        let snap = Arc::new(ArcSwap::from_pointee(Snapshot::default()));
        let db = Arc::new(ArcSwap::from_pointee(None));
        let a = Args {
            data_dir: dir.to_path_buf(),
            inbox: Arc::clone(&inbox),
            snapshot: Arc::clone(&snap),
            db: Arc::clone(&db),
            cfg: Arc::new(ArcSwap::from_pointee(Config::default())),
            feeds: Feeds::default(),
            node: "n1".into(),
            clock: Some(clock),
        };
        (a, inbox, snap, db)
    }

    /// REQ: DSC-906 - the thread takes pushed batches, writes records, publishes a status that counts
    /// them, and a stop flushes and exits; the database is readable while it runs.
    #[test]
    fn dsc_906_thread_ingests_pushed_batches_and_stops_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let clock: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(|| 1_000_000);
        let (a, inbox, snap, dbslot) = args(dir.path(), clock);
        let h = spawn(a).unwrap();
        let mut r = Record::new("neighbor", "n1", RecKind::Device, 1_000_000);
        r.text("mac", "aa:bb:cc:00:00:01");
        inbox.push(SourceBatch {
            source: "neighbor".into(),
            complete: true,
            records: vec![r],
            at: 1_000_000,
        });
        let mut ok = false;
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(50));
            if snap
                .load()
                .sources
                .iter()
                .any(|x| x.source == "neighbor" && x.held == 1)
                && dbslot.load().is_some()
            {
                ok = true;
                break;
            }
        }
        assert!(
            ok,
            "the record was ingested and the status counts it: {:?}",
            snap.load()
        );
        let s = snap.load();
        assert!(s.cis.iter().any(|(t, n)| t == "device" && *n >= 1));
        assert!(
            s.sources
                .iter()
                .any(|x| x.source == "neighbor" && x.held == 1)
        );
        inbox.stop();
        h.join().unwrap();
    }

    /// REQ: DSC-906 - the once-a-minute tick builds the configuration, cluster and network batches
    /// without any feed (a node alone is its own node), and reads the queries at privacy level 1 but
    /// not at 2.
    #[test]
    fn dsc_906_tick_reads_config_cluster_and_queries() {
        let dir = tempfile::tempdir().unwrap();
        let clock: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(|| 1_000_000);
        let (mut a, ..) = args(dir.path(), clock);
        let client = std::net::Ipv4Addr::new(192, 168, 1, 20)
            .to_ipv6_mapped()
            .octets();
        a.feeds.clients = Some(Arc::new(move |_| vec![(client, 3)]));
        let b = tick_batches(&a, 1_000_000);
        let sources: Vec<&str> = b.iter().map(|x| x.source.as_str()).collect();
        assert!(
            sources.contains(&"config") && sources.contains(&"cluster"),
            "{sources:?}"
        );
        assert!(sources.contains(&"queries"), "{sources:?}");
        let node = b.iter().find(|x| x.source == "cluster").unwrap();
        assert_eq!(node.records.len(), 1, "a node alone is its own node");
        a.cfg.store(Arc::new(
            telltale_config::Loader::new()
                .toml_str("t", "[telemetry.qlog]\nprivacy_level = 2\n")
                .load()
                .unwrap()
                .config,
        ));
        let b = tick_batches(&a, 1_000_000);
        assert!(
            !b.iter().any(|x| x.source == "queries"),
            "not read at level 2"
        );
    }
}

//! Server lifecycle: startup, hot reload on SIGHUP, graceful shutdown.
//!
//! REQ: OPS-007 (drain on shutdown), OPS-009 (reload without dropping queries).

use crate::lists::Lists;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use telltale_cache::{Cache, CachePolicy};
use telltale_config::{Config, ListenProto, Listener, Loader};
use telltale_net::{
    CertStore, DohConfig, DohServer, TcpConfig, TcpServer, Transport, UdpConfig, UdpListener,
};
use telltale_policy::LocalData;
use telltale_upstream::Router;
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::http;
use crate::pipeline::{Handler, Pipeline, Policy, Settings};

/// Loads and validates config from `files` + environment plus what the UI/API stored
/// (ADR-040), logging every problem.
/// REQ: NFR-001 (T10.2) — drops the executable's resident pages after work that runs once
/// (`telltale_net::trim_executable_pages`), off the query path.
pub(crate) fn trim_code_pages(after: &'static str) {
    std::thread::spawn(move || {
        telltale_net::background_thread();
        let bytes = telltale_net::trim_executable_pages();
        tracing::debug!(after, mib = bytes >> 20, "released code pages");
    });
}

pub(crate) fn load(files: &[PathBuf]) -> Option<Config> {
    load_files(files).map(|c| crate::replication::effective(&c))
}

/// Loads and validates `files` + environment only (without what the UI/API stored).
pub(crate) fn load_files(files: &[PathBuf]) -> Option<Config> {
    load_files_logging(files, true)
}

/// Like [`load_files`], logging only errors: for re-checking the node's own files on every
/// replicated change, where its warnings (a replica's file has no upstreams, by design)
/// would repeat what start-up already said.
pub(crate) fn load_files_quiet(files: &[PathBuf]) -> Option<Config> {
    load_files_logging(files, false)
}

fn load_files_logging(files: &[PathBuf], warnings: bool) -> Option<Config> {
    match files
        .iter()
        .fold(Loader::new(), Loader::file)
        .process_env()
        .load()
    {
        Ok(l) => {
            if warnings {
                for w in &l.warnings {
                    warn!("config: {w}");
                }
            }
            Some(l.config)
        }
        Err(errors) => {
            for e in &errors {
                error!("config: {e}");
            }
            None
        }
    }
}

/// Worker threads per UDP listener.
pub(crate) fn workers(cfg: &Config) -> usize {
    match cfg.node.workers {
        0 => telltale_net::default_workers(),
        n => usize::from(n),
    }
}

fn cache_policy(c: &telltale_config::CacheConfig, workers: usize) -> CachePolicy {
    CachePolicy {
        max_bytes: usize::try_from(c.max_bytes.bytes()).unwrap_or(usize::MAX),
        max_entries: c.max_entries as usize,
        min_ttl: c.min_ttl,
        max_ttl: c.max_ttl,
        negative_ttl_max: c.negative_ttl_max,
        servfail_ttl: c.servfail_ttl,
        serve_stale: c.serve_stale,
        stale_max_age: c.stale_max_age,
        stale_answer_ttl: c.stale_answer_ttl,
        prefetch: c.prefetch,
        prefetch_threshold_pct: c.prefetch_threshold_pct,
        prefetch_min_hits: c.prefetch_min_hits,
        // spec/03 §4: power of two >= 4 × workers, at least 64.
        shards: (workers * 4).max(64),
    }
}

/// Builds everything a reload can replace: upstreams/routes and policy (incl. local records).
pub(crate) fn build_dynamic(
    cfg: &Config,
    reuse: Option<Arc<Router>>,
) -> Result<(Arc<Router>, Policy), Vec<String>> {
    let router = match reuse {
        Some(r) => r,
        None => Arc::new(Router::from_config(cfg).map_err(|errs| {
            errs.into_iter()
                .map(|e| format!("upstreams: {e}"))
                .collect::<Vec<_>>()
        })?),
    };
    let (local, report) = LocalData::from_config(cfg);
    for w in &report.warnings {
        warn!("local records: {w}");
    }
    if !report.errors.is_empty() {
        return Err(report
            .errors
            .into_iter()
            .map(|e| format!("local records: {e}"))
            .collect());
    }
    for up in router.upstreams() {
        info!(name = %up.name, endpoint = %up.endpoint, "upstream");
    }
    if !local.is_empty() {
        info!(records = local.len(), "local records loaded");
    }
    let zones = load_zones(cfg)?;
    let mut policy = Policy::from_config(cfg, local);
    policy.zones = Arc::new(zones);
    Ok((router, policy))
}

/// REQ: OBS-024 (T13.1) — the policy and router a configuration would run with, built without
/// side effects or log lines (simulations build one per request, beside the serving state).
pub(crate) fn build_candidate(cfg: &Config) -> Result<(Arc<Router>, Policy), Vec<String>> {
    let router = Arc::new(Router::from_config(cfg).map_err(|errs| {
        errs.into_iter()
            .map(|e| format!("upstreams: {e}"))
            .collect::<Vec<_>>()
    })?);
    let (local, report) = LocalData::from_config(cfg);
    if !report.errors.is_empty() {
        return Err(report
            .errors
            .into_iter()
            .map(|e| format!("local records: {e}"))
            .collect());
    }
    let zones = load_zones(cfg)?;
    let mut policy = Policy::from_config(cfg, local);
    policy.zones = Arc::new(zones);
    Ok((router, policy))
}

/// REQ: DNS-018 (T7.22) — `[[zone]]`: each zone's file and records, most specific first.
pub(crate) fn load_zones(cfg: &Config) -> Result<Vec<crate::pipeline::Zone>, Vec<String>> {
    let mut zones = Vec::new();
    let mut errors = Vec::new();
    for (i, z) in cfg.zone.iter().enumerate() {
        let Ok(apex) = telltale_proto::NameBuf::from_presentation(z.name.as_str()) else {
            errors.push(format!("zone[{i}]: `{}` isn't a name", z.name.as_str()));
            continue;
        };
        let mut data = LocalData::default();
        let ttl = cfg.local.default_ttl;
        let mut apex_records = Vec::new();
        if let Some(f) = &z.file {
            match std::fs::read_to_string(f.as_str()) {
                Ok(text) => {
                    let mut im = crate::import::parse_zone(&text, Some(z.name.as_str()));
                    apex_records = std::mem::take(&mut im.apex);
                    for k in &im.skipped {
                        if !k.contains("SOA") && !k.contains(" NS") {
                            warn!(zone = %z.name.as_str(), "zone file: skipped {k}");
                        }
                    }
                    for r in &im.records {
                        if let Err(e) = data.add(&r.name, &r.rtype, &r.value, r.ttl.unwrap_or(ttl))
                        {
                            errors.push(format!("zone[{i}] {}: {e}", f.as_str()));
                        }
                    }
                }
                Err(e) => errors.push(format!("zone[{i}].file: {}: {e}", f.as_str())),
            }
        }
        for (j, r) in z.record.iter().enumerate() {
            if let Err(e) = data.add(&r.name, &r.rtype, &r.value, r.ttl.unwrap_or(ttl)) {
                errors.push(format!("zone[{i}].record[{j}]: {e}"));
            }
        }
        info!(zone = %z.name.as_str(), records = data.len(), "zone loaded");
        let (soa, ns) = apex_soa_ns(&apex, &apex_records, z.negative_ttl);
        zones.push(crate::pipeline::Zone {
            apex,
            data,
            groups: z.groups.iter().map(|g| g.as_str().into()).collect(),
            negative_ttl: z.negative_ttl,
            soa,
            ns,
            ttl,
        });
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    // Most specific first; group views before the zone for everyone.
    zones.sort_by_key(|z| (std::cmp::Reverse(z.apex.wire_len()), z.groups.is_empty()));
    Ok(zones)
}

/// A zone-file name: `@` is the apex, a name without a final dot is relative to it.
fn zone_name(token: &str, apex: &telltale_proto::NameBuf) -> Option<telltale_proto::NameBuf> {
    let text = if token == "@" {
        apex.display().to_string()
    } else if token.ends_with('.') {
        token.to_owned()
    } else {
        format!("{token}.{}", apex.display())
    };
    telltale_proto::NameBuf::from_presentation(text.trim_end_matches('.')).ok()
}

/// REQ: DNS-018 (T9.18) — a zone's SOA RDATA and name servers: the zone file's apex records,
/// or made up as resolvers serving local zones do (`localhost.`, `hostmaster.<apex>`, the
/// negative TTL as MINIMUM).
fn apex_soa_ns(
    apex: &telltale_proto::NameBuf,
    records: &[(String, Vec<String>)],
    negative_ttl: u32,
) -> (Vec<u8>, Vec<telltale_proto::NameBuf>) {
    let localhost = telltale_proto::NameBuf::from_presentation("localhost").unwrap_or_default();
    let soa = records
        .iter()
        .find(|(t, _)| t == "SOA")
        .and_then(|(_, d)| {
            let [mname, rname, nums @ ..] = d.as_slice() else {
                return None;
            };
            let nums: Vec<u32> = nums.iter().map(|n| n.parse().ok()).collect::<Option<_>>()?;
            if nums.len() != 5 {
                return None;
            }
            let mut out = zone_name(mname, apex)?.as_wire().to_vec();
            out.extend_from_slice(zone_name(rname, apex)?.as_wire());
            for n in nums {
                out.extend_from_slice(&n.to_be_bytes());
            }
            Some(out)
        })
        .unwrap_or_else(|| {
            let hostmaster = zone_name("hostmaster", apex).unwrap_or_default();
            let serial = u32::try_from(crate::pipeline::unix_now()).unwrap_or(1);
            let mut out = localhost.as_wire().to_vec();
            out.extend_from_slice(hostmaster.as_wire());
            for n in [serial, 3600, 600, 86_400, negative_ttl] {
                out.extend_from_slice(&n.to_be_bytes());
            }
            out
        });
    let mut ns: Vec<telltale_proto::NameBuf> = records
        .iter()
        .filter(|(t, _)| t == "NS")
        .filter_map(|(_, d)| zone_name(d.first()?, apex))
        .collect();
    if ns.is_empty() {
        ns.push(localhost);
    }
    (soa, ns)
}

/// REQ: FLT-006, DNS-001 (T24.32, ADR-1000) — the IP to MAC map for MAC-keyed clients: the kernel's
/// neighbor table (every interface, so every VLAN the node is directly on), then, for an address the
/// table doesn't hold, the MAC the router's DHCP leases give it. A device behind a router never has
/// a neighbor entry of its own (the table shows the router's MAC for the router's address only), so
/// the leases are the only source of its MAC. The kernel's entry wins where both exist; an offline
/// lease is not a device on the network now and is left out.
pub(crate) fn merged_macs(
    kernel: &[telltale_net::Neighbor],
    leases: &crate::devices::Leases,
) -> Vec<(std::net::IpAddr, [u8; 6])> {
    let mut out: Vec<(std::net::IpAddr, [u8; 6])> = kernel.iter().map(|n| (n.ip, n.mac)).collect();
    let have: std::collections::HashSet<std::net::IpAddr> =
        out.iter().map(|(ip, _)| ip.to_canonical()).collect();
    for l in leases.values().filter(|l| !l.offline) {
        let Some(mac) = crate::discovery::sources::parse_mac(&l.mac).filter(|m| *m != [0; 6])
        else {
            continue;
        };
        let v6 = l.ipv6.iter().map(|a| std::net::IpAddr::V6(*a));
        for ip in std::iter::once(std::net::IpAddr::V4(l.ip)).chain(v6) {
            if !have.contains(&ip.to_canonical()) {
                out.push((ip, mac));
            }
        }
    }
    out
}

/// REQ: FLT-006 — keeps the IP → MAC map fresh while any client is identified by MAC.
fn spawn_neighbor_refresh(pipeline: Arc<Pipeline>, every: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut warned = false;
        // The last good kernel read: a transient read error keeps it instead of wiping the map.
        let mut last_kernel = Vec::new();
        loop {
            if pipeline.current().policy.clients.uses_macs() {
                let kernel = match tokio::task::spawn_blocking(telltale_net::neighbors).await {
                    Ok(Ok(n)) => {
                        warned = false;
                        last_kernel.clone_from(&n);
                        n
                    }
                    Ok(Err(e)) => {
                        if !warned {
                            warn!(
                                "cannot read the neighbor table (MAC-based clients match only from router leases): {e}"
                            );
                            warned = true;
                        }
                        last_kernel.clone()
                    }
                    Err(_) => last_kernel.clone(),
                };
                let leases = pipeline.router_leases.load();
                pipeline.neighbors.replace(merged_macs(&kernel, &leases));
            }
            tokio::time::sleep(every).await;
        }
    })
}

fn spawn_health_checks(router: &Router) -> JoinHandle<()> {
    tokio::spawn(telltale_upstream::active_health_checks(
        router.upstreams().to_vec(),
        telltale_upstream::HEALTH_CHECK_INTERVAL,
    ))
}

/// The running DNS listeners: UDP keyed by address, stream listeners (TCP, DoT, DoH) by their
/// whole config entry.
struct Listeners {
    udp: Vec<(SocketAddr, UdpListener)>,
    streams: Vec<(Listener, Stream)>,
    workers: usize,
    handler: Arc<Handler>,
    rt: tokio::runtime::Handle,
}

/// A TCP-based listener, and the certificate watcher of a TLS one.
enum Stream {
    /// Plain TCP or DoT.
    Tcp(TcpServer, Option<JoinHandle<()>>),
    Doh(DohServer, JoinHandle<()>),
    /// REQ: DNS-004 (T7.7) — DNS over QUIC.
    Doq(telltale_net::DoqServer, JoinHandle<()>),
    /// REQ: DNS-004 (T7.8) — DoH over HTTP/3.
    Doh3(telltale_net::Doh3Server, JoinHandle<()>),
}

impl Stream {
    async fn shutdown(self) {
        match self {
            Self::Tcp(s, watch) => {
                if let Some(w) = watch {
                    w.abort();
                }
                s.shutdown().await;
            }
            Self::Doh(s, watch) => {
                watch.abort();
                s.shutdown().await;
            }
            Self::Doq(s, watch) => {
                watch.abort();
                s.shutdown().await;
            }
            Self::Doh3(s, watch) => {
                watch.abort();
                s.shutdown().await;
            }
        }
    }
}

/// REQ: FLT-010 (T7.10) — every 15 s: which schedules are on. A change rebuilds the filter's
/// list masks (no recompile) and turns block-everything on or off for the groups concerned.
async fn schedule_ticker(
    sources: Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut compiled_for: Option<Arc<Config>> = None;
    let mut compiled = Vec::new();
    loop {
        let cfg = sources.config.load_full();
        if compiled_for.as_ref().is_none_or(|c| !Arc::ptr_eq(c, &cfg)) {
            compiled = telltale_config::schedule::compile(&cfg);
            compiled_for = Some(Arc::clone(&cfg));
        }
        let clients = Arc::clone(&sources.pipeline.current().policy.clients);
        let now = i64::try_from(crate::pipeline::unix_now()).unwrap_or(i64::MAX);
        let state = crate::pipeline::ScheduleNow::compute(&cfg, &compiled, clients.groups(), now);
        if **sources.pipeline.schedules.load() != state {
            let on: Vec<&str> = compiled
                .iter()
                .filter(|s| s.is_on(now))
                .map(|s| s.name.as_str())
                .collect();
            info!(on = ?on, "schedules changed");
            sources.pipeline.schedules.store(Arc::new(state));
            sources.pipeline.set_filter(None);
        }
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(Duration::from_secs(15)) => {}
        }
    }
}

/// REQ: DNS-004 (T7.8) — the `Alt-Svc` an HTTP/2 DoH listener sends when an HTTP/3 DoH listener is
/// configured: clients that speak HTTP/3 switch to it for the same name.
fn alt_svc(listen: &[Listener]) -> Option<String> {
    listen
        .iter()
        .find(|l| l.proto == ListenProto::Doh3)
        .map(|l| format!("h3=\":{}\"; ma=86400", l.addr.port()))
}

/// REQ: DNS-002/003 — re-reads the certificate files every 10 s (cert-manager renewals). The
/// API listener's own files too (API-003, ADR-149).
pub(crate) fn watch_cert(store: Arc<CertStore>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        tick.tick().await;
        loop {
            tick.tick().await;
            match store.reload_if_changed() {
                Ok(true) => info!(cert = %store.cert_path().display(), "TLS certificate reloaded"),
                Ok(false) => {}
                Err(e) => warn!("TLS certificate reload failed (keeping the previous one): {e}"),
            }
        }
    })
}

impl Listeners {
    /// Makes the running set match `listen`: binds additions first, then closes removals, so a
    /// changed address never leaves a gap (`spec/08` §5). A stream listener whose settings
    /// changed on the same address is closed just before its replacement binds.
    async fn apply(&mut self, listen: &[Listener]) -> io::Result<()> {
        for l in listen {
            let ctx =
                |e: io::Error| io::Error::new(e.kind(), format!("{:?} {}: {e}", l.proto, l.addr));
            match l.proto {
                ListenProto::Udp if !self.udp.iter().any(|(a, _)| *a == l.addr) => {
                    let listener = UdpListener::spawn(
                        &UdpConfig::new(l.addr, self.workers),
                        &self.handler,
                        &self.rt,
                    )
                    .map_err(ctx)?;
                    info!(addr = %listener.local_addr(), workers = self.workers, "listening (udp)");
                    self.udp.push((l.addr, listener));
                }
                ListenProto::Tcp
                | ListenProto::Dot
                | ListenProto::Doh
                | ListenProto::Doq
                | ListenProto::Doh3
                    if !self.streams.iter().any(|(c, _)| c == l) =>
                {
                    // Same protocol and address with other settings: replace it.
                    if let Some(i) = self
                        .streams
                        .iter()
                        .position(|(c, _)| c.proto == l.proto && c.addr == l.addr)
                    {
                        let (_, old) = self.streams.remove(i);
                        old.shutdown().await;
                    }
                    let stream = self
                        .bind_stream(l, alt_svc(listen).as_deref())
                        .map_err(ctx)?;
                    self.streams.push((l.clone(), stream));
                }
                ListenProto::Udp
                | ListenProto::Tcp
                | ListenProto::Dot
                | ListenProto::Doh
                | ListenProto::Doq
                | ListenProto::Doh3 => {}
            }
        }
        let (kept, gone): (Vec<_>, Vec<_>) = self.udp.drain(..).partition(|(a, _)| {
            listen
                .iter()
                .any(|l| l.proto == ListenProto::Udp && l.addr == *a)
        });
        self.udp = kept;
        for (addr, l) in gone {
            info!(%addr, "closing udp listener");
            l.shutdown();
        }
        let (kept, gone): (Vec<_>, Vec<_>) = self
            .streams
            .drain(..)
            .partition(|(c, _)| listen.contains(c));
        self.streams = kept;
        for (c, s) in gone {
            info!(addr = %c.addr, proto = ?c.proto, "closing listener");
            tokio::spawn(s.shutdown()); // drains its connections in the background
        }
        Ok(())
    }

    fn bind_stream(&self, l: &Listener, alt_svc: Option<&str>) -> io::Result<Stream> {
        let store = match &l.tls {
            Some(t) => Some(CertStore::load(t.cert.as_str(), t.key.as_str())?),
            None => None,
        };
        let handler = Arc::clone(&self.handler);
        match (l.proto, store) {
            (ListenProto::Doh, Some(store)) => {
                let mut cfg = DohConfig::new(l.addr, Arc::clone(&store));
                if let Some(p) = &l.path {
                    p.as_str().trim_end_matches('/').clone_into(&mut cfg.path);
                }
                cfg.proxy_protocol = l.proxy_protocol;
                cfg.alt_svc = alt_svc.map(str::to_owned);
                if let Some(n) = l.max_connections {
                    cfg.max_connections = n as usize;
                }
                if let Some(n) = l.max_connections_per_address {
                    cfg.max_connections_per_address = n as usize;
                }
                let s = DohServer::bind(cfg, handler)?;
                info!(addr = %s.local_addr(), proxy_protocol = l.proxy_protocol, "listening (doh)");
                Ok(Stream::Doh(s, watch_cert(store)))
            }
            (ListenProto::Doh3, Some(store)) => {
                let mut cfg = telltale_net::Doh3Config::new(l.addr, Arc::clone(&store));
                if let Some(p) = &l.path {
                    p.as_str().trim_end_matches('/').clone_into(&mut cfg.path);
                }
                if let Some(n) = l.max_connections {
                    cfg.max_connections = n as usize;
                }
                if let Some(n) = l.max_connections_per_address {
                    cfg.max_connections_per_address = n as usize;
                }
                let s = telltale_net::Doh3Server::bind(&cfg, handler)?;
                info!(addr = %s.local_addr(), "listening (doh3)");
                Ok(Stream::Doh3(s, watch_cert(store)))
            }
            (ListenProto::Doq, Some(store)) => {
                let mut cfg = telltale_net::DoqConfig::new(l.addr, Arc::clone(&store));
                if let Some(n) = l.max_connections {
                    cfg.max_connections = n as usize;
                }
                if let Some(n) = l.max_connections_per_address {
                    cfg.max_connections_per_address = n as usize;
                }
                let s = telltale_net::DoqServer::bind(&cfg, handler)?;
                info!(addr = %s.local_addr(), "listening (doq)");
                Ok(Stream::Doq(s, watch_cert(store)))
            }
            (proto, store) => {
                let mut cfg = TcpConfig::new(l.addr);
                cfg.proxy_protocol = l.proxy_protocol;
                if let Some(n) = l.max_connections {
                    cfg.max_connections = n as usize;
                }
                if let Some(n) = l.max_connections_per_address {
                    cfg.max_connections_per_address = n as usize;
                }
                if proto == ListenProto::Dot {
                    cfg.transport = Transport::Dot;
                    cfg.tls.clone_from(&store);
                }
                let s = TcpServer::bind(cfg, handler)?;
                let label = if proto == ListenProto::Dot {
                    "dot"
                } else {
                    "tcp"
                };
                info!(addr = %s.local_addr(), proxy_protocol = l.proxy_protocol, "listening ({label})");
                Ok(Stream::Tcp(s, store.map(watch_cert)))
            }
        }
    }

    fn stats(&self) -> ListenerStats {
        ListenerStats {
            udp: self
                .udp
                .iter()
                .flat_map(|(_, l)| l.stats().iter().cloned())
                .collect(),
            tcp: self
                .streams
                .iter()
                .filter_map(|(_, s)| match s {
                    Stream::Tcp(t, _) => Some(t.stats_handle()),
                    Stream::Doh(..) | Stream::Doq(..) | Stream::Doh3(..) => None,
                })
                .collect(),
            doh: self
                .streams
                .iter()
                .filter_map(|(_, s)| match s {
                    Stream::Doh(d, _) => Some(d.stats_handle()),
                    Stream::Doh3(d, _) => Some(d.stats_handle()),
                    Stream::Tcp(..) | Stream::Doq(..) => None,
                })
                .collect(),
            doq: self
                .streams
                .iter()
                .filter_map(|(_, s)| match s {
                    Stream::Doq(d, _) => Some(d.stats_handle()),
                    Stream::Tcp(..) | Stream::Doh(..) | Stream::Doh3(..) => None,
                })
                .collect(),
        }
    }
}

/// Listener counters for `/metrics`.
struct ListenerStats {
    udp: Vec<Arc<telltale_net::WorkerStats>>,
    tcp: Vec<Arc<telltale_net::TcpStats>>,
    doh: Vec<Arc<telltale_net::DohStats>>,
    doq: Vec<Arc<telltale_net::DoqStats>>,
}

/// `[telemetry]` without what a reload applies (the event sinks and the OTLP destination,
/// interval and headers): what is left is read once, at start.
fn telemetry_at_start(t: &telltale_config::TelemetryConfig) -> telltale_config::TelemetryConfig {
    let mut t = t.clone();
    t.sink.clear();
    t.managed_sink.clear();
    t.managed_otlp = None;
    t.otlp.endpoint = None;
    t.otlp.headers.clear();
    t.otlp.header_refs.clear();
    t.otlp.interval_secs = 0;
    // REQ: OBS-013, OBS-005, OBS-003 (T27.5, ADR-1007) — anomaly detection, the per-client series
    // and the query log's privacy level follow a reload; the rest of the query log doesn't.
    t.anomaly = telltale_config::AnomalyConfig::default();
    t.metrics.per_client = false;
    t.metrics.per_client_cap = 0;
    t.qlog.privacy_level = 0;
    t
}

/// Settings a reload can't change without a restart; returns what differs.
fn restart_only_changes(old: &Config, new: &Config) -> Vec<&'static str> {
    let mut v = Vec::new();
    if old.cache != new.cache {
        v.push("[cache]");
    }
    // REQ: API-016 (T23.11) — sinks and the OTLP destination apply on reload; the rest of
    // `[telemetry]` (and the trace settings) are read once, at start.
    if telemetry_at_start(&old.telemetry) != telemetry_at_start(&new.telemetry) {
        v.push("[telemetry]");
    }
    // REQ: OPS-011 — the log files are opened once, at start.
    if old.support != new.support {
        v.push("[support]");
    }
    // REQ: OPS-012 (T27.11, ADR-1006) — the update check's loop starts with the value it had.
    if old.updates != new.updates {
        v.push("[updates]");
    }
    // REQ: OPS-012 — the watchdog thread reads its settings once, at start.
    if old.watchdog != new.watchdog {
        v.push("[watchdog]");
    }
    if old.node != new.node {
        v.push("[node]");
    }
    // REQ: FLT-901 (T24.29): `entry_budget` and `ads_tier` apply on a reload (the category lists
    // are derived from the configuration each time); the rest of `[filter]` is read at start.
    let fixed = |f: &telltale_config::FilterConfig| {
        let d = telltale_config::FilterConfig::default();
        telltale_config::FilterConfig {
            entry_budget: d.entry_budget,
            ads_tier: d.ads_tier,
            ..f.clone()
        }
    };
    if fixed(&old.filter) != fixed(&new.filter) {
        v.push("[filter]");
    }
    if old.dns != new.dns {
        v.push("[dns]");
    }
    if old.clients.neighbor_table != new.clients.neighbor_table
        || old.clients.neighbor_refresh_secs != new.clients.neighbor_refresh_secs
    {
        v.push("[clients] neighbor_table / neighbor_refresh_secs");
    }
    if old.clients.mdns != new.clients.mdns || old.clients.mdns_port != new.clients.mdns_port {
        v.push("[clients] mdns / mdns_port");
    }
    // The API listener is started once (API-003, ADR-149).
    if old.api.enabled != new.api.enabled
        || old.api.listen != new.api.listen
        || old.api.tls != new.api.tls
    {
        v.push("[api] enabled / listen / tls");
    }
    v
}

/// REQ: OBS-003 — the query-log writer, fed by the aggregator thread. A failure to start
/// it is logged and DNS carries on without a query log (`spec/02` §8.5).
pub(crate) fn query_log(
    cfg: &Config,
) -> (
    Option<Box<dyn telltale_telemetry::ring::Sink>>,
    Option<Arc<telltale_store::qlog::Stats>>,
) {
    let q = &cfg.telemetry.qlog;
    if !q.enabled {
        return (None, None);
    }
    // REQ: CLU-007 — in ship mode the local log is only a buffer: bounded, and closed on a
    // timer so the shipper can deliver it (ADR-055).
    let ship = cfg.telemetry.mode == telltale_config::TelemetryMode::Ship;
    let settings = telltale_store::qlog::Settings {
        dir: std::path::Path::new(cfg.node.data_dir.as_str()).join("qlog"),
        // Cluster node IDs come with membership (T5.x); a standalone node is 0.
        node: 0,
        privacy: q.privacy_level,
        flush_interval: Duration::from_secs(u64::from(q.flush_interval_secs.max(1))),
        fsync: q.fsync,
        retention_days: q.retention_days,
        retention_bytes: if ship {
            q.retention_bytes
                .bytes()
                .min(cfg.telemetry.ship.buffer_bytes.bytes())
        } else {
            q.retention_bytes.bytes()
        },
        rotate_after: ship
            .then(|| Duration::from_secs(u64::from(cfg.telemetry.ship.interval_secs))),
    };
    match telltale_store::qlog::Builder::spawn(settings) {
        Ok(b) => {
            let stats = b.stats();
            (Some(Box::new(b)), Some(stats))
        }
        Err(e) => {
            warn!("query log disabled: cannot start its writer: {e}");
            (None, None)
        }
    }
}

/// The query pipeline for `cfg` (settings derived from config).
fn build_pipeline(
    cfg: &Config,
    cache: Arc<Cache>,
    router: Arc<Router>,
    policy: Policy,
) -> Arc<Pipeline> {
    let settings = Settings {
        edns_payload: cfg.dns.edns_payload,
        stale_answer_timeout: Duration::from_millis(u64::from(
            cfg.cache.stale_answer_client_timeout_ms,
        )),
        // `ring_slots` events of ~128 bytes (ADR-026).
        ring_bytes: usize::try_from(cfg.telemetry.ring_slots).unwrap_or(4096) * 128,
        ..Settings::default()
    };
    let p = Pipeline::new(settings, cache, router, policy);
    p.set_dnssec(cfg);
    // REQ: OBS-019 (T11.4)
    p.set_upstream_check(cfg);
    p
}

/// REQ: OBS-005 — per-client query series are opt-in and capped (`[telemetry.metrics]`).
/// REQ: OBS-022 (T12.1, ADR-111) — the exclusions the aggregator applies from its next drain
/// (at start and on every reload, a replica's included).
pub(crate) fn exclusions(cfg: &Config) -> Option<telltale_telemetry::exclude::Exclusions> {
    let x = &cfg.exclusions;
    if !x.active() {
        return None;
    }
    let names = x.names.iter().filter_map(|n| {
        let bare = n.trim().trim_start_matches("*.");
        telltale_proto::NameBuf::from_presentation(bare)
            .ok()
            .map(|b| b.as_wire().to_vec())
    });
    let nets: Vec<(std::net::IpAddr, u8)> = x.clients.iter().map(|c| (c.addr, c.prefix)).collect();
    Some(telltale_telemetry::exclude::Exclusions::new(names, &nets))
}

/// REQ: OBS-903 (T24.35, ADR-1014) — what stays out of the query log only, from
/// `[exclusions.log]`; applied by the aggregator from its next drain (at start and on every
/// reload). Device names become the configured clients' references (`client_ref`: index + 1);
/// a name no client has matches nothing. `own_lookups` adds loopback and this node's own addresses.
pub(crate) fn log_exclusions(cfg: &Config) -> Option<telltale_telemetry::exclude::LogExclusions> {
    log_exclusions_with(cfg, &own_addresses(cfg))
}

pub(crate) fn log_exclusions_with(
    cfg: &Config,
    own: &[std::net::IpAddr],
) -> Option<telltale_telemetry::exclude::LogExclusions> {
    let x = &cfg.exclusions;
    if !x.log_active() {
        return None;
    }
    let wire = |n: &str| {
        let bare = n.trim().trim_start_matches("*.");
        telltale_proto::NameBuf::from_presentation(bare)
            .ok()
            .map(|b| b.as_wire().to_vec())
    };
    let exact = x
        .log
        .domains
        .iter()
        .filter(|d| !d.trim().starts_with("*."))
        .filter_map(|d| wire(d));
    let under = x
        .log
        .domains
        .iter()
        .filter(|d| d.trim().starts_with("*."))
        .filter_map(|d| wire(d));
    let mut nets: Vec<(std::net::IpAddr, u8)> = Vec::new();
    let mut refs: Vec<u32> = Vec::new();
    for c in &x.log.clients {
        if let Ok(cidr) = telltale_config::Cidr::parse(c) {
            nets.push((cidr.addr, cidr.prefix));
        } else {
            let want = c.trim();
            refs.extend(
                cfg.client
                    .iter()
                    .enumerate()
                    .filter(|(_, k)| k.name.trim().eq_ignore_ascii_case(want))
                    .filter_map(|(i, _)| u32::try_from(i).ok().map(|i| i + 1)),
            );
        }
    }
    if x.log.own_lookups {
        nets.push((std::net::Ipv4Addr::new(127, 0, 0, 0).into(), 8));
        nets.push((std::net::Ipv6Addr::LOCALHOST.into(), 128));
        nets.extend(
            own.iter()
                .map(|ip| (*ip, if ip.is_ipv4() { 32 } else { 128 })),
        );
    }
    Some(telltale_telemetry::exclude::LogExclusions::new(
        exact, under, &nets, refs,
    ))
}

/// This node's own addresses, as far as it can know them without asking the network: the
/// addresses its listeners are bound to (not wildcards), `TELLTALE_NODE_IPS` (the Helm chart sets
/// it), and the local address the kernel would use to reach the outside (a connected UDP socket
/// sends nothing).
fn own_addresses(cfg: &Config) -> Vec<std::net::IpAddr> {
    let mut out: Vec<std::net::IpAddr> = cfg
        .listen
        .iter()
        .map(|l| l.addr.ip())
        .filter(|ip| !ip.is_unspecified())
        .collect();
    if let Ok(v) = std::env::var("TELLTALE_NODE_IPS") {
        out.extend(
            v.split([',', ' '])
                .filter_map(|s| s.trim().parse::<std::net::IpAddr>().ok()),
        );
    }
    for (bind, target) in [("0.0.0.0:0", "192.0.2.1:9"), ("[::]:0", "[2001:db8::1]:9")] {
        if let Ok(sock) = std::net::UdpSocket::bind(bind)
            && sock.connect(target).is_ok()
            && let Ok(a) = sock.local_addr()
            && !a.ip().is_unspecified()
        {
            out.push(a.ip());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// REQ: OBS-901 (T26.2, ADR-958) — the live map's sampler, from `[map]` (`None`: off, and the
/// aggregator thread keeps no window). The slow threshold follows `[slo] latency_ms` unless
/// `[map] warn_latency_ms` is set.
pub(crate) fn map_sampler(cfg: &Config) -> Option<telltale_telemetry::map::Settings> {
    cfg.map.enabled.then(|| telltale_telemetry::map::Settings {
        event_rate: cfg.map.event_rate,
        slow_us: cfg
            .map
            .warn_latency_ms
            .unwrap_or(cfg.slo.latency_ms)
            .saturating_mul(1000),
    })
}

fn set_client_metrics(cfg: &Config, pipeline: &Pipeline) {
    pipeline.telemetry.set_exclusions(exclusions(cfg));
    // REQ: OBS-903 — what stays out of the query log only.
    pipeline.telemetry.set_log_exclusions(log_exclusions(cfg));
    // REQ: OBS-901 — the map's sampler follows `[map]`, at start and on every reload.
    pipeline.telemetry.set_map(map_sampler(cfg));
    let m = &cfg.telemetry.metrics;
    let mut agg = pipeline.telemetry.aggregates();
    agg.exported.client_cap = if m.per_client {
        usize::try_from(m.per_client_cap).unwrap_or(usize::MAX)
    } else {
        0
    };
    // REQ: OBS-016 (ADR-105) — the time buckets count answers slower than the latency
    // objective's threshold.
    agg.slo_latency_us = u64::from(cfg.slo.latency_ms) * 1000;
    agg.internal = internal_names(cfg);
}

/// REQ: OBS-037 (ADR-152) — the names the internal top list takes: reverse lookups of private
/// addresses, `cluster.local` when Kubernetes is on, and `[telemetry] internal_names`.
pub(crate) fn internal_names(cfg: &Config) -> telltale_telemetry::internal::InternalNames {
    let cluster = cfg.kubernetes.enabled.then_some("cluster.local");
    let names = cfg
        .telemetry
        .internal_names
        .iter()
        .map(|n| n.trim().trim_start_matches("*."))
        .chain(cluster)
        .filter_map(|n| {
            telltale_proto::NameBuf::from_presentation(n)
                .ok()
                .map(|b| b.as_wire().to_vec())
        });
    telltale_telemetry::internal::InternalNames::new(names, true)
}

/// Starts the metrics and API listeners; both stop when `stop` turns true.
async fn start_http(
    cfg: &Config,
    sources: &Arc<http::Sources>,
    stop: &tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    let stopped = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|s| *s).await;
    };
    if cfg.telemetry.metrics.enabled {
        let addr = cfg.telemetry.metrics.listen;
        let app = http::router(Arc::clone(sources));
        let bound = http::serve(addr, app, stopped(stop.clone()))
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("metrics {addr}: {e}")))?;
        info!(addr = %bound, "serving /metrics, /healthz, /readyz, /livez");
    }
    // REQ: API-001 — the REST API (and its OpenAPI document) on its own listener.
    // REQ: API-003 — behind sign-in. Rule 5: if state.db can't be opened, the API stays off
    // and DNS keeps answering.
    if cfg.api.enabled {
        let (c, store) = (cfg.clone(), Arc::clone(&sources.secrets));
        let auth =
            match tokio::task::spawn_blocking(move || crate::auth_setup::open(&c, &store)).await {
                Ok(Ok(a)) => a,
                Ok(Err(e)) => {
                    error!("api disabled: cannot open the user database: {e}");
                    return Ok(());
                }
                Err(e) => {
                    error!("api disabled: {e}");
                    return Ok(());
                }
            };
        let _purge =
            crate::auth_setup::spawn_purge(Arc::clone(&auth), cfg.auth.audit_retention_days);
        let addr = cfg.api.listen;
        auth.agents()
            .set(cfg.agents.enabled, cfg.agents.rate_per_minute);
        auth.agents()
            .set_require_approval(cfg.agents.require_approval);
        let _ = sources.auth.set(Arc::clone(&auth));
        // REQ: DSC-001 (T25.2) — the `[discovery]` section as the files set it, at start. The files'
        // own copy is audited, never `cfg`, which may already hold what the API stored.
        let file = sources.file_config.load_full();
        audit_discovery(sources, None, &file);
        audit_cmdb(sources, None, &file);
        // REQ: FLT-005 (ADR-067) — expired quick rules are removed and audit-logged.
        crate::api_backend::spawn_rule_sweep(Arc::clone(sources), Arc::clone(&auth), stop.clone());
        // REQ: API-007, DSC-901 (T35.1, ADR-1032) — names stored with HTML codes are decoded once, on the
        // primary (audited, replicated like any write); file entries are only reported.
        crate::names_repair::spawn(Arc::clone(sources), stop.clone());
        let app = http::api_router(Arc::clone(sources), Arc::clone(&auth));
        // REQ: API-902 (T27.13, ADR-956) — the guarded-changes engine: the API's routes reach it
        // through `Sources`, and the cluster channel's forwarded requests do too.
        start_guarded(sources, &auth, &app, cfg, stop.clone());
        // REQ: API-003 (ADR-149) — HTTPS on the listener itself. Without a certificate the API
        // stays off rather than serving sign-ins in the clear; DNS keeps answering.
        let tls = match &cfg.api.tls {
            None => None,
            Some(t) => match crate::api_tls::setup(cfg, t) {
                Ok(s) => Some(s),
                Err(e) => {
                    error!("api disabled: its TLS certificate ([api] tls): {e}");
                    return Ok(());
                }
            },
        };
        let bound = match &tls {
            Some(t) => crate::api_tls::serve(addr, app, t, stopped(stop.clone())).await,
            None => http::serve(addr, app, stopped(stop.clone())).await,
        }
        .map_err(|e| io::Error::new(e.kind(), format!("api {addr}: {e}")))?;
        let scheme = if tls.is_some() { "https" } else { "http" };
        info!(addr = %bound, scheme, "serving the API at /api/v1 (OpenAPI: /api/v1/openapi.json)");
    }
    Ok(())
}

/// REQ: API-902 (T27.13, ADR-956 §4) — builds the guarded engine and starts the probation watch: the
/// entries a start put on probation become active once the node is healthy (the API listener is
/// bound, its own DNS answers and, for the secrets key, the store is unlocked) within
/// `max(confirm_window_secs, 180)` seconds. DNS never waits for it (CLU-004).
fn start_guarded(
    sources: &Arc<http::Sources>,
    auth: &Arc<telltale_api::auth::Auth>,
    app: &axum::Router,
    cfg: &Config,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    let node = crate::guarded::node_label(cfg);
    crate::guarded::set_this_node(&node);
    let host = crate::guarded::prod::ProdHost::new(Arc::clone(sources), app.clone(), auth);
    let engine = crate::guarded::Engine::new(
        node.clone(),
        Arc::clone(auth.state()),
        host.clone(),
        crate::guarded::appliers::rows(),
        crate::guarded::restart::detect_process(),
    );
    host.set_engine(&engine);
    if sources.guarded.set(engine).is_err() {
        return;
    }
    // REQ: API-902 (ADR-957 step 10) — a removal queued by an offline clear on this replica.
    crate::guarded::prod::spawn_removals(
        Arc::clone(&host),
        Arc::clone(auth.state()),
        node.clone(),
        stop.clone(),
    );
    crate::guarded::probation::spawn_watch(
        Arc::clone(sources),
        Arc::clone(auth.state()),
        node,
        PathBuf::from(cfg.node.data_dir.as_str()),
        cfg.clone(),
        crate::guarded::probation::healthy_deadline_secs(cfg),
        stop,
    );
}

/// Runs until SIGTERM/SIGINT. SIGHUP reloads config from `files`.
// The startup sequence and the main loop read best in one place.
#[allow(clippy::too_many_lines)]
pub(crate) async fn serve(files: Vec<PathBuf>, cfg: Config) -> io::Result<()> {
    // REQ: OPS-007 — before any listener binds: a SIGTERM that comes once the node answers is
    // held until the loop below and drained, instead of ending the process at once.
    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    let mut usr1 = signal(SignalKind::user_defined1())?;
    // spec/04 §7: tag outbound queries so a forwarding loop back to us is detectable.
    telltale_upstream::set_node_tag(rand::random());
    let workers = workers(&cfg);
    let (router, policy) = build_dynamic(&cfg, None).map_err(|errs| {
        for e in &errs {
            error!("{e}");
        }
        io::Error::other("invalid configuration")
    })?;
    let mut health = spawn_health_checks(&router);
    let neighbor_refresh = cfg
        .clients
        .neighbor_table
        .then_some(Duration::from_secs(u64::from(
            cfg.clients.neighbor_refresh_secs,
        )));
    let cache = Arc::new(Cache::new(cache_policy(&cfg.cache, workers)));
    let pipeline = build_pipeline(&cfg, Arc::clone(&cache), router, policy);
    // REQ: OBS-007 (T7.18) — dnstap (read at startup).
    if let Some(tap) = crate::dnstap::start(&cfg) {
        let _ = pipeline.dnstap.set(tap);
    }
    // REQ: DNS-009 — start warm: reload the cache dumped at the last shutdown.
    let warm = cfg
        .cache
        .persist
        .then(|| load_cache(&cfg, &cache, &pipeline));
    // REQ: OBS-002 — one aggregator thread drains the event rings (`spec/06` §2). It never
    // touches the query path: a stalled aggregator only means dropped (counted) events.
    let (qlog, qlog_stats) = query_log(&cfg);
    set_client_metrics(&cfg, &pipeline);
    // REQ: OBS-008 — the live tail is fed by the same aggregator pass as the query log.
    let tail = crate::tail::Tail::new(cfg.telemetry.qlog.privacy_level);
    // REQ: OBS-013 — the anomaly engine rides the same aggregator pass (off the query path).
    let anomalies = crate::anomaly::Anomalies::start(&cfg);
    // REQ: OBS-003 (review 04-05) — level 1's names are hashed with this node's (or, once a
    // primary's version arrives, the cluster's) key.
    crate::privacy::init(std::path::Path::new(cfg.node.data_dir.as_str()));
    // REQ: OBS-033 — change markers: this start, and a new build.
    let annotations = crate::annotations::init(
        std::path::Path::new(cfg.node.data_dir.as_str()),
        crate::annotations::now_ms(),
    );
    annotations.started(
        crate::build_info::VERSION,
        crate::build_info::COMMIT,
        crate::datadir::unclean_start(),
        crate::annotations::now_ms(),
    );
    // REQ: OBS-009 (review 04-04) — the in-memory analytics follow the privacy level.
    pipeline
        .telemetry
        .set_privacy(cfg.telemetry.qlog.privacy_level);
    let anomaly_sink = anomalies
        .as_ref()
        .map(|a| Box::new(a.sink()) as Box<dyn telltale_telemetry::ring::Sink>);
    // REQ: OPS-014 (ADR-903 §2–3) — the secrets store: nothing is read yet (the first use, or
    // the blocking load below, opens it). DNS never waits for it.
    let secrets = Arc::new(crate::secrets::SecretStore::new(&cfg));
    // REQ: OBS-010 (T7.13) — event sinks (file, syslog, webhook) on the same pass.
    let (events, sink_manager) = crate::sinks::start(
        &cfg,
        &pipeline,
        &tokio::runtime::Handle::current(),
        Some(&secrets),
    );
    // REQ: OBS-018 (T11.5) — shadow lists and over-blocking suspects, on the same pass.
    let shadow = Arc::new(crate::shadow::Shadow::new(
        cfg.telemetry.qlog.privacy_level,
        pipeline.telemetry.ts_us(std::time::Instant::now()),
    ));
    let shadow_sink = Box::new(crate::shadow::ShadowSink::new(
        Arc::clone(&shadow),
        Arc::clone(&pipeline),
    )) as Box<dyn telltale_telemetry::ring::Sink>;
    // REQ: OBS-017 (T11.6) — latency exemplars and queries to trace, on the same pass.
    let traces = Arc::new(crate::traces::Traces::default());
    let trace_sink = Box::new(crate::traces::TraceSink::new(Arc::clone(&traces), &cfg))
        as Box<dyn telltale_telemetry::ring::Sink>;
    let extra: Vec<Box<dyn telltale_telemetry::ring::Sink>> = anomaly_sink
        .into_iter()
        .chain([events, shadow_sink, trace_sink])
        .collect();
    let extra =
        Some(Box::new(crate::tail::Fanout(extra)) as Box<dyn telltale_telemetry::ring::Sink>);
    let sink = crate::tail::combine(qlog, tail.as_deref(), extra);
    // REQ: FLT-017 (ADR-150) — with Kubernetes on, the analytics wait briefly for pod addresses
    // from the first query, before the first table arrives, and the workloads' counts carry on.
    if crate::kubernetes::wanted(&cfg) {
        pipeline
            .telemetry
            .set_workload_keys(Some(telltale_telemetry::workload::Keys::new()));
        crate::kubernetes::restore_counts(cfg.node.data_dir.as_str(), &pipeline.telemetry);
    }
    let _aggregator = pipeline
        .telemetry
        .spawn_aggregator(Duration::from_millis(25), sink)?;
    // REQ: OBS-004 (T6.16) — the current and previous hour's top lists come back after a
    // restart, from the query log (in the background; DNS doesn't wait).
    crate::replay::spawn(&cfg, &pipeline);
    let mut listeners = Listeners {
        udp: Vec::new(),
        streams: Vec::new(),
        workers,
        handler: Arc::new(Handler(Arc::clone(&pipeline))),
        rt: tokio::runtime::Handle::current(),
    };
    listeners.apply(&cfg.listen).await?;

    // REQ: OBS-004, `spec/06` §3 — rollups on disk, fed once a minute off the query path.
    let (rollups, _rollup_writer) = crate::rollups::start(&cfg, &pipeline);

    // REQ: OBS-005, OPS-006 — metrics and health probes. An ephemeral resolver pod is ready
    // only once it has the cluster's configuration too, so it never serves unfiltered (CLU-009).
    let readiness = Arc::new(crate::readiness::Readiness::new(cfg.cluster.ephemeral));
    let stats = listeners.stats();
    let (reload_tx, mut reload_rx) =
        tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<bool>>(8);
    let (stop_http, http_stopped) = tokio::sync::watch::channel(false);
    // REQ: CLU-009 — create or join the cluster on first start (the Helm chart's controller
    // and resolver pods). A resolver pod that can't join exits, so Kubernetes retries it.
    if let Err(e) = crate::cluster::bootstrap(&cfg, Duration::from_secs(120)).await {
        if cfg.cluster.ephemeral {
            return Err(io::Error::other(format!("cluster: {e}")));
        }
        warn!("cluster: {e}; running standalone");
    }
    // REQ: CLU-001, CLU-004 — the cluster channel runs beside DNS and never gates it.
    let cluster = crate::cluster::start(&cfg, &http_stopped);
    // REQ: OPS-010 — a maintenance window from before a restart takes effect before the node
    // first reports ready: the operator or the clock, not a reboot, says when it's back.
    let maintenance = Arc::new(crate::maintenance::Maintenance::open(
        std::path::Path::new(cfg.node.data_dir.as_str()),
        Arc::clone(&readiness),
        cluster.clone(),
        crate::maintenance::now_ms(),
    ));
    // REQ: DNS-006, OPS-011, OPS-012 (T27.2, T27.11, ADR-1006) — what this node runs with, for a change
    // to its per-node sections that waits for a restart.
    crate::node_settings::remember_start(&cfg);
    let sources = Arc::new(http::Sources {
        metrics: Arc::clone(&pipeline.metrics),
        cache: Arc::clone(&cache),
        pipeline: Arc::clone(&pipeline),
        udp: ArcSwap::from_pointee(stats.udp),
        tcp: ArcSwap::from_pointee(stats.tcp),
        doh: ArcSwap::from_pointee(stats.doh),
        doq: ArcSwap::from_pointee(stats.doq),
        readiness: Arc::clone(&readiness),
        maintenance,
        drills: Arc::default(),
        identify: Arc::new(crate::identify::Identifier::open(std::path::Path::new(
            cfg.node.data_dir.as_str(),
        ))),
        rollout: Arc::default(),
        started: std::time::Instant::now(),
        allowed: cfg.access.allowed_networks.clone(),
        lists: ArcSwapOption::empty(),
        qlog: qlog_stats,
        config: ArcSwap::from_pointee(cfg.clone()),
        file_config: ArcSwap::from_pointee(load_files(&files).unwrap_or_else(|| {
            // The origin labels (file / API) are only as good as this; say so loudly.
            warn!(
                "config: files alone failed to load; entry origins will read as file until they do"
            );
            cfg.clone()
        })),
        config_files: files.clone(),
        update: Arc::new(std::sync::Mutex::new(crate::updates::initial(
            cfg.updates.check,
        ))),
        rollups: rollups.clone(),
        tail,
        anomalies: anomalies.clone(),
        cache_history: {
            // REQ: OBS-003 (T6.15) — the cache's last hour, off the DNS path.
            let h = Arc::new(crate::cache_history::CacheHistory::new(warm));
            h.spawn(Arc::clone(&cache), http_stopped.clone());
            h
        },
        host: {
            // REQ: CLU-008 (T6.11) — host resources, off the DNS path.
            let h = Arc::new(crate::host::HostMonitor::default());
            h.spawn(std::path::PathBuf::from(cfg.node.data_dir.as_str()));
            h
        },
        auth: std::sync::OnceLock::new(),
        identities_applied: std::sync::Mutex::default(),
        alerts: std::sync::Mutex::default(),
        masking: crate::masking::Detector::default(),
        cluster,
        ship: Arc::default(),
        git_poke: Arc::default(),
        routers: Arc::default(),
        routers_changed: Arc::default(),
        oidc_changed: Arc::default(),
        telemetry_changed: Arc::default(),
        otlp_changed: Arc::default(),
        sinks: sink_manager,
        oidc_fetch: crate::auth_setup::FetchSlot::default(),
        reload: reload_tx,
        config_writes: tokio::sync::Mutex::new(()),
        probes: Arc::default(),
        shadow,
        traces,
        secrets,
        discovery: Arc::default(),
        cmdb: Arc::default(),
        guarded: crate::guarded::Slot::new(),
        geoip: Arc::new(crate::geoip::GeoIp::new(
            crate::geoip::Options::from_env(),
            crate::geoip::GeoIp::jitter_of(&crate::http::node_name(&cfg)),
        )),
    });
    // REQ: DSC-001 (T25.2, ADR-907) — the network inventory starts here only if `[discovery]` is
    // on and this node is the designated one (ephemeral pods and witnesses never are).
    // REQ: DSC-902 (T31.2) — the inventory pushes what it reads to the CMDB sink, when one runs.
    sources.discovery.set_cmdb_sink(sources.cmdb.sink());
    reconcile_discovery(&sources, &pipeline, &cfg);
    // REQ: DSC-901 (T31.2, ADR-1005 section 1) — the CMDB starts here only if `[cmdb]` is on and this
    // node is the one `[discovery]` designates (even when discovery itself is off).
    reconcile_cmdb(&sources, &pipeline, &cfg);
    // REQ: DSC-901, DSC-906 (T31.2) - with no node named, the designated node is the cluster's
    // primary: when that changes (a failover), the CMDB and the inventory move with it, not only at
    // the next configuration reload.
    if sources.cluster.is_some() && !cfg.cluster.ephemeral {
        let (s, p, mut stop) = (
            Arc::clone(&sources),
            Arc::clone(&pipeline),
            http_stopped.clone(),
        );
        tokio::spawn(async move {
            let designated = |s: &http::Sources| {
                let cfg = s.config.load_full();
                let own = crate::discovery::runtime::own_of(s.cluster.as_deref(), &cfg);
                crate::discovery::gate::designated(&cfg.discovery, own.me())
            };
            let mut last = designated(&s);
            loop {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(10)) => {}
                    _ = stop.wait_for(|v| *v) => return,
                }
                let now = designated(&s);
                if now != last {
                    last = now;
                    let cfg = s.config.load_full();
                    reconcile_discovery(&s, &p, &cfg);
                    reconcile_cmdb(&s, &p, &cfg);
                }
            }
        });
    }
    // REQ: OPS-014, API-014 (ADR-903 §3) — the store and the node key, at start on full members
    // (the key made on the first one, while the table is empty), so a missing or unreadable key
    // shows in the log at once; then every 30 s it retries a locked store, and a locked replica
    // whose rows are all the cluster's heals. Resolver pods hold no secrets and need none.
    // Nothing here waits on it (blocking tasks): DNS doesn't depend on the store.
    if !cfg.cluster.ephemeral {
        crate::secrets::store::spawn_upkeep(
            Arc::clone(&sources),
            cfg.clone(),
            http_stopped.clone(),
        );
        // REQ: CLU-015 (ADR-903 §6) — the secrets replication task: publishes this node's head,
        // pulls from the primary, refills a locked primary, purges after a removal.
        crate::secrets::sync::spawn(Arc::clone(&sources), http_stopped.clone());
        // REQ: DSC-906 (T31.2, ADR-1021) — the CMDB's authored data on the standby nodes.
        crate::cmdb::replication::spawn(Arc::clone(&sources), http_stopped.clone());
    }
    http::serve_peers(&sources);
    // REQ: OBS-025 — device identification, on a thread of its own.
    sources.identify.spawn(Arc::clone(&sources));
    // REQ: OPS-010 — the maintenance window ends by itself.
    crate::maintenance::spawn_expiry(Arc::clone(&sources), http_stopped.clone());
    // REQ: OBS-020 (T11.3) — synthetic probes of every listener, off the DNS path.
    crate::probes::spawn(Arc::clone(&sources), http_stopped.clone());
    // REQ: OBS-902 (T26.4, ADR-959) - the GeoIP database: fetched only after an admin's opt-in,
    // in the background, on nodes that serve the console (a resolver pod never fetches).
    if cfg.node.role != telltale_config::Role::Resolver {
        tokio::spawn(Arc::clone(&sources.geoip).run(Arc::clone(&sources), http_stopped.clone()));
    }
    // REQ: OPS-012 (ADR-163) — the watchdog: a thread outside the runtime that restarts a node
    // that stops answering, after a dump of why.
    crate::watchdog::spawn(
        &cfg,
        tokio::runtime::Handle::current(),
        http_stopped.clone(),
    );
    #[cfg(feature = "wedge-test")]
    crate::watchdog::wedge_for_test(&tokio::runtime::Handle::current());
    // REQ: OBS-033 — breaker markers and the daily compaction, off the DNS path.
    crate::annotations::spawn(Arc::clone(&sources), annotations, http_stopped.clone());
    // REQ: CLU-003 — the Git config source polls on the primary (ADR-049).
    if let Some(c) = &sources.cluster
        && cfg.cluster.git.is_some()
    {
        tokio::spawn(crate::gitsource::run(
            Arc::clone(c),
            Arc::clone(&sources),
            Arc::clone(&sources.git_poke),
            http_stopped.clone(),
        ));
    }
    // REQ: CLU-007 — ship mode delivers the query log to another node (ADR-055).
    if let Some(c) = &sources.cluster
        && cfg.telemetry.mode == telltale_config::TelemetryMode::Ship
        && cfg.telemetry.qlog.enabled
    {
        tokio::spawn(crate::ship::run(
            Arc::clone(c),
            std::path::Path::new(cfg.node.data_dir.as_str()).join("qlog"),
            cfg.telemetry.ship.to.as_ref().map(ToString::to_string),
            Arc::clone(&sources.ship),
            http_stopped.clone(),
        ));
    }
    // REQ: CLU-007 (T9.3) — ship mode also sends per-minute counts (dashboard history).
    if let (Some(c), Some(db)) = (&sources.cluster, &sources.rollups)
        && cfg.telemetry.mode == telltale_config::TelemetryMode::Ship
    {
        tokio::spawn(crate::ship::run_rollups(
            Arc::clone(c),
            Arc::clone(db),
            cfg.telemetry.ship.to.as_ref().map(ToString::to_string),
            // As often as query-log parts, at most once a minute (minutes complete then).
            std::time::Duration::from_secs(
                u64::from(cfg.telemetry.ship.interval_secs).clamp(5, 60),
            ),
            http_stopped.clone(),
        ));
    }
    // REQ: FLT-010 (T7.10) — schedules: which are on, every 15 s.
    tokio::spawn(schedule_ticker(Arc::clone(&sources), http_stopped.clone()));
    // REQ: OBS-010 (T7.12)
    tokio::spawn(crate::alerts::run(
        Arc::clone(&sources),
        http_stopped.clone(),
    ));
    // REQ: API-016 (T23.11) — event sinks follow the configuration without a restart.
    tokio::spawn(crate::sinks::run(
        Arc::clone(&sources),
        http_stopped.clone(),
    ));
    // REQ: OBS-006 (T7.17)
    tokio::spawn(crate::otlp::run(Arc::clone(&sources), http_stopped.clone()));
    // REQ: OBS-017 (T11.6) — sampled and slow queries as OTLP traces.
    tokio::spawn(crate::traces::run(
        Arc::clone(&sources),
        http_stopped.clone(),
    ));
    // REQ: API-016 (T23.10, ADR-903 §7) — OIDC providers apply without a restart; one pass at
    // start-up reads what changed since the service was built.
    crate::auth_setup::run(Arc::clone(&sources), http_stopped.clone());
    sources.oidc_changed.notify_one();
    // REQ: OBS-902 (T26.4) - a changed `[map.geoip]` is looked at now (a fetch starts, or stops).
    sources.geoip.poke();
    // REQ: T8.2 — device names from the routers' DHCP; API-016 (T23.7) — the live list: a router
    // the API or UI changes is read again without a restart.
    tokio::spawn(crate::routers::run(
        Arc::clone(&sources),
        http_stopped.clone(),
    ));
    // REQ: DNS-023 (T22.1) — device names answered in DNS (`[local] device_domain`), rebuilt
    // off the query path; follows reloads.
    tokio::spawn(crate::device_dns::run(
        Arc::clone(&pipeline),
        cfg.clients.mdns,
        http_stopped.clone(),
    ));
    // REQ: T8.3 — device names from mDNS announcements (read at startup).
    if cfg.clients.mdns {
        tokio::spawn(crate::mdns::run(
            cfg.clients.mdns_port,
            Arc::clone(&pipeline.mdns_names),
            http_stopped.clone(),
        ));
    }
    // REQ: CLU-002 (ADR-125) — the device names the other nodes know, so every node names a
    // client the same way.
    tokio::spawn(crate::devices::run(
        Arc::clone(&sources),
        http_stopped.clone(),
    ));
    // REQ: FLT-017 — Kubernetes workloads: the watcher (on its own thread) or the table from
    // the cluster; never on the DNS path.
    tokio::spawn(crate::kubernetes::run(
        Arc::clone(&sources),
        http_stopped.clone(),
    ));
    // REQ: CLU-014 — failover drills: expiry, windows, reports, the seen table's file.
    crate::drill::spawn(Arc::clone(&sources), http_stopped.clone());
    // REQ: CLU-011 (T8.1) — warm the cache from the cluster's hot names.
    tokio::spawn(crate::warm::run(Arc::clone(&sources), http_stopped.clone()));
    // REQ: OPS-004 (ADR-046) — a daily check of the signed release index (off: nothing leaves).
    tokio::spawn(crate::updates::run(
        Arc::clone(&sources.update),
        cfg.updates.check,
        cfg.updates.index_url.as_ref().map(ToString::to_string),
        http_stopped.clone(),
    ));
    start_http(&cfg, &sources, &http_stopped).await?;
    let neighbors =
        neighbor_refresh.map(|every| spawn_neighbor_refresh(Arc::clone(&pipeline), every));
    // Every listener is bound: ready for traffic (OPS-006), unless in maintenance (OPS-010).
    // An ephemeral resolver pod waits for the cluster's configuration too, so it never serves
    // unfiltered (CLU-009).
    readiness.set_bound();
    // REQ: OPS-901 (ADR-1014) — from here `/readyz` also asks the UDP listener.
    readiness.enable_dns_check();
    // REQ: NFR-001 (T10.2) — once start-up has settled, the code that ran only for it (config
    // loading, the API router and OpenAPI document) stops counting as resident.
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(15)).await;
        trim_code_pages("start-up");
    });
    if let Some(c) = &sources.cluster
        && cfg.cluster.ephemeral
    {
        let (c, readiness) = (Arc::clone(c), Arc::clone(&readiness));
        tokio::spawn(async move {
            while c.sync_status().applied_ms == 0 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            info!("cluster configuration applied: ready");
            readiness.set_synced();
        });
    }

    // REQ: FLT-004 — lists download in the background once DNS is up (rule 5: DNS never
    // waits for, or depends on, a list).
    // A synced replica gets them compiled from the primary instead (CLU-003).
    let mut lists = if crate::replication::follows_primary(&cfg) {
        None
    } else {
        Lists::start(&cfg, &pipeline)
    };
    sources
        .lists
        .store(lists.as_ref().map(|l| Arc::clone(&l.shared)));
    if let Some(c) = &sources.cluster {
        crate::replication::start(
            c,
            files.clone(),
            &sources,
            sources.reload.clone(),
            &http_stopped,
        );
    }

    let mut current = cfg;
    loop {
        tokio::select! {
            _ = term.recv() => { info!(signal = "SIGTERM", "shutting down"); break; }
            _ = tokio::signal::ctrl_c() => { info!(signal = "SIGINT", "shutting down"); break; }
            // REQ: API-902 (ADR-956 §4a) — an admin's "Restart now": the same drain as a SIGTERM,
            // then exit 75 (main).
            () = crate::guarded::restart::wait_requested() => { info!("restart requested: draining"); break; }
            _ = hup.recv() => { reload(&files, &mut current, &mut listeners, &mut health, &pipeline, &sources, &mut lists, false).await; }
            // ADR-040 — a change made through the API: re-read files + state.db and apply.
            Some(done) = reload_rx.recv() => {
                let ok = reload(&files, &mut current, &mut listeners, &mut health, &pipeline, &sources, &mut lists, true).await;
                let _ = done.send(ok);
            }
            _ = usr1.recv() => {
                // REQ: FLT-004 — refresh every list now (like `pihole -g`); the compiler
                // runs if anything changed.
                if let Some(l) = &lists {
                    info!(signal = "SIGUSR1", "refreshing lists");
                    l.shared.fetcher.request_refresh();
                }
            }
        }
    }

    // REQ: OPS-007 — not ready first (load balancers stop sending), stop taking new TCP
    // connections, let in-flight upstream lookups finish (bounded), then stop UDP workers.
    readiness.set_stopping();
    // REQ: OBS-025 — keep the device identities across the restart.
    sources.identify.save();
    // REQ: DSC-002 (T25.3) — the network inventory and its workers stop, and the inventory is saved.
    let discovery = Arc::clone(&sources.discovery);
    let _ = tokio::task::spawn_blocking(move || discovery.stop()).await;
    // REQ: DSC-906 (T31.2) — the CMDB flushes its last-seen times and stops.
    let cmdb = Arc::clone(&sources.cmdb);
    let _ = tokio::task::spawn_blocking(move || cmdb.stop()).await;
    // REQ: CLU-009 — a resolver pod leaves the cluster now rather than showing as down until
    // it expires (2 s at most; if the primary can't be reached, expiry still cleans up).
    // Before the stop signal: it closes the stream to the primary that the leave goes over.
    if let Some(c) = &sources.cluster
        && current.cluster.ephemeral
        && let Err(e) = c.leave(Duration::from_secs(2)).await
    {
        info!("cluster: leaving: {e}");
    }
    let _ = stop_http.send(true);
    // Keep answering while load balancers notice: a Kubernetes Service takes a moment to drop
    // a terminating pod, and queries sent to it meanwhile would otherwise be lost.
    // A requested restart drains within 5 seconds (ADR-956 §4a), whatever the drain delay says.
    let delay = if crate::guarded::restart::requested() {
        0
    } else {
        current.node.drain_delay_secs.min(60)
    };
    if delay > 0 {
        info!(
            seconds = delay,
            "shutdown: still answering while load balancers move away"
        );
        tokio::time::sleep(Duration::from_secs(u64::from(delay))).await;
    }
    for (_, s) in listeners.streams.drain(..) {
        s.shutdown().await;
    }
    if !pipeline.drain(Duration::from_secs(3)).await {
        warn!("shutdown: some upstream lookups were still in flight after 3 s");
    }
    for (_, l) in listeners.udp.drain(..) {
        l.shutdown();
    }
    health.abort();
    if let Some(n) = neighbors {
        n.abort();
    }
    if let Some(l) = lists {
        l.stop();
    }
    if current.cache.persist {
        save_cache(&current, &cache);
    }
    Ok(())
}

/// Where the cache is dumped (DNS-009).
fn cache_dump_path(cfg: &Config) -> PathBuf {
    Path::new(cfg.node.data_dir.as_str()).join("cache.bin")
}

/// What the cached answers depend on besides the question: upstreams and routes (a "view"
/// is a position in them). A dump taken under other routing isn't loaded.
fn cache_fingerprint(cfg: &Config) -> u64 {
    let b =
        serde_json::to_vec(&(&cfg.upstream, &cfg.upstream_group, &cfg.route)).unwrap_or_default();
    let h = blake3::hash(&b);
    u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap_or([0; 8]))
}

/// REQ: DNS-009 — loads the dump, then removes it (a crash later shouldn't reload old data).
/// Returns what happened, for the Cache page (T6.15).
fn load_cache(
    cfg: &Config,
    cache: &Cache,
    pipeline: &Pipeline,
) -> telltale_api::model::CacheWarmStart {
    let at = telltale_api::time::format_us(crate::cache_history::now_ms().saturating_mul(1000));
    let path = cache_dump_path(cfg);
    let Ok(data) = std::fs::read(&path) else {
        return telltale_api::model::CacheWarmStart {
            at,
            loaded: None,
            note: Some(
                "no dump from the last shutdown (first start, or it didn't stop cleanly)".into(),
            ),
        };
    };
    let _ = std::fs::remove_file(&path);
    match cache.load(
        &data,
        std::time::Instant::now(),
        cache_fingerprint(cfg),
        |n| pipeline.name_hash(n),
    ) {
        Ok(n) => {
            info!(
                entries = n,
                "cache: reloaded the dump from the last shutdown"
            );
            telltale_api::model::CacheWarmStart {
                at,
                loaded: Some(n as u64),
                note: None,
            }
        }
        Err(e) => {
            warn!("cache: not reloading the dump: {e}");
            telltale_api::model::CacheWarmStart {
                at,
                loaded: None,
                note: Some(e.clone()),
            }
        }
    }
}

/// REQ: DNS-009 — dumps the cache on shutdown (owner-only: it reveals what was looked up).
fn save_cache(cfg: &Config, cache: &Cache) {
    let path = cache_dump_path(cfg);
    let tmp = path.with_extension("tmp");
    let mut buf = Vec::new();
    let result = cache
        .dump(std::time::Instant::now(), cache_fingerprint(cfg), &mut buf)
        .and_then(|n| {
            std::fs::write(&tmp, &buf)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
            }
            std::fs::rename(&tmp, &path)?;
            Ok(n)
        });
    match result {
        Ok(n) => info!(
            entries = n,
            bytes = buf.len(),
            "cache: dumped for the next start"
        ),
        Err(e) => warn!("cache: couldn't dump: {e}"),
    }
}

/// REQ: OPS-009 — validate the whole new config, then swap; on any error keep serving the
/// running configuration.
// Everything a reload swaps; grouping it would only rename the parameters.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn reload(
    files: &[PathBuf],
    current: &mut Config,
    listeners: &mut Listeners,
    health: &mut JoinHandle<()>,
    pipeline: &Arc<Pipeline>,
    sources: &Arc<http::Sources>,
    lists: &mut Option<Lists>,
    from_api: bool,
) -> bool {
    if from_api {
        info!("applying a configuration change made through the API");
    } else {
        info!(signal = "SIGHUP", "reloading configuration");
    }
    // An API or replicated change leaves the files as they were: their warnings (a replica's
    // file has no upstreams, by design) were logged at start-up or on the last SIGHUP.
    let loaded = if from_api {
        load_files_quiet(files)
    } else {
        load_files(files)
    };
    let Some(file) = loaded else {
        error!("reload failed: configuration invalid; still serving the previous configuration");
        return false;
    };
    let new = crate::replication::effective(&file);
    // Unchanged upstream config keeps the running router: its health state, pooled
    // connections, and bootstrap cache survive the reload (T2.7).
    let same_upstreams = current.upstream == new.upstream
        && current.upstream_group == new.upstream_group
        && current.route == new.route
        && current.listen == new.listen;
    let reuse = same_upstreams.then(|| Arc::clone(&pipeline.current().router));
    let (router, policy) = match build_dynamic(&new, reuse) {
        Ok(v) => v,
        Err(errs) => {
            for e in &errs {
                error!("{e}");
            }
            error!("reload failed; still serving the previous configuration");
            return false;
        }
    };
    set_client_metrics(&new, pipeline);
    if let Err(e) = listeners.apply(&new.listen).await {
        error!("reload: {e}; listeners unchanged where binding failed");
    }
    if !same_upstreams {
        health.abort();
        *health = spawn_health_checks(&router);
    }
    pipeline.reload(router, policy);
    pipeline.set_dnssec(&new);
    // REQ: API-016 (T23.7, ADR-922) — the router poll loop reads the new list at once.
    sources.routers_changed.notify_one();
    pipeline.set_upstream_check(&new);
    let stats = listeners.stats();
    sources.udp.store(Arc::new(stats.udp));
    sources.tcp.store(Arc::new(stats.tcp));
    sources.doh.store(Arc::new(stats.doh));
    sources.doq.store(Arc::new(stats.doq));
    if crate::replication::follows_primary(&new) {
        // REQ: CLU-003 — a synced replica serves the primary's compiled lists.
        if let Some(l) = lists.take() {
            info!("following the cluster primary: this node no longer downloads lists");
            l.stop();
            sources.lists.store(None);
        }
    } else if let Some(l) = lists {
        l.reload(&new);
    } else {
        *lists = Lists::start(&new, pipeline);
        sources
            .lists
            .store(lists.as_ref().map(|l| Arc::clone(&l.shared)));
    }
    let restart = restart_only_changes(current, &new);
    if !restart.is_empty() {
        warn!(sections = ?restart, "these changes take effect after a restart");
    }
    // API changes are audited by the API with their author.
    if !from_api {
        audit_reload(sources, files, current, &new);
        audit_discovery(sources, Some(&current.discovery), &new);
        audit_cmdb(sources, Some(&current.cmdb), &new);
    }
    reconcile_discovery(sources, pipeline, &new);
    reconcile_cmdb(sources, pipeline, &new);
    if let Some(a) = &sources.anomalies {
        a.reconfigure(&new);
    }
    // REQ: OPS-014 (ADR-903 §2–3) — new key settings are read at the next use; a reference to a
    // secret this node doesn't store is a warning (DNS never depends on the store).
    // The check may load the store (SQLite, a key file): a blocking task, not this worker.
    sources.secrets.configure(&new);
    {
        let (store, cfg) = (Arc::clone(&sources.secrets), new.clone());
        drop(tokio::task::spawn_blocking(move || {
            crate::secrets::credential::warn_missing(&cfg, &store);
        }));
    }
    // REQ: AGT-009 — the agent kill switch follows the (cluster-shared) configuration.
    if let Some(a) = sources.auth.get() {
        a.agents()
            .set(new.agents.enabled, new.agents.rate_per_minute);
        a.agents().set_require_approval(new.agents.require_approval);
    }
    sources
        .pipeline
        .telemetry
        .set_privacy(new.telemetry.qlog.privacy_level);
    config_marker(sources, current, &new);
    sources.config.store(Arc::new(new.clone()));
    sources.file_config.store(Arc::new(file));
    *current = new;
    // REQ: API-016 (T23.10, ADR-903 §7) — OIDC providers added, changed or removed (the files',
    // the UI's, or a replicated node-managed entry) apply now, without a restart; discovery and
    // keys are read off this task, and a failure keeps the previous settings.
    sources.oidc_changed.notify_one();
    // REQ: API-016 (T23.11, ADR-984) - event sinks and the OTLP export follow the configuration
    // (the files', the UI's, or a replicated node-managed entry) without a restart.
    sources.notify_telemetry_changed();
    // REQ: FLT-017 — a `[[kubernetes.map]]` rule or a group change reaches the workload table
    // before the next query, not on the watcher's next tick.
    sources.pipeline.kube.reconfigured.notify_one();
    info!("configuration reloaded");
    true
}

/// REQ: OBS-033 — the `config.applied` marker for a reload that changed the configuration (a
/// cluster's primary writes it when it publishes the version).
fn config_marker(sources: &http::Sources, old: &Config, new: &Config) {
    let Some(ann) = crate::annotations::get() else {
        return;
    };
    let sections = crate::annotations::changed_sections(old, new);
    let primary = !crate::replication::follows_primary(new)
        && sources.cluster.as_ref().is_some_and(|c| c.is_primary());
    let seq = || match &sources.cluster {
        Some(c) => Some(c.local_state().applied_seq).filter(|s| *s > 0),
        None => sources
            .auth
            .get()
            .and_then(|a| a.state().config_version().ok()),
    };
    ann.reloaded(sections, primary, seq, crate::annotations::now_ms());
}

/// REQ: API-006 — a reload that changed anything is audited with the changed settings'
/// paths (never their values: configs can hold secrets).
/// REQ: DSC-001 (T25.2, ADR-907) — the `[discovery]` section is audited when the files set it: at
/// start (`old` is `None`), and on a reload that changes it, as `discovery.config_changed` with
/// `source = file`. Changes made through the API are audited by the API with their author.
fn audit_discovery(
    sources: &http::Sources,
    old: Option<&telltale_config::DiscoveryConfig>,
    new: &Config,
) {
    let Some(auth) = sources.auth.get() else {
        return;
    };
    let Some(detail) = discovery_audit_detail(old, new) else {
        return;
    };
    let auth = Arc::clone(auth);
    tokio::task::spawn_blocking(move || {
        auth.record(
            &telltale_api::auth::Actor::system("config"),
            "discovery.config_changed",
            "discovery",
            &detail,
        );
    });
}

/// REQ: DSC-901 (T31.2, ADR-1005 section 1) — the `[cmdb]` section is audited when the files set it: at
/// start (`old` is `None`), and on a reload that changes it, as `cmdb.config_changed` with
/// `source = file`. Changes made through the API are audited by the API with their author.
fn audit_cmdb(sources: &http::Sources, old: Option<&telltale_config::CmdbConfig>, new: &Config) {
    let Some(auth) = sources.auth.get() else {
        return;
    };
    let changed = match old {
        Some(o) => *o != new.cmdb,
        None => !new.cmdb.is_default(),
    };
    if !changed {
        return;
    }
    let detail = serde_json::json!({
        "source": "file",
        "cmdb": serde_json::to_value(&new.cmdb).unwrap_or(serde_json::Value::Null),
    });
    let auth = Arc::clone(auth);
    tokio::task::spawn_blocking(move || {
        auth.record(
            &telltale_api::auth::Actor::system("config"),
            "cmdb.config_changed",
            "cmdb",
            &detail,
        );
    });
}

/// REQ: DSC-901, DSC-906 (T31.2) — the CMDB starts, stops or restarts to match `cfg`, on this node
/// only when it is the one `[discovery]` designates. Called at start-up and on every reload.
fn reconcile_cmdb(sources: &http::Sources, pipeline: &Pipeline, cfg: &Config) {
    let own = crate::discovery::runtime::own_of(sources.cluster.as_deref(), cfg);
    let data_dir = std::path::PathBuf::from(cfg.node.data_dir.as_str());
    let (rt, cfg) = (Arc::clone(&sources.cmdb), cfg.clone());
    let telemetry = Arc::clone(&pipeline.telemetry);
    let workloads = Arc::clone(&pipeline.workloads);
    let cluster = sources.cluster.clone();
    let feeds = crate::cmdb::thread::Feeds {
        routers: Some(Arc::clone(&pipeline.router_leases)),
        mdns: Some(Arc::clone(&pipeline.mdns_names)),
        networks: Some(Arc::clone(&pipeline.router_networks)),
        clients: Some(Arc::new(move |now| {
            telemetry
                .aggregates()
                .last_hour_counts(u64::try_from(now).unwrap_or(0))
        })),
        workloads: Some(Arc::new(move || {
            workloads
                .snapshot()
                .workloads()
                .iter()
                .map(|w| crate::cmdb::adapters::WorkloadRow {
                    namespace: w.namespace.to_string(),
                    kind: w.kind.to_string(),
                    name: w.name.to_string(),
                    addresses: w
                        .pods
                        .iter()
                        .flat_map(|p| p.ips.iter().map(ToString::to_string))
                        .collect(),
                })
                .collect()
        })),
        nodes: cluster.map(
            |c| -> Arc<dyn Fn() -> Vec<crate::cmdb::adapters::NodeRow> + Send + Sync> {
                Arc::new(move || {
                    let mut rows: Vec<crate::cmdb::adapters::NodeRow> = c
                        .members()
                        .into_iter()
                        .map(|m| crate::cmdb::adapters::NodeRow {
                            id: m.node_id,
                            address: m.advertise.first().cloned().unwrap_or_default(),
                            primary: m.primary,
                            version: m.version,
                        })
                        .collect();
                    let me = c.identity.meta.node_id.clone();
                    if !rows.iter().any(|r| r.id == me) {
                        rows.push(crate::cmdb::adapters::NodeRow {
                            id: me,
                            address: String::new(),
                            primary: c.is_primary(),
                            version: crate::build_info::VERSION.to_owned(),
                        });
                    }
                    rows
                })
            },
        ),
        neighbours: true,
        own_networks: true,
        ifindex_root: None,
    };
    // REQ: DSC-901 — the generation is taken here, in reload order; the blocking task applies it.
    let generation = rt.next_generation();
    // A stopping CMDB flushes and joins its thread: that happens off the runtime's workers.
    drop(tokio::task::spawn_blocking(move || {
        rt.reconcile(generation, &cfg, &data_dir, &own, feeds);
    }));
}

/// REQ: DSC-001, DSC-002 (T25.2, T25.3, ADR-907, ADR-928) — the network inventory starts, stops or
/// restarts to match `cfg`, on this node only when it is the designated one (ephemeral pods and
/// witnesses never are). Called at start-up and on every reload.
fn reconcile_discovery(sources: &http::Sources, pipeline: &Pipeline, cfg: &Config) {
    let own = crate::discovery::runtime::own_of(sources.cluster.as_deref(), cfg);
    let data_dir = std::path::PathBuf::from(cfg.node.data_dir.as_str());
    let (rt, cfg) = (Arc::clone(&sources.discovery), cfg.clone());
    let (routers, mdns) = (
        Arc::clone(&pipeline.router_leases),
        Arc::clone(&pipeline.mdns_names),
    );
    // REQ: DSC-009 - the sessions the router poll shares with the inventory thread.
    let shared = sources.routers.share();
    // REQ: DSC-001 — the generation is taken here, in reload order; the blocking task applies it.
    let generation = rt.next_generation();
    // A stopping inventory saves and joins its thread: that happens off the runtime's workers.
    drop(tokio::task::spawn_blocking(move || {
        rt.reconcile(
            generation,
            &cfg,
            &data_dir,
            &own,
            Some(routers),
            Some(mdns),
            Some(shared),
        );
    }));
}

/// The detail of the `discovery.config_changed` record, or `None` when the section didn't change
/// (`old` is `None` at start: then any section the files set is recorded).
pub(crate) fn discovery_audit_detail(
    old: Option<&telltale_config::DiscoveryConfig>,
    new: &Config,
) -> Option<serde_json::Value> {
    let changed = match old {
        Some(o) => *o != new.discovery,
        None => !new.discovery.is_default(),
    };
    changed.then(|| {
        serde_json::json!({
            "source": "file",
            "discovery": serde_json::to_value(&new.discovery).unwrap_or(serde_json::Value::Null),
        })
    })
}

fn audit_reload(sources: &http::Sources, files: &[PathBuf], old: &Config, new: &Config) {
    let Some(auth) = sources.auth.get() else {
        return;
    };
    let (Ok(a), Ok(b)) = (serde_json::to_value(old), serde_json::to_value(new)) else {
        return;
    };
    let mut changed = Vec::new();
    changed_paths(&a, &b, String::new(), &mut changed);
    if changed.is_empty() {
        return;
    }
    let files: Vec<String> = files.iter().map(|f| f.display().to_string()).collect();
    let more = changed.len().saturating_sub(100);
    changed.truncate(100);
    let auth = Arc::clone(auth);
    let target = files.join(", ");
    let detail = serde_json::json!({ "changed": changed, "more": more, "files": files });
    tokio::task::spawn_blocking(move || {
        auth.record(
            &telltale_api::auth::Actor::system("reload"),
            "config.reload",
            &target,
            &detail,
        );
    });
}

/// Dotted paths whose values differ (arrays compare as a whole).
pub(crate) fn changed_paths(
    old: &serde_json::Value,
    new: &serde_json::Value,
    at: String,
    out: &mut Vec<String>,
) {
    use serde_json::Value::Object;
    match (old, new) {
        (Object(before), Object(after)) => {
            let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let path = if at.is_empty() {
                    key.clone()
                } else {
                    format!("{at}.{key}")
                };
                match (before.get(key), after.get(key)) {
                    (Some(was), Some(now)) => changed_paths(was, now, path, out),
                    _ => out.push(path),
                }
            }
        }
        _ if old != new => out.push(if at.is_empty() { "(root)".into() } else { at }),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use telltale_net::{QueryHandler, RequestMeta, Response, Transport};
    use telltale_proto::{EdnsOut, NameBuf, build_query, records, rtype};

    use super::*;
    use crate::pipeline::{Handler, Policy};

    // REQ: FLT-006, DNS-001 (T24.32, ADR-1000) — a device behind a router has no neighbor entry of
    // its own, so its MAC comes from the router's lease; the kernel's entry wins where both exist;
    // an offline lease and an empty or zero MAC are left out; a device's IPv6 address carries it too.
    #[test]
    fn flt_006_routed_devices_get_their_mac_from_router_leases() {
        use crate::devices::{Lease, Leases};
        use std::net::{IpAddr, Ipv4Addr};
        let kernel = [telltale_net::Neighbor {
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
            mac: [2, 0, 0, 0, 0, 0x20],
            ifindex: 2,
            state: 0x02,
        }];
        let lease = |last: u8, mac: &str, offline: bool, third: u8| {
            let ip = Ipv4Addr::new(192, 168, third, last);
            (
                ip,
                Lease {
                    mac: mac.into(),
                    ip,
                    hostname: None,
                    expires: 0,
                    router: Some("udm".into()),
                    offline,
                    ipv6: vec![format!("2001:db8:{third}::{last}").parse().unwrap()],
                },
            )
        };
        let leases: Leases = [
            // On the IoT VLAN, behind the router: not in the kernel table.
            lease(41, "aa:bb:cc:dd:ee:41", false, 200),
            // Also in the kernel table, with another MAC: the kernel's wins.
            lease(20, "aa:bb:cc:dd:ee:99", false, 10),
            lease(42, "aa:bb:cc:dd:ee:42", true, 200),
            lease(43, "", false, 200),
            lease(44, "00:00:00:00:00:00", false, 200),
        ]
        .into_iter()
        .collect();
        let n = telltale_policy::Neighbors::default();
        n.replace(merged_macs(&kernel, &leases));
        let mac41 = Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x41]);
        assert_eq!(n.get("203.0.113.41".parse().unwrap()), mac41);
        assert_eq!(n.get("2001:db8:200::41".parse().unwrap()), mac41);
        assert_eq!(
            n.get("192.0.2.20".parse().unwrap()),
            Some([2, 0, 0, 0, 0, 0x20]),
            "the kernel's entry wins"
        );
        for gone in ["203.0.113.42", "203.0.113.43", "203.0.113.44"] {
            assert_eq!(n.get(gone.parse().unwrap()), None, "{gone}");
        }
    }

    // REQ: OBS-037 — `cluster.local` is internal only with Kubernetes on; `[telemetry]
    // internal_names` adds suffixes; private reverse lookups always are; validation refuses a
    // name that isn't one.
    #[test]
    fn obs_037_internal_names_from_config() {
        let wire = |s: &str| NameBuf::from_presentation(s).unwrap().as_wire().to_vec();
        let parse = |t: &str| toml::from_str::<Config>(t).unwrap();
        let off = internal_names(&Config::default());
        assert!(!off.is_internal(&wire("kubernetes.default.svc.cluster.local")));
        assert!(off.is_internal(&wire("20.1.168.192.in-addr.arpa")));
        let on = internal_names(&parse(
            "[kubernetes]\nenabled = true\n[telemetry]\ninternal_names = [\"*.LAN\", \"home.arpa\"]\n",
        ));
        for name in [
            "kubernetes.default.svc.cluster.local",
            "nas.lan",
            "printer.home.arpa",
        ] {
            assert!(on.is_internal(&wire(name)), "{name}");
        }
        assert!(!on.is_internal(&wire("example.com")));
        let bad = parse("[telemetry]\ninternal_names = [\"not a name\"]\n");
        let errs = telltale_config::validate_config(&bad).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("telemetry.internal_names[0]")),
            "{errs:?}"
        );
    }

    // REQ: OBS-903 (T24.35, ADR-1014) — `[exclusions.log]` becomes the aggregator's filter:
    // addresses, networks and device names (the configured client's reference, case-blind);
    // exact and wildcard domains; `own_lookups` adds loopback and the node's addresses; off, or
    // nothing set, is no filter at all; a bad entry is refused by validation.
    #[test]
    fn obs_903_log_exclusions_from_config() {
        use telltale_telemetry::event::{Name, Record};
        let parse = |t: &str| toml::from_str::<Config>(t).unwrap();
        let q = |ip: &str, client_ref: u32, name: &str| {
            let ip: std::net::IpAddr = ip.parse().unwrap();
            let mapped = match ip {
                std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                std::net::IpAddr::V6(v6) => v6.octets(),
            };
            let ev = telltale_telemetry::QueryEvent {
                ts_us: 0,
                client_ip: mapped,
                client_ref,
                group: 0,
                qtype: 1,
                qclass: 1,
                rcode: Some(0),
                status: telltale_telemetry::Status::Forwarded,
                proto: telltale_telemetry::Proto::Udp,
                flags: 0,
                rule: None,
                upstream: 0,
                attempts: 0,
                t_total_us: 0,
                t_upstream_us: 0,
                resp_size: 0,
                answers: 0,
            };
            let wire = NameBuf::from_presentation(name).unwrap();
            Record::Query(ev, Name::from_wire(wire.as_wire()))
        };
        assert!(log_exclusions_with(&Config::default(), &[]).is_none());
        let cfg = parse(
            "[[client]]
name = \"Tablet\"
match = [\"192.168.1.40\"]
             [[client]]
name = \"Phone\"
match = [\"192.168.1.41\"]
             [exclusions.log]
clients = [\"phone\", \"10.9.0.0/16\", \"192.168.1.99\", \"no-such-device\"]
             domains = [\"localhost\", \"*.lan\"]
own_lookups = true
",
        );
        assert!(telltale_config::validate_config(&cfg).is_ok());
        let own: Vec<std::net::IpAddr> = vec!["192.168.1.2".parse().unwrap()];
        let x = log_exclusions_with(&cfg, &own).unwrap();
        assert!(
            x.excludes(&q("192.168.1.41", 2, "shop.example")),
            "device name"
        );
        assert!(
            !x.excludes(&q("192.168.1.40", 1, "shop.example")),
            "another client"
        );
        assert!(x.excludes(&q("10.9.4.4", 0, "shop.example")), "network");
        assert!(x.excludes(&q("192.168.1.99", 0, "shop.example")), "address");
        assert!(
            x.excludes(&q("192.168.1.50", 0, "localhost")),
            "exact domain"
        );
        assert!(!x.excludes(&q("192.168.1.50", 0, "a.localhost")));
        assert!(
            x.excludes(&q("192.168.1.50", 0, "nas.lan")),
            "wildcard domain"
        );
        assert!(!x.excludes(&q("192.168.1.50", 0, "lan")));
        assert!(
            x.excludes(&q("127.0.0.1", 0, "shop.example")),
            "own: loopback"
        );
        assert!(x.excludes(&q("::1", 0, "shop.example")), "own: loopback v6");
        assert!(
            x.excludes(&q("192.168.1.2", 0, "shop.example")),
            "own: node address"
        );
        assert!(!x.excludes(&q("192.168.1.3", 0, "shop.example")));
        // Own lookups off: loopback is logged like anyone else's.
        let no_own = parse(
            "[exclusions.log]
domains = [\"localhost\"]
",
        );
        let x = log_exclusions_with(&no_own, &own).unwrap();
        assert!(!x.excludes(&q("127.0.0.1", 0, "shop.example")));
        // The switch turns the lot off without losing it.
        let off = parse(
            "[exclusions]
enabled = false
[exclusions.log]
own_lookups = true
",
        );
        assert!(log_exclusions_with(&off, &own).is_none());
        for bad in ["domains = [\"not a name\"]", "clients = [\"10.0.0.0/99\"]"] {
            let cfg = parse(&format!(
                "[exclusions.log]
{bad}
"
            ));
            assert!(telltale_config::validate_config(&cfg).is_err(), "{bad}");
        }
    }

    /// The OPT record's UDP payload size in the answer to a `localhost A` query that carries EDNS.
    fn advertised(cfg: &Config) -> u16 {
        let p = build_pipeline(
            cfg,
            Arc::new(Cache::new(telltale_cache::CachePolicy::default())),
            Arc::new(Router::default()),
            Policy::open(),
        );
        let name = NameBuf::from_presentation("localhost").unwrap();
        let mut q = [0u8; 512];
        let len = build_query(
            &mut q,
            7,
            &name,
            rtype::A,
            1,
            true,
            Some(EdnsOut::new(4096)),
        )
        .unwrap();
        let meta = RequestMeta {
            peer: "127.0.0.1:1000".parse().unwrap(),
            local: None,
            transport: Transport::Udp,
            client_id: None,
        };
        let mut out = [0u8; 4096];
        let Response::Ready(n) = Handler(p).handle(&q[..len], &meta, &mut out) else {
            panic!("localhost is answered at once");
        };
        records(&out[..n])
            .unwrap()
            .map(Result::unwrap)
            .find(telltale_proto::Record::is_opt)
            .expect("an OPT record")
            .rclass
    }

    /// REQ: DNS-005 (review 01-12) — `[dns] edns_payload` is the size advertised in answers
    /// (default 1232), and it is bounded to what the UDP workers can send.
    #[test]
    fn dns_005_advertised_payload_size_is_configurable() {
        assert_eq!(advertised(&Config::default()), 1232);
        let mut cfg = Config::default();
        cfg.dns.edns_payload = 2048;
        assert_eq!(advertised(&cfg), 2048);
        for bad in [511, 4097] {
            let errs = telltale_config::Loader::new()
                .toml_str("t.toml", format!("[dns]\nedns_payload = {bad}\n"))
                .env(Vec::<(String, String)>::new())
                .load()
                .unwrap_err();
            assert!(
                errs.iter().any(|e| e.path == "dns.edns_payload"),
                "{bad}: {errs:?}"
            );
        }
    }
}

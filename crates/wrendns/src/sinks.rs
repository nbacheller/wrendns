//! Event sinks (REQ: OBS-010, `spec/06` §5; T7.13): every query event, as the same JSON
//! object the API's query log returns, copied to a JSON-lines file (rotated), syslog
//! (RFC 5424 over UDP, or TCP or (T9.11) TLS with octet counting), or a batched HTTP
//! webhook, which (T9.11) can keep refused batches on disk until the collector is back.
//!
//! The aggregator thread formats each event once and hands it to every sink through a
//! bounded channel (`max_buffer`); a sink that can't keep up drops events (counted, logged
//! once a minute), so neither DNS nor the query log waits for it (OBS-002). Each sink writes
//! from its own thread; the webhook thread retries a failed batch a few times, then drops it.

use std::io::Write;
use std::net::{IpAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{
    Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError, channel, sync_channel,
};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use wrendns_api::model::QueryRow;
use wrendns_config::{Config, SinkConfig, SinkFormat, SinkKind};
use wrendns_telemetry::Status;
use wrendns_telemetry::event::{QueryEvent, Record};
use wrendns_telemetry::ring::Sink;
use tracing::{info, warn};

use crate::pipeline::Pipeline;

/// How long a removed or changed sink gets to send what it holds before it is left to finish
/// on its own (REQ: API-016, T23.11).
const RETIRE_WAIT: Duration = Duration::from_secs(2);

/// One sink as the aggregator sees it.
#[derive(Clone)]
pub(crate) struct Out {
    name: String,
    /// Statuses it wants (empty = all).
    statuses: Vec<Status>,
    syslog: bool,
    tx: SyncSender<String>,
    dropped: Arc<AtomicU64>,
    reported: u64,
}

/// The aggregator-side half: formats events and offers them to each sink.
pub(crate) struct EventSinks {
    outs: Vec<Out>,
    /// REQ: API-016 (T23.11, ADR-984) — the manager's new list of sinks, taken (`try_recv`, no
    /// lock, no wait) once per batch.
    updates: Receiver<Vec<Out>>,
    pipeline: Arc<Pipeline>,
    node: String,
    privacy: u8,
    /// List names by ID, for the snapshot at `snapshot` (compared by pointer).
    lists: Vec<String>,
    snapshot: usize,
    last_report: Instant,
}

/// What a sink's thread is told: stop (after sending what it holds), and whether its kept
/// batches go with it.
#[derive(Debug, Default)]
struct Control {
    stop: AtomicBool,
    /// Set with `stop` when the sink is gone for good (or its destination changed): its
    /// spill files are deleted when the thread ends.
    remove: AtomicBool,
    /// Set by the manager when it stops waiting for a stopped thread: that thread never
    /// touches the kept batches again and never deletes them (a new sink may own them now).
    abandoned: AtomicBool,
    /// When it was told to stop (the deadline to end by counts from here, not from when the
    /// thread notices).
    stopped_at: std::sync::OnceLock<Instant>,
}

impl Control {
    fn stop_now(&self) {
        let _ = self.stopped_at.set(Instant::now());
        self.stop.store(true, Ordering::Release);
    }
    fn is_abandoned(&self) -> bool {
        self.abandoned.load(Ordering::Acquire)
    }
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
    fn removing(&self) -> bool {
        self.remove.load(Ordering::Acquire)
    }
}

/// REQ: API-016 (T23.11) — what the sinks are doing, for the API: one per configured sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SinkState {
    pub(crate) name: String,
    /// Whether its thread runs.
    pub(crate) running: bool,
    /// Why it doesn't, when it doesn't.
    pub(crate) reason: Option<String>,
}

/// A sink that runs: its settings (to tell a change), its thread and its way in.
struct Running {
    cfg: SinkConfig,
    /// The node name and data directory the thread was built with.
    context: (String, String),
    ctl: Arc<Control>,
    out: Out,
    thread: Option<std::thread::JoinHandle<()>>,
    spill_key: Option<String>,
}

#[derive(Default)]
struct Inner {
    running: Vec<Running>,
    /// Each name's dropped-event counter, kept across reloads (and removals) so that the
    /// metric only ever grows (NFR-007).
    counters: std::collections::HashMap<String, Arc<AtomicU64>>,
    /// Threads that were retired but hadn't ended after [`RETIRE_WAIT`].
    stragglers: Vec<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Manager").finish_non_exhaustive()
    }
}

/// REQ: API-016, OBS-010, NFR-007 (T23.11, ADR-984) — the event sinks, started and changed
/// without a restart. The manager lives off the query path (an applier task, a blocking
/// thread): it builds each sink's thread and hands the aggregator the new list through a
/// channel the aggregator reads once per batch. A sink that fails to build is left out alone;
/// one that is gone is told to stop, sends what it holds (one try) and ends (2 s).
pub(crate) struct Manager {
    inner: Mutex<Inner>,
    to_aggregator: Sender<Vec<Out>>,
    drops: ArcSwap<Vec<(String, Arc<AtomicU64>)>>,
    states: ArcSwap<Vec<SinkState>>,
}

/// The manager `/metrics` reads (set once at start; tests make their own).
static CURRENT: std::sync::OnceLock<Arc<Manager>> = std::sync::OnceLock::new();

/// Events each sink dropped since start (buffer full, or a batch the collector refused).
pub(crate) fn drops() -> Vec<(String, u64)> {
    CURRENT.get().map(|m| m.drops()).unwrap_or_default()
}

/// The part of a destination that decides which kept batches belong to a sink: its name and a
/// hash of its URL, so a name re-used for another collector never replays the old one's events.
fn spill_key(c: &SinkConfig) -> Option<String> {
    c.spill_max_bytes?;
    let url = c.url.as_ref().map_or("", |u| u.as_str());
    let hash = blake3::hash(url.as_bytes()).to_hex();
    let safe: String = c
        .name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    Some(format!("{safe}-{}", &hash.as_str()[..12]))
}

/// What a thread needs that can fail to build, made before the thread starts.
enum Ready {
    File,
    Syslog(Option<Arc<rustls::ClientConfig>>),
    Webhook(Box<wrendns_filter::fetch::Client>),
}

fn prepare(c: &SinkConfig) -> Result<Ready, String> {
    match c.kind {
        SinkKind::File => {
            if c.path.as_ref().is_none_or(|p| p.is_empty()) {
                return Err("a file sink needs a path".to_owned());
            }
            Ok(Ready::File)
        }
        SinkKind::Syslog => {
            let addr = c.address.as_ref().map_or("", |a| a.as_str());
            if addr.split_once("://").is_none() {
                return Err("the address is not udp://, tcp:// or tls://host:port".to_owned());
            }
            if addr.starts_with("tls://") {
                Ok(Ready::Syslog(Some(
                    syslog_tls(c).map_err(|e| format!("its TLS settings: {e}"))?,
                )))
            } else {
                Ok(Ready::Syslog(None))
            }
        }
        SinkKind::Webhook => wrendns_filter::fetch::Client::new(
            Arc::new(wrendns_filter::fetch::SystemResolver),
            &[],
        )
        .map(|cl| Ready::Webhook(Box::new(cl))),
    }
}

impl Manager {
    /// A manager and the receiving end the aggregator's [`EventSinks`] reads.
    pub(crate) fn new() -> (Arc<Self>, Receiver<Vec<Out>>) {
        let (tx, rx) = channel();
        (
            Arc::new(Self {
                inner: Mutex::new(Inner::default()),
                to_aggregator: tx,
                drops: ArcSwap::from_pointee(Vec::new()),
                states: ArcSwap::from_pointee(Vec::new()),
            }),
            rx,
        )
    }

    /// Events each running sink dropped, by name.
    pub(crate) fn drops(&self) -> Vec<(String, u64)> {
        self.drops
            .load()
            .iter()
            .map(|(n, d)| (n.clone(), d.load(Ordering::Relaxed)))
            .collect()
    }

    /// What each configured sink is doing.
    pub(crate) fn states(&self) -> Vec<SinkState> {
        self.states.load().as_ref().clone()
    }

    /// Makes the running sinks match `cfg`: starts new ones, restarts the changed ones, stops
    /// the removed ones. Blocks for at most [`RETIRE_WAIT`] (never call it from a worker or the
    /// aggregator). A sink that can't be built is reported and left out; the others carry on.
    pub(crate) fn apply(
        &self,
        cfg: &Config,
        rt: &tokio::runtime::Handle,
        store: Option<&Arc<crate::secrets::SecretStore>>,
    ) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let host = crate::http::node_name(cfg);
        let data_dir = cfg.node.data_dir.to_string();
        let context = (host.clone(), data_dir.clone());
        let mut states: Vec<SinkState> = Vec::new();
        // The sinks wanted here: a resolver pod holds no stored secrets, so one that needs one
        // is skipped (ADR-903 section 7), once with an info line.
        let mut wanted: Vec<&SinkConfig> = Vec::new();
        for s in cfg.telemetry.all_sinks() {
            if wanted.iter().any(|w| w.name == s.name) {
                continue;
            }
            if cfg.cluster.ephemeral && s.token_ref.is_some() {
                states.push(SinkState {
                    name: s.name.to_string(),
                    running: false,
                    reason: Some(
                        "this resolver pod holds no stored secrets: a sink that needs one isn't started here"
                            .to_owned(),
                    ),
                });
                warn_ephemeral_once(s.name.as_str());
                continue;
            }
            wanted.push(s);
        }
        let mut kept = retire_changed(&mut inner, &wanted, &context);
        for w in &wanted {
            if kept.iter().any(|r| r.cfg.name == w.name) {
                states.push(SinkState {
                    name: w.name.to_string(),
                    running: true,
                    reason: None,
                });
                continue;
            }
            let dropped = Arc::clone(
                inner
                    .counters
                    .entry(w.name.to_string())
                    .or_insert_with(|| Arc::new(AtomicU64::new(0))),
            );
            match start_one(w, &host, &data_dir, &dropped, rt, store) {
                Ok(r) => {
                    states.push(SinkState {
                        name: w.name.to_string(),
                        running: true,
                        reason: None,
                    });
                    kept.push(r);
                }
                Err(why) => {
                    warn!(sink = %w.name, error = %why, "event sink not started");
                    states.push(SinkState {
                        name: w.name.to_string(),
                        running: false,
                        reason: Some(why),
                    });
                }
            }
        }
        // The configured order, not the order they were started in.
        kept.sort_by_key(|r| {
            wanted
                .iter()
                .position(|w| w.name == r.cfg.name)
                .unwrap_or(usize::MAX)
        });
        inner.running = kept;
        self.drops.store(Arc::new(
            inner
                .running
                .iter()
                .map(|r| (r.cfg.name.to_string(), Arc::clone(&r.out.dropped)))
                .collect(),
        ));
        self.states.store(Arc::new(states));
        // The aggregator picks this up at its next batch; if it is gone (shutdown) nothing
        // is lost.
        let _ = self
            .to_aggregator
            .send(inner.running.iter().map(|r| r.out.clone()).collect());
    }
}

/// REQ: API-016 (T23.11, ADR-984) — the applier: after every configuration change (a reload, a
/// UI entry, a replicated node-managed entry) it makes the running sinks match, on a blocking
/// thread. Never on a request path, a reload or the DNS path.
pub(crate) async fn run(
    sources: Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            () = sources.telemetry_changed.notified() => {}
        }
        // A burst of changes (a reload, then a secret) is one pass.
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
        let cfg = sources.config.load_full();
        let (manager, store, rt) = (
            Arc::clone(&sources.sinks),
            Arc::clone(&sources.secrets),
            tokio::runtime::Handle::current(),
        );
        if let Err(e) =
            tokio::task::spawn_blocking(move || manager.apply(&cfg, &rt, Some(&store))).await
        {
            warn!("the event sinks could not be updated: {e}");
        }
    }
}

/// Stops the sinks that are gone or changed and waits for them (up to [`RETIRE_WAIT`]) before
/// anything new starts, so that two threads never share one sink's kept batches. Returns the ones
/// that stay.
fn retire_changed(
    inner: &mut Inner,
    wanted: &[&SinkConfig],
    context: &(String, String),
) -> Vec<Running> {
    let mut retiring: Vec<Running> = Vec::new();
    let mut kept: Vec<Running> = Vec::new();
    for r in std::mem::take(&mut inner.running) {
        let next = wanted.iter().find(|w| w.name == r.cfg.name);
        let same = next.is_some_and(|w| **w == r.cfg && r.context == *context);
        if same && r.thread.as_ref().is_some_and(|t| !t.is_finished()) {
            kept.push(r);
        } else {
            let next_key = next.and_then(|w| spill_key(w));
            if r.spill_key.is_some() && r.spill_key != next_key {
                r.ctl.remove.store(true, Ordering::Release);
            }
            r.ctl.stop_now();
            retiring.push(r);
        }
    }
    let deadline = Instant::now() + RETIRE_WAIT;
    for r in &mut retiring {
        if let Some(t) = r.thread.take() {
            while !t.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if t.is_finished() {
                let _ = t.join();
            } else {
                r.ctl.abandoned.store(true, Ordering::Release);
                warn!(sink = %r.cfg.name, "a stopped event sink is still sending; it ends after its attempt");
                inner.stragglers.push(t);
            }
        }
    }
    inner.stragglers.retain(|t| !t.is_finished());
    kept
}

/// A resolver pod says once per sink why it skips it.
fn warn_ephemeral_once(name: &str) {
    static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut seen = SEEN.lock().unwrap_or_else(PoisonError::into_inner);
    if !seen.iter().any(|s| s == name) {
        seen.push(name.to_owned());
        info!(sink = %name, "this resolver pod holds no stored secrets: the event sink that needs one isn't started here");
    }
}

/// Builds one sink and starts its thread.
fn start_one(
    s: &SinkConfig,
    host: &str,
    data_dir: &str,
    dropped: &Arc<AtomicU64>,
    rt: &tokio::runtime::Handle,
    store: Option<&Arc<crate::secrets::SecretStore>>,
) -> Result<Running, String> {
    let ready = prepare(s)?;
    let (tx, rx) = sync_channel::<String>(usize::try_from(s.max_buffer).unwrap_or(10_000));
    let ctl = Arc::new(Control::default());
    let name = s.name.to_string();
    let c = s.clone();
    let (d, rt, store, host_t, ctl_t) = (
        Arc::clone(dropped),
        rt.clone(),
        store.cloned(),
        host.to_owned(),
        Arc::clone(&ctl),
    );
    let spill = Spill::new(s, data_dir);
    let thread = std::thread::Builder::new()
        .name(format!("sink-{name}"))
        .spawn(move || match ready {
            Ready::File => file_writer(&c, &rx, &ctl_t),
            Ready::Syslog(tls) => syslog_writer(&c, &rx, &host_t, tls.as_ref(), &ctl_t),
            Ready::Webhook(client) => {
                webhook_writer(
                    &c,
                    &rx,
                    &ctl_t,
                    &d,
                    &client,
                    &rt,
                    &host_t,
                    spill.as_ref(),
                    store.as_deref(),
                );
            }
        })
        .map_err(|e| format!("cannot start its thread: {e}"))?;
    info!(sink = %name, kind = ?s.kind, "event sink started");
    Ok(Running {
        cfg: s.clone(),
        context: (host.to_owned(), data_dir.to_owned()),
        ctl,
        out: Out {
            name,
            statuses: s
                .statuses
                .iter()
                .filter_map(|x| {
                    Status::ALL
                        .iter()
                        .copied()
                        .find(|st| st.label() == x.as_str())
                })
                .collect(),
            syslog: s.kind == SinkKind::Syslog,
            tx,
            dropped: Arc::clone(dropped),
            reported: 0,
        },
        thread: Some(thread),
        spill_key: spill_key(s),
    })
}

/// Starts the configured sinks (at start; the manager changes them later, without a restart).
/// The returned sink always exists, even with no sink configured, so that one added later has
/// somewhere to go. `rt` runs the webhook requests.
pub(crate) fn start(
    cfg: &Config,
    pipeline: &Arc<Pipeline>,
    rt: &tokio::runtime::Handle,
    store: Option<&Arc<crate::secrets::SecretStore>>,
) -> (Box<dyn Sink>, Arc<Manager>) {
    let (manager, updates) = Manager::new();
    manager.apply(cfg, rt, store);
    let _ = CURRENT.set(Arc::clone(&manager));
    let mut sinks = EventSinks {
        outs: Vec::new(),
        updates,
        pipeline: Arc::clone(pipeline),
        node: crate::http::node_name(cfg),
        privacy: cfg.telemetry.qlog.privacy_level,
        lists: Vec::new(),
        snapshot: 0,
        last_report: Instant::now(),
    };
    sinks.take_update();
    (Box::new(sinks), manager)
}

impl EventSinks {
    /// REQ: API-016 (T23.11) — takes the manager's newest list of sinks, if it sent one: a
    /// `try_recv` (no lock, no wait) once per batch. A sink that stays keeps what has been
    /// reported of its drops.
    fn take_update(&mut self) {
        let mut latest = None;
        while let Ok(v) = self.updates.try_recv() {
            latest = Some(v);
        }
        if let Some(mut new) = latest {
            for o in &mut new {
                if let Some(old) = self.outs.iter().find(|x| x.name == o.name) {
                    o.reported = old.reported;
                } else {
                    o.reported = o.dropped.load(Ordering::Relaxed);
                }
            }
            self.outs = new;
        }
    }

    /// List names change with snapshots: re-read them only when the snapshot changed.
    fn refresh_lists(&mut self) {
        let f = self.pipeline.filter.load();
        let snap = f.as_ref().and_then(|f| f.matcher.snapshot());
        let ptr = snap.map_or(0, |s| Arc::as_ptr(s) as usize);
        if ptr != self.snapshot {
            self.lists = snap
                .map(|s| s.manifest.lists.iter().map(|l| l.name.clone()).collect())
                .unwrap_or_default();
            self.snapshot = ptr;
        }
    }

    /// The event as the API's query row (names resolved now, after the privacy level).
    fn row(&self, e: &QueryEvent, wire: &[u8]) -> QueryRow {
        let mut ev = *e;
        if self.privacy >= 2 {
            ev.client_ip = [0; 16];
        }
        let name = if self.privacy >= 1 {
            wrendns_telemetry::event::dotted(&wrendns_store::qlog::hidden_name(wire))
        } else {
            wrendns_telemetry::event::dotted(wire)
        };
        let state = self.pipeline.current();
        let policy = &state.policy;
        let client_name = (self.privacy < 2)
            .then(|| {
                let v6 = std::net::Ipv6Addr::from(ev.client_ip);
                let ip = v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4);
                let id = policy.clients.identify(
                    ip,
                    None,
                    None,
                    &self.pipeline.neighbors,
                    &self.pipeline.workloads,
                );
                policy.clients.client(id).map(|c| c.name.to_string())
            })
            .flatten();
        // REQ: OBS-010 (review 04-09) — borrowed, not cloned per event: this runs on the
        // aggregator thread for every event while a sink is configured.
        let schedules = self.pipeline.schedules.load();
        let (list, rule) =
            crate::api_backend::rule_labels(ev.rule, &self.lists, &policy.quick, &schedules.names);
        QueryRow {
            time: wrendns_api::time::format_us(ev.ts_us),
            ts_unix_micros: ev.ts_us,
            client: wrendns_telemetry::agg::client_text(ev.client_ip),
            client_name,
            group: policy
                .clients
                .groups()
                .get(usize::from(ev.group))
                .map(|g| g.name.to_string()),
            name,
            qtype: crate::api_backend::qtype_name(ev.qtype),
            status: ev.status.label().to_owned(),
            rcode: ev.rcode.map(crate::api_backend::rcode_name),
            proto: ev.proto.label().to_owned(),
            list,
            rule,
            total_ms: crate::api_backend::ms(u64::from(ev.t_total_us)),
            upstream_ms: crate::api_backend::ms(u64::from(ev.t_upstream_us)),
            response_bytes: ev.resp_size,
            answers: ev.answers,
            node: Some(self.node.clone()),
        }
    }
}

impl Sink for EventSinks {
    fn record(&mut self, r: &Record) {
        let Record::Query(e, name) = r else { return };
        let wanted = |o: &Out| o.statuses.is_empty() || o.statuses.contains(&e.status);
        if !self.outs.iter().any(wanted) {
            return;
        }
        if e.rule.is_some() {
            self.refresh_lists();
        }
        let row = self.row(e, name.as_wire());
        let Ok(json) = serde_json::to_string(&row) else {
            return;
        };
        for o in &self.outs {
            if !wanted(o) {
                continue;
            }
            let line = if o.syslog {
                // The syslog writer needs the time and severity; it gets them in front.
                format!(
                    "{}\t{}\t{json}",
                    row.time,
                    u8::from(e.status == Status::Blocked)
                )
            } else {
                json.clone()
            };
            match o.tx.try_send(line) {
                Ok(()) => {}
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                    o.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    fn tick(&mut self, now: Instant) {
        self.take_update();
        if now.duration_since(self.last_report) >= Duration::from_secs(60) {
            self.last_report = now;
            for o in &mut self.outs {
                let d = o.dropped.load(Ordering::Relaxed);
                if d > o.reported {
                    warn!(sink = %o.name, dropped = d - o.reported, "event sink fell behind; events dropped");
                    o.reported = d;
                }
            }
        }
    }
}

/// JSON lines appended to `path`, rotated at `max_bytes` to `<path>.1` .. `<path>.<keep>`.
fn file_writer(c: &SinkConfig, rx: &Receiver<String>, ctl: &Control) {
    let Some(path) = c
        .path
        .as_ref()
        .map(|p| std::path::PathBuf::from(p.as_str()))
    else {
        return;
    };
    let open = |p: &std::path::Path| {
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .map(|f| {
                let len = f.metadata().map_or(0, |m| m.len());
                (std::io::BufWriter::new(f), len)
            })
    };
    let mut file = match open(&path) {
        Ok(f) => Some(f),
        Err(e) => {
            warn!(sink = %c.name, path = %path.display(), error = %e, "event sink can't open its file");
            None
        }
    };
    loop {
        // REQ: API-016 (T23.11) — once told to stop, it writes what is queued and ends.
        let line = match next_line(rx, ctl) {
            Next::Line(l) => Some(l),
            Next::Idle => None,
            Next::End => break,
        };
        if file.is_none() {
            file = open(&path).ok();
        }
        let Some((w, len)) = file.as_mut() else {
            continue;
        };
        let Some(line) = line else {
            let _ = w.flush();
            continue;
        };
        if writeln!(w, "{line}").is_err() {
            file = None;
            continue;
        }
        *len += line.len() as u64 + 1;
        if *len >= c.max_bytes.bytes() {
            let _ = w.flush();
            drop(file.take()); // closed before it moves
            rotate(&path, c.keep);
            file = open(&path).ok();
        }
    }
    if let Some((mut w, _)) = file {
        let _ = w.flush();
    }
}

/// What a sink thread's queue says.
enum Next {
    Line(String),
    /// Nothing for a second.
    Idle,
    /// Stopped (everything queued has been taken) or the sender is gone.
    End,
}

/// The next queued line: waits up to a second, so a stop is noticed within one; after a stop
/// it hands out what is still queued and then ends.
fn next_line(rx: &Receiver<String>, ctl: &Control) -> Next {
    if ctl.stopping() {
        return rx.try_recv().map_or(Next::End, Next::Line);
    }
    match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(l) => Next::Line(l),
        Err(RecvTimeoutError::Timeout) => Next::Idle,
        Err(RecvTimeoutError::Disconnected) => Next::End,
    }
}

/// `path` → `path.1` → ... → `path.<keep>` (the oldest is removed).
fn rotate(path: &std::path::Path, keep: u32) {
    let numbered = |n: u32| {
        let mut s = path.as_os_str().to_owned();
        s.push(format!(".{n}"));
        std::path::PathBuf::from(s)
    };
    if keep == 0 {
        let _ = std::fs::remove_file(path);
        return;
    }
    let _ = std::fs::remove_file(numbered(keep));
    for n in (1..keep).rev() {
        let _ = std::fs::rename(numbered(n), numbered(n + 1));
    }
    let _ = std::fs::rename(path, numbered(1));
}

/// One RFC 5424 message: `<PRI>1 TIME HOST wrendns - query - JSON`.
pub(crate) fn syslog_message(
    facility: u8,
    blocked: bool,
    time: &str,
    host: &str,
    json: &str,
) -> String {
    // Severity: notice (5) for blocks, informational (6) for the rest.
    let pri = u16::from(facility) * 8 + if blocked { 5 } else { 6 };
    let host: String = host
        .chars()
        .filter(char::is_ascii_graphic)
        .take(255)
        .collect();
    let host = if host.is_empty() {
        "-".to_owned()
    } else {
        host
    };
    format!("<{pri}>1 {time} {host} wrendns - query - {json}")
}

/// REQ: OBS-010 (T9.11) — the TLS client for a `tls://` syslog collector: the public roots
/// plus `tls_ca`.
fn syslog_tls(c: &SinkConfig) -> Result<Arc<rustls::ClientConfig>, String> {
    use rustls::pki_types::pem::PemObject as _;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(f) = &c.tls_ca {
        for cert in rustls::pki_types::CertificateDer::pem_file_iter(f.as_str())
            .map_err(|e| format!("{}: {e}", f.as_str()))?
        {
            roots
                .add(cert.map_err(|e| format!("{}: {e}", f.as_str()))?)
                .map_err(|e| format!("{}: {e}", f.as_str()))?;
        }
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// A stream to a TCP or TLS syslog collector.
fn syslog_connect(
    target: &str,
    tls: Option<&Arc<rustls::ClientConfig>>,
) -> Option<Box<dyn Write + Send>> {
    let t = TcpStream::connect(target).ok()?;
    let _ = t.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = t.set_read_timeout(Some(Duration::from_secs(5)));
    let Some(cfg) = tls else {
        return Some(Box::new(t));
    };
    // REQ: OBS-010 (T9.11) — RFC 5425: the certificate must name the host in the address.
    let host = target
        .rsplit_once(':')
        .map_or(target, |(h, _)| h)
        .trim_matches(|ch| ch == '[' || ch == ']');
    let name = rustls::pki_types::ServerName::try_from(host.to_owned()).ok()?;
    let conn = rustls::ClientConnection::new(Arc::clone(cfg), name).ok()?;
    Some(Box::new(rustls::StreamOwned::new(conn, t)))
}

/// Syslog over UDP (one datagram per event) or TCP or TLS (octet-counted frames, RFC 6587
/// and RFC 5425), reconnecting when the collector goes away.
fn syslog_writer(
    c: &SinkConfig,
    rx: &Receiver<String>,
    host: &str,
    tls: Option<&Arc<rustls::ClientConfig>>,
    ctl: &Control,
) {
    let addr = c.address.as_ref().map_or("", |a| a.as_str()).to_owned();
    let (udp, target) = match addr.split_once("://") {
        Some(("udp", t)) => (true, t.to_owned()),
        Some((_, t)) => (false, t.to_owned()),
        None => return,
    };
    let mut sock: Option<UdpSocket> = None;
    let mut tcp: Option<Box<dyn Write + Send>> = None;
    let mut warned = false;
    loop {
        let line = match next_line(rx, ctl) {
            Next::Line(l) => l,
            Next::Idle => continue,
            Next::End => break,
        };
        let mut parts = line.splitn(3, '\t');
        let (Some(time), Some(blocked), Some(json)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let msg = syslog_message(c.facility, blocked == "1", time, host, json);
        let sent = if udp {
            if sock.is_none() {
                sock = UdpSocket::bind(if target.starts_with('[') {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                })
                .ok();
            }
            sock.as_ref()
                .is_some_and(|s| s.send_to(msg.as_bytes(), target.as_str()).is_ok())
        } else {
            if tcp.is_none() {
                tcp = syslog_connect(&target, tls);
            }
            let ok = tcp
                .as_mut()
                .is_some_and(|t| write!(t, "{} {msg}", msg.len()).is_ok() && t.flush().is_ok());
            if !ok {
                tcp = None;
            }
            ok
        };
        if !sent && !warned {
            warn!(sink = %c.name, address = %addr, "event sink can't reach its syslog collector");
        }
        warned = !sent;
    }
}

/// Waits `d`, or until the sink is told to stop.
fn nap(d: Duration, ctl: &Control) {
    let end = Instant::now() + d;
    while !ctl.stopping() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50).min(d));
    }
}

/// Batches of `batch` events (or whatever arrived in `flush_secs`) posted to `url`.
///
/// REQ: API-016 (T23.11) — told to stop, it sends what is queued (one try per batch, no waiting
/// between tries) and ends; what it can't send goes to its kept batches if it has them and
/// isn't being removed, and counts as dropped otherwise. A removed sink's kept batches are
/// deleted when it ends.
#[allow(clippy::too_many_arguments)]
fn webhook_writer(
    c: &SinkConfig,
    rx: &Receiver<String>,
    ctl: &Control,
    dropped: &AtomicU64,
    client: &wrendns_filter::fetch::Client,
    rt: &tokio::runtime::Handle,
    host: &str,
    spill: Option<&Spill>,
    store: Option<&crate::secrets::SecretStore>,
) {
    let batch = usize::try_from(c.batch.max(1)).unwrap_or(500);
    let wait = Duration::from_secs(u64::from(c.flush_secs.max(1)));
    let mut buf: Vec<String> = Vec::with_capacity(batch);
    let mut first: Option<Instant> = None;
    let mut open = true;
    let mut last_idle = Instant::now();
    // REQ: API-016 — a stopping writer has one overall deadline; past it nothing more goes to
    // the network (the rest is kept or counted dropped), so it can't outlive its replacement.
    let mut stop_deadline: Option<Instant> = None;
    while open || !buf.is_empty() {
        let stopping = ctl.stopping();
        if stopping {
            stop_deadline.get_or_insert_with(|| {
                ctl.stopped_at.get().copied().unwrap_or_else(Instant::now) + RETIRE_WAIT
            });
            // Everything still queued goes out in this last round.
            while let Ok(l) = rx.try_recv() {
                buf.push(l);
            }
            open = false;
        } else if open {
            let left = first
                .map_or(wait, |f| wait.saturating_sub(f.elapsed()))
                .min(Duration::from_secs(1));
            match rx.recv_timeout(left) {
                Ok(l) => {
                    first.get_or_insert_with(Instant::now);
                    buf.push(l);
                    if buf.len() < batch {
                        continue;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if first.is_some_and(|f| f.elapsed() < wait) {
                        continue;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => open = false,
            }
        }
        if buf.is_empty() {
            first = None;
            // REQ: OBS-010 (T9.11) — quiet: a chance to send what was kept.
            if open
                && last_idle.elapsed() >= wait
                && let Some(s) = spill
            {
                last_idle = Instant::now();
                replay(s, c, client, rt, host, batch, store);
            }
            continue;
        }
        for chunk in std::mem::take(&mut buf).chunks(batch) {
            if stop_deadline.is_some_and(|d| Instant::now() >= d) {
                keep_or_drop(c, chunk, ctl, dropped, spill);
            } else {
                deliver(
                    c, chunk, ctl, dropped, client, rt, host, spill, store, batch,
                );
            }
        }
        first = None;
    }
    if ctl.removing()
        && !ctl.is_abandoned()
        && let Some(s) = spill
    {
        s.delete();
    }
}

/// Not sent (no network): kept on disk when the sink has kept batches, isn't being removed and
/// hasn't been abandoned by the manager; counted as dropped otherwise.
fn keep_or_drop(
    c: &SinkConfig,
    events: &[String],
    ctl: &Control,
    dropped: &AtomicU64,
    spill: Option<&Spill>,
) {
    match spill {
        Some(s) if !ctl.removing() && !ctl.is_abandoned() && s.push(events) => {
            info!(sink = %c.name, events = events.len(), "event sink batch kept on disk until the collector is back");
        }
        _ => {
            dropped.fetch_add(events.len() as u64, Ordering::Relaxed);
        }
    }
}

/// One batch: up to three tries (one when the sink is stopping), then the kept batches if the
/// collector took it, or the batch goes to them (or is dropped, counted).
#[allow(clippy::too_many_arguments)]
fn deliver(
    c: &SinkConfig,
    events: &[String],
    ctl: &Control,
    dropped: &AtomicU64,
    client: &wrendns_filter::fetch::Client,
    rt: &tokio::runtime::Handle,
    host: &str,
    spill: Option<&Spill>,
    store: Option<&crate::secrets::SecretStore>,
    batch: usize,
) {
    let body = webhook_body(c, events, host);
    let mut delivered = false;
    for attempt in 0..3u32 {
        match rt.block_on(post(client, c, body.clone(), store)) {
            Ok(()) => {
                delivered = true;
                break;
            }
            Err(e) => {
                if attempt == 2 || ctl.stopping() {
                    warn!(sink = %c.name, error = %e, events = events.len(), "event sink batch not delivered");
                }
                if ctl.stopping() || attempt == 2 {
                    break;
                }
                nap(Duration::from_secs(1 << attempt), ctl);
            }
        }
    }
    match (delivered, spill) {
        // REQ: OBS-010 (T9.11) — the collector is back: send what was kept, oldest first (not
        // while stopping: the sink is on its way out).
        (true, Some(s)) if !ctl.stopping() => replay(s, c, client, rt, host, batch, store),
        (true, _) => {}
        (false, _) => keep_or_drop(c, events, ctl, dropped, spill),
    }
}

/// A webhook request body for `events`.
fn webhook_body(c: &SinkConfig, events: &[String], host: &str) -> String {
    match c.format {
        SinkFormat::JsonLines => {
            let mut s = events.join("\n");
            s.push('\n');
            s
        }
        SinkFormat::JsonArray => format!("[{}]", events.join(",")),
        // REQ: OBS-006 (T7.17)
        SinkFormat::OtlpLogs => crate::otlp::logs_body(events, &crate::otlp::resource(host)),
    }
}

/// REQ: OBS-010 (T9.11) — sends up to 20 kept batches, stopping at the first failure (the
/// rest wait for the next chance).
fn replay(
    s: &Spill,
    c: &SinkConfig,
    client: &wrendns_filter::fetch::Client,
    rt: &tokio::runtime::Handle,
    host: &str,
    batch: usize,
    store: Option<&crate::secrets::SecretStore>,
) {
    for _ in 0..20 {
        let (events, next) = s.take(batch);
        if events.is_empty() {
            return;
        }
        if rt
            .block_on(post(client, c, webhook_body(c, &events, host), store))
            .is_err()
        {
            return;
        }
        s.commit(next);
    }
}

/// REQ: OBS-010 (T9.11) — a webhook sink's refused batches on disk: events appended as
/// JSON lines to `<data_dir>/sinks/<name>.spill`, read from the offset in `.pos`; the files
/// go once everything is sent. The file never grows past `spill_max_bytes` (sent events
/// included until it's compacted); events that don't fit are dropped (counted).
pub(crate) struct Spill {
    path: std::path::PathBuf,
    pos: std::path::PathBuf,
    max: u64,
}

impl Spill {
    fn new(c: &SinkConfig, data_dir: &str) -> Option<Self> {
        let max = c.spill_max_bytes?.bytes();
        let key = spill_key(c)?;
        let dir = std::path::Path::new(data_dir).join("sinks");
        let me = Self {
            path: dir.join(format!("{key}.spill")),
            pos: dir.join(format!("{key}.spill.pos")),
            max,
        };
        // Kept batches from before the name carried a URL hash belong to this sink, as the
        // sink is (it is the one that wrote them).
        let legacy = key.rsplit_once('-').map_or(key.as_str(), |(n, _)| n);
        let old = dir.join(format!("{legacy}.spill"));
        if old.exists() && !me.path.exists() {
            let _ = std::fs::rename(&old, &me.path);
            let _ = std::fs::rename(dir.join(format!("{legacy}.spill.pos")), &me.pos);
        }
        Some(me)
    }

    /// Removes the kept batches (the sink is gone, or its destination changed).
    fn delete(&self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(&self.pos);
    }

    fn offset(&self) -> u64 {
        std::fs::read_to_string(&self.pos)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Appends `events`; false (nothing written) when they don't fit.
    fn push(&self, events: &[String]) -> bool {
        let mut size = std::fs::metadata(&self.path).map_or(0, |m| m.len());
        let add: u64 = events.iter().map(|e| e.len() as u64 + 1).sum();
        if size + add > self.max {
            // Sent events still at the front: drop them to make room.
            self.compact();
            size = std::fs::metadata(&self.path).map_or(0, |m| m.len());
            if size + add > self.max {
                return false;
            }
        }
        if let Some(d) = self.path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        else {
            return false;
        };
        let mut out = String::with_capacity(usize::try_from(add).unwrap_or(0));
        for e in events {
            out.push_str(e);
            out.push('\n');
        }
        f.write_all(out.as_bytes()).is_ok()
    }

    /// Up to `limit` events from the front, and the offset after them.
    fn take(&self, limit: usize) -> (Vec<String>, u64) {
        use std::io::{BufRead as _, Seek as _};
        let start = self.offset();
        let Ok(mut file) = std::fs::File::open(&self.path) else {
            return (Vec::new(), start);
        };
        if file.seek(std::io::SeekFrom::Start(start)).is_err() {
            return (Vec::new(), start);
        }
        let mut reader = std::io::BufReader::new(file);
        let (mut events, mut at) = (Vec::new(), start);
        let mut line = String::new();
        while events.len() < limit {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    at += read as u64;
                    let event = line.trim_end_matches('\n');
                    if !event.is_empty() {
                        events.push(event.to_owned());
                    }
                }
            }
        }
        (events, at)
    }

    /// Marks everything before `next` as sent; removes the files when that's all of it.
    fn commit(&self, next: u64) {
        let size = std::fs::metadata(&self.path).map_or(0, |m| m.len());
        if next >= size {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(&self.pos);
        } else {
            let _ = std::fs::write(&self.pos, next.to_string());
        }
    }

    /// Rewrites the file without its sent events.
    fn compact(&self) {
        let start = self.offset();
        if start == 0 {
            return;
        }
        let Ok(data) = std::fs::read(&self.path) else {
            return;
        };
        let rest = data
            .get(usize::try_from(start).unwrap_or(usize::MAX)..)
            .unwrap_or_default();
        let tmp = self.path.with_extension("spill.tmp");
        if std::fs::write(&tmp, rest).is_ok() && std::fs::rename(&tmp, &self.path).is_ok() {
            let _ = std::fs::remove_file(&self.pos);
        }
    }
}

async fn post(
    client: &wrendns_filter::fetch::Client,
    c: &SinkConfig,
    body: String,
    store: Option<&crate::secrets::SecretStore>,
) -> Result<(), String> {
    let url = c.url.as_ref().map_or("", |u| u.as_str());
    let ct = match c.format {
        SinkFormat::JsonLines => "application/x-ndjson",
        SinkFormat::JsonArray | SinkFormat::OtlpLogs => "application/json",
    };
    let mut req = http::Request::post(url)
        .header("content-type", ct)
        .header("user-agent", "WrenDNS");
    // REQ: OPS-014 (ADR-903 §2) — the token from its file or the store, read per batch.
    if let Some(t) = crate::secrets::Credential::of(c.token_file.as_ref(), c.token_ref.as_ref())
        .resolve(store)?
    {
        req = req.header(
            "authorization",
            format!("{} {}", c.token_scheme.as_str(), t.value.expose()),
        );
    }
    let req = req.body(body.into_bytes()).map_err(|e| e.to_string())?;
    let resp = tokio::time::timeout(Duration::from_secs(15), client.request(req, 64 * 1024))
        .await
        .map_err(|_| "timed out".to_owned())?
        .map_err(|e| e.message)?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

#[cfg(test)]
#[path = "sinks_tests.rs"]
mod live_tests;
#[cfg(test)]
pub(crate) use live_tests::Collector;

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: OBS-010 — RFC 5424 framing: PRI from facility and severity, version 1, host,
    /// app name, the event as the message.
    #[test]
    fn obs_010_syslog_message() {
        let m = syslog_message(16, true, "2026-10-06T10:00:00.000Z", "pi dns", "{\"a\":1}");
        assert_eq!(
            m,
            "<133>1 2026-10-06T10:00:00.000Z pidns wrendns - query - {\"a\":1}"
        );
        let m = syslog_message(1, false, "t", "", "{}");
        assert!(m.starts_with("<14>1 t - wrendns"), "{m}");
    }

    /// REQ: OBS-010 — file rotation keeps `keep` files and drops the oldest.
    #[test]
    #[allow(clippy::many_single_char_names)]
    fn obs_010_spill_keeps_order_and_cap() {
        let d = tempfile::tempdir().unwrap();
        let c: SinkConfig = toml::from_str(
            "name = \"hook/1\"\ntype = \"webhook\"\nurl = \"http://x\"\nspill_max_bytes = \"1MiB\"\n",
        )
        .unwrap();
        let s = Spill::new(&c, d.path().to_str().unwrap()).unwrap();
        assert!(
            s.path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("hook_1-") && n.rsplit('.').next() == Some("spill"))
        );
        let ev = |i: usize| format!("{{\"n\":{i}}}");
        assert!(s.push(&(0..3).map(ev).collect::<Vec<_>>()));
        assert!(s.push(&(3..5).map(ev).collect::<Vec<_>>()));
        let (a, next) = s.take(2);
        assert_eq!(a, vec![ev(0), ev(1)]);
        // Not committed (the post failed): the same events again.
        assert_eq!(s.take(2).0, a);
        s.commit(next);
        let (b, next) = s.take(10);
        assert_eq!(b, (2..5).map(ev).collect::<Vec<_>>());
        s.commit(next);
        assert!(
            !s.path.exists() && !s.pos.exists(),
            "all sent: files removed"
        );
        // The cap: what doesn't fit is refused, and sent events make room.
        let big = "x".repeat(300 * 1024);
        assert!(s.push(&[big.clone(), big.clone(), big.clone()]));
        assert!(!s.push(std::slice::from_ref(&big)), "over 1 MiB");
        let (_, next) = s.take(2);
        s.commit(next);
        assert!(s.push(std::slice::from_ref(&big)), "room after compaction");
        assert_eq!(s.take(10).0.len(), 2);
    }

    #[test]
    fn obs_010_file_rotation() {
        let dir = std::env::temp_dir().join(format!("tt-sink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("events.jsonl");
        for i in 0..4 {
            std::fs::write(&p, format!("{i}")).unwrap();
            rotate(&p, 2);
        }
        assert!(!p.exists());
        assert_eq!(
            std::fs::read_to_string(dir.join("events.jsonl.1")).unwrap(),
            "3"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("events.jsonl.2")).unwrap(),
            "2"
        );
        assert!(!dir.join("events.jsonl.3").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

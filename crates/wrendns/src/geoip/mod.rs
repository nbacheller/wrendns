//! REQ: OBS-902, NFR-001 (T26.4, ADR-959, ADR-1008) - the GeoIP database for the world view: an
//! opt-in download at runtime, verified, kept in the data directory, refreshed in the
//! background and never on the query path.
//!
//! Nothing here runs unless an admin turned `[map.geoip] enabled` on, and a failure only changes
//! the status shown: DNS never depends on it (AGENTS rule 5). The database is never bundled.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use tracing::{info, warn};
use wrendns_config::{Config, MapGeoipConfig};
use wrendns_filter::fetch::{Client, Conditional, Response, SystemResolver};

pub(crate) mod ttgeo;

use ttgeo::{Collector, Db, Limits, OpenError, Reject};

/// The publisher's monthly file (ADR-959 section 1).
const DEFAULT_URL: &str = "https://download.db-ip.com/free/dbip-country-lite-";
/// The longest one attempt may take, connect to last byte.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(120);
/// How often the task looks at the settings.
const TICK: Duration = Duration::from_secs(5);
/// A check runs at most once a day, after a success.
const CHECK_EVERY: u64 = 86_400;
/// A failure backs off from an hour, doubling, up to a day.
const BACKOFF_FIRST: u64 = 3_600;
/// A node starts its scheduled checks up to this much late, so a cluster does not hit the
/// publisher at once.
const JITTER_MAX: u64 = 6 * 3_600;
/// A database this old is flagged "old" (it still works).
const OLD_AFTER: u64 = 90 * 86_400;

/// What the status says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Off,
    /// On, and no database on this node yet (not fetched, deleted, or the first attempt failed
    /// before it started).
    Missing,
    Downloading,
    Ready,
    Failed,
}

impl State {
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Missing => "missing",
            Self::Downloading => "downloading",
            Self::Ready => "ready",
            Self::Failed => "failed",
        }
    }
}

/// A snapshot of the service for the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Status {
    pub(crate) enabled: bool,
    pub(crate) state: State,
    /// `YYYYMM` of the source.
    pub(crate) source_month: Option<u32>,
    pub(crate) updated_at: Option<u64>,
    pub(crate) rows: u64,
    pub(crate) size_bytes: u64,
    pub(crate) next_check_at: Option<u64>,
    pub(crate) last_error: Option<String>,
    pub(crate) old: bool,
}

/// Why a lookup was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unavailable {
    /// `[map.geoip] enabled` is off.
    Off,
    /// On, and there is no usable database on this node.
    Missing,
}

/// What the node is told in tests and, in a debug build, by the harness. A release build never
/// reads the environment for this (ADR-959 section 8).
#[derive(Debug, Clone)]
pub(crate) struct Options {
    pub(crate) limits: Limits,
    /// Certificates trusted besides the built-in roots (a fake HTTPS source).
    pub(crate) extra_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            limits: Limits::PRODUCTION,
            extra_roots: Vec::new(),
        }
    }
}

impl Options {
    /// The harness's allowance: `WRENDNS_GEOIP_TEST=1` accepts a small fake database and
    /// `WRENDNS_GEOIP_TEST_CA=<pem file>` trusts the fake source's certificate. Debug builds
    /// only.
    pub(crate) fn from_env() -> Self {
        let mut o = Self::default();
        if cfg!(debug_assertions) && std::env::var_os("WRENDNS_GEOIP_TEST").is_some() {
            o.limits = Limits::TEST;
        }
        // REQ: OBS-902 (ADR-1008 (h)) - the bench build (`--features geoip-probe`) trusts the
        // fake source too, with the production limits, so the build is measured as shipped.
        if (cfg!(debug_assertions) || cfg!(feature = "geoip-probe"))
            && let Some(p) = std::env::var_os("WRENDNS_GEOIP_TEST_CA")
        {
            use rustls::pki_types::CertificateDer;
            use rustls::pki_types::pem::PemObject;
            match CertificateDer::pem_file_iter(&p) {
                Ok(it) => o.extra_roots = it.filter_map(Result::ok).collect(),
                Err(e) => warn!("geoip: the test CA file can't be read: {e}"),
            }
        }
        o
    }
}

/// Where the database in use came from, so a changed source is noticed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// The publisher's monthly file.
    Publisher,
    /// The admin's `source_url`.
    Custom(String),
}

impl Source {
    fn of(g: &MapGeoipConfig) -> Self {
        g.source_url
            .as_ref()
            .map_or(Self::Publisher, |u| Self::Custom(u.as_str().to_owned()))
    }
}

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // independent flags of one small state machine
struct Inner {
    downloading: bool,
    last_error: Option<String>,
    next_check: Option<u64>,
    failures: u32,
    /// "Update now" was pressed.
    manual: bool,
    /// The database was deleted: nothing is fetched until an admin asks or turns it off and on.
    suppressed: bool,
    /// Bumped by `delete()`: an attempt that started before it throws its result away.
    generation: u64,
    /// Whether the toggle was on at the last tick (so an off-to-on change is noticed).
    was_enabled: bool,
    /// The configured `source_url` the database in use came from (`None`: the publisher's).
    fetched_from: Option<Source>,
    /// The disk was looked at since the toggle went on.
    probed: bool,
}

/// The GeoIP service of one node.
#[derive(Debug)]
pub(crate) struct GeoIp {
    inner: Mutex<Inner>,
    db: RwLock<Option<Arc<Db>>>,
    wake: tokio::sync::Notify,
    opts: Options,
    dir: Mutex<Option<PathBuf>>,
    /// Set while the database is on disk but the toggle is off, so the status can still show it.
    jitter: u64,
    /// A test hook: the write stops after this many bytes (a crash).
    crash_after: Mutex<Option<u64>>,
    busy: AtomicBool,
}

impl Default for GeoIp {
    fn default() -> Self {
        Self::new(Options::default(), 0)
    }
}

impl GeoIp {
    pub(crate) fn new(opts: Options, jitter: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                downloading: false,
                last_error: None,
                next_check: None,
                failures: 0,
                manual: false,
                suppressed: false,
                generation: 0,
                was_enabled: false,
                fetched_from: None,
                probed: false,
            }),
            db: RwLock::new(None),
            wake: tokio::sync::Notify::new(),
            opts,
            dir: Mutex::new(None),
            jitter: jitter % JITTER_MAX,
            crash_after: Mutex::new(None),
            busy: AtomicBool::new(false),
        }
    }

    /// The node-specific start delay of scheduled checks, from its name.
    pub(crate) fn jitter_of(node: &str) -> u64 {
        node.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
        }) % JITTER_MAX
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set_dir(&self, data_dir: &Path) -> PathBuf {
        let d = data_dir.join("geoip");
        *self.dir.lock().unwrap_or_else(PoisonError::into_inner) = Some(d.clone());
        d
    }

    fn dir(&self) -> Option<PathBuf> {
        self.dir
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn current(&self) -> Option<Arc<Db>> {
        self.db
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn store(&self, db: Option<Arc<Db>>) {
        *self.db.write().unwrap_or_else(PoisonError::into_inner) = db;
    }

    /// The status as the API shows it.
    pub(crate) fn status(&self, g: &MapGeoipConfig, now: u64) -> Status {
        let inner = self.inner();
        let db = self.current();
        let state = if !g.enabled {
            State::Off
        } else if inner.downloading || inner.manual {
            State::Downloading
        } else if db.is_some() {
            // A working database stays ready when only a later refresh failed: `last_error` says so.
            State::Ready
        } else if inner.last_error.is_some() {
            State::Failed
        } else {
            State::Missing
        };
        Status {
            enabled: g.enabled,
            state,
            source_month: db.as_ref().map(|d| d.month),
            updated_at: db.as_ref().map(|d| d.built_at),
            rows: db.as_ref().map_or(0, |d| u64::from(d.source_rows)),
            size_bytes: db.as_ref().map_or(0, |d| d.size),
            next_check_at: if g.enabled && !inner.suppressed {
                inner.next_check
            } else {
                None
            },
            last_error: inner.last_error.clone(),
            old: db
                .as_ref()
                .is_some_and(|d| now.saturating_sub(d.built_at) > OLD_AFTER),
        }
    }

    /// The countries of `ips`, one answer each: `None` for an address with no country (private,
    /// in a gap). Reads the file by position (blocking: call it from `blocking()`).
    pub(crate) fn locate(
        &self,
        g: &MapGeoipConfig,
        ips: &[IpAddr],
    ) -> Result<Vec<Option<[u8; 2]>>, Unavailable> {
        if !g.enabled {
            return Err(Unavailable::Off);
        }
        let db = self.current().ok_or(Unavailable::Missing)?;
        Ok(ips.iter().map(|ip| db.lookup(*ip).ok().flatten()).collect())
    }

    /// "Update now": the task fetches at its next tick. False when a fetch is running.
    pub(crate) fn request_update(&self) -> bool {
        let mut i = self.inner();
        if i.downloading {
            return false;
        }
        i.manual = true;
        i.suppressed = false;
        drop(i);
        self.wake.notify_one();
        true
    }

    /// "Delete database": removes the files and stops fetching until an admin asks again.
    pub(crate) fn delete(&self) -> std::io::Result<()> {
        let mut i = self.inner();
        i.suppressed = true;
        i.generation = i.generation.wrapping_add(1);
        i.manual = false;
        i.last_error = None;
        i.next_check = None;
        drop(i);
        self.store(None);
        match self.dir() {
            Some(d) => ttgeo::remove_all(&d),
            None => Ok(()),
        }
    }

    /// Wakes the task (the settings changed: look at them now, not at the next tick).
    pub(crate) fn poke(&self) {
        self.wake.notify_one();
    }

    /// The status in the API's words.
    pub(crate) fn model(&self, g: &MapGeoipConfig, now: u64) -> wrendns_api::model::GeoipStatus {
        let s = self.status(g, now);
        let at = |t: u64| wrendns_api::time::format_us(t.saturating_mul(1_000_000));
        wrendns_api::model::GeoipStatus {
            enabled: s.enabled,
            state: s.state.word().to_owned(),
            source_month: s
                .source_month
                .map(|m| format!("{:04}-{:02}", m / 100, m % 100)),
            updated_at: s.updated_at.map(at),
            rows: s.rows,
            size_bytes: s.size_bytes,
            next_check_at: s.next_check_at.map(at),
            last_error: s.last_error,
            old: s.old,
            attribution: "IP geolocation by DB-IP.com (CC BY 4.0)".to_owned(),
        }
    }

    /// A test hook: the next write stops after `n` bytes.
    #[cfg(test)]
    pub(crate) fn crash_next_write_after(&self, n: u64) {
        *self
            .crash_after
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(n);
    }

    // -----------------------------------------------------------------------------------------
    // The task

    /// Runs until `stop`: looks at the settings every few seconds and fetches when one is due.
    pub(crate) async fn run(
        self: Arc<Self>,
        sources: Arc<crate::http::Sources>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) {
        loop {
            let cfg = sources.config.load_full();
            self.tick(&cfg, crate::pipeline::unix_now()).await;
            tokio::select! {
                _ = stop.changed() => return,
                () = self.wake.notified() => {}
                () = tokio::time::sleep(TICK) => {}
            }
        }
    }

    /// One look at the settings. Public to the tests so they step the clock.
    pub(crate) async fn tick(self: &Arc<Self>, cfg: &Config, now: u64) {
        let g = &cfg.map.geoip;
        let data_dir = Path::new(cfg.node.data_dir.as_str());
        let dir = self.set_dir(data_dir);
        if !g.enabled {
            let mut i = self.inner();
            if i.was_enabled {
                i.was_enabled = false;
                i.probed = false;
                i.suppressed = false;
                i.next_check = None;
                i.manual = false;
                drop(i);
                // The file stays; the handle goes, so nothing can read it while it is off.
                self.store(None);
            }
            return;
        }
        let first = {
            let mut i = self.inner();
            let first = !i.was_enabled;
            i.was_enabled = true;
            if first {
                i.suppressed = false;
            }
            first || !i.probed
        };
        if first {
            self.probe(&dir).await;
        }
        let want = {
            let i = self.inner();
            if i.downloading {
                return;
            }
            let db = self.current();
            let source_changed = i.fetched_from.as_ref().is_some_and(|f| *f != Source::of(g));
            i.manual
                || (!i.suppressed
                    && (source_changed
                        || match &db {
                            None => i.next_check.is_none_or(|t| now >= t),
                            Some(d) => {
                                d.month < month_of(now) && i.next_check.is_none_or(|t| now >= t)
                            }
                        }))
        };
        if want && !self.busy.swap(true, Ordering::AcqRel) {
            self.attempt(g, &dir, now).await;
            self.busy.store(false, Ordering::Release);
        }
    }

    /// Opens what is on disk, once per time the toggle goes on.
    async fn probe(&self, dir: &Path) {
        let d = dir.to_owned();
        let opened = tokio::task::spawn_blocking(move || Db::open(&d))
            .await
            .map_err(|_| OpenError::Invalid)
            .and_then(|r| r);
        let mut i = self.inner();
        i.probed = true;
        match opened {
            Ok(db) => {
                drop(i);
                self.store(Some(Arc::new(db)));
            }
            Err(OpenError::Missing) => {}
            Err(OpenError::Invalid) => {
                warn!("geoip: the database on disk is damaged and is ignored; it is fetched again");
            }
            Err(OpenError::Io(e)) => warn!("geoip: the database can't be read: {e}"),
        }
    }

    async fn attempt(self: &Arc<Self>, g: &MapGeoipConfig, dir: &Path, now: u64) {
        let generation = {
            let mut i = self.inner();
            i.downloading = true;
            i.manual = false;
            // A changed source is fetched once, not at every look; the backoff takes it from here.
            i.fetched_from = Some(Source::of(g));
            i.generation
        };
        let result = self.fetch_and_build_apart(g, dir, now).await;
        let mut i = self.inner();
        i.downloading = false;
        if i.generation != generation {
            // Deleted while this attempt ran: the admin's delete wins. Remove what it wrote.
            drop(i);
            drop(result);
            self.store(None);
            if let Err(e) = ttgeo::remove_all(dir) {
                warn!("geoip: a database written during a delete could not be removed: {e}");
            }
            return;
        }
        match result {
            Ok(db) => {
                info!(
                    month = db.month,
                    rows = db.source_rows,
                    "geoip: the country database is up to date"
                );
                i.last_error = None;
                i.failures = 0;
                i.next_check = Some(now + CHECK_EVERY + self.jitter);
                drop(i);
                self.store(Some(Arc::new(db)));
            }
            Err(code) => {
                warn!(
                    code,
                    "geoip: the download was not accepted; the old database is kept"
                );
                i.failures = i.failures.saturating_add(1);
                let back = BACKOFF_FIRST
                    .saturating_mul(1u64 << i.failures.saturating_sub(1).min(5))
                    .min(CHECK_EVERY);
                i.next_check = Some(now + back);
                i.last_error = Some(code);
            }
        }
    }

    /// REQ: OBS-902, NFR-001 (ADR-1008 (h)) - `fetch_and_build` on a thread of its own, with a
    /// one-thread runtime that ends with it: every buffer of the download (the TLS session, the
    /// body) and of the build is allocated by that thread's heap, so when the thread has dropped
    /// them it hands the pages back to the OS (`allocator_collect`) and exits, and the resolver
    /// returns to its idle size. On the shared runtime the body's pages stayed with the worker
    /// thread that collected it, a few MiB more after every build (`bench/geoipbuild.py`).
    async fn fetch_and_build_apart(
        self: &Arc<Self>,
        g: &MapGeoipConfig,
        dir: &Path,
        now: u64,
    ) -> Result<Db, String> {
        let (this, g, dir) = (Arc::clone(self), g.clone(), dir.to_owned());
        let (tx, rx) = tokio::sync::oneshot::channel();
        let spawned = std::thread::Builder::new()
            .name("geoip-build".to_owned())
            .spawn(move || {
                let out = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => {
                        let out = rt.block_on(this.fetch_and_build(&g, &dir, now));
                        drop(rt);
                        out
                    }
                    Err(_) => Err("build_failed".to_owned()),
                };
                drop((g, dir));
                wrendns_net::allocator_collect();
                // The code the download and the build ran (once a month) stops counting too.
                crate::server::trim_code_pages("geoip build");
                let _ = tx.send(out);
            });
        if spawned.is_err() {
            return Err("build_failed".to_owned());
        }
        rx.await.unwrap_or_else(|_| Err("build_failed".to_owned()))
    }

    /// Downloads, verifies, builds and publishes; the error is a code for the status. Runs on
    /// the `geoip-build` thread (`fetch_and_build_apart`).
    async fn fetch_and_build(
        &self,
        g: &MapGeoipConfig,
        dir: &Path,
        now: u64,
    ) -> Result<Db, String> {
        let client = Client::new(Arc::new(SystemResolver), &self.opts.extra_roots)
            .map_err(|_| "client_failed".to_owned())?;
        let custom = g.source_url.as_ref().map(|u| u.as_str().to_owned());
        let this = month_of(now);
        let urls: Vec<(String, u32)> = match &custom {
            Some(u) => vec![(u.clone(), this)],
            None => vec![
                (default_url(this), this),
                (default_url(prev_month(this)), prev_month(this)),
            ],
        };
        let mut last = "download_failed".to_owned();
        let mut got: Option<(Vec<u8>, u32)> = None;
        for (url, month) in &urls {
            if !url.starts_with("https://") {
                return Err("not_https".to_owned());
            }
            let r = tokio::time::timeout(
                ATTEMPT_TIMEOUT,
                client.get(url, &Conditional::default(), self.opts.limits.max_download),
            )
            .await;
            match r {
                Err(_) => return Err("timeout".to_owned()),
                Ok(Ok(Response::Body { data, .. })) => {
                    got = Some((data, *month));
                    break;
                }
                Ok(Ok(Response::NotModified)) => return Err("download_failed".to_owned()),
                Ok(Err(e)) => {
                    last = error_code(&e.message);
                    // The new month's file may not be published yet: try the month before.
                    if custom.is_none() && last == "not_found" {
                        continue;
                    }
                    return Err(last);
                }
            }
        }
        let Some((body, month)) = got else {
            return Err(last);
        };
        let pin = g.sha256.as_ref().map(|d| d.as_str().to_ascii_lowercase());
        let limits = self.opts.limits;
        let crash = self
            .crash_after
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let previous = self.current().map(|d| u64::from(d.source_rows));
        build_and_publish(
            body,
            pin.as_deref(),
            &limits,
            previous,
            dir,
            month,
            now,
            crash,
        )
    }
}

/// The blocking part: digest, parse, verify, build, write, swap, open.
#[allow(clippy::too_many_arguments)] // one step of the download, each argument a distinct input
fn build_and_publish(
    body: Vec<u8>,
    pin: Option<&str>,
    limits: &Limits,
    previous_rows: Option<u64>,
    dir: &Path,
    month: u32,
    now: u64,
    crash_after: Option<u64>,
) -> Result<Db, String> {
    if let Some(want) = pin {
        let got = ring::digest::digest(&ring::digest::SHA256, &body);
        if hex(got.as_ref()) != want {
            return Err(Reject::DigestMismatch.code().to_owned());
        }
    }
    let mut c = Collector::with_limits(limits.max_rows, limits.max_rows_v6);
    ttgeo::read_gzip_csv(&body, &mut c, limits.max_inflated).map_err(|r| r.code().to_owned())?;
    // The compressed body is not needed again: free it before the tables are built.
    drop(body);
    let table = c
        .finish(limits, previous_rows)
        .map_err(|r| r.code().to_owned())?;
    let tmp = ttgeo::write_tmp(dir, &table, month, now, crash_after)
        .map_err(|_| "write_failed".to_owned())?;
    // The built tables are on disk: free them before the file is opened for positional reads.
    drop(table);
    ttgeo::publish(dir, &tmp).map_err(|_| "write_failed".to_owned())?;
    Db::open(dir).map_err(|_| "write_failed".to_owned())
}

/// Lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// A failure of the HTTP client as a stable code (never a response body).
fn error_code(message: &str) -> String {
    let m = message.to_ascii_lowercase();
    if m.contains("http 404") {
        "not_found"
    } else if m.contains("refusing redirect") {
        "redirect_refused"
    } else if m.contains("redirects") {
        "too_many_redirects"
    } else if m.contains("larger") || m.contains("too big") || m.contains("exceeds") {
        "too_large"
    } else if m.contains("tls") {
        "tls_failed"
    } else if m.contains("http ") {
        "http_error"
    } else if m.contains("cannot resolve") {
        "dns_failed"
    } else if m.contains("link-local") {
        "address_refused"
    } else {
        "download_failed"
    }
    .to_owned()
}

/// `YYYYMM` of a Unix time.
pub(crate) fn month_of(secs: u64) -> u32 {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    u32::try_from(y * 100 + m).unwrap_or(0)
}

/// The month before a `YYYYMM`.
pub(crate) fn prev_month(ym: u32) -> u32 {
    let (y, m) = (ym / 100, ym % 100);
    if m <= 1 {
        (y - 1) * 100 + 12
    } else {
        y * 100 + m - 1
    }
}

fn default_url(ym: u32) -> String {
    format!("{DEFAULT_URL}{:04}-{:02}.csv.gz", ym / 100, ym % 100)
}

#[cfg(test)]
mod tests;

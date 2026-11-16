//! REQ: OPS-011 (ADR-156) — the process's own small log, for the support package.
//!
//! No platform lets the process read its stderr back (the systemd unit has no journal group, a
//! container's log is outside it, the Helm chart's root filesystem is read-only), so it keeps
//! what it needs itself: the last [`RING_LINES`] events at INFO and above in memory from the first
//! line it logs, and, once the data directory is known and locked, two rotating files of about
//! [`FILE_BYTES`] each under `<data_dir>/logs/`, so lines from before a restart reach the package.
//!
//! It never slows or stops anything: lines go to a bounded channel with `try_send` (a full channel
//! drops the line and counts it), a single writer thread owns the files, and a write error turns
//! the files off and leaves the ring. The lines are not redacted here (they carry client
//! addresses; the files are mode 0640): the package redacts when it is made.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::Context;

/// Lines kept in memory.
pub(crate) const RING_LINES: usize = 2_000;
/// Size at which a log file rotates (two files: the current one and the one before).
pub(crate) const FILE_BYTES: u64 = 1024 * 1024;
/// Lines waiting for the writer thread; more are dropped and counted.
const CHANNEL: usize = 1_024;
/// The longest line kept (longer ones are cut, on a character boundary).
const MAX_LINE: usize = 2_048;
/// The current file, and the one before it (`.1`).
const FILE: &str = "telltale.log";

/// Whether the files are being written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Files {
    /// Not attached yet (early start, a command-line tool) or `[support] persist_logs = false`.
    Off,
    /// Written under the data directory.
    On,
    /// Tried and failed (a read-only data directory, a full disk): only the ring remains.
    Failed(String),
}

/// What the support package reads.
#[derive(Debug, Clone)]
pub(crate) struct Snapshot {
    /// Oldest first; the previous run's last lines come first when the files are on.
    pub(crate) lines: Vec<String>,
    /// Lines the writer never got (a full channel).
    pub(crate) dropped: u64,
    pub(crate) files: Files,
}

enum Msg {
    Line(String),
    /// The writer answers once everything before it is on disk (tests, shutdown).
    Flush(SyncSender<()>),
}

/// The ring, the writer's channel, and the files' state.
pub(crate) struct SupportLog {
    ring: Mutex<VecDeque<String>>,
    dropped: AtomicU64,
    tx: OnceLock<SyncSender<Msg>>,
    files: Mutex<Files>,
    file_bytes: u64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned lock only means a panic elsewhere while logging; the data is still a list of lines.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

static GLOBAL: OnceLock<Arc<SupportLog>> = OnceLock::new();

/// The process's log (made on first use).
pub(crate) fn global() -> &'static Arc<SupportLog> {
    GLOBAL.get_or_init(|| Arc::new(SupportLog::new(FILE_BYTES)))
}

/// The tracing layer that feeds [`global`].
pub(crate) fn layer() -> SupportLayer {
    SupportLayer(Arc::clone(global()))
}

/// INFO and above whatever `TELLTALE_LOG` says, without the DNSSEC library's per-answer lines
/// (`TELLTALE_LOG_DNSSEC_LIBRARY` turns those back on, as for the console).
pub(crate) fn filter(library: tracing::level_filters::LevelFilter) -> Targets {
    Targets::new()
        .with_default(tracing::level_filters::LevelFilter::INFO)
        .with_target("hickory_net::dnssec", library)
}

impl SupportLog {
    pub(crate) fn new(file_bytes: u64) -> Self {
        Self {
            ring: Mutex::new(VecDeque::with_capacity(RING_LINES)),
            dropped: AtomicU64::new(0),
            tx: OnceLock::new(),
            files: Mutex::new(Files::Off),
            file_bytes,
        }
    }

    /// Keeps `line`: in the ring, and on its way to the files when they are on.
    pub(crate) fn push(&self, line: String) {
        let mut ring = lock(&self.ring);
        // Sent under the ring's lock so `attach` (which takes it too) sees every line exactly once.
        if let Some(tx) = self.tx.get() {
            match tx.try_send(Msg::Line(line.clone())) {
                Ok(()) | Err(TrySendError::Disconnected(_)) => {}
                Err(TrySendError::Full(_)) => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        if ring.len() >= RING_LINES {
            ring.pop_front();
        }
        ring.push_back(line);
    }

    /// Turns the files on under `data_dir/logs` (if `persist`): reads the last run's lines into the
    /// ring ahead of this run's, writes this run's early lines out, and starts the writer. A
    /// directory that can't be made or written leaves the ring alone and says why in [`Files`].
    pub(crate) fn attach(self: &Arc<Self>, data_dir: &Path, persist: bool) {
        if !persist {
            return;
        }
        let dir = data_dir.join("logs");
        match self.start_writer(&dir) {
            Ok(()) => *lock(&self.files) = Files::On,
            Err(e) => {
                let why = format!("{}: {e}", dir.display());
                *lock(&self.files) = Files::Failed(why.clone());
                tracing::warn!(
                    "the support log files are off ({why}); the last {RING_LINES} lines stay in memory only"
                );
            }
        }
    }

    fn start_writer(self: &Arc<Self>, dir: &Path) -> io::Result<()> {
        make_dir(dir)?;
        let current = dir.join(FILE);
        // Opened first: a directory that can't be written fails here, before anything is moved.
        let file = open_append(&current)?;
        let size = file.metadata()?.len();
        let (tx, rx) = sync_channel::<Msg>(CHANNEL);
        let old = read_tail(dir);
        {
            let mut ring = lock(&self.ring);
            // This run's lines so far aren't in the files yet.
            let early: Vec<String> = ring.drain(..).collect();
            for l in &early {
                // The channel is empty and bigger than the ring.
                let _ = tx.try_send(Msg::Line(l.clone()));
            }
            let skip = (old.len() + early.len()).saturating_sub(RING_LINES);
            ring.extend(old.into_iter().chain(early).skip(skip));
            if self.tx.set(tx).is_err() {
                return Err(io::Error::other("already attached"));
            }
        }
        let log = Arc::clone(self);
        let dir = dir.to_owned();
        std::thread::Builder::new()
            .name("support-log".into())
            .spawn(move || write_loop(&log, &dir, file, size, &rx))?;
        Ok(())
    }

    /// Waits until the writer has everything logged so far on disk (a no-op without files).
    pub(crate) fn flush(&self) {
        let Some(tx) = self.tx.get() else { return };
        let (done_tx, done_rx) = sync_channel(1);
        if tx.send(Msg::Flush(done_tx)).is_ok() {
            let _ = done_rx.recv_timeout(std::time::Duration::from_secs(2));
        }
    }

    /// The lines kept, how many were dropped, and whether the files are on.
    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            lines: lock(&self.ring).iter().cloned().collect(),
            dropped: self.dropped.load(Ordering::Relaxed),
            files: lock(&self.files).clone(),
        }
    }

    /// Tests: sends this log's lines to `tx` as if it were the writer's channel.
    #[cfg(test)]
    fn attach_channel(&self, tx: SyncSender<Msg>) {
        let _ = self.tx.set(tx);
    }
}

/// `dir` and its parents, `0750` where the platform has modes.
fn make_dir(dir: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o750);
    b.create(dir)
}

/// Appends to `path` (made if needed), `0640` where the platform has modes.
fn open_append(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o640);
    o.open(path)
}

/// The last run's lines: the older file, then the newer, at most [`RING_LINES`].
fn read_tail(dir: &Path) -> Vec<String> {
    let mut out: VecDeque<String> = VecDeque::new();
    for name in [format!("{FILE}.1"), FILE.to_owned()] {
        let Ok(f) = File::open(dir.join(name)) else {
            continue;
        };
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            if out.len() >= RING_LINES {
                out.pop_front();
            }
            out.push_back(line);
        }
    }
    out.into()
}

/// The files stopped: say so in the state and once in the log; the ring carries on.
fn fail(log: &SupportLog, why: &str) {
    *lock(&log.files) = Files::Failed(why.to_owned());
    tracing::warn!(
        "the support log files stopped ({why}); the last {RING_LINES} lines stay in memory only"
    );
}

/// The writer thread: appends lines, rotates at the log's size limit, and on an error stops
/// writing but keeps draining (so the ring and the senders never wait on it).
fn write_loop(log: &SupportLog, dir: &Path, file: File, size: u64, rx: &Receiver<Msg>) {
    let limit = log.file_bytes;
    let current: PathBuf = dir.join(FILE);
    let mut out = io::BufWriter::new(file);
    let mut size = size;
    let mut failed = false;
    while let Ok(first) = rx.recv() {
        let mut next = Some(first);
        while let Some(msg) = next.take() {
            match msg {
                Msg::Line(l) => {
                    if failed {
                        continue;
                    }
                    let n = u64::try_from(l.len()).unwrap_or(u64::MAX).saturating_add(1);
                    if size > 0 && size + n > limit {
                        // Rotate: this file becomes `.1` (replacing the one before) and a new one starts.
                        let rotated = out.flush().is_ok()
                            && fs::rename(&current, dir.join(format!("{FILE}.1"))).is_ok();
                        let fresh = if rotated {
                            open_append(&current).ok()
                        } else {
                            None
                        };
                        if let Some(f) = fresh {
                            out = io::BufWriter::new(f);
                            size = 0;
                        } else {
                            failed = true;
                            fail(log, &format!("couldn't rotate {}", current.display()));
                            continue;
                        }
                    }
                    if writeln!(out, "{l}").is_err() {
                        failed = true;
                        fail(log, &format!("couldn't write {}", current.display()));
                    } else {
                        size += n;
                    }
                }
                Msg::Flush(done) => {
                    let _ = out.flush();
                    let _ = done.send(());
                }
            }
            next = rx.try_recv().ok();
        }
        let _ = out.flush();
    }
    let _ = out.flush();
}

/// The layer: one line per event, `time LEVEL message key=value ...`.
pub(crate) struct SupportLayer(Arc<SupportLog>);

#[derive(Default)]
struct Fields {
    message: String,
    rest: String,
}

impl Visit for Fields {
    fn record_str(&mut self, f: &Field, v: &str) {
        if f.name() == "message" {
            self.message.push_str(v);
        } else {
            let _ = write!(self.rest, " {}={v}", f.name());
        }
    }
    fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
        if f.name() == "message" {
            let _ = write!(self.message, "{v:?}");
        } else {
            let _ = write!(self.rest, " {}={v:?}", f.name());
        }
    }
}

/// One line: no control characters, no longer than [`MAX_LINE`].
fn tidy(mut s: String) -> String {
    if s.chars().any(char::is_control) {
        s = s
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
    }
    if s.len() > MAX_LINE {
        let mut cut = MAX_LINE;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

impl<S: Subscriber> tracing_subscriber::Layer<S> for SupportLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut f = Fields::default();
        event.record(&mut f);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(0));
        let line = format!(
            "{} {:>5} {}{}",
            telltale_api::time::format_us(now),
            event.metadata().level(),
            f.message,
            f.rest
        );
        self.0.push(tidy(line));
    }
}

#[cfg(test)]
#[path = "support_log_tests.rs"]
mod tests;

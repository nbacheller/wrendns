//! REQ: DSC-002 (T25.3, ADR-908) — the supervisor of a discovery worker, on the `telltale-inventory`
//! thread (its own runtime, never the query runtime). It starts the worker process from
//! `/proc/self/exe` with a cleared environment, runs the handshake, sends a `ping` every
//! [`PING_EVERY`] and the queued jobs, and restarts the worker with backoff (1 s, doubling, to 5
//! min) when it crashes, hangs or exits. Three crashes within ten minutes raise
//! `discovery_worker_failing`; a build that differs is refused and raises
//! `discovery_worker_version_mismatch`. While a worker is down its results go stale, and DNS is
//! unaffected (CLU-004).
//!
//! Each worker's stderr is read on its own task and logged at a rate limit, never inherited.

use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use telltale_api::model::DiscoveryWorker;
use tokio::io::BufReader;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use super::frames::{self, Frame, FrameError};
use super::snmp_job::{MAX_ROWS_PER_JOB, OP_POLL, OP_PROBE};
use super::snmp_tables::Row;
use super::worker::{self, Hello, Job, JobResult, Msg};

/// The first wait after a crash; it doubles each time (ADR-908).
pub(crate) const BACKOFF_START_SECS: u64 = 1;
/// The longest wait between restarts (ADR-908).
pub(crate) const BACKOFF_MAX_SECS: u64 = 300;
/// Crashes within [`FAILING_WINDOW_SECS`] that raise `discovery_worker_failing` (ADR-908).
pub(crate) const FAILING_CRASHES: usize = 3;
/// The window of [`FAILING_CRASHES`] (ADR-908).
pub(crate) const FAILING_WINDOW_SECS: u64 = 600;
/// A run this long resets the backoff (the worker was healthy for a while).
pub(crate) const HEALTHY_RUN: Duration = Duration::from_secs(600);
/// How often the supervisor pings a running worker.
pub(crate) const PING_EVERY: Duration = Duration::from_secs(30);
/// How long a worker has to answer the handshake.
pub(crate) const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a worker has to answer one job: the SNMP walk's budget (ADR-908, a 30 s walk). A `ping`
/// has [`PING_TIMEOUT`] instead, so a hung worker is noticed sooner.
pub(crate) const JOB_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a worker has to answer a `ping`.
pub(crate) const PING_TIMEOUT: Duration = Duration::from_secs(10);
/// The most of one stderr line that is kept and logged. The rest of a longer line is dropped while
/// it is read, so a worker can't make this process hold more (ADR-908, CLU-004).
pub(crate) const STDERR_LINE_MAX: usize = 400;
/// How long a worker of another build is left alone before the next try.
pub(crate) const VERSION_WAIT: Duration = Duration::from_secs(300);
/// Stderr lines logged per minute, per worker; the rest are counted and dropped.
pub(crate) const STDERR_LINES_PER_MINUTE: u32 = 20;

/// A worker's stdout, buffered for one run.
type Reader = BufReader<ChildStdout>;

/// The shared board the workers write and the API reads: one entry per worker.
pub(crate) type Board = Arc<ArcSwap<Vec<DiscoveryWorker>>>;

/// REQ: DSC-004 (T25.6) — what a job found: its result, and the rows that came before it.
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) result: JobResult,
    pub(crate) rows: Vec<Row>,
}

/// The channel an answer comes back on. An error is the reason the worker could not answer (it
/// crashed, hung, or sent more than it may); a dropped sender means the supervisor stopped.
pub(crate) type ReplyTx = tokio::sync::oneshot::Sender<Result<Reply, String>>;

/// One queued job, and where its answer goes (none: it is only logged).
pub(crate) struct Request {
    pub(crate) job: Job,
    pub(crate) reply: Option<ReplyTx>,
}

/// Jobs queued for the running worker: the SNMP jobs of the poller and of the Test button, and the
/// fault jobs the tests queue. The supervisor numbers them itself.
pub(crate) type Requests = Arc<Mutex<VecDeque<Request>>>;

/// What to run and how to watch it.
#[derive(Debug, Clone)]
pub(crate) struct Spec {
    /// `snmp` or `import`.
    pub(crate) name: &'static str,
    /// The arguments after the binary (`discovery-worker`, `--import`).
    pub(crate) args: Vec<String>,
    /// The worker's memory limit, in MiB (`[discovery] worker_memory_mib`).
    pub(crate) memory_mib: u32,
    /// The binary to run. `/proc/self/exe` on Linux: the image that is running, not a newer file.
    pub(crate) exe: PathBuf,
    pub(crate) ping_every: Duration,
    /// The longest a job may take, unless [`timeout_for`] names another for its op.
    pub(crate) job_timeout: Duration,
    pub(crate) ping_timeout: Duration,
    pub(crate) hello_timeout: Duration,
    pub(crate) version_wait: Duration,
}

impl Spec {
    /// The worker the running binary starts: `telltale discovery-worker`, with the defaults.
    pub(crate) fn snmp(memory_mib: u32) -> Self {
        Self {
            name: "snmp",
            args: vec!["discovery-worker".to_owned()],
            memory_mib,
            exe: exe_path(),
            ping_every: PING_EVERY,
            job_timeout: JOB_TIMEOUT,
            ping_timeout: PING_TIMEOUT,
            hello_timeout: HELLO_TIMEOUT,
            version_wait: VERSION_WAIT,
        }
    }
}

/// The time a job of `op` may take: a `ping` has its own, an SNMP probe or poll has five times the
/// job timeout (150 s: the worker ends a poll at 100 s, and one exchange can run its retries past
/// that), and every other op has the job timeout.
pub(crate) fn timeout_for(spec: &Spec, op: &str) -> Duration {
    match op {
        "ping" => spec.ping_timeout,
        OP_PROBE | OP_POLL => spec.job_timeout.saturating_mul(5),
        _ => spec.job_timeout,
    }
}

/// REQ: DSC-002 (ADR-908) — the limits a worker reports must be the ones this process asked for:
/// not dumpable, its data limit at `memory_mib`, and `oom_score_adj` at [`worker::OOM_SCORE_ADJ`].
/// A worker that reports otherwise is refused (on Linux, where the limits exist).
pub(crate) fn check_limits(reply: &Hello, memory_mib: u32) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        if reply.dumpable {
            return Err("the worker is dumpable".to_owned());
        }
        let want = u64::from(memory_mib) << 20;
        if reply.data_bytes != want {
            return Err(format!(
                "its data limit is {} bytes, not the {want} asked for",
                reply.data_bytes
            ));
        }
        if reply.oom_score_adj != Some(telltale_net::worker::OOM_SCORE_ADJ) {
            return Err(format!(
                "its oom_score_adj is {:?}, not {}",
                reply.oom_score_adj,
                telltale_net::worker::OOM_SCORE_ADJ
            ));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (reply, memory_mib);
    }
    Ok(())
}

/// The path the workers are started from: this process's own executable (ADR-908).
pub(crate) fn exe_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/proc/self/exe")
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("telltale"))
    }
}

/// The wait before restart number `attempt` (0 for the first restart): 1 s, doubling, to 5 min.
pub(crate) fn backoff(attempt: u32) -> Duration {
    let secs = BACKOFF_START_SECS
        .saturating_mul(1u64 << attempt.min(16))
        .min(BACKOFF_MAX_SECS);
    Duration::from_secs(secs)
}

/// Whether the crash times (Unix seconds) hold [`FAILING_CRASHES`] within the window at `now`.
pub(crate) fn is_failing(crashes: &[u64], now: u64) -> bool {
    crashes
        .iter()
        .filter(|t| now.saturating_sub(**t) <= FAILING_WINDOW_SECS)
        .count()
        >= FAILING_CRASHES
}

/// How one run of a worker ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The worker crashed, hung, or exited; the reason, in words.
    Crashed(String),
    /// The worker's build or protocol differs from this node's.
    VersionMismatch(String),
    /// The supervisor was asked to stop.
    Stopped,
}

/// Rate limit for stderr lines: at most `per_minute` in each minute.
#[derive(Debug, Default)]
pub(crate) struct LineLimit {
    minute: u64,
    count: u32,
    dropped: u64,
}

impl LineLimit {
    /// Whether a line at `now` (Unix seconds) is logged; a refused one is counted.
    pub(crate) fn allow(&mut self, now: u64, per_minute: u32) -> bool {
        let minute = now / 60;
        if minute != self.minute {
            self.minute = minute;
            self.count = 0;
        }
        if self.count < per_minute {
            self.count = self.count.saturating_add(1);
            true
        } else {
            self.dropped = self.dropped.saturating_add(1);
            false
        }
    }

    /// Lines refused so far.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Sets one worker's entry on the board.
fn update(board: &Board, name: &str, f: impl FnOnce(&mut DiscoveryWorker)) {
    let mut all: Vec<DiscoveryWorker> = (**board.load()).clone();
    if let Some(w) = all.iter_mut().find(|w| w.worker == name) {
        f(w);
    } else {
        let mut w = DiscoveryWorker {
            worker: name.to_owned(),
            ..DiscoveryWorker::default()
        };
        f(&mut w);
        all.push(w);
    }
    board.store(Arc::new(all));
}

/// Runs the supervisor until `stop` is set. It owns the child and restarts it.
pub(crate) async fn supervise(spec: Spec, board: Board, requests: Requests, stop: Arc<AtomicBool>) {
    let mut attempt = 0u32;
    let mut crashes: Vec<u64> = Vec::new();
    let mut restarts = 0u64;
    while !stop.load(Ordering::Acquire) {
        let started = Instant::now();
        let outcome = run_once(&spec, &board, &requests, &stop).await;
        update(&board, spec.name, |w| {
            w.up = false;
        });
        match outcome {
            Outcome::Stopped => break,
            Outcome::VersionMismatch(why) => {
                tracing::warn!(worker = spec.name, reason = %why, "discovery worker refused: version mismatch");
                update(&board, spec.name, |w| {
                    w.version_mismatch = true;
                    w.last_error = Some(format!("refused: {why}"));
                });
                if !sleep_unless_stopped(spec.version_wait, &stop).await {
                    break;
                }
            }
            Outcome::Crashed(why) => {
                if started.elapsed() >= HEALTHY_RUN {
                    attempt = 0;
                }
                let now = unix_now();
                crashes.retain(|t| now.saturating_sub(*t) <= FAILING_WINDOW_SECS);
                crashes.push(now);
                restarts = restarts.saturating_add(1);
                let failing = is_failing(&crashes, now);
                let wait = backoff(attempt);
                tracing::warn!(worker = spec.name, reason = %why, restarts, "discovery worker stopped; restarting");
                update(&board, spec.name, |w| {
                    w.restarts = restarts;
                    w.failing = failing;
                    w.last_error = Some(why.clone());
                    w.version_mismatch = false;
                });
                attempt = attempt.saturating_add(1);
                if !sleep_unless_stopped(wait, &stop).await {
                    break;
                }
            }
        }
    }
    update(&board, spec.name, |w| {
        w.up = false;
    });
}

/// Sleeps for `d`, one second at a time, and returns false if `stop` was set meanwhile.
async fn sleep_unless_stopped(d: Duration, stop: &AtomicBool) -> bool {
    let mut left = d;
    while !left.is_zero() {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        let pause = left.min(Duration::from_secs(1));
        tokio::time::sleep(pause).await;
        left = left.saturating_sub(pause);
    }
    !stop.load(Ordering::Acquire)
}

/// One run: start, handshake, then pings and queued jobs until the worker fails or is stopped.
async fn run_once(spec: &Spec, board: &Board, requests: &Requests, stop: &AtomicBool) -> Outcome {
    let mut cmd = Command::new(&spec.exe);
    cmd.args(&spec.args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // REQ: DSC-002 (ADR-934) — the worker starts with no ambient capability, and this process is not
    // dumpable, so a worker can't read our memory. Before any spawn, and a failure is a crash.
    if let Err(e) = telltale_net::worker::prepare_spawn(cmd.as_std_mut()) {
        return Outcome::Crashed(format!("cannot prepare the worker: {e}"));
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Outcome::Crashed(format!("cannot start the worker: {e}")),
    };
    if let Some(err) = child.stderr.take() {
        let name = spec.name;
        tokio::spawn(log_stderr(name, err));
    }
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill().await;
        return Outcome::Crashed("the worker has no pipes".to_owned());
    };
    // One buffered reader for the whole run: a reader per frame would drop what it read ahead.
    let mut stdout: Reader = BufReader::new(stdout);
    // The handshake: our hello, then the worker's, which must match this build.
    let hello = Msg::Hello(Hello {
        protocol: worker::PROTOCOL,
        build: worker::build_id(),
        mode: spec.name.to_owned(),
        memory_mib: spec.memory_mib,
        ..Hello::default()
    });
    if let Err(e) = send(&mut stdin, &hello).await {
        return fail(&mut child, format!("handshake: {e}")).await;
    }
    let reply = match tokio::time::timeout(spec.hello_timeout, recv(&mut stdout)).await {
        Ok(Ok(Msg::Hello(h))) => h,
        Ok(Ok(_)) => return fail(&mut child, "no handshake".to_owned()).await,
        Ok(Err(e)) => return fail(&mut child, format!("handshake: {e}")).await,
        Err(_) => return fail(&mut child, "no handshake in time".to_owned()).await,
    };
    if let Err(why) = worker::check_hello(&reply, &worker::build_id()) {
        let _ = child.kill().await;
        return Outcome::VersionMismatch(why);
    }
    if let Err(why) = check_limits(&reply, spec.memory_mib) {
        return fail(&mut child, format!("refused: {why}")).await;
    }
    update(board, spec.name, |w| {
        w.up = true;
        w.version_mismatch = false;
        w.failing = false;
        w.data_limit_mib = (reply.data_bytes != u64::MAX).then_some(reply.data_bytes >> 20);
        w.dumpable = Some(reply.dumpable);
        w.oom_score_adj = reply.oom_score_adj;
    });
    let mut next_id = 1u64;
    let mut last_ping = Instant::now();
    loop {
        if stop.load(Ordering::Acquire) {
            let _ = child.kill().await;
            return Outcome::Stopped;
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Outcome::Crashed(format!("the worker exited ({status})"));
        }
        // Queued jobs first, then the periodic ping that proves the worker still answers.
        let queued = next_request(requests);
        let (mut job, reply) = match queued {
            Some(Request { job, reply }) => (job, reply),
            None if last_ping.elapsed() >= spec.ping_every => {
                last_ping = Instant::now();
                (Job::plain(0, "ping", ""), None)
            }
            None => {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        };
        // The supervisor numbers every job, so an answer is always matched to its own request.
        job.id = next_id;
        next_id = next_id.saturating_add(1);
        let limit = timeout_for(spec, &job.op);
        match run_job(&mut stdin, &mut stdout, &job, limit).await {
            Ok((r, rows)) => {
                if !r.ok {
                    tracing::debug!(worker = spec.name, op = %r.op, error = ?r.error, "discovery job refused");
                }
                if let Some(tx) = reply {
                    let _ = tx.send(Ok(Reply { result: r, rows }));
                }
            }
            Err(e) => {
                if let Some(tx) = reply {
                    let _ = tx.send(Err(e.clone()));
                }
                return fail(&mut child, format!("job {}: {e}", job.op)).await;
            }
        }
    }
}

/// The next queued request that somebody still waits for. One whose answer nobody waits for any
/// more (its caller timed out) is dropped, so a worker that was down doesn't run a backlog of stale
/// polls when it comes back.
fn next_request(requests: &Requests) -> Option<Request> {
    let mut q = requests.lock().ok()?;
    while let Some(r) = q.pop_front() {
        if r.reply.as_ref().is_some_and(ReplyTx::is_closed) {
            continue;
        }
        return Some(r);
    }
    None
}

async fn fail(child: &mut Child, why: String) -> Outcome {
    let _ = child.kill().await;
    Outcome::Crashed(why)
}

/// Sends one job and waits for its result within `timeout`, taking the rows that come first. The
/// rows are capped ([`MAX_ROWS_PER_JOB`]): a worker that sends more is a failed job (ADR-908).
async fn run_job(
    stdin: &mut ChildStdin,
    stdout: &mut Reader,
    job: &Job,
    timeout: Duration,
) -> Result<(JobResult, Vec<Row>), String> {
    send(stdin, &Msg::Job(job.clone())).await?;
    let id = job.id;
    let answer = async {
        let mut rows: Vec<Row> = Vec::new();
        loop {
            match recv(stdout).await? {
                Msg::Result(r) if r.id == id => return Ok((r, rows)),
                Msg::Rows(batch) if batch.id == id => {
                    if rows.len().saturating_add(batch.rows.len()) > MAX_ROWS_PER_JOB {
                        return Err("more rows than a job may return".to_owned());
                    }
                    rows.extend(batch.rows);
                }
                _ => return Err("an answer that isn't this job's".to_owned()),
            }
        }
    };
    tokio::time::timeout(timeout, answer)
        .await
        .map_err(|_| "no answer in time".to_owned())?
}

/// Sends one message. The frame may hold a credential (an SNMP job), so both buffers it passes
/// through are overwritten once the frame is written (ADR-908: credentials over stdin only).
async fn send(stdin: &mut ChildStdin, msg: &Msg) -> Result<(), String> {
    use zeroize::Zeroize;
    let f = worker::encode(msg)?;
    let bytes = frames::encode(&f).map_err(|e| e.to_string());
    let (Frame::Json(mut body) | Frame::Chunk(mut body)) = f;
    body.zeroize();
    let mut bytes = bytes?;
    let written = write_bytes_async(stdin, &bytes)
        .await
        .map_err(|e| e.to_string());
    bytes.zeroize();
    written
}

/// Writes bytes to an async stream and flushes it.
async fn write_bytes_async<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    bytes: &[u8],
) -> Result<(), FrameError> {
    use tokio::io::AsyncWriteExt;
    w.write_all(bytes)
        .await
        .map_err(|e| FrameError::Io(e.to_string()))?;
    w.flush().await.map_err(|e| FrameError::Io(e.to_string()))
}

async fn recv(stdout: &mut Reader) -> Result<Msg, String> {
    let f: Frame = frames::read_frame_async(stdout)
        .await
        .map_err(|e: FrameError| e.to_string())?;
    worker::decode(&f)
}

/// REQ: DSC-002 (ADR-908) — reads one line of a worker's stderr, keeping at most `keep` bytes of it.
/// The rest of a longer line is read and dropped up to its newline, so the memory this holds is
/// bounded whatever the worker writes. Returns `None` at the end of the stream, else the kept bytes
/// and whether the line was cut.
pub(crate) async fn read_capped_line<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
    keep: usize,
) -> io::Result<Option<(Vec<u8>, bool)>> {
    use tokio::io::AsyncBufReadExt;
    let mut line = Vec::new();
    let mut cut = false;
    let mut seen = false;
    loop {
        let buf = r.fill_buf().await?;
        if buf.is_empty() {
            return Ok(seen.then_some((line, cut)));
        }
        seen = true;
        let (take, newline) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (i, true),
            None => (buf.len(), false),
        };
        let room = keep.saturating_sub(line.len());
        if take > room {
            cut = true;
        }
        line.extend_from_slice(buf.get(..take.min(room)).unwrap_or_default());
        r.consume(if newline {
            take.saturating_add(1)
        } else {
            take
        });
        if newline {
            return Ok(Some((line, cut)));
        }
    }
}

/// Makes a worker's stderr line safe to log: invalid UTF-8 is replaced, and every control character
/// (a newline, an escape sequence) is written as an escape, so a line can't forge another log entry.
pub(crate) fn sanitize_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<char>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

/// Reads a worker's stderr and logs it, at most [`STDERR_LINES_PER_MINUTE`] lines a minute, each
/// line at most [`STDERR_LINE_MAX`] bytes and with its control characters escaped (ADR-908).
async fn log_stderr(name: &'static str, err: tokio::process::ChildStderr) {
    let mut reader = BufReader::new(err);
    let mut limit = LineLimit::default();
    while let Ok(Some((bytes, cut))) = read_capped_line(&mut reader, STDERR_LINE_MAX).await {
        if limit.allow(unix_now(), STDERR_LINES_PER_MINUTE) {
            let mut text = sanitize_line(&bytes);
            if cut {
                text.push_str(" [cut]");
            }
            tracing::warn!(worker = name, "{text}");
        }
    }
    if limit.dropped() > 0 {
        tracing::warn!(
            worker = name,
            dropped = limit.dropped(),
            "discovery worker stderr lines dropped"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DSC-002 — the backoff starts at 1 s, doubles, and stops at 5 min.
    #[test]
    fn dsc_002_backoff_doubles_to_five_minutes() {
        assert_eq!(backoff(0), Duration::from_secs(1));
        assert_eq!(backoff(1), Duration::from_secs(2));
        assert_eq!(backoff(4), Duration::from_secs(16));
        assert_eq!(backoff(20), Duration::from_secs(300));
        assert_eq!(backoff(u32::MAX), Duration::from_secs(300));
    }

    /// REQ: DSC-002 (DSC-014) — three crashes in ten minutes raise `failing`; older ones don't count.
    #[test]
    fn dsc_002_three_crashes_in_ten_minutes_is_failing() {
        let now = 10_000;
        assert!(!is_failing(&[now - 100, now - 200], now));
        assert!(is_failing(&[now - 100, now - 200, now - 300], now));
        assert!(!is_failing(&[now - 601, now - 100, now - 200], now));
    }

    /// REQ: DSC-002 — stderr lines are rate limited, and the refused ones are counted.
    /// REQ: DSC-002 (`dsc_002_stderr_line_is_bounded`) — a worker's stderr line is kept to
    /// [`STDERR_LINE_MAX`] bytes however long it is, the rest is read and dropped up to its newline,
    /// and the next line is still read whole.
    #[tokio::test]
    async fn dsc_002_stderr_line_is_bounded() {
        let mut bytes = vec![b'x'; 5 << 20];
        bytes.extend_from_slice(b"\nnext line\n");
        let mut rd = tokio::io::BufReader::new(&bytes[..]);
        let (first, cut) = read_capped_line(&mut rd, STDERR_LINE_MAX)
            .await
            .expect("read")
            .expect("a line");
        assert_eq!(first.len(), STDERR_LINE_MAX);
        assert!(cut, "the cut is recorded");
        let (second, cut) = read_capped_line(&mut rd, STDERR_LINE_MAX)
            .await
            .expect("read")
            .expect("the next line");
        assert_eq!(second, b"next line");
        assert!(!cut);
        assert!(
            read_capped_line(&mut rd, STDERR_LINE_MAX)
                .await
                .expect("read")
                .is_none()
        );
    }

    /// REQ: DSC-002 (`dsc_002_stderr_is_escaped`) — control characters in a worker's stderr are
    /// escaped before they are logged, so a line can't forge a log entry or move the terminal.
    #[test]
    fn dsc_002_stderr_is_escaped() {
        let s = sanitize_line(b"ok\r\n2026 WARN forged\x1b[2J\xff");
        assert!(!s.chars().any(char::is_control), "{s:?}");
        assert_eq!(s, "ok\\r\\n2026 WARN forged\\u{1b}[2J\u{fffd}");
    }

    /// REQ: DSC-002 (`dsc_002_limits_must_match`) — the supervisor refuses a worker whose reported
    /// limits aren't the ones it asked for (Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn dsc_002_limits_must_match() {
        let good = Hello {
            dumpable: false,
            data_bytes: 64 << 20,
            oom_score_adj: Some(1000),
            ..Hello::default()
        };
        assert!(check_limits(&good, 64).is_ok());
        let dumpable = Hello {
            dumpable: true,
            ..good.clone()
        };
        assert!(check_limits(&dumpable, 64).is_err());
        let other_size = Hello {
            data_bytes: 32 << 20,
            ..good.clone()
        };
        assert!(check_limits(&other_size, 64).is_err());
        let no_oom = Hello {
            oom_score_adj: None,
            ..good
        };
        assert!(check_limits(&no_oom, 64).is_err());
    }

    /// REQ: DSC-002 (`dsc_002_job_timeouts_by_op`) — a ping has its own, shorter timeout; a job has
    /// the walk's budget.
    #[test]
    fn dsc_002_job_timeouts_by_op() {
        let spec = Spec::snmp(64);
        assert_eq!(timeout_for(&spec, "ping"), PING_TIMEOUT);
        assert_eq!(timeout_for(&spec, "walk"), JOB_TIMEOUT);
        assert!(PING_TIMEOUT < JOB_TIMEOUT);
    }

    #[test]
    fn dsc_002_stderr_is_rate_limited() {
        let mut l = LineLimit::default();
        let allowed = (0..30).filter(|_| l.allow(600, 20)).count();
        assert_eq!(allowed, 20);
        assert_eq!(l.dropped(), 10);
        assert!(l.allow(660, 20), "a new minute resets the count");
    }

    /// REQ: DSC-002 (`dsc_002_version_mismatch_refused`) — the board says the mismatch, and the
    /// supervisor keeps the worker down.
    #[test]
    fn dsc_002_update_sets_board_entries() {
        let board: Board = Arc::new(ArcSwap::from_pointee(Vec::new()));
        update(&board, "snmp", |w| w.version_mismatch = true);
        update(&board, "snmp", |w| w.restarts = 2);
        let all = board.load();
        assert_eq!(all.len(), 1);
        let only = all.first().cloned().unwrap_or_default();
        assert!(only.version_mismatch);
        assert_eq!(only.restarts, 2);
    }
}

/// The supervisor run against real processes (`/bin/sh` standing in for a worker), on Unix.
#[cfg(all(test, unix))]
mod process_tests {
    use super::*;
    use std::fmt::Write as _;

    fn spec_for(script: String) -> Spec {
        Spec {
            name: "snmp",
            args: vec!["-c".to_owned(), script],
            memory_mib: 64,
            exe: PathBuf::from("/bin/sh"),
            ping_every: Duration::from_secs(30),
            job_timeout: Duration::from_millis(500),
            ping_timeout: Duration::from_millis(500),
            hello_timeout: Duration::from_millis(500),
            version_wait: Duration::from_secs(1),
        }
    }

    /// REQ: DSC-002 (`dsc_002_worker_reporting_other_limits_is_refused`) — a worker that reports it
    /// is dumpable is refused and ends as a crash, not run.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dsc_002_worker_reporting_other_limits_is_refused() {
        let build = worker::build_id();
        let hello = frame_bytes(&format!(
            r#"{{"t":"hello","protocol":1,"build":"{build}","dumpable":true,"data_bytes":67108864,"oom_score_adj":1000}}"#
        ));
        let spec = spec_for(format!("printf '{}'; exec sleep 30", octal(&hello)));
        let out = run_once(
            &spec,
            &board(),
            &Requests::default(),
            &AtomicBool::new(false),
        )
        .await;
        assert!(
            matches!(&out, Outcome::Crashed(w) if w.contains("dumpable")),
            "{out:?}"
        );
    }

    fn board() -> Board {
        Arc::new(ArcSwap::from_pointee(Vec::new()))
    }

    /// One frame with `json` as its JSON payload.
    fn frame_bytes(json: &str) -> Vec<u8> {
        let body = json.as_bytes();
        let len = u32::try_from(body.len().saturating_add(1)).unwrap_or(u32::MAX);
        let mut v = len.to_be_bytes().to_vec();
        v.push(frames::KIND_JSON);
        v.extend_from_slice(body);
        v
    }

    /// The bytes as a `printf` format of octal escapes, so the shell prints them unchanged.
    fn octal(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            let _ = write!(s, "\\{b:03o}");
        }
        s
    }

    /// REQ: DSC-002 (`dsc_002_worker_hang_times_out`) — a worker that never answers the handshake is
    /// given up on within the handshake timeout, and the run ends as a crash.
    #[tokio::test]
    async fn dsc_002_worker_hang_times_out() {
        let spec = spec_for("exec sleep 30".to_owned());
        let started = Instant::now();
        let out = run_once(
            &spec,
            &board(),
            &Requests::default(),
            &AtomicBool::new(false),
        )
        .await;
        assert!(
            matches!(&out, Outcome::Crashed(w) if w.contains("handshake")),
            "{out:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "given up on, not waited for"
        );
    }

    /// REQ: DSC-002 (`dsc_002_version_mismatch_refused`) — a worker of another build is refused: the
    /// run ends as a version mismatch, which the supervisor reports as its own health reason.
    #[tokio::test]
    async fn dsc_002_version_mismatch_refused() {
        let hello = frame_bytes(r#"{"t":"hello","protocol":1,"build":"another build"}"#);
        let spec = spec_for(format!("printf '{}'; exec sleep 30", octal(&hello)));
        let out = run_once(
            &spec,
            &board(),
            &Requests::default(),
            &AtomicBool::new(false),
        )
        .await;
        assert!(
            matches!(&out, Outcome::VersionMismatch(w) if w.contains("another build")),
            "{out:?}"
        );
    }

    /// REQ: DSC-002 — a worker that exits is a crash, not a clean stop; and a supervisor that has been
    /// asked to stop leaves no worker marked up.
    #[tokio::test]
    async fn dsc_002_worker_exit_is_a_crash() {
        let spec = spec_for("exit 7".to_owned());
        let out = run_once(
            &spec,
            &board(),
            &Requests::default(),
            &AtomicBool::new(false),
        )
        .await;
        assert!(matches!(&out, Outcome::Crashed(_)), "{out:?}");
        let b = board();
        supervise(
            spec,
            Arc::clone(&b),
            Requests::default(),
            Arc::new(AtomicBool::new(true)),
        )
        .await;
        assert!(!b.load().iter().any(|w| w.up));
    }
}

//! REQ: DSC-002 (T25.3, ADR-908) — the discovery worker processes, run for real: the built
//! `telltale discovery-worker` binary, started with a cleared environment, driven over its stdin
//! and stdout with the frame protocol of ADR-908. The fault jobs (a panic, a hang, an allocation
//! past the memory limit) exist in debug builds only, so those tests are compiled out of release.

#![allow(clippy::unwrap_used, clippy::expect_used)] // test helpers, not runtime code

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_telltale");
const KIND_JSON: u8 = 1;

/// One frame on the wire: the length (kind byte plus payload), the kind, the payload.
fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len() + 1).unwrap();
    let mut out = len.to_be_bytes().to_vec();
    out.push(kind);
    out.extend_from_slice(body);
    out
}

fn json_frame(v: &Value) -> Vec<u8> {
    frame(KIND_JSON, v.to_string().as_bytes())
}

/// A running worker: its stdin, and a reader thread that hands each frame on a channel.
struct Worker {
    child: Child,
    frames: mpsc::Receiver<Value>,
}

impl Worker {
    fn start(args: &[&str]) -> Self {
        Self::spawn(
            Command::new(BIN)
                .args(args)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null()),
        )
    }

    /// Starts the worker as another user (`uid` and `gid`), as the systemd unit, the image and the
    /// Helm chart run it. Needs root to change the user.
    #[cfg(target_os = "linux")]
    fn start_as(args: &[&str], uid: u32) -> Self {
        use std::os::unix::process::CommandExt;
        Self::spawn(
            Command::new(BIN)
                .args(args)
                .env_clear()
                .uid(uid)
                .gid(uid)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null()),
        )
    }

    fn spawn(cmd: &mut Command) -> Self {
        let mut child = cmd.spawn().expect("the telltale binary starts");
        let mut out = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            loop {
                let mut head = [0u8; 5];
                if out.read_exact(&mut head).is_err() {
                    return;
                }
                let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
                let mut body = vec![0u8; len.saturating_sub(1)];
                if out.read_exact(&mut body).is_err() {
                    return;
                }
                if head[4] == KIND_JSON
                    && let Ok(v) = serde_json::from_slice::<Value>(&body)
                    && tx.send(v).is_err()
                {
                    return;
                }
            }
        });
        Self { child, frames: rx }
    }

    fn send(&mut self, bytes: &[u8]) {
        let stdin = self.child.stdin.as_mut().unwrap();
        // The worker may have exited already (a refused handshake); a broken pipe is the answer.
        let _ = stdin.write_all(bytes);
        let _ = stdin.flush();
    }

    fn next(&self, within: Duration) -> Option<Value> {
        self.frames.recv_timeout(within).ok()
    }

    fn hello(memory_mib: u32, build: &str) -> Value {
        json!({"t": "hello", "protocol": 1, "build": build, "memory_mib": memory_mib})
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// REQ: DSC-002 (`dsc_002_worker_starts_as_non_root`) — the worker starts, hardens itself and
/// answers its handshake as an unprivileged user. The systemd unit (`User=telltale`), the image
/// (`USER 65532`) and the Helm chart (`runAsUser: 65532`) all run it that way. Its `oom_score_adj` is
/// written before the process becomes not dumpable, so the write is still the process's own. The
/// test needs root to start the worker as another user, and skips when it isn't root.
#[cfg(target_os = "linux")]
#[test]
fn dsc_002_worker_starts_as_non_root() {
    let status = std::fs::read_to_string("/proc/self/status").expect("status");
    let root = status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .is_some_and(|l| l.split_whitespace().nth(1) == Some("0"));
    if !root {
        eprintln!("skipped: the test starts the worker as another user, which needs root");
        return;
    }
    let build = worker_build();
    let mut w = Worker::start_as(&["discovery-worker"], 65534);
    w.send(&json_frame(&Worker::hello(64, &build)));
    let reply = w.next(Duration::from_secs(10)).expect(
        "the non-root worker answers its hello (it exits with code 4 when it can't harden)",
    );
    assert_eq!(reply["t"], "hello");
    assert_eq!(reply["dumpable"], false, "a worker is not dumpable");
    assert_eq!(
        reply["oom_score_adj"], 1000,
        "the kernel kills the worker first"
    );
    assert_eq!(
        reply["data_bytes"],
        64u64 << 20,
        "RLIMIT_DATA is the asked-for size"
    );
    w.send(&json_frame(&json!({"t": "job", "id": 1, "op": "ping"})));
    let answer = w.next(Duration::from_secs(10)).expect("ping answer");
    assert_eq!(answer["ok"], true);
}

/// The worker's own build, as it answers a hello it refuses (the answer carries its build).
fn worker_build() -> String {
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(64, "not this build")));
    let reply = w
        .next(Duration::from_secs(10))
        .expect("the worker answers its hello");
    reply["build"].as_str().unwrap().to_owned()
}

/// The worker's hello reply to a matching hello, after its limits were applied.
fn limits_reply(memory_mib: u32) -> Value {
    let build = worker_build();
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(memory_mib, &build)));
    w.next(Duration::from_secs(10)).expect("hello reply")
}

/// REQ: DSC-002 (`dsc_002_worker_env_is_empty`) — the worker starts with no environment: the parent
/// cleared it, and the worker reports how many variables it sees.
#[test]
fn dsc_002_worker_env_is_empty() {
    let reply = limits_reply(64);
    assert_eq!(reply["t"], "hello");
    assert_eq!(reply["env_vars"], 0, "the worker sees no environment");
    assert_eq!(reply["mode"], "snmp");
}

/// REQ: DSC-002 (`dsc_002_worker_oom_is_preferred`) — the worker asks the kernel to kill it first.
#[test]
fn dsc_002_worker_oom_is_preferred() {
    let reply = limits_reply(64);
    assert_eq!(
        reply["oom_score_adj"], 1000,
        "the kernel kills the worker first"
    );
}

/// REQ: DSC-002 (`dsc_002_worker_not_dumpable`) — the worker is not dumpable, and its memory limit
/// is the one asked for (`RLIMIT_DATA` on Linux). A ping after the handshake is answered.
#[test]
fn dsc_002_worker_not_dumpable() {
    let build = worker_build();
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(64, &build)));
    let reply = w.next(Duration::from_secs(10)).expect("hello reply");
    assert_eq!(reply["dumpable"], false, "a worker is not dumpable");
    if cfg!(target_os = "linux") {
        assert_eq!(
            reply["data_bytes"],
            64u64 << 20,
            "RLIMIT_DATA is the asked-for size"
        );
    }
    w.send(&json_frame(&json!({"t": "job", "id": 1, "op": "ping"})));
    let answer = w.next(Duration::from_secs(10)).expect("ping answer");
    assert_eq!(answer["t"], "result");
    assert_eq!(answer["ok"], true);
}

/// REQ: DSC-002 (`dsc_002_version_mismatch_refused`) — a parent of another build is refused: the
/// worker answers its own hello and exits with code 3, and nothing else runs.
#[test]
fn dsc_002_version_mismatch_refused() {
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(
        64,
        "a build that isn't this one",
    )));
    let reply = w
        .next(Duration::from_secs(10))
        .expect("the refusal names the worker's build");
    assert_eq!(reply["t"], "hello");
    assert_ne!(reply["build"], "a build that isn't this one");
    let status = w.child.wait().unwrap();
    assert_eq!(status.code(), Some(3));
}

/// REQ: DSC-002 (`dsc_002_oversized_frame_refused`) — a frame whose header claims more than 1 MiB of
/// JSON is refused from the header alone: the worker exits with code 2 without reading the body.
#[test]
fn dsc_002_oversized_frame_refused() {
    let mut w = Worker::start(&["discovery-worker"]);
    let claimed: u32 = (1 << 20) + 2;
    let mut head = claimed.to_be_bytes().to_vec();
    head.push(KIND_JSON);
    w.send(&head);
    let status = w.child.wait().unwrap();
    assert_eq!(status.code(), Some(2));
}

/// REQ: DSC-002 (`dsc_002_worker_panic_keeps_dns_answering`, the worker's part) — a worker that
/// panics ends as its own process; the test process, which stands for the DNS process, is
/// unaffected and can start the next worker.
#[cfg(debug_assertions)]
#[test]
fn dsc_002_worker_panic_ends_only_the_worker() {
    let build = worker_build();
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(64, &build)));
    let _ = w.next(Duration::from_secs(10)).expect("hello reply");
    w.send(&json_frame(
        &json!({"t": "job", "id": 9, "op": "fault", "kind": "panic"}),
    ));
    let status = w.child.wait().unwrap();
    assert!(!status.success(), "a panicking worker exits unsuccessfully");
    let mut next = Worker::start(&["discovery-worker"]);
    next.send(&json_frame(&Worker::hello(64, &build)));
    assert!(
        next.next(Duration::from_secs(10)).is_some(),
        "the next worker starts"
    );
}

/// REQ: DSC-002 (`dsc_002_worker_hang_times_out`) — a job that never answers is not answered in time,
/// and the supervisor's kill (here, the test's) ends the worker.
#[cfg(debug_assertions)]
#[test]
fn dsc_002_worker_hang_times_out() {
    let build = worker_build();
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(64, &build)));
    let _ = w.next(Duration::from_secs(10)).expect("hello reply");
    w.send(&json_frame(
        &json!({"t": "job", "id": 5, "op": "fault", "kind": "hang"}),
    ));
    assert!(
        w.next(Duration::from_secs(2)).is_none(),
        "a hung job gives no answer"
    );
    w.child.kill().unwrap();
    assert!(w.child.wait().is_ok());
}

/// REQ: DSC-002 (`dsc_002_worker_rlimit_aborts_alone`) — a worker that allocates past its memory
/// limit aborts, and only it: the test process carries on.
#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn dsc_002_worker_rlimit_aborts_alone() {
    let build = worker_build();
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(32, &build)));
    let reply = w.next(Duration::from_secs(10)).expect("hello reply");
    assert_eq!(reply["data_bytes"], 32u64 << 20);
    w.send(&json_frame(
        &json!({"t": "job", "id": 2, "op": "fault", "kind": "alloc"}),
    ));
    let status = w.child.wait().unwrap();
    assert!(
        !status.success(),
        "an allocation past RLIMIT_DATA aborts the worker"
    );
}

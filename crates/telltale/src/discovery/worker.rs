//! REQ: DSC-002 (T25.3, ADR-908, ADR-913) — the discovery worker processes, child side. `telltale
//! discovery-worker` (the SNMP poller, from T25.4) and `telltale discovery-worker --import` (the
//! scan-import parser, from T25.11) are this same loop in two modes. The protocol:
//!
//! 1. The parent sends a `hello` (protocol, build ID, memory limit). A mismatch of protocol or
//!    build is answered with the worker's own `hello` and the worker exits (3): the parent reports
//!    `discovery_worker_version_mismatch` and runs nothing else.
//! 2. The worker applies its limits (`telltale_net::worker::harden`) and answers `hello` with them.
//! 3. Each `job` gets one `result`. The worker exits when its input ends (0), on a bad frame (2),
//!    or when it can't be hardened (4).
//!
//! Nothing secret arrives in argv or the environment (the parent clears it); credentials will come
//! on stdin only (ADR-908). The jobs themselves (SNMP, import parsing) are T25.4 and T25.11; until
//! then the only job is `ping`, and in debug builds the `fault` jobs the tests use to check that the
//! parent survives a panic, a hang and an allocation failure.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use telltale_net::worker::WorkerLimits;

use super::frames::{self, Frame, FrameError};

/// The wire protocol version. Bumped when a frame or message changes meaning (ADR-908).
pub(crate) const PROTOCOL: u32 = 1;
/// Exit code: a frame or message was malformed.
pub(crate) const EXIT_PROTOCOL: i32 = 2;
/// Exit code: the handshake was refused (protocol or build mismatch).
pub(crate) const EXIT_MISMATCH: i32 = 3;
/// Exit code: the limits couldn't be applied, so the worker refuses to run.
pub(crate) const EXIT_HARDEN: i32 = 4;

/// The build ID both sides compare: the version and the commit this binary was built from.
pub(crate) fn build_id() -> String {
    format!(
        "{} {}",
        crate::build_info::VERSION,
        crate::build_info::COMMIT
    )
}

/// One message on the channel. Unknown fields are ignored, so a newer peer can add some.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub(crate) enum Msg {
    Hello(Hello),
    Job(Job),
    Result(JobResult),
}

/// The handshake, in both directions. The worker's reply carries what it reports about itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Hello {
    pub(crate) protocol: u32,
    pub(crate) build: String,
    /// `snmp` or `import`: which worker this is.
    pub(crate) mode: String,
    /// The parent's request: the worker's `RLIMIT_DATA`, in MiB.
    pub(crate) memory_mib: u32,
    /// The worker's pid, for the logs.
    pub(crate) pid: u32,
    /// How many environment variables the worker sees (zero: the parent cleared them).
    pub(crate) env_vars: usize,
    /// The worker's `RLIMIT_DATA` after hardening, in bytes (`u64::MAX` when unlimited).
    pub(crate) data_bytes: u64,
    /// Whether the worker is dumpable (it must not be).
    pub(crate) dumpable: bool,
    /// The worker's `oom_score_adj`, when readable (1000 when hardened).
    pub(crate) oom_score_adj: Option<i32>,
}

/// One request to the worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Job {
    pub(crate) id: u64,
    pub(crate) op: String,
    #[serde(default)]
    pub(crate) kind: String,
}

/// The answer to one job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct JobResult {
    pub(crate) id: u64,
    pub(crate) ok: bool,
    #[serde(default)]
    pub(crate) op: String,
    #[serde(default)]
    pub(crate) error: Option<String>,
}

/// Decodes a JSON frame into a message.
pub(crate) fn decode(frame: &Frame) -> Result<Msg, String> {
    match frame {
        Frame::Json(b) => serde_json::from_slice::<Msg>(b).map_err(|e| e.to_string()),
        Frame::Chunk(_) => Err("a binary frame where a message was expected".to_owned()),
    }
}

/// Encodes a message as a JSON frame.
pub(crate) fn encode(msg: &Msg) -> Result<Frame, String> {
    let b = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
    Ok(Frame::Json(b))
}

/// Parent side: whether a worker's `hello` matches this binary (protocol and build ID).
pub(crate) fn check_hello(reply: &Hello, expected_build: &str) -> Result<(), String> {
    if reply.protocol != PROTOCOL {
        return Err(format!(
            "protocol {} (this node speaks {PROTOCOL})",
            reply.protocol
        ));
    }
    if reply.build != expected_build {
        return Err(format!(
            "build `{}` (this node is `{expected_build}`)",
            reply.build
        ));
    }
    Ok(())
}

/// Child side: runs the request loop over `input` and `output` until the input ends, and returns
/// the exit code. `harden` applies the limits for the memory the parent asked for and reports them;
/// the real one is [`harden_process`], and tests pass their own.
pub(crate) fn serve<R, W, H>(input: &mut R, output: &mut W, mode: &str, harden: H) -> i32
where
    R: Read,
    W: Write,
    H: FnOnce(u32) -> Result<WorkerLimits, String>,
{
    let Ok(Msg::Hello(first)) = frames::read_frame(input)
        .map_err(|e| e.to_string())
        .and_then(|f| decode(&f))
    else {
        return EXIT_PROTOCOL;
    };
    let build = build_id();
    let mismatch = first.protocol != PROTOCOL || first.build != build;
    let limits = if mismatch {
        WorkerLimits {
            data_bytes: 0,
            dumpable: false,
            oom_score_adj: None,
        }
    } else {
        match harden(first.memory_mib) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("discovery worker: {e}");
                return EXIT_HARDEN;
            }
        }
    };
    let reply = Hello {
        protocol: PROTOCOL,
        build,
        mode: mode.to_owned(),
        memory_mib: first.memory_mib,
        pid: std::process::id(),
        env_vars: std::env::vars_os().count(),
        data_bytes: limits.data_bytes,
        dumpable: limits.dumpable,
        oom_score_adj: limits.oom_score_adj,
    };
    if write_msg(output, &Msg::Hello(reply)).is_err() {
        return EXIT_PROTOCOL;
    }
    if mismatch {
        eprintln!("discovery worker: refused: the parent's build or protocol differs");
        return EXIT_MISMATCH;
    }
    loop {
        let frame = match frames::read_frame(input) {
            Ok(f) => f,
            Err(FrameError::Eof) => return 0,
            Err(e) => {
                eprintln!("discovery worker: {e}");
                return EXIT_PROTOCOL;
            }
        };
        let Ok(Msg::Job(job)) = decode(&frame) else {
            eprintln!("discovery worker: a frame that isn't a job");
            return EXIT_PROTOCOL;
        };
        let result = run_job(&job);
        if write_msg(output, &Msg::Result(result)).is_err() {
            return EXIT_PROTOCOL;
        }
    }
}

/// Runs one job. Fault jobs exist only in debug builds (the tests use them): a release worker
/// answers them as unknown ops, so no request can make a release worker panic, hang or exhaust its
/// memory.
pub(crate) fn run_job(job: &Job) -> JobResult {
    let ok = |op: &str| JobResult {
        id: job.id,
        ok: true,
        op: op.to_owned(),
        error: None,
    };
    let unknown = || JobResult {
        id: job.id,
        ok: false,
        op: job.op.clone(),
        error: Some("unknown op".to_owned()),
    };
    match job.op.as_str() {
        "ping" => ok("ping"),
        #[cfg(debug_assertions)]
        "fault" => match job.kind.as_str() {
            // The one deliberate panic: the tests check that a panicking worker ends alone.
            #[allow(clippy::panic)]
            "panic" => panic!("injected worker panic"),
            "hang" => {
                std::thread::sleep(std::time::Duration::from_secs(3600));
                ok("fault")
            }
            "alloc" => {
                // Past RLIMIT_DATA the allocation fails, and the worker aborts on its own.
                let v = std::hint::black_box(vec![1u8; 1 << 30]);
                std::hint::black_box(v.len());
                ok("fault")
            }
            _ => unknown(),
        },
        _ => unknown(),
    }
}

fn write_msg<W: Write>(w: &mut W, msg: &Msg) -> Result<(), String> {
    let f = encode(msg)?;
    frames::write_frame(w, &f).map_err(|e| e.to_string())
}

/// The real hardening: the memory limit the parent asked for, then the limits as reported.
pub(crate) fn harden_process(memory_mib: u32) -> Result<WorkerLimits, String> {
    let bytes = u64::from(memory_mib).saturating_mul(1 << 20);
    telltale_net::worker::harden(bytes).map_err(|e| format!("cannot apply the limits: {e}"))?;
    Ok(telltale_net::worker::limits())
}

/// The process entry point of `telltale discovery-worker [--import]`. Returns the exit code.
pub(crate) fn main(import: bool) -> i32 {
    let mode = if import { "import" } else { "snmp" };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    serve(&mut input, &mut output, mode, harden_process)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> WorkerLimits {
        WorkerLimits {
            data_bytes: 64 << 20,
            dumpable: false,
            oom_score_adj: Some(1000),
        }
    }

    fn hello(build: &str, protocol: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let h = Msg::Hello(Hello {
            protocol,
            build: build.to_owned(),
            memory_mib: 64,
            ..Hello::default()
        });
        write_msg(&mut out, &h).unwrap();
        out
    }

    fn job_bytes(id: u64, op: &str, kind: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let job = Msg::Job(Job {
            id,
            op: op.into(),
            kind: kind.into(),
        });
        write_msg(&mut out, &job).unwrap();
        out
    }

    fn next_msg(rd: &mut &[u8]) -> Msg {
        decode(&frames::read_frame(rd).unwrap()).unwrap()
    }

    /// REQ: DSC-002 (`dsc_002_version_mismatch_refused`) — a worker of another build is refused, and
    /// the parent's check names the difference.
    #[test]
    fn dsc_002_version_mismatch_refused() {
        let input = hello("0.0.1 other", PROTOCOL);
        let mut out = Vec::new();
        let code = serve(&mut input.as_slice(), &mut out, "snmp", |_| Ok(limits()));
        assert_eq!(code, EXIT_MISMATCH);
        // The worker still answers its own hello, so the parent can name the mismatch.
        let mut rd = out.as_slice();
        let Msg::Hello(h) = next_msg(&mut rd) else {
            panic!("no hello")
        };
        assert_eq!(check_hello(&h, &build_id()), Ok(()));
        assert!(check_hello(&h, "0.0.1 other").is_err());
        let wrong_protocol = Hello {
            protocol: PROTOCOL + 1,
            build: build_id(),
            ..Hello::default()
        };
        assert!(
            check_hello(&wrong_protocol, &build_id())
                .unwrap_err()
                .contains("protocol")
        );
    }

    /// REQ: DSC-002 — the worker answers the handshake with its limits, and `ping` after it.
    #[test]
    fn dsc_002_handshake_reports_limits_and_ping_answers() {
        let mut input = hello(&build_id(), PROTOCOL);
        input.extend(job_bytes(7, "ping", ""));
        let mut out = Vec::new();
        let code = serve(&mut input.as_slice(), &mut out, "import", |mib| {
            assert_eq!(mib, 64);
            Ok(limits())
        });
        assert_eq!(code, 0);
        let mut rd = out.as_slice();
        let Msg::Hello(h) = next_msg(&mut rd) else {
            panic!("no hello")
        };
        assert_eq!(h.mode, "import");
        assert_eq!(h.data_bytes, 64 << 20);
        assert!(!h.dumpable);
        assert_eq!(h.oom_score_adj, Some(1000));
        let Msg::Result(r) = next_msg(&mut rd) else {
            panic!("no result")
        };
        assert_eq!(
            r,
            JobResult {
                id: 7,
                ok: true,
                op: "ping".into(),
                error: None
            }
        );
    }

    /// REQ: DSC-002 — a limit that can't be applied stops the worker before it answers a job.
    #[test]
    fn dsc_002_unhardened_worker_refuses_to_run() {
        let mut input = hello(&build_id(), PROTOCOL);
        input.extend(job_bytes(1, "ping", ""));
        let mut out = Vec::new();
        let code = serve(
            &mut input.as_slice(),
            &mut out,
            "snmp",
            |_| Err("no".into()),
        );
        assert_eq!(code, EXIT_HARDEN);
        assert!(out.is_empty(), "no reply at all");
    }

    /// REQ: DSC-002 — a job the worker doesn't know gets `ok: false`, and the loop goes on.
    #[test]
    fn dsc_002_unknown_op_is_answered_not_fatal() {
        let mut input = hello(&build_id(), PROTOCOL);
        input.extend(job_bytes(3, "snmp_set", ""));
        input.extend(job_bytes(4, "ping", ""));
        let mut out = Vec::new();
        assert_eq!(
            serve(&mut input.as_slice(), &mut out, "snmp", |_| Ok(limits())),
            0
        );
        let mut rd = out.as_slice();
        let _hello = next_msg(&mut rd);
        let Msg::Result(a) = next_msg(&mut rd) else {
            panic!("no result")
        };
        assert!(!a.ok);
        assert_eq!(a.error.as_deref(), Some("unknown op"));
        let Msg::Result(b) = next_msg(&mut rd) else {
            panic!("no result")
        };
        assert!(b.ok);
    }

    /// REQ: DSC-002 — a binary frame, or JSON that isn't a message, ends the worker with the
    /// protocol code.
    #[test]
    fn dsc_002_bad_frame_ends_the_worker() {
        let mut input = hello(&build_id(), PROTOCOL);
        input.extend(frames::encode(&Frame::Chunk(vec![1, 2, 3])).unwrap());
        let mut out = Vec::new();
        assert_eq!(
            serve(&mut input.as_slice(), &mut out, "snmp", |_| Ok(limits())),
            EXIT_PROTOCOL
        );
        let mut input = hello(&build_id(), PROTOCOL);
        input.extend(frames::encode(&Frame::Json(b"not json".to_vec())).unwrap());
        let mut out = Vec::new();
        assert_eq!(
            serve(&mut input.as_slice(), &mut out, "snmp", |_| Ok(limits())),
            EXIT_PROTOCOL
        );
    }

    /// REQ: DSC-002 — the release build answers fault jobs as unknown ops (none of them runs).
    #[cfg(not(debug_assertions))]
    #[test]
    fn dsc_002_release_has_no_fault_ops() {
        let r = run_job(&Job {
            id: 1,
            op: "fault".into(),
            kind: "panic".into(),
        });
        assert!(!r.ok);
    }
}

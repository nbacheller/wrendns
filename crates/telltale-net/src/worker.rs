//! REQ: DSC-002 (T25.3, ADR-908) — the hardening of a discovery worker process: its memory limit,
//! no core dumps, not dumpable, and the OOM preference. The unsafe calls are in `sys`; this module
//! is the safe wrapper the worker calls once, at start (AGENTS rule 7).

use std::io;

/// The OOM score a discovery worker asks for: the kernel kills it before the DNS process.
pub const OOM_SCORE_ADJ: i32 = 1000;

/// What a worker reports about its own limits, so the supervisor can check them (DSC-002 AC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerLimits {
    /// `RLIMIT_DATA` soft limit in bytes (`u64::MAX` when unlimited; always the set value after
    /// [`harden`] on Linux).
    pub data_bytes: u64,
    /// Whether the process is dumpable (`PR_GET_DUMPABLE`).
    pub dumpable: bool,
    /// The `/proc/self/oom_score_adj` value, when readable.
    pub oom_score_adj: Option<i32>,
}

/// Applies the worker's limits, in this order (REQ: DSC-002, ADR-908):
///
/// 1. `oom_score_adj` at [`OOM_SCORE_ADJ`]. Raising the score needs no privilege, and it is first
///    because a non-dumpable process's `/proc/self` belongs to root: after step 5 this write fails
///    for every uid but root (the bug this order fixes).
/// 2. `RLIMIT_DATA` at `data_bytes` and `RLIMIT_CORE` 0.
/// 3. No capability: the ambient set cleared, the others emptied, `no_new_privs` set.
/// 4. The seccomp filter that refuses `bind`, `listen`, `ptrace` and `process_vm_*`.
/// 5. Not dumpable.
///
/// The capability, `no_new_privs` and seccomp steps apply to the calling thread (Linux keeps them per
/// thread), so `harden` runs on the worker's main thread before it does anything else. The limits and
/// dumpability apply to the whole process.
///
/// Any step that fails is an error, and the worker refuses to run (fail closed). A no-op off Linux,
/// where the discovery worker still runs (development builds on macOS), without the kernel limits.
pub fn harden(data_bytes: u64) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        std::fs::write("/proc/self/oom_score_adj", OOM_SCORE_ADJ.to_string())?;
        crate::sys::set_worker_rlimits(data_bytes)?;
        crate::sys::drop_worker_capabilities()?;
        crate::sys::install_worker_seccomp()?;
        crate::sys::set_dumpable(false)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = data_bytes;
        Ok(())
    }
}

/// The worker's current limits, as [`WorkerLimits`].
pub fn limits() -> WorkerLimits {
    #[cfg(target_os = "linux")]
    {
        let oom = std::fs::read_to_string("/proc/self/oom_score_adj")
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok());
        WorkerLimits {
            data_bytes: crate::sys::data_limit().unwrap_or(0),
            dumpable: crate::sys::dumpable(),
            oom_score_adj: oom,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        WorkerLimits {
            data_bytes: u64::MAX,
            dumpable: true,
            oom_score_adj: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DSC-002 — the hardening sets what it promises: the data limit, no dumps, not
    /// dumpable, and the OOM score. Run in a child process so the test process keeps its own.
    /// REQ: DSC-002 (`dsc_002_worker_not_dumpable`, `dsc_002_worker_oom_is_preferred`)
    #[cfg(target_os = "linux")]
    #[test]
    fn dsc_002_worker_limits_are_set() {
        if std::env::var_os("TT_HARDEN_CHILD").is_some() {
            harden(64 * 1024 * 1024).expect("harden");
            let l = limits();
            assert_eq!(l.data_bytes, 64 * 1024 * 1024);
            assert!(!l.dumpable);
            assert_eq!(l.oom_score_adj, Some(OOM_SCORE_ADJ));
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args([
                "worker::tests::dsc_002_worker_limits_are_set",
                "--exact",
                "--nocapture",
            ])
            .env("TT_HARDEN_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// REQ: DSC-002 (`dsc_002_worker_privileges_are_dropped`) — after [`harden`], the worker holds no
    /// capability and has `no_new_privs`, it cannot listen or bind (so it can't share the DNS port),
    /// and it cannot trace a process. Run in a child process, as the test above does.
    #[cfg(target_os = "linux")]
    #[test]
    fn dsc_002_worker_privileges_are_dropped() {
        if std::env::var("TT_HARDEN_CHILD").as_deref() == Ok("privs") {
            harden(64 * 1024 * 1024).expect("harden");
            // The capability sets, NoNewPrivs and the seccomp filter are per thread: read this thread's.
            let status = std::fs::read_to_string("/proc/thread-self/status").expect("status");
            for field in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
                let line = status
                    .lines()
                    .find(|l| l.starts_with(field))
                    .expect("a capability line");
                assert!(line.ends_with("0000000000000000"), "{line}");
            }
            assert!(
                status.lines().any(|l| l == "NoNewPrivs:\t1"),
                "no_new_privs is set"
            );
            let denied = Some(io::ErrorKind::PermissionDenied);
            let bind = std::net::UdpSocket::bind("127.0.0.1:0");
            assert_eq!(bind.err().map(|e| e.kind()), denied, "bind is refused");
            let listen = std::net::TcpListener::bind("127.0.0.1:0");
            assert_eq!(listen.err().map(|e| e.kind()), denied, "listen is refused");
            assert_eq!(
                crate::sys::ptrace_probe().err().map(|e| e.kind()),
                denied,
                "ptrace is refused"
            );
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args([
                "worker::tests::dsc_002_worker_privileges_are_dropped",
                "--exact",
                "--nocapture",
            ])
            .env("TT_HARDEN_CHILD", "privs")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

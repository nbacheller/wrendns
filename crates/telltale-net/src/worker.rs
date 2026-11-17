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

/// Applies the worker's limits: `RLIMIT_DATA` at `data_bytes`, `RLIMIT_CORE` 0, not dumpable, and
/// `oom_score_adj` at [`OOM_SCORE_ADJ`]. A no-op off Linux, where the discovery worker still runs
/// (development builds on macOS), but without the kernel limits.
pub fn harden(data_bytes: u64) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        crate::sys::harden_worker(data_bytes)?;
        // Raising the score is allowed to an unprivileged process; lowering it is not, so a
        // refusal here is reported, not hidden: the worker still runs, and the supervisor logs it.
        std::fs::write("/proc/self/oom_score_adj", OOM_SCORE_ADJ.to_string())?;
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
}

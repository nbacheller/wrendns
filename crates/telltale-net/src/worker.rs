//! REQ: DSC-002 (T25.3, ADR-908) — the hardening of a discovery worker process: its memory limit,
//! no core dumps, not dumpable, and the OOM preference. The unsafe calls are in `sys`; this module
//! is the safe wrapper the worker calls once, at start (AGENTS rule 7).

use std::io;

/// The OOM score a discovery worker asks for: the kernel kills it before the DNS process.
pub const OOM_SCORE_ADJ: i32 = 1000;

/// REQ: DSC-002, API-007 (ADR-988) — the environment a worker is started with so its allocator
/// reserves no arena. mimalloc, the global allocator of the release build, reserves a 1 GiB arena
/// at its first allocation (before `main`), and Linux counts a mapped read-write range against
/// `RLIMIT_DATA` whether or not it is touched: under any limit of 1 GiB or less, every allocation
/// after [`harden`] fails (the Pi-hole import answered `"<path>: <path>"`, SQLite's null handle).
/// `MIMALLOC_ARENA_RESERVE=0` (KiB) makes mimalloc take each 32 MiB segment from the kernel on
/// demand, committed page by page, so the limit counts what the worker really holds and still
/// stops a hostile input. [`prepare_spawn`] sets it; a spawner that skips `prepare_spawn` gets a
/// clear refusal from [`harden`] instead.
pub const WORKER_ALLOCATOR_ENV: (&str, &str) = ("MIMALLOC_ARENA_RESERVE", "0");

/// Address space the worker may already hold at [`harden`] before the limit is too small to leave
/// it room to run (the binary's data segment, the thread stacks' guard pages, the first segment).
const HARDEN_HEADROOM: u64 = 4 << 20;

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
/// 3. No capability: the ambient set cleared, the others emptied when any is held, `no_new_privs` set.
/// 4. The seccomp filter that refuses `bind`, `listen`, `ptrace`, `process_vm_*` and `io_uring`, and
///    every x32 syscall number.
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
        // REQ: DSC-002 (ADR-988) — a limit below what the process already maps would make the next
        // allocation fail with a message that names nothing: say why instead, and don't start.
        if let Some(held) = crate::sys::vm_data_bytes()
            && held.saturating_add(HARDEN_HEADROOM) > data_bytes
        {
            return Err(io::Error::other(format!(
                "the process already maps {} MiB of data, too much for a {} MiB limit (start the \
                 worker with {}={}, as prepare_spawn does)",
                held >> 20,
                data_bytes >> 20,
                WORKER_ALLOCATOR_ENV.0,
                WORKER_ALLOCATOR_ENV.1,
            )));
        }
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

/// REQ: DSC-002 (ADR-908, ADR-934) — prepares a spawn of a discovery worker from this process. Three
/// things, all on the parent side:
///
/// 0. The child gets [`WORKER_ALLOCATOR_ENV`] (ADR-988).
/// 1. The child clears its ambient capability set before it execs (`sys::clear_ambient_before_exec`),
///    so a worker started by a unit that grants `CAP_NET_BIND_SERVICE` holds nothing.
/// 2. This process becomes not dumpable. A worker of the same uid could otherwise open
///    `/proc/<parent>/mem` (Yama ptrace scope 0 allows it for a dumpable parent) and read the DNS
///    process's memory. Not dumpable makes that open fail with `EACCES` for a worker without
///    `CAP_SYS_PTRACE`. The cost: this process's own core dumps and attach by a debugger are refused.
///
/// Call it before each spawn; both steps are idempotent. A no-op off Linux.
pub fn prepare_spawn(cmd: &mut std::process::Command) -> io::Result<()> {
    // REQ: DSC-002, API-007 (ADR-988) — after the caller's `env_clear`, the one variable a worker needs.
    cmd.env(WORKER_ALLOCATOR_ENV.0, WORKER_ALLOCATOR_ENV.1);
    #[cfg(target_os = "linux")]
    {
        crate::sys::clear_ambient_before_exec(cmd);
        // REQ: DSC-002 (ADR-934) — `/proc/self/io` is opened before the process becomes not dumpable.
        crate::sys::pin_self_io();
        crate::sys::set_dumpable(false)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cmd;
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

    /// REQ: DSC-002 (`dsc_002_prepare_spawn_sets_allocator_env`, ADR-988) — a prepared spawn
    /// carries the allocator variable, whatever else the caller cleared.
    #[test]
    fn dsc_002_prepare_spawn_sets_allocator_env() {
        let mut cmd = std::process::Command::new("true");
        cmd.env_clear();
        prepare_spawn(&mut cmd).expect("prepare");
        let got: Vec<_> = cmd.get_envs().collect();
        assert_eq!(
            got,
            [(
                std::ffi::OsStr::new(WORKER_ALLOCATOR_ENV.0),
                Some(std::ffi::OsStr::new(WORKER_ALLOCATOR_ENV.1))
            )]
        );
    }

    /// REQ: DSC-002 (`dsc_002_vm_data_is_readable`, ADR-988) — the address space the limit counts
    /// can be read, and is more than nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn dsc_002_vm_data_is_readable() {
        let held = crate::sys::vm_data_bytes().expect("VmData");
        assert!(held > 0);
    }

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

    /// Whether this process is root. The tests that need a worker with no capability run their child
    /// as uid 65534 when it is.
    #[cfg(target_os = "linux")]
    fn is_root() -> bool {
        // SAFETY: getuid takes no arguments and cannot fail.
        unsafe { libc::getuid() == 0 }
    }

    /// This test binary, run as the test `name` with `mode` in `TT_HARDEN_CHILD`, as uid 65534 when this
    /// process is root (a root child keeps every capability, and these tests need a worker with none).
    #[cfg(target_os = "linux")]
    fn child_test(name: &str, mode: &str) -> std::process::Command {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([name, "--exact", "--nocapture"])
            .env("TT_HARDEN_CHILD", mode);
        if is_root() {
            cmd.uid(65534).gid(65534);
        }
        cmd
    }

    /// The mode a child test runs in, from `TT_HARDEN_CHILD` (empty for the parent test).
    #[cfg(target_os = "linux")]
    fn child_mode() -> String {
        std::env::var("TT_HARDEN_CHILD").unwrap_or_default()
    }

    /// The `errno` of the last failed call, when there is one.
    #[cfg(target_os = "linux")]
    fn last_errno() -> Option<i32> {
        std::io::Error::last_os_error().raw_os_error()
    }

    /// A seccomp filter that kills the process on `nr` and allows everything else (test helper).
    #[cfg(target_os = "linux")]
    fn install_kill_on(nr: libc::c_long) {
        let k = u32::try_from(nr).unwrap();
        let mut prog = [
            libc::sock_filter {
                code: 0x20, // LD nr
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x15, // JEQ nr: the next instruction kills, else skip it
                jt: 0,
                jf: 1,
                k,
            },
            libc::sock_filter {
                code: 0x06, // RET KILL_PROCESS
                jt: 0,
                jf: 0,
                k: 0x8000_0000,
            },
            libc::sock_filter {
                code: 0x06, // RET ALLOW
                jt: 0,
                jf: 0,
                k: 0x7fff_0000,
            },
        ];
        let fprog = libc::sock_fprog {
            len: 4,
            filter: prog.as_mut_ptr(),
        };
        // SAFETY: no_new_privs takes no pointers; the filter program lives for the prctl call.
        unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            let rc = libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::c_ulong::from(libc::SECCOMP_MODE_FILTER),
                std::ptr::from_ref(&fprog) as libc::c_ulong,
                0,
                0,
            );
            assert_eq!(rc, 0, "the test filter installs");
        }
    }

    /// REQ: DSC-002 (ADR-934, `dsc_002_worker_refuses_x32_and_io_uring`) — the filter refuses the x32
    /// syscall range (`nr | 0x40000000`), which the native numbers don't match, and the `io_uring` calls
    /// that skip the filter's bind and listen check on newer kernels. Each returns EPERM before the
    /// kernel sees it. Run in a child, as the privilege test does.
    #[cfg(target_os = "linux")]
    #[test]
    fn dsc_002_worker_refuses_x32_and_io_uring() {
        if child_mode() == "x32" {
            harden(64 * 1024 * 1024).expect("harden");
            // SAFETY: the syscall is refused by the filter, so the kernel reads none of the arguments.
            let rc = unsafe { libc::syscall(0x4000_0000 + libc::SYS_bind, 0, 0, 0) };
            assert_eq!(rc, -1, "the x32 bind is refused");
            assert_eq!(last_errno(), Some(libc::EPERM), "x32 bind: EPERM");
            // SAFETY: as above, refused before the kernel reads the arguments.
            let rc = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1, 0) };
            assert_eq!(
                (rc, last_errno()),
                (-1, Some(libc::EPERM)),
                "io_uring_setup"
            );
            // SAFETY: as above.
            let rc = unsafe { libc::syscall(libc::SYS_io_uring_enter, 0, 0, 0, 0, 0, 0) };
            assert_eq!(
                (rc, last_errno()),
                (-1, Some(libc::EPERM)),
                "io_uring_enter"
            );
            // SAFETY: as above.
            let rc = unsafe { libc::syscall(libc::SYS_io_uring_register, 0, 0, 0, 0) };
            assert_eq!(
                (rc, last_errno()),
                (-1, Some(libc::EPERM)),
                "io_uring_register"
            );
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args([
                "worker::tests::dsc_002_worker_refuses_x32_and_io_uring",
                "--exact",
                "--nocapture",
            ])
            .env("TT_HARDEN_CHILD", "x32")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// REQ: DSC-002 (ADR-934, `dsc_002_worker_without_capabilities_never_calls_capset`) — a worker that
    /// holds no capability never calls `capset`, so a filter that kills it (systemd's `@privileged`
    /// group, under the unit) leaves it alive. The control calls `capset` under the same filter and
    /// must die with SIGSYS, which shows the filter is in place.
    #[cfg(target_os = "linux")]
    #[test]
    fn dsc_002_worker_without_capabilities_never_calls_capset() {
        use std::os::unix::process::ExitStatusExt;
        const NAME: &str = "worker::tests::dsc_002_worker_without_capabilities_never_calls_capset";
        match child_mode().as_str() {
            "capset-skip" => {
                install_kill_on(libc::SYS_capset);
                crate::sys::drop_worker_capabilities().expect("the drop succeeds");
                std::process::exit(0);
            }
            "capset-direct" => {
                install_kill_on(libc::SYS_capset);
                let hdr = [0u32, 0u32];
                // SAFETY: the filter kills the process before the kernel reads the header.
                unsafe { libc::syscall(libc::SYS_capset, hdr.as_ptr(), 0) };
                std::process::exit(7);
            }
            _ => {}
        }
        let skip = child_test(NAME, "capset-skip").output().unwrap();
        assert!(
            skip.status.success(),
            "a worker with no capability never calls capset: {}",
            String::from_utf8_lossy(&skip.stdout)
        );
        let direct = child_test(NAME, "capset-direct").output().unwrap();
        assert_eq!(
            direct.status.signal(),
            Some(libc::SIGSYS),
            "the control calls capset and is killed"
        );
    }

    /// REQ: DSC-002 (ADR-908, ADR-934, `dsc_002_worker_cannot_read_its_parent`) — once the parent has
    /// called [`prepare_spawn`], it is not dumpable, and a worker of the same uid can't open its
    /// `/proc/<pid>/mem`. The middle process (the parent) first makes itself dumpable in both modes:
    /// a process that changed uid at exec is already not dumpable (the kernel resets it), so without
    /// that step the shield would pass with `prepare_spawn` doing nothing. The flag check is the
    /// decisive one and holds under any Yama setting. The open check is the end-to-end one: under
    /// Yama scope 0 a dumpable parent can be read by its worker (the control), so a refusal then comes
    /// from `prepare_spawn`. Under scope 1 (the Ubuntu default, and this container) Yama refuses the
    /// open either way, so the control is skipped and only the flag check decides.
    #[cfg(target_os = "linux")]
    #[test]
    fn dsc_002_worker_cannot_read_its_parent() {
        const NAME: &str = "worker::tests::dsc_002_worker_cannot_read_its_parent";
        match child_mode().as_str() {
            "worker-mem" => {
                // SAFETY: getppid takes no arguments and cannot fail.
                let ppid = unsafe { libc::getppid() };
                let code = match std::fs::File::open(format!("/proc/{ppid}/mem")) {
                    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => 0,
                    Ok(_) => 3,
                    Err(_) => 4,
                };
                std::process::exit(code);
            }
            mode @ ("parent-shield" | "parent-plain") => {
                let mut worker = child_test(NAME, "worker-mem");
                // Dumpable first, in both modes (see the test's doc comment).
                crate::sys::set_dumpable(true).expect("make the parent dumpable");
                if mode == "parent-shield" {
                    prepare_spawn(&mut worker).expect("prepare the spawn");
                    // Exit 5 when the flag is still set: prepare_spawn didn't make us not dumpable.
                    if crate::sys::dumpable() {
                        std::process::exit(5);
                    }
                }
                let code = worker.status().unwrap().code().unwrap_or(9);
                std::process::exit(code);
            }
            _ => {}
        }
        let shield = child_test(NAME, "parent-shield").status().unwrap();
        assert_eq!(
            shield.code(),
            Some(0),
            "prepare_spawn makes the parent not dumpable, and its worker can't open the parent"
        );
        let scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .unwrap_or(0);
        if scope == 0 {
            let plain = child_test(NAME, "parent-plain").status().unwrap();
            assert_eq!(
                plain.code(),
                Some(3),
                "the control worker can open a dumpable parent, so the refusal is the spawn's"
            );
        } else {
            eprintln!(
                "control skipped: Yama ptrace scope {scope} refuses the worker's open either way; the not-dumpable check above is the proof"
            );
        }
    }

    /// REQ: DSC-002 (ADR-934, `dsc_002_spawn_clears_ambient_capabilities`) — a worker spawned after
    /// [`prepare_spawn`] starts with an empty ambient set, even when its parent raised one for the
    /// spawn (as `AmbientCapabilities=` in the unit does). The control shows the raise took. Raising
    /// the ambient set needs `CAP_SETPCAP`, so the test runs only as root and skips otherwise.
    #[cfg(target_os = "linux")]
    #[test]
    fn dsc_002_spawn_clears_ambient_capabilities() {
        use std::os::unix::process::CommandExt;
        const NAME: &str = "worker::tests::dsc_002_spawn_clears_ambient_capabilities";
        if child_mode() == "ambient" {
            let status = std::fs::read_to_string("/proc/thread-self/status").expect("status");
            let ambient = status
                .lines()
                .find(|l| l.starts_with("CapAmb:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("")
                .to_owned();
            std::process::exit(if ambient == "0000000000000000" { 0 } else { 5 });
        }
        if !is_root() {
            eprintln!("skipped: raising an ambient capability needs root");
            return;
        }
        let raised = |cmd: &mut std::process::Command| {
            // SAFETY: the closure runs in the forked child before exec; it calls capget, capset and
            // prctl only, with pointers to locals that live for each call, and allocates nothing.
            unsafe { cmd.pre_exec(raise_net_bind_ambient) };
        };
        let root_child = |mode: &str| {
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args([NAME, "--exact", "--nocapture"])
                .env("TT_HARDEN_CHILD", mode);
            cmd
        };
        let mut control = root_child("ambient");
        raised(&mut control);
        assert_eq!(
            control.status().unwrap().code(),
            Some(5),
            "the control worker inherits the raised ambient set"
        );
        let mut cleared = root_child("ambient");
        raised(&mut cleared);
        prepare_spawn(&mut cleared).expect("prepare the spawn");
        assert_eq!(
            cleared.status().unwrap().code(),
            Some(0),
            "a prepared spawn starts with no ambient capability"
        );
    }

    /// Raises `CAP_NET_BIND_SERVICE` in the calling thread's ambient set (test helper, run in a child
    /// before exec): it makes the capability inheritable, then raises it.
    #[cfg(target_os = "linux")]
    fn raise_net_bind_ambient() -> io::Result<()> {
        const CAP_NET_BIND_SERVICE: u32 = 10;
        #[repr(C)]
        struct Header {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let hdr = Header {
            version: 0x2008_0522,
            pid: 0,
        };
        let mut data = [Data::default(); 2];
        // SAFETY: capget reads the header and writes the two data words, both alive for the call.
        if unsafe { libc::syscall(libc::SYS_capget, &raw const hdr, data.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        data[0].inheritable |= 1 << CAP_NET_BIND_SERVICE;
        // SAFETY: capset reads the header and the two data words, both alive for the call.
        if unsafe { libc::syscall(libc::SYS_capset, &raw const hdr, data.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: PR_CAP_AMBIENT_RAISE takes the capability number and no pointers.
        if unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
                libc::c_ulong::from(CAP_NET_BIND_SERVICE),
                0,
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

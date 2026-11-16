//! REQ: OPS-012 (ADR-163, GitHub issue #7) — the stack of every thread of the process, taken by
//! the threads themselves, for the watchdog's dump of a node that stopped answering.
//!
//! [`capture`] sends each thread a signal (`tgkill`); the handler, running on that thread, walks
//! its own stack with the unwinder std already links and stores up to [`MAX_FRAMES`] return
//! addresses in a fixed table. Nothing in the handler allocates or takes a lock. The addresses
//! are raw: `addr2line -e telltale.debug` (ADR-164) turns them into functions and lines.
//!
//! It is only for a node that is stuck: a thread that doesn't answer within the wait is
//! reported as not answering, which says it is blocked in the kernel. A signal can interrupt a
//! system call, which the restart flag mostly hides; this runs once, as a last act before a
//! restart, or (with `action = "dump"`) once per stall.

use std::ffi::{c_int, c_void};
use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Threads a capture can hold; more are left out.
const MAX_THREADS: usize = 256;
/// Return addresses kept per thread.
pub const MAX_FRAMES: usize = 64;
/// The signal the handler listens on.
const SIGNAL: c_int = libc::SIGUSR2;

/// One thread's answer, written by its own handler.
struct Slot {
    /// The thread this slot is for (0: unused).
    tid: AtomicU32,
    done: AtomicBool,
    len: AtomicUsize,
    frames: [AtomicUsize; MAX_FRAMES],
}

impl Slot {
    const fn new() -> Self {
        Self {
            tid: AtomicU32::new(0),
            done: AtomicBool::new(false),
            len: AtomicUsize::new(0),
            frames: [const { AtomicUsize::new(0) }; MAX_FRAMES],
        }
    }
}

static SLOTS: [Slot; MAX_THREADS] = [const { Slot::new() }; MAX_THREADS];
/// One capture at a time: the table is shared.
static CAPTURING: AtomicBool = AtomicBool::new(false);
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// What the unwinder calls for each frame.
type Callback = extern "C" fn(*mut c_void, *mut c_void) -> c_int;

unsafe extern "C" {
    // The unwinder std links for its own backtraces (libgcc's, or LLVM's libunwind on the static
    // musl builds): the same two functions the `backtrace` crate calls.
    fn _Unwind_Backtrace(callback: Callback, arg: *mut c_void) -> c_int;
    fn _Unwind_GetIP(context: *mut c_void) -> usize;
}

/// `_URC_NO_REASON`: keep walking.
const URC_NO_REASON: c_int = 0;
/// `_URC_END_OF_STACK`: stop.
const URC_END_OF_STACK: c_int = 5;

/// The walk in progress on one thread.
struct Walk<'a> {
    slot: &'a Slot,
    n: usize,
}

extern "C" fn step(context: *mut c_void, arg: *mut c_void) -> c_int {
    // SAFETY: `arg` is the `Walk` that `on_signal` passed to `_Unwind_Backtrace`; it lives on that
    // handler's stack for the whole walk, and nothing else touches it.
    let walk = unsafe { &mut *arg.cast::<Walk<'_>>() };
    if walk.n >= MAX_FRAMES {
        return URC_END_OF_STACK;
    }
    // SAFETY: `context` is the unwinder's own context, valid until this callback returns.
    let ip = unsafe { _Unwind_GetIP(context) };
    walk.slot.frames[walk.n].store(ip, Ordering::Relaxed);
    walk.n += 1;
    URC_NO_REASON
}

/// Runs on the thread that was signalled.
extern "C" fn on_signal(_signal: c_int) {
    // SAFETY: `gettid` has no preconditions and is async-signal-safe.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    let Ok(tid) = u32::try_from(tid) else {
        return;
    };
    for slot in &SLOTS {
        if slot.tid.load(Ordering::Acquire) == tid && !slot.done.load(Ordering::Acquire) {
            let mut walk = Walk { slot, n: 0 };
            // SAFETY: `step` is an `extern "C"` callback with the unwinder's signature, and `arg`
            // points at `walk`, which outlives the call.
            unsafe { _Unwind_Backtrace(step, std::ptr::from_mut(&mut walk).cast()) };
            slot.len.store(walk.n, Ordering::Relaxed);
            slot.done.store(true, Ordering::Release);
            return;
        }
    }
}

/// Installs the handler (once). Without it a capture's signal would end the process, so
/// [`capture`] installs it too.
pub fn install() -> io::Result<()> {
    if INSTALLED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    // SAFETY: `sigaction` is zero-initialised as the C API expects, `on_signal` is an
    // `extern "C" fn(c_int)` that only uses atomics and the unwinder, and the mask is emptied
    // before the struct is passed in.
    let ok = unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_signal as extern "C" fn(c_int) as usize;
        // Restart interrupted system calls: the node usually keeps running after a dump.
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&raw mut action.sa_mask);
        libc::sigaction(SIGNAL, &raw const action, std::ptr::null_mut()) == 0
    };
    if ok {
        Ok(())
    } else {
        INSTALLED.store(false, Ordering::Release);
        Err(io::Error::last_os_error())
    }
}

/// One thread's stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadStack {
    pub tid: u32,
    pub name: String,
    /// Return addresses, the innermost call first. Empty when it didn't answer.
    pub frames: Vec<usize>,
    pub answered: bool,
}

/// The threads of this process (`/proc/self/task`) with their names.
fn threads() -> Vec<(u32, String)> {
    let Ok(dir) = fs::read_dir("/proc/self/task") else {
        return Vec::new();
    };
    let mut v: Vec<(u32, String)> = dir
        .flatten()
        .filter_map(|e| {
            let tid: u32 = e.file_name().to_str()?.parse().ok()?;
            let name = fs::read_to_string(e.path().join("comm"))
                .map(|n| n.trim().to_owned())
                .unwrap_or_default();
            Some((tid, name))
        })
        .collect();
    v.sort_unstable();
    v
}

/// Asks every other thread for its stack and waits up to `wait` for the answers.
///
/// The calling thread is left out (it is the watchdog). Only one capture runs at a time; a second
/// call while one runs returns nothing.
pub fn capture(wait: Duration) -> Vec<ThreadStack> {
    if install().is_err() || CAPTURING.swap(true, Ordering::AcqRel) {
        return Vec::new();
    }
    // SAFETY: `gettid` has no preconditions.
    let me = u32::try_from(unsafe { libc::syscall(libc::SYS_gettid) }).unwrap_or(0);
    let mut targets: Vec<(u32, String)> = threads()
        .into_iter()
        .filter(|(tid, _)| *tid != me)
        .take(MAX_THREADS)
        .collect();
    targets.sort_unstable();
    for (slot, (tid, _)) in SLOTS.iter().zip(&targets) {
        slot.len.store(0, Ordering::Relaxed);
        slot.done.store(false, Ordering::Release);
        slot.tid.store(*tid, Ordering::Release);
    }
    // SAFETY: `getpid` has no preconditions.
    let pid = unsafe { libc::getpid() };
    for (tid, _) in &targets {
        // SAFETY: `tgkill` takes plain integers; a thread that has exited just fails with ESRCH.
        unsafe { libc::syscall(libc::SYS_tgkill, pid, *tid, SIGNAL) };
    }
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline
        && SLOTS
            .iter()
            .zip(&targets)
            .any(|(slot, _)| !slot.done.load(Ordering::Acquire))
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    let out = SLOTS
        .iter()
        .zip(targets)
        .map(|(slot, (tid, name))| {
            let answered = slot.done.load(Ordering::Acquire);
            let n = slot.len.load(Ordering::Relaxed).min(MAX_FRAMES);
            let frames = if answered {
                slot.frames[..n]
                    .iter()
                    .map(|f| f.load(Ordering::Relaxed))
                    .collect()
            } else {
                Vec::new()
            };
            // Free the slot: a late answer from a stuck thread finds nothing to write to.
            slot.tid.store(0, Ordering::Release);
            ThreadStack {
                tid,
                name,
                frames,
                answered,
            }
        })
        .collect();
    CAPTURING.store(false, Ordering::Release);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, mpsc};

    /// The table is shared: one capture at a time.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        ONE_AT_A_TIME
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A thread blocks in here, so its stack holds an address inside this function.
    #[inline(never)]
    fn blocked_in_known_function(entered: &mpsc::Sender<()>, held: &mpsc::Receiver<()>) {
        let _ = entered.send(());
        let _ = held.recv();
        std::hint::black_box(());
    }

    /// REQ: OPS-012 — a blocked thread reports a stack that holds its own function; the ones that
    /// aren't blocked answer too; a second capture works after the first.
    #[test]
    fn ops_012_a_blocked_thread_reports_a_stack_through_its_own_function() {
        let _one = serial();
        let (entered_tx, entered) = mpsc::channel();
        let (release, held) = mpsc::channel();
        let blocked = std::thread::Builder::new()
            .name("stack-test".to_owned())
            .spawn(move || blocked_in_known_function(&entered_tx, &held))
            .unwrap();
        entered.recv_timeout(Duration::from_secs(2)).unwrap();

        let start =
            blocked_in_known_function as fn(&mpsc::Sender<()>, &mpsc::Receiver<()>) as usize;
        for round in 0..2 {
            let stacks = capture(Duration::from_secs(3));
            let mine = stacks
                .iter()
                .find(|s| s.name == "stack-test")
                .unwrap_or_else(|| {
                    panic!("round {round}: no stack for the test thread: {stacks:?}")
                });
            assert!(mine.answered, "round {round}");
            assert!(!mine.frames.is_empty(), "round {round}");
            assert!(
                mine.frames
                    .iter()
                    .any(|ip| (start..start + 4096).contains(ip)),
                "round {round}: no frame inside the function at {start:#x}: {:x?}",
                mine.frames
            );
            assert!(
                stacks.iter().all(|s| s.frames.len() <= MAX_FRAMES),
                "bounded"
            );
        }
        release.send(()).unwrap();
        blocked.join().unwrap();
    }

    #[test]
    fn ops_012_a_thread_that_cannot_answer_is_reported_as_silent() {
        let _one = serial();
        // A thread with the signal blocked never runs the handler, as one stuck in the kernel
        // would not.
        let (up_tx, up) = mpsc::channel();
        let (release, held) = mpsc::channel::<()>();
        let deaf = std::thread::Builder::new()
            .name("deaf-test".to_owned())
            .spawn(move || {
                // SAFETY: the set is initialised by `sigemptyset` before use, and blocking a signal
                // on the current thread has no other precondition.
                unsafe {
                    let mut set: libc::sigset_t = std::mem::zeroed();
                    libc::sigemptyset(&raw mut set);
                    libc::sigaddset(&raw mut set, SIGNAL);
                    libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
                }
                let _ = up_tx.send(());
                let _ = held.recv();
            })
            .unwrap();
        up.recv_timeout(Duration::from_secs(2)).unwrap();
        let stacks = capture(Duration::from_millis(300));
        let silent = stacks.iter().find(|s| s.name == "deaf-test").unwrap();
        assert!(!silent.answered);
        assert_eq!(silent.frames.len(), 0);
        release.send(()).unwrap();
        deaf.join().unwrap();
    }
}

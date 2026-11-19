//! REQ: DSC-906 (T31.2, ADR-1005 section 3) - the sink: a bounded queue of source batches that
//! drops the oldest when full and counts it (`wrendns_cmdb_dropped_total{kind="batch"}`), so a slow
//! CMDB can never hold up a poller or the inventory. A feed pushes and moves on; the CMDB's thread
//! takes what is there. Commands from the API (a manual change) come through the same queue, so
//! they run between batches on the one thread that writes (CLU-004: nothing here is on the DNS path).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

use arc_swap::ArcSwap;
use std::sync::Arc;

use super::manual::{ManualError, ManualOp, Outcome};
use super::model::{SINK_BATCHES, SourceBatch};

/// A command for the CMDB's thread.
pub(crate) enum Cmd {
    /// Read the in-process feeds now (the configuration changed): the next tick is not a minute away.
    Tick,
    /// A manual link, unlink, merge or split (or its dry run).
    Manual {
        op: ManualOp,
        by: String,
        reason: String,
        dry_run: bool,
        reply: tokio::sync::oneshot::Sender<Result<Outcome, ManualError>>,
    },
}

#[derive(Default)]
struct Inner {
    batches: VecDeque<SourceBatch>,
    cmds: VecDeque<Cmd>,
    stop: bool,
}

/// The queue.
#[derive(Default)]
pub(crate) struct Inbox {
    inner: Mutex<Inner>,
    cv: Condvar,
    dropped: AtomicU64,
}

impl std::fmt::Debug for Inbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cmdb::Inbox")
    }
}

/// What the thread took from the queue.
pub(crate) struct Taken {
    pub(crate) batches: Vec<SourceBatch>,
    pub(crate) cmds: Vec<Cmd>,
    pub(crate) stop: bool,
}

impl Inbox {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues a batch; the oldest is dropped (and counted) when the queue is full.
    pub(crate) fn push(&self, b: SourceBatch) {
        let mut g = self.lock();
        while g.batches.len() >= SINK_BATCHES {
            g.batches.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        g.batches.push_back(b);
        drop(g);
        self.cv.notify_one();
    }

    /// Queues a command.
    pub(crate) fn command(&self, c: Cmd) {
        self.lock().cmds.push_back(c);
        self.cv.notify_one();
    }

    /// Asks the thread to stop.
    pub(crate) fn stop(&self) {
        self.lock().stop = true;
        self.cv.notify_all();
    }

    /// Batches waiting.
    pub(crate) fn depth(&self) -> usize {
        self.lock().batches.len()
    }

    /// Batches dropped because the queue was full.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Waits up to `wait` for something to do, then takes everything.
    pub(crate) fn take(&self, wait: Duration) -> Taken {
        let mut g = self.lock();
        if g.batches.is_empty() && g.cmds.is_empty() && !g.stop {
            g = self
                .cv
                .wait_timeout(g, wait)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        Taken {
            batches: g.batches.drain(..).collect(),
            cmds: g.cmds.drain(..).collect(),
            stop: g.stop,
        }
    }
}

/// Where other feeds find the CMDB's queue: the slot is filled while the CMDB runs on this node and
/// empty otherwise, so a feed pushes without knowing whether anyone listens.
#[derive(Debug, Default)]
pub(crate) struct SinkSlot(ArcSwap<Option<Arc<Inbox>>>);

impl SinkSlot {
    pub(crate) fn set(&self, inbox: Option<Arc<Inbox>>) {
        self.0.store(Arc::new(inbox));
    }

    pub(crate) fn get(&self) -> Option<Arc<Inbox>> {
        (**self.0.load()).clone()
    }

    /// Pushes a batch when the CMDB runs here. A feed's call, off the DNS path.
    pub(crate) fn push(&self, b: SourceBatch) {
        if let Some(i) = self.get() {
            i.push(b);
        }
    }

    /// Whether the CMDB runs here (a feed can skip building a batch nobody takes).
    pub(crate) fn listening(&self) -> bool {
        self.get().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(n: i64) -> SourceBatch {
        SourceBatch {
            source: "neighbor".into(),
            complete: true,
            records: Vec::new(),
            at: n,
        }
    }

    /// REQ: DSC-906 - a full sink drops its oldest batch and counts it; nothing blocks.
    #[test]
    fn dsc_906_full_sink_drops_the_oldest_and_counts() {
        let i = Inbox::default();
        for n in 0..i64::try_from(SINK_BATCHES + 5).unwrap() {
            i.push(b(n));
        }
        assert_eq!(i.depth(), SINK_BATCHES);
        assert_eq!(i.dropped(), 5);
        let t = i.take(Duration::from_millis(1));
        assert_eq!(t.batches.first().map(|x| x.at), Some(5), "the oldest went");
        assert_eq!(i.depth(), 0);
    }

    /// REQ: DSC-906 - an empty slot takes nothing, and a feed pushing into it is a no-op.
    #[test]
    fn dsc_906_an_empty_slot_is_a_no_op() {
        let s = SinkSlot::default();
        assert!(!s.listening());
        s.push(b(1));
        let inbox = Arc::new(Inbox::default());
        s.set(Some(Arc::clone(&inbox)));
        s.push(b(2));
        assert_eq!(inbox.depth(), 1);
        s.set(None);
        s.push(b(3));
        assert_eq!(inbox.depth(), 1);
    }
}

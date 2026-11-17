//! REQ: DSC-003, DSC-004 — the bounded walker (ADR-908). A table is read with GETBULK, one
//! request after another, with three caps: rows (5,000), time (30 s per walk) and pacing (a gap
//! of at least 50 ms between requests, so at most 20 requests a second). A walk ends at the
//! first varbind outside the subtree, at an endOfMibView, or at a cap. A walk whose OIDs do not
//! increase is an error, so a misbehaving agent cannot loop the client.
//!
//! The walker takes its agent and its clock through traits, so the caps are tested without a
//! network or a sleep (`dsc_003_walk_caps`).

use std::thread;
use std::time::{Duration, Instant};

use crate::agent::{Agent, AgentError};
use crate::oid::Oid;
use crate::pdu::{RequestKind, Response, Value, VarBind};

/// The most rows one walk returns (DSC-004: 5,000 rows per table).
pub const MAX_ROWS: usize = 5_000;
/// The most time one walk may take, measured before each request (DSC-004: a 30 s walk cap).
pub const WALK_TIME_CAP: Duration = Duration::from_secs(30);
/// The least gap between two requests (DSC-004: at least 50 ms, so at most 20 requests a second).
pub const MIN_GAP: Duration = Duration::from_millis(50);
/// The max-repetitions of each GETBULK.
pub const MAX_REPETITIONS: u32 = 20;

/// One GETBULK exchange. `Agent` implements it; tests and the fuzz target implement it too.
pub trait Bulk {
    fn bulk(&mut self, oid: &Oid, max_repetitions: u32) -> Result<Response, AgentError>;
}

impl Bulk for Agent {
    fn bulk(&mut self, oid: &Oid, max_repetitions: u32) -> Result<Response, AgentError> {
        self.request(RequestKind::GetBulk, std::slice::from_ref(oid), max_repetitions)
    }
}

/// The clock and the pause. The system pacer sleeps; tests advance a virtual clock.
pub trait Pacer {
    fn now(&self) -> Instant;
    fn pause(&mut self, d: Duration);
}

/// The pacer for a real walk.
#[derive(Debug, Default)]
pub struct SystemPacer;

impl Pacer for SystemPacer {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn pause(&mut self, d: Duration) {
        thread::sleep(d);
    }
}

/// The caps of one walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_rows: usize,
    pub max_time: Duration,
    /// The gap between requests. Never less than `MIN_GAP`.
    pub gap: Duration,
    pub max_repetitions: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rows: MAX_ROWS,
            max_time: WALK_TIME_CAP,
            gap: MIN_GAP,
            max_repetitions: MAX_REPETITIONS,
        }
    }
}

/// Why a walk ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// The walk left its subtree, or the agent sent endOfMibView.
    EndOfView,
    /// The row cap was reached and another row was waiting.
    RowCap,
    /// The time cap was reached before the next request.
    TimeCap,
}

/// What a walk read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walked {
    pub rows: Vec<VarBind>,
    pub stop: Stop,
    pub requests: u32,
}

/// Why a walk failed. Neither variant carries a secret or an input byte.
#[derive(Debug)]
pub enum WalkError {
    Agent(AgentError),
    /// The agent returned an OID that is not after the one asked for: the walk would not end.
    NotIncreasing,
}

impl From<AgentError> for WalkError {
    fn from(e: AgentError) -> Self {
        Self::Agent(e)
    }
}

/// Walks the subtree under `root`, within `limits`.
pub fn walk<B: Bulk, P: Pacer>(agent: &mut B, pacer: &mut P, root: &Oid, limits: &Limits) -> Result<Walked, WalkError> {
    let gap = limits.gap.max(MIN_GAP);
    let start = pacer.now();
    let mut rows: Vec<VarBind> = Vec::new();
    let mut last = root.clone();
    let mut requests: u32 = 0;
    loop {
        if requests > 0 {
            pacer.pause(gap);
        }
        if pacer.now().saturating_duration_since(start) >= limits.max_time {
            return Ok(Walked { rows, stop: Stop::TimeCap, requests });
        }
        let resp = agent.bulk(&last, limits.max_repetitions)?;
        requests = requests.saturating_add(1);
        if resp.varbinds.is_empty() {
            return Ok(Walked { rows, stop: Stop::EndOfView, requests });
        }
        for vb in resp.varbinds {
            if !vb.oid.starts_with(root) || matches!(vb.value, Value::EndOfMibView) {
                return Ok(Walked { rows, stop: Stop::EndOfView, requests });
            }
            if vb.oid <= last {
                return Err(WalkError::NotIncreasing);
            }
            if rows.len() >= limits.max_rows {
                return Ok(Walked { rows, stop: Stop::RowCap, requests });
            }
            last = vb.oid.clone();
            rows.push(vb);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::TAG_RESPONSE;

    /// Answers GETBULK from a sorted table, or from an endless generator under `root`.
    struct FakeBulk {
        table: Vec<Oid>,
        endless: Option<Oid>,
        next_endless: u32,
        calls: u32,
    }

    impl FakeBulk {
        fn table(rows: Vec<Oid>) -> Self {
            Self { table: rows, endless: None, next_endless: 0, calls: 0 }
        }

        fn endless(root: Oid) -> Self {
            Self { table: Vec::new(), endless: Some(root), next_endless: 0, calls: 0 }
        }
    }

    impl Bulk for FakeBulk {
        fn bulk(&mut self, oid: &Oid, max_repetitions: u32) -> Result<Response, AgentError> {
            self.calls = self.calls.saturating_add(1);
            let mut varbinds = Vec::new();
            if let Some(root) = &self.endless {
                for _ in 0..max_repetitions {
                    self.next_endless = self.next_endless.saturating_add(1);
                    let Some(o) = root.child(self.next_endless) else { break };
                    varbinds.push(VarBind { oid: o, value: Value::Integer(i64::from(self.next_endless)) });
                }
            } else {
                for o in self.table.iter().filter(|o| *o > oid).take(max_repetitions as usize) {
                    varbinds.push(VarBind { oid: o.clone(), value: Value::Integer(1) });
                }
                if let (true, Some(end)) = (varbinds.is_empty(), Oid::parse("1.3.6.1.6")) {
                    varbinds.push(VarBind { oid: end, value: Value::EndOfMibView });
                }
            }
            Ok(Response { tag: TAG_RESPONSE, request_id: 1, error_status: 0, error_index: 0, varbinds })
        }
    }

    /// A virtual clock: a pause moves it, nothing else does.
    struct FakePacer {
        t: Instant,
        pauses: u32,
        total: Duration,
    }

    impl FakePacer {
        fn new() -> Self {
            Self { t: Instant::now(), pauses: 0, total: Duration::ZERO }
        }
    }

    impl Pacer for FakePacer {
        fn now(&self) -> Instant {
            self.t
        }

        fn pause(&mut self, d: Duration) {
            self.pauses = self.pauses.saturating_add(1);
            self.total = self.total.saturating_add(d);
            self.t = self.t.checked_add(d).unwrap_or(self.t);
        }
    }

    fn oid(s: &str) -> Oid {
        Oid::parse(s).unwrap_or_else(|| panic!("oid {s}"))
    }

    #[test]
    fn dsc_003_walk_caps() {
        let root = oid("1.3.6.1.2.1.4.35");
        // Row cap: 12,000 rows under the root, but the walk stops at 5,000.
        let rows: Vec<Oid> = (1..=12_000u32).filter_map(|i| root.child(i)).collect();
        let mut agent = FakeBulk::table(rows);
        let mut pacer = FakePacer::new();
        let got = walk(&mut agent, &mut pacer, &root, &Limits::default());
        let got = got.unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(got.stop, Stop::RowCap);
        assert_eq!(got.rows.len(), MAX_ROWS);

        // Time cap: an endless table; the walk stops once 30 s have passed, and the gap holds.
        let mut agent = FakeBulk::endless(root.clone());
        let mut pacer = FakePacer::new();
        let unlimited_rows = Limits { max_rows: usize::MAX, ..Limits::default() };
        let got = walk(&mut agent, &mut pacer, &root, &unlimited_rows).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(got.stop, Stop::TimeCap);
        assert!(pacer.total >= WALK_TIME_CAP, "walk stopped before the cap");
        // At 50 ms a gap, 30 s allows 600 pauses; the request count never exceeds that plus one.
        assert!(got.requests <= 601, "requests {} over the pacing budget", got.requests);
        // One pause runs before every request but the first, and before the cap check.
        assert!(pacer.pauses >= got.requests.saturating_sub(1), "pauses {} for {} requests", pacer.pauses, got.requests);

        // Pacing: a gap below 50 ms is raised to 50 ms.
        let mut agent = FakeBulk::endless(root.clone());
        let mut pacer = FakePacer::new();
        let limits = Limits { gap: Duration::from_millis(1), max_time: Duration::from_secs(1), ..Limits::default() };
        let _ = walk(&mut agent, &mut pacer, &root, &limits);
        assert!(pacer.pauses > 0);
        assert_eq!(pacer.total, MIN_GAP.saturating_mul(pacer.pauses), "every gap is raised to the floor");
    }

    #[test]
    fn dsc_003_walk_ends_at_the_subtree_edge() {
        let root = oid("1.3.6.1.2.1.1");
        let mut rows: Vec<Oid> = (1..=3u32).filter_map(|i| root.child(i)).collect();
        rows.push(oid("1.3.6.1.2.1.2.1"));
        let mut agent = FakeBulk::table(rows);
        let mut pacer = FakePacer::new();
        let got = walk(&mut agent, &mut pacer, &root, &Limits::default()).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(got.stop, Stop::EndOfView);
        assert_eq!(got.rows.len(), 3);
    }

    #[test]
    fn dsc_003_walk_refuses_a_loop() {
        // An agent that answers the same OID again would never end the walk.
        struct Stuck(Oid);
        impl Bulk for Stuck {
            fn bulk(&mut self, _oid: &Oid, _n: u32) -> Result<Response, AgentError> {
                Ok(Response { tag: TAG_RESPONSE, request_id: 1, error_status: 0, error_index: 0, varbinds: vec![VarBind { oid: self.0.clone(), value: Value::Null }] })
            }
        }
        let root = oid("1.3.6.1.2.1.1");
        let mut agent = Stuck(oid("1.3.6.1.2.1.1.1.0"));
        let mut pacer = FakePacer::new();
        // The first row is after the root; the second answer is the same OID.
        let got = walk(&mut agent, &mut pacer, &root, &Limits::default());
        assert!(matches!(got, Err(WalkError::NotIncreasing)));
    }
}

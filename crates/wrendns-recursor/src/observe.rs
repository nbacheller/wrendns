// SPDX-License-Identifier: AGPL-3.0-or-later
//! Seeing the recursor (REQ: DNS-904, OBS-005, OBS-007, FLT-013): counters of what the
//! authoritative servers did, the exchanges an observer (dnstap's `RESOLVER_QUERY` and
//! `RESOLVER_RESPONSE`) is shown, and the lookup trace.
//!
//! The counters are relaxed atomics (no lock, no allocation); the trace is built only when a
//! lookup is asked for it; the observer costs one `OnceLock` load while none is set.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use crate::msg::Outcome;

/// One exchange with an authoritative server, as an observer sees it.
#[derive(Debug)]
pub struct Exchange<'a> {
    /// The server asked.
    pub server: SocketAddr,
    /// Over TCP (else UDP).
    pub tcp: bool,
    /// The query exactly as sent.
    pub query: &'a [u8],
    /// The response, if a usable one came.
    pub response: Option<&'a [u8]>,
    /// When the query was sent.
    pub sent: SystemTime,
}

type TapFn = dyn Fn(&Exchange<'_>) + Send + Sync;

/// What is shown every exchange (dnstap's resolver messages).
#[derive(Clone)]
pub struct ExchangeTap(Arc<TapFn>);

impl ExchangeTap {
    pub fn new(f: impl Fn(&Exchange<'_>) + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    pub(crate) fn show(&self, e: &Exchange<'_>) {
        (self.0)(e);
    }
}

impl std::fmt::Debug for ExchangeTap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExchangeTap")
    }
}

static GLOBAL: OnceLock<ExchangeTap> = OnceLock::new();

/// Sets the observer every `recursive://` upstream shows its exchanges to (once, at startup).
pub fn set_exchange_observer(tap: ExchangeTap) {
    let _ = GLOBAL.set(tap);
}

pub(crate) fn global_tap() -> Option<&'static ExchangeTap> {
    GLOBAL.get()
}

/// What the servers did, counted since start. No server is a label: the counters are totals.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    answer: AtomicU64,
    referral: AtomicU64,
    nodata: AtomicU64,
    nxdomain: AtomicU64,
    lame: AtomicU64,
    timeout: AtomicU64,
    error: AtomicU64,
    case_mismatch: AtomicU64,
    unwanted: AtomicU64,
}

/// The counters at one moment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Queries answered with records.
    pub answer: u64,
    /// Queries answered with a delegation.
    pub referral: u64,
    /// Queries answered NOERROR without the type.
    pub nodata: u64,
    /// Queries answered NXDOMAIN.
    pub nxdomain: u64,
    /// Answers that could not be used (REFUSED, FORMERR, unreadable, a referral to nowhere).
    pub lame: u64,
    /// Queries that went unanswered in time.
    pub timeout: u64,
    /// Queries that failed without a reply (no route, connection refused).
    pub error: u64,
    /// Replies whose letter case came back changed (0x20).
    pub case_mismatch: u64,
    /// Replies with the wrong ID or question that were ignored (stray or spoofed).
    pub unwanted: u64,
    /// Zone cuts cached right now (a gauge).
    pub zone_cuts: u64,
}

impl StatsSnapshot {
    /// The sum of two snapshots (one per `recursive://` upstream).
    #[must_use]
    pub fn plus(self, o: Self) -> Self {
        Self {
            answer: self.answer + o.answer,
            referral: self.referral + o.referral,
            nodata: self.nodata + o.nodata,
            nxdomain: self.nxdomain + o.nxdomain,
            lame: self.lame + o.lame,
            timeout: self.timeout + o.timeout,
            error: self.error + o.error,
            case_mismatch: self.case_mismatch + o.case_mismatch,
            unwanted: self.unwanted + o.unwanted,
            zone_cuts: self.zone_cuts + o.zone_cuts,
        }
    }
}

impl Stats {
    pub(crate) fn outcome(&self, o: &Outcome) {
        let c = match o {
            Outcome::Answer { .. } => &self.answer,
            Outcome::Referral { .. } => &self.referral,
            Outcome::NoData { .. } => &self.nodata,
            Outcome::NxDomain { .. } => &self.nxdomain,
            Outcome::Lame => &self.lame,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn timeout(&self) {
        self.timeout.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn error(&self) {
        self.error.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn lame(&self) {
        self.lame.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn case_mismatch(&self) {
        self.case_mismatch.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn unwanted(&self) {
        self.unwanted.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self, zone_cuts: usize) -> StatsSnapshot {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        StatsSnapshot {
            answer: g(&self.answer),
            referral: g(&self.referral),
            nodata: g(&self.nodata),
            nxdomain: g(&self.nxdomain),
            lame: g(&self.lame),
            timeout: g(&self.timeout),
            error: g(&self.error),
            case_mismatch: g(&self.case_mismatch),
            unwanted: g(&self.unwanted),
            zone_cuts: zone_cuts as u64,
        }
    }
}

/// Steps kept in one trace (a lookup is limited to 96 queries; nested lookups share them).
pub(crate) const MAX_STEPS: usize = 128;

/// One line of a lookup trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceStep {
    /// `start` (where the lookup began) or `query` (one query to one server).
    pub kind: &'static str,
    /// The zone whose servers were asked (`start`: the zone the lookup began at).
    pub zone: String,
    /// The server asked (none for `start`).
    pub server: Option<IpAddr>,
    /// The name asked (minimized while the name is cut down) and its type.
    pub qname: String,
    pub qtype: u16,
    /// `referral`, `answer`, `nodata`, `nxdomain`, `lame`, `timeout`, `error`, `case-mismatch`,
    /// or for `start` where it began: `cache`, `stub` or `root`.
    pub outcome: &'static str,
    /// The delegated zone of a referral, the CNAME target of an answer, else empty.
    pub detail: String,
    /// `udp` or `tcp` (empty for `start`).
    pub transport: &'static str,
    /// Time spent, in microseconds.
    pub micros: u64,
}

/// The steps of one lookup, shared with the queries in flight.
pub(crate) type TraceLog = Arc<parking_lot::Mutex<Vec<TraceStep>>>;

pub(crate) fn push(log: Option<&TraceLog>, step: TraceStep) {
    if let Some(l) = log {
        let mut l = l.lock();
        if l.len() < MAX_STEPS {
            l.push(step);
        }
    }
}

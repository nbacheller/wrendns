// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-902, OBS-020 (T27.14b; `docs/design/listener-editor.md` section 2.4, owner decision of
//! 2026-11-26) — the evidence from other hosts: how many distinct clients, other than the node
//! itself, sent a query to a socket staged for a confirmation window.
//!
//! A staged socket is bound with [`Observed`], a thin wrapper around the shared handler. On the
//! steady path it does one relaxed load of an "observe" flag. While the flag is set it adds the
//! peer to a table of at most [`MAX_PEERS`] entries (IPv6 by /64; the node's own addresses and
//! loopback left out). The table is read by the pending-change read and dropped when the window
//! ends; an adopted socket keeps the wrapper with the flag cleared. The evidence is shown and never
//! required: the proof is the node's own test query.

use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use wrendns_net::{QueryHandler, RequestMeta, Response};

use crate::pipeline::Handler;

/// The most distinct peers one socket remembers.
pub(crate) const MAX_PEERS: usize = 64;

/// The peers that queried one staged socket during a window.
#[derive(Debug)]
pub(crate) struct Evidence {
    observe: AtomicBool,
    /// The node's own addresses, read when the socket was staged.
    own: Vec<IpAddr>,
    peers: Mutex<Vec<IpAddr>>,
}

impl Evidence {
    /// A table that observes from now on. `own` are the node's own addresses (loopback is always
    /// left out).
    pub(crate) fn new(own: Vec<IpAddr>) -> Arc<Self> {
        Arc::new(Self {
            observe: AtomicBool::new(true),
            own,
            peers: Mutex::new(Vec::new()),
        })
    }

    /// The node's own addresses now (empty when the interface list cannot be read, which leaves
    /// only loopback out).
    pub(crate) fn node_addresses() -> Vec<IpAddr> {
        wrendns_net::local_addrs()
            .map(|l| l.iter().map(|a| a.ip.to_canonical()).collect())
            .unwrap_or_default()
    }

    /// The key a peer is counted under: an IPv6 address by its /64.
    fn key(ip: IpAddr) -> IpAddr {
        match ip.to_canonical() {
            IpAddr::V6(v6) => {
                let mut o = v6.octets();
                o[8..].fill(0);
                IpAddr::V6(Ipv6Addr::from(o))
            }
            IpAddr::V4(v4) => IpAddr::V4(v4),
        }
    }

    fn is_own(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        ip.is_loopback() || ip.is_unspecified() || self.own.contains(&ip)
    }

    /// Counts a query from `ip` when observing. Called on the hot path: one relaxed load when off.
    #[inline]
    pub(crate) fn note(&self, ip: IpAddr) {
        if !self.observe.load(Ordering::Relaxed) || self.is_own(ip) {
            return;
        }
        let key = Self::key(ip);
        let mut p = self.peers.lock().unwrap_or_else(PoisonError::into_inner);
        if p.len() < MAX_PEERS && !p.contains(&key) {
            p.push(key);
        }
    }

    /// Distinct other hosts seen so far (at most [`MAX_PEERS`]).
    pub(crate) fn others(&self) -> u32 {
        let n = self
            .peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// Stops observing and drops the table (the window ended).
    pub(crate) fn stop(&self) {
        self.observe.store(false, Ordering::Relaxed);
        self.peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

/// The shared handler with the evidence counter in front of it.
pub(crate) struct Observed {
    inner: Arc<Handler>,
    evidence: Arc<Evidence>,
}

impl Observed {
    pub(crate) const fn new(inner: Arc<Handler>, evidence: Arc<Evidence>) -> Self {
        Self { inner, evidence }
    }
}

impl QueryHandler for Observed {
    fn handle(&self, req: &[u8], meta: &RequestMeta, out: &mut [u8]) -> Response {
        self.evidence.note(meta.peer.ip());
        self.inner.handle(req, meta, out)
    }

    fn admit(&self, meta: &RequestMeta) -> bool {
        self.inner.admit(meta)
    }

    fn sent(&self) {
        self.inner.sent();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn api_902_evidence_leaves_out_the_node_itself() {
        let e = Evidence::new(vec![ip("192.0.2.1")]);
        e.note(ip("127.0.0.1"));
        e.note(ip("::1"));
        e.note(ip("192.0.2.1"));
        assert_eq!(e.others(), 0);
        e.note(ip("192.0.2.9"));
        e.note(ip("192.0.2.9"));
        assert_eq!(e.others(), 1);
    }

    #[test]
    fn api_902_evidence_counts_ipv6_by_64_and_stops_at_64() {
        let e = Evidence::new(Vec::new());
        e.note(ip("2001:db8:1:2::1"));
        e.note(ip("2001:db8:1:2::ffff"));
        assert_eq!(e.others(), 1);
        for i in 0..200u32 {
            e.note(ip(&format!("198.51.100.{}", i % 250)));
        }
        assert_eq!(e.others(), 64);
    }

    #[test]
    fn api_902_evidence_stop_clears_and_ignores_later_queries() {
        let e = Evidence::new(Vec::new());
        e.note(ip("192.0.2.9"));
        e.stop();
        assert_eq!(e.others(), 0);
        e.note(ip("192.0.2.10"));
        assert_eq!(e.others(), 0);
    }
}

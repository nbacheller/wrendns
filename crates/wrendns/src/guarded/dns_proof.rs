// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-902, OBS-020 (T27.14b; ADR-956 section 3, ADR-107, ADR-1090 point 4;
//! `docs/design/listener-editor.md` section 2.2) — the DNS probe proof of a window change.
//!
//! A change that binds a DNS socket is proved by the node's own test query, not by a request that
//! arrived on the new socket: the probe client of ADR-107 asks `probe.wrendns.invalid` (A) over the
//! listener's own protocol, at the address a client reaches it on (`probes::reachable`). It runs
//! right after the bind, every [`EVERY`] while the window is open (so the confirm step shows a live
//! result) and once more inside the confirm. On a gated listener the gate's own refusal is the
//! answer (HTTP 404 on DoH and DoH3, REFUSED with extended error 18 on DoT and DoQ): it also shows
//! the gate is on, the state the preview promised.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::task::JoinHandle;
use wrendns_config::{ListenProto, Listener};

use super::host::Host;
use crate::server::{Evidence, StagedListener};

/// How often a probe runs while the window is open.
pub(crate) const EVERY: Duration = Duration::from_secs(5);
/// How long one probe waits for an answer.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(3);

/// What a probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A well-formed DNS answer (a REFUSED from the allowed networks counts, ADR-107).
    Answered,
    /// The gate's refusal on a gated listener: the answer that proves the gate is on.
    RefusedByGate,
    /// Nothing usable came back.
    NoAnswer,
}

impl Kind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::RefusedByGate => "refused_by_gate",
            Self::NoAnswer => "no_answer",
        }
    }
}

/// One socket the node asks itself: protocol, address to ask, path, whether the gate's refusal is
/// the expected answer, and what other hosts sent to it.
#[derive(Debug, Clone)]
pub(crate) struct DnsProbe {
    pub(crate) proto: ListenProto,
    /// The address a client reaches the socket on (a wildcard is asked on loopback).
    pub(crate) addr: SocketAddr,
    /// The DoH and DoH3 path.
    pub(crate) path: Option<String>,
    /// The listener is gated: its refusal is the answer.
    pub(crate) gated: bool,
    /// The evidence counter of the staged socket, when the probe is for one.
    pub(crate) evidence: Option<Arc<Evidence>>,
}

impl DnsProbe {
    /// `proto://addr`, as the listener is named in a message.
    pub(crate) fn listener(&self) -> String {
        let p = match self.proto {
            ListenProto::Udp => "udp",
            ListenProto::Tcp => "tcp",
            ListenProto::Dot => "dot",
            ListenProto::Doh => "doh",
            ListenProto::Doh3 => "doh3",
            ListenProto::Doq => "doq",
        };
        format!("{p}://{}", self.addr)
    }

    /// The URL the probe client connects to (its scheme syntax).
    pub(crate) fn url(&self) -> String {
        let scheme = match self.proto {
            ListenProto::Udp => "udp",
            ListenProto::Tcp => "tcp",
            ListenProto::Dot => "tls",
            ListenProto::Doh => "https",
            ListenProto::Doh3 => "h3",
            ListenProto::Doq => "quic",
        };
        let path = match self.proto {
            ListenProto::Doh | ListenProto::Doh3 => {
                self.path.as_deref().unwrap_or("/dns-query").to_owned()
            }
            _ => String::new(),
        };
        format!("{scheme}://{}{path}", self.addr)
    }
}

/// The probes for what stage bound: one per staged socket, each with the gate its listener was
/// bound with and the path it serves. `list` is the new listener list and `host` the facts the
/// stage used.
pub(crate) fn probes_for(
    staged: &[StagedListener],
    list: &[Listener],
    host: wrendns_config::HostFacts,
) -> Vec<DnsProbe> {
    staged
        .iter()
        .map(|s| {
            let l = list.iter().find(|l| l.proto == s.proto && l.addr == s.addr);
            DnsProbe {
                proto: s.proto,
                addr: crate::probes::reachable(s.bound),
                path: l.and_then(served_path),
                gated: l.is_some_and(|l| l.proto.needs_tls() && l.gated(host)),
                evidence: Some(Arc::clone(&s.evidence)),
            }
        })
        .collect()
}

/// The path as the bound server serves it: no trailing slash.
fn served_path(l: &Listener) -> Option<String> {
    l.path
        .as_ref()
        .map(|p| p.as_str().trim_end_matches('/').to_owned())
        .filter(|p| !p.is_empty())
}

/// REQ: API-902 (T27.14c, design 2.2 "removal-only changes") — the probe of a listener that stays:
/// nothing new is bound, so the proof is that what remains still answers. No evidence counter.
pub(crate) fn probe_of_kept(l: &Listener, host: wrendns_config::HostFacts) -> DnsProbe {
    DnsProbe {
        proto: l.proto,
        addr: crate::probes::reachable(l.addr),
        path: served_path(l),
        gated: l.proto.needs_tls() && l.gated(host),
        evidence: None,
    }
}

/// The last result of one probe.
#[derive(Debug, Clone)]
pub(crate) struct Last {
    pub(crate) kind: Kind,
    /// Why it got no answer.
    pub(crate) error: Option<String>,
    /// Unix seconds.
    pub(crate) at: u64,
}

/// The probes of one pending change, and what each last found. Shared by the probe loop, the confirm
/// and the pending read.
pub(crate) struct ProbeSet {
    entries: Vec<(DnsProbe, Mutex<Option<Last>>)>,
    now: fn() -> u64,
}

impl ProbeSet {
    pub(crate) fn new(probes: Vec<DnsProbe>, now: fn() -> u64) -> Self {
        Self {
            entries: probes.into_iter().map(|p| (p, Mutex::new(None))).collect(),
            now,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Asks every socket once, records the results, and answers the failures as
    /// `<listener> got no answer: <error>`.
    pub(crate) async fn run(&self, host: &Arc<dyn Host>) -> Vec<String> {
        let mut failures = Vec::new();
        for (p, last) in &self.entries {
            let (kind, error) = match host.probe_dns(p).await {
                Ok(k) => (k, None),
                Err(e) => (Kind::NoAnswer, Some(e)),
            };
            if let Some(e) = &error {
                failures.push(format!("{} got no answer: {e}", p.listener()));
            }
            *last.lock().unwrap_or_else(PoisonError::into_inner) = Some(Last {
                kind,
                error,
                at: (self.now)(),
            });
        }
        failures
    }

    /// Each probe with its last result, for the pending read.
    pub(crate) fn lines(&self) -> Vec<(DnsProbe, Option<Last>)> {
        self.entries
            .iter()
            .map(|(p, l)| {
                (
                    p.clone(),
                    l.lock().unwrap_or_else(PoisonError::into_inner).clone(),
                )
            })
            .collect()
    }

    /// The window ended: stop counting evidence (an adopted socket keeps its counter, off).
    pub(crate) fn stop_evidence(&self) {
        for (p, _) in &self.entries {
            if let Some(e) = &p.evidence {
                e.stop();
            }
        }
    }
}

/// The task that probes while the window is open; dropping it stops it.
pub(crate) struct ProbeLoop(JoinHandle<()>);

impl ProbeLoop {
    /// Probes at once, then every `every`.
    pub(crate) fn spawn(set: Arc<ProbeSet>, host: Arc<dyn Host>, every: Duration) -> Self {
        Self(tokio::spawn(async move {
            loop {
                let _ = set.run(&host).await;
                tokio::time::sleep(every).await;
            }
        }))
    }
}

impl Drop for ProbeLoop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

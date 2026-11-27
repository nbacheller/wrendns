// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-902, CLU-004, DNS-001 (T27.14a; ADR-956 section 3, ADR-1098; `docs/design/listener-editor.md`
//! section 2.3) — the listeners' side of a confirmation window: stage, adoption, commit and abort.
//!
//! The guarded engine runs on the API's runtime; [`Listeners`] belongs to the server's main loop. The
//! engine reaches it through a [`ListenerHandle`], a command channel next to the reload channel.
//!
//! - **Stage** binds what a new list adds next to the running sockets (with the gate the host facts
//!   give now, served by the live handler), leaves what it removes alone, and binds a changed
//!   listener, or a TCP-based one that overlaps another on the same port, on a *proof port*. A failed
//!   bind closes everything staged and says which address failed and why.
//! - **Adoption**: `apply` moves a staged socket whose bound form matches into the running set instead
//!   of binding again, so commit does not depend on the order of a replicated reload and the engine's
//!   commit.
//! - **Commit** closes the proof ports and fails if a staged socket is left over. **Abort** closes
//!   only the staged and proof-port sockets.
//! - A reload in the window leaves the staged sockets alone; a file that now sets `[[listen]]`
//!   cancels the window.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};
use wrendns_config::{ListenProto, Listener};
use wrendns_net::{UdpConfig, UdpListener};

use super::evidence::{Evidence, Observed};
use super::{Listeners, Stream, alt_svc, bound_form};

#[cfg(test)]
mod probe_tests;
#[cfg(test)]
mod tests;

/// The rollback reasons of ADR-956 section 3 that a stage or a commit can answer.
pub(crate) const BIND_FAILED: &str = "bind_failed";
pub(crate) const CANCELLED: &str = "cancelled";
pub(crate) const COMMIT_FAILED: &str = "commit_failed";

/// What the file taking over says (the rollback detail of `cancelled`).
pub(crate) const FILE_TOOK_OVER: &str = "the file now sets the listeners";

/// One listener of a staged list, as stage answers it.
#[derive(Debug, Clone)]
pub(crate) struct StagedListener {
    pub(crate) proto: ListenProto,
    /// The address the configuration names.
    pub(crate) addr: SocketAddr,
    /// The socket that was bound: the address itself, or the proof port for a changed or overlapping
    /// listener.
    pub(crate) bound: SocketAddr,
    /// `bound` is a proof port: the real address is bound at commit.
    #[allow(dead_code)] // the `listen` row's preview reads it (T27.14c); the tests read it now
    pub(crate) proof: bool,
    /// The queries other hosts sent to this socket during the window (T27.14b).
    pub(crate) evidence: Arc<Evidence>,
}

/// A stage, commit or abort that did not work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowError {
    /// `bind_failed`, `cancelled` or `commit_failed`.
    pub(crate) reason: &'static str,
    /// For people: the address and the OS error.
    pub(crate) detail: String,
}

impl fmt::Display for WindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.reason, self.detail)
    }
}

/// The sockets bound for a pending change. None of them is in `Listeners::udp` or `::streams`.
#[derive(Default)]
pub(super) struct StagedSet {
    /// Added UDP listeners, on their real addresses.
    udp: Vec<(SocketAddr, UdpListener)>,
    /// Added stream listeners, on their real addresses, by bound form.
    streams: Vec<(Listener, Stream)>,
    /// Changed or overlapping stream listeners, on their proof ports. Never adopted.
    proofs: Vec<Stream>,
    /// What each proof-port listener must become at commit, and what to put back if it does not.
    plans: Vec<ProofPlan>,
    /// The errors `apply` met while this set was staged, for the detail of a `commit_failed`.
    apply_errors: Vec<(ListenProto, SocketAddr, String)>,
    /// The list the last `apply` ran with, so a restore after a failed swap can republish the states.
    last_list: Vec<Listener>,
}

/// A proof-port listener's way to the real address (design 2.3, rule 2.6.4).
struct ProofPlan {
    /// The bound form that must be running after the reload.
    want: Listener,
    /// The running form this one replaces on the same protocol and address, if any.
    replaces: Option<Listener>,
    /// Running listeners on an overlapping address that the new list removes and `apply` closes
    /// before the real bind.
    overlapped: Vec<Listener>,
}

impl StagedSet {
    /// Remembers an error `apply` met for `l` while the set is staged.
    pub(super) fn note_apply_error(&mut self, l: &Listener, e: &io::Error) {
        self.apply_errors.push((l.proto, l.addr, e.to_string()));
    }

    /// Remembers the list an `apply` ran with while the set is staged.
    pub(super) fn note_applied(&mut self, list: &[Listener]) {
        self.last_list = list.to_vec();
    }

    /// Closes every socket of the set.
    async fn close(self) {
        for (_, l) in self.udp {
            l.shutdown();
        }
        for (_, s) in self.streams {
            s.shutdown().await;
        }
        for s in self.proofs {
            s.shutdown().await;
        }
    }
}

/// A command for the main loop's [`Listeners`].
pub(crate) enum ListenerCmd {
    Stage(
        Vec<Listener>,
        oneshot::Sender<Result<Vec<StagedListener>, WindowError>>,
    ),
    /// After the entry is written and the reload has run: close the proof ports, fail if a staged
    /// socket was not adopted.
    Commit(oneshot::Sender<Result<(), WindowError>>),
    Abort(oneshot::Sender<()>),
}

/// The engine's way to the running listeners. Cheap to clone; a detached one (tests, a build
/// without a main loop) answers every call with an error.
#[derive(Clone)]
pub(crate) struct ListenerHandle(Option<mpsc::Sender<ListenerCmd>>);

impl fmt::Debug for ListenerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerHandle")
            .field("attached", &self.0.is_some())
            .finish()
    }
}

impl ListenerHandle {
    pub(crate) const fn new(tx: mpsc::Sender<ListenerCmd>) -> Self {
        Self(Some(tx))
    }

    #[cfg(test)]
    pub(crate) const fn detached() -> Self {
        Self(None)
    }

    fn gone(reason: &'static str) -> WindowError {
        WindowError {
            reason,
            detail: "the node's listeners cannot be reached".to_owned(),
        }
    }

    async fn ask<T>(
        &self,
        reason: &'static str,
        make: impl FnOnce(oneshot::Sender<T>) -> ListenerCmd,
    ) -> Result<T, WindowError> {
        let tx = self.0.as_ref().ok_or_else(|| Self::gone(reason))?;
        let (reply, answer) = oneshot::channel();
        tx.send(make(reply)).await.map_err(|_| Self::gone(reason))?;
        answer.await.map_err(|_| Self::gone(reason))
    }

    pub(crate) async fn stage(
        &self,
        list: Vec<Listener>,
    ) -> Result<Vec<StagedListener>, WindowError> {
        self.ask(BIND_FAILED, |r| ListenerCmd::Stage(list, r))
            .await?
    }

    pub(crate) async fn commit(&self) -> Result<(), WindowError> {
        self.ask(COMMIT_FAILED, ListenerCmd::Commit).await?
    }

    pub(crate) async fn abort(&self) {
        let _ = self.ask(COMMIT_FAILED, ListenerCmd::Abort).await;
    }
}

impl Stream {
    pub(super) fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Tcp(s, _) => s.local_addr(),
            Self::Doh(s, _) => s.local_addr(),
            Self::Doq(s, _) => s.local_addr(),
            Self::Doh3(s, _) => s.local_addr(),
        }
    }
}

/// The transports whose sockets do not share a port with an overlapping address: TCP-based ones
/// set only `SO_REUSEADDR`, and QUIC ones (`quinn::Endpoint::server`) set neither it nor
/// `SO_REUSEPORT`. Plain UDP sets `SO_REUSEPORT` and shares. Listeners compare within one class.
fn port_class(p: ListenProto) -> Option<u8> {
    match p {
        ListenProto::Udp => None,
        ListenProto::Tcp | ListenProto::Dot | ListenProto::Doh => Some(0),
        ListenProto::Doq | ListenProto::Doh3 => Some(1),
    }
}

/// `a` and `b` cannot be bound next to each other: the same class and overlapping addresses.
fn clash(a: &Listener, b: &Listener) -> bool {
    port_class(a.proto).is_some()
        && port_class(a.proto) == port_class(b.proto)
        && overlaps(a.addr, b.addr)
}

/// Two addresses on one port that a TCP or QUIC bind would refuse next to each other: the same family, one
/// of them the wildcard (an equal pair is one listener, not an overlap). Port 0 never overlaps.
fn overlaps(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() != 0
        && a.port() == b.port()
        && a.ip() != b.ip()
        && a.is_ipv4() == b.is_ipv4()
        && (a.ip().is_unspecified() || b.ip().is_unspecified())
}

/// Where a changed or overlapping listener is bound for the window: an ephemeral port on the same
/// IP, or on loopback for a wildcard.
fn proof_addr(a: SocketAddr) -> SocketAddr {
    let ip = match a.ip() {
        IpAddr::V4(v) if v.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v) if v.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, 0)
}

fn proto_name(p: ListenProto) -> String {
    format!("{p:?}").to_lowercase()
}

/// The words the apply uses for a bind that failed, with a hint for the common cause.
fn bind_error(l: &Listener, e: &io::Error) -> WindowError {
    let hint = if e.kind() == io::ErrorKind::AddrNotAvailable {
        " (the address is not on any interface)"
    } else {
        ""
    };
    WindowError {
        reason: BIND_FAILED,
        detail: format!("{} {}: {e}{hint}", proto_name(l.proto), l.addr),
    }
}

impl Listeners {
    /// Binds what `new` adds next to the running sockets and holds it staged; see the module notes.
    /// Nothing running is touched. A second stage replaces the first.
    pub(super) async fn stage(
        &mut self,
        new: &[Listener],
    ) -> Result<Vec<StagedListener>, WindowError> {
        self.abort_staged().await;
        self.window_cancelled = false;
        let host = crate::gate_host::read();
        let mut set = StagedSet::default();
        let mut out = Vec::new();
        for l in new {
            match self.stage_one(l, new, host, &mut set) {
                Ok(Some(s)) => out.push(s),
                Ok(None) => {}
                Err(e) => {
                    warn!(listener = %crate::gate_host::key(l), "staging the listeners failed: {}", e.detail);
                    set.close().await;
                    return Err(e);
                }
            }
        }
        info!(
            sockets = out.len(),
            "listeners staged for a confirmation window"
        );
        self.staged = Some(set);
        Ok(out)
    }

    fn stage_one(
        &self,
        l: &Listener,
        new: &[Listener],
        host: wrendns_config::HostFacts,
        set: &mut StagedSet,
    ) -> Result<Option<StagedListener>, WindowError> {
        if l.proto == ListenProto::Udp {
            if self.udp.iter().any(|(a, _)| *a == l.addr)
                || set.udp.iter().any(|(a, _)| *a == l.addr)
            {
                return Ok(None);
            }
            // SO_REUSEPORT: a specific address binds next to a wildcard on the same port.
            let evidence = Evidence::new(Evidence::node_addresses());
            let handler = Arc::new(Observed::new(
                Arc::clone(&self.handler),
                Arc::clone(&evidence),
            ));
            let s = UdpListener::spawn(&UdpConfig::new(l.addr, self.workers), &handler, &self.rt)
                .map_err(|e| bind_error(l, &e))?;
            let bound = s.local_addr();
            set.udp.push((l.addr, s));
            return Ok(Some(StagedListener {
                proto: l.proto,
                addr: l.addr,
                bound,
                proof: false,
                evidence,
            }));
        }
        let form = bound_form(l, host);
        let evidence = Evidence::new(Evidence::node_addresses());
        let handler = Arc::new(Observed::new(
            Arc::clone(&self.handler),
            Arc::clone(&evidence),
        ));
        let running = self
            .streams
            .iter()
            .find(|(c, _)| c.proto == l.proto && c.addr == l.addr);
        if running.is_some_and(|(c, _)| *c == form) || set.streams.iter().any(|(c, _)| *c == form) {
            return Ok(None);
        }
        let changed = running.is_some();
        // A TCP or QUIC bind refuses an address next to a wildcard on its port. When the new list
        // keeps both, the real bind could never work: refuse the stage. When it removes the other
        // one, the new socket goes on a proof port and `apply` closes the old one first.
        if let Some(x) = new
            .iter()
            .find(|x| !(x.proto == l.proto && x.addr == l.addr) && clash(x, l))
        {
            return Err(WindowError {
                reason: BIND_FAILED,
                detail: format!(
                    "{} {} overlaps {} {} on the same port",
                    proto_name(l.proto),
                    l.addr,
                    proto_name(x.proto),
                    x.addr
                ),
            });
        }
        let overlapped: Vec<Listener> = self
            .streams
            .iter()
            .map(|(c, _)| c)
            .filter(|c| clash(c, l))
            .cloned()
            .collect();
        let overlap = !overlapped.is_empty();
        if changed || overlap {
            let plan = ProofPlan {
                want: form.clone(),
                replaces: running.map(|(c, _)| c.clone()),
                overlapped,
            };
            let mut p = form;
            p.addr = proof_addr(l.addr);
            let s = Self::bind_stream_with(&p, host, alt_svc(new).as_deref(), handler)
                .map_err(|e| bind_error(l, &e))?;
            let bound = s.local_addr();
            set.proofs.push(s);
            set.plans.push(plan);
            return Ok(Some(StagedListener {
                proto: l.proto,
                addr: l.addr,
                bound,
                proof: true,
                evidence,
            }));
        }
        let s = Self::bind_stream_with(l, host, alt_svc(new).as_deref(), handler)
            .map_err(|e| bind_error(l, &e))?;
        let bound = s.local_addr();
        set.streams.push((form, s));
        Ok(Some(StagedListener {
            proto: l.proto,
            addr: l.addr,
            bound,
            proof: false,
            evidence,
        }))
    }

    /// [`Listeners::bind_stream`] for a bind right after a close on the same port. A QUIC endpoint
    /// gives its UDP socket back only when its driver task has run, a moment after `shutdown`
    /// returns, so an address-in-use answer is retried for a short while (about half a second), but
    /// only when `after_quic_close`: this apply closed a QUIC socket on that port just before. Any
    /// other address-in-use is a real holder, and answers at once.
    pub(super) async fn bind_stream_settled(
        &self,
        l: &Listener,
        host: wrendns_config::HostFacts,
        alt_svc: Option<&str>,
        after_quic_close: bool,
    ) -> io::Result<Stream> {
        let quic = after_quic_close && port_class(l.proto) == Some(1);
        let mut tries = 0;
        loop {
            match self.bind_stream(l, host, alt_svc) {
                Err(e) if quic && e.kind() == io::ErrorKind::AddrInUse && tries < 20 => {
                    tries += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                r => return r,
            }
        }
    }

    /// Closes every staged and proof-port socket and touches nothing else.
    pub(super) async fn abort_staged(&mut self) {
        if let Some(set) = self.staged.take() {
            info!("closing the staged listeners");
            set.close().await;
        }
        // An abort ends the window: a later commit has nothing to be cancelled.
        self.window_cancelled = false;
    }

    /// The close of a window: the proof ports go, and a staged socket that `apply` did not adopt is
    /// an error (it stays staged, for an abort to close).
    pub(super) async fn commit_staged(&mut self) -> Result<(), WindowError> {
        if std::mem::take(&mut self.window_cancelled) {
            return Err(WindowError {
                reason: CANCELLED,
                detail: FILE_TOOK_OVER.to_owned(),
            });
        }
        let Some(mut set) = self.staged.take() else {
            return Ok(());
        };
        for s in std::mem::take(&mut set.proofs) {
            s.shutdown().await;
        }
        let plans = std::mem::take(&mut set.plans);
        let errors = std::mem::take(&mut set.apply_errors);
        let last_list = std::mem::take(&mut set.last_list);
        let failed = self.verify_swaps(plans, &errors, &last_list).await;
        let mut left: Vec<String> = set.udp.iter().map(|(a, _)| format!("udp {a}")).collect();
        left.extend(
            set.streams
                .iter()
                .map(|(c, _)| format!("{} {}", proto_name(c.proto), c.addr)),
        );
        if left.is_empty() && failed.is_empty() {
            return Ok(());
        }
        let mut detail = String::new();
        if !left.is_empty() {
            detail = format!("staged but not adopted: {}", left.join(", "));
        }
        for f in failed {
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail.push_str(&f);
        }
        self.staged = Some(set);
        Err(WindowError {
            reason: COMMIT_FAILED,
            detail,
        })
    }

    /// After the reload: each proof-staged listener must be running in its bound form. One that is
    /// not (the real bind failed, or the file could not be read) puts back what it replaced, and the
    /// wildcard `apply` closed for it, with their old gates (design 2.3, rule 2.6.4). Returns the
    /// failures, each naming the address and the OS error.
    async fn verify_swaps(
        &mut self,
        plans: Vec<ProofPlan>,
        errors: &[(ListenProto, SocketAddr, String)],
        last_list: &[Listener],
    ) -> Vec<String> {
        let host = crate::gate_host::read();
        let mut failed = Vec::new();
        let mut restored: Vec<Listener> = Vec::new();
        for p in plans {
            if self.streams.iter().any(|(c, _)| *c == p.want) {
                continue;
            }
            let why = errors
                .iter()
                .find(|(pr, a, _)| *pr == p.want.proto && *a == p.want.addr)
                .map_or_else(
                    || "the listener was not bound after the reload".to_owned(),
                    |(_, _, e)| e.clone(),
                );
            let mut note = format!(
                "{} {} did not bind: {why}",
                proto_name(p.want.proto),
                p.want.addr
            );
            for old in p.replaces.into_iter().chain(p.overlapped) {
                if self
                    .streams
                    .iter()
                    .any(|(c, _)| c.proto == old.proto && c.addr == old.addr)
                {
                    continue;
                }
                let all: Vec<Listener> = self
                    .streams
                    .iter()
                    .map(|(c, _)| c.clone())
                    .chain(std::iter::once(old.clone()))
                    .collect();
                // `old` is a bound form: its gate is the one it ran with.
                match self
                    .bind_stream_settled(&old, host, alt_svc(&all).as_deref(), false)
                    .await
                {
                    Ok(s) => {
                        warn!(addr = %old.addr, proto = ?old.proto, "put the old listener back after a failed swap");
                        self.streams.push((old.clone(), s));
                        restored.push(old);
                    }
                    Err(e) => {
                        use std::fmt::Write as _;
                        let _ = write!(
                            note,
                            "; the old {} {} could not be put back: {e}",
                            proto_name(old.proto),
                            old.addr
                        );
                    }
                }
            }
            failed.push(note);
        }
        if !restored.is_empty() && !last_list.is_empty() {
            // The apply published the listener as down; it runs again, with its old gate. A
            // restored listener the new list no longer names (a closed wildcard) is published
            // too, or it would stay recorded as closed.
            let mut all = last_list.to_vec();
            for r in restored {
                if !all.iter().any(|l| l.proto == r.proto && l.addr == r.addr) {
                    all.push(r);
                }
            }
            self.publish(&all, host);
            // A gate that could not be applied closed its listener; one that runs again is not
            // closed, so the failure is recomputed rather than left as the apply set it.
            if self.gate_failed {
                self.gate_failed = last_list.iter().any(|l| {
                    l.proto.needs_tls()
                        && l.gated(host)
                        && !self
                            .streams
                            .iter()
                            .any(|(c, _)| c.proto == l.proto && c.addr == l.addr)
                });
            }
        }
        failed
    }

    /// A file that now sets `[[listen]]` has taken over: the staged sockets close and a commit
    /// answers `cancelled`.
    pub(super) async fn cancel_window_for_file(&mut self) {
        if self.staged.is_some() {
            warn!("{FILE_TOOK_OVER}: the pending listener change is cancelled");
            self.abort_staged().await;
            self.window_cancelled = true;
        }
    }

    /// A staged UDP socket for `addr`, taken out of the set (adoption).
    pub(super) fn adopt_udp(&mut self, addr: SocketAddr) -> Option<UdpListener> {
        let set = self.staged.as_mut()?;
        let i = set.udp.iter().position(|(a, _)| *a == addr)?;
        Some(set.udp.remove(i).1)
    }

    /// A staged stream whose bound form is `form`, taken out of the set (adoption).
    pub(super) fn adopt_stream(&mut self, form: &Listener) -> Option<Stream> {
        let set = self.staged.as_mut()?;
        let i = set.streams.iter().position(|(c, _)| c == form)?;
        Some(set.streams.remove(i).1)
    }

    /// Before a stream listener is bound at its real address: a running TCP or QUIC listener that
    /// overlaps it on the port and that the new list no longer names is closed first (a TCP bind
    /// would refuse the new address next to it). A gap of a few milliseconds on that one listener,
    /// as for a changed one.
    /// Answers whether a QUIC socket was closed (the bind after it may need to settle).
    pub(super) async fn close_overlapping_removed(
        &mut self,
        l: &Listener,
        listen: &[Listener],
    ) -> bool {
        if port_class(l.proto).is_none() {
            return false;
        }
        let gone: Vec<usize> = self
            .streams
            .iter()
            .enumerate()
            .filter(|(_, (c, _))| {
                clash(c, l)
                    && !listen
                        .iter()
                        .any(|x| x.proto == c.proto && x.addr == c.addr)
            })
            .map(|(i, _)| i)
            .collect();
        let mut quic = false;
        for i in gone.into_iter().rev() {
            let (c, s) = self.streams.remove(i);
            info!(addr = %c.addr, proto = ?c.proto, "closing an overlapping listener before its replacement binds");
            s.shutdown().await;
            quic |= port_class(c.proto) == Some(1);
            self.seam_after_close();
        }
        quic
    }

    /// Test seam: runs between a close the apply made and the bind that follows it, where a foreign
    /// process could take the port. Nothing in a release build.
    #[cfg(test)]
    pub(super) fn seam_after_close(&mut self) {
        if let Some(f) = self.after_close.as_mut() {
            f();
        }
    }

    #[cfg(not(test))]
    #[inline]
    #[allow(clippy::unused_self)]
    pub(super) const fn seam_after_close(&mut self) {}

    /// Runs one command from the engine.
    pub(super) async fn window_cmd(&mut self, cmd: ListenerCmd) {
        match cmd {
            ListenerCmd::Stage(list, reply) => {
                let _ = reply.send(self.stage(&list).await);
            }
            ListenerCmd::Commit(reply) => {
                let _ = reply.send(self.commit_staged().await);
            }
            ListenerCmd::Abort(reply) => {
                self.abort_staged().await;
                let _ = reply.send(());
            }
        }
    }
}

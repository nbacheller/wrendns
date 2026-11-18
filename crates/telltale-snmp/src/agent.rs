//! REQ: DSC-003 — one SNMP agent: a connected UDP exchange for v2c and v3 USM, with the reply
//! rules of ADR-908. The socket is connected to the agent, so the kernel drops other sources;
//! the source check stays as a second guard. A reply counts only if its message ID and request
//! ID match, and a v3 reply only if its security level, engine ID and user match the request.
//!
//! Message and request IDs start at a random value and count up on separate counters, so a
//! spoofed datagram cannot guess them (ADR-908). An unauthenticated `Report` is accepted only for
//! engine discovery. A time resync from an authenticated `Report` is limited to one per agent per
//! minute (`usm::ResyncGate`). Each agent keeps one 64 KiB receive buffer, reused for every
//! datagram.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::ber::{DecodeError, MAX_MESSAGE};
use crate::oid::Oid;
use crate::pdu::{self, RequestKind, Response, TAG_REPORT, TAG_RESPONSE};
use crate::secret::SecretValue;
use crate::usm::{self, Engine, ResyncGate, RoundKeys, UsmError, UsmUser, Window};
use crate::v2c;

/// How the agent waits for replies (ADR-908: timeout 1.5 s, two retries).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub timeout: Duration,
    pub retries: u32,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(1500),
            retries: 2,
        }
    }
}

/// How the agent authenticates. The community or the user comes from the credential source.
#[derive(Debug)]
pub enum Security {
    V2c { community: SecretValue },
    V3 { user: UsmUser },
}

/// Why an exchange failed. Carries no secret and no input byte.
#[derive(Debug)]
pub enum AgentError {
    /// No reply after every attempt.
    Timeout,
    /// The socket failed. The kind is kept; the message is not (it can name addresses).
    Io(io::ErrorKind),
    /// A reply did not decode.
    Decode(DecodeError),
    /// A v3 reply failed a USM check.
    Usm(UsmError),
    /// The agent answered with a `Report` that this client does not act on.
    ReportRefused,
    /// The agent has no engine ID, so v3 cannot be used.
    NoEngine,
    /// The agent answered with a non-zero error-status.
    Status(i32),
    /// The request could not be built (an OID is not encodable), or the user is not usable
    /// (v3 needs an authentication password; noAuthNoPriv is refused).
    BadRequest,
}

impl From<DecodeError> for AgentError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<UsmError> for AgentError {
    fn from(e: UsmError) -> Self {
        Self::Usm(e)
    }
}

/// What an accepted reply means for the exchange in progress.
enum Outcome {
    Answer(Response),
    /// The agent sent an authenticated time-window `Report`; its clock was taken, so the same
    /// request is sent again (one attempt).
    Resend,
}

/// The values a v3 reply must match (RFC 3412 §7.2, ADR-908).
struct Expect<'a> {
    msg_id: i32,
    request_id: i32,
    user: &'a [u8],
    flags: u8,
}

/// One SNMP agent at one address.
pub struct Agent {
    target: SocketAddr,
    socket: UdpSocket,
    buf: Vec<u8>,
    security: Security,
    timing: Timing,
    next_msg_id: i32,
    next_req_id: i32,
    engine: Option<Engine>,
    /// The engine as last seen in an authenticated message. Rediscovery may not move it back
    /// (RFC 3414 §3.2.7b; a spoofed discovery Report is unauthenticated).
    trusted: Option<Engine>,
    gate: ResyncGate,
    keys: Option<RoundKeys>,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

/// A random starting value in 1..2^30, so the first IDs cannot be guessed from the address.
fn random_start() -> i32 {
    let mut b = [0u8; 4];
    if SystemRandom::new().fill(&mut b).is_err() {
        return 1;
    }
    (i32::from_be_bytes(b) & 0x3fff_ffff).max(1)
}

/// Takes the next ID from a counter, wrapping inside the positive INTEGER range.
fn take(counter: &mut i32) -> i32 {
    let id = *counter;
    *counter = counter.checked_add(1).filter(|v| *v >= 1).unwrap_or(1);
    id
}

impl Agent {
    /// Opens a socket connected to one agent. The target is already validated by the caller
    /// (`dest`). A v3 user without an authentication password is refused: noAuthNoPriv is not
    /// a mode this client uses.
    pub fn new(target: SocketAddr, security: Security, timing: Timing) -> Result<Self, AgentError> {
        Self::check_security(&security)?;
        let bind: SocketAddr = match target.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind).map_err(|e| AgentError::Io(e.kind()))?;
        socket
            .connect(target)
            .map_err(|e| AgentError::Io(e.kind()))?;
        Ok(Self::from_connected(target, socket, security, timing))
    }

    /// REQ: DSC-003 (ADR-1001) - the same as [`Agent::new`] with a socket the caller already
    /// connected to `target`. A discovery worker's seccomp filter refuses `bind`, so it makes the
    /// socket with `socket` and `connect` alone (`telltale_net::worker::connected_udp_socket`) and
    /// hands it in; this crate holds no `unsafe` and makes no socket call of its own on this path.
    /// A socket not connected to `target` is refused.
    pub fn with_socket(
        target: SocketAddr,
        socket: UdpSocket,
        security: Security,
        timing: Timing,
    ) -> Result<Self, AgentError> {
        Self::check_security(&security)?;
        if socket.peer_addr().ok() != Some(target) {
            return Err(AgentError::BadRequest);
        }
        Ok(Self::from_connected(target, socket, security, timing))
    }

    /// A v3 user without an authentication password is refused: noAuthNoPriv is not a mode this
    /// client uses (REQ: DSC-003), and passwords under 8 octets are refused up front (RFC 3414 §11.2).
    fn check_security(security: &Security) -> Result<(), AgentError> {
        if matches!(security, Security::V3 { user } if user.auth.is_none()) {
            return Err(AgentError::BadRequest);
        }
        if let Security::V3 { user } = security {
            let short = user
                .auth
                .iter()
                .map(|(_, p)| p)
                .chain(user.privacy.iter().map(|(_, p)| p))
                .any(|p| usm::check_password(p.expose()).is_err());
            if short {
                return Err(AgentError::Usm(UsmError::ShortPassword));
            }
        }
        Ok(())
    }

    fn from_connected(
        target: SocketAddr,
        socket: UdpSocket,
        security: Security,
        timing: Timing,
    ) -> Self {
        Self {
            target,
            socket,
            buf: vec![0u8; MAX_MESSAGE],
            security,
            timing,
            next_msg_id: random_start(),
            next_req_id: random_start(),
            engine: None,
            trusted: None,
            gate: ResyncGate::default(),
            keys: None,
        }
    }

    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// The engine learned so far (v3), for the capability record.
    pub fn engine(&self) -> Option<&Engine> {
        self.engine.as_ref()
    }

    /// REQ: DSC-004 — the security level this agent uses, for the capability record: `v2c`,
    /// `authNoPriv` or `authPriv`.
    pub fn level(&self) -> &'static str {
        match &self.security {
            Security::V2c { .. } => "v2c",
            Security::V3 { user } if user.privacy.is_some() => "authPriv",
            Security::V3 { .. } => "authNoPriv",
        }
    }

    /// Moves the learned engine's clock origin back by `by`, as if that much local time had
    /// passed without a reply: the estimate then runs ahead of a slow or paused agent. For
    /// tests of the time-window recovery (DSC-003); it has no use in a poller.
    #[doc(hidden)]
    pub fn age_engine_estimate(&mut self, by: Duration) {
        for e in [self.engine.as_mut(), self.trusted.as_mut()]
            .into_iter()
            .flatten()
        {
            if let Some(t) = e.learned.checked_sub(by) {
                e.learned = t;
            }
        }
    }

    /// Derives the round's keys once, before a walk or a poll round (ADR-908).
    pub fn begin_round(&mut self) -> Result<(), AgentError> {
        if let (Security::V3 { user }, None) = (&self.security, self.keys.as_ref()) {
            self.keys = Some(user.derive()?);
        }
        Ok(())
    }

    /// Drops the round's keys (zeroized).
    pub fn end_round(&mut self) {
        self.keys = None;
    }

    /// One request and its reply, with retries. A non-zero error-status is returned as data.
    pub fn request(
        &mut self,
        kind: RequestKind,
        oids: &[Oid],
        max_repetitions: u32,
    ) -> Result<Response, AgentError> {
        match &self.security {
            Security::V2c { .. } => self.request_v2c(kind, oids, max_repetitions),
            Security::V3 { .. } => self.request_v3(kind, oids, max_repetitions),
        }
    }

    fn request_v2c(
        &mut self,
        kind: RequestKind,
        oids: &[Oid],
        max_repetitions: u32,
    ) -> Result<Response, AgentError> {
        let community = match &self.security {
            Security::V2c { community } => Zeroizing::new(community.expose().to_vec()),
            Security::V3 { .. } => return Err(AgentError::BadRequest),
        };
        for _ in 0..=self.timing.retries {
            let req_id = take(&mut self.next_req_id);
            let pdu = pdu::encode_request(kind, req_id, 0, max_repetitions, oids)
                .map_err(|_| AgentError::BadRequest)?;
            let msg = Zeroizing::new(v2c::encode(&community, &pdu));
            self.send(&msg)?;
            let got = self.wait_for(|_this, bytes| {
                let decoded = v2c::decode(bytes).ok()?;
                if !usm::ct_eq(&decoded.community, &community) {
                    return None;
                }
                if decoded.response.tag != TAG_RESPONSE || decoded.response.request_id != req_id {
                    return None;
                }
                Some(finish(decoded.response))
            });
            match got {
                Ok(resp) => return Ok(resp),
                Err(AgentError::Timeout) => {}
                Err(e) => return Err(e),
            }
        }
        Err(AgentError::Timeout)
    }

    fn request_v3(
        &mut self,
        kind: RequestKind,
        oids: &[Oid],
        max_repetitions: u32,
    ) -> Result<Response, AgentError> {
        let result = self.request_v3_inner(kind, oids, max_repetitions);
        // A failed exchange may mean the cached engine ID was forged or the device rebooted:
        // the next request discovers the engine again (ADR-908).
        if matches!(
            result,
            Err(AgentError::Timeout
                | AgentError::Usm(_)
                | AgentError::ReportRefused
                | AgentError::NoEngine)
        ) {
            self.engine = None;
        }
        result
    }

    fn request_v3_inner(
        &mut self,
        kind: RequestKind,
        oids: &[Oid],
        max_repetitions: u32,
    ) -> Result<Response, AgentError> {
        let (user_name, want_flags) = match &self.security {
            Security::V3 { user } => (
                user.name.clone(),
                if user.privacy.is_some() {
                    usm::LEVEL_MASK
                } else {
                    usm::AUTH_FLAG
                },
            ),
            Security::V2c { .. } => return Err(AgentError::BadRequest),
        };
        self.begin_round()?;
        if self.engine.is_none() {
            self.discover()?;
        }
        for _ in 0..=self.timing.retries {
            let msg_id = take(&mut self.next_msg_id);
            let req_id = take(&mut self.next_req_id);
            let engine = self.engine.clone().ok_or(AgentError::NoEngine)?;
            let pdu = pdu::encode_request(kind, req_id, 0, max_repetitions, oids)
                .map_err(|_| AgentError::BadRequest)?;
            let scoped = usm::scoped_request(&engine.id, &pdu);
            let out = usm::Outgoing {
                msg_id,
                engine_id: &engine.id,
                boots: engine.boots,
                time: engine.time_now(Instant::now()),
                user: &user_name,
                reportable: true,
            };
            let msg = usm::encode(&out, self.keys.as_ref(), &scoped)?;
            self.send(&msg)?;
            let expect = Expect {
                msg_id,
                request_id: req_id,
                user: &user_name,
                flags: want_flags,
            };
            let got = self.wait_for(|this, bytes| this.accept_v3(bytes, &expect, Instant::now()));
            match got {
                Ok(Outcome::Answer(resp)) => {
                    self.trusted = self.engine.clone();
                    return Ok(resp);
                }
                Ok(Outcome::Resend) => self.trusted = self.engine.clone(),
                Err(AgentError::Timeout) => {}
                Err(e) => return Err(e),
            }
        }
        Err(AgentError::Timeout)
    }

    /// Engine discovery: a noAuthNoPriv message with an empty engine ID. The agent answers with
    /// a `Report` whose varbind is usmStatsUnknownEngineIDs; that `Report` carries its engine ID,
    /// boots and time (RFC 3414 §4). Nothing else is accepted as discovery.
    fn discover(&mut self) -> Result<(), AgentError> {
        for _ in 0..=self.timing.retries {
            let msg_id = take(&mut self.next_msg_id);
            let req_id = take(&mut self.next_req_id);
            let pdu = pdu::encode_request(RequestKind::Get, req_id, 0, 0, &[])
                .map_err(|_| AgentError::BadRequest)?;
            let scoped = usm::scoped_request(&[], &pdu);
            let out = usm::Outgoing {
                msg_id,
                engine_id: &[],
                boots: 0,
                time: 0,
                user: &[],
                reportable: true,
            };
            let msg = usm::encode(&out, None, &scoped)?;
            self.send(&msg)?;
            let got = self
                .wait_for(|_this, bytes| accept_discovery(bytes, msg_id, req_id, Instant::now()));
            match got {
                Ok(engine) => {
                    // REQ: DSC-003. An unauthenticated discovery may move the clock forward
                    // (a reboot) but never back past what an authenticated message showed. When
                    // it is behind for the same engine, keep the trusted engine with its
                    // estimated clock instead of failing: authenticated time Reports resync it.
                    if !usm::discovery_allowed(self.trusted.as_ref(), &engine, Instant::now()) {
                        match self.trusted.clone() {
                            Some(t) if t.id == engine.id => {
                                self.engine = Some(t);
                                return Ok(());
                            }
                            _ => return Err(AgentError::Usm(UsmError::NotInTimeWindow)),
                        }
                    }
                    if self.trusted.as_ref().is_some_and(|t| t.id != engine.id) {
                        self.trusted = None;
                    }
                    self.engine = Some(engine);
                    return Ok(());
                }
                Err(AgentError::Timeout) => {}
                Err(e) => return Err(e),
            }
        }
        Err(AgentError::Timeout)
    }

    /// Checks one v3 reply. `Some(Ok)` is the answer or a resend; `Some(Err)` is a failure to
    /// report; `None` drops the datagram and keeps waiting.
    fn accept_v3(
        &mut self,
        bytes: &[u8],
        expect: &Expect<'_>,
        now: Instant,
    ) -> Option<Result<Outcome, AgentError>> {
        let reply = usm::parse(bytes).ok()?;
        if reply.msg_id != expect.msg_id {
            return None;
        }
        let engine = self.engine.clone()?;
        if reply.engine_id != engine.id || reply.user != expect.user {
            return None;
        }
        // The reply's security level is the request's (RFC 3412 §7.2), with one exception. An
        // agent checks the time window before it decrypts, so its time-window `Report` for an
        // authPriv request is sent at authNoPriv (RFC 3414 §3.2.7a). That `Report` is accepted
        // only when its MAC verifies, and it is in plaintext. An unauthenticated reply is never
        // accepted: a forged Report is what an attacker can send.
        let level = reply.flags & usm::LEVEL_MASK;
        let report_level = level == usm::AUTH_FLAG && expect.flags == usm::LEVEL_MASK;
        if level != expect.flags && !report_level {
            return None;
        }
        let keys = self.keys.as_ref()?;
        if usm::verify(bytes, &reply, keys).is_err() {
            return None;
        }
        // An authenticated message is ours to trust, so its clock may move (RFC 3414 §3.2.7).
        let window = engine.window(reply.boots, reply.time, now);
        let encrypted = level == usm::LEVEL_MASK;
        let plain = if encrypted {
            usm::decrypt(&reply, keys).ok()?
        } else {
            reply.scoped.clone()
        };
        let resp = usm::scoped_response(&plain).ok()?;
        if resp.tag == TAG_REPORT {
            // The agent may not know the request ID when it refuses the time window, so it may
            // send 0 (ADR-908). Any other ID is not ours.
            if resp.request_id != expect.request_id && resp.request_id != 0 {
                return None;
            }
            let not_in_window = resp
                .varbinds
                .iter()
                .any(|vb| vb.oid.to_string() == usm::USM_STATS_NOT_IN_TIME_WINDOW);
            if not_in_window && self.gate.allow(now) {
                // RFC 3414 §3.2.7b: the clock only moves forward, and boots at the maximum
                // are never taken. A Report that would move it back is refused.
                match window {
                    Window::Resync => {
                        if let Some(e) = self.engine.as_mut() {
                            e.resync(reply.boots, reply.time, now);
                        }
                    }
                    Window::Accept => {
                        if let Some(e) = self.engine.as_mut() {
                            e.note_received(reply.boots, reply.time);
                        }
                    }
                    Window::Stale => {
                        return Some(Err(AgentError::Usm(UsmError::NotInTimeWindow)));
                    }
                }
                return Some(Ok(Outcome::Resend));
            }
            return Some(Err(AgentError::ReportRefused));
        }
        // Only a `Report` may come at authNoPriv for an authPriv request.
        if level != expect.flags || resp.request_id != expect.request_id {
            return None;
        }
        match window {
            Window::Accept => {
                if let Some(e) = self.engine.as_mut() {
                    e.note_received(reply.boots, reply.time);
                }
            }
            Window::Resync => {
                if let Some(e) = self.engine.as_mut() {
                    e.resync(reply.boots, reply.time, now);
                }
            }
            Window::Stale => return Some(Err(AgentError::Usm(UsmError::NotInTimeWindow))),
        }
        Some(finish(resp).map(Outcome::Answer))
    }

    fn send(&self, msg: &[u8]) -> Result<(), AgentError> {
        self.socket
            .send(msg)
            .map(|_| ())
            .map_err(|e| AgentError::Io(e.kind()))
    }

    /// Waits for one datagram from the target that `accept` takes, within the timing's timeout.
    /// Datagrams from any other address are dropped before `accept` sees them. The datagram is
    /// held in the agent's buffer while `accept` runs, so `accept` may use the agent.
    fn wait_for<T>(
        &mut self,
        mut accept: impl FnMut(&mut Self, &[u8]) -> Option<Result<T, AgentError>>,
    ) -> Result<T, AgentError> {
        let deadline = Instant::now()
            .checked_add(self.timing.timeout)
            .ok_or(AgentError::Timeout)?;
        loop {
            let n = self.recv_one(deadline)?;
            let buf = std::mem::take(&mut self.buf);
            let verdict = match buf.get(..n) {
                Some(bytes) => accept(self, bytes),
                None => None,
            };
            self.buf = buf;
            if let Some(result) = verdict {
                return result;
            }
        }
    }

    /// Receives one datagram from the target into the buffer, before `deadline`. Returns its
    /// length. Errors that a lost reply can cause (a refused port, a reset) are a timeout, so
    /// the attempt is retried.
    fn recv_one(&mut self, deadline: Instant) -> Result<usize, AgentError> {
        loop {
            let remain = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(AgentError::Timeout)?;
            self.socket
                .set_read_timeout(Some(remain))
                .map_err(|e| AgentError::Io(e.kind()))?;
            match self.socket.recv_from(&mut self.buf) {
                Ok((n, from)) => {
                    if from == self.target {
                        return Ok(n);
                    }
                }
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionRefused => {
                        return Err(AgentError::Timeout);
                    }
                    kind => return Err(AgentError::Io(kind)),
                },
            }
        }
    }
}

/// Checks a discovery reply: a noAuthNoPriv `Report` for our message and request, with a
/// non-empty engine ID of at most 32 octets, whose varbind is usmStatsUnknownEngineIDs.
fn accept_discovery(
    bytes: &[u8],
    msg_id: i32,
    req_id: i32,
    now: Instant,
) -> Option<Result<Engine, AgentError>> {
    let reply = usm::parse(bytes).ok()?;
    if reply.msg_id != msg_id || reply.engine_id.is_empty() || reply.engine_id.len() > 32 {
        return None;
    }
    if reply.flags & usm::LEVEL_MASK != 0 {
        return None;
    }
    let resp = usm::scoped_response(&reply.scoped).ok()?;
    if resp.tag != TAG_REPORT || resp.request_id != req_id {
        return None;
    }
    if !resp
        .varbinds
        .iter()
        .any(|vb| vb.oid.to_string() == usm::USM_STATS_UNKNOWN_ENGINE_ID)
    {
        return None;
    }
    Some(Ok(Engine {
        id: reply.engine_id,
        boots: reply.boots,
        time: reply.time,
        learned: now,
        latest: None,
    }))
}

fn finish(resp: Response) -> Result<Response, AgentError> {
    if resp.error_status != 0 {
        return Err(AgentError::Status(resp.error_status));
    }
    Ok(resp)
}

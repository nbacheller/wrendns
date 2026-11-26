//! Iterative resolver (REQ: DNS-012, UPS-012; `spec/03` §6; T7.15).
//!
//! Resolves from the root servers down, the way `unbound` does for a Pi-hole, so WrenDNS
//! needs no forwarder: `url = "recursive://"` makes it an upstream like any other.
//! - **QNAME minimization** (RFC 9156, relaxed): each server sees only one more label than
//!   it needs (`com` for the root, `example.com` for `com`), asked as `A`; a minimized query
//!   that fails (NXDOMAIN, errors) falls back to the full name.
//! - **Spoofing defenses:** a random port and ID per query (RFC 5452), records accepted only
//!   in the answering server's bailiwick, glue only for server names under the referring
//!   zone, and optional 0x20 letter-case randomization (servers that don't echo the case are
//!   remembered and asked without it).
//! - **Server choice** by smoothed RTT; a timeout or lame answer moves to the next server.
//!   A server slower than usual is hedged: the next one is asked too, and the first useful
//!   answer wins (T9.8).
//! - **Root priming** (RFC 8109, T9.8): the root servers' current names and addresses are
//!   asked of the built-in hints once, then cached like any zone cut (and asked again a day
//!   later), so a changed root server address doesn't need a new build.
//! - **Limits:** 16 CNAME/DNAME hops, 32 referrals per lookup, at most 4 nested lookups for
//!   server names, and 96 queries per client question.
//! - **Caches:** zone cuts with their server addresses and server-name addresses (bounded,
//!   TTL-capped); final answers go to the server's answer cache like any upstream's.
//! - **Stub zones** (DNS-022): names at or under a stub zone start at its configured servers
//!   instead of the root (BIND's `static-stub`, Unbound's `stub-zone`), so an internal zone's
//!   own delegations are followed; names outside it are resolved from the root as usual.
//!
//! - **Addresses never queried** (DNS-902, Unbound's `do-not-query-localhost`): loopback,
//!   unspecified, link-local, multicast and broadcast addresses are never asked, whatever the
//!   glue, a server-name lookup or the cache holds, and private ranges (RFC 1918, carrier
//!   NAT, unique-local) only inside a stub zone, unless `allow_local_servers` or
//!   `allow_private_servers` says otherwise. A public delegation can't aim the resolver at
//!   the host or the home network.
//! - **Lame answers are failures** (DNS-902): a server that answers REFUSED, FORMERR or a
//!   referral that goes nowhere has its smoothed RTT worsened like a timeout, so a fast lame
//!   server stops coming first.
//!
//! DNSSEC: with DO set, signatures, DS sets, and NSEC/NSEC3 proofs are passed through, so the
//! validator above (DNS-011) checks the chain from the root's trust anchor.

// REQ: NFR-003 — no unsafe outside wrendns-net.
#![forbid(unsafe_code)]

mod cache;
pub mod msg;
mod net;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::{Duration, Instant};

use tracing::debug;
use wrendns_proto::{HEADER_LEN, NameBuf, rcode, read_name, rtype};

use crate::cache::Caches;
use crate::msg::{Outcome, Rr};
pub use net::NetError;

/// The root servers (IANA root hints, `named.root`): IPv4, then IPv6.
pub const ROOT_HINTS_V4: [[u8; 4]; 13] = [
    [198, 41, 0, 4],
    [170, 247, 170, 2],
    [192, 33, 4, 12],
    [199, 7, 91, 13],
    [192, 203, 230, 10],
    [192, 5, 5, 241],
    [192, 112, 36, 4],
    [198, 97, 190, 53],
    [192, 36, 148, 17],
    [192, 58, 128, 30],
    [193, 0, 14, 129],
    [199, 7, 83, 42],
    [202, 12, 27, 33],
];
pub const ROOT_HINTS_V6: [&str; 13] = [
    "2001:503:ba3e::2:30",
    "2801:1b8:10::b",
    "2001:500:2::c",
    "2001:500:2d::d",
    "2001:500:a8::e",
    "2001:500:2f::f",
    "2001:500:12::d0d",
    "2001:500:1::53",
    "2001:7fe::53",
    "2001:503:c27::2:30",
    "2001:7fd::1",
    "2001:500:9f::42",
    "2001:dc3::35",
];

const MAX_CNAME: u32 = 16;
const MAX_REFERRALS: u32 = 32;
const MAX_DEPTH: u8 = 4;
const MAX_QUERIES: u32 = 96;
/// Minimized steps before the rest of the name is sent at once (RFC 9156 §2.3).
const MAX_MINIMIZE: usize = 10;
/// Servers tried for one question before giving up.
const MAX_TRIES: usize = 4;
/// Zones whose refused server lists are remembered (REQ: DNS-902).
const REFUSALS_KEPT: usize = 16;

/// Resolver settings (`[[upstream]]` with `url = "recursive://"`).
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // independent on/off switches, not a state machine
pub struct Settings {
    /// RFC 9156 QNAME minimization (on by default).
    pub qname_minimization: bool,
    /// 0x20 letter-case randomization (off by default: a few servers don't echo the case).
    pub case_randomization: bool,
    /// Ask servers over IPv6 too (off by default: many home networks have no IPv6 route).
    pub ipv6: bool,
    /// The root servers to start from.
    pub roots: Vec<IpAddr>,
    /// The port servers listen on (53; tests use another).
    pub port: u16,
    /// The most a single server is waited for.
    pub server_timeout: Duration,
    /// REQ: DNS-012 (T9.8) — RFC 8109 root priming (on by default).
    pub prime: bool,
    /// Ask the next server too when one is slower than usual (on by default).
    pub hedge: bool,
    /// REQ: DNS-022 — zones that start at their own servers instead of the root.
    pub stubs: Vec<Stub>,
    /// REQ: DNS-902 — also ask loopback, unspecified, link-local, multicast and broadcast
    /// addresses (off by default; the test fixtures run their servers on loopback).
    pub allow_local_servers: bool,
    /// REQ: DNS-902 — also ask private-range addresses outside stub zones (off by default).
    pub allow_private_servers: bool,
}

/// REQ: DNS-022 — a stub zone: questions at or under `zone` are asked of `servers`
/// (iteratively, RD=0), and the referrals they give are followed. The servers are used as
/// configured, whatever the public delegation says (split horizon).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stub {
    pub zone: NameBuf,
    pub servers: Vec<IpAddr>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            qname_minimization: true,
            case_randomization: false,
            ipv6: false,
            roots: ROOT_HINTS_V4.iter().map(|a| IpAddr::from(*a)).collect(),
            port: 53,
            server_timeout: Duration::from_millis(1200),
            prime: true,
            hedge: true,
            stubs: Vec::new(),
            allow_local_servers: false,
            allow_private_servers: false,
        }
    }
}

/// REQ: DNS-902 — an address no authoritative server should have on the public Internet:
/// loopback, unspecified, link-local, multicast, broadcast.
#[must_use]
pub fn is_local_address(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(a) => {
            a.is_loopback()
                || a.is_unspecified()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
        }
        IpAddr::V6(a) => {
            a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || a.segments()[0] & 0xffc0 == 0xfe80
        }
    }
}

/// REQ: DNS-902 — a private-range address: RFC 1918, carrier-grade NAT (100.64.0.0/10),
/// unique-local (`fc00::/7`) and the deprecated site-local range (`fec0::/10`).
#[must_use]
pub fn is_private_address(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(a) => a.is_private() || (a.octets()[0] == 100 && a.octets()[1] & 0xc0 == 0x40),
        IpAddr::V6(a) => a.segments()[0] & 0xfe00 == 0xfc00 || a.segments()[0] & 0xffc0 == 0xfec0,
    }
}

impl Settings {
    /// The default settings, with the IPv6 root addresses added when `ipv6`.
    #[must_use]
    pub fn with_ipv6(mut self, ipv6: bool) -> Self {
        self.ipv6 = ipv6;
        if ipv6 {
            self.roots.extend(
                ROOT_HINTS_V6
                    .iter()
                    .filter_map(|a| a.parse::<IpAddr>().ok()),
            );
        }
        self
    }
}

/// Why a question couldn't be resolved (it becomes SERVFAIL).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("no server for {0} answered usefully")]
    NoServer(String),
    #[error("too many referrals, CNAMEs, or queries (a loop or a misconfigured zone)")]
    Limit,
    #[error("every server address for {0} is refused (loopback, link-local or private)")]
    Refused(String),
    #[error("malformed question")]
    Question,
}

/// The work one client question may cause.
#[derive(Debug, Default)]
struct Work {
    queries: u32,
    /// REQ: DNS-902 — a server list was emptied by the address rules (`permit`).
    refused: bool,
}

impl Work {
    /// A `NoServer` failure that followed an emptied server list says why.
    fn explain(&self, e: Error) -> Error {
        match e {
            Error::NoServer(z) if self.refused => Error::Refused(z),
            e => e,
        }
    }

    fn spend(&mut self) -> Result<(), Error> {
        self.queries += 1;
        if self.queries > MAX_QUERIES {
            Err(Error::Limit)
        } else {
            Ok(())
        }
    }
}

/// A resolution's result: RCODE, the answer section, the authority section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub rcode: u16,
    pub answer: Vec<Rr>,
    pub authority: Vec<Rr>,
}

type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The resolver. Share one per upstream (it holds the caches).
#[derive(Debug)]
pub struct Recursor {
    settings: Settings,
    caches: Caches,
    /// When priming was last tried (it's not tried again for a minute after a failure).
    primed_at: parking_lot::Mutex<Option<Instant>>,
    /// REQ: DNS-902 — the zones whose server lists the address rules emptied, newest last (a
    /// few; "Why?" says an address rule affected an answer only when one of these covers it).
    refusals: parking_lot::Mutex<Vec<(NameBuf, Instant)>>,
}

/// `name` cut to its last `n` labels.
fn suffix(name: &NameBuf, n: usize) -> NameBuf {
    let total = name.label_count();
    let wire = name.as_wire();
    let mut pos = 0usize;
    for _ in 0..total.saturating_sub(n) {
        pos += 1 + usize::from(wire[pos]);
    }
    let mut out = NameBuf::default();
    let _ = read_name(wire, pos, &mut out);
    out
}

impl Recursor {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            caches: Caches::default(),
            primed_at: parking_lot::Mutex::new(None),
            refusals: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// REQ: DNS-012 (T9.8) — RFC 8109: asks the hints for the root's NS set and its
    /// addresses (the glue in the same answer, else a lookup of the names), and caches it as
    /// the root zone cut. Quiet on failure: the hints keep working.
    async fn prime(&self, work: &mut Work) {
        let root = NameBuf::default();
        if !self.settings.prime || self.caches.closest(&root, false).is_some() {
            return;
        }
        {
            let mut at = self.primed_at.lock();
            if at.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
                return;
            }
            *at = Some(Instant::now());
        }
        let roots = self.permit(&self.settings.roots, &root, work);
        for (ip, _, _) in self.caches.order(&roots).into_iter().take(MAX_TRIES) {
            if work.spend().is_err() {
                return;
            }
            let addr = SocketAddr::new(ip, self.settings.port);
            let Ok(resp) = net::ask(
                addr,
                &root,
                rtype::NS,
                false,
                false,
                self.settings.server_timeout,
            )
            .await
            else {
                continue;
            };
            let Some(p) = msg::parse(&resp) else { continue };
            let ns: Vec<&Rr> = p
                .answer
                .iter()
                .filter(|r| r.rtype == rtype::NS && r.name.is_root())
                .collect();
            if ns.is_empty() {
                continue;
            }
            let ttl = ns.iter().map(|r| r.ttl).min().unwrap_or(86_400);
            let names: Vec<NameBuf> = ns.iter().filter_map(|r| r.target()).collect();
            let glue: Vec<(NameBuf, IpAddr)> = p
                .additional
                .iter()
                .filter(|r| names.contains(&r.name))
                .filter_map(|r| r.addr().map(|a| (r.name, a)))
                .collect();
            let addrs = self.delegation(&root, &names, &glue, work, 0).await;
            if addrs.is_empty() {
                continue;
            }
            debug!(servers = addrs.len(), "root priming");
            self.caches.put_zone(root, names, addrs, ttl);
            return;
        }
    }

    /// REQ: DNS-902 — whether the address rules affected answers for `name`: a stub zone
    /// covering it whose servers are all refused, or a server list for a zone at or above it
    /// emptied by the rules within `within`. "Why?" shows its refusal notes only then.
    #[must_use]
    pub fn address_rules_affect(&self, name: &NameBuf, within: Duration) -> bool {
        let stub_refused = self.stub_for(name, false).is_some_and(|s| {
            !s.servers.is_empty() && s.servers.iter().all(|ip| !self.may_ask(*ip, &s.zone))
        });
        stub_refused
            || self
                .refusals
                .lock()
                .iter()
                .any(|(z, at)| name.is_subdomain_of(z) && at.elapsed() <= within)
    }

    /// The settings this resolver runs with.
    #[must_use]
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Zone cuts cached (metrics, tests).
    pub fn cached_zones(&self) -> usize {
        self.caches.zones()
    }

    /// REQ: DNS-022 — the first stub zone, if any (health checks ask for its SOA rather than
    /// the root's NS, which authoritative-only servers refuse).
    pub fn stub_zone(&self) -> Option<&NameBuf> {
        self.settings.stubs.first().map(|s| &s.zone)
    }

    /// REQ: UPS-006, DNS-022 — a stub zone's liveness, for health checks: whether one of its
    /// servers answers the zone's SOA question. A refusal counts: an authoritative server that
    /// serves only zones below the apex refuses it, and is up. SERVFAIL does not: a server
    /// that says it is failing for its own zone (the zone didn't load, or it expired) isn't up
    /// for it. This is the one rule behind both the active check and the draft check. `None`
    /// without a stub zone.
    pub async fn probe_stub(&self) -> Option<bool> {
        let s = self.settings.stubs.first()?;
        let servers = self.permit(&s.servers, &s.zone, &mut Work::default());
        for (ip, _, _) in self.caches.order(&servers).into_iter().take(MAX_TRIES) {
            let addr = SocketAddr::new(ip, self.settings.port);
            let t0 = Instant::now();
            let timeout = self.settings.server_timeout;
            let r = net::ask(addr, &s.zone, rtype::SOA, false, false, timeout).await;
            self.caches
                .record(ip, r.is_ok().then(|| t0.elapsed()), timeout);
            if r.is_ok_and(|reply| {
                msg::parse(&reply).is_some_and(|p| p.rcode != wrendns_proto::rcode::SERVFAIL)
            }) {
                return Some(true);
            }
        }
        Some(false)
    }

    /// REQ: DNS-022 — the deepest stub zone at or above `name` (strictly above with
    /// `parent_only`: a zone's DS lives in its parent).
    fn stub_for(&self, name: &NameBuf, parent_only: bool) -> Option<&Stub> {
        self.settings
            .stubs
            .iter()
            .filter(|s| name.is_subdomain_of(&s.zone) && !(parent_only && *name == s.zone))
            .max_by_key(|s| s.zone.label_count())
    }

    /// Answers the client `query` (wire format: one question, maybe OPT): the full response,
    /// with the query's ID and question, RA set.
    pub async fn answer(&self, query: &[u8]) -> Result<Vec<u8>, Error> {
        let mut name = NameBuf::default();
        let end = wrendns_proto::read_name_uncompressed(query, HEADER_LEN, &mut name)
            .map_err(|_| Error::Question)?;
        let qtype = query
            .get(end..end + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .ok_or(Error::Question)?;
        let header = wrendns_proto::Header::parse(query).ok_or(Error::Question)?;
        let opt_at = end + 4;
        let dnssec_ok = header.arcount > 0 && query.get(opt_at + 7).is_some_and(|b| b & 0x80 != 0);
        let mut work = Work::default();
        // REQ: DNS-022 — a stub zone's names never need the root (a network with no route to
        // it doesn't wait on priming).
        if self.stub_for(&name, false).is_none() {
            self.prime(&mut work).await;
        }
        let r = self
            .lookup(name, qtype, dnssec_ok, &mut work, 0)
            .await
            .map_err(|e| work.explain(e))?;
        msg::encode(query, r.rcode, &r.answer, &r.authority).ok_or(Error::Question)
    }

    /// Resolves `name`/`qtype` from the closest known zone cut.
    pub async fn resolve(
        &self,
        name: NameBuf,
        qtype: u16,
        dnssec_ok: bool,
    ) -> Result<Resolved, Error> {
        let mut work = Work::default();
        if self.stub_for(&name, false).is_none() {
            self.prime(&mut work).await;
        }
        self.lookup(name, qtype, dnssec_ok, &mut work, 0)
            .await
            .map_err(|e| work.explain(e))
    }

    #[allow(clippy::too_many_lines)] // one state machine: referrals, minimization, chasing
    fn lookup<'a>(
        &'a self,
        name: NameBuf,
        qtype: u16,
        dnssec_ok: bool,
        work: &'a mut Work,
        depth: u8,
    ) -> Boxed<'a, Result<Resolved, Error>> {
        Box::pin(async move {
            let mut answer: Vec<Rr> = Vec::new();
            let mut current = name;
            let mut hops = 0u32;
            'chase: loop {
                let (mut zone, mut servers) = self
                    .start(&current, qtype == rtype::DS, work, depth)
                    .await?;
                let mut minimize = self.settings.qname_minimization;
                let mut labels = zone.label_count() + 1;
                let mut steps = 0usize;
                let mut referrals = 0u32;
                loop {
                    let full = !minimize || labels >= current.label_count();
                    let (qn, qt) = if full {
                        (current, qtype)
                    } else {
                        (suffix(&current, labels), rtype::A)
                    };
                    let outcome = match self
                        .ask(&servers, &qn, qt, dnssec_ok && full, &zone, work)
                        .await
                    {
                        Ok((o, _)) => o,
                        Err(Error::Limit) => return Err(Error::Limit),
                        // Relaxed mode: servers that fail a minimized query get the full one.
                        Err(_) if !full => {
                            minimize = false;
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    match outcome {
                        Outcome::Referral {
                            child,
                            ns,
                            glue,
                            ttl,
                            ds,
                        } => {
                            referrals += 1;
                            if referrals > MAX_REFERRALS {
                                return Err(Error::Limit);
                            }
                            if qtype == rtype::DS && full && child == current {
                                // The parent answered with a delegation to the very name: it
                                // has no DS for it (an unsigned delegation, or one it omits).
                                if !ds.is_empty() {
                                    answer.extend(ds);
                                    return Ok(Resolved {
                                        rcode: rcode::NOERROR,
                                        answer,
                                        authority: Vec::new(),
                                    });
                                }
                            }
                            let addrs = self.delegation(&child, &ns, &glue, work, depth).await;
                            self.caches.put_zone(child, ns, addrs.clone(), ttl);
                            if addrs.is_empty() {
                                return Err(Error::NoServer(child.display().to_string()));
                            }
                            debug!(zone = %child.display(), servers = addrs.len(), "referral");
                            zone = child;
                            servers = addrs;
                            labels = zone.label_count() + 1;
                        }
                        // REQ: DNS-012 — RFC 9156: a minimized query only finds the next cut.
                        _ if !full => {
                            match outcome {
                                Outcome::NoData { .. } | Outcome::Answer { .. } => {
                                    steps += 1;
                                    labels = if steps >= MAX_MINIMIZE {
                                        current.label_count()
                                    } else {
                                        labels + 1
                                    };
                                }
                                // Relaxed mode: NXDOMAIN or anything odd → ask the full name.
                                _ => minimize = false,
                            }
                        }
                        Outcome::Answer { records, next } => {
                            answer.extend(records);
                            match next {
                                Some(t) => {
                                    hops += 1;
                                    if hops > MAX_CNAME || answer.len() > 64 {
                                        return Err(Error::Limit);
                                    }
                                    current = t;
                                    continue 'chase;
                                }
                                None => {
                                    return Ok(Resolved {
                                        rcode: rcode::NOERROR,
                                        answer,
                                        authority: Vec::new(),
                                    });
                                }
                            }
                        }
                        Outcome::NoData { chain, authority } => {
                            answer.extend(chain);
                            return Ok(Resolved {
                                rcode: rcode::NOERROR,
                                answer,
                                authority,
                            });
                        }
                        Outcome::NxDomain { chain, authority } => {
                            answer.extend(chain);
                            return Ok(Resolved {
                                rcode: rcode::NXDOMAIN,
                                answer,
                                authority,
                            });
                        }
                        Outcome::Lame => return Err(Error::NoServer(zone.display().to_string())),
                    }
                }
            }
        })
    }

    /// Where to start for `name`: the deepest cached zone cut with addresses (resolving its
    /// server names when it has none), else the stub zone containing it (DNS-022), else the
    /// root.
    async fn start(
        &self,
        name: &NameBuf,
        parent_only: bool,
        work: &mut Work,
        depth: u8,
    ) -> Result<(NameBuf, Vec<IpAddr>), Error> {
        let stub = self.stub_for(name, parent_only);
        let mut at = *name;
        let mut skip = parent_only;
        loop {
            match self.caches.closest(&at, skip) {
                // REQ: DNS-022 — a cut at or above the stub zone is the outside view of it:
                // only the stub's servers (and the cuts they referred to) count.
                Some((zone, _))
                    if stub.is_some_and(|s| zone.label_count() <= s.zone.label_count()) =>
                {
                    break;
                }
                Some((zone, d)) => {
                    if !d.addrs.is_empty() {
                        let a = self.usable(&d.addrs, &zone, work);
                        if !a.is_empty() {
                            return Ok((zone, a));
                        }
                    }
                    let addrs = self.delegation(&zone, &d.ns, &[], work, depth).await;
                    if !addrs.is_empty() {
                        self.caches.add_zone_addrs(&zone, &addrs);
                        return Ok((zone, addrs));
                    }
                    if zone.is_root() {
                        break;
                    }
                    // Try the next cut up.
                    at = zone;
                    skip = true;
                }
                None => break,
            }
        }
        // The configured addresses as given (IPv6 too): the operator chose them.
        if let Some(s) = stub {
            return Ok((s.zone, s.servers.clone()));
        }
        Ok((NameBuf::default(), self.settings.roots.clone()))
    }

    /// REQ: DNS-902 — whether `ip` may be asked for `zone`: not a local address unless
    /// allowed, and a private one only inside a stub zone unless allowed.
    fn may_ask(&self, ip: IpAddr, zone: &NameBuf) -> bool {
        // The root hints are the resolver's own (built in; only tests replace them).
        if self.settings.roots.contains(&ip) {
            return true;
        }
        if is_local_address(ip) {
            return self.settings.allow_local_servers;
        }
        !is_private_address(ip)
            || self.settings.allow_private_servers
            || self.stub_for(zone, false).is_some()
    }

    /// `addrs` that may be asked for `zone` (REQ: DNS-902). When that leaves nothing of a
    /// non-empty list, the work is marked so the failure says the addresses were refused.
    fn permit(&self, addrs: &[IpAddr], zone: &NameBuf, work: &mut Work) -> Vec<IpAddr> {
        let ok: Vec<IpAddr> = addrs
            .iter()
            .copied()
            .filter(|a| self.may_ask(*a, zone))
            .collect();
        if ok.is_empty() && !addrs.is_empty() {
            debug!(zone = %zone.display(), "every server address refused");
            work.refused = true;
            let mut r = self.refusals.lock();
            r.retain(|(z, _)| z != zone);
            if r.len() >= REFUSALS_KEPT {
                r.remove(0);
            }
            r.push((*zone, Instant::now()));
        }
        ok
    }

    /// The addresses of the allowed families that may be asked for `zone`.
    fn usable(&self, addrs: &[IpAddr], zone: &NameBuf, work: &mut Work) -> Vec<IpAddr> {
        let fam: Vec<IpAddr> = addrs
            .iter()
            .copied()
            .filter(|a| self.settings.ipv6 || a.is_ipv4())
            .collect();
        self.permit(&fam, zone, work)
    }

    /// Addresses for a zone's servers: glue first, then cached addresses, then (if neither)
    /// a lookup of the server names, stopping at the first that resolves.
    async fn delegation(
        &self,
        child: &NameBuf,
        ns: &[NameBuf],
        glue: &[(NameBuf, IpAddr)],
        work: &mut Work,
        depth: u8,
    ) -> Vec<IpAddr> {
        let glued: Vec<IpAddr> = glue.iter().map(|(_, a)| *a).collect();
        let mut addrs = self.usable(&glued, child, work);
        for n in ns {
            if let Some(a) = self.caches.addrs(n) {
                addrs.extend(self.usable(&a, child, work));
            }
        }
        addrs.sort_unstable();
        addrs.dedup();
        if !addrs.is_empty() || depth >= MAX_DEPTH {
            return addrs;
        }
        for n in ns {
            // A server inside the zone it serves needs glue; without it, it's unreachable.
            if n.is_subdomain_of(child) {
                continue;
            }
            let mut found = Vec::new();
            let types: &[u16] = if self.settings.ipv6 {
                &[rtype::A, rtype::AAAA]
            } else {
                &[rtype::A]
            };
            for &t in types {
                if let Ok(r) = self.lookup(*n, t, false, work, depth + 1).await {
                    let ttl = r.answer.iter().map(|x| x.ttl).min().unwrap_or(300);
                    let a: Vec<IpAddr> = r.answer.iter().filter_map(Rr::addr).collect();
                    if !a.is_empty() {
                        self.caches.put_addrs(*n, a.clone(), ttl);
                        found.extend(self.usable(&a, child, work));
                    }
                }
            }
            if !found.is_empty() {
                return found;
            }
        }
        Vec::new()
    }

    /// Asks `servers` (fastest first) until one gives a usable answer for `zone`. A server
    /// slower than its usual (1.5 × its smoothed RTT, at least 150 ms) is hedged: the next one
    /// is asked as well, and the first usable answer wins (T9.8).
    async fn ask(
        &self,
        servers: &[IpAddr],
        qn: &NameBuf,
        qt: u16,
        dnssec_ok: bool,
        zone: &NameBuf,
        work: &mut Work,
    ) -> Result<(Outcome, IpAddr), Error> {
        let servers = self.permit(servers, zone, work);
        let order: Vec<_> = self
            .caches
            .order(&servers)
            .into_iter()
            .take(MAX_TRIES)
            .collect();
        let mut i = 0;
        while i < order.len() {
            let (ip, srtt_us, no_case) = order[i];
            work.spend()?;
            let first = self.try_server(ip, srtt_us, no_case, qn, qt, dnssec_ok, zone);
            tokio::pin!(first);
            let next = order.get(i + 1).copied().filter(|_| self.settings.hedge);
            let Some((ip2, srtt2, no_case2)) = next else {
                if let Some(o) = first.await {
                    return Ok(o);
                }
                i += 1;
                continue;
            };
            let hedge_after = srtt_us.map_or(Duration::from_millis(400), |s| {
                (Duration::from_micros(u64::from(s)) * 3 / 2).max(Duration::from_millis(150))
            });
            tokio::select! {
                r = &mut first => {
                    if let Some(o) = r {
                        return Ok(o);
                    }
                    // Failed quickly: the next server, hedged in turn.
                    i += 1;
                    continue;
                }
                () = tokio::time::sleep(hedge_after) => {}
            }
            // REQ: DNS-012 (T9.8) — slower than usual: ask the next server as well.
            work.spend()?;
            let second = self.try_server(ip2, srtt2, no_case2, qn, qt, dnssec_ok, zone);
            tokio::pin!(second);
            let won = tokio::select! {
                r = &mut first => match r {
                    Some(o) => Some(o),
                    None => second.await,
                },
                r = &mut second => match r {
                    Some(o) => Some(o),
                    None => first.await,
                },
            };
            if let Some(o) = won {
                return Ok(o);
            }
            i += 2;
        }
        Err(Error::NoServer(zone.display().to_string()))
    }

    /// One server, once (twice when it breaks 0x20): its usable outcome, or `None`. Records
    /// the server's RTT or timeout.
    #[allow(clippy::too_many_arguments)]
    async fn try_server(
        &self,
        ip: IpAddr,
        srtt_us: Option<u32>,
        no_case: bool,
        qn: &NameBuf,
        qt: u16,
        dnssec_ok: bool,
        zone: &NameBuf,
    ) -> Option<(Outcome, IpAddr)> {
        let timeout = match srtt_us {
            None => self.settings.server_timeout,
            Some(s) => (Duration::from_micros(u64::from(s)) * 3 + Duration::from_millis(100))
                .clamp(Duration::from_millis(250), self.settings.server_timeout),
        };
        let addr = SocketAddr::new(ip, self.settings.port);
        let mix = self.settings.case_randomization && !no_case;
        let t0 = Instant::now();
        let mut res = net::ask(addr, qn, qt, dnssec_ok, mix, timeout).await;
        if res == Err(NetError::CaseMismatch) {
            // REQ: DNS-012 — 0x20: nothing with the case intact came in time, only replies
            // with it changed: this server doesn't echo the case; ask it plainly.
            self.caches.no_case(ip);
            res = net::ask(addr, qn, qt, dnssec_ok, false, timeout).await;
        }
        let rtt = t0.elapsed();
        let outcome = res.ok().and_then(|resp| {
            let p = msg::parse(&resp)?;
            Some(msg::classify(&p, qn, qt, zone))
        });
        // REQ: DNS-902 — a lame answer (or one that can't be read) is a failure of the server,
        // however fast it came: counting its RTT as a success kept a quick lame server first.
        match outcome {
            Some(o) if o != Outcome::Lame => {
                self.caches.record(ip, Some(rtt), timeout);
                Some((o, ip))
            }
            _ => {
                self.caches.record(ip, None, timeout);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_012_suffix() {
        let n = NameBuf::from_presentation("a.b.example.com").unwrap();
        assert_eq!(
            suffix(&n, 2),
            NameBuf::from_presentation("example.com").unwrap()
        );
        assert_eq!(suffix(&n, 0), NameBuf::default());
        assert_eq!(suffix(&n, 9), n);
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// REQ: DNS-902 — private servers are asked only inside a stub zone (the zone's own
    /// servers and the delegations below it), unless allowed; local ones never unless allowed.
    #[test]
    fn dns_902_private_only_inside_stub_zones() {
        let corp = NameBuf::from_presentation("corp.example.com").unwrap();
        let below = NameBuf::from_presentation("sub.corp.example.com").unwrap();
        let outside = NameBuf::from_presentation("example.com").unwrap();
        let r = Recursor::new(Settings {
            stubs: vec![Stub {
                zone: corp,
                servers: vec![ip("10.1.0.8")],
            }],
            ..Settings::default()
        });
        assert!(r.may_ask(ip("10.1.0.8"), &corp));
        assert!(r.may_ask(ip("192.168.4.4"), &below));
        assert!(r.may_ask(ip("fd00::8"), &below));
        assert!(!r.may_ask(ip("10.1.0.8"), &outside));
        assert!(!r.may_ask(ip("10.1.0.8"), &NameBuf::default()));
        assert!(r.may_ask(ip("198.51.100.1"), &outside));
        assert!(
            !r.may_ask(ip("127.0.0.1"), &corp),
            "loopback even in a stub zone"
        );
        assert!(!r.may_ask(ip("::1"), &corp));
        assert!(!r.may_ask(ip("169.254.0.5"), &outside));
        let open = Recursor::new(Settings {
            allow_local_servers: true,
            allow_private_servers: true,
            ..Settings::default()
        });
        assert!(open.may_ask(ip("127.0.0.1"), &outside));
        assert!(open.may_ask(ip("10.0.0.1"), &outside));
        let private_only = Recursor::new(Settings {
            allow_private_servers: true,
            ..Settings::default()
        });
        assert!(private_only.may_ask(ip("10.0.0.1"), &outside));
        assert!(!private_only.may_ask(ip("127.0.0.1"), &outside));
    }

    /// REQ: DNS-902 — "Why?" learns that an address rule affected an answer only from a stub
    /// zone whose servers are all refused, or a server list the rules emptied; not otherwise.
    #[test]
    fn dns_902_address_rules_affect_only_after_a_refusal() {
        let within = Duration::from_secs(60);
        let name = NameBuf::from_presentation("www.example.com").unwrap();
        let zone = NameBuf::from_presentation("example.com").unwrap();
        let other = NameBuf::from_presentation("other.test").unwrap();
        let r = Recursor::new(Settings::default());
        assert!(
            !r.address_rules_affect(&name, within),
            "nothing refused yet"
        );
        let mut work = Work::default();
        // A public server is fine; a delegation to private-only servers leaves nothing to ask.
        assert_eq!(r.permit(&[ip("198.51.100.1")], &zone, &mut work).len(), 1);
        assert!(!r.address_rules_affect(&name, within));
        let left = r.permit(&[ip("10.0.0.1")], &zone, &mut work);
        assert_eq!(left.len(), 0);
        assert!(r.address_rules_affect(&name, within));
        assert!(!r.address_rules_affect(&other, within), "another zone");
        assert!(
            !r.address_rules_affect(&name, Duration::ZERO),
            "too long ago"
        );
        // A stub zone whose only server is on this machine is refused by the rules.
        let stub_zone = NameBuf::from_presentation("corp.test").unwrap();
        let stubbed = |allow| {
            Recursor::new(Settings {
                stubs: vec![Stub {
                    zone: stub_zone,
                    servers: vec![ip("127.0.0.1")],
                }],
                allow_local_servers: allow,
                ..Settings::default()
            })
        };
        let inside = NameBuf::from_presentation("a.corp.test").unwrap();
        assert!(stubbed(false).address_rules_affect(&inside, within));
        assert!(!stubbed(true).address_rules_affect(&inside, within));
    }
}

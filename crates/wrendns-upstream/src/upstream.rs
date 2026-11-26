//! One upstream server: how to talk to it, and how healthy it is.
//!
//! REQ: UPS-001 (UDP, TCP, DoT, DoH over HTTP/2 or HTTP/1.1), UPS-006 (health per upstream), UPS-008 (pooled,
//! pipelined connections), UPS-009 (bootstrap for hostnames), `spec/04` §7 (loop detection).

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use wrendns_proto::{
    EdnsOut, FlagBit, HEADER_LEN, NameBuf, build_query, header, opt, rcode, read_name, summarize,
};

use crate::bootstrap::Bootstrap;
use crate::conn::{BoxIo, ConnStats, Connector, Pool, counted};
use crate::doh::Doh;
use crate::doh3::Doh3;
use crate::doq::Doq;
use crate::endpoint::{Endpoint, Host, Protocol};
use crate::health::{Health, Outcome};
use crate::tls::{TlsOptions, client_config, server_name};

/// The question being forwarded, detached from the client's packet so it can move into
/// async tasks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: NameBuf,
    pub qtype: u16,
    pub qclass: u16,
    /// Ask upstream for DNSSEC records (client DO=1).
    pub dnssec_ok: bool,
    /// Client set CD (checking disabled).
    pub checking_disabled: bool,
    /// REQ: DNS-015 (T9.9) — the client's subnet, packed by [`client_subnet`] (0 = none), for
    /// upstreams with `ecs = "client"`.
    pub client_subnet: u64,
}

impl Question {
    pub fn from_query(q: &wrendns_proto::Query<'_>) -> Self {
        Self {
            name: q.qname,
            qtype: q.qtype,
            qclass: q.qclass,
            dnssec_ok: q.edns.is_some_and(|e| e.dnssec_ok),
            checking_disabled: q.header.flags.cd(),
            client_subnet: 0,
        }
    }
}

/// REQ: DNS-015 (T9.9) — RFC 7871 §11.1's privacy defaults for a client's own subnet.
const ECS_V4_PREFIX: u8 = 24;
const ECS_V6_PREFIX: u8 = 56;

/// REQ: DNS-015 (T9.9) — a client's subnet (/24 or /56) packed into a `u64` for the cache key:
/// family in the top 2 bits, then the address bits. 0 for an address that isn't public
/// (private, loopback, link-local, CGNAT, ULA…): announcing it would tell a CDN nothing and
/// leak the network's layout.
pub fn client_subnet(ip: std::net::IpAddr) -> u64 {
    let ip = match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4),
        v4 @ std::net::IpAddr::V4(_) => v4,
    };
    match ip {
        std::net::IpAddr::V4(a) => {
            let o = a.octets();
            let cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
            if a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
                || cgnat
                || o[0] == 0
            {
                return 0;
            }
            (1u64 << 62) | u64::from(u32::from(a) >> (32 - ECS_V4_PREFIX))
        }
        std::net::IpAddr::V6(a) => {
            let s = a.segments();
            let ula = (s[0] & 0xfe00) == 0xfc00;
            let link_local = (s[0] & 0xffc0) == 0xfe80;
            if a.is_loopback() || a.is_unspecified() || a.is_multicast() || ula || link_local {
                return 0;
            }
            let bits = u64::try_from(u128::from(a) >> (128 - ECS_V6_PREFIX)).unwrap_or(0);
            (2u64 << 62) | bits
        }
    }
}

/// REQ: DNS-015 (T9.9) — the ECS option for a packed [`client_subnet`], if any.
pub(crate) fn ecs_for_client(packed: u64) -> Option<Vec<u8>> {
    let bits = packed & ((1u64 << 62) - 1);
    match packed >> 62 {
        1 => {
            let a = u32::try_from(bits << (32 - ECS_V4_PREFIX)).ok()?;
            Some(ecs_option(
                std::net::Ipv4Addr::from(a).into(),
                ECS_V4_PREFIX,
            ))
        }
        2 => {
            let a = u128::from(bits) << (128 - ECS_V6_PREFIX);
            Some(ecs_option(
                std::net::Ipv6Addr::from(a).into(),
                ECS_V6_PREFIX,
            ))
        }
        _ => None,
    }
}

/// Why an attempt failed.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("timed out")]
    Timeout,
    #[error("network error: {0}")]
    Io(#[from] io::Error),
    #[error("malformed or mismatched response")]
    BadResponse,
    #[error("could not resolve the upstream's hostname")]
    Unresolved,
}

/// Our advertised EDNS payload toward upstreams (DNS Flag Day 2020).
const UPSTREAM_EDNS_PAYLOAD: u16 = 1232;

static NODE_TAG: OnceLock<[u8; 8]> = OnceLock::new();

/// REQ: OBS-007 (T9.19) — one exchange with an upstream, as an observer sees it (dnstap's
/// `FORWARDER_QUERY` and `FORWARDER_RESPONSE`).
#[derive(Debug)]
pub struct Exchange<'a> {
    pub protocol: Protocol,
    /// The upstream's address, when it has one (not for plugins).
    pub addr: Option<SocketAddr>,
    /// The query exactly as sent.
    pub query: &'a [u8],
    /// The response, if one came.
    pub response: Option<&'a [u8]>,
    pub sent: std::time::SystemTime,
}

/// What observes exchanges.
pub type ExchangeObserver = Box<dyn Fn(&Exchange<'_>) + Send + Sync>;

static OBSERVER: OnceLock<ExchangeObserver> = OnceLock::new();

/// REQ: OBS-007 (T9.19) — sets the exchange observer (once, at startup). Without one, an
/// exchange pays a single `OnceLock` load.
pub fn set_exchange_observer(f: ExchangeObserver) {
    let _ = OBSERVER.set(f);
}

/// Sets this node's loop-detection tag (once, at startup). Outbound queries carry it in EDNS
/// option 65429; a client query arriving with our own tag means we are forwarding to ourselves.
pub fn set_node_tag(tag: u64) {
    let _ = NODE_TAG.set(tag.to_be_bytes());
}

/// True if `q` carries this node's loop tag (`spec/04` §7).
pub fn is_own_loop_tag(q: &wrendns_proto::Query<'_>) -> bool {
    match (NODE_TAG.get(), q.edns.and_then(|e| e.loop_tag())) {
        (Some(ours), Some(theirs)) => ours.as_slice() == theirs,
        _ => false,
    }
}

/// Builds the outbound query: fresh ID, RD=1, our own OPT (client EDNS options such as ECS,
/// cookies, and MAC are never forwarded) with the loop tag, CD copied from the client.
pub fn encode_query(q: &Question, id: u16, out: &mut [u8]) -> Option<usize> {
    encode_query_with(q, id, out, &[], true)
}

/// [`encode_query`] with `extra` EDNS options (already encoded) after the loop tag; `tag`
/// false leaves the loop tag out (a self-probe, T11.3).
pub(crate) fn encode_query_with(
    q: &Question,
    id: u16,
    out: &mut [u8],
    extra: &[u8],
    tag: bool,
) -> Option<usize> {
    let edns = EdnsOut {
        udp_payload: UPSTREAM_EDNS_PAYLOAD,
        dnssec_ok: q.dnssec_ok,
        ede: None,
    };
    let mut len = build_query(out, id, &q.name, q.qtype, q.qclass, true, Some(edns)).ok()?;
    if q.checking_disabled {
        let f = header::flags(out).with(FlagBit::Cd, true);
        header::set_flags(out, f);
    }
    // The OPT record is last with RDLENGTH 0 in its final two bytes: append the options.
    let rdlen_at = len - 2;
    let mut rdlen = 0u16;
    if let Some(tag) = NODE_TAG.get().filter(|_| tag) {
        let dst = out.get_mut(len..len + 12)?;
        dst[..2].copy_from_slice(&opt::WRENDNS_LOOP.to_be_bytes());
        dst[2..4].copy_from_slice(&8u16.to_be_bytes());
        dst[4..].copy_from_slice(tag);
        len += 12;
        rdlen += 12;
    }
    if !extra.is_empty() {
        out.get_mut(len..len + extra.len())?.copy_from_slice(extra);
        len += extra.len();
        rdlen += u16::try_from(extra.len()).ok()?;
    }
    out[rdlen_at..rdlen_at + 2].copy_from_slice(&rdlen.to_be_bytes());
    Some(len)
}

/// REQ: DNS-015 (T7.23) — the EDNS Client Subnet option (RFC 7871 §6) announcing `subnet`
/// instead of the client: family, source prefix, scope 0, and the address cut to the prefix.
pub(crate) fn ecs_option(addr: std::net::IpAddr, prefix: u8) -> Vec<u8> {
    let (family, bytes, max): (u16, Vec<u8>, u8) = match addr {
        std::net::IpAddr::V4(a) => (1, a.octets().to_vec(), 32),
        std::net::IpAddr::V6(a) => (2, a.octets().to_vec(), 128),
    };
    let prefix = prefix.min(max);
    let n = usize::from(prefix.div_ceil(8));
    let mut a = bytes[..n].to_vec();
    if prefix % 8 != 0
        && let Some(last) = a.last_mut()
    {
        *last &= 0xff << (8 - prefix % 8);
    }
    let mut o = Vec::with_capacity(8 + n);
    o.extend_from_slice(&opt::ECS.to_be_bytes());
    o.extend_from_slice(&u16::try_from(4 + n).unwrap_or(0).to_be_bytes());
    o.extend_from_slice(&family.to_be_bytes());
    o.push(prefix);
    o.push(0);
    o.extend(a);
    o
}

/// Accepts a response only if it answers exactly our query: same ID, QR=1, QUERY opcode,
/// one question equal to ours (case-insensitively). Defends against spoofed or stray packets.
pub fn matches_query(resp: &[u8], query: &[u8], id: u16) -> bool {
    let (Some(rh), Some(qh)) = (
        wrendns_proto::Header::parse(resp),
        wrendns_proto::Header::parse(query),
    ) else {
        return false;
    };
    if rh.id != id || !rh.flags.qr() || rh.flags.opcode() != 0 || rh.qdcount != 1 || qh.qdcount != 1
    {
        return false;
    }
    let mut a = NameBuf::default();
    let mut b = NameBuf::default();
    let (Ok(ra), Ok(qb)) = (
        read_name(resp, HEADER_LEN, &mut a),
        read_name(query, HEADER_LEN, &mut b),
    ) else {
        return false;
    };
    a == b && resp.get(ra..ra + 4).is_some() && resp.get(ra..ra + 4) == query.get(qb..qb + 4)
}

/// Per-upstream settings (from `[[upstream]]`).
#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)] // independent settings, each from its own config key
pub struct UpstreamOptions {
    pub timeout: Duration,
    pub weight: u32,
    pub pool_size: usize,
    pub idle_timeout: Duration,
    pub tls_server_name: Option<String>,
    pub tls_insecure_skip_verify: bool,
    pub headers: Vec<(String, String)>,
    /// Resolver for hostname URLs.
    pub bootstrap: Option<Arc<Bootstrap>>,
    /// REQ: DNS-012 — `recursive://` settings.
    pub recursive: wrendns_recursor::Settings,
    /// REQ: UPS-010 — connect through this proxy (TCP-based protocols).
    pub proxy: Option<Arc<crate::proxy::Proxy>>,
    /// REQ: DNS-015 (T7.23) — an ECS option sent instead of the client's subnet.
    pub ecs: Option<Vec<u8>>,
    /// REQ: DNS-015 (T9.9) — `ecs = "client"`: send each client's own subnet.
    pub ecs_client: bool,
    /// REQ: UPS-003 (T7.24) — a DNSCrypt stamp's provider key and name.
    pub dnscrypt: Option<([u8; 32], String)>,
    /// REQ: UPS-003 (T9.9) — the anonymized DNSCrypt relay to go through.
    pub dnscrypt_relay: Option<SocketAddr>,
    /// REQ: UPS-011 — this upstream's CA, client certificate, and pins.
    pub tls: crate::tls::UpstreamTls,
    /// REQ: UPS-011 — `exec://`: the program's arguments, and the directory for its socket.
    pub plugin_args: Vec<String>,
    pub plugin_dir: Option<std::path::PathBuf>,
    /// REQ: UPS-011 (T9.9) — DoH over GET (`?dns=`) instead of POST.
    pub doh_get: bool,
    /// REQ: UPS-001 — DoH offers HTTP/2 only (`http_version = "2"`); otherwise it also offers
    /// HTTP/1.1 and speaks whichever the server selects.
    pub doh_h2_only: bool,
    /// REQ: UPS-013 (T24.31, ADR-997) — the local address (already resolved and checked) that
    /// this upstream's UDP sockets and TCP connections are bound to before they connect.
    pub source: Option<std::net::IpAddr>,
    /// REQ: UPS-013 — the configured `source` (an address or a network), looked up on this
    /// node; when it names no address the node holds, the upstream starts with a problem.
    pub source_spec: Option<String>,
    /// REQ: OBS-020 (T11.3) — WrenDNS asking its own listener (a synthetic probe): the
    /// query carries no loop tag (the listener would drop it as a forwarding loop, `spec/04`
    /// §7) and isn't copied to the exchange observer (dnstap's forwarder messages).
    pub self_probe: bool,
}

impl Default for UpstreamOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(400),
            weight: 1,
            pool_size: 4,
            idle_timeout: Duration::from_secs(30),
            tls_server_name: None,
            tls_insecure_skip_verify: false,
            headers: Vec::new(),
            bootstrap: None,
            recursive: wrendns_recursor::Settings::default(),
            proxy: None,
            ecs: None,
            ecs_client: false,
            dnscrypt: None,
            dnscrypt_relay: None,
            plugin_args: Vec::new(),
            plugin_dir: None,
            tls: crate::tls::UpstreamTls::default(),
            doh_get: false,
            doh_h2_only: false,
            source: None,
            source_spec: None,
            self_probe: false,
        }
    }
}

/// Where to connect: a fixed address, or a hostname resolved through bootstrap.
#[derive(Debug)]
struct Target {
    host: Host,
    port: u16,
    bootstrap: Option<Arc<Bootstrap>>,
    /// REQ: UPS-013 — the address sockets to this target are bound to.
    source: Option<Source>,
}

/// REQ: UPS-013 (T24.31, ADR-997 §4) — an upstream's source address. A node that doesn't hold
/// the address (a VLAN that isn't up yet, a pod network, a replica of another shape) doesn't
/// refuse to start: this upstream's queries fail fast with a problem the health report shows,
/// every other upstream serves, and the address is looked up again (at most every
/// `RESOLVE_EVERY`) so it recovers by itself when the interface comes up.
#[derive(Debug)]
pub(crate) struct Source {
    spec: String,
    /// The IP version of the address or network named: a hostname upstream is reached over it.
    v4: bool,
    upstream: String,
    state: std::sync::Mutex<SourceState>,
}

#[derive(Debug, Default)]
struct SourceState {
    ip: Option<std::net::IpAddr>,
    tried: Option<std::time::Instant>,
    problem: Option<String>,
}

/// How often a missing source address is looked for again.
const RESOLVE_EVERY: Duration = Duration::from_secs(5);

impl Source {
    fn new(spec: &str, known: Option<std::net::IpAddr>, upstream: &str) -> Result<Self, String> {
        let v4 = match wrendns_config::parse_source(spec)? {
            wrendns_config::SourceSpec::Addr(ip) => ip.is_ipv4(),
            wrendns_config::SourceSpec::Subnet(c) => c.addr.is_ipv4(),
        };
        let s = Self {
            spec: spec.to_owned(),
            v4,
            upstream: upstream.to_owned(),
            state: std::sync::Mutex::new(SourceState {
                ip: known,
                ..SourceState::default()
            }),
        };
        if known.is_none() {
            // A first look now, so the problem is visible before any query.
            s.current().ok();
        }
        Ok(s)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SourceState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn ip(&self) -> Option<std::net::IpAddr> {
        self.lock().ip
    }

    fn problem(&self) -> Option<String> {
        self.lock().problem.clone()
    }

    /// The address to bind now, looking it up when it isn't known (rate limited).
    fn current(&self) -> io::Result<std::net::IpAddr> {
        let mut st = self.lock();
        if let Some(ip) = st.ip {
            return Ok(ip);
        }
        let unavailable = |p: &Option<String>| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                p.clone()
                    .unwrap_or_else(|| "source address unavailable".into()),
            )
        };
        if st.tried.is_some_and(|t| t.elapsed() < RESOLVE_EVERY) {
            return Err(unavailable(&st.problem));
        }
        st.tried = Some(std::time::Instant::now());
        let found = match wrendns_net::local_addrs() {
            Ok(held) => crate::source::resolve_source(&self.spec, &held),
            Err(e) => Err(format!("couldn't list this node's addresses: {e}")),
        };
        match found {
            Ok(ip) => {
                st.ip = Some(ip);
                Ok(ip)
            }
            Err(e) => {
                let msg = format!("{e}; queries to this upstream fail until it does");
                if st.problem.as_deref() != Some(msg.as_str()) {
                    tracing::warn!(upstream = %self.upstream, "{msg}");
                }
                st.problem = Some(msg);
                Err(unavailable(&st.problem))
            }
        }
    }

    /// The local socket address to bind: the source address, any port.
    fn bind_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(self.current()?, 0))
    }

    /// Records how a bind went. An address that left the node is looked up again later.
    fn note<T>(&self, r: io::Result<T>) -> io::Result<T> {
        let mut st = self.lock();
        match &r {
            Ok(_) => {
                if st.problem.take().is_some() {
                    tracing::info!(upstream = %self.upstream, "upstream source address is back");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable => {
                let msg = format!(
                    "its source address {} is no longer held by this node: queries to it fail until it is back",
                    st.ip.map_or_else(|| self.spec.clone(), |ip| ip.to_string())
                );
                if st.problem.is_none() {
                    tracing::warn!(upstream = %self.upstream, "{msg}");
                }
                st.problem = Some(msg);
                st.ip = None;
                st.tried = Some(std::time::Instant::now());
            }
            Err(_) => {}
        }
        r
    }

    /// The server's hostname has no address of the source's IP version.
    fn no_family(&self, host: &str) -> io::Error {
        let v = if self.v4 { "IPv4" } else { "IPv6" };
        let msg = format!(
            "the server `{host}` has no {v} address to reach from source {}",
            self.spec
        );
        let mut st = self.lock();
        if st.problem.as_deref() != Some(msg.as_str()) {
            tracing::warn!(upstream = %self.upstream, "{msg}");
        }
        st.problem = Some(msg.clone());
        io::Error::other(msg)
    }
}

impl Target {
    async fn addr(&self) -> Result<SocketAddr, ExchangeError> {
        match &self.host {
            Host::Ip(ip) => Ok(SocketAddr::new(*ip, self.port)),
            Host::Name(name) => {
                let bs = self.bootstrap.as_ref().ok_or(ExchangeError::Unresolved)?;
                let ips = bs.resolve(name).await?;
                // REQ: UPS-013 — with a source address, the first address of its IP version
                // (a v6 source can't reach a v4 destination).
                match &self.source {
                    Some(src) => match ips.iter().find(|ip| ip.is_ipv4() == src.v4) {
                        Some(ip) => Ok(SocketAddr::new(*ip, self.port)),
                        None if ips.is_empty() => Err(ExchangeError::Unresolved),
                        None => Err(ExchangeError::Io(src.no_family(name))),
                    },
                    None => ips
                        .first()
                        .map(|ip| SocketAddr::new(*ip, self.port))
                        .ok_or(ExchangeError::Unresolved),
                }
            }
        }
    }
}

enum Transport {
    /// UDP, with a TCP pool for truncated answers, and (T9.9) through a SOCKS5 relay when
    /// the upstream has a proxy.
    Udp {
        tcp: Pool,
        relay: Option<RelayPool>,
    },
    Tcp(Pool),
    Tls(Pool),
    Https(Box<Doh>),
    /// REQ: UPS-002 (T7.7) — DNS over QUIC.
    Quic(Box<Doq>),
    /// REQ: UPS-002 (T7.8) — DoH over HTTP/3.
    H3(Box<Doh3>),
    /// REQ: UPS-012 (T7.15) — our own iterative resolver.
    Recursive(Box<wrendns_recursor::Recursor>),
    /// REQ: UPS-003 (T7.24) — DNSCrypt v2.
    DnsCrypt(Box<crate::dnscrypt::DnsCrypt>),
    /// REQ: UPS-011 (T7.16) — a plugin on a Unix socket; for `exec://`, with the process
    /// that serves it.
    Plugin(
        Pool,
        #[allow(dead_code)] // held for its Drop, which stops the process
        Option<crate::plugin::Supervisor>,
    ),
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Udp { .. } => "Udp",
            Self::Tcp(_) => "Tcp",
            Self::Tls(_) => "Tls",
            Self::Https(_) => "Https",
            Self::Quic(_) => "Quic",
            Self::H3(_) => "H3",
            Self::Recursive(_) => "Recursive",
            Self::Plugin(..) => "Plugin",
            Self::DnsCrypt(_) => "DnsCrypt",
        })
    }
}

/// A configured upstream.
#[derive(Debug)]
pub struct Upstream {
    /// Small stable ID for telemetry (index in config order, starting at 1).
    pub id: u16,
    pub name: String,
    pub endpoint: Endpoint,
    /// Per-attempt timeout ceiling.
    pub timeout: Duration,
    pub weight: u32,
    pub health: Health,
    target: Arc<Target>,
    transport: Transport,
    /// REQ: DNS-015 — the ECS option added to every query (substitute mode).
    ecs: Option<Vec<u8>>,
    /// REQ: DNS-015 (T9.9) — send the client's subnet (`ecs = "client"`).
    pub ecs_client: bool,
    /// REQ: OBS-020 — see [`UpstreamOptions::self_probe`].
    self_probe: bool,
    /// REQ: UPS-008 — connections opened and closed (TCP, DoT, DoH, and UDP's TCP fallback).
    conns: Arc<ConnStats>,
    /// REQ: UPS-006 (fork #25) — whether this node has a route to the address: 0 = not known (a
    /// hostname, or not yet checked), 1 = routed, 2 = the family has no route. Set by
    /// [`Self::check_route`], off the DNS path.
    route: AtomicU8,
}

/// REQ: UPS-006 — whether this node can route to an upstream's address (fork #25).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteState {
    /// A hostname, a local socket, or not checked yet.
    Unknown,
    Routed,
    /// No route for the address family: the reason is [`RouteState::reason`].
    NoRoute {
        v6: bool,
    },
}

impl RouteState {
    /// What the UI and the map say; `None` when there is nothing to say.
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Self::NoRoute { v6: true } => Some("this node has no IPv6 route"),
            Self::NoRoute { v6: false } => Some("this node has no IPv4 route"),
            _ => None,
        }
    }
}

/// REQ: UPS-006 — `connect()` on a UDP socket picks a route and sends nothing, so it answers
/// "does this host have a route to `ip`" without any traffic. An error (no route, no network,
/// the family disabled) means no route.
pub fn route_to(ip: std::net::IpAddr) -> bool {
    let local = match ip {
        std::net::IpAddr::V4(_) => std::net::SocketAddr::from(([0u8; 4], 0)),
        std::net::IpAddr::V6(_) => std::net::SocketAddr::from(([0u16; 8], 0)),
    };
    std::net::UdpSocket::bind(local)
        .and_then(|s| s.connect(SocketAddr::new(ip, 53)))
        .is_ok()
}

/// A TCP stream to the target: directly, or through the proxy (REQ: UPS-010), which gets a
/// hostname as is, so it resolves it.
async fn open_tcp(target: &Target, proxy: Option<&crate::proxy::Proxy>) -> io::Result<TcpStream> {
    let s = if let Some(p) = proxy {
        let dest = match &target.host {
            Host::Ip(ip) => crate::proxy::Dest::Addr(SocketAddr::new(*ip, target.port)),
            Host::Name(n) => crate::proxy::Dest::Name(n.clone(), target.port),
        };
        p.connect(&dest).await?
    } else {
        let addr = target.addr().await.map_err(io::Error::other)?;
        match &target.source {
            // REQ: UPS-013 — bound before connect, so the connection leaves from that address.
            Some(src) => {
                let sock = if addr.is_ipv4() {
                    TcpSocket::new_v4()?
                } else {
                    TcpSocket::new_v6()?
                };
                let local = src.bind_addr()?;
                src.note(sock.bind(local))?;
                sock.connect(addr).await?
            }
            None => TcpStream::connect(addr).await?,
        }
    };
    s.set_nodelay(true)?;
    Ok(s)
}

fn tcp_connector(target: Arc<Target>, proxy: Option<Arc<crate::proxy::Proxy>>) -> Connector {
    Arc::new(move || {
        let (target, proxy) = (Arc::clone(&target), proxy.clone());
        Box::pin(async move { Ok(Box::new(open_tcp(&target, proxy.as_deref()).await?) as BoxIo) })
    })
}

fn unix_connector(path: std::path::PathBuf) -> Connector {
    Arc::new(move || {
        let path = path.clone();
        Box::pin(
            async move { Ok(Box::new(tokio::net::UnixStream::connect(&path).await?) as BoxIo) },
        )
    })
}

fn tls_connector(
    target: Arc<Target>,
    cfg: Arc<rustls::ClientConfig>,
    name: ServerName<'static>,
    proxy: Option<Arc<crate::proxy::Proxy>>,
    stats: Arc<ConnStats>,
) -> Connector {
    let c = tls_connector_alpn(target, cfg, name, proxy, stats, false);
    Arc::new(move || {
        let f = c();
        Box::pin(async move { f.await.map(|(io, _)| io) })
    })
}

/// A TLS connector that also says whether the server selected HTTP/2 (`h2`) in ALPN. A server
/// that selects nothing is read as HTTP/1.1 when `http11` was offered (RFC 9110 practice), and as
/// HTTP/2 when it was not (the only protocol offered).
fn tls_connector_alpn(
    target: Arc<Target>,
    cfg: Arc<rustls::ClientConfig>,
    name: ServerName<'static>,
    proxy: Option<Arc<crate::proxy::Proxy>>,
    stats: Arc<ConnStats>,
    http11: bool,
) -> crate::doh::DohConnector {
    let tls = tokio_rustls::TlsConnector::from(cfg);
    Arc::new(move || {
        let (target, tls, name, proxy, stats) = (
            Arc::clone(&target),
            tls.clone(),
            name.clone(),
            proxy.clone(),
            Arc::clone(&stats),
        );
        Box::pin(async move {
            let s = open_tcp(&target, proxy.as_deref()).await?;
            let s = tls.connect(name, s).await?;
            // A resumed session saves a round trip; rustls keeps the tickets per ClientConfig.
            stats.tls(matches!(
                s.get_ref().1.handshake_kind(),
                Some(rustls::HandshakeKind::Resumed)
            ));
            let h2 = match s.get_ref().1.alpn_protocol() {
                Some(p) => p == b"h2",
                None => !http11,
            };
            Ok((Box::new(s) as BoxIo, h2))
        })
    })
}

impl Upstream {
    /// REQ: UPS-013 — the source address sockets are bound to, if one is set.
    pub fn source(&self) -> Option<std::net::IpAddr> {
        self.target.source.as_ref().and_then(Source::ip)
    }

    /// REQ: UPS-013 — set while binding the source address fails because this node no longer
    /// holds it (a health reason; cleared by the next successful bind).
    pub fn source_problem(&self) -> Option<String> {
        self.target.source.as_ref()?.problem()
    }

    /// An upstream with default options apart from timeout and weight (tests, embedding).
    pub fn new(
        id: u16,
        name: impl Into<String>,
        endpoint: Endpoint,
        timeout: Duration,
        weight: u32,
    ) -> Result<Self, String> {
        let opts = UpstreamOptions {
            timeout,
            weight,
            ..UpstreamOptions::default()
        };
        Self::build(id, name, endpoint, &opts, &TlsOptions::default())
    }

    /// Builds any upstream. Fails on invalid TLS names, headers, or missing bootstrap.
    #[allow(clippy::too_many_lines)] // one arm per protocol
    pub fn build(
        id: u16,
        name: impl Into<String>,
        endpoint: Endpoint,
        opts: &UpstreamOptions,
        tls: &TlsOptions,
    ) -> Result<Self, String> {
        let name = name.into();
        // REQ: UPS-010 — TCP-based protocols, and (T9.9) UDP through a SOCKS5 proxy's UDP
        // ASSOCIATE relay.
        let socks5 = matches!(
            opts.proxy.as_deref(),
            Some(crate::proxy::Proxy::Socks5 { .. })
        );
        if opts.proxy.is_some()
            && !matches!(
                endpoint.protocol,
                Protocol::Tcp | Protocol::Tls | Protocol::Https
            )
            && !(endpoint.protocol == Protocol::Udp && socks5)
        {
            return Err(format!(
                "upstream `{name}`: a proxy works with tcp://, tls://, and https:// upstreams, or udp:// through a socks5:// proxy (use tcp:// with an HTTP proxy)"
            ));
        }
        if matches!(endpoint.host, Host::Name(_))
            && opts.bootstrap.is_none()
            && opts.proxy.is_none()
            && !matches!(
                endpoint.protocol,
                Protocol::Recursive | Protocol::Unix | Protocol::Exec
            )
        {
            return Err(format!(
                "upstream `{name}`: hostname URL needs bootstrap servers"
            ));
        }
        // REQ: UPS-013 — a source address for the protocols that bind it, and one that fits the
        // server's address family.
        let mut source = None;
        if opts.source.is_some() || opts.source_spec.is_some() {
            if !matches!(
                endpoint.protocol,
                Protocol::Udp | Protocol::Tcp | Protocol::Tls | Protocol::Https
            ) || opts.proxy.is_some()
            {
                return Err(format!(
                    "upstream `{name}`: `source` works with udp://, tcp://, tls://, and https:// upstreams, without a proxy"
                ));
            }
            let spec = opts
                .source_spec
                .clone()
                .or_else(|| opts.source.map(|ip| ip.to_string()))
                .unwrap_or_default();
            let src = Source::new(&spec, opts.source, &name)
                .map_err(|e| format!("upstream `{name}`: {e}"))?;
            if let Host::Ip(host) = &endpoint.host
                && host.is_ipv4() != src.v4
            {
                return Err(format!(
                    "upstream `{name}`: source {spec} and server {host} are not the same IP version"
                ));
            }
            source = Some(src);
        }
        let target = Arc::new(Target {
            host: endpoint.host.clone(),
            port: endpoint.port,
            bootstrap: opts.bootstrap.clone(),
            source,
        });
        // TLS name to verify: tls_server_name, else the URL host (DNS name or IP literal).
        let tls_name = match (&opts.tls_server_name, &endpoint.host) {
            (Some(n), _) => n.clone(),
            (None, Host::Name(h)) => h.clone(),
            (None, Host::Ip(ip)) => ip.to_string(),
        };
        let conns = Arc::new(ConnStats::default());
        let pool = |c: Connector| {
            Pool::new(
                counted(c, Arc::clone(&conns)),
                opts.pool_size,
                opts.idle_timeout,
                Arc::clone(&conns),
            )
        };
        let transport = match endpoint.protocol {
            Protocol::Udp => Transport::Udp {
                // REQ: UPS-010 (T9.9) — with a SOCKS5 proxy, UDP goes through its relay and a
                // truncated answer's TCP retry through the proxy too.
                tcp: pool(tcp_connector(Arc::clone(&target), opts.proxy.clone())),
                relay: opts.proxy.clone().map(RelayPool::new),
            },
            Protocol::Tcp => {
                Transport::Tcp(pool(tcp_connector(Arc::clone(&target), opts.proxy.clone())))
            }
            Protocol::Tls => {
                let cfg = client_config(tls, &opts.tls, &[], opts.tls_insecure_skip_verify)
                    .map_err(|e| e.to_string())?;
                Transport::Tls(pool(tls_connector(
                    Arc::clone(&target),
                    cfg,
                    server_name(&tls_name)?,
                    opts.proxy.clone(),
                    Arc::clone(&conns),
                )))
            }
            Protocol::Https => {
                // REQ: UPS-001 — `h2` first, then `http/1.1` (unless `http_version = "2"`): the
                // server chooses, and a server that only speaks HTTP/1.1 still works.
                let http11 = !opts.doh_h2_only;
                let alpn: &[&[u8]] = if http11 {
                    &[b"h2", b"http/1.1"]
                } else {
                    &[b"h2"]
                };
                let cfg = client_config(tls, &opts.tls, alpn, opts.tls_insecure_skip_verify)
                    .map_err(|e| e.to_string())?;
                let host = match (&opts.tls_server_name, &endpoint.host) {
                    (None, Host::Ip(std::net::IpAddr::V6(ip))) => format!("[{ip}]"),
                    _ => tls_name.clone(),
                };
                let authority = if endpoint.port == 443 {
                    host
                } else {
                    format!("{host}:{}", endpoint.port)
                };
                let conn = counted(
                    tls_connector_alpn(
                        Arc::clone(&target),
                        cfg,
                        server_name(&tls_name)?,
                        opts.proxy.clone(),
                        Arc::clone(&conns),
                        http11,
                    ),
                    Arc::clone(&conns),
                );
                Transport::Https(Box::new(Doh::new(
                    conn,
                    &authority,
                    &endpoint.path,
                    &opts.headers,
                    opts.doh_get,
                    opts.pool_size,
                    opts.idle_timeout,
                )?))
            }
            Protocol::H3 => {
                let cfg = client_config(tls, &opts.tls, &[b"h3"], opts.tls_insecure_skip_verify)
                    .map_err(|e| e.to_string())?;
                let host = match (&opts.tls_server_name, &endpoint.host) {
                    (None, Host::Ip(std::net::IpAddr::V6(ip))) => format!("[{ip}]"),
                    _ => tls_name.clone(),
                };
                let authority = if endpoint.port == 443 {
                    host
                } else {
                    format!("{host}:{}", endpoint.port)
                };
                let t = Arc::clone(&target);
                let resolve: crate::doq::Resolve = Arc::new(move || {
                    let t = Arc::clone(&t);
                    Box::pin(async move { t.addr().await })
                });
                Transport::H3(Box::new(Doh3::new(
                    resolve,
                    cfg,
                    &server_name(&tls_name)?,
                    &authority,
                    &endpoint.path,
                    &opts.headers,
                    opts.idle_timeout,
                )?))
            }
            Protocol::Recursive => Transport::Recursive(Box::new(wrendns_recursor::Recursor::new(
                opts.recursive.clone(),
            ))),
            Protocol::DnsCrypt => {
                let (pk, name) = opts
                    .dnscrypt
                    .clone()
                    .ok_or_else(|| format!("upstream `{name}`: DNSCrypt needs a stamp"))?;
                let addr = match endpoint.host {
                    Host::Ip(ip) => SocketAddr::new(ip, endpoint.port),
                    Host::Name(_) => {
                        return Err(format!(
                            "upstream `{name}`: DNSCrypt stamps carry an address"
                        ));
                    }
                };
                Transport::DnsCrypt(Box::new(crate::dnscrypt::DnsCrypt::new(
                    addr,
                    pk,
                    &name,
                    opts.dnscrypt_relay,
                )?))
            }
            Protocol::Unix => {
                Transport::Plugin(pool(unix_connector(endpoint.path.clone().into())), None)
            }
            Protocol::Exec => {
                let dir = opts
                    .plugin_dir
                    .clone()
                    .unwrap_or_else(|| std::env::temp_dir().join("wrendns-plugins"));
                let safe: String = name
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect();
                let socket = dir.join(format!("{safe}.sock"));
                let sup = crate::plugin::supervise(
                    &name,
                    endpoint.path.clone().into(),
                    opts.plugin_args.clone(),
                    socket.clone(),
                );
                Transport::Plugin(pool(unix_connector(socket)), Some(sup))
            }
            Protocol::Quic => {
                let cfg = client_config(tls, &opts.tls, &[b"doq"], opts.tls_insecure_skip_verify)
                    .map_err(|e| e.to_string())?;
                let t = Arc::clone(&target);
                let resolve: crate::doq::Resolve = Arc::new(move || {
                    let t = Arc::clone(&t);
                    Box::pin(async move { t.addr().await })
                });
                Transport::Quic(Box::new(Doq::new(
                    resolve,
                    cfg,
                    &server_name(&tls_name)?,
                    opts.idle_timeout,
                )?))
            }
        };
        Ok(Self {
            id,
            name,
            endpoint,
            timeout: opts.timeout,
            weight: opts.weight.max(1),
            health: Health::default(),
            target,
            transport,
            ecs: opts.ecs.clone(),
            ecs_client: opts.ecs_client,
            self_probe: opts.self_probe,
            conns,
            route: AtomicU8::new(0),
        })
    }

    /// REQ: UPS-006 — re-checks the route to a literal address (a cheap syscall, no traffic).
    /// Called at start and on a timer by the node, never on the query path.
    pub fn check_route(&self) {
        if let Host::Ip(ip) = &self.endpoint.host
            && !matches!(self.endpoint.protocol, Protocol::Unix | Protocol::Exec)
        {
            self.route
                .store(if route_to(*ip) { 1 } else { 2 }, Ordering::Relaxed);
        }
    }

    /// REQ: UPS-006 — the last route check.
    pub fn route_state(&self) -> RouteState {
        match (self.route.load(Ordering::Relaxed), &self.endpoint.host) {
            (1, _) => RouteState::Routed,
            (2, Host::Ip(ip)) => RouteState::NoRoute { v6: ip.is_ipv6() },
            _ => RouteState::Unknown,
        }
    }

    /// REQ: UPS-008 — this upstream's connection counters.
    pub fn connections(&self) -> &ConnStats {
        &self.conns
    }

    /// REQ: UPS-006 — one active health check. A stub upstream (DNS-022) is up by
    /// [`Self::stub_liveness`]; any other asks [`Self::health_question`] as a client would.
    pub async fn health_check(&self) {
        let t0 = Instant::now();
        if let Some(up) = self.stub_liveness().await {
            let (outcome, latency) = if up {
                (Outcome::Ok, t0.elapsed())
            } else {
                (Outcome::Timeout, t0.elapsed().max(self.attempt_timeout()))
            };
            self.health.record_outcome(outcome, latency, Instant::now());
            return;
        }
        let _ = self
            .exchange(&self.health_question(), self.attempt_timeout())
            .await;
    }

    /// REQ: DNS-905 (T40.4) — empties a `recursive://` upstream's zone cuts (`cuts`) and/or
    /// server round-trip times (`rtts`); returns how many entries went, or `None` for an
    /// upstream that isn't our own resolver.
    pub fn flush_recursor(&self, cuts: bool, rtts: bool) -> Option<usize> {
        match &self.transport {
            Transport::Recursive(r) => Some(r.flush(cuts, rtts)),
            _ => None,
        }
    }

    /// REQ: UPS-006, DNS-022 — a stub upstream's liveness: one of its servers answers the zone's
    /// SOA (a refusal counts, since authoritative servers may refuse even the apex they delegate
    /// from; a SERVFAIL doesn't). The one rule behind the active check and the draft-upstream
    /// check. `None` for an upstream that isn't a stub.
    pub async fn stub_liveness(&self) -> Option<bool> {
        match &self.transport {
            Transport::Recursive(r) => r.probe_stub().await,
            _ => None,
        }
    }

    /// REQ: UPS-006, DNS-022 — what a health check asks: a stub zone's SOA (its servers are
    /// authoritative only and refuse anything else), else the root's NS records.
    pub fn health_question(&self) -> Question {
        let stub = match &self.transport {
            Transport::Recursive(r) => r.stub_zone().copied(),
            _ => None,
        };
        Question {
            name: stub.unwrap_or_default(),
            qtype: if stub.is_some() {
                wrendns_proto::rtype::SOA
            } else {
                wrendns_proto::rtype::NS
            },
            qclass: wrendns_proto::class::IN,
            dnssec_ok: false,
            checking_disabled: false,
            client_subnet: 0,
        }
    }

    /// Per-attempt timeout: min(configured, 3 × EWMA + 50 ms, 1 s) per `spec/04` §4.
    pub fn attempt_timeout(&self) -> Duration {
        // REQ: DNS-012 — a cold recursion walks several servers: give it the time it needs
        // (the query's overall budget still bounds it).
        if matches!(self.transport, Transport::Recursive(_)) {
            return self.timeout.max(Duration::from_secs(3));
        }
        let adaptive = self
            .health
            .ewma()
            .map_or(self.timeout, |e| e * 3 + Duration::from_millis(50));
        self.timeout.min(adaptive).min(Duration::from_secs(1))
    }

    /// REQ: UPS-006 (ADR-165) — the timeout of an attempt; `patient` for the last healthy
    /// member a query tries. The adaptive bound in [`Self::attempt_timeout`] exists to give up
    /// on one member and try another; with none left to try, it would only turn a slow answer
    /// (a name the upstream had to resolve itself, often several hundred milliseconds to over a
    /// second) into SERVFAIL. So that attempt may use the query's whole budget, like a
    /// recursive upstream's; the caller bounds it by what's left. `timeout_ms` (400 ms by
    /// default) still bounds the attempts that have a member to hand over to.
    pub fn timeout_for(&self, patient: bool) -> Duration {
        if patient {
            self.attempt_timeout().max(crate::DEFAULT_BUDGET)
        } else {
            self.attempt_timeout()
        }
    }

    /// How long to wait before hedging to the next upstream (ADR-013): about 3 × EWMA,
    /// bounded to [20 ms, attempt timeout]; 100 ms until there is data.
    pub fn hedge_delay(&self) -> Duration {
        let d = self.health.ewma().map_or(Duration::from_millis(100), |e| {
            e * 3 + Duration::from_millis(10)
        });
        d.clamp(Duration::from_millis(20), self.attempt_timeout())
    }

    /// Open pooled connections (TCP/DoT), for tests and metrics.
    pub fn pooled_connections(&self) -> usize {
        match &self.transport {
            Transport::Udp { tcp, .. } => tcp.len(),
            Transport::Tcp(p) | Transport::Tls(p) | Transport::Plugin(p, _) => p.len(),
            Transport::Https(_)
            | Transport::Quic(_)
            | Transport::H3(_)
            | Transport::Recursive(_)
            | Transport::DnsCrypt(_) => 0,
        }
    }

    /// Sends `q` and returns a validated response. Records the outcome in `health`: NOERROR
    /// and NXDOMAIN are successes; SERVFAIL/REFUSED and transport errors are failures.
    pub async fn exchange(
        &self,
        q: &Question,
        timeout: Duration,
    ) -> Result<Vec<u8>, ExchangeError> {
        let start = Instant::now();
        let result = self.exchange_inner(q, timeout).await;
        // REQ: UPS-006, OBS-011 — what went wrong, not only that something did.
        let outcome = match &result {
            Ok(resp) => match summarize(resp).map_or(rcode::SERVFAIL, |s| s.rcode) {
                rcode::NOERROR | rcode::NXDOMAIN => Outcome::Ok,
                rcode::SERVFAIL => Outcome::ServFail,
                rcode::REFUSED => Outcome::Refused,
                _ => Outcome::OtherRcode,
            },
            Err(ExchangeError::Timeout) => Outcome::Timeout,
            Err(ExchangeError::Io(_)) => Outcome::Network,
            Err(ExchangeError::BadResponse) => Outcome::BadResponse,
            Err(ExchangeError::Unresolved) => Outcome::Unresolved,
        };
        // A failure that is no answer counts as the whole timeout (a dead upstream sorts behind
        // slow ones); a SERVFAIL or REFUSED came back in the time it took (review 03-04).
        let latency = if outcome == Outcome::Ok || outcome.is_answer() {
            start.elapsed()
        } else {
            start.elapsed().max(timeout)
        };
        self.health.record_outcome(outcome, latency, Instant::now());
        result
    }

    /// One exchange within `timeout`. Over UDP, a truncated answer's TCP retry gets the
    /// configured timeout of its own: the adaptive one is calibrated on small UDP answers, and
    /// large ones (DNSKEY sets with signatures, long TXT) would never fit in it.
    async fn exchange_inner(
        &self,
        q: &Question,
        timeout: Duration,
    ) -> Result<Vec<u8>, ExchangeError> {
        // DoH uses ID 0 (RFC 8484 §4.1, cache-friendly) and DoQ must (RFC 9250 §4.2.1); the
        // stream identifies the response.
        let id: u16 = if matches!(
            self.transport,
            Transport::Https(_) | Transport::Quic(_) | Transport::H3(_)
        ) {
            0
        } else {
            rand::random()
        };
        let mut buf = [0u8; 512];
        // REQ: DNS-015 (T9.9) — the client's subnet, when this upstream passes it on.
        let client = if self.ecs_client {
            ecs_for_client(q.client_subnet)
        } else {
            None
        };
        let ecs = client
            .as_deref()
            .or(self.ecs.as_deref())
            .unwrap_or_default();
        let len = encode_query_with(q, id, &mut buf, ecs, !self.self_probe)
            .ok_or(ExchangeError::BadResponse)?;
        let query = &buf[..len];
        // REQ: OBS-007 (T9.19) — dnstap's forwarder messages, when observed (not for our own
        // resolver, whose queries go to many servers).
        let observer = OBSERVER
            .get()
            .filter(|_| !self.self_probe && !matches!(self.transport, Transport::Recursive(_)));
        let sent = observer.map(|_| std::time::SystemTime::now());
        let result = self.send(query, id, timeout).await;
        if let (Some(obs), Some(sent)) = (observer, sent) {
            let addr = match &self.transport {
                Transport::Plugin(..) => None,
                _ => self.target.addr().await.ok(),
            };
            obs(&Exchange {
                protocol: self.endpoint.protocol,
                addr,
                query,
                response: result.as_ref().ok().map(Vec::as_slice),
                sent,
            });
        }
        let resp = result?;
        if matches_query(&resp, query, id) && summarize(&resp).is_ok() {
            Ok(resp)
        } else {
            Err(ExchangeError::BadResponse)
        }
    }

    /// Sends `query` over this upstream's transport and returns what came back.
    async fn send(
        &self,
        query: &[u8],
        id: u16,
        timeout: Duration,
    ) -> Result<Vec<u8>, ExchangeError> {
        let resp = match &self.transport {
            Transport::Udp { tcp, relay } => {
                let udp = async {
                    let addr = self.target.addr().await?;
                    match relay {
                        Some(r) => r.exchange(addr, query, id).await,
                        None => udp_exchange(addr, query, id, self.target.source.as_ref()).await,
                    }
                };
                let resp = timed(tokio::time::timeout(timeout, udp).await)?;
                if header::flags(&resp).tc() {
                    // Truncated: retry over TCP (RFC 7766 §1), with time of its own.
                    let t = self.timeout.max(timeout);
                    timed(tokio::time::timeout(t, tcp.exchange(query.to_vec(), id)).await)?
                } else {
                    resp
                }
            }
            Transport::Tcp(pool) | Transport::Tls(pool) | Transport::Plugin(pool, _) => {
                timed(tokio::time::timeout(timeout, pool.exchange(query.to_vec(), id)).await)?
            }
            Transport::Https(doh) => {
                timed(tokio::time::timeout(timeout, doh.exchange(query)).await)?
            }
            Transport::Quic(doq) => {
                timed(tokio::time::timeout(timeout, doq.exchange(query)).await)?
            }
            Transport::H3(h3) => timed(tokio::time::timeout(timeout, h3.exchange(query)).await)?,
            Transport::DnsCrypt(d) => d.exchange(query, timeout).await?,
            Transport::Recursive(r) => tokio::time::timeout(timeout, r.answer(query))
                .await
                .map_err(|_| ExchangeError::Timeout)?
                .map_err(|e| {
                    tracing::debug!(error = %e, "recursion failed");
                    ExchangeError::BadResponse
                })?,
        };
        Ok(resp)
    }
}

/// A timed-out exchange is a timeout.
fn timed(
    r: Result<Result<Vec<u8>, ExchangeError>, tokio::time::error::Elapsed>,
) -> Result<Vec<u8>, ExchangeError> {
    r.unwrap_or(Err(ExchangeError::Timeout))
}

/// REQ: UPS-010 (T9.9) — SOCKS5 UDP associations kept for reuse (a few, each used by one
/// query at a time); one that fails is dropped and a new one made next time.
pub(crate) struct RelayPool {
    proxy: Arc<crate::proxy::Proxy>,
    idle: parking_lot::Mutex<Vec<crate::proxy::UdpRelay>>,
}

impl std::fmt::Debug for RelayPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayPool")
            .field("proxy", &self.proxy)
            .finish_non_exhaustive()
    }
}

impl RelayPool {
    fn new(proxy: Arc<crate::proxy::Proxy>) -> Self {
        Self {
            proxy,
            idle: parking_lot::Mutex::new(Vec::new()),
        }
    }

    async fn exchange(
        &self,
        dest: SocketAddr,
        query: &[u8],
        id: u16,
    ) -> Result<Vec<u8>, ExchangeError> {
        let held = self.idle.lock().pop();
        let relay = match held {
            Some(r) => r,
            None => self.proxy.udp_associate().await?,
        };
        let resp = relay.exchange(dest, query, id).await?;
        let mut idle = self.idle.lock();
        if idle.len() < 4 {
            idle.push(relay);
        }
        Ok(resp)
    }
}

async fn udp_exchange(
    addr: SocketAddr,
    query: &[u8],
    id: u16,
    source: Option<&Source>,
) -> Result<Vec<u8>, ExchangeError> {
    // A fresh socket per query gives a random source port (RFC 5452). REQ: UPS-013 — with a
    // source address, the socket is bound to it (port 0: still random).
    let sock = if let Some(src) = source {
        {
            let local = src.bind_addr()?;
            src.note(UdpSocket::bind(local).await)?
        }
    } else {
        let bind: SocketAddr = if addr.is_ipv4() {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        UdpSocket::bind(bind).await?
    };
    sock.connect(addr).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await?;
        if matches_query(&buf[..n], query, id) && summarize(&buf[..n]).is_ok() {
            buf.truncate(n);
            return Ok(buf);
        }
        // Mismatched or malformed: ignore and keep waiting (possible spoofing attempt).
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DNS-015 (T7.23) — the substitute ECS option (RFC 7871 §6): family, prefix, scope
    /// 0, the address cut to the prefix; appended to the query's OPT with the right length.
    #[test]
    fn dns_015_ecs_client_subnet() {
        let p = client_subnet("203.0.113.77".parse().unwrap());
        assert_ne!(p, 0);
        assert_eq!(p, client_subnet("203.0.113.1".parse().unwrap()), "same /24");
        assert_ne!(p, client_subnet("203.0.114.1".parse().unwrap()));
        assert_eq!(
            p,
            client_subnet("::ffff:203.0.113.9".parse().unwrap()),
            "v4-mapped"
        );
        assert_eq!(
            ecs_for_client(p).unwrap(),
            ecs_option("203.0.113.0".parse().unwrap(), 24)
        );
        let v6 = client_subnet("2001:db8:abcd:ef01::1".parse().unwrap());
        assert_eq!(
            v6,
            client_subnet("2001:db8:abcd:efff::2".parse().unwrap()),
            "same /56"
        );
        assert_eq!(
            ecs_for_client(v6).unwrap(),
            ecs_option("2001:db8:abcd:ef00::".parse().unwrap(), 56)
        );
        for private in [
            "10.1.2.3",
            "10.30.3.2",
            "172.16.0.1",
            "127.0.0.1",
            "100.64.1.1",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
            "::1",
        ] {
            assert_eq!(client_subnet(private.parse().unwrap()), 0, "{private}");
        }
        assert!(ecs_for_client(0).is_none());
    }

    #[test]
    fn dns_015_ecs_substitute() {
        let o = ecs_option("203.0.113.77".parse().unwrap(), 24);
        assert_eq!(o, vec![0, 8, 0, 7, 0, 1, 24, 0, 203, 0, 113]);
        let o = ecs_option("2001:db8:abcd:ef01::1".parse().unwrap(), 50);
        assert_eq!(&o[4..8], &[0, 2, 50, 0]);
        assert_eq!(
            &o[8..],
            &[0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0xc0],
            "the last byte keeps 2 bits"
        );
        let q = Question {
            name: wrendns_proto::NameBuf::from_presentation("example.com").unwrap(),
            qtype: wrendns_proto::rtype::A,
            qclass: 1,
            dnssec_ok: false,
            checking_disabled: false,
            client_subnet: 0,
        };
        let mut buf = [0u8; 512];
        let ecs = ecs_option("203.0.113.0".parse().unwrap(), 24);
        let len = encode_query_with(&q, 7, &mut buf, &ecs, true).unwrap();
        let parsed = wrendns_proto::parse_query(&buf[..len]).unwrap();
        let edns = parsed.edns.unwrap();
        assert_eq!(edns.client_subnet(), Some(&ecs[4..]));
        // Without an option, no ECS (strip).
        let len = encode_query(&q, 7, &mut buf).unwrap();
        let parsed = wrendns_proto::parse_query(&buf[..len]).unwrap();
        assert!(parsed.edns.unwrap().client_subnet().is_none());
    }

    /// REQ: OBS-020 (T11.3) — a self-probe carries no loop tag, so this node's own listener
    /// answers it instead of dropping it as a forwarding loop; ordinary queries carry it.
    #[test]
    fn obs_020_self_probes_carry_no_loop_tag() {
        set_node_tag(0x5EED);
        let q = Question {
            name: wrendns_proto::NameBuf::from_presentation("probe.wrendns.invalid").unwrap(),
            qtype: wrendns_proto::rtype::A,
            qclass: 1,
            dnssec_ok: false,
            checking_disabled: false,
            client_subnet: 0,
        };
        let mut buf = [0u8; 512];
        let len = encode_query_with(&q, 7, &mut buf, &[], true).unwrap();
        assert!(is_own_loop_tag(
            &wrendns_proto::parse_query(&buf[..len]).unwrap()
        ));
        let len = encode_query_with(&q, 7, &mut buf, &[], false).unwrap();
        assert!(!is_own_loop_tag(
            &wrendns_proto::parse_query(&buf[..len]).unwrap()
        ));
    }

    /// REQ: UPS-006 (fork #25) — the route check is a `connect()` with no traffic: loopback is
    /// routed, a hostname is not checked, and the reasons name the family.
    #[test]
    fn ups_006_route_check() {
        assert!(route_to("127.0.0.1".parse().unwrap()));
        let ep = Endpoint::parse("udp://127.0.0.1").unwrap();
        let u = Upstream::new(1, "lo", ep, Duration::from_secs(1), 1).unwrap();
        assert_eq!(u.route_state(), RouteState::Unknown, "not checked yet");
        u.check_route();
        assert_eq!(u.route_state(), RouteState::Routed);
        let ep = Endpoint::parse("tls://dns.example.net").unwrap();
        let named = Upstream::new(2, "n", ep, Duration::from_secs(1), 1);
        if let Ok(n) = named {
            n.check_route();
            assert_eq!(
                n.route_state(),
                RouteState::Unknown,
                "a hostname is never checked"
            );
        }
        assert_eq!(
            RouteState::NoRoute { v6: true }.reason(),
            Some("this node has no IPv6 route")
        );
        assert_eq!(
            RouteState::NoRoute { v6: false }.reason(),
            Some("this node has no IPv4 route")
        );
        assert_eq!(RouteState::Routed.reason(), None);
    }
}

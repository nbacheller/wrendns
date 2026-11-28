// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904, CLD-919 (T36.10b step b5; ADR-1084 as amended 2026-11-27, ADR-1115) - the
//! authoritative lookup: ask a zone's own name servers a question, never the node's local data or
//! its cache.
//!
//! The node owns the location subtree and answers it from local data, so a check that asked the
//! node's own resolver whether a CNAME or a TXT record exists at the DNS host would be answered by
//! the node itself (or by a cache). This helper therefore:
//!
//! 1. finds the zone's name servers by asking the *configured upstreams* (the [`Upstreams`] seam;
//!    production uses the default upstream group, which neither reads local records nor the cache)
//!    for the zone's `NS` set and for each server's `A` and `AAAA` addresses, then
//! 2. asks each of those servers directly (UDP, with TCP on truncation), without recursion, and
//!    believes only an answer that matches the question it sent.
//!
//! It is shared by the delegation check (`dns_provider::delegation`, T36.10b step b5) and by the
//! propagation check of the ACME order (T36.10d), which asks the same servers for the TXT value.
//!
//! Everything is bounded: a time per try, a number of tries, a total time, the number of servers and
//! addresses asked, and the size of an answer. It is async and runs on the management path (awaited in the API
//! request that asked for it, sharing the node's runtime), never on the query path (CLU-004), and a failure is a reason to show, never a DNS answer.
//! Addresses that are not public (loopback, private, link-local, unique-local, multicast,
//! unspecified, shared address space) are never asked, whatever the upstreams say a name server's
//! address is, so a hostile zone cannot aim the node at its own network (the recursor's rule too).

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, UdpSocket};
use wrendns_proto::{
    EdnsOut, NameBuf, Section, build_query, class, header, read_name, records, rtype,
};
use wrendns_upstream::{Group, Question};

/// The UDP payload size the query advertises (DNS flag day 2020).
const UDP_PAYLOAD: u16 = 1232;

/// The bounds of one lookup.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// How long one try of one server may take.
    pub(crate) per_try: Duration,
    /// Tries per server over UDP before it counts as unreachable.
    pub(crate) tries: u32,
    /// How long a whole lookup (finding the servers and asking them all) may take.
    pub(crate) total: Duration,
    /// The most server addresses asked.
    pub(crate) max_servers: usize,
    /// The largest answer believed, in bytes.
    pub(crate) max_answer: usize,
    /// The port the authoritative servers are asked on (53; tests use another).
    pub(crate) port: u16,
    /// Ask addresses that are not public too. Only the tests set this: their servers are on
    /// loopback.
    pub(crate) allow_private: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_try: Duration::from_secs(3),
            tries: 2,
            total: Duration::from_secs(20),
            max_servers: 8,
            max_answer: 8 * 1024,
            port: 53,
            allow_private: false,
        }
    }
}

/// Why a lookup did not give an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LookupError {
    /// The upstreams did not answer, or answered something unusable.
    Upstream(String),
    /// The zone has no name server this node may ask.
    NoServers(String),
    /// The lookup ran past its total time.
    Timeout,
    /// One server did not answer in the tries allowed.
    Unreachable(String),
    /// One server's answer was malformed, was not for the question, or was too large.
    Malformed(String),
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upstream(w) => write!(f, "the upstreams could not say: {w}"),
            Self::Timeout => f.write_str("the lookup ran out of time"),
            Self::NoServers(w) | Self::Unreachable(w) | Self::Malformed(w) => f.write_str(w),
        }
    }
}

/// A boxed future, as the seam returns.
pub(crate) type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What asks the configured upstreams a question: the whole message of the answer, or why not. The
/// production implementation is [`GroupUpstreams`]; tests supply canned answers.
pub(crate) trait Upstreams: Send + Sync {
    fn ask<'a>(&'a self, name: &'a str, qtype: u16) -> Fut<'a, Result<Vec<u8>, String>>;
}

/// The default upstream group as the seam: a question goes to the configured upstreams as it is, with
/// no local records and no cache in between.
pub(crate) struct GroupUpstreams {
    pub(crate) group: Arc<Group>,
    pub(crate) budget: Duration,
}

impl Upstreams for GroupUpstreams {
    fn ask<'a>(&'a self, name: &'a str, qtype: u16) -> Fut<'a, Result<Vec<u8>, String>> {
        Box::pin(async move {
            let name = NameBuf::from_presentation(name)
                .map_err(|_| format!("`{name}` is not a domain name"))?;
            let q = Question {
                name,
                qtype,
                qclass: class::IN,
                dnssec_ok: false,
                checking_disabled: false,
                client_subnet: 0,
            };
            self.group
                .resolve(q, self.budget)
                .await
                .map(|a| a.bytes)
                .map_err(|e| e.to_string())
        })
    }
}

/// A name server of a zone with the public addresses it may be asked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Server {
    pub(crate) name: String,
    pub(crate) addrs: Vec<IpAddr>,
}

/// One server's answer to one question.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    /// The response code.
    pub(crate) rcode: u8,
    /// The server answered with authority for the zone (the AA flag).
    pub(crate) aa: bool,
    msg: Vec<u8>,
}

fn lower(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn name_at(msg: &[u8], off: usize) -> Option<String> {
    let mut n = NameBuf::default();
    read_name(msg, off, &mut n).ok()?;
    Some(lower(&n.display().to_string()))
}

impl Reply {
    /// The targets of the CNAME records the answer section holds for `owner` (lowercase, no
    /// trailing dot).
    pub(crate) fn cnames(&self, owner: &str) -> Vec<String> {
        let owner = lower(owner);
        let mut out = Vec::new();
        for r in records(&self.msg).into_iter().flatten().flatten() {
            if r.section != Section::Answer
                || r.rtype != rtype::CNAME
                || r.rclass != class::IN
                || name_at(&self.msg, r.name_off).as_deref() != Some(owner.as_str())
            {
                continue;
            }
            if let Some(t) = name_at(&self.msg, r.rdata_off) {
                out.push(t);
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// The values of the TXT records the answer section holds for `owner` (the character strings
    /// of one record joined). The propagation check of the ACME order (T36.10d) reads these.
    #[allow(
        dead_code,
        reason = "the delegation check reads CNAMEs; the certificate issuer (T36.10d) reads TXT values and uses this"
    )]
    pub(crate) fn txts(&self, owner: &str) -> Vec<String> {
        let owner = lower(owner);
        let mut out = Vec::new();
        for r in records(&self.msg).into_iter().flatten().flatten() {
            if r.section != Section::Answer
                || r.rtype != rtype::TXT
                || r.rclass != class::IN
                || name_at(&self.msg, r.name_off).as_deref() != Some(owner.as_str())
            {
                continue;
            }
            let data = r.rdata(&self.msg);
            let mut text = Vec::new();
            let mut p = 0usize;
            while p < data.len() {
                let n = usize::from(data[p]);
                let Some(chunk) = data.get(p + 1..p + 1 + n) else {
                    break;
                };
                text.extend_from_slice(chunk);
                p += 1 + n;
            }
            out.push(String::from_utf8_lossy(&text).into_owned());
        }
        out.sort();
        out.dedup();
        out
    }
}

/// Whether an address may be asked: a public one (see the module comment).
pub(crate) fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_documentation()
                // 100.64.0.0/10, shared address space (CGNAT).
                || (o[0] == 100 && (o[1] & 0xC0) == 0x40)
                // 0.0.0.0/8 and 240.0.0.0/4.
                || o[0] == 0
                || o[0] >= 240)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                // fc00::/7 unique local, fe80::/10 link local, 2001:db8::/32 documentation.
                || (s[0] & 0xFE00) == 0xFC00
                || (s[0] & 0xFFC0) == 0xFE80
                || (s[0] == 0x2001 && s[1] == 0x0DB8))
        }
    }
}

fn rcode_of(msg: &[u8]) -> u8 {
    header::flags(msg).rcode()
}

/// The names (lowercase, no trailing dot) of the answer section's records of `rt` for `owner`, with
/// the rdata read as a name.
fn names_of(msg: &[u8], rt: u16, owner: &str) -> Vec<String> {
    let owner = lower(owner);
    let mut out = Vec::new();
    for r in records(msg).into_iter().flatten().flatten() {
        if r.section == Section::Answer
            && r.rtype == rt
            && r.rclass == class::IN
            && name_at(msg, r.name_off).as_deref() == Some(owner.as_str())
            && let Some(n) = name_at(msg, r.rdata_off)
        {
            out.push(n);
        }
    }
    out
}

/// The addresses a message holds for `owner` in any section (an answer, or glue in the additional
/// section).
fn addrs_of(msg: &[u8], owner: &str) -> Vec<IpAddr> {
    let owner = lower(owner);
    let mut out = Vec::new();
    for r in records(msg).into_iter().flatten().flatten() {
        if r.rclass != class::IN || name_at(msg, r.name_off).as_deref() != Some(owner.as_str()) {
            continue;
        }
        let d = r.rdata(msg);
        match (r.rtype, d.len()) {
            (rtype::A, 4) => out.push(IpAddr::from([d[0], d[1], d[2], d[3]])),
            (rtype::AAAA, 16) => {
                if let Ok(b) = <[u8; 16]>::try_from(d) {
                    out.push(IpAddr::from(b));
                }
            }
            _ => {}
        }
    }
    out
}

/// The name servers of `zone` and their public addresses, through the configured upstreams.
///
/// At most `limits.max_servers` addresses in all; a server with no public address is left out. An
/// error says why none could be asked (the upstreams did not answer, the zone has no `NS` set, or no
/// server has a public address).
pub(crate) async fn authoritative_servers(
    up: &dyn Upstreams,
    zone: &str,
    limits: &Limits,
) -> Result<Vec<Server>, LookupError> {
    let zone = lower(zone);
    let ns_msg = up
        .ask(&zone, rtype::NS)
        .await
        .map_err(LookupError::Upstream)?;
    let rc = rcode_of(&ns_msg);
    if rc != 0 {
        return Err(LookupError::Upstream(format!(
            "asked for the name servers of {zone}, the upstreams answered {}",
            rcode_name(rc)
        )));
    }
    let mut names = names_of(&ns_msg, rtype::NS, &zone);
    names.sort();
    names.dedup();
    if names.is_empty() {
        return Err(LookupError::NoServers(format!(
            "the upstreams know no name servers for {zone}"
        )));
    }
    let mut out: Vec<Server> = Vec::new();
    let mut budget = limits.max_servers;
    for n in names {
        if budget == 0 {
            break;
        }
        // Glue in the answer first, then explicit lookups.
        let mut addrs = addrs_of(&ns_msg, &n);
        if addrs.is_empty() {
            for t in [rtype::A, rtype::AAAA] {
                if let Ok(m) = up.ask(&n, t).await
                    && rcode_of(&m) == 0
                {
                    addrs.extend(addrs_of(&m, &n));
                }
            }
        }
        addrs.sort();
        addrs.dedup();
        addrs.retain(|a| limits.allow_private || is_public(*a));
        addrs.truncate(budget);
        if addrs.is_empty() {
            continue;
        }
        budget -= addrs.len();
        out.push(Server { name: n, addrs });
    }
    if out.is_empty() {
        return Err(LookupError::NoServers(format!(
            "none of the name servers of {zone} has a public address this node may ask"
        )));
    }
    Ok(out)
}

fn rcode_name(rc: u8) -> &'static str {
    match u16::from(rc) {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "an error",
    }
}

/// Checks that `msg` answers the question sent with `id`: a response, same ID, and the question
/// section echoes the name and type.
fn matches_question(msg: &[u8], id: u16, name: &str, qtype: u16) -> Result<(), LookupError> {
    let bad = |w: &str| LookupError::Malformed(w.to_owned());
    let h = header::Header::parse(msg).ok_or_else(|| bad("the answer is not a DNS message"))?;
    if h.id != id || !h.flags.qr() {
        return Err(bad("the answer does not match the question"));
    }
    if h.qdcount != 1 {
        return Err(bad("the answer does not repeat the question"));
    }
    let mut q = NameBuf::default();
    let end = read_name(msg, wrendns_proto::HEADER_LEN, &mut q)
        .map_err(|_| bad("the answer's question is malformed"))?;
    let t = msg
        .get(end..end + 2)
        .ok_or_else(|| bad("the answer is cut short"))?;
    if lower(&q.display().to_string()) != lower(name) || u16::from_be_bytes([t[0], t[1]]) != qtype {
        return Err(bad("the answer is for another question"));
    }
    Ok(())
}

fn query_bytes(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, LookupError> {
    let n = NameBuf::from_presentation(name)
        .map_err(|_| LookupError::Malformed(format!("`{name}` is not a domain name")))?;
    let mut buf = [0u8; 512];
    let len = build_query(
        &mut buf,
        id,
        &n,
        qtype,
        class::IN,
        false,
        Some(EdnsOut::new(UDP_PAYLOAD)),
    )
    .map_err(|_| LookupError::Malformed(format!("`{name}` does not fit a query")))?;
    Ok(buf[..len].to_vec())
}

async fn udp_try(addr: SocketAddr, q: &[u8], limits: &Limits) -> Result<Vec<u8>, std::io::Error> {
    let bind: SocketAddr = if addr.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    sock.send(q).await?;
    let mut buf = vec![0u8; limits.max_answer + 1];
    let n = sock.recv(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

async fn tcp_ask(addr: SocketAddr, q: &[u8], limits: &Limits) -> Result<Vec<u8>, LookupError> {
    let unreachable = |w: String| LookupError::Unreachable(format!("{addr}: {w}"));
    let fut = async {
        let mut s = TcpStream::connect(addr).await?;
        let len = u16::try_from(q.len()).map_err(|_| std::io::Error::other("query too long"))?;
        let mut framed = Vec::with_capacity(q.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(q);
        s.write_all(&framed).await?;
        let mut l = [0u8; 2];
        s.read_exact(&mut l).await?;
        let n = usize::from(u16::from_be_bytes(l));
        if n > limits.max_answer {
            return Ok(None);
        }
        let mut msg = vec![0u8; n];
        s.read_exact(&mut msg).await?;
        Ok::<_, std::io::Error>(Some(msg))
    };
    match tokio::time::timeout(limits.per_try, fut).await {
        Ok(Ok(Some(m))) => Ok(m),
        Ok(Ok(None)) => Err(LookupError::Malformed(format!(
            "{addr}: the answer is larger than the {} bytes this node reads",
            limits.max_answer
        ))),
        Ok(Err(e)) => Err(unreachable(e.to_string())),
        Err(_) => Err(unreachable("no answer over TCP in time".to_owned())),
    }
}

/// Asks one server `name`/`qtype` (no recursion). UDP with `limits.tries` tries, then TCP when the
/// answer is truncated. The answer is believed only when it matches the question.
pub(crate) async fn query_server(
    addr: SocketAddr,
    name: &str,
    qtype: u16,
    limits: &Limits,
) -> Result<Reply, LookupError> {
    let id: u16 = rand::random();
    let q = query_bytes(id, name, qtype)?;
    let mut last = String::from("no answer");
    let mut msg = None;
    for _ in 0..limits.tries.max(1) {
        match tokio::time::timeout(limits.per_try, udp_try(addr, &q, limits)).await {
            Ok(Ok(m)) => {
                msg = Some(m);
                break;
            }
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => "no answer in time".clone_into(&mut last),
        }
    }
    let mut msg = msg.ok_or_else(|| LookupError::Unreachable(format!("{addr}: {last}")))?;
    if msg.len() > limits.max_answer {
        return Err(LookupError::Malformed(format!(
            "{addr}: the answer is larger than the {} bytes this node reads",
            limits.max_answer
        )));
    }
    matches_question(&msg, id, name, qtype)?;
    if header::flags(&msg).tc() {
        msg = tcp_ask(addr, &q, limits).await?;
        matches_question(&msg, id, name, qtype)?;
    }
    let flags = header::flags(&msg);
    Ok(Reply {
        rcode: flags.rcode(),
        aa: flags.aa(),
        msg,
    })
}

/// One address of one name server and what it answered.
#[derive(Debug, Clone)]
pub(crate) struct ServerReport {
    /// The name server's name.
    pub(crate) server: String,
    pub(crate) addr: IpAddr,
    pub(crate) outcome: Result<Reply, LookupError>,
}

/// Asks every name server of `zone` (found through `up`) for `name`/`qtype`, all at once, within
/// `limits.total`.
pub(crate) async fn ask_all(
    up: &dyn Upstreams,
    zone: &str,
    name: &str,
    qtype: u16,
    limits: &Limits,
) -> Result<Vec<ServerReport>, LookupError> {
    let work = async {
        let servers = authoritative_servers(up, zone, limits).await?;
        let mut set = tokio::task::JoinSet::new();
        for s in servers {
            for a in s.addrs {
                let (server, name, limits) = (s.name.clone(), name.to_owned(), *limits);
                set.spawn(async move {
                    let addr = SocketAddr::new(a, limits.port);
                    let outcome = query_server(addr, &name, qtype, &limits).await;
                    ServerReport {
                        server,
                        addr: a,
                        outcome,
                    }
                });
            }
        }
        let mut out = Vec::new();
        while let Some(r) = set.join_next().await {
            if let Ok(r) = r {
                out.push(r);
            }
        }
        out.sort_by(|a, b| (&a.server, a.addr).cmp(&(&b.server, b.addr)));
        Ok::<_, LookupError>(out)
    };
    tokio::time::timeout(limits.total, work)
        .await
        .map_err(|_| LookupError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cld_904_only_public_addresses_are_asked() {
        for ok in ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"] {
            assert!(is_public(ok.parse().unwrap()), "{ok}");
        }
        for no in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "192.0.2.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public(no.parse().unwrap()), "{no}");
        }
    }
}

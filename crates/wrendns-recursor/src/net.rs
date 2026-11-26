//! One iterative query to one authoritative server (REQ: DNS-012): UDP from a fresh random
//! port with a random ID (RFC 5452), TCP when the answer is truncated (or when the server's
//! UDP has gone unanswered, DNS-903), optional 0x20 case randomization of the name (checked on
//! the way back), with or without EDNS, from the upstream's source address when it has one.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};
use wrendns_proto::{EdnsOut, HEADER_LEN, Header, NameBuf, build_query, read_name, summarize};

use crate::SourceAddr;
use crate::observe::{Exchange, ExchangeTap, Stats};

/// Why a server gave nothing usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("timed out")]
    Timeout,
    #[error("network error")]
    Io,
    #[error("malformed or mismatched response")]
    Bad,
    #[error("the name's letter case came back changed (0x20)")]
    CaseMismatch,
}

/// How one query is sent (REQ: DNS-012, DNS-903).
#[derive(Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // independent on/off switches, not a state machine
pub(crate) struct How<'a> {
    pub(crate) dnssec_ok: bool,
    pub(crate) mix_case: bool,
    /// REQ: DNS-903 — with an EDNS OPT record (off for a server that answered FORMERR or
    /// NOTIMP to one; DO needs it, so such a server's answers carry no signatures).
    pub(crate) edns: bool,
    /// REQ: DNS-903 — over TCP from the first byte (a server whose UDP goes unanswered).
    pub(crate) tcp: bool,
    /// REQ: DNS-903, UPS-013 — the local address sockets are bound to.
    pub(crate) source: Option<&'a dyn SourceAddr>,
    /// REQ: DNS-904 — what the servers did is counted here.
    pub(crate) stats: &'a Stats,
    /// REQ: DNS-904, OBS-007 — shown every exchange, when set.
    pub(crate) tap: Option<&'a ExchangeTap>,
}

/// The address to bind for a socket to `server`: the source address (which must be of the
/// server's family, as a v4 socket can't reach a v6 server), else any.
fn bind_addr(server: SocketAddr, source: Option<&dyn SourceAddr>) -> Result<SocketAddr, NetError> {
    match source {
        Some(s) => {
            let ip = s.current().map_err(|_| NetError::Io)?;
            if ip.is_ipv4() == server.is_ipv4() {
                Ok(SocketAddr::new(ip, 0))
            } else {
                Err(NetError::Io)
            }
        }
        None => Ok(match server.ip() {
            IpAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
            IpAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        }),
    }
}

/// Tells the source address how a bind went (so it can report one the node no longer holds).
fn bound<T>(source: Option<&dyn SourceAddr>, r: std::io::Result<T>) -> Result<T, NetError> {
    if let Some(s) = source {
        s.note(r.as_ref().err().map(std::io::Error::kind));
    }
    r.map_err(|_| NetError::Io)
}

/// The query: the name with each letter's case randomized when `mix_case`.
fn wire_query(id: u16, name: &NameBuf, qtype: u16, o: &How<'_>) -> Option<Vec<u8>> {
    let mut buf = [0u8; 512];
    let edns = o.edns.then_some(EdnsOut {
        udp_payload: 1232,
        dnssec_ok: o.dnssec_ok,
        ede: None,
    });
    let len = build_query(&mut buf, id, name, qtype, 1, false, edns).ok()?;
    let mut q = buf[..len].to_vec();
    if o.mix_case {
        let end = HEADER_LEN + name.wire_len();
        let mut pos = HEADER_LEN;
        while pos < end {
            let l = usize::from(q[pos]);
            for b in q.get_mut(pos + 1..pos + 1 + l)? {
                if b.is_ascii_alphabetic() && rand::random::<bool>() {
                    *b ^= 0x20;
                }
            }
            pos += 1 + l;
        }
    }
    Some(q)
}

/// The response answers `query`: same ID, QR, opcode 0, the same question (exactly, letter
/// case included, when `exact`).
fn check(resp: &[u8], query: &[u8], exact: bool) -> Result<(), NetError> {
    let (Some(rh), Some(qh)) = (Header::parse(resp), Header::parse(query)) else {
        return Err(NetError::Bad);
    };
    if rh.id != qh.id || !rh.flags.qr() || rh.flags.opcode() != 0 || rh.qdcount != 1 {
        return Err(NetError::Bad);
    }
    // The question sits uncompressed right after the header in both (nothing earlier to
    // point to): compare those bytes.
    let mut a = NameBuf::default();
    let end = read_name(query, HEADER_LEN, &mut a).map_err(|_| NetError::Bad)?;
    let (Some(rq), Some(qq)) = (
        resp.get(HEADER_LEN..end + 4),
        query.get(HEADER_LEN..end + 4),
    ) else {
        return Err(NetError::Bad);
    };
    if rq.eq_ignore_ascii_case(qq) {
        if exact && rq != qq {
            return Err(NetError::CaseMismatch);
        }
    } else {
        return Err(NetError::Bad);
    }
    summarize(resp).map(|_| ()).map_err(|_| NetError::Bad)
}

/// Sends the query to `server` and returns its response; the exchange is shown to the tap
/// (REQ: DNS-904).
pub(crate) async fn ask(
    server: SocketAddr,
    name: &NameBuf,
    qtype: u16,
    o: How<'_>,
    timeout: Duration,
) -> Result<Vec<u8>, NetError> {
    let id: u16 = rand::random();
    let query = wire_query(id, name, qtype, &o).ok_or(NetError::Bad)?;
    let sent = o.tap.map(|_| std::time::SystemTime::now());
    let mut tcp = o.tcp;
    let result = ask_inner(server, &query, &o, timeout, &mut tcp).await;
    if let (Some(t), Some(sent)) = (o.tap, sent) {
        t.show(&Exchange {
            server,
            tcp,
            query: &query,
            response: result.as_ref().ok().map(Vec::as_slice),
            sent,
        });
    }
    result
}

async fn ask_inner(
    server: SocketAddr,
    query: &[u8],
    o: &How<'_>,
    timeout: Duration,
    used_tcp: &mut bool,
) -> Result<Vec<u8>, NetError> {
    let mix_case = o.mix_case;
    if o.tcp {
        return tokio::time::timeout(timeout * 2, tcp(server, query, mix_case, o.source, o.stats))
            .await
            .map_err(|_| NetError::Timeout)?;
    }
    // REQ: DNS-012 — a reply whose letter case differs is not taken as the server's word: it
    // may be a spoof that guessed the ID and port but not the case. The one with the case
    // intact is waited for; only when none comes in time does the server count as one that
    // doesn't echo the case.
    let case_changed = AtomicBool::new(false);
    let resp = match tokio::time::timeout(
        timeout,
        udp(server, query, mix_case, &case_changed, o.source, o.stats),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) if case_changed.load(Ordering::Relaxed) => return Err(NetError::CaseMismatch),
        Err(_) => return Err(NetError::Timeout),
    };
    if Header::parse(&resp).is_some_and(|h| h.flags.tc()) {
        // Truncated: the whole answer over TCP (RFC 7766), with a little more time.
        *used_tcp = true;
        return tokio::time::timeout(timeout * 2, tcp(server, query, mix_case, o.source, o.stats))
            .await
            .map_err(|_| NetError::Timeout)?;
    }
    Ok(resp)
}

async fn udp(
    server: SocketAddr,
    query: &[u8],
    exact: bool,
    case_changed: &AtomicBool,
    source: Option<&dyn SourceAddr>,
    stats: &Stats,
) -> Result<Vec<u8>, NetError> {
    let bind = bind_addr(server, source)?;
    let sock = bound(source, UdpSocket::bind(bind).await)?;
    sock.connect(server).await.map_err(|_| NetError::Io)?;
    sock.send(query).await.map_err(|_| NetError::Io)?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await.map_err(|_| NetError::Io)?;
        match check(&buf[..n], query, exact) {
            Ok(()) => {
                buf.truncate(n);
                return Ok(buf);
            }
            // The case changed: noted, and the wait for an intact one goes on.
            Err(NetError::CaseMismatch) => {
                case_changed.store(true, Ordering::Relaxed);
                stats.case_mismatch();
            }
            // Stray or spoofed: counted (REQ: DNS-904), and the wait for the real one goes on.
            Err(_) => stats.unwanted(),
        }
    }
}

async fn tcp(
    server: SocketAddr,
    query: &[u8],
    exact: bool,
    source: Option<&dyn SourceAddr>,
    stats: &Stats,
) -> Result<Vec<u8>, NetError> {
    let bind = bind_addr(server, source)?;
    let sock = if server.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(|_| NetError::Io)?;
    bound(source, sock.bind(bind))?;
    let mut s = sock.connect(server).await.map_err(|_| NetError::Io)?;
    let len = u16::try_from(query.len()).map_err(|_| NetError::Bad)?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    s.write_all(&framed).await.map_err(|_| NetError::Io)?;
    let mut lb = [0u8; 2];
    s.read_exact(&mut lb).await.map_err(|_| NetError::Io)?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(lb))];
    s.read_exact(&mut buf).await.map_err(|_| NetError::Io)?;
    if let Err(e) = check(&buf, query, exact) {
        if e == NetError::CaseMismatch {
            stats.case_mismatch();
        }
        return Err(e);
    }
    Ok(buf)
}

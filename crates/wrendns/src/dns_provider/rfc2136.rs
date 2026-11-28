// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b4; ADR-1084; RFC 2136, RFC 8945) - the `rfc2136` provider: dynamic
//! update signed with TSIG (HMAC-SHA256) to any self-run authoritative server, over TCP.
//!
//! - **Writes** are one UPDATE message: `ensure` deletes the record set and adds every value in the
//!   same message (the server applies it atomically); `delete` deletes the record set.
//! - **Reads** are a zone transfer (AXFR) signed with the same key, because dynamic update has no
//!   way to list a zone. The key therefore needs `allow-transfer` as well as the update grant;
//!   the Test action checks that and says so.
//! - **Test** sends an update with one prerequisite (the zone's apex is in use) and no change:
//!   a server that accepts it has accepted the key's signature for the zone. A server does not
//!   report what a key may change, so the grant for a name and type is only checked when a record
//!   is written, and a refusal then names it.
//!
//! The answer is trusted only when its TSIG verifies against the request's MAC. The key's secret
//! never appears in an error: errors carry fixed text and the server's result code only.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use wrendns_config::DnsProviderConfig;
use wrendns_proto::{
    NameBuf, Prereq, Section, UpdateChange, build_query, build_update, class, header, rcode,
    read_name, records, rtype,
};

use super::tsig::{self, TsigError, TsigKey};
use super::{
    Change, DnsProvider, Fut, ProviderError, ProviderErrorKind, RecordSet, RecordType, Scope,
};
use crate::secrets::value::SecretValue;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// One request and its answer (an update, or the first message of a transfer).
const IO_TIMEOUT: Duration = Duration::from_secs(20);
/// A whole zone transfer.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(60);
/// What a zone transfer may hold before it is refused.
const MAX_TRANSFER_BYTES: usize = 16 * 1024 * 1024;
const MAX_TRANSFER_MESSAGES: usize = 4096;
const MAX_SETS: usize = 50_000;

/// A server taking dynamic updates for one zone.
pub(crate) struct Rfc2136 {
    zone: String,
    /// `host` or `host:port`.
    server: String,
    key: Result<TsigKey, TsigError>,
}

impl fmt::Debug for Rfc2136 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rfc2136")
            .field("zone", &self.zone)
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

fn err(kind: ProviderErrorKind, detail: impl Into<String>) -> ProviderError {
    ProviderError::new(kind, detail)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A name the wire builder is given: letters, digits, `-`, `_`, `.` and `*` only, so a backslash
/// escape can never reach the encoder.
fn wire_name(name: &str) -> Result<NameBuf, ProviderError> {
    let ok = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'*'));
    if !ok {
        return Err(err(
            ProviderErrorKind::Rejected,
            format!("`{name}` is not a name this provider writes"),
        ));
    }
    NameBuf::from_presentation(name).map_err(|_| {
        err(
            ProviderErrorKind::Rejected,
            format!("`{name}` is not a record name"),
        )
    })
}

/// The wire rdata of one value.
fn rdata(rtype: RecordType, value: &str) -> Result<Vec<u8>, ProviderError> {
    let bad = || {
        err(
            ProviderErrorKind::Rejected,
            format!("`{value}` is not a valid {} value", rtype.as_str()),
        )
    };
    match rtype {
        RecordType::A => Ok(value
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| bad())?
            .octets()
            .to_vec()),
        RecordType::Aaaa => Ok(value
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| bad())?
            .octets()
            .to_vec()),
        RecordType::Txt => {
            let bytes = value.as_bytes();
            if bytes.is_empty() {
                return Err(bad());
            }
            let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 255 + 1);
            for chunk in bytes.chunks(255) {
                out.push(u8::try_from(chunk.len()).map_err(|_| bad())?);
                out.extend_from_slice(chunk);
            }
            Ok(out)
        }
    }
}

const fn wire_type(t: RecordType) -> u16 {
    match t {
        RecordType::A => rtype::A,
        RecordType::Aaaa => rtype::AAAA,
        RecordType::Txt => rtype::TXT,
    }
}

/// What a result code means for the call that got it.
fn rcode_error(code: u16, what: &str) -> ProviderError {
    let (kind, text) = match code {
        rcode::FORMERR => (
            ProviderErrorKind::Rejected,
            "the server could not read the request (FORMERR)",
        ),
        rcode::SERVFAIL => (
            ProviderErrorKind::Unavailable,
            "the server failed (SERVFAIL)",
        ),
        rcode::NXDOMAIN => (
            ProviderErrorKind::Rejected,
            "a name the request needs does not exist (NXDOMAIN)",
        ),
        rcode::NOTIMP => (
            ProviderErrorKind::Rejected,
            "the server does not take this kind of request (NOTIMP)",
        ),
        rcode::REFUSED => (
            ProviderErrorKind::Forbidden,
            "the server refused it (REFUSED): the key's grant (update-policy or allow-update, or allow-transfer for reading) does not cover it",
        ),
        rcode::YXDOMAIN | rcode::YXRRSET | rcode::NXRRSET => (
            ProviderErrorKind::Rejected,
            "a prerequisite of the update did not hold",
        ),
        rcode::NOTAUTH => (
            ProviderErrorKind::Unauthorized,
            "the server does not accept the key for this zone (NOTAUTH)",
        ),
        rcode::NOTZONE => (
            ProviderErrorKind::Rejected,
            "the zone is not served by this server (NOTZONE)",
        ),
        _ => (
            ProviderErrorKind::Rejected,
            "the server answered with an error",
        ),
    };
    err(kind, format!("{what}: {text} (result code {code})"))
}

fn tsig_error(e: &TsigError) -> ProviderError {
    match e {
        TsigError::Server(16 | 17) | TsigError::BadKey(_) => err(
            ProviderErrorKind::Unauthorized,
            format!("the key was not accepted: {e}"),
        ),
        _ => err(
            ProviderErrorKind::Rejected,
            format!("the answer cannot be trusted: {e}"),
        ),
    }
}

/// One answer message, checked as an answer to `id`.
struct Answer {
    msg: Vec<u8>,
}

impl Answer {
    fn rcode(&self) -> u16 {
        u16::from(header::flags(&self.msg).rcode())
    }
}

impl Rfc2136 {
    pub(crate) fn new(cfg: &DnsProviderConfig, secret: Option<&SecretValue>) -> Self {
        let key = match (secret, cfg.key_name.as_ref()) {
            (Some(s), Some(n)) => TsigKey::new(n.trim(), s.expose()),
            (None, _) => Err(TsigError::BadKey("no credential is stored under that name")),
            (_, None) => Err(TsigError::BadKey("no key name")),
        };
        Self {
            zone: cfg.zone.as_str().to_owned(),
            server: cfg
                .server
                .as_ref()
                .map(|s| s.trim().to_owned())
                .unwrap_or_default(),
            key,
        }
    }

    fn key(&self) -> Result<&TsigKey, ProviderError> {
        self.key.as_ref().map_err(tsig_error)
    }

    async fn connect(&self) -> Result<TcpStream, ProviderError> {
        let target = if self.server.parse::<std::net::SocketAddr>().is_ok()
            || self
                .server
                .rsplit_once(':')
                .is_some_and(|(h, p)| !h.contains(':') && p.parse::<u16>().is_ok())
        {
            self.server.clone()
        } else if self.server.contains(':') {
            // A bare IPv6 address.
            format!("[{}]:53", self.server)
        } else {
            format!("{}:53", self.server)
        };
        let addrs: Vec<_> = tokio::net::lookup_host(&target)
            .await
            .map_err(|_| {
                err(
                    ProviderErrorKind::Unavailable,
                    format!("cannot resolve the server `{}`", self.server),
                )
            })?
            .collect();
        let mut last = String::from("the server has no address");
        for a in addrs {
            match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(e)) => last = format!("cannot connect to the server: {e}"),
                Err(_) => {
                    return Err(err(
                        ProviderErrorKind::Timeout,
                        "the server did not accept the connection in time",
                    ));
                }
            }
        }
        Err(err(ProviderErrorKind::Unavailable, last))
    }

    async fn send(s: &mut TcpStream, msg: &[u8]) -> Result<(), ProviderError> {
        let len = u16::try_from(msg.len())
            .map_err(|_| err(ProviderErrorKind::Rejected, "the request is too long"))?;
        let mut framed = Vec::with_capacity(msg.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(msg);
        s.write_all(&framed)
            .await
            .map_err(|e| err(ProviderErrorKind::Unavailable, format!("sending: {e}")))
    }

    async fn receive(s: &mut TcpStream) -> Result<Vec<u8>, ProviderError> {
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.map_err(|e| {
            err(
                ProviderErrorKind::Unavailable,
                format!("the server closed the connection or failed: {e}"),
            )
        })?;
        let mut msg = vec![0u8; usize::from(u16::from_be_bytes(len))];
        s.read_exact(&mut msg)
            .await
            .map_err(|e| err(ProviderErrorKind::Unavailable, format!("receiving: {e}")))?;
        Ok(msg)
    }

    /// Signs `msg` (built with `id`), sends it and reads one answer, which must verify.
    async fn exchange(&self, mut msg: Vec<u8>) -> Result<Answer, ProviderError> {
        let key = self.key()?;
        let id = header::id(&msg);
        let t = now();
        let mac = tsig::sign(&mut msg, key, t).map_err(|e| tsig_error(&e))?;
        let fut = async {
            let mut s = self.connect().await?;
            Self::send(&mut s, &msg).await?;
            Self::receive(&mut s).await
        };
        let answer = tokio::time::timeout(IO_TIMEOUT, fut).await.map_err(|_| {
            err(
                ProviderErrorKind::Timeout,
                "the server did not answer in time",
            )
        })??;
        Self::check_answer(&answer, id)?;
        let mut v = tsig::Verifier::new(key, mac, t);
        v.check(&answer).map_err(|e| tsig_error(&e))?;
        Ok(Answer { msg: answer })
    }

    /// An answer to this request: a response, same ID, same opcode.
    fn check_answer(answer: &[u8], id: u16) -> Result<(), ProviderError> {
        let h = header::Header::parse(answer).ok_or_else(|| {
            err(
                ProviderErrorKind::Rejected,
                "the answer is not a DNS message",
            )
        })?;
        if h.id != id || !h.flags.qr() {
            return Err(err(
                ProviderErrorKind::Rejected,
                "the answer does not match the request",
            ));
        }
        Ok(())
    }

    /// One UPDATE with these prerequisites and changes.
    async fn update(
        &self,
        prereqs: &[Prereq<'_>],
        changes: &[UpdateChange<'_>],
    ) -> Result<(), ProviderError> {
        let zone = wire_name(&self.zone)?;
        // A TCP message is at most 65535 bytes; leave room for the TSIG record (at most about 330).
        let mut buf = vec![0u8; usize::from(u16::MAX) - 512];
        let id: u16 = rand::random();
        let len = build_update(&mut buf, id, &zone, prereqs, changes)
            .map_err(|_| err(ProviderErrorKind::Rejected, "the update is too long"))?;
        buf.truncate(len);
        let a = self.exchange(buf).await?;
        match a.rcode() {
            rcode::NOERROR => Ok(()),
            c => Err(rcode_error(c, "the update")),
        }
    }

    /// A zone transfer. With `first_only` it reads and checks the first message and stops (the Test
    /// action); otherwise it reads to the end and returns the `A`, `AAAA` and `TXT` sets.
    async fn transfer(&self, first_only: bool) -> Result<Vec<RecordSet>, ProviderError> {
        let key = self.key()?;
        let zone = wire_name(&self.zone)?;
        let id: u16 = rand::random();
        let mut buf = vec![0u8; 512];
        let len = build_query(&mut buf, id, &zone, rtype::AXFR, class::IN, false, None)
            .map_err(|_| err(ProviderErrorKind::Rejected, "the request is too long"))?;
        buf.truncate(len);
        let t = now();
        let mac = tsig::sign(&mut buf, key, t).map_err(|e| tsig_error(&e))?;
        let run = async {
            let mut s = self.connect().await?;
            Self::send(&mut s, &buf).await?;
            let mut v = tsig::Verifier::new(key, mac, t);
            let mut sets: BTreeMap<(String, RecordType), (u32, BTreeSet<String>)> = BTreeMap::new();
            let (mut bytes, mut messages, mut soas) = (0usize, 0usize, 0usize);
            loop {
                let msg = tokio::time::timeout(IO_TIMEOUT, Self::receive(&mut s))
                    .await
                    .map_err(|_| {
                        err(
                            ProviderErrorKind::Timeout,
                            "the server stopped sending the zone",
                        )
                    })??;
                messages += 1;
                bytes += msg.len();
                if messages > MAX_TRANSFER_MESSAGES || bytes > MAX_TRANSFER_BYTES {
                    return Err(err(
                        ProviderErrorKind::Rejected,
                        "the zone is larger than WrenDNS reads for a provider",
                    ));
                }
                Self::check_answer(&msg, id)?;
                let code = u16::from(header::flags(&msg).rcode());
                if code != rcode::NOERROR {
                    // An error answer may carry an unsigned TSIG error (BADKEY): report that first.
                    if let Err(e) = v.check(&msg)
                        && matches!(e, TsigError::Server(_) | TsigError::WrongKey)
                    {
                        return Err(tsig_error(&e));
                    }
                    return Err(rcode_error(code, "the zone transfer"));
                }
                v.check(&msg).map_err(|e| tsig_error(&e))?;
                if first_only {
                    return Ok(Vec::new());
                }
                if Self::absorb(&msg, &mut sets, &mut soas)? {
                    break;
                }
            }
            v.finish().map_err(|e| tsig_error(&e))?;
            Ok(sets
                .into_iter()
                .map(|((name, rtype), (ttl, values))| RecordSet {
                    name,
                    rtype,
                    ttl,
                    values: values.into_iter().collect(),
                })
                .collect())
        };
        tokio::time::timeout(TRANSFER_TIMEOUT, run)
            .await
            .map_err(|_| {
                err(
                    ProviderErrorKind::Timeout,
                    "the zone transfer took too long",
                )
            })?
    }

    /// Takes the records of one transfer message into `sets`; true once the closing SOA is seen.
    fn absorb(
        msg: &[u8],
        sets: &mut BTreeMap<(String, RecordType), (u32, BTreeSet<String>)>,
        soas: &mut usize,
    ) -> Result<bool, ProviderError> {
        let bad = || {
            err(
                ProviderErrorKind::Rejected,
                "the zone transfer is malformed",
            )
        };
        let mut done = false;
        for r in records(msg).map_err(|_| bad())? {
            let r = r.map_err(|_| bad())?;
            if r.section != Section::Answer || r.rclass != class::IN {
                continue;
            }
            if r.rtype == rtype::SOA {
                *soas += 1;
                if *soas >= 2 {
                    done = true;
                }
                continue;
            }
            if *soas == 0 {
                // A transfer starts with the zone's SOA.
                return Err(bad());
            }
            let t = match r.rtype {
                rtype::A => RecordType::A,
                rtype::AAAA => RecordType::Aaaa,
                rtype::TXT => RecordType::Txt,
                _ => continue,
            };
            let data = r.rdata(msg);
            let value = match t {
                RecordType::A => <[u8; 4]>::try_from(data)
                    .map(|b| std::net::Ipv4Addr::from(b).to_string())
                    .map_err(|_| bad())?,
                RecordType::Aaaa => <[u8; 16]>::try_from(data)
                    .map(|b| std::net::Ipv6Addr::from(b).to_string())
                    .map_err(|_| bad())?,
                RecordType::Txt => {
                    let mut out = Vec::new();
                    let mut p = 0usize;
                    while p < data.len() {
                        let n = usize::from(data[p]);
                        out.extend_from_slice(data.get(p + 1..p + 1 + n).ok_or_else(bad)?);
                        p += 1 + n;
                    }
                    String::from_utf8_lossy(&out).into_owned()
                }
            };
            let mut name = NameBuf::default();
            read_name(msg, r.name_off, &mut name).map_err(|_| bad())?;
            let key = (name.display().to_string().to_ascii_lowercase(), t);
            if sets.len() >= MAX_SETS && !sets.contains_key(&key) {
                return Err(err(
                    ProviderErrorKind::Rejected,
                    "the zone holds more record sets than WrenDNS reads for a provider",
                ));
            }
            let e = sets.entry(key).or_insert((r.ttl, BTreeSet::new()));
            e.1.insert(value);
        }
        Ok(done)
    }
}

impl DnsProvider for Rfc2136 {
    fn kind(&self) -> &'static str {
        "rfc2136"
    }

    fn scope(&self) -> Fut<'_, Scope> {
        Box::pin(async move {
            let zone = wire_name(&self.zone)?;
            self.update(&[Prereq::NameInUse(&zone)], &[]).await?;
            // The update was accepted. Reading the zone is a transfer: if the key may not do that,
            // the next write would fail at its first step, so the Test says so now.
            self.transfer(true).await.map_err(|e| {
                if e.kind == ProviderErrorKind::Forbidden {
                    err(
                        ProviderErrorKind::Forbidden,
                        "the signed update was accepted, but the server refused a zone transfer for the key: WrenDNS reads the zone with a transfer before every change, so add the key to the zone's allow-transfer",
                    )
                } else {
                    e
                }
            })?;
            Ok(Scope {
                zone: self.zone.clone(),
                summary: format!(
                    "The server accepted a signed update for {} with no change, and a signed zone transfer. What the key may change was NOT checked; the type listed is that of the grant shown when the provider was added.",
                    self.zone
                ),
                // Not measured: the grant the form shows (TXT at the challenge name).
                record_types: vec![RecordType::Txt],
                record_sets: None,
                broader_than_needed: false,
                notes: vec![
                    "Not verified: a server does not report what a key may change: the grant for a name and a type is checked when a record is written, and a refusal then says so.".into(),
                    "Check the server's update-policy against the grant shown when the provider was added: it should name only the records WrenDNS writes.".into(),
                ],
            })
        })
    }

    fn list(&self) -> Fut<'_, Vec<RecordSet>> {
        Box::pin(async move { self.transfer(false).await })
    }

    fn ensure<'a>(&'a self, set: &'a RecordSet) -> Fut<'a, Change> {
        Box::pin(async move {
            let name = wire_name(&set.name)?;
            let datas = set
                .values
                .iter()
                .map(|v| rdata(set.rtype, v))
                .collect::<Result<Vec<_>, _>>()?;
            let t = wire_type(set.rtype);
            let mut changes = vec![UpdateChange::DeleteRrset(&name, t)];
            changes.extend(datas.iter().map(|d| UpdateChange::Add {
                name: &name,
                rtype: t,
                ttl: set.ttl,
                rdata: d,
            }));
            self.update(&[], &changes).await?;
            Ok(Change::default())
        })
    }

    fn delete<'a>(&'a self, name: &'a str, rtype: RecordType) -> Fut<'a, Change> {
        Box::pin(async move {
            let n = wire_name(name)?;
            self.update(&[], &[UpdateChange::DeleteRrset(&n, wire_type(rtype))])
                .await?;
            Ok(Change::default())
        })
    }
}

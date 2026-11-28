// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b4; RFC 8945) - TSIG with HMAC-SHA256 on `ring`: signing a request,
//! and verifying the answer to it (one message, or the chain of a zone transfer).
//!
//! Only `hmac-sha256` is supported (the table accepts nothing else), and a truncated MAC is
//! refused. The key's secret is held as a `ring` HMAC key and never printed. Nothing here is on the
//! query path.

use std::fmt;

use base64::Engine as _;
use ring::hmac;
use wrendns_proto::{NameBuf, Section, read_name, records};

/// The TSIG record type.
const TSIG_TYPE: u16 = 250;
/// The class a TSIG record carries (ANY).
const CLASS_ANY: u16 = 255;
/// `hmac-sha256.` as a wire name.
const ALG_WIRE: &[u8] = b"\x0bhmac-sha256\x00";
/// A full HMAC-SHA256 tag.
const MAC_LEN: usize = 32;
/// How far apart the two clocks may be, in seconds (RFC 8945 recommends 300).
pub(crate) const FUDGE: u16 = 300;

/// Why a message could not be signed, or an answer could not be trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TsigError {
    /// The key name or the secret is not usable.
    BadKey(&'static str),
    /// The message has no room for the record, or is not a message.
    Message(&'static str),
    /// The answer carries no TSIG record.
    Missing,
    /// The TSIG record names another key or algorithm.
    WrongKey,
    /// The MAC does not match (or is truncated).
    BadMac,
    /// The signature's time is outside the fudge.
    BadTime,
    /// The server reported a TSIG error code (16 BADSIG, 17 BADKEY, 18 BADTIME, ...).
    Server(u16),
    /// The TSIG record or the message is malformed.
    Malformed,
}

impl fmt::Display for TsigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadKey(w) => write!(f, "the TSIG key is not usable: {w}"),
            Self::Message(w) => write!(f, "the message cannot be signed: {w}"),
            Self::Missing => f.write_str("the answer is not signed"),
            Self::WrongKey => f.write_str("the answer is signed with another key or algorithm"),
            Self::BadMac => f.write_str("the answer's signature does not match"),
            Self::BadTime => f.write_str("the answer's signature is outside the allowed time"),
            Self::Server(16) => f.write_str("the server reports a bad signature (BADSIG)"),
            Self::Server(17) => f.write_str("the server does not know the key (BADKEY)"),
            Self::Server(18) => f.write_str(
                "the server reports the clocks differ by more than the allowed time (BADTIME)",
            ),
            Self::Server(c) => write!(f, "the server reports TSIG error {c}"),
            Self::Malformed => f.write_str("the signature record is malformed"),
        }
    }
}

/// A TSIG key: its name as the server knows it and the HMAC key.
pub(crate) struct TsigKey {
    name: NameBuf,
    key: hmac::Key,
}

impl fmt::Debug for TsigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TsigKey({:?}, <redacted>)", self.name)
    }
}

impl TsigKey {
    /// A key from its name (`acme-key`) and secret (the standard base64 BIND writes).
    pub(crate) fn new(name: &str, secret_b64: &str) -> Result<Self, TsigError> {
        let name_ok = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if !name_ok {
            return Err(TsigError::BadKey("the key name is not a plain name"));
        }
        let name = NameBuf::from_presentation(name)
            .map_err(|_| TsigError::BadKey("the key name is not a name"))?;
        let secret = base64::engine::general_purpose::STANDARD
            .decode(secret_b64.trim())
            .map_err(|_| TsigError::BadKey("the secret is not base64"))?;
        if secret.is_empty() {
            return Err(TsigError::BadKey("the secret is empty"));
        }
        Ok(Self {
            name,
            key: hmac::Key::new(hmac::HMAC_SHA256, &secret),
        })
    }
}

fn put_u48(out: &mut Vec<u8>, t: u64) {
    out.extend_from_slice(&t.to_be_bytes()[2..]);
}

/// The TSIG variables that go into the MAC after the message (RFC 8945 section 4.3.3). A message
/// that follows a signed one in a chain digests only the time and the fudge.
fn variables(
    out: &mut Vec<u8>,
    key: &TsigKey,
    time: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
    full: bool,
) {
    if full {
        out.extend_from_slice(key.name.as_wire());
        out.extend_from_slice(&CLASS_ANY.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(ALG_WIRE);
    }
    put_u48(out, time);
    out.extend_from_slice(&fudge.to_be_bytes());
    if full {
        out.extend_from_slice(&error.to_be_bytes());
        out.extend_from_slice(&u16::try_from(other.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(other);
    }
}

/// Signs a request: appends the TSIG record to `msg`, counts it, and returns the MAC (the answer
/// is verified against it).
pub(crate) fn sign(msg: &mut Vec<u8>, key: &TsigKey, now: u64) -> Result<Vec<u8>, TsigError> {
    if msg.len() < 12 {
        return Err(TsigError::Message("shorter than a header"));
    }
    let id = [msg[0], msg[1]];
    let mut data = msg.clone();
    variables(&mut data, key, now, FUDGE, 0, &[], true);
    let mac = hmac::sign(&key.key, &data).as_ref().to_vec();
    let count = u16::from_be_bytes([msg[10], msg[11]])
        .checked_add(1)
        .ok_or(TsigError::Message("too many additional records"))?;
    msg[10..12].copy_from_slice(&count.to_be_bytes());
    let mut rdata = Vec::with_capacity(ALG_WIRE.len() + 16 + mac.len());
    rdata.extend_from_slice(ALG_WIRE);
    put_u48(&mut rdata, now);
    rdata.extend_from_slice(&FUDGE.to_be_bytes());
    rdata.extend_from_slice(&u16::try_from(mac.len()).unwrap_or(0).to_be_bytes());
    rdata.extend_from_slice(&mac);
    rdata.extend_from_slice(&id);
    rdata.extend_from_slice(&0u16.to_be_bytes());
    rdata.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(key.name.as_wire());
    msg.extend_from_slice(&TSIG_TYPE.to_be_bytes());
    msg.extend_from_slice(&CLASS_ANY.to_be_bytes());
    msg.extend_from_slice(&0u32.to_be_bytes());
    msg.extend_from_slice(
        &u16::try_from(rdata.len())
            .map_err(|_| TsigError::Message("record too long"))?
            .to_be_bytes(),
    );
    msg.extend_from_slice(&rdata);
    Ok(mac)
}

/// A TSIG record read from a message.
struct Parsed<'a> {
    /// Where the record's owner name starts (the message before it is what was signed).
    start: usize,
    key_name: NameBuf,
    alg: NameBuf,
    time: u64,
    fudge: u16,
    mac: &'a [u8],
    orig_id: u16,
    error: u16,
    other: &'a [u8],
}

/// The TSIG record, which must be the message's last record.
#[allow(clippy::many_single_char_names)] // the fixed fields of the record, read in order
fn find_tsig(msg: &[u8]) -> Result<Option<Parsed<'_>>, TsigError> {
    let mut last = None;
    let mut seen = 0usize;
    for r in records(msg).map_err(|_| TsigError::Malformed)? {
        let r = r.map_err(|_| TsigError::Malformed)?;
        seen += 1;
        if seen > 4096 {
            return Err(TsigError::Malformed);
        }
        if r.rtype == TSIG_TYPE {
            if r.section != Section::Additional || last.is_some() {
                return Err(TsigError::Malformed);
            }
            last = Some(r);
        } else if last.is_some() {
            // A record after the TSIG record.
            return Err(TsigError::Malformed);
        }
    }
    let Some(r) = last else { return Ok(None) };
    let mut key_name = NameBuf::default();
    read_name(msg, r.name_off, &mut key_name).map_err(|_| TsigError::Malformed)?;
    let mut alg = NameBuf::default();
    let end = r.rdata_off + usize::from(r.rdlen);
    let mut p = read_name(msg, r.rdata_off, &mut alg).map_err(|_| TsigError::Malformed)?;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], TsigError> {
        let s = msg.get(*p..*p + n).ok_or(TsigError::Malformed)?;
        if *p + n > end {
            return Err(TsigError::Malformed);
        }
        *p += n;
        Ok(s)
    };
    let t = take(&mut p, 6)?;
    let time = t.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b));
    let f = take(&mut p, 2)?;
    let fudge = u16::from_be_bytes([f[0], f[1]]);
    let l = take(&mut p, 2)?;
    let mac_len = usize::from(u16::from_be_bytes([l[0], l[1]]));
    let mac = take(&mut p, mac_len)?;
    let i = take(&mut p, 2)?;
    let orig_id = u16::from_be_bytes([i[0], i[1]]);
    let e = take(&mut p, 2)?;
    let error = u16::from_be_bytes([e[0], e[1]]);
    let l = take(&mut p, 2)?;
    let other_len = usize::from(u16::from_be_bytes([l[0], l[1]]));
    let other = take(&mut p, other_len)?;
    if p != end {
        return Err(TsigError::Malformed);
    }
    Ok(Some(Parsed {
        start: r.name_off,
        key_name,
        alg,
        time,
        fudge,
        mac,
        orig_id,
        error,
        other,
    }))
}

/// Verifies the messages that answer one signed request: a single message, or a chain (a zone
/// transfer, RFC 8945 section 5.3.1: the first and the last message are signed, and a message
/// without a signature is digested with the next signed one).
pub(crate) struct Verifier<'k> {
    key: &'k TsigKey,
    /// The MAC of the request, then of the last signed message.
    prior: Vec<u8>,
    /// Unsigned messages since the last signed one.
    pending: Vec<u8>,
    first: bool,
    last_signed: bool,
    now: u64,
}

impl<'k> Verifier<'k> {
    pub(crate) fn new(key: &'k TsigKey, request_mac: Vec<u8>, now: u64) -> Self {
        Self {
            key,
            prior: request_mac,
            pending: Vec::new(),
            first: true,
            last_signed: false,
            now,
        }
    }

    /// Checks the next message of the answer.
    pub(crate) fn check(&mut self, msg: &[u8]) -> Result<(), TsigError> {
        let Some(t) = find_tsig(msg)? else {
            if self.first {
                return Err(TsigError::Missing);
            }
            self.pending.extend_from_slice(msg);
            self.last_signed = false;
            return Ok(());
        };
        if t.key_name != self.key.name || t.alg.as_wire() != ALG_WIRE {
            // An unsigned error answer (BADKEY and the like) names the key as asked.
            return if t.error == 0 {
                Err(TsigError::WrongKey)
            } else {
                Err(TsigError::Server(t.error))
            };
        }
        if t.error != 0 {
            return Err(TsigError::Server(t.error));
        }
        if t.mac.len() != MAC_LEN {
            return Err(TsigError::BadMac);
        }
        let mut data = Vec::with_capacity(self.prior.len() + self.pending.len() + msg.len() + 64);
        data.extend_from_slice(&u16::try_from(self.prior.len()).unwrap_or(0).to_be_bytes());
        data.extend_from_slice(&self.prior);
        data.extend_from_slice(&self.pending);
        let head = msg.get(..t.start).ok_or(TsigError::Malformed)?;
        let mut head = head.to_vec();
        if head.len() < 12 {
            return Err(TsigError::Malformed);
        }
        // The digest is over the message as it was signed: its original ID, without the TSIG
        // record it carries.
        head[..2].copy_from_slice(&t.orig_id.to_be_bytes());
        let count = u16::from_be_bytes([head[10], head[11]])
            .checked_sub(1)
            .ok_or(TsigError::Malformed)?;
        head[10..12].copy_from_slice(&count.to_be_bytes());
        data.extend_from_slice(&head);
        variables(
            &mut data, self.key, t.time, t.fudge, t.error, t.other, self.first,
        );
        hmac::verify(&self.key.key, &data, t.mac).map_err(|_| TsigError::BadMac)?;
        if self.now.abs_diff(t.time) > u64::from(t.fudge) {
            return Err(TsigError::BadTime);
        }
        self.prior = t.mac.to_vec();
        self.pending.clear();
        self.first = false;
        self.last_signed = true;
        Ok(())
    }

    /// The answer is complete: its last message must have been signed.
    pub(crate) fn finish(&self) -> Result<(), TsigError> {
        if self.last_signed {
            Ok(())
        } else {
            Err(TsigError::Missing)
        }
    }
}

/// Test helpers: what a server does with a request and an answer, written independently of the
/// verifier above where hickory cannot do it.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// A signed message of a chain (the first one when `prior` is the request's MAC), signed the
    /// way section 5.3.1 says. Returns the MAC.
    pub(crate) fn sign_answer(
        msg: &mut Vec<u8>,
        key: &TsigKey,
        prior: &[u8],
        unsigned_before: &[u8],
        first: bool,
        now: u64,
    ) -> Vec<u8> {
        let id = [msg[0], msg[1]];
        let mut data = Vec::new();
        data.extend_from_slice(&u16::try_from(prior.len()).unwrap_or(0).to_be_bytes());
        data.extend_from_slice(prior);
        data.extend_from_slice(unsigned_before);
        data.extend_from_slice(msg);
        variables(&mut data, key, now, FUDGE, 0, &[], first);
        let mac = hmac::sign(&key.key, &data).as_ref().to_vec();
        let count = u16::from_be_bytes([msg[10], msg[11]]) + 1;
        msg[10..12].copy_from_slice(&count.to_be_bytes());
        let mut rdata = Vec::new();
        rdata.extend_from_slice(ALG_WIRE);
        put_u48(&mut rdata, now);
        rdata.extend_from_slice(&FUDGE.to_be_bytes());
        rdata.extend_from_slice(&u16::try_from(mac.len()).unwrap_or(0).to_be_bytes());
        rdata.extend_from_slice(&mac);
        rdata.extend_from_slice(&id);
        rdata.extend_from_slice(&[0, 0, 0, 0]);
        msg.extend_from_slice(key.name.as_wire());
        msg.extend_from_slice(&TSIG_TYPE.to_be_bytes());
        msg.extend_from_slice(&CLASS_ANY.to_be_bytes());
        msg.extend_from_slice(&0u32.to_be_bytes());
        msg.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(0).to_be_bytes());
        msg.extend_from_slice(&rdata);
        mac
    }
}

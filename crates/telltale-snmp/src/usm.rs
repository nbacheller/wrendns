//! REQ: DSC-003 — `SNMPv3` User-based Security Model (RFC 3414, RFC 7860, RFC 3826; ADR-908,
//! ADR-911). Security levels authNoPriv and authPriv. Authentication is HMAC-SHA-96 or
//! HMAC-SHA-2 truncated per RFC 7860; privacy is AES-128-CFB (`aes_cfb`).
//!
//! Key handling (ADR-908): Ku, the password expanded to 1 MiB and hashed, is computed once per
//! credential per round and held zeroized. Kul, Ku localized to one engine, is computed on
//! demand and never cached. The privacy key is the first 16 octets of the localized privacy key.

use std::time::{Duration, Instant};

use ring::{digest, hmac, rand::SecureRandom, rand::SystemRandom};
use zeroize::Zeroizing;

use crate::aes_cfb;
use crate::ber::{self, DecodeError};
use crate::pdu::{self, Response};
use crate::secret::SecretValue;

/// The msgSecurityModel of USM.
pub const SECURITY_MODEL_USM: i64 = 3;
/// msgMaxSize the client advertises.
pub const MAX_SIZE: i64 = 65_507;
/// The time window, in seconds (RFC 3414 §2.2.3).
pub const TIME_WINDOW: u32 = 150;
/// The largest engineBoots value; an agent at this value cannot be synchronized (RFC 3414 §2.2.2).
pub const MAX_BOOTS: u32 = 2_147_483_647;
/// The most unauthenticated time resyncs per agent per minute (ADR-908).
pub const RESYNC_INTERVAL: Duration = Duration::from_secs(60);
const ONE_MIB: usize = 1 << 20;

const FLAG_AUTH: u8 = 0x01;
const FLAG_PRIV: u8 = 0x02;
const FLAG_REPORTABLE: u8 = 0x04;

/// The usmStats counters a `Report` may carry, as OIDs (RFC 3414 §5).
pub const USM_STATS_NOT_IN_TIME_WINDOW: &str = "1.3.6.1.6.3.15.1.1.3.0";
pub const USM_STATS_UNKNOWN_ENGINE_ID: &str = "1.3.6.1.6.3.15.1.1.4.0";

/// An authentication protocol the client supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProto {
    /// usmHMACSHA-96 (HMAC-SHA-1, truncated to 96 bits).
    HmacSha96,
    /// usmHMAC192SHA256: HMAC-SHA-256 truncated to 192 bits.
    Sha256,
    /// usmHMAC256SHA384: HMAC-SHA-384 truncated to 256 bits.
    Sha384,
    /// usmHMAC384SHA512: HMAC-SHA-512 truncated to 384 bits.
    Sha512,
}

/// A privacy protocol the client supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivProto {
    /// usmAesCfb128Protocol.
    Aes128,
}

/// A protocol or level the client refuses, with the reason shown to the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    Md5,
    Sha224,
    Des,
    Aes192,
    Aes256,
    NoAuthNoPriv,
    Unknown,
}

impl Refused {
    /// The reason the form and the config check show (DSC-003: refused protocols are explained).
    pub fn reason(self) -> &'static str {
        match self {
            Self::Md5 => "MD5 is refused: its collisions are practical, and ring provides no MD5 digest.",
            Self::Sha224 => "SHA-224 is refused: the client supports SHA-1 and the SHA-2 variants of 256 bits and up, and the owner's devices use those.",
            Self::Des => "DES is refused: it is broken and has no key that can be kept secret.",
            Self::Aes192 => "AES-192 is refused: RFC 3826 defines only AES-128, and the devices that matter use it.",
            Self::Aes256 => "AES-256 is refused: RFC 3826 defines only AES-128 for SNMPv3.",
            Self::NoAuthNoPriv => "noAuthNoPriv is refused: a v3 user must authenticate. Use v2c only where the device has no v3.",
            Self::Unknown => "This protocol is not known to TelltaleDNS, so it is refused.",
        }
    }
}

impl AuthProto {
    /// Parses the configuration name. The refused names return their reason.
    pub fn parse(name: &str) -> Result<Self, Refused> {
        match name.to_ascii_uppercase().as_str() {
            "SHA" | "SHA-1" | "SHA1" => Ok(Self::HmacSha96),
            "SHA-256" | "SHA256" => Ok(Self::Sha256),
            "SHA-384" | "SHA384" => Ok(Self::Sha384),
            "SHA-512" | "SHA512" => Ok(Self::Sha512),
            "MD5" => Err(Refused::Md5),
            "SHA-224" | "SHA224" => Err(Refused::Sha224),
            "NONE" | "NOAUTH" => Err(Refused::NoAuthNoPriv),
            _ => Err(Refused::Unknown),
        }
    }

    /// The truncated MAC length in octets (RFC 7860 §4.2).
    pub fn mac_len(self) -> usize {
        match self {
            Self::HmacSha96 => 12,
            Self::Sha256 => 24,
            Self::Sha384 => 32,
            Self::Sha512 => 48,
        }
    }

    fn digest(self) -> &'static digest::Algorithm {
        match self {
            Self::HmacSha96 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => &digest::SHA256,
            Self::Sha384 => &digest::SHA384,
            Self::Sha512 => &digest::SHA512,
        }
    }

    fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::HmacSha96 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha384 => hmac::HMAC_SHA384,
            Self::Sha512 => hmac::HMAC_SHA512,
        }
    }
}

impl PrivProto {
    pub fn parse(name: &str) -> Result<Self, Refused> {
        match name.to_ascii_uppercase().as_str() {
            "AES" | "AES-128" | "AES128" => Ok(Self::Aes128),
            "DES" => Err(Refused::Des),
            "AES-192" | "AES192" => Err(Refused::Aes192),
            "AES-256" | "AES256" => Err(Refused::Aes256),
            _ => Err(Refused::Unknown),
        }
    }
}

/// The password-to-key expansion (RFC 3414 A.2): the password repeated to 1 MiB, hashed.
/// Returns `None` for an empty password, which would never end the expansion.
pub fn password_to_key(alg: AuthProto, password: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if password.is_empty() {
        return None;
    }
    let mut ctx = digest::Context::new(alg.digest());
    let mut fed = 0usize;
    while fed < ONE_MIB {
        let take = password.len().min(ONE_MIB.saturating_sub(fed));
        ctx.update(password.get(..take).unwrap_or(&[]));
        fed = fed.saturating_add(take);
    }
    Some(Zeroizing::new(ctx.finish().as_ref().to_vec()))
}

/// Localizes Ku to one engine: Kul = H(Ku || engineID || Ku) (RFC 3414 A.2.2).
pub fn localize(alg: AuthProto, ku: &[u8], engine_id: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut ctx = digest::Context::new(alg.digest());
    ctx.update(ku);
    ctx.update(engine_id);
    ctx.update(ku);
    Zeroizing::new(ctx.finish().as_ref().to_vec())
}

/// Compares two byte strings in time that depends only on their lengths. The MAC check and the
/// community check use it. ring's `verify_slices_are_equal` is deprecated for this use.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// HMAC over `msg` with `kul`, truncated to the protocol's MAC length.
pub fn mac(alg: AuthProto, kul: &[u8], msg: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(alg.hmac(), kul);
    let tag = hmac::sign(&key, msg);
    tag.as_ref().get(..alg.mac_len()).unwrap_or(&[]).to_vec()
}

/// The errors of the USM layer. None carries a secret or an input byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsmError {
    Decode(DecodeError),
    /// The password is empty, so there is no key.
    EmptyPassword,
    /// The random source failed.
    Random,
    /// The authentication MAC does not match.
    BadDigest,
    /// The message's engine time is outside the window.
    NotInTimeWindow,
    /// The reply is not the shape a USM reply must have.
    BadSecurityParameters,
    /// The reply is encrypted under the wrong keys or does not decrypt to a `PDU`.
    DecryptFailed,
}

impl From<DecodeError> for UsmError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

/// A USM user: a name, an authentication password, and optionally a privacy password.
#[derive(Debug)]
pub struct UsmUser {
    pub name: Vec<u8>,
    pub auth: Option<(AuthProto, SecretValue)>,
    pub privacy: Option<(PrivProto, SecretValue)>,
}

impl UsmUser {
    /// Derives Ku for each password (privacy uses the authentication protocol, RFC 3414 §2.6).
    pub fn derive(&self) -> Result<RoundKeys, UsmError> {
        let (auth_alg, auth_ku) = match &self.auth {
            Some((alg, pw)) => (Some(*alg), Some(password_to_key(*alg, pw.expose()).ok_or(UsmError::EmptyPassword)?)),
            None => (None, None),
        };
        let priv_ku = match (&self.privacy, auth_alg) {
            (Some((_, pw)), Some(alg)) => Some(password_to_key(alg, pw.expose()).ok_or(UsmError::EmptyPassword)?),
            (Some(_), None) => return Err(UsmError::BadSecurityParameters),
            _ => None,
        };
        Ok(RoundKeys {
            auth_alg,
            auth_ku,
            priv_ku,
            has_priv: self.privacy.is_some(),
        })
    }
}

/// Ku for one user, for one poll round. Dropped (and zeroized) at the end of the round.
pub struct RoundKeys {
    auth_alg: Option<AuthProto>,
    auth_ku: Option<Zeroizing<Vec<u8>>>,
    priv_ku: Option<Zeroizing<Vec<u8>>>,
    has_priv: bool,
}

impl std::fmt::Debug for RoundKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoundKeys(<redacted>)")
    }
}

impl RoundKeys {
    pub fn is_priv(&self) -> bool {
        self.has_priv
    }
}

/// The engine a device reported: its ID, boots and time, and when this client learned them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Engine {
    pub id: Vec<u8>,
    pub boots: u32,
    pub time: u32,
    pub learned: Instant,
}

/// What a message's boots and time mean for our copy of the agent's clock (RFC 3414 §3.2.7b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    /// Inside the window: keep the clock as it is.
    Accept,
    /// Ahead of our clock (more boots, or the same boots and a later time): the agent's clock
    /// is authoritative, so take its values. Only an authenticated message may do this.
    Resync,
    /// Behind us (fewer boots, or the same boots and more than 150 s behind), or boots at the
    /// maximum value: the message is not in the window.
    Stale,
}

impl Engine {
    /// The engine's time now, estimated from the last learned time.
    pub fn time_now(&self, now: Instant) -> u32 {
        let elapsed = now.saturating_duration_since(self.learned).as_secs();
        let elapsed = u32::try_from(elapsed).unwrap_or(u32::MAX);
        self.time.saturating_add(elapsed)
    }

    /// Classifies an authenticated message's boots and time. Higher boots or a later time
    /// resync; lower boots, or equal boots more than `TIME_WINDOW` behind, are stale. Boots at
    /// `2^31 - 1` are stale, as RFC 3414 §2.2.2 says.
    pub fn window(&self, boots: u32, time: u32, now: Instant) -> Window {
        if boots >= MAX_BOOTS {
            return Window::Stale;
        }
        if boots > self.boots {
            return Window::Resync;
        }
        if boots < self.boots {
            return Window::Stale;
        }
        let local = self.time_now(now);
        if time > local {
            return Window::Resync;
        }
        if local.saturating_sub(time) > TIME_WINDOW {
            return Window::Stale;
        }
        Window::Accept
    }

    /// Takes an authoritative boots and time, as learned from an authenticated message.
    pub fn resync(&mut self, boots: u32, time: u32, now: Instant) {
        self.boots = boots;
        self.time = time;
        self.learned = now;
    }
}

/// The gate on unauthenticated time resyncs: one per agent per minute (ADR-908). A spoofed
/// `Report` can make the client resync at most this often.
#[derive(Debug, Default)]
pub struct ResyncGate {
    last: Option<Instant>,
}

impl ResyncGate {
    pub fn allow(&mut self, now: Instant) -> bool {
        if self.last.is_some_and(|last| now.saturating_duration_since(last) < RESYNC_INTERVAL) {
            return false;
        }
        self.last = Some(now);
        true
    }
}

/// The inputs of one outgoing v3 message.
#[derive(Debug)]
pub struct Outgoing<'a> {
    pub msg_id: i32,
    pub engine_id: &'a [u8],
    pub boots: u32,
    pub time: u32,
    pub user: &'a [u8],
    /// The reportable flag is set on every request, so the agent answers a `Report`.
    pub reportable: bool,
}

/// Encodes a v3 message. `keys` is `None` for the engine discovery message (noAuthNoPriv,
/// which the agent answers with a `Report`); otherwise the message is authenticated, and
/// encrypted when the keys carry a privacy key. `scoped` is the encoded `ScopedPDU`, or the
/// encoded `PDU` when a discovery message sends an empty `ScopedPDU`.
///
/// The privacy salt is eight random octets per message (64 random bits, from `SystemRandom`).
/// RFC 3826 suggests a counter seeded at random; a per-message random salt needs no counter
/// state across restarts, and 64 bits make a repeat under one key negligible (ADR-908).
pub fn encode(out: &Outgoing<'_>, keys: Option<&RoundKeys>, scoped: &[u8]) -> Result<Vec<u8>, UsmError> {
    let mut salt = [0u8; 8];
    let (auth_len, priv_on, flags) = match keys {
        None => (0usize, false, if out.reportable { FLAG_REPORTABLE } else { 0 }),
        Some(k) => {
            let alg = k.auth_alg.ok_or(UsmError::BadSecurityParameters)?;
            let mut f = FLAG_AUTH;
            if k.has_priv {
                f |= FLAG_PRIV;
            }
            if out.reportable {
                f |= FLAG_REPORTABLE;
            }
            (alg.mac_len(), k.has_priv, f)
        }
    };
    if priv_on {
        SystemRandom::new().fill(&mut salt).map_err(|_| UsmError::Random)?;
    }
    let msg_data = if priv_on {
        let keys = keys.ok_or(UsmError::BadSecurityParameters)?;
        let alg = keys.auth_alg.ok_or(UsmError::BadSecurityParameters)?;
        let key = priv_key(alg, keys, out.engine_id)?;
        let iv = priv_iv(out.boots, out.time, &salt);
        let mut enc = scoped.to_vec();
        aes_cfb::encrypt(&key, &iv, &mut enc);
        ber::octets(&enc)
    } else {
        scoped.to_vec()
    };
    let mut global = Vec::new();
    global.extend(ber::integer(i64::from(out.msg_id)));
    global.extend(ber::integer(MAX_SIZE));
    global.extend(ber::octets(&[flags]));
    global.extend(ber::integer(SECURITY_MODEL_USM));
    let global = ber::sequence(&global);

    let mut prefix = Vec::new();
    prefix.extend(ber::octets(out.engine_id));
    prefix.extend(ber::integer(i64::from(out.boots)));
    prefix.extend(ber::integer(i64::from(out.time)));
    prefix.extend(ber::octets(out.user));
    let prefix_len = prefix.len();
    let auth_tlv = ber::octets(&vec![0u8; auth_len]);
    let priv_tlv = if priv_on { ber::octets(&salt) } else { ber::octets(&[]) };
    let mut usm_content = prefix;
    usm_content.extend_from_slice(&auth_tlv);
    usm_content.extend_from_slice(&priv_tlv);
    let usm_seq = ber::sequence(&usm_content);
    let sec = ber::octets(&usm_seq);

    let mut inner = Vec::new();
    inner.extend(ber::integer(3));
    inner.extend_from_slice(&global);
    inner.extend_from_slice(&sec);
    inner.extend_from_slice(&msg_data);
    let mut whole = ber::sequence(&inner);

    if let Some(keys) = keys {
        let alg = keys.auth_alg.ok_or(UsmError::BadSecurityParameters)?;
        // Offset of the authParameters content inside the whole message.
        let auth_content_off = ber::header_len(inner.len())
            .saturating_add(ber::integer(3).len())
            .saturating_add(global.len())
            .saturating_add(ber::header_len(usm_seq.len()))
            .saturating_add(ber::header_len(usm_content.len()))
            .saturating_add(prefix_len)
            .saturating_add(ber::header_len(auth_len));
        let kul = localize_auth(alg, keys, out.engine_id)?;
        let tag = mac(alg, &kul, &whole);
        let dst = whole
            .get_mut(auth_content_off..auth_content_off.saturating_add(tag.len()))
            .ok_or(UsmError::BadSecurityParameters)?;
        dst.copy_from_slice(&tag);
    }
    Ok(whole)
}

fn localize_auth(alg: AuthProto, keys: &RoundKeys, engine_id: &[u8]) -> Result<Zeroizing<Vec<u8>>, UsmError> {
    let ku = keys.auth_ku.as_ref().ok_or(UsmError::BadSecurityParameters)?;
    Ok(localize(alg, ku, engine_id))
}

/// The privacy key: the first 16 octets of the privacy password localized to the engine.
/// Zeroized when the caller drops it.
fn priv_key(alg: AuthProto, keys: &RoundKeys, engine_id: &[u8]) -> Result<Zeroizing<[u8; 16]>, UsmError> {
    let ku = keys.priv_ku.as_ref().ok_or(UsmError::BadSecurityParameters)?;
    let kul = localize(alg, ku, engine_id);
    let mut key = Zeroizing::new([0u8; 16]);
    let src = kul.get(..16).ok_or(UsmError::BadSecurityParameters)?;
    key.copy_from_slice(src);
    Ok(key)
}

/// The RFC 3826 IV: engineBoots (4) || engineTime (4) || salt (8).
pub fn priv_iv(boots: u32, time: u32, salt: &[u8; 8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    if let Some(dst) = iv.get_mut(0..4) {
        dst.copy_from_slice(&boots.to_be_bytes());
    }
    if let Some(dst) = iv.get_mut(4..8) {
        dst.copy_from_slice(&time.to_be_bytes());
    }
    if let Some(dst) = iv.get_mut(8..16) {
        dst.copy_from_slice(salt);
    }
    iv
}

/// A parsed v3 reply, before its authentication and decryption.
#[derive(Debug)]
pub struct Reply {
    pub msg_id: i32,
    pub flags: u8,
    pub engine_id: Vec<u8>,
    pub boots: u32,
    pub time: u32,
    pub user: Vec<u8>,
    /// The byte range of the authParameters content inside the message, when present.
    pub auth_range: Option<std::ops::Range<usize>>,
    pub priv_salt: Vec<u8>,
    /// The `ScopedPDU` bytes: plaintext as received, or encrypted when `flags` has the priv bit.
    pub scoped: Vec<u8>,
}

/// Parses a v3 reply's envelope. `input` must be the whole datagram.
pub fn parse(input: &[u8]) -> Result<Reply, UsmError> {
    let msg = ber::read_message(input)?;
    if msg.tag != 0x30 {
        return Err(UsmError::Decode(DecodeError::UnexpectedTag { expected: 0x30, found: msg.tag }));
    }
    let kids = ber::children(msg.content, 0, 4)?;
    let [version, global, sec, data] = kids.as_slice() else {
        return Err(UsmError::BadSecurityParameters);
    };
    if ber::integer_value(version.content)? != 3 {
        return Err(UsmError::BadSecurityParameters);
    }
    let g = ber::children(global.content, 1, 4)?;
    let [id, _size, flags, model] = g.as_slice() else {
        return Err(UsmError::BadSecurityParameters);
    };
    if ber::integer_value(model.content)? != SECURITY_MODEL_USM {
        return Err(UsmError::BadSecurityParameters);
    }
    let msg_id = i32::try_from(ber::integer_value(id.content)?).map_err(|_| UsmError::BadSecurityParameters)?;
    let flag_byte = match flags.content {
        [b] => *b,
        _ => return Err(UsmError::BadSecurityParameters),
    };
    // msgSecurityParameters: an OCTET STRING holding the USM SEQUENCE.
    if sec.tag != 0x04 {
        return Err(UsmError::BadSecurityParameters);
    }
    let usm = ber::expect_tag(sec.content, 0x30)?;
    let parts = ber::children(usm.content, 2, 6)?;
    let [eid, eboots, etime, euser, eauth, epriv] = parts.as_slice() else {
        return Err(UsmError::BadSecurityParameters);
    };
    let auth_range = if eauth.content.is_empty() {
        None
    } else {
        let start = offset_in(input, eauth.content);
        Some(start..start.saturating_add(eauth.content.len()))
    };
    let boots = u32::try_from(ber::integer_value(eboots.content)?).map_err(|_| UsmError::BadSecurityParameters)?;
    let time = u32::try_from(ber::integer_value(etime.content)?).map_err(|_| UsmError::BadSecurityParameters)?;
    // msgData: an encrypted OCTET STRING, or the plaintext ScopedPDU SEQUENCE.
    let expected_tag = if flag_byte & FLAG_PRIV != 0 { 0x04 } else { 0x30 };
    if data.tag != expected_tag {
        return Err(UsmError::BadSecurityParameters);
    }
    // A plaintext ScopedPDU is kept whole, with its SEQUENCE header, for `scoped_response`. An
    // encrypted one is kept as the OCTET STRING's content, which is the ciphertext.
    let scoped = if flag_byte & FLAG_PRIV != 0 { data.content.to_vec() } else { data.raw.to_vec() };
    Ok(Reply {
        msg_id,
        flags: flag_byte,
        engine_id: eid.content.to_vec(),
        boots,
        time,
        user: euser.content.to_vec(),
        auth_range,
        priv_salt: epriv.content.to_vec(),
        scoped,
    })
}

fn offset_in(base: &[u8], part: &[u8]) -> usize {
    (part.as_ptr() as usize).saturating_sub(base.as_ptr() as usize)
}

/// Checks a reply's MAC: the message with its authParameters zeroed, under the localized key.
/// The comparison is constant-time. The tag is truncated, so ring's `hmac::verify` cannot
/// be used.
pub fn verify(input: &[u8], reply: &Reply, keys: &RoundKeys) -> Result<(), UsmError> {
    let alg = keys.auth_alg.ok_or(UsmError::BadSecurityParameters)?;
    let range = reply.auth_range.clone().ok_or(UsmError::BadDigest)?;
    if range.len() != alg.mac_len() {
        return Err(UsmError::BadDigest);
    }
    let mut copy = input.to_vec();
    copy.get_mut(range.clone()).ok_or(UsmError::BadDigest)?.fill(0);
    let kul = localize_auth(alg, keys, &reply.engine_id)?;
    let expected = mac(alg, &kul, &copy);
    let got = input.get(range).ok_or(UsmError::BadDigest)?;
    if ct_eq(&expected, got) {
        Ok(())
    } else {
        Err(UsmError::BadDigest)
    }
}

/// Decrypts a reply's `ScopedPDU` with the privacy key and the reply's own IV.
pub fn decrypt(reply: &Reply, keys: &RoundKeys) -> Result<Vec<u8>, UsmError> {
    let alg = keys.auth_alg.ok_or(UsmError::BadSecurityParameters)?;
    let key = priv_key(alg, keys, &reply.engine_id).map_err(|_| UsmError::DecryptFailed)?;
    let salt: [u8; 8] = reply.priv_salt.as_slice().try_into().map_err(|_| UsmError::DecryptFailed)?;
    let iv = priv_iv(reply.boots, reply.time, &salt);
    let mut data = reply.scoped.clone();
    aes_cfb::decrypt(&key, &iv, &mut data);
    Ok(data)
}

/// The `flags` byte's authFlag and privFlag bits (RFC 3412 §6).
pub const LEVEL_MASK: u8 = FLAG_AUTH | FLAG_PRIV;
/// The authFlag bit alone: authNoPriv.
pub const AUTH_FLAG: u8 = FLAG_AUTH;

/// Decodes a `ScopedPDU`: `contextEngineID`, `contextName`, and a `PDU`.
pub fn scoped_response(scoped: &[u8]) -> Result<Response, UsmError> {
    let seq = ber::expect_tag(scoped, 0x30)?;
    let kids = ber::children(seq.content, 1, 3)?;
    let [_engine, _name, pdu_tlv] = kids.as_slice() else {
        return Err(UsmError::BadSecurityParameters);
    };
    Ok(pdu::decode_response(*pdu_tlv)?)
}

/// Encodes a `ScopedPDU` around an encoded request `PDU`, with an empty context.
pub fn scoped_request(engine_id: &[u8], pdu: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(ber::octets(engine_id));
    body.extend(ber::octets(&[]));
    body.extend_from_slice(pdu);
    ber::sequence(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .filter_map(|i| s.get(i..i.saturating_add(2)).and_then(|p| u8::from_str_radix(p, 16).ok()))
            .collect()
    }

    #[test]
    fn dsc_003_rfc3414_a3_key_vectors() {
        // RFC 3414 A.3.2, SHA-1: password "maplesyrup", engineID 00..02.
        let engine = hex("000000000000000000000002");
        let ku = password_to_key(AuthProto::HmacSha96, b"maplesyrup").unwrap_or_default();
        assert_eq!(ku.as_slice(), hex("9fb5cc0381497b3793528939ff788d5d79145211").as_slice());
        let kul = localize(AuthProto::HmacSha96, &ku, &engine);
        assert_eq!(kul.as_slice(), hex("6695febc9288e36282235fc7151f128497b38f3f").as_slice());
    }

    #[test]
    fn dsc_003_rfc7860_vectors() {
        // RFC 7860 gives the truncation lengths; its HMAC values come from RFC 6234 and RFC 4231,
        // whose test case 1 (key 0x0b repeated 20 times, "Hi There") is checked here.
        let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let full256 = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), data);
        assert_eq!(full256.as_ref(), hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").as_slice());
        assert_eq!(mac(AuthProto::Sha256, &key, data), hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").get(..24).unwrap_or(&[]).to_vec());
        assert_eq!(mac(AuthProto::Sha384, &key, data), hex("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6").get(..32).unwrap_or(&[]).to_vec());
        assert_eq!(mac(AuthProto::Sha512, &key, data), hex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854").get(..48).unwrap_or(&[]).to_vec());
        assert_eq!(AuthProto::HmacSha96.mac_len(), 12);
        assert_eq!(AuthProto::Sha256.mac_len(), 24);
        assert_eq!(AuthProto::Sha384.mac_len(), 32);
        assert_eq!(AuthProto::Sha512.mac_len(), 48);
    }

    #[test]
    fn dsc_003_refused_protocols_explained() {
        for (name, want) in [("MD5", Refused::Md5), ("SHA-224", Refused::Sha224)] {
            assert_eq!(AuthProto::parse(name), Err(want), "{name}");
            assert_ne!(want.reason(), "");
        }
        assert_eq!(PrivProto::parse("DES"), Err(Refused::Des));
        assert_eq!(PrivProto::parse("AES-192"), Err(Refused::Aes192));
        assert_eq!(PrivProto::parse("AES-256"), Err(Refused::Aes256));
        assert_eq!(AuthProto::parse("NONE"), Err(Refused::NoAuthNoPriv));
        assert_eq!(AuthProto::parse("SHA-256"), Ok(AuthProto::Sha256));
        assert_eq!(PrivProto::parse("AES"), Ok(PrivProto::Aes128));
        assert!(Refused::Md5.reason().contains("MD5"));
        assert!(Refused::Des.reason().contains("DES"));
    }

    #[test]
    fn dsc_003_empty_password_has_no_key() {
        assert!(password_to_key(AuthProto::Sha256, b"").is_none());
    }

    #[test]
    fn dsc_003_spoofed_report_resync_limited() {
        let t0 = Instant::now();
        let mut gate = ResyncGate::default();
        let mut allowed = 0;
        // Ten reports inside one minute: one resync.
        for i in 0..10u64 {
            if gate.allow(t0 + Duration::from_secs(i)) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 1);
        // After a minute, one more is allowed.
        assert!(gate.allow(t0 + RESYNC_INTERVAL));
        assert!(!gate.allow(t0 + RESYNC_INTERVAL + Duration::from_secs(1)));
    }

    #[test]
    fn dsc_003_time_window_follows_rfc3414() {
        let t0 = Instant::now();
        let mut e = Engine { id: vec![1, 2, 3], boots: 5, time: 1000, learned: t0 };
        // Same boots, time within 150 s either way: accepted.
        assert_eq!(e.window(5, 1000, t0), Window::Accept);
        assert_eq!(e.window(5, 850, t0), Window::Accept);
        // Same boots, more than 150 s behind: stale.
        assert_eq!(e.window(5, 849, t0), Window::Stale);
        // Same boots, ahead of us: the agent's clock is authoritative.
        assert_eq!(e.window(5, 1151, t0), Window::Resync);
        // Fewer boots: stale; more boots (a real reboot): resync.
        assert_eq!(e.window(4, 1000, t0), Window::Stale);
        assert_eq!(e.window(6, 50, t0), Window::Resync);
        // The local clock advances with elapsed time.
        assert_eq!(e.window(5, 1100, t0 + Duration::from_secs(100)), Window::Accept);
        // Boots at the maximum cannot be synchronized.
        assert_eq!(e.window(MAX_BOOTS, 1000, t0), Window::Stale);
        e.resync(6, 50, t0);
        assert_eq!(e.boots, 6);
        assert_eq!(e.time, 50);
    }

    #[test]
    fn dsc_003_priv_iv_layout() {
        let iv = priv_iv(0x0102_0304, 0x0506_0708, &[9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(iv.get(..4), Some(&[1u8, 2, 3, 4][..]));
        assert_eq!(iv.get(4..8), Some(&[5u8, 6, 7, 8][..]));
        assert_eq!(iv.get(8..), Some(&[9u8, 10, 11, 12, 13, 14, 15, 16][..]));
    }

    #[test]
    fn dsc_003_ct_eq_is_exact() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    fn test_user(priv_on: bool) -> UsmUser {
        UsmUser {
            name: b"ttuser".to_vec(),
            auth: Some((AuthProto::Sha256, SecretValue::new(b"authpass-1234".to_vec()))),
            privacy: priv_on.then(|| (PrivProto::Aes128, SecretValue::new(b"privpass-1234".to_vec()))),
        }
    }

    fn scoped_request_for_test(engine: &[u8]) -> Vec<u8> {
        let pdu = crate::pdu::encode_request(crate::pdu::RequestKind::Get, 1, 0, 0, &[]).unwrap_or_default();
        scoped_request(engine, &pdu)
    }

    /// The MAC offset worked out inside `encode` must point at the authParameters content:
    /// the parsed range holds the MAC over the zeroed message, and verification passes.
    #[test]
    fn dsc_003_usm_encode_offset_round_trips() {
        let engine = hex("800000090102030405");
        for priv_on in [false, true] {
            let keys = test_user(priv_on).derive().unwrap_or_else(|e| panic!("{e:?}"));
            let scoped = scoped_request_for_test(&engine);
            let out = Outgoing { msg_id: 77, engine_id: &engine, boots: 3, time: 500, user: b"ttuser", reportable: true };
            let msg = encode(&out, Some(&keys), &scoped).unwrap_or_else(|e| panic!("{e:?}"));
            let reply = parse(&msg).unwrap_or_else(|e| panic!("{e:?}"));
            let range = reply.auth_range.clone().unwrap_or_default();
            assert_eq!(range.len(), 24, "SHA-256 MAC is 24 octets");
            let mut zeroed = msg.clone();
            zeroed.get_mut(range.clone()).unwrap_or(&mut []).fill(0);
            let ku: Vec<u8> = keys.auth_ku.as_ref().map(|k| k.to_vec()).unwrap_or_default();
            let kul = localize(AuthProto::Sha256, &ku, &engine);
            let expect = mac(AuthProto::Sha256, &kul, &zeroed);
            assert_eq!(msg.get(range.clone()), Some(expect.as_slice()));
            assert!(verify(&msg, &reply, &keys).is_ok());
            // A flipped byte in the last octet fails verification.
            let mut bad = msg.clone();
            let last = bad.len().saturating_sub(1);
            if let Some(b) = bad.get_mut(last) {
                *b ^= 1;
            }
            if let Ok(bad_reply) = parse(&bad) {
                assert!(verify(&bad, &bad_reply, &keys).is_err());
            }
        }
    }

    #[test]
    fn dsc_003_usm_privacy_round_trip() {
        let engine = hex("800000090102030405");
        let keys = test_user(true).derive().unwrap_or_else(|e| panic!("{e:?}"));
        let scoped = scoped_request_for_test(&engine);
        let out = Outgoing { msg_id: 5, engine_id: &engine, boots: 1, time: 2, user: b"ttuser", reportable: true };
        let msg = encode(&out, Some(&keys), &scoped).unwrap_or_else(|e| panic!("{e:?}"));
        let reply = parse(&msg).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(reply.flags & LEVEL_MASK, FLAG_AUTH | FLAG_PRIV);
        assert_ne!(reply.scoped, scoped);
        let plain = decrypt(&reply, &keys).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(plain, scoped);
    }
}

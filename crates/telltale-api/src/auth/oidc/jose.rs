//! JSON Web Signature checks for `OpenID` Connect ID tokens and MCP access tokens (REQ:
//! API-004, AGT-008, ADR-951): the signing-algorithm allow-list, JWK-to-key conversion, the
//! `typ`, `cty` and `crit` header rules, key selection by `kid`, and the signature itself, on
//! `ring` (already in the tree). Pure: no I/O and no clock.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde_json::Value;

/// The nine asymmetric algorithms this server verifies (ADR-951 decision 2). `none` and the HMAC
/// algorithms are not in the list, so a provider's public key is never used as an HMAC secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Alg {
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    EdDsa,
}

/// Every algorithm this server verifies, in the order the discovery intersection keeps them.
pub(super) const ALL: [Alg; 9] = [
    Alg::Rs256,
    Alg::Rs384,
    Alg::Rs512,
    Alg::Ps256,
    Alg::Ps384,
    Alg::Ps512,
    Alg::Es256,
    Alg::Es384,
    Alg::EdDsa,
];

impl Alg {
    /// The JOSE name (`alg` header value).
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
        }
    }

    /// The algorithm a JOSE name stands for, if this server verifies it.
    pub(super) fn from_name(name: &str) -> Option<Self> {
        ALL.into_iter().find(|alg| alg.name() == name)
    }

    /// Whether a key of this shape may verify this algorithm (kind, and curve for EC keys).
    fn fits(self, shape: &Shape) -> bool {
        matches!(
            (self, shape),
            (
                Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512,
                Shape::Rsa { .. }
            ) | (Self::Es256, Shape::Ec { crv: "P-256", .. })
                | (Self::Es384, Shape::Ec { crv: "P-384", .. })
                | (Self::EdDsa, Shape::Okp { .. })
        )
    }
}

/// The public key material a JWK carries, checked when the key is read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Shape {
    /// The modulus and exponent, without leading zero bytes; the modulus is at least 2048 bits.
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// An uncompressed point (`0x04 || x || y`) on `crv`.
    Ec { crv: &'static str, point: Vec<u8> },
    /// An Ed25519 public key.
    Okp { x: Vec<u8> },
}

/// A verification key from a provider's key set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Key {
    kid: Option<String>,
    /// The JWK's own `alg`, when present: it must equal the token's.
    alg: Option<String>,
    shape: Shape,
}

impl Key {
    /// The key, or `None` when the JWK isn't a usable signing key: `use` is present and isn't
    /// `sig`; the key type or curve is unknown (so no symmetric key is ever a verification key);
    /// a component is malformed; or an RSA modulus is under 2048 bits (ADR-951 decision 5).
    pub(super) fn from_jwk(jwk: &Value) -> Option<Self> {
        if jwk.get("use").is_some_and(|u| u.as_str() != Some("sig")) {
            return None;
        }
        let kid = match jwk.get("kid") {
            None => None,
            Some(v) => Some(v.as_str()?.to_owned()),
        };
        let alg = match jwk.get("alg") {
            None => None,
            Some(v) => Some(v.as_str()?.to_owned()),
        };
        let field = |name: &str| jwk.get(name).and_then(Value::as_str).and_then(b64);
        let shape = match jwk.get("kty")?.as_str()? {
            "RSA" => {
                let n = strip_zeros(field("n")?);
                let e = strip_zeros(field("e")?);
                if bit_len(&n) < 2048 || e.is_empty() {
                    return None;
                }
                Shape::Rsa { n, e }
            }
            "EC" => {
                let (crv, len) = match jwk.get("crv")?.as_str()? {
                    "P-256" => ("P-256", 32),
                    "P-384" => ("P-384", 48),
                    _ => return None,
                };
                let (x, y) = (field("x")?, field("y")?);
                if x.len() != len || y.len() != len {
                    return None;
                }
                let mut point = Vec::with_capacity(1 + 2 * len);
                point.push(0x04);
                point.extend(x);
                point.extend(y);
                Shape::Ec { crv, point }
            }
            "OKP" => {
                if jwk.get("crv")?.as_str()? != "Ed25519" {
                    return None;
                }
                let x = field("x")?;
                if x.len() != 32 {
                    return None;
                }
                Shape::Okp { x }
            }
            _ => return None,
        };
        Some(Self { kid, alg, shape })
    }

    /// Whether this key may verify `alg` (kind and curve, and the JWK's `alg` when present).
    fn accepts(&self, alg: Alg) -> bool {
        self.alg.as_deref().is_none_or(|a| a == alg.name()) && alg.fits(&self.shape)
    }

    /// Whether `signature` is `alg`'s signature of `message` under this key.
    fn verify(&self, alg: Alg, message: &[u8], signature: &[u8]) -> bool {
        match (&self.shape, alg) {
            (Shape::Rsa { n, e }, _) => {
                let params = match alg {
                    Alg::Rs256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    Alg::Rs384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    Alg::Rs512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    Alg::Ps256 => &signature::RSA_PSS_2048_8192_SHA256,
                    Alg::Ps384 => &signature::RSA_PSS_2048_8192_SHA384,
                    Alg::Ps512 => &signature::RSA_PSS_2048_8192_SHA512,
                    Alg::Es256 | Alg::Es384 | Alg::EdDsa => return false,
                };
                RsaPublicKeyComponents { n, e }
                    .verify(params, message, signature)
                    .is_ok()
            }
            (Shape::Ec { point, .. }, Alg::Es256) => {
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                    .verify(message, signature)
                    .is_ok()
            }
            (Shape::Ec { point, .. }, Alg::Es384) => {
                UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, point)
                    .verify(message, signature)
                    .is_ok()
            }
            (Shape::Okp { x }, Alg::EdDsa) => UnparsedPublicKey::new(&signature::ED25519, x)
                .verify(message, signature)
                .is_ok(),
            _ => false,
        }
    }
}

/// Which token is checked. The `typ` rules differ: an access token may be `at+jwt` (RFC 9068),
/// an ID token may not, so an access token can't pass as an ID token (ADR-951).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    IdToken,
    AccessToken,
}

/// Why a token was refused. `NoKey` and `Signature` may mean the provider rotated its keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Failure {
    /// Not a compact JWS, or a part that doesn't decode; the text says which.
    Malformed(&'static str),
    /// The header's `alg` is missing, unknown, not verified here, or not allowed.
    Algorithm,
    /// A header parameter this server refuses (`typ`, `cty` or `crit`).
    Header(&'static str),
    /// No key fits the token's `kid`, algorithm and kind.
    NoKey,
    /// The token has no `kid`, and more than one key fits it.
    Ambiguous,
    /// A key fits, and none of them verifies the signature.
    Signature,
}

impl Failure {
    /// The reason, as a sentence for the error text.
    pub(super) fn reason(&self) -> &'static str {
        match self {
            Self::Malformed(why) | Self::Header(why) => why,
            Self::Algorithm => "unsupported signing algorithm",
            Self::NoKey => "no key in the provider's key set fits this token",
            Self::Ambiguous => "the token has no key ID and several keys fit it",
            Self::Signature => "the signature doesn't verify",
        }
    }

    /// The provider may have rotated its keys: refetch the key set once, then try again.
    pub(super) fn may_be_rotation(&self) -> bool {
        matches!(self, Self::NoKey | Self::Signature)
    }
}

/// A token whose signature verified: its claims, which must be a JSON object.
#[derive(Debug)]
pub(super) struct Verified {
    pub(super) payload: Value,
}

/// Verifies a compact JWS against `keys` (ADR-951, "Algorithm and key rules"): the header first
/// (allow-listed `alg`, then `typ`, `cty` and `crit`), then the keys that fit it, then the
/// signature. The algorithm is checked on its own, before any key is chosen, so an allow-list
/// is never compared with a key of another family.
pub(super) fn verify(
    token: &str,
    keys: &[Key],
    allowed: &[Alg],
    kind: Kind,
) -> Result<Verified, Failure> {
    let mut parts = token.split('.');
    let (Some(head), Some(body), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Failure::Malformed("not a JWT"));
    };
    let header: Value = b64(head)
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or(Failure::Malformed("unreadable header"))?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .and_then(Alg::from_name)
        .filter(|alg| allowed.contains(alg))
        .ok_or(Failure::Algorithm)?;
    check_header(&header, kind)?;
    let key_id = match header.get("kid") {
        None => None,
        Some(v) => Some(
            v.as_str()
                .ok_or(Failure::Malformed("the key ID isn't a string"))?,
        ),
    };
    let signature = b64(sig).ok_or(Failure::Malformed("unreadable signature"))?;
    let candidates: Vec<&Key> = keys
        .iter()
        .filter(|key| key_id.is_none_or(|id| key.kid.as_deref() == Some(id)))
        .filter(|key| key.accepts(alg))
        .collect();
    if candidates.is_empty() {
        return Err(Failure::NoKey);
    }
    if key_id.is_none() && candidates.len() > 1 {
        return Err(Failure::Ambiguous);
    }
    let signed = format!("{head}.{body}");
    if !candidates
        .iter()
        .any(|key| key.verify(alg, signed.as_bytes(), &signature))
    {
        return Err(Failure::Signature);
    }
    let payload = b64(body)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(Value::is_object)
        .ok_or(Failure::Malformed("unreadable claims"))?;
    Ok(Verified { payload })
}

/// The header parameters this server refuses (ADR-951): a `typ` other than the token's own,
/// a nested JWT (`cty`), and critical extensions it doesn't implement (`crit`).
fn check_header(header: &Value, kind: Kind) -> Result<(), Failure> {
    if let Some(typ) = header.get("typ") {
        let typ = typ
            .as_str()
            .ok_or(Failure::Header("the token type isn't a string"))?
            .to_ascii_lowercase();
        let accepted = match kind {
            Kind::IdToken => matches!(typ.as_str(), "jwt" | "application/jwt" | "application/jose"),
            Kind::AccessToken => {
                matches!(
                    typ.as_str(),
                    "jwt" | "application/jwt" | "at+jwt" | "application/at+jwt"
                )
            }
        };
        if !accepted {
            return Err(Failure::Header(
                "the token type isn't one this server accepts",
            ));
        }
    }
    if let Some(cty) = header.get("cty") {
        let cty = cty
            .as_str()
            .ok_or(Failure::Header("the content type isn't a string"))?;
        if cty.eq_ignore_ascii_case("JWT") || cty.eq_ignore_ascii_case("application/jwt") {
            return Err(Failure::Header("nested JWTs aren't accepted"));
        }
    }
    if header.get("crit").is_some() {
        return Err(Failure::Header(
            "critical header parameters aren't supported",
        ));
    }
    Ok(())
}

/// URL-safe base64 without padding (a trailing `=` is tolerated).
fn b64(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok()
}

/// The big-endian integer without its leading zero bytes.
fn strip_zeros(bytes: Vec<u8>) -> Vec<u8> {
    bytes.into_iter().skip_while(|b| *b == 0).collect()
}

/// The bit length of a big-endian integer without leading zero bytes.
fn bit_len(n: &[u8]) -> usize {
    n.first().map_or(0, |top| {
        (n.len() - 1) * 8 + (8 - top.leading_zeros() as usize)
    })
}

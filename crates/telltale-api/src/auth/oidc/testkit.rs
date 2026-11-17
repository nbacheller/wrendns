//! Test-only signing for the OIDC tests (REQ: API-004, ADR-951): RSA keys from the committed
//! PKCS#1 fixture, EC and Ed25519 keys made at test time, compact JWS signing on `ring`, and
//! the JWK of each key. Nothing here is a verification path.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, RsaKeyPair};
use serde_json::{Value, json};

use super::jose::Alg;

/// The RSA test key: a 2048-bit PKCS#1 `RSA PRIVATE KEY`.
const PEM: &str = include_str!("test-key.pem");

enum Key {
    Rsa {
        pair: RsaKeyPair,
        n: Vec<u8>,
        e: Vec<u8>,
    },
    Ec {
        pair: EcdsaKeyPair,
        crv: &'static str,
        len: usize,
    },
    Ed(Ed25519KeyPair),
}

/// A signing key with its `kid` and the algorithm it signs with.
pub(super) struct Signer {
    pub(super) kid: String,
    pub(super) alg: Alg,
    key: Key,
}

impl Signer {
    /// The committed RSA key, signing with `alg` (an RS* or PS* algorithm).
    pub(super) fn rsa(kid: &str, alg: Alg) -> Self {
        let der = pem_to_der(PEM);
        let pair = RsaKeyPair::from_der(&der).expect("the committed RSA test key parses");
        let (n, e) = pkcs1_n_e(&der);
        Self {
            kid: kid.to_owned(),
            alg,
            key: Key::Rsa { pair, n, e },
        }
    }

    /// A freshly generated EC (ES256 or ES384) or Ed25519 (`EdDSA`) key.
    pub(super) fn generated(kid: &str, alg: Alg) -> Self {
        let rng = SystemRandom::new();
        let key = match alg {
            Alg::Es256 => ec(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                "P-256",
                32,
                &rng,
            ),
            Alg::Es384 => ec(
                &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                "P-384",
                48,
                &rng,
            ),
            Alg::EdDsa => {
                let doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("Ed25519 key");
                Key::Ed(Ed25519KeyPair::from_pkcs8(doc.as_ref()).expect("Ed25519 key parses"))
            }
            _ => panic!("generated keys are for ES256, ES384 and EdDSA"),
        };
        Self {
            kid: kid.to_owned(),
            alg,
            key,
        }
    }

    /// The public key as a JWK, with `kid`, `alg` and `use: sig`.
    pub(super) fn jwk(&self) -> Value {
        let mut jwk = match &self.key {
            Key::Rsa { n, e, .. } => json!({
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode(n),
                "e": URL_SAFE_NO_PAD.encode(e),
            }),
            Key::Ec { pair, crv, len } => {
                let point = pair.public_key().as_ref();
                let (x, y) = point[1..].split_at(*len);
                json!({
                    "kty": "EC",
                    "crv": crv,
                    "x": URL_SAFE_NO_PAD.encode(x),
                    "y": URL_SAFE_NO_PAD.encode(y),
                })
            }
            Key::Ed(pair) => json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
            }),
        };
        jwk["kid"] = json!(self.kid);
        jwk["alg"] = json!(self.alg.name());
        jwk["use"] = json!("sig");
        jwk
    }

    /// The signature of `message` (the signing input) with this key.
    pub(super) fn sign(&self, message: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        match &self.key {
            Key::Rsa { pair, .. } => {
                let padding: &'static dyn signature::RsaEncoding = match self.alg {
                    Alg::Rs256 => &signature::RSA_PKCS1_SHA256,
                    Alg::Rs384 => &signature::RSA_PKCS1_SHA384,
                    Alg::Rs512 => &signature::RSA_PKCS1_SHA512,
                    Alg::Ps256 => &signature::RSA_PSS_SHA256,
                    Alg::Ps384 => &signature::RSA_PSS_SHA384,
                    Alg::Ps512 => &signature::RSA_PSS_SHA512,
                    _ => panic!("an RSA key signs RS* and PS* tokens"),
                };
                let mut out = vec![0; pair.public().modulus_len()];
                pair.sign(padding, &rng, message, &mut out)
                    .expect("RSA signing");
                out
            }
            Key::Ec { pair, .. } => pair
                .sign(&rng, message)
                .expect("EC signing")
                .as_ref()
                .to_vec(),
            Key::Ed(pair) => pair.sign(message).as_ref().to_vec(),
        }
    }

    /// The header this key's tokens carry by default.
    pub(super) fn header(&self) -> Value {
        json!({ "alg": self.alg.name(), "kid": self.kid, "typ": "JWT" })
    }

    /// A compact JWS: `header` and `claims` as JSON, signed with this key.
    pub(super) fn token(&self, header: &Value, claims: &Value) -> String {
        let signing_input = format!("{}.{}", b64_json(header), b64_json(claims));
        let sig = self.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }
}

fn ec(
    alg: &'static signature::EcdsaSigningAlgorithm,
    crv: &'static str,
    len: usize,
    rng: &SystemRandom,
) -> Key {
    let doc = EcdsaKeyPair::generate_pkcs8(alg, rng).expect("EC key");
    let pair = EcdsaKeyPair::from_pkcs8(alg, doc.as_ref(), rng).expect("EC key parses");
    Key::Ec { pair, crv, len }
}

/// Base64url of a JSON value's compact serialization.
pub(super) fn b64_json(v: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).expect("JSON"))
}

/// A token with the algorithm `none` and no signature.
pub(super) fn unsigned_token(header: &Value, claims: &Value) -> String {
    format!("{}.{}.", b64_json(header), b64_json(claims))
}

/// An HS256 token whose "secret" is `secret` (for the algorithm-confusion test).
pub(super) fn hs256_token(secret: &[u8], claims: &Value) -> String {
    let header = json!({ "alg": "HS256", "kid": "k1", "typ": "JWT" });
    let signing_input = format!("{}.{}", b64_json(&header), b64_json(claims));
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let tag = ring::hmac::sign(&key, signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(tag.as_ref()))
}

/// The DER bytes of a single-block PEM (the test key has no headers to skip).
fn pem_to_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(body).expect("PEM body is base64")
}

/// The modulus and exponent of a PKCS#1 `RSAPrivateKey` (without leading zero bytes).
fn pkcs1_n_e(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (_, seq, _) = read_tlv(der);
    let (_, _version, rest) = read_tlv(seq);
    let (_, n, rest) = read_tlv(rest);
    let (_, e, _) = read_tlv(rest);
    (strip(n), strip(e))
}

fn strip(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().skip_while(|b| *b == 0).collect()
}

/// One DER element: its tag, its content, and the rest of the input.
fn read_tlv(input: &[u8]) -> (u8, &[u8], &[u8]) {
    let tag = input[0];
    let first = usize::from(input[1]);
    let (len, start) = if first < 0x80 {
        (first, 2)
    } else {
        let count = first & 0x7f;
        let len = input[2..2 + count]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, 2 + count)
    };
    (tag, &input[start..start + len], &input[start + len..])
}

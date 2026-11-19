//! REQ: API-004, AGT-008 — the token checks without a provider: every signing family, the
//! algorithm and key rules, the header rules, key rotation and the claim types (ADR-951).
//! The end-to-end flow against the fake provider is in `flow_tests.rs`.

use serde_json::{Value, json};

use super::claims::{self, IdCheck};
use super::jose::{self, ALL, Alg, Failure, Key, Kind};
use super::metadata;
use super::testkit::{Signer, b64_json, hs256_token, unsigned_token};

const ISS: &str = "https://idp.test";
const CLIENT: &str = "telltale";
const NONCE: &str = "n-1";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Claims a provider would issue for `CLIENT` right now.
fn id_claims() -> Value {
    let t = now();
    json!({"iss": ISS, "aud": CLIENT, "sub": "sub-1", "exp": t + 300, "iat": t, "nonce": NONCE})
}

fn check_id(c: &Value) -> Result<(), String> {
    check_id_at(c, now())
}

fn check_id_at(c: &Value, at: u64) -> Result<(), String> {
    claims::id_token(
        c,
        &IdCheck {
            issuer: ISS,
            client_id: CLIENT,
            nonce: NONCE,
            now: at,
        },
    )
}

/// The keys a provider would publish for `signers`, read as the server reads them.
fn keys_of(signers: &[&Signer]) -> Vec<Key> {
    signers
        .iter()
        .filter_map(|s| Key::from_jwk(&s.jwk()))
        .collect()
}

#[test]
fn api_004_each_signing_family_verifies() {
    // RS* and PS*: one 2048-bit key per padding; ES256, ES384 and EdDSA: generated keys.
    for alg in ALL {
        let signer = match alg {
            Alg::Es256 | Alg::Es384 | Alg::EdDsa => Signer::generated("k1", alg),
            _ => Signer::rsa("k1", alg),
        };
        let keys = keys_of(&[&signer]);
        let token = signer.token(&signer.header(), &id_claims());
        let verified = jose::verify(&token, &keys, &ALL, Kind::IdToken)
            .unwrap_or_else(|e| panic!("{} should verify: {e:?}", alg.name()));
        assert_eq!(verified.payload["sub"], "sub-1", "{}", alg.name());
    }
}

#[test]
fn api_004_allow_list_is_checked_before_any_key_is_chosen() {
    // An RSA key and an EC key are both published: an ES256 token must still verify, which a
    // jsonwebtoken-style `Validation` holding algorithms of two families could not do.
    let rsa = Signer::rsa("rsa", Alg::Rs256);
    let ec = Signer::generated("ec", Alg::Es256);
    let keys = keys_of(&[&rsa, &ec]);
    let token = ec.token(&ec.header(), &id_claims());
    assert!(jose::verify(&token, &keys, &ALL, Kind::IdToken).is_ok());
    let rs = rsa.token(&rsa.header(), &id_claims());
    assert!(jose::verify(&rs, &keys, &ALL, Kind::IdToken).is_ok());
}

#[test]
fn api_004_none_and_hmac_tokens_are_never_accepted() {
    let rsa = Signer::rsa("k1", Alg::Rs256);
    let keys = keys_of(&[&rsa]);
    let none = unsigned_token(&json!({"alg": "none", "kid": "k1"}), &id_claims());
    assert_eq!(
        jose::verify(&none, &keys, &ALL, Kind::IdToken).unwrap_err(),
        Failure::Algorithm,
        "alg=none"
    );
    // The provider's public key bytes used as an HMAC secret (the algorithm-confusion attack).
    let public = b64_json(&json!("modulus"));
    let hs = hs256_token(public.as_bytes(), &id_claims());
    assert_eq!(
        jose::verify(&hs, &keys, &ALL, Kind::IdToken).unwrap_err(),
        Failure::Algorithm,
        "HS256 with the public key"
    );
}

#[test]
fn api_004_bad_signature_is_refused() {
    let signer = Signer::rsa("k1", Alg::Rs256);
    let keys = keys_of(&[&signer]);
    let token = signer.token(&signer.header(), &id_claims());
    // One flipped bit in the signature.
    let (msg, sig) = token.rsplit_once('.').expect("compact JWS");
    let mut bytes = base64_url_decode(sig);
    bytes[0] ^= 0x01;
    let flipped = format!("{msg}.{}", base64_url_encode(&bytes));
    assert_eq!(
        jose::verify(&flipped, &keys, &ALL, Kind::IdToken).unwrap_err(),
        Failure::Signature
    );
}

#[test]
fn api_004_key_kind_and_curve_must_fit_the_algorithm() {
    // ES256 header, RSA key only: no key fits.
    let rsa = Signer::rsa("k1", Alg::Rs256);
    let keys = keys_of(&[&rsa]);
    let es = Signer::generated("k1", Alg::Es256);
    let token = es.token(&es.header(), &id_claims());
    assert_eq!(
        jose::verify(&token, &keys, &ALL, Kind::IdToken).unwrap_err(),
        Failure::NoKey,
        "key-kind mismatch"
    );
    // An ES256 token against a P-384 key: the curve must match the algorithm.
    let p384 = Signer::generated("k1", Alg::Es384);
    let keys = keys_of(&[&p384]);
    assert_eq!(
        jose::verify(&token, &keys, &ALL, Kind::IdToken).unwrap_err(),
        Failure::NoKey,
        "EC key on the wrong curve"
    );
}

#[test]
fn api_004_okp_key_must_be_ed25519_and_rsa_must_be_2048_bits() {
    let okp =
        json!({"kty": "OKP", "crv": "X25519", "x": base64_url_encode(&[7u8; 32]), "kid": "k1"});
    assert!(
        Key::from_jwk(&okp).is_none(),
        "an X25519 key is not a signing key"
    );
    // A 1024-bit modulus: refused when read, before any signature is looked at.
    let mut n = vec![0x80u8];
    n.extend([0x11u8; 127]);
    let short = json!({"kty": "RSA", "kid": "k1", "n": base64_url_encode(&n), "e": "AQAB"});
    assert!(Key::from_jwk(&short).is_none(), "a 1024-bit RSA key");
    // The same shape at 2048 bits is read.
    let mut n = vec![0x80u8];
    n.extend([0x11u8; 255]);
    let long = json!({"kty": "RSA", "kid": "k1", "n": base64_url_encode(&n), "e": "AQAB"});
    assert!(Key::from_jwk(&long).is_some());
}

#[test]
fn api_004_symmetric_and_encryption_keys_are_not_used() {
    let oct = json!({"kty": "oct", "kid": "k1", "k": "c2VjcmV0"});
    assert!(Key::from_jwk(&oct).is_none(), "no symmetric keys");
    let signer = Signer::rsa("k1", Alg::Rs256);
    let mut jwk = signer.jwk();
    jwk["use"] = json!("enc");
    assert!(Key::from_jwk(&jwk).is_none(), "use=enc is ignored");
    let keys = keys_of(&[&signer]);
    let mut only_enc = signer.jwk();
    only_enc["use"] = json!("enc");
    let enc_keys: Vec<Key> = Key::from_jwk(&only_enc).into_iter().collect();
    let token = signer.token(&signer.header(), &id_claims());
    assert_eq!(
        jose::verify(&token, &enc_keys, &ALL, Kind::IdToken).unwrap_err(),
        Failure::NoKey
    );
    assert!(jose::verify(&token, &keys, &ALL, Kind::IdToken).is_ok());
}

#[test]
fn api_004_the_jwk_alg_must_equal_the_token_alg() {
    // The key says RS384; an RS256 token must not use it.
    let signer = Signer::rsa("k1", Alg::Rs384);
    let keys = keys_of(&[&signer]);
    let mut header = signer.header();
    header["alg"] = json!("RS256");
    let token = signer.token(&header, &id_claims());
    assert_eq!(
        jose::verify(&token, &keys, &ALL, Kind::IdToken).unwrap_err(),
        Failure::NoKey
    );
}

#[test]
fn api_004_typ_cty_and_crit_are_checked() {
    let signer = Signer::rsa("k1", Alg::Rs256);
    let keys = keys_of(&[&signer]);
    let at = |header: Value| {
        let token = signer.token(&header, &id_claims());
        jose::verify(&token, &keys, &ALL, Kind::IdToken)
    };
    // An access token (`at+jwt`) must not pass as an ID token.
    assert!(matches!(
        at(json!({"alg": "RS256", "kid": "k1", "typ": "at+jwt"})),
        Err(Failure::Header(_))
    ));
    assert!(at(json!({"alg": "RS256", "kid": "k1", "typ": "JWT"})).is_ok());
    assert!(at(json!({"alg": "RS256", "kid": "k1", "typ": "application/jose"})).is_ok());
    assert!(matches!(
        at(json!({"alg": "RS256", "kid": "k1", "cty": "JWT"})),
        Err(Failure::Header(_))
    ));
    assert!(matches!(
        at(json!({"alg": "RS256", "kid": "k1", "crit": ["exp"]})),
        Err(Failure::Header(_))
    ));
    // An access token is accepted with `at+jwt`, and an ID token's `typ` rules don't apply to it.
    let token = signer.token(
        &json!({"alg": "RS256", "kid": "k1", "typ": "at+jwt"}),
        &id_claims(),
    );
    assert!(jose::verify(&token, &keys, &ALL, Kind::AccessToken).is_ok());
}

#[test]
fn api_004_a_missing_kid_with_two_eligible_keys_is_refused() {
    let a = Signer::generated("a", Alg::Es256);
    let b = Signer::generated("b", Alg::Es256);
    let keys = keys_of(&[&a, &b]);
    let mut header = a.header();
    header.as_object_mut().expect("object").remove("kid");
    let token = a.token(&header, &id_claims());
    assert_eq!(
        jose::verify(&token, &keys, &ALL, Kind::IdToken).unwrap_err(),
        Failure::Ambiguous
    );
    // With a kid, the matching key alone is used.
    let token = a.token(&a.header(), &id_claims());
    assert!(jose::verify(&token, &keys, &ALL, Kind::IdToken).is_ok());
}

#[test]
fn api_004_a_new_kid_is_rejected_before_the_refetch_and_accepted_after_it() {
    let old = Signer::rsa("k1", Alg::Rs256);
    let new = Signer::generated("k2", Alg::Es256);
    let before = keys_of(&[&old]);
    let token = new.token(&new.header(), &id_claims());
    let refused = jose::verify(&token, &before, &ALL, Kind::IdToken).unwrap_err();
    assert_eq!(refused, Failure::NoKey);
    assert!(refused.may_be_rotation(), "so the key set is refetched");
    let after = keys_of(&[&old, &new]);
    assert!(jose::verify(&token, &after, &ALL, Kind::IdToken).is_ok());
}

#[test]
fn api_004_the_provider_allow_list_refuses_other_algorithms() {
    // Discovery listed only RS256; an ES256 token with a published ES256 key is refused.
    let rsa = Signer::rsa("k1", Alg::Rs256);
    let ec = Signer::generated("k2", Alg::Es256);
    let keys = keys_of(&[&rsa, &ec]);
    let token = ec.token(&ec.header(), &id_claims());
    assert_eq!(
        jose::verify(&token, &keys, &[Alg::Rs256], Kind::IdToken).unwrap_err(),
        Failure::Algorithm
    );
}

#[test]
fn api_004_id_token_claims_are_checked_with_strict_types() {
    assert!(check_id(&id_claims()).is_ok(), "a valid claim set");
    let with = |name: &str, value: Value| {
        let mut c = id_claims();
        c[name] = value;
        c
    };
    // Each of these is refused, not skipped.
    assert!(
        check_id(&with("iss", json!(42))).is_err(),
        "iss as a number"
    );
    assert!(
        check_id(&with("iss", json!("https://other.test"))).is_err(),
        "wrong iss"
    );
    assert!(
        check_id(&with("exp", json!("9999999999"))).is_err(),
        "exp as a string"
    );
    assert!(
        check_id(&with("nbf", json!("9999999999"))).is_err(),
        "nbf as a string"
    );
    assert!(
        check_id(&with("nonce", json!("other"))).is_err(),
        "nonce mismatch"
    );
    assert!(
        check_id(&with("aud", json!(["telltale", "other-app"]))).is_err(),
        "extra audience"
    );
    assert!(
        check_id(&with("aud", json!("other-app"))).is_err(),
        "audience without client_id"
    );
    assert!(check_id(&with("aud", json!([]))).is_err(), "empty audience");
    assert!(
        check_id(&with("aud", json!(["telltale", "telltale"]))).is_err_and(|e| e.contains("azp")),
        "two audiences need azp"
    );
    assert!(
        check_id(&with("azp", json!("other-app"))).is_err(),
        "azp not this client"
    );
    let mut no_iat = id_claims();
    no_iat.as_object_mut().expect("object").remove("iat");
    assert!(check_id(&no_iat).is_err(), "missing iat");
    assert!(
        check_id(&with("iat", json!(now() + 3600))).is_err(),
        "iat far ahead"
    );
    assert!(
        check_id(&with("nbf", json!(now() + 3600))).is_err(),
        "nbf far ahead"
    );
    assert!(check_id(&with("exp", json!(now() - 1))).is_err(), "expired");
    assert!(
        check_id(&with("exp", json!(1.5))).is_err(),
        "a fractional date"
    );
    assert!(check_id(&with("sub", json!(""))).is_err(), "empty subject");
}

#[test]
fn api_004_id_token_expiry_has_no_leeway_and_iat_and_nbf_allow_sixty_seconds() {
    let t = 1_000_000u64;
    let mut c = id_claims();
    c["exp"] = json!(t);
    c["iat"] = json!(t - 10);
    assert!(check_id_at(&c, t - 1).is_ok(), "one second before exp");
    assert!(check_id_at(&c, t).is_err(), "exp is not in the future");
    c["exp"] = json!(t + 300);
    c["iat"] = json!(t + 60);
    assert!(check_id_at(&c, t).is_ok(), "iat 60 s ahead is tolerated");
    c["iat"] = json!(t + 61);
    assert!(check_id_at(&c, t).is_err(), "iat 61 s ahead is not");
}

#[test]
fn api_004_access_token_claims_keep_their_checks() {
    let t = 1_000_000u64;
    let ok = json!({"iss": ISS, "aud": "https://dns.test/mcp", "exp": t + 10});
    assert!(claims::access_token(&ok, ISS, "https://dns.test/mcp", t).is_ok());
    let other =
        json!({"iss": ISS, "aud": ["https://x.test", "https://dns.test/mcp"], "exp": t + 10});
    assert!(
        claims::access_token(&other, ISS, "https://dns.test/mcp", t).is_ok(),
        "array"
    );
    let wrong = json!({"iss": ISS, "aud": "https://x.test", "exp": t + 10});
    assert!(claims::access_token(&wrong, ISS, "https://dns.test/mcp", t).is_err());
    let stale = json!({"iss": ISS, "aud": "https://dns.test/mcp", "exp": t - 61});
    assert!(claims::access_token(&stale, ISS, "https://dns.test/mcp", t).is_err());
    let stringy = json!({"iss": ISS, "aud": "https://dns.test/mcp", "exp": "9999999999"});
    assert!(claims::access_token(&stringy, ISS, "https://dns.test/mcp", t).is_err());
}

#[test]
fn api_004_discovery_must_name_the_configured_issuer_and_https_endpoints() {
    let doc = |issuer: &str, token: &str| {
        json!({
            "issuer": issuer,
            "authorization_endpoint": "https://idp.test/authorize",
            "token_endpoint": token,
            "jwks_uri": "https://idp.test/jwks",
            "end_session_endpoint": "http://idp.test/logout",
        })
    };
    let good = metadata::parse(&doc(ISS, "https://idp.test/token"), ISS).expect("valid");
    assert!(
        good.end_session_endpoint.is_none(),
        "an http logout URL is dropped over HTTPS"
    );
    assert!(metadata::parse(&doc("https://other.test", "https://idp.test/token"), ISS).is_err());
    assert!(
        metadata::parse(&doc(ISS, "http://idp.test/token"), ISS).is_err(),
        "an HTTPS issuer can't have an HTTP token endpoint"
    );
    // A plain-HTTP issuer (a local test provider) may use HTTP endpoints.
    let local = "http://localhost:8080";
    let plain = json!({
        "issuer": local,
        "authorization_endpoint": "http://localhost:8080/authorize",
        "token_endpoint": "http://localhost:8080/token",
        "jwks_uri": "http://localhost:8080/jwks",
        "end_session_endpoint": "http://localhost:8080/logout",
    });
    let plain = metadata::parse(&plain, local).expect("HTTP issuer");
    assert_eq!(
        plain.end_session_endpoint.as_deref(),
        Some("http://localhost:8080/logout")
    );
    assert!(
        metadata::parse(&json!({"issuer": ISS, "token_endpoint": 1}), ISS).is_err(),
        "a mistyped endpoint is refused"
    );
    assert!(
        metadata::parse(
            &json!({"issuer": ISS, "authorization_endpoint": "https://idp.test/a", "token_endpoint": "https://idp.test/t", "jwks_uri": "https://idp.test/j", "id_token_signing_alg_values_supported": "RS256"}),
            ISS
        )
        .is_err(),
        "an algorithm list that isn't a list is refused"
    );
}

/// The base64url decoding the tests need (no padding), without the server's helpers.
fn base64_url_decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .expect("base64url")
}

fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// REQ: API-004 — a provider response over 1 MiB (the key set, the discovery document) is refused.
#[tokio::test]
async fn api_004_an_oversized_provider_response_is_refused() {
    let big: super::Fetch = std::sync::Arc::new(|_req| {
        Box::pin(async { Ok(axum::http::Response::new(vec![0u8; (1 << 20) + 1])) })
    });
    let req = axum::http::Request::get("https://idp.test/jwks")
        .body(Vec::new())
        .expect("request");
    let err = super::send(&big, req).await.expect_err("refused");
    assert!(err.contains("too large"), "{err}");
}

#[test]
fn api_004_padding_and_key_ops_are_refused() {
    let signer = Signer::rsa("k1", Alg::Rs256);
    let keys = keys_of(&[&signer]);
    let token = signer.token(&signer.header(), &id_claims());
    assert!(jose::verify(&token, &keys, &ALL, Kind::IdToken).is_ok());
    let padded = format!("{token}==");
    assert!(
        jose::verify(&padded, &keys, &ALL, Kind::IdToken).is_err(),
        "a padded signature"
    );
    let mut jwk = signer.jwk();
    jwk["key_ops"] = json!(["encrypt"]);
    assert!(Key::from_jwk(&jwk).is_none(), "key_ops without verify");
    jwk["key_ops"] = json!(["verify"]);
    assert!(Key::from_jwk(&jwk).is_some());
}

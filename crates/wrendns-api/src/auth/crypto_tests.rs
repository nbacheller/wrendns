// REQ: moved out of `crypto.rs` so the test code is a file of its own (CodeQL ignores test paths).
use super::*;

#[test]
fn api_003_password_hashes_verify_and_use_spec_parameters() {
    let h = hash_password("correct horse battery").unwrap();
    assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{h}");
    assert!(verify_password("correct horse battery", &h));
    assert!(!verify_password("correct horse batterY", &h));
    assert!(!verify_password("x", "not a hash"));
    assert_ne!(
        hash_password("same").unwrap(),
        hash_password("same").unwrap(),
        "salted"
    );
}

#[test]
fn api_003_secrets_and_encodings() {
    assert_eq!(random_secret().len(), 43);
    assert_eq!(random_id().len(), 16);
    assert!(ct_eq(&secret_hash("a"), &secret_hash("a")));
    assert!(!ct_eq(&secret_hash("a"), &secret_hash("b")));
    // RFC 4648 test vectors.
    assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    assert_eq!(base32(b"f"), "MY");
    let url = otpauth_url("WrenDNS", "ana maria", b"12345678901234567890");
    assert_eq!(
        url,
        "otpauth://totp/WrenDNS:ana%20maria?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=WrenDNS&algorithm=SHA1&digits=6&period=30"
    );
}

#[test]
fn api_003_totp_matches_rfc6238_and_allows_one_step_of_skew() {
    // RFC 6238 appendix B, SHA-1, 8 digits: 94287082 at T=59 → the 6-digit code is 287082.
    let secret = b"12345678901234567890";
    assert_eq!(totp_step(secret, "287082", 59), Some(1));
    assert_eq!(totp_step(secret, "287082", 89), Some(1), "one step late");
    assert_eq!(totp_step(secret, "287082", 200), None, "too late");
    assert_eq!(totp_step(secret, "28708", 59), None);
    assert_eq!(totp_step(secret, "abcdef", 59), None);
}

#[test]
fn api_003_recovery_codes_are_single_format_and_normalized() {
    let (codes, hashes) = recovery_codes();
    assert_eq!((codes.len(), hashes.len()), (10, 10));
    assert!(
        codes
            .iter()
            .all(|c| c.len() == 11 && c.as_bytes()[5] == b'-')
    );
    let typed = codes[0].to_ascii_uppercase().replace('-', " ");
    assert_eq!(recovery_hash(&typed), hashes[0]);
}

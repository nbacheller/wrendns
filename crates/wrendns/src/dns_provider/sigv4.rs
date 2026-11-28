// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b4; ADR-1084 point 6) - AWS Signature Version 4, hand-rolled on `ring`
//! (SHA-256 and HMAC-SHA256): no AWS SDK and no new crate. Checked against AWS's published `SigV4`
//! test-suite vectors in `route53_tests.rs`.
//!
//! The signer takes the pieces of one request and returns the `Authorization` header value. It
//! signs the `host` and `x-amz-date` headers plus any the caller adds, the way the test suite does.
//! The secret is only ever an input: it is not stored, printed or returned.

use ring::{digest, hmac};

/// What [`sign`] needs besides the request: who signs, for which region and service, and when.
pub(crate) struct Scope<'a> {
    pub(crate) access_key: &'a str,
    pub(crate) secret: &'a str,
    pub(crate) region: &'a str,
    pub(crate) service: &'a str,
    /// `YYYYMMDDTHHMMSSZ`.
    pub(crate) amz_date: &'a str,
}

/// The pieces of a request that are signed.
pub(crate) struct Request<'a> {
    pub(crate) method: &'a str,
    /// The authority as sent in `Host` (`route53.amazonaws.com`, or `host:port`).
    pub(crate) host: &'a str,
    /// The path, not encoded (`/2013-04-01/hostedzone/Z1/rrset`).
    pub(crate) path: &'a str,
    /// Query parameters, not encoded, in any order.
    pub(crate) query: &'a [(&'a str, &'a str)],
    /// Headers besides `host` and `x-amz-date` that are signed, as `(name, value)`.
    pub(crate) headers: &'a [(&'a str, &'a str)],
    pub(crate) body: &'a [u8],
}

/// The result: the header value, and the parts the caller sends.
pub(crate) struct Signed {
    pub(crate) authorization: String,
    /// The signature alone, so an error can be scrubbed of it.
    pub(crate) signature: String,
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn sha256_hex(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, data).as_ref())
}

fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
        .as_ref()
        .to_vec()
}

/// RFC 3986 percent-encoding as `SigV4` wants it: letters, digits and `-_.~` stay, the rest is
/// `%XX` in upper case.
pub(crate) fn uri_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The path as it goes on the request line: each segment encoded once.
pub(crate) fn encode_path(path: &str) -> String {
    if path.is_empty() {
        return "/".into();
    }
    path.split('/')
        .map(uri_encode)
        .collect::<Vec<_>>()
        .join("/")
}

/// The query string as it goes on the request line and into the signature: names and values
/// encoded, sorted by name and then value.
pub(crate) fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k), uri_encode(v)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The signing key for a date, region and service (`SigV4` step 3).
pub(crate) fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k = mac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k = mac(&k, region.as_bytes());
    let k = mac(&k, service.as_bytes());
    mac(&k, b"aws4_request")
}

/// The canonical request (`SigV4` step 1) and the signed-header list.
fn canonical_request(req: &Request<'_>, amz_date: &str) -> (String, String) {
    use std::fmt::Write as _;
    let mut headers: Vec<(String, String)> = vec![
        ("host".into(), req.host.trim().to_owned()),
        ("x-amz-date".into(), amz_date.to_owned()),
    ];
    for (k, v) in req.headers {
        let v = v.split_whitespace().collect::<Vec<_>>().join(" ");
        headers.push((k.to_ascii_lowercase(), v));
    }
    headers.sort();
    let mut canonical_headers = String::new();
    for (k, v) in &headers {
        let _ = writeln!(canonical_headers, "{k}:{v}");
    }
    let signed = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    // Services other than S3 encode each path segment twice.
    let path = if req.path.is_empty() {
        "/".to_owned()
    } else {
        req.path
            .split('/')
            .map(|s| uri_encode(&uri_encode(s)))
            .collect::<Vec<_>>()
            .join("/")
    };
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method,
        path,
        canonical_query(req.query),
        canonical_headers,
        signed,
        sha256_hex(req.body),
    );
    (canonical, signed)
}

/// The string to sign (`SigV4` step 2) for a canonical request.
fn string_to_sign(canonical: &str, s: &Scope<'_>) -> String {
    let date = s.amz_date.get(..8).unwrap_or(s.amz_date);
    format!(
        "AWS4-HMAC-SHA256\n{}\n{}/{}/{}/aws4_request\n{}",
        s.amz_date,
        date,
        s.region,
        s.service,
        sha256_hex(canonical.as_bytes())
    )
}

/// Signs `req`: the `Authorization` header value to send with the `x-amz-date` header.
pub(crate) fn sign(req: &Request<'_>, s: &Scope<'_>) -> Signed {
    let (canonical, signed_headers) = canonical_request(req, s.amz_date);
    let sts = string_to_sign(&canonical, s);
    let date = s.amz_date.get(..8).unwrap_or(s.amz_date);
    let key = signing_key(s.secret, date, s.region, s.service);
    let signature = hex(&mac(&key, sts.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}/{}/{}/aws4_request, SignedHeaders={}, Signature={}",
        s.access_key, date, s.region, s.service, signed_headers, signature
    );
    Signed {
        authorization,
        signature,
    }
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time in seconds.
pub(crate) fn amz_date(unix: u64) -> String {
    let days = i64::try_from(unix / 86_400).unwrap_or(0);
    let rem = unix % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

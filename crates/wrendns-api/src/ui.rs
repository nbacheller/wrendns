//! The embedded web UI (REQ: API-005, ADR-009, ADR-030): `ui/dist` compiled into the binary,
//! served at `/` on the API listener with a strict CSP (`spec/08` §6: no inline scripts,
//! `X-Frame-Options: DENY`). Hashed assets are cached forever; `index.html` never is.
//! `npm run build` replaces each text file with its `.gz` (REQ: NFR-001, ADR-168: the binary
//! embeds what `ui/dist` holds, so keeping both copies cost about the file's gzip size again in
//! the image). A browser that accepts gzip gets the stored file as it is; any other client gets
//! it inflated. A build without `ui/dist` still compiles and serves a short page saying so.

use std::borrow::Cow;

use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::Embed)]
#[folder = "../../ui/dist"]
#[allow_missing = true]
struct Assets;

/// The help glossary (REQ: API-011, ADR-036, ADR-1020 amendment): the one file the UI fetches when
/// a "?" first needs it. It is embedded from `docs/help/topics.json`, outside `ui/dist`, so the
/// UI's size budget (which counts every file in `ui/dist`) does not carry it. It is served like
/// the UI's own files, with no sign-in (the sign-in page has help buttons too).
static GLOSSARY: &[u8] = include_bytes!("../../../docs/help/topics.json");
const GLOSSARY_PATH: &str = "help/topics.json";

/// Content Security Policy for every UI response. Styles are only stylesheets: the UI sets
/// dynamic styles through the CSSOM, which CSP allows, never through `style` attributes.
pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
    font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; \
    frame-ancestors 'none'";

const MISSING: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>WrenDNS</title></head>\
    <body><h1>WrenDNS</h1><p>This build has no web UI. Build it with <code>npm --prefix ui ci &amp;&amp; \
    npm --prefix ui run build</code>, then rebuild the binary. The API is at \
    <a href=\"/api/v1/openapi.json\">/api/v1/openapi.json</a>.</p></body></html>";

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map_or("", |(_, ext)| ext) {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "json" | "map" => "application/json",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn security_headers(h: &mut HeaderMap) {
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

/// The most one embedded UI file may inflate to (the biggest is under 1 MB): a damaged stream
/// can't grow past it.
const MAX_INFLATED: usize = 8 << 20;

/// What a `.gz` file written by `ui/scripts/postbuild.mjs` holds: a 10-byte header with no
/// optional fields, a deflate stream, then CRC-32 and the length. The CRC isn't checked (the
/// file is part of this binary), the length is. `None` for anything else, so a damaged file is
/// refused and never served half-read.
fn gunzip(gz: &[u8]) -> Option<Vec<u8>> {
    let (head, rest) = gz.split_at_checked(10)?;
    // ID, deflate, and no flags: no extra field, name, comment, or header checksum to skip.
    if !head.starts_with(&[0x1f, 0x8b, 8, 0]) {
        return None;
    }
    let (stream, tail) = rest.split_at_checked(rest.len().checked_sub(8)?)?;
    let size = u32::from_le_bytes(tail.get(4..8)?.try_into().ok()?);
    let out = miniz_oxide::inflate::decompress_to_vec_with_limit(stream, MAX_INFLATED).ok()?;
    (out.len() == usize::try_from(size).ok()?).then_some(out)
}

fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|e| {
            let mut parts = e.trim().split(';');
            let name = parts.next().map(str::trim).unwrap_or_default();
            // RFC 9110 §12.5.3: names are case-insensitive, and any q of zero ("0", "0.0", "0.000")
            // refuses the coding.
            name.eq_ignore_ascii_case("gzip")
                && !parts.any(|p| {
                    let p = p.trim();
                    p.get(..2).is_some_and(|k| k.eq_ignore_ascii_case("q="))
                        && p.get(2..)
                            .and_then(|q| q.trim().parse::<f32>().ok())
                            .is_some_and(|q| q <= 0.0)
                })
        })
}

#[cfg(test)]
mod accept_tests {
    use super::accepts_gzip;
    use axum::http::{HeaderMap, HeaderValue, header};

    fn with(v: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, HeaderValue::from_static(v));
        h
    }

    // REQ: NFR-001 (ADR-915) — a zero q in any spelling refuses gzip; names ignore case.
    #[test]
    fn nfr_001_gzip_q_zero_in_any_form_refuses() {
        for v in [
            "gzip;q=0",
            "gzip;q=0.0",
            "gzip; q=0.000",
            "GZIP;Q=0",
            "br, gzip;q=0.00",
        ] {
            assert!(!accepts_gzip(&with(v)), "{v}");
        }
        for v in ["gzip", "GZip", "gzip;q=0.5", "br, gzip", "gzip; q=1"] {
            assert!(accepts_gzip(&with(v)), "{v}");
        }
        assert!(!accepts_gzip(&HeaderMap::new()));
    }
}

/// Serves a UI file (`/` is `index.html`); anything else is 404.
pub fn serve(method: &Method, uri: &Uri, headers: &HeaderMap) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = match uri.path().trim_start_matches('/') {
        "" | "index.html" => "index.html",
        p => p,
    };
    if path
        .split('/')
        .any(|seg| seg.is_empty() || seg == ".." || seg == ".")
        || std::path::Path::new(path)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("gz"))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (body, encoded): (Cow<'static, [u8]>, bool) = match Assets::get(&format!("{path}.gz")) {
        _ if path == GLOSSARY_PATH => (Cow::Borrowed(GLOSSARY), false),
        // A client that accepts gzip gets the stored file; any other gets it inflated.
        Some(f) if accepts_gzip(headers) => (f.data, true),
        Some(f) => match gunzip(&f.data) {
            Some(plain) => (Cow::Owned(plain), false),
            None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        // Files with no `.gz` (images, fonts, and the small ones gzip doesn't shrink) are
        // stored as they are.
        None => match Assets::get(path) {
            Some(f) => (f.data, false),
            None if path == "index.html" => (Cow::Borrowed(MISSING.as_bytes()), false),
            None => return StatusCode::NOT_FOUND.into_response(),
        },
    };
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(path)),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if path.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else if path == GLOSSARY_PATH {
            "public, max-age=3600"
        } else {
            "no-cache"
        }),
    );
    h.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    if encoded {
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    security_headers(h);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_005_gzip_negotiation_and_types() {
        let mut h = HeaderMap::new();
        assert!(!accepts_gzip(&h));
        h.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("br, gzip;q=0.8"),
        );
        assert!(accepts_gzip(&h));
        h.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip;q=0, br"),
        );
        assert!(!accepts_gzip(&h));
        assert_eq!(
            content_type("assets/index-1.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(content_type("favicon.svg"), "image/svg+xml");
    }

    // REQ: API-011 (ADR-1020 amendment) — the glossary is served outside the UI bundle, with the UI's
    // security headers, as JSON that holds every topic, to a client with or without gzip.
    #[test]
    fn api_011_glossary_is_served_from_the_binary() {
        let uri: Uri = "/help/topics.json".parse().unwrap();
        for method in [Method::GET, Method::HEAD] {
            let resp = serve(&method, &uri, &HeaderMap::new());
            assert_eq!(resp.status(), StatusCode::OK);
            let h = resp.headers();
            assert_eq!(h[header::CONTENT_TYPE], "application/json");
            assert!(h.get(header::CONTENT_ENCODING).is_none());
            assert!(h.contains_key(header::CONTENT_SECURITY_POLICY));
            assert!(
                h[header::CACHE_CONTROL]
                    .to_str()
                    .unwrap()
                    .contains("max-age=")
            );
        }
        let v: serde_json::Value = serde_json::from_slice(GLOSSARY).unwrap();
        let topics = v["topics"].as_array().unwrap();
        assert!(topics.len() > 100);
        assert!(
            topics
                .iter()
                .all(|t| t["id"].is_string() && t["title"].is_string())
        );
    }

    // REQ: NFR-001 (ADR-168) — a UI file is stored gzipped and inflated for a client that
    // doesn't accept gzip.
    #[test]
    fn nfr_001_gunzip_reads_what_postbuild_writes() {
        let plain = b"<!doctype html><title>WrenDNS</title>".repeat(40);
        let stream = miniz_oxide::deflate::compress_to_vec(&plain, 6);
        let len = u32::try_from(plain.len()).unwrap();
        // Node's gzip: ID, deflate, no flags, no time, extra flags, OS; then the stream, CRC-32, length.
        let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 3];
        gz.extend_from_slice(&stream);
        gz.extend_from_slice(&0u32.to_le_bytes());
        gz.extend_from_slice(&len.to_le_bytes());
        assert_eq!(gunzip(&gz).as_deref(), Some(plain.as_slice()));

        // Anything damaged or unexpected is refused, never served half-read.
        assert!(gunzip(b"").is_none());
        assert!(gunzip(&gz[..gz.len() - 9]).is_none(), "cut short");
        let mut not_deflate = gz.clone();
        not_deflate[2] = 9;
        assert!(gunzip(&not_deflate).is_none());
        let mut flagged = gz.clone();
        flagged[3] = 8; // a file name follows the header: not what postbuild writes
        assert!(gunzip(&flagged).is_none());
        let mut wrong_length = gz.clone();
        let n = wrong_length.len();
        wrong_length[n - 4] ^= 1;
        assert!(gunzip(&wrong_length).is_none());
    }
}

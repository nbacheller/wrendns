//! The embedded web UI (REQ: API-005, ADR-009, ADR-030): `ui/dist` compiled into the binary,
//! served at `/` on the API listener with a strict CSP (`spec/08` §6: no inline scripts,
//! `X-Frame-Options: DENY`). Hashed assets are cached forever; `index.html` never is.
//! `npm run build` writes a `.gz` for each text file that gzip shrinks and removes the raw copy
//! (REQ: NFR-001, ADR-915). The gzip goes to browsers that accept it; any other client gets the
//! same bytes inflated on the request. Binary files are embedded as they are. A build without
//! `ui/dist` still compiles and serves a short page saying so.

use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::Embed)]
#[folder = "../../ui/dist"]
#[allow_missing = true]
struct Assets;

/// Content Security Policy for every UI response. Styles are only stylesheets: the UI sets
/// dynamic styles through the CSSOM, which CSP allows, never through `style` attributes.
pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
    font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; \
    frame-ancestors 'none'";

const MISSING: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>TelltaleDNS</title></head>\
    <body><h1>TelltaleDNS</h1><p>This build has no web UI. Build it with <code>npm --prefix ui ci &amp;&amp; \
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

fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|e| {
            let mut parts = e.trim().split(';');
            parts.next() == Some("gzip") && !parts.any(|q| q.trim().replace(' ', "") == "q=0")
        })
}

/// Inflates a gzip member written by `ui/scripts/postbuild.mjs` (RFC 1952, no optional header
/// fields: FLG is 0). `None` for anything else.
fn gunzip(data: &[u8]) -> Option<Vec<u8>> {
    const HEADER: usize = 10;
    const TRAILER: usize = 8;
    if data.len() < HEADER + TRAILER || data[..3] != [0x1f, 0x8b, 8] || data[3] != 0 {
        return None;
    }
    miniz_oxide::inflate::decompress_to_vec(&data[HEADER..data.len() - TRAILER]).ok()
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
    let gz = Assets::get(&format!("{path}.gz"));
    let (body, encoded): (Vec<u8>, bool) = match (accepts_gzip(headers), gz, Assets::get(path)) {
        (true, Some(f), _) => (f.data.into_owned(), true),
        (_, _, Some(f)) => (f.data.into_owned(), false),
        (false, Some(f), None) => match gunzip(&f.data) {
            Some(plain) => (plain, false),
            None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        (_, _, None) if path == "index.html" => (MISSING.as_bytes().to_vec(), false),
        _ => return StatusCode::NOT_FOUND.into_response(),
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

    // REQ: NFR-001 (ADR-915) — `gzip.compress(b'hello, telltale\n', mtime=0)`, the form postbuild writes.
    #[test]
    fn ui_001_gunzip_inflates_the_postbuild_gzip() {
        let gz = [
            0x1f, 0x8b, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xff, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
            0xd7, 0x51, 0x28, 0x1, 0x52, 0x25, 0x89, 0x39, 0xa9, 0x5c, 0x0, 0x8a, 0x75, 0x12, 0x4c,
            0x10, 0x0, 0x0, 0x0,
        ];
        assert_eq!(gunzip(&gz).as_deref(), Some(&b"hello, telltale\n"[..]));
        assert_eq!(gunzip(b"not gzip at all, but long enough"), None);
        assert_eq!(gunzip(&gz[..12]), None);
    }
}

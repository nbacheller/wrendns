// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-003 (T24.44, ADR-1053) — the plain-HTTP redirect listener (`[api] http_redirect`).
//!
//! With the web UI and API on HTTPS (usually 443), `http://host/` on port 80 should reach the UI.
//! This listener answers every request with a `308` to `https://<the request's Host without its
//! port>[:<the API's port when it isn't 443>]<path and query>`, and the three health probes as the
//! API port does. It serves nothing else, and every response carries `Cache-Control: no-store`.
//!
//! The `Host` header is attacker-controlled, so it is validated before it is echoed into a
//! `Location`: a hostname, an IPv4 address or a bracketed IPv6 address, with an optional port, and
//! nothing else (no userinfo, no control characters, no path). Anything else is a 400, so the
//! redirect can't be turned into an open redirect to another site.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use axum::Router as HttpRouter;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::http::Sources;

/// The HTTPS port browsers assume, so the redirect leaves it out.
const HTTPS_DEFAULT: u16 = 443;

/// The host part of a `Host` header, validated and without its port: a hostname or IPv4 address as
/// is, an IPv6 address with its brackets. `None` for anything else.
pub(crate) fn host_only(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > 261 {
        return None;
    }
    let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        // An IPv6 literal, without a zone, and nothing but an optional `:port` after it.
        inner.parse::<Ipv6Addr>().ok()?;
        let port = match after {
            "" => None,
            a => Some(a.strip_prefix(':')?),
        };
        (format!("[{inner}]"), port)
    } else {
        let (name, port) = match raw.split_once(':') {
            Some((n, p)) => (n, Some(p)),
            None => (raw, None),
        };
        if !hostname_ok(name) {
            return None;
        }
        (name.to_owned(), port)
    };
    if let Some(p) = port
        && (p.is_empty()
            || p.len() > 5
            || !p.bytes().all(|b| b.is_ascii_digit())
            || p.parse::<u16>().is_err())
    {
        return None;
    }
    Some(host)
}

/// A DNS name (letters, digits, hyphens and dots, labels of 1 to 63 that don't start or end with a
/// hyphen, 253 in all) or a dotted-quad IPv4 address. A name that looks numeric but isn't an IPv4
/// address (`1.2.3`, `0x7f.1`) is refused: browsers read those as addresses in surprising ways.
fn hostname_ok(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    if name.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.iter().any(|l| {
        l.is_empty()
            || l.len() > 63
            || l.starts_with('-')
            || l.ends_with('-')
            || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return false;
    }
    // The last label of a real name has a letter in it (a numeric one would be an address).
    labels
        .last()
        .is_some_and(|l| l.bytes().any(|b| b.is_ascii_alphabetic()))
}

/// The `https://` address a request for `path_and_query` on `host_header` is sent to, with the API's
/// port (left out when it is 443). `None` when the `Host` header isn't acceptable.
pub(crate) fn target(host_header: &str, api_port: u16, path_and_query: &str) -> Option<String> {
    let host = host_only(host_header)?;
    let port = if api_port == HTTPS_DEFAULT {
        String::new()
    } else {
        format!(":{api_port}")
    };
    let path = if path_and_query.starts_with('/') {
        path_and_query
    } else {
        "/"
    };
    Some(format!("https://{host}{port}{path}"))
}

/// What the router needs: the API's HTTPS port.
#[derive(Clone, Copy)]
struct Redirect {
    api_port: u16,
}

/// The redirect listener's app: the health probes as the API serves them, a 308 for everything
/// else. Limited to `[access] allowed_networks` like the API.
pub(crate) fn router(src: &Arc<Sources>, api: SocketAddr) -> HttpRouter {
    let state = Redirect {
        api_port: api.port(),
    };
    HttpRouter::new()
        .route("/livez", get(|| async { "ok\n" }))
        .route("/healthz", get(|| async { "ok\n" }))
        .route(
            "/readyz",
            get(crate::http::readyz).with_state(Arc::clone(src)),
        )
        .fallback(redirect)
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(src),
            crate::http::only_allowed,
        ))
        .layer(axum::middleware::map_response(no_store))
}

async fn no_store(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

async fn redirect(State(st): State<Redirect>, req: Request) -> Response {
    let mut hosts = req.headers().get_all(header::HOST).iter();
    let (Some(host), None) = (hosts.next(), hosts.next()) else {
        return bad();
    };
    let Ok(host) = host.to_str() else {
        return bad();
    };
    let pq = req.uri().path_and_query().map_or("/", |p| p.as_str());
    let Some(to) = target(host, st.api_port, pq) else {
        return bad();
    };
    match HeaderValue::from_str(&to) {
        Ok(v) => (
            StatusCode::PERMANENT_REDIRECT,
            [(header::LOCATION, v)],
            "use https://\n",
        )
            .into_response(),
        Err(_) => bad(),
    }
}

fn bad() -> Response {
    (StatusCode::BAD_REQUEST, "bad request\n").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: API-003 (T24.44) — what a Host header may be: a name, an IPv4 or bracketed IPv6 address,
    // with or without a port; the port is dropped.
    #[test]
    fn api_003_redirect_host_accepts_names_and_addresses() {
        for (raw, want) in [
            ("dns.example.com", "dns.example.com"),
            ("dns.example.com:80", "dns.example.com"),
            ("dns", "dns"),
            ("a-b.example", "a-b.example"),
            ("192.0.2.10", "192.0.2.10"),
            ("192.0.2.10:8080", "192.0.2.10"),
            ("[2001:db8::1]", "[2001:db8::1]"),
            ("[2001:db8::1]:80", "[2001:db8::1]"),
            ("[::1]:65535", "[::1]"),
        ] {
            assert_eq!(host_only(raw).as_deref(), Some(want), "{raw}");
        }
    }

    // REQ: API-003 (T24.44) — nothing that could send the browser to another site or split the
    // header: userinfo, a path, CRLF, spaces, a bad port, an IPv6 zone, an empty or numeric name.
    #[test]
    fn api_003_redirect_host_refuses_anything_else() {
        for raw in [
            "",
            "evil.example@good.example",
            "user:pw@good.example",
            "good.example/evil",
            "good.example\r\nSet-Cookie: x=1",
            "good.example\nx",
            "good.example ",
            "good.example.",
            "good .example",
            "good.example:",
            "good.example:80a",
            "good.example:65536",
            "good.example:80:80",
            "-bad.example",
            "bad-.example",
            "bad..example",
            ".example",
            "bad_name.example",
            "1.2.3",
            "0x7f.1",
            "[2001:db8::1%25eth0]",
            "[2001:db8::1]x",
            "[2001:db8::1",
            "[evil]",
            "2001:db8::1",
            "good.example\\evil",
            "good.example?x",
            "good.example#x",
            "g\u{f6}\u{f6}d.example",
        ] {
            assert_eq!(host_only(raw), None, "{raw:?}");
        }
        assert_eq!(host_only(&"a".repeat(300)), None);
        assert_eq!(host_only(&format!("{}.example", "a".repeat(64))), None);
    }

    // REQ: API-003 (T24.44) — the target keeps the path and query, drops the request's port, and
    // adds the API's port only when it isn't 443.
    #[test]
    fn api_003_redirect_target_has_the_api_port_unless_443() {
        assert_eq!(
            target("dns.example.com", 443, "/ui/settings?tab=system").as_deref(),
            Some("https://dns.example.com/ui/settings?tab=system")
        );
        assert_eq!(
            target("dns.example.com:80", 443, "/").as_deref(),
            Some("https://dns.example.com/")
        );
        assert_eq!(
            target("dns.example.com:80", 8053, "/a").as_deref(),
            Some("https://dns.example.com:8053/a")
        );
        assert_eq!(
            target("[2001:db8::1]:80", 8443, "/").as_deref(),
            Some("https://[2001:db8::1]:8443/")
        );
        assert_eq!(
            target("[2001:db8::1]", 443, "/x").as_deref(),
            Some("https://[2001:db8::1]/x")
        );
        // A path that isn't origin-form can't make the host part longer.
        assert_eq!(
            target("dns.example.com", 443, "@evil.example/").as_deref(),
            Some("https://dns.example.com/")
        );
        assert_eq!(
            target("dns.example.com", 443, "//evil.example/x").as_deref(),
            Some("https://dns.example.com//evil.example/x")
        );
        assert_eq!(target("evil@dns.example.com", 443, "/"), None);
    }
}

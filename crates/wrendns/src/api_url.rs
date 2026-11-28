// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-902 (T27.14g0, ADR-1113) - the URL a cluster member announces for its web UI and API, so a
//! card on one node can link to another node's own address (for the confirm of a guarded change,
//! which must reach the node itself).
//!
//! The scheme follows `[api] tls`, the port is `[api] listen`'s, and the host is the address the API
//! is bound to when that is a specific one, else the host of the first cluster `advertise` URL (the
//! address the other members already reach this node on). A node that has neither (bound to a
//! wildcard or loopback with no advertise address) announces nothing: a card then says the node's
//! address is unknown instead of guessing one.

use std::net::{IpAddr, SocketAddr};

use wrendns_config::Config;

/// The announced URL, or an empty string when the node cannot name one.
pub(crate) fn announced(cfg: &Config, advertise: &[String]) -> String {
    // REQ: API-902, API-901 (T27.14g, ADR-1116) - `[api] public_url` says it outright: a node behind NAT or
    // a load balancer's name. It was checked when the configuration loaded; checked again here, so a value
    // that slipped through some other way is never announced.
    if let Some(u) = &cfg.api.public_url
        && wrendns_config::check_public_url(u.as_str()).is_ok()
    {
        return u.as_str().trim_end_matches('/').to_owned();
    }
    let listen: SocketAddr = cfg.api.listen;
    let host = if usable(listen.ip()) {
        Some(bracket(listen.ip()))
    } else {
        advertise.iter().find_map(|a| host_of(a))
    };
    let scheme = if cfg.api.tls.is_some() {
        "https"
    } else {
        "http"
    };
    host.map(|h| format!("{scheme}://{h}:{}", listen.port()))
        .unwrap_or_default()
}

/// A bound address another machine could use.
fn usable(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback()
}

fn bracket(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => format!("[{v}]"),
    }
}

/// The host of an advertise URL (`https://192.0.2.7:8443`, `https://[2001:db8::7]:8443`, a name),
/// kept in the form a URL carries it; none when it is empty or loopback.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if let Some(v6) = authority.strip_prefix('[') {
        let end = v6.find(']')?;
        let ip: IpAddr = v6[..end].parse().ok()?;
        return usable(ip).then(|| bracket(ip));
    }
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    if host.is_empty() || host.eq_ignore_ascii_case("localhost") {
        return None;
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => usable(ip).then(|| bracket(ip)),
        Err(_) => Some(host.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(listen: &str, tls: bool) -> Config {
        let mut c = Config::default();
        c.api.listen = listen.parse().unwrap();
        if tls {
            c.api.tls = Some(wrendns_config::ApiTls::default());
        }
        c
    }

    // REQ: API-902 (T27.14g0) - the scheme follows TLS, the port is the API's, the host is the bound
    // address when it is a specific one, else the advertise URL's host.
    #[test]
    fn api_902_announced_url_follows_the_bound_address_or_the_advertise_host() {
        let adv = ["https://192.0.2.7:8443".to_owned()];
        assert_eq!(
            announced(&cfg("0.0.0.0:8080", false), &adv),
            "http://192.0.2.7:8080"
        );
        assert_eq!(
            announced(&cfg("0.0.0.0:8443", true), &adv),
            "https://192.0.2.7:8443"
        );
        assert_eq!(
            announced(&cfg("192.168.1.5:8080", false), &adv),
            "http://192.168.1.5:8080"
        );
        assert_eq!(
            announced(
                &cfg("[::]:8080", false),
                &["https://[2001:db8::7]:8443".to_owned()]
            ),
            "http://[2001:db8::7]:8080"
        );
        assert_eq!(
            announced(&cfg("[2001:db8::5]:8080", false), &[]),
            "http://[2001:db8::5]:8080"
        );
        assert_eq!(
            announced(
                &cfg("0.0.0.0:8080", false),
                &["https://pi-a.example.test:8443/x".to_owned()]
            ),
            "http://pi-a.example.test:8080"
        );
    }

    // REQ: API-902, API-901 (T27.14g, ADR-1116) - `[api] public_url` replaces what the node would work out,
    // even when it could name none; an invalid one is not announced (the loader refuses it anyway).
    #[test]
    fn api_902_public_url_replaces_the_announced_address() {
        let adv = ["https://192.0.2.7:8443".to_owned()];
        let mut c = cfg("0.0.0.0:8080", false);
        c.api.public_url = Some(wrendns_config::SafeString::from(
            "https://pi-a.example.com/",
        ));
        assert_eq!(announced(&c, &adv), "https://pi-a.example.com");
        assert_eq!(announced(&c, &[]), "https://pi-a.example.com");
        c.api.public_url = Some(wrendns_config::SafeString::from("http://192.168.1.9:80"));
        assert_eq!(announced(&c, &adv), "http://192.168.1.9:80");
        // Not a plain web address: ignored, the worked-out address stands.
        for bad in [
            "https://u:p@pi-a.example.com",
            "javascript:alert(1)",
            "https://x/y",
        ] {
            c.api.public_url = Some(wrendns_config::SafeString::from(bad));
            assert_eq!(announced(&c, &adv), "http://192.0.2.7:8080", "{bad}");
        }
    }

    // REQ: API-902 (T27.14g0) - a node that cannot name an address announces nothing.
    #[test]
    fn api_902_announced_url_is_empty_when_no_address_can_be_named() {
        assert_eq!(announced(&cfg("0.0.0.0:8080", false), &[]), "");
        assert_eq!(
            announced(
                &cfg("127.0.0.1:8080", false),
                &["https://127.0.0.1:8443".to_owned()]
            ),
            ""
        );
        assert_eq!(
            announced(
                &cfg("0.0.0.0:8080", false),
                &["https://localhost:8443".to_owned()]
            ),
            ""
        );
        assert_eq!(announced(&cfg("0.0.0.0:8080", false), &[String::new()]), "");
    }
}

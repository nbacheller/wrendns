//! REQ: UPS-004, API-002 (T24.36) — the public resolvers the Upstreams page's simple view offers.
//!
//! The catalog (`presets/upstreams.toml`) is compiled into `wrendns-upstream`; this turns it
//! into the API's rows and answers whether this node has an IPv6 route, so the picker can grey
//! IPv6 out with a reason. It runs when the page asks, never on the query path.

use wrendns_api::model::{UpstreamPreset, UpstreamPresetEndpoint, UpstreamPresets};
use wrendns_upstream::presets::{self, Filtering};
use wrendns_upstream::{Endpoint, Host};

/// The catalog as API rows, and this node's IPv6 route.
pub(crate) fn presets() -> UpstreamPresets {
    UpstreamPresets {
        ipv6_route: ipv6_route(),
        items: rows(),
    }
}

fn rows() -> Vec<UpstreamPreset> {
    let Ok(catalog) = presets::catalog() else {
        return Vec::new();
    };
    catalog
        .iter()
        .map(|p| UpstreamPreset {
            id: p.id.clone(),
            name: p.name.clone(),
            provider: if p.provider.is_empty() {
                p.name.clone()
            } else {
                p.provider.clone()
            },
            variant: p.variant.clone(),
            note: p.note.clone(),
            homepage: p.homepage.clone(),
            filtering: match p.filtering {
                Filtering::None => "none",
                Filtering::Malware => "malware",
                Filtering::Family => "family",
                Filtering::Ads => "ads",
            }
            .to_owned(),
            dnssec: p.dnssec,
            simple: p.simple && p.params.is_empty(),
            params: p.params.clone(),
            endpoints: p
                .endpoint
                .iter()
                .filter_map(|e| {
                    // A placeholder address can't be parsed until it is filled in.
                    let parsed = Endpoint::parse(&e.url).ok()?;
                    Some(UpstreamPresetEndpoint {
                        url: e.url.clone(),
                        protocol: parsed.protocol.to_string(),
                        family: match parsed.host {
                            Host::Ip(ip) if ip.is_ipv6() => "v6",
                            Host::Ip(_) => "v4",
                            Host::Name(_) => "name",
                        }
                        .to_owned(),
                        tls_server_name: e.tls_server_name.clone(),
                    })
                })
                .collect(),
        })
        .collect()
}

/// Whether the kernel has an IPv6 default route that goes somewhere. Another OS, or a table that
/// can't be read, says yes: the picker only greys IPv6 out when it knows.
fn ipv6_route() -> bool {
    match std::fs::read_to_string("/proc/net/ipv6_route") {
        Ok(table) => default_route_in(&table),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No table at all: IPv6 is off in the kernel (Linux), or this isn't Linux.
            !cfg!(target_os = "linux")
        }
        Err(_) => true,
    }
}

/// `/proc/net/ipv6_route` lines: destination, its prefix length, source, its length, next hop,
/// metric, ref count, use count, flags, device (all hex but the device). A default route has
/// prefix length 0; it counts when it is up (`RTF_UP`), is not a reject route (`RTF_REJECT`, which
/// `lo` carries for "unreachable") and leaves by a device other than `lo`.
fn default_route_in(table: &str) -> bool {
    table.lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 10 || f[1] != "00" {
            return false;
        }
        let flags = u32::from_str_radix(f[8], 16).unwrap_or(0);
        flags & 0x1 != 0 && flags & 0x0020_0200 == 0 && f[9] != "lo"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_VIA_ETH0: &str = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000064 00000001 00000000 00000003 eth0\n00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001 lo\n";
    const LO_ONLY: &str = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001 lo\n";
    const LINK_LOCAL_ONLY: &str = "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n";

    /// REQ: UPS-004 (T24.36) — a node with an IPv6 default route reads true; one with only
    /// the loopback's reject route, or only link-local routes, reads false.
    #[test]
    fn ups_004_ipv6_route_check() {
        assert!(default_route_in(DEFAULT_VIA_ETH0));
        assert!(!default_route_in(LO_ONLY));
        assert!(!default_route_in(LINK_LOCAL_ONLY));
        assert!(!default_route_in(""));
    }

    /// REQ: UPS-004 (T24.36) — every simple row has addresses the picker can write, and each
    /// protocol and family is named.
    #[test]
    fn ups_004_rows_carry_endpoints_with_protocol_and_family() {
        let rows = rows();
        let cf = rows.iter().find(|r| r.id == "cloudflare").unwrap();
        assert!(cf.simple && cf.provider == "Cloudflare");
        assert!(cf.endpoints.iter().any(|e| e.protocol == "tls"
            && e.family == "v4"
            && e.tls_server_name.as_deref() == Some("cloudflare-dns.com")));
        assert!(
            cf.endpoints
                .iter()
                .any(|e| e.protocol == "tls" && e.family == "v6")
        );
        assert!(
            cf.endpoints
                .iter()
                .any(|e| e.protocol == "udp" && e.family == "v6")
        );
        assert!(
            cf.endpoints
                .iter()
                .any(|e| e.protocol == "https" && e.family == "name")
        );
        let nd = rows.iter().find(|r| r.id == "nextdns").unwrap();
        assert!(
            !nd.simple,
            "a preset with a parameter is for the Advanced view"
        );
        for r in rows.iter().filter(|r| r.simple) {
            assert!(
                r.endpoints
                    .iter()
                    .any(|e| e.protocol == "udp" || e.protocol == "tls" || e.protocol == "https"),
                "{}",
                r.id
            );
        }
    }
}

//! Resolving an upstream's `source` to an address this node holds.
//!
//! REQ: UPS-013 (T24.31, ADR-997) — `source` is an address, or a network meaning "the address
//! this node holds in it". Start (and every configuration change) refuses a source the node
//! doesn't hold: a query sent from an address no interface has can never leave the node.

use std::net::IpAddr;

use telltale_config::{SourceSpec, parse_source};
use telltale_net::IfAddr;

/// The local address `spec` names, from `held` (this node's interface addresses).
///
/// An address must be one of them. A network picks the lowest address inside it, up interfaces
/// before down ones and global addresses before IPv6 link-local ones, so every node with the
/// same address in that network chooses the same way.
pub fn resolve_source(spec: &str, held: &[IfAddr]) -> Result<IpAddr, String> {
    match parse_source(spec)? {
        SourceSpec::Addr(ip) => {
            if held.iter().any(|a| a.ip == ip) {
                Ok(ip)
            } else {
                Err(format!(
                    "source {ip}: this node holds no such address{}",
                    list(held)
                ))
            }
        }
        SourceSpec::Subnet(net) => {
            let mut inside: Vec<&IfAddr> = held.iter().filter(|a| net.contains(a.ip)).collect();
            inside.sort_by_key(|a| (!a.up, link_local(a.ip), a.ip));
            inside.first().map(|a| a.ip).ok_or_else(|| {
                format!(
                    "source {net}: this node holds no address in that network{}",
                    list(held)
                )
            })
        }
    }
}

/// REQ: UPS-013 (ADR-997 §4) — one line per upstream whose `source` names no address this node
/// holds. Start and reload don't refuse these (that upstream degrades; the others serve), so
/// `config check` and the pre-save checks are where an operator hears of it.
pub fn source_warnings(cfg: &telltale_config::Config) -> Vec<String> {
    let specs: Vec<(&str, &str)> = cfg
        .upstream
        .iter()
        .filter_map(|u| Some((u.name.as_str(), u.source.as_ref()?.as_str())))
        .collect();
    if specs.is_empty() {
        return Vec::new();
    }
    let held = match telltale_net::local_addrs() {
        Ok(h) => h,
        Err(e) => {
            return vec![format!(
                "couldn't list this node's addresses to check `source`: {e}"
            )];
        }
    };
    specs
        .into_iter()
        .filter_map(|(name, spec)| {
            resolve_source(spec, &held).err().map(|e| {
                format!(
                    "upstream `{name}`: {e} (this node would start with that upstream degraded)"
                )
            })
        })
        .collect()
}

fn link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// ` (its addresses: …)`, for an error message: what the operator can pick from.
fn list(held: &[IfAddr]) -> String {
    let mut v: Vec<String> = held
        .iter()
        .filter(|a| !a.ip.is_loopback() && !link_local(a.ip))
        .map(|a| format!("{} on {}", a.ip, a.iface))
        .collect();
    v.truncate(8);
    if v.is_empty() {
        String::new()
    } else {
        format!(" (its addresses: {})", v.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(iface: &str, ip: &str, up: bool) -> IfAddr {
        IfAddr {
            iface: iface.into(),
            ip: ip.parse().unwrap(),
            prefix: 24,
            up,
        }
    }

    /// REQ: UPS-013 — an address the node holds is accepted (with or without `:0`); one it
    /// doesn't is refused, naming what it does hold.
    #[test]
    fn ups_013_resolve_address_held_and_foreign() {
        let held = [
            a("eth0", "192.168.1.252", true),
            a("eth0.100", "198.51.100.252", true),
        ];
        let ip: IpAddr = "198.51.100.252".parse().unwrap();
        assert_eq!(resolve_source("198.51.100.252", &held).unwrap(), ip);
        assert_eq!(resolve_source("198.51.100.252:0", &held).unwrap(), ip);
        let e = resolve_source("203.0.113.252", &held).unwrap_err();
        assert!(e.contains("holds no such address"), "{e}");
        assert!(e.contains("198.51.100.252 on eth0.100"), "{e}");
        assert!(resolve_source("198.51.100.252:53", &held).is_err());
        assert!(resolve_source("0.0.0.0", &held).is_err());
        assert!(resolve_source("not an address", &held).is_err());
    }

    /// REQ: UPS-013 — a network means the address this node holds in it, so one shared
    /// upstream works on nodes whose addresses differ (.12 on one node, .11 on the other).
    #[test]
    fn ups_013_resolve_network_picks_the_nodes_own_address() {
        let pi1 = [
            a("eth0", "192.168.1.251", true),
            a("eth0.100", "198.51.100.251", true),
        ];
        let pi2 = [
            a("eth0", "192.168.1.252", true),
            a("eth0.100", "198.51.100.252", true),
        ];
        assert_eq!(
            resolve_source("198.51.100.0/24", &pi1)
                .unwrap()
                .to_string(),
            "198.51.100.251"
        );
        assert_eq!(
            resolve_source("198.51.100.0/24", &pi2)
                .unwrap()
                .to_string(),
            "198.51.100.252"
        );
        let e = resolve_source("203.0.113.0/24", &pi1).unwrap_err();
        assert!(e.contains("holds no address in that network"), "{e}");
    }

    /// REQ: UPS-013 — several addresses in the network: up before down, then the lowest.
    #[test]
    fn ups_013_resolve_network_is_deterministic() {
        let held = [
            a("eth0.100", "198.51.100.9", false),
            a("eth0.100", "198.51.100.30", true),
            a("eth0.100", "198.51.100.20", true),
        ];
        assert_eq!(
            resolve_source("198.51.100.0/24", &held)
                .unwrap()
                .to_string(),
            "198.51.100.20"
        );
    }
}

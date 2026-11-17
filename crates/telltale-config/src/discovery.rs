//! REQ: DSC-001 (T25.2, ADR-907, ADR-908) — `[discovery]`: the network inventory's switch and its
//! settings. Off by default. It runs on one designated node (`node`, else the primary or the
//! standalone node), and only reads: it names the private IPv4 subnets whose inventory addresses
//! may be read, and never a range to sweep (ADR-907). The section is a shared one, edited through
//! the admin-only `discovery` kind (ADR-907 "Writes and audit").

use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::types::{Cidr, SafeString};

/// REQ: DSC-002 (ADR-908) — the worker's memory limit, in MiB, from 32 to 128.
pub const WORKER_MEMORY_MIN_MIB: u32 = 32;
/// REQ: DSC-002 (ADR-908) — the worker's memory limit, in MiB (upper bound).
pub const WORKER_MEMORY_MAX_MIB: u32 = 128;
/// REQ: DSC-002 (ADR-908) — the default worker memory limit, in MiB.
pub const WORKER_MEMORY_DEFAULT_MIB: u32 = 64;

/// REQ: DSC-001 — the network inventory section (`[discovery]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct DiscoveryConfig {
    /// Turn the network inventory on. Off by default: nothing starts, and nothing is read.
    pub enabled: bool,
    /// The node that runs discovery. Unset: the cluster's primary, or the standalone node.
    /// Ephemeral pods and witnesses never run it, whatever is set here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<SafeString>,
    /// Memory limit of each discovery worker process, in MiB (32 to 128). A worker that
    /// allocates past it aborts alone (ADR-908).
    pub worker_memory_mib: u32,
    /// Private IPv4 subnets whose inventory addresses may be read. A filter on addresses the
    /// inventory already has, never a list of targets (ADR-907).
    #[serde(default, rename = "subnet")]
    pub subnets: Vec<DiscoverySubnet>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node: None,
            worker_memory_mib: WORKER_MEMORY_DEFAULT_MIB,
            subnets: Vec::new(),
        }
    }
}

impl DiscoveryConfig {
    /// True when the section is left at its defaults (it is then not serialized, CLU-010).
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// One `[[discovery.subnet]]`: a private IPv4 network, given as `cidr = "192.168.1.0/24"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySubnet {
    /// The network, in CIDR form. IPv4 only, inside RFC 1918.
    pub cidr: Cidr,
}

/// True for an RFC 1918 IPv4 network (`10/8`, `172.16/12`, `192.168/16`). A network that
/// starts in one of them but is wider than it (`10.0.0.0/7`) is not: it would reach outside.
pub fn is_rfc1918_network(c: &Cidr) -> bool {
    let IpAddr::V4(a) = c.addr else {
        return false;
    };
    let o = a.octets();
    let inside = match o {
        [10, ..] => c.prefix >= 8,
        [172, b, ..] => (16..=31).contains(&b) && c.prefix >= 12,
        [192, 168, ..] => c.prefix >= 16,
        _ => false,
    };
    inside && c.prefix <= 32
}

/// Container, cluster and Docker ranges that a subnet should not overlap (ADR-907, the overlap
/// warnings of `[discovery]`): a subnet over them reads pod and service addresses.
pub const OVERLAP_WARNINGS: &[(&str, &str)] = &[
    ("10.42.0.0/16", "the k3s pod network"),
    ("10.43.0.0/16", "the k3s service network"),
    ("10.96.0.0/12", "the Kubernetes service network"),
    ("10.244.0.0/16", "the Flannel pod network"),
    ("172.17.0.0/16", "the Docker default bridge"),
];

/// True when two IPv4 networks share an address.
pub fn overlaps(first: &Cidr, second: &Cidr) -> bool {
    let (IpAddr::V4(net_a), IpAddr::V4(net_b)) = (first.addr, second.addr) else {
        return false;
    };
    let prefix = first.prefix.min(second.prefix);
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from(net_a) & mask == u32::from(net_b) & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Loader};

    fn load(toml: &str) -> Result<Config, Vec<crate::ConfigError>> {
        Loader::new()
            .toml_str("test", toml)
            .load()
            .map(|l| l.config)
    }

    /// REQ: DSC-001 — off by default: no section in the defaults, and none in the serialized
    /// config (CLU-010), so a node that never set it sends nothing new.
    #[test]
    fn dsc_001_off_by_default_starts_nothing() {
        let cfg = Config::default();
        assert!(!cfg.discovery.enabled);
        assert!(cfg.discovery.is_default());
        let v = serde_json::to_value(&cfg).unwrap();
        assert!(v.get("discovery").is_none(), "left out when unset");
    }

    /// REQ: DSC-001 — a private IPv4 literal is read; a host name is not an address at all
    /// (the TOML fails to load, naming the key), and IPv6 is refused by validation.
    #[test]
    fn dsc_001_addresses_must_be_private_ip_literals() {
        let ok =
            load("[discovery]\nenabled = true\n[[discovery.subnet]]\ncidr = \"192.168.1.0/24\"\n");
        assert!(ok.is_ok(), "{ok:?}");
        let host = load("[discovery]\n[[discovery.subnet]]\ncidr = \"lan.example/24\"\n");
        assert!(host.is_err());
        let v6 = load("[discovery]\n[[discovery.subnet]]\ncidr = \"fd00::/64\"\n").unwrap_err();
        assert!(v6.iter().any(|e| e.message.contains("IPv6")), "{v6:?}");
    }

    /// REQ: DSC-001 — refused ranges: CGNAT (100.64/10, Tailscale's), loopback, link-local,
    /// public space, and a network wider than RFC 1918 that starts inside it.
    #[test]
    fn dsc_001_refused_ranges() {
        for bad in [
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "8.8.8.0/24",
            "10.0.0.0/7",
            "172.32.0.0/16",
        ] {
            let c = Cidr::parse(bad).unwrap();
            assert!(!is_rfc1918_network(&c), "{bad} must be refused");
            let t = format!("[discovery]\n[[discovery.subnet]]\ncidr = \"{bad}\"\n");
            assert!(load(&t).is_err(), "{bad} must fail validation");
        }
        for good in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
            assert!(is_rfc1918_network(&Cidr::parse(good).unwrap()), "{good}");
        }
    }

    /// REQ: DSC-001 — the worker memory limit is 32 to 128 MiB.
    #[test]
    fn dsc_001_worker_memory_bounds() {
        assert!(load("[discovery]\nworker_memory_mib = 31\n").is_err());
        assert!(load("[discovery]\nworker_memory_mib = 129\n").is_err());
        assert!(load("[discovery]\nworker_memory_mib = 128\n").is_ok());
    }

    /// REQ: DSC-001 — enabling is refused at privacy level 2 or more (the inventory needs the
    /// client addresses those levels hide), and allowed at 0 and 1.
    #[test]
    fn dsc_001_privacy_level_2_refuses_enable() {
        let refused =
            load("[discovery]\nenabled = true\n[telemetry.qlog]\nprivacy_level = 2\n").unwrap_err();
        assert!(
            refused.iter().any(|e| e.path == "discovery.enabled"),
            "{refused:?}"
        );
        assert!(load("[discovery]\nenabled = true\n[telemetry.qlog]\nprivacy_level = 1\n").is_ok());
        // Off is never refused, whatever the level.
        assert!(
            load("[discovery]\nenabled = false\n[telemetry.qlog]\nprivacy_level = 3\n").is_ok()
        );
    }

    /// REQ: DSC-001 — a subnet over a container or cluster range is a warning, not an error.
    #[test]
    fn dsc_001_overlap_with_container_ranges_warns() {
        let loaded = Loader::new()
            .toml_str(
                "test",
                "[discovery]\n[[discovery.subnet]]\ncidr = \"10.42.0.0/16\"\n",
            )
            .load()
            .unwrap();
        assert!(
            loaded
                .warnings
                .iter()
                .any(|w| w.contains("k3s pod network")),
            "{:?}",
            loaded.warnings
        );
    }

    /// REQ: DSC-001 — the section round-trips, and an unknown key is refused by name.
    #[test]
    fn dsc_001_section_round_trips() {
        let cfg = load("[discovery]\nenabled = true\nnode = \"pi-a\"\n[[discovery.subnet]]\ncidr = \"192.168.1.0/24\"\n").unwrap();
        let text = toml::to_string(&cfg.discovery).unwrap();
        let back: DiscoveryConfig = toml::from_str(&text).unwrap();
        assert_eq!(back, cfg.discovery);
        let bad = load("[discovery]\nenabld = true\n").unwrap_err();
        assert!(bad.iter().any(|e| e.message.contains("enabld")), "{bad:?}");
    }
}

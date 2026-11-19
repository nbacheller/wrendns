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

/// REQ: DSC-009 (T25.10, ADR-912) — the shortest `stat/alluser` window, in hours.
pub const ALL_USERS_MIN_HOURS: u32 = 1;
/// REQ: DSC-009 (ADR-912) — the longest `stat/alluser` window, in hours (one year).
pub const ALL_USERS_MAX_HOURS: u32 = 8_760;
/// REQ: DSC-009 (ADR-912) — the default `stat/alluser` window, in hours (30 days).
pub const ALL_USERS_DEFAULT_HOURS: u32 = 720;

/// REQ: DSC-009 (T25.10, ADR-912) — which extra read-only UniFi reads the inventory makes, for
/// each UniFi `[[router]]`. Each one is off until an admin turns it on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct UnifiReads {
    /// Read more fields of the clients the router poll already reads (`stat/sta`, `rest/user`):
    /// wired or wireless, the switch port, the access point, the VLAN and network, and the first
    /// time the client was seen. No extra request.
    pub client_fields: bool,
    /// `POST stat/alluser` (a query, it changes nothing): clients UniFi has seen within
    /// `unifi_all_users_within_hours`, as history (class 5). Never a current address.
    pub all_users: bool,
    /// `GET stat/device`: UniFi's own devices, their switch-port MAC tables (where a client plugs
    /// in) and LLDP neighbours.
    pub devices: bool,
}

impl UnifiReads {
    /// Whether any extra UniFi read is on.
    pub fn any(&self) -> bool {
        self.client_fields || self.all_users || self.devices
    }
}

fn default_within_hours() -> u32 {
    ALL_USERS_DEFAULT_HOURS
}

fn default_true() -> bool {
    true
}

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
    /// REQ: DSC-004 (T25.6, ADR-908) — the infrastructure devices that are polled over SNMP: a
    /// gateway's ARP table, a switch's forwarding table, LLDP neighbours. Each names a credential.
    #[serde(default, rename = "snmp_agent", skip_serializing_if = "Vec::is_empty")]
    pub snmp_agents: Vec<SnmpAgent>,
    /// REQ: DSC-004, DSC-007 (T25.6, ADR-908) — the SNMP credentials the agents use. A secret is
    /// only ever a file under `[node] secret_file_dirs`; an inline value is refused.
    #[serde(
        default,
        rename = "snmp_credential",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub snmp_credentials: Vec<SnmpCredential>,
    /// REQ: DSC-009 (ADR-912) — the extra UniFi reads, all off by default.
    #[serde(default)]
    pub unifi_reads: UnifiReads,
    /// REQ: DSC-009 (ADR-912) — how far back `stat/alluser` reaches, in hours (1 to 8,760).
    #[serde(default = "default_within_hours")]
    pub unifi_all_users_within_hours: u32,
    /// REQ: DSC-009 (ADR-912) — read Home Assistant's registry devices that have a MAC and no
    /// entity, into the inventory only. On by default; it applies only when discovery is on.
    #[serde(default = "default_true")]
    pub home_assistant_all_devices: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node: None,
            worker_memory_mib: WORKER_MEMORY_DEFAULT_MIB,
            subnets: Vec::new(),
            snmp_agents: Vec::new(),
            snmp_credentials: Vec::new(),
            unifi_reads: UnifiReads::default(),
            unifi_all_users_within_hours: ALL_USERS_DEFAULT_HOURS,
            home_assistant_all_devices: true,
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

/// REQ: DSC-004 (ADR-908) — the shortest poll interval of an agent, in seconds.
pub const AGENT_INTERVAL_MIN_SECS: u32 = 60;
/// REQ: DSC-004 — the longest poll interval of an agent, in seconds (one day).
pub const AGENT_INTERVAL_MAX_SECS: u32 = 86_400;
/// REQ: DSC-004 — the default poll interval of an agent, in seconds.
pub const AGENT_INTERVAL_DEFAULT_SECS: u32 = 300;
/// REQ: DSC-004 (ADR-908) — GETBULK `max_repetitions`, lowest.
pub const MAX_REPETITIONS_MIN: u32 = 5;
/// REQ: DSC-004 (ADR-908) — GETBULK `max_repetitions`, highest.
pub const MAX_REPETITIONS_MAX: u32 = 25;
/// REQ: DSC-004 (ADR-908) — GETBULK `max_repetitions`, default.
pub const MAX_REPETITIONS_DEFAULT: u32 = 10;
/// REQ: DSC-004 (ADR-1001) — agents (and credentials) listed at most.
pub const MAX_AGENTS: usize = 32;
/// REQ: DSC-004 — the default SNMP port.
pub const SNMP_PORT: u16 = 161;

fn default_interval() -> u32 {
    AGENT_INTERVAL_DEFAULT_SECS
}
fn default_repetitions() -> u32 {
    MAX_REPETITIONS_DEFAULT
}
fn default_port() -> u16 {
    SNMP_PORT
}
fn default_tables() -> Vec<SnmpTable> {
    vec![
        SnmpTable::Arp,
        SnmpTable::Ifmib,
        SnmpTable::Bridge,
        SnmpTable::Lldp,
    ]
}

/// REQ: DSC-004 — a table group an agent may be polled for (ADR-908 "Tables").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SnmpTable {
    /// `ipNetToPhysicalTable`, else `ipNetToMediaTable`.
    Arp,
    /// Interface names and the agent's own addresses.
    Ifmib,
    /// The forwarding table (Q-BRIDGE, else BRIDGE), with ports and VLANs.
    Bridge,
    /// The LLDP remote table.
    Lldp,
}

impl SnmpTable {
    /// The name used in the configuration, the API and the metrics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Arp => "arp",
            Self::Ifmib => "ifmib",
            Self::Bridge => "bridge",
            Self::Lldp => "lldp",
        }
    }
}

/// REQ: DSC-004 (ADR-908, ADR-1001) — one `[[discovery.snmp_agent]]`: an infrastructure device
/// polled over SNMP on the designated node. The address is an RFC 1918 IPv4 literal (ADR-907),
/// and the credential is named, never written here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnmpAgent {
    /// The agent's name: letters, digits, `.`, `_` and `-`, and never an IP address (the CLI and
    /// the API take a name only, ADR-969).
    pub name: SafeString,
    /// The device's IPv4 address (RFC 1918 only).
    pub address: SafeString,
    /// The UDP port (161 unless the device says otherwise).
    #[serde(default = "default_port")]
    pub port: u16,
    /// The `[[discovery.snmp_credential]]` this agent uses (role `infrastructure`).
    pub credential: SafeString,
    /// Seconds between polls (60 to 86,400; default 300).
    #[serde(default = "default_interval")]
    pub interval_secs: u32,
    /// GETBULK `max_repetitions` (5 to 25; default 10).
    #[serde(default = "default_repetitions")]
    pub max_repetitions: u32,
    /// The tables to poll. A table the device doesn't answer is skipped until the next test
    /// (capabilities are probed, never assumed).
    #[serde(default = "default_tables")]
    pub tables: Vec<SnmpTable>,
}

/// REQ: DSC-007 (ADR-908 "Credential roles") — who may use a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CredentialRole {
    /// Used by `[[discovery.snmp_agent]]` only: the gateway's and switches' credential.
    #[default]
    Infrastructure,
    /// Used by a subnet's identity reads (T25.7): a low-value, shared identity.
    Host,
}

/// REQ: DSC-003 — the SNMP version of a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub enum SnmpVersion {
    /// `SNMPv2c`: the community travels in clear text.
    #[default]
    #[serde(rename = "v2c")]
    V2c,
    /// `SNMPv3` USM at authNoPriv or authPriv.
    #[serde(rename = "v3")]
    V3,
}

/// REQ: DSC-004, DSC-007 (ADR-908) — one `[[discovery.snmp_credential]]`. Secrets are files under
/// `[node] secret_file_dirs` (an inline `community` or `*_password` is an unknown key and refuses
/// the load). T25.8 adds `*_ref` to the stored-secret store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnmpCredential {
    /// The credential's name, as an agent names it.
    pub name: SafeString,
    /// `infrastructure` (agents) or `host` (identity reads, T25.7).
    #[serde(default)]
    pub role: CredentialRole,
    /// `v2c` or `v3`.
    #[serde(default)]
    pub version: SnmpVersion,
    /// v2c: the file that holds the community.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community_file: Option<SafeString>,
    /// v3: the USM user name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<SafeString>,
    /// v3: `sha`, `sha-256`, `sha-384` or `sha-512`. MD5 and SHA-224 are refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_protocol: Option<SafeString>,
    /// v3: the file that holds the authentication password (8 octets or more).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_password_file: Option<SafeString>,
    /// v3: `aes-128` for authPriv; leave out for authNoPriv. DES, AES-192 and AES-256 are refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priv_protocol: Option<SafeString>,
    /// v3: the file that holds the privacy password. Left out, the authentication password is
    /// used for both (UniFi's single v3 password).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priv_password_file: Option<SafeString>,
}

/// REQ: DSC-004 — whether a name is a label an agent or a credential may have.
pub fn valid_label(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && name.parse::<IpAddr>().is_err()
}

/// REQ: DSC-004 (ADR-907) — an RFC 1918 IPv4 address (`10/8`, `172.16/12`, `192.168/16`).
pub fn is_rfc1918_addr(a: std::net::Ipv4Addr) -> bool {
    matches!(a.octets(), [10, ..] | [172, 16..=31, ..] | [192, 168, ..])
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

    const CRED_V3: &str = "[[discovery.snmp_credential]]
name = \"gw\"
version = \"v3\"
user = \"telltale\"
auth_protocol = \"sha\"
auth_password_file = \"/run/secrets/gw\"
priv_protocol = \"aes-128\"
";

    /// REQ: DSC-004 (ADR-908) — an agent names a credential, polls every 300 s with 10
    /// repetitions and all four tables by default, and the section round-trips.
    #[test]
    fn dsc_004_agent_defaults_and_round_trip() {
        let t = format!(
            "[discovery]
{CRED_V3}[[discovery.snmp_agent]]
name = \"gateway\"
address = \"192.0.2.1\"
credential = \"gw\"
"
        );
        let cfg = load(&t).unwrap();
        let a = &cfg.discovery.snmp_agents[0];
        assert_eq!((a.port, a.interval_secs, a.max_repetitions), (161, 300, 10));
        assert_eq!(a.tables.len(), 4);
        let text = toml::to_string(&cfg.discovery).unwrap();
        let back: DiscoveryConfig = toml::from_str(&text).unwrap();
        assert_eq!(back, cfg.discovery);
        assert!(!cfg.discovery.is_default());
    }

    /// REQ: DSC-004, ADR-907 — an agent's address is an RFC 1918 IPv4 literal; a host name,
    /// IPv6, loopback, CGNAT and public space are refused, and its name is never an address.
    #[test]
    fn dsc_004_agent_address_and_name_rules() {
        let agent = |name: &str, addr: &str| {
            format!(
                "[discovery]
{CRED_V3}[[discovery.snmp_agent]]
name = \"{name}\"
address = \"{addr}\"
credential = \"gw\"
"
            )
        };
        assert!(load(&agent("a", "10.1.2.3")).is_ok());
        assert!(load(&agent("a", "172.31.0.1")).is_ok());
        for bad in [
            "gateway.example",
            "fd00::1",
            "127.0.0.1",
            "100.64.1.1",
            "8.8.8.8",
            "172.32.0.1",
            "169.254.1.1",
        ] {
            assert!(load(&agent("a", bad)).is_err(), "{bad}");
        }
        for bad in ["192.168.1.1", "bad name", "", "a/b"] {
            assert!(load(&agent(bad, "10.1.2.3")).is_err(), "name {bad:?}");
        }
    }

    /// REQ: DSC-004, DSC-007 — the interval is 60 s or more, the repetitions 5 to 25, a table is
    /// named, and an unknown credential only warns (the agent is skipped).
    #[test]
    fn dsc_004_agent_limits() {
        let body = |extra: &str| {
            format!(
                "[discovery]
{CRED_V3}[[discovery.snmp_agent]]
name = \"a\"
address = \"10.0.0.2\"
credential = \"gw\"
{extra}"
            )
        };
        assert!(
            load(&body(
                "interval_secs = 60
"
            ))
            .is_ok()
        );
        assert!(
            load(&body(
                "interval_secs = 59
"
            ))
            .is_err()
        );
        assert!(
            load(&body(
                "max_repetitions = 4
"
            ))
            .is_err()
        );
        assert!(
            load(&body(
                "max_repetitions = 26
"
            ))
            .is_err()
        );
        assert!(
            load(&body(
                "tables = []
"
            ))
            .is_err()
        );
        assert!(
            load(&body(
                "tables = [\"arp\", \"bridge\"]
"
            ))
            .is_ok()
        );
        assert!(
            load(&body(
                "tables = [\"snmpset\"]
"
            ))
            .is_err()
        );
        assert!(
            load(&body(
                "port = 0
"
            ))
            .is_err()
        );
        let missing = Loader::new()
            .toml_str(
                "t",
                "[discovery]
[[discovery.snmp_agent]]
name = \"a\"
address = \"10.0.0.2\"
credential = \"nope\"
",
            )
            .load()
            .unwrap();
        assert!(
            missing.warnings.iter().any(|w| w.contains("skipped")),
            "{:?}",
            missing.warnings
        );
    }

    /// REQ: DSC-007, ADR-908 — an inline secret is not a key (the load fails), the refused v3
    /// protocols are named with their reason, and an agent can't use a host credential.
    #[test]
    fn dsc_004_credential_rules() {
        let inline = "[discovery]
[[discovery.snmp_credential]]
name = \"c\"
community = \"public\"
";
        let e = load(inline).unwrap_err();
        assert!(e.iter().any(|e| e.message.contains("community")), "{e:?}");
        let inline_pw = "[discovery]
[[discovery.snmp_credential]]
name = \"c\"
version = \"v3\"
auth_password = \"hunter22\"
";
        assert!(load(inline_pw).is_err());
        let v3 = |auth: &str, privp: &str| {
            format!(
                "[discovery]
[[discovery.snmp_credential]]
name = \"c\"
version = \"v3\"
user = \"u\"
auth_protocol = \"{auth}\"
auth_password_file = \"/run/secrets/c\"
{privp}"
            )
        };
        assert!(
            load(&v3(
                "sha-256",
                "priv_protocol = \"aes-128\"
"
            ))
            .is_ok()
        );
        assert!(load(&v3("sha", "")).is_ok(), "authNoPriv");
        for (a, p, why) in [
            ("md5", "", "MD5"),
            ("sha-224", "", "SHA-224"),
            (
                "sha",
                "priv_protocol = \"des\"
",
                "DES",
            ),
            (
                "sha",
                "priv_protocol = \"aes-256\"
",
                "AES-256",
            ),
        ] {
            let e = load(&v3(a, p)).unwrap_err();
            assert!(e.iter().any(|e| e.message.contains(why)), "{why}: {e:?}");
        }
        let v2c_with_v3 = "[discovery]
[[discovery.snmp_credential]]
name = \"c\"
community_file = \"/run/secrets/c\"
user = \"u\"
";
        assert!(load(v2c_with_v3).is_err());
        let host = "[discovery]
[[discovery.snmp_credential]]
name = \"h\"
role = \"host\"
community_file = \"/run/secrets/h\"
[[discovery.snmp_agent]]
name = \"a\"
address = \"10.0.0.2\"
credential = \"h\"
";
        let e = load(host).unwrap_err();
        assert!(
            e.iter().any(|e| e.message.contains("host credential")),
            "{e:?}"
        );
    }

    /// REQ: DSC-007 — a credential file outside `[node] secret_file_dirs` (or with `..`) warns
    /// that the poller will refuse to read it; v2c warns about the clear-text community.
    #[test]
    fn dsc_004_credential_file_outside_secret_dirs_warns() {
        let l = Loader::new()
            .toml_str(
                "t",
                "[discovery]
[[discovery.snmp_credential]]
name = \"c\"
community_file = \"/etc/passwd\"
",
            )
            .load()
            .unwrap();
        assert!(
            l.warnings.iter().any(|w| w.contains("secret_file_dirs")),
            "{:?}",
            l.warnings
        );
        assert!(l.warnings.iter().any(|w| w.contains("clear text")));
        let dots = Loader::new()
            .toml_str(
                "t",
                "[discovery]
[[discovery.snmp_credential]]
name = \"c\"
community_file = \"/run/secrets/../../etc/shadow\"
",
            )
            .load()
            .unwrap();
        assert!(dots.warnings.iter().any(|w| w.contains("secret_file_dirs")));
    }

    /// REQ: DSC-009 (T25.10, ADR-912) - the extra reads: every UniFi read is off by default, the
    /// window is 720 hours, and Home Assistant's all-devices read is on (it applies only when
    /// discovery is on).
    #[test]
    fn dsc_009_defaults_and_keys() {
        let d = Config::default().discovery;
        assert!(!d.unifi_reads.any());
        assert_eq!(d.unifi_all_users_within_hours, 720);
        assert!(d.home_assistant_all_devices);
        let cfg = load(
            "[discovery]
enabled = true
unifi_all_users_within_hours = 48
home_assistant_all_devices = false
[discovery.unifi_reads]
all_users = true
devices = true
",
        )
        .unwrap();
        assert!(cfg.discovery.unifi_reads.all_users && cfg.discovery.unifi_reads.devices);
        assert!(!cfg.discovery.unifi_reads.client_fields);
        assert_eq!(cfg.discovery.unifi_all_users_within_hours, 48);
        assert!(!cfg.discovery.home_assistant_all_devices);
        // The set values round-trip, and an unknown read is refused by name.
        let text = toml::to_string(&cfg.discovery).unwrap();
        assert_eq!(
            toml::from_str::<DiscoveryConfig>(&text).unwrap(),
            cfg.discovery
        );
        let bad = load(
            "[discovery]
[discovery.unifi_reads]
alluser = true
",
        )
        .unwrap_err();
        assert!(bad.iter().any(|e| e.message.contains("alluser")), "{bad:?}");
    }

    /// REQ: DSC-009 - the `stat/alluser` window is 1 to 8,760 hours.
    #[test]
    fn dsc_009_window_bounds() {
        assert!(
            load(
                "[discovery]
unifi_all_users_within_hours = 0
"
            )
            .is_err()
        );
        assert!(
            load(
                "[discovery]
unifi_all_users_within_hours = 8761
"
            )
            .is_err()
        );
        assert!(
            load(
                "[discovery]
unifi_all_users_within_hours = 1
"
            )
            .is_ok()
        );
        assert!(
            load(
                "[discovery]
unifi_all_users_within_hours = 8760
"
            )
            .is_ok()
        );
    }
}

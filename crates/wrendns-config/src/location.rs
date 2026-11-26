// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: DSC-908, DSC-909, DSC-910, DSC-911, DSC-916 (T36.10a; ADR-1081, ADR-1096) - the
//! `[[location]]` table: a slug, the networks and VLANs that belong to it, the nodes that serve it,
//! an optional parent domain, a visibility and the flat-name switch. Validation lives here so the
//! file loader, the API and a replica's merge all refuse the same tables with the same words.

use std::collections::HashSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Config;
use crate::types::{Cidr, SafeString};

/// Most locations a configuration may hold.
pub const MAX_LOCATIONS: usize = 64;

/// Labels a location slug may not take (they are never device labels either, ADR-901, and the
/// ACME challenge label belongs to the certificate work).
pub const RESERVED_SLUGS: [&str; 4] = ["wpad", "isatap", "localhost", "_acme-challenge"];

/// Who sees a location's device names (DSC-911).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LocationVisibility {
    /// Every client `[access]` allows sees the names (today's behaviour).
    #[default]
    Shared,
    /// Only a client whose source address is in one of the location's networks sees them.
    Private,
}

fn yes() -> bool {
    true
}

/// A location: a named part of the network with its own device-name subtree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocationConfig {
    /// The DNS label (`home`, `lab`): lowercase letters, digits and hyphens, 1 to 32 characters,
    /// unique in the cluster. Devices answer as `<device>.<slug>.<domain>`.
    pub slug: SafeString,
    /// Display name, at most 64 characters. Untrusted text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<SafeString>,
    /// The networks that belong to it: CIDRs (IPv4 or IPv6), or `vlan:<id>` (1 to 4094) resolved
    /// through the router network reads and this node's own VLAN interfaces. At least one; no
    /// CIDR may overlap another location's.
    pub networks: Vec<SafeString>,
    /// The nodes that serve the location, by node name. Empty: every node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<SafeString>,
    /// The parent domain, lowercase without a trailing dot. Default: `[local] device_domain`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<SafeString>,
    /// `shared` (default) or `private`.
    #[serde(default)]
    pub visibility: LocationVisibility,
    /// Keep answering the old `<device>.<device_domain>` names for the location's devices while
    /// people move over (DSC-916). On by default.
    #[serde(default = "yes")]
    pub flat_names: bool,
}

impl LocationConfig {
    /// The slug (the entry's name in the API).
    pub fn name(&self) -> &str {
        self.slug.as_str()
    }

    /// The parent domain this location composes names under: its own `domain`, else the global
    /// `[local] device_domain`; lowercase, no trailing dot. `None` when neither is set.
    pub fn parent_domain(&self, cfg: &Config) -> Option<String> {
        let d = self
            .domain
            .as_ref()
            .or(cfg.local.device_domain.as_ref())?
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        (!d.is_empty()).then_some(d)
    }
}

/// One entry of a location's `networks`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocationNet {
    Cidr(Cidr),
    Vlan(u16),
}

/// Reads one `networks` entry: a CIDR or `vlan:<id>`.
pub fn parse_network(s: &str) -> Result<LocationNet, String> {
    let s = s.trim();
    if let Some(id) = s.strip_prefix("vlan:") {
        return id
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|v| (1..=4094).contains(v))
            .map(LocationNet::Vlan)
            .ok_or_else(|| format!("`{s}`: a VLAN ID is 1 to 4094"));
    }
    if !s.contains('/') {
        return Err(format!(
            "`{s}`: write a network as a CIDR (`192.0.2.0/24`) or `vlan:<id>`"
        ));
    }
    Cidr::parse(s).map(LocationNet::Cidr)
}

/// REQ: ADR-901 - a device's name as one DNS label: lowercase letters, digits, and hyphens, at
/// most 63 bytes (`Kitchen Tablet` becomes `kitchen-tablet`, `Alex's iPhone` becomes
/// `alexs-iphone`). Apostrophes are dropped; anything else that is not an ASCII letter or digit
/// separates words. `None` when nothing is left.
pub fn device_label(name: &str) -> Option<String> {
    let mut out = String::with_capacity(name.len().min(63));
    let mut gap = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            if gap && !out.is_empty() {
                out.push('-');
            }
            gap = false;
            out.push(c.to_ascii_lowercase());
            if out.len() >= 63 {
                break;
            }
        } else if !matches!(c, '\'' | '\u{2019}') {
            gap = true;
        }
    }
    out.truncate(63);
    let label = out.trim_end_matches('-');
    (!label.is_empty()).then(|| label.to_owned())
}

fn slug_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

fn domain_ok(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 200
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Two networks of one family overlap when one contains the other's network address.
fn overlaps(a: &Cidr, b: &Cidr) -> bool {
    a.contains(b.network().addr) || b.contains(a.network().addr)
}

/// Every problem in the `[[location]]` table and in the `location` fields of `[[client]]`
/// entries, as `(path, message)` pairs. DSC-908: each names the bad field.
#[allow(clippy::too_many_lines)] // one pass over the table, one check per field
pub fn problems(cfg: &Config) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut err = |p: String, m: String| out.push((p, m));
    if cfg.location.len() > MAX_LOCATIONS {
        err(
            "location".into(),
            format!("at most {MAX_LOCATIONS} locations"),
        );
    }
    let mut slugs: HashSet<&str> = HashSet::new();
    let mut cidrs: Vec<(usize, Cidr)> = Vec::new();
    // Device labels the configuration names (a slug may not equal one under the same parent).
    let client_labels: HashSet<String> = cfg
        .client
        .iter()
        .filter_map(|c| device_label(c.name.as_str()))
        .collect();
    for (i, l) in cfg.location.iter().enumerate() {
        let p = format!("location[{i}]");
        let slug = l.slug.as_str();
        if !slug_ok(slug) {
            err(
                format!("{p}.slug"),
                format!(
                    "`{slug}` is not a label: lowercase letters, digits and hyphens, 1 to 32 characters, not starting or ending with a hyphen"
                ),
            );
        } else if RESERVED_SLUGS.contains(&slug) {
            err(format!("{p}.slug"), format!("`{slug}` is a reserved label"));
        } else if !slugs.insert(slug) {
            err(format!("{p}.slug"), format!("`{slug}` is used twice"));
        } else if client_labels.contains(slug) {
            err(
                format!("{p}.slug"),
                format!(
                    "`{slug}` is also the name of a device; a location's slug is a DNS label of its own"
                ),
            );
        }
        if let Some(label) = &l.label
            && label.chars().count() > 64
        {
            err(format!("{p}.label"), "at most 64 characters".into());
        }
        if l.networks.is_empty() {
            err(
                format!("{p}.networks"),
                "at least one network (a CIDR or `vlan:<id>`)".into(),
            );
        }
        if l.networks.len() > 64 {
            err(format!("{p}.networks"), "at most 64 networks".into());
        }
        for (j, n) in l.networks.iter().enumerate() {
            match parse_network(n.as_str()) {
                Ok(LocationNet::Cidr(c)) => cidrs.push((i, c)),
                Ok(LocationNet::Vlan(_)) => {}
                Err(m) => err(format!("{p}.networks[{j}]"), m),
            }
        }
        if l.nodes.len() > 64 {
            err(format!("{p}.nodes"), "at most 64 nodes".into());
        }
        for (j, n) in l.nodes.iter().enumerate() {
            if n.trim().is_empty() || n.len() > 63 {
                err(
                    format!("{p}.nodes[{j}]"),
                    "a node name of 1 to 63 characters".into(),
                );
            }
        }
        if let Some(d) = &l.domain {
            let d = d.trim().trim_end_matches('.');
            if !domain_ok(d) {
                err(
                    format!("{p}.domain"),
                    "a domain name of at most 200 characters, such as home.arpa or example.net"
                        .into(),
                );
            } else if d.eq_ignore_ascii_case("local") {
                err(
                    format!("{p}.domain"),
                    "`local` belongs to mDNS (RFC 6762)".into(),
                );
            }
        }
        match l.parent_domain(cfg) {
            None => err(
                format!("{p}.domain"),
                "set `[local] device_domain` or this location's `domain`".into(),
            ),
            Some(d) if l.domain.is_none() && !domain_ok(&d) => {
                // `[local] device_domain` is validated by its own rule; nothing to add.
            }
            Some(parent) => {
                // The flat names are `<label>.<device_domain>`: inside the location's own subtree
                // they would collide with the device's location name and never be reached (the
                // subtree is answered first).
                let apex = format!("{}.{parent}", l.slug);
                let flat = cfg
                    .local
                    .device_domain
                    .as_ref()
                    .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase());
                if l.flat_names
                    && let Some(f) = flat
                    && (f == apex || f.ends_with(&format!(".{apex}")))
                {
                    err(
                        format!("{p}.domain"),
                        format!(
                            "`[local] device_domain` ({f}) is inside this location's names ({apex}); its flat names would collide with them: pick another `domain` or `slug`, or set `flat_names = false`"
                        ),
                    );
                }
            }
        }
    }
    // Overlap between two locations' CIDRs names both.
    for (a, (i, ca)) in cidrs.iter().enumerate() {
        for (j, cb) in &cidrs[a + 1..] {
            if i != j && overlaps(ca, cb) {
                let la = &cfg.location[*i];
                err(
                    format!("location[{j}].networks"),
                    format!(
                        "overlaps location `{}` (`{}/{}` and `{}/{}`)",
                        la.slug, ca.addr, ca.prefix, cb.addr, cb.prefix
                    ),
                );
            }
        }
    }
    // A client's `location` names a configured location (DSC-910).
    for (i, c) in cfg.client.iter().enumerate() {
        if let Some(slug) = &c.location
            && !cfg.location.iter().any(|l| l.slug == *slug)
        {
            err(
                format!("client[{i}].location"),
                format!("no location `{slug}`"),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> Config {
        crate::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap_or_else(|e| panic!("{e:?}"))
            .config
    }

    fn refused(toml: &str) -> String {
        match crate::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
        {
            Ok(_) => String::new(),
            Err(e) => e
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

    const BASE: &str = "[local]\ndevice_domain = \"home.arpa\"\n";

    #[test]
    fn dsc_908_a_location_loads_with_its_defaults() {
        let c = cfg(&format!(
            "{BASE}[[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\", \"vlan:30\"]\n"
        ));
        let l = &c.location[0];
        assert_eq!(l.visibility, LocationVisibility::Shared);
        assert!(l.flat_names, "flat names are on by default (DSC-916)");
        assert_eq!(l.parent_domain(&c).as_deref(), Some("home.arpa"));
    }

    #[test]
    fn dsc_908_validation_names_the_bad_field() {
        for (toml, want) in [
            (
                "[[location]]\nslug = \"Home\"\nnetworks = [\"192.0.2.0/24\"]\n",
                "location[0].slug",
            ),
            (
                "[[location]]\nslug = \"wpad\"\nnetworks = [\"192.0.2.0/24\"]\n",
                "reserved label",
            ),
            (
                "[[location]]\nslug = \"home\"\nnetworks = []\n",
                "location[0].networks",
            ),
            (
                "[[location]]\nslug = \"home\"\nnetworks = [\"vlan:5000\"]\n",
                "1 to 4094",
            ),
            (
                "[[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0\"]\n",
                "CIDR",
            ),
            (
                "[[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\"]\n",
                "set `[local] device_domain` or this location's `domain`",
            ),
            (
                "[local]\ndevice_domain = \"home.arpa\"\n[[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\"]\nlabel = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
                "location[0].label",
            ),
        ] {
            let got = refused(toml);
            assert!(got.contains(want), "{toml}\n-> {got}");
        }
    }

    #[test]
    fn dsc_908_a_device_domain_inside_the_locations_subtree_is_refused() {
        let toml = |extra: &str| {
            format!(
                "[local]\ndevice_domain = \"home.arpa\"\n[[location]]\nslug = \"home\"\ndomain = \"arpa\"\nnetworks = [\"192.0.2.0/24\"]\n{extra}"
            )
        };
        let got = refused(&toml(""));
        assert!(
            got.contains("location[0].domain") && got.contains("inside this location's names"),
            "{got}"
        );
        // Flat names off: nothing collides.
        assert_eq!(refused(&toml("flat_names = false\n")), "");
        // A subdomain of the apex is inside too.
        let sub = toml("").replace("= \"home.arpa\"\n[[", "= \"lab.home.arpa\"\n[[");
        assert!(refused(&sub).contains("inside this location's names"));
    }

    #[test]
    fn dsc_908_a_slug_is_unique_and_never_a_device_label() {
        let got = refused(&format!(
            "{BASE}[[location]]\nslug = \"a\"\nnetworks = [\"192.0.2.0/24\"]\n[[location]]\nslug = \"a\"\nnetworks = [\"198.51.100.0/24\"]\n"
        ));
        assert!(got.contains("`a` is used twice"), "{got}");
        let got = refused(&format!(
            "{BASE}[[client]]\nname = \"Home\"\nmatch = [\"192.0.2.9\"]\n[[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\"]\n"
        ));
        assert!(got.contains("also the name of a device"), "{got}");
    }

    #[test]
    fn dsc_908_overlapping_networks_name_both_locations() {
        let got = refused(&format!(
            "{BASE}[[location]]\nslug = \"a\"\nnetworks = [\"192.0.2.0/24\"]\n[[location]]\nslug = \"b\"\nnetworks = [\"192.0.2.128/25\"]\n"
        ));
        assert!(
            got.contains("location[1].networks") && got.contains("overlaps location `a`"),
            "{got}"
        );
        // Two disjoint networks, and one location with two overlapping ones, are fine.
        cfg(&format!(
            "{BASE}[[location]]\nslug = \"a\"\nnetworks = [\"192.0.2.0/24\", \"192.0.2.0/25\"]\n[[location]]\nslug = \"b\"\nnetworks = [\"198.51.100.0/24\", \"2001:db8::/32\"]\n"
        ));
    }

    #[test]
    fn dsc_910_a_client_location_names_a_configured_location() {
        let got = refused(&format!(
            "{BASE}[[client]]\nname = \"laptop\"\nmatch = [\"192.0.2.9\"]\nlocation = \"lab\"\n"
        ));
        assert!(
            got.contains("client[0].location") && got.contains("no location `lab`"),
            "{got}"
        );
        let c = cfg(&format!(
            "{BASE}[[location]]\nslug = \"lab\"\nnetworks = [\"198.51.100.0/24\"]\n[[client]]\nname = \"laptop\"\nmatch = [\"192.0.2.9\"]\nlocation = \"lab\"\n"
        ));
        assert_eq!(
            c.client[0].location.as_ref().map(crate::SafeString::as_str),
            Some("lab")
        );
    }

    #[test]
    fn dsc_908_a_location_has_its_own_domain_without_the_global_one() {
        let c = cfg(
            "[[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\"]\ndomain = \"Example.net.\"\n",
        );
        assert_eq!(
            c.location[0].parent_domain(&c).as_deref(),
            Some("example.net")
        );
    }

    #[test]
    fn dsc_908_a_replica_gets_locations_and_older_sections_stay_unsent() {
        let c = cfg(&format!(
            "{BASE}[[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\"]\n"
        ));
        let shared = crate::shared::shared_part(&c);
        assert!(shared.get("location").is_some(), "{shared}");
        let none = crate::shared::shared_part(&Config::default());
        assert!(none.get("location").is_none(), "no table, no key: {none}");
        let merged = crate::shared::with_shared(&Config::default(), &shared).unwrap();
        assert_eq!(merged.location, c.location);
    }
}

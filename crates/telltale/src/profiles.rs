//! REQ: FLT-902 (T24.29, ADR-994, design 6.2) — what a filter profile's Source column and the
//! devices-and-networks picker show: a group's networks, router names and devices, and the
//! networks and devices that can be added, each with an icon, the keys it can be recognized by,
//! and a flag on a MAC that is a private Wi-Fi address (ADR-910).
//!
//! Computed on the server, so the profile list needs one call and the picker one more. Nothing
//! here is on the query path.

use std::collections::HashMap;
use std::net::IpAddr;

use telltale_api::categories_api::{ProfileDevices, ProfileKey, ProfileSource, mac_is_randomized};
use telltale_api::model::{DeviceIdentity, DhcpLease, NetworkInfo};
use telltale_config::{ClientConfig, Config, MatchKey};

/// The kinds of key a device can be recognized by.
fn key_of(raw: &str) -> Option<ProfileKey> {
    let raw = raw.trim();
    Some(match MatchKey::parse(raw).ok()? {
        MatchKey::Mac(_) => ProfileKey {
            kind: "mac".into(),
            value: raw.to_ascii_lowercase().replace('-', ":"),
            randomized: mac_is_randomized(raw),
        },
        MatchKey::Ip(_) | MatchKey::Cidr(_) => ProfileKey {
            kind: "ip".into(),
            value: raw.to_owned(),
            randomized: false,
        },
        MatchKey::ClientId(_) => ProfileKey {
            kind: "id".into(),
            value: raw.to_owned(),
            randomized: false,
        },
        MatchKey::Hostname(_) => ProfileKey {
            kind: "name".into(),
            value: raw.to_owned(),
            randomized: false,
        },
    })
}

/// A device class the UI draws an icon for: its identification (by an address it was seen at),
/// else the kind set on it, else `unknown`.
fn class_of(c: &ClientConfig, identities: &HashMap<String, DeviceIdentity>) -> String {
    for k in &c.match_keys {
        let ip = k.split('/').next().unwrap_or("");
        if let Some(i) = identities.get(ip)
            && i.available
            && i.class != "unknown"
        {
            return i.class.clone();
        }
    }
    c.kind
        .map_or_else(|| "unknown".to_owned(), |k| k.as_str().to_owned())
}

fn network_name(networks: &[NetworkInfo], cidr: &str) -> String {
    networks
        .iter()
        .find(|n| n.subnet == cidr)
        .map_or_else(|| cidr.to_owned(), |n| n.name.clone())
}

/// A group's configured sources: its networks, router names, and the devices that name it.
pub(crate) fn group_sources(
    cfg: &Config,
    networks: &[NetworkInfo],
    identities: &HashMap<String, DeviceIdentity>,
    group: &str,
    defined_in: &dyn Fn(&str) -> Option<String>,
) -> Vec<ProfileSource> {
    let mut out = Vec::new();
    let Some(g) = cfg.group.iter().find(|g| g.name.as_str() == group) else {
        return out;
    };
    for n in &g.networks {
        let id = n.to_string();
        out.push(ProfileSource {
            kind: "network".into(),
            label: network_name(networks, &id),
            id,
            icon: "network".into(),
            keys: Vec::new(),
            group: Some(group.to_owned()),
            configured: true,
            defined_in: None,
        });
    }
    for r in &g.router_names {
        out.push(ProfileSource {
            kind: "device".into(),
            label: r.to_string(),
            id: format!("hostname:{r}"),
            icon: "unknown".into(),
            keys: vec![ProfileKey {
                kind: "name".into(),
                value: format!("hostname:{r}"),
                randomized: false,
            }],
            group: Some(group.to_owned()),
            configured: true,
            defined_in: None,
        });
    }
    for c in cfg
        .client
        .iter()
        .filter(|c| c.groups.iter().any(|x| x.as_str() == group))
    {
        out.push(ProfileSource {
            kind: "device".into(),
            label: c.name.to_string(),
            id: c.name.to_string(),
            icon: class_of(c, identities),
            keys: c.match_keys.iter().filter_map(|k| key_of(k)).collect(),
            group: Some(group.to_owned()),
            configured: true,
            defined_in: defined_in(c.name.as_str()),
        });
    }
    out
}

/// The most specific group network holding `ip`, else `default`.
fn group_of_ip(cfg: &Config, ip: IpAddr) -> String {
    cfg.group
        .iter()
        .flat_map(|g| g.networks.iter().map(move |n| (g, n)))
        .filter(|(_, n)| n.contains(ip))
        .max_by_key(|(_, n)| n.prefix)
        .map_or_else(|| "default".to_owned(), |(g, _)| g.name.to_string())
}

/// The picker's data: the networks the Networks page names, and the configured and the seen
/// devices.
pub(crate) fn picker(
    cfg: &Config,
    networks: &[NetworkInfo],
    leases: &[DhcpLease],
    identities: &HashMap<String, DeviceIdentity>,
    defined_in: &dyn Fn(&str) -> Option<String>,
) -> ProfileDevices {
    let nets = networks
        .iter()
        .map(|n| ProfileSource {
            kind: "network".into(),
            label: n.name.clone(),
            id: n.subnet.clone(),
            icon: "network".into(),
            keys: Vec::new(),
            group: n.group.clone(),
            configured: false,
            defined_in: None,
        })
        .collect();
    let mut devices: Vec<ProfileSource> = Vec::new();
    let mut seen_macs: Vec<String> = Vec::new();
    let mut seen_ips: Vec<String> = Vec::new();
    for c in &cfg.client {
        let keys: Vec<ProfileKey> = c.match_keys.iter().filter_map(|k| key_of(k)).collect();
        for k in &keys {
            match k.kind.as_str() {
                "mac" => seen_macs.push(k.value.clone()),
                "ip" => seen_ips.push(k.value.split('/').next().unwrap_or("").to_owned()),
                _ => {}
            }
        }
        let group = c.groups.first().map(ToString::to_string).or_else(|| {
            keys.iter()
                .find(|k| k.kind == "ip")
                .and_then(|k| k.value.split('/').next()?.parse().ok())
                .map(|ip| group_of_ip(cfg, ip))
        });
        devices.push(ProfileSource {
            kind: "device".into(),
            label: c.name.to_string(),
            id: c.name.to_string(),
            icon: class_of(c, identities),
            keys,
            group,
            configured: true,
            defined_in: defined_in(c.name.as_str()),
        });
    }
    for l in leases.iter().filter(|l| !l.offline && l.source == "router") {
        let mac = l.mac.to_ascii_lowercase().replace('-', ":");
        if seen_macs.contains(&mac) || seen_ips.contains(&l.ip) {
            continue;
        }
        let mut keys = Vec::new();
        if let Some(k) = key_of(&mac) {
            keys.push(k);
        }
        keys.push(ProfileKey {
            kind: "ip".into(),
            value: l.ip.clone(),
            randomized: false,
        });
        let label = l
            .client_name
            .clone()
            .or_else(|| l.hostname.clone())
            .unwrap_or_else(|| l.ip.clone());
        let label_key = label.to_ascii_lowercase().replace([' ', '_'], "-");
        if !l.ip.is_empty()
            && l.hostname.is_some()
            && key_of(&format!("hostname:{label_key}")).is_some()
        {
            keys.push(ProfileKey {
                kind: "name".into(),
                value: format!("hostname:{label_key}"),
                randomized: false,
            });
        }
        let icon = identities
            .get(&l.ip)
            .filter(|i| i.available)
            .map_or_else(|| "unknown".to_owned(), |i| i.class.clone());
        let group = l.ip.parse().ok().map(|ip| group_of_ip(cfg, ip));
        devices.push(ProfileSource {
            kind: "device".into(),
            label,
            id: l.ip.clone(),
            icon,
            keys,
            group,
            configured: false,
            defined_in: None,
        });
    }
    ProfileDevices {
        networks: nets,
        devices,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> Config {
        telltale_config::Loader::new()
            .toml_str("t", toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config
    }

    fn lease(mac: &str, ip: &str, host: Option<&str>) -> DhcpLease {
        DhcpLease {
            mac: mac.to_owned(),
            ip: ip.to_owned(),
            hostname: host.map(str::to_owned),
            client_name: None,
            expires_unix_seconds: 0,
            source: "router".to_owned(),
            router: None,
            dns_name: None,
            offline: false,
            ipv6: Vec::new(),
        }
    }

    /// REQ: FLT-902 (ADR-910) — the picker marks a randomised MAC and offers the address and the
    /// router name as other keys; a configured device is not offered twice.
    #[test]
    fn flt_902_picker_marks_randomised_mac() {
        let c = cfg("[[group]]\nname = \"kids\"\nnetworks = [\"10.0.1.0/24\"]\n\
             [[client]]\nname = \"tablet\"\nmatch = [\"aa:bb:cc:00:00:01\"]\ngroups = [\"kids\"]\n");
        let leases = [
            lease("da:a1:19:00:00:01", "10.0.1.20", Some("Maya iPad")),
            lease("b8:27:eb:00:00:09", "10.0.0.30", None),
            lease("aa:bb:cc:00:00:01", "10.0.1.21", Some("tablet")),
        ];
        let p = picker(&c, &[], &leases, &HashMap::new(), &|_| None);
        let by = |id: &str| p.devices.iter().find(|d| d.id == id).unwrap();
        // The configured device is there once, by name.
        assert_eq!(p.devices.iter().filter(|d| d.label == "tablet").count(), 1);
        let ipad = by("10.0.1.20");
        assert_eq!(ipad.group.as_deref(), Some("kids"));
        let mac = ipad.keys.iter().find(|k| k.kind == "mac").unwrap();
        assert!(mac.randomized);
        assert!(ipad.keys.iter().any(|k| k.kind == "ip" && !k.randomized));
        assert!(ipad.keys.iter().any(|k| k.kind == "name"));
        let pi = by("10.0.0.30");
        assert!(!pi.keys.iter().find(|k| k.kind == "mac").unwrap().randomized);
        assert_eq!(pi.group.as_deref(), Some("default"));
    }

    /// REQ: FLT-902 — a group's sources are its networks, router names and the devices that
    /// name it, and it is computed from the one configuration.
    #[test]
    fn flt_902_group_sources_list_networks_names_and_devices() {
        let c = cfg(
            "[[group]]\nname = \"kids\"\nnetworks = [\"10.0.1.0/24\"]\nrouter_names = [\"kitchen-tablet\"]\n\
             [[client]]\nname = \"tablet\"\nmatch = [\"da:a1:19:00:00:01\"]\ngroups = [\"kids\"]\n\
             [[client]]\nname = \"tv\"\nmatch = [\"10.0.9.9\"]\n",
        );
        let s = group_sources(&c, &[], &HashMap::new(), "kids", &|_| Some("api".into()));
        let kinds: Vec<(&str, &str)> = s
            .iter()
            .map(|x| (x.kind.as_str(), x.label.as_str()))
            .collect();
        assert_eq!(
            kinds,
            [
                ("network", "10.0.1.0/24"),
                ("device", "kitchen-tablet"),
                ("device", "tablet")
            ]
        );
        assert!(s[2].keys[0].randomized);
        assert_eq!(s[2].defined_in.as_deref(), Some("api"));
    }
}

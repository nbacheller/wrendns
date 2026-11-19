//! Read-only sources for the inventory (ADR-910, DSC-001). Each one turns what the process
//! already holds, or what the kernel's neighbour table says, into observations. Nothing here
//! sends a packet or walks a range (ADR-907).

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use telltale_net::Neighbor;

use crate::devices::Leases;
use crate::routers::HaDevice;

use super::inventory::{NameKind, Observation, Source};

/// An IPv4 subnet from `a.b.c.d/nn` (the `[[discovery.subnet]]` form, T25.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ipv4Subnet {
    net: u32,
    mask: u32,
}

impl Ipv4Subnet {
    /// Parses `a.b.c.d/nn`. `None` for anything else.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = s.trim().split_once('/')?;
        let addr: Ipv4Addr = addr.parse().ok()?;
        let prefix: u32 = prefix.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        let mask = u32::MAX
            .checked_shl(32u32.checked_sub(prefix)?)
            .unwrap_or(0);
        Some(Self {
            net: u32::from(addr) & mask,
            mask,
        })
    }

    /// Whether `ip` lies inside the subnet.
    pub(crate) fn contains(self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask) == self.net
    }
}

/// Container, bridge and overlay interfaces, whose neighbours are not the LAN's devices
/// (ADR-910).
pub(crate) fn is_container_or_overlay(name: &str) -> bool {
    const PREFIXES: [&str; 12] = [
        "docker",
        "br-",
        "veth",
        "cni",
        "flannel",
        "cali",
        "vxlan",
        "tun",
        "tap",
        "wg",
        "tailscale",
        "zt",
    ];
    name == "lo" || PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Interface index → name, from `/sys/class/net/*/ifindex` under `root`.
pub(crate) fn ifindex_names(root: &Path) -> HashMap<u32, String> {
    let mut out = HashMap::new();
    let Ok(dir) = fs::read_dir(root) else {
        return out;
    };
    for entry in dir.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let idx = fs::read_to_string(entry.path().join("ifindex"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        if let Some(idx) = idx {
            out.insert(idx, name);
        }
    }
    out
}

/// Parses `aa:bb:cc:dd:ee:ff` (or with `-`), case-insensitively.
pub(crate) fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0usize;
    for part in s.trim().split([':', '-']) {
        let slot = out.get_mut(n)?;
        *slot = u8::from_str_radix(part, 16).ok()?;
        if part.len() != 2 {
            return None;
        }
        n = n.checked_add(1)?;
    }
    (n == 6).then_some(out)
}

/// The neighbour table as observations: IPv4 only, in REACHABLE, STALE, DELAY or PROBE, inside
/// a configured subnet, and not on a container or overlay interface (DSC-008, ADR-910).
pub(crate) fn neighbour_observations(
    neigh: &[Neighbor],
    names: &HashMap<u32, String>,
    subnets: &[Ipv4Subnet],
    now: u64,
) -> Vec<Observation> {
    const USABLE: [u16; 4] = [0x02, 0x04, 0x08, 0x10];
    let mut out = Vec::new();
    for n in neigh {
        if !USABLE.contains(&n.state) || n.mac == [0; 6] {
            continue;
        }
        let IpAddr::V4(v4) = n.ip else {
            continue;
        };
        if !subnets.iter().any(|s| s.contains(v4)) {
            continue;
        }
        // Fails closed: a row whose interface has no known name (the table could not be read, or
        // the index is missing) is not counted (ADR-910).
        let Some(name) = names.get(&n.ifindex) else {
            continue;
        };
        if is_container_or_overlay(name) {
            continue;
        }
        let mut o = Observation::new(Source::Neighbor, now);
        o.mac = Some(n.mac);
        o.ip = Some(n.ip);
        out.push(o);
    }
    out
}

/// A router's or mDNS's lease view as observations. `Source::Router` gives class 1 bindings
/// from the routers' answers; `Source::Mdns` gives names and addresses from announcements.
pub(crate) fn lease_observations(view: &Leases, source: Source, now: u64) -> Vec<Observation> {
    let name_kind = match source {
        Source::Mdns => NameKind::Mdns,
        _ => NameKind::RouterAlias,
    };
    view.values()
        // REQ: T8.2 (ADR-166) — an offline client is not a current answer: it gives no address
        // binding and its `last_seen` isn't refreshed (ADR-910, ADR-924).
        .filter(|lease| !lease.offline)
        // REQ: DSC-008 — a lease past its expiry is not a current answer (ADR-902).
        .filter(|lease| lease.expires == 0 || lease.expires >= now)
        .map(|lease| {
            let mut o = Observation::new(source, now);
            o.mac = parse_mac(&lease.mac);
            o.ip = Some(IpAddr::V4(lease.ip));
            o.name = lease.hostname.clone().map(|h| (name_kind, h));
            o.name_origin.clone_from(&lease.router);
            o
        })
        .collect()
}

/// Home Assistant's named devices as observations: one per MAC, with the tracker's address
/// when Home Assistant has one. A name a person gave is `HaUser`; an integration's is
/// `HaIntegration` (ADR-910 ranks).
pub(crate) fn ha_observations(
    devices: &[HaDevice],
    trackers: &HashMap<String, Ipv4Addr>,
    now: u64,
) -> Vec<Observation> {
    let mut out = Vec::new();
    for d in devices {
        let kind = if d.curated {
            NameKind::HaUser
        } else {
            NameKind::HaIntegration
        };
        for mac_text in &d.macs {
            let Some(mac) = parse_mac(mac_text) else {
                continue;
            };
            let mut o = Observation::new(Source::HomeAssistant, now);
            o.mac = Some(mac);
            o.ip = trackers.get(mac_text).copied().map(IpAddr::V4);
            o.name = Some((kind, d.name.clone()));
            // REQ: DSC-903 (R4) — Home Assistant's device id joins a device's MACs.
            o.hint_mut().device_key.clone_from(&d.id);
            out.push(o);
        }
    }
    out
}

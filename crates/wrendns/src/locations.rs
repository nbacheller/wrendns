// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: DSC-908, DSC-909, DSC-910, DSC-911, DSC-916 (T36.10a; ADR-1081, ADR-1096) - locations as the
//! node uses them: the configured `[[location]]` table compiled into a [`Plan`], each location's
//! networks resolved (CIDRs as written, `vlan:<id>` through the router network reads and this
//! node's own VLAN interfaces, never the device inventory, DSC-901) into a [`Resolved`] map from address to
//! location, and the 7-day count of queries that still used a location's flat names.
//!
//! Everything here runs off the query path, in the 10-second device-table task
//! (`device_dns::run`); the query path only reads the finished snapshot.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};

use wrendns_config::{Cidr, Config, LocationNet, LocationVisibility};

use crate::own_networks::OwnNetwork;
use crate::routers::Network;

/// One location, as the node composes names for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Loc {
    pub(crate) slug: String,
    pub(crate) label: Option<String>,
    /// The parent domain (the location's own, else `[local] device_domain`), lowercase.
    pub(crate) parent: String,
    pub(crate) private: bool,
    /// Keep answering the old flat names (DSC-916).
    pub(crate) flat: bool,
    pub(crate) cidrs: Vec<Cidr>,
    pub(crate) vlans: Vec<u16>,
    pub(crate) nodes: Vec<String>,
}

impl Loc {
    /// The subtree this node owns: `<slug>.<parent>`.
    pub(crate) fn apex(&self) -> String {
        format!("{}.{}", self.slug, self.parent)
    }
}

/// The `[[location]]` table, compiled. Empty without locations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) locs: Vec<Loc>,
}

impl Plan {
    pub(crate) fn from_config(cfg: &Config) -> Self {
        let locs = cfg
            .location
            .iter()
            .filter_map(|l| {
                let parent = l.parent_domain(cfg)?;
                let mut cidrs = Vec::new();
                let mut vlans = Vec::new();
                for n in &l.networks {
                    match wrendns_config::location::parse_network(n.as_str()) {
                        Ok(LocationNet::Cidr(c)) => cidrs.push(c.network()),
                        Ok(LocationNet::Vlan(v)) => vlans.push(v),
                        Err(_) => {}
                    }
                }
                Some(Loc {
                    slug: l.slug.to_string(),
                    label: l.label.as_ref().map(ToString::to_string),
                    parent,
                    private: l.visibility == LocationVisibility::Private,
                    flat: l.flat_names,
                    cidrs,
                    vlans,
                    nodes: l.nodes.iter().map(ToString::to_string).collect(),
                })
            })
            .collect();
        Self { locs }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.locs.is_empty()
    }

    /// Whether any location names a VLAN (so the router and interface reads matter).
    pub(crate) fn has_vlans(&self) -> bool {
        self.locs.iter().any(|l| !l.vlans.is_empty())
    }

    pub(crate) fn index_of(&self, slug: &str) -> Option<usize> {
        self.locs.iter().position(|l| l.slug == slug)
    }
}

/// A VLAN entry no read reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unresolved {
    pub(crate) location: usize,
    pub(crate) vlan: u16,
}

/// Two locations that claim the same network: neither applies until it is fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetConflict {
    pub(crate) network: Cidr,
    pub(crate) locations: [usize; 2],
}

/// Each location's networks, resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Resolved {
    /// `(network, location index)`, longest prefix first: the more specific network wins.
    entries: Vec<(Cidr, usize)>,
    /// Every network of each location (the private rule tests a client's address against it).
    pub(crate) nets: Vec<Vec<Cidr>>,
    pub(crate) unresolved: Vec<Unresolved>,
    pub(crate) conflicts: Vec<NetConflict>,
    /// What each `vlan:<id>` entry resolved to: `(location index, VLAN, networks)`.
    pub(crate) vlan_nets: Vec<(usize, u16, Vec<Cidr>)>,
}

fn net_of(subnet: Ipv4Addr, prefix: u8) -> Option<Cidr> {
    Cidr::parse(&format!("{subnet}/{prefix}"))
        .ok()
        .map(|c| c.network())
}

impl Resolved {
    /// REQ: DSC-909 - resolves each location's `networks`: its CIDRs as written, and each
    /// `vlan:<id>` to the subnets the routers (and this node's own VLAN interfaces) report for that
    /// VLAN. A VLAN nothing reports matches nothing (`unresolved`); two locations claiming the same
    /// network make a conflict and neither applies.
    pub(crate) fn resolve(plan: &Plan, routers: &[Network], own: &[OwnNetwork]) -> Self {
        let mut per: Vec<Vec<Cidr>> = Vec::with_capacity(plan.locs.len());
        let mut unresolved = Vec::new();
        let mut vlan_nets: Vec<(usize, u16, Vec<Cidr>)> = Vec::new();
        for (i, l) in plan.locs.iter().enumerate() {
            let mut nets: Vec<Cidr> = l.cidrs.clone();
            for v in &l.vlans {
                let before = nets.len();
                let from_routers = routers
                    .iter()
                    .filter(|n| n.vlan == Some(*v))
                    .filter_map(|n| net_of(n.subnet, n.prefix));
                let from_own = own
                    .iter()
                    .filter(|n| n.vlan == Some(*v))
                    .filter_map(|n| net_of(n.subnet, n.prefix));
                nets.extend(from_routers.chain(from_own));
                vlan_nets.push((i, *v, nets[before..].to_vec()));
                if nets.len() == before {
                    unresolved.push(Unresolved {
                        location: i,
                        vlan: *v,
                    });
                }
            }
            nets.sort_by_key(|c| (c.addr, c.prefix));
            nets.dedup();
            per.push(nets);
        }
        // Equal networks in two locations conflict.
        let mut conflicts: Vec<NetConflict> = Vec::new();
        for (a, na) in per.iter().enumerate() {
            for (b, nb) in per.iter().enumerate().skip(a + 1) {
                for c in na.iter().filter(|c| nb.contains(c)) {
                    conflicts.push(NetConflict {
                        network: *c,
                        locations: [a, b],
                    });
                }
            }
        }
        let mut entries: Vec<(Cidr, usize)> = Vec::new();
        for (i, nets) in per.iter().enumerate() {
            for c in nets {
                if !conflicts.iter().any(|k| k.network == *c) {
                    entries.push((*c, i));
                }
            }
        }
        entries.sort_by_key(|(c, i)| (std::cmp::Reverse(c.prefix), *i));
        Self {
            entries,
            nets: per,
            unresolved,
            conflicts,
            vlan_nets,
        }
    }

    /// The location whose network holds `ip`: the most specific one.
    pub(crate) fn locate(&self, ip: IpAddr) -> Option<usize> {
        self.entries
            .iter()
            .find(|(c, _)| c.contains(ip))
            .map(|(_, i)| *i)
    }
}

/// REQ: DSC-916 (T36.10a) - how many queries a location's flat names answered over the last 7
/// days: eight day slots, each stamped with its day number, so a slot is reused once its day is
/// more than a week old. One atomic add on the query path, no lock; kept in memory (a restart
/// starts the count again).
#[derive(Debug, Default)]
pub(crate) struct FlatUse {
    slots: [(AtomicU64, AtomicU64); 8],
}

const DAY: u64 = 86_400;

impl FlatUse {
    /// One query answered from a flat name, at `now` (Unix seconds).
    pub(crate) fn hit(&self, now: u64) {
        let day = now / DAY;
        // Both fields of the slot are relaxed: the count is a statistic, and a rollover racing a
        // hit may lose one.
        let (d, n) = &self.slots[(day % 8) as usize];
        if d.load(Ordering::Relaxed) != day {
            d.store(day, Ordering::Relaxed);
            n.store(0, Ordering::Relaxed);
        }
        n.fetch_add(1, Ordering::Relaxed);
    }

    /// Queries in the seven days up to and including `now`'s day.
    pub(crate) fn last_7_days(&self, now: u64) -> u64 {
        let today = now / DAY;
        self.slots
            .iter()
            .filter(|(d, _)| {
                let d = d.load(Ordering::Relaxed);
                d <= today && today - d < 7
            })
            .map(|(_, n)| n.load(Ordering::Relaxed))
            .sum()
    }
}

/// REQ: DSC-913 (T36.10a) - the locations as `GET /api/v1/locations` shows them: the configured
/// table with, from the node's current device table, each location's resolved networks, devices
/// (the names they answer as), collisions and flat-name use. `file` is the configuration the files
/// alone give, to say where a location comes from.
#[allow(clippy::too_many_lines)] // one entry per location, field by field
pub(crate) fn list(
    cfg: &Config,
    file: &Config,
    names: &crate::device_dns::DeviceNames,
    now: u64,
) -> wrendns_api::model::LocationList {
    use wrendns_api::model::{
        LocationCollision, LocationDevice, LocationInfo, LocationList, LocationNetworkInfo,
    };
    let plan = Plan::from_config(cfg);
    // The device table is rebuilt every 10 seconds: until it has seen this table, the device lists
    // are empty rather than another table's.
    let fresh = names.plan == plan;
    let resolved = if fresh {
        names.resolved.clone()
    } else {
        Resolved::resolve(&plan, &[], &[])
    };
    let slug_of = |i: Option<usize>| i.and_then(|i| plan.locs.get(i)).map(|l| l.slug.clone());
    let collision = |c: &crate::device_dns::Collision| LocationCollision {
        name: c.name.clone(),
        flat: c.flat,
        kept_address: c.kept.map(|a| a.to_string()),
        lost_address: c.lost.to_string(),
        lost_location: slug_of(c.lost_location),
    };
    let items = cfg
        .location
        .iter()
        .filter_map(|l| {
            let loc = plan.locs.iter().find(|p| p.slug == l.slug.as_str())?;
            let at = plan.index_of(l.slug.as_str())?;
            let networks = l
                .networks
                .iter()
                .map(|entry| {
                    let (resolved_nets, note): (Vec<Cidr>, Option<String>) =
                        match wrendns_config::location::parse_network(entry.as_str()) {
                            Ok(LocationNet::Cidr(c)) => (vec![c.network()], None),
                            Ok(LocationNet::Vlan(v)) => {
                                let nets = resolved
                                    .vlan_nets
                                    .iter()
                                    .find(|(li, vv, _)| *li == at && *vv == v)
                                    .map(|(_, _, n)| n.clone())
                                    .unwrap_or_default();
                                let note =
                                    nets.is_empty().then(|| "no network reported".to_owned());
                                (nets, note)
                            }
                            Err(_) => (Vec::new(), None),
                        };
                    let clash = resolved_nets
                        .iter()
                        .any(|c| resolved.conflicts.iter().any(|k| k.network == *c));
                    LocationNetworkInfo {
                        entry: entry.to_string(),
                        resolved: resolved_nets.iter().map(ToString::to_string).collect(),
                        note: if clash {
                            Some("conflict".to_owned())
                        } else {
                            note
                        },
                    }
                })
                .collect();
            let devices = if fresh {
                names
                    .named
                    .iter()
                    .filter(|n| n.loc == Some(at))
                    .map(|n| LocationDevice {
                        name: n.name.clone(),
                        address: n.ip.to_string(),
                        addresses_v6: n.v6.iter().map(ToString::to_string).collect(),
                        flat_name: n.flat.clone(),
                        pinned: n.pinned,
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let collisions = if fresh {
                names
                    .collisions
                    .iter()
                    .filter(|c| c.lost_location == Some(at))
                    .map(collision)
                    .collect()
            } else {
                Vec::new()
            };
            let uses = fresh
                .then(|| names.locs.get(at))
                .flatten()
                .map_or(0, |t| t.flat_use.last_7_days(now));
            Some(LocationInfo {
                slug: l.slug.to_string(),
                label: l.label.as_ref().map(ToString::to_string),
                source: if file.location.iter().any(|f| f.slug == l.slug) {
                    "file"
                } else {
                    "api"
                }
                .to_owned(),
                networks,
                nodes: l.nodes.iter().map(ToString::to_string).collect(),
                domain: loc.parent.clone(),
                visibility: if loc.private { "private" } else { "shared" }.to_owned(),
                flat_names: loc.flat,
                flat_name_uses_7d: uses,
                devices,
                collisions,
            })
        })
        .collect();
    LocationList {
        items,
        conflicts: resolved
            .conflicts
            .iter()
            .map(|k| {
                format!(
                    "{} is claimed by locations `{}` and `{}`: neither applies until one is changed",
                    k.network, plan.locs[k.locations[0]].slug, plan.locs[k.locations[1]].slug
                )
            })
            .collect(),
        collisions: if fresh {
            names
                .collisions
                .iter()
                .filter(|c| c.lost_location.is_none())
                .map(collision)
                .collect()
        } else {
            Vec::new()
        },
    }
}

/// REQ: DSC-910 (T36.10a) - the location a configured device is in now: the one it is pinned to,
/// else the one its exact IPv4 address gives it in the current device table. `(slug, display name,
/// pinned)`; `None` when it is on no location's network.
pub(crate) fn client_location(
    c: &wrendns_config::ClientConfig,
    names: &crate::device_dns::DeviceNames,
) -> Option<(String, String, bool)> {
    let display = |slug: &str| {
        names
            .plan
            .locs
            .iter()
            .find(|l| l.slug == slug)
            .and_then(|l| l.label.clone())
            .unwrap_or_else(|| slug.to_owned())
    };
    if let Some(pin) = &c.location {
        return Some((pin.to_string(), display(pin.as_str()), true));
    }
    c.match_keys.iter().find_map(|k| {
        let k = k.trim();
        let k = k.strip_suffix("/32").unwrap_or(k);
        let ip: Ipv4Addr = k.parse().ok()?;
        let slug = names
            .named
            .iter()
            .find(|n| n.ip == ip)
            .and_then(|n| n.loc)
            .and_then(|i| names.plan.locs.get(i))?
            .slug
            .clone();
        Some((slug.clone(), display(&slug), false))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> Config {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap_or_else(|e| panic!("{e:?}"))
            .config
    }

    fn net(name: &str, vlan: Option<u16>, subnet: [u8; 4], prefix: u8) -> Network {
        Network {
            router: "udm".into(),
            name: name.into(),
            vlan,
            subnet: Ipv4Addr::from(subnet),
            prefix,
            gateway: None,
            dhcp_start: None,
            dhcp_stop: None,
            domain: None,
            purpose: None,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // REQ: DSC-909 - a device's location comes from the configured networks; a VLAN entry is read
    // from the routers; the more specific network wins; an address in none has no location.
    #[test]
    fn dsc_909_resolve_cidrs_and_vlans_with_the_most_specific_winning() {
        let c = cfg("[local]\ndevice_domain = \"home.arpa\"\n\
             [[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\", \"vlan:30\"]\n\
             [[location]]\nslug = \"lab\"\nnetworks = [\"198.51.100.0/24\", \"vlan:99\"]\n");
        let plan = Plan::from_config(&c);
        let routers = [net("iot", Some(30), [203, 0, 113, 0], 24)];
        let r = Resolved::resolve(&plan, &routers, &[]);
        assert_eq!(r.locate(ip("192.0.2.9")), Some(0));
        assert_eq!(
            r.locate(ip("203.0.113.40")),
            Some(0),
            "VLAN 30 from the router read"
        );
        assert_eq!(r.locate(ip("198.51.100.7")), Some(1));
        assert_eq!(r.locate(ip("10.0.0.1")), None);
        assert_eq!(
            r.unresolved,
            vec![Unresolved {
                location: 1,
                vlan: 99
            }],
            "VLAN 99 is reported as no network"
        );
    }

    #[test]
    fn dsc_909_a_vlan_subnet_inside_another_location_is_the_more_specific_one() {
        let c = cfg("[local]\ndevice_domain = \"home.arpa\"\n\
             [[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\"]\n\
             [[location]]\nslug = \"lab\"\nnetworks = [\"vlan:50\"]\n");
        let plan = Plan::from_config(&c);
        let routers = [net("lab", Some(50), [192, 0, 2, 128], 25)];
        let r = Resolved::resolve(&plan, &routers, &[]);
        assert_eq!(r.locate(ip("192.0.2.200")), Some(1));
        assert_eq!(r.locate(ip("192.0.2.20")), Some(0));
        assert_eq!(r.conflicts.len(), 0);
    }

    // REQ: DSC-909 - the same network claimed by two locations (a VLAN that resolves to another
    // location's CIDR) applies to neither, and is reported.
    #[test]
    fn dsc_909_equal_networks_are_a_conflict_and_neither_applies() {
        let c = cfg("[local]\ndevice_domain = \"home.arpa\"\n\
             [[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\"]\n\
             [[location]]\nslug = \"lab\"\nnetworks = [\"vlan:50\"]\n");
        let plan = Plan::from_config(&c);
        let routers = [net("lab", Some(50), [192, 0, 2, 0], 24)];
        let r = Resolved::resolve(&plan, &routers, &[]);
        assert_eq!(r.locate(ip("192.0.2.20")), None);
        assert_eq!(r.conflicts.len(), 1);
        assert_eq!(r.conflicts[0].locations, [0, 1]);
    }

    #[test]
    fn dsc_916_the_flat_use_count_covers_seven_days() {
        let u = FlatUse::default();
        let day = |n: u64| n * DAY + 100;
        u.hit(day(10));
        u.hit(day(10));
        u.hit(day(12));
        assert_eq!(u.last_7_days(day(12)), 3);
        assert_eq!(u.last_7_days(day(16)), 3);
        assert_eq!(u.last_7_days(day(17)), 1, "day 10 is more than a week old");
        assert_eq!(u.last_7_days(day(19)), 0);
        // A slot is reused after a week and starts again.
        u.hit(day(18));
        assert_eq!(u.last_7_days(day(18)), 2, "day 12 and the new day 18");
    }
}

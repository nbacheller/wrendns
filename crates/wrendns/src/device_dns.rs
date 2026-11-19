//! REQ: DNS-023 (T22.1; ADR-901) — the devices WrenDNS knows by name answer in DNS, as
//! `<name>.<[local] device_domain>` with a PTR for the address, like a router that registers
//! its DHCP clients' names. WrenDNS still doesn't run DHCP (ADR-091): the names come from
//! named devices with one address, the routers' DHCP clients and Home Assistant (`[[router]]`),
//! the other nodes' routers (CLU-002), and with `device_mdns` the names devices announce.
//!
//! Built off the query path every few seconds into a [`LocalData`] that the pipeline loads
//! without locking (02 §3). Configured records, hosts files, and a zone's own records win;
//! the table only fills the gaps.
//!
//! When two devices' names make the same label, one keeps it (ADR-901): a named device,
//! then a router's or Home Assistant's name, then an mDNS name, then the lowest address. The
//! others get neither an A record nor a PTR; collisions are counted in the log line that
//! reports each change.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Weak};
use std::time::Duration;

use wrendns_policy::{ClientTable, LocalData, device_label};
use tracing::info;

use crate::devices::Leases;

/// How often the table is rebuilt (it changes when a router is read, every few minutes).
const EVERY: Duration = Duration::from_secs(10);

/// The policy the router names were last given to (held as a `Weak`, see [`run`]), and the names.
type GivenRouterNames = (Weak<crate::pipeline::Dynamic>, HashMap<IpAddr, Arc<str>>);

/// `[local] device_domain`, `device_ttl`, `device_mdns`, as the pipeline's policy holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Settings {
    /// Lowercase, without a trailing dot.
    pub(crate) domain: String,
    pub(crate) ttl: u32,
    pub(crate) mdns: bool,
}

impl Settings {
    pub(crate) fn from_config(cfg: &wrendns_config::Config) -> Option<Self> {
        let d = cfg.local.device_domain.as_ref()?;
        let domain = d.trim().trim_end_matches('.').to_ascii_lowercase();
        (!domain.is_empty()).then(|| Self {
            domain,
            ttl: cfg.local.device_ttl.max(1),
            mdns: cfg.local.device_mdns && cfg.clients.mdns,
        })
    }
}

/// REQ: DNS-023 (T24.8, ADR-983) — one device that answers in DNS: its full name, its IPv4
/// address (the key the routers know it by) and the IPv6 addresses that answer AAAA and PTR for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Named {
    pub(crate) name: String,
    pub(crate) ip: Ipv4Addr,
    pub(crate) v6: Vec<Ipv6Addr>,
}

/// The table the pipeline answers from, and each address's name for the API.
#[derive(Debug, Default)]
pub(crate) struct DeviceNames {
    pub(crate) data: LocalData,
    /// Address → the full name it answers as.
    pub(crate) by_ip: HashMap<Ipv4Addr, String>,
}

/// Labels no device gets, whatever it calls itself (ADR-901): `wpad` and `isatap` are how
/// Windows finds a proxy and a tunnel, so a device named that could take over other machines'
/// traffic (dnsmasq and Windows DNS refuse them too); `localhost` is RFC 6761's.
const RESERVED: [&str; 3] = ["wpad", "isatap", "localhost"];

/// Where a candidate name came from (lower wins an address and a label).
const NAMED: u8 = 0;
const ROUTER: u8 = 1;
const MDNS: u8 = 2;

/// What the table is built from.
pub(crate) struct Inputs<'a> {
    pub(crate) clients: &'a ClientTable,
    /// This node's routers first, then the peers' (CLU-002).
    pub(crate) routers: [&'a Leases; 2],
    /// This node's mDNS names, then the peers'; empty unless `device_mdns`.
    pub(crate) mdns: [&'a Leases; 2],
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split([':', '-']);
    for b in &mut out {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// The devices to answer, sorted by name, and how many names collided.
pub(crate) fn names(inputs: &Inputs<'_>, domain: &str) -> (Vec<Named>, usize) {
    // Best name per address.
    let mut by_ip: HashMap<Ipv4Addr, (u8, String)> = HashMap::new();
    let mut offer = |ip: Ipv4Addr, rank: u8, name: &str| {
        let better = by_ip.get(&ip).is_none_or(|(r, _)| rank < *r);
        if better {
            by_ip.insert(ip, (rank, name.to_owned()));
        }
    };
    for (ip, c) in inputs.clients.exact_ips() {
        if let IpAddr::V4(v4) = ip {
            offer(v4, NAMED, &c.name);
        }
    }
    for table in inputs.routers {
        for l in table.values() {
            // REQ: T8.2 (ADR-166) — an offline client's last address may belong to a device no
            // router reports now, so its name isn't published (own and peer tables alike).
            if l.offline {
                continue;
            }
            // A device named in WrenDNS by its MAC keeps that name at its new address.
            let named = parse_mac(&l.mac).and_then(|m| inputs.clients.by_exact_mac(m));
            match (named, &l.hostname) {
                (Some(c), _) => offer(l.ip, NAMED, &c.name),
                (None, Some(h)) => offer(l.ip, ROUTER, h),
                (None, None) => {}
            }
        }
    }
    for table in inputs.mdns {
        for l in table.values() {
            if let Some(h) = &l.hostname {
                offer(l.ip, MDNS, h);
            }
        }
    }
    // REQ: DNS-023 (T24.8, ADR-983) — the IPv6 addresses the routers report for a device, by its
    // IPv4 address: this node's routers first, then the peers'; an offline client has none
    // (it publishes no name either, ADR-166).
    let mut v6_of: HashMap<Ipv4Addr, &[Ipv6Addr]> = HashMap::new();
    for table in inputs.routers {
        for l in table.values().filter(|l| !l.offline && !l.ipv6.is_empty()) {
            v6_of.entry(l.ip).or_insert(l.ipv6.as_slice());
        }
    }
    // Best address per label: rank, then the lowest address.
    let mut ranked: Vec<(u8, Ipv4Addr, String)> = by_ip
        .into_iter()
        .filter_map(|(ip, (rank, name))| Some((rank, ip, device_label(&name)?)))
        .filter(|(_, _, label)| !RESERVED.contains(&label.as_str()))
        .collect();
    ranked.sort_by(|a, b| (a.0, u32::from(a.1)).cmp(&(b.0, u32::from(b.1))));
    let mut taken: HashMap<String, Ipv4Addr> = HashMap::new();
    // One IPv6 address, one name: the better-ranked device keeps it (as for an IPv4 address).
    let mut v6_taken: HashSet<Ipv6Addr> = HashSet::new();
    let mut v6_kept: HashMap<Ipv4Addr, Vec<Ipv6Addr>> = HashMap::new();
    let mut collisions = 0;
    for (_, ip, label) in ranked {
        if let Some(kept) = taken.get(&label) {
            collisions += 1;
            tracing::debug!(%label, %kept, dropped = %ip, "device names: two devices share a name; the first keeps it");
            continue;
        }
        let v6: Vec<Ipv6Addr> = v6_of
            .get(&ip)
            .into_iter()
            .flat_map(|a| a.iter().copied())
            .filter(|a| crate::devices::usable_ipv6(a) && v6_taken.insert(*a))
            .collect();
        v6_kept.insert(ip, v6);
        taken.insert(label, ip);
    }
    let mut out: Vec<Named> = taken
        .into_iter()
        .map(|(label, ip)| Named {
            name: format!("{label}.{domain}"),
            ip,
            v6: v6_kept.remove(&ip).unwrap_or_default(),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    (out, collisions)
}

/// REQ: FLT-006 (T24.9, ADR-973) — the name each address's router gave it (the label form, so
/// `[[client]] match = ["hostname:kitchen-tablet"]` matches it), from this node's routers and the
/// peers' (CLU-002). Offline clients publish none, as their device names don't (ADR-166).
pub(crate) fn router_names(routers: [&Leases; 2]) -> HashMap<IpAddr, Arc<str>> {
    let mut out: HashMap<IpAddr, Arc<str>> = HashMap::new();
    for table in routers {
        for l in table.values() {
            if l.offline {
                continue;
            }
            let Some(label) = l.hostname.as_deref().and_then(device_label) else {
                continue;
            };
            out.entry(IpAddr::V4(l.ip))
                .or_insert_with(|| Arc::from(label.as_str()));
        }
    }
    out
}

/// The table for `names`.
pub(crate) fn build(names: &[Named], ttl: u32) -> DeviceNames {
    let addrs = names.iter().flat_map(|n| {
        std::iter::once((n.name.as_str(), IpAddr::V4(n.ip)))
            .chain(n.v6.iter().map(|a| (n.name.as_str(), IpAddr::V6(*a))))
    });
    DeviceNames {
        data: LocalData::from_device_names(addrs, ttl),
        by_ip: names.iter().map(|n| (n.ip, n.name.clone())).collect(),
    }
}

/// Rebuilds the table every [`EVERY`] until `stop`, storing it only when it changed. Reads the
/// settings from the live policy, so a reload that sets or clears the domain takes effect.
/// `mdns_listening` is the `[clients] mdns` the node started with: the listener starts once
/// (`restart_only_changes`), so device names follow mDNS only while it runs (REQ: DNS-023, H1).
pub(crate) async fn run(
    pipeline: Arc<crate::pipeline::Pipeline>,
    mdns_listening: bool,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut last: Option<(Settings, Vec<Named>)> = None;
    // REQ: FLT-006 (T24.9) — the router names last given to the policy in force (a reload makes
    // a new one, so the names are given again to it). The policy is held as a `Weak`: its
    // allocation stays reserved while it is remembered, so a new policy can't reuse its address.
    let mut last_router_names: Option<GivenRouterNames> = None;
    let mut tick = tokio::time::interval(EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = tick.tick() => {}
        }
        let state = pipeline.current();
        let routers = pipeline.router_leases.load();
        let peers = pipeline.peer_names.load();
        let names_now = router_names([&routers, &peers.routers]);
        let current_policy = Arc::downgrade(&state);
        let already_given = last_router_names
            .as_ref()
            .is_some_and(|(id, n)| id.ptr_eq(&current_policy) && *n == names_now);
        if !already_given {
            state.policy.clients.set_router_names(names_now.clone());
            last_router_names = Some((current_policy, names_now));
        }
        let Some(mut settings) = state.policy.device_dns.clone() else {
            if last.take().is_some() {
                pipeline.device_names.store(Arc::default());
                info!("device names in DNS: off");
            }
            continue;
        };
        settings.mdns &= mdns_listening;
        let mdns = pipeline.mdns_names.load();
        let empty = Leases::new();
        let inputs = Inputs {
            clients: &state.policy.clients,
            routers: [&routers, &peers.routers],
            mdns: if settings.mdns {
                [&mdns, &peers.mdns]
            } else {
                [&empty, &empty]
            },
        };
        let (names, collisions) = names(&inputs, &settings.domain);
        if last
            .as_ref()
            .is_some_and(|(s, n)| *s == settings && *n == names)
        {
            continue;
        }
        info!(
            domain = %settings.domain,
            names = names.len(),
            collisions,
            "device names in DNS: updated"
        );
        pipeline
            .device_names
            .store(Arc::new(build(&names, settings.ttl)));
        last = Some((settings, names));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::Lease;

    fn lease(ip: [u8; 4], mac: &str, name: Option<&str>) -> (Ipv4Addr, Lease) {
        let ip = Ipv4Addr::from(ip);
        (
            ip,
            Lease {
                mac: mac.into(),
                ip,
                hostname: name.map(Into::into),
                expires: 0,
                router: Some("udm".into()),
                offline: false,
                ipv6: Vec::new(),
            },
        )
    }

    /// `(name, IPv4 address)` of each device.
    fn pairs(got: &[Named]) -> Vec<(String, Ipv4Addr)> {
        got.iter().map(|n| (n.name.clone(), n.ip)).collect()
    }

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn cfg(toml: &str) -> wrendns_config::Config {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config
    }

    fn table(toml: &str) -> ClientTable {
        ClientTable::from_config(&cfg(toml))
    }

    /// REQ: DNS-023 (T22.1) — names from every source, best first: a device named in
    /// WrenDNS (by address, or by MAC at whatever address it has now), then the router's,
    /// then mDNS; one address per name, the lowest on a collision; unusable and reserved
    /// names (`wpad`, `isatap`) skipped.
    #[test]
    fn dns_023_names_from_every_source() {
        let clients = table(
            "[[client]]\nname = \"NAS\"\nmatch = [\"192.0.2.5\"]\n\
             [[client]]\nname = \"Dad's laptop\"\nmatch = [\"aa:bb:cc:00:00:07\"]\n\
             [[client]]\nname = \"IoT VLAN\"\nmatch = [\"192.168.20.0/24\"]\n",
        );
        let routers: Leases = [
            lease([192, 0, 2, 5], "aa:bb:cc:00:00:05", Some("diskstation")),
            lease([192, 0, 2, 7], "AA:BB:CC:00:00:07", Some("macbook-pro")),
            lease(
                [192, 0, 2, 21],
                "aa:bb:cc:00:00:21",
                Some("Kitchen Tablet"),
            ),
            lease([192, 0, 2, 30], "aa:bb:cc:00:00:30", Some("android")),
            lease([192, 0, 2, 31], "aa:bb:cc:00:00:31", Some("Android")),
            lease([192, 168, 20, 9], "aa:bb:cc:00:00:99", Some("shelly-1")),
            lease([192, 0, 2, 40], "aa:bb:cc:00:00:40", Some("***")),
            lease([192, 0, 2, 41], "aa:bb:cc:00:00:41", None),
            lease([192, 0, 2, 42], "aa:bb:cc:00:00:42", Some("WPAD")),
            lease([192, 0, 2, 43], "aa:bb:cc:00:00:43", Some("isatap")),
        ]
        .into();
        let peers: Leases = [lease([192, 0, 2, 50], "", Some("peer-printer"))].into();
        let mdns: Leases = [
            lease([192, 0, 2, 21], "", Some("kitchen-homepod")),
            lease([192, 0, 2, 60], "", Some("brw123")),
        ]
        .into();
        let empty = Leases::new();
        let inputs = Inputs {
            clients: &clients,
            routers: [&routers, &peers],
            mdns: [&mdns, &empty],
        };
        let (got, collisions) = names(&inputs, "home.arpa");
        let ip = |d: [u8; 4]| Ipv4Addr::from(d);
        assert_eq!(
            pairs(&got),
            vec![
                ("android.home.arpa".to_owned(), ip([192, 0, 2, 30])),
                ("brw123.home.arpa".to_owned(), ip([192, 0, 2, 60])),
                ("dads-laptop.home.arpa".to_owned(), ip([192, 0, 2, 7])),
                (
                    "kitchen-tablet.home.arpa".to_owned(),
                    ip([192, 0, 2, 21])
                ),
                ("nas.home.arpa".to_owned(), ip([192, 0, 2, 5])),
                ("peer-printer.home.arpa".to_owned(), ip([192, 0, 2, 50])),
                ("shelly-1.home.arpa".to_owned(), ip([192, 168, 20, 9])),
            ]
        );
        assert_eq!(
            collisions, 1,
            "two Androids: the lower address keeps the name"
        );
    }

    /// REQ: T8.2 (ADR-166) — an offline client (own or peer router) publishes no name at its
    /// last address; a connected one at the same address does.
    #[test]
    fn t8_2_offline_clients_publish_no_name() {
        let clients = table("");
        let gone = |ip: [u8; 4], mac: &str, name: &str| {
            let mut l = lease(ip, mac, Some(name));
            l.1.offline = true;
            l
        };
        let own: Leases = [gone([192, 0, 2, 53], "aa:bb:cc:00:00:53", "old-ipad")].into();
        let peer: Leases = [gone([192, 0, 2, 54], "aa:bb:cc:00:00:54", "gone-tv")].into();
        let empty = Leases::new();
        let inputs = Inputs {
            clients: &clients,
            routers: [&own, &peer],
            mdns: [&empty, &empty],
        };
        let (got, _) = names(&inputs, "home.arpa");
        assert!(got.is_empty(), "offline names are not published: {got:?}");
        let connected: Leases =
            [lease([192, 0, 2, 53], "aa:bb:cc:00:00:53", Some("ipad"))].into();
        let inputs = Inputs {
            clients: &clients,
            routers: [&connected, &empty],
            mdns: [&empty, &empty],
        };
        let (got, _) = names(&inputs, "home.arpa");
        assert_eq!(
            pairs(&got),
            vec![("ipad.home.arpa".to_owned(), Ipv4Addr::new(192, 0, 2, 53))]
        );
    }

    /// REQ: FLT-006 (T24.9, ADR-973) — a router's name for a device is its label, from this node's
    /// routers first, then the peers'; an offline client gives none, and a name that isn't
    /// usable as a label gives none.
    #[test]
    fn flt_006_router_names_from_leases() {
        let own: Leases = [
            lease(
                [192, 0, 2, 21],
                "aa:bb:cc:00:00:21",
                Some("Kitchen Tablet"),
            ),
            lease([192, 0, 2, 22], "aa:bb:cc:00:00:22", Some("***")),
            lease([192, 0, 2, 23], "aa:bb:cc:00:00:23", None),
        ]
        .into();
        let mut gone = lease([192, 0, 2, 24], "aa:bb:cc:00:00:24", Some("old-tv"));
        gone.1.offline = true;
        let peers: Leases = [
            gone,
            lease([192, 0, 2, 21], "aa:bb:cc:00:00:99", Some("other")),
            lease(
                [192, 0, 2, 30],
                "aa:bb:cc:00:00:30",
                Some("peer-printer"),
            ),
        ]
        .into();
        let got = router_names([&own, &peers]);
        let ip = |d: [u8; 4]| IpAddr::from(Ipv4Addr::from(d));
        assert_eq!(
            got.get(&ip([192, 0, 2, 21])).map(|s| &**s),
            Some("kitchen-tablet")
        );
        assert_eq!(
            got.get(&ip([192, 0, 2, 30])).map(|s| &**s),
            Some("peer-printer")
        );
        assert!(!got.contains_key(&ip([192, 0, 2, 22])), "no label");
        assert!(!got.contains_key(&ip([192, 0, 2, 23])), "no name");
        assert!(!got.contains_key(&ip([192, 0, 2, 24])), "offline");
        assert_eq!(got.len(), 2);
    }

    /// REQ: DNS-023 — the built table answers by name and by address, and the API's reverse
    /// map matches.
    #[test]
    fn dns_023_built_table() {
        let names = vec![Named {
            name: "nas.home.arpa".to_owned(),
            ip: Ipv4Addr::new(192, 0, 2, 5),
            v6: Vec::new(),
        }];
        let t = build(&names, 60);
        assert_eq!(t.data.len(), 2, "an A and a PTR");
        assert_eq!(
            t.by_ip
                .get(&Ipv4Addr::new(192, 0, 2, 5))
                .map(String::as_str),
            Some("nas.home.arpa")
        );
        assert!(DeviceNames::default().data.is_empty());
    }

    /// REQ: DNS-023 — settings: off without a domain; lowercase, no trailing dot; mDNS only
    /// when the listener is on.
    #[test]
    fn dns_023_settings() {
        let s = |t: &str| Settings::from_config(&cfg(t));
        assert_eq!(s(""), None);
        assert_eq!(
            s("[local]\ndevice_domain = \"Home.ARPA.\"\ndevice_mdns = true\n"),
            Some(Settings {
                domain: "home.arpa".into(),
                ttl: 60,
                mdns: false
            })
        );
        assert_eq!(
            s("[clients]\nmdns = true\n[local]\ndevice_domain = \"lan\"\ndevice_ttl = 30\ndevice_mdns = true\n")
                .map(|x| (x.domain, x.ttl, x.mdns)),
            Some(("lan".into(), 30, true))
        );
    }

    /// REQ: DNS-023 (T24.8, ADR-983) — a device the router reports with IPv6 addresses answers
    /// AAAA and `ip6.arpa` PTR under the name it has for IPv4, by the same label rules; an
    /// offline client publishes none; a name collision drops the loser's addresses too; one
    /// IPv6 address names one device (the better-ranked keeps it); no table, no addresses.
    #[test]
    fn dns_023_ipv6_names_follow_the_ipv4_rules() {
        let clients = table(
            "[[client]]
name = \"NAS\"
match = [\"192.0.2.5\"]
",
        );
        let mut routers: Leases = [
            lease([192, 0, 2, 5], "aa:bb:cc:00:00:05", Some("diskstation")),
            lease(
                [192, 0, 2, 21],
                "aa:bb:cc:00:00:21",
                Some("Kitchen Tablet"),
            ),
            lease([192, 0, 2, 30], "aa:bb:cc:00:00:30", Some("android")),
            lease([192, 0, 2, 31], "aa:bb:cc:00:00:31", Some("Android")),
            lease([192, 0, 2, 32], "aa:bb:cc:00:00:32", Some("stale-claim")),
            lease([192, 0, 2, 33], "aa:bb:cc:00:00:33", Some("gone")),
        ]
        .into();
        let set = |t: &mut Leases, ip: [u8; 4], a: &[&str], off: bool| {
            let l = t.get_mut(&Ipv4Addr::from(ip)).unwrap();
            l.ipv6 = a.iter().map(|x| v6(x)).collect();
            l.offline = off;
        };
        set(&mut routers, [192, 0, 2, 5], &["fd00:10::5"], false);
        set(
            &mut routers,
            [192, 0, 2, 21],
            &["2001:db8:1::21", "fd00:10::21"],
            false,
        );
        set(&mut routers, [192, 0, 2, 30], &["fd00:10::30"], false);
        // The loser of the `android` label gets no addresses at all.
        set(&mut routers, [192, 0, 2, 31], &["fd00:10::31"], false);
        // Claims an address a better-ranked device already has.
        set(&mut routers, [192, 0, 2, 32], &["fd00:10::21"], false);
        set(&mut routers, [192, 0, 2, 33], &["fd00:10::33"], true);
        let empty = Leases::new();
        let inputs = Inputs {
            clients: &clients,
            routers: [&routers, &empty],
            mdns: [&empty, &empty],
        };
        let (got, collisions) = names(&inputs, "home.arpa");
        assert_eq!(collisions, 1);
        let find = |n: &str| got.iter().find(|x| x.name == n).map(|x| x.v6.clone());
        assert_eq!(find("nas.home.arpa"), Some(vec![v6("fd00:10::5")]));
        assert_eq!(
            find("kitchen-tablet.home.arpa"),
            Some(vec![v6("2001:db8:1::21"), v6("fd00:10::21")])
        );
        assert_eq!(find("android.home.arpa"), Some(vec![v6("fd00:10::30")]));
        assert_eq!(
            find("stale-claim.home.arpa"),
            Some(Vec::new()),
            "the address belongs to the better-ranked device"
        );
        assert_eq!(find("gone.home.arpa"), None, "offline: no name, no address");
        let all: Vec<Ipv6Addr> = got.iter().flat_map(|n| n.v6.clone()).collect();
        assert!(
            !all.contains(&v6("fd00:10::31")),
            "the dropped label's address"
        );
        assert!(!all.contains(&v6("fd00:10::33")), "offline address");
        // The built table answers for each address.
        let t = build(&got, 60);
        // An A or AAAA and a PTR for each address.
        assert_eq!(t.data.len(), 2 * (got.len() + all.len()));
    }

    /// REQ: DNS-023 (T24.8, ADR-983) — an address only names a device when it could be a
    /// neighbour's: link-local, loopback, multicast, unspecified and mapped ones never do.
    #[test]
    fn dns_023_ipv6_addresses_that_may_name_a_device() {
        for ok in ["2001:db8::1", "fd12:3456::9", "fc00::1"] {
            assert!(crate::devices::usable_ipv6(&v6(ok)), "{ok}");
        }
        for bad in [
            "fe80::1",
            "febf::1",
            "::1",
            "::",
            "ff02::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!crate::devices::usable_ipv6(&v6(bad)), "{bad}");
        }
    }
}

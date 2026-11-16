//! REQ: DNS-023 (T22.1; ADR-165) — the devices TelltaleDNS knows by name answer in DNS, as
//! `<name>.<[local] device_domain>` with a PTR for the address, like a router that registers
//! its DHCP clients' names. TelltaleDNS still doesn't run DHCP (ADR-091): the names come from
//! named devices with one address, the routers' DHCP clients and Home Assistant (`[[router]]`),
//! the other nodes' routers (CLU-002), and with `device_mdns` the names devices announce.
//!
//! Built off the query path every few seconds into a [`LocalData`] that the pipeline loads
//! without locking (02 §3). Configured records, hosts files, and a zone's own records win;
//! the table only fills the gaps.
//!
//! When two devices' names make the same label, one keeps it (ADR-165): a named device,
//! then a router's or Home Assistant's name, then an mDNS name, then the lowest address. The
//! others get neither an A record nor a PTR; collisions are counted in the log line that
//! reports each change.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use telltale_policy::{ClientTable, LocalData, device_label};
use tracing::info;

use crate::devices::Leases;

/// How often the table is rebuilt (it changes when a router is read, every few minutes).
const EVERY: Duration = Duration::from_secs(10);

/// `[local] device_domain`, `device_ttl`, `device_mdns`, as the pipeline's policy holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Settings {
    /// Lowercase, without a trailing dot.
    pub(crate) domain: String,
    pub(crate) ttl: u32,
    pub(crate) mdns: bool,
}

impl Settings {
    pub(crate) fn from_config(cfg: &telltale_config::Config) -> Option<Self> {
        let d = cfg.local.device_domain.as_ref()?;
        let domain = d.trim().trim_end_matches('.').to_ascii_lowercase();
        (!domain.is_empty()).then(|| Self {
            domain,
            ttl: cfg.local.device_ttl.max(1),
            mdns: cfg.local.device_mdns && cfg.clients.mdns,
        })
    }
}

/// The table the pipeline answers from, and each address's name for the API.
#[derive(Debug, Default)]
pub(crate) struct DeviceNames {
    pub(crate) data: LocalData,
    /// Address → the full name it answers as.
    pub(crate) by_ip: HashMap<Ipv4Addr, String>,
}

/// Labels no device gets, whatever it calls itself (ADR-165): `wpad` and `isatap` are how
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

/// The `(full name, address)` pairs to answer, sorted by name, and how many names collided.
pub(crate) fn names(inputs: &Inputs<'_>, domain: &str) -> (Vec<(String, Ipv4Addr)>, usize) {
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
            // A device named in TelltaleDNS by its MAC keeps that name at its new address.
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
    // Best address per label: rank, then the lowest address.
    let mut ranked: Vec<(u8, Ipv4Addr, String)> = by_ip
        .into_iter()
        .filter_map(|(ip, (rank, name))| Some((rank, ip, device_label(&name)?)))
        .filter(|(_, _, label)| !RESERVED.contains(&label.as_str()))
        .collect();
    ranked.sort_by(|a, b| (a.0, u32::from(a.1)).cmp(&(b.0, u32::from(b.1))));
    let mut taken: HashMap<String, Ipv4Addr> = HashMap::new();
    let mut collisions = 0;
    for (_, ip, label) in ranked {
        if let Some(kept) = taken.get(&label) {
            collisions += 1;
            tracing::debug!(%label, %kept, dropped = %ip, "device names: two devices share a name; the first keeps it");
            continue;
        }
        taken.insert(label, ip);
    }
    let mut out: Vec<(String, Ipv4Addr)> = taken
        .into_iter()
        .map(|(label, ip)| (format!("{label}.{domain}"), ip))
        .collect();
    out.sort();
    (out, collisions)
}

/// The table for `names`.
pub(crate) fn build(names: &[(String, Ipv4Addr)], ttl: u32) -> DeviceNames {
    DeviceNames {
        data: LocalData::from_device_names(names.iter().map(|(n, ip)| (n.as_str(), *ip)), ttl),
        by_ip: names.iter().map(|(n, ip)| (*ip, n.clone())).collect(),
    }
}

/// Rebuilds the table every [`EVERY`] until `stop`, storing it only when it changed. Reads the
/// settings from the live policy, so a reload that sets or clears the domain takes effect.
pub(crate) async fn run(
    pipeline: Arc<crate::pipeline::Pipeline>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut last: Option<(Settings, Vec<(String, Ipv4Addr)>)> = None;
    let mut tick = tokio::time::interval(EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = tick.tick() => {}
        }
        let state = pipeline.current();
        let Some(settings) = state.policy.device_dns.clone() else {
            if last.take().is_some() {
                pipeline.device_names.store(Arc::default());
                info!("device names in DNS: off");
            }
            continue;
        };
        let routers = pipeline.router_leases.load();
        let peers = pipeline.peer_names.load();
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
            },
        )
    }

    fn cfg(toml: &str) -> telltale_config::Config {
        telltale_config::Loader::new()
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
    /// TelltaleDNS (by address, or by MAC at whatever address it has now), then the router's,
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
            got,
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

    /// REQ: DNS-023 — the built table answers by name and by address, and the API's reverse
    /// map matches.
    #[test]
    fn dns_023_built_table() {
        let names = vec![("nas.home.arpa".to_owned(), Ipv4Addr::new(192, 0, 2, 5))];
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
}

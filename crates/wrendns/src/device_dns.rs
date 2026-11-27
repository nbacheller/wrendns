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
//!
//! REQ: DSC-908..DSC-911, DSC-916 (T36.10a; ADR-1081, ADR-1096) - with `[[location]]` entries a
//! device in a location answers as `<label>.<slug>.<domain>` (its PTR is that name), the old flat
//! name keeps answering while the location's `flat_names` is on, a private location's names
//! answer only to clients in its networks, and the node owns each location's subtree and says
//! no-such-name for anything in it that is not a device. The snapshot the query path reads is
//! built here, off the path, as the whole table is.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use tracing::info;
use wrendns_config::Cidr;
use wrendns_policy::{ClientTable, LocalData, device_label};
use wrendns_proto::{EdnsOut, NameBuf, Query, ResponseBuilder, rcode, rtype};

use crate::devices::Leases;
use crate::locations::{FlatUse, Plan, Resolved};

/// How often the table is rebuilt (it changes when a router is read, every few minutes).
const EVERY: Duration = Duration::from_secs(10);

/// How long this node's own VLAN interfaces are remembered between reads.
const OWN_NETWORKS_EVERY: Duration = Duration::from_secs(60);

/// The policy the router names were last given to (held as a `Weak`, see [`run`]), and the names.
type GivenRouterNames = (Weak<crate::pipeline::Dynamic>, HashMap<IpAddr, Arc<str>>);

/// `[local] device_domain`, `device_ttl`, `device_mdns`, as the pipeline's policy holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Settings {
    /// Lowercase, without a trailing dot. Empty when only `[[location]]` entries (each with its
    /// own domain) name devices: a device on no location's network then has no name.
    pub(crate) domain: String,
    pub(crate) ttl: u32,
    pub(crate) mdns: bool,
}

impl Settings {
    pub(crate) fn from_config(cfg: &wrendns_config::Config) -> Option<Self> {
        let domain = cfg
            .local
            .device_domain
            .as_ref()
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .unwrap_or_default();
        // REQ: DSC-908 - locations name devices too, so they turn the table on.
        (!domain.is_empty() || !cfg.location.is_empty()).then(|| Self {
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
    /// REQ: DSC-909 - the index of its location in the [`Plan`]; `None`: on no location's network.
    pub(crate) loc: Option<usize>,
    /// REQ: DSC-910 - the location comes from the device's `[[client]] location`, not its address.
    pub(crate) pinned: bool,
    /// REQ: DSC-916 - the old flat name that keeps answering (A and AAAA, no PTR).
    pub(crate) flat: Option<String>,
}

impl Default for Named {
    fn default() -> Self {
        Self {
            name: String::new(),
            ip: Ipv4Addr::UNSPECIFIED,
            v6: Vec::new(),
            loc: None,
            pinned: false,
            flat: None,
        }
    }
}

/// REQ: DSC-909 - a name two devices wanted: the better-ranked one (ADR-901) kept it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Collision {
    pub(crate) name: String,
    /// The name is a flat alias (the device keeps its location name).
    pub(crate) flat: bool,
    /// The device that kept it; `None` when the name is a location's own subtree apex.
    pub(crate) kept: Option<Ipv4Addr>,
    /// The device that did not.
    pub(crate) lost: Ipv4Addr,
    pub(crate) lost_location: Option<usize>,
}

/// One location in the snapshot the query path reads.
#[derive(Debug)]
pub(crate) struct LocTable {
    pub(crate) slug: Box<str>,
    /// `<slug>.<domain>`: the subtree this node owns.
    apex: NameBuf,
    soa: Box<[u8]>,
    ttl: u32,
    pub(crate) private: bool,
    /// Every network of the location, as resolved (the private rule's test).
    nets: Box<[Cidr]>,
    /// A private location's names and PTRs; empty for a shared one (those are in the shared table).
    names: LocalData,
    /// The flat aliases of the location's devices (A and AAAA).
    flat: LocalData,
    pub(crate) flat_use: Arc<FlatUse>,
}

impl LocTable {
    fn has_member(&self, peer: Option<IpAddr>) -> bool {
        peer.is_some_and(|p| self.nets.iter().any(|n| n.contains(p)))
    }
}

/// Where a local answer came from (for `explain` and the trace).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hit<'a> {
    /// A device on no location's network, or a PTR.
    Device,
    /// A name composed under this location.
    Location(&'a str),
    /// A flat name that still answers for a device in this location (DSC-916).
    Flat(&'a str),
    /// A name in this location's subtree that is no device: no such name, said locally.
    NoSuchName(&'a str),
}

/// The table the pipeline answers from, and each address's name for the API.
#[derive(Debug, Default)]
pub(crate) struct DeviceNames {
    /// The shared table: devices on no location's network and the shared locations' names.
    pub(crate) data: LocalData,
    /// Address → the full name it answers as.
    pub(crate) by_ip: HashMap<Ipv4Addr, String>,
    /// One per location, in the plan's order.
    pub(crate) locs: Vec<LocTable>,
    /// REQ: DSC-909 - every device with its location, for the API.
    pub(crate) named: Vec<Named>,
    pub(crate) collisions: Vec<Collision>,
    pub(crate) resolved: Resolved,
    pub(crate) plan: Plan,
}

/// SOA RDATA for a location's negative answers: `localhost.`, `hostmaster.<apex>`, the TTL as the
/// minimum (the same shape a made-up zone SOA has, `server::apex_soa_ns`).
fn soa_rdata(apex: &str, ttl: u32) -> Vec<u8> {
    let localhost = NameBuf::from_presentation("localhost").unwrap_or_default();
    let hostmaster = NameBuf::from_presentation(&format!("hostmaster.{apex}")).unwrap_or_default();
    let serial = u32::try_from(crate::pipeline::unix_now()).unwrap_or(1);
    let mut out = localhost.as_wire().to_vec();
    out.extend_from_slice(hostmaster.as_wire());
    for n in [serial, 3600, 600, 86_400, ttl] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    out
}

impl DeviceNames {
    /// REQ: DNS-023, DSC-909, DSC-911, DSC-912 - answers `q` from the device names for a client at
    /// `peer`: a private location's names to its own networks, then the shared table, then the
    /// no-such-name answer for a name in a location's subtree, then the flat aliases. No
    /// allocation, lock or I/O (one lock-free load of the snapshot happens before this); the
    /// location tests are over a handful of entries. With `explain` set nothing is counted and the
    /// answer's source is worked out; without it the source is only what is free to know.
    pub(crate) fn lookup<'a>(
        &'a self,
        q: &Query<'_>,
        peer: Option<IpAddr>,
        out: &mut [u8],
        edns: Option<EdnsOut<'_>>,
        explain: bool,
    ) -> Option<(usize, Hit<'a>)> {
        if self.locs.is_empty() {
            return self.data.answer(q, out, edns).map(|n| (n, Hit::Device));
        }
        for l in &self.locs {
            if l.private
                && l.has_member(peer)
                && let Some(n) = l.names.answer(q, out, edns)
            {
                return Some((n, Hit::Location(&l.slug)));
            }
        }
        if let Some(n) = self.data.answer(q, out, edns) {
            let hit = if explain {
                self.locs
                    .iter()
                    .find(|l| !l.private && q.qname.is_subdomain_of(&l.apex))
                    .map_or(Hit::Device, |l| Hit::Location(&l.slug))
            } else {
                Hit::Device
            };
            return Some((n, hit));
        }
        for l in &self.locs {
            if q.qname.is_subdomain_of(&l.apex) {
                return Self::no_such_name(l, q, out, edns).map(|n| (n, Hit::NoSuchName(&l.slug)));
            }
        }
        for l in &self.locs {
            if (l.private && !l.has_member(peer)) || l.flat.is_empty() {
                continue;
            }
            if let Some(n) = l.flat.answer(q, out, edns) {
                if !explain {
                    l.flat_use.hit(crate::pipeline::unix_now());
                }
                return Some((n, Hit::Flat(&l.slug)));
            }
        }
        None
    }

    /// The answer for a name in a location's subtree that no device, node or record holds: the
    /// same to everyone, a member of a private location included, so a private name looks like an
    /// unknown one to an outsider. The apex itself exists (it has names below it): no data.
    fn no_such_name(
        l: &LocTable,
        q: &Query<'_>,
        out: &mut [u8],
        edns: Option<EdnsOut<'_>>,
    ) -> Option<usize> {
        let rc = if q.qname == l.apex {
            rcode::NOERROR
        } else {
            rcode::NXDOMAIN
        };
        let mut b = ResponseBuilder::new(q, out, rc).ok()?;
        b.authoritative(true)
            .authority_rdata(&l.apex, rtype::SOA, l.ttl, &l.soa)
            .ok()?;
        b.finish(edns).ok()
    }

    /// [`Self::lookup`] without the source.
    pub(crate) fn answer(
        &self,
        q: &Query<'_>,
        peer: Option<IpAddr>,
        out: &mut [u8],
        edns: Option<EdnsOut<'_>>,
    ) -> Option<usize> {
        self.lookup(q, peer, out, edns, false).map(|(n, _)| n)
    }
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

/// REQ: DSC-909 - the locations a table is composed for.
#[derive(Clone, Copy)]
pub(crate) struct Located<'a> {
    pub(crate) plan: &'a Plan,
    pub(crate) resolved: &'a Resolved,
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
#[cfg(test)]
pub(crate) fn names(inputs: &Inputs<'_>, domain: &str) -> (Vec<Named>, usize) {
    let c = compose(inputs, domain, None);
    (c.named, c.collisions.len())
}

/// The devices to answer and the names that collided.
#[derive(Debug, Default)]
pub(crate) struct Composed {
    pub(crate) named: Vec<Named>,
    pub(crate) collisions: Vec<Collision>,
}

/// REQ: DNS-023, DSC-909, DSC-910, DSC-916 - composes every device's name. A device's location is
/// its `[[client]] location` when it has one, else the location whose resolved networks hold its
/// address; the router and `[[client]]` data only, never the device inventory's records (DSC-901). Names are claimed in
/// ADR-901's order (a named device, then a router's name, then mDNS, then the lowest address), the
/// first claimant keeping a name and every other getting nothing at it: a device that loses its
/// own name has none, one that loses only its flat alias keeps its location name.
#[allow(clippy::too_many_lines)] // one pass: candidates, ranking, claims
pub(crate) fn compose(inputs: &Inputs<'_>, domain: &str, located: Option<Located<'_>>) -> Composed {
    /// The best name per address: its rank, name and the `[[client]] location` pin.
    type Best = (u8, String, Option<String>);
    let mut by_ip: HashMap<Ipv4Addr, Best> = HashMap::new();
    let mut offer = |ip: Ipv4Addr, rank: u8, name: &str, pin: Option<&str>| {
        let better = by_ip.get(&ip).is_none_or(|(r, _, _)| rank < *r);
        if better {
            by_ip.insert(ip, (rank, name.to_owned(), pin.map(str::to_owned)));
        }
    };
    for (ip, c) in inputs.clients.exact_ips() {
        if let IpAddr::V4(v4) = ip {
            offer(v4, NAMED, &c.name, c.location.as_deref());
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
                (Some(c), _) => offer(l.ip, NAMED, &c.name, c.location.as_deref()),
                (None, Some(h)) => offer(l.ip, ROUTER, h, None),
                (None, None) => {}
            }
        }
    }
    for table in inputs.mdns {
        for l in table.values() {
            if let Some(h) = &l.hostname {
                offer(l.ip, MDNS, h, None);
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
    let mut ranked: Vec<(u8, Ipv4Addr, String, Option<String>)> = by_ip
        .into_iter()
        .filter_map(|(ip, (rank, name, pin))| Some((rank, ip, device_label(&name)?, pin)))
        .filter(|(_, _, label, _)| !RESERVED.contains(&label.as_str()))
        .collect();
    ranked.sort_by(|a, b| (a.0, u32::from(a.1)).cmp(&(b.0, u32::from(b.1))));
    // Every name a device may answer as: the first claimant keeps it.
    let mut taken: HashMap<String, Ipv4Addr> = HashMap::new();
    // A location's subtree apex is the location's, whatever device label equals it.
    let apexes: HashSet<String> = located
        .map(|l| {
            l.plan
                .locs
                .iter()
                .map(crate::locations::Loc::apex)
                .collect()
        })
        .unwrap_or_default();
    // One IPv6 address, one name: the better-ranked device keeps it (as for an IPv4 address).
    let mut v6_taken: HashSet<Ipv6Addr> = HashSet::new();
    let mut out: Vec<Named> = Vec::new();
    let mut collisions: Vec<Collision> = Vec::new();
    for (_, ip, label, pin) in ranked {
        let by_pin = located.and_then(|l| pin.as_deref().and_then(|s| l.plan.index_of(s)));
        let loc = by_pin.or_else(|| located.and_then(|l| l.resolved.locate(IpAddr::V4(ip))));
        let (fwd, flat) = match (loc, located) {
            (Some(i), Some(l)) => {
                let lc = &l.plan.locs[i];
                (
                    format!("{label}.{}.{}", lc.slug, lc.parent),
                    (lc.flat && !domain.is_empty()).then(|| format!("{label}.{domain}")),
                )
            }
            _ if domain.is_empty() => continue,
            _ => (format!("{label}.{domain}"), None),
        };
        if apexes.contains(&fwd) {
            collisions.push(Collision {
                name: fwd,
                flat: false,
                kept: None,
                lost: ip,
                lost_location: loc,
            });
            continue;
        }
        if let Some(kept) = taken.get(&fwd) {
            tracing::debug!(name = %fwd, %kept, dropped = %ip, "device names: two devices share a name; the first keeps it");
            collisions.push(Collision {
                name: fwd,
                flat: false,
                kept: Some(*kept),
                lost: ip,
                lost_location: loc,
            });
            continue;
        }
        taken.insert(fwd.clone(), ip);
        let flat = flat.filter(|f| {
            if apexes.contains(f) {
                collisions.push(Collision {
                    name: f.clone(),
                    flat: true,
                    kept: None,
                    lost: ip,
                    lost_location: loc,
                });
                return false;
            }
            if let Some(kept) = taken.get(f) {
                collisions.push(Collision {
                    name: f.clone(),
                    flat: true,
                    kept: Some(*kept),
                    lost: ip,
                    lost_location: loc,
                });
                return false;
            }
            taken.insert(f.clone(), ip);
            true
        });
        let v6: Vec<Ipv6Addr> = v6_of
            .get(&ip)
            .into_iter()
            .flat_map(|a| a.iter().copied())
            .filter(|a| crate::devices::usable_ipv6(a) && v6_taken.insert(*a))
            .collect();
        out.push(Named {
            name: fwd,
            ip,
            v6,
            loc,
            pinned: by_pin.is_some(),
            flat,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Composed {
        named: out,
        collisions,
    }
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

fn addrs_of(n: &Named) -> impl Iterator<Item = IpAddr> + '_ {
    std::iter::once(IpAddr::V4(n.ip)).chain(n.v6.iter().map(|a| IpAddr::V6(*a)))
}

/// The table for `names`, with no locations.
pub(crate) fn build(names: &[Named], ttl: u32) -> DeviceNames {
    let addrs = names
        .iter()
        .flat_map(|n| addrs_of(n).map(move |a| (n.name.as_str(), a)));
    DeviceNames {
        data: LocalData::from_device_names(addrs, ttl),
        by_ip: names.iter().map(|n| (n.ip, n.name.clone())).collect(),
        named: names.to_vec(),
        ..DeviceNames::default()
    }
}

/// REQ: DSC-909, DSC-911, DSC-916 - the table with locations: a private location's names in its
/// own table, the rest in the shared one, the flat aliases apart (so they can be counted and
/// kept private with their location). `uses` are the flat-name counters, one per location in the
/// plan's order.
pub(crate) fn build_located(
    composed: Composed,
    ttl: u32,
    plan: &Plan,
    resolved: &Resolved,
    uses: &[Arc<FlatUse>],
) -> DeviceNames {
    let Composed { named, collisions } = composed;
    let private = |n: &Named| n.loc.is_some_and(|i| plan.locs[i].private);
    let shared = named
        .iter()
        .filter(|n| !private(n))
        .flat_map(|n| addrs_of(n).map(move |a| (n.name.as_str(), a)));
    let data = LocalData::from_device_names(shared, ttl);
    let locs = plan
        .locs
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let apex_text = l.apex();
            let apex = NameBuf::from_presentation(&apex_text).unwrap_or_default();
            let mine = || named.iter().filter(move |n| n.loc == Some(i));
            let names = if l.private {
                LocalData::from_device_names(
                    mine().flat_map(|n| addrs_of(n).map(move |a| (n.name.as_str(), a))),
                    ttl,
                )
            } else {
                LocalData::default()
            };
            let flat = LocalData::from_aliases(
                mine()
                    .filter_map(|n| n.flat.as_deref().map(|f| (f, n)))
                    .flat_map(|(f, n)| addrs_of(n).map(move |a| (f, a))),
                ttl,
            );
            LocTable {
                slug: l.slug.as_str().into(),
                soa: soa_rdata(&apex_text, ttl).into(),
                apex,
                ttl,
                private: l.private,
                nets: resolved.nets.get(i).cloned().unwrap_or_default().into(),
                names,
                flat,
                flat_use: uses.get(i).cloned().unwrap_or_default(),
            }
        })
        .collect();
    DeviceNames {
        data,
        by_ip: named.iter().map(|n| (n.ip, n.name.clone())).collect(),
        locs,
        named,
        collisions,
        resolved: resolved.clone(),
        plan: plan.clone(),
    }
}

/// Everything a rebuild is decided by: when none of it changed the stored table stays.
#[derive(PartialEq)]
struct Built {
    settings: Settings,
    plan: Plan,
    resolved: Resolved,
    named: Vec<Named>,
    collisions: Vec<Collision>,
}

/// Rebuilds the table every [`EVERY`] until `stop`, storing it only when it changed. Reads the
/// settings from the live policy, so a reload that sets or clears the domain takes effect.
/// `mdns_listening` is the `[clients] mdns` the node started with: the listener starts once
/// (`restart_only_changes`), so device names follow mDNS only while it runs (REQ: DNS-023, H1).
#[allow(clippy::too_many_lines)] // one tick: inputs, locations, compose, store
pub(crate) async fn run(
    pipeline: Arc<crate::pipeline::Pipeline>,
    mdns_listening: bool,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut last: Option<Built> = None;
    // REQ: DSC-916 - the flat-name counters live across rebuilds, by location slug.
    let mut flat_uses: HashMap<String, Arc<FlatUse>> = HashMap::new();
    // REQ: DSC-909 - this node's own VLAN interfaces, read at most once a minute and only when a
    // location names a VLAN.
    let mut own: Option<(Instant, Vec<crate::own_networks::OwnNetwork>)> = None;
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
        let plan = (*state.policy.locations).clone();
        let resolved = if plan.is_empty() {
            Resolved::default()
        } else {
            let own_nets = if plan.has_vlans() {
                if own
                    .as_ref()
                    .is_none_or(|(at, _)| at.elapsed() >= OWN_NETWORKS_EVERY)
                {
                    let read = tokio::task::spawn_blocking(crate::own_networks::current)
                        .await
                        .unwrap_or_default();
                    own = Some((Instant::now(), read));
                }
                own.as_ref().map(|(_, n)| n.clone()).unwrap_or_default()
            } else {
                Vec::new()
            };
            let nets = pipeline.router_networks.load();
            Resolved::resolve(&plan, &nets, &own_nets)
        };
        let composed = compose(
            &inputs,
            &settings.domain,
            (!plan.is_empty()).then_some(Located {
                plan: &plan,
                resolved: &resolved,
            }),
        );
        let now = Built {
            settings,
            plan,
            resolved,
            named: composed.named.clone(),
            collisions: composed.collisions.clone(),
        };
        if last.as_ref().is_some_and(|b| *b == now) {
            continue;
        }
        info!(
            domain = %now.settings.domain,
            names = now.named.len(),
            collisions = now.collisions.len(),
            locations = now.plan.locs.len(),
            "device names in DNS: updated"
        );
        let table = if now.plan.is_empty() {
            build(&now.named, now.settings.ttl)
        } else {
            flat_uses.retain(|slug, _| now.plan.locs.iter().any(|l| &l.slug == slug));
            let uses: Vec<Arc<FlatUse>> = now
                .plan
                .locs
                .iter()
                .map(|l| Arc::clone(flat_uses.entry(l.slug.clone()).or_default()))
                .collect();
            build_located(composed, now.settings.ttl, &now.plan, &now.resolved, &uses)
        };
        pipeline.device_names.store(Arc::new(table));
        last = Some(now);
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
            lease([192, 0, 2, 21], "aa:bb:cc:00:00:21", Some("Kitchen Tablet")),
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
                ("kitchen-tablet.home.arpa".to_owned(), ip([192, 0, 2, 21])),
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
        let connected: Leases = [lease([192, 0, 2, 53], "aa:bb:cc:00:00:53", Some("ipad"))].into();
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
            lease([192, 0, 2, 21], "aa:bb:cc:00:00:21", Some("Kitchen Tablet")),
            lease([192, 0, 2, 22], "aa:bb:cc:00:00:22", Some("***")),
            lease([192, 0, 2, 23], "aa:bb:cc:00:00:23", None),
        ]
        .into();
        let mut gone = lease([192, 0, 2, 24], "aa:bb:cc:00:00:24", Some("old-tv"));
        gone.1.offline = true;
        let peers: Leases = [
            gone,
            lease([192, 0, 2, 21], "aa:bb:cc:00:00:99", Some("other")),
            lease([192, 0, 2, 30], "aa:bb:cc:00:00:30", Some("peer-printer")),
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
            ..Default::default()
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
            lease([192, 0, 2, 21], "aa:bb:cc:00:00:21", Some("Kitchen Tablet")),
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

    // ---- REQ: DSC-909, DSC-910, DSC-916 (T36.10a) - names with locations ----

    const LOCS: &str = "[local]\ndevice_domain = \"home.arpa\"\n\
        [[location]]\nslug = \"home\"\nnetworks = [\"10.1.1.0/24\"]\n\
        [[location]]\nslug = \"lab\"\nnetworks = [\"10.2.2.0/24\"]\n";

    fn located(toml: &str, routers: &Leases, mdns: &Leases) -> (Composed, crate::locations::Plan) {
        located_cfg(&cfg(toml), routers, mdns)
    }

    fn located_cfg(
        c: &wrendns_config::Config,
        routers: &Leases,
        mdns: &Leases,
    ) -> (Composed, crate::locations::Plan) {
        let plan = crate::locations::Plan::from_config(c);
        let resolved = crate::locations::Resolved::resolve(&plan, &[], &[]);
        let clients = ClientTable::from_config(c);
        let empty = Leases::new();
        let inputs = Inputs {
            clients: &clients,
            routers: [routers, &empty],
            mdns: [mdns, &empty],
        };
        let domain = c
            .local
            .device_domain
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        let composed = compose(
            &inputs,
            &domain,
            Some(Located {
                plan: &plan,
                resolved: &resolved,
            }),
        );
        (composed, plan)
    }

    fn name_list(c: &Composed) -> Vec<(String, Ipv4Addr, Option<String>)> {
        c.named
            .iter()
            .map(|n| (n.name.clone(), n.ip, n.flat.clone()))
            .collect()
    }

    // REQ: DSC-910 - a device that moves to another location's network is renamed by the next
    // rebuild, and its old name stops at the same moment (the inventory is never read).
    #[test]
    fn dsc_910_a_moved_device_is_renamed_at_the_next_rebuild() {
        let empty = Leases::new();
        let at = |ip: [u8; 4]| -> Leases { [lease(ip, "aa:bb:cc:00:00:20", Some("phone"))].into() };
        let (first, _) = located(LOCS, &at([10, 1, 1, 20]), &empty);
        assert_eq!(
            name_list(&first),
            vec![(
                "phone.home.home.arpa".to_owned(),
                Ipv4Addr::new(10, 1, 1, 20),
                Some("phone.home.arpa".to_owned())
            )]
        );
        let (moved, _) = located(LOCS, &at([10, 2, 2, 20]), &empty);
        assert_eq!(
            name_list(&moved),
            vec![(
                "phone.lab.home.arpa".to_owned(),
                Ipv4Addr::new(10, 2, 2, 20),
                Some("phone.home.arpa".to_owned())
            )]
        );
    }

    // REQ: DSC-909 - two devices that make one label in one location: the ADR-901 winner (a named
    // device over a router's name) keeps it, the other gets nothing, and the collision is listed.
    #[test]
    fn dsc_909_a_collision_in_a_location_keeps_the_adr_901_winner() {
        let routers: Leases = [
            lease([10, 1, 1, 5], "aa:bb:cc:00:00:05", Some("tablet")),
            lease([10, 1, 1, 6], "aa:bb:cc:00:00:06", Some("Tablet")),
            lease([10, 1, 1, 7], "aa:bb:cc:00:00:07", Some("tablet")),
        ]
        .into();
        let toml = format!("{LOCS}[[client]]\nname = \"Tablet\"\nmatch = [\"10.1.1.7\"]\n");
        let (c, _) = located(&toml, &routers, &Leases::new());
        let home: Vec<_> = c
            .named
            .iter()
            .filter(|n| n.name == "tablet.home.home.arpa")
            .collect();
        assert_eq!(home.len(), 1);
        assert_eq!(
            home[0].ip,
            Ipv4Addr::new(10, 1, 1, 7),
            "the named device keeps it"
        );
        let lost: Vec<Ipv4Addr> = c
            .collisions
            .iter()
            .filter(|k| !k.flat)
            .map(|k| k.lost)
            .collect();
        assert_eq!(
            lost,
            vec![Ipv4Addr::new(10, 1, 1, 5), Ipv4Addr::new(10, 1, 1, 6)],
            "the others are listed, lowest address first"
        );
        assert!(
            c.collisions
                .iter()
                .all(|k| k.kept == Some(Ipv4Addr::new(10, 1, 1, 7)))
        );
    }

    // REQ: DSC-916 - one flat label two locations compose goes to the ADR-901 winner and the
    // loser keeps its location name; with `flat_names` off a device does not claim it at all.
    #[test]
    fn dsc_916_a_flat_name_two_locations_compose_goes_to_the_ranked_winner() {
        let routers: Leases = [
            lease([10, 1, 1, 5], "aa:bb:cc:00:00:05", Some("nas")),
            lease([10, 2, 2, 5], "aa:bb:cc:00:00:15", Some("nas")),
        ]
        .into();
        let (c, _) = located(LOCS, &routers, &Leases::new());
        let flat: Vec<(&str, Option<&str>)> = c
            .named
            .iter()
            .map(|n| (n.name.as_str(), n.flat.as_deref()))
            .collect();
        assert_eq!(
            flat,
            vec![
                ("nas.home.home.arpa", Some("nas.home.arpa")),
                ("nas.lab.home.arpa", None)
            ],
            "the lower address keeps the flat name; both keep their location names"
        );
        let k: Vec<_> = c.collisions.iter().collect();
        assert_eq!(k.len(), 1);
        assert!(
            k[0].flat && k[0].name == "nas.home.arpa" && k[0].lost == Ipv4Addr::new(10, 2, 2, 5)
        );
        // The home location turns its flat names off: the lab's device may have the name.
        let off = LOCS.replacen(
            "slug = \"home\"\n",
            "slug = \"home\"\nflat_names = false\n",
            1,
        );
        let (c, _) = located(&off, &routers, &Leases::new());
        assert_eq!(c.collisions.len(), 0);
        let flat: Vec<(&str, Option<&str>)> = c
            .named
            .iter()
            .map(|n| (n.name.as_str(), n.flat.as_deref()))
            .collect();
        assert_eq!(
            flat,
            vec![
                ("nas.home.home.arpa", None),
                ("nas.lab.home.arpa", Some("nas.home.arpa"))
            ]
        );
    }

    // REQ: DSC-909 - a device on no location's network keeps its flat name, a device called like
    // a location's subtree apex loses to the location, and with no domain at all only located
    // devices have names.
    #[test]
    fn dsc_909_unlocated_devices_and_the_subtree_apex() {
        let routers: Leases = [
            lease([10, 9, 9, 4], "aa:bb:cc:00:00:04", Some("printer")),
            lease([10, 9, 9, 5], "aa:bb:cc:00:00:05", Some("home")),
            lease([10, 1, 1, 8], "aa:bb:cc:00:00:08", Some("camera")),
        ]
        .into();
        let (c, _) = located(LOCS, &routers, &Leases::new());
        let names: Vec<&str> = c.named.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["camera.home.home.arpa", "printer.home.arpa"]);
        assert_eq!(c.collisions.len(), 1);
        assert_eq!(c.collisions[0].name, "home.home.arpa");
        assert_eq!(c.collisions[0].kept, None, "the location wins");
        // No device_domain: the location has its own domain, and the unlocated printer has none.
        let own = "[[location]]\nslug = \"home\"\nnetworks = [\"10.1.1.0/24\"]\ndomain = \"example.net\"\n";
        let (c, _) = located(own, &routers, &Leases::new());
        let names: Vec<&str> = c.named.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["camera.home.example.net"]);
        assert_eq!(c.named[0].flat, None, "no device_domain, no flat name");
    }

    // REQ: DSC-910 - a pin from `[[client]] location` wins over the address, by IP and by MAC.
    #[test]
    fn dsc_910_a_pin_wins_by_address_and_by_mac() {
        let routers: Leases = [
            lease([10, 1, 1, 9], "aa:bb:cc:00:00:09", Some("laptop")),
            lease([10, 1, 1, 10], "AA:BB:CC:00:00:0A", Some("macbook")),
        ]
        .into();
        let toml = format!(
            "{LOCS}[[client]]\nname = \"Laptop\"\nmatch = [\"10.1.1.9\"]\nlocation = \"lab\"\n[[client]]\nname = \"Work Mac\"\nmatch = [\"aa:bb:cc:00:00:0a\"]\nlocation = \"lab\"\n"
        );
        let (c, _) = located(&toml, &routers, &Leases::new());
        let names: Vec<(&str, bool)> = c
            .named
            .iter()
            .map(|n| (n.name.as_str(), n.pinned))
            .collect();
        assert_eq!(
            names,
            vec![
                ("laptop.lab.home.arpa", true),
                ("work-mac.lab.home.arpa", true)
            ]
        );
    }

    // REQ: DSC-908 (ADR-1104 point 5) - a primary that holds its locations out at start-up answers
    // as it did without them: the device keeps its flat name only, a pinned device too, and the
    // subtree has no table.
    #[test]
    fn dsc_908_held_locations_are_not_served() {
        let empty = Leases::new();
        let routers: Leases = [lease([10, 1, 1, 20], "aa:bb:cc:00:00:20", Some("phone"))].into();
        let toml = format!(
            "{LOCS}[[client]]
name = \"phone\"
match = [\"10.1.1.20\"]
location = \"lab\"
"
        );
        let (with, _) = located(&toml, &routers, &empty);
        assert_eq!(with.named[0].name, "phone.lab.home.arpa");
        let mut stripped = cfg(&toml);
        let hold = crate::upgrade_gate::Hold::new();
        assert!(hold.at_start(&mut stripped, true, false));
        let (without, plan) = located_cfg(&stripped, &routers, &empty);
        assert_eq!(
            name_list(&without),
            vec![(
                "phone.home.arpa".to_owned(),
                Ipv4Addr::new(10, 1, 1, 20),
                None
            )]
        );
        assert_eq!(plan.locs.len(), 0);
    }
}

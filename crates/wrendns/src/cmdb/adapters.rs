//! REQ: DSC-902, DSC-903, DSC-906 (T31.2, ADR-1005 section 4) - one adapter per source: turns what a
//! feed already reads into source records for the sink. No adapter does any I/O of its own and none
//! adds a request to a poller: the router leases, the neighbour table, mDNS, the SNMP poller's rows,
//! the UniFi and Home Assistant reads are the inventory's feeds; `config` and `cluster` are read from
//! the live configuration and the cluster's member list; `queries` is a snapshot of the aggregator
//! the thread reads once a minute (never from the hot path); `k8s` is the workload table when the
//! Kubernetes feature is on.
//!
//! There is **no Pi-hole importer source** (owner question 14, 2026-11-19): what the importer brings
//! reaches the CMDB only as configuration, through `config`.
//!
//! **A feed is a source instance.** The leases and the extra UniFi reads of one router are two feeds
//! (`unifi:<router>` and `unifi:<router>#fields`, `#devices`, `#history`), so a complete batch of one
//! never marks the other's records missed, and two feeds never rewrite one record.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use wrendns_config::Config;

use super::model::{RecKind, Record, SourceBatch, norm_port};
use crate::devices::Leases;
use crate::discovery::inventory::{NameKind, Observation, Source};

/// The kind of each configured router (`unifi`, `opnsense`, `home_assistant`), by name.
pub(crate) fn router_kinds(cfg: &Config) -> HashMap<String, &'static str> {
    cfg.router
        .iter()
        .map(|r| {
            (
                r.name.as_str().to_owned(),
                match r.kind {
                    wrendns_config::RouterKind::Unifi => "unifi",
                    wrendns_config::RouterKind::Opnsense => "opnsense",
                    wrendns_config::RouterKind::HomeAssistant => "home_assistant",
                },
            )
        })
        .collect()
}

fn secs(t: u64) -> i64 {
    i64::try_from(t).unwrap_or(i64::MAX)
}

/// A hostname-like name: the kinds of name a device gives itself or a DHCP server records.
fn is_hostname_kind(k: NameKind) -> bool {
    matches!(
        k,
        NameKind::RouterAlias | NameKind::Mdns | NameKind::Import | NameKind::History
    )
}

fn scoped(source: &str, raw: &str) -> String {
    format!("{source}|{raw}")
}

fn merge_list(into: &mut Vec<String>, more: &[String]) {
    for m in more {
        if !into.contains(m) {
            into.push(m.clone());
        }
    }
}

/// Observations of one feed as records: one per MAC (or per address, for a claim with no MAC), the
/// facts of several observations of the same thing merged. A structured place (`hint.port_ref`)
/// also makes a port record under the switch it names, so port CIs exist for the ports clients are
/// seen on.
#[allow(clippy::too_many_lines)] // one flow over an observation's fields
pub(crate) fn records_from_observations(
    obs: &[Observation],
    source: &str,
    now: i64,
) -> Vec<Record> {
    let mut by_key: BTreeMap<String, Record> = BTreeMap::new();
    let mut ports: BTreeMap<String, Record> = BTreeMap::new();
    // A fixed order, so a feed read from a hash map yields the same record every time.
    let mut sorted: Vec<&Observation> = obs.iter().collect();
    sorted.sort_by(|a, b| {
        (a.mac, a.ip, a.name.as_ref().map(|n| &n.1)).cmp(&(
            b.mac,
            b.ip,
            b.name.as_ref().map(|n| &n.1),
        ))
    });
    for o in sorted {
        let (key, mac_text) = match (o.mac, o.ip) {
            (Some(m), _) => {
                let t = m
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":");
                (t.clone(), Some(t))
            }
            (None, Some(ip)) => (format!("ip:{ip}"), None),
            (None, None) => continue,
        };
        let seen = secs(o.seen).max(0);
        let r = by_key
            .entry(key.clone())
            .or_insert_with(|| Record::new(source, &key, RecKind::Device, seen));
        r.seen = r.seen.max(seen);
        if let Some(m) = &mac_text {
            r.text("mac", m.clone());
        }
        if let Some(ip) = o.ip {
            let mut have: Vec<String> = match r.attrs.get("addresses") {
                Some(serde_json::Value::Array(a)) => a
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect(),
                _ => Vec::new(),
            };
            merge_list(&mut have, &[ip.to_string()]);
            have.sort();
            r.list("addresses", have);
        }
        if let Some((kind, name)) = &o.name
            && !r.attrs.contains_key("name")
        {
            r.text("name", name.clone());
            if is_hostname_kind(*kind) && !r.attrs.contains_key("hostname") {
                r.text("hostname", name.clone());
            }
        }
        if let Some(v) = o.vlan {
            r.num("vlan", i64::from(v));
        }
        if let Some(n) = &o.network {
            r.text("network", n.clone());
        }
        if let Some(a) = &o.ap {
            r.text("ap", a.clone());
        }
        if let Some(p) = &o.port {
            r.text("port", p.clone());
        }
        if !o.lldp.is_empty() || o.router_lldp.as_ref().is_some_and(|l| !l.is_empty()) {
            let mut l: Vec<String> = o.lldp.clone();
            if let Some(extra) = &o.router_lldp {
                merge_list(&mut l, extra);
            }
            r.list("lldp", l);
        }
        if let Some(h) = &o.hint {
            if let Some(s) = &h.serial {
                r.text("serial", s.clone());
            }
            if let Some(k) = &h.device_key {
                r.text("device_key", scoped(source, k));
            }
            r.opt_text("model", h.model.clone());
            r.opt_text("role", h.role.clone());
            r.opt_text("firmware", h.firmware.clone());
            if let Some(hn) = &h.hostname {
                r.text("hostname", hn.clone());
            }
            if let Some((owner, raw)) = &h.port_ref {
                let owner = scoped(source, owner);
                r.text("attached_owner", owner.clone());
                r.text("attached_port", raw.clone());
                if let Some(norm) = norm_port(raw) {
                    let pk = format!("{owner}|{norm}");
                    ports.entry(pk.clone()).or_insert_with(|| {
                        let mut p = Record::new(source, &pk, RecKind::Port, seen);
                        p.text("owner", owner.clone()).text("port_id", raw.clone());
                        p
                    });
                }
            }
        }
    }
    let mut out: Vec<Record> = by_key.into_values().collect();
    out.extend(ports.into_values());
    let _ = now;
    out
}

/// The routers' lease view as batches: one complete batch per configured router (so a router that
/// reports nothing marks its records missed), named by the router's kind.
pub(crate) fn from_lease_view(
    view: &Leases,
    kinds: &HashMap<String, &'static str>,
    now: i64,
) -> Vec<SourceBatch> {
    let obs = crate::discovery::sources::lease_observations(
        view,
        Source::Router,
        u64::try_from(now).unwrap_or(0),
    );
    let mut by_router: BTreeMap<String, Vec<Observation>> = BTreeMap::new();
    for (name, kind) in kinds {
        if *kind != "home_assistant" {
            by_router.entry(name.clone()).or_default();
        }
    }
    for o in obs {
        let router = o.name_origin.clone().unwrap_or_default();
        // The Home Assistant feed is the discovery poll's (it has the device keys); the lease view
        // of the same devices would write a second, disagreeing batch under the same source name.
        if kinds.get(&router).is_some_and(|k| *k == "home_assistant") {
            continue;
        }
        by_router.entry(router).or_default().push(o);
    }
    by_router
        .into_iter()
        .map(|(router, obs)| {
            let source = match kinds.get(&router) {
                Some(k) => format!("{k}:{router}"),
                None => "lease".to_owned(),
            };
            SourceBatch {
                records: records_from_observations(&obs, &source, now),
                source,
                complete: true,
                at: now,
            }
        })
        .collect()
}

/// A feed's observations as one complete batch under `source`.
pub(crate) fn batch_from_observations(obs: &[Observation], source: &str, now: i64) -> SourceBatch {
    SourceBatch {
        source: source.to_owned(),
        complete: true,
        records: records_from_observations(obs, source, now),
        at: now,
    }
}

// -- config and cluster ------------------------------------------------------------------------

/// Whether an address is in a container, cluster or Docker range (the overlap warnings of
/// `[discovery]`, ADR-907): a pod or a service, not a device.
fn is_container_range(ip: Ipv4Addr) -> bool {
    wrendns_config::discovery::OVERLAP_WARNINGS
        .iter()
        .filter_map(|(net, _)| wrendns_config::Cidr::parse(net).ok())
        .any(|n| {
            wrendns_config::Cidr::parse(&format!("{ip}/32"))
                .is_ok_and(|one| wrendns_config::discovery::overlaps(&one, &n))
        })
}

/// What the configuration says: the known devices (`[[client]]`), the subnets (`[[discovery.subnet]]`),
/// the upstreams and this node's listeners. One complete batch under `config`; it never goes stale
/// (ADR-1004 section 6).
pub(crate) fn from_config(cfg: &Config, node: &str, now: i64) -> SourceBatch {
    let mut records: Vec<Record> = Vec::new();
    for c in &cfg.client {
        let mut r = Record::new(
            "config",
            &format!("client:{}", c.name),
            RecKind::Device,
            now,
        );
        r.text("name", c.name.as_str());
        let mut addrs: Vec<String> = Vec::new();
        let mut ids: Vec<String> = Vec::new();
        for m in &c.match_keys {
            let m = m.as_str();
            if super::model::norm_mac(m).is_some() && !r.attrs.contains_key("mac") {
                r.text("mac", m);
            } else if let Some(id) = m.strip_prefix("id:") {
                ids.push(id.to_owned());
            } else if m.parse::<IpAddr>().is_ok() {
                addrs.push(m.to_owned());
            }
        }
        if !addrs.is_empty() {
            r.list("addresses", addrs);
        }
        if !ids.is_empty() {
            r.list("client_ids", ids);
        }
        if !c.groups.is_empty() {
            r.list(
                "member_of",
                c.groups.iter().map(|g| g.as_str().to_owned()).collect(),
            );
        }
        if let Some(k) = &c.kind {
            r.text("role", format!("{k:?}").to_ascii_lowercase());
        }
        records.push(r);
    }
    for s in &cfg.discovery.subnets {
        let cidr = s.cidr.to_string();
        let mut r = Record::new("config", &format!("subnet:{cidr}"), RecKind::Network, now);
        r.text("key", format!("network:{cidr}|0"))
            .text("name", cidr.clone())
            .text("cidr", cidr);
        records.push(r);
    }
    for u in &cfg.upstream {
        let mut r = Record::new(
            "config",
            &format!("upstream:{}", u.name),
            RecKind::Upstream,
            now,
        );
        let url = u.url.as_str();
        r.text("key", format!("upstream:{}", u.name))
            .text("name", u.name.as_str())
            .text("address", url)
            .text(
                "protocol",
                url.split_once("://").map_or("", |(s, _)| s).to_owned(),
            );
        records.push(r);
    }
    for l in &cfg.listen {
        let key = format!("service:{node}|{:?}:{}", l.proto, l.addr);
        let mut r = Record::new("config", &key, RecKind::Service, now);
        r.text("key", key.clone())
            .text("name", format!("{:?} {}", l.proto, l.addr))
            .text("protocol", format!("{:?}", l.proto).to_ascii_lowercase())
            .num("port", i64::from(l.addr.port()))
            .text("node", node);
        records.push(r);
    }
    {
        let key = format!("service:{node}|api:{}", cfg.api.listen);
        let mut r = Record::new("config", &key, RecKind::Service, now);
        r.text("key", key.clone())
            .text("name", format!("API {}", cfg.api.listen))
            .text("protocol", "https")
            .num("port", i64::from(cfg.api.listen.port()))
            .text("node", node);
        records.push(r);
    }
    SourceBatch {
        source: "config".to_owned(),
        complete: true,
        records,
        at: now,
    }
}

/// A cluster member, as the CMDB needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeRow {
    pub(crate) id: String,
    pub(crate) address: String,
    pub(crate) primary: bool,
    pub(crate) version: String,
}

/// The cluster's nodes (a standalone node is its own): one complete batch under `cluster`.
pub(crate) fn from_cluster(nodes: &[NodeRow], now: i64) -> SourceBatch {
    let records = nodes
        .iter()
        .map(|n| {
            let mut r = Record::new("cluster", &format!("node:{}", n.id), RecKind::Node, now);
            r.text("key", format!("node:{}", n.id))
                .text("name", n.id.clone())
                .text("address", n.address.clone())
                .text("role", if n.primary { "primary" } else { "replica" })
                .text("version", n.version.clone());
            r
        })
        .collect();
    SourceBatch {
        source: "cluster".to_owned(),
        complete: true,
        records,
        at: now,
    }
}

/// A network a router reported or this node is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetRow {
    pub(crate) source: String,
    pub(crate) name: String,
    pub(crate) cidr: String,
    pub(crate) vlan: Option<u16>,
    pub(crate) gateway: Option<String>,
    pub(crate) domain: Option<String>,
    pub(crate) purpose: Option<String>,
}

/// Networks as batches, one per source (a router's networks, or this node's interfaces under
/// `cluster`). A network is one CI by its CIDR and VLAN whoever reports it.
pub(crate) fn from_networks(rows: &[NetRow], now: i64) -> Vec<SourceBatch> {
    let mut by: BTreeMap<String, Vec<Record>> = BTreeMap::new();
    for n in rows {
        let key = format!("network:{}|{}", n.cidr, n.vlan.unwrap_or(0));
        let mut r = Record::new(
            &n.source,
            &format!("net:{}|{}", n.cidr, n.name),
            RecKind::Network,
            now,
        );
        r.text("key", key)
            .text("name", n.name.clone())
            .text("cidr", n.cidr.clone());
        if let Some(v) = n.vlan {
            r.num("vlan_id", i64::from(v));
        }
        r.opt_text("gateway", n.gateway.clone());
        r.opt_text("domain", n.domain.clone());
        r.opt_text("purpose", n.purpose.clone());
        by.entry(n.source.clone()).or_default().push(r);
    }
    by.into_iter()
        .map(|(source, records)| SourceBatch {
            source,
            complete: true,
            records,
            at: now,
        })
        .collect()
}

// -- queries and Kubernetes --------------------------------------------------------------------

/// The clients that queried in the last hour, as keyless records that hold an address: a snapshot
/// the thread takes once a minute from the aggregator, off the DNS path (ADR-1005 section 4). An
/// address outside the configured discovery subnets is left out; with none configured only a
/// private IPv4 address outside the container and overlay ranges is kept (as the inventory does,
/// ADR-910). A record carries no count: a count that changes every minute would write every minute.
pub(crate) fn from_queries(clients: &[([u8; 16], u64)], cfg: &Config, now: i64) -> SourceBatch {
    let subnets: Vec<crate::discovery::sources::Ipv4Subnet> = cfg
        .discovery
        .subnets
        .iter()
        .filter_map(|s| crate::discovery::sources::Ipv4Subnet::parse(&s.cidr.to_string()))
        .collect();
    let mut records: Vec<Record> = Vec::new();
    for (raw, _) in clients {
        let ip = IpAddr::V6(std::net::Ipv6Addr::from(*raw)).to_canonical();
        let IpAddr::V4(v4) = ip else {
            continue;
        };
        let keep = if subnets.is_empty() {
            v4.is_private() && !is_container_range(v4)
        } else {
            subnets.iter().any(|s| s.contains(v4))
        };
        if !keep {
            continue;
        }
        let mut r = Record::new("queries", &v4.to_string(), RecKind::Device, now);
        r.list("addresses", vec![v4.to_string()]);
        records.push(r);
    }
    records.sort_by(|a, b| a.key.cmp(&b.key));
    SourceBatch {
        source: "queries".to_owned(),
        complete: true,
        records,
        at: now,
    }
}

/// A workload of the Kubernetes feature, as the CMDB needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkloadRow {
    pub(crate) namespace: String,
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) addresses: Vec<String>,
}

/// Workloads as device records (role `workload`), only when the Kubernetes feature is on (owner
/// question 15). One complete batch under `k8s`.
pub(crate) fn from_workloads(rows: &[WorkloadRow], now: i64) -> SourceBatch {
    let records = rows
        .iter()
        .map(|w| {
            let key = format!("{}/{}/{}", w.namespace, w.kind, w.name);
            let mut r = Record::new("k8s", &key, RecKind::Device, now);
            r.text("name", format!("{}/{}", w.kind, w.name))
                .text("namespace", w.namespace.clone())
                .text("role", "workload");
            if !w.addresses.is_empty() {
                r.list("addresses", w.addresses.iter().take(16).cloned().collect());
            }
            r
        })
        .collect();
    SourceBatch {
        source: "k8s".to_owned(),
        complete: true,
        records,
        at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::inventory::Hint;

    const NOW: u64 = 1_000_000;

    fn mac(last: u8) -> [u8; 6] {
        [0xaa, 0xbb, 0xcc, 0, 0, last]
    }

    /// REQ: DSC-902, DSC-903 (R4) - a UniFi infrastructure device's serial and stable id are keys, its
    /// ports exist as port records under it, and a client's UniFi `_id` is never a device key.
    #[test]
    fn dsc_903_unifi_keys_are_the_infrastructure_device_not_the_client() {
        let mut sw = Observation::new(Source::Router, NOW);
        sw.mac = Some(mac(1));
        sw.name = Some((NameKind::RouterAlias, "core-switch".into()));
        {
            let h = sw.hint_mut();
            h.device_key = Some("abc123".into());
            h.serial = Some("SN-1234".into());
            h.model = Some("USW-24".into());
        }
        let mut client = Observation::new(Source::Router, NOW);
        client.mac = Some(mac(2));
        client.name = Some((NameKind::RouterAlias, "laptop-anna".into()));
        client.hint_mut().port_ref = Some(("abc123".into(), "port5".into()));
        let recs = records_from_observations(&[sw, client], "unifi:home#devices", secs(NOW));
        let sw_rec = recs.iter().find(|r| r.key == "aa:bb:cc:00:00:01").unwrap();
        assert_eq!(
            sw_rec.attrs["device_key"],
            serde_json::json!("unifi:home#devices|abc123")
        );
        assert_eq!(sw_rec.attrs["serial"], serde_json::json!("SN-1234"));
        let cl = recs.iter().find(|r| r.key == "aa:bb:cc:00:00:02").unwrap();
        assert!(
            !cl.attrs.contains_key("device_key"),
            "a client has no device key: UniFi keys a client by MAC (a client `_id` is never used)"
        );
        let port = recs.iter().find(|r| r.kind == RecKind::Port).unwrap();
        assert_eq!(
            port.attrs["owner"],
            serde_json::json!("unifi:home#devices|abc123")
        );
        assert_eq!(port.attrs["port_id"], serde_json::json!("port5"));
    }

    /// REQ: DSC-902 - observations of one thing merge into one record: the addresses of a MAC are
    /// one list, the first name stays, and an observation with only an address is keyed by it.
    #[test]
    fn dsc_902_observations_merge_into_one_record() {
        let mut a = Observation::new(Source::Router, NOW);
        a.mac = Some(mac(7));
        a.ip = Some("192.168.1.7".parse().unwrap());
        a.name = Some((NameKind::RouterAlias, "printer".into()));
        let mut b = Observation::new(Source::SnmpArp, NOW + 5);
        b.mac = Some(mac(7));
        b.ip = Some("192.168.1.8".parse().unwrap());
        b.name = Some((NameKind::Snmp, "other".into()));
        let mut c = Observation::new(Source::Mdns, NOW);
        c.ip = Some("192.168.1.9".parse().unwrap());
        let recs = records_from_observations(&[a, b, c], "snmp:core", secs(NOW));
        assert_eq!(recs.len(), 2);
        let m = recs.iter().find(|r| r.key == "aa:bb:cc:00:00:07").unwrap();
        assert_eq!(
            m.attrs["addresses"],
            serde_json::json!(["192.168.1.7", "192.168.1.8"])
        );
        assert_eq!(m.attrs["name"], serde_json::json!("printer"));
        assert_eq!(m.attrs["hostname"], serde_json::json!("printer"));
        assert_eq!(m.seen, secs(NOW + 5));
        assert!(
            recs.iter()
                .any(|r| r.key == "ip:192.168.1.9" && !r.attrs.contains_key("mac"))
        );
    }

    /// REQ: DSC-903 (R4) - Home Assistant's device id scopes to the instance, so two instances never
    /// collide, and an SNMP agent's interfaces share one device key.
    #[test]
    fn dsc_903_device_keys_are_scoped_by_their_source_instance() {
        let mut o = Observation::new(Source::HomeAssistant, NOW);
        o.mac = Some(mac(3));
        o.hint = Some(Box::new(Hint {
            device_key: Some("devid1".into()),
            ..Hint::default()
        }));
        let a =
            records_from_observations(std::slice::from_ref(&o), "home_assistant:ha1", secs(NOW));
        let b = records_from_observations(&[o], "home_assistant:ha2", secs(NOW));
        assert_eq!(
            a[0].attrs["device_key"],
            serde_json::json!("home_assistant:ha1|devid1")
        );
        assert_ne!(a[0].attrs["device_key"], b[0].attrs["device_key"]);
    }

    /// REQ: DSC-902 - the configuration gives clients (with MAC and address keys), subnets, upstreams
    /// and this node's listeners; the cluster gives nodes; there is no Pi-hole importer source.
    #[test]
    fn dsc_902_config_and_cluster_sources() {
        let cfg = wrendns_config::Loader::new()
            .toml_str(
                "t",
                r#"
[[group]]
name = "kids"
[[client]]
name = "anna-laptop"
match = ["aa:bb:cc:00:00:09", "192.168.1.30"]
groups = ["kids"]
[[client]]
name = "tablet"
match = ["id:kids-tablet"]
[[discovery.subnet]]
cidr = "192.168.1.0/24"
"#,
            )
            .load()
            .unwrap()
            .config;
        let b = from_config(&cfg, "dns1", secs(NOW));
        assert_eq!(b.source, "config");
        assert!(b.complete);
        let c = b
            .records
            .iter()
            .find(|r| r.key == "client:anna-laptop")
            .unwrap();
        assert_eq!(c.attrs["mac"], serde_json::json!("aa:bb:cc:00:00:09"));
        assert_eq!(c.attrs["addresses"], serde_json::json!(["192.168.1.30"]));
        assert_eq!(c.attrs["member_of"], serde_json::json!(["kids"]));
        let t = b.records.iter().find(|r| r.key == "client:tablet").unwrap();
        assert_eq!(t.attrs["client_ids"], serde_json::json!(["kids-tablet"]));
        assert!(b.records.iter().any(|r| r.kind == RecKind::Network));
        assert!(b.records.iter().any(|r| r.kind == RecKind::Service));
        let nodes = from_cluster(
            &[NodeRow {
                id: "dns1".into(),
                address: "10.0.0.2".into(),
                primary: true,
                version: "0.8.0".into(),
            }],
            secs(NOW),
        );
        assert_eq!(nodes.records[0].attrs["role"], serde_json::json!("primary"));
        assert!(
            b.records
                .iter()
                .chain(nodes.records.iter())
                .all(|r| !r.source.contains("pihole")),
            "no Pi-hole importer source (owner question 14)"
        );
    }

    /// REQ: DSC-902 - the queries source keeps private addresses outside the container ranges (or the
    /// configured subnets), carries no count, and is keyless.
    #[test]
    fn dsc_902_queries_source_is_keyless_and_filtered() {
        let v4 = |s: &str| -> [u8; 16] {
            let ip: Ipv4Addr = s.parse().unwrap();
            ip.to_ipv6_mapped().octets()
        };
        let clients = vec![
            (v4("192.168.1.20"), 40),
            (v4("8.8.8.8"), 3),
            (v4("10.42.0.7"), 9),
            (std::net::Ipv6Addr::LOCALHOST.octets(), 1),
        ];
        let b = from_queries(&clients, &Config::default(), secs(NOW));
        let keys: Vec<&str> = b.records.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, ["192.168.1.20"], "{keys:?}");
        assert!(!b.records[0].attrs.contains_key("count"));
    }

    /// REQ: DSC-902, DSC-903 - a Home Assistant router's devices reach the CMDB through the discovery
    /// poll only: the lease view of the same devices would write a second, disagreeing batch under
    /// the same source name (records flipping between present and absent every minute). Fed both
    /// ways into one engine, nothing is rewritten on the second cycle.
    #[test]
    fn dsc_902_home_assistant_is_one_feed_not_two() {
        use crate::cmdb::engine::test_support::engine;
        let mut view = Leases::new();
        for (n, ip) in [(1u8, "192.168.1.31"), (2, "192.168.1.32")] {
            view.insert(
                ip.parse().unwrap(),
                crate::devices::Lease {
                    mac: format!("aa:bb:cc:00:00:{n:02x}"),
                    ip: ip.parse().unwrap(),
                    hostname: Some(format!("ha-dev-{n}")),
                    expires: 0,
                    router: Some("ha".to_owned()),
                    offline: false,
                    ipv6: Vec::new(),
                },
            );
        }
        let kinds: HashMap<String, &'static str> =
            HashMap::from([("ha".to_owned(), "home_assistant")]);
        let batches = from_lease_view(&view, &kinds, secs(NOW));
        assert!(
            batches
                .iter()
                .all(|b| !b.source.starts_with("home_assistant")),
            "the lease view writes no batch under the Home Assistant name: {:?}",
            batches.iter().map(|b| &b.source).collect::<Vec<_>>()
        );
        // The poll's batch, then the lease view's, twice: the second pass rewrites nothing.
        let mut ha = Vec::new();
        for n in 1u8..=2 {
            let mut o = Observation::new(Source::HomeAssistant, NOW);
            o.mac = Some(mac(n));
            o.hint_mut().device_key = Some(format!("dev{n}"));
            ha.push(o);
        }
        let (_d, mut e) = engine();
        let mut written = 0;
        for cycle in 0..3i64 {
            let at = secs(NOW) + cycle * 60;
            let b = batch_from_observations(&ha, "home_assistant:ha", at);
            let r = e.ingest(b, at).unwrap();
            if cycle > 0 {
                written += r.written + r.went_absent;
            }
            for b in from_lease_view(&view, &kinds, at) {
                let r = e.ingest(b, at).unwrap();
                if cycle > 0 {
                    written += r.written + r.went_absent;
                }
            }
        }
        assert_eq!(written, 0, "no flapping, no rewrites");
    }
}

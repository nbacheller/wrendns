//! REQ: API-013, API-016, API-010, CLU-002 (T24.41) - what a replica shows of the routers.
//!
//! A router whose credential is stored is read by the primary only (ADR-903 section 1), so a
//! replica's own tables hold none of its networks, leases or status. A replica asks the primary
//! for them (the `RouterView` read) and merges them with what it has itself: the networks it is
//! directly on, the names it hears over mDNS, and the routers it reads itself (a credential in a
//! file). Credentials never travel: the view holds results and states, nothing else, and nothing
//! is polled from a replica. A primary that is away, or too old to know the read, leaves the
//! replica's own answer; the caller names the primary as missing.

use serde::{Deserialize, Serialize};
use telltale_api::Backend;
use telltale_api::model::{DhcpLease, NetworkInfo, RouterEntry, RouterStatus};

/// What the node that reads the routers answers: its router networks, router leases and the
/// status of each router. Results only.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(super) struct RouterView {
    pub(super) networks: Vec<NetworkInfo>,
    pub(super) leases: Vec<DhcpLease>,
    /// Each router's status, by name.
    pub(super) statuses: Vec<(String, RouterStatus)>,
}

/// This node's part: what its own reads found (rows from `[[router]]`, not interfaces, groups
/// or mDNS names).
pub(super) fn own_view(b: &dyn Backend) -> RouterView {
    RouterView {
        networks: b
            .networks()
            .into_iter()
            .filter(|n| n.source == "router")
            .collect(),
        leases: b
            .dhcp_leases()
            .into_iter()
            .filter(|l| l.source == "router")
            .collect(),
        statuses: b
            .router_entries()
            .into_iter()
            .map(|e| (e.name, e.status))
            .collect(),
    }
}

/// A replica's networks: the routers' (its own reads first, then the primary's for the
/// subnets it has none for), then the rows only this node has (the networks it is on, a
/// group's) for subnets no router reported.
pub(super) fn merge_networks(
    local: Vec<NetworkInfo>,
    theirs: Vec<NetworkInfo>,
) -> Vec<NetworkInfo> {
    let (mut routed, rest): (Vec<_>, Vec<_>) =
        local.into_iter().partition(|n| n.source == "router");
    for n in theirs.into_iter().filter(|n| n.source == "router") {
        if !routed.iter().any(|r| r.subnet == n.subnet) {
            routed.push(n);
        }
    }
    let reported: Vec<String> = routed.iter().map(|n| n.subnet.clone()).collect();
    routed.extend(rest.into_iter().filter(|n| !reported.contains(&n.subnet)));
    routed
}

fn ip_key(l: &DhcpLease) -> u32 {
    l.ip.parse::<std::net::Ipv4Addr>().map_or(0, u32::from)
}

/// A replica's leases: its own router rows, the primary's for addresses it has none for, and
/// its own mDNS names unless a router names a live device at that address.
pub(super) fn merge_leases(local: Vec<DhcpLease>, theirs: Vec<DhcpLease>) -> Vec<DhcpLease> {
    let mut out = local;
    for l in theirs.into_iter().filter(|l| l.source == "router") {
        if !out.iter().any(|o| o.source == "router" && o.ip == l.ip) {
            out.push(l);
        }
    }
    let live: Vec<String> = out
        .iter()
        .filter(|l| l.source == "router" && !l.offline)
        .map(|l| l.ip.clone())
        .collect();
    out.retain(|l| l.source == "router" || !live.contains(&l.ip));
    out.sort_by_key(ip_key);
    out
}

/// A replica's router list: a router only the primary reads shows the primary's status,
/// labelled with `by` (the primary's name).
pub(super) fn merge_entries(
    mut local: Vec<RouterEntry>,
    theirs: &[(String, RouterStatus)],
    by: &str,
) -> Vec<RouterEntry> {
    for e in &mut local {
        if e.status.polled_by != "the primary" {
            continue;
        }
        if let Some((_, s)) = theirs.iter().find(|(n, _)| *n == e.name) {
            let mut s = s.clone();
            "the primary".clone_into(&mut s.polled_by);
            s.read_by = Some(by.to_owned());
            e.status = s;
        }
    }
    local
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(name: &str, subnet: &str, source: &str) -> NetworkInfo {
        NetworkInfo {
            name: name.into(),
            subnet: subnet.into(),
            vlan: None,
            gateway: None,
            dhcp_start: None,
            dhcp_end: None,
            domain: None,
            purpose: None,
            source: source.into(),
            router: None,
            group: None,
            addresses: 254,
            devices: 0,
            used_percent: 0.0,
            outside_pool: 0,
        }
    }

    fn lease(ip: &str, source: &str, offline: bool) -> DhcpLease {
        DhcpLease {
            mac: String::new(),
            ip: ip.into(),
            hostname: Some(format!("h-{source}")),
            client_name: None,
            expires_unix_seconds: 0,
            source: source.into(),
            router: None,
            dns_name: None,
            offline,
            ipv6: Vec::new(),
        }
    }

    fn status(by: &str, state: &str) -> RouterStatus {
        RouterStatus {
            polled_by: by.into(),
            state: state.into(),
            last_poll: Some(7),
            error: None,
            devices: 12,
            networks: 3,
            interval_secs: 300,
            read_by: None,
        }
    }

    fn entry(name: &str, s: RouterStatus) -> RouterEntry {
        RouterEntry {
            name: name.into(),
            kind: "unifi".into(),
            url: "https://gw".into(),
            source: "api".into(),
            definition: serde_json::Value::Null,
            set_by_file: Vec::new(),
            credentials: Vec::new(),
            status: s,
        }
    }

    // REQ: API-013 (T24.41) - the primary's router networks lead; a replica's interface row is
    // kept only for a subnet no router reported.
    #[test]
    fn api_013_replica_networks_are_the_primarys_plus_its_own() {
        let local = vec![
            net("eth0", "192.168.1.0/24", "interface"),
            net("eth0.100", "198.51.100.0/24", "interface"),
        ];
        let theirs = vec![
            net("LAN", "192.168.1.0/24", "router"),
            net("Kids", "192.168.30.0/24", "router"),
            net("their eth", "10.9.0.0/24", "interface"),
        ];
        let m = merge_networks(local, theirs);
        let names: Vec<&str> = m.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["LAN", "Kids", "eth0.100"]);
    }

    // REQ: API-013 (T24.41) - a router this node reads itself wins over the primary's row.
    #[test]
    fn api_013_own_router_rows_win() {
        let m = merge_networks(
            vec![net("mine", "10.0.0.0/24", "router")],
            vec![net("theirs", "10.0.0.0/24", "router")],
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, "mine");
    }

    // REQ: API-010 (T24.41) - the primary's router clients appear; a local mDNS name at a live
    // router client's address is dropped, one at an unknown address stays.
    #[test]
    fn api_010_replica_leases_merge() {
        let local = vec![
            lease("192.168.1.9", "mdns", false),
            lease("192.168.1.50", "mdns", false),
        ];
        let theirs = vec![
            lease("192.168.1.9", "router", false),
            lease("192.168.1.7", "router", true),
            lease("192.168.1.99", "mdns", false),
        ];
        let m = merge_leases(local, theirs);
        let key: Vec<(&str, &str)> = m
            .iter()
            .map(|l| (l.ip.as_str(), l.source.as_str()))
            .collect();
        assert_eq!(
            key,
            [
                ("192.168.1.7", "router"),
                ("192.168.1.9", "router"),
                ("192.168.1.50", "mdns")
            ]
        );
    }

    // REQ: API-016 (T24.41) - a router only the primary reads shows the primary's status,
    // labelled; one read here, or one the primary doesn't list, is untouched.
    #[test]
    fn api_016_replica_shows_the_primarys_router_status() {
        let local = vec![
            entry("udm", status("the primary", "skipped")),
            entry("file", status("this node", "ok")),
            entry("gone", status("the primary", "skipped")),
        ];
        let theirs = vec![
            ("udm".to_owned(), status("this node", "ok")),
            ("file".to_owned(), status("this node", "failing")),
        ];
        let m = merge_entries(local, &theirs, "pi1");
        assert_eq!(m[0].status.state, "ok");
        assert_eq!(m[0].status.devices, 12);
        assert_eq!(m[0].status.polled_by, "the primary");
        assert_eq!(m[0].status.read_by.as_deref(), Some("pi1"));
        assert_eq!(m[1].status.state, "ok");
        assert_eq!(m[1].status.read_by, None);
        assert_eq!(m[2].status.state, "skipped");
    }

    // REQ: CLU-002 (T24.41, N-1) - the view has no credential field, and an answer from a build
    // without `readBy` still decodes.
    #[test]
    fn clu_002_router_view_wire_form() {
        let v = RouterView {
            networks: vec![net("LAN", "192.168.1.0/24", "router")],
            leases: vec![lease("192.168.1.2", "router", false)],
            statuses: vec![("udm".into(), status("this node", "ok"))],
        };
        let text = serde_json::to_string(&v).unwrap();
        assert!(
            !text.contains("secret") && !text.contains("password"),
            "{text}"
        );
        let back: RouterView = serde_json::from_str(&text).unwrap();
        assert_eq!(back.statuses[0].1.read_by, None);
        assert_eq!(back.networks.len(), 1);
    }
}

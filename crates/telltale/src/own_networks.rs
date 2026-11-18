//! The networks this node is directly on (T24.32), for the Networks page.
//!
//! REQ: API-013, DSC-008 — a node with a tagged VLAN interface for each VLAN (the direct way in
//! docs/running.md "Serving several networks") is on several networks at once. The page lists
//! each, beside the ones a router reports, so an operator sees which networks the node reaches
//! without a router in between. Nothing here is on the DNS path: it runs when the page is asked.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use telltale_net::Ipv4Interface;

/// One network a node is directly on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnNetwork {
    /// The interface name (`eth0.100`).
    pub(crate) name: String,
    pub(crate) subnet: Ipv4Addr,
    pub(crate) prefix: u8,
    /// The VLAN ID, when the kernel says the interface is a tagged VLAN.
    pub(crate) vlan: Option<u16>,
}

/// VLAN IDs by interface name, from the kernel's `/proc/net/vlan/config` (`eth0.100 | 100 | eth0`).
pub(crate) fn vlan_ids(config: &str) -> HashMap<String, u16> {
    config
        .lines()
        .filter_map(|l| {
            let mut f = l.split('|').map(str::trim);
            let name = f.next()?;
            let id = f.next()?.parse::<u16>().ok()?;
            (!name.is_empty()).then(|| (name.to_owned(), id))
        })
        .collect()
}

/// The private IPv4 networks the interfaces are on: containers, bridges and overlays are left out
/// (ADR-910), as are public and link-local addresses, host routes (`/31`, `/32`) and one network
/// seen twice (a VIP on the same subnet as its interface's own address, or two interfaces).
pub(crate) fn from_interfaces(
    ifaces: &[Ipv4Interface],
    vlans: &HashMap<String, u16>,
) -> Vec<OwnNetwork> {
    let mut out: Vec<OwnNetwork> = Vec::new();
    for i in ifaces {
        if crate::discovery::sources::is_container_or_overlay(&i.name) {
            continue;
        }
        for a in &i.addrs {
            if !a.addr.is_private() || !(8..=30).contains(&a.prefix) {
                continue;
            }
            let subnet = Ipv4Addr::from(u32::from(a.addr) & crate::routers::prefix_mask(a.prefix));
            if out
                .iter()
                .any(|n| n.subnet == subnet && n.prefix == a.prefix)
            {
                continue;
            }
            out.push(OwnNetwork {
                name: i.name.clone(),
                subnet,
                prefix: a.prefix,
                vlan: vlans.get(&i.name).copied(),
            });
        }
    }
    out
}

/// Whether the interfaces belong to a container's own network namespace rather than a LAN: a
/// container marker file is present (`/.dockerenv`, `/run/.containerenv`) and the operator has not
/// said the container is on the host network (`TELLTALE_HOST_NETWORK` set). A bridged container's
/// `eth0` holds a private 172.x address that is not a network the node serves devices on.
pub(crate) fn in_container_network(marker_present: bool, host_network_override: bool) -> bool {
    marker_present && !host_network_override
}

/// This node's networks now. Empty in a pod (the pod network is not a LAN), in a container that is
/// not on the host network (ADR-1000), and where the interfaces cannot be read.
pub(crate) fn current() -> Vec<OwnNetwork> {
    if std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() {
        return Vec::new();
    }
    let marker = std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists();
    if in_container_network(marker, std::env::var_os("TELLTALE_HOST_NETWORK").is_some()) {
        return Vec::new();
    }
    let Ok(ifaces) = telltale_net::ipv4_interfaces() else {
        return Vec::new();
    };
    let vlans = std::fs::read_to_string("/proc/net/vlan/config")
        .map(|t| vlan_ids(&t))
        .unwrap_or_default();
    from_interfaces(&ifaces, &vlans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_net::IfaceAddr;

    fn iface(name: &str, idx: u32, addrs: &[([u8; 4], u8)]) -> Ipv4Interface {
        Ipv4Interface {
            name: name.into(),
            ifindex: idx,
            addrs: addrs
                .iter()
                .map(|(ip, p)| IfaceAddr {
                    addr: Ipv4Addr::from(*ip),
                    prefix: *p,
                })
                .collect(),
        }
    }

    // REQ: API-013 (T24.32) — a node on two tagged VLANs lists both, each with its VLAN ID, the
    // untagged network once (its VIP is on the same subnet), and none of the container networks.
    #[test]
    fn api_013_a_node_on_several_networks_lists_each() {
        let ifaces = [
            iface(
                "eth0",
                2,
                &[([192, 0, 2, 12], 24), ([192, 0, 2, 249], 24)],
            ),
            iface(
                "eth0.100",
                3,
                &[([198, 51, 100, 5], 24), ([198, 51, 100, 249], 24)],
            ),
            iface("eth0.200", 4, &[([203, 0, 113, 5], 24)]),
            iface("docker0", 5, &[([172, 17, 0, 1], 16)]),
            iface("wan0", 6, &[([8, 8, 8, 8], 24)]),
            iface("ppp0", 7, &[([10, 1, 1, 1], 32)]),
        ];
        let vlans = vlan_ids(
            "VLAN Dev name\t | VLAN ID\nName-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\n\
             eth0.100       | 100  | eth0\neth0.200       | 200  | eth0\n",
        );
        let n = from_interfaces(&ifaces, &vlans);
        let shown: Vec<(String, String, Option<u16>)> = n
            .iter()
            .map(|n| (n.name.clone(), format!("{}/{}", n.subnet, n.prefix), n.vlan))
            .collect();
        assert_eq!(
            shown,
            [
                ("eth0".into(), "192.0.2.0/24".into(), None),
                ("eth0.100".into(), "198.51.100.0/24".into(), Some(100)),
                ("eth0.200".into(), "203.0.113.0/24".into(), Some(200)),
            ]
        );
    }

    #[test]
    fn api_013_vlan_config_parses_only_rows() {
        let v = vlan_ids("VLAN Dev name | VLAN ID\nName-Type: x\nvlan5 | 5 | eth1\n");
        assert_eq!(v.len(), 1);
        assert_eq!(v.get("vlan5"), Some(&5));
    }
}

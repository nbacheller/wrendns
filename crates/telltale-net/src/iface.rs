//! This node's IPv4 interfaces and their networks, for a node on several networks (T24.32).
//!
//! REQ: DNS-001, DSC-008, CLU-004 — the listeners bind the wildcard address and answer on every
//! interface and VIP; what needs to know the interfaces is what listens on a multicast group
//! (mDNS joins it on each interface, not only the default route's) and the Networks page (it lists
//! the networks this node is directly on). The syscall lives in `sys`; the grouping is safe code.

use std::io;
use std::net::Ipv4Addr;

/// One address on an interface, with its prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfaceAddr {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

/// One up, multicast-capable, non-loopback interface with its IPv4 addresses (a VIP shows as one of
/// them while this node holds it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Interface {
    pub name: String,
    pub ifindex: u32,
    pub addrs: Vec<IfaceAddr>,
}

/// One raw row of `getifaddrs`: an interface's name, index, flags and an IPv4 address.
#[derive(Debug, Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct RawAddr {
    pub name: String,
    pub ifindex: u32,
    pub up: bool,
    pub multicast: bool,
    pub loopback: bool,
    pub addr: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

/// The prefix length of a netmask (the number of leading one bits, at most 32).
pub(crate) fn prefix_len(mask: Ipv4Addr) -> u8 {
    u8::try_from(u32::from(mask).leading_ones()).unwrap_or(32)
}

/// Groups raw rows by interface, keeping only up, multicast-capable, non-loopback ones, in the
/// order the interfaces first appear. Addresses that are 0.0.0.0 are dropped.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn group(rows: Vec<RawAddr>) -> Vec<Ipv4Interface> {
    let mut out: Vec<Ipv4Interface> = Vec::new();
    for r in rows {
        if !r.up || !r.multicast || r.loopback || r.addr.is_unspecified() {
            continue;
        }
        let a = IfaceAddr {
            addr: r.addr,
            prefix: prefix_len(r.netmask),
        };
        match out.iter_mut().find(|i| i.ifindex == r.ifindex) {
            Some(i) => {
                if !i.addrs.contains(&a) {
                    i.addrs.push(a);
                }
            }
            None => out.push(Ipv4Interface {
                name: r.name,
                ifindex: r.ifindex,
                addrs: vec![a],
            }),
        }
    }
    out
}

/// The node's usable IPv4 interfaces. Linux only; elsewhere an empty list.
pub fn ipv4_interfaces() -> io::Result<Vec<Ipv4Interface>> {
    #[cfg(target_os = "linux")]
    {
        crate::sys::interface_addrs().map(group)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, idx: u32, ip: [u8; 4], mask: [u8; 4]) -> RawAddr {
        RawAddr {
            name: name.into(),
            ifindex: idx,
            up: true,
            multicast: true,
            loopback: false,
            addr: Ipv4Addr::from(ip),
            netmask: Ipv4Addr::from(mask),
        }
    }

    // REQ: DNS-001 (T24.32) — a node on a VLAN has one row per interface address; the VIP joins the
    // address list of its interface, and a second VLAN is its own interface.
    #[test]
    fn dns_001_groups_vlan_interfaces_and_vips() {
        let m24 = [255, 255, 255, 0];
        let mut lo = row("lo", 1, [127, 0, 0, 1], [255, 0, 0, 0]);
        lo.loopback = true;
        let mut down = row("eth9", 9, [10, 9, 9, 9], m24);
        down.up = false;
        let mut nomc = row("ppp0", 8, [10, 8, 8, 8], m24);
        nomc.multicast = false;
        let rows = vec![
            lo,
            row("eth0", 2, [192, 0, 2, 12], m24),
            row("eth0.100", 3, [198, 51, 100, 5], m24),
            row("eth0.200", 4, [203, 0, 113, 5], m24),
            // The VIP, held now, on the VLAN 100 interface; and a repeated row.
            row("eth0.100", 3, [198, 51, 100, 249], m24),
            row("eth0.100", 3, [198, 51, 100, 5], m24),
            down,
            nomc,
            row("eth1", 5, [0, 0, 0, 0], m24),
        ];
        let g = group(rows);
        let names: Vec<&str> = g.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["eth0", "eth0.100", "eth0.200"]);
        assert_eq!(g[1].ifindex, 3);
        assert_eq!(
            g[1].addrs,
            [
                IfaceAddr {
                    addr: Ipv4Addr::new(198, 51, 100, 5),
                    prefix: 24
                },
                IfaceAddr {
                    addr: Ipv4Addr::new(198, 51, 100, 249),
                    prefix: 24
                },
            ]
        );
    }

    #[test]
    fn dns_001_prefix_from_netmask() {
        assert_eq!(prefix_len(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(prefix_len(Ipv4Addr::BROADCAST), 32);
        assert_eq!(prefix_len(Ipv4Addr::new(255, 255, 252, 0)), 22);
        assert_eq!(prefix_len(Ipv4Addr::UNSPECIFIED), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dns_001_reads_the_real_interfaces() {
        let v = ipv4_interfaces().unwrap();
        assert!(v.iter().all(|i| i.name != "lo" && !i.addrs.is_empty()));
    }
}

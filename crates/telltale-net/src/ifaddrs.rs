//! This node's own interface addresses (`getifaddrs`), for an upstream's `source` (UPS-013).
//!
//! REQ: UPS-013 (T24.31, ADR-997) — an upstream's source address must be one this node holds,
//! and a network (`198.51.100.0/24`) stands for the address the node holds inside it. The
//! only `unsafe` is the libc call and the walk of its result list.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One address on one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfAddr {
    /// The interface's name (`eth0`, `eth0.100`).
    pub iface: String,
    pub ip: IpAddr,
    /// The prefix length of its netmask.
    pub prefix: u8,
    /// The interface is up.
    pub up: bool,
}

/// Every IPv4 and IPv6 address on this node's interfaces, in the order the kernel lists them.
#[cfg(unix)]
pub fn local_addrs() -> io::Result<Vec<IfAddr>> {
    use std::ffi::CStr;

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is a valid out-pointer; on success the list it receives is freed below.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node of the list `getifaddrs` returned, valid until
        // `freeifaddrs`.
        let e = unsafe { &*cur };
        cur = e.ifa_next;
        if e.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` is non-null and points at a sockaddr whose `sa_family` says which
        // concrete type it is; each cast below is to the type that family names.
        let family = i32::from(unsafe { (*e.ifa_addr).sa_family });
        let (ip, prefix) = if family == libc::AF_INET {
            // SAFETY: AF_INET means a `sockaddr_in`.
            let a = unsafe { &*e.ifa_addr.cast::<libc::sockaddr_in>() };
            let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)));
            let prefix = if e.ifa_netmask.is_null() {
                32
            } else {
                // SAFETY: the netmask of an AF_INET address is a `sockaddr_in` too.
                let m = unsafe { &*e.ifa_netmask.cast::<libc::sockaddr_in>() };
                u8::try_from(u32::from_be(m.sin_addr.s_addr).count_ones()).unwrap_or(32)
            };
            (ip, prefix)
        } else if family == libc::AF_INET6 {
            // SAFETY: AF_INET6 means a `sockaddr_in6`.
            let a = unsafe { &*e.ifa_addr.cast::<libc::sockaddr_in6>() };
            let ip = IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr));
            let prefix = if e.ifa_netmask.is_null() {
                128
            } else {
                // SAFETY: the netmask of an AF_INET6 address is a `sockaddr_in6` too.
                let m = unsafe { &*e.ifa_netmask.cast::<libc::sockaddr_in6>() };
                let ones: u32 = m.sin6_addr.s6_addr.iter().map(|b| b.count_ones()).sum();
                u8::try_from(ones).unwrap_or(128)
            };
            (ip, prefix)
        } else {
            continue;
        };
        let iface = if e.ifa_name.is_null() {
            String::new()
        } else {
            // SAFETY: `ifa_name` is a NUL-terminated string owned by the list.
            unsafe { CStr::from_ptr(e.ifa_name) }
                .to_string_lossy()
                .into_owned()
        };
        #[allow(clippy::unnecessary_cast)] // the flag type differs by libc target
        let up = (e.ifa_flags as u32) & (libc::IFF_UP as u32) != 0;
        out.push(IfAddr {
            iface,
            ip,
            prefix,
            up,
        });
    }
    // SAFETY: `head` came from a successful `getifaddrs` and no reference into the list
    // outlives this point (everything copied out above is owned).
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// Not supported off Unix: no addresses are listed.
#[cfg(not(unix))]
pub fn local_addrs() -> io::Result<Vec<IfAddr>> {
    Ok(Vec::new())
}

#[cfg(all(test, unix))]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// REQ: UPS-013 — the loopback address is always one this node holds.
    #[test]
    fn ups_013_local_addrs_lists_loopback() {
        let all = local_addrs().expect("getifaddrs");
        let lo = all
            .iter()
            .find(|a| a.ip == IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect("127.0.0.1 on the loopback interface");
        assert_eq!(lo.prefix, 8);
        assert!(lo.up);
    }
}

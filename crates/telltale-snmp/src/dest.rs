//! REQ: DSC-001, DSC-003 — SNMP destinations (ADR-907). Every destination is an IPv4 literal
//! inside RFC 1918. Host names, IPv6 literals, loopback, link-local, multicast, broadcast,
//! the shared address space 100.64.0.0/10, and the host's own addresses are refused.

use std::net::Ipv4Addr;

/// Why a destination is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestError {
    /// Not an IPv4 literal (a host name, or IPv6).
    NotIpv4Literal,
    /// Outside RFC 1918.
    NotPrivate,
    /// One of the always-refused ranges.
    Refused,
    /// The host's own address.
    OwnAddress,
}

/// Checks one destination address. `own` lists this host's addresses.
pub fn check(text: &str, own: &[Ipv4Addr]) -> Result<Ipv4Addr, DestError> {
    let addr: Ipv4Addr = text.parse().map_err(|_| DestError::NotIpv4Literal)?;
    check_addr(addr, own)
}

/// Checks a parsed IPv4 address.
pub fn check_addr(addr: Ipv4Addr, own: &[Ipv4Addr]) -> Result<Ipv4Addr, DestError> {
    let o = addr.octets();
    let private = o.first() == Some(&10)
        || (o.first() == Some(&172) && o.get(1).is_some_and(|b| (16..=31).contains(b)))
        || (o.first() == Some(&192) && o.get(1) == Some(&168));
    if !private {
        return Err(DestError::NotPrivate);
    }
    // RFC 1918 overlaps none of these; they are listed so a reader sees every refused range.
    let refused = addr.is_loopback()
        || addr.is_link_local()
        || addr.is_multicast()
        || addr.is_broadcast()
        || addr.is_unspecified()
        || (o.first() == Some(&100) && o.get(1).is_some_and(|b| (64..=127).contains(b)));
    if refused {
        return Err(DestError::Refused);
    }
    if own.contains(&addr) {
        return Err(DestError::OwnAddress);
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsc_001_destinations_must_be_rfc1918_ipv4_literals() {
        let own = [Ipv4Addr::new(192, 168, 1, 50)];
        assert!(check("192.168.1.1", &[]).is_ok());
        assert!(check("10.0.0.7", &[]).is_ok());
        assert!(check("172.16.0.1", &[]).is_ok());
        assert!(check("172.31.255.254", &[]).is_ok());
        assert_eq!(check("172.32.0.1", &[]), Err(DestError::NotPrivate));
        assert_eq!(check("8.8.8.8", &[]), Err(DestError::NotPrivate));
        assert_eq!(check("gateway.example", &[]), Err(DestError::NotIpv4Literal));
        assert_eq!(check("fd00::1", &[]), Err(DestError::NotIpv4Literal));
        assert_eq!(check("::1", &[]), Err(DestError::NotIpv4Literal));
        assert_eq!(check("100.64.0.1", &[]), Err(DestError::NotPrivate));
        assert_eq!(check("192.168.1.50", &own), Err(DestError::OwnAddress));
        assert_eq!(check("127.0.0.1", &[]), Err(DestError::NotPrivate));
        assert_eq!(check("169.254.1.1", &[]), Err(DestError::NotPrivate));
        assert_eq!(check("255.255.255.255", &[]), Err(DestError::NotPrivate));
    }
}

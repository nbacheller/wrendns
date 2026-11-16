//! Special-use names (`spec/03` §3 step 4; RFC 6761, RFC 6303, RFC 9462; ADR-014, ADR-168).

use std::net::IpAddr;
use std::sync::OnceLock;

use telltale_config::{Config, ListenProto, SpecialConfig};
use telltale_proto::{NameBuf, Query, class, rtype};

/// How a special name is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Special {
    /// Answer NXDOMAIN (Firefox canary, `*.invalid`).
    Nxdomain,
    /// Answer REFUSED (CHAOS-class queries such as `version.bind`).
    Refused,
    /// Answer with loopback addresses (`localhost`, RFC 6761 §6.3).
    Localhost,
    /// Reverse lookup for a private address: NXDOMAIN unless local data or a route covers it.
    PrivatePtr,
    /// REQ: DNS-019 (ADR-168) — iCloud Private Relay's names: NXDOMAIN, so Apple devices
    /// turn Private Relay off on this network.
    PrivateRelay,
    /// REQ: DNS-019 (ADR-168) — `resolver.arpa` (RFC 9462): our DDR records for
    /// `_dns.resolver.arpa` SVCB, else no data. Never forwarded.
    ResolverArpa,
    /// REQ: DNS-019 (ADR-168) — a single-label name (`domain-needed`): NXDOMAIN unless local
    /// data or a route covers it.
    SingleLabel,
}

struct Names {
    canary: NameBuf,
    relay: NameBuf,
    relay_h2: NameBuf,
    resolver_arpa: NameBuf,
    ddr: NameBuf,
    in_addr: NameBuf,
    ip6: NameBuf,
}

fn names() -> &'static Names {
    static N: OnceLock<Names> = OnceLock::new();
    N.get_or_init(|| {
        let n = |s: &str| NameBuf::from_presentation(s).unwrap_or_default();
        Names {
            canary: n("use-application-dns.net"),
            relay: n("mask.icloud.com"),
            relay_h2: n("mask-h2.icloud.com"),
            resolver_arpa: n("resolver.arpa"),
            ddr: n("_dns.resolver.arpa"),
            in_addr: n("in-addr.arpa"),
            ip6: n("ip6.arpa"),
        }
    })
}

/// The last (top-level) label of a wire-format name and the number of labels; the root
/// has no label and a count of 0.
fn top_label(wire: &[u8]) -> (&[u8], usize) {
    let (mut pos, mut count, mut top) = (0usize, 0usize, &[][..]);
    while let Some(&len) = wire.get(pos) {
        if len == 0 {
            break;
        }
        let start = pos + 1;
        pos = start + usize::from(len);
        top = wire.get(start..pos).unwrap_or_default();
        count += 1;
    }
    (top, count)
}

/// Classifies `q`; `None` for ordinary names. Allocation-free: one walk over the labels finds
/// the top-level label, and each rule then costs a comparison only for names under its own
/// top-level label (`02` §3).
pub fn classify(q: &Query<'_>, cfg: &SpecialConfig) -> Option<Special> {
    if cfg.refuse_chaos && q.qclass == class::CH {
        return Some(Special::Refused);
    }
    let n = names();
    let name = &q.qname;
    let (top, labels) = top_label(name.as_wire());
    let hit = match top {
        b"net" if cfg.block_firefox_canary && *name == n.canary => Some(Special::Nxdomain),
        // REQ: DNS-019 (ADR-168) — iCloud Private Relay, the two names Apple documents.
        b"com" if cfg.block_icloud_private_relay && (*name == n.relay || *name == n.relay_h2) => {
            Some(Special::PrivateRelay)
        }
        b"invalid" => Some(Special::Nxdomain),
        b"localhost" if cfg.localhost => Some(Special::Localhost),
        // REQ: DNS-019 (ADR-168) — RFC 9462 §6.5: resolver.arpa stays here.
        b"arpa" if name.is_subdomain_of(&n.resolver_arpa) => Some(Special::ResolverArpa),
        b"arpa" if cfg.private_ptr_nxdomain && is_private_reverse(name, n) => {
            Some(Special::PrivatePtr)
        }
        _ => None,
    };
    if hit.is_some() {
        return hit;
    }
    // REQ: DNS-019 (ADR-168) — domain-needed: host lookups of a bare name.
    (cfg.single_label_nxdomain
        && labels == 1
        && matches!(q.qtype, rtype::A | rtype::AAAA | rtype::HTTPS))
    .then_some(Special::SingleLabel)
}

/// REQ: DNS-019 (ADR-168) — true for the DDR question itself: `_dns.resolver.arpa` SVCB.
pub fn is_ddr_query(q: &Query<'_>) -> bool {
    q.qtype == rtype::SVCB && q.qname == names().ddr
}

/// REQ: DNS-019 (ADR-168) — Discovery of Designated Resolvers (RFC 9462, RFC 9461): one
/// SVCB record (RDATA) per DoT, DoH, DoH3, and DoQ listener of this node, in listener order
/// (priority 1, 2, ...), targeting `[special] ddr_name`. Empty without a name or encrypted
/// listeners. Built off the query path, when the policy is.
pub fn ddr_records(cfg: &Config) -> Vec<Box<[u8]>> {
    let Some(target) = cfg
        .special
        .ddr_name
        .as_ref()
        .and_then(|n| NameBuf::from_presentation(n).ok())
        .filter(|n| !n.is_root())
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for l in cfg.listen.iter().filter(|l| l.proto.needs_tls()) {
        let Ok(priority) = u16::try_from(out.len() + 1) else {
            break;
        };
        let alpn: &[u8] = match l.proto {
            ListenProto::Dot => b"dot",
            ListenProto::Doh => b"h2",
            ListenProto::Doh3 => b"h3",
            ListenProto::Doq => b"doq",
            ListenProto::Udp | ListenProto::Tcp => continue,
        };
        let mut r = Vec::with_capacity(64);
        r.extend_from_slice(&priority.to_be_bytes());
        r.extend_from_slice(target.as_wire());
        // SvcParams in increasing key order (RFC 9460 §2.2).
        let mut alpn_value = vec![u8::try_from(alpn.len()).unwrap_or(0)];
        alpn_value.extend_from_slice(alpn);
        svc_param(&mut r, 1, &alpn_value);
        svc_param(&mut r, 3, &l.addr.port().to_be_bytes());
        // A hint only for an address clients can reach: not `0.0.0.0`, `::`, or loopback.
        let ip = l.addr.ip();
        if !ip.is_unspecified() && !ip.is_loopback() {
            match ip {
                IpAddr::V4(v4) => svc_param(&mut r, 4, &v4.octets()),
                IpAddr::V6(v6) => svc_param(&mut r, 6, &v6.octets()),
            }
        }
        if l.proto.is_http() {
            // RFC 9461 §5: the DoH URI template's path (the listener's, `/dns-query` by default).
            let path = l.path.as_deref().unwrap_or("/dns-query");
            let template = format!("{path}{{?dns}}");
            svc_param(&mut r, 7, template.as_bytes());
        }
        out.push(r.into_boxed_slice());
    }
    out
}

fn svc_param(r: &mut Vec<u8>, key: u16, value: &[u8]) {
    r.extend_from_slice(&key.to_be_bytes());
    r.extend_from_slice(&u16::try_from(value.len()).unwrap_or(0).to_be_bytes());
    r.extend_from_slice(value);
}

/// True for reverse names inside private/local address space (RFC 6303 locally served zones:
/// `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `169.254/16`, `127/8`, `0/8`; `fc00::/7`,
/// `fe80::/10`, `::1`).
fn is_private_reverse(name: &NameBuf, n: &Names) -> bool {
    let count = name.labels().count();
    // k = 0 is the last label ("arpa"), k = 1 "in-addr"/"ip6", k = 2 the most significant part.
    let from_end = |k: usize| name.labels().nth(count.checked_sub(k + 1)?);
    if name.is_subdomain_of(&n.in_addr) {
        let octet = |k| from_end(k).and_then(|l| std::str::from_utf8(l).ok()?.parse::<u8>().ok());
        return match (octet(2), octet(3)) {
            (Some(10 | 127 | 0), _) | (Some(192), Some(168)) | (Some(169), Some(254)) => true,
            (Some(172), Some(b)) => (16..=31).contains(&b),
            (Some(100), Some(b)) => (64..=127).contains(&b),
            _ => false,
        };
    }
    if name.is_subdomain_of(&n.ip6) {
        let nibble = |k| {
            from_end(k).and_then(|l| match l {
                [c] => char::from(*c).to_digit(16),
                _ => None,
            })
        };
        let (a, b, c) = (nibble(2), nibble(3), nibble(4));
        if a == Some(0xf) && matches!(b, Some(0xc | 0xd)) {
            return true; // fc00::/7
        }
        if a == Some(0xf) && b == Some(0xe) && matches!(c, Some(0x8..=0xb)) {
            return true; // fe80::/10
        }
        // ::1 — 32 nibble labels, least significant first: "1" then 31 × "0".
        return count == 34
            && name.labels().take(32).enumerate().all(|(i, l)| {
                l == if i == 0 {
                    b"1".as_slice()
                } else {
                    b"0".as_slice()
                }
            });
    }
    false
}

#[cfg(test)]
mod tests {
    use telltale_proto::{build_query, parse_query, rtype};

    use super::*;

    fn classify_name(name: &str, qclass: u16) -> Option<Special> {
        classify_with(name, rtype::A, qclass, &SpecialConfig::default())
    }

    fn classify_with(name: &str, qtype: u16, qclass: u16, cfg: &SpecialConfig) -> Option<Special> {
        let mut buf = [0u8; 512];
        let n = NameBuf::from_presentation(name).unwrap();
        let len = build_query(&mut buf, 1, &n, qtype, qclass, true, None).unwrap();
        let q = parse_query(&buf[..len]).unwrap();
        classify(&q, cfg)
    }

    /// REQ: DNS-019 (ADR-168) — iCloud Private Relay's two names are NXDOMAIN by default, and
    /// resolve normally with the switch off; other icloud.com names are never touched.
    #[test]
    fn dns_019_icloud_private_relay() {
        let on = SpecialConfig::default();
        for name in ["mask.icloud.com", "MASK-H2.icloud.com"] {
            assert_eq!(
                classify_with(name, rtype::A, 1, &on),
                Some(Special::PrivateRelay),
                "{name}"
            );
            assert_eq!(
                classify_with(name, rtype::HTTPS, 1, &on),
                Some(Special::PrivateRelay),
                "{name} HTTPS"
            );
        }
        for name in [
            "icloud.com",
            "www.icloud.com",
            "x.mask.icloud.com",
            "mask.icloud.net",
        ] {
            assert_eq!(classify_with(name, rtype::A, 1, &on), None, "{name}");
        }
        let off = SpecialConfig {
            block_icloud_private_relay: false,
            ..SpecialConfig::default()
        };
        assert_eq!(classify_with("mask.icloud.com", rtype::A, 1, &off), None);
    }

    /// REQ: DNS-019 (ADR-168) — every name in resolver.arpa stays local (RFC 9462 §6.5),
    /// whatever the other switches say; only `_dns.resolver.arpa` SVCB is the DDR question.
    #[test]
    fn dns_019_resolver_arpa_stays_local() {
        let off = SpecialConfig {
            private_ptr_nxdomain: false,
            ..SpecialConfig::default()
        };
        for name in ["resolver.arpa", "_dns.resolver.arpa", "x.y.resolver.arpa"] {
            assert_eq!(
                classify_with(name, rtype::SVCB, 1, &off),
                Some(Special::ResolverArpa),
                "{name}"
            );
        }
        assert_eq!(classify_name("resolver.arpa.example", 1), None);
        assert_eq!(classify_name("notresolver.arpa", 1), None);
        let ask = |name: &str, qtype| {
            let mut buf = [0u8; 512];
            let n = NameBuf::from_presentation(name).unwrap();
            let len = build_query(&mut buf, 1, &n, qtype, 1, true, None).unwrap();
            is_ddr_query(&parse_query(&buf[..len]).unwrap())
        };
        assert!(ask("_dns.resolver.arpa", rtype::SVCB));
        assert!(!ask("_dns.resolver.arpa", rtype::A));
        assert!(!ask("x._dns.resolver.arpa", rtype::SVCB));
    }

    /// REQ: DNS-019 (ADR-168) — domain-needed: off by default; on, host lookups (A, AAAA,
    /// HTTPS) of a bare name, never names with a dot, the root, or a TLD's DS or NS.
    #[test]
    fn dns_019_single_label_names() {
        assert_eq!(classify_name("nas", 1), None, "off by default");
        let on = SpecialConfig {
            single_label_nxdomain: true,
            ..SpecialConfig::default()
        };
        for qtype in [rtype::A, rtype::AAAA, rtype::HTTPS] {
            assert_eq!(
                classify_with("nas", qtype, 1, &on),
                Some(Special::SingleLabel)
            );
        }
        for qtype in [rtype::DS, rtype::NS, rtype::SOA, rtype::DNSKEY, rtype::TXT] {
            assert_eq!(classify_with("com", qtype, 1, &on), None, "type {qtype}");
        }
        assert_eq!(classify_with("nas.lan", rtype::A, 1, &on), None);
        assert_eq!(classify_with(".", rtype::A, 1, &on), None);
        // The RFC 6761 names keep their own answers.
        assert_eq!(
            classify_with("localhost", rtype::A, 1, &on),
            Some(Special::Localhost)
        );
        assert_eq!(
            classify_with("invalid", rtype::A, 1, &on),
            Some(Special::Nxdomain)
        );
    }

    fn ddr_config(toml: &str) -> Config {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config
    }

    /// REQ: DNS-019 (ADR-168) — DDR records: one SVCB per encrypted listener, in order, with
    /// its ALPN, port, a hint for a specific address, and the DoH path template.
    #[test]
    fn dns_019_ddr_records_encode_the_listeners() {
        let tls = "tls = { cert = \"/c.pem\", key = \"/k.pem\" }";
        let cfg = ddr_config(&format!(
            "[[listen]]\nproto = \"udp\"\naddr = \"0.0.0.0:53\"\n\
             [[listen]]\nproto = \"dot\"\naddr = \"0.0.0.0:853\"\n{tls}\n\
             [[listen]]\nproto = \"doh\"\naddr = \"192.168.1.2:443\"\npath = \"/q\"\n{tls}\n\
             [special]\nddr_name = \"dns.example.com\"\n"
        ));
        let r = ddr_records(&cfg);
        assert_eq!(r.len(), 2, "udp isn't advertised");
        let target = b"\x03dns\x07example\x03com\x00";
        let mut dot = vec![0, 1];
        dot.extend_from_slice(target);
        dot.extend_from_slice(b"\x00\x01\x00\x04\x03dot\x00\x03\x00\x02\x03\x55");
        assert_eq!(&*r[0], dot.as_slice());
        let mut doh = vec![0, 2];
        doh.extend_from_slice(target);
        doh.extend_from_slice(b"\x00\x01\x00\x03\x02h2\x00\x03\x00\x02\x01\xbb");
        doh.extend_from_slice(b"\x00\x04\x00\x04\xc0\xa8\x01\x02");
        doh.extend_from_slice(b"\x00\x07\x00\x08/q{?dns}");
        assert_eq!(&*r[1], doh.as_slice());

        // No name: nothing to advertise.
        let cfg = ddr_config(&format!(
            "[[listen]]\nproto = \"dot\"\naddr = \"0.0.0.0:853\"\n{tls}\n"
        ));
        assert_eq!(ddr_records(&cfg), Vec::<Box<[u8]>>::new());
    }

    #[test]
    fn dns_019_special_names() {
        assert_eq!(
            classify_name("use-application-dns.net", 1),
            Some(Special::Nxdomain)
        );
        assert_eq!(classify_name("foo.invalid", 1), Some(Special::Nxdomain));
        assert_eq!(classify_name("localhost", 1), Some(Special::Localhost));
        assert_eq!(classify_name("app.localhost", 1), Some(Special::Localhost));
        assert_eq!(
            classify_name("version.bind", class::CH),
            Some(Special::Refused)
        );
        assert_eq!(classify_name("example.com", 1), None);
        assert_eq!(
            classify_name("printer.local", 1),
            None,
            ".local is left alone"
        );
    }

    #[test]
    fn dns_019_private_reverse_zones() {
        for private in [
            "1.1.168.192.in-addr.arpa",
            "5.0.0.10.in-addr.arpa",
            "1.0.20.172.in-addr.arpa",
            "9.9.64.100.in-addr.arpa",
            "168.192.in-addr.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
        ] {
            assert_eq!(
                classify_name(private, 1),
                Some(Special::PrivatePtr),
                "{private}"
            );
        }
        for public in [
            "8.8.8.8.in-addr.arpa",
            "1.0.32.172.in-addr.arpa",
            "1.0.0.2.ip6.arpa",
        ] {
            assert_eq!(classify_name(public, 1), None, "{public}");
        }
    }
}

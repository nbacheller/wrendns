//! `telltale import pihole --compare` (REQ: API-007, T24.6; ADR-941): resolves a sample of names
//! through the Pi-hole and through TelltaleDNS and reports where the answers differ. A and AAAA
//! are asked of both servers; TTLs are ignored, and the addresses and names of the answer are
//! compared as sets.
//!
//! The client is plain UDP with a short timeout and no retries: it only has to tell two
//! servers apart, and it never sends anything but standard queries.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use serde::Serialize;
use telltale_proto::{NameBuf, Section, rtype};

/// How long one server has to answer one query.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(2);
/// Most names compared in one run (each costs two queries per server).
pub(crate) const MAX_NAMES: usize = 200;
/// A server that doesn't answer this many queries in a row is unreachable; stop asking it.
const GIVE_UP_AFTER: u32 = 5;
/// The whole comparison's time (REQ: API-007, ADR-941). A server that answers every other query
/// keeps the silent count at zero, so without this a request could run for half an hour.
pub(crate) const BUDGET: Duration = Duration::from_secs(60);

/// One server's answer, reduced to what matters for a comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Answer {
    /// `NOERROR`, `NXDOMAIN`, ..., or `no answer`.
    pub rcode: String,
    /// The answer's addresses and names, sorted.
    pub values: Vec<String>,
}

impl Answer {
    fn none() -> Self {
        Self {
            rcode: "no answer".into(),
            values: Vec::new(),
        }
    }
}

/// A name whose answers differ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Difference {
    pub name: String,
    pub qtype: &'static str,
    pub pihole: Answer,
    pub telltale: Answer,
}

/// The whole comparison.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Report {
    /// Names compared.
    pub names: usize,
    /// Names whose A and AAAA answers were the same on both servers.
    pub agree: usize,
    pub differences: Vec<Difference>,
    /// Problems that stopped the comparison early (an unreachable server, a bad name).
    pub errors: Vec<String>,
}

/// The rcode's name, as `dig` prints it.
fn rcode_name(code: u8) -> String {
    match code {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        n => format!("RCODE{n}"),
    }
}

/// One query to `server` for `name`/`qtype`, answered in time, or why not.
pub(crate) fn ask(server: SocketAddr, name: &str, qtype: u16, id: u16) -> Result<Answer, String> {
    let nb = NameBuf::from_presentation(name).map_err(|_| format!("`{name}` isn't a DNS name"))?;
    let mut query = [0u8; 512];
    let len = telltale_proto::build_query(&mut query, id, &nb, qtype, 1, true, None)
        .map_err(|_| format!("`{name}` is too long to ask"))?;
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    sock.connect(server).map_err(|e| e.to_string())?;
    sock.send(&query[..len]).map_err(|e| e.to_string())?;
    let mut resp = [0u8; 4096];
    // Stray answers (another ID) are skipped until the deadline.
    loop {
        let n = sock
            .recv(&mut resp)
            .map_err(|_| "no answer in time".to_owned())?;
        let msg = &resp[..n];
        if msg.len() < telltale_proto::HEADER_LEN || telltale_proto::header::id(msg) != id {
            continue;
        }
        return answer_of(msg);
    }
}

/// The rcode and sorted values of a response.
fn answer_of(msg: &[u8]) -> Result<Answer, String> {
    let header = telltale_proto::Header::parse(msg).ok_or("a short answer")?;
    let rcode = rcode_name(header.flags.rcode());
    let mut values = Vec::new();
    for r in telltale_proto::records(msg).map_err(|e| format!("{e:?}"))? {
        let r = r.map_err(|e| format!("{e:?}"))?;
        if r.section != Section::Answer {
            continue;
        }
        let rd = r.rdata(msg);
        match r.rtype {
            t if t == rtype::A => {
                if let Ok(b) = <[u8; 4]>::try_from(rd) {
                    values.push(Ipv4Addr::from(b).to_string());
                }
            }
            t if t == rtype::AAAA => {
                if let Ok(b) = <[u8; 16]>::try_from(rd) {
                    values.push(Ipv6Addr::from(b).to_string());
                }
            }
            t if t == rtype::CNAME => {
                let mut out = NameBuf::default();
                if telltale_proto::read_name(msg, r.rdata_off, &mut out).is_ok() {
                    values.push(out.display().to_string());
                }
            }
            _ => {}
        }
    }
    values.sort();
    Ok(Answer { rcode, values })
}

/// Resolves `names` (A and AAAA each) through both servers and reports the differences.
pub(crate) fn compare(pihole: SocketAddr, telltale: SocketAddr, names: &[String]) -> Report {
    let mut rep = Report::default();
    let mut seen = std::collections::HashSet::new();
    let names: Vec<&String> = names
        .iter()
        .filter(|n| seen.insert(n.to_ascii_lowercase()))
        .take(MAX_NAMES)
        .collect();
    let mut failures = [0u32; 2];
    let servers = [("Pi-hole", pihole), ("TelltaleDNS", telltale)];
    let started = std::time::Instant::now();
    for (i, name) in names.iter().enumerate() {
        if started.elapsed() > BUDGET {
            rep.errors.push(format!(
                "the comparison ran out of its {} seconds after {} names; the rest weren't compared",
                BUDGET.as_secs(),
                rep.names
            ));
            break;
        }
        rep.names += 1;
        let mut agree = true;
        for (qtype, label) in [(rtype::A, "A"), (rtype::AAAA, "AAAA")] {
            let mut got = [Answer::none(), Answer::none()];
            for (side, (who, addr)) in servers.iter().enumerate() {
                if failures[side] >= GIVE_UP_AFTER {
                    continue;
                }
                let id = u16::try_from(i).unwrap_or(0).wrapping_mul(7919) ^ qtype;
                match ask(*addr, name, qtype, id) {
                    Ok(a) => {
                        failures[side] = 0;
                        got[side] = a;
                    }
                    Err(e) => {
                        failures[side] += 1;
                        if failures[side] == GIVE_UP_AFTER {
                            rep.errors.push(format!(
                                "{who} at {addr} didn't answer {GIVE_UP_AFTER} queries in a row ({e}); the comparison stopped asking it"
                            ));
                        }
                    }
                }
            }
            let [p, t] = got;
            if p != t {
                agree = false;
                rep.differences.push(Difference {
                    name: name.as_str().to_owned(),
                    qtype: label,
                    pihole: p,
                    telltale: t,
                });
            }
        }
        if agree {
            rep.agree += 1;
        }
        if failures.iter().all(|&f| f >= GIVE_UP_AFTER) {
            rep.errors
                .push("neither server answers; nothing was compared past this point".into());
            break;
        }
    }
    rep
}

/// `ip` or `ip:port` (port 53 when omitted), IPv6 in brackets with a port.
pub(crate) fn parse_server(s: &str) -> Result<SocketAddr, String> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    s.parse::<std::net::IpAddr>()
        .map(|ip| SocketAddr::new(ip, 53))
        .map_err(|_| format!("`{s}` isn't an address like 192.168.1.2 or 192.168.1.2:5353"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake server answering from `answers` (name → A addresses); unknown names are NXDOMAIN.
    fn fake(answers: &'static [(&'static str, &'static str)]) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut b = [0u8; 512];
            while let Ok((n, from)) = sock.recv_from(&mut b) {
                let q = telltale_proto::parse_query(&b[..n]).unwrap();
                let qname = q.qname.display().to_string();
                let qname = qname.trim_end_matches('.');
                let hit = answers.iter().find(|(k, _)| *k == qname);
                let mut out = [0u8; 512];
                let mut w = telltale_proto::ResponseBuilder::new(
                    &q,
                    &mut out,
                    if hit.is_some() {
                        telltale_proto::rcode::NOERROR
                    } else {
                        telltale_proto::rcode::NXDOMAIN
                    },
                )
                .unwrap();
                if let (Some((_, ip)), true) = (hit, q.qtype == rtype::A) {
                    w.answer_a(60, ip.parse().unwrap()).unwrap();
                }
                let len = w.finish(None).unwrap();
                let _ = sock.send_to(&out[..len], from);
            }
        });
        addr
    }

    // REQ: API-007 (T24.6) — a difference is reported, and agreement is counted.
    #[test]
    fn api_007_compare_reports_differences() {
        let pihole = fake(&[("nas.lan", "192.168.1.10"), ("only.pihole", "10.0.0.1")]);
        let ours = fake(&[("nas.lan", "192.168.1.10")]);
        let names = vec!["nas.lan".to_owned(), "only.pihole".to_owned()];
        let rep = compare(pihole, ours, &names);
        assert_eq!(rep.names, 2, "{rep:?}");
        assert_eq!(rep.agree, 1, "{rep:?}");
        // A differs (an address against NXDOMAIN); AAAA differs too (NODATA against NXDOMAIN).
        assert_eq!(rep.differences.len(), 2, "{rep:?}");
        let d = rep
            .differences
            .iter()
            .find(|d| d.qtype == "A")
            .expect("the A difference");
        assert_eq!(d.name, "only.pihole");
        assert_eq!(d.pihole.values, ["10.0.0.1"]);
        assert_eq!(d.telltale.rcode, "NXDOMAIN");
    }

    // REQ: API-007 (T24.6) — an address that doesn't answer is named, and asking stops.
    #[test]
    fn api_007_compare_gives_up_on_a_silent_server() {
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = silent.local_addr().unwrap();
        let ours = fake(&[]);
        let names: Vec<String> = (0..3).map(|i| format!("n{i}.lan")).collect();
        let rep = compare(addr, ours, &names);
        assert!(
            rep.errors.iter().any(|e| e.contains("didn't answer")),
            "{rep:?}"
        );
    }

    #[test]
    fn api_007_parse_server_defaults_the_port() {
        assert_eq!(parse_server("192.168.1.2").unwrap().port(), 53);
        assert_eq!(parse_server("192.168.1.2:5353").unwrap().port(), 5353);
        assert!(parse_server("nas.lan").is_err());
    }
}

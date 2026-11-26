//! What the resolver remembers between queries (REQ: DNS-012), all bounded: zone cuts and
//! their servers (from referrals), server-name addresses, and each server's smoothed RTT.
//! Final answers aren't kept here: the server's answer cache holds them.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use wrendns_proto::NameBuf;

/// Entries per table before the expired (then the oldest) are dropped.
const MAX_ENTRIES: usize = 20_000;
/// TTL bounds for delegations and addresses.
const MIN_TTL: Duration = Duration::from_secs(30);
const MAX_TTL: Duration = Duration::from_hours(24);

pub(crate) fn ttl(secs: u32) -> Duration {
    Duration::from_secs(u64::from(secs)).clamp(MIN_TTL, MAX_TTL)
}

/// A zone cut: the zone's server names and the addresses known for them.
#[derive(Debug, Clone)]
pub(crate) struct Delegation {
    pub(crate) ns: Vec<NameBuf>,
    pub(crate) addrs: Vec<IpAddr>,
    expires: Instant,
}

#[derive(Debug)]
struct Table<V> {
    map: HashMap<NameBuf, V>,
}

impl<V> Default for Table<V> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

fn prune<V>(map: &mut HashMap<NameBuf, V>, expired: impl Fn(&V) -> bool) {
    if map.len() < MAX_ENTRIES {
        return;
    }
    map.retain(|_, v| !expired(v));
    if map.len() >= MAX_ENTRIES {
        // Still full of live entries: drop an arbitrary half rather than grow.
        let drop: Vec<NameBuf> = map.keys().take(map.len() / 2).copied().collect();
        for k in drop {
            map.remove(&k);
        }
    }
}

/// REQ: DNS-903 — the infrastructure cache's limits.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Infra {
    /// How long an entry is kept after it was last updated (Unbound's `infra-host-ttl`).
    pub(crate) ttl: Duration,
    /// How often a server that was timing out is asked again though others sort ahead of it.
    pub(crate) probe: Duration,
    /// Entries kept (Unbound's `infra-cache-numhosts`).
    pub(crate) max_hosts: usize,
}

impl Default for Infra {
    fn default() -> Self {
        Self {
            ttl: Duration::from_mins(15),
            probe: Duration::from_secs(10),
            max_hosts: MAX_ENTRIES,
        }
    }
}

/// What is known of one server (REQ: DNS-012, DNS-902, DNS-903): its smoothed RTT in
/// microseconds, and what its answers have shown. Unknown servers start optimistic, so each
/// gets tried. An entry lives `Infra::ttl` after its last update, then the server is a
/// stranger again.
#[derive(Debug, Clone, Copy)]
struct Rtt {
    srtt_us: u32,
    /// Leaves 0x20 off for this server (it doesn't echo the letter case).
    no_case: bool,
    /// Asked without EDNS until then: it answered FORMERR or NOTIMP to a query with it and
    /// answered one without. Set once; a busy server's entry does not renew it.
    no_edns_until: Option<Instant>,
    /// It has answered a query with EDNS with an OPT record of its own.
    edns_ok: bool,
    /// It has given a usable answer since the entry began.
    answered: bool,
    /// Consecutive UDP queries it didn't answer in time.
    udp_timeouts: u8,
    /// Consecutive queries (any transport) it didn't answer in time: a server with any is down,
    /// sorts last, and is asked now and then (`Infra::probe`) to see whether it is back; one
    /// that is sorted last and never asked would never be found to have recovered.
    timeouts: u8,
    /// Until then its queries go over TCP first (its UDP went unanswered, its TCP didn't).
    tcp_until: Option<Instant>,
    /// When a down server is next asked ahead of the others.
    probe_at: Instant,
    expires: Instant,
}

impl Rtt {
    fn fresh(srtt_us: u32, infra: &Infra) -> Self {
        let now = Instant::now();
        Self {
            srtt_us,
            no_case: false,
            no_edns_until: None,
            edns_ok: false,
            answered: false,
            udp_timeouts: 0,
            timeouts: 0,
            tcp_until: None,
            probe_at: now,
            expires: now + infra.ttl,
        }
    }

    fn down(&self) -> bool {
        self.timeouts >= 1
    }
}

/// One server as `order` hands it out.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Server {
    pub(crate) ip: IpAddr,
    /// `None`: never asked (or forgotten), or being probed.
    pub(crate) srtt_us: Option<u32>,
    pub(crate) no_case: bool,
    pub(crate) no_edns: bool,
    /// Ask over TCP first.
    pub(crate) tcp: bool,
}

/// How a failed query failed, for the infrastructure cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// No answer in time, or none possible (the connection was refused).
    Timeout { tcp: bool },
    /// A lame, unreadable or refused answer.
    Lame,
}

#[derive(Debug, Default)]
pub(crate) struct Caches {
    zones: Mutex<Table<Delegation>>,
    addrs: Mutex<Table<(Vec<IpAddr>, Instant)>>,
    rtt: Mutex<HashMap<IpAddr, Rtt>>,
    infra: Infra,
}

/// EWMA, 0.3 new / 0.7 old.
fn ewma(old: u32, sample: u32) -> u32 {
    u32::try_from((u64::from(old) * 7 + u64::from(sample) * 3) / 10).unwrap_or(u32::MAX)
}

impl Caches {
    pub(crate) fn new(infra: Infra) -> Self {
        Self {
            infra,
            ..Self::default()
        }
    }

    /// The deepest cached zone cut at or above `name` with addresses, skipping `name` itself
    /// when `parent_only` (DS records live in the parent).
    pub(crate) fn closest(
        &self,
        name: &NameBuf,
        parent_only: bool,
    ) -> Option<(NameBuf, Delegation)> {
        let now = Instant::now();
        let zones = self.zones.lock();
        let wire = name.as_wire();
        let mut pos = 0usize;
        let mut first = true;
        loop {
            let mut z = NameBuf::default();
            wrendns_proto::read_name(wire, pos, &mut z).ok()?;
            if !(first && parent_only)
                && let Some(d) = zones.map.get(&z)
                && d.expires > now
            {
                return Some((z, d.clone()));
            }
            first = false;
            let len = usize::from(*wire.get(pos)?);
            if len == 0 {
                return None;
            }
            pos += 1 + len;
        }
    }

    pub(crate) fn put_zone(&self, zone: NameBuf, ns: Vec<NameBuf>, addrs: Vec<IpAddr>, ttl_s: u32) {
        let mut z = self.zones.lock();
        let now = Instant::now();
        prune(&mut z.map, |d: &Delegation| d.expires <= now);
        z.map.insert(
            zone,
            Delegation {
                ns,
                addrs,
                expires: now + ttl(ttl_s),
            },
        );
    }

    /// Adds addresses to a cached zone cut (found for its server names later).
    pub(crate) fn add_zone_addrs(&self, zone: &NameBuf, addrs: &[IpAddr]) {
        if let Some(d) = self.zones.lock().map.get_mut(zone) {
            for a in addrs {
                if !d.addrs.contains(a) {
                    d.addrs.push(*a);
                }
            }
        }
    }

    pub(crate) fn addrs(&self, name: &NameBuf) -> Option<Vec<IpAddr>> {
        let a = self.addrs.lock();
        a.map
            .get(name)
            .filter(|(_, exp)| *exp > Instant::now())
            .map(|(v, _)| v.clone())
    }

    pub(crate) fn put_addrs(&self, name: NameBuf, addrs: Vec<IpAddr>, ttl_s: u32) {
        let mut a = self.addrs.lock();
        let now = Instant::now();
        prune(&mut a.map, |(_, exp): &(Vec<IpAddr>, Instant)| *exp <= now);
        a.map.insert(name, (addrs, now + ttl(ttl_s)));
    }

    /// `servers` ordered fastest first, with their smoothed RTT (`None`: never asked; those
    /// sort as a small random RTT, so each gets tried).
    ///
    /// REQ: DNS-903 — an entry past its lifetime is forgotten (the server is a stranger again),
    /// and a server that has been timing out sorts last but is put first once per
    /// `Infra::probe`, so it is noticed when it is back.
    pub(crate) fn order(&self, servers: &[IpAddr]) -> Vec<Server> {
        let now = Instant::now();
        let mut r = self.rtt.lock();
        let mut v: Vec<(Server, u32)> = servers
            .iter()
            .map(|&ip| match r.get_mut(&ip).filter(|x| x.expires > now) {
                Some(x) => {
                    let probe = x.down() && x.probe_at <= now;
                    if probe {
                        x.probe_at = now + self.infra.probe;
                    }
                    let s = Server {
                        ip,
                        srtt_us: (!probe).then_some(x.srtt_us),
                        no_case: x.no_case,
                        no_edns: x.no_edns_until.is_some_and(|t| t > now),
                        tcp: x.tcp_until.is_some_and(|t| t > now),
                    };
                    (s, if probe { 0 } else { x.srtt_us })
                }
                None => (
                    Server {
                        ip,
                        srtt_us: None,
                        no_case: false,
                        no_edns: false,
                        tcp: false,
                    },
                    rand::random::<u32>() % 20_000,
                ),
            })
            .collect();
        v.sort_by_key(|x| x.1);
        v.into_iter().map(|(s, _)| s).collect()
    }

    /// The entry for `ip` (a fresh one, with `srtt_us`, when there is none or it is past its
    /// lifetime), its lifetime renewed. The table never holds more than `Infra::max_hosts`.
    fn slot<'a>(&self, r: &'a mut HashMap<IpAddr, Rtt>, ip: IpAddr, srtt_us: u32) -> &'a mut Rtt {
        let now = Instant::now();
        if r.get(&ip).is_some_and(|x| x.expires <= now) {
            r.remove(&ip);
        }
        if !r.contains_key(&ip) && r.len() >= self.infra.max_hosts.max(1) {
            r.retain(|_, x| x.expires > now);
            if r.len() >= self.infra.max_hosts.max(1) {
                // Still full of live entries: drop an arbitrary half rather than grow.
                let n = (r.len() / 2).max(r.len() + 1 - self.infra.max_hosts.max(1));
                let drop: Vec<IpAddr> = r.keys().take(n).copied().collect();
                for k in drop {
                    r.remove(&k);
                }
            }
        }
        let e = r
            .entry(ip)
            .or_insert_with(|| Rtt::fresh(srtt_us, &self.infra));
        e.expires = now + self.infra.ttl;
        e
    }

    /// Folds in an answer after `rtt` (over TCP when `tcp`). A server that was timing out, or
    /// is new, takes this answer's time as its estimate, so a recovered server is first again.
    pub(crate) fn record_ok(&self, ip: IpAddr, rtt: Duration, tcp: bool) {
        let sample = u32::try_from(rtt.as_micros()).unwrap_or(u32::MAX);
        let mut r = self.rtt.lock();
        let x = self.slot(&mut r, ip, sample);
        x.srtt_us = if x.timeouts > 0 || !x.answered {
            sample
        } else {
            ewma(x.srtt_us, sample)
        };
        x.answered = true;
        x.timeouts = 0;
        if !tcp {
            x.udp_timeouts = 0;
            x.tcp_until = None;
        }
    }

    /// Folds in a failure: it counts as twice the timeout in the estimate.
    pub(crate) fn record_fail(&self, ip: IpAddr, why: Failure, timeout: Duration) {
        let sample = u32::try_from((timeout * 2).as_micros()).unwrap_or(u32::MAX);
        let mut r = self.rtt.lock();
        let x = self.slot(&mut r, ip, sample);
        x.srtt_us = ewma(x.srtt_us, sample);
        match why {
            Failure::Timeout { tcp } => {
                x.timeouts = x.timeouts.saturating_add(1);
                if tcp {
                    // TCP didn't help: back to UDP, and two fresh timeouts before TCP again.
                    x.tcp_until = None;
                    x.udp_timeouts = 0;
                } else {
                    x.udp_timeouts = x.udp_timeouts.saturating_add(1);
                }
            }
            // It spoke: it is up, if no use.
            Failure::Lame => x.timeouts = 0,
        }
    }

    /// REQ: DNS-903 — whether a server that has answered before, and has now left two UDP
    /// queries in a row unanswered, should be asked over TCP; if so, its next queries go that
    /// way first for a lifetime (then UDP is tried again).
    pub(crate) fn tcp_due(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut r = self.rtt.lock();
        match r.get_mut(&ip) {
            Some(x) if x.expires > now && x.answered && x.udp_timeouts >= 2 => {
                x.tcp_until = Some(now + self.infra.ttl);
                true
            }
            _ => false,
        }
    }

    pub(crate) fn no_case(&self, ip: IpAddr) {
        let mut r = self.rtt.lock();
        self.slot(&mut r, ip, 50_000).no_case = true;
    }

    /// REQ: DNS-903 — this server answers FORMERR or NOTIMP to EDNS: ask it without, for one
    /// lifetime from now. A note already in force is not extended, so EDNS is tried again.
    pub(crate) fn no_edns(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut r = self.rtt.lock();
        let x = self.slot(&mut r, ip, 50_000);
        if x.no_edns_until.is_none_or(|t| t <= now) {
            x.no_edns_until = Some(now + self.infra.ttl);
        }
    }

    /// REQ: DNS-903 — this server has answered a query with EDNS with an OPT record.
    pub(crate) fn edns_ok(&self, ip: IpAddr) {
        let mut r = self.rtt.lock();
        self.slot(&mut r, ip, 50_000).edns_ok = true;
    }

    /// Whether this server has been seen doing EDNS (its entry is alive and says so).
    pub(crate) fn edns_seen(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.rtt
            .lock()
            .get(&ip)
            .is_some_and(|x| x.expires > now && x.edns_ok)
    }

    /// Servers in the infrastructure cache (tests).
    #[cfg(test)]
    pub(crate) fn servers(&self) -> usize {
        self.rtt.lock().len()
    }

    /// REQ: DNS-905 (T40.4) — forgets every zone cut and every server-name address; returns how
    /// many entries went. The next lookup starts from the root again.
    pub(crate) fn clear_cuts(&self) -> usize {
        let mut z = self.zones.lock();
        let mut a = self.addrs.lock();
        let n = z.map.len() + a.map.len();
        z.map.clear();
        a.map.clear();
        n
    }

    /// REQ: DNS-905 (T40.4) — forgets every server's smoothed RTT and its 0x20 note; returns
    /// how many servers were known.
    pub(crate) fn clear_rtts(&self) -> usize {
        let mut r = self.rtt.lock();
        let n = r.len();
        r.clear();
        n
    }

    /// Cached zone cuts (metrics, tests).
    pub(crate) fn zones(&self) -> usize {
        self.zones.lock().map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n))
    }

    /// REQ: DNS-903 — the table of servers stays bounded however many servers answer.
    #[test]
    fn dns_903_the_infrastructure_table_stays_bounded() {
        let c = Caches::new(Infra {
            max_hosts: 1_000,
            ..Infra::default()
        });
        for n in 0..100_000 {
            c.record_ok(ip(n), Duration::from_millis(5), false);
            assert!(c.servers() <= 1_000);
        }
        for n in 0..100_000 {
            c.record_fail(
                ip(n),
                Failure::Timeout { tcp: false },
                Duration::from_millis(5),
            );
            c.no_edns(ip(n));
            assert!(c.servers() <= 1_000);
        }
        assert!(c.servers() > 0);
    }

    /// REQ: DNS-903 — the no-EDNS note is set once and lapses after one lifetime even while
    /// the server is busy (each answer renews the entry, not the note).
    #[test]
    fn dns_903_the_no_edns_note_is_not_renewed_by_activity() {
        let c = Caches::new(Infra {
            ttl: Duration::from_millis(150),
            ..Infra::default()
        });
        c.record_ok(ip(1), Duration::from_millis(5), false);
        c.no_edns(ip(1));
        for i in 0..4 {
            std::thread::sleep(Duration::from_millis(50));
            c.record_ok(ip(1), Duration::from_millis(5), false);
            if i == 0 {
                c.no_edns(ip(1)); // a repeat does not push the end out either
            }
        }
        let s = c.order(&[ip(1)])[0];
        assert!(s.srtt_us.is_some(), "the entry is alive: it was busy");
        assert!(!s.no_edns, "but the note lapsed");
    }

    /// REQ: DNS-903 — a server seen doing EDNS is known as one.
    #[test]
    fn dns_903_edns_seen() {
        let c = Caches::new(Infra::default());
        assert!(!c.edns_seen(ip(1)));
        c.edns_ok(ip(1));
        assert!(c.edns_seen(ip(1)));
    }

    /// REQ: DNS-903 — an entry past its lifetime is forgotten, and the table drops the dead
    /// before the living.
    #[test]
    fn dns_903_entries_expire() {
        let c = Caches::new(Infra {
            ttl: Duration::from_millis(30),
            max_hosts: 4,
            ..Infra::default()
        });
        c.record_ok(ip(1), Duration::from_millis(5), false);
        c.no_edns(ip(1));
        assert!(c.order(&[ip(1)])[0].no_edns);
        std::thread::sleep(Duration::from_millis(60));
        let s = c.order(&[ip(1)])[0];
        assert!(
            s.srtt_us.is_none() && !s.no_edns,
            "forgotten after its lifetime"
        );
        for n in 10..13 {
            c.record_ok(ip(n), Duration::from_millis(5), false);
        }
        std::thread::sleep(Duration::from_millis(60));
        c.record_ok(ip(20), Duration::from_millis(5), false);
        assert_eq!(c.servers(), 1, "the expired entries went first");
    }

    /// REQ: DNS-903 — two timeouts mark a server down; it sorts last, is put first once per
    /// probe interval, and one answer brings it back to first place.
    #[test]
    fn dns_903_a_down_server_is_probed_and_recovers() {
        let c = Caches::new(Infra {
            probe: Duration::from_millis(40),
            ..Infra::default()
        });
        let (a, b) = (ip(1), ip(2));
        let t = Duration::from_millis(100);
        c.record_ok(a, Duration::from_millis(2), false);
        c.record_ok(b, Duration::from_millis(20), false);
        assert_eq!(c.order(&[a, b])[0].ip, a);
        c.record_fail(a, Failure::Timeout { tcp: false }, t);
        c.record_fail(a, Failure::Timeout { tcp: false }, t);
        // Down: probed first right away (its first probe is due), then last until the next.
        assert_eq!(c.order(&[a, b])[0].ip, a);
        assert_eq!(c.order(&[a, b])[0].ip, b);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(c.order(&[a, b])[0].ip, a, "probed again");
        c.record_ok(a, Duration::from_millis(2), false);
        assert_eq!(
            c.order(&[a, b])[0].ip,
            a,
            "first place again after one answer"
        );
    }

    /// REQ: DNS-903 — TCP only for a server that answered before, after two UDP timeouts.
    #[test]
    fn dns_903_tcp_after_two_udp_timeouts_from_a_server_that_answered() {
        let c = Caches::new(Infra::default());
        let t = Duration::from_millis(100);
        let (known, stranger) = (ip(1), ip(2));
        c.record_ok(known, Duration::from_millis(2), false);
        for s in [known, stranger] {
            c.record_fail(s, Failure::Timeout { tcp: false }, t);
        }
        assert!(!c.tcp_due(known), "one timeout is not repeated");
        for s in [known, stranger] {
            c.record_fail(s, Failure::Timeout { tcp: false }, t);
        }
        assert!(!c.tcp_due(stranger), "never answered: no TCP");
        assert!(c.tcp_due(known));
        assert!(c.order(&[known])[0].tcp, "its next queries start with TCP");
        c.record_ok(known, Duration::from_millis(2), false);
        assert!(!c.order(&[known])[0].tcp, "a UDP answer ends it");
    }
}

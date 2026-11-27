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

/// What is known of one server, whatever zone it is asked about (REQ: DNS-012, DNS-902,
/// DNS-903): its smoothed RTT in microseconds, and what its answers have shown about the
/// server itself. Unknown servers start optimistic, so each gets tried. An entry lives
/// `Infra::ttl` after its last update, then the server is a stranger again.
#[derive(Debug, Clone, Copy)]
struct Rtt {
    srtt_us: u32,
    /// Leaves 0x20 off for this server (it doesn't echo the letter case).
    no_case: bool,
    /// It has answered a query with EDNS with an OPT record of its own.
    edns_ok: bool,
    /// It has given a usable answer since the entry began.
    answered: bool,
    expires: Instant,
}

impl Rtt {
    fn fresh(srtt_us: u32, infra: &Infra) -> Self {
        Self {
            srtt_us,
            no_case: false,
            edns_ok: false,
            answered: false,
            expires: Instant::now() + infra.ttl,
        }
    }
}

/// What is known of one server as asked about one zone (Unbound keys these by address and zone
/// too): its down, TCP and EDNS notes. A name under another zone cannot change how a server is
/// asked for this one: a zone's operator could otherwise steer queries for every zone that
/// shares the server's address.
#[derive(Debug, Clone, Copy)]
struct Note {
    /// Asked without EDNS until then: it answered FORMERR or NOTIMP to a query with it and
    /// answered one without. Set once; a busy server's entry does not renew it.
    no_edns_until: Option<Instant>,
    /// Consecutive UDP queries it didn't answer in time.
    udp_timeouts: u8,
    /// Consecutive queries (any transport) it didn't answer in time: a server with any is down,
    /// sorts after every server that is not down, and is asked now and then (`Infra::probe`) to see whether it is back; one
    /// that is sorted behind the others and never asked would never be found to have recovered.
    timeouts: u8,
    /// Until then its queries go over TCP first (its UDP went unanswered, its TCP didn't).
    tcp_until: Option<Instant>,
    /// When a down server is next asked ahead of the others.
    probe_at: Instant,
    /// What this zone's timeouts and lame answers have cost it, in microseconds (twice the
    /// timeout, smoothed), added to its RTT when this zone's servers are sorted; the address's
    /// shared RTT never sees it. A usable answer for this zone clears it.
    penalty_us: u32,
    expires: Instant,
}

impl Note {
    fn fresh(infra: &Infra) -> Self {
        let now = Instant::now();
        Self {
            no_edns_until: None,
            udp_timeouts: 0,
            timeouts: 0,
            tcp_until: None,
            probe_at: now,
            penalty_us: 0,
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
    /// Lock order: `rtt`, then `notes`.
    notes: Mutex<HashMap<(IpAddr, NameBuf), Note>>,
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

    /// `servers` ordered fastest first as asked about `zone`, with their smoothed RTT (`None`:
    /// never asked; those sort as a small random RTT, so each gets tried).
    ///
    /// REQ: DNS-903 — an entry past its lifetime is forgotten (the server is a stranger again),
    /// and a server that has been timing out for `zone` sorts after every server that is not
    /// down but is put first once per `Infra::probe`, so it is noticed when it is back.
    pub(crate) fn order(&self, servers: &[IpAddr], zone: &NameBuf) -> Vec<Server> {
        let now = Instant::now();
        let r = self.rtt.lock();
        let mut n = self.notes.lock();
        let mut v: Vec<(Server, (u8, u32))> = servers
            .iter()
            .map(|&ip| {
                let x = r.get(&ip).filter(|x| x.expires > now);
                let note = n.get_mut(&(ip, *zone)).filter(|y| y.expires > now);
                let down = note.as_ref().is_some_and(|y| y.down());
                let probe = down && note.as_ref().is_some_and(|y| y.probe_at <= now);
                let penalty = note.as_ref().map_or(0, |y| y.penalty_us);
                let (no_edns, tcp) = note.as_ref().map_or((false, false), |y| {
                    (
                        y.no_edns_until.is_some_and(|t| t > now),
                        y.tcp_until.is_some_and(|t| t > now),
                    )
                });
                if probe && let Some(y) = note {
                    y.probe_at = now + self.infra.probe;
                }
                let s = Server {
                    ip,
                    srtt_us: x.filter(|_| !probe).map(|x| x.srtt_us),
                    no_case: x.is_some_and(|x| x.no_case),
                    no_edns,
                    tcp,
                };
                // Class 0 before class 1: a down server not due for a probe goes after every
                // server that is not down, then by what its timeouts cost it for this zone.
                let key = if probe {
                    (0, 0)
                } else if down {
                    (1, x.map_or(0, |x| x.srtt_us).saturating_add(penalty))
                } else {
                    let base = x.map_or_else(|| rand::random::<u32>() % 20_000, |x| x.srtt_us);
                    (0, base.saturating_add(penalty))
                };
                (s, key)
            })
            .collect();
        v.sort_by_key(|x| x.1);
        v.into_iter().map(|(s, _)| s).collect()
    }

    /// Makes room for one more key in `map` (never more than `Infra::max_hosts`): drops the
    /// dead first, then an arbitrary half rather than grow.
    fn room<K: std::hash::Hash + Eq + Clone, V>(
        &self,
        map: &mut HashMap<K, V>,
        key: &K,
        dead: impl Fn(&V) -> bool,
    ) {
        let max = self.infra.max_hosts.max(1);
        if map.get(key).is_some_and(&dead) {
            map.remove(key);
        }
        if !map.contains_key(key) && map.len() >= max {
            map.retain(|_, x| !dead(x));
            if map.len() >= max {
                let n = (map.len() / 2).max(map.len() + 1 - max);
                let drop: Vec<K> = map.keys().take(n).cloned().collect();
                for k in drop {
                    map.remove(&k);
                }
            }
        }
    }

    /// The entry for `ip` (a fresh one, with `srtt_us`, when there is none or it is past its
    /// lifetime), its lifetime renewed. The table never holds more than `Infra::max_hosts`.
    fn slot<'a>(&self, r: &'a mut HashMap<IpAddr, Rtt>, ip: IpAddr, srtt_us: u32) -> &'a mut Rtt {
        let now = Instant::now();
        self.room(r, &ip, |x| x.expires <= now);
        let e = r
            .entry(ip)
            .or_insert_with(|| Rtt::fresh(srtt_us, &self.infra));
        e.expires = now + self.infra.ttl;
        e
    }

    /// The note for `ip` as asked about `zone`, made and renewed like `slot`'s.
    fn note<'a>(
        &self,
        n: &'a mut HashMap<(IpAddr, NameBuf), Note>,
        ip: IpAddr,
        zone: &NameBuf,
    ) -> &'a mut Note {
        let now = Instant::now();
        let key = (ip, *zone);
        self.room(n, &key, |x| x.expires <= now);
        let e = n.entry(key).or_insert_with(|| Note::fresh(&self.infra));
        e.expires = now + self.infra.ttl;
        e
    }

    /// The smoothed round-trip estimate of `ip`, in microseconds.
    pub(crate) fn srtt_us(&self, ip: IpAddr) -> Option<u32> {
        self.rtt.lock().get(&ip).map(|x| x.srtt_us)
    }

    /// Folds in an answer about `zone` after `rtt` (over TCP when `tcp`). A server that was
    /// timing out for `zone`, or is new, takes this answer's time as its estimate, so a
    /// recovered server is first again.
    pub(crate) fn record_ok(&self, ip: IpAddr, zone: &NameBuf, rtt: Duration, tcp: bool) {
        let sample = u32::try_from(rtt.as_micros()).unwrap_or(u32::MAX);
        let mut r = self.rtt.lock();
        let mut n = self.notes.lock();
        let y = self.note(&mut n, ip, zone);
        let was_down = y.timeouts > 0;
        y.timeouts = 0;
        y.penalty_us = 0;
        if !tcp {
            y.udp_timeouts = 0;
            y.tcp_until = None;
        }
        let x = self.slot(&mut r, ip, sample);
        x.srtt_us = if was_down || !x.answered {
            sample
        } else {
            ewma(x.srtt_us, sample)
        };
        x.answered = true;
    }

    /// Folds in a failure about `zone`. It touches only this (address, zone) note: a timeout
    /// counts as twice the timeout in the note's penalty, and the address's shared RTT is
    /// moved by real answers alone, so one zone cannot push a server back for the others.
    pub(crate) fn record_fail(&self, ip: IpAddr, zone: &NameBuf, why: Failure, timeout: Duration) {
        let sample = u32::try_from((timeout * 2).as_micros()).unwrap_or(u32::MAX);
        let mut n = self.notes.lock();
        let y = self.note(&mut n, ip, zone);
        match why {
            Failure::Timeout { tcp } => {
                y.penalty_us = if y.penalty_us == 0 {
                    sample
                } else {
                    ewma(y.penalty_us, sample)
                };
                y.timeouts = y.timeouts.saturating_add(1);
                if tcp {
                    // TCP didn't help: back to UDP, and two fresh timeouts before TCP again.
                    y.tcp_until = None;
                    y.udp_timeouts = 0;
                } else {
                    y.udp_timeouts = y.udp_timeouts.saturating_add(1);
                }
            }
            // It spoke: it is up, if no use.
            Failure::Lame => {
                y.timeouts = 0;
                y.penalty_us = if y.penalty_us == 0 {
                    sample
                } else {
                    ewma(y.penalty_us, sample)
                };
            }
        }
    }

    /// REQ: DNS-903 — a hedged server that lost to its sibling counts as a timeout over the
    /// transport it was asked on: over TCP that is "TCP did not help" (back to UDP), over UDP it
    /// may owe a move to TCP.
    pub(crate) fn hedge_lost(&self, server: Server, zone: &NameBuf, timeout: Duration) {
        self.record_fail(
            server.ip,
            zone,
            Failure::Timeout { tcp: server.tcp },
            timeout,
        );
        if !server.tcp {
            let _ = self.tcp_due(server.ip, zone);
        }
    }

    /// REQ: DNS-903 — whether a server that has answered before, and has now left two UDP
    /// queries about `zone` in a row unanswered, should be asked over TCP; if so, its next
    /// queries about `zone` go that way first for a lifetime (then UDP is tried again).
    pub(crate) fn tcp_due(&self, ip: IpAddr, zone: &NameBuf) -> bool {
        let now = Instant::now();
        let r = self.rtt.lock();
        let mut n = self.notes.lock();
        let answered = r.get(&ip).is_some_and(|x| x.expires > now && x.answered);
        match n.get_mut(&(ip, *zone)) {
            Some(y) if answered && y.expires > now && y.udp_timeouts >= 2 => {
                y.tcp_until = Some(now + self.infra.ttl);
                true
            }
            _ => false,
        }
    }

    pub(crate) fn no_case(&self, ip: IpAddr) {
        let mut r = self.rtt.lock();
        self.slot(&mut r, ip, 50_000).no_case = true;
    }

    /// REQ: DNS-903 — this server answers FORMERR or NOTIMP to EDNS for `zone`: ask it without,
    /// for that zone, for one lifetime from now. A note already in force is not extended, so
    /// EDNS is tried again.
    pub(crate) fn no_edns(&self, ip: IpAddr, zone: &NameBuf) {
        let now = Instant::now();
        let mut r = self.rtt.lock();
        let mut n = self.notes.lock();
        self.slot(&mut r, ip, 50_000);
        let y = self.note(&mut n, ip, zone);
        if y.no_edns_until.is_none_or(|t| t <= now) {
            y.no_edns_until = Some(now + self.infra.ttl);
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
        let mut notes = self.notes.lock();
        let n = r.len();
        r.clear();
        notes.clear();
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

    fn z() -> NameBuf {
        NameBuf::default()
    }

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
            c.record_ok(ip(n), &z(), Duration::from_millis(5), false);
            assert!(c.servers() <= 1_000);
        }
        for n in 0..100_000 {
            c.record_fail(
                ip(n),
                &z(),
                Failure::Timeout { tcp: false },
                Duration::from_millis(5),
            );
            c.no_edns(ip(n), &z());
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
        c.record_ok(ip(1), &z(), Duration::from_millis(5), false);
        c.no_edns(ip(1), &z());
        for i in 0..4 {
            std::thread::sleep(Duration::from_millis(50));
            c.record_ok(ip(1), &z(), Duration::from_millis(5), false);
            if i == 0 {
                c.no_edns(ip(1), &z()); // a repeat does not push the end out either
            }
        }
        let s = c.order(&[ip(1)], &z())[0];
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
        c.record_ok(ip(1), &z(), Duration::from_millis(5), false);
        c.no_edns(ip(1), &z());
        assert!(c.order(&[ip(1)], &z())[0].no_edns);
        std::thread::sleep(Duration::from_millis(60));
        let s = c.order(&[ip(1)], &z())[0];
        assert!(
            s.srtt_us.is_none() && !s.no_edns,
            "forgotten after its lifetime"
        );
        for n in 10..13 {
            c.record_ok(ip(n), &z(), Duration::from_millis(5), false);
        }
        std::thread::sleep(Duration::from_millis(60));
        c.record_ok(ip(20), &z(), Duration::from_millis(5), false);
        assert_eq!(c.servers(), 1, "the expired entries went first");
    }

    /// REQ: DNS-903 — one timeout marks a server down; it sorts after every server that is not
    /// down, is put first once per probe interval, and one answer brings it back to first place.
    #[test]
    fn dns_903_a_down_server_is_probed_and_recovers() {
        let c = Caches::new(Infra {
            probe: Duration::from_millis(40),
            ..Infra::default()
        });
        let (a, b) = (ip(1), ip(2));
        let t = Duration::from_millis(100);
        c.record_ok(a, &z(), Duration::from_millis(2), false);
        c.record_ok(b, &z(), Duration::from_millis(20), false);
        assert_eq!(c.order(&[a, b], &z())[0].ip, a);
        c.record_fail(a, &z(), Failure::Timeout { tcp: false }, t);
        c.record_fail(a, &z(), Failure::Timeout { tcp: false }, t);
        // Down: probed first right away (its first probe is due), then last until the next.
        assert_eq!(c.order(&[a, b], &z())[0].ip, a);
        assert_eq!(c.order(&[a, b], &z())[0].ip, b);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(c.order(&[a, b], &z())[0].ip, a, "probed again");
        c.record_ok(a, &z(), Duration::from_millis(2), false);
        assert_eq!(
            c.order(&[a, b], &z())[0].ip,
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
        c.record_ok(known, &z(), Duration::from_millis(2), false);
        for s in [known, stranger] {
            c.record_fail(s, &z(), Failure::Timeout { tcp: false }, t);
        }
        assert!(!c.tcp_due(known, &z()), "one timeout is not repeated");
        for s in [known, stranger] {
            c.record_fail(s, &z(), Failure::Timeout { tcp: false }, t);
        }
        assert!(!c.tcp_due(stranger, &z()), "never answered: no TCP");
        assert!(c.tcp_due(known, &z()));
        assert!(
            c.order(&[known], &z())[0].tcp,
            "its next queries start with TCP"
        );
        c.record_ok(known, &z(), Duration::from_millis(2), false);
        assert!(!c.order(&[known], &z())[0].tcp, "a UDP answer ends it");
    }

    /// REQ: DNS-903 — the down, TCP and no-EDNS notes belong to the zone they were seen for: a
    /// server's behaviour for one zone does not change how it is asked for another.
    #[test]
    fn dns_903_notes_are_kept_per_zone() {
        let c = Caches::new(Infra::default());
        let za = NameBuf::from_presentation("a.example").expect("name");
        let zb = NameBuf::from_presentation("b.example").expect("name");
        let t = Duration::from_millis(100);
        let srv = ip(1);
        c.record_ok(srv, &zb, Duration::from_millis(2), false);
        for _ in 0..2 {
            c.record_fail(srv, &za, Failure::Timeout { tcp: false }, t);
        }
        assert!(c.tcp_due(srv, &za));
        c.no_edns(srv, &za);
        let for_a = c.order(&[srv], &za)[0];
        assert!(for_a.tcp && for_a.no_edns);
        // Lame answers clear the down note, not the TCP one: still scoped to `a`.
        c.record_fail(srv, &za, Failure::Lame, t);
        let for_b = c.order(&[srv], &zb)[0];
        assert!(!for_b.tcp && !for_b.no_edns, "zone b is asked as usual");
        assert!(for_b.srtt_us.is_some(), "and the server is not down for b");
        // The notes table is bounded too.
        let small = Caches::new(Infra {
            max_hosts: 10,
            ..Infra::default()
        });
        for n in 0..1_000 {
            let zone = NameBuf::from_presentation(&format!("z{n}.example")).expect("name");
            small.record_fail(ip(1), &zone, Failure::Timeout { tcp: false }, t);
            assert!(small.notes.lock().len() <= 10);
        }
    }

    /// REQ: DNS-903 (ADR-1100 point 1) — a full table drops its expired entries first, then
    /// half of the live ones, never the whole table.
    #[test]
    fn dns_903_a_full_table_drops_expired_then_half_never_all() {
        let t = Duration::from_millis(5);
        // Expired first: 4 old entries lapse while 6 stay live; the 11th key costs only the 4.
        let c = Caches::new(Infra {
            ttl: Duration::from_millis(400),
            max_hosts: 10,
            ..Infra::default()
        });
        for n in 0..4 {
            c.record_ok(ip(n), &z(), t, false);
        }
        std::thread::sleep(Duration::from_millis(250));
        for n in 10..16 {
            c.record_ok(ip(n), &z(), t, false);
        }
        std::thread::sleep(Duration::from_millis(200));
        c.record_ok(ip(99), &z(), t, false);
        assert_eq!(c.servers(), 7, "the 4 expired went, the 6 live stayed");
        for n in 10..16 {
            assert!(c.order(&[ip(n)], &z())[0].srtt_us.is_some(), "{n} kept");
        }
        // All live: half of them go, and the new one is added; the table is not emptied.
        let c = Caches::new(Infra {
            max_hosts: 10,
            ..Infra::default()
        });
        for n in 0..10 {
            c.record_ok(ip(n), &z(), t, false);
        }
        c.record_ok(ip(99), &z(), t, false);
        assert_eq!(c.servers(), 6, "half of 10 live entries dropped, one added");
    }

    /// REQ: DNS-903 — a hedged server that lost while asked over TCP counts as "TCP did not
    /// help" (back to UDP); one asked over UDP that owes TCP is moved to it.
    #[test]
    fn dns_903_a_hedge_loser_is_recorded_on_the_transport_it_was_asked_on() {
        let c = Caches::new(Infra::default());
        let t = Duration::from_millis(100);
        let srv = ip(1);
        c.record_ok(srv, &z(), Duration::from_millis(2), false);
        for _ in 0..2 {
            c.record_fail(srv, &z(), Failure::Timeout { tcp: false }, t);
        }
        // Over UDP, two timeouts in a row: the loss owes TCP.
        c.hedge_lost(c.order(&[srv], &z())[0], &z(), t);
        assert!(c.order(&[srv], &z())[0].tcp, "UDP loser, two before: TCP");
        // Asked over TCP and lost: TCP did not help, so back to UDP.
        let asked = c.order(&[srv], &z())[0];
        assert!(asked.tcp);
        c.hedge_lost(asked, &z(), t);
        assert!(!c.order(&[srv], &z())[0].tcp, "TCP did not help");
    }

    /// REQ: DNS-903 — a recovered server's one answer sets its estimate, so it sorts before a
    /// 20 ms sibling.
    #[test]
    fn dns_903_a_recovered_server_takes_its_answer_as_its_estimate() {
        let c = Caches::new(Infra::default());
        let (a, b) = (ip(1), ip(2));
        let t = Duration::from_millis(300);
        c.record_ok(a, &z(), Duration::from_millis(2), false);
        c.record_ok(b, &z(), Duration::from_millis(20), false);
        c.record_fail(a, &z(), Failure::Timeout { tcp: false }, t);
        c.record_ok(a, &z(), Duration::from_micros(500), false);
        assert_eq!(c.order(&[a, b], &z())[0].ip, a);
        assert_eq!(c.order(&[a, b], &z())[0].srtt_us, Some(500));
    }

    /// REQ: DNS-903 (ADR-1100 point 1) — timeouts provoked through one zone change nothing for
    /// the other zones on the same address: the address's smoothed RTT moves by answers alone.
    #[test]
    fn dns_903_timeouts_for_one_zone_leave_the_order_for_another_zone_alone() {
        let c = Caches::new(Infra::default());
        let za = NameBuf::from_presentation("a.example").expect("name");
        let zb = NameBuf::from_presentation("b.example").expect("name");
        let (fast, slow) = (ip(1), ip(2));
        c.record_ok(fast, &zb, Duration::from_millis(2), false);
        c.record_ok(slow, &zb, Duration::from_millis(20), false);
        for _ in 0..10 {
            c.record_fail(
                fast,
                &za,
                Failure::Timeout { tcp: false },
                Duration::from_secs(1),
            );
        }
        let for_b = c.order(&[slow, fast], &zb);
        assert_eq!(for_b[0].ip, fast, "still first for b");
        assert_eq!(for_b[0].srtt_us, Some(2_000), "its RTT was not touched");
        let for_a = c.order(&[slow, fast], &za);
        assert_eq!(for_a[0].ip, fast, "down for a: probed first once");
        assert_eq!(
            c.order(&[slow, fast], &za)[0].ip,
            slow,
            "then after the other"
        );
    }

    /// REQ: DNS-903 — a down server not due for a probe sorts after every server that is not
    /// down, even a slower one.
    #[test]
    fn dns_903_a_down_server_sorts_after_every_server_that_is_up() {
        let c = Caches::new(Infra::default());
        let (a, b) = (ip(1), ip(2));
        c.record_ok(a, &z(), Duration::from_millis(2), false);
        c.record_ok(b, &z(), Duration::from_millis(900), false);
        c.record_fail(
            a,
            &z(),
            Failure::Timeout { tcp: false },
            Duration::from_micros(500),
        );
        assert_eq!(c.order(&[a, b], &z())[0].ip, a, "probe due once");
        assert_eq!(
            c.order(&[a, b], &z())[0].ip,
            b,
            "then behind the slower one"
        );
        assert_eq!(c.order(&[b, a], &z())[0].ip, b);
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: DNS-907 (T40.6) — RFC 8198 for zones signed with NSEC3 (ADR-1105, amending ADR-092).
//!
//! An NSEC3 record owns the hash of a name and says that no name hashes strictly between that
//! hash and its `next` hash. A table of such ranges is kept per zone with the zone's hash
//! parameters (salt and iterations: one set for the whole zone, RFC 5155 §4), and a later
//! question is answered from it by hashing the question's names:
//! - **NODATA** when an NSEC3 record matches the name and lacks the type and CNAME (and the name
//!   isn't a delegation, unless the question is DS);
//! - **NXDOMAIN** by the closest encloser proof of RFC 5155 §8.3: the longest ancestor whose
//!   hash matches a cached record (the encloser), a cached record covering the next closer name,
//!   and one covering the wildcard at the encloser.
//!
//! What is never used: a record that did not come from a secure denial, one that another zone
//! signed, one that hashes with more iterations than the validator's soft limit (it would only
//! cost a hash per lookup, RFC 9276), and any span with the opt-out flag set to cover a name: such
//! a span may hide unsigned delegations, so it proves nothing about a name inside it (RFC 5155
//! §6). A name below a delegation or a DNAME is left to the child zone.
//!
//! The walk starts at the zone apex and goes down while the names match, so a random name costs
//! four hash chains (the name itself, the apex, the next closer name and the wildcard), whatever
//! its depth.

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
use std::time::{Duration, Instant};

use hickory_net::proto::dnssec::Nsec3HashAlgorithm;
use hickory_net::proto::dnssec::Proof;
use hickory_net::proto::dnssec::rdata::DNSSECRData;
use hickory_net::proto::op::Message;
use hickory_net::proto::rr::{Name, RData, Record, RecordType};

use crate::dnssec::NSEC3_SOFT_LIMIT;
use crate::nsec::{Denial, rrsigs, signer};

/// Ranges kept per upstream group at most (the NSEC table's bound); past it, the ones expiring
/// first go.
pub(crate) const MAX_RANGES: usize = 20_000;
/// Zones (their hash parameters and ranges) kept per upstream group at most.
pub(crate) const MAX_ZONES: usize = 2_000;

/// One NSEC3 range: no name hashes strictly between its owner hash and `next`.
#[derive(Debug, Clone)]
struct Range {
    next: Vec<u8>,
    opt_out: bool,
    types: Vec<RecordType>,
    /// The NSEC3 record and its signatures.
    records: Vec<Record>,
    expires: Instant,
}

impl Range {
    /// An NS without an SOA: a delegation point.
    fn delegation(&self) -> bool {
        self.types.contains(&RecordType::NS) && !self.types.contains(&RecordType::SOA)
    }

    /// Whether `h` is strictly between the owner hash and `next` (the last record of the chain
    /// points back at the first and covers the hashes after its owner and before `next`).
    fn covers(&self, owner: &[u8], h: &[u8]) -> bool {
        if owner < self.next.as_slice() {
            owner < h && h < self.next.as_slice()
        } else {
            h > owner || h < self.next.as_slice()
        }
    }
}

/// One zone's ranges, with the hash parameters they were made with.
#[derive(Debug)]
struct Table {
    iterations: u16,
    salt: Vec<u8>,
    ranges: BTreeMap<Vec<u8>, Range>,
}

impl Table {
    fn new(iterations: u16, salt: &[u8]) -> Self {
        Self {
            iterations,
            salt: salt.to_vec(),
            ranges: BTreeMap::new(),
        }
    }

    fn hash(&self, name: &Name) -> Option<Vec<u8>> {
        Nsec3HashAlgorithm::SHA1
            .hash(&self.salt, name, self.iterations)
            .ok()
            .map(|d| d.as_ref().to_vec())
    }

    /// The live range that matches `h`, with its owner hash.
    fn live(&self, h: &[u8], now: Instant) -> Option<(&Vec<u8>, &Range)> {
        self.ranges
            .get_key_value(h)
            .filter(|(_, r)| r.expires > now)
    }

    /// The live range that covers `h`, with its owner hash.
    fn cover(&self, h: &[u8], now: Instant) -> Option<(&Vec<u8>, &Range)> {
        let (owner, r) = self
            .ranges
            .range::<[u8], _>((Bound::Unbounded, Bound::Excluded(h)))
            .next_back()
            .or_else(|| self.ranges.iter().next_back())?;
        (r.expires > now && r.covers(owner, h)).then_some((owner, r))
    }
}

/// A proof: what it says, and the cached records that make it, with their expiry.
pub(crate) type Proved<'a> = (Denial, Vec<(&'a [Record], Instant)>);

/// The validated NSEC3 ranges of one upstream group, by zone apex.
#[derive(Debug, Default)]
pub(crate) struct Nsec3Ranges {
    zones: HashMap<Name, Table>,
}

/// The bytes a base32hex (RFC 4648 §7) label stands for, in either case.
fn base32hex(label: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(label.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in label {
        let v = match c.to_ascii_lowercase() {
            d @ b'0'..=b'9' => d - b'0',
            l @ b'a'..=b'v' => l - b'a' + 10,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

impl Nsec3Ranges {
    /// REQ: DNS-907 (T40.6) — keeps the NSEC3 records of `m`, a validated negative answer from
    /// `zone` (the owner of its secure SOA), for `negative_ttl` seconds at most. Records that
    /// weren't proven secure, another zone signed, or hash with too many iterations are skipped.
    /// Returns whether any was kept.
    pub(crate) fn learn(
        &mut self,
        m: &Message,
        zone: &Name,
        negative_ttl: u32,
        now: Instant,
    ) -> bool {
        let mut learned = false;
        for r in &m.authorities {
            let RData::DNSSEC(DNSSECRData::NSEC3(n3)) = &r.data else {
                continue;
            };
            // Only SHA-1 is defined; a record that hashes with too many iterations is never
            // cached (RFC 9276: an answer that depends on it is insecure anyway).
            if r.proof != Proof::Secure
                || n3.hash_algorithm() != Nsec3HashAlgorithm::SHA1
                || n3.iterations() > NSEC3_SOFT_LIMIT
            {
                continue;
            }
            // The owner is `<hash>.<zone>`: one label under the apex.
            if r.name.num_labels() != zone.num_labels() + 1 || !zone.zone_of(&r.name) {
                continue;
            }
            let sigs = rrsigs(m, &r.name, RecordType::NSEC3);
            if signer(&sigs).as_ref() != Some(zone) {
                continue;
            }
            let Some(owner) = r.name.iter().next().and_then(base32hex) else {
                continue;
            };
            let next = n3.next_hashed_owner_name().to_vec();
            if owner.len() != next.len() || owner.len() != 20 {
                continue;
            }
            let table = self
                .zones
                .entry(zone.clone())
                .or_insert_with(|| Table::new(n3.iterations(), n3.salt()));
            if table.iterations != n3.iterations() || table.salt != n3.salt() {
                // New parameters for the zone: the old hashes mean nothing now.
                *table = Table::new(n3.iterations(), n3.salt());
            }
            let ttl = r.ttl.min(negative_ttl);
            let mut records = vec![r.clone()];
            records.extend(sigs);
            table.ranges.insert(
                owner,
                Range {
                    next,
                    opt_out: n3.opt_out(),
                    types: n3.type_bit_maps().collect(),
                    records,
                    expires: now + Duration::from_secs(u64::from(ttl)),
                },
            );
            learned = true;
        }
        if learned {
            self.trim(now);
        }
        learned
    }

    /// The deepest zone with a table that holds `q`'s names (for a DS question the parent's,
    /// where the delegation lives).
    fn zone_of(&self, q: &Name, qtype: RecordType) -> Option<(&Name, &Table)> {
        if self.zones.is_empty() {
            return None;
        }
        let top = if qtype == RecordType::DS && q.num_labels() > 0 {
            q.base_name()
        } else {
            q.clone()
        };
        (0..=usize::from(top.num_labels()))
            .rev()
            .find_map(|k| self.zones.get_key_value(&top.trim_to(k)))
    }

    /// REQ: DNS-907 (T40.6) — the zone and a negative answer for `q`/`qtype` that the cached
    /// ranges prove (the caller adds the zone's SOA), or `None` when they don't (then the
    /// question goes upstream as usual).
    pub(crate) fn prove(
        &self,
        q: &Name,
        qtype: RecordType,
        now: Instant,
    ) -> Option<(&Name, Proved<'_>)> {
        let (zone, t) = self.zone_of(q, qtype)?;
        // A record that matches the name itself: NODATA (RFC 5155 §8.5, §8.6). Names below a
        // delegation have no record in the zone's chain, so a match is the zone's own name.
        let qh = t.hash(q)?;
        if let Some((_, rec)) = t.live(&qh, now) {
            let child_side_ds = qtype == RecordType::DS && rec.types.contains(&RecordType::SOA);
            if rec.types.contains(&qtype)
                || rec.types.contains(&RecordType::CNAME)
                || (rec.delegation() && qtype != RecordType::DS)
                || child_side_ds
            {
                return None;
            }
            return Some((
                zone,
                (Denial::NoData, vec![(&rec.records[..], rec.expires)]),
            ));
        }
        // Otherwise NXDOMAIN: walk down from the apex (which always exists) while the names
        // match; the last one is the closest encloser.
        let mut enc = zone.clone();
        let (mut enc_owner, mut enc_rec) = t.live(&t.hash(&enc)?, now)?;
        loop {
            // Below a delegation or a DNAME, names belong elsewhere.
            if enc_rec.delegation() || enc_rec.types.contains(&RecordType::DNAME) {
                return None;
            }
            let next_closer = q.trim_to(usize::from(enc.num_labels()) + 1);
            let nh = t.hash(&next_closer)?;
            if let Some((o, r)) = t.live(&nh, now) {
                enc = next_closer;
                (enc_owner, enc_rec) = (o, r);
                continue;
            }
            // NXDOMAIN (RFC 5155 §8.4): the next closer name and the wildcard at the encloser
            // are both covered, by spans that hide no unsigned delegation.
            let (c1_owner, c1) = t.cover(&nh, now).filter(|(_, r)| !r.opt_out)?;
            let wildcard = enc.prepend_label("*").ok()?;
            let wh = t.hash(&wildcard)?;
            let (c2_owner, c2) = t.cover(&wh, now).filter(|(_, r)| !r.opt_out)?;
            let mut parts = vec![(&enc_rec.records[..], enc_rec.expires)];
            if c1_owner != enc_owner {
                parts.push((&c1.records[..], c1.expires));
            }
            if c2_owner != enc_owner && c2_owner != c1_owner {
                parts.push((&c2.records[..], c2.expires));
            }
            return Some((zone, (Denial::NxDomain, parts)));
        }
    }

    /// Drops expired entries, then the soonest-expiring ones past the bounds.
    fn trim(&mut self, now: Instant) {
        if self.len() > MAX_RANGES || self.zones.len() > MAX_ZONES {
            for t in self.zones.values_mut() {
                t.ranges.retain(|_, r| r.expires > now);
            }
            self.zones.retain(|_, t| !t.ranges.is_empty());
        }
        while self.len() > MAX_RANGES {
            let Some((z, k)) = self
                .zones
                .iter()
                .flat_map(|(z, t)| t.ranges.iter().map(move |(k, r)| (r.expires, z, k)))
                .min_by_key(|(e, _, _)| *e)
                .map(|(_, z, k)| (z.clone(), k.clone()))
            else {
                break;
            };
            if let Some(t) = self.zones.get_mut(&z) {
                t.ranges.remove(&k);
                if t.ranges.is_empty() {
                    self.zones.remove(&z);
                }
            }
        }
        while self.zones.len() > MAX_ZONES {
            let Some(z) = self
                .zones
                .iter()
                .filter_map(|(z, t)| t.ranges.values().map(|r| r.expires).max().map(|e| (e, z)))
                .min_by_key(|(e, _)| *e)
                .map(|(_, z)| z.clone())
            else {
                break;
            };
            self.zones.remove(&z);
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.zones.values().map(|t| t.ranges.len()).sum()
    }
}

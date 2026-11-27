//! REQ: DNS-011 (T9.16) — RFC 8198: aggressive use of DNSSEC-validated NSEC records.
//!
//! A validated, secure negative answer proves more than its own question: each NSEC record
//! says that no name exists between its owner and the next name (and which types its owner
//! has). Those ranges are kept, with the zone's SOA and every signature, and a later question
//! that falls inside one is answered here, without asking upstream:
//! - **NXDOMAIN** when the name is covered and so is the wildcard at its closest encloser
//!   (RFC 4035 §5.4); both NSEC records go into the answer.
//! - **NODATA** when an NSEC owned by the name lacks the type and CNAME (and isn't a
//!   delegation, unless the question is DS).
//!
//! NSEC3-signed zones have their own table ([`crate::nsec3`], DNS-907, ADR-1105): its ranges
//! are hashed, so each lookup hashes with the zone's parameters. Only records the validator
//! proved secure, signed by the zone whose SOA came with them, are used.
//! Entries live for the smaller of the NSEC TTL and the SOA's negative TTL (RFC 8198 §5.4).
//! The cache is per upstream group and bounded; it's consulted on cache misses only.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use hickory_net::proto::dnssec::Proof;
use hickory_net::proto::dnssec::rdata::DNSSECRData;
use hickory_net::proto::op::{Message, ResponseCode};
use hickory_net::proto::rr::{Name, RData, Record, RecordType};

use crate::nsec3::Nsec3Ranges;

/// Ranges kept per upstream group at most; past it, the ones expiring first go.
const MAX_RANGES: usize = 20_000;
/// Zones (their SOA records) kept per upstream group at most.
const MAX_ZONES: usize = 2_000;

/// One NSEC range: no name exists strictly between its owner and `next`.
#[derive(Debug, Clone)]
struct Range {
    next: Name,
    /// The zone that signed it (its apex).
    zone: Name,
    types: Vec<RecordType>,
    /// The NSEC record and its signatures.
    records: Vec<Record>,
    expires: Instant,
}

/// A zone's SOA and its signatures (the authority of a synthesized answer).
#[derive(Debug, Clone)]
struct Soa {
    records: Vec<Record>,
    expires: Instant,
}

/// What a synthesized answer says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Denial {
    NxDomain,
    NoData,
}

/// A synthesized negative answer: its rcode and its authority section (SOA, NSEC records,
/// signatures), with TTLs counted down.
#[derive(Debug, Clone)]
pub(crate) struct Synth {
    pub(crate) denial: Denial,
    pub(crate) authorities: Vec<Record>,
}

/// The validated NSEC ranges of one upstream group.
#[derive(Debug, Default)]
pub(crate) struct Ranges {
    by_owner: BTreeMap<Name, Range>,
    soas: HashMap<Name, Soa>,
    /// REQ: DNS-907 (T40.6) — the zones signed with NSEC3.
    nsec3: Nsec3Ranges,
}

pub(crate) fn rrsigs(m: &Message, owner: &Name, covered: RecordType) -> Vec<Record> {
    m.authorities
        .iter()
        .filter(|r| {
            r.name == *owner
                && matches!(&r.data, RData::DNSSEC(DNSSECRData::RRSIG(s)) if s.input().type_covered == covered)
        })
        .cloned()
        .collect()
}

pub(crate) fn signer(sigs: &[Record]) -> Option<Name> {
    sigs.iter().find_map(|r| match &r.data {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) => Some(s.input().signer_name.clone()),
        _ => None,
    })
}

/// The longest common ancestor of `a` and `b` (case-insensitive).
fn common_ancestor(a: &Name, b: &Name) -> Name {
    let n = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x.eq_ignore_ascii_case(y))
        .count();
    a.trim_to(n)
}

impl Range {
    /// An NS without an SOA: a delegation point, so names below belong to another zone.
    fn delegation(&self) -> bool {
        self.types.contains(&RecordType::NS) && !self.types.contains(&RecordType::SOA)
    }

    /// Whether `q` (greater than `owner`) is strictly between `owner` and `next`. The last NSEC
    /// of a zone points back at the apex: it covers everything after its owner.
    fn covers(&self, owner: &Name, q: &Name) -> bool {
        q > owner && (*q < self.next || self.next == self.zone) && self.zone.zone_of(q)
    }
}

/// Every record counts down to the earliest expiry among them.
fn countdown(parts: &[(&[Record], Instant)], denial: Denial, now: Instant) -> Synth {
    let left = parts
        .iter()
        .map(|(_, e)| e.saturating_duration_since(now).as_secs())
        .min()
        .unwrap_or(0);
    let left = u32::try_from(left).unwrap_or(u32::MAX).max(1);
    let authorities = parts
        .iter()
        .flat_map(|(rs, _)| rs.iter())
        .map(|r| {
            let mut r = r.clone();
            r.ttl = r.ttl.min(left);
            r
        })
        .collect();
    Synth {
        denial,
        authorities,
    }
}

impl Ranges {
    /// REQ: DNS-011 (T9.16) — keeps the NSEC records of `m`, a validated negative answer.
    /// Records the validator didn't prove secure, or that another zone signed, are skipped.
    pub(crate) fn learn(&mut self, m: &Message, now: Instant) {
        let negative = m.answers.is_empty()
            && matches!(
                m.metadata.response_code,
                ResponseCode::NXDomain | ResponseCode::NoError
            );
        if !negative {
            return;
        }
        let Some(soa) = m
            .authorities
            .iter()
            .find(|r| r.record_type() == RecordType::SOA && r.proof == Proof::Secure)
        else {
            return;
        };
        let RData::SOA(s) = &soa.data else {
            return;
        };
        let zone = soa.name.clone();
        let negative_ttl = soa.ttl.min(s.minimum);
        if negative_ttl == 0 {
            return;
        }
        // REQ: DNS-907 (T40.6) — NSEC3 records (a zone has one kind or the other).
        let mut learned = self.nsec3.learn(m, &zone, negative_ttl, now);
        for r in &m.authorities {
            let RData::DNSSEC(DNSSECRData::NSEC(n)) = &r.data else {
                continue;
            };
            if r.proof != Proof::Secure || !zone.zone_of(&r.name) {
                continue;
            }
            let sigs = rrsigs(m, &r.name, RecordType::NSEC);
            if signer(&sigs).as_ref() != Some(&zone) {
                continue;
            }
            let ttl = r.ttl.min(negative_ttl);
            let mut records = vec![r.clone()];
            records.extend(sigs);
            self.by_owner.insert(
                r.name.clone(),
                Range {
                    next: n.next_domain_name().clone(),
                    zone: zone.clone(),
                    types: n.type_bit_maps().collect(),
                    records,
                    expires: now + Duration::from_secs(u64::from(ttl)),
                },
            );
            learned = true;
        }
        if learned {
            let mut records = vec![soa.clone()];
            records.extend(rrsigs(m, &zone, RecordType::SOA));
            self.soas.insert(
                zone,
                Soa {
                    records,
                    expires: now + Duration::from_secs(u64::from(negative_ttl)),
                },
            );
            self.trim(now);
        }
    }

    /// The range whose owner is the greatest name not after `q`, if it hasn't expired.
    fn find(&self, q: &Name, now: Instant) -> Option<(&Name, &Range)> {
        self.by_owner
            .range(..=q.clone())
            .next_back()
            .filter(|(_, r)| r.expires > now)
    }

    /// REQ: DNS-011 (T9.16) — a negative answer for `q`/`qtype` proven by cached ranges, or
    /// `None` when they don't prove one (then the question goes upstream as usual).
    pub(crate) fn synthesize(&self, q: &Name, qtype: RecordType, now: Instant) -> Option<Synth> {
        // ANY lists every type; a cached range can't say what the zone would answer.
        if qtype == RecordType::ANY {
            return None;
        }
        self.synthesize_nsec(q, qtype, now)
            .or_else(|| self.synthesize_nsec3(q, qtype, now))
    }

    /// REQ: DNS-907 (T40.6) — the same from the NSEC3 ranges of the zone `q` is in.
    fn synthesize_nsec3(&self, q: &Name, qtype: RecordType, now: Instant) -> Option<Synth> {
        let (zone, (denial, proof)) = self.nsec3.prove(q, qtype, now)?;
        let soa = self.soas.get(zone).filter(|s| s.expires > now)?;
        let mut parts: Vec<(&[Record], Instant)> = vec![(&soa.records, soa.expires)];
        parts.extend(proof);
        Some(countdown(&parts, denial, now))
    }

    fn synthesize_nsec(&self, q: &Name, qtype: RecordType, now: Instant) -> Option<Synth> {
        let (owner, range) = self.find(q, now)?;
        let soa = self.soas.get(&range.zone).filter(|s| s.expires > now)?;
        let mut parts: Vec<(&[Record], Instant)> = vec![(&soa.records, soa.expires)];
        let denial = if owner == q {
            // NODATA (RFC 4035 §3.1.3.1).
            let delegation = range.delegation() && *owner != range.zone;
            if range.types.contains(&qtype)
                || range.types.contains(&RecordType::CNAME)
                || (delegation && qtype != RecordType::DS)
            {
                return None;
            }
            parts.push((&range.records, range.expires));
            Denial::NoData
        } else {
            // NXDOMAIN (RFC 4035 §5.4): the name is covered, and so is the wildcard at the
            // closest encloser.
            if !range.covers(owner, q) {
                return None;
            }
            // Below a delegation or a DNAME, names belong elsewhere.
            if owner.zone_of(q) && (range.delegation() || range.types.contains(&RecordType::DNAME))
            {
                return None;
            }
            let a = common_ancestor(q, owner);
            let b = common_ancestor(q, &range.next);
            let encloser = if a.num_labels() >= b.num_labels() {
                a
            } else {
                b
            };
            let wildcard = encloser.prepend_label("*").ok()?;
            let (wowner, wrange) = self.find(&wildcard, now)?;
            if wrange.zone != range.zone || !wrange.covers(wowner, &wildcard) {
                return None;
            }
            parts.push((&range.records, range.expires));
            if wowner != owner {
                parts.push((&wrange.records, wrange.expires));
            }
            Denial::NxDomain
        };
        Some(countdown(&parts, denial, now))
    }

    /// Drops expired entries, then the soonest-expiring ones past the bounds.
    fn trim(&mut self, now: Instant) {
        if self.by_owner.len() > MAX_RANGES {
            self.by_owner.retain(|_, r| r.expires > now);
        }
        while self.by_owner.len() > MAX_RANGES {
            let Some(k) = self
                .by_owner
                .iter()
                .min_by_key(|(_, r)| r.expires)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.by_owner.remove(&k);
        }
        if self.soas.len() > MAX_ZONES {
            self.soas.retain(|_, s| s.expires > now);
            while self.soas.len() > MAX_ZONES {
                let Some(k) = self
                    .soas
                    .iter()
                    .min_by_key(|(_, s)| s.expires)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                self.soas.remove(&k);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_owner.len() + self.nsec3.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_net::proto::dnssec::Nsec3HashAlgorithm;
    use hickory_net::proto::dnssec::rdata::{NSEC, NSEC3, RRSIG};
    use hickory_net::proto::dnssec::{Algorithm, rdata::sig::SigInput};
    use hickory_net::proto::rr::SerialNumber;
    use hickory_net::proto::rr::rdata::SOA;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn sig(owner: &str, covered: RecordType, signer: &str) -> Record {
        let input = SigInput {
            type_covered: covered,
            algorithm: Algorithm::ED25519,
            num_labels: 1,
            original_ttl: 86_400,
            sig_expiration: SerialNumber::new(u32::MAX),
            sig_inception: SerialNumber::new(0),
            key_tag: 1,
            signer_name: n(signer),
        };
        let mut r = Record::from_rdata(
            n(owner),
            86_400,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, vec![0; 64]))),
        );
        r.proof = Proof::Secure;
        r
    }

    fn nsec(owner: &str, next: &str, types: &[RecordType], ttl: u32) -> Record {
        let mut r = Record::from_rdata(
            n(owner),
            ttl,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(n(next), types.iter().copied()))),
        );
        r.proof = Proof::Secure;
        r
    }

    /// A secure denial from `zone` with these NSEC records.
    fn denial(zone: &str, rcode: ResponseCode, nsecs: &[Record]) -> Message {
        let mut m = Message::response(0, hickory_net::proto::op::OpCode::Query);
        m.metadata.response_code = rcode;
        let mut soa = Record::from_rdata(
            n(zone),
            86_400,
            RData::SOA(SOA::new(n("a.ns."), n("h.ns."), 1, 1, 1, 1, 3600)),
        );
        soa.proof = Proof::Secure;
        m.add_authority(soa);
        m.add_authority(sig(zone, RecordType::SOA, zone));
        for r in nsecs {
            m.add_authority(r.clone());
            m.add_authority(sig(&r.name.to_ascii(), r.record_type(), zone));
        }
        m
    }

    /// REQ: DNS-011 (T9.16) — the root's NXDOMAIN for one made-up TLD proves the next: the
    /// name and the root wildcard are both covered; the answer carries both NSEC records,
    /// their signatures, and the SOA, with the negative TTL.
    #[test]
    fn dns_011_rfc8198_nxdomain_from_cached_ranges() {
        let t0 = Instant::now();
        let mut r = Ranges::default();
        let m = denial(
            ".",
            ResponseCode::NXDomain,
            &[
                nsec(
                    "zw.",
                    ".",
                    &[
                        RecordType::NS,
                        RecordType::DS,
                        RecordType::RRSIG,
                        RecordType::NSEC,
                    ],
                    86_400,
                ),
                nsec(
                    ".",
                    "aaa.",
                    &[
                        RecordType::NS,
                        RecordType::SOA,
                        RecordType::RRSIG,
                        RecordType::NSEC,
                        RecordType::DNSKEY,
                    ],
                    86_400,
                ),
            ],
        );
        r.learn(&m, t0);
        assert_eq!(r.len(), 2);
        let s = r
            .synthesize(&n("zz-wrendns-2."), RecordType::A, t0)
            .expect("proven");
        assert_eq!(s.denial, Denial::NxDomain);
        let types: Vec<RecordType> = s.authorities.iter().map(Record::record_type).collect();
        assert_eq!(types.iter().filter(|t| **t == RecordType::NSEC).count(), 2);
        assert_eq!(types.iter().filter(|t| **t == RecordType::RRSIG).count(), 3);
        assert!(
            s.authorities.iter().all(|x| x.ttl <= 3600),
            "negative TTL caps all"
        );
        // Expired: nothing.
        assert!(
            r.synthesize(
                &n("zz-wrendns-2."),
                RecordType::A,
                t0 + Duration::from_secs(3601)
            )
            .is_none()
        );
    }

    /// REQ: DNS-011 (T9.16) — what isn't proven goes upstream: a name below a delegation the
    /// range starts at, an existing name's other type with CNAME, a missing wildcard proof,
    /// another zone's signature, an insecure record.
    #[test]
    fn dns_011_rfc8198_only_what_is_proven() {
        let t0 = Instant::now();
        let mut r = Ranges::default();
        r.learn(
            &denial(
                ".",
                ResponseCode::NXDomain,
                &[nsec(
                    "com.",
                    "commbank.",
                    &[
                        RecordType::NS,
                        RecordType::DS,
                        RecordType::RRSIG,
                        RecordType::NSEC,
                    ],
                    86_400,
                )],
            ),
            t0,
        );
        // Inside com.'s span but below the delegation: com's own zone decides.
        assert!(
            r.synthesize(&n("nothing-here.com."), RecordType::A, t0)
                .is_none()
        );
        // Covered, but no NSEC proves the root wildcard absent.
        assert!(r.synthesize(&n("comm."), RecordType::A, t0).is_none());

        let mut r = Ranges::default();
        r.learn(
            &denial(
                "example.",
                ResponseCode::NoError,
                &[nsec(
                    "www.example.",
                    "zzz.example.",
                    &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
                    600,
                )],
            ),
            t0,
        );
        let s = r
            .synthesize(&n("www.example."), RecordType::AAAA, t0)
            .expect("NODATA");
        assert_eq!(s.denial, Denial::NoData);
        assert!(
            r.synthesize(&n("www.example."), RecordType::A, t0)
                .is_none(),
            "the type exists"
        );

        // Signed by another zone, or not proven secure: not learned.
        let mut r = Ranges::default();
        let mut m = denial("example.", ResponseCode::NoError, &[]);
        m.add_authority(nsec("a.example.", "b.example.", &[RecordType::A], 600));
        m.add_authority(sig("a.example.", RecordType::NSEC, "other."));
        let mut insecure = nsec("c.example.", "d.example.", &[RecordType::A], 600);
        insecure.proof = Proof::Insecure;
        m.add_authority(insecure);
        m.add_authority(sig("c.example.", RecordType::NSEC, "example."));
        r.learn(&m, t0);
        assert_eq!(r.len(), 0);
    }

    // ---- REQ: DNS-907 (T40.6) — NSEC3 ranges ----

    const SALT: [u8; 2] = [0xab, 0xcd];

    fn hash3(it: u16, name: &Name) -> Vec<u8> {
        Nsec3HashAlgorithm::SHA1
            .hash(&SALT, name, it)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    /// base32hex, lowercase, no padding (RFC 4648 §7).
    fn b32(bytes: &[u8]) -> String {
        const T: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
        let mut out = String::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for b in bytes {
            acc = (acc << 8) | u32::from(*b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(char::from(T[((acc >> bits) & 31) as usize]));
            }
            acc &= (1 << bits) - 1;
        }
        if bits > 0 {
            out.push(char::from(T[((acc << (5 - bits)) & 31) as usize]));
        }
        out
    }

    fn nsec3_owner(zone: &str, hash: &[u8]) -> String {
        format!("{}.{zone}", b32(hash))
    }

    /// One NSEC3 record (secure) for the hash `owner`, pointing at `next`.
    fn nsec3(
        zone: &str,
        owner: &[u8],
        next: &[u8],
        it: u16,
        opt_out: bool,
        types: &[RecordType],
    ) -> Record {
        let mut r = Record::from_rdata(
            n(&nsec3_owner(zone, owner)),
            86_400,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                opt_out,
                it,
                SALT.to_vec(),
                next.to_vec(),
                types.iter().copied(),
            ))),
        );
        r.proof = Proof::Secure;
        r
    }

    type Chain = Vec<(Vec<u8>, Record)>;

    /// The full chain of a zone with these existing names: (owner hash, record), sorted.
    fn chain(zone: &str, it: u16, opt_out: bool, names: &[(&str, &[RecordType])]) -> Chain {
        let mut hashed: Vec<(Vec<u8>, &[RecordType])> = names
            .iter()
            .map(|(nm, t)| (hash3(it, &n(nm)), *t))
            .collect();
        hashed.sort();
        let count = hashed.len();
        (0..count)
            .map(|i| {
                let next = &hashed[(i + 1) % count].0;
                (
                    hashed[i].0.clone(),
                    nsec3(zone, &hashed[i].0, next, it, opt_out, hashed[i].1),
                )
            })
            .collect()
    }

    /// The chain record that covers `h`.
    fn covering<'a>(c: &'a Chain, h: &[u8]) -> &'a (Vec<u8>, Record) {
        c.iter()
            .rev()
            .find(|(o, _)| o.as_slice() < h)
            .unwrap_or_else(|| c.last().unwrap())
    }

    /// The chain record that matches `name`.
    fn matching(c: &Chain, it: u16, name: &Name) -> Record {
        c.iter()
            .find(|(o, _)| *o == hash3(it, name))
            .unwrap()
            .1
            .clone()
    }

    /// What an authoritative server sends for a name below `encloser` that doesn't exist.
    fn proof_records(c: &Chain, it: u16, encloser: &str, q: &Name) -> Vec<Record> {
        let enc = n(encloser);
        let next_closer = q.trim_to(usize::from(enc.num_labels()) + 1);
        let wildcard = enc.prepend_label("*").unwrap();
        let mut out: Vec<Record> = Vec::new();
        for r in [
            matching(c, it, &enc),
            covering(c, &hash3(it, &next_closer)).1.clone(),
            covering(c, &hash3(it, &wildcard)).1.clone(),
        ] {
            if !out.iter().any(|o| o.name == r.name) {
                out.push(r);
            }
        }
        out
    }

    const APEX_TYPES: &[RecordType] = &[
        RecordType::NS,
        RecordType::SOA,
        RecordType::RRSIG,
        RecordType::DNSKEY,
        RecordType::NSEC3PARAM,
    ];
    const A_TYPES: &[RecordType] = &[RecordType::A, RecordType::RRSIG];

    fn example_names() -> Vec<(&'static str, &'static [RecordType])> {
        vec![
            ("example.", APEX_TYPES),
            ("www.example.", A_TYPES),
            ("mail.example.", A_TYPES),
            ("sub.example.", &[RecordType::NS, RecordType::RRSIG]),
        ]
    }

    /// A name below `example.` whose next closer name is covered by the same record as `like`'s
    /// (or, with `other`, by a different one).
    fn name_like(c: &Chain, it: u16, like: &Name, other: bool) -> Name {
        let want = covering(c, &hash3(it, like)).0.clone();
        (0..10_000)
            .map(|i| n(&format!("zz-{i}.example.")))
            .find(|q| (covering(c, &hash3(it, q)).0 == want) != other && q != like)
            .unwrap()
    }

    /// REQ: DNS-907 (T40.6) — one signed NXDOMAIN proves the names of its span: the second name
    /// in it is answered from the cache with the closest encloser proof, signed; a name in a span
    /// not cached, an existing name's present type, and the type of a delegation go upstream.
    #[test]
    fn dns_907_nsec3_nxdomain_and_nodata_from_cached_ranges() {
        let t0 = Instant::now();
        let it = 5;
        let c = chain("example.", it, false, &example_names());
        let q1 = n("zz-first.example.");
        let proof = proof_records(&c, it, "example.", &q1);
        let mut r = Ranges::default();
        r.learn(&denial("example.", ResponseCode::NXDomain, &proof), t0);
        assert_eq!(r.len(), proof.len());
        let q2 = name_like(&c, it, &q1, false);
        let s = r.synthesize(&q2, RecordType::A, t0).expect("proven");
        assert_eq!(s.denial, Denial::NxDomain);
        let kinds: Vec<RecordType> = s.authorities.iter().map(Record::record_type).collect();
        assert!(kinds.contains(&RecordType::SOA));
        assert_eq!(
            kinds.iter().filter(|t| **t == RecordType::NSEC3).count(),
            proof.len()
        );
        assert_eq!(
            kinds.iter().filter(|t| **t == RecordType::RRSIG).count(),
            proof.len() + 1
        );
        assert!(s.authorities.iter().all(|x| x.ttl <= 3600));
        // Another span, not cached: nothing proven.
        let other = name_like(&c, it, &q1, true);
        assert!(r.synthesize(&other, RecordType::A, t0).is_none());
        // Expired: nothing.
        assert!(
            r.synthesize(&q2, RecordType::A, t0 + Duration::from_secs(3601))
                .is_none()
        );
        // ANY is never made up from a range.
        assert!(r.synthesize(&q2, RecordType::ANY, t0).is_none());

        // NODATA: the NSEC3 record matching `www.example.` lacks AAAA.
        let www = n("www.example.");
        let mut r = Ranges::default();
        let m = matching(&c, it, &www);
        r.learn(&denial("example.", ResponseCode::NoError, &[m]), t0);
        let s = r.synthesize(&www, RecordType::AAAA, t0).expect("NODATA");
        assert_eq!(s.denial, Denial::NoData);
        assert!(r.synthesize(&www, RecordType::A, t0).is_none(), "A exists");
        // At a delegation: any type but DS is the child zone's to answer.
        let sub = n("sub.example.");
        let m = matching(&c, it, &sub);
        let mut r = Ranges::default();
        r.learn(&denial("example.", ResponseCode::NoError, &[m]), t0);
        assert!(r.synthesize(&sub, RecordType::A, t0).is_none());
        assert!(r.synthesize(&sub, RecordType::DS, t0).is_some());
    }

    /// REQ: DNS-907 (T40.6) — a name under a delegation (the encloser has NS and no SOA) isn't
    /// denied by the parent's ranges.
    #[test]
    fn dns_907_nsec3_nothing_below_a_delegation() {
        let t0 = Instant::now();
        let it = 5;
        let c = chain("example.", it, false, &example_names());
        let q = n("deep.sub.example.");
        let mut all = proof_records(&c, it, "sub.example.", &q);
        all.push(matching(&c, it, &n("example.")));
        let mut r = Ranges::default();
        r.learn(&denial("example.", ResponseCode::NXDomain, &all), t0);
        assert!(r.synthesize(&q, RecordType::A, t0).is_none());
    }

    /// REQ: DNS-907 (T40.6) — an opt-out span never denies a name: it may hide an unsigned
    /// delegation. The records are kept (a matching record still proves NODATA for a name that
    /// exists), but no NXDOMAIN is made from the span.
    #[test]
    fn dns_907_nsec3_opt_out_spans_never_deny() {
        let t0 = Instant::now();
        let it = 5;
        let c = chain("example.", it, true, &example_names());
        let q1 = n("zz-first.example.");
        let proof = proof_records(&c, it, "example.", &q1);
        let mut r = Ranges::default();
        r.learn(&denial("example.", ResponseCode::NXDomain, &proof), t0);
        assert!(r.len() >= 2, "kept");
        let q2 = name_like(&c, it, &q1, false);
        assert!(r.synthesize(&q1, RecordType::A, t0).is_none());
        assert!(r.synthesize(&q2, RecordType::A, t0).is_none());
        // The same chain without the flag does deny.
        let c = chain("example.", it, false, &example_names());
        let proof = proof_records(&c, it, "example.", &q1);
        let mut r = Ranges::default();
        r.learn(&denial("example.", ResponseCode::NXDomain, &proof), t0);
        assert!(r.synthesize(&q1, RecordType::A, t0).is_some());
    }

    /// REQ: DNS-907 (T40.6) — records above the iteration limit are never cached (the limit is
    /// the validator's soft limit, 50); records not proven secure, or signed by another zone,
    /// are skipped; new hash parameters for a zone replace the old ranges.
    #[test]
    fn dns_907_nsec3_what_is_never_cached() {
        use crate::dnssec::NSEC3_SOFT_LIMIT;
        let t0 = Instant::now();
        for (it, kept) in [(NSEC3_SOFT_LIMIT, true), (NSEC3_SOFT_LIMIT + 1, false)] {
            let c = chain("example.", it, false, &example_names());
            let proof = proof_records(&c, it, "example.", &n("zz-first.example."));
            let mut r = Ranges::default();
            r.learn(&denial("example.", ResponseCode::NXDomain, &proof), t0);
            assert_eq!(r.len() > 0, kept, "iterations {it}");
        }
        let it = 5;
        let c = chain("example.", it, false, &example_names());
        let mut proof = proof_records(&c, it, "example.", &n("zz-first.example."));
        let total = proof.len();
        // One not secure, one signed by another zone.
        proof[0].proof = Proof::Insecure;
        let mut r = Ranges::default();
        let mut m = denial("example.", ResponseCode::NXDomain, &proof);
        let stranger = c
            .iter()
            .map(|(_, r)| r)
            .find(|r| !proof.iter().any(|p| p.name == r.name))
            .unwrap()
            .clone();
        m.add_authority(stranger.clone());
        m.add_authority(sig(&stranger.name.to_ascii(), RecordType::NSEC3, "other."));
        r.learn(&m, t0);
        assert_eq!(r.len(), total - 1);
        // Different parameters for the zone: the ranges of the old ones are dropped.
        let c2 = chain("example.", 7, false, &example_names());
        let p2 = proof_records(&c2, 7, "example.", &n("zz-first.example."));
        r.learn(&denial("example.", ResponseCode::NXDomain, &p2), t0);
        assert_eq!(r.len(), p2.len());
    }

    /// REQ: DNS-907 (T40.6) — bounded like the NSEC table: at most 20,000 ranges and 2,000
    /// zones, the soonest-expiring going first.
    #[test]
    fn dns_907_nsec3_is_bounded() {
        use crate::nsec3::{MAX_RANGES, MAX_ZONES, Nsec3Ranges};
        let t0 = Instant::now();
        let mut r = Nsec3Ranges::default();
        let zone = n("big.");
        let mut counter = 0u32;
        for batch in 0..42u32 {
            let mut m = Message::response(0, hickory_net::proto::op::OpCode::Query);
            for _ in 0..500 {
                counter += 1;
                let mut owner = vec![0u8; 20];
                owner[..4].copy_from_slice(&counter.to_be_bytes());
                let mut next = owner.clone();
                next[19] = 1;
                let rec = nsec3("big.", &owner, &next, 0, false, A_TYPES);
                m.add_authority(sig(&rec.name.to_ascii(), RecordType::NSEC3, "big."));
                m.add_authority(rec);
            }
            // Later batches live longer, so the first ones go first.
            r.learn(&m, &zone, 100 + batch, t0);
            assert!(r.len() <= MAX_RANGES);
        }
        assert_eq!(r.len(), MAX_RANGES);
        // Zones: one range each.
        let mut z = Nsec3Ranges::default();
        for i in 0..(MAX_ZONES + 20) {
            let name = format!("z{i}.");
            let mut m = Message::response(0, hickory_net::proto::op::OpCode::Query);
            let rec = nsec3(&name, &[1; 20], &[2; 20], 0, false, A_TYPES);
            m.add_authority(sig(&rec.name.to_ascii(), RecordType::NSEC3, &name));
            m.add_authority(rec);
            z.learn(&m, &n(&name), 3600, t0);
            assert!(z.len() <= MAX_ZONES);
        }
        assert_eq!(z.len(), MAX_ZONES);
    }

    /// REQ: DNS-907 (T40.6) — lookup cost (AGENTS rule 4: the hot path never reaches this, it
    /// runs on cache misses only): with a full chain, a miss costs two or three SHA-1 chains
    /// whatever the name's depth, so thousands of lookups fit in a fraction of a second.
    #[test]
    fn dns_907_nsec3_lookup_is_cheap() {
        use crate::nsec3::Nsec3Ranges;
        let t0 = Instant::now();
        let it = 10;
        let mut names: Vec<(String, Vec<RecordType>)> = vec![("big.".into(), APEX_TYPES.to_vec())];
        names.extend((0..5_000).map(|i| (format!("n{i}.big."), A_TYPES.to_vec())));
        let refs: Vec<(&str, &[RecordType])> = names
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_slice()))
            .collect();
        let c = chain("big.", it, false, &refs);
        let mut tables = Nsec3Ranges::default();
        // 500 records a message keeps the signature lookup short.
        for part in c.chunks(500) {
            let mut m = Message::response(0, hickory_net::proto::op::OpCode::Query);
            for (_, rec) in part {
                m.add_authority(sig(&rec.name.to_ascii(), RecordType::NSEC3, "big."));
                m.add_authority(rec.clone());
            }
            tables.learn(&m, &n("big."), 3600, t0);
        }
        assert_eq!(tables.len(), c.len());
        let start = std::time::Instant::now();
        let mut proven = 0;
        for i in 0..2_000 {
            let q = n(&format!("x{i}.a.b.c.d.e.f.g.h.i.j.k.l.m.nothing.big."));
            if tables.prove(&q, RecordType::A, t0).is_some() {
                proven += 1;
            }
        }
        assert_eq!(proven, 2_000, "every miss in a full chain is proven");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "2,000 lookups took {:?}",
            start.elapsed()
        );
    }
}

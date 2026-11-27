//! REQ: DNS-011 — DNSSEC validation offline, against a signed test root (T9.24): the root's
//! key is the trust anchor (an anchors file), and a fake upstream serves the zone's records with
//! their signatures, NSEC denials, and one forged signature. Covers the validator's secure,
//! NODATA, NXDOMAIN, bogus, and wrong-anchor paths, and RFC 8198 answering from cached NSEC
//! ranges without another upstream query. The root also delegates `u.` without a DS: an
//! unsigned zone with a CNAME chain (T10.9).

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use hickory_net::proto::dnssec::crypto::Ed25519SigningKey;
use hickory_net::proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, NSEC, NSEC3, RRSIG};
use hickory_net::proto::dnssec::{Algorithm, DigestType, Nsec3HashAlgorithm};
use hickory_net::proto::dnssec::{DnssecSigner, PublicKey as _, SigningKey};
use hickory_net::proto::op::{Message, OpCode, ResponseCode};
use hickory_net::proto::rr::rdata::{A, CNAME, NS, SOA};
use hickory_net::proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
use tokio::net::UdpSocket;
use wrendns_proto::{NameBuf, rtype};
use wrendns_upstream::dnssec::{Stats, Validator, Verdict};
use wrendns_upstream::{
    Endpoint, Group, Question, Strategy, TlsOptions, Upstream, UpstreamOptions,
};

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

/// The signed test root: record sets with their signatures, by (owner, type).
struct Zone {
    sets: BTreeMap<(Name, RecordType), Vec<Record>>,
    /// T10.9 — the unsigned zone `u.`, delegated from the root without a DS.
    plain: BTreeMap<(Name, RecordType), Vec<Record>>,
    /// The DNSKEY's RDATA, for the anchors file.
    key: Vec<u8>,
    /// ADR-098 — spoof `b.a.`: answer its A and SOA unsigned (an attacker's forgery for a
    /// name inside the signed root, with a made-up SOA so that it looks like a zone apex).
    forge: AtomicBool,
    /// NFR-004 — milliseconds every answer is held back (a slow upstream).
    lag_ms: AtomicU64,
    /// REQ: DNS-907 (T40.6) — set when the root is signed with an NSEC3 chain instead of NSEC.
    nsec3: Option<Nsec3Fix>,
}

/// REQ: DNS-907 (T40.6) — the hash parameters of an NSEC3-signed test root.
#[derive(Clone)]
struct Nsec3Cfg {
    iterations: u16,
    salt: Vec<u8>,
    /// Every NSEC3 record carries the opt-out flag and the unsigned delegation `u.` has none.
    opt_out: bool,
}

/// The names of the NSEC3 root and what exists at each (the chain is made from them).
const NSEC3_NAMES: [(&str, &[RecordType]); 5] = [
    (
        "z.",
        &[
            RecordType::NS,
            RecordType::SOA,
            RecordType::RRSIG,
            RecordType::DNSKEY,
        ],
    ),
    ("a.z.", &[RecordType::A, RecordType::RRSIG]),
    ("b.a.z.", &[RecordType::A, RecordType::RRSIG]),
    ("bad.z.", &[RecordType::A, RecordType::RRSIG]),
    ("u.z.", &[RecordType::NS]),
];

/// The chain: NSEC3 owner hashes, sorted, with the owner names of their records.
#[derive(Clone)]
struct Nsec3Fix {
    cfg: Nsec3Cfg,
    chain: Vec<(Vec<u8>, Name)>,
}

impl Nsec3Fix {
    fn hash(&self, name: &Name) -> Vec<u8> {
        Nsec3HashAlgorithm::SHA1
            .hash(&self.cfg.salt, name, self.cfg.iterations)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    /// The record owner whose hash is `h`.
    fn matching(&self, h: &[u8]) -> Option<&Name> {
        self.chain.iter().find(|(o, _)| o == h).map(|(_, n)| n)
    }

    /// The record owner whose span covers `h`: the greatest hash below it, or the last one.
    fn covering(&self, h: &[u8]) -> &Name {
        let (_, name) = self
            .chain
            .iter()
            .rev()
            .find(|(o, _)| o.as_slice() < h)
            .unwrap_or_else(|| self.chain.last().unwrap());
        name
    }

    /// A one-label name under `z.` (without the final dot) whose next closer proof uses the
    /// same covering record as `like` (or, with `other`, one that is neither that record nor the
    /// one that covers the wildcard `*.z.` or the apex's own, which the proof for `like` caches
    /// as well).
    fn name_like(&self, like: &Name, other: bool) -> String {
        let want = self.covering(&self.hash(like)).clone();
        let wild = self.covering(&self.hash(&n("*.z."))).clone();
        (0..10_000)
            .map(|i| format!("zz-{i}.z"))
            .find(|l| {
                let q = n(&format!("{l}."));
                let c = self.covering(&self.hash(&q));
                let cached =
                    *c == want || *c == wild || Some(c) == self.matching(&self.hash(&n("z.")));
                (cached != other) && q != *like
            })
            .unwrap()
    }
}

/// REQ: DNS-902 — iteration counts of the NSEC3 fixtures: above the soft limit (50) and the
/// default of hickory (100), and above the hard limit (500).
const NSEC3_ITERATIONS: [u16; 2] = [60, 600];

/// The NSEC3 owner name that matches the root for `iterations` (empty salt, SHA-1).
fn nsec3_owner(iterations: u16) -> Name {
    let hash = Nsec3HashAlgorithm::SHA1
        .hash(&[], &n("."), iterations)
        .unwrap();
    hash_owner(hash.as_ref(), "")
}

/// The NSEC3 owner name under `zone` (the root when empty) for a hash (base32hex).
fn hash_owner(hash: &[u8], zone: &str) -> Name {
    const T: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut label = String::new();
    for chunk in hash.chunks(5) {
        let mut block = [0u8; 8];
        block[3..3 + chunk.len()].copy_from_slice(chunk);
        let v = u64::from_be_bytes(block);
        for i in 0..(chunk.len() * 8).div_ceil(5) {
            label.push(char::from(
                T[usize::try_from((v >> (35 - 5 * i)) & 31).unwrap()],
            ));
        }
    }
    n(&format!("{label}.{zone}"))
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in data.chunks(3) {
        let v = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                s.push(char::from(
                    T[usize::try_from((v >> (18 - 6 * i)) & 63).unwrap()],
                ));
            } else {
                s.push('=');
            }
        }
    }
    s
}

fn zone() -> Zone {
    zone_with(None)
}

fn zone_with(nsec3_cfg: Option<Nsec3Cfg>) -> Zone {
    let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
    let key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
    let public = key.to_public_key().unwrap();
    let dnskey = DNSKEY::new(true, true, false, public.clone());
    let signer = DnssecSigner::new(
        dnskey.clone(),
        Box::new(key),
        n("."),
        Duration::from_hours(24),
    );
    let inception = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    let ttl = 3600;
    let soa = SOA::new(
        n("a.root-servers.test."),
        n("nstld.test."),
        1,
        1800,
        900,
        604_800,
        600,
    );
    let rrsets: Vec<(Name, Vec<RData>)> = vec![
        (n("."), vec![RData::SOA(soa.clone())]),
        (n("."), vec![RData::NS(NS(n("ns.a.")))]),
        (
            n("."),
            vec![RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone()))],
        ),
        (
            n("."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("a."),
                [
                    RecordType::NS,
                    RecordType::SOA,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                    RecordType::DNSKEY,
                ],
            )))],
        ),
        (n("a."), vec![RData::A(A::new(192, 0, 2, 1))]),
        (
            n("a."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("b.a."),
                [RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            )))],
        ),
        // An ordinary name inside the root (not a zone cut): its NSEC has no NS.
        (n("b.a."), vec![RData::A(A::new(192, 0, 2, 7))]),
        (
            n("b.a."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("bad."),
                [RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            )))],
        ),
        (n("bad."), vec![RData::A(A::new(192, 0, 2, 66))]),
        (
            n("bad."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("u."),
                [RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            )))],
        ),
        // T10.9 — `u.` is delegated without a DS: the NSEC proves NS and no DS.
        (
            n("u."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("."),
                [RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            )))],
        ),
    ];
    // REQ: DNS-902 (RFC 9276) — `n<iterations>.` is a name denied by one signed NSEC3 record
    // (matching the root) that hashes with that many iterations.
    let mut rrsets = rrsets;
    for iterations in NSEC3_ITERATIONS {
        rrsets.push((
            nsec3_owner(iterations),
            vec![RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                iterations,
                Vec::new(),
                vec![0xff; 20],
                [
                    RecordType::NS,
                    RecordType::SOA,
                    RecordType::RRSIG,
                    RecordType::DNSKEY,
                ],
            )))],
        ));
    }
    // REQ: DNS-907 (T40.6) — the secure child zone `z.`, signed with NSEC3 (hickory's NSEC3
    // validation asserts, in debug builds, that the zone is not the root): a second key, a DS
    // for it in the root, the root's NSEC chain with the delegation, and a signed NSEC3 chain
    // over the names of `z.` that exist.
    let mut nsec3_fix = None;
    let mut child_signer = None;
    if let Some(cfg) = nsec3_cfg {
        let ckey =
            Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap();
        let cdnskey = DNSKEY::new(true, true, false, ckey.to_public_key().unwrap());
        let ds = DS::new(
            cdnskey.calculate_key_tag().unwrap(),
            Algorithm::ED25519,
            DigestType::SHA256,
            cdnskey
                .to_digest(&n("z."), DigestType::SHA256)
                .unwrap()
                .as_ref()
                .to_vec(),
        );
        child_signer = Some(DnssecSigner::new(
            cdnskey.clone(),
            Box::new(ckey),
            n("z."),
            Duration::from_hours(24),
        ));
        // The root's NSEC chain: u. now points at z., which points back at the root.
        rrsets.retain(|(o, d)| {
            !(*o == n("u.") && matches!(d[0], RData::DNSSEC(DNSSECRData::NSEC(_))))
        });
        rrsets.push((
            n("u."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("z."),
                [RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            )))],
        ));
        rrsets.push((
            n("z."),
            vec![RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                n("."),
                [
                    RecordType::NS,
                    RecordType::DS,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                ],
            )))],
        ));
        rrsets.push((n("z."), vec![RData::DNSSEC(DNSSECRData::DS(ds))]));
        rrsets.push((
            n("z."),
            vec![RData::SOA(SOA::new(
                n("ns.a.z."),
                n("admin.z."),
                1,
                1800,
                900,
                604_800,
                600,
            ))],
        ));
        rrsets.push((n("z."), vec![RData::NS(NS(n("ns.a.z.")))]));
        rrsets.push((n("z."), vec![RData::DNSSEC(DNSSECRData::DNSKEY(cdnskey))]));
        rrsets.push((n("a.z."), vec![RData::A(A::new(192, 0, 2, 1))]));
        rrsets.push((n("b.a.z."), vec![RData::A(A::new(192, 0, 2, 7))]));
        rrsets.push((n("bad.z."), vec![RData::A(A::new(192, 0, 2, 66))]));
        let mut fix = Nsec3Fix {
            cfg: cfg.clone(),
            chain: Vec::new(),
        };
        let mut hashed: Vec<(Vec<u8>, &[RecordType])> = NSEC3_NAMES
            .iter()
            .filter(|(nm, _)| !(cfg.opt_out && *nm == "u.z."))
            .map(|(nm, types)| (fix.hash(&n(nm)), *types))
            .collect();
        hashed.sort();
        for (i, (h, types)) in hashed.iter().enumerate() {
            let next = hashed[(i + 1) % hashed.len()].0.clone();
            let owner = hash_owner(h, "z.");
            rrsets.push((
                owner.clone(),
                vec![RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                    Nsec3HashAlgorithm::SHA1,
                    cfg.opt_out,
                    cfg.iterations,
                    cfg.salt.clone(),
                    next,
                    types.iter().copied(),
                )))],
            ));
            fix.chain.push((h.clone(), owner));
        }
        nsec3_fix = Some(fix);
    }
    let mut sets = BTreeMap::new();
    for (name, datas) in rrsets {
        let rtype = datas[0].record_type();
        let mut rs = RecordSet::new(name.clone(), rtype, 0);
        let records: Vec<Record> = datas
            .into_iter()
            .map(|d| Record::from_rdata(name.clone(), ttl, d))
            .collect();
        for r in &records {
            rs.insert(r.clone(), 0);
        }
        // `z.`'s own records are signed by its key; the delegation's DS and NSEC by the root's.
        let child = n("z.").zone_of(&name)
            && !(name == n("z.") && matches!(rtype, RecordType::DS | RecordType::NSEC));
        let sg = match &child_signer {
            Some(c) if child => c,
            _ => &signer,
        };
        let mut sig = RRSIG::from_rrset(&rs, DNSClass::IN, inception, sg).unwrap();
        if name == n("bad.") && rtype == RecordType::A {
            // A forged signature: the record set is bogus.
            let input = sig.input().clone();
            let mut bytes = sig.sig().to_vec();
            bytes[0] ^= 0xff;
            sig = RRSIG::from_sig(input, bytes);
        }
        let mut all = records;
        all.push(Record::from_rdata(
            name.clone(),
            ttl,
            RData::DNSSEC(DNSSECRData::RRSIG(sig)),
        ));
        sets.insert((name, rtype), all);
    }
    let mut key_rdata = vec![1u8, 1, 3, 15]; // flags 257, protocol 3, algorithm 15 (Ed25519)
    key_rdata.extend_from_slice(public.public_bytes());
    // The unsigned zone: `www.u.` is a CNAME to `cdn.u.`, which has an address.
    let u_soa = SOA::new(n("ns.u."), n("admin.u."), 1, 1800, 900, 604_800, 300);
    let plain_sets: Vec<(Name, RData)> = vec![
        (n("u."), RData::SOA(u_soa)),
        (n("u."), RData::NS(NS(n("ns.u.")))),
        (n("www.u."), RData::CNAME(CNAME(n("cdn.u.")))),
        (n("cdn.u."), RData::A(A::new(192, 0, 2, 80))),
    ];
    let mut plain = BTreeMap::new();
    for (name, d) in plain_sets {
        let t = d.record_type();
        plain.insert((name.clone(), t), vec![Record::from_rdata(name, ttl, d)]);
    }
    Zone {
        sets,
        plain,
        key: key_rdata,
        forge: AtomicBool::new(false),
        lag_ms: AtomicU64::new(0),
        nsec3: nsec3_fix,
    }
}

/// T10.9 — `name` is in the unsigned zone `u.` (the delegation's DS question goes to the root).
fn in_plain(qn: &Name, qt: RecordType) -> bool {
    let u = n("u.");
    (*qn == u && qt != RecordType::DS) || (qn != &u && u.zone_of(qn))
}

/// T10.9 — an answer from the unsigned zone, chasing a CNAME the way a recursive resolver
/// does (also for a DS question about the CNAME's owner).
fn plain_answer(z: &Zone, m: &mut Message, qn: &Name, qt: RecordType) {
    let mut name = qn.clone();
    for _ in 0..4 {
        if let Some(rs) = z.plain.get(&(name.clone(), qt)) {
            m.add_answers(rs.clone());
            return;
        }
        let Some(c) = z.plain.get(&(name.clone(), RecordType::CNAME)) else {
            break;
        };
        m.add_answers(c.clone());
        let RData::CNAME(CNAME(target)) = c[0].data.clone() else {
            break;
        };
        name = target;
    }
    if m.answers.is_empty() {
        m.add_authorities(z.plain[&(n("u."), RecordType::SOA)].clone());
    }
}

/// The fake root server: answers from the zone (with signatures), NODATA or NXDOMAIN with the
/// SOA and the NSEC records that prove it. Counts the questions it gets.
async fn serve(z: Arc<Zone>, asked: Arc<AtomicUsize>) -> std::net::SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, from)) = s.recv_from(&mut buf).await else {
                return;
            };
            let Ok(q) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let Some(question) = q.queries.first().cloned() else {
                continue;
            };
            asked.fetch_add(1, Ordering::Relaxed);
            let lag = z.lag_ms.load(Ordering::Relaxed);
            if lag > 0 {
                tokio::time::sleep(Duration::from_millis(lag)).await;
            }
            let (qn, qt) = (question.name().clone(), question.query_type());
            let mut m = Message::response(q.metadata.id, OpCode::Query);
            m.metadata.recursion_desired = true;
            m.metadata.recursion_available = true;
            m.add_query(question);
            let authority = |m: &mut Message, owner: &Name| {
                m.add_authorities(z.sets[&(n("."), RecordType::SOA)].clone());
                m.add_authorities(z.sets[&(owner.clone(), RecordType::NSEC)].clone());
            };
            if z.forge.load(Ordering::Relaxed)
                && qn == n("b.a.")
                && matches!(qt, RecordType::A | RecordType::SOA)
            {
                let data = if qt == RecordType::A {
                    RData::A(A::new(192, 0, 2, 66))
                } else {
                    RData::SOA(SOA::new(
                        n("ns.b.a."),
                        n("x.b.a."),
                        1,
                        1800,
                        900,
                        604_800,
                        300,
                    ))
                };
                m.add_answers(vec![Record::from_rdata(qn.clone(), 300, data)]);
            } else if in_plain(&qn, qt) {
                plain_answer(&z, &mut m, &qn, qt);
            } else if let Some(rs) = z.sets.get(&(qn.clone(), qt)) {
                m.add_answers(rs.clone());
            } else if let Some(iterations) = NSEC3_ITERATIONS
                .into_iter()
                .find(|i| qn == n(&format!("n{i}.")))
            {
                // REQ: DNS-902 — NXDOMAIN, the root's SOA and the one NSEC3 record.
                m.metadata.response_code = ResponseCode::NXDomain;
                m.add_authorities(z.sets[&(n("."), RecordType::SOA)].clone());
                m.add_authorities(z.sets[&(nsec3_owner(iterations), RecordType::NSEC3)].clone());
            } else if let Some(f) = z.nsec3.as_ref().filter(|_| n("z.").zone_of(&qn)) {
                // REQ: DNS-907 (T40.6) — the NSEC3 root: NODATA from the record that matches
                // the name, NXDOMAIN with the closest encloser proof (RFC 5155 §7.2).
                m.add_authorities(z.sets[&(n("z."), RecordType::SOA)].clone());
                let set = |owner: &Name| z.sets[&(owner.clone(), RecordType::NSEC3)].clone();
                if let Some(o) = f.matching(&f.hash(&qn)) {
                    m.add_authorities(set(o));
                } else {
                    m.metadata.response_code = ResponseCode::NXDomain;
                    let mut enc = qn.base_name();
                    while f.matching(&f.hash(&enc)).is_none() {
                        enc = enc.base_name();
                    }
                    let next_closer = qn.trim_to(usize::from(enc.num_labels()) + 1);
                    let wildcard = enc.prepend_label("*").unwrap();
                    let mut owners = vec![
                        f.matching(&f.hash(&enc)).unwrap().clone(),
                        f.covering(&f.hash(&next_closer)).clone(),
                        f.covering(&f.hash(&wildcard)).clone(),
                    ];
                    owners.dedup();
                    owners.sort();
                    owners.dedup();
                    for o in owners {
                        m.add_authorities(set(&o));
                    }
                }
            } else if z.sets.keys().any(|(o, _)| *o == qn) {
                authority(&mut m, &qn);
            } else {
                // NXDOMAIN: the NSEC covering the name (the greatest owner before it), and the
                // root's own NSEC, which covers the wildcard `*.`.
                m.metadata.response_code = ResponseCode::NXDomain;
                let owners: Vec<&Name> = z
                    .sets
                    .keys()
                    .filter(|(_, t)| *t == RecordType::NSEC)
                    .map(|(o, _)| o)
                    .collect();
                let cover = owners
                    .iter()
                    .filter(|o| ***o < qn)
                    .max()
                    .map_or(n("."), |o| (*o).clone());
                authority(&mut m, &cover);
                if cover != n(".") {
                    m.add_authorities(z.sets[&(n("."), RecordType::NSEC)].clone());
                }
            }
            let mut edns = hickory_net::proto::op::Edns::new();
            edns.set_dnssec_ok(true);
            edns.set_max_payload(4096);
            m.set_edns(edns);
            if let Ok(out) = m.to_vec() {
                let _ = s.send_to(&out, from).await;
            }
        }
    });
    addr
}

fn question(name: &str, qtype: u16) -> Question {
    Question {
        name: NameBuf::from_presentation(name).unwrap(),
        qtype,
        qclass: 1,
        dnssec_ok: true,
        checking_disabled: false,
        client_subnet: 0,
    }
}

async fn setup(
    anchor: bool,
) -> (
    Validator,
    Arc<Group>,
    Arc<AtomicUsize>,
    Arc<Stats>,
    tempfile::TempDir,
) {
    setup_zone(anchor, Arc::new(zone())).await
}

async fn setup_zone(
    anchor: bool,
    z: Arc<Zone>,
) -> (
    Validator,
    Arc<Group>,
    Arc<AtomicUsize>,
    Arc<Stats>,
    tempfile::TempDir,
) {
    let asked = Arc::new(AtomicUsize::new(0));
    let addr = serve(Arc::clone(&z), Arc::clone(&asked)).await;
    let dir = tempfile::tempdir().unwrap();
    let anchors = dir.path().join("root.key");
    std::fs::write(
        &anchors,
        format!(". 3600 IN DNSKEY 257 3 15 {}\n", b64(&z.key[4..])),
    )
    .unwrap();
    let stats = Arc::new(Stats::default());
    let mut v = Validator::new(&[], Arc::clone(&stats));
    if anchor {
        v = v.with_anchors_file(Some(anchors.to_str().unwrap()));
    }
    let ep = Endpoint::parse(&format!("udp://{addr}")).unwrap();
    let up = Upstream::build(
        1,
        "root",
        ep,
        &UpstreamOptions::default(),
        &TlsOptions::default(),
    )
    .unwrap();
    let group = Arc::new(Group::new(
        "default",
        vec![Arc::new(up)],
        Strategy::Failover,
    ));
    (v, group, asked, stats, dir)
}

fn rcode(bytes: &[u8]) -> u16 {
    wrendns_proto::summarize(bytes).unwrap().rcode
}

/// REQ: DNS-011 — secure answers (AD for DO clients), signed NODATA and NXDOMAIN, a forged
/// signature is bogus (EDE 6).
#[tokio::test]
async fn dns_011_offline_signed_root() {
    let (v, g, _, _, _dir) = setup(true).await;
    let budget = Duration::from_secs(5);
    let r = v
        .resolve(&g, question("a", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Secure, "a. A");
    assert!(
        wrendns_proto::Header::parse(&r.bytes).unwrap().flags.ad(),
        "AD for a DO client"
    );

    let r = v
        .resolve(&g, question("a", rtype::AAAA), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, rcode(&r.bytes)),
        (Verdict::Secure, wrendns_proto::rcode::NOERROR),
        "NODATA"
    );

    let r = v
        .resolve(&g, question("zz-nope", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, rcode(&r.bytes)),
        (Verdict::Secure, wrendns_proto::rcode::NXDOMAIN),
        "NXDOMAIN"
    );

    let r = v
        .resolve(&g, question("bad", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Bogus, "forged signature");
    assert_eq!(r.ede, wrendns_proto::ede::DNSSEC_BOGUS);

    // Without DO (and AD not asked): no DNSSEC records, no AD.
    let r = v
        .resolve(&g, question("a", rtype::A), budget, false, false)
        .await
        .unwrap();
    assert!(!wrendns_proto::Header::parse(&r.bytes).unwrap().flags.ad());
}

/// REQ: DNS-902 (RFC 9276) — an NSEC3 denial that hashes with more iterations than the soft
/// limit validates as insecure (hickory's own limit, 100, would have judged 60 iterations on
/// the proof, which is incomplete here and so bogus); above the hard limit it is bogus.
#[tokio::test]
async fn dns_902_offline_nsec3_iterations_above_the_limit_are_insecure() {
    const { assert!(wrendns_upstream::dnssec::NSEC3_SOFT_LIMIT < 60) };
    const { assert!(wrendns_upstream::dnssec::NSEC3_HARD_LIMIT < 600) };
    let (v, g, _, _, _dir) = setup(true).await;
    let budget = Duration::from_secs(5);
    let r = v
        .resolve(&g, question("n60", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Insecure, "60 iterations");
    // RFC 9276 §3.2: an insecure answer because of the count carries EDE 27.
    assert_eq!(r.ede, wrendns_proto::ede::UNSUPPORTED_NSEC3_ITERATIONS);
    assert_eq!(rcode(&r.bytes), wrendns_proto::rcode::NXDOMAIN);
    let r = v
        .resolve(&g, question("n600", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Bogus, "600 iterations");
    assert_eq!(
        r.ede,
        wrendns_proto::ede::UNSUPPORTED_NSEC3_ITERATIONS,
        "SERVFAIL because of the count says so"
    );
}

/// REQ: DNS-011 (T9.16) — RFC 8198: after one signed NXDOMAIN, another name in the same range is
/// answered from the cached NSEC records: no upstream query, counted as synthesized, NXDOMAIN
/// with AD.
#[tokio::test]
async fn dns_011_offline_aggressive_nsec() {
    let (v, g, asked, stats, _dir) = setup(true).await;
    let budget = Duration::from_secs(5);
    let r = v
        .resolve(&g, question("zz-one", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(rcode(&r.bytes), wrendns_proto::rcode::NXDOMAIN);
    let before = asked.load(Ordering::Relaxed);
    let r = v
        .resolve(&g, question("zz-two", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, rcode(&r.bytes)),
        (Verdict::Secure, wrendns_proto::rcode::NXDOMAIN)
    );
    assert!(wrendns_proto::Header::parse(&r.bytes).unwrap().flags.ad());
    assert_eq!(
        asked.load(Ordering::Relaxed),
        before,
        "answered without asking upstream"
    );
    assert_eq!(stats.synthesized.load(Ordering::Relaxed), 1);
    // Switched off: it asks.
    let (v, g, asked, stats, _dir2) = setup(true).await;
    let v = v.with_aggressive_nsec(false);
    v.resolve(&g, question("zz-one", rtype::A), budget, true, false)
        .await
        .unwrap();
    let before = asked.load(Ordering::Relaxed);
    v.resolve(&g, question("zz-two", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert!(asked.load(Ordering::Relaxed) > before);
    assert_eq!(stats.synthesized.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-907 (T40.6) — an NSEC3-signed root, and the names that are in one span of its chain.
async fn nsec3_setup(
    cfg: Nsec3Cfg,
) -> (
    Validator,
    Arc<Group>,
    Arc<AtomicUsize>,
    Arc<Stats>,
    tempfile::TempDir,
    Nsec3Fix,
) {
    let z = zone_with(Some(cfg));
    let fix = z.nsec3.clone().unwrap();
    let (v, g, asked, stats, dir) = setup_zone(true, Arc::new(z)).await;
    (v, g, asked, stats, dir, fix)
}

fn nsec3_cfg(iterations: u16, opt_out: bool) -> Nsec3Cfg {
    Nsec3Cfg {
        iterations,
        salt: vec![0x12, 0x34],
        opt_out,
    }
}

/// REQ: DNS-907 (T40.6) — RFC 8198 with NSEC3: after one signed NXDOMAIN from a zone signed with
/// NSEC3 (salted, 3 iterations), another name in the same span is answered from the cached
/// records with the closest encloser proof, signed, with AD and no upstream query; a name in
/// another span asks; a NODATA at an existing name is made for another type of the name.
#[tokio::test]
async fn dns_907_offline_aggressive_nsec3() {
    let (v, g, asked, stats, _dir, fix) = nsec3_setup(nsec3_cfg(3, false)).await;
    let budget = Duration::from_secs(5);
    let q1 = n("zz-one.z.");
    let r = v
        .resolve(&g, question("zz-one.z", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, rcode(&r.bytes)),
        (Verdict::Secure, wrendns_proto::rcode::NXDOMAIN),
        "the NSEC3 denial validates"
    );
    assert_eq!(stats.synthesized.load(Ordering::Relaxed), 0);
    let before = asked.load(Ordering::Relaxed);
    let same = fix.name_like(&q1, false);
    let r = v
        .resolve(&g, question(&same, rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, rcode(&r.bytes)),
        (Verdict::Secure, wrendns_proto::rcode::NXDOMAIN)
    );
    assert!(wrendns_proto::Header::parse(&r.bytes).unwrap().flags.ad());
    assert_eq!(
        asked.load(Ordering::Relaxed),
        before,
        "answered without asking upstream"
    );
    assert_eq!(stats.synthesized.load(Ordering::Relaxed), 1);
    // The answer carries its proof: the SOA and NSEC3 records with signatures.
    let m = Message::from_vec(&r.bytes).unwrap();
    let kinds: Vec<RecordType> = m.authorities.iter().map(Record::record_type).collect();
    assert!(kinds.contains(&RecordType::SOA));
    let proof = kinds.iter().filter(|t| **t == RecordType::NSEC3).count();
    assert!(proof >= 2, "closest encloser, next closer and wildcard");
    assert_eq!(
        kinds.iter().filter(|t| **t == RecordType::RRSIG).count(),
        proof + 1
    );
    // Another span: it asks.
    let other = fix.name_like(&q1, true);
    let r = v
        .resolve(&g, question(&other, rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(rcode(&r.bytes), wrendns_proto::rcode::NXDOMAIN);
    assert!(asked.load(Ordering::Relaxed) > before, "asked upstream");
    assert_eq!(stats.synthesized.load(Ordering::Relaxed), 1);
    // NODATA: a. has no AAAA; once asked, its TXT is answered from the same record.
    let r = v
        .resolve(&g, question("a.z", rtype::AAAA), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, rcode(&r.bytes)),
        (Verdict::Secure, wrendns_proto::rcode::NOERROR)
    );
    let before = asked.load(Ordering::Relaxed);
    let r = v
        .resolve(&g, question("a.z", rtype::TXT), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, rcode(&r.bytes)),
        (Verdict::Secure, wrendns_proto::rcode::NOERROR)
    );
    assert_eq!(asked.load(Ordering::Relaxed), before, "NODATA from cache");
    assert_eq!(stats.synthesized.load(Ordering::Relaxed), 2);
    // The type that exists is not denied.
    let r = v
        .resolve(&g, question("a.z", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(rcode(&r.bytes), wrendns_proto::rcode::NOERROR);
    assert!(asked.load(Ordering::Relaxed) > before);
    assert_eq!(stats.synthesized.load(Ordering::Relaxed), 2);
    // Flushing the ranges drops the NSEC3 ones too.
    v.flush_ranges();
    let before = asked.load(Ordering::Relaxed);
    v.resolve(&g, question(&same, rtype::A), budget, true, false)
        .await
        .unwrap();
    assert!(asked.load(Ordering::Relaxed) > before);
}

/// REQ: DNS-907 (T40.6) — an opt-out span doesn't deny: with every NSEC3 record flagged opt-out
/// (and the unsigned delegation `u.` left out of the chain), a second name in the span of the
/// first is asked of the upstream, never answered from the cache.
#[tokio::test]
async fn dns_907_offline_nsec3_opt_out_span_is_not_used() {
    let (v, g, asked, stats, _dir, fix) = nsec3_setup(nsec3_cfg(3, true)).await;
    let budget = Duration::from_secs(5);
    let q1 = n("zz-one.z.");
    v.resolve(&g, question("zz-one.z", rtype::A), budget, true, false)
        .await
        .unwrap();
    let same = fix.name_like(&q1, false);
    let before = asked.load(Ordering::Relaxed);
    let r = v
        .resolve(&g, question(&same, rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(rcode(&r.bytes), wrendns_proto::rcode::NXDOMAIN);
    assert!(asked.load(Ordering::Relaxed) > before, "asked upstream");
    assert_eq!(stats.synthesized.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-907 (T40.6) — records that hash with more iterations than the soft limit (60 > 50)
/// are never cached: the answer is insecure (EDE 27) and a second name in the span asks again.
#[tokio::test]
async fn dns_907_offline_nsec3_over_the_limit_is_never_cached() {
    let (v, g, asked, stats, _dir, fix) = nsec3_setup(nsec3_cfg(60, false)).await;
    let budget = Duration::from_secs(5);
    let q1 = n("zz-one.z.");
    let r = v
        .resolve(&g, question("zz-one.z", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Insecure);
    let same = fix.name_like(&q1, false);
    let before = asked.load(Ordering::Relaxed);
    v.resolve(&g, question(&same, rtype::A), budget, true, false)
        .await
        .unwrap();
    assert!(asked.load(Ordering::Relaxed) > before, "asked upstream");
    assert_eq!(stats.synthesized.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-905 (T40.4) — a flush drops the cached NSEC ranges: a name in the same range is
/// then asked of the upstream again, not answered NXDOMAIN from the old proof.
#[tokio::test]
async fn dns_905_flush_ranges_stops_synthesis() {
    let (v, g, asked, stats, _dir) = setup(true).await;
    let budget = Duration::from_secs(5);
    v.resolve(&g, question("zz-one", rtype::A), budget, true, false)
        .await
        .unwrap();
    v.flush_ranges();
    let before = asked.load(Ordering::Relaxed);
    v.resolve(&g, question("zz-two", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert!(
        asked.load(Ordering::Relaxed) > before,
        "asked upstream again"
    );
    assert_eq!(stats.synthesized.load(Ordering::Relaxed), 0);
}

/// REQ: DNS-011 — with the real root's anchors (not the test key), the test root's answers
/// can't be proven: bogus.
#[tokio::test]
async fn dns_011_offline_wrong_anchor_is_bogus() {
    let (v, g, _, _, _dir) = setup(false).await;
    let r = v
        .resolve(
            &g,
            question("a", rtype::A),
            Duration::from_secs(5),
            true,
            false,
        )
        .await
        .unwrap();
    assert_ne!(r.verdict, Verdict::Secure);
}

/// REQ: DNS-011 (T10.9, ADR-098) — an answer in a zone delegated without a DS, reached through
/// a CNAME, is insecure (served, no AD), not bogus. Real resolvers answer the validator's DS
/// question about a CNAME's owner with the CNAME, as the fake root does.
#[tokio::test]
async fn dns_011_offline_unsigned_zone_through_cname_is_insecure() {
    let (v, g, _, stats, _dir) = setup(true).await;
    let budget = Duration::from_secs(5);
    let r = v
        .resolve(&g, question("www.u", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(
        r.verdict,
        Verdict::Insecure,
        "www.u. A (CNAME into the unsigned zone)"
    );
    assert_ne!(r.bytes.len(), 0, "an answer to serve");
    assert!(!wrendns_proto::Header::parse(&r.bytes).unwrap().flags.ad());
    let r = v
        .resolve(&g, question("cdn.u", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Insecure, "cdn.u. A");
    // The signed root is unaffected: a forged signature is still bogus.
    let r = v
        .resolve(&g, question("bad", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Bogus);
    assert_eq!(
        stats.bogus.load(Ordering::Relaxed),
        1,
        "only the forged signature"
    );
}

/// REQ: DNS-011 (ADR-098) — a spoofed, unsigned answer for a name inside the signed root
/// stays bogus even when the spoofer also forges an SOA for it. The root's secure denial of a
/// DS at `b.a.` proves there is no DS there, not that `b.a.` is a zone cut (its NSEC has no
/// NS), so the unsigned-zone proof must not accept it, and must not remember `b.a.` as an
/// unsigned zone for the questions that follow.
#[tokio::test]
async fn dns_011_offline_forged_apex_inside_signed_zone_stays_bogus() {
    let z = Arc::new(zone());
    let budget = Duration::from_secs(5);
    let (v, g, _, _, _dir) = setup_zone(true, Arc::clone(&z)).await;
    let r = v
        .resolve(&g, question("b.a", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Secure, "b.a. A, signed");

    z.forge.store(true, Ordering::Relaxed);
    let (v, g, _, stats, _dir2) = setup_zone(true, Arc::clone(&z)).await;
    for round in 1..=2 {
        let r = v
            .resolve(&g, question("b.a", rtype::A), budget, true, false)
            .await
            .unwrap();
        assert_eq!(
            r.verdict,
            Verdict::Bogus,
            "an unsigned answer inside the signed root (question {round})"
        );
    }
    assert_eq!(
        stats.insecure.load(Ordering::Relaxed),
        0,
        "never judged insecure"
    );
}

/// REQ: DNS-011, NFR-004 (ADR-098, review 03-05) — a validation that can't finish ends within
/// two query budgets whatever the upstream does (it holds an in-flight permit meanwhile): with
/// every answer taking two thirds of a budget, the lookup is cut off and the proof that would have
/// rescued it gets only what the deadline leaves. The verdict is the conservative one (no
/// answer: stale or SERVFAIL), and a name that couldn't be proven isn't walked again at once.
#[tokio::test]
async fn nfr_004_offline_slow_upstream_ends_within_two_budgets() {
    let z = Arc::new(zone());
    z.forge.store(true, Ordering::Relaxed);
    // Each answer takes two thirds of a budget: every attempt succeeds, but the chain of
    // lookups (the answer, the keys, the proof's SOA and DS) adds up to far more than two.
    z.lag_ms.store(200, Ordering::Relaxed);
    let (v, g, _, stats, _dir) = setup_zone(true, Arc::clone(&z)).await;
    let budget = Duration::from_millis(300);
    let started = std::time::Instant::now();
    let r = v
        .resolve(&g, question("b.a", rtype::A), budget, true, false)
        .await;
    let took = started.elapsed();
    assert!(r.is_err(), "no verdict from an upstream this slow: {r:?}");
    assert!(
        took < budget * 2 + Duration::from_millis(250),
        "ended after {took:?}, more than two budgets of {budget:?}"
    );
    assert_eq!(stats.insecure.load(Ordering::Relaxed), 0);
    // Asking again once the upstream is quick: the forged answer is still bogus, and the name
    // that couldn't be proven is not walked again (the proof is skipped for a minute).
    z.lag_ms.store(0, Ordering::Relaxed);
    let r = v
        .resolve(&g, question("b.a", rtype::A), budget, true, false)
        .await
        .unwrap();
    assert_eq!(r.verdict, Verdict::Bogus, "the forged answer, still bogus");
    assert_eq!(stats.insecure.load(Ordering::Relaxed), 0);
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b4; RFC 2136, RFC 8945) - the RFC 2136 provider against an in-process
//! DNS server that checks the TSIG of every request with hickory (an independent implementation),
//! signs its answers with hickory, and refuses an update outside the key's name and type; and
//! WrenDNS's TSIG code checked against messages hickory signed and verified.

#![allow(
    clippy::many_single_char_names,
    clippy::struct_excessive_bools,
    clippy::type_complexity,
    clippy::too_many_lines,
    clippy::format_push_string,
    clippy::format_collect,
    clippy::manual_let_else,
    clippy::single_match_else,
    clippy::doc_markdown
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hickory_net::proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_net::proto::rr::{Name, TSigResponseContext, TSigner};
use hickory_net::proto::serialize::binary::BinEncodable as _;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use wrendns_proto::{
    NameBuf, Prereq, Section, UpdateChange, build_update, class, read_name, records, rtype,
};
use zeroize::Zeroizing;

use super::rfc2136::Rfc2136;
use super::tsig::{TsigError, TsigKey, Verifier, sign, testing};
use super::{DnsProvider, ProviderErrorKind, RecordSet, RecordType};
use crate::secrets::value::SecretValue;

const KEY_BYTES: &[u8] = b"0123456789abcdef0123456789abcdef";
const OTHER_BYTES: &[u8] = b"fedcba9876543210fedcba9876543210";
/// The challenge name: the one name and type the server's grant covers.
const GRANTED: &str = "_acme-challenge.example.net.";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn signer(bytes: &[u8]) -> TSigner {
    TSigner::new(
        bytes.to_vec(),
        TsigAlgorithm::HmacSha256,
        Name::from_ascii("acme-key.").unwrap(),
        300,
    )
    .unwrap()
}

fn nb(s: &str) -> NameBuf {
    NameBuf::from_presentation(s).unwrap()
}

// ---------------------------------------------------------------------------------------------
// The in-process server
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct State {
    /// `(name, type)` to the TTL and the rdata of each value.
    sets: BTreeMap<(String, u16), (u32, Vec<Vec<u8>>)>,
    /// `(prerequisites, updates)` of each update the server accepted the signature of.
    updates: Vec<(usize, usize)>,
    /// Requests whose TSIG verified.
    verified: usize,
    /// Requests of any kind that arrived.
    arrived: usize,
    deny_transfer: bool,
    /// Sign answers with a different key.
    forge: bool,
    /// Change the result code after signing.
    tamper: bool,
    /// Send no TSIG.
    unsigned: bool,
    /// Sign with a time this many seconds off.
    skew: u64,
    /// Send the first transfer message and then the rest as an unsigned middle and a signed end.
    chain: bool,
}

type Shared = Arc<Mutex<State>>;

fn hdr(id: u16, rcode: u8, aa: bool, opcode: u8, qd: u16, an: u16) -> Vec<u8> {
    let flags: u16 =
        0x8000 | (u16::from(opcode) << 11) | if aa { 0x0400 } else { 0 } | u16::from(rcode);
    let mut h = Vec::new();
    for v in [id, flags, qd, an, 0, 0] {
        h.extend_from_slice(&v.to_be_bytes());
    }
    h
}

fn rr(name: &str, t: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut v = nb(name).as_wire().to_vec();
    v.extend_from_slice(&t.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&ttl.to_be_bytes());
    v.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    v.extend_from_slice(rdata);
    v
}

fn soa() -> Vec<u8> {
    let mut r = nb("ns1.example.net").as_wire().to_vec();
    r.extend_from_slice(nb("hostmaster.example.net").as_wire());
    for v in [1u32, 3600, 600, 86_400, 60] {
        r.extend_from_slice(&v.to_be_bytes());
    }
    rr("example.net", rtype::SOA, 3600, &r)
}

fn frame(m: &[u8]) -> Vec<u8> {
    let mut v = u16::try_from(m.len()).unwrap().to_be_bytes().to_vec();
    v.extend_from_slice(m);
    v
}

/// Signs `resp` as the server would for a request with `req_mac`.
fn sign_response(st: &State, id: u16, req_mac: Vec<u8>, resp: Vec<u8>) -> Vec<u8> {
    if st.unsigned {
        return resp;
    }
    let s = if st.forge {
        signer(OTHER_BYTES)
    } else {
        signer(KEY_BYTES)
    };
    let rec = TSigResponseContext::new(id, now() + st.skew, s, req_mac, None)
        .sign(&resp)
        .unwrap()
        .to_bytes()
        .unwrap();
    let mut out = resp;
    let n = u16::from_be_bytes([out[10], out[11]]) + 1;
    out[10..12].copy_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&rec);
    if st.tamper {
        out[3] = (out[3] & 0xF0) | 2; // SERVFAIL after signing
    }
    out
}

fn handle(st: &mut State, msg: &[u8]) -> Vec<Vec<u8>> {
    st.arrived += 1;
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let opcode = (msg[2] >> 3) & 0xF;
    let good = signer(KEY_BYTES);
    let (req_mac, time, _) = match good.verify_message_byte(msg, None, true) {
        Ok(v) => v,
        Err(_) => {
            // An unknown key or a bad signature: NOTAUTH, with an unsigned BADKEY TSIG.
            let resp = hdr(id, 9, false, opcode, 0, 0);
            let rec =
                TSigResponseContext::unknown_key(id, now(), Name::from_ascii("acme-key.").unwrap())
                    .sign(&resp)
                    .unwrap()
                    .to_bytes()
                    .unwrap();
            let mut out = resp;
            out[11] = 1;
            out.extend_from_slice(&rec);
            return vec![out];
        }
    };
    assert!(time.abs_diff(now()) < 300);
    st.verified += 1;
    if opcode == 5 {
        let (mut pre, mut upd) = (Vec::new(), Vec::new());
        for r in records(msg).unwrap() {
            let r = r.unwrap();
            let mut n = NameBuf::default();
            read_name(msg, r.name_off, &mut n).unwrap();
            let row = (
                n.display().to_string(),
                r.rtype,
                r.rclass,
                r.ttl,
                r.rdata(msg).to_vec(),
            );
            match r.section {
                Section::Answer => pre.push(row),
                Section::Authority => upd.push(row),
                Section::Additional => {}
            }
        }
        let mut rcode = 0u8;
        for (n, t, c, _, _) in &pre {
            let apex = n == "example.net";
            let present = apex || st.sets.keys().any(|(k, _)| k == n);
            if *c == 255 && *t == 255 && !present {
                rcode = 7;
            }
        }
        // The key's grant: the challenge name, TXT only.
        for (n, t, ..) in &upd {
            if n != GRANTED.trim_end_matches('.') || *t != rtype::TXT {
                rcode = 5;
            }
        }
        if rcode == 0 {
            for (n, t, c, ttl, d) in &upd {
                let k = (n.clone(), *t);
                if *c == 255 {
                    st.sets.remove(&k);
                } else if *c == 1 {
                    let e = st.sets.entry(k).or_insert((*ttl, Vec::new()));
                    e.0 = *ttl;
                    e.1.push(d.clone());
                }
            }
            st.updates.push((pre.len(), upd.len()));
        }
        let resp = hdr(id, rcode, false, 5, 0, 0);
        return vec![sign_response(st, id, req_mac, resp)];
    }
    // A zone transfer.
    if st.deny_transfer {
        return vec![sign_response(st, id, req_mac, hdr(id, 5, false, 0, 0, 0))];
    }
    let mut records_wire: Vec<Vec<u8>> = Vec::new();
    for ((n, t), (ttl, vals)) in &st.sets {
        for v in vals {
            records_wire.push(rr(n, *t, *ttl, v));
        }
    }
    let question = &msg[12..msg.len().min(12 + nb("example.net").wire_len() + 4)];
    let mk = |q: bool, recs: &[&Vec<u8>]| {
        let mut m = hdr(
            id,
            0,
            true,
            0,
            u16::from(q),
            u16::try_from(recs.len()).unwrap(),
        );
        if q {
            m.extend_from_slice(question);
        }
        for r in recs {
            m.extend_from_slice(r);
        }
        m
    };
    if !st.chain {
        let s = soa();
        let mut all: Vec<&Vec<u8>> = vec![&s];
        all.extend(records_wire.iter());
        all.push(&s);
        return vec![sign_response(st, id, req_mac, mk(true, &all))];
    }
    // Three messages: the first signed, the middle not signed, the last signed (RFC 8945 5.3.1).
    let s = soa();
    let half = records_wire.len() / 2;
    let m1 = mk(
        true,
        &std::iter::once(&s)
            .chain(records_wire[..half].iter())
            .collect::<Vec<_>>(),
    );
    let m2 = mk(false, &records_wire[half..].iter().collect::<Vec<_>>());
    let m3 = mk(false, &[&s]);
    let k = TsigKey::new("acme-key", &b64(KEY_BYTES)).unwrap();
    let m1 = sign_response(st, id, req_mac, m1);
    // The MAC of the first message is the one in its TSIG record: read it back.
    let mac1 = {
        let r = records(&m1).unwrap().last().unwrap().unwrap();
        let rd = r.rdata(&m1);
        let alg_len = 1 + 11 + 1;
        let mac_len = usize::from(u16::from_be_bytes([rd[alg_len + 8], rd[alg_len + 9]]));
        rd[alg_len + 10..alg_len + 10 + mac_len].to_vec()
    };
    let mut m3 = m3;
    testing::sign_answer(&mut m3, &k, &mac1, &m2, false, now());
    vec![m1, m2, m3]
}

async fn serve(state: Shared) -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let st = Arc::clone(&state);
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut msg = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    if s.read_exact(&mut msg).await.is_err() {
                        return;
                    }
                    let out = handle(&mut st.lock().unwrap(), &msg);
                    for m in out {
                        if s.write_all(&frame(&m)).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    addr
}

fn cfg(server: &str) -> wrendns_config::DnsProviderConfig {
    let v: Value = json!({
        "name": "bind", "kind": "rfc2136", "zone": "example.net", "credential_ref": "tsig",
        "server": server, "key_name": "acme-key", "dry_run": false
    });
    serde_json::from_value(v).unwrap()
}

fn provider_with(server: &str, key: &[u8]) -> Rfc2136 {
    let s = SecretValue::from_text(Zeroizing::new(b64(key)));
    Rfc2136::new(&cfg(server), Some(&s))
}

fn txt(name: &str, ttl: u32, values: &[&str]) -> RecordSet {
    RecordSet {
        name: name.to_owned(),
        rtype: RecordType::Txt,
        ttl,
        values: values.iter().map(|s| (*s).to_owned()).collect(),
    }
}

async fn start() -> (Shared, String) {
    let st: Shared = Arc::default();
    let addr = serve(Arc::clone(&st)).await;
    (st, addr)
}

#[tokio::test]
async fn cld_904_rfc2136_update_against_in_process_server_that_checks_tsig() {
    let (st, addr) = start().await;
    st.lock().unwrap().chain = true;
    // Something already in the zone, not made by us (a transfer lists it).
    st.lock().unwrap().sets.insert(
        ("www.example.net".into(), rtype::A),
        (300, vec![vec![192, 0, 2, 10]]),
    );
    let p = provider_with(&addr, KEY_BYTES);
    // Create with two values (one update message: delete the set, add both).
    p.ensure(&txt("_acme-challenge.example.net", 60, &["tok-b", "tok-a"]))
        .await
        .unwrap();
    {
        let g = st.lock().unwrap();
        let (ttl, vals) = &g.sets[&("_acme-challenge.example.net".to_owned(), rtype::TXT)];
        assert_eq!((*ttl, vals.len()), (60, 2));
        assert_eq!(g.updates.last(), Some(&(0, 3)), "delete, add, add");
    }
    // The signed zone transfer (an unsigned middle message included) lists it, and the A set.
    let l = p.list().await.unwrap();
    let t = l.iter().find(|s| s.rtype == RecordType::Txt).unwrap();
    assert_eq!(t.name, "_acme-challenge.example.net");
    assert_eq!(t.values, vec!["tok-a".to_owned(), "tok-b".to_owned()]);
    assert_eq!(t.ttl, 60);
    let a = l.iter().find(|s| s.rtype == RecordType::A).unwrap();
    assert_eq!(
        (a.name.as_str(), a.values[0].as_str()),
        ("www.example.net", "192.0.2.10")
    );
    // Replace the set.
    p.ensure(&txt("_acme-challenge.example.net", 120, &["tok-c"]))
        .await
        .unwrap();
    let l = p.list().await.unwrap();
    let t = l.iter().find(|s| s.rtype == RecordType::Txt).unwrap();
    assert_eq!((t.values.clone(), t.ttl), (vec!["tok-c".to_owned()], 120));
    // A long TXT value is split into character strings and read back whole.
    let long = "y".repeat(700);
    p.ensure(&txt("_acme-challenge.example.net", 60, &[&long]))
        .await
        .unwrap();
    let l = p.list().await.unwrap();
    assert_eq!(
        l.iter()
            .find(|s| s.rtype == RecordType::Txt)
            .unwrap()
            .values,
        vec![long]
    );
    // Delete.
    p.delete("_acme-challenge.example.net", RecordType::Txt)
        .await
        .unwrap();
    let l = p.list().await.unwrap();
    assert!(l.iter().all(|s| s.rtype != RecordType::Txt));
    let g = st.lock().unwrap();
    assert_eq!(
        g.verified, g.arrived,
        "the server verified the TSIG of every request"
    );
    assert!(g.arrived >= 8);
}

#[tokio::test]
async fn cld_904_rfc2136_update_outside_key_name_or_type_is_refused() {
    let (st, addr) = start().await;
    let p = provider_with(&addr, KEY_BYTES);
    // Another name: the server's grant refuses it, and the error says so.
    let e = p
        .ensure(&txt("other.example.net", 60, &["x"]))
        .await
        .unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Forbidden, "{e}");
    assert!(e.to_string().contains("REFUSED"), "{e}");
    // Another type at the granted name.
    let e = p
        .ensure(&RecordSet {
            name: "_acme-challenge.example.net".into(),
            rtype: RecordType::A,
            ttl: 60,
            values: vec!["192.0.2.1".into()],
        })
        .await
        .unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Forbidden);
    let e = p
        .delete("other.example.net", RecordType::Txt)
        .await
        .unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Forbidden);
    assert!(st.lock().unwrap().sets.is_empty(), "nothing changed");
    // Names that could carry an escape never reach the encoder.
    let n = st.lock().unwrap().arrived;
    assert!(
        p.ensure(&txt("a\\046b.example.net", 60, &["x"]))
            .await
            .is_err()
    );
    assert_eq!(st.lock().unwrap().arrived, n);
}

#[tokio::test]
async fn cld_904_rfc2136_the_test_sends_a_prerequisite_only_update() {
    let (st, addr) = start().await;
    let p = provider_with(&addr, KEY_BYTES);
    let s = p.scope().await.unwrap();
    assert!(
        s.summary
            .contains("accepted a signed update for example.net"),
        "{s:?}"
    );
    assert!(
        s.notes
            .iter()
            .any(|n| n.contains("does not report what a key may change"))
    );
    {
        let g = st.lock().unwrap();
        assert_eq!(g.updates, vec![(1, 0)], "one prerequisite, no change");
        assert!(g.sets.is_empty());
    }
    // A key that may update but not transfer: the Test says what to add.
    st.lock().unwrap().deny_transfer = true;
    let e = p.scope().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Forbidden);
    assert!(e.to_string().contains("allow-transfer"), "{e}");
}

#[tokio::test]
async fn cld_904_rfc2136_a_wrong_key_is_unauthorized_and_never_shown() {
    let (_st, addr) = start().await;
    let p = provider_with(&addr, OTHER_BYTES);
    let e = p.scope().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Unauthorized, "{e}");
    let text = format!("{e} {e:?}");
    for secret in [b64(OTHER_BYTES), b64(KEY_BYTES)] {
        assert!(!text.contains(&secret), "{text}");
    }
    // A secret that is not base64, and none at all.
    let bad = Rfc2136::new(
        &cfg(&addr),
        Some(&SecretValue::from_text(Zeroizing::new(
            "not base64 !!".into(),
        ))),
    );
    let e = bad.list().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Unauthorized);
    assert!(!e.to_string().contains("not base64 !!"));
    assert_eq!(
        Rfc2136::new(&cfg(&addr), None)
            .list()
            .await
            .unwrap_err()
            .kind,
        ProviderErrorKind::Unauthorized
    );
}

#[tokio::test]
async fn cld_904_rfc2136_an_answer_that_does_not_verify_is_not_believed() {
    for (name, set) in [
        ("forged", (|s: &mut State| s.forge = true) as fn(&mut State)),
        ("tampered", |s| s.tamper = true),
        ("unsigned", |s| s.unsigned = true),
        ("skewed", |s| s.skew = 1000),
    ] {
        let (st, addr) = start().await;
        set(&mut st.lock().unwrap());
        let p = provider_with(&addr, KEY_BYTES);
        let e = p
            .ensure(&txt("_acme-challenge.example.net", 60, &["x"]))
            .await
            .unwrap_err();
        assert_eq!(e.kind, ProviderErrorKind::Rejected, "{name}: {e}");
        assert!(e.to_string().contains("cannot be trusted"), "{name}: {e}");
        assert!(p.list().await.is_err(), "{name}");
    }
}

#[tokio::test]
async fn cld_904_rfc2136_an_unreachable_server_is_unavailable() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    drop(l);
    let e = provider_with(&addr, KEY_BYTES).scope().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Unavailable, "{e}");
}

#[tokio::test]
async fn cld_904_rfc2136_through_the_engine_with_audit_and_ledger() {
    use crate::credential_tests::harness;
    use crate::dns_provider::engine::{Outcome, Who, engine};
    use crate::dns_provider::ledger::Ledger;

    let h = harness("");
    let (st, addr) = start().await;
    let c = cfg(&addr);
    let mut c = c;
    c.max_writes_per_minute = 60;
    c.max_writes_per_hour = 1000;
    let secret = b64(KEY_BYTES);
    let handle = crate::dns_provider::registry::Handle {
        provider: Arc::new(provider_with(&addr, KEY_BYTES)),
        secret: Some(SecretValue::from_text(Zeroizing::new(secret.clone()))),
    };
    let who = Who::User {
        name: "ada".into(),
        kind: "session",
        remote: None,
        reason: None,
    };
    let o = engine()
        .ensure(
            &h.auth,
            &c,
            &handle,
            &who,
            &txt("_acme-challenge.example.net", 60, &["t1"]),
        )
        .await
        .unwrap();
    assert!(matches!(o, Outcome::Written { .. }), "{o:?}");
    assert!(
        Ledger(h.auth.state())
            .get("bind", RecordType::Txt, "_acme-challenge.example.net")
            .is_some()
    );
    // Outside the zone: the engine refuses before the provider (the server sees nothing).
    let n = st.lock().unwrap().arrived;
    let e = engine()
        .ensure(
            &h.auth,
            &c,
            &handle,
            &who,
            &txt("x.example.org", 60, &["t"]),
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains("outside the zone"), "{e}");
    assert_eq!(st.lock().unwrap().arrived, n);
    // A type the table never writes.
    let e = engine()
        .ensure(
            &h.auth,
            &c,
            &handle,
            &who,
            &RecordSet {
                name: "_acme-challenge.example.net".into(),
                rtype: RecordType::Txt,
                ttl: 0,
                values: vec!["t".into()],
            },
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains("TTL"), "{e}");
    let o = engine()
        .delete(
            &h.auth,
            &c,
            &handle,
            &who,
            "_acme-challenge.example.net",
            RecordType::Txt,
        )
        .await
        .unwrap();
    assert!(matches!(o, Outcome::Written { .. }));
    let audit = h.audit_text();
    assert!(audit.contains("dns_provider.ensure") && audit.contains("dns_provider.delete"));
    assert!(!audit.contains(&secret), "the key is not in the audit log");
}

// ---------------------------------------------------------------------------------------------
// TSIG against hickory
// ---------------------------------------------------------------------------------------------

fn update_bytes(id: u16) -> Vec<u8> {
    let (zone, name) = (nb("example.net"), nb("_acme-challenge.example.net"));
    let mut buf = vec![0u8; 512];
    let n = build_update(
        &mut buf,
        id,
        &zone,
        &[Prereq::NameInUse(&zone)],
        &[UpdateChange::DeleteRrset(&name, rtype::TXT)],
    )
    .unwrap();
    buf.truncate(n);
    buf
}

/// A request signed here is verified by hickory, and hickory's MAC is ours.
#[test]
fn cld_904_tsig_matches_independently_signed_messages() {
    let key = TsigKey::new("acme-key", &b64(KEY_BYTES)).unwrap();
    let t = now();
    let mut msg = update_bytes(0x4242);
    let mac = sign(&mut msg, &key, t).unwrap();
    let (their_mac, their_time, range) = signer(KEY_BYTES)
        .verify_message_byte(&msg, None, true)
        .unwrap();
    assert_eq!(their_mac, mac);
    assert_eq!(their_time, t);
    assert!(range.contains(&t));
    // Another key does not verify.
    assert!(
        signer(OTHER_BYTES)
            .verify_message_byte(&msg, None, true)
            .is_err()
    );

    // An answer signed by hickory is verified here.
    let resp = hdr(0x4242, 0, false, 5, 0, 0);
    let rec = TSigResponseContext::new(0x4242, t, signer(KEY_BYTES), mac.clone(), None)
        .sign(&resp)
        .unwrap()
        .to_bytes()
        .unwrap();
    let mut signed = resp.clone();
    signed[11] = 1;
    signed.extend_from_slice(&rec);
    Verifier::new(&key, mac.clone(), t).check(&signed).unwrap();
    // A flipped bit, another request's MAC, another key, and a stale time each fail.
    let mut bad = signed.clone();
    bad[3] ^= 2;
    assert_eq!(
        Verifier::new(&key, mac.clone(), t).check(&bad),
        Err(TsigError::BadMac)
    );
    assert_eq!(
        Verifier::new(&key, vec![0; 32], t).check(&signed),
        Err(TsigError::BadMac)
    );
    let other = TsigKey::new("acme-key", &b64(OTHER_BYTES)).unwrap();
    assert_eq!(
        Verifier::new(&other, mac.clone(), t).check(&signed),
        Err(TsigError::BadMac)
    );
    assert_eq!(
        Verifier::new(&key, mac.clone(), t + 1000).check(&signed),
        Err(TsigError::BadTime)
    );
    assert_eq!(
        Verifier::new(&key, mac.clone(), t).check(&resp),
        Err(TsigError::Missing)
    );
    let wrong_name = TsigKey::new("other-key", &b64(KEY_BYTES)).unwrap();
    assert_eq!(
        Verifier::new(&wrong_name, mac, t).check(&signed),
        Err(TsigError::WrongKey)
    );
}

/// The chain rule (an unsigned middle message, a signed end digesting only the timers) is the one
/// hickory verifies.
#[test]
fn cld_904_tsig_chain_of_a_transfer_matches_hickory() {
    let key = TsigKey::new("acme-key", &b64(KEY_BYTES)).unwrap();
    let t = now();
    let mut req = update_bytes(7);
    let req_mac = sign(&mut req, &key, t).unwrap();
    let req_mac2 = req_mac.clone();
    let m1 = hdr(7, 0, true, 0, 0, 0);
    let rec = TSigResponseContext::new(7, t, signer(KEY_BYTES), req_mac.clone(), None)
        .sign(&m1)
        .unwrap()
        .to_bytes()
        .unwrap();
    let mut m1s = m1.clone();
    m1s[11] = 1;
    m1s.extend_from_slice(&rec);
    let mut v = Verifier::new(&key, req_mac, t);
    v.check(&m1s).unwrap();
    assert_eq!(v.finish(), Ok(()));
    let mac1 = {
        let r = records(&m1s).unwrap().last().unwrap().unwrap();
        let rd = r.rdata(&m1s);
        let a = 13;
        let ml = usize::from(u16::from_be_bytes([rd[a + 8], rd[a + 9]]));
        rd[a + 10..a + 10 + ml].to_vec()
    };
    let m2 = hdr(7, 0, true, 0, 0, 0);
    let mut m3 = hdr(7, 0, true, 0, 0, 0);
    testing::sign_answer(&mut m3, &key, &mac1, &m2, false, t);
    v.check(&m2).unwrap();
    assert_eq!(
        v.finish(),
        Err(TsigError::Missing),
        "the transfer must end signed"
    );
    v.check(&m3).unwrap();
    assert_eq!(v.finish(), Ok(()));
    // A middle message changed after the fact breaks the end.
    let mut v = Verifier::new(&key, req_mac2, t);
    v.check(&m1s).unwrap();
    let mut m2_bad = m2.clone();
    m2_bad[0] ^= 1;
    v.check(&m2_bad).unwrap();
    assert_eq!(v.check(&m3), Err(TsigError::BadMac));
}

/// The timers-only digest of a message that follows a signed one is the one hickory checks.
#[test]
fn cld_904_tsig_second_message_of_a_chain_verifies_under_hickory() {
    let key = TsigKey::new("acme-key", &b64(KEY_BYTES)).unwrap();
    let t = now();
    let prior = vec![9u8; 32];
    let mut m = hdr(7, 0, true, 0, 0, 0);
    let mac = testing::sign_answer(&mut m, &key, &prior, &[], false, t);
    let (their, _, _) = signer(KEY_BYTES)
        .verify_message_byte(&m, Some(&prior), false)
        .unwrap();
    assert_eq!(their, mac);
}

#[test]
fn cld_904_tsig_key_input_is_checked() {
    assert!(TsigKey::new("acme-key", "not base64 !!").is_err());
    assert!(TsigKey::new("acme-key", "").is_err());
    assert!(TsigKey::new("bad name", &b64(KEY_BYTES)).is_err());
    assert!(TsigKey::new("", &b64(KEY_BYTES)).is_err());
    let k = TsigKey::new("acme-key", &b64(KEY_BYTES)).unwrap();
    assert!(!format!("{k:?}").contains(&b64(KEY_BYTES)));
    let _ = (class::IN, Section::Answer);
}

#[tokio::test]
async fn cld_904_rfc2136_the_largest_engine_record_set_fits_one_update() {
    let (st, addr) = start().await;
    let p = provider_with(&addr, KEY_BYTES);
    let values: Vec<String> = (0..16)
        .map(|i| format!("{i:x}{}", "x".repeat(1019)))
        .collect();
    let refs: Vec<&str> = values.iter().map(String::as_str).collect();
    p.ensure(&txt("_acme-challenge.example.net", 60, &refs))
        .await
        .unwrap();
    let g = st.lock().unwrap();
    let (_, vals) = &g.sets[&("_acme-challenge.example.net".to_owned(), rtype::TXT)];
    assert_eq!(vals.len(), 16);
}

#[tokio::test]
async fn cld_904_rfc2136_scope_does_not_claim_types_it_did_not_check() {
    let (_st, addr) = start().await;
    let s = provider_with(&addr, KEY_BYTES).scope().await.unwrap();
    assert_eq!(s.record_types, vec![RecordType::Txt]);
    assert!(s.summary.contains("NOT checked"), "{s:?}");
}

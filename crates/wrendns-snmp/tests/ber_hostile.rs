//! REQ: DSC-003 (ADR-908) — the decoder against hostile input. Nothing here may panic, and what
//! a decode returns stays bounded by the input (no allocation from a declared length). The
//! cases are the ones the fuzz target `snmp_ber` finds by search, written down as a fixed set
//! plus a seeded mutation sweep, so a regression fails `cargo test` without a fuzzer.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use wrendns_snmp::ber::{self, DecodeError, MAX_DEPTH, MAX_MESSAGE, MAX_VARBINDS};
use wrendns_snmp::oid::Oid;
use wrendns_snmp::pdu::{self, RequestKind, TAG_RESPONSE, Value, VarBind};
use wrendns_snmp::v2c;

/// Everything the client runs on a received datagram, as the fuzz target does.
fn decode_all(data: &[u8]) {
    let _ = ber::read_tlv(data);
    if let Ok(tlv) = ber::read_message(data) {
        let _ = ber::children(tlv.content, 0, MAX_VARBINDS);
        let _ = pdu::decode_varbinds(tlv.content);
        let _ = ber::integer_value(tlv.content);
        let _ = ber::unsigned_value(tlv.content);
        let _ = pdu::decode_value(tlv);
    }
    if let Ok(d) = v2c::decode(data) {
        // The result is bounded by the input and by the caps.
        assert!(d.response.varbinds.len() <= MAX_VARBINDS);
        assert!(d.community.len() <= data.len());
        for vb in &d.response.varbinds {
            let _ = vb.oid.to_string();
        }
    }
    let _ = Oid::from_content(data);
}

fn reply() -> Vec<u8> {
    let vbs = vec![
        VarBind {
            oid: Oid::parse("1.3.6.1.2.1.1.5.0").unwrap(),
            value: Value::OctetString(b"tt-snmpd-test".to_vec()),
        },
        VarBind {
            oid: Oid::parse("1.3.6.1.2.1.1.3.0").unwrap(),
            value: Value::TimeTicks(123_456),
        },
        VarBind {
            oid: Oid::parse("1.3.6.1.2.1.31.1.1.1.6.1").unwrap(),
            value: Value::Counter64(u64::MAX),
        },
        VarBind {
            oid: Oid::parse("1.3.6.1.2.1.4.20.1.1.10.0.0.1").unwrap(),
            value: Value::IpAddress([10, 0, 0, 1]),
        },
    ];
    let p = pdu::encode_response(TAG_RESPONSE, 7, 0, &vbs).unwrap();
    v2c::encode(b"ttcomm", &p)
}

#[test]
fn dsc_003_ber_hostile_valid_reply_decodes() {
    let msg = reply();
    let d = v2c::decode(&msg).unwrap();
    assert_eq!(d.response.varbinds.len(), 4);
    decode_all(&msg);
}

/// Every prefix of a valid reply is a truncation: refused, never a panic.
#[test]
fn dsc_003_ber_hostile_every_truncation_is_refused() {
    let msg = reply();
    for n in 0..msg.len() {
        let cut = msg.get(..n).unwrap();
        decode_all(cut);
        assert!(v2c::decode(cut).is_err(), "prefix {n} decoded");
    }
}

/// Trailing bytes after a complete message are refused.
#[test]
fn dsc_003_ber_hostile_trailing_bytes_refused() {
    let mut msg = reply();
    msg.push(0);
    assert_eq!(v2c::decode(&msg).err(), Some(DecodeError::Trailing));
}

/// Every single-byte substitution of a valid reply: no panic.
#[test]
fn dsc_003_ber_hostile_single_byte_mutations() {
    let msg = reply();
    for i in 0..msg.len() {
        for v in [
            0x00u8, 0x01, 0x7f, 0x80, 0x81, 0x84, 0xff, 0x30, 0x02, 0x04, 0x06,
        ] {
            let mut m = msg.clone();
            *m.get_mut(i).unwrap() = v;
            decode_all(&m);
        }
    }
}

/// A seeded xorshift mutation sweep: random byte flips, inserts and deletions.
#[test]
fn dsc_003_ber_hostile_random_mutations() {
    let base = reply();
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    for _ in 0..20_000 {
        let mut m = base.clone();
        for _ in 0..=(next() % 4) {
            let at = usize::try_from(next() % (m.len() as u64 + 1)).unwrap();
            match next() % 3 {
                0 => {
                    if let Some(b) = m.get_mut(at) {
                        *b = u8::try_from(next() & 0xff).unwrap();
                    }
                }
                1 => m.insert(at, u8::try_from(next() & 0xff).unwrap()),
                _ => {
                    if at < m.len() {
                        m.remove(at);
                    }
                }
            }
        }
        decode_all(&m);
    }
    // Pure noise of every small length.
    for len in 0..200usize {
        let noise: Vec<u8> = (0..len)
            .map(|_| u8::try_from(next() & 0xff).unwrap())
            .collect();
        decode_all(&noise);
    }
}

/// A length that claims more than the input holds, in every length form, is `Truncated` (or
/// `LengthTooLong`), and the decoder does not size anything from it.
#[test]
fn dsc_003_ber_hostile_oversized_lengths() {
    for input in [
        vec![0x30, 0x7f],
        vec![0x30, 0x81, 0xff],
        vec![0x30, 0x82, 0xff, 0xff],
        vec![0x30, 0x83, 0xff, 0xff, 0xff],
        vec![0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
        vec![0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x00],
        vec![0x04, 0x84, 0x80, 0x00, 0x00, 0x00],
    ] {
        assert_eq!(ber::read_tlv(&input).err(), Some(DecodeError::Truncated));
        decode_all(&input);
    }
    for input in [
        vec![0x30, 0x85, 1, 0, 0, 0, 0],
        vec![0x30, 0xff],
        vec![0x30, 0x88, 0, 0, 0, 0, 0, 0, 0, 1],
    ] {
        assert_eq!(
            ber::read_tlv(&input).err(),
            Some(DecodeError::LengthTooLong)
        );
    }
    assert_eq!(
        ber::read_tlv(&[0x30, 0x80]).err(),
        Some(DecodeError::IndefiniteLength)
    );
    // A message over the cap is refused before anything reads it.
    let big = vec![0x30u8; MAX_MESSAGE + 1];
    assert_eq!(
        ber::read_message(&big).err(),
        Some(DecodeError::MessageTooLarge)
    );
    assert!(v2c::decode(&big).is_err());
}

/// Nesting past the cap is refused; the decoder follows no recursion of its own, so a deep
/// input never reaches the stack either.
#[test]
fn dsc_003_ber_hostile_deep_nesting() {
    let mut v = vec![0x05u8, 0x00];
    for _ in 0..10_000 {
        if v.len() > MAX_MESSAGE / 2 {
            break;
        }
        v = ber::sequence(&v);
    }
    decode_all(&v);
    assert!(v2c::decode(&v).is_err());
    // A varbind whose value is a deep SEQUENCE is an Unknown value, not a recursion.
    let oid = ber::tlv(
        0x06,
        &Oid::parse("1.3.6.1.2.1.1.5.0")
            .unwrap()
            .to_content()
            .unwrap(),
    );
    let mut vb = oid;
    vb.extend(v);
    let list = ber::sequence(&vb);
    let _ = pdu::decode_varbinds(ber::read_tlv(&ber::sequence(&list)).unwrap().content);
    // Nine nested SEQUENCEs, parsed from depth 8, are over the cap.
    let mut inner = vec![0x05u8, 0x00];
    for _ in 0..9 {
        inner = ber::sequence(&inner);
    }
    let top = ber::read_tlv(&inner).unwrap();
    assert_eq!(
        ber::children(top.content, MAX_DEPTH, 4).err(),
        Some(DecodeError::TooDeep)
    );
}

/// Negative, huge, empty and over-long INTEGERs.
#[test]
fn dsc_003_ber_hostile_integers() {
    assert_eq!(ber::integer_value(&[]).err(), Some(DecodeError::BadInteger));
    assert_eq!(
        ber::integer_value(&[0; 9]).err(),
        Some(DecodeError::BadInteger)
    );
    assert_eq!(ber::integer_value(&[0xff; 8]), Ok(-1));
    assert_eq!(
        ber::integer_value(&[0x80, 0, 0, 0, 0, 0, 0, 0]),
        Ok(i64::MIN)
    );
    assert_eq!(
        ber::integer_value(&[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        Ok(i64::MAX)
    );
    assert_eq!(
        ber::unsigned_value(&[0xff; 9]).err(),
        Some(DecodeError::BadInteger)
    );
    assert_eq!(ber::unsigned_value(&[0xff; 8]), Ok(u64::MAX));
    assert_eq!(
        ber::unsigned_value(&[]).err(),
        Some(DecodeError::BadInteger)
    );
    // A request id or error status outside i32 or 0..=18 is refused in a PDU.
    for (rid, status, index) in [
        (i64::from(i32::MAX) + 1, 0i64, 0i64),
        (i64::MIN, 0, 0),
        (1, -1, 0),
        (1, 19, 0),
        (1, i64::MAX, 0),
        (1, 0, -1),
        (1, 0, i64::MAX),
    ] {
        let mut body = ber::integer(rid);
        body.extend(ber::integer(status));
        body.extend(ber::integer(index));
        body.extend(ber::sequence(&[]));
        let msg = v2c::encode(b"c", &ber::tlv(TAG_RESPONSE, &body));
        assert!(v2c::decode(&msg).is_err(), "{rid} {status} {index}");
    }
    // Counter32 / Gauge32 / TimeTicks above u32 are refused.
    for tag in [0x41u8, 0x42, 0x43] {
        let enc = ber::tlv(tag, &[0x01, 0, 0, 0, 0]);
        let t = ber::read_tlv(&enc).unwrap();
        assert_eq!(pdu::decode_value(t).err(), Some(DecodeError::BadInteger));
    }
}

/// OIDs: empty, too many arcs, an arc past 32 bits, an unterminated arc.
#[test]
fn dsc_003_ber_hostile_oids() {
    assert!(Oid::from_content(&[]).is_err());
    assert!(Oid::from_content(&[0x2b, 0x81]).is_err());
    assert!(Oid::from_content(&[0x2b, 0xff, 0xff, 0xff, 0xff, 0x7f]).is_err());
    let many = vec![0x01u8; 4096];
    assert!(Oid::from_content(&many).is_err());
    assert!(Oid::new(vec![1; 200]).is_none());
}

/// More varbinds than the cap are refused.
#[test]
fn dsc_003_ber_hostile_too_many_varbinds() {
    let one = ber::sequence(&[ber::tlv(0x06, &[0x2b, 0x06]), ber::tlv(0x05, &[])].concat());
    let mut content = Vec::new();
    for _ in 0..=MAX_VARBINDS {
        content.extend_from_slice(&one);
    }
    assert_eq!(
        pdu::decode_varbinds(&content).err(),
        Some(DecodeError::TooManyVarbinds)
    );
    let mut ok = Vec::new();
    for _ in 0..MAX_VARBINDS {
        ok.extend_from_slice(&one);
    }
    assert_eq!(pdu::decode_varbinds(&ok).map(|v| v.len()), Ok(MAX_VARBINDS));
}

/// A wrong tag where the position needs another: refused, no panic.
#[test]
fn dsc_003_ber_hostile_wrong_tags() {
    // Message that is not a SEQUENCE.
    let m = ber::tlv(0x31, &[]);
    assert!(matches!(
        v2c::decode(&m),
        Err(DecodeError::UnexpectedTag { .. })
    ));
    // Community as an INTEGER.
    let mut body = ber::integer(1);
    body.extend(ber::integer(5));
    body.extend(ber::tlv(TAG_RESPONSE, &[]));
    assert!(v2c::decode(&ber::sequence(&body)).is_err());
    // A request PDU where a response is required (a GET reply is not a GET).
    let get =
        pdu::encode_request(RequestKind::Get, 1, 0, 0, &[Oid::parse("1.3.6.1").unwrap()]).unwrap();
    assert!(v2c::decode(&v2c::encode(b"c", &get)).is_err());
    // Varbind that is not a SEQUENCE; OID slot that is not an OID; a null that carries bytes.
    assert!(pdu::decode_varbinds(&ber::integer(1)).is_err());
    let bad_oid = ber::sequence(&[ber::integer(1), ber::tlv(0x05, &[])].concat());
    assert!(pdu::decode_varbinds(&bad_oid).is_err());
    let bad_null = ber::sequence(&[ber::tlv(0x06, &[0x2b]), ber::tlv(0x05, &[0])].concat());
    assert!(pdu::decode_varbinds(&bad_null).is_err());
    // An IpAddress of the wrong length.
    let bad_ip = ber::sequence(&[ber::tlv(0x06, &[0x2b]), ber::tlv(0x40, &[1, 2, 3])].concat());
    assert!(pdu::decode_varbinds(&bad_ip).is_err());
    // High-tag-number form.
    assert_eq!(
        ber::read_tlv(&[0x5f, 0x81, 0x00, 0x00]).err(),
        Some(DecodeError::BadTag)
    );
    // Every first byte, with a short body.
    for tag in 0..=255u8 {
        decode_all(&[tag, 0x02, 0x05, 0x00]);
        decode_all(&[0x30, 0x04, tag, 0x02, 0x00, 0x00]);
    }
}

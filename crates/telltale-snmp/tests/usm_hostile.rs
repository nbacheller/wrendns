//! REQ: DSC-003 (ADR-908, ADR-911): the USM reply path against hostile input. The cases are the
//! ones the fuzz target `snmp_usm` finds by search, written down as a fixed set plus a seeded
//! mutation sweep, so a regression fails `cargo test` without a fuzzer. Nothing may panic, and
//! a message that differs from a valid authenticated one by any byte never verifies.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use telltale_snmp::pdu::{self, RequestKind};
use telltale_snmp::secret::SecretValue;
use telltale_snmp::usm::{self, AuthProto, Outgoing, PrivProto, UsmUser};

const ENGINE: [u8; 9] = [0x80, 0, 0, 9, 1, 2, 3, 4, 5];

fn user(auth: AuthProto, priv_on: bool) -> UsmUser {
    UsmUser {
        name: b"ttuser".to_vec(),
        auth: Some((auth, SecretValue::new(b"authpass-1234".to_vec()))),
        privacy: priv_on.then(|| {
            (
                PrivProto::Aes128,
                SecretValue::new(b"privpass-1234".to_vec()),
            )
        }),
    }
}

fn message(auth: AuthProto, priv_on: bool) -> (Vec<u8>, usm::RoundKeys) {
    let keys = user(auth, priv_on).derive().unwrap();
    let pdu = pdu::encode_request(RequestKind::Get, 1, 0, 0, &[]).unwrap();
    let scoped = usm::scoped_request(&ENGINE, &pdu);
    let out = Outgoing {
        msg_id: 9,
        engine_id: &ENGINE,
        boots: 2,
        time: 40,
        user: b"ttuser",
        reportable: false,
    };
    (usm::encode(&out, Some(&keys), &scoped).unwrap(), keys)
}

/// Everything the client runs on a received datagram. Returns whether the MAC verified.
fn run(data: &[u8], keys: &usm::RoundKeys) -> bool {
    let Ok(reply) = usm::parse(data) else {
        return false;
    };
    let ok = usm::verify(data, &reply, keys).is_ok();
    if let Ok(plain) = usm::decrypt(&reply, keys) {
        let _ = usm::scoped_response(&plain);
    }
    ok
}

#[test]
fn dsc_003_usm_hostile_every_truncation_is_refused() {
    for (auth, priv_on) in [
        (AuthProto::HmacSha96, false),
        (AuthProto::Sha256, true),
        (AuthProto::Sha512, true),
    ] {
        let (msg, keys) = message(auth, priv_on);
        assert!(run(&msg, &keys), "the unmodified message verifies");
        for n in 0..msg.len() {
            assert!(!run(msg.get(..n).unwrap(), &keys), "prefix {n} verified");
        }
        let mut longer = msg.clone();
        longer.push(0);
        assert!(!run(&longer, &keys), "trailing byte verified");
    }
}

#[test]
fn dsc_003_usm_hostile_single_byte_changes_never_verify() {
    for (auth, priv_on) in [(AuthProto::HmacSha96, false), (AuthProto::Sha256, true)] {
        let (msg, keys) = message(auth, priv_on);
        for i in 0..msg.len() {
            for v in [0x00u8, 0x01, 0x7f, 0x80, 0xff, 0x30, 0x04] {
                let mut m = msg.clone();
                let b = m.get_mut(i).unwrap();
                if *b == v {
                    continue;
                }
                *b = v;
                assert!(!run(&m, &keys), "byte {i} set to {v:#x} verified");
            }
        }
    }
}

#[test]
fn dsc_003_usm_hostile_random_mutations() {
    let (msg, keys) = message(AuthProto::Sha256, true);
    let mut s: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    for _ in 0..20_000 {
        let mut m = msg.clone();
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
        if m != msg {
            assert!(!run(&m, &keys), "a changed message verified");
        }
    }
    for len in 0..300usize {
        let noise: Vec<u8> = (0..len)
            .map(|_| u8::try_from(next() & 0xff).unwrap())
            .collect();
        assert!(!run(&noise, &keys));
    }
}

/// Deeply nested and over-long envelopes: refused, bounded.
#[test]
fn dsc_003_usm_hostile_nesting_and_lengths() {
    let (_, keys) = message(AuthProto::Sha256, true);
    let mut nest = Vec::new();
    for _ in 0..500 {
        nest.splice(0..0, [0x30u8, 0x80]);
    }
    assert!(!run(&nest, &keys));
    for lens in [
        [0x84u8, 0xff, 0xff, 0xff, 0xff],
        [0x83, 0xff, 0xff, 0xff, 0],
    ] {
        let mut m = vec![0x30u8];
        m.extend_from_slice(&lens);
        m.extend_from_slice(&[0x02, 0x01, 0x03]);
        assert!(!run(&m, &keys));
    }
}

/// No secret appears in Debug output: not the passwords, and not the derived keys.
#[test]
fn dsc_003_usm_debug_output_holds_no_secret() {
    let u = user(AuthProto::Sha256, true);
    let keys = u.derive().unwrap();
    let text = format!("{u:?} {keys:?}");
    assert!(!text.contains("authpass-1234"));
    assert!(!text.contains("privpass-1234"));
    // The derived Ku, as hex, is not printed either.
    let ku = usm::password_to_key(AuthProto::Sha256, b"authpass-1234").unwrap();
    let hex = ku.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    assert!(!text.to_lowercase().contains(&hex));
    assert!(!text.contains(&format!("{:?}", ku.to_vec())));
}

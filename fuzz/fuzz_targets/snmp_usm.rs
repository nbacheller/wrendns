//! REQ: DSC-003 — the SNMPv3 USM reply path (ADR-908, ADR-911): the envelope parser, the MAC
//! check and the privacy decryption, on arbitrary bytes under fixed keys. None may panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use wrendns_snmp::pdu::Value;
use wrendns_snmp::secret::SecretValue;
use wrendns_snmp::usm::{self, AuthProto, PrivProto, RoundKeys, UsmUser};

// Ku is two 1 MiB password expansions: derive once, not per input.
static KEYS: OnceLock<Option<RoundKeys>> = OnceLock::new();

fn keys() -> Option<&'static RoundKeys> {
    KEYS.get_or_init(|| {
        let user = UsmUser {
            name: b"ttuser".to_vec(),
            auth: Some((
                AuthProto::Sha256,
                SecretValue::new(b"authpass-1234".to_vec()),
            )),
            privacy: Some((
                PrivProto::Aes128,
                SecretValue::new(b"privpass-1234".to_vec()),
            )),
        };
        user.derive().ok()
    })
    .as_ref()
}

fuzz_target!(|data: &[u8]| {
    let Some(keys) = keys() else { return };
    let Ok(reply) = usm::parse(data) else { return };
    let _ = usm::verify(data, &reply, keys);
    if let Ok(plain) = usm::decrypt(&reply, keys) {
        if let Ok(resp) = usm::scoped_response(&plain) {
            for vb in &resp.varbinds {
                if let Value::OctetString(s) = &vb.value {
                    let _ = s.len();
                }
            }
        }
    }
});

//! REQ: DSC-003 — the SNMPv3 USM reply path (ADR-908, ADR-911): the envelope parser, the MAC
//! check and the privacy decryption, on arbitrary bytes under fixed keys. None may panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use telltale_snmp::pdu::Value;
use telltale_snmp::secret::SecretValue;
use telltale_snmp::usm::{self, AuthProto, PrivProto, UsmUser};

fuzz_target!(|data: &[u8]| {
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
    let Ok(keys) = user.derive() else { return };
    let Ok(reply) = usm::parse(data) else { return };
    let _ = usm::verify(data, &reply, &keys);
    if let Ok(plain) = usm::decrypt(&reply, &keys) {
        if let Ok(resp) = usm::scoped_response(&plain) {
            for vb in &resp.varbinds {
                if let Value::OctetString(s) = &vb.value {
                    let _ = s.len();
                }
            }
        }
    }
});

//! REQ: DSC-003 — the SNMP BER codec and the v2c reply path (ADR-908). Arbitrary bytes go
//! through the message reader, the v2c decoder, the PDU and varbind decoders, and the OID
//! decoder. None may panic, and every length is bounded before it allocates.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wrendns_snmp::ber;
use wrendns_snmp::oid::Oid;
use wrendns_snmp::pdu;
use wrendns_snmp::v2c;

fuzz_target!(|data: &[u8]| {
    let _ = ber::read_tlv(data);
    if let Ok(tlv) = ber::read_message(data) {
        let _ = ber::children(tlv.content, 0, ber::MAX_VARBINDS);
        let _ = pdu::decode_varbinds(tlv.content);
    }
    if let Ok(decoded) = v2c::decode(data) {
        for vb in &decoded.response.varbinds {
            let _ = vb.oid.to_string();
        }
    }
    let _ = Oid::from_content(data);
});

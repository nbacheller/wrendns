//! REQ: DSC-003 — the `SNMPv2c` message: `SEQUENCE { version, community, `PDU` }` (RFC 3416).

use crate::ber::{self, DecodeError};
use crate::pdu::{self, Response};

/// The `msgVersion` of `SNMPv2c`.
pub const VERSION_V2C: i64 = 1;

/// Encodes a v2c message around an encoded request `PDU`.
pub fn encode(community: &[u8], pdu: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(ber::integer(VERSION_V2C));
    body.extend(ber::octets(community));
    body.extend_from_slice(pdu);
    ber::sequence(&body)
}

/// A decoded v2c reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub community: Vec<u8>,
    pub response: Response,
}

/// Decodes a v2c reply. The community is returned so the caller can compare it with its own.
pub fn decode(input: &[u8]) -> Result<Decoded, DecodeError> {
    let msg = ber::read_message(input)?;
    if msg.tag != 0x30 {
        return Err(DecodeError::UnexpectedTag {
            expected: 0x30,
            found: msg.tag,
        });
    }
    let kids = ber::children(msg.content, 0, 3)?;
    let (version, community, pdu_tlv) = match kids.as_slice() {
        [v, c, p] => (*v, *c, *p),
        _ => return Err(DecodeError::BadField),
    };
    if ber::integer_value(version.content)? != VERSION_V2C {
        return Err(DecodeError::BadField);
    }
    if community.tag != 0x04 {
        return Err(DecodeError::UnexpectedTag {
            expected: 0x04,
            found: community.tag,
        });
    }
    let response = pdu::decode_response(pdu_tlv)?;
    Ok(Decoded {
        community: community.content.to_vec(),
        response,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid::Oid;
    use crate::pdu::{RequestKind, encode_request};

    #[test]
    fn dsc_003_v2c_message_roundtrip_shape() {
        let oid = Oid::parse("1.3.6.1.2.1.1.5.0").unwrap_or_else(|| panic!("oid"));
        let pdu = encode_request(RequestKind::Get, 9, 0, 0, std::slice::from_ref(&oid))
            .unwrap_or_default();
        let msg = encode(b"ttcomm", &pdu);
        let tlv = ber::read_message(&msg).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(tlv.tag, 0x30);
        // A reply with the same shape, built by hand, decodes.
        let reply_pdu = crate::pdu::tests_support::response(9, 0, &oid, &ber::octets(b"x"));
        let reply = encode(b"ttcomm", &reply_pdu);
        let d = decode(&reply).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(d.community, b"ttcomm");
        assert_eq!(d.response.request_id, 9);
    }

    #[test]
    fn dsc_003_v2c_rejects_wrong_version() {
        let pdu = crate::pdu::tests_support::response(
            1,
            0,
            &Oid::parse("1.3").unwrap_or_else(|| panic!("oid")),
            &ber::tlv(0x05, &[]),
        );
        let mut body = Vec::new();
        body.extend(ber::integer(0));
        body.extend(ber::octets(b"c"));
        body.extend(pdu);
        let msg = ber::sequence(&body);
        assert_eq!(decode(&msg).err(), Some(DecodeError::BadField));
    }
}

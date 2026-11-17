//! REQ: DSC-003 — the `PDUs` the client sends (GET, GETNEXT, GETBULK) and the ones it reads
//! (`Response`, `Report`). There is no write `PDU` in this module, and none is in the crate (ADR-908).

use crate::ber::{self, DecodeError, MAX_VARBINDS};
use crate::oid::Oid;

/// A request `PDU` the client may send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Get,
    GetNext,
    GetBulk,
}

impl RequestKind {
    fn tag(self) -> u8 {
        match self {
            Self::Get => 0xa0,
            Self::GetNext => 0xa1,
            Self::GetBulk => 0xa5,
        }
    }
}

/// The `PDU` tag of a `Response`.
pub const TAG_RESPONSE: u8 = 0xa2;
/// The `PDU` tag of a `Report` (`SNMPv3` engine discovery and time windows).
pub const TAG_REPORT: u8 = 0xa8;

/// An SNMP value as it arrived. Unknown application types keep only their tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Integer(i64),
    OctetString(Vec<u8>),
    Oid(Oid),
    Null,
    IpAddress([u8; 4]),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
    Unknown(u8),
}

/// One variable binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarBind {
    pub oid: Oid,
    pub value: Value,
}

/// A decoded `Response` or `Report` `PDU`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub tag: u8,
    pub request_id: i32,
    pub error_status: i32,
    pub error_index: i32,
    pub varbinds: Vec<VarBind>,
}

/// Encodes a request `PDU`. For GETBULK, `non_repeaters` and `max_repetitions` take the two
/// fields that GET and GETNEXT fill with zeros.
pub fn encode_request(kind: RequestKind, request_id: i32, non_repeaters: u32, max_repetitions: u32, oids: &[Oid]) -> Result<Vec<u8>, DecodeError> {
    let (f1, f2) = match kind {
        RequestKind::GetBulk => (non_repeaters, max_repetitions),
        _ => (0, 0),
    };
    let mut body = Vec::new();
    body.extend(ber::integer(i64::from(request_id)));
    body.extend(ber::integer(i64::from(f1)));
    body.extend(ber::integer(i64::from(f2)));
    let mut list = Vec::new();
    for oid in oids {
        let mut vb = Vec::new();
        vb.extend(ber::tlv(0x06, &oid.to_content()?));
        vb.extend(ber::tlv(0x05, &[]));
        list.extend(ber::sequence(&vb));
    }
    body.extend(ber::sequence(&list));
    Ok(ber::tlv(kind.tag(), &body))
}

/// Decodes a `Response` or `Report` `PDU`, given its whole TLV.
pub fn decode_response(tlv: ber::Tlv<'_>) -> Result<Response, DecodeError> {
    if tlv.tag != TAG_RESPONSE && tlv.tag != TAG_REPORT {
        return Err(DecodeError::UnexpectedTag {
            expected: TAG_RESPONSE,
            found: tlv.tag,
        });
    }
    let kids = ber::children(tlv.content, 2, 4)?;
    if kids.len() != 4 {
        return Err(DecodeError::BadField);
    }
    let request_id = i32::try_from(ber::integer_value(kid(&kids, 0)?.content)?).map_err(|_| DecodeError::BadInteger)?;
    let error_status = i32::try_from(ber::integer_value(kid(&kids, 1)?.content)?).map_err(|_| DecodeError::BadField)?;
    let error_index = i32::try_from(ber::integer_value(kid(&kids, 2)?.content)?).map_err(|_| DecodeError::BadField)?;
    if !(0..=18).contains(&error_status) || error_index < 0 {
        return Err(DecodeError::BadField);
    }
    let list = kid(&kids, 3)?;
    if list.tag != 0x30 {
        return Err(DecodeError::UnexpectedTag {
            expected: 0x30,
            found: list.tag,
        });
    }
    let varbinds = decode_varbinds(list.content)?;
    Ok(Response {
        tag: tlv.tag,
        request_id,
        error_status,
        error_index,
        varbinds,
    })
}

fn kid<'a>(kids: &[ber::Tlv<'a>], i: usize) -> Result<ber::Tlv<'a>, DecodeError> {
    kids.get(i).copied().ok_or(DecodeError::BadField)
}

/// Decodes the content of a varbind list: at most `MAX_VARBINDS` SEQUENCEs of OID and value.
pub fn decode_varbinds(content: &[u8]) -> Result<Vec<VarBind>, DecodeError> {
    let items = ber::children(content, 3, MAX_VARBINDS)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if item.tag != 0x30 {
            return Err(DecodeError::UnexpectedTag {
                expected: 0x30,
                found: item.tag,
            });
        }
        let parts = ber::children(item.content, 4, 2)?;
        if parts.len() != 2 {
            return Err(DecodeError::BadField);
        }
        let oid_tlv = kid(&parts, 0)?;
        if oid_tlv.tag != 0x06 {
            return Err(DecodeError::UnexpectedTag {
                expected: 0x06,
                found: oid_tlv.tag,
            });
        }
        let oid = Oid::from_content(oid_tlv.content)?;
        let value = decode_value(kid(&parts, 1)?)?;
        out.push(VarBind { oid, value });
    }
    Ok(out)
}

/// Decodes one value TLV.
pub fn decode_value(tlv: ber::Tlv<'_>) -> Result<Value, DecodeError> {
    let c = tlv.content;
    Ok(match tlv.tag {
        0x02 => Value::Integer(ber::integer_value(c)?),
        0x04 => Value::OctetString(c.to_vec()),
        0x05 => {
            if !c.is_empty() {
                return Err(DecodeError::BadField);
            }
            Value::Null
        }
        0x06 => Value::Oid(Oid::from_content(c)?),
        0x40 => {
            let four: [u8; 4] = c.try_into().map_err(|_| DecodeError::BadField)?;
            Value::IpAddress(four)
        }
        0x41 => Value::Counter32(u32::try_from(ber::unsigned_value(c)?).map_err(|_| DecodeError::BadInteger)?),
        0x42 => Value::Gauge32(u32::try_from(ber::unsigned_value(c)?).map_err(|_| DecodeError::BadInteger)?),
        0x43 => Value::TimeTicks(u32::try_from(ber::unsigned_value(c)?).map_err(|_| DecodeError::BadInteger)?),
        0x46 => Value::Counter64(ber::unsigned_value(c)?),
        0x80 => Value::NoSuchObject,
        0x81 => Value::NoSuchInstance,
        0x82 => Value::EndOfMibView,
        other => Value::Unknown(other),
    })
}

/// Encodes a `Response` or a `Report` `PDU`. The client never sends these; the fake agents of the
/// tests and the fuzz targets build replies with them.
pub fn encode_response(tag: u8, request_id: i32, error_status: i32, varbinds: &[VarBind]) -> Result<Vec<u8>, DecodeError> {
    if tag != TAG_RESPONSE && tag != TAG_REPORT {
        return Err(DecodeError::BadField);
    }
    let mut list = Vec::new();
    for vb in varbinds {
        let mut item = Vec::new();
        item.extend(ber::tlv(0x06, &vb.oid.to_content()?));
        item.extend(encode_value(&vb.value)?);
        list.extend(ber::sequence(&item));
    }
    let mut body = Vec::new();
    body.extend(ber::integer(i64::from(request_id)));
    body.extend(ber::integer(i64::from(error_status)));
    body.extend(ber::integer(0));
    body.extend(ber::sequence(&list));
    Ok(ber::tlv(tag, &body))
}

/// Encodes one value TLV, the inverse of `decode_value`.
pub fn encode_value(v: &Value) -> Result<Vec<u8>, DecodeError> {
    Ok(match v {
        Value::Integer(i) => ber::integer(*i),
        Value::OctetString(b) => ber::octets(b),
        Value::Oid(o) => ber::tlv(0x06, &o.to_content()?),
        Value::Null => ber::tlv(0x05, &[]),
        Value::IpAddress(a) => ber::tlv(0x40, a),
        Value::Counter32(x) => ber::tlv(0x41, &unsigned_content(u64::from(*x))),
        Value::Gauge32(x) => ber::tlv(0x42, &unsigned_content(u64::from(*x))),
        Value::TimeTicks(x) => ber::tlv(0x43, &unsigned_content(u64::from(*x))),
        Value::Counter64(x) => ber::tlv(0x46, &unsigned_content(*x)),
        Value::NoSuchObject => ber::tlv(0x80, &[]),
        Value::NoSuchInstance => ber::tlv(0x81, &[]),
        Value::EndOfMibView => ber::tlv(0x82, &[]),
        Value::Unknown(_) => return Err(DecodeError::BadField),
    })
}

/// The minimal content octets of an unsigned value (a leading zero when the top bit is set).
fn unsigned_content(v: u64) -> Vec<u8> {
    let mut out: Vec<u8> = v.to_be_bytes().iter().copied().skip_while(|&b| b == 0).collect();
    if out.is_empty() {
        out.push(0);
    }
    if out.first().is_some_and(|&b| b & 0x80 != 0) {
        out.insert(0, 0);
    }
    out
}

/// Test-only builders shared by the codec and client tests.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// A `Response` `PDU` with one varbind (`value` is its encoded TLV).
    pub(crate) fn response(request_id: i64, status: i64, oid: &Oid, value: &[u8]) -> Vec<u8> {
        response_pdu(request_id, status, &[(oid.clone(), value.to_vec())])
    }

    /// Builds a `Response` `PDU` around the given varbinds.
    pub(crate) fn response_pdu(request_id: i64, status: i64, varbinds: &[(Oid, Vec<u8>)]) -> Vec<u8> {
        let mut list = Vec::new();
        for (oid, value) in varbinds {
            let mut vb = Vec::new();
            vb.extend(ber::tlv(0x06, &oid.to_content().unwrap_or_default()));
            vb.extend_from_slice(value);
            list.extend(ber::sequence(&vb));
        }
        let mut body = Vec::new();
        body.extend(ber::integer(request_id));
        body.extend(ber::integer(status));
        body.extend(ber::integer(0));
        body.extend(ber::sequence(&list));
        ber::tlv(TAG_RESPONSE, &body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::tests_support::response_pdu;

    #[test]
    fn dsc_003_ber_roundtrip() {
        let oid = Oid::parse("1.3.6.1.2.1.1.5.0").unwrap_or_else(|| panic!("oid"));
        let values: Vec<(Vec<u8>, Value)> = vec![
            (ber::integer(-42), Value::Integer(-42)),
            (ber::octets(b"tt-snmpd-test"), Value::OctetString(b"tt-snmpd-test".to_vec())),
            (ber::tlv(0x05, &[]), Value::Null),
            (ber::tlv(0x40, &[172, 30, 250, 10]), Value::IpAddress([172, 30, 250, 10])),
            (ber::tlv(0x41, &[0x01, 0x00]), Value::Counter32(256)),
            (ber::tlv(0x42, &[0x7f]), Value::Gauge32(127)),
            (ber::tlv(0x43, &[0x00, 0xff, 0xff, 0xff, 0xff]), Value::TimeTicks(u32::MAX)),
            (ber::tlv(0x46, &[0x00, 0x80, 0, 0, 0, 0, 0, 0, 0]), Value::Counter64(1u64 << 63)),
            (ber::tlv(0x80, &[]), Value::NoSuchObject),
            (ber::tlv(0x81, &[]), Value::NoSuchInstance),
            (ber::tlv(0x82, &[]), Value::EndOfMibView),
        ];
        for (enc, want) in values {
            let pdu = response_pdu(7, 0, &[(oid.clone(), enc)]);
            let tlv = ber::read_message(&pdu).unwrap_or_else(|e| panic!("{e:?}"));
            let resp = decode_response(tlv).unwrap_or_else(|e| panic!("{e:?}"));
            assert_eq!(resp.request_id, 7);
            assert_eq!(resp.varbinds.first().map(|v| &v.value), Some(&want));
        }
    }

    #[test]
    fn dsc_003_request_encodings_are_read_pdus() {
        let oid = Oid::parse("1.3.6.1.2.1.1").unwrap_or_else(|| panic!("oid"));
        let get = encode_request(RequestKind::Get, 1, 0, 0, std::slice::from_ref(&oid)).unwrap_or_default();
        let next = encode_request(RequestKind::GetNext, 1, 0, 0, std::slice::from_ref(&oid)).unwrap_or_default();
        let bulk = encode_request(RequestKind::GetBulk, 1, 0, 10, std::slice::from_ref(&oid)).unwrap_or_default();
        assert_eq!(get.first(), Some(&0xa0));
        assert_eq!(next.first(), Some(&0xa1));
        assert_eq!(bulk.first(), Some(&0xa5));
    }

    #[test]
    fn dsc_003_response_field_limits() {
        // error-status 19 is outside the SNMP range.
        let pdu = response_pdu(1, 19, &[]);
        let tlv = ber::read_message(&pdu).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(decode_response(tlv).err(), Some(DecodeError::BadField));
    }

    #[test]
    fn dsc_003_varbind_cap_is_enforced() {
        let oid = Oid::parse("1.3.6.1.2.1.1.5.0").unwrap_or_else(|| panic!("oid"));
        let one = (oid, ber::tlv(0x05, &[]));
        let many: Vec<(Oid, Vec<u8>)> = std::iter::repeat_n(one, MAX_VARBINDS.saturating_add(1)).collect();
        let pdu = response_pdu(1, 0, &many);
        assert!(pdu.len() < ber::MAX_MESSAGE);
        let tlv = ber::read_message(&pdu).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(decode_response(tlv).err(), Some(DecodeError::TooManyVarbinds));
    }
}

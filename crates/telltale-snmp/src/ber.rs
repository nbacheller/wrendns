//! REQ: DSC-003 — the BER codec (ADR-908). Definite lengths only, a depth cap of 8, a message
//! cap of 64 KiB and at most 256 varbinds per `PDU`. Input is untrusted: every read is bounds
//! checked, every length is checked against what is left, and nothing is allocated before its
//! length has been checked against the input.

/// The largest message the codec accepts, in bytes (ADR-908).
pub const MAX_MESSAGE: usize = 64 * 1024;
/// The deepest constructed nesting the decoder follows (ADR-908).
pub const MAX_DEPTH: u8 = 8;
/// The most varbinds one `PDU` may carry (ADR-908).
pub const MAX_VARBINDS: usize = 256;

/// A decoding failure. Carries no input bytes, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ends before a length says it should.
    Truncated,
    /// The whole message is larger than `MAX_MESSAGE`.
    MessageTooLarge,
    /// Constructed nesting is deeper than `MAX_DEPTH`.
    TooDeep,
    /// The indefinite length form (0x80) is not used by SNMP and is refused.
    IndefiniteLength,
    /// A length takes more than four octets, so it cannot fit a message this size.
    LengthTooLong,
    /// A high-tag-number form (tag bits 0x1f) is not used by SNMP and is refused.
    BadTag,
    /// A tag other than the one the position requires.
    UnexpectedTag { expected: u8, found: u8 },
    /// An INTEGER or an unsigned application type has a bad length or does not fit.
    BadInteger,
    /// An OBJECT IDENTIFIER is empty, has too many arcs, or an arc does not fit 32 bits.
    BadOid,
    /// A `PDU` carries more than `MAX_VARBINDS` varbinds.
    TooManyVarbinds,
    /// Bytes are left over after the value that should end the input.
    Trailing,
    /// An error-status or a `PDU` field is outside the range SNMP allows.
    BadField,
}

/// One tag-length-value at the front of an input.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    /// The whole value: tag, length and content.
    pub raw: &'a [u8],
    /// The bytes after this value.
    pub rest: &'a [u8],
}

/// Reads one TLV from the front of `input`.
pub fn read_tlv(input: &[u8]) -> Result<Tlv<'_>, DecodeError> {
    let tag = *input.first().ok_or(DecodeError::Truncated)?;
    if tag & 0x1f == 0x1f {
        return Err(DecodeError::BadTag);
    }
    let len_byte = *input.get(1).ok_or(DecodeError::Truncated)?;
    let (len, header) = match len_byte {
        0..=0x7f => (usize::from(len_byte), 2usize),
        0x80 => return Err(DecodeError::IndefiniteLength),
        _ => {
            let n = usize::from(len_byte & 0x7f);
            if n > 4 {
                return Err(DecodeError::LengthTooLong);
            }
            let header_end = 2usize.checked_add(n).ok_or(DecodeError::Truncated)?;
            let bytes = input.get(2..header_end).ok_or(DecodeError::Truncated)?;
            let mut len = 0usize;
            for &b in bytes {
                len = len
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(usize::from(b)))
                    .ok_or(DecodeError::LengthTooLong)?;
            }
            (len, header_end)
        }
    };
    let end = header.checked_add(len).ok_or(DecodeError::Truncated)?;
    let content = input.get(header..end).ok_or(DecodeError::Truncated)?;
    let raw = input.get(..end).ok_or(DecodeError::Truncated)?;
    let rest = input.get(end..).ok_or(DecodeError::Truncated)?;
    Ok(Tlv {
        tag,
        content,
        raw,
        rest,
    })
}

/// Reads one TLV that must be the whole of `input`, and must be at most `MAX_MESSAGE` long.
pub fn read_message(input: &[u8]) -> Result<Tlv<'_>, DecodeError> {
    if input.len() > MAX_MESSAGE {
        return Err(DecodeError::MessageTooLarge);
    }
    let tlv = read_tlv(input)?;
    if !tlv.rest.is_empty() {
        return Err(DecodeError::Trailing);
    }
    Ok(tlv)
}

/// Reads one TLV that must carry `expected` as its tag.
pub fn expect_tag(input: &[u8], expected: u8) -> Result<Tlv<'_>, DecodeError> {
    let tlv = read_tlv(input)?;
    if tlv.tag != expected {
        return Err(DecodeError::UnexpectedTag {
            expected,
            found: tlv.tag,
        });
    }
    Ok(tlv)
}

/// Splits the content of a constructed value into its children, at most `max_items` of them.
/// `depth` is the nesting depth of the parent value; the children are one level deeper and
/// may not exceed `MAX_DEPTH`.
pub fn children(content: &[u8], depth: u8, max_items: usize) -> Result<Vec<Tlv<'_>>, DecodeError> {
    if depth >= MAX_DEPTH {
        return Err(DecodeError::TooDeep);
    }
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        if out.len() >= max_items {
            return Err(DecodeError::TooManyVarbinds);
        }
        let tlv = read_tlv(rest)?;
        out.push(tlv);
        rest = tlv.rest;
    }
    Ok(out)
}

/// Reads the next child of a sequence, failing if it does not carry `tag`.
pub fn take_tagged(input: &[u8], tag: u8) -> Result<(&[u8], &[u8]), DecodeError> {
    let tlv = expect_tag(input, tag)?;
    Ok((tlv.content, tlv.rest))
}

/// Decodes a signed INTEGER's content: one to eight octets, two's complement.
pub fn integer_value(content: &[u8]) -> Result<i64, DecodeError> {
    if content.is_empty() || content.len() > 8 {
        return Err(DecodeError::BadInteger);
    }
    let negative = content.first().is_some_and(|&b| b & 0x80 != 0);
    let mut v: i128 = if negative { -1 } else { 0 };
    for &b in content {
        v = v
            .checked_mul(256)
            .and_then(|x| x.checked_add(i128::from(b)))
            .ok_or(DecodeError::BadInteger)?;
    }
    i64::try_from(v).map_err(|_| DecodeError::BadInteger)
}

/// Decodes an unsigned application value's content (`Counter32`, `Gauge32`, `TimeTicks`,
/// `Counter64`). A leading zero octet is allowed, so up to nine octets are read.
pub fn unsigned_value(content: &[u8]) -> Result<u64, DecodeError> {
    if content.is_empty() || content.len() > 9 {
        return Err(DecodeError::BadInteger);
    }
    let mut v: u64 = 0;
    for &b in content {
        v = v
            .checked_mul(256)
            .and_then(|x| x.checked_add(u64::from(b)))
            .ok_or(DecodeError::BadInteger)?;
    }
    Ok(v)
}

/// Writes a TLV with a definite, minimal length.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len().saturating_add(6));
    out.push(tag);
    push_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// The number of octets a TLV's header takes for a content of `len` octets.
pub fn header_len(len: usize) -> usize {
    if len < 0x80 {
        2
    } else {
        let mut n = 0usize;
        let mut v = len;
        while v > 0 {
            n = n.saturating_add(1);
            v /= 256;
        }
        n.saturating_add(2)
    }
}

fn push_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0x7f));
        return;
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    let significant = bytes.get(skip..).unwrap_or(&[]);
    out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0));
    out.extend_from_slice(significant);
}

/// The content of a minimal two's-complement INTEGER.
pub fn integer_content(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0usize;
    while start < 7 {
        let cur = bytes.get(start).copied().unwrap_or(0);
        let next = bytes.get(start.saturating_add(1)).copied().unwrap_or(0);
        let redundant = (cur == 0x00 && next & 0x80 == 0) || (cur == 0xff && next & 0x80 != 0);
        if !redundant {
            break;
        }
        start = start.saturating_add(1);
    }
    bytes.get(start..).unwrap_or(&[]).to_vec()
}

/// A complete INTEGER TLV.
pub fn integer(v: i64) -> Vec<u8> {
    tlv(0x02, &integer_content(v))
}

/// A complete `OCTET STRING` TLV.
pub fn octets(content: &[u8]) -> Vec<u8> {
    tlv(0x04, content)
}

/// A complete `SEQUENCE` TLV around the given content.
pub fn sequence(content: &[u8]) -> Vec<u8> {
    tlv(0x30, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsc_003_ber_length_forms_roundtrip() {
        for len in [0usize, 1, 127, 128, 255, 256, 65_535] {
            let content = vec![0xabu8; len];
            let enc = tlv(0x04, &content);
            assert_eq!(enc.len(), len + header_len(len), "header size for {len}");
            let back = read_tlv(&enc).unwrap_or_else(|e| panic!("{len}: {e:?}"));
            assert_eq!(back.tag, 0x04);
            assert_eq!(back.content.len(), len);
            assert_eq!(back.rest.len(), 0);
        }
    }

    #[test]
    fn dsc_003_ber_integers_are_minimal_and_roundtrip() {
        for v in [
            0i64,
            1,
            -1,
            127,
            128,
            -128,
            -129,
            255,
            256,
            65_535,
            i64::MAX,
            i64::MIN,
            2_147_483_647,
            -2_147_483_648,
        ] {
            let content = integer_content(v);
            assert!(content.len() <= 8);
            assert_eq!(integer_value(&content), Ok(v), "value {v}");
        }
        assert_eq!(integer_content(0), vec![0x00]);
        assert_eq!(integer_content(128), vec![0x00, 0x80]);
        assert_eq!(integer_content(-1), vec![0xff]);
        assert_eq!(integer_content(-129), vec![0xff, 0x7f]);
    }

    #[test]
    fn dsc_003_ber_rejects_indefinite_and_long_lengths() {
        assert_eq!(
            read_tlv(&[0x30, 0x80]).err(),
            Some(DecodeError::IndefiniteLength)
        );
        assert_eq!(
            read_tlv(&[0x30, 0x85, 0, 0, 0, 0, 1]).err(),
            Some(DecodeError::LengthTooLong)
        );
        assert_eq!(
            read_tlv(&[0x30, 0x82, 0x01]).err(),
            Some(DecodeError::Truncated)
        );
        assert_eq!(
            read_tlv(&[0x1f, 0x01, 0x00]).err(),
            Some(DecodeError::BadTag)
        );
    }

    fn descend(content: &[u8], depth: u8) -> Result<(), DecodeError> {
        for kid in children(content, depth, 4)? {
            if kid.tag == 0x30 {
                descend(kid.content, depth.saturating_add(1))?;
            }
        }
        Ok(())
    }

    #[test]
    fn dsc_003_ber_depth_cap() {
        // Eight nested SEQUENCEs fit under the cap of 8; a ninth is refused.
        let wrap = |levels: usize| {
            let mut v = vec![0x05u8, 0x00];
            for _ in 0..levels {
                v = sequence(&v);
            }
            v
        };
        let eight = wrap(8);
        let top = read_tlv(&eight);
        assert!(top.is_ok());
        assert_eq!(top.map(|t| descend(t.content, 0)), Ok(Ok(())));
        let nine = wrap(9);
        let top = read_tlv(&nine);
        assert!(top.is_ok());
        assert_eq!(
            top.map(|t| descend(t.content, 0)),
            Ok(Err(DecodeError::TooDeep))
        );
    }
}

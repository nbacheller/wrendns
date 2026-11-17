//! REQ: DSC-003 — OBJECT IDENTIFIER values: parsing, text form, and BER content encoding.
//! An OID decoded from a device is capped at 128 arcs (ADR-908 codec rules).

use std::fmt;

use crate::ber::DecodeError;

/// The most arcs one OID may have when it is decoded from a message.
pub const MAX_ARCS: usize = 128;

/// An OBJECT IDENTIFIER: at least two arcs, the first two in the BER packing rules.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid(Vec<u32>);

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({self})")
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, arc) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

impl Oid {
    /// Builds an OID from arcs. Returns `None` for fewer than two arcs, or more than `MAX_ARCS`,
    /// or a first arc above 2, or a second arc above 39 when the first is below 2.
    pub fn new(arcs: Vec<u32>) -> Option<Self> {
        if arcs.len() < 2 || arcs.len() > MAX_ARCS {
            return None;
        }
        let first = *arcs.first()?;
        let second = *arcs.get(1)?;
        if first > 2 || (first < 2 && second > 39) {
            return None;
        }
        Some(Self(arcs))
    }

    /// Parses dotted decimal such as `1.3.6.1.2.1.1.5.0`.
    pub fn parse(text: &str) -> Option<Self> {
        let arcs: Option<Vec<u32>> = text.split('.').map(|p| p.parse::<u32>().ok()).collect();
        Self::new(arcs?)
    }

    pub fn arcs(&self) -> &[u32] {
        &self.0
    }

    /// Whether `prefix` is this OID or one of its ancestors.
    pub fn starts_with(&self, prefix: &Oid) -> bool {
        self.0.starts_with(&prefix.0)
    }

    /// A copy with one more arc appended (used for the index of a table column).
    pub fn child(&self, arc: u32) -> Option<Self> {
        if self.0.len() >= MAX_ARCS {
            return None;
        }
        let mut v = self.0.clone();
        v.push(arc);
        Some(Self(v))
    }

    /// The BER content octets of this OID (X.690 §8.19).
    pub fn to_content(&self) -> Result<Vec<u8>, DecodeError> {
        let first = *self.0.first().ok_or(DecodeError::BadOid)?;
        let second = *self.0.get(1).ok_or(DecodeError::BadOid)?;
        let packed = first
            .checked_mul(40)
            .and_then(|v| v.checked_add(second))
            .ok_or(DecodeError::BadOid)?;
        let mut out = Vec::new();
        push_base128(&mut out, packed);
        for &arc in self.0.get(2..).unwrap_or(&[]) {
            push_base128(&mut out, arc);
        }
        Ok(out)
    }

    /// Decodes OID content octets. Refuses an empty value, a value with an unterminated arc,
    /// a non-minimal arc (a leading 0x80 octet), an arc above 32 bits, and more than `MAX_ARCS`
    /// arcs. The first subidentifier packs the first two arcs (X.690 §8.19.4); it must fit
    /// 2 * 40 + 2^32 - 1, and an arc after it must fit 32 bits.
    pub fn from_content(content: &[u8]) -> Result<Self, DecodeError> {
        if content.is_empty() {
            return Err(DecodeError::BadOid);
        }
        let mut arcs: Vec<u32> = Vec::new();
        let mut value: u64 = 0;
        let mut in_arc = false;
        for &b in content {
            if !in_arc && b == 0x80 {
                // A subidentifier that starts with a zero continuation octet is not minimal.
                return Err(DecodeError::BadOid);
            }
            value = value
                .checked_mul(128)
                .and_then(|v| v.checked_add(u64::from(b & 0x7f)))
                .ok_or(DecodeError::BadOid)?;
            in_arc = true;
            if b & 0x80 != 0 {
                continue;
            }
            if arcs.is_empty() {
                let (first, second) = split_first(value).ok_or(DecodeError::BadOid)?;
                arcs.push(first);
                arcs.push(second);
            } else {
                arcs.push(u32::try_from(value).map_err(|_| DecodeError::BadOid)?);
            }
            if arcs.len() > MAX_ARCS {
                return Err(DecodeError::BadOid);
            }
            value = 0;
            in_arc = false;
        }
        if in_arc {
            return Err(DecodeError::BadOid);
        }
        Self::new(arcs).ok_or(DecodeError::BadOid)
    }
}

/// Splits the packed first subidentifier into the first two arcs. `None` when the second arc
/// does not fit 32 bits (the first arc is 2 and the packed value is 80 or more).
fn split_first(packed: u64) -> Option<(u32, u32)> {
    if packed < 80 {
        let first = u32::try_from(packed / 40).ok()?;
        let second = u32::try_from(packed % 40).ok()?;
        Some((first, second))
    } else {
        let second = u32::try_from(packed.checked_sub(80)?).ok()?;
        Some((2, second))
    }
}

fn push_base128(out: &mut Vec<u8>, v: u32) {
    // Least significant seven bits first; emitted most significant first, with the high bit set
    // on every octet except the last (X.690 §8.19.2).
    let mut chunks = Vec::with_capacity(5);
    let mut v = v;
    loop {
        chunks.push(u8::try_from(v & 0x7f).unwrap_or(0));
        v >>= 7;
        if v == 0 {
            break;
        }
    }
    for (i, c) in chunks.iter().enumerate().rev() {
        out.push(if i == 0 { *c } else { c | 0x80 });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsc_003_oid_content_roundtrip() {
        for text in [
            "1.3.6.1.2.1.1.5.0",
            "1.3.6.1.2.1.4.35.1.4",
            "2.999.1",
            "0.39",
            "1.3.6.1.4.1.8072.3.2.10",
            "1.3.6.1.2.1.1.9.1.2.2147483647",
        ] {
            let oid = Oid::parse(text).unwrap_or_else(|| panic!("parse {text}"));
            let content = oid.to_content().unwrap_or_else(|e| panic!("{e:?}"));
            let back = Oid::from_content(&content).unwrap_or_else(|e| panic!("{text}: {e:?}"));
            assert_eq!(back, oid);
            assert_eq!(back.to_string(), text);
        }
    }

    #[test]
    fn dsc_003_oid_known_encoding() {
        // sysName.0 = 1.3.6.1.2.1.1.5.0 encodes as 2b 06 01 02 01 01 05 00 (X.690 packing).
        let oid = Oid::parse("1.3.6.1.2.1.1.5.0");
        assert_eq!(
            oid.and_then(|o| o.to_content().ok()),
            Some(vec![0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00])
        );
    }

    #[test]
    fn dsc_003_oid_rejects_bad_content() {
        assert_eq!(Oid::from_content(&[]), Err(DecodeError::BadOid));
        // Unterminated final arc.
        assert_eq!(Oid::from_content(&[0x2b, 0x81]), Err(DecodeError::BadOid));
        // One subidentifier packs the first two arcs, so 0x2b is 1.3 and is a valid OID.
        assert_eq!(
            Oid::from_content(&[0x2b]).map(|o| o.to_string()),
            Ok("1.3".to_owned())
        );
        assert_eq!(Oid::from_content(&[0x80]), Err(DecodeError::BadOid));
        // A non-minimal first subidentifier (a leading 0x80) is refused.
        assert_eq!(Oid::from_content(&[0x80, 0x2b]), Err(DecodeError::BadOid));
        // A first subidentifier above 2^32 + 79 is refused, not clamped to u32::MAX.
        assert_eq!(
            Oid::from_content(&[0x90, 0x80, 0x80, 0x80, 0x50]),
            Err(DecodeError::BadOid)
        );
        // A non-minimal arc after the first is refused.
        assert_eq!(
            Oid::from_content(&[0x2b, 0x80, 0x01]),
            Err(DecodeError::BadOid)
        );
        // An arc above 32 bits after the first subidentifier.
        assert_eq!(
            Oid::from_content(&[0x2b, 0x90, 0x80, 0x80, 0x80, 0x00]),
            Err(DecodeError::BadOid)
        );
        // More than 128 arcs.
        let many = vec![0x01u8; 200];
        assert_eq!(Oid::from_content(&many), Err(DecodeError::BadOid));
    }

    #[test]
    fn dsc_003_oid_new_rules() {
        assert!(Oid::new(vec![1]).is_none());
        assert!(Oid::new(vec![3, 0]).is_none());
        assert!(Oid::new(vec![1, 40]).is_none());
        assert!(Oid::new(vec![2, 40]).is_some());
    }
}

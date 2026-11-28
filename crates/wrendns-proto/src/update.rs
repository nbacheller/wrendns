// SPDX-License-Identifier: AGPL-3.0-or-later
//! Dynamic update messages (RFC 2136): the zone, prerequisite and update sections.
//!
//! REQ: CLD-904 (T36.10b step b4) - the `rfc2136` DNS provider builds its requests here. Nothing
//! in this file is on the query hot path: only the provider calls it, a few times an hour at most,
//! and it allocates nothing (the caller supplies the buffer, like [`crate::build_query`]).

use crate::consts::{class, opcode, rtype};
use crate::header::{Flags, Header};
use crate::name::NameBuf;
use crate::writer::{BufferTooSmall, Writer};

/// A prerequisite (RFC 2136 section 2.4): what must hold for the update to be applied at all.
#[derive(Debug, Clone, Copy)]
pub enum Prereq<'a> {
    /// The name has at least one record of any type.
    NameInUse(&'a NameBuf),
    /// The name has no record of any type.
    NameNotInUse(&'a NameBuf),
    /// The name has a record set of this type (any value).
    RrsetExists(&'a NameBuf, u16),
    /// The name has no record set of this type.
    RrsetAbsent(&'a NameBuf, u16),
}

/// One change of the update section (RFC 2136 section 2.5).
#[derive(Debug, Clone, Copy)]
pub enum UpdateChange<'a> {
    /// Adds one record to the set (a set of several values is several `Add`s).
    Add {
        name: &'a NameBuf,
        rtype: u16,
        ttl: u32,
        rdata: &'a [u8],
    },
    /// Removes the whole record set of this type.
    DeleteRrset(&'a NameBuf, u16),
    /// Removes the record with exactly this value.
    DeleteRr {
        name: &'a NameBuf,
        rtype: u16,
        rdata: &'a [u8],
    },
    /// Removes every record set of the name.
    DeleteName(&'a NameBuf),
}

fn rr(
    w: &mut Writer<'_>,
    name: &NameBuf,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdata: &[u8],
) -> Result<(), BufferTooSmall> {
    w.bytes(name.as_wire())?;
    w.u16(rtype)?;
    w.u16(rclass)?;
    w.u32(ttl)?;
    w.u16(u16::try_from(rdata.len()).map_err(|_| BufferTooSmall)?)?;
    w.bytes(rdata)
}

/// Writes an UPDATE (opcode 5) for `zone` into `out` and returns its length. The additional
/// section is left empty: the caller appends a TSIG record there and counts it.
pub fn build_update(
    out: &mut [u8],
    id: u16,
    zone: &NameBuf,
    prereqs: &[Prereq<'_>],
    changes: &[UpdateChange<'_>],
) -> Result<usize, BufferTooSmall> {
    let mut w = Writer::new(out);
    w.bytes(
        &Header {
            id,
            flags: Flags(0).with_opcode(opcode::UPDATE),
            qdcount: 1,
            ancount: u16::try_from(prereqs.len()).map_err(|_| BufferTooSmall)?,
            nscount: u16::try_from(changes.len()).map_err(|_| BufferTooSmall)?,
            arcount: 0,
        }
        .to_bytes(),
    )?;
    // The zone section: the zone's name, type SOA, class IN.
    w.bytes(zone.as_wire())?;
    w.u16(rtype::SOA)?;
    w.u16(class::IN)?;
    for p in prereqs {
        match *p {
            Prereq::NameInUse(n) => rr(&mut w, n, rtype::ANY, class::ANY, 0, &[])?,
            Prereq::NameNotInUse(n) => rr(&mut w, n, rtype::ANY, class::NONE, 0, &[])?,
            Prereq::RrsetExists(n, t) => rr(&mut w, n, t, class::ANY, 0, &[])?,
            Prereq::RrsetAbsent(n, t) => rr(&mut w, n, t, class::NONE, 0, &[])?,
        }
    }
    for c in changes {
        match *c {
            UpdateChange::Add {
                name,
                rtype,
                ttl,
                rdata,
            } => rr(&mut w, name, rtype, class::IN, ttl, rdata)?,
            UpdateChange::DeleteRrset(n, t) => rr(&mut w, n, t, class::ANY, 0, &[])?,
            UpdateChange::DeleteRr { name, rtype, rdata } => {
                rr(&mut w, name, rtype, class::NONE, 0, rdata)?;
            }
            UpdateChange::DeleteName(n) => rr(&mut w, n, rtype::ANY, class::ANY, 0, &[])?,
        }
    }
    Ok(w.pos())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, OpCode};
    use hickory_proto::serialize::binary::BinDecodable;

    fn n(s: &str) -> NameBuf {
        NameBuf::from_presentation(s).unwrap()
    }

    /// REQ: CLD-904 - an update built here is read by an independent decoder with the sections where
    /// RFC 2136 puts them.
    #[test]
    fn cld_904_an_update_is_read_by_hickory() {
        let (zone, name) = (n("example.net"), n("_acme-challenge.example.net"));
        let mut buf = [0u8; 512];
        let txt = [5, b'h', b'e', b'l', b'l', b'o'];
        let len = build_update(
            &mut buf,
            0x1234,
            &zone,
            &[
                Prereq::NameInUse(&zone),
                Prereq::RrsetAbsent(&name, rtype::A),
            ],
            &[
                UpdateChange::DeleteRrset(&name, rtype::TXT),
                UpdateChange::Add {
                    name: &name,
                    rtype: rtype::TXT,
                    ttl: 60,
                    rdata: &txt,
                },
            ],
        )
        .unwrap();
        let m = Message::from_bytes(&buf[..len]).unwrap();
        assert_eq!(m.id, 0x1234);
        assert_eq!(m.op_code, OpCode::Update);
        assert_eq!(m.queries.len(), 1, "one zone entry");
        assert_eq!(m.answers.len(), 2, "two prerequisites");
        assert_eq!(m.authorities.len(), 2, "two updates");
        assert_eq!(m.additionals.len(), 0);
        assert_eq!(m.authorities[1].ttl, 60);
    }

    #[test]
    fn cld_904_an_update_that_does_not_fit_says_so() {
        let zone = n("example.net");
        let mut buf = [0u8; 20];
        assert!(build_update(&mut buf, 1, &zone, &[Prereq::NameInUse(&zone)], &[]).is_err());
    }
}

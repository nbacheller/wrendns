//! REQ: DSC-004, DSC-015 (T25.6, ADR-908, ADR-1001) — the SNMP tables the infrastructure poller reads,
//! as pure functions: the roots of each table and its alternatives, the parse of walked varbinds into
//! typed [`Row`]s (the worker does this, so no raw varbind crosses the process boundary), and the
//! interpretation of those rows into inventory observations (the main process does this: the
//! uplink rule, the FDB ID to VLAN ID map, the bridge port to ifIndex map, LLDP neighbours).
//!
//! Nothing here does I/O or reads a clock. Device text is cut and cleaned on parse (ADR-908
//! "Untrusted strings"), and a malformed row is skipped and counted, never fatal.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use wrendns_config::SnmpTable;
use wrendns_snmp::oid::Oid;
use wrendns_snmp::pdu::{Value, VarBind};

use super::inventory::{NameKind, Observation, Source, sanitize};
use super::sources::{Ipv4Subnet, parse_mac};

/// Device text kept per field (sysName and port names: 64 bytes, ADR-908).
pub(crate) const TEXT_MAX: usize = 64;
/// More than this many learned MACs on a bridge port make it an uplink or trunk (ADR-908).
pub(crate) const UPLINK_MAC_LIMIT: usize = 8;
/// Interfaces kept per poll.
pub(crate) const MAX_IFACES: usize = 2_048;
/// LLDP neighbours kept per bridge or LLDP port (ADR-908: at most 4 per port).
pub(crate) const MAX_LLDP_PER_PORT: usize = 4;

/// A MAC address on the wire: `aa:bb:cc:dd:ee:ff`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Mac(pub(crate) [u8; 6]);

impl Mac {
    /// A MAC that can name a device: not all zero, not a group (multicast or broadcast) address.
    pub(crate) fn is_unicast(self) -> bool {
        self.0 != [0; 6] && self.0.first().is_some_and(|b| b & 0x01 == 0)
    }
}

impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [m0, m1, m2, m3, m4, m5] = self.0;
        write!(f, "{m0:02x}:{m1:02x}:{m2:02x}:{m3:02x}:{m4:02x}:{m5:02x}")
    }
}

impl std::fmt::Debug for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl Serialize for Mac {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Mac {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        parse_mac(&text)
            .map(Mac)
            .ok_or_else(|| serde::de::Error::custom("not a MAC address"))
    }
}

/// One thing the worker found in a table, typed. The worker sends these in batches; the main
/// process reads them with the caps of [`super::supervisor`] (ADR-908).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub(crate) enum Row {
    /// An ARP entry: an address, its MAC and the interface it was learned on.
    Arp { ip: Ipv4Addr, mac: Mac, ifi: u32 },
    /// An interface: its index, name (ifName, else ifDescr), operational state and MAC.
    Iface {
        index: u32,
        name: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        descr: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        oper: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mac: Option<Mac>,
    },
    /// An address the agent holds itself, and the interface it is on.
    Own { ip: Ipv4Addr, ifi: u32 },
    /// A forwarding-table entry: a MAC, the bridge port it was learned on, the FDB ID (Q-BRIDGE
    /// only) and the status (3 = learned).
    Fdb {
        mac: Mac,
        port: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fdb: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<u8>,
    },
    /// `dot1dBasePortIfIndex`: a bridge port and its interface.
    PortIf { port: u32, ifi: u32 },
    /// `dot1qVlanFdbId`: the FDB ID a VLAN uses.
    VlanFdb { fdb: u32, vlan: u32 },
    /// An LLDP neighbour: the local port number it was seen on, its chassis MAC (when the chassis
    /// ID is a MAC address), its port and its system name.
    Lldp {
        port: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chassis: Option<Mac>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        port_id: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        port_desc: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        sys_name: String,
    },
    /// An LLDP local port: its number, ID and description (to name the port a neighbour is on).
    LldpLoc {
        port: u32,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        id: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        desc: String,
    },
}

/// One alternative of a table part (ADR-908 "Tables": the first alternative that answers is used).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum AltId {
    ArpPhysical,
    ArpMedia,
    IfTable,
    AddrNew,
    AddrOld,
    FdbQ,
    FdbD,
    BasePort,
    VlanCurrent,
    LldpRem,
    LldpLoc,
}

impl AltId {
    /// The MIB table's name, as the capability record shows it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::ArpPhysical => "ipNetToPhysicalTable",
            Self::ArpMedia => "ipNetToMediaTable",
            Self::IfTable => "ifTable",
            Self::AddrNew => "ipAddressTable",
            Self::AddrOld => "ipAddrTable",
            Self::FdbQ => "dot1qTpFdbTable",
            Self::FdbD => "dot1dTpFdbTable",
            Self::BasePort => "dot1dBasePortIfIndex",
            Self::VlanCurrent => "dot1qVlanCurrentTable",
            Self::LldpRem => "lldpRemTable",
            Self::LldpLoc => "lldpLocPortTable",
        }
    }

    /// The alternative with this MIB name.
    pub(crate) fn from_name(n: &str) -> Option<Self> {
        ALL_ALTS.iter().copied().find(|a| a.name() == n)
    }

    /// The column roots read for the alternative, in order. The first is the probe's root: one
    /// GETNEXT on it says whether the table answers.
    pub(crate) const fn columns(self) -> &'static [&'static str] {
        match self {
            // ipNetToPhysicalPhysAddress, ipNetToPhysicalState.
            Self::ArpPhysical => &["1.3.6.1.2.1.4.35.1.4", "1.3.6.1.2.1.4.35.1.7"],
            // ipNetToMediaPhysAddress, ipNetToMediaType.
            Self::ArpMedia => &["1.3.6.1.2.1.4.22.1.2", "1.3.6.1.2.1.4.22.1.4"],
            // ifDescr, ifPhysAddress, ifOperStatus, ifName (ifXTable).
            Self::IfTable => &[
                "1.3.6.1.2.1.2.2.1.2",
                "1.3.6.1.2.1.2.2.1.6",
                "1.3.6.1.2.1.2.2.1.8",
                "1.3.6.1.2.1.31.1.1.1.1",
            ],
            // ipAddressIfIndex.
            Self::AddrNew => &["1.3.6.1.2.1.4.34.1.3"],
            // ipAdEntIfIndex.
            Self::AddrOld => &["1.3.6.1.2.1.4.20.1.2"],
            // dot1qTpFdbPort, dot1qTpFdbStatus.
            Self::FdbQ => &["1.3.6.1.2.1.17.7.1.2.2.1.2", "1.3.6.1.2.1.17.7.1.2.2.1.3"],
            // dot1dTpFdbPort, dot1dTpFdbStatus.
            Self::FdbD => &["1.3.6.1.2.1.17.4.3.1.2", "1.3.6.1.2.1.17.4.3.1.3"],
            Self::BasePort => &["1.3.6.1.2.1.17.1.4.1.2"],
            // dot1qVlanFdbId.
            Self::VlanCurrent => &["1.3.6.1.2.1.17.7.1.4.2.1.3"],
            // lldpRemChassisId, lldpRemChassisIdSubtype, lldpRemPortId, PortDesc, SysName.
            Self::LldpRem => &[
                "1.0.8802.1.1.2.1.4.1.1.5",
                "1.0.8802.1.1.2.1.4.1.1.4",
                "1.0.8802.1.1.2.1.4.1.1.7",
                "1.0.8802.1.1.2.1.4.1.1.8",
                "1.0.8802.1.1.2.1.4.1.1.9",
            ],
            // lldpLocPortId, lldpLocPortDesc.
            Self::LldpLoc => &["1.0.8802.1.1.2.1.3.7.1.3", "1.0.8802.1.1.2.1.3.7.1.4"],
        }
    }
}

pub(crate) const ALL_ALTS: [AltId; 11] = [
    AltId::ArpPhysical,
    AltId::ArpMedia,
    AltId::IfTable,
    AltId::AddrNew,
    AltId::AddrOld,
    AltId::FdbQ,
    AltId::FdbD,
    AltId::BasePort,
    AltId::VlanCurrent,
    AltId::LldpRem,
    AltId::LldpLoc,
];

/// One part of a table group: its alternatives, tried in order.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PartDef {
    pub(crate) table: SnmpTable,
    pub(crate) part: &'static str,
    pub(crate) alts: &'static [AltId],
}

/// The parts of every table group (ADR-908 "Tables"). The first part of a group is its main one;
/// the others only improve what the main one says (names for ports, VLAN IDs, local ports).
pub(crate) const PARTS: &[PartDef] = &[
    PartDef {
        table: SnmpTable::Arp,
        part: "arp",
        alts: &[AltId::ArpPhysical, AltId::ArpMedia],
    },
    PartDef {
        table: SnmpTable::Ifmib,
        part: "interfaces",
        alts: &[AltId::IfTable],
    },
    PartDef {
        table: SnmpTable::Ifmib,
        part: "addresses",
        alts: &[AltId::AddrNew, AltId::AddrOld],
    },
    PartDef {
        table: SnmpTable::Bridge,
        part: "forwarding",
        alts: &[AltId::FdbQ, AltId::FdbD],
    },
    PartDef {
        table: SnmpTable::Bridge,
        part: "ports",
        alts: &[AltId::BasePort],
    },
    PartDef {
        table: SnmpTable::Bridge,
        part: "vlans",
        alts: &[AltId::VlanCurrent],
    },
    PartDef {
        table: SnmpTable::Lldp,
        part: "neighbours",
        alts: &[AltId::LldpRem],
    },
    PartDef {
        table: SnmpTable::Lldp,
        part: "local_ports",
        alts: &[AltId::LldpLoc],
    },
];

/// The parts a table group polls.
pub(crate) fn parts_of(table: SnmpTable) -> impl Iterator<Item = &'static PartDef> {
    PARTS.iter().filter(move |p| p.table == table)
}

/// sysObjectID.0 (read once, for the capability record).
pub(crate) const SYS_OBJECT_ID: &str = "1.3.6.1.2.1.1.2.0";

/// How a parse went: what it kept and what it skipped.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Parsed {
    pub(crate) rows: Vec<Row>,
    /// IPv6 entries that were counted and left out (M25 is IPv4 only).
    pub(crate) ipv6_ignored: u32,
    /// Entries that were malformed or in a state that isn't an address binding.
    pub(crate) skipped: u32,
}

/// The arcs of `oid` after `root`, when `oid` is under it.
fn suffix<'a>(oid: &'a Oid, root: &Oid) -> Option<&'a [u32]> {
    let arcs = oid.arcs();
    if !arcs.starts_with(root.arcs()) {
        return None;
    }
    arcs.get(root.arcs().len()..)
}

fn int(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => Some(*i),
        Value::Gauge32(n) | Value::Counter32(n) | Value::TimeTicks(n) => Some(i64::from(*n)),
        _ => None,
    }
}

fn octets(v: &Value) -> Option<&[u8]> {
    match v {
        Value::OctetString(b) => Some(b.as_slice()),
        _ => None,
    }
}

fn mac_of(v: &Value) -> Option<Mac> {
    let b: [u8; 6] = octets(v)?.try_into().ok()?;
    Some(Mac(b))
}

/// Device text as plain text, cut to [`TEXT_MAX`] (ADR-908 "Untrusted strings").
fn text_of(v: &Value) -> String {
    let Some(b) = octets(v) else {
        return String::new();
    };
    let cut = b.get(..b.len().min(255)).unwrap_or(b);
    sanitize(&String::from_utf8_lossy(cut), TEXT_MAX)
}

/// An ID or port name that may be a MAC or binary: text when it is printable, else hex.
fn id_text(v: &Value) -> String {
    let Some(b) = octets(v) else {
        return String::new();
    };
    let cut = b.get(..b.len().min(64)).unwrap_or(b);
    if !cut.is_empty() && cut.iter().all(|c| (0x20..0x7f).contains(c)) {
        sanitize(&String::from_utf8_lossy(cut), TEXT_MAX)
    } else {
        let hex: Vec<String> = cut.iter().take(16).map(|c| format!("{c:02x}")).collect();
        hex.join(":")
    }
}

fn u32_of(i: i64) -> Option<u32> {
    u32::try_from(i).ok()
}

fn root(text: &str) -> Option<Oid> {
    Oid::parse(text)
}

fn ipv4_of(arcs: &[u32]) -> Option<Ipv4Addr> {
    let [a, b, c, d] = arcs else {
        return None;
    };
    Some(Ipv4Addr::new(
        u8::try_from(*a).ok()?,
        u8::try_from(*b).ok()?,
        u8::try_from(*c).ok()?,
        u8::try_from(*d).ok()?,
    ))
}

fn mac_from_arcs(arcs: &[u32]) -> Option<Mac> {
    let mut out = [0u8; 6];
    if arcs.len() != 6 {
        return None;
    }
    for (slot, arc) in out.iter_mut().zip(arcs) {
        *slot = u8::try_from(*arc).ok()?;
    }
    Some(Mac(out))
}

/// Parses the walked columns of one alternative into rows. `walks` holds one walk per column of
/// [`AltId::columns`], in that order (a column that wasn't read is empty).
pub(crate) fn parse(alt: AltId, walks: &[Vec<VarBind>]) -> Parsed {
    let empty: Vec<VarBind> = Vec::new();
    let col = |i: usize| walks.get(i).unwrap_or(&empty);
    match alt {
        AltId::ArpPhysical => parse_arp_physical(col(0), col(1)),
        AltId::ArpMedia => parse_arp_media(col(0), col(1)),
        AltId::IfTable => parse_ifs(col(0), col(1), col(2), col(3)),
        AltId::AddrNew => parse_addr_new(col(0)),
        AltId::AddrOld => parse_addr_old(col(0)),
        AltId::FdbQ => parse_fdb_q(col(0), col(1)),
        AltId::FdbD => parse_fdb_d(col(0), col(1)),
        AltId::BasePort => parse_base_port(col(0)),
        AltId::VlanCurrent => parse_vlan_fdb(col(0)),
        AltId::LldpRem => parse_lldp_rem(walks),
        AltId::LldpLoc => parse_lldp_loc(col(0), col(1)),
    }
}

/// `ipNetToPhysicalTable`: index ifIndex, address type, address length, address. Type 1 with four
/// octets is IPv4; the IPv6 types are counted and ignored. A state of invalid, unknown or
/// incomplete is not a binding.
fn parse_arp_physical(macs: &[VarBind], states: &[VarBind]) -> Parsed {
    let mut out = Parsed::default();
    let (Some(mac_root), Some(state_root)) = (
        AltId::ArpPhysical.columns().first().and_then(|t| root(t)),
        AltId::ArpPhysical.columns().get(1).and_then(|t| root(t)),
    ) else {
        return out;
    };
    let mut state: HashMap<(u32, Ipv4Addr), i64> = HashMap::new();
    for vb in states {
        if let Some([ifi, 1, 4, addr @ ..]) = suffix(&vb.oid, &state_root)
            && let (Some(ip), Some(s)) = (ipv4_of(addr), int(&vb.value))
        {
            state.insert((*ifi, ip), s);
        }
    }
    for vb in macs {
        let Some(rest) = suffix(&vb.oid, &mac_root) else {
            continue;
        };
        match rest {
            [ifi, 1, 4, addr @ ..] => {
                let (Some(ip), Some(mac)) = (ipv4_of(addr), mac_of(&vb.value)) else {
                    out.skipped = out.skipped.saturating_add(1);
                    continue;
                };
                // reachable(1), stale(2), delay(3), probe(4) are bindings; invalid(5), unknown(6)
                // and incomplete(7) are not.
                if state.get(&(*ifi, ip)).is_some_and(|s| !(1..=4).contains(s)) {
                    out.skipped = out.skipped.saturating_add(1);
                    continue;
                }
                out.rows.push(Row::Arp { ip, mac, ifi: *ifi });
            }
            // ipv6(2), ipv6z(4) and anything else with another length.
            [_, _, _, ..] => out.ipv6_ignored = out.ipv6_ignored.saturating_add(1),
            _ => out.skipped = out.skipped.saturating_add(1),
        }
    }
    out
}

/// `ipNetToMediaTable`: index ifIndex and the IPv4 address. Type invalid(2) is not a binding.
fn parse_arp_media(macs: &[VarBind], types: &[VarBind]) -> Parsed {
    let mut out = Parsed::default();
    let (Some(mac_root), Some(type_root)) = (
        AltId::ArpMedia.columns().first().and_then(|t| root(t)),
        AltId::ArpMedia.columns().get(1).and_then(|t| root(t)),
    ) else {
        return out;
    };
    let mut kind: HashMap<(u32, Ipv4Addr), i64> = HashMap::new();
    for vb in types {
        if let Some([ifi, addr @ ..]) = suffix(&vb.oid, &type_root)
            && let (Some(ip), Some(t)) = (ipv4_of(addr), int(&vb.value))
        {
            kind.insert((*ifi, ip), t);
        }
    }
    for vb in macs {
        let Some([ifi, addr @ ..]) = suffix(&vb.oid, &mac_root) else {
            continue;
        };
        let (Some(ip), Some(mac)) = (ipv4_of(addr), mac_of(&vb.value)) else {
            out.skipped = out.skipped.saturating_add(1);
            continue;
        };
        if kind.get(&(*ifi, ip)) == Some(&2) {
            out.skipped = out.skipped.saturating_add(1);
            continue;
        }
        out.rows.push(Row::Arp { ip, mac, ifi: *ifi });
    }
    out
}

/// One interface being assembled from the columns of ifTable and ifXTable.
#[derive(Default)]
struct IfaceBuilder {
    descr: String,
    name: String,
    oper: Option<u8>,
    mac: Option<Mac>,
}

/// One LLDP neighbour being assembled from the columns of `lldpRemTable`.
#[derive(Default)]
struct LldpBuilder {
    chassis: Option<Vec<u8>>,
    csub: Option<i64>,
    port_id: String,
    port_desc: String,
    sys_name: String,
}

/// An LLDP remote entry's index: time mark, local port number, remote index.
type LldpKey = (u32, u32, u32);

/// The builder of interface `idx`, unless the cap of interfaces is reached.
fn entry(by: &mut BTreeMap<u32, IfaceBuilder>, idx: u32) -> Option<&mut IfaceBuilder> {
    if by.len() >= MAX_IFACES && !by.contains_key(&idx) {
        return None;
    }
    Some(by.entry(idx).or_default())
}

/// ifTable and ifXTable: one row per interface, named by ifName, else ifDescr.
fn parse_ifs(descr: &[VarBind], macs: &[VarBind], oper: &[VarBind], names: &[VarBind]) -> Parsed {
    let mut out = Parsed::default();
    let cols = AltId::IfTable.columns();
    let (Some(r_descr), Some(r_mac), Some(r_oper), Some(r_name)) = (
        cols.first().and_then(|t| root(t)),
        cols.get(1).and_then(|t| root(t)),
        cols.get(2).and_then(|t| root(t)),
        cols.get(3).and_then(|t| root(t)),
    ) else {
        return out;
    };
    let mut by: BTreeMap<u32, IfaceBuilder> = BTreeMap::new();
    for vb in descr {
        if let Some([i]) = suffix(&vb.oid, &r_descr)
            && let Some(b) = entry(&mut by, *i)
        {
            b.descr = text_of(&vb.value);
        }
    }
    for vb in names {
        if let Some([i]) = suffix(&vb.oid, &r_name)
            && let Some(b) = entry(&mut by, *i)
        {
            b.name = text_of(&vb.value);
        }
    }
    for vb in oper {
        if let Some([i]) = suffix(&vb.oid, &r_oper)
            && let Some(b) = entry(&mut by, *i)
        {
            b.oper = int(&vb.value).and_then(|v| u8::try_from(v).ok());
        }
    }
    for vb in macs {
        if let Some([i]) = suffix(&vb.oid, &r_mac)
            && let Some(b) = entry(&mut by, *i)
        {
            b.mac = mac_of(&vb.value).filter(|m| m.is_unicast());
        }
    }
    for (index, b) in by {
        let name = if b.name.is_empty() {
            b.descr.clone()
        } else {
            b.name
        };
        out.rows.push(Row::Iface {
            index,
            name,
            descr: b.descr,
            oper: b.oper,
            mac: b.mac,
        });
    }
    out
}

/// `ipAddressTable`: the interface of each address; index address type, length, address.
fn parse_addr_new(ifs: &[VarBind]) -> Parsed {
    let mut out = Parsed::default();
    let Some(r) = AltId::AddrNew.columns().first().and_then(|t| root(t)) else {
        return out;
    };
    for vb in ifs {
        match suffix(&vb.oid, &r) {
            Some([1, 4, addr @ ..]) => {
                if let (Some(ip), Some(ifi)) = (ipv4_of(addr), int(&vb.value).and_then(u32_of)) {
                    out.rows.push(Row::Own { ip, ifi });
                } else {
                    out.skipped = out.skipped.saturating_add(1);
                }
            }
            Some([_, _, ..]) => out.ipv6_ignored = out.ipv6_ignored.saturating_add(1),
            _ => out.skipped = out.skipped.saturating_add(1),
        }
    }
    out
}

/// `ipAddrTable`: index is the IPv4 address; the value is its interface.
fn parse_addr_old(ifs: &[VarBind]) -> Parsed {
    let mut out = Parsed::default();
    let Some(r) = AltId::AddrOld.columns().first().and_then(|t| root(t)) else {
        return out;
    };
    for vb in ifs {
        let Some(addr) = suffix(&vb.oid, &r) else {
            continue;
        };
        if let (Some(ip), Some(ifi)) = (ipv4_of(addr), int(&vb.value).and_then(u32_of)) {
            out.rows.push(Row::Own { ip, ifi });
        } else {
            out.skipped = out.skipped.saturating_add(1);
        }
    }
    out
}

/// `dot1qTpFdbTable`: index FDB ID and the MAC (six arcs).
fn parse_fdb_q(ports: &[VarBind], status: &[VarBind]) -> Parsed {
    let mut out = Parsed::default();
    let cols = AltId::FdbQ.columns();
    let (Some(r_port), Some(r_status)) = (
        cols.first().and_then(|t| root(t)),
        cols.get(1).and_then(|t| root(t)),
    ) else {
        return out;
    };
    let mut st: HashMap<(u32, Mac), u8> = HashMap::new();
    for vb in status {
        if let Some([fdb, m @ ..]) = suffix(&vb.oid, &r_status)
            && let (Some(mac), Some(s)) = (
                mac_from_arcs(m),
                int(&vb.value).and_then(|v| u8::try_from(v).ok()),
            )
        {
            st.insert((*fdb, mac), s);
        }
    }
    for vb in ports {
        let Some([fdb, m @ ..]) = suffix(&vb.oid, &r_port) else {
            continue;
        };
        let (Some(mac), Some(port)) = (mac_from_arcs(m), int(&vb.value).and_then(u32_of)) else {
            out.skipped = out.skipped.saturating_add(1);
            continue;
        };
        out.rows.push(Row::Fdb {
            mac,
            port,
            fdb: Some(*fdb),
            status: st.get(&(*fdb, mac)).copied(),
        });
    }
    out
}

/// `dot1dTpFdbTable`: index is the MAC (six arcs).
fn parse_fdb_d(ports: &[VarBind], status: &[VarBind]) -> Parsed {
    let mut out = Parsed::default();
    let cols = AltId::FdbD.columns();
    let (Some(r_port), Some(r_status)) = (
        cols.first().and_then(|t| root(t)),
        cols.get(1).and_then(|t| root(t)),
    ) else {
        return out;
    };
    let mut st: HashMap<Mac, u8> = HashMap::new();
    for vb in status {
        if let Some(m) = suffix(&vb.oid, &r_status)
            && let (Some(mac), Some(s)) = (
                mac_from_arcs(m),
                int(&vb.value).and_then(|v| u8::try_from(v).ok()),
            )
        {
            st.insert(mac, s);
        }
    }
    for vb in ports {
        let Some(m) = suffix(&vb.oid, &r_port) else {
            continue;
        };
        let (Some(mac), Some(port)) = (mac_from_arcs(m), int(&vb.value).and_then(u32_of)) else {
            out.skipped = out.skipped.saturating_add(1);
            continue;
        };
        out.rows.push(Row::Fdb {
            mac,
            port,
            fdb: None,
            status: st.get(&mac).copied(),
        });
    }
    out
}

/// `dot1dBasePortIfIndex`: bridge port to interface.
fn parse_base_port(ifs: &[VarBind]) -> Parsed {
    let mut out = Parsed::default();
    let Some(r) = AltId::BasePort.columns().first().and_then(|t| root(t)) else {
        return out;
    };
    for vb in ifs {
        if let Some([port]) = suffix(&vb.oid, &r)
            && let Some(ifi) = int(&vb.value).and_then(u32_of)
        {
            out.rows.push(Row::PortIf { port: *port, ifi });
        } else {
            out.skipped = out.skipped.saturating_add(1);
        }
    }
    out
}

/// `dot1qVlanCurrentTable`: index time mark and VLAN ID; `dot1qVlanFdbId` is the value.
fn parse_vlan_fdb(fdbs: &[VarBind]) -> Parsed {
    let mut out = Parsed::default();
    let Some(r) = AltId::VlanCurrent.columns().first().and_then(|t| root(t)) else {
        return out;
    };
    let mut seen: BTreeSet<(u32, u32)> = BTreeSet::new();
    for vb in fdbs {
        if let Some([_, vlan]) = suffix(&vb.oid, &r)
            && let Some(fdb) = int(&vb.value).and_then(u32_of)
        {
            if seen.insert((fdb, *vlan)) {
                out.rows.push(Row::VlanFdb { fdb, vlan: *vlan });
            }
        } else {
            out.skipped = out.skipped.saturating_add(1);
        }
    }
    out
}

/// The builder of the LLDP entry an index names, unless the cap of entries is reached.
fn slot(by: &mut BTreeMap<LldpKey, LldpBuilder>, arcs: &[u32]) -> Option<LldpKey> {
    let [t, p, i] = arcs else {
        return None;
    };
    let k = (*t, *p, *i);
    if by.len() >= 512 && !by.contains_key(&k) {
        return None;
    }
    by.entry(k).or_default();
    Some(k)
}

/// `lldpRemTable`: index time mark, local port number and remote index. The chassis is a MAC only
/// when its subtype is macAddress(4).
fn parse_lldp_rem(walks: &[Vec<VarBind>]) -> Parsed {
    let mut out = Parsed::default();
    let cols = AltId::LldpRem.columns();
    let roots: Vec<Option<Oid>> = cols.iter().map(|t| root(t)).collect();
    let [
        Some(r_chassis),
        Some(r_csub),
        Some(r_pid),
        Some(r_pdesc),
        Some(r_name),
    ] = roots.as_slice()
    else {
        return out;
    };
    let mut by: BTreeMap<LldpKey, LldpBuilder> = BTreeMap::new();
    let empty: Vec<VarBind> = Vec::new();
    let walk = |i: usize| walks.get(i).unwrap_or(&empty);
    for vb in walk(0) {
        if let Some(a) = suffix(&vb.oid, r_chassis)
            && let Some(k) = slot(&mut by, a)
            && let Some(b) = by.get_mut(&k)
        {
            b.chassis = octets(&vb.value).map(<[u8]>::to_vec);
        }
    }
    for vb in walk(1) {
        if let Some(a) = suffix(&vb.oid, r_csub)
            && let Some(k) = slot(&mut by, a)
            && let Some(b) = by.get_mut(&k)
        {
            b.csub = int(&vb.value);
        }
    }
    for vb in walk(2) {
        if let Some(a) = suffix(&vb.oid, r_pid)
            && let Some(k) = slot(&mut by, a)
            && let Some(b) = by.get_mut(&k)
        {
            b.port_id = id_text(&vb.value);
        }
    }
    for vb in walk(3) {
        if let Some(a) = suffix(&vb.oid, r_pdesc)
            && let Some(k) = slot(&mut by, a)
            && let Some(b) = by.get_mut(&k)
        {
            b.port_desc = text_of(&vb.value);
        }
    }
    for vb in walk(4) {
        if let Some(a) = suffix(&vb.oid, r_name)
            && let Some(k) = slot(&mut by, a)
            && let Some(b) = by.get_mut(&k)
        {
            b.sys_name = text_of(&vb.value);
        }
    }
    for ((_, port, _), b) in by {
        // The chassis is a MAC only when its subtype says so (macAddress = 4).
        let chassis = match (b.csub, b.chassis) {
            (Some(4), Some(c)) => <[u8; 6]>::try_from(c.as_slice()).ok().map(Mac),
            _ => None,
        }
        .filter(|m| m.is_unicast());
        out.rows.push(Row::Lldp {
            port,
            chassis,
            port_id: b.port_id,
            port_desc: b.port_desc,
            sys_name: b.sys_name,
        });
    }
    out
}

/// `lldpLocPortTable`: index is the local port number.
fn parse_lldp_loc(ids: &[VarBind], descs: &[VarBind]) -> Parsed {
    let mut out = Parsed::default();
    let cols = AltId::LldpLoc.columns();
    let (Some(r_id), Some(r_desc)) = (
        cols.first().and_then(|t| root(t)),
        cols.get(1).and_then(|t| root(t)),
    ) else {
        return out;
    };
    let mut by: BTreeMap<u32, (String, String)> = BTreeMap::new();
    for vb in ids {
        if let Some([p]) = suffix(&vb.oid, &r_id)
            && by.len() < MAX_IFACES
        {
            by.entry(*p).or_default().0 = id_text(&vb.value);
        }
    }
    for vb in descs {
        if let Some([p]) = suffix(&vb.oid, &r_desc)
            && (by.len() < MAX_IFACES || by.contains_key(p))
        {
            by.entry(*p).or_default().1 = text_of(&vb.value);
        }
    }
    for (port, (id, desc)) in by {
        out.rows.push(Row::LldpLoc { port, id, desc });
    }
    out
}

/// REQ: DSC-004 — who counts as infrastructure when the uplink rule asks whether an LLDP neighbour
/// is a listed agent or a UniFi device (ADR-908).
#[derive(Debug, Default, Clone)]
pub(crate) struct InfraSet {
    /// The MACs of listed agents' own interfaces (learned from earlier polls and this one).
    pub(crate) macs: HashSet<Mac>,
    /// The listed agents' names and their sysNames, lower case.
    pub(crate) names: HashSet<String>,
    /// The MACs of UniFi devices (T25.10 fills this; empty until then).
    pub(crate) unifi_macs: HashSet<Mac>,
}

/// What one poll's rows meant, for the status and the metrics.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Interpreted {
    /// ARP entries merged.
    pub(crate) arp_merged: u32,
    /// ARP entries outside every `[[discovery.subnet]]`, or addresses that name no host.
    pub(crate) arp_outside_subnets: u32,
    /// The agent's own addresses merged.
    pub(crate) own_merged: u32,
    /// Forwarding entries that gave a location.
    pub(crate) fdb_located: u32,
    /// Forwarding entries left out because they were learned on an uplink or trunk port.
    pub(crate) fdb_uplink: u32,
    /// Forwarding entries left out for another reason (not learned, the agent's own MAC).
    pub(crate) fdb_skipped: u32,
    /// Ports that count as uplinks.
    pub(crate) uplink_ports: u32,
    /// LLDP neighbours merged.
    pub(crate) lldp_merged: u32,
    /// LLDP neighbours with no MAC chassis (left out).
    pub(crate) lldp_no_mac: u32,
}

/// An interpretation: observations to merge, the agent's own interface MACs, and the counts.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    pub(crate) observations: Vec<Observation>,
    /// The MACs of the agent's own interfaces (for other agents' uplink rule).
    pub(crate) own_macs: Vec<Mac>,
    pub(crate) counts: Interpreted,
}

fn address_names_a_host(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast())
}

/// What the interpretation needs besides the rows.
pub(crate) struct Context<'a> {
    pub(crate) agent: &'a str,
    pub(crate) subnets: &'a [Ipv4Subnet],
    pub(crate) infra: &'a InfraSet,
    pub(crate) now: u64,
}

/// REQ: DSC-004 (ADR-908, ADR-910) — turns a poll's rows into observations:
/// - ARP entries become class 3 bindings (`Source::SnmpArp`), inside the listed subnets only;
/// - the agent's own addresses become bindings with its interface's MAC and its name;
/// - forwarding entries give a VLAN and a port, except on an uplink or trunk port (more than 8
///   learned MACs, or an LLDP neighbour that is itself a listed agent or a UniFi device);
/// - LLDP neighbours with a MAC chassis give that device its name and the port it hangs off.
#[allow(clippy::too_many_lines)] // one pass per kind of row over the same few maps
pub(crate) fn interpret(rows: &[Row], cx: &Context<'_>) -> Outcome {
    let mut out = Outcome::default();
    let mut ifaces: HashMap<u32, (&str, &str, Option<Mac>)> = HashMap::new();
    let mut port_if: HashMap<u32, u32> = HashMap::new();
    let mut vlan_of_fdb: HashMap<u32, u32> = HashMap::new();
    let mut lldp_loc: HashMap<u32, (&str, &str)> = HashMap::new();
    for r in rows {
        match r {
            Row::Iface {
                index,
                name,
                descr,
                mac,
                ..
            } => {
                ifaces.insert(*index, (name.as_str(), descr.as_str(), *mac));
            }
            Row::PortIf { port, ifi } => {
                port_if.insert(*port, *ifi);
            }
            Row::VlanFdb { fdb, vlan } => {
                // The FDB ID is not the VLAN ID (ADR-908); the first VLAN that uses an ID names it.
                vlan_of_fdb.entry(*fdb).or_insert(*vlan);
            }
            Row::LldpLoc { port, id, desc } => {
                lldp_loc.insert(*port, (id.as_str(), desc.as_str()));
            }
            _ => {}
        }
    }
    let in_subnets = |ip: Ipv4Addr| cx.subnets.iter().any(|s| s.contains(ip));
    let own_macs: HashSet<Mac> = ifaces.values().filter_map(|(_, _, m)| *m).collect();
    out.own_macs = own_macs.iter().copied().collect();
    out.own_macs.sort();

    // The label of an interface: ifName, else ifDescr, else its number.
    let if_label = |ifi: u32| -> String {
        match ifaces.get(&ifi) {
            Some((name, _, _)) if !name.is_empty() => (*name).to_owned(),
            Some((_, descr, _)) if !descr.is_empty() => (*descr).to_owned(),
            _ => format!("if{ifi}"),
        }
    };
    let port_label = |port: u32| -> String {
        match port_if.get(&port) {
            Some(ifi) => if_label(*ifi),
            None => format!("port {port}"),
        }
    };
    let located = |label: &str| sanitize(&format!("{} {label}", cx.agent), TEXT_MAX);

    // ARP and the agent's own addresses.
    for r in rows {
        match r {
            Row::Arp { ip, mac, .. } => {
                if !address_names_a_host(*ip) || !in_subnets(*ip) || !mac.is_unicast() {
                    out.counts.arp_outside_subnets =
                        out.counts.arp_outside_subnets.saturating_add(1);
                    continue;
                }
                let mut o = Observation::new(Source::SnmpArp, cx.now);
                o.mac = Some(mac.0);
                o.ip = Some(IpAddr::V4(*ip));
                out.observations.push(o);
                out.counts.arp_merged = out.counts.arp_merged.saturating_add(1);
            }
            Row::Own { ip, ifi } => {
                let Some((_, _, Some(mac))) = ifaces.get(ifi) else {
                    continue;
                };
                if !address_names_a_host(*ip) || !in_subnets(*ip) {
                    continue;
                }
                let mut o = Observation::new(Source::SnmpArp, cx.now);
                o.mac = Some(mac.0);
                o.ip = Some(IpAddr::V4(*ip));
                o.name = Some((NameKind::Snmp, cx.agent.to_owned()));
                // REQ: DSC-903 (R4) — the agent is one device whatever its interfaces' MACs.
                o.hint_mut().device_key = Some("device".to_owned());
                out.observations.push(o);
                out.counts.own_merged = out.counts.own_merged.saturating_add(1);
            }
            _ => {}
        }
    }

    // LLDP neighbours: which port each is on, by interface.
    // The interface of an LLDP local port: the interface whose name or description is the port's
    // ID or description, else the port number taken as an ifIndex when such an interface exists.
    let lldp_if = |port: u32| -> Option<u32> {
        if let Some((id, desc)) = lldp_loc.get(&port) {
            let hit = ifaces.iter().find(|(_, (name, d, _))| {
                [*id, *desc]
                    .iter()
                    .any(|t| !t.is_empty() && (t == name || t == d))
            });
            if let Some((i, _)) = hit {
                return Some(*i);
            }
        }
        ifaces.contains_key(&port).then_some(port)
    };
    let lldp_label = |port: u32| -> String {
        if let Some((id, desc)) = lldp_loc.get(&port) {
            if !desc.is_empty() {
                return (*desc).to_owned();
            }
            if !id.is_empty() {
                return (*id).to_owned();
            }
        }
        match lldp_if(port) {
            Some(i) => if_label(i),
            None => format!("port {port}"),
        }
    };
    let is_infra = |chassis: Option<Mac>, sys_name: &str| -> bool {
        chassis.is_some_and(|m| {
            cx.infra.macs.contains(&m) || cx.infra.unifi_macs.contains(&m) || own_macs.contains(&m)
        }) || (!sys_name.is_empty() && cx.infra.names.contains(&sys_name.to_ascii_lowercase()))
    };
    let mut infra_ifs: HashSet<u32> = HashSet::new();
    let mut per_port: HashMap<u32, usize> = HashMap::new();
    for r in rows {
        if let Row::Lldp {
            port,
            chassis,
            sys_name,
            ..
        } = r
        {
            if is_infra(*chassis, sys_name)
                && let Some(i) = lldp_if(*port)
            {
                infra_ifs.insert(i);
            }
            let n = per_port.entry(*port).or_insert(0);
            *n = n.saturating_add(1);
            if *n > MAX_LLDP_PER_PORT {
                continue;
            }
            let Some(mac) = chassis else {
                out.counts.lldp_no_mac = out.counts.lldp_no_mac.saturating_add(1);
                continue;
            };
            if own_macs.contains(mac) {
                continue;
            }
            let mut o = Observation::new(Source::Snmp, cx.now);
            o.mac = Some(mac.0);
            if !sys_name.is_empty() {
                o.name = Some((NameKind::Snmp, sys_name.clone()));
            }
            o.lldp.push(sanitize(
                &format!("{} {}", cx.agent, lldp_label(*port)),
                TEXT_MAX,
            ));
            out.observations.push(o);
            out.counts.lldp_merged = out.counts.lldp_merged.saturating_add(1);
        }
    }

    // Forwarding entries: learned only, never the agent's own MAC, and never on an uplink.
    let mut learned_on: HashMap<u32, HashSet<Mac>> = HashMap::new();
    for r in rows {
        if let Row::Fdb {
            mac, port, status, ..
        } = r
            && status.is_none_or(|s| s == 3)
        {
            learned_on.entry(*port).or_default().insert(*mac);
        }
    }
    let mut uplink: HashSet<u32> = HashSet::new();
    for (port, macs) in &learned_on {
        let by_lldp = port_if.get(port).is_some_and(|i| infra_ifs.contains(i))
            || (!port_if.contains_key(port) && infra_ifs.contains(port));
        if macs.len() > UPLINK_MAC_LIMIT || by_lldp {
            uplink.insert(*port);
        }
    }
    // A port whose neighbour is infrastructure is an uplink even with no learned MAC.
    out.counts.uplink_ports = u32::try_from(uplink.len()).unwrap_or(u32::MAX);
    for r in rows {
        let Row::Fdb {
            mac,
            port,
            fdb,
            status,
        } = r
        else {
            continue;
        };
        if status.is_some_and(|s| s != 3) || own_macs.contains(mac) || !mac.is_unicast() {
            out.counts.fdb_skipped = out.counts.fdb_skipped.saturating_add(1);
            continue;
        }
        if uplink.contains(port) {
            out.counts.fdb_uplink = out.counts.fdb_uplink.saturating_add(1);
            continue;
        }
        let mut o = Observation::new(Source::Snmp, cx.now);
        o.mac = Some(mac.0);
        o.port = Some(located(&port_label(*port)));
        // REQ: DSC-903 (T31.2) — the same place, structured: the agent's device and the port.
        o.hint_mut().port_ref = Some(("device".to_owned(), port_label(*port)));
        o.vlan = fdb
            .and_then(|f| vlan_of_fdb.get(&f).copied())
            .and_then(|v| u16::try_from(v).ok());
        out.observations.push(o);
        out.counts.fdb_located = out.counts.fdb_located.saturating_add(1);
    }
    out
}

#[cfg(test)]
#[path = "snmp_tables_tests.rs"]
mod tests;

//! The network inventory's data model and merge (DSC-008, ADR-910, ADR-923).
//!
//! One entry per MAC, with at most four address bindings, ranked names, a source mask and the
//! import rows it holds. A claim with no MAC attaches to the MAC entry that holds its address as
//! a current binding; otherwise it goes to an IP-only entry keyed by its address. This module does
//! no I/O and reads no clock: callers pass `now` in Unix seconds, so the merge can be tested and
//! fuzzed. Nothing here reaches DNS, policy, client matching or `identify` (ADR-910; the test
//! `dsc_008_never_in_neighbors_or_leases` guards that).

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// MAC entries kept at most (ADR-910).
pub(crate) const MAX_MAC_ENTRIES: usize = 4_096;
/// IP-only entries kept at most, oldest dropped first (ADR-910).
pub(crate) const MAX_IP_ONLY_ENTRIES: usize = 1_024;
/// Import-derived rows kept in total, oldest import dropped first (DSC-008).
pub(crate) const MAX_IMPORT_ROWS: usize = 8_192;
/// Rows one import may carry (DSC-010, ADR-913).
pub(crate) const MAX_ROWS_PER_IMPORT: usize = 4_096;
/// Imports kept at once: one bit each in the 16-bit import mask.
pub(crate) const MAX_IMPORTS: usize = 16;
/// Distinct addresses per entry (DSC-008). Records are kept per source, so the cap counts
/// addresses, not records.
pub(crate) const MAX_ADDRS: usize = 4;
/// How long a conflict holds after the last competing current claim (ADR-923). Above two poll
/// intervals, so one missed poll does not clear it.
pub(crate) const CONFLICT_HOLD_SECS: u64 = 900;
/// Display names per entry.
pub(crate) const MAX_NAMES: usize = 4;
/// Open TCP ports per entry, from imports (ADR-910).
pub(crate) const MAX_PORTS: usize = 16;
/// LLDP neighbours per entry (ADR-910).
pub(crate) const MAX_LLDP: usize = 4;
/// Mutes kept at most; the oldest goes first (T25.1 review, fix 12).
pub(crate) const MAX_MUTES: usize = 1_024;
/// The learning period after the first enable or an empty start (ADR-910).
pub(crate) const LEARNING_SECS: u64 = 24 * 3600;
/// Names are cut to this many bytes (DSC-015).
pub(crate) const NAME_MAX: usize = 64;
/// Other device strings are cut to this many bytes (DSC-015).
pub(crate) const TEXT_MAX: usize = 255;

/// Where an observation came from. The class decides whether its address is a current binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Source {
    /// UniFi clients and reservations, OPNsense leases, and the `[[router]]` answers.
    Router,
    /// Home Assistant's device registry and trackers (ADR-923: an address is a claim).
    HomeAssistant,
    /// The local kernel neighbour table, filtered (ADR-910).
    Neighbor,
    /// ARP from a listed infrastructure agent (DSC-004; not polled before T25.6).
    SnmpArp,
    /// Passive mDNS announcements. Unauthenticated, so an address is a claim (ADR-923).
    Mdns,
    /// SNMP identity (sysName and friends); carries names, not addresses (ADR-923).
    Snmp,
    /// A scan the owner uploaded (ADR-913).
    Import,
    /// UniFi `stat/alluser` `last_ip`: history only, never current (ADR-912).
    History,
    /// The configured client name. Attaches to entries; never creates one (ADR-923).
    Config,
}

impl Source {
    /// The precedence class of an address from this source (ADR-910, ADR-923). Classes 1–3 are
    /// current bindings and 4–5 are claims. `None` marks a source whose addresses are never
    /// current: Home Assistant and mDNS addresses are claims, and SNMP identity and the configured
    /// name carry no address of their own.
    pub(crate) const fn class(self) -> Option<u8> {
        match self {
            Self::Router => Some(1),
            Self::Neighbor => Some(2),
            Self::SnmpArp => Some(3),
            Self::Import => Some(4),
            Self::History => Some(5),
            Self::HomeAssistant | Self::Mdns | Self::Snmp | Self::Config => None,
        }
    }

    /// Whether an address from this source is a current binding (classes 1–3). Only those make an
    /// address an SNMP destination (ADR-907), take part in conflicts, or count as an owner.
    pub(crate) const fn is_current(self) -> bool {
        matches!(self.class(), Some(1..=3))
    }

    /// The sort order of bindings: the class, with unclassed claims after the classed ones.
    pub(crate) const fn order(self) -> u8 {
        match self.class() {
            Some(c) => c,
            None => 4,
        }
    }

    /// The bit this source takes in an entry's source mask.
    pub(crate) const fn bit(self) -> u16 {
        match self {
            Self::Router => 0x001,
            Self::HomeAssistant => 0x002,
            Self::Neighbor => 0x004,
            Self::SnmpArp => 0x008,
            Self::Mdns => 0x010,
            Self::Snmp => 0x020,
            Self::Import => 0x040,
            Self::History => 0x080,
            Self::Config => 0x100,
        }
    }
}

/// What a display name is, which gives its rank (ADR-910, lower wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NameKind {
    /// The configured client name.
    ClientName,
    /// Home Assistant's `name_by_user`.
    HaUser,
    /// The router alias or host name, in `[[router]]` order.
    RouterAlias,
    /// A Home Assistant integration's name.
    HaIntegration,
    /// A passive mDNS name.
    Mdns,
    /// SNMP sysName or a printer name (labelled with its source).
    Snmp,
    /// An import's host name (labelled with its source).
    Import,
    /// A name from UniFi's client history (`stat/alluser`, ADR-912): history, so it ranks last.
    History,
}

impl NameKind {
    /// The rank in ADR-910's display order.
    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::ClientName => 1,
            Self::HaUser => 2,
            Self::RouterAlias => 3,
            Self::HaIntegration => 4,
            Self::Mdns => 5,
            Self::Snmp => 6,
            Self::Import => 7,
            Self::History => 8,
        }
    }

    /// The source a name is labelled with.
    pub(crate) const fn source(self) -> Source {
        match self {
            Self::ClientName => Source::Config,
            Self::HaUser | Self::HaIntegration => Source::HomeAssistant,
            Self::RouterAlias => Source::Router,
            Self::Mdns => Source::Mdns,
            Self::Snmp => Source::Snmp,
            Self::Import => Source::Import,
            Self::History => Source::History,
        }
    }
}

/// One address a source reported for an entry. A binding is kept per (address, source, import),
/// so a source that stops reporting an address expires only its own record (ADR-924).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Binding {
    pub(crate) ip: IpAddr,
    pub(crate) source: Source,
    /// Unix seconds of the newest observation.
    pub(crate) seen: u64,
    /// The import that supplied it, so deleting the import removes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) import_bit: Option<u8>,
}

impl Binding {
    /// Whether this binding is current (class 1–3).
    pub(crate) const fn is_current(&self) -> bool {
        self.source.is_current()
    }
}

/// A display name with its kind. A name is replaced when a source reports the same kind again
/// from the same origin (a router, or none), so a rename shows the new name (DSC-008).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NameEntry {
    pub(crate) kind: NameKind,
    pub(crate) label: String,
    /// The `[[router]]` that named it, for router aliases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) origin: Option<String>,
}

/// SNMP identity reads for a host (DSC-005, T25.7). Nothing fills it yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Identity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) descr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) location: Option<String>,
}

/// The identity of an entry: its MAC, or its address when no MAC is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub(crate) enum Key {
    Mac([u8; 6]),
    Ip(IpAddr),
}

/// One device in the inventory.
// The four flags are separate stored facts (ADR-910), not a state machine.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Entry {
    pub(crate) key: Key,
    /// Sorted best first: class, then the newest `seen`. The first is the current address.
    pub(crate) addrs: Vec<Binding>,
    /// Sorted by rank, at most [`MAX_NAMES`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) names: Vec<NameEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) vlan: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) port: Option<String>,
    /// Open TCP ports from imports, at most [`MAX_PORTS`], sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) ports: Vec<u16>,
    /// The OUI vendor from the preset (T25.7 fills it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) vendor: Option<String>,
    /// The LAN or VLAN name the router reports (T25.10, DSC-009).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) network: Option<String>,
    /// The access point the client associates with (T25.10, DSC-009).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ap: Option<String>,
    /// LLDP neighbours, at most [`MAX_LLDP`] (T25.10, DSC-009: a switch's neighbours).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) lldp: Vec<String>,
    /// SNMP identity (T25.7 fills it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) identity: Option<Identity>,
    /// The host answered the `public` community (ADR-909), so the `default_community` finding
    /// applies. T25.9 sets it.
    #[serde(default)]
    pub(crate) default_community: bool,
    /// The sources that currently back the entry (a [`Source::bit`] mask).
    pub(crate) sources: u16,
    /// One bit per import that holds a row for this entry.
    #[serde(default)]
    pub(crate) import_bits: u16,
    pub(crate) first_seen: u64,
    pub(crate) last_seen: u64,
    /// The MAC has the locally administered bit set (ADR-910).
    #[serde(default)]
    pub(crate) randomized: bool,
    /// Two entries claim one address (`ip_conflict`).
    #[serde(default)]
    pub(crate) conflict: bool,
    /// Until when the conflict holds (Unix seconds). It is refreshed by every competing current
    /// claim and cleared only after this time, so a flag survives the polls in between (ADR-923).
    #[serde(default)]
    pub(crate) conflict_until: u64,
    /// The `new_device` finding has been raised for this entry.
    #[serde(default)]
    pub(crate) new_device: bool,
}

impl Entry {
    fn new(key: Key, seen: u64) -> Self {
        Self {
            randomized: matches!(key, Key::Mac(m) if is_randomized(m)),
            key,
            addrs: Vec::new(),
            names: Vec::new(),
            vlan: None,
            port: None,
            ports: Vec::new(),
            vendor: None,
            network: None,
            ap: None,
            lldp: Vec::new(),
            identity: None,
            default_community: false,
            sources: 0,
            import_bits: 0,
            first_seen: seen,
            last_seen: seen,
            conflict: false,
            conflict_until: 0,
            new_device: false,
        }
    }

    /// The MAC, when the entry has one.
    pub(crate) fn mac(&self) -> Option<[u8; 6]> {
        match self.key {
            Key::Mac(m) => Some(m),
            Key::Ip(_) => None,
        }
    }

    /// The current address: the first binding.
    pub(crate) fn current(&self) -> Option<&Binding> {
        self.addrs.first()
    }

    /// The name shown: the best rank.
    pub(crate) fn display_name(&self) -> Option<&NameEntry> {
        self.names.first()
    }

    /// Whether any current (class 1–3) binding exists, so SNMP may poll the entry (ADR-907).
    pub(crate) fn snmp_eligible(&self) -> bool {
        self.addrs.iter().any(Binding::is_current)
    }

    /// Whether only weak sources (the neighbour table, SNMP, history) back the entry.
    pub(crate) fn is_weak_only(&self) -> bool {
        let weak = Source::Neighbor.bit()
            | Source::SnmpArp.bit()
            | Source::Snmp.bit()
            | Source::History.bit();
        (self.sources & !weak) == 0
    }

    fn normalize(&mut self) {
        self.addrs.sort_by(|a, b| {
            a.source
                .order()
                .cmp(&b.source.order())
                .then(b.seen.cmp(&a.seen))
                .then(a.ip.cmp(&b.ip))
        });
        let mut kept: Vec<(IpAddr, Source, Option<u8>)> = Vec::new();
        self.addrs.retain(|b| {
            let k = (b.ip, b.source, b.import_bit);
            if kept.contains(&k) {
                false
            } else {
                kept.push(k);
                true
            }
        });
        // The cap counts distinct addresses: the first [`MAX_ADDRS`] in binding order keep their
        // records, and the rest go.
        let mut ips: Vec<IpAddr> = Vec::new();
        for b in &self.addrs {
            if !ips.contains(&b.ip) {
                ips.push(b.ip);
            }
        }
        ips.truncate(MAX_ADDRS);
        self.addrs.retain(|b| ips.contains(&b.ip));
        self.names.sort_by_key(|n| n.kind.rank());
        self.names.dedup();
        self.names.truncate(MAX_NAMES);
        self.ports.sort_unstable();
        self.ports.dedup();
        self.ports.truncate(MAX_PORTS);
        self.lldp.sort();
        self.lldp.dedup();
        self.lldp.truncate(MAX_LLDP);
        let mut sources = 0u16;
        for b in &self.addrs {
            sources |= b.source.bit();
        }
        for n in &self.names {
            sources |= n.kind.source().bit();
        }
        if self.import_bits != 0 {
            sources |= Source::Import.bit();
        }
        self.sources = sources;
    }

    /// Takes everything another entry for the same device knows.
    fn absorb(&mut self, other: Entry) {
        self.addrs.extend(other.addrs);
        self.names.extend(other.names);
        self.ports.extend(other.ports);
        self.lldp.extend(other.lldp);
        self.vlan = self.vlan.or(other.vlan);
        self.port = self.port.take().or(other.port);
        self.vendor = self.vendor.take().or(other.vendor);
        self.network = self.network.take().or(other.network);
        self.ap = self.ap.take().or(other.ap);
        self.identity = self.identity.take().or(other.identity);
        self.default_community |= other.default_community;
        self.import_bits |= other.import_bits;
        self.first_seen = self.first_seen.min(other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
        self.conflict |= other.conflict;
        self.conflict_until = self.conflict_until.max(other.conflict_until);
        self.new_device |= other.new_device;
        self.randomized |= other.randomized;
        self.normalize();
    }
}

/// The findings an entry can carry (ADR-910). Each can be muted per entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FindingKind {
    IpConflict,
    NewDevice,
    DefaultCommunity,
}

/// A mute on one finding of one entry, optionally until a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Mute {
    pub(crate) key: Key,
    pub(crate) kind: FindingKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) until: Option<u64>,
}

/// One kept import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ImportRecord {
    pub(crate) bit: u8,
    /// When it was merged (Unix seconds).
    pub(crate) at: u64,
    /// Rows it contributed (those with a MAC or an address).
    pub(crate) rows: usize,
    /// A sanitised label, such as the file name.
    pub(crate) label: String,
}

/// One claim from a source, ready to merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    pub(crate) source: Source,
    pub(crate) mac: Option<[u8; 6]>,
    pub(crate) ip: Option<IpAddr>,
    /// The raw device string; sanitised on merge (DSC-015).
    pub(crate) name: Option<(NameKind, String)>,
    /// The `[[router]]` that named it, for router aliases.
    pub(crate) name_origin: Option<String>,
    pub(crate) vlan: Option<u16>,
    pub(crate) port: Option<String>,
    /// Open TCP ports (imports).
    pub(crate) ports: Vec<u16>,
    /// REQ: DSC-009 (T25.10) — the LAN or VLAN name the router reports.
    pub(crate) network: Option<String>,
    /// REQ: DSC-009 — the access point a wireless client is on.
    pub(crate) ap: Option<String>,
    /// REQ: DSC-009 — the LLDP neighbours a switch or access point reports. `Some` replaces the
    /// entry's list (an empty list clears it); `None` leaves it.
    pub(crate) lldp: Option<Vec<String>>,
    /// REQ: DSC-009 — when the router first saw the device (Unix seconds); the entry keeps the
    /// earliest time it has.
    pub(crate) first_seen: Option<u64>,
    /// Unix seconds.
    pub(crate) seen: u64,
}

impl Observation {
    /// An observation with only a source and a time; set the other fields after it.
    pub(crate) fn new(source: Source, seen: u64) -> Self {
        Self {
            source,
            mac: None,
            ip: None,
            name: None,
            name_origin: None,
            vlan: None,
            port: None,
            ports: Vec::new(),
            network: None,
            ap: None,
            lldp: None,
            first_seen: None,
            seen,
        }
    }
}

/// What one merge did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct MergeReport {
    /// Observations merged into an entry.
    pub(crate) merged: usize,
    /// Observations with neither a MAC nor an address.
    pub(crate) dropped: usize,
    /// Entries that raised `new_device` in this merge (the alert uses `source = "inventory"`).
    pub(crate) new_devices: Vec<Key>,
}

/// Why an import was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportError {
    TooManyRows { rows: usize, max: usize },
}

/// The inventory itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Inventory {
    entries: BTreeMap<Key, Entry>,
    imports: Vec<ImportRecord>,
    mutes: Vec<Mute>,
    learning_until: u64,
    dirty: bool,
    /// The stored file could not be read or moved aside, so saving would overwrite the owner's
    /// data. Set by the store; a save is skipped while it holds (DSC-008).
    writes_blocked: bool,
}

/// Whether a MAC is locally administered (the randomised-address bit, ADR-910).
pub(crate) const fn is_randomized(mac: [u8; 6]) -> bool {
    mac[0] & 0x02 != 0
}

/// Cuts a device-supplied string: control characters removed, then cut to `max` bytes on a
/// character boundary (DSC-015). The result is plain text, trimmed.
pub(crate) fn sanitize(raw: &str, max: usize) -> String {
    let mut out = String::new();
    for c in raw.chars().filter(|c| !c.is_control()) {
        let Some(next) = out.len().checked_add(c.len_utf8()) else {
            break;
        };
        if next > max {
            break;
        }
        out.push(c);
    }
    out.trim().to_owned()
}

fn bit16(i: u8) -> u16 {
    1u16.checked_shl(u32::from(i)).unwrap_or(0)
}

/// Clears what an entry holds from imports that are no longer kept (`kept` is their mask).
fn clear_unheld_imports(e: &mut Entry, kept: u16) {
    e.import_bits &= kept;
    e.addrs
        .retain(|b| b.import_bit.is_none_or(|i| kept & bit16(i) != 0));
    if e.import_bits == 0 {
        e.ports.clear();
        e.names.retain(|n| n.kind != NameKind::Import);
    }
    e.normalize();
}

impl Inventory {
    /// An empty inventory that starts its learning period at `now` (ADR-910).
    pub(crate) fn new(now: u64) -> Self {
        Self {
            learning_until: now.saturating_add(LEARNING_SECS),
            ..Self::default()
        }
    }

    /// Rebuilds an inventory from its stored parts. Caps are enforced by dropping the oldest, and
    /// what an import no longer covers is cleared (a stored file is untrusted).
    pub(crate) fn restore(
        entries: Vec<Entry>,
        imports: Vec<ImportRecord>,
        mutes: Vec<Mute>,
        learning_until: u64,
    ) -> Self {
        let mut kept: Vec<ImportRecord> = Vec::new();
        for mut r in imports {
            if usize::from(r.bit) >= MAX_IMPORTS || kept.iter().any(|k| k.bit == r.bit) {
                continue;
            }
            r.label = sanitize(&r.label, NAME_MAX);
            kept.push(r);
        }
        while kept.iter().map(|r| r.rows).sum::<usize>() > MAX_IMPORT_ROWS && kept.len() > 1 {
            drop_oldest_record(&mut kept);
        }
        let skip = mutes.len().saturating_sub(MAX_MUTES);
        let mut inv = Self {
            learning_until,
            mutes: mutes.into_iter().skip(skip).collect(),
            imports: kept,
            ..Self::default()
        };
        let mask = inv.kept_import_mask();
        for mut e in entries {
            clear_unheld_imports(&mut e, mask);
            inv.entries.insert(e.key, e);
        }
        while inv.mac_count() > MAX_MAC_ENTRIES {
            inv.evict_oldest(true);
        }
        while inv.ip_count() > MAX_IP_ONLY_ENTRIES {
            inv.evict_oldest(false);
        }
        inv
    }

    /// Every entry, in key order.
    pub(crate) fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    /// One entry.
    pub(crate) fn get(&self, key: &Key) -> Option<&Entry> {
        self.entries.get(key)
    }

    /// The number of entries.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The kept imports.
    pub(crate) fn imports(&self) -> &[ImportRecord] {
        &self.imports
    }

    /// The mutes.
    pub(crate) fn mutes(&self) -> &[Mute] {
        &self.mutes
    }

    /// When the learning period ends.
    pub(crate) fn learning_until(&self) -> u64 {
        self.learning_until
    }

    /// Whether the learning period is still running at `now`.
    pub(crate) fn learning(&self, now: u64) -> bool {
        now < self.learning_until
    }

    /// Whether anything changed since the last save.
    pub(crate) fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Clears the dirty flag after a save.
    pub(crate) fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// Refuses saves: the stored file is still in place and could not be moved aside.
    pub(crate) fn block_writes(&mut self) {
        self.writes_blocked = true;
    }

    /// Whether saves are refused (see [`Inventory::block_writes`]).
    pub(crate) fn writes_blocked(&self) -> bool {
        self.writes_blocked
    }

    /// Rows held by all kept imports.
    pub(crate) fn import_rows(&self) -> usize {
        self.imports.iter().map(|r| r.rows).sum()
    }

    /// The mask of the kept imports' bits.
    fn kept_import_mask(&self) -> u16 {
        self.imports.iter().fold(0u16, |m, r| m | bit16(r.bit))
    }

    /// Merges observations from a poll or a stream of claims.
    pub(crate) fn apply(&mut self, observations: &[Observation], now: u64) -> MergeReport {
        let mut report = MergeReport::default();
        for o in observations {
            self.merge_one(o, now, None, &mut report);
        }
        if report.merged > 0 {
            self.dirty = true;
        }
        report
    }

    /// Merges one import's rows as one kept import (DSC-010). Rows are claims from source
    /// `Import`: they never replace a current binding (ADR-910). The oldest import goes first
    /// when the import count or the 8,192-row cap would be exceeded.
    pub(crate) fn apply_import(
        &mut self,
        label: &str,
        rows: &[Observation],
        now: u64,
    ) -> Result<(u8, MergeReport), ImportError> {
        if rows.len() > MAX_ROWS_PER_IMPORT {
            return Err(ImportError::TooManyRows {
                rows: rows.len(),
                max: MAX_ROWS_PER_IMPORT,
            });
        }
        let accepted = rows
            .iter()
            .filter(|r| r.mac.is_some() || r.ip.is_some())
            .count();
        if self.imports.len() >= MAX_IMPORTS {
            self.drop_oldest_import();
        }
        let bit = (0..u8::try_from(MAX_IMPORTS).unwrap_or(u8::MAX))
            .find(|b| self.imports.iter().all(|r| r.bit != *b))
            .unwrap_or(0);
        self.imports.push(ImportRecord {
            bit,
            at: now,
            rows: accepted,
            label: sanitize(label, NAME_MAX),
        });
        while self.import_rows() > MAX_IMPORT_ROWS && self.imports.len() > 1 {
            self.drop_oldest_import();
        }
        let mut report = MergeReport::default();
        for r in rows {
            let mut claim = r.clone();
            claim.source = Source::Import;
            self.merge_one(&claim, now, Some(bit), &mut report);
        }
        self.dirty = true;
        Ok((bit, report))
    }

    fn drop_oldest_import(&mut self) {
        if let Some(oldest) = self.imports.iter().min_by_key(|r| r.at).map(|r| r.bit) {
            self.remove_import(oldest);
        }
    }

    /// Deletes one import: its rows, its ports, and entries left empty (DSC-010).
    pub(crate) fn remove_import(&mut self, bit: u8) -> bool {
        let Some(pos) = self.imports.iter().position(|r| r.bit == bit) else {
            return false;
        };
        self.imports.remove(pos);
        let mask = self.kept_import_mask();
        for e in self.entries.values_mut() {
            clear_unheld_imports(e, mask);
        }
        self.entries
            .retain(|_, e| !(e.addrs.is_empty() && e.import_bits == 0 && e.names.is_empty()));
        self.dirty = true;
        true
    }

    /// Drops the bindings a source has not refreshed for `max_age` seconds. Callers pass
    /// twice the source's poll interval, so one missed poll does not drop a host (DSC-004).
    pub(crate) fn expire_source(&mut self, source: Source, now: u64, max_age: u64) {
        let mut changed = false;
        for e in self.entries.values_mut() {
            let before = e.addrs.len();
            e.addrs
                .retain(|b| !(b.source == source && b.seen.saturating_add(max_age) < now));
            // REQ: DSC-009 - history's names go with its last address (ADR-912).
            let mut names_gone = false;
            if source == Source::History && !e.addrs.iter().any(|b| b.source == Source::History) {
                let names = e.names.len();
                e.names.retain(|n| n.kind != NameKind::History);
                names_gone = e.names.len() != names;
            }
            if e.addrs.len() != before || names_gone {
                changed = true;
                e.normalize();
            }
        }
        if changed {
            self.dirty = true;
        }
    }

    /// The retention pass (ADR-910): imports past `import_retention_secs` go, entries with no
    /// address or import that have not been seen for `retention_secs` go, a conflict that no
    /// longer holds is cleared, and mutes of gone entries or expired mutes are pruned.
    pub(crate) fn sweep(&mut self, now: u64, retention_secs: u64, import_retention_secs: u64) {
        let expired: Vec<u8> = self
            .imports
            .iter()
            .filter(|r| r.at.saturating_add(import_retention_secs) < now)
            .map(|r| r.bit)
            .collect();
        for bit in expired {
            self.remove_import(bit);
        }
        // REQ: DSC-008 — a conflict clears only after its hold has passed with no competing
        // current claim (ADR-923). The displaced claim is gone from the address at once, so a
        // count of owners would clear the flag in the same tick that set it.
        let mut changed = false;
        for e in self.entries.values_mut() {
            if e.conflict && e.conflict_until < now {
                e.conflict = false;
                e.conflict_until = 0;
                changed = true;
            }
        }
        let before = self.entries.len();
        self.entries.retain(|_, e| {
            !(e.addrs.is_empty()
                && e.import_bits == 0
                && e.last_seen.saturating_add(retention_secs) < now)
        });
        let entries = &self.entries;
        let mutes_before = self.mutes.len();
        self.mutes
            .retain(|m| entries.contains_key(&m.key) && m.until.is_none_or(|u| u > now));
        if changed || self.entries.len() != before || self.mutes.len() != mutes_before {
            self.dirty = true;
        }
    }

    /// Whether a current (class 1–3) binding has `ip`, so SNMP may poll it (ADR-907, DSC-005).
    pub(crate) fn snmp_eligible_address(&self, ip: IpAddr) -> bool {
        self.entries
            .values()
            .any(|e| e.addrs.iter().any(|b| b.ip == ip && b.is_current()))
    }

    /// The findings on an entry that no mute hides at `now`.
    pub(crate) fn visible_findings(&self, key: &Key, now: u64) -> Vec<FindingKind> {
        let Some(e) = self.entries.get(key) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if e.conflict {
            out.push(FindingKind::IpConflict);
        }
        if e.new_device {
            out.push(FindingKind::NewDevice);
        }
        if e.default_community {
            out.push(FindingKind::DefaultCommunity);
        }
        out.retain(|k| !self.muted(key, *k, now));
        out
    }

    fn muted(&self, key: &Key, kind: FindingKind, now: u64) -> bool {
        self.mutes
            .iter()
            .any(|m| m.key == *key && m.kind == kind && m.until.is_none_or(|u| u > now))
    }

    /// Mutes one finding on one entry, replacing an earlier mute of the same finding. At most
    /// [`MAX_MUTES`] are kept; the oldest goes first.
    pub(crate) fn mute(&mut self, key: Key, kind: FindingKind, until: Option<u64>) {
        self.mutes.retain(|m| !(m.key == key && m.kind == kind));
        while self.mutes.len() >= MAX_MUTES {
            self.mutes.remove(0);
        }
        self.mutes.push(Mute { key, kind, until });
        self.dirty = true;
    }

    /// Removes a mute. Returns whether one existed.
    pub(crate) fn unmute(&mut self, key: &Key, kind: FindingKind) -> bool {
        let before = self.mutes.len();
        self.mutes.retain(|m| !(m.key == *key && m.kind == kind));
        let removed = self.mutes.len() != before;
        if removed {
            self.dirty = true;
        }
        removed
    }

    fn mac_count(&self) -> usize {
        self.entries
            .keys()
            .filter(|k| matches!(k, Key::Mac(_)))
            .count()
    }

    fn ip_count(&self) -> usize {
        self.entries
            .keys()
            .filter(|k| matches!(k, Key::Ip(_)))
            .count()
    }

    /// Drops the entry of one kind (MAC or IP-only) that was seen least recently.
    fn evict_oldest(&mut self, mac_kind: bool) {
        let victim = self
            .entries
            .iter()
            .filter(|(k, _)| matches!(k, Key::Mac(_)) == mac_kind)
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(k, _)| *k);
        if let Some(k) = victim {
            self.entries.remove(&k);
        }
    }

    /// The MAC entry that owns `a` for a claim with no MAC (ADR-910, ADR-923). A MAC entry that
    /// holds `a` as a current binding wins. Otherwise a MAC entry that holds `a` from the same
    /// source takes it, so a device's own record of the address (for example its mDNS record)
    /// does not split into an IP-only duplicate after the router binding expires.
    fn current_owner(&self, a: IpAddr, source: Source) -> Option<Key> {
        let mut same_source = None;
        for (k, e) in &self.entries {
            if !matches!(k, Key::Mac(_)) {
                continue;
            }
            if e.addrs.iter().any(|b| b.ip == a && b.is_current()) {
                return Some(*k);
            }
            if same_source.is_none() && e.addrs.iter().any(|b| b.ip == a && b.source == source) {
                same_source = Some(*k);
            }
        }
        same_source
    }

    fn merge_one(
        &mut self,
        o: &Observation,
        now: u64,
        import_bit: Option<u8>,
        report: &mut MergeReport,
    ) {
        let mac = o.mac.filter(|m| *m != [0; 6]);
        let ip = o.ip.filter(|a| !a.is_unspecified());
        let key = match (mac, ip) {
            (Some(m), _) => Key::Mac(m),
            // REQ: DSC-008 — a MAC-less claim for an address a MAC entry holds attaches to it.
            (None, Some(a)) => self.current_owner(a, o.source).unwrap_or(Key::Ip(a)),
            (None, None) => {
                report.dropped = report.dropped.saturating_add(1);
                return;
            }
        };
        let mac_kind = matches!(key, Key::Mac(_));
        let existing = self.entries.remove(&key);
        let created = existing.is_none();
        let mut entry = if let Some(e) = existing {
            e
        } else {
            if mac_kind && self.mac_count() >= MAX_MAC_ENTRIES {
                self.evict_oldest(true);
            }
            if !mac_kind && self.ip_count() >= MAX_IP_ONLY_ENTRIES {
                self.evict_oldest(false);
            }
            Entry::new(key, o.seen)
        };
        // REQ: DSC-008 — an IP-only entry is the same device once a MAC names its address,
        // whether or not the MAC entry is new (ADR-910).
        if let (Key::Mac(_), Some(a)) = (key, ip)
            && let Some(ip_only) = self.entries.remove(&Key::Ip(a))
        {
            entry.absorb(ip_only);
        }
        // A MAC seen for the first time after the learning period raises new_device once.
        // Randomised MACs raise none (ADR-910: no stable-identity finding for them).
        // REQ: DSC-009 (ADR-912) — a client UniFi remembers from before is history, not a new
        // device: its first sight here raises no `new_device`.
        if created
            && mac_kind
            && !entry.randomized
            && !self.learning(now)
            && !entry.new_device
            && o.source != Source::History
        {
            entry.new_device = true;
            report.new_devices.push(key);
        }
        self.fold(&mut entry, o, import_bit, ip);
        self.entries.insert(key, entry);
        report.merged = report.merged.saturating_add(1);
    }

    /// Folds one observation into an entry the merge owns.
    fn fold(
        &mut self,
        entry: &mut Entry,
        o: &Observation,
        import_bit: Option<u8>,
        ip: Option<IpAddr>,
    ) {
        if let Some(a) = ip {
            // IP-only entries are not devices, so they take part in no conflict (DSC-008).
            if matches!(entry.key, Key::Mac(_)) {
                self.resolve_conflicts(entry, a, o);
            }
            // REQ: DSC-008 — a source refreshes only its own record of an address; another
            // source's record of the same address keeps its own age, so it can expire.
            match entry
                .addrs
                .iter_mut()
                .find(|x| x.ip == a && x.source == o.source && x.import_bit == import_bit)
            {
                Some(ex) => ex.seen = ex.seen.max(o.seen),
                None => entry.addrs.push(Binding {
                    ip: a,
                    source: o.source,
                    seen: o.seen,
                    import_bit,
                }),
            }
        }
        if let Some((kind, raw)) = &o.name {
            let label = sanitize(raw, NAME_MAX);
            if !label.is_empty() {
                let origin = o.name_origin.as_deref().map(|s| sanitize(s, NAME_MAX));
                // REQ: DSC-008 — a name from the same kind and origin replaces the old one.
                match entry
                    .names
                    .iter_mut()
                    .find(|n| n.kind == *kind && n.origin == origin)
                {
                    Some(n) => n.label = label,
                    None => entry.names.push(NameEntry {
                        kind: *kind,
                        label,
                        origin,
                    }),
                }
            }
        }
        if o.vlan.is_some() {
            entry.vlan = o.vlan;
        }
        if let Some(p) = o
            .port
            .as_ref()
            .map(|p| sanitize(p, NAME_MAX))
            .filter(|p| !p.is_empty())
        {
            entry.port = Some(p);
        }
        for p in &o.ports {
            if entry.ports.len() < MAX_PORTS {
                entry.ports.push(*p);
            }
        }
        // REQ: DSC-009 (T25.10) — the router's network, access point and LLDP view, cut as every
        // device string is (DSC-015).
        if let Some(n) = o
            .network
            .as_ref()
            .map(|n| sanitize(n, NAME_MAX))
            .filter(|n| !n.is_empty())
        {
            entry.network = Some(n);
        }
        if let Some(a) =
            o.ap.as_ref()
                .map(|a| sanitize(a, NAME_MAX))
                .filter(|a| !a.is_empty())
        {
            entry.ap = Some(a);
        }
        if let Some(list) = &o.lldp {
            entry.lldp = list
                .iter()
                .map(|l| sanitize(l, TEXT_MAX))
                .filter(|l| !l.is_empty())
                .collect();
        }
        if let Some(f) = o.first_seen.filter(|f| *f > 0) {
            entry.first_seen = entry.first_seen.min(f);
        }
        if let Some(b) = import_bit {
            entry.import_bits |= bit16(b);
        }
        entry.first_seen = entry.first_seen.min(o.seen);
        entry.last_seen = entry.last_seen.max(o.seen);
        entry.normalize();
        self.dirty = true;
    }

    /// Same address, different MAC: the newest current (class 1–3) claim wins, and both entries
    /// are flagged for [`CONFLICT_HOLD_SECS`] after this claim (ADR-923). A claim of class 4 or 5,
    /// or from an unclassed source, neither displaces a current binding nor raises a conflict:
    /// it is history or a claim, not a current owner (ADR-910, ADR-923).
    fn resolve_conflicts(&mut self, entry: &mut Entry, a: IpAddr, o: &Observation) {
        if !o.source.is_current() {
            return;
        }
        let hold = o.seen.saturating_add(CONFLICT_HOLD_SECS);
        for other in self.entries.values_mut() {
            // REQ: DSC-008 — only MAC entries are devices; IP-only entries take no part.
            if !matches!(other.key, Key::Mac(_)) {
                continue;
            }
            let Some(other_seen) = other
                .addrs
                .iter()
                .filter(|b| b.ip == a && b.is_current())
                .map(|b| b.seen)
                .max()
            else {
                continue;
            };
            entry.conflict = true;
            entry.conflict_until = entry.conflict_until.max(hold);
            other.conflict = true;
            other.conflict_until = other.conflict_until.max(hold);
            if o.seen >= other_seen {
                other.addrs.retain(|b| !(b.ip == a && b.is_current()));
                other.normalize();
            }
        }
    }
}

/// Drops the record of the import that was merged first.
fn drop_oldest_record(imports: &mut Vec<ImportRecord>) {
    if let Some(pos) = imports
        .iter()
        .enumerate()
        .min_by_key(|(_, r)| r.at)
        .map(|(i, _)| i)
    {
        imports.remove(pos);
    }
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;

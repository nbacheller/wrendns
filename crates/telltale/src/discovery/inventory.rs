//! The network inventory's data model and merge (DSC-008, ADR-910).
//!
//! One entry per MAC, with at most four address bindings, ranked names, a source mask and the
//! import rows it holds. A result with no MAC goes to an IP-only entry keyed by its address.
//! This module does no I/O and reads no clock: callers pass `now` in Unix seconds, so the
//! merge can be tested and fuzzed. Nothing here reaches DNS, policy, client matching or
//! `identify` (ADR-910; the test `dsc_008_never_in_neighbors_or_leases` guards that).

use std::collections::{BTreeMap, HashMap};
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
/// Address bindings per entry (DSC-008).
pub(crate) const MAX_ADDRS: usize = 4;
/// Display names per entry.
pub(crate) const MAX_NAMES: usize = 4;
/// Open TCP ports per entry, from imports (ADR-910).
pub(crate) const MAX_PORTS: usize = 16;
/// The learning period after the first enable or an empty start (ADR-910).
pub(crate) const LEARNING_SECS: u64 = 24 * 3600;
/// Names are cut to this many bytes (DSC-015).
pub(crate) const NAME_MAX: usize = 64;
/// Other device strings are cut to this many bytes (DSC-015).
pub(crate) const TEXT_MAX: usize = 255;

/// Where an observation came from. The class decides which address a MAC currently uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Source {
    /// UniFi clients and reservations, OPNsense leases, and the `[[router]]` answers.
    Router,
    /// Home Assistant's device registry and trackers.
    HomeAssistant,
    /// The local kernel neighbour table, filtered (ADR-910).
    Neighbor,
    /// ARP from a listed infrastructure agent (DSC-004; not polled before T25.6).
    SnmpArp,
    /// Passive mDNS announcements.
    Mdns,
    /// SNMP identity (sysName and friends); carries names, not addresses.
    Snmp,
    /// A scan the owner uploaded (ADR-913).
    Import,
    /// UniFi `stat/alluser` `last_ip`: history only, never current (ADR-912).
    History,
    /// The configured client name. Attaches to entries; never creates one.
    Config,
}

impl Source {
    /// The precedence class of an address from this source (ADR-910). Lower is better; classes
    /// 1–3 are current bindings, 4 and 5 are claims.
    pub(crate) const fn class(self) -> u8 {
        match self {
            Self::Router => 1,
            Self::HomeAssistant | Self::Neighbor | Self::Mdns => 2,
            Self::SnmpArp | Self::Snmp | Self::Config => 3,
            Self::Import => 4,
            Self::History => 5,
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
        }
    }
}

/// One address a source reported for an entry.
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
    /// The precedence class of this binding.
    pub(crate) const fn class(&self) -> u8 {
        self.source.class()
    }
}

/// A display name with its kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NameEntry {
    pub(crate) kind: NameKind,
    pub(crate) label: String,
}

/// The identity of an entry: its MAC, or its address when no MAC is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub(crate) enum Key {
    Mac([u8; 6]),
    Ip(IpAddr),
}

/// One device in the inventory.
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
            sources: 0,
            import_bits: 0,
            first_seen: seen,
            last_seen: seen,
            conflict: false,
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
        self.addrs.iter().any(|b| b.class() <= 3)
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
            a.class()
                .cmp(&b.class())
                .then(b.seen.cmp(&a.seen))
                .then(a.ip.cmp(&b.ip))
        });
        let mut seen_ips: Vec<IpAddr> = Vec::new();
        self.addrs.retain(|b| {
            if seen_ips.contains(&b.ip) {
                false
            } else {
                seen_ips.push(b.ip);
                true
            }
        });
        self.addrs.truncate(MAX_ADDRS);
        self.names.sort_by_key(|n| n.kind.rank());
        self.names.dedup();
        self.names.truncate(MAX_NAMES);
        self.ports.sort_unstable();
        self.ports.dedup();
        self.ports.truncate(MAX_PORTS);
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
        self.vlan = self.vlan.or(other.vlan);
        self.port = self.port.take().or(other.port);
        self.import_bits |= other.import_bits;
        self.first_seen = self.first_seen.min(other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
        self.conflict |= other.conflict;
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
    pub(crate) vlan: Option<u16>,
    pub(crate) port: Option<String>,
    /// Open TCP ports (imports).
    pub(crate) ports: Vec<u16>,
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
            vlan: None,
            port: None,
            ports: Vec::new(),
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

impl Inventory {
    /// An empty inventory that starts its learning period at `now` (ADR-910).
    pub(crate) fn new(now: u64) -> Self {
        Self {
            learning_until: now.saturating_add(LEARNING_SECS),
            ..Self::default()
        }
    }

    /// Rebuilds an inventory from its stored parts. Caps are enforced by dropping the oldest.
    pub(crate) fn restore(
        entries: Vec<Entry>,
        imports: Vec<ImportRecord>,
        mutes: Vec<Mute>,
        learning_until: u64,
    ) -> Self {
        let mut inv = Self {
            learning_until,
            mutes,
            imports: imports.into_iter().take(MAX_IMPORTS).collect(),
            ..Self::default()
        };
        for mut e in entries {
            e.normalize();
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

    /// Rows held by all kept imports.
    pub(crate) fn import_rows(&self) -> usize {
        self.imports.iter().map(|r| r.rows).sum()
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
        let mask = bit16(bit);
        for e in self.entries.values_mut() {
            e.import_bits &= !mask;
            e.addrs.retain(|b| b.import_bit != Some(bit));
            if e.import_bits == 0 {
                e.ports.clear();
                e.names.retain(|n| n.kind != NameKind::Import);
            }
            e.normalize();
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
            if e.addrs.len() != before {
                changed = true;
                e.normalize();
            }
        }
        if changed {
            self.dirty = true;
        }
    }

    /// The retention pass (ADR-910): imports past `import_retention_secs` go, entries with no
    /// address or import that have not been seen for `retention_secs` go, and a conflict that
    /// no longer holds is cleared.
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
        let mut owners: HashMap<IpAddr, usize> = HashMap::new();
        for e in self.entries.values() {
            for b in e.addrs.iter().filter(|b| b.class() <= 3) {
                let n = owners.entry(b.ip).or_insert(0);
                *n = n.saturating_add(1);
            }
        }
        let mut changed = false;
        for e in self.entries.values_mut() {
            if e.conflict {
                e.conflict = e
                    .addrs
                    .iter()
                    .any(|b| b.class() <= 3 && owners.get(&b.ip).copied().unwrap_or(0) > 1);
                changed = true;
            }
        }
        let before = self.entries.len();
        self.entries.retain(|_, e| {
            !(e.addrs.is_empty()
                && e.import_bits == 0
                && e.last_seen.saturating_add(retention_secs) < now)
        });
        if changed || self.entries.len() != before {
            self.dirty = true;
        }
    }

    /// Whether a current (class 1–3) binding has `ip`, so SNMP may poll it (ADR-907, DSC-005).
    pub(crate) fn snmp_eligible_address(&self, ip: IpAddr) -> bool {
        self.entries
            .values()
            .any(|e| e.addrs.iter().any(|b| b.ip == ip && b.class() <= 3))
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
        out.retain(|k| !self.muted(key, *k, now));
        out
    }

    fn muted(&self, key: &Key, kind: FindingKind, now: u64) -> bool {
        self.mutes
            .iter()
            .any(|m| m.key == *key && m.kind == kind && m.until.is_none_or(|u| u > now))
    }

    /// Mutes one finding on one entry, replacing an earlier mute of the same finding.
    pub(crate) fn mute(&mut self, key: Key, kind: FindingKind, until: Option<u64>) {
        self.mutes.retain(|m| !(m.key == key && m.kind == kind));
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
            (None, Some(a)) => Key::Ip(a),
            (None, None) => {
                report.dropped = report.dropped.saturating_add(1);
                return;
            }
        };
        if let Some(mut entry) = self.entries.remove(&key) {
            self.fold(&mut entry, o, import_bit, ip);
            self.entries.insert(key, entry);
            report.merged = report.merged.saturating_add(1);
            return;
        }
        let mut entry = Entry::new(key, o.seen);
        // An IP-only entry becomes the MAC's entry when the MAC arrives.
        if let (Key::Mac(_), Some(a)) = (key, ip)
            && let Some(ip_only) = self.entries.remove(&Key::Ip(a))
        {
            entry.absorb(ip_only);
        }
        let mac_kind = matches!(key, Key::Mac(_));
        if mac_kind && self.mac_count() >= MAX_MAC_ENTRIES {
            self.evict_oldest(true);
        }
        if !mac_kind && self.ip_count() >= MAX_IP_ONLY_ENTRIES {
            self.evict_oldest(false);
        }
        // A MAC seen for the first time after the learning period raises new_device once.
        // Randomised MACs raise none (ADR-910: no stable-identity finding for them).
        if mac_kind && !entry.randomized && !self.learning(now) && !entry.new_device {
            entry.new_device = true;
            report.new_devices.push(key);
        }
        self.fold(&mut entry, o, import_bit, ip);
        self.entries.insert(key, entry);
        report.merged = report.merged.saturating_add(1);
    }

    /// Folds one observation into an entry the merge owns.
    fn fold(&mut self, entry: &mut Entry, o: &Observation, import_bit: Option<u8>, ip: Option<IpAddr>) {
        if let Some(a) = ip {
            self.resolve_conflicts(entry, a, o);
            let b = Binding {
                ip: a,
                source: o.source,
                seen: o.seen,
                import_bit,
            };
            if let Some(ex) = entry.addrs.iter_mut().find(|x| x.ip == a) {
                if b.class() <= ex.class() {
                    ex.source = b.source;
                    ex.import_bit = b.import_bit;
                }
                ex.seen = ex.seen.max(b.seen);
            } else {
                entry.addrs.push(b);
            }
        }
        if let Some((kind, raw)) = &o.name {
            let label = sanitize(raw, NAME_MAX);
            if !label.is_empty() {
                let name = NameEntry {
                    kind: *kind,
                    label,
                };
                if !entry.names.contains(&name) {
                    entry.names.push(name);
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
        if let Some(b) = import_bit {
            entry.import_bits |= bit16(b);
        }
        entry.first_seen = entry.first_seen.min(o.seen);
        entry.last_seen = entry.last_seen.max(o.seen);
        entry.normalize();
        self.dirty = true;
    }

    /// Same address, different MAC: the newest class 1–3 claim wins, and both entries are
    /// flagged. A claim of class 4 or 5 never displaces a class 1–3 binding (ADR-910).
    fn resolve_conflicts(&mut self, entry: &mut Entry, a: IpAddr, o: &Observation) {
        let class = o.source.class();
        for (k, other) in &mut self.entries {
            if *k == entry.key {
                continue;
            }
            let Some(pos) = other
                .addrs
                .iter()
                .position(|b| b.ip == a && b.class() <= 3)
            else {
                continue;
            };
            let other_seen = other.addrs.get(pos).map_or(0, |b| b.seen);
            entry.conflict = true;
            other.conflict = true;
            if class <= 3 && o.seen >= other_seen {
                other.addrs.remove(pos);
            }
        }
    }
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;

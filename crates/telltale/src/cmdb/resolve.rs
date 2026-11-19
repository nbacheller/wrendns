//! REQ: DSC-903 (T31.2, ADR-1004 section 4) - reconciliation as a pure function of the records.
//!
//! The records that share a key (a MAC, a serial, a stable device key) are applied **in a
//! canonical order** (oldest `first_seen`, then source, then key), never in the order they
//! arrived, so the same records give the same groups whatever order their batches came in (the
//! property test `dsc_903_any_order_gives_the_same_links`).
//!
//! One MAC is one device until a serial, a stable device key or a person says otherwise: a
//! record's claims join the groups they point at. Two groups are **not** joined when that would
//! give one device two serials or two keys of one scope (they are two devices), or would join a
//! manually pinned group to an unpinned one or to another pinned one (a manual decision wins).
//! Such a record joins nothing at the device level, stays on its own interface's device, and is
//! reported as a disagreement, which the engine raises as a merge proposal and never applies
//! (the level disagreement of ADR-1004 section 4, `dsc_903_level_disagreement_proposes_merge`).
//!
//! This module reads no database and no clock.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::model::devkey_scope;

/// The evidence one record gives, with its place in the canonical order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ev {
    pub(crate) rid: i64,
    pub(crate) first_seen: i64,
    pub(crate) source: String,
    pub(crate) skey: String,
    pub(crate) mac: Option<String>,
    pub(crate) serial: Option<String>,
    pub(crate) devkey: Option<String>,
}

/// Which rule linked a record at the device level (ADR-1004 section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// A manual link or merge (R1).
    Manual,
    /// The MAC (R2).
    Mac,
    /// The serial (R3).
    Serial,
    /// A stable device key (R4).
    DeviceKey,
}

impl Rule {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Mac => "auto:R2",
            Self::Serial => "auto:R3",
            Self::DeviceKey => "auto:R4",
        }
    }
}

/// Records that belong together: the interfaces (MACs) and the keys one device holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Group {
    /// A stable name for ordering: the smallest claim in the group.
    pub(crate) key: String,
    pub(crate) rids: Vec<i64>,
    pub(crate) macs: BTreeSet<String>,
    pub(crate) serials: BTreeSet<String>,
    pub(crate) devkeys: BTreeSet<String>,
    /// The device CI the owner pinned MACs of this group to.
    pub(crate) anchors: BTreeSet<String>,
}

/// A record whose claims point at more than one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Disagreement {
    pub(crate) rid: i64,
    /// Indexes into [`Resolution::groups`], at least two.
    pub(crate) groups: Vec<usize>,
}

/// The result of a resolution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Resolution {
    pub(crate) groups: Vec<Group>,
    /// The group of each record (`None`: linked to nothing at the device level).
    pub(crate) group_of: HashMap<i64, Option<usize>>,
    pub(crate) rule_of: HashMap<i64, Rule>,
    pub(crate) disagreements: Vec<Disagreement>,
}

#[derive(Default, Clone)]
struct Info {
    serial: Option<String>,
    scopes: BTreeMap<String, String>,
    anchor: Option<String>,
}

struct Uf {
    parent: Vec<usize>,
    info: Vec<Info>,
}

impl Uf {
    fn new() -> Self {
        Self {
            parent: Vec::new(),
            info: Vec::new(),
        }
    }

    fn add(&mut self) -> usize {
        let n = self.parent.len();
        self.parent.push(n);
        self.info.push(Info::default());
        n
    }

    fn find(&mut self, x: usize) -> usize {
        let mut r = x;
        while let Some(p) = self.parent.get(r).copied().filter(|p| *p != r) {
            r = p;
        }
        let mut c = x;
        while let Some(p) = self.parent.get(c).copied().filter(|p| *p != r && *p != c) {
            if let Some(slot) = self.parent.get_mut(c) {
                *slot = r;
            }
            c = p;
        }
        r
    }

    fn info(&self, root: usize) -> Info {
        self.info.get(root).cloned().unwrap_or_default()
    }

    fn union(&mut self, a: usize, b: usize) -> usize {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra == rb {
            return ra;
        }
        // The smaller index survives, so the result does not depend on the order of unions.
        let (keep, gone) = if ra < rb { (ra, rb) } else { (rb, ra) };
        if let Some(p) = self.parent.get_mut(gone) {
            *p = keep;
        }
        let g = self
            .info
            .get_mut(gone)
            .map(std::mem::take)
            .unwrap_or_default();
        if let Some(k) = self.info.get_mut(keep) {
            if k.serial.is_none() {
                k.serial = g.serial;
            }
            for (s, v) in g.scopes {
                k.scopes.entry(s).or_insert(v);
            }
            if k.anchor.is_none() {
                k.anchor = g.anchor;
            }
        }
        keep
    }
}

fn node_of(uf: &mut Uf, ids: &mut HashMap<String, usize>, key: &str) -> usize {
    if let Some(n) = ids.get(key) {
        return *n;
    }
    let n = uf.add();
    ids.insert(key.to_owned(), n);
    n
}

/// Whether the groups `roots` may become one, and a record's new strong claims may join them.
fn compatible(
    uf: &Uf,
    roots: &BTreeSet<usize>,
    serial: Option<&String>,
    devkey: Option<&String>,
) -> bool {
    let infos: Vec<Info> = roots.iter().map(|r| uf.info(*r)).collect();
    if infos.len() >= 2 {
        let anchored = infos.iter().filter(|i| i.anchor.is_some()).count();
        if anchored != 0 {
            // A pinned group is not joined to another group by evidence: a manual decision wins.
            return false;
        }
    }
    let serials: BTreeSet<&String> = infos.iter().filter_map(|i| i.serial.as_ref()).collect();
    if serials.len() >= 2 {
        return false;
    }
    if let (Some(have), Some(new)) = (serials.iter().next(), serial)
        && *have != new
    {
        return false;
    }
    let mut by_scope: BTreeMap<&str, BTreeSet<&String>> = BTreeMap::new();
    for i in &infos {
        for (s, v) in &i.scopes {
            by_scope.entry(s.as_str()).or_default().insert(v);
        }
    }
    if by_scope.values().any(|v| v.len() >= 2) {
        return false;
    }
    if let Some(k) = devkey
        && let Some(have) = by_scope.get(devkey_scope(k))
        && !have.contains(k)
    {
        return false;
    }
    true
}

/// Resolves `evs` against the owner's pins (`nic_pins`: a MAC to the device CI it is pinned to).
/// Only the pins of MACs the records carry matter.
#[allow(clippy::too_many_lines)] // one pass: the pins, the canonical order, then the groups
pub(crate) fn resolve(evs: &[Ev], nic_pins: &HashMap<String, String>) -> Resolution {
    let mut order: Vec<&Ev> = evs.iter().collect();
    order.sort_by(|a, b| {
        (a.first_seen, &a.source, &a.skey, a.rid).cmp(&(b.first_seen, &b.source, &b.skey, b.rid))
    });
    let mut uf = Uf::new();
    let mut ids: HashMap<String, usize> = HashMap::new();
    let macs: BTreeSet<&str> = evs.iter().filter_map(|e| e.mac.as_deref()).collect();
    // The pins first: a pinned MAC and its device are one node. One device is one anchor: pins to
    // the same CI join their MACs.
    let mut pins: Vec<(&String, &String)> = nic_pins.iter().collect();
    pins.sort();
    for (mac, ci) in pins {
        if !macs.contains(mac.as_str()) {
            continue;
        }
        let m = node_of(&mut uf, &mut ids, &format!("m:{mac}"));
        let p = node_of(&mut uf, &mut ids, &format!("p:{ci}"));
        let root = uf.union(m, p);
        if let Some(i) = uf.info.get_mut(root) {
            i.anchor = Some(ci.clone());
        }
    }
    let mut skipped: Vec<(i64, Vec<usize>)> = Vec::new();
    for ev in &order {
        // A pinned interface is where the owner put it: its records give the MAC and nothing
        // that could pull other records into its device, or it into another.
        let pinned = ev.mac.as_ref().is_some_and(|m| nic_pins.contains_key(m));
        let mut claims: Vec<String> = Vec::new();
        if let Some(m) = &ev.mac {
            claims.push(format!("m:{m}"));
        }
        if !pinned && let Some(s) = &ev.serial {
            claims.push(format!("s:{s}"));
        }
        if !pinned && let Some(k) = &ev.devkey {
            claims.push(format!("k:{k}"));
        }
        if claims.is_empty() {
            continue;
        }
        let known: Vec<usize> = claims.iter().filter_map(|c| ids.get(c).copied()).collect();
        let mut roots: BTreeSet<usize> = BTreeSet::new();
        for n in &known {
            roots.insert(uf.find(*n));
        }
        // Claims whose node does not exist yet are new strong claims for the merged group.
        let new_serial = ev
            .serial
            .as_ref()
            .filter(|s| !pinned && !ids.contains_key(&format!("s:{s}")));
        let new_key = ev
            .devkey
            .as_ref()
            .filter(|k| !pinned && !ids.contains_key(&format!("k:{k}")));
        if !compatible(&uf, &roots, new_serial, new_key) {
            // The record's MAC is still an interface of its own.
            if let Some(m) = &ev.mac {
                node_of(&mut uf, &mut ids, &format!("m:{m}"));
            }
            skipped.push((ev.rid, known));
            continue;
        }
        let nodes: Vec<usize> = claims
            .iter()
            .map(|c| node_of(&mut uf, &mut ids, c))
            .collect();
        let mut root = nodes.first().copied().unwrap_or(0);
        for n in nodes.iter().skip(1) {
            root = uf.union(root, *n);
        }
        let root = uf.find(root);
        if let Some(i) = uf.info.get_mut(root) {
            if let Some(s) = ev.serial.as_ref().filter(|_| !pinned)
                && i.serial.is_none()
            {
                i.serial = Some(s.clone());
            }
            if let Some(k) = ev.devkey.as_ref().filter(|_| !pinned) {
                i.scopes
                    .entry(devkey_scope(k).to_owned())
                    .or_insert_with(|| k.clone());
            }
        }
    }
    // The groups: one per root that holds a node.
    let mut by_root: BTreeMap<usize, Group> = BTreeMap::new();
    let mut names: Vec<(&String, &usize)> = ids.iter().collect();
    names.sort();
    for (key, node) in names {
        let root = uf.find(*node);
        let g = by_root.entry(root).or_default();
        if g.key.is_empty() || key.as_str() < g.key.as_str() {
            g.key.clone_from(key);
        }
        if let Some(m) = key.strip_prefix("m:") {
            g.macs.insert(m.to_owned());
        } else if let Some(s) = key.strip_prefix("s:") {
            g.serials.insert(s.to_owned());
        } else if let Some(k) = key.strip_prefix("k:") {
            g.devkeys.insert(k.to_owned());
        } else if let Some(c) = key.strip_prefix("p:") {
            g.anchors.insert(c.to_owned());
        }
    }
    let mut groups: Vec<(usize, Group)> = by_root.into_iter().collect();
    groups.sort_by(|a, b| a.1.key.cmp(&b.1.key));
    let index: HashMap<usize, usize> = groups
        .iter()
        .enumerate()
        .map(|(i, (root, _))| (*root, i))
        .collect();
    let mut out = Resolution::default();
    for ev in &order {
        let mut roots: BTreeSet<usize> = BTreeSet::new();
        for (prefix, val) in [
            ("m:", ev.mac.as_ref()),
            ("s:", ev.serial.as_ref()),
            ("k:", ev.devkey.as_ref()),
        ] {
            if let Some(v) = val
                && let Some(n) = ids.get(&format!("{prefix}{v}"))
            {
                roots.insert(uf.find(*n));
            }
        }
        // A record with a MAC belongs to its interface's device. One without joins the group its
        // claims agree on, or none when they point at several.
        let group = match (&ev.mac, roots.len()) {
            (Some(m), _) => ids.get(&format!("m:{m}")).map(|n| uf.find(*n)),
            (None, 1) => roots.iter().next().copied(),
            _ => None,
        }
        .and_then(|r| index.get(&r).copied());
        out.group_of.insert(ev.rid, group);
        let rule = match (&ev.mac, &ev.serial, &ev.devkey) {
            (Some(m), _, _) if nic_pins.contains_key(m) => Rule::Manual,
            (_, Some(_), _) => Rule::Serial,
            (_, None, Some(_)) => Rule::DeviceKey,
            _ => Rule::Mac,
        };
        out.rule_of.insert(ev.rid, rule);
    }
    for (rid, known) in skipped {
        let mut gs: BTreeSet<usize> = BTreeSet::new();
        for n in known {
            let r = uf.find(n);
            if let Some(i) = index.get(&r) {
                gs.insert(*i);
            }
        }
        if gs.len() >= 2 {
            out.disagreements.push(Disagreement {
                rid,
                groups: gs.into_iter().collect(),
            });
        }
    }
    let mut rids: Vec<Vec<i64>> = vec![Vec::new(); groups.len()];
    for (rid, g) in &out.group_of {
        if let Some(v) = g.and_then(|i| rids.get_mut(i)) {
            v.push(*rid);
        }
    }
    for ((_, mut g), mut r) in groups.into_iter().zip(rids) {
        r.sort_unstable();
        g.rids = r;
        out.groups.push(g);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(rid: i64, at: i64, mac: Option<&str>, serial: Option<&str>, key: Option<&str>) -> Ev {
        Ev {
            rid,
            first_seen: at,
            source: format!("s{rid}"),
            skey: format!("k{rid}"),
            mac: mac.map(str::to_owned),
            serial: serial.map(str::to_owned),
            devkey: key.map(str::to_owned),
        }
    }

    fn partition(r: &Resolution, evs: &[Ev]) -> Vec<Vec<i64>> {
        let mut by: BTreeMap<Option<usize>, Vec<i64>> = BTreeMap::new();
        for e in evs {
            by.entry(r.group_of.get(&e.rid).copied().flatten())
                .or_default()
                .push(e.rid);
        }
        let mut out: Vec<Vec<i64>> = by.into_values().collect();
        for g in &mut out {
            g.sort_unstable();
        }
        out.sort();
        out
    }

    /// REQ: DSC-903 - one MAC is one interface, and a serial joins interfaces into one device.
    #[test]
    fn dsc_903_mac_then_serial_join() {
        let evs = vec![
            ev(1, 1, Some("aa:00:00:00:00:01"), None, None),
            ev(2, 2, Some("aa:00:00:00:00:02"), None, None),
            ev(3, 3, Some("aa:00:00:00:00:01"), Some("sn-0001"), None),
            ev(4, 4, Some("aa:00:00:00:00:02"), Some("sn-0001"), None),
        ];
        let r = resolve(&evs, &HashMap::new());
        assert_eq!(partition(&r, &evs), vec![vec![1, 2, 3, 4]]);
        assert_eq!(r.groups.len(), 1);
        assert_eq!(r.groups[0].macs.len(), 2);
        assert_eq!(r.rule_of[&3], Rule::Serial);
        assert_eq!(r.rule_of[&1], Rule::Mac);
    }

    /// REQ: DSC-903 - a record whose MAC belongs to one device and whose serial to another joins
    /// nothing at the device level and is a disagreement (each device has its own serial).
    #[test]
    fn dsc_903_level_disagreement_is_reported_not_merged() {
        let evs = vec![
            ev(1, 1, Some("aa:00:00:00:00:01"), Some("sn-0001"), None),
            ev(2, 2, Some("aa:00:00:00:00:02"), Some("sn-0002"), None),
            ev(3, 3, Some("aa:00:00:00:00:01"), Some("sn-0002"), None),
        ];
        let r = resolve(&evs, &HashMap::new());
        assert_eq!(r.groups.len(), 2, "the two devices stay two");
        assert_eq!(r.disagreements.len(), 1);
        assert_eq!(r.disagreements[0].rid, 3);
        assert_eq!(r.disagreements[0].groups.len(), 2);
        // Record 3 stays on its interface's device.
        assert_eq!(r.group_of[&3], r.group_of[&1]);
    }

    /// REQ: DSC-903 - two serials in one group are a contradiction, not a merge.
    #[test]
    fn dsc_903_two_serials_do_not_join() {
        let evs = vec![
            ev(1, 1, Some("aa:00:00:00:00:01"), Some("sn-0001"), None),
            ev(2, 2, Some("aa:00:00:00:00:01"), Some("sn-0002"), None),
        ];
        let r = resolve(&evs, &HashMap::new());
        assert_eq!(r.groups.len(), 1);
        assert_eq!(
            r.groups[0].serials.len(),
            1,
            "the later serial is not taken"
        );
    }

    /// REQ: DSC-903 - a stable device key joins a device's interfaces, and a key of the same scope
    /// with another value is a contradiction.
    #[test]
    fn dsc_903_device_key_joins_and_scopes_conflict() {
        let evs = vec![
            ev(1, 1, Some("aa:00:00:00:00:01"), None, Some("ha:home|dev1")),
            ev(2, 2, Some("aa:00:00:00:00:02"), None, Some("ha:home|dev1")),
            ev(
                3,
                3,
                Some("aa:00:00:00:00:03"),
                None,
                Some("snmp:sw|device"),
            ),
            ev(4, 4, Some("aa:00:00:00:00:02"), None, Some("ha:home|dev2")),
        ];
        let r = resolve(&evs, &HashMap::new());
        assert_eq!(r.group_of[&1], r.group_of[&2]);
        assert_ne!(r.group_of[&1], r.group_of[&3]);
        assert_eq!(r.rule_of[&1], Rule::DeviceKey);
        assert!(r.groups.iter().all(|g| !g.devkeys.contains("ha:home|dev2")));
    }

    /// REQ: DSC-903 - a pin keeps a MAC with its device whatever a serial says: the pinned group
    /// is not joined to an unpinned one by evidence, and its records claim nothing for others to join.
    #[test]
    fn dsc_903_a_pin_is_not_overridden_by_a_serial() {
        let evs = vec![
            ev(1, 1, Some("aa:00:00:00:00:01"), Some("sn-0001"), None),
            ev(2, 2, Some("aa:00:00:00:00:02"), Some("sn-0001"), None),
        ];
        let pins: HashMap<String, String> = [("aa:00:00:00:00:02".to_owned(), "ci_x".to_owned())]
            .into_iter()
            .collect();
        let r = resolve(&evs, &pins);
        assert_eq!(r.groups.len(), 2, "the pinned interface stays apart");
        assert!(r.groups.iter().any(|g| g.anchors.contains("ci_x")));
        assert_eq!(r.rule_of[&2], Rule::Manual);
        assert!(
            r.disagreements.is_empty(),
            "the owner decided: nothing is asked again"
        );
        assert!(
            r.groups.iter().any(|g| g.serials.contains("sn-0001")),
            "the other keeps the serial"
        );
    }

    /// REQ: DSC-903 (`dsc_903_any_order_gives_the_same_links`, the pure half) - the groups do not
    /// depend on the order the records are listed in.
    #[test]
    fn dsc_903_listing_order_does_not_matter() {
        let evs = vec![
            ev(1, 1, Some("aa:00:00:00:00:01"), None, None),
            ev(2, 2, Some("aa:00:00:00:00:02"), Some("sn-0002"), None),
            ev(3, 3, Some("aa:00:00:00:00:01"), Some("sn-0003"), None),
            ev(
                4,
                4,
                Some("aa:00:00:00:00:03"),
                Some("sn-0003"),
                Some("k|a"),
            ),
            ev(5, 5, None, Some("sn-0003"), None),
            ev(6, 6, Some("aa:00:00:00:00:01"), Some("sn-0002"), None),
        ];
        let base = resolve(&evs, &HashMap::new());
        let mut rev = evs.clone();
        rev.reverse();
        let r2 = resolve(&rev, &HashMap::new());
        assert_eq!(partition(&base, &evs), partition(&r2, &evs));
        assert_eq!(base.disagreements, r2.disagreements);
    }
}

//! REQ: DSC-902, DSC-903, DSC-906 (T31.2, ADR-1004 section 4, ADR-1005 sections 3 and 5) - applies
//! a resolution to the registry: interface CIs by MAC, device CIs by the groups [`resolve`] made,
//! natural-key CIs (network, node, service, upstream), keyless records, port CIs, merge proposals,
//! and the caps. One call per ingested batch, inside the batch's transaction, over the connected
//! components of the records that changed: a component is every record that shares a MAC, a serial
//! or a device key with another, so the work is bounded by the change, not by the database.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde_json::{Map, Value};
use telltale_store::cmdb::{
    CiRow, CmdbError, FLAG_UNCONFIRMED, FLAG_UNMAPPED_PORT, Ops, Pin, RecordRow, RecordWrite,
    SeenRow,
};

use super::model::{
    ALIAS_SECS, Caps, RecKind, is_presence, kind_of, name_rank, new_ci_id, trailing_number,
};
use super::resolve::{Ev, Resolution, resolve};

type Result<T> = std::result::Result<T, CmdbError>;

/// The keys of records that changed, which is where resolution starts.
#[derive(Debug, Default, Clone)]
pub(crate) struct Seeds {
    pub(crate) macs: BTreeSet<String>,
    pub(crate) serials: BTreeSet<String>,
    pub(crate) devkeys: BTreeSet<String>,
    /// Natural keys (networks, nodes, services, upstreams).
    pub(crate) natural: BTreeSet<String>,
    /// Port owners (the device keys the port records name).
    pub(crate) owners: BTreeSet<String>,
    /// Addresses of changed records: keyless records that hold one are looked at again.
    pub(crate) addrs: BTreeSet<String>,
    /// Keyless records that changed themselves.
    pub(crate) keyless: BTreeSet<i64>,
}

impl Seeds {
    /// The keys a record about to be written carries.
    pub(crate) fn add_write(&mut self, w: &RecordWrite, rid: i64) {
        self.add_parts(
            &w.ty,
            w.mac.as_ref(),
            w.serial.as_ref(),
            w.devkey.as_ref(),
            w.owner.as_ref(),
            rid,
        );
        for (ip, _) in &w.addrs {
            self.addrs.insert(ip.clone());
        }
    }

    /// The keys a stored record carries (an old version, or a record that is going away).
    pub(crate) fn add_row(&mut self, r: &RecordRow) {
        self.add_parts(
            &r.ty,
            r.mac.as_ref(),
            r.serial.as_ref(),
            r.devkey.as_ref(),
            r.owner.as_ref(),
            r.rid,
        );
    }

    fn add_parts(
        &mut self,
        ty: &str,
        mac: Option<&String>,
        serial: Option<&String>,
        devkey: Option<&String>,
        owner: Option<&String>,
        rid: i64,
    ) {
        match RecKind::parse(ty) {
            Some(RecKind::Device) => {
                if mac.is_none() && serial.is_none() && devkey.is_none() {
                    self.keyless.insert(rid);
                }
                self.macs.extend(mac.cloned());
                self.serials.extend(serial.cloned());
                self.devkeys.extend(devkey.cloned());
            }
            Some(RecKind::Port) => {
                self.owners.extend(owner.cloned());
            }
            Some(_) => {
                self.natural.extend(devkey.cloned());
            }
            None => {}
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.macs.is_empty()
            && self.serials.is_empty()
            && self.devkeys.is_empty()
            && self.natural.is_empty()
            && self.owners.is_empty()
            && self.addrs.is_empty()
            && self.keyless.is_empty()
    }
}

/// What the engine passes in and takes out of one application.
pub(crate) struct Cx<'a> {
    pub(crate) ops: &'a Ops<'a>,
    pub(crate) now: i64,
    pub(crate) caps: Caps,
    pub(crate) ci_total: i64,
    pub(crate) dropped_ci: u64,
    pub(crate) created: u64,
    pub(crate) merged: u64,
    pub(crate) proposals: u64,
    /// Proposals raised in this pass; open ones about the same CIs that are not here have ended.
    pub(crate) raised: HashSet<(String, String, String)>,
    /// Device CIs this pass touched (resolved, or got a keyless record).
    pub(crate) devices: BTreeSet<String>,
    /// Device CIs whose whole component this pass resolved: only these have their open proposals
    /// compared with what the pass raised.
    pub(crate) resolved: BTreeSet<String>,
    /// Devices a resolved group named as a candidate (they may have been merged, split or emptied):
    /// the keyless records on them are looked at again.
    pub(crate) candidates: BTreeSet<String>,
    /// CIs whose last-seen the engine should refresh.
    pub(crate) pins: Option<Vec<Pin>>,
}

impl<'a> Cx<'a> {
    pub(crate) fn new(ops: &'a Ops<'a>, now: i64, caps: Caps) -> Result<Self> {
        Ok(Self {
            ops,
            now,
            caps,
            ci_total: ops.ci_count(None)?,
            dropped_ci: 0,
            created: 0,
            merged: 0,
            proposals: 0,
            raised: HashSet::new(),
            devices: BTreeSet::new(),
            resolved: BTreeSet::new(),
            candidates: BTreeSet::new(),
            pins: None,
        })
    }

    fn pins(&mut self) -> Result<Vec<Pin>> {
        if self.pins.is_none() {
            self.pins = Some(self.ops.pins()?);
        }
        Ok(self.pins.clone().unwrap_or_default())
    }
}

fn attrs_of(r: &RecordRow) -> Map<String, Value> {
    serde_json::from_str::<Value>(&r.attrs)
        .ok()
        .and_then(|v| match v {
            Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default()
}

fn attr_text(r: &RecordRow, name: &str) -> Option<String> {
    attrs_of(r)
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
}

/// A source whose records confirm a thing exists: a presence source (class 1 to 3), or a source
/// that declares it (the configuration, a person, the cluster, Kubernetes).
pub(crate) fn confirming(source: &str) -> bool {
    is_presence(source) || matches!(kind_of(source), "config" | "manual" | "cluster" | "k8s")
}

/// The name shown for a device: the best rank among its records' names (ADR-910's order is the
/// built-in default precedence, T31.3 makes it configurable), then the host name.
fn best_name(recs: &[&RecordRow]) -> Option<String> {
    let mut best: Option<(u8, &str, &str, String)> = None;
    for r in recs {
        let Some(n) = attr_text(r, "name").or_else(|| attr_text(r, "hostname")) else {
            continue;
        };
        let rank = name_rank(&r.source);
        let cand = (rank, r.source.as_str(), r.skey.as_str(), n);
        if best
            .as_ref()
            .is_none_or(|b| (cand.0, cand.1, cand.2) < (b.0, b.1, b.2))
        {
            best = Some(cand);
        }
    }
    best.map(|b| b.3)
}

fn live_device(ops: &Ops<'_>, id: &str) -> Result<Option<CiRow>> {
    Ok(ops.ci_get(id)?.filter(|c| c.ty == "device"))
}

/// Makes room for and writes a new CI, or counts the refusal (ADR-1005 section 3).
fn new_ci(cx: &mut Cx<'_>, row: &CiRow) -> Result<bool> {
    if cx.ci_total >= cx.caps.cis {
        let mut freed = false;
        for id in cx.ops.ci_eviction_candidates(64)? {
            if !cx.ops.ci_authored(&id)? && !cx.devices.contains(&id) {
                cx.ops.ci_delete(&id)?;
                cx.ci_total = cx.ci_total.saturating_sub(1);
                freed = true;
                break;
            }
        }
        if !freed {
            cx.dropped_ci = cx.dropped_ci.saturating_add(1);
            return Ok(false);
        }
    }
    cx.ops.ci_put(row)?;
    cx.ops.seen_put(
        &row.id,
        SeenRow {
            last_seen: cx.now,
            days_seen: 0,
            day: 0,
        },
    )?;
    cx.ci_total = cx.ci_total.saturating_add(1);
    cx.created = cx.created.saturating_add(1);
    Ok(true)
}

fn proposal(cx: &mut Cx<'_>, kind: &str, a: &str, b: &str, rule: &str, detail: &str) -> Result<()> {
    if a == b {
        return Ok(());
    }
    let (x, y) = if a <= b { (a, b) } else { (b, a) };
    cx.ops.proposal_raise(kind, x, y, rule, detail, cx.now)?;
    cx.raised
        .insert((kind.to_owned(), x.to_owned(), y.to_owned()));
    cx.proposals = cx.proposals.saturating_add(1);
    Ok(())
}

// -- components --------------------------------------------------------------------------------

/// Everything the records of a component say, with the pins that matter.
struct Component {
    recs: BTreeMap<i64, RecordRow>,
    nic_pins: HashMap<String, String>,
}

/// The records that share a key with the seeds, and with each other, transitively.
fn component(
    cx: &mut Cx<'_>,
    macs: &BTreeSet<String>,
    serials: &BTreeSet<String>,
    devkeys: &BTreeSet<String>,
) -> Result<Component> {
    let all_pins: Vec<Pin> = cx.pins()?;
    let explicit: HashMap<String, String> = all_pins
        .iter()
        .filter(|p| p.kind == "nic_device")
        .map(|p| (p.a.clone(), p.b.clone()))
        .collect();
    let mut recs: BTreeMap<i64, RecordRow> = BTreeMap::new();
    let (mut pm, mut ps, mut pk) = (macs.clone(), serials.clone(), devkeys.clone());
    let (mut km, mut ks, mut kk): (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) =
        (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    let mut implied: HashMap<String, String> = HashMap::new();
    loop {
        let qm: Vec<String> = pm.difference(&km).cloned().collect();
        let qs: Vec<String> = ps.difference(&ks).cloned().collect();
        let qk: Vec<String> = pk.difference(&kk).cloned().collect();
        if qm.is_empty() && qs.is_empty() && qk.is_empty() {
            break;
        }
        km.extend(qm.iter().cloned());
        ks.extend(qs.iter().cloned());
        kk.extend(qk.iter().cloned());
        // A pinned device keeps all its interfaces in one group: the MACs it already holds and the
        // ones pinned to it join the closure.
        for m in &qm {
            let Some(target) = explicit.get(m) else {
                continue;
            };
            let Some(live) = cx.ops.resolve_id(target, cx.now)? else {
                continue;
            };
            for child in cx.ops.ci_children(&live)? {
                if let Some(cm) = cx.ops.mac_of(&child.id)? {
                    if !explicit.contains_key(&cm) {
                        implied.insert(cm.clone(), live.clone());
                    }
                    pm.insert(cm);
                }
            }
            for p in all_pins.iter().filter(|p| p.kind == "nic_device" && &p.b == target) {
                pm.insert(p.a.clone());
            }
        }
        for row in cx.ops.records_by_keys(&qm, &qs, &qk)? {
            if row.ty != "device" || recs.contains_key(&row.rid) {
                continue;
            }
            pm.extend(row.mac.clone());
            ps.extend(row.serial.clone());
            pk.extend(row.devkey.clone());
            recs.insert(row.rid, row);
        }
    }
    let mut nic_pins = implied;
    nic_pins.extend(explicit);
    Ok(Component { recs, nic_pins })
}

fn ev_of(r: &RecordRow) -> Ev {
    Ev {
        rid: r.rid,
        first_seen: r.first_seen,
        source: r.source.clone(),
        skey: r.skey.clone(),
        mac: r.mac.clone(),
        serial: r.serial.clone(),
        devkey: r.devkey.clone(),
    }
}

// -- the registry ------------------------------------------------------------------------------

/// The interface CI of a MAC, made if there is none. `None` when the CI cap refused it.
fn nic_ci(cx: &mut Cx<'_>, mac: &str, first_seen: i64) -> Result<Option<String>> {
    if let Some(id) = cx.ops.key_find("mac", mac)?.into_iter().next() {
        return Ok(Some(id));
    }
    let row = CiRow {
        id: new_ci_id(),
        ty: "interface".to_owned(),
        kind: Some("nic".to_owned()),
        name: Some(mac.to_owned()),
        parent: None,
        flags: 0,
        first_seen,
    };
    if !new_ci(cx, &row)? {
        return Ok(None);
    }
    cx.ops.key_add("mac", mac, &row.id)?;
    Ok(Some(row.id))
}

/// Folds one device CI into another (ADR-1004 section 2: a merge moves interfaces and leaves the
/// loser's id as an alias that redirects for 90 days).
pub(crate) fn merge_ci(cx: &mut Cx<'_>, loser: &str, survivor: &str) -> Result<()> {
    if loser == survivor {
        return Ok(());
    }
    let ops = cx.ops;
    for child in ops.ci_children(loser)? {
        if child.kind.as_deref() == Some("port") {
            // Its ports are made again from the port records, under the survivor.
            ops.ci_delete(&child.id)?;
            cx.ci_total = cx.ci_total.saturating_sub(1);
            continue;
        }
        ops.ci_put(&CiRow {
            parent: Some(survivor.to_owned()),
            ..child
        })?;
    }
    for (kind, value) in ops.keys_of(loser)? {
        ops.key_add(&kind, &value, survivor)?;
        ops.key_del(&kind, &value, loser)?;
    }
    if let (Some(l), Some(s)) = (ops.ci_get(loser)?, ops.ci_get(survivor)?)
        && l.first_seen < s.first_seen
    {
        ops.ci_put(&CiRow {
            first_seen: l.first_seen,
            ..s
        })?;
    }
    ops.seen_merge(loser, survivor)?;
    ops.records_relink_device(loser, survivor)?;
    ops.pins_retarget(loser, survivor)?;
    ops.proposals_retarget(loser, survivor)?;
    ops.alias_set(loser, survivor, cx.now.saturating_add(ALIAS_SECS))?;
    ops.ci_delete(loser)?;
    cx.ci_total = cx.ci_total.saturating_sub(1);
    cx.merged = cx.merged.saturating_add(1);
    Ok(())
}

// -- devices -----------------------------------------------------------------------------------

struct Plan {
    nics: Vec<(String, Option<String>)>,
    cands: BTreeSet<String>,
    /// The candidates found through a serial or a device key (not through an interface's parent).
    keyed: BTreeSet<String>,
    forced: Option<String>,
}

/// Resolves the device components of the seeds and applies them. Returns the device CIs resolved.
fn resolve_devices(cx: &mut Cx<'_>, seeds: &Seeds) -> Result<()> {
    let mut done_m: BTreeSet<String> = BTreeSet::new();
    let mut done_s: BTreeSet<String> = BTreeSet::new();
    let mut done_k: BTreeSet<String> = BTreeSet::new();
    loop {
        let m: BTreeSet<String> = seeds
            .macs
            .difference(&done_m)
            .take(128)
            .cloned()
            .collect();
        let s: BTreeSet<String> = seeds
            .serials
            .difference(&done_s)
            .take(128)
            .cloned()
            .collect();
        let k: BTreeSet<String> = seeds
            .devkeys
            .difference(&done_k)
            .take(128)
            .cloned()
            .collect();
        if m.is_empty() && s.is_empty() && k.is_empty() {
            break;
        }
        let comp = component(cx, &m, &s, &k)?;
        done_m.extend(m);
        done_s.extend(s);
        done_k.extend(k);
        for r in comp.recs.values() {
            done_m.extend(r.mac.clone());
            done_s.extend(r.serial.clone());
            done_k.extend(r.devkey.clone());
        }
        if comp.recs.is_empty() {
            continue;
        }
        let evs: Vec<Ev> = comp.recs.values().map(ev_of).collect();
        let res = resolve(&evs, &comp.nic_pins);
        apply_groups(cx, &res, &comp)?;
    }
    Ok(())
}

fn apply_groups(cx: &mut Cx<'_>, res: &Resolution, comp: &Component) -> Result<()> {
    let now = cx.now;
    let mut plans: Vec<Plan> = Vec::new();
    for g in &res.groups {
        let mut nics: Vec<(String, Option<String>)> = Vec::new();
        for mac in &g.macs {
            let first = comp
                .recs
                .values()
                .filter(|r| r.mac.as_deref() == Some(mac))
                .map(|r| r.first_seen)
                .min()
                .unwrap_or(now);
            let ci = nic_ci(cx, mac, first)?;
            nics.push((mac.clone(), ci));
        }
        let mut cands: BTreeSet<String> = BTreeSet::new();
        let mut keyed: BTreeSet<String> = BTreeSet::new();
        let mut forced = None;
        for a in &g.anchors {
            if let Some(id) = cx.ops.resolve_id(a, now)?
                && live_device(cx.ops, &id)?.is_some()
            {
                forced = Some(id.clone());
                cands.insert(id);
            }
        }
        for (_, ci) in &nics {
            if let Some(ci) = ci
                && let Some(row) = cx.ops.ci_get(ci)?
                && let Some(p) = row.parent
                && live_device(cx.ops, &p)?.is_some()
            {
                cands.insert(p);
            }
        }
        for s in &g.serials {
            for ci in cx.ops.key_find("serial", s)? {
                if live_device(cx.ops, &ci)?.is_some() {
                    keyed.insert(ci.clone());
                    cands.insert(ci);
                }
            }
        }
        for k in &g.devkeys {
            for ci in cx.ops.key_find("devkey", k)? {
                if live_device(cx.ops, &ci)?.is_some() {
                    keyed.insert(ci.clone());
                    cands.insert(ci);
                }
            }
        }
        cx.candidates.extend(cands.iter().cloned());
        plans.push(Plan {
            nics,
            cands,
            keyed,
            forced,
        });
    }
    let mut want: HashMap<String, usize> = HashMap::new();
    for p in &plans {
        for c in &p.cands {
            *want.entry(c.clone()).or_insert(0) += 1;
        }
    }
    let mut order: Vec<usize> = (0..plans.len()).collect();
    order.sort_by(|a, b| {
        let (pa, pb) = (&plans[*a], &plans[*b]);
        (
            pa.forced.is_none(),
            std::cmp::Reverse(pa.nics.len()),
            res.groups.get(*a).map(|g| g.key.as_str()),
        )
            .cmp(&(
                pb.forced.is_none(),
                std::cmp::Reverse(pb.nics.len()),
                res.groups.get(*b).map(|g| g.key.as_str()),
            ))
    });
    let mut claimed: HashSet<String> = HashSet::new();
    let mut claimed_forced: HashSet<String> = HashSet::new();
    let mut survivors: HashMap<usize, Option<String>> = HashMap::new();
    for gi in order {
        let (Some(plan), Some(group)) = (plans.get(gi), res.groups.get(gi)) else {
            continue;
        };
        let members: Vec<&RecordRow> = group
            .rids
            .iter()
            .filter_map(|r| comp.recs.get(r))
            .collect();
        // The survivor: the pinned device, else the oldest candidate nobody else took.
        let survivor: Option<String> = if let Some(f) = &plan.forced {
            Some(f.clone())
        } else {
            let mut avail: Vec<CiRow> = Vec::new();
            for c in &plan.cands {
                // A device the owner pinned interfaces to may still take an interface that a
                // serial or a key points at (a new interface of that device).
                let open = !claimed.contains(c)
                    || (claimed_forced.contains(c) && plan.keyed.contains(c));
                if open && let Some(row) = cx.ops.ci_get(c)? {
                    avail.push(row);
                }
            }
            avail.sort_by(|a, b| (a.first_seen, &a.id).cmp(&(b.first_seen, &b.id)));
            avail.first().map(|c| c.id.clone())
        };
        let first_seen = members
            .iter()
            .map(|r| r.first_seen)
            .min()
            .unwrap_or(now);
        let name = best_name(&members);
        let unconfirmed = !members.iter().any(|r| confirming(&r.source));
        let survivor = match survivor {
            Some(s) => s,
            None => {
                if !plan.nics.is_empty() && plan.nics.iter().all(|(_, c)| c.is_none()) {
                    // Every interface was refused by the CI cap: nothing to hold a device.
                    survivors.insert(gi, None);
                    continue;
                }
                let row = CiRow {
                    id: new_ci_id(),
                    ty: "device".to_owned(),
                    kind: None,
                    name: name
                        .clone()
                        .or_else(|| group.macs.iter().next().cloned()),
                    parent: None,
                    flags: if unconfirmed { FLAG_UNCONFIRMED } else { 0 },
                    first_seen,
                };
                if !new_ci(cx, &row)? {
                    survivors.insert(gi, None);
                    continue;
                }
                row.id
            }
        };
        claimed.insert(survivor.clone());
        if plan.forced.is_some() {
            claimed_forced.insert(survivor.clone());
        }
        // Candidates only this group wants are the same device now: merge them in.
        for c in &plan.cands {
            if *c != survivor && !claimed.contains(c) && want.get(c).copied() == Some(1) {
                claimed.insert(c.clone());
                merge_ci(cx, c, &survivor)?;
            }
        }
        // The device's row: its name, its flags and its keys.
        if let Some(row) = cx.ops.ci_get(&survivor)? {
            let want_name = name.clone().or_else(|| row.name.clone());
            let flags = if unconfirmed {
                row.flags | FLAG_UNCONFIRMED
            } else {
                row.flags & !FLAG_UNCONFIRMED
            };
            if row.name != want_name || row.flags != flags {
                cx.ops.ci_put(&CiRow {
                    name: want_name,
                    flags,
                    ..row
                })?;
            }
        }
        for s in &group.serials {
            cx.ops.key_add("serial", s, &survivor)?;
        }
        for k in &group.devkeys {
            cx.ops.key_add("devkey", k, &survivor)?;
        }
        for (_, ci) in &plan.nics {
            let Some(ci) = ci else { continue };
            if let Some(row) = cx.ops.ci_get(ci)?
                && row.parent.as_deref() != Some(survivor.as_str())
            {
                cx.ops.ci_put(&CiRow {
                    parent: Some(survivor.clone()),
                    ..row
                })?;
            }
        }
        cx.devices.insert(survivor.clone());
        cx.resolved.insert(survivor.clone());
        survivors.insert(gi, Some(survivor));
    }
    // The links of every record of the component.
    let nic_of: HashMap<&str, &Option<String>> = plans
        .iter()
        .flat_map(|p| p.nics.iter().map(|(m, c)| (m.as_str(), c)))
        .collect();
    for (rid, rec) in &comp.recs {
        let ici = rec
            .mac
            .as_deref()
            .and_then(|m| nic_of.get(m))
            .and_then(|c| c.as_deref());
        let group = res.group_of.get(rid).copied().flatten();
        let dci = group
            .and_then(|g| survivors.get(&g))
            .and_then(|s| s.as_deref());
        let rule = res
            .rule_of
            .get(rid)
            .map_or("auto:R2", |r| if dci.is_some() { r.label() } else { "none" });
        cx.ops.record_link(*rid, ici, dci, rule)?;
    }
    // Disagreements: proposed, never applied.
    for d in &res.disagreements {
        let ids: Vec<String> = d
            .groups
            .iter()
            .filter_map(|g| survivors.get(g).and_then(Clone::clone))
            .collect();
        let rec = comp.recs.get(&d.rid);
        let detail = rec.map_or_else(String::new, |r| {
            format!(
                "the record {}/{} points at both devices (its MAC at one, its serial or device key at the other)",
                r.source, r.skey
            )
        });
        let rule = rec.map_or("R3", |r| {
            if r.serial.is_some() {
                "R3"
            } else {
                "R4"
            }
        });
        for (i, a) in ids.iter().enumerate() {
            for b in ids.iter().skip(i.saturating_add(1)) {
                proposal(cx, "level_disagreement", a, b, rule, &detail)?;
            }
        }
    }
    host_network_proposals(cx, comp, res, &survivors)?;
    Ok(())
}

/// Rule R5: a host name and a network shared with exactly one other device propose a merge. It is
/// never applied (owner question 12).
fn host_network_proposals(
    cx: &mut Cx<'_>,
    comp: &Component,
    res: &Resolution,
    survivors: &HashMap<usize, Option<String>>,
) -> Result<()> {
    for (rid, rec) in &comp.recs {
        let (Some(host), Some(net)) = (&rec.host, &rec.net) else {
            continue;
        };
        let Some(own) = res
            .group_of
            .get(rid)
            .copied()
            .flatten()
            .and_then(|g| survivors.get(&g))
            .and_then(Clone::clone)
        else {
            continue;
        };
        let mut others: BTreeSet<String> = BTreeSet::new();
        for o in cx.ops.records_by_hostnet(host, net)? {
            if let Some(d) = o.dci
                && d != own
            {
                others.insert(d);
            }
        }
        if others.len() != 1 {
            continue;
        }
        let Some(other) = others.into_iter().next() else {
            continue;
        };
        let serial_of = |ci: &str| -> Result<Option<String>> {
            Ok(cx
                .ops
                .keys_of(ci)?
                .into_iter()
                .find(|(k, _)| k == "serial")
                .map(|(_, v)| v))
        };
        if let (Some(a), Some(b)) = (serial_of(&own)?, serial_of(&other)?)
            && a != b
        {
            continue;
        }
        proposal(
            cx,
            "host_network",
            &own,
            &other,
            "R5",
            &format!("the host name `{host}` on the network `{net}` appears on both devices"),
        )?;
    }
    Ok(())
}

// -- natural-key CIs ---------------------------------------------------------------------------

fn apply_natural(cx: &mut Cx<'_>, keys: &BTreeSet<String>) -> Result<()> {
    for key in keys {
        let recs = records_with_devkey(cx.ops, key)?;
        let Some(first) = recs.first() else {
            continue;
        };
        let Some(kind) = RecKind::parse(&first.ty) else {
            continue;
        };
        let ty = kind.ci_type();
        let ci = match cx
            .ops
            .key_find(ty, key)?
            .into_iter()
            .find(|c| cx.ops.ci_get(c).ok().flatten().is_some())
        {
            Some(c) => c,
            None => {
                let row = CiRow {
                    id: new_ci_id(),
                    ty: ty.to_owned(),
                    kind: None,
                    name: None,
                    parent: None,
                    flags: 0,
                    first_seen: recs.iter().map(|r| r.first_seen).min().unwrap_or(cx.now),
                };
                if !new_ci(cx, &row)? {
                    continue;
                }
                cx.ops.key_add(ty, key, &row.id)?;
                row.id
            }
        };
        let refs: Vec<&RecordRow> = recs.iter().collect();
        let name = best_name(&refs).or_else(|| Some(key.clone()));
        if let Some(row) = cx.ops.ci_get(&ci)?
            && row.name != name
        {
            cx.ops.ci_put(&CiRow { name, ..row })?;
        }
        for r in &recs {
            cx.ops.record_link(r.rid, None, Some(&ci), "auto:key")?;
        }
    }
    Ok(())
}

fn records_with_devkey(ops: &Ops<'_>, key: &str) -> Result<Vec<RecordRow>> {
    Ok(ops
        .records_by_keys(&[], &[], &[key.to_owned()])?
        .into_iter()
        .filter(|r| r.ty != "device" && r.ty != "port")
        .collect())
}

// -- keyless records ---------------------------------------------------------------------------

/// A record with no MAC, serial or device key attaches through a class 1 to 3 address binding, or
/// becomes a CI of its own that is `unconfirmed` (ADR-1004 section 4, ADR-923). A pin overrides.
fn attach_keyless(cx: &mut Cx<'_>, rid: i64) -> Result<()> {
    let Some(rec) = cx.ops.record_by_id(rid)? else {
        return Ok(());
    };
    if rec.ty != "device" || rec.mac.is_some() || rec.serial.is_some() || rec.devkey.is_some() {
        return Ok(());
    }
    let pin_key = format!("{}\x1f{}", rec.source, rec.skey);
    let pins: Vec<Pin> = cx
        .pins()?
        .into_iter()
        .filter(|p| p.a == pin_key && (p.kind == "rec_device" || p.kind == "rec_never"))
        .collect();
    // R1: a manual link wins.
    if let Some(p) = pins.iter().find(|p| p.kind == "rec_device")
        && let Some(id) = cx.ops.resolve_id(&p.b, cx.now)?
        && live_device(cx.ops, &id)?.is_some()
    {
        return relink_keyless(cx, &rec, Some(&id), "manual");
    }
    let never: BTreeSet<String> = pins
        .iter()
        .filter(|p| p.kind == "rec_never")
        .map(|p| p.b.clone())
        .collect();
    let mut targets: BTreeSet<String> = BTreeSet::new();
    if !never.contains("*") {
        for ip in cx.ops.addrs_of(rec.rid)? {
            for (holder, cls) in cx.ops.addr_holders(&ip)? {
                if cls > 3 || holder.rid == rec.rid {
                    continue;
                }
                if let Some(d) = holder.dci
                    && !never.contains(&d)
                {
                    targets.insert(d);
                }
            }
        }
    }
    match targets.len() {
        1 => {
            let id = targets.into_iter().next();
            relink_keyless(cx, &rec, id.as_deref(), "auto:addr")
        }
        0 => {
            // Its own CI, unconfirmed.
            let key = pin_key.clone();
            let existing = cx
                .ops
                .key_find("recdev", &key)?
                .into_iter()
                .find(|c| cx.ops.ci_get(c).ok().flatten().is_some());
            let id = match existing {
                Some(id) => id,
                None => {
                    let row = CiRow {
                        id: new_ci_id(),
                        ty: "device".to_owned(),
                        kind: None,
                        name: attr_text(&rec, "name").or_else(|| attr_text(&rec, "hostname")),
                        parent: None,
                        flags: FLAG_UNCONFIRMED,
                        first_seen: rec.first_seen,
                    };
                    if !new_ci(cx, &row)? {
                        return Ok(());
                    }
                    cx.ops.key_add("recdev", &key, &row.id)?;
                    row.id
                }
            };
            relink_keyless(cx, &rec, Some(&id), "auto:own")
        }
        _ => {
            // Ambiguous: unlinked, with a proposal naming the candidates (never a guess).
            let ids: Vec<String> = targets.into_iter().collect();
            relink_keyless(cx, &rec, None, "none")?;
            for (i, a) in ids.iter().enumerate() {
                for b in ids.iter().skip(i.saturating_add(1)) {
                    proposal(
                        cx,
                        "ambiguous_record",
                        a,
                        b,
                        "addr",
                        &format!(
                            "the record {}/{} holds an address that two devices hold",
                            rec.source, rec.skey
                        ),
                    )?;
                }
            }
            Ok(())
        }
    }
}

fn relink_keyless(cx: &mut Cx<'_>, rec: &RecordRow, to: Option<&str>, rule: &str) -> Result<()> {
    let old = rec.dci.clone();
    cx.ops.record_link(rec.rid, None, to, rule)?;
    if let Some(o) = old
        && Some(o.as_str()) != to
    {
        drop_if_empty_unconfirmed(cx, &o)?;
    }
    if let Some(t) = to {
        cx.devices.insert(t.to_owned());
    }
    Ok(())
}

/// A CI made only for a keyless record is removed when its record moves on.
fn drop_if_empty_unconfirmed(cx: &mut Cx<'_>, ci: &str) -> Result<()> {
    let Some(row) = cx.ops.ci_get(ci)? else {
        return Ok(());
    };
    if row.flags & FLAG_UNCONFIRMED != 0
        && cx.ops.record_count_of_ci(ci)? == 0
        && cx.ops.ci_children(ci)?.is_empty()
        && !cx.ops.ci_authored(ci)?
    {
        cx.ops.ci_delete(ci)?;
        cx.ci_total = cx.ci_total.saturating_sub(1);
    }
    Ok(())
}

// -- ports -------------------------------------------------------------------------------------

/// Port records resolve by (device CI, normalised port id) and the alias table; a port seen by one
/// source that no alias joins to another source's port is its own CI marked `unmapped_port`, never
/// a conflict (docs/design/cmdb.md, Port identity).
fn apply_ports(cx: &mut Cx<'_>, owners: &BTreeSet<String>) -> Result<()> {
    let owner_list: Vec<String> = owners.iter().cloned().collect();
    if owner_list.is_empty() {
        return Ok(());
    }
    let mut touched_devices: BTreeSet<String> = BTreeSet::new();
    for rec in cx.ops.records_by_owner(&owner_list)? {
        let (Some(owner), Some(norm)) = (rec.owner.clone(), rec.port.clone()) else {
            continue;
        };
        let device = cx
            .ops
            .key_find("devkey", &owner)?
            .into_iter()
            .find(|c| live_device(cx.ops, c).ok().flatten().is_some());
        let Some(device) = device else {
            cx.ops.record_link(rec.rid, None, None, "none")?;
            continue;
        };
        // Ports are made only for devices a presence source reports (ADR-1004 section 2).
        let has_presence = cx
            .ops
            .records_of_ci(&device)?
            .iter()
            .any(|r| is_presence(&r.source));
        if !has_presence {
            cx.ops.record_link(rec.rid, None, Some(&device), "none")?;
            continue;
        }
        let kind = kind_of(&rec.source).to_owned();
        let raw = attr_text(&rec, "port_id").unwrap_or_else(|| norm.clone());
        let port = match cx.ops.port_alias_get(&device, &kind, &norm)? {
            Some(p) if cx.ops.ci_get(&p)?.is_some() => Some(p),
            _ => {
                let key = format!("{device}|{norm}");
                match cx.ops.key_find("port", &key)?.into_iter().next() {
                    Some(p) => Some(p),
                    None => {
                        let row = CiRow {
                            id: new_ci_id(),
                            ty: "interface".to_owned(),
                            kind: Some("port".to_owned()),
                            name: Some(raw),
                            parent: Some(device.clone()),
                            flags: 0,
                            first_seen: rec.first_seen,
                        };
                        if new_ci(cx, &row)? {
                            cx.ops.key_add("port", &key, &row.id)?;
                            Some(row.id)
                        } else {
                            None
                        }
                    }
                }
            }
        };
        cx.ops
            .record_link(rec.rid, port.as_deref(), Some(&device), "auto:port")?;
        touched_devices.insert(device);
    }
    for d in touched_devices {
        learn_port_aliases(cx, &d)?;
        flag_unmapped_ports(cx, &d)?;
    }
    Ok(())
}

/// An alias is learned only from evidence on the same device: an SNMP `ifName` whose trailing
/// number equals a UniFi `port<idx>`, on a device matched by a serial or a manual link.
fn learn_port_aliases(cx: &mut Cx<'_>, device: &str) -> Result<()> {
    let has_serial = cx
        .ops
        .keys_of(device)?
        .iter()
        .any(|(k, _)| k == "serial");
    let pinned = cx.ops.ci_authored(device)?;
    if !has_serial && !pinned {
        return Ok(());
    }
    let ports = cx.ops.ports_of(device)?;
    // port CI -> (source kinds, normalised ids)
    let mut info: Vec<(CiRow, BTreeSet<String>, BTreeSet<String>)> = Vec::new();
    for p in ports {
        let recs = cx.ops.records_of_ci(&p.id)?;
        let kinds: BTreeSet<String> = recs.iter().map(|r| kind_of(&r.source).to_owned()).collect();
        let ids: BTreeSet<String> = recs.iter().filter_map(|r| r.port.clone()).collect();
        info.push((p, kinds, ids));
    }
    for (u, ukinds, uids) in &info {
        if !ukinds.contains("unifi") || ukinds.contains("snmp") {
            continue;
        }
        let Some(n) = uids
            .iter()
            .find_map(|i| i.strip_prefix("port").and_then(|d| d.parse::<u32>().ok()))
        else {
            continue;
        };
        let cands: Vec<&CiRow> = info
            .iter()
            .filter(|(p, k, ids)| {
                p.id != u.id
                    && k.contains("snmp")
                    && !k.contains("unifi")
                    && ids
                        .iter()
                        .any(|i| !i.starts_with("port") && trailing_number(i) == Some(n))
            })
            .map(|(p, _, _)| p)
            .collect();
        let [winner] = cands.as_slice() else {
            continue;
        };
        for id in uids {
            cx.ops
                .port_alias_set(device, "unifi", id, &winner.id, true)?;
        }
        cx.ops.records_relink_interface(&u.id, &winner.id)?;
        cx.ops.ci_delete(&u.id)?;
        cx.ci_total = cx.ci_total.saturating_sub(1);
    }
    Ok(())
}

fn flag_unmapped_ports(cx: &mut Cx<'_>, device: &str) -> Result<()> {
    let ports = cx.ops.ports_of(device)?;
    let mut kinds_of: Vec<(CiRow, BTreeSet<String>)> = Vec::new();
    let mut all_kinds: BTreeSet<String> = BTreeSet::new();
    for p in ports {
        let k: BTreeSet<String> = cx
            .ops
            .record_sources_of_ci(&p.id)?
            .iter()
            .map(|s| kind_of(s).to_owned())
            .collect();
        all_kinds.extend(k.iter().cloned());
        kinds_of.push((p, k));
    }
    for (p, k) in kinds_of {
        let unmapped = all_kinds.len() >= 2 && k.len() == 1;
        let flags = if unmapped {
            p.flags | FLAG_UNMAPPED_PORT
        } else {
            p.flags & !FLAG_UNMAPPED_PORT
        };
        if flags != p.flags {
            cx.ops.ci_put(&CiRow { flags, ..p })?;
        }
    }
    Ok(())
}

// -- the entry point ---------------------------------------------------------------------------

/// Applies the changes the seeds name: devices, natural-key CIs, keyless records and ports.
pub(crate) fn resolve_seeds(cx: &mut Cx<'_>, seeds: &Seeds) -> Result<()> {
    if seeds.is_empty() {
        return Ok(());
    }
    cx.pins = None;
    resolve_devices(cx, seeds)?;
    apply_natural(cx, &seeds.natural)?;
    // Keyless records: those that changed, those that hold an address a changed record holds, and
    // those on a device whose interfaces just moved (a device may have been split or folded).
    let mut keyless: BTreeSet<i64> = seeds.keyless.clone();
    let moved: Vec<String> = cx
        .candidates
        .iter()
        .chain(cx.resolved.iter())
        .cloned()
        .collect();
    for d in &moved {
        for r in cx.ops.records_of_ci(d)? {
            if r.ty == "device"
                && r.mac.is_none()
                && r.serial.is_none()
                && r.devkey.is_none()
                && r.dci.as_deref() == Some(d.as_str())
            {
                keyless.insert(r.rid);
            }
        }
    }
    let ips: Vec<String> = seeds.addrs.iter().cloned().collect();
    for r in cx.ops.keyless_by_addr(&ips)? {
        keyless.insert(r.rid);
    }
    for rid in keyless {
        attach_keyless(cx, rid)?;
    }
    // Ports: the owners that changed, and the devices resolved just now.
    let mut owners = seeds.owners.clone();
    let dev: Vec<String> = cx.devices.iter().cloned().collect();
    for d in &dev {
        for (k, v) in cx.ops.keys_of(d)? {
            if k == "devkey" {
                owners.insert(v);
            }
        }
    }
    apply_ports(cx, &owners)?;
    // Proposals about the devices resolved that nothing raised again have ended.
    let dev: Vec<String> = cx.resolved.iter().cloned().collect();
    cx.ops.proposals_prune(&dev, &cx.raised)?;
    Ok(())
}

//! REQ: DSC-903 (T31.2, ADR-1004 section 4, rule R1) - the manual link, unlink, merge and split.
//!
//! Each is a plan first: the records that would move, so the UI can show a preview and an API
//! caller can ask for a dry run. A plan that is applied writes pins (the owner's decisions, which
//! are authored data: replicated, never rebuilt) and runs the resolution again over what they
//! touch. An unlink is a "never match" pin and survives the next batch; a merge leaves the losing
//! id as an alias that redirects for 90 days; a split gives chosen records a new device and pins
//! them there. Nothing here writes to a device, a gateway or the network (DSC-901).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use telltale_store::cmdb::{CiRow, CmdbDb, CmdbError, Ops, Pin, RecordRow};

use super::apply::{Cx, Seeds, merge_ci, resolve_seeds};
use super::engine::Engine;
use super::model::{is_ci_id, new_ci_id};

/// A record by its source and key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecRef {
    pub(crate) source: String,
    pub(crate) key: String,
}

impl RecRef {
    fn pin_key(&self) -> String {
        format!("{}\x1f{}", self.source, self.key)
    }
}

/// A manual change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ManualOp {
    /// Put the record (its interface, when it has a MAC) under a device.
    Link { record: RecRef, to: String },
    /// Take the record away from its device and keep it from being matched there again.
    Unlink { record: RecRef },
    /// Fold a device into another.
    Merge { from: String, into: String },
    /// Move chosen records of a device to a new device.
    Split { device: String, records: Vec<RecRef> },
}

impl ManualOp {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Link { .. } => "link",
            Self::Unlink { .. } => "unlink",
            Self::Merge { .. } => "merge",
            Self::Split { .. } => "split",
        }
    }
}

/// One record that moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Move {
    pub(crate) source: String,
    pub(crate) key: String,
    /// The device it is on now.
    pub(crate) from: Option<String>,
    /// The device it goes to (`None`: a new device).
    pub(crate) to: Option<String>,
    /// Why it moves: `its interface` (a MAC identifies an interface, so every record of the MAC
    /// goes), `chosen` or `device` (it was on the folded device).
    pub(crate) why: &'static str,
}

/// What an operation would do, or did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Preview {
    pub(crate) op: String,
    pub(crate) moves: Vec<Move>,
    /// The devices the operation touches.
    pub(crate) devices: Vec<String>,
    /// What else follows (an alias that redirects, a pin that is written).
    pub(crate) notes: Vec<String>,
}

/// Why an operation is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ManualError {
    NotFound(String),
    Invalid(String),
    Db(String),
}

impl From<CmdbError> for ManualError {
    fn from(e: CmdbError) -> Self {
        Self::Db(e.to_string())
    }
}

type Result<T> = std::result::Result<T, ManualError>;

/// The device a CI id names now (following a merge alias), or an error.
fn device(ops: &Ops<'_>, id: &str, now: i64) -> Result<CiRow> {
    if !is_ci_id(id) {
        return Err(ManualError::Invalid(format!("`{id}` is not a CI id")));
    }
    let live = ops
        .resolve_id(id, now)?
        .ok_or_else(|| ManualError::NotFound(format!("no CI `{id}`")))?;
    let row = ops
        .ci_get(&live)?
        .ok_or_else(|| ManualError::NotFound(format!("no CI `{id}`")))?;
    if row.ty != "device" {
        return Err(ManualError::Invalid(format!(
            "`{id}` is a {} CI: manual changes are made between devices",
            row.ty
        )));
    }
    Ok(row)
}

fn record(ops: &Ops<'_>, r: &RecRef) -> Result<RecordRow> {
    ops.record_get(&r.source, &r.key)?
        .ok_or_else(|| ManualError::NotFound(format!("no record `{}` from `{}`", r.key, r.source)))
}

/// The records on a MAC (an interface goes with all of its records).
fn records_on_mac(ops: &Ops<'_>, mac: &str) -> Result<Vec<RecordRow>> {
    Ok(ops
        .records_by_keys(&[mac.to_owned()], &[], &[])?
        .into_iter()
        .filter(|r| r.ty == "device")
        .collect())
}

fn mv(r: &RecordRow, to: Option<&str>, why: &'static str) -> Move {
    Move {
        source: r.source.clone(),
        key: r.skey.clone(),
        from: r.dci.clone(),
        to: to.map(str::to_owned),
        why,
    }
}

/// What the operation writes, decided from the records as they are.
struct Plan {
    preview: Preview,
    /// MACs and keyless records the resolution runs over afterwards.
    macs: BTreeSet<String>,
    keyless: BTreeSet<i64>,
    pins: Vec<Pin>,
    drop_pins: Vec<(String, String, String)>,
    new_device: Option<CiRow>,
    merge: Option<(String, String)>,
    /// A device a link left with nothing: folded into the device the record went to.
    absorb: Option<(String, String)>,
}

fn pin(kind: &str, a: &str, b: &str, by: &str, reason: &str, now: i64) -> Pin {
    Pin {
        kind: kind.to_owned(),
        a: a.to_owned(),
        b: b.to_owned(),
        at: now,
        by: by.to_owned(),
        reason: reason.to_owned(),
    }
}

#[allow(clippy::too_many_lines)] // one branch per operation
fn plan(ops: &Ops<'_>, op: &ManualOp, by: &str, reason: &str, now: i64) -> Result<Plan> {
    let mut p = Plan {
        preview: Preview {
            op: op.name().to_owned(),
            ..Preview::default()
        },
        macs: BTreeSet::new(),
        keyless: BTreeSet::new(),
        pins: Vec::new(),
        drop_pins: Vec::new(),
        new_device: None,
        merge: None,
        absorb: None,
    };
    match op {
        ManualOp::Link { record: r, to } => {
            let target = device(ops, to, now)?;
            let rec = record(ops, r)?;
            if rec.ty != "device" {
                return Err(ManualError::Invalid(
                    "only a host or device record is linked to a device".into(),
                ));
            }
            if rec.dci.as_deref() == Some(target.id.as_str()) {
                return Err(ManualError::Invalid(
                    "the record is on that device already".into(),
                ));
            }
            if let Some(mac) = &rec.mac {
                // A MAC identifies an interface: the interface moves, with every record of it.
                for x in records_on_mac(ops, mac)? {
                    if x.dci.as_deref() != Some(target.id.as_str()) {
                        p.preview.moves.push(mv(&x, Some(&target.id), "its interface"));
                    }
                }
                p.pins
                    .push(pin("nic_device", mac, &target.id, by, reason, now));
                p.macs.insert(mac.clone());
                p.preview.notes.push(format!(
                    "the interface {mac} is pinned to this device: a serial or a key will not move it"
                ));
            } else if rec.serial.is_none() && rec.devkey.is_none() {
                p.preview.moves.push(mv(&rec, Some(&target.id), "chosen"));
                p.pins.push(pin(
                    "rec_device",
                    &r.pin_key(),
                    &target.id,
                    by,
                    reason,
                    now,
                ));
                p.keyless.insert(rec.rid);
            } else {
                return Err(ManualError::Invalid(
                    "this record is keyed by a serial or a device key, not a MAC: merge its device instead".into(),
                ));
            }
            if let Some(d) = &rec.dci {
                p.preview.devices.push(d.clone());
                p.absorb = Some((d.clone(), target.id.clone()));
            }
            p.preview.devices.push(target.id);
        }
        ManualOp::Unlink { record: r } => {
            let rec = record(ops, r)?;
            let Some(from) = rec.dci.clone() else {
                return Err(ManualError::Invalid("the record is not linked".into()));
            };
            if let Some(mac) = &rec.mac {
                // An interface is a MAC's: unlinking it means it gets a device of its own.
                let nics = ops.ci_children(&from)?;
                if nics.len() <= 1 {
                    return Err(ManualError::Invalid(
                        "this is the only interface of its device: there is nothing to unlink it from".into(),
                    ));
                }
                let x = CiRow {
                    id: new_ci_id(),
                    ty: "device".to_owned(),
                    kind: None,
                    name: rec_name(&rec),
                    parent: None,
                    flags: 0,
                    first_seen: now,
                };
                for y in records_on_mac(ops, mac)? {
                    p.preview.moves.push(mv(&y, None, "its interface"));
                }
                p.pins.push(pin("nic_device", mac, &x.id, by, reason, now));
                p.macs.insert(mac.clone());
                p.preview.notes.push(
                    "a MAC identifies an interface, so it leaves with a device of its own".into(),
                );
                p.new_device = Some(x);
            } else if rec.serial.is_none() && rec.devkey.is_none() {
                p.preview.moves.push(mv(&rec, None, "chosen"));
                p.pins
                    .push(pin("rec_never", &r.pin_key(), &from, by, reason, now));
                p.drop_pins
                    .push(("rec_device".into(), r.pin_key(), String::new()));
                p.keyless.insert(rec.rid);
                p.preview.notes.push(
                    "it will not be matched to this device again; it may match another, or stay on its own".into(),
                );
            } else {
                return Err(ManualError::Invalid(
                    "this record is keyed by a serial or a device key, not a MAC: split its device instead".into(),
                ));
            }
            p.preview.devices.push(from);
        }
        ManualOp::Merge { from, into } => {
            let a = device(ops, from, now)?;
            let b = device(ops, into, now)?;
            if a.id == b.id {
                return Err(ManualError::Invalid("a device cannot be merged into itself".into()));
            }
            for x in ops.records_of_ci(&a.id)? {
                if x.dci.as_deref() == Some(a.id.as_str()) {
                    p.preview.moves.push(mv(&x, Some(&b.id), "device"));
                }
            }
            for nic in ops.ci_children(&a.id)? {
                if nic.kind.as_deref() != Some("nic") {
                    continue;
                }
                if let Some(mac) = ops.mac_of(&nic.id)? {
                    p.pins.push(pin("nic_device", &mac, &b.id, by, reason, now));
                    p.macs.insert(mac);
                }
            }
            for x in ops.records_of_ci(&a.id)? {
                if x.dci.as_deref() == Some(a.id.as_str())
                    && x.mac.is_none()
                    && x.serial.is_none()
                    && x.devkey.is_none()
                    && x.ty == "device"
                {
                    p.pins.push(pin(
                        "rec_device",
                        &format!("{}\x1f{}", x.source, x.skey),
                        &b.id,
                        by,
                        reason,
                        now,
                    ));
                    p.keyless.insert(x.rid);
                }
            }
            p.preview.notes.push(format!(
                "{} stays as an alias that redirects to {} for 90 days",
                a.id, b.id
            ));
            p.preview.devices.push(a.id.clone());
            p.preview.devices.push(b.id.clone());
            p.merge = Some((a.id, b.id));
        }
        ManualOp::Split { device: d, records } => {
            let dev = device(ops, d, now)?;
            if records.is_empty() {
                return Err(ManualError::Invalid("choose the records to move".into()));
            }
            let nic_count = ops
                .ci_children(&dev.id)?
                .iter()
                .filter(|c| c.kind.as_deref() == Some("nic"))
                .count();
            let x = CiRow {
                id: new_ci_id(),
                ty: "device".to_owned(),
                kind: None,
                name: None,
                parent: None,
                flags: 0,
                first_seen: now,
            };
            let mut macs: BTreeSet<String> = BTreeSet::new();
            let mut name = None;
            for r in records {
                let rec = record(ops, r)?;
                if rec.dci.as_deref() != Some(dev.id.as_str()) {
                    return Err(ManualError::Invalid(format!(
                        "the record `{}` from `{}` is not on this device",
                        r.key, r.source
                    )));
                }
                name = name.or_else(|| rec_name(&rec));
                if let Some(mac) = &rec.mac {
                    macs.insert(mac.clone());
                } else if rec.serial.is_none() && rec.devkey.is_none() {
                    p.pins
                        .push(pin("rec_device", &r.pin_key(), &x.id, by, reason, now));
                    p.keyless.insert(rec.rid);
                    p.preview.moves.push(mv(&rec, None, "chosen"));
                } else {
                    return Err(ManualError::Invalid(
                        "a record keyed by a serial or a device key is moved with its interface: choose a record with a MAC".into(),
                    ));
                }
            }
            if !macs.is_empty() && macs.len() >= nic_count {
                return Err(ManualError::Invalid(
                    "that would move every interface: leave at least one on the device, or merge instead".into(),
                ));
            }
            for mac in &macs {
                for y in records_on_mac(ops, mac)? {
                    p.preview.moves.push(mv(&y, None, "its interface"));
                }
                p.pins.push(pin("nic_device", mac, &x.id, by, reason, now));
                p.macs.insert(mac.clone());
            }
            p.preview.notes.push(
                "the records go to a new device and stay there: a serial or a key will not join them back".into(),
            );
            p.preview.devices.push(dev.id);
            p.new_device = Some(CiRow { name, ..x });
        }
    }
    p.preview.devices.sort();
    p.preview.devices.dedup();
    Ok(p)
}

fn rec_name(r: &RecordRow) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(&r.attrs)
        .ok()
        .and_then(|v| {
            v.get("name")
                .or_else(|| v.get("hostname"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
}

/// What a manual change returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Outcome {
    pub(crate) preview: Preview,
    pub(crate) applied: bool,
    /// The device the records went to when it is new (a split or an unlink), or the survivor of a
    /// merge.
    pub(crate) result: Option<String>,
}

/// Previews a change without writing anything.
pub(crate) fn preview(db: &CmdbDb, op: &ManualOp, now: i64) -> Result<Preview> {
    db.read(|ops| Ok(plan(ops, op, "", "", now).map(|p| p.preview)))
        .map_err(ManualError::from)?
}

impl Engine {
    /// Runs a manual change: previews it, and applies it unless `dry_run`. Pins are authored data
    /// (replicated); the resolution runs again over the MACs and records the change touches, in
    /// the same transaction, so a reader never sees half of it.
    pub(crate) fn manual(
        &mut self,
        op: &ManualOp,
        by: &str,
        reason: &str,
        now: i64,
        dry_run: bool,
    ) -> Result<Outcome> {
        let db = std::sync::Arc::clone(self.db());
        if dry_run {
            let pv = preview(&db, op, now)?;
            return Ok(Outcome {
                preview: pv,
                applied: false,
                result: None,
            });
        }
        let mut moved_rids: Vec<i64> = Vec::new();
        let outcome = db
            .write(|ops| {
                let plan = match plan(ops, op, by, reason, now) {
                    Ok(p) => p,
                    Err(e) => return Ok(Err(e)),
                };
                let mut cx = Cx::new(ops, now)?;
                if let Some(x) = &plan.new_device {
                    ops.ci_put(x)?;
                    ops.seen_put(
                        &x.id,
                        telltale_store::cmdb::SeenRow {
                            last_seen: now,
                            days_seen: 0,
                            day: 0,
                        },
                    )?;
                    cx.ci_total = cx.ci_total.saturating_add(1);
                }
                for (kind, a, b) in &plan.drop_pins {
                    if b.is_empty() {
                        for old in ops.pins()?.into_iter().filter(|q| &q.kind == kind && &q.a == a) {
                            ops.pin_del(&old.kind, &old.a, &old.b)?;
                        }
                    } else {
                        ops.pin_del(kind, a, b)?;
                    }
                }
                for p in &plan.pins {
                    ops.pin_set(p)?;
                }
                cx.pins = None;
                if let Some((from, into)) = &plan.merge {
                    merge_ci(&mut cx, from, into)?;
                }
                let mut seeds = Seeds::default();
                seeds.macs.extend(plan.macs.iter().cloned());
                seeds.keyless.extend(plan.keyless.iter().copied());
                // The other records of the devices touched are looked at again too, so a device
                // that lost an interface is resolved without it.
                for d in &plan.preview.devices {
                    for r in ops.records_of_ci(d)? {
                        seeds.add_row(&r);
                    }
                }
                resolve_seeds(&mut cx, &seeds)?;
                if let Some((old, target)) = &plan.absorb
                    && ops.ci_get(old)?.is_some()
                    && ops.ci_children(old)?.is_empty()
                    && ops.records_of_ci(old)?.is_empty()
                {
                    merge_ci(&mut cx, old, target)?;
                }
                for mv in &plan.preview.moves {
                    if let Some(r) = ops.record_get(&mv.source, &mv.key)? {
                        moved_rids.push(r.rid);
                    }
                }
                let result = plan
                    .new_device
                    .as_ref()
                    .map(|x| x.id.clone())
                    .or_else(|| plan.merge.as_ref().map(|(_, b)| b.clone()))
                    .or_else(|| plan.preview.devices.last().cloned());
                Ok(Ok(Outcome {
                    preview: plan.preview,
                    applied: true,
                    result,
                }))
            })
            .map_err(ManualError::from)??;
        self.reload_links(&moved_rids);
        Ok(outcome)
    }
}

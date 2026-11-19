//! REQ: DSC-902, DSC-903 (T31.2, ADR-1005 section 8) - the API's view of the store: a page of CIs, one
//! CI with its records side by side, the open proposals. Reads only. At privacy level 1 the names
//! are hashed as the inventory's are (ADR-102, ADR-1005 section 12); at level 2 and above the CMDB
//! cannot be on (a validation error), so there is no level-2 view. A merged-away id answers with
//! the CI it became (the alias redirect), and everything a device said is cut text.

use std::collections::BTreeSet;

use telltale_api::cmdb_api::{
    CmdbAlias, CmdbCi, CmdbCiDetail, CmdbCiPage, CmdbPin, CmdbProposal, CmdbQuery, CmdbRecord,
};
use telltale_api::problem::Problem;
use telltale_store::cmdb::{
    CiRow, CmdbDb, CmdbError, FLAG_UNCONFIRMED, FLAG_UNMAPPED_PORT, Ops, Pin, Proposal, RecordRow,
};

use super::model::kind_of;

fn db_problem(e: &CmdbError) -> Problem {
    Problem::internal(e.to_string())
}

/// A name as shown: at privacy level 1 and above, one hashed label (keyed like the query log's
/// names), so the same name still groups but cannot be read.
pub(crate) fn shown(name: &str, level: u8) -> String {
    if level == 0 {
        return name.to_owned();
    }
    let w = telltale_telemetry::event::hidden_name(name.as_bytes());
    let inner = w.get(1..w.len().saturating_sub(1)).unwrap_or(&[]);
    String::from_utf8_lossy(inner).into_owned()
}

fn ci_of(ops: &Ops<'_>, row: &CiRow, level: u8) -> Result<CmdbCi, CmdbError> {
    let seen = ops.seen_get(&row.id)?;
    let recs = ops.records_of_ci(&row.id)?;
    let mut sources: BTreeSet<String> = BTreeSet::new();
    for r in &recs {
        sources.insert(kind_of(&r.source).to_owned());
    }
    let proposals = ops.proposals(Some("open"), Some(&row.id))?.len();
    Ok(CmdbCi {
        id: row.id.clone(),
        ty: row.ty.clone(),
        kind: row.kind.clone(),
        name: row.name.as_deref().map(|n| shown(n, level)),
        parent: row.parent.clone(),
        unconfirmed: row.flags & FLAG_UNCONFIRMED != 0,
        unmapped_port: row.flags & FLAG_UNMAPPED_PORT != 0,
        first_seen: row.first_seen,
        last_seen: seen.map(|s| s.last_seen),
        days_seen: seen.map(|s| s.days_seen),
        records: u64::try_from(recs.len()).unwrap_or(u64::MAX),
        sources: sources.into_iter().collect(),
        proposals: u64::try_from(proposals).unwrap_or(u64::MAX),
    })
}

/// A page of CIs. A device is listed with its interfaces on its own page, so by default only the
/// top-level types are listed; `type=interface` lists those.
pub(crate) fn list(db: &CmdbDb, q: &CmdbQuery, level: u8) -> Result<CmdbCiPage, Problem> {
    let limit = i64::from(q.limit.unwrap_or(100).clamp(1, 500));
    db.read(|ops| {
        let mut rows = ops.ci_list_in(
            q.ty.as_deref(),
            q.ty.is_none(),
            q.q.as_deref(),
            q.after.as_deref(),
            limit + 1,
        )?;
        let more = i64::try_from(rows.len()).unwrap_or(0) > limit;
        rows.truncate(usize::try_from(limit).unwrap_or(100));
        let next = more.then(|| rows.last().map(|r| r.id.clone())).flatten();
        let mut items = Vec::new();
        for r in &rows {
            items.push(ci_of(ops, r, level)?);
        }
        Ok(CmdbCiPage { items, next })
    })
    .map_err(|e| db_problem(&e))
}

fn record_of(r: &RecordRow, level: u8) -> CmdbRecord {
    let mut attrs: serde_json::Value =
        serde_json::from_str(&r.attrs).unwrap_or(serde_json::Value::Null);
    if level > 0
        && let Some(o) = attrs.as_object_mut()
    {
        for k in ["name", "hostname"] {
            if let Some(serde_json::Value::String(s)) = o.get(k).cloned() {
                o.insert(k.to_owned(), serde_json::Value::String(shown(&s, level)));
            }
        }
    }
    CmdbRecord {
        source: r.source.clone(),
        key: r.skey.clone(),
        ty: r.ty.clone(),
        state: r.state.clone(),
        link: r.link.clone(),
        first_seen: r.first_seen,
        last_changed: r.last_changed,
        last_seen: r.last_seen,
        interface: r.ici.clone(),
        device: r.dci.clone(),
        attrs,
    }
}

fn proposal_of(p: &Proposal) -> CmdbProposal {
    CmdbProposal {
        id: p.id,
        kind: p.kind.clone(),
        a: p.a.clone(),
        b: p.b.clone(),
        rule: p.rule.clone(),
        detail: p.detail.clone(),
        first_seen: p.first_seen,
        last_seen: p.last_seen,
    }
}

fn pin_of(p: &Pin) -> CmdbPin {
    CmdbPin {
        kind: p.kind.clone(),
        subject: p.a.replace('\x1f', "/"),
        target: p.b.clone(),
        at: p.at,
        by: p.by.clone(),
        reason: p.reason.clone(),
    }
}

/// One CI with what reconciliation holds about it. An id that was merged away leads to the CI it
/// became while its alias lasts; after that it is 404.
pub(crate) fn detail(db: &CmdbDb, id: &str, now: i64, level: u8) -> Result<CmdbCiDetail, Problem> {
    let r = db.read(|ops| {
        let Some(live) = ops.resolve_id(id, now)? else {
            return Ok(None);
        };
        let Some(row) = ops.ci_get(&live)? else {
            return Ok(None);
        };
        let ci = ci_of(ops, &row, level)?;
        let mut interfaces = Vec::new();
        for c in ops.ci_children(&row.id)? {
            interfaces.push(ci_of(ops, &c, level)?);
        }
        let mut records: Vec<RecordRow> = ops.records_of_ci(&row.id)?;
        for c in ops.ci_children(&row.id)? {
            for r in ops.records_of_ci(&c.id)? {
                if !records.iter().any(|x| x.rid == r.rid) {
                    records.push(r);
                }
            }
        }
        records.sort_by(|a, b| (&a.source, &a.skey).cmp(&(&b.source, &b.skey)));
        let proposals = ops
            .proposals(Some("open"), Some(&row.id))?
            .iter()
            .map(proposal_of)
            .collect();
        let macs: BTreeSet<String> = ops
            .ci_children(&row.id)?
            .iter()
            .filter_map(|c| ops.mac_of(&c.id).ok().flatten())
            .collect();
        let pins = ops
            .pins()?
            .iter()
            .filter(|p| p.b == row.id || macs.contains(&p.a))
            .map(pin_of)
            .collect();
        let aliases = ops
            .aliases()?
            .into_iter()
            .filter(|(_, new, until)| *new == row.id && *until > now)
            .map(|(old, _, until)| CmdbAlias { id: old, until })
            .collect();
        Ok(Some(CmdbCiDetail {
            ci,
            interfaces,
            records: records.iter().map(|r| record_of(r, level)).collect(),
            proposals,
            pins,
            aliases,
        }))
    });
    match r {
        Ok(Some(d)) => Ok(d),
        Ok(None) => Err(Problem::not_found(format!("no CI `{id}`"))
            .hint("A merged-away id redirects for 90 days, then it is gone.")),
        Err(e) => Err(db_problem(&e)),
    }
}

/// The open proposals.
pub(crate) fn proposals(db: &CmdbDb) -> Result<Vec<CmdbProposal>, Problem> {
    db.read(|ops| {
        Ok(ops
            .proposals(Some("open"), None)?
            .iter()
            .map(proposal_of)
            .collect())
    })
    .map_err(|e| db_problem(&e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmdb::engine::test_support::{batch, engine, host};

    /// REQ: DSC-902 - the list shows devices (not their interfaces), pages by cursor, finds text in a
    /// MAC, and the detail shows the records side by side and follows a merge alias.
    #[test]
    fn dsc_902_list_detail_and_alias_redirect() {
        let (_d, mut e) = engine();
        let mk = |k: &str, m: &str| {
            let mut r = host("unifi:home", k, m, 1_000_000);
            r.text("name", format!("host-{k}"));
            r
        };
        e.ingest(
            batch(
                "unifi:home",
                vec![
                    mk("a", "aa:bb:cc:00:00:01"),
                    mk("b", "aa:bb:cc:00:00:02"),
                    mk("c", "aa:bb:cc:00:00:03"),
                ],
                true,
                1_000_000,
            ),
            1_000_000,
        )
        .unwrap();
        let q = CmdbQuery {
            limit: Some(2),
            ..CmdbQuery::default()
        };
        let p1 = list(e.db(), &q, 0).unwrap();
        assert_eq!(p1.items.len(), 2);
        assert!(
            p1.items.iter().all(|c| c.ty == "device"),
            "interfaces are not listed by default"
        );
        let p2 = list(
            e.db(),
            &CmdbQuery {
                after: p1.next.clone(),
                ..q.clone()
            },
            0,
        )
        .unwrap();
        assert_eq!(p2.items.len(), 1);
        assert!(p2.next.is_none());
        let found = list(
            e.db(),
            &CmdbQuery {
                q: Some("00:00:02".into()),
                ..CmdbQuery::default()
            },
            0,
        )
        .unwrap();
        assert_eq!(found.items.len(), 1, "a MAC finds its device");
        let id = found.items[0].id.clone();
        let d = detail(e.db(), &id, 1_000_001, 0).unwrap();
        assert_eq!(d.records.len(), 1);
        assert_eq!(d.records[0].attrs["name"], "host-b");
        assert_eq!(d.interfaces.len(), 1);
        // Merge it away and ask for the old id.
        let other = p1.items.iter().find(|c| c.id != id).unwrap().id.clone();
        e.manual(
            &crate::cmdb::manual::ManualOp::Merge {
                from: id.clone(),
                into: other.clone(),
            },
            "t",
            "x",
            1_000_002,
            false,
        )
        .unwrap();
        let moved = detail(e.db(), &id, 1_000_003, 0).unwrap();
        assert_eq!(moved.ci.id, other, "the alias redirects");
        assert!(moved.aliases.iter().any(|a| a.id == id));
        assert_eq!(
            detail(e.db(), &id, 1_000_003 + 91 * 86_400, 0)
                .unwrap_err()
                .status,
            404
        );
    }

    /// REQ: DSC-906 (ADR-1005 section 12) - at privacy level 1 a name is one hashed label, the same
    /// every time, and level 0 shows it as it is.
    #[test]
    fn dsc_906_names_are_hashed_at_level_one() {
        let a = shown("kitchen-hub", 1);
        assert_ne!(a, "kitchen-hub");
        assert_eq!(a, shown("kitchen-hub", 1));
        assert_ne!(a, shown("other", 1));
        assert_eq!(shown("kitchen-hub", 0), "kitchen-hub");
    }
}

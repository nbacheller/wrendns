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
            level == 0,
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

/// The attributes whose text is a name a person gave (or one built from it): a host name, an access
/// point, a switch name with a port, a neighbour's name, the owner of an attached port.
const NAME_ATTRS: [&str; 8] = [
    "name",
    "hostname",
    "ap",
    "port",
    "lldp",
    "attached_owner",
    "owner",
    "namespace",
];

/// A record key as shown: the keys built from a name (`client:<name>`, the workloads'
/// `namespace/kind/name`) are hashed at privacy level 1, the others (MACs, device ids) stay.
fn shown_key(source: &str, key: &str, level: u8) -> String {
    if level == 0 {
        return key.to_owned();
    }
    if let Some(n) = key.strip_prefix("client:") {
        return format!("client:{}", shown(n, level));
    }
    if source == "k8s" {
        return shown(key, level);
    }
    key.to_owned()
}

/// A proposal's text with the names in it hidden at privacy level 1: the host names between
/// backticks are hashed, and a text that names a record key is replaced.
fn shown_detail(kind: &str, detail: &str, level: u8) -> String {
    if level == 0 {
        return detail.to_owned();
    }
    if kind != "host_network" {
        return "the record points at more than one device (its details are hidden at privacy level 1)"
            .to_owned();
    }
    detail
        .split('`')
        .enumerate()
        .map(|(i, part)| {
            if i % 2 == 1 {
                shown(part, level)
            } else {
                part.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("`")
}

fn record_of(r: &RecordRow, level: u8) -> CmdbRecord {
    let mut attrs: serde_json::Value =
        serde_json::from_str(&r.attrs).unwrap_or(serde_json::Value::Null);
    if level > 0
        && let Some(o) = attrs.as_object_mut()
    {
        for k in NAME_ATTRS {
            match o.get(k).cloned() {
                Some(serde_json::Value::String(s)) => {
                    o.insert(k.to_owned(), serde_json::Value::String(shown(&s, level)));
                }
                Some(serde_json::Value::Array(a)) => {
                    let hidden = a
                        .iter()
                        .map(|v| match v {
                            serde_json::Value::String(s) => {
                                serde_json::Value::String(shown(s, level))
                            }
                            other => other.clone(),
                        })
                        .collect();
                    o.insert(k.to_owned(), serde_json::Value::Array(hidden));
                }
                _ => {}
            }
        }
    }
    CmdbRecord {
        source: r.source.clone(),
        key: shown_key(&r.source, &r.skey, level),
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

fn proposal_of(p: &Proposal, level: u8) -> CmdbProposal {
    CmdbProposal {
        id: p.id,
        kind: p.kind.clone(),
        a: p.a.clone(),
        b: p.b.clone(),
        rule: p.rule.clone(),
        detail: shown_detail(&p.kind, &p.detail, level),
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
            .map(|p| proposal_of(p, level))
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
pub(crate) fn proposals(db: &CmdbDb, level: u8) -> Result<Vec<CmdbProposal>, Problem> {
    db.read(|ops| {
        Ok(ops
            .proposals(Some("open"), None)?
            .iter()
            .map(|p| proposal_of(p, level))
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

    /// REQ: DSC-906 (ADR-1005 section 12) - at privacy level 1 no name leaks: not in the proposal's
    /// text, a record's key, the attributes that carry a name (access point, port, neighbours,
    /// owner) or a search (which then matches ids and MACs only).
    #[test]
    fn dsc_906_level_one_hides_names_everywhere() {
        let (_d, mut e) = engine();
        let mk = |k: &str, m: &str| {
            let mut r = host("unifi:home", k, m, 1_000_000);
            r.text("name", "secret-host");
            r.text("hostname", "secret-host");
            r.text("network", "Lan");
            r.text("ap", "secret-ap");
            r.text("port", "secret-switch port 3");
            r.list("lldp", vec!["secret-neighbour".to_owned()]);
            r
        };
        let mut client = host(
            "config",
            "client:secret-laptop",
            "aa:bb:cc:00:00:09",
            1_000_000,
        );
        client.text("name", "secret-laptop");
        e.ingest(
            batch(
                "unifi:home",
                vec![mk("a", "aa:bb:cc:00:00:01"), mk("b", "aa:bb:cc:00:00:02")],
                true,
                1_000_000,
            ),
            1_000_000,
        )
        .unwrap();
        let mut keyless = host("config", "client:secret-keyless", "", 1_000_000);
        keyless.text("name", "secret-keyless");
        e.ingest(
            batch("config", vec![client, keyless], true, 1_000_000),
            1_000_000,
        )
        .unwrap();
        let everything = |level: u8| -> String {
            let page = list(
                e.db(),
                &CmdbQuery {
                    limit: Some(100),
                    ..CmdbQuery::default()
                },
                level,
            )
            .unwrap();
            let mut text = serde_json::to_string(&page).unwrap();
            for c in &page.items {
                text += &serde_json::to_string(&detail(e.db(), &c.id, 1_000_001, level).unwrap())
                    .unwrap();
            }
            text += &serde_json::to_string(&proposals(e.db(), level).unwrap()).unwrap();
            text
        };
        let open = everything(0);
        assert!(open.contains("secret-host") && open.contains("client:secret-laptop"));
        assert!(
            serde_json::to_string(&proposals(e.db(), 0).unwrap())
                .unwrap()
                .contains("secret-host"),
            "level 0 keeps the proposal text"
        );
        let hidden = everything(1);
        assert!(!hidden.contains("secret"), "a name leaked: {hidden}");
        assert!(hidden.contains("client:"), "the key keeps its shape");
        // A search finds an id or a MAC, never a name.
        let by = |q: &str, level: u8| {
            list(
                e.db(),
                &CmdbQuery {
                    q: Some(q.into()),
                    ..CmdbQuery::default()
                },
                level,
            )
            .unwrap()
            .items
            .len()
        };
        assert_eq!(by("secret", 0), 4);
        assert_eq!(
            by("keyless", 1),
            0,
            "a key that holds a name is not searched"
        );
        assert_eq!(by("secret", 1), 0, "a search cannot confirm a name");
        assert_eq!(by("00:00:01", 1), 1, "a MAC is still found");
    }
}

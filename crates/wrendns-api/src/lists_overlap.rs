//! REQ: FLT-004, AGT-001, AGT-002, API-005 (T24.28, ADR-992) - which filter lists add little:
//! `GET /api/v1/lists/overlap` (each enabled list's unique names and the lists covering the
//! rest), `GET /api/v1/lists/prune-plan` (the lists that add at most a threshold, and what
//! turning them off could lose; changes nothing), and `POST /api/v1/lists/prune` (turns the
//! plan's lists off after a person confirmed it in the UI; never for agents).
//!
//! Nothing here reads a snapshot or touches a query: the numbers are the ones the compile counts
//! while it merges the lists (`GET /api/v1/lists`' `unique`, `overlap` and `rules`), so the
//! cost is the compile's, once per compile. A list that is turned off stays in the configuration
//! with `enabled = false`: turning it on again is one edit (Manage lists), and its source stays.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::auth::Auth;
use crate::auth::routes::{principal, reason, remote};
use crate::model::{
    GroupInfo, Items, ListCover, ListInfo, ListOverlapRow, ListPruneCandidate, ListPruneKept,
    ListPrunePlan, ListsPruneRequest, ListsPruneResult, PruneParams,
};
use crate::problem::{Code, Problem};
use crate::{ManagedKind, ManagedWrite, Shared, blocking};

/// The default threshold: a list adding under 1 % of its own entries.
pub const DEFAULT_THRESHOLD: f64 = 1.0;
/// The highest threshold the plan accepts. Above half, two near-identical lists could each look
/// removable; the plan also checks the lists together, but a cap keeps the question sensible.
pub const MAX_THRESHOLD: f64 = 50.0;
/// The most lists a request may name.
pub const MAX_NAMES: usize = 256;
/// Covering lists shown per list.
const SHOWN_COVERS: usize = 5;

/// Reads (any signed-in role; agents: `config:read`).
pub(crate) fn read_routes(backend: Shared) -> Router {
    Router::new()
        .route("/api/v1/lists/overlap", get(overlap))
        .route("/api/v1/lists/prune-plan", get(prune_plan))
        .with_state(backend)
}

/// The apply (operator, a person: agent tokens are refused).
pub(crate) fn write_routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/lists/prune", post(prune))
        .with_state((backend, auth))
}

/// A threshold from the query or body: `None` is the default; 0 to [`MAX_THRESHOLD`].
pub fn threshold(given: Option<f64>) -> Result<f64, Problem> {
    let t = given.unwrap_or(DEFAULT_THRESHOLD);
    if !t.is_finite() || !(0.0..=MAX_THRESHOLD).contains(&t) {
        return Err(Problem::invalid(format!(
            "`thresholdPercent` must be between 0 and {MAX_THRESHOLD}"
        ))
        .hint("A list is proposed when it adds at most this share of its own entries; 1 is a good start."));
    }
    Ok(t)
}

fn share(of: &ListInfo, other: &str) -> u64 {
    of.overlap
        .iter()
        .find(|s| s.list == other)
        .map_or(0, |s| s.names)
}

fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        // Counts stay far below 2^52, so the conversion is exact.
        #[allow(clippy::cast_precision_loss)]
        let p = part as f64 * 100.0 / whole as f64;
        (p * 10.0).round() / 10.0
    }
}

fn covers(l: &ListInfo) -> Vec<ListCover> {
    l.overlap
        .iter()
        .take(SHOWN_COVERS)
        .map(|s| ListCover {
            list: s.list.clone(),
            names: s.names,
            percent: percent(s.names, l.entries),
        })
        .collect()
}

/// Each group that names lists of its own, with those lists (a group with no `lists` uses every
/// enabled list and names none).
pub type Named = [(String, Vec<String>)];

/// The groups that name lists, from `GET /api/v1/groups`.
pub fn named_lists(groups: &[GroupInfo]) -> Vec<(String, Vec<String>)> {
    groups
        .iter()
        .filter_map(|g| g.lists.clone().map(|l| (g.name.clone(), l)))
        .collect()
}

fn named_by(groups: &Named, list: &str) -> Vec<String> {
    groups
        .iter()
        .filter(|(_, ls)| ls.iter().any(|n| n == list))
        .map(|(g, _)| g.clone())
        .collect()
}

/// Each enabled list's overlap, in configuration order.
pub fn rows(lists: &[ListInfo], groups: &Named) -> Vec<ListOverlapRow> {
    lists
        .iter()
        .filter(|l| l.enabled)
        .map(|l| ListOverlapRow {
            name: l.name.clone(),
            kind: l.kind.clone(),
            mode: l.mode.clone(),
            entries: l.entries,
            unique: l.unique,
            rules: l.rules,
            adds_percent: percent(l.unique + l.rules, l.entries),
            covered_by: covers(l),
            groups: named_by(groups, &l.name),
        })
        .collect()
}

/// Does this list block right now? Only an enabled block list in enforce mode covers names.
fn covering(y: &ListInfo) -> bool {
    y.enabled && y.mode == "enforce" && y.kind == "block"
}

/// Is the overlap from a compile that no longer matches the configuration? A share naming a list
/// that is off or gone means the lists changed (a prune, an edit) and the compile that follows
/// hasn't finished, or failed and the old snapshot stays.
fn compile_pending(lists: &[ListInfo]) -> bool {
    lists
        .iter()
        .filter(|l| l.enabled)
        .flat_map(|l| l.overlap.iter())
        .any(|s| {
            // A service's synthetic list (`svc-<id>`, from a blocked service) is in the compile
            // but has no row here; it covers only its group, so it never makes the plan pending.
            !s.list.starts_with(wrendns_config::services::PREFIX)
                && !lists.iter().any(|y| y.enabled && y.name == s.list)
        })
}

/// What turning a list off could lose that is certain to be lost or can't be shown covered:
/// its unique names, its rules (overlap is by name), and the names it shares with a list that
/// does not block now (a shadow list, an allow list, a list that is off or gone: it covers
/// nothing).
fn base_loss(l: &ListInfo, lists: &[ListInfo]) -> u64 {
    let uncovered: u64 = l
        .overlap
        .iter()
        .filter(|s| s.list != l.name && !lists.iter().any(|y| y.name == s.list && covering(y)))
        .map(|s| s.names)
        .sum();
    l.unique + l.rules + uncovered
}

/// `base_loss` as a share of the list's entries (0 to a few; for ordering only).
#[allow(clippy::cast_precision_loss)] // counts are far below 2^52
fn loss_ratio(l: &ListInfo, lists: &[ListInfo]) -> f64 {
    base_loss(l, lists) as f64 / l.entries.max(1) as f64
}

/// The names turning off every list in `set` could lose, as an upper bound: each list's
/// `base_loss` plus the names two lists of the set share (a name whose every holder is in the
/// set is shared by at least one pair of them).
fn set_loss(set: &[&ListInfo], lists: &[ListInfo]) -> u64 {
    let mut total: u64 = set.iter().map(|l| base_loss(l, lists)).sum();
    for (i, a) in set.iter().enumerate() {
        for b in &set[i + 1..] {
            total += share(a, &b.name);
        }
    }
    total
}

/// Does every list in `set` still add at most `threshold` percent of its entries counting the
/// names it shares with the others in the set?
fn set_fits(set: &[&ListInfo], lists: &[ListInfo], threshold: f64) -> bool {
    set.iter().all(|x| {
        let others: u64 = set
            .iter()
            .filter(|y| y.name != x.name)
            .map(|y| share(x, &y.name))
            .sum();
        #[allow(clippy::cast_precision_loss)]
        let loss = (base_loss(x, lists) + others) as f64 * 100.0;
        #[allow(clippy::cast_precision_loss)]
        let allowed = threshold * x.entries as f64;
        loss <= allowed
    })
}

/// The lists to turn off at `threshold` percent. Greedy, least-adding first, and each list added
/// has to keep the whole set within the threshold (two lists that mirror each other are never
/// both proposed). `of_names` is the active snapshot's size, for the note.
#[allow(clippy::too_many_lines)] // one pass: classify, choose the set, describe it
pub fn plan(lists: &[ListInfo], groups: &Named, threshold: f64, of_names: u64) -> ListPrunePlan {
    let mut kept: Vec<ListPruneKept> = Vec::new();
    let mut pool: Vec<&ListInfo> = Vec::new();
    let pending = compile_pending(lists);
    for l in lists.iter().filter(|l| l.enabled) {
        let why = if pending {
            Some("the lists changed and the compile that follows hasn't finished".to_owned())
        } else if l.kind != "block" {
            Some("allow list: only block lists are proposed".to_owned())
        } else if l.mode != "enforce" {
            Some(
                "shadow mode: it never blocks; switch it to enforce or turn it off yourself"
                    .to_owned(),
            )
        } else if l.entries == 0 {
            Some("no entries in the snapshot yet (not downloaded or not compiled)".to_owned())
        } else if let Some(g) = named_by(groups, &l.name).first() {
            Some(format!(
                "group `{g}` names it, so it can't be covered by others for that group"
            ))
        } else {
            // Exact, not the rounded share: `set_fits` is exact too.
            #[allow(clippy::cast_precision_loss)]
            let over = base_loss(l, lists) as f64 * 100.0 > threshold * l.entries as f64;
            let adds = percent(base_loss(l, lists), l.entries);
            if over {
                Some(format!("adds {adds}% of its entries, above {threshold}%"))
            } else {
                None
            }
        };
        match why {
            Some(reason) => kept.push(ListPruneKept {
                name: l.name.clone(),
                reason,
            }),
            None => pool.push(l),
        }
    }
    pool.sort_by(|a, b| {
        loss_ratio(a, lists)
            .total_cmp(&loss_ratio(b, lists))
            .then_with(|| a.name.cmp(&b.name))
    });
    let mut chosen: Vec<&ListInfo> = Vec::new();
    for c in pool {
        let mut trial = chosen.clone();
        trial.push(c);
        if set_fits(&trial, lists, threshold) {
            chosen = trial;
        } else {
            kept.push(ListPruneKept {
                name: c.name.clone(),
                reason: format!(
                    "turning it off together with the others in the plan would lose more than {threshold}% of one of them"
                ),
            });
        }
    }
    let candidates: Vec<ListPruneCandidate> = chosen
        .iter()
        .map(|l| {
            let others: u64 = chosen
                .iter()
                .filter(|y| y.name != l.name)
                .map(|y| share(l, &y.name))
                .sum();
            ListPruneCandidate {
                name: l.name.clone(),
                entries: l.entries,
                unique: l.unique,
                adds_percent: percent(l.unique + l.rules, l.entries),
                loses_at_most: base_loss(l, lists) + others,
                covered_by: covers(l),
            }
        })
        .collect();
    let total = set_loss(&chosen, lists);
    let note = if pending {
        "A compile is pending: the lists changed since the last one finished, so what each list adds isn't known yet. Preview again in a moment.".to_owned()
    } else if candidates.is_empty() {
        format!("No enabled list adds {threshold}% or less of its own entries.")
    } else {
        format!(
            "{} {} would be turned off; at most {total} of {of_names} blocked names could stop being blocked. Turned-off lists stay in the configuration.",
            candidates.len(),
            if candidates.len() == 1 {
                "list"
            } else {
                "lists"
            }
        )
    };
    ListPrunePlan {
        threshold_percent: threshold,
        candidates,
        kept,
        loses_at_most: total,
        of_names,
        note,
        compile_pending: pending,
        snapshot_version: 0,
        config_version: 0,
    }
}

/// The lists, the groups, and the snapshot's size, from the primary on a replica (the compile
/// runs there).
async fn inputs(b: &Shared) -> Result<Inputs, Problem> {
    let bk = Arc::clone(b);
    blocking(move || {
        // The version first: an edit after it makes the apply's write fail, never get lost.
        let config_version = bk.config_version();
        let lists = bk.lists_and_hits().lists;
        let groups = named_lists(&bk.groups_local());
        let info = bk.system_info();
        Ok(Inputs {
            lists,
            groups,
            names: info.filter_names,
            snapshot_version: info.filter_snapshot.unwrap_or(0),
            config_version,
        })
    })
    .await
}

/// What a plan is computed from, with the two versions it was read at.
struct Inputs {
    lists: Vec<ListInfo>,
    groups: Vec<(String, Vec<String>)>,
    names: u64,
    snapshot_version: u64,
    config_version: u64,
}

impl Inputs {
    fn plan(&self, threshold: f64) -> ListPrunePlan {
        let mut p = plan(&self.lists, &self.groups, threshold, self.names);
        p.snapshot_version = self.snapshot_version;
        p.config_version = self.config_version;
        p
    }
}

/// How much each filter list adds.
///
/// Every enabled list with its entries, the names no other list of its kind has (`unique`:
/// what turning it off would lose), its modifier rules and regexes (counted as unique: overlap
/// is by name), what it adds as a share of its entries, the lists that cover the rest, and the
/// groups that name it. Counted while the lists are compiled, once per compile; a list not
/// compiled yet shows zeros. Names a block list and an allow list both have don't count as
/// shared.
#[utoipa::path(get, path = "/api/v1/lists/overlap", tag = "config",
    responses((status = 200, body = Items<ListOverlapRow>, description = "Each enabled list's overlap.")))]
pub(crate) async fn overlap(
    State(b): State<Shared>,
) -> Result<Json<Items<ListOverlapRow>>, Problem> {
    let i = inputs(&b).await?;
    Ok(Json(Items {
        items: rows(&i.lists, &i.groups),
        missing_nodes: Vec::new(),
    }))
}

/// Which lists a prune would turn off.
///
/// The block lists in enforce mode that add at most `thresholdPercent` (default 1) of their own
/// entries, least-adding first, chosen so that turning all of them off together still loses at
/// most that share of each; `kept` says why every other enabled list stays (an allow list, a
/// shadow list, a group names it, it adds more). `losesAtMost` is an upper bound on the names
/// that would stop being blocked. Changes nothing; the apply is `POST /api/v1/lists/prune`, for
/// a person.
#[utoipa::path(get, path = "/api/v1/lists/prune-plan", tag = "config",
    params(PruneParams),
    responses(
        (status = 200, body = ListPrunePlan, description = "What would be turned off."),
        (status = 400, body = Problem, description = "A threshold outside 0 to 50."),
    ))]
pub(crate) async fn prune_plan(
    State(b): State<Shared>,
    Query(q): Query<PruneParams>,
) -> Result<Json<ListPrunePlan>, Problem> {
    let t = threshold(q.threshold_percent)?;
    Ok(Json(inputs(&b).await?.plan(t)))
}

/// Turn off the lists that add little.
///
/// Recomputes the plan for `thresholdPercent` and turns the lists in it off (`enabled = false`;
/// each stays in the configuration with its source, so turning it on again is one edit). With
/// `names` (the ones the person previewed), each must still be in the plan or nothing changes
/// (409: preview again). Needs the operator role and a person: agent tokens are refused
/// (`agent_not_allowed`); they read the plan. Audit-logged as `lists.prune`.
#[allow(clippy::too_many_lines)] // one request: read, check, plan, write each list, audit
#[utoipa::path(post, path = "/api/v1/lists/prune", tag = "config",
    request_body = ListsPruneRequest,
    responses(
        (status = 200, body = ListsPruneResult, description = "The lists now off."),
        (status = 400, body = Problem, description = "A malformed body, a threshold outside 0 to 50, or too many names."),
        (status = 403, body = Problem, description = "Needs the operator role; agent tokens are refused."),
        (status = 409, body = Problem, description = "A named list isn't in the plan any more: preview again."),
    ))]
pub(crate) async fn prune(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    body: Bytes,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    // REQ: AGT-004 - the middleware already refuses agent tokens; this stays true if a route moves.
    if p.agent.is_some() {
        return Problem::new(
            Code::AgentNotAllowed,
            "agent tokens can't turn lists off in bulk",
        )
        .hint("Read GET /api/v1/lists/prune-plan; a person confirms it in the UI.")
        .into_response();
    }
    let req: ListsPruneRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return Problem::invalid(format!("request body: {e}"))
                .hint("Send what the preview returned: {\"thresholdPercent\": 1, \"names\": [\"<list>\"], \"snapshotVersion\": 7, \"configVersion\": 12}.")
                .into_response();
        }
    };
    let t = match threshold(req.threshold_percent) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if req.names.len() > MAX_NAMES {
        return Problem::invalid(format!("`names`: at most {MAX_NAMES} lists")).into_response();
    }
    let input = match inputs(&backend).await {
        Ok(i) => i,
        Err(e) => return e.into_response(),
    };
    let stale_hint = "The lists changed since the preview. Nothing was turned off; preview again.";
    if input.config_version != req.config_version || input.snapshot_version != req.snapshot_version
    {
        return Problem::new(
            Code::Conflict,
            "the configuration or the compiled lists changed since the preview",
        )
        .hint(stale_hint)
        .into_response();
    }
    let plan = input.plan(t);
    if plan.compile_pending {
        return Problem::new(Code::Conflict, "a compile is pending")
            .hint("The lists changed and the compile that follows hasn't finished. Nothing was turned off; preview again in a moment.")
            .into_response();
    }
    let mut chosen: Vec<String> = Vec::new();
    for n in req.names.iter().map(|n| n.trim()) {
        if !plan.candidates.iter().any(|c| c.name == n) {
            return Problem::new(Code::Conflict, format!("not in the plan any more: `{n}`"))
                .hint(stale_hint)
                .into_response();
        }
        if !chosen.iter().any(|c| c == n) {
            chosen.push(n.to_owned());
        }
    }
    if chosen.is_empty() {
        return Json(ListsPruneResult {
            disabled: Vec::new(),
            config_version: input.config_version,
            note: "Nothing to turn off.".into(),
        })
        .into_response();
    }
    let bk = Arc::clone(&backend);
    let entries = match blocking(move || Ok(bk.config_entries(Some("list")))).await {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let defs: HashMap<&str, &serde_json::Value> = entries
        .iter()
        .filter_map(|e| e.definition.as_ref().map(|d| (e.name.as_str(), d)))
        .collect();
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let mut disabled: Vec<String> = Vec::new();
    // REQ: API-002 - each write is checked against the version read before the definitions, then
    // against the one the write before it returned: an edit in between fails it, never lost.
    let mut version = input.config_version;
    for name in &chosen {
        let Some(def) = defs.get(name.as_str()) else {
            return failed(
                &auth,
                &actor,
                t,
                &disabled,
                Problem::not_found(format!("no definition for list `{name}`")),
            );
        };
        let mut body = (*def).clone();
        match body.as_object_mut() {
            Some(o) => {
                o.insert("enabled".into(), serde_json::Value::Bool(false));
            }
            None => {
                return failed(
                    &auth,
                    &actor,
                    t,
                    &disabled,
                    Problem::internal(format!("list `{name}` has no editable definition")),
                );
            }
        }
        let w = ManagedWrite {
            kind: ManagedKind::List,
            name: name.clone(),
            body: Some(body),
            dry_run: false,
            expect: Some(version),
            by: actor.name.clone(),
            simulate: None,
            role: Some(p.role),
            agent: None,
            origin: None,
        };
        match backend.write_managed(w).await {
            Ok(c) => {
                version = c.config_version;
                // The same audit entry the list's own edit writes (ADR-993).
                auth.record(
                    &actor,
                    "list.put",
                    name,
                    &serde_json::json!({ "before": c.before, "after": c.after, "configVersion": c.config_version }),
                );
                disabled.push(name.clone());
            }
            Err(e) => return failed(&auth, &actor, t, &disabled, e),
        }
    }
    auth.record(
        &actor,
        "lists.prune",
        &disabled.join(", "),
        &serde_json::json!({ "thresholdPercent": t, "disabled": disabled, "losesAtMost": plan.loses_at_most }),
    );
    Json(ListsPruneResult {
        note: format!(
            "{} {} turned off. They stay in the configuration; turn one on again in Manage lists.",
            disabled.len(),
            if disabled.len() == 1 { "list" } else { "lists" }
        ),
        disabled,
        config_version: version,
    })
    .into_response()
}

/// A write that failed part-way: the lists already off stay off (and are named).
fn failed(
    auth: &Auth,
    actor: &crate::auth::Actor,
    t: f64,
    done: &[String],
    e: Problem,
) -> Response {
    if done.is_empty() {
        return e.into_response();
    }
    // The lists already off are audited as a prune too, so none changes unrecorded.
    auth.record(
        actor,
        "lists.prune",
        &done.join(", "),
        &serde_json::json!({ "thresholdPercent": t, "disabled": done, "partial": true, "error": e.title }),
    );
    let hint = format!(
        "Already turned off: {}. They stay off; turn them on again in Manage lists if you don't want that.",
        done.join(", ")
    );
    e.hint(hint).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ListShare;

    fn list(name: &str, entries: u64, unique: u64, over: &[(&str, u64)]) -> ListInfo {
        let mut v: Vec<ListShare> = over
            .iter()
            .map(|(l, n)| ListShare {
                list: (*l).to_owned(),
                names: *n,
            })
            .collect();
        v.sort_by_key(|s| std::cmp::Reverse(s.names));
        serde_json::from_value(serde_json::json!({
            "name": name, "kind": "block", "enabled": true, "mode": "enforce",
            "source": "inline", "state": "ok", "bytes": 1, "lines": 1,
            "entries": entries, "unique": unique, "regexSkipped": 0, "hits": 0,
            "overlap": v, "refreshing": false,
        }))
        .unwrap()
    }

    fn group(name: &str, lists: &[&str]) -> (String, Vec<String>) {
        (
            name.to_owned(),
            lists.iter().map(|l| (*l).to_owned()).collect(),
        )
    }

    // REQ: FLT-004 (T24.28) - the threshold is 0 to 50, default 1; anything else is a 400.
    #[test]
    fn flt_004_prune_threshold_is_checked() {
        assert_eq!(threshold(None).unwrap(), 1.0);
        assert_eq!(threshold(Some(0.0)).unwrap(), 0.0);
        assert_eq!(threshold(Some(50.0)).unwrap(), 50.0);
        for bad in [-0.1, 50.1, f64::NAN, f64::INFINITY] {
            assert_eq!(threshold(Some(bad)).unwrap_err().status, 400, "{bad}");
        }
    }

    // REQ: FLT-004 (T24.28) - a list nearly all of whose names another list has is proposed; a
    // list adding more than the threshold stays, with the share in the reason.
    #[test]
    fn flt_004_prune_plan_proposes_lists_that_add_little() {
        let lists = vec![
            list("big", 1000, 900, &[("dup", 99)]),
            list("dup", 100, 0, &[("big", 99)]),
            list("mixed", 200, 40, &[]),
        ];
        let p = plan(&lists, &[], 1.0, 1300);
        assert_eq!(p.candidates.len(), 1, "{p:?}");
        assert_eq!(p.candidates[0].name, "dup");
        assert_eq!(p.candidates[0].adds_percent, 0.0);
        assert_eq!(p.candidates[0].loses_at_most, 0);
        assert_eq!(p.loses_at_most, 0);
        let why = |n: &str| p.kept.iter().find(|k| k.name == n).unwrap().reason.clone();
        assert!(why("mixed").contains("adds 20%"), "{}", why("mixed"));
        assert!(why("big").contains("adds 90%"), "{}", why("big"));
    }

    // REQ: FLT-004 (T24.28) - two lists that mirror each other are never both proposed: the
    // second would lose everything the first still covers.
    #[test]
    fn flt_004_prune_plan_never_proposes_both_of_two_mirrors() {
        let lists = vec![
            list("a", 100, 0, &[("b", 100)]),
            list("b", 100, 0, &[("a", 100)]),
        ];
        let p = plan(&lists, &[], 1.0, 100);
        assert_eq!(p.candidates.len(), 1);
        assert_eq!(p.candidates[0].name, "a");
        assert!(
            p.kept[0].reason.contains("together"),
            "{}",
            p.kept[0].reason
        );
        assert_eq!(p.loses_at_most, 0);
    }

    // REQ: FLT-004 (T24.28) - the loss bound adds the names the plan's lists share: three lists
    // with the same 50 names, two proposed at 50 %, lose at most their unique and shared names.
    #[test]
    fn flt_004_prune_plan_bounds_what_the_set_loses() {
        let lists = vec![
            list("keep", 1000, 1000, &[]),
            list("x", 100, 2, &[("y", 10)]),
            list("y", 100, 2, &[("x", 10)]),
        ];
        let p = plan(&lists, &[], 15.0, 1200);
        assert_eq!(p.candidates.len(), 2, "{p:?}");
        // 2 + 2 unique, and the 10 names they share (pair counted once).
        assert_eq!(p.loses_at_most, 14);
        assert!(p.note.contains("at most 14 of 1200"), "{}", p.note);
    }

    // REQ: FLT-004 (T24.28, ADR-992) - allow lists, shadow lists, lists without entries and
    // lists a group names are never proposed; names a shadow list shares don't count as covered;
    // regexes and modifier rules count as unique.
    #[test]
    fn flt_004_prune_plan_keeps_what_cannot_be_judged() {
        let mut allow = list("allow", 10, 0, &[]);
        allow.kind = "allow".into();
        let mut shadow = list("shadow", 100, 0, &[("covered", 100)]);
        shadow.mode = "shadow".into();
        let mut rules = list("rules", 100, 0, &[("big", 100)]);
        rules.rules = 50;
        let lists = vec![
            list("big", 500, 500, &[("rules", 100), ("covered", 100)]),
            allow,
            shadow,
            list("empty", 0, 0, &[]),
            list("named", 100, 0, &[("big", 100)]),
            rules,
            list("covered", 100, 0, &[("big", 100), ("shadow", 100)]),
        ];
        let groups = vec![group("kids", &["named"])];
        let p = plan(&lists, &groups, 1.0, 1000);
        assert!(p.candidates.is_empty(), "{:?}", p.candidates);
        let why = |n: &str| p.kept.iter().find(|k| k.name == n).unwrap().reason.clone();
        assert!(why("allow").starts_with("allow list"));
        assert!(why("shadow").starts_with("shadow mode"));
        assert!(why("empty").starts_with("no entries"));
        assert!(why("named").contains("group `kids`"));
        assert!(why("rules").contains("adds 50%"), "{}", why("rules"));
        // Everything of `covered` is also in a shadow list, which blocks nothing.
        assert!(why("covered").contains("adds 100%"), "{}", why("covered"));
    }

    // REQ: FLT-004 (T24.28) - the overlap rows: enabled lists only, what each adds, who covers it,
    // and the groups that name it.
    #[test]
    fn flt_004_overlap_rows_show_what_each_list_adds() {
        let mut off = list("off", 10, 10, &[]);
        off.enabled = false;
        let mut rules = list("b", 200, 10, &[("a", 150)]);
        rules.rules = 10;
        let lists = vec![list("a", 200, 100, &[("b", 150)]), off, rules];
        let groups = vec![group("kids", &["a"])];
        let r = rows(&lists, &groups);
        assert_eq!(r.len(), 2);
        assert_eq!((r[0].name.as_str(), r[0].adds_percent), ("a", 50.0));
        assert_eq!(r[0].covered_by[0].percent, 75.0);
        assert_eq!(r[0].groups, ["kids"]);
        assert_eq!(r[1].adds_percent, 10.0, "unique + rules over entries");
    }

    // REQ: FLT-004 (T24.28, ADR-992 item 6) - a list that covered another is now off (a first
    // prune, before the compile ran): the old overlap still names it, but it covers nothing, so
    // the second list is not proposed, and the plan says a compile is pending.
    #[test]
    fn flt_004_prune_plan_ignores_cover_by_a_list_now_off() {
        let mut a = list("a", 100, 0, &[("b", 100)]);
        a.enabled = false;
        let b = list("b", 100, 0, &[("a", 100)]);
        let p = plan(&[a, b], &[], 1.0, 100);
        assert!(p.candidates.is_empty(), "{p:?}");
        assert!(p.compile_pending);
        assert!(p.note.contains("compile is pending"), "{}", p.note);
        // A list deleted from the configuration is the same.
        let b = list("b", 100, 0, &[("gone", 100)]);
        let p = plan(&[b], &[], 1.0, 100);
        assert!(p.candidates.is_empty() && p.compile_pending, "{p:?}");
        // A cover that is now in shadow mode is not a cover either.
        let mut a = list("a", 100, 0, &[("b", 100)]);
        a.mode = "shadow".into();
        let b = list("b", 100, 0, &[("a", 100)]);
        let p = plan(&[a, b], &[], 1.0, 100);
        assert!(p.candidates.is_empty() && !p.compile_pending, "{p:?}");
    }

    // REQ: FLT-004 (T24.28) - an overlap naming a service's synthetic `svc-` list is not a stale
    // compile: the list has no row, and it covers nothing for the plan.
    #[test]
    fn flt_004_prune_plan_not_pending_for_service_lists() {
        let a = list("a", 100, 0, &[("svc-tiktok", 10)]);
        let p = plan(&[a], &[], 1.0, 100);
        assert!(!p.compile_pending, "{p:?}");
        assert!(p.candidates.is_empty(), "{p:?}");
    }

    // REQ: FLT-004 (T24.28) - the first check is exact, so a list just over the threshold is kept
    // with the "adds" reason, not the "together with the others" one.
    #[test]
    fn flt_004_prune_plan_near_threshold_is_exact() {
        // 1.04 % adds, rounded to 1.0, at a threshold of 1.
        let lists = vec![
            list("big", 10_000, 10_000, &[]),
            list("near", 10_000, 104, &[]),
        ];
        let p = plan(&lists, &[], 1.0, 20_000);
        assert!(p.candidates.is_empty(), "{p:?}");
        let why = &p.kept.iter().find(|k| k.name == "near").unwrap().reason;
        assert!(why.starts_with("adds"), "{why}");
    }
}

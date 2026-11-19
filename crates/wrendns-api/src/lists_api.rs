//! REQ: FLT-004, AGT-002, AGT-003, AGT-005 — "update lists now" (`POST /api/v1/lists/refresh`,
//! like Pi-hole's `pihole -g`): download every enabled list again (or the ones named) without
//! waiting for their schedule; the filter is recompiled if anything changed. Lists download where
//! they're compiled: this node, or in a cluster the primary (a replica forwards, CLU-003). It
//! changes no configuration, so a GitOps-managed cluster takes it too. Needs an operator (agents:
//! `config:write:lists`, the scope that can already make a list download by saving it);
//! `?dryRun=true` says what would be queued; `Idempotency-Key` replays the first answer for 24
//! hours; audit-logged as `lists.refresh`. Progress is `refreshing` in `GET /api/v1/lists`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use wrendns_store::state::Replay;

use crate::auth::Auth;
use crate::auth::routes::{principal, reason, remote};
use crate::config_api::{IDEMPOTENCY_KEY, PlainDryRun};
use crate::model::{ListRefreshSkip, ListsRefreshRequest, ListsRefreshResult};
use crate::problem::{Code, Problem};
use crate::{ListsRefreshWrite, Shared};

/// The most lists one request may name.
pub const MAX_NAMES: usize = 256;

/// The refresh (operator).
pub(crate) fn routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/lists/refresh", post(refresh_lists))
        .with_state((backend, auth))
}

/// This node doesn't download lists.
pub fn not_here() -> Problem {
    Problem::new(
        Code::ListsNotHere,
        "this node doesn't download filter lists",
    )
    .hint("Ask a node with role `all` or `controller` (in a cluster, the primary), or see the log for why the list fetcher didn't start.")
}

/// The request's names: trimmed, without repeats, in the order given; `None` (every enabled
/// list) when absent or empty.
pub fn names(req: &ListsRefreshRequest) -> Result<Option<Vec<String>>, Problem> {
    let Some(given) = &req.names else {
        return Ok(None);
    };
    if given.len() > MAX_NAMES {
        return Err(
            Problem::invalid(format!("`names`: at most {MAX_NAMES} lists"))
                .hint("Leave `names` out to refresh every enabled list."),
        );
    }
    let mut out: Vec<String> = Vec::new();
    for n in given {
        let n = n.trim();
        if n.is_empty() {
            return Err(Problem::invalid("`names`: a list name is empty")
                .hint("Use the names from GET /api/v1/lists."));
        }
        if n.chars().any(char::is_control) {
            return Err(
                Problem::invalid("`names`: a list name has a control character")
                    .hint("Use the names from GET /api/v1/lists."),
            );
        }
        if !out.iter().any(|o| o == n) {
            out.push(n.to_owned());
        }
    }
    Ok((!out.is_empty()).then_some(out))
}

/// REQ: FLT-004 — what a refresh of `names` (`None`: every enabled list) covers among the
/// `configured` lists (`(name, enabled)`, in configuration order): the lists to download, and
/// the named ones left out (disabled). A name nobody configured is refused (404).
pub fn plan(
    configured: &[(String, bool)],
    names: Option<&[String]>,
) -> Result<(Vec<String>, Vec<ListRefreshSkip>), Problem> {
    let Some(names) = names else {
        let queued = configured
            .iter()
            .filter(|(_, on)| *on)
            .map(|(n, _)| n.clone())
            .collect();
        return Ok((queued, Vec::new()));
    };
    let unknown: Vec<&str> = names
        .iter()
        .filter(|n| !configured.iter().any(|(c, _)| c == *n))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        let known: Vec<&str> = configured.iter().map(|(n, _)| n.as_str()).collect();
        let hint = if known.is_empty() {
            "No lists are configured yet.".to_owned()
        } else {
            format!("Lists: {}.", known.join(", "))
        };
        return Err(Problem::not_found(format!(
            "no list named {}",
            unknown
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .hint(hint));
    }
    let mut queued = Vec::new();
    let mut skipped = Vec::new();
    for (name, on) in configured {
        if !names.contains(name) {
            continue;
        }
        if *on {
            queued.push(name.clone());
        } else {
            skipped.push(ListRefreshSkip {
                name: name.clone(),
                reason: "disabled".into(),
            });
        }
    }
    Ok((queued, skipped))
}

/// The answer's `note`.
pub fn note(dry_run: bool, queued: &[String], already: &[String]) -> String {
    match (dry_run, queued.len()) {
        (_, 0) => "Nothing to download: no enabled list matched.".into(),
        (true, n) => format!(
            "Nothing changed (dry run). {n} {} would be downloaded again now.",
            if n == 1 { "list" } else { "lists" }
        ),
        (false, n) => {
            let mut s = format!(
                "{n} {} queued: unchanged sources cost one conditional request each, and the filter is recompiled only if something changed. Watch `refreshing` and `lastSuccessUnixSeconds` in GET /api/v1/lists.",
                if n == 1 { "list" } else { "lists" }
            );
            if !already.is_empty() {
                s.push_str(" Lists already downloading are downloaded once more when that ends.");
            }
            s
        }
    }
}

/// Update lists now.
///
/// Downloads every enabled filter list again now (or only the lists in `names`), without
/// waiting for their `refresh_secs` schedule, like Pi-hole's "Update Gravity" (`pihole -g`).
/// Answers 202 at once with what was queued; the downloads run in the background, and
/// `refreshing` in `GET /api/v1/lists` is true until each list's download ends
/// (`lastSuccessUnixSeconds` then moves on). Unchanged sources cost one conditional request
/// each, and the filter snapshot is recompiled only when something changed (it then serves
/// within seconds). A failed download keeps the last good copy. Disabled lists are left out
/// (`skipped`). In a cluster the primary downloads and compiles the lists every node serves:
/// a replica forwards the request (503 when it can't reach the primary; replicas keep serving
/// the last lists). `?dryRun=true` says what would be queued and queues nothing.
/// `Idempotency-Key` replays the first answer for 24 hours. It changes no configuration (a
/// GitOps-managed cluster takes it too). Needs the operator role (agents: the
/// `config:write:lists` scope and a reason); audit-logged as `lists.refresh`.
#[utoipa::path(post, path = "/api/v1/lists/refresh", tag = "config",
    params(PlainDryRun),
    request_body(content = Option<ListsRefreshRequest>, description = "Optional: `{}` or no body refreshes every enabled list."),
    responses(
        (status = 202, body = ListsRefreshResult, description = "Queued (or, with dryRun, what would be): the lists, the ones left out, and the node that downloads them."),
        (status = 400, body = Problem, description = "A malformed body or an empty name."),
        (status = 403, body = Problem, description = "Needs the operator role (agents: config:write:lists)."),
        (status = 404, body = Problem, description = "No list by one of those names (the hint lists them)."),
        (status = 409, body = Problem, description = "This node doesn't download lists (`lists_not_here`: role resolver), or an Idempotency-Key reused for another request."),
        (status = 503, body = Problem, description = "A cluster replica that can't reach the primary (it downloads the lists)."),
    ))]
pub(crate) async fn refresh_lists(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Query(query): Query<PlainDryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    body: Bytes,
) -> Response {
    let req: ListsRefreshRequest = if body.iter().all(u8::is_ascii_whitespace) {
        ListsRefreshRequest::default()
    } else {
        match serde_json::from_slice::<Option<ListsRefreshRequest>>(&body) {
            Ok(r) => r.unwrap_or_default(),
            Err(e) => {
                return Problem::invalid(format!("request body: {e}"))
                    .hint("Send {} for every enabled list, or {\"names\": [\"<list>\"]}.")
                    .into_response();
            }
        }
    };
    let names = match names(&req) {
        Ok(n) => n,
        Err(e) => return e.into_response(),
    };
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let dry_run = query.dry_run.unwrap_or(false);
    // REQ: AGT-003 — a retried request gets the first answer; another request with the same key
    // is refused.
    let request = format!(
        "POST /lists/refresh {}",
        serde_json::json!({ "names": names })
    );
    let key = headers
        .get(IDEMPOTENCY_KEY)
        .and_then(|v| v.to_str().ok())
        .map(|k| format!("{}:{}", p.user_id, k.trim()))
        .filter(|k| !dry_run && k.len() > 2);
    // REQ: API-014 (ADR-903 §4) — the record keeps a keyed hash of the request, never its text.
    let fingerprint = if key.is_some() {
        match backend.idempotency_request(None, &request, None) {
            Ok(f) => Some(f),
            Err(e) => return e.into_response(),
        }
    } else {
        None
    };
    let now = backend.now_unix_seconds();
    if let Some(k) = &key {
        match auth.state().idempotent(k, now) {
            Ok(Some(r)) if fingerprint.as_ref() == Some(&r.request) => {
                return crate::config_api::replay(&r);
            }
            Ok(Some(_)) => {
                return Problem::new(
                    Code::Conflict,
                    "this Idempotency-Key was used for a different request",
                )
                .hint("Use a new key for each distinct request.")
                .into_response();
            }
            Ok(None) => {}
            Err(e) => return Problem::internal(e.to_string()).into_response(),
        }
    }
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let w = ListsRefreshWrite {
        names: names.clone(),
        dry_run,
        by: actor.name.clone(),
        reason: actor.reason.clone(),
    };
    match backend.lists_refresh(w).await {
        Ok(r) => {
            if !dry_run {
                let target = match &names {
                    None => "*".to_owned(),
                    Some(n) => n.join(", "),
                };
                auth.record(
                    &actor,
                    "lists.refresh",
                    &target,
                    &serde_json::json!({ "queued": r.queued, "skipped": r.skipped, "node": r.node }),
                );
            }
            let text = serde_json::to_string(&r).unwrap_or_default();
            if let (Some(k), Some(fp)) = (&key, &fingerprint) {
                let rep = Replay {
                    request: fp.clone(),
                    status: StatusCode::ACCEPTED.as_u16(),
                    response: text,
                };
                if let Err(e) = auth.state().remember_idempotent(k, &rep, now) {
                    tracing::warn!("idempotency key not stored: {e}");
                }
            }
            (StatusCode::ACCEPTED, Json(r)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// REQ: FLT-004 — a refresh's answer for the lists of `configured` on the node that downloads
/// them; `refreshing` says whether a list is downloading already, `queue` queues the download
/// (not called for a dry run or when nothing matched).
pub fn answer(
    configured: &[(String, bool)],
    w: &ListsRefreshWrite,
    node: Option<String>,
    refreshing: impl Fn(&str) -> bool,
    queue: impl FnOnce(Option<&[String]>),
) -> Result<ListsRefreshResult, Problem> {
    let (queued, skipped) = plan(configured, w.names.as_deref())?;
    let already: Vec<String> = queued.iter().filter(|n| refreshing(n)).cloned().collect();
    if !w.dry_run && !queued.is_empty() {
        queue(w.names.as_ref().map(|_| queued.as_slice()));
    }
    Ok(ListsRefreshResult {
        dry_run: w.dry_run,
        note: note(w.dry_run, &queued, &already),
        queued,
        skipped,
        already_refreshing: already,
        node,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured() -> Vec<(String, bool)> {
        vec![
            ("hagezi".into(), true),
            ("old".into(), false),
            ("mine".into(), true),
        ]
    }

    fn write(names: Option<&[&str]>, dry_run: bool) -> ListsRefreshWrite {
        ListsRefreshWrite {
            names: names.map(|n| n.iter().map(|s| (*s).to_owned()).collect()),
            dry_run,
            by: "alice".into(),
            reason: None,
        }
    }

    // REQ: FLT-004 — every enabled list by default, the named ones otherwise (disabled ones
    // skipped with the reason), and an unknown name is a 404 whose hint lists the names.
    #[test]
    fn flt_004_refresh_plans_the_lists_named() {
        let (q, s) = plan(&configured(), None).unwrap();
        assert_eq!((q, s.len()), (vec!["hagezi".into(), "mine".into()], 0));
        let names = ["mine".to_owned(), "old".to_owned()];
        let (q, s) = plan(&configured(), Some(&names)).unwrap();
        assert_eq!(q, ["mine"]);
        assert_eq!(
            (s[0].name.as_str(), s[0].reason.as_str()),
            ("old", "disabled")
        );
        let e = plan(&configured(), Some(&["nope".to_owned()])).unwrap_err();
        assert_eq!((e.code, e.status), (Code::NotFound, 404));
        assert!(e.detail.contains("`nope`"), "{}", e.detail);
        assert!(
            e.hint
                .as_deref()
                .is_some_and(|h| h.contains("hagezi, old, mine")),
            "{:?}",
            e.hint
        );
    }

    // REQ: FLT-004, AGT-001 — names are trimmed and deduplicated; empty means every list;
    // blank names and too many are 400s.
    #[test]
    fn flt_004_refresh_names_are_checked() {
        let req =
            |v: serde_json::Value| -> ListsRefreshRequest { serde_json::from_value(v).unwrap() };
        assert_eq!(names(&req(serde_json::json!({}))).unwrap(), None);
        assert_eq!(names(&req(serde_json::json!({"names": []}))).unwrap(), None);
        assert_eq!(
            names(&req(serde_json::json!({"names": [" a ", "a", "b"]}))).unwrap(),
            Some(vec!["a".to_owned(), "b".to_owned()])
        );
        assert_eq!(
            names(&req(serde_json::json!({"names": [" "]})))
                .unwrap_err()
                .status,
            400
        );
        let many: Vec<String> = (0..=MAX_NAMES).map(|i| format!("l{i}")).collect();
        assert_eq!(
            names(&req(serde_json::json!({ "names": many })))
                .unwrap_err()
                .status,
            400
        );
        assert!(
            serde_json::from_value::<ListsRefreshRequest>(serde_json::json!({"all": true}))
                .is_err()
        );
    }

    // REQ: FLT-004, AGT-002 — a dry run queues nothing; a refresh queues the lists named (or
    // every list), and says which are downloading already.
    #[test]
    fn flt_004_refresh_answer_queues_unless_dry_run() {
        let queued = std::cell::RefCell::new(Vec::new());
        let r = answer(
            &configured(),
            &write(None, true),
            Some("pi".into()),
            |_| false,
            |n| queued.borrow_mut().push(n.map(<[String]>::to_vec)),
        )
        .unwrap();
        assert!(r.dry_run && queued.borrow().is_empty());
        assert_eq!(r.queued, ["hagezi", "mine"]);
        assert!(r.note.contains("dry run"), "{}", r.note);

        let r = answer(
            &configured(),
            &write(None, false),
            Some("pi".into()),
            |n| n == "mine",
            |n| queued.borrow_mut().push(n.map(<[String]>::to_vec)),
        )
        .unwrap();
        assert_eq!(*queued.borrow(), [None], "every list");
        assert_eq!(r.already_refreshing, ["mine"]);
        assert_eq!(r.node.as_deref(), Some("pi"));

        queued.borrow_mut().clear();
        answer(
            &configured(),
            &write(Some(&["mine", "old"]), false),
            None,
            |_| false,
            |n| queued.borrow_mut().push(n.map(<[String]>::to_vec)),
        )
        .unwrap();
        assert_eq!(*queued.borrow(), [Some(vec!["mine".to_owned()])]);

        // Only a disabled list named: nothing to queue.
        queued.borrow_mut().clear();
        let r = answer(
            &configured(),
            &write(Some(&["old"]), false),
            None,
            |_| false,
            |n| queued.borrow_mut().push(n.map(<[String]>::to_vec)),
        )
        .unwrap();
        assert!(queued.borrow().is_empty() && r.queued.is_empty());
        assert!(r.note.starts_with("Nothing to download"), "{}", r.note);
    }
}

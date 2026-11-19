//! REQ: DSC-901, DSC-902, DSC-903, DSC-906 (T31.2, ADR-1004, ADR-1005 sections 8 and 13) - the CMDB's
//! API for this task: its status, a page of CIs, one CI with its source records side by side, and
//! the manual link, unlink, merge and split (each with `?dryRun=true`, an `Idempotency-Key` and an
//! audit entry). The complete read API (filters, scopes, MCP tools, the federated read) is T31.5.
//!
//! The CMDB runs on the node `[discovery]` designates. A node that is not it answers 503 with a hint
//! naming the designated node (forwarding is T31.5), and DNS is unaffected either way. Reads need a
//! viewer, writes an operator; no agent scope reaches any of these routes (ADR-1005 section 9: the
//! scopes `cmdb:read` and `ops:cmdb` arrive with T31.5, in no default or wildcard grant). Everything
//! a device said is untrusted text, cut and cleaned (DSC-015).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use telltale_store::state::Replay;
use utoipa::{IntoParams, ToSchema};

use crate::auth::Auth;
use crate::auth::routes::{principal, reason, remote};
use crate::config_api::{IDEMPOTENCY_KEY, PlainDryRun};
use crate::problem::{Code, Problem};
use crate::Shared;

// -- model -------------------------------------------------------------------------------------

/// `GET /api/v1/cmdb/status`: whether the CMDB runs on this node, what it holds, and what it
/// dropped. Health reasons never mark DNS unhealthy.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbStatus {
    /// `[cmdb] enabled`.
    pub enabled: bool,
    /// Whether this node is the designated one (the node `[discovery]` designates).
    pub designated: bool,
    /// The designated node's name, when `[discovery] node` names one.
    pub node: Option<String>,
    /// Whether the CMDB's thread runs here.
    pub running: bool,
    /// The end of the 24 h learning period (Unix seconds), while it runs.
    pub learning_until: Option<i64>,
    /// CIs by type.
    pub cis: Vec<CmdbCount>,
    /// Source records kept, and those `present`.
    pub records: u64,
    pub records_present: u64,
    /// Merge proposals waiting for a person.
    pub proposals_open: u64,
    /// The last batch of each source instance.
    pub sources: Vec<CmdbSourceStatus>,
    /// Batches waiting in the sink.
    pub queue_depth: u64,
    /// What was dropped at a cap.
    pub dropped: CmdbDropped,
    /// The caps (ADR-1005 section 3).
    pub caps: CmdbCaps,
    /// The database and its WAL on disk, in bytes.
    pub disk_bytes: u64,
    /// The in-memory index, an estimate in bytes.
    pub index_bytes: u64,
    /// The newest authored-row stamp: what a standby copies.
    pub head_epoch: i64,
    pub head_seq: i64,
    /// The last error the CMDB logged, when it had one (it never touches DNS).
    pub last_error: Option<String>,
}

/// A count of CIs of one type.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbCount {
    /// `device`, `interface`, `network`, `node`, `service` or `upstream`.
    pub ty: String,
    pub count: u64,
}

/// One source instance's last batch.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbSourceStatus {
    /// The source instance (`unifi:home`, `snmp:core`, `neighbor`, ...).
    pub source: String,
    /// Records in its last batch.
    pub records: u64,
    /// Records it holds in the database.
    pub held: u64,
    /// When its last batch was ingested (Unix seconds).
    pub last_batch_unix: i64,
    /// Whether the batch listed everything the instance reports.
    pub complete: bool,
    pub batches: u64,
}

/// What the CMDB dropped at a cap (`telltale_cmdb_dropped_total`).
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbDropped {
    /// New CIs refused because every CI left is authored (at the cap).
    pub ci: u64,
    /// New records dropped at the record caps.
    pub record: u64,
    /// Batches the sink dropped because it was full.
    pub batch: u64,
}

/// The caps (ADR-1005 section 3).
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbCaps {
    pub cis: u64,
    pub records: u64,
    pub records_per_ci: u64,
}

/// One CI in a list.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbCi {
    /// `ci_` and 32 hex digits, random and never reused.
    #[schema(example = "ci_0f3a9c1e5b7d42a8c6e0b1d3f5a79c21")]
    pub id: String,
    /// `device`, `interface`, `network`, `node`, `service` or `upstream`.
    pub ty: String,
    /// For an interface: `nic` or `port`.
    pub kind: Option<String>,
    /// The name shown. Device-supplied text (cut and cleaned).
    pub name: Option<String>,
    /// For an interface: the device it belongs to.
    pub parent: Option<String>,
    /// No source confirms it yet (a query-only or import-only record).
    pub unconfirmed: bool,
    /// A port that no alias joins to another source's port.
    pub unmapped_port: bool,
    /// When the CMDB first saw it (Unix seconds).
    pub first_seen: i64,
    /// The newest time a presence source saw it, when known.
    pub last_seen: Option<i64>,
    /// Distinct days a presence source saw it, at most 32.
    pub days_seen: Option<i64>,
    /// How many source records are linked to it.
    pub records: u64,
    /// The source kinds that report it.
    pub sources: Vec<String>,
    /// Open merge proposals that name it.
    pub proposals: u64,
}

/// A page of CIs.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbCiPage {
    pub items: Vec<CmdbCi>,
    /// Pass this as `after` for the next page; absent on the last.
    pub next: Option<String>,
}

/// One source record, as the source reported it.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbRecord {
    pub source: String,
    /// The thing's identity in that source.
    pub key: String,
    /// `device`, `port`, `network`, `node`, `service` or `upstream`.
    pub ty: String,
    /// `present`, or `absent` after two missed complete batches.
    pub state: String,
    /// `auto:R2`, `auto:R3`, `auto:R4`, `auto:addr`, `auto:key`, `auto:port`, `auto:own`, `manual`
    /// or `none`.
    pub link: String,
    pub first_seen: i64,
    pub last_changed: i64,
    pub last_seen: i64,
    /// The interface and the device it is linked to.
    pub interface: Option<String>,
    pub device: Option<String>,
    /// The attributes as reported: device-supplied text, untrusted.
    #[schema(value_type = Object)]
    pub attrs: serde_json::Value,
}

/// A merge proposal: raised, never applied (ADR-1004 section 4).
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbProposal {
    pub id: i64,
    /// `level_disagreement`, `host_network` or `ambiguous_record`.
    pub kind: String,
    /// The two CIs it names.
    pub a: String,
    pub b: String,
    /// The rule that raised it: `R3`, `R4`, `R5` or `addr`.
    pub rule: String,
    pub detail: String,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// A manual decision pinned to a CI.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbPin {
    /// `nic_device`, `rec_device` or `rec_never`.
    pub kind: String,
    pub subject: String,
    pub target: String,
    pub at: i64,
    pub by: String,
    pub reason: String,
}

/// A merged-away id that redirects for 90 days.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbAlias {
    pub id: String,
    pub until: i64,
}

/// `GET /api/v1/cmdb/cis/{id}`: a CI with its interfaces, its records side by side and what
/// reconciliation decided.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbCiDetail {
    pub ci: CmdbCi,
    /// The interfaces and ports under a device.
    pub interfaces: Vec<CmdbCi>,
    pub records: Vec<CmdbRecord>,
    pub proposals: Vec<CmdbProposal>,
    pub pins: Vec<CmdbPin>,
    /// Ids merged into this CI that still redirect.
    pub aliases: Vec<CmdbAlias>,
}

/// A record by its source and key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CmdbRecordRef {
    /// The source instance, as `GET /api/v1/cmdb/cis/{id}` shows it.
    #[schema(example = "unifi:home")]
    pub source: String,
    /// The record's key in that source.
    #[schema(example = "aa:bb:cc:00:00:01")]
    pub key: String,
}

/// Body of `POST /api/v1/cmdb/cis/{id}/link`: put a record (its interface, when it has a MAC) under
/// the device in the path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CmdbLinkRequest {
    pub record: CmdbRecordRef,
}

/// Body of `POST /api/v1/cmdb/cis/{id}/unlink`: take a record away from the device in the path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CmdbUnlinkRequest {
    pub record: CmdbRecordRef,
}

/// Body of `POST /api/v1/cmdb/cis/{id}/merge`: fold the device in the path into another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CmdbMergeRequest {
    /// The device that stays; the one in the path becomes an alias of it for 90 days.
    #[schema(example = "ci_0f3a9c1e5b7d42a8c6e0b1d3f5a79c21")]
    pub into: String,
}

/// Body of `POST /api/v1/cmdb/cis/{id}/split`: move chosen records of the device in the path to a
/// new device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CmdbSplitRequest {
    pub records: Vec<CmdbRecordRef>,
}

/// One record a change moves.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbMove {
    pub source: String,
    pub key: String,
    /// The device it is on now.
    pub from: Option<String>,
    /// The device it goes to; absent for a new device.
    pub to: Option<String>,
    /// `its interface` (a MAC identifies an interface, so all its records go), `chosen` or `device`.
    pub why: String,
}

/// What a link, unlink, merge or split would do, or did.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmdbChange {
    /// `link`, `unlink`, `merge` or `split`.
    pub op: String,
    /// Whether it was applied (`false` for `?dryRun=true`).
    pub applied: bool,
    /// The records that move.
    pub moves: Vec<CmdbMove>,
    /// The devices it touches.
    pub devices: Vec<String>,
    /// What else follows: an alias that redirects, a pin that is written.
    pub notes: Vec<String>,
    /// The device the records went to when it is new (a split or an unlink), or the one that
    /// stayed (a merge).
    pub result: Option<String>,
}

/// A manual change as the API checked it, ready for the node that runs the CMDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmdbOp {
    Link { source: String, key: String, to: String },
    Unlink { source: String, key: String, device: String },
    Merge { from: String, into: String },
    Split { device: String, records: Vec<CmdbRecordRef> },
}

/// A write to the CMDB.
#[derive(Debug, Clone)]
pub struct CmdbWrite {
    pub op: CmdbOp,
    pub dry_run: bool,
    /// Who asked: the actor's name.
    pub by: String,
    /// Why, as the user gave it (`X-Telltale-Reason`), kept with the pin and the audit entry.
    pub reason: Option<String>,
}

/// The query of `GET /api/v1/cmdb/cis`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct CmdbQuery {
    /// Only CIs of this type: `device`, `interface`, `network`, `node`, `service` or `upstream`.
    #[serde(default, rename = "type")]
    pub ty: Option<String>,
    /// Text to find in a name, an id, a MAC, a serial or a source record.
    #[serde(default)]
    pub q: Option<String>,
    /// The cursor: the `next` of the previous page.
    #[serde(default)]
    pub after: Option<String>,
    /// Page size, 1 to 500 (default 100).
    #[serde(default)]
    pub limit: Option<u32>,
}

// -- routes ------------------------------------------------------------------------------------

/// The read routes (viewer).
pub(crate) fn read_routes(backend: Shared) -> Router {
    Router::new()
        .route("/api/v1/cmdb/status", get(cmdb_status))
        .route("/api/v1/cmdb/cis", get(cmdb_cis))
        .route("/api/v1/cmdb/cis/{id}", get(cmdb_ci))
        .route("/api/v1/cmdb/proposals", get(cmdb_proposals))
        .with_state(backend)
}

/// The write routes (operator).
pub(crate) fn write_routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/cmdb/cis/{id}/link", post(cmdb_link))
        .route("/api/v1/cmdb/cis/{id}/unlink", post(cmdb_unlink))
        .route("/api/v1/cmdb/cis/{id}/merge", post(cmdb_merge))
        .route("/api/v1/cmdb/cis/{id}/split", post(cmdb_split))
        .with_state((backend, auth))
}

/// This node doesn't run the CMDB: it is off, or another node is the designated one. 503, with a
/// hint that names the node (DNS is unaffected, CLU-004).
pub fn not_here(enabled: bool, designated_node: Option<&str>) -> Problem {
    let detail = if enabled {
        "this node doesn't run the CMDB".to_owned()
    } else {
        "the CMDB is off".to_owned()
    };
    let hint = match (enabled, designated_node) {
        (false, _) => "Turn on [cmdb] (Settings, CMDB) first.".to_owned(),
        (true, Some(n)) => format!(
            "Ask the designated node: `{n}`. If it is down, nothing runs until an admin clears or changes `[discovery] node`; DNS is unaffected."
        ),
        (true, None) => {
            "Ask the designated node (the cluster's primary, or the node `[discovery] node` names)."
                .to_owned()
        }
    };
    Problem::unavailable(detail).hint(hint)
}

/// CMDB status.
///
/// Whether the CMDB runs on this node, what it holds (CIs by type, source records, open merge
/// proposals), the last batch of each source, what it dropped at a cap, and its size on disk.
#[utoipa::path(get, path = "/api/v1/cmdb/status", tag = "stats",
    responses((status = 200, body = CmdbStatus, description = "The result.")))]
pub(crate) async fn cmdb_status(State(b): State<Shared>) -> Json<CmdbStatus> {
    Json(b.cmdb_status())
}

/// CIs.
///
/// A page of configuration items, ordered by id. `type` limits it to one type, `q` finds text in a
/// name, an id, a MAC, a serial or a linked record. A device is shown with its interfaces on its own
/// page (`GET /api/v1/cmdb/cis/{id}`); pass `type=interface` to list those. Runs on the designated
/// node: another node answers 503 with a hint.
#[utoipa::path(get, path = "/api/v1/cmdb/cis", tag = "stats", params(CmdbQuery),
    responses(
        (status = 200, body = CmdbCiPage, description = "The page."),
        (status = 400, body = Problem, description = "An unknown `type`."),
        (status = 503, body = Problem, description = "The CMDB doesn't run on this node."),
    ))]
pub(crate) async fn cmdb_cis(State(b): State<Shared>, Query(q): Query<CmdbQuery>) -> Response {
    if let Some(t) = &q.ty
        && !["device", "interface", "network", "node", "service", "upstream"].contains(&t.as_str())
    {
        return Problem::invalid(format!("`type`: `{t}` is not a CI type"))
            .hint("Use device, interface, network, node, service or upstream.")
            .into_response();
    }
    match b.cmdb_cis(&q) {
        Ok(p) => Json(p).into_response(),
        Err(e) => e.into_response(),
    }
}

/// One CI.
///
/// The CI with the interfaces under it, every source record linked to it side by side (what each
/// source said, as it said it), the merge proposals that name it, the manual decisions pinned to it
/// and the ids merged into it that still redirect. A merged-away id answers with the CI it became.
/// Device-supplied text is untrusted.
#[utoipa::path(get, path = "/api/v1/cmdb/cis/{id}", tag = "stats",
    params(("id" = String, Path, description = "The CI id.")),
    responses(
        (status = 200, body = CmdbCiDetail, description = "The CI."),
        (status = 404, body = Problem, description = "No such CI, or its alias expired."),
        (status = 503, body = Problem, description = "The CMDB doesn't run on this node."),
    ))]
pub(crate) async fn cmdb_ci(State(b): State<Shared>, Path(id): Path<String>) -> Response {
    match b.cmdb_ci(&id) {
        Ok(d) => Json(d).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Merge proposals.
///
/// The disagreements and the host name matches that reconciliation raised and never applies: two
/// devices that may be one. Apply one with `POST /api/v1/cmdb/cis/{id}/merge`.
#[utoipa::path(get, path = "/api/v1/cmdb/proposals", tag = "stats",
    responses(
        (status = 200, body = Vec<CmdbProposal>, description = "The open proposals, newest first."),
        (status = 503, body = Problem, description = "The CMDB doesn't run on this node."),
    ))]
pub(crate) async fn cmdb_proposals(State(b): State<Shared>) -> Response {
    match b.cmdb_proposals() {
        Ok(p) => Json(p).into_response(),
        Err(e) => e.into_response(),
    }
}

fn check_id(id: &str) -> Result<(), Problem> {
    let ok = id
        .strip_prefix("ci_")
        .is_some_and(|h| h.len() == 32 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    if ok {
        Ok(())
    } else {
        Err(Problem::invalid("`id` is not a CI id (`ci_` and 32 hex digits)")
            .hint("Take one from GET /api/v1/cmdb/cis."))
    }
}

fn check_ref(r: &CmdbRecordRef) -> Result<(), Problem> {
    if r.source.trim().is_empty() || r.key.trim().is_empty() {
        return Err(Problem::invalid("`record` needs a `source` and a `key`")
            .hint("Take them from GET /api/v1/cmdb/cis/{id}, `records`."));
    }
    if r.source.len() > 128 || r.key.len() > 300 {
        return Err(Problem::invalid("`record`: the source or the key is too long"));
    }
    Ok(())
}

/// Runs one manual change: the body is parsed, the idempotent replay is checked, the node that
/// runs the CMDB does it, and the audit entry is written.
#[allow(clippy::too_many_arguments)] // one request: its parts
async fn run(
    backend: Shared,
    auth: Arc<Auth>,
    name: &'static str,
    dry_run: bool,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    request: String,
    op: CmdbOp,
    target: String,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    // REQ: AGT-003 - a retried request gets the first answer; another request with the same key is
    // refused.
    let key = headers
        .get(IDEMPOTENCY_KEY)
        .and_then(|v| v.to_str().ok())
        .map(|k| format!("{}:{}", p.user_id, k.trim()))
        .filter(|k| !dry_run && k.len() > 2);
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
    let w = CmdbWrite {
        op,
        dry_run,
        by: actor.name.clone(),
        reason: actor.reason.clone(),
    };
    match backend.cmdb_manual(w).await {
        Ok(r) => {
            if !dry_run {
                auth.record(
                    &actor,
                    name,
                    &target,
                    &serde_json::json!({
                        "moves": r.moves.len(),
                        "devices": r.devices,
                        "result": r.result,
                    }),
                );
            }
            let text = serde_json::to_string(&r).unwrap_or_default();
            if let (Some(k), Some(fp)) = (&key, &fingerprint) {
                let rep = Replay {
                    request: fp.clone(),
                    status: StatusCode::OK.as_u16(),
                    response: text,
                };
                if let Err(e) = auth.state().remember_idempotent(k, &rep, now) {
                    tracing::warn!("idempotency key not stored: {e}");
                }
            }
            (StatusCode::OK, Json(r)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

fn body<T: serde::de::DeserializeOwned>(b: &Bytes, hint: &str) -> Result<T, Problem> {
    serde_json::from_slice(b)
        .map_err(|e| Problem::invalid(format!("request body: {e}")).hint(hint.to_owned()))
}

/// Link a record to a device.
///
/// Puts the record under the device in the path. A record with a MAC moves its interface, with every
/// record of that MAC (a MAC identifies an interface), and pins it there: a serial or a device key
/// will not move it. A record with no key moves alone. With `?dryRun=true` nothing is written and the
/// answer lists the records that would move. Operators; audit-logged as `cmdb.link` with the reason
/// (`X-Telltale-Reason`); `Idempotency-Key` replays the first answer for 24 hours.
#[utoipa::path(post, path = "/api/v1/cmdb/cis/{id}/link", tag = "stats",
    params(("id" = String, Path, description = "The device the record goes to."), PlainDryRun),
    request_body = CmdbLinkRequest,
    responses(
        (status = 200, body = CmdbChange, description = "What moved, or with dryRun what would."),
        (status = 400, body = Problem, description = "A malformed body or id."),
        (status = 404, body = Problem, description = "No such device or record."),
        (status = 409, body = Problem, description = "The record is on that device already, or an Idempotency-Key reused for another request."),
        (status = 503, body = Problem, description = "The CMDB doesn't run on this node."),
    ))]
pub(crate) async fn cmdb_link(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Path(id): Path<String>,
    Query(q): Query<PlainDryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Bytes,
) -> Response {
    if let Err(e) = check_id(&id) {
        return e.into_response();
    }
    let req: CmdbLinkRequest = match body(&b, "Send {\"record\": {\"source\": \"...\", \"key\": \"...\"}}.") {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = check_ref(&req.record) {
        return e.into_response();
    }
    let request = format!("POST /cmdb/cis/{id}/link {}", serde_json::to_string(&req).unwrap_or_default());
    run(
        backend,
        auth,
        "cmdb.link",
        q.dry_run.unwrap_or(false),
        headers,
        ext,
        request,
        CmdbOp::Link {
            source: req.record.source,
            key: req.record.key,
            to: id.clone(),
        },
        id,
    )
    .await
}

/// Unlink a record from a device.
///
/// Takes the record away from the device in the path and writes a never-match pin, so the next batch
/// does not link it back. A record with no key may match another device, or stay on its own as an
/// unconfirmed CI. A record with a MAC leaves with its interface, which gets a device of its own (a
/// MAC identifies an interface). With `?dryRun=true` nothing is written. Operators; audit-logged as
/// `cmdb.unlink`; `Idempotency-Key` replays the first answer.
#[utoipa::path(post, path = "/api/v1/cmdb/cis/{id}/unlink", tag = "stats",
    params(("id" = String, Path, description = "The device the record is on."), PlainDryRun),
    request_body = CmdbUnlinkRequest,
    responses(
        (status = 200, body = CmdbChange, description = "What moved, or with dryRun what would."),
        (status = 400, body = Problem, description = "A malformed body or id."),
        (status = 404, body = Problem, description = "No such record."),
        (status = 409, body = Problem, description = "The record is not linked, or is the only interface of its device."),
        (status = 503, body = Problem, description = "The CMDB doesn't run on this node."),
    ))]
pub(crate) async fn cmdb_unlink(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Path(id): Path<String>,
    Query(q): Query<PlainDryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Bytes,
) -> Response {
    if let Err(e) = check_id(&id) {
        return e.into_response();
    }
    let req: CmdbUnlinkRequest = match body(&b, "Send {\"record\": {\"source\": \"...\", \"key\": \"...\"}}.") {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = check_ref(&req.record) {
        return e.into_response();
    }
    let request = format!("POST /cmdb/cis/{id}/unlink {}", serde_json::to_string(&req).unwrap_or_default());
    run(
        backend,
        auth,
        "cmdb.unlink",
        q.dry_run.unwrap_or(false),
        headers,
        ext,
        request,
        CmdbOp::Unlink {
            source: req.record.source,
            key: req.record.key,
            device: id.clone(),
        },
        id,
    )
    .await
}

/// Merge a device into another.
///
/// Moves every interface and record of the device in the path to `into`, pins them there, and leaves
/// the losing id as an alias that redirects for 90 days. With `?dryRun=true` nothing is written and
/// the answer lists the records that would move. Operators; audit-logged as `cmdb.merge`;
/// `Idempotency-Key` replays the first answer.
#[utoipa::path(post, path = "/api/v1/cmdb/cis/{id}/merge", tag = "stats",
    params(("id" = String, Path, description = "The device that goes away."), PlainDryRun),
    request_body = CmdbMergeRequest,
    responses(
        (status = 200, body = CmdbChange, description = "What moved, or with dryRun what would."),
        (status = 400, body = Problem, description = "A malformed body or id."),
        (status = 404, body = Problem, description = "No such device."),
        (status = 409, body = Problem, description = "A device cannot be merged into itself."),
        (status = 503, body = Problem, description = "The CMDB doesn't run on this node."),
    ))]
pub(crate) async fn cmdb_merge(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Path(id): Path<String>,
    Query(q): Query<PlainDryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Bytes,
) -> Response {
    if let Err(e) = check_id(&id) {
        return e.into_response();
    }
    let req: CmdbMergeRequest = match body(&b, "Send {\"into\": \"ci_...\"}.") {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = check_id(&req.into) {
        return e.into_response();
    }
    let request = format!("POST /cmdb/cis/{id}/merge {}", serde_json::to_string(&req).unwrap_or_default());
    run(
        backend,
        auth,
        "cmdb.merge",
        q.dry_run.unwrap_or(false),
        headers,
        ext,
        request,
        CmdbOp::Merge {
            from: id.clone(),
            into: req.into,
        },
        id,
    )
    .await
}

/// Split a device.
///
/// Moves the chosen records (a record with a MAC takes its interface and all its records) to a new
/// device and pins them there, so a serial or a device key does not join them back. At least one
/// interface stays. With `?dryRun=true` nothing is written. Operators; audit-logged as `cmdb.split`;
/// `Idempotency-Key` replays the first answer.
#[utoipa::path(post, path = "/api/v1/cmdb/cis/{id}/split", tag = "stats",
    params(("id" = String, Path, description = "The device to split."), PlainDryRun),
    request_body = CmdbSplitRequest,
    responses(
        (status = 200, body = CmdbChange, description = "What moved, or with dryRun what would."),
        (status = 400, body = Problem, description = "A malformed body or id, or no record chosen."),
        (status = 404, body = Problem, description = "No such device or record."),
        (status = 409, body = Problem, description = "A record is not on this device, or every interface would move."),
        (status = 503, body = Problem, description = "The CMDB doesn't run on this node."),
    ))]
pub(crate) async fn cmdb_split(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Path(id): Path<String>,
    Query(q): Query<PlainDryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Bytes,
) -> Response {
    if let Err(e) = check_id(&id) {
        return e.into_response();
    }
    let req: CmdbSplitRequest = match body(&b, "Send {\"records\": [{\"source\": \"...\", \"key\": \"...\"}]}.") {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    if req.records.is_empty() || req.records.len() > 64 {
        return Problem::invalid("`records`: choose from 1 to 64 records")
            .hint("Take them from GET /api/v1/cmdb/cis/{id}, `records`.")
            .into_response();
    }
    for r in &req.records {
        if let Err(e) = check_ref(r) {
            return e.into_response();
        }
    }
    let request = format!("POST /cmdb/cis/{id}/split {}", serde_json::to_string(&req).unwrap_or_default());
    run(
        backend,
        auth,
        "cmdb.split",
        q.dry_run.unwrap_or(false),
        headers,
        ext,
        request,
        CmdbOp::Split {
            device: id.clone(),
            records: req.records,
        },
        id,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DSC-906 - a node that doesn't run the CMDB says 503 and names the designated node; the CMDB
    /// being off says how to turn it on.
    #[test]
    fn dsc_906_not_here_is_503_with_a_hint() {
        let off = not_here(false, None);
        assert_eq!(off.status, 503);
        assert!(off.hint.as_deref().is_some_and(|h| h.contains("[cmdb]")));
        let other = not_here(true, Some("pi-a"));
        assert_eq!(other.status, 503);
        assert!(other.hint.as_deref().is_some_and(|h| h.contains("pi-a") && h.contains("DNS")));
    }

    /// REQ: DSC-903 - ids and record references are checked before anything else happens, and a body
    /// with another field is refused by name.
    #[test]
    fn dsc_903_requests_are_checked() {
        assert!(check_id("ci_0f3a9c1e5b7d42a8c6e0b1d3f5a79c21").is_ok());
        for bad in ["", "ci_", "ci_xyz", "0f3a9c1e5b7d42a8c6e0b1d3f5a79c21", "ci_0f3a9c1e5b7d42a8c6e0b1d3f5a79c2"] {
            assert_eq!(check_id(bad).unwrap_err().status, 400, "{bad}");
        }
        assert!(check_ref(&CmdbRecordRef { source: "unifi:home".into(), key: "k".into() }).is_ok());
        assert!(check_ref(&CmdbRecordRef { source: " ".into(), key: "k".into() }).is_err());
        assert!(
            serde_json::from_str::<CmdbMergeRequest>(r#"{"into":"ci_0","extra":1}"#).is_err(),
            "an unknown field is refused"
        );
    }
}

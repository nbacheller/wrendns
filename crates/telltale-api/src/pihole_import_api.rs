//! REQ: API-007 (T24.18, ADR-939, ADR-940, ADR-941) — importing a Pi-hole export. Admins only,
//! and never an agent: an import replaces configuration in bulk (spec/13 §3). The upload is
//! previewed first (nothing changes); the preview is a plan the same admin applies, as one
//! configuration change, audited as `import.pihole`.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{Extensions, HeaderMap};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, post};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::auth::Auth;
use crate::auth::routes::{principal, reason, remote};
use crate::problem::{Code, Problem};
use crate::{Backend, PiholeImportRequest};

type Ctx = (Arc<dyn Backend>, Arc<Auth>);

/// Most bytes an upload may have.
const UPLOAD_LIMIT: usize = 64 << 20;

/// The preview's options (`compare` is a Pi-hole address; `telltale` the node's resolver).
#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub(crate) struct PreviewQuery {
    /// REQ: API-007 (ADR-941) — resolve a sample through this Pi-hole (`ip` or `ip:port`).
    pub(crate) compare: Option<String>,
    /// The TelltaleDNS to compare with (default `127.0.0.1:53`).
    pub(crate) telltale: Option<String>,
    /// Extra names for the sample, comma-separated.
    pub(crate) samples: Option<String>,
}

pub(crate) fn admin_routes(backend: Arc<dyn Backend>, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/import/pihole", post(preview))
        .route("/api/v1/import/pihole/plans/{id}/apply", post(apply))
        .route("/api/v1/import/pihole/plans/{id}", delete(discard))
        .layer(DefaultBodyLimit::max(UPLOAD_LIMIT))
        .with_state((backend, auth))
}

fn agent_refused() -> Response {
    Problem::new(
        Code::AgentNotAllowed,
        "agents can't import a configuration: an admin does it on the Settings page, or with `telltale import pihole`",
    )
    .into_response()
}

/// Preview a Pi-hole import.
///
/// The body is the export: a Teleporter zip (v6) or tar.gz (v5), or a gravity.db. Nothing
/// changes. The answer is a plan (what would be added, changed or skipped) that an admin applies
/// with its `planId`, and with `compare` a sample resolved through both servers.
#[utoipa::path(post, path = "/api/v1/import/pihole", tag = "config",
    params(PreviewQuery),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The Pi-hole export: a Teleporter zip (v6) or tar.gz (v5), or a gravity.db."),
    responses(
        (status = 200, body = Object, description = "The plan: what would be added, changed or skipped, and the comparison when asked."),
        (status = 403, body = Problem, description = "Admins only; agents can't import."),
        (status = 413, description = "The upload is larger than 64 MiB."),
        (status = 422, body = Problem, description = "The file isn't a Pi-hole export the import can read."),
    ))]
pub(crate) async fn preview(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<PreviewQuery>,
    headers: HeaderMap,
    ext: Extensions,
    body: Bytes,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if p.agent.is_some() {
        return agent_refused();
    }
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let samples = q
        .samples
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let req = PiholeImportRequest {
        data: body.to_vec(),
        compare: q.compare,
        telltale: q.telltale,
        samples,
        by: actor.name.clone(),
    };
    match backend.pihole_import_preview(req).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Apply a previewed Pi-hole import.
///
/// The plan's entries are written as one configuration change, audited as `import.pihole`. The
/// configuration must be the one the preview saw; otherwise the answer is 409 and the preview
/// runs again.
#[utoipa::path(post, path = "/api/v1/import/pihole/plans/{id}/apply", tag = "config",
    params(("id" = String, Path, description = "The plan's ID, from the preview.")),
    responses(
        (status = 200, body = Object, description = "Applied: counts of what was added, changed and skipped."),
        (status = 403, body = Problem, description = "Admins only; agents can't import."),
        (status = 404, body = Problem, description = "No such plan (it expired, or was applied or discarded)."),
        (status = 409, body = Problem, description = "The configuration changed since the preview."),
        (status = 422, body = Problem, description = "The plan no longer loads with the configuration."),
    ))]
pub(crate) async fn apply(
    State((backend, auth)): State<Ctx>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ext: Extensions,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if p.agent.is_some() {
        return agent_refused();
    }
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    match backend.pihole_import_apply(id, actor.name.clone()).await {
        Ok(v) => {
            auth.record(&actor, "import.pihole", "pihole", &v);
            Json(v).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Discard a previewed Pi-hole import.
///
/// The plan is forgotten and nothing is written. Plans also expire after ten minutes.
#[utoipa::path(delete, path = "/api/v1/import/pihole/plans/{id}", tag = "config",
    params(("id" = String, Path, description = "The plan's ID.")),
    responses(
        (status = 200, body = Object, description = "Discarded."),
        (status = 403, body = Problem, description = "Admins only; agents can't import."),
        (status = 404, body = Problem, description = "No such plan."),
    ))]
pub(crate) async fn discard(
    State((backend, _auth)): State<Ctx>,
    Path(id): Path<String>,
    ext: Extensions,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if p.agent.is_some() {
        return agent_refused();
    }
    match backend.pihole_import_discard(&id) {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

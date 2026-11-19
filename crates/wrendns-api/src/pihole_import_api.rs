//! REQ: API-007 (T24.18, ADR-939, ADR-940, ADR-941) — importing a Pi-hole export. Admins only,
//! and never an agent: an import replaces configuration in bulk (spec/13 §3). The upload is
//! previewed first (nothing changes); the preview is a plan the same admin applies, as one
//! configuration change, audited as `import.pihole`. The three routes take an `Idempotency-Key`
//! like the configuration writes (AGT-003): a retried request gets the first answer.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{Extensions, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, post};
use serde::Deserialize;
use utoipa::IntoParams;
use wrendns_store::state::Replay;

use crate::auth::Auth;
use crate::auth::routes::{principal, reason, remote};
use crate::config_api::{IDEMPOTENCY_KEY, replay};
use crate::problem::{Code, Problem};
use crate::{Backend, PiholeImportRequest};

type Ctx = (Arc<dyn Backend>, Arc<Auth>);

/// Most bytes an upload may have.
const UPLOAD_LIMIT: usize = 64 << 20;

/// The preview's options (`compare` is a Pi-hole address; `wrendns` the node's resolver).
#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub(crate) struct PreviewQuery {
    /// REQ: API-007 (ADR-941) — resolve a sample through this Pi-hole (`ip` or `ip:port`).
    pub(crate) compare: Option<String>,
    /// The WrenDNS to compare with (default `127.0.0.1:53`).
    pub(crate) wrendns: Option<String>,
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
        "agents can't import a configuration: an admin does it on the Settings page, or with `wrendns import pihole`",
    )
    .into_response()
}

/// REQ: AGT-003 (API-007) — an `Idempotency-Key` on an import: the key is the admin's own and the
/// scope names the route, so keys don't collide across routes. `Ok(None)` when no key was sent.
fn keyed(
    backend: &dyn Backend,
    headers: &HeaderMap,
    user: i64,
    scope: &str,
    request: &str,
) -> Result<Option<(String, Vec<u8>)>, Problem> {
    let Some(k) = headers
        .get(IDEMPOTENCY_KEY)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|k| k.len() > 2)
    else {
        return Ok(None);
    };
    let fingerprint = backend.idempotency_request(None, request, None)?;
    Ok(Some((format!("import:{scope}:{user}:{k}"), fingerprint)))
}

/// The first answer to this key, replayed; a different request under the same key is a 409.
fn already_answered(
    auth: &Auth,
    (key, fingerprint): &(String, Vec<u8>),
    now: u64,
) -> Option<Response> {
    match auth.state().idempotent(key, now) {
        Ok(Some(r)) if &r.request == fingerprint => Some(replay(&r)),
        Ok(Some(_)) => Some(
            Problem::new(
                Code::Conflict,
                "this Idempotency-Key was used for a different request",
            )
            .hint("Use a new key for each distinct change.")
            .into_response(),
        ),
        Ok(None) => None,
        Err(e) => Some(Problem::internal(e.to_string()).into_response()),
    }
}

/// Keeps a successful answer under its key (a failure is retried, not replayed).
fn remember(auth: &Auth, (key, fingerprint): &(String, Vec<u8>), text: &str, now: u64) {
    let r = Replay {
        request: fingerprint.clone(),
        status: StatusCode::OK.as_u16(),
        response: text.to_owned(),
    };
    if let Err(e) = auth.state().remember_idempotent(key, &r, now) {
        tracing::warn!("idempotency key not stored: {e}");
    }
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
    let samples: Vec<String> = q
        .samples
        .clone()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let now = backend.now_unix_seconds();
    let request = format!(
        "pihole-preview {} {:?} {:?} {:?}",
        blake3::hash(&body).to_hex(),
        q.compare,
        q.wrendns,
        samples
    );
    let keyed = match keyed(backend.as_ref(), &headers, p.user_id, "preview", &request) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    if let Some(k) = &keyed
        && let Some(r) = already_answered(&auth, k, now)
    {
        return r;
    }
    let req = PiholeImportRequest {
        data: body,
        compare: q.compare,
        wrendns: q.wrendns,
        samples,
        by: actor.name.clone(),
    };
    match backend.pihole_import_preview(req).await {
        Ok(v) => {
            let text = v.to_string();
            if let Some(k) = &keyed {
                remember(&auth, k, &text, now);
            }
            Json(v).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Apply a previewed Pi-hole import.
///
/// The plan's entries are written as one configuration change, audited as `import.pihole`. The
/// configuration must be the one the preview saw; otherwise the answer is 409 and the preview
/// runs again. The plan belongs to the admin who previewed it.
#[utoipa::path(post, path = "/api/v1/import/pihole/plans/{id}/apply", tag = "config",
    params(("id" = String, Path, description = "The plan's ID, from the preview.")),
    responses(
        (status = 200, body = Object, description = "Applied: counts of what was added, changed and skipped."),
        (status = 403, body = Problem, description = "Admins only; agents can't import."),
        (status = 404, body = Problem, description = "No such plan (it expired, or was applied or discarded)."),
        (status = 409, body = Problem, description = "The configuration changed since the preview."),
        (status = 422, body = Problem, description = "The plan no longer loads with the configuration."),
        (status = 500, body = Problem, description = "The change was stored but the node couldn't reload it; the audit record says so."),
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
    let now = backend.now_unix_seconds();
    let keyed = match keyed(
        backend.as_ref(),
        &headers,
        p.user_id,
        "apply",
        &format!("pihole-apply {id}"),
    ) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    if let Some(k) = &keyed
        && let Some(r) = already_answered(&auth, k, now)
    {
        return r;
    }
    match backend.pihole_import_apply(id, actor.name.clone()).await {
        Ok(v) => {
            // The change is audited once it's stored, even when the reload that follows fails.
            auth.record(&actor, "import.pihole", "pihole", &v);
            if v["applied"] != serde_json::Value::Bool(true) {
                return Problem::internal(
                    "the change was saved but couldn't be applied; the server log says why",
                )
                .into_response();
            }
            let text = v.to_string();
            if let Some(k) = &keyed {
                remember(&auth, k, &text, now);
            }
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
    let now = backend.now_unix_seconds();
    let keyed = match keyed(
        backend.as_ref(),
        &headers,
        p.user_id,
        "discard",
        &format!("pihole-discard {id}"),
    ) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    if let Some(k) = &keyed
        && let Some(r) = already_answered(&auth, k, now)
    {
        return r;
    }
    match backend.pihole_import_discard(&id, &actor.name) {
        Ok(v) => {
            let text = v.to_string();
            if let Some(k) = &keyed {
                remember(&auth, k, &text, now);
            }
            Json(v).into_response()
        }
        Err(e) => e.into_response(),
    }
}

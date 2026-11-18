//! REQ: API-902, API-006, AGT-009 (T27.13; ADR-914, ADR-956) — `/api/v1/guarded`: the routes of
//! the guarded-changes framework.
//!
//! - `GET /api/v1/guarded` — what is guarded on each node, what a file sets, what is pending or
//!   waiting for a restart (`config:read`; no value, preview ID or token is ever in it).
//! - `POST /api/v1/guarded/{id}/preview` — the dry run: the effect, the phrase, the warnings.
//! - `POST /api/v1/guarded/{id}` — the change: `previewId`, `confirm` (the phrase), a reason.
//! - `POST /api/v1/guarded/pending/{id}/confirm` and `.../cancel` — the window's two ends.
//!
//! Who may call: an interactive admin session, nobody else. An agent token is refused whatever its
//! scopes (403 `agent_not_allowed`; no tool, plan or scope exists), any other API token or Basic
//! credential is 403 `reauth_required` with a hint to the file or the CLI, an operator or viewer
//! is 403. The confirm route is the one that may arrive without a session: on a new address the
//! admin has none, so the single-use `confirmToken` the change answered with stands in for it.
//! Everything past these checks (the phrase, the preview's binding, the sign-in recency, the
//! window, the audit) is the node's (`telltale/src/guarded/`), because it must hold for a request
//! the primary forwarded as well.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::auth::routes::{principal, reason, remote, remote_under};
use crate::auth::{Auth, Principal, Role, Via};
use crate::guarded::{
    ArrivedOn, GuardedApplied, GuardedApplyRequest, GuardedCaller, GuardedConfirmRequest,
    GuardedPreview, GuardedPreviewRequest, GuardedResult, GuardedStatus,
};
use crate::problem::{Code, Problem};
use crate::{Backend, blocking};

type Ctx = (Arc<dyn Backend>, Arc<Auth>);

/// The read route (viewers; agents with `config:read`).
pub(crate) fn read_routes(backend: Arc<dyn Backend>) -> Router {
    Router::new()
        .route("/api/v1/guarded", get(guarded_status))
        .with_state(backend)
}

/// Preview, apply and cancel: admins only (the handlers check again, and refuse every token).
pub(crate) fn admin_routes(backend: Arc<dyn Backend>, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/guarded/{id}/preview", post(guarded_preview))
        .route("/api/v1/guarded/{id}", post(guarded_apply))
        .route("/api/v1/guarded/pending/{id}/cancel", post(guarded_cancel))
        .with_state((backend, auth))
}

/// Confirm: a session of the same admin, or the single-use token (the layer lets a request
/// with no credentials through; the handler then needs the token).
pub(crate) fn confirm_routes(backend: Arc<dyn Backend>, auth: Arc<Auth>) -> Router {
    Router::new()
        .route(
            "/api/v1/guarded/pending/{id}/confirm",
            post(guarded_confirm),
        )
        .with_state((backend, auth))
}

/// Why a guarded call is refused before it reaches the node: the credential must be an admin's
/// interactive session (ADR-956 §3, ADR-914).
pub(crate) fn require_admin_session(p: &Principal) -> Result<(), Problem> {
    if p.agent.is_some() {
        return Err(Problem::new(
            Code::AgentNotAllowed,
            "agent tokens can't change guarded settings, whatever their scopes",
        )
        .hint("Guarded settings (listeners, the API address, TLS, proxies, secret keys, cluster, restart) are for people: an admin changes them in the web UI, or in the configuration file."));
    }
    if p.role != Role::Admin {
        return Err(Problem::new(
            Code::Forbidden,
            "only an admin can change guarded settings",
        ));
    }
    if p.display.is_some() {
        return Err(Problem::new(
            Code::Forbidden,
            "a wall display can't do this",
        ));
    }
    if !matches!(p.via, Via::Session { .. }) {
        return Err(Problem::new(
            Code::ReauthRequired,
            "guarded settings are changed from a signed-in session; API tokens and Basic credentials can't do it",
        )
        .hint("Sign in to the web UI as an admin (Settings), or set the value in the configuration file and restart the node (`telltale guarded list` shows what is stored)."));
    }
    Ok(())
}

/// The caller the node needs to know, after [`require_admin_session`].
async fn caller(
    backend: &Arc<dyn Backend>,
    auth: &Arc<Auth>,
    p: &Principal,
    ext: &axum::http::Extensions,
    headers: &HeaderMap,
) -> Result<GuardedCaller, Problem> {
    require_admin_session(p)?;
    let ip = remote(auth, ext, headers);
    let (a2, p2) = (Arc::clone(auth), p.clone());
    let signed_in_at = blocking(move || Ok(a2.sign_in_time(&p2))).await?;
    let under = backend
        .guarded_pending_proxies()
        .map(|list| remote_under(auth, ext, headers, &list));
    Ok(GuardedCaller {
        actor: auth.actor(p, ip, reason(headers)),
        username: p.username.clone(),
        session: Auth::session_key(p),
        signed_in_at,
        arrived_on: ext.get::<ArrivedOn>().map(|a| a.0),
        remote: Some(ip),
        remote_under_pending: under,
        tls: ext.get::<crate::auth::routes::TlsConnection>().is_some(),
    })
}

fn rejection(e: &JsonRejection) -> Problem {
    // REQ: API-015 — a parse error's own text can quote the input.
    let what = match e {
        JsonRejection::JsonSyntaxError(_) => "isn't valid JSON",
        JsonRejection::JsonDataError(_) => "has an unknown, missing or wrongly typed field",
        JsonRejection::MissingJsonContentType(_) => "must be sent as application/json",
        _ => "couldn't be read",
    };
    Problem::invalid(format!("the request body {what}"))
}

fn body<T>(b: Result<Json<T>, JsonRejection>) -> Result<T, Problem> {
    b.map(|Json(v)| v).map_err(|e| rejection(&e))
}

/// What is guarded on each node, what a file sets, and what is pending.
///
/// Never holds a value, a preview ID or a confirmation token: only that a change is pending, its
/// setting and the seconds left. `config:read` is enough, agent tokens included.
#[utoipa::path(get, path = "/api/v1/guarded", tag = "config",
    responses((status = 200, body = GuardedStatus, description = "Each node's guarded settings.")))]
pub(crate) async fn guarded_status(
    State(b): State<Arc<dyn Backend>>,
) -> Result<Json<GuardedStatus>, Problem> {
    b.guarded_status().await.map(Json)
}

/// The dry run of a guarded change: what it would do, and the phrase to type.
///
/// Changes nothing. The preview is bound to you, the node, the setting, the value and the
/// configuration version, and lives 5 minutes (a changed value is 409 `preview_stale`). Admin
/// session only: 403 `agent_not_allowed` for agent tokens, 403 `reauth_required` for other tokens.
#[utoipa::path(post, path = "/api/v1/guarded/{id}/preview", tag = "config",
    params(("id" = String, Path, description = "The setting (`listen`, `restart-now`, ...).")),
    request_body = GuardedPreviewRequest,
    responses(
        (status = 200, body = GuardedPreview, description = "The dry run."),
        (status = 403, body = Problem, description = "Not an admin session, an agent token, or another token."),
        (status = 404, body = Problem, description = "No such guarded setting."),
        (status = 409, body = Problem, description = "Set by file, a change already pending, restarting, no supervisor, would disconnect you."),
        (status = 421, body = Problem, description = "Ask the primary: only it forwards a request for another node."),
        (status = 429, body = Problem, description = "Too many requests, or too many failed confirmations from this session."),
    ))]
pub(crate) async fn guarded_preview(
    State((backend, auth)): State<Ctx>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    req: Result<Json<GuardedPreviewRequest>, JsonRejection>,
) -> Result<Json<GuardedPreview>, Problem> {
    let p = principal(&ext)?;
    require_admin_session(&p)?;
    let req = body(req)?;
    let c = caller(&backend, &auth, &p, &ext, &headers).await?;
    backend.guarded_preview(c, id, req).await.map(Json)
}

/// Makes a guarded change.
///
/// Send the `previewId`, the `confirm` phrase the preview returned (the server compares it), the
/// same `value`, and a `reason`. The answer depends on the setting: 200 `applied` (it took effect),
/// 202 `staged` (it waits for the node's next start; `pendingRestart`), 202 `pending` (a window
/// change: confirm it through the new address within `deadlineSecs` with the single-use
/// `confirmToken`, or it rolls back) or 202 `restarting`. A change that weakens security needs a
/// session signed in within the last 10 minutes (403 `reauth_required`). Audited as
/// `settings.guarded`; it raises the `guarded_setting_changed` alert.
#[utoipa::path(post, path = "/api/v1/guarded/{id}", tag = "config",
    params(("id" = String, Path, description = "The setting.")),
    request_body = GuardedApplyRequest,
    responses(
        (status = 200, body = GuardedApplied, description = "Applied."),
        (status = 202, body = GuardedApplied, description = "Staged for the next start, waiting for confirmation, or restarting."),
        (status = 400, body = Problem, description = "The phrase doesn't match, or the request is malformed."),
        (status = 403, body = Problem, description = "Not an admin session, an agent token, another token, or a weakening change without a recent sign-in."),
        (status = 409, body = Problem, description = "preview_stale, set_by_file, guarded_change_pending, restarting, would_disconnect_you, no_supervisor, primary_unreachable."),
        (status = 421, body = Problem, description = "Ask the primary."),
        (status = 429, body = Problem, description = "Too many requests, or too many failed confirmations from this session."),
    ))]
pub(crate) async fn guarded_apply(
    State((backend, auth)): State<Ctx>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    req: Result<Json<GuardedApplyRequest>, JsonRejection>,
) -> Result<Response, Problem> {
    let p = principal(&ext)?;
    require_admin_session(&p)?;
    let req = body(req)?;
    let c = caller(&backend, &auth, &p, &ext, &headers).await?;
    let done = backend.guarded_apply(c, id, req).await?;
    let code = match done.status.as_str() {
        "applied" => StatusCode::OK,
        _ => StatusCode::ACCEPTED,
    };
    Ok((code, Json(done)).into_response())
}

/// Confirms a pending window change.
///
/// The request has to arrive through the new address or certificate the change set up (what the
/// setting's proof says), carrying the single-use `confirmToken` or the same admin's session. A
/// wrong token or a request on the old address is refused and counted (5 in 10 minutes block the
/// session) and the window runs on. On success the node keeps the new value, closes the old
/// sockets and audits `settings.guarded`.
#[utoipa::path(post, path = "/api/v1/guarded/pending/{id}/confirm", tag = "config",
    params(("id" = String, Path, description = "The pending change's ID.")),
    request_body = GuardedConfirmRequest,
    responses(
        (status = 200, body = GuardedResult, description = "Confirmed."),
        (status = 401, body = Problem, description = "Neither a session nor a token."),
        (status = 403, body = Problem, description = "The token or the arrival point is wrong."),
        (status = 404, body = Problem, description = "Nothing is pending under that ID (it may have rolled back)."),
        (status = 409, body = Problem, description = "primary_unreachable: the node couldn't record the change."),
        (status = 429, body = Problem, description = "Too many failed confirmations."),
    ))]
pub(crate) async fn guarded_confirm(
    State((backend, auth)): State<Ctx>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    req: Result<Json<GuardedConfirmRequest>, JsonRejection>,
) -> Result<Json<GuardedResult>, Problem> {
    // An empty body is `{}`.
    let req = match req {
        Ok(Json(r)) => r,
        Err(JsonRejection::MissingJsonContentType(_)) => GuardedConfirmRequest::default(),
        Err(e) => return Err(rejection(&e)),
    };
    let c = if let Some(p) = ext.get::<Principal>() {
        let p = p.clone();
        caller(&backend, &auth, &p, &ext, &headers).await?
    } else {
        // No session: only a token can confirm, and the node then knows the admin from the
        // pending change it is bound to.
        if req.confirm_token.is_none() {
            return Err(Problem::new(
                Code::Unauthorized,
                "sign in, or send the confirmToken the change answered with",
            ));
        }
        let ip = remote(&auth, &ext, &headers);
        GuardedCaller {
            actor: crate::auth::Actor {
                name: String::new(),
                kind: "token",
                remote: Some(ip.to_string()),
                reason: reason(&headers),
            },
            username: String::new(),
            session: None,
            signed_in_at: None,
            arrived_on: ext.get::<ArrivedOn>().map(|a| a.0),
            remote: Some(ip),
            remote_under_pending: backend
                .guarded_pending_proxies()
                .map(|list| remote_under(&auth, &ext, &headers, &list)),
            tls: ext.get::<crate::auth::routes::TlsConnection>().is_some(),
        }
    };
    backend
        .guarded_confirm(c, id, req.confirm_token)
        .await
        .map(Json)
}

/// Cancels a pending window change.
///
/// The new sockets close, nothing is kept (the old ones were never touched), and the rollback is
/// audited as `settings.guarded_rolled_back` with the reason `cancelled`. The admin who made it, or
/// any admin session, can cancel; an agent token never can.
#[utoipa::path(post, path = "/api/v1/guarded/pending/{id}/cancel", tag = "config",
    params(("id" = String, Path, description = "The pending change's ID.")),
    responses(
        (status = 200, body = GuardedResult, description = "Rolled back."),
        (status = 403, body = Problem, description = "Not an admin session, or an agent token."),
        (status = 404, body = Problem, description = "Nothing is pending under that ID."),
    ))]
pub(crate) async fn guarded_cancel(
    State((backend, auth)): State<Ctx>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Result<Json<GuardedResult>, Problem> {
    let p = principal(&ext)?;
    let c = caller(&backend, &auth, &p, &ext, &headers).await?;
    backend.guarded_cancel(c, id).await.map(Json)
}

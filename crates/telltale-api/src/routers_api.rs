//! REQ: API-016 (T23.7, T23.8, ADR-903 §9, ADR-921, ADR-922) — router integrations: the list
//! with each router's status (`GET /api/v1/routers`), and the two admin-only checks of a draft
//! (`POST /api/v1/checks/router`, `POST /api/v1/checks/router-certificate`). Writes are in
//! `config_api` (`PUT`/`DELETE /api/v1/routers/{name}`).

use axum::Json;
use axum::extract::State;
use axum::routing::{get, post};

use crate::Shared;
use crate::auth::routes::principal;
use crate::model::{RouterCertificate, RouterCheck, RouterList};
use crate::problem::{Code, Problem};

/// The read route (viewers and up).
pub(crate) fn read_routes(backend: Shared) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/routers", get(list_routers))
        .with_state(backend)
}

/// The two checks (admins only, by the handlers and the agent forbidden list).
pub(crate) fn check_routes(backend: Shared) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/checks/router", post(check_router))
        .route(
            "/api/v1/checks/router-certificate",
            post(check_router_certificate),
        )
        .with_state(backend)
}

/// The admin-only rule of the checks (ADR-903 §5): agents never, operators never. The forbidden
/// list of agent tokens (`never_for_agents`) refuses agents before this runs.
fn admin_only(ext: &axum::http::Extensions) -> Result<(), Problem> {
    let p = principal(ext)?;
    if p.role != crate::auth::Role::Admin || p.agent.is_some() {
        return Err(Problem::new(
            Code::Forbidden,
            "only an admin can check a router",
        ));
    }
    Ok(())
}

/// The routers in the configuration, with their status.
///
/// Each router comes with its settings (secrets as names, never values), where it comes from (the
/// files or the API), and what this node's last read did (API-016, T23.8). A replica answers with
/// its own reads: the primary is the one that reads a router that stores its credential.
#[utoipa::path(get, path = "/api/v1/routers", tag = "config",
    responses((status = 200, body = RouterList, description = "The routers, by name.")))]
pub(crate) async fn list_routers(State(b): State<Shared>) -> Json<RouterList> {
    Json(RouterList {
        items: b.router_entries(),
        stale: false,
    })
}

/// Check a router draft: one read, nothing saved.
///
/// It needs an admin (agents never). A stored credential is sent only to the address and TLS settings
/// it was saved with: with another address the check runs without it (`credentialSent: false`), so a
/// stored key never goes to a new address (API-016, T23.8, ADR-922).
#[utoipa::path(post, path = "/api/v1/checks/router", tag = "config",
    request_body = Object,
    responses(
        (status = 200, body = RouterCheck, description = "What the read found."),
        (status = 403, body = Problem, description = "Only an admin can check a router (agents never)."),
        (status = 422, body = Problem, description = "The draft is not a router."),
    ))]
pub(crate) async fn check_router(
    State(b): State<Shared>,
    ext: axum::http::Extensions,
    body: Result<Json<serde_json::Value>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<RouterCheck>, Problem> {
    admin_only(&ext)?;
    let input = match body {
        Ok(Json(v)) => v,
        Err(e) => return Err(Problem::invalid(format!("body: {e}"))),
    };
    let r = b.check_router(input).await?;
    Ok(Json(r))
}

/// The certificate a router console presents at `url`.
///
/// Its names, fingerprint and PEM, and the name to set as `tls_server_name` when it names something
/// else. Admin-only. The check trusts nothing it reads: the PEM is saved only when the admin submits
/// the form (API-016, T23.8, ADR-120).
#[utoipa::path(post, path = "/api/v1/checks/router-certificate", tag = "config",
    request_body = Object,
    responses(
        (status = 200, body = RouterCertificate, description = "The certificate."),
        (status = 403, body = Problem, description = "Only an admin can check a router (agents never)."),
        (status = 422, body = Problem, description = "The URL is not an https address, or no certificate could be read."),
    ))]
pub(crate) async fn check_router_certificate(
    State(b): State<Shared>,
    ext: axum::http::Extensions,
    body: Result<Json<serde_json::Value>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<RouterCertificate>, Problem> {
    admin_only(&ext)?;
    let input = match body {
        Ok(Json(v)) => v,
        Err(e) => return Err(Problem::invalid(format!("body: {e}"))),
    };
    let url = input
        .get("url")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let c = b.router_certificate(url).await?;
    Ok(Json(c))
}

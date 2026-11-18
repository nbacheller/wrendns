//! REQ: API-016 (T23.10, ADR-903 §6, ADR-967) — OIDC providers: the list with each provider's
//! status on this node (`GET /api/v1/oidc-providers`). Admin-only: the providers are a security
//! gate, and an operator has no Sign-in tab. Writes are in `config_api`
//! (`PUT`/`DELETE /api/v1/oidc-providers/{id}`).

use axum::Json;
use axum::extract::State;
use axum::routing::get;

use crate::Shared;
use crate::auth::routes::principal;
use crate::model::OidcProviderList;
use crate::problem::{Code, Problem};

/// The read route (admins only, by the handler; agents never, by the default of their scopes).
pub(crate) fn read_routes(backend: Shared) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/oidc-providers", get(list_oidc_providers))
        .with_state(backend)
}

/// The OIDC sign-in providers in the configuration, with their status on this node.
///
/// Each provider comes with its settings (the client secret as a name, never a value), where it
/// comes from (the files or the API), and whether this node serves its sign-in button: a node
/// without `[auth.oidc] public_url`, or one that can't read the provider's secret or reach its
/// issuer, shows it as inactive with the reason (API-016). Admins only.
#[utoipa::path(get, path = "/api/v1/oidc-providers", tag = "config",
    responses(
        (status = 200, body = OidcProviderList, description = "The providers, files' first."),
        (status = 403, body = Problem, description = "Only an admin can read the sign-in providers."),
    ))]
pub(crate) async fn list_oidc_providers(
    State(b): State<Shared>,
    ext: axum::http::Extensions,
) -> Result<Json<OidcProviderList>, Problem> {
    let p = principal(&ext)?;
    if p.role != crate::auth::Role::Admin || p.agent.is_some() {
        return Err(Problem::new(
            Code::Forbidden,
            "only an admin can read the sign-in providers",
        ));
    }
    Ok(Json(b.oidc_provider_entries()))
}

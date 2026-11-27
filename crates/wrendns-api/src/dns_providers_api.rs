// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b, ADR-1084 as amended 2026-11-26, ADR-1104) - the reads of DNS providers:
//! the table with, for each provider, its settings (the credential as a stored secret's name, never
//! a value), where it comes from and its state. Writes (`PUT` and `DELETE
//! /api/v1/dns-providers/{name}`) are in `config_api`, admin only; an agent token never writes one.
//! The table is stored and validated; nothing calls a provider yet, and the reads say so.

use axum::Json;
use axum::extract::{Path, State};
use axum::routing::get;

use crate::Shared;
use crate::model::{DnsProviderEntry, DnsProviderList};
use crate::problem::Problem;

/// The read routes (viewers and up; agents with `config:read`). No credential is in an answer.
pub(crate) fn read_routes(backend: Shared) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/dns-providers", get(list_dns_providers))
        .route("/api/v1/dns-providers/{name}", get(get_dns_provider))
        .with_state(backend)
}

/// The DNS providers in the configuration.
///
/// Each one comes with its settings (the credential as the name of a stored secret, never a value),
/// whether this node stores a secret by that name, where it comes from (the files or the API), and
/// its state. The table is stored and validated: nothing calls a provider yet, so every entry
/// reads `not_used`. `held` is true while the start-up hold keeps the providers out of what this
/// node serves and publishes (a cluster member's build does not know them yet).
#[utoipa::path(get, path = "/api/v1/dns-providers", tag = "config",
    responses((status = 200, body = DnsProviderList, description = "The DNS providers.")))]
pub(crate) async fn list_dns_providers(State(b): State<Shared>) -> Json<DnsProviderList> {
    let b = crate::request_backend(&b);
    let list = tokio::task::spawn_blocking(move || b.dns_providers())
        .await
        .unwrap_or_default();
    Json(list)
}

/// One DNS provider by name.
///
/// The same entry `GET /api/v1/dns-providers` lists. No credential is in the answer.
#[utoipa::path(get, path = "/api/v1/dns-providers/{name}", tag = "config",
    params(("name" = String, Path, description = "The provider's name.")),
    responses(
        (status = 200, body = DnsProviderEntry, description = "The DNS provider."),
        (status = 404, body = Problem, description = "No such DNS provider."),
    ))]
pub(crate) async fn get_dns_provider(
    State(b): State<Shared>,
    Path(name): Path<String>,
) -> Result<Json<DnsProviderEntry>, Problem> {
    let b = crate::request_backend(&b);
    let list = tokio::task::spawn_blocking(move || b.dns_providers())
        .await
        .unwrap_or_default();
    list.items
        .into_iter()
        .find(|p| p.name == name)
        .map(Json)
        .ok_or_else(|| Problem::not_found(format!("no DNS provider `{name}`")))
}

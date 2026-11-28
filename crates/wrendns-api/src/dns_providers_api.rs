// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b, ADR-1084 as amended 2026-11-26, ADR-1104) - the reads of DNS providers:
//! the table with, for each provider, its settings (the credential as a stored secret's name, never
//! a value), where it comes from and its state. Writes (`PUT` and `DELETE
//! /api/v1/dns-providers/{name}`) are in `config_api`, admin only; an agent token never writes one.
//!
//! T36.10b step b3 adds the actions that go through the write engine and run on the primary, all
//! admin only and never for agents: `POST .../test` (check the credential, show its scope, end dry
//! run on the first success), `GET .../records` (the zone's record sets and who owns each) and
//! `POST .../records/adopt` (take a record set into the ownership ledger, CLD-919). Step b5 adds
//! `POST .../verify` for a `delegated` provider: it looks the hand-made CNAME up at the zone's own
//! authoritative servers (admin only, never for agents; a read that runs on the node asked).

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};

use crate::auth::Auth;
use crate::auth::routes::{principal, reason, remote};
use crate::model::{
    DnsProviderAdoptRequest, DnsProviderAdopted, DnsProviderEntry, DnsProviderList,
    DnsProviderRecords, DnsProviderTestResult, DnsProviderVerifyResult,
};
use crate::problem::{Code, Problem};
use crate::{DnsProviderAction, DnsProviderOp, Shared};

/// The read routes (viewers and up; agents with `config:read`) and the admin-only actions (checked
/// by the handlers, and refused for agent tokens by the forbidden list). No credential is in an
/// answer.
pub(crate) fn read_routes(backend: Shared, auth: Arc<Auth>) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/dns-providers", get(list_dns_providers))
        .route("/api/v1/dns-providers/{name}", get(get_dns_provider))
        .with_state(Arc::clone(&backend))
        .merge(
            axum::Router::new()
                .route("/api/v1/dns-providers/{name}/test", post(test_dns_provider))
                .route(
                    "/api/v1/dns-providers/{name}/verify",
                    post(verify_dns_provider),
                )
                .route(
                    "/api/v1/dns-providers/{name}/records",
                    get(dns_provider_records),
                )
                .route(
                    "/api/v1/dns-providers/{name}/records/adopt",
                    post(adopt_dns_provider_record),
                )
                .with_state((backend, auth)),
        )
}

type Ctx = (Shared, Arc<Auth>);

/// The admin-only rule of the actions: agents never, operators and viewers never.
fn admin_only(ext: &axum::http::Extensions) -> Result<crate::auth::Principal, Problem> {
    let p = principal(ext)?;
    if p.role != crate::auth::Role::Admin || p.agent.is_some() {
        return Err(Problem::new(
            Code::Forbidden,
            "only an admin can test a DNS provider, verify its delegation, read its records or adopt one",
        ));
    }
    Ok(p)
}

fn op(
    auth: &Auth,
    p: &crate::auth::Principal,
    ext: &axum::http::Extensions,
    headers: &HeaderMap,
    name: String,
    action: DnsProviderAction,
) -> DnsProviderOp {
    let actor = auth.actor(p, remote(auth, ext, headers), reason(headers));
    DnsProviderOp {
        name,
        action,
        by: actor.name,
        remote: actor.remote,
        reason: actor.reason,
    }
}

fn typed<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<Json<T>, Problem> {
    serde_json::from_value(v)
        .map(Json)
        .map_err(|e| Problem::internal(format!("unreadable answer from the node: {e}")))
}

/// Test a DNS provider: check the credential and show what it may change.
///
/// CLD-904, CLD-919 (T36.10b step b3). The provider is asked what the credential can do and the
/// answer is the scope: the zone, the record types, the record sets it is limited to, and a warning
/// when it reaches further than the node needs. Nothing is written, and the credential is never in
/// the answer or the audit entry (a failure's text is scrubbed of it). The first success ends the
/// entry's dry run (an entry the config files define keeps the file's setting, and the answer says
/// so). A kind without provider code in this build answers `supported: false`. It runs on the
/// primary (a replica forwards it). Admin only, never for agents.
#[utoipa::path(post, path = "/api/v1/dns-providers/{name}/test", tag = "config",
    params(("name" = String, Path, description = "The provider's name.")),
    responses(
        (status = 200, body = DnsProviderTestResult, description = "What the test found."),
        (status = 403, body = Problem, description = "Only an admin can test a DNS provider (agents never)."),
        (status = 404, body = Problem, description = "No DNS provider by that name."),
        (status = 409, body = Problem, description = "`upgrade_required`: a cluster member's build does not know the test yet."),
    ))]
pub(crate) async fn test_dns_provider(
    State((b, auth)): State<Ctx>,
    Path(name): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Result<Json<DnsProviderTestResult>, Problem> {
    let p = admin_only(&ext)?;
    let o = op(&auth, &p, &ext, &headers, name, DnsProviderAction::Test);
    typed(b.dns_provider_op(o).await?)
}

/// Verify the delegation CNAME of a `delegated` provider.
///
/// CLD-904 (T36.10b step b5, ADR-1115). For each location whose domain is in the provider's zone the
/// node asks the zone's own authoritative name servers (found through the configured upstreams, never
/// its own local data or cache) whether `_acme-challenge.<slug>.<domain>` is a CNAME to
/// `<slug>.<validation zone>`. Every name server must answer with authority and with exactly that
/// target. The answer lists each record with the verdict and the reason; a failure is a health
/// reason only and changes no DNS answer. Nothing is written anywhere. It runs on the node asked.
/// Admin only, never for agents.
#[utoipa::path(post, path = "/api/v1/dns-providers/{name}/verify", tag = "config",
    params(("name" = String, Path, description = "The provider's name.")),
    responses(
        (status = 200, body = DnsProviderVerifyResult, description = "Each record with its verdict."),
        (status = 403, body = Problem, description = "Only an admin can verify a DNS provider (agents never)."),
        (status = 404, body = Problem, description = "No DNS provider by that name."),
        (status = 409, body = Problem, description = "The entry is not a `delegated` provider, or it is held back."),
        (status = 503, body = Problem, description = "This node has no upstream to find the name servers through."),
    ))]
pub(crate) async fn verify_dns_provider(
    State((b, auth)): State<Ctx>,
    Path(name): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Result<Json<DnsProviderVerifyResult>, Problem> {
    let p = admin_only(&ext)?;
    let o = op(&auth, &p, &ext, &headers, name, DnsProviderAction::Verify);
    typed(b.dns_provider_op(o).await?)
}

/// The record sets at a DNS provider, and who owns each.
///
/// CLD-919. `owner` is `created` (the node made it) or `adopted` (an admin took it over); a record set
/// with no owner is never changed or deleted by the node until it is adopted. Admin only, never for
/// agents. Runs on the primary, which holds the ledger.
#[utoipa::path(get, path = "/api/v1/dns-providers/{name}/records", tag = "config",
    params(("name" = String, Path, description = "The provider's name.")),
    responses(
        (status = 200, body = DnsProviderRecords, description = "The zone's TXT, A and AAAA record sets."),
        (status = 403, body = Problem, description = "Only an admin can read a provider's records."),
        (status = 404, body = Problem, description = "No DNS provider by that name."),
        (status = 409, body = Problem, description = "No provider code for the entry (only a test-only entry has none), or `upgrade_required`."),
        (status = 503, body = Problem, description = "The provider refused or did not answer the call."),
    ))]
pub(crate) async fn dns_provider_records(
    State((b, auth)): State<Ctx>,
    Path(name): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Result<Json<DnsProviderRecords>, Problem> {
    let p = admin_only(&ext)?;
    let o = op(&auth, &p, &ext, &headers, name, DnsProviderAction::Records);
    typed(b.dns_provider_op(o).await?)
}

/// Adopt a record set: the node may then change and delete it.
///
/// CLD-919 (ADR-1112 point 1). The node changes or deletes only the record sets it made itself or
/// that an admin adopted. Adopting records the claim in the ownership ledger (kept across restarts and
/// replicated) and sends nothing to the provider, so it works in dry run too. The body is the record
/// set's `name` and `recordType`. Audited as `dns_provider.adopt`. Admin only, never for agents.
#[utoipa::path(post, path = "/api/v1/dns-providers/{name}/records/adopt", tag = "config",
    params(("name" = String, Path, description = "The provider's name.")),
    request_body = DnsProviderAdoptRequest,
    responses(
        (status = 200, body = DnsProviderAdopted, description = "The record set is in the ledger."),
        (status = 403, body = Problem, description = "Only an admin can adopt a record set."),
        (status = 404, body = Problem, description = "No DNS provider by that name."),
        (status = 422, body = Problem, description = "The name is outside the zone, the type is not A, AAAA or TXT, or the record set is not at the provider."),
    ))]
pub(crate) async fn adopt_dns_provider_record(
    State((b, auth)): State<Ctx>,
    Path(name): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    body: Result<Json<DnsProviderAdoptRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<DnsProviderAdopted>, Problem> {
    let p = admin_only(&ext)?;
    let Json(req) = body.map_err(|e| Problem::invalid(format!("body: {e}")))?;
    let o = op(
        &auth,
        &p,
        &ext,
        &headers,
        name,
        DnsProviderAction::Adopt {
            record: req.name,
            record_type: req.record_type,
        },
    );
    typed(b.dns_provider_op(o).await?)
}

/// The DNS providers in the configuration.
///
/// Each one comes with its settings (the credential as the name of a stored secret, never a value),
/// whether this node stores a secret by that name, where it comes from (the files or the API), and
/// its state: `not_used` (this build has no provider code for the entry; every real kind has code, so only a test-only entry reads this), `dry_run` (changes are
/// recorded and not sent until the first successful test) or `ready`. `held` is true while the start-up hold keeps the providers out of what this
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

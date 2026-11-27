//! Configuration changes through the API (REQ: API-002, API-010; AGT-002 dry-run, AGT-003
//! idempotency; ADR-040, ADR-042): devices (`/clients/{name}`), local names
//! (`/records/{name}`), and domains sent elsewhere (`/forwards/{domain}`). Every write takes
//! `?dryRun=true` (validate and report, change nothing), `If-Match: <configVersion>`
//! (412 when the config changed meanwhile), and `Idempotency-Key` (the first response is
//! replayed for 24 hours), and is recorded in the audit log.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Deserialize;
use utoipa::IntoParams;
use wrendns_store::state::Replay;

use crate::auth::Auth;
use crate::auth::routes::{body, principal, reason, remote};
use crate::blocking;
use crate::model::{ClientChange, ClientInput, ConfigChange, ForwardInput, RecordsInput};
use crate::problem::{Code, Problem};
use crate::{Backend, ClientWrite, ManagedKind, ManagedWrite, SimulateOpts};

type Ctx = (Arc<dyn Backend>, Arc<Auth>);

/// `?dryRun=true` validates and reports without changing anything (AGT-002).
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct DryRun {
    /// Validate and report the change without applying it.
    pub dry_run: Option<bool>,
    /// REQ: OBS-024 — with `dryRun=true`: replay the query log over this window (`24h`,
    /// `7d`; at most 7 days; `true` for `[simulate] default_window`) and report what the
    /// change would have done to those queries (`simulation`). `auto`: only when
    /// `[simulate] plans_by_default` is on.
    pub simulate: Option<String>,
    /// REQ: OBS-024 — where the simulated window ends: RFC 3339 or relative (`-24h`).
    /// Default now.
    pub simulate_until: Option<String>,
}

/// `?dryRun=true` alone, where nothing can be simulated (promotion).
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct PlainDryRun {
    /// Check and report without changing anything.
    pub dry_run: Option<bool>,
}

/// A dry run's options.
#[derive(Debug, Clone, Default)]
pub(crate) struct WriteOpts {
    pub(crate) dry_run: bool,
    pub(crate) simulate: Option<String>,
    pub(crate) simulate_until: Option<String>,
}

/// Header names.
pub const IF_MATCH: &str = "if-match";
pub const IDEMPOTENCY_KEY: &str = "idempotency-key";

/// `If-Match: "7"`, `7`, or `W/"7"` → 7. `*` or absent → no check.
pub(crate) fn expected_version(headers: &HeaderMap) -> Result<Option<u64>, Problem> {
    let Some(v) = headers.get(IF_MATCH) else {
        return Ok(None);
    };
    let s = v.to_str().unwrap_or("").trim();
    if s == "*" {
        return Ok(None);
    }
    s.trim_start_matches("W/")
        .trim_matches('"')
        .parse()
        .map(Some)
        .map_err(|_| {
            Problem::invalid(format!("`If-Match`: `{s}` is not a config version"))
                .hint("Send the configVersion from the last read or write, e.g. If-Match: \"7\".")
        })
}

#[allow(clippy::too_many_lines)] // one route per endpoint of this module
pub(crate) fn routes(backend: Arc<dyn Backend>, auth: Arc<Auth>) -> Router {
    use axum::routing::put;
    Router::new()
        .route(
            "/api/v1/clients/{name}",
            put(put_client).delete(delete_client),
        )
        .route(
            "/api/v1/records/{name}",
            put(put_records).delete(delete_records),
        )
        .route(
            "/api/v1/forwards/{domain}",
            put(put_forward).delete(delete_forward),
        )
        // REQ: DNS-010 (T27.7) — authoritative zones made through the API or UI.
        .route("/api/v1/zones/{name}", put(put_zone).delete(delete_zone))
        // REQ: DSC-913 (T36.10a) — locations made through the API or UI.
        .route(
            "/api/v1/locations/{slug}",
            put(put_location).delete(delete_location),
        )
        // REQ: OBS-016, OBS-020, OBS-019, OBS-013, OBS-003, OBS-005 (T27.5, ADR-1007) — the tuning
        // sections (one entry each).
        .route(
            "/api/v1/slo-settings/default",
            put(put_slo_settings).delete(delete_slo_settings),
        )
        .route(
            "/api/v1/probe-settings/default",
            put(put_probe_settings).delete(delete_probe_settings),
        )
        .route(
            "/api/v1/upstream-check-settings/default",
            put(put_upstream_check_settings).delete(delete_upstream_check_settings),
        )
        .route(
            "/api/v1/anomaly-settings/default",
            put(put_anomaly_settings).delete(delete_anomaly_settings),
        )
        .route(
            "/api/v1/qlog-settings/default",
            put(put_qlog_settings).delete(delete_qlog_settings),
        )
        .route(
            "/api/v1/metrics-settings/default",
            put(put_metrics_settings).delete(delete_metrics_settings),
        )
        .route(
            "/api/v1/dnstap-settings/default",
            put(put_dnstap_settings).delete(delete_dnstap_settings),
        )
        .route("/api/v1/rules/{id}", put(put_rule).delete(delete_rule))
        // REQ: API-002 (T7.5, ADR-069)
        .route(
            "/api/v1/upstreams/{name}",
            put(put_upstream).delete(delete_upstream),
        )
        .route(
            "/api/v1/upstream-groups/{name}",
            put(put_upstream_group).delete(delete_upstream_group),
        )
        .route("/api/v1/lists/{name}", put(put_list).delete(delete_list))
        .route("/api/v1/groups/{name}", put(put_group).delete(delete_group))
        // REQ: OBS-010 (T9.6)
        .route(
            "/api/v1/alerts/destinations/{name}",
            put(put_alert_destination).delete(delete_alert_destination),
        )
        .route(
            "/api/v1/alerts/rules/{name}",
            put(put_alert_rule).delete(delete_alert_rule),
        )
        // REQ: API-016 (T23.7, ADR-921) — router integrations (admin-only).
        .route(
            "/api/v1/routers/{name}",
            put(put_router).delete(delete_router),
        )
        // REQ: API-016 (T23.10, ADR-967) — OIDC providers (admin-only, node-managed).
        .route(
            "/api/v1/oidc-providers/{id}",
            put(put_oidc_provider).delete(delete_oidc_provider),
        )
        // REQ: API-016 (T23.11, ADR-984) - event sinks and the OTLP export (admin-only, node-managed).
        .route("/api/v1/sinks/{name}", put(put_sink).delete(delete_sink))
        .route("/api/v1/otlp/default", put(put_otlp).delete(delete_otlp))
        .route(
            "/api/v1/alerts/destinations/{name}/test",
            axum::routing::post(test_alert_destination),
        )
        // REQ: API-002 (T9.12)
        .route(
            "/api/v1/checks/upstream",
            axum::routing::post(check_upstream),
        )
        .route("/api/v1/checks/list", axum::routing::post(check_list))
        // REQ: FLT-010 (T9.7)
        .route(
            "/api/v1/schedules/{name}",
            put(put_schedule).delete(delete_schedule),
        )
        // REQ: OBS-038 (ADR-161)
        .route(
            "/api/v1/anomaly-mutes/{name}",
            put(put_anomaly_mute).delete(delete_anomaly_mute),
        )
        // REQ: FLT-017 — a workload's (or a namespace's) group.
        .route(
            "/api/v1/kubernetes/map/{*key}",
            put(put_kubernetes_map).delete(delete_kubernetes_map),
        )
        // REQ: DNS-014 (review 01 q1)
        .route(
            "/api/v1/ratelimit/default",
            put(put_ratelimit).delete(delete_ratelimit),
        )
        // REQ: OBS-022 (T12.1)
        .route(
            "/api/v1/exclusions/default",
            put(put_exclusions).delete(delete_exclusions),
        )
        // REQ: OBS-024 (T13.1)
        .route(
            "/api/v1/simulate-settings/default",
            put(put_simulate_settings).delete(delete_simulate_settings),
        )
        // REQ: OBS-901 (T26.2, ADR-958) — `[map]`.
        .route(
            "/api/v1/map-settings/default",
            put(put_map_settings).delete(delete_map_settings),
        )
        // REQ: DNS-019 (T24.12, ADR-904, ADR-914) — `[special]`.
        .route(
            "/api/v1/special-names/default",
            put(put_special).delete(delete_special),
        )
        // REQ: DNS-023 (T24.13, ADR-901, ADR-914) — `[local]`, and `[clients]` (`mdns` only).
        .route(
            "/api/v1/local-settings/default",
            put(put_local).delete(delete_local),
        )
        .route(
            "/api/v1/clients-settings/default",
            put(put_clients_settings).delete(delete_clients_settings),
        )
        // REQ: DSC-001 (T25.2, ADR-907) — `[discovery]`: admin-only, no agent scope.
        .route(
            "/api/v1/discovery-settings/default",
            put(put_discovery_settings).delete(delete_discovery_settings),
        )
        // REQ: DSC-901, DSC-906 (T31.2, ADR-1005) — `[cmdb]`: admin-only, no agent scope.
        .route(
            "/api/v1/cmdb-settings/default",
            put(put_cmdb_settings).delete(delete_cmdb_settings),
        )
        .with_state((backend, auth))
}

/// Add or change an upstream resolver (ADR-069).
///
/// The body has the same fields as `[[upstream]]` in `wrendns.toml` (the name comes from the path),
/// e.g. `{"url": "tls://9.9.9.9", "tls_server_name": "dns.quad9.net"}`. A name the config files use is overridden: this definition replaces theirs
/// until it's deleted again (`GET /api/v1/config/overrides` lists such changes). The whole
/// configuration is checked before anything is stored. On a node whose configuration comes from
/// Git, the response's `toml` says what to add to the repository to keep the change.
#[utoipa::path(put, path = "/api/v1/upstreams/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid: problem+json says which."),
    ))]
pub(crate) async fn put_upstream(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /upstreams/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Upstream, Some(input)),
    )
    .await
}

/// Remove an upstream resolver (ADR-069).
///
/// An entry added through the API goes away; an override goes away and the config files'
/// entry is back; an entry only the files define is hidden (left out) until this override is
/// deleted in turn. The configuration is checked first (say, a group still using a list).
#[utoipa::path(delete, path = "/api/v1/upstreams/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "Something still uses it: problem+json says what."),
    ))]
pub(crate) async fn delete_upstream(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /upstreams/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Upstream, None),
    )
    .await
}

/// Add or change an upstream group (ADR-069).
///
/// The body has the same fields as `[[upstream_group]]` in `wrendns.toml` (the name comes from the path),
/// e.g. `{"members": ["quad9", "cloudflare"], "strategy": "fastest"}`. A name the config files use is overridden: this definition replaces theirs
/// until it's deleted again (`GET /api/v1/config/overrides` lists such changes). The whole
/// configuration is checked before anything is stored. On a node whose configuration comes from
/// Git, the response's `toml` says what to add to the repository to keep the change.
#[utoipa::path(put, path = "/api/v1/upstream-groups/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid: problem+json says which."),
    ))]
pub(crate) async fn put_upstream_group(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /upstream-groups/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::UpstreamGroup, Some(input)),
    )
    .await
}

/// Remove an upstream group (ADR-069).
///
/// An entry added through the API goes away; an override goes away and the config files'
/// entry is back; an entry only the files define is hidden (left out) until this override is
/// deleted in turn. The configuration is checked first (say, a group still using a list).
#[utoipa::path(delete, path = "/api/v1/upstream-groups/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "Something still uses it: problem+json says what."),
    ))]
pub(crate) async fn delete_upstream_group(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /upstream-groups/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::UpstreamGroup, None),
    )
    .await
}

/// Add or change a filter list (ADR-069).
///
/// The body has the same fields as `[[list]]` in `wrendns.toml` (the name comes from the path),
/// e.g. `{"url": "https://example.com/hosts.txt"}`. A name the config files use is overridden: this definition replaces theirs
/// until it's deleted again (`GET /api/v1/config/overrides` lists such changes). The whole
/// configuration is checked before anything is stored. On a node whose configuration comes from
/// Git, the response's `toml` says what to add to the repository to keep the change.
#[utoipa::path(put, path = "/api/v1/lists/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid: problem+json says which."),
    ))]
pub(crate) async fn put_list(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    // REQ: FLT-901 (ADR-994 item 9) — a category list takes its source from the catalog: only
    // its mode can be set (refreshing and shadow stay), anything else is refused.
    if wrendns_config::categories::is_category_list(&name)
        && let Some(o) = input.as_object()
        && let Some(k) = o.keys().find(|k| !matches!(k.as_str(), "mode" | "name"))
    {
        return Problem::new(
            Code::OwnedByCategory,
            format!("`{name}` is a category list: `{k}` comes from the catalog and can't be changed here"),
        )
        .hint("Change which categories a group uses (Groups, Categories); a category list can be refreshed and put in shadow mode.")
        .into_response();
    }
    let request = format!("PUT /lists/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::List, Some(input)),
    )
    .await
}

/// Remove a filter list (ADR-069).
///
/// An entry added through the API goes away; an override goes away and the config files'
/// entry is back; an entry only the files define is hidden (left out) until this override is
/// deleted in turn. The configuration is checked first (say, a group still using a list).
#[utoipa::path(delete, path = "/api/v1/lists/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "Something still uses it: problem+json says what."),
    ))]
pub(crate) async fn delete_list(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    // REQ: FLT-901 — a category list goes when no group uses it; only a mode override of one
    // (shadow) can be deleted.
    if wrendns_config::categories::is_category_list(&name) {
        let bk = Arc::clone(&backend);
        let n = name.clone();
        let override_exists = blocking(move || {
            Ok(bk
                .config_entries(Some("list"))
                .iter()
                .any(|e| e.name == n && e.source != "file"))
        })
        .await
        .unwrap_or(false);
        if !override_exists {
            return Problem::new(
                Code::OwnedByCategory,
                format!("`{name}` is a category list: it goes when no group uses its category"),
            )
            .hint("Stop selecting its category in the groups that do (Groups, Categories).")
            .into_response();
        }
    }
    let request = format!("DELETE /lists/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::List, None),
    )
    .await
}

/// Add or change a client group (ADR-069).
///
/// The body has the same fields as `[[group]]` in `wrendns.toml` (the name comes from the path),
/// e.g. `{"lists": ["stevenblack"], "block_mode": "null_ip"}`. A name the config files use is overridden: this definition replaces theirs
/// until it's deleted again (`GET /api/v1/config/overrides` lists such changes). The whole
/// configuration is checked before anything is stored. On a node whose configuration comes from
/// Git, the response's `toml` says what to add to the repository to keep the change.
#[utoipa::path(put, path = "/api/v1/groups/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."),
        ("confirm" = Option<bool>, Query, description = "Accept the cost of a heavy `content` selection (see `PUT /groups/{name}/content`)."),
        DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid: problem+json says which."),
    ))]
pub(crate) async fn put_group(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    // REQ: FLT-901, FLT-902 (T24.29) — a change to the group's `content` is checked against the
    // catalog and the node's budget, is a person's (an agent token is refused), and a group
    // that leaves `content` out keeps the one it has.
    let input = match crate::categories_api::guard_group_put(
        &backend,
        &ext,
        &name,
        input,
        q.dry_run.unwrap_or(false),
        raw.as_deref(),
    )
    .await
    {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /groups/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Group, Some(input)),
    )
    .await
}

/// Remove a client group (ADR-069).
///
/// An entry added through the API goes away; an override goes away and the config files'
/// entry is back; an entry only the files define is hidden (left out) until this override is
/// deleted in turn. The configuration is checked first (say, a group still using a list).
#[utoipa::path(delete, path = "/api/v1/groups/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "Something still uses it: problem+json says what."),
    ))]
pub(crate) async fn delete_group(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /groups/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Group, None),
    )
    .await
}

/// Admin-only cluster actions.
pub(crate) fn admin_routes(backend: Arc<dyn Backend>, auth: Arc<Auth>) -> Router {
    Router::new()
        .route(
            "/api/v1/cluster/promote",
            axum::routing::post(cluster_promote),
        )
        .route(
            "/api/v1/backup",
            axum::routing::get(backup_download).post(backup_create),
        )
        .with_state((backend, auth))
}

/// Promote this node to primary.
///
/// Manual failover (ADR-051): use when the primary is gone. The node takes a new epoch,
/// publishes the cluster's configuration from the last version it applied, and every node
/// follows it. An old primary that comes back steps down, and anything it changed meanwhile
/// shows under `conflicts`.
///
/// Refused when:
/// - the current primary is up;
/// - the node isn't eligible or lacks the cluster key;
/// - without `emergency`, the cluster takes its configuration from Git and this node isn't
///   managed from Git.
///
/// With `?dryRun=true`, nothing changes: the checks run and the answer is a `PromotePlan`
/// (the epoch, whether it would be an emergency primary, and a sentence on what would happen).
///
/// Admin only; audited as `cluster.promote`. From a signed-in session it needs `password`
/// (and `totp` with two-factor sign-in on); API tokens don't.
#[utoipa::path(post, path = "/api/v1/cluster/promote", tag = "system",
    params(PlainDryRun),
    request_body = crate::model::PromoteRequest,
    responses(
        (status = 200, body = crate::model::ClusterView, description = "Promoted; the cluster as it is now. With `dryRun=true`: a `PromotePlan` instead, and nothing changed."),
        (status = 400, body = Problem, description = "A signed-in session didn't send `password`."),
        (status = 401, body = Problem, description = "Not signed in, or two-factor sign-in is on and `totp` is missing (`totp_required`)."),
        (status = 403, body = Problem, description = "The password or code is wrong, or not an admin."),
        (status = 409, body = Problem, description = "Not allowed now (the primary is up, or this node can't be primary)."),
        (status = 429, body = Problem, description = "Too many wrong passwords: wait for Retry-After seconds."),
    ))]
pub(crate) async fn cluster_promote(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<PlainDryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<crate::model::PromoteRequest>, JsonRejection>,
) -> Response {
    let req = match body(b) {
        Ok(r) => r,
        Err(p) => return p.into_response(),
    };
    if q.dry_run.unwrap_or(false) {
        let b2 = Arc::clone(&backend);
        return tokio::task::spawn_blocking(move || b2.promote_plan(&req))
            .await
            .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))))
            .map_or_else(IntoResponse::into_response, |plan| {
                Json(plan).into_response()
            });
    }
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    // REQ: CLU-005, API-003 (`spec/12` §5, review 05-09) — the password (and code) again.
    let (a2, p2) = (Arc::clone(&auth), p.clone());
    let (password, totp) = (req.password.clone(), req.totp.clone());
    let confirmed = tokio::task::spawn_blocking(move || {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        a2.confirm(&p2, password.as_deref(), totp.as_deref(), now)
    })
    .await
    .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))));
    if let Err(e) = confirmed {
        return e.into_response();
    }
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let emergency = req.emergency;
    let (b2, by) = (Arc::clone(&backend), actor.name.clone());
    let result = tokio::task::spawn_blocking(move || b2.promote(req, by))
        .await
        .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))));
    match result {
        Ok(view) => {
            auth.record(
                &actor,
                "cluster.promote",
                view.this_node.as_deref().unwrap_or(""),
                &serde_json::json!({ "emergency": emergency }),
            );
            Json(view).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Download a backup of this node.
///
/// One `.ttbk` file (ADR-063) with the configuration files, users and API tokens, devices and
/// names made through the API, the audit log, statistics history, and anomaly baselines.
/// Sign-in sessions, lists, and the cluster identity aren't included, and neither is the
/// query log (use `POST /api/v1/backup` with `includeQlog`, or `wrendns backup create
/// --include-qlog`, for that). **The stored secrets are left out** (they are encrypted with this
/// node's key, which no backup holds): `X-Wrendns-Backup-Secrets: omitted; count=N` says how
/// many. `POST /api/v1/backup` with a passphrase carries them. Restore it with
/// `wrendns backup restore FILE` on the new machine.
///
/// The file holds password hashes: keep it private. Admin only; audited as `backup.create`.
#[utoipa::path(get, path = "/api/v1/backup", tag = "system",
    responses(
        (status = 200, content_type = "application/octet-stream", body = Vec<u8>,
            headers(("X-Wrendns-Backup-Secrets" = String, description = "`omitted; count=N`: how many stored secrets were left out.")),
            description = "The backup, as an attachment named `wrendns-<node>-<time>.ttbk`."),
        (status = 503, body = Problem, description = "Backups aren't available on this node."),
    ))]
pub(crate) async fn backup_download(
    State((backend, auth)): State<Ctx>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    backup_response(backend, &auth, &actor, false, None).await
}

/// REQ: API-007 (T23.9, ADR-903 §8) — the body of `POST /api/v1/backup`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BackupRequest {
    /// Also include the query log (refused when it is too big to build in memory: use the CLI).
    #[serde(default)]
    pub include_qlog: Option<bool>,
    /// At least 12 characters. With one, the node's stored secrets are encrypted into the backup
    /// (`data/secrets.enc`, Argon2id and ChaCha20-Poly1305), and the request needs a session
    /// signed in within the last 10 minutes. Write-only: never answered, logged or audited.
    #[serde(default)]
    #[schema(value_type = Option<String>, write_only, example = "correct horse battery staple")]
    pub passphrase: Option<crate::secrets_api::SecretText>,
}

/// Make a backup, optionally with the stored secrets.
///
/// Like `GET /api/v1/backup` (one `.ttbk`; ADR-063), and with a body it can carry more:
/// - `includeQlog`: the query log too;
/// - `passphrase` (at least 12 characters): the node's stored secrets, encrypted under a key made
///   from it (Argon2id m = 19 MiB, t = 2, p = 1; ChaCha20-Poly1305), as `data/secrets.enc`.
///   The archive is then format 2, which builds before this one refuse. Restore needs the
///   passphrase (`wrendns backup restore --secrets-passphrase-file`) or `--skip-secrets`.
///
/// `X-Wrendns-Backup-Secrets` says `included; count=N` or `omitted; count=N` (how many were left
/// out), and `X-Wrendns-Backup-Warnings` lists what to know (credentials held inline in the
/// configuration are copied as they are).
///
/// Admin only, never an agent token (403 `agent_not_allowed`), only over HTTPS or from the node
/// itself (403 `insecure_transport`). With a passphrase it needs an interactive session signed in
/// within the last 10 minutes: tokens and Basic sign-in get 403 `reauth_required`, with a hint to
/// run `wrendns backup create` on the node. One key derivation runs at a time: a second request
/// gets 429. On a cluster replica a passphrase is refused (409): make it on the primary, which
/// holds the same secrets and raises the alert. Audited as `backup.create` (`secretsIncluded`, `count`; never the passphrase), and
/// a backup with secrets raises the alert event `secrets_exported`. It takes no
/// `Idempotency-Key`: it changes no state.
#[utoipa::path(post, path = "/api/v1/backup", tag = "system",
    request_body(content = BackupRequest, description = "Optional: `includeQlog`, `passphrase`."),
    responses(
        (status = 200, content_type = "application/octet-stream", body = Vec<u8>,
            headers(
                ("X-Wrendns-Backup-Secrets" = String, description = "`included; count=N` or `omitted; count=N`."),
                ("X-Wrendns-Backup-Warnings" = String, description = "Present when there is something to know; items separated by ` | `."),
            ),
            description = "The backup, as an attachment named `wrendns-<node>-<time>.ttbk`."),
        (status = 400, body = Problem, description = "The body isn't valid, or the passphrase is under 12 characters, or the query log is too big for the API."),
        (status = 403, body = Problem, description = "Not an admin, an agent token (`agent_not_allowed`), plain HTTP from another host (`insecure_transport`), or a passphrase without a recent sign-in (`reauth_required`)."),
        (status = 409, body = Problem, description = "A backup with a passphrase on a cluster replica: make it on the primary."),
        (status = 429, body = Problem, description = "Another backup with a passphrase is deriving its key: wait for Retry-After seconds."),
        (status = 503, body = Problem, description = "Backups aren't available on this node, or its secrets key can't be read (`secrets_locked`)."),
    ))]
pub(crate) async fn backup_create(
    State((backend, auth)): State<Ctx>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    raw: axum::body::Bytes,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return no_store(e.into_response()),
    };
    if p.agent.is_some() {
        return no_store(
            Problem::new(
                Code::AgentNotAllowed,
                "agent tokens can't make backups, whatever their scopes",
            )
            .hint("A backup holds password hashes and, with a passphrase, every stored secret: it is for people.")
            .into_response(),
        );
    }
    if let Err(e) = crate::secrets_api::transport_ok(&auth, &backend, &ext, &headers) {
        return no_store(e.into_response());
    }
    // REQ: API-015 — the parser's own message can quote the input, so only its category is told.
    let req: BackupRequest = if raw.iter().all(u8::is_ascii_whitespace) {
        BackupRequest {
            include_qlog: None,
            passphrase: None,
        }
    } else {
        match serde_json::from_slice(&raw) {
            Ok(b) => b,
            Err(e) => {
                let what = match e.classify() {
                    serde_json::error::Category::Syntax => "isn't valid JSON",
                    serde_json::error::Category::Eof => "ended early",
                    serde_json::error::Category::Data => {
                        "has an unknown or wrongly typed field (`includeQlog` is a boolean, `passphrase` a string)"
                    }
                    serde_json::error::Category::Io => "couldn't be read",
                };
                return no_store(
                    Problem::invalid(format!(
                        "the body {what}; it should be {{\"includeQlog\": false, \"passphrase\": \"...\"}}"
                    ))
                    .into_response(),
                );
            }
        }
    };
    drop(raw);
    let passphrase = req
        .passphrase
        .map(crate::secrets_api::SecretText::into_inner);
    if let Some(pass) = &passphrase
        && pass.chars().count() < 12
    {
        return no_store(
            Problem::invalid("the passphrase must be at least 12 characters").into_response(),
        );
    }
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    if passphrase.is_some() {
        let (a2, p2, now) = (Arc::clone(&auth), p.clone(), backend.now_unix_seconds());
        let ok = tokio::task::spawn_blocking(move || a2.recent_sign_in(&p2, now))
            .await
            .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))));
        if let Err(e) = ok {
            return no_store(e.into_response());
        }
    }
    backup_response(
        backend,
        &auth,
        &actor,
        req.include_qlog.unwrap_or(false),
        passphrase,
    )
    .await
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    r
}

/// Builds the backup on a blocking thread, audits it, and answers with the file.
async fn backup_response(
    backend: Arc<dyn Backend>,
    auth: &Arc<Auth>,
    actor: &crate::auth::Actor,
    include_qlog: bool,
    passphrase: Option<zeroize::Zeroizing<String>>,
) -> Response {
    let b2 = Arc::clone(&backend);
    let result = tokio::task::spawn_blocking(move || b2.backup_create(include_qlog, passphrase))
        .await
        .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))));
    match result {
        Ok(out) => {
            // REQ: API-007 (ADR-903 §8) — the record says whether secrets went out and how many,
            // never the passphrase; the `secrets_exported` alert reads `secretsIncluded`.
            auth.record(
                actor,
                "backup.create",
                &out.name,
                &serde_json::json!({
                    "bytes": out.bytes.len(),
                    "secretsIncluded": out.secrets_included,
                    "count": out.secrets_count,
                    "includeQlog": include_qlog,
                }),
            );
            let mut resp = out.bytes.into_response();
            let h = resp.headers_mut();
            h.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            h.insert(
                axum::http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            );
            // The name is ours (letters, digits, `-`, `.`), so it's safe in the header.
            if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", out.name))
            {
                h.insert(axum::http::header::CONTENT_DISPOSITION, v);
            }
            let word = if out.secrets_included {
                "included"
            } else {
                "omitted"
            };
            if let Ok(v) = HeaderValue::from_str(&format!("{word}; count={}", out.secrets_count)) {
                h.insert(crate::legacy::BACKUP_SECRETS, v.clone());
                h.insert("x-wrendns-backup-secrets", v);
            }
            if !out.warnings.is_empty()
                && let Ok(v) = HeaderValue::from_str(&out.warnings.join(" | "))
            {
                h.insert(crate::legacy::BACKUP_WARNINGS, v.clone());
                h.insert("x-wrendns-backup-warnings", v);
            }
            resp
        }
        Err(e) => no_store(e.into_response()),
    }
}

/// REQ: DSC-913, DSC-910 (ADR-1104, the owner's decision of 2026-11-26) - an agent token that
/// would set, change or remove a device's location pin needs `config:write:locations` as well as
/// `config:write:clients`. A write that leaves the pin as it is (a rename or a regroup that keeps
/// it) passes. `existing` is the device `name` names, if any (read off the runtime by the caller).
fn pin_guard(
    p: &crate::auth::Principal,
    existing: Option<&crate::model::ClientInfo>,
    op: &Op,
) -> Result<(), Problem> {
    let Some(a) = p.agent.as_ref() else {
        return Ok(());
    };
    if a.scopes.contains("config:write:locations") {
        return Ok(());
    }
    let Op::Client(input) = op else {
        return Ok(());
    };
    let before = existing
        .filter(|c| c.location_pinned)
        .and_then(|c| c.location.as_deref());
    let after = input
        .as_ref()
        .and_then(|i| i.location.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if before == after {
        return Ok(());
    }
    Err(Problem::new(
        Code::Forbidden,
        "setting, changing or removing a device's location pin needs the `config:write:locations` scope as well as `config:write:clients`",
    )
    .hint("Create an agent token with both scopes (POST /api/v1/tokens with kind = agent), or leave the pin as it is."))
}

/// REQ: AGT-004 — an agent restricted to a group changes only that group's devices, and
/// only into that group (ADR-064). `existing` is the device `name` names, if any: the caller
/// reads it off the runtime (CLU-004), because a replica's read waits on the cluster.
fn group_guard(
    p: &crate::auth::Principal,
    existing: Option<&crate::model::ClientInfo>,
    name: &str,
    op: &Op,
) -> Result<(), Problem> {
    let Some(g) = p.agent.as_ref().and_then(|a| a.group.as_deref()) else {
        return Ok(());
    };
    let refuse = |why: String| {
        Err(Problem::new(Code::Forbidden, why)
            .hint(format!("This token is restricted to group `{g}`.")))
    };
    if let Some(c) = existing
        && !c.groups.iter().any(|x| x == g)
    {
        return refuse(format!("`{name}` isn't in group `{g}`"));
    }
    match op {
        Op::Client(Some(input)) if input.groups != [g] => refuse(format!(
            "devices you change must be in group `{g}` (set \"groups\": [\"{g}\"])"
        )),
        Op::Client(None) if existing.is_none() => refuse(format!("`{name}` isn't in group `{g}`")),
        Op::Client(_) => Ok(()),
        Op::Managed(..) => refuse(
            "restricted tokens can't change local names, forwarded domains, quick rules, upstreams, lists, or groups".into(),
        ),
    }
}

/// Add or change an alert destination (OBS-010, T9.6).
///
/// The body has the same fields as `[[alerts.destination]]` (the name comes from the path):
/// `{"type": "ntfy", "url": "https://ntfy.sh/my-topic"}`, or for email
/// `{"type": "email", "url": "smtp://smtp.gmail.com:587", "from": "me@gmail.com", "to":
/// ["me@gmail.com"], "username": "me@gmail.com", "password_file": "/run/secrets/smtp"}`, or for
/// Pushover `{"type": "pushover", "token_ref": "pushover-app", "user_key_ref": "pushover-user"}`
/// (the `url` defaults to Pushover's own; optional `device`, `sound`, `priority_firing`
/// (default 0), `priority_resolved` (default -1)).
/// Secrets stay in files on the node (`token_file`, `password_file`, `user_key_file`) or in its
/// encrypted store (`token_ref`, `password_ref`, `user_key_ref` name a stored secret: 422 `secret_missing` when none has that
/// name): only the path or the name is sent, and a password in `url` reads `<redacted>` wherever
/// the destination is shown (API-014; send it back as it is to keep it, as long as the URL's host
/// is unchanged). Setting a file or a reference is an admin's (OPS-014).
/// A destination the config files define is overridden until this one is deleted; a credential
/// the files set for it stays as they set it: left out of the body, it is kept, and a body that
/// sets, replaces or removes it is refused (409 `set_by_file`).
#[utoipa::path(put, path = "/api/v1/alerts/destinations/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files set this destination's credential, and they win."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, a reference names no stored secret (`secret_missing`), or the configuration wouldn't be valid: problem+json says which."),
    ))]
pub(crate) async fn put_alert_destination(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /alerts/destinations/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::AlertDestination, Some(input)),
    )
    .await
}

/// Remove an alert destination (OBS-010, T9.6).
///
/// Rules that still send to it make the configuration invalid (422 says which). A destination
/// the config files define, with a credential they set, can't be hidden (409 `set_by_file`).
#[utoipa::path(delete, path = "/api/v1/alerts/destinations/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files define it with a credential."),
        (status = 422, body = Problem, description = "A rule still uses it."),
    ))]
pub(crate) async fn delete_alert_destination(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /alerts/destinations/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::AlertDestination, None),
    )
    .await
}

/// Add or change a router integration.
///
/// API-016 (T23.7, ADR-921). The body has the same fields as `[[router]]` (the name comes from the path). Secrets are
/// named, never sent: `api_key_ref`, `api_secret_ref` and `password_ref` name stored secrets
/// (422 `secret_missing` when none has that name), entered through Settings → Integrations &
/// secrets. A certificate is sent as text in `tls_ca_pem`. The API takes no file paths for a
/// router (`api_key_file`, `api_secret_file`, `password_file`, `tls_ca`): those are set in the
/// configuration file. Admins only: an operator or an agent is refused (403).
/// A router the config files define is read-only here (409 `set_by_file`).
#[utoipa::path(put, path = "/api/v1/routers/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Only an admin can change a router."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files define this router, which is read-only here."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, a reference names no stored secret (`secret_missing`), a file path is set through the API, or the configuration wouldn't be valid."),
    ))]
pub(crate) async fn put_router(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /routers/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Router, Some(input)),
    )
    .await
}

/// Remove a router integration that the API added.
///
/// API-016 (T23.7). Its leases go with it at the next read; the routers that stay keep their last
/// answers.
#[utoipa::path(delete, path = "/api/v1/routers/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Only an admin can remove a router."),
        (status = 404, body = Problem, description = "No router by that name."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files define it."),
    ))]
pub(crate) async fn delete_router(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /routers/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Router, None),
    )
    .await
}

/// Add or change an OIDC sign-in provider.
///
/// API-016 (T23.10, ADR-903 §6, ADR-967). The body has the fields of `[[auth.oidc.provider]]`
/// (the ID comes from the path): `issuer`, `client_id`, `name`, `scopes`, the claims and the role
/// rules. The client secret is a name, never a value: `client_secret_ref` names a stored secret
/// (422 `secret_missing` when none has that name); `client_secret` and `client_secret_file` are
/// set in the configuration file, not through the API. Admins only: an operator or an agent is
/// refused (403). A provider the config files define is read-only here (409 `set_by_file`). The
/// provider is read and applied on every node without a restart; a node without `public_url`
/// shows it as inactive. Under a Git source the write is refused (409 `gitops_managed`).
#[utoipa::path(put, path = "/api/v1/oidc-providers/{id}", tag = "config",
    params(("id" = String, Path, description = "The provider ID: 1-32 lowercase letters, digits, or -."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Only an admin can change an OIDC provider."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files define this provider, which is read-only here."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, the reference names no stored secret (`secret_missing`), or a secret or file path is set through the API."),
    ))]
pub(crate) async fn put_oidc_provider(
    State((backend, auth)): State<Ctx>,
    Path(id): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /oidc-providers/{id} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        id,
        Op::Managed(ManagedKind::OidcProvider, Some(input)),
    )
    .await
}

/// Remove an OIDC provider that the API added.
///
/// API-016 (T23.10). The provider stops serving sign-ins on every node at once, and the sessions
/// that were opened through it end. The users it created stay (they can sign in again if the
/// provider returns).
#[utoipa::path(delete, path = "/api/v1/oidc-providers/{id}", tag = "config",
    params(("id" = String, Path, description = "The provider ID."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Only an admin can remove an OIDC provider."),
        (status = 404, body = Problem, description = "No provider by that ID."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files define it."),
    ))]
pub(crate) async fn delete_oidc_provider(
    State((backend, auth)): State<Ctx>,
    Path(id): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /oidc-providers/{id}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        id,
        Op::Managed(ManagedKind::OidcProvider, None),
    )
    .await
}

/// Add or change an event sink.
///
/// API-016, OBS-010 (T23.11, ADR-903 section 7, ADR-984). The body has the fields of
/// `[[telemetry.sink]]` (the name comes from the path): `type` (`file`, `syslog` or `webhook`),
/// `address`, `url`, `format`, `batch`, `flush_secs`, `max_buffer`, `statuses`, `spill_max_bytes`.
/// A file sink's `path` is a file name, written under the node's data directory (`sinks/`).
/// A webhook's token is a name, never a value: `token_ref` names a stored secret (422
/// `secret_missing` when none has that name); `token_file`, `tls_ca` and a password in a URL are
/// set in the configuration file, not through the API. Admins only: an operator or an agent is
/// refused (403). A sink the config files define is read-only here (409 `set_by_file`). The sink
/// starts, changes or stops on every node within seconds, without a restart. Under a Git source
/// the write is refused (409 `gitops_managed`).
#[utoipa::path(put, path = "/api/v1/sinks/{name}", tag = "config",
    params(("name" = String, Path, description = "The sink's name: unique, used in logs and metrics."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Only an admin can change an event sink."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files define this sink, which is read-only here."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, the reference names no stored secret (`secret_missing`), or a file path or a password in a URL is set through the API."),
    ))]
pub(crate) async fn put_sink(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /sinks/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Sink, Some(input)),
    )
    .await
}

/// Remove an event sink that the API added.
///
/// API-016 (T23.11). The sink sends what it holds (one try, within 2 seconds) and stops on every
/// node; the batches it kept on disk are deleted.
#[utoipa::path(delete, path = "/api/v1/sinks/{name}", tag = "config",
    params(("name" = String, Path, description = "The sink's name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Only an admin can remove an event sink."),
        (status = 404, body = Problem, description = "No sink by that name."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files define it."),
    ))]
pub(crate) async fn delete_sink(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /sinks/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Sink, None),
    )
    .await
}

/// Set the OTLP export.
///
/// API-016, OBS-006 (T23.11, ADR-984). The body has `endpoint` (the collector's base URL),
/// `interval_secs` and `header_refs`, a map from header name to the name of a stored secret that
/// holds the value (422 `secret_missing` when none has that name). Inline `headers`, the trace
/// settings and a password in the URL are set in the configuration file, not through the API.
/// Admins only. The files win: when they set an `endpoint`, `headers` or `header_refs`, this is
/// read-only (409 `set_by_file`). It applies on every node without a restart; the headers are read
/// for every export.
#[utoipa::path(put, path = "/api/v1/otlp/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Only an admin can change the OTLP export."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files set the OTLP destination."),
        (status = 422, body = Problem, description = "A field is wrong, or a reference names no stored secret (`secret_missing`)."),
    ))]
pub(crate) async fn put_otlp(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /otlp/default {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        "default".to_owned(),
        Op::Managed(ManagedKind::Otlp, Some(input)),
    )
    .await
}

/// Turn off the OTLP export the API set.
///
/// API-016 (T23.11). Metrics stop going out on every node (unless the configuration files set a
/// destination).
#[utoipa::path(delete, path = "/api/v1/otlp/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Only an admin can change the OTLP export."),
        (status = 404, body = Problem, description = "The API sets no OTLP export."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files set the OTLP destination."),
    ))]
pub(crate) async fn delete_otlp(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = "DELETE /otlp/default".to_owned();
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        "default".to_owned(),
        Op::Managed(ManagedKind::Otlp, None),
    )
    .await
}

/// Add or change an alert rule (OBS-010, T9.6).
///
/// The body has the same fields as `[[alerts.rule]]` (the name comes from the path):
/// `{"when": "upstream_down", "for_secs": 60, "to": ["phone"]}`. `when` is one of
/// `upstream_down`, `node_down`, `list_failing`, `anomaly`, `servfail_rate`,
/// `update_available`, `sync_lag`, `primary_unreachable`, `new_device`, `disk_full`, `plan_pending`.
#[utoipa::path(put, path = "/api/v1/alerts/rules/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid: problem+json says which."),
    ))]
pub(crate) async fn put_alert_rule(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /alerts/rules/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::AlertRule, Some(input)),
    )
    .await
}

/// Remove an alert rule (OBS-010, T9.6).
///
/// An alert the rule has firing stops being tracked (no "Resolved" message is sent). A rule
/// the config files define is hidden until this override is deleted in turn.
#[utoipa::path(delete, path = "/api/v1/alerts/rules/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
    ))]
pub(crate) async fn delete_alert_rule(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /alerts/rules/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::AlertRule, None),
    )
    .await
}

/// Send a test alert to one destination (OBS-010, T9.6).
///
/// Sends a message marked as a test, from this node, and answers with what happened: `ok`, or
/// the destination's error (a wrong password, an unreachable server). Nothing is stored, but
/// the test is audited. Needs the operator role.
#[utoipa::path(post, path = "/api/v1/alerts/destinations/{name}/test", tag = "config",
    params(("name" = String, Path, description = "The destination.")),
    responses(
        (status = 200, body = crate::model::AlertTest, description = "Sent, or why not."),
        (status = 404, body = Problem, description = "No destination by that name."),
    ))]
pub(crate) async fn test_alert_destination(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Result<Json<crate::model::AlertTest>, Problem> {
    let p = principal(&ext)?;
    let r = backend.alert_test(&name).await?;
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    auth.record(
        &actor,
        "alert.test",
        &name,
        &serde_json::json!({ "ok": r.ok, "error": r.error }),
    );
    Ok(Json(r))
}

/// Check a draft upstream before saving it (API-002, T9.12).
///
/// The body has the same fields as `PUT /api/v1/upstreams/{name}` (`name` optional). This node
/// builds it and asks it for the root's NS records, as health checks do, and answers with what
/// happened: `ok` with the rcode, records, and time, or the error (a bad URL, a TLS name that
/// doesn't match, a timeout). Nothing is saved; the check is audited. Needs the operator role
/// (agents: `config:write:upstreams`).
#[utoipa::path(post, path = "/api/v1/checks/upstream", tag = "config",
    request_body = Object,
    responses(
        (status = 200, body = crate::model::CheckResult, description = "Answered, or why not."),
        (status = 422, body = Problem, description = "The body isn't an upstream (an unknown or mistyped field)."),
    ))]
pub(crate) async fn check_upstream(
    State((backend, auth)): State<Ctx>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<crate::model::CheckResult>, Problem> {
    let p = principal(&ext)?;
    let input = body(b)?;
    let url = input.get("url").cloned().unwrap_or_default();
    // REQ: API-014 (T23.2, ADR-903 §4) — a check builds and runs the draft: one that runs a
    // program (`exec://`, `unix://`) or reads a file holding a credential is an admin's, as
    // saving it would be. Agents never, whatever their scopes.
    let program = wrendns_config::credentials::runs_program(url.as_str().unwrap_or_default());
    let key_file = wrendns_config::credentials::reference_changes("upstream", None, &input);
    if (program || !key_file.is_empty())
        && (p.role != crate::auth::Role::Admin || p.agent.is_some())
    {
        let what = if program {
            "an `exec://` or `unix://` upstream runs a program, or talks to a socket, on the node"
                .to_owned()
        } else {
            format!(
                "`{}` names a file holding a credential",
                key_file.join("`, `")
            )
        };
        return Err(Problem::new(
            Code::Forbidden,
            format!("only an admin can check this draft: {what}"),
        )
        .hint("Ask an admin to check and add this upstream."));
    }
    let mut r = backend.check_upstream(input).await?;
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    auth.record(
        &actor,
        "check.upstream",
        url.as_str().unwrap_or(""),
        &serde_json::json!({ "ok": r.ok, "error": r.error }),
    );
    // REQ: AGT-009 (review 06 q5) — why a probe failed (refused, timed out, reset) tells open
    // from closed ports: an agent learns only that it didn't answer. The audit log keeps it.
    if p.agent.is_some() && !r.ok && r.detail != "not built" {
        r.error = Some("unreachable (an operator can see why in the UI)".into());
        "no answer".clone_into(&mut r.detail);
    }
    Ok(Json(r))
}

/// Check a draft list before saving it (API-002, T9.12).
///
/// The body has the same fields as `PUT /api/v1/lists/{name}` (`name` optional): a `url` is
/// downloaded from this node (with `[filter]`'s size limit and timeout), or `rules` are taken
/// as they are, then parsed as the compiler would. Answers with the rules found, the lines it
/// couldn't use, and the time. Nothing is saved or compiled; the check is audited. `path`
/// lists are checked when saved. Needs the operator role (agents: `config:write:lists`).
#[utoipa::path(post, path = "/api/v1/checks/list", tag = "config",
    request_body = Object,
    responses(
        (status = 200, body = crate::model::CheckResult, description = "Parsed, or why not."),
        (status = 422, body = Problem, description = "The body isn't a list (an unknown or mistyped field), or it has no url or rules."),
    ))]
pub(crate) async fn check_list(
    State((backend, auth)): State<Ctx>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<crate::model::CheckResult>, Problem> {
    let p = principal(&ext)?;
    let input = body(b)?;
    let url = input.get("url").cloned().unwrap_or_default();
    let mut r = backend.check_list(input).await?;
    // REQ: AGT-009 — the sample lines are the fetched content: operators see them in the UI;
    // an agent gets how many and why (the node would otherwise read any URL it can reach on
    // the agent's behalf). The shape `line N: <text> (<reason>)` is `checks::list`'s.
    if p.agent.is_some() && !r.warnings.is_empty() {
        let reasons: std::collections::BTreeSet<&str> = r
            .warnings
            .iter()
            .filter_map(|w| w.rsplit_once(" ("))
            .map(|(_, reason)| reason.trim_end_matches(')'))
            .collect();
        r.warnings = vec![format!(
            "{} line(s) couldn't be used ({}); an operator can see them in the UI",
            r.warnings.len(),
            reasons.into_iter().collect::<Vec<_>>().join(", ")
        )];
    }
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    auth.record(
        &actor,
        "check.list",
        url.as_str().unwrap_or("(rules)"),
        &serde_json::json!({ "ok": r.ok, "rules": r.rules, "error": r.error }),
    );
    // REQ: AGT-009 (review 06 q5) — likewise for a download that failed.
    if p.agent.is_some() && r.detail == "not downloaded" {
        r.error = Some("unreachable (an operator can see why in the UI)".into());
    }
    Ok(Json(r))
}

/// Add or change a schedule (FLT-010, T9.7).
///
/// The body has the same fields as `[[schedule]]` (the name comes from the path), e.g. a
/// bedtime: `{"action": "block_all", "tz": "America/New_York", "window": [{"days":
/// ["weekdays"], "start": "21:00", "end": "07:00"}]}`. Groups use a schedule by naming it in
/// their `schedules`. A schedule the config files define is overridden until this one is
/// deleted.
#[utoipa::path(put, path = "/api/v1/schedules/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong (a window's time, an unknown list or service), or the configuration wouldn't be valid."),
    ))]
pub(crate) async fn put_schedule(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /schedules/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Schedule, Some(input)),
    )
    .await
}

/// Mute kinds of device anomaly for some devices or groups (OBS-038).
///
/// The body has the same fields as `[[anomaly_mute]]` (the name comes from the path):
/// `devices` (device names, IPs or CIDRs) and/or `groups`, `kinds` (`rate_spike`,
/// `domain_volume`, `drift`, `beacon`, `nxdomain_storm`, `dga`, `chatty_loop`), and optionally
/// `expires` (RFC 3339) and `note`, e.g. `{"devices": ["lg-tv-living"], "kinds":
/// ["nxdomain_storm"], "expires": "2026-12-31T00:00:00Z", "note": "hourly PTR sweep"}`. A finding
/// a mute matches when it is created is still recorded and listed (`GET
/// /analytics/anomalies?muted=true`, with `mutedBy`), but isn't counted in
/// `wrendns_anomalies_total`, the badge, the `anomaly` alert rule, or the health level
/// (`wrendns_anomalies_muted_total` counts it). The same kind still counts for every other
/// device. The mute is shared: it applies on every node. There is no mute for everyone: name at
/// least one device or group.
#[utoipa::path(put, path = "/api/v1/anomaly-mutes/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong (no device or group, an unknown kind, a name that matches nothing, a MAC address), or the configuration wouldn't be valid."),
    ))]
pub(crate) async fn put_anomaly_mute(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /anomaly-mutes/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::AnomalyMute, Some(input)),
    )
    .await
}

/// Remove an anomaly mute (OBS-038).
///
/// Findings created from now on count again; ones recorded while the mute held stay muted.
#[utoipa::path(delete, path = "/api/v1/anomaly-mutes/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
    ))]
pub(crate) async fn delete_anomaly_mute(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /anomaly-mutes/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::AnomalyMute, None),
    )
    .await
}

/// Put Kubernetes workloads in a group (FLT-017).
///
/// Writes a `[[kubernetes.map]]` rule: the key in the path is `namespace/kind/name` with `*` for
/// any (`media/deploy/jellyfin` for one workload, `media*/*/*` for every namespace starting with
/// `media`), the body names the group: `{"group": "iot"}`. Rules made here are checked before
/// the configuration files' (first match wins); a pod or namespace label
/// (`wrendns.com/group`) still wins over any rule (the way to do the same from Git).
/// The workload's next query uses the group.
#[utoipa::path(put, path = "/api/v1/kubernetes/map/{key}", tag = "config",
    params(("key" = String, Path, description = "namespace/kind/name; `*` for any kind or name; the namespace may be a glob."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 400, body = Problem, description = "The key isn't namespace/kind/name, or the body has no `group`."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "No such group, or an unknown kind."),
    ))]
pub(crate) async fn put_kubernetes_map(
    State((backend, auth)): State<Ctx>,
    Path(key): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let key = key.trim_start_matches('/').to_owned();
    let request = format!("PUT /kubernetes/map/{key} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        key,
        Op::Managed(ManagedKind::KubernetesMap, Some(input)),
    )
    .await
}

/// Remove a Kubernetes workloads' group rule (FLT-017).
///
/// A rule made here goes; a rule of the configuration files is hidden until this one is put
/// back. The workloads it matched take the next rule, `default_group`, or their network's group.
#[utoipa::path(delete, path = "/api/v1/kubernetes/map/{key}", tag = "config",
    params(("key" = String, Path, description = "namespace/kind/name, as the rule was made."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No rule by that key."),
    ))]
pub(crate) async fn delete_kubernetes_map(
    State((backend, auth)): State<Ctx>,
    Path(key): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let key = key.trim_start_matches('/').to_owned();
    let request = format!("DELETE /kubernetes/map/{key}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        key,
        Op::Managed(ManagedKind::KubernetesMap, None),
    )
    .await
}

/// Remove a schedule (FLT-010, T9.7).
///
/// A group that still names it makes the configuration invalid (422 says which): take it out
/// of the group's `schedules` first.
#[utoipa::path(delete, path = "/api/v1/schedules/{name}", tag = "config",
    params(("name" = String, Path, description = "The name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No entry by that name."),
        (status = 422, body = Problem, description = "A group still uses it."),
    ))]
pub(crate) async fn delete_schedule(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /schedules/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Schedule, None),
    )
    .await
}

/// Set the per-client rate limit (DNS-014).
///
/// The body has the same fields as `[ratelimit]` in `wrendns.toml`: `enabled`, `queries` (allowed
/// per window, per client; bursts up to this), `window_secs`, `action` (`refused` or `drop`),
/// `exempt` (CIDRs never limited), `ipv4_prefix`, and `ipv6_prefix` (how clients are grouped: 32
/// is one address, 64 groups a device's rotating IPv6 addresses). It replaces the whole section
/// (fields left out take the defaults, not the config file's values) until it's deleted again.
/// A router or proxy that forwards for a whole network shows up as one client: add it to
/// `exempt`, or raise `queries`. Applies on the next query, with no restart; every client's count
/// starts over.
#[utoipa::path(put, path = "/api/v1/ratelimit/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong (a prefix, a CIDR, zero queries while enabled), or the configuration wouldn't be valid."),
    ))]
pub(crate) async fn put_ratelimit(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /ratelimit/default {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        "default".to_owned(),
        Op::Managed(ManagedKind::RateLimit, Some(input)),
    )
    .await
}

/// Go back to the config file's rate limit (DNS-014).
///
/// Removes what the API or UI stored, so `[ratelimit]` in the config files (or the defaults)
/// applies again. 404 when nothing was stored.
#[utoipa::path(delete, path = "/api/v1/ratelimit/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's rate limit is in effect already."),
    ))]
pub(crate) async fn delete_ratelimit(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        "DELETE /ratelimit/default".to_owned(),
        "default".to_owned(),
        Op::Managed(ManagedKind::RateLimit, None),
    )
    .await
}

/// Keep names and devices out of the query log and analytics (OBS-022).
///
/// The body has the same fields as `[exclusions]` in `wrendns.toml`: `enabled` (turn them on or
/// off without losing the lists), `names` (each with its subdomains, e.g.
/// `connectivitycheck.gstatic.com`), and `clients` (addresses or networks). Their queries are
/// still answered and still counted in `/metrics`, but left out of the query log, the live view,
/// the dashboard and top lists, anomalies, and every export. `log` (clients as addresses,
/// networks or device names; `domains`, exact or `*.` for everything under; `own_lookups`) keeps
/// queries out of the query log, the live view and the event sinks only: the statistics still
/// count them (OBS-903). It replaces the whole section until it's deleted again; it applies to
/// every node of a cluster from the next query on.
#[utoipa::path(put, path = "/api/v1/exclusions/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A name isn't a domain name, a client isn't an address or network, or the configuration wouldn't be valid."),
    ))]
pub(crate) async fn put_exclusions(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /exclusions/default {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        "default".to_owned(),
        Op::Managed(ManagedKind::Exclusions, Some(input)),
    )
    .await
}

/// Go back to the config file's exclusions (OBS-022).
///
/// Removes what the API or UI stored, so `[exclusions]` in the config files (or none) applies
/// again. 404 when nothing was stored.
#[utoipa::path(delete, path = "/api/v1/exclusions/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's exclusions are in effect already."),
    ))]
pub(crate) async fn delete_exclusions(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        "DELETE /exclusions/default".to_owned(),
        "default".to_owned(),
        Op::Managed(ManagedKind::Exclusions, None),
    )
    .await
}

/// REQ: CLU-013 — `[cluster.rollout]`, for admins (merged with `require_admin`).
pub(crate) fn rollout_settings_routes(backend: Arc<dyn Backend>, auth: Arc<Auth>) -> Router {
    Router::new()
        .route(
            "/api/v1/cluster/rollout-settings/default",
            axum::routing::put(put_rollout_settings).delete(delete_rollout_settings),
        )
        .with_state((backend, auth))
}

/// Staged rollouts' settings (CLU-013).
///
/// The body has the same fields as `[cluster.rollout]` in `wrendns.toml`: `canaries` (node
/// IDs, `site:<name>`, or `ephemeral` for the resolver pods; empty = no rollouts), `bake_secs`
/// (at least 5), `servfail_pct`, `require_traffic`, `max_bake_secs`, `fail_on_disconnect`, and
/// `history` (versions kept for pinning). It replaces the whole section until deleted again,
/// on every node. A change to these settings is published at once, never staged itself.
/// Admins only (agents: `cluster:admin`).
#[utoipa::path(put, path = "/api/v1/cluster/rollout-settings/default", tag = "system",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A bound is out of range or a canary isn't a node ID, `site:<name>`, or `ephemeral`."),
    ))]
pub(crate) async fn put_rollout_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /cluster/rollout-settings/default {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        "default".to_owned(),
        Op::Managed(ManagedKind::Rollout, Some(input)),
    )
    .await
}

/// Go back to the config file's rollout settings (CLU-013).
///
/// Removes what the API or UI stored, so `[cluster.rollout]` in the config files (or the
/// default: no rollouts) applies again. 404 when nothing was stored.
#[utoipa::path(delete, path = "/api/v1/cluster/rollout-settings/default", tag = "system",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_rollout_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        "DELETE /cluster/rollout-settings/default".to_owned(),
        "default".to_owned(),
        Op::Managed(ManagedKind::Rollout, None),
    )
    .await
}

/// Change simulation's settings (OBS-024).
///
/// The body has the same fields as `[simulate]` in `wrendns.toml`: `enabled` (simulations at
/// all), `plans_by_default` (agents' plans simulate even when they don't ask), `max_secs`
/// (1 to 300), `max_rows` (at least 1,000), and `default_window` (`24h`; at most `7d`). It
/// replaces the whole section until it's deleted again, on every node of a cluster.
#[utoipa::path(put, path = "/api/v1/simulate-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A bound is out of range, or the configuration wouldn't be valid."),
    ))]
pub(crate) async fn put_simulate_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /simulate-settings/default {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        "default".to_owned(),
        Op::Managed(ManagedKind::Simulate, Some(input)),
    )
    .await
}

/// Go back to the config file's simulation settings (OBS-024).
///
/// Removes what the API or UI stored, so `[simulate]` in the config files (or the defaults)
/// applies again. 404 when nothing was stored.
#[utoipa::path(delete, path = "/api/v1/simulate-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_simulate_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        "DELETE /simulate-settings/default".to_owned(),
        "default".to_owned(),
        Op::Managed(ManagedKind::Simulate, None),
    )
    .await
}

/// The live network map's settings (OBS-901).
///
/// The body has the same fields as `[map]` in `wrendns.toml`: `enabled`, `event_rate` (lookups
/// per second each node samples, 10 to 2,000), `min_sample` (answers before a device or edge is
/// coloured, 1 to 1,000), `warn_latency_ms` (unset: the latency objective's), and the percent
/// thresholds `warn_slow_pct`, `warn_error_pct`, `error_pct` and `warn_blocked_pct` (1 to 100;
/// `error_pct` at least `warn_error_pct`). It replaces the whole section until it's deleted
/// again, on every node of a cluster, and applies within a few seconds with no restart.
#[utoipa::path(put, path = "/api/v1/map-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A value is out of range (the detail names the field), or the configuration wouldn't be valid."),
    ))]
pub(crate) async fn put_map_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /map-settings/default {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        "default".to_owned(),
        Op::Managed(ManagedKind::Map, Some(input)),
    )
    .await
}

/// Go back to the config file's map settings (OBS-901).
///
/// Removes what the API or UI stored, so `[map]` in the config files (or the defaults)
/// applies again. 404 when nothing was stored.
#[utoipa::path(delete, path = "/api/v1/map-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_map_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        "DELETE /map-settings/default".to_owned(),
        "default".to_owned(),
        Op::Managed(ManagedKind::Map, None),
    )
    .await
}

/// Set the special-name handling (DNS-019, ADR-904).
///
/// The body has the fields of `[special]` in `wrendns.toml`: `block_firefox_canary`, `localhost`,
/// `private_ptr_nxdomain`, `refuse_chaos`, `block_icloud_private_relay`, `single_label_nxdomain`,
/// and `ddr_name` (the name the encrypted listeners' certificates carry, for DDR). It replaces the
/// whole section (fields left out take the defaults), except fields the config files set: those
/// win, and a body that sets one to another value is 409 `set_by_file`. Applies on the next query,
/// with no restart. `ddr_name` is admin-only: an operator's change is 403 naming the field, and
/// no agent changes it.
#[utoipa::path(put, path = "/api/v1/special-names/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "An operator changes `ddr_name` (admin-only), or an agent does."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files set that field, and they win."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong or unknown, or the configuration wouldn't be valid."),
    ))]
pub(crate) async fn put_special(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Special,
        "/special-names/default",
    )
    .await
}

/// Go back to the config file's special-name handling (DNS-019).
///
/// Removes what the API or UI stored, so `[special]` in the config files (or the defaults) applies
/// again. 404 when nothing was stored.
#[utoipa::path(delete, path = "/api/v1/special-names/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "The change would switch `ddr_name` off, and only an admin may."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_special(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Special,
        "DELETE /special-names/default",
    )
    .await
}

/// Set the device-name settings (DNS-023, ADR-901).
///
/// The body has the fields of `[local]` that name devices: `device_domain` (a domain such as
/// `home.arpa`; `local` is refused), `device_ttl` (seconds), `device_mdns` (names devices announce
/// over mDNS, which needs `[clients] mdns`), `auto_ptr`, and `default_ttl`. `hosts_files` is set in
/// the file only. Like `PUT /special-names/default`, the file's fields win (409 `set_by_file`).
/// Names change within about 10 seconds on every node, with no restart.
#[utoipa::path(put, path = "/api/v1/local-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files set that field, and they win."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A field is wrong or unknown (a domain `local`, for one), or the configuration wouldn't be valid."),
    ))]
pub(crate) async fn put_local(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Local,
        "/local-settings/default",
    )
    .await
}

/// Go back to the config file's device-name settings (DNS-023).
///
/// Removes what the API or UI stored: the fields the config files don't set go back to the file's
/// values (or the defaults), and the names change within about 10 seconds. Needs the operator role.
#[utoipa::path(delete, path = "/api/v1/local-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_local(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Local,
        "DELETE /local-settings/default",
    )
    .await
}

/// Set the `[clients]` setting this API changes (DNS-023, T24.13, ADR-914).
///
/// Only `mdns` is here: when on, WrenDNS listens for mDNS announcements on every node, which
/// names devices that announce themselves (`[local] device_mdns` answers for them). `mdns_port`
/// stays in the file. This is admin-only: an operator's change is 403 naming `mdns`, and no agent
/// can change it.
#[utoipa::path(put, path = "/api/v1/clients-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Only an admin may change `mdns`; agents never."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files set `mdns`, and they win."),
        (status = 422, body = Problem, description = "A field is unknown (`mdns_port` is set in the file)."),
    ))]
pub(crate) async fn put_clients_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Clients,
        "/clients-settings/default",
    )
    .await
}

/// Set the network inventory's settings (DSC-001, T25.2, ADR-907): whether it runs, the node that
/// runs it, the subnets it may read, and the worker memory limit.
///
/// Admin only: an operator's change is 403, and no agent can change it. The first write is refused
/// with 409 `members_too_old` while any member runs a version older than this one (ADR-907, CLU-010).
/// The configuration files win field by field (`set_by_file`).
#[utoipa::path(put, path = "/api/v1/discovery-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Only an admin may change the network inventory; agents never."),
        (status = 409, body = Problem, description = "`set_by_file`, or `members_too_old`: a member runs an older version."),
        (status = 422, body = Problem, description = "A field is unknown, or a subnet isn't a private IPv4 network."),
    ))]
pub(crate) async fn put_discovery_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Discovery,
        "/discovery-settings/default",
    )
    .await
}

/// Go back to the config file's `[discovery]` section (DSC-001).
///
/// Removes what the API stored, so the file's settings apply again. Admin only; no agent.
#[utoipa::path(delete, path = "/api/v1/discovery-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Only an admin may change the network inventory; agents never."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_discovery_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Discovery,
        "DELETE /discovery-settings/default",
    )
    .await
}

/// Set the CMDB's settings (DSC-901, DSC-906, T31.2, ADR-1005): whether it runs, how long a device
/// must be gone before a delete is raised, the settle time, the alert and plan times, and how long
/// history and change records are kept.
///
/// Admin only: an operator's change is 403, and no agent can change it. The CMDB runs on the node
/// `[discovery]` designates, and `enabled` is refused at privacy level 2 and above. The first write
/// is refused with 409 `members_too_old` while any member runs a version older than this one. The
/// configuration files win field by field (`set_by_file`).
#[utoipa::path(put, path = "/api/v1/cmdb-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Only an admin may change the CMDB's settings; agents never."),
        (status = 409, body = Problem, description = "`set_by_file`, or `members_too_old`: a member runs an older version."),
        (status = 422, body = Problem, description = "A field is unknown or out of range, or `enabled` at privacy level 2 or more."),
    ))]
pub(crate) async fn put_cmdb_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Cmdb,
        "/cmdb-settings/default",
    )
    .await
}

/// Go back to the config file's `[cmdb]` section (DSC-901).
///
/// Removes what the API stored, so the file's settings apply again. Admin only; no agent.
#[utoipa::path(delete, path = "/api/v1/cmdb-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Only an admin may change the CMDB's settings; agents never."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_cmdb_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Cmdb,
        "DELETE /cmdb-settings/default",
    )
    .await
}

/// Set the objectives (`[slo]`): the availability and latency targets, the latency threshold and the window. Operators change them; the error budget and the burn-rate alerts follow on every node within a few seconds.
///
/// REQ: OBS-016 (T27.5, ADR-1007). Admin only for the telemetry sections; operators for the rest. Agents never.
/// The configuration files win field by field (`set_by_file`), and a field left out takes its default.
#[utoipa::path(put, path = "/api/v1/slo-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Not allowed for this role, or an agent."),
        (status = 409, body = Problem, description = "`set_by_file`: a field the configuration files set."),
        (status = 422, body = Problem, description = "A field is unknown or out of range."),
    ))]
pub(crate) async fn put_slo_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Slo,
        "/slo-settings/default",
    )
    .await
}

/// Go back to the configuration file's `[slo]` settings (ADR-1007).
///
/// Removes what the API stored, so the file's settings apply again on every node (ADR-1007).
#[utoipa::path(delete, path = "/api/v1/slo-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Not allowed for this role, or an agent."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_slo_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Slo,
        "DELETE /slo-settings/default",
    )
    .await
}

/// Set the listener checks (`[probe]`): on or off, the interval (at least 5 seconds), the timeout, extra targets and the certificate warning. Operators change them; every node applies them with the next round.
///
/// REQ: OBS-020 (T27.5, ADR-1007). Admin only for the telemetry sections; operators for the rest. Agents never.
/// The configuration files win field by field (`set_by_file`), and a field left out takes its default.
#[utoipa::path(put, path = "/api/v1/probe-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Not allowed for this role, or an agent."),
        (status = 409, body = Problem, description = "`set_by_file`: a field the configuration files set."),
        (status = 422, body = Problem, description = "A field is unknown or out of range."),
    ))]
pub(crate) async fn put_probe_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Probe,
        "/probe-settings/default",
    )
    .await
}

/// Go back to the configuration file's `[probe]` settings (ADR-1007).
///
/// Removes what the API stored, so the file's settings apply again on every node (ADR-1007).
#[utoipa::path(delete, path = "/api/v1/probe-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Not allowed for this role, or an agent."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_probe_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Probe,
        "DELETE /probe-settings/default",
    )
    .await
}

/// Set the second opinions (`[upstream_check]`): one question in `sample_every` (0 is off), the reference group and how many disagreements are kept. Operators change them.
///
/// REQ: OBS-019 (T27.5, ADR-1007). Admin only for the telemetry sections; operators for the rest. Agents never.
/// The configuration files win field by field (`set_by_file`), and a field left out takes its default.
#[utoipa::path(put, path = "/api/v1/upstream-check-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Not allowed for this role, or an agent."),
        (status = 409, body = Problem, description = "`set_by_file`: a field the configuration files set."),
        (status = 422, body = Problem, description = "A field is unknown or out of range."),
    ))]
pub(crate) async fn put_upstream_check_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::UpstreamCheck,
        "/upstream-check-settings/default",
    )
    .await
}

/// Go back to the configuration file's `[upstream_check]` settings (ADR-1007).
///
/// Removes what the API stored, so the file's settings apply again on every node (ADR-1007).
#[utoipa::path(delete, path = "/api/v1/upstream-check-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Not allowed for this role, or an agent."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_upstream_check_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::UpstreamCheck,
        "DELETE /upstream-check-settings/default",
    )
    .await
}

/// Set device anomaly detection (`[telemetry.anomaly]`): on or off, the learning period, sensitivity, the device and domain limits and the NXDOMAIN storm thresholds. Admins only: the whole kind is admin-only, and no agent can change it.
///
/// REQ: OBS-013 (T27.5, ADR-1007). Admin only for the telemetry sections; operators for the rest. Agents never.
/// The configuration files win field by field (`set_by_file`), and a field left out takes its default.
#[utoipa::path(put, path = "/api/v1/anomaly-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Not allowed for this role, or an agent."),
        (status = 409, body = Problem, description = "`set_by_file`: a field the configuration files set."),
        (status = 422, body = Problem, description = "A field is unknown or out of range."),
    ))]
pub(crate) async fn put_anomaly_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::TelemetryAnomaly,
        "/anomaly-settings/default",
    )
    .await
}

/// Go back to the configuration file's `[telemetry.anomaly]` settings (ADR-1007).
///
/// Removes what the API stored, so the file's settings apply again on every node (ADR-1007).
#[utoipa::path(delete, path = "/api/v1/anomaly-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Not allowed for this role, or an agent."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_anomaly_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::TelemetryAnomaly,
        "DELETE /anomaly-settings/default",
    )
    .await
}

/// Set the query log's store (`[telemetry.qlog]`): on or off, retention, the privacy level, fsync and the flush interval. Admins only, since privacy and retention are at stake; no agent can change it.
///
/// REQ: OBS-003 (T27.5, ADR-1007). Admin only for the telemetry sections; operators for the rest. Agents never.
/// The configuration files win field by field (`set_by_file`), and a field left out takes its default.
#[utoipa::path(put, path = "/api/v1/qlog-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Not allowed for this role, or an agent."),
        (status = 409, body = Problem, description = "`set_by_file`: a field the configuration files set."),
        (status = 422, body = Problem, description = "A field is unknown or out of range."),
    ))]
pub(crate) async fn put_qlog_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::TelemetryQlog,
        "/qlog-settings/default",
    )
    .await
}

/// Go back to the configuration file's `[telemetry.qlog]` settings (ADR-1007).
///
/// Removes what the API stored, so the file's settings apply again on every node (ADR-1007).
#[utoipa::path(delete, path = "/api/v1/qlog-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Not allowed for this role, or an agent."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_qlog_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::TelemetryQlog,
        "DELETE /qlog-settings/default",
    )
    .await
}

/// Set the per-client metric series (`[telemetry.metrics]`): on or off, and the cap on how many clients get their own series. Admins only; no agent can change it.
///
/// REQ: OBS-005 (T27.5, ADR-1007). Admin only for the telemetry sections; operators for the rest. Agents never.
/// The configuration files win field by field (`set_by_file`), and a field left out takes its default.
#[utoipa::path(put, path = "/api/v1/metrics-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Not allowed for this role, or an agent."),
        (status = 409, body = Problem, description = "`set_by_file`: a field the configuration files set."),
        (status = 422, body = Problem, description = "A field is unknown or out of range."),
    ))]
pub(crate) async fn put_metrics_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::TelemetryMetrics,
        "/metrics-settings/default",
    )
    .await
}

/// Go back to the configuration file's `[telemetry.metrics]` settings (ADR-1007).
///
/// Removes what the API stored, so the file's settings apply again on every node (ADR-1007).
#[utoipa::path(delete, path = "/api/v1/metrics-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Not allowed for this role, or an agent."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_metrics_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::TelemetryMetrics,
        "DELETE /metrics-settings/default",
    )
    .await
}

/// Narrow the dnstap output (`[telemetry.dnstap]`): the tap off, a feed off, sampling less often, a different queue size. Admins only; no agent can change it.
///
/// REQ: OBS-007, API-905 (T40.13, ADR-1107). The whole section is one entry: a field left out takes its default. The tap is
/// read when the node starts, so a change applies after a restart of every node (the answer says so). A change that copies
/// more of the clients' queries out of the process (the tap on, another socket or address, upstream or recursor exchanges
/// added, sampling more often) is refused with 409 `guarded_only`: it goes through the guarded review (`/api/v1/guarded/dnstap-output`:
/// a preview, the typed phrase, a sign-in within the last 10 minutes and the `settings.guarded` audit record). A file that
/// sets a field wins (`set_by_file`). Held until every cluster member announces the kind (409 `upgrade_required`).
#[utoipa::path(put, path = "/api/v1/dnstap-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change; `warnings` says that a restart is needed)."),
        (status = 403, body = Problem, description = "Not an admin, or an agent."),
        (status = 409, body = Problem, description = "`guarded_only` (the change copies more: use the guarded review), `set_by_file`, or a cluster member's build does not know the dnstap settings yet (`upgrade_required`)."),
        (status = 422, body = Problem, description = "A field is unknown or out of range (`buffer` 100 to 1000000, `sample_every` at least 1, a socket or an address, not both)."),
    ))]
pub(crate) async fn put_dnstap_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::TelemetryDnstap,
        "/dnstap-settings/default",
    )
    .await
}

/// Go back to the configuration file's `[telemetry.dnstap]` settings (OBS-007).
///
/// Removes what the API stored, so the file's settings (or the defaults: no tap) apply again on every node after a restart.
/// Never held for an old member: it is the way out.
#[utoipa::path(delete, path = "/api/v1/dnstap-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Not an admin, or an agent."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's settings are in effect already."),
    ))]
pub(crate) async fn delete_dnstap_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::TelemetryDnstap,
        "DELETE /dnstap-settings/default",
    )
    .await
}

/// Go back to the config file's `[clients]` mdns setting (DNS-023).
///
/// Removes what the API stored, so the file's `mdns` applies again on every node. Only an admin may
/// do this, and no agent can.
#[utoipa::path(delete, path = "/api/v1/clients-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Only an admin may change `mdns`; agents never."),
        (status = 404, body = Problem, description = "Nothing was changed through the API: the file's setting is in effect already."),
    ))]
pub(crate) async fn delete_clients_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Clients,
        "DELETE /clients-settings/default",
    )
    .await
}

/// REQ: DNS-006, OPS-011, OPS-012 (T27.2, T27.11, ADR-1006) — a per-node section (`[cache]`,
/// `[support] persist_logs`, `[updates] check`) changed for the node named in the path. The
/// plan checks the role (admins only) and that the node is one of the cluster's.
#[allow(clippy::too_many_arguments)] // the extractors, plus the kind, the node and the prefix
async fn put_node_settings(
    backend: Arc<dyn Backend>,
    auth: Arc<Auth>,
    q: DryRun,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
    kind: ManagedKind,
    node: String,
    prefix: &str,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT {prefix}/{node} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        node,
        Op::Managed(kind, Some(input)),
    )
    .await
}

/// The shared body of the `DELETE`s of the per-node sections.
#[allow(clippy::too_many_arguments)] // the extractors, plus the kind, the node and the prefix
async fn delete_node_settings(
    backend: Arc<dyn Backend>,
    auth: Arc<Auth>,
    q: DryRun,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    kind: ManagedKind,
    node: String,
    prefix: &str,
) -> Response {
    let request = format!("DELETE {prefix}/{node}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        node,
        Op::Managed(kind, None),
    )
    .await
}

/// The `[cache]` section of one node (DNS-006, T27.2): the 15 fields, admins only.
///
/// Every field takes effect after a restart of that node; the files' fields win (`set_by_file`).
#[utoipa::path(put, path = "/api/v1/cache-settings/{node}", tag = "config",
    params(("node" = String, Path, description = "The node ID the settings apply to."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Only an admin can change a node's cache settings."),
        (status = 404, body = Problem, description = "No node of this cluster has that ID."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files set this field, which is read-only here."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid."),
    ))]
pub(crate) async fn put_cache_settings(
    State((backend, auth)): State<Ctx>,
    Path(node): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_node_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Cache,
        node,
        "/cache-settings",
    )
    .await
}

/// Removes the `[cache]` section the API set for one node (the files' apply again).
///
/// The node then runs with the config files' cache settings, or the defaults, after a restart.
#[utoipa::path(delete, path = "/api/v1/cache-settings/{node}", tag = "config",
    params(("node" = String, Path, description = "The node ID."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Only an admin can change a node's cache settings."),
        (status = 404, body = Problem, description = "The API sets no cache settings on that node."),
    ))]
pub(crate) async fn delete_cache_settings(
    State((backend, auth)): State<Ctx>,
    Path(node): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_node_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Cache,
        node,
        "/cache-settings",
    )
    .await
}

/// REQ: OPS-011 (T27.11, ADR-1006) — `[support] persist_logs` for one node. Admins only.
///
/// The node's log files are kept on disk (or not) from its next start; the files' value wins.
#[utoipa::path(put, path = "/api/v1/support-settings/{node}", tag = "config",
    params(("node" = String, Path, description = "The node ID the settings apply to."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Only an admin can change this."),
        (status = 404, body = Problem, description = "No node of this cluster has that ID."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files set this field."),
        (status = 422, body = Problem, description = "A field is wrong."),
    ))]
pub(crate) async fn put_support_settings(
    State((backend, auth)): State<Ctx>,
    Path(node): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_node_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Support,
        node,
        "/support-settings",
    )
    .await
}

/// Removes the `[support]` setting the API set for one node.
///
/// The node then runs with the config files' setting, or the default, after a restart.
#[utoipa::path(delete, path = "/api/v1/support-settings/{node}", tag = "config",
    params(("node" = String, Path, description = "The node ID."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Only an admin can change this."),
        (status = 404, body = Problem, description = "The API sets nothing on that node."),
    ))]
pub(crate) async fn delete_support_settings(
    State((backend, auth)): State<Ctx>,
    Path(node): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_node_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Support,
        node,
        "/support-settings",
    )
    .await
}

/// REQ: OPS-012 (T27.11, ADR-1006) — `[updates] check` for one node. Admins only.
///
/// The node checks for a newer build once a day (or not), from its next start; the files' value wins.
#[utoipa::path(put, path = "/api/v1/updates-settings/{node}", tag = "config",
    params(("node" = String, Path, description = "The node ID the settings apply to."), DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Only an admin can change this."),
        (status = 404, body = Problem, description = "No node of this cluster has that ID."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files set this field."),
        (status = 422, body = Problem, description = "A field is wrong."),
    ))]
pub(crate) async fn put_updates_settings(
    State((backend, auth)): State<Ctx>,
    Path(node): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_node_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Updates,
        node,
        "/updates-settings",
    )
    .await
}

/// Removes the `[updates]` setting the API set for one node.
///
/// The node then runs with the config files' setting, or the default, after a restart.
#[utoipa::path(delete, path = "/api/v1/updates-settings/{node}", tag = "config",
    params(("node" = String, Path, description = "The node ID."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Only an admin can change this."),
        (status = 404, body = Problem, description = "The API sets nothing on that node."),
    ))]
pub(crate) async fn delete_updates_settings(
    State((backend, auth)): State<Ctx>,
    Path(node): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_node_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Updates,
        node,
        "/updates-settings",
    )
    .await
}

/// REQ: DNS-011 (T27.11, ADR-1006) — `[dnssec]` `mode` and `negative_trust_anchors`.
///
/// The validation mode and the domains it skips apply on every node within seconds; the files' fields win.
#[utoipa::path(put, path = "/api/v1/dnssec-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files set this field."),
        (status = 422, body = Problem, description = "A field is wrong, or the configuration wouldn't be valid."),
    ))]
pub(crate) async fn put_dnssec_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Dnssec,
        "/dnssec-settings/default",
    )
    .await
}

/// Removes the `[dnssec]` settings the API set (the files' apply again).
///
/// The config files' DNSSEC settings, or the defaults, apply again on every node.
#[utoipa::path(delete, path = "/api/v1/dnssec-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "The API sets no DNSSEC settings."),
    ))]
pub(crate) async fn delete_dnssec_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Dnssec,
        "DELETE /dnssec-settings/default",
    )
    .await
}

/// REQ: FLT-004 (T27.11, ADR-1006), FLT-901 (T24.29) — `[filter]` `refresh_secs`, `stale_after_days`,
/// `entry_budget` and `ads_tier`.
///
/// The list refresh interval and the stale-list age apply after a restart of every node; the files' fields win.
/// `entry_budget` is the most distinct blocklist entries the selected categories may add before the
/// Categories view warns (default 1,000,000; a node too small for a selection refuses it whatever this
/// says), and `ads_tier` is the size of the Ad Block category (`light`, `pro`, `pro_plus`, `ultimate`);
/// changing `ads_tier` makes the primary download the other list and is refused (422 `budget_refused`)
/// when the new selection needs more memory than the node may use. No agent can change it.
#[utoipa::path(put, path = "/api/v1/filter-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files set this field."),
        (status = 422, body = Problem, description = "A field is out of range."),
    ))]
pub(crate) async fn put_filter_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Filter,
        "/filter-settings/default",
    )
    .await
}

/// Removes the `[filter]` settings the API set (the files' apply again).
///
/// The config files' list settings, or the defaults, apply again after a restart of every node.
#[utoipa::path(delete, path = "/api/v1/filter-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "The API sets no list settings."),
    ))]
pub(crate) async fn delete_filter_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Filter,
        "DELETE /filter-settings/default",
    )
    .await
}

/// REQ: CLU-014 (T27.11, ADR-1006) — `[drill] schedule`. Admins only.
///
/// The schedule and the nodes that drill themselves apply without a restart; the files' fields win.
#[utoipa::path(put, path = "/api/v1/drill-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "Only an admin can change the drill schedule."),
        (status = 409, body = Problem, description = "`set_by_file`: the config files set this field."),
        (status = 422, body = Problem, description = "A field is wrong."),
    ))]
pub(crate) async fn put_drill_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Drill,
        "/drill-settings/default",
    )
    .await
}

/// Removes the drill schedule the API set (the files' apply again).
///
/// The config files' drill schedule, or off, applies again without a restart.
#[utoipa::path(delete, path = "/api/v1/drill-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Only an admin can change the drill schedule."),
        (status = 404, body = Problem, description = "The API sets no drill schedule."),
    ))]
pub(crate) async fn delete_drill_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Drill,
        "DELETE /drill-settings/default",
    )
    .await
}

/// REQ: DNS-014, API-901 (T27.14h, ADR-1098 point 4) — `[access] allowed_networks`, the one list for
/// the whole cluster. Admins only; no agent token changes it.
///
/// Who may use this resolver, and reach the web UI and the API. The list applies on every node within
/// seconds; a file that sets it wins. A list that leaves out the requester's own address is refused
/// (409 `would_disconnect_you`).
#[utoipa::path(put, path = "/api/v1/access-settings/default", tag = "config",
    params(DryRun),
    request_body = Object,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change; `warnings` names a public range)."),
        (status = 403, body = Problem, description = "Only an admin can change the allowed networks; agents are refused."),
        (status = 409, body = Problem, description = "`set_by_file`, the list leaves out your own address (`would_disconnect_you`), or a cluster member's build does not know the allowed networks yet (`upgrade_required`)."),
        (status = 422, body = Problem, description = "A network is wrong."),
    ))]
pub(crate) async fn put_access_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    put_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        b,
        ManagedKind::Access,
        "/access-settings/default",
    )
    .await
}

/// Removes the allowed networks the API set (the files' list, or the defaults, apply again).
///
/// The list the configuration files give, or the built-in defaults (private ranges, CGNAT, link-local
/// and loopback), applies again on every node within seconds.
#[utoipa::path(delete, path = "/api/v1/access-settings/default", tag = "config",
    params(DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 403, body = Problem, description = "Only an admin can change the allowed networks."),
        (status = 409, body = Problem, description = "The list that would apply leaves out your own address (`would_disconnect_you`)."),
        (status = 404, body = Problem, description = "The API sets no allowed networks."),
    ))]
pub(crate) async fn delete_access_settings(
    State((backend, auth)): State<Ctx>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    delete_settings(
        backend,
        auth,
        q,
        headers,
        ext,
        ManagedKind::Access,
        "DELETE /access-settings/default",
    )
    .await
}

/// REQ: DNS-006, OPS-011, OPS-012, DNS-011, FLT-004, CLU-014 (T27.2, T27.11, ADR-1006) — the
/// per-node sections and the shared singletons added for the cache and the small settings. The
/// operator role is required on the router (`lib.rs`); the plans check the rest (admins only for
/// the support and update switches and the drill schedule).
pub(crate) fn node_settings_routes(backend: Arc<dyn Backend>, auth: Arc<Auth>) -> Router {
    Router::new()
        // REQ: DNS-006, OPS-011, OPS-012 (T27.2, T27.11, ADR-1006) — the per-node sections.
        .route(
            "/api/v1/cache-settings/{node}",
            axum::routing::put(put_cache_settings).delete(delete_cache_settings),
        )
        .route(
            "/api/v1/support-settings/{node}",
            axum::routing::put(put_support_settings).delete(delete_support_settings),
        )
        .route(
            "/api/v1/updates-settings/{node}",
            axum::routing::put(put_updates_settings).delete(delete_updates_settings),
        )
        // REQ: DNS-011, FLT-004, CLU-014 (T27.11, ADR-1006) — the shared singletons.
        .route(
            "/api/v1/dnssec-settings/default",
            axum::routing::put(put_dnssec_settings).delete(delete_dnssec_settings),
        )
        .route(
            "/api/v1/filter-settings/default",
            axum::routing::put(put_filter_settings).delete(delete_filter_settings),
        )
        .route(
            "/api/v1/drill-settings/default",
            axum::routing::put(put_drill_settings).delete(delete_drill_settings),
        )
        .route(
            "/api/v1/access-settings/default",
            axum::routing::put(put_access_settings).delete(delete_access_settings),
        )
        .with_state((backend, auth))
}

/// The shared body of the three `PUT`s above.
#[allow(clippy::too_many_arguments)] // the extractors, plus the kind and the request line
async fn put_settings(
    backend: Arc<dyn Backend>,
    auth: Arc<Auth>,
    q: DryRun,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, JsonRejection>,
    kind: ManagedKind,
    path: &str,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT {path} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        "default".to_owned(),
        Op::Managed(kind, Some(input)),
    )
    .await
}

/// The shared body of the three `DELETE`s above.
async fn delete_settings(
    backend: Arc<dyn Backend>,
    auth: Arc<Auth>,
    q: DryRun,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    kind: ManagedKind,
    request: &str,
) -> Response {
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request.to_owned(),
        "default".to_owned(),
        Op::Managed(kind, None),
    )
    .await
}

/// REQ: FLT-901 — the options of a write with `dry_run` decided by the caller.
pub(crate) fn write_opts(q: &DryRun, dry_run: bool) -> WriteOpts {
    let mut o = dry(q);
    o.dry_run = dry_run;
    o
}

/// REQ: FLT-902 — writes who a group applies to (`PUT /groups/{name}/sources`) as one change.
#[allow(clippy::too_many_arguments)] // the inputs of `write`
pub(crate) async fn write_group_sources(
    backend: Arc<dyn Backend>,
    auth: Arc<Auth>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    dry: WriteOpts,
    request: String,
    name: String,
    body: serde_json::Value,
) -> Response {
    write(
        backend,
        auth,
        headers,
        ext,
        dry,
        request,
        name,
        Op::Managed(ManagedKind::GroupSources, Some(body)),
    )
    .await
}

/// REQ: FLT-901 — writes a group entry (the whole definition) like `PUT /groups/{name}`.
#[allow(clippy::too_many_arguments)] // the inputs of `write`
pub(crate) async fn write_group_entry(
    backend: Arc<dyn Backend>,
    auth: Arc<Auth>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    dry: WriteOpts,
    request: String,
    name: String,
    body: serde_json::Value,
) -> Response {
    write(
        backend,
        auth,
        headers,
        ext,
        dry,
        request,
        name,
        Op::Managed(ManagedKind::Group, Some(body)),
    )
    .await
}

/// What a write changes.
enum Op {
    Client(Option<ClientInput>),
    Managed(ManagedKind, Option<serde_json::Value>),
}

impl Op {
    fn audit_kind(&self) -> &'static str {
        match self {
            Self::Client(_) => "client",
            Self::Managed(ManagedKind::Record, _) => "record",
            Self::Managed(ManagedKind::Forward, _) => "forward",
            Self::Managed(ManagedKind::Zone, _) => "zone",
            Self::Managed(ManagedKind::Location, _) => "location",
            Self::Managed(ManagedKind::Rule, _) => "rule",
            Self::Managed(ManagedKind::Upstream, _) => "upstream",
            Self::Managed(ManagedKind::UpstreamGroup, _) => "upstream_group",
            Self::Managed(ManagedKind::List, _) => "list",
            Self::Managed(ManagedKind::Group, _) => "group",
            Self::Managed(ManagedKind::GroupSources, _) => "group_sources",
            Self::Managed(ManagedKind::AlertDestination, _) => "alert_destination",
            Self::Managed(ManagedKind::AlertRule, _) => "alert_rule",
            Self::Managed(ManagedKind::Router, _) => "router",
            Self::Managed(ManagedKind::OidcProvider, _) => "oidc_provider",
            Self::Managed(ManagedKind::Sink, _) => "sink",
            Self::Managed(ManagedKind::Otlp, _) => "otlp",
            Self::Managed(ManagedKind::Schedule, _) => "schedule",
            Self::Managed(ManagedKind::AnomalyMute, _) => "anomaly_mute",
            Self::Managed(ManagedKind::RateLimit, _) => "ratelimit",
            Self::Managed(ManagedKind::Exclusions, _) => "exclusions",
            Self::Managed(ManagedKind::Simulate, _) => "simulate",
            Self::Managed(ManagedKind::Map, _) => "map",
            Self::Managed(ManagedKind::Rollout, _) => "rollout_settings",
            Self::Managed(ManagedKind::KubernetesMap, _) => "kubernetes_map",
            Self::Managed(ManagedKind::Special, _) => "special",
            Self::Managed(ManagedKind::Local, _) => "local",
            // LOW 5: not one letter from the device writes' `client.put`.
            Self::Managed(ManagedKind::Clients, _) => "clients_settings",
            Self::Managed(ManagedKind::Discovery, _) => "discovery",
            Self::Managed(ManagedKind::Cmdb, _) => "cmdb",
            Self::Managed(ManagedKind::Cache, _) => "cache",
            Self::Managed(ManagedKind::Support, _) => "support",
            Self::Managed(ManagedKind::Updates, _) => "updates",
            Self::Managed(ManagedKind::Dnssec, _) => "dnssec",
            Self::Managed(ManagedKind::Filter, _) => "filter",
            Self::Managed(ManagedKind::Drill, _) => "drill",
            Self::Managed(ManagedKind::Access, _) => "access",
            Self::Managed(ManagedKind::Slo, _) => "slo",
            Self::Managed(ManagedKind::Probe, _) => "probe",
            Self::Managed(ManagedKind::UpstreamCheck, _) => "upstream_check",
            Self::Managed(ManagedKind::TelemetryAnomaly, _) => "anomaly_settings",
            Self::Managed(ManagedKind::TelemetryQlog, _) => "qlog_settings",
            Self::Managed(ManagedKind::TelemetryMetrics, _) => "metrics_settings",
            Self::Managed(ManagedKind::TelemetryDnstap, _) => "dnstap_settings",
        }
    }
    fn deleting(&self) -> bool {
        matches!(self, Self::Client(None) | Self::Managed(_, None))
    }
}

fn dry(q: &DryRun) -> WriteOpts {
    WriteOpts {
        dry_run: q.dry_run.unwrap_or(false),
        simulate: q.simulate.clone(),
        simulate_until: q.simulate_until.clone(),
    }
}

/// REQ: OBS-024 — `simulate`/`simulateUntil` as the backend takes them. Only with a dry run
/// (`auto` is ignored without one: it means "if the settings say so").
pub(crate) fn simulate_opts(d: &WriteOpts, now_s: u64) -> Result<Option<SimulateOpts>, Problem> {
    let Some(text) = d.simulate.as_deref().map(str::trim) else {
        if d.simulate_until.is_some() {
            return Err(Problem::invalid("`simulateUntil` needs `simulate`"));
        }
        return Ok(None);
    };
    let auto = text.eq_ignore_ascii_case("auto");
    if !d.dry_run {
        if auto {
            return Ok(None);
        }
        return Err(Problem::invalid("`simulate` needs `dryRun=true`")
            .hint("A simulation previews a change: add dryRun=true."));
    }
    let until_s = d
        .simulate_until
        .as_deref()
        .map(|u| crate::time::parse_time(u, now_s))
        .transpose()
        .map_err(|e| Problem::invalid(format!("`simulateUntil`: {e}")))?;
    let window =
        (!auto && !text.is_empty() && !text.eq_ignore_ascii_case("true")).then(|| text.to_owned());
    Ok(Some(SimulateOpts {
        window,
        auto,
        until_s,
    }))
}

fn json_of<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// Create, rename, or change a device (API-010).
///
/// Names devices across every view: the query log, live tail, charts, and history (names
/// are resolved when read, so earlier queries are relabelled too). To rename, send the new
/// `name` in the body. Devices defined in the config files are read-only here (409). Needs
/// the operator role (or a `write` token). An agent token also needs `config:write:locations`
/// when the write would set, change or remove the device's location pin; this is a full
/// replace, so leaving `location` out removes the pin.
#[utoipa::path(put, path = "/api/v1/clients/{name}", tag = "config",
    params(("name" = String, Path, description = "The device's current name (or the name for a new one)."), DryRun),
    request_body = ClientInput,
    responses(
        (status = 200, body = ClientChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 403, body = Problem, description = "An agent token without `config:write:locations` tried to set, change or remove the device's location pin."),
        (status = 409, body = Problem, description = "Defined in the config files, or an Idempotency-Key reused for another request."),
        (status = 412, body = Problem, description = "If-Match: the config changed since that version."),
        (status = 422, body = Problem, description = "The resulting configuration is invalid (e.g. an unknown group)."),
    ))]
pub(crate) async fn put_client(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<ClientInput>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /clients/{name} {}", json_of(&input));
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Client(Some(input)),
    )
    .await
}

/// Delete a device named through the API.
///
/// Its queries, past and future, go back to showing the address, and it leaves its groups
/// (the `default` group applies). Devices from the config files can't be deleted here (409).
/// Needs the operator role (or a `write` token). An agent token also needs
/// `config:write:locations` when the device has a location pin (deleting it removes the pin).
#[utoipa::path(delete, path = "/api/v1/clients/{name}", tag = "config",
    params(("name" = String, Path, description = "The device's name."), DryRun),
    responses(
        (status = 200, body = ClientChange, description = "The result."),
        (status = 403, body = Problem, description = "An agent token without `config:write:locations` tried to delete a device that has a location pin."),
        (status = 404, body = Problem, description = "No device by that name was created through the API."),
        (status = 409, body = Problem, description = "Defined in the config files."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
    ))]
pub(crate) async fn delete_client(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /clients/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Client(None),
    )
    .await
}

/// Set a local name's records (API-011, "Names on my network").
///
/// Replaces every record of `name` made through the API with `records` (A and AAAA addresses,
/// CNAME aliases, and in Advanced PTR, TXT, MX, SRV). WrenDNS then answers the name itself,
/// before the cache and upstreams; reverse lookups for addresses are added automatically
/// (`[local] auto_ptr`). Names defined in the config files are read-only here (409). Needs the
/// operator role (or a `write` token).
#[utoipa::path(put, path = "/api/v1/records/{name}", tag = "config",
    params(("name" = String, Path, description = "The full name, e.g. nas.home.arpa (a leading `*.` makes a wildcard)."), DryRun),
    request_body = RecordsInput,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "Defined in the config files, or an Idempotency-Key reused."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A value doesn't fit its type (e.g. A with a name), or the result is invalid."),
    ))]
pub(crate) async fn put_records(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<RecordsInput>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /records/{name} {}", json_of(&input));
    let v = serde_json::to_value(&input).unwrap_or_default();
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Record, Some(v)),
    )
    .await
}

/// Remove a local name made through the API.
///
/// WrenDNS stops answering it itself; queries for it go to the upstreams (or a route) as
/// usual. Names from the config files can't be removed here (409).
#[utoipa::path(delete, path = "/api/v1/records/{name}", tag = "config",
    params(("name" = String, Path, description = "The full name."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No name like that was created through the API."),
        (status = 409, body = Problem, description = "Conflicts with the current state: problem+json says what to change."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
    ))]
pub(crate) async fn delete_records(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /records/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Record, None),
    )
    .await
}

/// Send a domain to other DNS servers (conditional forwarding; API-011).
///
/// Every name under `domain` is asked of `servers` (in order, failing over) instead of the
/// public upstreams: a work network's DNS over a VPN, a router that knows your devices, another
/// lab. A bare address means plain DNS; `tls://` and `https://` URLs work too. Local names still
/// answer first. Domains routed in the config files are read-only here (409).
#[utoipa::path(put, path = "/api/v1/forwards/{domain}", tag = "config",
    params(("domain" = String, Path, description = "The domain, e.g. corp.example (its whole subtree is sent)."), DryRun),
    request_body = ForwardInput,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "Conflicts with the current state: problem+json says what to change."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A server isn't an address or a supported URL."),
    ))]
pub(crate) async fn put_forward(
    State((backend, auth)): State<Ctx>,
    Path(domain): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<ForwardInput>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /forwards/{domain} {}", json_of(&input));
    let v = serde_json::to_value(&input).unwrap_or_default();
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        domain,
        Op::Managed(ManagedKind::Forward, Some(v)),
    )
    .await
}

/// Create or replace an authoritative zone (DNS-010, T27.7, ADR-1007).
///
/// Every name under `name` is answered from the zone's records, for everyone or only `groups`
/// (split horizon); a name the zone doesn't have gets "no such name". A zone the configuration
/// files define is read-only here (409 `set_by_file`), and so is its zone file (guarded, T27.17).
/// Needs the operator role (or the `config:write:records` agent scope, with a reason).
#[utoipa::path(put, path = "/api/v1/zones/{name}", tag = "config",
    params(("name" = String, Path, description = "The zone's apex, e.g. home.example.com."), DryRun),
    request_body = crate::model::ZoneInput,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "Defined in the configuration files (`set_by_file`)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A name, group, or record is invalid, or the body names a zone file."),
    ))]
pub(crate) async fn put_zone(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<crate::model::ZoneInput>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /zones/{name} {}", json_of(&input));
    let v = serde_json::to_value(&input).unwrap_or_default();
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Zone, Some(v)),
    )
    .await
}

/// Create or replace a location (DSC-913, T36.10a, ADR-1081, ADR-1096).
///
/// A location is a part of the network with a device-name subtree of its own: a device on one of
/// its `networks` answers as `<device>.<slug>.<domain>` (its PTR is that name), the old flat name
/// keeps answering while `flatNames` is on, a `private` location's names answer only to clients in
/// its networks, and a name in its subtree that is no device gets "no such name" locally. The
/// fields left out take their defaults. A location the configuration files define is read-only
/// here (409 `set_by_file`). The first location is refused (409 `upgrade_required`, dry runs too)
/// while a cluster member's build does not know locations, naming the member. Needs the operator
/// role (or the `config:write:locations` agent scope, with a reason).
#[utoipa::path(put, path = "/api/v1/locations/{slug}", tag = "config",
    params(("slug" = String, Path, description = "The location's slug (a DNS label, e.g. home)."), DryRun),
    request_body = crate::model::LocationInput,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "Defined in the configuration files (`set_by_file`), or a cluster member does not know locations yet (`upgrade_required`)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "The slug, a network, the domain or the visibility is invalid, or two locations overlap."),
    ))]
pub(crate) async fn put_location(
    State((backend, auth)): State<Ctx>,
    Path(slug): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<crate::model::LocationInput>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /locations/{slug} {}", json_of(&input));
    let v = serde_json::to_value(&input).unwrap_or_default();
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        slug,
        Op::Managed(ManagedKind::Location, Some(v)),
    )
    .await
}

/// Remove a location made through the API (DSC-913, T36.10a).
///
/// Its devices go back to the names they had without it (`<device>.<device_domain>`), and a device
/// pinned to it (`[[client]] location`) must be unpinned first (422). A location the configuration
/// files define can't be removed here (409).
#[utoipa::path(delete, path = "/api/v1/locations/{slug}", tag = "config",
    params(("slug" = String, Path, description = "The location's slug."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Not found."),
        (status = 409, body = Problem, description = "Defined in the configuration files (`set_by_file`)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "A device is pinned to it."),
    ))]
pub(crate) async fn delete_location(
    State((backend, auth)): State<Ctx>,
    Path(slug): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /locations/{slug}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        slug,
        Op::Managed(ManagedKind::Location, None),
    )
    .await
}

/// Remove a zone made through the API (DNS-010, T27.7).
///
/// The names it answered go back to the upstreams. A zone the configuration files define can't be
/// removed here (409).
#[utoipa::path(delete, path = "/api/v1/zones/{name}", tag = "config",
    params(("name" = String, Path, description = "The zone's apex."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Not found."),
        (status = 409, body = Problem, description = "Defined in the configuration files (`set_by_file`)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
    ))]
pub(crate) async fn delete_zone(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /zones/{name}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        name,
        Op::Managed(ManagedKind::Zone, None),
    )
    .await
}

/// Stop sending a domain to other servers.
///
/// Names under it go to the public upstreams again. Routes from the config files can't be
/// removed here (409).
#[utoipa::path(delete, path = "/api/v1/forwards/{domain}", tag = "config",
    params(("domain" = String, Path, description = "The domain."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "Not found."),
        (status = 409, body = Problem, description = "Conflicts with the current state: problem+json says what to change."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
    ))]
pub(crate) async fn delete_forward(
    State((backend, auth)): State<Ctx>,
    Path(domain): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /forwards/{domain}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        domain,
        Op::Managed(ManagedKind::Forward, None),
    )
    .await
}

/// Create or replace a quick rule (T6.12, ADR-067).
///
/// Allows or blocks `domain` and its subdomains for `devices`, `groups`, or everyone (neither
/// given), before any list: a device rule beats a group rule beats an everyone rule; within one
/// scope the longer domain wins, then allow. With `expires` or `forMinutes` it stops applying
/// then (and is removed). It takes effect on the next query, without recompiling the lists.
/// Rules from the config files are read-only here (409). Needs the operator role (or the
/// `config:write:rules` agent scope, with a reason).
#[utoipa::path(put, path = "/api/v1/rules/{id}", tag = "config",
    params(("id" = String, Path, description = "The rule's ID: any short unique name (the UI makes one)."), DryRun),
    request_body = crate::model::RuleInput,
    responses(
        (status = 200, body = ConfigChange, description = "Applied (or, with dryRun, what would change)."),
        (status = 409, body = Problem, description = "Defined in the config files, or an Idempotency-Key reused."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
        (status = 422, body = Problem, description = "An unknown device or group, a bad domain, or an expiry in the past."),
    ))]
pub(crate) async fn put_rule(
    State((backend, auth)): State<Ctx>,
    Path(id): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<crate::model::RuleInput>, JsonRejection>,
) -> Response {
    let input = match body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /rules/{id} {}", json_of(&input));
    let v = serde_json::to_value(&input).unwrap_or_default();
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        id,
        Op::Managed(ManagedKind::Rule, Some(v)),
    )
    .await
}

/// Remove a quick rule made through the API.
///
/// The lists decide for its domain again. Rules from the config files can't be removed here
/// (409).
#[utoipa::path(delete, path = "/api/v1/rules/{id}", tag = "config",
    params(("id" = String, Path, description = "The rule's ID."), DryRun),
    responses(
        (status = 200, body = ConfigChange, description = "The result."),
        (status = 404, body = Problem, description = "No rule with that ID was created through the API."),
        (status = 409, body = Problem, description = "Defined in the config files."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version: re-read it and retry."),
    ))]
pub(crate) async fn delete_rule(
    State((backend, auth)): State<Ctx>,
    Path(id): Path<String>,
    Query(q): Query<DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let request = format!("DELETE /rules/{id}");
    write(
        backend,
        auth,
        headers,
        ext,
        dry(&q),
        request,
        id,
        Op::Managed(ManagedKind::Rule, None),
    )
    .await
}

/// REQ: DNS-014, API-901 (T27.14h, owner question open: taken as the conservative option) — refuses an
/// `allowed_networks` list, sent in `body`, that does not hold `client`, the requester's address (the
/// forwarded one on a replica's behalf). A body without the list, one with an entry that does not
/// parse (the backend says which), and an unknown address (no connection information) pass.
pub fn lockout_guard(
    body: &serde_json::Value,
    client: std::net::IpAddr,
    peer: Option<std::net::IpAddr>,
) -> Result<(), Problem> {
    let Some(list) = body.get("allowed_networks").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    let mut nets = Vec::new();
    for v in list {
        match v.as_str().map(wrendns_config::Cidr::parse) {
            Some(Ok(c)) => nets.push(c),
            _ => return Ok(()),
        }
    }
    // The gate judges the TCP peer; behind a trusted proxy that is the proxy, not the client. Both
    // must be in the list, or the proxy is refused and the whole UI with it.
    for (ip, what) in [
        (Some(client), "your own address"),
        (peer, "the address your request reached this node from"),
    ] {
        let Some(ip) = ip.filter(|i| !i.is_unspecified()) else {
            continue;
        };
        if !nets.iter().any(|n| n.contains(ip)) {
            return Err(Problem::new(
                Code::WouldDisconnectYou,
                format!(
                    "this list leaves out {what}, {ip}: once it applies, this web UI and API would refuse you"
                ),
            )
            .hint("Add a network that holds your address, then save again. If you need the list without it, change it in the configuration file."));
        }
    }
    Ok(())
}

/// REQ: API-002, API-010 (ADR-040) - a configuration write runs to its end (the audit record
/// included) even when the client hangs up first, as a browser does when the page reloads right
/// after Apply: stored but not applied is not a state a change may end in.
#[allow(clippy::too_many_arguments)] // the write's own parts, as `write_inner`
async fn write(
    backend: Arc<dyn Backend>,
    auth: Arc<Auth>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    dry: WriteOpts,
    request: String,
    name: String,
    op: Op,
) -> Response {
    match tokio::spawn(write_inner(
        backend, auth, headers, ext, dry, request, name, op,
    ))
    .await
    {
        Ok(r) => r,
        Err(e) => Problem::internal(format!("the write's worker failed: {e}")).into_response(),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // one path for every write
async fn write_inner(
    backend: Arc<dyn Backend>,
    auth: Arc<Auth>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    dry: WriteOpts,
    request: String,
    name: String,
    op: Op,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let dry_run = dry.dry_run;
    let simulate = match simulate_opts(&dry, backend.now_unix_seconds()) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    // REQ: OBS-024 — a simulation reads the query log: agents need that scope too.
    if simulate.as_ref().is_some_and(|s| !s.auto)
        && let Err(e) = crate::simulate_api::agent_may_simulate(&p, None)
    {
        return e.into_response();
    }
    // `simulate=auto` from a token that can't read the log: no simulation, not an error.
    let simulate = simulate.filter(|_| crate::simulate_api::agent_may_simulate(&p, None).is_ok());
    // REQ: CLU-004 (upstream #7) — only a group-restricted agent's check reads the devices;
    // that read waits on the cluster on a replica, so it runs off the runtime.
    // REQ: DSC-913 - the pin check reads the device too (an agent without the locations scope).
    let needs_device = matches!(op, Op::Client(_))
        && p.agent
            .as_ref()
            .is_some_and(|a| a.group.is_some() || !a.scopes.contains("config:write:locations"));
    let existing = if needs_device {
        let bk = Arc::clone(&backend);
        let device = name.clone();
        match blocking(move || Ok(bk.clients().into_iter().find(|c| c.name == device))).await {
            Ok(existing) => existing,
            Err(e) => return e.into_response(),
        }
    } else {
        None
    };
    if let Err(e) = group_guard(&p, existing.as_ref(), &name, &op) {
        return e.into_response();
    }
    if let Err(e) = pin_guard(&p, existing.as_ref(), &op) {
        return e.into_response();
    }
    let expect = match expected_version(&headers) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    // REQ: AGT-003 — a retried request gets the first response; another request with the
    // same key is refused.
    let key = headers
        .get(IDEMPOTENCY_KEY)
        .and_then(|v| v.to_str().ok())
        .map(|k| format!("{}:{}", p.user_id, k.trim()))
        .filter(|k| !dry_run && k.len() > 2);
    // REQ: API-014 (ADR-903 §4) — the record keeps a keyed hash of the whole request, never
    // its text (a body can carry an upstream's headers), so a body differing only in a
    // credential is another request.
    let fingerprint = if key.is_some() {
        let (kind, body) = match &op {
            Op::Managed(k, b) => (Some(*k), b.as_ref()),
            Op::Client(_) => (None, None),
        };
        match backend.idempotency_request(kind, &request, body) {
            Ok(f) => Some(f),
            Err(e) => return e.into_response(),
        }
    } else {
        None
    };
    drop(request);
    let now = backend.now_unix_seconds();
    if let (Some(k), Some(f)) = (&key, &fingerprint) {
        match auth.state().idempotent(k, now) {
            Ok(Some(r)) if &r.request == f => return replay(&r),
            Ok(Some(_)) => {
                return Problem::new(
                    Code::Conflict,
                    "this Idempotency-Key was used for a different request",
                )
                .hint("Use a new key for each distinct change.")
                .into_response();
            }
            Ok(None) => {}
            Err(e) => return Problem::internal(e.to_string()).into_response(),
        }
    }
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let action = format!(
        "{}.{}",
        op.audit_kind(),
        if op.deleting() { "delete" } else { "put" }
    );
    // REQ: DNS-014, API-901 (T27.14h) — the list also limits the web UI and the API (ADR-029): a list
    // that leaves out the address this request came from is refused, a dry run included.
    if let Op::Managed(ManagedKind::Access, body) = &op {
        let client = remote(&auth, &ext, &headers);
        let peer = if ext.get::<crate::auth::routes::OnBehalfOf>().is_some() {
            None
        } else {
            ext.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|c| c.0.ip())
        };
        // The check runs on the list that WOULD BE IN FORCE after the write (the backend's normalized
        // result), whatever the body holds: a PUT without the key stores the built-in defaults, and a
        // DELETE reverts to the file's list. A dry run that fails is its own answer: the real write
        // would fail the same way, and a DELETE is never let through unjudged.
        let judged = backend
            .write_managed(ManagedWrite {
                kind: ManagedKind::Access,
                name: name.clone(),
                body: body.clone(),
                dry_run: true,
                expect: None,
                by: actor.name.clone(),
                simulate: None,
                role: Some(p.role),
                agent: p.agent.as_ref().map(|a| a.token_name.clone()),
            })
            .await;
        match judged {
            Ok(c) => {
                let Some(after) = c.after else {
                    return Problem::internal("the dry run named no resulting list")
                        .into_response();
                };
                if let Err(e) = lockout_guard(&after, client, peer) {
                    return e.into_response();
                }
            }
            Err(e) => {
                // A list the backend cannot take (an empty one) that also cuts the requester off
                // is answered as the lockout, the more useful word. Any other failure (a file that
                // sets the list, a member that is too old) is its own answer, not the lockout.
                if matches!(e.code, Code::InvalidConfig)
                    && let Some(b) = body
                    && let Err(lock) = lockout_guard(b, client, peer)
                {
                    return lock.into_response();
                }
                return crate::simulate_api::sanitize_problem(&p, e).into_response();
            }
        }
    }
    let result: Result<serde_json::Value, Problem> = match op {
        Op::Client(input) => backend
            .write_client(ClientWrite {
                name: name.clone(),
                input,
                dry_run,
                expect,
                by: actor.name.clone(),
                simulate: simulate.clone(),
            })
            .await
            .map(|c| serde_json::to_value(c).unwrap_or_default()),
        Op::Managed(kind, body) => backend
            .write_managed(ManagedWrite {
                kind,
                name: name.clone(),
                body,
                dry_run,
                expect,
                by: actor.name.clone(),
                simulate,
                // REQ: API-014 (T23.2) — the backend holds credential changes to the role.
                role: Some(p.role),
                agent: p.agent.as_ref().map(|a| a.token_name.clone()),
            })
            .await
            .map(|c| serde_json::to_value(c).unwrap_or_default()),
    };
    let result = result.map_err(|e| crate::simulate_api::sanitize_problem(&p, e));
    let (status, text) = match &result {
        Ok(c) => (StatusCode::OK, c.to_string()),
        Err(e) => (e.code_status(), json_of(e)),
    };
    if let Ok(c) = &result
        && c["applied"].as_bool() == Some(true)
    {
        auth.record(
            &actor,
            &action,
            &name,
            &serde_json::json!({ "before": c["before"], "after": c["after"], "configVersion": c["configVersion"] }),
        );
    }
    if let (Some(k), Some(f)) = (&key, fingerprint)
        && status.is_success()
    {
        // The response is the backend's, redacted already (API-014).
        let r = Replay {
            request: f,
            status: status.as_u16(),
            response: text.clone(),
        };
        if let Err(e) = auth.state().remember_idempotent(k, &r, now) {
            tracing::warn!("idempotency key not stored: {e}");
        }
    }
    match result {
        Ok(c) => {
            let mut r = Json(c).into_response();
            // The version after the write, read off the runtime (CLU-004).
            let bk = Arc::clone(&backend);
            if let Ok(version) = blocking(move || Ok(bk.config_version())).await
                && let Ok(v) = HeaderValue::from_str(&format!("\"{version}\""))
            {
                r.headers_mut().insert(axum::http::header::ETAG, v);
            }
            r
        }
        Err(e) => e.into_response(),
    }
}

pub(crate) fn replay(r: &Replay) -> Response {
    let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::OK);
    let mut resp = (status, r.response.clone()).into_response();
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert("idempotency-replayed", HeaderValue::from_static("true"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agt_001_if_match_forms() {
        let h = |v: &str| {
            let mut m = HeaderMap::new();
            m.insert(IF_MATCH, HeaderValue::from_str(v).unwrap());
            m
        };
        assert_eq!(expected_version(&HeaderMap::new()).unwrap(), None);
        assert_eq!(expected_version(&h("\"7\"")).unwrap(), Some(7));
        assert_eq!(expected_version(&h("W/\"7\"")).unwrap(), Some(7));
        assert_eq!(expected_version(&h("7")).unwrap(), Some(7));
        assert_eq!(expected_version(&h("*")).unwrap(), None);
        assert!(expected_version(&h("latest")).is_err());
    }
}

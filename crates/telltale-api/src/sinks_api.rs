//! REQ: API-016, OBS-010, OBS-006 (T23.11, ADR-903 section 7, ADR-984) - event sinks and the OTLP
//! export: the lists with what this node does with each (`GET /api/v1/sinks`, `GET /api/v1/otlp`).
//! Any signed-in role reads them (secrets as names, never values); writes are admin-only, in
//! `config_api` (`PUT`/`DELETE /api/v1/sinks/{name}` and `/api/v1/otlp/default`).

use axum::Json;
use axum::extract::State;
use axum::routing::get;

use crate::Shared;
use crate::model::{OtlpEntry, SinkList};

/// The read routes (viewers and up).
pub(crate) fn read_routes(backend: Shared) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/sinks", get(list_sinks))
        .route("/api/v1/otlp", get(get_otlp))
        .with_state(backend)
}

/// The event sinks in the configuration, with their status.
///
/// Each sink comes with its settings (a webhook token as a stored secret's name, never a value),
/// where it comes from (the files, or the API), and whether this node runs it: a resolver pod holds
/// no stored secrets, so a sink that needs one isn't started there. `dropped` counts the events a
/// sink lost since the node started (its buffer was full, or a batch was refused).
#[utoipa::path(get, path = "/api/v1/sinks", tag = "config",
    responses((status = 200, body = SinkList, description = "The sinks, the files' first.")))]
pub(crate) async fn list_sinks(State(b): State<Shared>) -> Json<SinkList> {
    Json(b.sink_entries())
}

/// The OTLP export in effect on this node.
///
/// Its collector address, interval and headers (a header's value is a stored secret's name, or
/// `<redacted>` when the configuration file holds it inline), where the setting comes from, and
/// whether the export runs here.
#[utoipa::path(get, path = "/api/v1/otlp", tag = "config",
    responses((status = 200, body = OtlpEntry, description = "The OTLP export.")))]
pub(crate) async fn get_otlp(State(b): State<Shared>) -> Json<OtlpEntry> {
    Json(b.otlp_entry())
}

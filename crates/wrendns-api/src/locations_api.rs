// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: DSC-913 (T36.10a, ADR-1081, ADR-1096) - the reads of locations: the table with, for each
//! location, its networks as resolved, its devices with the names they answer as, every collision
//! with its ADR-901 winner, and the 7-day count of queries its flat names still answered. Writes
//! (`PUT` and `DELETE /api/v1/locations/{slug}`) are in `config_api`.

use axum::Json;
use axum::extract::{Path, State};
use axum::routing::get;

use crate::Shared;
use crate::model::{LocationInfo, LocationList};
use crate::problem::Problem;

/// The read routes (viewers and up; agents with `config:read`).
pub(crate) fn read_routes(backend: Shared) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/locations", get(list_locations))
        .route("/api/v1/locations/{slug}", get(get_location))
        .with_state(backend)
}

/// The locations in the configuration, with the names each composes.
///
/// For each location: its networks as resolved now (a VLAN to the subnets the routers and this
/// node's VLAN interfaces report), the devices that answer under it with their names and the old
/// flat names that still answer, the collisions with the device that kept each name (ADR-901's
/// ranking), and how many queries the flat names answered over the last 7 days on this node. A
/// device's location comes from the configured networks and its `[[client]] location`, never from
/// the CMDB (DSC-901). Names and address lists reflect this node's table, rebuilt every 10 seconds.
#[utoipa::path(get, path = "/api/v1/locations", tag = "config",
    responses((status = 200, body = LocationList, description = "The locations.")))]
pub(crate) async fn list_locations(State(b): State<Shared>) -> Json<LocationList> {
    let b = crate::request_backend(&b);
    let list = tokio::task::spawn_blocking(move || b.locations())
        .await
        .unwrap_or_default();
    Json(list)
}

/// One location, with its devices and collisions.
///
/// The same entry `GET /api/v1/locations` lists: its networks as resolved now, the devices that
/// answer under it with the names they answer as (and the old flat names that still answer), its
/// collisions with the ADR-901 winner, and the 7-day count of queries its flat names answered.
#[utoipa::path(get, path = "/api/v1/locations/{slug}", tag = "config",
    params(("slug" = String, Path, description = "The location's slug.")),
    responses(
        (status = 200, body = LocationInfo, description = "The location."),
        (status = 404, body = Problem, description = "No such location."),
    ))]
pub(crate) async fn get_location(
    State(b): State<Shared>,
    Path(slug): Path<String>,
) -> Result<Json<LocationInfo>, Problem> {
    let b = crate::request_backend(&b);
    let list = tokio::task::spawn_blocking(move || b.locations())
        .await
        .unwrap_or_default();
    list.items
        .into_iter()
        .find(|l| l.slug == slug)
        .map(Json)
        .ok_or_else(|| Problem::not_found(format!("no location `{slug}`")))
}

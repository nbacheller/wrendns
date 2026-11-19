//! REQ: DNS-006, OPS-011, OPS-012 (T27.2, T27.11, ADR-1006) - the per-node sections
//! (`[cache]`, `[support] persist_logs`, `[updates] check`) as one read:
//! `GET /api/v1/node-settings` (this node) and `GET /api/v1/node-settings/{node}` (a member of the
//! cluster). Any signed-in role reads them; the writes are admin-only, in `config_api`
//! (`PUT`/`DELETE /api/v1/cache-settings/{node}` and the other two).

use axum::Json;
use axum::extract::{Path, State};
use axum::routing::get;

use crate::Shared;
use crate::model::NodeSettings;
use crate::problem::Problem;

/// The read routes (viewers and up).
pub(crate) fn read_routes(backend: Shared) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/node-settings", get(get_this_node_settings))
        .route("/api/v1/node-settings/{node}", get(get_node_settings))
        .with_state(backend)
}

/// The per-node sections of this node.
///
/// The cache, support and updates settings it runs with, the fields the files set, and whether a
/// restart is still pending for them. Its `node` is the name the `*-settings/{node}` routes take.
#[utoipa::path(get, path = "/api/v1/node-settings", tag = "config",
    responses((status = 200, body = NodeSettings, description = "This node's sections.")))]
pub(crate) async fn get_this_node_settings(
    State(b): State<Shared>,
) -> Result<Json<NodeSettings>, Problem> {
    b.node_settings(None).map(Json)
}

/// The per-node sections of `node`.
///
/// The cache, support and updates settings in effect there, the fields the files set, and whether a
/// restart is still pending for them. 404 when no node of the cluster has that ID.
#[utoipa::path(get, path = "/api/v1/node-settings/{node}", tag = "config",
    params(("node" = String, Path, description = "The node ID.")),
    responses(
        (status = 200, body = NodeSettings, description = "The node's sections."),
        (status = 404, body = Problem, description = "No node of this cluster has that ID."),
    ))]
pub(crate) async fn get_node_settings(
    State(b): State<Shared>,
    Path(node): Path<String>,
) -> Result<Json<NodeSettings>, Problem> {
    b.node_settings(Some(&node)).map(Json)
}

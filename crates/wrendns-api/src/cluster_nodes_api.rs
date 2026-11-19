//! REQ: CLU-001 (ADR-155, GitHub issue #5) — removing a node from the cluster: a stale record
//! (a node rejoined from scratch under a new ID, a machine that's gone) or a node being
//! retired. Admin (agents: `cluster:admin`); runs on the primary, which a replica sends it to;
//! allowed under a `GitOps` authority, since membership isn't configuration; audit-logged as
//! `cluster.node.remove`.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::delete;
use axum::{Json, Router};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::auth::Auth;
use crate::auth::routes::{principal, reason, remote};
use crate::model::NodeRemoval;
use crate::problem::{Code, Problem};
use crate::{NodeRemoveWrite, Shared};

/// The command (admin).
pub(crate) fn admin_routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/cluster/nodes/{id}", delete(remove_node))
        .with_state((backend, auth))
}

/// Query parameters of the removal.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct RemoveQuery {
    /// Check and report without removing anything.
    pub dry_run: Option<bool>,
    /// Remove the node although it is up: its connection is closed and it is refused afterwards.
    pub force: Option<bool>,
}

/// Remove a node from the cluster.
///
/// The primary drops the node from the member list (so it stops counting as a voter, and the
/// Cluster page and the `WrenDNSClusterPeerDown` alert stop listing it) and adds its ID to
/// the list of removed nodes that travels with every version: no node accepts a connection from
/// it again, even while its certificate is valid. The node's own data isn't touched. A node that
/// is up is removed only with `force=true`; the answer then says it was up. The primary can't
/// be removed, and neither can a node by site or pod name: use the ID the Cluster page shows.
///
/// If the node was eligible it holds a copy of the cluster key (`heldClusterKey`): removal
/// stops the cluster accepting its certificate, but if the node is lost or can't be trusted,
/// rotate the CA too (`wrendns cluster rotate-ca`). Removing a voter can leave fewer than three,
/// which turns automatic failover into manual (`automaticFailoverAfter`, and a note).
///
/// A replica sends the request to the primary. It changes no configuration, so a GitOps-managed
/// cluster takes it too. `?dryRun=true` runs every check and says what would happen. Admin
/// (agents: `cluster:admin`); audit-logged as `cluster.node.remove`.
#[utoipa::path(delete, path = "/api/v1/cluster/nodes/{id}", tag = "system",
    params(("id" = String, Path, description = "The node's ID, as the Cluster page lists it."), RemoveQuery),
    responses(
        (status = 200, body = NodeRemoval, description = "The node was removed (or, with dryRun, what would be)."),
        (status = 404, body = Problem, description = "No member has that ID (`node_unknown`)."),
        (status = 409, body = Problem, description = "The node is the primary (`node_is_primary`), or it is up and `force` wasn't given (`node_is_up`)."),
        (status = 503, body = Problem, description = "Not in a cluster, or the primary is unreachable or has no lease (`unavailable`)."),
    ))]
pub(crate) async fn remove_node(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Path(id): Path<String>,
    Query(q): Query<RemoveQuery>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let id = id.trim().to_owned();
    if id.is_empty() || id.len() > 128 || id.chars().any(|c| c.is_control() || c == '/') {
        return Problem::invalid("`id`: a node ID, as the Cluster page lists it").into_response();
    }
    let dry_run = q.dry_run.unwrap_or(false);
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let w = NodeRemoveWrite {
        node: id.clone(),
        force: q.force.unwrap_or(false),
        dry_run,
        by: actor.name.clone(),
    };
    match backend.remove_node(w).await {
        Ok(r) => {
            if !dry_run {
                auth.record(
                    &actor,
                    "cluster.node.remove",
                    &id,
                    &serde_json::json!({
                        "site": r.site,
                        "up": r.up,
                        "eligible": r.eligible,
                        "witness": r.witness,
                        "ephemeral": r.ephemeral,
                    }),
                );
            }
            Json(r).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// The problem for a request that needs a cluster.
pub fn no_cluster() -> Problem {
    Problem::new(Code::Unavailable, "removing a node needs a cluster")
        .hint("This node isn't in a cluster: there is no member list to remove from.")
}

/// The problem for a node ID the primary doesn't know.
pub fn unknown(id: &str) -> Problem {
    Problem::new(
        Code::NodeUnknown,
        format!("no cluster member has the ID `{id}`"),
    )
    .hint("Use the ID in the Cluster page's node list (not the site or pod name).")
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: CLU-001 (ADR-155) — the problems have stable codes and statuses, and say what to do.
    #[test]
    fn clu_001_removal_problems_have_codes_and_hints() {
        let e = unknown("abc");
        assert_eq!((e.code, e.status), (Code::NodeUnknown, 404));
        assert!(e.hint.as_deref().is_some_and(|h| h.contains("ID")));
        let e = no_cluster();
        assert_eq!((e.code, e.status), (Code::Unavailable, 503));
        for (c, s) in [(Code::NodeIsPrimary, 409), (Code::NodeIsUp, 409)] {
            assert_eq!(Problem::new(c, "x").status, s);
        }
    }
}

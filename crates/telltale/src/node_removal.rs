//! REQ: CLU-001 (ADR-155, GitHub issue #5) — removing a node from the cluster. The primary does it
//! ([`remove`]); a replica's request reaches it over the cluster channel ([`send`], answered by
//! [`handle`], which audits it with the user and the entry node).

use std::sync::Arc;
use std::time::Duration;

use telltale_api::NodeRemoveWrite;
use telltale_api::cluster_nodes_api::unknown;
use telltale_api::model::NodeRemoval;
use telltale_api::problem::{Code, Problem};
use telltale_cluster::net::Cluster;
use telltale_cluster::removal::{Removal, RemoveError};

/// The RPC for a replica's removal request; its body is a JSON [`NodeRemoveWrite`].
pub(crate) const KIND: &str = "cluster.remove";
const DEADLINE: Duration = Duration::from_secs(15);

fn problem(e: RemoveError, node: &str) -> Problem {
    match e {
        RemoveError::NotPrimary => Problem::new(Code::Conflict, "this node isn't the primary any more")
            .hint("Retry: the entry node asks the current primary."),
        RemoveError::Unknown => unknown(node),
        RemoveError::IsSelf => Problem::new(
            Code::NodeIsPrimary,
            format!("`{node}` is the primary, which keeps the member list and can't remove itself"),
        )
        .hint("Promote another node first (the Cluster page, or automatic failover), then remove this one from the new primary."),
        RemoveError::Up => Problem::new(Code::NodeIsUp, format!("`{node}` is up"))
            .hint("Stop it first. To cut it off anyway, repeat with force=true (the Cluster page asks): its connection is closed and the cluster refuses it afterwards."),
        RemoveError::Store(e) => Problem::internal(format!("can't store the member list: {e}")),
    }
}

fn model(r: Removal) -> NodeRemoval {
    NodeRemoval {
        node_id: r.node_id,
        site: r.site,
        up: r.up,
        eligible: r.eligible,
        witness: r.witness,
        ephemeral: r.ephemeral,
        held_cluster_key: r.held_cluster_key,
        voters_after: u32::try_from(r.voters_after).unwrap_or(u32::MAX),
        automatic_failover_after: r.automatic_failover_after,
        removed: r.removed,
        notes: r.notes,
    }
}

/// On the primary: removes (or, with `dry_run`, checks) `w.node`. A primary that holds no lease
/// under automatic failover publishes nothing (ADR-056), and a removal travels in the next
/// version, so it waits too.
pub(crate) async fn remove(
    cluster: Arc<Cluster>,
    w: NodeRemoveWrite,
) -> Result<NodeRemoval, Problem> {
    if !w.dry_run && !cluster.may_publish() {
        return Err(Problem::unavailable(
            "this primary can't reach a majority of voters, so it isn't taking changes",
        )
        .hint("DNS keeps answering. Changes resume when a majority of voters is reachable again; see the Cluster page."));
    }
    tokio::task::spawn_blocking(move || {
        cluster
            .remove_member(&w.node, w.force, w.dry_run, &w.by)
            .map(model)
            .map_err(|e| problem(e, &w.node))
    })
    .await
    .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))))
}

/// A replica's request on this node (the primary), from a node that serves a UI: removed here,
/// and audited with the user and the entry node.
pub(crate) async fn handle(
    src: Arc<crate::http::Sources>,
    cluster: Arc<Cluster>,
    peer: String,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let w: NodeRemoveWrite =
        serde_json::from_slice(&body).map_err(|e| format!("bad request: {e}"))?;
    if !cluster.is_primary() {
        return crate::forward::encode_answer::<()>(Err(problem(RemoveError::NotPrimary, &w.node)));
    }
    let via = cluster
        .members()
        .into_iter()
        .find(|m| m.node_id == peer)
        .map(|m| m.site)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| peer.clone());
    let who = format!("{} via {via}", w.by);
    let (node, dry) = (w.node.clone(), w.dry_run);
    let r = remove(
        cluster,
        NodeRemoveWrite {
            by: who.clone(),
            ..w
        },
    )
    .await;
    if let (Ok(res), false, Some(auth)) = (&r, dry, src.auth.get()) {
        let actor = telltale_api::auth::Actor {
            name: who,
            kind: "cluster",
            remote: Some(format!("node {peer}")),
            reason: None,
        };
        auth.record(
            &actor,
            "cluster.node.remove",
            &node,
            &serde_json::json!({
                "site": res.site,
                "up": res.up,
                "eligible": res.eligible,
                "witness": res.witness,
                "ephemeral": res.ephemeral,
            }),
        );
    }
    crate::forward::encode_answer(r)
}

/// Sends `w` to the primary and decodes the answer.
pub(crate) async fn send(
    cluster: Arc<Cluster>,
    primary: Option<String>,
    w: NodeRemoveWrite,
) -> Result<NodeRemoval, Problem> {
    let Some(primary) = primary else {
        return Err(Problem::unavailable(
            "this node is a cluster replica and can't reach the primary, which keeps the member list",
        )
        .hint("Retry when the primary is back, or use the primary's UI; DNS keeps working meanwhile."));
    };
    let body = serde_json::to_vec(&w).map_err(|e| Problem::internal(e.to_string()))?;
    let reply = cluster
        .call(&primary, KIND, body, DEADLINE)
        .await
        .map_err(|e| {
            Problem::unavailable(format!("the primary didn't answer: {e}"))
                .hint("Retry; if the primary runs an older version, it can't remove nodes yet.")
        })?;
    crate::forward::decode_answer(&reply)
}

//! REQ: CLU-001 (ADR-155, GitHub issue #5) — removing a node from the cluster: what the primary
//! checks, what it does, and what it tells the person who asked. The work itself is
//! [`crate::net::Cluster::remove_member`]; this holds its answer and its refusals.

use serde::{Deserialize, Serialize};

/// What removing (or, with `dry_run`, what would remove) a node does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // independent facts about the node
pub struct Removal {
    pub node_id: String,
    pub site: String,
    /// Heard from within the last few heartbeats, or connected now.
    pub up: bool,
    pub eligible: bool,
    pub witness: bool,
    pub ephemeral: bool,
    /// It was an eligible node, so it holds the cluster key: removal stops the cluster
    /// accepting it, but if it can't be trusted the CA should be rotated too.
    pub held_cluster_key: bool,
    /// Voters (eligible nodes and witnesses) left.
    pub voters_after: usize,
    /// Whether automatic failover still runs (it needs three voters).
    pub automatic_failover_after: bool,
    /// False for a dry run.
    pub removed: bool,
    /// Sentences for the person: what to do about the key, what happens to failover.
    pub notes: Vec<String>,
}

/// Why a node can't be removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoveError {
    /// This node isn't the primary: only the primary keeps the member list.
    NotPrimary,
    /// No member with that ID.
    Unknown,
    /// This node is the primary: it can't remove itself.
    IsSelf,
    /// The node is up: removing it cuts a working node off (needs `force`).
    Up,
    /// The registry or the removed list couldn't be written.
    Store(String),
}

impl std::fmt::Display for RemoveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPrimary => f.write_str("only the primary keeps the member list"),
            Self::Unknown => f.write_str("no cluster member has that ID"),
            Self::IsSelf => f.write_str("this node is the primary and can't remove itself"),
            Self::Up => f.write_str("the node is up"),
            Self::Store(e) => write!(f, "can't store the member list: {e}"),
        }
    }
}

/// The sentences a removal tells the person who asked. `lost_auto` is the number of voters left
/// when the removal turns automatic failover (which needs three) into manual.
pub(crate) fn notes(eligible: bool, up: bool, lost_auto: Option<usize>) -> Vec<String> {
    let mut v = Vec::new();
    if eligible {
        v.push(
            "It was an eligible node, so it holds a copy of the cluster key. The cluster no longer accepts its certificate, but if the node is lost or can't be trusted, rotate the cluster CA (`wrendns cluster rotate-ca`)."
                .to_owned(),
        );
    }
    if up {
        v.push(
            "It was up: its connection is closed and it is refused when it reconnects. Stop it, and clear its cluster directory before it joins again with a new token."
                .to_owned(),
        );
    }
    if let Some(voters_after) = lost_auto {
        v.push(format!(
            "{voters_after} voter(s) are left and automatic failover needs three, so it acts as manual until another eligible node or a witness joins."
        ));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: CLU-001 (ADR-155) — what a removal says: the key for an eligible node, the closed
    // connection for one that was up, failover when it drops below three voters.
    #[test]
    fn clu_001_a_removal_says_what_it_leaves_behind() {
        assert_eq!(notes(false, false, None), Vec::<String>::new());
        let n = notes(true, true, Some(2));
        assert_eq!(n.len(), 3, "{n:?}");
        assert!(n[0].contains("rotate the cluster CA"));
        assert!(n[1].contains("refused when it reconnects"));
        assert!(n[2].contains("2 voter(s)") && n[2].contains("acts as manual"));
    }
}

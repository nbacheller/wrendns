//! REQ: DSC-001 (T25.2, ADR-907) — which node runs the network inventory. `[discovery] node` when it
//! is set, else the cluster's primary, else the standalone node. Ephemeral resolver pods and
//! witnesses never run it, even when they are named. Off unless `[discovery] enabled` is set.

use telltale_config::DiscoveryConfig;

/// What this node is in the cluster, as the gate needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Me<'a> {
    /// The cluster node ID (the name `node` may also match).
    pub(crate) node_id: &'a str,
    /// The node's configured name (`[node] name`), which `node` may also name.
    pub(crate) name: &'a str,
    /// The cluster's primary, or the standalone node.
    pub(crate) primary: bool,
    /// An ephemeral member (a resolver pod).
    pub(crate) ephemeral: bool,
    /// A witness (votes only, holds no configuration).
    pub(crate) witness: bool,
}

/// Whether this node is the designated one for `[discovery]` (DSC-001).
pub(crate) fn designated(cfg: &DiscoveryConfig, me: Me<'_>) -> bool {
    if me.ephemeral || me.witness {
        return false;
    }
    match cfg.node.as_ref() {
        Some(n) => n.as_str() == me.node_id || (!me.name.is_empty() && n.as_str() == me.name),
        None => me.primary,
    }
}

/// Whether this node runs the inventory and its workers: enabled, and designated.
pub(crate) fn should_run(cfg: &DiscoveryConfig, me: Me<'_>) -> bool {
    cfg.enabled && designated(cfg, me)
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_config::SafeString;

    fn on() -> DiscoveryConfig {
        DiscoveryConfig {
            enabled: true,
            ..DiscoveryConfig::default()
        }
    }

    fn me(primary: bool) -> Me<'static> {
        Me {
            node_id: "node-a",
            name: "pi-a",
            primary,
            ephemeral: false,
            witness: false,
        }
    }

    /// REQ: DSC-001 (`dsc_001_off_by_default_starts_nothing`) — disabled, nothing runs anywhere.
    #[test]
    fn dsc_001_off_by_default_starts_nothing() {
        let off = DiscoveryConfig::default();
        assert!(!should_run(&off, me(true)));
        assert!(!should_run(&off, me(false)));
    }

    /// REQ: DSC-001 (`dsc_001_only_designated_node_runs`) — with no `node`, the primary (or the
    /// standalone node) runs it; a replica doesn't. With `node` set, only that node does.
    #[test]
    fn dsc_001_only_designated_node_runs() {
        assert!(should_run(&on(), me(true)));
        assert!(!should_run(&on(), me(false)));
        let named = DiscoveryConfig {
            node: Some(SafeString::new("pi-a").unwrap()),
            ..on()
        };
        assert!(should_run(&named, me(false)), "the named replica runs it");
        assert!(!should_run(
            &named,
            Me {
                name: "pi-b",
                node_id: "node-b",
                ..me(true)
            }
        ));
        let by_id = DiscoveryConfig {
            node: Some(SafeString::new("node-a").unwrap()),
            ..on()
        };
        assert!(should_run(&by_id, me(false)), "a node ID names it too");
    }

    /// REQ: DSC-001 (`dsc_001_never_on_ephemeral_or_witness`) — never on an ephemeral pod or a
    /// witness, even when `node` names it.
    #[test]
    fn dsc_001_never_on_ephemeral_or_witness() {
        let named = DiscoveryConfig {
            node: Some(SafeString::new("pi-a").unwrap()),
            ..on()
        };
        let pod = Me {
            ephemeral: true,
            ..me(true)
        };
        let witness = Me {
            witness: true,
            ..me(true)
        };
        assert!(!should_run(&on(), pod));
        assert!(!should_run(&named, pod));
        assert!(!should_run(&named, witness));
        assert!(!should_run(&on(), witness));
    }
}

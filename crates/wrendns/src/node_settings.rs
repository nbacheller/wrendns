//! REQ: DNS-006, OPS-011, OPS-012 (T27.2, T27.11, ADR-1006) - the per-node sections: `[cache]`
//! (15 fields), `[support] persist_logs` and `[updates] check`, as node-managed entries.
//!
//! - **Named by node.** An entry is named by the node it applies to (`node_label`, the name guarded
//!   phrases use: the cluster node ID for a member, the configured name or hostname otherwise).
//!   Every node applies its own row only; the rows replicate in the manifest's `node_managed` blob
//!   (`node_managed.rs`), references only (these kinds carry no secret).
//! - **Roles.** The cache is an operator's setting (T27.2: operators and admins change it, viewers
//!   read it); the support and update switches are admins' (T27.11). An agent is refused (403,
//!   `agent_not_allowed`) whatever its scopes, and a write whose role an older node didn't send is
//!   refused until that node is upgraded (409 `upgrade_required`), as the other settings are.
//! - **The files win.** A field the configuration files set can't be changed here (409
//!   `set_by_file`) and is kept when a request leaves it out (`settings_kinds::prepare`).
//! - **Restart.** Each of these sections is read once, when the node starts (`restart_only_changes`
//!   in `server.rs`, and the start-time snapshot below), so a change is "pending restart" until the
//!   node restarts.

use std::sync::OnceLock;

use serde_json::Value;
use wrendns_api::ManagedKind;
use wrendns_api::ManagedWrite;
use wrendns_api::auth::Role;
use wrendns_api::model::{NodeSection, NodeSettings};
use wrendns_api::problem::{Code, Problem};
use wrendns_config::Config;
use wrendns_store::state::State;

use crate::api_backend::ManagedPlan;
use crate::http::Sources;
use crate::managed::{CACHE, Entries, SUPPORT, UPDATES};
use crate::settings_kinds;

/// The kinds this module plans, in the order the status lists them.
pub(crate) const KINDS: [ManagedKind; 3] = [
    ManagedKind::Cache,
    ManagedKind::Support,
    ManagedKind::Updates,
];

/// The sections the node started with (what the process runs), taken once at start.
static STARTED: OnceLock<Vec<(ManagedKind, Value)>> = OnceLock::new();

/// Records what the node runs with, from its start-time configuration (the first call wins).
pub(crate) fn remember_start(cfg: &Config) {
    let _ = STARTED.set(started_of(cfg));
}

/// The sections of `cfg` as `describe` compares them.
pub(crate) fn started_of(cfg: &Config) -> Vec<(ManagedKind, Value)> {
    KINDS
        .iter()
        .map(|k| (*k, settings_kinds::section_json(*k, cfg)))
        .collect()
}

/// What this process started with, once `remember_start` ran.
pub(crate) fn started() -> Option<&'static [(ManagedKind, Value)]> {
    STARTED.get().map(Vec::as_slice)
}

/// The storage kind name of a per-node kind.
fn storage(kind: ManagedKind) -> &'static str {
    match kind {
        ManagedKind::Cache => CACHE,
        ManagedKind::Support => SUPPORT,
        _ => UPDATES,
    }
}

/// The name a node goes by in these entries (the same as the guarded module's).
pub(crate) fn node_name(cfg: &Config) -> String {
    crate::guarded::node_label(cfg)
}

/// The stored body of `kind` for `node`, if the API or UI set one.
fn row<'a>(e: &'a Entries, kind: ManagedKind, node: &str) -> Option<&'a Value> {
    let k = storage(kind);
    e.node_settings
        .iter()
        .find(|(kk, n, _)| kk == k && n == node)
        .map(|(_, _, v)| v)
}

/// The section of `kind` as `node` runs it: the files, with the node's own stored row laid over.
fn section_for(file: &Config, e: &Entries, kind: ManagedKind, node: &str) -> Value {
    let mut c = file.clone();
    if let Some(v) = row(e, kind, node) {
        // A stored row that no longer validates is left out here (the files' value shows);
        // the merge reports it.
        let _ = settings_kinds::overlay(&mut c, file, kind, v);
    }
    settings_kinds::section_json(kind, &c)
}

/// REQ: DNS-006 (T27.2) - lays this node's own rows over the files' configuration (`cfg` is the
/// files' configuration until this runs; `own` decides which fields the files set). Returns the
/// problems with the stored values, which leave the files' values in place.
pub(crate) fn apply_stored(cfg: &mut Config, own: &Config, e: &Entries) -> Vec<String> {
    if e.node_settings.is_empty() {
        return Vec::new();
    }
    let me = node_name(own);
    let mut errs = Vec::new();
    for kind in KINDS {
        if let Some(v) = row(e, kind, &me)
            && let Err(why) = settings_kinds::overlay(cfg, own, kind, v)
        {
            errs.push(format!("{}: {why}", settings_kinds::section(kind)));
        }
    }
    errs
}

/// REQ: DNS-006, OPS-011, OPS-012 (T27.2, T27.11) - a replica lays the rows of the replicated blob
/// for this node over its configuration, under its own files (CLU-004: a bad row is dropped alone).
pub(crate) fn overlay_blob(cfg: &mut Config, entries: &[crate::node_managed::Entry]) {
    let me = node_name(cfg);
    let own = cfg.clone();
    for e in entries {
        let Some(kind) = KINDS.into_iter().find(|k| storage(*k) == e.kind) else {
            continue;
        };
        if e.name != me {
            continue;
        }
        if let Err(why) = settings_kinds::overlay(cfg, &own, kind, &e.body) {
            tracing::warn!(
                section = settings_kinds::section(kind),
                "a node-managed section for this node is ignored: {why}"
            );
        }
    }
}

/// The node IDs of this cluster (its members), for the names a write may use. A standalone node
/// has none (only its own name is valid).
pub(crate) fn members(src: &Sources) -> Vec<String> {
    src.cluster
        .as_ref()
        .map(|c| c.members().into_iter().map(|m| m.node_id).collect())
        .unwrap_or_default()
}

/// REQ: DNS-006 (T27.2) - the status of `node`'s sections, for `GET /api/v1/node-settings`.
/// `eff` is the configuration this node runs with now; `me` is this node's name.
pub(crate) fn describe(
    file: &Config,
    eff: &Config,
    e: &Entries,
    node: &str,
    me: &str,
    started: Option<&[(ManagedKind, Value)]>,
) -> NodeSettings {
    let mine = node == me;
    let sections = KINDS
        .into_iter()
        .map(|kind| {
            let section = settings_kinds::section(kind);
            let fields = if mine {
                settings_kinds::section_json(kind, eff)
            } else {
                section_for(file, e, kind, node)
            };
            let set_by_file = settings_kinds::keys(kind)
                .iter()
                .filter(|k| file.file_set.contains(&format!("{section}.{k}")))
                .map(|k| (*k).to_owned())
                .collect();
            let pending_restart = mine
                && started.is_some_and(|s| {
                    s.iter()
                        .find(|(k, _)| *k == kind)
                        .is_some_and(|(_, v)| *v != fields)
                });
            NodeSection {
                section: section.to_owned(),
                fields,
                set_by_file,
                stored: row(e, kind, node).is_some(),
                pending_restart,
                restart_only: true,
            }
        })
        .collect();
    NodeSettings {
        node: node.to_owned(),
        sections,
    }
}

/// REQ: DNS-006, OPS-011, OPS-012 (T27.2, T27.11, ADR-1006) - plans a `PUT` or `DELETE` of one
/// node's section (`w.name` is the node).
pub(crate) fn plan(src: &Sources, state: &State, w: &ManagedWrite) -> Result<ManagedPlan, Problem> {
    let section = settings_kinds::section(w.kind);
    may_change(w.kind, w.role, w.agent.as_deref())?;
    let file = src.file_config.load_full();
    let me = node_name(&file);
    let node = w.name.trim().to_owned();
    if node != me && !members(src).contains(&node) {
        return Err(
            Problem::not_found(format!("no node of this cluster has the ID `{node}`"))
                .hint("GET /api/v1/node-settings lists this node's ID."),
        );
    }
    let mut entries = crate::managed::entries(state);
    let before = section_for(&file, &entries, w.kind, &node);
    let file_section = settings_kinds::section_json(w.kind, &file);
    let storage_kind = storage(w.kind);
    let stored = if let Some(v) = &w.body {
        let s = settings_kinds::prepare(w.kind, v, &file_section, &file)?;
        entries
            .node_settings
            .retain(|(k, n, _)| !(k == storage_kind && *n == node));
        entries
            .node_settings
            .push((storage_kind.to_owned(), node.clone(), s.clone()));
        Some(s)
    } else {
        if row(&entries, w.kind, &node).is_none() {
            return Err(Problem::not_found(format!(
                "the {} of `{node}` weren't changed through the API or UI: the config file's are in effect",
                settings_kinds::noun(w.kind)
            )));
        }
        entries
            .node_settings
            .retain(|(k, n, _)| !(k == storage_kind && *n == node));
        None
    };
    let after = section_for(&file, &entries, w.kind, &node);
    let merged = crate::managed::merge(&file, &entries)
        .map_err(|errs| Problem::new(Code::InvalidConfig, errs.join("; ")))?;
    let mut warnings = wrendns_config::validate_config(&merged).unwrap_or_default();
    if before != after {
        warnings.push(format!(
            "Takes effect after a restart of `{node}`: {}.",
            restart_reason(w.kind)
        ));
    }
    let impact = if stored.is_some() {
        format!(
            "Takes effect after a restart of `{node}`: {}.",
            restart_reason(w.kind)
        )
    } else {
        format!(
            "The config file's `[{section}]` (or the defaults) applies again on `{node}` after a restart."
        )
    };
    Ok(ManagedPlan {
        name: node,
        before: Some(before),
        after: Some(after),
        body: stored.map(|s| s.to_string()),
        recent_queries: 0,
        impact,
        warnings,
        also: Vec::new(),
        candidate: merged,
        redirect: None,
    })
}

/// Who may change a per-node section (ADR-1006): an agent never; the cache an operator or an admin
/// (T27.2); the support and update switches an admin (T27.11). A write whose role an older node
/// didn't send is refused until that node is upgraded.
pub(crate) fn may_change(
    kind: ManagedKind,
    role: Option<Role>,
    agent: Option<&str>,
) -> Result<(), Problem> {
    let section = settings_kinds::section(kind);
    if agent.is_some() {
        return Err(Problem::new(
            Code::AgentNotAllowed,
            format!("agents can't change `[{section}]`"),
        )
        .hint("Ask an admin to make this change in the UI."));
    }
    let lowest = if kind == ManagedKind::Cache {
        Role::Operator
    } else {
        Role::Admin
    };
    let who = if lowest == Role::Admin {
        "an admin"
    } else {
        "an operator"
    };
    match role {
        None => Err(Problem::new(
            Code::UpgradeRequired,
            format!(
                "this change to `[{section}]` needs {who}, and the node it was made on is too old to say who made it"
            ),
        )
        .hint("Upgrade that node first, or make the change on the primary.")),
        Some(r) if r >= lowest => Ok(()),
        Some(_) => Err(Problem::new(
            Code::Forbidden,
            format!("only {who} can change `[{section}]` on a node"),
        )
        .hint("Ask an admin to make this change.")),
    }
}

/// Why a change to a per-node section applies only after a restart.
fn restart_reason(kind: ManagedKind) -> &'static str {
    match kind {
        ManagedKind::Cache => {
            "the cache is sized and tuned when the node starts (its memory budget, TTLs and prefetch)"
        }
        ManagedKind::Support => "the log files are opened once, when the node starts",
        _ => "the daily update check starts with the node",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DNS-006 - the stored row of one node is laid over the files for that node only.
    #[test]
    fn dns_006_row_is_for_its_node() {
        let file = Config::default();
        let mut e = Entries::default();
        e.node_settings.push((
            CACHE.to_owned(),
            "node-a".to_owned(),
            serde_json::json!({"max_bytes": 1_048_576}),
        ));
        let a = section_for(&file, &e, ManagedKind::Cache, "node-a");
        let b = section_for(&file, &e, ManagedKind::Cache, "node-b");
        assert_eq!(a["max_bytes"], serde_json::json!("1MiB"));
        assert_eq!(
            b["max_bytes"],
            serde_json::to_value(file.cache.max_bytes).unwrap()
        );
    }
}

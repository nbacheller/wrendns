//! REQ: API-902, CLU-004 (T27.13; ADR-957) — recovery for guarded settings: `telltale guarded list`
//! and `telltale guarded clear`, offline.
//!
//! No UI control (API-901's exception for inherently offline commands: the owner of the data
//! directory runs them, and the UI may be the thing that is unreachable). Both open `state.db`
//! directly, so the node must be stopped: they refuse while a running node holds the data
//! directory's lock. A clear is audited in `state.db` with the actor `cli:<os user>`, prints what
//! the node will use afterwards (the file's values, or the defaults), and says to restart. In a
//! cluster it clears only this node's entries. A replica can't publish a removal (the primary is
//! the single writer and replicates the entry back), so a clear there is also recorded locally as
//! *suppressed until the primary's copy changes*: the node ignores that entry's replicated value
//! while the primary's copy is the same one (compared by hash), says so in the log, the UI and
//! `guarded list`.
//!
//! `TELLTALE_IGNORE_GUARDED=1` is the other way: the node starts with every guarded entry ignored
//! (not deleted), for places where running the CLI offline is awkward (Kubernetes: set the
//! variable and let the pod restart). It never ignores the file.

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use telltale_config::Config;
use telltale_store::state::{NewAudit, State};

use super::engine::redact;
use super::store::{self, EntryState, Stored};

/// What to clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    One(String),
    All,
}

/// The state database of the node `cfg` describes, with the data directory locked: refused while
/// a node runs, and refused for a directory with no `state.db` (a mistyped `-c`).
fn open_offline(
    cfg: &Config,
) -> Result<(Arc<State>, crate::datadir::DataDirLock, PathBuf), String> {
    let dir = PathBuf::from(cfg.node.data_dir.as_str());
    let path = crate::managed::state_path(cfg);
    if !path.is_file() {
        return Err(format!(
            "no TelltaleDNS state in {}: check the data directory in the config (-c)",
            dir.display()
        ));
    }
    let lock = match crate::datadir::lock(&dir, Duration::ZERO) {
        Ok(l) => l,
        Err(crate::datadir::LockError::Held(holder)) => {
            return Err(format!(
                "TelltaleDNS is running on this data directory ({holder}). Stop the node first: guarded entries are listed and cleared with it stopped"
            ));
        }
        Err(crate::datadir::LockError::Io(e)) => return Err(e.to_string()),
    };
    let state = State::open(&path).map_err(|e| format!("state.db can't be opened: {e}"))?;
    Ok((Arc::new(state), lock, dir))
}

/// What a line of `list` says about an entry.
fn describe(e: &Stored, suppressed: bool) -> String {
    let state = match e.state {
        EntryState::Active => "active",
        EntryState::Staged => "staged (waits for the next start)",
        EntryState::Probation => "on probation",
    };
    let sup = if suppressed {
        "  [suppressed: a local clear hides the primary's copy until it changes]"
    } else {
        ""
    };
    format!(
        "{:<24} {:<10} {}{}  by {} at {}  value {}",
        e.id,
        e.mode,
        state,
        sup,
        if e.by.is_empty() { "-" } else { &e.by },
        e.at,
        redact(&e.value)
    )
}

/// `telltale guarded list`: each guarded entry on the node (staged, on probation, active, the
/// `data-dir` pointer included). Changes nothing.
pub(crate) fn run_list(cfg: &Config, out: &mut impl Write) -> io::Result<bool> {
    let (state, _lock, _dir) = match open_offline(cfg) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("error: {e}");
            return Ok(false);
        }
    };
    let node = super::node_label(cfg);
    let entries = store::for_node(&state, &node);
    let suppressed = store::suppressed(&state);
    if entries.is_empty() && suppressed.is_empty() {
        writeln!(out, "no guarded entries on {node}")?;
        return Ok(true);
    }
    writeln!(out, "guarded entries on {node}:")?;
    for e in &entries {
        writeln!(out, "  {}", describe(e, suppressed.contains_key(&e.id)))?;
    }
    for id in suppressed
        .keys()
        .filter(|id| !entries.iter().any(|e| e.id == **id))
    {
        writeln!(
            out,
            "  {id:<24} (suppressed locally; the primary's copy is hidden)"
        )?;
    }
    if super::ignored() || std::env::var(super::IGNORE_ENV).is_ok_and(|v| v == "1") {
        writeln!(
            out,
            "TELLTALE_IGNORE_GUARDED=1 is set: the node ignores every entry above."
        )?;
    }
    Ok(true)
}

/// `telltale guarded clear <id>|--all`: removes this node's entries, with the node stopped. Audited
/// as `cli:<os user>`.
pub(crate) fn run_clear(
    cfg: &Config,
    target: &Target,
    os_user: &str,
    out: &mut impl Write,
) -> io::Result<bool> {
    let (state, _lock, dir) = match open_offline(cfg) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("error: {e}");
            return Ok(false);
        }
    };
    let node = super::node_label(cfg);
    let mut entries = store::for_node(&state, &node);
    // On a replica the entries come from the primary's blob: what it last applied is what a clear
    // has to suppress.
    let replica = is_replica_at(&dir);
    if replica {
        for e in replicated_entries(cfg, &node) {
            if !entries.iter().any(|x| x.id == e.id) {
                entries.push(e);
            }
        }
    }
    let wanted: Vec<Stored> = match target {
        Target::All => entries.clone(),
        Target::One(id) => entries.iter().filter(|e| e.id == *id).cloned().collect(),
    };
    if wanted.is_empty() {
        match target {
            Target::One(id) => eprintln!(
                "error: no guarded entry `{id}` on {node}: `telltale guarded list` shows what is stored"
            ),
            Target::All => writeln!(out, "no guarded entries on {node}: nothing to clear")?,
        }
        return Ok(matches!(target, Target::All));
    }
    let now = super::now_secs();
    let actor = format!("cli:{os_user}");
    let mut suppressed = store::suppressed(&state);
    let mut cleared = Vec::new();
    for e in &wanted {
        // The local row (a primary's or a standalone node's), if there is one.
        let had_row = store::all(&state)
            .iter()
            .any(|r| r.node == node && r.id == e.id);
        if had_row && let Err(why) = store::delete(&state, &node, &e.id) {
            eprintln!("error: can't clear `{}`: {why}", e.id);
            return Ok(false);
        }
        if replica {
            suppressed.insert(e.id.clone(), e.digest());
        }
        let detail = json!({"setting": e.id, "node": node, "was": e.state.as_str(), "suppressedLocally": replica}).to_string();
        let audited = state.audit_append(&NewAudit {
            ts: now,
            actor: &actor,
            actor_kind: "cli",
            remote: None,
            action: "settings.guarded_cleared",
            target: &super::entry_name(&node, &e.id),
            detail: &detail,
            reason: None,
        });
        if let Err(why) = audited {
            eprintln!(
                "warning: the clear of `{}` couldn't be audited: {why}",
                e.id
            );
        }
        cleared.push(e.id.clone());
    }
    if replica && let Err(why) = store::set_suppressed(&state, &suppressed) {
        eprintln!("warning: the local suppression couldn't be saved: {why}");
    }
    // The probation counter belongs to the entries that were cleared.
    super::probation::clear_sidecar(&dir);
    writeln!(out, "cleared on {node}: {}", cleared.join(", "))?;
    if replica {
        writeln!(
            out,
            "This node is a cluster replica: the primary still holds these entries and replicates them back, so this node ignores them locally until the primary's copy changes (the primary can remove them from its own side)."
        )?;
    }
    writeln!(
        out,
        "After the restart the node uses the values in its configuration file (or the defaults). Start it now."
    )?;
    Ok(true)
}

/// The guarded entries for this node in the cluster version a replica last applied.
fn replicated_entries(cfg: &Config, node: &str) -> Vec<Stored> {
    crate::node_managed::applied_guarded(cfg, node)
}

/// Whether the node whose data directory this is has a cluster identity as a replica (a primary or
/// a standalone node keeps its own rows; a replica's entries come from the primary).
fn is_replica_at(dir: &std::path::Path) -> bool {
    matches!(
        telltale_cluster::node::Identity::load(dir),
        Ok(Some(id)) if matches!(id.meta.role, Some(telltale_cluster::node::Role::Replica))
    )
}

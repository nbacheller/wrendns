//! REQ: API-902, CLU-015 (T27.13; ADR-956 §2, ADR-957) — where a guarded value lives: a
//! `node_managed` entry of the reserved kind `guarded`, one per node and setting
//! (`guarded/<node>/<id>`), in `state.db`. Written only by the guarded module, and only when a
//! change is final (confirmed, applied or staged), never while it is pending. The node's
//! outcomes and the CLI's local suppressions are notes in `meta`: node-local, never replicated.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use telltale_api::guarded::GuardedOutcome;
use telltale_store::state::State;

use super::{KIND, entry_name, split_name};

/// Where an entry stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EntryState {
    /// In force: confirmed, applied, or a staged one that has proved healthy.
    Active,
    /// Written, waiting for the next start (`staged` settings). Not applied.
    Staged,
    /// Applied by the start that is running, until the node proves healthy (ADR-956 §4).
    Probation,
}

impl EntryState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Staged => "staged",
            Self::Probation => "probation",
        }
    }
}

/// One stored guarded entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Stored {
    pub(crate) node: String,
    pub(crate) id: String,
    /// The value, in the shape the setting's configuration section has. References only: a key
    /// is a path, never the key.
    pub(crate) value: Value,
    /// The mode it was written under (`window`, `immediate`, `staged`, `action`).
    pub(crate) mode: String,
    pub(crate) state: EntryState,
    /// Who made the change (a user name; `cli:<os user>` for the CLI).
    #[serde(default)]
    pub(crate) by: String,
    /// Unix seconds.
    #[serde(default)]
    pub(crate) at: u64,
}

impl Stored {
    /// A hash of the value, for "the primary's copy changed" (ADR-957).
    pub(crate) fn digest(&self) -> String {
        let bytes = serde_json::to_vec(&self.value).unwrap_or_default();
        super::hex(blake3::hash(&bytes).as_bytes())
    }
}

/// Settings whose entry is local to the node and never replicated (ADR-956 §1(a): the `data-dir`
/// pointer, written to and read only from the file-named directory's `state.db`). Their entries are
/// notes in `meta`, not `managed` rows, so the node-managed blob never carries them.
pub(crate) const LOCAL_ONLY: &[&str] = &["data-dir"];

fn local_key(node: &str, id: &str) -> String {
    format!("guarded.local.{node}.{id}")
}

pub(crate) fn is_local(id: &str) -> bool {
    LOCAL_ONLY.contains(&id)
}

/// Every stored guarded entry in `state`, bad rows skipped (a row that won't parse is logged and
/// left in place: the CLI can clear it).
pub(crate) fn all(state: &State) -> Vec<Stored> {
    let mut out = all_managed(state);
    for (_, text) in state.meta_prefix("guarded.local.").unwrap_or_default() {
        if let Ok(s) = serde_json::from_str::<Stored>(&text) {
            out.push(s);
        }
    }
    out
}

fn all_managed(state: &State) -> Vec<Stored> {
    let rows = match state.managed(KIND) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("guarded entries can't be read: {e}");
            return Vec::new();
        }
    };
    rows.into_iter()
        .filter_map(|m| match serde_json::from_str::<Stored>(&m.body) {
            Ok(mut s) => {
                // The name is the key: it wins over what the body says.
                if let Some((node, id)) = split_name(&m.name) {
                    s.node = node.to_owned();
                    s.id = id.to_owned();
                }
                Some(s)
            }
            Err(e) => {
                tracing::warn!(name = %m.name, "a guarded entry isn't readable and is ignored: {e}");
                None
            }
        })
        .collect()
}

/// The entries for one node.
pub(crate) fn for_node(state: &State, node: &str) -> Vec<Stored> {
    all(state).into_iter().filter(|s| s.node == node).collect()
}

/// Writes (or replaces) an entry. Bumps the configuration version like any managed write, so the
/// primary publishes it in the node-managed blob.
pub(crate) fn put(state: &State, s: &Stored, now: u64, by: &str) -> Result<(), String> {
    let body = serde_json::to_string(s).map_err(|e| e.to_string())?;
    if is_local(&s.id) {
        return state
            .meta_set(&local_key(&s.node, &s.id), Some(&body))
            .map_err(|e| e.to_string());
    }
    state
        .put_managed(
            KIND,
            &entry_name(&s.node, &s.id),
            &body,
            None,
            None,
            now,
            by,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Removes an entry (not an error when it isn't there).
pub(crate) fn delete(state: &State, node: &str, id: &str) -> Result<(), String> {
    if is_local(id) {
        return state
            .meta_set(&local_key(node, id), None)
            .map_err(|e| e.to_string());
    }
    match state.delete_managed(KIND, &entry_name(node, id), None) {
        Ok(_) => Ok(()),
        Err(telltale_store::state::ManagedError::NotFound { .. }) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

const OUTCOMES: &str = "guarded.outcomes";
const SUPPRESSED: &str = "guarded.suppressed";
/// How many outcomes a node keeps.
pub(crate) const OUTCOMES_KEPT: usize = 10;

/// The node's latest outcomes, newest first.
pub(crate) fn outcomes(state: &State) -> Vec<GuardedOutcome> {
    state
        .meta_get(OUTCOMES)
        .ok()
        .flatten()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Records an outcome (newest first, a bounded list).
pub(crate) fn record_outcome(state: &State, o: GuardedOutcome) {
    let mut v = outcomes(state);
    v.insert(0, o);
    v.truncate(OUTCOMES_KEPT);
    if let Ok(t) = serde_json::to_string(&v)
        && let Err(e) = state.meta_set(OUTCOMES, Some(&t))
    {
        tracing::warn!("a guarded outcome can't be kept: {e}");
    }
}

/// The CLI's local suppressions: setting ID to the digest of the primary's copy that was cleared
/// (ADR-957). The node ignores that entry's replicated value while the digest is the same.
pub(crate) fn suppressed(state: &State) -> std::collections::BTreeMap<String, String> {
    state
        .meta_get(SUPPRESSED)
        .ok()
        .flatten()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Replaces the suppressions.
pub(crate) fn set_suppressed(
    state: &State,
    m: &std::collections::BTreeMap<String, String>,
) -> Result<(), String> {
    if m.is_empty() {
        return state.meta_set(SUPPRESSED, None).map_err(|e| e.to_string());
    }
    let t = serde_json::to_string(m).map_err(|e| e.to_string())?;
    state
        .meta_set(SUPPRESSED, Some(&t))
        .map_err(|e| e.to_string())
}

//! REQ: API-902, CLU-004, OPS-012 (T27.13; ADR-956 §4, ADR-957) — probation: what a node does at
//! start with a staged or restored guarded entry.
//!
//! A `staged` entry is written at once and applied at the next start. That start marks it on
//! **probation** and counts the attempt in a sidecar file, `<data_dir>/guarded-probation` (mode
//! 0600), not in `state.db`, because the failure may be that `state.db` won't open. Before any
//! guarded value is applied the node writes the attempt count and the entry IDs to it with an
//! fsync and a rename; it deletes the file when the node is healthy. A start that finds the count
//! at 2 drops the listed entries (audited `settings.guarded_rolled_back`, `failed_start`) and
//! starts from the file. A power loss counts as a failed start.
//!
//! *Healthy* is: the state opened, the API listener is bound, the node's own DNS probe answered,
//! and (for `secrets-key`) the store is unlocked, within `max(confirm_window_secs, 180)` seconds (a
//! floor, so a slow Pi compiling a large filter isn't rolled back, and a window of 30 doesn't
//! shorten it).
//!
//! Once any row has been re-encrypted under a new key, dropping the entry must not return the node
//! to the old key alone: a row's `fallback` replaces the dropped entry (the new key as the
//! previous key, so every row opens) and the node reports `secrets_rotation_incomplete`.
//!
//! A confirmed `window` entry (a `listen` or `api-address` on an interface that isn't up yet at
//! boot) is protected too: a bind failure for a guarded listener falls back, for that start only,
//! to the file's value with the health reason `guarded_bind_fallback`; the entry stays and is tried
//! again next start.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use telltale_api::auth::Actor;
use telltale_api::guarded::GuardedOutcome;
use telltale_config::Config;
use telltale_store::state::{NewAudit, State};
use tracing::{info, warn};

use super::engine::RowDef;
use super::store::{self, EntryState, Stored};

/// The sidecar's name in the data directory.
pub(crate) const SIDECAR: &str = "guarded-probation";
/// Failed starts before the entries are dropped.
pub(crate) const MAX_ATTEMPTS: u32 = 2;
/// The floor of the healthy deadline, in seconds.
pub(crate) const HEALTHY_FLOOR_SECS: u64 = 180;

/// The counter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Sidecar {
    /// Starts that began with these entries applied and didn't become healthy.
    pub(crate) attempts: u32,
    /// The entries on probation.
    pub(crate) ids: Vec<String>,
}

pub(crate) fn sidecar_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SIDECAR)
}

/// The sidecar, if there is one and it reads. An unreadable one counts as a failed start with no
/// entries (it can't name any), so it is treated as absent.
pub(crate) fn read_sidecar(data_dir: &Path) -> Option<Sidecar> {
    let text = std::fs::read_to_string(sidecar_path(data_dir)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Writes the sidecar with an fsync and a rename (so a power loss leaves the old or the new one).
pub(crate) fn write_sidecar(data_dir: &Path, s: &Sidecar) -> std::io::Result<()> {
    let final_path = sidecar_path(data_dir);
    let tmp = data_dir.join(format!("{SIDECAR}.tmp"));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(serde_json::to_string(s).unwrap_or_default().as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, &final_path)?;
    // The rename itself is made durable by syncing the directory.
    if let Ok(d) = std::fs::File::open(data_dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

pub(crate) fn clear_sidecar(data_dir: &Path) {
    let _ = std::fs::remove_file(sidecar_path(data_dir));
}

/// What the start-up step did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Begin {
    /// Entries that went on probation (their IDs).
    pub(crate) on_probation: Vec<String>,
    /// Entries dropped after two failed starts.
    pub(crate) dropped: Vec<String>,
    /// The node ignores every guarded entry (`TELLTALE_IGNORE_GUARDED`).
    pub(crate) ignored: bool,
}

fn audit_system(state: &State, now: u64, action: &str, target: &str, detail: &serde_json::Value) {
    let a = Actor::system("guarded");
    let d = detail.to_string();
    let _ = state.audit_append(&NewAudit {
        ts: now,
        actor: &a.name,
        actor_kind: a.kind,
        remote: None,
        action,
        target,
        detail: &d,
        reason: None,
    });
}

/// The start-up step (`run`, before the configuration is loaded with what the UI stored): decides
/// what the guarded entries do at this start. `cfg` is the node's files alone.
pub(crate) fn begin(cfg: &Config, defs: &[RowDef], now: u64) -> Begin {
    let node = super::node_label(cfg);
    super::set_this_node(&node);
    let ignore = std::env::var(super::IGNORE_ENV).is_ok_and(|v| v == "1");
    let out = begin_for(cfg, &node, defs, now, ignore);
    super::set_ignored(out.ignored);
    out
}

/// [`begin`] for node `node`, with the environment switch passed in (the tests' form).
#[allow(clippy::too_many_lines)] // the start-up decision reads best in one place
pub(crate) fn begin_for(
    cfg: &Config,
    node: &str,
    defs: &[RowDef],
    now: u64,
    ignore: bool,
) -> Begin {
    let node = node.to_owned();
    let mut out = Begin::default();
    // The environment switch: ignore every entry, delete none (ADR-957). It ignores a `data-dir`
    // pointer too, so the node starts in the directory the file names.
    if ignore {
        warn!(
            "TELLTALE_IGNORE_GUARDED=1: every guarded entry is ignored at this start (nothing is deleted); the node runs on its files"
        );
        out.ignored = true;
        return out;
    }
    let data_dir = Path::new(cfg.node.data_dir.as_str());
    let path = crate::managed::state_path(cfg);
    let prior = read_sidecar(data_dir);
    // Without a database there is nothing to apply. A sidecar left over from a database that is
    // gone is stale.
    let Ok(state) = (if path.exists() {
        State::open(&path).map_err(|_| ())
    } else {
        Err(())
    }) else {
        if prior.as_ref().is_some_and(|p| p.attempts >= MAX_ATTEMPTS) {
            warn!(
                "the guarded-entry probation count is at its limit but state.db won't open: starting from the files"
            );
        }
        return out;
    };
    // REQ: API-902 — on a replica the staged entry is the primary's, in the blob it applied.
    let pairs = store::effective(cfg, &state, &node);
    let entries: Vec<Stored> = pairs.iter().map(|(e, _)| e.clone()).collect();
    let replicated = |id: &str| pairs.iter().any(|(e, r)| *r && e.id == id);
    let waiting: Vec<&Stored> = entries
        .iter()
        .filter(|e| matches!(e.state, EntryState::Staged | EntryState::Probation))
        .collect();
    let attempts = prior.as_ref().map_or(0, |p| p.attempts);
    let listed: BTreeSet<String> = prior
        .iter()
        .flat_map(|p| p.ids.iter().cloned())
        .chain(waiting.iter().map(|e| e.id.clone()))
        .collect();
    if listed.is_empty() {
        // Nothing staged or on probation: a stale sidecar is cleaned up.
        if prior.is_some() {
            clear_sidecar(data_dir);
        }
        return out;
    }
    if attempts >= MAX_ATTEMPTS {
        // Two starts with these entries didn't become healthy: drop them and start from the file.
        for id in &listed {
            let dropped = entries.iter().find(|e| e.id == *id);
            let replacement = dropped.filter(|d| !replicated(&d.id)).and_then(|d| {
                defs.iter()
                    .find(|r| r.row.id == d.id)
                    .and_then(|r| r.applier.failed_start(d, &state))
            });
            match replacement {
                None if dropped.is_some_and(|d| replicated(&d.id)) => {
                    // The primary keeps the entry: this node ignores it until it changes.
                    if let Some(d) = dropped
                        && let Err(e) = store::drop_entry(&state, d, true)
                    {
                        warn!(id = %id, "a failed replicated guarded entry can't be suppressed: {e}");
                    }
                }
                Some(r) => {
                    if let Err(e) = store::put(&state, &r, now, "system") {
                        warn!(id = %id, "the fallback entry can't be written: {e}");
                    }
                }
                None => {
                    if let Err(e) = store::delete(&state, &node, id) {
                        warn!(id = %id, "a failed guarded entry can't be dropped: {e}");
                    }
                }
            }
            audit_system(
                &state,
                now,
                "settings.guarded_rolled_back",
                &super::entry_name(&node, id),
                &json!({"setting": id, "node": node, "reason": "failed_start"}),
            );
            store::record_outcome(
                &state,
                GuardedOutcome {
                    setting: id.clone(),
                    node: node.clone(),
                    outcome: "rolled_back".to_owned(),
                    reason: Some("failed_start".to_owned()),
                    at: now,
                },
            );
            out.dropped.push(id.clone());
        }
        clear_sidecar(data_dir);
        warn!(dropped = ?out.dropped, "guarded entries that didn't make two starts healthy were dropped; starting from the files");
        return out;
    }
    // Count the attempt before any guarded value is applied (fsync and rename).
    let side = Sidecar {
        attempts: attempts + 1,
        ids: listed.iter().cloned().collect(),
    };
    if let Err(e) = write_sidecar(data_dir, &side) {
        // Without the counter the node can't promise to fall back: it starts from the files.
        warn!(
            "the probation counter can't be written ({e}): guarded entries are not applied at this start"
        );
        out.ignored = true;
        return out;
    }
    for e in waiting {
        if e.state == EntryState::Staged
            && let Err(err) = store::transition(
                &state,
                e,
                replicated(&e.id),
                EntryState::Probation,
                now,
                "system",
            )
        {
            warn!(id = %e.id, "can't mark an entry on probation: {err}");
        }
        out.on_probation.push(e.id.clone());
    }
    info!(entries = ?out.on_probation, attempt = side.attempts, "guarded entries are on probation at this start");
    out
}

/// What proving healthy needs, as the node reports it.
#[allow(clippy::struct_excessive_bools)] // four independent facts
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Health {
    pub(crate) state_open: bool,
    pub(crate) api_bound: bool,
    pub(crate) dns_probe_ok: bool,
    /// For `secrets-key`: the store is unlocked.
    pub(crate) secrets_unlocked: bool,
}

impl Health {
    pub(crate) const fn healthy(self, needs_unlocked: bool) -> bool {
        self.state_open
            && self.api_bound
            && self.dns_probe_ok
            && (self.secrets_unlocked || !needs_unlocked)
    }
}

/// The node proved healthy: entries on probation become active, the counter is deleted and the
/// outcome is recorded (`applied`).
pub(crate) fn mark_healthy(state: &State, node: &str, data_dir: &Path, now: u64) -> Vec<String> {
    let entries = store::for_node(state, node)
        .into_iter()
        .map(|e| (e, false))
        .collect();
    mark_healthy_of(state, node, data_dir, now, entries)
}

/// [`mark_healthy`] over `entries` (each with whether the primary replicated it).
pub(crate) fn mark_healthy_of(
    state: &State,
    node: &str,
    data_dir: &Path,
    now: u64,
    entries: Vec<(Stored, bool)>,
) -> Vec<String> {
    let mut done = Vec::new();
    for (e, replicated) in entries {
        if e.state == EntryState::Probation
            && store::transition(state, &e, replicated, EntryState::Active, now, "system").is_ok()
        {
            store::record_outcome(
                state,
                GuardedOutcome {
                    setting: e.id.clone(),
                    node: node.to_owned(),
                    outcome: "applied".to_owned(),
                    reason: None,
                    at: now,
                },
            );
            done.push(e.id);
        }
    }
    clear_sidecar(data_dir);
    if !done.is_empty() {
        info!(entries = ?done, "the node is healthy: guarded entries on probation are now active");
    }
    done
}

/// How long the node has to prove healthy: `max(confirm_window_secs, 180)`.
pub(crate) fn healthy_deadline_secs(cfg: &Config) -> u64 {
    u64::from(cfg.api.confirm_window_secs).max(HEALTHY_FLOOR_SECS)
}

static FALLBACK: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// A confirmed guarded listener couldn't bind at this start (an interface that isn't up yet, a DHCP
/// or VLAN address): the node runs on the file's value for this start only, with the health reason
/// `guarded_bind_fallback` and an audit row (`failed_start`). The entry stays and is tried again at
/// the next start (ADR-956 §4).
pub(crate) fn note_bind_fallback(state: Option<&State>, node: &str, id: &str, now: u64) {
    if let Ok(mut f) = FALLBACK.lock() {
        f.insert(id.to_owned());
    }
    warn!(
        setting = id,
        "a confirmed guarded listener couldn't bind: this start runs on the file's value"
    );
    if let Some(s) = state {
        audit_system(
            s,
            now,
            "settings.guarded_rolled_back",
            &super::entry_name(node, id),
            &json!({"setting": id, "node": node, "reason": "failed_start", "kept": true}),
        );
        store::record_outcome(
            s,
            GuardedOutcome {
                setting: id.to_owned(),
                node: node.to_owned(),
                outcome: "rolled_back".to_owned(),
                reason: Some("failed_start".to_owned()),
                at: now,
            },
        );
    }
}

/// Whether a start-up failure is a listener that couldn't bind (an interface that isn't up yet, an
/// address in use, a port the process may not open).
pub(crate) fn is_bind_failure(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{AddrInUse, AddrNotAvailable, PermissionDenied};
    matches!(e.kind(), AddrNotAvailable | AddrInUse | PermissionDenied)
}

/// REQ: API-902 (ADR-956 §4) — the node failed to start because a listener couldn't bind. Every
/// confirmed (active) listener entry of this node (a `window` row whose proof is a new socket) is
/// set aside for this start only ([`note_bind_fallback`]: audit row, outcome, health reason); the
/// caller rebuilds the configuration (the overlay skips what fell back) and starts again. The
/// entries stay, and the next start tries them again. Returns the settings that fell back.
pub(crate) fn fall_back_after_bind_failure(
    file_cfg: &Config,
    defs: &[RowDef],
    now: u64,
) -> Vec<String> {
    use telltale_config::guarded::{Mode, Proof};
    if super::ignored() {
        return Vec::new();
    }
    let node = super::this_node().unwrap_or_else(|| super::node_label(file_cfg));
    let path = crate::managed::state_path(file_cfg);
    let Ok(state) = State::open(&path) else {
        return Vec::new();
    };
    let mut done = Vec::new();
    for (e, _replicated) in store::effective(file_cfg, &state, &node) {
        let listener = defs.iter().any(|d| {
            d.row.id == e.id && d.row.mode == Mode::Window && d.row.proof == Some(Proof::NewSocket)
        });
        if e.state == EntryState::Active && listener && !fell_back(&e.id) {
            note_bind_fallback(Some(&state), &node, &e.id, now);
            done.push(e.id);
        }
    }
    done
}

/// Whether `id` fell back for this start (the overlay skips it).
pub(crate) fn fell_back(id: &str) -> bool {
    FALLBACK.lock().is_ok_and(|f| f.contains(id))
}

/// The settings that fell back at this start.
pub(crate) fn fallbacks() -> Vec<String> {
    FALLBACK
        .lock()
        .map(|f| f.iter().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) fn reset_fallbacks() {
    if let Ok(mut f) = FALLBACK.lock() {
        f.clear();
    }
}

/// Watches for the node proving healthy (see the module notes) and then makes the entries on
/// probation active. A node that never does leaves the counter in place, so the next start
/// counts the failure.
pub(crate) fn spawn_watch(
    src: Arc<crate::http::Sources>,
    state: Arc<State>,
    node: String,
    data_dir: PathBuf,
    cfg: Config,
    deadline_secs: u64,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let waiting = store::effective(&cfg, &state, &node)
        .iter()
        .any(|(e, _)| e.state == EntryState::Probation);
    if !waiting {
        return;
    }
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        loop {
            let needs_key = store::effective(&cfg, &state, &node)
                .iter()
                .any(|(e, _)| e.state == EntryState::Probation && e.id == "secrets-key");
            let h = Health {
                state_open: true,
                api_bound: src.readiness.serving(),
                dns_probe_ok: src
                    .probes
                    .results()
                    .iter()
                    .filter(|p| p.listener)
                    .all(|p| p.ok),
                secrets_unlocked: matches!(
                    src.secrets.status().state,
                    crate::secrets::store::StoreState::Ready
                        | crate::secrets::store::StoreState::Ephemeral
                ),
            };
            if h.healthy(needs_key) {
                mark_healthy_of(
                    &state,
                    &node,
                    &data_dir,
                    super::now_secs(),
                    store::effective(&cfg, &state, &node),
                );
                return;
            }
            if started.elapsed().as_secs() >= deadline_secs {
                warn!(
                    "the node isn't healthy after {deadline_secs} s with guarded entries on probation: they stay on probation, and the next start counts this one"
                );
                return;
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_millis(500)) => {}
                _ = stop.changed() => return,
            }
        }
    });
}

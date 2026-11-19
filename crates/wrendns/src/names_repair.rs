//! REQ: API-007, DSC-901 (T35.1, ADR-1032) — the one-off repair of names already stored with HTML
//! entities in them.
//!
//! Before names were decoded where they are read, a Pi-hole import could store a client called
//! `Alex&#039;s PC`. On the primary, a task finds the API-managed clients and groups whose names
//! hold an entity and stores the decoded name: one configuration change, audited as a system
//! change (`names.repair`), published to the replicas like any write. It is idempotent: a name
//! with no entity is never touched, so a second pass (or a restart) finds nothing and writes
//! nothing. Names that a configuration file defines are never rewritten: the repair reports them
//! (a health note naming the file) and leaves the file to its owner.
//!
//! Lists have no human-text field to repair: a list's name is an ID of lowercase letters, digits,
//! `-` and `_`, so it can hold no entity (the importer writes `pihole-<id>-<slug>`).
//!
//! A repair that would leave the configuration invalid (a group renamed that something still
//! names, a name that another entry already takes) is skipped and logged; DNS is never
//! involved.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use wrendns_config::Config;
use wrendns_store::state::{NewAudit, State};
use tracing::{info, warn};

use crate::managed::{
    self, ANOMALY_MUTE, CLIENT, DRILL, EXCLUSIONS, Entries, FORWARD, GROUP, KUBERNETES_MAP, Ovr,
    RULE, ZONE,
};
use crate::names::{clean_text, has_entities, tail};

/// The node-local note that the repair has run on this database (its value: the configuration
/// version then). The repair is one-off: once set, no later pass decodes anything, so a name
/// typed after the upgrade (`R&amp;D lab`) and a name that kept one escape layer are never
/// touched. Recorded in the write's own transaction, or on its own when the pass found nothing.
pub(crate) const MARKER: &str = "names-repair-v1";

/// The audit action of a repair.
pub(crate) const ACTION: &str = "names.repair";
/// Who the audit entry names.
pub(crate) const ACTOR: &str = "names repair";

/// One entry the repair renamed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Renamed {
    pub(crate) kind: &'static str,
    pub(crate) from: String,
    pub(crate) to: String,
}

/// A name a configuration file defines that holds an HTML entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamesInFile {
    /// `device` or `group`.
    pub(crate) kind: String,
    pub(crate) name: String,
    /// The file or files that hold it.
    pub(crate) files: Vec<String>,
}

/// What a pass did.
#[derive(Debug, Default)]
pub(crate) struct Report {
    pub(crate) renamed: Vec<Renamed>,
    /// Entries left as they are, and why: `(kind, name, reason)`.
    pub(crate) skipped: Vec<(&'static str, String, String)>,
    /// Entries a configuration file defines whose names hold entities (never rewritten).
    pub(crate) file_entries: Vec<NamesInFile>,
    /// The configuration version the repair stored, when it changed anything.
    pub(crate) version: Option<u64>,
}

/// The rows the repair reads: what is stored, by (kind, name).
type Rows = BTreeMap<(&'static str, String), Value>;

/// The kinds read: clients and groups (renamed), and every kind that names a device or a group.
const KINDS: [&str; 9] = [
    CLIENT,
    GROUP,
    RULE,
    FORWARD,
    ZONE,
    KUBERNETES_MAP,
    ANOMALY_MUTE,
    EXCLUSIONS,
    DRILL,
];

fn load(state: &State) -> Result<Rows, String> {
    let mut rows = Rows::new();
    for kind in KINDS {
        for m in state.managed(kind).map_err(|e| e.to_string())? {
            if let Ok(v) = serde_json::from_str::<Value>(&m.body) {
                rows.insert((kind, m.name), v);
            }
        }
    }
    Ok(rows)
}

/// `base` with the clients, groups, rules and forwards replaced by `rows`: what the node would
/// build on if the rows were stored.
fn entries_of(mut base: Entries, rows: &Rows) -> Entries {
    base.clients = Vec::new();
    base.groups = Vec::new();
    base.rules = Vec::new();
    base.forwards = Vec::new();
    base.zones = Vec::new();
    base.kubernetes_map = Vec::new();
    base.anomaly_mutes = Vec::new();
    base.exclusions = None;
    base.drill = None;
    for ((kind, name), body) in rows {
        match *kind {
            CLIENT => {
                if let Ok(c) = serde_json::from_value(body.clone()) {
                    base.clients.push(c);
                }
            }
            GROUP => {
                if body.get("hidden").and_then(Value::as_bool) == Some(true) {
                    base.groups.push((name.clone(), Ovr::Hidden));
                } else if let Ok(g) = serde_json::from_value(body.clone()) {
                    base.groups.push((name.clone(), Ovr::Set(g)));
                }
            }
            RULE => {
                if let Ok(r) = serde_json::from_value(body.clone()) {
                    base.rules.push(r);
                }
            }
            FORWARD => {
                if let Ok(f) = serde_json::from_value(body.clone()) {
                    base.forwards.push((name.clone(), f));
                }
            }
            ZONE => {
                if let Ok(z) = serde_json::from_value(body.clone()) {
                    base.zones.push((name.clone(), z));
                }
            }
            KUBERNETES_MAP => {
                if body.get("hidden").and_then(Value::as_bool) == Some(true) {
                    base.kubernetes_map.push((name.clone(), Ovr::Hidden));
                } else if let Ok(r) = serde_json::from_value(body.clone()) {
                    base.kubernetes_map.push((name.clone(), Ovr::Set(r)));
                }
            }
            ANOMALY_MUTE => {
                if body.get("hidden").and_then(Value::as_bool) == Some(true) {
                    base.anomaly_mutes.push((name.clone(), Ovr::Hidden));
                } else if let Ok(m) = serde_json::from_value(body.clone()) {
                    base.anomaly_mutes.push((name.clone(), Ovr::Set(m)));
                }
            }
            EXCLUSIONS => base.exclusions = serde_json::from_value(body.clone()).ok(),
            _ => base.drill = Some(body.clone()),
        }
    }
    base
}

/// Replaces every string equal to `from` in the array at `body[key]` by `to`.
fn rename_in(body: &mut Value, key: &str, from: &str, to: &str) {
    if let Some(Value::Array(items)) = body.get_mut(key) {
        for item in items {
            if item.as_str() == Some(from) {
                *item = Value::String(to.to_owned());
            }
        }
    }
}

/// Replaces the string at `body[key]` by `to` when it is `from`.
fn rename_str(body: &mut Value, key: &str, from: &str, to: &str) {
    if let Some(v) = body.get_mut(key)
        && v.as_str() == Some(from)
    {
        *v = Value::String(to.to_owned());
    }
}

fn names_in<'a>(body: &'a Value, key: &str) -> impl Iterator<Item = &'a str> + use<'a> {
    body.get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// The text of `kind`'s stored name for display in reports.
fn describe(kind: &str) -> &'static str {
    match kind {
        CLIENT => "device",
        _ => "group",
    }
}

/// The files that mention `raw` (a TOML string holds it between quotes), else all of them.
fn files_naming(files: &[PathBuf], raw: &str) -> Vec<String> {
    let shown = |p: &Path| {
        p.file_name().map_or_else(
            || p.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        )
    };
    let hits: Vec<String> = files
        .iter()
        .filter(|p| {
            std::fs::read_to_string(p).is_ok_and(|t| {
                t.contains(raw) || t.contains(&raw.replace('\\', "\\\\").replace('"', "\\\""))
            })
        })
        .map(|p| shown(p))
        .collect();
    if hits.is_empty() {
        files.iter().map(|p| shown(p)).collect()
    } else {
        hits
    }
}

/// The names a configuration file defines that hold entities (REQ: T35.1: reported, never
/// rewritten).
pub(crate) fn file_findings(file: &Config, files: &[PathBuf]) -> Vec<NamesInFile> {
    let mut out = Vec::new();
    let mut add = |kind: &'static str, name: &str| {
        if has_entities(name) {
            out.push(NamesInFile {
                kind: describe(kind).to_owned(),
                name: name.to_owned(),
                files: files_naming(files, name),
            });
        }
    };
    for c in &file.client {
        add(CLIENT, c.name.as_str());
    }
    for g in &file.group {
        add(GROUP, g.name.as_str());
    }
    out
}

/// One repair pass over `state`. `file` is the configuration the files alone give (what the
/// stored entries are validated against), `files` their paths (for the report). Changes nothing
/// when no stored name holds an entity.
#[allow(clippy::too_many_lines)] // one step per kind of entry, then the write
pub(crate) fn repair(
    state: &State,
    file: &Config,
    files: &[PathBuf],
    now: u64,
) -> Result<Report, String> {
    let mut report = Report {
        file_entries: file_findings(file, files),
        ..Report::default()
    };
    // One-off: a database that has had its pass is never decoded again.
    if state.meta_get(MARKER).map_err(|e| e.to_string())?.is_some() {
        return Ok(report);
    }
    let version = state.config_version().map_err(|e| e.to_string())?;
    let mark = |state: &State| {
        state
            .meta_set(MARKER, Some(&version.to_string()))
            .map_err(|e| e.to_string())
    };
    let original = load(state)?;
    if !original
        .keys()
        .any(|(k, n)| matches!(*k, CLIENT | GROUP) && has_entities(n))
    {
        mark(state)?;
        return Ok(report);
    }
    let base = managed::entries(state);
    // A configuration that does not validate to begin with can't judge a repair: nothing is
    // renamed then (a rename could dangle a reference that nothing can check).
    let judged = managed::merge(file, &entries_of(base.clone(), &original)).is_ok();
    let accept =
        |trial: &Rows| judged && managed::merge(file, &entries_of(base.clone(), trial)).is_ok();
    let token_groups: BTreeSet<String> = state
        .agent_token_groups()
        .map_err(|e| e.to_string())?
        .into_iter()
        .collect();
    let file_clients: BTreeSet<&str> = file.client.iter().map(|c| c.name.as_str()).collect();
    let file_groups: BTreeSet<&str> = file.group.iter().map(|g| g.name.as_str()).collect();
    let mut work = original.clone();

    // Groups first: a client's `groups` list follows a renamed group.
    let groups: Vec<String> = work
        .keys()
        .filter(|(k, n)| *k == GROUP && has_entities(n))
        .map(|(_, n)| n.clone())
        .collect();
    for old in groups {
        let new = clean_text(&old);
        let skip = |report: &mut Report, why: &str| {
            report.skipped.push((GROUP, old.clone(), why.to_owned()));
        };
        if work
            .get(&(GROUP, old.clone()))
            .and_then(|b| b.get("hidden"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            continue;
        }
        if file_groups.contains(old.as_str()) {
            skip(&mut report, "a configuration file defines this group");
            continue;
        }
        if new.is_empty() {
            skip(&mut report, "nothing is left of the name");
            continue;
        }
        if work.contains_key(&(GROUP, new.clone())) || file_groups.contains(new.as_str()) {
            skip(&mut report, "a group with the cleaned name exists");
            continue;
        }
        let mut trial = work.clone();
        let Some(mut body) = trial.remove(&(GROUP, old.clone())) else {
            continue;
        };
        body["name"] = Value::String(new.clone());
        trial.insert((GROUP, new.clone()), body);
        for ((kind, _), b) in &mut trial {
            match *kind {
                CLIENT | RULE | ZONE | ANOMALY_MUTE => rename_in(b, "groups", &old, &new),
                FORWARD => rename_in(b, "match_group", &old, &new),
                KUBERNETES_MAP | DRILL => rename_str(b, "group", &old, &new),
                _ => {}
            }
        }
        // A file's entry that still names the group by its old name would dangle.
        let named_by_file = file
            .client
            .iter()
            .any(|c| c.groups.iter().any(|g| g.as_str() == old))
            || file
                .rule
                .iter()
                .any(|r| r.groups.iter().any(|g| g.as_str() == old))
            || file
                .zone
                .iter()
                .any(|z| z.groups.iter().any(|g| g.as_str() == old))
            || file
                .anomaly_mute
                .iter()
                .any(|m| m.groups.iter().any(|g| g.as_str() == old))
            || file.kubernetes.map.iter().any(|r| r.group.as_str() == old)
            || file.drill.group.as_ref().is_some_and(|g| g.as_str() == old);
        if named_by_file {
            skip(&mut report, "a configuration file names this group");
            continue;
        }
        if token_groups.contains(&old) {
            skip(&mut report, "an agent token is limited to this group");
            continue;
        }
        if !accept(&trial) {
            skip(&mut report, "the configuration would not validate");
            continue;
        }
        work = trial;
        report.renamed.push(Renamed {
            kind: GROUP,
            from: old,
            to: new,
        });
    }

    // Devices: the row's name and the body's, and the rules that name the device.
    let clients: Vec<String> = work
        .keys()
        .filter(|(k, n)| *k == CLIENT && has_entities(n))
        .map(|(_, n)| n.clone())
        .collect();
    for old in clients {
        let skip = |report: &mut Report, why: &str| {
            report.skipped.push((CLIENT, old.clone(), why.to_owned()));
        };
        if file_clients.contains(old.as_str()) {
            skip(&mut report, "a configuration file defines this device");
            continue;
        }
        let new = clean_text(&old);
        if new.is_empty() {
            skip(&mut report, "nothing is left of the name");
            continue;
        }
        if file
            .rule
            .iter()
            .any(|r| r.devices.iter().any(|d| d.as_str() == old))
            || file
                .anomaly_mute
                .iter()
                .any(|m| m.devices.iter().any(|d| d.as_str() == old))
            || file
                .exclusions
                .log
                .clients
                .iter()
                .any(|d| d.as_str() == old)
            || file.drill.clients.iter().any(|d| d.as_str() == old)
        {
            skip(&mut report, "a configuration file names this device");
            continue;
        }
        let first_key = work
            .get(&(CLIENT, old.clone()))
            .and_then(|b| names_in(b, "match").next().map(str::to_owned))
            .unwrap_or_default();
        let taken = |n: &str, work: &Rows| {
            work.keys()
                .any(|(k, name)| *k == CLIENT && name.eq_ignore_ascii_case(n) && *name != old)
                || file_clients.iter().any(|c| c.eq_ignore_ascii_case(n))
        };
        let mut new = new;
        if taken(&new, &work) {
            // REQ: API-007 (A6) — told apart by the device's own tail, then by a number.
            let tail = tail(&first_key);
            let base_name = if tail.is_empty() {
                new.clone()
            } else {
                format!("{new} ({tail})")
            };
            new.clone_from(&base_name);
            let mut i = 2;
            while taken(&new, &work) {
                new = format!("{base_name} ({i})");
                i += 1;
            }
        }
        let mut trial = work.clone();
        let Some(mut body) = trial.remove(&(CLIENT, old.clone())) else {
            continue;
        };
        body["name"] = Value::String(new.clone());
        trial.insert((CLIENT, new.clone()), body);
        for ((kind, _), b) in &mut trial {
            match *kind {
                RULE | ANOMALY_MUTE => rename_in(b, "devices", &old, &new),
                DRILL => rename_in(b, "clients", &old, &new),
                EXCLUSIONS => {
                    if let Some(log) = b.get_mut("log") {
                        rename_in(log, "clients", &old, &new);
                    }
                }
                _ => {}
            }
        }
        if !accept(&trial) {
            skip(&mut report, "the configuration would not validate");
            continue;
        }
        work = trial;
        report.renamed.push(Renamed {
            kind: CLIENT,
            from: old,
            to: new,
        });
    }

    if report.renamed.is_empty() {
        mark(state)?;
        return Ok(report);
    }
    // The write: what is new or changed, and what is gone, in one transaction.
    let puts: Vec<(&str, String, String)> = work
        .iter()
        .filter(|(k, v)| original.get(*k) != Some(*v))
        .map(|((kind, name), body)| (*kind, name.clone(), body.to_string()))
        .collect();
    let removes: Vec<(&str, String)> = original
        .keys()
        .filter(|k| !work.contains_key(*k))
        .map(|(kind, name)| (*kind, name.clone()))
        .collect();
    let put_refs: Vec<(&str, &str, &str)> = puts
        .iter()
        .map(|(k, n, b)| (*k, n.as_str(), b.as_str()))
        .collect();
    let remove_refs: Vec<(&str, &str)> = removes.iter().map(|(k, n)| (*k, n.as_str())).collect();
    let next = state
        .put_and_remove_managed(
            &put_refs,
            &remove_refs,
            Some(version),
            now,
            ACTOR,
            Some((MARKER, &(version + 1).to_string())),
        )
        .map_err(|e| e.to_string())?;
    report.version = Some(next);
    audit(state, &report, now);
    Ok(report)
}

/// The one audit entry of a repair: a system change that lists what was renamed.
fn audit(state: &State, report: &Report, now: u64) {
    let detail = serde_json::json!({
        "renamed": report.renamed.iter().map(|r| serde_json::json!({
            "kind": r.kind, "from": r.from, "to": r.to,
        })).collect::<Vec<_>>(),
        "configVersion": report.version,
        "reason": "names stored with HTML entities were decoded once (ADR-1032)",
    })
    .to_string();
    let who = wrendns_api::auth::Actor::system(ACTOR);
    if let Err(e) = state.audit_append(&NewAudit {
        ts: now,
        actor: &who.name,
        actor_kind: who.kind,
        remote: None,
        action: ACTION,
        target: "names",
        detail: &detail,
        reason: None,
    }) {
        warn!("the names repair's audit entry could not be written: {e}");
    }
}

/// The files' names that hold entities, as the last pass found them (the health note).
static FILE_ENTRIES: Mutex<Vec<NamesInFile>> = Mutex::new(Vec::new());

fn set_file_entries(v: Vec<NamesInFile>) {
    *FILE_ENTRIES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = v;
}

/// REQ: T35.1 — the health note for names a configuration file defines with entities in them:
/// degraded (never severe), naming the file. DNS is unaffected.
pub(crate) fn health_reasons() -> Vec<wrendns_api::model::HealthReason> {
    let held = FILE_ENTRIES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if held.is_empty() {
        return Vec::new();
    }
    let list = held
        .iter()
        .take(3)
        .map(|f| format!("{} `{}` in {}", f.kind, f.name, f.files.join(", ")))
        .collect::<Vec<_>>()
        .join("; ");
    let more = held.len().saturating_sub(3);
    vec![wrendns_api::model::HealthReason {
        level: "degraded".to_owned(),
        code: "names_in_files".to_owned(),
        summary: format!(
            "{} name(s) in a configuration file hold HTML codes: {list}{}. WrenDNS never rewrites a file; change the name there. DNS is unaffected",
            held.len(),
            if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            }
        ),
        node: None,
        link: Some("#/clients".to_owned()),
    }]
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One pass on this node, if it may write: the repair, then a reload so the node serves the
/// names it stored (the primary publishes the new version to the replicas as for any write).
pub(crate) async fn run_once(src: &Arc<crate::http::Sources>) {
    let Some(auth) = src.auth.get() else { return };
    // The health note covers every node, a replica too (it reads the same files).
    set_file_entries(file_findings(
        &crate::api_backend::plan_files(src),
        &src.config_files,
    ));
    let backend = crate::api_backend::ApiBackend {
        src: Arc::clone(src),
    };
    // A replica, a GitOps cluster, a pinned one: nothing to write here.
    if backend.replica_read_only().is_some()
        || crate::rollout::surface::pinned_problem(src).is_some()
        || src.cluster.as_ref().is_some_and(|c| !c.is_primary())
    {
        return;
    }
    let one_at_a_time = src.config_writes.lock().await;
    let state = Arc::clone(auth.state());
    if crate::api_backend::refuse_unadopted(src, &state).is_err() {
        return;
    }
    let file = crate::api_backend::plan_files(src);
    let files = src.config_files.clone();
    let result = tokio::task::spawn_blocking(move || repair(&state, &file, &files, now_secs()))
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
    match result {
        Ok(report) => {
            set_file_entries(report.file_entries.clone());
            for (kind, name, why) in &report.skipped {
                warn!(
                    kind,
                    name, why, "a stored name with HTML codes was left as it is"
                );
            }
            if let Some(version) = report.version {
                crate::api_backend::provenance(ACTOR, version);
                let (tx, rx) = tokio::sync::oneshot::channel();
                let applied = src.reload.send(tx).await.is_ok() && rx.await.unwrap_or(false);
                info!(
                    renamed = report.renamed.len(),
                    version, applied, "stored names with HTML codes were decoded"
                );
            }
        }
        Err(e) => warn!("the names repair did not run: {e}"),
    }
    drop(one_at_a_time);
}

/// REQ: T35.1 — the repair task: a pass shortly after start, then every minute (a node promoted
/// to primary runs it at once; a pass that finds nothing writes nothing).
pub(crate) fn spawn(src: Arc<crate::http::Sources>, mut stop: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut wait = std::time::Duration::from_secs(15);
        loop {
            tokio::select! {
                _ = stop.changed() => return,
                () = tokio::time::sleep(wait) => {}
            }
            run_once(&src).await;
            wait = std::time::Duration::from_secs(60);
        }
    });
}

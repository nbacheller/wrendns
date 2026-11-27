// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: OBS-007, API-905 (T40.13, ADR-1107 point 4) - the ordinary write of the dnstap settings.
//!
//! The settings are node-local: every dnstap value is one node's own entry (the `dnstap-output` row of
//! the guarded store, keyed by the node), and there is no cluster-wide value. A write is for exactly
//! one node: the replica it was forwarded from (by its certificate), else this one. It is judged on
//! that node's own view - its files and what it will run after its next start - which the replica
//! sends with the write, as the primary cannot see its files. A change that copies more of the
//! clients' queries goes through the guarded flow (preview, typed phrase, `settings.guarded`); one that
//! copies no more is stored here, as that node's entry, and takes effect after that node restarts.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use wrendns_api::problem::{Code, Problem};
use wrendns_api::{ManagedKind, ManagedWrite};
use wrendns_config::guarded::{DNSTAP, dnstap_widened};
use wrendns_store::state::State;

use crate::api_backend::ManagedPlan;
use crate::guarded::store::{EntryState, Stored};
use crate::http::Sources;
use crate::settings_kinds;

const KIND: ManagedKind = ManagedKind::TelemetryDnstap;

/// A node's own view of its dnstap settings: the section its files give, the fields they set, and the
/// section it will run after its next start (the files, then its reviewed entry in whatever state).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct View {
    pub(crate) file: Value,
    pub(crate) file_set: Vec<String>,
    pub(crate) pending: Value,
}

/// The dnstap fields a configuration's files set.
fn file_set_of(files: &wrendns_config::Config) -> Vec<String> {
    settings_kinds::keys(KIND)
        .iter()
        .filter(|k| {
            files
                .file_set
                .iter()
                .any(|f| f == &format!("telemetry.dnstap.{k}"))
        })
        .map(|k| (*k).to_owned())
        .collect()
}

/// This node's view (what a replica sends with a forwarded write, and what its card shows) and
/// whether it has an entry of its own.
pub(crate) fn own_view(src: &Sources, state: &State) -> (View, bool) {
    let files = src.file_config.load_full();
    let mut cfg = (*files).clone();
    let mut has_entry = false;
    if let Some(me) = crate::guarded::this_node() {
        let live = src.config.load();
        // A staged entry is read at the next start, so it is what the node will run: it counts here.
        let mine: Vec<Stored> = crate::guarded::store::effective(&live, state, &me)
            .into_iter()
            .map(|(mut e, _)| {
                e.state = EntryState::Active;
                e
            })
            .filter(|e| e.id == DNSTAP && e.node == me)
            .collect();
        has_entry = !mine.is_empty();
        crate::guarded::appliers::overlay(&mut cfg, &files, &mine, Some(state));
    }
    let view = View {
        file: settings_kinds::section_json(KIND, &files),
        file_set: file_set_of(&files),
        pending: settings_kinds::section_json(KIND, &cfg),
    };
    (view, has_entry)
}

/// An entry's value as a section: a field left out takes its default.
fn normal(v: &Value) -> Option<Value> {
    crate::guarded::dnstap::parse(v)
        .ok()
        .and_then(|d| serde_json::to_value(d).ok())
}

/// The value an entry stores: the whole section, a reader that is not there left out (as a guarded
/// value is laid out).
fn entry_value(after: &Value) -> Value {
    let mut v = after.clone();
    if let Some(o) = v.as_object_mut() {
        o.retain(|k, x| !(matches!(k.as_str(), "socket" | "address") && x.is_null()));
    }
    v
}

fn guarded_only(deleting: bool) -> Problem {
    let how = if deleting {
        "this brings back values in the config file that copy more of the clients' queries (their addresses and names) out of the process than this node will run"
    } else {
        "this copies more of the clients' queries (their addresses and names) out of the process than this node will run (the tap on, another socket or address, upstream or recursor exchanges added, or sampling more often)"
    };
    Problem::new(
        Code::GuardedOnly,
        format!(
            "{how}, so it is changed from the guarded review: a preview, the phrase you type and a sign-in from the last 10 minutes"
        ),
    )
    .hint("Use Settings, System, dnstap output in the web UI, or POST /api/v1/guarded/dnstap-output/preview, then POST /api/v1/guarded/dnstap-output with the previewId and the phrase.")
}

/// The write of the node's entry the change needs: none when the files say as much as the section
/// does, else the whole section; nothing when the entry already holds it.
fn entry_change(
    w: &ManagedWrite,
    node: &str,
    after: &Value,
    file_section: &Value,
    existing: Option<&Stored>,
) -> crate::api_backend::AlsoStored {
    let wanted = (after != file_section).then(|| entry_value(after));
    let have = existing.map(|e| normal(&e.value));
    match (&wanted, &have) {
        (None, None) => Vec::new(),
        (Some(a), Some(h)) if normal(a) == *h => Vec::new(),
        _ => {
            let name = crate::guarded::entry_name(node, DNSTAP);
            let body = wanted.map(|value| {
                let entry = Stored {
                    node: node.to_owned(),
                    id: DNSTAP.to_owned(),
                    value,
                    mode: "staged".to_owned(),
                    state: EntryState::Staged,
                    by: w.by.clone(),
                    at: crate::guarded::now_secs(),
                };
                serde_json::to_string(&entry).unwrap_or_default()
            });
            vec![(crate::guarded::KIND, name, body)]
        }
    }
}

/// The plan of one dnstap write: judged on the node it is for, stored as that node's entry.
pub(crate) fn plan(src: &Sources, state: &State, w: &ManagedWrite) -> Result<ManagedPlan, Problem> {
    let noun = settings_kinds::noun(KIND);
    if w.name.trim() != "default" {
        return Err(Problem::not_found(format!(
            "there is one {noun}, named `default`"
        )));
    }
    crate::api_backend::settings_feature_gate(src, w)?;
    let node = w
        .origin
        .clone()
        .or_else(crate::guarded::this_node)
        .ok_or_else(|| Problem::unavailable("this node's name isn't known yet"))?;
    // The node's own view: a replica sends it (it is the node's own word about its own files).
    let view = match (&w.origin, &w.node_view) {
        (None, _) => own_view(src, state).0,
        (Some(_), Some(v)) => serde_json::from_value::<View>(v.clone()).map_err(|e| {
            Problem::invalid(format!(
                "the node's own dnstap settings are unreadable: {e}"
            ))
        })?,
        (Some(_), None) => {
            return Err(Problem::new(
                Code::UpgradeRequired,
                "this node did not send its own dnstap settings, which the change is judged against",
            )
            .hint("Upgrade that node first, or make the change on the primary for the primary's own settings."));
        }
    };
    // The files as that node has them: the dnstap fields and the marks of the fields they set.
    let mut file_n = (*crate::api_backend::plan_files(src)).clone();
    file_n.telemetry.dnstap = crate::guarded::dnstap::parse(&view.file)?;
    file_n
        .file_set
        .retain(|f| !f.starts_with("telemetry.dnstap."));
    file_n.file_set.extend(
        view.file_set
            .iter()
            .map(|k| format!("telemetry.dnstap.{k}")),
    );
    let file_section = settings_kinds::section_json(KIND, &file_n);
    let existing = crate::guarded::store::all(state)
        .into_iter()
        .find(|e| e.id == DNSTAP && e.node == node);
    let stored = if let Some(v) = &w.body {
        Some(settings_kinds::prepare(KIND, v, &file_section, &file_n)?)
    } else {
        if existing.is_none() {
            return Err(Problem::not_found(format!(
                "the {noun} of {node} weren't changed through the API or UI: the config file's are in effect"
            )));
        }
        None
    };
    let mut merged = file_n.clone();
    if let Some(s) = &stored {
        settings_kinds::overlay(&mut merged, &file_n, KIND, s)
            .map_err(|why| Problem::new(Code::InvalidConfig, why))?;
    }
    let mut warnings = match wrendns_config::validate_config(&merged) {
        Ok(w) => w,
        Err(errs) => {
            return Err(Problem::new(
                Code::InvalidConfig,
                errs.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            ));
        }
    };
    let before = view.pending;
    let after = settings_kinds::section_json(KIND, &merged);
    settings_kinds::check_admin_fields(KIND, &before, &after, w.role, w.agent.as_deref())?;
    // What the node will run copies more than it will run now: the review's, never an ordinary write
    // (the way back to the files is no way round it).
    if dnstap_widened(&before, &after) {
        return Err(guarded_only(w.body.is_none()));
    }
    if before != after {
        warnings.push(format!(
            "The dnstap settings are read when a node starts: this takes effect on {node} after a restart of that node (restart needed). Other nodes keep their own."
        ));
    }
    let also = entry_change(w, &node, &after, &file_section, existing.as_ref());
    let (recent_queries, impact) =
        crate::api_backend::managed_impact(src, KIND, "default", w.body.is_some());
    Ok(ManagedPlan {
        name: "default".to_owned(),
        before: Some(before),
        after: Some(after),
        body: None,
        recent_queries,
        impact,
        warnings,
        also,
        candidate: merged,
        redirect: None,
        node: Some(node),
    })
}

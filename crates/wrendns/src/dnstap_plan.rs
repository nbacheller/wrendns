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
    /// The time (`at`) of the replicated entry this node set aside after failed starts, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) set_aside_at: Option<u64>,
}

/// What a replica sends with a write it forwards: its files, and what it will run after its next
/// start. What the node will run is worked out by the primary from its own entry of that node too (a
/// replica's copy of the store can lag); a change is refused as a widening if it widens against
/// either, and the entry is kept as confirmed only if the replica says it is in force.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SentView {
    pub(crate) file: Value,
    pub(crate) file_set: Vec<String>,
    /// Absent from a sender that does not send it.
    #[serde(default)]
    pub(crate) pending: Option<Value>,
    /// The time of the entry the node set aside (two failed starts): the primary then judges that
    /// entry as what the node does not run, so the files alone are "before".
    #[serde(default)]
    pub(crate) set_aside_at: Option<u64>,
}

impl View {
    /// The part a replica sends.
    pub(crate) fn sent(&self) -> SentView {
        SentView {
            file: self.file.clone(),
            file_set: self.file_set.clone(),
            pending: Some(self.pending.clone()),
            set_aside_at: self.set_aside_at,
        }
    }
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
    let (cfg, has_entry) = pending_of(src, state, &files);
    let view = View {
        file: settings_kinds::section_json(KIND, &files),
        file_set: file_set_of(&files),
        pending: settings_kinds::section_json(KIND, &cfg),
        set_aside_at: set_aside_at(src, state),
    };
    (view, has_entry)
}

/// The time of this node's replicated dnstap entry that it set aside (a local suppression the
/// primary's copy has not changed since), for the primary to judge writes without it.
fn set_aside_at(src: &Sources, state: &State) -> Option<u64> {
    let me = crate::guarded::this_node()?;
    let live = src.config.load();
    let held = crate::guarded::store::suppressed(state)
        .get(DNSTAP)
        .cloned()?;
    crate::guarded::store::effective(&live, state, &me)
        .into_iter()
        .map(|(e, _)| e)
        .find(|e| e.id == DNSTAP && e.node == me && e.digest() == held)
        .map(|e| e.at)
}

/// What this node will run after its next start (its files and its own entry of the guarded store,
/// a staged one included): what the guarded review judges against.
pub(crate) fn pending_config(src: &Sources, state: &State) -> wrendns_config::Config {
    pending_of(src, state, &src.file_config.load_full()).0
}

fn pending_of(
    src: &Sources,
    state: &State,
    files: &wrendns_config::Config,
) -> (wrendns_config::Config, bool) {
    let mut cfg = files.clone();
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
        crate::guarded::appliers::overlay(&mut cfg, files, &mine, Some(state));
    }
    (cfg, has_entry)
}

/// An entry's value as a section: a field left out takes its default.
fn normal(v: &Value) -> Option<Value> {
    crate::guarded::dnstap::parse(v)
        .ok()
        .and_then(|d| serde_json::to_value(d).ok())
}

/// The reader of a section: its socket and address, when set.
fn reader(v: &Value) -> Vec<String> {
    ["socket", "address"]
        .iter()
        .filter_map(|k| v.get(*k).and_then(Value::as_str).filter(|t| !t.is_empty()))
        .map(str::to_owned)
        .collect()
}

/// The value an entry stores, and the mode it is stored under. An ordinary write (no phrase) changes
/// only what narrows: its entry is marked `narrowed` and carries no reader, a socket or address the
/// files supplied or a reviewed entry holds being no part of what the admin set (so the files
/// dropping the tap later leaves the node with none, and the entry is applied only while it copies
/// no more than the files). The reviewed entry an admin narrows keeps its confirmed mode while the
/// reader is still the one confirmed on this node and that node runs the entry (`in_force`); what it
/// stores is then clamped to what was confirmed (the feeds only if confirmed, sampling no more often),
/// as the files' values in `after` were never confirmed with the phrase.
fn entry_value(
    after: &Value,
    existing: Option<&Stored>,
    in_force: bool,
    file_n: &wrendns_config::Config,
) -> (Value, &'static str) {
    let confirmed = existing.filter(|e| e.mode != crate::guarded::dnstap::NARROWED);
    let by_file = crate::guarded::dnstap::file_fields(file_n);
    // A reader the files set is not the admin's to change: the confirmed one is kept as it is.
    let file_reader = by_file.contains(&"socket");
    let keeps_confirmed = in_force
        && confirmed.is_some_and(|e| {
            !reader(&e.value).is_empty() && (file_reader || reader(&e.value) == reader(after))
        });
    let mut v = after.clone();
    if keeps_confirmed && let Some(c) = confirmed.and_then(|e| normal(&e.value)) {
        let on = |x: &Value, k: &str| x.get(k).and_then(Value::as_bool) == Some(true);
        let every = |x: &Value| x.get("sample_every").and_then(Value::as_u64).unwrap_or(1);
        if let Some(o) = v.as_object_mut() {
            for k in ["forwarder", "resolver"] {
                o.insert(k.to_owned(), Value::Bool(on(after, k) && on(&c, k)));
            }
            o.insert(
                "sample_every".to_owned(),
                Value::from(every(after).max(every(&c))),
            );
            // Every field the files set holds the file's value in `after`, which the admin never
            // sent: the confirmed one stays, for the day the file lets go of it.
            for k in &by_file {
                match c.get(*k) {
                    Some(x) => o.insert((*k).to_owned(), x.clone()),
                    None => o.remove(*k),
                };
            }
        }
    }
    if let Some(o) = v.as_object_mut() {
        o.retain(|k, x| {
            !(matches!(k.as_str(), "socket" | "address") && (x.is_null() || !keeps_confirmed))
        });
    }
    let mode = if keeps_confirmed {
        "staged"
    } else {
        crate::guarded::dnstap::NARROWED
    };
    (v, mode)
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

/// Whether the node runs the entry the primary holds for it: the reader it confirmed, and the entry
/// itself, not a section its files displace through a feed or a sampling (`not_applied`).
fn in_force(sent: &SentView, existing: Option<&Stored>, file_n: &wrendns_config::Config) -> bool {
    match (&sent.pending, existing) {
        (Some(p), Some(e)) if p.is_object() => {
            (crate::guarded::dnstap::file_fields(file_n).contains(&"socket")
                || reader(p) == reader(&e.value))
                && (e.mode == crate::guarded::dnstap::NARROWED
                    || !crate::guarded::dnstap::not_applied(file_n, &e.mode, &e.value))
        }
        _ => true,
    }
}

/// Whether the node runs something else than `after` (it set the entry aside): the write is then
/// stored again, with a new time, so that the node stops ignoring it.
fn node_differs(sent: &SentView, after: &Value) -> bool {
    sent.pending
        .as_ref()
        .is_some_and(|p| p.is_object() && p != after)
}

/// The write of the node's entry the change needs: none when the files say as much as the section
/// does, else the whole section; nothing when the entry already holds it.
fn entry_change(
    w: &ManagedWrite,
    file_n: &wrendns_config::Config,
    node: &str,
    after: &Value,
    file_section: &Value,
    existing: Option<&Stored>,
    (in_force, node_differs): (bool, bool),
) -> crate::api_backend::AlsoStored {
    // A confirmed entry the result still keeps (the tap stays on its confirmed reader) is stored
    // narrowed, even when the result equals the files: it holds the reader for the day the files drop it.
    let keeps = |v: &(Value, &'static str)| {
        w.body.is_some()
            && existing.is_some_and(|e| e.mode != crate::guarded::dnstap::NARROWED)
            && !reader(after).is_empty()
            && v.1 != crate::guarded::dnstap::NARROWED
    };
    let value = entry_value(after, existing, in_force, file_n);
    let wanted = (after != file_section || keeps(&value)).then_some(value);
    let have = existing.map(|e| normal(&e.value));
    match (&wanted, &have) {
        (None, None) => Vec::new(),
        (Some((a, _)), Some(h)) if normal(a) == *h && !node_differs => Vec::new(),
        _ => {
            let name = crate::guarded::entry_name(node, DNSTAP);
            let body = wanted.map(|(value, mode)| {
                let entry = Stored {
                    node: node.to_owned(),
                    id: DNSTAP.to_owned(),
                    value,
                    mode: mode.to_owned(),
                    state: EntryState::Staged,
                    by: w.by.clone(),
                    at: crate::guarded::now_secs().max(existing.map_or(0, |e| e.at + 1)),
                };
                serde_json::to_string(&entry).unwrap_or_default()
            });
            vec![(crate::guarded::KIND, name, body)]
        }
    }
}

/// A confirmed entry the file displaces is kept for the file to change back; an ordinary write that
/// would replace it with a narrowed one, or delete it (an unchanged value), would lose it with no
/// word. That is refused: the way to drop it is the explicit DELETE.
fn refuse_discarding(
    node: &str,
    file_n: &wrendns_config::Config,
    after: &Value,
    existing: Option<&Stored>,
    in_force: bool,
) -> Result<(), Problem> {
    let Some(e) = existing.filter(|e| e.mode != crate::guarded::dnstap::NARROWED) else {
        return Ok(());
    };
    // Only a write that turns the tap off ends a confirmed entry; any other one that would drop it
    // loses a value the admin confirmed, whether the file displaces it or only overrides its reader.
    if !crate::guarded::dnstap::not_applied(file_n, &e.mode, &e.value) && reader(after).is_empty() {
        return Ok(());
    }
    let keeps =
        entry_value(after, existing, in_force, file_n).1 != crate::guarded::dnstap::NARROWED;
    if keeps {
        return Ok(());
    }
    let why = if crate::guarded::dnstap::not_applied(file_n, &e.mode, &e.value) {
        "its config file sets a feed or sampling that copies more, or another reader, and displaces it"
    } else {
        "this write would remove the confirmed value"
    };
    Err(Problem::new(
        Code::Conflict,
        format!(
            "{node} holds a confirmed dnstap value that this write would drop ({why}); saving this would discard it, and it would not come back when the file changes"
        ),
    )
    .hint("Remove the saved value first (DELETE /api/v1/dnstap-settings/default, or Remove in the dnstap card), or change the config file."))
}

/// The node's files, as the node says them: a replica sends them (the node's own word about its own
/// files), the primary reads its own.
fn sent_view(src: &Sources, state: &State, w: &ManagedWrite) -> Result<SentView, Problem> {
    Ok(match (&w.origin, &w.node_view) {
        (None, _) => own_view(src, state).0.sent(),
        (Some(_), Some(v)) => serde_json::from_value::<SentView>(v.clone()).map_err(|e| {
            Problem::invalid(format!(
                "the node's own dnstap settings are unreadable: {e}"
            ))
        })?,
        // A change that adds is held until every member announces the feature
        // (`settings_feature_gate`), so a sender that sent nothing with one is a current build that
        // could not read its own settings. A removal is not held: that sender may be an older build.
        (Some(_), None) if w.body.is_some() => {
            return Err(Problem::unavailable(
                "that node's dnstap settings were not sent with the change, so it cannot be judged",
            )
            .hint("Try again from that node in a moment."));
        }
        (Some(_), None) => {
            return Err(Problem::new(
                Code::UpgradeRequired,
                "this node did not send its own dnstap settings, which the change is judged against",
            )
            .hint("Upgrade that node first, or make the change on the primary for the primary's own settings."));
        }
    })
}

/// The files as that node has them: the dnstap fields and the marks of the fields they set.
fn node_files(src: &Sources, sent: &SentView) -> Result<wrendns_config::Config, Problem> {
    let mut file_n = (*crate::api_backend::plan_files(src)).clone();
    file_n.telemetry.dnstap = crate::guarded::dnstap::parse(&sent.file)?;
    file_n
        .file_set
        .retain(|f| !f.starts_with("telemetry.dnstap."));
    file_n.file_set.extend(
        sent.file_set
            .iter()
            .map(|k| format!("telemetry.dnstap.{k}")),
    );
    Ok(file_n)
}

/// What the node will run after its next start: its files and the entry this primary holds for it,
/// but not an entry the node says it set aside (two failed starts): that one is not run.
fn pending_for(
    sent: &SentView,
    file_n: &wrendns_config::Config,
    existing: Option<&Stored>,
    node: &str,
) -> wrendns_config::Config {
    let mut cfg = file_n.clone();
    let aside = sent
        .set_aside_at
        .is_some_and(|a| existing.is_some_and(|e| e.at == a));
    if let Some(e) = existing.filter(|_| !aside) {
        let mut e = e.clone();
        e.state = EntryState::Active;
        crate::guarded::appliers::overlay_for(&mut cfg, file_n, &[e], node);
    }
    cfg
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
    let sent = sent_view(src, state, w)?;
    let file_n = node_files(src, &sent)?;
    let file_section = settings_kinds::section_json(KIND, &file_n);
    let existing = crate::guarded::store::all(state)
        .into_iter()
        .find(|e| e.id == DNSTAP && e.node == node);
    // What the node will run after its next start: its files and the entry this primary holds for it
    // (read here, authoritatively), whatever the replica's own copy of the store says.
    let pending_cfg = pending_for(&sent, &file_n, existing.as_ref(), &node);
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
    let before = settings_kinds::section_json(KIND, &pending_cfg);
    let after = settings_kinds::section_json(KIND, &merged);
    settings_kinds::check_admin_fields(KIND, &before, &after, w.role, w.agent.as_deref())?;
    // What the node will run copies more than it will run now: the review's, never an ordinary write
    // (the way back to the files is no way round it).
    // The node's own word of what it will run counts too: an entry it has set aside (two failed starts)
    // is not what it runs, whatever this primary still holds.
    let sent_wider = |p: &Value| p.is_object() && dnstap_widened(p, &after);
    if dnstap_widened(&before, &after) || sent.pending.as_ref().is_some_and(sent_wider) {
        return Err(guarded_only(w.body.is_none()));
    }
    if before != after {
        warnings.push(format!(
            "The dnstap settings are read when a node starts: this takes effect on {node} after a restart of that node (restart needed). Other nodes keep their own."
        ));
    }
    let forced = in_force(&sent, existing.as_ref(), &file_n);
    let also = entry_change(
        w,
        &file_n,
        &node,
        &after,
        &file_section,
        existing.as_ref(),
        (forced, node_differs(&sent, &after)),
    );
    if w.body.is_some() && !also.is_empty() {
        refuse_discarding(&node, &file_n, &after, existing.as_ref(), forced)?;
    }
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

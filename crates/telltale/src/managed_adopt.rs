//! REQ: CLU-015, CLU-004, API-016 (T24.37, ADR-1016) — a promoted primary adopts the entries the
//! cluster last published.
//!
//! The API's entries (upstreams, lists, groups, devices, records, ...) live in `state.db` of the
//! node that took the write. A replica applies the shared configuration, which already has them
//! merged in, and keeps no rows. So a replica promoted to primary served every entry but could
//! see none as its own: an edit or a delete answered 404, and a deleted entry would have come
//! back from the version the node builds on.
//!
//! The primary therefore publishes its rows of the shared kinds whole, in the manifest's
//! `node_managed` blob ([`crate::node_managed::SHARED_KINDS`]). A node promoted from replica
//! **replaces** its own rows with the blob it inherited, once per blob (a marker keeps the hash;
//! it is dropped when the node follows a primary again), and builds on the inherited
//! configuration with those entries taken out ([`strip`]), so what its rows say is what
//! applies and an entry it deletes stays deleted. A blob from a build that does not publish the
//! rows (an older primary) is adopted from what the node serves instead ([`adopt_served`], T24.40,
//! ADR-1019).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use telltale_config::Config;
use telltale_store::state::State;
use tracing::{info, warn};

use crate::managed::{self, Named};
use crate::node_managed::{Entry, SHARED_KINDS, parse_shared};

/// The `meta` key holding the hash of the blob this node adopted the rows of. It is written in
/// the same transaction as the rows, so the rows and the record of them never part.
const SEEDED: &str = "managed-seeded";

/// The `meta` key prefix of the entries a served-version adoption derived (T24.40): after a
/// restart those names are stripped, not whatever the files derive to then.
const ADOPTED_NAMES: &str = "managed-adopted-names";

/// The blob adopted in this process: (state path, hash, entries). A call for the same blob
/// answers from here without reading the blob or the store (the publish loop calls every 500 ms).
/// The lock is held for a whole adoption, so a write plan, a reload and the publish loop never
/// adopt at once, and none sees the rows half replaced.
static ADOPTED: Mutex<Option<(PathBuf, String, Vec<Entry>)>> = Mutex::new(None);

/// Forgets the adoption: this node follows a primary, so its rows (from an earlier time as
/// primary) are stale, and the next promotion adopts the blob it inherits whatever its hash.
pub(crate) fn forget(state_path: &Path) {
    let mut held = ADOPTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *held = None;
    if state_path.exists()
        && let Ok(state) = State::open(state_path)
        && state.meta_get(SEEDED).is_ok_and(|m| m.is_some())
    {
        let _ = state.meta_set(SEEDED, None);
    }
}

/// Forgets the process's memory of an adoption, as a restart does (the tests' restart).
#[cfg(test)]
pub(crate) fn reset_cache() {
    *ADOPTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What [`adopt`] found in the inherited blob.
pub(crate) enum Outcome {
    /// The rows the node's store is now the source of.
    Entries(Vec<Entry>),
    /// The blob is from a build that does not publish the rows (an older primary), REQ: CLU-015
    /// (T24.40, ADR-1019): the served entries are the only record of them.
    NoRows,
    /// The blob can't be read or the store can't be written: nothing was adopted.
    Failed,
}

/// Adopts the shared rows of the inherited blob (`hash`, read with `read`) into this node's
/// `state.db`, once, replacing what it holds. Returns the entries the node's rows now are the
/// source of (to be [`strip`]ped from the configuration it builds on), or `None` when nothing was
/// adopted: a blob without the rows, one that can't be read, or a store that can't be written
/// (the node then keeps building on the inherited configuration as it always did). The check of
/// the record, the replacement and the record are one transaction, under a process-wide lock.
pub(crate) fn adopt(
    state_path: &Path,
    hash: &str,
    read: impl FnOnce() -> Option<Vec<u8>>,
) -> Outcome {
    let mut held = ADOPTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((p, h, entries)) = held.as_ref()
        && p == state_path
        && h == hash
    {
        return Outcome::Entries(entries.clone());
    }
    let Some(bytes) = read() else {
        return Outcome::Failed;
    };
    let entries = match parse_shared(&bytes) {
        Ok(Some(e)) => e,
        Ok(None) => return Outcome::NoRows,
        Err(why) => {
            warn!("the inherited cluster entries can't be adopted: {why}");
            return Outcome::Failed;
        }
    };
    let state = match State::open(state_path) {
        Ok(s) => s,
        Err(e) => {
            warn!("the inherited cluster entries can't be adopted: state.db: {e}");
            return Outcome::Failed;
        }
    };
    let rows: Vec<(String, String, String)> = entries
        .iter()
        .filter_map(|e| {
            Some((
                e.kind.clone(),
                e.name.clone(),
                serde_json::to_string(&e.body).ok()?,
            ))
        })
        .collect();
    let refs: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|(k, n, b)| (k.as_str(), n.as_str(), b.as_str()))
        .collect();
    match state.replace_managed_noted(
        SHARED_KINDS,
        &refs,
        now_secs(),
        "promotion",
        Some((SEEDED, hash)),
    ) {
        Ok(Some(_)) => info!(
            entries = entries.len(),
            "this node was promoted: it adopted the cluster's last published API entries as its own"
        ),
        // Adopted by an earlier run of this node: its rows are the source, keep them.
        Ok(None) => {}
        Err(e) => {
            warn!("the inherited cluster entries can't be adopted: {e}");
            return Outcome::Failed;
        }
    }
    *held = Some((state_path.to_path_buf(), hash.to_owned(), entries.clone()));
    Outcome::Entries(entries)
}

/// REQ: CLU-015, CLU-004 (T24.40, ADR-1019) — a node promoted from replica whose inherited
/// version came from a primary that did not publish its rows (a build before ADR-1016, or a
/// version with no blob) adopts the entries it *serves* that its own files do not define, as its
/// own rows: once (a marker in `state.db`, `served:<key>`, written in the same transaction), in
/// one transaction, recorded with `updated_by` `adopted:<seq>`. A row the node already holds stays
/// as it is, and `node_only` rows are not touched. `served` is the version the node built from
/// (the shared configuration with its blob overlaid), `own` its files. Returns the entries to
/// [`strip`] from `served`: the derived ones and the rows the node holds, or `None` when the
/// store can't be written (the node then refuses writes that would drop served entries).
pub(crate) fn adopt_served(
    state_path: &Path,
    key: &str,
    seq: u64,
    served: &Config,
    own: &Config,
) -> Option<Vec<Entry>> {
    let mut held = ADOPTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((p, h, entries)) = held.as_ref()
        && p == state_path
        && h == key
    {
        return Some(entries.clone());
    }
    let state = match State::open(state_path) {
        Ok(s) => s,
        Err(e) => {
            warn!("the served cluster entries can't be adopted: state.db: {e}");
            return None;
        }
    };
    let marker = format!("served:{key}");
    let record = format!("{ADOPTED_NAMES}:{key}");
    // Adopted before (this process or an earlier one): what was adopted is what the meta says,
    // not what the caller's `served` derives to now (the files may have changed since, and a
    // caller without the real version must not decide it).
    let done = state.meta_get(SEEDED).ok().flatten().as_deref() == Some(marker.as_str());
    let stored: Option<Vec<Entry>> = if done {
        state
            .meta_get(&record)
            .ok()
            .flatten()
            .and_then(|j| serde_json::from_str(&j).ok())
    } else {
        None
    };
    let derived = match stored {
        Some(d) => d,
        None if done => derive(served, own),
        None => {
            let derived = derive(served, own);
            let entries = with_held(&state, derived.clone());
            // REQ: CLU-004 - validate the whole candidate first: a row that would not merge
            // would send the node back to the stripped files and drop every adopted entry.
            if let Err(why) = candidate_merges(&state, served, own, &derived, &entries) {
                warn!("the served cluster entries are not adopted: {why}");
                return None;
            }
            let Ok(json) = serde_json::to_string(&derived) else {
                return None;
            };
            if let Err(e) = state.meta_set(&record, Some(&json)) {
                warn!("the served cluster entries can't be adopted: {e}");
                return None;
            }
            insert_derived(&state, &derived, seq, &marker)?;
            derived
        }
    };
    // What the version no longer provides: the entries it was derived from (so a row deleted
    // since stays deleted, after a restart too) and every row the node holds.
    let entries = with_held(&state, derived);
    *held = Some((state_path.to_path_buf(), key.to_owned(), entries.clone()));
    Some(entries)
}

/// REQ: DNS-010, OBS-016, OBS-020, OBS-019, DNS-011, FLT-004, CLU-014 (T27.5, T27.7, T27.11,
/// T24.40, ADR-1019) — a zone by apex goes back to the files' zone of that name (or goes); the
/// `[dnssec]`, `[filter]`, `[drill]`, `[slo]`, `[probe]` and `[upstream_check]` sections get the
/// fields the API edits back as the files have them (their other fields stay as served).
fn strip_tuning(cfg: &mut Config, e: &Entry, own: &Config) {
    use telltale_api::ManagedKind as K;
    let kind = match e.kind.as_str() {
        managed::ZONE => {
            let apex = zone_key(&e.name);
            cfg.zone.retain(|z| zone_key(z.name.as_str()) != apex);
            if let Some(o) = own.zone.iter().find(|z| zone_key(z.name.as_str()) == apex) {
                cfg.zone.push(o.clone());
            }
            return;
        }
        managed::DNSSEC => K::Dnssec,
        managed::FILTER => K::Filter,
        managed::DRILL => K::Drill,
        managed::SLO => K::Slo,
        managed::PROBE => K::Probe,
        managed::UPSTREAM_CHECK => K::UpstreamCheck,
        _ => return,
    };
    crate::settings_kinds::restore_api_fields(cfg, own, kind);
}

/// A zone's row name: its apex as the API stores it (trimmed, no final dot, lower case).
fn zone_key(apex: &str) -> String {
    apex.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// REQ: CLU-015 (T24.40, ADR-1019) — the shared kinds ([`SHARED_KINDS`]) that [`derive`] adopts
/// from a served version: every one a primary can serve without holding its rows.
pub(crate) const ADOPTED_KINDS: &[&str] = &[
    managed::CLIENT,
    managed::RECORD,
    managed::FORWARD,
    managed::RULE,
    managed::UPSTREAM,
    managed::UPSTREAM_GROUP,
    managed::LIST,
    managed::GROUP,
    managed::ALERT_DESTINATION,
    managed::ALERT_RULE,
    managed::SCHEDULE,
    managed::ANOMALY_MUTE,
    managed::RATELIMIT,
    managed::EXCLUSIONS,
    managed::SIMULATE,
    managed::MAP,
    managed::ROLLOUT,
    managed::KUBERNETES_MAP,
    managed::SPECIAL,
    managed::LOCAL,
    managed::CLIENTS,
    managed::DISCOVERY,
    managed::CMDB,
    managed::ROUTER,
    managed::DNSSEC,
    managed::FILTER,
    managed::DRILL,
    managed::ZONE,
    managed::SLO,
    managed::PROBE,
    managed::UPSTREAM_CHECK,
];

/// REQ: CLU-015 (T24.40, ADR-1019) — the shared kinds that need no adoption from a served version,
/// each with the reason. None today: a kind added to [`SHARED_KINDS`] goes in [`ADOPTED_KINDS`]
/// (with a block in [`derive`] and [`strip`]) or here, or the test
/// `clu_015_t24_40_every_shared_kind_is_adopted_or_exempt` fails.
#[cfg_attr(not(test), allow(dead_code))] // a registry: read by that test
pub(crate) const NOT_ADOPTED: &[(&str, &str)] = &[];

/// Inserts the rows of `derived` the node does not hold, with the marker, in one transaction.
fn insert_derived(state: &State, derived: &[Entry], seq: u64, marker: &str) -> Option<()> {
    let rows: Vec<(String, String, String)> = derived
        .iter()
        .filter_map(|e| {
            Some((
                e.kind.clone(),
                e.name.clone(),
                serde_json::to_string(&e.body).ok()?,
            ))
        })
        .collect();
    let refs: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|(k, n, b)| (k.as_str(), n.as_str(), b.as_str()))
        .collect();
    match state.insert_missing_managed_noted(
        &refs,
        now_secs(),
        &format!("adopted:{seq}"),
        (SEEDED, marker),
    ) {
        Ok(Some(added)) if added.is_empty() => Some(()),
        Ok(Some(added)) => {
            let mut counts: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();
            for k in added {
                *counts.entry(k).or_default() += 1;
            }
            let by_kind = counts
                .iter()
                .map(|(k, n)| format!("{k} {n}"))
                .collect::<Vec<_>>()
                .join(", ");
            info!(
                seq,
                kinds = %by_kind,
                "this node serves entries from a primary that did not hand over its API entries: it adopted them as its own"
            );
            Some(())
        }
        Ok(None) => Some(()),
        Err(e) => {
            warn!("the served cluster entries can't be adopted: {e}");
            None
        }
    }
}

/// `derived` plus every row of the shared kinds the node holds that it does not name.
fn with_held(state: &State, mut entries: Vec<Entry>) -> Vec<Entry> {
    for kind in SHARED_KINDS {
        for m in state.managed(kind).unwrap_or_default() {
            if entries.iter().any(|e| e.kind == *kind && e.name == m.name) {
                continue;
            }
            if let Ok(body) = serde_json::from_str(&m.body) {
                entries.push(Entry {
                    kind: (*kind).to_owned(),
                    name: m.name,
                    body,
                });
            }
        }
    }
    entries
}

/// Whether `served`, stripped of `entries`, merges with the rows the node would hold after
/// adopting `derived`: checked on a scratch store, so nothing is written.
fn candidate_merges(
    state: &State,
    served: &Config,
    own: &Config,
    derived: &[Entry],
    entries: &[Entry],
) -> Result<(), String> {
    let scratch = State::in_memory().map_err(|e| e.to_string())?;
    let mut rows: Vec<(String, String, String)> = Vec::new();
    for kind in SHARED_KINDS {
        for m in state.managed(kind).unwrap_or_default() {
            rows.push(((*kind).to_owned(), m.name, m.body));
        }
    }
    for e in derived {
        if let Ok(b) = serde_json::to_string(&e.body) {
            rows.push((e.kind.clone(), e.name.clone(), b));
        }
    }
    let refs: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|(k, n, b)| (k.as_str(), n.as_str(), b.as_str()))
        .collect();
    scratch
        .insert_missing_managed_noted(&refs, 0, "check", ("check", "1"))
        .map_err(|e| e.to_string())?;
    let mut stripped = served.clone();
    strip(&mut stripped, entries, own);
    managed::merge_on(&stripped, own, &managed::entries(&scratch))
        .map(|_| ())
        .map_err(|errs| errs.join("; "))
}

/// Whether `state` holds a row `kind`/`name`.
pub(crate) fn held(state: &State, kind: &str, name: &str) -> bool {
    state
        .managed(kind)
        .is_ok_and(|rows| rows.iter().any(|m| m.name == name))
}

/// Whether an entry's body holds a credential (inline or by file path), a reference to a stored
/// secret excepted, or a file path a router entry may not carry.
fn holds_secret(kind: &str, body: &serde_json::Value) -> bool {
    let mut probe = body.clone();
    if let Some(o) = probe.as_object_mut() {
        o.retain(|k, _| !(k.ends_with("_ref") || k.ends_with("_refs")));
    }
    if telltale_config::credentials::holds_credential(kind, &probe) {
        return true;
    }
    // REQ: OBS-020 (T27.5; T24.40) - a probe target is a URL: one with a user or password in it
    // (`https://u:p@host/dns-query`) is not copied into a row.
    if kind == managed::PROBE
        && probe
            .get("targets")
            .and_then(|v| v.as_array())
            .is_some_and(|t| t.iter().filter_map(|v| v.as_str()).any(url_has_userinfo))
    {
        return true;
    }
    kind == managed::ROUTER
        && crate::router_settings::FILE_FIELDS.iter().any(|f| {
            probe
                .get(*f)
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty())
        })
}

/// Whether a URL names a user (and so maybe a password) before its host: `scheme://user@host`.
fn url_has_userinfo(url: &str) -> bool {
    url.split_once("://").is_some_and(|(_, rest)| {
        rest.split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| authority.contains('@'))
    })
}

/// The upstream group and upstream name prefix of a forwarded domain (`managed::forward_group`).
const FORWARD_PREFIX: &str = "forward:";

/// REQ: CLU-015 (T24.40, ADR-1019) — the entries `served` (a cluster version) has that `own` (this
/// node's files) does not define, as the rows the API would have stored for them: every kind
/// ADR-1016 publishes ([`ADOPTED_KINDS`]). A name the files define stays a file entry. `node_only`
/// entries are left out (they never travelled), and so are the node-managed kinds (`cache`,
/// `support`, `updates`, the telemetry settings: never in the shared version) and anything holding
/// a credential. Forwarded domains are rebuilt from their route, group and upstreams; a singleton
/// section is adopted only when the served one differs from the files' in a field the API edits.
#[allow(clippy::too_many_lines)] // one block per kind of entry
pub(crate) fn derive(served: &Config, own: &Config) -> Vec<Entry> {
    use serde::Serialize;
    use serde_json::Value;
    fn push(out: &mut Vec<Entry>, kind: &str, name: &str, body: Value) {
        if body.get("node_only") == Some(&Value::Bool(true)) {
            return;
        }
        // REQ: API-014, API-016 (ADR-921) - a credential, or a path to one, that the old
        // primary's files set is not copied into a row: the entry stays in the version the node
        // builds on.
        if holds_secret(kind, &body) {
            warn!(
                kind,
                name,
                "this served entry holds a credential or a path to one: it stays in the cluster version and is not adopted as an API entry"
            );
            return;
        }
        out.push(Entry {
            kind: kind.to_owned(),
            name: name.to_owned(),
            body,
        });
    }
    fn named<T: Named + Serialize>(
        out: &mut Vec<Entry>,
        kind: &str,
        served: &[T],
        own: &[T],
        generated: bool,
    ) {
        for i in served {
            if own.iter().any(|o| o.name() == i.name()) {
                continue;
            }
            if generated && i.name().starts_with(FORWARD_PREFIX) {
                continue;
            }
            if let Ok(b) = serde_json::to_value(i) {
                push(out, kind, i.name(), b);
            }
        }
    }
    let mut out = Vec::new();
    named(
        &mut out,
        managed::UPSTREAM,
        &served.upstream,
        &own.upstream,
        true,
    );
    named(
        &mut out,
        managed::UPSTREAM_GROUP,
        &served.upstream_group,
        &own.upstream_group,
        true,
    );
    named(&mut out, managed::LIST, &served.list, &own.list, false);
    named(&mut out, managed::GROUP, &served.group, &own.group, false);
    named(
        &mut out,
        managed::ALERT_DESTINATION,
        &served.alerts.destination,
        &own.alerts.destination,
        false,
    );
    named(
        &mut out,
        managed::ALERT_RULE,
        &served.alerts.rule,
        &own.alerts.rule,
        false,
    );
    named(
        &mut out,
        managed::SCHEDULE,
        &served.schedule,
        &own.schedule,
        false,
    );
    named(
        &mut out,
        managed::ANOMALY_MUTE,
        &served.anomaly_mute,
        &own.anomaly_mute,
        false,
    );
    named(
        &mut out,
        managed::ROUTER,
        &served.router,
        &own.router,
        false,
    );
    for r in &served.kubernetes.map {
        if own.kubernetes.map.iter().any(|o| o.key() == r.key()) {
            continue;
        }
        if let Ok(b) = serde_json::to_value(r) {
            push(&mut out, managed::KUBERNETES_MAP, &r.key(), b);
        }
    }
    for c in &served.client {
        if own.client.iter().any(|o| o.name == c.name) {
            continue;
        }
        if let Ok(b) = serde_json::to_value(c) {
            push(&mut out, managed::CLIENT, c.name.as_str(), b);
        }
    }
    for r in &served.rule {
        if own.rule.iter().any(|o| o.id == r.id) {
            continue;
        }
        if let Ok(b) = serde_json::to_value(r) {
            push(&mut out, managed::RULE, r.id.as_str(), b);
        }
    }
    // Local names: one row per name, its records together.
    let key = |n: &str| n.trim_end_matches('.').to_ascii_lowercase();
    let mut names: Vec<String> = Vec::new();
    for r in &served.record {
        let n = key(r.name.as_str());
        if r.node_only
            || own
                .record
                .iter()
                .any(|o| o.name.eq_ignore_ascii_case(r.name.as_str()))
            || names.contains(&n)
        {
            continue;
        }
        names.push(n);
    }
    for n in names {
        let vals: Vec<managed::RecordValue> = served
            .record
            .iter()
            .filter(|r| key(r.name.as_str()) == n && !r.node_only)
            .map(|r| managed::RecordValue {
                rtype: r.rtype.to_string(),
                value: r.value.to_string(),
                ttl: r.ttl,
                node_only: false,
            })
            .collect();
        if let Ok(b) = serde_json::to_value(vals) {
            push(&mut out, managed::RECORD, &n, b);
        }
    }
    // Forwarded domains: a route to `forward:<domain>`, whose members are the servers.
    for r in &served.route {
        let Some(domain) = r.upstream_group.as_str().strip_prefix(FORWARD_PREFIX) else {
            continue;
        };
        if own.route.iter().any(|o| {
            o.match_suffix
                .iter()
                .any(|s| s.eq_ignore_ascii_case(domain))
        }) {
            continue;
        }
        let Some(g) = served
            .upstream_group
            .iter()
            .find(|g| g.name == r.upstream_group)
        else {
            continue;
        };
        let mut servers = Vec::new();
        let mut stub = false;
        for m in &g.members {
            let Some(u) = served.upstream.iter().find(|u| u.name == *m) else {
                continue;
            };
            if u.recursive.stub_zone.is_some() {
                stub = true;
                servers.extend(u.recursive.stub_servers.iter().map(ToString::to_string));
            } else {
                servers.push(u.url.to_string());
            }
        }
        if servers.is_empty() {
            continue;
        }
        // REQ: DNS-010, CLU-006 (T27.7) - the route's group and query-type limits and its DNSSEC
        // negative trust anchor travel with it; a node-only route never left its node.
        if r.node_only {
            continue;
        }
        let f = managed::Forward {
            servers,
            stub,
            match_group: r.match_group.iter().map(ToString::to_string).collect(),
            match_qtype: r.match_qtype.iter().map(ToString::to_string).collect(),
            dnssec_nta: r.dnssec_nta,
            node_only: false,
        };
        if let Ok(b) = serde_json::to_value(f) {
            push(&mut out, managed::FORWARD, domain, b);
        }
    }
    // REQ: DNS-010 (T27.7) — zones by apex. A zone read from a zone file (`file`) is the old
    // primary's files': it stays in the version the node builds on, as the API never stores one.
    for z in &served.zone {
        let apex = zone_key(z.name.as_str());
        if z.file.is_some() || own.zone.iter().any(|o| zone_key(o.name.as_str()) == apex) {
            continue;
        }
        if let Ok(b) = serde_json::to_value(z) {
            push(&mut out, managed::ZONE, &apex, b);
        }
    }
    // Sections the API replaces whole.
    macro_rules! whole {
        ($kind:expr, $a:expr, $b:expr) => {
            if $a != $b
                && let Ok(b) = serde_json::to_value(&$a)
            {
                push(&mut out, $kind, "default", b);
            }
        };
    }
    whole!(managed::RATELIMIT, served.ratelimit, own.ratelimit);
    whole!(managed::EXCLUSIONS, served.exclusions, own.exclusions);
    whole!(managed::SIMULATE, served.simulate, own.simulate);
    whole!(managed::MAP, served.map, own.map);
    whole!(
        managed::ROLLOUT,
        served.cluster.rollout,
        own.cluster.rollout
    );
    for (kind, k) in [
        (managed::SPECIAL, telltale_api::ManagedKind::Special),
        (managed::LOCAL, telltale_api::ManagedKind::Local),
        (managed::CLIENTS, telltale_api::ManagedKind::Clients),
        (managed::DISCOVERY, telltale_api::ManagedKind::Discovery),
        (managed::CMDB, telltale_api::ManagedKind::Cmdb),
        // REQ: DNS-011, FLT-004, CLU-014, OBS-016, OBS-020, OBS-019 (T27.11, T27.5) — the shared
        // tuning sections, by the fields the API edits (a field only the files set stays served).
        (managed::DNSSEC, telltale_api::ManagedKind::Dnssec),
        (managed::FILTER, telltale_api::ManagedKind::Filter),
        (managed::DRILL, telltale_api::ManagedKind::Drill),
        (managed::SLO, telltale_api::ManagedKind::Slo),
        (managed::PROBE, telltale_api::ManagedKind::Probe),
        (
            managed::UPSTREAM_CHECK,
            telltale_api::ManagedKind::UpstreamCheck,
        ),
    ] {
        let a = crate::settings_kinds::section_json(k, served);
        if a != crate::settings_kinds::section_json(k, own) {
            push(&mut out, kind, "default", a);
        }
    }
    // Only the kinds this module adopts (and strips): the list is the contract.
    out.retain(|e| ADOPTED_KINDS.contains(&e.kind.as_str()));
    out
}

/// Removes from `cfg` (a cluster version, with the API's entries merged in) what `entries` name,
/// so the node's rows are the only source of them. A name `own` (this node's files) also
/// defines is put back as the files have it, so deleting the row reveals the files' entry; a
/// section the rows replace as a whole goes back to the files'.
#[allow(clippy::too_many_lines)] // one line per settings kind
pub(crate) fn strip(cfg: &mut Config, entries: &[Entry], own: &Config) {
    fn names<'a>(entries: &'a [Entry], kind: &str) -> Vec<&'a str> {
        entries
            .iter()
            .filter(|e| e.kind == kind)
            .map(|e| e.name.as_str())
            .collect()
    }
    fn named<T: Named + Clone>(items: &mut Vec<T>, own: &[T], names: &[&str]) {
        for n in names {
            items.retain(|i| i.name() != *n);
            if let Some(o) = own.iter().find(|i| i.name() == *n) {
                items.push(o.clone());
            }
        }
    }
    named(
        &mut cfg.upstream,
        &own.upstream,
        &names(entries, managed::UPSTREAM),
    );
    named(
        &mut cfg.upstream_group,
        &own.upstream_group,
        &names(entries, managed::UPSTREAM_GROUP),
    );
    named(&mut cfg.list, &own.list, &names(entries, managed::LIST));
    named(&mut cfg.group, &own.group, &names(entries, managed::GROUP));
    named(
        &mut cfg.alerts.destination,
        &own.alerts.destination,
        &names(entries, managed::ALERT_DESTINATION),
    );
    named(
        &mut cfg.alerts.rule,
        &own.alerts.rule,
        &names(entries, managed::ALERT_RULE),
    );
    named(
        &mut cfg.schedule,
        &own.schedule,
        &names(entries, managed::SCHEDULE),
    );
    named(
        &mut cfg.anomaly_mute,
        &own.anomaly_mute,
        &names(entries, managed::ANOMALY_MUTE),
    );
    named(
        &mut cfg.router,
        &own.router,
        &names(entries, managed::ROUTER),
    );
    for key in names(entries, managed::KUBERNETES_MAP) {
        cfg.kubernetes.map.retain(|r| r.key() != key);
        if let Some(o) = own.kubernetes.map.iter().find(|r| r.key() == key) {
            cfg.kubernetes.map.push(o.clone());
        }
    }
    // Entries that are only ever the API's: devices, quick rules, local names, forwarded domains.
    for e in entries {
        match e.kind.as_str() {
            managed::CLIENT => {
                let body = e.body.get("name").and_then(|n| n.as_str());
                cfg.client
                    .retain(|c| c.name.as_str() != e.name && Some(c.name.as_str()) != body);
            }
            managed::RULE => cfg.rule.retain(|r| r.id.as_str() != e.name),
            managed::RECORD => cfg
                .record
                .retain(|r| !r.name.as_str().eq_ignore_ascii_case(&e.name)),
            managed::FORWARD => {
                let group = managed::forward_group(&e.name);
                let prefix = format!("{group}#");
                cfg.route.retain(|r| r.upstream_group.as_str() != group);
                cfg.upstream_group.retain(|g| g.name.as_str() != group);
                cfg.upstream
                    .retain(|u| !u.name.as_str().starts_with(&prefix));
            }
            managed::RATELIMIT => cfg.ratelimit = own.ratelimit.clone(),
            managed::EXCLUSIONS => cfg.exclusions = own.exclusions.clone(),
            managed::SIMULATE => cfg.simulate = own.simulate.clone(),
            managed::MAP => cfg.map = own.map.clone(),
            managed::ROLLOUT => cfg.cluster.rollout = own.cluster.rollout.clone(),
            managed::SPECIAL => cfg.special = own.special.clone(),
            managed::DISCOVERY => cfg.discovery = own.discovery.clone(),
            managed::CMDB => cfg.cmdb = own.cmdb.clone(),
            managed::CLIENTS => cfg.clients.mdns = own.clients.mdns,
            managed::ZONE
            | managed::DNSSEC
            | managed::FILTER
            | managed::DRILL
            | managed::SLO
            | managed::PROBE
            | managed::UPSTREAM_CHECK => strip_tuning(cfg, e, own),
            managed::LOCAL => {
                let hosts_files = std::mem::take(&mut cfg.local.hosts_files);
                cfg.local = own.local.clone();
                cfg.local.hosts_files = hosts_files;
            }
            _ => {}
        }
    }
}

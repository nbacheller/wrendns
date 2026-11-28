//! REQ: API-016, CLU-015, CLU-004, CLU-010 (T23.10, ADR-903 §6, ADR-967) — node-managed entries.
//!
//! A node-local section (`NODE_LOCAL`: `auth`, `telemetry`, ...) never travels in the shared
//! configuration. The few settings of those sections an admin changes in the UI (`oidc_provider`
//! and, with T23.11 (ADR-984), `sink` and `otlp`) are entries of a *node-managed kind*: stored by the
//! primary in `managed` like any entry, and replicated as one more blob of the signed manifest
//! (`ClusterManifest.node_managed`) holding **references only**: a secret is named, never carried.
//!
//! Every member persists the last blob it applied (it is one of the manifest's blobs), validates
//! it and merges it apart from the shared part, under its own files: a file's entry of the same ID
//! wins, a bad entry (or a bad blob) is dropped with one log line and leaves the shared part and
//! DNS untouched (CLU-004), and an older node ignores the field (CLU-010). A promoted primary
//! seeds its own rows from the blob it inherited, once, and publishes from them.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};
use wrendns_config::{Config, OidcProvider, OtlpConfig, SinkConfig};
use wrendns_store::state::State;

use crate::managed::{CACHE, OIDC_PROVIDER, OTLP, SINK, SUPPORT, UPDATES};

/// The blob's name in the manifest.
pub(crate) const BLOB: &str = "node-managed.json";
/// The document's version.
const VERSION: u32 = 1;
/// The kinds that are node-managed (the others are the shared configuration's).
pub(crate) const KINDS: &[&str] = &[
    OIDC_PROVIDER,
    SINK,
    OTLP,
    // REQ: DNS-006, OPS-011, OPS-012 (T27.2, T27.11, ADR-1006) — the per-node sections.
    CACHE,
    SUPPORT,
    UPDATES,
    // REQ: OBS-013, OBS-003, OBS-005 (T27.5, ADR-1007) — the node-local telemetry settings.
    crate::managed::ANOMALY_SETTINGS,
    crate::managed::QLOG_SETTINGS,
    crate::managed::METRICS_SETTINGS,
    crate::guarded::KIND,
];
/// REQ: CLU-015 (T24.37, ADR-1016) — the kinds of the shared configuration that the API stores:
/// the blob also carries their rows, whole, so a replica that is promoted adopts exactly what the
/// cluster last published. A replica applies the shared configuration, not these rows; a build
/// that doesn't know the kinds skips them (CLU-010).
pub(crate) const SHARED_KINDS: &[&str] = &[
    crate::managed::CLIENT,
    crate::managed::RECORD,
    crate::managed::FORWARD,
    crate::managed::RULE,
    crate::managed::UPSTREAM,
    crate::managed::UPSTREAM_GROUP,
    crate::managed::LIST,
    crate::managed::GROUP,
    crate::managed::ALERT_DESTINATION,
    crate::managed::ALERT_RULE,
    crate::managed::SCHEDULE,
    crate::managed::ANOMALY_MUTE,
    crate::managed::RATELIMIT,
    crate::managed::EXCLUSIONS,
    crate::managed::SIMULATE,
    crate::managed::MAP,
    crate::managed::ROLLOUT,
    crate::managed::KUBERNETES_MAP,
    crate::managed::SPECIAL,
    crate::managed::LOCAL,
    crate::managed::CLIENTS,
    crate::managed::DISCOVERY,
    crate::managed::CMDB,
    crate::managed::ROUTER,
    // REQ: DNS-011, FLT-004, CLU-014 (T27.11, ADR-1006) — the cluster-wide `[dnssec]`, `[filter]`
    // and `[drill]` sections are shared configuration the API stores.
    crate::managed::DNSSEC,
    crate::managed::FILTER,
    crate::managed::DRILL,
    crate::managed::ACCESS,
    // REQ: DNS-010, OBS-016, OBS-020, OBS-019 (T27.5, T27.7, ADR-1007) — the zones and the SLO, probe
    // and upstream-check sections are shared too.
    crate::managed::ZONE,
    // REQ: DSC-913 (T36.10a) - locations are shared too.
    crate::managed::LOCATION,
    // REQ: CLD-904 (T36.10b) - and the DNS providers (a build that does not know the kind skips the row).
    crate::managed::DNS_PROVIDER,
    crate::managed::SLO,
    crate::managed::PROBE,
    crate::managed::UPSTREAM_CHECK,
];
/// The fields that hold or point at a secret outside the store: a provider's `client_secret` and
/// its file, a sink's `token_file` (and `tls_ca`, a path), OTLP's inline `headers`. A blob never
/// carries them: only the references (`client_secret_ref`, `token_ref`, `header_refs`: names)
/// travel.
const SECRET_FIELDS: &[&str] = &[
    "client_secret",
    "client_secret_file",
    "token_file",
    "tls_ca",
    "headers",
];
/// The marker a primary keeps once it seeded its rows from an inherited blob (its hash).
const SEEDED: &str = "node-managed-seeded";

/// The document the manifest's `node_managed` blob holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Doc {
    pub(crate) version: u32,
    /// REQ: CLU-015 (T24.37) — the document carries the rows of [`SHARED_KINDS`] (possibly none).
    /// A blob from a build that doesn't publish them lacks the flag, and a promoted primary then
    /// keeps the rows it has.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) managed: bool,
    #[serde(default)]
    pub(crate) entries: Vec<Entry>,
}

/// One entry: a kind, its name (a provider's ID) and its body, as the stored JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Entry {
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) body: Value,
}

/// Whether `body` carries a field that holds or points at a secret outside the store.
fn carries_secret(body: &Value) -> bool {
    SECRET_FIELDS.iter().any(|f| {
        body.get(*f).is_some_and(|v| match v {
            Value::Null => false,
            Value::String(s) => !s.is_empty(),
            Value::Object(o) => !o.is_empty(),
            Value::Array(a) => !a.is_empty(),
            _ => true,
        })
    })
}

/// The blob for `rows` (kind, name, stored JSON): sorted, references only. A row that carries
/// an inline secret or a file path (one stored before the API refused them) is exported without
/// those fields, so the blob never holds a value.
pub(crate) fn encode(rows: &[(String, String, String)]) -> Vec<u8> {
    let mut entries: Vec<Entry> = rows
        .iter()
        .filter(|(k, _, _)| KINDS.contains(&k.as_str()) || SHARED_KINDS.contains(&k.as_str()))
        .filter_map(|(kind, name, body)| {
            let mut body: Value = serde_json::from_str(body).ok()?;
            // REQ: CLU-006 — a row the operator pinned to this node stays here: the shared
            // configuration keeps such entries on their node, and so does the blob.
            if SHARED_KINDS.contains(&kind.as_str())
                && body.get("node_only") == Some(&Value::Bool(true))
            {
                return None;
            }
            // The shared kinds travel whole, as the shared configuration does.
            if KINDS.contains(&kind.as_str())
                && let Some(o) = body.as_object_mut()
            {
                for f in SECRET_FIELDS {
                    o.remove(*f);
                }
            }
            Some(Entry {
                kind: kind.clone(),
                name: name.clone(),
                body,
            })
        })
        .collect();
    entries.sort_by(|a, b| (&a.kind, &a.name).cmp(&(&b.kind, &b.name)));
    serde_json::to_vec(&Doc {
        version: VERSION,
        managed: true,
        entries,
    })
    .unwrap_or_default()
}

/// The primary's rows of the node-managed kinds, as [`encode`] takes them.
fn rows_of(state: &State) -> Vec<(String, String, String)> {
    let mut rows = Vec::new();
    for kind in KINDS.iter().chain(SHARED_KINDS) {
        match state.managed(kind) {
            Ok(r) => rows.extend(r.into_iter().map(|m| (m.kind, m.name, m.body))),
            Err(e) => warn!(kind, "node-managed entries can't be read to publish: {e}"),
        }
    }
    rows
}

/// REQ: DSC-908 (ADR-1104 point 5) - the kind that carries a device's `location` pin while the
/// start-up hold stands, keyed by the device's name: the body is `{"location": slug}`. A build
/// that does not know it skips the entry as any unknown kind (CLU-010), and a `client` row it
/// reads has no field it would refuse.
pub(crate) const LOCATION_PIN: &str = "location_pin";

/// REQ: DSC-908 (ADR-1104 point 5) - `blob` as published while the start-up hold stands: the
/// `location` rows stay (a build that does not know the kind skips them), and a pin moves from
/// its `client` row into a `location_pin` entry of the same device, so a member that does not
/// know the field never receives it on a row it parses, and a replica promoted during the hold
/// adopts both (the stored rows are not touched).
pub(crate) fn strip_held(blob: &[u8]) -> Vec<u8> {
    let Ok(mut doc) = serde_json::from_slice::<Doc>(blob) else {
        return blob.to_vec();
    };
    let mut pins = Vec::new();
    for e in &mut doc.entries {
        if e.kind == crate::managed::CLIENT
            && let Some(o) = e.body.as_object_mut()
            && let Some(pin) = o.remove("location")
            && !pin.is_null()
        {
            pins.push(Entry {
                kind: LOCATION_PIN.to_owned(),
                name: e.name.clone(),
                body: serde_json::json!({ "location": pin }),
            });
        }
    }
    doc.entries.extend(pins);
    serde_json::to_vec(&doc).unwrap_or_else(|_| blob.to_vec())
}

/// REQ: DSC-908 (ADR-1104 point 5) - puts each `location_pin` entry back on its device's `client`
/// entry and drops the pin entries: the rows a promoted replica adopts are the operator's, pins
/// included. A pin whose device is not among the entries is dropped.
pub(crate) fn fold_pins(entries: Vec<Entry>) -> Vec<Entry> {
    let (pins, mut rest): (Vec<Entry>, Vec<Entry>) =
        entries.into_iter().partition(|e| e.kind == LOCATION_PIN);
    for p in pins {
        let Some(pin) = p.body.get("location").cloned() else {
            continue;
        };
        if let Some(o) = rest
            .iter_mut()
            .find(|e| e.kind == crate::managed::CLIENT && e.name == p.name)
            .and_then(|e| e.body.as_object_mut())
        {
            o.insert("location".to_owned(), pin);
        }
    }
    rest
}

/// The blob to publish from `state`'s rows.
pub(crate) fn export(state: &State) -> Vec<u8> {
    encode(&rows_of(state))
}

/// Reads a blob: the entries it holds. A document that doesn't parse, or one from a newer
/// version, is an `Err` (all of its entries are dropped); an entry of a kind this build doesn't
/// know is skipped (a newer primary's), and one that carries a secret is refused.
pub(crate) fn parse(bytes: &[u8]) -> Result<Vec<Entry>, String> {
    parse_kinds(bytes, KINDS)
}

/// [`parse`] for a build that knows only `kinds` (the tests read a blob as an older node would).
pub(crate) fn parse_kinds(bytes: &[u8], kinds: &[&str]) -> Result<Vec<Entry>, String> {
    let doc: Doc = serde_json::from_slice(bytes).map_err(|e| format!("not readable: {e}"))?;
    if doc.version > VERSION {
        return Err(format!(
            "written by a newer version (document version {}, this build reads {VERSION}): upgrade this node",
            doc.version
        ));
    }
    Ok(doc
        .entries
        .into_iter()
        .filter(|e| kinds.contains(&e.kind.as_str()))
        .filter(|e| {
            let refused = carries_secret(&e.body);
            if refused {
                warn!(kind = %e.kind, name = %e.name, "a node-managed entry carries a secret instead of a reference: dropped");
            }
            !refused
        })
        .collect())
}

/// REQ: CLU-015 (T24.37) — the rows of the shared kinds a blob carries: `Ok(None)` for a blob from
/// a build that doesn't publish them, `Err` for one that can't be read.
pub(crate) fn parse_shared(bytes: &[u8]) -> Result<Option<Vec<Entry>>, String> {
    let doc: Doc = serde_json::from_slice(bytes).map_err(|e| format!("not readable: {e}"))?;
    if doc.version > VERSION {
        return Err(format!(
            "written by a newer version (document version {}, this build reads {VERSION}): upgrade this node",
            doc.version
        ));
    }
    if !doc.managed {
        return Ok(None);
    }
    Ok(Some(
        doc.entries
            .into_iter()
            .filter(|e| SHARED_KINDS.contains(&e.kind.as_str()) || e.kind == LOCATION_PIN)
            .collect(),
    ))
}

/// The providers among `entries` that validate, and what was wrong with the others.
pub(crate) fn providers(entries: &[Entry]) -> (Vec<OidcProvider>, Vec<String>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for e in entries.iter().filter(|e| e.kind == OIDC_PROVIDER) {
        let mut body = e.body.clone();
        if let Some(o) = body.as_object_mut() {
            // The ID is the entry's name, whatever the body says.
            o.insert("id".into(), Value::String(e.name.clone()));
        }
        match serde_json::from_value::<OidcProvider>(body) {
            Ok(mut p) => {
                p.client_secret = None;
                p.client_secret_file = None;
                let errs = wrendns_config::oidc_provider_errors(&p);
                if errs.is_empty() {
                    ok.push(p);
                } else {
                    bad.push(format!("provider `{}`: {}", e.name, errs.join("; ")));
                }
            }
            Err(err) => bad.push(format!("provider `{}`: {err}", e.name)),
        }
    }
    (ok, bad)
}

/// REQ: API-016 (T23.11) — the sinks among `entries` that validate, and what was wrong with the
/// others. The name is the entry's, whatever the body says.
pub(crate) fn sinks(entries: &[Entry]) -> (Vec<SinkConfig>, Vec<String>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for e in entries.iter().filter(|e| e.kind == SINK) {
        let mut body = e.body.clone();
        if let Some(o) = body.as_object_mut() {
            o.insert("name".into(), Value::String(e.name.clone()));
        }
        match serde_json::from_value::<SinkConfig>(body) {
            Ok(mut s) => {
                s.token_file = None;
                s.tls_ca = None;
                let mut errs = wrendns_config::sink_errors(&s);
                if let Err(why) = crate::sink_settings::stored_limits(&s) {
                    errs.push(why);
                }
                if ok.len() >= crate::sink_settings::max_sinks() {
                    errs.push("more sinks than a node takes".into());
                }
                if errs.is_empty() {
                    ok.push(s);
                } else {
                    bad.push(format!("sink `{}`: {}", e.name, errs.join("; ")));
                }
            }
            Err(err) => bad.push(format!("sink `{}`: {err}", e.name)),
        }
    }
    (ok, bad)
}

/// REQ: API-016 (T23.11) — the OTLP export among `entries`, if it validates.
pub(crate) fn otlp(entries: &[Entry]) -> (Option<OtlpConfig>, Vec<String>) {
    let mut bad = Vec::new();
    for e in entries.iter().filter(|e| e.kind == OTLP) {
        match serde_json::from_value::<OtlpConfig>(e.body.clone()) {
            Ok(mut o) => {
                o.headers.clear();
                o.traces_sample_every = 0;
                o.traces_slow_ms = 0;
                o.tls_ca = None;
                let errs = wrendns_config::otlp_errors(&o);
                if errs.is_empty() {
                    return (Some(o), bad);
                }
                bad.push(format!("the OTLP export: {}", errs.join("; ")));
            }
            Err(err) => bad.push(format!("the OTLP export: {err}")),
        }
    }
    (None, bad)
}

/// REQ: API-016 (T23.11) — merges `sinks` into `cfg` as the node-managed ones: a sink the files
/// define (by name) is left out, a node-managed one of the same name is replaced. A file sink
/// made in the UI is a bare file name; it is written under `<data_dir>/sinks/`.
pub(crate) fn overlay_sinks(cfg: &mut Config, sinks: Vec<SinkConfig>) {
    let dir = Path::new(cfg.node.data_dir.as_str()).join("sinks");
    for mut s in sinks {
        if cfg.telemetry.sink.iter().any(|f| f.name == s.name) {
            continue;
        }
        if s.kind == wrendns_config::SinkKind::File
            && let Some(name) = s.path.as_ref().map(ToString::to_string)
            && let Ok(full) =
                wrendns_config::SafeString::new(dir.join(name).to_string_lossy().as_ref())
        {
            s.path = Some(full);
        }
        cfg.telemetry.managed_sink.retain(|q| q.name != s.name);
        cfg.telemetry.managed_sink.push(s);
    }
}

/// REQ: API-016 (T23.11) — the node-managed OTLP export; the files win when they set a
/// destination (`telemetry.otlp_set_by_file`).
pub(crate) fn overlay_otlp(cfg: &mut Config, otlp: Option<OtlpConfig>) {
    if let Some(o) = otlp {
        cfg.telemetry.managed_otlp = Some(o);
    }
}

/// Merges `providers` into `cfg` as the node-managed ones: a provider the files define (by ID)
/// is left out, a node-managed one of the same ID is replaced, and a resolver pod skips the
/// ones that need a stored secret (it holds none, and serves no sign-in).
pub(crate) fn overlay_providers(cfg: &mut Config, providers: Vec<OidcProvider>) {
    let ephemeral = cfg.cluster.ephemeral;
    let files: Vec<String> = cfg
        .auth
        .oidc
        .provider
        .iter()
        .map(|p| p.id.to_string())
        .collect();
    let mut skipped = 0_u32;
    for p in providers {
        if files.iter().any(|f| *f == p.id.as_str()) {
            continue;
        }
        if ephemeral && p.client_secret_ref.is_some() {
            skipped += 1;
            continue;
        }
        cfg.auth.oidc.managed_provider.retain(|q| q.id != p.id);
        cfg.auth.oidc.managed_provider.push(p);
    }
    if skipped > 0 {
        info!(
            skipped,
            "this resolver pod holds no stored secrets: providers that need one aren't set up here"
        );
    }
}

/// Logs a problem with the node-managed blob once per distinct message.
fn warn_once(what: &str, why: &str) {
    static LAST: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
    let msg = format!("{what}: {why}");
    let mut last = LAST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if *last != msg {
        warn!(
            "node-managed entries from the primary are ignored (the shared configuration is applied): {msg}"
        );
        last.clone_from(&msg);
    }
}

/// Merges the entries of the manifest's blob (`bytes`) into `cfg`, apart from the shared part
/// (CLU-004): whatever is wrong with the blob or an entry drops that part only.
pub(crate) fn overlay_blob(cfg: &mut Config, bytes: &[u8]) {
    let entries = match parse(bytes) {
        Ok(e) => e,
        Err(why) => {
            warn_once("the blob", &why);
            return;
        }
    };
    let (ok, bad) = providers(&entries);
    let (sink_ok, sink_bad) = sinks(&entries);
    let (otlp_ok, otlp_bad) = otlp(&entries);
    for b in bad.iter().chain(&sink_bad).chain(&otlp_bad) {
        warn_once("an entry", b);
    }
    overlay_providers(cfg, ok);
    overlay_sinks(cfg, sink_ok);
    overlay_otlp(cfg, otlp_ok);
    // REQ: DNS-006, OPS-011, OPS-012 (T27.2, T27.11, ADR-1006) — this node's per-node sections.
    crate::node_settings::overlay_blob(cfg, &entries);
    // REQ: API-902 (T27.13, ADR-956 §2) — this node's guarded entries, under its own files.
    overlay_guarded(cfg, &entries);
}

/// REQ: API-902 (T27.13) — the guarded entries of `entries` that name this node, as stored
/// values (an entry for another node, or one this build can't read, isn't this node's).
pub(crate) fn guarded_of(entries: &[Entry], node: &str) -> Vec<crate::guarded::store::Stored> {
    entries
        .iter()
        .filter(|e| e.kind == crate::guarded::KIND)
        .filter_map(|e| {
            let mut s: crate::guarded::store::Stored =
                serde_json::from_value(e.body.clone()).ok()?;
            let (n, id) = crate::guarded::split_name(&e.name)?;
            n.clone_into(&mut s.node);
            id.clone_into(&mut s.id);
            (s.node == node).then_some(s)
        })
        .collect()
}

/// Puts this node's guarded values from a replicated blob into `cfg`: the file wins, an entry a
/// local clear is suppressing (until the primary's copy changes) is skipped.
fn overlay_guarded(cfg: &mut Config, entries: &[Entry]) {
    let Some(me) = crate::guarded::this_node() else {
        return;
    };
    let own = cfg.clone();
    let mut mine = guarded_of(entries, &me);
    if mine.is_empty() {
        return;
    }
    let state = {
        let p = crate::managed::state_path(&own);
        if p.exists() {
            State::open(&p).ok()
        } else {
            None
        }
    };
    // REQ: API-902 (ADR-956 §4) — what this node made of an entry the primary replicated (on
    // probation after a start with it, then active) lives here, not in the primary's copy.
    if let Some(st) = &state {
        let notes = crate::guarded::store::replica_states(st);
        for e in &mut mine {
            if let Some((digest, s)) = notes.get(&e.id)
                && *digest == e.digest()
            {
                e.state = *s;
            }
        }
    }
    crate::guarded::appliers::overlay(cfg, &own, &mine, state.as_ref());
}

/// REQ: API-902 (ADR-957) — the guarded entries for `node` in the cluster version this node last
/// applied (what a replica's offline clear has to suppress).
pub(crate) fn applied_guarded(cfg: &Config, node: &str) -> Vec<crate::guarded::store::Stored> {
    let Some(m) = crate::replication::last_applied(cfg) else {
        return Vec::new();
    };
    let Some(b) = &m.node_managed else {
        return Vec::new();
    };
    let Ok(store) =
        wrendns_cluster::sync::BlobStore::open(std::path::Path::new(cfg.node.data_dir.as_str()))
    else {
        return Vec::new();
    };
    match store.read(b).ok().and_then(|bytes| parse(&bytes).ok()) {
        Some(entries) => guarded_of(&entries, node),
        None => Vec::new(),
    }
}

/// The rows of this node's own `state.db` for the node-managed kinds, as providers: what a
/// Git-sourced primary applies (its writes are refused, so the rows are carried unchanged). A
/// missing or unreadable database adds nothing.
pub(crate) fn overlay_own(cfg: &mut Config, state_path: &Path) {
    if !state_path.exists() {
        return;
    }
    let Ok(state) = State::open(state_path) else {
        return;
    };
    let entries = parse(&export(&state)).unwrap_or_default();
    let (ok, bad) = providers(&entries);
    let (sink_ok, sink_bad) = sinks(&entries);
    let (otlp_ok, otlp_bad) = otlp(&entries);
    for b in bad.iter().chain(&sink_bad).chain(&otlp_bad) {
        warn!("a node-managed entry on this node is ignored: {b}");
    }
    overlay_providers(cfg, ok);
    overlay_sinks(cfg, sink_ok);
    overlay_otlp(cfg, otlp_ok);
    // REQ: DNS-006, OPS-011, OPS-012 (T27.2, T27.11, ADR-1006) — the per-node sections it holds.
    crate::node_settings::overlay_blob(cfg, &entries);
}

/// A promoted primary's seeding (ADR-903 §6): the entries of the blob it inherited that it has no
/// row for become its own rows, once per inherited blob (a marker keeps the hash), so that they
/// can be changed here and are published from here. A node's rows from an earlier time as
/// primary were cleared when it became a replica ([`clear_stale`]), so the blob wins. Returns whether this node's
/// rows are the source now: when it is, the inherited blob is no longer overlaid (a deleted entry
/// must not come back from a stale copy).
pub(crate) fn seed_once(state_path: &Path, cluster_dir: &Path, hash: &str, bytes: &[u8]) -> bool {
    let marker = cluster_dir.join(SEEDED);
    if std::fs::read_to_string(&marker).is_ok_and(|h| h.trim() == hash) {
        return true;
    }
    let entries = match parse(bytes) {
        Ok(e) => e,
        Err(why) => {
            warn_once("the inherited blob can't be seeded", &why);
            return false;
        }
    };
    let Ok(state) = State::open(state_path) else {
        return false;
    };
    let have: Vec<(String, String)> = KINDS
        .iter()
        .flat_map(|k| state.managed(k).unwrap_or_default())
        .map(|m| (m.kind, m.name))
        .collect();
    let (valid, _) = providers(&entries);
    let (valid_sinks, _) = sinks(&entries);
    let (valid_otlp, _) = otlp(&entries);
    let rows: Vec<(String, String, String)> = entries
        .iter()
        .filter(|e| !have.iter().any(|(k, n)| *k == e.kind && *n == e.name))
        .filter(|e| match e.kind.as_str() {
            OIDC_PROVIDER => valid.iter().any(|p| p.id.as_str() == e.name),
            SINK => valid_sinks.iter().any(|s| s.name.as_str() == e.name),
            OTLP => valid_otlp.is_some(),
            _ => true,
        })
        .filter_map(|e| {
            Some((
                e.kind.clone(),
                e.name.clone(),
                serde_json::to_string(&e.body).ok()?,
            ))
        })
        .collect();
    if !rows.is_empty() {
        let refs: Vec<(&str, &str, &str)> = rows
            .iter()
            .map(|(k, n, b)| (k.as_str(), n.as_str(), b.as_str()))
            .collect();
        if let Err(e) = state.put_managed_batch(&refs, None, now_secs(), "promotion") {
            warn!("can't seed the inherited node-managed entries: {e}");
            return false;
        }
        info!(
            entries = rows.len(),
            "this node was promoted: its node-managed entries are seeded from the last cluster version"
        );
    }
    if let Err(e) = std::fs::write(&marker, hash) {
        warn!("can't record the node-managed seeding: {e}");
        return false;
    }
    true
}

/// REQ: CLU-015, API-016 (ADR-968 point 4) — a replica never writes node-managed rows (writes
/// are forwarded to the primary), so any it holds are left from an earlier time as primary. They
/// are deleted, and the seeding marker with them, so that a later promotion starts from the
/// blob it inherits and not from a stale copy (a provider the cluster removed must not come back).
pub(crate) fn clear_stale(state_path: &Path, cluster_dir: &Path) {
    if state_path.exists()
        && let Ok(state) = State::open(state_path)
    {
        for kind in KINDS {
            for m in state.managed(kind).unwrap_or_default() {
                if let Err(e) = state.delete_managed(&m.kind, &m.name, None) {
                    warn!(kind = %m.kind, name = %m.name, "can't clear a stale node-managed row on a replica: {e}");
                }
            }
        }
    }
    let _ = std::fs::remove_file(cluster_dir.join(SEEDED));
}

/// Whether the seeding of the blob with `hash` is recorded.
pub(crate) fn seeded(cluster_dir: &Path, hash: &str) -> bool {
    std::fs::read_to_string(cluster_dir.join(SEEDED)).is_ok_and(|h| h.trim() == hash)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: CLD-904 (T36.10b) - a `dns_provider` row is a shared kind: the blob carries it whole (the
    /// credential as a stored secret's name), a build that does not know the kind skips it and
    /// reads the rest, and the start-up hold's strip leaves the row where it is.
    #[test]
    fn cld_904_a_dns_provider_row_is_shared_and_an_older_build_skips_it() {
        let rows = vec![
            (
                crate::managed::DNS_PROVIDER.to_owned(),
                "cf-home".to_owned(),
                r#"{"name":"cf-home","kind":"cloudflare","zone":"example.net","credential_ref":"cf"}"#
                    .to_owned(),
            ),
            (
                crate::managed::CLIENT.to_owned(),
                "tv".to_owned(),
                r#"{"match":["192.0.2.10"]}"#.to_owned(),
            ),
        ];
        let full = encode(&rows);
        assert!(SHARED_KINDS.contains(&crate::managed::DNS_PROVIDER));
        let got = parse_shared(&full).unwrap().unwrap();
        assert!(got.iter().any(|e| e.kind == crate::managed::DNS_PROVIDER));
        // The hold keeps the row in the blob (a build that does not know it skips it).
        let held = parse_shared(&strip_held(&full)).unwrap().unwrap();
        assert!(held.iter().any(|e| e.kind == crate::managed::DNS_PROVIDER));
        // An older build's kinds: the device is read, the provider skipped.
        let old = parse_kinds(&full, &[crate::managed::CLIENT]).unwrap();
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].kind, crate::managed::CLIENT);
    }

    /// REQ: DSC-908 (ADR-1104 point 5) - the blob published during the start-up hold keeps the
    /// `location` rows, carries each pin as a `location_pin` entry instead of a field of the
    /// `client` row, and a build without those kinds reads every device from it; a promoted
    /// replica folds the pins back onto the devices.
    #[test]
    fn dsc_908_strip_held_moves_pins_to_their_own_kind_and_keeps_the_rows() {
        let rows = vec![
            (
                crate::managed::LOCATION.to_owned(),
                "lab".to_owned(),
                r#"{"networks":["192.0.2.0/24"]}"#.to_owned(),
            ),
            (
                crate::managed::CLIENT.to_owned(),
                "laptop".to_owned(),
                r#"{"match":["192.0.2.9"],"location":"lab"}"#.to_owned(),
            ),
            (
                crate::managed::CLIENT.to_owned(),
                "tv".to_owned(),
                r#"{"match":["192.0.2.10"]}"#.to_owned(),
            ),
        ];
        let full = encode(&rows);
        let held = strip_held(&full);
        let got = parse_shared(&held).unwrap().unwrap();
        assert!(
            got.iter().any(|e| e.kind == crate::managed::LOCATION),
            "the rows stay: {got:?}"
        );
        let dev = got
            .iter()
            .find(|e| e.name == "laptop" && e.kind == crate::managed::CLIENT)
            .unwrap();
        assert!(dev.body.get("location").is_none(), "{dev:?}");
        assert!(dev.body.get("match").is_some(), "the device itself stays");
        let pins: Vec<_> = got.iter().filter(|e| e.kind == LOCATION_PIN).collect();
        assert_eq!(pins.len(), 1, "only the pinned device: {got:?}");
        assert_eq!(pins[0].name, "laptop");
        assert_eq!(pins[0].body["location"], "lab");
        // A build that knows neither kind reads the devices and skips the rest.
        let old = parse_kinds(&held, &[crate::managed::CLIENT]).unwrap();
        assert!(old.iter().all(|e| e.kind == crate::managed::CLIENT));
        // The promoted replica's rows have the pin back and no pin entries.
        let folded = fold_pins(got);
        assert!(folded.iter().all(|e| e.kind != LOCATION_PIN));
        let dev = folded.iter().find(|e| e.name == "laptop").unwrap();
        assert_eq!(dev.body["location"], "lab");
        // The full blob still has them on the row (the stored rows are untouched).
        let all = parse_shared(&full).unwrap().unwrap();
        assert!(all.iter().any(|e| e.kind == crate::managed::LOCATION));
        // A blob that is not a document is returned as it was.
        assert_eq!(strip_held(b"nope"), b"nope".to_vec());
    }

    fn provider_body(secret_ref: Option<&str>) -> String {
        let mut v = serde_json::json!({
            "issuer": "https://idp.example",
            "client_id": "wrendns",
            "default_role": "viewer",
        });
        if let Some(r) = secret_ref {
            v["client_secret_ref"] = r.into();
        }
        v.to_string()
    }

    /// REQ: CLU-015 — the blob holds references only: an inline secret or a file path on a row is
    /// left out of it, and a blob that carries one is refused when read.
    #[test]
    fn clu_015_node_managed_refs_only() {
        let mut leaked: Value = serde_json::from_str(&provider_body(Some("oidc.sso"))).unwrap();
        leaked["client_secret"] = "hunter2-the-real-secret".into();
        leaked["client_secret_file"] = "/run/secrets/sso".into();
        let rows = vec![(
            OIDC_PROVIDER.to_owned(),
            "sso".to_owned(),
            leaked.to_string(),
        )];
        let blob = encode(&rows);
        let text = String::from_utf8(blob.clone()).unwrap();
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("/run/secrets"), "{text}");
        assert!(text.contains("oidc.sso"), "the reference travels: {text}");
        let entries = parse(&blob).unwrap();
        assert_eq!(entries.len(), 1);
        // A blob built by hand with a secret is dropped, entry by entry.
        let forged = serde_json::to_vec(&Doc {
            version: 1,
            managed: false,
            entries: vec![Entry {
                kind: OIDC_PROVIDER.into(),
                name: "sso".into(),
                body: leaked,
            }],
        })
        .unwrap();
        assert_eq!(parse(&forged).unwrap().len(), 0);
    }

    /// REQ: CLU-004 — a bad blob, or a bad entry, drops only itself.
    #[test]
    fn clu_004_a_bad_entry_drops_only_itself() {
        assert!(parse(b"not json").is_err());
        let newer = br#"{"version": 99, "entries": []}"#;
        assert!(parse(newer).unwrap_err().contains("upgrade"));
        let doc = Doc {
            version: 1,
            managed: false,
            entries: vec![
                Entry {
                    kind: OIDC_PROVIDER.into(),
                    name: "good".into(),
                    body: serde_json::from_str(&provider_body(None)).unwrap(),
                },
                Entry {
                    kind: OIDC_PROVIDER.into(),
                    name: "BAD ID".into(),
                    body: serde_json::from_str(&provider_body(None)).unwrap(),
                },
                Entry {
                    kind: OIDC_PROVIDER.into(),
                    name: "noissuer".into(),
                    body: serde_json::json!({"client_id": "x"}),
                },
                Entry {
                    kind: "from-the-future".into(),
                    name: "x".into(),
                    body: serde_json::json!({}),
                },
            ],
        };
        let entries = parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(entries.len(), 3, "an unknown kind is skipped");
        let (ok, bad) = providers(&entries);
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].id.as_str(), "good");
        assert_eq!(bad.len(), 2, "{bad:?}");
    }

    /// REQ: API-016 — the files win by ID, and a resolver pod skips providers that need a secret.
    #[test]
    fn api_016_overlay_files_win_and_pods_skip_secrets() {
        let entries = |names: &[(&str, Option<&str>)]| -> Vec<Entry> {
            names
                .iter()
                .map(|(n, r)| Entry {
                    kind: OIDC_PROVIDER.into(),
                    name: (*n).into(),
                    body: serde_json::from_str(&provider_body(*r)).unwrap(),
                })
                .collect()
        };
        let mut cfg = Config::default();
        cfg.auth.oidc.provider = vec![
            toml::from_str(
                "id = \"sso\"\nissuer = \"https://file.example\"\nclient_id = \"from-file\"\n",
            )
            .unwrap(),
        ];
        let (ok, _) = providers(&entries(&[("sso", None), ("lab", Some("oidc.lab"))]));
        overlay_providers(&mut cfg, ok.clone());
        let ids: Vec<&str> = cfg
            .auth
            .oidc
            .managed_provider
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(ids, ["lab"], "the file's `sso` wins");
        let mut pod = Config::default();
        pod.cluster.ephemeral = true;
        overlay_providers(&mut pod, ok);
        let ids: Vec<&str> = pod
            .auth
            .oidc
            .managed_provider
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(ids, ["sso"], "the pod skips the one that names a secret");
    }
}

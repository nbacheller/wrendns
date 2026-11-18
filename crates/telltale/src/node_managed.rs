//! REQ: API-016, CLU-015, CLU-004, CLU-010 (T23.10, ADR-903 §6, ADR-967) — node-managed entries.
//!
//! A node-local section (`NODE_LOCAL`: `auth`, `telemetry`, ...) never travels in the shared
//! configuration. The few settings of those sections an admin changes in the UI (`oidc_provider`
//! today, `sink` and `otlp` with T23.11) are entries of a *node-managed kind*: stored by the
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
use telltale_config::{Config, OidcProvider};
use telltale_store::state::State;
use tracing::{info, warn};

use crate::managed::OIDC_PROVIDER;

/// The blob's name in the manifest.
pub(crate) const BLOB: &str = "node-managed.json";
/// The document's version.
const VERSION: u32 = 1;
/// The kinds that are node-managed (the others are the shared configuration's).
pub(crate) const KINDS: &[&str] = &[OIDC_PROVIDER];
/// The fields of a provider that hold or point at a secret outside the store. A blob never
/// carries them: only `client_secret_ref` (a name) travels.
const SECRET_FIELDS: &[&str] = &["client_secret", "client_secret_file"];
/// The marker a primary keeps once it seeded its rows from an inherited blob (its hash).
const SEEDED: &str = "node-managed-seeded";

/// The document the manifest's `node_managed` blob holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Doc {
    pub(crate) version: u32,
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
        body.get(*f)
            .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
    })
}

/// The blob for `rows` (kind, name, stored JSON): sorted, references only. A row that carries
/// an inline secret or a file path (one stored before the API refused them) is exported without
/// those fields, so the blob never holds a value.
pub(crate) fn encode(rows: &[(String, String, String)]) -> Vec<u8> {
    let mut entries: Vec<Entry> = rows
        .iter()
        .filter(|(k, _, _)| KINDS.contains(&k.as_str()))
        .filter_map(|(kind, name, body)| {
            let mut body: Value = serde_json::from_str(body).ok()?;
            if let Some(o) = body.as_object_mut() {
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
        entries,
    })
    .unwrap_or_default()
}

/// The primary's rows of the node-managed kinds, as [`encode`] takes them.
fn rows_of(state: &State) -> Vec<(String, String, String)> {
    let mut rows = Vec::new();
    for kind in KINDS {
        match state.managed(kind) {
            Ok(r) => rows.extend(r.into_iter().map(|m| (m.kind, m.name, m.body))),
            Err(e) => warn!(kind, "node-managed entries can't be read to publish: {e}"),
        }
    }
    rows
}

/// The blob to publish from `state`'s rows.
pub(crate) fn export(state: &State) -> Vec<u8> {
    encode(&rows_of(state))
}

/// Reads a blob: the entries it holds. A document that doesn't parse, or one from a newer
/// version, is an `Err` (all of its entries are dropped); an entry of a kind this build doesn't
/// know is skipped (a newer primary's), and one that carries a secret is refused.
pub(crate) fn parse(bytes: &[u8]) -> Result<Vec<Entry>, String> {
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
        .filter(|e| KINDS.contains(&e.kind.as_str()))
        .filter(|e| {
            let refused = carries_secret(&e.body);
            if refused {
                warn!(kind = %e.kind, name = %e.name, "a node-managed entry carries a secret instead of a reference: dropped");
            }
            !refused
        })
        .collect())
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
                let errs = telltale_config::oidc_provider_errors(&p);
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
        warn!("node-managed entries from the primary are ignored (the shared configuration is applied): {msg}");
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
    for b in &bad {
        warn_once("an entry", b);
    }
    overlay_providers(cfg, ok);
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
    let (ok, bad) = providers(&parse(&export(&state)).unwrap_or_default());
    for b in &bad {
        warn!("a node-managed entry on this node is ignored: {b}");
    }
    overlay_providers(cfg, ok);
}

/// A promoted primary's seeding (ADR-903 §6): the entries of the blob it inherited that it has no
/// row for become its own rows, once per inherited blob (a marker keeps the hash), so that they
/// can be changed here and are published from here. Its own rows win. Returns whether this node's
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
    let rows: Vec<(String, String, String)> = entries
        .iter()
        .filter(|e| !have.iter().any(|(k, n)| *k == e.kind && *n == e.name))
        .filter(|e| e.kind != OIDC_PROVIDER || valid.iter().any(|p| p.id.as_str() == e.name))
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

    fn provider_body(secret_ref: Option<&str>) -> String {
        let mut v = serde_json::json!({
            "issuer": "https://idp.example",
            "client_id": "telltale",
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
            entries: vec![Entry {
                kind: OIDC_PROVIDER.into(),
                name: "sso".into(),
                body: leaked,
            }],
        })
        .unwrap();
        assert!(parse(&forged).unwrap().is_empty());
    }

    /// REQ: CLU-004 — a bad blob, or a bad entry, drops only itself.
    #[test]
    fn clu_004_a_bad_entry_drops_only_itself() {
        assert!(parse(b"not json").is_err());
        let newer = br#"{"version": 99, "entries": []}"#;
        assert!(parse(newer).unwrap_err().contains("upgrade"));
        let doc = Doc {
            version: 1,
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

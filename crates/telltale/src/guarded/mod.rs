//! REQ: API-902, API-006, AGT-009, CLU-004 (T27.13; ADR-914, ADR-956, ADR-957) — the guarded
//! changes framework on a node.
//!
//! The settings that can lock every admin out, put credentials on the wire, re-encrypt the secret
//! store or replace a node's configuration are changed only through here. One registry
//! (`telltale_config::guarded`) says what each is; this module does what is common to all of them:
//!
//! - [`engine`]: the preview and its binding, the typed phrase, the sign-in recency, the
//!   confirmation window (a state machine on the monotonic clock), the audit and the alert, the
//!   per-node operation lock, the failure counter.
//! - [`store`]: a guarded value is a `node_managed` entry of the reserved kind `guarded`
//!   (`<node>/<id>`), written only here and only when a change is final.
//! - [`probation`]: a staged or restored entry starts on probation and is dropped after two failed
//!   starts; the counter is a sidecar file, because the failure may be that `state.db` won't open.
//! - [`restart`]: "Restart now", only where a declared supervisor will start the node again.
//! - [`cli`]: `telltale guarded list|clear` (offline) and `TELLTALE_IGNORE_GUARDED`.
//! - [`assertion`]: what the primary signs to forward a request for another node.
//!
//! DNS never depends on any of it (CLU-004): a failure here fails the change, not the queries.

pub(crate) mod appliers;
pub(crate) mod assertion;
pub(crate) mod cli;
#[cfg(feature = "e2e")]
pub(crate) mod e2e;
pub(crate) mod engine;
pub(crate) mod host;
pub(crate) mod probation;
pub(crate) mod prod;
pub(crate) mod restart;
pub(crate) mod store;

#[cfg(test)]
mod api_tests;
#[cfg(test)]
mod tests;

pub(crate) use engine::{Engine, RowDef};
pub(crate) use host::Host;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// The reserved managed kind a guarded value is stored under (`guarded/<node>/<id>`). The generic
/// kind routes can't reach it (409 `guarded_only`).
pub(crate) const KIND: &str = "guarded";

/// How long a preview lives (ADR-956 §3).
pub(crate) const PREVIEW_SECS: u64 = 300;

/// What a cleared (or ignored) entry set the node to: `TELLTALE_IGNORE_GUARDED=1` (ADR-957).
pub(crate) const IGNORE_ENV: &str = "TELLTALE_IGNORE_GUARDED";

/// The slot in `Sources` the engine is put in once the API has opened `state.db`.
pub(crate) type Slot = OnceLock<Arc<Engine>>;

static IGNORED: AtomicBool = AtomicBool::new(false);
static THIS_NODE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Whether this process started with every guarded entry ignored (`TELLTALE_IGNORE_GUARDED=1`).
pub(crate) fn ignored() -> bool {
    IGNORED.load(Ordering::Relaxed)
}

/// Records the start-up decision to ignore (or not) the guarded entries (ADR-957).
pub(crate) fn set_ignored(on: bool) {
    IGNORED.store(on, Ordering::Relaxed);
}

/// The name this node's entries carry (`<node>/<id>`).
pub(crate) fn set_this_node(name: &str) {
    if let Ok(mut n) = THIS_NODE.lock() {
        *n = Some(name.to_owned());
    }
}

/// This node's name, once start-up has set it.
pub(crate) fn this_node() -> Option<String> {
    THIS_NODE.lock().ok().and_then(|n| n.clone())
}

/// The name a node goes by in guarded phrases, previews and entries (`pi-a listen`): the cluster
/// site when it is a member and has one, else its node ID; a standalone node's configured name
/// (or hostname). Every member computes the others' names the same way (`site`, else ID), so the
/// primary can name a target and the target recognises itself.
pub(crate) fn node_label(cfg: &telltale_config::Config) -> String {
    let dir = std::path::Path::new(cfg.node.data_dir.as_str());
    if let Ok(Some(id)) = telltale_cluster::node::Identity::load(dir) {
        return if id.meta.site.is_empty() {
            id.meta.node_id
        } else {
            id.meta.site
        };
    }
    crate::http::node_name(cfg)
}

/// The entry name for a node's setting.
pub(crate) fn entry_name(node: &str, id: &str) -> String {
    format!("{node}/{id}")
}

/// Splits an entry name into the node and the setting ID. The setting is the last segment: a node
/// name never has a `/` (`SafeString`s used for names don't allow one in a node name).
pub(crate) fn split_name(name: &str) -> Option<(&str, &str)> {
    name.rsplit_once('/')
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh random identifier of `n` bytes, in hex.
pub(crate) fn random_id(n: usize) -> String {
    let mut v = vec![0_u8; n];
    for b in &mut v {
        *b = rand::random();
    }
    hex(&v)
}

/// Constant-time equality for tokens and hashes.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Unix seconds now.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// REQ: API-902 (ADR-956 §4, ADR-957) — the guarded framework's health reasons for this node:
/// `guarded_ignored` while `TELLTALE_IGNORE_GUARDED=1` has the node on its files alone (the UI
/// shows it until the variable is removed), and `guarded_bind_fallback` for a confirmed listener
/// that couldn't bind at this start. Both degraded: DNS answers.
pub(crate) fn health_reasons() -> Vec<telltale_api::model::HealthReason> {
    let mut out = Vec::new();
    if ignored() {
        out.push(telltale_api::model::HealthReason {
            level: "degraded".to_owned(),
            code: "guarded_ignored".to_owned(),
            summary: format!(
                "{IGNORE_ENV}=1 is set: this node ignores every guarded entry stored in the UI and runs on its configuration files (nothing is deleted)"
            ),
            node: None,
            link: Some("#/settings?tab=system".to_owned()),
        });
    }
    for id in probation::fallbacks() {
        out.push(telltale_api::model::HealthReason {
            level: "degraded".to_owned(),
            code: "guarded_bind_fallback".to_owned(),
            summary: format!(
                "the confirmed `{id}` setting couldn't bind at this start, so the node runs on the file's value until the next start tries again"
            ),
            node: None,
            link: Some("#/settings?tab=system".to_owned()),
        });
    }
    out
}

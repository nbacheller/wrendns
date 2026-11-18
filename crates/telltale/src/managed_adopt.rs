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
//! rows changes nothing.

use std::path::Path;

use telltale_config::Config;
use telltale_store::state::State;
use tracing::{info, warn};

use crate::managed::{self, Named};
use crate::node_managed::{Entry, SHARED_KINDS, parse_shared};

/// The marker a primary keeps once it adopted the rows of an inherited blob (its hash).
const SEEDED: &str = "managed-seeded";

/// Whether the adoption of the blob with `hash` is recorded.
pub(crate) fn adopted(cluster_dir: &Path, hash: &str) -> bool {
    std::fs::read_to_string(cluster_dir.join(SEEDED)).is_ok_and(|h| h.trim() == hash)
}

/// Forgets the adoption: this node follows a primary, so its rows (from an earlier time as
/// primary) are stale, and the next promotion adopts the blob it inherits whatever its hash.
pub(crate) fn forget(cluster_dir: &Path) {
    let _ = std::fs::remove_file(cluster_dir.join(SEEDED));
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Adopts the shared rows of the inherited blob (`bytes`, with `hash`) into this node's
/// `state.db`, once, replacing what it holds. Returns the entries the node's rows now are the
/// source of (to be [`strip`]ped from the configuration it builds on), or `None` when nothing was
/// adopted: a blob without the rows, one that can't be read, or a store that can't be written
/// (the node then keeps building on the inherited configuration as it always did).
pub(crate) fn adopt(
    state_path: &Path,
    cluster_dir: &Path,
    hash: &str,
    bytes: &[u8],
) -> Option<Vec<Entry>> {
    let entries = match parse_shared(bytes) {
        Ok(Some(e)) => e,
        Ok(None) => return None,
        Err(why) => {
            warn!("the inherited cluster entries can't be adopted: {why}");
            return None;
        }
    };
    if adopted(cluster_dir, hash) {
        return Some(entries);
    }
    let state = match State::open(state_path) {
        Ok(s) => s,
        Err(e) => {
            warn!("the inherited cluster entries can't be adopted: state.db: {e}");
            return None;
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
    if let Err(e) = state.replace_managed(SHARED_KINDS, &refs, now_secs(), "promotion") {
        warn!("the inherited cluster entries can't be adopted: {e}");
        return None;
    }
    if let Err(e) = std::fs::write(cluster_dir.join(SEEDED), hash) {
        // The rows are in; without the marker the next start would adopt the blob again and drop
        // what was changed since, so say it and do not strip.
        warn!("can't record the adoption of the inherited cluster entries: {e}");
        return None;
    }
    info!(
        entries = entries.len(),
        "this node was promoted: it adopted the cluster's last published API entries as its own"
    );
    Some(entries)
}

/// Removes from `cfg` (a cluster version, with the API's entries merged in) what `entries` name,
/// so the node's rows are the only source of them. A name `own` (this node's files) also
/// defines is put back as the files have it, so deleting the row reveals the files' entry; a
/// section the rows replace as a whole goes back to the files'.
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
            managed::CLIENTS => cfg.clients.mdns = own.clients.mdns,
            managed::LOCAL => {
                let hosts_files = std::mem::take(&mut cfg.local.hosts_files);
                cfg.local = own.local.clone();
                cfg.local.hosts_files = hosts_files;
            }
            _ => {}
        }
    }
}

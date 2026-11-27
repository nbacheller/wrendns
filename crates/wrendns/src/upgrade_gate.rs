// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: DSC-908, CLD-920 (ADR-1096 point 5; T36.10a0) — this node's side of the compatibility
//! gate for new shared sections and secret kinds: the check the API and the file loader call, and
//! the record that lets health say a gate is holding a change back.
//!
//! The rule itself is `wrendns_cluster::gate`; nothing here is on the query path.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use wrendns_cluster::gate::{self, Feature};
use wrendns_cluster::net::Cluster;

/// Features whose first use was refused, until a later check passes.
static HELD: Mutex<BTreeSet<Feature>> = Mutex::new(BTreeSet::new());

fn held() -> std::sync::MutexGuard<'static, BTreeSet<Feature>> {
    HELD.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The peers heard from and the full members the identity registry names (this node and removed
/// nodes left out): a registered member this process has not heard from since it started has
/// not reported its build, and the gate counts it as not knowing the feature.
fn judge(cluster: Option<&Cluster>, f: Feature) -> Result<(), gate::Refusal> {
    let Some(c) = cluster else {
        return gate::check_members(&[], &[], f);
    };
    let own = c.identity.meta.node_id.as_str();
    let removed = c.identity.removed();
    let registered: Vec<String> = c
        .identity
        .registry()
        .into_iter()
        .map(|n| n.node_id)
        .filter(|id| id != own && !removed.contains(id))
        .collect();
    gate::check_members(&c.members(), &registered, f)
}

/// Judges `f` against `cluster`'s members (a standalone node has none, so it passes), records a
/// refusal for health, and returns the words that name the member and its version.
pub(crate) fn enforce(cluster: Option<&Cluster>, f: Feature) -> Result<(), String> {
    match judge(cluster, f) {
        Ok(()) => {
            held().remove(&f);
            Ok(())
        }
        Err(r) => {
            held().insert(f);
            Err(r.to_string())
        }
    }
}

/// The refusals still standing now: each held feature is judged again against the members as
/// they are, so a gate that has dropped away stops showing.
pub(crate) fn standing(cluster: Option<&Cluster>) -> Vec<String> {
    let features: Vec<Feature> = held().iter().copied().collect();
    let mut out = Vec::new();
    for f in features {
        match judge(cluster, f) {
            Ok(()) => {
                held().remove(&f);
            }
            Err(r) => out.push(r.to_string()),
        }
    }
    out
}

/// REQ: DSC-908, DSC-910 (T36.10a; ADR-1096 point 5) - whether a configuration uses what an older
/// replica refuses to read: a `[[location]]` entry, or a `location` on a `[[client]]` (both are
/// shared, and `deny_unknown_fields` makes a build without them refuse the whole section).
pub(crate) fn uses_locations(cfg: &wrendns_config::Config) -> bool {
    !cfg.location.is_empty() || cfg.client.iter().any(|c| c.location.is_some())
}

/// REQ: DSC-908 (T36.10a) - the gate for the first location: `Ok` unless `after` starts using
/// locations (`before` did not) while a member's build does not know them. Used by the API write
/// path (dry runs too) and by the file loader on a reload; once the table is in use, every
/// member already knew it when it was let in, so later changes are not held. A node that joins
/// later with an older build refuses the table itself and says so (the replica's own refusal).
pub(crate) fn enforce_locations(
    cluster: Option<&Cluster>,
    before: &wrendns_config::Config,
    after: &wrendns_config::Config,
) -> Result<(), String> {
    if !uses_locations(after) || uses_locations(before) {
        return Ok(());
    }
    enforce(cluster, Feature::Locations)
}

/// REQ: DSC-908 (T36.10a; ADR-1104 point 5, the owner's decision of 2026-11-26) - the locations a
/// primary holds out until the gate can pass. A primary (or a standalone node made a primary)
/// that starts with a file holding a location, or a client pin, does not know yet whether every
/// member announces the feature: it starts and serves DNS, but leaves the location entries and
/// the device pins out of the configuration it serves and publishes, and says why in health. When
/// the members have been heard and all announce the feature the entries are applied without a
/// restart. A node with no cluster is never held.
pub(crate) struct Hold {
    /// The locations are held out.
    active: AtomicBool,
    /// A release reload is running: it builds the configuration with the entries, and the hold
    /// stays on (the blob stays stripped) until that reload has applied them.
    releasing: AtomicBool,
    /// The last release reload did not apply the entries.
    reload_failed: AtomicBool,
    /// Why the entries were dropped, when the node stopped leading before they were published.
    lost: Mutex<Option<String>>,
}

/// The hold of this process.
pub(crate) static HOLD: Hold = Hold::new();

impl Hold {
    pub(crate) const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            releasing: AtomicBool::new(false),
            reload_failed: AtomicBool::new(false),
            lost: Mutex::new(None),
        }
    }

    fn lost(&self) -> std::sync::MutexGuard<'_, Option<String>> {
        self.lost.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the locations are being held out now.
    pub(crate) fn active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// At start-up: when `clustered_primary` and `cfg` uses locations, takes them out of `cfg`
    /// and starts holding. Returns whether it did. `already_published`: the version the cluster
    /// last got already carried locations, so every member knew them when it was let in and a
    /// restart holds nothing (ADR-1096 point 5; ADR-1104 point 5).
    pub(crate) fn at_start(
        &self,
        cfg: &mut wrendns_config::Config,
        clustered_primary: bool,
        already_published: bool,
    ) -> bool {
        if !clustered_primary || !uses_locations(cfg) || already_published {
            return false;
        }
        strip_locations(cfg);
        self.begin();
        true
    }

    /// Starts holding (a promotion whose reload the gate refused, or the start-up).
    pub(crate) fn begin(&self) {
        *self.lost() = None;
        self.reload_failed.store(false, Ordering::Relaxed);
        self.releasing.store(false, Ordering::Relaxed);
        self.active.store(true, Ordering::Relaxed);
    }

    /// Puts the hold back after a release whose reload did not apply the entries.
    pub(crate) fn resume(&self) {
        self.releasing.store(false, Ordering::Relaxed);
        self.reload_failed.store(true, Ordering::Relaxed);
        self.active.store(true, Ordering::Relaxed);
    }

    /// Ends the hold once the release reload has applied the entries.
    pub(crate) fn finish(&self) {
        self.releasing.store(false, Ordering::Relaxed);
        self.reload_failed.store(false, Ordering::Relaxed);
        self.active.store(false, Ordering::Relaxed);
    }

    /// Tests only: ends the hold of the process.
    #[cfg(test)]
    pub(crate) fn clear(&self) {
        self.finish();
        *self.lost() = None;
    }

    /// For every later configuration the node builds while the hold stands (a release reload
    /// builds with the entries).
    pub(crate) fn apply(&self, cfg: &mut wrendns_config::Config) {
        if self.active() && !self.releasing.load(Ordering::Relaxed) {
            strip_locations(cfg);
        }
    }

    /// The words for health while the hold stands: the member that does not know the feature, or
    /// that the members have not been heard from yet; or, once the node stopped leading with the
    /// entries unpublished, that they were dropped.
    pub(crate) fn reason(&self, cluster: Option<&Cluster>) -> Option<String> {
        if !self.active() {
            return self.lost().clone();
        }
        Some(match judge(cluster, Feature::Locations) {
            Err(r) => hold_words(&r),
            Ok(()) if self.reload_failed.load(Ordering::Relaxed) => RELOAD_FAILED.to_owned(),
            Ok(()) => READY_WORDS.to_owned(),
        })
    }

    /// Decides whether the entries can be applied now (the gate passes, or this node is no longer
    /// the primary): `true` when the caller should reload. The hold stays on until the reload has
    /// applied the entries ([`Hold::finish`]), so nothing is published before. A node that no
    /// longer leads never published them: that is logged with the entries (`held`) and kept in
    /// health, and the hold ends without a reload (`false`), as a replica serves its primary's version.
    pub(crate) fn release(&self, cluster: Option<&Cluster>, held: &str) -> bool {
        if !self.active() {
            return false;
        }
        if cluster.is_some_and(|c| !c.is_primary()) {
            tracing::error!(
                entries = held,
                "locations: this node stopped leading before the held entries were published; they are not part of the cluster's configuration"
            );
            *self.lost() = Some(format!(
                "the held locations ({held}) were not published before this node stopped leading; enter them again on the new primary"
            ));
            self.finish();
            return false;
        }
        if judge(cluster, Feature::Locations).is_ok() {
            self.releasing.store(true, Ordering::Relaxed);
            self.reload_failed.store(false, Ordering::Relaxed);
            return true;
        }
        false
    }
}

/// Health's words when the gate passes but the reload that applies the held entries failed.
pub(crate) const RELOAD_FAILED: &str = "the reload that applies them failed; see the log";

/// Health's words when the gate passes and the entries have not been applied yet.
pub(crate) const READY_WORDS: &str = "every member knows them; applying the held entries";

/// The held entries, named: the `[[location]]` slugs and the pinned devices of `cfg` (the build
/// with them in).
pub(crate) fn describe_held(cfg: Option<&wrendns_config::Config>) -> String {
    let Some(cfg) = cfg else {
        return "none known".to_owned();
    };
    let slugs: Vec<&str> = cfg.location.iter().map(|l| l.slug.as_str()).collect();
    let pins: Vec<&str> = cfg
        .client
        .iter()
        .filter(|c| c.location.is_some())
        .map(|c| c.name.as_str())
        .collect();
    format!(
        "locations: {}; pinned devices: {}",
        slugs.join(", "),
        pins.join(", ")
    )
}

/// Takes the `[[location]]` entries and the clients' `location` pins out of `cfg`.
pub(crate) fn strip_locations(cfg: &mut wrendns_config::Config) {
    cfg.location.clear();
    for c in &mut cfg.client {
        c.location = None;
    }
}

/// The hold's words: names the member (and its build) or says the members are not heard yet.
pub(crate) fn hold_words(r: &gate::Refusal) -> String {
    if r.blockers.iter().all(|b| b.version.is_empty()) {
        return "waiting to hear from the members".to_owned();
    }
    r.to_string()
}

/// REQ: DSC-908 - the hold, polled until it ends: every couple of seconds the gate is judged
/// again (members arrive, announce, or are upgraded), and when it passes the locations are applied
/// by a reload. A reload that does not apply them (the gate refused it after a member changed
/// between the two judgements, or the file was invalid) puts the hold back and the loop goes on,
/// so the entries are never dropped silently.
pub(crate) async fn release_loop(
    sources: std::sync::Arc<crate::http::Sources>,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    release_loop_inner(sources, stop).await;
    LOOPING.store(false, Ordering::SeqCst);
}

/// Whether a [`release_loop`] runs (one per process).
static LOOPING: AtomicBool = AtomicBool::new(false);

/// Starts the release loop unless one runs.
pub(crate) fn ensure_release_loop(
    sources: &std::sync::Arc<crate::http::Sources>,
    stop: &tokio::sync::watch::Receiver<bool>,
) {
    if !LOOPING.swap(true, Ordering::SeqCst) {
        tokio::spawn(release_loop(std::sync::Arc::clone(sources), stop.clone()));
    }
}

/// REQ: DSC-908 (ADR-1104 point 5) - after a role change to primary: whether the reload was
/// refused by the locations gate (a promoted replica adopted entries an older member cannot
/// read). Then the hold begins on this node as well, the entries stay out of what it serves, and
/// the release loop applies them once the gate passes.
pub(crate) fn hold_after_refusal() -> bool {
    if !held().contains(&Feature::Locations) {
        return false;
    }
    HOLD.begin();
    true
}

/// The pause before the next release attempt: 2 s after a success, else doubling up to 60 s.
pub(crate) fn next_wait(wait: u64, applied: bool) -> u64 {
    if applied { 2 } else { (wait * 2).min(60) }
}

async fn release_loop_inner(
    sources: std::sync::Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut wait = 2u64;
    while HOLD.active() {
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(std::time::Duration::from_secs(wait)) => {}
        }
        let held = describe_held(sources.unheld.load_full().as_deref());
        if HOLD.release(sources.cluster.as_deref(), &held) {
            tracing::info!("locations: every member knows them; applying the held entries");
            let (tx, rx) = tokio::sync::oneshot::channel();
            let applied = sources.reload.send(tx).await.is_ok() && rx.await.unwrap_or(false);
            if applied {
                HOLD.finish();
                wait = next_wait(wait, true);
            } else {
                tracing::warn!(
                    "locations: the reload did not apply the held entries; holding them and trying again"
                );
                HOLD.resume();
                wait = next_wait(wait, false);
            }
        }
    }
}

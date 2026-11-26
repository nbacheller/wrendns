// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: DSC-908, CLD-920 (ADR-1096 point 5; T36.10a0) — this node's side of the compatibility
//! gate for new shared sections and secret kinds: the check the API and the file loader call, and
//! the record that lets health say a gate is holding a change back.
//!
//! The rule itself is `wrendns_cluster::gate`; nothing here is on the query path.

use std::collections::BTreeSet;
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

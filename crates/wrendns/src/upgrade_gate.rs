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

/// Judges `f` against `cluster`'s members (a standalone node has none, so it passes), records a
/// refusal for health, and returns the words that name the member and its version.
pub(crate) fn enforce(cluster: Option<&Cluster>, f: Feature) -> Result<(), String> {
    let members = cluster.map(Cluster::members).unwrap_or_default();
    match gate::check_members(&members, f) {
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
    let members = cluster.map(Cluster::members).unwrap_or_default();
    let mut out = Vec::new();
    for f in features {
        match gate::check_members(&members, f) {
            Ok(()) => {
                held().remove(&f);
            }
            Err(r) => out.push(r.to_string()),
        }
    }
    out
}

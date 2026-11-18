//! REQ: API-902 (T27.13; ADR-956 §4a) — the end-to-end build's simulated restart. Compiled only
//! under the cargo feature `e2e` (the Playwright server is built with it; a release binary is not),
//! and used only when `TT_E2E_RESTART_HOOK` is also set, so a test never kills its own server.
//!
//! "Restart now" then audits as usual and drops the node's guarded routes to 409 `restarting`
//! for a moment, and the return is simulated the way start-up would handle it: a staged entry
//! whose value says `"fail": true` is dropped as a failed start (outcome `rolled_back`,
//! `failed_start`), the others become active (outcome `applied`).

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use telltale_api::auth::Actor;
use telltale_api::guarded::GuardedOutcome;

use super::engine::Engine;
use super::store::{self, EntryState};

/// Simulates the restart's return after a short pause.
pub(crate) fn simulate_restart(e: Arc<Engine>) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let node = e.node.clone();
        let now = (e.now)();
        for entry in store::for_node(&e.state, &node) {
            if entry.state != EntryState::Staged {
                continue;
            }
            let fail = entry.value.get("fail").and_then(serde_json::Value::as_bool) == Some(true);
            if fail {
                let _ = store::delete(&e.state, &node, &entry.id);
                let _ = e.host.audit(
                    &Actor::system("guarded"),
                    "settings.guarded_rolled_back",
                    &super::entry_name(&node, &entry.id),
                    &json!({"setting": entry.id, "node": node, "reason": "failed_start"}),
                );
                store::record_outcome(
                    &e.state,
                    GuardedOutcome {
                        setting: entry.id.clone(),
                        node: node.clone(),
                        outcome: "rolled_back".to_owned(),
                        reason: Some("failed_start".to_owned()),
                        at: now,
                    },
                );
            } else {
                let mut a = entry.clone();
                a.state = EntryState::Active;
                let _ = store::put(&e.state, &a, now, "system");
                store::record_outcome(
                    &e.state,
                    GuardedOutcome {
                        setting: entry.id.clone(),
                        node: node.clone(),
                        outcome: "applied".to_owned(),
                        reason: None,
                        at: now,
                    },
                );
            }
        }
        e.clear_restarting();
    });
}

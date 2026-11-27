//! REQ: API-902, OPS-012, CLU-004 (T27.13; ADR-956 §4a) — "Restart now": an explicit, audited
//! restart of the node, offered only where something will start it again.
//!
//! The node never guesses. `supervisor` is computed once at start, from a declaration only:
//! `WRENDNS_SUPERVISOR=systemd|docker|kubernetes|none`, set by the shipped unit, the Compose
//! bundles and the chart. `INVOCATION_ID`, `JOURNAL_STREAM`, `NOTIFY_SOCKET` and
//! `KUBERNETES_SERVICE_HOST` are never read: every child of a service inherits them (a terminal, a
//! CI runner), so detecting from them would offer a button that stops a node nobody restarts. With
//! no supervisor the route answers 409 `no_supervisor` and the UI shows the manual steps.
//!
//! Acceptance takes the node's guarded-operation lock with the pending check and the audit write;
//! the audit row `settings.guarded_restart` is written before the exit (no audit, no restart);
//! then the node drains (new work stops, in-flight queries finish within 5 seconds) and exits with
//! code 75. Exit 75 is deliberate and non-zero: systemd `Restart=on-failure` and Docker
//! `on-failure` restart on it, and `always` and Kubernetes restart either way. It is a normal
//! shutdown path, not a crash: the watchdog's exit 70 and the probation count are separate (the
//! start that follows counts, not the exit).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::json;
use tracing::info;
use wrendns_api::guarded::{
    GuardedApplied, GuardedApplyRequest, GuardedCaller, GuardedCheck, Supervisor,
};
use wrendns_api::problem::{Code, Problem};

use super::engine::{Checked, Engine, Preview};

/// The exit code of a requested restart.
pub(crate) const EXIT_CODE: u8 = 75;
/// How long the drain may take before the process exits anyway.
pub(crate) const DRAIN_CAP_SECS: u64 = 5;
/// The variable a supervisor's unit, bundle or chart sets.
pub(crate) const SUPERVISOR_ENV: &str = "WRENDNS_SUPERVISOR";

static REQUESTED: AtomicBool = AtomicBool::new(false);
static WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Whether a restart was requested (the process exits [`EXIT_CODE`] when it has drained).
pub(crate) fn requested() -> bool {
    REQUESTED.load(Ordering::SeqCst)
}

/// Resolves when a restart is requested (the main loop selects on it).
pub(crate) async fn wait_requested() {
    loop {
        let notified = WAKE.notified();
        if requested() {
            return;
        }
        notified.await;
    }
}

/// Asks the node to drain and exit with [`EXIT_CODE`]. A hard cap exits the process anyway if the
/// drain does not finish (ADR-956 §4a, failure).
pub(crate) fn request_exit() {
    request_exit_with(DRAIN_CAP_SECS + 5, exit_now);
}

/// [`request_exit`] with the hard cap's length and what it does at the cap passed in (the tests'
/// form: the real one ends the process).
pub(crate) fn request_exit_with(cap_secs: u64, at_cap: impl FnOnce() + Send + 'static) {
    if REQUESTED.swap(true, Ordering::SeqCst) {
        return;
    }
    WAKE.notify_waiters();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(cap_secs));
        at_cap();
    });
}

/// The process's exit code after the node has stopped: [`EXIT_CODE`] for a requested restart, else 0.
pub(crate) fn exit_status() -> u8 {
    if requested() { EXIT_CODE } else { 0 }
}

/// Forgets a request (tests only: the flag is process-wide).
#[cfg(test)]
pub(crate) fn reset_for_tests() {
    REQUESTED.store(false, Ordering::SeqCst);
}

/// The end of the process for a restart. The end-to-end build replaces it (so a test never kills
/// its own server): that code exists only under the cargo feature `e2e`, and even there only when
/// the hook's variable is set; a release build has no such code.
pub(crate) fn exit_now() {
    #[cfg(feature = "e2e")]
    if std::env::var_os(E2E_HOOK_ENV).is_some() {
        return;
    }
    std::process::exit(i32::from(EXIT_CODE));
}

/// The end-to-end build's hook: with it set, "Restart now" is simulated in process.
#[cfg(feature = "e2e")]
pub(crate) const E2E_HOOK_ENV: &str = "TT_E2E_RESTART_HOOK";

/// The supervisor this process declares, from `env` (a lookup, so tests pass their own). Only the
/// declaration counts.
pub(crate) fn detect(env: impl Fn(&str) -> Option<String>) -> Supervisor {
    let declared = env(SUPERVISOR_ENV).map(|v| v.trim().to_ascii_lowercase());
    match declared.as_deref() {
        Some(k @ ("systemd" | "docker" | "kubernetes")) => Supervisor {
            kind: k.to_owned(),
            how: SUPERVISOR_ENV.to_owned(),
        },
        Some("none") => Supervisor {
            kind: "none".to_owned(),
            how: format!("{SUPERVISOR_ENV}=none"),
        },
        Some(other) if !other.is_empty() => Supervisor {
            kind: "none".to_owned(),
            how: format!("{SUPERVISOR_ENV} is not one of systemd, docker, kubernetes, none"),
        },
        _ => Supervisor {
            kind: "none".to_owned(),
            how: "not declared".to_owned(),
        },
    }
}

/// [`detect`] from the process environment.
pub(crate) fn detect_process() -> Supervisor {
    detect(|k| std::env::var(k).ok())
}

impl Engine {
    /// The dry run of `restart-now`: needs a supervisor, lists what the restart will apply.
    pub(crate) fn restart_checked(&self) -> Result<Checked, Problem> {
        if self.supervisor.kind == "none" {
            return Err(Problem::new(
                Code::NoSupervisor,
                "this node declares no supervisor, so it won't exit: nothing would start it again",
            )
            .hint("Restart it yourself (systemd: `systemctl restart wrendns`; Compose: `docker compose restart`; Kubernetes: delete the pod). The shipped unit, bundles and chart set WRENDNS_SUPERVISOR."));
        }
        let staged = self.staged_ids();
        let kind = &self.supervisor.kind;
        let mut warnings = vec![format!(
            "The node cannot check that your {kind} will start it again; if it does not, start it by hand."
        )];
        if self.host.clustered() {
            if self.host.is_primary() {
                warnings.push(
                    "This node is the primary: configuration changes and cluster writes pause until it is back; replicas keep answering DNS from their snapshot."
                        .to_owned(),
                );
            }
            // A resolver of this node's own site that is up and serves DNS (a witness only votes,
            // and another site's resolver doesn't answer this site's clients).
            let site = self.host.site();
            let others_up = self
                .host
                .members()
                .iter()
                .filter(|m| {
                    m.up && !m.witness && m.site == site && m.id != self.node && m.name != self.node
                })
                .count();
            if others_up == 0 {
                warnings.push(if site.is_empty() {
                    "No other resolver in the cluster is up: DNS stops until this node is back."
                        .to_owned()
                } else {
                    format!(
                        "No other resolver in site `{site}` is up: DNS from this site stops until this node is back."
                    )
                });
            }
        }
        let window = u64::from(self.host.running_config().api.confirm_window_secs).max(180);
        Ok(Checked {
            effect: if staged.is_empty() {
                format!(
                    "Restarts {} in about 10 seconds; no staged change is waiting.",
                    self.node
                )
            } else {
                format!(
                    "Restarts {} and applies the staged change(s) ({}) at the start. If the node is not healthy within {window} seconds, twice in a row, they are dropped and it starts from the file.",
                    self.node,
                    staged.join(", ")
                )
            },
            restart_required: false,
            would_disconnect: false,
            warnings,
            checks: vec![GuardedCheck {
                name: "supervisor".to_owned(),
                ok: true,
                detail: format!("{kind} ({})", self.supervisor.how),
            }],
            proof_port: None,
            acknowledgements: Vec::new(),
            weakening: false,
            disconnect_detail: None,
            listeners: Vec::new(),
            host_facts: None,
            seen_client: None,
        })
    }

    /// Accepts the restart (the lock is held): audits, then drains and exits.
    pub(crate) async fn restart_apply(
        self: &Arc<Self>,
        c: &GuardedCaller,
        req: &GuardedApplyRequest,
        _pre: &Preview,
    ) -> Result<GuardedApplied, Problem> {
        self.restart_checked()?;
        let staged = self.staged_ids();
        // No audit, no restart: the row is written before anything stops.
        let audited = self.host.audit(
            &c.actor,
            "settings.guarded_restart",
            &self.target_name("restart-now"),
            &json!({
                "node": self.node,
                "supervisor": self.supervisor.kind,
                "staged": staged,
                "reason": req.reason.clone().or_else(|| c.actor.reason.clone()),
                "sessionKey": c.session,
                "remote": c.remote.map(|r| r.to_string()),
            }),
        );
        if let Err(e) = audited {
            return Err(Problem::new(
                Code::Unavailable,
                format!(
                    "the audit log can't record the restart, so the node was not restarted: {e}"
                ),
            ));
        }
        self.set_restarting();
        info!(node = %self.node, staged = ?staged, "guarded restart accepted");
        self.host.restart().await;
        Ok(GuardedApplied {
            status: "restarting".to_owned(),
            setting: wrendns_config::guarded::RESTART_NOW.to_owned(),
            node: self.node.clone(),
            pending_restart: false,
            pending_id: None,
            deadline_secs: None,
            confirm_token: None,
            new_address: None,
            proof: None,
            message: format!("{} is restarting.", self.node),
        })
    }
}

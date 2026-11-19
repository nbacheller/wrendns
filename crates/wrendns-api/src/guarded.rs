//! REQ: API-902, API-006, AGT-009 (T27.13; ADR-914, ADR-956) — the guarded-changes framework's
//! types: what the routes in [`crate::guarded_api`] take and answer, and the caller a backend is
//! told about. The machinery behind them (the preview store, the confirmation window, staging,
//! probation, the restart) is the node's, in `wrendns/src/guarded/`.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::auth::Actor;

/// Who is asking, as the guarded machinery needs to know it. Built by the routes from the
/// request's principal after the role and credential checks, so a backend can trust it.
#[derive(Debug, Clone)]
pub struct GuardedCaller {
    /// For the audit log.
    pub actor: Actor,
    /// The admin's user name: a preview, a pending change and a confirmation token are bound to it.
    pub username: String,
    /// The session's identifier (a hash; never the cookie): failed confirmations are counted
    /// against it, and a confirmation by session must come from the session's admin.
    pub session: Option<String>,
    /// When the session was created (Unix seconds); `None` for anything that isn't an
    /// interactive session. A weakening change needs this within the last 10 minutes.
    pub signed_in_at: Option<u64>,
    /// The listener the request arrived on, when it wasn't the node's main API listener (the
    /// confirmation window's temporary socket): what a `new_socket` proof compares.
    pub arrived_on: Option<SocketAddr>,
    /// The client address as the node's current trusted-proxy list sees it (audit, rate limits).
    pub remote: Option<std::net::IpAddr>,
    /// The client address as the *pending* trusted-proxy list would see it, set only when the
    /// request passes under that list (its peer is one of the new proxies and the client address
    /// differs from the peer): only the confirm route computes it, and a `proxy_list` proof needs
    /// it set (it is also what the result shows as the client now seen).
    pub remote_under_pending: Option<std::net::IpAddr>,
    /// Whether the request came over TLS (and which certificate answered it: the connection's
    /// marker; `new_cert` proofs read it).
    pub tls: bool,
}

/// REQ: API-902 (ADR-956 §7) — whether a REST path is one of the guarded framework's
/// (`/api/v1/guarded...`). Agents' plans refuse it (ADR-070's plan store never stores or replays
/// one), the MCP catalog names none, and the agent route policy refuses every change to it.
pub fn is_guarded_path(path: &str) -> bool {
    let p = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    p == "/api/v1/guarded" || p.starts_with("/api/v1/guarded/")
}

/// What the request arrived on, when it wasn't the main API listener: the confirmation window's
/// temporary listener tags every request it serves with this (an extension), so the confirm route
/// can tell which socket the admin reached the node through. Nothing a client sends can set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArrivedOn(pub SocketAddr);

/// How a node is supervised (ADR-956 §4a): from a declaration only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Supervisor {
    /// `systemd`, `docker`, `kubernetes` or `none`.
    pub kind: String,
    /// How the node knows: `WRENDNS_SUPERVISOR`, or `not declared`.
    pub how: String,
}

/// One guarded setting, as `GET /api/v1/guarded` lists it for this node.
#[allow(clippy::struct_excessive_bools)] // the flags are independent facts the UI shows
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuardedSetting {
    pub id: String,
    pub label: String,
    /// `window`, `immediate`, `staged` or `action`.
    pub mode: String,
    /// For a `window` setting: `new_socket`, `new_cert` or `proxy_list`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// The configuration paths it covers.
    pub paths: Vec<String>,
    /// A file sets it, and wins: the control is locked and shows the file.
    pub set_by_file: bool,
    /// A guarded entry holds a value for it (confirmed, applied or staged).
    pub has_entry: bool,
    /// A staged change waits for the node to restart.
    pub pending_restart: bool,
    /// A start has the entry on probation (it counts as applied once the node is healthy).
    pub on_probation: bool,
    /// A command-line clear is hiding the replicated entry until the primary's copy changes.
    pub suppressed: bool,
}

/// A window change waiting to be confirmed: what it is and how long is left, never its value, a
/// preview ID or the confirmation token.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuardedPending {
    /// The pending change's ID (what `confirm` and `cancel` name).
    pub id: String,
    pub setting: String,
    pub node: String,
    /// Seconds left, measured on the node's monotonic clock.
    pub deadline_secs: u64,
    /// Who made it.
    pub by: String,
}

/// How a guarded change ended.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuardedOutcome {
    pub setting: String,
    pub node: String,
    /// `confirmed`, `applied` or `rolled_back`.
    pub outcome: String,
    /// For `rolled_back`: `expired`, `cancelled`, `commit_failed`, `bind_failed` or
    /// `failed_start`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Unix seconds.
    pub at: u64,
}

/// `GET /api/v1/guarded`: what is guarded on a node and what is pending. No value, preview ID or
/// confirmation token is ever in it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuardedNodeStatus {
    pub node: String,
    pub supervisor: Supervisor,
    pub settings: Vec<GuardedSetting>,
    /// The window change waiting for confirmation, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<GuardedPending>,
    /// Staged changes waiting for a restart (setting IDs).
    pub pending_restart: Vec<String>,
    /// The latest outcomes (newest first, at most 10): applied, confirmed, or rolled back with
    /// the reason.
    pub outcomes: Vec<GuardedOutcome>,
    /// A restart was accepted and the node is on its way down.
    pub restarting: bool,
    /// `WRENDNS_IGNORE_GUARDED` is set: every guarded entry is ignored (health reason
    /// `guarded_ignored`).
    pub ignored: bool,
    /// The seconds a window change waits (`[api] confirm_window_secs`).
    pub confirm_window_secs: u32,
}

/// The answer of `GET /api/v1/guarded`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuardedStatus {
    /// This node first, then the members the primary can see.
    pub nodes: Vec<GuardedNodeStatus>,
}

/// The body of `POST /api/v1/guarded/{id}/preview`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuardedPreviewRequest {
    /// The node the change is for (its ID or name). Default: the node answering.
    #[serde(default)]
    pub node: Option<String>,
    /// The new value, in the shape the setting's configuration section has. Not needed for an
    /// action such as `restart-now`.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub value: Value,
    /// Options the setting's form carries (for example `copyState`).
    #[serde(default)]
    #[schema(value_type = Object)]
    pub options: Value,
}

/// One check of a dry run.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuardedCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// The dry run's answer. Nothing was changed.
#[allow(clippy::struct_excessive_bools)] // the flags are independent facts the UI shows
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuardedPreview {
    /// Send it back with the change. Bound to you, the node, the setting, the value and the
    /// configuration version; lives 5 minutes.
    pub preview_id: String,
    /// What to type to confirm (`<node> <setting>`).
    pub phrase: String,
    pub setting: String,
    pub node: String,
    pub mode: String,
    /// What the change does, in words.
    pub effect: String,
    /// The nodes it reaches (always one).
    pub nodes: Vec<String>,
    /// The change is weaker than what is set now: marked in red, and it needs a sign-in within
    /// the last 10 minutes.
    pub weakening: bool,
    pub restart_required: bool,
    /// Once confirmed, the node would have no API or DNS listener, or this request's listener
    /// would go.
    pub would_disconnect: bool,
    pub warnings: Vec<String>,
    pub checks: Vec<GuardedCheck>,
    /// For a window change that needs a temporary parallel listener (a TLS-only change): its port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_port: Option<u16>,
    /// A second acknowledgement the change needs (`acknowledgeNoAdmins`, ...), when it does.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub acknowledgements: Vec<String>,
    /// Seconds a window change would wait for its confirmation.
    pub window_secs: u32,
    /// The change needs a session signed in within the last 10 minutes (it weakens security, or
    /// it restarts the node).
    pub needs_recent_sign_in: bool,
    /// The setting is a file's: the control is locked.
    pub set_by_file: bool,
}

/// The body of `POST /api/v1/guarded/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuardedApplyRequest {
    pub preview_id: String,
    /// The phrase the preview returned, typed by the admin. The server compares it.
    pub confirm: String,
    /// Why: kept in the audit record.
    #[serde(default)]
    pub reason: Option<String>,
    /// The same value (and options) the preview was made for: a different one is
    /// 409 `preview_stale`.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub value: Value,
    #[serde(default)]
    #[schema(value_type = Object)]
    pub options: Value,
    /// The node the preview was for.
    #[serde(default)]
    pub node: Option<String>,
    /// The extra acknowledgements the preview named.
    #[serde(default)]
    pub acknowledge: Vec<String>,
}

/// What happened to a request to change a guarded setting.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuardedApplied {
    /// `applied` (200), `staged` (202), `pending` (202) or `restarting` (202).
    pub status: String,
    pub setting: String,
    pub node: String,
    /// `staged`: the change waits for the node's next start.
    pub pending_restart: bool,
    /// `pending`: the change waiting to be confirmed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_id: Option<String>,
    /// `pending`: seconds left, on the node's monotonic clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_secs: Option<u64>,
    /// `pending`: the single-use token that confirms it from the new address (put it in the
    /// address's `#fragment`, never in a query).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirm_token: Option<String>,
    /// `pending`: where to confirm, when the confirmation has to arrive somewhere new.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_address: Option<String>,
    /// `pending`: what the confirming request has to prove (`new_socket`, `new_cert`,
    /// `proxy_list`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// What to tell the admin, in words.
    pub message: String,
}

/// The body of `POST /api/v1/guarded/pending/{id}/confirm`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuardedConfirmRequest {
    /// The single-use token the change answered with. Without one, the request must be the same
    /// admin's session.
    #[serde(default)]
    pub confirm_token: Option<String>,
}

/// The answer of a confirmation or a cancellation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuardedResult {
    pub setting: String,
    pub node: String,
    /// `confirmed` or `rolled_back`.
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// For a `proxy_list` proof: the client address the node now sees for this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seen_client: Option<String>,
}

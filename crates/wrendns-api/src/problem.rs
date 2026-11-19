//! RFC 9457 problem details (`application/problem+json`) with a stable `code` and an
//! actionable `hint` (`spec/07` §1, AGT-001).

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

/// Stable error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    /// A parameter is missing, malformed, or out of range.
    InvalidParameter,
    /// No such route or object.
    NotFound,
    /// The `scope` needs clustering.
    UnsupportedScope,
    /// The feature is off or not ready (for example, the query log).
    Unavailable,
    /// A server-side failure; retrying may help.
    Internal,
    /// Not signed in, or the credentials are wrong.
    Unauthorized,
    /// The password was right; a TOTP code (or recovery code) is needed too.
    TotpRequired,
    /// Signed in, but the role or token scope doesn't allow this.
    Forbidden,
    /// A session-authenticated change without a valid `X-CSRF-Token` header.
    CsrfRejected,
    /// Conflicts with existing state (a duplicate name, the last admin).
    Conflict,
    /// The configuration changed since the version in `If-Match`: re-read and retry.
    VersionConflict,
    /// The change is well-formed but the resulting configuration is invalid (the detail
    /// names the field).
    InvalidConfig,
    /// Too many failed sign-ins; wait and retry.
    RateLimited,
    /// The cluster's configuration comes from Git (ADR-048): change it there.
    GitopsManaged,
    /// REQ: OPS-010 — a maintenance window longer than allowed (a day; two hours for agents).
    MaintenanceTooLong,
    /// REQ: OPS-010 — a maintenance request without a usable reason, or shorter than a minute.
    MaintenanceInvalid,
    /// REQ: OPS-010 — the node a request is for isn't reachable over the cluster channel.
    NodeUnreachable,
    /// REQ: OPS-010 — no cluster node by that ID, site, or pod name.
    NodeUnknown,
    /// REQ: OBS-024 — this node is already running a simulation (one at a time per node).
    SimulationBusy,
    /// REQ: OBS-024 — a simulation window that isn't a duration, or is longer than 7 days.
    SimulationWindow,
    /// REQ: CLU-013 — the cluster is pinned to an older version: configuration changes wait
    /// until it's unpinned (`diff` says what the pin holds back).
    ClusterPinned,
    /// REQ: CLU-013 — no version is baking (nothing to promote or abort).
    NoRollout,
    /// REQ: CLU-013 — no kept version by that number.
    VersionUnknown,
    /// REQ: CLU-013 — the version is listed but its files are no longer kept.
    VersionBlobsMissing,
    /// REQ: OBS-033 — a note's text is empty, longer than 200 characters, or not one line.
    AnnotationText,
    /// REQ: OBS-033 — a note's time is in the future or more than 7 days back.
    AnnotationTime,
    /// The route exists but not for this method (annotations are append-only).
    MethodNotAllowed,
    /// REQ: OBS-029 — a heatmap window too long for its grain, or a finer grain than the data.
    HeatmapWindow,
    /// The query log's privacy level hides what was asked for (names, or devices).
    PrivacyLevel,
    /// REQ: FLT-017 — Kubernetes workloads aren't on (`[kubernetes] enabled`, the chart's
    /// `kubernetes.enabled`).
    KubernetesDisabled,
    /// REQ: CLU-014 — a drill a precondition refuses (the detail says which: no other node,
    /// maintenance, a recent drill, a pinned or baking rollout, severe health).
    DrillRefused,
    /// REQ: CLU-014 — a drill is already running on the node.
    DrillActive,
    /// REQ: CLU-014 — a drill's targets, length, or reason are unusable (an unknown group, no
    /// device seen, more than 300 seconds).
    DrillTargets,
    /// REQ: CLU-001 (ADR-155) — the node to remove is the primary (it keeps the member list and
    /// can't remove itself).
    NodeIsPrimary,
    /// REQ: CLU-001 (ADR-155) — the node to remove is up: pass `force` to cut it off anyway.
    NodeIsUp,
    /// REQ: FLT-004 — this node doesn't download lists (role `resolver`, or the list fetcher
    /// didn't start): ask a node that does.
    ListsNotHere,
    /// REQ: DSC-004 (T25.6, ADR-1002) - this node doesn't run the network inventory's SNMP poller:
    /// the inventory is off, or another node is the designated one.
    DiscoveryNotHere,
    /// REQ: API-014 (ADR-903 §4) — a write sent `<redacted>` back for a credential whose entry
    /// now points somewhere else (or that has no stored value): enter the credential again.
    CredentialReentryRequired,
    /// REQ: API-014, OPS-014 (ADR-903 §3) — this node's secrets key can't be read, so nothing
    /// that needs it (a write with an `Idempotency-Key` that sets a credential) can be done.
    SecretsLocked,
    /// REQ: API-014, CLU-010 (ADR-903 §4) — the change needs a newer primary: it sends
    /// `<redacted>` back, which an older primary would store as the value; or (T23.2) it
    /// touches a credential and was forwarded by a node too old to say who made it.
    UpgradeRequired,
    /// REQ: DSC-001 (T25.2, ADR-907, CLU-010) — the network inventory's first write waits until no
    /// member runs an older version than the one that knows `[discovery]`.
    MembersTooOld,
    /// REQ: API-014 (T23.2, ADR-903 §4) — a path set through the API points where none may
    /// (under `/proc`, `/sys`, `/dev`, the data directory, or a key file), or a file holding a
    /// credential isn't under `[node] secret_file_dirs`.
    PathNotAllowed,
    /// REQ: OPS-014 (ADR-903 §2, decision 4) — the configuration files set this credential
    /// (inline or by file), and they win: the API can't set, replace or remove it.
    SetByFile,
    /// REQ: OPS-014 (ADR-903 §2) — a `*_ref` names a secret this node doesn't store.
    SecretMissing,
    /// REQ: API-015 (ADR-903 §4) — an entry or a node still uses the secret: remove those
    /// references first (or, when a member's references can't be read, `?force=true`).
    SecretInUse,
    /// REQ: API-015 (ADR-903 §4) — a secret's value (or a backup's passphrase) would cross the
    /// network in clear: use HTTPS, or the node itself (loopback).
    InsecureTransport,
    /// REQ: API-015, AGT-004 (ADR-903 §5) — agent tokens never do this, whatever their scopes
    /// (secret values, backups, router checks: a value would sit in an agent's plan and transcript).
    AgentNotAllowed,
    /// REQ: OBS-901 (ADR-958) — the live network map is off (`[map] enabled = false`).
    MapDisabled,
    /// REQ: OBS-901 (ADR-958) — 8 map streams are already open on this node.
    MapStreamsBusy,
    /// REQ: API-007 (T23.9, ADR-903 §8) — a backup with a passphrase needs an interactive session
    /// signed in within the last 10 minutes: sign in again (a token or Basic sign-in never can).
    ReauthRequired,
    /// REQ: API-902 (T27.13, ADR-956) — a managed kind that only the guarded module writes (`guarded`): use `/api/v1/guarded` (ADR-956 §2).
    GuardedOnly,
    /// REQ: API-902 (T27.13, ADR-956) — this node already has a guarded change waiting to be confirmed (or a restart waiting for its start): confirm, cancel or wait for it (ADR-956 §3).
    GuardedChangePending,
    /// REQ: API-902 (T27.13, ADR-956) — the value, the configuration or the node changed since the preview, or the preview is older than 5 minutes, or it was made by someone else: preview again.
    PreviewStale,
    /// REQ: API-902 (T27.13, ADR-956) — the node can't reach the primary to record the change, so it was not kept (it rolls back when the window ends).
    PrimaryUnreachable,
    /// REQ: API-902 (T27.13, ADR-956) — the change would leave the node with no API listener or no DNS listener, or removes the listener this request came in on.
    WouldDisconnectYou,
    /// REQ: API-902 (T27.13, ADR-956) — no admin could sign in afterwards.
    WouldLockOutAdmins,
    /// REQ: API-902 (T27.13, ADR-956) — the node declares no supervisor (`WRENDNS_SUPERVISOR`), so it won't exit: restart it yourself.
    NoSupervisor,
    /// REQ: API-902 (T27.13, ADR-956) — the new directory already holds state that a copy would overwrite.
    TargetNotEmpty,
    /// REQ: API-902 (T27.13, ADR-956) — this change needs the extra acknowledgement named in the preview.
    AcknowledgementRequired,
    /// REQ: API-902 (T27.13, ADR-956) — leave the cluster first, make the change, then join again.
    ClusteredNode,
    /// REQ: API-902 (T27.13, ADR-956) — a restart was accepted: guarded requests wait until the node is back.
    Restarting,
    /// REQ: API-902 (T27.13, ADR-956) — some stored secrets are still under the previous key.
    RotationIncomplete,
    /// REQ: API-902 (T27.13, ADR-956) — the target is on storage the node was told is ephemeral.
    DataDirNotPersistent,
    /// REQ: API-902 (T27.13, ADR-956) — only the primary forwards a guarded request for another node (the detail names it).
    NotPrimary,
    /// REQ: FLT-901 (T24.29, ADR-994) — a category list belongs to the catalog: it can be refreshed
    /// and put in shadow mode, not edited or deleted.
    OwnedByCategory,
    /// REQ: FLT-901 (T24.29, ADR-994 item 5) — this node is too small for the selection (the detail
    /// says what it would need).
    BudgetRefused,
    /// REQ: FLT-901 (T24.29, ADR-994 item 5) — a heavy selection (or one over `[filter]
    /// entry_budget`) needs `confirm=true` after its cost is shown.
    ConfirmRequired,
}

impl Code {
    const fn uri(self) -> &'static str {
        match self {
            Self::InvalidParameter => "https://wrendns.com/problems/invalid_parameter",
            Self::NotFound => "https://wrendns.com/problems/not_found",
            Self::UnsupportedScope => "https://wrendns.com/problems/unsupported_scope",
            Self::Unavailable => "https://wrendns.com/problems/unavailable",
            Self::Internal => "https://wrendns.com/problems/internal",
            Self::Unauthorized => "https://wrendns.com/problems/unauthorized",
            Self::TotpRequired => "https://wrendns.com/problems/totp_required",
            Self::Forbidden => "https://wrendns.com/problems/forbidden",
            Self::CsrfRejected => "https://wrendns.com/problems/csrf_rejected",
            Self::Conflict => "https://wrendns.com/problems/conflict",
            Self::RateLimited => "https://wrendns.com/problems/rate_limited",
            Self::VersionConflict => "https://wrendns.com/problems/version_conflict",
            Self::InvalidConfig => "https://wrendns.com/problems/invalid_config",
            Self::GitopsManaged => "https://wrendns.com/problems/gitops_managed",
            Self::MaintenanceTooLong => "https://wrendns.com/problems/maintenance_too_long",
            Self::MaintenanceInvalid => "https://wrendns.com/problems/maintenance_invalid",
            Self::NodeUnreachable => "https://wrendns.com/problems/node_unreachable",
            Self::NodeUnknown => "https://wrendns.com/problems/node_unknown",
            Self::SimulationBusy => "https://wrendns.com/problems/simulation_busy",
            Self::SimulationWindow => "https://wrendns.com/problems/simulation_window",
            Self::ClusterPinned => "https://wrendns.com/problems/cluster_pinned",
            Self::NoRollout => "https://wrendns.com/problems/no_rollout",
            Self::VersionUnknown => "https://wrendns.com/problems/version_unknown",
            Self::VersionBlobsMissing => "https://wrendns.com/problems/version_blobs_missing",
            Self::AnnotationText => "https://wrendns.com/problems/annotation_text",
            Self::AnnotationTime => "https://wrendns.com/problems/annotation_time",
            Self::MethodNotAllowed => "https://wrendns.com/problems/method_not_allowed",
            Self::HeatmapWindow => "https://wrendns.com/problems/heatmap_window",
            Self::PrivacyLevel => "https://wrendns.com/problems/privacy_level",
            Self::KubernetesDisabled => "https://wrendns.com/problems/kubernetes_disabled",
            Self::DrillRefused => "https://wrendns.com/problems/drill_refused",
            Self::DrillActive => "https://wrendns.com/problems/drill_active",
            Self::DrillTargets => "https://wrendns.com/problems/drill_targets",
            Self::NodeIsPrimary => "https://wrendns.com/problems/node_is_primary",
            Self::NodeIsUp => "https://wrendns.com/problems/node_is_up",
            Self::ListsNotHere => "https://wrendns.com/problems/lists_not_here",
            Self::DiscoveryNotHere => "https://wrendns.com/problems/discovery_not_here",
            Self::CredentialReentryRequired => {
                "https://wrendns.com/problems/credential_reentry_required"
            }
            Self::SecretsLocked => "https://wrendns.com/problems/secrets_locked",
            Self::UpgradeRequired => "https://wrendns.com/problems/upgrade_required",
            Self::MembersTooOld => "https://wrendns.com/problems/members_too_old",
            Self::PathNotAllowed => "https://wrendns.com/problems/path_not_allowed",
            Self::SetByFile => "https://wrendns.com/problems/set_by_file",
            Self::SecretMissing => "https://wrendns.com/problems/secret_missing",
            Self::SecretInUse => "https://wrendns.com/problems/secret_in_use",
            Self::InsecureTransport => "https://wrendns.com/problems/insecure_transport",
            Self::AgentNotAllowed => "https://wrendns.com/problems/agent_not_allowed",
            Self::MapDisabled => "https://wrendns.com/problems/map_disabled",
            Self::MapStreamsBusy => "https://wrendns.com/problems/map_streams_busy",
            Self::ReauthRequired => "https://wrendns.com/problems/reauth_required",
            Self::GuardedOnly => "https://wrendns.com/problems/guarded_only",
            Self::GuardedChangePending => "https://wrendns.com/problems/guarded_change_pending",
            Self::PreviewStale => "https://wrendns.com/problems/preview_stale",
            Self::PrimaryUnreachable => "https://wrendns.com/problems/primary_unreachable",
            Self::WouldDisconnectYou => "https://wrendns.com/problems/would_disconnect_you",
            Self::WouldLockOutAdmins => "https://wrendns.com/problems/would_lock_out_admins",
            Self::NoSupervisor => "https://wrendns.com/problems/no_supervisor",
            Self::TargetNotEmpty => "https://wrendns.com/problems/target_not_empty",
            Self::AcknowledgementRequired => {
                "https://wrendns.com/problems/acknowledgement_required"
            }
            Self::ClusteredNode => "https://wrendns.com/problems/clustered_node",
            Self::Restarting => "https://wrendns.com/problems/restarting",
            Self::RotationIncomplete => "https://wrendns.com/problems/rotation_incomplete",
            Self::DataDirNotPersistent => {
                "https://wrendns.com/problems/data_dir_not_persistent"
            }
            Self::NotPrimary => "https://wrendns.com/problems/not_primary",
            Self::OwnedByCategory => "https://wrendns.com/problems/owned_by_category",
            Self::BudgetRefused => "https://wrendns.com/problems/budget_refused",
            Self::ConfirmRequired => "https://wrendns.com/problems/confirm_required",
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::InvalidParameter => "Invalid parameter",
            Self::NotFound => "Not found",
            Self::UnsupportedScope => "Unsupported scope",
            Self::Unavailable => "Temporarily unavailable",
            Self::Internal => "Internal error",
            Self::Unauthorized => "Authentication required",
            Self::TotpRequired => "Second factor required",
            Self::Forbidden => "Not allowed",
            Self::CsrfRejected => "CSRF check failed",
            Self::Conflict => "Conflict",
            Self::RateLimited => "Too many attempts",
            Self::VersionConflict => "Configuration changed",
            Self::InvalidConfig => "Invalid configuration",
            Self::GitopsManaged => "Managed in Git",
            Self::MaintenanceTooLong => "Maintenance window too long",
            Self::MaintenanceInvalid => "Invalid maintenance request",
            Self::NodeUnreachable => "Node unreachable",
            Self::NodeUnknown => "Unknown node",
            Self::SimulationBusy => "Simulation already running",
            Self::SimulationWindow => "Invalid simulation window",
            Self::ClusterPinned => "Cluster pinned",
            Self::NoRollout => "No rollout in progress",
            Self::VersionUnknown => "Unknown version",
            Self::VersionBlobsMissing => "Version no longer kept",
            Self::AnnotationText => "Invalid note text",
            Self::AnnotationTime => "Invalid note time",
            Self::MethodNotAllowed => "Method not allowed",
            Self::HeatmapWindow => "Heatmap window too long",
            Self::PrivacyLevel => "Hidden by the privacy level",
            Self::KubernetesDisabled => "Kubernetes workloads are off",
            Self::DrillRefused => "Drill refused",
            Self::DrillActive => "A drill is already running",
            Self::DrillTargets => "Invalid drill request",
            Self::NodeIsPrimary => "The node is the primary",
            Self::NodeIsUp => "The node is up",
            Self::ListsNotHere => "Lists aren't downloaded here",
            Self::DiscoveryNotHere => "The network inventory doesn't run here",
            Self::CredentialReentryRequired => "Enter the credential again",
            Self::SecretsLocked => "Secrets key unavailable",
            Self::UpgradeRequired => "Upgrade needed",
            Self::MembersTooOld => "A member runs an older version",
            Self::PathNotAllowed => "Path not allowed",
            Self::SetByFile => "Set by the configuration files",
            Self::SecretMissing => "No such stored secret",
            Self::SecretInUse => "Secret in use",
            Self::InsecureTransport => "HTTPS needed",
            Self::AgentNotAllowed => "Not for agents",
            Self::MapDisabled => "The network map is off",
            Self::MapStreamsBusy => "Too many map streams",
            Self::ReauthRequired => "Recent sign-in needed",
            Self::GuardedOnly => "The setting is changed from the guarded form",
            Self::GuardedChangePending => "A guarded change is already pending",
            Self::PreviewStale => "The preview is out of date",
            Self::PrimaryUnreachable => "The primary can't be reached",
            Self::WouldDisconnectYou => "The change would cut you off",
            Self::WouldLockOutAdmins => "The change would lock every admin out",
            Self::NoSupervisor => "Nothing will restart the node",
            Self::TargetNotEmpty => "The target directory isn't empty",
            Self::AcknowledgementRequired => "A second acknowledgement is needed",
            Self::ClusteredNode => "The node is a cluster member",
            Self::Restarting => "The node is restarting",
            Self::RotationIncomplete => "A key rotation isn't finished",
            Self::DataDirNotPersistent => "The directory isn't persistent",
            Self::NotPrimary => "Ask the primary",
            Self::OwnedByCategory => "Owned by a category",
            Self::BudgetRefused => "The node is too small for that selection",
            Self::ConfirmRequired => "Confirm the cost",
        }
    }

    const fn status(self) -> StatusCode {
        match self {
            Self::InvalidParameter | Self::UnsupportedScope => StatusCode::BAD_REQUEST,
            Self::NotFound | Self::NodeUnknown | Self::VersionUnknown | Self::MapDisabled => {
                StatusCode::NOT_FOUND
            }
            Self::Unavailable | Self::NodeUnreachable | Self::SecretsLocked => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unauthorized | Self::TotpRequired => StatusCode::UNAUTHORIZED,
            Self::Forbidden
            | Self::CsrfRejected
            | Self::InsecureTransport
            | Self::AgentNotAllowed
            | Self::ReauthRequired => StatusCode::FORBIDDEN,
            Self::Conflict
            | Self::GitopsManaged
            | Self::SimulationBusy
            | Self::ClusterPinned
            | Self::NoRollout
            | Self::VersionBlobsMissing
            | Self::KubernetesDisabled
            | Self::DrillRefused
            | Self::DrillActive
            | Self::NodeIsPrimary
            | Self::NodeIsUp
            | Self::ListsNotHere
            | Self::DiscoveryNotHere
            | Self::UpgradeRequired
            | Self::MembersTooOld
            | Self::SetByFile
            | Self::GuardedOnly
            | Self::GuardedChangePending
            | Self::PreviewStale
            | Self::PrimaryUnreachable
            | Self::WouldDisconnectYou
            | Self::WouldLockOutAdmins
            | Self::NoSupervisor
            | Self::TargetNotEmpty
            | Self::AcknowledgementRequired
            | Self::ClusteredNode
            | Self::Restarting
            | Self::RotationIncomplete
            | Self::DataDirNotPersistent
            | Self::OwnedByCategory
            | Self::ConfirmRequired
            | Self::SecretInUse => StatusCode::CONFLICT,
            Self::NotPrimary => StatusCode::MISDIRECTED_REQUEST,
            Self::RateLimited | Self::MapStreamsBusy => StatusCode::TOO_MANY_REQUESTS,
            Self::VersionConflict => StatusCode::PRECONDITION_FAILED,
            Self::InvalidConfig
            | Self::MaintenanceTooLong
            | Self::MaintenanceInvalid
            | Self::SimulationWindow
            | Self::AnnotationText
            | Self::AnnotationTime
            | Self::HeatmapWindow
            | Self::PrivacyLevel
            | Self::DrillTargets
            | Self::CredentialReentryRequired
            | Self::PathNotAllowed
            | Self::BudgetRefused
            | Self::SecretMissing => StatusCode::UNPROCESSABLE_ENTITY,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
        }
    }
}

/// An API error.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(example = json!({
    "type": "https://wrendns.com/problems/invalid_parameter",
    "title": "Invalid parameter",
    "status": 400,
    "code": "invalid_parameter",
    "detail": "`from`: `yesterday`: expected RFC 3339 time (2026-10-03T12:00:00Z) or a relative offset (-24h)",
    "hint": "Use a relative offset such as -24h, or RFC 3339 such as 2026-10-03T00:00:00Z."
}))]
pub struct Problem {
    /// URI identifying the problem type.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// Short, human-readable summary of the problem type.
    pub title: &'static str,
    /// HTTP status code.
    pub status: u16,
    /// Stable machine-readable code.
    pub code: Code,
    /// What went wrong in this request.
    pub detail: String,
    /// What to do about it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// REQ: CLU-013 — with `cluster_pinned`: what the pin holds back, as JSON Patch operations
    /// from the pinned version's shared configuration to the one this node would publish.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<Object>>)]
    pub diff: Option<Box<serde_json::Value>>,
    /// Seconds to wait, sent as `Retry-After` (rate limits).
    #[serde(skip)]
    pub retry_after: Option<u64>,
}

impl Problem {
    pub fn new(code: Code, detail: impl Into<String>) -> Self {
        Self {
            kind: code.uri(),
            title: code.title(),
            status: code.status().as_u16(),
            code,
            detail: detail.into(),
            hint: None,
            diff: None,
            retry_after: None,
        }
    }

    /// Attaches the diff a `cluster_pinned` problem shows.
    #[must_use]
    pub fn diff(mut self, diff: serde_json::Value) -> Self {
        self.diff = Some(Box::new(diff));
        self
    }

    #[must_use]
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Sends `Retry-After: <seconds>` with the problem.
    #[must_use]
    pub fn retry_after(mut self, seconds: u64) -> Self {
        self.retry_after = Some(seconds);
        self
    }

    pub fn invalid(detail: impl Into<String>) -> Self {
        Self::new(Code::InvalidParameter, detail)
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(Code::NotFound, detail)
    }

    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::new(Code::Unavailable, detail)
    }

    /// The HTTP status this problem is sent with.
    pub fn code_status(&self) -> StatusCode {
        self.code.status()
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(Code::Internal, detail)
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let status = self.code.status();
        let body = serde_json::to_vec(&self).unwrap_or_default();
        let mut resp = (
            status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            body,
        )
            .into_response();
        if let Some(s) = self.retry_after
            && let Ok(v) = header::HeaderValue::from_str(&s.to_string())
        {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        resp
    }
}

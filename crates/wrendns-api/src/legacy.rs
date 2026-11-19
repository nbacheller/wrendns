//! Pre-rename spellings on the wire (ADR-1028; REQ: API-001, AGT-005).
//!
//! The API reads each of these as well as its new name, so a browser's open session, an agent's
//! script and a CLI of the previous version keep working through an upgrade, and a cluster of
//! nodes of both versions answers the same requests. Responses that name a header carry both
//! names. Nothing here is removed before the release that drops the old `wrendns` names
//! (spec/10 T33.2).

use axum::http::HeaderValue;

/// The reason header (`x-wrendns-reason` now).
pub const REASON: &str = "x-telltale-reason";
/// The agent software header (`x-wrendns-client` now).
pub const CLIENT: &str = "x-telltale-client";
/// The session cookie (`wrendns_session` now).
pub const SESSION_COOKIE: &str = "telltale_session";
/// The sign-in flow cookie (`wrendns_oidc` now).
pub const FLOW_COOKIE: &str = "telltale_oidc";
/// Backup response headers (`x-wrendns-backup-secrets` and `-warnings` now).
pub const BACKUP_SECRETS: &str = "x-telltale-backup-secrets";
pub const BACKUP_WARNINGS: &str = "x-telltale-backup-warnings";

/// Expires the old session cookie, sent with the new one's expiry on sign-out.
#[must_use]
pub fn clear_session_cookie() -> HeaderValue {
    HeaderValue::from_static("telltale_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

//! REQ: DSC-004, AGT-001..005 (T25.6, ADR-908, ADR-1002) — `POST /api/v1/discovery/snmp/test`: probe
//! one configured SNMP agent now and show what it answered (the capability record). The body names
//! the agent and nothing else: an address is never accepted (ADR-907). `?dryRun=true` lists the OIDs
//! a test would query and sends no packet. A test of an agent waits 60 s after the last one.
//! `Idempotency-Key` replays the first answer for 24 hours. Admin only (agents: `ops:discovery_test`
//! and a reason); audit-logged as `discovery.snmp_test`. The poll runs on the designated node: a
//! replica forwards to the primary (CLU-003), and a node that isn't designated says where it is.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use wrendns_store::state::Replay;

use crate::auth::Auth;
use crate::auth::routes::{principal, reason, remote};
use crate::config_api::{IDEMPOTENCY_KEY, PlainDryRun};
use crate::model::{SnmpTestRequest, SnmpTestResult};
use crate::problem::{Code, Problem};
use crate::{Shared, SnmpTestWrite};

/// The longest an agent name may be (the config's label rule).
pub const NAME_MAX: usize = 64;

/// The route (admin).
pub(crate) fn routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/discovery/snmp/test", post(snmp_test))
        .with_state((backend, auth))
}

/// This node doesn't run the network inventory's poller: it is off, or another node is designated.
pub fn not_here(enabled: bool, designated_node: Option<&str>) -> Problem {
    let detail = if enabled {
        "this node doesn't run the network inventory's SNMP poller".to_owned()
    } else {
        "the network inventory is off".to_owned()
    };
    let hint = match (enabled, designated_node) {
        (false, _) => "Turn on [discovery] (Settings → Network inventory) first.".to_owned(),
        (true, Some(n)) => format!("Ask the designated node: `{n}`."),
        (true, None) => {
            "Ask the designated node (the cluster's primary, or the node `[discovery] node` names)."
                .to_owned()
        }
    };
    Problem::new(Code::DiscoveryNotHere, detail).hint(hint)
}

/// An agent name checked: a non-empty label, never an address.
pub fn check_name(req: &SnmpTestRequest) -> Result<String, Problem> {
    let name = req.agent.trim();
    if name.is_empty() || name.len() > NAME_MAX || name.chars().any(char::is_control) {
        return Err(Problem::invalid("`agent`: name a configured SNMP agent")
            .hint("Use a name from GET /api/v1/discovery/status (`agents`)."));
    }
    if name.parse::<std::net::IpAddr>().is_ok() || name.parse::<std::net::SocketAddr>().is_ok() {
        return Err(
            Problem::invalid("`agent` takes a configured agent's name, not an address")
                .hint("The test never sends to an address given in a request (ADR-907)."),
        );
    }
    Ok(name.to_owned())
}

/// Test an SNMP agent.
///
/// Probes the agent named in the body, the way the poller's first poll does: one GETNEXT on the
/// root of each table it is configured for, and one GET of sysObjectID. The answer is the agent's
/// capability record: the security level reached, the engine ID (v3), and for each part of each
/// table, the MIB table that answered (or none). A table that did not answer is skipped by the
/// poller until the next test. Read-only: the client has no write PDU (ADR-908).
///
/// The body is `{"agent": "<name>"}` and nothing else: an address is refused (ADR-907).
/// `?dryRun=true` sends no packet and lists the OIDs a test would query. A test waits 60 seconds
/// after the previous test of the same agent (429 with `Retry-After`). It runs on the designated
/// node: a cluster replica forwards the request to the primary. `Idempotency-Key` replays the
/// first answer for 24 hours. Needs the admin role (agents: `ops:discovery_test` and a reason);
/// audit-logged as `discovery.snmp_test`.
#[utoipa::path(post, path = "/api/v1/discovery/snmp/test", tag = "stats",
    params(PlainDryRun),
    request_body(content = SnmpTestRequest, description = "The agent's name, and nothing else."),
    responses(
        (status = 200, body = SnmpTestResult, description = "The capability record (or, with dryRun, the OIDs a test would query)."),
        (status = 400, body = Problem, description = "A malformed body, an unknown field, or an address where a name belongs."),
        (status = 403, body = Problem, description = "Needs the admin role (agents: ops:discovery_test and a reason)."),
        (status = 404, body = Problem, description = "No SNMP agent by that name (the hint lists them)."),
        (status = 409, body = Problem, description = "The inventory is off, this node isn't the designated one (`discovery_not_here`), or an Idempotency-Key reused for another request."),
        (status = 429, body = Problem, description = "The agent was tested less than 60 seconds ago (Retry-After says how long)."),
        (status = 503, body = Problem, description = "The SNMP worker is down or busy, or a replica that can't reach the primary."),
    ))]
pub(crate) async fn snmp_test(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Query(query): Query<PlainDryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    body: Bytes,
) -> Response {
    let req: SnmpTestRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return Problem::invalid(format!("request body: {e}"))
                .hint("Send {\"agent\": \"<name>\"}: a configured agent's name and nothing else.")
                .into_response();
        }
    };
    let name = match check_name(&req) {
        Ok(n) => n,
        Err(e) => return e.into_response(),
    };
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let dry_run = query.dry_run.unwrap_or(false);
    // REQ: AGT-003 - a retried request gets the first answer; another request with the same key
    // is refused.
    let request = format!(
        "POST /discovery/snmp/test {}",
        serde_json::json!({ "agent": name })
    );
    let key = headers
        .get(IDEMPOTENCY_KEY)
        .and_then(|v| v.to_str().ok())
        .map(|k| format!("{}:{}", p.user_id, k.trim()))
        .filter(|k| !dry_run && k.len() > 2);
    // REQ: API-014 (ADR-903 §4) - the record keeps a keyed hash of the request, never its text.
    let fingerprint = if key.is_some() {
        match backend.idempotency_request(None, &request, None) {
            Ok(f) => Some(f),
            Err(e) => return e.into_response(),
        }
    } else {
        None
    };
    let now = backend.now_unix_seconds();
    if let Some(k) = &key {
        match auth.state().idempotent(k, now) {
            Ok(Some(r)) if fingerprint.as_ref() == Some(&r.request) => {
                return crate::config_api::replay(&r);
            }
            Ok(Some(_)) => {
                return Problem::new(
                    Code::Conflict,
                    "this Idempotency-Key was used for a different request",
                )
                .hint("Use a new key for each distinct request.")
                .into_response();
            }
            Ok(None) => {}
            Err(e) => return Problem::internal(e.to_string()).into_response(),
        }
    }
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let w = SnmpTestWrite {
        agent: name.clone(),
        dry_run,
        by: actor.name.clone(),
        reason: actor.reason.clone(),
    };
    match backend.snmp_test(w).await {
        Ok(r) => {
            if !dry_run {
                auth.record(
                    &actor,
                    "discovery.snmp_test",
                    &name,
                    &serde_json::json!({
                        "ok": r.ok,
                        "level": r.capability.as_ref().map(|c| c.level.clone()),
                        "error": r.error,
                        "node": r.node,
                    }),
                );
            }
            let text = serde_json::to_string(&r).unwrap_or_default();
            if let (Some(k), Some(fp)) = (&key, &fingerprint) {
                let rep = Replay {
                    request: fp.clone(),
                    status: StatusCode::OK.as_u16(),
                    response: text,
                };
                if let Err(e) = auth.state().remember_idempotent(k, &rep, now) {
                    tracing::warn!("idempotency key not stored: {e}");
                }
            }
            (StatusCode::OK, Json(r)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DSC-004, DSC-003 (`dsc_003_walk_cli_takes_agent_name_only`, API side) - the body names a
    /// configured agent: an address, a socket address and a blank are refused before anything
    /// else happens (ADR-907).
    #[test]
    fn dsc_004_snmp_test_takes_a_name_only() {
        let req = |a: &str| SnmpTestRequest { agent: a.into() };
        assert_eq!(check_name(&req(" gateway ")).unwrap(), "gateway");
        for bad in ["192.168.1.1", "10.0.0.1:161", "::1", "", "  ", "a\nb"] {
            let e = check_name(&req(bad)).unwrap_err();
            assert_eq!(e.status, 400, "{bad:?}");
        }
        assert!(check_name(&req(&"x".repeat(NAME_MAX + 1))).is_err());
        // Any other field is refused by name.
        assert!(
            serde_json::from_str::<SnmpTestRequest>(r#"{"agent":"gw","address":"10.0.0.1"}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<SnmpTestRequest>(r#"{"agent":"gw","dryRun":true}"#).is_err()
        );
    }

    /// REQ: DSC-004 - a node that doesn't run the poller says why, and where.
    #[test]
    fn dsc_004_not_here_names_the_designated_node() {
        let off = not_here(false, None);
        assert_eq!((off.code, off.status), (Code::DiscoveryNotHere, 409));
        assert!(off.detail.contains("off"));
        let other = not_here(true, Some("pi-a"));
        assert!(other.hint.as_deref().is_some_and(|h| h.contains("pi-a")));
    }
}

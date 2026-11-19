//! REQ: FLT-006, API-010, AGT-001 (T24.30, ADR-996) — a device's effective policy: the group it
//! lands in and the key that matched, then every filter and rule that applies to it, as a list of
//! sections the panel renders as they come. Read off the DNS path, through the same
//! identification a query and Explain use.
//!
//! **Extension point (ADR-996 section 4).** The panel knows how to draw a [`PolicySection`], not
//! which sections exist. A later feature (content categories, filter profiles) adds one section
//! with its own `id`; the panel, the MCP tool and the Explain link need no change.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, State};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::Shared;
use crate::problem::Problem;

pub(crate) fn routes(backend: Shared) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/clients/{id}/policy", get(client_policy))
        .with_state(backend)
}

/// A page in the UI a line comes from.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyLink {
    /// A UI route (`/groups`, `/lists`, `/rules`, ...).
    pub path: String,
    /// Its query parameters.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
}

/// One line of a section: a list, a service, a schedule, a rule, a rewrite, an upstream group.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyItem {
    /// What it is (`ads`, `tiktok`, `bedtime`, `example.com`).
    pub label: String,
    /// More, in words (`Mon-Fri 21:00-07:00`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// `on`, `off`, `in_effect`, `not_in_effect`, `not_applied`, `expired`, `shadow`, or absent when a line has no
    /// state of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// What gives the device this line: `group kids`, `device`, `everyone`, `a schedule`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// When it stops applying (a rule's expiry), Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_unix_seconds: Option<u64>,
    /// Where to change it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<PolicyLink>,
}

/// A titled group of lines. Sections are the panel's unit; it renders whatever arrives, in order.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicySection {
    /// `block`, `lists`, `services`, `safe_search`, `rewrites`, `schedules`, `rules`, `upstream`;
    /// new sections get new ids.
    pub id: String,
    pub title: String,
    /// One sentence that stands alone (T35.2): it names the group and the count, and never points at the page ("below", "these"), so the API and an agent read it as it is.
    #[schema(example = "Group kids uses the 3 lists it names.")]
    pub summary: String,
    pub items: Vec<PolicyItem>,
    /// Where the whole section is edited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<PolicyLink>,
}

/// One rung of the identification ladder (ADR-973, ADR-976).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRung {
    /// `client_id`, `edns_mac`, `neighbor_mac`, `kubernetes`, `ip`, `cidr`, `router_name`, `default`
    /// (the values Explain's `identifiedBy` uses).
    pub source: String,
    pub label: String,
    /// The rung that decided.
    pub matched: bool,
}

/// REQ: FLT-006, API-010 (T24.30, ADR-996) — what a replica observed of a device (its address, the
/// MAC its neighbor table holds, a client ID), sent to the primary so the primary applies its
/// configuration to the replica's observations and both give Explain's answer. Cluster-internal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyObservation {
    pub ip: String,
    #[serde(default)]
    pub mac: Option<[u8; 6]>,
    #[serde(default)]
    pub client_id: Option<String>,
    /// The configured device asked for by name, if one was.
    #[serde(default)]
    pub wanted: Option<String>,
}

/// REQ: FLT-006, API-010 (T24.30) — a device's effective policy.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientPolicy {
    /// What was asked for: a device's name, an address, or a workload.
    pub client: String,
    /// The configured device it is (a `[[client]]`'s name, or the workload's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// The address the policy was resolved for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// How it was recognized: the same word Explain's `client.identifiedBy` says.
    pub identified_by: String,
    /// The key that matched, written as a `[[client]] match` is. Absent for `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_key: Option<String>,
    /// The group whose settings apply.
    pub group: String,
    /// Where it came from: `device`, `network`, `router_name`, `kubernetes`, `default`.
    pub group_from: String,
    /// The network or router name that gave the group, when it isn't the device's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_key: Option<String>,
    /// Every group it is in, the first one's settings applying (the same as Explain's).
    pub groups: Vec<String>,
    /// The ladder a device is matched down, with the rung that decided.
    pub precedence: Vec<PolicyRung>,
    pub sections: Vec<PolicySection>,
    /// Caveats: the address was a stand-in, another device wins, no filter snapshot yet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// When it was read (Unix seconds); schedules and rule expiry are as of then.
    pub at_unix_seconds: u64,
    /// The node whose configuration answered (a replica asks the primary).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// The ladder `identify` walks, most specific first (ADR-973, ADR-976). Shared by the backend and
/// the docs, so they can't list a different order.
pub const PRECEDENCE: [(&str, &str); 8] = [
    ("client_id", "DoH/DoT client ID"),
    ("edns_mac", "MAC in the query (trusted networks)"),
    ("neighbor_mac", "MAC from the neighbor table"),
    ("kubernetes", "Kubernetes workload"),
    ("ip", "exact address"),
    ("cidr", "most specific network"),
    ("router_name", "the name a router gave it"),
    ("default", "no match: the default group"),
];

/// A device's effective policy (FLT-006, API-010).
///
/// `id` is a configured device's name, an address, or a Kubernetes workload
/// (`namespace/kind/name`). The answer names the group the device lands in and the key that
/// matched (the precedence is client ID, MAC, workload, address, network, router name, default),
/// then lists what applies as `sections`: the block response, the group's lists and blocked
/// services, safe search, rewrites, schedules with whether each is in effect now, the quick and
/// group rules with their expiry, and the upstream group. It is resolved with the same
/// identification a query and `GET /explain` use, so the two agree. In a cluster a replica asks
/// the primary. Needs `config:read` for an agent.
#[utoipa::path(get, path = "/api/v1/clients/{id}/policy", tag = "config",
    params(("id" = String, Path, description = "A device's name, an address, or a workload.")),
    responses(
        (status = 200, body = ClientPolicy, description = "The effective policy."),
        (status = 404, body = Problem, description = "Neither a configured device, an address, nor a known workload."),
    ))]
pub(crate) async fn client_policy(
    State(b): State<Shared>,
    ext: axum::http::Extensions,
    Path(id): Path<String>,
) -> Result<Json<ClientPolicy>, Problem> {
    let b = crate::request_backend(&b);
    let p = crate::blocking(move || {
        let mut p = b.client_policy(&id)?;
        let missing = b.missing_nodes();
        if !missing.is_empty() {
            p.missing_nodes = missing;
        }
        Ok(p)
    })
    .await?;
    // REQ: AGT-004 — a group-restricted agent reads its group's devices only.
    if let Some(g) = ext
        .get::<crate::auth::Principal>()
        .and_then(|p| p.agent.as_ref())
        .and_then(|a| a.group.as_deref())
        && !p.groups.iter().any(|x| x == g)
    {
        return Err(Problem::not_found(format!(
            "`{}` is not in the group this token is limited to",
            p.client
        )));
    }
    Ok(Json(p))
}

//! REQ: API-016 (T23.7, ADR-903 §2, §4, §5, ADR-921) — router integrations as a managed kind:
//! `[[router]]` entries made through the API or UI, stored in `state.db` by name (ADR-040).
//!
//! - **Admin only.** An operator is refused (403) and an agent never writes one (its scopes don't
//!   cover them, and its forbidden list refuses the checks). A forwarded write without a role
//!   (an older node) is refused (409 `upgrade_required`), as credential writes are.
//! - **The files win.** A router the configuration files define is read-only here (409
//!   `set_by_file`): ADR-040's rule for named entries.
//! - **Secrets are named.** `api_key_ref`, `api_secret_ref` and `password_ref` name stored
//!   secrets (422 `secret_missing` when none has that name, from `secret_references`). The API
//!   takes no file paths: `api_key_file`, `api_secret_file`, `password_file` and `tls_ca` are set
//!   in the configuration file (422, ADR-921). The certificate goes in as text (`tls_ca_pem`).

use telltale_api::ManagedWrite;
use telltale_api::auth::Role;
use telltale_api::problem::{Code, Problem};
use telltale_config::{Config, RouterConfig};

use crate::api_backend::{ManagedPlan, secret_references};
use crate::http::Sources;
use crate::managed::{Entries, Ovr};

/// The body fields an API router must not carry (the files set them).
const FILE_FIELDS: [&str; 4] = ["api_key_file", "api_secret_file", "password_file", "tls_ca"];

/// Who may change a router: an admin, through the API (never an agent). A write whose role an
/// older node didn't send is refused until that node is upgraded.
pub(crate) fn may_change(role: Option<Role>, agent: Option<&str>) -> Result<(), Problem> {
    if agent.is_some() {
        return Err(Problem::new(
            Code::AgentNotAllowed,
            "agents can't change router integrations",
        )
        .hint("Ask an admin to make this change in the UI."));
    }
    match role {
        Some(Role::Admin) => Ok(()),
        None => Err(Problem::new(
            Code::UpgradeRequired,
            "this change to a router needs an admin, and the node it was made on is too old to say who made it",
        )
        .hint("Upgrade that node first, or make the change on the primary.")),
        Some(_) => Err(Problem::new(
            Code::Forbidden,
            "only an admin can add, change or remove a router integration",
        )
        .hint("Ask an admin to make this change.")),
    }
}

/// Parses an API body into a router, named by the path. File paths are refused (ADR-921).
pub(crate) fn parse(name: &str, body: &serde_json::Value) -> Result<RouterConfig, Problem> {
    let Some(obj) = body.as_object() else {
        return Err(Problem::invalid(
            "the body must be a JSON object (a router's fields)",
        ));
    };
    for f in FILE_FIELDS {
        if obj.contains_key(f) {
            return Err(Problem::new(
                Code::InvalidConfig,
                format!("`{f}`: a router's file paths are set in the configuration file, not through the API"),
            )
            .hint("Put the file in the configuration file, or use a stored secret (`*_ref`) or `tls_ca_pem` for the certificate text."));
        }
    }
    // REQ: API-016 (review of T23.7, ADR-921) — certificate checking is turned off in the file
    // only. An API router has no file of its own, so only `false` (the default) is taken.
    if obj
        .get("tls_insecure_skip_verify")
        .is_some_and(|v| v.as_bool() != Some(false))
    {
        return Err(Problem::new(
            Code::InvalidConfig,
            "`tls_insecure_skip_verify`: a router's certificate can't be left unchecked through the API",
        )
        .hint("Trust the console's certificate with `tls_ca_pem` instead (the form's trust step)."));
    }
    let mut v = body.clone();
    // The path names the router; a body that also names it must agree.
    if let Some(n) = obj.get("name").and_then(serde_json::Value::as_str)
        && n != name
    {
        return Err(Problem::invalid(format!(
            "the body's name `{n}` isn't the path's `{name}`"
        )));
    }
    v["name"] = serde_json::Value::String(name.to_owned());
    serde_json::from_value::<RouterConfig>(v)
        .map_err(|e| Problem::new(Code::InvalidConfig, format!("router `{name}`: {e}")))
}

/// REQ: API-016 — plans a `PUT` or `DELETE` of a router (see the module comment).
pub(crate) fn plan(
    src: &Sources,
    state: &telltale_store::state::State,
    w: &ManagedWrite,
) -> Result<ManagedPlan, Problem> {
    may_change(w.role, w.agent.as_deref())?;
    let name = w.name.trim().to_owned();
    if name.is_empty() {
        return Err(Problem::invalid("the name is empty"));
    }
    let file = src.file_config.load_full();
    if file.router.iter().any(|r| r.name.as_str() == name) {
        return Err(Problem::new(
            Code::SetByFile,
            format!("router `{name}` is defined in the configuration files, which win: it's read-only here"),
        )
        .hint("Change it in the configuration file. The UI shows it as set by file."));
    }
    let mut entries: Entries = crate::managed::entries(state);
    let before_cfg: Config =
        crate::managed::merge(&file, &entries).unwrap_or_else(|_| (*file).clone());
    let before = before_cfg
        .router
        .iter()
        .find(|r| r.name.as_str() == name)
        .and_then(|r| serde_json::to_value(r).ok());
    let (body, stored) = if let Some(v) = &w.body {
        let cfg = parse(&name, v)?;
        let stored = serde_json::to_string(&cfg).map_err(|e| Problem::internal(e.to_string()))?;
        entries.routers.retain(|(n, _)| *n != name);
        entries.routers.push((name.clone(), Ovr::Set(cfg)));
        (Some(v.clone()), Some(stored))
    } else {
        if before.is_none() {
            return Err(Problem::not_found(format!("no router is named `{name}`")));
        }
        entries.routers.retain(|(n, _)| *n != name);
        (None, None)
    };
    let merged = crate::managed::merge(&file, &entries)
        .map_err(|errs| Problem::new(Code::InvalidConfig, errs.join("; ")))?;
    let after = merged
        .router
        .iter()
        .find(|r| r.name.as_str() == name)
        .and_then(|r| serde_json::to_value(r).ok());
    // OPS-014 (ADR-903 §4) — a reference names a stored secret; one pointed at another kind's
    // secret is a redirect, audited as such.
    let redirect = match &body {
        Some(b) => secret_references(src, w, &name, &before_cfg, b)?,
        None => None,
    };
    let mut warnings = telltale_config::validate_config(&merged).unwrap_or_default();
    if let Some(b) = &body
        && b.as_object()
            .is_some_and(|o| o.keys().any(|k| k.ends_with("_ref")))
        && src.cluster.is_some()
    {
        // REQ: OPS-014, CLU-010 (ADR-903 "Mixed versions") — members older than 0.8.0 refuse the
        // version that carries a `*_ref`.
        warnings.push(format!(
            "`{name}` names a stored secret: members older than 0.8.0 refuse this configuration version and keep their last good one until they're upgraded."
        ));
    }
    if redirect.is_some() {
        warnings.push(format!(
            "This points `{name}`'s credential at a secret another entry uses: the change is audited as credential.redirect and raises the credential_redirected alert."
        ));
    }
    Ok(ManagedPlan {
        name: name.clone(),
        before,
        after,
        body: stored,
        recent_queries: 0,
        impact: "Polled by this node at its interval (by the primary, for a stored credential); the names it reports reach DNS after the next poll.".to_owned(),
        warnings,
        also: Vec::new(),
        candidate: merged,
        redirect,
    })
}

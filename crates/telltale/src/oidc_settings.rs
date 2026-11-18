//! REQ: API-016 (T23.10, ADR-903 §6, ADR-967) — OIDC sign-in providers as a node-managed kind:
//! `[[auth.oidc.provider]]` entries made through the API or UI, stored in `state.db` by ID on the
//! primary (or a standalone node) and replicated to every member as the manifest's `node_managed`
//! blob (`node_managed.rs`).
//!
//! - **Admin only.** An operator is refused (403) and an agent never writes one (no scope; the
//!   agent forbidden list is the default). A forwarded write without a role (an older node) is
//!   refused (409 `upgrade_required`), as credential writes are.
//! - **The files win.** A provider the configuration files define is read-only here (409
//!   `set_by_file`): ADR-040's rule for named entries.
//! - **The secret is a name.** `client_secret_ref` names a stored secret (422 `secret_missing`
//!   when none has that name). The API takes no inline `client_secret` and no file path: those
//!   are set in the configuration file (ADR-921's reason: a path the API can set is a path an
//!   admin can point at any readable file).
//! - **`public_url` stays node-local.** A node without it shows the provider as inactive.

use telltale_api::ManagedWrite;
use telltale_api::auth::Role;
use telltale_api::model::{OidcProviderEntry, OidcProviderList, OidcRoleRuleInfo};
use telltale_api::problem::{Code, Problem};
use telltale_config::{Config, OidcProvider};

use crate::api_backend::{ManagedPlan, secret_references};
use crate::http::Sources;
use crate::managed::Entries;

/// The body fields an API provider must not carry (the files set them).
const FILE_FIELDS: [&str; 2] = ["client_secret", "client_secret_file"];

/// Who may change a provider: an admin, through the API (never an agent). A write whose role an
/// older node didn't send is refused until that node is upgraded.
pub(crate) fn may_change(role: Option<Role>, agent: Option<&str>) -> Result<(), Problem> {
    if agent.is_some() {
        return Err(Problem::new(
            Code::AgentNotAllowed,
            "agents can't change sign-in providers",
        )
        .hint("Ask an admin to make this change in the UI."));
    }
    match role {
        Some(Role::Admin) => Ok(()),
        None => Err(Problem::new(
            Code::UpgradeRequired,
            "this change to a sign-in provider needs an admin, and the node it was made on is too old to say who made it",
        )
        .hint("Upgrade that node first, or make the change on the primary.")),
        Some(_) => Err(Problem::new(
            Code::Forbidden,
            "only an admin can add, change or remove a sign-in provider",
        )
        .hint("Ask an admin to make this change.")),
    }
}

/// Parses an API body into a provider, named by the path. Secrets and file paths are refused.
pub(crate) fn parse(id: &str, body: &serde_json::Value) -> Result<OidcProvider, Problem> {
    let Some(obj) = body.as_object() else {
        return Err(Problem::invalid(
            "the body must be a JSON object (a provider's fields)",
        ));
    };
    for f in FILE_FIELDS {
        if obj.get(f).is_some_and(|v| !v.is_null()) {
            return Err(Problem::new(
                Code::InvalidConfig,
                format!("`{f}`: a provider's client secret is set in the configuration file, not through the API"),
            )
            .hint("Store the secret (Settings → Integrations & secrets) and name it in `client_secret_ref`."));
        }
    }
    if let Some(n) = obj.get("id").and_then(serde_json::Value::as_str)
        && n != id
    {
        return Err(Problem::invalid(format!(
            "the body's id `{n}` isn't the path's `{id}`"
        )));
    }
    let mut v = body.clone();
    v["id"] = serde_json::Value::String(id.to_owned());
    let p = serde_json::from_value::<OidcProvider>(v)
        .map_err(|e| Problem::new(Code::InvalidConfig, format!("provider `{id}`: {e}")))?;
    let errs = telltale_config::oidc_provider_errors(&p);
    if !errs.is_empty() {
        return Err(Problem::new(Code::InvalidConfig, errs.join("; ")));
    }
    Ok(p)
}

/// The stored body of `p`: its fields without the secret ones (references only).
fn stored(p: &OidcProvider) -> Result<String, Problem> {
    let mut v = serde_json::to_value(p).map_err(|e| Problem::internal(e.to_string()))?;
    if let Some(o) = v.as_object_mut() {
        for f in FILE_FIELDS {
            o.remove(f);
        }
    }
    Ok(v.to_string())
}

/// REQ: API-016 — plans a `PUT` or `DELETE` of a provider (see the module comment).
pub(crate) fn plan(
    src: &Sources,
    state: &telltale_store::state::State,
    w: &ManagedWrite,
) -> Result<ManagedPlan, Problem> {
    may_change(w.role, w.agent.as_deref())?;
    let id = w.name.trim().to_owned();
    if id.is_empty() {
        return Err(Problem::invalid("the id is empty"));
    }
    let file = src.file_config.load_full();
    if file.auth.oidc.provider.iter().any(|p| p.id.as_str() == id) {
        return Err(Problem::new(
            Code::SetByFile,
            format!("provider `{id}` is defined in the configuration files, which win: it's read-only here"),
        )
        .hint("Change it in the configuration file. The UI shows it as set by file."));
    }
    let mut entries: Entries = crate::managed::entries(state);
    let before_cfg: Config =
        crate::managed::merge(&file, &entries).unwrap_or_else(|_| (*file).clone());
    let find = |c: &Config| {
        c.auth
            .oidc
            .managed_provider
            .iter()
            .find(|p| p.id.as_str() == id)
            .and_then(|p| serde_json::to_value(p).ok())
    };
    let before = find(&before_cfg);
    let (body, stored_body) = if let Some(v) = &w.body {
        let p = parse(&id, v)?;
        let text = stored(&p)?;
        entries.oidc_providers.retain(|(n, _)| *n != id);
        entries.oidc_providers.push((id.clone(), p));
        (Some(v.clone()), Some(text))
    } else {
        if before.is_none() {
            return Err(Problem::not_found(format!("no provider is named `{id}`")));
        }
        entries.oidc_providers.retain(|(n, _)| *n != id);
        (None, None)
    };
    let merged = crate::managed::merge(&file, &entries)
        .map_err(|errs| Problem::new(Code::InvalidConfig, errs.join("; ")))?;
    let after = find(&merged);
    // OPS-014 (ADR-903 §4) — the reference names a stored secret; one pointed at another kind's
    // secret is a redirect, audited as such.
    let redirect = match &body {
        Some(b) => secret_references(src, w, &id, &before_cfg, b)?,
        None => None,
    };
    let mut warnings = telltale_config::validate_config(&merged).unwrap_or_default();
    if file.auth.oidc.public_url.is_empty() {
        warnings.push(format!(
            "this node has no [auth.oidc] public_url (it is node-local, set in each node's file): `{id}` is inactive here until it does."
        ));
    }
    if src.cluster.is_some() {
        // REQ: CLU-010 — a member older than this feature ignores the blob.
        warnings.push(
            "members older than this version ignore sign-in providers made in the UI until they're upgraded."
                .to_owned(),
        );
    }
    if redirect.is_some() {
        warnings.push(format!(
            "This points `{id}`'s client secret at a secret another entry uses: the change is audited as credential.redirect and raises the credential_redirected alert."
        ));
    }
    Ok(ManagedPlan {
        name: id,
        before,
        after,
        body: stored_body,
        recent_queries: 0,
        impact: "Applied on every node within seconds, without a restart: the sign-in button appears or goes, and the sessions of a removed provider end.".to_owned(),
        warnings,
        also: Vec::new(),
        candidate: merged,
        redirect,
    })
}

fn role_name(r: telltale_config::UserRole) -> &'static str {
    match r {
        telltale_config::UserRole::Viewer => "viewer",
        telltale_config::UserRole::Operator => "operator",
        telltale_config::UserRole::Admin => "admin",
    }
}

/// `GET /api/v1/oidc-providers`: the providers in effect on this node, the files' first.
pub(crate) fn list(src: &Sources) -> OidcProviderList {
    let cfg = src.config.load_full();
    let o = &cfg.auth.oidc;
    let status = src.auth.get().map(|a| a.oidc_status()).unwrap_or_default();
    let public_url = o.public_url.as_str().trim_end_matches('/').to_owned();
    let entry = |p: &OidcProvider, from_file: bool| -> OidcProviderEntry {
        let (secret_source, secret) = if p.client_secret_ref.is_some() {
            (
                "stored",
                p.client_secret_ref.as_ref().map(ToString::to_string),
            )
        } else if p.client_secret_file.is_some() {
            ("file", None)
        } else if p.client_secret.is_some() {
            ("inline", None)
        } else {
            ("none", None)
        };
        let secret_readable = match secret_source {
            "stored" => secret.as_deref().map(|n| src.secrets.readable(n).is_ok()),
            "file" | "inline" => Some(
                crate::secrets::Credential::of(
                    p.client_secret_file.as_ref(),
                    p.client_secret_ref.as_ref(),
                )
                .with_inline(p.client_secret.as_ref())
                .resolve(Some(&src.secrets))
                .is_ok(),
            ),
            _ => None,
        };
        let st = status.iter().find(|s| s.id == p.id.as_str());
        let (active, reason) = match (st, public_url.is_empty()) {
            (_, true) => (
                false,
                Some("this node has no [auth.oidc] public_url (set it in this node's file; it is node-local)".to_owned()),
            ),
            (Some(s), false) => (s.active, s.reason.clone()),
            (None, false) => (false, Some("not applied on this node yet".to_owned())),
        };
        OidcProviderEntry {
            id: p.id.to_string(),
            name: if p.name.is_empty() {
                p.id.to_string()
            } else {
                p.name.to_string()
            },
            issuer: telltale_config::credentials::url_shown(p.issuer.as_str()),
            client_id: p.client_id.to_string(),
            source: if from_file { "file" } else { "api" }.to_owned(),
            scopes: p.scopes.iter().map(ToString::to_string).collect(),
            username_claim: p.username_claim.to_string(),
            groups_claim: p.groups_claim.to_string(),
            roles: p
                .role
                .iter()
                .map(|r| OidcRoleRuleInfo {
                    group: r.group.to_string(),
                    role: role_name(r.role).to_owned(),
                })
                .collect(),
            default_role: p.default_role.map(|r| role_name(r).to_owned()),
            require_verified_email: p.require_verified_email,
            secret_source: secret_source.to_owned(),
            secret,
            secret_readable,
            active,
            reason,
            redirect_uri: (!public_url.is_empty())
                .then(|| format!("{public_url}/api/v1/auth/oidc/{}/callback", p.id)),
        }
    };
    let mut items: Vec<OidcProviderEntry> = o.provider.iter().map(|p| entry(p, true)).collect();
    items.extend(o.managed_provider.iter().map(|p| entry(p, false)));
    OidcProviderList {
        items,
        public_url: o.public_url.to_string(),
    }
}

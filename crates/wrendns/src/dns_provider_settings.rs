// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b, ADR-1084 as amended 2026-11-26, ADR-1104, ADR-903 §2, §4) - DNS providers
//! as a managed kind: `[[dns_provider]]` entries made through the API or UI, stored in `state.db`
//! by name and shared by the cluster.
//!
//! - **Admin only.** An operator is refused (403) and an agent never writes one (its scopes do not
//!   cover the routes, and the forbidden list refuses them: `agent_not_allowed`). A forwarded write
//!   without a role (an older node) is refused (409 `upgrade_required`).
//! - **The files win.** A provider the configuration files define is read-only here (409
//!   `set_by_file`): ADR-040's rule for named entries.
//! - **Secrets are named.** `credential_ref` names a stored secret (422 `secret_missing` when none
//!   has that name). The table has no inline credential and no file field, so a credential never sits
//!   in a body, a file, an audit record or a support package.
//! - **The gate.** The first provider waits until every cluster member's build knows the table (409
//!   `upgrade_required` naming the member; dry runs too): `Feature::DnsProviders` through
//!   `upgrade_gate::enforce_dns_providers`.
//! - **Not used yet.** The table stores and validates entries. The provider trait and the write
//!   engine (T36.10b step b3) is in `dns_provider/`; its Test, records and adopt actions are in
//!   `dns_provider_ops`. The reads say `not_used` for an entry with no provider code (every real kind has code; only the
//!   test-only `nocode...` entry does), `dry_run`
//!   until the first successful test, then `ready`.

use wrendns_api::ManagedWrite;
use wrendns_api::auth::Role;
use wrendns_api::model::{DnsProviderEntry, DnsProviderList};
use wrendns_api::problem::{Code, Problem};
use wrendns_config::{Config, DnsProviderConfig};

use crate::api_backend::ManagedPlan;
use crate::http::Sources;
use crate::managed::Entries;

/// Body fields that would hold a credential: refused with the way to do it right (the table's
/// own `deny_unknown_fields` refuses them too, but with a less helpful sentence).
const CREDENTIAL_FIELDS: [&str; 10] = [
    "credential",
    "credential_file",
    "secret",
    "client_secret",
    "token",
    "api_token",
    "api_key",
    "password",
    "private_key",
    "tsig_key",
];

/// Who may change a provider: an admin, through the API (never an agent). A write whose role an
/// older node didn't send is refused until that node is upgraded.
pub(crate) fn may_change(role: Option<Role>, agent: Option<&str>) -> Result<(), Problem> {
    if agent.is_some() {
        return Err(
            Problem::new(Code::AgentNotAllowed, "agents can't change DNS providers")
                .hint("Ask an admin to make this change in the UI."),
        );
    }
    match role {
        Some(Role::Admin) => Ok(()),
        None => Err(Problem::new(
            Code::UpgradeRequired,
            "this change to a DNS provider needs an admin, and the node it was made on is too old to say who made it",
        )
        .hint("Upgrade that node first, or make the change on the primary.")),
        Some(_) => Err(Problem::new(
            Code::Forbidden,
            "only an admin can add, change or remove a DNS provider",
        )
        .hint("Ask an admin to make this change.")),
    }
}

/// Parses an API body into a provider, named by the path. A credential in the body is refused.
pub(crate) fn parse(name: &str, body: &serde_json::Value) -> Result<DnsProviderConfig, Problem> {
    let Some(obj) = body.as_object() else {
        return Err(Problem::invalid(
            "the body must be a JSON object (a provider's fields)",
        ));
    };
    for f in CREDENTIAL_FIELDS {
        if obj.get(f).is_some_and(|v| !v.is_null()) {
            return Err(Problem::new(
                Code::InvalidConfig,
                format!("`{f}`: a DNS provider holds no credential: it names a stored secret"),
            )
            .hint("Store the secret (Settings, Integrations and secrets) and name it in `credential_ref`."));
        }
    }
    // The path names the provider; a body that also names it must agree.
    if let Some(n) = obj.get("name").and_then(serde_json::Value::as_str)
        && n != name
    {
        return Err(Problem::invalid(format!(
            "the body's name `{n}` isn't the path's `{name}`"
        )));
    }
    let mut v = body.clone();
    v["name"] = serde_json::Value::String(name.to_owned());
    serde_json::from_value::<DnsProviderConfig>(v)
        .map_err(|e| Problem::new(Code::InvalidConfig, format!("DNS provider `{name}`: {e}")))
}

/// 409 `upgrade_required`, naming the member, while the configuration `after` starts using DNS
/// providers and a cluster member's build does not know the table (dry runs too).
fn gate(src: &Sources, after: &Config) -> Result<(), Problem> {
    let before = src.config.load();
    crate::upgrade_gate::enforce_dns_providers(src.cluster.as_deref(), &before, after).map_err(
        |why| {
            Problem::new(Code::UpgradeRequired, why)
                .hint("Upgrade the member named, then repeat the write. DNS is unaffected.")
        },
    )
}

/// REQ: CLD-904 - plans a `PUT` or `DELETE` of a DNS provider (see the module comment).
pub(crate) fn plan(
    src: &Sources,
    state: &wrendns_store::state::State,
    w: &ManagedWrite,
) -> Result<ManagedPlan, Problem> {
    may_change(w.role, w.agent.as_deref())?;
    let name = w.name.trim().to_owned();
    if name.is_empty() {
        return Err(Problem::invalid("the name is empty"));
    }
    let file = src.file_config.load_full();
    if file.dns_provider.iter().any(|p| p.name.as_str() == name) {
        return Err(Problem::new(
            Code::SetByFile,
            format!("DNS provider `{name}` is defined in the configuration files, which win: it's read-only here"),
        )
        .hint("Change it in the configuration file. The UI shows it as set by file."));
    }
    let mut entries: Entries = crate::managed::entries(state);
    let before_cfg: Config =
        crate::managed::merge(&file, &entries).unwrap_or_else(|_| (*file).clone());
    let find = |c: &Config| {
        c.dns_provider
            .iter()
            .find(|p| p.name.as_str() == name)
            .and_then(|p| serde_json::to_value(p).ok())
    };
    let before = find(&before_cfg);
    let (stored, after_entry) = if let Some(v) = &w.body {
        let p = parse(&name, v)?;
        // The reference names a stored secret this node has (the value is never read here).
        if let Some(secret) = p.credential_ref.as_ref().map(|s| s.trim().to_owned())
            && !secret.is_empty()
            && !src.secrets.exists(&secret)
        {
            return Err(Problem::new(
                Code::SecretMissing,
                format!("`credential_ref`: no stored secret is named `{secret}` on this node"),
            )
            .hint(
                "Set the secret first (Settings, Integrations and secrets), then name it here.",
            ));
        }
        let text = serde_json::to_string(&p).map_err(|e| Problem::internal(e.to_string()))?;
        entries.dns_providers.retain(|(n, _)| *n != name);
        entries.dns_providers.push((name.clone(), p));
        (Some(text), true)
    } else {
        if before.is_none() {
            return Err(Problem::not_found(format!(
                "no DNS provider is named `{name}`"
            )));
        }
        entries.dns_providers.retain(|(n, _)| *n != name);
        (None, false)
    };
    let merged = crate::managed::merge(&file, &entries)
        .map_err(|errs| Problem::new(Code::InvalidConfig, errs.join("; ")))?;
    // REQ: DSC-908, CLD-904 - the first provider waits for every member's build to know the table.
    gate(src, &merged)?;
    let after = find(&merged);
    let mut warnings = wrendns_config::validate_config(&merged).unwrap_or_default();
    if after_entry
        && after
            .as_ref()
            .and_then(|a| a.get("dry_run"))
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    {
        warnings.push(
            "This provider starts in dry run: changes are recorded in the audit log and nothing is sent to the DNS host until its first successful test (the Test button)."
                .to_owned(),
        );
    }
    Ok(ManagedPlan {
        name: name.clone(),
        before,
        after,
        body: stored,
        recent_queries: 0,
        impact: "Stored and shared by the cluster with no restart. No DNS answer changes: a provider is called only to write a record at the DNS host when an admin or a certificate or dynamic-DNS task asks, always through the write engine (dry run, ownership ledger, rate limits), and never on the query path.".to_owned(),
        warnings,
        also: Vec::new(),
        candidate: merged,
        redirect: None,
        node: None,
    })
}

/// The configuration the table is read from: the one kept before the start-up hold's strip while
/// the hold keeps the providers out, else the running one.
fn read_config(src: &Sources, held: bool) -> std::sync::Arc<Config> {
    if held && let Some(c) = src.unheld.load_full() {
        c
    } else {
        src.config.load_full()
    }
}

/// REQ: CLD-904 - the providers in effect, for `GET /api/v1/dns-providers`: the settings as the
/// configuration holds them (the credential as a stored secret's name), where each comes from, and
/// whether this node stores the named secret. While the start-up hold keeps the providers out of
/// what this node serves, the list is what is configured, marked `held` with the reason.
pub(crate) fn list(src: &Sources) -> DnsProviderList {
    let held = crate::upgrade_gate::HOLD
        .held_features()
        .contains(&wrendns_cluster::gate::Feature::DnsProviders);
    let cfg = read_config(src, held);
    let file = src.file_config.load();
    let items = cfg
        .dns_provider
        .iter()
        .map(|p| entry(src, p, &file, held))
        .collect();
    DnsProviderList {
        items,
        held,
        held_reason: held
            .then(|| crate::upgrade_gate::HOLD.reason(src.cluster.as_deref()))
            .flatten(),
    }
}

fn entry(src: &Sources, p: &DnsProviderConfig, file: &Config, held: bool) -> DnsProviderEntry {
    let secret = p
        .credential_ref
        .as_ref()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let present = secret.as_deref().is_some_and(|n| src.secrets.exists(n));
    // REQ: CLD-919 - what the entry does now: no provider code (test-only entries), dry run until the first
    // successful test, or sending writes.
    let (state, detail) = if !crate::dns_provider::registry::has_code(p) {
        (
            "not_used",
            "Stored and validated. This build has no provider code for this entry, so Test says so and nothing is written at the DNS host.",
        )
    } else if p.dry_run {
        (
            "dry_run",
            "Dry run: changes are recorded in the audit log and none is sent, until the first successful test.",
        )
    } else {
        (
            "ready",
            "Tested. Changes are sent, within the entry's write limits, to records the node owns.",
        )
    };
    DnsProviderEntry {
        name: p.name.to_string(),
        kind: p.kind.as_str().to_owned(),
        zone: p.zone.to_string(),
        source: if file.dns_provider.iter().any(|f| f.name == p.name) {
            "file"
        } else {
            "api"
        }
        .to_owned(),
        definition: serde_json::to_value(p).unwrap_or_default(),
        dry_run: p.dry_run,
        credential_secret: secret,
        credential_present: present,
        state: state.to_owned(),
        detail: detail.to_owned(),
        held,
    }
}

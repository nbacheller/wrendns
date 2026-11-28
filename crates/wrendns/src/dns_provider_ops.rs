// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904, CLD-919 (T36.10b step b3; ADR-1084, ADR-1112) - the actions on a DNS provider that
//! go through the write engine: **Test** (check the credential and show its scope, and end the
//! entry's dry run on the first success), **verify** (a `delegated` entry's CNAME, T36.10b step b5:
//! a read that runs on the node asked), **records** (the zone with who owns each record set) and
//! **adopt** (take a record set into the ownership ledger).
//!
//! They run on the primary, which holds the ledger and writes the audit entries of provider calls: a
//! replica forwards them (`forward::dns_provider_op`, after the cluster gate for
//! `Feature::DnsProviderLedger`). The caller has already checked that the user is an admin and not an
//! agent. The credential is read from the stored secrets here and goes no further than the provider
//! call: it is in no answer, audit entry, log line or health reason.

use std::sync::Arc;

use serde_json::{Value, json};
use wrendns_api::auth::Role;
use wrendns_api::model::{
    DnsProviderAdopted, DnsProviderDelegationRecord, DnsProviderRecord, DnsProviderRecords,
    DnsProviderScope, DnsProviderTestResult, DnsProviderVerifyResult,
};
use wrendns_api::problem::{Code, Problem};
use wrendns_api::{Backend, DnsProviderAction, DnsProviderOp, ManagedKind, ManagedWrite};
use wrendns_config::DnsProviderConfig;

use crate::dns_provider::engine::{EngineError, Who, engine};
use crate::dns_provider::registry::{self, Handle};
use crate::dns_provider::{RecordType, Scope};
use crate::http::Sources;

/// The engine's refusal as an API problem.
pub(crate) fn problem(e: &EngineError) -> Problem {
    match e {
        EngineError::Refused(why) => Problem::new(Code::InvalidConfig, why.clone()),
        EngineError::NotOwned(why) => Problem::new(Code::Conflict, why.clone()).hint(
            "Adopt the record set (Settings, DNS providers, Records) if the node should manage it.",
        ),
        EngineError::Limited { retry_after, .. } | EngineError::Backoff(retry_after) => {
            Problem::new(Code::RateLimited, e.to_string()).retry_after(retry_after.as_secs().max(1))
        }
        EngineError::Provider(p) => Problem::unavailable(p.to_string())
            .hint("Test the provider (Settings, DNS providers) to see what it answers."),
        EngineError::Store(_) => Problem::internal(e.to_string()),
    }
}

fn scope_model(s: &Scope) -> DnsProviderScope {
    DnsProviderScope {
        zone: s.zone.clone(),
        summary: s.summary.clone(),
        record_types: s
            .record_types
            .iter()
            .map(|t| t.as_str().to_owned())
            .collect(),
        record_sets: s.record_sets.clone(),
        broader_than_needed: s.broader_than_needed,
        notes: s.notes.clone(),
    }
}

/// The entry `name`, as the node serves it (404 when there is none, 409 while the start-up hold keeps
/// it out).
fn find(src: &Sources, name: &str) -> Result<DnsProviderConfig, Problem> {
    let held = crate::upgrade_gate::HOLD.held_features();
    if held.contains(&wrendns_cluster::gate::Feature::DnsProviders) {
        return Err(Problem::new(
            Code::Conflict,
            "DNS providers are held out until every cluster member knows them",
        )
        .hint("See the health panel for the member the hold is waiting for."));
    }
    src.config
        .load()
        .dns_provider
        .iter()
        .find(|p| p.name.as_str() == name)
        .cloned()
        .ok_or_else(|| {
            if held.contains(&wrendns_cluster::gate::Feature::DnsProviderDelegation) {
                Problem::new(
                    Code::Conflict,
                    "delegated DNS providers are held out until every cluster member knows them",
                )
                .hint("See the health panel for the member the hold is waiting for.")
            } else {
                Problem::not_found(format!("no DNS provider `{name}`"))
            }
        })
}

/// The provider for an entry, with its credential read from the stored secrets.
fn handle(src: &Sources, cfg: &DnsProviderConfig) -> Result<Handle, Problem> {
    if cfg.is_delegated() {
        return Err(
            Problem::new(Code::Conflict, registry::BuildError::Delegated.to_string())
                .hint("Use Verify to check the CNAME made at the DNS host."),
        );
    }
    if !registry::has_code(cfg) {
        return Err(Problem::new(
            Code::Conflict,
            format!("no provider code for the `{}` kind yet", cfg.kind.as_str()),
        )
        .hint("Providers arrive one kind at a time; the table keeps the entry until then."));
    }
    let secret = match cfg
        .credential_ref
        .as_ref()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
    {
        Some(n) => Some(src.secrets.get(&n).map_err(|why| {
            Problem::new(
                Code::Conflict,
                format!("the credential `{n}` can't be read on this node: {why}"),
            )
        })?),
        None => None,
    };
    registry::build(cfg, secret).map_err(|e| Problem::new(Code::Conflict, e.to_string()))
}

fn who(op: &DnsProviderOp) -> Who {
    Who::User {
        name: op.by.clone(),
        kind: if op.by.contains(" via ") {
            "cluster"
        } else {
            "session"
        },
        remote: op.remote.clone(),
        reason: op.reason.clone(),
    }
}

/// Runs one action on this node (the primary, or a standalone node).
pub(crate) async fn run(src: &Arc<Sources>, op: DnsProviderOp) -> Result<Value, Problem> {
    // REQ: CLD-904 (T36.10b step b5) - Verify is a read on the node asked: no ledger, no write, so
    // it waits for no member's build.
    if matches!(op.action, DnsProviderAction::Verify) {
        return verify(src, &op).await;
    }
    // REQ: DSC-908, CLD-919 - the ledger rows and these actions wait for every member's build.
    crate::upgrade_gate::enforce(
        src.cluster.as_deref(),
        wrendns_cluster::gate::Feature::DnsProviderLedger,
    )
    .map_err(|why| {
        Problem::new(Code::UpgradeRequired, why)
            .hint("Upgrade the member named, then repeat this. DNS is unaffected.")
    })?;
    let cfg = find(src, &op.name)?;
    let auth = src
        .auth
        .get()
        .cloned()
        .ok_or_else(|| Problem::unavailable("the API isn't ready yet"))?;
    let who = who(&op);
    match &op.action {
        DnsProviderAction::Test => test(src, &cfg, &auth, &who, &op).await,
        DnsProviderAction::Verify => verify(src, &op).await,
        DnsProviderAction::Records => {
            let h = handle(src, &cfg)?;
            let views = engine()
                .records(&auth, &cfg, &h)
                .await
                .map_err(|e| problem(&e))?;
            json_of(&DnsProviderRecords {
                dry_run: cfg.dry_run,
                items: views
                    .into_iter()
                    .map(|v| DnsProviderRecord {
                        name: v.set.name,
                        record_type: v.set.rtype.as_str().to_owned(),
                        ttl: v.set.ttl,
                        values: v.set.values,
                        owner: v.owner.map(str::to_owned),
                        by: v.by,
                        at: v.at,
                    })
                    .collect(),
            })
        }
        DnsProviderAction::Adopt {
            record,
            record_type,
        } => {
            let rtype = RecordType::parse(record_type).ok_or_else(|| {
                Problem::new(
                    Code::InvalidConfig,
                    "`recordType`: only A, AAAA and TXT record sets are managed",
                )
            })?;
            let h = handle(src, &cfg)?;
            let o = engine()
                .adopt(&auth, &cfg, &h, &who, record, rtype)
                .await
                .map_err(|e| problem(&e))?;
            json_of(&DnsProviderAdopted {
                name: o.name,
                record_type: o.rtype.as_str().to_owned(),
                owner: o.owner.as_str().to_owned(),
                by: o.by,
                at: o.at,
            })
        }
    }
}

/// The Test action: the scope the credential has, and the end of dry run on the first success.
async fn test(
    src: &Arc<Sources>,
    cfg: &DnsProviderConfig,
    auth: &Arc<wrendns_api::auth::Auth>,
    who: &Who,
    op: &DnsProviderOp,
) -> Result<Value, Problem> {
    if cfg.is_delegated() {
        return json_of(&DnsProviderTestResult {
            ok: false,
            supported: false,
            dry_run: cfg.dry_run,
            dry_run_cleared: false,
            scope: None,
            error: Some(registry::BuildError::Delegated.to_string()),
            note: Some(
                "Nothing is stored for this DNS host, so there is no credential to test. Use Verify to check the CNAME made there."
                    .to_owned(),
            ),
        });
    }
    if !registry::has_code(cfg) {
        return json_of(&DnsProviderTestResult {
                ok: false,
                supported: false,
                dry_run: cfg.dry_run,
                dry_run_cleared: false,
                scope: None,
                error: Some(format!(
                    "no provider code for the `{}` kind yet",
                    cfg.kind.as_str()
                )),
                note: Some(
                    "The entry is stored and checked; this build cannot reach this kind of provider yet."
                        .to_owned(),
                ),
            });
    }
    let h = handle(src, cfg)?;
    let report = engine().test(auth, cfg, &h, who).await;
    let mut dry_run = cfg.dry_run;
    let mut cleared = false;
    let mut note = None;
    if report.ok && cfg.dry_run {
        match end_dry_run(src, cfg, op).await {
            Ok(()) => {
                dry_run = false;
                cleared = true;
            }
            Err(why) => note = Some(why),
        }
    }
    json_of(&DnsProviderTestResult {
        ok: report.ok,
        supported: true,
        dry_run,
        dry_run_cleared: cleared,
        scope: report.scope.as_ref().map(scope_model),
        error: report.error,
        note,
    })
}

/// Test seam: the upstreams and bounds a named entry's verification uses, instead of the node's own
/// upstream group and the public port. Tests only.
#[cfg(test)]
pub(crate) static TEST_LOOKUP: std::sync::Mutex<Vec<TestLookup>> =
    std::sync::Mutex::new(Vec::new());

/// An entry's name, the upstreams its verification asks and the bounds it uses.
#[cfg(test)]
pub(crate) type TestLookup = (
    String,
    Arc<dyn crate::authoritative::Upstreams>,
    crate::authoritative::Limits,
);

/// The upstreams the node finds a zone's name servers through, and the bounds of a lookup.
fn lookup(
    src: &Sources,
    name: &str,
) -> Result<
    (
        Arc<dyn crate::authoritative::Upstreams>,
        crate::authoritative::Limits,
    ),
    Problem,
> {
    #[cfg(test)]
    if let Some((_, up, limits)) = TEST_LOOKUP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(n, _, _)| n == name)
    {
        return Ok((Arc::clone(up), *limits));
    }
    let _ = name;
    let group = src.pipeline.rollover_group().ok_or_else(|| {
        Problem::unavailable("this node has no upstream to find the name servers through")
            .hint("Configure an upstream (Settings, Upstreams), then verify again.")
    })?;
    Ok((
        Arc::new(crate::authoritative::GroupUpstreams {
            group,
            budget: std::time::Duration::from_secs(5),
        }),
        crate::authoritative::Limits::default(),
    ))
}

/// The most records one Verify checks (a location each; the zone rarely holds more than a few).
const MAX_VERIFY: usize = 16;

/// REQ: CLD-904 (T36.10b step b5, ADR-1115) - Verify: asks the zone's authoritative name servers
/// (found through the configured upstreams, never this node's own data or cache) for each CNAME the
/// operator was to create, keeps the verdicts for the card and for health, and audits the check.
async fn verify(src: &Arc<Sources>, op: &DnsProviderOp) -> Result<Value, Problem> {
    let entry = find(src, &op.name)?;
    if !entry.is_delegated() {
        return Err(Problem::new(
            Code::Conflict,
            format!(
                "`{}` is a `{}` provider: only a `delegated` provider has a CNAME to verify",
                entry.name,
                entry.kind.as_str()
            ),
        )
        .hint("Use Test and show scope for a provider with an account."));
    }
    let cfg = src.config.load_full();
    let (validation, want) = crate::dns_provider::delegation::expected(&cfg, &entry);
    if validation.is_none() {
        return Err(Problem::new(
            Code::Conflict,
            format!(
                "`{}` delegates to a provider that is not in the configuration",
                entry.name
            ),
        )
        .hint("Change the entry to name a provider that holds the validation zone."));
    }
    let to_model = |w: &crate::dns_provider::delegation::Expected,
                    c: Option<&crate::dns_provider::delegation::Check>| {
        DnsProviderDelegationRecord {
            location: w.location.clone(),
            name: w.name.clone(),
            target: w.target.clone(),
            verified: c.map(|c| c.verified),
            reason: c.map(|c| c.reason.clone()),
            checked_at: c.map(|c| c.checked_at),
        }
    };
    // No location uses the zone yet: the template names what to create, and there is nothing to ask.
    if want.iter().all(|w| w.location.is_none()) {
        return json_of(&DnsProviderVerifyResult {
            ok: false,
            records: want.iter().map(|w| to_model(w, None)).collect(),
            note: Some(
                "No location uses this zone yet, so there is nothing to verify. Create a location in it, then create the CNAME shown and verify again."
                    .to_owned(),
            ),
        });
    }
    let (up, limits) = lookup(src, entry.name.as_str())?;
    let mut checks = Vec::new();
    let mut truncated = false;
    for (i, w) in want.iter().enumerate() {
        if i >= MAX_VERIFY {
            truncated = true;
            break;
        }
        checks.push(
            crate::dns_provider::delegation::verify(up.as_ref(), &limits, entry.zone.as_str(), w)
                .await,
        );
    }
    let ok = !truncated && checks.iter().all(|c| c.verified);
    if let Some(auth) = src.auth.get() {
        crate::dns_provider::engine::note(
            auth,
            &who(op),
            "dns_provider.verify",
            entry.name.as_str(),
            json!({
                "verified": ok,
                "records": checks
                    .iter()
                    .map(|c| json!({ "name": c.name, "verified": c.verified }))
                    .collect::<Vec<_>>(),
            }),
        )
        .await;
    }
    let records = want
        .iter()
        .map(|w| {
            let c = checks
                .iter()
                .find(|c| c.name == w.name && c.target == w.target);
            to_model(w, c)
        })
        .collect();
    crate::dns_provider::delegation::record(entry.name.as_str(), checks);
    json_of(&DnsProviderVerifyResult {
        ok,
        records,
        note: truncated.then(|| format!("Only the first {MAX_VERIFY} records were checked.")),
    })
}

fn json_of<T: serde::Serialize>(v: &T) -> Result<Value, Problem> {
    serde_json::to_value(v).map_err(|e| Problem::internal(e.to_string()))
}

/// The first successful test ends the entry's dry run (ADR-1112 point 2): the same stored entry,
/// `dry_run` false, written through the ordinary managed write (so every member gets it and the
/// audit log shows it). An entry the files define keeps the file's setting.
pub(crate) async fn end_dry_run(
    src: &Arc<Sources>,
    cfg: &DnsProviderConfig,
    op: &DnsProviderOp,
) -> Result<(), String> {
    if src
        .file_config
        .load()
        .dns_provider
        .iter()
        .any(|p| p.name == cfg.name)
    {
        return Err(
            "This entry is defined in a configuration file, which keeps `dry_run = true`: set it to false there to send changes."
                .to_owned(),
        );
    }
    let backend = crate::api_backend::ApiBackend {
        src: Arc::clone(src),
    };
    let mut next = cfg.clone();
    next.dry_run = false;
    let body = serde_json::to_value(&next).map_err(|e| e.to_string())?;
    // The write names the configuration version it was decided against, so an edit saved while the
    // test ran is never overwritten with the entry as it was loaded: the entry is compared first
    // (changed: no write, the admin tests again) and a version conflict re-reads and tries again.
    let mut attempt = 0;
    loop {
        attempt += 1;
        let still_same = src
            .config
            .load()
            .dns_provider
            .iter()
            .find(|p| p.name == cfg.name)
            == Some(cfg);
        if !still_same {
            return Err(
                "The test passed, but the entry was changed while it ran, so dry run was left on: test it again."
                    .to_owned(),
            );
        }
        let version = match src.auth.get() {
            Some(a) => {
                let a = Arc::clone(a);
                tokio::task::spawn_blocking(move || a.state().config_version().ok())
                    .await
                    .ok()
                    .flatten()
            }
            None => None,
        };
        let Some(version) = version else {
            return Err(
                "The test passed, but dry run could not be ended: the configuration version could not be read."
                    .to_owned(),
            );
        };
        let done = backend
            .write_managed(ManagedWrite {
                kind: ManagedKind::DnsProvider,
                name: cfg.name.to_string(),
                body: Some(body.clone()),
                dry_run: false,
                expect: Some(version),
                by: op.by.clone(),
                simulate: None,
                role: Some(Role::Admin),
                agent: None,
                origin: None,
                node_view: None,
            })
            .await;
        match done {
            Ok(_) => break,
            Err(p) if p.code == Code::VersionConflict && attempt < 3 => {}
            Err(p) => {
                return Err(format!(
                    "The test passed, but dry run could not be ended: {}",
                    p.detail
                ));
            }
        }
    }
    if let Some(auth) = src.auth.get() {
        let who = who(op);
        crate::dns_provider::engine::note(
            auth,
            &who,
            "dns_provider.dry_run_ended",
            cfg.name.as_str(),
            json!({ "cause": "first successful test" }),
        )
        .await;
    }
    Ok(())
}

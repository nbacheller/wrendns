// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904, CLD-919 (T36.10b step b3; ADR-1084, ADR-1112) - the actions on a DNS provider that
//! go through the write engine: **Test** (check the credential and show its scope, and end the
//! entry's dry run on the first success), **records** (the zone with who owns each record set) and
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
    DnsProviderAdopted, DnsProviderRecord, DnsProviderRecords, DnsProviderScope,
    DnsProviderTestResult,
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
    if crate::upgrade_gate::HOLD
        .held_features()
        .contains(&wrendns_cluster::gate::Feature::DnsProviders)
    {
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
        .ok_or_else(|| Problem::not_found(format!("no DNS provider `{name}`")))
}

/// The provider for an entry, with its credential read from the stored secrets.
fn handle(src: &Sources, cfg: &DnsProviderConfig) -> Result<Handle, Problem> {
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

// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904, CLD-919, CLU-004 (T36.10b step b3; ADR-1084, ADR-1112) - the write engine: the one
//! way a record set is changed at a DNS provider.
//!
//! Every write goes through here, whoever asks (an admin's adopt, the certificate issuer, dynamic
//! DNS). The engine does the work around the provider's call, in this order:
//!
//! 1. the name must be inside the entry's zone and the type one of `A`, `AAAA`, `TXT`;
//! 2. a Retry-After backoff from an earlier 429 is honoured;
//! 3. the zone is read (reads run in dry run too), so a write that changes nothing is skipped and
//!    a record the node does not own is found;
//! 4. **ownership** (ADR-1112 point 1): a record set that exists and is not in the ledger is
//!    refused until an admin adopts it; the node changes and deletes only what it made or adopted;
//! 5. **dry run** (point 2): a dry-run entry records what would be written, in the audit log, and
//!    calls no write endpoint;
//! 6. **rate limits** (point 3): the entry's writes a minute and an hour, a refusal saying when to
//!    come back;
//! 7. the write, audited (old and new values and the provider's change ID, never the credential),
//!    the ledger updated, and a failure recorded as a health reason and nothing else (CLU-004).
//!
//! The engine runs on whatever task calls it, never on a DNS worker; its SQLite and audit calls run
//! on blocking threads.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::json;
use wrendns_api::auth::{Actor, Auth};
use wrendns_config::DnsProviderConfig;

use super::ledger::{Ledger, Owned, Owner};
use super::registry::Handle;
use super::{ProviderError, ProviderErrorKind, RecordSet, RecordType, Scope};

/// A 429 without a `Retry-After` backs the entry off this long, doubling with each one in a row up to
/// [`MAX_UNHINTED`] (design 4.5: doubling to 15 minutes).
const DEFAULT_BACKOFF: Duration = Duration::from_secs(30);
const MAX_UNHINTED: Duration = Duration::from_mins(15);
/// The longest a provider's `Retry-After` is honoured.
const MAX_BACKOFF: Duration = Duration::from_secs(3600);
#[allow(
    dead_code,
    reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
)]
const MINUTE: Duration = Duration::from_secs(60);
#[allow(
    dead_code,
    reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
)]
const HOUR: Duration = Duration::from_secs(3600);

/// Who asked for a change: the audit log's actor.
#[derive(Debug, Clone)]
pub(crate) enum Who {
    /// A person (or a node forwarding for one).
    User {
        name: String,
        kind: &'static str,
        remote: Option<String>,
        reason: Option<String>,
    },
    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    /// The node itself, for a cause (`acme renewal of cert.cluster`, `dynamic DNS for lan`).
    System { cause: String },
}

impl Who {
    fn actor(&self) -> Actor {
        match self {
            Self::User {
                name,
                kind,
                remote,
                reason,
            } => Actor {
                name: name.clone(),
                kind,
                remote: remote.clone(),
                reason: reason.clone(),
            },
            Self::System { cause } => {
                let mut a = Actor::system("dns-provider");
                a.reason = Some(cause.clone());
                a
            }
        }
    }

    /// The name the ledger keeps.
    fn by(&self) -> String {
        match self {
            Self::User { name, .. } => name.clone(),
            Self::System { cause } => format!("system: {cause}"),
        }
    }
}

#[allow(
    dead_code,
    reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
)]
/// What a change would be, or was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Plan {
    /// `create`, `update` or `delete`.
    pub(crate) action: &'static str,
    pub(crate) old: Option<RecordSet>,
    pub(crate) new: Option<RecordSet>,
}

#[allow(
    dead_code,
    reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
)]
/// What an engine call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Nothing to change: the record set is as asked (or already gone).
    Unchanged,
    /// Dry run: the change was recorded and nothing was sent.
    DryRun(Plan),
    /// The provider made the change.
    Written {
        plan: Plan,
        change_id: Option<String>,
    },
}

/// Why the engine did not change a record set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EngineError {
    /// The request itself is not allowed: outside the zone, another type, a bad value.
    Refused(String),
    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    /// The record set exists and the node does not own it: an admin adopts it first.
    NotOwned(String),
    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    /// The entry's own limit on writes: come back after `retry_after`.
    Limited {
        retry_after: Duration,
        why: &'static str,
    },
    /// The provider said to slow down: come back after `0`.
    Backoff(Duration),
    /// The provider's call failed (the text is scrubbed of the credential).
    Provider(ProviderError),
    /// The ledger or the audit log could not be written.
    Store(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(why) | Self::NotOwned(why) => f.write_str(why),
            Self::Limited { retry_after, why } => write!(
                f,
                "this provider's limit of {why} is reached: try again in {} s",
                retry_after.as_secs().max(1)
            ),
            Self::Backoff(d) => write!(
                f,
                "the provider asked to slow down: try again in {} s",
                d.as_secs().max(1)
            ),
            Self::Provider(e) => write!(f, "{e}"),
            Self::Store(why) => write!(f, "the change could not be recorded: {why}"),
        }
    }
}

impl std::error::Error for EngineError {}

/// What a test of a provider found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TestReport {
    pub(crate) ok: bool,
    pub(crate) scope: Option<Scope>,
    /// Why not, when `ok` is false (scrubbed of the credential).
    pub(crate) error: Option<String>,
}

/// A record set at the provider with who owns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RecordView {
    pub(crate) set: RecordSet,
    /// `created`, `adopted`, or `None` when the node does not own it.
    pub(crate) owner: Option<&'static str>,
    pub(crate) by: Option<String>,
    pub(crate) at: Option<u64>,
}

#[derive(Debug, Default)]
struct Slot {
    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    /// When the entry's writes were attempted, within the last hour.
    writes: VecDeque<Instant>,
    /// A 429's Retry-After: no write before this.
    backoff_until: Option<Instant>,
    /// 429s in a row without a `Retry-After` (the doubling).
    streak: u32,
    /// The latest failure, until a later call succeeds.
    failure: Option<String>,
}

/// The engine's memory: per entry, the write times, the backoff and the latest failure. Nothing here
/// is persisted (a restart starts the limits empty, as the DNS-side rate limiters do); the ledger is.
#[derive(Debug, Default)]
pub(crate) struct Engine {
    slots: Mutex<HashMap<String, Slot>>,
    /// Test clock: added to every reading of the time.
    skew_ms: std::sync::atomic::AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The process's engine.
pub(crate) fn engine() -> &'static Engine {
    static E: OnceLock<Engine> = OnceLock::new();
    E.get_or_init(Engine::default)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn target(cfg: &DnsProviderConfig, name: &str, rtype: RecordType) -> String {
    format!("{}/{name}/{}", cfg.name.as_str(), rtype.as_str())
}

fn set_json(s: Option<&RecordSet>) -> serde_json::Value {
    s.map_or(
        serde_json::Value::Null,
        |s| json!({ "ttl": s.ttl, "values": s.values }),
    )
}

/// An audit entry for a change the engine's callers make around a write (the end of a dry run).
pub(crate) async fn note(
    ctx: &Arc<Auth>,
    who: &Who,
    action: &'static str,
    target: &str,
    detail: serde_json::Value,
) {
    Engine::audit(ctx, who, action, target.to_owned(), detail).await;
}

/// Runs `f` on a blocking thread.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, EngineError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| EngineError::Store(e.to_string()))
}

impl Engine {
    fn now(&self) -> Instant {
        Instant::now()
            + Duration::from_millis(self.skew_ms.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Moves the engine's clock forward (tests: the hour passes without waiting for it).
    #[cfg(test)]
    pub(crate) fn advance(&self, d: Duration) {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        self.skew_ms
            .fetch_add(ms, std::sync::atomic::Ordering::Relaxed);
    }

    /// The entries whose latest call failed, with the (scrubbed) reason: the health reasons.
    pub(crate) fn failures(&self) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = lock(&self.slots)
            .iter()
            .filter_map(|(n, s)| s.failure.clone().map(|f| (n.clone(), f)))
            .collect();
        v.sort();
        v
    }

    /// The failures of the entries still in the table; a slot whose entry was deleted is dropped
    /// first, so its failure, limit and back-off do not outlive it (or reach a new entry of that name).
    pub(crate) fn failures_among(&self, names: &[String]) -> Vec<(String, String)> {
        lock(&self.slots).retain(|n, _| names.contains(n));
        self.failures()
    }

    fn fail(&self, name: &str, text: &str) {
        lock(&self.slots)
            .entry(name.to_owned())
            .or_default()
            .failure = Some(text.to_owned());
    }

    fn succeed(&self, name: &str) {
        if let Some(s) = lock(&self.slots).get_mut(name) {
            s.failure = None;
            s.streak = 0;
        }
    }

    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    /// Forgets an entry that left the table.
    pub(crate) fn forget(&self, name: &str) {
        lock(&self.slots).remove(name);
    }

    fn check_backoff(&self, name: &str) -> Result<(), EngineError> {
        let now = self.now();
        let g = lock(&self.slots);
        match g.get(name).and_then(|s| s.backoff_until) {
            Some(t) if t > now => Err(EngineError::Backoff(t.saturating_duration_since(now))),
            _ => Ok(()),
        }
    }

    fn back_off(&self, name: &str, after: Option<Duration>) {
        let mut g = lock(&self.slots);
        let slot = g.entry(name.to_owned()).or_default();
        let d = if let Some(a) = after {
            a.clamp(Duration::from_secs(1), MAX_BACKOFF)
        } else {
            let d = DEFAULT_BACKOFF
                .saturating_mul(1 << slot.streak.min(5))
                .min(MAX_UNHINTED);
            slot.streak += 1;
            d
        };
        slot.backoff_until = Some(self.now() + d);
    }

    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    /// Takes a place in the entry's per-minute and per-hour limits (ADR-1112 point 3).
    fn take_place(&self, cfg: &DnsProviderConfig) -> Result<(), EngineError> {
        let now = self.now();
        let mut g = lock(&self.slots);
        let slot = g.entry(cfg.name.as_str().to_owned()).or_default();
        while slot
            .writes
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= HOUR)
        {
            slot.writes.pop_front();
        }
        let per_hour = cfg.max_writes_per_hour as usize;
        let per_minute = cfg.max_writes_per_minute as usize;
        if slot.writes.len() >= per_hour {
            let oldest = slot.writes.front().copied().unwrap_or(now);
            return Err(EngineError::Limited {
                retry_after: HOUR.saturating_sub(now.saturating_duration_since(oldest)),
                why: "writes an hour",
            });
        }
        let recent: Vec<Instant> = slot
            .writes
            .iter()
            .copied()
            .filter(|t| now.saturating_duration_since(*t) < MINUTE)
            .collect();
        if recent.len() >= per_minute {
            let oldest = recent.first().copied().unwrap_or(now);
            return Err(EngineError::Limited {
                retry_after: MINUTE.saturating_sub(now.saturating_duration_since(oldest)),
                why: "writes a minute",
            });
        }
        slot.writes.push_back(now);
        Ok(())
    }

    /// Reads the zone, a failure scrubbed and kept as the entry's health reason.
    async fn read_zone(
        &self,
        cfg: &DnsProviderConfig,
        h: &Handle,
    ) -> Result<Vec<RecordSet>, EngineError> {
        // ADR-1112 point 7: every call waits out a back-off, reads included.
        self.check_backoff(cfg.name.as_str())?;
        match h.provider.list().await {
            Ok(v) => Ok(v),
            Err(e) => Err(self.provider_failed(cfg, h, e)),
        }
    }

    fn provider_failed(
        &self,
        cfg: &DnsProviderConfig,
        h: &Handle,
        e: ProviderError,
    ) -> EngineError {
        let e = h.scrub(e);
        if e.kind == ProviderErrorKind::RateLimited {
            self.back_off(cfg.name.as_str(), e.retry_after);
        }
        self.fail(cfg.name.as_str(), &e.to_string());
        EngineError::Provider(e)
    }

    async fn audit(
        ctx: &Arc<Auth>,
        who: &Who,
        action: &'static str,
        target: String,
        detail: serde_json::Value,
    ) {
        let (auth, actor) = (Arc::clone(ctx), who.actor());
        let _ = blocking(move || auth.record(&actor, action, &target, &detail)).await;
    }

    async fn owned(
        ctx: &Arc<Auth>,
        provider: &str,
        rtype: RecordType,
        name: &str,
    ) -> Result<Option<Owned>, EngineError> {
        let (auth, p, n) = (Arc::clone(ctx), provider.to_owned(), name.to_owned());
        blocking(move || Ledger(auth.state()).get(&p, rtype, &n)).await
    }

    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    /// Makes the record set exactly `want`.
    #[allow(clippy::too_many_lines)] // one pass of the numbered steps in the module comment
    pub(crate) async fn ensure(
        &self,
        ctx: &Arc<Auth>,
        cfg: &DnsProviderConfig,
        h: &Handle,
        who: &Who,
        want: &RecordSet,
    ) -> Result<Outcome, EngineError> {
        let want = RecordSet::checked(
            cfg.zone.as_str(),
            &want.name,
            want.rtype,
            want.ttl,
            &want.values,
        )
        .map_err(EngineError::Refused)?;
        let tgt = target(cfg, &want.name, want.rtype);
        let current = self
            .read_zone(cfg, h)
            .await?
            .into_iter()
            .find(|s| s.name == want.name && s.rtype == want.rtype);
        if current.as_ref() == Some(&want) {
            return Ok(Outcome::Unchanged);
        }
        let owned = Self::owned(ctx, cfg.name.as_str(), want.rtype, &want.name).await?;
        if current.is_some() && owned.is_none() {
            return Err(EngineError::NotOwned(format!(
                "`{}` {} exists at the provider and was not made by this node: an admin adopts it first (it is then changed, never before)",
                want.name,
                want.rtype.as_str()
            )));
        }
        let plan = Plan {
            action: if current.is_some() {
                "update"
            } else {
                "create"
            },
            old: current,
            new: Some(want.clone()),
        };
        if cfg.dry_run {
            Self::audit(
                ctx,
                who,
                "dns_provider.ensure",
                tgt,
                json!({ "action": plan.action, "dry_run": true, "outcome": "dry_run",
                        "old": set_json(plan.old.as_ref()), "new": set_json(plan.new.as_ref()) }),
            )
            .await;
            return Ok(Outcome::DryRun(plan));
        }
        self.take_place(cfg)?;
        match h.provider.ensure(&want).await {
            Err(e) => {
                let err = self.provider_failed(cfg, h, e);
                Self::audit(
                    ctx,
                    who,
                    "dns_provider.ensure",
                    tgt,
                    json!({ "action": plan.action, "dry_run": false, "outcome": "failed",
                            "error": err.to_string(),
                            "old": set_json(plan.old.as_ref()), "new": set_json(plan.new.as_ref()) }),
                )
                .await;
                Err(err)
            }
            Ok(change) => {
                self.succeed(cfg.name.as_str());
                Self::audit(
                    ctx,
                    who,
                    "dns_provider.ensure",
                    tgt,
                    json!({ "action": plan.action, "dry_run": false, "outcome": "written",
                            "change_id": change.id,
                            "old": set_json(plan.old.as_ref()), "new": set_json(plan.new.as_ref()) }),
                )
                .await;
                if owned.is_none() {
                    let row = Owned {
                        provider: cfg.name.as_str().to_owned(),
                        name: want.name.clone(),
                        rtype: want.rtype,
                        owner: Owner::Created,
                        by: who.by(),
                        at: now_secs(),
                        change_id: change.id.clone(),
                    };
                    let auth = Arc::clone(ctx);
                    blocking(move || Ledger(auth.state()).put(&row))
                        .await?
                        .map_err(EngineError::Store)?;
                }
                Ok(Outcome::Written {
                    plan,
                    change_id: change.id,
                })
            }
        }
    }

    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    /// Removes the record set of this name and type, when the node owns it.
    pub(crate) async fn delete(
        &self,
        ctx: &Arc<Auth>,
        cfg: &DnsProviderConfig,
        h: &Handle,
        who: &Who,
        name: &str,
        rtype: RecordType,
    ) -> Result<Outcome, EngineError> {
        let name = super::name_in_zone(name, cfg.zone.as_str()).map_err(EngineError::Refused)?;
        let tgt = target(cfg, &name, rtype);
        let current = self
            .read_zone(cfg, h)
            .await?
            .into_iter()
            .find(|s| s.name == name && s.rtype == rtype);
        let owned = Self::owned(ctx, cfg.name.as_str(), rtype, &name).await?;
        let Some(current) = current else {
            if owned.is_some() {
                let (auth, p, n) = (Arc::clone(ctx), cfg.name.as_str().to_owned(), name);
                blocking(move || Ledger(auth.state()).remove(&p, rtype, &n))
                    .await?
                    .map_err(EngineError::Store)?;
            }
            return Ok(Outcome::Unchanged);
        };
        if owned.is_none() {
            return Err(EngineError::NotOwned(format!(
                "`{name}` {} exists at the provider and was not made by this node: it is never deleted unless an admin adopts it",
                rtype.as_str()
            )));
        }
        let plan = Plan {
            action: "delete",
            old: Some(current),
            new: None,
        };
        if cfg.dry_run {
            Self::audit(
                ctx,
                who,
                "dns_provider.delete",
                tgt,
                json!({ "action": "delete", "dry_run": true, "outcome": "dry_run",
                        "old": set_json(plan.old.as_ref()) }),
            )
            .await;
            return Ok(Outcome::DryRun(plan));
        }
        self.take_place(cfg)?;
        match h.provider.delete(&name, rtype).await {
            Err(e) => {
                let err = self.provider_failed(cfg, h, e);
                Self::audit(
                    ctx,
                    who,
                    "dns_provider.delete",
                    tgt,
                    json!({ "action": "delete", "dry_run": false, "outcome": "failed",
                            "error": err.to_string(), "old": set_json(plan.old.as_ref()) }),
                )
                .await;
                Err(err)
            }
            Ok(change) => {
                self.succeed(cfg.name.as_str());
                Self::audit(
                    ctx,
                    who,
                    "dns_provider.delete",
                    tgt,
                    json!({ "action": "delete", "dry_run": false, "outcome": "written",
                            "change_id": change.id, "old": set_json(plan.old.as_ref()) }),
                )
                .await;
                let (auth, p) = (Arc::clone(ctx), cfg.name.as_str().to_owned());
                blocking(move || Ledger(auth.state()).remove(&p, rtype, &name))
                    .await?
                    .map_err(EngineError::Store)?;
                Ok(Outcome::Written {
                    plan,
                    change_id: change.id,
                })
            }
        }
    }

    /// An admin takes a record set at the provider into the ledger: the node may then change and
    /// delete it. Nothing is sent to the provider (it is a claim, not a write), so it works in dry
    /// run too.
    pub(crate) async fn adopt(
        &self,
        ctx: &Arc<Auth>,
        cfg: &DnsProviderConfig,
        h: &Handle,
        who: &Who,
        name: &str,
        rtype: RecordType,
    ) -> Result<Owned, EngineError> {
        let name = super::name_in_zone(name, cfg.zone.as_str()).map_err(EngineError::Refused)?;
        let current = self
            .read_zone(cfg, h)
            .await?
            .into_iter()
            .find(|s| s.name == name && s.rtype == rtype)
            .ok_or_else(|| {
                EngineError::Refused(format!(
                    "`{name}` {} is not at the provider: there is nothing to adopt",
                    rtype.as_str()
                ))
            })?;
        if let Some(o) = Self::owned(ctx, cfg.name.as_str(), rtype, &name).await? {
            return Ok(o);
        }
        let row = Owned {
            provider: cfg.name.as_str().to_owned(),
            name: name.clone(),
            rtype,
            owner: Owner::Adopted,
            by: who.by(),
            at: now_secs(),
            change_id: None,
        };
        let (auth, r) = (Arc::clone(ctx), row.clone());
        blocking(move || Ledger(auth.state()).put(&r))
            .await?
            .map_err(EngineError::Store)?;
        Self::audit(
            ctx,
            who,
            "dns_provider.adopt",
            target(cfg, &name, rtype),
            json!({ "outcome": "adopted", "current": set_json(Some(&current)) }),
        )
        .await;
        Ok(row)
    }

    /// Checks the credential and reports what it may change. Nothing is written.
    pub(crate) async fn test(
        &self,
        ctx: &Arc<Auth>,
        cfg: &DnsProviderConfig,
        h: &Handle,
        who: &Who,
    ) -> TestReport {
        // ADR-1112 point 7: a test waits out a back-off too.
        let report = if let Err(wait) = self.check_backoff(cfg.name.as_str()) {
            TestReport {
                ok: false,
                scope: None,
                error: Some(wait.to_string()),
            }
        } else {
            match h.provider.scope().await {
                Ok(scope) => {
                    self.succeed(cfg.name.as_str());
                    TestReport {
                        ok: true,
                        scope: Some(scope),
                        error: None,
                    }
                }
                Err(e) => {
                    let err = self.provider_failed(cfg, h, e);
                    TestReport {
                        ok: false,
                        scope: None,
                        error: Some(err.to_string()),
                    }
                }
            }
        };
        Self::audit(
            ctx,
            who,
            "dns_provider.test",
            cfg.name.as_str().to_owned(),
            json!({ "ok": report.ok, "error": report.error,
                    "broader_than_needed": report.scope.as_ref().map(|s| s.broader_than_needed) }),
        )
        .await;
        report
    }

    /// Every record set at the provider with who owns it. A ledger row whose set is gone from the
    /// provider is not listed: the table shows what is at the provider, and the row is cleared the
    /// next time the node deletes that name (the engine's `delete` of a set that is gone forgets
    /// the row) or recreates it. No admin action depends on seeing it, so no forget control exists.
    pub(crate) async fn records(
        &self,
        ctx: &Arc<Auth>,
        cfg: &DnsProviderConfig,
        h: &Handle,
    ) -> Result<Vec<RecordView>, EngineError> {
        let zone = self.read_zone(cfg, h).await?;
        let (auth, p) = (Arc::clone(ctx), cfg.name.as_str().to_owned());
        let rows = blocking(move || Ledger(auth.state()).list(&p)).await?;
        let mut out: Vec<RecordView> = zone
            .into_iter()
            .map(|set| {
                let row = rows
                    .iter()
                    .find(|o| o.name == set.name && o.rtype == set.rtype);
                RecordView {
                    owner: row.map(|o| o.owner.as_str()),
                    by: row.map(|o| o.by.clone()),
                    at: row.map(|o| o.at),
                    set,
                }
            })
            .collect();
        out.sort_by(|a, b| (&a.set.name, a.set.rtype).cmp(&(&b.set.name, b.set.rtype)));
        Ok(out)
    }
}

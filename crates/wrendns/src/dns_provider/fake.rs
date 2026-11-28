// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904, CLD-919 (T36.10b step b3) - a provider that lives in memory, for tests.
//!
//! It is not a kind of the table: a configured entry keeps a real kind, and the registry hands the
//! fake to an entry whose name starts with `fake` (test builds and the browser tests' build only,
//! never a release). It holds a zone in a map, reports a scope a test sets, can be told to fail the
//! next calls (401, 403, 429 with a Retry-After, 5xx, a timeout), waits a set time, and logs every
//! call it receives.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::{Change, DnsProvider, Fut, ProviderError, RecordSet, RecordType, Scope};

/// One call the fake received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Call {
    /// `scope`, `list`, `ensure` or `delete`.
    pub(crate) op: &'static str,
    /// The record set's name, for `ensure` and `delete`.
    pub(crate) name: Option<String>,
}

#[derive(Debug, Default)]
struct Inner {
    zone: BTreeMap<(String, RecordType), RecordSet>,
    scope: Option<Scope>,
    failures: VecDeque<ProviderError>,
    write_failures: VecDeque<ProviderError>,
    latency: Duration,
    calls: Vec<Call>,
    changes: u64,
}

/// The in-memory provider.
#[derive(Debug)]
pub(crate) struct FakeProvider {
    zone_name: String,
    inner: Mutex<Inner>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeProvider {
    pub(crate) fn new(zone: &str) -> Self {
        Self {
            zone_name: zone.to_owned(),
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Puts a record set in the zone as if someone else made it (an unowned record).
    pub(crate) fn seed(&self, set: RecordSet) {
        lock(&self.inner)
            .zone
            .insert((set.name.clone(), set.rtype), set);
    }

    /// What the credential may change, as `scope` reports it.
    pub(crate) fn set_scope(&self, scope: Scope) {
        lock(&self.inner).scope = Some(scope);
    }

    /// The next call (of any kind) fails with `e`; calls after it are served again.
    pub(crate) fn fail_next(&self, e: ProviderError) {
        lock(&self.inner).failures.push_back(e);
    }

    /// The next write (`ensure` or `delete`) fails with `e`; reads are served.
    pub(crate) fn fail_next_write(&self, e: ProviderError) {
        lock(&self.inner).write_failures.push_back(e);
    }

    /// Every call answers after this long.
    pub(crate) fn set_latency(&self, d: Duration) {
        lock(&self.inner).latency = d;
    }

    /// The calls received, oldest first.
    pub(crate) fn calls(&self) -> Vec<Call> {
        lock(&self.inner).calls.clone()
    }

    /// How many `ensure` and `delete` calls arrived.
    pub(crate) fn writes(&self) -> usize {
        lock(&self.inner)
            .calls
            .iter()
            .filter(|c| c.op == "ensure" || c.op == "delete")
            .count()
    }

    /// The record set in the zone, if any.
    pub(crate) fn get(&self, name: &str, rtype: RecordType) -> Option<RecordSet> {
        lock(&self.inner)
            .zone
            .get(&(name.to_owned(), rtype))
            .cloned()
    }

    /// Logs the call, waits the latency, and takes the next injected failure.
    async fn enter(&self, op: &'static str, name: Option<&str>) -> Result<(), ProviderError> {
        let (latency, failure) = {
            let mut g = lock(&self.inner);
            g.calls.push(Call {
                op,
                name: name.map(str::to_owned),
            });
            let write = op == "ensure" || op == "delete";
            let failure = if write {
                g.write_failures
                    .pop_front()
                    .or_else(|| g.failures.pop_front())
            } else {
                g.failures.pop_front()
            };
            (g.latency, failure)
        };
        if !latency.is_zero() {
            tokio::time::sleep(latency).await;
        }
        failure.map_or(Ok(()), Err)
    }

    fn default_scope(&self) -> Scope {
        Scope {
            zone: self.zone_name.clone(),
            summary: format!(
                "the fake credential may change any record set in {}",
                self.zone_name
            ),
            record_types: vec![RecordType::A, RecordType::Aaaa, RecordType::Txt],
            record_sets: None,
            broader_than_needed: true,
            notes: vec!["This is the test provider: nothing is sent anywhere.".to_owned()],
        }
    }
}

impl DnsProvider for FakeProvider {
    fn kind(&self) -> &'static str {
        "fake"
    }

    fn scope(&self) -> Fut<'_, Scope> {
        Box::pin(async move {
            self.enter("scope", None).await?;
            Ok(lock(&self.inner)
                .scope
                .clone()
                .unwrap_or_else(|| self.default_scope()))
        })
    }

    fn list(&self) -> Fut<'_, Vec<RecordSet>> {
        Box::pin(async move {
            self.enter("list", None).await?;
            Ok(lock(&self.inner).zone.values().cloned().collect())
        })
    }

    fn ensure<'a>(&'a self, set: &'a RecordSet) -> Fut<'a, Change> {
        Box::pin(async move {
            self.enter("ensure", Some(&set.name)).await?;
            let mut g = lock(&self.inner);
            g.changes += 1;
            let id = format!("fake-{}", g.changes);
            g.zone.insert((set.name.clone(), set.rtype), set.clone());
            Ok(Change { id: Some(id) })
        })
    }

    fn delete<'a>(&'a self, name: &'a str, rtype: RecordType) -> Fut<'a, Change> {
        Box::pin(async move {
            self.enter("delete", Some(name)).await?;
            let mut g = lock(&self.inner);
            g.changes += 1;
            let id = format!("fake-{}", g.changes);
            g.zone.remove(&(name.to_owned(), rtype));
            Ok(Change { id: Some(id) })
        })
    }
}

/// The fakes by entry name: one per name, shared by every call, so a test can set it up before the
/// node reaches it and read its log afterwards.
static FAKES: Mutex<BTreeMap<String, Arc<FakeProvider>>> = Mutex::new(BTreeMap::new());

/// Whether an entry of this name is served by the fake.
pub(crate) fn is_fake_name(name: &str) -> bool {
    name.starts_with("fake")
}

/// The fake of the entry `name` for `zone`, made on first use. The browser tests' build seeds one
/// record nobody owns (`legacy.<zone>`) so the Adopt action has something to adopt.
pub(crate) fn for_entry(name: &str, zone: &str) -> Arc<FakeProvider> {
    let mut g = lock(&FAKES);
    Arc::clone(g.entry(name.to_owned()).or_insert_with(|| {
        let f = FakeProvider::new(zone);
        #[cfg(feature = "e2e")]
        f.seed(RecordSet {
            name: format!("legacy.{zone}"),
            rtype: RecordType::A,
            ttl: 300,
            values: vec!["192.0.2.10".to_owned()],
        });
        Arc::new(f)
    }))
}

/// A fake error for tests: the provider says 401 and quotes `quoted` (a credential, to see it go).
#[cfg(test)]
pub(crate) fn unauthorized_quoting(quoted: &str) -> ProviderError {
    ProviderError::new(
        super::ProviderErrorKind::Unauthorized,
        format!("invalid credential {quoted}"),
    )
}

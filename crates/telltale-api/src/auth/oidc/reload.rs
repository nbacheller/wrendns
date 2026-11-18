//! REQ: API-016 (T23.10, ADR-903 §7) — OIDC providers applied without a restart.
//!
//! `Auth.oidc` is an `ArcSwapOption`: a request takes the service it finds, and a change builds a
//! new one and swaps it in. The sign-ins in progress and what discovery read live in [`Shared`],
//! which every service of one `Auth` continues, so a rebuild neither cuts off a person who is
//! halfway through signing in nor reads an unchanged provider again. Rebuilds run one at a time
//! with a generation counter: a rebuild that a newer one overtook, before or after its discovery,
//! is discarded. A provider whose discovery fails keeps the settings it had, or is left out with
//! the reason. Sessions and the break-glass admin are never touched, except that a removed
//! provider's sessions end.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{Fetch, Oidc, OidcSettings, ProviderSettings, Shared, load_discovery};
use crate::auth::Auth;

/// What a provider is doing on this node: serving sign-ins, or why not.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProviderStatus {
    pub id: String,
    /// Whether the sign-in button works.
    pub active: bool,
    /// Why it isn't active, or what went wrong the last time it was read.
    pub reason: Option<String>,
}

impl ProviderStatus {
    pub fn active(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: true,
            reason: None,
        }
    }

    pub fn inactive(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: false,
            reason: Some(reason.into()),
        }
    }
}

/// How a rebuild ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reloaded {
    /// This rebuild's providers are in use now; the status of each.
    Applied(Vec<ProviderStatus>),
    /// A newer rebuild overtook this one, which changed nothing.
    Discarded,
}

impl Auth {
    /// The sign-in service in use, if any provider is configured.
    pub fn oidc(&self) -> Option<Arc<Oidc>> {
        self.oidc.load_full()
    }

    /// Attaches OIDC providers (in tests). Discovery is read at the first sign-in.
    pub fn set_oidc(&self, o: Oidc) {
        self.oidc.store(Some(Arc::new(o)));
    }

    /// REQ: API-016 — the providers of this node's configuration at startup: `settings` are
    /// served (discovery is lazy, so starting never waits on a provider), `skipped` are the ones
    /// that can't be, with the reason.
    pub fn start_oidc(&self, settings: OidcSettings, skipped: Vec<ProviderStatus>, fetch: Fetch) {
        let mut status: Vec<ProviderStatus> = settings
            .providers
            .iter()
            .map(|p| ProviderStatus::active(p.id.clone()))
            .collect();
        status.extend(skipped);
        let service = (!settings.providers.is_empty()).then(|| {
            Arc::new(Oidc::with_shared(
                settings,
                fetch,
                Arc::clone(&self.oidc_shared),
            ))
        });
        self.oidc.store(service);
        *self
            .oidc_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = status;
    }

    /// The status of every provider the configuration names, as of the last rebuild.
    pub fn oidc_status(&self) -> Vec<ProviderStatus> {
        self.oidc_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// REQ: API-016 — applies `settings` (the providers this node can serve) and `skipped` (the
    /// ones it can't, with why: no `public_url`, a secret it can't read). A provider that is new
    /// or has a new issuer is read now; one that can't be read keeps its previous settings, or is
    /// left out with the reason. Providers that are gone end their sessions. Returns the status
    /// of each, or [`Reloaded::Discarded`] when a newer rebuild overtook this one.
    #[allow(clippy::too_many_lines)] // one pass: read, decide, swap, end sessions
    pub async fn reload_oidc(
        &self,
        settings: OidcSettings,
        skipped: Vec<ProviderStatus>,
        fetch: Fetch,
    ) -> Reloaded {
        let ticket = self.oidc_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let _gate = self.oidc_gate.lock().await;
        // A newer rebuild queued behind this one makes this one pointless.
        if self.oidc_gen.load(Ordering::SeqCst) != ticket {
            return Reloaded::Discarded;
        }
        let previous = self.oidc.load_full();
        let mut serve: Vec<ProviderSettings> = Vec::new();
        let mut status: Vec<ProviderStatus> = Vec::new();
        for p in &settings.providers {
            if self.oidc_shared.is_read(&p.id, &p.issuer) {
                serve.push(p.clone());
                status.push(ProviderStatus::active(p.id.clone()));
                continue;
            }
            match load_discovery(&fetch, &p.issuer).await {
                Ok(d) => {
                    self.oidc_shared.put(&p.id, &p.issuer, Arc::new(d));
                    serve.push(p.clone());
                    status.push(ProviderStatus::active(p.id.clone()));
                }
                Err(e) => {
                    tracing::warn!(provider = %p.id, error = %e, "OIDC discovery failed on reload");
                    match previous
                        .as_ref()
                        .and_then(|o| o.settings.providers.iter().find(|q| q.id == p.id))
                    {
                        Some(old) => {
                            serve.push(old.clone());
                            status.push(ProviderStatus {
                                id: p.id.clone(),
                                active: true,
                                reason: Some(format!(
                                    "the new settings aren't applied yet, because the provider couldn't be read: {e}"
                                )),
                            });
                        }
                        None => status.push(ProviderStatus::inactive(
                            p.id.clone(),
                            format!("the provider couldn't be read: {e}"),
                        )),
                    }
                }
            }
        }
        // Discovery took time: a rebuild that arrived meanwhile has newer settings.
        if self.oidc_gen.load(Ordering::SeqCst) != ticket {
            return Reloaded::Discarded;
        }
        status.extend(skipped.iter().cloned());
        let next = OidcSettings {
            public_url: settings.public_url.clone(),
            providers: serve,
            mcp: settings.mcp.clone(),
        };
        if previous.as_ref().is_none_or(|o| o.settings != next) {
            let service = (!next.providers.is_empty()).then(|| {
                Arc::new(Oidc::with_shared(
                    next.clone(),
                    fetch,
                    Arc::clone(&self.oidc_shared),
                ))
            });
            self.oidc.store(service);
        }
        let keep: Vec<(String, String)> = next
            .providers
            .iter()
            .map(|p| (p.id.clone(), p.issuer.clone()))
            .collect();
        self.oidc_shared.retain(&keep);
        // A provider the configuration no longer names ends its sessions (one that is only
        // inactive here keeps them).
        let wanted: Vec<&str> = settings
            .providers
            .iter()
            .map(|p| p.id.as_str())
            .chain(skipped.iter().map(|s| s.id.as_str()))
            .collect();
        let gone: Vec<String> = self
            .oidc_status()
            .into_iter()
            .map(|s| s.id)
            .filter(|id| !wanted.contains(&id.as_str()))
            .collect();
        self.oidc_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone_from(&status);
        for id in gone {
            let state = Arc::clone(&self.state);
            let removed = id.clone();
            match tokio::task::spawn_blocking(move || state.delete_provider_sessions(&removed))
                .await
            {
                Ok(Ok(n)) => {
                    tracing::info!(provider = %id, sessions = n, "OIDC provider removed: its sessions ended");
                }
                Ok(Err(e)) => {
                    tracing::error!(provider = %id, error = %e, "can't end a removed provider's sessions");
                }
                Err(e) => {
                    tracing::error!(provider = %id, error = %e, "can't end a removed provider's sessions");
                }
            }
        }
        Reloaded::Applied(status)
    }
}

impl Shared {
    /// Whether discovery of `id` at `issuer` has been read (fresh or not: a stale copy refreshes
    /// itself at the next sign-in).
    fn is_read(&self, id: &str, issuer: &str) -> bool {
        self.cached(id, issuer).is_some()
    }

    fn put(&self, id: &str, issuer: &str, d: Arc<super::Discovered>) {
        self.store(id, issuer, d);
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b3; ADR-1084) - the registry: a configured entry (its kind, its zone
//! and the stored credential) to the code that talks to that provider.
//!
//! All four kinds have code: Azure DNS and Cloudflare (T36.10b step b4a and b4b) and Route 53 and
//! RFC 2136 (the rest of step b4); delegation is step b5. Test builds (and the browser tests' build)
//! also hand an entry named `nocode...` no code, so [`BuildError::NoCode`] and the Test route's
//! "no provider code" answer stay testable; no release build has that seam. Test builds (and the
//! browser tests' build) hand an entry named `fake...` the in-memory
//! fake instead; no release build does.

use std::sync::Arc;

use wrendns_config::{DnsProviderConfig, DnsProviderKind};

use super::DnsProvider;
use crate::secrets::value::SecretValue;

/// A provider ready to be called, with the credential it was built from (for scrubbing errors).
#[derive(Debug)]
pub(crate) struct Handle {
    pub(crate) provider: Arc<dyn DnsProvider>,
    /// The credential's value. It prints as `<redacted>`; the engine reads it only to scrub it out
    /// of a provider's error text.
    pub(crate) secret: Option<SecretValue>,
}

impl Handle {
    /// A provider's error with the credential taken out.
    pub(crate) fn scrub(&self, e: super::ProviderError) -> super::ProviderError {
        match &self.secret {
            Some(s) => e.redacted(s.expose()),
            None => e,
        }
    }
}

/// Why no provider could be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// A `delegated` entry has no account to call: the operator made one CNAME by hand and the
    /// challenge is written by the provider it delegates to (ADR-1115).
    Delegated,
    /// The entry has no code in this build. Only the test-only `nocode...` seam produces it; every
    /// real kind has code.
    #[cfg_attr(not(any(test, feature = "e2e")), allow(dead_code))]
    NoCode(&'static str),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Delegated => f.write_str(
                "a delegated entry has no account of its own: the challenge is written by the provider it delegates to",
            ),
            Self::NoCode(kind) => write!(f, "no provider code for the `{kind}` kind yet"),
        }
    }
}

/// Whether this build has provider code for the entry: every real kind has (the test-only `nocode...`
/// seam aside).
pub(crate) fn has_code(cfg: &DnsProviderConfig) -> bool {
    #[cfg(any(test, feature = "e2e"))]
    if super::fake::is_fake_name(cfg.name.as_str()) {
        return true;
    }
    // An entry named `nocode...` has no code in test builds, so the "no provider code" paths stay
    // testable now that every kind has some.
    #[cfg(any(test, feature = "e2e"))]
    if cfg.name.starts_with("nocode") {
        return false;
    }
    matches!(
        cfg.kind,
        DnsProviderKind::AzureDns
            | DnsProviderKind::Cloudflare
            | DnsProviderKind::Route53
            | DnsProviderKind::Rfc2136
    )
}

/// The provider for `cfg`, built with `secret` (the stored credential's value, when the entry names
/// one and this node can read it).
// The handle owns the credential from here on; a real kind uses it, the fake only keeps it.
// Release builds never fail (every kind has code); test builds fail for the `nocode...` seam.
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
pub(crate) fn build(
    cfg: &DnsProviderConfig,
    secret: Option<SecretValue>,
) -> Result<Handle, BuildError> {
    if cfg.is_delegated() {
        return Err(BuildError::Delegated);
    }
    #[cfg(any(test, feature = "e2e"))]
    if super::fake::is_fake_name(cfg.name.as_str()) {
        return Ok(Handle {
            provider: super::fake::for_entry(cfg.name.as_str(), cfg.zone.as_str()),
            secret,
        });
    }
    #[cfg(any(test, feature = "e2e"))]
    if !has_code(cfg) {
        return Err(BuildError::NoCode(cfg.kind.as_str()));
    }
    // The provider keeps its own copy of the credential (it signs in with it); the handle keeps one
    // to scrub errors with.
    let copy = |s: &Option<SecretValue>| {
        s.as_ref()
            .map(|v| SecretValue::from_text(zeroize::Zeroizing::new(v.expose().to_owned())))
    };
    // Test builds only: an entry whose name has a replay base (see `set_replay_base`) talks to a
    // local replay server instead of the provider.
    #[cfg(test)]
    if let Some(base) = replay_base(cfg.name.as_str()) {
        match cfg.kind {
            DnsProviderKind::AzureDns => {
                return Ok(Handle {
                    provider: Arc::new(super::azure::AzureDns::with_bases(
                        cfg,
                        copy(&secret),
                        &base,
                        &base,
                    )),
                    secret,
                });
            }
            DnsProviderKind::Cloudflare => {
                return Ok(Handle {
                    provider: Arc::new(super::cloudflare::Cloudflare::with_base(
                        cfg,
                        copy(&secret),
                        &base,
                    )),
                    secret,
                });
            }
            DnsProviderKind::Route53 | DnsProviderKind::Rfc2136 | DnsProviderKind::Delegated => {}
        }
    }
    // T36.10b step b4: every kind has code.
    let provider: Arc<dyn DnsProvider> = match cfg.kind {
        DnsProviderKind::AzureDns => Arc::new(super::azure::AzureDns::new(cfg, copy(&secret))),
        DnsProviderKind::Cloudflare => {
            Arc::new(super::cloudflare::Cloudflare::new(cfg, copy(&secret)))
        }
        DnsProviderKind::Route53 => Arc::new(super::route53::Route53::new(cfg, secret.as_ref())),
        DnsProviderKind::Rfc2136 => Arc::new(super::rfc2136::Rfc2136::new(cfg, secret.as_ref())),
        DnsProviderKind::Delegated => return Err(BuildError::Delegated),
    };
    Ok(Handle { provider, secret })
}

/// Test seam: the base URL a named entry's provider talks to (a local replay server).
#[cfg(test)]
static REPLAY: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());

/// Point the entry `name` (`azure_dns` or `cloudflare` kind) at a replay server. Tests only.
#[cfg(test)]
pub(crate) fn set_replay_base(name: &str, base: &str) {
    let mut r = REPLAY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    r.retain(|(n, _)| n != name);
    r.push((name.to_owned(), base.to_owned()));
}

#[cfg(test)]
fn replay_base(name: &str) -> Option<String> {
    REPLAY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, b)| b.clone())
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b3; ADR-1084) - the registry: a configured entry (its kind, its zone
//! and the stored credential) to the code that talks to that provider.
//!
//! Route 53 and RFC 2136 have provider code (T36.10b step b4); Azure DNS and Cloudflare arrive with
//! their own step b4 branches, and delegation is step b5. Until each arrives its kind answers [`BuildError::NoCode`], and the Test route
//! says so. Test builds (and the browser tests' build) hand an entry named `fake...` the in-memory
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
    /// The kind has no code in this build yet.
    NoCode(&'static str),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCode(kind) => write!(f, "no provider code for the `{kind}` kind yet"),
        }
    }
}

/// Whether this build has provider code for the entry: only the test provider so far.
pub(crate) fn has_code(cfg: &DnsProviderConfig) -> bool {
    #[cfg(any(test, feature = "e2e"))]
    if super::fake::is_fake_name(cfg.name.as_str()) {
        return true;
    }
    matches!(
        cfg.kind,
        DnsProviderKind::Route53 | DnsProviderKind::Rfc2136
    )
}

/// The provider for `cfg`, built with `secret` (the stored credential's value, when the entry names
/// one and this node can read it).
// The handle owns the credential from here on; a real kind uses it, the fake only keeps it.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn build(
    cfg: &DnsProviderConfig,
    secret: Option<SecretValue>,
) -> Result<Handle, BuildError> {
    #[cfg(any(test, feature = "e2e"))]
    if super::fake::is_fake_name(cfg.name.as_str()) {
        return Ok(Handle {
            provider: super::fake::for_entry(cfg.name.as_str(), cfg.zone.as_str()),
            secret,
        });
    }
    // T36.10b step b4: Route 53 and RFC 2136.
    if cfg.kind == DnsProviderKind::Route53 {
        return Ok(Handle {
            provider: Arc::new(super::route53::Route53::new(cfg, secret.as_ref())),
            secret,
        });
    }
    if cfg.kind == DnsProviderKind::Rfc2136 {
        return Ok(Handle {
            provider: Arc::new(super::rfc2136::Rfc2136::new(cfg, secret.as_ref())),
            secret,
        });
    }
    let _ = secret;
    // Each real kind arrives with its own step; none has code here yet.
    Err(BuildError::NoCode(match cfg.kind {
        DnsProviderKind::AzureDns => "azure_dns",
        DnsProviderKind::Cloudflare => "cloudflare",
        DnsProviderKind::Route53 => "route53",
        DnsProviderKind::Rfc2136 => "rfc2136",
    }))
}

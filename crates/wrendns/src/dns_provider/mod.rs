// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904, CLD-919 (T36.10b step b3; ADR-1084 and its 2026-11-27 amendment, ADR-1112) - the
//! DNS-provider trait, the registry that maps a configured kind to code, a fake for tests, and the
//! write engine that every write to a provider goes through.
//!
//! - **The trait** ([`DnsProvider`]): `scope`, `list`, `ensure` and `delete`, for `TXT`, `A` and
//!   `AAAA` record sets only, and only inside the entry's zone. The engine checks both before a
//!   provider sees a request, so a provider can not be asked for anything else.
//! - **The registry** ([`registry`]): a configured kind to a constructor. Route 53 and RFC 2136
//!   exist (T36.10b step b4); Azure DNS and Cloudflare answer "no provider code for this kind yet".
//! - **The fake** ([`fake`]): an in-memory zone for tests (and for the browser tests' build); never a
//!   kind in the table.
//! - **The engine** ([`engine`]): audit, dry run, the ownership ledger, per-entry rate limits and
//!   Retry-After backoff, failures as a health reason only. It runs off the DNS runtime (CLU-004).
//!
//! A provider's credential is held in a `SecretValue`: it prints as `<redacted>`, and every
//! [`ProviderError`] is scrubbed of it before it leaves the engine.

pub(crate) mod engine;
#[cfg(any(test, feature = "e2e"))]
pub(crate) mod fake;
pub(crate) mod ledger;
pub(crate) mod registry;
pub(crate) mod rfc2136;
#[cfg(test)]
mod rfc2136_tests;
pub(crate) mod route53;
#[cfg(test)]
mod route53_tests;
pub(crate) mod sigv4;
pub(crate) mod tsig;
pub(crate) mod xml;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A boxed future, as the provider trait's methods return.
pub(crate) type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, ProviderError>> + Send + 'a>>;

/// The record types a provider may be asked about: nothing else is ever written (CLD-904).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum RecordType {
    A,
    Aaaa,
    Txt,
}

impl RecordType {
    /// The type as DNS spells it.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Txt => "TXT",
        }
    }

    /// Reads a type, in any case; `None` for anything but `A`, `AAAA` and `TXT`.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "A" => Some(Self::A),
            "AAAA" => Some(Self::Aaaa),
            "TXT" => Some(Self::Txt),
            _ => None,
        }
    }
}

/// One record set: every value of one name and type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecordSet {
    /// The full name, lowercase, no trailing dot.
    pub(crate) name: String,
    pub(crate) rtype: RecordType,
    pub(crate) ttl: u32,
    /// The values, sorted, without duplicates.
    pub(crate) values: Vec<String>,
}

#[allow(
    dead_code,
    reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
)]
/// The most TTL a write may ask for (a day).
pub(crate) const MAX_TTL: u32 = 86_400;
#[allow(
    dead_code,
    reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
)]
/// The most values one record set may hold.
const MAX_VALUES: usize = 16;
#[allow(
    dead_code,
    reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
)]
/// The longest TXT value (four character strings of 255).
const MAX_TXT: usize = 1020;

/// `name` inside `zone`, normalised (lowercase, no trailing dot), or why not.
pub(crate) fn name_in_zone(name: &str, zone: &str) -> Result<String, String> {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let z = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() || n.len() > 253 || n.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!("`{name}` is not a record name"));
    }
    if n != z && !n.ends_with(&format!(".{z}")) {
        return Err(format!(
            "`{n}` is outside the zone `{z}`: only names inside it are written"
        ));
    }
    if n.split('.').any(|l| l.is_empty() || l.len() > 63) {
        return Err(format!("`{n}` is not a record name"));
    }
    Ok(n)
}

impl RecordSet {
    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    /// A record set checked against `zone`: the name inside it, one to sixteen values that suit the
    /// type, a TTL from 1 to a day. Values are sorted and deduplicated.
    pub(crate) fn checked(
        zone: &str,
        name: &str,
        rtype: RecordType,
        ttl: u32,
        values: &[String],
    ) -> Result<Self, String> {
        let name = name_in_zone(name, zone)?;
        if ttl == 0 || ttl > MAX_TTL {
            return Err(format!("the TTL is 1 to {MAX_TTL} seconds"));
        }
        let mut vs: Vec<String> = values.iter().map(|v| v.trim().to_owned()).collect();
        vs.sort();
        vs.dedup();
        if vs.is_empty() || vs.len() > MAX_VALUES || vs.iter().any(String::is_empty) {
            return Err(format!("a record set holds 1 to {MAX_VALUES} values"));
        }
        for v in &vs {
            let ok = match rtype {
                RecordType::A => v.parse::<std::net::Ipv4Addr>().is_ok(),
                RecordType::Aaaa => v.parse::<std::net::Ipv6Addr>().is_ok(),
                RecordType::Txt => v.len() <= MAX_TXT && !v.chars().any(char::is_control),
            };
            if !ok {
                return Err(format!("`{v}` is not a valid {} value", rtype.as_str()));
            }
        }
        Ok(Self {
            name,
            rtype,
            ttl,
            values: vs,
        })
    }
}

/// What a credential may change at a provider, as the provider reports it. Never holds a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Scope {
    /// The zone it was checked against.
    pub(crate) zone: String,
    /// One line for people.
    pub(crate) summary: String,
    /// The record types the credential may write.
    pub(crate) record_types: Vec<RecordType>,
    /// `Some(names)`: it may write only these record sets; `None`: any in the zone.
    pub(crate) record_sets: Option<Vec<String>>,
    /// The credential reaches further than this one zone (or all of it where a narrower grant
    /// exists), so the card says to narrow it.
    pub(crate) broader_than_needed: bool,
    /// Further notes for the card.
    pub(crate) notes: Vec<String>,
}

#[allow(
    dead_code,
    reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
)]
/// The provider's own identifier of a change (a request ID, a serial), when it gives one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Change {
    pub(crate) id: Option<String>,
}

#[allow(
    dead_code,
    reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
)]
/// Why a provider call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderErrorKind {
    /// 401: the credential is not accepted.
    Unauthorized,
    /// 403: accepted, but not allowed to do this.
    Forbidden,
    /// 429: too many requests; `retry_after` says when to come back.
    RateLimited,
    /// 5xx: the provider failed.
    Unavailable,
    /// No answer in time.
    Timeout,
    /// Any other refusal of the request.
    Rejected,
}

impl ProviderErrorKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Unauthorized => "the credential was not accepted (401)",
            Self::Forbidden => "the credential may not do this (403)",
            Self::RateLimited => "the provider asked to slow down (429)",
            Self::Unavailable => "the provider failed (5xx)",
            Self::Timeout => "the provider did not answer in time",
            Self::Rejected => "the provider refused the request",
        }
    }
}

/// A failed provider call. It prints through its own `Display` and `Debug` only: the detail is cut
/// short, stripped of control characters, and scrubbed of the credential by [`Self::redacted`]
/// before the engine lets it go anywhere (audit, log, API answer, health).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProviderError {
    pub(crate) kind: ProviderErrorKind,
    /// From a `Retry-After` header, when the provider sent one.
    pub(crate) retry_after: Option<Duration>,
    detail: String,
}

#[allow(
    dead_code,
    reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
)]
/// How much of a provider's text is kept until it is scrubbed, and how much is ever shown.
const DETAIL_KEEP: usize = 8192;
const DETAIL_SHOWN: usize = 300;

impl ProviderError {
    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    pub(crate) fn new(kind: ProviderErrorKind, detail: impl Into<String>) -> Self {
        let mut d: String = detail
            .into()
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        // Cut to the shown length only after scrubbing (`redacted`): a credential straddling a cut
        // would survive as a prefix no piece matches.
        d.truncate(d.floor_char_boundary(DETAIL_KEEP));
        Self {
            kind,
            retry_after: None,
            detail: d,
        }
    }

    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    pub(crate) fn rate_limited(retry_after: Option<Duration>) -> Self {
        let mut e = Self::new(ProviderErrorKind::RateLimited, "");
        e.retry_after = retry_after;
        e
    }

    /// The error with every part of the credential replaced by `<redacted>`. The credential is a
    /// whole value (`token`) or a pair (`id:secret`); each piece of three or more characters goes.
    pub(crate) fn redacted(mut self, secret: &str) -> Self {
        let mut pieces: Vec<&str> = vec![secret];
        pieces.extend(secret.split([':', ' ', '\n']));
        for p in pieces {
            if p.len() >= 3 {
                self.detail = self.detail.replace(p, "<redacted>");
            }
        }
        self.detail
            .truncate(self.detail.floor_char_boundary(DETAIL_SHOWN));
        self
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            f.write_str(self.kind.label())
        } else {
            let d = &self.detail[..self.detail.floor_char_boundary(DETAIL_SHOWN)];
            write!(f, "{}: {}", self.kind.label(), d)
        }
    }
}

impl fmt::Debug for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProviderError({self})")
    }
}

impl std::error::Error for ProviderError {}

/// A DNS host the node may write to. Implementations do the network call; the engine does
/// everything around it (the zone and type rules, ownership, dry run, limits, audit).
pub(crate) trait DnsProvider: Send + Sync + fmt::Debug {
    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    /// The kind, as the table spells it.
    fn kind(&self) -> &'static str;
    /// Checks the credential and reports what it may change.
    fn scope(&self) -> Fut<'_, Scope>;
    /// Every `TXT`, `A` and `AAAA` record set in the zone.
    fn list(&self) -> Fut<'_, Vec<RecordSet>>;
    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    /// Makes the record set exactly `set` (creating or replacing it).
    fn ensure<'a>(&'a self, set: &'a RecordSet) -> Fut<'a, Change>;
    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    /// Removes the record set of this name and type.
    fn delete<'a>(&'a self, name: &'a str, rtype: RecordType) -> Fut<'a, Change>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cld_904_the_zone_and_type_rules() {
        assert_eq!(
            name_in_zone("_acme-challenge.Example.NET.", "example.net").as_deref(),
            Ok("_acme-challenge.example.net")
        );
        assert!(name_in_zone("example.org", "example.net").is_err());
        assert!(name_in_zone("badexample.net", "example.net").is_err());
        assert!(name_in_zone("example.net.evil.org", "example.net").is_err());
        assert_eq!(RecordType::parse("mx"), None);
        assert_eq!(RecordType::parse("aaaa"), Some(RecordType::Aaaa));
        let v = |s: &str| vec![s.to_owned()];
        let ok = |t, s: &str| RecordSet::checked("example.net", "a.example.net", t, 60, &v(s));
        assert!(ok(RecordType::A, "192.0.2.1").is_ok());
        assert!(ok(RecordType::A, "::1").is_err());
        assert!(
            RecordSet::checked("example.net", "a.example.net", RecordType::Txt, 0, &v("x"))
                .is_err()
        );
        assert!(
            RecordSet::checked("example.net", "a.example.net", RecordType::Txt, 60, &[]).is_err()
        );
    }

    #[test]
    fn cld_904_a_provider_error_never_prints_the_credential() {
        let e = ProviderError::new(
            ProviderErrorKind::Unauthorized,
            "bad key AKIAEXAMPLE:s3cr3t-value-xyz and token s3cr3t-value-xyz",
        )
        .redacted("AKIAEXAMPLE:s3cr3t-value-xyz");
        let text = format!("{e} {e:?}");
        assert!(!text.contains("s3cr3t"), "{text}");
        assert!(!text.contains("AKIAEXAMPLE"), "{text}");
    }

    #[test]
    fn cld_904_a_credential_straddling_the_cut_is_scrubbed() {
        let secret = "s3cr3t-value-xyz-0123456789";
        let body = format!("{}{secret} tail", "x".repeat(290));
        let e = ProviderError::new(ProviderErrorKind::Unauthorized, body).redacted(secret);
        let text = format!("{e} {e:?}");
        assert!(!text.contains("s3cr3t"), "{text}");
        assert!(!text.contains("s3cr"), "{text}");
        // An unscrubbed error is still never longer than the shown length.
        let long = ProviderError::new(ProviderErrorKind::Unavailable, "y".repeat(2000));
        assert!(format!("{long}").len() < 400);
    }
}

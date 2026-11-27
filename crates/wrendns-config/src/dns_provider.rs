// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b, ADR-1084 as amended 2026-11-26, ADR-1104) - the `[[dns_provider]]`
//! table: an account at a DNS host (or a self-run server) that the node may one day write record
//! sets in (the ACME DNS-01 challenge, dynamic DNS). The table only stores and validates entries
//! for now: no provider is called yet (the provider trait and the write engine are T36.10b step 3
//! onward). Validation lives here so the file loader, the API and a replica's merge all refuse the
//! same tables with the same words.
//!
//! A provider's credential is never in the table: `credential_ref` names a stored secret (ADR-1084
//! point 2), and `credential` or `credential_file` are not fields of this table at all, so a
//! credential never sits in a file that could reach a support package.

use std::collections::HashSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Config;
use crate::types::SafeString;

/// Most providers a configuration may hold.
pub const MAX_DNS_PROVIDERS: usize = 16;

/// The default of `max_writes_per_hour` (design 4.5).
pub const DEFAULT_WRITES_PER_HOUR: u32 = 30;

/// The default of `max_writes_per_minute` (design 4.5).
pub const DEFAULT_WRITES_PER_MINUTE: u32 = 5;

/// The one TSIG algorithm (RFC 8945) an `rfc2136` provider signs with.
pub const TSIG_ALGORITHM: &str = "hmac-sha256";

/// What a provider talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsProviderKind {
    /// Azure DNS (`OAuth2` client credentials, the Azure DNS REST API).
    AzureDns,
    /// Cloudflare (a bearer API token).
    Cloudflare,
    /// Amazon Route 53 (Signature Version 4).
    Route53,
    /// RFC 2136 dynamic update, signed with TSIG (RFC 8945), for any self-run authoritative server.
    Rfc2136,
}

impl DnsProviderKind {
    /// The kind as the file and the API spell it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AzureDns => "azure_dns",
            Self::Cloudflare => "cloudflare",
            Self::Route53 => "route53",
            Self::Rfc2136 => "rfc2136",
        }
    }
}

const fn yes() -> bool {
    true
}

const fn per_hour() -> u32 {
    DEFAULT_WRITES_PER_HOUR
}

const fn per_minute() -> u32 {
    DEFAULT_WRITES_PER_MINUTE
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if passes a reference
fn is_default_hour(v: &u32) -> bool {
    *v == DEFAULT_WRITES_PER_HOUR
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if passes a reference
fn is_default_minute(v: &u32) -> bool {
    *v == DEFAULT_WRITES_PER_MINUTE
}

/// A DNS provider: an account and zone the node may write record sets in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsProviderConfig {
    /// Unique name (a stored secret's shape: lowercase letters, digits, `.`, `_`, `-`; at most 63
    /// characters). Locations and the ACME issuer refer to it.
    pub name: SafeString,
    /// `azure_dns`, `cloudflare`, `route53` or `rfc2136`.
    pub kind: DnsProviderKind,
    /// The zone the provider serves, such as `example.net`: lowercase, no trailing dot. Names
    /// outside it are never written.
    pub zone: SafeString,
    /// The name of the stored secret holding the credential (a client secret, an API token, an
    /// access key pair as `id:secret`, a TSIG key). Required; the table has no inline credential
    /// and no credential file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<SafeString>,
    /// Azure DNS: the subscription ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription: Option<SafeString>,
    /// Azure DNS: the resource group that holds the zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_group: Option<SafeString>,
    /// Azure DNS: the Entra tenant ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<SafeString>,
    /// Azure DNS: the application (client) ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<SafeString>,
    /// Route 53: the hosted zone ID (looked up by `zone` when left out).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosted_zone_id: Option<SafeString>,
    /// RFC 2136: the server that takes the update, a host name or address with an optional port
    /// (`ns1.example.net`, `192.168.1.53:53`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<SafeString>,
    /// RFC 2136: the TSIG key's name, as the server knows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_name: Option<SafeString>,
    /// RFC 2136: the TSIG algorithm; only `hmac-sha256` (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<SafeString>,
    /// The challenge name is delegated: the domain whose zone this entry serves, where the
    /// operator's `_acme-challenge` CNAME points (design 4.4). A domain name, not the zone itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_to: Option<SafeString>,
    /// Compute every change and record it without calling the provider's write endpoint. New
    /// entries start with it on (design 4.5) until the first successful test.
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// The most writes an hour (1 to 1000; default 30).
    #[serde(default = "per_hour", skip_serializing_if = "is_default_hour")]
    pub max_writes_per_hour: u32,
    /// The most writes a minute (1 to 60; default 5).
    #[serde(default = "per_minute", skip_serializing_if = "is_default_minute")]
    pub max_writes_per_minute: u32,
}

impl DnsProviderConfig {
    /// The name (the entry's name in the API).
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

fn domain_ok(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 200
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn set(v: Option<&SafeString>) -> bool {
    v.is_some_and(|s| !s.trim().is_empty())
}

/// An Entra tenant, subscription or application ID, or an AWS hosted zone ID: letters, digits and
/// hyphens, at most 64 characters.
fn id_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// An Azure resource group name: letters, digits, `-`, `_`, `.`, `(`, `)`; at most 90 characters.
fn group_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 90
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'(' | b')'))
}

/// A host name or address with an optional port.
fn server_ok(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    if s.parse::<std::net::SocketAddr>().is_ok() || s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, Some(p)),
        _ => (s, None),
    };
    if port.is_some_and(|p| !p.parse::<u16>().is_ok_and(|n| n > 0)) {
        return false;
    }
    domain_ok(host)
}

/// The fields each kind takes besides the common ones, by name.
const KIND_FIELDS: [&str; 7] = [
    "subscription",
    "resource_group",
    "tenant",
    "client_id",
    "hosted_zone_id",
    "server",
    "key_name",
];

/// Whether `field` belongs to `kind` (the common fields belong to all).
fn belongs(kind: DnsProviderKind, field: &str) -> bool {
    match kind {
        DnsProviderKind::AzureDns => {
            matches!(
                field,
                "subscription" | "resource_group" | "tenant" | "client_id"
            )
        }
        DnsProviderKind::Route53 => field == "hosted_zone_id",
        DnsProviderKind::Rfc2136 => matches!(field, "server" | "key_name"),
        DnsProviderKind::Cloudflare => false,
    }
}

/// Every problem in the `[[dns_provider]]` table, as `(path, message)` pairs. CLD-904: each names
/// the bad field.
#[allow(clippy::too_many_lines)] // one pass over the table, one check per field
pub fn problems(cfg: &Config) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut err = |p: String, m: String| out.push((p, m));
    if cfg.dns_provider.len() > MAX_DNS_PROVIDERS {
        err(
            "dns_provider".into(),
            format!("at most {MAX_DNS_PROVIDERS} DNS providers"),
        );
    }
    let mut names: HashSet<&str> = HashSet::new();
    for (i, p) in cfg.dns_provider.iter().enumerate() {
        let at = format!("dns_provider[{i}]");
        let name = p.name.as_str();
        if !crate::secret_refs::valid_name(name) {
            err(
                format!("{at}.name"),
                format!(
                    "`{name}` is not a name: lowercase letters, digits, `.`, `_` or `-`, starting with a letter or digit, at most 63"
                ),
            );
        } else if !names.insert(name) {
            err(format!("{at}.name"), format!("`{name}` is used twice"));
        }
        let zone = p.zone.as_str();
        if !domain_ok(zone) || !zone.contains('.') {
            err(
                format!("{at}.zone"),
                "a zone such as example.net: lowercase letters, digits and hyphens in at least two labels, no trailing dot".into(),
            );
        }
        match p.credential_ref.as_ref().map(|c| c.trim()) {
            None | Some("") => err(
                format!("{at}.credential_ref"),
                "required: the name of the stored secret that holds the credential (Settings, Integrations and secrets)".into(),
            ),
            Some(n) if !crate::secret_refs::valid_name(n) => err(
                format!("{at}.credential_ref"),
                "a stored secret's name: lowercase letters, digits, `.`, `_` or `-`, starting with a letter or digit, at most 63".into(),
            ),
            Some(_) => {}
        }
        // Each kind's own fields: required ones are named when missing, and a field that belongs
        // to another kind is refused rather than ignored.
        let value = |f: &str| -> Option<&SafeString> {
            match f {
                "subscription" => p.subscription.as_ref(),
                "resource_group" => p.resource_group.as_ref(),
                "tenant" => p.tenant.as_ref(),
                "client_id" => p.client_id.as_ref(),
                "hosted_zone_id" => p.hosted_zone_id.as_ref(),
                "server" => p.server.as_ref(),
                "key_name" => p.key_name.as_ref(),
                _ => None,
            }
        };
        for f in KIND_FIELDS {
            if set(value(f)) && !belongs(p.kind, f) {
                err(
                    format!("{at}.{f}"),
                    format!("not a field of a `{}` provider", p.kind.as_str()),
                );
            }
        }
        let required: &[&str] = match p.kind {
            DnsProviderKind::AzureDns => &["subscription", "resource_group", "tenant", "client_id"],
            DnsProviderKind::Rfc2136 => &["server", "key_name"],
            DnsProviderKind::Cloudflare | DnsProviderKind::Route53 => &[],
        };
        for f in required {
            if !set(value(f)) {
                err(
                    format!("{at}.{f}"),
                    format!("required for a `{}` provider", p.kind.as_str()),
                );
            }
        }
        for f in ["subscription", "tenant", "client_id", "hosted_zone_id"] {
            if let Some(v) = value(f).filter(|v| set(Some(v)))
                && belongs(p.kind, f)
                && !id_ok(v.trim())
            {
                err(
                    format!("{at}.{f}"),
                    "an ID: letters, digits and hyphens, at most 64 characters".into(),
                );
            }
        }
        if let Some(v) = p.resource_group.as_ref().filter(|v| set(Some(v)))
            && belongs(p.kind, "resource_group")
            && !group_ok(v.trim())
        {
            err(
                format!("{at}.resource_group"),
                "a resource group name: letters, digits, `-`, `_`, `.`, `(` and `)`, at most 90 characters".into(),
            );
        }
        if let Some(v) = p.server.as_ref().filter(|v| set(Some(v)))
            && belongs(p.kind, "server")
            && !server_ok(v.trim())
        {
            err(
                format!("{at}.server"),
                "a lowercase host name or an address, with an optional port (`ns1.example.net`, `192.0.2.53:53`)".into(),
            );
        }
        if let Some(v) = p.key_name.as_ref().filter(|v| set(Some(v)))
            && belongs(p.kind, "key_name")
            && !domain_ok(v.trim().trim_end_matches('.'))
        {
            err(
                format!("{at}.key_name"),
                "the TSIG key's name as a lowercase domain name (`acme-key`, `acme.example.net`)"
                    .into(),
            );
        }
        if let Some(a) = p.algorithm.as_ref().filter(|a| set(Some(a))) {
            if p.kind != DnsProviderKind::Rfc2136 {
                err(
                    format!("{at}.algorithm"),
                    format!("not a field of a `{}` provider", p.kind.as_str()),
                );
            } else if !a.trim().eq_ignore_ascii_case(TSIG_ALGORITHM) {
                err(
                    format!("{at}.algorithm"),
                    format!("only `{TSIG_ALGORITHM}` is supported"),
                );
            }
        }
        if let Some(d) = p.delegated_to.as_ref().filter(|d| set(Some(d))) {
            let d = d.trim().trim_end_matches('.');
            if !domain_ok(d) || !d.contains('.') {
                err(
                    format!("{at}.delegated_to"),
                    "a domain name such as home.acme-validation.example.org (lowercase, no trailing dot)".into(),
                );
            } else if d == zone {
                err(
                    format!("{at}.delegated_to"),
                    "the challenge is delegated to another name than the zone itself".into(),
                );
            }
        }
        if !(1..=1000).contains(&p.max_writes_per_hour) {
            err(
                format!("{at}.max_writes_per_hour"),
                "from 1 to 1000 writes an hour".into(),
            );
        }
        if !(1..=60).contains(&p.max_writes_per_minute) {
            err(
                format!("{at}.max_writes_per_minute"),
                "from 1 to 60 writes a minute".into(),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> Config {
        toml::from_str(toml).expect("parses")
    }

    fn paths(c: &Config) -> Vec<String> {
        problems(c).into_iter().map(|(p, _)| p).collect()
    }

    const GOOD: &str = r#"
[[dns_provider]]
name = "azure-home"
kind = "azure_dns"
zone = "example.net"
credential_ref = "azure-home"
subscription = "11111111-2222-3333-4444-555555555555"
resource_group = "rg-dns"
tenant = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
client_id = "99999999-8888-7777-6666-555555555555"
"#;

    #[test]
    fn cld_904_a_good_entry_has_no_problems_and_starts_in_dry_run() {
        let c = cfg(GOOD);
        assert!(problems(&c).is_empty(), "{:?}", problems(&c));
        assert!(c.dns_provider[0].dry_run);
        assert_eq!(
            c.dns_provider[0].max_writes_per_hour,
            DEFAULT_WRITES_PER_HOUR
        );
    }

    #[test]
    fn cld_904_validation_names_the_bad_field() {
        let c = cfg(&GOOD.replace("credential_ref = \"azure-home\"\n", ""));
        assert_eq!(paths(&c), vec!["dns_provider[0].credential_ref"]);
        let c = cfg(&GOOD.replace("zone = \"example.net\"", "zone = \"example\""));
        assert_eq!(paths(&c), vec!["dns_provider[0].zone"]);
        let c = cfg(&GOOD.replace("tenant = \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"\n", ""));
        assert_eq!(paths(&c), vec!["dns_provider[0].tenant"]);
        let c = cfg(&format!("{GOOD}server = \"ns1.example.net\"\n"));
        assert_eq!(paths(&c), vec!["dns_provider[0].server"]);
        let c = cfg(&format!("{GOOD}max_writes_per_minute = 0\n"));
        assert_eq!(paths(&c), vec!["dns_provider[0].max_writes_per_minute"]);
        let c = cfg(&format!("{GOOD}delegated_to = \"example.net\"\n"));
        assert_eq!(paths(&c), vec!["dns_provider[0].delegated_to"]);
    }

    #[test]
    fn cld_904_the_table_takes_no_inline_credential_or_file() {
        for key in ["credential", "credential_file", "token", "secret"] {
            let bad = format!("{GOOD}{key} = \"x\"\n");
            let e = toml::from_str::<Config>(&bad).unwrap_err().to_string();
            assert!(e.contains(key), "{key}: {e}");
        }
    }

    #[test]
    fn cld_904_names_are_unique_and_rfc2136_needs_its_server_and_key() {
        let two = format!("{GOOD}{GOOD}");
        let c = cfg(&two);
        assert_eq!(paths(&c), vec!["dns_provider[1].name"]);
        let c = cfg(
            "[[dns_provider]]\nname = \"bind\"\nkind = \"rfc2136\"\nzone = \"example.net\"\ncredential_ref = \"tsig\"\nserver = \"192.0.2.53:53\"\nkey_name = \"acme-key\"\nalgorithm = \"hmac-sha1\"\n",
        );
        assert_eq!(paths(&c), vec!["dns_provider[0].algorithm"]);
        let c = cfg(
            "[[dns_provider]]\nname = \"bind\"\nkind = \"rfc2136\"\nzone = \"example.net\"\ncredential_ref = \"tsig\"\n",
        );
        assert_eq!(
            paths(&c),
            vec!["dns_provider[0].server", "dns_provider[0].key_name"]
        );
        let c = cfg(
            "[[dns_provider]]\nname = \"cf\"\nkind = \"cloudflare\"\nzone = \"example.net\"\ncredential_ref = \"cf\"\n",
        );
        assert_eq!(paths(&c), Vec::<String>::new());
    }
}

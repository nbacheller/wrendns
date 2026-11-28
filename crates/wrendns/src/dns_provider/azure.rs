// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b4a; ADR-1084, ADR-1112) - the Azure DNS provider.
//!
//! Sign-in is `OAuth2` client credentials to Entra ID (the stored secret is the application's client
//! secret); the access token is cached until shortly before it expires and then asked for again.
//! Record sets are read, written and deleted with the Azure DNS REST API (`2018-05-01`).
//!
//! **Least privilege.** Azure can scope a role to one record set, and that is the setup the helper
//! shows: `DNS Zone Contributor` on `.../dnszones/<zone>/TXT/_acme-challenge.<name>`, plus `Reader`
//! on the zone so the engine can see what exists (it never overwrites a record the node does not
//! own). The record set must exist before the role can be used to change it: Azure checks a
//! create at the zone, so the operator creates the empty record set first.
//!
//! The provider only makes the calls: the zone and type rules, ownership, dry run, limits and audit
//! are the engine's. No token, client secret or header reaches an error: an error is a status and a
//! short provider message, scrubbed of the secret and of the access token.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use wrendns_config::DnsProviderConfig;
use zeroize::Zeroizing;

use super::http_json::{self, Reply};
use super::{
    Change, DnsProvider, Fut, ProviderError, ProviderErrorKind, RecordSet, RecordType, Scope,
    name_in_zone,
};
use crate::secrets::value::SecretValue;

const LOGIN_BASE: &str = "https://login.microsoftonline.com";
const ARM_BASE: &str = "https://management.azure.com";
const RESOURCE_SCOPE: &str = "https://management.azure.com/.default";
const DNS_API: &str = "2018-05-01";
const PERMISSIONS_API: &str = "2022-04-01";
/// A token is asked for again this long before it expires.
const SKEW: Duration = Duration::from_secs(120);
/// The longest a token is kept, whatever the token endpoint says.
const MAX_TOKEN_LIFE: Duration = Duration::from_hours(24);
/// The token cache holds at most this many (one per entry, so far fewer).
const MAX_CACHED: usize = 16;
/// The most listing pages read, and the most record sets kept.
const MAX_PAGES: usize = 50;
const MAX_SETS: usize = 5000;

type Cached = (String, Zeroizing<String>, Instant);
static TOKENS: Mutex<Vec<Cached>> = Mutex::new(Vec::new());

/// An Azure DNS zone.
#[derive(Debug)]
pub(crate) struct AzureDns {
    zone: String,
    subscription: String,
    resource_group: String,
    tenant: String,
    client_id: String,
    secret: Option<SecretValue>,
    login_base: String,
    arm_base: String,
}

fn field(v: Option<&wrendns_config::SafeString>) -> String {
    v.map(|s| s.trim().to_owned()).unwrap_or_default()
}

impl AzureDns {
    /// The provider for `cfg`, signing in with `secret` (the client secret).
    pub(crate) fn new(cfg: &DnsProviderConfig, secret: Option<SecretValue>) -> Self {
        Self::with_bases(cfg, secret, LOGIN_BASE, ARM_BASE)
    }

    /// As [`Self::new`] with other base URLs. For tests, which point both at a local server; no
    /// setting reaches this.
    pub(crate) fn with_bases(
        cfg: &DnsProviderConfig,
        secret: Option<SecretValue>,
        login_base: &str,
        arm_base: &str,
    ) -> Self {
        Self {
            zone: cfg.zone.trim().trim_end_matches('.').to_ascii_lowercase(),
            subscription: field(cfg.subscription.as_ref()),
            resource_group: field(cfg.resource_group.as_ref()),
            tenant: field(cfg.tenant.as_ref()),
            client_id: field(cfg.client_id.as_ref()),
            secret,
            login_base: login_base.trim_end_matches('/').to_owned(),
            arm_base: arm_base.trim_end_matches('/').to_owned(),
        }
    }

    fn zone_url(&self) -> String {
        format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}",
            self.arm_base,
            http_json::encode(&self.subscription),
            http_json::encode(&self.resource_group),
            http_json::encode(&self.zone),
        )
    }

    /// The name of the record set inside the zone (`@` for the apex).
    fn relative(&self, name: &str) -> Result<String, ProviderError> {
        let n = name_in_zone(name, &self.zone)
            .map_err(|e| ProviderError::new(ProviderErrorKind::Rejected, e))?;
        Ok(if n == self.zone {
            "@".to_owned()
        } else {
            n[..n.len() - self.zone.len() - 1].to_owned()
        })
    }

    fn set_url(&self, rtype: RecordType, relative: &str) -> String {
        // `@` (the apex) is a legal path character and is how Azure's documentation writes it.
        let seg = if relative == "@" {
            "@".to_owned()
        } else {
            http_json::encode(relative)
        };
        format!(
            "{}/{}/{seg}?api-version={DNS_API}",
            self.zone_url(),
            rtype.as_str()
        )
    }

    /// An error with the client secret and the access token (when there is one) taken out.
    fn clean(&self, e: ProviderError, token: Option<&str>) -> ProviderError {
        let e = match &self.secret {
            Some(s) => e.redacted(s.expose()),
            None => e,
        };
        match token {
            Some(t) => e.redacted(t),
            None => e,
        }
    }

    fn secret_text(&self) -> Result<&str, ProviderError> {
        self.secret
            .as_ref()
            .map(SecretValue::expose)
            .ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorKind::Unauthorized,
                    "the entry's credential is not stored on this node",
                )
            })
    }

    fn cache_key(&self, secret: &str) -> String {
        format!(
            "{}|{}|{}|{}",
            self.login_base,
            self.tenant,
            self.client_id,
            http_json::fingerprint(secret)
        )
    }

    fn cached(key: &str) -> Option<Zeroizing<String>> {
        let now = Instant::now();
        let mut cache = TOKENS.lock().unwrap_or_else(PoisonError::into_inner);
        cache.retain(|(_, _, until)| *until > now);
        cache
            .iter()
            .find(|(k, _, _)| k == key)
            .map(|(_, t, _)| t.clone())
    }

    fn forget(key: &str) {
        TOKENS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(k, _, _)| k != key);
    }

    fn remember(key: String, token: Zeroizing<String>, until: Instant) {
        let mut cache = TOKENS.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        cache.retain(|(k, _, u)| *u > now && *k != key);
        while cache.len() >= MAX_CACHED {
            let soonest = cache
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, _, u))| *u)
                .map(|(i, _)| i);
            match soonest {
                Some(i) => {
                    cache.swap_remove(i);
                }
                None => break,
            }
        }
        cache.push((key, token, until));
    }

    /// A bearer token for Azure Resource Manager: the cached one while it lives, or a new one.
    async fn token(&self) -> Result<Zeroizing<String>, ProviderError> {
        let secret = self.secret_text()?;
        let key = self.cache_key(secret);
        if let Some(t) = Self::cached(&key) {
            return Ok(t);
        }
        let form = format!(
            "client_id={}&client_secret={}&scope={}&grant_type=client_credentials",
            http_json::encode(&self.client_id),
            http_json::encode(secret),
            http_json::encode(RESOURCE_SCOPE),
        );
        let url = format!(
            "{}/{}/oauth2/v2.0/token",
            self.login_base,
            http_json::encode(&self.tenant)
        );
        let reply = http_json::send(
            "POST",
            &url,
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("accept", "application/json"),
            ],
            Some(form.into_bytes()),
        )
        .await
        .map_err(|e| self.clean(e, None))?;
        // An answer that echoes the secret (raw or as it was sent in the form) is cleaned first.
        let mut reply = reply;
        reply.body = http_json::cut_out(reply.body, secret);
        reply.body = http_json::cut_out(reply.body, &http_json::encode(secret));
        if !reply.ok() {
            // The token endpoint answers a wrong secret, tenant or application with 400 or 401.
            let mut e = reply.error(&http_json::message_of(&reply.body));
            if matches!(reply.status, 400 | 401) {
                e = ProviderError::new(
                    ProviderErrorKind::Unauthorized,
                    format!(
                        "Entra ID did not accept the client credentials: {}",
                        http_json::message_of(&reply.body)
                    ),
                );
            }
            return Err(self.clean(e, None));
        }
        let v = reply.json().map_err(|e| self.clean(e, None))?;
        let Some(access) = v.get("access_token").and_then(Value::as_str) else {
            return Err(ProviderError::new(
                ProviderErrorKind::Rejected,
                "Entra ID's answer had no access token",
            ));
        };
        let secs = v
            .get("expires_in")
            .and_then(|e| {
                e.as_u64()
                    .or_else(|| e.as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(300);
        let life = Duration::from_secs(secs).min(MAX_TOKEN_LIFE);
        let token = Zeroizing::new(access.to_owned());
        if let Some(keep) = life.checked_sub(SKEW) {
            Self::remember(key, token.clone(), Instant::now() + keep);
        }
        Ok(token)
    }

    /// One call to Resource Manager with a bearer token. A 401 drops the cached token and tries
    /// once more with a new one. A failed status becomes an error with the credentials scrubbed.
    async fn call(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Reply, ProviderError> {
        let mut reply = None;
        for attempt in 0..2 {
            let token = self.token().await?;
            let auth = Zeroizing::new(format!("Bearer {}", token.as_str()));
            let mut headers = vec![
                ("authorization", auth.as_str()),
                ("accept", "application/json"),
            ];
            if body.is_some() {
                headers.push(("content-type", "application/json"));
            }
            let r = http_json::send(method, url, &headers, body.clone())
                .await
                .map_err(|e| self.clean(e, Some(token.as_str())))?;
            // A 401 may be a token that expired early: drop it and try once with a new one.
            if r.status == 401
                && attempt == 0
                && let Ok(s) = self.secret_text()
            {
                Self::forget(&self.cache_key(s));
            }
            let mut r = r;
            // A provider may echo the bearer token in its answer: it is cut out before anything
            // reads the body.
            r.body = http_json::cut_out(r.body, token.as_str());
            reply = Some(r);
            if reply.as_ref().is_some_and(|r| r.status != 401) {
                break;
            }
        }
        reply.ok_or_else(|| {
            ProviderError::new(ProviderErrorKind::Unavailable, "no answer from Azure")
        })
    }

    /// The error for a failed answer: the hint first (the provider's own text can be long and is
    /// cut), then the provider's message. The access token is cut out of the answer by [`Self::call`].
    fn failed(&self, reply: &Reply, hint: &str) -> ProviderError {
        let mut msg = String::new();
        if !hint.is_empty() {
            msg.push_str(hint);
            msg.push_str(". ");
        }
        msg.push_str(&http_json::message_of(&reply.body));
        self.clean(reply.error(msg.trim_end()), None)
    }

    async fn do_list(&self, top: usize) -> Result<Vec<RecordSet>, ProviderError> {
        let mut url = format!(
            "{}/recordsets?api-version={DNS_API}&$top={top}",
            self.zone_url()
        );
        let prefix = format!("{}/", self.arm_base);
        let mut out = Vec::new();
        for _ in 0..MAX_PAGES {
            let reply = self.call("GET", &url, None).await?;
            if !reply.ok() {
                return Err(self.failed(
                    &reply,
                    match reply.status {
                        403 => "The credential needs the Reader role on the zone so the node can see what exists",
                        404 => "The subscription, resource group or zone was not found",
                        _ => "",
                    },
                ));
            }
            let v = reply.json().map_err(|e| self.clean(e, None))?;
            for item in v
                .get("value")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(set) = self.parse_set(item) {
                    out.push(set);
                }
            }
            if out.len() > MAX_SETS {
                return Err(ProviderError::new(
                    ProviderErrorKind::Rejected,
                    format!("the zone holds more than {MAX_SETS} record sets"),
                ));
            }
            match v.get("nextLink").and_then(Value::as_str) {
                // Only a link on the same host is followed: the bearer token goes nowhere else.
                Some(next) if next.starts_with(&prefix) => next.clone_into(&mut url),
                Some(next) if !next.is_empty() => {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Rejected,
                        "the listing's next page is on another host",
                    ));
                }
                _ => return Ok(out),
            }
            if top == 1 {
                return Ok(out);
            }
        }
        Ok(out)
    }

    /// One record set from a listing item; `None` for a type that is not written or an empty one.
    fn parse_set(&self, item: &Value) -> Option<RecordSet> {
        let kind = item.get("type")?.as_str()?.rsplit('/').next()?;
        let rtype = RecordType::parse(kind)?;
        let rel = item.get("name")?.as_str()?.to_ascii_lowercase();
        let name = if rel == "@" {
            self.zone.clone()
        } else {
            format!("{rel}.{}", self.zone)
        };
        let props = item.get("properties")?;
        let ttl = u32::try_from(props.get("TTL").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0);
        let mut values: Vec<String> = match rtype {
            RecordType::Txt => props
                .get("TXTRecords")?
                .as_array()?
                .iter()
                .map(|r| {
                    r.get("value")
                        .and_then(Value::as_array)
                        .map(|parts| parts.iter().filter_map(Value::as_str).collect::<String>())
                        .unwrap_or_default()
                })
                .collect(),
            RecordType::A => props
                .get("ARecords")?
                .as_array()?
                .iter()
                .filter_map(|r| r.get("ipv4Address")?.as_str().map(str::to_owned))
                .collect(),
            RecordType::Aaaa => props
                .get("AAAARecords")?
                .as_array()?
                .iter()
                .filter_map(|r| r.get("ipv6Address")?.as_str())
                .map(|a| {
                    a.parse::<std::net::Ipv6Addr>()
                        .map_or_else(|_| a.to_owned(), |ip| ip.to_string())
                })
                .collect(),
        };
        values.sort();
        values.dedup();
        if values.is_empty() {
            return None;
        }
        Some(RecordSet {
            name,
            rtype,
            ttl,
            values,
        })
    }

    fn body_of(set: &RecordSet) -> Value {
        let records = match set.rtype {
            RecordType::Txt => json!({ "TXTRecords": set.values.iter()
                .map(|v| json!({ "value": txt_chunks(v) })).collect::<Vec<_>>() }),
            RecordType::A => json!({ "ARecords": set.values.iter()
                .map(|v| json!({ "ipv4Address": v })).collect::<Vec<_>>() }),
            RecordType::Aaaa => json!({ "AAAARecords": set.values.iter()
                .map(|v| json!({ "ipv6Address": v })).collect::<Vec<_>>() }),
        };
        let mut props = records;
        props["TTL"] = json!(set.ttl);
        json!({ "properties": props })
    }

    async fn do_scope(&self) -> Result<Scope, ProviderError> {
        // The token call is the proof the credential is accepted at all.
        self.token().await?;
        // The engine reads the zone before it writes, so the credential must be able to.
        self.do_list(1).await?;
        let record_scope = format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnszones/{}/TXT/_acme-challenge.<name>",
            self.subscription, self.resource_group, self.zone
        );
        let mut notes = vec![
            "The record set must exist before the node can change it: create an empty TXT record set with the challenge name first.".to_owned(),
            format!("To limit the application to one record set, give it DNS Zone Contributor at the scope {record_scope}"),
            format!(
                "az role assignment create --assignee {} --role \"DNS Zone Contributor\" --scope {record_scope}",
                self.client_id
            ),
        ];
        let url = format!(
            "{}/providers/Microsoft.Authorization/permissions?api-version={PERMISSIONS_API}",
            self.zone_url()
        );
        let wide = match self.call("GET", &url, None).await {
            Ok(r) if r.ok() => r.json().ok().map(|v| zone_wide_write(&v)),
            _ => None,
        };
        let types = vec![RecordType::Txt, RecordType::A, RecordType::Aaaa];
        Ok(match wide {
            Some(true) => Scope {
                zone: self.zone.clone(),
                summary: format!(
                    "Accepted. The application can change record sets across the whole zone {}.",
                    self.zone
                ),
                record_types: types,
                record_sets: None,
                broader_than_needed: true,
                notes: {
                    notes.insert(
                        0,
                        "A zone-wide write role is more than the node needs: move DNS Zone Contributor from the zone to the record set, and keep Reader on the zone.".to_owned(),
                    );
                    notes
                },
            },
            Some(false) => Scope {
                zone: self.zone.clone(),
                summary: "Accepted for the record sets it was granted a write role on; at the zone it can only read.".to_owned(),
                record_types: types,
                record_sets: Some(vec!["only the record sets it was granted on (Azure does not list them here)".to_owned()]),
                broader_than_needed: false,
                notes,
            },
            None => Scope {
                zone: self.zone.clone(),
                summary: "Accepted: the credential signs in and can read the zone. Azure did not report its write grants, so whether it is limited to one record set is not known.".to_owned(),
                record_types: types,
                record_sets: None,
                broader_than_needed: false,
                notes,
            },
        })
    }
}

/// A TXT value as the character strings Azure takes: pieces of at most 255 bytes.
fn txt_chunks(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in v.chars() {
        if cur.len() + c.len_utf8() > 255 {
            out.push(std::mem::take(&mut cur));
        }
        cur.push(c);
    }
    out.push(cur);
    out
}

/// Whether `pattern` (with `*` for any run) matches `text`, ignoring case.
fn wild(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.to_ascii_lowercase(), text.to_ascii_lowercase());
    let parts: Vec<&str> = p.split('*').collect();
    if parts.len() == 1 {
        return p == t;
    }
    let mut rest = t.as_str();
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            let Some(r) = rest.strip_prefix(part) else {
                return false;
            };
            rest = r;
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else if let Some(at) = rest.find(part) {
            rest = &rest[at + part.len()..];
        } else {
            return false;
        }
    }
    true
}

/// Whether the effective permissions at the zone (the `permissions` answer) allow writing `TXT`,
/// `A` or `AAAA` record sets across it.
fn zone_wide_write(v: &Value) -> bool {
    let list = |p: &Value, k: &str| -> Vec<String> {
        p.get(k)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|a| a.as_str().map(str::to_owned))
            .collect()
    };
    let targets = [
        "Microsoft.Network/dnszones/TXT/write",
        "Microsoft.Network/dnszones/A/write",
        "Microsoft.Network/dnszones/AAAA/write",
    ];
    v.get("value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|p| {
            let (allow, deny) = (list(p, "actions"), list(p, "notActions"));
            targets
                .iter()
                .any(|t| allow.iter().any(|a| wild(a, t)) && !deny.iter().any(|d| wild(d, t)))
        })
}

impl DnsProvider for AzureDns {
    fn kind(&self) -> &'static str {
        "azure_dns"
    }

    fn scope(&self) -> Fut<'_, Scope> {
        Box::pin(self.do_scope())
    }

    fn list(&self) -> Fut<'_, Vec<RecordSet>> {
        Box::pin(self.do_list(100))
    }

    fn ensure<'a>(&'a self, set: &'a RecordSet) -> Fut<'a, Change> {
        Box::pin(async move {
            let rel = self.relative(&set.name)?;
            let body = serde_json::to_vec(&Self::body_of(set)).map_err(|_| {
                ProviderError::new(
                    ProviderErrorKind::Rejected,
                    "the record set could not be encoded",
                )
            })?;
            let reply = self
                .call("PUT", &self.set_url(set.rtype, &rel), Some(body))
                .await?;
            if reply.ok() {
                return Ok(Change {
                    id: reply.request_id,
                });
            }
            Err(self.failed(
                &reply,
                if reply.status == 403 {
                    "If the record set does not exist yet, create it first: a role on one record set cannot create it"
                } else {
                    ""
                },
            ))
        })
    }

    fn delete<'a>(&'a self, name: &'a str, rtype: RecordType) -> Fut<'a, Change> {
        Box::pin(async move {
            let rel = self.relative(name)?;
            let reply = self
                .call("DELETE", &self.set_url(rtype, &rel), None)
                .await?;
            // 200 deleted, 204 there was none: either way it is gone.
            if reply.ok() || reply.status == 404 {
                return Ok(Change {
                    id: reply.request_id,
                });
            }
            Err(self.failed(&reply, ""))
        })
    }
}

#[cfg(test)]
#[path = "azure_tests.rs"]
mod tests;

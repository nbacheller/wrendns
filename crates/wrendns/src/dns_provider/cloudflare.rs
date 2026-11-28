// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b4b; ADR-1084, ADR-1112) - the Cloudflare provider.
//!
//! A bearer API token (the stored secret) and the v4 REST API: the zone is found by name, its DNS
//! records are listed, created, patched and deleted. Cloudflare holds one record per value, not a
//! record set, so a set is made by creating, re-using and deleting records until the values match.
//!
//! **Least privilege.** Cloudflare cannot limit a token to one record: the narrowest token is
//! `Zone:Zone:Read` and `Zone:DNS:Edit` on one zone, and that token can change every record in the
//! zone. The scope report says so, warns when the token reaches more than one zone, and the helper
//! recommends delegating the challenge name to a small separate zone when this zone holds anything
//! else of value.
//!
//! The provider only makes the calls (the engine does the rest). The token reaches no error: an
//! error is a status and a short provider message, scrubbed of the token.

use std::sync::{Mutex, PoisonError};

use serde_json::{Value, json};
use wrendns_config::DnsProviderConfig;

use super::http_json::{self, Reply};
use super::{
    Change, DnsProvider, Fut, ProviderError, ProviderErrorKind, RecordSet, RecordType, Scope,
    name_in_zone,
};
use crate::secrets::value::SecretValue;

const API_BASE: &str = "https://api.cloudflare.com/client/v4";
/// Cloudflare's lowest explicit TTL; `1` means automatic.
const MIN_TTL: u32 = 60;
const PAGE: usize = 100;
/// The most pages read of one listing.
const MAX_PAGES: usize = 50;
/// The most zones named in a note.
const MAX_ZONES_SHOWN: usize = 10;

/// One zone at Cloudflare.
#[derive(Debug)]
pub(crate) struct Cloudflare {
    zone: String,
    token: Option<SecretValue>,
    base: String,
    zone_id: Mutex<Option<String>>,
}

/// One DNS record as Cloudflare holds it.
#[derive(Debug)]
struct Rec {
    id: String,
    content: String,
    ttl: u32,
}

impl Cloudflare {
    /// The provider for `cfg`, with `token` (the API token).
    pub(crate) fn new(cfg: &DnsProviderConfig, token: Option<SecretValue>) -> Self {
        Self::with_base(cfg, token, API_BASE)
    }

    /// As [`Self::new`] with another base URL. For tests, which point it at a local server; no
    /// setting reaches this.
    pub(crate) fn with_base(
        cfg: &DnsProviderConfig,
        token: Option<SecretValue>,
        base: &str,
    ) -> Self {
        Self {
            zone: cfg.zone.trim().trim_end_matches('.').to_ascii_lowercase(),
            token,
            base: base.trim_end_matches('/').to_owned(),
            zone_id: Mutex::new(None),
        }
    }

    fn clean(&self, e: ProviderError) -> ProviderError {
        match &self.token {
            Some(t) => e.redacted(t.expose()),
            None => e,
        }
    }

    /// The error for a failed answer: the hint first (the provider's own text can be long and is
    /// cut), then the provider's message.
    fn failed(&self, reply: &Reply, hint: &str) -> ProviderError {
        let mut msg = String::new();
        if !hint.is_empty() {
            msg.push_str(hint);
            msg.push_str(". ");
        }
        msg.push_str(&http_json::message_of(&reply.body));
        self.clean(reply.error(msg.trim_end()))
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Reply, ProviderError> {
        let token = self.token.as_ref().ok_or_else(|| {
            ProviderError::new(
                ProviderErrorKind::Unauthorized,
                "the entry's credential is not stored on this node",
            )
        })?;
        let auth = zeroize::Zeroizing::new(format!("Bearer {}", token.expose()));
        let mut headers = vec![
            ("authorization", auth.as_str()),
            ("accept", "application/json"),
        ];
        let bytes = match body {
            Some(b) => {
                headers.push(("content-type", "application/json"));
                Some(serde_json::to_vec(b).map_err(|_| {
                    ProviderError::new(
                        ProviderErrorKind::Rejected,
                        "the record could not be encoded",
                    )
                })?)
            }
            None => None,
        };
        let mut reply = http_json::send(method, &format!("{}{path}", self.base), &headers, bytes)
            .await
            .map_err(|e| self.clean(e))?;
        // An answer that echoes the token is cleaned before anything reads it.
        reply.body = http_json::cut_out(reply.body, token.expose());
        Ok(reply)
    }

    /// A successful answer's JSON, or the failure. Cloudflare says `"success": false` with errors.
    async fn json(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        hint: &str,
    ) -> Result<(Value, Reply), ProviderError> {
        let reply = self.call(method, path, body).await?;
        if !reply.ok() {
            return Err(self.failed(&reply, hint));
        }
        let v = reply.json().map_err(|e| self.clean(e))?;
        if v.get("success").and_then(Value::as_bool) == Some(false) {
            return Err(self.failed(
                &Reply {
                    status: 400,
                    ..reply
                },
                "",
            ));
        }
        Ok((v, reply))
    }

    /// The zone's ID, looked up by name once.
    async fn zone_id(&self) -> Result<String, ProviderError> {
        if let Some(id) = self
            .zone_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Ok(id);
        }
        let path = format!("/zones?name={}&per_page=5", http_json::encode(&self.zone));
        let (v, _) = self
            .json(
                "GET",
                &path,
                None,
                "The token needs Zone:Zone:Read and Zone:DNS:Edit for this zone",
            )
            .await?;
        let id = v
            .get("result")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|z| {
                z.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| n.eq_ignore_ascii_case(&self.zone))
            })
            .and_then(|z| z.get("id")?.as_str().map(str::to_owned))
            .ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorKind::Rejected,
                    format!(
                        "the token cannot see the zone {}: it needs Zone:Zone:Read and Zone:DNS:Edit for it",
                        self.zone
                    ),
                )
            })?;
        *self.zone_id.lock().unwrap_or_else(PoisonError::into_inner) = Some(id.clone());
        Ok(id)
    }

    fn relative_check(&self, name: &str) -> Result<String, ProviderError> {
        name_in_zone(name, &self.zone)
            .map_err(|e| ProviderError::new(ProviderErrorKind::Rejected, e))
    }

    /// The records of one name and type.
    async fn records_of(
        &self,
        id: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<Vec<Rec>, ProviderError> {
        let mut out = Vec::new();
        for page in 1..=MAX_PAGES {
            let path = format!(
                "/zones/{}/dns_records?type={}&name={}&per_page={PAGE}&page={page}",
                http_json::encode(id),
                rtype.as_str(),
                http_json::encode(name)
            );
            let (v, _) = self.json("GET", &path, None, "").await?;
            let items = v.get("result").and_then(Value::as_array);
            for r in items.into_iter().flatten() {
                if let Some(rec) = parse_rec(r) {
                    out.push(rec);
                }
            }
            if !more_pages(&v, page) {
                break;
            }
        }
        Ok(out)
    }

    async fn do_list(&self) -> Result<Vec<RecordSet>, ProviderError> {
        let id = self.zone_id().await?;
        let mut all: Vec<RecordSet> = Vec::new();
        for rtype in [RecordType::Txt, RecordType::A, RecordType::Aaaa] {
            for page in 1..=MAX_PAGES {
                let path = format!(
                    "/zones/{}/dns_records?type={}&per_page={PAGE}&page={page}",
                    http_json::encode(&id),
                    rtype.as_str()
                );
                let (v, _) = self.json("GET", &path, None, "").await?;
                for r in v
                    .get("result")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let (Some(name), Some(rec)) =
                        (r.get("name").and_then(Value::as_str), parse_rec(r))
                    else {
                        continue;
                    };
                    let name = name.trim_end_matches('.').to_ascii_lowercase();
                    match all.iter_mut().find(|s| s.name == name && s.rtype == rtype) {
                        Some(s) => {
                            s.values.push(rec.content);
                            s.ttl = s.ttl.min(rec.ttl);
                        }
                        None => all.push(RecordSet {
                            name,
                            rtype,
                            ttl: rec.ttl,
                            values: vec![rec.content],
                        }),
                    }
                }
                if !more_pages(&v, page) {
                    break;
                }
            }
        }
        for s in &mut all {
            s.values.sort();
            s.values.dedup();
        }
        Ok(all)
    }

    async fn do_ensure(&self, set: &RecordSet) -> Result<Change, ProviderError> {
        let name = self.relative_check(&set.name)?;
        let id = self.zone_id().await?;
        let ttl = set.ttl.max(MIN_TTL);
        let mut leftovers = self.records_of(&id, &name, set.rtype).await?;
        let mut last = None;
        let mut todo: Vec<&String> = Vec::new();
        for v in &set.values {
            // A record that already holds the value stays (its TTL is brought in line).
            if let Some(i) = leftovers.iter().position(|r| &r.content == v) {
                let r = leftovers.swap_remove(i);
                if r.ttl != ttl {
                    last = self
                        .patch(&id, &r.id, &json!({ "ttl": ttl }))
                        .await?
                        .or(last);
                }
            } else {
                todo.push(v);
            }
        }
        for v in todo {
            // A record with a value nobody wants is changed to this one; else one is created.
            let body = json!({ "type": set.rtype.as_str(), "name": name, "content": v,
                               "ttl": ttl, "proxied": false });
            let made = if let Some(r) = leftovers.pop() {
                self.patch(&id, &r.id, &json!({ "content": v, "ttl": ttl }))
                    .await?
            } else {
                let path = format!("/zones/{}/dns_records", http_json::encode(&id));
                let (answer, reply) = self
                    .json(
                        "POST",
                        &path,
                        Some(&body),
                        "The token needs Zone:DNS:Edit for this zone",
                    )
                    .await?;
                id_of(&answer).or(reply.request_id)
            };
            last = made.or(last);
        }
        for r in leftovers {
            last = self.remove(&id, &r.id).await?.or(last);
        }
        Ok(Change { id: last })
    }

    async fn patch(
        &self,
        zone: &str,
        rec: &str,
        body: &Value,
    ) -> Result<Option<String>, ProviderError> {
        let path = format!(
            "/zones/{}/dns_records/{}",
            http_json::encode(zone),
            http_json::encode(rec)
        );
        let (_, reply) = self
            .json(
                "PATCH",
                &path,
                Some(body),
                "The token needs Zone:DNS:Edit for this zone",
            )
            .await?;
        Ok(reply.request_id)
    }

    async fn remove(&self, zone: &str, rec: &str) -> Result<Option<String>, ProviderError> {
        let path = format!(
            "/zones/{}/dns_records/{}",
            http_json::encode(zone),
            http_json::encode(rec)
        );
        let reply = self.call("DELETE", &path, None).await?;
        // 404: it was already gone.
        if reply.ok() || reply.status == 404 {
            return Ok(reply.request_id);
        }
        Err(self.failed(&reply, ""))
    }

    async fn do_delete(&self, name: &str, rtype: RecordType) -> Result<Change, ProviderError> {
        let name = self.relative_check(name)?;
        let id = self.zone_id().await?;
        let mut last = None;
        for r in self.records_of(&id, &name, rtype).await? {
            last = self.remove(&id, &r.id).await?.or(last);
        }
        Ok(Change { id: last })
    }

    async fn do_scope(&self) -> Result<Scope, ProviderError> {
        let mut notes = Vec::new();
        // The verify call answers for a user API token; an account-owned token has its own verify
        // path, so a refusal here is not final while the zone list still works.
        let verify = self
            .json("GET", "/user/tokens/verify", None, "")
            .await
            .and_then(|(v, _)| {
                let status = v
                    .pointer("/result/status")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                if status == "active" {
                    Ok(())
                } else {
                    Err(ProviderError::new(
                        ProviderErrorKind::Unauthorized,
                        format!("the token's status is `{status}`, not `active`"),
                    ))
                }
            });
        let mut zones: Vec<String> = Vec::new();
        let mut page = 1;
        loop {
            let path = format!("/zones?per_page=50&page={page}");
            match self.json("GET", &path, None, "").await {
                Ok((v, _)) => {
                    zones.extend(
                        v.get("result")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(|z| z.get("name")?.as_str().map(str::to_ascii_lowercase)),
                    );
                    if !more_pages(&v, page) || page >= 5 {
                        break;
                    }
                    page += 1;
                }
                Err(e) => return Err(verify.err().unwrap_or(e)),
            }
        }
        if let Err(e) = verify {
            notes.push(format!(
                "Token verify did not accept it ({e}), but the zone list worked: an account-owned token is verified another way."
            ));
        }
        if !zones.contains(&self.zone) {
            return Err(ProviderError::new(
                ProviderErrorKind::Rejected,
                format!(
                    "the token cannot see the zone {}: it needs Zone:Zone:Read and Zone:DNS:Edit for it",
                    self.zone
                ),
            ));
        }
        zones.sort();
        zones.dedup();
        let many = zones.len() > 1;
        let shown: Vec<&str> = zones
            .iter()
            .take(MAX_ZONES_SHOWN)
            .map(String::as_str)
            .collect();
        if many {
            notes.push(format!(
                "The token reaches {} zones ({}{}): create one for {} only, so a leaked token can change nothing else.",
                zones.len(),
                shown.join(", "),
                if zones.len() > MAX_ZONES_SHOWN { ", and more" } else { "" },
                self.zone
            ));
        }
        notes.push(
            "The zone list shows every zone the token can read, not only those it can edit."
                .to_owned(),
        );
        notes.push(
            "Cloudflare cannot limit a token to one record: it can change every record in the zone. If the zone holds anything else of value, delegate the challenge name to a small separate zone instead (see Challenge delegation).".to_owned(),
        );
        Ok(Scope {
            zone: self.zone.clone(),
            summary: if many {
                format!(
                    "Accepted, but the token reaches {} zones, not only {}.",
                    zones.len(),
                    self.zone
                )
            } else {
                format!(
                    "Accepted for the zone {}. The token reaches no other zone.",
                    self.zone
                )
            },
            record_types: vec![RecordType::Txt, RecordType::A, RecordType::Aaaa],
            record_sets: None,
            broader_than_needed: many,
            notes,
        })
    }
}

fn id_of(v: &Value) -> Option<String> {
    v.pointer("/result/id")?.as_str().map(str::to_owned)
}

/// Whether the listing has a page after `page`.
fn more_pages(v: &Value, page: usize) -> bool {
    v.pointer("/result_info/total_pages")
        .and_then(Value::as_u64)
        .is_some_and(|t| (page as u64) < t)
}

fn parse_rec(r: &Value) -> Option<Rec> {
    let content = r.get("content")?.as_str()?;
    let ttl = u32::try_from(r.get("ttl").and_then(Value::as_u64).unwrap_or(1)).unwrap_or(1);
    Some(Rec {
        id: r.get("id")?.as_str()?.to_owned(),
        content: unquote(content),
        ttl,
    })
}

/// A TXT value as Cloudflare returns it is wrapped in one pair of quotes; the value is without.
fn unquote(s: &str) -> String {
    match s.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
        Some(inner) if !s.is_empty() && s.len() >= 2 => inner.to_owned(),
        _ => s.to_owned(),
    }
}

impl DnsProvider for Cloudflare {
    fn kind(&self) -> &'static str {
        "cloudflare"
    }

    fn scope(&self) -> Fut<'_, Scope> {
        Box::pin(self.do_scope())
    }

    fn list(&self) -> Fut<'_, Vec<RecordSet>> {
        Box::pin(self.do_list())
    }

    fn ensure<'a>(&'a self, set: &'a RecordSet) -> Fut<'a, Change> {
        Box::pin(self.do_ensure(set))
    }

    fn delete<'a>(&'a self, name: &'a str, rtype: RecordType) -> Fut<'a, Change> {
        Box::pin(self.do_delete(name, rtype))
    }
}

#[cfg(test)]
#[path = "cloudflare_tests.rs"]
mod tests;

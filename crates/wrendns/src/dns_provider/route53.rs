// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b4; ADR-1084 point 6) - the `route53` provider: Amazon Route 53's REST
//! API signed with Signature Version 4 ([`super::sigv4`], hand-rolled on `ring`), through the
//! bounded HTTP client (`wrendns_filter::fetch::http::Client`: response size cap, no redirects).
//!
//! - **Credential:** one stored text secret, `ACCESS_KEY_ID:SECRET_ACCESS_KEY`.
//! - **Reads:** `ListResourceRecordSets` (paged, bounded). A record set that has an alias target or a
//!   routing policy (`SetIdentifier`) is listed as a set WrenDNS did not make and never writes: the
//!   provider refuses to change or delete one, so a routing record is never replaced by an `UPSERT`.
//! - **Writes:** `ChangeResourceRecordSets` with one `UPSERT` or one `DELETE` (a `DELETE` repeats the
//!   record set's current TTL and values, which Route 53 requires).
//! - **Test:** `GetHostedZone` and a one-item `ListResourceRecordSets`. IAM does not let a key read
//!   its own policy cheaply, so the Test says that the key is accepted for the zone and shows the
//!   policy to attach; whether a write is allowed is decided when one is made.
//!
//! The access key, the secret and the signature never appear in an error: the detail of every
//! failure is scrubbed of all three before it is built, and again by the engine.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wrendns_config::DnsProviderConfig;
use wrendns_filter::fetch::{Client, SystemResolver};
use zeroize::Zeroizing;

use super::sigv4;
use super::xml::{self, Node};
use super::{
    Change, DnsProvider, Fut, ProviderError, ProviderErrorKind, RecordSet, RecordType, Scope,
};
use crate::secrets::value::SecretValue;

/// Route 53 is global; its signing region is `us-east-1`.
const REGION: &str = "us-east-1";
const SERVICE: &str = "route53";
const ENDPOINT: &str = "https://route53.amazonaws.com";
const API: &str = "/2013-04-01";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// The largest answer read (a page of 300 record sets is well under it).
const MAX_RESPONSE: u64 = 2 * 1024 * 1024;
const PAGE: &str = "300";
const MAX_PAGES: usize = 200;
/// The values shown for a set WrenDNS does not manage.
const FOREIGN: &str = "(an alias or routing-policy record set, managed outside WrenDNS)";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A hosted zone at Route 53.
pub(crate) struct Route53 {
    zone: String,
    configured_zone_id: Option<String>,
    zone_id: Mutex<Option<String>>,
    /// The access key ID and the secret, or why there is none.
    creds: Result<(String, Zeroizing<String>), &'static str>,
    endpoint: String,
    client: OnceLock<Result<Client, String>>,
}

impl fmt::Debug for Route53 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Route53")
            .field("zone", &self.zone)
            .finish_non_exhaustive()
    }
}

fn err(kind: ProviderErrorKind, detail: impl Into<String>) -> ProviderError {
    ProviderError::new(kind, detail)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A name Route 53 is given: letters, digits, `-`, `_`, `.` and `*` only.
fn plain_name(name: &str) -> Result<(), ProviderError> {
    let ok = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'*'));
    if ok {
        Ok(())
    } else {
        Err(err(
            ProviderErrorKind::Rejected,
            format!("`{name}` is not a name this provider writes"),
        ))
    }
}

/// A name as Route 53 returns it (`\052` escapes, a trailing dot) to the form the engine uses.
fn read_name(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = u32::from(b[i + 1] - b'0') * 64
                + u32::from(b[i + 2] - b'0') * 8
                + u32::from(b[i + 3] - b'0');
            out.push(char::from_u32(v).unwrap_or('?'));
            i += 4;
        } else {
            out.push(char::from(b[i]));
            i += 1;
        }
    }
    out.trim_end_matches('.').to_ascii_lowercase()
}

/// A TXT value as Route 53 takes it: quoted strings of at most 255 characters.
fn quote_txt(v: &str) -> Result<String, ProviderError> {
    if !v.is_ascii() {
        return Err(err(
            ProviderErrorKind::Rejected,
            "a TXT value with characters outside ASCII is not written through Route 53",
        ));
    }
    let chunks: Vec<String> = v
        .as_bytes()
        .chunks(255)
        .map(|c| {
            let mut s = String::from("\"");
            for &b in c {
                if b == b'"' || b == b'\\' {
                    s.push('\\');
                }
                s.push(char::from(b));
            }
            s.push('"');
            s
        })
        .collect();
    Ok(chunks.join(" "))
}

/// A TXT value as Route 53 returns it: the quoted strings joined.
fn unquote_txt(v: &str) -> String {
    let b = v.trim().as_bytes();
    if b.first() != Some(&b'"') {
        return String::from_utf8_lossy(b).into_owned();
    }
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    let mut open = false;
    while i < b.len() {
        match b[i] {
            b'"' => open = !open,
            b'\\' if open && i + 1 < b.len() => {
                if i + 3 < b.len() && b[i + 1..i + 4].iter().all(u8::is_ascii_digit) {
                    let v = u32::from(b[i + 1] - b'0') * 100
                        + u32::from(b[i + 2] - b'0') * 10
                        + u32::from(b[i + 3] - b'0');
                    out.push(u8::try_from(v).unwrap_or(b'?'));
                    i += 3;
                } else {
                    i += 1;
                    out.push(b[i]);
                }
            }
            c if open => out.push(c),
            _ => {}
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One record set as the API lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listed {
    name: String,
    rtype: RecordType,
    /// An alias target or a routing policy: not a plain set.
    foreign: bool,
    ttl: u32,
    values: Vec<String>,
    /// The values as Route 53 wrote them, for a `DELETE` (which must repeat them exactly).
    raw: Vec<String>,
}

/// The sets of a `ListResourceRecordSets` answer that are `A`, `AAAA` or `TXT`.
fn listed_sets(doc: &Node) -> Vec<Listed> {
    let Some(sets) = doc.child("ResourceRecordSets") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for s in sets.all("ResourceRecordSet") {
        let Some(rtype) = s.text_at(&["Type"]).and_then(RecordType::parse) else {
            continue;
        };
        let Some(name) = s.text_at(&["Name"]) else {
            continue;
        };
        let foreign = s.child("AliasTarget").is_some() || s.child("SetIdentifier").is_some();
        let raw: Vec<String> = s
            .child("ResourceRecords")
            .map(|r| {
                r.all("ResourceRecord")
                    .filter_map(|v| v.text_at(&["Value"]))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let mut values: Vec<String> = raw
            .iter()
            .map(String::as_str)
            .map(|v| match rtype {
                RecordType::Txt => unquote_txt(v),
                RecordType::Aaaa => v
                    .parse::<std::net::Ipv6Addr>()
                    .map_or_else(|_| v.to_owned(), |a| a.to_string()),
                RecordType::A => v.to_owned(),
            })
            .collect();
        values.sort();
        values.dedup();
        out.push(Listed {
            name: read_name(name),
            rtype,
            foreign,
            ttl: s
                .text_at(&["TTL"])
                .and_then(|t| t.parse().ok())
                .unwrap_or(0),
            values,
            raw,
        });
    }
    out
}

/// The body of one `Change` of a `ChangeResourceRecordSets` request.
fn change_xml(action: &str, name: &str, rtype: RecordType, ttl: u32, texts: &[String]) -> String {
    let mut records = String::new();
    for text in texts {
        records.push_str("<ResourceRecord><Value>");
        records.push_str(&xml::escape(text));
        records.push_str("</Value></ResourceRecord>");
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><ChangeBatch><Comment>WrenDNS</Comment><Changes><Change><Action>{action}</Action><ResourceRecordSet><Name>{}.</Name><Type>{}</Type><TTL>{ttl}</TTL><ResourceRecords>{records}</ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>",
        xml::escape(name),
        rtype.as_str()
    )
}

/// The values of a set in the form Route 53 takes them.
fn texts(rtype: RecordType, values: &[String]) -> Result<Vec<String>, ProviderError> {
    values
        .iter()
        .map(|v| match rtype {
            RecordType::Txt => quote_txt(v),
            RecordType::A | RecordType::Aaaa => Ok(v.clone()),
        })
        .collect()
}

impl Route53 {
    pub(crate) fn new(cfg: &DnsProviderConfig, secret: Option<&SecretValue>) -> Self {
        let creds = match secret {
            None => Err("no credential is stored under that name"),
            Some(s) => match s.expose().split_once(':') {
                Some((id, sk)) if !id.trim().is_empty() && !sk.trim().is_empty() => {
                    Ok((id.trim().to_owned(), Zeroizing::new(sk.trim().to_owned())))
                }
                _ => Err("the stored credential is not ACCESS_KEY_ID:SECRET_ACCESS_KEY"),
            },
        };
        Self {
            zone: cfg.zone.as_str().to_owned(),
            configured_zone_id: cfg
                .hosted_zone_id
                .as_ref()
                .map(|z| z.trim().to_owned())
                .filter(|z| !z.is_empty()),
            zone_id: Mutex::new(None),
            creds,
            endpoint: ENDPOINT.to_owned(),
            client: OnceLock::new(),
        }
    }

    /// Points the provider at a local server (tests only: the endpoint is not a setting).
    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: &str) -> Self {
        self.endpoint = endpoint.trim_end_matches('/').to_owned();
        self
    }

    fn client(&self) -> Result<&Client, ProviderError> {
        self.client
            .get_or_init(|| Client::new(Arc::new(SystemResolver), &[]))
            .as_ref()
            .map_err(|e| err(ProviderErrorKind::Unavailable, e.clone()))
    }

    /// `text` without the key ID, the secret or the signature.
    fn scrubbed(&self, text: &str, signature: &str) -> String {
        let mut t = text.to_owned();
        if let Ok((id, sk)) = &self.creds {
            for p in [id.as_str(), sk.as_str(), signature] {
                if p.len() >= 3 {
                    t = t.replace(p, "<redacted>");
                }
            }
        }
        t
    }

    /// One signed request. `Ok` is a 2xx answer's document; any other answer is an error.
    async fn call(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, &str)],
        body: Option<String>,
    ) -> Result<Node, ProviderError> {
        let (id, sk) = self
            .creds
            .as_ref()
            .map_err(|e| err(ProviderErrorKind::Unauthorized, *e))?;
        let client = self.client()?;
        let uri: http::Uri = self
            .endpoint
            .parse()
            .map_err(|_| err(ProviderErrorKind::Rejected, "the endpoint is not a URL"))?;
        let host = uri
            .authority()
            .map(|a| a.as_str().to_owned())
            .ok_or_else(|| err(ProviderErrorKind::Rejected, "the endpoint has no host"))?;
        let body_bytes = body.unwrap_or_default().into_bytes();
        let date = sigv4::amz_date(now());
        let content_type = [("content-type", "text/xml")];
        let signed = sigv4::sign(
            &sigv4::Request {
                method,
                host: &host,
                path,
                query,
                headers: if body_bytes.is_empty() {
                    &content_type[..0]
                } else {
                    &content_type[..]
                },
                body: &body_bytes,
            },
            &sigv4::Scope {
                access_key: id,
                secret: sk,
                region: REGION,
                service: SERVICE,
                amz_date: &date,
            },
        );
        let sig = signed.signature.as_str();
        let q = sigv4::canonical_query(query);
        let url = format!(
            "{}{}{}{}",
            self.endpoint,
            sigv4::encode_path(path),
            if q.is_empty() { "" } else { "?" },
            q
        );
        let mut b = http::Request::builder()
            .method(method)
            .uri(url)
            .header("x-amz-date", &date)
            .header("authorization", &signed.authorization);
        if !body_bytes.is_empty() {
            b = b.header("content-type", "text/xml");
        }
        let req = b.body(body_bytes).map_err(|_| {
            err(
                ProviderErrorKind::Rejected,
                "the request could not be built",
            )
        })?;
        let resp = tokio::time::timeout(REQUEST_TIMEOUT, client.request(req, MAX_RESPONSE))
            .await
            .map_err(|_| {
                err(
                    ProviderErrorKind::Timeout,
                    "Route 53 did not answer in time",
                )
            })?
            .map_err(|e| {
                err(
                    if e.retryable {
                        ProviderErrorKind::Unavailable
                    } else {
                        ProviderErrorKind::Rejected
                    },
                    self.scrubbed(&e.message, sig),
                )
            })?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            return xml::parse(resp.body()).map_err(|e| {
                err(
                    ProviderErrorKind::Rejected,
                    self.scrubbed(&e.to_string(), sig),
                )
            });
        }
        let retry = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        Err(self.api_error(status, resp.body(), retry, sig))
    }

    /// An error answer: its status and AWS's error code decide the kind; its message is shown
    /// (scrubbed). AWS reports a rejected key as 403, so the code tells that from a missing grant.
    fn api_error(
        &self,
        status: u16,
        body: &[u8],
        retry: Option<Duration>,
        sig: &str,
    ) -> ProviderError {
        let doc = xml::parse(body).ok();
        let code = doc
            .as_ref()
            .and_then(|d| d.child("Error").or(Some(d)))
            .and_then(|e| e.text_at(&["Code"]))
            .unwrap_or("")
            .to_owned();
        let message = doc
            .as_ref()
            .and_then(|d| d.child("Error").or(Some(d)))
            .and_then(|e| e.text_at(&["Message"]))
            .unwrap_or("")
            .to_owned();
        let kind = match (status, code.as_str()) {
            (
                _,
                "InvalidClientTokenId"
                | "SignatureDoesNotMatch"
                | "IncompleteSignature"
                | "ExpiredToken"
                | "MissingAuthenticationToken"
                | "UnrecognizedClientException",
            )
            | (401, _) => ProviderErrorKind::Unauthorized,
            (_, "Throttling" | "ThrottlingException" | "PriorRequestNotComplete") | (429, _) => {
                ProviderErrorKind::RateLimited
            }
            (403, _) => ProviderErrorKind::Forbidden,
            (500..=599, _) => ProviderErrorKind::Unavailable,
            _ => ProviderErrorKind::Rejected,
        };
        if kind == ProviderErrorKind::RateLimited {
            return ProviderError::rate_limited(retry);
        }
        let detail = if code.is_empty() {
            format!("HTTP {status}")
        } else {
            self.scrubbed(&format!("{code}: {message}"), sig)
        };
        err(kind, detail)
    }

    /// The hosted zone's ID: the configured one, or the public zone of this name.
    async fn zone_id(&self) -> Result<String, ProviderError> {
        if let Some(id) = &self.configured_zone_id {
            return Ok(id.clone());
        }
        if let Some(id) = lock(&self.zone_id).clone() {
            return Ok(id);
        }
        let want = format!("{}.", self.zone);
        let doc = self
            .call(
                "GET",
                &format!("{API}/hostedzonesbyname"),
                &[("dnsname", &self.zone), ("maxitems", "10")],
                None,
            )
            .await?;
        let found = doc
            .child("HostedZones")
            .into_iter()
            .flat_map(|z| z.all("HostedZone"))
            .find(|z| {
                z.text_at(&["Name"])
                    .is_some_and(|n| n.eq_ignore_ascii_case(&want))
                    && z.text_at(&["Config", "PrivateZone"]) != Some("true")
            })
            .and_then(|z| z.text_at(&["Id"]))
            .map(|id| id.rsplit('/').next().unwrap_or(id).to_owned());
        let id = found.ok_or_else(|| {
            err(
                ProviderErrorKind::Rejected,
                format!(
                    "no public hosted zone named `{}` is visible to this key (set the hosted zone ID, and allow route53:ListHostedZonesByName)",
                    self.zone
                ),
            )
        })?;
        *lock(&self.zone_id) = Some(id.clone());
        Ok(id)
    }

    /// Every `A`, `AAAA` and `TXT` set, or (with `only`) the sets at that name and type.
    async fn sets(&self, only: Option<(&str, RecordType)>) -> Result<Vec<Listed>, ProviderError> {
        let id = self.zone_id().await?;
        let path = format!("{API}/hostedzone/{id}/rrset");
        let mut out: Vec<Listed> = Vec::new();
        let (mut next_name, mut next_type, mut next_id): (
            Option<String>,
            Option<String>,
            Option<String>,
        ) = match only {
            Some((n, t)) => (Some(format!("{n}.")), Some(t.as_str().to_owned()), None),
            None => (None, None, None),
        };
        for _ in 0..MAX_PAGES {
            let mut q: Vec<(&str, &str)> =
                vec![("maxitems", if only.is_some() { "4" } else { PAGE })];
            if let Some(n) = &next_name {
                q.push(("name", n));
            }
            if let Some(t) = &next_type {
                q.push(("type", t));
            }
            if let Some(i) = &next_id {
                q.push(("identifier", i));
            }
            let doc = self.call("GET", &path, &q, None).await?;
            out.extend(listed_sets(&doc));
            if only.is_some() {
                break;
            }
            if doc.text_at(&["IsTruncated"]) != Some("true") {
                return Ok(out);
            }
            next_name = doc.text_at(&["NextRecordName"]).map(str::to_owned);
            next_type = doc.text_at(&["NextRecordType"]).map(str::to_owned);
            next_id = doc.text_at(&["NextRecordIdentifier"]).map(str::to_owned);
            if next_name.is_none() {
                return Ok(out);
            }
        }
        if let Some((n, t)) = only {
            out.retain(|s| s.name == n && s.rtype == t);
            return Ok(out);
        }
        Err(err(
            ProviderErrorKind::Rejected,
            "the zone has more record sets than WrenDNS reads for a provider",
        ))
    }

    /// The one set at this name and type, if any; a routing or alias set is refused.
    async fn current(
        &self,
        name: &str,
        rtype: RecordType,
    ) -> Result<Option<Listed>, ProviderError> {
        plain_name(name)?;
        let mut found: Vec<Listed> = self
            .sets(Some((name, rtype)))
            .await?
            .into_iter()
            .filter(|s| s.name == name && s.rtype == rtype)
            .collect();
        match found.len() {
            0 => Ok(None),
            1 if !found[0].foreign => Ok(found.pop()),
            _ => Err(err(
                ProviderErrorKind::Rejected,
                format!(
                    "`{name}` {} is an alias or has a routing policy at Route 53: WrenDNS does not change it",
                    rtype.as_str()
                ),
            )),
        }
    }

    async fn change(&self, body: String) -> Result<Change, ProviderError> {
        let id = self.zone_id().await?;
        let doc = self
            .call(
                "POST",
                &format!("{API}/hostedzone/{id}/rrset/"),
                &[],
                Some(body),
            )
            .await?;
        let change = doc
            .text_at(&["ChangeInfo", "Id"])
            .map(|c| c.rsplit('/').next().unwrap_or(c).to_owned());
        Ok(Change { id: change })
    }
}

impl DnsProvider for Route53 {
    fn kind(&self) -> &'static str {
        "route53"
    }

    fn scope(&self) -> Fut<'_, Scope> {
        Box::pin(async move {
            let id = self.zone_id().await?;
            let doc = self
                .call("GET", &format!("{API}/hostedzone/{id}"), &[], None)
                .await?;
            let name = doc.text_at(&["HostedZone", "Name"]).unwrap_or("");
            if !name.trim_end_matches('.').eq_ignore_ascii_case(&self.zone) {
                return Err(err(
                    ProviderErrorKind::Rejected,
                    format!(
                        "hosted zone {id} is `{}`, not `{}`",
                        name.trim_end_matches('.'),
                        self.zone
                    ),
                ));
            }
            // The engine reads the zone before every change, so the key must be allowed to.
            self.call(
                "GET",
                &format!("{API}/hostedzone/{id}/rrset"),
                &[("maxitems", "1")],
                None,
            )
            .await?;
            let mut notes = vec![
                "Route 53 does not report what a key may change: the IAM policy shown when the provider was added limits it to the challenge name and the TXT type, and a change the policy does not allow is refused when it is made.".to_owned(),
            ];
            if doc.text_at(&["HostedZone", "Config", "PrivateZone"]) == Some("true") {
                notes.push("This is a private hosted zone: it is not served on the internet, so a public certificate cannot be validated through it.".into());
            }
            Ok(Scope {
                zone: self.zone.clone(),
                summary: format!(
                    "The key is accepted for hosted zone {id} ({}): it may read the zone.",
                    self.zone
                ),
                record_types: vec![RecordType::Txt, RecordType::A, RecordType::Aaaa],
                record_sets: None,
                broader_than_needed: false,
                notes,
            })
        })
    }

    fn list(&self) -> Fut<'_, Vec<RecordSet>> {
        Box::pin(async move {
            let mut map: BTreeMap<(String, RecordType), RecordSet> = BTreeMap::new();
            for s in self.sets(None).await? {
                let key = (s.name.clone(), s.rtype);
                if s.foreign {
                    map.insert(
                        key,
                        RecordSet {
                            name: s.name,
                            rtype: s.rtype,
                            ttl: 0,
                            values: vec![FOREIGN.to_owned()],
                        },
                    );
                } else if let Some(e) = map.get_mut(&key) {
                    // A second set of the same name and type is a routing policy.
                    e.ttl = 0;
                    e.values = vec![FOREIGN.to_owned()];
                } else {
                    map.insert(
                        key,
                        RecordSet {
                            name: s.name,
                            rtype: s.rtype,
                            ttl: s.ttl,
                            values: s.values,
                        },
                    );
                }
            }
            Ok(map.into_values().collect())
        })
    }

    fn ensure<'a>(&'a self, set: &'a RecordSet) -> Fut<'a, Change> {
        Box::pin(async move {
            plain_name(&set.name)?;
            // An alias or a routing policy at the name is never replaced.
            self.current(&set.name, set.rtype).await?;
            let body = change_xml(
                "UPSERT",
                &set.name,
                set.rtype,
                set.ttl,
                &texts(set.rtype, &set.values)?,
            );
            self.change(body).await
        })
    }

    fn delete<'a>(&'a self, name: &'a str, rtype: RecordType) -> Fut<'a, Change> {
        Box::pin(async move {
            let Some(cur) = self.current(name, rtype).await? else {
                return Ok(Change::default());
            };
            let body = change_xml("DELETE", name, rtype, cur.ttl, &cur.raw);
            self.change(body).await
        })
    }
}

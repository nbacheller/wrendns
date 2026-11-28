// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b4a) - the Azure DNS provider against a local server that replays
//! Azure's documented answers (token endpoint, record sets, permissions). No live credential and no
//! real endpoint: the base URLs are the test's own.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};
use wrendns_config::DnsProviderConfig;
use zeroize::Zeroizing;

use super::AzureDns;
use crate::dns_provider::http_json::replay::{Answer, Seen, ok, start, status};
use crate::dns_provider::registry::Handle;
use crate::dns_provider::{DnsProvider, ProviderErrorKind, RecordSet, RecordType};
use crate::secrets::value::SecretValue;

const TOKEN: &str = include_str!("testdata/azure_token.json");
const SETS: &str = include_str!("testdata/azure_recordsets.json");
const TOKEN_ERROR: &str = include_str!("testdata/azure_token_error.json");
const PERMS_RECORD_SET: &str = include_str!("testdata/azure_permissions_record_set_only.json");
const PERMS_ZONE: &str = include_str!("testdata/azure_permissions_zone_wide.json");
const FORBIDDEN: &str = include_str!("testdata/azure_forbidden.json");
/// A client secret with characters a form must encode.
const SECRET: &str = "az-client-secret~Zk39+x/yz=7Q";
const ACCESS: &str = "tok-azure-access-5f2c";
const ZONE_PATH: &str = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-dns/providers/Microsoft.Network/dnsZones/example.net";

fn cfg() -> DnsProviderConfig {
    serde_json::from_value(json!({
        "name": "azure-home", "kind": "azure_dns", "zone": "example.net", "credential_ref": "az",
        "subscription": "00000000-0000-0000-0000-000000000001", "resource_group": "rg-dns",
        "tenant": "tenant-1", "client_id": "app-1"
    }))
    .unwrap()
}

fn secret() -> SecretValue {
    SecretValue::from_text(Zeroizing::new(SECRET.to_owned()))
}

fn provider(base: &str) -> AzureDns {
    AzureDns::with_bases(&cfg(), Some(secret()), base, base)
}

fn is_token(r: &Seen) -> bool {
    r.target.starts_with("/tenant-1/oauth2/v2.0/token")
}

fn txt(name: &str, ttl: u32, values: &[&str]) -> RecordSet {
    RecordSet {
        name: name.to_owned(),
        rtype: RecordType::Txt,
        ttl,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
    }
}

fn with_id(code: u16, id: &str, body: &str) -> Answer {
    Answer(
        code,
        vec![("x-ms-request-id".to_owned(), id.to_owned())],
        body.to_owned(),
    )
}

/// The documented answers, replayed: list, create or update, delete; the token is asked for once.
#[allow(clippy::too_many_lines)] // one walk through the documented calls
#[tokio::test]
async fn cld_904_azure_create_update_delete_against_recorded_api() {
    let tokens = Arc::new(AtomicUsize::new(0));
    let t = Arc::clone(&tokens);
    let server = start(move |r| {
        if is_token(r) {
            t.fetch_add(1, Ordering::SeqCst);
            ok(TOKEN)
        } else if r.method == "GET" && r.target.contains("/recordsets") {
            ok(SETS)
        } else if r.method == "PUT" {
            with_id(200, "req-put-1", "{}")
        } else if r.method == "DELETE" {
            with_id(200, "req-del-1", "")
        } else {
            status(404, "{}")
        }
    })
    .await;
    let p = provider(&server.base);

    // List: TXT chunks joined, A values sorted, AAAA normalised, names lowercase and full; the
    // SOA, NS and CNAME sets are not ours to see.
    let sets = p.list().await.unwrap();
    assert_eq!(sets.len(), 3, "{sets:?}");
    let get = |n: &str, t: RecordType| sets.iter().find(|s| s.name == n && s.rtype == t).unwrap();
    assert_eq!(
        get("_acme-challenge.home.example.net", RecordType::Txt).values,
        vec!["part-one-part-two".to_owned()]
    );
    assert_eq!(
        get("home.example.net", RecordType::A).values,
        vec!["192.0.2.1".to_owned(), "192.0.2.9".to_owned()]
    );
    assert_eq!(get("home.example.net", RecordType::A).ttl, 300);
    assert_eq!(
        get("example.net", RecordType::Aaaa).values,
        vec!["2001:db8::1".to_owned()]
    );

    // Create or update: one PUT of the record set on its own path.
    let want = txt("_acme-challenge.home.example.net", 60, &["tok-1"]);
    let change = p.ensure(&want).await.unwrap();
    assert_eq!(change.id.as_deref(), Some("req-put-1"));
    // The apex is `@`; an A set takes its addresses.
    let apex = RecordSet {
        name: "example.net".to_owned(),
        rtype: RecordType::A,
        ttl: 300,
        values: vec!["192.0.2.7".to_owned()],
    };
    p.ensure(&apex).await.unwrap();
    // Delete.
    let change = p
        .delete("_acme-challenge.home.example.net", RecordType::Txt)
        .await
        .unwrap();
    assert_eq!(change.id.as_deref(), Some("req-del-1"));

    let seen = server.seen();
    let puts: Vec<&Seen> = seen.iter().filter(|r| r.method == "PUT").collect();
    assert_eq!(puts.len(), 2);
    assert_eq!(
        puts[0].target,
        format!("{ZONE_PATH}/TXT/_acme-challenge.home?api-version=2018-05-01")
    );
    let body: Value = serde_json::from_str(&puts[0].body).unwrap();
    assert_eq!(
        body,
        json!({ "properties": { "TTL": 60, "TXTRecords": [{ "value": ["tok-1"] }] } })
    );
    assert_eq!(
        puts[1].target,
        format!("{ZONE_PATH}/A/@?api-version=2018-05-01")
    );
    let body: Value = serde_json::from_str(&puts[1].body).unwrap();
    assert_eq!(
        body,
        json!({ "properties": { "TTL": 300, "ARecords": [{ "ipv4Address": "192.0.2.7" }] } })
    );
    let del = seen.iter().find(|r| r.method == "DELETE").unwrap();
    assert_eq!(
        del.target,
        format!("{ZONE_PATH}/TXT/_acme-challenge.home?api-version=2018-05-01")
    );
    // Every call carried the bearer token, and the token was asked for once.
    for r in seen.iter().filter(|r| !is_token(r)) {
        assert!(
            r.head
                .to_lowercase()
                .contains(&format!("authorization: bearer {ACCESS}")),
            "{}",
            r.head
        );
    }
    assert_eq!(tokens.load(Ordering::SeqCst), 1, "the token is cached");
    // The token request is the client-credentials grant, the secret encoded.
    let tok = seen.iter().find(|r| is_token(r)).unwrap();
    assert!(
        tok.body.contains("grant_type=client_credentials"),
        "{}",
        tok.body
    );
    assert!(tok.body.contains("client_id=app-1"));
    assert!(
        tok.body.contains("az-client-secret~Zk39%2Bx%2Fyz%3D7Q"),
        "{}",
        tok.body
    );
    assert!(
        tok.body
            .contains("scope=https%3A%2F%2Fmanagement.azure.com%2F.default")
    );
}

/// A long TXT value goes out as character strings of at most 255 bytes and is read back joined.
#[tokio::test]
async fn cld_904_azure_long_txt_value_is_split_into_strings() {
    let server = start(|r| if is_token(r) { ok(TOKEN) } else { ok("{}") }).await;
    let long = "x".repeat(600);
    let p = provider(&server.base);
    p.ensure(&txt("a.example.net", 60, &[&long])).await.unwrap();
    let put = server
        .seen()
        .into_iter()
        .find(|r| r.method == "PUT")
        .unwrap();
    let body: Value = serde_json::from_str(&put.body).unwrap();
    let parts = body["properties"]["TXTRecords"][0]["value"]
        .as_array()
        .unwrap();
    assert_eq!(parts.len(), 3);
    assert!(parts.iter().all(|s| s.as_str().unwrap().len() <= 255));
    let joined: String = parts.iter().map(|s| s.as_str().unwrap()).collect();
    assert_eq!(joined, long);
}

/// A refused sign-in is a 401-kind error that carries no client secret, even when Entra echoes it;
/// a 403 that echoes the access token carries no token; the record set that must exist first is
/// said.
#[tokio::test]
async fn cld_904_azure_token_error_is_redacted() {
    let echoed = TOKEN_ERROR.replace("SECRET_ECHO", SECRET);
    let server = start(move |r| {
        if is_token(r) {
            status(401, &echoed)
        } else {
            status(404, "{}")
        }
    })
    .await;
    let p = provider(&server.base);
    let e = p.scope().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Unauthorized);
    let text = format!("{e} {e:?}");
    assert!(text.contains("invalid_client"), "{text}");
    assert!(!text.contains(SECRET), "{text}");
    assert!(!text.contains("Zk39"), "{text}");
    // The engine's own scrub (the handle's copy of the secret) leaves nothing either.
    let handle = Handle {
        provider: Arc::new(provider(&server.base)),
        secret: Some(secret()),
    };
    let e = handle.scrub(handle.provider.list().await.unwrap_err());
    assert!(!format!("{e} {e:?}").contains("Zk39"));

    // An API refusal that echoes the bearer token.
    let server = start(|r| {
        if is_token(r) {
            ok(TOKEN)
        } else {
            status(403, FORBIDDEN)
        }
    })
    .await;
    let p = provider(&server.base);
    let e = p
        .ensure(&txt("_acme-challenge.home.example.net", 60, &["v"]))
        .await
        .unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Forbidden);
    let text = format!("{e} {e:?}");
    assert!(!text.contains(ACCESS), "{text}");
    assert!(!text.contains(SECRET), "{text}");
    assert!(text.contains("create it first"), "{text}");
}

/// The token is kept until shortly before it expires: a long-lived one is fetched once, one that is
/// about to expire is fetched again, and a 401 from the API drops it and retries with a new one.
#[tokio::test]
async fn cld_904_azure_token_cache_is_bounded_by_expiry() {
    let long = Arc::new(AtomicUsize::new(0));
    let short = Arc::new(AtomicUsize::new(0));
    let (long_hits, short_hits) = (Arc::clone(&long), Arc::clone(&short));
    let server = start(move |r| {
        if is_token(r) {
            // A different tenant is not routed here; the two cases are told apart by client id.
            if r.body.contains("client_id=app-short") {
                short_hits.fetch_add(1, Ordering::SeqCst);
                ok(r#"{"access_token":"tok-short","expires_in":60}"#)
            } else {
                long_hits.fetch_add(1, Ordering::SeqCst);
                ok(TOKEN)
            }
        } else {
            ok(r#"{"value":[]}"#)
        }
    })
    .await;
    let p = provider(&server.base);
    p.list().await.unwrap();
    p.list().await.unwrap();
    assert_eq!(long.load(Ordering::SeqCst), 1);
    let mut short_cfg = serde_json::to_value(cfg()).unwrap();
    short_cfg["client_id"] = json!("app-short");
    let short_cfg: DnsProviderConfig = serde_json::from_value(short_cfg).unwrap();
    let q = AzureDns::with_bases(&short_cfg, Some(secret()), &server.base, &server.base);
    q.list().await.unwrap();
    q.list().await.unwrap();
    assert_eq!(
        short.load(Ordering::SeqCst),
        2,
        "a token that expires within the skew is not kept"
    );

    // A 401 from the API: the cached token is dropped and one new token is tried.
    let tokens = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let (token_hits, api_hits) = (Arc::clone(&tokens), Arc::clone(&calls));
    let server = start(move |r| {
        if is_token(r) {
            token_hits.fetch_add(1, Ordering::SeqCst);
            ok(TOKEN)
        } else if api_hits.fetch_add(1, Ordering::SeqCst) == 0 {
            status(
                401,
                r#"{"error":{"code":"ExpiredAuthenticationToken","message":"expired"}}"#,
            )
        } else {
            ok(r#"{"value":[]}"#)
        }
    })
    .await;
    let p = provider(&server.base);
    assert_eq!(p.list().await.unwrap().len(), 0);
    assert_eq!(tokens.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// A listing's `nextLink` on another host is never followed (the bearer token goes nowhere else),
/// and one on the same host is.
#[tokio::test]
async fn cld_904_azure_next_link_stays_on_the_azure_host() {
    let server = start(|r| {
        if is_token(r) {
            ok(TOKEN)
        } else {
            ok(r#"{"value":[],"nextLink":"https://evil.example.invalid/x?skip=1"}"#)
        }
    })
    .await;
    let e = provider(&server.base).list().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Rejected);
    assert_eq!(server.seen().len(), 2, "the token call and one listing");

    let base = Arc::new(std::sync::Mutex::new(String::new()));
    let b = Arc::clone(&base);
    let pages = Arc::new(AtomicUsize::new(0));
    let pg = Arc::clone(&pages);
    let server = start(move |r| {
        if is_token(r) {
            ok(TOKEN)
        } else if r.target.contains("skip=1") {
            pg.fetch_add(1, Ordering::SeqCst);
            ok(r#"{"value":[]}"#)
        } else {
            let base = b.lock().unwrap().clone();
            ok(&format!(
                r#"{{"value":[],"nextLink":"{base}{ZONE_PATH}/recordsets?api-version=2018-05-01&skip=1"}}"#
            ))
        }
    })
    .await;
    *base.lock().unwrap() = server.base.clone();
    provider(&server.base).list().await.unwrap();
    assert_eq!(pages.load(Ordering::SeqCst), 1);
}

/// The scope report of a credential with Reader on the zone: accepted, limited to the record sets
/// it was granted, with the record-set scope string, the az command and the "must exist first" note.
#[tokio::test]
async fn cld_904_azure_scope_reports_the_record_set_level_grant() {
    let server = start(|r| {
        if is_token(r) {
            ok(TOKEN)
        } else if r.target.contains("Microsoft.Authorization/permissions") {
            ok(PERMS_RECORD_SET)
        } else {
            ok(r#"{"value":[]}"#)
        }
    })
    .await;
    let s = provider(&server.base).scope().await.unwrap();
    assert!(!s.broader_than_needed, "{s:?}");
    assert!(s.record_sets.is_some());
    let notes = s.notes.join("\n");
    assert!(notes.contains("must exist before"), "{notes}");
    assert!(
        notes.contains("/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-dns/providers/Microsoft.Network/dnszones/example.net/TXT/_acme-challenge.<name>"),
        "{notes}"
    );
    assert!(
        notes.contains(
            "az role assignment create --assignee app-1 --role \"DNS Zone Contributor\" --scope"
        ),
        "{notes}"
    );
    let text = format!("{s:?}");
    assert!(!text.contains(SECRET) && !text.contains(ACCESS));
}

/// A credential that can write across the whole zone is reported as broader than needed.
#[tokio::test]
async fn cld_904_azure_scope_warns_for_a_zone_wide_role() {
    let server = start(|r| {
        if is_token(r) {
            ok(TOKEN)
        } else if r.target.contains("Microsoft.Authorization/permissions") {
            ok(PERMS_ZONE)
        } else {
            ok(r#"{"value":[]}"#)
        }
    })
    .await;
    let s = provider(&server.base).scope().await.unwrap();
    assert!(s.broader_than_needed, "{s:?}");
    assert_eq!(s.record_sets, None);
    assert!(
        s.notes[0].contains("move DNS Zone Contributor"),
        "{:?}",
        s.notes
    );
}

/// Without Reader on the zone the test fails and says what to grant; a missing zone is its own error.
#[tokio::test]
async fn cld_904_azure_scope_needs_read_on_the_zone() {
    let server = start(|r| {
        if is_token(r) {
            ok(TOKEN)
        } else {
            status(403, FORBIDDEN)
        }
    })
    .await;
    let e = provider(&server.base).scope().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Forbidden);
    assert!(format!("{e}").contains("Reader"), "{e}");
    assert!(!format!("{e}").contains(ACCESS));
    let server = start(|r| {
        if is_token(r) {
            ok(TOKEN)
        } else {
            status(
                404,
                r#"{"error":{"code":"ResourceGroupNotFound","message":"nope"}}"#,
            )
        }
    })
    .await;
    let e = provider(&server.base).list().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Rejected);
}

/// A name outside the zone is refused by the provider too, before any call; a missing credential is
/// an error, not a panic or a call.
#[tokio::test]
async fn cld_904_azure_refuses_outside_names_and_a_missing_credential() {
    let server = start(|_| ok("{}")).await;
    let p = provider(&server.base);
    let e = p
        .ensure(&txt("a.example.org", 60, &["v"]))
        .await
        .unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Rejected);
    assert!(server.seen().is_empty());
    let q = AzureDns::with_bases(&cfg(), None, &server.base, &server.base);
    let e = q.list().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Unauthorized);
    assert!(server.seen().is_empty());
}

/// 429 carries the Retry-After through to the engine's backoff.
#[tokio::test]
async fn cld_904_azure_rate_limit_keeps_retry_after() {
    let server = start(|r| {
        if is_token(r) {
            ok(TOKEN)
        } else {
            Answer(
                429,
                vec![("retry-after".to_owned(), "17".to_owned())],
                "{}".to_owned(),
            )
        }
    })
    .await;
    let e = provider(&server.base).list().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::RateLimited);
    assert_eq!(e.retry_after, Some(std::time::Duration::from_secs(17)));
}

#[test]
fn cld_904_azure_wildcards_and_strings() {
    use super::{txt_chunks, wild, zone_wide_write};
    assert!(wild(
        "Microsoft.Network/dnszones/*",
        "microsoft.network/dnszones/TXT/write"
    ));
    assert!(wild("*", "anything"));
    assert!(wild("*/read", "Microsoft.Network/dnszones/read"));
    assert!(!wild(
        "Microsoft.Network/dnszones/A/write",
        "Microsoft.Network/dnszones/TXT/write"
    ));
    assert!(!wild("*/read", "x/write"));
    assert_eq!(txt_chunks("abc"), vec!["abc".to_owned()]);
    // A multi-byte character is never split across two strings.
    let v = "é".repeat(200);
    assert!(
        txt_chunks(&v)
            .iter()
            .all(|c| c.len() <= 255 && c.chars().all(|ch| ch == 'é'))
    );
    // A deny rule removes the grant.
    let denied =
        json!({"value":[{"actions":["*"],"notActions":["Microsoft.Network/dnszones/*/write"]}]});
    assert!(!zone_wide_write(&denied));
    assert!(zone_wide_write(
        &serde_json::from_str::<Value>(PERMS_ZONE).unwrap()
    ));
    assert!(!zone_wide_write(
        &serde_json::from_str::<Value>(PERMS_RECORD_SET).unwrap()
    ));
}

/// The registry builds the kind (so the Test route reaches it), and keeps the secret out of Debug.
#[test]
fn cld_904_azure_is_in_the_registry() {
    let c = cfg();
    assert!(crate::dns_provider::registry::has_code(&c));
    let h = crate::dns_provider::registry::build(&c, Some(secret())).unwrap();
    assert_eq!(h.provider.kind(), "azure_dns");
    let text = format!("{h:?}");
    assert!(!text.contains("Zk39"), "{text}");
}

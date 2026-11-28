// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b4b) - the Cloudflare provider against a local server that replays
//! Cloudflare's documented answers (token verify, zones, DNS records). No live token and no real
//! endpoint: the base URL is the test's own.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};
use wrendns_config::DnsProviderConfig;
use zeroize::Zeroizing;

use super::Cloudflare;
use crate::dns_provider::http_json::replay::{Answer, Seen, ok, start, status};
use crate::dns_provider::registry::Handle;
use crate::dns_provider::{DnsProvider, ProviderErrorKind, RecordSet, RecordType};
use crate::secrets::value::SecretValue;

const VERIFY: &str = include_str!("testdata/cloudflare_verify.json");
const ZONES_ONE: &str = include_str!("testdata/cloudflare_zones_one.json");
const ZONES_TWO: &str = include_str!("testdata/cloudflare_zones_two.json");
const TXT_RECORDS: &str = include_str!("testdata/cloudflare_txt_records.json");
const CREATED: &str = include_str!("testdata/cloudflare_created.json");
const AUTH_ERROR: &str = include_str!("testdata/cloudflare_auth_error.json");
const TOKEN: &str = "cf-token-planted-77aa";
const ZONE_ID: &str = "023e105f4ecef8ad9ca31a8372d0c353";
const EMPTY: &str = r#"{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":100,"count":0,"total_count":0,"total_pages":1}}"#;
const DONE: &str = r#"{"success":true,"errors":[],"messages":[],"result":{"id":"r"}}"#;

fn cfg() -> DnsProviderConfig {
    serde_json::from_value(json!({
        "name": "cf-home", "kind": "cloudflare", "zone": "example.net", "credential_ref": "cf"
    }))
    .unwrap()
}

fn secret() -> SecretValue {
    SecretValue::from_text(Zeroizing::new(TOKEN.to_owned()))
}

fn provider(base: &str) -> Cloudflare {
    Cloudflare::with_base(&cfg(), Some(secret()), base)
}

fn txt(values: &[&str], ttl: u32) -> RecordSet {
    RecordSet {
        name: "_acme-challenge.home.example.net".to_owned(),
        rtype: RecordType::Txt,
        ttl,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
    }
}

/// The replayed API: verify, zone lookup and listing, the records of the challenge name, and the
/// write endpoints.
fn api(zones: &'static str) -> impl Fn(&Seen) -> Answer + Send + Sync + 'static {
    move |r| {
        let t = r.target.as_str();
        if t == "/user/tokens/verify" {
            ok(VERIFY)
        } else if t.starts_with("/zones?name=") {
            ok(ZONES_ONE)
        } else if t.starts_with("/zones?per_page") {
            ok(zones)
        } else if t.starts_with(&format!("/zones/{ZONE_ID}/dns_records?type=TXT")) {
            ok(TXT_RECORDS)
        } else if t.starts_with(&format!("/zones/{ZONE_ID}/dns_records?type=")) {
            ok(EMPTY)
        } else if r.method == "POST" && t == format!("/zones/{ZONE_ID}/dns_records") {
            ok(CREATED)
        } else if r.method == "PATCH" || r.method == "DELETE" {
            ok(DONE)
        } else {
            status(
                404,
                r#"{"success":false,"errors":[{"code":7003,"message":"no route"}]}"#,
            )
        }
    }
}

fn writes(seen: &[Seen]) -> Vec<(String, String, Value)> {
    seen.iter()
        .filter(|r| matches!(r.method.as_str(), "POST" | "PATCH" | "DELETE"))
        .map(|r| {
            (
                r.method.clone(),
                r.target.clone(),
                serde_json::from_str(&r.body).unwrap_or(Value::Null),
            )
        })
        .collect()
}

/// List, create, update and delete against the documented answers: Cloudflare holds one record per
/// value, so a set is made by re-using, patching, creating and deleting records.
#[tokio::test]
async fn cld_904_cloudflare_create_update_delete_against_recorded_api() {
    let server = start(api(ZONES_ONE)).await;
    let p = provider(&server.base);

    // List: the two records of one name are one set, unquoted, sorted; the TTL is the lowest.
    let sets = p.list().await.unwrap();
    assert_eq!(sets.len(), 1, "{sets:?}");
    assert_eq!(sets[0].name, "_acme-challenge.home.example.net");
    assert_eq!(
        sets[0].values,
        vec!["old-token".to_owned(), "second-token".to_owned()]
    );
    assert_eq!(sets[0].ttl, 60);

    // Update to one new value: one record takes it, the other is deleted, nothing is created.
    p.ensure(&txt(&["tok-1"], 60)).await.unwrap();
    let w = writes(&server.seen());
    assert_eq!(w.len(), 2, "{w:?}");
    assert_eq!(w[0].0, "PATCH");
    assert_eq!(w[0].1, format!("/zones/{ZONE_ID}/dns_records/r-txt-2"));
    assert_eq!(w[0].2, json!({ "content": "tok-1", "ttl": 60 }));
    assert_eq!(w[1].0, "DELETE");
    assert_eq!(w[1].1, format!("/zones/{ZONE_ID}/dns_records/r-txt-1"));
    assert!(server.seen().iter().filter(|r| r.method != "GET").all(|r| {
        r.head
            .to_lowercase()
            .contains(&format!("authorization: bearer {TOKEN}"))
    }));

    // Three values: two records are re-used, one is created.
    let server = start(api(ZONES_ONE)).await;
    let c = provider(&server.base)
        .ensure(&txt(&["a", "b", "c"], 60))
        .await
        .unwrap();
    assert!(c.id.is_some());
    let w = writes(&server.seen());
    assert_eq!(w.iter().filter(|x| x.0 == "PATCH").count(), 2, "{w:?}");
    let post: Vec<_> = w.iter().filter(|x| x.0 == "POST").collect();
    assert_eq!(post.len(), 1, "{w:?}");
    assert_eq!(post[0].2["type"], "TXT");
    assert_eq!(post[0].2["name"], "_acme-challenge.home.example.net");
    assert_eq!(post[0].2["ttl"], 60);
    assert_eq!(post[0].2["proxied"], false);
    assert!(w.iter().all(|x| x.0 != "DELETE"));

    // Already right (one record kept, the surplus one removed; no TTL change): a single delete.
    let server = start(api(ZONES_ONE)).await;
    provider(&server.base)
        .ensure(&txt(&["second-token"], 60))
        .await
        .unwrap();
    let w = writes(&server.seen());
    assert_eq!(w.len(), 1, "{w:?}");
    assert_eq!(w[0].0, "DELETE");

    // A TTL below Cloudflare's lowest is sent as the lowest.
    let server = start(api(ZONES_ONE)).await;
    provider(&server.base)
        .ensure(&txt(&["second-token"], 5))
        .await
        .unwrap();
    assert!(
        writes(&server.seen())
            .iter()
            .all(|x| x.2.get("ttl").is_none_or(|t| *t == 60)),
    );

    // Delete removes every record of the name and type.
    let server = start(api(ZONES_ONE)).await;
    provider(&server.base)
        .delete("_acme-challenge.home.example.net", RecordType::Txt)
        .await
        .unwrap();
    let w = writes(&server.seen());
    assert_eq!(w.len(), 2);
    assert!(w.iter().all(|x| x.0 == "DELETE"));
}

/// The zone is looked up by name once, however many calls follow.
#[tokio::test]
async fn cld_904_cloudflare_zone_lookup_is_cached() {
    let lookups = Arc::new(AtomicUsize::new(0));
    let l = Arc::clone(&lookups);
    let inner = api(ZONES_ONE);
    let server = start(move |r| {
        if r.target.starts_with("/zones?name=") {
            l.fetch_add(1, Ordering::SeqCst);
        }
        inner(r)
    })
    .await;
    let p = provider(&server.base);
    p.list().await.unwrap();
    p.ensure(&txt(&["second-token"], 60)).await.unwrap();
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
}

/// A token that reaches more than one zone is reported as broader than needed, naming the zones;
/// one zone is not, and a zone the token cannot see is an error.
#[tokio::test]
async fn cld_904_cloudflare_multi_zone_token_warns() {
    let server = start(api(ZONES_TWO)).await;
    let s = provider(&server.base).scope().await.unwrap();
    assert!(s.broader_than_needed, "{s:?}");
    assert!(s.summary.contains("2 zones"), "{}", s.summary);
    let notes = s.notes.join("\n");
    assert!(notes.contains("example.org"), "{notes}");
    assert!(notes.contains("delegate the challenge name"), "{notes}");
    assert_eq!(s.record_sets, None);

    let server = start(api(ZONES_ONE)).await;
    let s = provider(&server.base).scope().await.unwrap();
    assert!(!s.broader_than_needed, "{s:?}");
    assert!(s.summary.contains("no other zone"), "{}", s.summary);
    assert!(s.notes.join("\n").contains("every record in the zone"));

    // The configured zone is not among the zones the token sees.
    let other: &'static str = Box::leak(
        ZONES_ONE
            .replace("example.net", "example.org")
            .into_boxed_str(),
    );
    let inner = api(other);
    let server = start(move |r| {
        if r.target.starts_with("/zones?name=") {
            ok(other)
        } else {
            inner(r)
        }
    })
    .await;
    let e = provider(&server.base).scope().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Rejected);
    assert!(format!("{e}").contains("example.net"), "{e}");
}

/// A token whose zone answer says what it may do per zone is counted by the zones it can edit;
/// a long zone list is cut and reported, and does not fail a token that sees the zone.
#[tokio::test]
async fn cld_904_cloudflare_scope_counts_editable_zones_and_cuts_long_lists() {
    // Two zones readable, one editable: not broader than needed.
    let two: &'static str = Box::leak(
        ZONES_TWO
            .replace(
                "\"name\": \"example.net\",",
                "\"name\": \"example.net\", \"permissions\": [\"#dns_records:edit\", \"#zone:read\"],",
            )
            .replace(
                "\"name\": \"example.org\",",
                "\"name\": \"example.org\", \"permissions\": [\"#zone:read\"],",
            )
            .into_boxed_str(),
    );
    let server = start(api(two)).await;
    let s = provider(&server.base).scope().await.unwrap();
    assert!(!s.broader_than_needed, "{s:?}");

    // An endless zone list that never includes the entry's zone: cut at five pages, the zone is
    // found by name, and the answer says "more than".
    let server = start(|r| {
        let t = r.target.as_str();
        if t.starts_with("/zones?per_page") {
            ok(r#"{"success":true,"result":[{"id":"z","name":"other.test"}],"result_info":{"total_pages":99}}"#)
        } else {
            api(ZONES_ONE)(r)
        }
    })
    .await;
    let s = provider(&server.base).scope().await.unwrap();
    assert!(s.broader_than_needed, "{s:?}");
    assert!(s.summary.contains("more than"), "{}", s.summary);
}

/// A listing that still has pages at the page cap fails; it is never returned partial.
#[tokio::test]
async fn cld_919_cloudflare_capped_listing_fails() {
    let server = start(|r| {
        let t = r.target.as_str();
        if t.starts_with("/zones?name=") {
            ok(ZONES_ONE)
        } else {
            ok(r#"{"success":true,"result":[],"result_info":{"total_pages":9999}}"#)
        }
    })
    .await;
    let e = provider(&server.base).list().await.unwrap_err();
    assert!(e.to_string().contains("more records"), "{e}");
}

/// An inactive token is refused; an account-owned token (verify refused, zones listed) is accepted
/// with a note.
#[tokio::test]
async fn cld_904_cloudflare_token_status_and_account_tokens() {
    let inner = api(ZONES_ONE);
    let server = start(move |r| {
        if r.target == "/user/tokens/verify" {
            ok(&VERIFY.replace("\"active\"", "\"expired\""))
        } else {
            inner(r)
        }
    })
    .await;
    let s = provider(&server.base).scope().await.unwrap();
    assert!(s.notes.join("\n").contains("expired"), "{:?}", s.notes);

    let inner = api(ZONES_ONE);
    let server = start(move |r| {
        if r.target == "/user/tokens/verify" {
            status(
                401,
                r#"{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}"#,
            )
        } else {
            inner(r)
        }
    })
    .await;
    let s = provider(&server.base).scope().await.unwrap();
    assert!(
        s.notes.join("\n").contains("account-owned"),
        "{:?}",
        s.notes
    );
}

/// The token is in no error: a refusal that echoes it, through the provider and through the
/// engine's handle.
#[tokio::test]
async fn cld_904_cloudflare_token_never_in_an_error() {
    let server = start(|_| status(401, AUTH_ERROR)).await;
    let p = provider(&server.base);
    for e in [
        p.scope().await.unwrap_err(),
        p.list().await.unwrap_err(),
        p.ensure(&txt(&["v"], 60)).await.unwrap_err(),
        p.delete("_acme-challenge.home.example.net", RecordType::Txt)
            .await
            .unwrap_err(),
    ] {
        assert_eq!(e.kind, ProviderErrorKind::Unauthorized);
        let text = format!("{e} {e:?}");
        assert!(!text.contains(TOKEN), "{text}");
        assert!(!text.contains("planted"), "{text}");
        assert!(text.contains("Authentication error"), "{text}");
    }
    let handle = Handle {
        provider: Arc::new(provider(&server.base)),
        secret: Some(secret()),
    };
    let e = handle.scrub(handle.provider.list().await.unwrap_err());
    assert!(!format!("{e} {e:?}").contains(TOKEN));

    // A 403 hints at the permission to grant; a missing credential is not a call.
    let server = start(|_| {
        status(403, r#"{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}]}"#)
    })
    .await;
    let e = provider(&server.base).list().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Forbidden);
    assert!(format!("{e}").contains("Zone:DNS:Edit"), "{e}");
    let q = Cloudflare::with_base(&cfg(), None, &server.base);
    let before = server.seen().len();
    assert_eq!(
        q.list().await.unwrap_err().kind,
        ProviderErrorKind::Unauthorized
    );
    assert_eq!(server.seen().len(), before);
}

/// 429 carries Retry-After; a name outside the zone is refused before any call.
#[tokio::test]
async fn cld_904_cloudflare_rate_limit_and_outside_names() {
    let server = start(|_| {
        Answer(
            429,
            vec![("retry-after".to_owned(), "9".to_owned())],
            "{}".to_owned(),
        )
    })
    .await;
    let e = provider(&server.base).list().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::RateLimited);
    assert_eq!(e.retry_after, Some(std::time::Duration::from_secs(9)));

    let server = start(api(ZONES_ONE)).await;
    let mut set = txt(&["v"], 60);
    set.name = "a.example.org".to_owned();
    let e = provider(&server.base).ensure(&set).await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Rejected);
    assert!(server.seen().is_empty());
}

#[test]
fn cld_904_cloudflare_unquotes_txt_and_is_in_the_registry() {
    assert_eq!(super::unquote("\"abc\""), "abc");
    assert_eq!(super::unquote("abc"), "abc");
    assert_eq!(super::unquote("\""), "\"");
    let c = cfg();
    assert!(crate::dns_provider::registry::has_code(&c));
    let h = crate::dns_provider::registry::build(&c, Some(secret())).unwrap();
    assert_eq!(h.provider.kind(), "cloudflare");
    assert!(!format!("{h:?}").contains("planted"));
    // An entry named `nocode...` is the test build's way to a kind with no code.
    let mut n = serde_json::to_value(&c).unwrap();
    n["name"] = json!("nocode-cf");
    let n: DnsProviderConfig = serde_json::from_value(n).unwrap();
    assert!(!crate::dns_provider::registry::has_code(&n));
    assert!(crate::dns_provider::registry::build(&n, None).is_err());
}

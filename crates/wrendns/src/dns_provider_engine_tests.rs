// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904, CLD-919, CLU-004, DSC-908 (T36.10b step b3; ADR-1084 as amended 2026-11-27, ADR-1112)
//! The provider trait's write engine with the in-memory fake: idempotent writes, the zone and type
//! rules, dry run, the entry's write limits, Retry-After backoff, the ownership ledger and adopt, a
//! failure as a health reason only, the credential in no output, and the Test, records and adopt
//! routes of a real node end to end (the fake provider stands in for the DNS host).
//!
//! The cluster side: the ledger kind rides the node-managed blob and an older build skips it, and the
//! actions wait for every member's build.

#![allow(clippy::many_single_char_names)] // the tests' `h`, `s`, `v`, `p`, `b`, as the other API tests have

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};
use wrendns_api::auth;
use wrendns_config::DnsProviderConfig;

use crate::credential_tests::{Harness, harness, harness_in};
use crate::dns_provider::engine::{Engine, EngineError, Outcome, Who, engine};
use crate::dns_provider::fake::{self, FakeProvider};
use crate::dns_provider::ledger::{self, Ledger};
use crate::dns_provider::registry::{self, Handle};
use crate::dns_provider::{ProviderError, ProviderErrorKind, RecordSet, RecordType};
use crate::secrets_api_tests::{GATE, json_of, pair_features, req_from, token};

/// A value planted in a stored secret: it must never come back anywhere.
const SECRET: &str = "planted-provider-credential-91c4";

fn entry(name: &str, extra: &Value) -> DnsProviderConfig {
    let mut v = json!({
        "name": name, "kind": "cloudflare", "zone": "example.net", "credential_ref": "cf",
        "dry_run": false, "max_writes_per_minute": 60, "max_writes_per_hour": 1000
    });
    for (k, x) in extra.as_object().cloned().unwrap_or_default() {
        v[k] = x;
    }
    serde_json::from_value(v).unwrap()
}

fn set(name: &str, value: &str) -> RecordSet {
    RecordSet {
        name: name.to_owned(),
        rtype: RecordType::Txt,
        ttl: 60,
        values: vec![value.to_owned()],
    }
}

fn user() -> Who {
    Who::User {
        name: "ada".to_owned(),
        kind: "session",
        remote: None,
        reason: None,
    }
}

fn parts(h: &Harness, cfg: &DnsProviderConfig) -> (Arc<auth::Auth>, Handle, Arc<FakeProvider>) {
    let secret =
        crate::secrets::value::SecretValue::from_text(zeroize::Zeroizing::new(SECRET.to_owned()));
    let handle = registry::build(cfg, Some(secret)).unwrap();
    (
        Arc::clone(&h.auth),
        handle,
        fake::for_entry(cfg.name.as_str(), cfg.zone.as_str()),
    )
}

fn audit(h: &Harness) -> String {
    h.audit_text()
}

/// An entry that is written to twice with the same record set changes the provider once, and the
/// node owns what it made.
#[tokio::test]
async fn cld_904_ensure_is_idempotent() {
    let h = harness("");
    let cfg = entry("fake-idem", &json!({}));
    let (auth, handle, fake) = parts(&h, &cfg);
    let want = set("_acme-challenge.example.net", "tok-1");
    let first = engine()
        .ensure(&auth, &cfg, &handle, &user(), &want)
        .await
        .unwrap();
    assert!(matches!(first, Outcome::Written { .. }), "{first:?}");
    let second = engine()
        .ensure(&auth, &cfg, &handle, &user(), &want)
        .await
        .unwrap();
    assert_eq!(second, Outcome::Unchanged);
    assert_eq!(fake.writes(), 1, "the second call wrote nothing");
    let row = Ledger(auth.state())
        .get("fake-idem", RecordType::Txt, "_acme-challenge.example.net")
        .unwrap();
    assert_eq!(row.owner, ledger::Owner::Created);
    // The node changes what it made.
    let next = set("_acme-challenge.example.net", "tok-2");
    let o = engine()
        .ensure(&auth, &cfg, &handle, &user(), &next)
        .await
        .unwrap();
    assert!(
        matches!(&o, Outcome::Written { plan, .. } if plan.action == "update"),
        "{o:?}"
    );
    assert_eq!(
        fake.get("_acme-challenge.example.net", RecordType::Txt)
            .unwrap()
            .values,
        vec!["tok-2".to_owned()]
    );
    // And deletes it, which forgets the row.
    let d = engine()
        .delete(
            &auth,
            &cfg,
            &handle,
            &user(),
            "_acme-challenge.example.net",
            RecordType::Txt,
        )
        .await
        .unwrap();
    assert!(matches!(d, Outcome::Written { .. }));
    assert!(
        fake.get("_acme-challenge.example.net", RecordType::Txt)
            .is_none()
    );
    assert!(
        Ledger(auth.state())
            .get("fake-idem", RecordType::Txt, "_acme-challenge.example.net")
            .is_none()
    );
}

/// A name outside the zone, a type other than TXT, A or AAAA and a value that does not fit the type
/// are refused before the provider is called.
#[tokio::test]
async fn cld_904_out_of_zone_name_and_other_types_are_refused() {
    let h = harness("");
    let cfg = entry("fake-zone", &json!({}));
    let (auth, handle, fake) = parts(&h, &cfg);
    for bad in [
        set("host.example.org", "x"),
        set("example.net.evil.org", "x"),
        set("badexample.net", "x"),
    ] {
        let e = engine()
            .ensure(&auth, &cfg, &handle, &user(), &bad)
            .await
            .unwrap_err();
        assert!(matches!(e, EngineError::Refused(_)), "{bad:?}: {e:?}");
    }
    let mut a = set("www.example.net", "not-an-address");
    a.rtype = RecordType::A;
    assert!(matches!(
        engine().ensure(&auth, &cfg, &handle, &user(), &a).await,
        Err(EngineError::Refused(_))
    ));
    let e = engine()
        .delete(
            &auth,
            &cfg,
            &handle,
            &user(),
            "host.example.org",
            RecordType::Txt,
        )
        .await
        .unwrap_err();
    assert!(matches!(e, EngineError::Refused(_)));
    assert!(RecordType::parse("MX").is_none() && RecordType::parse("CNAME").is_none());
    assert!(
        fake.calls().is_empty(),
        "the provider was never called: {:?}",
        fake.calls()
    );
}

/// A dry-run entry reads the zone, writes nothing, and records what it would have written.
#[tokio::test]
async fn cld_919_dry_run_makes_no_write_and_records_a_dry_run_entry() {
    let h = harness("");
    let cfg = entry("fake-dry", &json!({"dry_run": true}));
    let (auth, handle, fake) = parts(&h, &cfg);
    let o = engine()
        .ensure(
            &auth,
            &cfg,
            &handle,
            &user(),
            &set("_acme-challenge.example.net", "tok"),
        )
        .await
        .unwrap();
    assert!(
        matches!(&o, Outcome::DryRun(p) if p.action == "create"),
        "{o:?}"
    );
    assert_eq!(fake.writes(), 0);
    assert!(
        fake.calls().iter().any(|c| c.op == "list"),
        "reads still run"
    );
    let a = audit(&h);
    assert!(
        a.contains("dns_provider.ensure fake-dry/_acme-challenge.example.net/TXT")
            && a.contains("\"dry_run\":true")
            && a.contains("tok"),
        "{a}"
    );
    assert!(
        Ledger(auth.state())
            .get("fake-dry", RecordType::Txt, "_acme-challenge.example.net")
            .is_none(),
        "a dry run owns nothing"
    );
}

/// The entry's limits: 30 writes an hour (the 31st is refused with when to come back), 5 a minute.
#[tokio::test]
async fn cld_919_the_bucket_refuses_the_31st_write_in_an_hour() {
    let h = harness("");
    let eng = Engine::default();
    let cfg = entry(
        "fake-hour",
        &json!({"max_writes_per_hour": 30, "max_writes_per_minute": 60}),
    );
    let (auth, handle, fake) = parts(&h, &cfg);
    for i in 0..30 {
        eng.ensure(
            &auth,
            &cfg,
            &handle,
            &user(),
            &set(&format!("h{i}.example.net"), "v"),
        )
        .await
        .unwrap();
    }
    let e = eng
        .ensure(&auth, &cfg, &handle, &user(), &set("h30.example.net", "v"))
        .await
        .unwrap_err();
    let EngineError::Limited { retry_after, why } = e else {
        panic!("{e:?}");
    };
    assert_eq!(why, "writes an hour");
    assert!(retry_after > Duration::from_mins(50), "{retry_after:?}");
    assert_eq!(fake.writes(), 30, "the 31st never reached the provider");
    eng.advance(Duration::from_secs(3601));
    eng.ensure(&auth, &cfg, &handle, &user(), &set("h30.example.net", "v"))
        .await
        .unwrap();

    let cfg = entry("fake-min", &json!({"max_writes_per_minute": 5}));
    let (auth, handle, _) = parts(&h, &cfg);
    for i in 0..5 {
        eng.ensure(
            &auth,
            &cfg,
            &handle,
            &user(),
            &set(&format!("m{i}.example.net"), "v"),
        )
        .await
        .unwrap();
    }
    let e = eng
        .ensure(&auth, &cfg, &handle, &user(), &set("m5.example.net", "v"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            EngineError::Limited {
                why: "writes a minute",
                ..
            }
        ),
        "{e:?}"
    );
    eng.advance(Duration::from_secs(61));
    eng.ensure(&auth, &cfg, &handle, &user(), &set("m5.example.net", "v"))
        .await
        .unwrap();
}

/// A 429 with Retry-After stops every call to that entry until the time is up.
#[tokio::test]
async fn cld_919_a_429_backs_off_by_retry_after() {
    let h = harness("");
    let eng = Engine::default();
    let cfg = entry("fake-429", &json!({}));
    let (auth, handle, fake) = parts(&h, &cfg);
    fake.fail_next_write(ProviderError::rate_limited(Some(Duration::from_secs(120))));
    let want = set("a.example.net", "v");
    let e = eng
        .ensure(&auth, &cfg, &handle, &user(), &want)
        .await
        .unwrap_err();
    assert!(
        matches!(&e, EngineError::Provider(p) if p.kind == ProviderErrorKind::RateLimited),
        "{e:?}"
    );
    let calls = fake.calls().len();
    let e = eng
        .ensure(&auth, &cfg, &handle, &user(), &want)
        .await
        .unwrap_err();
    let EngineError::Backoff(d) = e else {
        panic!("{e:?}");
    };
    assert!(
        d > Duration::from_secs(100) && d <= Duration::from_secs(120),
        "{d:?}"
    );
    assert_eq!(
        fake.calls().len(),
        calls,
        "no call went out while backing off"
    );
    let p = crate::dns_provider_ops::problem(&EngineError::Backoff(d));
    assert_eq!(p.status, 429);
    assert!(p.retry_after.is_some_and(|s| s >= 100));
    eng.advance(Duration::from_secs(121));
    eng.ensure(&auth, &cfg, &handle, &user(), &want)
        .await
        .unwrap();
}

/// A record set that exists and was not made by the node is never overwritten or deleted until an
/// admin adopts it; the ledger is in `state.db` and survives a restart.
#[tokio::test]
async fn cld_919_an_unowned_record_set_is_not_overwritten_until_adopted() {
    let h = harness("");
    let cfg = entry("fake-own", &json!({}));
    let (auth, handle, fake) = parts(&h, &cfg);
    fake.seed(set("legacy.example.net", "theirs"));
    let want = set("legacy.example.net", "mine");
    let e = engine()
        .ensure(&auth, &cfg, &handle, &user(), &want)
        .await
        .unwrap_err();
    assert!(matches!(e, EngineError::NotOwned(_)), "{e:?}");
    let e = engine()
        .delete(
            &auth,
            &cfg,
            &handle,
            &user(),
            "legacy.example.net",
            RecordType::Txt,
        )
        .await
        .unwrap_err();
    assert!(matches!(e, EngineError::NotOwned(_)), "{e:?}");
    assert_eq!(fake.writes(), 0);
    assert_eq!(
        fake.get("legacy.example.net", RecordType::Txt)
            .unwrap()
            .values,
        vec!["theirs".to_owned()]
    );
    // Adopt: then the node may change it.
    let row = engine()
        .adopt(
            &auth,
            &cfg,
            &handle,
            &user(),
            "legacy.example.net",
            RecordType::Txt,
        )
        .await
        .unwrap();
    assert_eq!(row.owner, ledger::Owner::Adopted);
    engine()
        .ensure(&auth, &cfg, &handle, &user(), &want)
        .await
        .unwrap();
    assert_eq!(
        fake.get("legacy.example.net", RecordType::Txt)
            .unwrap()
            .values,
        vec!["mine".to_owned()]
    );
    // Adopting what is not there is refused.
    let e = engine()
        .adopt(
            &auth,
            &cfg,
            &handle,
            &user(),
            "ghost.example.net",
            RecordType::Txt,
        )
        .await
        .unwrap_err();
    assert!(matches!(e, EngineError::Refused(_)), "{e:?}");
    // Kept across a restart: a new connection to the same state.db sees the row.
    let dir = h.src.config.load().node.data_dir.to_string();
    let reopened =
        wrendns_store::state::State::open(&std::path::Path::new(&dir).join("state.db")).unwrap();
    assert_eq!(
        Ledger(&reopened)
            .get("fake-own", RecordType::Txt, "legacy.example.net")
            .unwrap()
            .owner,
        ledger::Owner::Adopted
    );
    let a = audit(&h);
    assert!(
        a.contains("dns_provider.adopt fake-own/legacy.example.net/TXT"),
        "{a}"
    );
}

/// A provider that fails is a health reason and nothing else: degraded (never severe), the entry
/// named, and a later success clears it. (DNS answering does not call the engine at all.)
#[tokio::test]
async fn clu_004_a_provider_failure_is_health_only() {
    let h = harness("");
    let cfg = entry("fake-down", &json!({}));
    let (auth, handle, fake) = parts(&h, &cfg);
    fake.fail_next(ProviderError::new(
        ProviderErrorKind::Unavailable,
        "bad gateway",
    ));
    let e = engine()
        .ensure(&auth, &cfg, &handle, &user(), &set("a.example.net", "v"))
        .await
        .unwrap_err();
    assert!(matches!(e, EngineError::Provider(_)));
    let failures = engine().failures();
    assert!(
        failures.iter().any(|(n, _)| n == "fake-down"),
        "{failures:?}"
    );
    let reasons = crate::health::dns_provider_reasons(&failures);
    let r = reasons
        .iter()
        .find(|r| r.summary.contains("fake-down"))
        .unwrap();
    assert_eq!(r.code, "dns_provider_failing");
    assert_eq!(r.level, "degraded", "never severe: {r:?}");
    assert!(r.summary.contains("DNS answers are unaffected"));
    engine()
        .ensure(&auth, &cfg, &handle, &user(), &set("a.example.net", "v"))
        .await
        .unwrap();
    assert!(!engine().failures().iter().any(|(n, _)| n == "fake-down"));
}

// REQ: CLD-904, CLU-004 - a failure recorded before the entry was deleted is no health reason.
#[tokio::test]
async fn clu_004_a_deleted_entrys_failure_leaves_the_health_reasons() {
    let h = harness("");
    let cfg = entry("fake-gone", &json!({}));
    let (auth, handle, fake) = parts(&h, &cfg);
    fake.fail_next(ProviderError::new(
        ProviderErrorKind::Unavailable,
        "bad gateway",
    ));
    let _ = engine()
        .ensure(&auth, &cfg, &handle, &user(), &set("a.example.net", "v"))
        .await
        .unwrap_err();
    let kept = vec!["fake-gone".to_owned()];
    assert!(
        engine()
            .failures_among(&kept)
            .iter()
            .any(|(n, _)| n == "fake-gone")
    );
    // The entry is deleted: its name is no longer in the configuration.
    let left = engine().failures_among(&[]);
    assert!(!left.iter().any(|(n, _)| n == "fake-gone"), "{left:?}");
}

fn provider_body(name: &str) -> Value {
    let _ = name;
    json!({"kind": "cloudflare", "zone": "example.net", "credential_ref": "cf"})
}

async fn store_secret(h: &Harness) {
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/secrets/cf",
            Some(&json!({"value": SECRET, "kind": "text"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// The Test route of a real node with the fake behind it: the scope is shown, the first success
/// ends dry run, the secret is in no answer, audit entry, health reason, log line or support package,
/// even when the provider's own error quotes it.
#[tokio::test]
async fn cld_904_secret_absent_from_logs_errors_api_audit_and_support_package() {
    let h = harness("");
    store_secret(&h).await;
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/dns-providers/fake-sec",
            Some(&provider_body("fake-sec")),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let fake = fake::for_entry("fake-sec", "example.net");
    // The provider's own error quotes the credential: it comes back scrubbed.
    fake.fail_next(fake::unauthorized_quoting(SECRET));
    let (s, _, bad) = h
        .call("POST", "/api/v1/dns-providers/fake-sec/test", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{bad}");
    assert_eq!(bad["ok"], false, "{bad}");
    assert!(
        bad["error"].as_str().unwrap().contains("<redacted>"),
        "{bad}"
    );
    let failures = engine().failures();
    let reasons = crate::health::dns_provider_reasons(&failures);
    let mut seen = vec![
        bad.to_string(),
        audit(&h),
        format!("{failures:?} {reasons:?}"),
    ];
    // A good test: the scope, the broader-than-needed warning, dry run ended.
    let (s, _, ok) = h
        .call("POST", "/api/v1/dns-providers/fake-sec/test", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{ok}");
    assert_eq!(ok["ok"], true, "{ok}");
    assert_eq!(ok["supported"], true);
    assert_eq!(ok["dryRunCleared"], true, "{ok}");
    assert_eq!(ok["dryRun"], false);
    assert_eq!(ok["scope"]["zone"], "example.net");
    assert_eq!(ok["scope"]["broaderThanNeeded"], true);
    assert_eq!(ok["scope"]["recordTypes"], json!(["A", "AAAA", "TXT"]));
    // The second test changes nothing.
    let (_, _, again) = h
        .call("POST", "/api/v1/dns-providers/fake-sec/test", None)
        .await;
    assert_eq!(again["dryRunCleared"], false, "{again}");
    let (_, _, list) = h.call("GET", "/api/v1/dns-providers", None).await;
    assert_eq!(list["items"][0]["dryRun"], false, "{list}");
    assert_eq!(list["items"][0]["state"], "ready", "{list}");
    assert!(h.src.config.load().dns_provider.iter().all(|p| !p.dry_run));
    let a = audit(&h);
    assert!(
        a.contains("dns_provider.test") && a.contains("dns_provider.dry_run_ended"),
        "{a}"
    );
    seen.extend([
        ok.to_string(),
        again.to_string(),
        list.to_string(),
        audit(&h),
    ]);
    let req = wrendns_api::model::SupportPackageRequest {
        level: Some("none".into()),
        reveal: Vec::new(),
        query_sample: 0,
        keep_map: false,
        cluster: false,
    };
    let (pkg, _) = crate::support::offline(&h.src.config.load(), &req).unwrap();
    for f in wrendns_support::archive::read_tar_gz(&pkg.archive).unwrap() {
        seen.push(String::from_utf8_lossy(&f.data).into_owned());
    }
    for text in seen {
        assert!(!text.contains(SECRET), "the credential came back: {text}");
    }
}

/// A real kind has no provider code yet: Test says so (200, `supported: false`), records and adopt
/// answer 409, and the entry reads `not_used`.
#[tokio::test]
async fn cld_904_a_kind_without_code_says_so() {
    let h = harness("");
    store_secret(&h).await;
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/dns-providers/cf-home",
            Some(&provider_body("cf-home")),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = h
        .call("POST", "/api/v1/dns-providers/cf-home/test", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], false);
    assert_eq!(v["supported"], false);
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("no provider code for the `cloudflare` kind yet"),
        "{v}"
    );
    assert_eq!(v["dryRun"], true, "an unsupported test never ends dry run");
    let (s, _, v) = h
        .call("GET", "/api/v1/dns-providers/cf-home/records", None)
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, _, v) = h
        .call(
            "POST",
            "/api/v1/dns-providers/cf-home/records/adopt",
            Some(&json!({"name": "a.example.net", "recordType": "TXT"})),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (_, _, list) = h.call("GET", "/api/v1/dns-providers", None).await;
    assert_eq!(list["items"][0]["state"], "not_used", "{list}");
    let (s, _, _) = h
        .call("POST", "/api/v1/dns-providers/nope/test", None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// The records and adopt routes: the zone with who owns each set; an adopt (type checked, name in the
/// zone) puts a record in the ledger; an operator, a viewer and an agent are refused.
#[tokio::test]
async fn cld_919_records_and_adopt_through_the_api_are_admin_only() {
    let h = harness("");
    store_secret(&h).await;
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/dns-providers/fake-adopt",
            Some(&provider_body("fake-adopt")),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let fake = fake::for_entry("fake-adopt", "example.net");
    fake.seed(set("legacy.example.net", "theirs"));
    let (s, _, recs) = h
        .call("GET", "/api/v1/dns-providers/fake-adopt/records", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{recs}");
    assert_eq!(recs["dryRun"], true);
    assert_eq!(recs["items"][0]["name"], "legacy.example.net");
    assert!(recs["items"][0].get("owner").is_none(), "{recs}");
    for bad in [
        json!({"name": "x.example.org", "recordType": "TXT"}),
        json!({"name": "legacy.example.net", "recordType": "MX"}),
        json!({"name": "ghost.example.net", "recordType": "TXT"}),
    ] {
        let (s, _, v) = h
            .call(
                "POST",
                "/api/v1/dns-providers/fake-adopt/records/adopt",
                Some(&bad),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {v}");
    }
    let (s, _, v) = h
        .call(
            "POST",
            "/api/v1/dns-providers/fake-adopt/records/adopt",
            Some(&json!({"name": "legacy.example.net", "recordType": "txt"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["owner"], "adopted");
    let (_, _, recs) = h
        .call("GET", "/api/v1/dns-providers/fake-adopt/records", None)
        .await;
    assert_eq!(recs["items"][0]["owner"], "adopted", "{recs}");
    assert!(
        recs["items"][0]["by"].as_str().unwrap().contains("root"),
        "{recs}"
    );

    let every: Vec<&str> = auth::agent::SCOPES.iter().map(|(n, _)| *n).collect();
    let agent = token(&h, "bot-own", auth::Role::Admin, Some(&every.join(" ")));
    let op = token(&h, "olive-own", auth::Role::Operator, None);
    let viewer = token(&h, "vic-own", auth::Role::Viewer, None);
    let adopt = json!({"name": "legacy.example.net", "recordType": "TXT"});
    for (who, bearer, code) in [
        ("operator", &op, "forbidden"),
        ("viewer", &viewer, "forbidden"),
        ("agent", &agent, "agent_not_allowed"),
    ] {
        for (m, uri, b) in [
            ("POST", "/api/v1/dns-providers/fake-adopt/test", None),
            ("GET", "/api/v1/dns-providers/fake-adopt/records", None),
            (
                "POST",
                "/api/v1/dns-providers/fake-adopt/records/adopt",
                Some(&adopt),
            ),
        ] {
            let (s, _, v) = json_of(&h, req_from(bearer, [127, 0, 0, 1], m, uri, b)).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{who} {m} {uri}: {v}");
            assert_eq!(v["code"], code, "{who} {m} {uri}: {v}");
        }
    }
}

/// An entry the files define keeps the file's dry run: a good test says so and changes nothing.
#[tokio::test]
async fn cld_919_a_file_entry_keeps_the_files_dry_run() {
    let h = harness(
        "[[dns_provider]]\nname = \"fake-file\"\nkind = \"cloudflare\"\nzone = \"example.net\"\ncredential_ref = \"cf\"\n",
    );
    store_secret(&h).await;
    let (s, _, v) = h
        .call("POST", "/api/v1/dns-providers/fake-file/test", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["dryRunCleared"], false);
    assert_eq!(v["dryRun"], true);
    assert!(
        v["note"].as_str().unwrap().contains("configuration file"),
        "{v}"
    );
}

/// The ledger is a node-managed kind: its rows ride the manifest's node-managed blob (names and
/// times, no values), and a build that does not know the kind skips them and reads the rest.
#[test]
fn cld_919_the_ledger_rides_the_node_managed_blob_and_an_older_build_skips_it() {
    let rows = vec![
        (
            ledger::KIND.to_owned(),
            "cf-home/TXT/legacy.example.net".to_owned(),
            r#"{"provider":"cf-home","name":"legacy.example.net","rtype":"Txt","owner":"adopted","by":"ada","at":1}"#
                .to_owned(),
        ),
        (
            crate::managed::OIDC_PROVIDER.to_owned(),
            "kc".to_owned(),
            r#"{"id":"kc"}"#.to_owned(),
        ),
    ];
    let blob = crate::node_managed::encode(&rows);
    assert!(crate::node_managed::KINDS.contains(&ledger::KIND));
    let got = crate::node_managed::parse(&blob).unwrap();
    assert!(got.iter().any(|e| e.kind == ledger::KIND), "{got:?}");
    let old: Vec<&str> = crate::node_managed::KINDS
        .iter()
        .copied()
        .filter(|k| *k != ledger::KIND)
        .collect();
    let seen = crate::node_managed::parse_kinds(&blob, &old).unwrap();
    assert!(seen.iter().all(|e| e.kind != ledger::KIND), "{seen:?}");
    assert!(seen.iter().any(|e| e.kind == crate::managed::OIDC_PROVIDER));
    assert!(
        !String::from_utf8_lossy(&blob).contains(SECRET),
        "the blob carries references only"
    );
}

/// The actions wait for every member's build: a node with an older member refuses (409, naming the
/// member and its version, nothing run) and a replica does not forward to a primary that lacks the
/// ledger; with current builds a replica forwards.
#[tokio::test(flavor = "multi_thread")]
async fn dsc_908_the_dns_ledger_actions_wait_for_every_members_build() {
    let _turn = GATE.lock().await;
    crate::upgrade_gate::forget_held();
    let toml = "[[dns_provider]]\nname = \"fake-gate\"\nkind = \"cloudflare\"\nzone = \"example.net\"\ncredential_ref = \"cf\"\n";
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    let ph = harness_in(toml, Some(Arc::clone(&old.primary)));
    crate::http::serve_peers(&ph.src);
    store_secret(&ph).await;
    for (m, uri, b) in [
        ("POST", "/api/v1/dns-providers/fake-gate/test", None),
        ("GET", "/api/v1/dns-providers/fake-gate/records", None),
        (
            "POST",
            "/api/v1/dns-providers/fake-gate/records/adopt",
            Some(json!({"name": "a.example.net", "recordType": "TXT"})),
        ),
    ] {
        let (s, _, v) = ph.call(m, uri, b.as_ref()).await;
        assert_eq!(s, StatusCode::CONFLICT, "{m} {uri}: {v}");
        assert_eq!(v["code"], "upgrade_required", "{v}");
        let d = v["detail"].as_str().unwrap();
        assert!(
            d.contains("version 1.1.0-edge.40")
                && d.contains("does not know the DNS-provider ownership ledger"),
            "{v}"
        );
    }
    assert!(
        fake::for_entry("fake-gate", "example.net")
            .calls()
            .is_empty(),
        "nothing ran"
    );
    let _ = old.stop.send(true);

    // A replica with a primary that lacks the ledger does not forward.
    let announce_all_but_ledger: Vec<String> = wrendns_cluster::gate::own_features()
        .into_iter()
        .filter(|f| f != "dns_provider_ledger")
        .collect();
    let (replica, older) = crate::credential_tests::older_primary_and_replica_features(
        "1.1.0",
        Some(announce_all_but_ledger),
        None,
    )
    .await;
    let rh = harness_in(toml, Some(replica));
    let (s, _, v) = rh
        .call("POST", "/api/v1/dns-providers/fake-gate/test", None)
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "upgrade_required", "{v}");
    assert_eq!(older.got.lock().unwrap().len(), 0, "not forwarded");
    let _ = older.stop.send(true);

    // Current builds: the replica forwards the test to the primary.
    let (replica, current) = crate::credential_tests::older_primary_and_replica("1.1.0").await;
    let rh = harness_in(toml, Some(replica));
    let _ = rh
        .call("POST", "/api/v1/dns-providers/fake-gate/test", None)
        .await;
    assert!(!current.got.lock().unwrap().is_empty(), "forwarded");
    let _ = current.stop.send(true);
    crate::upgrade_gate::forget_held();
}

/// The forwarded action survives the cluster channel intact.
#[test]
fn cld_919_the_forwarded_action_round_trips() {
    let w = crate::forward::Write::DnsProvider(wrendns_api::DnsProviderOp {
        name: "cf-home".to_owned(),
        action: wrendns_api::DnsProviderAction::Adopt {
            record: "a.example.net".to_owned(),
            record_type: "TXT".to_owned(),
        },
        by: "ada".to_owned(),
        remote: None,
        reason: Some("tidy".to_owned()),
    });
    let wire = serde_json::to_vec(&w).unwrap();
    let back: crate::forward::Write = serde_json::from_slice(&wire).unwrap();
    let crate::forward::Write::DnsProvider(op) = back else {
        panic!("not a provider action");
    };
    assert_eq!(op.name, "cf-home");
    assert!(matches!(
        op.action,
        wrendns_api::DnsProviderAction::Adopt { .. }
    ));
}

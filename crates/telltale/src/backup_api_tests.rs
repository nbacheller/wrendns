//! REQ: API-007, API-015, AGT-004, OPS-014 (T23.9, ADR-903 §8) — `POST /api/v1/backup` through a
//! running node: a backup with a passphrase carries the stored secrets and needs an admin's
//! interactive session signed in within 10 minutes, over HTTPS or loopback, never an agent;
//! nothing of the passphrase or a value is answered, logged or audited.

// The tests that derive a key hold the backup module's test lock for their whole run, so two of
// them never meet in the one KDF slot. They run on one thread; the lock is never taken in the
// handlers they call.
#![allow(
    clippy::await_holding_lock,
    clippy::assert_is_empty,
    clippy::format_push_string
)]

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use telltale_api::Backend as _;
use telltale_api::auth;
use tower::ServiceExt as _;

use crate::credential_tests::{Harness, harness};

const PASS: &str = "correct horse battery staple";
const VALUE: &str = "planted-backup-secret-4e71a9";

fn secret_put(h: &Harness, name: &str, value: &str) -> Request<Body> {
    h.request(
        "PUT",
        &format!("/api/v1/secrets/{name}"),
        Some(&json!({"value": value, "kind": "text"})),
    )
}

async fn plant(h: &Harness) {
    let (s, _, t) = h.send(secret_put(h, "unifi", VALUE)).await;
    assert_eq!(s, StatusCode::OK, "{t}");
    let (s, _, t) = h
        .send(secret_put(h, "ntfy", "planted-other-value-15d2"))
        .await;
    assert_eq!(s, StatusCode::OK, "{t}");
}

/// A request from the admin's signed-in session, whose sign-in was `age` seconds ago.
fn from_session(h: &Harness, age: u64, uri_body: Option<Value>) -> Request<Body> {
    let user = h.auth.state().user(h.admin_id).unwrap().unwrap();
    let now = crate::pipeline::unix_now().saturating_sub(age);
    let s = h
        .auth
        .start_session(&user, "127.0.0.1".parse().unwrap(), now)
        .unwrap();
    // The session has to be "now" for the idle limit: only its creation time is old.
    let id_hash = auth::crypto::secret_hash(&s.cookie);
    h.auth
        .state()
        .touch_session(&id_hash, crate::pipeline::unix_now())
        .unwrap();
    Request::builder()
        .method("POST")
        .uri("/api/v1/backup")
        .header("cookie", format!("{}={}", auth::routes::COOKIE, s.cookie))
        .header("x-csrf-token", &s.csrf)
        .header("content-type", "application/json")
        .extension(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            40000,
        ))))
        .body(uri_body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap()
}

/// The status, headers and raw body of `req`.
async fn send(h: &Harness, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let resp = h.app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let body = tokio::time::timeout(
        Duration::from_secs(30),
        axum::body::to_bytes(resp.into_body(), 64 << 20),
    )
    .await
    .unwrap()
    .unwrap();
    (status, headers, body.to_vec())
}

fn json_of(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap_or(Value::Null)
}

fn archive_of(h: &Harness, bytes: &[u8]) -> crate::backup::Manifest {
    let path = h.dir_path().join("downloaded.ttbk");
    std::fs::write(&path, bytes).unwrap();
    crate::backup::show(&path).unwrap()
}

fn audit_backups(h: &Harness) -> String {
    h.auth
        .state()
        .audit_page(None, 100, Some("backup."), None)
        .unwrap()
        .iter()
        .map(|e| format!("{} | {} | {} | {}\n", e.actor, e.action, e.target, e.detail))
        .collect::<Vec<_>>()
        .concat()
}

// REQ: API-007 (AC1) — GET, and POST without a passphrase, leave the stored secrets out and say
// how many (`X-Telltale-Backup-Secrets`); an admin token is enough for those.
#[tokio::test]
async fn api_007_backup_without_passphrase_omits_secrets() {
    let h = harness("");
    plant(&h).await;
    for (method, body) in [("GET", None), ("POST", Some(json!({}))), ("POST", None)] {
        let (s, hd, bytes) = send(&h, h.request(method, "/api/v1/backup", body.as_ref())).await;
        assert_eq!(s, StatusCode::OK, "{method}");
        assert_eq!(hd["x-telltale-backup-secrets"], "omitted; count=2");
        assert_eq!(hd["cache-control"], "no-store");
        let m = archive_of(&h, &bytes);
        assert_eq!(m.version, 1);
        assert!(!bytes.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
    }
    let audit = audit_backups(&h);
    assert!(
        audit.contains("\"secretsIncluded\":false") && audit.contains("\"count\""),
        "{audit}"
    );
}

// REQ: API-007 (AC2, AC12) — with a passphrase and a session signed in just now the backup carries
// the secrets (`included; count=2`, format 2), audited as `backup.create {secretsIncluded, count}`,
// and it restores.
#[tokio::test]
async fn api_007_roundtrip_with_passphrase() {
    let _serial = crate::backup::test_lock();
    let h = harness("");
    plant(&h).await;
    let (s, hd, bytes) = send(
        &h,
        from_session(
            &h,
            0,
            Some(json!({"passphrase": PASS, "includeQlog": false})),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&bytes));
    assert_eq!(hd["x-telltale-backup-secrets"], "included; count=2");
    assert!(
        hd["content-disposition"]
            .to_str()
            .unwrap()
            .contains(".ttbk")
    );
    let m = archive_of(&h, &bytes);
    assert_eq!(m.version, 2);
    assert!(m.has_secrets());
    assert!(!bytes.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
    let audit = audit_backups(&h);
    assert!(
        audit.contains("\"secretsIncluded\":true") && audit.contains("\"count\":2"),
        "{audit}"
    );
    // It restores under another node's key with the passphrase.
    let new = h.dir_path().join("restored");
    let none: crate::secrets::store::EnvFn = std::sync::Arc::new(|_: &str| None);
    let r = crate::backup::restore_with(
        &h.dir_path().join("downloaded.ttbk"),
        Some(&new.join("data")),
        Some(&new.join("etc")),
        false,
        &crate::backup::SecretsMode::Passphrase(zeroize::Zeroizing::new(PASS.to_owned())),
        &crate::backup::RestoreKeys {
            cfg: None,
            env: &*none,
        },
    )
    .unwrap();
    assert_eq!(r.secrets.unwrap().count, 2);
}

// REQ: API-007 (AC12) — a passphrase backup needs a recent sign-in: a token (even an admin's) gets
// 403 `reauth_required` with a hint to run the CLI, so does a session signed in over 10 minutes
// ago, and one signed in just now is accepted.
#[tokio::test]
async fn api_007_passphrase_backup_needs_recent_sign_in() {
    let _serial = crate::backup::test_lock();
    let h = harness("");
    plant(&h).await;
    let body = json!({"passphrase": PASS});
    let (s, hd, b) = send(&h, h.request("POST", "/api/v1/backup", Some(&body))).await;
    let v = json_of(&b);
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "reauth_required");
    assert!(
        v["hint"]
            .as_str()
            .unwrap()
            .contains("telltale backup create"),
        "{v}"
    );
    assert_eq!(hd["cache-control"], "no-store");
    assert!(!v.to_string().contains(PASS));
    // A session signed in 11 minutes ago.
    let (s, _, b) = send(&h, from_session(&h, 11 * 60, Some(body.clone()))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(json_of(&b)["code"], "reauth_required");
    // 9 minutes ago is within the window.
    let (s, _, b) = send(&h, from_session(&h, 9 * 60, Some(body.clone()))).await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    // The recent-sign-in rule is only for a passphrase: without one an old session is fine.
    let (s, _, _) = send(&h, from_session(&h, 3 * 3600, Some(json!({})))).await;
    assert_eq!(s, StatusCode::OK);
    // Nothing was made for the refusals.
    let audit = audit_backups(&h);
    assert_eq!(audit.matches("backup.create").count(), 2, "{audit}");
}

// REQ: API-007 (AC13) — agent tokens never make a backup, whatever their scopes or their owner's
// role: 403 `agent_not_allowed`.
#[tokio::test]
async fn api_007_backup_post_refused_for_agents() {
    let h = harness("");
    let now = crate::pipeline::unix_now();
    let owner = h
        .auth
        .create_user(
            "bot-owner",
            "correct horse battery",
            auth::Role::Admin,
            false,
            now,
        )
        .unwrap();
    let (id, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
    h.auth
        .state()
        .create_token(
            &id,
            owner.id,
            "bot",
            &auth::crypto::secret_hash(&secret),
            "admin",
            None,
            now,
        )
        .unwrap();
    let every: Vec<&str> = auth::agent::SCOPES.iter().map(|(n, _)| *n).collect();
    h.auth
        .state()
        .set_token_agent(&id, &every.join(" "), None, None)
        .unwrap();
    for body in [None, Some(json!({})), Some(json!({"passphrase": PASS}))] {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/backup")
            .header("authorization", format!("Bearer tt_{id}_{secret}"))
            .header("content-type", "application/json")
            .extension(axum::extract::ConnectInfo(SocketAddr::from((
                [127, 0, 0, 1],
                40000,
            ))))
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap();
        let (s, _, b) = send(&h, req).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(json_of(&b)["code"], "agent_not_allowed");
    }
    assert_eq!(audit_backups(&h), "");
}

// REQ: API-007 (AC7) — one key derivation at a time: while one is running a second passphrase
// backup is 429 with Retry-After, and a backup without a passphrase is unaffected.
#[tokio::test]
async fn api_007_concurrent_backup_kdf_429() {
    let _serial = crate::backup::test_lock();
    let h = harness("");
    plant(&h).await;
    let slot = crate::backup::kdf_slot_for_tests();
    let (s, hd, b) = send(&h, from_session(&h, 0, Some(json!({"passphrase": PASS})))).await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        String::from_utf8_lossy(&b)
    );
    assert!(hd.contains_key("retry-after"));
    let (s, _, _) = send(&h, h.request("POST", "/api/v1/backup", Some(&json!({})))).await;
    assert_eq!(s, StatusCode::OK);
    drop(slot);
    let (s, _, _) = send(&h, from_session(&h, 0, Some(json!({"passphrase": PASS})))).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        !std::fs::read_dir(h.dir_path())
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(".backup-api")),
        "no partial file left"
    );
}

// REQ: API-007 — the body is checked: a short passphrase, an unknown field and a wrong type are
// 400, and the answer never quotes what was sent.
#[tokio::test]
async fn api_007_backup_post_validates_body() {
    let h = harness("");
    for (body, what) in [
        (json!({"passphrase": "short"}), "at least 12"),
        (json!({"passphrase": 123_456_789_012_i64}), "wrongly typed"),
        (json!({"unknown": "planted-extra-field-77"}), "unknown"),
        (
            json!({"includeQlog": "planted-not-a-bool-31"}),
            "wrongly typed",
        ),
    ] {
        let user_session = from_session(&h, 0, Some(body.clone()));
        let (s, _, b) = send(&h, user_session).await;
        let text = String::from_utf8_lossy(&b).into_owned();
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {text}");
        assert!(text.contains(what), "{what}: {text}");
        for planted in [
            "planted-extra-field-77",
            "planted-not-a-bool-31",
            "123456789012",
        ] {
            assert!(!text.contains(planted), "{text}");
        }
    }
}

// REQ: API-007 (ADR-903 §4, §8) — the HTTPS rule: from another host over plain HTTP the backup is
// 403 `insecure_transport`, unless `[api] allow_secrets_over_http`.
#[tokio::test]
async fn api_007_backup_post_needs_https_or_loopback() {
    let h = harness("");
    let mut req = h.request("POST", "/api/v1/backup", Some(&json!({})));
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            40000,
        ))));
    // A request a proxy forwarded counts as not local.
    req.headers_mut()
        .insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
    let (s, _, b) = send(&h, req).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(json_of(&b)["code"], "insecure_transport");
}

// REQ: API-007 (AC9) — the passphrase and the values appear nowhere: not in an answer to a refused
// or accepted request, not in the audit log, not in the log of making the backup.
#[tokio::test]
async fn api_007_passphrase_never_logged_or_audited() {
    let _serial = crate::backup::test_lock();
    let h = harness("");
    plant(&h).await;
    let body = json!({"passphrase": PASS});
    let mut seen = String::new();
    for req in [
        h.request("POST", "/api/v1/backup", Some(&body)),
        from_session(&h, 11 * 60, Some(body.clone())),
        from_session(&h, 0, Some(body.clone())),
    ] {
        let (_, hd, b) = send(&h, req).await;
        seen.push_str(&format!("{hd:?}"));
        if hd["content-type"] != "application/octet-stream" {
            seen.push_str(&String::from_utf8_lossy(&b));
        }
    }
    seen.push_str(&h.audit_text());
    assert!(
        !seen.contains(PASS) && !seen.contains(VALUE),
        "a secret came back: {seen}"
    );

    // The log of making a backup: captured on this thread, the call made on it.
    let out = Captured::default();
    let mut log = String::new();
    for _ in 0..5 {
        out.0.lock().unwrap().clear();
        let w = out.clone();
        let sub = tracing_subscriber::fmt()
            .with_writer(move || w.clone())
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::with_default(sub, || {
            tracing::callsite::rebuild_interest_cache();
            let backend = crate::api_backend::ApiBackend {
                src: std::sync::Arc::clone(&h.src),
            };
            let made = backend
                .backup_create(true, Some(zeroize::Zeroizing::new(PASS.to_owned())))
                .unwrap();
            assert!(made.secrets_included);
        });
        log = String::from_utf8_lossy(&out.0.lock().unwrap()).into_owned();
        if log.contains("backup downloaded") {
            break;
        }
    }
    assert!(
        log.contains("backup downloaded"),
        "the log was captured: {log}"
    );
    assert!(!log.contains(PASS) && !log.contains(VALUE), "{log}");
}

#[derive(Clone, Default)]
struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// REQ: API-007 (ADR-903 §8) — a backup that carried secrets raises `secrets_exported`, once per
// backup, naming who and how many (not which); one without secrets raises nothing.
#[tokio::test]
async fn api_007_secrets_exported_alert() {
    let _serial = crate::backup::test_lock();
    let h = harness("");
    plant(&h).await;
    let now = crate::pipeline::unix_now();
    let (s, _, _) = send(&h, h.request("POST", "/api/v1/backup", Some(&json!({})))).await;
    assert_eq!(s, StatusCode::OK);
    assert!(crate::alerts::recent_exports(&h.src, now).is_empty());
    let (s, _, _) = send(&h, from_session(&h, 0, Some(json!({"passphrase": PASS})))).await;
    assert_eq!(s, StatusCode::OK);
    let seen = crate::alerts::recent_exports(&h.src, now);
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(
        seen[0].1.contains("root") && seen[0].1.contains("2 stored secret"),
        "{seen:?}"
    );
    assert!(!seen[0].1.contains("unifi") && !seen[0].1.contains(VALUE));
    // The same record is not sent again; a later one is a new subject; an old one ages out.
    assert_eq!(crate::alerts::recent_exports(&h.src, now).len(), 1);
    assert!(crate::alerts::recent_exports(&h.src, now + 7200).is_empty());
    // The condition goes out once per subject, never "clears".
    let rule = telltale_config::AlertRule {
        name: telltale_config::SafeString::new("exports").unwrap(),
        when: telltale_config::AlertWhen::SecretsExported,
        for_secs: 60,
        threshold: None,
        to: vec![telltale_config::SafeString::new("phone").unwrap()],
        enabled: true,
    };
    let mut engine = crate::alerts::Engine::default();
    let rules = [rule];
    let first = engine.step(0, &rules, std::slice::from_ref(&seen));
    assert_eq!(first.len(), 1);
    assert!(first[0].firing);
    assert!(
        engine
            .step(10, &rules, std::slice::from_ref(&seen))
            .is_empty()
    );
    assert!(
        engine.step(20, &rules, &[Vec::new()]).is_empty(),
        "no resolve"
    );
}

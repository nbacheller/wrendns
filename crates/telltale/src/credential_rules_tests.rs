//! REQ: API-014, CLU-010 (T23.2, ADR-167 §4) — who may point a credential somewhere: an operator
//! (or an agent) can't change which file holds a credential, where an entry with a credential
//! sends it, or set up an upstream that runs a program; API-set paths are confined; an admin's
//! redirect is audited and alerted.

use std::net::SocketAddr;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use telltale_api::auth;
use tower::ServiceExt as _;

use crate::credential_tests::{Harness, harness, leaks};

/// A token for a new user of `role`; with `agent_scopes`, an agent token.
fn token(h: &Harness, user: &str, role: auth::Role, agent_scopes: Option<&str>) -> String {
    let now = crate::pipeline::unix_now();
    let u = h
        .auth
        .create_user(user, "correct horse battery", role, false, now)
        .unwrap();
    let (id, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
    let scope = if role == auth::Role::Admin {
        "admin"
    } else {
        "write"
    };
    h.auth
        .state()
        .create_token(
            &id,
            u.id,
            user,
            &auth::crypto::secret_hash(&secret),
            scope,
            None,
            now,
        )
        .unwrap();
    if let Some(s) = agent_scopes {
        h.auth.state().set_token_agent(&id, s, None, None).unwrap();
    }
    format!("tt_{id}_{secret}")
}

/// Sends `method uri` with `bearer`; the status and the JSON body.
async fn call(
    h: &Harness,
    bearer: &str,
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        // Agents must say why (AGT-005); people may.
        .header("x-telltale-reason", "T23.2 test")
        .extension(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            40001,
        ))))
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let b = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    (
        status,
        serde_json::from_slice(&b).unwrap_or(Value::String(String::from_utf8_lossy(&b).into())),
    )
}

/// A node whose `[node] secret_file_dirs` is a fresh directory (returned, with a file in it).
fn with_secret_dir() -> (Harness, tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap().to_owned();
    std::fs::write(dir.path().join("ntfy-token"), "tk_planted\n").unwrap();
    let h = harness(&format!("[node]\nsecret_file_dirs = [\"{d}\"]\n"));
    let token = format!("{d}/ntfy-token");
    (h, dir, token)
}

/// An admin's alert destination with a token file.
async fn ntfy(h: &Harness, token: &str) {
    let (s, v) = call(
        h,
        &h.bearer,
        "PUT",
        "/api/v1/alerts/destinations/phone",
        Some(&json!({"type": "ntfy", "url": "https://ntfy.sh/my-topic", "token_file": token})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: API-014 (T23.2) — `*_file` (and `tls_client_key`) changes are an admin's: an operator
/// gets 403 adding, changing or dropping one; an admin can.
#[tokio::test]
async fn api_014_file_reference_change_needs_admin() {
    let (h, dir, token_file) = with_secret_dir();
    let op = token(&h, "olive", auth::Role::Operator, None);
    let body = json!({"type": "ntfy", "url": "https://ntfy.sh/my-topic", "token_file": token_file});
    let (s, v) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/alerts/destinations/phone",
        Some(&body),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "forbidden");
    assert!(v["detail"].as_str().unwrap().contains("token_file"), "{v}");
    // Not even as a dry run.
    let (s, _) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/alerts/destinations/phone?dryRun=true",
        Some(&body),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    ntfy(&h, &token_file).await;
    // Pointing it at another file, or dropping it: admin only too.
    std::fs::write(dir.path().join("other"), "x").unwrap();
    let mut other = body.clone();
    other["token_file"] = json!(format!("{}/other", dir.path().display()));
    let (s, _) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/alerts/destinations/phone",
        Some(&other),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/alerts/destinations/phone",
        Some(&json!({"type": "ntfy", "url": "https://ntfy.sh/my-topic"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // An upstream's client key is a credential file too.
    let (s, v) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/upstreams/mtls",
        Some(
            &json!({"url": "tls://9.9.9.9", "tls_server_name": "dns.quad9.net",
            "tls_client_cert": format!("{}/other", dir.path().display()),
            "tls_client_key": format!("{}/other", dir.path().display())}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    // An agent token never, whatever its scopes (its owner is an admin).
    let agent = token(
        &h,
        "bot-owner",
        auth::Role::Admin,
        Some("config:read config:write:alerts cluster:admin"),
    );
    let (s, v) = call(
        &h,
        &agent,
        "PUT",
        "/api/v1/alerts/destinations/phone",
        Some(&other),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(v["detail"].as_str().unwrap().contains("agent"), "{v}");
    // The admin can, and the operator still edits what isn't a credential's.
    let (s, v) = call(
        &h,
        &h.bearer,
        "PUT",
        "/api/v1/alerts/destinations/phone",
        Some(&other),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/alerts/rules/down",
        Some(&json!({"when": "upstream_down", "to": ["phone"]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: API-014 (T23.2) — an operator can't send a credential somewhere else: an upstream with
/// headers and an alert destination with a `token_file` both give 403 on a URL change (typed
/// values or not), while other edits of the same entries go through.
#[tokio::test]
async fn api_014_operator_cannot_redirect_credential() {
    let (h, _dir, token_file) = with_secret_dir();
    let op = token(&h, "olive", auth::Role::Operator, None);
    // The files' upstream with headers, sent to another host with the header typed again.
    let moved = json!({
        "url": "https://doh.attacker.example/dns-query",
        "tls_server_name": "doh.example",
        "headers": {"Authorization": "Bearer typed"}
    });
    let (s, v) = call(&h, &op, "PUT", "/api/v1/upstreams/nextdns", Some(&moved)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(v["detail"].as_str().unwrap().contains("`url`"), "{v}");
    // A new TLS name is a new destination too.
    let (s, _) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/upstreams/nextdns",
        Some(&json!({
            "url": "https://me:typedpw@doh.example/dns-query",
            "tls_server_name": "other.example",
            "headers": {"Authorization": "Bearer typed"}
        })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // What the operator read, sent back with another weight: allowed.
    let (_, entries) = call(&h, &op, "GET", "/api/v1/config/entries?kind=upstream", None).await;
    let mut same = entries["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "nextdns")
        .unwrap()["definition"]
        .clone();
    same["weight"] = json!(7);
    let (s, v) = call(&h, &op, "PUT", "/api/v1/upstreams/nextdns", Some(&same)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // An alert destination with a token file.
    ntfy(&h, &token_file).await;
    let (s, v) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/alerts/destinations/phone",
        Some(&json!({"type": "ntfy", "url": "https://ntfy.attacker.example/t", "token_file": token_file})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    // And one with a password in its URL (the files' `hook`).
    let (s, _) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/alerts/destinations/hook",
        Some(&json!({"type": "webhook", "url": "https://u:typed@evil.example/notify"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // A destination without a credential is the operator's to move.
    let (s, v) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/alerts/destinations/plain",
        Some(&json!({"type": "ntfy", "url": "https://ntfy.sh/a"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/alerts/destinations/plain",
        Some(&json!({"type": "ntfy", "url": "https://ntfy.sh/b"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // Nothing the operator was refused reached the configuration.
    let cfg = h.src.config.load();
    assert!(cfg.upstream.iter().all(|u| !u.url.contains("attacker")));
    assert!(
        cfg.alerts
            .destination
            .iter()
            .all(|d| !d.url.contains("attacker"))
    );
}

/// REQ: API-014 (T23.2) — `exec://` and `unix://` upstreams are an admin's: an operator can't
/// create one, check one, switch an upstream to one, or change a plugin's arguments; an agent
/// with `config:write:upstreams` can't either.
#[tokio::test]
async fn api_014_operator_cannot_create_exec_upstream() {
    let h = harness("");
    let op = token(&h, "olive", auth::Role::Operator, None);
    let plugin = json!({"url": "exec:///usr/local/bin/evil", "args": ["--steal"]});
    let (s, v) = call(&h, &op, "PUT", "/api/v1/upstreams/evil", Some(&plugin)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(v["detail"].as_str().unwrap().contains("exec://"), "{v}");
    let (s, v) = call(&h, &op, "POST", "/api/v1/checks/upstream", Some(&plugin)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, _) = call(
        &h,
        &op,
        "POST",
        "/api/v1/checks/upstream",
        Some(&json!({"url": "unix:///run/evil.sock"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Switching a plain upstream to a program.
    let (s, v) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/upstreams/quad9",
        Some(&json!({"url": "tls://9.9.9.9", "tls_server_name": "dns.quad9.net"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/upstreams/quad9",
        Some(&json!({"url": "unix:///run/evil.sock"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // The files' plugin: new arguments are the admin's, another weight isn't.
    let (s, _) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/upstreams/plug",
        Some(&json!({"url": "exec:///usr/local/bin/plugin", "args": ["--token", "mine"]})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/upstreams/plug",
        Some(&json!({"url": "exec:///usr/local/bin/plugin", "args": ["<redacted>", "<redacted>"], "weight": 3})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // A forwarded domain's servers become upstreams too.
    let (s, v) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/forwards/corp.example",
        Some(&json!({"servers": ["exec:///usr/local/bin/evil"]})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, v) = call(
        &h,
        &op,
        "PUT",
        "/api/v1/forwards/corp.example",
        Some(&json!({"servers": ["10.0.0.53"]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // An agent with the upstreams scope.
    let agent = token(
        &h,
        "bot-owner",
        auth::Role::Admin,
        Some("config:read config:write:upstreams"),
    );
    let (s, v) = call(&h, &agent, "PUT", "/api/v1/upstreams/evil", Some(&plugin)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, _) = call(&h, &agent, "POST", "/api/v1/checks/upstream", Some(&plugin)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // The admin may.
    let (s, v) = call(
        &h,
        &h.bearer,
        "PUT",
        "/api/v1/upstreams/evil?dryRun=true",
        Some(&plugin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        h.src
            .config
            .load()
            .upstream
            .iter()
            .all(|u| u.name.as_str() != "evil")
    );
}

/// REQ: API-014 (T23.2) — paths set through the API are canonicalized and confined, for an
/// admin too: `/proc/self/environ`, a symlink into the data directory, the key files, and a
/// credential file outside `[node] secret_file_dirs` are refused (422 `path_not_allowed`); a
/// path stored before the rules stops being read and is reported in `credentialIssues`.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one case per kind of path
async fn api_014_file_path_confined() {
    let (h, dir, token_file) = with_secret_dir();
    let data_dir = h.src.file_config.load().node.data_dir.to_string();
    let put = |token: String| json!({"type": "ntfy", "url": "https://ntfy.sh/my-topic", "token_file": token});
    let refused = |v: &Value| {
        assert_eq!(v["code"], "path_not_allowed", "{v}");
        assert!(leaks(&v.to_string()).is_empty(), "{v}");
    };
    // The process's environment.
    let (s, v) = call(
        &h,
        &h.bearer,
        "PUT",
        "/api/v1/alerts/destinations/phone",
        Some(&put("/proc/self/environ".into())),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    refused(&v);
    // A symlink in an allowed directory that leads into the data directory.
    // (to a file that exists, and to one that doesn't yet: a dangling link is followed too).
    #[cfg(unix)]
    for (link, target) in [
        ("innocent", format!("{data_dir}/state.db")),
        ("dangling", format!("{data_dir}/not-yet")),
        (
            "relative",
            "../../../../../../../../proc/self/environ".to_owned(),
        ),
    ] {
        let link = dir.path().join(link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (s, v) = call(
            &h,
            &h.bearer,
            "PUT",
            "/api/v1/alerts/destinations/phone",
            Some(&put(link.display().to_string())),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{target}: {v}");
        refused(&v);
    }
    // The data directory itself, by a `..` or directly.
    for p in [
        format!("{}/../x", dir.path().display()),
        format!("{data_dir}/state.db"),
    ] {
        let (s, v) = call(
            &h,
            &h.bearer,
            "PUT",
            "/api/v1/alerts/destinations/phone",
            Some(&put(p)),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    }
    // A credential file outside the allowed directories (it exists, and is readable).
    let outside = tempfile::NamedTempFile::new().unwrap();
    let (s, v) = call(
        &h,
        &h.bearer,
        "PUT",
        "/api/v1/alerts/destinations/phone",
        Some(&put(outside.path().display().to_string())),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(
        v["detail"].as_str().unwrap().contains("secret_file_dirs"),
        "{v}"
    );
    // A list's path and a CA are held to the denied places too (not to the secret dirs).
    let (s, v) = call(
        &h,
        &h.bearer,
        "PUT",
        "/api/v1/lists/local",
        Some(&json!({"path": format!("{data_dir}/secrets.key")})),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, v) = call(
        &h,
        &h.bearer,
        "POST",
        "/api/v1/checks/upstream",
        Some(&json!({"url": "tls://9.9.9.9", "tls_ca": "/proc/self/environ"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    // The configured key files, wherever they are.
    let key_dir = tempfile::tempdir().unwrap();
    let key = key_dir.path().join("secrets.key");
    let h2 = harness(&format!(
        "[node]\nsecret_file_dirs = [\"{}\"]\nsecrets_key_file = \"{}\"\n",
        key_dir.path().display(),
        key.display()
    ));
    let (s, v) = call(
        &h2,
        &h2.bearer,
        "PUT",
        "/api/v1/alerts/destinations/phone",
        Some(&put(key.display().to_string())),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v["detail"].as_str().unwrap().contains("secrets key"), "{v}");
    // The allowed file is fine.
    ntfy(&h, &token_file).await;

    // A path stored before these rules (or since moved): not read, and said so.
    let now = crate::pipeline::unix_now();
    h.auth
        .state()
        .put_managed(
            crate::managed::ALERT_DESTINATION,
            "old",
            &json!({"name": "old", "type": "ntfy", "url": "https://ntfy.sh/old", "token_file": "/proc/self/environ"}).to_string(),
            None,
            None,
            now,
            "before T23.2",
        )
        .unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    h.src.reload.send(tx).await.unwrap();
    assert!(rx.await.unwrap());
    let cfg = h.src.config.load();
    let old = cfg
        .alerts
        .destination
        .iter()
        .find(|d| d.name.as_str() == "old")
        .unwrap();
    assert!(
        old.token_file
            .as_deref()
            .unwrap()
            .starts_with(crate::credential_rules::REFUSED),
        "{old:?}"
    );
    let (s, v) = call(
        &h,
        &h.bearer,
        "GET",
        "/api/v1/config/entries?kind=alert_destination",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let entry = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "old")
        .unwrap();
    assert_eq!(
        entry["credentialIssues"][0]["field"], "token_file",
        "{entry}"
    );
    assert!(
        entry["credentialIssues"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("isn't read"),
        "{entry}"
    );
    let phone = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "phone")
        .unwrap();
    assert!(phone.get("credentialIssues").is_none(), "{phone}");
}

/// REQ: API-014 (T23.2) — an admin's change of where a credential goes is audited as
/// `credential.redirect` (without the credential) and raises `credential_redirected` once.
#[tokio::test]
async fn api_014_admin_redirect_audited_and_alerted() {
    let h = harness("");
    let moved = json!({
        "url": "https://me:typedpw@doh2.example/dns-query",
        "tls_server_name": "doh2.example",
        "headers": {"Authorization": "Bearer typed-header"}
    });
    let (s, v) = call(
        &h,
        &h.bearer,
        "PUT",
        "/api/v1/upstreams/nextdns?dryRun=true",
        Some(&moved),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        v["warnings"].to_string().contains("credential_redirected"),
        "the dry run says so: {v}"
    );
    let (s, v) = call(
        &h,
        &h.bearer,
        "PUT",
        "/api/v1/upstreams/nextdns",
        Some(&moved),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let records = h
        .auth
        .state()
        .audit_page(
            None,
            10,
            Some(crate::credential_rules::REDIRECT_ACTION),
            None,
        )
        .unwrap();
    assert_eq!(records.len(), 1, "one record, not one for the dry run");
    let r = &records[0];
    assert_eq!(r.target, "nextdns");
    let text = format!("{} {}", r.actor, r.detail);
    assert!(text.contains("doh2.example"), "{text}");
    assert!(
        !text.contains("typedpw") && !text.contains("typed-header"),
        "{text}"
    );
    assert!(leaks(&text).is_empty(), "{text}");
    // The alert: once per change.
    let now = crate::pipeline::unix_now();
    let seen = crate::alerts::recent_redirects(&h.src, now);
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].1.contains("upstream nextdns"), "{seen:?}");
    assert!(!seen[0].1.contains("typedpw"), "{seen:?}");
    // An edit that keeps the destination isn't a redirect.
    let mut same = moved.clone();
    same["weight"] = json!(4);
    let (s, _) = call(
        &h,
        &h.bearer,
        "PUT",
        "/api/v1/upstreams/nextdns",
        Some(&same),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(crate::alerts::recent_redirects(&h.src, now).len(), 1);
    // Older than the window: not sent again after a restart.
    assert_eq!(
        crate::alerts::recent_redirects(&h.src, now + 7200),
        Vec::new()
    );
    // Through the rule engine: one notice, not repeated at the next evaluation.
    let rule = telltale_config::AlertRule {
        name: telltale_config::SafeString::new("redirects").unwrap(),
        when: telltale_config::AlertWhen::CredentialRedirected,
        for_secs: 60,
        threshold: None,
        to: Vec::new(),
        enabled: true,
    };
    let mut engine = crate::alerts::Engine::default();
    let rules = [rule];
    assert_eq!(
        engine.step(now, &rules, std::slice::from_ref(&seen)).len(),
        1
    );
    assert_eq!(engine.step(now + 30, &rules, &[seen]), Vec::new());
}

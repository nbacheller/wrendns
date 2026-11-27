//! REQ: API-015, AGT-001–005, AGT-009, CLU-010 (T23.4, ADR-903 §4–5) — the write-only secrets
//! API through a running node: answers, reads, the audit log, idempotency records and logs carry
//! metadata only; only admins set or clear a secret (never an agent token), over HTTPS or
//! loopback, with CSRF for sessions; a dry run stores nothing; a replica forwards by its own RPC
//! kind, which an older primary refuses; a `GitOps` authority and a pin don't stop secret writes,
//! an emergency primary and one without its lease do; a delete is refused while any node's field
//! names the secret.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use wrendns_api::auth;
use wrendns_cluster::net::Cluster;

use crate::credential_tests::{Harness, harness, harness_from, harness_in, harness_with, leaks};

/// The value planted: it must never come back.
const VALUE: &str = "planted-secret-value-61f0";
const OTHER: &str = "planted-other-value-93c4";

fn no_value(text: &str) {
    assert!(
        !text.contains(VALUE) && !text.contains(OTHER),
        "a value came back: {text}"
    );
    assert!(leaks(text).is_empty(), "{text}");
}

fn put_body(v: &str) -> Value {
    json!({"value": v, "kind": "text"})
}

/// A request as `bearer` from `peer`.
fn req_from(
    bearer: &str,
    peer: [u8; 4],
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .header("x-wrendns-reason", "T23.4 test")
        .extension(axum::extract::ConnectInfo(SocketAddr::from((peer, 40000))))
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap()
}

async fn json_of(h: &Harness, r: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
    let (s, hd, t) = h.send(r).await;
    (s, hd, serde_json::from_str(&t).unwrap_or(Value::String(t)))
}

/// A token for a new user of `role`; with `agent_scopes`, an agent token.
fn token(h: &Harness, user: &str, role: auth::Role, agent_scopes: Option<&str>) -> String {
    let now = crate::pipeline::unix_now();
    let u = h
        .auth
        .create_user(user, "correct horse battery", role, false, now)
        .unwrap();
    let (id, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
    let scope = match role {
        auth::Role::Admin => "admin",
        auth::Role::Operator => "write",
        auth::Role::Viewer => "read",
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

fn audit(h: &Harness) -> String {
    h.auth
        .state()
        .audit_page(None, 100, Some("secret."), None)
        .unwrap()
        .iter()
        .map(|e| format!("{} | {} | {} | {}\n", e.actor, e.action, e.target, e.detail))
        .collect::<Vec<_>>()
        .concat()
}

/// REQ: API-015, AGT-001 (AC1) — a `PUT` answers with metadata only: the name, kind, stamp, the
/// head and its `ETag`, with `Cache-Control: no-store`; the store holds the value.
#[tokio::test]
async fn api_015_put_returns_metadata_only() {
    let h = harness(
        "[[alerts.destination]]\nname = \"phone\"\ntype = \"ntfy\"\nurl = \"https://ntfy.example/topic\"\ntoken_ref = \"ntfy\"\n",
    );
    let (s, hd, v) = h
        .call("PUT", "/api/v1/secrets/ntfy", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    no_value(&v.to_string());
    assert_eq!(v["applied"], true);
    assert_eq!(v["wouldCreate"], true);
    assert_eq!(v["secret"]["name"], "ntfy");
    assert_eq!(v["secret"]["kind"], "text");
    assert_eq!(v["secret"]["set"], true);
    assert_eq!(v["secret"]["origin"], "local");
    assert_eq!(v["secret"]["stamp"]["epoch"], 0);
    assert!(v["secret"]["stamp"]["seq"].as_u64().unwrap() >= 1);
    assert_eq!(v["usedBy"][0]["kind"], "alert_destination", "{v}");
    assert_eq!(v["usedBy"][0]["name"], "phone");
    assert!(v.get("value").is_none() && v["secret"].get("value").is_none());
    assert_eq!(hd.get("cache-control").unwrap(), "no-store");
    let etag = hd.get("etag").unwrap().to_str().unwrap().to_owned();
    assert_eq!(etag, format!("\"{}\"", v["head"]["etag"].as_str().unwrap()));
    assert_eq!(h.src.secrets.get("ntfy").unwrap().expose(), VALUE);
    // Replacing it: `wouldReplace`, and the old ETag no longer matches (412).
    let mut r = h.request("PUT", "/api/v1/secrets/ntfy", Some(&put_body(OTHER)));
    r.headers_mut().insert("if-match", etag.parse().unwrap());
    let (s, hd2, v2) = json_of(&h, r).await;
    assert_eq!(s, StatusCode::OK, "{v2}");
    assert_eq!(v2["wouldReplace"], true);
    no_value(&v2.to_string());
    let mut r = h.request("PUT", "/api/v1/secrets/ntfy", Some(&put_body(VALUE)));
    r.headers_mut().insert("if-match", etag.parse().unwrap());
    let (s, _, v3) = json_of(&h, r).await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED, "{v3}");
    assert_ne!(hd2.get("etag"), hd.get("etag"));
    assert_eq!(h.src.secrets.get("ntfy").unwrap().expose(), OTHER);
}

/// REQ: API-015, AGT-001 (AC2) — no read returns a value: the list, one secret, the MCP tool
/// `secrets_status`, and the configuration's entries; the list shows the store and the
/// credential fields with their sources, never a value.
#[tokio::test]
async fn api_015_get_never_returns_value() {
    let h = harness(
        "[[alerts.destination]]\nname = \"phone\"\ntype = \"ntfy\"\nurl = \"https://ntfy.example/topic\"\ntoken_ref = \"ntfy\"\n",
    );
    let (s, _, _) = h
        .call("PUT", "/api/v1/secrets/ntfy", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, hd, v) = h.call("GET", "/api/v1/secrets", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    no_value(&v.to_string());
    assert_eq!(hd.get("cache-control").unwrap(), "no-store");
    assert_eq!(v["stale"], false);
    assert_eq!(v["store"]["state"], "ready", "{v}");
    assert!(v["store"]["keyId"].as_str().is_some_and(|k| k.len() == 16));
    let item = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "ntfy")
        .unwrap();
    assert_eq!(item["health"], "readable");
    assert_eq!(item["usedBy"][0]["field"], "token_ref");
    assert_eq!(item["nodes"][0]["applied"], true);
    // The files' inline OIDC client secret: listed as `inline`, without its value.
    let kc = v["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["entry"] == "kc")
        .unwrap();
    assert_eq!(kc["source"], "inline");
    let ntfy = v["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["entry"] == "phone")
        .unwrap();
    assert_eq!(
        (&ntfy["source"], &ntfy["at"]),
        (&json!("stored"), &json!("ntfy"))
    );
    let (s, _, one) = h.call("GET", "/api/v1/secrets/ntfy", None).await;
    assert_eq!(s, StatusCode::OK);
    no_value(&one.to_string());
    assert_eq!(one["name"], "ntfy");
    let (s, _, _) = h.call("GET", "/api/v1/secrets/nothing", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // MCP: the read-only tool.
    let (_, _, tool) = h
        .call(
            "POST",
            "/mcp",
            Some(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "secrets_status", "arguments": {}}})),
        )
        .await;
    assert_ne!(tool["result"]["isError"], true, "{tool}");
    assert!(tool.to_string().contains("ntfy"), "{tool}");
    no_value(&tool.to_string());
    let (_, _, entries) = h.call("GET", "/api/v1/config/entries", None).await;
    no_value(&entries.to_string());
}

/// REQ: API-015, AGT-002 (AC3) — a dry run checks and reports (`wouldCreate`, the fields that
/// would become configured) and stores nothing; a bad value fails the dry run as it would the
/// write.
#[tokio::test]
async fn api_015_dry_run_stores_nothing() {
    let h = harness(
        "[[alerts.destination]]\nname = \"phone\"\ntype = \"ntfy\"\nurl = \"https://ntfy.example/topic\"\ntoken_ref = \"ntfy\"\n",
    );
    let (_, before, _) = h.call("GET", "/api/v1/secrets", None).await;
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/secrets/ntfy?dryRun=true",
            Some(&put_body(VALUE)),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (&v["applied"], &v["dryRun"], &v["wouldCreate"]),
        (&json!(false), &json!(true), &json!(true))
    );
    assert_eq!(v["usedBy"][0]["name"], "phone", "{v}");
    no_value(&v.to_string());
    assert!(!h.src.secrets.exists("ntfy"));
    let (_, after, list) = h.call("GET", "/api/v1/secrets", None).await;
    assert_eq!(
        before.get("etag"),
        after.get("etag"),
        "the head didn't move"
    );
    let item = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "ntfy")
        .unwrap();
    assert_eq!(item["set"], false, "named but not set: {item}");
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/secrets/ntfy?dryRun=true",
            Some(&put_body("")),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(audit(&h), "");
    // A dry-run delete of something stored deletes nothing.
    h.call("PUT", "/api/v1/secrets/spare", Some(&put_body(VALUE)))
        .await;
    let (s, _, v) = h
        .call("DELETE", "/api/v1/secrets/spare?dryRun=true", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (&v["wouldDelete"], &v["applied"]),
        (&json!(true), &json!(false))
    );
    assert!(h.src.secrets.exists("spare"));
}

/// REQ: API-015, AGT-003 (AC4) — an `Idempotency-Key` retry gets the first answer back; the same
/// key with another value is 409; the record holds `PUT /secrets/<name> kind=<kind> ` and a keyed hash,
/// never the value, and its stored answer neither.
#[tokio::test]
async fn api_015_idempotency_replay_without_body() {
    let h = harness("");
    let put = |v: &str| {
        let mut r = h.request("PUT", "/api/v1/secrets/hook", Some(&put_body(v)));
        r.headers_mut()
            .insert("idempotency-key", "secret-1".parse().unwrap());
        r
    };
    let (s, _, first) = h.send(put(VALUE)).await;
    assert_eq!(s, StatusCode::OK, "{first}");
    let (s, hd, again) = h.send(put(VALUE)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(hd.get("idempotency-replayed").unwrap(), "true");
    assert_eq!(hd.get("cache-control").unwrap(), "no-store");
    assert_eq!(again, first);
    let (s, _, v) = h.send(put(OTHER)).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(
        h.src.secrets.get("hook").unwrap().expose(),
        VALUE,
        "the refused retry changed nothing"
    );
    let row = h
        .auth
        .state()
        .idempotent(
            &format!("{}:secret-1", h.admin_id),
            crate::pipeline::unix_now(),
        )
        .unwrap()
        .unwrap();
    let request = String::from_utf8_lossy(&row.request).into_owned();
    no_value(&request);
    no_value(&row.response);
    let digest = request
        .strip_prefix("PUT /secrets/hook kind=text ")
        .unwrap();
    assert_eq!(digest.len(), 64, "{request}");
    assert_ne!(
        digest,
        blake3::hash(VALUE.as_bytes()).to_hex().as_str(),
        "keyed, not a plain hash of the value"
    );
    // The kind is part of the request: the same key and value as another kind is 409.
    let mut r = h.request(
        "PUT",
        "/api/v1/secrets/hook",
        Some(&json!({"value": VALUE, "kind": "pem"})),
    );
    r.headers_mut()
        .insert("idempotency-key", "secret-1".parse().unwrap());
    let (s, _, v) = h.send(r).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    // An empty header is no key: nothing is recorded under it.
    let mut r = h.request("PUT", "/api/v1/secrets/spare", Some(&put_body(VALUE)));
    r.headers_mut()
        .insert("idempotency-key", "".parse().unwrap());
    let (s, _, v) = h.send(r).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        h.auth
            .state()
            .idempotent(&format!("{}:", h.admin_id), crate::pipeline::unix_now())
            .unwrap()
            .is_none()
    );
}

/// REQ: API-015 (AC5) — an operator (and a viewer) can't set or clear a secret; an operator lists
/// them, a viewer doesn't.
#[tokio::test]
async fn api_015_operator_cannot_set() {
    let h = harness("");
    h.call("PUT", "/api/v1/secrets/kept", Some(&put_body(VALUE)))
        .await;
    let op = token(&h, "olive", auth::Role::Operator, None);
    for (m, uri, body) in [
        ("PUT", "/api/v1/secrets/new", Some(put_body(OTHER))),
        (
            "PUT",
            "/api/v1/secrets/kept?dryRun=true",
            Some(put_body(OTHER)),
        ),
        ("DELETE", "/api/v1/secrets/kept", None),
    ] {
        let (s, _, v) = json_of(&h, req_from(&op, [127, 0, 0, 1], m, uri, body.as_ref())).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{m} {uri}: {v}");
        assert_eq!(v["code"], "forbidden");
    }
    assert!(!h.src.secrets.exists("new") && h.src.secrets.exists("kept"));
    let (s, _, v) = json_of(
        &h,
        req_from(&op, [127, 0, 0, 1], "GET", "/api/v1/secrets", None),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    no_value(&v.to_string());
    let viewer = token(&h, "vic", auth::Role::Viewer, None);
    let (s, _, _) = json_of(
        &h,
        req_from(&viewer, [127, 0, 0, 1], "GET", "/api/v1/secrets", None),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

/// REQ: API-015, AGT-004 (AC6) — an agent token whose owner is an admin, with every scope
/// (`cluster:admin` included), gets 403 `agent_not_allowed` on a secret write, and reads the
/// metadata with `config:read`.
#[tokio::test]
async fn api_015_agent_token_refused_with_admin_owner() {
    let h = harness("");
    let every: Vec<&str> = auth::agent::SCOPES.iter().map(|(n, _)| *n).collect();
    let agent = token(&h, "bot-owner", auth::Role::Admin, Some(&every.join(" ")));
    for (m, uri, body) in [
        ("PUT", "/api/v1/secrets/x", Some(put_body(VALUE))),
        (
            "PUT",
            "/api/v1/secrets/x?dryRun=true",
            Some(put_body(VALUE)),
        ),
        ("DELETE", "/api/v1/secrets/x", None),
    ] {
        let (s, _, v) = json_of(&h, req_from(&agent, [127, 0, 0, 1], m, uri, body.as_ref())).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{m} {uri}: {v}");
        assert_eq!(v["code"], "agent_not_allowed", "{v}");
    }
    assert!(!h.src.secrets.exists("x"));
    let (s, _, v) = json_of(
        &h,
        req_from(&agent, [127, 0, 0, 1], "GET", "/api/v1/secrets", None),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let reader = token(&h, "reader", auth::Role::Admin, Some("analytics:read"));
    let (s, _, _) = json_of(
        &h,
        req_from(&reader, [127, 0, 0, 1], "GET", "/api/v1/secrets", None),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "config:read is needed");
}

/// REQ: API-015, AGT-005 (AC7) — the audit log records `secret.put` and `secret.delete` with the
/// name, kind, stamp, users and reason, never the value or its length.
#[tokio::test]
async fn api_015_audit_without_value() {
    let h = harness("");
    let mut r = h.request("PUT", "/api/v1/secrets/ntfy", Some(&put_body(VALUE)));
    r.headers_mut().insert(
        "x-wrendns-reason",
        "rotated after the leak".parse().unwrap(),
    );
    let (s, _, _) = h.send(r).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = h.call("DELETE", "/api/v1/secrets/ntfy", None).await;
    assert_eq!(s, StatusCode::OK);
    let entries = h
        .auth
        .state()
        .audit_page(None, 100, Some("secret."), None)
        .unwrap();
    let actions: Vec<&str> = entries.iter().map(|e| e.action.as_str()).collect();
    assert!(
        actions.contains(&"secret.put") && actions.contains(&"secret.delete"),
        "{actions:?}"
    );
    let text = audit(&h);
    no_value(&text);
    assert!(text.contains("\"kind\":\"text\""), "{text}");
    assert!(text.contains("\"stamp\""), "{text}");
    assert!(text.contains("\"usedBy\""), "{text}");
    for word in ["length", "bytes", "\"value\""] {
        assert!(!text.contains(word), "{word}: {text}");
    }
    assert!(
        entries
            .iter()
            .any(|e| e.reason.as_deref() == Some("rotated after the leak")),
        "the reason is kept"
    );
    // A refused write leaves no entry.
    let (s, _, _) = h
        .call("PUT", "/api/v1/secrets/Bad!", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        h.auth
            .state()
            .audit_page(None, 100, Some("secret."), None)
            .unwrap()
            .len(),
        2
    );
}

/// A two-node cluster on loopback: a primary (answering with `handler`, or the real node when
/// `None`) and a replica, joined and connected.
pub(crate) struct Pair {
    pub(crate) primary: Arc<Cluster>,
    pub(crate) replica: Arc<Cluster>,
    pub(crate) stop: tokio::sync::watch::Sender<bool>,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

pub(crate) async fn pair(version: &str, replica_version: &str) -> Pair {
    pair_features(version, replica_version, None).await
}

/// [`pair`], the replica announcing `features` (`None`: every feature this build knows).
pub(crate) async fn pair_features(
    version: &str,
    replica_version: &str,
    features: Option<Vec<String>>,
) -> Pair {
    use wrendns_cluster::net::{dial, join, serve};
    use wrendns_cluster::node::{Identity, JoinRequest, TokenGrants};
    let (pdir, rdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let url = format!("https://{addr}");
    let pid = Identity::init(pdir.path(), "home", vec![url.clone()], "attic").unwrap();
    let token = pid
        .create_token_for(
            600,
            Some(vec![url.clone()]),
            TokenGrants {
                eligible: true,
                witness: false,
            },
        )
        .unwrap();
    let primary = Cluster::new(pid, version);
    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    tokio::spawn(serve(Arc::clone(&primary), addr, stop.clone()));
    let key = wrendns_cluster::pki::new_node_key().unwrap();
    let req = JoinRequest {
        witness: false,
        ephemeral: false,
        secret: token.secret.clone(),
        csr_pem: key.csr_pem.clone(),
        advertise: vec![],
        site: "pi".into(),
        eligible: true,
        version: replica_version.into(),
    };
    // Poll until the listener is up, with a deadline, instead of a fixed sleep (flaky under load).
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let resp = loop {
        match join(&token, &req).await {
            Ok(r) => break r,
            Err(e) if std::time::Instant::now() >= deadline => panic!("join: {e:?}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    };
    let rid = Identity::save_joined(rdir.path(), &key.key_pem, &resp, "pi", true, vec![]).unwrap();
    let replica = Cluster::new(rid, replica_version);
    if let Some(f) = features {
        replica.set_features(f);
    }
    tokio::spawn(dial(Arc::clone(&replica), stop));
    for _ in 0..400 {
        if replica.reachable_primary().is_some() && !primary.reachable_peers().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        replica.reachable_primary().is_some(),
        "the replica connects"
    );
    Pair {
        primary,
        replica,
        stop: stop_tx,
        _dirs: (pdir, rdir),
    }
}

/// Collects what a `fmt` subscriber writes.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// REQ: API-015, CLU-002 (AC8) — a secret set on a replica goes to the primary as `secret.put`
/// and is stored there; with TRACE logging on both nodes (one process, one capture), nothing
/// logged holds the value, while both sides log the operation and the name. The primary audits
/// it with the user and the replica, and the replica's answer and audit entry are metadata.
#[tokio::test]
async fn api_015_replica_forward_logs_no_value() {
    let out = Captured::default();
    let w = out.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || w.clone())
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let guard = tracing::subscriber::set_default(sub);
    tracing::callsite::rebuild_interest_cache();
    let p = pair(crate::build_info::VERSION, crate::build_info::VERSION).await;
    let ph = harness_in("", Some(Arc::clone(&p.primary)));
    crate::http::serve_peers(&ph.src);
    let rh = harness_in("", Some(Arc::clone(&p.replica)));
    crate::http::serve_peers(&rh.src);
    // Tried again if another test's thread registered the log's call sites first (tracing
    // caches their interest), so the check never passes on an empty log.
    let mut log = String::new();
    for _ in 0..5 {
        tracing::callsite::rebuild_interest_cache();
        out.0.lock().unwrap().clear();
        let (s, _, v) = rh
            .call("PUT", "/api/v1/secrets/unifi", Some(&put_body(VALUE)))
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["applied"], true);
        assert_eq!(v["secret"]["origin"], "cluster");
        assert!(v["secret"]["stamp"]["epoch"].as_u64().unwrap() >= 1, "{v}");
        no_value(&v.to_string());
        assert_eq!(ph.src.secrets.get("unifi").unwrap().expose(), VALUE);
        assert!(!rh.src.secrets.exists("unifi"), "replication is T23.5's");
        let primary_audit = audit(&ph);
        assert!(
            primary_audit.contains("via pi | secret.put | unifi"),
            "{primary_audit}"
        );
        no_value(&primary_audit);
        no_value(&audit(&rh));
        // A delete through the replica too.
        let (s, _, v) = rh.call("DELETE", "/api/v1/secrets/unifi", None).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert!(!ph.src.secrets.exists("unifi"));
        log = String::from_utf8_lossy(&out.0.lock().unwrap()).into_owned();
        no_value(&log);
        if log.contains("forwarding a secret write to the primary")
            && log.contains("a forwarded secret write")
            && log.contains("stored secret set")
            && log.contains("stored secret deleted")
        {
            break;
        }
    }
    drop(guard);
    assert!(
        log.contains("forwarding a secret write to the primary"),
        "the replica's side: {log}"
    );
    assert!(
        log.contains("a forwarded secret write"),
        "the primary's side: {log}"
    );
    // The primary's blocking thread (the rules, the encryption, the store) logs into the same
    // capture: the dispatcher goes along with it.
    assert!(
        log.contains("stored secret set") && log.contains("stored secret deleted"),
        "the primary's store: {log}"
    );
    assert!(log.contains("unifi"), "the name is logged");
    let _ = p.stop.send(true);
}

/// REQ: API-015, CLU-010 (AC9) — an older primary doesn't know `secret.put`: the replica answers
/// 409 `upgrade_required` naming its version, instead of a write the primary might misread.
#[tokio::test]
async fn api_015_n_minus_1_primary_refuses_by_kind() {
    let p = pair("0.7.4", crate::build_info::VERSION).await;
    // What an older node's handler does with a kind it doesn't know.
    p.primary.set_rpc_handler(Arc::new(|_peer, kind, _body| {
        Box::pin(async move { Err(format!("unknown call `{kind}`")) })
    }));
    let rh = harness_in("", Some(Arc::clone(&p.replica)));
    let (s, _, v) = rh
        .call("PUT", "/api/v1/secrets/unifi", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "upgrade_required", "{v}");
    assert!(v["detail"].as_str().unwrap().contains("0.7.4"), "{v}");
    no_value(&v.to_string());
    assert_eq!(audit(&rh), "");
    let _ = p.stop.send(true);
}

const PEM_VALUE: &str =
    "-----BEGIN PRIVATE KEY-----\nplantedPemKeyBytes61f0\n-----END PRIVATE KEY-----";

/// The upgrade gate keeps one process-wide record for health; the tests that read it take turns.
pub(crate) static GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What the issuer's own path does: a write that does not go through the public routes.
async fn issuer_put(
    src: &Arc<crate::http::Sources>,
    name: &str,
    dry_run: bool,
) -> Result<wrendns_api::secrets_api::SecretChange, wrendns_api::problem::Problem> {
    use wrendns_api::secrets_api::{SecretOp, SecretText, SecretWrite};
    crate::secrets_api::write_here(
        Arc::clone(src),
        SecretWrite {
            name: name.to_owned(),
            op: SecretOp::Put {
                kind: "pem".into(),
                value: SecretText::new(PEM_VALUE.to_owned()),
            },
            dry_run,
            expect: None,
            by: "issuer".into(),
            role: Some(auth::Role::Admin),
            agent: None,
        },
    )
    .await
}

/// REQ: DSC-908, CLD-920 (ADR-1096 point 5) - the first `pem` secret is refused while a member's
/// build does not announce the kind, naming the member and its version (dry runs too), even when
/// that build carries the same version number as this one (a development build of 1.1.0); a text
/// secret is not held; health says the gate is holding a change back; and once the member's build
/// announces the kind the write goes through and nothing returned holds the key.
#[tokio::test]
async fn dsc_908_pem_secret_waits_for_every_members_build() {
    let _turn = GATE.lock().await;
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    let ph = harness_in("", Some(Arc::clone(&old.primary)));
    crate::http::serve_peers(&ph.src);
    for dry in [true, false] {
        let e = issuer_put(&ph.src, "cert.cluster.key", dry)
            .await
            .unwrap_err();
        assert_eq!(e.code_status(), StatusCode::CONFLICT, "{e:?}");
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["code"], "upgrade_required", "{v}");
        let d = v["detail"].as_str().unwrap();
        assert!(
            d.contains("version 1.1.0-edge.40") && d.contains("`pem`"),
            "{v}"
        );
        assert!(!v.to_string().contains("plantedPemKeyBytes"), "{v}");
    }
    assert!(!ph.src.secrets.exists("cert.cluster.key"));
    let (s, _, v) = ph
        .call("PUT", "/api/v1/secrets/plain", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let holds = crate::upgrade_gate::standing(Some(&old.primary));
    assert_eq!(holds.len(), 1, "{holds:?}");
    let reasons = crate::health::upgrade_gate_reasons(&holds);
    assert_eq!(reasons[0].code, "upgrade_gate_holding");
    assert!(
        reasons[0].summary.contains("version 1.1.0-edge.40"),
        "{reasons:?}"
    );
    let _ = old.stop.send(true);

    let new = pair("1.1.0", "1.1.0").await;
    let ph = harness_in("", Some(Arc::clone(&new.primary)));
    crate::http::serve_peers(&ph.src);
    let c = issuer_put(&ph.src, "cert.cluster.key", false)
        .await
        .unwrap();
    assert_eq!(c.secret.kind, "pem");
    assert!(
        !serde_json::to_string(&c)
            .unwrap()
            .contains("plantedPemKeyBytes")
    );
    assert_eq!(
        crate::upgrade_gate::standing(Some(&new.primary)),
        Vec::<String>::new()
    );
    let (_, _, list) = ph.call("GET", "/api/v1/secrets", None).await;
    assert!(!list.to_string().contains("plantedPemKeyBytes"), "{list}");
    let _ = new.stop.send(true);
}

/// REQ: DSC-908 - a full member in the registry that has not connected since this process started
/// has not reported its build: the gate counts it as not knowing the kind (the primary has just
/// restarted, or the member is offline), and a removed member no longer counts.
#[tokio::test]
async fn dsc_908_a_registered_member_never_heard_from_holds_the_gate() {
    let _turn = GATE.lock().await;
    let (c, dir) = lone_primary("api");
    let h = harness_in("", Some(Arc::clone(&c)));
    assert!(issuer_put(&h.src, "cert.cluster.key", true).await.is_ok());
    let nodes = json!([
        {"node_id": c.identity.meta.node_id, "site": "home", "eligible": true, "advertise": [], "joined": 0},
        {"node_id": "pi-c", "site": "home", "eligible": true, "advertise": [], "joined": 1},
    ]);
    std::fs::write(c.identity.dir.join("nodes.json"), nodes.to_string()).unwrap();
    let e = issuer_put(&h.src, "cert.cluster.key", false)
        .await
        .unwrap_err();
    let v = serde_json::to_value(&e).unwrap();
    assert_eq!(v["code"], "upgrade_required", "{v}");
    assert!(
        v["detail"].as_str().unwrap().starts_with("node pi-c "),
        "{v}"
    );
    assert!(!h.src.secrets.exists("cert.cluster.key"));
    c.identity.add_removed("pi-c").unwrap();
    assert!(issuer_put(&h.src, "cert.cluster.key", false).await.is_ok());
    drop(dir);
}

/// REQ: CLD-920, DSC-908 (owner decision 2026-11-26) - the public secrets API neither writes nor
/// deletes the five names the issuer keeps (no admin or stolen admin token can plant a key a
/// listener would load), whatever the kind; a name that only looks similar is an ordinary secret.
#[tokio::test]
async fn cld_920_public_api_refuses_the_issuers_names() {
    let h = harness("");
    let pem_body = json!({"value": PEM_VALUE, "kind": "pem"});
    for name in [
        "acme.account",
        "cert.cluster.key",
        "cert.cluster.chain",
        "cert.home.key",
        "cert.home.chain",
    ] {
        for body in [put_body(VALUE), pem_body.clone()] {
            let (s, _, v) = h
                .call("PUT", &format!("/api/v1/secrets/{name}"), Some(&body))
                .await;
            assert_eq!(s, StatusCode::CONFLICT, "{name}: {v}");
            no_value(&v.to_string());
            assert!(!v.to_string().contains("plantedPemKeyBytes"), "{v}");
        }
        let (s, _, v) = h
            .call("DELETE", &format!("/api/v1/secrets/{name}"), None)
            .await;
        assert_eq!(s, StatusCode::CONFLICT, "{name}: {v}");
        assert!(!h.src.secrets.exists(name));
    }
    // The store trims a name; a padded spelling of a reserved name is the reserved name.
    for name in [
        "%20cert.cluster.key",
        "cert.cluster.key%09",
        "%20acme.account",
    ] {
        for body in [put_body(VALUE), pem_body.clone()] {
            let (s, _, v) = h
                .call("PUT", &format!("/api/v1/secrets/{name}"), Some(&body))
                .await;
            assert_eq!(s, StatusCode::CONFLICT, "{name}: {v}");
        }
        let (s, _, v) = h
            .call("DELETE", &format!("/api/v1/secrets/{name}"), None)
            .await;
        assert_eq!(s, StatusCode::CONFLICT, "{name}: {v}");
    }
    assert!(!h.src.secrets.exists("cert.cluster.key"));
    assert!(!h.src.secrets.exists("acme.account"));
    for name in [
        "acme.accounts",
        "cert.key",
        "cert.home.keys",
        "my.cert.home.key",
    ] {
        let (s, _, v) = h
            .call(
                "PUT",
                &format!("/api/v1/secrets/{name}"),
                Some(&put_body(VALUE)),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{name}: {v}");
    }
}

/// REQ: CLD-920 (owner decision 2026-11-26) - an admin uploads a `pem` secret through the public
/// API under a name the issuer does not keep: stored as kind `pem`, audited like another secret
/// write, and the value is in neither the answer, the dry run, the list nor the audit log. The
/// value is checked as PEM (400 otherwise), an operator and a viewer are refused (403), an agent
/// token is refused even with an admin owner and every scope, and a credential field cannot name
/// it.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one path, every actor
async fn cld_920_admin_uploads_a_pem_secret_and_nobody_reads_it_back() {
    let h = harness("");
    let body = json!({"value": PEM_VALUE, "kind": "pem"});
    let gone = |t: &str| assert!(!t.contains("plantedPemKeyBytes"), "a key came back: {t}");
    let (s, _, v) = h
        .call("PUT", "/api/v1/secrets/loc.key?dryRun=true", Some(&body))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    gone(&v.to_string());
    assert!(!h.src.secrets.exists("loc.key"), "a dry run stores nothing");
    let (s, _, v) = h.call("PUT", "/api/v1/secrets/loc.key", Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["secret"]["kind"], "pem", "{v}");
    gone(&v.to_string());
    assert!(h.src.secrets.exists("loc.key"));
    let (s, _, list) = h.call("GET", "/api/v1/secrets", None).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert!(list.to_string().contains("loc.key"), "{list}");
    gone(&list.to_string());
    let log = audit(&h);
    assert!(
        log.contains("secret.put") && log.contains("loc.key"),
        "{log}"
    );
    gone(&log);
    // The value is not a credential: a `*_ref` field cannot name it, and `get` agrees.
    assert!(h.src.secrets.get("loc.key").is_err());
    assert!(h.src.secrets.readable("loc.key").is_err());
    // Not PEM: refused with the reason, nothing stored.
    for bad in ["just a token", "-----BEGIN CERTIFICATE-----\nAAAA"] {
        let (s, _, v) = h
            .call(
                "PUT",
                "/api/v1/secrets/other.key",
                Some(&json!({"value": bad, "kind": "pem"})),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
        assert!(v["detail"].as_str().unwrap().contains("PEM"), "{v}");
    }
    assert!(!h.src.secrets.exists("other.key"));
    // Operator, viewer and an agent token (admin owner, every scope): refused, nothing stored.
    let every: Vec<&str> = auth::agent::SCOPES.iter().map(|(n, _)| *n).collect();
    let agent = token(&h, "bot-pem", auth::Role::Admin, Some(&every.join(" ")));
    let op = token(&h, "olive-pem", auth::Role::Operator, None);
    let viewer = token(&h, "vic-pem", auth::Role::Viewer, None);
    for (who, bearer, status, code) in [
        ("operator", &op, StatusCode::FORBIDDEN, "forbidden"),
        ("viewer", &viewer, StatusCode::FORBIDDEN, "forbidden"),
        ("agent", &agent, StatusCode::FORBIDDEN, "agent_not_allowed"),
    ] {
        let (s, _, v) = json_of(
            &h,
            req_from(
                bearer,
                [127, 0, 0, 1],
                "PUT",
                "/api/v1/secrets/by-other.key",
                Some(&body),
            ),
        )
        .await;
        assert_eq!((s, v["code"].clone()), (status, json!(code)), "{who}: {v}");
        gone(&v.to_string());
    }
    assert!(!h.src.secrets.exists("by-other.key"));
}

/// REQ: CLD-920 (AC 4) - a `pem` value stored through the issuer's path appears in no log line,
/// no API answer or list, and no support package.
#[tokio::test]
async fn cld_920_pem_value_in_no_log_answer_or_support_package() {
    let out = Captured::default();
    let w = out.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || w.clone())
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let guard = tracing::subscriber::set_default(sub);
    let h = harness("");
    let mut log = String::new();
    for _ in 0..5 {
        tracing::callsite::rebuild_interest_cache();
        out.0.lock().unwrap().clear();
        let c = issuer_put(&h.src, "cert.cluster.key", false).await.unwrap();
        assert!(
            !serde_json::to_string(&c)
                .unwrap()
                .contains("plantedPemKeyBytes")
        );
        log = String::from_utf8_lossy(&out.0.lock().unwrap()).into_owned();
        if log.contains("stored secret set") {
            break;
        }
    }
    drop(guard);
    assert!(log.contains("stored secret set"), "{log}");
    assert!(!log.contains("plantedPemKeyBytes"), "{log}");
    assert!(h.src.secrets.exists("cert.cluster.key"));
    let (_, _, list) = h.call("GET", "/api/v1/secrets", None).await;
    assert!(!list.to_string().contains("plantedPemKeyBytes"), "{list}");
    let req = wrendns_api::model::SupportPackageRequest {
        level: Some("none".into()),
        reveal: Vec::new(),
        query_sample: 0,
        keep_map: false,
        cluster: false,
    };
    let (pkg, _) = crate::support::offline(&h.src.config.load(), &req).unwrap();
    let files = wrendns_support::archive::read_tar_gz(&pkg.archive).unwrap();
    assert_ne!(files.len(), 0);
    for f in files {
        assert!(
            !String::from_utf8_lossy(&f.data).contains("plantedPemKeyBytes"),
            "{}",
            f.path
        );
    }
}

/// A primary of its own cluster (no peers), its identity's authority `authority`.
fn lone_primary(authority: &str) -> (Arc<Cluster>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let id = wrendns_cluster::node::Identity::init_with(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "attic",
        authority,
    )
    .unwrap();
    (Cluster::new(id, crate::build_info::VERSION), dir)
}

/// REQ: API-015, CLU-013, ADR-048 (AC10) — under a `GitOps` authority entry writes are 409
/// `gitops_managed` but secret writes go through (secrets are state, never in Git); a pinned
/// cluster holds entry writes back (409 `cluster_pinned`) but not secret writes; an emergency
/// primary refuses them (409).
#[tokio::test]
async fn api_015_gitops_authority_allows_secret_writes() {
    let (c, _d) = lone_primary("gitops");
    let h = harness_in("", Some(c));
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/upstreams/quad9",
            Some(&json!({"url": "tls://9.9.9.9", "tls_server_name": "dns.quad9.net"})),
        )
        .await;
    assert_eq!(
        (s, v["code"].clone()),
        (StatusCode::CONFLICT, json!("gitops_managed")),
        "{v}"
    );
    let (s, _, v) = h
        .call("PUT", "/api/v1/secrets/unifi", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["secret"]["origin"], "cluster");
    let (s, _, v) = h.call("DELETE", "/api/v1/secrets/unifi", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: API-015, CLU-013 (AC10) — a pin holds back configuration, not secrets.
#[tokio::test]
async fn api_015_pinned_allows_secret_writes() {
    use wrendns_cluster::sync::PinInfo;
    let (c, _d) = lone_primary("api");
    let h = harness_in("", Some(c));
    let data = h.src.config.load().node.data_dir.to_string();
    let cdir = wrendns_cluster::node::dir_of(std::path::Path::new(&data));
    std::fs::create_dir_all(&cdir).unwrap();
    crate::rollout::State {
        active: None,
        pinned: Some(PinInfo {
            to: (1, 2),
            since_ms: 1,
            by: "root".into(),
            reason: "hold".into(),
        }),
    }
    .save(&cdir)
    .unwrap();
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/upstreams/quad9",
            Some(&json!({"url": "tls://9.9.9.9", "tls_server_name": "dns.quad9.net"})),
        )
        .await;
    assert_eq!(
        (s, v["code"].clone()),
        (StatusCode::CONFLICT, json!("cluster_pinned")),
        "{v}"
    );
    let (s, _, v) = h
        .call("PUT", "/api/v1/secrets/unifi", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(h.src.secrets.get("unifi").unwrap().expose(), VALUE);
}

/// REQ: API-015, CLU-005 (AC10) — an emergency primary changes nothing, stored secrets included.
#[tokio::test]
async fn api_015_emergency_primary_refuses() {
    let (c, _d) = lone_primary("api");
    let epoch = c.role().1;
    c.set_role(wrendns_cluster::node::Role::Emergency, epoch)
        .unwrap();
    let h = harness_in("", Some(c));
    for (m, uri) in [
        ("PUT", "/api/v1/secrets/unifi"),
        ("PUT", "/api/v1/secrets/unifi?dryRun=true"),
    ] {
        let (s, _, v) = h.call(m, uri, Some(&put_body(VALUE))).await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert!(v["detail"].as_str().unwrap().contains("emergency"), "{v}");
    }
    assert!(!h.src.secrets.exists("unifi"));
}

/// REQ: API-015, CLU-005 (AC11) — a primary whose lease doesn't hold (automatic failover, no
/// majority) takes no secret write (409), dry runs included.
#[tokio::test]
async fn api_015_no_lease_refuses() {
    use wrendns_cluster::node::{Identity, NodeRecord};
    let dir = tempfile::tempdir().unwrap();
    let mut id = Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "attic",
    )
    .unwrap();
    let me = id.registry().remove(0);
    let voter = |n: &str| NodeRecord {
        node_id: n.into(),
        site: n.into(),
        eligible: true,
        advertise: vec![],
        joined: 0,
        witness: false,
        ephemeral: false,
    };
    id.save_registry(&[me, voter("b"), voter("c")]).unwrap();
    id.meta.failover = "auto".into();
    let c = Cluster::new(id, crate::build_info::VERSION);
    assert!(c.is_primary() && !c.may_publish(), "waiting for its lease");
    let h = harness_in("", Some(c));
    for uri in ["/api/v1/secrets/unifi", "/api/v1/secrets/unifi?dryRun=true"] {
        let (s, _, v) = h.call("PUT", uri, Some(&put_body(VALUE))).await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert!(v["detail"].as_str().unwrap().contains("majority"), "{v}");
    }
    assert!(!h.src.secrets.exists("unifi"));
}

/// REQ: API-015 (AC12, ADR-903 §4) — a delete is refused (409 `secret_in_use`) while a field
/// names the secret: one in the primary's configuration, and a node-local one on another member
/// (an OIDC provider of the replica's own files), listed with its node. With a full member whose
/// references can't be read (offline), it needs `?force=true`; known references refuse even then.
#[tokio::test]
async fn api_015_delete_in_use_refused() {
    let p = pair(crate::build_info::VERSION, crate::build_info::VERSION).await;
    let ph = harness_in(
        "[[alerts.destination]]\nname = \"phone\"\ntype = \"ntfy\"\nurl = \"https://ntfy.example/topic\"\ntoken_ref = \"ntfy\"\n",
        Some(Arc::clone(&p.primary)),
    );
    crate::http::serve_peers(&ph.src);
    let rh = harness_in(
        "[[auth.oidc.provider]]\nid = \"gh\"\nissuer = \"https://gh.example\"\nclient_id = \"wrendns\"\nclient_secret_ref = \"oidc-gh\"\n",
        Some(Arc::clone(&p.replica)),
    );
    crate::http::serve_peers(&rh.src);
    for n in ["ntfy", "oidc-gh"] {
        let (s, _, v) = ph
            .call(
                "PUT",
                &format!("/api/v1/secrets/{n}"),
                Some(&put_body(VALUE)),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let (s, _, v) = ph.call("DELETE", "/api/v1/secrets/ntfy", None).await;
    assert_eq!(
        (s, v["code"].clone()),
        (StatusCode::CONFLICT, json!("secret_in_use")),
        "{v}"
    );
    assert!(v["detail"].as_str().unwrap().contains("phone"), "{v}");
    let (s, _, v) = ph.call("DELETE", "/api/v1/secrets/oidc-gh", None).await;
    assert_eq!(
        (s, v["code"].clone()),
        (StatusCode::CONFLICT, json!("secret_in_use")),
        "{v}"
    );
    let detail = v["detail"].as_str().unwrap();
    assert!(detail.contains("gh") && detail.contains("on pi"), "{v}");
    // Through the replica: the same answer from the primary.
    let (s, _, v) = rh
        .call("DELETE", "/api/v1/secrets/oidc-gh?force=true", None)
        .await;
    assert_eq!(
        (s, v["code"].clone()),
        (StatusCode::CONFLICT, json!("secret_in_use")),
        "{v}"
    );
    assert!(ph.src.secrets.exists("oidc-gh"));
    // The replica drops its reference; a member that can't be asked now needs `force`.
    let mut cfg = (*rh.src.config.load_full()).clone();
    cfg.auth.oidc.provider.retain(|x| x.id.as_str() != "gh");
    rh.src.config.store(Arc::new(cfg));
    let mut reg = p.primary.identity.registry();
    reg.push(wrendns_cluster::node::NodeRecord {
        node_id: "offline-node".into(),
        site: "garage".into(),
        eligible: true,
        advertise: vec![],
        joined: 0,
        witness: false,
        ephemeral: false,
    });
    p.primary.identity.save_registry(&reg).unwrap();
    let (s, _, v) = ph.call("DELETE", "/api/v1/secrets/oidc-gh", None).await;
    assert_eq!(
        (s, v["code"].clone()),
        (StatusCode::CONFLICT, json!("secret_in_use")),
        "{v}"
    );
    assert!(v["detail"].as_str().unwrap().contains("garage"), "{v}");
    let (s, _, v) = ph
        .call("DELETE", "/api/v1/secrets/oidc-gh?force=true", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["warnings"][0].as_str().unwrap().contains("garage"), "{v}");
    assert!(!ph.src.secrets.exists("oidc-gh"));
    let _ = p.stop.send(true);
}

/// REQ: API-015 (AC13, ADR-903 §4) — a value over plain HTTP from another host is refused with
/// 403 `insecure_transport` (a forwarded request from loopback too, and a client's own
/// `X-Forwarded-Proto` isn't believed); HTTPS (the API's own TLS), loopback, or
/// `[api] allow_secrets_over_http` let it through.
#[allow(clippy::too_many_lines)] // AC13's cases, one after another
#[tokio::test]
async fn api_015_plain_http_refused_unless_loopback_or_allowed() {
    let open = || vec![wrendns_config::Cidr::parse("0.0.0.0/0").unwrap()];
    let h = harness_from("", None, open());
    let lan = [192, 168, 1, 50];
    let (s, _, v) = json_of(
        &h,
        req_from(
            &h.bearer,
            lan,
            "PUT",
            "/api/v1/secrets/a",
            Some(&put_body(VALUE)),
        ),
    )
    .await;
    assert_eq!(
        (s, v["code"].clone()),
        (StatusCode::FORBIDDEN, json!("insecure_transport")),
        "{v}"
    );
    assert!(v["hint"].as_str().unwrap().contains("self_signed"), "{v}");
    let mut r = req_from(&h.bearer, lan, "DELETE", "/api/v1/secrets/a", None);
    r.headers_mut()
        .insert("x-forwarded-proto", "https".parse().unwrap());
    assert_eq!(
        h.send(r).await.0,
        StatusCode::FORBIDDEN,
        "not a trusted proxy"
    );
    let mut r = req_from(
        &h.bearer,
        [127, 0, 0, 1],
        "PUT",
        "/api/v1/secrets/a",
        Some(&put_body(VALUE)),
    );
    r.headers_mut()
        .insert("x-forwarded-for", "192.168.1.50".parse().unwrap());
    assert_eq!(
        h.send(r).await.0,
        StatusCode::FORBIDDEN,
        "forwarded from afar"
    );
    // A plain-HTTP proxy or relay on the same host passing a remote client's headers through:
    // loopback isn't a trusted proxy for this check, whatever `X-Forwarded-Proto` says.
    for fwd in ["x-forwarded-for", "forwarded", "x-real-ip"] {
        let mut r = req_from(
            &h.bearer,
            [127, 0, 0, 1],
            "PUT",
            "/api/v1/secrets/a",
            Some(&put_body(VALUE)),
        );
        let v = if fwd == "forwarded" {
            "for=192.168.1.50"
        } else {
            "192.168.1.50"
        };
        r.headers_mut().insert(fwd, v.parse().unwrap());
        r.headers_mut()
            .insert("x-forwarded-proto", "https".parse().unwrap());
        let (s, _, v) = json_of(&h, r).await;
        assert_eq!(
            (s, v["code"].clone()),
            (StatusCode::FORBIDDEN, json!("insecure_transport")),
            "{fwd} + X-Forwarded-Proto from loopback: {v}"
        );
    }
    assert!(!h.src.secrets.exists("a"));
    // `[::]` listener: `::ffff:127.0.0.1` is the node itself.
    let mut r = req_from(
        &h.bearer,
        lan,
        "PUT",
        "/api/v1/secrets/mapped",
        Some(&put_body(VALUE)),
    );
    r.extensions_mut().insert(axum::extract::ConnectInfo(
        "[::ffff:127.0.0.1]:40000".parse::<SocketAddr>().unwrap(),
    ));
    let (s, _, v) = json_of(&h, r).await;
    assert_eq!(s, StatusCode::OK, "IPv4-mapped loopback: {v}");
    // A proxy listed in `[api] trusted_proxies` saying HTTPS is believed (and only it).
    let proxy = auth::Settings {
        trusted_proxies: vec![("192.168.1.2".parse().unwrap(), 32)],
        ..auth::Settings::default()
    };
    let h3 = harness_with("", None, open(), proxy);
    for (peer, want) in [
        ([192, 168, 1, 2], StatusCode::OK),
        ([192, 168, 1, 3], StatusCode::FORBIDDEN),
    ] {
        let mut r = req_from(
            &h3.bearer,
            peer,
            "PUT",
            "/api/v1/secrets/p",
            Some(&put_body(VALUE)),
        );
        r.headers_mut()
            .insert("x-forwarded-for", "192.168.1.50".parse().unwrap());
        r.headers_mut()
            .insert("x-forwarded-proto", "https".parse().unwrap());
        let (s, _, v) = json_of(&h3, r).await;
        assert_eq!(s, want, "proxy {peer:?}: {v}");
    }
    // The API's own TLS.
    let mut r = req_from(
        &h.bearer,
        lan,
        "PUT",
        "/api/v1/secrets/a",
        Some(&put_body(VALUE)),
    );
    r.extensions_mut()
        .insert(wrendns_api::auth::routes::TlsConnection);
    let (s, _, v) = json_of(&h, r).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // Reads aren't held to it.
    let (s, _, _) = json_of(&h, req_from(&h.bearer, lan, "GET", "/api/v1/secrets", None)).await;
    assert_eq!(s, StatusCode::OK);
    // Allowed by the node's files.
    let h2 = harness_from("[api]\nallow_secrets_over_http = true\n", None, open());
    let (s, _, v) = json_of(
        &h2,
        req_from(
            &h2.bearer,
            lan,
            "PUT",
            "/api/v1/secrets/b",
            Some(&put_body(VALUE)),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: API-015, API-003 (AC14) — a signed-in session's secret write needs its `X-CSRF-Token`.
#[tokio::test]
async fn api_015_csrf_enforced() {
    let h = harness("");
    let login = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("content-type", "application/json")
        .extension(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            40003,
        ))))
        .body(Body::from(
            json!({"username": "root", "password": "correct horse battery"}).to_string(),
        ))
        .unwrap();
    let (s, hd, text) = h.send(login).await;
    assert_eq!(s, StatusCode::OK, "{text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    let csrf = v["csrfToken"].as_str().unwrap().to_owned();
    let cookie = hd
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let put = |csrf: Option<&str>| {
        let mut b = Request::builder()
            .method("PUT")
            .uri("/api/v1/secrets/csrf")
            .header("cookie", cookie.as_str())
            .header("content-type", "application/json")
            .extension(axum::extract::ConnectInfo(SocketAddr::from((
                [127, 0, 0, 1],
                40003,
            ))));
        if let Some(c) = csrf {
            b = b.header("x-csrf-token", c);
        }
        b.body(Body::from(put_body(VALUE).to_string())).unwrap()
    };
    let (s, _, v) = json_of(&h, put(None)).await;
    assert_eq!(
        (s, v["code"].clone()),
        (StatusCode::FORBIDDEN, json!("csrf_rejected")),
        "{v}"
    );
    let (s, _, _) = json_of(&h, put(Some("wrong"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(!h.src.secrets.exists("csrf"));
    let (s, _, v) = json_of(&h, put(Some(&csrf))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(h.src.secrets.exists("csrf"));
}

/// REQ: API-015, OPS-014 (AC15, ADR-903 §2) — the value rules through the API: empty, over
/// 8 KiB, a control character, `<redacted>`, a `pem` value that is not PEM or an unknown kind, a bad
/// name, a 129th secret, and a webhook secret under 16 characters are refused (with the reason,
/// never the value); 8 KiB exactly and surrounding space are fine. A credential the files set
/// can't get the secret the UI would name for it (409 `set_by_file`).
#[tokio::test]
#[allow(clippy::too_many_lines)] // one case per rule
async fn api_015_value_limits() {
    let h = harness(
        "[[alerts.destination]]\nname = \"pager\"\ntype = \"ntfy\"\nurl = \"https://ntfy.example/p\"\ntoken_file = \"/run/secrets/pager\"\n[cluster.git]\nrepo = \"https://git.example/net.git\"\npath = \"wrendns.toml\"\nwebhook_secret_ref = \"hook\"\n",
    );
    let refused = |v: &Value| v["detail"].as_str().unwrap_or_default().to_owned();
    for (name, body, why) in [
        ("a", json!({"value": "   "}), "empty"),
        ("a", json!({"value": "x".repeat(8 * 1024 + 1)}), "8 KiB"),
        ("a", json!({"value": "one\ttwo"}), "control"),
        ("a", json!({"value": "one\ntwo"}), "control"),
        ("a", json!({"value": "<redacted>"}), "<redacted>"),
        ("a", json!({"value": VALUE, "kind": "blob"}), "kind"),
        ("a", json!({"value": VALUE, "kind": "pem"}), "PEM"),
        ("Bad.Name", json!({"value": VALUE}), "name"),
        ("-lead", json!({"value": VALUE}), "name"),
        (&"n".repeat(64), json!({"value": VALUE}), "name"),
        ("hook", json!({"value": "short-hook"}), "16"),
    ] {
        let (s, _, v) = h
            .call("PUT", &format!("/api/v1/secrets/{name}"), Some(&body))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{name} {body}: {v}");
        assert!(refused(&v).contains(why), "{why}: {v}");
        no_value(&v.to_string());
        assert!(!v.to_string().contains("short-hook"), "{v}");
    }
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/secrets/a",
            Some(&json!({"value": VALUE, "other": 1})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    no_value(&v.to_string());
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/secrets/hook",
            Some(&json!({"value": "a-webhook-secret-of-24ch"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let big = "y".repeat(8 * 1024);
    let (s, _, v) = h
        .call("PUT", "/api/v1/secrets/big", Some(&json!({"value": big})))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, _) = h
        .call(
            "PUT",
            "/api/v1/secrets/spaced",
            Some(&json!({"value": format!("  {VALUE}\n")})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h.src.secrets.get("spaced").unwrap().expose(), VALUE);
    // The files set the pager's token: the name the UI would store it under is refused.
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/secrets/alert_destination.pager.token",
            Some(&put_body(VALUE)),
        )
        .await;
    assert_eq!(
        (s, v["code"].clone()),
        (StatusCode::CONFLICT, json!("set_by_file")),
        "{v}"
    );
    assert!(
        v["detail"].as_str().unwrap().contains("/run/secrets/pager"),
        "{v}"
    );
    // At most 128.
    let have = h.src.secrets.status().live();
    for i in have..128 {
        h.src
            .secrets
            .put(
                &format!("fill-{i}"),
                crate::secrets::value::Kind::Text,
                &crate::secrets::SecretValue::new(
                    crate::secrets::value::Kind::Text,
                    zeroize::Zeroizing::new("v".to_owned()),
                )
                .unwrap(),
                0,
                "root",
                "local",
                1,
            )
            .unwrap();
    }
    let (s, _, v) = h
        .call("PUT", "/api/v1/secrets/one-more", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(refused(&v).contains("128"), "{v}");
    // Replacing one is still fine.
    let (s, _, _) = h
        .call("PUT", "/api/v1/secrets/fill-127", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::OK);
}

/// REQ: API-015, OPS-014 — a locked store refuses secret writes (503 `secrets_locked`), and a
/// retry-keyed one too, while reads still answer with the reason.
#[tokio::test]
async fn api_015_locked_store_refuses_writes() {
    let h = harness("[node]\nsecrets_key_file = \"/nonexistent/wrendns/secrets.key\"\n");
    h.src.secrets.configure(&h.src.config.load_full());
    let (s, _, v) = h
        .call("PUT", "/api/v1/secrets/a", Some(&put_body(VALUE)))
        .await;
    assert_eq!(
        (s, v["code"].clone()),
        (StatusCode::SERVICE_UNAVAILABLE, json!("secrets_locked")),
        "{v}"
    );
    let mut r = h.request("PUT", "/api/v1/secrets/a", Some(&put_body(VALUE)));
    r.headers_mut()
        .insert("idempotency-key", "locked".parse().unwrap());
    assert_eq!(h.send(r).await.0, StatusCode::SERVICE_UNAVAILABLE);
    let (s, _, v) = h.call("GET", "/api/v1/secrets", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["store"]["state"], "locked");
    assert!(
        v["store"]["reason"]
            .as_str()
            .unwrap()
            .contains("/nonexistent"),
        "{v}"
    );
}

/// REQ: OPS-014, CLU-010 (ADR-903 "Mixed versions") — a write that adds a `*_ref` warns, naming
/// the members too old to know the field (they keep their last configuration until upgraded).
#[tokio::test(flavor = "multi_thread")]
async fn api_015_new_ref_warns_older_members() {
    let p = pair(crate::build_info::VERSION, "0.7.4").await;
    let ph = harness_in("", Some(Arc::clone(&p.primary)));
    for _ in 0..200 {
        if p.primary.members().iter().any(|m| m.version == "0.7.4") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let (s, _, v) = ph
        .call("PUT", "/api/v1/secrets/ntfy", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let body = json!({"type": "ntfy", "url": "https://ntfy.example/topic", "token_ref": "ntfy"});
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/alerts/destinations/phone?dryRun=true",
            Some(&body),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let warnings = v["warnings"].to_string();
    assert!(
        warnings.contains("older than 0.8.0") && warnings.contains("pi (0.7.4)"),
        "{v}"
    );
    // An entry without a reference: no such warning.
    let (_, _, v) = ph
        .call(
            "PUT",
            "/api/v1/alerts/destinations/plain?dryRun=true",
            Some(&json!({"type": "ntfy", "url": "https://ntfy.example/other"})),
        )
        .await;
    assert!(!v["warnings"].to_string().contains("0.8.0"), "{v}");
    let _ = p.stop.send(true);
}

/// REQ: API-015 (AC15) — a body the parser refuses is answered with its category and position,
/// never the parser's own text, which can quote the input (a numeric PIN).
#[tokio::test]
async fn api_015_bad_body_never_quotes_value() {
    let h = harness("");
    for body in [json!({"value": 12_345_678}), json!({"value": [12_345_678]})] {
        let (s, _, v) = h.call("PUT", "/api/v1/secrets/pin", Some(&body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
        assert!(!v.to_string().contains("12345678"), "{v}");
        assert!(v["detail"].as_str().unwrap().contains("line 1"), "{v}");
    }
    assert!(!h.src.secrets.exists("pin"));
}

/// Every byte under `dir` (the database, its WAL and anything else a node writes).
fn bytes_under(dir: &std::path::Path) -> Vec<u8> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(bytes_under(&p));
            } else if let Ok(b) = std::fs::read(&p) {
                out.extend(b);
            }
        }
    }
    out
}

/// Runs one sync pass on each node until `done` holds (heartbeats carry the heads between them).
async fn sync_until(
    pairs: (&Harness, &Harness),
    clusters: (&Arc<Cluster>, &Arc<Cluster>),
    mut done: impl FnMut() -> bool,
) {
    for _ in 0..200 {
        crate::secrets::sync::run_once(&pairs.0.src, clusters.0).await;
        crate::secrets::sync::run_once(&pairs.1.src, clusters.1).await;
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// REQ: CLU-015 (AC17) — over the real mTLS channel of two nodes: a secret set on the replica is
/// forwarded to the primary (as `secret.put`), the replica's own standalone row is offered to the
/// primary when the replica joins, and the primary's rows come back to the replica re-encrypted
/// under its key. A deletion on the primary reaches the replica as a tombstone. No plaintext is
/// written under the replica's data directory.
#[tokio::test]
async fn clu_015_set_on_replica_replicates_back() {
    use crate::secrets::value::{Kind, SecretValue};
    let p = pair(crate::build_info::VERSION, crate::build_info::VERSION).await;
    let ph = harness_in("", Some(Arc::clone(&p.primary)));
    crate::http::serve_peers(&ph.src);
    let rh = harness_in("", Some(Arc::clone(&p.replica)));
    crate::http::serve_peers(&rh.src);
    // A row the replica made before it joined: offered to the primary, then shadowed.
    let own =
        SecretValue::new(Kind::Text, zeroize::Zeroizing::new("own-local-7713".into())).unwrap();
    rh.src
        .secrets
        .put("local.one", Kind::Text, &own, 0, "root", "local", 50)
        .unwrap();
    // Set on the replica: forwarded to the primary.
    let (s, _, v) = rh
        .call("PUT", "/api/v1/secrets/unifi", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(ph.src.secrets.exists("unifi"), "stored on the primary");
    // Replicated back.
    sync_until((&ph, &rh), (&p.primary, &p.replica), || {
        rh.src.secrets.get("unifi").is_ok() && ph.src.secrets.exists("local.one")
    })
    .await;
    assert_eq!(rh.src.secrets.get("unifi").unwrap().expose(), VALUE);
    assert_eq!(
        rh.src
            .secrets
            .status()
            .secrets
            .iter()
            .find(|s| s.name == "unifi")
            .map(|s| s.origin.clone()),
        Some("cluster".to_owned())
    );
    assert!(
        ph.src.secrets.exists("local.one"),
        "the joiner's row was adopted"
    );
    // The replica's own row is shadowed by the cluster's, and still there.
    assert!(
        rh.src
            .secrets
            .status()
            .shadows
            .iter()
            .any(|n| n == "local.one"),
        "the replica's own row is shadowed"
    );
    // No plaintext under the replica's data directory.
    let rdir = rh.src.config.load().node.data_dir.as_str().to_owned();
    let on_disk = bytes_under(std::path::Path::new(&rdir));
    assert!(
        !on_disk.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()),
        "no value on disk"
    );
    // A deletion on the primary reaches the replica by tombstone.
    let (s, _, v) = ph.call("DELETE", "/api/v1/secrets/unifi", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    sync_until((&ph, &rh), (&p.primary, &p.replica), || {
        rh.src.secrets.get("unifi").is_err()
    })
    .await;
    assert!(
        rh.src.secrets.get("unifi").is_err(),
        "deleted on the replica too"
    );
    let _ = p.stop.send(true);
}

/// REQ: CLU-015 (AC2) — the primary answers a secrets read only for a member its registry lists as
/// full: a stranger (or a member that calls itself full) gets nothing.
#[tokio::test]
async fn clu_015_stranger_refused() {
    let p = pair(crate::build_info::VERSION, crate::build_info::VERSION).await;
    let ph = harness_in("", Some(Arc::clone(&p.primary)));
    let r = crate::secrets::sync::answer_fetch(
        Arc::clone(&ph.src),
        Arc::clone(&p.primary),
        "not-a-member".into(),
        Vec::new(),
    )
    .await;
    assert!(r.is_err(), "{r:?}");
    let _ = p.stop.send(true);
}

/// Joins one more node to the pair's primary as a witness or an ephemeral member (a registry
/// entry that isn't full), and returns its node ID.
async fn join_other(p: &Pair, witness: bool, ephemeral: bool) -> String {
    use wrendns_cluster::net::join;
    use wrendns_cluster::node::{JoinRequest, TokenGrants};
    let urls = p.primary.identity.meta.advertise.clone();
    let token = p
        .primary
        .identity
        .create_token_for(
            600,
            Some(urls),
            TokenGrants {
                eligible: !witness,
                witness,
            },
        )
        .unwrap();
    let key = wrendns_cluster::pki::new_node_key().unwrap();
    let req = JoinRequest {
        witness,
        ephemeral,
        secret: token.secret.clone(),
        csr_pem: key.csr_pem.clone(),
        advertise: vec![],
        site: "extra".into(),
        eligible: !witness,
        version: crate::build_info::VERSION.into(),
    };
    join(&token, &req).await.unwrap().node_id
}

/// Writes the pin or the canary bake a node's cluster directory holds (`rollout.json`).
fn write_rollout(h: &Harness, state: &crate::rollout::State) {
    let data = h.src.config.load().node.data_dir.as_str().to_owned();
    let cdir = wrendns_cluster::node::dir_of(std::path::Path::new(&data));
    std::fs::create_dir_all(&cdir).unwrap();
    state.save(&cdir).unwrap();
}

/// REQ: CLU-015 (AC2; M5) — a witness and an ephemeral member, both registered with the primary,
/// get no secrets over the channel: a stranger's refusal. A full member gets its answer.
#[tokio::test]
async fn clu_015_witness_and_ephemeral_refused_over_the_channel() {
    let p = pair(crate::build_info::VERSION, crate::build_info::VERSION).await;
    let ph = harness_in("", Some(Arc::clone(&p.primary)));
    crate::http::serve_peers(&ph.src);
    let witness = join_other(&p, true, false).await;
    let ephemeral = join_other(&p, false, true).await;
    for peer in [witness, ephemeral] {
        let r = crate::secrets::sync::answer_fetch(
            Arc::clone(&ph.src),
            Arc::clone(&p.primary),
            peer.clone(),
            Vec::new(),
        )
        .await;
        assert!(r.is_err(), "{peer} is not a full member: {r:?}");
    }
    let full = p.replica.identity.meta.node_id.clone();
    let r = crate::secrets::sync::answer_fetch(
        Arc::clone(&ph.src),
        Arc::clone(&p.primary),
        full,
        Vec::new(),
    )
    .await;
    assert!(r.is_ok(), "{r:?}");
    let _ = p.stop.send(true);
}

/// REQ: CLU-015 (ADR-917 point 11; M1; ADR-903 §4) — an emergency primary answers with its rows
/// marked non-authoritative, so a replica only fills by stamp from it; its sync pass changes
/// nothing it holds.
#[tokio::test]
async fn clu_015_emergency_primary_answers_non_authoritatively() {
    let p = pair(crate::build_info::VERSION, crate::build_info::VERSION).await;
    let ph = harness_in("", Some(Arc::clone(&p.primary)));
    crate::http::serve_peers(&ph.src);
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/secrets/emergency.one",
            Some(&put_body(VALUE)),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let epoch = p.primary.role().1;
    p.primary
        .set_role(wrendns_cluster::node::Role::Emergency, epoch)
        .unwrap();
    let full = p.replica.identity.meta.node_id.clone();
    let raw = crate::secrets::sync::answer_fetch(
        Arc::clone(&ph.src),
        Arc::clone(&p.primary),
        full,
        Vec::new(),
    )
    .await
    .unwrap();
    let ans: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(ans["authoritative"], json!(false), "{ans}");
    assert_eq!(ans["items"].as_array().map(Vec::len), Some(1), "{ans}");
    // The emergency primary's own sync pass refills nothing and hands nothing over.
    crate::secrets::sync::run_once(&ph.src, &p.primary).await;
    assert_eq!(ph.src.secrets.get("emergency.one").unwrap().expose(), VALUE);
    let _ = p.stop.send(true);
}

/// REQ: CLU-015 (ADR-903 §6; ADR-917 points 10, 12; M3) — a joining node's offer: a fresh name is
/// taken and audited as `secret.adopt`; a name the cluster holds (a deletion too) and an unusable
/// row are conflicts, audited as `secret.adopt_conflict`, and no deleted name comes back.
#[tokio::test]
async fn clu_015_adopt_audited_and_tombstones_conflict() {
    let p = pair(crate::build_info::VERSION, crate::build_info::VERSION).await;
    let ph = harness_in("", Some(Arc::clone(&p.primary)));
    crate::http::serve_peers(&ph.src);
    let (s, _, v) = ph
        .call("PUT", "/api/v1/secrets/gone", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = ph
        .call("DELETE", "/api/v1/secrets/gone?force=true", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let body = json!({ "secrets": [
        { "name": "fresh.one", "kind": "text", "value": "fresh-value-8891" },
        { "name": "gone", "kind": "text", "value": "gone-value-8892" },
        { "name": "bad.kind", "kind": "bogus", "value": "bogus-value-8893" },
    ]});
    let peer = p.replica.identity.meta.node_id.clone();
    let raw = crate::secrets::sync::answer_adopt(
        Arc::clone(&ph.src),
        Arc::clone(&p.primary),
        peer,
        serde_json::to_vec(&body).unwrap(),
    )
    .await
    .unwrap();
    let ans: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(ans["adopted"], json!(["fresh.one"]), "{ans}");
    assert_eq!(ans["conflicts"], json!(["gone", "bad.kind"]), "{ans}");
    assert!(
        ph.src.secrets.get("gone").is_err(),
        "a deleted name isn't re-created"
    );
    assert!(ph.src.secrets.exists("fresh.one"));
    let log = audit(&ph);
    assert!(log.contains("cluster | secret.adopt | fresh.one"), "{log}");
    assert!(
        log.contains("cluster | secret.adopt_conflict | gone"),
        "{log}"
    );
    assert!(!log.contains("fresh-value-8891"), "no value in the audit");
    let _ = p.stop.send(true);
}

/// REQ: DSC-908, CLD-920 (ADR-1096 point 5) - a joining node's `pem` row is not taken while a
/// member's build does not announce the kind (a conflict: the joiner keeps it), and is taken once
/// every member announces it; a text row from the same offer is taken either way.
#[tokio::test]
async fn dsc_908_adopt_holds_a_pem_row_until_every_member_knows_the_kind() {
    let _turn = GATE.lock().await;
    let body = json!({ "secrets": [
        { "name": "joined.text", "kind": "text", "value": "joined-value-7741" },
        { "name": "cert.cluster.key", "kind": "pem", "value": PEM_VALUE },
    ]});
    for (features, pem_taken) in [(Some(Vec::new()), false), (None, true)] {
        let p = pair_features("1.1.0", "1.1.0-edge.40", features).await;
        let ph = harness_in("", Some(Arc::clone(&p.primary)));
        crate::http::serve_peers(&ph.src);
        let peer = p.replica.identity.meta.node_id.clone();
        let raw = crate::secrets::sync::answer_adopt(
            Arc::clone(&ph.src),
            Arc::clone(&p.primary),
            peer,
            serde_json::to_vec(&body).unwrap(),
        )
        .await
        .unwrap();
        let ans: Value = serde_json::from_slice(&raw).unwrap();
        assert!(ph.src.secrets.exists("joined.text"), "{ans}");
        assert_eq!(
            ph.src.secrets.exists("cert.cluster.key"),
            pem_taken,
            "{ans}"
        );
        // The refusals a gate records are process-wide, and a test of another kind (the allowed
        // networks, the dnstap settings) may have one standing: this test reads the pem kind's.
        let pem_holds = || -> Vec<String> {
            crate::upgrade_gate::standing(Some(&p.primary))
                .into_iter()
                .filter(|h| h.contains("`pem` kind"))
                .collect()
        };
        if pem_taken {
            assert_eq!(ans["conflicts"], json!([]), "{ans}");
            assert_eq!(pem_holds(), Vec::<String>::new());
        } else {
            assert_eq!(ans["conflicts"], json!(["cert.cluster.key"]), "{ans}");
            let holds = pem_holds();
            assert_eq!(holds.len(), 1, "{holds:?}");
            assert!(holds[0].contains("1.1.0-edge.40"), "{holds:?}");
        }
        let _ = p.stop.send(true);
    }
}

/// REQ: CLU-015 (AC9; M5) — over the real channel: a primary whose data-directory key is lost
/// (its store is locked, and every row is the cluster's) refills from a replica holding every row
/// at its stamp, and its reads work again.
#[tokio::test]
async fn clu_015_reverse_heal_over_mtls() {
    let p = pair(crate::build_info::VERSION, crate::build_info::VERSION).await;
    let ph = harness_in("", Some(Arc::clone(&p.primary)));
    crate::http::serve_peers(&ph.src);
    let rh = harness_in("", Some(Arc::clone(&p.replica)));
    crate::http::serve_peers(&rh.src);
    let (s, _, v) = ph
        .call("PUT", "/api/v1/secrets/heal.one", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    sync_until((&ph, &rh), (&p.primary, &p.replica), || {
        rh.src.secrets.get("heal.one").is_ok()
    })
    .await;
    assert!(
        rh.src.secrets.get("heal.one").is_ok(),
        "the replica holds it"
    );
    // The primary loses its key file; the store reloads locked.
    let data = ph.src.config.load().node.data_dir.as_str().to_owned();
    std::fs::remove_file(std::path::Path::new(&data).join(crate::secrets::KEY_FILE)).unwrap();
    ph.src.secrets.load_now();
    assert!(ph.src.secrets.get("heal.one").is_err(), "locked");
    // Its sync pass refills from the replica over the channel.
    for _ in 0..50 {
        crate::secrets::sync::run_once(&ph.src, &p.primary).await;
        if ph.src.secrets.get("heal.one").is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(ph.src.secrets.get("heal.one").unwrap().expose(), VALUE);
    let _ = p.stop.send(true);
}

/// REQ: CLU-015 (AC12; M5) — a pinned manifest doesn't hold a secret back: the replica is pinned,
/// and a primary's new secret still reaches it through the sync pass.
#[tokio::test]
async fn clu_015_replicates_while_pinned() {
    use wrendns_cluster::sync::PinInfo;
    let p = pair(crate::build_info::VERSION, crate::build_info::VERSION).await;
    let ph = harness_in("", Some(Arc::clone(&p.primary)));
    crate::http::serve_peers(&ph.src);
    let rh = harness_in("", Some(Arc::clone(&p.replica)));
    crate::http::serve_peers(&rh.src);
    write_rollout(
        &rh,
        &crate::rollout::State {
            active: None,
            pinned: Some(PinInfo {
                to: (1, 2),
                since_ms: 1,
                by: "root".into(),
                reason: "hold".into(),
            }),
        },
    );
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/secrets/pinned.secret",
            Some(&put_body(VALUE)),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    sync_until((&ph, &rh), (&p.primary, &p.replica), || {
        rh.src.secrets.get("pinned.secret").is_ok()
    })
    .await;
    assert_eq!(rh.src.secrets.get("pinned.secret").unwrap().expose(), VALUE);
    let _ = p.stop.send(true);
}

/// REQ: CLU-015 (AC12; M5) — a canary bake doesn't hold a secret back: the replica is in the
/// middle of a bake, and a primary's new secret still reaches it through the sync pass.
#[tokio::test]
async fn clu_015_not_gated_by_canary_bake() {
    let p = pair(crate::build_info::VERSION, crate::build_info::VERSION).await;
    let ph = harness_in("", Some(Arc::clone(&p.primary)));
    crate::http::serve_peers(&ph.src);
    let rh = harness_in("", Some(Arc::clone(&p.replica)));
    crate::http::serve_peers(&rh.src);
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap_or(0);
    write_rollout(
        &rh,
        &crate::rollout::State {
            active: Some(crate::rollout::Active {
                version: (2, 1),
                stable: (1, 1),
                started_ms: now,
                bake_secs: 3600,
                canaries: vec![p.replica.identity.meta.node_id.clone()],
                before_pct: None,
            }),
            pinned: None,
        },
    );
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/secrets/baking.secret",
            Some(&put_body(VALUE)),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    sync_until((&ph, &rh), (&p.primary, &p.replica), || {
        rh.src.secrets.get("baking.secret").is_ok()
    })
    .await;
    assert_eq!(rh.src.secrets.get("baking.secret").unwrap().expose(), VALUE);
    let _ = p.stop.send(true);
}

/// REQ: CLU-015 (AC14; M5) — the sync never gates readiness: a replica whose pulls fail (the
/// primary's store is locked, so it answers "unavailable") is exactly as ready as before its passes.
#[tokio::test]
async fn clu_015_fetch_never_gates_readiness() {
    let p = pair(crate::build_info::VERSION, crate::build_info::VERSION).await;
    let ph = harness_in("", Some(Arc::clone(&p.primary)));
    crate::http::serve_peers(&ph.src);
    let rh = harness_in("", Some(Arc::clone(&p.replica)));
    crate::http::serve_peers(&rh.src);
    rh.src.readiness.set_bound();
    rh.src.readiness.set_synced();
    let (s, _, v) = ph
        .call("PUT", "/api/v1/secrets/ready.one", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The primary loses its key file: its store is locked and its answers say unavailable.
    let data = ph.src.config.load().node.data_dir.as_str().to_owned();
    std::fs::remove_file(std::path::Path::new(&data).join(crate::secrets::KEY_FILE)).unwrap();
    ph.src.secrets.load_now();
    let before = rh.src.readiness.ready();
    assert!(before, "the replica is ready before its pass");
    for _ in 0..3 {
        crate::secrets::sync::run_once(&rh.src, &p.replica).await;
    }
    assert!(
        rh.src.secrets.get("ready.one").is_err(),
        "the pull failed (the primary is locked)"
    );
    assert_eq!(rh.src.readiness.ready(), before, "readiness is unchanged");
    let _ = p.stop.send(true);
}

/// REQ: CLD-920, DSC-908 (ADR-1097 point 1) - the issuer-only rule is enforced where a write is
/// applied: an older replica forwards a PUT or DELETE of a reserved name as kind `text` (only the
/// entry node's handler judged it before), and the primary refuses both with 409, storing and
/// deleting nothing. The issuer's own path still writes the name.
#[tokio::test]
async fn cld_920_forwarded_write_of_an_issuer_name_is_refused_on_the_primary() {
    use wrendns_api::secrets_api::{SecretOp, SecretText, SecretWrite};
    let _turn = GATE.lock().await;
    let p = pair(crate::build_info::VERSION, crate::build_info::VERSION).await;
    let ph = harness_in("", Some(Arc::clone(&p.primary)));
    crate::http::serve_peers(&ph.src);
    let w = |name: &str, op| SecretWrite {
        name: name.to_owned(),
        op,
        dry_run: false,
        expect: None,
        by: "admin".into(),
        role: Some(auth::Role::Admin),
        agent: None,
    };
    for name in ["cert.cluster.key", "acme.account", " cert.home.chain "] {
        let put = SecretOp::Put {
            kind: "text".into(),
            value: SecretText::new("planted-forwarded-value".to_owned()),
        };
        let e = crate::secrets_api::forward(Arc::clone(&p.replica), w(name, put))
            .await
            .unwrap_err();
        assert_eq!(e.code_status(), StatusCode::CONFLICT, "{name}: {e:?}");
        assert!(
            !serde_json::to_string(&e)
                .unwrap()
                .contains("planted-forwarded")
        );
        assert!(!ph.src.secrets.exists(name.trim()), "{name}");
    }
    // A row that is there (the issuer wrote it) cannot be deleted by a forwarded write either.
    issuer_put(&ph.src, "cert.cluster.key", false)
        .await
        .unwrap();
    let e = crate::secrets_api::forward(
        Arc::clone(&p.replica),
        w("cert.cluster.key", SecretOp::Delete { force: true }),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code_status(), StatusCode::CONFLICT, "{e:?}");
    assert!(ph.src.secrets.exists("cert.cluster.key"));
    // An ordinary name still goes through the same path.
    let ok = crate::secrets_api::forward(
        Arc::clone(&p.replica),
        w(
            "plain",
            SecretOp::Put {
                kind: "text".into(),
                value: SecretText::new(VALUE.to_owned()),
            },
        ),
    )
    .await;
    assert!(ok.is_ok(), "{ok:?}");
    let _ = p.stop.send(true);
}

/// REQ: DSC-908, CLD-920 - `PUT /api/v1/secrets/{name}` with kind `pem`, through the public
/// route, is refused with the gate's 409 `upgrade_required` while a member does not announce
/// `pem_secrets`, naming it; a text secret on the same cluster is not held.
#[tokio::test]
async fn dsc_908_public_pem_put_is_refused_while_a_member_lacks_the_kind() {
    let _turn = GATE.lock().await;
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    let ph = harness_in("", Some(Arc::clone(&old.primary)));
    crate::http::serve_peers(&ph.src);
    let body = json!({"value": PEM_VALUE, "kind": "pem"});
    for path in [
        "/api/v1/secrets/loc.key",
        "/api/v1/secrets/loc.key?dryRun=true",
    ] {
        let (s, _, v) = ph.call("PUT", path, Some(&body)).await;
        assert_eq!(s, StatusCode::CONFLICT, "{path}: {v}");
        assert_eq!(v["code"], "upgrade_required", "{v}");
        assert!(
            v["detail"]
                .as_str()
                .unwrap()
                .contains("version 1.1.0-edge.40"),
            "{v}"
        );
        assert!(!v.to_string().contains("plantedPemKeyBytes"), "{v}");
    }
    assert!(!ph.src.secrets.exists("loc.key"));
    let (s, _, v) = ph
        .call("PUT", "/api/v1/secrets/plain", Some(&put_body(VALUE)))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let _ = old.stop.send(true);
}

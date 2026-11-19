//! REQ: API-016, CLU-015, CLU-004, CLU-010 (T23.10, ADR-903 §6, ADR-967) — OIDC providers made in
//! the UI as a node-managed kind: the API writes through the real path (the route, the plan, the
//! reload, the applier), a replica merges the primary's blob apart from the shared part, a
//! promoted primary seeds its rows from it, and the files always win. A fake issuer answers
//! discovery in process; nothing reaches the network.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use serde_json::{Value, json};
use wrendns_api::auth::Role;
use wrendns_cluster::node::{Identity, Role as NodeRole};
use wrendns_cluster::sync::{BlobStore, ClusterManifest, blob_ref};
use wrendns_config::Config;

use crate::credential_tests::{Harness, harness};
use crate::managed::OIDC_PROVIDER;
use crate::secrets::value::Kind;
use crate::settings_kinds_tests::{call_as, token};

const PROVIDERS: &str = "/api/v1/oidc-providers";

/// A provider body: references only.
fn body(issuer: &str) -> Value {
    json!({"issuer": issuer, "client_id": "wrendns", "default_role": "viewer", "name": "Lab SSO"})
}

/// Serves discovery and an empty key set for `https://idp.test`, and nothing else.
fn fake_fetch() -> wrendns_api::auth::oidc::Fetch {
    Arc::new(|req: axum::http::Request<Vec<u8>>| {
        Box::pin(async move {
            let (host, path) = (
                req.uri().host().unwrap_or_default().to_owned(),
                req.uri().path().to_owned(),
            );
            if host != "idp.test" {
                return Err(format!("no fake provider at {host}"));
            }
            let doc = if path.ends_with("/openid-configuration") {
                json!({
                    "issuer": "https://idp.test",
                    "authorization_endpoint": "https://idp.test/authorize",
                    "token_endpoint": "https://idp.test/token",
                    "jwks_uri": "https://idp.test/jwks",
                })
            } else {
                json!({"keys": []})
            };
            Ok(axum::http::Response::new(doc.to_string().into_bytes()))
        })
    })
}

/// Waits until `f` holds, up to ten seconds.
async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    f()
}

fn has_provider(h: &Harness, id: &str) -> bool {
    h.auth
        .oidc()
        .is_some_and(|o| o.providers().iter().any(|(p, _)| p == id))
}

/// The harness with the applier running against the fake issuer.
fn live() -> (Harness, tokio::sync::watch::Sender<bool>) {
    let h = harness("");
    assert!(h.src.oidc_fetch.set(fake_fetch()).is_ok());
    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    crate::auth_setup::run(Arc::clone(&h.src), stop);
    (h, stop_tx)
}

fn data_dir(h: &Harness) -> std::path::PathBuf {
    std::path::PathBuf::from(h.src.file_config.load().node.data_dir.as_str())
}

/// REQ: API-016 (T23.10) — a provider `PUT` through the API is served on this node without a
/// restart, `GET` lists it with its source and status, and `DELETE` takes it away and ends the
/// sessions it opened.
#[tokio::test]
async fn api_016_oidc_put_applies_live_and_delete_ends_sessions() {
    let (h, _stop) = live();
    let (s, _, out) = h
        .call(
            "PUT",
            &format!("{PROVIDERS}/lab"),
            Some(&body("https://idp.test")),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    assert!(
        eventually(|| has_provider(&h, "lab")).await,
        "the provider applied without a restart"
    );
    let (s, _, list) = h.call("GET", PROVIDERS, None).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    let lab = list["items"]
        .as_array()
        .and_then(|a| a.iter().find(|p| p["id"] == "lab"))
        .expect("listed")
        .clone();
    assert_eq!(lab["source"], "api");
    assert_eq!(lab["active"], true, "{lab}");
    assert_eq!(lab["name"], "Lab SSO");
    assert_eq!(
        lab["redirectUri"],
        "https://dns.example.com/api/v1/auth/oidc/lab/callback"
    );
    // The file's provider is listed too, as the file's, and no secret value is anywhere.
    let kc = list["items"]
        .as_array()
        .and_then(|a| a.iter().find(|p| p["id"] == "kc"))
        .expect("the file provider")
        .clone();
    assert_eq!(kc["source"], "file");
    assert_eq!(kc["secretSource"], "inline");
    assert!(
        !list
            .to_string()
            .contains(crate::credential_tests::CLIENT_SECRET)
    );

    // A session the provider opened.
    let now = crate::pipeline::unix_now();
    let user = h
        .auth
        .create_user(
            "sso-user",
            "another long password",
            Role::Viewer,
            false,
            now,
        )
        .unwrap();
    let ip = "127.0.0.1".parse().unwrap();
    let session = h.auth.start_session(&user, ip, now).unwrap();
    let hash = wrendns_api::auth::crypto::secret_hash(&session.cookie);
    h.auth
        .state()
        .set_session_provider(&hash, "lab", "https://idp.test")
        .unwrap();
    assert!(h.auth.state().session(&hash).unwrap().is_some());

    let (s, _, out) = h.call("DELETE", &format!("{PROVIDERS}/lab"), None).await;
    assert_eq!(s, StatusCode::OK, "{out}");
    assert!(
        eventually(|| !has_provider(&h, "lab")).await,
        "the provider is gone without a restart"
    );
    assert!(
        eventually(|| h.auth.state().session(&hash).unwrap().is_none()).await,
        "the removed provider's session ended"
    );
}

/// REQ: API-016 (T23.10, ADR-040) — a provider the files define is read-only through the API, and
/// the files' ID wins when a node-managed entry has the same one.
#[tokio::test]
async fn api_016_oidc_file_provider_wins() {
    let h = harness("");
    let (s, _, out) = h
        .call(
            "PUT",
            &format!("{PROVIDERS}/kc"),
            Some(&body("https://idp.test")),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{out}");
    assert_eq!(out["code"], "set_by_file");
    let (s, _, _) = h.call("DELETE", &format!("{PROVIDERS}/kc"), None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    // Even a row planted for the same ID (say, a blob from a primary that didn't have the file)
    // doesn't replace the file's provider.
    h.auth
        .state()
        .put_managed(
            OIDC_PROVIDER,
            "kc",
            &json!({"id": "kc", "issuer": "https://evil.example", "client_id": "x"}).to_string(),
            None,
            None,
            1,
            "test",
        )
        .unwrap();
    let cfg = crate::managed::effective(&h.src.file_config.load());
    assert_eq!(cfg.auth.oidc.managed_provider.len(), 0);
    assert_eq!(
        cfg.auth.oidc.provider[0].issuer.as_str(),
        "https://kc.example/realms/home"
    );
}

/// REQ: API-016 (T23.10, ADR-967) — admins only: an operator is refused with 403 on the write and
/// the read, an agent token never, and a secret or file path in the body is 422.
#[tokio::test]
async fn api_016_oidc_provider_admin_only_and_references_only() {
    let h = harness("");
    let op = token(&h, "ops", Role::Operator, None);
    for (m, uri, b) in [
        (
            "PUT",
            format!("{PROVIDERS}/lab"),
            Some(body("https://idp.test")),
        ),
        ("GET", PROVIDERS.to_owned(), None),
    ] {
        let (s, _, out) = call_as(&h, &op, m, &uri, b.as_ref(), &[]).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{m} {out}");
    }
    let agent = token(
        &h,
        "bot",
        Role::Admin,
        Some("config:read config:write:upstreams"),
    );
    let (s, _, _) = call_as(&h, &agent, "GET", PROVIDERS, None, &[]).await;
    assert_ne!(s, StatusCode::OK, "an agent never reads the providers");
    let (s, _, _) = call_as(
        &h,
        &agent,
        "PUT",
        &format!("{PROVIDERS}/lab"),
        Some(&body("https://idp.test")),
        &[],
    )
    .await;
    assert_ne!(s, StatusCode::OK, "an agent never writes one");
    assert_eq!(h.auth.state().managed(OIDC_PROVIDER).unwrap().len(), 0);
    for field in ["client_secret", "client_secret_file"] {
        let mut b = body("https://idp.test");
        b[field] = "planted-secret-value".into();
        let (s, _, out) = h.call("PUT", &format!("{PROVIDERS}/lab"), Some(&b)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{field}: {out}");
        assert!(!out.to_string().contains("planted-secret-value"));
    }
    // A reference to a secret nobody stored is refused; once stored, it's accepted.
    let mut b = body("https://idp.test");
    b["client_secret_ref"] = "oidc.lab".into();
    let (s, _, out) = h.call("PUT", &format!("{PROVIDERS}/lab"), Some(&b)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{out}");
    assert_eq!(out["code"], "secret_missing");
    h.src
        .secrets
        .put(
            "oidc.lab",
            Kind::Text,
            &crate::secrets::SecretValue::new(
                Kind::Text,
                zeroize::Zeroizing::new("s3cret-lab".to_owned()),
            )
            .unwrap(),
            0,
            "root",
            "local",
            1,
        )
        .unwrap();
    let (s, _, out) = h.call("PUT", &format!("{PROVIDERS}/lab"), Some(&b)).await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let (_, _, list) = h.call("GET", PROVIDERS, None).await;
    let lab = list["items"]
        .as_array()
        .and_then(|a| a.iter().find(|p| p["id"] == "lab"))
        .expect("listed");
    assert_eq!(lab["secretSource"], "stored");
    assert_eq!(lab["secret"], "oidc.lab");
    assert_eq!(lab["secretReadable"], true);
    assert!(!list.to_string().contains("s3cret-lab"));
}

/// A node directory that follows a primary: this node's identity as `role`, the version it last
/// applied (the shared part of `cfg` and the node-managed `blob`), and the config file's settings.
fn follow(h: &Harness, role: NodeRole, blob: Option<&[u8]>) -> Config {
    let dir = data_dir(h);
    let file: Config = (**h.src.file_config.load()).clone();
    let mut id = Identity::init(&dir, "home", vec!["https://127.0.0.1:1".into()], "k8s").unwrap();
    id.save_role(role, 1).unwrap();
    let shared = serde_json::to_vec(&wrendns_config::shared::shared_part(&file)).unwrap();
    let store = BlobStore::open(&dir).unwrap();
    let config = blob_ref("config.json", &shared);
    store.put(&config, &shared).unwrap();
    let node_managed = blob.map(|b| {
        let r = blob_ref(crate::node_managed::BLOB, b);
        store.put(&r, b).unwrap();
        r
    });
    let m = ClusterManifest {
        cluster_id: "c".into(),
        epoch: 1,
        seq: 3,
        primary: "primary".into(),
        config,
        node_managed,
        ..ClusterManifest::default()
    };
    std::fs::write(
        wrendns_cluster::node::dir_of(&dir).join(crate::replication::APPLIED),
        serde_json::to_vec(&m).unwrap(),
    )
    .unwrap();
    file
}

/// The blob a primary publishes for `rows` (kind, name, stored JSON).
fn blob(rows: &[(&str, Value)]) -> Vec<u8> {
    let rows: Vec<(String, String, String)> = rows
        .iter()
        .map(|(n, b)| (OIDC_PROVIDER.to_owned(), (*n).to_owned(), b.to_string()))
        .collect();
    crate::node_managed::encode(&rows)
}

fn ids(cfg: &Config) -> Vec<String> {
    cfg.auth
        .oidc
        .managed_provider
        .iter()
        .map(|p| p.id.to_string())
        .collect()
}

/// REQ: CLU-015, API-016 (T23.10) — a replica merges the primary's node-managed entries apart from
/// the shared part, and a replica with no blob (an older primary) has none.
#[tokio::test]
async fn clu_015_replica_merges_the_node_managed_blob() {
    let h = harness("");
    let b = blob(&[
        ("sso", body("https://idp.test")),
        ("lab", body("https://lab.test")),
    ]);
    let file = follow(&h, NodeRole::Replica, Some(&b));
    let cfg = crate::replication::effective(&file);
    assert_eq!(ids(&cfg), ["lab", "sso"]);
    // The files' provider is untouched and the replica did not store rows of its own.
    assert_eq!(cfg.auth.oidc.provider.len(), 1);
    assert_eq!(h.auth.state().managed(OIDC_PROVIDER).unwrap().len(), 0);
}

/// REQ: CLU-015 (T23.10, ADR-903 §6) — a replica promoted to primary keeps the node-managed entries
/// it had: it seeds its own rows from the blob it inherited (once), publishes from them, and an
/// entry deleted afterwards does not come back from the stale copy.
#[tokio::test]
async fn clu_015_node_managed_survives_promotion() {
    let h = harness("");
    let b = blob(&[("sso", body("https://idp.test"))]);
    let file = follow(&h, NodeRole::Replica, Some(&b));
    assert_eq!(ids(&crate::replication::effective(&file)), ["sso"]);

    // Promotion: the node is the primary of epoch 2.
    let dir = data_dir(&h);
    let mut id = Identity::load(&dir).unwrap().unwrap();
    id.save_role(NodeRole::Primary, 2).unwrap();
    let cfg = crate::replication::effective(&file);
    assert_eq!(ids(&cfg), ["sso"], "the provider survives the promotion");
    let rows = h.auth.state().managed(OIDC_PROVIDER).unwrap();
    assert_eq!(rows.len(), 1, "seeded as this node's own row");
    assert_eq!(rows[0].name, "sso");
    // What this primary publishes carries it.
    let published = crate::node_managed::export(h.auth.state());
    assert!(String::from_utf8(published).unwrap().contains("\"sso\""));
    // Seeding runs once: a second pass doesn't duplicate or resurrect.
    assert_eq!(ids(&crate::replication::effective(&file)), ["sso"]);
    h.auth
        .state()
        .delete_managed(OIDC_PROVIDER, "sso", None)
        .unwrap();
    assert!(
        ids(&crate::replication::effective(&file)).is_empty(),
        "a deleted entry doesn't come back from the inherited blob"
    );
    let published = crate::node_managed::export(h.auth.state());
    assert!(!String::from_utf8(published).unwrap().contains("\"sso\""));
}

/// REQ: CLU-015 (ADR-968 point 4) — rows left from an earlier time as primary are cleared when the
/// node is a replica, so a provider the cluster removed meanwhile does not come back on a later
/// promotion.
#[tokio::test]
async fn clu_015_stale_rows_cleared_on_replica() {
    let h = harness("");
    let stale = serde_json::to_string(&body("https://old.test")).unwrap();
    h.auth
        .state()
        .put_managed_batch(&[(OIDC_PROVIDER, "corp", stale.as_str())], None, 1, "test")
        .unwrap();
    // The cluster's current blob has no `corp`.
    let b = blob(&[("sso", body("https://idp.test"))]);
    let file = follow(&h, NodeRole::Replica, Some(&b));
    assert_eq!(ids(&crate::replication::effective(&file)), ["sso"]);
    assert_eq!(h.auth.state().managed(OIDC_PROVIDER).unwrap().len(), 0);
    // Promoted again: seeded from the blob alone.
    let dir = data_dir(&h);
    let mut id = Identity::load(&dir).unwrap().unwrap();
    id.save_role(NodeRole::Primary, 3).unwrap();
    assert_eq!(ids(&crate::replication::effective(&file)), ["sso"]);
    let rows = h.auth.state().managed(OIDC_PROVIDER).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "sso");
}

/// REQ: CLU-004 (T23.10) — a bad node-managed blob drops only those entries: the shared part of the
/// version still applies, and so does a good blob with one bad entry (the good ones stay).
#[tokio::test]
async fn clu_004_bad_node_managed_keeps_shared_part() {
    let h = harness("");
    let file = follow(&h, NodeRole::Replica, Some(b"{ this is not json"));
    let cfg = crate::replication::effective(&file);
    assert!(ids(&cfg).is_empty(), "the bad blob is dropped");
    assert_eq!(
        cfg.upstream.len(),
        file.upstream.len(),
        "the shared part applied: {:?}",
        cfg.upstream
    );
    assert_ne!(cfg.upstream.len(), 0);
    // One bad entry beside a good one.
    let mixed = serde_json::to_vec(&json!({
        "version": 1,
        "entries": [
            {"kind": "oidc_provider", "name": "good", "body": body("https://idp.test")},
            {"kind": "oidc_provider", "name": "bad", "body": {"client_id": "x"}},
        ],
    }))
    .unwrap();
    let file = follow_again(&h, &mixed);
    let cfg = crate::replication::effective(&file);
    assert_eq!(ids(&cfg), ["good"]);
    assert_ne!(cfg.upstream.len(), 0);
}

/// Replaces the applied version's node-managed blob.
fn follow_again(h: &Harness, blob: &[u8]) -> Config {
    let dir = data_dir(h);
    let path = wrendns_cluster::node::dir_of(&dir).join(crate::replication::APPLIED);
    let mut m: ClusterManifest = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let r = blob_ref(crate::node_managed::BLOB, blob);
    BlobStore::open(&dir).unwrap().put(&r, blob).unwrap();
    m.node_managed = Some(r);
    std::fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
    (**h.src.file_config.load()).clone()
}

/// REQ: API-016 (T23.10, ADR-903 §3, §6) — a provider that arrived in the node-managed blob uses
/// the client secret that was replicated to this node's store, and a node with no `public_url`
/// shows it as inactive instead of failing the configuration.
#[tokio::test]
async fn api_016_oidc_on_replica_uses_replicated_secret() {
    let h = harness("");
    let mut b = body("https://idp.test");
    b["client_secret_ref"] = "oidc.sso".into();
    let blob = blob(&[("sso", b)]);
    let file = follow(&h, NodeRole::Replica, Some(&blob));
    // The secret the primary replicated: stored here as a cluster row.
    h.src
        .secrets
        .put(
            "oidc.sso",
            Kind::Text,
            &crate::secrets::SecretValue::new(
                Kind::Text,
                zeroize::Zeroizing::new("replicated-client-secret".to_owned()),
            )
            .unwrap(),
            1,
            "primary",
            "cluster",
            1,
        )
        .unwrap();
    let cfg = crate::replication::effective(&file);
    let (settings, skipped) = crate::auth_setup::oidc_inputs(&cfg, &h.src.secrets);
    let sso = settings
        .providers
        .iter()
        .find(|p| p.id == "sso")
        .expect("the provider is served here");
    assert_eq!(
        sso.client_secret.as_deref(),
        Some("replicated-client-secret")
    );
    assert!(skipped.iter().all(|s| s.id != "sso"));
    // A node whose file has no public_url: every provider is inactive, nothing fails.
    let mut bare = cfg.clone();
    bare.auth.oidc.public_url = wrendns_config::SafeString::default();
    let (settings, skipped) = crate::auth_setup::oidc_inputs(&bare, &h.src.secrets);
    assert_eq!(settings.providers.len(), 0);
    let why = skipped
        .iter()
        .find(|s| s.id == "sso")
        .and_then(|s| s.reason.clone())
        .unwrap_or_default();
    assert!(why.contains("public_url"), "{why}");
    // A reference whose secret this node doesn't hold leaves that provider out alone.
    let mut missing = cfg.clone();
    if let Some(p) = missing.auth.oidc.managed_provider.first_mut() {
        p.client_secret_ref = wrendns_config::SafeString::new("oidc.nobody").ok();
    }
    let (settings, skipped) = crate::auth_setup::oidc_inputs(&missing, &h.src.secrets);
    assert!(settings.providers.iter().all(|p| p.id != "sso"));
    assert!(skipped.iter().any(|s| s.id == "sso" && !s.active));
    assert!(
        settings.providers.iter().any(|p| p.id == "kc"),
        "the file's provider is unaffected"
    );
}

/// REQ: CLU-015 (T24.37, ADR-1016), DNS-006, OPS-011, OPS-012, DNS-011, FLT-004, CLU-014 (T27.2,
/// T27.11, ADR-1006), OBS-016, OBS-020, OBS-019, OBS-013, OBS-003, OBS-005, DNS-010 (T27.5, T27.7,
/// ADR-1007) — every settings kind the API stores is in exactly one class: node-managed (per node or
/// node-local) or shared (carried whole so a promoted replica adopts it).
#[test]
fn clu_015_every_settings_kind_is_classified_once() {
    use crate::managed as m;
    use crate::node_managed::{KINDS, SHARED_KINDS};
    let node = [
        m::CACHE,
        m::SUPPORT,
        m::UPDATES,
        m::ANOMALY_SETTINGS,
        m::QLOG_SETTINGS,
        m::METRICS_SETTINGS,
    ];
    let shared = [
        m::DNSSEC,
        m::FILTER,
        m::DRILL,
        m::ZONE,
        m::SLO,
        m::PROBE,
        m::UPSTREAM_CHECK,
    ];
    for k in node {
        assert!(
            KINDS.contains(&k) && !SHARED_KINDS.contains(&k),
            "{k} is node-managed"
        );
    }
    for k in shared {
        assert!(
            SHARED_KINDS.contains(&k) && !KINDS.contains(&k),
            "{k} is shared"
        );
    }
    for k in KINDS {
        assert!(!SHARED_KINDS.contains(k), "{k} is in both classes");
    }
}

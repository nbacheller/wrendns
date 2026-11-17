//! REQ: OPS-014 (T23.3, ADR-903 §2–3) — the secrets store through a running node's API: a locked
//! store refuses secret writes (503) and degrades health while DNS answers and `/readyz` stays as
//! it was; a credential the files set wins over a reference, and the API can't replace it; a
//! reference must name a stored secret; and one pointed at another kind's secret is audited.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::credential_tests::{HEADER, Harness, harness};
use crate::secrets::store::{StoreError, StoreState};
use crate::secrets::value::Kind;

fn value(v: &str) -> crate::secrets::SecretValue {
    crate::secrets::SecretValue::new(Kind::Text, zeroize::Zeroizing::new(v.to_owned())).unwrap()
}

/// `/readyz` through the metrics listener's router, from loopback.
async fn readyz(h: &Harness) -> u16 {
    let req = Request::builder()
        .uri("/readyz")
        .extension(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            40002,
        ))))
        .body(Body::empty())
        .unwrap();
    crate::http::router(Arc::clone(&h.src))
        .oneshot(req)
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// REQ: OPS-014, CLU-004 (AC3) — `[node] secrets_key_file` names a key that can't be read: the
/// store is locked; a secret write gets 503 `secrets_locked` (and so does a retry-keyed write of
/// a credential); health is degraded with `secrets_locked`; and in the same test DNS answers and
/// `/readyz` is unchanged.
#[tokio::test]
async fn ops_014_configured_key_unreadable_locks_store() {
    let h = harness(
        "[node]\nsecrets_key_file = \"/nonexistent/telltale/secrets.key\"\n[[record]]\nname = \"nas.home\"\ntype = \"A\"\nvalue = \"192.168.1.5\"\n",
    );
    let ready_before = readyz(&h).await;
    let cfg = h.src.config.load_full();
    h.src.secrets.configure(&cfg);
    assert!(h.src.secrets.keys().is_err());
    let st = h.src.secrets.status();
    assert_eq!(st.state, StoreState::Locked);
    assert!(
        st.reason
            .unwrap()
            .contains("/nonexistent/telltale/secrets.key")
    );
    let err = h
        .src
        .secrets
        .put("unifi", Kind::Text, &value("k"), 0, "root", "local", 1)
        .unwrap_err();
    assert!(matches!(err, StoreError::Locked(_)));
    let p = err.problem();
    assert_eq!(
        (p.status, p.code),
        (503, telltale_api::problem::Code::SecretsLocked)
    );
    let mut r = h.request(
        "PUT",
        "/api/v1/upstreams/nextdns",
        Some(
            &json!({"url": "https://doh.example/dns-query", "headers": {"Authorization": HEADER}}),
        ),
    );
    r.headers_mut()
        .insert("idempotency-key", "locked-1".parse().unwrap());
    let (s, _, body) = h.send(r).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("secrets_locked"), "{body}");
    let (s, _, health) = h.call("GET", "/api/v1/system/health", None).await;
    assert_eq!(s, StatusCode::OK, "{health}");
    assert_eq!(health["level"], "degraded", "{health}");
    assert!(
        health["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["code"] == "secrets_locked"),
        "{health}"
    );
    // DNS answers through this node's own pipeline (the one its listeners use, beside the locked
    // store), and readiness didn't move.
    let (local, _) = telltale_policy::LocalData::from_config(&cfg);
    h.src.pipeline.reload(
        Arc::new(telltale_upstream::Router::from_config(&cfg).unwrap_or_default()),
        crate::pipeline::Policy::from_config(&cfg, local),
    );
    assert_eq!(h.src.secrets.status().state, StoreState::Locked);
    assert!(crate::pipeline::tests_support::answer(
        &h.src.pipeline,
        "nas.home",
        "192.168.1.30"
    ));
    assert_eq!(readyz(&h).await, ready_before);
    assert_eq!(ready_before, 200);
}

/// A node whose files define the alert destination `filed` with a token file, and a stored
/// secret `ntfy` (a router uses `unifi`).
fn filed() -> (Harness, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap().to_owned();
    std::fs::write(dir.path().join("ntfy-token"), "tk_file\n").unwrap();
    let h = harness(&format!(
        r#"[node]
secret_file_dirs = ["{d}"]
[[alerts.destination]]
name = "filed"
type = "ntfy"
url = "https://ntfy.sh/filed"
token_file = "{d}/ntfy-token"
[[router]]
name = "unifi"
type = "unifi"
url = "https://192.168.1.1"
api_key_ref = "unifi"
"#
    ));
    for (n, v) in [("ntfy", "tk_stored"), ("unifi", "uk-planted-77")] {
        h.src
            .secrets
            .put(n, Kind::Text, &value(v), 0, "root", "local", 1)
            .unwrap();
    }
    (h, dir)
}

fn effective(h: &Harness, name: &str) -> telltale_config::AlertDestination {
    h.src
        .config
        .load()
        .alerts
        .destination
        .iter()
        .find(|d| d.name.as_str() == name)
        .cloned()
        .unwrap()
}

/// REQ: OPS-014 (AC8, decision 4) — the files' credential wins: an override stored with a
/// reference before the files set a token file merges with the file's token and no reference,
/// and the one place that reads credentials takes the file first.
#[tokio::test]
async fn ops_014_file_wins_over_ref() {
    let (h, dir) = filed();
    // Stored before the files set `token_file` (written straight to the table).
    h.auth
        .state()
        .put_managed(
            "alert_destination",
            "filed",
            &json!({"name": "filed", "type": "ntfy", "url": "https://ntfy.sh/filed", "token_ref": "ntfy"}).to_string(),
            None,
            None,
            1,
            "root",
        )
        .unwrap();
    let e = crate::managed::entries(h.auth.state());
    let merged = crate::managed::merge(&h.src.file_config.load(), &e).unwrap();
    let d = merged
        .alerts
        .destination
        .iter()
        .find(|d| d.name.as_str() == "filed")
        .unwrap();
    assert_eq!(
        (d.token_file.as_deref(), d.token_ref.as_deref()),
        (Some(dir.path().join("ntfy-token").to_str().unwrap()), None)
    );
    // Both given to the reader: the file's value.
    let r = crate::secrets::Credential::of(
        Some(
            &telltale_config::SafeString::new(dir.path().join("ntfy-token").to_str().unwrap())
                .unwrap(),
        ),
        Some(&telltale_config::SafeString::new("ntfy").unwrap()),
    )
    .resolve(Some(&h.src.secrets))
    .unwrap()
    .unwrap();
    assert_eq!(
        (r.value.expose(), r.source),
        ("tk_file", crate::secrets::Source::File)
    );
}

/// REQ: OPS-014 (AC8, ADR-903 §2 rule 1) — an override of a destination whose token the files
/// set can't set a reference, another file or none for it (409 `set_by_file`), nor hide the
/// destination; one that changes other fields keeps the files' token. A reference must name a
/// stored secret (422 `secret_missing`), and one pointed at a secret a router uses is audited as
/// `credential.redirect`.
#[tokio::test]
#[allow(clippy::many_single_char_names)] // status, body, entry, as in the other API tests
async fn ops_014_override_cannot_replace_file_credential() {
    let (h, dir) = filed();
    let token_file = dir.path().join("ntfy-token").to_str().unwrap().to_owned();
    let uri = "/api/v1/alerts/destinations/filed";
    for body in [
        json!({"type": "ntfy", "url": "https://ntfy.sh/filed", "token_ref": "ntfy"}),
        json!({"type": "ntfy", "url": "https://ntfy.sh/filed", "token_file": format!("{token_file}.2")}),
        json!({"type": "ntfy", "url": "https://ntfy.sh/filed", "token_file": token_file, "token_ref": "ntfy"}),
    ] {
        let (s, _, v) = h.call("PUT", uri, Some(&body)).await;
        assert_eq!(s, StatusCode::CONFLICT, "{body} {v}");
        assert_eq!(v["code"], "set_by_file", "{v}");
    }
    // Other fields: the token file is carried over.
    let (s, _, v) = h
        .call(
            "PUT",
            uri,
            Some(&json!({"type": "ntfy", "url": "https://ntfy.sh/filed"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let d = effective(&h, "filed");
    assert_eq!(
        (d.token_file.as_deref(), d.token_ref.as_deref()),
        (Some(token_file.as_str()), None)
    );
    // Reverting the override is fine; hiding the files' destination isn't.
    let (s, _, v) = h.call("DELETE", uri, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = h.call("DELETE", uri, None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "set_by_file", "{v}");

    // A destination of the API's own: the reference must name a stored secret.
    let own = "/api/v1/alerts/destinations/phone";
    let (s, _, v) = h
        .call(
            "PUT",
            own,
            Some(&json!({"type": "ntfy", "url": "https://ntfy.sh/phone", "token_ref": "nope"})),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["code"], "secret_missing", "{v}");
    let (s, _, v) = h
        .call(
            "PUT",
            own,
            Some(&json!({"type": "ntfy", "url": "https://ntfy.sh/phone", "token_ref": "ntfy"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(effective(&h, "phone").token_ref.as_deref(), Some("ntfy"));
    let redirects = || {
        h.auth
            .state()
            .audit_page(
                None,
                50,
                Some(crate::credential_rules::REDIRECT_ACTION),
                None,
            )
            .unwrap()
    };
    assert!(redirects().is_empty(), "nothing else uses `ntfy`");
    // Pointed at the router's secret: audited, without a value.
    let (s, _, v) = h
        .call(
            "PUT",
            own,
            Some(&json!({"type": "ntfy", "url": "https://ntfy.sh/phone", "token_ref": "unifi"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let r = redirects();
    assert_eq!(r.len(), 1, "{r:?}");
    let detail: Value = serde_json::from_str(&r[0].detail).unwrap();
    assert_eq!(
        (&detail["field"], &detail["to"], &detail["secretUsedBy"]),
        (&json!("token_ref"), &json!("unifi"), &json!(["router"]))
    );
    assert!(!r[0].detail.contains("uk-planted-77"), "{}", r[0].detail);
}

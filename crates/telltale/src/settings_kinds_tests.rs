//! REQ: DNS-019 (T24.12), DNS-023 (T24.13, ADR-914, ADR-918) — the settings kinds through the
//! real write path (the route, `plan_settings`, the reload): the admin-only fields are refused
//! for an operator and an agent over HTTP, a PUT applies through the reload, a DELETE brings the
//! files' values back, a dry run and an `Idempotency-Key` replay behave as on every write, and a
//! primary too old to read the kinds is refused before anything is forwarded.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use telltale_api::auth;
use tower::ServiceExt as _;

use crate::credential_tests::{Harness, harness, harness_in, older_primary_and_replica};

const SPECIAL: &str = "/api/v1/special-names/default";
const CLIENTS: &str = "/api/v1/clients-settings/default";

/// A token for a new user of `role`; with `agent_scopes`, an agent token owned by that user.
pub(crate) fn token(
    h: &Harness,
    user: &str,
    role: auth::Role,
    agent_scopes: Option<&str>,
) -> String {
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

/// Sends `method uri` with `bearer` (an agent must give a reason, AGT-005) and `extra` headers;
/// the status, the response headers, and the JSON body.
pub(crate) async fn call_as(
    h: &Harness,
    bearer: &str,
    method: &str,
    uri: &str,
    body: Option<&Value>,
    extra: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .header("x-telltale-reason", "settings kinds test")
        .extension(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            40002,
        ))));
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    let req: Request<Body> = b
        .body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    let v = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, headers, v)
}

/// REQ: DNS-019 (T24.12, ADR-914) — an operator can't move `ddr_name`: its PUT, its dry run, and
/// its DELETE (which would switch it off) are 403 naming the field, and nothing changes. An
/// operator's change that leaves `ddr_name` alone is allowed.
#[tokio::test]
async fn dns_019_operator_put_and_delete_cannot_move_ddr_name() {
    let h = harness("");
    let op = token(&h, "olive", auth::Role::Operator, None);
    let set = json!({ "ddr_name": "dns.home.arpa" });
    let (s, _, v) = call_as(&h, &op, "PUT", SPECIAL, Some(&set), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "forbidden", "{v}");
    assert!(v["detail"].as_str().unwrap().contains("ddr_name"), "{v}");
    let dry = format!("{SPECIAL}?dryRun=true");
    let (s, _, _) = call_as(&h, &op, "PUT", &dry, Some(&set), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "not even as a dry run");
    assert!(h.src.config.load().special.ddr_name.is_none());
    let body = json!({ "localhost": false });
    let (s, _, v) = call_as(&h, &op, "PUT", SPECIAL, Some(&body), &[]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The admin sets it. An operator's DELETE would switch it off, so it is refused too.
    let (s, _, v) = h.call("PUT", SPECIAL, Some(&set)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(h.src.config.load().special.ddr_name.is_some());
    let (s, _, v) = call_as(&h, &op, "DELETE", SPECIAL, None, &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(v["detail"].as_str().unwrap().contains("ddr_name"), "{v}");
    assert!(h.src.config.load().special.ddr_name.is_some(), "kept");
}

/// REQ: DNS-023 (T24.13, ADR-914) — an operator can't turn `[clients] mdns` on, through the route
/// or a dry run. The admin's dry run says it takes a restart, and changes nothing.
#[tokio::test]
async fn dns_023_operator_put_on_clients_settings_is_refused() {
    let h = harness("");
    let op = token(&h, "olive", auth::Role::Operator, None);
    let on = json!({ "mdns": true });
    let (s, _, v) = call_as(&h, &op, "PUT", CLIENTS, Some(&on), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(v["detail"].as_str().unwrap().contains("mdns"), "{v}");
    let dry = format!("{CLIENTS}?dryRun=true");
    let (s, _, _) = call_as(&h, &op, "PUT", &dry, Some(&on), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(!h.src.config.load().clients.mdns);
    // REQ: DNS-023 (H1) — an admin's change is a restart's: the dry run warns about it.
    let (s, _, v) = h.call("PUT", &dry, Some(&on)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["warnings"].to_string().contains("restart"), "{v}");
    assert!(
        !h.src.config.load().clients.mdns,
        "a dry run changes nothing"
    );
}

/// REQ: DNS-019, DNS-023 (M5, ADR-914) — an agent with the scope can't set `ddr_name` (403
/// `agent_not_allowed`), and no agent reaches `[clients]`, however it is scoped.
#[tokio::test]
async fn dns_019_agent_cannot_set_ddr_name_or_clients() {
    let h = harness("");
    let bot = token(
        &h,
        "bot-owner",
        auth::Role::Admin,
        Some("config:read config:write:special"),
    );
    let set = json!({ "ddr_name": "dns.home.arpa" });
    let (s, _, v) = call_as(&h, &bot, "PUT", SPECIAL, Some(&set), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "agent_not_allowed", "{v}");
    let dry = format!("{SPECIAL}?dryRun=true");
    let (s, _, v) = call_as(&h, &bot, "PUT", &dry, Some(&set), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "agent_not_allowed", "{v}");
    assert!(h.src.config.load().special.ddr_name.is_none());
    let clients = token(
        &h,
        "bot-clients",
        auth::Role::Admin,
        Some("config:read config:write:clients"),
    );
    let on = json!({ "mdns": true });
    let (s, _, v) = call_as(&h, &clients, "PUT", CLIENTS, Some(&on), &[]).await;
    // No agent scope reaches this route at all (the route refuses agent tokens).
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(v["detail"].as_str().unwrap().contains("agent"), "{v}");
    assert!(!h.src.config.load().clients.mdns);
}

/// REQ: DNS-019 (T24.12) — a PUT applies through the reload: `src.config` changes with no
/// restart. The file's `single_label_nxdomain` wins: a body that sets it is 409 `set_by_file`,
/// and a body that leaves it out keeps it. A DELETE brings the file's values back.
#[tokio::test]
async fn dns_019_put_applies_through_the_reload_and_delete_restores_the_file() {
    let h = harness("[special]\nsingle_label_nxdomain = true\n");
    let file = h.src.file_config.load().special.clone();
    let (s, _, v) = h
        .call(
            "PUT",
            SPECIAL,
            Some(&json!({ "single_label_nxdomain": false })),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "set_by_file", "{v}");
    let (s, _, v) = h
        .call("PUT", SPECIAL, Some(&json!({ "localhost": false })))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let applied = h.src.config.load().special.clone();
    assert!(!applied.localhost, "the reload applied the PUT");
    assert!(applied.single_label_nxdomain, "the file's value is kept");
    let (s, _, v) = h.call("DELETE", SPECIAL, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let back = h.src.config.load().special.clone();
    assert_eq!(
        back.localhost, file.localhost,
        "the file's (default) applies again"
    );
    assert!(back.single_label_nxdomain);
}

/// REQ: DNS-023 (M5, API-002) — a dry run leaves the configuration alone; `If-Match` checks the
/// version (a stale one is 412, the current one passes); an `Idempotency-Key` replay returns the
/// first answer, with no second change.
#[tokio::test]
async fn dns_023_dry_run_if_match_and_idempotency_on_settings() {
    let h = harness("");
    let dry = format!("{CLIENTS}?dryRun=true");
    let (s, _, first_dry) = h.call("PUT", &dry, Some(&json!({ "mdns": true }))).await;
    assert_eq!(s, StatusCode::OK, "{first_dry}");
    let version = first_dry["configVersion"]
        .as_u64()
        .expect("a config version");
    assert!(!h.src.config.load().clients.mdns);
    let stale = (version + 100).to_string();
    let (s, _, v) = call_as(
        &h,
        &h.bearer,
        "PUT",
        CLIENTS,
        Some(&json!({ "mdns": false })),
        &[("if-match", &stale)],
    )
    .await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED, "{v}");
    let current = version.to_string();
    let (s, _, v) = call_as(
        &h,
        &h.bearer,
        "PUT",
        &format!("{SPECIAL}?dryRun=true"),
        Some(&json!({ "localhost": false })),
        &[("if-match", &current)],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The same key, twice: the second is the first's answer, replayed.
    let key = [("idempotency-key", "settings-kinds-1")];
    let body = json!({ "localhost": false });
    let (s, _, first) = call_as(&h, &h.bearer, "PUT", SPECIAL, Some(&body), &key).await;
    assert_eq!(s, StatusCode::OK, "{first}");
    let (s, hd, again) = call_as(&h, &h.bearer, "PUT", SPECIAL, Some(&body), &key).await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(hd.get("idempotency-replayed").unwrap(), "true");
    assert_eq!(again, first);
}

/// REQ: DNS-019 (M2, ADR-914) — the set-by-file marks come from the files, not from the
/// configuration in effect: a merged configuration (which doesn't carry `file_set`) still lists
/// the file's field, and a clash is still 409.
#[tokio::test]
async fn dns_019_set_by_file_marks_hold_on_a_merged_configuration() {
    let h = harness("[special]\nsingle_label_nxdomain = true\n");
    let mut merged = (*h.src.config.load_full()).clone();
    merged.file_set.clear();
    h.src.config.store(Arc::new(merged));
    let (_, _, v) = h
        .call("GET", "/api/v1/config/entries?kind=special", None)
        .await;
    let entry = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "default")
        .unwrap();
    assert!(
        entry["setByFile"]
            .to_string()
            .contains("single_label_nxdomain"),
        "{entry}"
    );
    let (s, _, v) = h
        .call(
            "PUT",
            SPECIAL,
            Some(&json!({ "single_label_nxdomain": false })),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
}

/// REQ: DNS-023, CLU-010 (M3, ADR-918) — a primary one version behind can't read the settings
/// kinds: the replica refuses with 409 `upgrade_required` before forwarding. A primary at 0.8.0
/// gets the write.
#[tokio::test(flavor = "multi_thread")]
async fn dns_023_older_primary_is_refused_before_forwarding() {
    let (replica, older) = older_primary_and_replica("0.7.4").await;
    let h = harness_in("", Some(replica));
    let (s, _, v) = h
        .call("PUT", CLIENTS, Some(&json!({ "mdns": false })))
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "upgrade_required", "{v}");
    assert!(v["detail"].as_str().unwrap().contains("0.7.4"), "{v}");
    assert!(
        v["hint"].as_str().unwrap().contains("Upgrade the primary"),
        "{v}"
    );
    assert_eq!(older.got.lock().unwrap().len(), 0, "not forwarded");
    let _ = older.stop.send(true);

    let (replica, current) = older_primary_and_replica("0.8.0").await;
    let h = harness_in("", Some(replica));
    let (s, _, v) = h
        .call("PUT", CLIENTS, Some(&json!({ "mdns": false })))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(current.got.lock().unwrap().len(), 1, "forwarded");
    let _ = current.stop.send(true);
}

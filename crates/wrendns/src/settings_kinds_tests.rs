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
use tower::ServiceExt as _;
use wrendns_api::auth;
use wrendns_config::{Config, Loader};

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
        .header("x-wrendns-reason", "settings kinds test")
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

// ---- REQ: DSC-001 (T25.2, ADR-907, ADR-928) — the network inventory's settings ----

const DISCOVERY: &str = "/api/v1/discovery-settings/default";

/// REQ: DSC-001 (`dsc_001_write_is_admin_only_and_audited`) — an admin's change is checked (a dry run
/// changes nothing) and applied; an operator's is refused (403 naming the field).
#[tokio::test]
async fn dsc_001_write_is_admin_only_and_audited() {
    let h = harness("");
    let op = token(&h, "olive", auth::Role::Operator, None);
    let on = json!({ "enabled": true, "node": null, "worker_memory_mib": 64,
        "subnet": [{ "cidr": "192.168.1.0/24" }] });
    let (s, _, v) = call_as(&h, &op, "PUT", DISCOVERY, Some(&on), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(v["detail"].as_str().unwrap().contains("enabled"), "{v}");
    assert!(!h.src.config.load().discovery.enabled);

    let dry = format!("{DISCOVERY}?dryRun=true");
    let (s, _, v) = h.call("PUT", &dry, Some(&on)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        !h.src.config.load().discovery.enabled,
        "a dry run changes nothing"
    );

    let (s, _, v) = h.call("PUT", DISCOVERY, Some(&on)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = h
        .call("GET", "/api/v1/config/entries?kind=discovery", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"][0]["source"], "override", "{v}");
    assert_eq!(
        v["items"][0]["definition"]["subnet"][0]["cidr"], "192.168.1.0/24",
        "{v}"
    );
    // The admin's write is audited with what changed (ADR-928): the record names the action and
    // carries the section after the change.
    let audit = h.audit_text();
    assert!(audit.contains("discovery.put"), "{audit}");
    assert!(audit.contains("192.168.1.0/24"), "{audit}");
}

/// REQ: DSC-001 (`dsc_001_agents_cannot_write_kind`) — no agent writes the network inventory's
/// settings, whatever its scopes; the auth table refuses the kind (`agent_not_allowed`).
#[tokio::test]
async fn dsc_001_agents_cannot_write_kind() {
    let h = harness("");
    let bot = token(
        &h,
        "bot-owner",
        auth::Role::Admin,
        Some("config:read config:write:special config:write:local"),
    );
    let on = json!({ "enabled": true, "worker_memory_mib": 64 });
    let (s, _, v) = call_as(&h, &bot, "PUT", DISCOVERY, Some(&on), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(!h.src.config.load().discovery.enabled);
}

/// REQ: DSC-001 (`dsc_001_n1_member_refuses_first_write`) — the first write waits while any member
/// runs an older version than the one that knows `[discovery]`, and a member whose version can't be
/// read counts as older.
#[test]
fn dsc_001_n1_member_refuses_first_write() {
    let since = crate::forward::DISCOVERY_SINCE;
    let old = vec![
        ("pi-a".to_owned(), "0.8.0".to_owned()),
        ("pi-b".to_owned(), "0.7.9".to_owned()),
    ];
    let refused =
        crate::settings_kinds::members_too_old(&old, since).expect("an N-1 member refuses");
    assert_eq!(refused.code_status(), StatusCode::CONFLICT);
    assert!(
        refused.detail.contains("pi-b") && !refused.detail.contains("pi-a"),
        "{}",
        refused.detail
    );
    let unknown = vec![("pi-c".to_owned(), "dev".to_owned())];
    assert!(crate::settings_kinds::members_too_old(&unknown, since).is_some());
    // REQ: CLU-005 (T21.6, ADR-948) — a local build's `-dev` version passes; an older one doesn't.
    let local = vec![("pi-a".to_owned(), "0.8.0-dev".to_owned())];
    assert!(crate::settings_kinds::members_too_old(&local, since).is_none());
    let older_local = vec![("pi-b".to_owned(), "0.7.9-dev".to_owned())];
    assert!(crate::settings_kinds::members_too_old(&older_local, since).is_some());
    let current = vec![("pi-a".to_owned(), "0.8.0".to_owned())];
    assert!(crate::settings_kinds::members_too_old(&current, since).is_none());
    let later = vec![("pi-a".to_owned(), "0.8.1-rc.1".to_owned())];
    assert!(crate::settings_kinds::members_too_old(&later, since).is_none());
}

/// REQ: DSC-001 (`dsc_001_current_build_passes_the_gate`, ADR-928) — through the real route and the
/// real build version: a write from a replica to a primary at the release that carries `[discovery]`
/// goes through (a local build reports `<crate version>-dev`, which the gate reads as the crate's
/// version, ADR-948, T21.6), and to a primary at an older release it is refused with 409 and never
/// forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn dsc_001_current_build_passes_the_gate() {
    let body = json!({"enabled": false, "node": null, "worker_memory_mib": 64,
        "subnet": [{ "cidr": "192.168.1.0/24" }] });
    let (replica, current) = older_primary_and_replica(crate::build_info::VERSION).await;
    let h = harness_in("", Some(replica));
    let mut req = h.request("PUT", DISCOVERY, Some(&body));
    req.headers_mut()
        .insert("idempotency-key", "gate-current".parse().unwrap());
    let (s, _, text) = h.send(req).await;
    assert_eq!(s, StatusCode::OK, "{text}");
    assert_eq!(
        current.got.lock().unwrap().len(),
        1,
        "forwarded to the primary"
    );

    let (older_replica, older) = older_primary_and_replica("0.7.4").await;
    let h = harness_in("", Some(older_replica));
    let mut req = h.request("PUT", DISCOVERY, Some(&body));
    req.headers_mut()
        .insert("idempotency-key", "gate-older".parse().unwrap());
    let (s, _, text) = h.send(req).await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    assert!(
        text.contains("members_too_old") || text.contains("upgrade_required"),
        "{text}"
    );
    assert!(older.got.lock().unwrap().is_empty(), "never forwarded");
}

/// REQ: DSC-001 (`dsc_001_file_edit_audited_at_start`) — the file's `[discovery]` is audited at start
/// when it is set, and on a reload that changes it; an unchanged section is not audited again.
#[test]
fn dsc_001_file_edit_audited_at_start() {
    let set = Loader::new()
        .toml_str("t", "[discovery]\nenabled = true\n")
        .load()
        .unwrap()
        .config;
    let unset = Config::default();
    assert!(
        crate::server::discovery_audit_detail(None, &unset).is_none(),
        "unset: nothing to record"
    );
    let at_start = crate::server::discovery_audit_detail(None, &set).expect("start records it");
    assert_eq!(at_start["source"], "file");
    assert_eq!(at_start["discovery"]["enabled"], true);
    assert!(crate::server::discovery_audit_detail(Some(&set.discovery), &set).is_none());
    let changed = crate::server::discovery_audit_detail(Some(&unset.discovery), &set);
    assert!(changed.is_some(), "a reload that turns it on is recorded");
}

const PROBE: &str = "/api/v1/probe-settings/default";
const ANOMALY: &str = "/api/v1/anomaly-settings/default";
const QLOG: &str = "/api/v1/qlog-settings/default";
const SLO_SETTINGS: &str = "/api/v1/slo-settings/default";

/// REQ: OBS-020 (T27.5, ADR-1007) — the listener checks' settings apply through the reload: the
/// interval the next round uses changes, the files' fields hold, and a DELETE brings the file back.
#[tokio::test]
async fn obs_020_probe_settings_apply_on_reload() {
    let h = harness("[probe]\ncert_warn_days = 21\n");
    let (s, _, v) = h
        .call(
            "PUT",
            PROBE,
            Some(&json!({ "enabled": true, "interval_secs": 60, "timeout_ms": 2000, "targets": [], "cert_warn_days": 5 })),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "set_by_file", "{v}");
    let (s, _, v) = h
        .call("PUT", PROBE, Some(&json!({ "interval_secs": 60 })))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let applied = h.src.config.load().probe.clone();
    assert_eq!(applied.interval_secs, 60, "the reload applied the PUT");
    assert_eq!(applied.cert_warn_days, 21, "the file's value is kept");
    let (s, _, v) = h.call("DELETE", PROBE, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        h.src.config.load().probe.interval_secs,
        30,
        "the default applies again"
    );
}

/// REQ: OBS-013 (T27.5, ADR-1007) — anomaly settings are node-managed and admin-only: an operator
/// and an agent are refused (403), an admin's change applies on the node through the reload.
#[tokio::test]
async fn obs_013_anomaly_settings_node_managed() {
    let h = harness("");
    let op = token(&h, "olive", auth::Role::Operator, None);
    let (s, _, v) = call_as(
        &h,
        &op,
        "PUT",
        ANOMALY,
        Some(&json!({ "learning_days": 3 })),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let agent = token(&h, "agent-owner", auth::Role::Admin, Some("config:read"));
    let (s, _, v) = call_as(
        &h,
        &agent,
        "PUT",
        ANOMALY,
        Some(&json!({ "learning_days": 3 })),
        &[("x-agent-reason", "tuning")],
    )
    .await;
    assert_ne!(s, StatusCode::OK, "an agent never changes the kind: {v}");
    let (s, _, v) = h
        .call(
            "PUT",
            ANOMALY,
            Some(&json!({ "learning_days": 3, "max_clients": 256 })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let applied = h.src.config.load().telemetry.anomaly.clone();
    assert_eq!(applied.learning_days, 3);
    assert_eq!(applied.max_clients, 256);
    let (s, _, v) = h.call("DELETE", ANOMALY, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(h.src.config.load().telemetry.anomaly.learning_days, 7);
}

/// REQ: OBS-003 (T27.5, ADR-1007) — the query log's settings are admin-only, privacy included: an
/// operator's change of the privacy level is 403 (the whole kind is an admin's); an admin's change
/// of the retention applies on the next reload.
#[tokio::test]
async fn obs_003_qlog_retention_node_managed() {
    let h = harness("");
    let op = token(&h, "olive", auth::Role::Operator, None);
    let (s, _, v) = call_as(
        &h,
        &op,
        "PUT",
        QLOG,
        Some(&json!({ "privacy_level": 2, "retention_days": 30 })),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, _, v) = h
        .call(
            "PUT",
            QLOG,
            Some(&json!({ "retention_days": 7, "privacy_level": 1 })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let applied = h.src.config.load().telemetry.qlog.clone();
    assert_eq!(applied.retention_days, 7);
    assert_eq!(applied.privacy_level, 1);
    // An unknown field is refused with its name, not silently dropped.
    let (s, _, v) = h.call("PUT", QLOG, Some(&json!({ "retention": 7 }))).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
}

/// REQ: OBS-016 (T27.5, ADR-1007) — the objectives are an operator's setting, and a window out of
/// range is refused by the configuration's own rules (the error names the field).
#[tokio::test]
async fn obs_016_slo_settings_operator_and_bounds() {
    let h = harness("");
    let op = token(&h, "olive", auth::Role::Operator, None);
    let (s, _, v) = call_as(
        &h,
        &op,
        "PUT",
        SLO_SETTINGS,
        Some(&json!({ "window_days": 14 })),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(h.src.config.load().slo.window_days, 14);
    let (s, _, v) = h
        .call("PUT", SLO_SETTINGS, Some(&json!({ "window_days": 0 })))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v.to_string().contains("window"), "{v}");
}

/// REQ: DNS-014, DSC-908 (T27.14h) - the `access` kind is gated by the feature every member
/// announces, not by a version number: a primary that carries the same number as this build but
/// announces no features (a development build of 1.1.0) is refused before forwarding (409
/// `upgrade_required`, naming the node), nothing is sent; a primary that announces it gets the write.
#[tokio::test(flavor = "multi_thread")]
async fn dns_014_primary_without_the_access_feature_is_refused_before_forwarding() {
    let url = "/api/v1/access-settings/default";
    let body = json!({ "allowed_networks": ["127.0.0.0/8"] });
    let (replica, older) = crate::credential_tests::older_primary_and_replica_features(
        "1.1.0-edge.40",
        Some(Vec::new()),
        None,
    )
    .await;
    let h = harness_in("", Some(replica));
    let (s, _, v) = h.call("PUT", url, Some(&body)).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "upgrade_required", "{v}");
    assert!(
        v["detail"].as_str().unwrap().contains("1.1.0-edge.40"),
        "{v}"
    );
    assert_eq!(older.got.lock().unwrap().len(), 0, "not forwarded");
    let _ = older.stop.send(true);

    let (replica, current) = older_primary_and_replica("1.1.0").await;
    let h = harness_in("", Some(replica));
    let (s, _, v) = h.call("PUT", url, Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The primary judges the write twice: the dry run that the lockout check reads, then the write.
    assert_eq!(current.got.lock().unwrap().len(), 2, "forwarded");
    let _ = current.stop.send(true);
}

/// REQ: DNS-014, DSC-908 (T27.14h) - where the write is applied: a primary with a member that
/// does not announce the `access` kind refuses the write (409 `upgrade_required`, dry run too,
/// naming the member), stores nothing and leaves the list in force; a DELETE is not held; with
/// every member announcing it, the write goes through.
#[tokio::test(flavor = "multi_thread")]
async fn dns_014_access_write_waits_for_every_members_build() {
    let url = "/api/v1/access-settings/default";
    let body = json!({ "allowed_networks": ["127.0.0.0/8"] });
    let (replica, old) = crate::credential_tests::older_primary_and_replica_features(
        "1.1.0",
        None,
        Some(Vec::new()),
    )
    .await;
    let member = replica.identity.meta.node_id.clone();
    let h = harness_in("", Some(Arc::clone(&old.primary)));
    for dry in [true, false] {
        let target = if dry {
            format!("{url}?dryRun=true")
        } else {
            url.to_owned()
        };
        let (s, _, v) = h.call("PUT", &target, Some(&body)).await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert_eq!(v["code"], "upgrade_required", "{v}");
        let detail = v["detail"].as_str().unwrap();
        assert!(detail.contains("allowed networks"), "{v}");
        assert!(
            detail.contains(&member),
            "the refusal names the member: {v}"
        );
    }
    // A DELETE is not held: nothing is stored, so it answers 404, not 409 upgrade_required.
    let (s, _, v) = h.call("DELETE", url, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    assert_ne!(v["code"], "upgrade_required", "{v}");
    assert_eq!(
        h.auth.state().managed("access").unwrap().len(),
        0,
        "nothing stored"
    );
    let _ = old.stop.send(true);

    let (_replica, new) = older_primary_and_replica("1.1.0").await;
    let h = harness_in("", Some(Arc::clone(&new.primary)));
    let (s, _, v) = h.call("PUT", url, Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(h.auth.state().managed("access").unwrap().len(), 1);
    let _ = new.stop.send(true);
}

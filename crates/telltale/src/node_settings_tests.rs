//! REQ: DNS-006, OPS-011, OPS-012, DNS-011, FLT-004, CLU-014 (T27.2, T27.11, ADR-1006) - the
//! per-node sections (`[cache]`, `[support]`, `[updates]`) and the shared singletons (`[dnssec]`,
//! `[filter]`, `[drill]`) written through the real path: route, plan, store, reload. Admins only;
//! agents are refused; the files win field by field; a row names the node it applies to.

use axum::http::StatusCode;
use serde_json::json;
use telltale_api::auth::Role;
use telltale_config::Config;

use crate::credential_tests::{Harness, harness_toml};
use crate::managed::{CACHE, SUPPORT, UPDATES};
use crate::node_managed;
use crate::node_settings::{describe, node_name, overlay_blob, started_of};
use crate::settings_kinds_tests::{call_as, token};

const CACHE_URL: &str = "/api/v1/cache-settings";
const SUPPORT_URL: &str = "/api/v1/support-settings";
const UPDATES_URL: &str = "/api/v1/updates-settings";

/// A node with no planted settings.
fn bare() -> Harness {
    harness_toml(
        "",
        None,
        vec![telltale_config::Cidr::parse("127.0.0.0/8").unwrap()],
        telltale_api::auth::Settings::default(),
    )
}

/// A node whose files set the given TOML.
fn with_toml(toml: &str) -> Harness {
    harness_toml(
        toml,
        None,
        vec![telltale_config::Cidr::parse("127.0.0.0/8").unwrap()],
        telltale_api::auth::Settings::default(),
    )
}

/// This node's name in the per-node entries (what its `GET /api/v1/node-settings` says).
fn me(h: &Harness) -> String {
    node_name(&h.src.config.load_full())
}

/// The configuration as the stored rows make it (the same merge the reload applies).
fn merged(h: &Harness) -> Config {
    crate::managed::merge(
        &h.src.file_config.load_full(),
        &crate::managed::entries(h.auth.state()),
    )
    .expect("the merged configuration validates")
}

/// REQ: DNS-006 (T27.2, AC1) - the cache settings apply to the named node only, through the real
/// path; the files' value wins; an operator and an agent are refused.
#[tokio::test]
async fn dns_006_cache_settings_node_managed() {
    let h = bare();
    let node = me(&h);
    let (s, _, out) = h
        .call(
            "PUT",
            &format!("{CACHE_URL}/{node}"),
            Some(&json!({"max_bytes": 16_777_216})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    assert_eq!(h.src.config.load_full().cache.max_bytes.bytes(), 16_777_216);
    let rows = h.auth.state().managed(CACHE).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, node, "the row is named by its node");

    // A row for another node is stored under that node's name and changes nothing here.
    h.auth
        .state()
        .put_managed(
            CACHE,
            "node-b",
            &json!({"max_bytes": 1024}).to_string(),
            None,
            None,
            1,
            "test",
        )
        .unwrap();
    assert_eq!(merged(&h).cache.max_bytes.bytes(), 16_777_216);

    // A name that is not a node of this cluster is refused.
    let (s, _, _) = h
        .call(
            "PUT",
            &format!("{CACHE_URL}/not-a-member"),
            Some(&json!({"max_bytes": 1})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // A field that isn't in the section is refused by name.
    let (s, _, out) = h
        .call(
            "PUT",
            &format!("{CACHE_URL}/{node}"),
            Some(&json!({"no_such_field": 1})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{out}");

    // The status view shows what the node runs and that it is stored.
    let (s, _, st) = h.call("GET", "/api/v1/node-settings", None).await;
    assert_eq!(s, StatusCode::OK, "{st}");
    assert_eq!(st["node"], node);
    let cache = &st["sections"][0];
    assert_eq!(cache["section"], "cache");
    assert_eq!(
        cache["fields"]["max_bytes"],
        serde_json::to_value(telltale_config::ByteSize::mib(16)).unwrap()
    );
    assert_eq!(cache["stored"], true);

    // An operator changes the cache (T27.2 makes it operator-editable); a viewer reads only, and an
    // agent never writes.
    let op = token(&h, "ops", Role::Operator, None);
    let (s, _, out) = call_as(
        &h,
        &op,
        "PUT",
        &format!("{CACHE_URL}/{node}"),
        Some(&json!({"min_ttl": 5})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let viewer = token(&h, "viewer", Role::Viewer, None);
    let (s, _, _) = call_as(
        &h,
        &viewer,
        "PUT",
        &format!("{CACHE_URL}/{node}"),
        Some(&json!({"min_ttl": 6})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, st) = call_as(&h, &viewer, "GET", "/api/v1/node-settings", None, &[]).await;
    assert_eq!(s, StatusCode::OK, "{st}");
    let agent = token(&h, "agent", Role::Operator, Some("dns:read"));
    let (s, _, _) = call_as(
        &h,
        &agent,
        "PUT",
        &format!("{CACHE_URL}/{node}"),
        Some(&json!({"min_ttl": 5})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // DELETE removes the stored section: the default applies again.
    let (s, _, out) = h.call("DELETE", &format!("{CACHE_URL}/{node}"), None).await;
    assert_eq!(s, StatusCode::OK, "{out}");
    assert_eq!(
        h.src.config.load_full().cache.max_bytes.bytes(),
        telltale_config::CacheConfig::default().max_bytes.bytes()
    );
    let (s, _, _) = h.call("DELETE", &format!("{CACHE_URL}/{node}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// REQ: DNS-006 (T27.2, AC1) - a field the files set can't be changed through the API (409), and a
/// request that leaves it out keeps the file's value.
#[tokio::test]
async fn dns_006_file_wins_over_the_cache_settings() {
    let h = with_toml("[cache]\nmax_bytes = \"8MiB\"\n");
    let node = me(&h);
    let (s, _, out) = h
        .call(
            "PUT",
            &format!("{CACHE_URL}/{node}"),
            Some(&json!({"max_bytes": 16_777_216})),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{out}");
    let (s, _, out) = h
        .call(
            "PUT",
            &format!("{CACHE_URL}/{node}"),
            Some(&json!({"min_ttl": 5})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let cfg = h.src.config.load_full();
    assert_eq!(
        cfg.cache.max_bytes.bytes(),
        8 * 1024 * 1024,
        "the file's value stays"
    );
    assert_eq!(cfg.cache.min_ttl, 5);
}

/// REQ: DNS-006 (T27.2) - a change to a node's cache section is pending until the node restarts.
#[test]
fn dns_006_pending_restart_until_the_node_starts_again() {
    let file = Config::default();
    let started = started_of(&file);
    let mut e = crate::managed::Entries::default();
    let body = json!({"max_bytes": 16_777_216});
    e.node_settings
        .push((CACHE.to_owned(), "n1".to_owned(), body.clone()));
    let mut eff = file.clone();
    crate::settings_kinds::overlay(&mut eff, &file, telltale_api::ManagedKind::Cache, &body)
        .unwrap();
    let d = describe(&file, &eff, &e, "n1", "n1", Some(&started));
    assert!(d.sections[0].pending_restart, "{:?}", d.sections[0]);
    assert!(d.sections.iter().all(|s| s.restart_only));
    let same = describe(
        &file,
        &file,
        &crate::managed::Entries::default(),
        "n1",
        "n1",
        Some(&started),
    );
    assert!(!same.sections[0].pending_restart);
}

/// REQ: DNS-006 (T27.2) - a replica applies the row for its own name from the replicated blob, and
/// no other row.
#[test]
fn dns_006_blob_applies_only_this_nodes_row() {
    let mut cfg = Config::default();
    let me = node_name(&cfg);
    let rows = vec![
        (
            CACHE.to_owned(),
            me.clone(),
            json!({"max_bytes": 4096}).to_string(),
        ),
        (
            CACHE.to_owned(),
            "someone-else".to_owned(),
            json!({"max_bytes": 8192}).to_string(),
        ),
    ];
    let blob = node_managed::encode(&rows);
    let entries = node_managed::parse(&blob).unwrap();
    overlay_blob(&mut cfg, &entries);
    assert_eq!(cfg.cache.max_bytes.bytes(), 4096);
}

/// REQ: OPS-011, OPS-012 (T27.11, AC1) - `[support] persist_logs` and `[updates] check` for one
/// node, admins only.
#[tokio::test]
async fn ops_011_ops_012_support_and_updates_per_node() {
    let h = bare();
    let node = me(&h);
    let (s, _, out) = h
        .call(
            "PUT",
            &format!("{SUPPORT_URL}/{node}"),
            Some(&json!({"persist_logs": false})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    assert!(!h.src.config.load_full().support.persist_logs);
    let (s, _, out) = h
        .call(
            "PUT",
            &format!("{UPDATES_URL}/{node}"),
            Some(&json!({"check": false})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    assert!(!h.src.config.load_full().updates.check);
    assert_eq!(h.auth.state().managed(SUPPORT).unwrap().len(), 1);
    assert_eq!(h.auth.state().managed(UPDATES).unwrap().len(), 1);
    let op = token(&h, "ops", Role::Operator, None);
    let (s, _, _) = call_as(
        &h,
        &op,
        "PUT",
        &format!("{UPDATES_URL}/{node}"),
        Some(&json!({"check": true})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, st) = h.call("GET", "/api/v1/node-settings", None).await;
    assert_eq!(s, StatusCode::OK, "{st}");
    assert_eq!(st["sections"][1]["fields"]["persist_logs"], false);
    assert_eq!(st["sections"][2]["fields"]["check"], false);
}

/// REQ: CLU-014 (T27.11, AC1) - the drill schedule is admin-only; an operator is refused by name.
#[tokio::test]
async fn clu_014_drill_schedule_admin_only() {
    let h = bare();
    let op = token(&h, "ops", Role::Operator, None);
    let (s, _, out) = call_as(
        &h,
        &op,
        "PUT",
        "/api/v1/drill-settings/default",
        Some(&json!({"schedule": "monthly", "nodes": ["node-1"]})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{out}");
    let (s, _, out) = h
        .call(
            "PUT",
            "/api/v1/drill-settings/default",
            Some(&json!({"schedule": "monthly", "nodes": ["node-1"]})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    assert_eq!(
        serde_json::to_value(h.src.config.load_full().drill.schedule).unwrap(),
        "monthly"
    );
}

/// REQ: DNS-011 (T27.11, AC1) - `[dnssec]` mode and negative trust anchors, through the API.
#[tokio::test]
async fn dns_011_dnssec_mode_and_trust_anchors() {
    let h = bare();
    let (s, _, out) = h
        .call(
            "PUT",
            "/api/v1/dnssec-settings/default",
            Some(&json!({"mode": "validate", "negative_trust_anchors": ["lab.example"]})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let cfg = h.src.config.load_full();
    assert_eq!(serde_json::to_value(cfg.dnssec.mode).unwrap(), "validate");
    assert_eq!(
        cfg.dnssec
            .negative_trust_anchors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["lab.example"]
    );
}

/// REQ: FLT-004 (T27.11, AC1) - `[filter]` refresh and stale settings, through the API; the other
/// filter fields keep their values.
#[tokio::test]
async fn flt_004_filter_refresh_and_stale_settings() {
    let h = bare();
    let before = h.src.config.load_full().filter.fetch_concurrency;
    let (s, _, out) = h
        .call(
            "PUT",
            "/api/v1/filter-settings/default",
            Some(&json!({"refresh_secs": 3600, "stale_after_days": 14})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let cfg = h.src.config.load_full();
    assert_eq!(cfg.filter.refresh_secs, 3600);
    assert_eq!(cfg.filter.stale_after_days, 14);
    assert_eq!(cfg.filter.fetch_concurrency, before);
    let (s, _, _) = h
        .call(
            "PUT",
            "/api/v1/filter-settings/default",
            Some(&json!({"max_list_bytes": 1})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

//! REQ: CLU-015, CLU-004, API-016, API-010 (T24.37, ADR-1016) — entries added through the API stay
//! editable after a failover. Node A (primary) takes the writes through the real API; its
//! published configuration and blob are handed to node B, which follows, is promoted, and must
//! then be able to edit and delete every entry, with none lost or resurrected, across failback
//! too.

use axum::http::StatusCode;
use serde_json::{Value, json};
use telltale_cluster::node::{Identity, Role as NodeRole};
use telltale_cluster::sync::{BlobStore, ClusterManifest, blob_ref};
use telltale_config::Config;

use crate::credential_tests::{Harness, harness};
use crate::managed::{RATELIMIT, entries};

pub(crate) fn data_dir(h: &Harness) -> std::path::PathBuf {
    h.dir_path().to_path_buf()
}

pub(crate) fn file_of(h: &Harness) -> Config {
    (**h.src.file_config.load()).clone()
}

/// What primary `a` publishes: its effective shared configuration and its blob.
pub(crate) fn published(a: &Harness) -> (Config, Vec<u8>) {
    let merged = crate::managed::merge(&file_of(a), &entries(a.auth.state())).unwrap();
    (merged, crate::node_managed::export(a.auth.state()))
}

/// Makes `h` a member of the cluster as `role` that last applied the version (`merged`, `blob`).
pub(crate) fn follow(
    h: &Harness,
    role: NodeRole,
    epoch: u64,
    merged: &Config,
    blob: &[u8],
) -> Config {
    let dir = data_dir(h);
    let file = file_of(h);
    let mut id = match Identity::load(&dir).unwrap() {
        Some(id) => id,
        None => Identity::init(&dir, "home", vec!["https://127.0.0.1:1".into()], "k8s").unwrap(),
    };
    id.save_role(role, epoch).unwrap();
    let shared = serde_json::to_vec(&telltale_config::shared::shared_part(merged)).unwrap();
    let store = BlobStore::open(&dir).unwrap();
    let config = blob_ref("config.json", &shared);
    store.put(&config, &shared).unwrap();
    let nm = blob_ref(crate::node_managed::BLOB, blob);
    store.put(&nm, blob).unwrap();
    let m = ClusterManifest {
        cluster_id: "c".into(),
        epoch,
        seq: epoch * 10,
        primary: "other".into(),
        config,
        node_managed: Some(nm),
        ..ClusterManifest::default()
    };
    std::fs::write(
        telltale_cluster::node::dir_of(&dir).join(crate::replication::APPLIED),
        serde_json::to_vec(&m).unwrap(),
    )
    .unwrap();
    file
}

pub(crate) fn promote(h: &Harness, epoch: u64) {
    let mut id = Identity::load(&data_dir(h)).unwrap().unwrap();
    id.save_role(NodeRole::Primary, epoch).unwrap();
}

pub(crate) async fn ok(h: &Harness, method: &str, uri: &str, body: Option<Value>) -> Value {
    let (s, _, v) = h.call(method, uri, body.as_ref()).await;
    assert_eq!(s, StatusCode::OK, "{method} {uri}: {v}");
    v
}

pub(crate) fn upstream_names(c: &Config) -> Vec<String> {
    c.upstream.iter().map(|u| u.name.to_string()).collect()
}

pub(crate) fn group_members(c: &Config, group: &str) -> Vec<String> {
    c.upstream_group
        .iter()
        .find(|g| g.name.as_str() == group)
        .map(|g| g.members.iter().map(ToString::to_string).collect())
        .unwrap_or_default()
}

/// Node A takes one write of every kind of entry the cluster's shared configuration holds.
pub(crate) async fn fill(a: &Harness) {
    ok(
        a,
        "PUT",
        "/api/v1/upstreams/pihole-3",
        Some(json!({"url": "udp://192.0.2.3"})),
    )
    .await;
    ok(
        a,
        "PUT",
        "/api/v1/upstreams/pihole-4",
        Some(json!({"url": "udp://192.0.2.4"})),
    )
    .await;
    ok(
        a,
        "PUT",
        "/api/v1/upstream-groups/default",
        Some(json!({"members": ["nextdns", "plug", "pihole-3", "pihole-4"]})),
    )
    .await;
    ok(
        a,
        "PUT",
        "/api/v1/lists/hag",
        Some(json!({"url": "https://lists.example/hag.txt"})),
    )
    .await;
    ok(a, "PUT", "/api/v1/groups/kids", Some(json!({}))).await;
    ok(
        a,
        "PUT",
        "/api/v1/clients/tv",
        Some(json!({"match": ["192.168.1.42"]})),
    )
    .await;
    ok(
        a,
        "PUT",
        "/api/v1/records/nas.home.arpa",
        Some(json!({"records": [{"type": "A", "value": "192.168.1.9"}]})),
    )
    .await;
    ok(
        a,
        "PUT",
        "/api/v1/forwards/corp.example",
        Some(json!({"servers": ["10.0.0.53"]})),
    )
    .await;
    ok(
        a,
        "PUT",
        "/api/v1/rules/game",
        Some(json!({"action": "block", "domain": "game.example.com"})),
    )
    .await;
    // A section the API replaces whole (written as a row; its API route takes the same body).
    let mut r = telltale_config::RateLimitConfig::default();
    r.queries += 7;
    a.auth
        .state()
        .put_managed(
            RATELIMIT,
            "default",
            &serde_json::to_string(&r).unwrap(),
            None,
            None,
            1,
            "t",
        )
        .unwrap();
}

/// REQ: CLU-015, API-010 (T24.37) — the owner's case: entries added through the API while A was
/// primary can be dry-run deleted, deleted and edited on B after B is promoted, whatever their kind,
/// and a deleted entry stays deleted.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one story, told once
async fn clu_015_promoted_primary_edits_and_deletes_every_api_entry() {
    let (a, b) = (harness(""), harness(""));
    fill(&a).await;
    let (merged, blob) = published(&a);
    let file = follow(&b, NodeRole::Replica, 1, &merged, &blob);

    // As a replica: the entries are served, and it keeps no rows of its own.
    let cfg = crate::replication::effective(&file);
    assert!(upstream_names(&cfg).contains(&"pihole-3".to_owned()));
    assert_eq!(b.auth.state().managed("upstream").unwrap().len(), 0);

    // Promoted: still served, and now B's own rows (adopted from what A last published).
    promote(&b, 2);
    let cfg = crate::replication::effective(&file);
    assert_eq!(upstream_names(&cfg), upstream_names(&merged));
    assert_eq!(
        group_members(&cfg, "default"),
        group_members(&merged, "default")
    );
    assert_eq!(cfg.client.len(), merged.client.len());
    assert_eq!(cfg.record.len(), merged.record.len());
    assert_eq!(cfg.rule.len(), merged.rule.len());
    assert_eq!(cfg.route.len(), merged.route.len());
    assert_eq!(cfg.ratelimit, merged.ratelimit);
    assert_eq!(b.auth.state().managed("upstream").unwrap().len(), 2);
    assert_eq!(
        crate::node_managed::export(b.auth.state()),
        blob,
        "B publishes exactly the entries A last published"
    );

    // The dry run and the delete work (they answered 404 before the fix).
    ok(&b, "DELETE", "/api/v1/upstreams/pihole-3?dryRun=true", None).await;
    ok(&b, "DELETE", "/api/v1/upstreams/pihole-3", None).await;
    let cfg = crate::replication::effective(&file);
    assert!(
        !upstream_names(&cfg).contains(&"pihole-3".to_owned()),
        "{:?}",
        upstream_names(&cfg)
    );
    assert!(
        !group_members(&cfg, "default").contains(&"pihole-3".to_owned()),
        "taken out of its group too"
    );
    assert!(upstream_names(&cfg).contains(&"pihole-4".to_owned()));
    // Run again: the adopted version is not applied a second time and nothing comes back.
    let again = crate::replication::effective(&file);
    assert_eq!(upstream_names(&again), upstream_names(&cfg));

    // An edit.
    ok(
        &b,
        "PUT",
        "/api/v1/upstreams/pihole-4",
        Some(json!({"url": "udp://192.0.2.44"})),
    )
    .await;
    let cfg = crate::replication::effective(&file);
    let u4 = cfg
        .upstream
        .iter()
        .find(|u| u.name.as_str() == "pihole-4")
        .unwrap();
    assert!(u4.url.as_str().contains("192.0.2.44"), "{}", u4.url);

    // Every other kind too.
    ok(&b, "DELETE", "/api/v1/lists/hag", None).await;
    ok(&b, "DELETE", "/api/v1/groups/kids", None).await;
    ok(&b, "DELETE", "/api/v1/clients/tv", None).await;
    ok(&b, "DELETE", "/api/v1/records/nas.home.arpa", None).await;
    ok(&b, "DELETE", "/api/v1/forwards/corp.example", None).await;
    ok(&b, "DELETE", "/api/v1/rules/game", None).await;
    b.auth
        .state()
        .delete_managed(RATELIMIT, "default", None)
        .unwrap();
    let cfg = crate::replication::effective(&file);
    assert!(cfg.list.iter().all(|l| l.name.as_str() != "hag"));
    assert!(cfg.group.iter().all(|g| g.name.as_str() != "kids"));
    assert!(cfg.client.iter().all(|c| c.name.as_str() != "tv"));
    assert!(
        cfg.record
            .iter()
            .all(|r| r.name.as_str() != "nas.home.arpa")
    );
    assert!(
        cfg.route
            .iter()
            .all(|r| r.upstream_group.as_str() != "forward:corp.example")
    );
    assert!(
        cfg.upstream
            .iter()
            .all(|u| !u.name.as_str().starts_with("forward:corp.example"))
    );
    assert_eq!(cfg.rule.len(), 0);
    assert_eq!(cfg.ratelimit, file.ratelimit, "the files' section is back");
    // The planted file entries are untouched.
    assert!(upstream_names(&cfg).contains(&"nextdns".to_owned()));

    // Failback: A comes back as a replica with its stale rows; B's later version wins, and when A is
    // promoted again its rows are exactly what the cluster last published (nothing resurrected).
    let (merged_b, blob_b) = published(&b);
    assert!(
        !String::from_utf8(blob_b.clone())
            .unwrap()
            .contains("pihole-3")
    );
    let file_a = follow(&a, NodeRole::Replica, 3, &merged_b, &blob_b);
    assert_eq!(
        a.auth.state().managed("upstream").unwrap().len(),
        2,
        "stale rows"
    );
    let cfg_a = crate::replication::effective(&file_a);
    assert!(!upstream_names(&cfg_a).contains(&"pihole-3".to_owned()));
    promote(&a, 4);
    let cfg_a = crate::replication::effective(&file_a);
    assert!(!upstream_names(&cfg_a).contains(&"pihole-3".to_owned()));
    let rows: Vec<String> = a
        .auth
        .state()
        .managed("upstream")
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert_eq!(rows, ["pihole-4"], "A's stale rows were replaced");
    assert_eq!(a.auth.state().managed("list").unwrap().len(), 0);
}

/// REQ: CLU-015 (T24.37) — the adoption marker is dropped while the node follows a primary, so a
/// later promotion adopts the inherited blob even when its hash is the one adopted before (the
/// rows changed in between are not kept).
#[tokio::test]
async fn clu_015_readoption_after_a_demotion_even_for_the_same_blob() {
    let (a, b) = (harness(""), harness(""));
    fill(&a).await;
    let (merged, blob) = published(&a);
    let file = follow(&b, NodeRole::Replica, 1, &merged, &blob);
    promote(&b, 2);
    let _ = crate::replication::effective(&file);
    ok(&b, "DELETE", "/api/v1/upstreams/pihole-3", None).await;
    assert_eq!(b.auth.state().managed("upstream").unwrap().len(), 1);
    // B follows again, applying the very same version, then is promoted again.
    let file = follow(&b, NodeRole::Replica, 3, &merged, &blob);
    let _ = crate::replication::effective(&file);
    promote(&b, 4);
    let cfg = crate::replication::effective(&file);
    assert_eq!(b.auth.state().managed("upstream").unwrap().len(), 2);
    assert!(upstream_names(&cfg).contains(&"pihole-3".to_owned()));
}

/// REQ: CLU-015 (T24.37) — a primary publishes the rows of the shared kinds whole, and an older
/// build reading the blob sees only the kinds it knows.
#[tokio::test]
async fn clu_015_the_blob_carries_the_shared_rows() {
    let a = harness("");
    fill(&a).await;
    let blob = crate::node_managed::export(a.auth.state());
    let shared = crate::node_managed::parse_shared(&blob).unwrap().unwrap();
    for kind in [
        "upstream",
        "upstream_group",
        "list",
        "group",
        "client",
        "record",
        "forward",
        "rule",
        "ratelimit",
    ] {
        assert!(shared.iter().any(|e| e.kind == kind), "{kind}");
    }
    // The node-managed readers don't see them.
    assert_eq!(crate::node_managed::parse(&blob).unwrap().len(), 0);
}

/// REQ: CLU-015 (T24.37) — the record of an adoption lives in `state.db` with the rows, so a
/// second adoption of the same blob (the publish loop, a reload, a write plan) changes nothing,
/// an edit made since survives it, and a node that followed a primary adopts the next blob again.
#[tokio::test]
async fn clu_015_adoption_is_recorded_with_the_rows_and_runs_once() {
    let (a, b) = (harness(""), harness(""));
    fill(&a).await;
    let (merged, blob) = published(&a);
    let file = follow(&b, NodeRole::Replica, 1, &merged, &blob);
    promote(&b, 2);
    let _ = crate::replication::effective(&file);
    ok(
        &b,
        "PUT",
        "/api/v1/upstreams/pihole-4",
        Some(json!({"url": "udp://192.0.2.44"})),
    )
    .await;
    let version = b.auth.state().config_version().unwrap();
    // The same blob again, as every later tick and reload does.
    for _ in 0..3 {
        let _ = crate::replication::effective(&file);
    }
    assert_eq!(b.auth.state().config_version().unwrap(), version);
    let rows = b.auth.state().managed("upstream").unwrap();
    assert!(
        rows.iter().any(|r| r.body.contains("192.0.2.44")),
        "the edit survived a second adoption"
    );
    // Following a primary again forgets it: the next promotion adopts afresh.
    let state_path = crate::managed::state_path(&file);
    crate::managed_adopt::forget(&state_path);
    assert_eq!(
        b.auth.state().meta_get("managed-seeded").unwrap(),
        None,
        "the record is dropped"
    );
}

/// REQ: CLU-006, CLU-015 (T24.37) — a row pinned to its node (`node_only`) never leaves it: the
/// blob does not carry it, as the shared configuration does not.
#[test]
fn clu_006_node_only_rows_stay_out_of_the_blob() {
    let rows = vec![
        (
            "upstream".to_owned(),
            "lan-only".to_owned(),
            json!({"name": "lan-only", "url": "udp://10.0.0.9", "node_only": true}).to_string(),
        ),
        (
            "upstream".to_owned(),
            "shared".to_owned(),
            json!({"name": "shared", "url": "udp://192.0.2.1"}).to_string(),
        ),
    ];
    let blob = crate::node_managed::encode(&rows);
    let shared = crate::node_managed::parse_shared(&blob).unwrap().unwrap();
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].name, "shared");
}

/// REQ: CLU-006, CLU-015 (T24.37) — a node's own `node_only` row survives a failback: the blob
/// never carried it, and adopting the blob must not delete it.
#[tokio::test]
async fn clu_006_node_only_row_survives_a_failback() {
    let a = harness("");
    fill(&a).await;
    ok(
        &a,
        "PUT",
        "/api/v1/upstreams/lan-only",
        Some(json!({"url": "udp://10.0.0.9", "node_only": true})),
    )
    .await;
    let (merged, blob) = published(&a);
    // A follows another primary's version, then is promoted again.
    let file = follow(&a, NodeRole::Replica, 2, &merged, &blob);
    let _ = crate::replication::effective(&file);
    crate::managed_adopt::forget(&crate::managed::state_path(&file));
    promote(&a, 3);
    let _ = crate::replication::effective(&file);
    let rows = a.auth.state().managed("upstream").unwrap();
    assert!(
        rows.iter().any(|r| r.name == "lan-only"),
        "node_only row lost on failback"
    );
}

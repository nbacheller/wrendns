//! REQ: CLU-015, CLU-004, API-010 (T24.40, ADR-1019) — a cluster upgraded from a version before
//! ADR-1016 keeps its API entries. The old primary's blob has no rows of the shared kinds; the node
//! promoted from replica (or already primary at startup) adopts the entries it serves that its own
//! files don't define, and every write builds on them: nothing served is dropped.

use axum::http::StatusCode;
use serde_json::{Value, json};
use telltale_cluster::node::Role as NodeRole;
use telltale_cluster::sync::{BlobStore, blob_ref};
use telltale_config::Config;

use crate::managed::entries;
use crate::managed_adopt_tests::{fill, follow, ok, promote, upstream_names};

/// The blob an older primary published: no `managed` flag, no shared rows.
fn old_blob() -> Vec<u8> {
    serde_json::to_vec(&json!({"version": 1, "entries": []})).unwrap()
}

fn put_row(h: &crate::credential_tests::Harness, kind: &str, name: &str, body: &Value) {
    h.auth
        .state()
        .put_managed(kind, name, &body.to_string(), None, None, 1, "t")
        .unwrap();
}

/// What node A (the old primary) serves, for every kind: `fill`'s kinds and the rest.
async fn fill_all(a: &crate::credential_tests::Harness) {
    fill(a).await;
    ok(
        a,
        "PUT",
        "/api/v1/upstream-groups/extra",
        Some(json!({"members": ["pihole-3"]})),
    )
    .await;
    put_row(
        a,
        "alert_destination",
        "ntfy",
        &json!({"name": "ntfy", "type": "ntfy", "url": "https://ntfy.example/t"}),
    );
    put_row(
        a,
        "alert_rule",
        "down",
        &json!({"name": "down", "when": "upstream_down", "to": ["ntfy"]}),
    );
    put_row(
        a,
        "schedule",
        "night",
        &json!({"name": "night", "action": "block_all",
            "window": [{"days": ["mon"], "start": "22:00", "end": "23:00"}]}),
    );
    put_row(
        a,
        "anomaly_mute",
        "quiet",
        &json!({"name": "quiet", "devices": ["192.168.1.77"], "kinds": ["rate_spike"]}),
    );
    put_row(
        a,
        "kubernetes_map",
        "apps/*/*",
        &json!({"namespace": "apps", "group": "default"}),
    );
    put_row(
        a,
        "router",
        "gw",
        &json!({"name": "gw", "type": "unifi", "url": "https://192.0.2.1", "api_key_ref": "unifi"}),
    );
    // A settings section: flip the first boolean.
    let mut special = serde_json::to_value(Config::default().special).unwrap();
    let key = special
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, v)| v.is_boolean())
        .map(|(k, _)| k.clone())
        .unwrap();
    let flipped = !special[&key].as_bool().unwrap();
    special[&key] = json!(flipped);
    put_row(a, "special", "default", &special);
}

fn rows(h: &crate::credential_tests::Harness, kind: &str) -> Vec<String> {
    let mut v: Vec<String> = h
        .auth
        .state()
        .managed(kind)
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    v.sort();
    v
}

/// Promotes B (a replica of A's old-format version) and returns its files and what it serves.
fn promoted_from_old(
    a: &crate::credential_tests::Harness,
    b: &crate::credential_tests::Harness,
) -> (Config, Config) {
    let merged = crate::managed::merge(
        &crate::managed_adopt_tests::file_of(a),
        &entries(a.auth.state()),
    )
    .unwrap();
    let file = follow(b, NodeRole::Replica, 1, &merged, &old_blob());
    // As a replica it serves everything and holds nothing.
    let cfg = crate::replication::effective(&file);
    assert!(upstream_names(&cfg).contains(&"pihole-3".to_owned()));
    assert_eq!(rows(b, "list").len(), 0);
    promote(b, 2);
    (file, merged)
}

/// REQ: CLU-015 (T24.40, ADR-1019) — the failing case first: a promoted replica whose inherited blob
/// is an older primary's: a dry-run write of a served entry shows it as `before`, the candidate keeps
/// every other served entry, and the adopted rows are recorded as `adopted:<seq>`.
#[tokio::test]
async fn clu_015_t24_40_a_promoted_replicas_dry_run_sees_the_served_entry() {
    let (a, b) = (harness_(), harness_());
    fill_all(&a).await;
    let (file, merged) = promoted_from_old(&a, &b);
    let cfg = crate::replication::effective(&file);
    b.src.config.store(std::sync::Arc::new(cfg.clone()));

    let (s, _, v) = b
        .call(
            "PUT",
            "/api/v1/lists/hag?dryRun=true",
            Some(&json!({"url": "https://lists.example/hag2.txt"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(!v["before"].is_null(), "before is the served entry: {v}");
    assert!(
        v["before"]["url"].as_str().unwrap().contains("hag.txt"),
        "{v}"
    );
    // The candidate every write builds on keeps every served entry.
    let base = crate::replication::managed_base(&file).expect("adopted");
    let candidate = crate::managed::merge(&base, &entries(b.auth.state())).unwrap();
    assert_eq!(upstream_names(&candidate), upstream_names(&merged));
    assert_eq!(candidate.list.len(), merged.list.len());
    assert_eq!(candidate.client.len(), merged.client.len());
    assert_eq!(candidate.record.len(), merged.record.len());
    assert_eq!(candidate.rule.len(), merged.rule.len());
    assert_eq!(candidate.route.len(), merged.route.len());
    for r in b.auth.state().managed("list").unwrap() {
        assert_eq!(r.updated_by, "adopted:10", "{}", r.name);
    }
}

/// REQ: CLU-015 (T24.40, ADR-1019) — every kind: what the files don't define is adopted as a row, what
/// they do stays a file entry, and nothing served is lost (the whole served set is the same before
/// and after).
#[tokio::test]
async fn clu_015_t24_40_every_kind_is_adopted_and_the_files_entries_stay() {
    let (a, b) = (harness_(), harness_());
    fill_all(&a).await;
    // A node_only row of B's own is not touched.
    put_row(
        &b,
        "upstream",
        "lan-only",
        &json!({"name": "lan-only", "url": "udp://10.0.0.9", "node_only": true}),
    );
    let (file, merged) = promoted_from_old(&a, &b);
    let cfg = crate::replication::effective(&file);

    for (kind, want) in [
        ("upstream", vec!["lan-only", "pihole-3", "pihole-4"]),
        ("upstream_group", vec!["extra"]),
        ("list", vec!["hag"]),
        ("group", vec!["kids"]),
        ("client", vec!["tv"]),
        ("record", vec!["nas.home.arpa"]),
        ("forward", vec!["corp.example"]),
        ("rule", vec!["game"]),
        ("ratelimit", vec!["default"]),
        ("special", vec!["default"]),
        ("alert_destination", vec!["ntfy"]),
        ("alert_rule", vec!["down"]),
        ("schedule", vec!["night"]),
        ("anomaly_mute", vec!["quiet"]),
        ("kubernetes_map", vec!["apps/*/*"]),
        ("router", vec!["gw"]),
    ] {
        assert_eq!(rows(&b, kind), want, "{kind}");
    }
    // The files' own entries are file entries: no row for the files' group or upstreams.
    assert!(!rows(&b, "upstream").contains(&"nextdns".to_owned()));
    assert!(!rows(&b, "upstream_group").contains(&"default".to_owned()));
    // The node_only row is as it was.
    let lan = b.auth.state().managed("upstream").unwrap();
    assert_eq!(
        lan.iter()
            .find(|m| m.name == "lan-only")
            .unwrap()
            .updated_by,
        "t"
    );
    // The same set is served, kind by kind.
    assert_eq!(
        upstream_names(&cfg).len(),
        upstream_names(&merged).len() + 1,
        "plus its own node_only row"
    );
    assert_eq!(cfg.upstream_group.len(), merged.upstream_group.len());
    assert_eq!(cfg.list.len(), merged.list.len());
    assert_eq!(cfg.group.len(), merged.group.len());
    assert_eq!(cfg.client.len(), merged.client.len());
    assert_eq!(cfg.record.len(), merged.record.len());
    assert_eq!(cfg.route.len(), merged.route.len());
    assert_eq!(cfg.rule.len(), merged.rule.len());
    assert_eq!(cfg.ratelimit, merged.ratelimit);
    assert_eq!(cfg.special, merged.special);
    assert_eq!(
        cfg.alerts.destination.len(),
        merged.alerts.destination.len()
    );
    assert_eq!(cfg.alerts.rule.len(), merged.alerts.rule.len());
    assert_eq!(cfg.schedule.len(), merged.schedule.len());
    assert_eq!(cfg.anomaly_mute.len(), merged.anomaly_mute.len());
    assert_eq!(cfg.kubernetes.map.len(), merged.kubernetes.map.len());
    assert_eq!(cfg.router.len(), merged.router.len());
    // The default group keeps what the old primary served (a file entry here).
    let members = |c: &Config| crate::managed_adopt_tests::group_members(c, "default");
    assert_eq!(members(&cfg), members(&merged));
    // (4) The rows publish, with the shared kinds, so a later failover keeps them (ADR-1016).
    let blob = crate::node_managed::export(b.auth.state());
    let shared = crate::node_managed::parse_shared(&blob).unwrap().unwrap();
    for kind in [
        "upstream", "list", "client", "record", "forward", "rule", "special", "router",
    ] {
        assert!(shared.iter().any(|e| e.kind == kind), "{kind}");
    }
    assert!(
        !shared.iter().any(|e| e.name == "lan-only"),
        "node_only stays on its node"
    );
    // Once: another pass changes nothing (the version is the same).
    let version = b.auth.state().config_version().unwrap();
    for _ in 0..3 {
        let _ = crate::replication::effective(&file);
    }
    assert_eq!(b.auth.state().config_version().unwrap(), version);
}

/// REQ: CLU-015 (T24.40, ADR-1019) — the edit and the delete of an inherited entry stick, the others
/// stay served, and a restart changes nothing (nothing resurrected, nothing lost).
#[tokio::test]
async fn clu_015_t24_40_edit_and_delete_stick_across_a_restart() {
    let (a, b) = (harness_(), harness_());
    fill_all(&a).await;
    let (file, merged) = promoted_from_old(&a, &b);
    let _ = crate::replication::effective(&file);

    ok(
        &b,
        "PUT",
        "/api/v1/lists/hag",
        Some(json!({"url": "https://lists.example/hag2.txt"})),
    )
    .await;
    ok(&b, "DELETE", "/api/v1/clients/tv", None).await;
    ok(&b, "DELETE", "/api/v1/records/nas.home.arpa", None).await;
    ok(&b, "DELETE", "/api/v1/forwards/corp.example", None).await;
    ok(&b, "DELETE", "/api/v1/rules/game", None).await;
    ok(&b, "DELETE", "/api/v1/groups/kids", None).await;
    ok(&b, "DELETE", "/api/v1/upstream-groups/extra", None).await;
    ok(&b, "DELETE", "/api/v1/upstreams/pihole-4", None).await;

    let check = |cfg: &Config| {
        let hag = cfg.list.iter().find(|l| l.name.as_str() == "hag").unwrap();
        assert!(hag.url.as_ref().unwrap().as_str().contains("hag2"));
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
        assert_eq!(cfg.rule.len(), 0);
        assert!(cfg.group.iter().all(|g| g.name.as_str() != "kids"));
        assert!(
            cfg.upstream_group
                .iter()
                .all(|g| g.name.as_str() != "extra")
        );
        assert!(!upstream_names(cfg).contains(&"pihole-4".to_owned()));
        // The others stay served.
        assert!(upstream_names(cfg).contains(&"pihole-3".to_owned()));
        assert_eq!(cfg.ratelimit, merged.ratelimit);
        assert_eq!(cfg.special, merged.special);
        assert_eq!(
            cfg.alerts.destination.len(),
            merged.alerts.destination.len()
        );
        assert_eq!(cfg.router.len(), merged.router.len());
    };
    check(&crate::replication::effective(&file));
    // A restart: the process forgets, the marker and rows are in state.db.
    crate::managed_adopt::reset_cache();
    check(&crate::replication::effective(&file));
}

/// REQ: CLU-015 (T24.40, ADR-1019) — a node that is already primary in this state at startup (the
/// owner's third node: promoted while every node ran a build without ADR-1016) adopts too, with no
/// promotion step, and the adoption is a fixed point.
#[tokio::test]
async fn clu_015_t24_40_a_primary_at_startup_adopts() {
    let (a, b) = (harness_(), harness_());
    fill_all(&a).await;
    let merged = crate::managed::merge(
        &crate::managed_adopt_tests::file_of(&a),
        &entries(a.auth.state()),
    )
    .unwrap();
    // B is primary already, with the old-format version as the last it applied.
    let file = follow(&b, NodeRole::Primary, 2, &merged, &old_blob());
    assert_eq!(rows(&b, "list").len(), 0);
    let cfg = crate::replication::effective(&file);
    assert_eq!(rows(&b, "list"), ["hag"]);
    assert_eq!(cfg.list.len(), merged.list.len());
    let (s, _, v) = b
        .call("DELETE", "/api/v1/lists/hag?dryRun=true", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(!v["before"].is_null(), "{v}");
}

/// REQ: CLU-015, CLU-004 (T24.40, ADR-1019) — also when the version has no blob at all.
#[tokio::test]
async fn clu_015_t24_40_a_version_without_a_blob_is_adopted_too() {
    let (a, b) = (harness_(), harness_());
    fill_all(&a).await;
    let merged = crate::managed::merge(
        &crate::managed_adopt_tests::file_of(&a),
        &entries(a.auth.state()),
    )
    .unwrap();
    let file = follow(&b, NodeRole::Primary, 2, &merged, &old_blob());
    // Take the blob out of the manifest.
    let path = telltale_cluster::node::dir_of(&crate::managed_adopt_tests::data_dir(&b))
        .join(crate::replication::APPLIED);
    let mut m: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    m.as_object_mut().unwrap().remove("node_managed");
    std::fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
    let _ = crate::replication::effective(&file);
    assert_eq!(rows(&b, "list"), ["hag"]);
    assert_eq!(rows(&b, "upstream"), ["pihole-3", "pihole-4"]);
}

/// REQ: CLU-015, CLU-004 (T24.40, ADR-1019 point 3) — until adoption has happened, a write must never
/// publish a candidate that drops served entries: the node refuses it with 409 and the reason, and
/// changes nothing; once the version is readable again the write goes through.
#[tokio::test]
async fn clu_015_t24_40_a_write_is_refused_until_the_entries_are_adopted() {
    let (a, b) = (harness_(), harness_());
    fill_all(&a).await;
    let (file, merged) = promoted_from_old(&a, &b);
    // The blob the manifest names can't be read: nothing can be adopted.
    let dir = crate::managed_adopt_tests::data_dir(&b);
    let store = BlobStore::open(&dir).unwrap();
    let nm = blob_ref(crate::node_managed::BLOB, &old_blob());
    let at = store.path(&nm.hash).unwrap();
    let kept = std::fs::read(&at).unwrap();
    std::fs::remove_file(&at).unwrap();
    let cfg = crate::replication::effective(&file);
    assert_eq!(cfg.list.len(), merged.list.len(), "still served");
    b.src.config.store(std::sync::Arc::new(cfg));
    for (method, uri, body) in [
        (
            "PUT",
            "/api/v1/lists/other",
            Some(json!({"url": "https://lists.example/o.txt"})),
        ),
        ("DELETE", "/api/v1/lists/hag", None),
        (
            "PUT",
            "/api/v1/lists/other?dryRun=true",
            Some(json!({"url": "https://lists.example/o.txt"})),
        ),
    ] {
        let (s, _, v) = b.call(method, uri, body.as_ref()).await;
        assert_eq!(s, StatusCode::CONFLICT, "{method} {uri}: {v}");
        assert!(
            v["detail"].as_str().unwrap().contains("does not hold"),
            "{v}"
        );
    }
    assert_eq!(rows(&b, "list").len(), 0, "nothing was written");
    // The version is readable again: the node adopts and the write goes through.
    std::fs::write(&at, kept).unwrap();
    let cfg = crate::replication::effective(&file);
    b.src.config.store(std::sync::Arc::new(cfg));
    ok(
        &b,
        "PUT",
        "/api/v1/lists/other",
        Some(json!({"url": "https://lists.example/o.txt"})),
    )
    .await;
    assert_eq!(rows(&b, "list"), ["hag", "other"]);
}

/// REQ: CLU-015 (T24.40, ADR-1019) — a node that is not a promoted primary is not affected: no
/// adoption, no refusal.
#[tokio::test]
async fn clu_015_t24_40_a_standalone_node_is_not_affected() {
    let b = harness_();
    let file = crate::managed_adopt_tests::file_of(&b);
    assert!(matches!(
        crate::replication::managed_base_state(&file),
        crate::replication::Base::NotApplicable
    ));
    ok(
        &b,
        "PUT",
        "/api/v1/lists/mine",
        Some(json!({"url": "https://lists.example/m.txt"})),
    )
    .await;
}

fn harness_() -> crate::credential_tests::Harness {
    crate::credential_tests::harness("")
}

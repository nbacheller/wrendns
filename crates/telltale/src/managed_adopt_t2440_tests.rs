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

/// REQ: CLU-015, CLU-004 (T24.40 review, HIGH) - the publish loop's adoption on promotion runs
/// before the reload (`managed_base_state`, on the real merged base): the entries are adopted from
/// what the node serves, and a restart afterwards keeps every one of them.
#[tokio::test]
async fn clu_015_t24_40_the_publish_loop_adopting_first_loses_nothing_after_a_restart() {
    let (a, b) = (harness_(), harness_());
    fill_all(&a).await;
    let merged = crate::managed::merge(
        &crate::managed_adopt_tests::file_of(&a),
        &entries(a.auth.state()),
    )
    .unwrap();
    let file = follow(&b, NodeRole::Replica, 1, &merged, &old_blob());
    // What gather holds: the files (never the running config), captured while a replica.
    let _running = crate::replication::effective(&file);
    promote(&b, 2);
    // The publish loop's first gather, before any reload.
    assert!(matches!(
        crate::replication::managed_base_state(&file),
        crate::replication::Base::Adopted(_)
    ));
    assert_eq!(rows(&b, "list"), ["hag"], "adopted as rows by the gather");
    crate::managed_adopt::reset_cache();
    let cfg = crate::replication::effective(&file);
    assert_eq!(rows(&b, "list"), ["hag"]);
    assert_eq!(cfg.special, merged.special);
    assert_eq!(upstream_names(&cfg), upstream_names(&merged));
    assert_eq!(cfg.list.len(), merged.list.len());
    assert_eq!(cfg.record.len(), merged.record.len());
}

/// REQ: CLU-015 (T24.40 review, HIGH) - once adopted, the names that were adopted are the ones
/// stripped: a caller whose `served` has nothing in it (or whose files now define a name) can't
/// change them.
#[tokio::test]
async fn clu_015_t24_40_the_adopted_names_are_remembered_not_rederived() {
    let (a, b) = (harness_(), harness_());
    fill_all(&a).await;
    let merged = crate::managed::merge(
        &crate::managed_adopt_tests::file_of(&a),
        &entries(a.auth.state()),
    )
    .unwrap();
    let file = crate::managed_adopt_tests::file_of(&b);
    let path = crate::managed::state_path(&file);
    let first = crate::managed_adopt::adopt_served(&path, "none:1", 1, &merged, &file).unwrap();
    assert!(first.len() > 10, "{}", first.len());
    crate::managed_adopt::reset_cache();
    let again =
        crate::managed_adopt::adopt_served(&path, "none:1", 1, &Config::default(), &file).unwrap();
    let names = |v: &[crate::node_managed::Entry]| {
        let mut n: Vec<String> = v.iter().map(|e| format!("{}/{}", e.kind, e.name)).collect();
        n.sort();
        n
    };
    assert_eq!(names(&first), names(&again));
}

/// REQ: API-014, API-016 (ADR-921; T24.40 review) - a served entry holding a credential, or a path
/// to one, is not copied into a row; a reference to a stored secret is fine.
#[test]
fn clu_015_t24_40_credentials_are_not_copied_into_rows() {
    let own = Config::default();
    let mut served = Config::default();
    let cfg: Config = toml::from_str(
        r#"
[[upstream]]
name = "mtls"
url = "https://dns.example/dns-query"
tls_client_cert = "/etc/telltale/c.pem"
tls_client_key = "/etc/telltale/k.pem"

[[upstream]]
name = "plain"
url = "https://plain.example/dns-query"

[[router]]
name = "gw"
type = "unifi"
url = "https://192.0.2.1"
api_key_file = "/etc/telltale/gw.key"
"#,
    )
    .unwrap();
    served.upstream = cfg.upstream;
    served.router = cfg.router;
    let derived = crate::managed_adopt::derive(&served, &own);
    let names: Vec<_> = derived.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"plain"), "{names:?}");
    assert!(!names.contains(&"mtls"), "{names:?}");
    assert!(!names.contains(&"gw"), "{names:?}");
}

/// REQ: CLU-004 (T24.40 review, MEDIUM) - a candidate that would not merge is not adopted: nothing
/// is inserted and the node refuses writes, instead of falling back to the stripped files.
#[tokio::test]
async fn clu_015_t24_40_a_row_that_would_not_merge_blocks_the_adoption() {
    let (a, b) = (harness_(), harness_());
    fill_all(&a).await;
    let merged = crate::managed::merge(
        &crate::managed_adopt_tests::file_of(&a),
        &entries(a.auth.state()),
    )
    .unwrap();
    let file = crate::managed_adopt_tests::file_of(&b);
    put_row(
        &b,
        "upstream_group",
        "broken",
        &json!({"name": "broken", "members": ["no-such-upstream"]}),
    );
    let path = crate::managed::state_path(&file);
    let before = rows(&b, "list");
    assert!(crate::managed_adopt::adopt_served(&path, "none:1", 1, &merged, &file).is_none());
    assert_eq!(rows(&b, "list"), before);
}

/// A copy of `v` with one field changed: the first integer plus one, else the first boolean
/// flipped, else `example.com` added to the first list.
fn perturbed(mut v: Value) -> Value {
    let Some(o) = v.as_object_mut() else {
        return v;
    };
    if let Some((_, n)) = o.iter_mut().find(|(_, n)| n.is_u64()) {
        *n = json!(n.as_u64().unwrap_or(0) + 1);
    } else if let Some((_, b)) = o.iter_mut().find(|(_, b)| b.is_boolean()) {
        *b = json!(!b.as_bool().unwrap_or(false));
    } else if let Some((_, a)) = o.iter_mut().find(|(_, a)| a.is_array())
        && let Some(a) = a.as_array_mut()
    {
        a.push(json!("example.com"));
    }
    v
}

/// `t` with one field changed (see [`perturbed`]).
fn bumped<T: serde::Serialize + serde::de::DeserializeOwned>(t: &T) -> T {
    serde_json::from_value(perturbed(serde_json::to_value(t).unwrap())).unwrap()
}

/// REQ: CLU-015 (T24.40, ADR-1019) — every kind a primary publishes is either adopted from a
/// served version or listed as needing no adoption, never both; node-managed kinds are neither.
/// A kind added to `SHARED_KINDS` without either fails here.
#[test]
fn clu_015_t24_40_every_shared_kind_is_adopted_or_exempt() {
    use crate::managed_adopt::{ADOPTED_KINDS, NOT_ADOPTED};
    use crate::node_managed::{KINDS, SHARED_KINDS};
    for k in SHARED_KINDS {
        let adopted = ADOPTED_KINDS.contains(k);
        let exempt = NOT_ADOPTED.iter().any(|(n, _)| n == k);
        assert!(
            adopted ^ exempt,
            "shared kind `{k}`: add it to ADOPTED_KINDS (with derive and strip) or to NOT_ADOPTED (with a reason)"
        );
    }
    for k in ADOPTED_KINDS {
        assert!(SHARED_KINDS.contains(k), "{k} is not a shared kind");
        assert!(!KINDS.contains(k), "{k} is node-managed");
    }
    for (k, why) in NOT_ADOPTED {
        assert!(SHARED_KINDS.contains(k), "{k} is not a shared kind");
        assert!(!why.is_empty(), "{k} needs a reason");
    }
}

/// REQ: CLU-015 (T24.40, ADR-1019) — and `derive` does adopt every kind in `ADOPTED_KINDS`: an old
/// primary serving an entry of each, its files defining none of them, hands every kind over.
#[tokio::test]
async fn clu_015_t24_40_derive_covers_every_adopted_kind() {
    use crate::managed_adopt::ADOPTED_KINDS;
    use telltale_api::ManagedKind as K;
    let a = harness_();
    fill_all(&a).await;
    let d = Config::default();
    for (kind, k) in [
        ("local", K::Local),
        ("clients", K::Clients),
        ("discovery", K::Discovery),
        ("dnssec", K::Dnssec),
        ("filter", K::Filter),
        ("drill", K::Drill),
        ("slo", K::Slo),
        ("probe", K::Probe),
        ("upstream_check", K::UpstreamCheck),
    ] {
        let mut body = crate::settings_kinds::section_json(k, &d);
        if k == K::Slo {
            // `latency_ms` is one of the histogram's bounds: change the switch instead.
            body["enabled"] = json!(!d.slo.enabled);
        } else {
            body = perturbed(body);
        }
        put_row(&a, kind, "default", &body);
    }
    for (kind, body) in [
        ("exclusions", serde_json::to_value(&d.exclusions).unwrap()),
        ("simulate", serde_json::to_value(&d.simulate).unwrap()),
        ("map", serde_json::to_value(&d.map).unwrap()),
        ("rollout", serde_json::to_value(&d.cluster.rollout).unwrap()),
    ] {
        put_row(&a, kind, "default", &perturbed(body));
    }
    put_row(
        &a,
        "zone",
        "lab.example",
        &json!({"name": "lab.example", "negative_ttl": 300,
            "record": [{"name": "www.lab.example", "type": "A", "value": "192.0.2.9"}]}),
    );
    let file = crate::managed_adopt_tests::file_of(&a);
    let merged = crate::managed::merge(&file, &entries(a.auth.state())).unwrap();
    let derived = crate::managed_adopt::derive(&merged, &file);
    for k in ADOPTED_KINDS {
        assert!(
            derived.iter().any(|e| e.kind == *k),
            "`{k}` is served but not adopted: {:?}",
            derived.iter().map(|e| &e.kind).collect::<Vec<_>>()
        );
    }
}

/// The tuning sections an old primary served, and the node-managed ones changed too.
fn tuned(own: &Config) -> Config {
    let mut s = own.clone();
    s.dnssec.mode = telltale_config::DnssecMode::Validate;
    // Not a field the API edits: it stays served, never in a row.
    s.dnssec.aggressive_nsec = !own.dnssec.aggressive_nsec;
    s.filter.refresh_secs += 60;
    s.filter.fetch_concurrency += 1;
    // One of the /metrics histogram's bounds.
    s.slo.latency_ms = if own.slo.latency_ms == 250 { 500 } else { 250 };
    s.probe.interval_secs += 5;
    s.upstream_check.sample_every += 1;
    // `[drill]` is the same as the files': nothing to adopt.
    s.cache = bumped(&own.cache);
    s.support = bumped(&own.support);
    s.updates = bumped(&own.updates);
    s.telemetry.anomaly = bumped(&own.telemetry.anomaly);
    s.telemetry.qlog = bumped(&own.telemetry.qlog);
    s.telemetry.metrics.per_client = !own.telemetry.metrics.per_client;
    s
}

/// REQ: CLU-015, DNS-011, FLT-004, OBS-016, OBS-020, OBS-019 (T24.40, ADR-1019) — a tuning section
/// is adopted when the served one differs from the files' in a field the API edits, and only then;
/// the node-managed sections never are.
#[test]
fn clu_015_t24_40_tuning_sections_are_adopted_when_they_differ() {
    let own = Config::default();
    let served = tuned(&own);
    assert_ne!(served.cache, own.cache);
    let derived = crate::managed_adopt::derive(&served, &own);
    let mut kinds: Vec<&str> = derived.iter().map(|e| e.kind.as_str()).collect();
    kinds.sort_unstable();
    assert_eq!(
        kinds,
        ["dnssec", "filter", "probe", "slo", "upstream_check"],
        "drill is unchanged; cache, support, updates and the telemetry settings are node-managed"
    );
    assert!(derived.iter().all(|e| e.name == "default"));
    let dnssec = derived.iter().find(|e| e.kind == "dnssec").unwrap();
    assert_eq!(dnssec.body["mode"], "validate");
    assert!(
        dnssec.body.get("aggressive_nsec").is_none(),
        "only the API's fields"
    );
    // Equal sections: nothing.
    assert_eq!(crate::managed_adopt::derive(&own, &own).len(), 0);
}

/// REQ: CLU-015, CLU-004 (T24.40, ADR-1019) — stripping the adopted tuning rows gives the files'
/// API fields back (the other fields stay as served), and the rows merged on that give exactly what
/// was served: adoption changes nothing the node answers with, and a deleted row reveals the files.
#[test]
fn clu_015_t24_40_tuning_sections_strip_and_merge_back() {
    use telltale_api::ManagedKind as K;
    let own = Config::default();
    let served = tuned(&own);
    let derived = crate::managed_adopt::derive(&served, &own);
    let mut stripped = served.clone();
    crate::managed_adopt::strip(&mut stripped, &derived, &own);
    let all = [
        K::Dnssec,
        K::Filter,
        K::Drill,
        K::Slo,
        K::Probe,
        K::UpstreamCheck,
    ];
    for k in all {
        assert_eq!(
            crate::settings_kinds::section_json(k, &stripped),
            crate::settings_kinds::section_json(k, &own),
            "{k:?} goes back to the files'"
        );
    }
    assert_eq!(
        stripped.dnssec.aggressive_nsec, served.dnssec.aggressive_nsec,
        "a field only the files set stays served"
    );
    assert_eq!(
        stripped.filter.fetch_concurrency,
        served.filter.fetch_concurrency
    );
    let scratch = telltale_store::state::State::in_memory().unwrap();
    for e in &derived {
        scratch
            .put_managed(&e.kind, &e.name, &e.body.to_string(), None, None, 1, "t")
            .unwrap();
    }
    let back = crate::managed::merge_on(&stripped, &own, &entries(&scratch)).unwrap();
    for k in all {
        assert_eq!(
            crate::settings_kinds::section_json(k, &back),
            crate::settings_kinds::section_json(k, &served),
            "{k:?} is served as before"
        );
    }
    assert_eq!(back.dnssec, served.dnssec);
    assert_eq!(back.filter, served.filter);
}

/// REQ: CLU-015, DNS-010 (T24.40, ADR-1019) — a served zone the files don't define is adopted by
/// its apex as the API names it; a zone the files define, or one read from a zone file, is not.
/// Stripping takes out only the adopted one, and its row decodes back to the same zone.
#[test]
fn clu_015_t24_40_zones_are_adopted_by_apex() {
    let own: Config = toml::from_str(
        r#"
[[zone]]
name = "files.example"
[[zone.record]]
name = "a.files.example"
type = "A"
value = "192.0.2.1"
"#,
    )
    .unwrap();
    let mut served = own.clone();
    let extra: Config = toml::from_str(
        r#"
[[zone]]
name = "Lab.Example."
[[zone.record]]
name = "www.lab.example"
type = "A"
value = "192.0.2.9"

[[zone]]
name = "zf.example"
file = "/etc/telltale/zf.zone"
"#,
    )
    .unwrap();
    served.zone.extend(extra.zone);
    let derived = crate::managed_adopt::derive(&served, &own);
    let zones: Vec<&str> = derived
        .iter()
        .filter(|e| e.kind == "zone")
        .map(|e| e.name.as_str())
        .collect();
    assert_eq!(zones, ["lab.example"]);
    let mut stripped = served.clone();
    crate::managed_adopt::strip(&mut stripped, &derived, &own);
    let mut names: Vec<&str> = stripped.zone.iter().map(|z| z.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["files.example", "zf.example"]);
    let scratch = telltale_store::state::State::in_memory().unwrap();
    for e in &derived {
        scratch
            .put_managed(&e.kind, &e.name, &e.body.to_string(), None, None, 1, "t")
            .unwrap();
    }
    let ent = entries(&scratch);
    assert_eq!(ent.zones.len(), 1, "the row decodes as a zone");
    let lab = served
        .zone
        .iter()
        .find(|z| z.name.as_str() == "Lab.Example.")
        .unwrap();
    assert_eq!(&ent.zones[0].1, lab, "the same zone");
}

/// REQ: API-014, OBS-020 (T24.40, ADR-1019) — a probe target with a user or password in its URL is
/// not copied into a row; the section stays served.
#[test]
fn clu_015_t24_40_a_probe_target_with_a_password_is_not_adopted() {
    let own = Config::default();
    let mut served = own.clone();
    served.probe.targets =
        vec![telltale_config::SafeString::new("https://u:p@dns.example/dns-query").unwrap()];
    assert_eq!(crate::managed_adopt::derive(&served, &own).len(), 0);
    served.probe.targets =
        vec![telltale_config::SafeString::new("https://dns.example/dns-query").unwrap()];
    let derived = crate::managed_adopt::derive(&served, &own);
    assert_eq!(derived.len(), 1);
    assert_eq!(derived[0].kind, "probe");
}

/// REQ: CLU-015, OBS-902 (T24.40, T26.4, ADR-1019, ADR-1008) — `[map.geoip]` rides inside the
/// shared `map` kind: a served GeoIP setting is adopted with the thresholds (it holds no secret:
/// `source_url` is refused with credentials, a query string or a fragment), and stripping the row
/// gives the files' `[map]` back.
#[test]
fn clu_015_obs_902_map_geoip_is_adopted_with_the_map() {
    let own = Config::default();
    let mut served = own.clone();
    served.map.geoip.enabled = true;
    served.map.geoip.home_country = Some("NL".into());
    served.map.geoip.source_url = Some("https://mirror.example/geo.csv.gz".into());
    let derived = crate::managed_adopt::derive(&served, &own);
    let kinds: Vec<&str> = derived.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, ["map"]);
    let map = &derived[0].body;
    assert_eq!(map["geoip"]["enabled"], true);
    assert_eq!(map["geoip"]["home_country"], "NL");
    assert_eq!(
        map["geoip"]["source_url"],
        "https://mirror.example/geo.csv.gz"
    );
    let mut stripped = served.clone();
    crate::managed_adopt::strip(&mut stripped, &derived, &own);
    assert_eq!(stripped.map, own.map);
}

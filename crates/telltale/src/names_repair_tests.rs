//! REQ: API-007, DSC-901 (T35.1, ADR-1032) — the one-off repair of names stored with HTML entities.

use serde_json::{Value, json};
use telltale_cluster::node::Role as NodeRole;

use crate::credential_tests::{Harness, harness, harness_toml};
use crate::managed::{CLIENT, GROUP, RULE};
use crate::managed_adopt_tests::{file_of, follow, published};
use crate::names_repair::{ACTION, repair};

const NOW: u64 = 1_700_000_000;

fn put(h: &Harness, kind: &str, name: &str, body: &Value) {
    h.auth
        .state()
        .put_managed(kind, name, &body.to_string(), None, None, 1, "import")
        .unwrap();
}

/// A node holding what an old Pi-hole import stored: two clients named alike once decoded, a
/// group with an entity and a client and a rule that name it, and clean entries beside them.
fn old_import(h: &Harness) {
    put(
        h,
        CLIENT,
        "Alex&#039;s PC",
        &json!({"name": "Alex&#039;s PC", "match": ["192.168.1.20"], "groups": ["Kids &amp; Teens"]}),
    );
    // A clean name that the decoded one would collide with.
    put(
        h,
        CLIENT,
        "Tom & Jerry",
        &json!({"name": "Tom & Jerry", "match": ["192.168.1.30"]}),
    );
    put(
        h,
        CLIENT,
        "Tom &amp; Jerry",
        &json!({"name": "Tom &amp; Jerry", "match": ["aa:bb:cc:dd:ee:0f"]}),
    );
    put(
        h,
        CLIENT,
        "plain",
        &json!({"name": "plain", "match": ["192.168.1.40"]}),
    );
    put(
        h,
        GROUP,
        "Kids &amp; Teens",
        &json!({"name": "Kids &amp; Teens"}),
    );
    put(
        h,
        RULE,
        "r1",
        &json!({"id": "r1", "action": "block", "domain": "game.example.com",
                "devices": ["Alex&#039;s PC"], "groups": ["Kids &amp; Teens"]}),
    );
}

fn names(h: &Harness, kind: &str) -> Vec<String> {
    h.auth
        .state()
        .managed(kind)
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect()
}

fn audits(h: &Harness) -> usize {
    h.auth
        .state()
        .audit_page(None, 50, Some(ACTION), None)
        .unwrap()
        .len()
}

#[tokio::test]
async fn api_007_t35_1_repair_decodes_stored_names_and_what_names_them() {
    let h = harness("");
    old_import(&h);
    let file = file_of(&h);
    let r = repair(h.auth.state(), &file, &[], NOW).unwrap();
    assert!(r.version.is_some(), "one change was stored: {r:?}");
    assert_eq!(r.renamed.len(), 3, "{r:?}");
    assert!(r.skipped.is_empty(), "{:?}", r.skipped);

    let clients = names(&h, CLIENT);
    assert!(clients.contains(&"Alex's PC".to_owned()), "{clients:?}");
    // The collision is told apart by the device's own tail (the MAC), never " (2)".
    assert!(clients.contains(&"Tom & Jerry".to_owned()), "{clients:?}");
    assert!(
        clients.contains(&"Tom & Jerry (ee:0f)".to_owned()),
        "{clients:?}"
    );
    assert!(clients.contains(&"plain".to_owned()));
    assert!(
        clients
            .iter()
            .all(|n| !n.contains("&#") && !n.contains("&amp;"))
    );
    assert_eq!(clients.len(), 4, "renamed, not copied: {clients:?}");
    assert_eq!(names(&h, GROUP), vec!["Kids & Teens".to_owned()]);

    // What names them follows: the client's groups, the rule's devices and groups.
    let rows = h.auth.state().managed(CLIENT).unwrap();
    let pc = rows.iter().find(|m| m.name == "Alex's PC").unwrap();
    let body: Value = serde_json::from_str(&pc.body).unwrap();
    assert_eq!(body["name"], "Alex's PC");
    assert_eq!(body["groups"], json!(["Kids & Teens"]));
    let rule: Value = serde_json::from_str(&h.auth.state().managed(RULE).unwrap()[0].body).unwrap();
    assert_eq!(rule["devices"], json!(["Alex's PC"]));
    assert_eq!(rule["groups"], json!(["Kids & Teens"]));

    // One audited system change.
    let page = h
        .auth
        .state()
        .audit_page(None, 50, Some(ACTION), None)
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].actor_kind, "system");
    assert!(
        page[0].detail.contains("Alex&#039;s PC"),
        "{}",
        page[0].detail
    );

    // The node builds on the repaired rows.
    let merged = crate::managed::merge(&file, &crate::managed::entries(h.auth.state())).unwrap();
    assert!(
        merged
            .client
            .iter()
            .any(|c| c.name.as_str() == "Alex's PC")
    );
}

#[tokio::test]
async fn api_007_t35_1_repair_is_idempotent_across_passes_and_restarts() {
    let h = harness("");
    old_import(&h);
    let file = file_of(&h);
    let first = repair(h.auth.state(), &file, &[], NOW).unwrap();
    let version = first.version.unwrap();
    let rows = h.auth.state().managed(CLIENT).unwrap();
    // A second pass, and a restart (the store reopened from disk): nothing to do, nothing written.
    let second = repair(h.auth.state(), &file, &[], NOW + 60).unwrap();
    assert!(second.version.is_none() && second.renamed.is_empty());
    let reopened = telltale_store::state::State::open(&h.dir_path().join("state.db")).unwrap();
    let third = repair(&reopened, &file, &[], NOW + 120).unwrap();
    assert!(third.version.is_none() && third.renamed.is_empty());
    assert_eq!(
        reopened.config_version().unwrap(),
        version,
        "the version didn't move"
    );
    assert_eq!(
        reopened.managed(CLIENT).unwrap(),
        rows,
        "no row was rewritten"
    );
    assert_eq!(audits(&h), 1, "one audit entry in all");
}

#[tokio::test]
async fn api_007_t35_1_clean_stores_are_never_touched() {
    let h = harness("");
    put(
        &h,
        CLIENT,
        "plain",
        &json!({"name": "plain", "match": ["192.168.1.40"]}),
    );
    put(
        &h,
        CLIENT,
        "a & b",
        &json!({"name": "a & b", "match": ["192.168.1.41"]}),
    );
    let v = h.auth.state().config_version().unwrap();
    let r = repair(h.auth.state(), &file_of(&h), &[], NOW).unwrap();
    assert!(r.version.is_none() && r.renamed.is_empty());
    assert_eq!(h.auth.state().config_version().unwrap(), v);
    assert_eq!(audits(&h), 0);
}

fn harness_of(toml: &str) -> Harness {
    harness_toml(
        toml,
        None,
        vec![telltale_config::Cidr::parse("127.0.0.0/8").unwrap()],
        telltale_api::auth::Settings::default(),
    )
}

#[tokio::test]
async fn api_007_t35_1_file_entries_are_reported_and_never_rewritten() {
    let toml = r#"
[[group]]
name = "Files &amp; Co"

[[client]]
name = "File&#039;s TV"
match = ["192.168.9.9"]
"#;
    let h = harness_of(toml);
    let dir = h.dir_path().join("conf");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("telltale.toml");
    std::fs::write(&path, toml).unwrap();
    let other = dir.join("other.toml");
    std::fs::write(&other, "# nothing\n").unwrap();
    // An API override of the file's client (same name) is the file's name too: left alone.
    put(
        &h,
        CLIENT,
        "File&#039;s TV",
        &json!({"name": "File&#039;s TV", "match": ["192.168.9.9"]}),
    );
    let file = file_of(&h);
    let r = repair(h.auth.state(), &file, &[path, other], NOW).unwrap();
    assert!(r.renamed.is_empty(), "{r:?}");
    assert!(r.version.is_none());
    assert_eq!(r.file_entries.len(), 2, "{:?}", r.file_entries);
    for f in &r.file_entries {
        assert_eq!(f.files, vec!["telltale.toml".to_owned()], "{f:?}");
    }
    assert_eq!(names(&h, CLIENT), vec!["File&#039;s TV".to_owned()]);
    assert!(r.skipped.iter().any(|(_, n, _)| n == "File&#039;s TV"));
}

#[tokio::test]
async fn api_007_t35_1_a_group_a_file_defines_is_left_as_it_is() {
    let toml = r#"
[[group]]
name = "Kids &amp; Teens"

[[client]]
name = "kid"
match = ["192.168.9.9"]
groups = ["Kids &amp; Teens"]
"#;
    let h = harness_of(toml);
    put(
        &h,
        GROUP,
        "Kids &amp; Teens",
        &json!({"name": "Kids &amp; Teens"}),
    );
    let r = repair(h.auth.state(), &file_of(&h), &[], NOW).unwrap();
    assert!(r.renamed.is_empty(), "{r:?}");
    assert_eq!(r.skipped.len(), 1);
    assert_eq!(names(&h, GROUP), vec!["Kids &amp; Teens".to_owned()]);
}

// REQ: CLU-015 — a replica sees the repaired names: the primary publishes its rows and the
// shared configuration like any write, and the follower serves them decoded.
#[tokio::test]
async fn api_007_t35_1_a_replica_sees_the_repaired_names() {
    let (a, b) = (harness(""), harness(""));
    old_import(&a);
    let r = repair(a.auth.state(), &file_of(&a), &[], NOW).unwrap();
    assert!(r.version.is_some());
    let (merged, blob) = published(&a);
    let file = follow(&b, NodeRole::Replica, 1, &merged, &blob);
    let cfg = crate::replication::effective(&file);
    let served: Vec<&str> = cfg.client.iter().map(|c| c.name.as_str()).collect();
    assert!(served.contains(&"Alex's PC"), "{served:?}");
    assert!(
        served
            .iter()
            .all(|n| !n.contains("&#039;") && !n.contains("&amp;")),
        "{served:?}"
    );
    assert!(cfg.group.iter().any(|g| g.name.as_str() == "Kids & Teens"));
    // The replica keeps no rows of its own (it follows the primary's).
    assert_eq!(names(&b, CLIENT).len(), 0);
}

// REQ: T35.1 — the task's pass on a standalone node: stored, audited, and applied by a reload.
#[tokio::test]
async fn api_007_t35_1_the_task_repairs_and_reloads_the_node() {
    let h = harness("");
    old_import(&h);
    crate::names_repair::run_once(&h.src).await;
    assert_eq!(audits(&h), 1);
    let cfg = h.src.config.load();
    assert!(cfg.client.iter().any(|c| c.name.as_str() == "Alex's PC"));
    // Run again: nothing more happens.
    crate::names_repair::run_once(&h.src).await;
    assert_eq!(audits(&h), 1);
}

#[test]
fn api_007_t35_1_file_names_become_a_health_note() {
    let toml = "[[client]]\nname = \"File&#039;s TV\"\nmatch = [\"192.168.9.9\"]\n";
    let cfg = crate::credential_tests::config(toml);
    let found = crate::names_repair::file_findings(&cfg, &[]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].kind, "device");
}

//! REQ: API-007, DSC-901 (T35.1, ADR-1032) — the one-off repair of names stored with HTML entities.

use serde_json::{Value, json};
use wrendns_cluster::node::Role as NodeRole;

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
    assert!(merged.client.iter().any(|c| c.name.as_str() == "Alex's PC"));
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
    let reopened = wrendns_store::state::State::open(&h.dir_path().join("state.db")).unwrap();
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
        vec![wrendns_config::Cidr::parse("127.0.0.0/8").unwrap()],
        wrendns_api::auth::Settings::default(),
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
    let path = dir.join("wrendns.toml");
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
        assert_eq!(f.files, vec!["wrendns.toml".to_owned()], "{f:?}");
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

// REQ: API-007 (T35.1, ADR-1032) — one-off: a name that keeps one escape layer after the pass, and
// one typed after it, are never decoded again.
#[tokio::test]
async fn api_007_t35_1_repair_runs_once_and_keeps_one_layer() {
    let h = harness("");
    put(
        &h,
        CLIENT,
        "&amp;amp;",
        &json!({"name": "&amp;amp;", "match": ["192.168.1.50"]}),
    );
    put(
        &h,
        CLIENT,
        "Double&amp;#039;d",
        &json!({"name": "Double&amp;#039;d", "match": ["192.168.1.51"]}),
    );
    let file = file_of(&h);
    let first = repair(h.auth.state(), &file, &[], NOW).unwrap();
    assert_eq!(first.renamed.len(), 2, "{first:?}");
    let mut clients = names(&h, CLIENT);
    clients.sort();
    assert_eq!(
        clients,
        vec!["&amp;".to_owned(), "Double&#039;d".to_owned()]
    );
    let audited = audits(&h);

    // A name typed after the pass.
    put(
        &h,
        CLIENT,
        "R&amp;D lab",
        &json!({"name": "R&amp;D lab", "match": ["192.168.1.52"]}),
    );
    let second = repair(h.auth.state(), &file, &[], NOW + 60).unwrap();
    assert!(
        second.version.is_none() && second.renamed.is_empty(),
        "{second:?}"
    );
    let mut after = names(&h, CLIENT);
    after.sort();
    assert_eq!(
        after,
        vec![
            "&amp;".to_owned(),
            "Double&#039;d".to_owned(),
            "R&amp;D lab".to_owned()
        ]
    );
    assert_eq!(audits(&h), audited, "no second audit entry");
}

// REQ: API-007 (T35.1) — a pass that finds nothing marks the database too, so a name typed
// later is not touched.
#[tokio::test]
async fn api_007_t35_1_a_pass_that_finds_nothing_still_marks_the_database() {
    let h = harness("");
    let file = file_of(&h);
    let first = repair(h.auth.state(), &file, &[], NOW).unwrap();
    assert!(first.version.is_none());
    put(
        &h,
        CLIENT,
        "R&amp;D lab",
        &json!({"name": "R&amp;D lab", "match": ["192.168.1.52"]}),
    );
    let second = repair(h.auth.state(), &file, &[], NOW + 60).unwrap();
    assert!(second.renamed.is_empty(), "{second:?}");
    assert_eq!(names(&h, CLIENT), vec!["R&amp;D lab".to_owned()]);
}

// REQ: API-007 (T35.1) — a renamed device or group is followed in the log exclusions, the
// anomaly mutes, the drill, the zones and the Kubernetes map; a group an agent token is limited
// to is left as it is.
#[tokio::test]
async fn api_007_t35_1_repair_follows_every_stored_reference() {
    use crate::managed::{ANOMALY_MUTE, DRILL, EXCLUSIONS, KUBERNETES_MAP, ZONE};
    let h = harness("");
    put(
        &h,
        CLIENT,
        "Alex&#039;s PC",
        &json!({"name": "Alex&#039;s PC", "match": ["192.168.1.20"], "groups": ["Kids &amp; Teens"]}),
    );
    put(
        &h,
        GROUP,
        "Kids &amp; Teens",
        &json!({"name": "Kids &amp; Teens"}),
    );
    put(
        &h,
        EXCLUSIONS,
        "default",
        &json!({"enabled": true, "log": {"clients": ["Alex&#039;s PC", "10.0.0.0/8"]}}),
    );
    put(
        &h,
        ANOMALY_MUTE,
        "m1",
        &json!({"name": "m1", "devices": ["Alex&#039;s PC"], "groups": ["Kids &amp; Teens"], "kinds": ["beacon"]}),
    );
    put(
        &h,
        DRILL,
        "default",
        &json!({"clients": ["Alex&#039;s PC"], "group": "Kids &amp; Teens"}),
    );
    put(
        &h,
        ZONE,
        "home.example.com",
        &json!({"name": "home.example.com", "groups": ["Kids &amp; Teens"],
                "record": [{"name": "nas.home.example.com", "type": "A", "value": "10.0.0.9"}]}),
    );
    put(
        &h,
        KUBERNETES_MAP,
        "k1",
        &json!({"namespace": "kids", "group": "Kids &amp; Teens"}),
    );
    let why = crate::managed::merge(&file_of(&h), &crate::managed::entries(h.auth.state())).err();
    assert!(why.is_none(), "{why:?}");
    let r = repair(h.auth.state(), &file_of(&h), &[], NOW).unwrap();
    assert_eq!(r.renamed.len(), 2, "{r:?} {:?}", r.skipped);
    let body = |kind: &str, name: &str| -> Value {
        let row = h
            .auth
            .state()
            .managed(kind)
            .unwrap()
            .into_iter()
            .find(|m| m.name == name)
            .unwrap_or_else(|| panic!("{kind} {name}"));
        serde_json::from_str(&row.body).unwrap()
    };
    assert_eq!(
        body(EXCLUSIONS, "default")["log"]["clients"],
        json!(["Alex's PC", "10.0.0.0/8"])
    );
    let mute = body(ANOMALY_MUTE, "m1");
    assert_eq!(mute["devices"], json!(["Alex's PC"]));
    assert_eq!(mute["groups"], json!(["Kids & Teens"]));
    let drill = body(DRILL, "default");
    assert_eq!(drill["clients"], json!(["Alex's PC"]));
    assert_eq!(drill["group"], "Kids & Teens");
    assert_eq!(
        body(ZONE, "home.example.com")["groups"],
        json!(["Kids & Teens"])
    );
    assert_eq!(body(KUBERNETES_MAP, "k1")["group"], "Kids & Teens");
}

#[tokio::test]
async fn api_007_t35_1_repair_leaves_a_group_an_agent_token_is_limited_to() {
    let h = harness("");
    put(
        &h,
        GROUP,
        "Kids &amp; Teens",
        &json!({"name": "Kids &amp; Teens"}),
    );
    let user = h
        .auth
        .state()
        .create_user("agent-owner", "x", "admin", false, NOW)
        .unwrap()
        .id;
    h.auth
        .state()
        .create_token("tok1", user, "t", &[1, 2, 3], "read", None, NOW)
        .unwrap();
    h.auth
        .state()
        .set_token_agent("tok1", "read", Some("Kids &amp; Teens"), None)
        .unwrap();
    let r = repair(h.auth.state(), &file_of(&h), &[], NOW).unwrap();
    assert!(r.renamed.is_empty(), "{r:?}");
    assert!(
        r.skipped
            .iter()
            .any(|(_, _, why)| why.contains("agent token")),
        "{:?}",
        r.skipped
    );
    assert_eq!(names(&h, GROUP), vec!["Kids &amp; Teens".to_owned()]);
}

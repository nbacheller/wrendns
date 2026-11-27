// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: DSC-908, DSC-910, DSC-913 (T36.10a) - the locations API end to end on a real node:
//! create, replace, read and remove, validation, the files winning, the device override, and the
//! compatibility gate (the first location, or the first device pin, waits for every member).

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::credential_tests::{harness, harness_in};
use crate::secrets_api_tests::{GATE, pair, pair_features};

const DOMAIN: &str = "[local]\ndevice_domain = \"home.arpa\"\n";

fn body(networks: &[&str]) -> Value {
    json!({ "label": "Home", "networks": networks })
}

/// A location is made, read, replaced and removed through the API; a dry run changes nothing; the
/// node applies it (the effective configuration has it); the audit log names the write.
#[tokio::test]
async fn dsc_913_a_location_is_created_read_replaced_and_removed() {
    let h = harness(DOMAIN);
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/locations/home?dryRun=true",
            Some(&body(&["192.0.2.0/24"])),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["applied"], false, "{v}");
    assert!(
        h.src.config.load().location.is_empty(),
        "a dry run changes nothing"
    );

    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/locations/home",
            Some(&json!({
                "label": "Home",
                "networks": ["192.0.2.0/24", "vlan:30"],
                "visibility": "private",
                "flatNames": false,
            })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["applied"], true, "{v}");
    let l = h.src.config.load().location.clone();
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].slug.as_str(), "home");
    assert!(!l[0].flat_names);

    let (s, _, v) = h.call("GET", "/api/v1/locations", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let item = &v["items"][0];
    assert_eq!(item["slug"], "home");
    assert_eq!(item["source"], "api");
    assert_eq!(item["domain"], "home.arpa");
    assert!(
        item.get("ownDomain").is_none(),
        "a location with no domain of its own follows device_domain, and says so: {item}"
    );
    assert_eq!(item["visibility"], "private");
    assert_eq!(item["flatNames"], false);
    assert_eq!(item["networks"][0]["resolved"][0], "192.0.2.0/24");
    assert_eq!(item["networks"][1]["entry"], "vlan:30");
    assert_eq!(
        item["networks"][1]["note"], "no network reported",
        "a VLAN no router reported matches nothing, and says so"
    );
    let (s, _, one) = h.call("GET", "/api/v1/locations/home", None).await;
    assert_eq!(s, StatusCode::OK, "{one}");
    assert_eq!(one["slug"], "home");
    let (s, _, _) = h.call("GET", "/api/v1/locations/nope", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Replace: the whole location, with the defaults for what is left out.
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/locations/home",
            Some(&json!({ "networks": ["198.51.100.0/24"] })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let l = h.src.config.load().location.clone();
    assert_eq!(l.len(), 1);
    assert!(l[0].flat_names && l[0].label.is_none(), "{l:?}");
    assert_eq!(l[0].networks[0].as_str(), "198.51.100.0/24");

    let audit = h.audit_text();
    assert!(audit.contains("location"), "{audit}");

    let (s, _, v) = h.call("DELETE", "/api/v1/locations/home", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(h.src.config.load().location.len(), 0);
    let (s, _, _) = h.call("DELETE", "/api/v1/locations/home", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// A refused table names the bad field and leaves the configuration alone: a bad slug, an overlap
/// with another location (naming it), a bad visibility, a missing network, an unknown field, and
/// a location with no domain anywhere.
#[tokio::test]
async fn dsc_908_a_bad_location_is_refused_and_changes_nothing() {
    let h = harness(DOMAIN);
    let (s, _, _) = h
        .call("PUT", "/api/v1/locations/a", Some(&body(&["192.0.2.0/24"])))
        .await;
    assert_eq!(s, StatusCode::OK);
    for (slug, b, want) in [
        ("bad_slug", body(&["198.51.100.0/24"]), "slug"),
        ("b", body(&["192.0.2.128/25"]), "overlaps location `a`"),
        ("c", body(&["10.0.0.0"]), "CIDR"),
        ("d", body(&["vlan:5000"]), "1 to 4094"),
        ("e", json!({ "networks": [] }), "networks"),
        (
            "f",
            json!({ "networks": ["198.51.100.0/24"], "visibility": "secret" }),
            "visibility",
        ),
    ] {
        let (s, _, v) = h
            .call("PUT", &format!("/api/v1/locations/{slug}"), Some(&b))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{slug}: {v}");
        assert!(v.to_string().contains(want), "{slug}: {v}");
    }
    let (s, _, _) = h
        .call(
            "PUT",
            "/api/v1/locations/g",
            Some(&json!({ "networks": ["198.51.100.0/24"], "bogus": 1 })),
        )
        .await;
    assert!(s.is_client_error(), "{s}");
    assert_eq!(h.src.config.load().location.len(), 1, "nothing was added");

    // No domain anywhere: refused, saying what to set.
    let bare = harness_in("", None);
    let (s, _, v) = bare
        .call(
            "PUT",
            "/api/v1/locations/home",
            Some(&body(&["192.0.2.0/24"])),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v.to_string().contains("device_domain"), "{v}");
    let (s, _, v) = bare
        .call(
            "PUT",
            "/api/v1/locations/home",
            Some(&json!({ "networks": ["192.0.2.0/24"], "domain": "example.net" })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "a domain of its own is enough: {v}");
    let (_, _, v) = bare.call("GET", "/api/v1/locations", None).await;
    assert_eq!(v["items"][0]["ownDomain"], "example.net", "{v}");
}

/// A location the files define is read-only through the API (ADR-040): 409, and it is listed as
/// `file`.
#[tokio::test]
async fn dsc_908_a_location_in_the_files_is_read_only_here() {
    let h = harness(&format!(
        "{DOMAIN}[[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\"]\n"
    ));
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/locations/home",
            Some(&body(&["198.51.100.0/24"])),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, _, _) = h.call("DELETE", "/api/v1/locations/home", None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (_, _, v) = h.call("GET", "/api/v1/locations", None).await;
    assert_eq!(v["items"][0]["source"], "file", "{v}");
}

/// DSC-910 - a device is pinned to a location through its own entry: a slug that names no
/// location is refused, a known one is kept and shown (with it pinned), and a location a device is
/// pinned to cannot be removed first.
#[tokio::test]
async fn dsc_910_a_device_is_pinned_to_a_location_through_its_entry() {
    let h = harness(DOMAIN);
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/clients/laptop",
            Some(&json!({ "match": ["192.0.2.9"], "location": "lab" })),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v.to_string().contains("no location `lab`"), "{v}");
    let (s, _, _) = h
        .call(
            "PUT",
            "/api/v1/locations/lab",
            Some(&body(&["198.51.100.0/24"])),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/clients/laptop",
            Some(&json!({ "match": ["192.0.2.9"], "location": "lab" })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, _, v) = h.call("GET", "/api/v1/clients", None).await;
    let c = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "laptop")
        .unwrap();
    assert_eq!(c["location"], "lab", "{c}");
    assert_eq!(c["locationPinned"], true, "{c}");
    let (s, _, v) = h.call("DELETE", "/api/v1/locations/lab", None).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v.to_string().contains("no location `lab`"), "{v}");
    // Unpin, then it goes.
    let (s, _, _) = h
        .call(
            "PUT",
            "/api/v1/clients/laptop",
            Some(&json!({ "match": ["192.0.2.9"] })),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = h.call("DELETE", "/api/v1/locations/lab", None).await;
    assert_eq!(s, StatusCode::OK);
}

/// REQ: DSC-908 (ADR-1096 point 5) - the first location is refused while a cluster member's build
/// does not announce locations, naming the member and its version (dry runs too), even when it
/// carries the same version number as this one (a development build of 1.1.0); so is the first
/// device pin; and once the member's build knows the table the write goes through, and a second
/// location is never held.
#[tokio::test]
async fn dsc_908_the_first_location_waits_for_every_members_build() {
    let _turn = GATE.lock().await;
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    let ph = harness_in(DOMAIN, Some(Arc::clone(&old.primary)));
    crate::http::serve_peers(&ph.src);
    for dry in ["?dryRun=true", ""] {
        let (s, _, v) = ph
            .call(
                "PUT",
                &format!("/api/v1/locations/home{dry}"),
                Some(&body(&["192.0.2.0/24"])),
            )
            .await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert_eq!(v["code"], "upgrade_required", "{v}");
        let d = v["detail"].as_str().unwrap();
        assert!(
            d.contains("version 1.1.0-edge.40") && d.contains("does not know locations"),
            "{v}"
        );
    }
    assert_eq!(ph.src.config.load().location.len(), 0);
    // A pin is judged through its location: no `home` exists here, so validation refuses it
    // (the gate itself is shown for a pin by `uses_locations` below).
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/clients/laptop",
            Some(&json!({ "match": ["192.0.2.9"], "location": "home" })),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{s} {v}");
    assert!(v.to_string().contains("no location `home`"), "{v}");
    // An ordinary device is not held.
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/clients/tv",
            Some(&json!({ "match": ["192.0.2.30"] })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The held set is one per process and the crate's tests share it, so this looks for its own
    // feature's refusal and does not count the others.
    let holds = crate::upgrade_gate::standing(Some(&old.primary));
    assert!(
        holds.iter().any(|h| h.contains("does not know locations")),
        "{holds:?}"
    );
    let _ = old.stop.send(true);

    let new = pair("1.1.0", "1.1.0").await;
    let ph = harness_in(DOMAIN, Some(Arc::clone(&new.primary)));
    crate::http::serve_peers(&ph.src);
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/locations/home",
            Some(&body(&["192.0.2.0/24"])),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/locations/lab",
            Some(&body(&["198.51.100.0/24"])),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        crate::upgrade_gate::standing(Some(&new.primary)),
        Vec::<String>::new()
    );
    let _ = new.stop.send(true);
}

/// REQ: DSC-908 - the file loader's half of the gate: a reload that adds the first location is
/// refused while a member's build does not know the table (the judgement the reload makes is the
/// same one the API makes), and one that does not add it is not held.
#[tokio::test]
async fn dsc_908_the_file_loader_holds_the_first_location_too() {
    let _turn = GATE.lock().await;
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    let none = crate::credential_tests::config(DOMAIN);
    let with = crate::credential_tests::config(&format!(
        "{DOMAIN}[[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\"]\n"
    ));
    let why = crate::upgrade_gate::enforce_locations(Some(&old.primary), &none, &with).unwrap_err();
    assert!(
        why.contains("version 1.1.0-edge.40") && why.contains("does not know locations"),
        "{why}"
    );
    // The gate the reload itself runs (every cause: SIGHUP, an API change, a Git commit): it
    // refuses, so the reload returns false before anything is swapped.
    let ph = harness_in(DOMAIN, Some(Arc::clone(&old.primary)));
    let why = crate::server::reload_gate(&ph.src, &none, &with).unwrap_err();
    assert!(why.contains("does not know locations"), "{why}");
    assert!(crate::server::reload_gate(&ph.src, &none, &none).is_ok());
    assert!(crate::server::reload_gate(&ph.src, &with, &with).is_ok());
    // A Git commit's refusal is the commit's `refused` error.
    let mut st = crate::gitsource::Status {
        commit: Some("0123456789abcdef".into()),
        ..crate::gitsource::Status::default()
    };
    crate::gitsource::mark_gate_refusal(&mut st, &why);
    assert!(
        st.refused
            && st
                .error
                .as_deref()
                .unwrap()
                .starts_with("commit 0123456789ab: ")
    );
    // No change in use: not held. Already in use: later reloads are not held either.
    assert!(crate::upgrade_gate::enforce_locations(Some(&old.primary), &none, &none).is_ok());
    assert!(crate::upgrade_gate::enforce_locations(Some(&old.primary), &with, &with).is_ok());
    // A standalone node has no members to wait for.
    assert!(crate::upgrade_gate::enforce_locations(None, &none, &with).is_ok());
    let _ = old.stop.send(true);
    // The pin alone counts as using locations.
    let pinned = crate::credential_tests::config(&format!(
        "{DOMAIN}[[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\"]\n[[client]]\nname = \"x\"\nmatch = [\"192.0.2.9\"]\nlocation = \"home\"\n"
    ));
    assert!(crate::upgrade_gate::uses_locations(&pinned));
    assert!(!crate::upgrade_gate::uses_locations(&none));
    // Only the pin (built in code, no table): the pin branch alone makes it true.
    let mut only_pin = pinned.clone();
    only_pin.location.clear();
    assert!(only_pin.client.iter().any(|c| c.location.is_some()));
    assert!(crate::upgrade_gate::uses_locations(&only_pin));
    // Only the table: the table branch alone.
    let mut only_table = pinned.clone();
    for c in &mut only_table.client {
        c.location = None;
    }
    assert!(crate::upgrade_gate::uses_locations(&only_table));
}

/// REQ: DSC-913, DSC-910 (AGT-001..005) - the read tools and the plan tools: the listings and the
/// plans are in the catalog; a plan needs a reason, and there is no direct write tool.
#[test]
fn dsc_913_the_mcp_catalog_has_the_location_tools() {
    let catalog = wrendns_api::mcp::catalog();
    let names: Vec<&str> = catalog
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    for n in [
        "list_locations",
        "get_location",
        "plan_set_location",
        "plan_set_device_location",
    ] {
        assert!(names.contains(&n), "{n} is missing from {names:?}");
    }
    let plan = catalog
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "plan_set_location")
        .unwrap();
    assert!(
        plan["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("reason")),
        "a plan names its reason"
    );
}

const HELD: &str = "[local]\ndevice_domain = \"home.arpa\"\n\
    [[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\"]\n\
    [[client]]\nname = \"x\"\nmatch = [\"192.0.2.9\"]\nlocation = \"home\"\n";

/// REQ: DSC-908 (T36.10a; ADR-1104 point 5, the owner's decision of 2026-11-26) - a primary that
/// starts with locations while a member's build does not announce them holds the entries out of
/// what it serves and publishes, says why in health, and applies them (the hold ends) once the
/// member announces the feature, with no restart; a node with no cluster is never held.
#[tokio::test]
async fn dsc_908_held_at_start_with_an_older_member_released_when_it_announces() {
    let _turn = GATE.lock().await;
    let file = crate::credential_tests::config(HELD);
    assert!(crate::upgrade_gate::uses_locations(&file));

    // Standalone (not a clustered primary): never held.
    let standalone = crate::upgrade_gate::Hold::new();
    let mut c = file.clone();
    assert!(!standalone.at_start(&mut c, false, false));
    assert!(!standalone.active() && uses_both(&c));

    // Held: the entries and the pin are out of what the node serves and publishes.
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    let mut stripped = file.clone();
    let hold = crate::upgrade_gate::Hold::new();
    assert!(hold.at_start(&mut stripped, true, false));
    assert!(stripped.location.is_empty() && stripped.client.iter().all(|c| c.location.is_none()));
    assert_eq!(stripped.client.len(), 1, "the device itself stays");
    // Later builds of the configuration (a reload) keep them out while the hold stands.
    let mut again = file.clone();
    hold.apply(&mut again);
    assert_eq!(again.location.len(), 0);
    // Published: the shared part (what members receive) has no location and no pin; a member
    // merging it sees none.
    let published = wrendns_config::shared::shared_part(&stripped);
    assert!(!published.to_string().contains("\"home\""), "{published}");
    let member_file = crate::credential_tests::config(DOMAIN);
    let seen = wrendns_config::shared::with_shared(&member_file, &published).unwrap();
    assert!(seen.location.is_empty() && seen.client.iter().all(|c| c.location.is_none()));
    assert!(
        wrendns_config::shared::shared_part(&file)
            .to_string()
            .contains("\"home\""),
        "without the hold the same file publishes its location"
    );
    // Health says why, naming the member.
    let why = hold.reason(Some(&old.primary)).unwrap();
    assert!(why.contains("version 1.1.0-edge.40"), "{why}");
    let reasons = crate::health::locations_held_reasons(Some(&why));
    assert_eq!(reasons[0].code, "locations_held");
    assert!(reasons[0].summary.contains("DNS answers as without them"));
    // The older member keeps the hold.
    assert!(!hold.release(Some(&old.primary), "x") && hold.active());
    let _ = old.stop.send(true);

    // The member announces the feature: the hold ends, the reason clears, and a reload applies.
    let new = pair("1.1.0", "1.1.0").await;
    assert!(hold.release(Some(&new.primary), "x"));
    // The hold stands until the reload has applied them: nothing is published before, but the
    // release reload itself builds with the entries.
    assert!(hold.active());
    let mut during = file.clone();
    hold.apply(&mut during);
    assert!(
        !during.location.is_empty(),
        "the release reload builds with them"
    );
    hold.finish();
    assert!(!hold.active() && hold.reason(Some(&new.primary)).is_none());
    assert!(crate::health::locations_held_reasons(None).is_empty());
    let mut released = file.clone();
    hold.apply(&mut released);
    assert!(!released.location.is_empty(), "applied without a restart");
    let ph = harness_in(DOMAIN, Some(Arc::clone(&new.primary)));
    assert!(crate::server::reload_gate(&ph.src, &stripped, &released).is_ok());
    let _ = new.stop.send(true);
}

/// REQ: DSC-908 (ADR-1096 point 5, ADR-1104 point 5) - a restart of a primary whose cluster already
/// runs locations holds nothing, even with a registered member not yet heard from (or an older
/// one): the last published version carried them, so every member knew the table when let in.
#[tokio::test]
async fn dsc_908_a_restart_of_an_established_cluster_does_not_hold() {
    let _turn = GATE.lock().await;
    let file = crate::credential_tests::config(HELD);
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    let hold = crate::upgrade_gate::Hold::new();
    let mut c = file.clone();
    assert!(
        !hold.at_start(&mut c, true, true),
        "already published: no hold"
    );
    assert!(!hold.active() && uses_both(&c), "the entries stay");
    assert!(hold.reason(Some(&old.primary)).is_none());
    // The first use is still held.
    let mut c = file.clone();
    assert!(hold.at_start(&mut c, true, false));
    let _ = old.stop.send(true);

    // What the node reads of its last published version.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = crate::credential_tests::config(DOMAIN);
    cfg.node.data_dir = wrendns_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
    assert!(!crate::replication::published_uses_locations(&cfg));
    std::fs::create_dir_all(dir.path().join("cluster")).unwrap();
    let put = |v: &Value| {
        std::fs::write(
            dir.path().join("cluster/published-config.json"),
            v.to_string(),
        )
        .unwrap();
    };
    put(&json!({"upstream": []}));
    assert!(!crate::replication::published_uses_locations(&cfg));
    put(&wrendns_config::shared::shared_part(&file));
    assert!(crate::replication::published_uses_locations(&cfg));
    put(&json!({"client": [{"name": "x", "location": "home"}]}));
    assert!(crate::replication::published_uses_locations(&cfg));
}

/// REQ: DSC-908 - when the gate passes but the reload that applies the held entries failed, the
/// hold is back and health still says so (no silent `locations_held` gap); before any release
/// attempt the words say the members are ready, not that a reload failed.
#[tokio::test]
async fn dsc_908_a_failed_release_reload_still_shows_in_health() {
    let _turn = GATE.lock().await;
    let new = pair("1.1.0", "1.1.0").await;
    let hold = crate::upgrade_gate::Hold::new();
    let mut c = crate::credential_tests::config(HELD);
    assert!(hold.at_start(&mut c, true, false));
    // The gate passes but no release was tried: no reload has failed.
    assert_eq!(
        hold.reason(Some(&new.primary)).as_deref(),
        Some(crate::upgrade_gate::READY_WORDS)
    );
    assert!(hold.release(Some(&new.primary), "x"));
    assert!(hold.active(), "the hold stands until the reload applied");
    assert_eq!(
        hold.reason(Some(&new.primary)).as_deref(),
        Some(crate::upgrade_gate::READY_WORDS)
    );
    hold.resume();
    assert_eq!(
        hold.reason(Some(&new.primary)).as_deref(),
        Some(crate::upgrade_gate::RELOAD_FAILED)
    );
    // The next attempt clears the flag.
    assert!(hold.release(Some(&new.primary), "x"));
    assert_eq!(
        hold.reason(Some(&new.primary)).as_deref(),
        Some(crate::upgrade_gate::READY_WORDS)
    );
    let _ = new.stop.send(true);
}

/// REQ: DSC-908 (ADR-1104 point 5) - a node that stops leading while it holds entries never
/// published them: the hold ends without a reload, the entries are named, and health keeps
/// saying so instead of clearing silently.
#[tokio::test]
async fn dsc_908_a_hold_that_ends_because_the_node_stopped_leading_says_so() {
    let _turn = GATE.lock().await;
    let pair = pair("1.1.0", "1.1.0").await;
    let hold = crate::upgrade_gate::Hold::new();
    let mut c = crate::credential_tests::config(HELD);
    assert!(hold.at_start(&mut c, true, false));
    let named = crate::upgrade_gate::describe_held(Some(&crate::credential_tests::config(HELD)));
    assert!(named.contains("home"), "{named}");
    // The replica side of the pair does not lead.
    assert!(
        !hold.release(Some(&pair.replica), &named),
        "no reload to run"
    );
    assert!(!hold.active());
    let why = hold.reason(Some(&pair.replica)).expect("a reason stays");
    assert!(
        why.contains("home") && why.contains("not published"),
        "{why}"
    );
    // Owner decision 2026-11-27: file-only entries are not carried over; the words say so.
    assert!(
        why.contains("were not published before this node stopped leading")
            && why.contains("only a config file holds")
            && why.contains("not carried to the new primary")
            && why.contains("same file"),
        "{why}"
    );
    assert_eq!(
        crate::health::locations_held_reasons(Some(&why))[0].code,
        "locations_held"
    );
    // A new hold forgets it.
    let mut c = crate::credential_tests::config(HELD);
    assert!(hold.at_start(&mut c, true, false));
    assert!(
        !hold
            .reason(Some(&pair.primary))
            .unwrap()
            .contains("not published")
    );
    let _ = pair.stop.send(true);
}

/// REQ: DSC-908 (ADR-1104 rule c; owner decision 2026-11-27) - after a node stopped leading with
/// held entries the Locations list is not held, but carries the reason the entries were not
/// published, so the page can show it.
#[tokio::test]
async fn dsc_908_the_list_carries_the_reason_after_the_node_stopped_leading() {
    let _turn = GATE.lock().await;
    let _end = ClearHold;
    let pair = pair("1.1.0", "1.1.0").await;
    let h = harness_in(DOMAIN, Some(Arc::clone(&pair.replica)));
    let (_, _, v) = h.call("GET", "/api/v1/locations", None).await;
    assert!(v.get("heldReason").is_none(), "no hold, no reason: {v}");
    let mut c = crate::credential_tests::config(HELD);
    assert!(crate::upgrade_gate::HOLD.at_start(&mut c, true, false));
    let named = crate::upgrade_gate::describe_held(Some(&crate::credential_tests::config(HELD)));
    assert!(!crate::upgrade_gate::HOLD.release(Some(&pair.replica), &named));
    let (_, _, v) = h.call("GET", "/api/v1/locations", None).await;
    assert!(v.get("held").is_none(), "the hold is over: {v}");
    let why = v["heldReason"].as_str().expect("the reason stays");
    assert!(
        why.contains("not published before this node stopped leading")
            && why.contains("only a config file holds"),
        "{why}"
    );
    let _ = pair.stop.send(true);
}

/// REQ: DSC-908 (ADR-1104 point 5) - a replica promoted during the hold adopts the `location`
/// rows and the pins from the blob the held primary published, so its promotion reload carries
/// them and the gate judges them (rule c).
#[test]
fn dsc_908_a_replica_promoted_during_the_hold_adopts_the_rows_and_the_pins() {
    let rows = vec![
        (
            crate::managed::LOCATION.to_owned(),
            "lab".to_owned(),
            r#"{"networks":["198.51.100.0/24"]}"#.to_owned(),
        ),
        (
            crate::managed::CLIENT.to_owned(),
            "laptop".to_owned(),
            r#"{"match":["192.0.2.9"],"location":"lab"}"#.to_owned(),
        ),
    ];
    let held = crate::node_managed::strip_held(&crate::node_managed::encode(&rows));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let out = crate::managed_adopt::adopt(&path, "held-blob", || Some(held));
    assert!(matches!(out, crate::managed_adopt::Outcome::Entries(_)));
    let state = wrendns_store::state::State::open(&path).unwrap();
    let locs = state.managed(crate::managed::LOCATION).unwrap();
    assert_eq!(locs.len(), 1, "the location row is the new primary's now");
    let devs = state.managed(crate::managed::CLIENT).unwrap();
    let dev: Value = serde_json::from_str(&devs[0].body).unwrap();
    assert_eq!(
        dev["location"], "lab",
        "the pin is back on the device: {dev}"
    );
}

fn uses_both(c: &wrendns_config::Config) -> bool {
    !c.location.is_empty() && c.client.iter().all(|c| c.location.is_some())
}

/// REQ: DSC-908 - a member not heard from yet is "waiting to hear from the members"; one that is
/// heard and does not know the feature is named with its version.
#[test]
fn dsc_908_the_hold_names_the_member_or_the_wait() {
    use wrendns_cluster::gate::{Blocker, Feature, Refusal};
    let unheard = Refusal {
        feature: Feature::Locations,
        blockers: vec![Blocker {
            node: "n1".into(),
            version: String::new(),
        }],
    };
    assert_eq!(
        crate::upgrade_gate::hold_words(&unheard),
        "waiting to hear from the members"
    );
    let old = Refusal {
        feature: Feature::Locations,
        blockers: vec![Blocker {
            node: "n1".into(),
            version: "1.0.0".into(),
        }],
    };
    assert!(crate::upgrade_gate::hold_words(&old).contains("node n1 runs version 1.0.0"));
}

/// REQ: DSC-908 (ADR-1104 point 5) - a Git commit the gate refused is applied again at a later poll
/// once the members allow it, without a manual reload; while one still refuses, no reload is sent.
#[tokio::test]
async fn dsc_908_a_refused_git_commit_is_retried_when_the_members_allow_it() {
    let _turn = GATE.lock().await;
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = crate::credential_tests::config(DOMAIN);
    cfg.node.data_dir = wrendns_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
    let (reload, mut reloads) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<bool>>(4);
    let src = Arc::new(crate::http::Sources {
        reload,
        ..crate::http::tests::sources_in(dir.path())
    });
    let none = crate::credential_tests::config(DOMAIN);
    let with = crate::credential_tests::config(HELD);
    // The reload that refused the commit left the refusal standing.
    assert!(crate::upgrade_gate::enforce_locations(Some(&old.primary), &none, &with).is_err());
    let counted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c2 = Arc::clone(&counted);
    tokio::spawn(async move {
        while let Some(done) = reloads.recv().await {
            c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = done.send(true);
        }
    });
    let mut retry = true;
    crate::gitsource::retry_pending(&src, &old.primary, &cfg, &mut retry).await;
    assert!(retry, "still refused: kept for the next poll");
    assert_eq!(counted.load(std::sync::atomic::Ordering::SeqCst), 0);
    let _ = old.stop.send(true);

    let new = pair("1.1.0", "1.1.0").await;
    crate::gitsource::retry_pending(&src, &new.primary, &cfg, &mut retry).await;
    assert!(!retry, "applied: nothing left to retry");
    assert_eq!(counted.load(std::sync::atomic::Ordering::SeqCst), 1);
    let _ = new.stop.send(true);
}

/// Ends the process-wide start-up hold when a test ends, however it ends.
struct ClearHold;
impl Drop for ClearHold {
    fn drop(&mut self) {
        crate::upgrade_gate::HOLD.clear();
    }
}

/// Waits up to `secs` seconds for `f`.
async fn within(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..secs * 20 {
        if f() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    f()
}

/// After a write during the hold (the harness reload applies the hold as the server's does): the
/// configuration the node serves has no pin and no location table.
fn served_has_no_pin(h: &crate::credential_tests::Harness) {
    let c = h.src.config.load_full();
    assert!(
        c.location.is_empty(),
        "the table stays out: {:?}",
        c.location
    );
    assert!(
        c.client.iter().all(|c| c.location.is_none()),
        "no pin is served: {:?}",
        c.client
    );
}

fn rpc(id: u64, name: &str, args: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}})
}

/// REQ: DSC-908, DSC-910 (ADR-1104 point 5) - the hold of the process, as the server wires it: while
/// it stands the running configuration has no pins, but a device the API holds is still read with
/// its pin, so the edit forms and the MCP plans (which copy the entry back) keep it; a rename, a
/// regroup, a kind change and a pin to a file's location all go through, and the pin is still
/// there when the hold ends.
#[tokio::test]
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
async fn dsc_910_a_device_edited_during_the_hold_keeps_its_pin() {
    let _turn = GATE.lock().await;
    let _end = ClearHold;
    let h = harness(&format!(
        "{DOMAIN}[[location]]\nslug = \"lab\"\nnetworks = [\"198.51.100.0/24\"]\n\
         [[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\"]\n"
    ));
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/clients/laptop",
            Some(&json!({ "match": ["192.0.2.9"], "kind": "tv", "location": "lab" })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The hold starts: what the node serves has no pin (the server's reload strips each build).
    let mut c = (*h.src.config.load_full()).clone();
    h.src.unheld.store(Some(Arc::new(c.clone())));
    assert!(crate::upgrade_gate::HOLD.at_start(&mut c, true, false));
    h.src.config.store(Arc::new(c));
    assert!(
        h.src
            .config
            .load()
            .client
            .iter()
            .all(|c| c.location.is_none())
    );
    let (_, _, v) = h.call("GET", "/api/v1/clients", None).await;
    let d = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "laptop")
        .cloned()
        .unwrap();
    assert_eq!(d["location"], "lab", "read from the unheld entry: {d}");
    assert_eq!(d["locationPinned"], true, "{d}");

    // The edit form: the entry as read, renamed.
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/clients/laptop",
            Some(
                &json!({ "name": "laptop2", "match": d["match"], "groups": d["groups"],
                "kind": d["kind"], "location": d["location"] }),
            ),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    served_has_no_pin(&h);
    // The MCP plans: rename, regroup, then a pin to the other location (validated against the
    // table the hold keeps out of service).
    for (i, (tool, args)) in [
        (
            "plan_rename_client",
            json!({"client": "laptop2", "newName": "laptop3", "reason": "r"}),
        ),
        (
            "plan_assign_client",
            json!({"client": "laptop3", "groups": ["default"], "reason": "r"}),
        ),
        (
            "plan_set_device_location",
            json!({"device": "laptop3", "location": "home", "reason": "r"}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (_, _, v) = h
            .call("POST", "/mcp", Some(&rpc(i as u64 + 1, tool, &args)))
            .await;
        assert_ne!(v["result"]["isError"], true, "{tool}: {v}");
        let id = v["result"]["structuredContent"]["planId"]
            .as_str()
            .unwrap_or_else(|| panic!("no planId: {v}"))
            .to_owned();
        let (_, _, v) = h
            .call(
                "POST",
                "/mcp",
                Some(&rpc(i as u64 + 10, "apply_plan", &json!({"planId": id}))),
            )
            .await;
        assert_ne!(v["result"]["isError"], true, "{tool} apply: {v}");
        served_has_no_pin(&h);
    }
    // The hold ends and a reload applies: the pin and the kind are in the device.
    crate::upgrade_gate::HOLD.clear();
    let (tx, rx) = tokio::sync::oneshot::channel();
    h.src.reload.send(tx).await.unwrap();
    assert!(rx.await.unwrap());
    let cfg = h.src.config.load_full();
    let c = cfg.client.iter().find(|c| c.name.as_str() == "laptop3");
    let c = c.unwrap_or_else(|| panic!("{:?}", cfg.client));
    assert_eq!(
        c.location.as_ref().map(wrendns_config::SafeString::as_str),
        Some("home")
    );
    assert_eq!(
        c.kind,
        Some(wrendns_config::DeviceClass::Tv),
        "the kind is kept"
    );
}

/// REQ: DSC-908 (ADR-1104 point 5) - while the hold stands the locations read through the API
/// are the configured ones, marked `held` with the reason (not an empty list a caller would
/// recreate from); without a hold the marker is absent.
#[tokio::test]
async fn dsc_908_the_location_list_shows_held_locations_during_the_hold() {
    let _turn = GATE.lock().await;
    let _end = ClearHold;
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    let h = harness_in(HELD, Some(Arc::clone(&old.primary)));
    let (_, _, v) = h.call("GET", "/api/v1/locations", None).await;
    assert!(v.get("held").is_none(), "no hold: {v}");
    let (_, _, one) = h.call("GET", "/api/v1/locations/home", None).await;
    assert!(one.get("held").is_none(), "no hold, no marker: {one}");
    let mut c = (*h.src.config.load_full()).clone();
    h.src.unheld.store(Some(Arc::new(c.clone())));
    assert!(crate::upgrade_gate::HOLD.at_start(&mut c, true, false));
    h.src.config.store(Arc::new(c));
    let (s, _, v) = h.call("GET", "/api/v1/locations", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["held"], true, "{v}");
    assert!(
        v["heldReason"].as_str().unwrap().contains("1.1.0-edge.40"),
        "{v}"
    );
    assert_eq!(v["items"][0]["slug"], "home", "{v}");
    let (s, _, v) = h.call("GET", "/api/v1/locations/home", None).await;
    assert_eq!(s, StatusCode::OK, "a held slug is not a 404: {v}");
    assert_eq!(v["held"], true, "one location carries the marker too: {v}");
    assert!(
        v["heldReason"].as_str().unwrap().contains("1.1.0-edge.40"),
        "{v}"
    );
    let _ = old.stop.send(true);
}

/// REQ: DSC-908 (ADR-1104 point 5) - a replica promoted during the hold adopted entries an older
/// member cannot read: the refused reload leaves the refusal standing, which starts the hold on
/// this node, and the release loop applies the entries once the member is upgraded.
#[tokio::test]
async fn dsc_908_a_promotion_during_the_hold_holds_then_releases() {
    let _turn = GATE.lock().await;
    let _end = ClearHold;
    // The refusals a gate records are process-wide and the tests of the crate leave theirs (the
    // DNS providers' too): start with none standing.
    crate::upgrade_gate::forget_held();
    // Nothing refused: no hold starts.
    let new = pair("1.1.0", "1.1.0").await;
    let none = crate::credential_tests::config(DOMAIN);
    let with = crate::credential_tests::config(HELD);
    assert!(crate::upgrade_gate::enforce_locations(Some(&new.primary), &none, &with).is_ok());
    assert!(!crate::upgrade_gate::hold_after_refusal());
    assert!(!crate::upgrade_gate::HOLD.active());
    // An older member refuses the promotion reload: the hold begins.
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    assert!(crate::upgrade_gate::enforce_locations(Some(&old.primary), &none, &with).is_err());
    assert!(crate::upgrade_gate::hold_after_refusal());
    assert!(crate::upgrade_gate::HOLD.active());
    let _ = old.stop.send(true);
    // The member is upgraded: the loop applies the entries (one reload) and the hold ends.
    let dir = tempfile::tempdir().unwrap();
    let (reload, mut reloads) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<bool>>(4);
    let src = Arc::new(crate::http::Sources {
        reload,
        cluster: Some(Arc::clone(&new.primary)),
        ..crate::http::tests::sources_in(dir.path())
    });
    let reloaded = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&reloaded);
    tokio::spawn(async move {
        while let Some(done) = reloads.recv().await {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = done.send(true);
        }
    });
    let (_stop_tx, stop) = tokio::sync::watch::channel(false);
    crate::upgrade_gate::ensure_release_loop(&src, &stop);
    assert!(
        within(8, || !crate::upgrade_gate::HOLD.active()).await,
        "the hold ends"
    );
    assert_eq!(reloaded.load(std::sync::atomic::Ordering::SeqCst), 1);
    let _ = new.stop.send(true);
}

/// The retry pace of the release loop: 2 s, doubling to 60 s while the reload fails, back to 2 s
/// once it applies.
#[test]
fn dsc_908_the_release_retry_backs_off() {
    use crate::upgrade_gate::next_wait;
    let mut w = 2;
    let mut seen = Vec::new();
    for _ in 0..7 {
        w = next_wait(w, false);
        seen.push(w);
    }
    assert_eq!(seen, [4, 8, 16, 32, 60, 60, 60]);
    assert_eq!(next_wait(60, true), 2);
}

/// How many `locations_held` reasons the node's health lists.
async fn held_reasons(h: &crate::credential_tests::Harness) -> usize {
    let (s, _, v) = h.call("GET", "/api/v1/system/health", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["code"] == "locations_held")
        .count()
}

/// REQ: DSC-908 (ADR-1104 point 5) - the process-wide hold as the server uses it: health says why
/// while it stands (and not after); the release loop leaves it alone while an older member
/// stands, applies the entries by one reload once every member announces the feature, and when
/// that reload does not apply them it puts the hold back and tries again.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn dsc_908_the_process_hold_shows_in_health_and_is_released_by_the_loop() {
    let _turn = GATE.lock().await;
    let _end = ClearHold;
    let mut c = crate::credential_tests::config(HELD);
    assert!(crate::upgrade_gate::HOLD.at_start(&mut c, true, false));
    // An older member: the reason names it, and the loop sends no reload.
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    let h = harness_in(DOMAIN, Some(Arc::clone(&old.primary)));
    crate::http::serve_peers(&h.src);
    assert_eq!(held_reasons(&h).await, 1);
    let dir = tempfile::tempdir().unwrap();
    let make = |cluster: &Arc<wrendns_cluster::net::Cluster>| {
        let (reload, rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<bool>>(4);
        let src = Arc::new(crate::http::Sources {
            reload,
            cluster: Some(Arc::clone(cluster)),
            ..crate::http::tests::sources_in(dir.path())
        });
        (src, rx)
    };
    let (src, mut reloads) = make(&old.primary);
    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(crate::upgrade_gate::release_loop(src, stop));
    tokio::time::sleep(std::time::Duration::from_millis(4500)).await;
    assert!(
        reloads.try_recv().is_err(),
        "no reload while a member is old"
    );
    assert!(crate::upgrade_gate::HOLD.active());
    let _ = stop_tx.send(true);
    let _ = task.await;
    let _ = old.stop.send(true);

    // Every member announces it: the first reload is refused (answered false), so the hold is put
    // back and the loop goes on; the second one applies, and the hold and its reason are gone.
    let new = pair("1.1.0", "1.1.0").await;
    let h = harness_in(DOMAIN, Some(Arc::clone(&new.primary)));
    crate::http::serve_peers(&h.src);
    let (src, mut reloads) = make(&new.primary);
    let (_stop_tx, stop) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(crate::upgrade_gate::release_loop(src, stop));
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c2 = Arc::clone(&count);
    // The hold must stand while the release reload runs (nothing is published before it applied).
    let dropped_early = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let early = Arc::clone(&dropped_early);
    tokio::spawn(async move {
        while let Some(done) = reloads.recv().await {
            if !crate::upgrade_gate::HOLD.active() {
                early.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            let n = c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = done.send(n >= 1);
        }
    });
    assert!(
        within(12, || {
            count.load(std::sync::atomic::Ordering::SeqCst) == 2
                && !crate::upgrade_gate::HOLD.active()
        })
        .await,
        "reloads: {}, held: {}",
        count.load(std::sync::atomic::Ordering::SeqCst),
        crate::upgrade_gate::HOLD.active()
    );
    let _ = task.await;
    assert!(
        !dropped_early.load(std::sync::atomic::Ordering::SeqCst),
        "the hold was cleared before the reload applied the entries"
    );
    assert_eq!(held_reasons(&h).await, 0, "the reason clears with the hold");
    let _ = new.stop.send(true);
}

/// An agent token with `scopes` (stored for the admin, as the sign-in-only route would); its
/// bearer.
fn agent_bearer(h: &crate::credential_tests::Harness, name: &str, scopes: &[&str]) -> String {
    let (id, secret) = (
        wrendns_api::auth::crypto::random_id(),
        wrendns_api::auth::crypto::random_secret(),
    );
    let state = h.auth.state();
    state
        .create_token(
            &id,
            h.admin_id,
            name,
            &wrendns_api::auth::crypto::secret_hash(&secret),
            "admin",
            None,
            crate::pipeline::unix_now(),
        )
        .unwrap();
    state
        .set_token_agent(&id, &scopes.join(" "), None, Some(600))
        .unwrap();
    format!("tt_{id}_{secret}")
}

/// One request as the bearer, with a reason (an agent write needs one).
async fn call_with(
    h: &crate::credential_tests::Harness,
    bearer: &str,
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let mut req = h.request(method, uri, body);
    req.headers_mut()
        .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    req.headers_mut()
        .insert("x-wrendns-reason", "a test".parse().unwrap());
    let (s, _, t) = h.send(req).await;
    (s, serde_json::from_str(&t).unwrap_or(Value::String(t)))
}

fn pin_of(h: &crate::credential_tests::Harness, device: &str) -> Option<String> {
    h.src
        .config
        .load()
        .client
        .iter()
        .find(|c| c.name.as_str() == device)
        .and_then(|c| c.location.as_ref().map(|l| l.as_str().to_owned()))
}

/// One MCP tool call as the bearer.
async fn mcp_as(
    h: &crate::credential_tests::Harness,
    bearer: &str,
    id: u64,
    tool: &str,
    args: Value,
) -> Value {
    let mut req = h.request("POST", "/mcp", Some(&rpc(id, tool, &args)));
    req.headers_mut()
        .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    let (_, _, t) = h.send(req).await;
    serde_json::from_str::<Value>(&t).unwrap()
}

/// Plans `tool` as the bearer and applies the plan; the apply's result.
async fn plan_and_apply(
    h: &crate::credential_tests::Harness,
    bearer: &str,
    tool: &str,
    args: Value,
) -> Value {
    let v = mcp_as(h, bearer, 1, tool, args).await;
    assert_ne!(v["result"]["isError"], true, "{tool}: {v}");
    let id = v["result"]["structuredContent"]["planId"]
        .as_str()
        .unwrap_or_else(|| panic!("no planId: {v}"))
        .to_owned();
    mcp_as(h, bearer, 2, "apply_plan", json!({"planId": id})).await
}

fn device_body(name: &str, extra: &Value) -> Value {
    let mut b = json!({ "match": [format!("203.0.113.{}", name.len())] });
    b.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    b
}

/// REQ: DSC-913, DSC-910 (ADR-1104; the owner's decision of 2026-11-26, through the question
/// tool) - an agent token that would set, change or remove a device's pin needs
/// `config:write:locations` as well as `config:write:clients`: the direct write, the MCP device
/// plans and the delete; a write that leaves the pin as it is passes and keeps it; a token
/// holding both scopes pins.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn dsc_913_an_agent_pins_a_device_only_with_both_scopes() {
    let h = harness(DOMAIN);
    for (slug, net) in [("lab", "198.51.100.0/24"), ("home", "192.0.2.0/24")] {
        let (s, _, v) = h
            .call(
                "PUT",
                &format!("/api/v1/locations/{slug}"),
                Some(&body(&[net])),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    // A pinned device and an unpinned one, made by an operator.
    for (name, extra) in [("pinned", json!({"location": "lab"})), ("plain", json!({}))] {
        let (s, _, v) = h
            .call(
                "PUT",
                &format!("/api/v1/clients/{name}"),
                Some(&device_body(name, &extra)),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let clients = agent_bearer(&h, "clients-only", &["config:read", "config:write:clients"]);
    let both = agent_bearer(
        &h,
        "both",
        &[
            "config:read",
            "config:write:clients",
            "config:write:locations",
        ],
    );
    let refused = |s: StatusCode, v: &Value, what: &str| {
        assert_eq!(s, StatusCode::FORBIDDEN, "{what}: {v}");
        assert!(
            v.to_string().contains("config:write:locations"),
            "{what}: {v}"
        );
    };

    // Direct writes without the locations scope: set, change, remove (empty, or left out), delete.
    for (what, uri, b) in [
        (
            "set",
            "/api/v1/clients/plain",
            device_body("plain", &json!({"location": "lab"})),
        ),
        (
            "change",
            "/api/v1/clients/pinned",
            device_body("pinned", &json!({"location": "home"})),
        ),
        (
            "remove",
            "/api/v1/clients/pinned",
            device_body("pinned", &json!({"location": ""})),
        ),
        (
            "absent",
            "/api/v1/clients/pinned",
            device_body("pinned", &json!({})),
        ),
    ] {
        let (s, v) = call_with(&h, &clients, "PUT", uri, Some(&b)).await;
        refused(s, &v, what);
        // A dry run is refused too.
        let (s, v) = call_with(&h, &clients, "PUT", &format!("{uri}?dryRun=true"), Some(&b)).await;
        refused(s, &v, what);
    }
    let (s, v) = call_with(&h, &clients, "DELETE", "/api/v1/clients/pinned", None).await;
    refused(s, &v, "delete");
    assert_eq!(
        pin_of(&h, "pinned").as_deref(),
        Some("lab"),
        "nothing changed"
    );
    assert_eq!(pin_of(&h, "plain"), None);

    // Leaving the pin as it is passes: a regroup and a rename keep it; an unpinned device is
    // changed freely.
    let (s, v) = call_with(
        &h,
        &clients,
        "PUT",
        "/api/v1/clients/pinned",
        Some(&device_body(
            "pinned",
            &json!({"location": "lab", "groups": ["default"]}),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = call_with(
        &h,
        &clients,
        "PUT",
        "/api/v1/clients/pinned",
        Some(&device_body(
            "pinned",
            &json!({"name": "pinned2", "location": "lab"}),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(pin_of(&h, "pinned2").as_deref(), Some("lab"));
    let (s, v) = call_with(
        &h,
        &clients,
        "PUT",
        "/api/v1/clients/plain",
        Some(&device_body("plain", &json!({"kind": "tv"}))),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // The MCP plans as the clients-only agent: the pin plan is refused (at the plan), the rename
    // and the regroup plans pass and keep the pin.
    for (device, location) in [("plain", "lab"), ("pinned2", "")] {
        let v = mcp_as(
            &h,
            &clients,
            1,
            "plan_set_device_location",
            json!({"device": device, "location": location, "reason": "r"}),
        )
        .await;
        assert_eq!(v["result"]["isError"], true, "{v}");
        assert!(v.to_string().contains("config:write:locations"), "{v}");
    }
    for (tool, args) in [
        (
            "plan_rename_client",
            json!({"client": "pinned2", "newName": "pinned3", "reason": "r"}),
        ),
        (
            "plan_assign_client",
            json!({"client": "pinned3", "groups": ["default"], "reason": "r"}),
        ),
    ] {
        let v = plan_and_apply(&h, &clients, tool, args).await;
        assert_ne!(v["result"]["isError"], true, "{tool} apply: {v}");
    }
    assert_eq!(
        pin_of(&h, "pinned3").as_deref(),
        Some("lab"),
        "the pin is kept"
    );

    // With both scopes the pin is changed and removed, and set by a direct write; the delete of
    // a pinned device passes.
    for (loc, want) in [("home", Some("home")), ("", None)] {
        let v = plan_and_apply(
            &h,
            &both,
            "plan_set_device_location",
            json!({"device": "pinned3", "location": loc, "reason": "r"}),
        )
        .await;
        assert_ne!(v["result"]["isError"], true, "{v}");
        assert_eq!(pin_of(&h, "pinned3").as_deref(), want);
    }
    let (s, v) = call_with(
        &h,
        &both,
        "PUT",
        "/api/v1/clients/plain",
        Some(&device_body("plain", &json!({"location": "lab"}))),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = call_with(&h, &both, "DELETE", "/api/v1/clients/plain", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: DSC-908 (ADR-1104 point 5) - a promoted primary that has published nothing (no
/// `published-config.json`) still knows the cluster runs locations: the version it last applied
/// as a replica carried them, so a restart does not hold them. A published file, when there is
/// one, stays the answer; a last-applied version without locations holds nothing back.
#[test]
fn dsc_908_a_promoted_primary_with_no_published_file_reads_the_applied_version() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = crate::credential_tests::config(DOMAIN);
    cfg.node.data_dir = wrendns_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
    let cluster = dir.path().join("cluster");
    std::fs::create_dir_all(&cluster).unwrap();
    let applied = |shared: &Value| {
        let bytes = shared.to_string().into_bytes();
        let blob = wrendns_cluster::sync::blob_ref("config", &bytes);
        wrendns_cluster::sync::BlobStore::open(dir.path())
            .unwrap()
            .put(&blob, &bytes)
            .unwrap();
        let m = wrendns_cluster::sync::ClusterManifest {
            cluster_id: "c".into(),
            epoch: 1,
            seq: 1,
            primary: "other".into(),
            config: blob,
            ..wrendns_cluster::sync::ClusterManifest::default()
        };
        std::fs::write(
            cluster.join(crate::replication::APPLIED),
            serde_json::to_vec(&m).unwrap(),
        )
        .unwrap();
    };
    // Nothing published and nothing applied: not held back by this check.
    assert!(!crate::replication::published_uses_locations(&cfg));
    applied(&json!({"upstream": []}));
    assert!(!crate::replication::published_uses_locations(&cfg));
    applied(&json!({"location": [{"slug": "home", "networks": ["192.0.2.0/24"]}]}));
    assert!(crate::replication::published_uses_locations(&cfg));
    applied(&json!({"client": [{"name": "x", "location": "home"}]}));
    assert!(crate::replication::published_uses_locations(&cfg));
    // A published file wins over the applied version.
    std::fs::write(cluster.join("published-config.json"), r#"{"upstream": []}"#).unwrap();
    assert!(!crate::replication::published_uses_locations(&cfg));
}

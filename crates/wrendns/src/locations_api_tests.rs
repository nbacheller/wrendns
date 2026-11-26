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
    // A device pin is the same shared change (an older replica refuses the field).
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/clients/laptop",
            Some(&json!({ "match": ["192.0.2.9"], "location": "home" })),
        )
        .await;
    assert!(s.is_client_error(), "{s} {v}");
    // An ordinary device is not held.
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/clients/tv",
            Some(&json!({ "match": ["192.0.2.30"] })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let holds = crate::upgrade_gate::standing(Some(&old.primary));
    assert_eq!(holds.len(), 1, "{holds:?}");
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

// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: FLT-906 (T40.9, ADR-1110) - the compatibility gate for lists in the RPZ format, on real
//! two-node clusters: a list with `format = "rpz"` is refused (409 `upgrade_required`, naming the
//! member) while a member's build does not announce `rpz_lists`, for the API (dry runs too) and
//! the file loader, and goes through once every member announces it.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;
use wrendns_cluster::gate::Feature;

use crate::credential_tests::harness_in;
use crate::secrets_api_tests::{GATE, pair, pair_features};

const DOMAIN: &str = "[local]\ndevice_domain = \"home.arpa\"\n";

/// Every feature this build knows except the RPZ format: a member cut just before this task.
fn without_rpz() -> Vec<String> {
    Feature::ALL
        .iter()
        .filter(|f| **f != Feature::RpzLists)
        .map(|f| f.name().to_owned())
        .collect()
}

#[tokio::test]
async fn flt_906_an_rpz_list_waits_for_every_members_build() {
    let _turn = GATE.lock().await;
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(without_rpz())).await;
    let ph = harness_in(DOMAIN, Some(Arc::clone(&old.primary)));
    crate::http::serve_peers(&ph.src);
    let rpz = json!({ "url": "https://lists.example/policy.rpz", "format": "rpz" });
    for dry in ["?dryRun=true", ""] {
        let (s, _, v) = ph
            .call("PUT", &format!("/api/v1/lists/policy{dry}"), Some(&rpz))
            .await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert_eq!(v["code"], "upgrade_required", "{v}");
        let d = v["detail"].as_str().unwrap();
        assert!(
            d.contains("version 1.1.0-edge.40")
                && d.contains("does not know lists in the RPZ format"),
            "{v}"
        );
    }
    assert!(
        !ph.src
            .config
            .load()
            .list
            .iter()
            .any(|l| l.name.as_str() == "policy"),
        "nothing was stored"
    );
    // An ordinary list is never held (the removal of an RPZ list is checked further down).
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/lists/plain",
            Some(&json!({ "url": "https://lists.example/hosts.txt" })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let holds = crate::upgrade_gate::standing(Some(&old.primary));
    assert!(
        holds
            .iter()
            .any(|h| h.contains("does not know lists in the RPZ format")),
        "{holds:?}"
    );
    // The file loader's half: a reload that adds an RPZ list is refused, one that does not is not.
    let none = crate::credential_tests::config(DOMAIN);
    let with = crate::credential_tests::config(&format!(
        "{DOMAIN}[[list]]\nname = \"policy\"\nurl = \"https://lists.example/policy.rpz\"\nformat = \"rpz\"\n"
    ));
    let why = crate::server::reload_gate(&ph.src, &none, &with).unwrap_err();
    assert!(
        why.contains("does not know lists in the RPZ format"),
        "{why}"
    );
    assert!(crate::server::reload_gate(&ph.src, &none, &none).is_ok());
    assert!(
        crate::server::reload_gate(&ph.src, &with, &with).is_ok(),
        "an unchanged RPZ list is not held again"
    );
    // Removing an RPZ list is never held: through the loader, the gate itself, and the API on a
    // node that already stores one (a list saved before a member was downgraded).
    assert!(crate::server::reload_gate(&ph.src, &with, &none).is_ok());
    assert!(crate::upgrade_gate::enforce_rpz(Some(&old.primary), &with, &none).is_ok());
    let stored = harness_in(
        &format!(
            "{DOMAIN}[[list]]\nname = \"policy\"\nurl = \"https://lists.example/policy.rpz\"\nformat = \"rpz\"\n"
        ),
        Some(Arc::clone(&old.primary)),
    );
    crate::http::serve_peers(&stored.src);
    let (s, _, v) = stored.call("DELETE", "/api/v1/lists/policy", None).await;
    assert!(s.is_success(), "{s} {v}");
    assert!(
        !stored
            .src
            .config
            .load()
            .list
            .iter()
            .any(|l| l.name.as_str() == "policy"),
        "the list is gone"
    );
    // A standalone node has no members to wait for.
    assert!(crate::upgrade_gate::enforce_rpz(None, &none, &with).is_ok());
    let _ = old.stop.send(true);

    let new = pair("1.1.0", "1.1.0").await;
    let ph = harness_in(DOMAIN, Some(Arc::clone(&new.primary)));
    crate::http::serve_peers(&ph.src);
    let (s, _, v) = ph.call("PUT", "/api/v1/lists/policy", Some(&rpz)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let stored = ph.src.config.load().list.clone();
    let policy = stored.iter().find(|l| l.name.as_str() == "policy").unwrap();
    assert_eq!(policy.format, wrendns_config::ListFormat::Rpz);
    // The list view says how it is read.
    let (s, _, v) = ph.call("GET", "/api/v1/lists", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let row = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["name"] == "policy")
        .unwrap();
    assert_eq!(row["format"], "rpz", "{v}");
    let _ = new.stop.send(true);
}

/// A list that is `format = "rpz"` must be a block list (the zone's own rules say what is allowed).
#[tokio::test]
async fn flt_906_an_rpz_list_must_be_a_block_list() {
    let h = crate::credential_tests::harness(DOMAIN);
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/lists/policy",
            Some(
                &json!({ "url": "https://lists.example/p.rpz", "format": "rpz", "kind": "allow" }),
            ),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{s} {v}");
    assert!(v.to_string().contains("needs kind"), "{v}");
}

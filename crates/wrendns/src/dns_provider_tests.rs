// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904, DSC-908 (T36.10b steps b1 and b2; ADR-1084, ADR-1104) - the DNS-provider table on a
//! real node: made, read, replaced and removed through the API, validation naming the field, the
//! files winning, admin only (an agent never), the credential only ever a stored secret's name, the
//! compatibility gate (the first provider waits for every member's build, at the API and at file
//! load) and the start-up hold that now covers providers as well as locations.

#![allow(clippy::many_single_char_names)] // the tests' `h`, `s`, `v`, `p`, `b`, as the other API tests have

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};
use wrendns_api::auth;

use crate::credential_tests::{harness, harness_in};
use crate::secrets_api_tests::{GATE, json_of, pair, pair_features, req_from, token};

/// A value planted in a stored secret: it must never come back anywhere.
const SECRET: &str = "planted-dns-credential-7d21";

fn cloudflare() -> Value {
    json!({"kind": "cloudflare", "zone": "example.net", "credential_ref": "cf"})
}

/// Stores the secret a provider names.
async fn store_secret(h: &crate::credential_tests::Harness, name: &str) {
    let (s, _, v) = h
        .call(
            "PUT",
            &format!("/api/v1/secrets/{name}"),
            Some(&json!({"value": SECRET, "kind": "text"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

fn gone(text: &str) {
    assert!(!text.contains(SECRET), "the credential came back: {text}");
}

/// A provider is made, read, replaced and removed through the API; a dry run changes nothing; the
/// node applies it; the audit log names the write; the credential is a name and never a value; the
/// entry starts in dry run and reads as not used yet.
#[tokio::test]
async fn cld_904_a_dns_provider_is_created_read_replaced_and_removed() {
    let h = harness("");
    store_secret(&h, "cf").await;
    let (s, _, v) = h
        .call(
            "PUT",
            "/api/v1/dns-providers/cf-home?dryRun=true",
            Some(&cloudflare()),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["applied"], false, "{v}");
    assert!(
        h.src.config.load().dns_provider.is_empty(),
        "a dry run changes nothing"
    );

    let (s, _, v) = h
        .call("PUT", "/api/v1/dns-providers/cf-home", Some(&cloudflare()))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["applied"], true, "{v}");
    gone(&v.to_string());
    let p = h.src.config.load().dns_provider.clone();
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].name.as_str(), "cf-home");
    assert!(p[0].dry_run, "a new entry starts in dry run");

    let (s, _, list) = h.call("GET", "/api/v1/dns-providers", None).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    gone(&list.to_string());
    let item = &list["items"][0];
    assert_eq!(item["name"], "cf-home");
    assert_eq!(item["kind"], "cloudflare");
    assert_eq!(item["zone"], "example.net");
    assert_eq!(item["source"], "api");
    assert_eq!(item["dryRun"], true);
    assert_eq!(item["credentialSecret"], "cf");
    assert_eq!(item["credentialPresent"], true);
    assert_eq!(item["state"], "not_used", "{item}");
    assert_eq!(item["definition"]["credential_ref"], "cf");
    assert!(list.get("held").is_none());
    let (s, _, one) = h.call("GET", "/api/v1/dns-providers/cf-home", None).await;
    assert_eq!(s, StatusCode::OK, "{one}");
    assert_eq!(one["name"], "cf-home");
    let (s, _, _) = h.call("GET", "/api/v1/dns-providers/nope", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Replace: the whole entry, with the defaults for what is left out.
    let mut b = cloudflare();
    b["dry_run"] = json!(false);
    b["max_writes_per_hour"] = json!(10);
    let (s, _, v) = h
        .call("PUT", "/api/v1/dns-providers/cf-home", Some(&b))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let p = h.src.config.load().dns_provider.clone();
    assert_eq!(p.len(), 1);
    assert!(!p[0].dry_run && p[0].max_writes_per_hour == 10, "{p:?}");

    let audit = h.audit_text();
    assert!(audit.contains("dns_provider"), "{audit}");
    gone(&audit);

    let (s, _, v) = h
        .call("DELETE", "/api/v1/dns-providers/cf-home", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        h.src.config.load().dns_provider.is_empty(),
        "removed: the table is empty again"
    );
    let (s, _, _) = h
        .call("DELETE", "/api/v1/dns-providers/cf-home", None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// REQ: CLD-904 - a refused entry names the bad field and leaves the configuration alone: a missing
/// reference, an inline credential (refused with the way to do it), a reference to a secret that is
/// not stored (422 `secret_missing`), a bad zone, a kind that needs more, an unknown kind and
/// field, and a body that names another provider than the path.
#[tokio::test]
async fn cld_904_a_bad_provider_is_refused_naming_the_field() {
    let h = harness("");
    store_secret(&h, "cf").await;
    for (name, b, code, want) in [
        (
            "a",
            json!({"kind": "cloudflare", "zone": "example.net"}),
            "invalid_config",
            "credential_ref",
        ),
        (
            "b",
            json!({"kind": "cloudflare", "zone": "example.net", "credential_ref": "cf", "token": "x"}),
            "invalid_config",
            "holds no credential",
        ),
        (
            "c",
            json!({"kind": "cloudflare", "zone": "example.net", "credential_ref": "cf", "credential_file": "/x"}),
            "invalid_config",
            "credential_file",
        ),
        (
            "d",
            json!({"kind": "cloudflare", "zone": "example.net", "credential_ref": "absent"}),
            "secret_missing",
            "`absent`",
        ),
        (
            "e",
            json!({"kind": "cloudflare", "zone": "example", "credential_ref": "cf"}),
            "invalid_config",
            "zone",
        ),
        (
            "f",
            json!({"kind": "azure_dns", "zone": "example.net", "credential_ref": "cf"}),
            "invalid_config",
            "subscription",
        ),
        (
            "g",
            json!({"kind": "godaddy", "zone": "example.net", "credential_ref": "cf"}),
            "invalid_config",
            "godaddy",
        ),
        (
            "h",
            json!({"kind": "cloudflare", "zone": "example.net", "credential_ref": "cf", "bogus": 1}),
            "invalid_config",
            "bogus",
        ),
        (
            "i",
            json!({"name": "other", "kind": "cloudflare", "zone": "example.net", "credential_ref": "cf"}),
            "",
            "the path's",
        ),
    ] {
        let (s, _, v) = h
            .call("PUT", &format!("/api/v1/dns-providers/{name}"), Some(&b))
            .await;
        assert!(
            s == StatusCode::UNPROCESSABLE_ENTITY || s == StatusCode::BAD_REQUEST,
            "{name}: {s} {v}"
        );
        assert!(v.to_string().contains(want), "{name}: {v}");
        if !code.is_empty() {
            assert_eq!(v["code"], code, "{name}: {v}");
        }
    }
    assert!(
        h.src.config.load().dns_provider.is_empty(),
        "a refused write stores nothing"
    );
}

/// REQ: CLD-904 (ADR-040) - a provider the configuration files define is read-only through the
/// API (409 `set_by_file`, a dry run too), and shows as coming from the file.
#[tokio::test]
async fn cld_904_the_files_win() {
    let h = harness(
        "[[dns_provider]]\nname = \"cf-file\"\nkind = \"cloudflare\"\nzone = \"example.net\"\ncredential_ref = \"cf\"\n",
    );
    store_secret(&h, "cf").await;
    for (m, uri, b) in [
        ("PUT", "/api/v1/dns-providers/cf-file", Some(cloudflare())),
        (
            "PUT",
            "/api/v1/dns-providers/cf-file?dryRun=true",
            Some(cloudflare()),
        ),
        ("DELETE", "/api/v1/dns-providers/cf-file", None),
    ] {
        let (s, _, v) = h.call(m, uri, b.as_ref()).await;
        assert_eq!(s, StatusCode::CONFLICT, "{m} {uri}: {v}");
        assert_eq!(v["code"], "set_by_file", "{v}");
    }
    let (s, _, v) = h.call("GET", "/api/v1/dns-providers", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"][0]["source"], "file", "{v}");
    assert_eq!(v["items"][0]["state"], "not_used");
}

/// REQ: CLD-904, AGT-004 - an admin writes; an operator and a viewer are refused (403); an agent
/// token, whatever its owner's role and scopes, gets 403 `agent_not_allowed` on every write (a dry
/// run included) and reads the status with `config:read`; nothing is stored by a refused write, and
/// no answer or audit record carries the credential.
#[tokio::test]
async fn cld_904_only_an_admin_writes_and_no_agent_does() {
    let h = harness("");
    store_secret(&h, "cf").await;
    let every: Vec<&str> = auth::agent::SCOPES.iter().map(|(n, _)| *n).collect();
    let agent = token(&h, "bot-dns", auth::Role::Admin, Some(&every.join(" ")));
    let op = token(&h, "olive-dns", auth::Role::Operator, None);
    let viewer = token(&h, "vic-dns", auth::Role::Viewer, None);
    for (who, bearer, status, code) in [
        ("operator", &op, StatusCode::FORBIDDEN, "forbidden"),
        ("viewer", &viewer, StatusCode::FORBIDDEN, "forbidden"),
        ("agent", &agent, StatusCode::FORBIDDEN, "agent_not_allowed"),
    ] {
        for (m, uri, b) in [
            ("PUT", "/api/v1/dns-providers/x", Some(cloudflare())),
            (
                "PUT",
                "/api/v1/dns-providers/x?dryRun=true",
                Some(cloudflare()),
            ),
            ("DELETE", "/api/v1/dns-providers/x", None),
        ] {
            let (s, _, v) = json_of(&h, req_from(bearer, [127, 0, 0, 1], m, uri, b.as_ref())).await;
            assert_eq!(
                (s, v["code"].clone()),
                (status, json!(code)),
                "{who} {m} {uri}: {v}"
            );
            gone(&v.to_string());
        }
    }
    assert!(
        h.src.config.load().dns_provider.is_empty(),
        "a refused write stores nothing"
    );

    // An admin's token writes it.
    let admin = token(&h, "ada-dns", auth::Role::Admin, None);
    let (s, _, v) = json_of(
        &h,
        req_from(
            &admin,
            [127, 0, 0, 1],
            "PUT",
            "/api/v1/dns-providers/x",
            Some(&cloudflare()),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The agent reads the list and one entry with config:read, and nothing else is needed.
    for uri in ["/api/v1/dns-providers", "/api/v1/dns-providers/x"] {
        let (s, _, v) = json_of(&h, req_from(&agent, [127, 0, 0, 1], "GET", uri, None)).await;
        assert_eq!(s, StatusCode::OK, "{uri}: {v}");
        gone(&v.to_string());
    }
    let reader = token(&h, "reader-dns", auth::Role::Admin, Some("analytics:read"));
    let (s, _, _) = json_of(
        &h,
        req_from(
            &reader,
            [127, 0, 0, 1],
            "GET",
            "/api/v1/dns-providers",
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "config:read is needed");
    let audit = h.audit_text();
    assert!(audit.contains("dns_provider"), "{audit}");
    gone(&audit);
}

/// REQ: CLD-904, AGT-001 - the catalog has the read tool and no tool that writes, plans, tests or
/// removes a provider, and the tool reads the list route.
#[test]
fn cld_904_the_mcp_catalog_has_the_read_tool_and_no_write_tool() {
    let catalog = wrendns_api::mcp::catalog();
    let names: Vec<&str> = catalog
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"list_dns_providers"), "{names:?}");
    for n in &names {
        let lower = n.to_ascii_lowercase();
        assert!(
            !(lower.contains("dns_provider") && *n != "list_dns_providers"),
            "{n}: no write, plan or test tool for providers"
        );
    }
}

const WITH: &str = "[[dns_provider]]\nname = \"cf-home\"\nkind = \"cloudflare\"\nzone = \"example.net\"\ncredential_ref = \"cf\"\n";

/// REQ: DSC-908, CLD-904 (T36.10a0 criterion 2) - the first provider is refused through the API
/// while a member's build does not announce the table, naming the member and its version (a dry run
/// too), even with the same version number as this build; a second write of another kind is not
/// held; and once every member announces it the same write succeeds and no refusal stands for it.
#[tokio::test]
async fn dsc_908_the_first_dns_provider_waits_for_every_members_build() {
    let _turn = GATE.lock().await;
    crate::upgrade_gate::forget_held();
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    let ph = harness_in("", Some(Arc::clone(&old.primary)));
    crate::http::serve_peers(&ph.src);
    store_secret(&ph, "cf").await;
    for dry in ["?dryRun=true", ""] {
        let (s, _, v) = ph
            .call(
                "PUT",
                &format!("/api/v1/dns-providers/cf-home{dry}"),
                Some(&cloudflare()),
            )
            .await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert_eq!(v["code"], "upgrade_required", "{v}");
        let d = v["detail"].as_str().unwrap();
        assert!(
            d.contains("version 1.1.0-edge.40") && d.contains("does not know DNS providers"),
            "{v}"
        );
    }
    assert!(
        ph.src.config.load().dns_provider.is_empty(),
        "a refused write stores nothing"
    );
    let holds = crate::upgrade_gate::standing(Some(&old.primary));
    assert!(
        holds
            .iter()
            .any(|h| h.contains("does not know DNS providers")),
        "{holds:?}"
    );
    // An ordinary device write is not held.
    let (s, _, v) = ph
        .call(
            "PUT",
            "/api/v1/clients/tv",
            Some(&json!({"match": ["192.0.2.30"]})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let _ = old.stop.send(true);

    let new = pair("1.1.0", "1.1.0").await;
    let ph = harness_in("", Some(Arc::clone(&new.primary)));
    crate::http::serve_peers(&ph.src);
    store_secret(&ph, "cf").await;
    let (s, _, v) = ph
        .call("PUT", "/api/v1/dns-providers/cf-home", Some(&cloudflare()))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = ph
        .call("PUT", "/api/v1/dns-providers/cf-two", Some(&cloudflare()))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        crate::upgrade_gate::standing(Some(&new.primary)),
        Vec::<String>::new()
    );
    let _ = new.stop.send(true);
    crate::upgrade_gate::forget_held();
}

/// REQ: DSC-908, CLD-904 - the file loader's half of the gate: a reload that adds the first provider
/// is refused while a member's build does not know the table (the judgement the reload makes is the
/// same as the API's), one that does not add it is not held, and a standalone node waits for no one.
#[tokio::test]
async fn dsc_908_the_file_loader_holds_the_first_dns_provider() {
    let _turn = GATE.lock().await;
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    let none = crate::credential_tests::config("");
    let with = crate::credential_tests::config(WITH);
    let why =
        crate::upgrade_gate::enforce_dns_providers(Some(&old.primary), &none, &with).unwrap_err();
    assert!(
        why.contains("version 1.1.0-edge.40") && why.contains("does not know DNS providers"),
        "{why}"
    );
    // The gate the reload runs (every cause): refused, so nothing is swapped.
    let ph = harness_in("", Some(Arc::clone(&old.primary)));
    let why = crate::server::reload_gate(&ph.src, &none, &with).unwrap_err();
    assert!(why.contains("does not know DNS providers"), "{why}");
    assert!(crate::server::reload_gate(&ph.src, &none, &none).is_ok());
    assert!(crate::server::reload_gate(&ph.src, &with, &with).is_ok());
    // A Git commit's refusal is the commit's `refused` error.
    let mut st = crate::gitsource::Status {
        commit: Some("0123456789abcdef".into()),
        ..crate::gitsource::Status::default()
    };
    crate::gitsource::mark_gate_refusal(&mut st, &why);
    assert!(st.refused);
    assert!(crate::upgrade_gate::enforce_dns_providers(None, &none, &with).is_ok());
    assert!(crate::upgrade_gate::uses_dns_providers(&with));
    assert!(!crate::upgrade_gate::uses_dns_providers(&none));
    let _ = old.stop.send(true);
    crate::upgrade_gate::forget_held();
}

/// Ends the process-wide start-up hold when a test ends, however it ends.
struct ClearHold;
impl Drop for ClearHold {
    fn drop(&mut self) {
        crate::upgrade_gate::HOLD.clear();
    }
}

/// REQ: DSC-908, CLD-904 (ADR-1104 point 5, generalised to a set of features) - a primary that
/// starts with a provider while a member's build does not announce the table holds the provider out
/// of what it serves and publishes (and only it: the locations of the same file are not held for
/// it), says why, and applies it when every member announces; a restart of a cluster that already
/// published providers holds nothing, one that published only locations still holds the first
/// provider, and a standalone node is never held.
#[tokio::test]
async fn dsc_908_the_start_up_hold_covers_providers() {
    use wrendns_cluster::gate::Feature;
    let _turn = GATE.lock().await;
    let _clear = ClearHold;
    let file = crate::credential_tests::config(&format!(
        "[local]\ndevice_domain = \"home.arpa\"\n[[location]]\nslug = \"home\"\nnetworks = [\"192.0.2.0/24\"]\n{WITH}"
    ));
    assert_eq!(
        crate::upgrade_gate::features_used(&file),
        vec![Feature::Locations, Feature::DnsProviders]
    );

    // Standalone: never held.
    let standalone = crate::upgrade_gate::Hold::new();
    let mut c = file.clone();
    assert!(!standalone.at_start(&mut c, false, false));
    assert!(!c.dns_provider.is_empty() && !c.location.is_empty());

    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    // The cluster already runs locations: only the provider is held.
    let hold = crate::upgrade_gate::Hold::new();
    let mut only = file.clone();
    assert!(hold.at_start_for(&mut only, true, &[Feature::Locations]));
    assert!(only.dns_provider.is_empty() && !only.location.is_empty());
    assert_eq!(hold.held_features(), vec![Feature::DnsProviders]);
    let mut again = file.clone();
    hold.apply(&mut again);
    assert!(again.dns_provider.is_empty() && !again.location.is_empty());
    hold.clear();

    // Nothing published yet: both are held, and the published part names neither.
    let hold = crate::upgrade_gate::Hold::new();
    let mut stripped = file.clone();
    assert!(hold.at_start(&mut stripped, true, false));
    assert!(stripped.dns_provider.is_empty() && stripped.location.is_empty());
    let published = wrendns_config::shared::shared_part(&stripped);
    assert!(published.get("dns_provider").is_none(), "{published}");
    assert!(
        wrendns_config::shared::shared_part(&file)
            .get("dns_provider")
            .is_some(),
        "without the hold the same file publishes its provider"
    );
    let why = hold.reason(Some(&old.primary)).unwrap();
    assert!(why.contains("version 1.1.0-edge.40"), "{why}");
    let reasons = crate::health::locations_held_reasons(Some(&why));
    assert_eq!(reasons[0].code, "locations_held");
    assert!(reasons[0].summary.contains("DNS providers"));
    assert!(!hold.release(Some(&old.primary), "x") && hold.active());
    let named = crate::upgrade_gate::describe_held(Some(&file));
    assert!(named.contains("DNS providers: cf-home"), "{named}");
    let _ = old.stop.send(true);

    let new = pair("1.1.0", "1.1.0").await;
    assert!(hold.release(Some(&new.primary), "x"));
    let mut during = file.clone();
    hold.apply(&mut during);
    assert!(
        !during.dns_provider.is_empty(),
        "the release reload builds with them"
    );
    hold.finish();
    assert!(!hold.active() && hold.held_features().is_empty());
    let mut released = file.clone();
    hold.apply(&mut released);
    assert!(
        !released.dns_provider.is_empty(),
        "applied without a restart"
    );
    let ph = harness_in("", Some(Arc::clone(&new.primary)));
    assert!(crate::server::reload_gate(&ph.src, &stripped, &released).is_ok());
    let _ = new.stop.send(true);

    // Established clusters: what the last published version carried is not held again.
    let hold = crate::upgrade_gate::Hold::new();
    let mut c = file.clone();
    assert!(!hold.at_start(&mut c, true, true));
    assert!(!hold.at_start_for(&mut c, true, &[Feature::Locations, Feature::DnsProviders]));
    assert!(!c.dns_provider.is_empty(), "the provider stays");
}

/// REQ: DSC-908, CLD-904 - the API, as a node under the hold shows it: the providers are listed as
/// configured with `held` and the reason (not the stripped running table), a write while the hold
/// stands is judged against the members, and the locations list is not marked held for a hold of
/// providers alone.
#[tokio::test]
async fn dsc_908_a_held_provider_is_listed_as_held_and_locations_are_not() {
    use wrendns_cluster::gate::Feature;
    let _turn = GATE.lock().await;
    let _clear = ClearHold;
    let old = pair_features("1.1.0", "1.1.0-edge.40", Some(Vec::new())).await;
    let ph = harness_in("", Some(Arc::clone(&old.primary)));
    // The node serves a configuration without the provider; the build with it is kept.
    let full = crate::credential_tests::config(WITH);
    ph.src.unheld.store(Some(Arc::new(full)));
    crate::upgrade_gate::HOLD.begin_with(&[Feature::DnsProviders]);
    let (s, _, v) = ph.call("GET", "/api/v1/dns-providers", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["held"], true, "{v}");
    assert!(
        v["heldReason"]
            .as_str()
            .is_some_and(|r| r.contains("version 1.1.0-edge.40")),
        "{v}"
    );
    assert_eq!(v["items"][0]["name"], "cf-home");
    assert_eq!(v["items"][0]["held"], true);
    let (s, _, loc) = ph.call("GET", "/api/v1/locations", None).await;
    assert_eq!(s, StatusCode::OK, "{loc}");
    assert!(loc.get("held").is_none(), "locations are not held: {loc}");
    assert!(loc.get("heldReason").is_none(), "{loc}");
    let _ = old.stop.send(true);
}

/// REQ: CLD-904, CLU-004 - with no provider configured nothing the cluster replicates or serves
/// changes: the shared part of a default configuration has no `dns_provider` key (an older replica
/// refuses a section it does not know), and a configuration with one has it.
#[test]
fn cld_904_golden_no_provider_means_no_section_in_the_shared_part() {
    let none = wrendns_config::Config::default();
    assert!(
        wrendns_config::shared::shared_part(&none)
            .get("dns_provider")
            .is_none()
    );
    let with = crate::credential_tests::config(WITH);
    assert!(
        wrendns_config::shared::shared_part(&with)
            .get("dns_provider")
            .is_some()
    );
    assert!(!crate::upgrade_gate::uses_dns_providers(&none));
}

/// REQ: CLD-904, OPS-014 - a provider's credential reference counts as a use of the stored secret
/// (the secret can't be deleted while a provider names it), and the references list names it.
#[tokio::test]
async fn cld_904_a_secret_in_use_by_a_provider_is_not_deleted() {
    let h = harness("");
    store_secret(&h, "cf").await;
    let (s, _, v) = h
        .call("PUT", "/api/v1/dns-providers/cf-home", Some(&cloudflare()))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let refs = wrendns_config::secret_refs::references(&h.src.config.load());
    assert!(
        refs.iter()
            .any(|r| r.kind == "dns_provider" && r.entry == "cf-home" && r.name == "cf"),
        "{refs:?}"
    );
    let (s, _, v) = h.call("DELETE", "/api/v1/secrets/cf", None).await;
    assert!(
        s == StatusCode::CONFLICT || s == StatusCode::UNPROCESSABLE_ENTITY,
        "{s} {v}"
    );
    assert!(v.to_string().contains("dns_provider"), "{v}");
    assert!(h.src.secrets.exists("cf"));
}

/// REQ: CLD-904, DSC-908 - a replica that forwards a provider write to a primary whose build does
/// not announce the table is refused before anything is sent (409 `upgrade_required`, naming the
/// node: an older primary would fail on the unknown kind of the write), and a primary that
/// announces it gets the write.
#[tokio::test(flavor = "multi_thread")]
async fn dsc_908_a_provider_write_is_not_forwarded_to_a_primary_that_does_not_know_the_table() {
    let _turn = GATE.lock().await;
    crate::upgrade_gate::forget_held();
    let url = "/api/v1/dns-providers/cf-home";
    let (replica, older) = crate::credential_tests::older_primary_and_replica_features(
        "1.1.0-edge.40",
        Some(Vec::new()),
        None,
    )
    .await;
    let h = harness_in("", Some(replica));
    let (s, _, v) = h.call("PUT", url, Some(&cloudflare())).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "upgrade_required", "{v}");
    let d = v["detail"].as_str().unwrap();
    assert!(
        d.contains("1.1.0-edge.40") && d.contains("does not know DNS providers"),
        "{v}"
    );
    assert_eq!(older.got.lock().unwrap().len(), 0, "not forwarded");
    let _ = older.stop.send(true);

    let (replica, current) = crate::credential_tests::older_primary_and_replica("1.1.0").await;
    let h = harness_in("", Some(replica));
    let (s, _, v) = h.call("PUT", url, Some(&cloudflare())).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(!current.got.lock().unwrap().is_empty(), "forwarded");
    let _ = current.stop.send(true);
    crate::upgrade_gate::forget_held();
}

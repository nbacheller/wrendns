// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: DNS-014, API-901 (T27.14h, ADR-1098 point 4) - the allowed-networks control: one list for
//! the whole cluster (`[access] allowed_networks`), written through the real path (route, plan,
//! store, reload). Admins only; no agent; a public range warns; the file wins; the list that would
//! cut the requester off is refused.

use axum::http::StatusCode;
use serde_json::{Value, json};
use wrendns_api::auth::Role;
use wrendns_config::Config;

use crate::credential_tests::{Harness, harness_toml};
use crate::settings_kinds_tests::{call_as, token};

const URL: &str = "/api/v1/access-settings/default";

/// A node with no planted settings, answering clients from 127.0.0.0/8 (the harness's address).
fn bare() -> Harness {
    with_toml("")
}

fn with_toml(toml: &str) -> Harness {
    harness_toml(
        toml,
        None,
        vec![wrendns_config::Cidr::parse("127.0.0.0/8").unwrap()],
        wrendns_api::auth::Settings::default(),
    )
}

/// The configuration as the stored rows make it (the same merge the reload applies).
fn merged(h: &Harness) -> Config {
    crate::managed::merge(
        &h.src.file_config.load_full(),
        &crate::managed::entries(h.auth.state()),
    )
    .expect("the merged configuration validates")
}

fn nets(c: &Config) -> Vec<String> {
    c.access
        .allowed_networks
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// The harness's own address plus `more`.
fn list(more: &[&str]) -> Value {
    let mut l = vec!["127.0.0.0/8"];
    l.extend_from_slice(more);
    json!({ "allowed_networks": l })
}

fn warns_public(v: &Value) -> Vec<String> {
    v["warnings"]
        .as_array()
        .map(|w| {
            w.iter()
                .filter_map(Value::as_str)
                .filter(|s| s.contains("from the internet too"))
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// REQ: DNS-014, API-901 (T27.14h, AC1) - operators and viewers are refused, an agent token is
/// refused whatever its scope (the owner's open question is taken the conservative way), and an
/// admin's change is stored and audited with before and after.
#[tokio::test]
async fn dns_014_allowed_networks_control_admin_only() {
    let h = bare();
    let body = list(&["198.18.0.0/15"]);
    let op = token(&h, "ops", Role::Operator, None);
    let (s, _, v) = call_as(&h, &op, "PUT", URL, Some(&body), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    // Not even a request that changes nothing.
    let (s, _, _) = call_as(&h, &op, "PUT", URL, Some(&json!({})), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let viewer = token(&h, "view", Role::Viewer, None);
    let (s, _, _) = call_as(&h, &viewer, "PUT", URL, Some(&body), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let bot = token(
        &h,
        "bot-owner",
        Role::Admin,
        Some("config:read config:write:special"),
    );
    let (s, _, v) = call_as(&h, &bot, "PUT", URL, Some(&body), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let dry = format!("{URL}?dryRun=true");
    let (s, _, _) = call_as(&h, &bot, "PUT", &dry, Some(&body), &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "not even as a dry run");
    assert!(!nets(&h.src.config.load_full()).contains(&"198.18.0.0/15".to_owned()));
    assert_eq!(h.auth.state().managed("access").unwrap().len(), 0);

    let (s, _, v) = h.call("PUT", URL, Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(nets(&merged(&h)), ["127.0.0.0/8", "198.18.0.0/15"]);
    assert_eq!(h.auth.state().managed("access").unwrap().len(), 1);
    let audit = h.audit_text();
    assert!(audit.contains("access.put"), "{audit}");
    assert!(
        audit.contains("before") && audit.contains("after"),
        "{audit}"
    );
    assert!(audit.contains("198.18.0.0/15"), "{audit}");

    let (s, _, _) = call_as(&h, &op, "DELETE", URL, None, &[]).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "an operator cannot hand it back either"
    );
    assert_eq!(h.auth.state().managed("access").unwrap().len(), 1);

    // The entry shows the list and where it comes from.
    let (s, _, e) = h
        .call("GET", "/api/v1/config/entries?kind=access", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{e}");
    assert_eq!(e["items"][0]["source"], "override", "{e}");
    assert_eq!(
        e["items"][0]["definition"]["allowed_networks"],
        json!(["127.0.0.0/8", "198.18.0.0/15"])
    );
    // A DELETE hands it back to the defaults.
    let (s, _, v) = h.call("DELETE", URL, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        nets(&merged(&h)),
        nets(&Config::default()),
        "the defaults of ADR-014 apply again"
    );
}

/// REQ: DNS-014 (T27.14h, AC2) - a range with any public address warns before it is saved; private,
/// CGNAT, link-local and unique-local ranges do not.
#[tokio::test]
async fn dns_014_allowed_networks_public_range_warns() {
    let h = bare();
    let dry = format!("{URL}?dryRun=true");
    for public in [
        "0.0.0.0/0",
        "::/0",
        "203.0.113.0/24",
        "8.8.8.8",
        "2001:db8::/32",
    ] {
        let (s, _, v) = h.call("PUT", &dry, Some(&list(&[public]))).await;
        assert_eq!(s, StatusCode::OK, "{public}: {v}");
        let w = warns_public(&v);
        assert_eq!(w.len(), 1, "{public} warns once: {v}");
        assert!(w[0].contains(public), "{public}: {w:?}");
        assert!(w[0].contains("no device key"), "{w:?}");
    }
    for private in [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.5.0/24",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "fd00::/8",
        "fe80::/10",
        "::1/128",
    ] {
        let (s, _, v) = h.call("PUT", &dry, Some(&list(&[private]))).await;
        assert_eq!(s, StatusCode::OK, "{private}: {v}");
        assert!(warns_public(&v).is_empty(), "{private} must not warn: {v}");
    }
    // A range already in the list does not warn again; nothing was stored by the dry runs.
    assert_eq!(h.auth.state().managed("access").unwrap().len(), 0);
    let (s, _, _) = h.call("PUT", URL, Some(&list(&["203.0.113.0/24"]))).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, v) = h.call("PUT", &dry, Some(&list(&["203.0.113.0/24"]))).await;
    assert_eq!(s, StatusCode::OK);
    assert!(warns_public(&v).is_empty(), "already allowed: {v}");
}

/// REQ: DNS-014 (T27.14h, AC3, ADR-040) - a file that sets the list wins: a different list is 409
/// `set_by_file`, a body that leaves it out keeps the file's, and the entry says it is set by file.
#[tokio::test]
async fn dns_014_allowed_networks_file_wins() {
    let h = with_toml("[access]\nallowed_networks = [\"127.0.0.0/8\", \"10.0.0.0/8\"]\n");
    let (s, _, v) = h.call("PUT", URL, Some(&list(&["192.168.0.0/16"]))).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "set_by_file", "{v}");
    let (s, _, v) = h.call("PUT", URL, Some(&json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(nets(&merged(&h)), ["127.0.0.0/8", "10.0.0.0/8"]);
    let (s, _, e) = h
        .call("GET", "/api/v1/config/entries?kind=access", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{e}");
    assert_eq!(
        e["items"][0]["setByFile"],
        json!(["allowed_networks"]),
        "{e}"
    );
}

/// REQ: DNS-014, CLU-004 (T27.14h, AC4) - the list is in the shared part, so a change on the primary
/// is the list a replica takes from the version it follows, and the kind is replicated and adopted.
#[tokio::test]
async fn dns_014_allowed_networks_change_reaches_every_node() {
    let primary = bare();
    let (s, _, v) = primary
        .call(
            "PUT",
            URL,
            Some(&list(&["198.18.0.0/15", "fd12:3456::/32"])),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let served = merged(&primary);
    let shared = wrendns_config::shared::shared_part(&served);
    assert!(
        shared.get("access").is_some(),
        "the list travels in the shared part"
    );
    // A second node, with its own files (the defaults), takes the shared part as a replica does.
    let replica = bare();
    let own = (**replica.src.file_config.load()).clone();
    let on_replica = wrendns_config::shared::with_shared(&own, &shared).expect("merges");
    assert_eq!(nets(&on_replica), nets(&served));
    assert!(nets(&on_replica).contains(&"198.18.0.0/15".to_owned()));
    assert!(crate::managed_adopt::ADOPTED_KINDS.contains(&"access"));
    assert!(crate::node_managed::SHARED_KINDS.contains(&"access"));
}

/// REQ: DNS-014, API-901 (T27.14h, AC5) - a list that leaves out the requester's own address is
/// refused (409 `would_disconnect_you`), a dry run too; the empty list likewise; nothing is stored.
#[tokio::test]
async fn dns_014_allowed_networks_lockout_refused() {
    let h = bare();
    let dry = format!("{URL}?dryRun=true");
    for body in [
        json!({ "allowed_networks": ["10.0.0.0/8"] }),
        json!({ "allowed_networks": [] }),
        json!({ "allowed_networks": ["::1/128", "192.168.0.0/16"] }),
    ] {
        for url in [URL, dry.as_str()] {
            let (s, _, v) = h.call("PUT", url, Some(&body)).await;
            assert_eq!(s, StatusCode::CONFLICT, "{body}: {v}");
            assert_eq!(v["code"], "would_disconnect_you", "{v}");
            assert!(v["detail"].as_str().unwrap().contains("127.0.0.1"), "{v}");
        }
    }
    assert_eq!(h.auth.state().managed("access").unwrap().len(), 0);
    assert!(!h.audit_text().contains("access.put"));
    // A list that holds the address (a single host route, too) is accepted.
    let (s, _, v) = h
        .call(
            "PUT",
            URL,
            Some(&json!({ "allowed_networks": ["127.0.0.1"] })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // A malformed network is not a lockout.
    let (s, _, v) = h
        .call(
            "PUT",
            URL,
            Some(&json!({ "allowed_networks": ["127.0.0.0/8", "nope"] })),
        )
        .await;
    assert_ne!(s, StatusCode::OK, "{v}");
    assert_ne!(v["code"], "would_disconnect_you", "{v}");
}

/// REQ: DNS-014 (T27.14h) - the range test and the lockout guard, on their own.
#[test]
fn dns_014_public_range_test_and_lockout_guard() {
    use wrendns_config::Cidr;
    let p = |s: &str| Cidr::parse(s).unwrap().includes_public();
    assert!(p("0.0.0.0/0") && p("::/0") && p("11.0.0.0/8") && p("8.8.8.8"));
    assert!(p("100.0.0.0/8"), "wider than CGNAT");
    assert!(p("172.0.0.0/8"), "wider than 172.16/12");
    assert!(!p("10.1.2.0/24") && !p("172.31.0.0/16") && !p("100.127.0.0/16"));
    assert!(!p("127.0.0.1") && !p("fc00::/7") && !p("fd00::1/128") && !p("fe80::/10"));
    assert!(p("2000::/3"));
    let me: std::net::IpAddr = "192.168.1.9".parse().unwrap();
    let guard = |v: Value, ip| wrendns_api::config_api::lockout_guard(&v, ip, Some(ip));
    assert!(guard(json!({"allowed_networks": ["192.168.0.0/16"]}), me).is_ok());
    assert!(guard(json!({"allowed_networks": ["10.0.0.0/8"]}), me).is_err());
    assert!(
        guard(json!({}), me).is_ok(),
        "no list in the body: the file's stays"
    );
    let mapped: std::net::IpAddr = "::ffff:192.168.1.9".parse().unwrap();
    assert!(guard(json!({"allowed_networks": ["192.168.0.0/16"]}), mapped).is_ok());
}

/// The status of a request to the harness's router from `ip`.
async fn status_from(h: &Harness, ip: [u8; 4]) -> StatusCode {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/healthz")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            ip, 40100,
        ))))
        .body(axum::body::Body::empty())
        .unwrap();
    h.send(req).await.0
}

/// REQ: DNS-014, API-901 (T27.14h, ADR-1103 point 4) - the web UI's and the API's own gate follows the
/// list: an address the list adds gets through after the PUT and is refused again after the DELETE.
#[tokio::test]
async fn dns_014_allowed_networks_gate_follows_the_list() {
    let h = bare();
    assert_eq!(
        status_from(&h, [198, 18, 0, 5]).await,
        StatusCode::FORBIDDEN
    );
    let (s, _, v) = h.call("PUT", URL, Some(&list(&["198.18.0.0/15"]))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        h.src
            .allowed
            .load()
            .iter()
            .any(|n| n.to_string() == "198.18.0.0/15")
    );
    assert_eq!(status_from(&h, [198, 18, 0, 5]).await, StatusCode::OK);
    assert_eq!(
        status_from(&h, [203, 0, 113, 9]).await,
        StatusCode::FORBIDDEN
    );
    let (s, _, v) = h.call("DELETE", URL, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        !h.src
            .allowed
            .load()
            .iter()
            .any(|n| n.to_string() == "198.18.0.0/15")
    );
    assert_eq!(
        status_from(&h, [198, 18, 0, 5]).await,
        StatusCode::FORBIDDEN
    );
}

fn behind_proxy() -> Harness {
    harness_toml(
        "",
        None,
        vec![wrendns_config::Cidr::parse("127.0.0.0/8").unwrap()],
        wrendns_api::auth::Settings {
            trusted_proxies: vec![("127.0.0.1".parse().unwrap(), 32)],
            ..wrendns_api::auth::Settings::default()
        },
    )
}

/// REQ: DNS-014, API-901 (T27.14h, review) - behind a trusted proxy the gate judges the proxy's
/// address, so a list that holds the client but not the proxy is refused (it would lock out every
/// request, the page included); a list that holds both is accepted.
#[tokio::test]
async fn dns_014_allowed_networks_lockout_judges_the_proxy_too() {
    let h = behind_proxy();
    let admin = token(&h, "adm", Role::Admin, None);
    let xff = [("x-forwarded-for", "192.168.1.20")];
    let (s, _, v) = call_as(
        &h,
        &admin,
        "PUT",
        URL,
        Some(&json!({ "allowed_networks": ["192.168.1.0/24"] })),
        &xff,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "would_disconnect_you", "{v}");
    assert!(v["detail"].as_str().unwrap().contains("127.0.0.1"), "{v}");
    assert_eq!(h.auth.state().managed("access").unwrap().len(), 0);
    let (s, _, v) = call_as(
        &h,
        &admin,
        "PUT",
        URL,
        Some(&json!({ "allowed_networks": ["192.168.1.0/24", "127.0.0.1"] })),
        &xff,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: DNS-014, API-901 (T27.14h, review) - a DELETE is checked on the list that would be in force:
/// the file's (here the defaults) leave out a public client, so the revert is refused and the list
/// stays.
#[tokio::test]
async fn dns_014_allowed_networks_revert_is_checked() {
    let h = behind_proxy();
    let admin = token(&h, "adm", Role::Admin, None);
    let xff = [("x-forwarded-for", "8.8.8.8")];
    let (s, _, v) = call_as(
        &h,
        &admin,
        "PUT",
        URL,
        Some(&json!({ "allowed_networks": ["127.0.0.0/8", "8.8.8.0/24"] })),
        &xff,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = call_as(&h, &admin, "DELETE", URL, None, &xff).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "would_disconnect_you", "{v}");
    assert_eq!(h.auth.state().managed("access").unwrap().len(), 1);
    // From an address the defaults hold, the revert goes through.
    let (s, _, v) = call_as(&h, &admin, "DELETE", URL, None, &[]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: DNS-014 (T27.14h, review) - the dry run says what the change does.
#[tokio::test]
async fn dns_014_allowed_networks_dry_run_states_the_impact() {
    let h = bare();
    let dry = format!("{URL}?dryRun=true");
    let (s, _, v) = h.call("PUT", &dry, Some(&list(&[]))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["impact"].as_str().unwrap().contains("every node"), "{v}");
}

fn behind_proxy_with(toml: &str) -> Harness {
    harness_toml(
        toml,
        None,
        vec![wrendns_config::Cidr::parse("127.0.0.0/8").unwrap()],
        wrendns_api::auth::Settings {
            trusted_proxies: vec![("127.0.0.1".parse().unwrap(), 32)],
            ..wrendns_api::auth::Settings::default()
        },
    )
}

/// REQ: DNS-014, API-901 (T27.14h, ADR-1103) - through the real router, a PUT is judged on the
/// client address AND the TCP peer: a list that holds the peer but not the client is refused
/// naming the client, one that holds the client but not the peer is refused naming the peer, and
/// a DELETE is judged the same way on the list that would be in force (the peer-excluded case of
/// a DELETE cannot arise: the file wins field by field, so no list is stored while the file sets one). Nothing is stored by a refused write.
#[tokio::test]
async fn dns_014_lockout_check_covers_client_and_peer_on_put_and_delete() {
    let h = behind_proxy_with("");
    let admin = token(&h, "adm", Role::Admin, None);
    let xff = [("x-forwarded-for", "192.168.1.20")];
    // PUT: holds the peer (127.0.0.1), not the client.
    let (s, _, v) = call_as(
        &h,
        &admin,
        "PUT",
        URL,
        Some(&json!({ "allowed_networks": ["127.0.0.0/8"] })),
        &xff,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "would_disconnect_you", "{v}");
    assert!(
        v["detail"].as_str().unwrap().contains("192.168.1.20"),
        "{v}"
    );
    // PUT: holds the client, not the peer.
    let (s, _, v) = call_as(
        &h,
        &admin,
        "PUT",
        URL,
        Some(&json!({ "allowed_networks": ["192.168.1.0/24"] })),
        &xff,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert!(v["detail"].as_str().unwrap().contains("127.0.0.1"), "{v}");
    assert_eq!(h.auth.state().managed("access").unwrap().len(), 0);
    // A list that holds both is stored.
    let (s, _, v) = call_as(
        &h,
        &admin,
        "PUT",
        URL,
        Some(&json!({ "allowed_networks": ["192.168.1.0/24", "127.0.0.0/8"] })),
        &xff,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // DELETE: the file's list (the defaults) holds the peer but not this public client.
    let out = [("x-forwarded-for", "8.8.8.8")];
    let (s, _, v) = call_as(&h, &admin, "DELETE", URL, None, &out).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "would_disconnect_you", "{v}");
    assert!(v["detail"].as_str().unwrap().contains("8.8.8.8"), "{v}");
    assert_eq!(h.auth.state().managed("access").unwrap().len(), 1);
}

/// REQ: DNS-014, API-901 (T27.14h review) - a PUT whose body holds no `allowed_networks` stores
/// the built-in defaults; the check judges that list, so a requester the defaults leave out is
/// refused, on a dry run too, and nothing is stored. A DELETE with nothing stored answers from
/// its own dry run (404), not from an unjudged write.
#[tokio::test]
async fn dns_014_put_without_the_list_is_judged_on_the_defaults() {
    let h = behind_proxy_with("");
    let admin = token(&h, "adm", Role::Admin, None);
    let out = [("x-forwarded-for", "8.8.8.8")];
    for url in [URL.to_owned(), format!("{URL}?dryRun=true")] {
        let (s, _, v) = call_as(&h, &admin, "PUT", &url, Some(&json!({})), &out).await;
        assert_eq!(s, StatusCode::CONFLICT, "{url}: {v}");
        assert_eq!(v["code"], "would_disconnect_you", "{v}");
        assert!(v["detail"].as_str().unwrap().contains("8.8.8.8"), "{v}");
    }
    assert_eq!(h.auth.state().managed("access").unwrap().len(), 0);
    let (s, _, v) = call_as(&h, &admin, "DELETE", URL, None, &out).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
}

/// REQ: DNS-014, API-901 (T27.14h, final check) - a file that sets the list answers `set_by_file`
/// even for a body that leaves out the requester: the lockout word is for a list the backend cannot
/// take, not for every refusal.
#[tokio::test]
async fn dns_014_set_by_file_is_not_answered_as_a_lockout() {
    let h = with_toml("[access]\nallowed_networks = [\"127.0.0.0/8\", \"10.0.0.0/8\"]\n");
    let body = json!({ "allowed_networks": ["192.168.0.0/16"] });
    for url in [URL.to_owned(), format!("{URL}?dryRun=true")] {
        let (s, _, v) = h.call("PUT", &url, Some(&body)).await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert_eq!(v["code"], "set_by_file", "{v}");
    }
}

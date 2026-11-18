//! REQ: API-016, OBS-010, OBS-006, CLU-015, CLU-004 (T23.11, ADR-903 sections 6-7, ADR-984) -
//! event sinks and the OTLP export made in the UI as node-managed kinds: the API writes through
//! the real path (route, plan, reload), admins only, references only; the files win; the blob
//! carries names, never values; and an OTLP header from a stored secret is sent with each export.
//! The collectors are local fakes on loopback.

use axum::http::StatusCode;
use serde_json::{Value, json};
use telltale_api::auth::Role;
use telltale_config::Config;

use crate::credential_tests::{Harness, harness, harness_toml, leaks};
use crate::managed::{OTLP, SINK};
use crate::node_managed::{self, Doc, Entry};
use crate::secrets::value::Kind;
use crate::settings_kinds_tests::{call_as, token};

const SINKS: &str = "/api/v1/sinks";
const OTLP_URL: &str = "/api/v1/otlp";
const OTLP_PUT: &str = "/api/v1/otlp/default";

/// A node with no planted settings (so that the OTLP export is not set by file).
fn bare() -> Harness {
    harness_toml(
        "",
        None,
        vec![telltale_config::Cidr::parse("127.0.0.0/8").unwrap()],
        telltale_api::auth::Settings::default(),
    )
}

fn with_toml(toml: &str) -> Harness {
    harness_toml(
        toml,
        None,
        vec![telltale_config::Cidr::parse("127.0.0.0/8").unwrap()],
        telltale_api::auth::Settings::default(),
    )
}

fn store_secret(h: &Harness, name: &str, value: &str) {
    h.src
        .secrets
        .put(
            name,
            Kind::Text,
            &crate::secrets::SecretValue::new(
                Kind::Text,
                zeroize::Zeroizing::new(value.to_owned()),
            )
            .unwrap(),
            0,
            "root",
            "local",
            1,
        )
        .unwrap();
}

fn webhook() -> Value {
    json!({"type": "webhook", "url": "https://collector.example/in", "batch": 100})
}

/// REQ: API-016 (T23.11) - a sink `PUT` through the API is stored, merged as a node-managed sink
/// and listed with its source; `DELETE` removes it.
#[tokio::test]
async fn api_016_sink_put_lists_and_applies() {
    let h = bare();
    let (s, _, out) = h
        .call("PUT", &format!("{SINKS}/hook"), Some(&webhook()))
        .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let cfg = h.src.config.load_full();
    assert_eq!(cfg.telemetry.managed_sink.len(), 1);
    assert!(cfg.telemetry.sink.is_empty(), "never in the files' list");
    let (s, _, list) = h.call("GET", SINKS, None).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    let hook = &list["items"][0];
    assert_eq!(hook["name"], "hook");
    assert_eq!(hook["source"], "api");
    assert_eq!(hook["type"], "webhook");
    assert_eq!(hook["location"], "https://collector.example/in");
    assert_eq!(hook["tokenSource"], "none");
    assert_eq!(h.auth.state().managed(SINK).unwrap().len(), 1);
    let (s, _, out) = h.call("DELETE", &format!("{SINKS}/hook"), None).await;
    assert_eq!(s, StatusCode::OK, "{out}");
    assert_eq!(h.src.config.load_full().telemetry.managed_sink.len(), 0);
    let (s, _, _) = h.call("DELETE", &format!("{SINKS}/hook"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[allow(clippy::too_many_lines)]
/// REQ: API-016 (T23.11, AC8) - an operator reads sinks but can't change them (403), an agent
/// never writes one, and what a body may not carry (a credential path, a password in a URL,
/// another directory) is 422 and never stored.
#[tokio::test]
async fn api_016_sink_admin_only_and_references_only() {
    let h = bare();
    let op = token(&h, "ops", Role::Operator, None);
    let (s, _, out) = call_as(
        &h,
        &op,
        "PUT",
        &format!("{SINKS}/hook"),
        Some(&webhook()),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{out}");
    let (s, _, out) = call_as(&h, &op, "DELETE", &format!("{SINKS}/hook"), None, &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{out}");
    let (s, _, out) = call_as(&h, &op, "GET", SINKS, None, &[]).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "an operator sees telemetry read-only: {out}"
    );
    let (s, _, _) = call_as(&h, &op, "GET", OTLP_URL, None, &[]).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call_as(
        &h,
        &op,
        "PUT",
        OTLP_PUT,
        Some(&json!({"endpoint": "http://c:4318"})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let agent = token(
        &h,
        "bot",
        Role::Admin,
        Some("config:read config:write:upstreams"),
    );
    let (s, _, _) = call_as(
        &h,
        &agent,
        "PUT",
        &format!("{SINKS}/hook"),
        Some(&webhook()),
        &[],
    )
    .await;
    assert_ne!(s, StatusCode::OK, "an agent never writes one");
    let (s, _, _) = call_as(&h, &agent, "GET", SINKS, None, &[]).await;
    assert_eq!(s, StatusCode::OK, "an agent may read (names only)");
    assert_eq!(h.auth.state().managed(SINK).unwrap().len(), 0);

    let bad = |extra: Value| {
        let mut b = webhook();
        for (k, v) in extra.as_object().unwrap() {
            b[k] = v.clone();
        }
        b
    };
    for (what, body) in [
        ("token_file", bad(json!({"token_file": "/etc/shadow"}))),
        ("tls_ca", bad(json!({"tls_ca": "/etc/ca.pem"}))),
        (
            "password in url",
            bad(json!({"url": "https://me:hunter2-planted@collector.example/in"})),
        ),
        ("buffer", bad(json!({"max_buffer": 4_000_000_000_u64}))),
        ("unknown field", bad(json!({"bogus": 1}))),
        ("path on webhook", bad(json!({"path": "x.jsonl"}))),
    ] {
        let (s, _, out) = h.call("PUT", &format!("{SINKS}/hook"), Some(&body)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{what}: {out}");
        assert!(!out.to_string().contains("hunter2-planted"), "{what}");
    }
    for path in [
        "../etc/passwd",
        "/etc/passwd",
        "a/b.jsonl",
        ".hidden",
        "x.spill",
    ] {
        let body = json!({"type": "file", "path": path});
        let (s, _, out) = h.call("PUT", &format!("{SINKS}/f"), Some(&body)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{path}: {out}");
    }
    assert_eq!(h.auth.state().managed(SINK).unwrap().len(), 0);
    // A file sink is a file name, under the node's `sinks` directory.
    let (s, _, out) = h
        .call(
            "PUT",
            &format!("{SINKS}/f"),
            Some(&json!({"type": "file", "path": "events.jsonl"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let cfg = h.src.config.load_full();
    let full = cfg.telemetry.managed_sink[0]
        .path
        .as_ref()
        .unwrap()
        .to_string();
    assert!(
        full.ends_with("events.jsonl") && full.contains("sinks"),
        "{full}"
    );
    let (_, _, list) = h.call("GET", SINKS, None).await;
    assert_eq!(list["items"][0]["definition"]["path"], "events.jsonl");

    // A reference to a secret nobody stored is refused; once stored, it's accepted and shown as a
    // name, never as a value.
    let mut b = webhook();
    b["token_ref"] = "hook-token".into();
    let (s, _, out) = h.call("PUT", &format!("{SINKS}/hook"), Some(&b)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{out}");
    assert_eq!(out["code"], "secret_missing");
    store_secret(&h, "hook-token", "s3cret-token-planted");
    let (s, _, out) = h.call("PUT", &format!("{SINKS}/hook"), Some(&b)).await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let (_, _, list) = h.call("GET", SINKS, None).await;
    let hook = list["items"]
        .as_array()
        .and_then(|a| a.iter().find(|i| i["name"] == "hook"))
        .unwrap();
    assert_eq!(hook["tokenSource"], "stored");
    assert_eq!(hook["token"], "hook-token");
    assert_eq!(hook["tokenReadable"], true);
    assert!(!list.to_string().contains("s3cret-token-planted"));
    assert!(!h.audit_text().contains("s3cret-token-planted"));
}

/// REQ: API-016 (T23.11, ADR-040) - a sink the files define is read-only through the API and its
/// credential paths stay the file's; the files' entry wins over a row of the same name.
#[tokio::test]
async fn api_016_sink_file_defined_is_read_only() {
    let h = with_toml(
        "[[telemetry.sink]]\nname = \"fromfile\"\ntype = \"webhook\"\nurl = \"https://f.example/in\"\ntoken_file = \"/run/secrets/hook\"\n",
    );
    let (s, _, out) = h
        .call("PUT", &format!("{SINKS}/fromfile"), Some(&webhook()))
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{out}");
    assert_eq!(out["code"], "set_by_file");
    let (s, _, _) = h.call("DELETE", &format!("{SINKS}/fromfile"), None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    // A row planted for the same name (a blob from a primary that didn't have the file) doesn't
    // replace the file's sink.
    h.auth
        .state()
        .put_managed(
            SINK,
            "fromfile",
            &json!({"type": "webhook", "url": "https://evil.example/in"}).to_string(),
            None,
            None,
            1,
            "test",
        )
        .unwrap();
    let cfg = crate::managed::effective(&h.src.file_config.load());
    assert_eq!(
        cfg.telemetry.sink[0].url.as_ref().unwrap().as_str(),
        "https://f.example/in"
    );
    assert!(
        cfg.telemetry.managed_sink.is_empty(),
        "a row is merged only when no file sink has the name"
    );
    let (_, _, list) = h.call("GET", SINKS, None).await;
    let f = &list["items"][0];
    assert_eq!(f["source"], "file");
    assert_eq!(f["tokenSource"], "file");
}

/// REQ: API-016, OBS-006 (T23.11, AC8) - the OTLP export: an endpoint and `header_refs` naming
/// stored secrets; inline headers, trace settings and a missing endpoint are refused; a missing
/// secret is `secret_missing`.
#[tokio::test]
async fn api_016_otlp_put_header_refs_and_refusals() {
    let h = bare();
    let (s, _, list) = h.call("GET", OTLP_URL, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list["source"], "none");
    let put = |b: Value| {
        let h = &h;
        async move { h.call("PUT", OTLP_PUT, Some(&b)).await }
    };
    for (what, b) in [
        ("no endpoint", json!({"interval_secs": 60})),
        (
            "inline header",
            json!({"endpoint": "http://c:4318", "headers": {"api-key": "planted-otlp-value"}}),
        ),
        (
            "traces",
            json!({"endpoint": "http://c:4318", "traces_sample_every": 10}),
        ),
        (
            "password in url",
            json!({"endpoint": "http://me:planted-otlp-pw@c:4318"}),
        ),
        (
            "reserved header",
            json!({"endpoint": "http://c:4318", "header_refs": {"Content-Type": "x"}}),
        ),
        (
            "short interval",
            json!({"endpoint": "http://c:4318", "interval_secs": 1}),
        ),
        ("not http", json!({"endpoint": "ftp://c"})),
    ] {
        let (s, _, out) = put(b).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{what}: {out}");
        assert!(!out.to_string().contains("planted-otlp"), "{what}");
    }
    let refd = json!({"endpoint": "http://c:4318", "header_refs": {"api-key": "otlp-key"}});
    let (s, _, out) = put(refd.clone()).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{out}");
    assert_eq!(out["code"], "secret_missing");
    store_secret(&h, "otlp-key", "planted-otlp-secret-77");
    let (s, _, out) = put(refd).await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let cfg = h.src.config.load_full();
    assert!(cfg.telemetry.managed_otlp.is_some());
    assert!(
        cfg.telemetry.otlp.endpoint.is_none(),
        "never in the file's section"
    );
    assert_eq!(
        cfg.telemetry
            .otlp_effective()
            .endpoint
            .as_ref()
            .unwrap()
            .as_str(),
        "http://c:4318"
    );
    let (_, _, e) = h.call("GET", OTLP_URL, None).await;
    assert_eq!(e["source"], "api");
    assert_eq!(e["headers"][0]["name"], "api-key");
    assert_eq!(e["headers"][0]["source"], "stored");
    assert_eq!(e["headers"][0]["secret"], "otlp-key");
    assert_eq!(e["headers"][0]["readable"], true);
    assert_eq!(e["active"], true);
    assert!(!e.to_string().contains("planted-otlp-secret"));
    assert!(!h.audit_text().contains("planted-otlp-secret"));
    let (s, _, _) = h.call("DELETE", OTLP_PUT, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(h.src.config.load_full().telemetry.managed_otlp.is_none());
    let (s, _, _) = h.call("DELETE", OTLP_PUT, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// REQ: API-016, OBS-006 (T23.11) - the files win: an OTLP destination in a file (here an inline
/// header, as the planted configuration has) makes the kind read-only, the inline value is shown
/// as `<redacted>`, and no value is in any answer.
#[tokio::test]
async fn api_016_otlp_set_by_file() {
    let h = harness("");
    let (s, _, out) = h
        .call("PUT", OTLP_PUT, Some(&json!({"endpoint": "http://c:4318"})))
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{out}");
    assert_eq!(out["code"], "set_by_file");
    let (_, _, e) = h.call("GET", OTLP_URL, None).await;
    assert_eq!(e["source"], "file");
    assert_eq!(e["headers"][0]["source"], "inline");
    assert_eq!(e["headers"][0]["value"], "<redacted>");
    assert!(leaks(&e.to_string()).is_empty(), "{e}");
}

/// REQ: OBS-006, OPS-014 (T23.11, AC5) - an OTLP header whose value is a stored secret is sent
/// with the export, and read again for every export: a rotated secret goes out from the next one.
#[tokio::test]
async fn obs_006_otlp_header_ref_sent() {
    let hook = crate::sinks::Collector::new();
    let h = bare();
    store_secret(&h, "otlp-key", "first-key-4242");
    let (s, _, out) = h
        .call(
            "PUT",
            OTLP_PUT,
            Some(&json!({"endpoint": hook.url_base(), "header_refs": {"x-api-key": "otlp-key"}})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let client = crate::otlp::client().unwrap();
    let cfg = h.src.config.load_full();
    let url = format!("{}/v1/metrics", crate::otlp::endpoint(&cfg).unwrap());
    crate::otlp::post(&client, &url, &cfg, "{}".to_owned(), &h.src.secrets)
        .await
        .unwrap();
    store_secret(&h, "otlp-key", "second-key-9191");
    crate::otlp::post(&client, &url, &cfg, "{}".to_owned(), &h.src.secrets)
        .await
        .unwrap();
    let got = hook.heads();
    assert!(got[0].contains("x-api-key: first-key-4242"), "{:?}", got[0]);
    assert!(
        got[1].contains("x-api-key: second-key-9191"),
        "{:?}",
        got[1]
    );
    assert!(got[0].starts_with("post /v1/metrics"), "{:?}", got[0]);
}

fn rows(entries: &[(&str, &str, Value)]) -> Vec<(String, String, String)> {
    entries
        .iter()
        .map(|(k, n, b)| ((*k).to_owned(), (*n).to_owned(), b.to_string()))
        .collect()
}

/// REQ: CLU-015, API-016 (T23.11) - the blob carries names only: a sink's `token_file`, `tls_ca`
/// and OTLP's inline `headers` are left out when exporting and refuse the entry when found.
#[test]
fn clu_015_sink_and_otlp_blob_refs_only() {
    let leaky_sink = json!({
        "type": "webhook", "url": "https://c.example/in", "token_ref": "hook-token",
        "token_file": "/run/secrets/planted-path", "tls_ca": "/etc/planted-ca.pem",
    });
    let leaky_otlp = json!({
        "endpoint": "http://c:4318", "header_refs": {"x-api-key": "otlp-key"},
        "headers": {"x-other": "planted-header-value"},
    });
    let blob = node_managed::encode(&rows(&[
        (SINK, "hook", leaky_sink.clone()),
        (OTLP, "default", leaky_otlp.clone()),
    ]));
    let text = String::from_utf8(blob.clone()).unwrap();
    for planted in ["planted-path", "planted-ca", "planted-header-value"] {
        assert!(!text.contains(planted), "{planted} in {text}");
    }
    assert!(
        text.contains("hook-token") && text.contains("otlp-key"),
        "{text}"
    );
    assert_eq!(node_managed::parse(&blob).unwrap().len(), 2);
    // A blob made by hand with the values is dropped entry by entry.
    let forged = serde_json::to_vec(&Doc {
        version: 1,
        entries: vec![
            Entry {
                kind: SINK.into(),
                name: "hook".into(),
                body: leaky_sink,
            },
            Entry {
                kind: OTLP.into(),
                name: "default".into(),
                body: leaky_otlp,
            },
        ],
    })
    .unwrap();
    assert_eq!(node_managed::parse(&forged).unwrap().len(), 0);
}

/// REQ: CLU-004, API-016 (T23.11) - a bad sink entry drops only itself; the files' sink of the
/// same name wins; a bad OTLP entry changes nothing; a good one applies unless the files set a
/// destination.
#[test]
fn clu_004_bad_sink_entry_drops_only_itself() {
    let blob = node_managed::encode(&rows(&[
        (
            SINK,
            "good",
            json!({"type": "webhook", "url": "https://c.example/in"}),
        ),
        (SINK, "nourl", json!({"type": "webhook"})),
        (
            SINK,
            "badaddr",
            json!({"type": "syslog", "address": "nonsense"}),
        ),
        (
            SINK,
            "fromfile",
            json!({"type": "webhook", "url": "https://evil.example/in"}),
        ),
        (OTLP, "default", json!({"endpoint": "not-a-url"})),
    ]));
    let mut cfg = Config::default();
    cfg.telemetry.sink = vec![
        toml::from_str("name = \"fromfile\"\ntype = \"webhook\"\nurl = \"https://f.example/in\"\n")
            .unwrap(),
    ];
    node_managed::overlay_blob(&mut cfg, &blob);
    let names: Vec<&str> = cfg
        .telemetry
        .managed_sink
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(names, ["good"], "{names:?}");
    assert!(
        cfg.telemetry.managed_otlp.is_none(),
        "a bad export is dropped"
    );
    assert_eq!(
        cfg.telemetry.sink[0].url.as_ref().unwrap().as_str(),
        "https://f.example/in"
    );

    let blob = node_managed::encode(&rows(&[(
        OTLP,
        "default",
        json!({"endpoint": "http://c:4318", "header_refs": {"x-api-key": "otlp-key"}}),
    )]));
    let mut cfg = Config::default();
    node_managed::overlay_blob(&mut cfg, &blob);
    assert_eq!(
        cfg.telemetry
            .otlp_effective()
            .endpoint
            .as_ref()
            .unwrap()
            .as_str(),
        "http://c:4318"
    );
    // The files set a destination: theirs wins whole.
    let mut cfg = Config::default();
    cfg.telemetry.otlp.endpoint =
        Some(telltale_config::SafeString::new("http://file:4318").unwrap());
    node_managed::overlay_blob(&mut cfg, &blob);
    assert_eq!(
        cfg.telemetry
            .otlp_effective()
            .endpoint
            .as_ref()
            .unwrap()
            .as_str(),
        "http://file:4318"
    );
    assert!(cfg.telemetry.otlp_effective().header_refs.is_empty());
}

/// REQ: API-016 (T23.11, ADR-984) - a file sink made in the UI is written under the node's own
/// data directory, whatever the primary's was.
#[test]
fn api_016_file_sink_path_resolves_per_node() {
    let blob = node_managed::encode(&rows(&[(
        SINK,
        "f",
        json!({"type": "file", "path": "e.jsonl"}),
    )]));
    let mut cfg = Config::default();
    cfg.node.data_dir = telltale_config::SafeString::new("/var/lib/this-node").unwrap();
    node_managed::overlay_blob(&mut cfg, &blob);
    assert_eq!(
        cfg.telemetry.managed_sink[0]
            .path
            .as_ref()
            .unwrap()
            .as_str(),
        "/var/lib/this-node/sinks/e.jsonl"
    );
}

/// REQ: CLU-015, API-016 (T23.11, ADR-968 point 4) - a promoted primary seeds its own rows from
/// the blob it inherited, sinks and the OTLP export with the providers, once; an entry that
/// doesn't validate is not seeded.
#[test]
fn clu_015_promoted_primary_seeds_sinks_and_otlp() {
    let dir = tempfile::tempdir().unwrap();
    let (state_path, cluster) = (dir.path().join("state.db"), dir.path().join("cluster"));
    std::fs::create_dir_all(&cluster).unwrap();
    let blob = node_managed::encode(&rows(&[
        (
            SINK,
            "good",
            json!({"type": "webhook", "url": "https://c.example/in"}),
        ),
        (
            SINK,
            "bad",
            json!({"type": "syslog", "address": "nonsense"}),
        ),
        (OTLP, "default", json!({"endpoint": "http://c:4318"})),
    ]));
    assert!(node_managed::seed_once(&state_path, &cluster, "h1", &blob));
    let state = telltale_store::state::State::open(&state_path).unwrap();
    let sinks: Vec<String> = state
        .managed(SINK)
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert_eq!(sinks, ["good"]);
    assert_eq!(state.managed(OTLP).unwrap().len(), 1);
    // Entries made after the promotion are the node's; the marker keeps the blob from coming back.
    state.delete_managed(SINK, "good", None).unwrap();
    assert!(node_managed::seed_once(&state_path, &cluster, "h1", &blob));
    assert_eq!(state.managed(SINK).unwrap().len(), 0);
}

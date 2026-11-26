//! REQ: API-014, OPS-011, AGT-010 (T23.1, ADR-903 §4) — credentials planted in the
//! configuration never come back through a read surface: the API's entries (on the primary and on
//! a replica, an older primary's included), write responses and audit records, idempotency
//! records, the TOML kept for Git, every GET the OpenAPI document lists, every MCP read tool and
//! resource, and `config check --print`. And the marker rule: `<redacted>` sent back keeps a value
//! only while the destination is the same.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use wrendns_api::auth::{self, Auth};

use crate::http::Sources;

/// The planted credentials: each must never appear in anything a read returns.
pub(crate) const HEADER: &str = "Bearer planted-header-7f3a";
pub(crate) const ARG: &str = "planted-arg-9c1e";
pub(crate) const URL_PASSWORD: &str = "plantedpw4b2d";
pub(crate) const PROXY_PASSWORD: &str = "plantedproxy81e0";
pub(crate) const HOOK_PASSWORD: &str = "plantedhook6a6a";
pub(crate) const CLIENT_SECRET: &str = "planted-client-secret-55aa";
pub(crate) const OTLP: &str = "planted-otlp-1d2c";
pub(crate) const LIST_PASSWORD: &str = "plantedlist3e9f";
const PLANTED: &[&str] = &[
    HEADER,
    "planted-header-7f3a",
    ARG,
    URL_PASSWORD,
    PROXY_PASSWORD,
    HOOK_PASSWORD,
    CLIENT_SECRET,
    OTLP,
    LIST_PASSWORD,
];

pub(crate) fn planted_toml(extra: &str) -> String {
    format!(
        r#"
[[upstream]]
name = "nextdns"
url = "https://me:{URL_PASSWORD}@doh.example/dns-query"
tls_server_name = "doh.example"
headers = {{ Authorization = "{HEADER}" }}
proxy = "socks5://p:{PROXY_PASSWORD}@10.0.0.1:1080"
[[upstream]]
name = "plug"
url = "exec:///usr/local/bin/plugin"
args = ["--token", "{ARG}"]
[[upstream_group]]
name = "default"
members = ["nextdns", "plug"]
[[alerts.destination]]
name = "hook"
type = "webhook"
url = "https://u:{HOOK_PASSWORD}@hook.example/notify"
[[list]]
name = "ads"
url = "https://l:{LIST_PASSWORD}@lists.example/ads.txt"
[telemetry.otlp]
headers = {{ api-key = "{OTLP}" }}
[auth.oidc]
public_url = "https://dns.example.com"
[[auth.oidc.provider]]
id = "kc"
issuer = "https://kc.example/realms/home"
client_id = "wrendns"
client_secret = "{CLIENT_SECRET}"
{extra}
"#
    )
}

/// What `text` leaks, if anything.
pub(crate) fn leaks(text: &str) -> Vec<&'static str> {
    PLANTED
        .iter()
        .copied()
        .filter(|p| text.contains(p))
        .collect()
}

pub(crate) struct Harness {
    pub(crate) src: Arc<Sources>,
    pub(crate) app: axum::Router,
    pub(crate) auth: Arc<Auth>,
    pub(crate) bearer: String,
    pub(crate) admin_id: i64,
    dir: tempfile::TempDir,
}

pub(crate) fn config(toml: &str) -> wrendns_config::Config {
    wrendns_config::Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .map_err(|e| format!("{e:?}"))
        .unwrap()
        .config
}

/// A standalone node with the planted configuration, its API (an admin token), and a reload
/// loop that applies what the API stores.
pub(crate) fn harness(extra: &str) -> Harness {
    harness_in(extra, None)
}

/// [`harness`] on a cluster member (`cluster`): its API is the federated one.
pub(crate) fn harness_in(
    extra: &str,
    cluster: Option<Arc<wrendns_cluster::net::Cluster>>,
) -> Harness {
    harness_from(
        extra,
        cluster,
        vec![wrendns_config::Cidr::parse("127.0.0.0/8").unwrap()],
    )
}

/// [`harness_in`] answering clients in `allowed` (`[access] allowed_networks`).
pub(crate) fn harness_from(
    extra: &str,
    cluster: Option<Arc<wrendns_cluster::net::Cluster>>,
    allowed: Vec<wrendns_config::Cidr>,
) -> Harness {
    harness_with(extra, cluster, allowed, auth::Settings::default())
}

/// [`harness_from`] with these auth settings (`[api] trusted_proxies` and the like).
pub(crate) fn harness_with(
    extra: &str,
    cluster: Option<Arc<wrendns_cluster::net::Cluster>>,
    allowed: Vec<wrendns_config::Cidr>,
    settings: auth::Settings,
) -> Harness {
    harness_toml(&planted_toml(extra), cluster, allowed, settings)
}

/// [`harness_with`] over exactly this configuration (none of the planted settings).
pub(crate) fn harness_toml(
    toml: &str,
    cluster: Option<Arc<wrendns_cluster::net::Cluster>>,
    allowed: Vec<wrendns_config::Cidr>,
    settings: auth::Settings,
) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(toml);
    cfg.node.data_dir = wrendns_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
    let (reload, mut reloads) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<bool>>(4);
    let src = Arc::new(Sources {
        allowed: arc_swap::ArcSwap::from_pointee(allowed),
        cluster,
        reload,
        ..crate::http::tests::sources_in(dir.path())
    });
    src.config.store(Arc::new(cfg.clone()));
    src.file_config.store(Arc::new(cfg));
    let state = Arc::new(wrendns_store::state::State::open(&dir.path().join("state.db")).unwrap());
    let auth = Arc::new(Auth::new(state, settings));
    let now = crate::pipeline::unix_now();
    let admin = auth
        .create_user(
            "root",
            "correct horse battery",
            auth::Role::Admin,
            false,
            now,
        )
        .unwrap();
    let (id, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
    auth.state()
        .create_token(
            &id,
            admin.id,
            "tests",
            &auth::crypto::secret_hash(&secret),
            "admin",
            None,
            now,
        )
        .unwrap();
    let _ = src.auth.set(Arc::clone(&auth));
    let s2 = Arc::clone(&src);
    tokio::spawn(async move {
        while let Some(done) = reloads.recv().await {
            let ok = s2.auth.get().is_some_and(|a| {
                let e = crate::managed::entries(a.state());
                crate::managed::merge(&s2.file_config.load(), &e)
                    .map(|c| s2.config.store(Arc::new(c)))
                    .is_ok()
            });
            // REQ: API-016 (T23.7) — the router loop reads the new list, as the server's reload does.
            s2.routers_changed.notify_one();
            // REQ: API-016 (T23.10) — and the OIDC applier, as the reload does.
            s2.oidc_changed.notify_one();
            // REQ: API-016 (T23.11) - and the sinks and OTLP export, as the reload does.
            s2.telemetry_changed.notify_one();
            s2.otlp_changed.notify_one();
            let _ = done.send(ok);
        }
    });
    let app = crate::http::api_router(Arc::clone(&src), Arc::clone(&auth));
    Harness {
        src,
        app,
        auth,
        bearer: format!("tt_{id}_{secret}"),
        admin_id: admin.id,
        dir,
    }
}

impl Harness {
    /// The node's data directory (a temporary one).
    pub(crate) fn dir_path(&self) -> &std::path::Path {
        self.dir.path()
    }

    pub(crate) fn request(&self, method: &str, uri: &str, body: Option<&Value>) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", self.bearer))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .extension(axum::extract::ConnectInfo(SocketAddr::from((
                [127, 0, 0, 1],
                40000,
            ))))
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap()
    }

    /// Sends `req`; the status, headers, and body text (a stream is read for at most a second).
    pub(crate) async fn send(
        &self,
        req: Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let (status, headers) = (resp.status(), resp.headers().clone());
        let text = tokio::time::timeout(
            Duration::from_secs(1),
            axum::body::to_bytes(resp.into_body(), 16 << 20),
        )
        .await
        .map(|b| String::from_utf8_lossy(&b.unwrap_or_default()).into_owned())
        .unwrap_or_default();
        (status, headers, text)
    }

    pub(crate) async fn call(
        &self,
        method: &str,
        uri: &str,
        body: Option<&Value>,
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        let (s, h, t) = self.send(self.request(method, uri, body)).await;
        (s, h, serde_json::from_str(&t).unwrap_or(Value::String(t)))
    }

    pub(crate) fn audit_text(&self) -> String {
        self.auth
            .state()
            .audit_page(None, 100, None, None)
            .unwrap()
            .iter()
            .map(|e| format!("{} {} {}\n", e.action, e.target, e.detail))
            .collect::<Vec<_>>()
            .concat()
    }

    fn effective_upstream(&self, name: &str) -> wrendns_config::Upstream {
        self.src
            .config
            .load()
            .upstream
            .iter()
            .find(|u| u.name.as_str() == name)
            .cloned()
            .unwrap()
    }
}

/// The definitions of an entries listing, by name.
fn entry<'a>(items: &'a Value, name: &str) -> &'a Value {
    items["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == name)
        .unwrap()
}

/// REQ: API-014 — headers, args and URL passwords come back as `<redacted>` and are listed in
/// `redacted`: on the primary (this node), and on a replica, which redacts the primary's answer
/// again (an N−1 primary sends it as it is).
#[tokio::test]
async fn api_014_config_entries_redacts_upstream_headers_and_args() {
    let h = harness("");
    let (s, _, v) = h.call("GET", "/api/v1/config/entries", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(leaks(&v.to_string()).is_empty(), "{v}");
    let up = entry(&v, "nextdns");
    assert_eq!(up["definition"]["headers"]["Authorization"], "<redacted>");
    assert_eq!(
        up["definition"]["url"],
        "https://me:<redacted>@doh.example/dns-query"
    );
    let mut red: Vec<&str> = up["redacted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    red.sort_unstable();
    assert_eq!(red, ["headers.Authorization", "proxy", "url"]);
    let plug = entry(&v, "plug");
    assert_eq!(
        plug["definition"]["args"],
        json!(["<redacted>", "<redacted>"])
    );
    assert_eq!(entry(&v, "hook")["redacted"], json!(["url"]));
    assert!(
        entry(&v, "default").get("redacted").is_none(),
        "nothing to list"
    );

    // A replica, from this primary's answer and from an older one's (no `redacted`, values in).
    let items: Vec<wrendns_api::model::ConfigEntry> =
        serde_json::from_value(v["items"].clone()).unwrap();
    let new = crate::federated::entries_from_primary(&serde_json::to_vec(&items).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&new).unwrap(), v["items"]);
    let cfg = h.src.config.load();
    let old: Vec<Value> = cfg
        .upstream
        .iter()
        .map(|u| json!({"kind": "upstream", "name": u.name.as_str(), "source": "file", "definition": u}))
        .collect();
    let old_body = serde_json::to_vec(&old).unwrap();
    assert!(
        !leaks(&String::from_utf8_lossy(&old_body)).is_empty(),
        "planted"
    );
    let replica = crate::federated::entries_from_primary(&old_body).unwrap();
    let text = serde_json::to_string(&replica).unwrap();
    assert!(leaks(&text).is_empty(), "{text}");
    assert_eq!(replica[0].redacted.len(), 3, "{:?}", replica[0].redacted);
}

/// REQ: API-014 — a write's response and its audit record carry no credential, and a write
/// entered on a replica neither: the primary's audit record (`forward::apply`, tested there) and
/// the entry node's, which redacts the primary's answer again.
#[tokio::test]
async fn api_014_write_response_and_audit_redacted() {
    let h = harness("");
    let body = json!({
        "url": format!("https://me:{URL_PASSWORD}@doh.example/dns-query"),
        "tls_server_name": "doh.example",
        "headers": {"Authorization": HEADER, "X-Extra": "planted-header-7f3a"}
    });
    let (s, _, v) = h
        .call("PUT", "/api/v1/upstreams/nextdns", Some(&body))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["applied"], true);
    assert!(leaks(&v.to_string()).is_empty(), "{v}");
    assert_eq!(v["after"]["headers"]["X-Extra"], "<redacted>");
    let audit = h.audit_text();
    assert!(audit.contains("upstream.put nextdns"), "{audit}");
    assert!(leaks(&audit).is_empty(), "{audit}");
    // The value itself was stored and applied.
    let u = h.effective_upstream("nextdns");
    assert_eq!(
        u.headers
            .values()
            .next()
            .map(wrendns_config::SafeString::as_str),
        Some(HEADER)
    );

    // An answer from an older primary, as the entry node gets it back.
    let mut answer = wrendns_api::model::ConfigChange {
        applied: true,
        config_version: 3,
        before: None,
        after: Some(serde_json::to_value(&u).unwrap()),
        recent_queries: 0,
        impact: String::new(),
        warnings: Vec::new(),
        keep_in_git: Some(format!(
            "# Add to the configuration in Git.\n[[upstream]]\nname = \"nextdns\"\nurl = \"https://me:{URL_PASSWORD}@doh.example/\"\n"
        )),
        simulation: None,
    };
    crate::redact::change(wrendns_api::ManagedKind::Upstream, &mut answer);
    let text = serde_json::to_string(&answer).unwrap();
    assert!(leaks(&text).is_empty(), "{text}");
    let detail = crate::redact::audit_detail(
        wrendns_api::ManagedKind::Upstream,
        &json!({"before": serde_json::to_value(&u).unwrap(), "after": null, "configVersion": 3}),
    );
    assert!(leaks(&detail.to_string()).is_empty(), "{detail}");
}

/// REQ: API-014, AGT-003 — the idempotency record holds neither the request nor a credential:
/// a retry still gets the first answer, and the same key with only a header value changed is
/// another request (409).
#[tokio::test]
async fn api_014_idempotency_row_holds_no_credential() {
    let h = harness("");
    let put = |body: &Value| {
        let mut r = h.request("PUT", "/api/v1/upstreams/nextdns", Some(body));
        r.headers_mut()
            .insert("idempotency-key", "retry-1".parse().unwrap());
        r
    };
    let b1 = json!({"url": "https://doh.example/dns-query", "headers": {"Authorization": HEADER}});
    let (s, _, first) = h.send(put(&b1)).await;
    assert_eq!(s, StatusCode::OK, "{first}");
    let (s, hd, again) = h.send(put(&b1)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(hd.get("idempotency-replayed").unwrap(), "true");
    assert_eq!(again, first);
    let b2 = json!({"url": "https://doh.example/dns-query", "headers": {"Authorization": "Bearer another"}});
    let (s, _, v) = h.send(put(&b2)).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let row = h
        .auth
        .state()
        .idempotent(
            &format!("{}:retry-1", h.admin_id),
            crate::pipeline::unix_now(),
        )
        .unwrap()
        .unwrap();
    let request = String::from_utf8_lossy(&row.request).into_owned();
    assert!(
        leaks(&request).is_empty() && leaks(&row.response).is_empty(),
        "{request} {}",
        row.response
    );
    assert!(
        !request.contains("PUT"),
        "a hash, not the request: {request}"
    );
    assert_eq!(request.len(), 64, "{request}");
}

/// REQ: API-014 — on a Git-managed node, the TOML to keep a change in Git names credentials only
/// by the marker.
#[tokio::test]
async fn api_014_keep_in_git_never_prints_values() {
    let h = harness("[cluster]\nconfig_source = \"gitops\"\n");
    let body = json!({
        "url": format!("https://me:{URL_PASSWORD}@doh.example/dns-query"),
        "headers": {"Authorization": HEADER}
    });
    let (s, _, v) = h
        .call("PUT", "/api/v1/upstreams/nextdns?dryRun=true", Some(&body))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let toml = v["keepInGit"].as_str().unwrap();
    assert!(leaks(toml).is_empty(), "{toml}");
    assert!(toml.contains("Authorization = \"<redacted>\""), "{toml}");
    assert!(toml.contains(crate::redact::GIT_NOTE), "{toml}");
}

/// REQ: API-014 (ADR-903 §4) — `<redacted>` sent back unchanged keeps the value.
#[tokio::test]
#[allow(clippy::many_single_char_names)] // h, v, s, r, u: the harness and its answers
async fn api_014_redacted_marker_keeps_value() {
    let h = harness("");
    let (_, _, v) = h
        .call("GET", "/api/v1/config/entries?kind=upstream", None)
        .await;
    let mut def = entry(&v, "nextdns")["definition"].clone();
    def["timeout_ms"] = json!(1500);
    let (s, _, r) = h.call("PUT", "/api/v1/upstreams/nextdns", Some(&def)).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert!(leaks(&r.to_string()).is_empty(), "{r}");
    let u = h.effective_upstream("nextdns");
    assert_eq!(u.timeout_ms, 1500);
    assert_eq!(
        u.headers
            .values()
            .next()
            .map(wrendns_config::SafeString::as_str),
        Some(HEADER)
    );
    assert!(u.url.contains(URL_PASSWORD), "the URL's password is kept");
    assert!(u.proxy.unwrap().contains(PROXY_PASSWORD));
    // An exec upstream's args likewise.
    let (_, _, v) = h
        .call("GET", "/api/v1/config/entries?kind=upstream", None)
        .await;
    let plug = entry(&v, "plug")["definition"].clone();
    let (s, _, r) = h.call("PUT", "/api/v1/upstreams/plug", Some(&plug)).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(h.effective_upstream("plug").args[1].as_str(), ARG);
}

/// REQ: API-014 — `<redacted>` for something with no stored value is 422.
#[tokio::test]
async fn api_014_redacted_marker_without_value_422() {
    let h = harness("");
    for (path, body) in [
        (
            "/api/v1/upstreams/brand-new",
            json!({"url": "https://doh.example/q", "headers": {"Authorization": "<redacted>"}}),
        ),
        (
            "/api/v1/upstreams/nextdns",
            json!({"url": "https://me:<redacted>@doh.example/dns-query", "tls_server_name": "doh.example",
                   "proxy": "socks5://p:<redacted>@10.0.0.1:1080",
                   "headers": {"Authorization": "<redacted>", "X-New": "<redacted>"}}),
        ),
    ] {
        let (s, _, v) = h.call("PUT", path, Some(&body)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{path}: {v}");
        assert_eq!(v["code"], "credential_reentry_required", "{v}");
    }
    // A check never resolves the marker.
    let (s, _, v) = h
        .call(
            "POST",
            "/api/v1/checks/upstream",
            Some(&json!({"url": "https://doh.example/q", "headers": {"Authorization": "<redacted>"}})),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["code"], "credential_reentry_required", "{v}");
}

/// REQ: API-014 — `<redacted>` with a new URL (or TLS name) is 422: a credential isn't sent to a
/// new destination unless typed again; so is an agent's plan that changes an upstream's URL (it
/// merges the redacted entry).
#[tokio::test]
async fn api_014_redacted_marker_with_new_url_422() {
    let h = harness("");
    let (_, _, v) = h
        .call("GET", "/api/v1/config/entries?kind=upstream", None)
        .await;
    let def = entry(&v, "nextdns")["definition"].clone();
    for (field, value) in [
        ("url", json!("https://me:<redacted>@evil.example/dns-query")),
        ("tls_server_name", json!("evil.example")),
        ("proxy", json!("socks5://p:<redacted>@203.0.113.9:1080")),
    ] {
        let mut moved = def.clone();
        moved[field] = value;
        let (s, _, r) = h
            .call("PUT", "/api/v1/upstreams/nextdns", Some(&moved))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{field}: {r}");
        assert_eq!(r["code"], "credential_reentry_required");
    }
    // Typed again, the move is fine.
    let mut typed = def.clone();
    typed["url"] = json!("https://evil.example/dns-query");
    typed["headers"] = json!({"Authorization": "Bearer new"});
    typed["proxy"] = Value::Null;
    let (s, _, r) = h
        .call("PUT", "/api/v1/upstreams/nextdns", Some(&typed))
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");

    // MCP: plan_update_upstreams with a new URL merges the redacted entry and is refused.
    let h = harness("");
    let rpc = |id: u64, method: &str, params: Value| json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let (_, _, v) = h
        .call(
            "POST",
            "/mcp",
            Some(&rpc(
                1,
                "tools/call",
                json!({"name": "plan_update_upstreams", "arguments": {
                    "kind": "upstream", "name": "nextdns",
                    "url": "https://evil.example/dns-query", "reason": "move it"}}),
            )),
        )
        .await;
    let text = v["result"].to_string();
    assert_eq!(v["result"]["isError"], true, "{v}");
    assert!(
        text.contains("credential_reentry_required") || text.contains("entered again"),
        "{text}"
    );
    assert!(leaks(&text).is_empty(), "{text}");
}

/// REQ: API-014 — `config check --print` redacts unless `--show-secrets`.
#[test]
fn api_014_config_check_print_redacts() {
    let cfg = config(&planted_toml(""));
    let shown = crate::printed_config(&cfg, false).unwrap();
    assert!(leaks(&shown).is_empty(), "{shown}");
    assert!(shown.contains("<redacted>"), "{shown}");
    let all = crate::printed_config(&cfg, true).unwrap();
    assert!(all.contains(HEADER) && all.contains(CLIENT_SECRET), "{all}");
}

/// REQ: API-014, ADR-905 — a replica's lists from the primary's answer, and from an older one's
/// (source and fetch error with the list URL's password in them): no password on the replica,
/// and the marker where it was.
#[test]
fn api_014_lists_from_primary_redacted() {
    let list = |source: &str, error: Option<String>| {
        json!({
            "name": "ads", "kind": "block", "enabled": true, "mode": "enforce",
            "source": source, "state": "failed", "error": error,
            "bytes": 0, "lines": 0, "entries": 0, "unique": 0, "regexSkipped": 0,
            "hits": 0, "overlap": [], "refreshing": false,
        })
    };
    let url = format!("https://l:{LIST_PASSWORD}@lists.example/ads.txt");
    let old = json!([list(
        &url,
        Some(format!("fetch {url}: 503 Service Unavailable"))
    )]);
    let got = crate::federated::lists_from_primary(&serde_json::to_vec(&old).unwrap()).unwrap();
    let text = serde_json::to_string(&got).unwrap();
    assert!(leaks(&text).is_empty(), "{text}");
    assert_eq!(got[0].source, "https://l:<redacted>@lists.example/ads.txt");
    assert_eq!(
        got[0].error.as_deref(),
        Some("fetch https://l:<redacted>@lists.example/ads.txt: 503 Service Unavailable")
    );
    // The new primary's answer is already redacted: it passes through unchanged.
    let shown = json!([list(
        "https://l:<redacted>@lists.example/ads.txt",
        Some("fetch https://l:<redacted>@lists.example/ads.txt: 503".into())
    )]);
    let again = crate::federated::lists_from_primary(&serde_json::to_vec(&shown).unwrap()).unwrap();
    assert_eq!(again[0].source, got[0].source);
    assert_eq!(
        again[0].error.as_deref(),
        Some("fetch https://l:<redacted>@lists.example/ads.txt: 503")
    );
}

/// Arguments for a tool from its input schema: each required field a plausible value.
fn tool_args(schema: &Value) -> Value {
    let mut args = serde_json::Map::new();
    let props = &schema["properties"];
    for r in schema["required"].as_array().into_iter().flatten() {
        let k = r.as_str().unwrap_or_default();
        let p = &props[k];
        let v = if let Some(first) = p["enum"].as_array().and_then(|e| e.first()) {
            first.clone()
        } else {
            match p["type"].as_str() {
                Some("array") => json!([]),
                Some("integer" | "number") => json!(1),
                Some("boolean") => json!(false),
                Some("object") => json!({}),
                _ => json!("nextdns"),
            }
        };
        args.insert(k.to_owned(), v);
    }
    Value::Object(args)
}

/// REQ: API-014, AGT-010 — with a header, an arg, URL passwords, an OIDC `client_secret`, and
/// OTLP headers planted: every GET the OpenAPI document lists, every MCP read tool and resource,
/// and the query tail return none of them. Left out, for stated reasons: `/backup` (an admin's
/// copy of the configuration files themselves, which hold what they hold; ADR-903 §8) and the
/// support package (classified by OPS-011, its own tests plant secrets the same way).
#[tokio::test]
#[allow(clippy::too_many_lines)] // one walk over every read surface
async fn api_014_planted_credential_never_returned() {
    let h = harness("");
    // A write first, so the audit log, versions, and the idempotency table have something.
    let body = json!({"url": format!("https://me:{URL_PASSWORD}@doh.example/q"), "headers": {"Authorization": HEADER}});
    let (s, _, v) = h.call("PUT", "/api/v1/upstreams/second", Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let rpc = |id: u64, method: &str, params: Value| json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    // And an agent's plan whose body holds a URL password (plans keep the write they replay).
    let (_, _, v) = h
        .call(
            "POST",
            "/mcp",
            Some(&rpc(
                9,
                "tools/call",
                json!({"name": "plan_update_upstreams", "arguments": {
                    "kind": "upstream", "name": "third",
                    "url": format!("https://me:{URL_PASSWORD}@doh3.example/dns-query"),
                    "reason": "a third one"}}),
            )),
        )
        .await;
    assert_ne!(v["result"]["isError"], true, "{v}");
    assert!(leaks(&v.to_string()).is_empty(), "{v}");
    let (_, _, plans) = h.call("GET", "/api/v1/plans", None).await;
    assert_eq!(plans["items"].as_array().map(Vec::len), Some(1), "{plans}");

    let (_, _, doc) = h.call("GET", "/api/v1/openapi.json", None).await;
    let paths = doc["paths"].as_object().unwrap();
    let skipped = ["/api/v1/backup", "/api/v1/system/support-package/{id}/map"];
    let (mut walked, mut answered) = (0, 0);
    let mut found = Vec::new();
    for (path, ops) in paths {
        if ops.get("get").is_none() || skipped.contains(&path.as_str()) {
            continue;
        }
        let mut uri = String::new();
        let mut in_param = false;
        for c in path.chars() {
            match c {
                '{' => in_param = true,
                '}' => {
                    in_param = false;
                    uri.push_str("nextdns");
                }
                _ if in_param => {}
                _ => uri.push(c),
            }
        }
        let (status, _, text) = h.send(h.request("GET", &uri, None)).await;
        walked += 1;
        if status == StatusCode::OK {
            answered += 1;
        }
        let l = leaks(&text);
        if !l.is_empty() {
            found.push(format!(
                "GET {uri}: {l:?}: {}",
                text.chars().take(300).collect::<String>()
            ));
        }
    }
    assert!(walked > 60, "{walked} GETs");
    assert!(answered > 40, "{answered} of {walked} GETs answered 200");

    // MCP: every read tool (`list_plans` included), every resource.
    let (_, _, tools) = h
        .call("POST", "/mcp", Some(&rpc(1, "tools/list", json!({}))))
        .await;
    let tools = tools["result"]["tools"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(tools.len() > 10, "{tools:?}");
    let mut read_tools = 0;
    for (i, t) in tools.iter().enumerate() {
        if t["annotations"]["readOnlyHint"] != true {
            continue;
        }
        read_tools += 1;
        let name = t["name"].as_str().unwrap();
        let args = tool_args(&t["inputSchema"]);
        let (_, _, text) = h
            .send(h.request(
                "POST",
                "/mcp",
                Some(&rpc(
                    100 + i as u64,
                    "tools/call",
                    json!({"name": name, "arguments": args}),
                )),
            ))
            .await;
        let l = leaks(&text);
        if !l.is_empty() {
            found.push(format!("MCP tool {name}: {l:?}"));
        }
    }
    assert!(read_tools > 10, "{read_tools} read tools");
    // The answers of "update lists now" (ADR-905): REST and MCP, dry runs (not walked above: not
    // GETs, and a real refresh would download the lists).
    let (s, _, v) = h
        .call(
            "POST",
            "/api/v1/lists/refresh?dryRun=true",
            Some(&json!({})),
        )
        .await;
    // The harness node has no list fetcher, so it answers `lists_not_here`; either answer is
    // walked for the planted values.
    assert!(
        s == StatusCode::ACCEPTED || v["code"] == "lists_not_here",
        "{s} {v}"
    );
    if !leaks(&v.to_string()).is_empty() {
        found.push("POST /api/v1/lists/refresh".into());
    }
    let (_, _, v) = h
        .call(
            "POST",
            "/mcp",
            Some(&rpc(
                4,
                "tools/call",
                json!({"name": "refresh_lists", "arguments": {"names": ["ads"], "dryRun": true, "reason": "check first"}}),
            )),
        )
        .await;
    // As above: `lists_not_here` here (an error answer, still walked).
    assert!(
        v["result"]["isError"] != true || v.to_string().contains("lists_not_here"),
        "{v}"
    );
    if !leaks(&v.to_string()).is_empty() {
        found.push("MCP refresh_lists".into());
    }
    let (_, _, res) = h
        .call("POST", "/mcp", Some(&rpc(2, "resources/list", json!({}))))
        .await;
    let resources = res["result"]["resources"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!resources.is_empty(), "{res}");
    for r in &resources {
        let uri = r["uri"].as_str().unwrap();
        let (_, _, text) = h
            .send(h.request(
                "POST",
                "/mcp",
                Some(&rpc(3, "resources/read", json!({"uri": uri}))),
            ))
            .await;
        assert!(text.contains("contents"), "{uri}: {text}");
        let l = leaks(&text);
        if !l.is_empty() {
            found.push(format!("MCP resource {uri}: {l:?}"));
        }
    }
    // The query tail (a stream: what arrives within a second).
    let (_, _, text) = h
        .send(h.request("GET", "/api/v1/queries/stream", None))
        .await;
    if !leaks(&text).is_empty() {
        found.push("the query tail".into());
    }
    assert!(found.is_empty(), "{found:#?}");
}

/// REQ: API-014 (ADR-903 §4) — the Git webhook answers a refusal with a generic 401: no file
/// path, no I/O error (they go to the log).
#[tokio::test]
async fn api_014_webhook_401_is_generic() {
    let h = harness(
        "[cluster.git]\nrepo = \"https://git.example/r\"\npath = \"t.toml\"\nwebhook_secret_file = \"/run/secrets/planted-hook-path\"\n",
    );
    let req = Request::post("/api/v1/hooks/git")
        .header("x-hub-signature-256", "sha256=00")
        .extension(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            40000,
        ))))
        .body(Body::from("{}"))
        .unwrap();
    let (s, _, text) = h.send(req).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{text}");
    assert!(!text.contains("planted-hook-path"), "{text}");
    assert!(!text.contains("No such file"), "{text}");
}

/// REQ: API-014, CLU-013 — a pin that holds back a credential's change: the pin's diff and the
/// `409 cluster_pinned` a write gets show that it changed (a `replace` with the marker), never
/// the value pinned or the one held back.
#[tokio::test]
async fn api_014_pin_diff_never_shows_a_credential() {
    use wrendns_cluster::sync::{BlobStore, ClusterManifest, PinInfo, blob_ref};
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap().replace('\\', "/");
    let node = format!("[node]\ndata_dir = \"{d}\"\n");
    let pinned_cfg = config(&format!("{node}{}", planted_toml("")));
    // The files now: only the header's value changed.
    let now = format!(
        "{node}{}",
        planted_toml("").replace(HEADER, "Bearer planted-header-7f3a-v2")
    );
    let file = dir.path().join("t.toml");
    std::fs::write(&file, &now).unwrap();
    let id = wrendns_cluster::node::Identity::init(
        dir.path(),
        "home",
        vec!["https://127.0.0.1:1".into()],
        "k8s",
    )
    .unwrap();
    let src = Sources {
        cluster: Some(wrendns_cluster::net::Cluster::new(id, "0.8.0")),
        config_files: vec![file],
        ..crate::http::tests::sources_in(dir.path())
    };
    let cfg = config(&now);
    src.config.store(Arc::new(cfg.clone()));
    src.file_config.store(Arc::new(cfg));
    // The pinned version, and the pin.
    let bytes = serde_json::to_vec(&wrendns_config::shared::shared_part(&pinned_cfg)).unwrap();
    let b = blob_ref("config.json", &bytes);
    BlobStore::open(dir.path())
        .unwrap()
        .put(&b, &bytes)
        .unwrap();
    let cdir = wrendns_cluster::node::dir_of(dir.path());
    std::fs::write(
        cdir.join(crate::rollout::PINNED),
        serde_json::to_vec(&ClusterManifest {
            config: b,
            ..ClusterManifest::default()
        })
        .unwrap(),
    )
    .unwrap();
    crate::rollout::State {
        active: None,
        pinned: Some(PinInfo {
            to: (1, 2),
            since_ms: 1,
            by: "root".into(),
            reason: "hold".into(),
        }),
    }
    .save(&cdir)
    .unwrap();

    let (ops, sentences) = crate::rollout::surface::pin_diff(&src).unwrap();
    let text = serde_json::to_string(&ops).unwrap();
    assert!(leaks(&text).is_empty(), "{text}");
    assert!(
        ops.iter().any(|o| o["op"] == "replace"
            && o["path"] == "/upstream/0/headers/Authorization"
            && o["value"] == "<redacted>"),
        "the change shows: {text}"
    );
    assert!(
        sentences.iter().any(|s| s == "upstream: changed"),
        "{sentences:?}"
    );
    let p = crate::rollout::surface::pinned_problem(&src).unwrap();
    let text = serde_json::to_string(&p).unwrap();
    assert!(text.contains("cluster_pinned"), "{text}");
    assert!(text.contains("/upstream/0/headers/Authorization"), "{text}");
    assert!(leaks(&text).is_empty(), "{text}");
    // A version diff (the rollout commands' `diff`) is the same function.
    let a = wrendns_config::shared::shared_part(&pinned_cfg);
    let mut b = a.clone();
    b["upstream"][0]["url"] = json!("https://me:other-pw@doh.example/dns-query");
    let ops = crate::rollout::surface::shared_diff(&a, &b);
    let text = serde_json::to_string(&ops).unwrap();
    assert_eq!(ops.len(), 1, "{text}");
    assert!(
        leaks(&text).is_empty() && !text.contains("other-pw"),
        "{text}"
    );
}

/// What an older primary's stub received, and what keeps the two-node cluster up.
pub(crate) struct OlderPrimary {
    pub(crate) got: Arc<std::sync::Mutex<Vec<Value>>>,
    pub(crate) stop: tokio::sync::watch::Sender<bool>,
    _primary: Arc<wrendns_cluster::net::Cluster>,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

/// A two-node cluster: the primary at `version`, answering forwarded writes as an older primary
/// does (the entry as stored, credentials in), and the replica, joined and connected.
pub(crate) async fn older_primary_and_replica(
    version: &str,
) -> (Arc<wrendns_cluster::net::Cluster>, OlderPrimary) {
    use wrendns_cluster::net::{Cluster, dial, join, serve};
    use wrendns_cluster::node::{Identity, JoinRequest, TokenGrants};
    let (pdir, rdir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let url = format!("https://{addr}");
    let pid = Identity::init(pdir.path(), "home", vec![url.clone()], "k8s").unwrap();
    let token = pid
        .create_token_for(
            600,
            Some(vec![url.clone()]),
            TokenGrants {
                eligible: true,
                witness: false,
            },
        )
        .unwrap();
    let primary = Cluster::new(pid, version);
    let got = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let g = Arc::clone(&got);
    primary.set_rpc_handler(Arc::new(move |_peer, kind, body| {
        let g = Arc::clone(&g);
        Box::pin(async move {
            if kind != crate::forward::KIND {
                return Err("not answered by this stub".to_owned());
            }
            let w: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
            let after = w["body"].clone();
            g.lock().unwrap().push(w);
            let git = format!(
                "# Add to the configuration in Git.\n[[upstream]]\nname = \"nextdns\"\n\n[upstream.headers]\nAuthorization = \"{HEADER}\"\n"
            );
            let answer = json!({"ok": {
                "applied": true, "configVersion": 7, "before": null, "after": after,
                "recentQueries": 0, "impact": "", "warnings": [], "keepInGit": git
            }});
            serde_json::to_vec(&answer).map_err(|e| e.to_string())
        })
    }));
    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    tokio::spawn(serve(Arc::clone(&primary), addr, stop.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let key = wrendns_cluster::pki::new_node_key().unwrap();
    let req = JoinRequest {
        witness: false,
        ephemeral: false,
        secret: token.secret.clone(),
        csr_pem: key.csr_pem.clone(),
        advertise: vec![],
        site: "pi".into(),
        eligible: true,
        version: crate::build_info::VERSION.into(),
    };
    let resp = join(&token, &req).await.unwrap();
    let rid = Identity::save_joined(rdir.path(), &key.key_pem, &resp, "pi", true, vec![]).unwrap();
    let replica = Cluster::new(rid, crate::build_info::VERSION);
    tokio::spawn(dial(Arc::clone(&replica), stop));
    for _ in 0..400 {
        if replica.reachable_primary().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        replica.reachable_primary().is_some(),
        "the replica connects"
    );
    (
        replica,
        OlderPrimary {
            got,
            stop: stop_tx,
            _primary: primary,
            _dirs: (pdir, rdir),
        },
    )
}

/// REQ: API-014, CLU-010 — a write entered on a replica, through the real route (the federated
/// backend, `forward::managed`, the entry node's audit record and stored idempotency response)
/// to an older primary that answers with the credentials in: none of them comes back. And a
/// body that sends `<redacted>` back is refused (409 `upgrade_required`) rather than forwarded
/// to a primary that would store the marker itself.
#[tokio::test(flavor = "multi_thread")]
async fn api_014_replica_write_through_an_older_primary() {
    let (replica, older) = older_primary_and_replica("0.7.4").await;
    let h = harness_in("", Some(replica));
    let put = |body: &Value, key: &str| {
        let mut r = h.request("PUT", "/api/v1/upstreams/nextdns", Some(body));
        r.headers_mut()
            .insert("idempotency-key", key.parse().unwrap());
        r
    };
    let typed = json!({
        "url": format!("https://me:{URL_PASSWORD}@doh.example/dns-query"),
        "tls_server_name": "doh.example",
        "headers": {"Authorization": HEADER}
    });
    let (s, _, text) = h.send(put(&typed, "replica-1")).await;
    assert_eq!(s, StatusCode::OK, "{text}");
    assert!(leaks(&text).is_empty(), "{text}");
    assert!(text.contains("<redacted>"), "{text}");
    assert_eq!(older.got.lock().unwrap().len(), 1, "forwarded");
    let audit = h.audit_text();
    assert!(audit.contains("upstream.put nextdns"), "{audit}");
    assert!(leaks(&audit).is_empty(), "{audit}");
    let row = h
        .auth
        .state()
        .idempotent(
            &format!("{}:replica-1", h.admin_id),
            crate::pipeline::unix_now(),
        )
        .unwrap()
        .unwrap();
    assert!(leaks(&row.response).is_empty(), "{}", row.response);
    let (s, hd, again) = h.send(put(&typed, "replica-1")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(hd.get("idempotency-replayed").unwrap(), "true");
    assert_eq!(again, text);

    // Markers sent back: refused here, nothing forwarded.
    let (_, _, v) = h
        .call("GET", "/api/v1/config/entries?kind=upstream", None)
        .await;
    let def = entry(&v, "nextdns")["definition"].clone();
    assert!(def.to_string().contains("<redacted>"), "{def}");
    let (s, _, r) = h.call("PUT", "/api/v1/upstreams/nextdns", Some(&def)).await;
    assert_eq!(s, StatusCode::CONFLICT, "{r}");
    assert_eq!(r["code"], "upgrade_required", "{r}");
    assert!(r["detail"].as_str().unwrap().contains("0.7.4"), "{r}");
    assert_eq!(older.got.lock().unwrap().len(), 1, "not forwarded");
    let _ = older.stop.send(true);
}

/// REQ: API-014, FLT-004, AGT-003 — a refresh through a real list fetcher: the list's URL password
/// (its download fails: nothing listens on 127.0.0.1:9) is in no list read, the 202 answer, the
/// `lists.refresh` audit row, or the idempotency record of the request.
#[tokio::test]
async fn api_014_refresh_with_real_fetcher_keeps_password_out() {
    let h = harness_from(
        "",
        None,
        vec![wrendns_config::Cidr::parse("127.0.0.0/8").unwrap()],
    );
    let scratch = tempfile::tempdir().unwrap();
    let data = scratch.path().join("data");
    let conf = config(&format!(
        "[node]
data_dir = {:?}
[[list]]
name = \"local\"
url = \"https://l:{URL_PASSWORD}@127.0.0.1:9/x\"
",
        data.to_string_lossy()
    ));
    h.src.config.store(Arc::new(conf.clone()));
    let lists = crate::lists::Lists::start(&conf, &h.src.pipeline).unwrap();
    h.src.lists.store(Some(Arc::clone(&lists.shared)));

    let (s, _, listed) = h.call("GET", "/api/v1/lists", None).await;
    assert_eq!(s, StatusCode::OK, "{listed}");
    assert!(
        listed.to_string().contains("local"),
        "the list is there: {listed}"
    );
    assert!(!listed.to_string().contains(URL_PASSWORD), "{listed}");

    let mut req = h.request("POST", "/api/v1/lists/refresh", Some(&json!({})));
    req.headers_mut()
        .insert("idempotency-key", "refresh-1".parse().unwrap());
    let (s, _, answer) = h.send(req).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{answer}");
    assert!(!answer.contains(URL_PASSWORD), "{answer}");
    assert!(!h.audit_text().contains(URL_PASSWORD), "the audit row");
    let key = format!("{}:refresh-1", h.admin_id);
    let record = h
        .auth
        .state()
        .idempotent(&key, crate::pipeline::unix_now())
        .unwrap()
        .expect("the refresh is remembered");
    let kept = format!(
        "{} {}",
        String::from_utf8_lossy(&record.request),
        record.response
    );
    assert!(
        !kept.contains(URL_PASSWORD),
        "the idempotency record: {kept}"
    );
    assert!(
        !kept.contains("lists/refresh"),
        "a keyed hash, not the text"
    );
    lists.stop();
}

/// REQ: API-002, UPS-004 (T24.36) — an upstream made through the API (the picker, the form, a
/// Pi-hole import) says `added`, and one the file also defines says `override`; never `file`.
#[tokio::test]
async fn ups_004_api_made_upstream_is_not_labelled_file() {
    let h = harness("");
    let body = json!({"url": "tls://1.1.1.1", "tls_server_name": "cloudflare-dns.com"});
    let (s, _, r) = h
        .call("PUT", "/api/v1/upstreams/picker-cloudflare", Some(&body))
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let (_, _, v) = h
        .call("GET", "/api/v1/config/entries?kind=upstream", None)
        .await;
    assert_eq!(entry(&v, "picker-cloudflare")["source"], "added", "{v}");
    assert_eq!(entry(&v, "nextdns")["source"], "file", "{v}");
}

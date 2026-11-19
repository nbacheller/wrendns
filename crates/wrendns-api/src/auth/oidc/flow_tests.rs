//! REQ: API-004 — the whole sign-in flow against in-process fake identity providers: discovery,
//! the key set, the token endpoint, and ID tokens signed with each provider's keys (ring, ADR-951).

// Short names (h, r, v) keep the request/response story readable.
#![allow(clippy::many_single_char_names)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{Json, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::jose::Alg;
use super::testkit::{Signer, hs256_token, unsigned_token};
use super::{Fetch, McpOAuth, Oidc, OidcSettings, ProviderSettings};
use crate::auth::{Auth, Role, Settings};

const ISSUER: &str = "https://idp.test";
const OTHER: &str = "https://other.test";

/// The codes a provider issues: code -> the ID token its token endpoint returns for it.
type Codes = Arc<Mutex<HashMap<String, String>>>;

/// One fake identity provider: the key set it publishes, what its discovery advertises, the
/// client secret its token endpoint requires (none: a public client), and its counters.
#[derive(Clone)]
struct Idp {
    issuer: String,
    keys: Arc<Mutex<Vec<Signer>>>,
    /// `id_token_signing_alg_values_supported`, when advertised.
    advertised: Option<Vec<String>>,
    secret: Option<String>,
    codes: Codes,
    /// Key-set requests served.
    jwks_hits: Arc<AtomicUsize>,
    /// When set, the key set answers HTTP 500.
    jwks_broken: Arc<AtomicBool>,
    /// When set, discovery names an HTTP token endpoint (a scheme downgrade).
    downgrade: bool,
    /// When set, the provider lists and expects `client_secret_post` (not Basic).
    post_auth: bool,
}

impl Idp {
    fn new(issuer: &str, keys: Vec<Signer>, secret: Option<&str>) -> Self {
        Self {
            issuer: issuer.to_owned(),
            keys: Arc::new(Mutex::new(keys)),
            advertised: None,
            secret: secret.map(str::to_owned),
            codes: Arc::default(),
            jwks_hits: Arc::default(),
            jwks_broken: Arc::default(),
            downgrade: false,
            post_auth: false,
        }
    }

    /// Signs `claims` with the published key `kid`.
    fn sign(&self, kid: &str, claims: &Value) -> String {
        let keys = self.keys.lock().unwrap();
        let key = keys
            .iter()
            .find(|k| k.kid == kid)
            .expect("the provider publishes this key");
        key.token(&key.header(), claims)
    }

    /// Replaces the published key set (key rotation).
    fn rotate(&self, keys: Vec<Signer>) {
        *self.keys.lock().unwrap() = keys;
    }

    /// Key-set requests served so far.
    fn hits(&self) -> usize {
        self.jwks_hits.load(Ordering::SeqCst)
    }
}

fn router(idp: Idp) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(idp)
}

async fn discovery(State(s): State<Idp>) -> Json<Value> {
    let token_endpoint = if s.downgrade {
        format!("http://{}/token", s.issuer.trim_start_matches("https://"))
    } else {
        format!("{}/token", s.issuer)
    };
    let mut doc = json!({
        "issuer": s.issuer,
        "authorization_endpoint": format!("{}/authorize", s.issuer),
        "token_endpoint": token_endpoint,
        "jwks_uri": format!("{}/jwks", s.issuer),
        "end_session_endpoint": format!("{}/logout", s.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "token_endpoint_auth_methods_supported": if s.post_auth {
            json!(["client_secret_post"])
        } else {
            json!(["client_secret_basic"])
        },
    });
    if let Some(algs) = &s.advertised {
        doc["id_token_signing_alg_values_supported"] = json!(algs);
    }
    Json(doc)
}

async fn jwks(State(s): State<Idp>) -> Result<Json<Value>, StatusCode> {
    s.jwks_hits.fetch_add(1, Ordering::SeqCst);
    if s.jwks_broken.load(Ordering::SeqCst) {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let keys: Vec<Value> = s.keys.lock().unwrap().iter().map(Signer::jwk).collect();
    Ok(Json(json!({ "keys": keys })))
}

async fn token(
    State(s): State<Idp>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<Value>, StatusCode> {
    let f: HashMap<String, String> = body
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    assert!(f.contains_key("code_verifier"), "PKCE verifier sent");
    // Client authentication: HTTP Basic with the form-encoded ID and secret, or the client ID
    // in the body for a public client (ADR-951 decision 6).
    let basic = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    match &s.secret {
        Some(secret) if s.post_auth => {
            let in_body = f.get("client_id").map(String::as_str) == Some("wrendns")
                && f.get("client_secret").map(String::as_str) == Some(secret.as_str());
            if basic.is_some() || !in_body {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        Some(secret) => {
            let want = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("wrendns:{secret}"))
            );
            if basic.as_deref() != Some(want.as_str()) || f.contains_key("client_id") {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        None => {
            if basic.is_some() || f.get("client_id").map(String::as_str) != Some("wrendns") {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    }
    let code = f.get("code").ok_or(StatusCode::BAD_REQUEST)?;
    let id_token = s
        .codes
        .lock()
        .unwrap()
        .remove(code)
        .ok_or(StatusCode::BAD_REQUEST)?;
    Ok(Json(json!({
        "access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": id_token
    })))
}

/// Serves each provider's router to requests for its host, instead of the network.
fn fetch(routes: HashMap<String, Router>) -> Fetch {
    Arc::new(move |req: Request<Vec<u8>>| {
        let routes = routes.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let host = parts.uri.host().unwrap_or_default().to_owned();
            let idp = routes
                .get(&host)
                .cloned()
                .ok_or_else(|| format!("no fake provider at {host}"))?;
            let path = parts
                .uri
                .path_and_query()
                .map_or("/", |p| p.as_str())
                .to_owned();
            let mut b = Request::builder().method(parts.method).uri(path);
            for (k, v) in &parts.headers {
                b = b.header(k, v);
            }
            let resp = idp
                .oneshot(b.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            let (parts, body) = resp.into_parts();
            let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap().to_vec();
            Ok(axum::http::Response::from_parts(parts, bytes))
        })
    })
}

/// A backend with no data (these tests only use the auth routes).
struct NoData;
impl crate::Backend for NoData {
    fn system_info(&self) -> crate::model::SystemInfo {
        unimplemented!()
    }
    fn timeseries(&self, _: crate::model::Step, _: u64, _: u64) -> Vec<crate::model::TimeBucket> {
        Vec::new()
    }
    fn top(
        &self,
        _: crate::model::TopKind,
        _: crate::model::Hour,
        _: usize,
        _: Option<std::net::IpAddr>,
    ) -> Vec<crate::model::TopItem> {
        Vec::new()
    }
    fn latency(
        &self,
        _: crate::model::LatencyBy,
        _: crate::model::Hour,
    ) -> Vec<crate::model::LatencyRow> {
        Vec::new()
    }
    fn queries(
        &self,
        _: &crate::model::QueryParams,
        _: u64,
        _: u64,
        _: usize,
    ) -> Result<crate::model::QueryPage, crate::problem::Problem> {
        unimplemented!()
    }
    fn explain(
        &self,
        _: &crate::model::ExplainParams,
    ) -> Result<crate::model::Explanation, crate::problem::Problem> {
        unimplemented!()
    }
    fn lists(&self) -> Vec<crate::model::ListInfo> {
        Vec::new()
    }
    fn groups(&self) -> Vec<crate::model::GroupInfo> {
        Vec::new()
    }
    fn clients(&self) -> Vec<crate::model::ClientInfo> {
        Vec::new()
    }
    fn upstreams(&self) -> Vec<crate::model::UpstreamInfo> {
        Vec::new()
    }
}

struct Harness {
    app: Router,
    auth: Arc<Auth>,
    /// The fake providers by `id`.
    idps: HashMap<String, Idp>,
}

/// One provider `fake` (RS256, a client secret), and MCP through it.
fn harness(settings: Settings) -> Harness {
    let fake = Idp::new(ISSUER, vec![Signer::rsa("k1", Alg::Rs256)], Some("s3cret"));
    build(
        settings,
        vec![(provider("fake", "Fake IdP", ISSUER, Some("s3cret")), fake)],
    )
}

fn provider(id: &str, name: &str, issuer: &str, secret: Option<&str>) -> ProviderSettings {
    ProviderSettings {
        id: id.into(),
        name: name.into(),
        issuer: issuer.into(),
        client_id: "wrendns".into(),
        client_secret: secret.map(str::to_owned),
        scopes: vec!["openid".into(), "profile".into()],
        username_claim: "preferred_username".into(),
        groups_claim: "groups".into(),
        roles: vec![
            ("dns-admins".into(), Role::Admin),
            ("family".into(), Role::Viewer),
        ],
        default_role: None,
        require_verified_email: false,
    }
}

/// An app with the given providers (each with its fake), MCP through `fake`, and one admin.
fn build(settings: Settings, providers: Vec<(ProviderSettings, Idp)>) -> Harness {
    let state = Arc::new(wrendns_store::state::State::in_memory().unwrap());
    let auth = Arc::new(Auth::new(state, settings));
    let mut routes = HashMap::new();
    let mut idps = HashMap::new();
    let mut configured = Vec::new();
    for (p, idp) in providers {
        let host = idp.issuer.trim_start_matches("https://").to_owned();
        routes.insert(host, router(idp.clone()));
        idps.insert(p.id.clone(), idp);
        configured.push(p);
    }
    auth.set_oidc(Oidc::new(
        OidcSettings {
            public_url: "https://dns.test".into(),
            providers: configured,
            mcp: Some(McpOAuth {
                provider: "fake".into(),
                audience: "https://dns.test/mcp".into(),
            }),
        },
        fetch(routes),
    ));
    // Someone must exist so the UI isn't in first-run setup.
    auth.create_user("root", "correct horse battery", Role::Admin, false, 1)
        .unwrap();
    let app = crate::router(Arc::new(NoData), Arc::clone(&auth));
    Harness { app, auth, idps }
}

fn query_param(url: &str, k: &str) -> String {
    url.split(['?', '&'])
        .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
        .map(|v| v.replace("%2F", "/").replace("%3A", ":"))
        .unwrap_or_default()
}

fn set_cookie(r: &axum::http::Response<Body>, name: &str) -> Option<String> {
    r.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap_or_default().to_owned())
}

/// The claims a provider issues for a user: `aud` is `client_id` unless the test changes it.
fn id_claims(sub: &str, name: &str, groups: &[&str], nonce: &str) -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    json!({
        "iss": ISSUER, "aud": "wrendns", "sub": sub, "exp": now + 300, "iat": now,
        "nonce": nonce, "preferred_username": name, "groups": groups,
    })
}

/// Starts a sign-in with provider `id`: the flow cookie, the `state` and the `nonce`.
async fn start_flow(h: &Harness, id: &str) -> (String, String, String) {
    let start = h
        .app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/auth/oidc/{id}/start?returnTo=/%23/queries"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::FOUND);
    let to = start.headers()["location"].to_str().unwrap().to_owned();
    let authorize = format!("{}/authorize?", h.idps[id].issuer);
    assert!(
        to.starts_with(&authorize),
        "{to} should start with {authorize}"
    );
    assert!(to.contains("code_challenge_method=S256"), "PKCE");
    assert!(
        to.contains(&format!(
            "redirect_uri=https%3A%2F%2Fdns.test%2Fapi%2Fv1%2Fauth%2Foidc%2F{id}%2Fcallback"
        )),
        "{to}"
    );
    assert!(
        start.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("SameSite=Lax")
    );
    let flow = set_cookie(&start, "wrendns_oidc").unwrap();
    (flow, query_param(&to, "state"), query_param(&to, "nonce"))
}

/// The callback of provider `id` with `state`, from the browser holding `cookie`.
async fn callback(h: &Harness, id: &str, state: &str, cookie: &str) -> Response<Body> {
    h.app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/auth/oidc/{id}/callback?code=code1&state={state}"
            ))
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap()
}

/// Start → (the provider issues `id_token_for(nonce)` for the code) → callback. Returns the
/// callback response. `tamper_cookie` sends a different browser's flow cookie.
async fn sign_in_with(
    h: &Harness,
    id: &str,
    id_token_for: impl FnOnce(&str) -> String,
    tamper_cookie: bool,
) -> Response<Body> {
    let (flow, state, nonce) = start_flow(h, id).await;
    let token = id_token_for(&nonce);
    h.idps[id]
        .codes
        .lock()
        .unwrap()
        .insert("code1".into(), token);
    let cookie = if tamper_cookie {
        "wrendns_oidc=someone-else".to_owned()
    } else {
        flow
    };
    callback(h, id, &state, &cookie).await
}

/// Start → (identity provider: issue code for these claims) → callback. Returns the callback response.
async fn sign_in(
    h: &Harness,
    sub: &str,
    name: &str,
    groups: &[&str],
    tamper_cookie: bool,
) -> axum::http::Response<Body> {
    sign_in_with(
        h,
        "fake",
        |nonce| h.idps["fake"].sign("k1", &id_claims(sub, name, groups, nonce)),
        tamper_cookie,
    )
    .await
}

/// The location a refused sign-in redirects to, as text.
fn refused_at(r: &Response<Body>) -> String {
    r.headers()["location"]
        .to_str()
        .unwrap_or_default()
        .to_owned()
}

async fn me(h: &Harness, session: &str) -> serde_json::Value {
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/me")
                .header("cookie", session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap()).unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one story through the flow
async fn api_004_oidc_sign_in_end_to_end() {
    let h = harness(Settings::default());

    // Status lists the provider; local sign-in is still on.
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap())
            .unwrap();
    assert_eq!(
        v["oidc"][0],
        serde_json::json!({"id": "fake", "name": "Fake IdP"})
    );
    assert_eq!(v["localLogin"], true);

    // First sign-in creates the user with the role from their groups.
    let r = sign_in(&h, "sub-1", "ana", &["dns-admins", "family"], false).await;
    assert_eq!(r.status(), StatusCode::FOUND);
    assert_eq!(
        r.headers()["location"],
        "/#/queries",
        "returns where it started"
    );
    let session = set_cookie(&r, "wrendns_session").expect("signed in");
    let m = me(&h, &session).await;
    assert_eq!(
        (m["username"].as_str(), m["role"].as_str()),
        (Some("ana"), Some("admin"))
    );
    let u = h.auth.state().user_by_name("ana").unwrap().unwrap();
    assert_eq!(u.oidc_provider.as_deref(), Some("fake"));
    assert!(
        !crate::auth::crypto::verify_password("anything", &u.password_hash),
        "no local password"
    );

    // Next sign-in with fewer groups lowers the role, and it's audited.
    let r = sign_in(&h, "sub-1", "ana", &["family"], false).await;
    let session = set_cookie(&r, "wrendns_session").unwrap();
    assert_eq!(me(&h, &session).await["role"], "viewer");
    let updates = h
        .auth
        .state()
        .audit_page(None, 10, Some("user.update"), None)
        .unwrap();
    assert!(
        updates[0]
            .detail
            .contains("\"from\":\"admin\",\"to\":\"viewer\""),
        "{}",
        updates[0].detail
    );
    let logins = h
        .auth
        .state()
        .audit_page(None, 10, Some("auth.login"), None)
        .unwrap();
    assert!(
        logins
            .iter()
            .all(|e| e.actor_kind == "oidc" && e.detail.contains("\"provider\":\"fake\""))
    );

    // A local account with the same name is never taken over: the new user gets name@provider.
    let r = sign_in(&h, "sub-2", "root", &["family"], false).await;
    let session = set_cookie(&r, "wrendns_session").unwrap();
    assert_eq!(me(&h, &session).await["username"], "root@fake");

    // No mapped group: refused, back to sign-in with the reason.
    let r = sign_in(&h, "sub-3", "eve", &["strangers"], false).await;
    let to = r.headers()["location"].to_str().unwrap();
    assert!(
        to.starts_with("/#/?loginError=") && to.contains("group"),
        "{to}"
    );
    assert!(set_cookie(&r, "wrendns_session").is_none());

    // A callback from a different browser (no matching flow cookie) is refused.
    let r = sign_in(&h, "sub-1", "ana", &["family"], true).await;
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("another%20browser")
    );
    assert!(set_cookie(&r, "wrendns_session").is_none());

    // Signing out of an OIDC session points at the provider's logout.
    let r = sign_in(&h, "sub-1", "ana", &["family"], false).await;
    let session = set_cookie(&r, "wrendns_session").unwrap();
    let csrf = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/status")
                .header("cookie", &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(csrf.into_body(), 1 << 16)
            .await
            .unwrap(),
    )
    .unwrap();
    let out = h
        .app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/logout")
                .header("cookie", &session)
                .header("x-csrf-token", v["csrfToken"].as_str().unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(out.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(out.into_body(), 1 << 16)
            .await
            .unwrap(),
    )
    .unwrap();
    let url = v["logoutUrl"].as_str().unwrap();
    assert!(url.starts_with("https://idp.test/logout?client_id=wrendns&post_logout_redirect_uri=https%3A%2F%2Fdns.test%2F"), "{url}");
}

#[tokio::test]
async fn api_004_states_are_single_use_and_unknown_providers_404() {
    let h = harness(Settings::default());
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/oidc/fake/callback?code=x&state=never-issued")
                .header("cookie", "wrendns_oidc=x")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("expired")
    );
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/oidc/nope/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("no%20sign-in%20provider")
    );
    let r = h.app.clone().oneshot(Request::get("/api/v1/auth/oidc/fake/callback?error=access_denied&error_description=User%20cancelled").body(Body::empty()).unwrap()).await.unwrap();
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("loginError=")
    );
}

/// Break-glass: with local sign-in off, passwords work only for admins from admin networks.
#[tokio::test]
async fn api_004_disable_local_login_keeps_a_break_glass_admin() {
    let lan = Settings {
        disable_local_login: true,
        admin_networks: vec![("0.0.0.0".parse().unwrap(), 0)],
        ..Settings::default()
    };
    let h = harness(lan);
    h.auth
        .create_user("kid", "another long password", Role::Viewer, false, 1)
        .unwrap();
    let ip = "192.168.1.5".parse().unwrap();
    assert!(
        h.auth
            .login("root", "correct horse battery", None, None, ip, 10)
            .is_ok(),
        "admin from an admin network"
    );
    let e = h
        .auth
        .login("kid", "another long password", None, None, ip, 10)
        .unwrap_err();
    assert_eq!(
        e.code,
        crate::problem::Code::Forbidden,
        "non-admins must use the provider"
    );

    let closed = Settings {
        disable_local_login: true,
        admin_networks: vec![("10.0.0.0".parse().unwrap(), 8)],
        ..Settings::default()
    };
    let h = harness(closed);
    let e = h
        .auth
        .login("root", "correct horse battery", None, None, ip, 10)
        .unwrap_err();
    assert_eq!(
        e.code,
        crate::problem::Code::Forbidden,
        "not from an admin network"
    );
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap())
            .unwrap();
    assert_eq!(v["localLogin"], false, "the UI hides the password form");
    assert!(crate::auth::in_network(
        "10.1.2.3".parse().unwrap(),
        "10.0.0.0".parse().unwrap(),
        8
    ));
    assert!(crate::auth::in_network(
        "::ffff:10.1.2.3".parse().unwrap(),
        "10.0.0.0".parse().unwrap(),
        8
    ));
    assert!(!crate::auth::in_network(
        "11.1.2.3".parse().unwrap(),
        "10.0.0.0".parse().unwrap(),
        8
    ));
}

/// An access token from the fake provider (the MCP provider), signed with its RSA key `k1`.
fn access_token(claims: &serde_json::Value) -> String {
    Signer::rsa("k1", Alg::Rs256).token(
        &json!({"alg": "RS256", "kid": "k1", "typ": "at+jwt"}),
        claims,
    )
}

async fn mcp_call(
    app: &Router,
    bearer: &str,
    body: serde_json::Value,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// REQ: AGT-008 (T7.4) — OAuth for MCP: the metadata names the provider; a 401 says where
/// to sign in; a valid access token acts as an agent with the consented scopes (never above
/// the user's role); wrong audience, expiry, and unknown users are refused.
#[tokio::test]
async fn agt_008_mcp_oauth_access_tokens() {
    let h = harness(Settings::default());
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/.well-known/oauth-protected-resource")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let meta: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap())
            .unwrap();
    assert_eq!(meta["resource"], "https://dns.test/mcp");
    assert_eq!(meta["authorization_servers"][0], ISSUER);
    assert!(
        meta["scopes_supported"]
            .as_array()
            .unwrap()
            .contains(&"config:write:rules".into())
    );

    // No credentials: a challenge pointing at the metadata.
    let r = h
        .app
        .clone()
        .oneshot(Request::post("/mcp").body(Body::from("{}")).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let www = r.headers()["www-authenticate"].to_str().unwrap().to_owned();
    assert!(
        www.contains("resource_metadata=\"https://dns.test/.well-known/oauth-protected-resource\""),
        "{www}"
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let claims = |aud: &str, exp: u64, sub: &str, scope: &str| serde_json::json!({"iss": ISSUER, "aud": aud, "exp": exp, "iat": now, "sub": sub, "azp": "claude-desktop", "scope": scope});
    // A user who has signed in to the UI with the provider before (an operator).
    h.auth
        .state()
        .create_oidc_user("alice", "operator", "fake", "sub-alice", 1)
        .unwrap();
    let list = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let ok = access_token(&claims(
        "https://dns.test/mcp",
        now + 300,
        "sub-alice",
        "openid analytics:read",
    ));
    assert_eq!(
        mcp_call(&h.app, &ok, list.clone()).await.status(),
        StatusCode::OK
    );
    // Read-only consent: a write tool is refused inside the tool.
    let plan = serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "plan_block_domain", "arguments": {"domain": "x.example", "reason": "test"}}});
    let r = mcp_call(&h.app, &ok, plan).await;
    let v: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap())
            .unwrap();
    assert_eq!(v["result"]["isError"], true, "{v}");
    assert!(v.to_string().contains("config:write:rules"), "{v}");
    // Refused: another audience, expired, a stranger, a forged signature.
    for (token, why) in [
        (
            access_token(&claims(
                "https://other.test/mcp",
                now + 300,
                "sub-alice",
                "",
            )),
            "not issued for",
        ),
        (
            access_token(&claims("https://dns.test/mcp", now - 3600, "sub-alice", "")),
            "expired",
        ),
        (
            access_token(&claims("https://dns.test/mcp", now + 300, "sub-bob", "")),
            "hasn't used WrenDNS",
        ),
        (format!("{}x", &ok[..ok.len() - 4]), "signature"),
    ] {
        let r = mcp_call(&h.app, &token, list.clone()).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{why}");
        assert!(
            r.headers()["www-authenticate"]
                .to_str()
                .unwrap()
                .contains("invalid_token"),
            "{why}"
        );
        let body = String::from_utf8(
            axum::body::to_bytes(r.into_body(), 1 << 16)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains(why), "{why}: {body}");
    }
}

/// Harness with four providers: `fake` (RS256, a client secret, the MCP provider), `other`
/// (ES256 under `e1`), `ed` (`EdDSA` under `d1`) and `pub` (a public client, no secret).
fn four_providers() -> Harness {
    let fake = Idp::new(ISSUER, vec![Signer::rsa("k1", Alg::Rs256)], Some("s3cret"));
    let other = Idp::new(
        OTHER,
        vec![Signer::generated("e1", Alg::Es256)],
        Some("s3cret"),
    );
    let ed = Idp::new(
        "https://ed.test",
        vec![Signer::generated("d1", Alg::EdDsa)],
        Some("s3cret"),
    );
    let public = Idp::new(
        "https://pub.test",
        vec![Signer::rsa("p1", Alg::Rs256)],
        None,
    );
    build(
        Settings::default(),
        vec![
            (provider("fake", "Fake IdP", ISSUER, Some("s3cret")), fake),
            (provider("other", "Other IdP", OTHER, Some("s3cret")), other),
            (
                provider("ed", "Ed IdP", "https://ed.test", Some("s3cret")),
                ed,
            ),
            (
                provider("pub", "Public IdP", "https://pub.test", None),
                public,
            ),
        ],
    )
}

/// The refusal a sign-in gets: back to the sign-in page with the reason, and no session.
fn assert_refused(r: &Response<Body>, why: &str) {
    let to = refused_at(r);
    assert!(to.starts_with("/#/?loginError="), "{why}: {to}");
    assert!(to.contains(why), "{why}: {to}");
    assert!(set_cookie(r, "wrendns_session").is_none(), "{why}");
}

/// REQ: API-004 — a token must be for this provider and this client: a token signed with another
/// provider's key is refused at this provider's callback.
#[tokio::test]
async fn api_004_a_token_from_another_provider_is_refused() {
    let h = four_providers();
    let other = &h.idps["other"];
    let r = sign_in_with(
        &h,
        "fake",
        |nonce| {
            let mut c = id_claims("sub-1", "ana", &["family"], nonce);
            c["iss"] = json!(OTHER);
            // Signed by the other provider's key (e1), presented at fake's callback.
            other.sign("e1", &c)
        },
        false,
    )
    .await;
    assert_refused(&r, "fits");
}

/// REQ: API-004 — an audience other than this client is refused, even alongside it (ADR-951).
#[tokio::test]
async fn api_004_extra_untrusted_audience_rejected() {
    let h = four_providers();
    let r = sign_in_with(
        &h,
        "fake",
        |nonce| {
            let mut c = id_claims("sub-1", "ana", &["family"], nonce);
            c["aud"] = json!(["wrendns", "other-app"]);
            c["azp"] = json!("wrendns");
            h.idps["fake"].sign("k1", &c)
        },
        false,
    )
    .await;
    assert_refused(&r, "alone");
    let r = sign_in_with(
        &h,
        "fake",
        |nonce| {
            let mut c = id_claims("sub-1", "ana", &["family"], nonce);
            c["aud"] = json!("other-app");
            h.idps["fake"].sign("k1", &c)
        },
        false,
    )
    .await;
    assert_refused(&r, "alone");
}

/// REQ: API-004 — each claim the flow checks, tampered one at a time, is refused. The claims
/// are built with the nonce of the flow being started.
#[tokio::test]
async fn api_004_tampered_claims_are_refused() {
    let cases: Vec<(&str, Value, &str)> = vec![
        ("iss", json!(42), "issuer"),
        ("iss", json!("https://evil.test"), "another"),
        ("exp", json!("9999999999"), "whole"),
        ("nbf", json!("9999999999"), "whole"),
        ("iat", Value::Null, "issue"),
        ("nonce", json!("someone-else"), "nonce"),
        ("sub", json!(""), "subject"),
        ("azp", json!("other-app"), "azp"),
    ];
    for (name, value, why) in cases {
        let h = four_providers();
        let r = sign_in_with(
            &h,
            "fake",
            |nonce| {
                let mut c = id_claims("sub-x", "x", &["family"], nonce);
                if value.is_null() {
                    c.as_object_mut().expect("object").remove(name);
                } else {
                    c[name] = value.clone();
                }
                h.idps["fake"].sign("k1", &c)
            },
            false,
        )
        .await;
        assert_refused(&r, why);
    }
    // An expired token, and a token not valid yet.
    let h = four_providers();
    let r = sign_in_with(
        &h,
        "fake",
        |nonce| {
            let mut c = id_claims("sub-x", "x", &["family"], nonce);
            c["exp"] = json!(1_000_000u64);
            h.idps["fake"].sign("k1", &c)
        },
        false,
    )
    .await;
    assert_refused(&r, "expired");
    let h = four_providers();
    let r = sign_in_with(
        &h,
        "fake",
        |nonce| {
            let mut c = id_claims("sub-x", "x", &["family"], nonce);
            c["nbf"] = json!(4_000_000_000u64);
            h.idps["fake"].sign("k1", &c)
        },
        false,
    )
    .await;
    assert_refused(&r, "not%20valid%20yet");
}

/// REQ: API-004 — the header rules: `alg=none`, HS256 with the public key as the secret, and an
/// access token's `typ` (`at+jwt`) presented as an ID token.
#[tokio::test]
async fn api_004_forged_and_mistyped_headers_are_refused() {
    let h = four_providers();
    let claims = id_claims("sub-1", "ana", &["family"], "x");
    let n = {
        let keys = h.idps["fake"].keys.lock().unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(keys[0].jwk()["n"].as_str().unwrap())
            .unwrap()
    };
    let none = unsigned_token(&json!({"alg": "none", "kid": "k1"}), &claims);
    let r = sign_in_with(&h, "fake", |_| none, false).await;
    assert_refused(&r, "algorithm");
    let hs = hs256_token(&n, &claims);
    let r = sign_in_with(&h, "fake", |_| hs, false).await;
    assert_refused(&r, "algorithm");
    let r = sign_in_with(
        &h,
        "fake",
        |nonce| {
            let c = id_claims("sub-1", "ana", &["family"], nonce);
            Signer::rsa("k1", Alg::Rs256)
                .token(&json!({"alg": "RS256", "kid": "k1", "typ": "at+jwt"}), &c)
        },
        false,
    )
    .await;
    assert_refused(&r, "type");
}

/// REQ: API-004 — a provider whose discovery lists only RS256 is never accepted with ES256.
#[tokio::test]
async fn api_004_the_provider_allow_list_is_enforced_in_the_flow() {
    let mut fake = Idp::new(
        ISSUER,
        vec![
            Signer::rsa("k1", Alg::Rs256),
            Signer::generated("e1", Alg::Es256),
        ],
        Some("s3cret"),
    );
    fake.advertised = Some(vec!["RS256".into()]);
    let h = build(
        Settings::default(),
        vec![(provider("fake", "Fake IdP", ISSUER, Some("s3cret")), fake)],
    );
    let r = sign_in_with(
        &h,
        "fake",
        |nonce| h.idps["fake"].sign("e1", &id_claims("sub-1", "ana", &["family"], nonce)),
        false,
    )
    .await;
    assert_refused(&r, "algorithm");
}

/// REQ: API-004 — an unknown key ID refetches the key set once per provider per minute.
#[tokio::test]
async fn api_004_key_set_refetch_is_rate_limited_and_keeps_good_keys() {
    let h = four_providers();
    let fake = &h.idps["fake"];
    let rogue = Signer::rsa("k9", Alg::Rs256);
    let r = sign_in_with(
        &h,
        "fake",
        |nonce| {
            rogue.token(
                &rogue.header(),
                &id_claims("sub-1", "ana", &["family"], nonce),
            )
        },
        false,
    )
    .await;
    assert_refused(&r, "fits");
    assert_eq!(
        fake.hits(),
        2,
        "the discovery read, then one refetch for the unknown kid"
    );
    // A second unknown kid within a minute: no refetch.
    let r = sign_in_with(
        &h,
        "fake",
        |nonce| {
            rogue.token(
                &rogue.header(),
                &id_claims("sub-1", "ana", &["family"], nonce),
            )
        },
        false,
    )
    .await;
    assert_refused(&r, "fits");
    assert_eq!(fake.hits(), 2, "rate limited");
    // The other provider has its own limit.
    let other = &h.idps["other"];
    let r = sign_in_with(
        &h,
        "other",
        |nonce| {
            let mut c = id_claims("sub-1", "ana", &["family"], nonce);
            c["iss"] = json!(OTHER);
            rogue.token(&rogue.header(), &c)
        },
        false,
    )
    .await;
    assert_refused(&r, "fits");
    assert_eq!(
        other.hits(),
        2,
        "its own discovery read and refetch, per provider"
    );
}

/// REQ: API-004 — a failed key-set refetch keeps the cached keys: the flow that found the unknown
/// key is refused, and a token whose key is cached still signs in.
#[tokio::test]
async fn api_004_a_failed_key_set_refetch_keeps_the_cached_keys() {
    let h = four_providers();
    let fake = &h.idps["fake"];
    // The first sign-in reads the discovery document and the key set.
    let r = sign_in(&h, "sub-1", "ana", &["family"], false).await;
    assert!(
        set_cookie(&r, "wrendns_session").is_some(),
        "the first sign-in"
    );
    let before = fake.hits();
    fake.jwks_broken.store(true, Ordering::SeqCst);
    let rogue = Signer::rsa("k9", Alg::Rs256);
    let r = sign_in_with(
        &h,
        "fake",
        |nonce| {
            rogue.token(
                &rogue.header(),
                &id_claims("sub-1", "ana", &["family"], nonce),
            )
        },
        false,
    )
    .await;
    assert_refused(&r, "fits");
    assert_eq!(
        fake.hits(),
        before + 1,
        "the refetch was attempted, and failed"
    );
    let r = sign_in(&h, "sub-1", "ana", &["family"], false).await;
    assert!(
        set_cookie(&r, "wrendns_session").is_some(),
        "the cached keys still verify"
    );
    fake.jwks_broken.store(false, Ordering::SeqCst);
}

/// REQ: API-004 — a rotated key is accepted after the key set is refetched (ADR-951, JWKS).
#[tokio::test]
async fn api_004_jwks_rotation_is_accepted_after_the_refetch() {
    let h = four_providers();
    let fake = &h.idps["fake"];
    let r = sign_in_with(
        &h,
        "fake",
        |nonce| {
            // Rotate while the flow is in progress: the cache knows only k1, so the new key is
            // found by the refetch that the unknown kid triggers.
            let new = Signer::generated("k2", Alg::Es256);
            let token = new.token(
                &new.header(),
                &id_claims("sub-1", "ana", &["family"], nonce),
            );
            fake.rotate(vec![Signer::rsa("k1", Alg::Rs256), new]);
            token
        },
        false,
    )
    .await;
    assert!(
        set_cookie(&r, "wrendns_session").is_some(),
        "accepted after the refetch"
    );
}

/// REQ: API-004 — discovery that downgrades an endpoint to HTTP for an HTTPS issuer is refused,
/// and no flow starts.
#[tokio::test]
async fn api_004_scheme_downgrade_is_refused() {
    let mut fake = Idp::new(ISSUER, vec![Signer::rsa("k1", Alg::Rs256)], Some("s3cret"));
    fake.downgrade = true;
    let h = build(
        Settings::default(),
        vec![(provider("fake", "Fake IdP", ISSUER, Some("s3cret")), fake)],
    );
    let start = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/oidc/fake/start?returnTo=/%23/queries")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let to = refused_at(&start);
    assert!(to.contains("HTTPS"), "{to}");
    assert!(
        set_cookie(&start, "wrendns_oidc").is_none(),
        "no flow started"
    );
}

/// REQ: API-004 — a public client (no secret) signs in with its client ID in the token body.
#[tokio::test]
async fn api_004_public_client_signs_in_without_a_secret() {
    let h = four_providers();
    let r = sign_in_with(
        &h,
        "pub",
        |nonce| {
            let mut c = id_claims("sub-p", "pat", &["family"], nonce);
            c["iss"] = json!("https://pub.test");
            h.idps["pub"].sign("p1", &c)
        },
        false,
    )
    .await;
    assert!(set_cookie(&r, "wrendns_session").is_some(), "signed in");
}

/// REQ: API-004 — a provider that lists only `client_secret_post` gets the secret in the body.
#[tokio::test]
async fn api_004_client_secret_post_when_it_is_the_only_method() {
    let mut fake = Idp::new(ISSUER, vec![Signer::rsa("k1", Alg::Rs256)], Some("s3cret"));
    fake.post_auth = true;
    let h = build(
        Settings::default(),
        vec![(provider("fake", "Fake IdP", ISSUER, Some("s3cret")), fake)],
    );
    let r = sign_in(&h, "sub-1", "ana", &["family"], false).await;
    assert!(
        set_cookie(&r, "wrendns_session").is_some(),
        "signed in with post"
    );
}

/// REQ: API-004 — an ES256 provider and an `EdDSA` provider sign in, each with its own key.
#[tokio::test]
async fn api_004_es256_and_eddsa_providers_sign_in() {
    let h = four_providers();
    let r = sign_in_with(
        &h,
        "other",
        |nonce| {
            let mut c = id_claims("sub-o", "oscar", &["family"], nonce);
            c["iss"] = json!(OTHER);
            h.idps["other"].sign("e1", &c)
        },
        false,
    )
    .await;
    assert!(set_cookie(&r, "wrendns_session").is_some(), "ES256");
    let r = sign_in_with(
        &h,
        "ed",
        |nonce| {
            let mut c = id_claims("sub-e", "edda", &["family"], nonce);
            c["iss"] = json!("https://ed.test");
            h.idps["ed"].sign("d1", &c)
        },
        false,
    )
    .await;
    assert!(set_cookie(&r, "wrendns_session").is_some(), "EdDSA");
}

/// REQ: AGT-008 — MCP access tokens: one signed by another provider's key, `alg=none`, HS256
/// with the public key, an unknown `kid` (refetched once, then rate limited) are refused, and
/// the MCP provider's own token still works.
#[tokio::test]
async fn agt_008_mcp_token_negatives() {
    let h = four_providers();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    h.auth
        .state()
        .create_oidc_user("alice", "operator", "fake", "sub-alice", 1)
        .unwrap();
    let claims = json!({"iss": ISSUER, "aud": "https://dns.test/mcp", "exp": now + 300, "iat": now, "sub": "sub-alice", "azp": "claude-desktop", "scope": "openid analytics:read"});
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    // Another provider's key (e1, ES256) for a token that names this resource.
    let mut foreign = claims.clone();
    foreign["iss"] = json!(OTHER);
    let token = h.idps["other"].sign("e1", &foreign);
    let r = mcp_call(&h.app, &token, list.clone()).await;
    assert_eq!(
        r.status(),
        StatusCode::UNAUTHORIZED,
        "another provider's key"
    );
    // alg=none.
    let token = unsigned_token(&json!({"alg": "none", "kid": "k1"}), &claims);
    let r = mcp_call(&h.app, &token, list.clone()).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "alg=none");
    // HS256 with the RSA public key as the secret.
    let n = {
        let keys = h.idps["fake"].keys.lock().unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(keys[0].jwk()["n"].as_str().unwrap())
            .unwrap()
    };
    let token = hs256_token(&n, &claims);
    let r = mcp_call(&h.app, &token, list.clone()).await;
    assert_eq!(
        r.status(),
        StatusCode::UNAUTHORIZED,
        "HS256 with the public key"
    );
    // An unknown kid: refetched once, then refused, and not refetched again within a minute.
    let fake = &h.idps["fake"];
    let rogue = Signer::rsa("k9", Alg::Rs256);
    let token = rogue.token(&rogue.header(), &claims);
    // The foreign token above already refetched this provider's key set, so the window is open
    // and neither unknown-kid request refetches again.
    let before = fake.hits();
    let r = mcp_call(&h.app, &token, list.clone()).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "unknown kid");
    assert_eq!(fake.hits(), before, "rate limited");
    let r = mcp_call(&h.app, &token, list.clone()).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(fake.hits(), before, "still rate limited");
    // The MCP provider's own token still works.
    let good = fake.sign("k1", &claims);
    assert_eq!(
        mcp_call(&h.app, &good, list.clone()).await.status(),
        StatusCode::OK
    );
}

/// REQ: API-004 — a state this browser didn't start is refused, the right state signs in once,
/// and a replay of it is refused.
#[tokio::test]
async fn api_004_state_mismatch_and_replay_are_refused() {
    let h = four_providers();
    let fake = &h.idps["fake"];
    let (flow, state, nonce) = start_flow(&h, "fake").await;
    let token = fake.sign("k1", &id_claims("sub-1", "ana", &["family"], &nonce));
    fake.codes
        .lock()
        .unwrap()
        .insert("code1".into(), token.clone());
    let r = callback(&h, "fake", "not-my-state", &flow).await;
    assert_refused(&r, "expired");
    let r = callback(&h, "fake", &state, &flow).await;
    assert!(
        set_cookie(&r, "wrendns_session").is_some(),
        "the right state signs in"
    );
    fake.codes.lock().unwrap().insert("code1".into(), token);
    let r = callback(&h, "fake", &state, &flow).await;
    assert_refused(&r, "expired");
}

/// REQ: API-004 — concurrent refetches for one provider collapse into one key-set fetch (ADR-951).
#[tokio::test]
async fn api_004_concurrent_refetches_collapse_into_one() {
    let h = four_providers();
    let fake = &h.idps["fake"];
    let oidc = h.auth.oidc().expect("OIDC configured");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let claims = json!({"iss": ISSUER, "aud": "https://dns.test/mcp", "exp": now + 300, "iat": now, "sub": "sub-1"});
    // Warm the cache: the discovery read.
    let good = fake.sign("k1", &claims);
    oidc.verify_access_token(&good, now)
        .await
        .expect("the cached key verifies");
    let before = fake.hits();
    let rogue = Signer::rsa("k9", Alg::Rs256);
    let a = rogue.token(&rogue.header(), &claims);
    let b = rogue.token(&rogue.header(), &claims);
    let (ra, rb) = tokio::join!(
        oidc.verify_access_token(&a, now),
        oidc.verify_access_token(&b, now)
    );
    assert!(ra.is_err() && rb.is_err(), "both refused");
    assert_eq!(fake.hits(), before + 1, "one fetch for both");
}

// ---- API-016 (T23.10): providers applied without a restart

/// An app whose `Auth` starts with no provider, the fake provider reachable at `idp.test`, and
/// the fetch to hand to `reload_oidc`.
fn reload_harness() -> (Harness, Fetch) {
    let fake = Idp::new(ISSUER, vec![Signer::rsa("k1", Alg::Rs256)], Some("s3cret"));
    let mut routes = HashMap::new();
    routes.insert("idp.test".to_owned(), router(fake.clone()));
    let f = fetch(routes);
    let state = Arc::new(wrendns_store::state::State::in_memory().unwrap());
    let auth = Arc::new(Auth::new(state, Settings::default()));
    auth.start_oidc(oidc_settings(Vec::new()), Vec::new(), Arc::clone(&f));
    auth.create_user("root", "correct horse battery", Role::Admin, false, 1)
        .unwrap();
    let app = crate::router(Arc::new(NoData), Arc::clone(&auth));
    let mut idps = HashMap::new();
    idps.insert("fake".to_owned(), fake);
    (Harness { app, auth, idps }, f)
}

fn oidc_settings(providers: Vec<ProviderSettings>) -> OidcSettings {
    OidcSettings {
        public_url: "https://dns.test".into(),
        providers,
        mcp: None,
    }
}

async fn status_buttons(h: &Harness) -> Value {
    let r = h
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v: Value =
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap())
            .unwrap();
    v["oidc"].clone()
}

/// Signs `sub` in through provider `fake`; the session cookie.
async fn session_for(h: &Harness, sub: &str, groups: &[&str]) -> String {
    let r = sign_in(h, sub, sub, groups, false).await;
    assert_eq!(r.status(), StatusCode::FOUND);
    set_cookie(&r, "wrendns_session").expect("signed in")
}

async fn me_status(h: &Harness, session: &str) -> StatusCode {
    h.app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/me")
                .header("cookie", session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// REQ: API-016 — a provider added after start serves sign-ins at once: its button appears and a
/// person signs in, with no restart.
#[tokio::test]
async fn api_016_oidc_provider_added_without_restart() {
    let (h, f) = reload_harness();
    assert_eq!(status_buttons(&h).await, json!([]));
    let out = h
        .auth
        .reload_oidc(
            oidc_settings(vec![provider("fake", "Fake IdP", ISSUER, Some("s3cret"))]),
            Vec::new(),
            f,
        )
        .await;
    assert_eq!(
        out,
        super::Reloaded::Applied(vec![super::ProviderStatus::active("fake").at(ISSUER)])
    );
    assert_eq!(
        status_buttons(&h).await,
        json!([{"id": "fake", "name": "Fake IdP"}])
    );
    let session = session_for(&h, "ana", &["dns-admins"]).await;
    assert_eq!(me(&h, &session).await["role"], "admin");
}

/// REQ: API-016 — a changed issuer that can't be read is left out with the reason (it fails
/// closed); so is a new provider that can't be read. (An unchanged issuer keeps its previous
/// settings: `api_016_oidc_unchanged_issuer_keeps_previous`.)
#[tokio::test]
async fn api_016_oidc_discovery_failure_keeps_previous() {
    let (h, f) = reload_harness();
    h.auth
        .reload_oidc(
            oidc_settings(vec![provider("fake", "Fake IdP", ISSUER, Some("s3cret"))]),
            Vec::new(),
            Arc::clone(&f),
        )
        .await;
    // The issuer moves to a host nobody serves.
    let out = h
        .auth
        .reload_oidc(
            oidc_settings(vec![
                provider("fake", "Renamed", OTHER, Some("s3cret")),
                provider("new", "New", "https://gone.test", None),
            ]),
            Vec::new(),
            f,
        )
        .await;
    let super::Reloaded::Applied(status) = out else {
        panic!("applied")
    };
    // A changed issuer that can't be read fails closed: the old issuer isn't trusted on.
    let fake = status.iter().find(|s| s.id == "fake").unwrap();
    assert!(
        !fake.active
            && fake.retry
            && fake
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("couldn't be read")),
        "{fake:?}"
    );
    let new = status.iter().find(|s| s.id == "new").unwrap();
    assert!(!new.active, "{new:?}");
    assert_eq!(
        status_buttons(&h).await,
        json!([]),
        "the old issuer no longer serves sign-ins"
    );
}

/// REQ: API-016 — sessions made through a provider survive a rebuild that keeps it, and end when
/// the provider is removed.
#[tokio::test]
async fn api_016_oidc_sessions_survive_reload() {
    let (h, f) = reload_harness();
    let p = provider("fake", "Fake IdP", ISSUER, Some("s3cret"));
    h.auth
        .reload_oidc(oidc_settings(vec![p.clone()]), Vec::new(), Arc::clone(&f))
        .await;
    let session = session_for(&h, "ana", &["dns-admins"]).await;
    assert_eq!(me_status(&h, &session).await, StatusCode::OK);
    // A changed provider (new role rules, new secret) keeps the session.
    let mut changed = p.clone();
    changed.roles.push(("extra".into(), Role::Operator));
    changed.client_secret = Some("rotated".into());
    h.auth
        .reload_oidc(oidc_settings(vec![changed]), Vec::new(), Arc::clone(&f))
        .await;
    assert_eq!(me_status(&h, &session).await, StatusCode::OK);
    // A provider that is only inactive here (say, no public_url) keeps its sessions too.
    h.auth
        .reload_oidc(
            oidc_settings(Vec::new()),
            vec![super::ProviderStatus::inactive("fake", "no public_url")],
            Arc::clone(&f),
        )
        .await;
    assert_eq!(me_status(&h, &session).await, StatusCode::OK);
    // Removed: the session ends.
    h.auth
        .reload_oidc(oidc_settings(Vec::new()), Vec::new(), f)
        .await;
    assert_eq!(me_status(&h, &session).await, StatusCode::UNAUTHORIZED);
}

/// REQ: API-016 (ADR-967 point 7) — a provider repointed to another issuer ends the sessions
/// opened at the old one (even when the new one can't be read), and a user linked at the old
/// issuer isn't mapped onto a subject of the new one.
#[tokio::test]
async fn api_016_oidc_issuer_change_ends_sessions() {
    let (h, f) = reload_harness();
    let p = provider("fake", "Fake IdP", ISSUER, Some("s3cret"));
    h.auth
        .reload_oidc(oidc_settings(vec![p.clone()]), Vec::new(), Arc::clone(&f))
        .await;
    let session = session_for(&h, "ana", &["dns-admins"]).await;
    assert_eq!(me_status(&h, &session).await, StatusCode::OK);
    let user = h.auth.state().user_by_oidc("fake", "ana").unwrap().unwrap();
    assert_eq!(user.oidc_issuer.as_deref(), Some(ISSUER));
    // Repointed at an issuer nobody serves: the session ends at once.
    let mut moved = p.clone();
    moved.issuer = OTHER.into();
    h.auth
        .reload_oidc(oidc_settings(vec![moved]), Vec::new(), Arc::clone(&f))
        .await;
    assert_eq!(me_status(&h, &session).await, StatusCode::UNAUTHORIZED);
    // Back at the first issuer, a user linked at another one isn't mapped.
    h.auth
        .reload_oidc(oidc_settings(vec![p]), Vec::new(), f)
        .await;
    h.auth.state().set_user_issuer(user.id, OTHER).unwrap();
    let r = sign_in(&h, "ana", "ana", &["dns-admins"], false).await;
    assert_refused(&r, "another%20issuer");
}

/// REQ: API-016 (ADR-967 point 7) — a repointed provider this node can't serve at all (its new
/// secret can't be read, so it is skipped) still ends the old issuer's sessions.
#[tokio::test]
async fn api_016_oidc_skipped_repointed_provider_ends_sessions() {
    let (h, f) = reload_harness();
    h.auth
        .reload_oidc(
            oidc_settings(vec![provider("fake", "Fake IdP", ISSUER, Some("s3cret"))]),
            Vec::new(),
            Arc::clone(&f),
        )
        .await;
    let session = session_for(&h, "ana", &["dns-admins"]).await;
    assert_eq!(me_status(&h, &session).await, StatusCode::OK);
    h.auth
        .reload_oidc(
            oidc_settings(Vec::new()),
            vec![super::ProviderStatus::inactive("fake", "the secret file is missing").at(OTHER)],
            f,
        )
        .await;
    assert_eq!(me_status(&h, &session).await, StatusCode::UNAUTHORIZED);
}

/// REQ: API-016 — a provider that can't be read just now keeps its previous settings when its
/// issuer is unchanged (it is down, not repointed), with the reason and a retry.
#[tokio::test]
async fn api_016_oidc_unchanged_issuer_keeps_previous() {
    let (h, _f) = reload_harness();
    let p = provider("fake", "Fake IdP", ISSUER, Some("s3cret"));
    let down = fetch(HashMap::new());
    // As after a restart while the provider is down: settings in place, discovery not read.
    h.auth.start_oidc(
        oidc_settings(vec![p.clone()]),
        Vec::new(),
        Arc::clone(&down),
    );
    let mut renamed = p;
    renamed.name = "Renamed".into();
    let out = h
        .auth
        .reload_oidc(oidc_settings(vec![renamed]), Vec::new(), down)
        .await;
    let super::Reloaded::Applied(status) = out else {
        panic!("applied")
    };
    let fake = status.iter().find(|s| s.id == "fake").unwrap();
    assert!(
        fake.active && fake.retry && fake.reason.is_some(),
        "{fake:?}"
    );
    assert_eq!(
        status_buttons(&h).await,
        json!([{"id": "fake", "name": "Fake IdP"}])
    );
}

/// REQ: API-016 (ADR-967 point 7) — a user of a provider the configuration no longer names can't
/// use a session or a token, even one the removal's sweep never saw (a node that was down).
#[tokio::test]
async fn api_016_oidc_removed_provider_users_cannot_authenticate() {
    let (h, f) = reload_harness();
    let p = provider("fake", "Fake IdP", ISSUER, Some("s3cret"));
    h.auth
        .reload_oidc(oidc_settings(vec![p]), Vec::new(), Arc::clone(&f))
        .await;
    let session = session_for(&h, "ana", &["dns-admins"]).await;
    assert_eq!(me_status(&h, &session).await, StatusCode::OK);
    h.auth
        .reload_oidc(oidc_settings(Vec::new()), Vec::new(), f)
        .await;
    let user = h.auth.state().user_by_oidc("fake", "ana").unwrap().unwrap();
    // A session that survived (written after the sweep, as on a node that missed the removal).
    let late = h
        .auth
        .start_session(
            &user,
            "127.0.0.1".parse().unwrap(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
        .unwrap();
    assert_eq!(
        me_status(&h, &format!("wrendns_session={}", late.cookie)).await,
        StatusCode::UNAUTHORIZED
    );
}

/// REQ: API-016 — a sign-in in progress for a provider that is removed meanwhile fails with the
/// login error and opens no session.
#[tokio::test]
async fn api_016_oidc_sign_in_of_removed_provider_fails() {
    let (h, f) = reload_harness();
    h.auth
        .reload_oidc(
            oidc_settings(vec![provider("fake", "Fake IdP", ISSUER, Some("s3cret"))]),
            Vec::new(),
            Arc::clone(&f),
        )
        .await;
    let (flow, state, nonce) = start_flow(&h, "fake").await;
    h.auth
        .reload_oidc(oidc_settings(Vec::new()), Vec::new(), f)
        .await;
    let token = h.idps["fake"].sign("k1", &id_claims("sub-9", "late", &["family"], &nonce));
    h.idps["fake"]
        .codes
        .lock()
        .unwrap()
        .insert("code1".into(), token);
    let r = callback(&h, "fake", &state, &flow).await;
    let to = refused_at(&r);
    assert!(to.starts_with("/#/?loginError="), "{to}");
    assert!(set_cookie(&r, "wrendns_session").is_none());
}

/// REQ: API-016 — a sign-in started before a rebuild completes after it: the flow state lives in
/// `Auth`, and the new service applies the new rules.
#[tokio::test]
async fn api_016_oidc_sign_in_spanning_reload_completes() {
    let (h, f) = reload_harness();
    let p = provider("fake", "Fake IdP", ISSUER, Some("s3cret"));
    h.auth
        .reload_oidc(oidc_settings(vec![p.clone()]), Vec::new(), Arc::clone(&f))
        .await;
    let (flow, state, nonce) = start_flow(&h, "fake").await;
    // The rebuild: a rule that maps `ops` to operator.
    let mut changed = p;
    changed.roles.push(("ops".into(), Role::Operator));
    h.auth
        .reload_oidc(oidc_settings(vec![changed]), Vec::new(), f)
        .await;
    let token = h.idps["fake"].sign("k1", &id_claims("sub-9", "ops-user", &["ops"], &nonce));
    h.idps["fake"]
        .codes
        .lock()
        .unwrap()
        .insert("code1".into(), token);
    let r = callback(&h, "fake", &state, &flow).await;
    assert_eq!(r.status(), StatusCode::FOUND);
    let session = set_cookie(&r, "wrendns_session").expect("the sign-in completed");
    assert_eq!(me(&h, &session).await["role"], "operator");
}

/// REQ: API-016 — a rebuild that a newer one overtook while it read discovery changes nothing:
/// the newer settings are the ones in use.
#[tokio::test]
async fn api_016_oidc_stale_rebuild_discarded() {
    let fake = Idp::new(ISSUER, vec![Signer::rsa("k1", Alg::Rs256)], Some("s3cret"));
    let slow = Idp::new(
        "https://slow.test",
        vec![Signer::rsa("s1", Alg::Rs256)],
        None,
    );
    let mut routes = HashMap::new();
    routes.insert("idp.test".to_owned(), router(fake));
    routes.insert("slow.test".to_owned(), router(slow));
    let inner = fetch(routes);
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let open = Arc::new(AtomicBool::new(false));
    let (e2, r2, o2) = (
        Arc::clone(&entered),
        Arc::clone(&release),
        Arc::clone(&open),
    );
    // slow.test holds its answers until the test lets it go (then it answers at once).
    let gated: Fetch = Arc::new(move |req: Request<Vec<u8>>| {
        let (inner, e, r, o) = (
            Arc::clone(&inner),
            Arc::clone(&e2),
            Arc::clone(&r2),
            Arc::clone(&o2),
        );
        Box::pin(async move {
            if req.uri().host() == Some("slow.test") && !o.load(Ordering::SeqCst) {
                e.notify_one();
                r.notified().await;
            }
            inner(req).await
        })
    });
    let state = Arc::new(wrendns_store::state::State::in_memory().unwrap());
    let auth = Arc::new(Auth::new(state, Settings::default()));
    auth.start_oidc(oidc_settings(Vec::new()), Vec::new(), Arc::clone(&gated));
    let a = {
        let auth = Arc::clone(&auth);
        let gated = Arc::clone(&gated);
        tokio::spawn(async move {
            auth.reload_oidc(
                oidc_settings(vec![provider("slow", "Slow", "https://slow.test", None)]),
                Vec::new(),
                gated,
            )
            .await
        })
    };
    entered.notified().await; // A is reading discovery
    let b = {
        let auth = Arc::clone(&auth);
        let gated = Arc::clone(&gated);
        tokio::spawn(async move {
            auth.reload_oidc(
                oidc_settings(vec![provider("fake", "Fake IdP", ISSUER, Some("s3cret"))]),
                Vec::new(),
                gated,
            )
            .await
        })
    };
    // Let B take its ticket (it queues behind A's gate), then release A.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    open.store(true, Ordering::SeqCst);
    release.notify_one();
    assert_eq!(a.await.unwrap(), super::Reloaded::Discarded);
    assert!(matches!(b.await.unwrap(), super::Reloaded::Applied(_)));
    let ids: Vec<String> = auth
        .oidc()
        .expect("B's providers are in use")
        .providers()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(ids, ["fake"], "A's provider never went live");
}

/// REQ: API-016 — a rebuild, even one that leaves every provider out, never touches password
/// sign-in or the local admin's sessions.
#[tokio::test]
async fn api_016_break_glass_admin_unaffected() {
    let (h, f) = reload_harness();
    let ip = "127.0.0.1".parse().unwrap();
    h.auth
        .reload_oidc(
            oidc_settings(vec![provider("fake", "Fake IdP", ISSUER, Some("s3cret"))]),
            Vec::new(),
            Arc::clone(&f),
        )
        .await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let user = h
        .auth
        .login("root", "correct horse battery", None, None, ip, now)
        .expect("password sign-in works");
    let login = h.auth.start_session(&user, ip, now).expect("a session");
    // Everything removed, then a provider that can't be read: the admin's session stays.
    h.auth
        .reload_oidc(oidc_settings(Vec::new()), Vec::new(), Arc::clone(&f))
        .await;
    h.auth
        .reload_oidc(
            oidc_settings(vec![provider("down", "Down", "https://gone.test", None)]),
            Vec::new(),
            f,
        )
        .await;
    let session = format!("wrendns_session={}", login.cookie);
    assert_eq!(me_status(&h, &session).await, StatusCode::OK);
    assert!(
        h.auth
            .login("root", "correct horse battery", None, None, ip, now + 1)
            .is_ok()
    );
}

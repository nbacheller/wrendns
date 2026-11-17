//! `OpenID Connect` sign-in (REQ: API-004, `spec/08` §6, ADR-034, ADR-951): Authorization Code +
//! PKCE with discovery, ID-token and access-token verification (`oidc/jose.rs`, `oidc/claims.rs`,
//! `oidc/metadata.rs`), group/role claims mapped to roles, users created on first sign-in, and
//! RP-initiated sign-out. Sessions are local after sign-in: the provider is only contacted while
//! signing in.
//!
//! The flow state (PKCE verifier, nonce, where to return) lives in memory for 10 minutes,
//! keyed by the `state` parameter and bound to the browser that started it by a short-lived
//! `SameSite=Lax` cookie (Strict cookies aren't sent on the provider's redirect back).

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::digest::{self, SHA256};
use serde_json::Value;
use telltale_store::state::User;

use super::{Actor, Auth, Role, crypto};
use crate::problem::{Code, Problem};

mod claims;
mod jose;
mod metadata;

/// What the binary supplies to reach providers (its HTTPS client; no redirects followed).
pub type Fetch = Arc<
    dyn Fn(
            axum::http::Request<Vec<u8>>,
        )
            -> Pin<Box<dyn Future<Output = Result<axum::http::Response<Vec<u8>>, String>> + Send>>
        + Send
        + Sync,
>;

/// How long a started sign-in may take, and how many may be in flight.
const FLOW_TTL: Duration = Duration::from_secs(600);
const MAX_FLOWS: usize = 1000;
/// Discovery (the endpoints and the key set) is refreshed this often.
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
/// A key set is refetched when a token's key isn't in it or its signature fails, at most once
/// per provider in this interval (ADR-951, "JWKS").
const JWKS_MIN_INTERVAL: Duration = Duration::from_secs(60);
/// The largest discovery document or key set read from a provider.
const MAX_RESPONSE: usize = 1 << 20;
pub const FLOW_COOKIE: &str = "telltale_oidc";

/// One configured provider.
#[derive(Debug, Clone)]
pub struct ProviderSettings {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub username_claim: String,
    pub groups_claim: String,
    /// (group, role), in config order.
    pub roles: Vec<(String, Role)>,
    pub default_role: Option<Role>,
    pub require_verified_email: bool,
}

/// `[auth.oidc]`.
#[derive(Debug, Clone, Default)]
pub struct OidcSettings {
    /// `https://dns.example.com` (no trailing slash).
    pub public_url: String,
    pub providers: Vec<ProviderSettings>,
    /// REQ: AGT-008 (T7.4) — MCP clients sign in through this provider.
    pub mcp: Option<McpOAuth>,
}

/// OAuth for MCP (REQ: AGT-008, T7.4): which provider issues access tokens, and for whom.
#[derive(Debug, Clone)]
pub struct McpOAuth {
    /// A provider's `id`.
    pub provider: String,
    /// The `aud` tokens must carry (the MCP endpoint's URL).
    pub audience: String,
}

/// A provider's discovery document and key set, as last read.
#[derive(Debug)]
struct Discovered {
    meta: metadata::Metadata,
    keys: Vec<jose::Key>,
    /// When the discovery document was read (its TTL runs from here).
    at: Instant,
}

#[derive(Debug)]
struct Flow {
    provider: String,
    verifier: String,
    nonce: String,
    return_to: String,
    browser: Vec<u8>,
    started: Instant,
}

/// The OIDC service.
pub struct Oidc {
    settings: OidcSettings,
    fetch: Fetch,
    discovered: Mutex<HashMap<String, Arc<Discovered>>>,
    flows: Mutex<HashMap<String, Flow>>,
    /// Per provider: when its key set was last fetched. Held across a fetch, so concurrent
    /// refetches for one provider collapse into one.
    jwks_gate: HashMap<String, tokio::sync::Mutex<Option<Instant>>>,
}

impl std::fmt::Debug for Oidc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oidc")
            .field("providers", &self.settings.providers.len())
            .finish_non_exhaustive()
    }
}

/// A started sign-in: send the browser to `redirect`, and set `browser` as the flow cookie.
#[derive(Debug)]
pub struct Started {
    pub redirect: String,
    pub browser: String,
}

/// Who the provider says signed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub subject: String,
    pub username: String,
    pub email_verified: Option<bool>,
    pub groups: Vec<String>,
}

fn provider_down(id: &str, e: impl std::fmt::Display) -> Problem {
    Problem::unavailable(format!("can't reach the `{id}` sign-in provider: {e}"))
        .hint("Check the issuer URL and that this server can reach it; sign in locally meanwhile if allowed.")
}

/// One request to a provider: its status and body, or the transport error. A body over
/// `MAX_RESPONSE` is an error.
async fn send(
    fetch: &Fetch,
    req: axum::http::Request<Vec<u8>>,
) -> Result<(axum::http::StatusCode, Vec<u8>), String> {
    let resp = fetch(req).await?;
    if resp.body().len() > MAX_RESPONSE {
        return Err("the response is too large".into());
    }
    let status = resp.status();
    Ok((status, resp.into_body()))
}

/// The key set at `uri`, the keys this server can use (`Key::from_jwk`).
async fn fetch_keys(fetch: &Fetch, uri: &str) -> Result<Vec<jose::Key>, String> {
    let req = axum::http::Request::get(uri)
        .body(Vec::new())
        .map_err(|e| e.to_string())?;
    let (status, body) = send(fetch, req).await?;
    if !status.is_success() {
        return Err(format!("the key set returned HTTP {}", status.as_u16()));
    }
    let set: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    let keys = set
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("the key set has no keys list")?;
    Ok(keys.iter().filter_map(jose::Key::from_jwk).collect())
}

/// A `returnTo` that stays inside the UI (no open redirects).
pub fn safe_return(r: Option<&str>) -> String {
    match r {
        Some(r) if r.starts_with("/#/") && !r.contains("//") && !r.contains('\\') => r.to_owned(),
        _ => "/#/".to_owned(),
    }
}

/// How the token request authenticates the client (ADR-951 decision 6).
enum TokenAuth {
    /// HTTP Basic with the form-encoded client ID and secret (RFC 6749 §2.3.1).
    Basic,
    /// The client ID and secret in the form body, when the provider lists only that.
    Post,
}

/// Basic, unless the provider lists its methods without `client_secret_basic`.
fn token_auth(meta: &metadata::Metadata) -> Result<TokenAuth, Problem> {
    match &meta.token_auth_methods {
        Some(methods) if !methods.iter().any(|m| m == "client_secret_basic") => {
            if methods.iter().any(|m| m == "client_secret_post") {
                Ok(TokenAuth::Post)
            } else {
                Err(Problem::unavailable(
                    "the sign-in provider accepts no client authentication this server supports",
                ))
            }
        }
        _ => Ok(TokenAuth::Basic),
    }
}

/// The ID-token algorithms: the nine this server verifies, intersected with the provider's
/// `id_token_signing_alg_values_supported` when it lists them (ADR-951 decision 2). An empty
/// intersection refuses every ID token.
fn id_token_algs(meta: &metadata::Metadata) -> Result<Vec<jose::Alg>, Problem> {
    let algs: Vec<jose::Alg> = jose::ALL
        .into_iter()
        .filter(|alg| {
            meta.id_token_algs
                .as_ref()
                .is_none_or(|listed| listed.iter().any(|name| name == alg.name()))
        })
        .collect();
    if algs.is_empty() {
        return Err(Problem::unavailable(
            "the sign-in provider's ID tokens use no algorithm this server accepts",
        ));
    }
    Ok(algs)
}

/// Whole Unix seconds now.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Oidc {
    pub fn new(settings: OidcSettings, fetch: Fetch) -> Self {
        let jwks_gate = settings
            .providers
            .iter()
            .map(|p| (p.id.clone(), tokio::sync::Mutex::new(None)))
            .collect();
        Self {
            settings,
            fetch,
            discovered: Mutex::new(HashMap::new()),
            flows: Mutex::new(HashMap::new()),
            jwks_gate,
        }
    }

    /// `(id, name)` of each provider, for sign-in buttons.
    pub fn providers(&self) -> Vec<(String, String)> {
        self.settings
            .providers
            .iter()
            .map(|p| (p.id.clone(), p.name.clone()))
            .collect()
    }

    fn provider(&self, id: &str) -> Result<&ProviderSettings, Problem> {
        self.settings
            .providers
            .iter()
            .find(|p| p.id == id)
            .ok_or_else(|| Problem::not_found(format!("no sign-in provider `{id}`")))
    }

    fn redirect_uri(&self, id: &str) -> String {
        format!(
            "{}/api/v1/auth/oidc/{id}/callback",
            self.settings.public_url.trim_end_matches('/')
        )
    }

    /// The cached discovery for provider `id`, if any (fresh or not).
    fn cached(&self, id: &str) -> Option<Arc<Discovered>> {
        self.discovered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    fn store(&self, id: &str, d: Arc<Discovered>) {
        self.discovered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.to_owned(), d);
    }

    /// Reads the discovery document and the key set of `p`.
    async fn load(&self, p: &ProviderSettings) -> Result<Discovered, String> {
        let req = axum::http::Request::get(metadata::url_of(&p.issuer))
            .body(Vec::new())
            .map_err(|e| e.to_string())?;
        let (status, body) = send(&self.fetch, req).await?;
        if !status.is_success() {
            return Err(format!(
                "the discovery document returned HTTP {}",
                status.as_u16()
            ));
        }
        let doc: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        let meta = metadata::parse(&doc, &p.issuer)?;
        let keys = fetch_keys(&self.fetch, &meta.jwks_uri).await?;
        Ok(Discovered {
            meta,
            keys,
            at: Instant::now(),
        })
    }

    /// The discovery of `p`, from the cache while it's fresh.
    async fn discover(&self, p: &ProviderSettings) -> Result<Arc<Discovered>, Problem> {
        if let Some(d) = self
            .cached(&p.id)
            .filter(|d| d.at.elapsed() < DISCOVERY_TTL)
        {
            return Ok(d);
        }
        let d = Arc::new(self.load(p).await.map_err(|e| provider_down(&p.id, e))?);
        self.store(&p.id, Arc::clone(&d));
        Ok(d)
    }

    /// The keys to try after `seen` failed to verify a token: the key set is refetched once
    /// per provider per `JWKS_MIN_INTERVAL`, and only one fetch runs at a time. A request that
    /// waited while another refreshed the keys uses those. A failed fetch keeps the cached keys.
    async fn refreshed(&self, p: &ProviderSettings, seen: &Arc<Discovered>) -> Arc<Discovered> {
        let Some(gate) = self.jwks_gate.get(&p.id) else {
            return Arc::clone(seen);
        };
        let mut last = gate.lock().await;
        let current = self.cached(&p.id).unwrap_or_else(|| Arc::clone(seen));
        if !Arc::ptr_eq(&current, seen) || last.is_some_and(|at| at.elapsed() < JWKS_MIN_INTERVAL) {
            return current;
        }
        *last = Some(Instant::now());
        match fetch_keys(&self.fetch, &seen.meta.jwks_uri).await {
            Ok(keys) => {
                let fresh = Arc::new(Discovered {
                    meta: seen.meta.clone(),
                    keys,
                    at: seen.at,
                });
                self.store(&p.id, Arc::clone(&fresh));
                fresh
            }
            Err(e) => {
                tracing::warn!(provider = %p.id, error = %e, "OIDC key set refetch failed; keeping the cached keys");
                Arc::clone(seen)
            }
        }
    }

    /// Verifies `token` against the keys of `d`; when its key is unknown or its signature
    /// fails, the key set is refreshed (`refreshed`) and it is tried once more.
    async fn verified(
        &self,
        p: &ProviderSettings,
        d: &Arc<Discovered>,
        token: &str,
        kind: jose::Kind,
        allowed: &[jose::Alg],
    ) -> Result<jose::Verified, jose::Failure> {
        match jose::verify(token, &d.keys, allowed, kind) {
            Err(failure) if failure.may_be_rotation() => {
                let fresh = self.refreshed(p, d).await;
                jose::verify(token, &fresh.keys, allowed, kind)
            }
            other => other,
        }
    }

    /// Begins a sign-in with provider `id`; afterwards the browser returns to `return_to`.
    pub async fn start(&self, id: &str, return_to: &str) -> Result<Started, Problem> {
        let p = self.provider(id)?;
        let d = self.discover(p).await?;
        let verifier = crypto::random_secret();
        let challenge = URL_SAFE_NO_PAD.encode(digest::digest(&SHA256, verifier.as_bytes()));
        let state = crypto::random_secret();
        let nonce = crypto::random_secret();
        let redirect = self.redirect_uri(id);
        let mut scope = String::from("openid");
        for s in p.scopes.iter().filter(|s| s.as_str() != "openid") {
            scope.push(' ');
            scope.push_str(s);
        }
        let query = [
            ("response_type", "code"),
            ("client_id", p.client_id.as_str()),
            ("redirect_uri", redirect.as_str()),
            ("scope", scope.as_str()),
            ("state", state.as_str()),
            ("nonce", nonce.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ]
        .iter()
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect::<Vec<_>>()
        .join("&");
        let sep = if d.meta.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        let url = format!("{}{sep}{query}", d.meta.authorization_endpoint);
        let browser = crypto::random_secret();
        let mut flows = self.flows.lock().unwrap_or_else(PoisonError::into_inner);
        flows.retain(|_, f| f.started.elapsed() < FLOW_TTL);
        if flows.len() >= MAX_FLOWS {
            return Err(Problem::new(
                Code::RateLimited,
                "too many sign-ins in progress; try again shortly",
            ));
        }
        flows.insert(
            state,
            Flow {
                provider: id.to_owned(),
                verifier,
                nonce,
                return_to: return_to.to_owned(),
                browser: crypto::secret_hash(&browser),
                started: Instant::now(),
            },
        );
        Ok(Started {
            redirect: url,
            browser,
        })
    }

    /// The token request (RFC 6749 §4.1.3) with the PKCE verifier and the client
    /// authentication of `token_auth`. Returns the ID token.
    async fn exchange(
        &self,
        p: &ProviderSettings,
        meta: &metadata::Metadata,
        code: &str,
        verifier: &str,
    ) -> Result<String, Problem> {
        let mut form = vec![
            "grant_type=authorization_code".to_owned(),
            format!("code={}", enc(code)),
            format!("redirect_uri={}", enc(&self.redirect_uri(&p.id))),
            format!("code_verifier={}", enc(verifier)),
        ];
        let mut req = axum::http::Request::post(&meta.token_endpoint)
            .header("content-type", "application/x-www-form-urlencoded");
        match &p.client_secret {
            // A public client: no secret, so the client ID goes in the body.
            None => form.push(format!("client_id={}", enc(&p.client_id))),
            Some(secret) => match token_auth(meta)? {
                TokenAuth::Basic => {
                    let credentials = format!("{}:{}", enc(&p.client_id), enc(secret));
                    req = req.header(
                        "authorization",
                        format!("Basic {}", STANDARD.encode(credentials)),
                    );
                }
                TokenAuth::Post => {
                    form.push(format!("client_id={}", enc(&p.client_id)));
                    form.push(format!("client_secret={}", enc(secret)));
                }
            },
        }
        let req = req
            .body(form.join("&").into_bytes())
            .map_err(|e| Problem::internal(e.to_string()))?;
        let (status, bytes) = send(&self.fetch, req)
            .await
            .map_err(|e| provider_down(&p.id, e))?;
        if !status.is_success() {
            return Err(Problem::new(
                Code::Unauthorized,
                format!(
                    "the `{}` provider refused the sign-in: HTTP {}",
                    p.id,
                    status.as_u16()
                ),
            ));
        }
        let reply: Value = serde_json::from_slice(&bytes).map_err(|_| {
            Problem::new(
                Code::Unauthorized,
                "the provider's token response isn't JSON",
            )
        })?;
        reply
            .get("id_token")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Problem::new(Code::Unauthorized, "the provider sent no ID token"))
    }

    /// Completes a sign-in: checks the state and browser binding, exchanges the code, and
    /// verifies the ID token. Returns the identity and where to send the browser.
    pub async fn finish(
        &self,
        id: &str,
        code: &str,
        state: &str,
        browser: Option<&str>,
    ) -> Result<(Identity, String), Problem> {
        let flow = self
            .flows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(state)
            .filter(|f| f.started.elapsed() < FLOW_TTL)
            .ok_or_else(|| {
                Problem::new(
                    Code::Unauthorized,
                    "this sign-in expired or was already used",
                )
                .hint("Start again from the sign-in page.")
            })?;
        let same_browser =
            browser.is_some_and(|b| crypto::ct_eq(&crypto::secret_hash(b), &flow.browser));
        if flow.provider != id || !same_browser {
            return Err(Problem::new(
                Code::Unauthorized,
                "this sign-in was started in another browser or for another provider",
            )
            .hint("Start again from the sign-in page in this browser."));
        }
        let p = self.provider(id)?;
        let d = self.discover(p).await?;
        let id_token = self.exchange(p, &d.meta, code, &flow.verifier).await?;
        let allowed = id_token_algs(&d.meta)?;
        let verified = self
            .verified(p, &d, &id_token, jose::Kind::IdToken, &allowed)
            .await
            .map_err(|e| {
                Problem::new(
                    Code::Unauthorized,
                    format!("the ID token isn't valid: {}", e.reason()),
                )
            })?;
        claims::id_token(
            &verified.payload,
            &claims::IdCheck {
                issuer: &p.issuer,
                client_id: &p.client_id,
                nonce: &flow.nonce,
                now: unix_now(),
            },
        )
        .map_err(|why| {
            Problem::new(
                Code::Unauthorized,
                format!("the ID token isn't valid: {why}"),
            )
        })?;
        Ok((
            identity(&verified.payload, &p.username_claim, &p.groups_claim),
            flow.return_to,
        ))
    }

    /// REQ: AGT-008 (T7.4) — OAuth for MCP, when configured.
    pub fn mcp(&self) -> Option<&McpOAuth> {
        self.settings.mcp.as_ref()
    }

    /// The RFC 9728 protected-resource metadata for `/mcp`: this resource, its authorization
    /// server (the provider), and the scopes agents can ask for. `None` when not configured.
    pub fn resource_metadata(&self) -> Option<Value> {
        let m = self.mcp()?;
        let p = self.provider(&m.provider).ok()?;
        let scopes: Vec<&str> = super::agent::SCOPES.iter().map(|(s, _)| *s).collect();
        Some(serde_json::json!({
            "resource": m.audience,
            "authorization_servers": [p.issuer],
            "scopes_supported": scopes,
            "bearer_methods_supported": ["header"],
            "resource_name": "TelltaleDNS",
            "resource_documentation": "https://paimonsoror.github.io/telltaledns/",
        }))
    }

    /// Where the protected-resource metadata is.
    pub fn resource_metadata_url(&self) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource",
            self.settings.public_url.trim_end_matches('/')
        )
    }

    /// REQ: AGT-008 (T7.4) — an MCP access token from the configured provider, verified: a JWT
    /// signed with one of the provider's keys (asymmetric algorithms only), from its issuer,
    /// for this resource's audience, and current. Its claims. Opaque (non-JWT) tokens aren't
    /// accepted: there's no introspection.
    pub async fn verify_access_token(&self, token: &str, now: u64) -> Result<Value, Problem> {
        let bad = |why: &str| {
            Problem::new(
                Code::Unauthorized,
                format!("the access token isn't valid: {why}"),
            )
            .hint("Sign in again from your MCP client to get a new token.")
        };
        let mcp = self
            .mcp()
            .ok_or_else(|| bad("OAuth for MCP isn't configured"))?;
        let provider = self.provider(&mcp.provider)?;
        let d = self.discover(provider).await?;
        let verified = self
            .verified(provider, &d, token, jose::Kind::AccessToken, &jose::ALL)
            .await
            .map_err(|e| bad(e.reason()))?;
        claims::access_token(&verified.payload, &provider.issuer, &mcp.audience, now)
            .map_err(|why| bad(&why))?;
        Ok(verified.payload)
    }

    /// Where to send the browser to also sign out at the provider, if it supports that.
    pub fn logout_url(&self, id: &str) -> Option<String> {
        let p = self.provider(id).ok()?;
        let end = self.cached(id)?.meta.end_session_endpoint.clone()?;
        let back = format!("{}/", self.settings.public_url.trim_end_matches('/'));
        let sep = if end.contains('?') { '&' } else { '?' };
        Some(format!(
            "{end}{sep}client_id={}&post_logout_redirect_uri={}",
            enc(&p.client_id),
            enc(&back)
        ))
    }

    /// The role for `groups`, or why there's none.
    pub fn role(&self, id: &str, who: &Identity) -> Result<Role, Problem> {
        let p = self.provider(id)?;
        if p.require_verified_email && who.email_verified != Some(true) {
            return Err(Problem::new(
                Code::Forbidden,
                "your email address isn't verified at the sign-in provider",
            ));
        }
        role_for(&who.groups, &p.roles, p.default_role).ok_or_else(|| {
            Problem::new(
                Code::Forbidden,
                "your account at the sign-in provider isn't in a group that may use TelltaleDNS",
            )
            .hint("Ask an admin to add you to a group mapped in [[auth.oidc.provider.role]].")
        })
    }
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// A claim by dotted path (`realm_access.roles`).
fn claim<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(v, |v, k| v.get(k))
}

/// Identity from verified ID-token claims.
pub fn identity(claims: &Value, username_claim: &str, groups_claim: &str) -> Identity {
    let text = |path: &str| {
        claim(claims, path)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let subject = text("sub").unwrap_or_default();
    let username = text(username_claim)
        .or_else(|| text("email"))
        .unwrap_or_else(|| subject.clone());
    let groups = match claim(claims, groups_claim) {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .map(|g| g.trim_start_matches('/').to_owned())
            .collect(),
        Some(Value::String(s)) => s
            .split([',', ' '])
            .filter(|g| !g.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    let email_verified = match claim(claims, "email_verified") {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::String(s)) => Some(s == "true"),
        _ => None,
    };
    Identity {
        subject,
        username,
        email_verified,
        groups,
    }
}

/// The highest role any group maps to, else the default.
pub fn role_for(
    groups: &[String],
    rules: &[(String, Role)],
    default: Option<Role>,
) -> Option<Role> {
    rules
        .iter()
        .filter(|(g, _)| groups.iter().any(|x| x == g))
        .map(|(_, r)| *r)
        .max()
        .or(default)
}

/// A username for a new OIDC user: the claim made safe; `name@provider` if a different
/// account already has it (never merged into an existing local account).
fn username_for(auth: &Auth, provider: &str, wanted: &str) -> Result<String, Problem> {
    let clean: String = wanted
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || "._-@".contains(c) {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    let clean = if clean.is_empty() {
        "user".to_owned()
    } else {
        clean
    };
    for candidate in [clean.clone(), format!("{clean}@{provider}")] {
        if auth
            .state()
            .user_by_name(&candidate)
            .map_err(super::db)?
            .is_none()
        {
            return Ok(candidate);
        }
    }
    Err(Problem::new(
        Code::Conflict,
        format!("the username `{clean}` is taken by another account"),
    )
    .hint("Ask an admin to rename or remove the other account."))
}

impl Auth {
    /// REQ: AGT-008 (T7.4, ADR-071) — the agent an MCP access token stands for: the user who
    /// signed in (they must have signed in to the web UI with the provider before), with the
    /// TelltaleDNS scopes they consented to (read-only when it names none), never above their
    /// role. Blocking.
    pub fn oauth_principal(
        &self,
        oidc: &Oidc,
        claims: &Value,
    ) -> Result<super::Principal, Problem> {
        let provider = oidc
            .mcp()
            .map(|m| m.provider.clone())
            .ok_or_else(|| Problem::new(Code::Unauthorized, "OAuth for MCP isn't configured"))?;
        let sub = claims
            .get("sub")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let user = self
            .state()
            .user_by_oidc(&provider, sub)
            .map_err(super::db)?
            .filter(|_| !sub.is_empty())
            .ok_or_else(|| {
                Problem::new(
                    Code::Unauthorized,
                    "this account hasn't used TelltaleDNS yet",
                )
                .hint("Sign in to the web UI with the same provider once, then connect the MCP client again.")
            })?;
        if user.disabled {
            return Err(Problem::new(
                Code::Forbidden,
                "this account is disabled in TelltaleDNS",
            ));
        }
        // `scope` (space-separated) or `scp` (a list): the TelltaleDNS scopes among them.
        let asked: Vec<String> = match (claims.get("scope"), claims.get("scp")) {
            (Some(Value::String(s)), _) => s.split_whitespace().map(str::to_owned).collect(),
            (_, Some(Value::Array(v))) => v
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        };
        let known: Vec<String> = asked
            .into_iter()
            .filter(|s| s == "config:write:*" || super::agent::SCOPES.iter().any(|(k, _)| k == s))
            .collect();
        let mut scopes = super::agent::parse_scopes(&known).unwrap_or_default();
        if scopes.is_empty() {
            scopes = super::agent::DEFAULT_SCOPES
                .iter()
                .map(|s| (*s).to_owned())
                .collect();
        }
        let user_role = Role::parse(&user.role).unwrap_or(Role::Viewer);
        let role = user_role.min(super::agent::implied_role(&scopes));
        // The MCP client the token was issued to names the agent in the audit log.
        let client = claims
            .get("azp")
            .or_else(|| claims.get("client_id"))
            .and_then(Value::as_str)
            .unwrap_or("mcp")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "-_.:".contains(*c))
            .take(64)
            .collect::<String>();
        Ok(super::Principal {
            user_id: user.id,
            username: user.username,
            role,
            via: super::Via::Token {
                id: format!("oauth:{client}:{sub}"),
            },
            agent: Some(super::AgentGrant {
                token_name: format!("oauth:{client}"),
                scopes,
                group: None,
                rate_per_minute: None,
                client: None,
            }),
            display: None,
        })
    }

    /// Signs in (and on first sign-in creates) the user `who` from provider `id`, updating
    /// their role from their groups. Blocking.
    pub fn oidc_user(
        &self,
        oidc: &Oidc,
        id: &str,
        who: &Identity,
        remote: IpAddr,
        now: u64,
    ) -> Result<User, Problem> {
        if who.subject.is_empty() {
            return Err(Problem::new(
                Code::Unauthorized,
                "the ID token has no subject",
            ));
        }
        let role = oidc.role(id, who)?;
        let actor = |u: &User| Actor {
            name: u.username.clone(),
            kind: "oidc",
            remote: Some(remote.to_string()),
            reason: None,
        };
        let existing = self
            .state()
            .user_by_oidc(id, &who.subject)
            .map_err(super::db)?;
        let user = if let Some(u) = existing {
            {
                if u.disabled {
                    return Err(Problem::new(
                        Code::Forbidden,
                        "this account is disabled in TelltaleDNS",
                    ));
                }
                let was = Role::parse(&u.role).unwrap_or(Role::Viewer);
                if was != role {
                    self.state()
                        .update_user(u.id, Some(role.as_str()), None, None)
                        .map_err(super::db)?;
                    self.forget_basic(u.id);
                    self.record(
                        &actor(&u),
                        "user.update",
                        &u.username,
                        &serde_json::json!({ "role": { "from": was.as_str(), "to": role.as_str() }, "via": "oidc", "provider": id }),
                    );
                }
                self.state().user(u.id).map_err(super::db)?.unwrap_or(u)
            }
        } else {
            {
                let name = username_for(self, id, &who.username)?;
                let u = self
                    .state()
                    .create_oidc_user(&name, role.as_str(), id, &who.subject, now)
                    .map_err(super::db)?;
                self.record(
                    &actor(&u),
                    "user.create",
                    &u.username,
                    &serde_json::json!({ "role": role.as_str(), "via": "oidc", "provider": id }),
                );
                u
            }
        };
        self.record(
            &actor(&user),
            "auth.login",
            &user.username,
            &serde_json::json!({ "via": "oidc", "provider": id }),
        );
        Ok(user)
    }
}

#[cfg(test)]
mod flow_tests;
#[cfg(test)]
mod testkit;
#[cfg(test)]
mod verify_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_004_claims_to_identity_and_role() {
        let c = serde_json::json!({
            "sub": "1234",
            "preferred_username": "Ana Maria",
            "email": "ana@example.com",
            "email_verified": true,
            "groups": ["/dns-admins", "family"],
            "realm_access": { "roles": ["dns-operator"] },
        });
        let i = identity(&c, "preferred_username", "groups");
        assert_eq!(i.subject, "1234");
        assert_eq!(i.username, "Ana Maria");
        assert_eq!(i.email_verified, Some(true));
        assert_eq!(
            i.groups,
            ["dns-admins", "family"],
            "Keycloak's leading / is dropped"
        );
        let nested = identity(&c, "missing", "realm_access.roles");
        assert_eq!(nested.username, "ana@example.com", "falls back to email");
        assert_eq!(nested.groups, ["dns-operator"]);
        let rules = vec![
            ("family".to_owned(), Role::Viewer),
            ("dns-admins".to_owned(), Role::Admin),
        ];
        assert_eq!(
            role_for(&i.groups, &rules, None),
            Some(Role::Admin),
            "highest wins"
        );
        assert_eq!(role_for(&["other".into()], &rules, None), None);
        assert_eq!(
            role_for(&["other".into()], &rules, Some(Role::Viewer)),
            Some(Role::Viewer)
        );
    }

    #[test]
    fn api_004_return_paths_stay_inside_the_ui() {
        assert_eq!(
            safe_return(Some("/#/queries?client=1.2.3.4")),
            "/#/queries?client=1.2.3.4"
        );
        for bad in [
            "https://evil.example",
            "//evil.example",
            "/#//evil",
            "/\\evil",
            "javascript:x",
        ] {
            assert_eq!(safe_return(Some(bad)), "/#/", "{bad}");
        }
        assert_eq!(safe_return(None), "/#/");
    }
}

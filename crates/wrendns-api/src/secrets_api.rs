//! REQ: API-015, AGT-001–005, AGT-009 (ADR-903 §4–5) — stored secrets over HTTP. Values are
//! write-only: `PUT /api/v1/secrets/{name}` takes one and every answer is metadata (name, kind,
//! stamp, who set it when, which entries use it, whether each node can read it); nothing reads a
//! value back, not even an admin.
//!
//! - **Reads** (`GET /api/v1/secrets`, `/secrets/{name}`): operators, and agents with
//!   `config:read` (the MCP tool `secrets_status`). On a replica they come from the primary when
//!   it answers, otherwise from this node with `stale: true`.
//! - **Writes** (`PUT`/`DELETE`): admins only, never agent tokens (403 `agent_not_allowed`), only
//!   over HTTPS or from the node itself (403 `insecure_transport`, unless
//!   `[api] allow_secrets_over_http`), with `?dryRun=true`, a keyed `Idempotency-Key`, `If-Match`
//!   on the secrets head (its `ETag`), `X-Wrendns-Reason`, and `Cache-Control: no-store`. Audited
//!   as `secret.put` / `secret.delete` with the name, kind, stamp and users, never the value or
//!   its length.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use wrendns_store::state::Replay;
use zeroize::Zeroizing;

use crate::auth::routes::{OnBehalfOf, TlsConnection, is_https, principal, reason, remote};
use crate::auth::{Auth, Principal, Role};
use crate::config_api::{IDEMPOTENCY_KEY, IF_MATCH};
use crate::problem::{Code, Problem};
use crate::{BoxFuture, Shared};

/// What a redacted value reads as.
const MARKER: &str = "<redacted>";

/// REQ: API-015, NFR-005 — a secret's value on its way to the store: printed `<redacted>`, never
/// serialized by the API, wiped when dropped. What the HTTP layer and the JSON parser copy on the
/// way isn't wiped (`docs/secrets.md`).
pub struct SecretText(Zeroizing<String>);

impl SecretText {
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    /// The value, for the store (and the forward to the primary) only.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The value, handed over (wiped when the receiver drops it).
    pub fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(MARKER)
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}

/// The body of `PUT /api/v1/secrets/{name}`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretPut {
    /// The value: one line of text (a token, a password, an API key), at most 8 KiB, trimmed, no
    /// control characters. Write-only: no answer, read, log, audit entry or backup without a
    /// passphrase ever holds it.
    #[schema(value_type = String, write_only, example = "s3cr3t-token")]
    pub value: SecretText,
    /// `text` (the default) or `pem` (PEM blocks only; its value is never shown or returned).
    #[serde(default)]
    pub kind: Option<String>,
}

/// A stamp: the epoch (0 on a standalone node) and the change's number in it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretStamp {
    pub epoch: u64,
    pub seq: u64,
}

/// REQ: API-015 (ADR-903 §2) — the secrets head: the highest stamp and a digest of every
/// secret's name, kind, stamp and deletion (no value, no value hash). `etag` is what `If-Match`
/// takes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretsHead {
    pub epoch: u64,
    pub seq: u64,
    /// BLAKE3, hex.
    pub digest: String,
    /// `"<epoch>.<seq>.<first 16 digits of digest>"`: send it as `If-Match`.
    pub etag: String,
}

impl SecretsHead {
    /// The head's `ETag` text (without quotes).
    pub fn etag_of(epoch: u64, seq: u64, digest: &str) -> String {
        format!("{epoch}.{seq}.{}", digest.get(..16).unwrap_or(digest))
    }
}

/// A credential field that names a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretUse {
    /// `router`, `alert_destination`, `oidc_provider`, `sink`, `git`, `otlp`.
    pub kind: String,
    /// The entry's name (`default` for the Git source and OTLP).
    pub name: String,
    /// The reference (`api_key_ref`, `header_refs.api-key`).
    pub field: String,
    /// `stored`: the field takes the secret.
    pub source: String,
    /// The node whose own (node-local) configuration holds the reference; absent: the cluster's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
}

/// How one node holds a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretNode {
    pub node: String,
    /// It holds this stamp.
    pub applied: bool,
    /// It holds it but can't read it (another key made it, or it's damaged).
    pub unreadable: bool,
    /// REQ: API-015 (T24.42) - how this member holds it: `applied` (the stamp the list shows,
    /// readable), `unreadable`, `behind` (an older stamp), `ahead` (a newer one), `missing`, or
    /// `unknown` (the member didn't answer, or is too old to say). Absent from an older node.
    #[serde(default)]
    pub state: String,
    /// The stamp it holds (never a value or a hash of one); absent when it holds none or didn't
    /// answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamp: Option<SecretStamp>,
}

/// REQ: API-015 (T24.42) - one cluster member's part in `GET /api/v1/secrets`: the same list on
/// every node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretMember {
    /// As the Cluster page names it.
    pub node: String,
    /// `full` (holds every stored secret), `resolver` (a resolver pod: holds none, by design) or
    /// `witness` (votes only: holds none, by design).
    pub kind: String,
    /// `answered`, `unknown` (a full member that didn't answer, or is too old to), or `not_held`.
    pub state: String,
    /// How many stored secrets it holds (0 unless it answered).
    pub held: u32,
}

/// A stored secret: never its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretMeta {
    pub name: String,
    /// `text`.
    pub kind: String,
    /// Stored now (false: a reference names it but it isn't set, or it was deleted).
    pub set: bool,
    pub stamp: SecretStamp,
    /// When it was set or deleted (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    /// `local` (made on this node) or `cluster` (the primary's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// On the answering node: `readable`, `unreadable` (another key made it) or `corrupt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
    /// The credential fields that name it.
    pub used_by: Vec<SecretUse>,
    /// Which nodes hold it, and whether they can read it.
    pub nodes: Vec<SecretNode>,
}

/// A credential field of a node's configuration, with where its value comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialField {
    pub kind: String,
    pub entry: String,
    /// `api_key`, `token`, `header:api-key`, ...
    pub field: String,
    /// `inline` or `file` (set by the configuration files: the UI won't edit it), or `stored`.
    pub source: String,
    /// The file's path, or the stored secret's name (never a value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    /// This node can read it (a file is opened without being read; a stored secret is judged by
    /// its row, not decrypted).
    pub readable: bool,
    /// Why not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The node this is about.
    pub node: String,
}

/// The answering node's secrets store.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretsStore {
    pub node: String,
    /// `starting`, `ready`, `locked`, or `ephemeral` (a resolver pod: it holds none).
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Where the key came from (the environment, or a file's path); never the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
    /// The key's ID (8 bytes, hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_key_id: Option<String>,
    /// The data directory isn't kept across restarts (stored secrets would be lost).
    pub data_ephemeral: bool,
}

/// REQ: API-015 — `GET /api/v1/secrets`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretsStatus {
    /// From this node's own copy: the primary couldn't be asked.
    pub stale: bool,
    pub head: SecretsHead,
    /// This node's store.
    pub store: SecretsStore,
    /// Stored secrets (and names a reference uses that aren't set), by name.
    pub items: Vec<SecretMeta>,
    /// This node's credential fields.
    pub credentials: Vec<CredentialField>,
    /// REQ: API-015 (T24.42) - every member of the cluster and whether it holds the secrets, the
    /// same on every node. Empty on a standalone node.
    #[serde(default)]
    pub members: Vec<SecretMember>,
    /// Full members that did not answer (offline, or an older version): their state is `unknown`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
    /// A full member that lacks a secret, holds an older one or can't read it, in words.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// REQ: API-015, AGT-002 — what a `PUT` or `DELETE` did (or, with `dryRun`, would do).
#[allow(clippy::struct_excessive_bools)] // the answer's flags, as AGT-002 names them
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretChange {
    pub applied: bool,
    pub dry_run: bool,
    /// A new secret.
    pub would_create: bool,
    /// One that was set already.
    pub would_replace: bool,
    pub would_delete: bool,
    /// The fields that name it: they become configured with it (or lose it, on delete).
    pub used_by: Vec<SecretUse>,
    pub secret: SecretMeta,
    /// The head after the change (its `etag` for the next `If-Match`).
    pub head: SecretsHead,
    pub warnings: Vec<String>,
}

/// What a write does.
#[derive(Debug)]
pub enum SecretOp {
    Put { kind: String, value: SecretText },
    Delete { force: bool },
}

/// REQ: API-015 — a secret write as the API checked it. Its `Debug` never shows the value.
#[derive(Debug)]
pub struct SecretWrite {
    pub name: String,
    pub op: SecretOp,
    pub dry_run: bool,
    /// `If-Match`: the head's `ETag` the change was made against.
    pub expect: Option<String>,
    /// Who: the actor's name.
    pub by: String,
    pub role: Option<Role>,
    pub agent: Option<String>,
}

/// `?dryRun=true` and, for `DELETE`, `?force=true`.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct SecretQuery {
    /// Check and report without changing anything.
    pub dry_run: Option<bool>,
    /// `DELETE` only: go ahead although a full member's references can't be read now (it is
    /// offline). References that are known still refuse.
    pub force: Option<bool>,
}

type Ctx = (Shared, Arc<Auth>);

/// The routes: reads for operators (agents: `config:read`), writes for admins.
pub(crate) fn routes(backend: Shared, auth: Arc<Auth>) -> Router {
    use axum::middleware::from_fn;
    use axum::routing::get;

    use crate::auth::routes::{require_admin, require_viewer};
    Router::new()
        .route(
            "/api/v1/secrets",
            get(list_secrets).route_layer(from_fn(require_viewer)),
        )
        .route(
            "/api/v1/secrets/{name}",
            get(get_secret).route_layer(from_fn(require_viewer)).merge(
                axum::routing::put(put_secret)
                    .delete(delete_secret)
                    .route_layer(from_fn(require_admin)),
            ),
        )
        .with_state((backend, auth))
}

/// Adds `Cache-Control: no-store` (and the head's `ETag`, when given).
fn no_store(mut r: Response, etag: Option<&str>) -> Response {
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(e) = etag
        && let Ok(v) = HeaderValue::from_str(&format!("\"{e}\""))
    {
        h.insert(header::ETAG, v);
    }
    r
}

/// Operators, and agents (the middleware checked their `config:read`).
fn may_read(p: &Principal) -> Result<(), Problem> {
    if p.role >= Role::Operator || p.agent.is_some() {
        return Ok(());
    }
    Err(Problem::new(
        Code::Forbidden,
        format!(
            "stored secrets are listed for operators and admins; you have {}",
            p.role.as_str()
        ),
    ))
}

async fn status(backend: &Shared) -> Result<SecretsStatus, Problem> {
    let b = Arc::clone(backend);
    tokio::task::spawn_blocking(move || b.secrets_status())
        .await
        .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))))
}

/// List the stored secrets (never a value).
///
/// Every stored secret with its kind, stamp, who set it when, the credential fields that name it
/// (`usedBy`), and which nodes hold it and can read it; names a reference uses that aren't set
/// come with `set: false`. Also this node's secrets store (ready, locked and why, the key's
/// source and ID: never the key) and every credential field of this node's configuration with
/// its source: `inline` or `file` (the configuration files set it, and win: the UI shows it
/// read-only), or `stored`, and whether this node can read it. On a replica the list is the
/// primary's when it answers, otherwise this node's with `stale: true`. The answer's `ETag` is the
/// secrets head, for `If-Match` on a write. Operators and admins; agents with `config:read`
/// (MCP `secrets_status`).
#[utoipa::path(get, path = "/api/v1/secrets", tag = "config",
    responses(
        (status = 200, body = SecretsStatus, description = "The stored secrets, without values."),
        (status = 403, body = Problem, description = "Viewers don't see them."),
    ))]
pub(crate) async fn list_secrets(
    State((backend, _)): State<Ctx>,
    ext: axum::http::Extensions,
) -> Response {
    if let Err(e) = principal(&ext).and_then(|p| may_read(&p)) {
        return no_store(e.into_response(), None);
    }
    match status(&backend).await {
        Ok(s) => {
            let etag = s.head.etag.clone();
            no_store(Json(s).into_response(), Some(&etag))
        }
        Err(e) => no_store(e.into_response(), None),
    }
}

/// One stored secret (never its value).
///
/// As in the list: its kind, stamp, who set it when, which fields name it, and which nodes hold
/// it. 404 when no secret of that name is stored and nothing names it.
#[utoipa::path(get, path = "/api/v1/secrets/{name}", tag = "config",
    params(("name" = String, Path, description = "The secret's name.")),
    responses(
        (status = 200, body = SecretMeta, description = "The secret, without its value."),
        (status = 404, body = Problem, description = "No secret of that name, and nothing names one."),
    ))]
pub(crate) async fn get_secret(
    State((backend, _)): State<Ctx>,
    Path(name): Path<String>,
    ext: axum::http::Extensions,
) -> Response {
    if let Err(e) = principal(&ext).and_then(|p| may_read(&p)) {
        return no_store(e.into_response(), None);
    }
    match status(&backend).await {
        Ok(s) => {
            let etag = s.head.etag.clone();
            match s.items.into_iter().find(|i| i.name == name) {
                Some(m) => no_store(Json(m).into_response(), Some(&etag)),
                None => no_store(
                    Problem::not_found(format!("no secret named `{name}` is stored or used"))
                        .hint("GET /api/v1/secrets lists them.")
                        .into_response(),
                    Some(&etag),
                ),
            }
        }
        Err(e) => no_store(e.into_response(), None),
    }
}

/// REQ: API-015 (ADR-903 §4) — secret values cross only HTTPS (the API's own TLS, or a trusted
/// proxy saying so) or the loopback interface (a request no proxy forwarded), unless
/// `[api] allow_secrets_over_http` says otherwise.
pub(crate) fn transport_ok(
    auth: &Auth,
    backend: &Shared,
    ext: &axum::http::Extensions,
    headers: &HeaderMap,
) -> Result<(), Problem> {
    if ext.get::<TlsConnection>().is_some() || backend.secrets_over_http_allowed() {
        return Ok(());
    }
    // In-process MCP calls: their outer request decided (`is_https`); they have no peer.
    if ext.get::<OnBehalfOf>().is_some() {
        return if is_https(auth, ext, headers) {
            Ok(())
        } else {
            Err(insecure())
        };
    }
    let peer = ext
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_canonical());
    // A request some proxy forwarded: its `X-Forwarded-Proto` counts only from a proxy listed in
    // `[api] trusted_proxies` — loopback isn't one here, since a plain-HTTP proxy or a relay on
    // the same host would pass a remote client's `X-Forwarded-Proto: https` through.
    let forwarded = ["x-forwarded-for", "forwarded", "x-real-ip"]
        .iter()
        .any(|h| headers.contains_key(*h));
    let says_https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("https"));
    let listed = peer.is_some_and(|ip| {
        auth.settings()
            .trusted_proxies
            .iter()
            .any(|(n, l)| crate::auth::in_network(ip, *n, *l))
    });
    if says_https && listed {
        return Ok(());
    }
    // The node itself: the loopback interface, no proxy in between.
    if peer.is_some_and(|ip| ip.is_loopback()) && !forwarded {
        return Ok(());
    }
    Err(insecure())
}

fn insecure() -> Problem {
    Problem::new(
        Code::InsecureTransport,
        "a secret's value would cross the network unencrypted: this request came over plain HTTP from another host (or through a proxy not listed in [api] trusted_proxies)",
    )
    .hint("Use HTTPS: turn on [api] tls = { self_signed = true } (or your own certificate), or put a TLS proxy in front and list it in [api] trusted_proxies (a proxy on the same host too: 127.0.0.1/32). On the node itself, http://127.0.0.1 works. [api] allow_secrets_over_http = true lifts this check (not recommended).")
}

/// Who may write: admins, never agent tokens.
fn may_write(p: &Principal) -> Result<(), Problem> {
    if let Some(a) = &p.agent {
        return Err(Problem::new(
            Code::AgentNotAllowed,
            format!(
                "agent token `{}` can't set or clear stored secrets, whatever its scopes",
                a.token_name
            ),
        )
        .hint("A value would sit in the agent's plan, its approval and its transcript. A person sets it in Settings → Integrations & secrets, or with `wrendns ctl secrets set`."));
    }
    if p.role < Role::Admin {
        return Err(Problem::new(
            Code::Forbidden,
            format!(
                "setting or clearing a stored secret needs the admin role; you have {}",
                p.role.as_str()
            ),
        ));
    }
    Ok(())
}

/// `If-Match: "<etag>"`, `W/"..."`, or the bare text; `*` or absent: no check.
fn expected_head(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(IF_MATCH)?.to_str().ok()?.trim();
    let v = v.trim_start_matches("W/").trim_matches('"').trim();
    (!v.is_empty() && v != "*").then(|| v.to_owned())
}

fn replay(r: &Replay) -> Response {
    let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::OK);
    let mut resp = (status, r.response.clone()).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert("idempotency-replayed", HeaderValue::from_static("true"));
    no_store(resp, None)
}

/// Set (or replace) a stored secret.
///
/// Stores `value`, encrypted with the node's key, under `name` (lowercase letters, digits, `.`,
/// `_` and `-`, starting with a letter or digit, at most 63). Entries name it in their `*_ref`
/// fields (`api_key_ref = "unifi"`). The value is write-only: the answer, every read, the audit
/// entry (`secret.put`: name, kind, stamp, users) and the logs hold only metadata. In a cluster a
/// replica sends it to the primary (`secret.put` over the cluster channel); pins and staged
/// rollouts don't hold it back, and a configuration managed in Git doesn't refuse it (secrets
/// are state, never in Git). Refused on an emergency primary, a primary without its lease, or
/// with no primary reachable (409).
///
/// Admins only: agent tokens get 403 `agent_not_allowed`, whatever their scopes. Only over HTTPS
/// or from the node itself (403 `insecure_transport`; `[api] allow_secrets_over_http` lifts it).
/// `?dryRun=true` checks the name, kind and value and reports `wouldCreate`/`wouldReplace` and the
/// fields that would become configured, storing nothing. `Idempotency-Key` replays the first
/// answer for the same value (another value with the same key is 409); `If-Match` takes the
/// secrets head's `ETag` (412 when it moved).
#[utoipa::path(put, path = "/api/v1/secrets/{name}", tag = "config",
    params(("name" = String, Path, description = "The secret's name."), SecretQuery),
    request_body = SecretPut,
    responses(
        (status = 200, body = SecretChange, description = "Stored (or, with dryRun, what would be). Metadata only."),
        (status = 403, body = Problem, description = "Not an admin, an agent token (`agent_not_allowed`), or plain HTTP from another host (`insecure_transport`)."),
        (status = 409, body = Problem, description = "No primary to take it, an emergency primary or one without its lease, a primary too old to store secrets (`upgrade_required`), the configuration files set that credential (`set_by_file`), or an Idempotency-Key reused with another value."),
        (status = 412, body = Problem, description = "If-Match: the secrets head moved."),
        (status = 400, body = Problem, description = "The name, kind or value isn't acceptable (empty, over 8 KiB, a control character, `<redacted>`; a webhook secret under 16 characters), or 128 secrets are stored (`invalid_parameter`)."),
        (status = 503, body = Problem, description = "The node's secrets key can't be read (`secrets_locked`)."),
    ))]
#[allow(clippy::too_many_lines)] // check, replay, write, audit, remember: one path
pub(crate) async fn put_secret(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<SecretQuery>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    raw: Bytes,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return no_store(e.into_response(), None),
    };
    if let Err(e) = may_write(&p).and_then(|()| transport_ok(&auth, &backend, &ext, &headers)) {
        return no_store(e.into_response(), None);
    }
    let body: SecretPut = match serde_json::from_slice(&raw) {
        Ok(b) => b,
        // REQ: API-015 — the parser's own message can quote the input (`invalid type: integer
        // `12345678``, a numeric PIN), so only its category and position are told.
        Err(e) => {
            let what = match e.classify() {
                serde_json::error::Category::Syntax => "isn't valid JSON",
                serde_json::error::Category::Eof => "ended early",
                serde_json::error::Category::Data => {
                    "has a missing, unknown or wrongly typed field (`value` and `kind` are strings)"
                }
                serde_json::error::Category::Io => "couldn't be read",
            };
            return no_store(
                Problem::invalid(format!(
                    "the body {what} (line {}, column {}); it should be {{\"value\": \"...\", \"kind\": \"text\"}}",
                    e.line(),
                    e.column()
                ))
                .into_response(),
                None,
            );
        }
    };
    drop(raw);
    let kind = body.kind.unwrap_or_else(|| "text".to_owned());
    let op = SecretOp::Put {
        kind,
        value: body.value,
    };
    write(
        backend,
        auth,
        headers,
        ext,
        p,
        name,
        op,
        q.dry_run.unwrap_or(false),
    )
    .await
}

/// Delete a stored secret.
///
/// Removes the value (a deletion record stays, so members that were offline learn of it). Refused
/// with 409 `secret_in_use` while a field names it, on any node (the answer lists them): change
/// those entries first. When a full member's references can't be read now (it is offline), the
/// delete needs `?force=true`. Admins only (never agents), audited as `secret.delete`; the same
/// dry run, `Idempotency-Key`, `If-Match` and HTTPS rule as setting one.
#[utoipa::path(delete, path = "/api/v1/secrets/{name}", tag = "config",
    params(("name" = String, Path, description = "The secret's name."), SecretQuery),
    responses(
        (status = 200, body = SecretChange, description = "Deleted (or, with dryRun, what would be)."),
        (status = 403, body = Problem, description = "Not an admin, an agent token, or plain HTTP from another host."),
        (status = 404, body = Problem, description = "No secret of that name is stored."),
        (status = 409, body = Problem, description = "Still named by a field (`secret_in_use`; or a member's references are unknown: `?force=true`), or no primary to take it."),
        (status = 412, body = Problem, description = "If-Match: the secrets head moved."),
        (status = 503, body = Problem, description = "The node's secrets key can't be read (`secrets_locked`)."),
    ))]
pub(crate) async fn delete_secret(
    State((backend, auth)): State<Ctx>,
    Path(name): Path<String>,
    Query(q): Query<SecretQuery>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return no_store(e.into_response(), None),
    };
    if let Err(e) = may_write(&p).and_then(|()| transport_ok(&auth, &backend, &ext, &headers)) {
        return no_store(e.into_response(), None);
    }
    let op = SecretOp::Delete {
        force: q.force.unwrap_or(false),
    };
    write(
        backend,
        auth,
        headers,
        ext,
        p,
        name,
        op,
        q.dry_run.unwrap_or(false),
    )
    .await
}

#[allow(clippy::too_many_arguments)] // one path for both writes
async fn write(
    backend: Shared,
    auth: Arc<Auth>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    p: Principal,
    name: String,
    op: SecretOp,
    dry_run: bool,
) -> Response {
    // REQ: AGT-003 (ADR-903 §4) — the record keeps `PUT /secrets/<name> ` and a keyed hash of
    // the value, never the value: the same key with another value is another request (409).
    // An empty header is no key.
    let key = headers
        .get(IDEMPOTENCY_KEY)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|k| !dry_run && !k.is_empty())
        .map(|k| format!("{}:{k}", p.user_id));
    let fingerprint = if key.is_some() {
        let r = match &op {
            // The kind is part of the request: the same key and value as another kind is 409.
            SecretOp::Put { value, kind } => backend.secret_idempotency(
                &format!("PUT /secrets/{name} kind={}", kind.trim()),
                Some(value),
            ),
            SecretOp::Delete { force } => backend.secret_idempotency(
                &format!(
                    "DELETE /secrets/{name}{}",
                    if *force { "?force" } else { "" }
                ),
                None,
            ),
        };
        match r {
            Ok(f) => Some(f),
            Err(e) => return no_store(e.into_response(), None),
        }
    } else {
        None
    };
    let now = backend.now_unix_seconds();
    if let (Some(k), Some(f)) = (&key, &fingerprint) {
        match auth.state().idempotent(k, now) {
            Ok(Some(r)) if &r.request == f => return replay(&r),
            Ok(Some(_)) => {
                return no_store(
                    Problem::new(
                        Code::Conflict,
                        "this Idempotency-Key was used for a different request",
                    )
                    .hint("Use a new key for each distinct change.")
                    .into_response(),
                    None,
                );
            }
            Ok(None) => {}
            Err(e) => return no_store(Problem::internal(e.to_string()).into_response(), None),
        }
    }
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let deleting = matches!(op, SecretOp::Delete { .. });
    let w = SecretWrite {
        name: name.clone(),
        op,
        dry_run,
        expect: expected_head(&headers),
        by: actor.name.clone(),
        role: Some(p.role),
        agent: p.agent.as_ref().map(|a| a.token_name.clone()),
    };
    let result = backend.secret_write(w).await;
    let (status, text) = match &result {
        Ok(c) => (StatusCode::OK, serde_json::to_string(c).unwrap_or_default()),
        Err(e) => (
            e.code_status(),
            serde_json::to_string(e).unwrap_or_default(),
        ),
    };
    if let Ok(c) = &result
        && c.applied
    {
        auth.record(
            &actor,
            if deleting {
                "secret.delete"
            } else {
                "secret.put"
            },
            &name,
            &audit_detail(c),
        );
    }
    if let (Some(k), Some(f)) = (&key, fingerprint)
        && status.is_success()
    {
        let r = Replay {
            request: f,
            status: status.as_u16(),
            response: text,
        };
        if let Err(e) = auth.state().remember_idempotent(k, &r, now) {
            tracing::warn!("idempotency key not stored: {e}");
        }
    }
    match result {
        Ok(c) => {
            let etag = c.head.etag.clone();
            no_store(Json(c).into_response(), Some(&etag))
        }
        Err(e) => no_store(e.into_response(), None),
    }
}

/// REQ: AGT-005 (ADR-903 §4) — what the audit log keeps of a secret change: its name, kind,
/// stamp and users, never the value or its length.
pub fn audit_detail(c: &SecretChange) -> serde_json::Value {
    serde_json::json!({
        "name": c.secret.name,
        "kind": c.secret.kind,
        "stamp": c.secret.stamp,
        "usedBy": c.used_by.iter().map(|u| match &u.node {
            Some(n) => format!("{} {}.{} (node {n})", u.kind, u.name, u.field),
            None => format!("{} {}.{}", u.kind, u.name, u.field),
        }).collect::<Vec<_>>(),
    })
}

/// A boxed answer for backends without a store.
pub(crate) fn unavailable() -> BoxFuture<Result<SecretChange, Problem>> {
    Box::pin(async {
        Err(Problem::unavailable(
            "stored secrets aren't available on this node",
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: API-015, NFR-005 — a value never prints, and a body parses into one.
    #[test]
    fn api_015_secret_text_never_prints() {
        let b: SecretPut =
            serde_json::from_str(r#"{"value": "hunter2-long", "kind": "text"}"#).unwrap();
        assert_eq!(b.value.expose(), "hunter2-long");
        let shown = format!("{b:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains(MARKER), "{shown}");
        assert!(serde_json::from_str::<SecretPut>(r#"{"value": "x", "other": 1}"#).is_err());
        let w = SecretWrite {
            name: "n".into(),
            op: SecretOp::Put {
                kind: "text".into(),
                value: SecretText::new("hunter2-long".into()),
            },
            dry_run: false,
            expect: None,
            by: "root".into(),
            role: Some(Role::Admin),
            agent: None,
        };
        assert!(!format!("{w:?}").contains("hunter2"));
    }

    // REQ: API-015 — `If-Match` forms for the head's ETag.
    #[test]
    fn api_015_if_match_head_forms() {
        let h = |v: &str| {
            let mut m = HeaderMap::new();
            m.insert(IF_MATCH, HeaderValue::from_str(v).unwrap());
            m
        };
        assert_eq!(expected_head(&HeaderMap::new()), None);
        assert_eq!(expected_head(&h("*")), None);
        assert_eq!(
            expected_head(&h("\"3.7.abcd\"")).as_deref(),
            Some("3.7.abcd")
        );
        assert_eq!(
            expected_head(&h("W/\"3.7.abcd\"")).as_deref(),
            Some("3.7.abcd")
        );
        assert_eq!(
            SecretsHead::etag_of(0, 2, "0123456789abcdef0123"),
            "0.2.0123456789abcdef"
        );
    }
}

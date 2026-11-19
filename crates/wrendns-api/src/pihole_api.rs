//! REQ: API-005, API-002, AGT-001 (T24.10, ADR-961) — the Pi-hole compatible API: the part of
//! Pi-hole's v6 (`/api/...`) and v5 (`/admin/api.php`) interfaces that dashboards, phone apps and
//! the Home Assistant Pi-hole integration use: the summary and status reads, the top lists, and
//! turning blocking off for a while and on again. Nothing else writes through it.
//!
//! It is **off by default** and behind one token (the v6 `password`, the v5 `auth` value), shown
//! once and stored as a BLAKE3 hash. A v6 sign-in gives a short in-memory session (`sid`, never a
//! cookie, so there is no CSRF surface). Failed attempts share the sign-in lockout. Pausing calls
//! the same code as `POST /api/v1/blocking/pause`. Clean room: written from Pi-hole's public API
//! documentation and from the requests the Home Assistant integration makes.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wrendns_store::state::State as Store;
use utoipa::ToSchema;

use crate::Shared;
use crate::auth::routes::{principal, reason, remote};
use crate::auth::{Actor, Auth, crypto};
use crate::model::{BlockingNode, Step, TopKind};
use crate::problem::{Code, Problem};

/// A v6 session lasts this long without use; every use renews it.
pub const SESSION_SECS: u64 = 300;
/// Open v6 sessions (the oldest goes when a new one needs room).
const MAX_SESSIONS: usize = 32;
/// The statistics are computed at most this often.
const STATS_TTL: Duration = Duration::from_secs(10);
/// "Clients ever seen" (30 days of hours) is recounted at most this often.
const TOTAL_TTL: Duration = Duration::from_secs(600);
/// `pihole_api.denied` entries: at most one per client address per minute.
const DENIED_EVERY_SECS: u64 = 60;
/// `pihole_api.denied` entries: at most this many in all per minute.
const DENIED_MAX_PER_WINDOW: usize = 10;
/// A v6 session ends this long after sign-in, however often it is used.
const SESSION_MAX_SECS: u64 = 24 * 3600;
/// The window every statistic covers.
const WINDOW_SECS: u64 = 86_400;
/// The most clients and names counted (what `top_range` is asked for).
const COUNT_CAP: usize = 1_000;
const TOTAL_CAP: usize = 10_000;
/// The longest pause an admin may allow (a day, as `POST /blocking/pause`).
pub const MAX_PAUSE_MINUTES: u32 = 24 * 60;
/// The default longest pause (an agent's cap, spec/13 §3.2).
pub const DEFAULT_PAUSE_MINUTES: u32 = 60;
/// The actor name audit entries carry for pauses made through this API.
const ACTOR: &str = "token:pihole-api";

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Debug, Clone, Default)]
struct Cfg {
    enabled: bool,
    token_hash: Option<Vec<u8>>,
    token_created: Option<u64>,
    last_used: Option<u64>,
    max_pause_minutes: u32,
}

#[derive(Debug)]
struct Session {
    sid_hash: Vec<u8>,
    csrf: String,
    expires: u64,
    /// Hard end (sign-in plus `SESSION_MAX_SECS`).
    until: u64,
}

/// The statistics one 24 hour window gives (shared by the v6 and v5 summaries).
#[derive(Debug, Default)]
struct Stats {
    queries: u64,
    blocked: u64,
    cached: u64,
    forwarded: u64,
    by_status: BTreeMap<String, u64>,
    by_qtype: BTreeMap<String, u64>,
    by_rcode: BTreeMap<String, u64>,
    unique_domains: u64,
    active_clients: u64,
    domains_blocked: u64,
    version: String,
}

/// The Pi-hole compatible API's settings and sessions, held by [`Auth`].
#[derive(Debug)]
pub struct PiholeCompat {
    store: Arc<Store>,
    cfg: RwLock<Cfg>,
    sessions: Mutex<Vec<Session>>,
    denied: Mutex<HashMap<IpAddr, u64>>,
    persisted_use: Mutex<u64>,
    stats: Mutex<Option<(Instant, Arc<Stats>)>>,
    clients_total: Mutex<Option<(Instant, u64)>>,
}

/// The settings as the admin API shows them: never the token.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PiholeApiStatus {
    /// Whether the Pi-hole compatible API answers. Off by default.
    pub enabled: bool,
    /// Whether a token has been issued (the token itself is shown only when it is made).
    pub token_set: bool,
    pub token_created_unix_seconds: Option<u64>,
    /// When a request last carried the token (to the minute).
    pub last_used_unix_seconds: Option<u64>,
    /// The longest pause it may start, in minutes (1 to 1,440). Pi-hole's "disable with no timer"
    /// pauses for this long.
    pub max_pause_minutes: u32,
}

/// Body of `PUT /api/v1/pihole-api`: fields left out keep their value.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PiholeApiSettings {
    pub enabled: Option<bool>,
    #[schema(minimum = 1, maximum = 1440)]
    pub max_pause_minutes: Option<u32>,
}

/// A freshly issued token: shown once.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PiholeApiToken {
    /// The token. It is not stored and can't be read again: rotate to get another.
    pub token: String,
    pub status: PiholeApiStatus,
}

#[allow(clippy::needless_pass_by_value)] // used as `map_err(db)`
fn db(e: wrendns_store::state::StateError) -> Problem {
    Problem::internal(format!("{e}"))
}

impl PiholeCompat {
    /// Loads the settings from the state database (off, with no token, when it can't be read).
    pub fn load(store: Arc<Store>) -> Self {
        let cfg = store.pihole_api().map_or_else(
            |_| Cfg {
                max_pause_minutes: DEFAULT_PAUSE_MINUTES,
                ..Cfg::default()
            },
            |r| Cfg {
                enabled: r.enabled,
                token_hash: r.token_hash,
                token_created: r.token_created,
                last_used: r.last_used,
                max_pause_minutes: r.max_pause_minutes.clamp(1, MAX_PAUSE_MINUTES),
            },
        );
        Self {
            store,
            cfg: RwLock::new(cfg),
            sessions: Mutex::new(Vec::new()),
            denied: Mutex::new(HashMap::new()),
            persisted_use: Mutex::new(0),
            stats: Mutex::new(None),
            clients_total: Mutex::new(None),
        }
    }

    fn cfg(&self) -> Cfg {
        self.cfg
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn status(&self) -> PiholeApiStatus {
        let c = self.cfg();
        PiholeApiStatus {
            enabled: c.enabled,
            token_set: c.token_hash.is_some(),
            token_created_unix_seconds: c.token_created,
            last_used_unix_seconds: c.last_used,
            max_pause_minutes: c.max_pause_minutes,
        }
    }

    /// Whether the paths answer at all: on, with a token.
    fn serving(&self) -> bool {
        let c = self.cfg.read().unwrap_or_else(PoisonError::into_inner);
        c.enabled && c.token_hash.is_some()
    }

    fn clear_sessions(&self) {
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Turns the API on or off (off ends every session). Blocking.
    pub fn set_enabled(&self, on: bool, now: u64) -> Result<(), Problem> {
        self.store.set_pihole_enabled(on, now).map_err(db)?;
        self.cfg
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .enabled = on;
        if !on {
            self.clear_sessions();
        }
        Ok(())
    }

    /// Sets the longest pause (1 to 1,440 minutes). Blocking.
    pub fn set_max_pause(&self, minutes: u32, now: u64) -> Result<(), Problem> {
        if !(1..=MAX_PAUSE_MINUTES).contains(&minutes) {
            return Err(Problem::invalid(format!(
                "`maxPauseMinutes`: 1 to {MAX_PAUSE_MINUTES}"
            )));
        }
        self.store.set_pihole_max_pause(minutes, now).map_err(db)?;
        self.cfg
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .max_pause_minutes = minutes;
        Ok(())
    }

    /// Issues a new token (replacing any), ends every session, and returns the token: the only
    /// time it exists in clear. Blocking.
    pub fn issue_token(&self, now: u64) -> Result<String, Problem> {
        let token = crypto::random_secret();
        let hash = crypto::secret_hash(&token);
        self.store.set_pihole_token(Some(&hash), now).map_err(db)?;
        {
            let mut c = self.cfg.write().unwrap_or_else(PoisonError::into_inner);
            c.token_hash = Some(hash);
            c.token_created = Some(now);
            c.last_used = None;
        }
        self.clear_sessions();
        Ok(token)
    }

    /// Removes the token (and so every session). Blocking.
    pub fn revoke_token(&self, now: u64) -> Result<(), Problem> {
        self.store.set_pihole_token(None, now).map_err(db)?;
        {
            let mut c = self.cfg.write().unwrap_or_else(PoisonError::into_inner);
            c.token_hash = None;
            c.token_created = None;
            c.last_used = None;
        }
        self.clear_sessions();
        Ok(())
    }

    /// Whether `presented` is the token (constant time). False when the API is off.
    fn token_ok(&self, presented: &str) -> bool {
        let c = self.cfg();
        let Some(hash) = c.token_hash.filter(|_| c.enabled) else {
            return false;
        };
        crypto::ct_eq(&crypto::secret_hash(presented), &hash)
    }

    /// Records a use (kept to the minute; the database row at most once a minute).
    fn touch(&self, now: u64) {
        let now = now - now % 60;
        {
            let mut c = self.cfg.write().unwrap_or_else(PoisonError::into_inner);
            if c.last_used == Some(now) {
                return;
            }
            c.last_used = Some(now);
        }
        let mut last = self
            .persisted_use
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if now.saturating_sub(*last) >= 60 {
            *last = now;
            let _ = self.store.touch_pihole(now);
        }
    }

    /// Opens a v6 session: `(sid, csrf)`.
    fn open_session(&self, now: u64) -> (String, String) {
        let (sid, csrf) = (crypto::random_secret(), crypto::random_secret());
        let mut s = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        s.retain(|x| x.expires > now && x.until > now);
        while s.len() >= MAX_SESSIONS {
            s.remove(0);
        }
        s.push(Session {
            sid_hash: crypto::secret_hash(&sid),
            csrf: csrf.clone(),
            expires: now + SESSION_SECS,
            until: now + SESSION_MAX_SECS,
        });
        (sid, csrf)
    }

    /// Whether `sid` is a live session (renewed by this use); `csrf`, when sent, must match.
    fn session_ok(&self, sid: &str, csrf: Option<&str>, now: u64) -> bool {
        if !self.serving() {
            return false;
        }
        let hash = crypto::secret_hash(sid);
        let mut s = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        s.retain(|x| x.expires > now && x.until > now);
        let Some(x) = s.iter_mut().find(|x| crypto::ct_eq(&x.sid_hash, &hash)) else {
            return false;
        };
        if csrf.is_some_and(|c| !crypto::ct_eq(c.as_bytes(), x.csrf.as_bytes())) {
            return false;
        }
        x.expires = now + SESSION_SECS;
        true
    }

    fn close_session(&self, sid: &str) {
        let hash = crypto::secret_hash(sid);
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|x| !crypto::ct_eq(&x.sid_hash, &hash));
    }

    /// `true` once per client network per minute (an IPv6 client by its /64), and at most
    /// `DENIED_MAX_PER_WINDOW` in all per minute, so no scanner can flood the audit log. The map
    /// holds only the entries allowed in the last minute, so it never holds more than that cap.
    fn may_audit_denied(&self, ip: IpAddr, now: u64) -> bool {
        let key = match ip {
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & (u128::MAX << 64)).into()),
            v4 @ IpAddr::V4(_) => v4,
        };
        let mut m = self.denied.lock().unwrap_or_else(PoisonError::into_inner);
        m.retain(|_, t| now.saturating_sub(*t) < DENIED_EVERY_SECS);
        if m.contains_key(&key) || m.len() >= DENIED_MAX_PER_WINDOW {
            return false;
        }
        m.insert(key, now);
        true
    }

    fn cached_stats(&self) -> Option<Arc<Stats>> {
        self.stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|(at, _)| at.elapsed() < STATS_TTL)
            .map(|(_, s)| Arc::clone(s))
    }
}

// ---- the statistics

/// The 24 hour window behind every summary field (ADR-961 §4). Blocking.
fn gather(b: &Shared, compat: &PiholeCompat) -> Arc<Stats> {
    if let Some(s) = compat.cached_stats() {
        return s;
    }
    let now = b.now_unix_seconds();
    let from = now.saturating_sub(WINDOW_SECS);
    let mut s = Stats::default();
    for bucket in b.timeseries(Step::Minute, from, now + 1) {
        s.queries += u64::from(bucket.total);
        for (k, v) in &bucket.by_status {
            *s.by_status.entry(k.clone()).or_default() += u64::from(*v);
        }
        for (k, v) in &bucket.by_qtype {
            *s.by_qtype.entry(k.clone()).or_default() += u64::from(*v);
        }
        for (k, v) in &bucket.by_rcode {
            *s.by_rcode.entry(k.clone()).or_default() += u64::from(*v);
        }
    }
    let st = |k: &str| s.by_status.get(k).copied().unwrap_or(0);
    s.blocked = st("blocked");
    s.cached = st("cached") + st("stale") + st("refreshed");
    s.forwarded = st("forwarded");
    s.unique_domains = b.top_range(TopKind::Domains, from, now, COUNT_CAP).len() as u64;
    s.active_clients = b.top_range(TopKind::Clients, from, now, COUNT_CAP).len() as u64;
    let info = b.system_info();
    s.domains_blocked = info.filter_names;
    s.version = info.version;
    let s = Arc::new(s);
    *compat.stats.lock().unwrap_or_else(PoisonError::into_inner) =
        Some((Instant::now(), Arc::clone(&s)));
    s
}

/// Distinct clients over 30 days (at most [`TOTAL_CAP`]), recounted every [`TOTAL_TTL`]. Blocking.
fn clients_total(b: &Shared, compat: &PiholeCompat, active: u64) -> u64 {
    let cached = compat
        .clients_total
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .filter(|(at, _)| at.elapsed() < TOTAL_TTL)
        .map(|(_, n)| n);
    let n = cached.unwrap_or_else(|| {
        let now = b.now_unix_seconds();
        let n = b
            .top_range(
                TopKind::Clients,
                now.saturating_sub(30 * 86_400),
                now,
                TOTAL_CAP,
            )
            .len() as u64;
        *compat
            .clients_total
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some((Instant::now(), n));
        n
    });
    n.max(active)
}

#[allow(clippy::cast_precision_loss)]
fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64 * 1000.0 / whole as f64).round() / 10.0
    }
}

/// `(status word, seconds left)` from every node's pauses (ADR-961 §4).
fn blocking_status(items: &[BlockingNode]) -> (&'static str, Option<u64>) {
    let mut answered = false;
    let mut timer: Option<u64> = None;
    for n in items.iter().filter(|n| n.error.is_none()) {
        answered = true;
        for p in n.pauses.iter().filter(|p| p.group.is_none()) {
            timer = Some(timer.map_or(p.seconds_left, |t| t.max(p.seconds_left)));
        }
    }
    if !items.is_empty() && !answered {
        ("unknown", None)
    } else if timer.is_some() {
        ("disabled", timer)
    } else {
        ("enabled", None)
    }
}

/// The reply type counts Pi-hole's summary has, from the response codes.
fn replies(s: &Stats) -> BTreeMap<&'static str, u64> {
    let rc = |k: &str| s.by_rcode.get(k).copied().unwrap_or(0);
    let known = rc("NOERROR") + rc("NXDOMAIN") + rc("SERVFAIL") + rc("REFUSED");
    BTreeMap::from([
        ("UNKNOWN", 0),
        ("NODATA", 0),
        ("NXDOMAIN", rc("NXDOMAIN")),
        ("CNAME", 0),
        ("IP", rc("NOERROR")),
        ("DOMAIN", 0),
        ("RRNAME", 0),
        ("SERVFAIL", rc("SERVFAIL")),
        ("REFUSED", rc("REFUSED")),
        ("NOTIMP", 0),
        ("OTHER", s.queries.saturating_sub(known)),
        ("DNSSEC", 0),
        ("NONE", 0),
        ("BLOB", 0),
    ])
}

// ---- admin routes (/api/v1/pihole-api)

/// Reads (operator): the status.
pub(crate) fn read_routes(auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/pihole-api", get(get_status))
        .with_state(auth)
}

/// Changes (admin; never an agent: the token is a credential).
pub(crate) fn admin_routes(auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/pihole-api", axum::routing::put(put_settings))
        .route(
            "/api/v1/pihole-api/token",
            post(issue_token).delete(revoke_token),
        )
        .with_state(auth)
}

/// Pi-hole compatible API: settings and status.
///
/// Whether the Pi-hole compatible API (v6 `/api/...` and v5 `/admin/api.php`, for dashboards,
/// phone apps and the Home Assistant Pi-hole integration) is on, whether a token has been issued
/// and when, when it was last used, and the longest pause it may start. Never the token. Needs
/// the operator role (agents: `config:read`).
#[utoipa::path(get, path = "/api/v1/pihole-api", tag = "config",
    responses((status = 200, body = PiholeApiStatus, description = "The settings, without the token.")))]
pub(crate) async fn get_status(State(auth): State<Arc<Auth>>) -> Json<PiholeApiStatus> {
    Json(auth.pihole().status())
}

/// Change the Pi-hole compatible API's settings.
///
/// Turns it on or off (off ends every session and makes its paths answer 404) and sets the
/// longest pause it may start (`maxPauseMinutes`, 1 to 1,440, default 60). Fields left out keep
/// their value. Turning it on needs a token: issue one with `POST /api/v1/pihole-api/token`.
/// Admins only, never agent tokens; audit-logged as `pihole_api.enable`, `pihole_api.disable`
/// and `pihole_api.settings`.
#[utoipa::path(put, path = "/api/v1/pihole-api", tag = "config", request_body = PiholeApiSettings,
    responses(
        (status = 200, body = PiholeApiStatus, description = "The settings now."),
        (status = 400, body = Problem, description = "`maxPauseMinutes` out of range."),
    ))]
pub(crate) async fn put_settings(
    State(auth): State<Arc<Auth>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<PiholeApiSettings>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let req = match crate::auth::routes::body(b) {
        Ok(r) => r,
        Err(p) => return p.into_response(),
    };
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let a2 = Arc::clone(&auth);
    let r = tokio::task::spawn_blocking(move || -> Result<PiholeApiStatus, Problem> {
        a2.audit_ready()?;
        let before = a2.pihole().status();
        let now = unix_now();
        // Validate the enable precondition before applying anything.
        if req.enabled == Some(true) && !before.enabled && !before.token_set {
            return Err(Problem::new(
                Code::Conflict,
                "the Pi-hole compatible API has no token yet",
            )
            .hint("Issue one first: POST /api/v1/pihole-api/token (Settings → Pi-hole)."));
        }
        if let Some(m) = req.max_pause_minutes {
            a2.pihole().set_max_pause(m, now)?;
            a2.record(
                &actor,
                "pihole_api.settings",
                "pihole-api",
                &json!({ "maxPauseMinutes": m, "was": before.max_pause_minutes }),
            );
        }
        if let Some(on) = req.enabled.filter(|on| *on != before.enabled) {
            if on && !before.token_set {
                return Err(Problem::new(
                    Code::Conflict,
                    "the Pi-hole compatible API has no token yet",
                )
                .hint("Issue one first: POST /api/v1/pihole-api/token (Settings → Pi-hole)."));
            }
            a2.pihole().set_enabled(on, now)?;
            a2.record(
                &actor,
                if on {
                    "pihole_api.enable"
                } else {
                    "pihole_api.disable"
                },
                "pihole-api",
                &json!({}),
            );
        }
        Ok(a2.pihole().status())
    })
    .await;
    match r {
        Ok(Ok(s)) => Json(s).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => Problem::internal(format!("pihole-api settings: {e}")).into_response(),
    }
}

/// Issue or rotate the Pi-hole compatible API's token.
///
/// Makes a new token (replacing any: the old one stops working and every session ends) and
/// returns it. **This is the only time it is shown**; only its hash is kept. It is the v6
/// `password` and the v5 `auth` value. Does not turn the API on. Admins only, never agent
/// tokens; audit-logged as `pihole_api.token_rotate`; the answer is `Cache-Control: no-store`.
#[utoipa::path(post, path = "/api/v1/pihole-api/token", tag = "config",
    responses((status = 200, body = PiholeApiToken, description = "The token, once.")))]
pub(crate) async fn issue_token(
    State(auth): State<Arc<Auth>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let a2 = Arc::clone(&auth);
    let r = tokio::task::spawn_blocking(move || -> Result<PiholeApiToken, Problem> {
        a2.audit_ready()?;
        let had = a2.pihole().status().token_set;
        let token = a2.pihole().issue_token(unix_now())?;
        a2.record(
            &actor,
            "pihole_api.token_rotate",
            "pihole-api",
            &json!({ "replaced": had }),
        );
        Ok(PiholeApiToken {
            token,
            status: a2.pihole().status(),
        })
    })
    .await;
    match r {
        Ok(Ok(t)) => {
            let mut resp = Json(t).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => Problem::internal(format!("pihole-api token: {e}")).into_response(),
    }
}

/// Revoke the Pi-hole compatible API's token.
///
/// Removes the token: nothing can sign in until a new one is issued, and the API is turned off.
/// Admins only, never agent tokens; audit-logged as `pihole_api.token_revoke`.
#[utoipa::path(delete, path = "/api/v1/pihole-api/token", tag = "config",
    responses((status = 200, body = PiholeApiStatus, description = "The settings now.")))]
pub(crate) async fn revoke_token(
    State(auth): State<Arc<Auth>>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let a2 = Arc::clone(&auth);
    let r = tokio::task::spawn_blocking(move || -> Result<PiholeApiStatus, Problem> {
        a2.audit_ready()?;
        let now = unix_now();
        let was_on = a2.pihole().status().enabled;
        a2.pihole().revoke_token(now)?;
        if was_on {
            a2.pihole().set_enabled(false, now)?;
        }
        a2.record(
            &actor,
            "pihole_api.token_revoke",
            "pihole-api",
            &json!({ "wasEnabled": was_on }),
        );
        Ok(a2.pihole().status())
    })
    .await;
    match r {
        Ok(Ok(s)) => Json(s).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => Problem::internal(format!("pihole-api revoke: {e}")).into_response(),
    }
}

// ---- the compatible paths

/// What a compatible path needs next to the API's own state.
type Compat = (Shared, Arc<Auth>);

/// The Pi-hole v6 and v5 paths (ADR-961 §2). Outside the sign-in machinery: each handler checks
/// the token or the session itself, and answers the API's ordinary 404 when the API is off.
pub(crate) fn compat_routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route(
            "/api/auth",
            post(v6_login).get(v6_session).delete(v6_logout),
        )
        .route("/api/stats/summary", get(v6_summary))
        .route("/api/stats/top_domains", get(v6_top_domains))
        .route("/api/stats/top_clients", get(v6_top_clients))
        .route("/api/stats/upstreams", get(v6_upstreams))
        .route("/api/info/version", get(v6_version))
        .route("/api/dns/blocking", get(v6_blocking).post(v6_set_blocking))
        .route("/admin/api.php", get(v5))
        .with_state((backend, auth))
}

/// How a compatible request was refused.
enum Refusal {
    /// Off (or no token): the API's ordinary 404.
    Absent,
    /// Locked out after repeated failures: seconds to wait.
    Locked(u64),
    /// No or a wrong credential.
    Bad,
}

fn limiter_key(ip: IpAddr) -> String {
    format!("p:{ip}")
}

/// Checks `presented` (a v5 token, or a v6 password) for `ip`. Failures count toward the lockout.
fn check(
    auth: &Auth,
    ip: IpAddr,
    now: u64,
    ok: impl FnOnce(&PiholeCompat) -> bool,
) -> Result<(), Refusal> {
    let pc = auth.pihole();
    if !pc.serving() {
        return Err(Refusal::Absent);
    }
    let key = limiter_key(ip);
    // A correct credential (256 bits) goes through even from a locked address: another client
    // behind the same address (NAT, a proxy, the Docker bridge) with a stale token must not
    // lock the right one out. The lock applies to failures only.
    if ok(pc) {
        auth.succeed(&key);
        pc.touch(now);
        return Ok(());
    }
    if let Some(wait) = auth.locked(&key, now) {
        return Err(Refusal::Locked(wait));
    }
    auth.fail(&key, now);
    Err(Refusal::Bad)
}

/// Audits a refused write (rate limited; never while the API is off). The database write runs
/// off the async threads.
fn audit_denied(auth: &Arc<Auth>, ip: IpAddr, path: &str, why: &str, now: u64) {
    if auth.pihole().may_audit_denied(ip, now) {
        let a = Arc::clone(auth);
        let (path, why) = (path.to_owned(), why.to_owned());
        drop(tokio::task::spawn_blocking(move || {
            a.record(
                &Actor {
                    name: "pihole-api (no valid token)".into(),
                    kind: "token",
                    remote: Some(ip.to_string()),
                    reason: None,
                },
                "pihole_api.denied",
                &path,
                &json!({ "why": why }),
            );
        }));
    }
}

fn took(t: Instant) -> f64 {
    (t.elapsed().as_secs_f64() * 1000.0).round() / 1000.0
}

/// A v6 error body: `{"error":{"key","message","hint"},"took"}`.
fn v6_error(status: StatusCode, key: &str, message: &str, hint: Option<&str>) -> Response {
    (
        status,
        Json(json!({ "error": { "key": key, "message": message, "hint": hint }, "took": 0.0 })),
    )
        .into_response()
}

fn v6_refusal(r: &Refusal, uri: &Uri) -> Response {
    match r {
        Refusal::Absent => crate::not_found(uri).into_response(),
        Refusal::Locked(wait) => {
            let mut resp = v6_error(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limiting",
                "Too many requests",
                Some(&format!("Too many failed attempts; try again in {wait} s")),
            );
            if let Ok(v) = HeaderValue::from_str(&wait.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
            resp
        }
        Refusal::Bad => v6_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unauthorized",
            None,
        ),
    }
}

/// The v6 session id: `X-FTL-SID`, or the `sid` query parameter.
fn sid_of(headers: &HeaderMap, q: &HashMap<String, String>) -> Option<String> {
    headers
        .get("x-ftl-sid")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| q.get("sid").cloned())
        .filter(|s| !s.is_empty())
}

/// Authenticates a v6 read or write by its session; `Ok(remote)` when it may go on.
#[allow(clippy::result_large_err)] // the refusal is the response to send
fn v6_gate(
    auth: &Arc<Auth>,
    ext: &axum::http::Extensions,
    headers: &HeaderMap,
    q: &HashMap<String, String>,
    uri: &Uri,
    write: bool,
) -> Result<IpAddr, Response> {
    let ip = remote(auth, ext, headers);
    let now = unix_now();
    let sid = sid_of(headers, q);
    let csrf = headers.get("x-ftl-csrf").and_then(|v| v.to_str().ok());
    match check(auth, ip, now, |pc| {
        sid.as_deref().is_some_and(|s| pc.session_ok(s, csrf, now))
    }) {
        Ok(()) => Ok(ip),
        Err(r) => {
            if write && !matches!(r, Refusal::Absent) {
                let why = match r {
                    Refusal::Locked(_) => "locked",
                    _ => "no valid session",
                };
                audit_denied(auth, ip, uri.path(), why, now);
            }
            Err(v6_refusal(&r, uri))
        }
    }
}

/// Body of `POST /api/auth`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginBody {
    /// The token.
    pub password: Option<String>,
}

/// Pi-hole v6: sign in (the token is the `password`).
///
/// Part of the Pi-hole compatible API (off unless an admin turned it on). Takes
/// `{"password": "<token>"}` and answers `{"session": {"valid": true, "sid": ..., "csrf": ...,
/// "validity": 300}}`; send `sid` as `X-FTL-SID` afterwards. 401 for a wrong password, 429 after
/// repeated failures, the ordinary 404 when the API is off.
#[utoipa::path(post, path = "/api/auth", tag = "pihole-compat", security(()), request_body = LoginBody,
    responses((status = 200, description = "A session."), (status = 401, description = "Wrong password."),
        (status = 429, description = "Too many failed attempts."), (status = 404, body = Problem, description = "The API is off.")))]
pub(crate) async fn v6_login(
    State((_, auth)): State<Compat>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    uri: Uri,
    body: Result<Json<LoginBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let t = Instant::now();
    let ip = remote(&auth, &ext, &headers);
    let now = unix_now();
    if !auth.pihole().serving() {
        return crate::not_found(&uri).into_response();
    }
    let Ok(Json(b)) = body else {
        return v6_error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "Bad request",
            Some("Send a JSON body {\"password\": \"<token>\"}"),
        );
    };
    let password = b.password.unwrap_or_default();
    match check(&auth, ip, now, |pc| pc.token_ok(&password)) {
        Ok(()) => {
            let (sid, csrf) = auth.pihole().open_session(now);
            Json(json!({
                "session": {
                    "valid": true, "totp": false, "sid": sid, "csrf": csrf,
                    "validity": SESSION_SECS, "message": "correct password"
                },
                "took": took(t)
            }))
            .into_response()
        }
        Err(r) => v6_refusal(&r, &uri),
    }
}

/// Pi-hole v6: the current session.
///
/// Part of the Pi-hole compatible API. With a live `X-FTL-SID` answers
/// `{"session": {"valid": true, "validity": 300}}` and renews it; 401 otherwise.
#[utoipa::path(get, path = "/api/auth", tag = "pihole-compat", security(()),
    responses((status = 200, description = "The session is valid."), (status = 401, description = "No valid session.")))]
pub(crate) async fn v6_session(
    State((_, auth)): State<Compat>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    uri: Uri,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let t = Instant::now();
    match v6_gate(&auth, &ext, &headers, &q, &uri, false) {
        Ok(_) => Json(json!({
            "session": { "valid": true, "totp": false, "validity": SESSION_SECS, "message": "session is valid" },
            "took": took(t)
        }))
        .into_response(),
        Err(r) => r,
    }
}

/// Pi-hole v6: sign out.
///
/// Part of the Pi-hole compatible API. Ends the session named by `X-FTL-SID`; 204.
#[utoipa::path(delete, path = "/api/auth", tag = "pihole-compat", security(()),
    responses((status = 204, description = "Signed out.")))]
pub(crate) async fn v6_logout(
    State((_, auth)): State<Compat>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !auth.pihole().serving() {
        return crate::not_found(&uri).into_response();
    }
    if let Some(sid) = sid_of(&headers, &q) {
        auth.pihole().close_session(&sid);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn stats_of(backend: &Shared, auth: &Arc<Auth>) -> Result<(Arc<Stats>, u64), Problem> {
    let b = crate::request_backend(backend);
    let a = Arc::clone(auth);
    tokio::task::spawn_blocking(move || {
        let s = gather(&b, a.pihole());
        let total = clients_total(&b, a.pihole(), s.active_clients);
        (s, total)
    })
    .await
    .map_err(|e| Problem::internal(format!("pihole-api stats: {e}")))
}

/// The pause state of every node, as `(word, seconds left)`.
async fn blocking_of(backend: &Shared) -> Result<(&'static str, Option<u64>), Problem> {
    let b = crate::request_backend(backend);
    tokio::task::spawn_blocking(move || blocking_status(&b.blocking_state()))
        .await
        .map_err(|e| Problem::internal(format!("pihole-api blocking: {e}")))
}

fn v6_problem(p: &Problem) -> Response {
    v6_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "Internal server error",
        Some(&p.detail),
    )
}

/// Pi-hole v6: the summary.
///
/// Part of the Pi-hole compatible API (needs a v6 session). The last 24 hours: `queries` (total,
/// blocked, `percent_blocked`, cached, forwarded, `unique_domains`, types, status, replies),
/// `clients` (active, total) and `gravity.domains_being_blocked`, in Pi-hole's shape.
#[utoipa::path(get, path = "/api/stats/summary", tag = "pihole-compat", security(()),
    responses((status = 200, description = "Pi-hole's summary object."), (status = 401, description = "No valid session.")))]
pub(crate) async fn v6_summary(
    State((backend, auth)): State<Compat>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    uri: Uri,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let t = Instant::now();
    if let Err(r) = v6_gate(&auth, &ext, &headers, &q, &uri, false) {
        return r;
    }
    let (s, total) = match stats_of(&backend, &auth).await {
        Ok(x) => x,
        Err(p) => return v6_problem(&p),
    };
    let status: BTreeMap<&str, u64> = BTreeMap::from([
        ("UNKNOWN", 0),
        ("GRAVITY", s.blocked),
        ("FORWARDED", s.forwarded),
        ("CACHE", s.cached),
    ]);
    #[allow(clippy::cast_precision_loss)]
    let frequency = s.queries as f64 / (WINDOW_SECS as f64 / 60.0);
    Json(json!({
        "queries": {
            "total": s.queries,
            "blocked": s.blocked,
            "percent_blocked": percent(s.blocked, s.queries),
            "unique_domains": s.unique_domains,
            "forwarded": s.forwarded,
            "cached": s.cached,
            "frequency": (frequency * 1000.0).round() / 1000.0,
            "types": s.by_qtype,
            "status": status,
            "replies": replies(&s),
        },
        "clients": { "active": s.active_clients, "total": total },
        "gravity": { "domains_being_blocked": s.domains_blocked, "last_update": 0 },
        "took": took(t),
    }))
    .into_response()
}

fn count_of(q: &HashMap<String, String>) -> usize {
    q.get("count")
        .and_then(|c| c.parse::<usize>().ok())
        .map_or(10, |c| c.clamp(1, 100))
}

async fn top_items(backend: &Shared, kind: TopKind, limit: usize) -> Vec<crate::model::TopItem> {
    let b = crate::request_backend(backend);
    tokio::task::spawn_blocking(move || {
        let now = b.now_unix_seconds();
        b.top_range(kind, now.saturating_sub(WINDOW_SECS), now, limit)
    })
    .await
    .unwrap_or_default()
}

/// Pi-hole v6: the top domains.
///
/// Part of the Pi-hole compatible API (needs a v6 session). `blocked=true` ranks blocked names,
/// otherwise the permitted ones; `count` (default 10, at most 100). Over the last 24 hours:
/// `{"domains": [{"domain", "count"}], "total_queries", "blocked_queries"}`.
#[utoipa::path(get, path = "/api/stats/top_domains", tag = "pihole-compat", security(()),
    responses((status = 200, description = "Pi-hole's top-domains object."), (status = 401, description = "No valid session.")))]
pub(crate) async fn v6_top_domains(
    State((backend, auth)): State<Compat>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    uri: Uri,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let t = Instant::now();
    if let Err(r) = v6_gate(&auth, &ext, &headers, &q, &uri, false) {
        return r;
    }
    let blocked = q.get("blocked").is_some_and(|v| v == "true");
    let kind = if blocked {
        TopKind::Blocked
    } else {
        TopKind::Domains
    };
    let items = top_items(&backend, kind, count_of(&q)).await;
    let (s, _) = match stats_of(&backend, &auth).await {
        Ok(x) => x,
        Err(p) => return v6_problem(&p),
    };
    Json(json!({
        "domains": items.iter().map(|i| json!({ "domain": i.key, "count": i.count })).collect::<Vec<_>>(),
        "total_queries": s.queries,
        "blocked_queries": s.blocked,
        "took": took(t),
    }))
    .into_response()
}

/// Pi-hole v6: the top clients.
///
/// Part of the Pi-hole compatible API (needs a v6 session). The busiest devices over the last 24
/// hours (`count`, default 10, at most 100): `{"clients": [{"ip", "name", "count"}],
/// "total_queries", "blocked_queries"}`; names and addresses follow the node's privacy level.
#[utoipa::path(get, path = "/api/stats/top_clients", tag = "pihole-compat", security(()),
    responses((status = 200, description = "Pi-hole's top-clients object."), (status = 401, description = "No valid session.")))]
pub(crate) async fn v6_top_clients(
    State((backend, auth)): State<Compat>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    uri: Uri,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let t = Instant::now();
    if let Err(r) = v6_gate(&auth, &ext, &headers, &q, &uri, false) {
        return r;
    }
    let items = top_items(&backend, TopKind::Clients, count_of(&q)).await;
    let (s, _) = match stats_of(&backend, &auth).await {
        Ok(x) => x,
        Err(p) => return v6_problem(&p),
    };
    Json(json!({
        "clients": items.iter().map(|i| json!({
            "ip": i.key, "name": i.name.clone().unwrap_or_default(), "count": i.count
        })).collect::<Vec<_>>(),
        "total_queries": s.queries,
        "blocked_queries": s.blocked,
        "took": took(t),
    }))
    .into_response()
}

/// `udp://1.1.1.1:53` or `https://dns.example/dns-query` as `(host, port)`.
fn split_endpoint(e: &str) -> (String, u16) {
    let rest = e.split_once("://").map_or(e, |(_, r)| r);
    let hostport = rest.split('/').next().unwrap_or(rest);
    let default = if e.starts_with("tls://") {
        853
    } else if e.starts_with("https://") {
        443
    } else {
        53
    };
    if let Some(inner) = hostport.strip_prefix('[')
        && let Some((h, p)) = inner.split_once(']')
    {
        return (
            h.to_owned(),
            p.trim_start_matches(':').parse().unwrap_or(default),
        );
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h.to_owned(), p.parse().unwrap_or(default)),
        _ => (hostport.to_owned(), default),
    }
}

/// Pi-hole v6: the upstream servers.
///
/// Part of the Pi-hole compatible API (needs a v6 session). Each configured upstream as
/// `{"ip", "name", "port", "count", "statistics": {"response", "variance"}}` (`count` is the
/// requests sent since start; `response` the smoothed answer time in seconds), with
/// `forwarded_queries` and `total_queries`.
#[utoipa::path(get, path = "/api/stats/upstreams", tag = "pihole-compat", security(()),
    responses((status = 200, description = "Pi-hole's upstreams object."), (status = 401, description = "No valid session.")))]
pub(crate) async fn v6_upstreams(
    State((backend, auth)): State<Compat>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    uri: Uri,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let t = Instant::now();
    if let Err(r) = v6_gate(&auth, &ext, &headers, &q, &uri, false) {
        return r;
    }
    let b = crate::request_backend(&backend);
    let ups = tokio::task::spawn_blocking(move || b.upstreams())
        .await
        .unwrap_or_default();
    let (s, _) = match stats_of(&backend, &auth).await {
        Ok(x) => x,
        Err(p) => return v6_problem(&p),
    };
    Json(json!({
        "upstreams": ups.iter().map(|u| {
            let (host, port) = split_endpoint(&u.endpoint);
            json!({
                "ip": host, "name": u.name, "port": port, "count": u.requests,
                "statistics": { "response": u.latency_ewma_ms / 1000.0, "variance": 0.0 }
            })
        }).collect::<Vec<_>>(),
        "forwarded_queries": s.forwarded,
        "total_queries": s.queries,
        "took": took(t),
    }))
    .into_response()
}

/// Pi-hole v6: the version.
///
/// Part of the Pi-hole compatible API (needs a v6 session). Our version as the `core`, `web`
/// and `ftl` local versions; the remote (latest) versions are empty, so no update is offered.
#[utoipa::path(get, path = "/api/info/version", tag = "pihole-compat", security(()),
    responses((status = 200, description = "Pi-hole's version object."), (status = 401, description = "No valid session.")))]
pub(crate) async fn v6_version(
    State((backend, auth)): State<Compat>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    uri: Uri,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let t = Instant::now();
    if let Err(r) = v6_gate(&auth, &ext, &headers, &q, &uri, false) {
        return r;
    }
    let b = crate::request_backend(&backend);
    let version = tokio::task::spawn_blocking(move || b.system_info().version)
        .await
        .unwrap_or_default();
    let part = || {
        json!({
            "local": { "branch": "wrendns", "version": version, "hash": null },
            "remote": { "version": null, "hash": null }
        })
    };
    Json(json!({
        "version": {
            "core": part(), "web": part(), "ftl": part(),
            "docker": { "local": null, "remote": null }
        },
        "took": took(t),
    }))
    .into_response()
}

fn blocking_body(word: &str, timer: Option<u64>, t: Instant) -> Response {
    Json(json!({ "blocking": word, "timer": timer, "took": took(t) })).into_response()
}

/// Pi-hole v6: whether blocking is on.
///
/// Part of the Pi-hole compatible API (needs a v6 session). `{"blocking": "enabled" | "disabled" |
/// "unknown", "timer": <seconds left or null>}`: disabled while any node has blocking paused for
/// everyone (the same state as `GET /api/v1/blocking`).
#[utoipa::path(get, path = "/api/dns/blocking", tag = "pihole-compat", security(()),
    responses((status = 200, description = "Pi-hole's blocking object."), (status = 401, description = "No valid session.")))]
pub(crate) async fn v6_blocking(
    State((backend, auth)): State<Compat>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    uri: Uri,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let t = Instant::now();
    if let Err(r) = v6_gate(&auth, &ext, &headers, &q, &uri, false) {
        return r;
    }
    match blocking_of(&backend).await {
        Ok((word, timer)) => blocking_body(word, timer, t),
        Err(p) => v6_problem(&p),
    }
}

/// Body of `POST /api/dns/blocking`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BlockingBody {
    /// `true` ends every pause, `false` pauses blocking for everyone.
    pub blocking: Option<bool>,
    /// Seconds to stay off (rounded up to whole minutes; none: the longest allowed). Anything but
    /// a number counts as none: the Home Assistant integration sends `true` for "no timer".
    #[schema(value_type = Option<f64>)]
    pub timer: Option<Value>,
}

/// Seconds as whole minutes, rounded up, between 1 and `max` (no timer: `max`).
fn pause_minutes(timer_secs: Option<f64>, max: u32) -> u32 {
    let Some(secs) = timer_secs.filter(|s| s.is_finite() && *s > 0.0) else {
        return max;
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let m = (secs / 60.0).ceil().min(f64::from(MAX_PAUSE_MINUTES)) as u32;
    m.clamp(1, max)
}

/// The shared pause or resume, as the token's actor.
async fn switch_blocking(
    backend: &Shared,
    auth: &Arc<Auth>,
    ip: IpAddr,
    enable: bool,
    timer_secs: Option<f64>,
    dialect: &str,
) -> Result<(), Problem> {
    let actor = Actor {
        name: ACTOR.into(),
        kind: "token",
        remote: Some(ip.to_string()),
        reason: Some(format!("Pi-hole compatible API ({dialect})")),
    };
    let a2 = Arc::clone(auth);
    let ready = tokio::task::spawn_blocking(move || a2.audit_ready())
        .await
        .map_err(|e| Problem::internal(format!("audit: {e}")))?;
    ready?;
    if enable {
        crate::blocking_api::apply_resume(backend, auth, &actor, None, None, Some("pihole-api"))
            .await
            .map(|_| ())
    } else {
        let minutes = pause_minutes(timer_secs, auth.pihole().cfg().max_pause_minutes);
        crate::blocking_api::apply_pause(
            backend,
            auth,
            &actor,
            None,
            minutes,
            None,
            Some("pihole-api"),
        )
        .await
        .map(|_| ())
    }
}

/// Pi-hole v6: turn blocking off for a while, or back on.
///
/// Part of the Pi-hole compatible API (needs a v6 session). `{"blocking": false, "timer": 300}`
/// pauses blocking for everyone for the timer's seconds (rounded up to whole minutes; no timer
/// pauses for the longest allowed, default 60 minutes; a longer timer is cut to it), the same
/// pause as `POST /api/v1/blocking/pause`. `{"blocking": true}` ends every pause. Answers like
/// `GET /api/dns/blocking`. Audit-logged as `blocking.pause` / `blocking.resume` by
/// `token:pihole-api`.
#[utoipa::path(post, path = "/api/dns/blocking", tag = "pihole-compat", security(()), request_body = BlockingBody,
    responses((status = 200, description = "Pi-hole's blocking object, as now."),
        (status = 400, description = "No `blocking` boolean."), (status = 401, description = "No valid session.")))]
pub(crate) async fn v6_set_blocking(
    State((backend, auth)): State<Compat>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    uri: Uri,
    Query(q): Query<HashMap<String, String>>,
    body: Result<Json<BlockingBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let t = Instant::now();
    let ip = match v6_gate(&auth, &ext, &headers, &q, &uri, true) {
        Ok(ip) => ip,
        Err(r) => return r,
    };
    let Some(enable) = body.ok().and_then(|Json(b)| {
        b.blocking
            .map(|e| (e, b.timer.as_ref().and_then(Value::as_f64)))
    }) else {
        return v6_error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "Bad request",
            Some("Send {\"blocking\": true|false, \"timer\": seconds|null}"),
        );
    };
    if let Err(p) = switch_blocking(&backend, &auth, ip, enable.0, enable.1, "v6").await {
        return v6_problem(&p);
    }
    match blocking_of(&backend).await {
        Ok((word, timer)) => blocking_body(word, timer, t),
        Err(p) => v6_problem(&p),
    }
}

// ---- Pi-hole v5: /admin/api.php

/// Numbers as Pi-hole's `summary` prints them: `1,234`.
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn v5_denied(r: &Refusal, uri: &Uri, write: bool) -> Response {
    match r {
        Refusal::Absent => crate::not_found(uri).into_response(),
        Refusal::Locked(_) => (StatusCode::TOO_MANY_REQUESTS, Json(json!([]))).into_response(),
        Refusal::Bad => {
            let status = if write {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::OK
            };
            (status, Json(json!([]))).into_response()
        }
    }
}

/// Pi-hole v5: `/admin/api.php`.
///
/// Part of the Pi-hole compatible API. The query string picks the call, as in Pi-hole v5, with
/// the token as `auth`: `summaryRaw` and `summary` (the 24 hour totals), `status`, `topItems`
/// (`topItems=N`: the top permitted and blocked names), `enable`, and `disable` or
/// `disable=<seconds>` (the same pause as `POST /api/v1/blocking/pause`; no number pauses for the
/// longest allowed, default 60 minutes). `versions` needs no token. Without a valid token a read
/// answers `[]` and a write 401; the API being off answers as any unknown page does. Prefer v6: v5 puts the
/// token in the address, which proxies and logs may keep.
#[utoipa::path(get, path = "/admin/api.php", tag = "pihole-compat", security(()),
    responses((status = 200, description = "Pi-hole v5's answer for the call."),
        (status = 401, description = "A write without a valid token.")))]
#[allow(clippy::too_many_lines)] // one flat dispatch over Pi-hole v5's query-string calls
pub(crate) async fn v5(
    State((backend, auth)): State<Compat>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    uri: Uri,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let ip = remote(&auth, &ext, &headers);
    let now = unix_now();
    let has = |k: &str| q.contains_key(k);
    if !auth.pihole().serving() {
        // Off: the same answer as any unknown path (the web UI), and nothing audited.
        return crate::ui::serve(&axum::http::Method::GET, &uri, &headers);
    }
    // Version information needs no token in v5, and the Home Assistant integration asks for it
    // without one: it holds only our version.
    if (has("versions") || has("version")) && !has("summaryRaw") && !has("summary") {
        let b = crate::request_backend(&backend);
        let v = tokio::task::spawn_blocking(move || b.system_info().version)
            .await
            .unwrap_or_default();
        return Json(json!({
            "core_update": false, "web_update": false, "FTL_update": false,
            "core_current": v, "web_current": v, "FTL_current": v,
            "core_latest": v, "web_latest": v, "FTL_latest": v,
            "core_branch": "wrendns", "web_branch": "wrendns", "FTL_branch": "wrendns",
        }))
        .into_response();
    }
    let write = has("enable") || has("disable");
    let presented = q.get("auth").cloned().unwrap_or_default();
    if let Err(r) = check(&auth, ip, now, |pc| pc.token_ok(&presented)) {
        if write && !matches!(r, Refusal::Absent) {
            let why = match r {
                Refusal::Locked(_) => "locked",
                _ => "no valid token",
            };
            audit_denied(&auth, ip, uri.path(), why, now);
        }
        return v5_denied(&r, &uri, write);
    }
    if write {
        let enable = has("enable");
        // `disable=300` is seconds; `disable` / `disable=True` is "until enabled" (here: the cap).
        let secs = q.get("disable").and_then(|v| v.parse::<f64>().ok());
        if let Err(p) = switch_blocking(&backend, &auth, ip, enable, secs, "v5").await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": p.detail })),
            )
                .into_response();
        }
        return match blocking_of(&backend).await {
            Ok((word, _)) => Json(json!({ "status": word })).into_response(),
            Err(p) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": p.detail })),
            )
                .into_response(),
        };
    }
    if has("status") && !has("summaryRaw") && !has("summary") && !has("topItems") {
        return match blocking_of(&backend).await {
            Ok((word, _)) => Json(json!({ "status": word })).into_response(),
            Err(p) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": p.detail })),
            )
                .into_response(),
        };
    }
    if has("topItems") {
        let n = q
            .get("topItems")
            .and_then(|c| c.parse::<usize>().ok())
            .map_or(10, |c| c.clamp(1, 100));
        let top = top_items(&backend, TopKind::Domains, n).await;
        let ads = top_items(&backend, TopKind::Blocked, n).await;
        let map = |v: Vec<crate::model::TopItem>| -> Value {
            Value::Object(v.into_iter().map(|i| (i.key, json!(i.count))).collect())
        };
        return Json(json!({ "top_queries": map(top), "top_ads": map(ads) })).into_response();
    }
    if has("summaryRaw") || has("summary") {
        let (s, total) = match stats_of(&backend, &auth).await {
            Ok(x) => x,
            Err(p) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": p.detail })),
                )
                    .into_response();
            }
        };
        let (word, _) = blocking_of(&backend).await.unwrap_or(("unknown", None));
        let raw = has("summaryRaw");
        let n = |v: u64| -> Value { if raw { json!(v) } else { json!(grouped(v)) } };
        let pct = percent(s.blocked, s.queries);
        let mut o = json!({
            "domains_being_blocked": n(s.domains_blocked),
            "dns_queries_today": n(s.queries),
            "ads_blocked_today": n(s.blocked),
            "ads_percentage_today": if raw { json!(pct) } else { json!(format!("{pct:.1}")) },
            "unique_domains": n(s.unique_domains),
            "queries_forwarded": n(s.forwarded),
            "queries_cached": n(s.cached),
            "clients_ever_seen": n(total),
            "unique_clients": n(s.active_clients),
            "dns_queries_all_types": n(s.queries),
            "dns_queries_all_replies": n(s.queries),
            "privacy_level": 0,
            "status": word,
            "gravity_last_updated": { "file_exists": true, "absolute": 0,
                "relative": { "days": 0, "hours": 0, "minutes": 0 } },
        });
        if let Some(obj) = o.as_object_mut() {
            for (k, v) in replies(&s) {
                obj.insert(format!("reply_{k}"), n(v));
            }
        }
        return Json(o).into_response();
    }
    (StatusCode::OK, Json(json!([]))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_005_pause_minutes_rounds_up_and_caps() {
        assert_eq!(pause_minutes(Some(1.0), 60), 1);
        assert_eq!(pause_minutes(Some(60.0), 60), 1);
        assert_eq!(pause_minutes(Some(61.0), 60), 2);
        assert_eq!(pause_minutes(Some(300.0), 60), 5);
        assert_eq!(pause_minutes(Some(86_400.0), 60), 60, "cut to the setting");
        assert_eq!(pause_minutes(Some(86_400.0), 1_440), 1_440);
        assert_eq!(pause_minutes(None, 60), 60, "no timer: the cap");
        assert_eq!(pause_minutes(Some(0.0), 45), 45);
        assert_eq!(pause_minutes(Some(f64::NAN), 45), 45);
        assert_eq!(pause_minutes(Some(-5.0), 45), 45);
    }

    #[test]
    fn api_005_endpoints_split_into_host_and_port() {
        assert_eq!(split_endpoint("udp://1.1.1.1:53"), ("1.1.1.1".into(), 53));
        assert_eq!(split_endpoint("tls://9.9.9.9"), ("9.9.9.9".into(), 853));
        assert_eq!(
            split_endpoint("https://dns.example/dns-query"),
            ("dns.example".into(), 443)
        );
        assert_eq!(
            split_endpoint("udp://[2606:4700::1111]:53"),
            ("2606:4700::1111".into(), 53)
        );
    }

    #[test]
    fn api_005_numbers_group_like_pi_hole() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_234), "1,234");
        assert_eq!(grouped(1_234_567), "1,234,567");
    }

    #[test]
    fn api_005_blocking_status_reads_everyone_pauses_only() {
        use crate::model::PauseInfo;
        let pause = |group: Option<&str>, left| PauseInfo {
            group: group.map(str::to_owned),
            until: String::new(),
            seconds_left: left,
        };
        assert_eq!(blocking_status(&[]), ("enabled", None));
        let one = |pauses| BlockingNode {
            node: None,
            pauses,
            error: None,
        };
        assert_eq!(blocking_status(&[one(vec![])]), ("enabled", None));
        assert_eq!(
            blocking_status(&[one(vec![pause(Some("kids"), 30)])]),
            ("enabled", None),
            "one group paused is not blocking off"
        );
        assert_eq!(
            blocking_status(&[one(vec![pause(None, 90)]), one(vec![pause(None, 120)])]),
            ("disabled", Some(120))
        );
        let failed = BlockingNode {
            node: Some("n".into()),
            pauses: vec![],
            error: Some("down".into()),
        };
        assert_eq!(blocking_status(&[failed]), ("unknown", None));
    }
}

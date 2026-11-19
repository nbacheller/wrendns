//! REQ: OBS-901 (T26.2, ADR-958 sections 5 and 6) — the map's routes, the shared ticker behind the
//! stream, and the per-peer cache the cluster read keeps.
//!
//! - `GET /api/v1/map`: the snapshot, with server filters.
//! - `GET /api/v1/map/stream`: Server-Sent Events, one `snapshot` every 2 s. **One** ticker builds
//!   one unfiltered snapshot for every subscriber and stops when none remain; at most 8 streams
//!   (`429 map_streams_busy`).
//! - `GET /api/v1/map/world` and `GET /api/v1/map/health`.
//!
//! **A ticker never waits on a peer** (ADR-958 section 6): a separate gather task polls each peer
//! on its own schedule and keeps the last good answer with its age ([`PeerCache`]); the snapshot
//! builder only reads those. A peer whose last answer is older than [`PEER_STALE`] is missing.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use tokio::sync::watch;
use utoipa::IntoParams;

use crate::map::{self, Context, Filter, Gateway, MapPart, MapParts, MapSnapshot, Net};
use crate::problem::{Code, Problem};
use crate::{Backend, Shared, blocking};

/// Streams one node serves at once.
pub const MAX_STREAMS: usize = 8;
/// How often the ticker builds a snapshot.
pub const TICK: Duration = Duration::from_secs(2);
/// Streams one user or token may hold.
pub const MAX_PER_OWNER: usize = 2;
/// An unfiltered read is served from the ticker's snapshot when it is younger than this.
pub const FRESH: Duration = Duration::from_secs(2);
/// Snapshot builds the routes run at once (the rest wait).
pub const MAX_BUILDS: usize = 4;
/// A peer whose last good answer is older than this is missing (three intervals).
pub const PEER_STALE: Duration = Duration::from_secs(6);

/// The routes (viewer role; agents: `analytics:read`).
pub(crate) fn read_routes(backend: Shared) -> Router {
    let state = MapState {
        hub: MapHub::new(Arc::clone(&backend), TICK),
        backend,
    };
    Router::new()
        .route("/api/v1/map", get(get_map))
        .route("/api/v1/map/stream", get(map_stream))
        .route("/api/v1/map/world", get(get_world))
        .route("/api/v1/map/health", get(get_health))
        // REQ: OBS-902 (T26.4) - the GeoIP database's status: everyone who sees the map sees it.
        .route("/api/v1/map/geoip", get(get_geoip))
        // The settings are read here (viewers) and written in `config_api` (operators): one path.
        .route("/api/v1/map-settings/default", get(get_settings))
        .with_state(state)
}

/// REQ: OBS-902 (T26.4, ADR-959 section 2) - "Update now" and "Delete database": admin only, no
/// agent scope (an agent can't make a node download from the internet or delete what it holds).
pub(crate) fn admin_routes(backend: Shared, auth: Arc<crate::auth::Auth>) -> Router {
    Router::new()
        .route(
            "/api/v1/map/geoip/update",
            axum::routing::post(update_geoip),
        )
        .route("/api/v1/map/geoip", axum::routing::delete(delete_geoip))
        .with_state((backend, auth))
}

#[derive(Clone)]
pub(crate) struct MapState {
    backend: Shared,
    hub: Arc<MapHub>,
}

impl std::fmt::Debug for MapState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapState").finish_non_exhaustive()
    }
}

/// `GET /api/v1/map` filters: they narrow what the server builds. The stream is never filtered
/// (one snapshot serves every subscriber); a client filters it on its side.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MapParams {
    /// Only this network (a name from `GET /api/v1/networks`).
    pub network: Option<String>,
    /// Only devices of this client group.
    pub group: Option<String>,
    /// Only devices whose name or address contains this text.
    pub device: Option<String>,
    /// Only this TelltaleDNS node (its pod, site or ID, as the Cluster page shows it).
    pub node: Option<String>,
}

/// `GET /api/v1/map/world` filters. Answer prefixes are counted per node, not per device, so the
/// network, group and device filters of the map have nothing to narrow here.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct WorldParams {
    /// Only this TelltaleDNS node (its pod, site or ID, as the Cluster page shows it).
    pub node: Option<String>,
}

impl MapParams {
    fn filter(&self) -> Filter {
        let t = |v: &Option<String>| {
            v.as_ref()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
        };
        Filter {
            network: t(&self.network),
            group: t(&self.group),
            device: t(&self.device),
            node: t(&self.node),
        }
    }
}

fn disabled() -> Problem {
    Problem::new(
        Code::MapDisabled,
        "the live network map is off on this node",
    )
    .hint("Turn it on in Settings, or set [map] enabled = true.")
}

/// What `[map]` says here; `map_disabled` when the map is off (or this backend has none).
pub fn settings(b: &dyn Backend) -> Result<map::MapSettings, Problem> {
    b.map_settings().filter(|s| s.enabled).ok_or_else(disabled)
}

fn context<'a>(
    b: &'a dyn Backend,
    th: map::Thresholds,
    names: &'a dyn Fn(std::net::IpAddr) -> Option<String>,
) -> Context<'a> {
    let networks = b
        .networks()
        .into_iter()
        .filter_map(|n| {
            telltale_config::Cidr::parse(&n.subnet)
                .ok()
                .map(|cidr| Net { name: n.name, cidr })
        })
        .collect();
    let routers = b.router_entries();
    let gateway = if routers.is_empty() {
        Gateway::None
    } else if let Some(r) = routers.iter().find(|r| r.status.state == "failing") {
        Gateway::Error(
            r.status
                .error
                .clone()
                .unwrap_or_else(|| format!("{} isn't answering", r.name)),
        )
    } else {
        Gateway::Ok
    };
    Context {
        thresholds: th,
        gateway,
        networks,
        device_name: names,
        now_unix_seconds: b.now_unix_seconds(),
    }
}

/// One snapshot from what this backend knows now (and, in a cluster, what the gather task has).
pub fn snapshot(b: &dyn Backend, filter: &Filter) -> Result<MapSnapshot, Problem> {
    let s = settings(b)?;
    let parts = b.map_parts();
    let names = |ip| b.client_name(ip);
    let ctx = context(b, s.thresholds, &names);
    Ok(map::build(&parts, &ctx, filter))
}

/// The live network map.
///
/// The network as a graph: the gateway, networks and VLANs, devices (the 200 busiest; the rest
/// fold into `+N more` per network), one resolver per TelltaleDNS node with its answer kinds, and
/// the upstreams. Edges carry the rate over the last 60 seconds and the shares of slow, failing and
/// blocked answers. Every node and edge has a `health`: `green`, `yellow`, `red`, or `idle` (too
/// few answers to say). The map is built from a sample of the lookups, never from the query path;
/// `sampleRate` says how thin the sample is. No domain name appears anywhere. `partial` and
/// `missingNodes` say when a cluster node didn't answer (it is a red resolver).
#[utoipa::path(get, path = "/api/v1/map", tag = "map", params(MapParams),
    responses(
        (status = 200, body = MapSnapshot, description = "The map."),
        (status = 404, body = Problem, description = "`map_disabled`: the map is off ([map] enabled).")))]
pub(crate) async fn get_map(
    State(s): State<MapState>,
    Query(p): Query<MapParams>,
) -> Result<Json<MapSnapshot>, Problem> {
    let filter = p.filter();
    s.hub.read(&filter).await.map(|m| Json((*m).clone()))
}

/// Live map stream.
///
/// Server-Sent Events: one `snapshot` event every 2 seconds (the same body as `GET /api/v1/map`,
/// unfiltered: filter it on your side) and a `ping` event every 15 seconds. One ticker builds the
/// snapshot for every subscriber and stops when the last one leaves. At most 8 streams per node
/// (`429 map_streams_busy`) and at most 2 per user or token. When the map is turned off the stream sends a `map_disabled` event and ends. Close it when the page is hidden.
#[utoipa::path(get, path = "/api/v1/map/stream", tag = "map",
    responses(
        (status = 200, description = "`text/event-stream` of `snapshot` (MapSnapshot) events.",
            content_type = "text/event-stream", body = String),
        (status = 404, body = Problem, description = "`map_disabled`."),
        (status = 429, body = Problem, description = "`map_streams_busy`: 8 streams are open on this node.")))]
pub(crate) async fn map_stream(
    State(s): State<MapState>,
    principal: Option<axum::Extension<crate::auth::Principal>>,
) -> Result<Response, Problem> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    settings(&*s.backend)?;
    let owner = principal.map_or_else(String::new, |p| crate::plans::owner_key(&p.0));
    let sub = s.hub.subscribe_as(&owner)?;
    // An empty text is the ticker saying the map was turned off: the stream says so and ends.
    let stream =
        futures_util::stream::unfold((sub, true, false), |(mut sub, first, done)| async move {
            if done {
                return None;
            }
            let text = sub.next(first).await?;
            if text.is_empty() {
                let event = Event::default().event("map_disabled").data("");
                return Some((Ok::<_, std::convert::Infallible>(event), (sub, false, true)));
            }
            let event = Event::default().event("snapshot").data(text.as_str());
            Some((
                Ok::<_, std::convert::Infallible>(event),
                (sub, false, false),
            ))
        });
    Ok(Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .event(Event::default().event("ping").data("")),
        )
        .into_response())
}

/// Where answers point (world view).
///
/// Countries with the rate, count and slow share of the answers that point there, and a marker
/// for each upstream whose address has a country. `available: false` with a `reason` when
/// answers can't be placed: `geoip_off` or `geoip_missing` (the GeoIP database, `GET
/// /map/geoip`), `address_not_recorded` (the lookup's answer address isn't kept yet, ADR-970: the
/// upstream `markers` are then where the upstreams are, not where answers point) or `privacy`
/// (level 3 keeps nothing per event). `unlocated` counts the answers with no place: failed,
/// blocked and local ones, and prefixes with no country. Countries come from the database of the
/// node that answers.
#[utoipa::path(get, path = "/api/v1/map/world", tag = "map", params(WorldParams),
    responses(
        (status = 200, body = map::MapWorld, description = "The world view's data, or why it is unavailable."),
        (status = 404, body = Problem, description = "`map_disabled`.")))]
pub(crate) async fn get_world(
    State(s): State<MapState>,
    Query(p): Query<WorldParams>,
) -> Result<Json<map::MapWorld>, Problem> {
    let b = s.backend;
    let _seat = s.hub.builds.acquire().await;
    let node = p
        .node
        .map(|n| n.trim().to_owned())
        .filter(|n| !n.is_empty());
    blocking(move || {
        let settings = settings(&*b)?;
        let parts = b.map_parts();
        let locate = |ips: &[std::net::IpAddr]| b.geoip_locate(ips);
        Ok(map::world(
            &parts,
            &settings.thresholds,
            b.now_unix_seconds(),
            node.as_deref(),
            &locate,
        ))
    })
    .await
    .map(Json)
}

/// The GeoIP database.
///
/// This node's country database for the world view: `enabled`, `state` (`off`, `missing`,
/// `downloading`, `ready`, `failed`), the source's month, when it was built, its size, when the
/// next check is due and the last error's code. The database is never bundled and is downloaded
/// only after an admin turns `[map.geoip]` on; each node that serves the console keeps its own
/// copy. Change the settings with `PUT /map-settings/default` (admin), fetch now with `POST
/// /map/geoip/update`, remove it with `DELETE /map/geoip`.
#[utoipa::path(get, path = "/api/v1/map/geoip", tag = "map",
    responses(
        (status = 200, body = crate::model::GeoipStatus, description = "The database's status."),
        (status = 404, body = Problem, description = "This node has no GeoIP database (a resolver pod).")))]
pub(crate) async fn get_geoip(
    State(s): State<MapState>,
) -> Result<Json<crate::model::GeoipStatus>, Problem> {
    let b = s.backend;
    blocking(move || {
        b.geoip_status()
            .ok_or_else(|| Problem::not_found("this node keeps no GeoIP database"))
    })
    .await
    .map(Json)
}

/// Fetch the GeoIP database now.
///
/// Starts a download on this node, in the background, even when the day's check is not due (it
/// also lifts a "Delete database"). The status shows `downloading`, then `ready` or `failed` with
/// the error's code; a failed fetch keeps the old database. Admin only (never an agent); audited
/// as `map.geoip.update`. 409 `conflict` when a fetch is running or the toggle is off.
#[utoipa::path(post, path = "/api/v1/map/geoip/update", tag = "map",
    responses(
        (status = 202, body = crate::model::GeoipStatus, description = "The fetch was started."),
        (status = 409, body = Problem, description = "A fetch is running already, or `[map.geoip]` is off.")))]
pub(crate) async fn update_geoip(
    State((backend, auth)): State<(Shared, Arc<crate::auth::Auth>)>,
    headers: axum::http::HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    geoip_action(backend, auth, headers, ext, "map.geoip.update", |b| {
        b.geoip_update()
    })
    .await
}

/// Delete the GeoIP database.
///
/// Removes this node's copy (and its `.prev`). While `[map.geoip]` stays on nothing is fetched
/// again until an admin presses Update now or turns it off and on; the world view says
/// `geoip_missing`. Admin only (never an agent); audited as `map.geoip.delete`.
#[utoipa::path(delete, path = "/api/v1/map/geoip", tag = "map",
    responses((status = 200, body = crate::model::GeoipStatus, description = "The status after the delete.")))]
pub(crate) async fn delete_geoip(
    State((backend, auth)): State<(Shared, Arc<crate::auth::Auth>)>,
    headers: axum::http::HeaderMap,
    ext: axum::http::Extensions,
) -> Response {
    geoip_action(backend, auth, headers, ext, "map.geoip.delete", |b| {
        b.geoip_delete()
    })
    .await
}

async fn geoip_action(
    backend: Shared,
    auth: Arc<crate::auth::Auth>,
    headers: axum::http::HeaderMap,
    ext: axum::http::Extensions,
    action: &'static str,
    run: fn(&dyn Backend) -> Result<crate::model::GeoipStatus, Problem>,
) -> Response {
    use crate::auth::routes::{principal, reason, remote};
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let actor = auth.actor(&p, remote(&auth, &ext, &headers), reason(&headers));
    let status = tokio::task::spawn_blocking({
        let b = Arc::clone(&backend);
        move || run(&*b)
    })
    .await
    .unwrap_or_else(|e| Err(Problem::internal(format!("request worker failed: {e}"))));
    let status = match status {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let a2 = Arc::clone(&auth);
    let detail = serde_json::json!({ "state": status.state });
    let _ = tokio::task::spawn_blocking(move || a2.record(&actor, action, "geoip", &detail)).await;
    let code = if action == "map.geoip.update" {
        axum::http::StatusCode::ACCEPTED
    } else {
        axum::http::StatusCode::OK
    };
    (code, Json(status)).into_response()
}

/// The live map's settings.
///
/// The `[map]` section as this node runs it: `enabled`, `event_rate`, `min_sample`,
/// `warn_latency_ms` (null: the latency objective's), and the thresholds that colour the map.
/// `source` is `file` (the configuration files' section or the defaults) or `override` (set
/// through the API or the UI). Written with `PUT /api/v1/map-settings/default`, reverted with
/// `DELETE`. The same entry is in `GET /api/v1/config/entries?kind=map`.
#[utoipa::path(get, path = "/api/v1/map-settings/default", tag = "map",
    responses((status = 200, body = crate::model::ConfigEntry, description = "The map's settings and where they come from.")))]
pub(crate) async fn get_settings(
    State(s): State<MapState>,
) -> Result<Json<crate::model::ConfigEntry>, Problem> {
    let b = s.backend;
    blocking(move || {
        b.config_entries(Some("map"))
            .into_iter()
            .next()
            .ok_or_else(|| Problem::not_found("this node has no map settings"))
    })
    .await
    .map(Json)
}

/// Network health in short.
///
/// Counts by health, the red and yellow nodes with their reasons (at most 50), and the five
/// busiest flows. Device names appear only at privacy levels 0 and 1 (at 2 and above devices are
/// hidden). The same data as the MCP tool `network_health`.
#[utoipa::path(get, path = "/api/v1/map/health", tag = "map", params(MapParams),
    responses(
        (status = 200, body = map::NetworkHealth, description = "The short version of the map."),
        (status = 404, body = Problem, description = "`map_disabled`.")))]
pub(crate) async fn get_health(
    State(s): State<MapState>,
    Query(p): Query<MapParams>,
) -> Result<Json<map::NetworkHealth>, Problem> {
    let filter = p.filter();
    s.hub
        .read(&filter)
        .await
        .map(|m| Json(map::network_health(&m)))
}

// ---------------------------------------------------------------------------------------------
// The shared ticker

/// One ticker for every stream: builds one unfiltered snapshot per interval while somebody
/// listens, and stops when nobody does.
pub struct MapHub {
    backend: Shared,
    interval: Duration,
    subs: AtomicUsize,
    running: AtomicBool,
    ticks: AtomicU64,
    tx: watch::Sender<Option<Arc<String>>>,
    /// Streams open per user or token ([`MAX_PER_OWNER`]).
    owners: Mutex<HashMap<String, usize>>,
    /// The newest unfiltered snapshot and when it was built: reads of it within [`FRESH`] are
    /// served from here.
    last: Mutex<Option<(Instant, Arc<MapSnapshot>)>>,
    /// Snapshot builds running at once for the routes ([`MAX_BUILDS`]).
    builds: tokio::sync::Semaphore,
}

impl std::fmt::Debug for MapHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapHub")
            .field("subscribers", &self.subscribers())
            .field("running", &self.running())
            .field("ticks", &self.ticks())
            .finish_non_exhaustive()
    }
}

/// A stream's seat: dropping it frees the seat.
#[derive(Debug)]
pub struct Subscription {
    hub: Arc<MapHub>,
    owner: String,
    rx: watch::Receiver<Option<Arc<String>>>,
}

impl Subscription {
    /// The next snapshot (as JSON text): the newest one at once when `first`, else the next
    /// the ticker builds. `None` when the hub is gone.
    pub async fn next(&mut self, first: bool) -> Option<Arc<String>> {
        // An empty text is the end-of-stream marker of an earlier map-off: a new stream joining
        // after a quick off-then-on toggle must not take it as its first frame.
        if first
            && let Some(v) = self.rx.borrow_and_update().clone()
            && !v.is_empty()
        {
            return Some(v);
        }
        loop {
            self.rx.changed().await.ok()?;
            if let Some(v) = self.rx.borrow_and_update().clone() {
                return Some(v);
            }
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.hub.release_owner(&self.owner);
        self.hub.subs.fetch_sub(1, Ordering::AcqRel);
    }
}

impl MapHub {
    pub fn new(backend: Shared, interval: Duration) -> Arc<Self> {
        Arc::new(Self {
            backend,
            interval,
            subs: AtomicUsize::new(0),
            running: AtomicBool::new(false),
            ticks: AtomicU64::new(0),
            tx: watch::channel(None).0,
            owners: Mutex::new(HashMap::new()),
            last: Mutex::new(None),
            builds: tokio::sync::Semaphore::new(MAX_BUILDS),
        })
    }

    fn release_owner(&self, owner: &str) {
        if owner.is_empty() {
            return;
        }
        let mut o = self.owners.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = o.get_mut(owner) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                o.remove(owner);
            }
        }
    }

    /// A snapshot for a route: the ticker's own when the filter is empty and it is younger than
    /// [`FRESH`]; else a build, at most [`MAX_BUILDS`] at a time. A build copies the sampler's
    /// window out and sums it outside the sampler's lock, so it never stalls the aggregator.
    pub async fn read(&self, filter: &Filter) -> Result<Arc<MapSnapshot>, Problem> {
        let plain = *filter == Filter::default();
        // A cached snapshot is never served once the map is off (404 at once, not within 2 s).
        settings(&*self.backend)?;
        if plain
            && let Some((at, m)) = self
                .last
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
            && at.elapsed() < FRESH
        {
            return Ok(Arc::clone(m));
        }
        let _seat = self.builds.acquire().await;
        let (b, f) = (Arc::clone(&self.backend), filter.clone());
        let m = Arc::new(blocking(move || snapshot(&*b, &f)).await?);
        if plain {
            *self.last.lock().unwrap_or_else(PoisonError::into_inner) =
                Some((Instant::now(), Arc::clone(&m)));
        }
        Ok(m)
    }

    /// Takes a seat (`429 map_streams_busy` when [`MAX_STREAMS`] are taken) and makes sure the
    /// ticker runs. Needs a tokio runtime.
    pub fn subscribe(self: &Arc<Self>) -> Result<Subscription, Problem> {
        self.subscribe_as("")
    }

    /// As [`Self::subscribe`] for `owner` (a user or token), who may hold at most
    /// [`MAX_PER_OWNER`] seats; an empty owner is not counted.
    pub fn subscribe_as(self: &Arc<Self>, owner: &str) -> Result<Subscription, Problem> {
        if !owner.is_empty() {
            let mut o = self.owners.lock().unwrap_or_else(PoisonError::into_inner);
            let n = o.entry(owner.to_owned()).or_insert(0);
            if *n >= MAX_PER_OWNER {
                let mut p = Problem::new(
                    Code::MapStreamsBusy,
                    format!("this user or token already holds {MAX_PER_OWNER} map streams"),
                )
                .hint("Close another map page, or poll GET /api/v1/map instead.");
                p.retry_after = Some(5);
                return Err(p);
            }
            *n += 1;
        }
        self.subs
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_STREAMS).then_some(n + 1)
            })
            .map_err(|_| {
                self.release_owner(owner);
                let mut p = Problem::new(
                    Code::MapStreamsBusy,
                    format!("{MAX_STREAMS} map streams are already open on this node"),
                )
                .hint("Close another map page, or poll GET /api/v1/map instead.");
                p.retry_after = Some(5);
                p
            })?;
        let sub = Subscription {
            hub: Arc::clone(self),
            owner: owner.to_owned(),
            rx: self.tx.subscribe(),
        };
        if self
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            tokio::spawn(Arc::clone(self).tick_loop());
        }
        Ok(sub)
    }

    /// Streams open now.
    pub fn subscribers(&self) -> usize {
        self.subs.load(Ordering::Acquire)
    }

    /// Whether the ticker is running (it isn't with no subscribers).
    pub fn running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Snapshots built so far.
    pub fn ticks(&self) -> u64 {
        self.ticks.load(Ordering::Acquire)
    }

    async fn tick_loop(self: Arc<Self>) {
        loop {
            let b = Arc::clone(&self.backend);
            let built =
                tokio::task::spawn_blocking(move || snapshot(&*b, &Filter::default())).await;
            match built {
                Ok(Ok(s)) => {
                    if let Ok(text) = serde_json::to_string(&s) {
                        // Nobody listening is fine: the value waits for the next subscriber.
                        let _ = self.tx.send(Some(Arc::new(text)));
                    }
                    *self.last.lock().unwrap_or_else(PoisonError::into_inner) =
                        Some((Instant::now(), Arc::new(s)));
                }
                // The map was turned off: an empty text tells every stream to end.
                Ok(Err(e)) if e.code == Code::MapDisabled => {
                    *self.last.lock().unwrap_or_else(PoisonError::into_inner) = None;
                    let _ = self.tx.send(Some(Arc::new(String::new())));
                }
                _ => {}
            }
            self.ticks.fetch_add(1, Ordering::AcqRel);
            tokio::time::sleep(self.interval).await;
            if self.subs.load(Ordering::Acquire) == 0 {
                self.running.store(false, Ordering::Release);
                // A stream may have joined between the check and the store: it saw `running`.
                if self.subs.load(Ordering::Acquire) > 0
                    && self
                        .running
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    continue;
                }
                // The next snapshot starts from nothing: an old one must not greet a new stream.
                self.tx.send_replace(None);
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The per-peer cache of the cluster read

#[derive(Debug, Default)]
struct PeerInner {
    /// When the grace of peers not heard from began (restarted with each gather start).
    since: Option<Instant>,
    parts: HashMap<String, (Instant, MapPart)>,
    in_flight: HashSet<String>,
}

/// The last good part of each peer, with its age. The gather task writes, the snapshot reads;
/// neither waits for the other or for a peer.
#[derive(Debug)]
pub struct PeerCache {
    inner: Mutex<PeerInner>,
    started: Instant,
    stale: Duration,
}

/// A peer as the cache sees it: its ID, the label the map shows, whether it is connected.
#[derive(Debug, Clone)]
pub struct PeerRef {
    pub id: String,
    pub label: String,
    pub connected: bool,
    /// Not connected to this node, but the cluster's health relay reports it up (ADR-971).
    pub relayed_up: bool,
}

impl PeerCache {
    pub fn new(now: Instant) -> Self {
        Self::with_stale(now, PEER_STALE)
    }

    /// A cache with its own stale window (tests; the map uses [`PEER_STALE`]).
    pub fn with_stale(now: Instant, stale: Duration) -> Self {
        Self {
            inner: Mutex::new(PeerInner::default()),
            started: now,
            stale,
        }
    }

    /// A gather task is starting at `now`: peers are given their grace from here, not from when
    /// the cache was made (the first read after an idle spell finds the cache old).
    pub fn restart(&self, now: Instant) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .since = Some(now);
    }

    pub fn put(&self, peer: &str, part: MapPart, at: Instant) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .parts
            .insert(peer.to_owned(), (at, part));
    }

    /// Marks a poll of `peer` as running; false when one already is (a dead peer holds at most
    /// one task, however long its deadline).
    pub fn begin(&self, peer: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .in_flight
            .insert(peer.to_owned())
    }

    pub fn end(&self, peer: &str) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .in_flight
            .remove(peer);
    }

    /// Forgets peers that left the cluster.
    pub fn retain(&self, keep: &HashSet<String>) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .parts
            .retain(|k, _| keep.contains(k));
    }

    /// What the peers say now: each peer's last good part when it is younger than
    /// [`PEER_STALE`]; the rest are missing. A disconnected peer is missing at once; one that has
    /// not answered yet is given [`PEER_STALE`] from the first demand before it counts as missing.
    pub fn view(&self, peers: &[PeerRef], now: Instant) -> MapParts {
        let g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out = MapParts::default();
        let since = g.since.unwrap_or(self.started);
        let grace = now.saturating_duration_since(since) < self.stale;
        for p in peers {
            if !p.connected {
                if p.relayed_up {
                    out.unseen.push(p.label.clone());
                } else {
                    out.missing.push(p.label.clone());
                }
                continue;
            }
            match g.parts.get(&p.id) {
                Some((at, part)) if now.saturating_duration_since(*at) <= self.stale => {
                    let mut part = part.clone();
                    part.node.clone_from(&p.label);
                    out.parts.push(part);
                }
                // An old part or none: pending while the gather's first round may still land.
                _ if grace => out.pending.push(p.label.clone()),
                _ => out.missing.push(p.label.clone()),
            }
        }
        out
    }
}

/// Whether anybody has read the map lately: the gather task polls only while somebody does.
#[derive(Debug)]
pub struct Demand {
    started: Instant,
    /// Milliseconds since `started` of the last read.
    last_ms: AtomicU64,
    running: AtomicBool,
}

impl Demand {
    pub fn new(now: Instant) -> Self {
        Self {
            started: now,
            last_ms: AtomicU64::new(0),
            running: AtomicBool::new(false),
        }
    }

    /// Notes a read at `now`; true when the gather task isn't running (the caller starts it).
    pub fn touch(&self, now: Instant) -> bool {
        let ms = u64::try_from(now.saturating_duration_since(self.started).as_millis())
            .unwrap_or(u64::MAX);
        self.last_ms.store(ms.max(1), Ordering::Release);
        self.running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn idle_for(&self, now: Instant) -> Duration {
        let ms = u64::try_from(now.saturating_duration_since(self.started).as_millis())
            .unwrap_or(u64::MAX);
        Duration::from_millis(ms.saturating_sub(self.last_ms.load(Ordering::Acquire)))
    }

    /// Whether the gather task is running.
    pub fn running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Marks the gather task as not running (a caller that could not start it).
    pub fn stop(&self) {
        self.running.store(false, Ordering::Release);
    }
}

/// The gather task: every `interval`, polls each peer that has no poll running (each in a task of
/// its own with `deadline`) and files the answer in `cache`; stops after `idle_after` with no
/// read (see [`Demand`]). It never waits for a peer itself, so a dead one costs one parked task
/// and nothing else.
pub async fn gather<L, F, Fut>(
    cache: Arc<PeerCache>,
    demand: Arc<Demand>,
    peers: L,
    fetch: F,
    interval: Duration,
    deadline: Duration,
    idle_after: Duration,
) where
    L: Fn() -> Vec<PeerRef> + Send + 'static,
    F: Fn(String) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Option<MapPart>> + Send + 'static,
{
    loop {
        let list = peers();
        cache.retain(&list.iter().map(|p| p.id.clone()).collect());
        for p in list.into_iter().filter(|p| p.connected) {
            if !cache.begin(&p.id) {
                continue;
            }
            let (cache, fetch) = (Arc::clone(&cache), fetch.clone());
            tokio::spawn(async move {
                if let Ok(Some(part)) = tokio::time::timeout(deadline, fetch(p.id.clone())).await {
                    cache.put(&p.id, part, Instant::now());
                }
                cache.end(&p.id);
            });
        }
        tokio::time::sleep(interval).await;
        if demand.idle_for(Instant::now()) >= idle_after {
            demand.running.store(false, Ordering::Release);
            return;
        }
    }
}

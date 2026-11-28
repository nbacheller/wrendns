//! Request and response types. JSON is camelCase; field names carry their units
//! (`totalMs`, `ttlSeconds`) so agents and dashboards never have to guess (AGT-001).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// REQ: DNS-901 (T36.2) — one DNS listener's known-ID gate.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // one flag per fact the UI shows
pub struct ListenerAccess {
    /// The listener, as `proto://addr`.
    pub listener: String,
    /// It answers only a query that carries a known device key (the effective `require_client_id`).
    pub require_client_id: bool,
    /// What the file says: `unset`, `true` or `false`.
    pub setting: String,
    /// On only because the setting is unset and the default is on (a public address, or a wildcard bind
    /// on a host with a public IPv4 address).
    pub gated_by_default: bool,
    /// Bound to a public address (not loopback, RFC 1918, CGNAT, link-local or unique-local; a
    /// wildcard bind is not public).
    pub public_address: bool,
    /// Bound to every address (`0.0.0.0`, `::` or `::ffff:0.0.0.0`).
    pub wildcard_bind: bool,
    /// What the unset setting resolves to for this listener on this host: on for a public address,
    /// and for a wildcard bind when the host holds a public IPv4 address (or its interface list
    /// could not be read); off otherwise.
    pub default_on: bool,
    /// The default and why, as a sentence ("on, because it binds every address and this host has a
    /// public IPv4 address"); names the wildcard rule when it applies.
    pub default_reason: String,
    /// A public address reaches this listener (or might: fail closed), so turning the device key off
    /// opens it to the internet.
    pub public_exposure: bool,
    /// The transport can carry a device key (`dot`, `doh`, `doh3`, `doq`).
    pub can_carry_key: bool,
    /// REQ: API-902 (T27.14c) — the certificate and key paths of an encrypted listener (paths only; the
    /// files' contents are never returned), so the Listeners card can show and re-send them.
    ///
    /// Admin only (owner decision, 2026-11-27): absent from every other role's answer, with the path,
    /// the limits and `proxy_protocol` below.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
    /// The URL path of a DoH or DoH3 listener, when one is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The connection limits, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections_per_address: Option<u32>,
    /// The listener accepts PROXY protocol v2 (set in the configuration file only). Admin only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<bool>,
    /// The certificate's file name, without its directory: every signed-in role sees it (the paths
    /// above are admin only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert_name: Option<String>,
}

impl ListenerAccess {
    /// REQ: API-902 (T27.14c; owner decision, 2026-11-27) — drop what only an admin sees: the
    /// certificate and key paths, the URL path, the limits and the PROXY setting. The address, the
    /// protocol, the certificate's file name and the gate stay.
    pub fn without_admin_fields(&mut self) {
        self.tls_cert = None;
        self.tls_key = None;
        self.path = None;
        self.max_connections = None;
        self.max_connections_per_address = None;
        self.proxy_protocol = None;
    }
}

/// REQ: API-902, API-901 (T27.14f; owner decision, 2026-11-27) - how this node serves its web UI and
/// API, for the Settings "Web UI and API" card. Admin only: absent from every other caller's answer,
/// as the listener paths are, and absent from an older node's.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiInfo {
    /// The address the API listens on (`[api] listen`).
    pub listen: String,
    /// `https` when `[api] tls` is set (the node serves HTTPS itself), else `http`.
    pub scheme: String,
    /// With HTTPS: `self-signed`, or the certificate file's name (never its path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// `[api] trusted_proxies`, as in force now: each address or network.
    pub trusted_proxies: Vec<String>,
    /// The plain-HTTP redirect listener's address (`[api] http_redirect`), when one is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_redirect: Option<String>,
}

/// Node and build information.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    /// WrenDNS version.
    #[schema(example = "0.1.0")]
    pub version: String,
    /// Node name.
    pub node: String,
    /// Process role: `all`, `resolver`, or `controller`.
    pub role: String,
    pub uptime_seconds: u64,
    /// When the process started (RFC 3339).
    pub started_at: String,
    /// REQ: OBS-002 (T9.13) — times a node started on this data directory, and how many of
    /// those followed a run that didn't stop cleanly.
    pub starts: u64,
    pub unclean_starts: u64,
    /// DNS listeners, as `proto://addr`.
    pub listeners: Vec<String>,
    /// REQ: DNS-901 (T36.2) — each listener's known-ID gate: whether it requires a device key
    /// and whether it is bound to a public address, so the UI can warn about an open one.
    pub listener_access: Vec<ListenerAccess>,
    /// Whether the per-query log is being written.
    pub query_log: bool,
    /// Version of the active filter snapshot, if one is loaded.
    pub filter_snapshot: Option<u64>,
    /// Blocked names in the active snapshot.
    pub filter_names: u64,
    /// Present when client IPs appear masked (OPS-003): most recent queries come from a few
    /// infrastructure addresses (a Kubernetes node, a Docker bridge, a forwarding router),
    /// so per-device statistics and rules see those instead of devices.
    pub client_ips_masked: Option<MaskedClients>,
    /// Present when this node belongs to a cluster (CLU-001).
    pub cluster: Option<ClusterInfo>,
    /// Exactly which build this is (ADR-046).
    pub build: BuildInfo,
    /// Whether a newer build exists on this build's channel (ADR-046).
    pub update: UpdateStatus,
    /// REQ: OPS-010 — this node's maintenance window, while it's in maintenance.
    pub maintenance: Option<NodeMaintenance>,
    /// REQ: UPS-013 (T24.31, ADR-997) — this node's own interface addresses (loopback and
    /// link-local left out), which an upstream's `source` can name. They differ per node.
    pub addresses: Vec<NodeAddress>,
    /// REQ: API-902 (T27.14f) - how this node serves the web UI and API: the address, the scheme,
    /// the certificate's name, the trusted proxies and the redirect. Admin only (owner decision,
    /// 2026-11-27); an older node omits it, so a reader must treat it as absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<ApiInfo>,
}

/// One address this node holds, for the Upstreams form's `source` suggestions.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeAddress {
    /// The interface (`eth0`, `eth0.100`).
    pub interface: String,
    /// `198.51.100.252`
    pub address: String,
    /// The network it is in, which a shared upstream can name instead: `198.51.100.0/24`.
    pub network: String,
}

/// REQ: UPS-004 (T24.36) — one address a public resolver answers on.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamPresetEndpoint {
    /// `tls://1.1.1.1`, `udp://[2606:4700:4700::1111]`, `https://cloudflare-dns.com/dns-query`.
    pub url: String,
    /// `udp`, `tcp`, `tls`, `https` or `quic`.
    pub protocol: String,
    /// `v4` or `v6` for an address, `name` for a host name (which resolves to either).
    pub family: String,
    /// The name on the server certificate, for a `tls://` address given by IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
}

/// REQ: UPS-004 (T24.36) — a public resolver variant the simple picker offers.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamPreset {
    pub id: String,
    pub name: String,
    /// The heading it is listed under (`Cloudflare`).
    pub provider: String,
    /// The choice under the heading (`Malware`).
    pub variant: String,
    /// One line: what it filters and what it does with your queries.
    pub note: String,
    pub homepage: String,
    /// `none`, `malware`, `family` or `ads`.
    pub filtering: String,
    pub dnssec: bool,
    /// Offered in the simple view (false: it needs a parameter, or is for the Advanced view).
    pub simple: bool,
    /// Placeholders in its addresses (a NextDNS profile); empty for every simple preset.
    pub params: Vec<String>,
    pub endpoints: Vec<UpstreamPresetEndpoint>,
}

/// REQ: UPS-004 (T24.36) — the catalog, and what this node can reach.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamPresets {
    /// Whether this node has a usable IPv6 default route: without one, an IPv6 upstream only
    /// times out. Unknown (another OS) reads true.
    pub ipv6_route: bool,
    pub items: Vec<UpstreamPreset>,
}

/// The build identity (REQ: OPS-004, ADR-046): the same on every architecture of one commit.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BuildInfo {
    /// `0.1.0` (release), `0.1.0-edge.47` (main build), or `0.1.0-dev` (local build, read by peers as 0.1.0).
    pub version: String,
    /// Short commit SHA.
    pub commit: String,
    /// Build date (RFC 3339), or `unknown`.
    pub date: String,
    /// `stable`, `edge`, or `dev`.
    pub channel: String,
    /// Rust target, e.g. `aarch64-unknown-linux-musl`.
    pub target: String,
    /// `native`, `container`, or `helm`: decides how to update.
    pub install: String,
}

/// Update status from the signed release index (ADR-046).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    /// `up_to_date`, `available`, `newer` (this build is newer than the index, e.g. dev),
    /// `off` (`[updates] check = false`), or `unknown` (not checked yet, or failing).
    pub state: String,
    /// The newest version on this channel, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    /// Its commit and date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_date: Option<String>,
    /// Release notes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes_url: Option<String>,
    /// When the index was last read successfully (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_unix_seconds: Option<u64>,
    /// Why the last check failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// How to update this install, step by step.
    pub how: String,
}

/// This node's cluster membership and the peers it holds a stream with.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterInfo {
    pub cluster_id: String,
    /// The name given at `wrendns cluster init`.
    #[schema(example = "home")]
    pub name: String,
    /// This node's ID (from its key; stable across restarts).
    #[schema(example = "3f9c2a71d04b8e15")]
    pub node_id: String,
    #[schema(example = "home-pi")]
    pub site: String,
    /// Whether this node holds the cluster CA (the first node, until promotion arrives).
    pub primary: bool,
    /// When this node's cluster certificate expires (RFC 3339).
    pub cert_expires_at: String,
    /// The configuration version this node published (primary) or applied (replica), CLU-003.
    pub config_seq: u64,
    /// When that version was created on the primary (RFC 3339).
    pub config_created_at: Option<String>,
    /// When this node applied it (RFC 3339).
    pub config_applied_at: Option<String>,
    /// Blobs fetched for the last applied version (replicas).
    pub last_sync_fetched: u64,
    /// Fetch + apply time of the last sync, in milliseconds.
    pub last_sync_ms: u64,
    /// The last replication error, until the next success.
    pub sync_error: Option<String>,
    /// Peers this node has heard from since it started.
    pub peers: Vec<ClusterPeer>,
}

/// A peer node, as last heard over the cluster channel.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterPeer {
    pub node_id: String,
    pub site: String,
    pub version: String,
    /// Heard from within the last three heartbeats (15 s).
    pub up: bool,
    pub primary: bool,
    pub last_seen_seconds_ago: u64,
    /// `inbound` (it connected to us) or `outbound`.
    pub via: String,
    /// The configuration version the peer reports as applied (the primary: published).
    pub config_seq: u64,
}

/// Evidence that client IPs appear masked.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MaskedClients {
    /// Share of the window's queries sent by `sources`, in percent (> 90).
    #[schema(example = 97)]
    pub share_percent: u32,
    /// The infrastructure addresses that sent them, heaviest first (at most 3).
    #[schema(example = json!(["10.42.0.1"]))]
    pub sources: Vec<String>,
    /// Queries in the 10-minute window examined.
    pub queries: u64,
    /// Start of that window (RFC 3339).
    pub window_start: String,
}

/// Time-bucket size for [`TimeseriesParams`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Step {
    /// 1-second buckets (the last 15 minutes are kept).
    Second,
    /// 1-minute buckets: 48 hours in memory, 7 days in the rollup database.
    Minute,
    /// 1-hour buckets from the rollup database (400 days).
    Hour,
    /// 1-day buckets from the rollup database (kept forever).
    Day,
}

/// Which nodes' data an analytics call reads (`spec/07` §1, `spec/12` §6, AGT-011). On a
/// standalone node, `cluster` and `node:local` both mean this node.
#[derive(Debug, Clone, Default, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct ScopeParam {
    /// `cluster` (default, every node), `site:<name>`, `node:<name or ID>`, or `node:local`
    /// (this node). Federated reads list nodes that didn't answer in `missingNodes`.
    #[param(example = "cluster")]
    pub scope: Option<String>,
}

/// Query parameter `limit` alone.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LimitParam {
    /// At most this many (1–500, default 50).
    pub limit: Option<usize>,
}

/// Counts for one time bucket.
#[derive(Debug, Clone, Default, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeBucket {
    /// Bucket start, Unix seconds.
    pub start_unix_seconds: u64,
    /// Queries in the bucket.
    pub total: u32,
    /// By status (`cached`, `forwarded`, `blocked`, ...).
    pub by_status: BTreeMap<String, u32>,
    /// By query type (`A`, `AAAA`, ..., `other`).
    pub by_qtype: BTreeMap<String, u32>,
    /// By response code (`NOERROR`, `NXDOMAIN`, ...).
    pub by_rcode: BTreeMap<String, u32>,
    /// Upstream exchanges, and how many failed.
    pub upstream_queries: u32,
    pub upstream_failures: u32,
    /// Queries by the client's group (ADR-050). Empty for buckets read from rollups.
    #[serde(default)]
    pub by_group: BTreeMap<String, u32>,
    /// Blocked queries by group.
    #[serde(default)]
    pub blocked_by_group: BTreeMap<String, u32>,
    /// REQ: OBS-016 — answered queries slower than the latency objective's threshold
    /// (`[slo] latency_ms`). 0 in buckets stored by builds before 0.4.
    #[serde(default)]
    pub slow: u32,
    /// REQ: OBS-027 — SERVFAIL answers by status (`refreshed`, `forwarded`, ...). Empty in
    /// buckets without any, or stored by builds before 0.5.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub servfail_by_status: BTreeMap<String, u32>,
    /// REQ: OBS-027 — slow answers (see `slow`) by status.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub slow_by_status: BTreeMap<String, u32>,
    /// REQ: OBS-027 — SERVFAIL answers by the upstream that gave them (`none`: no upstream on
    /// the answer, such as one served from the cache).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub servfail_by_upstream: BTreeMap<String, u32>,
    /// REQ: OBS-027 — slow answers by upstream.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub slow_by_upstream: BTreeMap<String, u32>,
    /// REQ: OBS-027 — slow answers by response code.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub slow_by_rcode: BTreeMap<String, u32>,
    /// REQ: OBS-030 — answers per latency bucket (the `wrendns_query_duration_seconds` bounds
    /// and the overflow, 17 counts) by path (`cache`, `upstream`, `local`, `synthesized`) and
    /// by upstream (`upstream:<name>`). Minute and longer buckets; empty before 0.5.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub latency_hist: BTreeMap<String, Vec<u32>>,
    /// REQ: OBS-032 — the query flow's joint counts: `gs:<group>/<status>` (every answer),
    /// `su:<status>/<upstream>` and `ur:<upstream>/<rcode>` (answers an upstream was asked for),
    /// `sr:<status>/<rcode>` (the rest with a response code). Minute and longer buckets; empty
    /// before 0.5.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub flow: BTreeMap<String, u32>,
}

/// Query parameters for `GET /stats/timeseries`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TimeseriesParams {
    /// Start: RFC 3339 or relative (`-1h`). Default: 5 minutes ago (second steps), 1 hour
    /// (minute), 7 days (hour), or 90 days (day).
    pub from: Option<String>,
    /// End: RFC 3339 or relative. Default: now.
    pub to: Option<String>,
    /// Bucket size. Default: `minute`.
    pub step: Option<Step>,
    /// `cluster` (default, every node), `site:<name>`, `node:<name or ID>`, or `node:local`
    /// (this node). Federated reads list nodes that didn't answer in `missingNodes`.
    pub scope: Option<String>,
}

/// Totals over a time range.
#[derive(Debug, Clone, Default, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub from_unix_seconds: u64,
    pub to_unix_seconds: u64,
    pub queries: u64,
    pub blocked: u64,
    /// Blocked share of all queries, 0–100.
    pub blocked_percent: f64,
    /// Answered from cache (fresh, refreshed in the background, or stale).
    pub cached: u64,
    /// REQ: DNS-007 — of `cached`, answers whose entry had expired and was answered at once
    /// while it was refreshed in the background (`[cache] stale_answer_client_timeout_ms = 0`).
    #[serde(default)]
    pub refreshed: u64,
    /// Cache share of answered queries that weren't blocked or local, 0–100.
    pub cache_hit_percent: f64,
    pub forwarded: u64,
    pub nxdomain: u64,
    pub servfail: u64,
    /// Distinct clients seen in the hours the range overlaps (REQ: OBS-004): this hour's list,
    /// the previous hour's, and each stored hour's busiest 100, so ranges past the last two
    /// hours undercount on networks with more than 100 devices an hour.
    pub active_clients: u64,
    /// Latency percentiles this hour, by answer path (`cache`, `upstream`, ...).
    pub latency: Vec<LatencyRow>,
    /// Cluster nodes that couldn't be read (CLU-002).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// Query parameters for `GET /stats/summary`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SummaryParams {
    /// Start: RFC 3339 or relative (`-24h`, `-30d`). Default: 24 hours ago. Ranges over
    /// 48 hours are summed from hourly rollups.
    pub from: Option<String>,
    /// End. Default: now.
    pub to: Option<String>,
    /// `cluster` (default, every node), `site:<name>`, `node:<name or ID>`, or `node:local`
    /// (this node). Federated reads list nodes that didn't answer in `missingNodes`.
    pub scope: Option<String>,
}

/// What a top-K list ranks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TopKind {
    /// Most queried names.
    Domains,
    /// Most blocked names.
    Blocked,
    /// Names most often answered NXDOMAIN.
    Nxdomain,
    /// Most active clients.
    Clients,
    /// REQ: OBS-037 — most queried internal names (the cluster domain, reverse lookups of
    /// private addresses, `[telemetry] internal_names`), which `domains` and `nxdomain`
    /// leave out.
    Internal,
}

/// Which hour a top-K or latency call reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Hour {
    /// The hour in progress.
    #[default]
    Current,
    /// The last complete hour.
    Previous,
}

/// Which window a top list reads: an hour, or (clients only) the last 60 minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TopHour {
    /// The hour in progress.
    #[default]
    Current,
    /// The last complete hour.
    Previous,
    /// REQ: API-005 (ADR-158) — the last hour whatever the clock hour: 60–65 minutes up to
    /// now, in whole 5-minute slots. `kind=clients` only; counts are exact.
    Rolling,
}

impl TopHour {
    /// The clock hour this reads, `None` for `rolling`.
    pub fn hour(self) -> Option<Hour> {
        match self {
            Self::Current => Some(Hour::Current),
            Self::Previous => Some(Hour::Previous),
            Self::Rolling => None,
        }
    }
}

/// Query parameters for `GET /stats/top`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TopParams {
    /// Which list: `domains`, `blocked`, `nxdomain`, or `clients`.
    pub kind: TopKind,
    /// Items to return (1–100, default 10).
    pub limit: Option<usize>,
    /// `current` (default), `previous`, or `rolling` (the last hour, 60–65 minutes;
    /// `kind=clients` only).
    pub hour: Option<TopHour>,
    /// Only this client's domains (an IP address; `kind=domains` only).
    pub client: Option<String>,
    /// Only this group's queries (a group name; not with `client`, not for `nxdomain`).
    pub group: Option<String>,
    /// `cluster` (default, every node), `site:<name>`, `node:<name or ID>`, or `node:local`
    /// (this node). Federated reads list nodes that didn't answer in `missingNodes`.
    pub scope: Option<String>,
    /// A window instead of one hour (REQ: OBS-004): a relative offset such as `-24h`, or RFC
    /// 3339. Every hour the window overlaps counts whole: the stored hours (400 days) plus the
    /// current one. Not with `hour`, `client`, or `group`.
    pub from: Option<String>,
    /// The window's end (default: now). Only with `from`.
    pub to: Option<String>,
}

/// One ranked item. Counts come from a Space-Saving sketch: the true count lies in
/// `[count - errorBound, count]`.
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopItem {
    /// Domain name or client address.
    pub key: String,
    /// The configured device name, for clients that have one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub count: u64,
    pub error_bound: u64,
    /// For clients: the groups whose settings apply to it, highest priority first (its
    /// device's groups, else its network's group, else the default; ADR-050).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// For clients: how its queries were answered (REQ: OBS-004). Counts cover the queries
    /// since the client entered the list, `count - errorBound` of them; the rest of `count`
    /// is other statuses (local, special, refused, …) and that error bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_status: Option<ClientStatusCounts>,
}

/// A top-list client's queries by how they were answered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientStatusCounts {
    pub blocked: u64,
    /// From the cache, including stale and refreshed answers.
    pub cached: u64,
    /// Answered by an upstream.
    pub forwarded: u64,
}

/// What `GET /stats/latency` groups by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LatencyBy {
    /// Answer path (`cache`, `upstream`, `local`, `synthesized`) and transport.
    Path,
    /// Query type.
    Qtype,
    /// Upstream server (from upstream exchanges, including prefetches).
    Upstream,
    /// Time spent waiting for upstreams, per client query.
    Stage,
}

/// Query parameters for `GET /stats/latency`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LatencyParams {
    /// What to break latency down by: `stage`, `upstream`, `client`, or `qtype`.
    pub by: LatencyBy,
    /// Default: `current`.
    pub hour: Option<Hour>,
    /// `cluster` (default, every node), `site:<name>`, `node:<name or ID>`, or `node:local`
    /// (this node). Federated reads list nodes that didn't answer in `missingNodes`.
    pub scope: Option<String>,
}

/// Latency percentiles for one key (HDR histogram, 2 significant digits).
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencyRow {
    /// What the row is for (`cache/udp`, `AAAA`, `quad9-tls-1`, `upstream`).
    pub key: String,
    pub count: u64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub p999_ms: f64,
    pub max_ms: f64,
}

/// How `name` in [`QueryParams`] is matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum NameMatch {
    /// The name contains the text (default).
    #[default]
    Substring,
    /// Exactly this name.
    Exact,
    /// This name or any name below it.
    Suffix,
    /// `*` and `?` wildcards over the whole name.
    Glob,
    /// A regular expression over the whole name (no backreferences or lookaround).
    Regex,
}

/// Query parameters for `GET /queries`. Filters combine with AND.
#[derive(Debug, Clone, Default, Deserialize, IntoParams, Serialize)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct QueryParams {
    /// Name to look for; see `match`.
    pub name: Option<String>,
    /// How to match `name`. Default: `substring`.
    #[serde(rename = "match")]
    #[param(rename = "match")]
    pub name_match: Option<NameMatch>,
    /// REQ: OBS-003 (ADR-171) — keep the rows whose name does NOT match `name` and `match`:
    /// does not contain, is not, is not under, doesn't match the wildcard or the regex. Needs
    /// `name`. Default: false.
    pub name_not: Option<bool>,
    /// Client IP address, or several, comma-separated (REQ: OBS-003, ADR-1013): addresses,
    /// `hostname:<label>` (the addresses a router gave that name now) and Kubernetes workloads
    /// (`namespace/kind/name`). At most 100 entries and 256 addresses; `clientTruncated` says
    /// when a cap cut the set.
    pub client: Option<String>,
    /// Keep the rows from every client except `client` (all of them, when several). Needs `client`. Default: false.
    pub client_not: Option<bool>,
    /// Statuses, comma-separated (`blocked,forwarded`).
    pub status: Option<String>,
    /// Keep the rows whose status is none of `status` (`status=blocked&statusNot=true`: every
    /// query that was not blocked). Needs `status`. Default: false.
    pub status_not: Option<bool>,
    /// Query types, comma-separated (`A,AAAA`).
    pub qtype: Option<String>,
    /// Keep the rows whose type is none of `qtype`. Needs `qtype`. Default: false.
    pub qtype_not: Option<bool>,
    /// Response codes, comma-separated (`NXDOMAIN,SERVFAIL`).
    pub rcode: Option<String>,
    /// Keep the rows whose response code is none of `rcode` (queries that got no response code
    /// are kept). Needs `rcode`. Default: false.
    pub rcode_not: Option<bool>,
    /// Upstream ID (from `/upstreams`): the forwarded queries it answered. Coalesced queries
    /// name the upstream that answered for all of them.
    pub upstream: Option<u16>,
    /// Only queries from devices in this group (a group name, ADR-050).
    pub group: Option<String>,
    /// Only queries that took at least this long.
    pub min_latency_ms: Option<u32>,
    /// Start: RFC 3339 or relative (`-1h`). Default: no limit.
    pub from: Option<String>,
    /// End. Default: now.
    pub to: Option<String>,
    /// Rows per page (1–1000, default 100).
    pub limit: Option<usize>,
    /// Continue after a previous page (`nextCursor` from it).
    pub cursor: Option<String>,
    /// `cluster` (default, every node), `site:<name>`, `node:<name or ID>`, or `node:local`
    /// (this node). Federated reads list nodes that didn't answer in `missingNodes`.
    pub scope: Option<String>,
    /// REQ: OBS-017 (ADR-110) — the query a trace ID names (32 hex digits, from an exemplar
    /// on `/metrics` or an exported trace). Replaces `from` and `to`.
    pub trace: Option<String>,
}

impl QueryParams {
    /// REQ: OBS-003 (ADR-171) — whether any filter is negated. A negated search goes to peers
    /// as a read that an older node doesn't know (it would ignore the flags and answer rows
    /// that were not negated).
    pub fn negates(&self) -> bool {
        [
            self.name_not,
            self.client_not,
            self.status_not,
            self.qtype_not,
            self.rcode_not,
        ]
        .contains(&Some(true))
    }
}

/// One logged query.
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryRow {
    /// When the query arrived (RFC 3339, milliseconds).
    pub time: String,
    pub ts_unix_micros: u64,
    /// Client address.
    pub client: String,
    /// The configured device name, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// The client's primary group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    pub name: String,
    pub qtype: String,
    pub status: String,
    /// Response code, or null when nothing was sent.
    pub rcode: Option<String>,
    pub proto: String,
    /// The list whose rule blocked or allowed the query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list: Option<String>,
    /// `domain`, `modifier`, `regex`, `cname`, or `allow`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub total_ms: f64,
    pub upstream_ms: f64,
    pub response_bytes: u16,
    pub answers: u16,
    /// The node that answered it (federated reads: its site).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
}

/// A page of query-log rows, newest first.
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryPage {
    pub items: Vec<QueryRow>,
    /// Pass as `cursor` to get older rows; absent when there are none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// How much of the log this page looked at.
    pub scanned: ScanStats,
    /// Cluster nodes that couldn't be read (CLU-002: partial results, never a hang).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
    /// REQ: FLT-017 — `client` named a Kubernetes workload that held more than 64 pod
    /// addresses in the window: only the newest 64 were searched.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub client_truncated: bool,
}

#[derive(Debug, Clone, Default, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStats {
    pub segments: usize,
    pub blocks_read: usize,
    pub blocks_total: usize,
    pub rows_scanned: usize,
}

/// Query parameters for `GET /explain`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExplainParams {
    /// The name to explain.
    #[param(example = "ads.example.com")]
    pub name: String,
    /// The client's IP address. Default: 127.0.0.1.
    pub client: Option<String>,
    /// Query type. Default: `A`.
    pub qtype: Option<String>,
    /// The client's MAC address (default: from the neighbor table).
    pub mac: Option<String>,
}

/// Why a name is or isn't blocked for a client, and where it would go (FLT-013).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Explanation {
    pub name: String,
    pub qtype: String,
    pub client: ExplainClient,
    /// `refused`, `special`, `local`, `blocked`, `allowed`, or `resolved`.
    pub outcome: String,
    /// REQ: DNS-019 (T24.12, ADR-914) — for `special`, the special-name rule that answered:
    /// `private_relay`, `single_label`, `resolver_arpa`, `ddr`, `firefox_canary`, `private_ptr`,
    /// `chaos`, or `localhost`. A rule's name, not a field of `[special]`: the UI maps it to the
    /// switch that controls it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub special: Option<String>,
    /// One sentence for people.
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<ExplainBlock>,
    /// Blocking is paused for this client until then (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused_until_unix_seconds: Option<u64>,
    /// Every matching rule in precedence order; absent until a filter is loaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<ExplainFilter>,
    /// Where a forwarded query goes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<ExplainRoute>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainClient {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// The configured device it was recognized as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// `client_id`, `edns_mac`, `neighbor_mac`, `kubernetes`, `router_name`, `ip`, `cidr`, or `default`.
    pub identified_by: String,
    /// REQ: FLT-006, API-010 (T24.30, ADR-996) — the key it matched on, written as a
    /// `[[client]] match` is (`id:kids`, a MAC, an address, a network, `hostname:tv`), or the
    /// workload's name. Absent for the `default` group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_key: Option<String>,
    /// The group whose settings apply (the first of `groups`).
    pub group: String,
    /// Where that group came from: `device`, `network`, `router_name`, `kubernetes`, `default`.
    pub group_from: String,
    /// The network or router name that gave the group, when it isn't the device's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_key: Option<String>,
    /// Highest priority first.
    pub groups: Vec<String>,
    /// REQ: FLT-017 — the Kubernetes workload a pod address belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<ExplainWorkload>,
}

/// REQ: FLT-017 — a pod address's workload in an explanation.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainWorkload {
    #[schema(example = "media/deploy/jellyfin")]
    pub name: String,
    #[schema(example = "jellyfin-7d9f4c8b6-x2k1q")]
    pub pod: String,
    /// `pod_label`, `namespace_label`, `map`, `default_group`, or `none`.
    pub group_from: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainBlock {
    pub list: String,
    /// REQ: FLT-901 — the category (or categories) a `cat-` list stands for, for example "Adult
    /// content"; absent for any other list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// `null_ip`, `nxdomain`, `nodata`, `refused`, or `custom_ip`.
    pub mode: String,
    pub ttl_seconds: u32,
    pub ede_code: u16,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainFilter {
    pub snapshot: Option<u64>,
    pub rules: Vec<ExplainRule>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainRule {
    pub list: String,
    /// `important_allow`, `important_block`, `allow`, or `block`.
    pub tier: String,
    /// `domain`, `modifier`, or `regex`.
    pub kind: String,
    /// `subtree`, `exact`, or `subdomains`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The listed name that matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The client's groups use this list.
    pub enabled: bool,
    /// REQ: OBS-018 — the list is in shadow mode: it never blocks, its would-be blocks are
    /// counted.
    #[serde(default)]
    pub shadow: bool,
    /// This rule decides the query.
    pub winner: bool,
    /// Where the rule is in the list.
    pub lines: Vec<ExplainLine>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainLine {
    pub line: u32,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainRoute {
    /// Upstream group.
    pub group: String,
    /// An explicit route matched (not just the default group).
    pub routed: bool,
}

fn auto_format() -> String {
    "auto".to_owned()
}

/// A filter list and its download state.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListInfo {
    pub name: String,
    /// `block` or `allow`.
    pub kind: String,
    /// REQ: FLT-906 (T40.9) - how the source is read: `auto` (each line's syntax is detected) or
    /// `rpz` (a response policy zone).
    #[serde(default = "auto_format")]
    pub format: String,
    pub enabled: bool,
    /// REQ: OBS-018 — `enforce`, or `shadow` (compiled, never blocks; its would-be blocks are
    /// at `GET /analytics/shadow-lists`).
    pub mode: String,
    /// URL, file path, or `inline`.
    pub source: String,
    /// `ok`, `failed`, or `pending` (not downloaded yet).
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub bytes: u64,
    pub lines: u64,
    /// Names this list contributes to the active snapshot.
    pub entries: u64,
    /// REQ: OBS-009 (T7.14) — names no other list has (what removing it would lose).
    pub unique: u64,
    /// REQ: FLT-003 (review 02-08) — regex rules this list ships that the active snapshot
    /// leaves out: over `[filter] max_regexes`, too large for the matcher, or not valid.
    pub regex_skipped: u64,
    /// REQ: FLT-906 (T40.9) - lines (records, for an RPZ) it holds that are valid but not applied:
    /// cosmetic rules, URL rules, and an RPZ's response-IP, NSDNAME and NSIP triggers.
    #[serde(default)]
    pub unsupported: u64,
    /// Queries it blocked (or allowed, for an allow list) since each node started; in a
    /// cluster, every node's added up.
    pub hits: u64,
    /// Lists it shares names with, most shared first.
    pub overlap: Vec<ListShare>,
    /// REQ: FLT-004 (T24.28, ADR-992) - modifier rules and regexes it ships. The overlap counts
    /// names only, so these are never shown covered by another list.
    #[serde(default)]
    pub rules: u64,
    /// Last download attempt (Unix seconds), whatever its outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked_unix_seconds: Option<u64>,
    /// REQ: FLT-004 — last time the source was confirmed current: a download, a `304 Not
    /// Modified`, or the same content again (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_unix_seconds: Option<u64>,
    /// Last time the content changed (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_changed_unix_seconds: Option<u64>,
    /// REQ: FLT-004 — a refresh asked for (`POST /api/v1/lists/refresh`) is waiting to start
    /// or downloading this list now (also true during a scheduled download). It clears when
    /// the download ends; the snapshot follows within seconds if the content changed.
    #[serde(default)]
    pub refreshing: bool,
    /// REQ: OBS-023 — days since a URL list's content last changed, when that's longer than its
    /// `stale_after_days`: the source may be abandoned while still answering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_days: Option<u64>,
    /// REQ: FLT-901 (T24.29) — the categories that use this list. A list with owners is a category
    /// list: it takes its source from the catalog and can be refreshed and put in shadow mode, not
    /// edited or deleted (409 `owned_by_category`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owners: Vec<ListOwner>,
}

/// REQ: FLT-901 — a category that uses a list.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListOwner {
    /// The category's ID (`adult`).
    pub id: String,
    /// Its name (`Adult content`).
    pub name: String,
}

/// REQ: FLT-004 — which lists to download again now (`POST /api/v1/lists/refresh`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListsRefreshRequest {
    /// Only these lists, by name (as `GET /api/v1/lists` lists them). Absent or empty: every
    /// enabled list.
    #[schema(example = json!(["hagezi-pro"]))]
    #[serde(default)]
    pub names: Option<Vec<String>>,
}

/// A named list a refresh leaves out.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListRefreshSkip {
    pub name: String,
    /// `disabled` (the list is off: it's never downloaded until it's turned on).
    pub reason: String,
}

/// REQ: FLT-004 — what a refresh queued (`202 Accepted`), or with `dryRun`, would queue.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListsRefreshResult {
    /// True when nothing was queued (`?dryRun=true`): `queued` is what would be.
    pub dry_run: bool,
    /// The lists queued for download now (or that would be), in configuration order.
    pub queued: Vec<String>,
    /// Named lists left out, and why.
    pub skipped: Vec<ListRefreshSkip>,
    /// Of `queued`, the lists downloading already: each is downloaded once more when that
    /// download ends.
    pub already_refreshing: Vec<String>,
    /// The node that downloads and compiles the lists: this one, or (on a cluster replica) the
    /// primary the request was forwarded to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// What happens next, in a sentence.
    pub note: String,
}

/// A client group.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
// Independent per-group switches as the config has them; an enum set would only obscure the JSON.
#[allow(clippy::struct_excessive_bools)]
pub struct GroupInfo {
    pub name: String,
    pub priority: i32,
    /// Lists this group uses; null means every enabled list.
    pub lists: Option<Vec<String>>,
    /// `null_ip`, `nxdomain`, `nodata`, `refused`, or `custom_ip`.
    pub block_mode: String,
    pub block_ttl_seconds: u32,
    /// Blocking is paused for this group until then (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused_until_unix_seconds: Option<u64>,
    /// Networks (CIDRs) whose devices belong to this group (ADR-050).
    pub networks: Vec<String>,
    /// `#rrggbb` for charts and chips (configured, or a stable pick).
    pub color: String,
    /// Queries from the group's devices over the last 24 hours.
    pub queries_24h: u64,
    /// Of those, blocked.
    pub blocked_24h: u64,
    /// Devices seen in the group this hour.
    pub devices_this_hour: u64,
    /// REQ: FLT-012 (T7.9) — services this group blocks (IDs from `GET /api/v1/services`).
    pub blocked_services: Vec<String>,
    /// REQ: FLT-010 (T7.10) — the group's schedules, and which of them are on now.
    pub schedules: Vec<String>,
    pub schedules_on: Vec<String>,
    /// REQ: FLT-011 (T7.11) — safe search, and YouTube's restriction: `strict`, `moderate`,
    /// or `off` (absent when safe search is off).
    pub safe_search: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub youtube_restrict: Option<String>,
    /// REQ: FLT-014 (T7.20) — private addresses in public answers are blocked (DNS
    /// rebinding protection), and the networks whose answers are filtered.
    pub rebinding_protection: bool,
    pub block_answer_ips: Vec<String>,
    /// REQ: FLT-015 (T7.20) — names answered with a fixed address or name.
    pub rewrites: Vec<RewriteInfo>,
    /// REQ: DNS-016 (T7.21) — AAAA answers synthesized for IPv4-only names (DNS64), and the
    /// prefix (`64:ff9b::/96` unless set).
    pub dns64: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns64_prefix: Option<String>,
    /// REQ: FLT-016 (T12.5) — AAAA questions get no data (the group's devices use IPv4).
    pub filter_aaaa: bool,
    /// REQ: UPS-007 (T9.25) — the upstream group this group's queries go to (absent: `default`,
    /// or wherever `[[route]]` entries send them).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstreams: Option<String>,
    /// REQ: FLT-902 (T24.29) — what the group filters by category (absent: nothing set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<crate::categories_api::GroupContentInfo>,
    /// REQ: FLT-902 — the engines safe search covers (empty with `safeSearch`: every engine).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub safe_search_engines: Vec<String>,
    /// REQ: FLT-902 — who the group applies to: its networks, router names and devices, for the
    /// profile list's Source column.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<crate::categories_api::ProfileSource>,
    /// REQ: FLT-902 — "Off", "Basic", "Enhanced (3 of 21)" and "Ad block", for the Filter Scope column.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub filter_scope: String,
}

/// A group's rewrite: `domain` (or `*.domain`) answered with `answer`.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RewriteInfo {
    #[schema(example = "nas.example.com")]
    pub domain: String,
    /// An address, or a name (answered as a CNAME).
    #[schema(example = "192.168.1.20")]
    pub answer: String,
}

/// REQ: DNS-018 (T7.22) — an authoritative zone from `[[zone]]`.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ZoneInfo {
    /// The apex.
    #[schema(example = "home.example.com")]
    pub name: String,
    /// Groups that see it (split horizon); empty: everyone.
    pub groups: Vec<String>,
    /// Records loaded (from the file and inline).
    pub records: u64,
    /// The zone file, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// TTL of its NXDOMAIN and no-data answers.
    pub negative_ttl_seconds: u32,
    /// REQ: DNS-010 (T27.7) — `file` (read-only here) or `api` (made in the UI or API).
    pub source: String,
    /// REQ: DNS-010 (T27.7) — an API zone's records, to edit them; empty for a file zone (its
    /// records are read-only here, and only the count shows).
    pub values: Vec<ZoneRecordInput>,
}

/// REQ: DNS-010 (T27.7) — one record of an API zone: the owner name, its type and value, and
/// an optional TTL.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZoneRecordInput {
    #[schema(example = "printer.home.example.com")]
    pub name: String,
    /// `A`, `AAAA`, `CNAME`, `PTR`, `TXT`, `MX` or `SRV`.
    #[serde(rename = "type")]
    #[schema(example = "A")]
    pub rtype: String,
    #[schema(example = "192.168.1.20")]
    pub value: String,
    /// TTL in seconds (default: `[local] default_ttl`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

/// REQ: DNS-010 (T27.7) — an authoritative zone made through the API or UI
/// (`PUT /api/v1/zones/{name}`). The zone file is set in the configuration file (guarded, T27.17),
/// so a body that names one is refused.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZoneInput {
    /// Groups that see the zone (split horizon); empty: everyone.
    #[serde(default)]
    pub groups: Vec<String>,
    /// TTL of its NXDOMAIN and no-data answers (default 300).
    #[serde(default)]
    pub negative_ttl_seconds: Option<u32>,
    /// The zone's records: names under the zone.
    #[serde(default)]
    pub records: Vec<ZoneRecordInput>,
}

/// REQ: DSC-913 (T36.10a, ADR-1081, ADR-1096) - a location to create or replace
/// (`PUT /api/v1/locations/{slug}`): a part of the network with a device-name subtree of its own.
/// Fields left out take their defaults (`visibility` shared, `flatNames` on).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocationInput {
    /// Display name, at most 64 characters (untrusted text).
    #[serde(default)]
    #[schema(example = "Home")]
    pub label: Option<String>,
    /// The networks that belong to it: CIDRs, or `vlan:<id>` (1 to 4094) resolved through the
    /// router network reads and this node's own VLAN interfaces. At least one; no CIDR may
    /// overlap another location's.
    #[schema(example = json!(["192.0.2.0/24", "vlan:30"]))]
    pub networks: Vec<String>,
    /// The nodes that serve the location, by node name; empty: every node.
    #[serde(default)]
    pub nodes: Vec<String>,
    /// The parent domain (default: `[local] device_domain`).
    #[serde(default)]
    #[schema(example = "example.net")]
    pub domain: Option<String>,
    /// `shared` (default: every client `[access]` allows sees the names) or `private` (only a
    /// client whose address is in the location's networks does).
    #[serde(default)]
    #[schema(example = "shared")]
    pub visibility: Option<String>,
    /// Keep answering the old `<device>.<device_domain>` names for the location's devices
    /// (default on).
    #[serde(default)]
    pub flat_names: Option<bool>,
}

/// REQ: DSC-909 (T36.10a) - one entry of a location's `networks`, with what it resolved to.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LocationNetworkInfo {
    /// As written: a CIDR or `vlan:<id>`.
    pub entry: String,
    /// The networks it covers now: the CIDR itself, or the subnets the routers and this node's
    /// VLAN interfaces report for the VLAN.
    pub resolved: Vec<String>,
    /// `no network reported` for a VLAN nothing reports; `conflict` for a network two locations
    /// claim (neither applies until it is fixed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// REQ: DSC-909, DSC-910, DSC-916 (T36.10a) - a device and the names it answers as.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LocationDevice {
    /// The name it answers as (`nas.home.example.net`); its PTR is the same name.
    pub name: String,
    pub address: String,
    /// The IPv6 addresses that answer AAAA and PTR for it.
    #[serde(default)]
    pub addresses_v6: Vec<String>,
    /// The old flat name that still answers for it (A and AAAA, no PTR), while `flatNames` is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flat_name: Option<String>,
    /// The location comes from the device's `[[client]] location`, not its address.
    pub pinned: bool,
}

/// REQ: DSC-909, DSC-916 (T36.10a) - a name two devices wanted: the better-ranked one (ADR-901)
/// kept it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LocationCollision {
    pub name: String,
    /// The name is a flat alias: the device that lost it keeps its location name.
    pub flat: bool,
    /// The address of the device that kept the name; absent when the name is a location's own
    /// subtree (the location wins).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept_address: Option<String>,
    /// The address of the device that did not.
    pub lost_address: String,
    /// The slug of the location the losing device is in, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost_location: Option<String>,
}

/// REQ: DSC-913 (T36.10a) - a location, as the node composes names for it now.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LocationInfo {
    pub slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// `file` (read-only here) or `api`.
    #[schema(example = "api")]
    pub source: String,
    pub networks: Vec<LocationNetworkInfo>,
    pub nodes: Vec<String>,
    /// The parent domain in effect; its names are `<device>.<slug>.<domain>`.
    pub domain: String,
    /// The domain this location sets itself; absent when it follows `[local] device_domain`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_domain: Option<String>,
    /// `shared` or `private`.
    pub visibility: String,
    pub flat_names: bool,
    /// How many queries the flat names answered over the last 7 days (this node; a restart starts
    /// the count again).
    pub flat_name_uses_7d: u64,
    /// The devices that answer under it, by name.
    pub devices: Vec<LocationDevice>,
    /// Every name that collided in this location or with its devices' flat names, each with its
    /// ADR-901 winner.
    pub collisions: Vec<LocationCollision>,
    /// True while the start-up hold keeps this location out of the answers the node serves (as
    /// `held` on the list): what is shown is configured, its devices and collisions are not
    /// resolved until the hold ends.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
    /// Why it is held; set with `held`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_reason: Option<String>,
}

/// REQ: DSC-913 (T36.10a) - the locations (`GET /api/v1/locations`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LocationList {
    pub items: Vec<LocationInfo>,
    /// Networks two locations claim at once (neither applies until it is fixed), as sentences.
    pub conflicts: Vec<String>,
    /// Collisions of devices on no location's network.
    pub collisions: Vec<LocationCollision>,
    /// True while the start-up hold keeps the locations out of the answers this node serves
    /// (a cluster member's build does not know them yet): the list is what is configured, and
    /// the devices and collisions are not resolved until the hold ends.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
    /// Why they are held (the member that does not know them, or that the members are not heard
    /// from yet); set with `held`. Also set, with `held` false, after a node that held entries
    /// stopped leading: they were not published, and a config-file-only entry is not carried to
    /// the new primary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_reason: Option<String>,
}

/// REQ: CLD-904 (T36.10b, ADR-1084, ADR-1104) - one DNS provider as the API shows it: its settings
/// (the credential as a stored secret's name, never a value), where it comes from, and its state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsProviderEntry {
    pub name: String,
    /// `azure_dns`, `cloudflare`, `route53`, `rfc2136` or `delegated`.
    pub kind: String,
    /// The zone the provider serves.
    pub zone: String,
    /// `file` (the configuration files define it; read-only here) or `api`.
    pub source: String,
    /// The settings in effect: the `[[dns_provider]]` fields as JSON, with `credential_ref` the
    /// name of a stored secret.
    pub definition: serde_json::Value,
    /// Whether it only computes changes and records them (`dry_run`).
    pub dry_run: bool,
    /// The name of the stored secret that holds the credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_secret: Option<String>,
    /// Whether this node stores a secret by that name (the value is never shown).
    pub credential_present: bool,
    /// `not_used`: this build has no provider code for the entry (every real kind has code; only a
    /// test-only entry reads this);
    /// `dry_run`: it computes and records changes and sends none, until its first successful test;
    /// `ready`: the first test passed and writes are sent.
    pub state: String,
    /// The sentence that goes with `state`.
    pub detail: String,
    /// True while the start-up hold keeps the entry out of what this node serves and publishes (a
    /// cluster member's build does not know DNS providers yet).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
    /// A `delegated` entry only: the record to create at its DNS host and whether this node has
    /// verified it (T36.10b step b5, ADR-1115).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<DnsProviderDelegation>,
}

/// REQ: CLD-904 (T36.10b step b5, ADR-1115) - the delegation of a `delegated` provider: the
/// provider that holds the validation zone and the CNAME records the operator creates by hand at
/// the DNS host, each with this node's latest check.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsProviderDelegation {
    /// The provider entry that takes the challenge TXT (`delegated_to`).
    pub validation_provider: String,
    /// That provider's zone (absent when the entry it names is missing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_zone: Option<String>,
    /// The CNAME records to create, one per location in the zone; one template with `<slug>` when
    /// no location is in the zone yet.
    pub records: Vec<DnsProviderDelegationRecord>,
}

/// REQ: CLD-904 (T36.10b step b5) - one `_acme-challenge` CNAME to create at the DNS host, and
/// whether this node has verified it at the zone's authoritative servers.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsProviderDelegationRecord {
    /// The location it is for; absent for the template shown before any location uses the zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// The name to create the CNAME at: `_acme-challenge.<slug>.<domain>` (no trailing dot).
    pub name: String,
    /// What it points to: `<slug>.<validation zone>` (no trailing dot).
    pub target: String,
    /// `true` verified, `false` not verified; absent when this node has not checked it yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    /// Why, from the latest check on this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When that check ran, Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<u64>,
}

/// REQ: CLD-904 (T36.10b step b5) - the answer of `POST /api/v1/dns-providers/{name}/verify`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsProviderVerifyResult {
    /// Every record is verified.
    pub ok: bool,
    /// Each record with its verdict and reason.
    pub records: Vec<DnsProviderDelegationRecord>,
    /// A sentence for the card (for example, that no location uses the zone yet so nothing was
    /// checked).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// REQ: CLD-904 (T36.10b) - the DNS providers (`GET /api/v1/dns-providers`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsProviderList {
    pub items: Vec<DnsProviderEntry>,
    /// True while the start-up hold keeps the providers out of the answers this node serves: the
    /// list is what is configured.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
    /// Why they are held (the member that does not know them, or that the members are not heard
    /// from yet); set with `held`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_reason: Option<String>,
}

/// REQ: CLD-904 (T36.10b step b3) - what a provider credential may change, as the provider reports
/// it. Never a secret.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsProviderScope {
    /// The zone it was checked against.
    pub zone: String,
    /// One line that says it.
    pub summary: String,
    /// The record types it may write (`A`, `AAAA`, `TXT`).
    pub record_types: Vec<String>,
    /// The record sets it is limited to; absent when it may write any in the zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_sets: Option<Vec<String>>,
    /// The credential reaches further than the node needs: narrow it at the provider.
    pub broader_than_needed: bool,
    /// More notes for the card.
    pub notes: Vec<String>,
}

/// REQ: CLD-904 (T36.10b step b3) - the answer of `POST /api/v1/dns-providers/{name}/test`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // the answer's flags, each a fact the card shows
pub struct DnsProviderTestResult {
    /// The credential was accepted and the scope is shown.
    pub ok: bool,
    /// False when this build has no provider code for the entry (`error` says so; every real kind has code).
    pub supported: bool,
    /// Whether the entry is in dry run now (after this test).
    pub dry_run: bool,
    /// True when this test was the first success and ended the entry's dry run.
    pub dry_run_cleared: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<DnsProviderScope>,
    /// Why not, when `ok` is false. Never holds the credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// A sentence for the card (for example, that dry run is set in a file).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// REQ: CLD-919 (T36.10b step b3) - one record set at a provider, with whether the node owns it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsProviderRecord {
    pub name: String,
    /// `A`, `AAAA` or `TXT`.
    pub record_type: String,
    pub ttl: u32,
    pub values: Vec<String>,
    /// `created` (the node made it), `adopted` (an admin took it over); absent when the node does
    /// not own it, so it is never changed or deleted until adopted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Who made or adopted it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// When, Unix seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<u64>,
}

/// REQ: CLD-919 (T36.10b step b3) - `GET /api/v1/dns-providers/{name}/records`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsProviderRecords {
    pub items: Vec<DnsProviderRecord>,
    /// Whether the entry is in dry run (writes are recorded, not sent).
    pub dry_run: bool,
}

/// REQ: CLD-919 (T36.10b step b3) - the body of `POST /api/v1/dns-providers/{name}/records/adopt`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsProviderAdoptRequest {
    /// The record set's full name.
    pub name: String,
    /// `A`, `AAAA` or `TXT`.
    pub record_type: String,
}

/// REQ: CLD-919 (T36.10b step b3) - the record set an adopt took into the ledger.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsProviderAdopted {
    pub name: String,
    pub record_type: String,
    /// `adopted`, or `created` when the node already owned it.
    pub owner: String,
    pub by: String,
    pub at: u64,
}

/// REQ: FLT-012 (T7.9) — a blockable service.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    /// For `blocked_services` in a group.
    #[schema(example = "tiktok")]
    pub id: String,
    #[schema(example = "TikTok")]
    pub name: String,
    /// `social`, `video`, `music`, `gaming`, `messaging`, `dating`, `ai`, ...
    pub category: String,
    /// The domains it blocks (with everything under them).
    pub domains: Vec<String>,
}

/// A configured client (device).
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientInfo {
    pub name: String,
    /// IPs, CIDRs, MACs, or `id:<client-id>` this device is recognized by.
    #[serde(rename = "match")]
    pub matches: Vec<String>,
    /// Highest priority first.
    pub groups: Vec<String>,
    /// `file` (defined in the config files: read-only here) or `api` (named in the UI or
    /// through the API: editable with `PUT /clients/{name}`).
    #[schema(example = "api")]
    pub source: String,
    /// The groups that actually apply, highest priority first: `groups` when set, else the
    /// group of the network its addresses are in (ADR-050), else the default group. Empty
    /// when it depends on the address it's seen at (a device known only by MAC).
    #[serde(default)]
    pub effective_groups: Vec<String>,
    /// Where `effectiveGroups` comes from: `device`, `network`, or `default`.
    #[serde(default)]
    #[schema(example = "network")]
    pub groups_from: String,
    /// REQ: OBS-025 — what kind of device it is, as set (`[[client]] kind`), if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "camera")]
    pub kind: Option<String>,
    /// REQ: DSC-910 (T36.10a) - the location in effect: the one it is pinned to (`[[client]]
    /// location`), else the one whose networks hold its address; absent when it is on no
    /// location's network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "home")]
    pub location: Option<String>,
    /// REQ: DSC-910 - the location's display name (its label, else its slug).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location_name: Option<String>,
    /// REQ: DSC-910 - `location` is the device's own setting (an override), not derived from its
    /// address.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub location_pinned: bool,
    /// REQ: OBS-025 — what it looks like (the identity of the first of its addresses that was
    /// seen), without the evidence (`GET /api/v1/clients/{id}/identity` has it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<DeviceIdentity>,
}

/// REQ: OBS-025 (T13.3, ADR-117) — what a device looks like: a guess from its MAC vendor,
/// the names it announces, and the domains it talks to, or what it was set to be.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeviceIdentity {
    /// The device's address (or client ID), as the query log shows it.
    pub client: String,
    /// False when identification is off or not allowed (`reason`).
    pub available: bool,
    /// `disabled`, `privacy_level`, or `not_seen` (no queries from it in the last day).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The product (`Roku player`), when it's at least `possibly`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// The signature's ID (`roku-player`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_id: Option<String>,
    /// `phone`, `tv`, `streaming`, `camera`, ... or `unknown`.
    #[schema(example = "streaming")]
    pub class: String,
    /// `likely`, `possibly`, or `unknown`; `certain` for a Kubernetes workload (FLT-017).
    #[schema(example = "likely")]
    pub level: String,
    /// 0 to 1.
    pub score: f32,
    /// The MAC's registered vendor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// The group whose `device_classes` lists this class, when the device isn't in it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_group: Option<String>,
    /// `inferred`, `override` (`[[client]] kind`), or `kubernetes` (a workload, FLT-017).
    #[schema(example = "inferred")]
    pub source: String,
    /// When it was worked out (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computed_at: Option<String>,
    /// The node that worked it out (in a cluster).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Why (only from `GET /api/v1/clients/{id}/identity`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<IdentityEvidence>,
    /// REQ: OBS-034 (T14.12) — when its product or class last changed (RFC 3339), and what it
    /// looked like before (`Roku player`, or a class such as `unknown`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
}

/// REQ: OBS-025 — the evidence behind an identity.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IdentityEvidence {
    /// The signature's domains the device talked to, with their weights.
    pub domains: Vec<MatchedDomain>,
    /// The MAC's registry prefix (`D0:4D:2C`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_prefix: Option<String>,
    /// The announced name that matched the signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_name: Option<String>,
    /// Every name the device announced (DHCP, mDNS).
    pub names: Vec<String>,
    /// The registrable domains it talked to (at most 24).
    pub seen_domains: Vec<String>,
    /// The next best guess, when it's within 0.1: "could also be …".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_up: Option<IdentityRunnerUp>,
    /// REQ: FLT-017 — a Kubernetes workload: what the API server says (`source: kubernetes`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<WorkloadEvidence>,
}

/// REQ: FLT-017 — a workload's identity, from the Kubernetes API.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadEvidence {
    /// `media/deploy/jellyfin`.
    #[schema(example = "media/deploy/jellyfin")]
    pub workload: String,
    /// Its pods now.
    pub pods: Vec<String>,
    /// `app.kubernetes.io/name` and `app.kubernetes.io/part-of`, when its pods have them.
    pub labels: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MatchedDomain {
    pub name: String,
    pub weight: f32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IdentityRunnerUp {
    pub product: String,
    pub product_id: String,
    pub score: f32,
}

/// A device to create, rename, or change (`PUT /api/v1/clients/{name}`, API-010).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientInput {
    /// The new name, to rename the device (default: the name in the path).
    #[schema(example = "Living room TV")]
    pub name: Option<String>,
    /// How to recognize it: IPs, CIDRs, MACs (`aa:bb:cc:dd:ee:ff`), or `id:<client-id>`.
    #[serde(rename = "match")]
    #[schema(example = json!(["192.168.1.42"]))]
    pub matches: Vec<String>,
    /// Groups, highest priority first (default `["default"]`).
    #[serde(default)]
    pub groups: Vec<String>,
    /// REQ: OBS-025 — what kind of device it is (`camera`, `tv`, `unknown` to stop guessing);
    /// wins over identification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "camera")]
    pub kind: Option<String>,
    /// REQ: DSC-910 (T36.10a) - pin the device to a location (its slug), whatever its address;
    /// absent: the location its address gives it. A slug that names no location is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "home")]
    pub location: Option<String>,
}

/// What a device change did, or would do with `dryRun=true` (AGT-002).
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientChange {
    /// False for a dry run.
    pub applied: bool,
    /// The configuration version after the change (send it as `If-Match` next time).
    pub config_version: u64,
    /// The device before the change (absent when it's new).
    pub before: Option<ClientInfo>,
    /// The device after the change (absent after a delete).
    pub after: Option<ClientInfo>,
    /// Queries in the current and previous hour from the addresses it matches: how much
    /// history gets the new label (names are resolved when read, so the past is relabelled).
    pub recent_queries: u64,
    /// What the change does, in one sentence, with the numbers (AGT-002 impact estimate).
    #[serde(default)]
    pub impact: String,
    /// Configuration warnings after the change.
    pub warnings: Vec<String>,
    /// REQ: OBS-024 (T13.1) — with `simulate=` on a dry run: what the change would have done
    /// to the queries in the query log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulation: Option<Simulation>,
}

/// An upstream server and its health.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamInfo {
    /// Stable ID (config order, from 1); query rows and latency rows refer to it.
    pub id: u16,
    pub name: String,
    /// `udp://…`, `tls://…`, `https://…`.
    pub endpoint: String,
    /// Groups it belongs to.
    pub groups: Vec<String>,
    /// Circuit breaker: `closed` (healthy), `open` (benched), or `half_open` (probing).
    pub breaker: String,
    pub requests: u64,
    pub failures: u64,
    /// `failures` by kind, which say what to fix: timeouts point at the path or the upstream's
    /// load, network errors at the connection, SERVFAIL at the domain asked about.
    pub failures_by_kind: FailureKinds,
    /// Smoothed answer time.
    pub latency_ewma_ms: f64,
    /// REQ: UPS-006 — why this node can't reach it, when it can say: `this node has no IPv6
    /// route` (or IPv4). Checked at start and every 30 s with a `connect()` that sends nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_problem: Option<String>,
    /// REQ: UPS-013 (T24.31, ADR-997) — the local address its sockets are bound to, when the
    /// upstream sets a `source`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// REQ: UPS-013 — set while this node no longer holds that address: its queries fail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_problem: Option<String>,
}

/// Failed attempts by kind (their sum is `failures`).
#[derive(Debug, Clone, Copy, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FailureKinds {
    /// No answer within the attempt's timeout.
    pub timeout: u64,
    /// A connection, TLS, or socket error.
    pub network: u64,
    /// An answer that didn't match the query or didn't parse.
    pub bad_response: u64,
    /// The upstream's hostname couldn't be resolved.
    pub unresolved: u64,
    /// The upstream answered SERVFAIL (often the domain's fault, not the upstream's).
    pub servfail: u64,
    pub refused: u64,
    /// Any other error RCODE (FORMERR, NOTIMP, ...).
    pub other_rcode: u64,
}

/// A list wrapper used by every collection endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Items<T> {
    pub items: Vec<T>,
    /// Cluster nodes that couldn't be read, for federated reads (CLU-002).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// Query parameters for `GET /queries/stream` (OBS-008). Filters combine with AND and are
/// applied on the server, before the rate cap.
#[derive(Debug, Clone, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct TailParams {
    /// Name to look for; see `match`.
    pub name: Option<String>,
    /// How to match `name`: `substring` (default), `exact`, `suffix`, or `glob` (`*`, `?`).
    #[serde(rename = "match")]
    #[param(rename = "match")]
    pub name_match: Option<NameMatch>,
    /// REQ: OBS-003 (ADR-171) — only queries whose name does NOT match `name` and `match`.
    /// Needs `name`. Default: false.
    pub name_not: Option<bool>,
    /// Client IP address, or several, comma-separated (addresses, `hostname:<label>` and
    /// Kubernetes workloads; REQ: OBS-003, ADR-1013).
    pub client: Option<String>,
    /// Only queries from every client except `client` (all of them, when several). Needs `client`. Default: false.
    pub client_not: Option<bool>,
    /// The client's group (its highest-priority group).
    pub group: Option<String>,
    /// Statuses, comma-separated (`blocked,forwarded`).
    pub status: Option<String>,
    /// Only queries whose status is none of `status`. Needs `status`. Default: false.
    pub status_not: Option<bool>,
    /// Query types, comma-separated (`A,AAAA`).
    pub qtype: Option<String>,
    /// Only queries whose type is none of `qtype`. Needs `qtype`. Default: false.
    pub qtype_not: Option<bool>,
    /// Upstream ID (from `GET /upstreams`).
    pub upstream: Option<u16>,
    /// Only queries that took at least this long.
    pub min_latency_ms: Option<u32>,
    /// Most events per second sent to this subscriber (1–2000, default 500). The rest are
    /// counted and reported in `dropped` events.
    pub rate: Option<u32>,
    /// `cluster` (default: every reachable node's queries, each row naming its node),
    /// `site:<name>`, `node:<id or site>`, or `node:local` (this node only).
    pub scope: Option<String>,
}

impl TailParams {
    /// REQ: OBS-003 (ADR-171) — whether any filter is negated (see [`QueryParams::negates`]).
    pub fn negates(&self) -> bool {
        [
            self.name_not,
            self.client_not,
            self.status_not,
            self.qtype_not,
        ]
        .contains(&Some(true))
    }
}

/// Sent as an SSE `dropped` event when matching queries weren't delivered.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TailDropped {
    /// How many matching queries were skipped since the last report.
    pub dropped: u64,
    /// `rate`: over this subscriber's `rate`; `lag`: the subscriber fell behind.
    pub reason: String,
}

/// What a live tail delivers (also sent between cluster nodes, T9.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "item", rename_all = "snake_case")]
pub enum TailItem {
    Query(Box<QueryRow>),
    Dropped(TailDropped),
}

/// REQ: OBS-010 (T9.6) — the result of a test alert.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlertTest {
    pub ok: bool,
    /// Why it wasn't delivered (the destination's own message where there is one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// REQ: API-002 (T9.12) — a pre-save check of a draft upstream or list.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    /// It works: the upstream answered, or the list downloaded and has rules.
    pub ok: bool,
    /// Why not (the server's or the parser's own message where there is one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// What was seen: `answered NOERROR, 13 records` or `81,234 rules from 81,512 lines`.
    pub detail: String,
    /// How long the probe or the download took.
    pub elapsed_ms: u64,
    /// Lists: the rules found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<u64>,
    /// Lists: up to 10 lines that were invalid or unsupported, with why.
    pub warnings: Vec<String>,
}

/// REQ: OBS-010 (T9.6) — an alert that is firing now.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FiringAlert {
    pub rule: String,
    /// What it's about: an upstream, a node, a list.
    pub subject: String,
    pub summary: String,
}

/// REQ: OBS-010 (T9.6) — the last delivery to a destination.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlertDelivery {
    pub destination: String,
    pub unix_seconds: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// REQ: DSC-014 (T25.3, ADR-908) — the network inventory's status: whether it runs on this node,
/// and each discovery worker process. Health reasons for the workers never mark DNS unhealthy.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryStatus {
    /// `[discovery] enabled`.
    pub enabled: bool,
    /// Whether this node is the designated one (it runs the inventory and its workers).
    pub designated: bool,
    /// The designated node's name, when `[discovery] node` is set.
    pub node: Option<String>,
    /// The worker processes this node runs (none unless enabled and designated).
    pub workers: Vec<DiscoveryWorker>,
    /// REQ: DSC-004, DSC-014 (T25.6) — each `[[discovery.snmp_agent]]` the poller runs on this
    /// node: its last poll, its tables and its capability record.
    #[serde(default)]
    pub agents: Vec<DiscoveryAgent>,
    /// REQ: DSC-009 (T25.10, ADR-912) - the last result of each extra UniFi and Home Assistant
    /// read: which ones work, and which the console refused. Empty unless one is on.
    pub reads: Vec<DiscoveryRead>,
}

/// REQ: DSC-004, DSC-014 (T25.6, ADR-908) — one SNMP agent as the poller sees it. Everything that
/// came from the device (names, the sysObjectID) is device-supplied text, cut and cleaned.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryAgent {
    /// The agent's name, as `[[discovery.snmp_agent]]` gives it.
    #[schema(example = "gateway")]
    pub name: String,
    /// The address it is polled at (RFC 1918 only).
    #[schema(example = "192.0.2.1")]
    pub address: String,
    /// The credential it uses (by name; the secret is never shown).
    pub credential: String,
    /// Seconds between polls.
    pub interval_secs: u32,
    /// `waiting` (no poll yet), `ok`, `error` (the last poll failed), `failing` (three polls in a
    /// row failed) or `skipped` (its credential can't be read, or its address is refused).
    pub state: String,
    /// When the last poll ended (Unix seconds).
    pub last_poll_unix: Option<u64>,
    /// When a poll last succeeded (Unix seconds).
    pub last_success_unix: Option<u64>,
    /// How long the last poll took, in milliseconds.
    pub last_duration_ms: Option<u64>,
    /// Why the last poll failed, in words. Carries no address, credential or reply byte.
    pub last_error: Option<String>,
    /// Polls that failed in a row.
    pub consecutive_failures: u32,
    /// Polls made since start.
    pub polls: u64,
    /// Polls that failed since start.
    pub failures: u64,
    /// SNMP requests the last poll sent.
    pub last_requests: Option<u32>,
    /// Exchanges of the last poll that timed out.
    pub last_timeouts: Option<u32>,
    /// One entry per configured table.
    pub tables: Vec<DiscoveryAgentTable>,
    /// What the agent answered when it was last probed (the first poll, or **Test**). Never
    /// assumed: a table that did not answer is skipped until the next test.
    pub capability: Option<AgentCapability>,
    /// What the last poll's rows meant.
    pub last_counts: Option<DiscoveryAgentCounts>,
    /// When **Test** last ran for this agent (Unix seconds); a new test waits 60 s after it.
    pub last_test_unix: Option<u64>,
}

/// REQ: DSC-004 — a configured table of an agent and what is known of it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryAgentTable {
    /// `arp`, `ifmib`, `bridge` or `lldp`.
    pub table: String,
    /// `unprobed`, `answered`, or `unanswered` (skipped until the next test).
    pub state: String,
    /// The rows the last poll read from the table, over every part and column.
    pub rows: Option<u32>,
    /// Why the last walk of the table ended: `end`, `row_cap`, `time_cap`, `byte_cap`, `error` or `skipped`.
    pub stop: Option<String>,
    /// The last error of the table, in words.
    pub error: Option<String>,
}

/// REQ: DSC-004 (ADR-908 "Capability record") — what an agent answered when it was probed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapability {
    /// When it was probed (Unix seconds).
    pub probed_unix: u64,
    /// The security level reached: `v2c`, `authNoPriv` or `authPriv`.
    pub level: String,
    /// The v3 engine ID, in hex.
    pub engine_id: Option<String>,
    /// sysObjectID, when the agent answered it (device-supplied).
    pub sys_object_id: Option<String>,
    /// One entry per part of every configured table.
    pub parts: Vec<AgentCapabilityPart>,
}

/// REQ: DSC-004 — one part of a table group and the MIB table that answered it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilityPart {
    /// `arp`, `ifmib`, `bridge` or `lldp`.
    pub table: String,
    /// The part: `arp`, `interfaces`, `addresses`, `forwarding`, `ports`, `vlans`, `neighbours`
    /// or `local_ports`.
    pub part: String,
    /// The MIB table that answered (`ipNetToPhysicalTable`, `ipNetToMediaTable`, ...); none when
    /// no alternative did.
    pub source: Option<String>,
}

/// REQ: DSC-004, DSC-014 — what the last poll's rows meant.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryAgentCounts {
    /// ARP entries merged into the inventory.
    pub arp_merged: u32,
    /// ARP entries outside every `[[discovery.subnet]]` (or naming no host).
    pub arp_outside_subnets: u32,
    /// IPv6 entries counted and left out (M25 is IPv4 only).
    pub ipv6_ignored: u32,
    /// The agent's own addresses merged.
    pub own_merged: u32,
    /// Forwarding entries that gave a device a port and a VLAN.
    pub fdb_located: u32,
    /// Forwarding entries left out because they were learned on an uplink or trunk port.
    pub fdb_uplink: u32,
    /// Ports counted as uplinks (more than 8 learned MACs, or a listed agent or UniFi device as
    /// the LLDP neighbour).
    pub uplink_ports: u32,
    /// LLDP neighbours merged.
    pub lldp_merged: u32,
}

/// REQ: DSC-004 (T25.6, ADR-908, ADR-1002) — `POST /api/v1/discovery/snmp/test`: the agent to
/// test, by name. No address is ever accepted (ADR-907).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnmpTestRequest {
    /// The agent's name, from `[[discovery.snmp_agent]]` (`GET /api/v1/discovery/status` lists them).
    #[schema(example = "gateway")]
    pub agent: String,
}

/// REQ: DSC-004 — one table root a test would query (or did).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnmpTestOid {
    /// `arp`, `ifmib`, `bridge` or `lldp`.
    pub table: String,
    /// The part of the table group.
    pub part: String,
    /// The MIB table (an alternative; the first that answers is used).
    pub alternative: String,
    /// The OID the probe's one GETNEXT starts from.
    pub probe_oid: String,
    /// The column OIDs a poll walks when this alternative answers.
    pub columns: Vec<String>,
}

/// REQ: DSC-004 — the answer of **Test** (`POST /api/v1/discovery/snmp/test`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnmpTestResult {
    /// The agent tested.
    pub agent: String,
    /// True when no packet was sent (`?dryRun=true`): `oids` is what a test would query.
    pub dry_run: bool,
    /// Whether the agent answered (a dry run is always `true`).
    pub ok: bool,
    /// The OIDs a test queries: one GETNEXT on each probe root, one GET of sysObjectID.
    pub oids: Vec<SnmpTestOid>,
    /// What the agent answered (not for a dry run, or a test that failed).
    pub capability: Option<AgentCapability>,
    /// Why the test failed, in words.
    pub error: Option<String>,
    /// How long the test took, in milliseconds.
    pub duration_ms: Option<u64>,
    /// The node that ran the test (the designated node, which may not be the one asked).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// What happens next, in a sentence.
    pub note: String,
}

/// REQ: DSC-009 (T25.10, ADR-912) - one extra read of one router, as the inventory thread last saw
/// it. Read-only: nothing here changes a console.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryRead {
    /// The `[[router]]` read.
    #[schema(example = "udm")]
    pub router: String,
    /// `client_fields`, `all_users`, `devices` or `home_assistant_all_devices`.
    #[schema(example = "all_users")]
    pub read: String,
    /// `ok`, `refused` (the console answered 401 or 403) or `failed`.
    #[schema(example = "ok")]
    pub state: String,
    /// Rows used.
    pub rows: u32,
    /// More rows were offered than the 8,192 cap; the rest were left out.
    pub truncated: bool,
    /// Why a read did not work, in words (no credential in it).
    pub error: Option<String>,
    /// When the result was recorded (Unix seconds).
    pub at: Option<u64>,
}

/// REQ: DSC-002 (T25.3, ADR-908) — one discovery worker process, as the supervisor sees it.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryWorker {
    /// `snmp` (the SNMP poller) or `import` (the scan-import parser, short-lived).
    #[schema(example = "snmp")]
    pub worker: String,
    /// Running, with a handshake that matched.
    pub up: bool,
    /// Times the worker has been restarted since start.
    pub restarts: u64,
    /// The worker's build differs from this node's: it is refused (`discovery_worker_version_mismatch`).
    pub version_mismatch: bool,
    /// Three or more crashes in ten minutes: restarts are slowed (`discovery_worker_failing`).
    pub failing: bool,
    /// The last failure, in words (the stderr line is logged, rate-limited).
    pub last_error: Option<String>,
    /// The worker's `RLIMIT_DATA` in MiB, as it reported it at the handshake.
    pub data_limit_mib: Option<u64>,
    /// Whether the worker reported it isn't dumpable (no core dumps, no /proc reads by others).
    pub dumpable: Option<bool>,
    /// The worker's `oom_score_adj`, as it reported it.
    pub oom_score_adj: Option<i32>,
}

/// REQ: OBS-010 (T9.6) — alerts now: what fires, and how deliveries went.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlertsStatus {
    /// Rules are checked on the cluster's primary (or a standalone node); elsewhere this is
    /// false and the lists are empty.
    pub evaluating: bool,
    pub firing: Vec<FiringAlert>,
    pub deliveries: Vec<AlertDelivery>,
    /// REQ: OPS-010 — nodes whose alerts are paused for maintenance, until when.
    pub maintenance: Vec<NodeMaintenance>,
}

/// REQ: OBS-010 (T9.5) — a device seen for the first time (internal: alerts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewDevice {
    pub client: String,
    pub client_name: Option<String>,
    pub first_seen_unix_seconds: u64,
}

/// REQ: CLU-002 (T9.2) — one latency histogram, as `(microseconds, count)` pairs: what
/// cluster nodes send each other so percentiles merge exactly. Internal (not an API route).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyHist {
    pub key: String,
    pub buckets: Vec<(u64, u64)>,
}

/// One record of a local name.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordInput {
    /// `A`, `AAAA`, `CNAME` (Simple); `PTR`, `TXT`, `MX`, `SRV` (Advanced).
    #[serde(rename = "type")]
    #[schema(example = "A")]
    pub rtype: String,
    /// An address for A/AAAA, a name for CNAME/PTR, text for TXT, `"10 mail.home.arpa"` for MX,
    /// `"0 5 5060 pbx.home.arpa"` for SRV.
    #[schema(example = "192.168.1.10")]
    pub value: String,
    /// TTL in seconds (default: `[local] default_ttl`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    /// REQ: CLU-006 (T27.7) — keep this record on this node only (a cluster doesn't share it).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub node_only: bool,
}

/// A local name's records (`PUT /api/v1/records/{name}`).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordsInput {
    pub records: Vec<RecordInput>,
}

/// A name WrenDNS answers itself.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LocalName {
    #[schema(example = "nas.home.arpa")]
    pub name: String,
    pub records: Vec<RecordInput>,
    /// `file` (read-only here) or `api`.
    pub source: String,
}

/// The servers a domain is sent to (`PUT /api/v1/forwards/{domain}`).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForwardInput {
    /// Addresses (plain DNS) or `udp://`, `tcp://`, `tls://`, `https://` URLs, tried in order.
    /// For a stub zone: the zone's own servers, as IP addresses (port 53).
    #[schema(example = json!(["10.0.0.53"]))]
    pub servers: Vec<String>,
    /// REQ: DNS-022 — a stub zone (BIND's `static-stub`): the servers are authoritative only,
    /// so they're asked iteratively and the delegations they give to other servers are
    /// followed, instead of forwarding with recursion desired. Default `false`.
    #[serde(default)]
    pub stub: bool,
    /// REQ: DNS-902 — a stub zone only: also ask its servers at loopback or link-local
    /// addresses (a server on this machine). Off by default, and refused for a forward that
    /// is not a stub zone. Left out, the stored value stays as it is.
    #[serde(default)]
    pub allow_local_servers: Option<bool>,
    /// REQ: DNS-902 — a stub zone only: also ask private-range servers for names outside the
    /// zone (the zone's own private servers are asked either way). Off by default, and refused
    /// for a forward that is not a stub zone. Left out, the stored value stays as it is.
    #[serde(default)]
    pub allow_private_servers: Option<bool>,
    /// REQ: DNS-010 (T27.7) — only these client groups are sent (empty: every client).
    #[serde(default)]
    pub match_group: Vec<String>,
    /// REQ: DNS-010 (T27.7) — only these query types are sent, e.g. `["PTR"]` (empty: all).
    #[serde(default)]
    pub match_qtype: Vec<String>,
    /// REQ: DNS-010 (T27.7) — add a DNSSEC negative trust anchor for the domain (default `true`:
    /// local zones are usually unsigned).
    #[serde(default = "default_true")]
    pub dnssec_nta: bool,
    /// REQ: CLU-006 (T27.7) — keep this route on this node only.
    #[serde(default)]
    pub node_only: bool,
}

fn default_true() -> bool {
    true
}

/// REQ: DNS-006 (T6.13) — one node's cache counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheNodeStats {
    /// The node (its site), or absent for a standalone node.
    pub node: Option<String>,
    pub entries: u64,
    pub bytes: u64,
    pub hits: u64,
    pub misses: u64,
    /// hits / (hits + misses), percent; absent before any lookup. Fresh entries only.
    pub hit_percent: Option<f64>,
    /// REQ: DNS-007 — lookups answered from the cache, fresh or from an expired entry
    /// (refreshed in the background, or stale), percent: what the dashboard's cache tile shows.
    /// Absent before any lookup, and from older nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_percent: Option<f64>,
    pub stale_served: u64,
    pub prefetches: u64,
    pub evictions: u64,
    pub inserts: u64,
    pub uncacheable: u64,
    /// REQ: DNS-006, OBS-003 (T6.15) — the `[cache]` settings in effect (absent from older
    /// nodes).
    #[serde(default)]
    pub settings: Option<CacheSettings>,
    /// Whether the cache was reloaded from its dump at the last start (DNS-009).
    #[serde(default)]
    pub warm_start: Option<CacheWarmStart>,
    /// The last hour, every 15 s, oldest first (empty from older nodes).
    #[serde(default)]
    pub history: Vec<CachePoint>,
    /// REQ: OBS-021 (T11.2) — whether the cache is the right size (absent from older nodes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sizing: Option<CacheSizing>,
}

/// REQ: OBS-021 (ADR-106) — one node's cache size advice: what a bigger cache would have
/// answered (estimated from a sample of evicted names), and its peak use.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheSizing {
    /// `grow`, `shrink`, `ok`, or `learning` (too few lookups to judge).
    #[schema(example = "grow")]
    pub verdict: String,
    /// The advice in one or two sentences, with the `[cache] max_bytes` to try.
    pub advice: String,
    /// Lookups since start (what the percentages are of).
    pub lookups: u64,
    /// A cache 125%, 150%, and 200% of today's size.
    pub steps: Vec<CacheSizingStep>,
    /// The most memory the cache held since start.
    pub peak_bytes: u64,
    /// The `[cache] max_bytes` the advice suggests, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_max_bytes: Option<u64>,
}

/// REQ: OBS-021 — what one larger cache would have added.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheSizingStep {
    /// The size, in percent of today's (125, 150, 200).
    pub size_percent: u32,
    /// Estimated extra hits since start, and as a share of lookups (percentage points).
    pub extra_hits: u64,
    pub extra_hit_percent: f64,
    /// The extra memory it takes.
    pub extra_bytes: u64,
}

/// REQ: DNS-006 (T6.15) — the `[cache]` settings a node runs with.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheSettings {
    /// Memory budget for cached answers.
    pub max_bytes: u64,
    /// Entry cap; absent: limited by memory only.
    pub max_entries: Option<u64>,
    pub min_ttl_seconds: u32,
    pub max_ttl_seconds: u32,
    /// Cap for negative answers (NXDOMAIN, no data), RFC 2308.
    pub negative_ttl_max_seconds: u32,
    /// How long SERVFAIL is cached, RFC 9520.
    pub servfail_ttl_seconds: u32,
    /// Serve expired answers when upstreams fail (RFC 8767).
    pub serve_stale: bool,
    /// How long expired answers are kept for that.
    pub stale_max_age_seconds: u32,
    /// REQ: DNS-007 — how long an expired answer waits for the upstream before it's given
    /// (`[cache] stale_answer_client_timeout_ms`): 0 answers at once and refreshes in the
    /// background. Absent from older nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_answer_wait_ms: Option<u32>,
    /// Refresh popular answers before they expire.
    pub prefetch: bool,
    /// Prefetch below this share of the TTL left.
    pub prefetch_threshold_percent: u8,
    /// ...for answers asked at least this often.
    pub prefetch_min_hits: u32,
    /// Keep the cache across restarts.
    pub persist: bool,
}

/// REQ: DNS-009 (T6.15) — what happened to the cache dump at the last start.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheWarmStart {
    /// When (RFC 3339).
    pub at: String,
    /// Answers reloaded; absent when nothing was loaded.
    pub loaded: Option<u64>,
    /// Why nothing was loaded (no dump, a dump from other upstreams, ...).
    pub note: Option<String>,
}

/// REQ: OBS-003 (T6.15) — 15 s of one node's cache.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CachePoint {
    /// End of the interval (RFC 3339).
    pub at: String,
    /// Hits per lookup in the interval, percent; absent without lookups.
    pub hit_percent: Option<f64>,
    /// REQ: DNS-007 — lookups answered from the cache (fresh, refreshed, or stale) in the
    /// interval, percent; absent without lookups, and from older nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_percent: Option<f64>,
    pub lookups: u64,
    pub stale_served: u64,
    pub prefetches: u64,
    pub evictions: u64,
    /// At the end of the interval.
    pub entries: u64,
    pub bytes: u64,
}

/// REQ: DNS-006, OBS-003 (T6.15) — what the cache holds by kind (entries).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheMakeup {
    /// Answers with records.
    pub positive: u64,
    /// The name doesn't exist.
    pub nxdomain: u64,
    /// The name exists, but not with that type.
    pub nodata: u64,
    pub servfail: u64,
    /// Expired, kept only to serve stale when upstreams fail.
    pub stale: u64,
    /// DNSSEC-validated.
    pub validated: u64,
}

/// One entry in a node's top list.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheTopEntry {
    #[schema(example = "www.example.com")]
    pub name: String,
    #[schema(example = "A")]
    pub qtype: String,
    #[schema(example = "NOERROR")]
    pub rcode: String,
    pub answers: u16,
    pub authentic: bool,
    pub dnssec_ok: bool,
    /// Seconds until it goes stale; negative: how long it has been stale.
    pub ttl_left_seconds: i64,
    pub age_seconds: u64,
    pub bytes: u64,
    pub hits: u32,
}

/// One node's top entries and makeup (`GET /api/v1/cache/entries`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheNodeEntries {
    /// The node (absent on a standalone node).
    pub node: Option<String>,
    pub makeup: CacheMakeup,
    pub entries: Vec<CacheTopEntry>,
    /// Set when the node couldn't be asked.
    pub error: Option<String>,
}

/// REQ: API-002 (T7.5, ADR-069) — one upstream, upstream group, list, or group: its definition
/// in effect and where it comes from.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigEntry {
    /// `upstream`, `upstream_group`, `list`, or `group`.
    pub kind: String,
    pub name: String,
    /// `file` (the config files), `added` (made through the UI or API), `override` (replaces
    /// the files' entry of that name), or `hidden` (the files' entry is left out).
    pub source: String,
    /// The definition in effect, with the same fields as in `wrendns.toml` (absent when
    /// hidden). Credentials read `<redacted>` (API-014).
    #[schema(value_type = Option<Object>)]
    pub definition: Option<serde_json::Value>,
    /// REQ: API-014 — the fields of `definition` that hold a credential and read `<redacted>`
    /// (`headers.Authorization`, `args[1]`, `url` for a URL's password). Send them back as they
    /// are to keep the values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted: Vec<String>,
    /// REQ: API-014 (T23.2, ADR-903 §4) — paths this entry sets through the UI or API that the
    /// path rules refuse (under `/proc` or the data directory, a key file, a credential file
    /// outside `[node] secret_file_dirs`): they aren't read until an admin sets another.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_issues: Vec<CredentialIssue>,
    /// REQ: DNS-019, DNS-023 (ADR-914) — the fields of a shared settings section (`special`,
    /// `local`, `clients`) that the config files set: the API can't change them, and the UI
    /// shows them as "set by file".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set_by_file: Vec<String>,
    /// REQ: DNS-023 (T24.13) — how many names this entry answers right now (the device names
    /// for `local`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answering: Option<u64>,
}

/// REQ: API-014 (T23.2) — a stored path that isn't read, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialIssue {
    /// The entry's field (`token_file`, `tls_ca`, `path`).
    pub field: String,
    /// Why it isn't read.
    pub reason: String,
}

/// `GET /api/v1/config/entries` parameters.
#[derive(Debug, Clone, Default, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EntriesQuery {
    /// One kind only: `upstream`, `upstream_group`, `list`, or `group`.
    pub kind: Option<String>,
}

/// REQ: FLT-009 (T7.1) — pause or resume blocking (`POST /api/v1/blocking/pause|resume`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockingRequest {
    /// Pause only: for how long, 1 to 1,440 (agents: at most 60).
    #[schema(example = 15)]
    pub minutes: Option<u32>,
    /// One group's devices only; absent: everyone (resume: every pause).
    #[schema(example = "kids")]
    pub group: Option<String>,
    /// One node only (its site, pod, or ID); absent: every node.
    pub node: Option<String>,
}

/// One active pause.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PauseInfo {
    /// The group paused; absent: everyone.
    pub group: Option<String>,
    /// When blocking turns back on (RFC 3339).
    pub until: String,
    pub seconds_left: u64,
}

/// One node's pauses (`GET /api/v1/blocking`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BlockingNode {
    /// The node (absent on a standalone node).
    pub node: Option<String>,
    /// Active pauses; empty: blocking is on.
    pub pauses: Vec<PauseInfo>,
    /// Set when the node couldn't be reached.
    pub error: Option<String>,
}

/// One cached answer for a name.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheEntry {
    /// The node holding it (absent on a standalone node).
    pub node: Option<String>,
    #[schema(example = "A")]
    pub qtype: String,
    #[schema(example = "NOERROR")]
    pub rcode: String,
    pub answers: u16,
    /// DNSSEC-validated (the AD bit).
    pub authentic: bool,
    /// The variant for clients that set DO (they get DNSSEC records).
    pub dnssec_ok: bool,
    /// The variant for clients that set CD (checking disabled).
    pub checking_disabled: bool,
    /// Seconds until it goes stale; negative: how long it has been stale.
    pub ttl_left_seconds: i64,
    pub age_seconds: u64,
    pub bytes: u64,
    pub hits: u32,
}

/// What the cache holds for a name.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheLookup {
    pub name: String,
    pub entries: Vec<CacheEntry>,
}

/// What to flush (`POST /api/v1/cache/flush`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CacheFlushRequest {
    /// A name; absent: everything.
    #[schema(example = "www.example.com")]
    pub name: Option<String>,
    /// Also every name under `name`.
    pub subtree: Option<bool>,
    /// One node only (its site or ID); absent: every node.
    pub node: Option<String>,
    /// REQ: DNS-905 (T40.4) — only this query type (`A`, `AAAA`, `HTTPS`, `TYPE65`): with a
    /// `name`, that name's answers of this type; without, every name's.
    #[serde(rename = "type")]
    #[schema(example = "AAAA")]
    pub qtype: Option<String>,
    /// REQ: DNS-905 (T40.4) — only `negative` answers (NXDOMAIN and no-data) or `bogus` ones
    /// (failed lookups: SERVFAIL, which is how a DNSSEC validation failure is answered);
    /// absent: every kind.
    #[schema(example = "negative")]
    pub kind: Option<String>,
    /// REQ: DNS-905 (T40.4) — instead of answers, empty what the recursive resolver
    /// remembers: `cuts` (zone cuts and server addresses: the next lookup starts from the
    /// root), `rtts` (each server's round-trip time), or `all`. Can't be combined with
    /// `name`, `subtree`, `type` or `kind`.
    #[schema(example = "cuts")]
    pub recursor: Option<String>,
}

impl CacheFlushRequest {
    /// REQ: DNS-905 (T40.4) — whether this is the original flush (a name, a subtree, or
    /// everything), which every node version understands.
    #[must_use]
    pub fn is_plain(&self) -> bool {
        self.qtype.is_none() && self.kind.is_none() && self.recursor.is_none()
    }

    /// REQ: DNS-905 (T40.4) — the text of what's wrong with the request, if anything: an
    /// unknown `kind` or `recursor`, or a recursor flush mixed with an answer flush.
    #[must_use]
    pub fn problem(&self) -> Option<String> {
        if let Some(k) = &self.kind
            && !["negative", "bogus"].contains(&k.as_str())
        {
            return Some(format!("`kind`: `{k}` isn't negative or bogus"));
        }
        if let Some(r) = &self.recursor {
            if !["cuts", "rtts", "all"].contains(&r.as_str()) {
                return Some(format!("`recursor`: `{r}` isn't cuts, rtts, or all"));
            }
            if self.name.is_some()
                || self.subtree.is_some()
                || self.qtype.is_some()
                || self.kind.is_some()
            {
                return Some(
                    "`recursor` flushes the resolver's memory and can't be combined with `name`, `subtree`, `type` or `kind`"
                        .into(),
                );
            }
        }
        if self.subtree == Some(true) && self.name.is_none() {
            return Some("`subtree` needs a `name`".into());
        }
        None
    }
}

/// What one node removed.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheFlushNode {
    pub node: Option<String>,
    /// Entries removed; absent when the node couldn't be reached.
    pub removed: Option<u64>,
    /// REQ: DNS-905 (T40.4) — recursor entries dropped (a `recursor` flush): zone cuts and
    /// addresses, or server round-trip times.
    #[serde(default)]
    pub recursor_removed: Option<u64>,
    pub error: Option<String>,
}

/// The result of a flush.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CacheFlushResult {
    pub total_removed: u64,
    pub nodes: Vec<CacheFlushNode>,
}

/// REQ: FLT-005 (T6.12, ADR-067) — a quick rule to create or replace
/// (`PUT /api/v1/rules/{id}`).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleInput {
    /// `allow` or `block`.
    #[schema(example = "allow")]
    pub action: String,
    /// The domain; its subdomains are included.
    #[schema(example = "game.example.com")]
    pub domain: String,
    /// Device names, IPs, or CIDRs it applies to.
    #[serde(default)]
    pub devices: Vec<String>,
    /// Groups it applies to. With neither devices nor groups: everyone.
    #[serde(default)]
    pub groups: Vec<String>,
    /// When it stops applying (RFC 3339). Use this or `forMinutes`; neither means never.
    #[serde(default)]
    pub expires: Option<String>,
    /// Stop applying this many minutes from now.
    #[serde(default)]
    pub for_minutes: Option<u32>,
    /// Why it exists, shown with every decision it makes.
    #[serde(default)]
    pub note: Option<String>,
}

/// A quick rule (files and API), with how long it has left.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleInfo {
    pub id: String,
    /// `allow` or `block`.
    pub action: String,
    pub domain: String,
    pub devices: Vec<String>,
    pub groups: Vec<String>,
    /// RFC 3339, when it stops applying.
    pub expires: Option<String>,
    /// Seconds until it expires (0 once it has).
    pub expires_in_seconds: Option<u64>,
    pub note: Option<String>,
    pub created_by: Option<String>,
    pub created: Option<String>,
    /// `file` (read-only here) or `api`.
    pub source: String,
}

/// A domain sent to other servers (conditional forwarding).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // independent flags of one route, as the API shows them
pub struct ForwardInfo {
    #[schema(example = "corp.example")]
    pub domain: String,
    /// The servers (upstream URLs), in order; a stub zone's are IP addresses.
    pub servers: Vec<String>,
    /// REQ: DNS-022 — a stub zone: the servers are asked iteratively and their delegations
    /// followed.
    pub stub: bool,
    /// REQ: DNS-902 — a stub zone whose servers may be at loopback or link-local addresses.
    pub allow_local_servers: bool,
    /// REQ: DNS-902 — a stub zone whose private-range servers are also asked for names outside
    /// the zone.
    pub allow_private_servers: bool,
    /// `file` (read-only here) or `api`.
    pub source: String,
    /// REQ: DNS-010 (T27.7) — the client groups the route applies to (empty: every client).
    pub match_group: Vec<String>,
    /// REQ: DNS-010 (T27.7) — the query types the route applies to (empty: all).
    pub match_qtype: Vec<String>,
    /// REQ: DNS-010 (T27.7) — a DNSSEC negative trust anchor is added for the domain.
    pub dnssec_nta: bool,
    /// REQ: CLU-006 (T27.7) — this route stays on this node.
    pub node_only: bool,
}

/// What a change to local names or forwarded domains did (or would do, with `dryRun`).
#[derive(Debug, Clone, Serialize, ToSchema, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigChange {
    /// False for a dry run.
    pub applied: bool,
    /// The configuration version after the change (send it as `If-Match` next time).
    pub config_version: u64,
    /// The entry before (absent when new).
    #[schema(value_type = Option<Object>)]
    pub before: Option<serde_json::Value>,
    /// The entry after (absent after a delete).
    #[schema(value_type = Option<Object>)]
    pub after: Option<serde_json::Value>,
    /// Queries in the current and previous hour for the name (or names under the domain)
    /// that the change affects. A lower bound: counted from the busiest names.
    #[serde(default)]
    pub recent_queries: u64,
    /// What the change does, in one sentence, with the numbers (AGT-002 impact estimate).
    #[serde(default)]
    pub impact: String,
    /// Configuration warnings after the change.
    pub warnings: Vec<String>,
    /// REQ: API-002 (T7.5, ADR-069) — on a node whose configuration comes from Git: the TOML
    /// to add to (or the block to remove from) the repository or the Helm values' `config:` to
    /// make this change permanent there. Changes made through the API live in this node's
    /// `state.db`, not in Git. Absent on other nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_in_git: Option<String>,
    /// REQ: OBS-024 (T13.1) — with `simulate=` on a dry run: what the change would have done to
    /// the queries in the query log. Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulation: Option<Simulation>,
    /// REQ: OBS-007, API-905 (T40.13) - the node a per-node change was made for (the dnstap
    /// settings: the node whose own entry `before` and `after` describe). Absent for the rest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
}

/// REQ: OBS-024 (T13.1, ADR-115) — what a configuration change would have done to the queries
/// already in the query log: each logged query decided again under the current configuration
/// and under the candidate, and the differences counted. Decisions only: nothing is asked of
/// upstreams, and caching, DNSSEC, rate limits, pauses, and CNAME-target blocks aren't replayed.
/// About the past: names nobody asked in the window count for nothing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Simulation {
    /// False when it couldn't run (`reason` says why: `disabled`, `privacy_level`,
    /// `no_query_log`, `busy`, ...).
    pub available: bool,
    /// False for a change that can't affect a decision (alerts, users, exclusions): nothing
    /// was read.
    pub applicable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The window replayed (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Logged queries read (on every node that answered).
    pub rows: u64,
    /// Stopped early (`[simulate] max_rows` or `max_secs`): the counts cover the newest `rows`.
    pub partial: bool,
    /// Allowed now, blocked under the change.
    pub newly_blocked: SimulatedClass,
    /// Blocked now, allowed under the change (`list` names the list that had blocked it).
    pub newly_allowed: SimulatedClass,
    /// Forwarded to another upstream group (`list` says from where to where).
    pub changed_route: SimulatedClass,
    /// Answered differently without a block: a local record, a rewrite, no IPv6 addresses, a
    /// special answer (`list` describes the new answer).
    pub changed_answer: SimulatedClass,
    pub unchanged: u64,
    /// At privacy level 1 (names hashed), queries of devices whose group changes to one with
    /// different settings: they can't be decided again without the names.
    pub undetermined: u64,
    /// The devices most affected, most first (at most 50).
    pub by_device: Vec<SimulatedDevice>,
    pub by_group: Vec<SimulatedGroup>,
    /// Approximations that applied (`badfilter_cross_snapshot`, `identity_from_event`, ...).
    pub notes: Vec<String>,
    /// Cluster nodes whose queries aren't included (they didn't answer).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// One kind of difference: how many queries, from how many devices, and the names most
/// affected (at most 20, most first).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SimulatedClass {
    pub queries: u64,
    pub devices: u64,
    pub top_names: Vec<SimulatedName>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SimulatedName {
    pub name: String,
    pub queries: u64,
    pub devices: u64,
    /// What decided: the list (or quick rule, schedule) that blocks or had blocked it, the
    /// route change, or the new answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SimulatedDevice {
    pub client: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub newly_blocked: u64,
    pub newly_allowed: u64,
    pub changed_route: u64,
    pub changed_answer: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SimulatedGroup {
    pub group: String,
    pub newly_blocked: u64,
    pub newly_allowed: u64,
    pub changed_route: u64,
    pub changed_answer: u64,
}

/// `POST /api/v1/simulate`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SimulateRequest {
    /// The candidate shared configuration, as JSON: the shape a Git commit's shared TOML
    /// becomes (node-local sections are ignored; this node's own apply).
    #[schema(value_type = Object)]
    pub config: serde_json::Value,
    /// How far back: `30m`, `24h`, `7d` (at most 7 days). Default `[simulate] default_window`.
    #[serde(default)]
    pub window: Option<String>,
    /// The end of the window (RFC 3339 or relative, e.g. `-1h`); default now.
    #[serde(default)]
    pub until: Option<String>,
}

/// A device named by a router's DHCP or by mDNS (REQ: API-010; T8.2, T8.3).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DhcpLease {
    pub mac: String,
    pub ip: String,
    /// The name the router knows it by (its DHCP host name or alias), or the one it announces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The device's name in WrenDNS (a named client, else the host name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// When the router's lease ends (Unix seconds; 0 when unknown).
    pub expires_unix_seconds: u64,
    /// `router` (read from a `[[router]]`) or `mdns` (the name the device announces,
    /// `[clients] mdns`; no MAC).
    pub source: String,
    /// REQ: API-012 (T22.3) — the `[[router]]` whose answer named it (`udm`,
    /// `home-assistant`); absent for mDNS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub router: Option<String>,
    /// REQ: DNS-023 (T22.1) — the name it answers as in DNS (`kitchen-tablet.home.arpa`),
    /// with `[local] device_domain` set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    /// REQ: T8.2 (ADR-166, ADR-942) — a client the router remembers but doesn't see now (UniFi's
    /// offline clients). It is listed so the admin can see it, but it names no DNS name, gives
    /// no discovery binding and isn't counted in a network's devices.
    pub offline: bool,
    /// REQ: DNS-023 (T24.8, ADR-983) — the IPv6 addresses the router reports for the device
    /// (global and unique-local, never link-local), up to 4. With `[local] device_domain` set,
    /// each answers AAAA and an `ip6.arpa` PTR under `dnsName`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipv6: Vec<String>,
}

/// REQ: API-013 (T22.2) — a network: a LAN or VLAN a router reported, or a client group's
/// network that no router reported, with how many known devices are in it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInfo {
    #[schema(example = "IoT")]
    pub name: String,
    /// The network in CIDR form.
    #[schema(example = "192.168.20.0/24")]
    pub subnet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// The DHCP pool, when the router serves DHCP on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcp_start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcp_end: Option<String>,
    /// The domain the router hands out on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The router's own word for it (UniFi: `corporate`, `guest`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// `router` (a `[[router]]` reported it), `interface` (this node is directly on it, for example
    /// on a tagged VLAN interface; it is named after the interface) or `group` (only a
    /// `[[group]] networks` entry).
    pub source: String,
    /// The `[[router]]` that reported it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub router: Option<String>,
    /// The client group whose networks hold it (most specific), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Host addresses in it (without the network and broadcast addresses).
    pub addresses: u64,
    /// Devices known in it: the routers' DHCP clients, Home Assistant's devices, and mDNS
    /// names.
    pub devices: u64,
    /// `devices` as a share of `addresses`, 0–100.
    pub used_percent: f64,
    /// Of `devices`, those outside the DHCP pool (fixed addresses and reservations).
    pub outside_pool: u64,
}

/// Names a list shares with another (OBS-009).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListShare {
    pub list: String,
    pub names: u64,
}

/// REQ: FLT-004 (T24.28, ADR-992) - names a list shares with another list that does the same
/// thing, as a share of this list's own entries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListCover {
    /// The other list.
    pub list: String,
    /// Names both have.
    pub names: u64,
    /// `names` as a share of this list's entries, 0-100.
    pub percent: f64,
}

/// REQ: FLT-004 (T24.28, ADR-992) - one enabled list's overlap with the others.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListOverlapRow {
    pub name: String,
    /// `block` or `allow`.
    pub kind: String,
    /// `enforce` or `shadow`.
    pub mode: String,
    /// Entries in the active snapshot (names, regexes and modifier rules).
    pub entries: u64,
    /// Names no other list of its kind has: what turning it off would lose.
    pub unique: u64,
    /// Modifier rules and regexes: counted as unique, since overlap is by name.
    pub rules: u64,
    /// `(unique + rules)` as a share of `entries`, 0-100: what this list adds. 0 when it has
    /// no entries compiled yet.
    pub adds_percent: f64,
    /// The lists it shares names with, most shared first (at most 5).
    pub covered_by: Vec<ListCover>,
    /// Groups that name this list in their own `lists` (a list they use by name is never
    /// proposed for turning off).
    pub groups: Vec<String>,
}

/// A list a prune would turn off.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListPruneCandidate {
    pub name: String,
    pub entries: u64,
    pub unique: u64,
    /// What it adds as a share of its entries (the same number as in the overlap).
    pub adds_percent: f64,
    /// The most names turning it off, together with the others in this plan, could stop
    /// blocking: its own unique names and rules, and names it shares with other lists in the
    /// plan (an upper bound: a name another enabled list still has isn't lost).
    pub loses_at_most: u64,
    /// Lists that still have most of its names.
    pub covered_by: Vec<ListCover>,
}

/// An enabled list a prune keeps, and why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListPruneKept {
    pub name: String,
    pub reason: String,
}

/// REQ: FLT-004 (T24.28, ADR-992) - what a prune would turn off at a threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListPrunePlan {
    /// The threshold used: lists adding at most this share of their own entries.
    pub threshold_percent: f64,
    /// Lists that would be turned off, least-adding first.
    pub candidates: Vec<ListPruneCandidate>,
    /// Every other enabled list, with the reason it stays.
    pub kept: Vec<ListPruneKept>,
    /// An upper bound on the names the whole plan stops blocking (a share of the snapshot is
    /// `of_names`).
    pub loses_at_most: u64,
    /// Names in the active snapshot.
    pub of_names: u64,
    /// In a sentence.
    pub note: String,
    /// True when the lists changed after the last compile finished (a list turned off or
    /// edited): what each adds isn't known yet, so nothing is proposed. Preview again.
    pub compile_pending: bool,
    /// Version of the compiled snapshot the numbers come from (send it back to apply).
    pub snapshot_version: u64,
    /// Configuration version the plan was read at (send it back to apply).
    pub config_version: u64,
}

/// `GET /api/v1/lists/overlap` and `GET /api/v1/lists/prune-plan` parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PruneParams {
    /// Turn off lists adding at most this share of their entries, 0 to 50 (default 1).
    #[serde(rename = "thresholdPercent")]
    pub threshold_percent: Option<f64>,
}

/// REQ: FLT-004 (T24.28, ADR-992) - `POST /api/v1/lists/prune`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListsPruneRequest {
    /// Lists adding at most this share of their entries, 0 to 50 (default 1).
    #[serde(default)]
    pub threshold_percent: Option<f64>,
    /// The lists the person saw in the preview. Each must still be in the plan, or nothing is
    /// changed (409).
    pub names: Vec<String>,
    /// The preview's `snapshotVersion`: another compile since is a 409.
    pub snapshot_version: u64,
    /// The preview's `configVersion`: any configuration change since is a 409.
    pub config_version: u64,
}

/// REQ: FLT-004 (T24.28, ADR-992) - what a prune turned off.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListsPruneResult {
    /// The lists now off. They stay in the configuration: turn one on again in Manage lists.
    pub disabled: Vec<String>,
    /// The configuration version after the last change.
    pub config_version: u64,
    pub note: String,
}

/// `GET /analytics/vqlog` parameters (REQ: AGT-012).
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct VqlogParams {
    /// The query, for example `from -24h | where status = blocked | top 10 name`.
    #[param(example = "from -24h | where status = blocked | top 10 name")]
    pub q: String,
    /// Only parse and estimate the cost; don't scan.
    #[serde(rename = "dryRun")]
    pub dry_run: Option<bool>,
}

/// What a `vqlog` query costs (REQ: AGT-012).
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VqlogCost {
    /// Before scanning, from block headers: how many logged queries could match at most.
    pub estimated_rows: u64,
    pub segments: usize,
    pub blocks: usize,
    /// What the scan did (0 for a dry run).
    pub rows_scanned: u64,
    pub rows_matched: u64,
    pub elapsed_ms: u64,
}

/// A `vqlog` result: a table (REQ: AGT-012).
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VqlogResult {
    /// The query as understood, with the defaults filled in.
    pub query: String,
    /// `time` (with `bucket`), the keys (a `client` key adds `clientName`), then the
    /// statistics. Latencies are in ms.
    pub columns: Vec<String>,
    /// One array per row, in column order.
    #[schema(value_type = Vec<Vec<Object>>)]
    pub rows: Vec<Vec<serde_json::Value>>,
    /// Groups found before `limit`.
    pub groups: u64,
    pub cost: VqlogCost,
    /// The scan stopped early (`truncatedReason` says why); the numbers cover what it read.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_reason: Option<String>,
    /// Cluster nodes whose query log isn't here (not shipped to this node).
    pub missing_nodes: Vec<String>,
    /// REQ: AGT-012 (T9.12) — where the numbers come from: `querylog` (every query, kept
    /// `retention_days`) or `rollups` (counts by one breakdown, kept much longer).
    pub source: String,
    /// Something to know about the answer (a window longer than the query log keeps).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// `GET /analytics/new-domains` parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct NewDomainParams {
    /// Only domains first seen after this (RFC 3339 or relative, default `-24h`).
    pub since: Option<String>,
    /// Only this device (its address).
    pub client: Option<String>,
    /// At most this many (default 200, at most 2000).
    pub limit: Option<usize>,
}

/// A registrable domain a device contacted for the first time (REQ: OBS-009).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NewDomain {
    /// When it was first seen (RFC 3339).
    pub time: String,
    pub client: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[schema(example = "vendor.example")]
    pub domain: String,
    /// How machine-generated its name looks, 0 to 1 (0.6 and up is suspicious; `06` §7).
    pub dga_score: f32,
}

/// `GET /analytics/anomalies` parameters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AnomalyParams {
    /// Only findings whose window started after this (RFC 3339 or relative, default `-7d`).
    pub since: Option<String>,
    /// REQ: OBS-014 — `false`: only findings nobody acknowledged; `true`: only acknowledged
    /// ones. Default: both.
    pub acknowledged: Option<bool>,
    /// REQ: OBS-038 — `true`: muted findings are listed too, each with `mutedBy`. Default:
    /// they are left out, as they are from the badge and the alerts.
    pub muted: Option<bool>,
}

/// A device anomaly and its evidence (OBS-013). Alert-only: WrenDNS never acts on it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyFinding {
    /// REQ: OBS-014 — stable ID (from the kind, device, domain, and window): the same finding
    /// has the same ID on every node and after restarts. Acknowledge findings by it.
    #[schema(example = "6ab0f180a1b2c3d4")]
    pub id: String,
    /// `rate_spike`, `domain_volume`, `drift`, `beacon`, `nxdomain_storm`, or `dga`.
    #[schema(example = "domain_volume")]
    pub kind: String,
    /// The device's address, and its name when known.
    pub client: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// The registrable domain, for domain findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "vendor.example")]
    pub domain: Option<String>,
    /// The window examined (RFC 3339 start, and length in seconds).
    pub window_start: String,
    pub window_seconds: u32,
    /// What was seen, the device's usual value (± spread), and the bar it crossed.
    pub observed: f64,
    pub baseline: f64,
    pub spread: f64,
    pub threshold: f64,
    /// The finding in words, with the numbers.
    #[schema(example = "4100 queries in an hour; usually 119 ± 30")]
    pub detail: String,
    /// REQ: OBS-014, CLU-002 — the cluster nodes that found it (each learns from the queries it
    /// answers). Empty on a standalone node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
    /// REQ: OBS-014 — who acknowledged it and when; absent while nobody has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<AnomalyAckInfo>,
    /// REQ: OBS-031 — a beacon's (or a chatty loop's) rhythm when it was reported: 24 counts of
    /// gaps between its queries per log-spaced bin (bounds in `GET /api/v1/clients/{id}/rhythm`'s
    /// `binsS`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rhythm: Option<Vec<u32>>,
    /// REQ: OBS-036 — a finding to see, not an anomaly (`chatty_loop`): left out of the sidebar
    /// badge and the `anomaly` alert rule.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub informational: bool,
    /// REQ: OBS-038 (ADR-161) — the anomaly mute (its name) that matched this finding when it
    /// was created. A muted finding is kept and listed, but not counted in
    /// `wrendns_anomalies_total`, the sidebar badge, or the `anomaly` alert rule. Absent when no
    /// mute matched; listed only with `muted=true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "lg-tv-ptr-sweep")]
    pub muted_by: Option<String>,
}

/// REQ: OPS-011 (ADR-156) — `POST /system/support-package`: what the package should hold.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupportPackageRequest {
    /// `strict` (the default), `standard`, or `none`: how much is obfuscated.
    #[schema(example = "strict")]
    pub level: Option<String>,
    /// Names (a device, a group, a node, a host) to keep readable. At most 50.
    #[serde(default)]
    pub reveal: Vec<String>,
    /// Rows of the query log to include, newest first (0 to 1,000; `standard` and `none` only).
    #[serde(default)]
    pub query_sample: u32,
    /// Keep the pseudonym map in memory for one download (`GET /system/support-package/{id}/map`).
    #[serde(default)]
    pub keep_map: bool,
    /// REQ: OPS-011 (ADR-172) — one package for the whole cluster: every reachable node makes and
    /// redacts its own part under one key made for this package, so a device has the same
    /// pseudonym on every node and no real name or address leaves the node it is on. Not with
    /// `keepMap` (the names never leave their nodes, so there is no map). A node that doesn't
    /// answer, or is older than this feature, is listed in the manifest.
    #[serde(default)]
    pub cluster: bool,
}

/// REQ: OPS-011 (ADR-172) — what a node is asked for when a cluster package is made. It goes over
/// the cluster channel only (never as an API request body), with the key of this one package.
#[derive(Clone, Serialize, Deserialize)]
pub struct SupportCollectRequest {
    /// `strict`, `standard`, or `none`, as in [`SupportPackageRequest`].
    pub level: Option<String>,
    pub reveal: Vec<String>,
    pub query_sample: u32,
    /// The package's key: 64 hex digits, held in memory for the call and never stored.
    pub key: String,
    /// The most bytes of file content this node's part may hold (its share of the cap).
    pub max_bytes: usize,
}

// The key is the one secret of the request: whatever prints a read (a debug log, a panic message)
// must not print it.
impl std::fmt::Debug for SupportCollectRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupportCollectRequest")
            .field("level", &self.level)
            .field("reveal", &self.reveal.len())
            .field("query_sample", &self.query_sample)
            .field("key", &"<hidden>")
            .field("max_bytes", &self.max_bytes)
            .finish()
    }
}

/// REQ: OBS-014 (ADR-103) — a finding's stable ID: its window start (Unix seconds, 8 hex
/// digits) then an FNV-1a hash of its kind, device, domain, and window length (8 hex digits).
/// Every node that sees the same finding gives it the same ID, and the ID alone says how old the
/// finding is.
#[must_use]
pub fn anomaly_id(
    kind: &str,
    client: &str,
    domain: Option<&str>,
    window_start_s: u64,
    window_s: u32,
) -> String {
    let mut h: u32 = 0x811c_9dc5;
    let key = format!("{kind}|{client}|{}|{window_s}", domain.unwrap_or(""));
    for b in key.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    format!("{:08x}{h:08x}", window_start_s & 0xffff_ffff)
}

/// The window start an [`anomaly_id`] carries; `None` when `id` isn't one.
#[must_use]
pub fn anomaly_id_window(id: &str) -> Option<u64> {
    (id.len() == 16
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then(|| u64::from_str_radix(&id[..8], 16).ok())
    .flatten()
}

/// REQ: OBS-014 — an acknowledgement: someone looked at the finding.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyAckInfo {
    #[schema(example = "alice")]
    pub by: String,
    /// RFC 3339.
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// REQ: OBS-014 — `POST /analytics/anomalies/acknowledge` and `/unacknowledge`.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnomalyAckRequest {
    /// Finding IDs (`id` in `GET /analytics/anomalies`), 1 to 1,000.
    pub ids: Vec<String>,
    /// Why (acknowledging only; at most 200 characters), shown with the finding.
    #[serde(default)]
    #[schema(example = "the TV's monthly update")]
    pub note: Option<String>,
}

/// REQ: OBS-014 — what an acknowledge or unacknowledge changed.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyAckResult {
    /// Findings whose state changed (one already acknowledged doesn't count again).
    pub changed: u64,
    /// The IDs asked about that aren't current findings on any node that answered (still
    /// recorded when acknowledging, in case a node that found them was unreachable).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown: Vec<String>,
}

/// REQ: OBS-018 (ADR-109) — what a `shadow` list would have blocked (it never does), since
/// the node started (every node's, merged, in a cluster).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ShadowListStats {
    pub list: String,
    /// When counting started (RFC 3339): the earliest node's start, in a cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// Queries it would have blocked (answered normally instead).
    pub hits: u64,
    /// Devices those queries came from (each node counts its own; capped at 4,096 per node).
    pub devices: u64,
    /// The names it would have blocked most (hashed at privacy level 1 and above).
    pub top_names: Vec<NameCount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_hit_at: Option<String>,
    /// The nodes that counted (cluster nodes only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
}

/// A name and how often.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NameCount {
    pub name: String,
    pub count: u64,
}

/// REQ: OBS-018 (ADR-109) — a blocked name that looks like it shouldn't be: devices kept
/// retrying it, or it was answered normally soon after being blocked (someone paused
/// blocking or allowed it).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OverblockSuspect {
    /// Hashed at privacy level 1 and above.
    pub name: String,
    /// The lists that blocked it.
    pub lists: Vec<String>,
    /// Devices involved (none counted at privacy level 2 and above).
    pub devices: u64,
    /// Times a device asked for it 10 or more times within a minute while it was blocked
    /// (apps that break retry; ad libraries do too).
    pub retry_bursts: u64,
    /// Times a device got it answered normally within 10 minutes of a block (a pause, a
    /// quick allow, or an allowlist entry: someone wanted it).
    pub allowed_after_block: u64,
    /// RFC 3339.
    pub last_seen: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
}

/// REQ: OBS-019 (ADR-108) — one node's view of its upstreams' answers: second opinions
/// (sampled, `[upstream_check]`), DNSSEC verdicts, and the EDE codes they returned.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamChecks {
    /// The node (cluster nodes only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Second opinions are on (`sample_every` > 0).
    pub enabled: bool,
    /// One forwarded question in this many gets a second opinion.
    pub sample_every: u32,
    /// The upstream group asked (none: another member of the answering group).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Per upstream that answered.
    pub upstreams: Vec<UpstreamQuality>,
    /// The latest disagreements, newest first.
    pub recent: Vec<UpstreamDisagreement>,
}

/// REQ: OBS-019 — one upstream's answers since start.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamQuality {
    pub upstream: String,
    /// Second opinions by outcome: the same answer; different addresses (CDNs and geo-DNS
    /// do this); a different response code; filtered (one side had addresses, the other none
    /// or only 0.0.0.0/loopback); the second upstream didn't answer.
    pub same: u64,
    pub different_addresses: u64,
    pub different_rcode: u64,
    pub filtered: u64,
    pub unanswered: u64,
    /// DNSSEC verdicts on its answers (when `[dnssec] mode` validates).
    pub dnssec_secure: u64,
    pub dnssec_insecure: u64,
    pub dnssec_bogus: u64,
    pub dnssec_indeterminate: u64,
    /// The Extended DNS Error codes in its answers (RFC 8914).
    pub ede: Vec<EdeCount>,
}

/// REQ: OBS-019 — answers carrying one EDE code.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EdeCount {
    #[schema(example = 15)]
    pub code: u16,
    /// The registry's name (`Blocked`, `Censored`, `Filtered`, `Stale Answer`, ...).
    #[schema(example = "Blocked")]
    pub name: String,
    pub count: u64,
}

/// REQ: OBS-019 — two upstreams that answered the same question differently.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamDisagreement {
    /// RFC 3339.
    pub at: String,
    /// The name (hashed at privacy level 1 and above) and type.
    pub name: String,
    pub qtype: String,
    /// `different_addresses`, `different_rcode`, or `filtered`.
    pub result: String,
    /// Who answered first, and what.
    pub upstream: String,
    pub answer: String,
    /// The second opinion.
    pub reference: String,
    pub reference_answer: String,
}

/// REQ: OBS-020 (ADR-107) — one synthetic probe: a DNS listener asked through its own
/// protocol, or an extra target, from one node, and the listener's certificate.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    /// The node that probed (cluster nodes only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// What was asked: `udp://127.0.0.1:53`, `https://127.0.0.1:443/dns-query`, ...
    #[schema(example = "tls://127.0.0.1:853")]
    pub target: String,
    /// `udp`, `tcp`, `dot`, `doh`, `doh3`, or `doq`; or `api`: the web UI and API over HTTPS
    /// (`[api] tls`, ADR-149), checked with a `GET /livez`.
    pub proto: String,
    /// One of this node's listeners (else an extra `[probe] targets` entry).
    pub listener: bool,
    /// The last probe got a well-formed answer (any response code).
    pub ok: bool,
    /// How long it took.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    /// Why it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Probes failed in a row (2 or more degrade the health level).
    pub consecutive_failures: u32,
    /// When it last answered, and when it was last asked (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ok_unix_seconds: Option<u64>,
    pub checked_unix_seconds: u64,
    /// Not probed, and why (a listener that requires the PROXY protocol header).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    /// A TLS listener's certificate: when it expires and the days left (negative: expired).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_expires_unix_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_days_left: Option<i64>,
    /// Why the certificate couldn't be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_error: Option<String>,
    /// The certificate's SHA-256 fingerprint (colon-separated hex), to compare with the one a
    /// browser shows before trusting it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "3F:A1:…")]
    pub cert_sha256: Option<String>,
    /// The names and addresses the certificate covers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cert_names: Vec<String>,
    /// WrenDNS made the certificate itself (`[api] tls = { self_signed = true }`); it
    /// doesn't expire.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cert_self_signed: bool,
}

impl ProbeResult {
    /// The target without its path (`proto://host`): what every role may see, and what health
    /// reasons name (the DoH path is for admins only).
    #[must_use]
    pub fn public_target(&self) -> String {
        match self.target.split_once("://") {
            Some((head, rest)) => {
                let host = rest.split('/').next().unwrap_or(rest);
                format!("{head}://{host}")
            }
            None => self.target.clone(),
        }
    }

    /// REQ: API-902 (T27.14c; owner decision, 2026-11-27) — drop what only an admin sees of a
    /// listener's probe: the DoH path in the target, and the PROXY setting in the reason it was not
    /// probed.
    pub fn without_admin_fields(&mut self) {
        self.target = self.public_target();
        if self.cert_error.is_some() {
            // The error names the certificate file's path.
            self.cert_error = Some("the certificate can't be read".to_owned());
        }
        if self.skipped.as_deref().is_some_and(|s| s.contains("PROXY")) {
            self.skipped = Some("it is not probed".to_owned());
        }
    }
}

/// REQ: OBS-016 (ADR-105) — the service-level objectives, their error budgets, and how fast
/// they're being spent, over every node's answers.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SloStatus {
    /// `[slo] enabled`; when false there are no objectives.
    pub enabled: bool,
    /// Days each error budget covers (`[slo] window_days`).
    pub window_days: u32,
    pub objectives: Vec<SloObjective>,
    /// Cluster nodes that didn't answer (their answers aren't counted).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// REQ: OBS-016 — one objective: `availability` (answers that aren't SERVFAIL) or `latency`
/// (answers within `latencyMs`). Dropped queries got no answer and count for neither.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SloObjective {
    /// `availability` or `latency`.
    #[schema(example = "availability")]
    pub name: String,
    /// What counts as a good answer, in words.
    #[schema(example = "answers that aren't SERVFAIL")]
    pub good_means: String,
    /// The share of good answers aimed for, in percent.
    #[schema(example = 99.9)]
    pub target_percent: f64,
    /// The latency objective's threshold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u32>,
    /// Good answers over the window, in percent (none: no answers yet).
    pub sli_percent: Option<f64>,
    /// Good and all answers over the window.
    pub good: u64,
    pub total: u64,
    /// The window's error budget left, in percent: 100 untouched, 0 spent, below 0 overspent.
    pub budget_remaining_percent: Option<f64>,
    /// Burn rates over 5m, 30m, 1h, 6h, and 3d.
    pub burn_rates: Vec<SloBurn>,
    /// `fast` (14.4× over 1h and 5m), `slow` (6× over 6h and 30m), or `ticket` (1× over 3d
    /// and 6h); none when the budget lasts. `fast` and `slow` degrade the health level and
    /// fire `slo_burn` alerts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "fast")]
    pub alert: Option<String>,
    /// One sentence with the numbers.
    pub summary: String,
}

/// REQ: OBS-016 — the error budget's burn rate over one window: the bad share divided by the
/// share the target allows (1 spends exactly the budget over the objective's window).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SloBurn {
    /// `5m`, `30m`, `1h`, `6h`, or `3d`.
    #[schema(example = "1h")]
    pub window: String,
    /// None when there were no answers (or no hourly data for `3d`).
    pub rate: Option<f64>,
    /// Answers in the window, and bad ones.
    pub total: u64,
    pub bad: u64,
}

/// REQ: OBS-015 (ADR-104) — how WrenDNS is doing, in one word, with the reasons.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    /// `healthy`, `degraded` (something needs a look, DNS answers), or `severe` (DNS is failing
    /// or about to).
    #[schema(example = "degraded")]
    pub level: String,
    /// Every condition found, the most serious first. Empty when healthy.
    pub reasons: Vec<HealthReason>,
    /// When it was worked out (RFC 3339).
    pub checked_at: String,
    /// Cluster nodes that didn't answer (their own conditions aren't included).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
    /// REQ: OPS-010 — nodes in maintenance: their conditions are left out of `reasons` and the
    /// level until the window ends (a node in maintenance still answers DNS).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub maintenance: Vec<NodeMaintenance>,
}

/// REQ: OPS-010 (ADR-118) — a node's maintenance window: it reports not ready (balancers stop
/// sending it new queries), keeps answering, and is left out of alerts, the health level, and
/// elections until `until`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeMaintenance {
    /// The node (its pod, site, or ID), in lists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// When it ends (RFC 3339).
    pub until: String,
    /// When it started (RFC 3339).
    pub since: String,
    #[schema(example = "SD card swap")]
    pub reason: String,
    /// Who started it: a user, `<user> via <site>` from another node, or an agent.
    #[schema(example = "alice via pi")]
    pub by: String,
    pub seconds_left: u64,
}

/// `POST /api/v1/nodes/{id}/maintenance`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MaintenanceRequest {
    /// How long, in seconds: 60 to 86,400 (agents at most 7,200). Default: the node's
    /// `[node] maintenance_default_secs` (3,600).
    #[serde(default)]
    #[schema(example = 3600)]
    pub for_secs: Option<u32>,
    /// Why, in a few words (1 to 200 characters, one line). Shown on the Cluster page, in the
    /// health panel, and in the audit log.
    #[serde(default)]
    #[schema(example = "SD card swap")]
    pub reason: Option<String>,
    /// For the primary under automatic failover: hand the primary role to another eligible
    /// node first (about 30 s without configuration changes). Default true; ignored on other
    /// nodes.
    #[serde(default)]
    pub handover: Option<bool>,
}

/// A node's maintenance after a start or end.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceResult {
    /// The node (its pod, site, or ID).
    pub node: String,
    /// Whether it's in maintenance now.
    pub active: bool,
    /// The window, while active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<NodeMaintenance>,
    /// Starting on the primary: `started` (another node is being elected; the old primary
    /// follows), `unavailable` (manual failover, or no other eligible node reachable: it stays
    /// the primary), or `declined` (`handover: false`). `not_needed` on other nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handover: Option<String>,
    /// What to know, in one sentence (e.g. promote another node first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// REQ: CLU-014 — `"all"`: every device (the node's infrastructure, cluster nodes, and
/// excluded devices are never dropped).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DrillAll {
    All,
}

/// REQ: CLU-014 — who a drill stops answering: `"all"`, `{ "clients": [...] }` (addresses,
/// device names, or Kubernetes workloads), or `{ "group": "iot" }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum DrillTargets {
    All(DrillAll),
    Clients {
        #[schema(example = json!(["10.20.2.14", "kids-tablet"]))]
        clients: Vec<String>,
    },
    Group {
        #[schema(example = "iot")]
        group: String,
    },
}

/// `POST /api/v1/nodes/{id}/drill`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DrillRequest {
    /// How long, in seconds: 15 to 300 (default 60).
    #[serde(default)]
    #[schema(example = 60)]
    pub for_secs: Option<u32>,
    pub targets: DrillTargets,
    /// Why, in a few words (1 to 200 characters, one line).
    #[serde(default)]
    #[schema(example = "does the Pi's second server work?")]
    pub reason: Option<String>,
    /// On the primary under automatic failover: hand the role over first (default true).
    #[serde(default)]
    pub handover: Option<bool>,
    /// `drop` (default: no answer at all, like a dead server) or `refused` (REFUSED at once:
    /// faster, but some devices don't try their next server on it).
    #[serde(default)]
    pub mode: Option<DrillMode>,
}

/// REQ: CLU-014 (owner 2026-10-19) — what the drilled node does with its targets' queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrillMode {
    #[default]
    Drop,
    Refused,
}

/// REQ: CLU-014 — one precondition and whether it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DrillCheck {
    /// `other_node`, `maintenance`, `recent_drill`, `rollout`, `health`, `targets`.
    pub name: String,
    pub ok: bool,
    /// In one sentence.
    pub detail: String,
}

/// REQ: CLU-014 — a device a drill would stop answering (a dry run lists them).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DrillTargetDevice {
    /// Its address (or a workload's name).
    pub client: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// REQ: CLU-014 — a drill started (or, with `dryRun`, what would happen).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DrillStart {
    /// The drill's ID (empty on a dry run).
    pub id: String,
    /// The node (its pod, site, or ID).
    pub node: String,
    pub dry_run: bool,
    /// When it started and ends (RFC 3339; on a dry run, as if now).
    pub since: String,
    pub until: String,
    /// The targets in words.
    #[schema(example = "group iot")]
    pub targets: String,
    /// Devices seen on the node in the last hour that the drill stops answering.
    pub targets_resolved: u32,
    /// Devices seen on the node in the last hour (the report's baseline).
    pub baseline: u32,
    /// Every precondition (on a start, all hold).
    pub checks: Vec<DrillCheck>,
    /// On a dry run: the devices it would stop answering (at most 200).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<DrillTargetDevice>,
    /// As for maintenance: `started`, `unavailable` (the drill runs anyway: DNS is what's
    /// tested), `declined`, `not_needed`, or `none`.
    pub handover: String,
    /// In plain words, what it will do to devices.
    pub preview: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// REQ: CLU-014 — the drill running on a node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ActiveDrill {
    pub id: String,
    pub node: String,
    pub since: String,
    pub until: String,
    pub seconds_left: u64,
    pub targets: String,
    pub reason: String,
    pub by: String,
    /// Queries not answered so far, and from how many devices.
    pub dropped: u64,
    pub devices_dropped: u32,
}

/// REQ: CLU-014 — one device in a drill report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DrillDevice {
    /// Its address, or a Kubernetes workload's key.
    pub client: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// `followed` (asked another node after its first unanswered query, by 5 s after the end),
    /// `stuck` (3 or more unanswered and no such answer: no working second server), `quiet`
    /// (nothing unanswered, or too little: unknown), or `elsewhere` (not a target or in the
    /// baseline; asked another node: informational).
    pub verdict: String,
    /// Queries the drilled node didn't answer.
    pub dropped: u32,
    /// Queries other nodes answered during the drill.
    pub queries_elsewhere: u32,
    /// First query elsewhere − first unanswered query (`followed` with something dropped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_to_failover_ms: Option<u64>,
    /// Whether it asked the drilled node again within 15 minutes after the drill (false:
    /// it stayed on the other node, "sticky"); absent until checked, and for other verdicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returned: Option<bool>,
    /// The nodes that answered it during the drill.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
}

/// REQ: CLU-014 — queries one node answered (or dropped) during a drill.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DrillNodeCount {
    pub node: String,
    pub queries: u64,
    pub devices: u32,
}

/// REQ: CLU-014 — a drill in a list.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DrillSummary {
    pub id: String,
    /// The drilled node.
    pub node: String,
    pub since: String,
    pub until: String,
    /// When it really ended (early with DELETE, or a restart).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<String>,
    pub targets: String,
    pub reason: String,
    /// Who started it: a user, an agent, or `schedule` (`[drill] schedule`).
    pub by: String,
    /// `drop` or `refused`.
    #[serde(default)]
    pub mode: DrillMode,
    /// `running`, `collecting` (the 60-second grace and the other nodes' parts),
    /// `complete`, or `cancelled` (a restart ended it; no report).
    pub status: String,
    /// followed / (followed + stuck), in percent; absent when neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_percent: Option<f64>,
    pub followed: u32,
    pub stuck: u32,
    pub quiet: u32,
    pub elsewhere: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub median_failover_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p90_failover_ms: Option<u64>,
    /// A resolver pod behind one balancer address: the verdicts measure the balancer.
    pub via_balancer: bool,
    /// Nodes whose part is missing (unreachable, or too old to record drills).
    pub missing_nodes: Vec<String>,
}

/// REQ: CLU-014 — a full drill report.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DrillReport {
    #[serde(flatten)]
    pub summary: DrillSummary,
    /// Devices seen on the node in the hour before the drill.
    pub baseline: u32,
    /// Every device in the baseline, the targets, or seen anywhere during the drill (privacy
    /// level 2 and above: empty, counts only).
    pub devices: Vec<DrillDevice>,
    /// Queries per node during the drill.
    pub nodes: Vec<DrillNodeCount>,
    /// `viaBalancer`: last unanswered query − start (how long the balancer kept sending to the
    /// not-ready pod).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balancer_switch_ms: Option<u64>,
    /// Devices not tracked because a table was full.
    pub overflow: u64,
    /// Whether `returned` has been checked (15 minutes after the drill).
    pub returned_checked: bool,
}

/// `GET /api/v1/drills`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DrillPage {
    pub items: Vec<DrillSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub missing_nodes: Vec<String>,
}

/// REQ: CLU-014 — one node's share of a device's queries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AffinityNode {
    pub node: String,
    pub queries: u64,
}

/// REQ: CLU-014 — how a device's queries spread over the nodes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AffinityRow {
    pub client: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub queries: u64,
    pub nodes: Vec<AffinityNode>,
    /// The node it used most, and its share of the queries.
    pub top_node: String,
    pub top_share_percent: f64,
    /// `mostly <node>` (90 % or more on one node) or `both` / `several`.
    pub label: String,
}

/// `GET /api/v1/clients/affinity`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AffinityPage {
    pub window_days: u32,
    pub items: Vec<AffinityRow>,
    pub missing_nodes: Vec<String>,
    /// What the view can't tell.
    pub caveat: String,
}

/// REQ: OBS-015 — one condition behind [`Health`].
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthReason {
    /// `degraded` or `severe`.
    pub level: String,
    /// Stable: `upstream_down`, `upstream_group_down`, `not_serving`, `node_down`,
    /// `sync_lag`, `primary_unreachable`, `list_failing`, `list_stale`, `rate_limited`, `servfail_rate`, `disk_full`,
    /// `slo_burn`, `probe_failing`, `cert_expiring`, `cert_expired`, `cluster_pinned`,
    /// `rollout_stuck`, `discovery_worker_failing`, `discovery_worker_version_mismatch`,
    /// `discovery_agent_failing`,
    /// `guarded_ignored`, `guarded_bind_fallback`, `secret_not_held`, `names_in_files`,
    /// `listener_gate_default`, `listener_gate_stale`, `listener_not_applied`, `upgrade_gate_holding`,
    /// `locations_held`.
    #[schema(example = "upstream_down")]
    pub code: String,
    /// In words, with the numbers.
    #[schema(example = "upstream quad9 isn't answering (its circuit breaker is open)")]
    pub summary: String,
    /// The node it's about (cluster nodes only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Where to look in the web UI (a `#/…` path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "#/upstreams")]
    pub link: Option<String>,
}

/// The cluster as this node sees it (REQ: CLU-008): every node with its health, sync, and
/// serving state, a timeline, and a pass/fail check list.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterView {
    /// False on a standalone node (everything else is then empty).
    pub enabled: bool,
    pub cluster_id: Option<String>,
    pub name: Option<String>,
    /// The node answering this request.
    pub this_node: Option<String>,
    /// The newest configuration version any node reports.
    pub newest_config_seq: u64,
    /// Every check passed.
    pub healthy: bool,
    pub checks: Vec<ClusterCheck>,
    /// This node first, then peers by site and ID.
    pub nodes: Vec<ClusterNode>,
    /// Recent events, newest first.
    pub events: Vec<ClusterEvent>,
    /// Where the cluster's configuration comes from: `api` or `gitops` (ADR-048).
    pub authority: Option<String>,
    /// Versions this node published that the cluster moved on without (ADR-051), newest first.
    pub conflicts: Vec<ClusterConflict>,
    /// How the cluster fails over (ADR-056).
    pub failover: Option<ClusterFailover>,
    /// The Git repository the configuration comes from, when it does (ADR-049).
    pub source: Option<ClusterSource>,
    /// A standalone node's own machine (T6.11); in a cluster, each node carries its own.
    pub host: Option<HostReport>,
    /// REQ: CLU-013 — the staged rollout and the pin, in brief (`GET /cluster/rollout` has the
    /// detail).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollout: Option<ClusterRollout>,
}

/// REQ: CLU-013 — the staged rollout and the pin, as the cluster view shows them.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterRollout {
    /// `none`, `canary`, `waiting`, or `pinned` (see `RolloutStatus`).
    pub stage: String,
    /// The version baking, `epoch.seq`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The canary nodes it went to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub canaries: Vec<String>,
    /// When the bake ends (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bake_ends: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<ClusterPin>,
    /// How long canaries have been set with none online (seconds): changes reach every node at
    /// once meanwhile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canaries_offline_seconds: Option<u64>,
    /// The last version the guard failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<RolloutFailure>,
}

/// REQ: CLU-013 — a version the guard failed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutFailure {
    /// `epoch.seq`.
    pub version: String,
    pub reason: String,
    /// RFC 3339.
    pub at: String,
}

/// REQ: CLU-008 (T6.11) — the machine a node runs on: its latest sample, what looks wrong,
/// and the last hour. Values the node couldn't read are absent (see `unavailable`).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostReport {
    pub latest: HostInfo,
    /// Up to an hour of samples (every 15 s), oldest first.
    pub history: Vec<HostPoint>,
}

/// One host sample, with sizes in bytes and shares in percent.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostInfo {
    /// When it was sampled (RFC 3339, the node's clock).
    pub sampled_at: String,
    pub os: Option<String>,
    pub kernel: Option<String>,
    pub arch: String,
    pub host_uptime_seconds: Option<u64>,
    pub cpus: Option<u32>,
    pub load1: Option<f64>,
    pub load5: Option<f64>,
    pub load15: Option<f64>,
    /// Host CPU busy over the last 15 s.
    pub cpu_percent: Option<f64>,
    pub mem_total_bytes: Option<u64>,
    pub mem_available_bytes: Option<u64>,
    /// `100 × (1 − available / total)`.
    pub mem_used_percent: Option<f64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    /// The container's (cgroup's) memory limit, when it has one.
    pub cgroup_mem_limit_bytes: Option<u64>,
    pub cgroup_mem_used_bytes: Option<u64>,
    pub cgroup_mem_used_percent: Option<f64>,
    /// Processes killed for lack of memory in this container, ever.
    pub oom_kills: Option<u64>,
    /// The container's CPU quota, in cores.
    pub cgroup_cpu_quota_cores: Option<f64>,
    /// Share of the last 15 s the container was throttled by its quota.
    pub throttled_percent: Option<f64>,
    /// The filesystem holding the data directory.
    pub disk_total_bytes: Option<u64>,
    pub disk_free_bytes: Option<u64>,
    pub disk_used_percent: Option<f64>,
    pub qlog_bytes: Option<u64>,
    pub snapshot_bytes: Option<u64>,
    /// What this process writes to storage (SD-card wear on a Pi).
    pub write_bytes_per_second: Option<u64>,
    pub process_rss_bytes: Option<u64>,
    pub open_fds: Option<u32>,
    pub max_fds: Option<u32>,
    pub threads: Option<u32>,
    /// The hottest thermal zone (on a Pi, the system-on-chip).
    pub temperature_c: Option<f64>,
    /// Its clock minus this node's, from heartbeats (peers only).
    pub clock_offset_ms: Option<i64>,
    /// Sources it couldn't read: `memory`, `load`, `cpu`, `process`, `cgroup`, `thermal`,
    /// `disk`, `os`.
    pub unavailable: Vec<String>,
    /// What looks wrong, in plain words (low disk, memory pressure, heat, clock drift).
    pub warnings: Vec<String>,
}

/// A point of the last hour, for trend lines.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostPoint {
    /// Unix seconds.
    pub t: u64,
    pub cpu_percent: Option<f64>,
    pub mem_used_percent: Option<f64>,
    pub load1: Option<f64>,
    pub disk_used_percent: Option<f64>,
    pub temperature_c: Option<f64>,
}

/// The cluster's configuration from Git (ADR-049): the commit in use and the last check.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterSource {
    pub repo: String,
    pub git_ref: String,
    pub path: String,
    /// The commit every node should be serving.
    pub commit: Option<String>,
    pub author: Option<String>,
    /// Commit time (RFC 3339).
    pub committed_at: Option<String>,
    pub subject: Option<String>,
    /// The allowed signer who signed it (with `require_signed`).
    pub signed_by: Option<String>,
    /// When the primary last checked the ref (RFC 3339; on the primary only).
    pub checked_at: Option<String>,
    /// Why the last check failed, or why the newest commit was refused.
    pub error: Option<String>,
    /// The newest commit isn't acceptable (invalid, unsigned, rewound): the cluster stays on
    /// `commit`.
    pub refused: bool,
}

/// Automatic failover as this node sees it (ADR-056).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterFailover {
    /// `manual` (promote by hand) or `auto` (elected by vote).
    pub mode: String,
    /// Whether elections run: `auto`, with three or more voters, this node one of them.
    pub active: bool,
    /// Eligible nodes plus witnesses.
    pub voters: u32,
    /// Voters this node has a stream to (itself included).
    pub reachable_voters: u32,
    /// This node is the elected primary and its lease holds.
    pub lease_held: bool,
    /// How long its lease still runs, in seconds (primaries only).
    pub lease_seconds_left: Option<f64>,
    /// The epoch and node this node last voted for.
    pub voted_epoch: u64,
    pub voted_for: Option<String>,
    /// REQ: CLU-005 (T24.38, ADR-1018) — voters whose link to this node dropped three or more
    /// times in the last ten minutes while both processes stayed up (a link that comes and goes;
    /// a restart or an upgrade of either node is not counted). Empty when all are steady.
    #[serde(default)]
    pub unstable_voters: Vec<UnstableVoter>,
}

/// REQ: CLU-005 (T24.38, ADR-1018) — a voter this node reaches only some of the time.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UnstableVoter {
    pub node_id: String,
    /// How many times its link dropped within `windowSeconds` (not counting a drop the voter
    /// came back from as a restarted process).
    pub drops: u32,
    pub window_seconds: u64,
    /// Seconds since the last drop.
    pub last_drop_seconds_ago: u64,
}

/// A version an old primary published after a newer primary took over: never applied
/// anywhere; listed so the change can be re-made on the current primary.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterConflict {
    pub epoch: u64,
    pub seq: u64,
    /// When this node published it (RFC 3339).
    pub published_at: String,
    /// When the newer primary's version arrived (RFC 3339).
    pub detected_at: String,
    pub new_primary: String,
    /// Settings that differ from the current primary's version (dotted paths).
    pub changed: Vec<String>,
}

/// `POST /api/v1/cluster/promote`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromoteRequest {
    /// Promote even though this node can't publish configuration under the cluster's
    /// authority (configuration from Git, and no Git-managed node reachable): it coordinates the
    /// cluster and keeps the last version, and publishes nothing new (ADR-048).
    #[serde(default)]
    pub emergency: bool,
    /// From a signed-in session: your password, to confirm (`spec/12` §5). Not needed with
    /// an API token or for `dryRun`.
    #[serde(default)]
    pub password: Option<String>,
    /// From a signed-in session with two-factor sign-in on: the current code.
    #[serde(default)]
    pub totp: Option<String>,
}

/// What promoting this node would do (`POST /cluster/promote?dryRun=true`, AGT-002).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PromotePlan {
    /// Always false: nothing changed.
    pub applied: bool,
    /// The epoch this node would take.
    pub epoch: u64,
    /// It would coordinate without publishing new configuration (ADR-048).
    pub emergency: bool,
    /// What would happen, in one sentence.
    pub impact: String,
}

/// What removing a node from the cluster did, or with `dryRun` would do
/// (`DELETE /api/v1/cluster/nodes/{id}`, CLU-001, ADR-155).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[allow(clippy::struct_excessive_bools)] // independent facts about the node
#[serde(rename_all = "camelCase")]
pub struct NodeRemoval {
    pub node_id: String,
    pub site: String,
    /// It was connected or heard from within the last few heartbeats.
    pub up: bool,
    /// It could vote and be primary, so it holds a copy of the cluster key.
    pub eligible: bool,
    /// It only voted.
    pub witness: bool,
    /// It was a Kubernetes resolver pod.
    pub ephemeral: bool,
    /// Rotate the cluster CA if this node is lost or can't be trusted: removal stops the
    /// cluster accepting it, but it keeps its copy of the key.
    pub held_cluster_key: bool,
    /// Voters (eligible nodes and witnesses) left.
    pub voters_after: u32,
    /// Whether automatic failover still runs (it needs three voters).
    pub automatic_failover_after: bool,
    /// False for `dryRun`: nothing changed.
    pub removed: bool,
    /// What to do or expect next, one sentence each.
    pub notes: Vec<String>,
}

/// REQ: CLU-015 (ADR-903 §6) — one member's stored secrets. Stamps are `epoch.seq`; a value is
/// never here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterSecrets {
    /// The newest stamp in its secrets head.
    pub head: Option<String>,
    /// The head it has applied from the primary (the primary's own, on the primary).
    pub applied: Option<String>,
    /// Its applied head is the primary's head: same stamps and digest.
    pub in_sync: bool,
    /// Live secrets it can't read here (encrypted under a key it doesn't have, or damaged).
    pub unreadable: u32,
    /// Secrets the primary holds but couldn't decrypt to send: this node keeps its own copy.
    pub held: u32,
}

/// REQ: CLU-009 (T24.33, ADR-1011) — a witness's part in the election, as this node sees it. A
/// witness only votes: it has no configuration, no secrets and no DNS.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterVote {
    /// Seconds since it last answered a vote request or lease renewal from this node (absent: this
    /// node hasn't asked it, as in manual failover or on a node that isn't the primary).
    pub last_reply_seconds_ago: Option<u64>,
    /// Seconds since it last granted one.
    pub last_grant_seconds_ago: Option<u64>,
    /// The epoch it reported in its last reply (the epoch it voted in).
    pub voted_epoch: Option<u64>,
}

/// One node in [`ClusterView`].
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[allow(clippy::struct_excessive_bools)] // independent flags of one record
#[serde(rename_all = "camelCase")]
pub struct ClusterNode {
    pub node_id: String,
    pub site: String,
    /// A Kubernetes resolver pod (CLU-009): dropped when no longer heard from.
    pub ephemeral: bool,
    /// Votes in automatic failover only (ADR-056). A witness has no configuration version, no
    /// secrets and no DNS: `configSeq`, `configLag`, `secrets` and `ready` mean nothing for it
    /// (REQ: CLU-009, T24.33, ADR-1011), and the checks and alerts about them skip it.
    pub witness: bool,
    /// REQ: CLU-009 (T24.33) — for a witness: its vote state (absent for other nodes).
    pub vote: Option<ClusterVote>,
    /// The cluster protocol it speaks (CLU-010); nodes within one version work together.
    pub protocol: u32,
    /// The Git commit of the configuration it serves (ADR-049).
    pub source_commit: Option<String>,
    /// `primary` or `replica`.
    pub role: String,
    /// The node answering this request.
    pub this_node: bool,
    pub eligible: bool,
    pub version: String,
    /// Heard from within 15 s (always true for this node), by this node or, for a member it has
    /// no stream to, by a peer that says so (`link` `relayed`).
    pub up: bool,
    /// A stream to it is open (this node: n/a, true).
    pub connected: bool,
    /// `self`, `inbound` (it connected to this node), `outbound`, or `relayed` (no stream: a
    /// peer reports it up, as the primary does for a replica in manual failover).
    pub link: String,
    pub last_seen_seconds_ago: u64,
    /// Round-trip time over the cluster link.
    pub rtt_ms: Option<u32>,
    pub config_seq: u64,
    /// Versions behind the newest.
    pub config_lag: u64,
    /// How long it has been behind (absent when in sync).
    pub behind_seconds: Option<u64>,
    /// REQ: OBS-010 (T24.5, fork #2) — a replica's time without reaching its primary, in seconds
    /// (the `primary_unreachable` alert and the health icon read it). Absent when it reaches the
    /// primary, is the primary, or isn't heard from.
    pub primary_silent_seconds: Option<u64>,
    /// Serving DNS (listeners bound, not shutting down).
    pub ready: bool,
    /// Queries per second over the last minute, to two decimals (a node one minor version older
    /// reports whole numbers).
    pub qps: f64,
    /// SERVFAIL share over the last minute, percent.
    pub servfail_percent: f64,
    /// Upstream p90 this hour.
    pub upstream_p90_ms: f64,
    pub uptime_seconds: u64,
    /// This node only: when its cluster certificate expires (RFC 3339).
    pub cert_expires_at: Option<String>,
    /// How the node's own configuration is managed: `gitops` or `file` (ADR-048).
    pub config_source: Option<String>,
    /// The machine it runs on (T6.11); absent from older nodes and before the first sample.
    pub host: Option<HostReport>,
    /// REQ: API-902 (T27.14g0, ADR-1113) - the URL its web UI and API answer on (`https://host:port`),
    /// as the node announces it; absent from an older node, from a node that cannot name one and from
    /// one not heard from. A card links to the node's own address from it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    /// REQ: CLU-015 (ADR-903 §6) — its stored secrets: stamps and counts, never a value. Absent
    /// from older nodes and from nodes not heard from.
    pub secrets: Option<ClusterSecrets>,
    /// REQ: CLU-008 (T6.14) — the Kubernetes node and pod it runs in (absent elsewhere and
    /// from older nodes).
    pub kube_node: Option<String>,
    pub pod: Option<String>,
    /// When its process started (RFC 3339); absent from older nodes.
    pub started_at: Option<String>,
    /// Restarts this node has seen since it started itself (0 for this node).
    pub restarts: u32,
    /// Its cache: entries, and over the last minute the cache share of its answers that weren't
    /// blocked or local, as on the dashboard (absent without any).
    pub cache_entries: Option<u64>,
    pub cache_hit_percent: Option<f64>,
    /// Its share of the queries the nodes that are up answered over the last minute, percent
    /// (absent when there were none).
    pub query_share_percent: Option<f64>,
    /// REQ: OPS-010 — its maintenance window, while it's in maintenance (older nodes never
    /// report one).
    pub maintenance: Option<NodeMaintenance>,
}

/// A cluster event (joins, connections, published and applied versions, failures).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterEvent {
    /// RFC 3339.
    pub at: String,
    /// `joined`, `connected`, `disconnected`, `restarted`, `published`, `applied`,
    /// `sync_failed`, `rejected`.
    pub kind: String,
    pub node_id: String,
    pub detail: String,
}

/// One health check with a plain-language fix when it fails.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterCheck {
    /// Stable ID: `peers_up`, `primary_present`, `in_sync`, `sync_errors`, `serving`, `certificate`,
    /// `failover`, `voter_links` (a voter reached only some of the time, T24.38).
    pub id: String,
    pub ok: bool,
    pub summary: String,
    /// What to do about it (failing checks only).
    pub fix: Option<String>,
}

/// REQ: CLU-013 — the guard's readings over a bake.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuardReadings {
    /// The canaries' (and the primary's) SERVFAIL share, in percent, over the bake before the
    /// rollout began.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_percent: Option<f64>,
    /// The same share during the bake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_percent: Option<f64>,
    /// Answers the canaries (and the primary) gave during the bake (the share is judged from
    /// 50 on).
    pub answers: u64,
    /// Why the guard failed the version, when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// REQ: CLU-013 — what pins the cluster.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterPin {
    /// The version whose content every node serves, `epoch.seq`.
    #[schema(example = "3.124")]
    pub to: String,
    /// RFC 3339.
    pub since: String,
    /// Who pinned it: a user, `<user> via <node>`, or `the guard`.
    pub by: String,
    pub reason: String,
    /// What the pin holds back: JSON Patch operations from the pinned version's shared
    /// configuration to the one the primary would publish once unpinned (the primary only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub diff: Vec<serde_json::Value>,
    /// The same, one sentence per section (`list: changed`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<String>,
}

/// REQ: CLU-013 — one node during a rollout.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutNode {
    pub node: String,
    pub site: String,
    /// Whether it's a canary (of the rollout in progress, or under the settings).
    pub canary: bool,
    /// The version it applied (its `seq`).
    pub applied_seq: u64,
    pub ready: bool,
    pub connected: bool,
    /// Its SERVFAIL share now, in percent.
    pub servfail_percent: f64,
}

/// REQ: CLU-013 — `GET /api/v1/cluster/rollout`: the rollout in progress, the guard, and the
/// pin.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutStatus {
    /// Whether the answer comes from the primary (a replica that can't reach it shows what it
    /// knows from the version it applied).
    pub from_primary: bool,
    /// `[cluster.rollout] canaries`: node IDs, `site:<name>`, or `ephemeral`; empty means
    /// changes reach every node at once.
    pub canaries: Vec<String>,
    pub bake_secs: u32,
    /// The version every node runs (or is getting), `epoch.seq`.
    #[schema(example = "3.124")]
    pub stable: String,
    /// `none`, `canary` (a version is baking), `waiting` (canaries are set and none is online:
    /// the change goes to every node after a minute), or `pinned`.
    #[schema(example = "canary")]
    pub stage: String,
    /// The version baking, `epoch.seq`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// When the bake began and ends (RFC 3339), and the seconds left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bake_ends: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds_left: Option<u64>,
    /// The canary nodes the version went to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rollout_canaries: Vec<String>,
    /// The guard's readings so far, or of the last decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readings: Option<GuardReadings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<ClusterPin>,
    pub nodes: Vec<RolloutNode>,
    /// Why the last change went to every node at once although canaries are set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    /// Since when a change has waited for a canary (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting_since: Option<String>,
}

/// REQ: CLU-013 — one kept version.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterVersion {
    /// `epoch.seq`.
    #[schema(example = "3.124")]
    pub version: String,
    /// RFC 3339.
    pub created: String,
    /// What made it: this node's configuration, a Git commit.
    pub by: String,
    /// `stable`, `canary`, `canary_promoted`, `canary_failed`, `superseded`, `aborted`, or
    /// `pinned_to`.
    #[schema(example = "canary_promoted")]
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readings: Option<GuardReadings>,
    /// For a pin: the version whose content it serves, and why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The filter snapshot it carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_version: Option<u64>,
    /// Every node runs it (or is getting it) now.
    pub current: bool,
    /// Its files are all kept, so the cluster can be pinned to it.
    pub pinnable: bool,
}

/// REQ: CLU-013 — `GET /api/v1/cluster/versions`: newest first.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterVersions {
    pub items: Vec<ClusterVersion>,
    /// How many are kept (`[cluster.rollout] history`).
    pub history: u32,
}

/// REQ: CLU-013 — `POST /api/v1/cluster/versions/{version}/pin`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinRequest {
    /// Why, in a few words (1 to 200 characters, one line): shown on the Cluster page, in the
    /// `cluster_pinned` alert, and in the audit log.
    #[serde(default)]
    #[schema(example = "the new upstream group breaks banking sites")]
    pub reason: Option<String>,
}

/// REQ: CLU-013 — what a rollout or pin action did (or, as a dry run, would do).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RolloutAction {
    /// In one sentence.
    #[schema(example = "pinned to version 3.124 (published as 131)")]
    pub done: String,
    /// A dry run: nothing changed.
    pub dry_run: bool,
    /// For a pin: what changes on every node, as JSON Patch from the version served now to
    /// the pinned one, and one sentence per section.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub diff: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<String>,
    /// The configuration version the action was checked against (plans send it back in
    /// `If-Match`).
    pub config_version: u64,
}

/// REQ: OBS-033 (ADR-133) — one change marker: something done to a node, or that it did to
/// itself, at a moment. The same shape is a line of `<data_dir>/annotations.jsonl`. Which
/// fields are set depends on `kind`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Annotation {
    /// When, RFC 3339 UTC.
    #[schema(example = "2026-10-13T02:52:11.000Z")]
    pub t: String,
    /// The same, Unix milliseconds.
    pub t_unix_ms: u64,
    /// `config.applied`, `build.started`, `node.restarted`, `lists.refreshed`, `rollout.stage`,
    /// `maintenance.entered`, `maintenance.left`, `blocking.paused`, `blocking.resumed`,
    /// `cache.flushed`, `upstream.breaker`, `drill.started`, `drill.ended` (CLU-014), or
    /// `note`.
    #[schema(example = "config.applied")]
    pub kind: String,
    /// What happened, in one sentence.
    #[schema(example = "configuration 312 applied (gitops, 3 sections changed)")]
    pub summary: String,
    /// The node it happened on (federated reads; a standalone node leaves it out).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// `config.applied`: where the change came from: `ui` (a signed-in user), `api` (an API
    /// token), `agent` (an agent token), `gitops`, `file` (the config files were reloaded),
    /// or `cluster` (a replica applying the primary's version).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Who, when known: a user, `token:<name> (owner: <user>)`, or
    /// `agent:<name> (owner: <user>)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// `config.applied`: the configuration sequence (the cluster's, else this node's
    /// configuration version).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// `config.applied`: the configuration sections that changed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<String>,
    /// `config.applied` on a replica, `lists.refreshed`: the filter snapshot version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_version: Option<u64>,
    /// `build.started`, `node.restarted`, `rollout.stage`: the build or rollout version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// `build.started`, `node.restarted`: the build's commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// `node.restarted`: the run before didn't stop cleanly (a crash, an OOM kill, a power cut).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unclean_shutdown: Option<bool>,
    /// `lists.refreshed`: the lists whose content changed (added, removed, or downloaded anew).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lists: Vec<String>,
    /// `lists.refreshed`: blocked names gained (negative: lost).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_delta: Option<i64>,
    /// `rollout.stage`: `canary`, `promoted`, `aborted`, `failed`, `pinned`, or `unpinned`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// `maintenance.entered`, `blocking.paused`: until when (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    /// `maintenance.entered`: why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `upstream.breaker`: the upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    /// `upstream.breaker`: `open`, `half_open`, or `closed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// `note`: the text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// `blocking.*`, `cache.flushed`: the nodes it was done on, when not only this one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
    /// Where the web UI shows more (`#/settings?tab=system`, `#/cluster`, `#/lists`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
}

/// REQ: OBS-033 — the parameters of `GET /api/v1/annotations`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AnnotationParams {
    /// Start (RFC 3339 or relative such as `-24h`; default 24 hours ago).
    #[param(example = "-24h")]
    pub from: Option<String>,
    /// End (default now).
    pub to: Option<String>,
    /// Kinds to keep, comma-separated (default all), e.g. `config.applied,note`.
    #[param(example = "config.applied,note")]
    pub kinds: Option<String>,
    /// `cluster` (default, every node), `site:<name>`, `node:<name or ID>`, or `node:local`.
    #[param(example = "cluster")]
    pub scope: Option<String>,
    /// At most this many, newest first (1–2000, default 500).
    pub limit: Option<usize>,
    /// Only markers before this time (RFC 3339): pass `nextBefore` from the previous page.
    pub before: Option<String>,
}

/// REQ: OBS-033 — what a federated annotation read asks each node, already parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnotationFilter {
    /// `[from_ms, to_ms)`.
    pub from_ms: u64,
    pub to_ms: u64,
    /// Empty: every kind.
    pub kinds: Vec<String>,
    /// At most this many, newest first.
    pub limit: usize,
}

/// REQ: OBS-033 — a page of change markers, newest first.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AnnotationPage {
    pub items: Vec<Annotation>,
    /// More markers in the window than `limit`: ask again with `before = nextBefore`.
    pub truncated: bool,
    /// With `truncated`: the `before` for the next page (the oldest marker's time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_before: Option<String>,
    /// Cluster nodes that couldn't be read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// REQ: OBS-033 — `POST /api/v1/annotations`: a note on every time chart.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NoteRequest {
    /// 1 to 200 characters, one line.
    #[schema(example = "moved the access point to the hallway")]
    pub text: String,
    /// When it happened (RFC 3339; default now): up to 7 days back, never ahead.
    #[serde(default)]
    #[schema(example = "2026-10-16T14:05:00Z")]
    pub time: Option<String>,
}

/// REQ: FLT-017 (T15.1) — one Kubernetes workload: a device WrenDNS names, groups, and
/// watches (`GET /api/v1/kubernetes/workloads`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadInfo {
    /// Its device name everywhere: `namespace/kind/name`.
    #[schema(example = "media/deploy/jellyfin")]
    pub name: String,
    pub namespace: String,
    /// `deploy`, `sts`, `ds`, `job`, `cronjob`, `rs`, `pod`, or another controller's kind.
    #[schema(example = "deploy")]
    pub kind: String,
    /// The workload's own name (`jellyfin` for `media/deploy/jellyfin`).
    #[schema(example = "jellyfin")]
    pub workload_name: String,
    /// Its analytics address (`100::/64`, RFC 6666): how top lists, anomalies, rhythm, and the
    /// device timeline key it, across rollouts.
    #[schema(example = "100::8a3f:12c4:9e01:77b2")]
    pub key: String,
    /// Its group; absent: its network's group or `default`, like any device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Where the group came from: `pod_label`, `namespace_label`, `map`, `default_group`, or
    /// `none`.
    #[schema(example = "namespace_label")]
    pub group_from: String,
    /// Its pods now (a deleted one stays 30 seconds, `terminating`).
    pub pods: Vec<WorkloadPod>,
    /// Queries and blocked answers in the last 24 hours (every node's, in a cluster).
    pub queries_24h: u64,
    pub blocked_24h: u64,
    /// When it last asked (RFC 3339), within the last day.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// `app.kubernetes.io/name` and `app.kubernetes.io/part-of`, when its pods have them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// REQ: FLT-017 — one pod of a workload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadPod {
    #[schema(example = "jellyfin-7d9f4c8b6-x2k1q")]
    pub name: String,
    #[schema(example = json!(["10.42.0.15"]))]
    pub addresses: Vec<String>,
    /// Deleted: its addresses stay its own for 30 seconds (queries in flight).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub terminating: bool,
}

/// REQ: FLT-017 — a page of workloads, by name.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadPage {
    pub items: Vec<WorkloadInfo>,
    /// Workloads matching the filters, on every page.
    pub total: usize,
    /// Pass as `cursor` for the next page; absent on the last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Nodes whose counts are missing (the table itself is the watcher's, on every node).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// REQ: FLT-017 — one node's counts for one workload (what a cluster sums).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadCount {
    /// The analytics key.
    pub key: String,
    pub queries_24h: u64,
    pub blocked_24h: u64,
    pub last_seen_unix_seconds: u64,
}

/// REQ: FLT-017 — whether Kubernetes workloads are on, and how the table is doing
/// (`GET /api/v1/kubernetes/status`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesStatus {
    /// `[kubernetes] enabled` (the chart's `kubernetes.enabled`).
    pub enabled: bool,
    /// `off`, `watching` (this node watches the API server), `peer` (it takes the table from
    /// the cluster), or `fixture` (a test file).
    #[schema(example = "watching")]
    pub role: String,
    /// This node watches the API server.
    pub watching: bool,
    /// Seconds since the table was last confirmed (watcher) or received (peer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync_seconds_ago: Option<u64>,
    pub pods: u64,
    pub workloads: u64,
    /// `*` for every namespace.
    pub namespaces_watched: Vec<String>,
    /// The last error, until the next success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// The node a peer's table came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Pod addresses left out past the table's cap (20,000).
    pub addresses_dropped: u64,
}

/// REQ: API-016 (T23.7, ADR-921) — one router integration as the API shows it: its settings
/// (secrets as names, never values), where it comes from, and what this node's poll of it did.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouterEntry {
    pub name: String,
    /// `unifi`, `opnsense`, or `home_assistant`.
    pub kind: String,
    /// The address, with any password in it removed (API-014).
    pub url: String,
    /// `file` (the configuration files define it; read-only here) or `api`.
    pub source: String,
    /// The settings in effect: the `[[router]]` fields as JSON, with `*_ref` names.
    pub definition: serde_json::Value,
    /// The fields the configuration files set (`api_key_file`, `tls_ca`...), shown as set by file.
    pub set_by_file: Vec<String>,
    /// Each credential this entry uses, where it comes from, and whether this node can read it.
    pub credentials: Vec<RouterCredential>,
    pub status: RouterStatus,
}

/// REQ: API-016 (T23.7) — one credential field of a router and where it stands on this node.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouterCredential {
    /// `api_key`, `api_secret`, or `password`.
    pub field: String,
    /// `file` (read as it is), `stored` (the encrypted store, by name), or `none`.
    pub source: String,
    /// The stored secret's name, when `source` is `stored`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Whether this node can read it now; `None` when nothing is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readable: Option<bool>,
    /// Why it can't be used here (named, never valued), when it can't.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue: Option<String>,
}

/// REQ: API-016 (T23.7) — what this node's poll of a router last did.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouterStatus {
    /// `this node`, `the primary` (a stored credential polls there only), or `skipped` with the
    /// reason (a resolver pod).
    pub polled_by: String,
    /// `waiting` (not read yet), `ok`, `failing` (keeping the last answer), or `skipped`.
    pub state: String,
    /// Unix seconds of the last read attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_poll: Option<u64>,
    /// Why the last read failed (the address has no password in it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub devices: u32,
    pub networks: u32,
    pub interval_secs: u32,
    /// REQ: API-016 (T24.41) - the node whose read this status is, when it is not the node that
    /// answered: a replica shows the primary's state of a router only the primary reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_by: Option<String>,
}

/// REQ: API-016 (T23.8, ADR-903 §9) — `GET /api/v1/routers`.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouterList {
    pub items: Vec<RouterEntry>,
    /// REQ: API-016 (T24.41) - the primary, when this node reads routers through it and it
    /// didn't answer (the statuses are this node's own then).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_nodes: Vec<String>,
}

/// REQ: API-016 (T23.8) — a read-only poll of a router as a draft (`POST /checks/router`).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouterCheck {
    pub ok: bool,
    pub devices: u32,
    pub networks: u32,
    /// Why it failed, with the address's password removed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether a stored credential went to the address (it's sent only to the address it was
    /// saved for; see the check's help).
    pub credential_sent: bool,
}

/// REQ: API-016 (T23.8) — a router's certificate as the console presents it
/// (`POST /checks/router-certificate`).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouterCertificate {
    /// The names it carries (subject and subject alternative names).
    pub names: Vec<String>,
    /// SHA-256 of the DER, as colon-separated hex.
    pub fingerprint_sha256: String,
    /// The PEM text, ready to paste into `tls_ca_pem`.
    pub pem: String,
    /// The name to set as `tls_server_name` when the certificate names something other than the
    /// address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_tls_server_name: Option<String>,
}

#[cfg(test)]
mod dhcp_lease_tests {
    use super::DhcpLease;

    /// REQ: T8.2 (ADR-942) — every lease carries `offline`, true for a client the router only
    /// remembers and false for a connected one, so a client can show the marker either way.
    #[test]
    fn t8_2_dhcp_lease_offline_is_always_serialized() {
        let lease = |offline| DhcpLease {
            mac: "02:00:00:00:00:04".into(),
            ip: "192.168.1.53".into(),
            hostname: None,
            client_name: None,
            expires_unix_seconds: 0,
            source: "router".into(),
            router: Some("udm".into()),
            dns_name: None,
            offline,
            ipv6: Vec::new(),
        };
        let on = serde_json::to_value(lease(true)).expect("serializes");
        let off = serde_json::to_value(lease(false)).expect("serializes");
        assert_eq!(on["offline"], serde_json::json!(true));
        assert_eq!(off["offline"], serde_json::json!(false));
    }
}

/// REQ: API-016 (T23.10, ADR-903 §6, ADR-967) — one OIDC provider as the API shows it: its
/// settings (the client secret as a name, never a value), where it comes from, and whether this
/// node serves its sign-in button.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OidcProviderEntry {
    /// The short ID used in URLs.
    pub id: String,
    /// The button label.
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    /// `file` (the configuration files define it; read-only here) or `api`.
    pub source: String,
    pub scopes: Vec<String>,
    pub username_claim: String,
    pub groups_claim: String,
    /// Group to role rules, in order.
    pub roles: Vec<OidcRoleRuleInfo>,
    /// The role for people in no mapped group; absent means they can't sign in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_role: Option<String>,
    pub require_verified_email: bool,
    /// Where the client secret comes from: `stored` (the encrypted store, by name), `file`,
    /// `inline` (in the configuration file), or `none` (a public client).
    pub secret_source: String,
    /// The stored secret's name, when `secretSource` is `stored`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Whether this node can read the secret now; absent when none is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_readable: Option<bool>,
    /// Whether the button works on this node.
    pub active: bool,
    /// Why it doesn't (no `public_url` on this node, an unreadable secret), or what went wrong
    /// the last time the provider was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The address to register with the provider as the redirect URI; absent without `public_url`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
}

/// One group to role rule of an OIDC provider.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OidcRoleRuleInfo {
    pub group: String,
    /// `viewer`, `operator` or `admin`.
    pub role: String,
}

/// REQ: API-016 (T23.10) — `GET /api/v1/oidc-providers`.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OidcProviderList {
    pub items: Vec<OidcProviderEntry>,
    /// This node's `[auth.oidc] public_url` (node-local, set in its file); empty when unset, and
    /// then every provider is inactive here.
    pub public_url: String,
}

/// REQ: API-016, OBS-010 (T23.11, ADR-984) — one event sink in the configuration: its settings
/// (a stored token as a name, never a value), where it comes from, and what this node does with it.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SinkEntry {
    pub name: String,
    /// `file`, `syslog` or `webhook`.
    #[serde(rename = "type")]
    pub kind: String,
    /// `file` (the configuration files define it; read-only here) or `api`.
    pub source: String,
    /// Where events go: the file, the syslog address or the webhook URL (a password in it
    /// removed, API-014).
    pub location: String,
    /// The settings in effect: the `[[telemetry.sink]]` fields as JSON, with `token_ref` named.
    pub definition: serde_json::Value,
    /// Where the webhook token comes from: `stored` (the encrypted store, by name), `file`, or
    /// `none`.
    pub token_source: String,
    /// The stored secret's name, when `tokenSource` is `stored`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Whether this node can read the token now; absent when none is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_readable: Option<bool>,
    /// Whether the sink's thread runs on this node.
    pub running: bool,
    /// Why it doesn't (a resolver pod holds no stored secrets; its settings couldn't be used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Events dropped since this node started (the buffer was full, or a batch was refused).
    pub dropped: u64,
}

/// REQ: API-016 (T23.11) — `GET /api/v1/sinks`.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SinkList {
    pub items: Vec<SinkEntry>,
    /// Where a file sink made in the UI writes: the file name it is given goes under this
    /// directory on every node.
    pub files_dir: String,
}

/// REQ: API-016, OBS-006 (T23.11) — one header of the OTLP export.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OtlpHeader {
    pub name: String,
    /// `stored` (a stored secret, by name) or `inline` (a value in the configuration file: never
    /// shown, `<redacted>`; enter it as a stored secret to move it to the UI).
    pub source: String,
    /// The stored secret's name, when `source` is `stored`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Whether this node can read the secret now (`stored` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readable: Option<bool>,
    /// `<redacted>` for an inline value; absent for a stored one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// REQ: API-016, OBS-006 (T23.11) — `GET /api/v1/otlp`: the OTLP export in effect on this node.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OtlpEntry {
    /// `none` (no export), `file` (the configuration files set the destination; read-only here)
    /// or `api`.
    pub source: String,
    /// The collector's address (a password in it removed); absent when there is none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub interval_secs: u32,
    pub headers: Vec<OtlpHeader>,
    /// Trace settings (a file's; read at start).
    pub traces_sample_every: u32,
    pub traces_slow_ms: u32,
    /// `none` or `gzip`: whether the metrics and traces requests are gzip compressed (the
    /// encoding is JSON either way).
    pub compression: String,
    /// Whether the export runs on this node.
    pub active: bool,
    /// Why it doesn't, when an endpoint is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// REQ: OBS-902 (T26.4, ADR-959 section 6) - this node's GeoIP database: whether it is on, what
/// it holds, and how the last fetch went. Everyone who can see the map sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GeoipStatus {
    /// `[map.geoip] enabled`.
    pub enabled: bool,
    /// `off`, `missing` (on, with no database on this node yet), `downloading`, `ready` or
    /// `failed` (the last attempt was not accepted: `lastError` says why, and the previous
    /// database, if any, is kept).
    pub state: String,
    /// The month of the database's source, `YYYY-MM`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_month: Option<String>,
    /// When this node built the database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Rows of the source file.
    pub rows: u64,
    pub size_bytes: u64,
    /// When the next check is due (a check runs at most once a day).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_check_at: Option<String>,
    /// A stable code (`digest_mismatch`, `overlapping_ranges`, `not_found`, ...), never a
    /// response body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// The database is more than 90 days old (it still works).
    pub old: bool,
    /// The attribution the database's licence (CC BY 4.0) asks for.
    pub attribution: String,
}

/// REQ: DNS-006, OPS-011, OPS-012 (T27.2, T27.11, ADR-1006) — `GET /api/v1/node-settings/{node}`:
/// the per-node sections of one node (`cache`, `support`, `updates`).
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeSettings {
    /// The node the sections belong to.
    pub node: String,
    pub sections: Vec<NodeSection>,
}

/// One per-node section: the fields in effect, which of them the files set, and whether a restart
/// is still pending for it.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeSection {
    /// `cache`, `support` or `updates` (the names the `*-settings` routes use).
    pub section: String,
    /// The fields in effect, with the same names as in `wrendns.toml`.
    #[schema(value_type = Object)]
    pub fields: serde_json::Value,
    /// The fields the configuration files set: the API can't change them (409 `set_by_file`).
    pub set_by_file: Vec<String>,
    /// Whether the API set this section for the node (`false`: the files' values apply).
    pub stored: bool,
    /// The section differs from what the node started with: it applies after a restart.
    pub pending_restart: bool,
    /// Whether every field of the section applies only after a restart of the node.
    pub restart_only: bool,
}

/// Query parameters for `GET /recursor/trace` (REQ: DNS-904).
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RecursorTraceParams {
    /// The name to look up.
    #[param(example = "www.example.com")]
    pub name: String,
    /// Query type. Default: `A`.
    pub qtype: Option<String>,
    /// The `recursive://` upstream to ask. Default: the first one.
    pub upstream: Option<String>,
}

/// One line of a recursive lookup's trace (REQ: DNS-904).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecursorTraceStep {
    /// `start` (where the lookup began) or `query` (one query to one server).
    pub kind: String,
    /// The zone whose servers were asked (`start`: the zone the lookup began at).
    pub zone: String,
    /// The server's address (none for `start`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// The name asked: a prefix of the full name while the name is being cut down (RFC 9156).
    pub qname: String,
    /// The type asked, as text (`A`, `NS`).
    pub qtype: String,
    /// A query: `referral`, `answer`, `nodata`, `nxdomain`, `lame`, `timeout`, `error` or
    /// `case-mismatch`. A start: `cache`, `stub` or `root`.
    pub outcome: String,
    /// The zone a referral delegates to, the target of a CNAME answer, or how many servers a
    /// start had; empty otherwise.
    pub detail: String,
    /// `udp` or `tcp` (empty for `start`).
    pub transport: String,
    /// Time spent, in microseconds.
    pub micros: u64,
}

/// How a recursive lookup went, step by step (`GET /api/v1/recursor/trace`, REQ: DNS-904).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecursorTrace {
    pub name: String,
    pub qtype: String,
    /// The `recursive://` upstream that resolved it.
    pub upstream: String,
    /// The answer's code (`NOERROR`, `NXDOMAIN`); absent when the lookup failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rcode: Option<String>,
    /// Records in the answer section.
    pub answers: u32,
    /// Why the lookup failed (answered SERVFAIL to a client), when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// From the first step to the last, in microseconds.
    pub total_micros: u64,
    /// The steps, in order. At most 128.
    pub steps: Vec<RecursorTraceStep>,
}

/// One root trust anchor a node tracks (`GET /api/v1/dnssec/anchors`, REQ: DNS-906).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TrustAnchorKey {
    /// The RFC 4034 key tag.
    pub key_tag: u16,
    /// The DNSSEC algorithm number (8 RSA/SHA-256, 13 ECDSA P-256, 15 Ed25519).
    pub algorithm: u8,
    /// The DNSKEY flags (257 a key-signing key, 385 once revoked).
    pub flags: u16,
    /// `valid` (a trust anchor), `add_pend` (seen, in its hold-down, not trusted yet),
    /// `missing` (trusted, but the last reading did not list it) or `revoked` (never trusted).
    pub state: String,
    /// When the key entered this state (Unix seconds); absent for a built-in anchor never changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_s: Option<u64>,
    /// For a pending key: when its hold-down ends and it becomes a trust anchor (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_at_s: Option<u64>,
}

/// One node's root trust anchors and how they are kept (`GET /api/v1/dnssec/anchors`,
/// REQ: DNS-906).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TrustAnchorStatus {
    /// The node (cluster nodes only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// `following` (the built-in anchors, kept up to date by RFC 5011), `file` (the keys of
    /// `trust_anchors_file`; rollover is off), `off` (DNSSEC validation is off) or `unsupported`
    /// (the node runs a build that does not know this read).
    pub mode: String,
    /// The keys, in no particular order. Empty when the mode is `file`, `off` or `unsupported`.
    pub keys: Vec<TrustAnchorKey>,
    /// When the root's keys were last read (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reading_s: Option<u64>,
    /// When the next reading is due (Unix seconds), while following.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_reading_s: Option<u64>,
    /// Why the last reading failed, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

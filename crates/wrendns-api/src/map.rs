//! REQ: OBS-901 (T26.2, ADR-958) — the live network map as data: the snapshot model, the
//! health classification (one pure function, table-tested), the merge of every node's window,
//! and the snapshot builder. Nothing here touches the DNS path: the sampler lives on the
//! aggregator thread (`wrendns_telemetry::map`), and this module only reads what it kept.
//!
//! A snapshot is `nodes` and `edges`, all derived and none stored: the gateway, the networks, the
//! devices (the 200 busiest; the rest fold into one `+N more` node per network), one resolver per
//! WrenDNS node with its three terminal answer kinds, and the upstreams. An edge carries its
//! rate over the 60 s window, the shares of slow, failing and blocked answers, and a health.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use wrendns_config::{Cidr, MapConfig};
use wrendns_telemetry::map::{AnswerKind, ClientKey, Counts, Window};

/// Most devices drawn in one snapshot; the rest fold into `+N more` per network.
pub const MAX_DEVICES: usize = 200;
/// Most edges in one snapshot.
pub const MAX_EDGES: usize = 2048;
/// Edges that carry their last few lookups.
pub const RECENT_EDGES: usize = 64;
/// Lookups an edge carries.
pub const RECENT_PER_EDGE: usize = 20;

/// One word for a node or an edge: colour is never alone (shape and words change too).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MapHealth {
    /// Too few answers in the window to say (grey). Not a health state.
    Idle,
    Green,
    Yellow,
    Red,
}

impl MapHealth {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Red => "red",
        }
    }
    /// The worse of two; `Idle` is never worse than a state that has data.
    #[must_use]
    pub fn worst(self, other: Self) -> Self {
        self.max(other)
    }
}

/// What a node is.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MapNodeKind {
    Gateway,
    Network,
    Device,
    /// Devices folded for the node cap (`+N more`), per network.
    More,
    Resolver,
    /// One of a resolver's terminal answer kinds: `cache`, `local`, `blocked`.
    Answer,
    Upstream,
}

/// A stable reason behind a colour, in words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapReason {
    /// Stable: `error_rate`, `slow`, `rate_limited`, `high_blocked`, `anomaly`, `breaker_open`,
    /// `breaker_half_open`, `unreachable`, `severe`, `degraded`, `router_error`,
    /// `not_configured`, `few_samples`, `children`, `member_down`, `no_route`.
    pub code: String,
    pub summary: String,
}

fn reason(code: &str, summary: impl Into<String>) -> MapReason {
    MapReason {
        code: code.to_owned(),
        summary: summary.into(),
    }
}

/// A node of the map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapNode {
    /// Stable within a snapshot and across them: `gateway`, `net:<name>`, `dev:<address>`,
    /// `res:<node>`, `ans:<node>:<kind>`, `up:<name>`, `more:<network>`, `dev:hidden`.
    pub id: String,
    pub kind: MapNodeKind,
    pub label: String,
    pub health: MapHealth,
    pub reasons: Vec<MapReason>,
    /// Answers per second over the window (an estimate when the sample is thinned).
    pub qps: f64,
    /// Answers in the window (an estimate), and the real events behind it.
    pub count: u64,
    pub sampled: u64,
    /// A device's address (not at privacy level 2 and above).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The network a device (or a fold) is in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// A device's client group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// The WrenDNS node a resolver or an answer node belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Devices folded into a `more` node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folded: Option<u32>,
}

/// One recently kept lookup on an edge (no name: the map never shows one).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapRecent {
    pub ts_unix_micros: u64,
    pub total_ms: u32,
    /// The status: `cached`, `forwarded`, `blocked`, ...
    pub status: String,
}

/// An edge `from -> to`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapEdge {
    pub from: String,
    pub to: String,
    /// Structural edges (gateway to network, network to device) carry no rate.
    pub structural: bool,
    pub qps: f64,
    pub count: u64,
    pub slow_pct: f64,
    pub err_pct: f64,
    pub blocked_pct: f64,
    pub health: MapHealth,
    /// The last lookups on this edge (the busiest 64 device edges only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent: Vec<MapRecent>,
}

/// How many nodes are in each state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapCounts {
    pub green: u32,
    pub yellow: u32,
    pub red: u32,
    pub idle: u32,
}

impl MapCounts {
    fn add(&mut self, h: MapHealth) {
        match h {
            MapHealth::Green => self.green += 1,
            MapHealth::Yellow => self.yellow += 1,
            MapHealth::Red => self.red += 1,
            MapHealth::Idle => self.idle += 1,
        }
    }
}

/// `GET /api/v1/map`: the network as a graph, coloured by health.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapSnapshot {
    /// When it was built (RFC 3339).
    pub generated_at: String,
    /// The window the rates cover.
    pub window_secs: u32,
    /// Every Nth lookup is sampled (1: nothing is thinned); an estimate beyond that.
    pub sample_rate: u32,
    /// Lookups the worker rings dropped in the window (the estimate is scaled for them).
    pub dropped: u64,
    /// The strictest privacy level in force (0 to 3): at 2 devices are hidden, at 3 only totals.
    pub privacy: u8,
    /// Devices were folded or edges cut for the caps.
    pub truncated: bool,
    /// Some node's part is missing: the map is of the nodes that answered.
    pub partial: bool,
    pub missing_nodes: Vec<String>,
    /// The worst health of any resolver or network (`idle` when nothing has enough answers).
    pub health: MapHealth,
    pub counts: MapCounts,
    pub nodes: Vec<MapNode>,
    pub edges: Vec<MapEdge>,
}

// ---------------------------------------------------------------------------------------------
// Settings and thresholds

/// The thresholds that colour the map (`[map]`, with `warn_latency_ms` resolved).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    /// Sampled answers needed before a device, edge or upstream is coloured.
    pub min_sample: u32,
    pub warn_latency_ms: u32,
    pub warn_slow_pct: u32,
    pub warn_error_pct: u32,
    pub error_pct: u32,
    pub warn_blocked_pct: u32,
}

impl Thresholds {
    /// From `[map]`; the slow threshold follows `[slo] latency_ms` when unset.
    pub fn from_config(c: &MapConfig, slo_latency_ms: u32) -> Self {
        Self {
            min_sample: c.min_sample,
            warn_latency_ms: c.warn_latency_ms.unwrap_or(slo_latency_ms),
            warn_slow_pct: c.warn_slow_pct,
            warn_error_pct: c.warn_error_pct,
            error_pct: c.error_pct,
            warn_blocked_pct: c.warn_blocked_pct,
        }
    }
}

impl Default for Thresholds {
    fn default() -> Self {
        Self::from_config(&MapConfig::default(), 250)
    }
}

/// What the map needs of `[map]` on a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapSettings {
    pub enabled: bool,
    pub event_rate: u32,
    pub thresholds: Thresholds,
}

// ---------------------------------------------------------------------------------------------
// What a node reports

/// An upstream's state on one node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartUpstream {
    pub id: u16,
    pub name: String,
    /// `closed`, `open` or `half_open`.
    pub breaker: String,
    /// The upstream's address when its endpoint is an IP literal (a name has none): the world
    /// view places it with the GeoIP database (OBS-902, ADR-959).
    #[serde(default)]
    pub ip: Option<IpAddr>,
    /// REQ: OBS-901 (fork #25) — the upstream groups it is a member of (ADR-1012).
    #[serde(default)]
    pub groups: Vec<String>,
    /// REQ: UPS-006 — why this node can't reach it ("this node has no IPv6 route"), if known.
    #[serde(default)]
    pub route_problem: Option<String>,
}

/// REQ: OBS-902 (T26.5, ADR-958 section 6) - answers pointing at one address prefix (a /24 for
/// IPv4, a /48 for IPv6) in the window: the counts are the sample's estimates, like the map's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerPrefix {
    /// An address in the prefix (the world view takes its /24 or /48).
    pub addr: IpAddr,
    pub weighted: u64,
    pub sampled: u64,
    pub slow: u64,
}

/// The most prefixes a node reports for the world view (ADR-958 section 6).
pub const MAX_PREFIXES: usize = 256;
/// The most countries the world view carries.
pub const MAX_REGIONS: usize = 64;

/// One node's part of the map: its window and what it knows of its own health.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MapPart {
    /// The node's label (its pod or site, else its ID), set by whoever gathers the parts.
    pub node: String,
    pub window: Window,
    pub upstreams: Vec<PartUpstream>,
    /// This node's own health: `healthy`, `degraded` or `severe` (ADR-104), with its reasons.
    pub level: String,
    pub reasons: Vec<(String, String)>,
    /// Client groups in configuration order (an event carries the index).
    pub groups: Vec<String>,
    /// Devices with an open anomaly finding nobody acknowledged (only at privacy level 0).
    pub anomalous: Vec<String>,
    /// REQ: OBS-902 (T26.5) - whether this node records the address an answer points at. It does
    /// not today (ADR-970: the ring record would grow), so `answers` is empty and the world
    /// view shows the upstreams only.
    #[serde(default)]
    pub answers_recorded: bool,
    /// The busiest answer prefixes of the window (at most [`MAX_PREFIXES`]); empty unless
    /// `answers_recorded`.
    #[serde(default)]
    pub answers: Vec<AnswerPrefix>,
}

/// The parts a read has: every node that answered, and the labels of those that didn't.
#[derive(Debug, Clone, Default)]
pub struct MapParts {
    pub parts: Vec<MapPart>,
    pub missing: Vec<String>,
    /// Members this node has no stream to but the cluster's health relay reports up (a replica
    /// in manual failover sees only the primary): shown idle, not red (ADR-971).
    pub unseen: Vec<String>,
    /// Peers connected but not heard from yet, inside the grace of a gather that has just
    /// started: shown idle and the snapshot is `partial` (ADR-971).
    pub pending: Vec<String>,
}

// ---------------------------------------------------------------------------------------------
// Classification

/// Counters of one device, edge or upstream over the window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Agg {
    /// Real events behind it (what `min_sample` reads).
    pub sampled: u64,
    /// The estimates.
    pub weighted: u64,
    pub slow: u64,
    pub error: u64,
    pub blocked: u64,
    pub limited: u64,
}

impl Agg {
    pub fn add(&mut self, c: &Counts) {
        self.sampled += u64::from(c.sampled);
        self.weighted += u64::from(c.weighted);
        self.slow += u64::from(c.slow);
        self.error += u64::from(c.error);
        self.blocked += u64::from(c.blocked);
        self.limited += u64::from(c.limited);
    }
    pub fn plus(&mut self, o: &Self) {
        self.sampled += o.sampled;
        self.weighted += o.weighted;
        self.slow += o.slow;
        self.error += o.error;
        self.blocked += o.blocked;
        self.limited += o.limited;
    }
    fn pct(part: u64, whole: u64) -> f64 {
        if whole == 0 {
            return 0.0;
        }
        // Counts are far below 2^52, so the conversion is exact.
        #[allow(clippy::cast_precision_loss)]
        let p = part as f64 * 1000.0 / whole as f64;
        p.round() / 10.0
    }
}

/// Whether `part` is at least `pct` percent of `whole` (exact, in integers).
fn at_least(part: u64, whole: u64, pct: u32) -> bool {
    whole > 0 && part.saturating_mul(100) >= u64::from(pct).saturating_mul(whole)
}

/// An upstream's circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Breaker {
    Closed,
    HalfOpen,
    Open,
}

impl Breaker {
    pub fn parse(s: &str) -> Self {
        match s {
            "open" => Self::Open,
            "half_open" | "half-open" => Self::HalfOpen,
            _ => Self::Closed,
        }
    }
}

/// What is being classified (the rules differ: ADR-958 section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// A device: every rule, including rate limits, blocked share and anomalies.
    Device,
    /// A flow between two nodes: errors and slowness.
    Edge,
    /// An upstream (or the flow to it): errors, slowness and the circuit breaker.
    Upstream,
    /// A terminal answer kind (`cache`, `local`, `blocked`): slowness only, never red; blocking is
    /// the intended outcome.
    Answer,
}

/// Facts that aren't counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    pub breaker: Breaker,
    /// An open, unacknowledged anomaly finding (the caller passes it only at privacy level 0).
    pub anomaly: bool,
    /// The node is unreachable (a cluster peer missing from the read).
    pub unreachable: bool,
}

impl Default for Facts {
    fn default() -> Self {
        Self {
            breaker: Breaker::Closed,
            anomaly: false,
            unreachable: false,
        }
    }
}

/// The health of one device, edge, upstream or answer kind, with the reasons. Order: facts
/// first (an open breaker or an unreachable node is red whatever was sampled), then `idle` (fewer
/// than `min_sample` real answers), then red, then yellow, else green.
#[allow(clippy::too_many_lines)] // one rule after another, in the order ADR-958 section 4 states them
pub fn classify(
    c: &Agg,
    th: &Thresholds,
    scope: Scope,
    facts: &Facts,
) -> (MapHealth, Vec<MapReason>) {
    let mut reasons = Vec::new();
    if facts.unreachable {
        reasons.push(reason("unreachable", "the node doesn't answer"));
        return (MapHealth::Red, reasons);
    }
    if scope == Scope::Upstream && facts.breaker == Breaker::Open {
        reasons.push(reason(
            "breaker_open",
            "its circuit breaker is open (benched after failures)",
        ));
        return (MapHealth::Red, reasons);
    }
    let half_open = scope == Scope::Upstream && facts.breaker == Breaker::HalfOpen;
    if half_open {
        reasons.push(reason(
            "breaker_half_open",
            "its circuit breaker is half open (being tested)",
        ));
    }
    if c.sampled < u64::from(th.min_sample) {
        if half_open {
            return (MapHealth::Yellow, reasons);
        }
        reasons.push(reason(
            "few_samples",
            format!(
                "{} sampled answers in the last minute, {} needed",
                c.sampled, th.min_sample
            ),
        ));
        return (MapHealth::Idle, reasons);
    }
    let mut red = false;
    let mut yellow = half_open;
    if scope != Scope::Answer {
        if at_least(c.error, c.weighted, th.error_pct) {
            red = true;
            reasons.push(reason(
                "error_rate",
                format!(
                    "{}% of answers are SERVFAIL or time out (red from {}%)",
                    Agg::pct(c.error, c.weighted),
                    th.error_pct
                ),
            ));
        } else if at_least(c.error, c.weighted, th.warn_error_pct) {
            yellow = true;
            reasons.push(reason(
                "error_rate",
                format!(
                    "{}% of answers are SERVFAIL or time out (yellow from {}%)",
                    Agg::pct(c.error, c.weighted),
                    th.warn_error_pct
                ),
            ));
        }
    }
    if at_least(c.slow, c.weighted, th.warn_slow_pct) {
        yellow = true;
        reasons.push(reason(
            "slow",
            format!(
                "{}% of answers took over {} ms (yellow from {}%)",
                Agg::pct(c.slow, c.weighted),
                th.warn_latency_ms,
                th.warn_slow_pct
            ),
        ));
    }
    if scope == Scope::Device {
        if c.limited > 0 {
            yellow = true;
            reasons.push(reason(
                "rate_limited",
                "some of its queries were rate limited",
            ));
        }
        if at_least(c.blocked, c.weighted, th.warn_blocked_pct) {
            yellow = true;
            reasons.push(reason(
                "high_blocked",
                format!(
                    "{}% of its answers are blocked (yellow from {}%)",
                    Agg::pct(c.blocked, c.weighted),
                    th.warn_blocked_pct
                ),
            ));
        }
        if facts.anomaly {
            yellow = true;
            reasons.push(reason(
                "anomaly",
                "an open anomaly finding nobody has acknowledged",
            ));
        }
    }
    let h = if red {
        MapHealth::Red
    } else if yellow {
        MapHealth::Yellow
    } else {
        MapHealth::Green
    };
    (h, reasons)
}

/// REQ: API-013, OBS-901 (T35.3) — what a person reads for an upstream or an upstream group's ID.
///
/// A forwarded domain makes the group `forward:<domain>` and one upstream per server,
/// `forward:<domain>#1`, `#2`, ... (a stub zone's is `#stub`). Those internal IDs are not words:
/// - `forward:home.example` reads "home.example names";
/// - `forward:168.192.in-addr.arpa` reads "Reverse lookups, 192.168.x.x" (the reverse zone
///   written the way an address is);
/// - a stub zone adds "(stub zone)", and the second and later servers of one domain "server N".
///
/// Any other ID (a preset such as `cloudflare`, a group such as `default`) is its own name. The
/// server's address is a field of the node, not part of the label. The server renders this, so
/// the map, the policy route detail, the world view and MCP's `network_health` agree.
pub fn display_label(id: &str) -> String {
    let Some(rest) = id.strip_prefix("forward:") else {
        return id.to_owned();
    };
    let (domain, suffix) = match rest.rsplit_once('#') {
        Some((d, s)) => (d, Some(s)),
        None => (rest, None),
    };
    if domain.is_empty() {
        return id.to_owned();
    }
    let mut label = reverse_label(domain).unwrap_or_else(|| format!("{domain} names"));
    match suffix {
        Some("stub") => label.push_str(" (stub zone)"),
        Some(n) => {
            if let Ok(i) = n.parse::<u32>()
                && i > 1
            {
                label = format!("{label}, server {i}");
            }
        }
        None => {}
    }
    label
}

/// `192.168.x.x` for `168.192.in-addr.arpa`: "Reverse lookups, 192.168.x.x"; an IPv6 reverse zone
/// reads "Reverse lookups, IPv6 <prefix>/<bits>" with the nibbles put back in order.
fn reverse_label(domain: &str) -> Option<String> {
    let lower = domain.to_ascii_lowercase();
    if let Some(v4) = lower.strip_suffix(".in-addr.arpa") {
        let mut octets: Vec<&str> = v4.split('.').collect();
        if octets.is_empty()
            || octets.len() > 4
            || octets
                .iter()
                .any(|o| o.is_empty() || !o.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        octets.reverse();
        let mut shown: Vec<String> = octets.iter().map(|o| (*o).to_owned()).collect();
        while shown.len() < 4 {
            shown.push("x".to_owned());
        }
        return Some(format!("Reverse lookups, {}", shown.join(".")));
    }
    if let Some(v6) = lower.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = v6.split('.').collect();
        if nibbles.is_empty()
            || nibbles.len() > 32
            || nibbles
                .iter()
                .any(|n| n.len() != 1 || !n.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return None;
        }
        let mut hex: Vec<&str> = nibbles.clone();
        hex.reverse();
        let groups: Vec<String> = hex
            .chunks(4)
            .map(|c| {
                let g = c.concat();
                let t = g.trim_start_matches('0');
                if t.is_empty() {
                    "0".to_owned()
                } else {
                    t.to_owned()
                }
            })
            .collect();
        return Some(format!(
            "Reverse lookups, IPv6 {}::/{}",
            groups.join(":"),
            nibbles.len() * 4
        ));
    }
    None
}

/// REQ: OBS-901 (fork #25, ADR-1012) — the resolver's view of its upstreams. An upstream that is
/// red but belongs only to groups that have a member that is not red (the group still answers)
/// counts as yellow for the resolver, and a reason names it and the member that answers. An
/// upstream in no group, or in a group with no healthy member, stays red: the group itself fails.
/// The upstream's own node on the map keeps its colour; only the roll-up changes.
pub fn group_aware(ups: &[(&PartUpstream, MapHealth)]) -> (Vec<MapHealth>, Vec<MapReason>) {
    let mut out = Vec::with_capacity(ups.len());
    let mut notes = Vec::new();
    for (u, h) in ups {
        if *h != MapHealth::Red || u.groups.is_empty() {
            out.push(*h);
            continue;
        }
        // The first healthy member of each of its groups, or None when a group has none.
        let mut answering: Vec<&str> = Vec::new();
        let mut covered = true;
        for g in &u.groups {
            let alive = ups
                .iter()
                .find(|(m, mh)| *mh != MapHealth::Red && m.groups.iter().any(|x| x == g));
            let Some((m, _)) = alive else {
                covered = false;
                break;
            };
            answering.push(m.name.as_str());
        }
        if covered {
            answering.sort_unstable();
            answering.dedup();
            // REQ: API-013 (T35.3) — the sentence names the upstreams the way the map does.
            let answering: Vec<String> = answering.into_iter().map(display_label).collect();
            out.push(MapHealth::Yellow);
            notes.push(reason(
                "member_down",
                format!(
                    "upstream {} is down; its group still answers through {}",
                    display_label(&u.name),
                    answering.join(", ")
                ),
            ));
        } else {
            out.push(MapHealth::Red);
        }
    }
    (out, notes)
}

/// A parent takes the worst of its children (`idle` ones don't count unless they all are), and
/// says how many are red and yellow.
pub fn rollup(children: &[MapHealth]) -> (MapHealth, Option<MapReason>) {
    let red = children.iter().filter(|h| **h == MapHealth::Red).count();
    let yellow = children.iter().filter(|h| **h == MapHealth::Yellow).count();
    let any_data = children.iter().any(|h| *h != MapHealth::Idle);
    let h = if red > 0 {
        MapHealth::Red
    } else if yellow > 0 {
        MapHealth::Yellow
    } else if any_data {
        MapHealth::Green
    } else {
        MapHealth::Idle
    };
    let why = (red + yellow > 0).then(|| reason("children", format!("{red} red, {yellow} yellow")));
    (h, why)
}

// ---------------------------------------------------------------------------------------------
// The router integration's state, the networks, and the filters

/// The gateway's state as the router integrations report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gateway {
    /// No `[[router]]` configured.
    None,
    Ok,
    /// A router integration's last read failed.
    Error(String),
}

/// A network of the map: a name and its subnets.
#[derive(Debug, Clone)]
pub struct Net {
    pub name: String,
    pub cidr: Cidr,
}

/// What the answering node knows besides the parts.
#[allow(missing_debug_implementations)] // holds a closure
pub struct Context<'a> {
    pub thresholds: Thresholds,
    pub gateway: Gateway,
    pub networks: Vec<Net>,
    /// A device's inventory name.
    pub device_name: &'a dyn Fn(IpAddr) -> Option<String>,
    pub now_unix_seconds: u64,
}

/// `GET /api/v1/map` filters; the server narrows the read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    pub network: Option<String>,
    pub group: Option<String>,
    /// Matches a device's name or address (a substring, any case).
    pub device: Option<String>,
    /// A WrenDNS node's label.
    pub node: Option<String>,
}

fn ci_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn network_of(nets: &[Net], ip: IpAddr) -> Option<&Net> {
    nets.iter()
        .filter(|n| n.cidr.contains(ip))
        .max_by_key(|n| n.cidr.prefix)
}

fn client_ip(k: &ClientKey) -> IpAddr {
    k.addr()
}

fn kind_label(k: AnswerKind) -> &'static str {
    k.label()
}

/// What a network adds up from its devices.
struct NetAcc {
    qps_w: u64,
    sampled: u64,
    health: Vec<MapHealth>,
}

/// Per device, over every node: its counters, and per node.
#[derive(Default)]
struct Dev {
    agg: Agg,
    group: u16,
    by_node: BTreeMap<usize, Agg>,
}

/// One snapshot from the parts. Pure: the same input gives the same map.
#[allow(clippy::too_many_lines)] // one pass per kind of node, in the order a reader draws them
pub fn build(parts: &MapParts, ctx: &Context<'_>, filter: &Filter) -> MapSnapshot {
    let th = &ctx.thresholds;
    let privacy = parts
        .parts
        .iter()
        .map(|p| p.window.privacy)
        .max()
        .unwrap_or(0);
    let hidden = privacy >= 2;
    let mut sample_rate = 1;
    let mut dropped = 0u64;
    let window_secs = parts
        .parts
        .iter()
        .map(|p| p.window.window_secs)
        .max()
        .unwrap_or(wrendns_telemetry::map::WINDOW_SECS);

    // Labels: one per node, made unique.
    let mut labels: Vec<String> = Vec::new();
    for p in &parts.parts {
        let mut l = if p.node.is_empty() {
            "node".to_owned()
        } else {
            p.node.clone()
        };
        let base = l.clone();
        let mut n = 2;
        while labels.contains(&l) {
            l = format!("{base}-{n}");
            n += 1;
        }
        labels.push(l);
    }
    let keep_node = |i: usize| filter.node.as_deref().is_none_or(|n| ci_eq(n, &labels[i]));

    // Devices, edges' counters.
    let mut devs: BTreeMap<ClientKey, Dev> = BTreeMap::new();
    let mut res_total: BTreeMap<usize, Agg> = BTreeMap::new();
    let mut ans: BTreeMap<(usize, AnswerKind), Agg> = BTreeMap::new();
    let mut up_edge: BTreeMap<(usize, String), Agg> = BTreeMap::new();
    let mut breakers: BTreeMap<String, Breaker> = BTreeMap::new();
    let mut up_breaker_edge: BTreeMap<(usize, String), Breaker> = BTreeMap::new();
    let mut anomalous: std::collections::HashSet<String> = std::collections::HashSet::new();
    let name_of = |p: &MapPart, id: u16| -> String {
        p.upstreams
            .iter()
            .find(|u| u.id == id)
            .map_or_else(|| format!("upstream {id}"), |u| u.name.clone())
    };
    let group_name =
        |p: &MapPart, g: u16| -> Option<String> { p.groups.get(usize::from(g)).cloned() };
    // Group names come from the answering node's view of the first part that has them.
    let group_of = |g: u16| -> Option<String> { parts.parts.iter().find_map(|p| group_name(p, g)) };
    let selected_groups: Option<Vec<u16>> = filter.group.as_ref().map(|name| {
        let max = parts
            .parts
            .iter()
            .map(|p| p.groups.len())
            .max()
            .unwrap_or(0);
        (0..max)
            .filter_map(|i| u16::try_from(i).ok())
            .filter(|g| group_of(*g).is_some_and(|n| ci_eq(&n, name)))
            .collect()
    });

    for (i, p) in parts.parts.iter().enumerate() {
        sample_rate = sample_rate.max(p.window.sample_rate);
        dropped += p.window.dropped;
        for u in &p.upstreams {
            let b = Breaker::parse(&u.breaker);
            let cur = breakers.entry(u.name.clone()).or_insert(Breaker::Closed);
            *cur = (*cur).max(b);
            up_breaker_edge.insert((i, u.name.clone()), b);
            up_edge.entry((i, u.name.clone())).or_default();
        }
        anomalous.extend(p.anomalous.iter().cloned());
        if !keep_node(i) {
            continue;
        }
        let rt = res_total.entry(i).or_default();
        rt.add(&p.window.other);
        for e in &p.window.entries {
            if let Some(sel) = &selected_groups
                && !sel.contains(&e.group)
            {
                continue;
            }
            if let Some(q) = &filter.device {
                // A hidden device has no name or address to match.
                if hidden || e.client.is_hidden() {
                    continue;
                }
                let ip = client_ip(&e.client);
                let name = (ctx.device_name)(ip).unwrap_or_default();
                let q = q.to_ascii_lowercase();
                if !ip.to_string().to_ascii_lowercase().contains(&q)
                    && !name.to_ascii_lowercase().contains(&q)
                {
                    continue;
                }
            }
            if let Some(net) = &filter.network {
                let n = if hidden || e.client.is_hidden() {
                    None
                } else {
                    network_of(&ctx.networks, client_ip(&e.client))
                };
                if !n.is_some_and(|n| ci_eq(&n.name, net)) {
                    continue;
                }
            }
            res_total.entry(i).or_default().add(&e.c);
            // REQ: OBS-901 — at privacy 2+ every key is hidden, whatever the part holds.
            let client = if hidden { ClientKey::HIDDEN } else { e.client };
            let d = devs.entry(client).or_default();
            d.agg.add(&e.c);
            d.group = e.group;
            d.by_node.entry(i).or_default().add(&e.c);
            match e.kind {
                AnswerKind::Cache | AnswerKind::Local | AnswerKind::Blocked => {
                    ans.entry((i, e.kind)).or_default().add(&e.c);
                }
                AnswerKind::Upstream => {
                    let name = name_of(p, e.upstream);
                    up_edge.entry((i, name)).or_default().add(&e.c);
                }
                AnswerKind::Other => {}
            }
        }
    }
    let mut nodes: Vec<MapNode> = Vec::new();
    let mut edges: Vec<MapEdge> = Vec::new();
    let mut truncated = false;
    let qps_of = |weighted: u64| -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let q = weighted as f64 / f64::from(window_secs.max(1));
        (q * 100.0).round() / 100.0
    };
    let edge_of = |from: String, to: String, a: &Agg, health: MapHealth| MapEdge {
        from,
        to,
        structural: false,
        qps: qps_of(a.weighted),
        count: a.weighted,
        slow_pct: Agg::pct(a.slow, a.weighted),
        err_pct: Agg::pct(a.error, a.weighted),
        blocked_pct: Agg::pct(a.blocked, a.weighted),
        health,
        recent: Vec::new(),
    };
    let structural = |from: String, to: String, health: MapHealth| MapEdge {
        from,
        to,
        structural: true,
        qps: 0.0,
        count: 0,
        slow_pct: 0.0,
        err_pct: 0.0,
        blocked_pct: 0.0,
        health,
        recent: Vec::new(),
    };

    // Devices: the busiest are drawn, the rest fold per network.
    let mut ordered: Vec<(&ClientKey, &Dev)> = devs.iter().collect();
    ordered.sort_by(|a, b| {
        b.1.agg
            .weighted
            .cmp(&a.1.agg.weighted)
            .then_with(|| a.0.cmp(b.0))
    });
    let mut net_acc: BTreeMap<String, NetAcc> = BTreeMap::new();
    let hidden_net = "All networks";
    let mut folded: BTreeMap<String, (u32, Agg, Vec<MapHealth>)> = BTreeMap::new();
    let mut device_ids: HashMap<ClientKey, String> = HashMap::new();
    let mut drawn = 0usize;
    for (key, d) in ordered {
        let hidden_dev = key.is_hidden();
        let ip = client_ip(key);
        let net_name = if hidden_dev {
            hidden_net.to_owned()
        } else {
            network_of(&ctx.networks, ip).map_or_else(|| "Other".to_owned(), |n| n.name.clone())
        };
        let anomaly = privacy == 0 && !hidden_dev && anomalous.contains(&ip.to_string());
        let (health, reasons) = classify(
            &d.agg,
            th,
            Scope::Device,
            &Facts {
                anomaly,
                ..Facts::default()
            },
        );
        let acc = net_acc.entry(net_name.clone()).or_insert(NetAcc {
            qps_w: 0,
            sampled: 0,
            health: Vec::new(),
        });
        acc.qps_w += d.agg.weighted;
        acc.sampled += d.agg.sampled;
        acc.health.push(health);
        if drawn >= MAX_DEVICES {
            truncated = true;
            let f = folded.entry(net_name).or_default();
            f.0 += 1;
            f.1.plus(&d.agg);
            f.2.push(health);
            continue;
        }
        drawn += 1;
        let id = if hidden_dev {
            "dev:hidden".to_owned()
        } else {
            format!("dev:{ip}")
        };
        device_ids.insert(*key, id.clone());
        let label = if hidden_dev {
            "devices hidden by privacy".to_owned()
        } else {
            (ctx.device_name)(ip).unwrap_or_else(|| ip.to_string())
        };
        nodes.push(MapNode {
            id: id.clone(),
            kind: MapNodeKind::Device,
            label,
            health,
            reasons,
            qps: qps_of(d.agg.weighted),
            count: d.agg.weighted,
            sampled: d.agg.sampled,
            address: (!hidden_dev).then(|| ip.to_string()),
            network: Some(net_name.clone()),
            group: group_of(d.group).filter(|_| privacy < 3),
            node: None,
            folded: None,
        });
        edges.push(structural(format!("net:{net_name}"), id.clone(), health));
        for (i, a) in &d.by_node {
            let (eh, _) = classify(a, th, Scope::Edge, &Facts::default());
            let mut e = edge_of(id.clone(), format!("res:{}", labels[*i]), a, eh);
            if hidden_dev {
                e.recent = Vec::new();
            }
            edges.push(e);
        }
    }
    for (net, (n, agg, hs)) in &folded {
        let (h, _) = rollup(hs);
        let id = format!("more:{net}");
        nodes.push(MapNode {
            id: id.clone(),
            kind: MapNodeKind::More,
            label: format!("+{n} more"),
            health: h,
            reasons: Vec::new(),
            qps: qps_of(agg.weighted),
            count: agg.weighted,
            sampled: agg.sampled,
            address: None,
            network: Some(net.clone()),
            group: None,
            node: None,
            folded: Some(*n),
        });
        edges.push(structural(format!("net:{net}"), id, h));
    }

    // Networks: every known one (grey when idle), plus the ones devices landed in.
    let mut net_names: Vec<String> = ctx.networks.iter().map(|n| n.name.clone()).collect();
    net_names.extend(net_acc.keys().cloned());
    net_names.sort();
    net_names.dedup();
    if let Some(f) = &filter.network {
        net_names.retain(|n| ci_eq(n, f));
    }
    if filter.device.is_some() || filter.group.is_some() {
        net_names.retain(|n| net_acc.contains_key(n));
    }
    if net_names.is_empty() && !hidden {
        net_names.push("Other".to_owned());
    }
    let gateway_health = match &ctx.gateway {
        Gateway::None => MapHealth::Idle,
        Gateway::Ok => MapHealth::Green,
        Gateway::Error(_) => MapHealth::Yellow,
    };
    let gateway_reasons = match &ctx.gateway {
        Gateway::None => vec![reason(
            "not_configured",
            "no router integration is configured",
        )],
        Gateway::Ok => Vec::new(),
        Gateway::Error(e) => vec![reason(
            "router_error",
            format!("the router read failed: {e}"),
        )],
    };
    nodes.push(MapNode {
        id: "gateway".into(),
        kind: MapNodeKind::Gateway,
        label: "Gateway".into(),
        health: gateway_health,
        reasons: gateway_reasons,
        qps: 0.0,
        count: 0,
        sampled: 0,
        address: None,
        network: None,
        group: None,
        node: None,
        folded: None,
    });
    for name in &net_names {
        let (h, why, qps_w, sampled) = match net_acc.get(name) {
            Some(a) => {
                let (h, why) = rollup(&a.health);
                (h, why, a.qps_w, a.sampled)
            }
            None => (MapHealth::Idle, None, 0, 0),
        };
        nodes.push(MapNode {
            id: format!("net:{name}"),
            kind: MapNodeKind::Network,
            label: name.clone(),
            health: h,
            reasons: why.into_iter().collect(),
            qps: qps_of(qps_w),
            count: qps_w,
            sampled,
            address: None,
            network: None,
            group: None,
            node: None,
            folded: None,
        });
        edges.push(structural("gateway".into(), format!("net:{name}"), h));
    }

    // Resolvers, their answer kinds and the upstreams.
    let mut up_total: BTreeMap<String, Agg> = BTreeMap::new();
    for ((_, name), a) in &up_edge {
        up_total.entry(name.clone()).or_default().plus(a);
    }
    let mut up_health: BTreeMap<String, MapHealth> = BTreeMap::new();
    // REQ: UPS-006 (fork #25) — the nodes that have no route to an upstream's address.
    let mut no_route: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
    for (i, p) in parts.parts.iter().enumerate() {
        for u in &p.upstreams {
            if let Some(why) = u.route_problem.as_deref() {
                no_route
                    .entry(u.name.as_str())
                    .or_default()
                    .push((labels[i].as_str(), why));
            }
        }
    }
    // The address of each upstream whose endpoint is an IP literal (any node's part will do).
    let mut server_ip: BTreeMap<&str, IpAddr> = BTreeMap::new();
    for p in &parts.parts {
        for u in &p.upstreams {
            if let Some(ip) = u.ip {
                server_ip.entry(u.name.as_str()).or_insert(ip);
            }
        }
    }
    for (name, a) in &up_total {
        let b = breakers.get(name).copied().unwrap_or(Breaker::Closed);
        let (mut h, mut why) = classify(
            a,
            th,
            Scope::Upstream,
            &Facts {
                breaker: b,
                ..Facts::default()
            },
        );
        // A route that is missing is worth saying, and an upstream nobody has asked (a spare)
        // is not "idle" when it cannot be reached: it is a warning.
        for (node, problem) in no_route.get(name.as_str()).into_iter().flatten() {
            why.push(reason("no_route", format!("{node}: {problem}")));
            if h == MapHealth::Idle {
                h = MapHealth::Yellow;
            }
        }
        up_health.insert(name.clone(), h);
        nodes.push(MapNode {
            id: format!("up:{name}"),
            kind: MapNodeKind::Upstream,
            // REQ: API-013 (T35.3) — a person's words for the internal ID, and the server's address.
            label: display_label(name),
            health: h,
            reasons: why,
            qps: qps_of(a.weighted),
            count: a.weighted,
            sampled: a.sampled,
            address: server_ip.get(name.as_str()).map(ToString::to_string),
            network: None,
            group: None,
            node: None,
            folded: None,
        });
    }
    for (i, p) in parts.parts.iter().enumerate() {
        if !keep_node(i) {
            continue;
        }
        let label = &labels[i];
        let res_id = format!("res:{label}");
        let total = res_total.get(&i).copied().unwrap_or_default();
        let mut children: Vec<MapHealth> = Vec::new();
        for kind in [AnswerKind::Cache, AnswerKind::Local, AnswerKind::Blocked] {
            let a = ans.get(&(i, kind)).copied().unwrap_or_default();
            let (h, why) = classify(&a, th, Scope::Answer, &Facts::default());
            children.push(h);
            let id = format!("ans:{label}:{}", kind_label(kind));
            nodes.push(MapNode {
                id: id.clone(),
                kind: MapNodeKind::Answer,
                label: kind_label(kind).to_owned(),
                health: h,
                reasons: why,
                qps: qps_of(a.weighted),
                count: a.weighted,
                sampled: a.sampled,
                address: None,
                network: None,
                group: None,
                node: Some(label.clone()),
                folded: None,
            });
            edges.push(edge_of(res_id.clone(), id, &a, h));
        }
        let mut ups: Vec<(&PartUpstream, MapHealth)> = Vec::new();
        for u in &p.upstreams {
            let a = up_edge
                .get(&(i, u.name.clone()))
                .copied()
                .unwrap_or_default();
            let b = up_breaker_edge
                .get(&(i, u.name.clone()))
                .copied()
                .unwrap_or(Breaker::Closed);
            let (h, _) = classify(
                &a,
                th,
                Scope::Upstream,
                &Facts {
                    breaker: b,
                    ..Facts::default()
                },
            );
            ups.push((u, up_health.get(&u.name).copied().unwrap_or(h)));
            edges.push(edge_of(res_id.clone(), format!("up:{}", u.name), &a, h));
        }
        // REQ: OBS-901 (fork #25, ADR-1012) — a dead member of a group that still answers
        // through a healthy one is a warning for the resolver, not a failure.
        let (member_health, member_notes) = group_aware(&ups);
        children.extend(member_health);
        // The resolver: its own level (ADR-104) and what is downstream of it.
        let (below, why) = rollup(&children);
        let mut reasons: Vec<MapReason> = Vec::new();
        let own = match p.level.as_str() {
            "severe" => MapHealth::Red,
            "degraded" => MapHealth::Yellow,
            _ => MapHealth::Idle,
        };
        for (code, summary) in p.reasons.iter().take(3) {
            reasons.push(reason(
                if own == MapHealth::Red {
                    "severe"
                } else {
                    "degraded"
                },
                format!("{code}: {summary}"),
            ));
        }
        reasons.extend(member_notes);
        reasons.extend(why);
        // A node that says it is healthy is green even when nobody asked it anything.
        let floor = if p.level == "healthy" {
            MapHealth::Green
        } else {
            MapHealth::Idle
        };
        let h = below.worst(own).worst(floor);
        nodes.push(MapNode {
            id: res_id,
            kind: MapNodeKind::Resolver,
            label: label.clone(),
            health: h,
            reasons,
            qps: qps_of(total.weighted),
            count: total.weighted,
            sampled: total.sampled,
            address: None,
            network: None,
            group: None,
            node: Some(label.clone()),
            folded: None,
        });
    }
    // A node that didn't answer is a red resolver, not a gap.
    let mut missing = parts.missing.clone();
    missing.sort();
    missing.dedup();
    for m in &missing {
        if filter.node.as_deref().is_some_and(|n| !ci_eq(n, m)) {
            continue;
        }
        nodes.push(MapNode {
            id: format!("res:{m}"),
            kind: MapNodeKind::Resolver,
            label: m.clone(),
            health: MapHealth::Red,
            reasons: vec![reason(
                "unreachable",
                "this node didn't answer the read (its part of the map is missing)",
            )],
            qps: 0.0,
            count: 0,
            sampled: 0,
            address: None,
            network: None,
            group: None,
            node: Some(m.clone()),
            folded: None,
        });
    }

    // REQ: OBS-901 (ADR-971) — a member this node can't reach but the relay says is up is idle
    // here, with a reason of its own; it doesn't make the map partial.
    let mut unseen = parts.unseen.clone();
    unseen.sort();
    unseen.dedup();
    for m in unseen.iter().filter(|m| !missing.contains(m)) {
        if filter.node.as_deref().is_some_and(|n| !ci_eq(n, m)) {
            continue;
        }
        nodes.push(MapNode {
            id: format!("res:{m}"),
            kind: MapNodeKind::Resolver,
            label: m.clone(),
            health: MapHealth::Idle,
            reasons: vec![reason(
                "not_reachable_from_here",
                "this node has no direct link to it; the cluster's health relay reports it up",
            )],
            qps: 0.0,
            count: 0,
            sampled: 0,
            address: None,
            network: None,
            group: None,
            node: Some(m.clone()),
            folded: None,
        });
    }

    // REQ: OBS-901 (ADR-971) - a peer whose first answer hasn't landed: idle with a reason, and
    // the map says it is partial, so a cold one-shot read is never mistaken for a whole map.
    let mut pending = parts.pending.clone();
    pending.sort();
    pending.dedup();
    for m in pending.iter().filter(|m| !missing.contains(m)) {
        if filter.node.as_deref().is_some_and(|n| !ci_eq(n, m)) {
            continue;
        }
        nodes.push(MapNode {
            id: format!("res:{m}"),
            kind: MapNodeKind::Resolver,
            label: m.clone(),
            health: MapHealth::Idle,
            reasons: vec![reason(
                "pending",
                "this node hasn't answered yet (the first read after an idle spell); ask again in a few seconds",
            )],
            qps: 0.0,
            count: 0,
            sampled: 0,
            address: None,
            network: None,
            group: None,
            node: Some(m.clone()),
            folded: None,
        });
    }

    // The last lookups of the busiest device edges.
    let mut busiest: Vec<usize> = (0..edges.len())
        .filter(|i| edges[*i].from.starts_with("dev:") && edges[*i].count > 0)
        .collect();
    busiest.sort_by(|a, b| edges[*b].count.cmp(&edges[*a].count));
    busiest.truncate(RECENT_EDGES);
    if privacy < 3 {
        for i in busiest {
            let Some(dev_key) = device_ids
                .iter()
                .find(|(_, id)| **id == edges[i].from)
                .map(|(k, _)| *k)
            else {
                continue;
            };
            let Some(node_idx) = labels
                .iter()
                .position(|l| format!("res:{l}") == edges[i].to)
            else {
                continue;
            };
            let mut rec: Vec<MapRecent> = parts.parts[node_idx]
                .window
                .recent
                .iter()
                .filter(|r| r.client == dev_key)
                .map(|r| MapRecent {
                    ts_unix_micros: r.ts_us,
                    total_ms: r.ms,
                    status: wrendns_telemetry::Status::from_u8(r.status)
                        .map_or("unknown", wrendns_telemetry::Status::label)
                        .to_owned(),
                })
                .collect();
            let skip = rec.len().saturating_sub(RECENT_PER_EDGE);
            rec.drain(..skip);
            edges[i].recent = rec;
        }
    }
    if edges.len() > MAX_EDGES {
        truncated = true;
        edges.sort_by_key(|e| std::cmp::Reverse(e.count));
        edges.truncate(MAX_EDGES);
    }

    // Order: by kind (as a reader draws them), then id: the same input gives the same bytes.
    nodes.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.id.cmp(&b.id)));
    edges.sort_by(|a, b| a.from.cmp(&b.from).then_with(|| a.to.cmp(&b.to)));
    let mut counts = MapCounts::default();
    let mut health = MapHealth::Idle;
    for n in &nodes {
        counts.add(n.health);
        if matches!(n.kind, MapNodeKind::Resolver | MapNodeKind::Network) {
            health = health.worst(n.health);
        }
    }
    MapSnapshot {
        generated_at: crate::time::format_us(ctx.now_unix_seconds.saturating_mul(1_000_000)),
        window_secs,
        sample_rate,
        dropped,
        privacy,
        truncated,
        partial: !missing.is_empty() || !pending.is_empty(),
        missing_nodes: missing,
        health,
        counts,
        nodes,
        edges,
    }
}

// ---------------------------------------------------------------------------------------------
// `GET /api/v1/map/health` and the MCP tool: the short version for an agent

/// One node that isn't green, with why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthProblem {
    pub id: String,
    pub kind: MapNodeKind,
    pub label: String,
    pub health: MapHealth,
    pub reasons: Vec<MapReason>,
}

/// One of the busiest flows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthFlow {
    pub from: String,
    pub to: String,
    /// REQ: API-013 (T35.3) — `from` and `to` in words (a device's name, an upstream's display
    /// label), for an agent that reads the answer to a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_label: Option<String>,
    pub qps: f64,
    pub health: MapHealth,
}

/// `GET /api/v1/map/health`: counts by health, what is red or yellow and why, and the busiest
/// flows. Device names are left out at privacy level 2 and above (they are not in the map then).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NetworkHealth {
    pub generated_at: String,
    pub health: MapHealth,
    pub counts: MapCounts,
    /// Red first, then yellow; at most 50.
    pub problems: Vec<HealthProblem>,
    /// The five busiest flows.
    pub busiest: Vec<HealthFlow>,
    pub sample_rate: u32,
    pub privacy: u8,
    pub partial: bool,
    pub missing_nodes: Vec<String>,
}

/// The short version of a snapshot.
pub fn network_health(s: &MapSnapshot) -> NetworkHealth {
    let mut problems: Vec<HealthProblem> = s
        .nodes
        .iter()
        .filter(|n| matches!(n.health, MapHealth::Red | MapHealth::Yellow))
        .map(|n| HealthProblem {
            id: n.id.clone(),
            kind: n.kind,
            label: n.label.clone(),
            health: n.health,
            reasons: n.reasons.clone(),
        })
        .collect();
    problems.sort_by(|a, b| b.health.cmp(&a.health).then_with(|| a.id.cmp(&b.id)));
    problems.truncate(50);
    let labels: BTreeMap<&str, &str> = s
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), n.label.as_str()))
        .collect();
    let mut flows: Vec<&MapEdge> = s.edges.iter().filter(|e| !e.structural).collect();
    flows.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.from.cmp(&b.from))
            .then_with(|| a.to.cmp(&b.to))
    });
    NetworkHealth {
        generated_at: s.generated_at.clone(),
        health: s.health,
        counts: s.counts,
        problems,
        busiest: flows
            .into_iter()
            .take(5)
            .map(|e| HealthFlow {
                from: e.from.clone(),
                to: e.to.clone(),
                from_label: labels.get(e.from.as_str()).map(|l| (*l).to_owned()),
                to_label: labels.get(e.to.as_str()).map(|l| (*l).to_owned()),
                qps: e.qps,
                health: e.health,
            })
            .collect(),
        sample_rate: s.sample_rate,
        privacy: s.privacy,
        partial: s.partial,
        missing_nodes: s.missing_nodes.clone(),
    }
}

// ---------------------------------------------------------------------------------------------
// The world view (OBS-902, ADR-958 section 5, ADR-959)

/// One country of the world view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorldRegion {
    /// The two-letter country code.
    pub cc: String,
    /// The code again: the console writes the country's name.
    pub name: String,
    pub qps: f64,
    pub count: u64,
    pub slow_pct: f64,
    pub health: MapHealth,
}

/// An upstream placed on the map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorldMarker {
    pub name: String,
    pub cc: Option<String>,
    pub qps: f64,
    pub health: MapHealth,
}

/// Answers that have no place on the map, and why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorldUnlocated {
    pub count: u64,
    pub reason: Option<String>,
}

/// `GET /api/v1/map/world`: where answers point.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MapWorld {
    /// True when answers are placed (`regions`). False when they can't be: `reason` says why
    /// (`geoip_off`, `geoip_missing`, `address_not_recorded` or `privacy`). With
    /// `address_not_recorded` the upstream `markers` are still there: they are where the
    /// upstreams are, not where answers point (the lookup's answer address isn't kept: ADR-970).
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub updated_at: String,
    pub window_secs: f64,
    /// The country arcs start from (`[map.geoip] home_country`); unset: "Your network".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_country: Option<String>,
    pub regions: Vec<WorldRegion>,
    pub markers: Vec<WorldMarker>,
    /// Upstreams with no place on the map (a host name, or an address with no country).
    pub unplaced_upstreams: u64,
    pub unlocated: WorldUnlocated,
}

/// What the answering node's GeoIP database says about some addresses.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum GeoState {
    /// `[map.geoip] enabled` is off.
    #[default]
    Off,
    /// On, with no usable database on this node.
    Missing,
    Ready,
}

/// The GeoIP lookup of a backend: its state, the home country, and one country per address
/// asked (`None`: no country).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GeoAnswer {
    pub state: GeoState,
    pub home: Option<String>,
    pub countries: Vec<Option<String>>,
}

/// The first address of the /24 (IPv4) or /48 (IPv6) containing `ip`.
pub fn prefix_of(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(a) => IpAddr::V4((u32::from(a) & 0xffff_ff00).into()),
        IpAddr::V6(a) => IpAddr::V6((u128::from(a) & !((1u128 << 80) - 1)).into()),
    }
}

fn total_weighted(parts: &MapParts) -> u64 {
    parts
        .parts
        .iter()
        .map(|p| {
            let mut a = Agg::default();
            a.add(&p.window.other);
            for e in &p.window.entries {
                a.add(&e.c);
            }
            a.weighted
        })
        .sum()
}

/// One upstream across the nodes: its address, the worst breaker, and its counters.
#[derive(Default)]
struct WorldUp {
    ip: Option<IpAddr>,
    breaker: Option<Breaker>,
    agg: Agg,
}

/// The world view from every node's part. `locate` is the answering node's GeoIP database
/// (blocking: the caller runs this inside `blocking()`); it is asked once, for at most
/// [`MAX_PREFIXES`] prefixes and the upstreams' addresses.
///
/// Prefixes merge across nodes (the same prefix on two nodes adds). At privacy level 3 nothing
/// per event is kept, so every answer is unlocated (`privacy`); levels 0 to 2 place answers,
/// because an answer's address says nothing about a device (ADR-958 section 7).
#[allow(clippy::too_many_lines)] // one pass: merge, ask the database once, then markers and regions
pub fn world(
    parts: &MapParts,
    th: &Thresholds,
    now_unix_seconds: u64,
    node: Option<&str>,
    locate: &dyn Fn(&[IpAddr]) -> GeoAnswer,
) -> MapWorld {
    // `node` narrows the read to one WrenDNS node (its label, any case). The other map
    // filters have nothing to narrow: a prefix is counted per node, not per device (ADR-1009).
    let narrowed;
    let parts = match node {
        Some(n) => {
            narrowed = MapParts {
                parts: parts
                    .parts
                    .iter()
                    .filter(|p| {
                        let label = if p.node.is_empty() {
                            "node"
                        } else {
                            p.node.as_str()
                        };
                        label.eq_ignore_ascii_case(n)
                    })
                    .cloned()
                    .collect(),
                missing: parts.missing.clone(),
                unseen: parts.unseen.clone(),
                pending: parts.pending.clone(),
            };
            &narrowed
        }
        None => parts,
    };
    let total = total_weighted(parts);
    let window_secs = parts
        .parts
        .iter()
        .map(|p| p.window.window_secs)
        .max()
        .unwrap_or(wrendns_telemetry::map::WINDOW_SECS);
    let secs = f64::from(window_secs.max(1));
    let privacy = parts
        .parts
        .iter()
        .map(|p| p.window.privacy)
        .max()
        .unwrap_or(0);
    let base = |available: bool, reason: Option<&str>, home: Option<String>| MapWorld {
        available,
        reason: reason.map(str::to_owned),
        updated_at: crate::time::format_us(now_unix_seconds.saturating_mul(1_000_000)),
        window_secs: f64::from(window_secs),
        home_country: home,
        regions: Vec::new(),
        markers: Vec::new(),
        unplaced_upstreams: 0,
        unlocated: WorldUnlocated {
            count: total,
            reason: reason.map(str::to_owned),
        },
    };

    // Merge the prefixes and the upstreams' addresses, then ask once.
    let mut merged: BTreeMap<IpAddr, Agg> = BTreeMap::new();
    let recorded = parts.parts.iter().any(|p| p.answers_recorded);
    if privacy < 3 {
        for p in &parts.parts {
            for a in &p.answers {
                let e = merged.entry(prefix_of(a.addr)).or_default();
                e.weighted += a.weighted;
                e.sampled += a.sampled;
                e.slow += a.slow;
            }
        }
    }
    // The busiest prefixes survive the merge cap.
    let mut ranked: Vec<(IpAddr, Agg)> = merged.into_iter().collect();
    ranked.sort_by(|a, b| b.1.weighted.cmp(&a.1.weighted).then(a.0.cmp(&b.0)));
    ranked.truncate(MAX_PREFIXES);

    let mut ups: BTreeMap<String, WorldUp> = BTreeMap::new();
    for p in &parts.parts {
        for u in &p.upstreams {
            let e = ups.entry(u.name.clone()).or_default();
            e.ip = e.ip.or(u.ip);
            let b = Breaker::parse(&u.breaker);
            e.breaker = Some(e.breaker.map_or(b, |x| x.max(b)));
            for en in &p.window.entries {
                if en.kind == AnswerKind::Upstream && en.upstream == u.id {
                    e.agg.add(&en.c);
                }
            }
        }
    }
    let mut addrs: Vec<IpAddr> = ranked.iter().map(|(a, _)| *a).collect();
    let up_names: Vec<String> = ups
        .iter()
        .filter(|(_, u)| u.ip.is_some())
        .map(|(n, _)| n.clone())
        .collect();
    addrs.extend(up_names.iter().filter_map(|n| ups[n].ip));
    let geo = locate(&addrs);
    match geo.state {
        GeoState::Off => return base(false, Some("geoip_off"), None),
        GeoState::Missing => return base(false, Some("geoip_missing"), geo.home),
        GeoState::Ready => {}
    }
    let cc_of = |i: usize| {
        geo.countries
            .get(i)
            .cloned()
            .flatten()
            .map(|c| c.to_ascii_uppercase())
    };

    // Markers: one per upstream that has a country.
    let mut markers = Vec::new();
    let mut unplaced = 0u64;
    for (k, name) in up_names.iter().enumerate() {
        let u = &ups[name];
        if let Some(cc) = cc_of(ranked.len() + k) {
            let facts = Facts {
                breaker: u.breaker.unwrap_or(Breaker::Closed),
                ..Facts::default()
            };
            let (health, _) = classify(&u.agg, th, Scope::Upstream, &facts);
            markers.push(WorldMarker {
                name: display_label(name),
                cc: Some(cc),
                qps: rate(u.agg.weighted, secs),
                health,
            });
        } else {
            unplaced += 1;
        }
    }
    unplaced += (ups.len() - up_names.len()) as u64;

    if privacy >= 3 {
        let mut w = base(false, Some("privacy"), geo.home);
        w.markers = markers;
        w.unplaced_upstreams = unplaced;
        return w;
    }
    if !recorded {
        let mut w = base(false, Some("address_not_recorded"), geo.home);
        w.markers = markers;
        w.unplaced_upstreams = unplaced;
        return w;
    }

    // Regions: the prefixes' counters added by country.
    let mut by_cc: BTreeMap<String, Agg> = BTreeMap::new();
    let mut located = 0u64;
    for (i, (_, a)) in ranked.iter().enumerate() {
        if let Some(cc) = cc_of(i) {
            located += a.weighted;
            by_cc.entry(cc).or_default().plus(a);
        }
    }
    let mut regions: Vec<WorldRegion> = by_cc
        .into_iter()
        .map(|(cc, a)| {
            let (health, _) = classify(&a, th, Scope::Edge, &Facts::default());
            WorldRegion {
                name: cc.clone(),
                cc,
                qps: rate(a.weighted, secs),
                count: a.weighted,
                slow_pct: Agg::pct(a.slow, a.weighted),
                health,
            }
        })
        .collect();
    regions.sort_by(|a, b| b.count.cmp(&a.count).then(a.cc.cmp(&b.cc)));
    regions.truncate(MAX_REGIONS);
    MapWorld {
        available: true,
        reason: None,
        updated_at: crate::time::format_us(now_unix_seconds.saturating_mul(1_000_000)),
        window_secs: f64::from(window_secs),
        home_country: geo.home,
        regions,
        markers,
        unplaced_upstreams: unplaced,
        unlocated: WorldUnlocated {
            count: total.saturating_sub(located),
            reason: None,
        },
    }
}

/// A rate from an estimate and a window.
#[allow(clippy::cast_precision_loss)] // counts are far below 2^52
fn rate(count: u64, secs: f64) -> f64 {
    ((count as f64 / secs) * 100.0).round() / 100.0
}

/// The parts of every node merged for a reader that wants one window (the cluster read): the
/// same edge on two nodes adds, and a device that asked both lists once.
///
/// [`build`] does this as it goes (it keys devices by client and adds per node); this helper is
/// for tests and for a caller that wants the sums.
pub fn merged_totals(parts: &MapParts) -> BTreeMap<(ClientKey, AnswerKind, String), Agg> {
    let mut out: BTreeMap<(ClientKey, AnswerKind, String), Agg> = BTreeMap::new();
    for p in &parts.parts {
        for e in &p.window.entries {
            let up = if e.kind == AnswerKind::Upstream {
                p.upstreams
                    .iter()
                    .find(|u| u.id == e.upstream)
                    .map_or_else(|| format!("upstream {}", e.upstream), |u| u.name.clone())
            } else {
                String::new()
            };
            out.entry((e.client, e.kind, up)).or_default().add(&e.c);
        }
    }
    out
}

#[cfg(test)]
mod tests;

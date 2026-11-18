//! REQ: OBS-901 (T26.2, ADR-958) — the live network map as data: the snapshot model, the
//! health classification (one pure function, table-tested), the merge of every node's window,
//! and the snapshot builder. Nothing here touches the DNS path: the sampler lives on the
//! aggregator thread (`telltale_telemetry::map`), and this module only reads what it kept.
//!
//! A snapshot is `nodes` and `edges`, all derived and none stored: the gateway, the networks, the
//! devices (the 200 busiest; the rest fold into one `+N more` node per network), one resolver per
//! TelltaleDNS node with its three terminal answer kinds, and the upstreams. An edge carries its
//! rate over the 60 s window, the shares of slow, failing and blocked answers, and a health.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use telltale_config::{Cidr, MapConfig};
use telltale_telemetry::map::{AnswerKind, ClientKey, Counts, Window};
use utoipa::ToSchema;

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
    /// `not_configured`, `few_samples`, `children`.
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
    /// The TelltaleDNS node a resolver or an answer node belongs to.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartUpstream {
    pub id: u16,
    pub name: String,
    /// `closed`, `open` or `half_open`.
    pub breaker: String,
}

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
}

/// The parts a read has: every node that answered, and the labels of those that didn't.
#[derive(Debug, Clone, Default)]
pub struct MapParts {
    pub parts: Vec<MapPart>,
    pub missing: Vec<String>,
    /// Members this node has no stream to but the cluster's health relay reports up (a replica
    /// in manual failover sees only the primary): shown idle, not red (ADR-971).
    pub unseen: Vec<String>,
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
    /// A TelltaleDNS node's label.
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
        .unwrap_or(telltale_telemetry::map::WINDOW_SECS);

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
    for (name, a) in &up_total {
        let b = breakers.get(name).copied().unwrap_or(Breaker::Closed);
        let (h, why) = classify(
            a,
            th,
            Scope::Upstream,
            &Facts {
                breaker: b,
                ..Facts::default()
            },
        );
        up_health.insert(name.clone(), h);
        nodes.push(MapNode {
            id: format!("up:{name}"),
            kind: MapNodeKind::Upstream,
            label: name.clone(),
            health: h,
            reasons: why,
            qps: qps_of(a.weighted),
            count: a.weighted,
            sampled: a.sampled,
            address: None,
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
            children.push(up_health.get(&u.name).copied().unwrap_or(h));
            edges.push(edge_of(res_id.clone(), format!("up:{}", u.name), &a, h));
        }
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
                    status: telltale_telemetry::Status::from_u8(r.status)
                        .map_or("unknown", telltale_telemetry::Status::label)
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
        partial: !missing.is_empty(),
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
// The world view's answer until T26.5 (ADR-958 section 5, T26.2 step 1)

/// One country of the world view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorldRegion {
    pub cc: String,
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
    /// False when it can't be drawn; `reason` says why: `geoip_off`, `geoip_missing` or
    /// `address_not_recorded` (the lookup's answer address isn't kept: ADR-970).
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub updated_at: String,
    pub regions: Vec<WorldRegion>,
    pub markers: Vec<WorldMarker>,
    pub unlocated: WorldUnlocated,
}

/// The world view while the answer address isn't recorded: nothing can be placed, and every
/// lookup counts as unlocated.
pub fn world_unavailable(parts: &MapParts, now_unix_seconds: u64) -> MapWorld {
    let total: u64 = parts
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
        .sum();
    MapWorld {
        available: false,
        reason: Some("address_not_recorded".into()),
        updated_at: crate::time::format_us(now_unix_seconds.saturating_mul(1_000_000)),
        regions: Vec::new(),
        markers: Vec::new(),
        unlocated: WorldUnlocated {
            count: total,
            reason: Some("address_not_recorded".into()),
        },
    }
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

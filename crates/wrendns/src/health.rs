//! REQ: OBS-015 (ADR-104) — one word for how WrenDNS is doing (`healthy`, `degraded`,
//! `severe`) and the reasons, for the web UI's health icon, scripts, and agents.
//!
//! - **severe:** DNS fails for some devices: every upstream of a group down, no node serving, or
//!   SERVFAIL for [`SERVFAIL_SEVERE`]% of the last 5 minutes' queries.
//! - **degraded:** DNS answers, but something needs a look: one upstream down, a node
//!   unreachable, not serving, or behind on configuration, a list failing to download, devices
//!   rate-limited, SERVFAIL for [`SERVFAIL_DEGRADED`]%, a data disk over [`DISK_FULL`]% full.
//!
//! Each condition is judged over a window it already has (the circuit breaker, the last 5
//! minutes, the cluster heartbeat), so a single blip doesn't flip the level. Device anomalies
//! don't count (they have their own badge). Pure functions over what the API already reads;
//! nothing here touches the query path.

use std::collections::{BTreeMap, HashSet};

use wrendns_api::model::{ClusterView, Health, HealthReason, ListInfo, TimeBucket, UpstreamInfo};

pub(crate) const DEGRADED: &str = "degraded";
pub(crate) const SEVERE: &str = "severe";
/// SERVFAIL shares (percent) over the last 5 minutes that degrade or are severe...
pub(crate) const SERVFAIL_DEGRADED: f64 = 5.0;
pub(crate) const SERVFAIL_SEVERE: f64 = 25.0;
/// ...once there were at least this many queries.
const MIN_QUERIES: u64 = 50;
/// A data disk fuller than this (percent) degrades.
pub(crate) const DISK_FULL: f64 = 90.0;
/// A replica behind the primary's configuration for this long degrades.
const SYNC_LAG_SECONDS: u64 = 60;
/// REQ: OBS-010 (T24.5, fork #2) — the health icon's fixed threshold for a replica that hasn't
/// reached its primary (ADR-104 fixed thresholds; the alert rule's `threshold` is its own).
pub(crate) const PRIMARY_UNREACHABLE_SECONDS: u64 = 60;

/// REQ: DSC-002 (T25.3, DSC-014) — a discovery worker that is refused for its build, or that keeps
/// crashing, is degraded. It never makes DNS unhealthy: the inventory is not on the query path.
pub(crate) fn discovery_reasons(
    workers: &[wrendns_api::model::DiscoveryWorker],
    agents: &[wrendns_api::model::DiscoveryAgent],
) -> Vec<HealthReason> {
    let mut out = Vec::new();
    // REQ: DSC-004, DSC-014 (T25.6) - an SNMP agent whose last three polls failed is degraded: its
    // devices stop being refreshed. Never severe: DNS doesn't depend on the inventory.
    for a in agents.iter().filter(|a| a.state == "failing") {
        out.push(reason(
            DEGRADED,
            "discovery_agent_failing",
            format!(
                "the SNMP agent `{}` failed {} polls in a row ({}). DNS is unaffected",
                a.name,
                a.consecutive_failures,
                a.last_error.as_deref().unwrap_or("no reply")
            ),
            "#/network-inventory",
        ));
    }
    for w in workers {
        if w.version_mismatch {
            out.push(reason(
                DEGRADED,
                "discovery_worker_version_mismatch",
                format!(
                    "the {} discovery worker is refused: its build differs from this node's ({})",
                    w.worker,
                    w.last_error.as_deref().unwrap_or("unknown")
                ),
                "#/network-inventory",
            ));
        }
        if w.failing {
            out.push(reason(
                DEGRADED,
                "discovery_worker_failing",
                format!(
                    "the {} discovery worker keeps stopping ({} restarts); its restarts are slowed. DNS is unaffected",
                    w.worker, w.restarts
                ),
                "#/network-inventory",
            ));
        }
    }
    out
}

/// REQ: DNS-901 (ADR-1090 point 1) — listeners that are gated only because `require_client_id` is
/// unset on a public address: degraded (DNS answers, but clients without a key are refused)
/// until the configuration sets the flag, to `true` to keep it or `false` to open the listener.
pub(crate) fn gate_default_reasons(
    listen: &[wrendns_config::Listener],
    host: wrendns_config::HostFacts,
) -> Vec<HealthReason> {
    let names: Vec<String> = listen
        .iter()
        .filter(|l| l.gated_by_default(host))
        .map(|l| format!("{:?}://{}", l.proto, l.addr).to_lowercase())
        .collect();
    if names.is_empty() {
        return Vec::new();
    }
    vec![reason(
        DEGRADED,
        "listener_gate_default",
        format!(
            "{} refuse{} queries without a known device key, because require_client_id is not set and the default is on (a public address, or a wildcard bind on a host with a public IPv4 address). Set it to true to keep this, or false to open the listener",
            names.join(", "),
            if names.len() == 1 { "s" } else { "" }
        ),
        "#/settings?tab=system",
    )]
}

/// REQ: DNS-901 (ADR-1090 point 2) — the host gained or lost a public IPv4 address since a
/// listener was bound, and an encrypted listener with no setting would now resolve its default the
/// other way. Degraded until the next reload (or restart) applies it. `bound` gives the host facts
/// each listener was bound with, `now` the facts now.
pub(crate) fn gate_stale_reasons(
    listen: &[wrendns_config::Listener],
    bound: &dyn Fn(&wrendns_config::Listener) -> wrendns_config::HostFacts,
    now: wrendns_config::HostFacts,
) -> Vec<HealthReason> {
    let flipping: Vec<&wrendns_config::Listener> = listen
        .iter()
        .filter(|l| l.require_client_id.is_none() && l.proto.needs_tls())
        .filter(|l| l.default_gate(bound(l)).on() != l.default_gate(now).on())
        .collect();
    if flipping.is_empty() {
        return Vec::new();
    }
    let names: Vec<String> = flipping
        .iter()
        .map(|l| format!("{:?}://{}", l.proto, l.addr).to_lowercase())
        .collect();
    // The word is the new default of the listeners named, and of no other.
    let word = if flipping.iter().all(|l| l.default_gate(now).on()) {
        "on"
    } else if flipping.iter().all(|l| !l.default_gate(now).on()) {
        "off"
    } else {
        "on or off, each as the host now implies"
    };
    vec![reason(
        DEGRADED,
        "listener_gate_stale",
        format!(
            "this host's addresses changed since the listeners were bound, so the default device key setting of {} would now be {word}. Reload the configuration (SIGHUP) to apply it, or set require_client_id to true or false",
            names.join(", "),
        ),
        "#/settings?tab=system",
    )]
}

/// REQ: DNS-901 (ADR-1090 point 3) — an encrypted listener whose socket is not what the
/// configuration asks for after an apply (its certificate could not be read, or the bind failed);
/// `listeners` is `(name, running)`. A change that turns the gate on closes the old ungated socket
/// (`running` false); one that turns it off keeps the old gated one.
pub(crate) fn listener_not_applied_reasons(listeners: &[(String, bool)]) -> Vec<HealthReason> {
    if listeners.is_empty() {
        return Vec::new();
    }
    let names: Vec<String> = listeners
        .iter()
        .map(|(n, running)| {
            format!(
                "{n} ({})",
                if *running {
                    "still running with its previous settings"
                } else {
                    "closed"
                }
            )
        })
        .collect();
    vec![reason(
        DEGRADED,
        "listener_not_applied",
        format!(
            "the listener(s) {} do not match the configuration, because the last apply could not load the certificate or bind. A listener whose device key gate was turned on is closed rather than left open; fix the certificate or the address and reload (SIGHUP)",
            names.join(", ")
        ),
        "#/settings?tab=system",
    )]
}

/// REQ: DSC-906 (T31.2, ADR-1005 section 13) — the CMDB dropping things at a cap, or failing to write, is
/// degraded. It never makes DNS unhealthy: the CMDB is not on the query path (CLU-004).
pub(crate) fn cmdb_reasons(s: &wrendns_api::cmdb_api::CmdbStatus) -> Vec<HealthReason> {
    let mut out = Vec::new();
    if !s.running {
        return out;
    }
    if s.dropped.ci > 0 {
        out.push(reason(
            DEGRADED,
            "cmdb_ci_cap",
            format!(
                "the CMDB refused {} new CIs: it holds the most it keeps and every one is authored. DNS is unaffected",
                s.dropped.ci
            ),
            "#/cmdb",
        ));
    }
    if s.dropped.record > 0 || s.dropped.batch > 0 {
        out.push(reason(
            DEGRADED,
            "cmdb_dropping",
            format!(
                "the CMDB dropped {} records and {} batches at its caps. DNS is unaffected",
                s.dropped.record, s.dropped.batch
            ),
            "#/cmdb",
        ));
    }
    if let Some(e) = &s.last_error {
        out.push(reason(
            DEGRADED,
            "cmdb_failing",
            format!("the CMDB's last error: {e}. DNS is unaffected"),
            "#/cmdb",
        ));
    }
    out
}

/// REQ: DSC-908, CLD-920 (ADR-1096 point 5; T36.10a0) — a change the upgrade gate is holding back
/// because a member's build does not know the new section or secret kind: degraded, DNS
/// unaffected. `holds` are the refusals' words, which name the member and its version.
pub(crate) fn upgrade_gate_reasons(holds: &[String]) -> Vec<HealthReason> {
    holds
        .iter()
        .map(|h| {
            reason(
                DEGRADED,
                "upgrade_gate_holding",
                format!(
                    "a change is held back until every member is upgraded: {h}. DNS is unaffected"
                ),
                "#/cluster",
            )
        })
        .collect()
}

/// REQ: DSC-908, CLD-904 (ADR-1104 point 5) - a primary that started with locations or DNS providers
/// and holds them out until every member is heard from and knows them: degraded, DNS unaffected (it
/// answers as without them). `held` is the words naming the member, or that the members are
/// awaited. The code stays `locations_held` (the first table the hold covered).
pub(crate) fn locations_held_reasons(held: Option<&str>) -> Vec<HealthReason> {
    held.map(|h| {
        reason(
            DEGRADED,
            "locations_held",
            format!(
                "locations, device pins and DNS providers that the configuration holds are held out until the members are checked: {h}. DNS answers as without them"
            ),
            "#/cluster",
        )
    })
    .into_iter()
    .collect()
}

/// REQ: DNS-906 (T40.5) - a root key in its add hold-down, or a trust anchor the root revoked:
/// degraded, DNS unaffected. `items` are `Rollover::reasons`.
pub(crate) fn anchor_reasons(items: Vec<(&'static str, String)>) -> Vec<HealthReason> {
    items
        .into_iter()
        .map(|(code, text)| reason(DEGRADED, code, text, "#/settings?tab=queries"))
        .collect()
}

fn reason(level: &str, code: &str, summary: String, link: &str) -> HealthReason {
    HealthReason {
        level: level.to_owned(),
        code: code.to_owned(),
        summary,
        node: None,
        link: Some(link.to_owned()),
    }
}

/// What one node knows about itself.
pub(crate) struct Local<'a> {
    /// Its DNS listeners are bound and it isn't shutting down.
    pub(crate) serving: bool,
    pub(crate) upstreams: &'a [UpstreamInfo],
    /// Minute buckets of the last 5 minutes.
    pub(crate) recent: &'a [TimeBucket],
    /// Its lists, when it downloads them (a replica takes the primary's snapshot instead).
    pub(crate) lists: Option<&'a [ListInfo]>,
    pub(crate) disk_used_percent: Option<f64>,
    /// REQ: OBS-020 — its synthetic probes, and when a certificate expiring counts.
    pub(crate) probes: &'a [wrendns_api::model::ProbeResult],
    pub(crate) cert_warn_days: u32,
    /// REQ: FLT-017 — this node watches Kubernetes and its table is this many seconds old
    /// (`None`: it doesn't watch, or the table is fresh).
    pub(crate) kubernetes_stale_s: Option<u64>,
    /// REQ: FLT-901 (ADR-994 item 7) — category IDs a group names that this version does not
    /// know (a newer node wrote them): `(group, id)`. They are ignored, and reported.
    pub(crate) unknown_categories: &'a [(String, String)],
}

/// REQ: OBS-020 (ADR-107) — listeners (or extra targets) that failed their probe twice in a
/// row are degraded; when every probed listener does, the node isn't serving DNS (`not_serving`,
/// severe unless other nodes serve). A certificate within `cert_warn_days` is degraded; an
/// expired one is severe: DoT/DoH/DoQ clients can't connect.
fn probe_reasons(l: &Local<'_>, out: &mut Vec<HealthReason>) {
    let failing = |p: &&wrendns_api::model::ProbeResult| {
        p.skipped.is_none() && p.consecutive_failures >= crate::probes::FAILING_AFTER
    };
    // The web UI's check (ADR-149) isn't a DNS listener: it never makes "not answering DNS".
    let listeners: Vec<_> = l
        .probes
        .iter()
        .filter(|p| {
            p.listener
                && p.skipped.is_none()
                && p.proto != crate::probes::API_PROTO
                && p.proto != crate::probes::REDIRECT_PROTO
        })
        .collect();
    if l.serving && !listeners.is_empty() && listeners.iter().all(failing) {
        out.push(reason(
            SEVERE,
            "not_serving",
            "isn't answering DNS: none of its listeners answers its own probe".into(),
            "#/settings?tab=system",
        ));
    } else {
        for p in l.probes.iter().filter(failing) {
            let what = if p.proto == crate::probes::API_PROTO {
                "the web UI at"
            } else if p.proto == crate::probes::REDIRECT_PROTO {
                // REQ: API-003 (T24.44) — the plain-HTTP redirect isn't a DNS listener either.
                "the HTTP to HTTPS redirect at"
            } else if p.listener {
                "listener"
            } else {
                "probe target"
            };
            out.push(reason(
                DEGRADED,
                "probe_failing",
                format!(
                    "{what} {} doesn't answer its probe ({} in a row: {})",
                    p.public_target(),
                    p.consecutive_failures,
                    p.error.as_deref().unwrap_or("no answer")
                ),
                "#/settings?tab=system",
            ));
        }
    }
    for p in l.probes {
        let who = if p.proto == crate::probes::API_PROTO {
            "browsers and tools can't open the web UI"
        } else {
            "encrypted DNS clients can't connect"
        };
        match p.cert_days_left {
            Some(d) if d < 0 => out.push(reason(
                SEVERE,
                "cert_expired",
                format!(
                    "the certificate of {} expired {} day(s) ago: {who}",
                    p.public_target(),
                    -d
                ),
                "#/settings?tab=system",
            )),
            Some(d) if d < i64::from(l.cert_warn_days) => out.push(reason(
                DEGRADED,
                "cert_expiring",
                format!(
                    "the certificate of {} expires in {d} day(s)",
                    p.public_target()
                ),
                "#/settings?tab=system",
            )),
            _ => {}
        }
    }
}

/// One node's own conditions.
#[allow(clippy::too_many_lines)] // one check after another
pub(crate) fn local_reasons(l: &Local<'_>) -> Vec<HealthReason> {
    let mut out = Vec::new();
    if !l.serving {
        out.push(reason(
            SEVERE,
            "not_serving",
            "isn't answering DNS: its listeners aren't bound, or it's shutting down".into(),
            "#/cluster",
        ));
    }
    upstream_reasons(l.upstreams, &mut out);
    probe_reasons(l, &mut out);
    let sum =
        |f: &dyn Fn(&TimeBucket) -> u32| -> u64 { l.recent.iter().map(|b| u64::from(f(b))).sum() };
    let total = sum(&|b| b.total);
    let limited = sum(&|b| b.by_status.get("rate_limited").copied().unwrap_or(0));
    if limited > 0 {
        out.push(reason(
            DEGRADED,
            "rate_limited",
            format!(
                "{limited} quer{} rate-limited in the last 5 minutes: a device asked faster than the per-client limit allows",
                if limited == 1 { "y was" } else { "ies were" }
            ),
            "#/queries?status=rate_limited&from=-5m",
        ));
    }
    let servfail = sum(&|b| b.by_rcode.get("SERVFAIL").copied().unwrap_or(0));
    if total >= MIN_QUERIES {
        #[allow(clippy::cast_precision_loss)] // query counts
        let pct = servfail as f64 * 100.0 / total as f64;
        let level = if pct >= SERVFAIL_SEVERE {
            Some(SEVERE)
        } else if pct >= SERVFAIL_DEGRADED {
            Some(DEGRADED)
        } else {
            None
        };
        if let Some(level) = level {
            out.push(reason(
                level,
                "servfail_rate",
                format!("SERVFAIL for {pct:.1}% of {total} queries in the last 5 minutes"),
                "#/queries?rcode=SERVFAIL&from=-5m",
            ));
        }
    }
    for list in l.lists.unwrap_or_default() {
        if list.enabled
            && let Some(e) = &list.error
        {
            out.push(reason(
                DEGRADED,
                "list_failing",
                format!("list {} fails to update: {e}", list.name),
                "#/lists",
            ));
        }
        // REQ: OBS-023 (T12.3) — downloads fine, but its content stopped changing.
        if list.enabled
            && list.error.is_none()
            && let Some(days) = list.stale_days
        {
            out.push(reason(
                DEGRADED,
                "list_stale",
                format!(
                    "list {} hasn't changed in {days} days: its source may be abandoned",
                    list.name
                ),
                "#/lists",
            ));
        }
    }
    // REQ: FLT-901 (ADR-994 item 7) — a category this version doesn't know is ignored, never an
    // error: DNS keeps answering from the categories it does know.
    if !l.unknown_categories.is_empty() {
        let names: Vec<String> = l
            .unknown_categories
            .iter()
            .map(|(g, c)| format!("{c} (group {g})"))
            .collect();
        out.push(reason(
            DEGRADED,
            "category_unknown",
            format!(
                "this version doesn't know the categor{} {}: ignored until the node is upgraded",
                if names.len() == 1 { "y" } else { "ies" },
                names.join(", ")
            ),
            "#/groups",
        ));
    }
    // REQ: FLT-017 (ADR-150) — the API server unreachable for 15 minutes: pods keep their
    // last names, new pods are plain addresses until it's back. DNS is unaffected.
    if let Some(s) = l.kubernetes_stale_s {
        out.push(reason(
            DEGRADED,
            "kubernetes_stale",
            format!(
                "the Kubernetes workload table is {} minutes old: pods may be named by address until the API server is reachable",
                s / 60
            ),
            "#/clients?tab=workloads",
        ));
    }
    if let Some(d) = l.disk_used_percent.filter(|d| *d > DISK_FULL) {
        out.push(reason(
            DEGRADED,
            "disk_full",
            format!("its data disk is {d:.0}% full"),
            "#/settings?tab=system",
        ));
    }
    out
}

/// Upstreams that aren't answering (an open or half-open circuit breaker): severe when that
/// leaves a group with none, degraded otherwise.
fn upstream_reasons(upstreams: &[UpstreamInfo], out: &mut Vec<HealthReason>) {
    let down = |u: &UpstreamInfo| u.breaker != "closed";
    let mut groups: BTreeMap<&str, (usize, Vec<&str>)> = BTreeMap::new();
    for u in upstreams {
        for g in &u.groups {
            let e = groups.entry(g.as_str()).or_default();
            e.0 += 1;
            if down(u) {
                e.1.push(u.name.as_str());
            }
        }
    }
    let mut covered: HashSet<&str> = HashSet::new();
    for (g, (members, down_names)) in &groups {
        if *members > 0 && down_names.len() == *members {
            out.push(reason(
                SEVERE,
                "upstream_group_down",
                format!(
                    "no upstream in group {g} is answering ({}): its devices' lookups fail",
                    down_names.join(", ")
                ),
                "#/upstreams",
            ));
            covered.extend(down_names.iter().copied());
        }
    }
    // REQ: UPS-013 (T24.31) — an upstream whose source address left the node.
    for u in upstreams {
        if let Some(p) = &u.source_problem {
            out.push(reason(
                DEGRADED,
                "upstream_source_lost",
                format!("upstream {}: {p}", u.name),
                "#/upstreams",
            ));
        }
    }
    // REQ: UPS-006 — no route to the address while the breaker is still closed (a spare nobody
    // has asked yet): the map shows it yellow, so say why here too.
    for u in upstreams.iter().filter(|u| !down(u)) {
        if let Some(p) = &u.route_problem {
            out.push(reason(
                DEGRADED,
                "upstream_no_route",
                format!("upstream {}: {p}", u.name),
                "#/upstreams",
            ));
        }
    }
    for u in upstreams
        .iter()
        .filter(|u| down(u) && !covered.contains(u.name.as_str()))
    {
        out.push(reason(
            DEGRADED,
            "upstream_down",
            format!(
                "upstream {} isn't answering (its circuit breaker is {}{}); the rest of its group answers",
                u.name,
                u.breaker.replace('_', "-"),
                // REQ: UPS-006 — say why when it is the route.
                u.route_problem
                    .as_deref()
                    .map(|p| format!(": {p}"))
                    .unwrap_or_default()
            ),
            "#/upstreams",
        ));
    }
}

/// REQ: CLU-013 — canaries set and none online this long degrades (changes skip the bake).
const ROLLOUT_STUCK_SECONDS: u64 = 600;

/// REQ: CLU-013 — the cluster pinned to an older version, or a change stuck waiting for a
/// canary.
fn rollout_reasons(view: &ClusterView) -> Vec<HealthReason> {
    let Some(r) = &view.rollout else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(p) = &r.pinned {
        out.push(reason(
            DEGRADED,
            "cluster_pinned",
            format!(
                "the cluster is pinned to version {} since {} by {}: {}; configuration changes wait until it's unpinned",
                p.to, p.since, p.by, p.reason
            ),
            "#/cluster?tab=rollouts",
        ));
    }
    if let Some(s) = r
        .canaries_offline_seconds
        .filter(|s| *s >= ROLLOUT_STUCK_SECONDS)
    {
        out.push(reason(
            DEGRADED,
            "rollout_stuck",
            format!(
                "no canary node has been online for {} minutes, so configuration changes reach every node without a staged rollout",
                s / 60
            ),
            "#/cluster?tab=rollouts",
        ));
    }
    out
}

/// The cluster's own conditions, as this node sees them: peers unreachable or behind.
pub(crate) fn cluster_reasons(view: &ClusterView) -> Vec<HealthReason> {
    let mut out = rollout_reasons(view);
    if !view.enabled {
        return out;
    }
    // REQ: OBS-010 (T24.5, fork #2) — a replica that hasn't reached its primary for a minute
    // (a silent split). Witnesses, resolver pods and nodes in maintenance are left out, as the
    // alert leaves them out.
    for n in view.nodes.iter().filter(|n| {
        n.role == "replica" && n.up && !n.witness && !n.ephemeral && n.maintenance.is_none()
    }) {
        if let Some(s) = n
            .primary_silent_seconds
            .filter(|s| *s >= PRIMARY_UNREACHABLE_SECONDS)
        {
            let name = node_name(n);
            let mut r = reason(
                DEGRADED,
                "primary_unreachable",
                format!("{name} hasn't reached its primary for {s} s"),
                "#/cluster",
            );
            r.node = Some(name);
            out.push(r);
        }
    }
    // REQ: CLU-009 (T24.33) — a witness that is unreachable still counts (automatic failover needs
    // its vote); it is never "behind" or "not serving", as it has no configuration and no DNS.
    for n in view.nodes.iter().filter(|n| !n.this_node) {
        let name = node_name(n);
        if !n.ephemeral && !n.connected {
            let mut r = reason(
                DEGRADED,
                "node_down",
                format!(
                    "cluster node {name} is unreachable (last seen {} s ago)",
                    n.last_seen_seconds_ago
                ),
                "#/cluster",
            );
            r.node = Some(name);
            out.push(r);
        } else if n.connected
            && !n.witness
            && n.config_lag > 0
            && n.behind_seconds.is_some_and(|s| s >= SYNC_LAG_SECONDS)
        {
            let mut r = reason(
                DEGRADED,
                "sync_lag",
                format!(
                    "{name} is {} configuration version(s) behind the primary (for {} s)",
                    n.config_lag,
                    n.behind_seconds.unwrap_or(0)
                ),
                "#/cluster",
            );
            r.node = Some(name);
            out.push(r);
        }
    }
    out
}

/// REQ: API-015, OBS-015 (T24.42) - a full member that has not applied the primary's stored
/// secrets for this long is degraded (a secret write reaches the members within seconds).
pub(crate) const SECRETS_LAG_SECONDS: u64 = 60;

/// When each node was first seen out of step with the primary's stored secrets, by node ID.
pub(crate) type SecretsSince = std::collections::HashMap<String, std::time::Instant>;

/// REQ: API-015, OBS-015 (T24.42) - a full member (never a witness or a resolver pod, which hold
/// none by design) whose applied secrets head differs from the primary's, or that can't read some
/// secret, for [`SECRETS_LAG_SECONDS`]: `secret_not_held`, degraded and never severe. DNS doesn't
/// depend on a stored secret, so this never marks DNS unhealthy. `since` remembers when each node
/// first looked out of step, so a write in flight isn't reported.
pub(crate) fn secret_reasons(
    view: &ClusterView,
    since: &mut SecretsSince,
    now: std::time::Instant,
) -> Vec<HealthReason> {
    let primary_head = view
        .nodes
        .iter()
        .find(|n| n.role == "primary")
        .and_then(|n| n.secrets.as_ref())
        .and_then(|s| s.head.clone());
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    if !view.enabled || primary_head.is_none() {
        since.clear();
        return out;
    }
    for n in view
        .nodes
        .iter()
        .filter(|n| !n.witness && !n.ephemeral && (n.this_node || n.connected))
    {
        let Some(s) = n.secrets.as_ref() else {
            continue;
        };
        if s.in_sync && s.unreadable == 0 {
            continue;
        }
        seen.insert(n.node_id.clone());
        let first = *since.entry(n.node_id.clone()).or_insert(now);
        if now.saturating_duration_since(first).as_secs() < SECRETS_LAG_SECONDS {
            continue;
        }
        let name = node_name(n);
        let what = if s.in_sync {
            format!(
                "{name} can't read {} of the stored secrets it holds",
                s.unreadable
            )
        } else {
            format!(
                "{name} hasn't received all the stored secrets (it holds {}, the primary {})",
                s.applied.as_deref().unwrap_or("none"),
                primary_head.as_deref().unwrap_or("none")
            )
        };
        let mut r = reason(
            DEGRADED,
            "secret_not_held",
            format!(
                "{what}; a router or webhook that needs one can't be read there after a failover. DNS is unaffected"
            ),
            "#/settings?tab=secrets",
        );
        r.node = Some(name);
        out.push(r);
    }
    since.retain(|k, _| seen.contains(k));
    out
}

/// REQ: OBS-016 (ADR-105) — `[slo]` as the API's settings.
pub(crate) fn slo_settings(cfg: &wrendns_config::Config) -> wrendns_api::slo::Settings {
    let s = &cfg.slo;
    wrendns_api::slo::Settings {
        enabled: s.enabled,
        availability_target: s.availability_target,
        latency_target: s.latency_target,
        latency_ms: s.latency_ms,
        window_days: s.window_days,
    }
}

/// REQ: OBS-016 (ADR-105) — degraded while an objective spends its error budget fast (the
/// `fast` or `slow` burn-rate pair), from `b`'s minute buckets of the last 6 hours.
pub(crate) fn slo_reasons(b: &dyn wrendns_api::Backend, now: u64) -> Vec<HealthReason> {
    let s = b.slo_settings();
    if !s.enabled {
        return Vec::new();
    }
    let minutes = b.timeseries(
        wrendns_api::model::Step::Minute,
        now.saturating_sub(wrendns_api::slo::MINUTE_SPAN_S),
        now + 1,
    );
    wrendns_api::slo::burning(&s, now, &minutes)
        .into_iter()
        .map(|(_, _, summary)| reason(DEGRADED, "slo_burn", summary, "#/"))
        .collect()
}

/// How the cluster page and every other reason name a node: its pod, else its site, else its ID.
fn node_name(n: &wrendns_api::model::ClusterNode) -> String {
    if let Some(pod) = n.pod.as_ref().filter(|p| !p.is_empty()) {
        pod.clone()
    } else if n.site.is_empty() {
        n.node_id.clone()
    } else {
        n.site.clone()
    }
}

/// In a cluster, a node that isn't serving leaves DNS to the others: degraded, unless none of
/// the `reporting` nodes serves.
pub(crate) fn soften_not_serving(reasons: &mut [HealthReason], reporting: usize) {
    let down = reasons.iter().filter(|r| r.code == "not_serving").count();
    if down < reporting {
        for r in reasons.iter_mut().filter(|r| r.code == "not_serving") {
            DEGRADED.clone_into(&mut r.level);
        }
    }
}

/// The level and the reasons, most serious first.
pub(crate) fn summarize(
    mut reasons: Vec<HealthReason>,
    missing_nodes: Vec<String>,
    checked_at: String,
) -> Health {
    let rank = |r: &HealthReason| u8::from(r.level == SEVERE);
    reasons.sort_by(|a, b| {
        rank(b)
            .cmp(&rank(a))
            .then_with(|| a.node.cmp(&b.node))
            .then_with(|| a.code.cmp(&b.code))
    });
    let level = if reasons.iter().any(|r| r.level == SEVERE) {
        SEVERE
    } else if reasons.is_empty() {
        "healthy"
    } else {
        DEGRADED
    };
    Health {
        level: level.to_owned(),
        reasons,
        checked_at,
        missing_nodes,
        maintenance: Vec::new(),
    }
}

/// REQ: OPS-010 (ADR-118) — leaves out the conditions of nodes in maintenance (by the label
/// reasons carry: pod, site, or ID) and lists those nodes instead. `missing` drops them too:
/// a node stopped during its window is expected to be silent.
pub(crate) fn exclude_maintenance(
    reasons: &mut Vec<HealthReason>,
    missing: &mut Vec<String>,
    view: &ClusterView,
) -> Vec<wrendns_api::model::NodeMaintenance> {
    let mut out = Vec::new();
    let mut names: HashSet<String> = HashSet::new();
    for n in &view.nodes {
        if let Some(m) = &n.maintenance {
            let name = node_name(n);
            names.insert(name.clone());
            // Probe and federated labels may use the site or the ID where a pod has none.
            names.insert(n.node_id.clone());
            if !n.site.is_empty() && n.pod.is_none() {
                names.insert(n.site.clone());
            }
            let mut m = m.clone();
            m.node = Some(name);
            out.push(m);
        }
    }
    if names.is_empty() {
        return out;
    }
    reasons.retain(|r| r.node.as_ref().is_none_or(|n| !names.contains(n)));
    missing.retain(|n| !names.contains(n));
    out.sort_by(|a, b| a.node.cmp(&b.node));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wrendns_api::model::FailureKinds;

    /// REQ: DNS-901 (ADR-1090 point 2) — a change of the host's public IPv4 address since bind
    /// raises a reason only for a wildcard listener whose default would flip.
    #[test]
    fn dns_901_gate_stale_reason_when_the_host_addresses_changed() {
        let l = |addr: &str, flag: Option<bool>| wrendns_config::Listener {
            proto: wrendns_config::ListenProto::Dot,
            addr: addr.parse().unwrap(),
            path: None,
            tls: None,
            proxy_protocol: false,
            max_connections: None,
            max_connections_per_address: None,
            require_client_id: flag,
        };
        let no = wrendns_config::HostFacts {
            public_ipv4: Some(false),
            global_ipv6: false,
        };
        let yes = wrendns_config::HostFacts {
            public_ipv4: Some(true),
            global_ipv6: false,
        };
        let bound = |_: &wrendns_config::Listener| no;
        assert!(gate_stale_reasons(&[l("0.0.0.0:853", None)], &bound, no).is_empty());
        let r = gate_stale_reasons(&[l("0.0.0.0:853", None)], &bound, yes);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].code, "listener_gate_stale");
        assert!(r[0].summary.contains("would now be on"), "{}", r[0].summary);
        // An explicit setting, a private address and a public address do not flip.
        assert!(
            gate_stale_reasons(
                &[
                    l("0.0.0.0:853", Some(false)),
                    l("192.168.1.2:853", None),
                    l("203.0.113.5:853", None)
                ],
                &bound,
                yes
            )
            .is_empty()
        );
        // The word follows the listeners that flip: the wildcard goes off, the public address
        // (on in both) is not named.
        let on_bound = |_: &wrendns_config::Listener| yes;
        let r = gate_stale_reasons(
            &[l("0.0.0.0:853", None), l("203.0.113.5:853", None)],
            &on_bound,
            no,
        );
        assert!(
            r[0].summary.contains("would now be off"),
            "{}",
            r[0].summary
        );
        assert!(!r[0].summary.contains("203.0.113.5"), "{}", r[0].summary);
    }

    /// REQ: DNS-901 — a listener that does not match the configuration is named, with whether it
    /// still runs.
    #[test]
    fn dns_901_listener_not_applied_reason_names_the_listener() {
        assert!(listener_not_applied_reasons(&[]).is_empty());
        let r = listener_not_applied_reasons(&[
            ("dot://0.0.0.0:853".to_owned(), false),
            ("doh://0.0.0.0:443".to_owned(), true),
        ]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].code, "listener_not_applied");
        assert!(r[0].summary.contains("dot://0.0.0.0:853 (closed)"));
        assert!(r[0].summary.contains("doh://0.0.0.0:443 (still running"));
    }

    /// REQ: DNS-901 — only a listener gated by the default (unset, public) raises the notice;
    /// an explicit setting acknowledges it.
    #[test]
    fn dns_901_gate_default_is_a_health_reason_until_the_flag_is_set() {
        let l = |addr: &str, flag: Option<bool>| wrendns_config::Listener {
            proto: wrendns_config::ListenProto::Dot,
            addr: addr.parse().unwrap(),
            path: None,
            tls: None,
            proxy_protocol: false,
            max_connections: None,
            max_connections_per_address: None,
            require_client_id: flag,
        };
        let private = wrendns_config::HostFacts {
            public_ipv4: Some(false),
            global_ipv6: false,
        };
        let public = wrendns_config::HostFacts {
            public_ipv4: Some(true),
            global_ipv6: false,
        };
        assert!(
            gate_default_reasons(
                &[l("192.168.1.2:853", None), l("0.0.0.0:853", None)],
                private
            )
            .is_empty()
        );
        // A wildcard bind on a host with a public IPv4 address is gated by default: a notice.
        let w = gate_default_reasons(&[l("0.0.0.0:853", None)], public);
        assert_eq!(w.len(), 1, "wildcard with a public IPv4 address");
        assert!(
            gate_default_reasons(&[l("[::ffff:0.0.0.0]:853", None)], public).len() == 1,
            "mapped wildcard"
        );
        assert!(
            gate_default_reasons(
                &[
                    l("203.0.113.5:853", Some(true)),
                    l("203.0.113.5:854", Some(false))
                ],
                private
            )
            .is_empty()
        );
        let r = gate_default_reasons(&[l("203.0.113.5:853", None)], private);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].code, "listener_gate_default");
        assert!(
            r[0].summary.contains("dot://203.0.113.5:853"),
            "{}",
            r[0].summary
        );
    }

    fn up(name: &str, groups: &[&str], breaker: &str) -> UpstreamInfo {
        UpstreamInfo {
            id: 1,
            name: name.into(),
            endpoint: format!("udp://{name}"),
            groups: groups.iter().map(|g| (*g).to_owned()).collect(),
            breaker: breaker.into(),
            requests: 0,
            failures: 0,
            failures_by_kind: FailureKinds::default(),
            latency_ewma_ms: 0.0,
            route_problem: None,
            source: None,
            source_problem: None,
        }
    }

    fn local<'a>(ups: &'a [UpstreamInfo], recent: &'a [TimeBucket]) -> Local<'a> {
        Local {
            serving: true,
            upstreams: ups,
            recent,
            lists: None,
            disk_used_percent: Some(40.0),
            probes: &[],
            cert_warn_days: 14,
            kubernetes_stale_s: None,
            unknown_categories: &[],
        }
    }

    /// REQ: FLT-901 (ADR-994 item 7) — a category id this version doesn't know is reported as
    /// degraded, naming the id and the group; nothing else changes.
    #[test]
    fn flt_901_unknown_category_ignored_and_reported() {
        let (ups, recent) = (Vec::new(), Vec::new());
        let unknown = [("kids".to_owned(), "from-the-future".to_owned())];
        let l = Local {
            unknown_categories: &unknown,
            ..local(&ups, &recent)
        };
        let r = local_reasons(&l);
        assert_eq!(r.len(), 1);
        assert_eq!(
            (r[0].level.as_str(), r[0].code.as_str()),
            (DEGRADED, "category_unknown")
        );
        assert!(
            r[0].summary.contains("from-the-future (group kids)"),
            "{}",
            r[0].summary
        );
    }

    // REQ: UPS-006 — an upstream with no route and a closed breaker is a warning, as on the map.
    #[test]
    fn ups_006_no_route_with_closed_breaker_degrades() {
        let mut u = up("spare", &["g"], "closed");
        u.route_problem = Some("no route to 10.9.9.9".into());
        let mut out = Vec::new();
        upstream_reasons(&[u], &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(
            (out[0].level.as_str(), out[0].code.as_str()),
            (DEGRADED, "upstream_no_route")
        );
    }

    // REQ: FLT-017 (ADR-150) — a watcher's table older than 15 minutes degrades, with the
    // reason in words; nothing else changes.
    #[test]
    fn flt_017_stale_workload_table_degrades() {
        let (ups, recent) = (Vec::new(), Vec::new());
        assert!(local_reasons(&local(&ups, &recent)).is_empty());
        let stale = Local {
            kubernetes_stale_s: Some(1_200),
            ..local(&ups, &recent)
        };
        let r = local_reasons(&stale);
        assert_eq!(r.len(), 1);
        assert_eq!(
            (r[0].level.as_str(), r[0].code.as_str()),
            (DEGRADED, "kubernetes_stale")
        );
        assert!(r[0].summary.contains("20 minutes"), "{}", r[0].summary);
        assert!(r[0].summary.contains("named by address"));
    }

    fn probe(
        target: &str,
        listener: bool,
        failures: u32,
        cert_days: Option<i64>,
    ) -> wrendns_api::model::ProbeResult {
        wrendns_api::model::ProbeResult {
            target: target.into(),
            proto: "udp".into(),
            listener,
            ok: failures == 0,
            consecutive_failures: failures,
            cert_days_left: cert_days,
            ..wrendns_api::model::ProbeResult::default()
        }
    }

    // REQ: OBS-020 (ADR-107) — a probe failing twice degrades; every listener failing is
    // `not_serving`; one blip doesn't count; certificates degrade near expiry, expired is
    // severe.
    #[test]
    fn obs_020_probes_and_certificates() {
        let ps = [
            probe("udp://127.0.0.1:53", true, 0, None),
            probe("tls://127.0.0.1:853", true, 3, Some(40)),
            probe("udp://10.50.5.112:53", false, 1, None),
        ];
        let mut l = local(&[], &[]);
        l.probes = &ps;
        assert_eq!(
            codes(&summarize(local_reasons(&l), vec![], String::new())),
            vec![("degraded", "probe_failing")]
        );
        let all = [
            probe("udp://127.0.0.1:53", true, 2, None),
            probe("tcp://127.0.0.1:53", true, 5, None),
        ];
        l.probes = &all;
        let mut r = local_reasons(&l);
        assert_eq!(
            codes(&summarize(r.clone(), vec![], String::new())),
            vec![("severe", "not_serving")]
        );
        soften_not_serving(&mut r, 2);
        assert_eq!(
            summarize(r, vec![], String::new()).level,
            "degraded",
            "others serve"
        );
        let certs = [
            probe("tls://127.0.0.1:853", true, 0, Some(5)),
            probe("https://127.0.0.1:443/dns-query", true, 0, Some(-2)),
        ];
        l.probes = &certs;
        let h = summarize(local_reasons(&l), vec![], String::new());
        assert_eq!(
            codes(&h),
            vec![("severe", "cert_expired"), ("degraded", "cert_expiring")]
        );
        // REQ: API-003 (ADR-149) — the web UI's check: an expiring certificate degrades like a
        // listener's, but an answering web UI doesn't hide every DNS listener failing.
        let mut web = probe("https://127.0.0.1:8053/livez", true, 0, Some(3));
        web.proto = crate::probes::API_PROTO.into();
        let mixed = [
            probe("udp://127.0.0.1:53", true, 2, None),
            probe("tcp://127.0.0.1:53", true, 2, None),
            web,
        ];
        l.probes = &mixed;
        let h = summarize(local_reasons(&l), vec![], String::new());
        assert_eq!(
            codes(&h),
            vec![("severe", "not_serving"), ("degraded", "cert_expiring")]
        );
        assert!(
            h.reasons
                .iter()
                .any(|r| r.code == "cert_expiring" && r.summary.contains("8053"))
        );
    }

    // REQ: API-902 (owner decision, 2026-11-27) — health is read by every role and agent: its
    // reasons never carry a DoH path.
    #[test]
    fn api_902_health_reasons_carry_no_doh_path() {
        let ps = [
            probe("https://192.168.1.2:443/secret-doh-path", true, 3, Some(5)),
            probe("https://192.168.1.2:444/secret-doh-path", true, 0, Some(-2)),
            probe("https://192.168.1.2:445/secret-doh-path", true, 0, Some(5)),
        ];
        let mut l = local(&[], &[]);
        l.probes = &ps;
        let text = format!("{:?}", local_reasons(&l));
        assert!(text.contains("192.168.1.2:443"), "{text}");
        assert!(!text.contains("secret-doh-path"), "{text}");
    }

    fn codes(h: &Health) -> Vec<(&str, &str)> {
        h.reasons
            .iter()
            .map(|r| (r.level.as_str(), r.code.as_str()))
            .collect()
    }

    // REQ: OBS-015 — nothing wrong: healthy, no reasons.
    #[test]
    fn obs_015_all_good_is_healthy() {
        let ups = [
            up("quad9", &["default"], "closed"),
            up("cf", &["default"], "closed"),
        ];
        let h = summarize(local_reasons(&local(&ups, &[])), vec![], String::new());
        assert_eq!(h.level, "healthy");
        assert_eq!(h.reasons.len(), 0);
    }

    // REQ: OBS-015 (owner, 2026-10-08) — one upstream down while the group still answers is
    // degraded; the whole group down is severe.
    #[test]
    fn obs_015_one_upstream_down_degrades_a_whole_group_is_severe() {
        let ups = [
            up("quad9", &["default"], "open"),
            up("cf", &["default"], "closed"),
        ];
        let h = summarize(local_reasons(&local(&ups, &[])), vec![], String::new());
        assert_eq!(
            (h.level.as_str(), codes(&h)),
            ("degraded", vec![("degraded", "upstream_down")])
        );

        let ups = [
            up("quad9", &["default"], "open"),
            up("cf", &["default"], "half_open"),
            up("kids-dns", &["kids"], "closed"),
        ];
        let h = summarize(local_reasons(&local(&ups, &[])), vec![], String::new());
        assert_eq!(h.level, "severe");
        assert_eq!(
            codes(&h),
            vec![("severe", "upstream_group_down")],
            "no per-upstream repeats"
        );
        assert!(
            h.reasons[0].summary.contains("quad9, cf"),
            "{}",
            h.reasons[0].summary
        );
    }

    fn minute(total: u32, rate_limited: u32, servfail: u32) -> TimeBucket {
        let mut b = TimeBucket {
            total,
            ..TimeBucket::default()
        };
        b.by_status.insert("rate_limited".into(), rate_limited);
        b.by_rcode.insert("SERVFAIL".into(), servfail);
        b
    }

    // REQ: OBS-015 (owner, 2026-10-08) — a rate-limited device degrades; SERVFAIL degrades at
    // 5% and is severe at 25%, once there were enough queries to judge.
    #[test]
    fn obs_015_rate_limits_and_servfail() {
        let h = summarize(
            local_reasons(&local(&[], &[minute(100, 3, 0)])),
            vec![],
            String::new(),
        );
        assert_eq!(codes(&h), vec![("degraded", "rate_limited")]);
        let h = summarize(
            local_reasons(&local(&[], &[minute(100, 0, 6)])),
            vec![],
            String::new(),
        );
        assert_eq!(codes(&h), vec![("degraded", "servfail_rate")]);
        let h = summarize(
            local_reasons(&local(&[], &[minute(100, 0, 30)])),
            vec![],
            String::new(),
        );
        assert_eq!(codes(&h), vec![("severe", "servfail_rate")]);
        let h = summarize(
            local_reasons(&local(&[], &[minute(20, 0, 20)])),
            vec![],
            String::new(),
        );
        assert_eq!(h.level, "healthy", "too few queries to judge");
    }

    // REQ: OBS-010 (T24.5, fork #2) — a replica that hasn't reached its primary for a minute
    // gives a degraded reason naming it (the exact boundary counts); witnesses, resolver pods
    // and replicas out of contact don't; the reason is gone once it reaches the primary again.
    #[test]
    fn obs_010_t24_5_health_names_a_replica_that_cannot_reach_its_primary() {
        use wrendns_api::model::ClusterNode;
        let node = |id: &str, silent: Option<u64>| ClusterNode {
            node_id: id.into(),
            site: id.into(),
            role: "replica".into(),
            connected: true,
            up: true,
            primary_silent_seconds: silent,
            ..ClusterNode::default()
        };
        let mut primary = node("p", None);
        primary.role = "primary".into();
        primary.this_node = true;
        let codes = |nodes: Vec<ClusterNode>| {
            let view = ClusterView {
                enabled: true,
                cluster_id: None,
                name: None,
                this_node: Some("p".into()),
                newest_config_seq: 1,
                healthy: true,
                checks: Vec::new(),
                nodes,
                events: Vec::new(),
                authority: None,
                conflicts: Vec::new(),
                failover: None,
                source: None,
                rollout: None,
                host: None,
            };
            cluster_reasons(&view)
        };
        assert!(codes(vec![primary.clone(), node("r", Some(59))]).is_empty());
        let r = codes(vec![primary.clone(), node("r", Some(60))]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].code, "primary_unreachable");
        assert_eq!(r[0].node.as_deref(), Some("r"));
        assert_eq!(r[0].link.as_deref(), Some("#/cluster"));
        assert_eq!(r[0].summary, "r hasn't reached its primary for 60 s");
        // The answering node's own replica state counts too (it is in the view).
        let mut me = node("me", Some(120));
        me.this_node = true;
        assert_eq!(codes(vec![primary.clone(), me]).len(), 1);
        // Witnesses, resolver pods and replicas out of contact: no reason.
        let mut witness = node("w", Some(600));
        witness.witness = true;
        let mut pod = node("pod", Some(600));
        pod.ephemeral = true;
        let mut away = node("away", Some(600));
        away.up = false;
        assert!(codes(vec![primary.clone(), witness, pod, away]).is_empty());
        // A replica in a maintenance window: no reason either (as the alert leaves it out).
        let mut maint = node("m", Some(600));
        maint.maintenance = Some(wrendns_api::model::NodeMaintenance {
            until: "2026-10-09T14:00:00Z".into(),
            reason: "disk swap".into(),
            by: "alice".into(),
            seconds_left: 600,
            ..wrendns_api::model::NodeMaintenance::default()
        });
        assert!(codes(vec![primary.clone(), maint]).is_empty());
        // Reconnected: the value is absent, so the reason clears.
        assert!(codes(vec![primary, node("r", None)]).is_empty());
    }

    // REQ: CLU-009 (T24.33) — an unreachable witness is a degraded reason (automatic failover
    // needs its vote); a connected one is never "behind", whatever it reports.
    #[test]
    fn clu_009_t24_33_health_counts_a_witness_only_as_a_voter() {
        use wrendns_api::model::ClusterNode;
        let node = |id: &str, connected: bool| ClusterNode {
            node_id: id.into(),
            site: id.into(),
            role: "replica".into(),
            connected,
            up: connected,
            ..ClusterNode::default()
        };
        let mut primary = node("p", true);
        primary.role = "primary".into();
        primary.this_node = true;
        let view = |nodes: Vec<ClusterNode>| ClusterView {
            enabled: true,
            cluster_id: None,
            name: None,
            this_node: Some("p".into()),
            newest_config_seq: 14,
            healthy: true,
            checks: Vec::new(),
            nodes,
            events: Vec::new(),
            authority: None,
            conflicts: Vec::new(),
            failover: None,
            source: None,
            rollout: None,
            host: None,
        };
        let mut witness = node("w", true);
        witness.witness = true;
        witness.config_lag = 13;
        witness.behind_seconds = Some(1920);
        assert!(cluster_reasons(&view(vec![primary.clone(), witness.clone()])).is_empty());
        witness.connected = false;
        witness.up = false;
        let r = cluster_reasons(&view(vec![primary, witness]));
        assert_eq!(r.len(), 1);
        assert_eq!(
            (r[0].code.as_str(), r[0].node.as_deref()),
            ("node_down", Some("w"))
        );
    }

    // REQ: OPS-010 (ADR-118) — a node in maintenance that went silent: its `node_down` and
    // its own reasons are left out, it isn't "missing", and it's listed under `maintenance`;
    // the level stays healthy. Another node's reasons still count.
    #[test]
    fn ops_010_health_leaves_out_nodes_in_maintenance() {
        use wrendns_api::model::{ClusterNode, NodeMaintenance};
        let node = |id: &str, site: &str| ClusterNode {
            node_id: id.into(),
            site: site.into(),
            ..ClusterNode::default()
        };
        let mut me = node("a1", "k8s");
        me.this_node = true;
        me.connected = true;
        let mut pi = node("b2", "pi");
        pi.last_seen_seconds_ago = 40;
        pi.maintenance = Some(NodeMaintenance {
            until: "2026-10-09T14:00:00Z".into(),
            reason: "SD card swap".into(),
            by: "alice".into(),
            seconds_left: 600,
            ..NodeMaintenance::default()
        });
        let view = ClusterView {
            enabled: true,
            cluster_id: None,
            name: None,
            this_node: Some("a1".into()),
            newest_config_seq: 1,
            healthy: true,
            checks: Vec::new(),
            nodes: vec![me, pi],
            events: Vec::new(),
            authority: None,
            conflicts: Vec::new(),
            failover: None,
            source: None,
            rollout: None,
            host: None,
        };
        let mut reasons = cluster_reasons(&view);
        assert_eq!(reasons.len(), 1, "node_down for pi");
        let mut probe = reason(DEGRADED, "probe_failing", "x".into(), "#/");
        probe.node = Some("pi".into());
        reasons.push(probe);
        let mut other = reason(DEGRADED, "disk_full", "y".into(), "#/");
        other.node = Some("k8s".into());
        let mut missing = vec!["pi".to_owned()];
        let m = exclude_maintenance(&mut reasons, &mut missing, &view);
        assert!(
            reasons.is_empty() && missing.is_empty(),
            "{reasons:?} {missing:?}"
        );
        assert_eq!(m.len(), 1);
        assert_eq!(
            (m[0].node.as_deref(), m[0].reason.as_str()),
            (Some("pi"), "SD card swap")
        );
        let mut h = summarize(reasons, missing, String::new());
        h.maintenance = m;
        assert_eq!(h.level, "healthy");
        let mut with_other = vec![other];
        exclude_maintenance(&mut with_other, &mut Vec::new(), &view);
        assert_eq!(
            summarize(with_other, vec![], String::new()).level,
            "degraded"
        );
    }

    // REQ: OBS-015 — a node not serving is severe alone, degraded when others serve.
    #[test]
    fn obs_015_not_serving_depends_on_the_others() {
        let mut l = local(&[], &[]);
        l.serving = false;
        let mut r = local_reasons(&l);
        soften_not_serving(&mut r, 1);
        assert_eq!(summarize(r, vec![], String::new()).level, "severe");
        let mut r = local_reasons(&l);
        soften_not_serving(&mut r, 3);
        assert_eq!(summarize(r, vec![], String::new()).level, "degraded");
    }

    // REQ: OBS-015, OBS-023 — failing and stale lists and a full disk degrade; severe reasons
    // sort first.
    #[test]
    fn obs_015_lists_disk_and_order() {
        let failing = ListInfo {
            name: "hagezi".into(),
            kind: "block".into(),
            format: "auto".into(),
            unsupported: 0,
            enabled: true,
            mode: "enforce".into(),
            source: "https://lists.example/hagezi.txt".into(),
            state: "failed".into(),
            error: Some("HTTP 404".into()),
            bytes: 0,
            lines: 0,
            entries: 0,
            unique: 0,
            regex_skipped: 0,
            hits: 0,
            overlap: Vec::new(),
            rules: 0,
            last_checked_unix_seconds: None,
            last_success_unix_seconds: None,
            last_changed_unix_seconds: None,
            refreshing: false,
            stale_days: None,
            owners: Vec::new(),
        };
        let stale = ListInfo {
            name: "old".into(),
            state: "ok".into(),
            error: None,
            stale_days: Some(45),
            ..failing.clone()
        };
        let lists = [failing, stale];
        let ups = [up("quad9", &["default"], "open")];
        let recent = [minute(100, 0, 40)];
        let mut l = local(&ups, &recent);
        l.lists = Some(&lists);
        l.disk_used_percent = Some(95.0);
        let h = summarize(local_reasons(&l), vec![], String::new());
        assert_eq!(h.level, "severe");
        let first_two: Vec<&str> = h.reasons[..2].iter().map(|r| r.code.as_str()).collect();
        assert_eq!(
            first_two,
            ["servfail_rate", "upstream_group_down"],
            "severe first"
        );
        assert!(
            h.reasons
                .iter()
                .any(|r| r.code == "list_failing" && r.level == "degraded")
        );
        assert!(
            h.reasons
                .iter()
                .any(|r| r.code == "list_stale"
                    && r.summary.contains("old hasn't changed in 45 days")),
            "{:?}",
            h.reasons
        );
        assert!(h.reasons.iter().any(|r| r.code == "disk_full"));
    }

    // REQ: CLU-013 — a pinned cluster degrades (cluster_pinned); canaries set with none online
    // for 10 minutes degrades (rollout_stuck); a version baking alone doesn't.
    #[test]
    fn clu_013_pinned_and_stuck_rollouts_degrade() {
        use wrendns_api::model::{ClusterPin, ClusterRollout};
        let view = |r: Option<ClusterRollout>| ClusterView {
            enabled: true,
            cluster_id: None,
            name: None,
            this_node: None,
            newest_config_seq: 1,
            healthy: true,
            checks: Vec::new(),
            nodes: Vec::new(),
            events: Vec::new(),
            authority: None,
            conflicts: Vec::new(),
            failover: None,
            source: None,
            host: None,
            rollout: r,
        };
        let code_list = |v: &ClusterView| -> Vec<String> {
            cluster_reasons(v).into_iter().map(|r| r.code).collect()
        };
        assert_eq!(code_list(&view(None)), Vec::<String>::new());
        let baking = ClusterRollout {
            stage: "canary".into(),
            version: Some("1.8".into()),
            ..ClusterRollout::default()
        };
        assert_eq!(code_list(&view(Some(baking))), Vec::<String>::new());
        let pinned = ClusterRollout {
            stage: "pinned".into(),
            pinned: Some(ClusterPin {
                to: "1.7".into(),
                by: "the guard".into(),
                reason: "SERVFAIL 30%".into(),
                ..ClusterPin::default()
            }),
            ..ClusterRollout::default()
        };
        let r = cluster_reasons(&view(Some(pinned)));
        assert_eq!(r.len(), 1);
        assert_eq!(
            (r[0].level.as_str(), r[0].code.as_str()),
            ("degraded", "cluster_pinned")
        );
        assert!(r[0].summary.contains("1.7") && r[0].summary.contains("SERVFAIL 30%"));
        let offline = |secs| ClusterRollout {
            stage: "none".into(),
            canaries_offline_seconds: Some(secs),
            ..ClusterRollout::default()
        };
        assert_eq!(code_list(&view(Some(offline(120)))), Vec::<String>::new());
        assert_eq!(code_list(&view(Some(offline(700)))), vec!["rollout_stuck"]);
    }

    /// REQ: DSC-002 (T25.3, DSC-014) — a discovery worker that is refused or keeps crashing is
    /// degraded, under the two codes, and never severe: the inventory is off the query path.
    #[test]
    fn dsc_002_discovery_reasons_are_degraded_only() {
        use wrendns_api::model::DiscoveryWorker;
        let workers = vec![
            DiscoveryWorker {
                worker: "snmp".into(),
                version_mismatch: true,
                last_error: Some("build `x` (this node is `y`)".into()),
                ..DiscoveryWorker::default()
            },
            DiscoveryWorker {
                worker: "import".into(),
                failing: true,
                restarts: 3,
                ..DiscoveryWorker::default()
            },
            DiscoveryWorker {
                worker: "snmp".into(),
                up: true,
                ..DiscoveryWorker::default()
            },
        ];
        let r = discovery_reasons(&workers, &[]);
        let codes: Vec<&str> = r.iter().map(|x| x.code.as_str()).collect();
        assert_eq!(
            codes,
            [
                "discovery_worker_version_mismatch",
                "discovery_worker_failing"
            ]
        );
        assert!(r.iter().all(|x| x.level == DEGRADED), "{r:?}");
        assert!(discovery_reasons(&[DiscoveryWorker::default()], &[]).is_empty());
    }

    /// REQ: DSC-004, DSC-014 (`dsc_014_failing_agent_is_degraded_only`) - an SNMP agent whose last three
    /// polls failed raises `discovery_agent_failing` (degraded, never severe); one that is merely in
    /// error, waiting or skipped does not.
    #[test]
    fn dsc_014_failing_agent_is_degraded_only() {
        use wrendns_api::model::DiscoveryAgent;
        let agent = |state: &str| DiscoveryAgent {
            name: "gateway".into(),
            state: state.into(),
            consecutive_failures: 3,
            last_error: Some("no reply (timeout)".into()),
            ..DiscoveryAgent::default()
        };
        let r = discovery_reasons(&[], &[agent("failing")]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].code, "discovery_agent_failing");
        assert_eq!(r[0].level, DEGRADED);
        assert!(r[0].summary.contains("gateway"), "{}", r[0].summary);
        for quiet in ["ok", "error", "waiting", "skipped"] {
            assert!(
                discovery_reasons(&[], &[agent(quiet)]).is_empty(),
                "{quiet}"
            );
        }
    }

    /// REQ: API-015, OBS-015 (T24.42) - a full member that has not applied the primary's secrets
    /// for a minute is `secret_not_held` (degraded, never severe); a witness and a resolver pod
    /// never are; a member that catches up is forgotten; a write in flight is not reported.
    #[test]
    fn api_015_t24_42_a_member_without_the_secrets_is_degraded() {
        use super::{SECRETS_LAG_SECONDS, SecretsSince, secret_reasons};
        use wrendns_api::model::{ClusterNode, ClusterSecrets};
        let node = |id: &str, role: &str, in_sync: bool| ClusterNode {
            node_id: id.into(),
            site: id.into(),
            role: role.into(),
            connected: true,
            up: true,
            secrets: Some(ClusterSecrets {
                head: Some("1.3".into()),
                applied: (!in_sync).then(|| "1.1".into()),
                in_sync,
                ..ClusterSecrets::default()
            }),
            ..ClusterNode::default()
        };
        let mut witness = node("w", "replica", false);
        witness.witness = true;
        let mut pod = node("pod", "replica", false);
        pod.ephemeral = true;
        let view = |nodes: Vec<ClusterNode>| ClusterView {
            enabled: true,
            cluster_id: None,
            name: None,
            this_node: Some("p".into()),
            newest_config_seq: 14,
            healthy: true,
            checks: Vec::new(),
            nodes,
            events: Vec::new(),
            authority: None,
            conflicts: Vec::new(),
            failover: None,
            source: None,
            rollout: None,
            host: None,
        };
        let v = view(vec![
            node("p", "primary", true),
            node("a", "replica", true),
            node("b", "replica", false),
            witness,
            pod,
        ]);
        let mut since = SecretsSince::new();
        let t0 = std::time::Instant::now();
        // Just seen: not reported yet.
        assert!(secret_reasons(&v, &mut since, t0).is_empty());
        let later = t0 + std::time::Duration::from_secs(SECRETS_LAG_SECONDS + 1);
        let r = secret_reasons(&v, &mut since, later);
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(
            (
                r[0].code.as_str(),
                r[0].level.as_str(),
                r[0].node.as_deref()
            ),
            ("secret_not_held", DEGRADED, Some("b"))
        );
        assert!(r[0].summary.contains("DNS is unaffected"));
        // It catches up: forgotten, and a later lapse starts a new window.
        let v2 = view(vec![node("p", "primary", true), node("b", "replica", true)]);
        assert!(secret_reasons(&v2, &mut since, later).is_empty());
        assert!(since.is_empty());
        // No secrets stored anywhere (the primary has no head): nothing to lack.
        let mut p = node("p", "primary", true);
        p.secrets = Some(ClusterSecrets::default());
        let v3 = view(vec![p, node("b", "replica", false)]);
        assert!(secret_reasons(&v3, &mut since, later).is_empty());
    }
}

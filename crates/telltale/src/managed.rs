//! Config made through the API and UI, merged with the config files (REQ: API-002, API-010,
//! API-011; ADR-040, ADR-042).
//!
//! Entries live in `state.db` by kind and name: devices (`client`), local names (`record`: an
//! owner name and its records), and domains sent to other servers (`forward`: a domain and its
//! servers, expanded into upstreams, an upstream group, and a route). The files stay
//! authoritative: an entry the files define is read-only through the API, and the API can't
//! create a name the files use. If the merged config doesn't validate (say a group named by an
//! API client was removed from the file), the files alone are used and the reason is logged:
//! DNS never waits on, or breaks because of, the API layer.

use std::path::Path;

use serde::{Deserialize, Serialize};
use telltale_config::{
    ClientConfig, Config, FilterList, GroupConfig, LocalRecord, Route, SafeString, Upstream,
    UpstreamGroup,
};
use telltale_store::state::State;
use tracing::{error, warn};

/// The kind names in `state.db`.
pub(crate) const CLIENT: &str = "client";
pub(crate) const RECORD: &str = "record";
pub(crate) const FORWARD: &str = "forward";
/// REQ: DNS-010 (T27.7) — authoritative zones made through the API, by apex: the body is a
/// `[[zone]]` without its file (the files' zones win).
pub(crate) const ZONE: &str = "zone";
/// Quick rules (T6.12, ADR-067), stored by ID.
pub(crate) const RULE: &str = "rule";
/// T7.5 (ADR-069): these may override or hide the files' entry of the same name.
pub(crate) const UPSTREAM: &str = "upstream";
pub(crate) const UPSTREAM_GROUP: &str = "upstream_group";
pub(crate) const LIST: &str = "list";
pub(crate) const GROUP: &str = "group";
/// REQ: OBS-010 (T9.6) — alert destinations and rules (they override the files' too).
pub(crate) const ALERT_DESTINATION: &str = "alert_destination";
pub(crate) const ALERT_RULE: &str = "alert_rule";
/// REQ: FLT-010 (T9.7) — schedules.
pub(crate) const SCHEDULE: &str = "schedule";
/// REQ: OBS-038 (ADR-161) — anomaly mutes.
pub(crate) const ANOMALY_MUTE: &str = "anomaly_mute";
/// REQ: DNS-014 (review 01 q1) — the rate limit: one entry, `default`, replacing `[ratelimit]`.
pub(crate) const RATELIMIT: &str = "ratelimit";
/// REQ: OBS-022 (T12.1) — the exclusions: one entry, `default`, replacing `[exclusions]`.
pub(crate) const EXCLUSIONS: &str = "exclusions";
/// REQ: OBS-024 (T13.1) — change simulation's settings: one entry, `default`, replacing
/// `[simulate]`.
pub(crate) const SIMULATE: &str = "simulate";
/// REQ: OBS-901 (T26.2, ADR-958) — the live map's settings: one entry, `default`, replacing `[map]`.
pub(crate) const MAP: &str = "map";
/// REQ: CLU-013 (T13.2) — staged rollouts' settings: one entry, `default`, replacing
/// `[cluster.rollout]`.
pub(crate) const ROLLOUT: &str = "rollout";
/// REQ: FLT-017 (T15.1) — `[[kubernetes.map]]` rules, by key (`namespace/kind/name`).
pub(crate) const KUBERNETES_MAP: &str = "kubernetes_map";
/// REQ: DNS-019 (T24.12, ADR-904, ADR-914) — `[special]`: one entry, `default`, whose fields
/// the files win over (see `settings_kinds`).
pub(crate) const SPECIAL: &str = "special";
/// REQ: DNS-023 (T24.13, ADR-901, ADR-914) — `[local]` without `hosts_files`.
pub(crate) const LOCAL: &str = "local";
/// REQ: DNS-023 (T24.13, ADR-914) — `[clients]`, which takes only `mdns` in M24.
pub(crate) const CLIENTS: &str = "clients";
/// REQ: DSC-001 (T25.2, ADR-907) — `[discovery]`: the network inventory's settings, one entry.
pub(crate) const DISCOVERY: &str = "discovery";
/// REQ: API-016 (T23.7, ADR-921) — `[[router]]` integrations, by name. Admin-only; a router the
/// files define is read-only through the API (ADR-040), so these never override the files.
pub(crate) const ROUTER: &str = "router";
/// REQ: API-016 (T23.10, ADR-967) — OIDC sign-in providers, by ID: a node-managed kind
/// (ADR-903 §6). Admin-only; a provider the files define is read-only through the API, and the
/// rows travel to the other members as the manifest's `node_managed` blob, not in `[auth]`.
pub(crate) const OIDC_PROVIDER: &str = "oidc_provider";
/// REQ: API-016 (T23.11, ADR-984) — event sinks, by name: a node-managed kind (ADR-903 §6),
/// admin-only; a sink the files define is read-only through the API.
pub(crate) const SINK: &str = "sink";
/// REQ: OBS-016, OBS-020, OBS-019 (T27.5, ADR-1007) — `[slo]`, `[probe]` and `[upstream_check]`:
/// shared singletons (one entry, `default`), operators write them; the files win field by field.
pub(crate) const SLO: &str = "slo";
pub(crate) const PROBE: &str = "probe";
pub(crate) const UPSTREAM_CHECK: &str = "upstream_check";
/// REQ: OBS-013, OBS-003, OBS-005 (T27.5, ADR-1007) — `[telemetry.anomaly]`, `[telemetry.qlog]` and
/// `[telemetry.metrics]`: node-managed singletons (`node-managed.json`), admin-only.
pub(crate) const ANOMALY_SETTINGS: &str = "anomaly_settings";
pub(crate) const QLOG_SETTINGS: &str = "qlog_settings";
pub(crate) const METRICS_SETTINGS: &str = "metrics_settings";
/// REQ: API-016 (T23.11, ADR-984) — the OTLP export (one row, named `default`): a node-managed
/// kind, admin-only; the files win when they set a destination.
pub(crate) const OTLP: &str = "otlp";
/// The one OTLP row's name.
pub(crate) const OTLP_NAME: &str = "default";

/// An API entry for a kind that can override the files (ADR-069): a definition, or the
/// files' entry of that name left out.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Ovr<T> {
    Set(T),
    Hidden,
}

/// The stored body of a hidden entry.
pub(crate) const HIDDEN: &str = r#"{"hidden":true}"#;

/// The config entries a kind holds, by name.
pub(crate) trait Named {
    fn name(&self) -> &str;
}
impl Named for Upstream {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for UpstreamGroup {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for FilterList {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for GroupConfig {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for telltale_config::AlertDestination {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for telltale_config::ScheduleConfig {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for telltale_config::AnomalyMuteConfig {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for telltale_config::RouterConfig {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
impl Named for telltale_config::AlertRule {
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

/// One record of a local name (a name's records are stored together).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordValue {
    #[serde(rename = "type")]
    pub(crate) rtype: String,
    pub(crate) value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ttl: Option<u32>,
    /// REQ: CLU-006 (T27.7) — this record stays on this node.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) node_only: bool,
}

/// The servers a domain is sent to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Forward {
    pub(crate) servers: Vec<String>,
    /// REQ: DNS-022 — a stub zone: the servers are the zone's own (authoritative only), asked
    /// iteratively, and the delegations they give are followed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) stub: bool,
    /// REQ: DNS-010 (T27.7) — only these client groups are sent (empty: all).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) match_group: Vec<String>,
    /// REQ: DNS-010 (T27.7) — only these query types are sent (empty: all).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) match_qtype: Vec<String>,
    /// REQ: DNS-010 (T27.7) — a DNSSEC negative trust anchor for the domain (on by default, as
    /// forwards always had it).
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub(crate) dnssec_nta: bool,
    /// REQ: CLU-006 (T27.7) — the route, its group and its servers stay on this node.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) node_only: bool,
}

/// The serde default of a flag that is on unless stored off.
fn default_true() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if passes a reference
fn is_true(v: &bool) -> bool {
    *v
}

/// Everything stored through the API.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Entries {
    pub(crate) clients: Vec<ClientConfig>,
    pub(crate) records: Vec<(String, Vec<RecordValue>)>,
    pub(crate) forwards: Vec<(String, Forward)>,
    /// REQ: DNS-010 (T27.7) — the zones made through the API, by apex.
    pub(crate) zones: Vec<(String, telltale_config::ZoneConfig)>,
    pub(crate) rules: Vec<telltale_config::RuleConfig>,
    pub(crate) upstreams: Vec<(String, Ovr<Upstream>)>,
    pub(crate) upstream_groups: Vec<(String, Ovr<UpstreamGroup>)>,
    pub(crate) lists: Vec<(String, Ovr<FilterList>)>,
    pub(crate) groups: Vec<(String, Ovr<GroupConfig>)>,
    pub(crate) alert_destinations: Vec<(String, Ovr<telltale_config::AlertDestination>)>,
    pub(crate) alert_rules: Vec<(String, Ovr<telltale_config::AlertRule>)>,
    /// REQ: API-016 (T23.7) — the routers made through the API or UI.
    pub(crate) routers: Vec<(String, Ovr<telltale_config::RouterConfig>)>,
    /// REQ: API-016 (T23.10) — the OIDC providers made through the API or UI, by ID.
    pub(crate) oidc_providers: Vec<(String, telltale_config::OidcProvider)>,
    /// REQ: API-016 (T23.11) — the event sinks made through the API or UI, by name.
    pub(crate) sinks: Vec<(String, telltale_config::SinkConfig)>,
    /// REQ: API-016 (T23.11) — the OTLP export made through the API or UI.
    pub(crate) otlp: Option<telltale_config::OtlpConfig>,
    pub(crate) schedules: Vec<(String, Ovr<telltale_config::ScheduleConfig>)>,
    /// REQ: OBS-038 — anomaly mutes.
    pub(crate) anomaly_mutes: Vec<(String, Ovr<telltale_config::AnomalyMuteConfig>)>,
    /// The `[ratelimit]` the API or UI set, replacing the files' section as a whole.
    pub(crate) ratelimit: Option<telltale_config::RateLimitConfig>,
    /// The `[exclusions]` the API or UI set, likewise.
    pub(crate) exclusions: Option<telltale_config::ExclusionsConfig>,
    /// REQ: OBS-024 — the `[simulate]` the API or UI set, likewise.
    pub(crate) simulate: Option<telltale_config::SimulateConfig>,
    /// REQ: OBS-901 — the `[map]` the API or UI set, likewise.
    pub(crate) map: Option<telltale_config::MapConfig>,
    /// REQ: CLU-013 — the `[cluster.rollout]` the API or UI set, likewise.
    pub(crate) rollout: Option<telltale_config::RolloutConfig>,
    /// REQ: FLT-017 — `[[kubernetes.map]]` rules by key; they come before the files' rules.
    pub(crate) kubernetes_map: Vec<(String, Ovr<telltale_config::KubernetesMapRule>)>,
    /// REQ: DNS-019 (T24.12) — the stored `[special]` section (every editable key), if the API
    /// or UI set one. The files' fields win over it (ADR-914).
    pub(crate) special: Option<serde_json::Value>,
    /// REQ: DNS-023 (T24.13) — the stored `[local]` fields, likewise.
    pub(crate) local: Option<serde_json::Value>,
    /// REQ: DNS-023 (T24.13) — the stored `[clients]` fields (`mdns`), likewise.
    pub(crate) clients_settings: Option<serde_json::Value>,
    /// REQ: DSC-001 (T25.2) — the stored `[discovery]` section, likewise.
    pub(crate) discovery: Option<serde_json::Value>,
    /// REQ: OBS-016, OBS-020, OBS-019 (T27.5) — the stored `[slo]`, `[probe]` and
    /// `[upstream_check]` sections, likewise.
    pub(crate) slo: Option<serde_json::Value>,
    pub(crate) probe: Option<serde_json::Value>,
    pub(crate) upstream_check: Option<serde_json::Value>,
    /// REQ: OBS-013, OBS-003, OBS-005 (T27.5) — the stored `[telemetry.*]` sections, likewise.
    pub(crate) telemetry_anomaly: Option<serde_json::Value>,
    pub(crate) telemetry_qlog: Option<serde_json::Value>,
    pub(crate) telemetry_metrics: Option<serde_json::Value>,
    /// REQ: API-902 (T27.13) — this node's guarded entries (the reserved kind `guarded`).
    pub(crate) guarded: Vec<crate::guarded::store::Stored>,
}

impl Entries {
    /// The stored OIDC providers that validate, with the secret fields a body never carries
    /// cleared (references only); the ones that don't are logged and left out (CLU-004).
    pub(crate) fn valid_oidc_providers(&self) -> Vec<telltale_config::OidcProvider> {
        let mut ok = Vec::new();
        for (id, p) in &self.oidc_providers {
            let mut p = p.clone();
            p.id = telltale_config::SafeString::new(id).unwrap_or(p.id);
            p.client_secret = None;
            p.client_secret_file = None;
            let errs = telltale_config::oidc_provider_errors(&p);
            if errs.is_empty() {
                ok.push(p);
            } else {
                warn!(provider = %id, "skipping a stored OIDC provider: {}", errs.join("; "));
            }
        }
        ok
    }
}

impl Entries {
    /// REQ: API-016 (T23.11) — the stored sinks that validate (those that don't are logged and
    /// left out alone, CLU-004), with the fields a body never carries cleared.
    pub(crate) fn valid_sinks(&self) -> Vec<telltale_config::SinkConfig> {
        let mut ok = Vec::new();
        for (name, s) in &self.sinks {
            let mut s = s.clone();
            s.name = telltale_config::SafeString::new(name).unwrap_or(s.name);
            s.token_file = None;
            s.tls_ca = None;
            let mut errs = telltale_config::sink_errors(&s);
            if let Err(why) = crate::sink_settings::stored_limits(&s) {
                errs.push(why);
            }
            if ok.len() >= crate::sink_settings::max_sinks() {
                errs.push("more sinks than a node takes".into());
            }
            if errs.is_empty() {
                ok.push(s);
            } else {
                warn!(sink = %name, "skipping a stored event sink: {}", errs.join("; "));
            }
        }
        ok
    }

    /// REQ: API-016 (T23.11) — the stored OTLP export, if it validates.
    pub(crate) fn valid_otlp(&self) -> Option<telltale_config::OtlpConfig> {
        let mut o = self.otlp.clone()?;
        o.headers.clear();
        o.traces_sample_every = 0;
        o.traces_slow_ms = 0;
        let errs = telltale_config::otlp_errors(&o);
        if errs.is_empty() {
            Some(o)
        } else {
            warn!("skipping the stored OTLP export: {}", errs.join("; "));
            None
        }
    }
}

/// Where the state database lives.
pub(crate) fn state_path(cfg: &Config) -> std::path::PathBuf {
    Path::new(cfg.node.data_dir.as_str()).join("state.db")
}

fn decode<T: for<'de> Deserialize<'de>>(state: &State, kind: &str) -> Vec<(String, T)> {
    let rows = match state.managed(kind) {
        Ok(r) => r,
        Err(e) => {
            warn!("config made in the UI ({kind}) is unavailable: {e}");
            return Vec::new();
        }
    };
    rows.into_iter()
        .filter_map(|m| match serde_json::from_str::<T>(&m.body) {
            Ok(v) => Some((m.name, v)),
            Err(e) => {
                warn!(kind, name = %m.name, "skipping a stored entry: {e}");
                None
            }
        })
        .collect()
}

/// REQ: API-016 (T23.10) — the stored OIDC providers: the row's name is the provider's ID, whatever
/// the body says (a row seeded from a replicated blob names it only by the row).
fn decode_oidc_providers(state: &State) -> Vec<(String, telltale_config::OidcProvider)> {
    decode::<serde_json::Value>(state, OIDC_PROVIDER)
        .into_iter()
        .filter_map(|(name, mut v)| {
            if let Some(o) = v.as_object_mut() {
                o.insert("id".into(), serde_json::Value::String(name.clone()));
            }
            match serde_json::from_value::<telltale_config::OidcProvider>(v) {
                Ok(p) => Some((name, p)),
                Err(e) => {
                    warn!(kind = OIDC_PROVIDER, %name, "skipping a stored entry: {e}");
                    None
                }
            }
        })
        .collect()
}

/// REQ: API-016 (T23.11) — the stored sinks: the row's name is the sink's, whatever the body says.
fn decode_sinks(state: &State) -> Vec<(String, telltale_config::SinkConfig)> {
    decode::<serde_json::Value>(state, SINK)
        .into_iter()
        .filter_map(|(name, mut v)| {
            if let Some(o) = v.as_object_mut() {
                o.insert("name".into(), serde_json::Value::String(name.clone()));
            }
            match serde_json::from_value::<telltale_config::SinkConfig>(v) {
                Ok(s) => Some((name, s)),
                Err(e) => {
                    warn!(kind = SINK, %name, "skipping a stored entry: {e}");
                    None
                }
            }
        })
        .collect()
}

/// Entries of a kind that can override the files: a definition, or `{"hidden":true}`.
fn decode_ovr<T: for<'de> Deserialize<'de>>(state: &State, kind: &str) -> Vec<(String, Ovr<T>)> {
    decode::<serde_json::Value>(state, kind)
        .into_iter()
        .filter_map(|(name, v)| {
            if v.get("hidden").and_then(serde_json::Value::as_bool) == Some(true) {
                return Some((name, Ovr::Hidden));
            }
            match serde_json::from_value::<T>(v) {
                Ok(t) => Some((name, Ovr::Set(t))),
                Err(e) => {
                    warn!(kind, %name, "skipping a stored entry: {e}");
                    None
                }
            }
        })
        .collect()
}

/// Applies `over` to `items` by name: an override replaces the files' entry, a new name is
/// added, a hidden name is removed.
pub(crate) fn apply_ovr<T: Named + Clone>(items: &mut Vec<T>, over: &[(String, Ovr<T>)]) {
    for (name, o) in over {
        items.retain(|i| i.name() != name);
        if let Ovr::Set(t) = o {
            items.push(t.clone());
        }
    }
}

/// Everything stored through the API, decoded (bad rows are skipped with a warning).
pub(crate) fn entries(state: &State) -> Entries {
    Entries {
        clients: decode::<ClientConfig>(state, CLIENT)
            .into_iter()
            .map(|(_, c)| c)
            .collect(),
        records: decode(state, RECORD),
        forwards: decode(state, FORWARD),
        zones: decode(state, ZONE),
        rules: decode::<telltale_config::RuleConfig>(state, RULE)
            .into_iter()
            .map(|(_, r)| r)
            .collect(),
        upstreams: decode_ovr(state, UPSTREAM),
        upstream_groups: decode_ovr(state, UPSTREAM_GROUP),
        lists: decode_ovr(state, LIST),
        groups: decode_ovr(state, GROUP),
        alert_destinations: decode_ovr(state, ALERT_DESTINATION),
        alert_rules: decode_ovr(state, ALERT_RULE),
        routers: decode_ovr(state, ROUTER),
        oidc_providers: decode_oidc_providers(state),
        sinks: decode_sinks(state),
        otlp: decode::<telltale_config::OtlpConfig>(state, OTLP)
            .into_iter()
            .next()
            .map(|(_, o)| o),
        schedules: decode_ovr(state, SCHEDULE),
        anomaly_mutes: decode_ovr(state, ANOMALY_MUTE),
        ratelimit: decode::<telltale_config::RateLimitConfig>(state, RATELIMIT)
            .into_iter()
            .next()
            .map(|(_, r)| r),
        exclusions: decode::<telltale_config::ExclusionsConfig>(state, EXCLUSIONS)
            .into_iter()
            .next()
            .map(|(_, x)| x),
        simulate: decode::<telltale_config::SimulateConfig>(state, SIMULATE)
            .into_iter()
            .next()
            .map(|(_, x)| x),
        map: decode::<telltale_config::MapConfig>(state, MAP)
            .into_iter()
            .next()
            .map(|(_, x)| x),
        rollout: decode::<telltale_config::RolloutConfig>(state, ROLLOUT)
            .into_iter()
            .next()
            .map(|(_, x)| x),
        kubernetes_map: decode_ovr(state, KUBERNETES_MAP),
        special: decode::<serde_json::Value>(state, SPECIAL)
            .into_iter()
            .next()
            .map(|(_, v)| v),
        local: decode::<serde_json::Value>(state, LOCAL)
            .into_iter()
            .next()
            .map(|(_, v)| v),
        clients_settings: decode::<serde_json::Value>(state, CLIENTS)
            .into_iter()
            .next()
            .map(|(_, v)| v),
        discovery: decode::<serde_json::Value>(state, DISCOVERY)
            .into_iter()
            .next()
            .map(|(_, v)| v),
        slo: decode::<serde_json::Value>(state, SLO)
            .into_iter()
            .next()
            .map(|(_, v)| v),
        probe: decode::<serde_json::Value>(state, PROBE)
            .into_iter()
            .next()
            .map(|(_, v)| v),
        upstream_check: decode::<serde_json::Value>(state, UPSTREAM_CHECK)
            .into_iter()
            .next()
            .map(|(_, v)| v),
        telemetry_anomaly: decode::<serde_json::Value>(state, ANOMALY_SETTINGS)
            .into_iter()
            .next()
            .map(|(_, v)| v),
        telemetry_qlog: decode::<serde_json::Value>(state, QLOG_SETTINGS)
            .into_iter()
            .next()
            .map(|(_, v)| v),
        telemetry_metrics: decode::<serde_json::Value>(state, METRICS_SETTINGS)
            .into_iter()
            .next()
            .map(|(_, v)| v),
        guarded: crate::guarded::store::all(state),
    }
}

/// REQ: FLT-017 — the API's `[[kubernetes.map]]` rules: each replaces (or hides) the files'
/// rule with the same key, and comes first, so a rule made for one workload wins over a
/// namespace glob in the files.
fn apply_kubernetes_map(
    cfg: &mut Config,
    over: &[(String, Ovr<telltale_config::KubernetesMapRule>)],
) {
    let mut front = Vec::new();
    for (key, o) in over {
        cfg.kubernetes.map.retain(|r| r.key() != *key);
        if let Ovr::Set(r) = o {
            front.push(r.clone());
        }
    }
    front.append(&mut cfg.kubernetes.map);
    cfg.kubernetes.map = front;
}

/// The upstream group a forwarded domain uses.
pub(crate) fn forward_group(domain: &str) -> String {
    format!("forward:{domain}")
}

/// REQ: DNS-022 — the one upstream a stub zone's servers become.
pub(crate) fn stub_upstream_name(group: &str) -> String {
    format!("{group}#stub")
}

/// REQ: DNS-022 — a stub zone's server: an IP address (port 53), written bare or as
/// `udp://` plus the address, as the forwarding form writes servers.
pub(crate) fn stub_addr(s: &str) -> Option<std::net::IpAddr> {
    s.trim()
        .strip_prefix("udp://")
        .unwrap_or(s.trim())
        .parse()
        .ok()
}

/// REQ: DNS-022 — a stub zone as an upstream: `recursive://`, starting at `servers` for
/// `domain` instead of the root.
fn stub_upstream(domain: &str, group: &str, servers: &[String]) -> Result<Upstream, String> {
    let mut addrs = Vec::new();
    for s in servers {
        addrs.push(stub_addr(s).ok_or_else(|| {
            format!("invalid server `{s}` (a stub zone's servers are IP addresses)")
        })?);
    }
    let mut u = new_upstream(safe(&stub_upstream_name(group))?, safe("recursive://")?)
        .ok_or("invalid upstream")?;
    u.recursive.stub_zone = Some(safe(domain)?);
    u.recursive.stub_servers = addrs;
    Ok(u)
}

/// A server as an upstream URL: a bare address means plain DNS (`udp://`).
pub(crate) fn server_url(s: &str) -> String {
    if s.contains("://") {
        s.to_owned()
    } else {
        format!("udp://{s}")
    }
}

fn safe(s: &str) -> Result<SafeString, String> {
    SafeString::new(s)
}

/// The one-of sections the API or UI set, each replacing the files' section as a whole.
fn apply_one_of(cfg: &mut Config, own: &Config, e: &Entries) {
    // REQ: API-902 (T27.13, ADR-956 §2) — the guarded values in force (a field the files set wins).
    crate::guarded::appliers::overlay(cfg, own, &e.guarded, None);
    if let Some(r) = &e.ratelimit {
        cfg.ratelimit = r.clone();
    }
    if let Some(x) = &e.exclusions {
        cfg.exclusions = x.clone();
    }
    if let Some(x) = &e.simulate {
        cfg.simulate = x.clone();
    }
    if let Some(x) = &e.map {
        cfg.map = x.clone();
    }
    if let Some(x) = &e.rollout {
        cfg.cluster.rollout = x.clone();
    }
}

/// REQ: API-016 (T23.10, T23.11, ADR-967, ADR-984) - the node-managed kinds: OIDC providers, event
/// sinks and the OTLP export, merged apart from their file sections (the files win, a bad entry is
/// dropped alone).
fn overlay_node_managed(cfg: &mut Config, e: &Entries) {
    crate::node_managed::overlay_providers(cfg, e.valid_oidc_providers());
    crate::node_managed::overlay_sinks(cfg, e.valid_sinks());
    crate::node_managed::overlay_otlp(cfg, e.valid_otlp());
}

/// `file` plus the entries (names the files already use are skipped), if the result validates
/// (including record values); otherwise `Err` with the reasons.
pub(crate) fn merge(file: &Config, e: &Entries) -> Result<Config, Vec<String>> {
    merge_on(file, file, e)
}

/// [`merge`] over `file`, which may be a cluster version built on this node's own files `own`
/// (a promoted primary's, ADR-051): `own` decides which stored paths are the files' and the path
/// rules (REQ: API-014, review of T23.2), so a path an older primary published as the API's is
/// judged, not taken for the files'.
#[allow(clippy::too_many_lines)] // one step per kind of entry, in the order the files win
pub(crate) fn merge_on(file: &Config, own: &Config, e: &Entries) -> Result<Config, Vec<String>> {
    let mut cfg = file.clone();
    // ADR-069 — upstreams, upstream groups, lists, and groups made through the API override
    // or hide the files' entries of the same name (before forwards add their own).
    apply_ovr(&mut cfg.upstream, &e.upstreams);
    apply_ovr(&mut cfg.upstream_group, &e.upstream_groups);
    apply_ovr(&mut cfg.list, &e.lists);
    apply_ovr(&mut cfg.group, &e.groups);
    apply_ovr(&mut cfg.alerts.destination, &e.alert_destinations);
    // REQ: OPS-014 (ADR-903 §2, decision 4) — a credential this node's files set (inline or by
    // file) wins over whatever an override stored for it (one stored before the files set it):
    // the merged entry has one source per field, the files'.
    for d in &mut cfg.alerts.destination {
        if let Some(f) = own.alerts.destination.iter().find(|f| f.name == d.name) {
            for field in
                telltale_config::secret_refs::prefer_file_credentials("alert_destination", f, d)
            {
                warn!(destination = %d.name, field, "an alert destination's credential is set by the configuration files, which win over the one stored through the API");
            }
        }
    }
    apply_ovr(&mut cfg.alerts.rule, &e.alert_rules);
    // REQ: API-016 (T23.7, ADR-040) — a router the files define is read-only here: the API's
    // entry of that name is left out (the files' applies), and a new name is added.
    for (name, o) in &e.routers {
        if let Ovr::Set(r) = o
            && !file.router.iter().any(|f| f.name.as_str() == name)
        {
            cfg.router.retain(|f| f.name.as_str() != name);
            cfg.router.push(r.clone());
        }
    }
    // REQ: API-016 (T23.10, ADR-967) — the providers made in the UI are node-managed: merged
    // apart from `[[auth.oidc.provider]]` (a node without `public_url` shows them as inactive
    // instead of failing the configuration), the files' ID wins, and a bad one is dropped alone.
    overlay_node_managed(&mut cfg, e);
    apply_ovr(&mut cfg.schedule, &e.schedules);
    apply_ovr(&mut cfg.anomaly_mute, &e.anomaly_mutes);
    apply_kubernetes_map(&mut cfg, &e.kubernetes_map);
    apply_one_of(&mut cfg, own, e);
    // REQ: API-014 (T23.2, ADR-903 §4) — a stored path the rules refuse isn't read
    // (`effective` logs why; the entries list it in `credentialIssues`).
    crate::credential_rules::confine(&mut cfg, own, e);
    for c in &e.clients {
        if !cfg.client.iter().any(|f| f.name == c.name) {
            cfg.client.push(c.clone());
        }
    }
    // A rule ID the files use wins (ADR-067).
    for r in &e.rules {
        if !cfg.rule.iter().any(|f| f.id == r.id) {
            cfg.rule.push(r.clone());
        }
    }
    let mut errs = crate::settings_kinds::apply_stored(&mut cfg, own, e);
    for (name, recs) in &e.records {
        if file
            .record
            .iter()
            .any(|r| r.name.eq_ignore_ascii_case(name))
        {
            continue;
        }
        for r in recs {
            match (safe(name), safe(&r.rtype), safe(&r.value)) {
                (Ok(n), Ok(t), Ok(v)) => cfg.record.push(LocalRecord {
                    name: n,
                    rtype: t,
                    value: v,
                    ttl: r.ttl,
                    node_only: r.node_only,
                }),
                _ => errs.push(format!("record `{name}`: invalid characters")),
            }
        }
    }
    for (domain, f) in &e.forwards {
        let taken = file.route.iter().any(|r| {
            r.match_suffix
                .iter()
                .any(|s| s.eq_ignore_ascii_case(domain))
        });
        if taken {
            continue;
        }
        let group = forward_group(domain);
        let members = forward_upstreams(&mut cfg, domain, &group, f, &mut errs);
        if f.node_only {
            // REQ: CLU-006 (T27.7) — a node-only forward's servers stay on this node with it.
            for u in cfg
                .upstream
                .iter_mut()
                .filter(|u| members.contains(&u.name))
            {
                u.node_only = true;
            }
        }
        match (safe(&group), safe(domain)) {
            (Ok(g), Ok(d)) => {
                cfg.upstream_group.push(UpstreamGroup {
                    name: g.clone(),
                    members,
                    strategy: telltale_config::Strategy::Failover,
                    parallel_fanout: 2,
                    node_only: f.node_only,
                });
                let groups = f.match_group.iter().filter_map(|s| safe(s).ok()).collect();
                let qtypes = f.match_qtype.iter().filter_map(|s| safe(s).ok()).collect();
                cfg.route.push(Route {
                    match_suffix: vec![d],
                    match_group: groups,
                    match_qtype: qtypes,
                    upstream_group: g,
                    dnssec_nta: f.dnssec_nta,
                    node_only: f.node_only,
                });
            }
            _ => errs.push(format!("forward `{domain}`: invalid name")),
        }
    }
    // REQ: DNS-010 (T27.7) — zones made through the API; a zone the files define wins, and a bad
    // one is named in the errors (the files alone then apply, CLU-004).
    for (_, z) in &e.zones {
        if file
            .zone
            .iter()
            .any(|f| f.name.as_str().eq_ignore_ascii_case(z.name.as_str()))
        {
            continue;
        }
        let mut z = z.clone();
        z.file = None;
        cfg.zone.push(z);
    }
    if let Err(v) = telltale_config::validate_config(&cfg) {
        errs.extend(v.iter().map(ToString::to_string));
    }
    let (_, report) = telltale_policy::LocalData::from_config(&cfg);
    errs.extend(report.errors);
    if errs.is_empty() { Ok(cfg) } else { Err(errs) }
}

/// Adds the upstreams a forwarded domain becomes to `cfg` and returns their names: one per
/// server, or (REQ: DNS-022) one `recursive://` upstream for a stub zone.
fn forward_upstreams(
    cfg: &mut Config,
    domain: &str,
    group: &str,
    f: &Forward,
    errs: &mut Vec<String>,
) -> Vec<SafeString> {
    let mut members = Vec::new();
    if f.stub {
        match stub_upstream(domain, group, &f.servers) {
            Ok(u) => {
                members.push(u.name.clone());
                cfg.upstream.push(u);
            }
            Err(e) => errs.push(format!("forward `{domain}`: {e}")),
        }
        return members;
    }
    for (i, s) in f.servers.iter().enumerate() {
        let name = format!("{group}#{}", i + 1);
        match (safe(&name), safe(&server_url(s))) {
            (Ok(n), Ok(url)) => match new_upstream(n.clone(), url) {
                Some(u) => {
                    members.push(n);
                    cfg.upstream.push(u);
                }
                None => errs.push(format!("forward `{domain}`: invalid server `{s}`")),
            },
            _ => errs.push(format!("forward `{domain}`: invalid server `{s}`")),
        }
    }
    members
}

/// An upstream with every optional field at its default.
fn new_upstream(name: SafeString, url: SafeString) -> Option<Upstream> {
    let mut u: Upstream = toml::from_str(
        "name = \"x\"
url = \"udp://127.0.0.1\"",
    )
    .ok()?;
    u.name = name;
    u.url = url;
    Some(u)
}

/// Tests that only add devices.
#[cfg(test)]
pub(crate) fn merge_clients(
    file: &Config,
    extra: Vec<ClientConfig>,
) -> Result<Config, Vec<String>> {
    merge(
        file,
        &Entries {
            clients: extra,
            ..Entries::default()
        },
    )
}

/// The effective config: `file` plus what the API stored. Opens `state.db` briefly; any
/// problem falls back to `file`.
pub(crate) fn effective(file: &Config) -> Config {
    effective_on(file, file)
}

/// [`effective`] over `file`, a cluster version built on this node's own files `own` (see
/// [`merge_on`]).
pub(crate) fn effective_on(file: &Config, own: &Config) -> Config {
    let path = state_path(file);
    if !path.exists() {
        return file.clone();
    }
    let state = match State::open(&path) {
        Ok(s) => s,
        Err(e) => {
            warn!("config made in the UI is unavailable ({e}); using the config files only");
            return file.clone();
        }
    };
    let e = entries(&state);
    for i in crate::credential_rules::issues(own, &e) {
        warn!(kind = i.kind, name = %i.name, field = i.field, "a path set through the UI or API: {}", i.reason);
    }
    match merge_on(file, own, &e) {
        Ok(c) => c,
        Err(errs) => {
            for e in &errs {
                error!("config made in the UI/API: {e}");
            }
            error!(
                "ignoring config made in the UI until this is fixed; using the config files only"
            );
            file.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_config::SafeString;

    fn client(name: &str, ip: &str, groups: &[&str]) -> ClientConfig {
        ClientConfig {
            name: SafeString::new(name).unwrap(),
            match_keys: vec![SafeString::new(ip).unwrap()],
            groups: groups
                .iter()
                .map(|g| SafeString::new(*g).unwrap())
                .collect(),
            kind: None,
        }
    }

    #[test]
    fn api_010_files_win_and_bad_entries_fall_back() {
        let mut file = Config::default();
        file.client
            .push(client("nas", "192.168.1.10", &["default"]));
        let merged = merge_clients(
            &file,
            vec![
                client("tv", "192.168.1.20", &["default"]),
                client("nas", "192.168.1.99", &["default"]), // the file's name: ignored
            ],
        )
        .unwrap();
        let names: Vec<&str> = merged.client.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["nas", "tv"]);
        assert_eq!(merged.client[0].match_keys[0].as_str(), "192.168.1.10");
        // A group that doesn't exist: the merge is refused with the reason.
        let err =
            merge_clients(&file, vec![client("phone", "192.168.1.30", &["kids"])]).unwrap_err();
        assert!(err.iter().any(|e| e.contains("kids")), "{err:?}");
    }

    // REQ: FLT-017 — map rules made through the API come before the files' (first match
    // wins), replace a file rule with the same key, or hide it.
    #[test]
    fn flt_017_api_map_rules_come_first() {
        let file: Config = toml::from_str(
            r#"
            [[group]]
            name = "iot"
            [[group]]
            name = "media"
            [[kubernetes.map]]
            namespace = "media*"
            group = "iot"
            [[kubernetes.map]]
            namespace = "tools"
            group = "iot"
            "#,
        )
        .unwrap();
        let rule =
            |ns: &str, kind: &str, name: &str, group: &str| telltale_config::KubernetesMapRule {
                namespace: SafeString::new(ns).unwrap(),
                kind: SafeString::new(kind).unwrap(),
                name: SafeString::new(name).unwrap(),
                group: SafeString::new(group).unwrap(),
            };
        let e = Entries {
            kubernetes_map: vec![
                (
                    "media/deploy/jellyfin".into(),
                    Ovr::Set(rule("media", "deploy", "jellyfin", "media")),
                ),
                ("tools/*/*".into(), Ovr::Hidden),
            ],
            ..Entries::default()
        };
        let c = merge(&file, &e).unwrap();
        let keys: Vec<String> = c
            .kubernetes
            .map
            .iter()
            .map(telltale_config::KubernetesMapRule::key)
            .collect();
        assert_eq!(keys, ["media/deploy/jellyfin", "media*/*/*"]);
        // A rule naming a group that doesn't exist is refused with the reason.
        let bad = Entries {
            kubernetes_map: vec![("x/*/*".into(), Ovr::Set(rule("x", "", "", "nope")))],
            ..Entries::default()
        };
        assert!(
            merge(&file, &bad)
                .unwrap_err()
                .iter()
                .any(|e| e.contains("nope"))
        );
    }

    #[test]
    fn api_010_effective_reads_state_db() {
        let dir = tempfile::tempdir().unwrap();
        let mut file = Config::default();
        file.node.data_dir = SafeString::new(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(effective(&file), file, "no state.db yet");
        let state = State::open(&state_path(&file)).unwrap();
        let body = serde_json::to_string(&client("tv", "192.168.1.20", &["default"])).unwrap();
        state
            .put_managed(CLIENT, "tv", &body, None, None, 1, "admin")
            .unwrap();
        state
            .put_managed(CLIENT, "junk", "not json", None, None, 2, "admin")
            .unwrap();
        let eff = effective(&file);
        assert_eq!(eff.client.len(), 1);
        assert_eq!(eff.client[0].name.as_str(), "tv");
    }

    fn rv(t: &str, v: &str) -> RecordValue {
        RecordValue {
            rtype: t.into(),
            value: v.into(),
            ttl: None,
            node_only: false,
        }
    }

    fn base() -> Config {
        telltale_config::Loader::new()
            .toml_str(
                "t",
                "[[upstream]]\nname = \"up\"\nurl = \"udp://9.9.9.9\"\n[[upstream_group]]\nname = \"default\"\nmembers = [\"up\"]\n[[record]]\nname = \"router.home.arpa\"\ntype = \"A\"\nvalue = \"192.168.1.1\"\n",
            )
            .load()
            .unwrap()
            .config
    }

    #[test]
    fn api_011_records_and_forwards_merge() {
        let e = Entries {
            records: vec![
                (
                    "nas.home.arpa".into(),
                    vec![rv("A", "192.168.1.10"), rv("AAAA", "fd00::10")],
                ),
                ("router.home.arpa".into(), vec![rv("A", "10.9.9.9")]), // the file's: ignored
            ],
            forwards: vec![(
                "corp.example".into(),
                Forward {
                    servers: vec!["10.0.0.53".into(), "tls://10.0.0.54".into()],
                    stub: false,
                    match_group: Vec::new(),
                    match_qtype: Vec::new(),
                    dnssec_nta: true,
                    node_only: false,
                },
            )],
            ..Entries::default()
        };
        let cfg = merge(&base(), &e).unwrap();
        let names: Vec<(&str, &str)> = cfg
            .record
            .iter()
            .map(|r| (r.name.as_str(), r.value.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("router.home.arpa", "192.168.1.1"),
                ("nas.home.arpa", "192.168.1.10"),
                ("nas.home.arpa", "fd00::10")
            ]
        );
        let route = cfg.route.last().unwrap();
        assert_eq!(route.match_suffix[0].as_str(), "corp.example");
        assert_eq!(route.upstream_group.as_str(), "forward:corp.example");
        let urls: Vec<&str> = cfg
            .upstream
            .iter()
            .skip(1)
            .map(|u| u.url.as_str())
            .collect();
        assert_eq!(urls, ["udp://10.0.0.53", "tls://10.0.0.54"]);
    }

    #[test]
    fn api_011_bad_values_are_refused_with_reasons() {
        let bad_record = Entries {
            records: vec![("nas.home.arpa".into(), vec![rv("A", "not-an-address")])],
            ..Entries::default()
        };
        let errs = merge(&base(), &bad_record).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("not-an-address")),
            "{errs:?}"
        );
        let bad_server = Entries {
            forwards: vec![(
                "corp.example".into(),
                Forward {
                    servers: vec!["ftp://x".into()],
                    stub: false,
                    match_group: Vec::new(),
                    match_qtype: Vec::new(),
                    dnssec_nta: true,
                    node_only: false,
                },
            )],
            ..Entries::default()
        };
        assert!(merge(&base(), &bad_server).is_err());
    }

    /// REQ: DNS-022 — a stub forward becomes one `recursive://` upstream that starts at the
    /// zone's servers; a server that isn't an address is refused.
    #[test]
    fn dns_022_stub_forward_merges() {
        let e = Entries {
            forwards: vec![(
                "corp.example".into(),
                Forward {
                    servers: vec!["10.0.0.53".into(), "udp://10.0.0.54".into()],
                    stub: true,
                    match_group: Vec::new(),
                    match_qtype: Vec::new(),
                    dnssec_nta: true,
                    node_only: false,
                },
            )],
            ..Entries::default()
        };
        let cfg = merge(&base(), &e).unwrap();
        let u = cfg.upstream.last().unwrap();
        assert_eq!(u.name.as_str(), "forward:corp.example#stub");
        assert_eq!(u.url.as_str(), "recursive://");
        assert_eq!(u.recursive.stub_zone.as_deref(), Some("corp.example"));
        assert_eq!(
            u.recursive.stub_servers,
            [
                "10.0.0.53".parse::<std::net::IpAddr>().unwrap(),
                "10.0.0.54".parse().unwrap()
            ]
        );
        let g = cfg.upstream_group.last().unwrap();
        assert_eq!(g.members, std::slice::from_ref(&u.name));
        assert_eq!(cfg.route.last().unwrap().upstream_group, g.name);
        let bad = Entries {
            forwards: vec![(
                "corp.example".into(),
                Forward {
                    servers: vec!["tls://10.0.0.53".into()],
                    stub: true,
                    match_group: Vec::new(),
                    match_qtype: Vec::new(),
                    dnssec_nta: true,
                    node_only: false,
                },
            )],
            ..Entries::default()
        };
        let errs = merge(&base(), &bad).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("IP addresses")), "{errs:?}");
    }

    /// REQ: API-002 (T7.5, ADR-069) — API upstreams, groups, and lists add, override, or hide
    /// the files' entries by name, and the merged configuration must still be valid.
    #[test]
    fn api_002_overrides_add_replace_and_hide_file_entries() {
        let file: Config = toml::from_str(
            r#"
            [[upstream]]
            name = "quad9"
            url = "udp://9.9.9.9"
            [[upstream]]
            name = "cloudflare"
            url = "udp://1.1.1.1"
            [[upstream_group]]
            name = "default"
            members = ["quad9"]
            [[list]]
            name = "ads"
            rules = ["||ads.example^"]
            "#,
        )
        .unwrap();
        let up = |name: &str, url: &str| {
            new_upstream(
                SafeString::new(name).unwrap(),
                SafeString::new(url).unwrap(),
            )
            .unwrap()
        };
        let mut group: UpstreamGroup = file.upstream_group[0].clone();
        group.members = vec![SafeString::from("cloudflare"), SafeString::from("mullvad")];
        let e = Entries {
            upstreams: vec![
                ("quad9".into(), Ovr::Set(up("quad9", "tls://9.9.9.9"))),
                (
                    "mullvad".into(),
                    Ovr::Set(up("mullvad", "udp://194.242.2.2")),
                ),
            ],
            upstream_groups: vec![("default".into(), Ovr::Set(group))],
            lists: vec![("ads".into(), Ovr::Hidden)],
            ..Entries::default()
        };
        let c = merge(&file, &e).unwrap();
        let names: Vec<&str> = c.upstream.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, ["cloudflare", "quad9", "mullvad"]);
        assert_eq!(
            c.upstream
                .iter()
                .find(|u| u.name.as_str() == "quad9")
                .unwrap()
                .url
                .as_str(),
            "tls://9.9.9.9"
        );
        assert_eq!(c.upstream_group[0].members.len(), 2);
        assert!(c.list.is_empty(), "the files' list is hidden");
        // Hiding an upstream the default group still uses is refused (the merge doesn't validate).
        let broken = Entries {
            upstreams: vec![("quad9".into(), Ovr::Hidden)],
            ..Entries::default()
        };
        assert!(merge(&file, &broken).is_err());
    }
}

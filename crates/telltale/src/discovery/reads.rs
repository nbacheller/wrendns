//! REQ: DSC-009 (T25.10, ADR-912) — the extra read-only reads the inventory makes from the routers
//! it already knows: UniFi's `client_fields` (more fields of the clients the poll reads),
//! `stat/alluser` (history), `stat/device` (infrastructure, switch-port MAC tables, LLDP), and
//! Home Assistant's registry devices that have a MAC and no entity.
//!
//! Where they run. The router poll (`routers.rs`) only stores the session it used and a copy of
//! the raw answers it already holds ([`crate::routers::Shared`]). Every extra request, and every
//! parse, runs here, on the `telltale-inventory` thread's own current-thread runtime, never on the
//! main runtime that serves queries. Results go into the inventory only (ADR-910): never into
//! the lease view, the DNS names or policy.
//!
//! Each read is optional and capped: 4 MiB and 8,192 rows (Home Assistant: 1 MiB). A read that the
//! console refuses or that fails is reported once per change, never on every poll.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde_json::Value;
use telltale_api::model::DiscoveryRead;
use telltale_config::{DiscoveryConfig, RouterConfig};
use tokio::sync::mpsc;

use super::inventory::{Inventory, NameKind, Observation, Source};
use super::sources::{ha_observations, parse_mac};
use crate::routers::{Shared, SharedHa, SharedUnifi, call_capped, first_str, http_client, mac_key};

/// Most bytes a UniFi read may answer with (ADR-912).
pub(crate) const MAX_ANSWER: u64 = 4 << 20;
/// Most bytes Home Assistant's registry template may answer with (ADR-912).
pub(crate) const HA_MAX_ANSWER: u64 = 1 << 20;
/// Most rows one read uses (ADR-912).
pub(crate) const MAX_ROWS: usize = 8_192;
/// A port whose MAC table holds more MACs than this is a trunk, not a place (ADR-912).
pub(crate) const MAX_PORT_MACS: usize = 8;
/// The least time between two extra reads of one router, whatever its poll interval.
pub(crate) const MIN_GAP_SECS: u64 = 120;
/// Home Assistant's claims age out after this many seconds without a new poll, at the least.
pub(crate) const HA_MIN_AGE_SECS: u64 = 1_800;

/// The names of the reads, as the status and the log give them.
pub(crate) const READ_CLIENT_FIELDS: &str = "client_fields";
pub(crate) const READ_ALL_USERS: &str = "all_users";
pub(crate) const READ_DEVICES: &str = "devices";
pub(crate) const READ_HA_ALL: &str = "home_assistant_all_devices";

/// REQ: DSC-009 (ADR-912) — a fixed, read-only template: the registry devices that have a MAC
/// connection and no entity, found through the areas and the labels they sit in (Home Assistant's
/// templates cannot list the registry itself). Rendered by Home Assistant; it changes nothing. A
/// device with entities is the other template's (`routers::HA_TEMPLATE`).
pub(crate) const HA_ENTITYLESS_TEMPLATE: &str = r"{%- set ns = namespace(devices=[], seen=[]) -%}
{%- set groups = namespace(ids=[]) -%}
{%- for a in areas() -%}{%- set groups.ids = groups.ids + area_devices(a) -%}{%- endfor -%}
{%- for l in labels() -%}{%- set groups.ids = groups.ids + label_devices(l) -%}{%- endfor -%}
{%- for d in groups.ids -%}
{%- if d not in ns.seen and (device_entities(d) | length) == 0 -%}
{%- set ns.seen = ns.seen + [d] -%}
{%- set m = namespace(macs=[]) -%}
{%- for c in device_attr(d, 'connections') or [] -%}
{%- if c[0] == 'mac' -%}{%- set m.macs = m.macs + [c[1] | string] -%}{%- endif -%}
{%- endfor -%}
{%- if m.macs -%}
{%- set ns.devices = ns.devices + [{'name_by_user': device_attr(d, 'name_by_user') or '', 'name': device_attr(d, 'name') or '', 'macs': m.macs, 'area': area_name(d) or ''}] -%}
{%- endif -%}
{%- endif -%}
{%- endfor -%}
{{ {'devices': ns.devices} | tojson }}";

/// What the thread reads, from `[discovery]`.
// The four flags are the four settings, not a state machine.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReadsConfig {
    pub(crate) client_fields: bool,
    pub(crate) all_users: bool,
    pub(crate) devices: bool,
    pub(crate) within_hours: u32,
    pub(crate) ha_all_devices: bool,
}

impl ReadsConfig {
    /// The reads `[discovery]` asks for.
    pub(crate) fn of(d: &DiscoveryConfig) -> Self {
        Self {
            client_fields: d.unifi_reads.client_fields,
            all_users: d.unifi_reads.all_users,
            devices: d.unifi_reads.devices,
            within_hours: d.unifi_all_users_within_hours,
            ha_all_devices: d.home_assistant_all_devices,
        }
    }

    /// Whether any UniFi read beyond the poll is on.
    pub(crate) fn any_unifi(self) -> bool {
        self.client_fields || self.all_users || self.devices
    }
}

/// What the thread is given to run the reads.
#[derive(Clone)]
pub(crate) struct ReadsInput {
    /// The sessions and raw answers the router poll shares.
    pub(crate) share: Arc<ArcSwap<Shared>>,
    pub(crate) cfg: ReadsConfig,
    /// Where each read's last result is published, for the API and the UI.
    pub(crate) status: Arc<ArcSwap<Vec<DiscoveryRead>>>,
    /// The resolver the reads connect through. `None`: the system's. Tests set their own.
    pub(crate) resolver: Option<Arc<dyn telltale_filter::fetch::Resolve>>,
}

// -- parsing (pure) --------------------------------------------------------------------------

/// A JSON number, or a string holding one.
// The float arm is guarded (finite and not negative), and a whole-number float is all a console sends.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn num(v: &Value, key: &str) -> Option<u64> {
    let x = v.get(key)?;
    x.as_u64()
        .or_else(|| x.as_str().and_then(|s| s.trim().parse().ok()))
        // Some consoles send whole numbers as floats.
        .or_else(|| {
            x.as_f64()
                .filter(|f| *f >= 0.0 && f.is_finite())
                .map(|f| f as u64)
        })
}

/// The row objects of a UniFi answer: `data`, or a bare array.
fn rows(v: &Value) -> &[Value] {
    v.get("data")
        .and_then(Value::as_array)
        .or_else(|| v.as_array())
        .map_or(&[], Vec::as_slice)
}

fn mac_of(row: &Value, key: &str) -> Option<[u8; 6]> {
    parse_mac(row.get(key)?.as_str()?).filter(|m| *m != [0; 6])
}

fn v4_of(row: &Value, keys: &[&str]) -> Option<Ipv4Addr> {
    keys.iter()
        .filter_map(|k| row.get(*k).and_then(Value::as_str))
        .find_map(|s| s.trim().parse::<Ipv4Addr>().ok())
        .filter(|a| !a.is_unspecified())
}

fn mac_text(m: [u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// What one read produced.
#[derive(Debug, Default)]
pub(crate) struct Parsed {
    pub(crate) observations: Vec<Observation>,
    /// Rows used.
    pub(crate) rows: usize,
    /// More rows were offered than the cap.
    pub(crate) truncated: bool,
    /// UniFi's own devices by MAC, for the names of access points and switches.
    pub(crate) device_names: HashMap<String, String>,
}

/// REQ: DSC-009 (`client_fields`) — more of what `stat/sta` says about each connected client: wired
/// or wireless, the switch port or the access point, the VLAN and the network name, and when the
/// router first saw it (`rest/user` knows it too). No address: the router poll already supplies
/// those, and this only adds fields to the entries it made. `device_names` maps a switch's or an
/// access point's MAC to its name (from the `devices` read); without it the MAC stands.
pub(crate) fn client_fields(
    sta: &Value,
    users: Option<&Value>,
    device_names: &HashMap<String, String>,
    now: u64,
) -> Parsed {
    let first_seen: HashMap<[u8; 6], u64> = users
        .map(|u| {
            rows(u)
                .iter()
                .take(MAX_ROWS)
                .filter_map(|r| Some((mac_of(r, "mac")?, num(r, "first_seen").filter(|t| *t > 0)?)))
                .collect()
        })
        .unwrap_or_default();
    let named = |mac_str: &str| -> String {
        device_names
            .get(&mac_key(mac_str))
            .cloned()
            .unwrap_or_else(|| mac_key(mac_str))
    };
    let all = rows(sta);
    let mut out = Parsed {
        truncated: all.len() > MAX_ROWS,
        ..Parsed::default()
    };
    for r in all.iter().take(MAX_ROWS) {
        let Some(mac) = mac_of(r, "mac") else {
            continue;
        };
        let mut o = Observation::new(Source::Router, now);
        o.mac = Some(mac);
        let wired = r.get("is_wired").and_then(Value::as_bool);
        if wired == Some(true) {
            let sw = r.get("sw_mac").and_then(Value::as_str);
            if let (Some(sw), Some(port)) = (sw, num(r, "sw_port").filter(|p| *p > 0)) {
                o.port = Some(format!("{} port {port}", named(sw)));
            }
        } else if let Some(ap) = r.get("ap_mac").and_then(Value::as_str) {
            o.ap = Some(named(ap));
        }
        o.vlan = num(r, "vlan")
            .filter(|v| *v > 0)
            .and_then(|v| u16::try_from(v).ok());
        o.network = first_str(r, &["network"]);
        o.first_seen = num(r, "first_seen")
            .filter(|t| *t > 0)
            .or_else(|| first_seen.get(&mac).copied());
        out.observations.push(o);
        out.rows = out.rows.saturating_add(1);
    }
    out
}

/// REQ: DSC-009 (`all_users`) — clients UniFi has seen within the window, as history: class 5, the
/// address `last_ip`, the name UniFi has, and `last_seen` as the time. It is never a current
/// address, so it neither answers for a device now nor takes an address from one.
pub(crate) fn all_users(v: &Value, router: &str, now: u64, within_hours: u32) -> Parsed {
    let window = u64::from(within_hours).saturating_mul(3_600);
    let oldest = now.saturating_sub(window);
    let all = rows(v);
    let mut out = Parsed {
        truncated: all.len() > MAX_ROWS,
        ..Parsed::default()
    };
    for r in all.iter().take(MAX_ROWS) {
        let Some(mac) = mac_of(r, "mac") else {
            continue;
        };
        // No date: treated as the oldest the window allows, so the row ages out on its own.
        let seen = num(r, "last_seen").unwrap_or(oldest).min(now);
        if seen < oldest {
            continue;
        }
        let mut o = Observation::new(Source::History, seen);
        o.mac = Some(mac);
        o.ip = v4_of(r, &["last_ip", "ip"]).map(IpAddr::V4);
        o.name = first_str(r, &["name", "hostname"]).map(|n| (NameKind::History, n));
        o.name_origin = Some(router.to_owned());
        o.first_seen = num(r, "first_seen").filter(|t| *t > 0);
        out.observations.push(o);
        out.rows = out.rows.saturating_add(1);
    }
    out
}

/// One place a MAC was learned on: the port's table size says how close to the edge it is.
struct Place {
    port: String,
    vlan: Option<u16>,
    port_macs: usize,
    seen: u64,
}

/// REQ: DSC-009 (`devices`) — `stat/device`: UniFi's own devices as infrastructure (class 1, with
/// their LLDP neighbours), and where each client plugs in, from the switch ports' MAC tables.
/// A port that is an uplink, or whose table holds more than [`MAX_PORT_MACS`] MACs, gives no
/// location; static entries are not evidence; a MAC learned on two ports takes the one with the
/// smaller table.
pub(crate) fn devices(v: &Value, router: &str, now: u64) -> Parsed {
    let all = rows(v);
    let mut out = Parsed {
        truncated: all.len() > MAX_ROWS,
        ..Parsed::default()
    };
    let all: Vec<&Value> = all.iter().take(MAX_ROWS).collect();
    // The names first: a switch's and an access point's name is how a place is spelled.
    for d in &all {
        if let Some(mac) = d.get("mac").and_then(Value::as_str) {
            let name = first_str(d, &["name", "hostname", "model"]).unwrap_or_else(|| mac_key(mac));
            out.device_names.insert(mac_key(mac), name);
        }
    }
    let mut places: HashMap<[u8; 6], Place> = HashMap::new();
    for d in &all {
        out.rows = out.rows.saturating_add(1);
        let Some(dev_mac) = mac_of(d, "mac") else {
            continue;
        };
        let dev_name = out
            .device_names
            .get(&mac_text(dev_mac))
            .cloned()
            .unwrap_or_else(|| mac_text(dev_mac));
        // The device itself: infrastructure at its address.
        let mut o = Observation::new(Source::Router, now);
        o.mac = Some(dev_mac);
        o.ip = v4_of(d, &["ip"]).map(IpAddr::V4);
        o.name = Some((NameKind::RouterAlias, dev_name.clone()));
        o.name_origin = Some(router.to_owned());
        o.router_lldp = Some(lldp_list(d));
        out.observations.push(o);
        let uplink_port = d
            .get("uplink")
            .and_then(|u| num(u, "port_idx"))
            .filter(|p| *p > 0);
        let Some(ports) = d.get("port_table").and_then(Value::as_array) else {
            continue;
        };
        for p in ports {
            let Some(idx) = num(p, "port_idx").filter(|i| *i > 0) else {
                continue;
            };
            let is_uplink = p.get("is_uplink").and_then(Value::as_bool) == Some(true)
                || uplink_port == Some(idx);
            let table = p
                .get("mac_table")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice);
            if is_uplink || table.len() > MAX_PORT_MACS {
                continue;
            }
            for row in table {
                out.rows = out.rows.saturating_add(1);
                if out.rows > MAX_ROWS {
                    out.truncated = true;
                    break;
                }
                if row.get("static").and_then(Value::as_bool) == Some(true) {
                    continue;
                }
                let Some(mac) = mac_of(row, "mac") else {
                    continue;
                };
                let seen = now.saturating_sub(num(row, "age").unwrap_or(0));
                let place = Place {
                    port: format!("{dev_name} port {idx}"),
                    vlan: num(row, "vlan")
                        .filter(|v| *v > 0)
                        .and_then(|v| u16::try_from(v).ok()),
                    port_macs: table.len(),
                    seen,
                };
                match places.get(&mac) {
                    Some(old) if old.port_macs <= place.port_macs => {}
                    _ => {
                        places.insert(mac, place);
                    }
                }
            }
        }
    }
    // A stable order, so the same answer gives the same observations.
    let mut ordered: Vec<([u8; 6], Place)> = places.into_iter().collect();
    ordered.sort_by_key(|(m, _)| *m);
    for (mac, place) in ordered {
        let mut o = Observation::new(Source::Router, place.seen);
        o.mac = Some(mac);
        o.port = Some(place.port);
        o.vlan = place.vlan;
        out.observations.push(o);
    }
    out
}

/// A device's LLDP neighbours as short labels: who it is, and the remote port.
fn lldp_list(d: &Value) -> Vec<String> {
    let Some(table) = d.get("lldp_table").and_then(Value::as_array) else {
        return Vec::new();
    };
    table
        .iter()
        .filter_map(|n| {
            let remote = first_str(n, &["chassis_name", "system_name", "chassis_descr"])
                .or_else(|| first_str(n, &["chassis_id"]))?;
            let remote_port = first_str(n, &["port_id", "port_descr"]);
            let local = num(n, "local_port_idx").filter(|p| *p > 0);
            let mut label = remote;
            if let Some(rp) = remote_port {
                label = format!("{label} {rp}");
            }
            if let Some(lp) = local {
                label = format!("{label} on port {lp}");
            }
            Some(label)
        })
        .collect()
}

/// REQ: DSC-009 (Home Assistant) — the registry devices that have no entity, as observations at
/// `now`: names only (a name a person gave is `HaUser`), no address.
pub(crate) fn ha_entityless(v: &Value, now: u64) -> Parsed {
    let (devices, _) = crate::routers::ha_devices(v);
    let capped: Vec<_> = devices.into_iter().take(MAX_ROWS).collect();
    let observations = ha_observations(&capped, &HashMap::new(), now);
    Parsed {
        rows: observations.len(),
        observations,
        ..Parsed::default()
    }
}

// -- running ---------------------------------------------------------------------------------

/// How one read ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ended {
    Ok {
        rows: usize,
        truncated: bool,
    },
    /// The console answered 401 or 403: the key or the user can't read this.
    Refused(String),
    /// Anything else: unreachable, timed out, too big, not JSON.
    Failed(String),
}

/// One read's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadResult {
    pub(crate) read: &'static str,
    pub(crate) ended: Ended,
}

/// What a finished set of reads for one router hands back to the thread.
struct Outcome {
    router: String,
    /// The poll time the reads were made for.
    at: u64,
    observations: Vec<Observation>,
    results: Vec<ReadResult>,
}

/// REQ: DSC-009 — a refused or failed read is reported once per change. [`Reported::changed`] says
/// whether `ended` differs from what was last reported for this (router, read).
#[derive(Debug, Default)]
pub(crate) struct Reported(HashMap<(String, &'static str), Ended>);

impl Reported {
    /// Records `ended` and returns true when it differs from the last one, so the caller logs it
    /// then, and only then. A first success is a change too (it is logged at info level).
    pub(crate) fn changed(&mut self, router: &str, read: &'static str, ended: &Ended) -> bool {
        // Row counts move on every poll: a success is compared as a success.
        let key = (router.to_owned(), read);
        let same = match (self.0.get(&key), ended) {
            (Some(Ended::Ok { .. }), Ended::Ok { .. }) => true,
            (Some(old), new) => old == new,
            (None, _) => false,
        };
        self.0.insert(key, ended.clone());
        !same
    }

    /// Forgets a router that is no longer read.
    pub(crate) fn forget(&mut self, keep: &HashSet<String>) {
        self.0.retain(|(r, _), _| keep.contains(r));
    }
}

#[derive(Debug, Default)]
struct RouterState {
    /// The poll time the last started reads were for.
    consumed_at: u64,
    last_start: u64,
    in_flight: bool,
}

/// The reads' runner on the inventory thread.
pub(crate) struct Reader {
    input: ReadsInput,
    resolver: Arc<dyn telltale_filter::fetch::Resolve>,
    tx: mpsc::UnboundedSender<Outcome>,
    rx: mpsc::UnboundedReceiver<Outcome>,
    state: HashMap<String, RouterState>,
    /// Home Assistant's polls already merged into the inventory (router → poll time).
    ha_applied: HashMap<String, u64>,
    reported: Reported,
    statuses: BTreeMap<(String, &'static str), DiscoveryRead>,
}

impl Reader {
    pub(crate) fn new(input: ReadsInput) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            resolver: input
                .resolver
                .clone()
                .unwrap_or_else(|| Arc::new(telltale_filter::fetch::SystemResolver)),
            input,
            tx,
            rx,
            state: HashMap::new(),
            ha_applied: HashMap::new(),
            reported: Reported::default(),
            statuses: BTreeMap::new(),
        }
    }

    /// One step of the thread's loop: merges what finished reads brought, merges Home Assistant's
    /// polls, and starts the reads that are due (each on its own task of this thread's runtime, so
    /// a slow console never holds the loop). Returns whether the inventory took anything in.
    pub(crate) fn step(&mut self, inv: &mut Inventory, now: u64) -> bool {
        let mut changed = false;
        let mut merged = false;
        while let Ok(out) = self.rx.try_recv() {
            merged |= !out.observations.is_empty();
            inv.apply(&out.observations, now);
            if let Some(s) = self.state.get_mut(&out.router) {
                s.in_flight = false;
                s.consumed_at = s.consumed_at.max(out.at);
            }
            for r in &out.results {
                self.record(&out.router, r, now);
            }
            changed = true;
        }
        let shared = self.input.share.load_full();
        let cfg = self.input.cfg;
        let mut live: HashSet<String> = HashSet::new();
        for su in &shared.unifi {
            live.insert(su.name.clone());
            if cfg.any_unifi() {
                self.start_unifi(su, now);
            }
        }
        for h in &shared.ha {
            live.insert(h.name.clone());
            live.insert(format!("ha:{}", h.name));
            merged |= self.merge_ha(h, inv, now);
            if cfg.ha_all_devices {
                self.start_ha(h, now);
            }
        }
        // Gone routers: their state and results go with them.
        let before = self.statuses.len();
        self.state.retain(|n, _| live.contains(n));
        self.ha_applied.retain(|n, _| live.contains(n));
        self.statuses.retain(|(n, _), _| live.contains(n));
        self.reported.forget(&live);
        changed |= self.statuses.len() != before;
        if changed {
            self.publish();
        }
        merged
    }

    /// Ages out what no read keeps fresh: Home Assistant's claims (a few polls), and UniFi's
    /// history (its window; at once when `all_users` is off, as nothing refreshes it then).
    pub(crate) fn age(&self, inv: &mut Inventory, now: u64) {
        let cfg = self.input.cfg;
        let shared = self.input.share.load();
        let ha_max_age = shared
            .ha
            .iter()
            .map(|h| u64::from(h.config.interval_secs).saturating_mul(3))
            .fold(HA_MIN_AGE_SECS, u64::max);
        inv.expire_source(Source::HomeAssistant, now, ha_max_age);
        let history_age = if cfg.all_users {
            u64::from(cfg.within_hours).saturating_mul(3_600)
        } else {
            0
        };
        inv.expire_source(Source::History, now, history_age);
    }

    /// Home Assistant's own poll (devices with entities, and the trackers' addresses) as
    /// observations, once per poll. This is the feed `sources::ha_observations` waited for.
    fn merge_ha(&mut self, h: &SharedHa, inv: &mut Inventory, now: u64) -> bool {
        if self.ha_applied.get(&h.name).copied() == Some(h.at) {
            return false;
        }
        self.ha_applied.insert(h.name.clone(), h.at);
        let (devices, trackers) = &*h.raw;
        // The poll's own time: an address that Home Assistant stops reporting ages out from it.
        let seen = if h.at == 0 { now } else { h.at.min(now) };
        let obs = ha_observations(devices, trackers, seen);
        inv.apply(&obs, now);
        !obs.is_empty()
    }

    fn start_unifi(&mut self, su: &SharedUnifi, now: u64) {
        let st = self.state.entry(su.name.clone()).or_default();
        if st.in_flight
            || su.at <= st.consumed_at
            || now < st.last_start.saturating_add(MIN_GAP_SECS)
        {
            return;
        }
        st.in_flight = true;
        st.last_start = now;
        let (su, cfg, tx, resolver) = (
            su.clone(),
            self.input.cfg,
            self.tx.clone(),
            Arc::clone(&self.resolver),
        );
        tokio::spawn(async move {
            let out = read_unifi_extras(&su, cfg, now, &resolver).await;
            let _ = tx.send(out);
        });
    }

    fn start_ha(&mut self, h: &SharedHa, now: u64) {
        let key = format!("ha:{}", h.name);
        let st = self.state.entry(key).or_default();
        if st.in_flight
            || h.at <= st.consumed_at
            || now < st.last_start.saturating_add(MIN_GAP_SECS)
        {
            return;
        }
        st.in_flight = true;
        st.last_start = now;
        let (h, tx, resolver) = (h.clone(), self.tx.clone(), Arc::clone(&self.resolver));
        tokio::spawn(async move {
            let out = read_ha_entityless(&h, now, &resolver).await;
            let _ = tx.send(out);
        });
    }

    /// Records one result: the status, and a log line when it changed.
    fn record(&mut self, router: &str, r: &ReadResult, now: u64) {
        let name = router.strip_prefix("ha:").unwrap_or(router);
        if self.reported.changed(name, r.read, &r.ended) {
            match &r.ended {
                Ended::Ok { rows, truncated } => {
                    tracing::info!(router = %name, read = r.read, rows, truncated, "inventory: extra read works");
                }
                Ended::Refused(why) => {
                    tracing::warn!(router = %name, read = r.read, error = %why, "inventory: the console refused an extra read; it is reported once, and tried again at the next poll");
                }
                Ended::Failed(why) => {
                    tracing::warn!(router = %name, read = r.read, error = %why, "inventory: an extra read failed; it is reported once, and tried again at the next poll");
                }
            }
        }
        let (state, rows, error) = match &r.ended {
            Ended::Ok { rows, .. } => ("ok", *rows, None),
            Ended::Refused(why) => ("refused", 0, Some(why.clone())),
            Ended::Failed(why) => ("failed", 0, Some(why.clone())),
        };
        self.statuses.insert(
            (name.to_owned(), r.read),
            DiscoveryRead {
                router: name.to_owned(),
                read: r.read.to_owned(),
                state: state.to_owned(),
                rows: u32::try_from(rows).unwrap_or(u32::MAX),
                truncated: matches!(
                    r.ended,
                    Ended::Ok {
                        truncated: true,
                        ..
                    }
                ),
                error,
                at: Some(now),
            },
        );
    }

    fn publish(&self) {
        self.input
            .status
            .store(Arc::new(self.statuses.values().cloned().collect()));
    }
}

/// Reads a UniFi answer, mapping a 401/403 to a refusal and any other bad status to a failure.
async fn unifi_get(
    client: &telltale_filter::fetch::Client,
    req: Result<http::Request<Vec<u8>>, String>,
    what: &str,
) -> Result<Value, Ended> {
    let (status, _, v) = call_capped(client, req.map_err(Ended::Failed)?, MAX_ANSWER)
        .await
        .map_err(Ended::Failed)?;
    if status == http::StatusCode::UNAUTHORIZED || status == http::StatusCode::FORBIDDEN {
        return Err(Ended::Refused(format!(
            "{what}: HTTP {status} (the key or user can't read it; UniFi gives this read to an administrator)"
        )));
    }
    if !status.is_success() {
        return Err(Ended::Failed(format!("{what}: HTTP {status}")));
    }
    Ok(v)
}

fn ended_of(p: &Parsed) -> Ended {
    Ended::Ok {
        rows: p.rows,
        truncated: p.truncated,
    }
}

/// The extra UniFi reads for one router, in order: devices (their names spell the places), history,
/// then the client fields from the poll's own answers.
async fn read_unifi_extras(
    su: &SharedUnifi,
    cfg: ReadsConfig,
    now: u64,
    resolver: &Arc<dyn telltale_filter::fetch::Resolve>,
) -> Outcome {
    let mut out = Outcome {
        router: su.name.clone(),
        at: su.at,
        observations: Vec::new(),
        results: Vec::new(),
    };
    let client = match http_client(&su.config, resolver) {
        Ok(c) => c,
        Err(e) => {
            // Without a client none of the reads can run: every enabled one reports it.
            for (on, read) in [(cfg.devices, READ_DEVICES), (cfg.all_users, READ_ALL_USERS)] {
                if on {
                    out.results.push(ReadResult {
                        read,
                        ended: Ended::Failed(e.clone()),
                    });
                }
            }
            return out;
        }
    };
    let api = format!("{}/api/s/{}", su.session.root, su.session.site);
    let auth = &su.session.auth;
    let mut device_names: HashMap<String, String> = HashMap::new();
    if cfg.devices {
        let url = format!("{api}/stat/device");
        let ended = match unifi_get(&client, auth.get(&url), &url).await {
            Ok(v) => {
                let p = devices(&v, &su.name, now);
                let ended = ended_of(&p);
                device_names = p.device_names;
                out.observations.extend(p.observations);
                ended
            }
            Err(e) => e,
        };
        out.results.push(ReadResult {
            read: READ_DEVICES,
            ended,
        });
    }
    if cfg.all_users {
        let url = format!("{api}/stat/alluser");
        let body = serde_json::json!({
            "type": "all",
            "conn": "all",
            "within": cfg.within_hours,
        });
        let ended = match unifi_get(&client, auth.query(&url, &body), &url).await {
            Ok(v) => {
                let p = all_users(&v, &su.name, now, cfg.within_hours);
                let ended = ended_of(&p);
                out.observations.extend(p.observations);
                ended
            }
            Err(e) => e,
        };
        out.results.push(ReadResult {
            read: READ_ALL_USERS,
            ended,
        });
    }
    if cfg.client_fields
        && let Some(raw) = &su.raw
    {
        let p = client_fields(&raw.sta, raw.users.as_deref(), &device_names, now);
        out.results.push(ReadResult {
            read: READ_CLIENT_FIELDS,
            ended: ended_of(&p),
        });
        out.observations.extend(p.observations);
    }
    out
}

/// Home Assistant's registry devices without entities (the second fixed template, ADR-912).
async fn read_ha_entityless(
    h: &SharedHa,
    now: u64,
    resolver: &Arc<dyn telltale_filter::fetch::Resolve>,
) -> Outcome {
    let router = format!("ha:{}", h.name);
    let mut out = Outcome {
        router,
        at: h.at,
        observations: Vec::new(),
        results: Vec::new(),
    };
    let ended = match ha_get(&h.config, &h.token, resolver).await {
        Ok(v) => {
            let p = ha_entityless(&v, now);
            let ended = ended_of(&p);
            out.observations = p.observations;
            ended
        }
        Err(e) => e,
    };
    out.results.push(ReadResult {
        read: READ_HA_ALL,
        ended,
    });
    out
}

async fn ha_get(
    cfg: &RouterConfig,
    token: &str,
    resolver: &Arc<dyn telltale_filter::fetch::Resolve>,
) -> Result<Value, Ended> {
    let client = http_client(cfg, resolver).map_err(Ended::Failed)?;
    let url = format!("{}/api/template", cfg.url.trim_end_matches('/'));
    let body = serde_json::json!({ "template": HA_ENTITYLESS_TEMPLATE }).to_string();
    let req = http::Request::post(url.as_str())
        .header(
            "authorization",
            crate::routers::bearer_header(token).map_err(|e| Ended::Failed(e.to_string()))?,
        )
        .header("content-type", "application/json")
        .header("accept", "text/plain, application/json")
        .body(body.into_bytes())
        .map_err(|e| Ended::Failed(e.to_string()))?;
    let (status, _, v) = call_capped(&client, req, HA_MAX_ANSWER)
        .await
        .map_err(Ended::Failed)?;
    if status == http::StatusCode::UNAUTHORIZED || status == http::StatusCode::FORBIDDEN {
        return Err(Ended::Refused(format!(
            "{url}: HTTP {status} (rendering templates needs an administrator's token)"
        )));
    }
    if !status.is_success() {
        return Err(Ended::Failed(format!("{url}: HTTP {status}")));
    }
    if v.get("devices").is_none() {
        return Err(Ended::Failed(format!(
            "{url}: the answer isn't the expected JSON"
        )));
    }
    Ok(v)
}

#[cfg(test)]
#[path = "reads_tests.rs"]
mod tests;

//! Router integrations (REQ: API-010 naming sources, M8 "router integrations"; T8.2): device
//! names and addresses read from the router's DHCP, so devices show up by name without
//! TelltaleDNS running DHCP itself.
//! - **UniFi** (UniFi OS consoles: UDM, UCG, Cloud Key Gen2+; and the classic Network
//!   application): the active clients (`stat/sta`), named by their UniFi alias, else their
//!   host name; (T22.2) the known clients with a fixed IP (`rest/user`), so a reserved device
//!   keeps its name while it's offline; and the networks (`rest/networkconf`: subnet, VLAN,
//!   DHCP range, domain). An API key (`X-API-KEY`), or a local username and password.
//! - **OPNsense**: the DHCP leases (Dnsmasq, Kea, or ISC, whichever the box runs), with an
//!   API key and secret.
//! - **Home Assistant** (REQ: API-012, T22.3): the device registry's names for devices
//!   registered with a MAC address (Shelly, `ESPHome`, Sonos, TVs...), read with a long-lived
//!   access token through the REST template endpoint (the registry has no REST endpoint of
//!   its own, and the template keeps this read-only and on the HTTP client already in the
//!   tree). Home Assistant knows MAC addresses, not IP addresses: a device's address comes from
//!   the other routers' answers, else from Home Assistant's own `device_tracker` entities.
//!
//! Polled every `interval_secs`; the result replaces that router's part of the lease view
//! the naming falls back to (after configured device names). Never on the DNS path; a router
//! that's down keeps its last answer and is logged.
//!
//! When two sources name one address (ADR-902): a name you gave the device in Home Assistant
//! wins, then the routers' (in configuration order), then the name a Home Assistant
//! integration gave it.

// REQ: API-016 (ADR-922) — the release build aborts on panic, so this module's runtime code uses no
// unwrap, expect, or unchecked indexing (malformed answers are tested).
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use std::time::Instant;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use telltale_api::model::{RouterCheck, RouterStatus};
use telltale_config::{RouterConfig, RouterKind};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::devices::{Lease, Leases};

/// Most bytes one answer may have.
const MAX_ANSWER: u64 = 16 << 20;

/// One device a router reported: (MAC, IPv4 address, name).
pub(crate) type Entry = (String, Ipv4Addr, Option<String>);
/// What a router reported.
pub(crate) type Seen = Vec<Entry>;
/// An entry with how good its name is (ADR-902).
type Ranked = (u8, Entry);

/// How good a name is when two sources name one address (lower wins; ADR-902).
const RANK_CURATED: u8 = 0;
const RANK_ROUTER: u8 = 1;
const RANK_INTEGRATION: u8 = 2;

/// REQ: API-013 (T22.2) — a network (a LAN or VLAN) a router reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Network {
    /// The `[[router]]` that reported it.
    pub(crate) router: String,
    pub(crate) name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) vlan: Option<u16>,
    /// The network address and prefix length (`192.0.2.0`, 24).
    pub(crate) subnet: Ipv4Addr,
    pub(crate) prefix: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) gateway: Option<Ipv4Addr>,
    /// The DHCP pool, when the router serves DHCP on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) dhcp_start: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) dhcp_stop: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) domain: Option<String>,
    /// The router's own word for it (UniFi: `corporate`, `guest`, `vlan-only`...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) purpose: Option<String>,
}

/// The address is in the network `net/prefix`.
pub(crate) fn in_network(net: Ipv4Addr, prefix: u8, ip: Ipv4Addr) -> bool {
    let mask = prefix_mask(prefix);
    u32::from(ip) & mask == u32::from(net) & mask
}

pub(crate) fn prefix_mask(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - u32::from(p)),
    }
}

/// One router's answer.
#[derive(Debug, Default, Clone)]
struct Polled {
    /// `(rank, (MAC, address, name))`.
    seen: Vec<Ranked>,
    networks: Vec<Network>,
    /// Optional reads that didn't work (logged once, so a key without access is noticed).
    notes: Vec<String>,
    /// REQ: T8.2 (ADR-166) — UniFi's offline clients that are known by name: they name an
    /// address in the query log, but they aren't "seen", so device identification doesn't
    /// count them.
    offline: Seen,
    /// REQ: DNS-023 (T24.8, ADR-983) — the connected clients' usable IPv6 addresses, by MAC
    /// (UniFi's `ipv6_addresses`). They ride on the lease of the same MAC (see [`rebuild`]).
    v6: Vec<(String, Ipv6Addr)>,
    /// REQ: DSC-009 (ADR-912) — the session this poll used, for the inventory's extra reads.
    session: Option<UnifiSession>,
    /// REQ: DSC-009 — the raw client answers, kept only when asked for.
    raw: Option<RawClients>,
}

impl Polled {
    fn routed(seen: Seen) -> Self {
        Self {
            seen: seen.into_iter().map(|s| (RANK_ROUTER, s)).collect(),
            ..Self::default()
        }
    }
}

/// REQ: T8.2 (ADR-166) — most offline clients one UniFi poll keeps (most recently seen first),
/// whatever `offline_days` says: they ride in every node's answer to `devices.names` and sit
/// in memory on every node.
pub(crate) const OFFLINE_MAX: usize = 1024;

/// REQ: OPS-014 (ADR-903 §2) — a router credential: its file, or the stored secret it names.
pub(crate) fn secret(
    file: Option<&telltale_config::SafeString>,
    reference: Option<&telltale_config::SafeString>,
    store: &crate::secrets::SecretStore,
) -> Result<Option<crate::secrets::SecretValue>, String> {
    crate::secrets::Credential::of(file, reference)
        .resolve(Some(store))
        .map(|r| r.map(|r| r.value))
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for i in 0..4 {
            if i <= chunk.len() {
                let idx = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0);
                out.push(char::from(T.get(idx).copied().unwrap_or(b'=')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `AA-BB-CC-00-00-01` → `aa:bb:cc:00:00:01`.
pub(crate) fn mac_key(mac: &str) -> String {
    mac.trim().to_ascii_lowercase().replace('-', ":")
}

/// One HTTP exchange; the JSON body and the response headers.
async fn call(
    client: &telltale_filter::fetch::Client,
    req: http::Request<Vec<u8>>,
) -> Result<(http::StatusCode, http::HeaderMap, Value), String> {
    call_capped(client, req, MAX_ANSWER).await
}

/// One HTTP exchange whose answer may have at most `cap` bytes (REQ: DSC-009, ADR-912: the extra
/// UniFi reads take 4 MiB, Home Assistant's registry template 1 MiB).
pub(crate) async fn call_capped(
    client: &telltale_filter::fetch::Client,
    req: http::Request<Vec<u8>>,
    cap: u64,
) -> Result<(http::StatusCode, http::HeaderMap, Value), String> {
    // REQ: API-014 — an error never quotes a password in the URL.
    let url = telltale_config::credentials::url_shown(&req.uri().to_string());
    let resp = tokio::time::timeout(Duration::from_secs(15), client.request(req, cap))
        .await
        .map_err(|_| format!("{url}: timed out"))?
        .map_err(|e| format!("{url}: {}", e.message))?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body();
    // REQ: API-016 (review of T23.7, ADR-922) — a success whose answer isn't JSON is a failed read:
    // read as nothing, it would clear the router's names. An error status keeps its own message.
    let v = if body.is_empty() || !status.is_success() {
        serde_json::from_slice(&body).unwrap_or(Value::Null)
    } else {
        serde_json::from_slice(&body).map_err(|_| format!("{url}: the answer isn't JSON"))?
    };
    Ok((status, headers, v))
}

/// The `name=value` pairs of every `Set-Cookie`.
fn cookies(h: &http::HeaderMap) -> String {
    h.get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|c| c.split(';').next())
        .collect::<Vec<_>>()
        .join("; ")
}

/// The first non-empty string among `keys`.
pub(crate) fn first_str(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|k| v.get(*k).and_then(Value::as_str))
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_owned)
}

/// UniFi clients in a `stat/sta` (or `rest/user`) answer.
pub(crate) fn unifi_clients(v: &Value) -> Seen {
    let Some(data) = v.get("data").and_then(Value::as_array) else {
        return Vec::new();
    };
    data.iter()
        .filter_map(|c| {
            let mac = c.get("mac")?.as_str()?.to_ascii_lowercase();
            let ip: Ipv4Addr = c
                .get("ip")
                .or_else(|| c.get("last_ip"))
                .or_else(|| c.get("fixed_ip"))?
                .as_str()?
                .parse()
                .ok()?;
            let name = first_str(c, &["name", "hostname"]);
            Some((mac, ip, name))
        })
        .collect()
}

/// REQ: DNS-023 (T24.8, ADR-983) — the IPv6 addresses UniFi reports for its connected clients
/// (`ipv6_addresses` in a `stat/sta` row), by MAC: usable addresses only (`usable_ipv6`: no
/// link-local), however many the row lists.
pub(crate) fn unifi_ipv6(v: &Value) -> Vec<(String, Ipv6Addr)> {
    let Some(data) = v.get("data").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for c in data {
        let Some(mac) = c.get("mac").and_then(Value::as_str).map(mac_key) else {
            continue;
        };
        let Some(list) = c.get("ipv6_addresses").and_then(Value::as_array) else {
            continue;
        };
        for a in list.iter().filter_map(Value::as_str) {
            if let Ok(ip) = a.trim().parse::<Ipv6Addr>()
                && crate::devices::usable_ipv6(&ip)
            {
                out.push((mac.clone(), ip));
            }
        }
    }
    out
}

/// REQ: T22.2 — UniFi's known clients that have a fixed IP (a DHCP reservation), from a
/// `rest/user` answer: the reserved address, whether or not the device is connected. Known
/// clients without one are left out: their last address may belong to someone else by now.
pub(crate) fn unifi_reserved(v: &Value) -> Seen {
    let Some(data) = v.get("data").and_then(Value::as_array) else {
        return Vec::new();
    };
    data.iter()
        .filter_map(|c| {
            if !c
                .get("use_fixedip")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return None;
            }
            let mac = c.get("mac")?.as_str()?.to_ascii_lowercase();
            let ip: Ipv4Addr = c.get("fixed_ip")?.as_str()?.trim().parse().ok()?;
            Some((mac, ip, first_str(c, &["name", "hostname"])))
        })
        .collect()
}

/// REQ: T22.2 — the connected clients, then the reservations of devices that aren't
/// connected (a connected device's current address wins over its reservation).
fn unifi_merge(active: Seen, reserved: Seen) -> Seen {
    let mut out = active;
    for r in reserved {
        if !out.iter().any(|(mac, ip, _)| *mac == r.0 || *ip == r.1) {
            out.push(r);
        }
    }
    out
}

/// REQ: T8.2 (ADR-166) — the client objects of a UniFi answer: `data` in the classic API, a
/// bare array in v2.
fn unifi_rows(v: &Value) -> &[Value] {
    v.get("data")
        .and_then(Value::as_array)
        .or_else(|| v.as_array())
        .map_or(&[], Vec::as_slice)
}

/// REQ: T8.2 (ADR-166) — UniFi's known clients that may be offline (v2 `clients/history`,
/// `rest/user`): the named ones, most recently seen first, at most [`OFFLINE_MAX`]. A row last
/// seen before `not_before` (Unix seconds) is dropped; one with no date stays (the cap bounds
/// those). A fixed address counts only while its reservation is on.
pub(crate) fn unifi_known(v: &Value, not_before: u64) -> Seen {
    let mut rows: Vec<(u64, Entry)> = unifi_rows(v)
        .iter()
        .filter_map(|c| {
            let seen = c.get("last_seen").and_then(Value::as_u64);
            if seen.is_some_and(|t| t < not_before) {
                return None;
            }
            let mac = c.get("mac")?.as_str()?.to_ascii_lowercase();
            let fixed = c
                .get("use_fixedip")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let mut addrs: Vec<&str> = ["ip", "last_ip"]
                .iter()
                .filter_map(|k| c.get(*k).and_then(Value::as_str))
                .collect();
            if fixed {
                addrs.extend(c.get("fixed_ip").and_then(Value::as_str));
            }
            let ip: Ipv4Addr = addrs.into_iter().find_map(|s| s.trim().parse().ok())?;
            let name = first_str(c, &["name", "hostname"])?;
            Some((seen.unwrap_or(0), (mac, ip, Some(name))))
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.0));
    rows.truncate(OFFLINE_MAX);
    rows.into_iter().map(|(_, e)| e).collect()
}

/// REQ: T8.2 (ADR-166) — a connected client with no name takes the name UniFi knows for its
/// MAC.
fn unifi_fill_names(seen: &mut Seen, known: &Seen) {
    let names: HashMap<&str, &str> = known
        .iter()
        .filter_map(|k| Some((k.0.as_str(), k.2.as_deref()?)))
        .collect();
    for c in seen.iter_mut().filter(|c| c.2.is_none()) {
        c.2 = names.get(c.0.as_str()).map(|n| (*n).to_owned());
    }
}

/// REQ: T8.2 (ADR-166) — the known clients that no connected or reserved device holds (by MAC
/// or address), at most [`OFFLINE_MAX`]; the first of two rows for one device or address wins.
pub(crate) fn unifi_offline(held: &Seen, known: Seen) -> Seen {
    let mut macs: std::collections::HashSet<String> = held.iter().map(|c| c.0.clone()).collect();
    let mut ips: std::collections::HashSet<Ipv4Addr> = held.iter().map(|c| c.1).collect();
    let mut out = Seen::new();
    for (mac, ip, name) in known {
        if out.len() >= OFFLINE_MAX {
            break;
        }
        if macs.contains(&mac) || !ips.insert(ip) {
            continue;
        }
        macs.insert(mac.clone());
        out.push((mac, ip, name));
    }
    out
}

/// REQ: API-013 (T22.2) — UniFi's networks in a `rest/networkconf` answer: the ones with a
/// subnet (not WAN or VPN); `ip_subnet` is the gateway's address with the prefix
/// (`192.0.2.1/24`).
pub(crate) fn unifi_networks(v: &Value, router: &str) -> Vec<Network> {
    let Some(data) = v.get("data").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out: Vec<Network> = data
        .iter()
        .filter_map(|n| {
            let purpose = first_str(n, &["purpose"]);
            if matches!(
                purpose.as_deref(),
                Some("wan" | "remote-user-vpn" | "site-vpn" | "vpn-client")
            ) {
                return None;
            }
            let (addr, prefix) = n.get("ip_subnet")?.as_str()?.trim().split_once('/')?;
            let gateway: Ipv4Addr = addr.parse().ok()?;
            let prefix: u8 = prefix.parse().ok().filter(|p| *p <= 32)?;
            let subnet = Ipv4Addr::from(u32::from(gateway) & prefix_mask(prefix));
            let vlan = match n.get("vlan") {
                Some(Value::Number(x)) => x.as_u64(),
                Some(Value::String(s)) => s.trim().parse().ok(),
                _ => None,
            }
            .and_then(|x| u16::try_from(x).ok())
            .filter(|x| (1..=4094).contains(x))
            .filter(|_| {
                n.get("vlan_enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(true)
            });
            let dhcp = n
                .get("dhcpd_enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let addr_of = |k: &str| {
                dhcp.then(|| n.get(k).and_then(Value::as_str))
                    .flatten()
                    .and_then(|s| s.trim().parse::<Ipv4Addr>().ok())
            };
            Some(Network {
                router: router.to_owned(),
                name: first_str(n, &["name"]).unwrap_or_else(|| format!("{subnet}/{prefix}")),
                vlan,
                subnet,
                prefix,
                gateway: Some(gateway),
                dhcp_start: addr_of("dhcpd_start"),
                dhcp_stop: addr_of("dhcpd_stop"),
                domain: first_str(n, &["domain_name"]),
                purpose,
            })
        })
        .collect();
    out.sort_by_key(|n| (u32::from(n.subnet), n.prefix));
    out
}

/// OPNsense leases in a search answer (Dnsmasq, Kea, or ISC field names).
pub(crate) fn opnsense_leases(v: &Value) -> Seen {
    let Some(rows) = v.get("rows").and_then(Value::as_array) else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|r| {
            let ip: Ipv4Addr = r.get("address")?.as_str()?.parse().ok()?;
            let mac = r
                .get("mac")
                .or_else(|| r.get("hwaddr"))?
                .as_str()?
                .to_ascii_lowercase();
            let name = ["hostname", "client_hostname", "descr"]
                .iter()
                .filter_map(|k| r.get(*k).and_then(Value::as_str))
                .map(str::trim)
                .find(|s| !s.is_empty() && *s != "*")
                .map(str::to_owned);
            Some((mac, ip, name))
        })
        .collect()
}

/// How a UniFi request authenticates.
#[derive(Clone)]
pub(crate) enum UnifiAuth {
    /// REQ: OPS-014 — wiped when the poll ends (ADR-903 note 37).
    Key(zeroize::Zeroizing<String>),
    Cookie(zeroize::Zeroizing<String>),
}

impl UnifiAuth {
    pub(crate) fn get(&self, url: &str) -> Result<http::Request<Vec<u8>>, String> {
        let b = http::Request::get(url).header("accept", "application/json");
        self.apply(b).body(Vec::new()).map_err(|e| e.to_string())
    }

    /// REQ: DSC-009 (ADR-912) — a read that UniFi takes as a `POST` with a query body
    /// (the history query of the inventory). It changes nothing on the console.
    pub(crate) fn query(&self, url: &str, body: &Value) -> Result<http::Request<Vec<u8>>, String> {
        let b = http::Request::post(url)
            .header("accept", "application/json")
            .header("content-type", "application/json");
        self.apply(b)
            .body(body.to_string().into_bytes())
            .map_err(|e| e.to_string())
    }

    fn apply(&self, b: http::request::Builder) -> http::request::Builder {
        match self {
            Self::Key(k) => b.header("x-api-key", k.as_str()),
            Self::Cookie(c) => b.header("cookie", c.as_str()),
        }
    }
}

impl std::fmt::Debug for UnifiAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // REQ: API-014 — a credential never reaches a log or a Debug print.
        f.write_str("UnifiAuth(<redacted>)")
    }
}

/// REQ: DSC-009 (ADR-912) — the session a UniFi poll used, shared with the inventory thread so its
/// extra reads use the router's own credentials and need no second login.
#[derive(Debug, Clone)]
pub(crate) struct UnifiSession {
    /// `https://console/proxy/network` (UniFi OS) or the controller's base.
    pub(crate) root: String,
    pub(crate) site: String,
    pub(crate) auth: Arc<UnifiAuth>,
}

/// REQ: DSC-009 (ADR-912) — the raw `stat/sta` and `rest/user` answers the poll already holds,
/// kept only while `[discovery] unifi_reads.client_fields` is on.
#[derive(Debug, Clone)]
pub(crate) struct RawClients {
    pub(crate) sta: Arc<Value>,
    pub(crate) users: Option<Arc<Value>>,
}

/// REQ: DSC-009 (ADR-912) — one UniFi router as the inventory thread sees it.
#[derive(Debug, Clone)]
pub(crate) struct SharedUnifi {
    pub(crate) name: String,
    pub(crate) config: RouterConfig,
    pub(crate) session: UnifiSession,
    pub(crate) raw: Option<RawClients>,
    /// When the poll that made this session finished (Unix seconds).
    pub(crate) at: u64,
}

/// What Home Assistant's poll read: the named devices and the trackers' addresses.
pub(crate) type HaRead = (Vec<HaDevice>, HashMap<String, Ipv4Addr>);

/// REQ: DSC-009 (ADR-912) — Home Assistant as the inventory thread sees it: its settings, its
/// token and the last devices and trackers the poll read.
#[derive(Clone)]
pub(crate) struct SharedHa {
    pub(crate) name: String,
    pub(crate) config: RouterConfig,
    pub(crate) token: Arc<zeroize::Zeroizing<String>>,
    pub(crate) raw: Arc<HaRead>,
    pub(crate) at: u64,
}

impl std::fmt::Debug for SharedHa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedHa")
            .field("name", &self.name)
            .field("token", &"<redacted>")
            .field("at", &self.at)
            .finish_non_exhaustive()
    }
}

/// REQ: DSC-009 (ADR-912) — what the router poll shares with the `telltale-inventory` thread. The
/// poll only stores it; every extra read and every parse of it runs on that thread, never on the
/// main runtime. Empty unless `[discovery]` runs on this node.
#[derive(Debug, Clone, Default)]
pub(crate) struct Shared {
    pub(crate) unifi: Vec<SharedUnifi>,
    pub(crate) ha: Vec<SharedHa>,
}

impl Shared {
    /// Whether two shares hold the same reads (by router and poll time), so the poll loop
    /// publishes only a change.
    fn same_as(&self, other: &Self) -> bool {
        self.unifi.len() == other.unifi.len()
            && self.ha.len() == other.ha.len()
            && self
                .unifi
                .iter()
                .zip(&other.unifi)
                .all(|(a, b)| a.name == b.name && a.at == b.at && a.config == b.config)
            && self
                .ha
                .iter()
                .zip(&other.ha)
                .all(|(a, b)| a.name == b.name && a.at == b.at && a.config == b.config)
    }
}

/// REQ: DSC-009 (ADR-912) — what the poll is to keep for the inventory.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Keep {
    /// Share sessions (discovery runs on this node).
    pub(crate) share: bool,
    /// Also keep the raw `stat/sta` and `rest/user` answers (`unifi_reads.client_fields`).
    pub(crate) raw_clients: bool,
}

/// The active clients (required), then the reservations and the networks (each optional: a
/// console or key that can't read them still names the connected clients).
async fn read_unifi(
    client: &telltale_filter::fetch::Client,
    auth: &UnifiAuth,
    root: &str,
    site: &str,
    router: &str,
    offline_days: u32,
    keep: Keep,
) -> Result<Polled, String> {
    let api = format!("{root}/api/s/{site}");
    let url = format!("{api}/stat/sta");
    let (status, _, v) = call(client, auth.get(&url)?).await?;
    if status == http::StatusCode::UNAUTHORIZED || status == http::StatusCode::FORBIDDEN {
        let what = match auth {
            UnifiAuth::Key(_) => {
                "check the API key (UniFi Network → Settings → Control Plane → Integrations)"
            }
            UnifiAuth::Cookie(_) => "check the user's role on this site",
        };
        return Err(format!("{url}: HTTP {status} ({what})"));
    }
    if !status.is_success() {
        return Err(format!("{url}: HTTP {status}"));
    }
    let active = unifi_clients(&v);
    let v6 = unifi_ipv6(&v);
    // REQ: DSC-009 (ADR-912) — the answer is moved, not copied, into what the inventory thread
    // parses; nothing is kept unless `client_fields` is on.
    let sta_raw = keep.raw_clients.then(|| Arc::new(v));
    let mut notes = Vec::new();
    let mut optional =
        |what: &str, r: Result<(http::StatusCode, http::HeaderMap, Value), String>| match r {
            Ok((s, _, v)) if s.is_success() => Some(v),
            Ok((s, _, _)) => {
                notes.push(format!("{what}: HTTP {s}"));
                None
            }
            Err(e) => {
                notes.push(format!("{what}: {e}"));
                None
            }
        };
    let user_rows = optional(
        "reservations (rest/user)",
        call(client, auth.get(&format!("{api}/rest/user"))?).await,
    );
    let reserved = user_rows.as_ref().map(unifi_reserved).unwrap_or_default();
    let raw = sta_raw.map(|sta| RawClients {
        sta,
        users: user_rows.clone().map(Arc::new),
    });
    let networks = optional(
        "networks (rest/networkconf)",
        call(client, auth.get(&format!("{api}/rest/networkconf"))?).await,
    )
    .map(|v| unifi_networks(&v, router))
    .unwrap_or_default();
    // REQ: T8.2 (ADR-166) — offline clients, when `offline_days` keeps any: the console filters
    // its history by the window before answering, and every dated row is checked against it.
    let mut known = Seen::new();
    if offline_days > 0 {
        let days = u64::from(offline_days);
        let not_before = crate::pipeline::unix_now().saturating_sub(days * 86_400);
        let history = format!(
            "{root}/v2/api/site/{site}/clients/history?onlyNonBlocked=true&includeUnifiDevices=false&withinHours={}",
            days * 24
        );
        if let Some(v) = optional(
            "offline clients (clients/history)",
            call(client, auth.get(&history)?).await,
        ) {
            known.extend(unifi_known(&v, not_before));
        }
        // REQ: T8.2 (ADR-942) — the names the console's configured clients (rest/user) carry,
        // by their dated last-seen window like the history rows, so an alias without a
        // reservation names an offline device too.
        if let Some(v) = &user_rows {
            known.extend(unifi_known(v, not_before));
        }
    }
    let mut seen = unifi_merge(active, reserved);
    unifi_fill_names(&mut seen, &known);
    let offline = unifi_offline(&seen, known);
    Ok(Polled {
        networks,
        notes,
        offline,
        v6,
        session: keep.share.then(|| UnifiSession {
            root: root.to_owned(),
            site: site.to_owned(),
            auth: Arc::new(auth.clone()),
        }),
        raw,
        ..Polled::routed(seen)
    })
}

/// One poll of a UniFi console or Network application.
async fn poll_unifi(
    client: &telltale_filter::fetch::Client,
    c: &RouterConfig,
    store: &crate::secrets::SecretStore,
    keep: Keep,
) -> Result<Polled, String> {
    let base = c.url.trim_end_matches('/');
    let site = c.site.as_deref().unwrap_or("default");
    if let Some(key) = secret(c.api_key_file.as_ref(), c.api_key_ref.as_ref(), store)? {
        return read_unifi(
            client,
            &UnifiAuth::Key(zeroize::Zeroizing::new(key.expose().to_owned())),
            &format!("{base}/proxy/network"),
            site,
            &c.name,
            c.offline_days,
            keep,
        )
        .await;
    }
    let user = c
        .username
        .as_deref()
        .ok_or("set api_key_file, or username and password_file")?;
    let pass = secret(c.password_file.as_ref(), c.password_ref.as_ref(), store)?
        .ok_or("set password_file")?;
    let body = zeroize::Zeroizing::new(
        serde_json::json!({"username": user, "password": pass.expose(), "remember": false})
            .to_string(),
    );
    // UniFi OS consoles first, then the classic Network application.
    for (login, prefix) in [("/api/auth/login", "/proxy/network"), ("/api/login", "")] {
        let req = http::Request::post(format!("{base}{login}"))
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .body(body.as_bytes().to_vec())
            .map_err(|e| e.to_string())?;
        let (status, headers, _) = call(client, req).await?;
        if status == http::StatusCode::NOT_FOUND {
            continue;
        }
        if !status.is_success() {
            return Err(format!(
                "{base}{login}: HTTP {status} (check the username and password)"
            ));
        }
        return read_unifi(
            client,
            &UnifiAuth::Cookie(zeroize::Zeroizing::new(cookies(&headers))),
            &format!("{base}{prefix}"),
            site,
            &c.name,
            c.offline_days,
            keep,
        )
        .await;
    }
    Err(format!(
        "{base}: neither a UniFi OS console nor a Network application"
    ))
}

/// One poll of an OPNsense box.
async fn poll_opnsense(
    client: &telltale_filter::fetch::Client,
    c: &RouterConfig,
    store: &crate::secrets::SecretStore,
) -> Result<Polled, String> {
    let base = c.url.trim_end_matches('/');
    let key = secret(c.api_key_file.as_ref(), c.api_key_ref.as_ref(), store)?
        .ok_or("set api_key_file")?;
    let sec = secret(c.api_secret_file.as_ref(), c.api_secret_ref.as_ref(), store)?
        .ok_or("set api_secret_file")?;
    let pair = zeroize::Zeroizing::new(format!("{}:{}", key.expose(), sec.expose()));
    let auth = format!("Basic {}", base64(pair.as_bytes()));
    let mut last = String::new();
    for path in [
        "/api/dnsmasq/leases/search",
        "/api/kea/leases4/search",
        "/api/dhcpv4/leases/searchLease",
    ] {
        let req = http::Request::get(format!("{base}{path}"))
            .header("authorization", auth.as_str())
            .header("accept", "application/json")
            .body(Vec::new())
            .map_err(|e| e.to_string())?;
        let (status, _, v) = call(client, req).await?;
        if status.is_success() && v.get("rows").is_some() {
            return Ok(Polled::routed(opnsense_leases(&v)));
        }
        if status == http::StatusCode::UNAUTHORIZED || status == http::StatusCode::FORBIDDEN {
            return Err(format!(
                "{base}: HTTP {status} (check the API key and its privileges)"
            ));
        }
        last = format!("{base}{path}: HTTP {status}");
    }
    Err(format!("no DHCP lease API answered ({last})"))
}

/// REQ: API-012 (T22.3) — the template Home Assistant renders: every device that has an
/// entity and a MAC connection (its user-given name, its integration's name, its area), and
/// every `device_tracker` entity's MAC and IP. Rendered by Home Assistant's own template
/// engine; it reads, it changes nothing.
pub(crate) const HA_TEMPLATE: &str = r"{%- set ns = namespace(devices=[], trackers=[]) -%}
{%- for d in states | map(attribute='entity_id') | map('device_id') | reject('none') | unique -%}
{%- set m = namespace(macs=[]) -%}
{%- for c in device_attr(d, 'connections') or [] -%}
{%- if c[0] == 'mac' -%}{%- set m.macs = m.macs + [c[1] | string] -%}{%- endif -%}
{%- endfor -%}
{%- if m.macs -%}
{%- set ns.devices = ns.devices + [{'name_by_user': device_attr(d, 'name_by_user') or '', 'name': device_attr(d, 'name') or '', 'macs': m.macs, 'area': area_name(d) or ''}] -%}
{%- endif -%}
{%- endfor -%}
{%- for s in states.device_tracker -%}
{%- if s.attributes.mac and s.attributes.ip -%}
{%- set ns.trackers = ns.trackers + [{'mac': s.attributes.mac | string, 'ip': s.attributes.ip | string}] -%}
{%- endif -%}
{%- endfor -%}
{{ {'devices': ns.devices, 'trackers': ns.trackers} | tojson }}";

/// One device Home Assistant names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HaDevice {
    pub(crate) macs: Vec<String>,
    /// The name and whether a person gave it (`name_by_user`) or an integration did.
    pub(crate) name: String,
    pub(crate) curated: bool,
}

/// REQ: API-012 (T22.3) — Home Assistant's answer: the named devices and the trackers'
/// addresses. Devices without a name are skipped.
pub(crate) fn ha_devices(v: &Value) -> (Vec<HaDevice>, HashMap<String, Ipv4Addr>) {
    let devices = v
        .get("devices")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|d| {
                    let macs: Vec<String> = d
                        .get("macs")?
                        .as_array()?
                        .iter()
                        .filter_map(Value::as_str)
                        .map(mac_key)
                        .filter(|m| m.len() == 17)
                        .collect();
                    if macs.is_empty() {
                        return None;
                    }
                    if let Some(n) = first_str(d, &["name_by_user"]) {
                        return Some(HaDevice {
                            macs,
                            name: n,
                            curated: true,
                        });
                    }
                    first_str(d, &["name"]).map(|n| HaDevice {
                        macs,
                        name: n,
                        curated: false,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let trackers = v
        .get("trackers")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|t| {
                    let mac = mac_key(t.get("mac")?.as_str()?);
                    let ip: Ipv4Addr = t.get("ip")?.as_str()?.trim().parse().ok()?;
                    Some((mac, ip))
                })
                .collect()
        })
        .unwrap_or_default();
    (devices, trackers)
}

/// REQ: API-012 (T22.3) — Home Assistant's devices with the addresses their MACs have: from
/// `addresses` (the other routers' answers), else Home Assistant's own trackers.
fn ha_seen(
    devices: &[HaDevice],
    trackers: &HashMap<String, Ipv4Addr>,
    addresses: &HashMap<String, Ipv4Addr>,
) -> Vec<Ranked> {
    let mut out = Vec::new();
    for d in devices {
        let rank = if d.curated {
            RANK_CURATED
        } else {
            RANK_INTEGRATION
        };
        for mac in &d.macs {
            if let Some(ip) = addresses.get(mac).or_else(|| trackers.get(mac)) {
                out.push((rank, (mac.clone(), *ip, Some(d.name.clone()))));
            }
        }
    }
    out
}

/// One poll of Home Assistant: its devices and trackers (addresses are matched in
/// [`rebuild`]'s caller, which knows the other routers' answers).
async fn poll_home_assistant(
    client: &telltale_filter::fetch::Client,
    c: &RouterConfig,
    store: &crate::secrets::SecretStore,
) -> Result<(HaRead, Arc<zeroize::Zeroizing<String>>), String> {
    let base = c.url.trim_end_matches('/');
    let token = secret(c.api_key_file.as_ref(), c.api_key_ref.as_ref(), store)?
        .ok_or("set api_key_file")?;
    let url = format!("{base}/api/template");
    let body = serde_json::json!({ "template": HA_TEMPLATE }).to_string();
    let req = http::Request::post(url.as_str())
        .header(
            "authorization",
            bearer_header(token.expose()).map_err(|e| e.to_string())?,
        )
        .header("content-type", "application/json")
        .header("accept", "text/plain, application/json")
        .body(body.into_bytes())
        .map_err(|e| e.to_string())?;
    let (status, _, v) = call(client, req).await?;
    if status == http::StatusCode::UNAUTHORIZED || status == http::StatusCode::FORBIDDEN {
        return Err(format!(
            "{url}: HTTP {status} (check the long-lived access token; rendering templates needs an administrator's token)"
        ));
    }
    if !status.is_success() {
        return Err(format!("{url}: HTTP {status}"));
    }
    if v.get("devices").is_none() {
        return Err(format!(
            "{url}: the answer isn't the expected JSON (is this Home Assistant?)"
        ));
    }
    let token = Arc::new(zeroize::Zeroizing::new(token.expose().to_owned()));
    Ok((ha_devices(&v), token))
}

/// The leases view from every router's last answer, best name first for each address
/// (ADR-902): rank, then the order of `[[router]]` entries.
fn rebuild(order: &[String], parts: &HashMap<String, Polled>, view: &ArcSwap<Leases>) {
    let mut all: Vec<(u8, usize, &str, &Entry)> = Vec::new();
    for (i, name) in order.iter().enumerate() {
        if let Some(p) = parts.get(name) {
            for (rank, s) in &p.seen {
                all.push((*rank, i, name.as_str(), s));
            }
        }
    }
    all.sort_by_key(|(rank, i, _, _)| (*rank, *i));
    let mut m = Leases::new();
    for (_, _, router, (mac, ip, name)) in all {
        match m.get_mut(ip) {
            None => {
                m.insert(
                    *ip,
                    Lease {
                        mac: mac.clone(),
                        ip: *ip,
                        hostname: name.clone(),
                        expires: 0,
                        router: Some(router.to_owned()),
                        offline: false,
                        ipv6: Vec::new(),
                    },
                );
            }
            // A better source without a name doesn't hide a worse one's name.
            Some(l) if l.hostname.is_none() && name.is_some() => {
                l.hostname.clone_from(name);
                l.router = Some(router.to_owned());
            }
            Some(_) => {}
        }
    }
    // REQ: DNS-023 (T24.8, ADR-983) — a connected device's IPv6 addresses, from any router's
    // answer for its MAC (a Home Assistant name takes the addresses UniFi reports). Sorted and
    // capped, so the same input always gives the same table.
    let mut v6: HashMap<&str, Vec<Ipv6Addr>> = HashMap::new();
    for name in order {
        for (mac, ip) in parts.get(name).map_or(&[][..], |p| p.v6.as_slice()) {
            v6.entry(mac.as_str()).or_default().push(*ip);
        }
    }
    if !v6.is_empty() {
        for l in m.values_mut() {
            if let Some(list) = v6.get_mut(mac_key(&l.mac).as_str()) {
                list.sort_unstable();
                list.dedup();
                list.truncate(crate::devices::MAX_IPV6);
                l.ipv6.clone_from(list);
            }
        }
    }
    // REQ: T8.2 (ADR-166) — an offline client only names an address no router reports as
    // connected, and is marked, so it isn't "seen". Routers in configuration order (ADR-902), so
    // two routers' offline clients on one address always give the same name.
    for name in order {
        let Some(p) = parts.get(name) else {
            continue;
        };
        for (mac, ip, hostname) in &p.offline {
            m.entry(*ip).or_insert_with(|| Lease {
                mac: mac.clone(),
                ip: *ip,
                hostname: hostname.clone(),
                expires: 0,
                router: Some(name.clone()),
                offline: true,
                ipv6: Vec::new(),
            });
        }
    }
    view.store(Arc::new(m));
}

/// The networks from every router's last answer, in configuration order.
fn rebuild_networks(
    order: &[String],
    parts: &HashMap<String, Polled>,
    view: &ArcSwap<Vec<Network>>,
) {
    let nets: Vec<Network> = order
        .iter()
        .filter_map(|n| parts.get(n))
        .flat_map(|p| p.networks.iter().cloned())
        .collect();
    if **view.load() != nets {
        view.store(Arc::new(nets));
    }
}

/// MAC → address from the routers' answers (Home Assistant's trackers aren't routers).
fn addresses(parts: &HashMap<String, Polled>, skip: &[String]) -> HashMap<String, Ipv4Addr> {
    let mut m = HashMap::new();
    for (name, p) in parts {
        if skip.contains(name) {
            continue;
        }
        for (_, (mac, ip, _)) in &p.seen {
            m.entry(mac.clone()).or_insert(*ip);
        }
    }
    m
}

/// The HTTP client for one router: its TLS settings (REQ: T8.2 — a console whose certificate
/// names something other than `url`'s host).
pub(crate) fn http_client(
    r: &RouterConfig,
    resolver: &Arc<dyn telltale_filter::fetch::Resolve>,
) -> Result<telltale_filter::fetch::Client, String> {
    let client = if r.tls_insecure_skip_verify {
        telltale_filter::fetch::Client::insecure(Arc::clone(resolver))
    } else if let Some(pem) = &r.tls_ca_pem {
        // REQ: API-016 (ADR-921) — the certificate entered as text: only it is trusted.
        telltale_filter::fetch::Client::with_ca_pem(Arc::clone(resolver), pem)
    } else if let Some(p) = &r.tls_ca {
        // REQ: API-016 (ADR-120) — the file's certificate is the only one trusted.
        std::fs::read_to_string(p.as_str())
            .map_err(|e| format!("{p}: {e}"))
            .and_then(|pem| telltale_filter::fetch::Client::with_ca_pem(Arc::clone(resolver), &pem))
    } else {
        telltale_filter::fetch::Client::new(Arc::clone(resolver), &[])
    }?;
    Ok(client.with_server_name(
        r.tls_server_name
            .as_ref()
            .map(telltale_config::SafeString::as_str),
    ))
}

/// REQ: API-012 (T22.3) — Home Assistant's devices, at the addresses their MACs have now
/// (re-matched every round, so a device that moves keeps its name).
fn match_home_assistant(
    ha_names: &[String],
    ha_raw: &HashMap<String, (Vec<HaDevice>, HashMap<String, Ipv4Addr>)>,
    parts: &mut HashMap<String, Polled>,
) {
    let addrs = addresses(parts, ha_names);
    for name in ha_names {
        if let Some((devices, trackers)) = ha_raw.get(name) {
            let seen = ha_seen(devices, trackers, &addrs);
            if !parts.contains_key(name.as_str()) {
                info!(router = %name, devices = devices.len(), matched = seen.len(), "Home Assistant: devices read");
            }
            parts.insert(
                name.clone(),
                Polled {
                    seen,
                    ..Polled::default()
                },
            );
        }
    }
}

/// REQ: API-016 (T23.7, ADR-922) — what each router's last read did, for the API and the Routers
/// page. Written by the poll loop, read by the API; never on the DNS path.
#[derive(Debug, Default)]
pub(crate) struct Board {
    statuses: std::sync::Mutex<HashMap<String, RouterStatus>>,
    /// REQ: DSC-009 (ADR-912) — what the inventory thread reads on top of the polls.
    share: Arc<ArcSwap<Shared>>,
}

impl Board {
    /// REQ: DSC-009 — the shared sessions and answers, for the inventory thread. Written by the
    /// poll loop only while `[discovery]` runs on this node.
    pub(crate) fn share(&self) -> Arc<ArcSwap<Shared>> {
        Arc::clone(&self.share)
    }

    /// Every router's status, by name.
    pub(crate) fn snapshot(&self) -> HashMap<String, RouterStatus> {
        self.statuses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn put(&self, name: &str, status: RouterStatus) {
        self.statuses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(name.to_owned(), status);
    }

    fn keep_only(&self, names: &[String]) {
        self.statuses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|n, _| names.iter().any(|k| k == n));
    }
}

/// REQ: API-016 (ADR-922) — the least time between two reads of one router after its settings
/// or a stored secret change (a burst of changes is one read).
const DEBOUNCE: Duration = Duration::from_secs(5);
/// REQ: API-016 — a router that failed is asked again within this (it may still be booting).
const RETRY: Duration = Duration::from_secs(15);

/// One router's read state, as the loop keeps it between rounds.
struct Slot {
    config: RouterConfig,
    /// Bumped when the settings change: a read still running for the old settings is dropped.
    generation: u64,
    /// When the next read is due.
    due: Instant,
    /// When the last read started.
    last: Option<Instant>,
    in_flight: bool,
    failing: bool,
    /// Whether a read has ever succeeded for these settings (for the log).
    read_once: bool,
    /// Why this node doesn't read the router now (`resolver pod`, or `primary`).
    skipped: Option<&'static str>,
    part: Polled,
    /// Home Assistant's raw devices and trackers (matched to addresses each round).
    ha: Option<HaRead>,
    /// REQ: DSC-009 — Home Assistant's token, shared with the inventory thread (`Keep::share`).
    ha_token: Option<Arc<zeroize::Zeroizing<String>>>,
    last_unix: Option<u64>,
    error: Option<String>,
}

/// One finished read, back on the loop.
struct Done {
    name: String,
    generation: u64,
    at_unix: u64,
    result: Result<Read, String>,
}

/// What a read produced.
enum Read {
    Routed(Polled),
    Ha(
        Vec<HaDevice>,
        HashMap<String, Ipv4Addr>,
        Arc<zeroize::Zeroizing<String>>,
    ),
}

/// Home Assistant's devices and trackers by router name.
type HaRaw = HashMap<String, (Vec<HaDevice>, HashMap<String, Ipv4Addr>)>;

/// One read of one router: its HTTP client and the kind's poll.
async fn read_one(
    r: &RouterConfig,
    resolver: &Arc<dyn telltale_filter::fetch::Resolve>,
    store: &crate::secrets::SecretStore,
    keep: Keep,
) -> Result<Read, String> {
    let client = http_client(r, resolver)?;
    match r.kind {
        RouterKind::Unifi => poll_unifi(&client, r, store, keep).await.map(Read::Routed),
        RouterKind::Opnsense => poll_opnsense(&client, r, store).await.map(Read::Routed),
        RouterKind::HomeAssistant => poll_home_assistant(&client, r, store)
            .await
            .map(|((d, t), token)| Read::Ha(d, t, token)),
    }
}

/// Whether a router with a stored credential is read here: only on the primary (or a standalone
/// node). A replica gets its names through the primary's leases (ADR-903 §1, ADR-125).
fn read_here(r: &RouterConfig, primary: bool) -> bool {
    let stored = r.api_key_ref.is_some() || r.api_secret_ref.is_some() || r.password_ref.is_some();
    !stored || primary
}

/// Brings the slots in line with the configuration: a new or changed router is due (debounced
/// when it changed), a removed one is dropped, and a router whose secret changed is read again.
fn reconcile(
    slots: &mut HashMap<String, Slot>,
    order: &mut Vec<String>,
    routers: &[RouterConfig],
    secrets_changed: bool,
    now: Instant,
    generation: &mut u64,
    board: &Board,
) {
    let names: Vec<String> = routers.iter().map(|r| r.name.to_string()).collect();
    slots.retain(|n, _| names.contains(n));
    board.keep_only(&names);
    *order = names;
    for r in routers {
        let name = r.name.to_string();
        let stored =
            r.api_key_ref.is_some() || r.api_secret_ref.is_some() || r.password_ref.is_some();
        match slots.get_mut(&name) {
            Some(s) if s.config != *r => {
                *generation += 1;
                // REQ: API-016 (review of T23.7, ADR-922) — a change to the same address keeps the
                // names until the debounced read succeeds; another address or kind is another
                // device, so its names go now.
                if s.config.url != r.url || s.config.kind != r.kind {
                    s.part = Polled::default();
                    s.ha = None;
                    s.ha_token = None;
                }
                s.config = r.clone();
                s.generation = *generation;
                s.due = debounced(s.last, now);
                s.in_flight = false;
                s.failing = false;
                s.read_once = false;
                s.error = None;
            }
            Some(s) if secrets_changed && stored => {
                s.due = debounced(s.last, now);
            }
            Some(_) => {}
            None => {
                *generation += 1;
                slots.insert(
                    name,
                    Slot {
                        config: r.clone(),
                        generation: *generation,
                        due: now,
                        last: None,
                        in_flight: false,
                        failing: false,
                        read_once: false,
                        skipped: None,
                        part: Polled::default(),
                        ha: None,
                        ha_token: None,
                        last_unix: None,
                        error: None,
                    },
                );
            }
        }
    }
}

/// `now`, or later if the router was read less than [`DEBOUNCE`] ago.
fn debounced(last: Option<Instant>, now: Instant) -> Instant {
    last.map_or(now, |l| now.max(l + DEBOUNCE))
}

/// Starts the reads that are due, each on its own task, so a slow or failing router delays no
/// other (failure isolation, ADR-922).
#[allow(clippy::too_many_arguments)] // REQ: DSC-009 - `keep` is the one new input of the loop's state.
fn start_due(
    slots: &mut HashMap<String, Slot>,
    now: Instant,
    ephemeral: bool,
    primary: bool,
    resolver: &Arc<dyn telltale_filter::fetch::Resolve>,
    store: &Arc<crate::secrets::SecretStore>,
    done: &mpsc::UnboundedSender<Done>,
    keep: Keep,
) {
    for (name, s) in slots.iter_mut() {
        // REQ: API-016 (ADR-921) — a resolver pod reads no router: it holds no secrets, and the
        // controller reads the router for the UI.
        let skip = if ephemeral {
            Some("resolver pod")
        } else if !read_here(&s.config, primary) {
            Some("primary")
        } else {
            None
        };
        if let Some(why) = skip {
            s.skipped = Some(why);
            s.part = Polled::default();
            s.ha = None;
            s.ha_token = None;
            s.due = now;
            continue;
        }
        s.skipped = None;
        if s.in_flight || s.due > now {
            continue;
        }
        s.in_flight = true;
        s.last = Some(now);
        let (r, generation, name) = (s.config.clone(), s.generation, name.clone());
        let (resolver, store, done) = (Arc::clone(resolver), Arc::clone(store), done.clone());
        tokio::spawn(async move {
            let result = read_one(&r, &resolver, &store, keep).await;
            let _ = done.send(Done {
                name,
                generation,
                at_unix: crate::pipeline::unix_now(),
                result,
            });
        });
    }
}

/// Applies one finished read to its slot (a read for settings since changed is dropped).
fn finish(slots: &mut HashMap<String, Slot>, d: Done, now: Instant) {
    let Some(s) = slots.get_mut(&d.name) else {
        return;
    };
    if s.generation != d.generation {
        return;
    }
    s.in_flight = false;
    s.last_unix = Some(d.at_unix);
    let interval = Duration::from_secs(u64::from(s.config.interval_secs.max(30)));
    let name = d.name.as_str();
    match d.result {
        Ok(Read::Routed(p)) => {
            if s.failing || !s.read_once {
                info!(router = %name, devices = p.seen.len(), offline = p.offline.len(), networks = p.networks.len(), "router integration: devices read");
            }
            if !p.notes.is_empty() && p.notes != s.part.notes {
                info!(router = %name, skipped = %p.notes.join("; "), "router integration: some optional reads didn't work (names of connected devices still come through)");
            }
            s.part = p;
            s.read_once = true;
            s.error = None;
            s.failing = false;
            s.due = now + interval;
        }
        Ok(Read::Ha(devices, trackers, token)) => {
            if s.failing || !s.read_once {
                info!(router = %name, devices = devices.len(), "Home Assistant: devices read");
            }
            s.ha = Some((devices, trackers));
            s.ha_token = Some(token);
            s.read_once = true;
            s.error = None;
            s.failing = false;
            s.due = now + interval;
        }
        Err(e) => {
            // REQ: API-014 — nor does the log.
            let e = e.replace(
                s.config.url.as_str(),
                &telltale_config::credentials::url_shown(s.config.url.as_str()),
            );
            if !s.failing {
                warn!(router = %name, error = %e, "router integration failed (keeping its last answer)");
            }
            s.error = Some(e);
            s.failing = true;
            s.due = now + interval.min(RETRY);
        }
    }
}

/// The routers' parts (for the leases and networks) and Home Assistant's raw answers, from the
/// slots in configuration order.
fn parts_of(
    slots: &HashMap<String, Slot>,
    order: &[String],
) -> (HashMap<String, Polled>, Vec<String>, HaRaw) {
    let mut parts = HashMap::new();
    let mut ha_names = Vec::new();
    let mut ha_raw = HashMap::new();
    for n in order {
        let Some(s) = slots.get(n) else {
            continue;
        };
        if s.config.kind == RouterKind::HomeAssistant {
            ha_names.push(n.clone());
            if let Some(raw) = &s.ha {
                ha_raw.insert(n.clone(), raw.clone());
            }
        } else {
            parts.insert(n.clone(), s.part.clone());
        }
    }
    (parts, ha_names, ha_raw)
}

/// REQ: DSC-009 (ADR-912) — the sessions and raw answers the inventory thread reads: each UniFi
/// router that was read here with a shared session, and each Home Assistant that was read. Empty
/// when `want` is false.
fn shared_of(slots: &HashMap<String, Slot>, order: &[String], want: bool) -> Shared {
    let mut out = Shared::default();
    if !want {
        return out;
    }
    for n in order {
        let Some(s) = slots.get(n) else {
            continue;
        };
        if s.skipped.is_some() {
            continue;
        }
        let at = s.last_unix.unwrap_or(0);
        match s.config.kind {
            RouterKind::Unifi => {
                if let Some(session) = &s.part.session {
                    out.unifi.push(SharedUnifi {
                        name: n.clone(),
                        config: s.config.clone(),
                        session: session.clone(),
                        raw: s.part.raw.clone(),
                        at,
                    });
                }
            }
            RouterKind::HomeAssistant => {
                if let (Some(raw), Some(token)) = (&s.ha, &s.ha_token) {
                    out.ha.push(SharedHa {
                        name: n.clone(),
                        config: s.config.clone(),
                        token: Arc::clone(token),
                        raw: Arc::new(raw.clone()),
                        at,
                    });
                }
            }
            RouterKind::Opnsense => {}
        }
    }
    out
}

/// Writes each router's status to the board, for the API and the Routers page.
fn publish(slots: &HashMap<String, Slot>, board: &Board) {
    for (name, s) in slots {
        // REQ: API-016 (review of T23.7) — a changed router reads `waiting` until its debounced read
        // lands (its names are the last read's, not the new settings').
        let state = if s.skipped.is_some() {
            "skipped"
        } else if s.error.is_some() {
            "failing"
        } else if !s.read_once {
            "waiting"
        } else {
            "ok"
        };
        let polled_by = match s.skipped {
            Some("resolver pod") => "skipped: resolver pod".to_owned(),
            Some(_) => "the primary".to_owned(),
            None => "this node".to_owned(),
        };
        let (devices, networks) = match &s.ha {
            Some((d, _)) if s.config.kind == RouterKind::HomeAssistant => (d.len(), 0),
            _ => (s.part.seen.len(), s.part.networks.len()),
        };
        board.put(
            name,
            RouterStatus {
                polled_by,
                state: state.to_owned(),
                last_poll: s.last_unix,
                error: s.error.clone(),
                devices: u32::try_from(devices).unwrap_or(u32::MAX),
                networks: u32::try_from(networks).unwrap_or(u32::MAX),
                interval_secs: s.config.interval_secs,
            },
        );
    }
}

/// Polls every `[[router]]` until `stop`, reading the live configuration each round (REQ:
/// API-016, T23.7, ADR-922): a router the API or UI adds, changes or removes takes effect here
/// without a restart, and a failing router keeps the others' names. Nothing here is on the query
/// path; DNS keeps its last names when a router fails.
pub(crate) async fn run(
    src: Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let resolver: Arc<dyn telltale_filter::fetch::Resolve> =
        Arc::new(telltale_filter::fetch::SystemResolver);
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<Done>();
    let mut slots: HashMap<String, Slot> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut generation: u64 = 0;
    // Set when the loop was woken by a secret or configuration change (see below).
    let mut poked = false;
    let mut last_keep = (false, false);
    let store = Arc::clone(&src.secrets);
    loop {
        let cfg = src.config.load_full();
        let now = Instant::now();
        let ephemeral = cfg.cluster.ephemeral;
        let primary = src.cluster.as_ref().is_none_or(|c| c.is_primary());
        // A stored secret that changed may be a router's credential: a wake from the secrets API
        // (or a reload) reads those routers again, debounced. The store isn't asked here: this loop
        // runs on a runtime worker, and the store's lock can be held by a load at start-up.
        let secrets_changed = std::mem::take(&mut poked);
        reconcile(
            &mut slots,
            &mut order,
            &cfg.router,
            secrets_changed,
            now,
            &mut generation,
            &src.routers,
        );
        // REQ: DSC-009 (ADR-912) — the polls keep their session (and, for `client_fields`, their
        // raw client answers) only while the inventory runs on this node.
        let own = crate::discovery::runtime::own_of(src.cluster.as_deref(), &cfg);
        let share = crate::discovery::gate::should_run(&cfg.discovery, own.me());
        let keep = Keep {
            share,
            raw_clients: share && cfg.discovery.unifi_reads.client_fields,
        };
        // A change of what to keep reads every router again (debounced), so the inventory has its
        // session and answers without waiting out a long `interval_secs`.
        if (keep.share, keep.raw_clients) != last_keep {
            last_keep = (keep.share, keep.raw_clients);
            for s in slots.values_mut() {
                s.due = s.due.min(debounced(s.last, now));
            }
        }
        start_due(
            &mut slots, now, ephemeral, primary, &resolver, &store, &done_tx, keep,
        );
        let (mut parts, ha_names, ha_raw) = parts_of(&slots, &order);
        match_home_assistant(&ha_names, &ha_raw, &mut parts);
        rebuild(&order, &parts, &src.pipeline.router_leases);
        rebuild_networks(&order, &parts, &src.pipeline.router_networks);
        publish(&slots, &src.routers);
        let shared = shared_of(&slots, &order, share);
        if !shared.same_as(&src.routers.share().load()) {
            src.routers.share().store(Arc::new(shared));
        }
        // Wake for the next read due (at most every RETRY, so a change of role is seen), a
        // finished read, a changed configuration or secret, or a stop.
        let next = slots
            .values()
            .filter(|s| !s.in_flight && s.skipped.is_none())
            .map(|s| s.due)
            .min()
            .map_or(now + RETRY, |d| d.min(now + RETRY));
        let wait = next
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(50));
        tokio::select! {
            _ = stop.changed() => return,
            Some(d) = done_rx.recv() => {
                finish(&mut slots, d, Instant::now());
                while let Ok(d) = done_rx.try_recv() {
                    finish(&mut slots, d, Instant::now());
                }
            }
            () = src.routers_changed.notified() => { poked = true; }
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// REQ: API-016 (review of T23.8, ADR-922) — whether a check may send the stored secret a draft
/// names: the saved router's own secret when its address and TLS settings are the saved ones, or
/// the one named for this router when no other router uses it.
fn ref_sent(
    reference: &str,
    named_for_router: &str,
    saved_ref: Option<&telltale_config::SafeString>,
    saved_missing: bool,
    same_target: bool,
    used_elsewhere: bool,
) -> bool {
    if same_target && saved_ref.is_some_and(|s| s.as_str() == reference) {
        return true;
    }
    // The secret the form names for this router goes only where the router was saved for it:
    // a new router (no saved entry under the draft's name), or a saved one at its own address.
    // A saved router aimed elsewhere never receives its stored key (ADR-922, NEW-1 of the review).
    reference == named_for_router && (saved_missing || same_target) && !used_elsewhere
}

/// REQ: API-016 (T23.8, ADR-922) — one read of a router draft, without saving it. A stored
/// credential is sent only when the draft's address and TLS settings are the saved ones: a draft
/// aimed elsewhere runs without it (`credential_sent: false`), so a stored key never goes to a new
/// address. Draft files are refused (ADR-921).
pub(crate) async fn check_draft(
    src: &crate::http::Sources,
    draft: Value,
) -> Result<RouterCheck, telltale_api::problem::Problem> {
    let mut draft = draft;
    if let Some(o) = draft.as_object_mut().filter(|o| !o.contains_key("name")) {
        o.insert("name".to_owned(), Value::String("draft".to_owned()));
    }
    let name = draft
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("draft")
        .to_owned();
    let mut r = crate::router_settings::parse(&name, &draft)?;
    let cfg = src.config.load_full();
    let saved = cfg.router.iter().find(|s| s.name == r.name);
    let same_target = saved.is_some_and(|s| {
        s.url == r.url
            && s.tls_ca == r.tls_ca
            && s.tls_ca_pem == r.tls_ca_pem
            && s.tls_server_name == r.tls_server_name
            && s.tls_insecure_skip_verify == r.tls_insecure_skip_verify
    });
    // REQ: API-016 (review of T23.8, ADR-922) — a stored credential goes only where it was saved
    // for: each of the draft's references is kept when it is the saved router's own secret (and
    // the address and TLS settings are the saved ones), or the secret the form names for this
    // router (`<kind>.<name>.<field>`) when no other router uses it. Any other reference is
    // dropped, so another kind's secret never goes to a console.
    let kind = match r.kind {
        telltale_config::RouterKind::Unifi => "unifi",
        telltale_config::RouterKind::Opnsense => "opnsense",
        telltale_config::RouterKind::HomeAssistant => "home_assistant",
    };
    let router_name = r.name.as_str().to_owned();
    let mut credential_sent = true;
    let references_all = telltale_config::secret_refs::references(&cfg);
    let fields: [(
        &str,
        &mut Option<telltale_config::SafeString>,
        Option<&telltale_config::SafeString>,
    ); 3] = [
        (
            "api_key",
            &mut r.api_key_ref,
            saved.and_then(|s| s.api_key_ref.as_ref()),
        ),
        (
            "api_secret",
            &mut r.api_secret_ref,
            saved.and_then(|s| s.api_secret_ref.as_ref()),
        ),
        (
            "password",
            &mut r.password_ref,
            saved.and_then(|s| s.password_ref.as_ref()),
        ),
    ];
    for (field, reference, saved_ref) in fields {
        let Some(value) = reference.as_ref().map(|s| s.as_str().to_owned()) else {
            continue;
        };
        let named = format!("{kind}.{router_name}.{field}");
        // REQ: API-016 (NEW-1/NEW-2 of the review, ADR-922) — a secret another entry of any kind
        // (router, alert destination, sink, OIDC provider, Git source) also uses is never sent
        // for this router's name.
        let used_elsewhere = references_all
            .iter()
            .any(|o| o.name == value && !(o.kind == "router" && o.entry == router_name));
        if !ref_sent(
            &value,
            &named,
            saved_ref,
            saved.is_none(),
            same_target,
            used_elsewhere,
        ) {
            *reference = None;
            credential_sent = false;
        }
    }
    let resolver: Arc<dyn telltale_filter::fetch::Resolve> =
        Arc::new(telltale_filter::fetch::SystemResolver);
    let out = match read_one(&r, &resolver, &src.secrets, Keep::default()).await {
        Ok(Read::Routed(p)) => RouterCheck {
            ok: true,
            devices: u32::try_from(p.seen.len()).unwrap_or(u32::MAX),
            networks: u32::try_from(p.networks.len()).unwrap_or(u32::MAX),
            error: None,
            credential_sent,
        },
        Ok(Read::Ha(devices, _, _)) => RouterCheck {
            ok: true,
            devices: u32::try_from(devices.len()).unwrap_or(u32::MAX),
            networks: 0,
            error: None,
            credential_sent,
        },
        Err(e) => RouterCheck {
            ok: false,
            devices: 0,
            networks: 0,
            error: Some(e.replace(
                r.url.as_str(),
                &telltale_config::credentials::url_shown(r.url.as_str()),
            )),
            credential_sent,
        },
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: T8.2 — UniFi's client list: the alias wins over the host name; clients without
    /// an IPv4 address are skipped.
    #[test]
    fn unifi_clients_named() {
        let v = serde_json::json!({"meta": {"rc": "ok"}, "data": [
            {"mac": "AA:BB:CC:00:00:01", "ip": "192.168.1.20", "hostname": "android-123", "name": "Kitchen tablet"},
            {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.1.21", "hostname": "roku"},
            {"mac": "aa:bb:cc:00:00:03", "hostname": "no-ip"},
            {"mac": "aa:bb:cc:00:00:04", "last_ip": "192.168.1.22", "name": ""}
        ]});
        assert_eq!(
            unifi_clients(&v),
            vec![
                (
                    "aa:bb:cc:00:00:01".into(),
                    Ipv4Addr::new(192, 168, 1, 20),
                    Some("Kitchen tablet".into())
                ),
                (
                    "aa:bb:cc:00:00:02".into(),
                    Ipv4Addr::new(192, 168, 1, 21),
                    Some("roku".into())
                ),
                (
                    "aa:bb:cc:00:00:04".into(),
                    Ipv4Addr::new(192, 168, 1, 22),
                    None
                ),
            ]
        );
    }

    /// REQ: T22.2 — reservations: only known clients with a fixed IP, at that address; a
    /// connected device's current address wins.
    #[test]
    fn t22_2_unifi_reservations() {
        let v = serde_json::json!({"data": [
            {"mac": "aa:bb:cc:00:00:10", "use_fixedip": true, "fixed_ip": "192.0.2.40", "name": "Printer", "last_ip": "192.0.2.99"},
            {"mac": "aa:bb:cc:00:00:11", "use_fixedip": false, "fixed_ip": "192.0.2.41", "name": "Old"},
            {"mac": "aa:bb:cc:00:00:12", "last_ip": "192.0.2.42", "hostname": "gone"},
            {"mac": "aa:bb:cc:00:00:13", "use_fixedip": true, "fixed_ip": "192.0.2.43", "hostname": "nvr"},
            {"mac": "aa:bb:cc:00:00:14", "use_fixedip": true, "fixed_ip": "not an ip"}
        ]});
        let reserved = unifi_reserved(&v);
        assert_eq!(
            reserved,
            vec![
                (
                    "aa:bb:cc:00:00:10".into(),
                    Ipv4Addr::new(192, 0, 2, 40),
                    Some("Printer".into())
                ),
                (
                    "aa:bb:cc:00:00:13".into(),
                    Ipv4Addr::new(192, 0, 2, 43),
                    Some("nvr".into())
                ),
            ]
        );
        // The NVR is connected at another address: that one stands.
        let active = vec![(
            "aa:bb:cc:00:00:13".to_owned(),
            Ipv4Addr::new(192, 0, 2, 77),
            Some("nvr".to_owned()),
        )];
        let merged = unifi_merge(active, reserved);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].1, Ipv4Addr::new(192, 0, 2, 77));
        assert_eq!(merged[1].1, Ipv4Addr::new(192, 0, 2, 40));
    }

    /// REQ: API-013 (T22.2) — UniFi's networks: subnet from the gateway's address, VLAN only
    /// when enabled, the DHCP pool only when DHCP is on, no WAN or VPN.
    #[test]
    fn api_013_unifi_networks() {
        let v = serde_json::json!({"data": [
            {"name": "Default", "purpose": "corporate", "ip_subnet": "192.168.1.1/24", "dhcpd_enabled": true, "dhcpd_start": "192.168.1.6", "dhcpd_stop": "192.168.1.254", "domain_name": "home.arpa"},
            {"name": "IoT", "purpose": "corporate", "ip_subnet": "192.168.20.1/24", "vlan_enabled": true, "vlan": "20", "dhcpd_enabled": false, "dhcpd_start": "192.168.20.6"},
            {"name": "Cameras", "purpose": "corporate", "ip_subnet": "10.30.0.1/22", "vlan": 30},
            {"name": "Internet", "purpose": "wan", "ip_subnet": "203.0.113.2/30"},
            {"name": "VPN", "purpose": "remote-user-vpn", "ip_subnet": "10.30.3.1/24"},
            {"name": "Trunk", "purpose": "vlan-only", "vlan": 40},
            {"name": "Off", "purpose": "corporate", "ip_subnet": "192.168.50.1/24", "vlan_enabled": false, "vlan": 50}
        ]});
        let n = unifi_networks(&v, "udm");
        let names: Vec<&str> = n.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["Cameras", "Default", "IoT", "Off"]);
        let cams = &n[0];
        assert_eq!(
            (cams.subnet, cams.prefix, cams.vlan, cams.gateway),
            (
                Ipv4Addr::new(10, 30, 0, 0),
                22,
                Some(30),
                Some(Ipv4Addr::new(10, 30, 0, 1))
            )
        );
        assert!(in_network(
            cams.subnet,
            cams.prefix,
            Ipv4Addr::new(10, 30, 3, 200)
        ));
        assert!(!in_network(
            cams.subnet,
            cams.prefix,
            Ipv4Addr::new(10, 30, 4, 1)
        ));
        let def = &n[1];
        assert_eq!(def.vlan, None);
        assert_eq!(def.dhcp_start, Some(Ipv4Addr::new(192, 168, 1, 6)));
        assert_eq!(def.domain.as_deref(), Some("home.arpa"));
        assert_eq!(def.router, "udm");
        assert_eq!((n[2].vlan, n[2].dhcp_start), (Some(20), None));
        assert_eq!(n[3].vlan, None, "VLAN off");
    }

    /// REQ: T8.2 — OPNsense leases, whichever DHCP server answered.
    #[test]
    fn opnsense_leases_any_backend() {
        let isc = serde_json::json!({"rows": [{"address": "10.0.0.5", "mac": "00:11:22:33:44:55", "hostname": "nas"}]});
        let kea = serde_json::json!({"rows": [{"address": "10.0.0.6", "hwaddr": "00:11:22:33:44:66", "hostname": "*"}]});
        assert_eq!(
            opnsense_leases(&isc),
            vec![(
                "00:11:22:33:44:55".into(),
                Ipv4Addr::new(10, 0, 0, 5),
                Some("nas".into())
            )]
        );
        assert_eq!(
            opnsense_leases(&kea),
            vec![("00:11:22:33:44:66".into(), Ipv4Addr::new(10, 0, 0, 6), None)]
        );
        assert_eq!(base64(b"key:secret"), "a2V5OnNlY3JldA==");
    }

    /// REQ: API-012 (T22.3) — Home Assistant's answer: user-given names are marked curated,
    /// MACs normalized, devices without a name or MAC skipped, trackers' addresses read.
    #[test]
    fn api_012_home_assistant_devices() {
        let v = serde_json::json!({
            "devices": [
                {"name_by_user": "Porch light", "name": "Shelly Plus 1", "macs": ["A8:03:2A:00:00:01"], "area": "Porch"},
                {"name_by_user": "", "name": "Living Room TV", "macs": ["a8-03-2a-00-00-02", "a8:03:2a:00:00:03"], "area": ""},
                {"name_by_user": "", "name": "", "macs": ["a8:03:2a:00:00:04"]},
                {"name_by_user": "No MAC", "name": "x", "macs": []},
                {"name_by_user": "Bad MAC", "name": "x", "macs": ["zigbee-1234"]}
            ],
            "trackers": [
                {"mac": "A8:03:2A:00:00:03", "ip": "192.0.2.33"},
                {"mac": "a8:03:2a:00:00:09", "ip": "not-an-ip"}
            ]
        });
        let (devices, trackers) = ha_devices(&v);
        assert_eq!(
            devices,
            vec![
                HaDevice {
                    macs: vec!["a8:03:2a:00:00:01".into()],
                    name: "Porch light".into(),
                    curated: true
                },
                HaDevice {
                    macs: vec!["a8:03:2a:00:00:02".into(), "a8:03:2a:00:00:03".into()],
                    name: "Living Room TV".into(),
                    curated: false
                },
            ]
        );
        assert_eq!(
            trackers,
            HashMap::from([(
                "a8:03:2a:00:00:03".to_owned(),
                Ipv4Addr::new(192, 0, 2, 33)
            )])
        );
        // The porch light's address comes from a router; the TV's second MAC from HA's own
        // tracker; its first MAC has no address anywhere and is skipped.
        let addrs = HashMap::from([(
            "a8:03:2a:00:00:01".to_owned(),
            Ipv4Addr::new(192, 0, 2, 31),
        )]);
        let seen = ha_seen(&devices, &trackers, &addrs);
        assert_eq!(
            seen,
            vec![
                (
                    RANK_CURATED,
                    (
                        "a8:03:2a:00:00:01".into(),
                        Ipv4Addr::new(192, 0, 2, 31),
                        Some("Porch light".into())
                    )
                ),
                (
                    RANK_INTEGRATION,
                    (
                        "a8:03:2a:00:00:03".into(),
                        Ipv4Addr::new(192, 0, 2, 33),
                        Some("Living Room TV".into())
                    )
                ),
            ]
        );
        assert!(HA_TEMPLATE.contains("device_attr(d, 'connections')"));
    }

    /// REQ: ADR-902 — one address named by several sources: a curated Home Assistant name
    /// wins, then routers in configuration order, then an integration's name; a better source
    /// without a name doesn't hide a worse one's.
    #[test]
    fn adr_902_lease_precedence() {
        let ip = |d: u8| Ipv4Addr::new(192, 168, 10, d);
        let mac = |d: u8| format!("aa:bb:cc:00:00:{d:02x}");
        let order = vec!["udm".to_owned(), "opn".to_owned(), "ha".to_owned()];
        let mut parts = HashMap::new();
        parts.insert(
            "udm".to_owned(),
            Polled {
                seen: vec![
                    (
                        RANK_ROUTER,
                        (mac(1), ip(1), Some("shellyplus1-a8032a".into())),
                    ),
                    (RANK_ROUTER, (mac(2), ip(2), Some("lg-webos-tv".into()))),
                    (RANK_ROUTER, (mac(3), ip(3), None)),
                ],
                ..Polled::default()
            },
        );
        parts.insert(
            "opn".to_owned(),
            Polled {
                seen: vec![
                    (RANK_ROUTER, (mac(2), ip(2), Some("tv-from-opn".into()))),
                    (RANK_ROUTER, (mac(3), ip(3), Some("nas".into()))),
                ],
                ..Polled::default()
            },
        );
        parts.insert(
            "ha".to_owned(),
            Polled {
                seen: vec![
                    (RANK_CURATED, (mac(1), ip(1), Some("Porch light".into()))),
                    (
                        RANK_INTEGRATION,
                        (mac(2), ip(2), Some("LG webOS TV OLED55".into())),
                    ),
                ],
                ..Polled::default()
            },
        );
        let view = ArcSwap::from_pointee(Leases::new());
        rebuild(&order, &parts, &view);
        let v = view.load();
        let name = |d: u8| v.get(&ip(d)).and_then(|l| l.hostname.clone());
        let via = |d: u8| v.get(&ip(d)).and_then(|l| l.router.clone());
        assert_eq!(name(1).as_deref(), Some("Porch light"));
        assert_eq!(via(1).as_deref(), Some("ha"));
        assert_eq!(
            name(2).as_deref(),
            Some("lg-webos-tv"),
            "first router beats the integration"
        );
        assert_eq!(name(3).as_deref(), Some("nas"), "a name beats no name");
        assert_eq!(via(3).as_deref(), Some("opn"));
    }

    /// REQ: DNS-023 (T24.8, ADR-983) — UniFi's `ipv6_addresses`: usable ones only (no
    /// link-local), by MAC; a row without the field, or with junk in it, gives none.
    #[test]
    fn dns_023_unifi_reports_ipv6_addresses() {
        let v = serde_json::json!({"data": [
            {"mac": "AA:BB:CC:00:00:01", "ip": "192.168.1.20", "ipv6_addresses":
                ["fe80::1", "2001:db8:1::20", "fd00:1::20", "not an address", "::1"]},
            {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.1.21"},
            {"mac": "aa:bb:cc:00:00:03", "ip": "192.168.1.22", "ipv6_addresses": "oops"}
        ]});
        let got = unifi_ipv6(&v);
        let a = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        assert_eq!(
            got,
            vec![
                ("aa:bb:cc:00:00:01".to_owned(), a("2001:db8:1::20")),
                ("aa:bb:cc:00:00:01".to_owned(), a("fd00:1::20")),
            ]
        );
    }

    /// REQ: DNS-023 (T24.8, ADR-983) — a device's IPv6 addresses ride on the lease with its MAC,
    /// whichever router named it (a Home Assistant name takes UniFi's addresses), sorted and
    /// capped; an offline client gets none.
    #[test]
    fn dns_023_ipv6_addresses_ride_on_the_lease() {
        let a = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        let mac = |n: u8| format!("aa:bb:cc:00:00:{n:02x}");
        let ip = |n: u8| Ipv4Addr::new(192, 168, 1, n);
        let order = vec!["udm".to_owned(), "ha".to_owned()];
        let mut parts: HashMap<String, Polled> = HashMap::new();
        parts.insert(
            "udm".to_owned(),
            Polled {
                seen: vec![
                    (RANK_ROUTER, (mac(1), ip(1), Some("tablet".into()))),
                    (RANK_ROUTER, (mac(2), ip(2), None)),
                ],
                offline: vec![(mac(3), ip(3), Some("old-phone".into()))],
                v6: vec![
                    (mac(1), a("2001:db8::9")),
                    (mac(1), a("2001:db8::1")),
                    (mac(1), a("2001:db8::1")),
                    (mac(2), a("fd00::2")),
                    (mac(2), a("fd00::3")),
                    (mac(2), a("fd00::4")),
                    (mac(2), a("fd00::5")),
                    (mac(2), a("fd00::6")),
                    (mac(3), a("fd00::7")),
                ],
                ..Polled::default()
            },
        );
        parts.insert(
            "ha".to_owned(),
            Polled {
                seen: vec![(RANK_CURATED, (mac(2), ip(2), Some("Porch light".into())))],
                ..Polled::default()
            },
        );
        let view = ArcSwap::from_pointee(Leases::new());
        rebuild(&order, &parts, &view);
        let v = view.load();
        assert_eq!(
            v[&ip(1)].ipv6,
            vec![a("2001:db8::1"), a("2001:db8::9")],
            "sorted, once each"
        );
        assert_eq!(v[&ip(2)].hostname.as_deref(), Some("Porch light"));
        assert_eq!(
            v[&ip(2)].ipv6,
            vec![a("fd00::2"), a("fd00::3"), a("fd00::4"), a("fd00::5")],
            "the HA-named device takes UniFi's addresses, capped at four"
        );
        assert!(
            v[&ip(3)].offline && v[&ip(3)].ipv6.is_empty(),
            "offline: none"
        );
    }

    /// REQ: T8.2 (ADR-166) — UniFi's offline known clients keep their names: the history (a bare
    /// array) and `rest/user` give the named ones, most recently seen first; a connected client
    /// keeps its address and only takes a name it lacks; an offline client never takes an address
    /// a connected one holds, and a MAC counts once.
    #[test]
    fn t8_2_offline_known_names_and_held_addresses() {
        let mut seen = unifi_clients(&serde_json::json!({"data": [
            {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.20", "name": "Kitchen tablet"},
            {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.1.21"}
        ]}));
        let history = serde_json::json!([
            {"mac": "aa:bb:cc:00:00:10", "last_ip": "192.168.1.30", "hostname": "old-laptop", "last_seen": 100},
            {"mac": "AA:BB:CC:00:00:11", "last_ip": "192.168.1.30", "name": "Work laptop", "last_seen": 200},
            {"mac": "aa:bb:cc:00:00:12", "last_ip": "192.168.1.20", "name": "Old phone", "last_seen": 300},
            {"mac": "aa:bb:cc:00:00:13", "last_ip": "192.168.1.31", "last_seen": 400},
            {"mac": "aa:bb:cc:00:00:02", "last_ip": "192.168.1.21", "name": "Living room TV"},
            {"hostname": "phone", "fixed_ip": "192.168.1.62", "use_fixedip": false, "last_ip": "192.168.1.63",
             "mac": "aa:bb:cc:00:00:17", "name": "Spare phone", "last_seen": 150, "status": "offline"}
        ]);
        let users = serde_json::json!({"meta": {"rc": "ok"}, "data": [
            {"mac": "aa:bb:cc:00:00:14", "fixed_ip": "192.168.1.40", "use_fixedip": true, "name": "Printer"},
            {"mac": "aa:bb:cc:00:00:15", "name": "No address"},
            {"mac": "aa:bb:cc:00:00:16", "fixed_ip": "192.168.1.41", "use_fixedip": false, "name": "Reservation off"}
        ]});
        let mut known = unifi_known(&history, 0);
        known.extend(unifi_known(&users, 0));
        unifi_fill_names(&mut seen, &known);
        assert_eq!(seen[1].2.as_deref(), Some("Living room TV"));
        assert_eq!(seen[0].2.as_deref(), Some("Kitchen tablet"));
        assert_eq!(
            unifi_offline(&seen, known),
            vec![
                (
                    "aa:bb:cc:00:00:11".into(),
                    Ipv4Addr::new(192, 168, 1, 30),
                    Some("Work laptop".into())
                ),
                (
                    "aa:bb:cc:00:00:17".into(),
                    Ipv4Addr::new(192, 168, 1, 63),
                    Some("Spare phone".into())
                ),
                (
                    "aa:bb:cc:00:00:14".into(),
                    Ipv4Addr::new(192, 168, 1, 40),
                    Some("Printer".into())
                ),
            ]
        );
    }

    /// REQ: T8.2 (ADR-166) — `offline_days`: a row last seen before the window is dropped, one with
    /// no date stays, the most recently seen come first, and no more than `OFFLINE_MAX` are kept.
    #[test]
    fn t8_2_known_window_and_cap() {
        let rows = serde_json::json!([
            {"mac": "aa:bb:cc:00:01:01", "last_ip": "10.0.1.1", "name": "recent", "last_seen": 2_000_000},
            {"mac": "aa:bb:cc:00:01:02", "last_ip": "10.0.1.2", "name": "old", "last_seen": 1_000_000},
            {"mac": "aa:bb:cc:00:01:03", "last_ip": "10.0.1.3", "name": "undated"},
            {"mac": "aa:bb:cc:00:01:04", "last_ip": "10.0.1.4", "name": "newest", "last_seen": 2_500_000},
        ]);
        let names = |s: Seen| s.into_iter().filter_map(|d| d.2).collect::<Vec<_>>();
        assert_eq!(
            names(unifi_known(&rows, 0)),
            ["newest", "recent", "old", "undated"]
        );
        assert_eq!(
            names(unifi_known(&rows, 1_500_000)),
            ["newest", "recent", "undated"]
        );
        let many: Vec<Value> = (0..2 * OFFLINE_MAX)
            .map(|i| {
                serde_json::json!({
                    "mac": format!("02:00:00:00:{:02x}:{:02x}", i / 256, i % 256),
                    "last_ip": format!("10.1.{}.{}", i / 250, i % 250 + 1),
                    "name": format!("c{i}"),
                    "last_seen": 1_000 + i,
                })
            })
            .collect();
        let known = unifi_known(&Value::Array(many), 0);
        assert_eq!(known.len(), OFFLINE_MAX);
        let newest = format!("c{}", 2 * OFFLINE_MAX - 1);
        assert_eq!(known[0].2.as_deref(), Some(newest.as_str()));
    }

    /// REQ: T8.2 (ADR-166) — the offline clients are capped, and a device or address the
    /// connected ones hold is never offered again.
    #[test]
    fn t8_2_offline_is_capped_and_skips_held_devices() {
        let ip = |n: u32| Ipv4Addr::from(0x0a00_0000 + n);
        let held: Seen = vec![("aa:aa:aa:00:00:01".into(), ip(1), None)];
        let mut known: Seen = vec![("aa:aa:aa:00:00:01".into(), ip(1), Some("TV".into()))];
        known.extend((2..3000_u32).map(|n| {
            (
                format!("bb:00:00:00:{:02x}:{:02x}", n / 256, n % 256),
                ip(n),
                Some(format!("off{n}")),
            )
        }));
        let offline = unifi_offline(&held, known);
        assert_eq!(offline.len(), OFFLINE_MAX);
        assert_eq!(offline[0].2.as_deref(), Some("off2"));
    }

    /// REQ: T8.2 (ADR-166) — an offline client names an address, marked as offline, only where no
    /// router reports a connected device; connected ones are not marked.
    #[test]
    fn t8_2_offline_clients_never_replace_a_connected_device() {
        let dev = |mac: &str, ip: [u8; 4], name: &str| -> Entry {
            (mac.to_owned(), Ipv4Addr::from(ip), Some(name.to_owned()))
        };
        let mut parts = HashMap::new();
        parts.insert(
            "udm".to_owned(),
            Polled {
                seen: vec![(RANK_ROUTER, dev("aa:00:00:00:00:01", [10, 0, 0, 5], "Desk"))],
                offline: vec![dev("aa:00:00:00:00:02", [10, 0, 0, 9], "Old phone")],
                ..Polled::default()
            },
        );
        parts.insert(
            "other".to_owned(),
            Polled {
                offline: vec![dev("aa:00:00:00:00:03", [10, 0, 0, 5], "Gone laptop")],
                ..Polled::default()
            },
        );
        let order = ["udm".to_owned(), "other".to_owned()];
        let view = ArcSwap::from_pointee(Leases::new());
        rebuild(&order, &parts, &view);
        let leases = view.load_full();
        let desk = &leases[&Ipv4Addr::new(10, 0, 0, 5)];
        assert_eq!(
            (desk.hostname.as_deref(), desk.offline),
            (Some("Desk"), false)
        );
        let phone = &leases[&Ipv4Addr::new(10, 0, 0, 9)];
        assert_eq!(
            (phone.hostname.as_deref(), phone.offline),
            (Some("Old phone"), true)
        );
    }

    /// REQ: T8.2 (ADR-166, ADR-902) — two routers' offline clients on one address: the router
    /// earlier in configuration order names it, every time, and the lease says which router.
    #[test]
    fn t8_2_offline_name_follows_configuration_order() {
        let dev = |mac: &str, name: &str| -> Entry {
            (
                mac.to_owned(),
                Ipv4Addr::new(10, 0, 0, 77),
                Some(name.to_owned()),
            )
        };
        let mut parts = HashMap::new();
        parts.insert(
            "ha".to_owned(),
            Polled {
                offline: vec![dev("aa:00:00:00:00:0a", "From ha")],
                ..Polled::default()
            },
        );
        parts.insert(
            "udm".to_owned(),
            Polled {
                offline: vec![dev("aa:00:00:00:00:0b", "From udm")],
                ..Polled::default()
            },
        );
        let order = ["udm".to_owned(), "ha".to_owned()];
        for _ in 0..16 {
            let view = ArcSwap::from_pointee(Leases::new());
            rebuild(&order, &parts, &view);
            let leases = view.load_full();
            let l = &leases[&Ipv4Addr::new(10, 0, 0, 77)];
            assert_eq!(l.hostname.as_deref(), Some("From udm"));
            assert_eq!(l.router.as_deref(), Some("udm"));
            assert!(l.offline);
        }
    }
}

#[cfg(test)]
#[path = "routers_tests.rs"]
mod routers_tests;

/// Builds a `Bearer` header value marked sensitive (never shown by `Debug`), with the intermediate
/// text held in a zeroizing buffer. REQ: DSC-009
pub(crate) fn bearer_header(
    token: &str,
) -> Result<http::HeaderValue, http::header::InvalidHeaderValue> {
    let text = zeroize::Zeroizing::new(format!("Bearer {token}"));
    let mut v = http::HeaderValue::from_str(text.as_str())?;
    v.set_sensitive(true);
    Ok(v)
}

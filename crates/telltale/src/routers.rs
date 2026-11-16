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

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use telltale_config::{RouterConfig, RouterKind};
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
}

impl Polled {
    fn routed(seen: Seen) -> Self {
        Self {
            seen: seen.into_iter().map(|s| (RANK_ROUTER, s)).collect(),
            ..Self::default()
        }
    }
}

fn secret(path: Option<&telltale_config::SafeString>) -> Result<Option<String>, String> {
    path.map(|p| {
        std::fs::read_to_string(p.as_str())
            .map(|s| s.trim().to_owned())
            .map_err(|e| format!("{}: {e}", p.as_str()))
    })
    .transpose()
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(
                    T[usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0)],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `AA-BB-CC-00-00-01` → `aa:bb:cc:00:00:01`.
fn mac_key(mac: &str) -> String {
    mac.trim().to_ascii_lowercase().replace('-', ":")
}

/// One HTTP exchange; the JSON body and the response headers.
async fn call(
    client: &telltale_filter::fetch::Client,
    req: http::Request<Vec<u8>>,
) -> Result<(http::StatusCode, http::HeaderMap, Value), String> {
    let url = req.uri().to_string();
    let resp = tokio::time::timeout(Duration::from_secs(15), client.request(req, MAX_ANSWER))
        .await
        .map_err(|_| format!("{url}: timed out"))?
        .map_err(|e| format!("{url}: {}", e.message))?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body();
    let v = serde_json::from_slice(&body).unwrap_or(Value::Null);
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
fn first_str(v: &Value, keys: &[&str]) -> Option<String> {
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
enum UnifiAuth {
    Key(String),
    Cookie(String),
}

impl UnifiAuth {
    fn get(&self, url: &str) -> Result<http::Request<Vec<u8>>, String> {
        let b = http::Request::get(url).header("accept", "application/json");
        let b = match self {
            Self::Key(k) => b.header("x-api-key", k.as_str()),
            Self::Cookie(c) => b.header("cookie", c.as_str()),
        };
        b.body(Vec::new()).map_err(|e| e.to_string())
    }
}

/// The active clients (required), then the reservations and the networks (each optional: a
/// console or key that can't read them still names the connected clients).
async fn read_unifi(
    client: &telltale_filter::fetch::Client,
    auth: &UnifiAuth,
    api: &str,
    router: &str,
) -> Result<Polled, String> {
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
    let reserved = optional(
        "reservations (rest/user)",
        call(client, auth.get(&format!("{api}/rest/user"))?).await,
    )
    .map(|v| unifi_reserved(&v))
    .unwrap_or_default();
    let networks = optional(
        "networks (rest/networkconf)",
        call(client, auth.get(&format!("{api}/rest/networkconf"))?).await,
    )
    .map(|v| unifi_networks(&v, router))
    .unwrap_or_default();
    Ok(Polled {
        networks,
        notes,
        ..Polled::routed(unifi_merge(active, reserved))
    })
}

/// One poll of a UniFi console or Network application.
async fn poll_unifi(
    client: &telltale_filter::fetch::Client,
    c: &RouterConfig,
) -> Result<Polled, String> {
    let base = c.url.trim_end_matches('/');
    let site = c.site.as_deref().unwrap_or("default");
    if let Some(key) = secret(c.api_key_file.as_ref())? {
        let api = format!("{base}/proxy/network/api/s/{site}");
        return read_unifi(client, &UnifiAuth::Key(key), &api, &c.name).await;
    }
    let user = c
        .username
        .as_deref()
        .ok_or("set api_key_file, or username and password_file")?;
    let pass = secret(c.password_file.as_ref())?.ok_or("set password_file")?;
    let body =
        serde_json::json!({"username": user, "password": pass, "remember": false}).to_string();
    // UniFi OS consoles first, then the classic Network application.
    for (login, prefix) in [("/api/auth/login", "/proxy/network"), ("/api/login", "")] {
        let req = http::Request::post(format!("{base}{login}"))
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .body(body.clone().into_bytes())
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
        let api = format!("{base}{prefix}/api/s/{site}");
        return read_unifi(client, &UnifiAuth::Cookie(cookies(&headers)), &api, &c.name).await;
    }
    Err(format!(
        "{base}: neither a UniFi OS console nor a Network application"
    ))
}

/// One poll of an OPNsense box.
async fn poll_opnsense(
    client: &telltale_filter::fetch::Client,
    c: &RouterConfig,
) -> Result<Polled, String> {
    let base = c.url.trim_end_matches('/');
    let key = secret(c.api_key_file.as_ref())?.ok_or("set api_key_file")?;
    let sec = secret(c.api_secret_file.as_ref())?.ok_or("set api_secret_file")?;
    let auth = format!("Basic {}", base64(format!("{key}:{sec}").as_bytes()));
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
) -> Result<(Vec<HaDevice>, HashMap<String, Ipv4Addr>), String> {
    let base = c.url.trim_end_matches('/');
    let token = secret(c.api_key_file.as_ref())?.ok_or("set api_key_file")?;
    let url = format!("{base}/api/template");
    let body = serde_json::json!({ "template": HA_TEMPLATE }).to_string();
    let req = http::Request::post(url.as_str())
        .header("authorization", format!("Bearer {token}"))
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
    Ok(ha_devices(&v))
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
fn http_client(
    r: &RouterConfig,
    resolver: &Arc<dyn telltale_filter::fetch::Resolve>,
) -> Result<telltale_filter::fetch::Client, String> {
    let client = if r.tls_insecure_skip_verify {
        telltale_filter::fetch::Client::insecure(Arc::clone(resolver))
    } else if let Some(p) = &r.tls_ca {
        telltale_filter::fetch::Client::with_ca_file(Arc::clone(resolver), p.as_str())
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

/// Polls every `[[router]]` until `stop`. `resolver_pod`: a Helm resolver pod, which has the
/// routers' settings but not their key files (ADR-120), logs its failures as info; the
/// controller, which serves the names in the UI, warns.
pub(crate) async fn run(
    routers: Vec<RouterConfig>,
    view: Arc<ArcSwap<Leases>>,
    networks: Arc<ArcSwap<Vec<Network>>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    resolver_pod: bool,
) {
    if routers.is_empty() {
        return;
    }
    let resolver: Arc<dyn telltale_filter::fetch::Resolve> =
        Arc::new(telltale_filter::fetch::SystemResolver);
    let order: Vec<String> = routers.iter().map(|r| r.name.to_string()).collect();
    let ha_names: Vec<String> = routers
        .iter()
        .filter(|r| r.kind == RouterKind::HomeAssistant)
        .map(|r| r.name.to_string())
        .collect();
    // Routers first, so Home Assistant's devices find the addresses their MACs have now.
    let mut polling: Vec<&RouterConfig> = routers.iter().collect();
    polling.sort_by_key(|r| r.kind == RouterKind::HomeAssistant);
    let mut parts: HashMap<String, Polled> = HashMap::new();
    let mut ha_raw: HashMap<String, (Vec<HaDevice>, HashMap<String, Ipv4Addr>)> = HashMap::new();
    let mut failing: HashMap<String, bool> = HashMap::new();
    let interval = routers
        .iter()
        .map(|r| r.interval_secs.max(30))
        .min()
        .unwrap_or(300);
    loop {
        for r in &polling {
            // Like a failed poll, a TLS setting that can't load (a node without the CA file, ADR-120)
            // is logged once until it works.
            let client = match http_client(r, &resolver) {
                Ok(c) => c,
                Err(e) => {
                    if !failing.get(r.name.as_str()).copied().unwrap_or(false) {
                        if resolver_pod {
                            info!(router = %r.name, error = %e, "router integration: TLS settings (not on this resolver pod; the controller reads the router)");
                        } else {
                            warn!(router = %r.name, error = %e, "router integration: TLS settings");
                        }
                    }
                    failing.insert(r.name.to_string(), true);
                    continue;
                }
            };
            let result = match r.kind {
                RouterKind::Unifi => poll_unifi(&client, r).await,
                RouterKind::Opnsense => poll_opnsense(&client, r).await,
                RouterKind::HomeAssistant => poll_home_assistant(&client, r).await.map(|raw| {
                    ha_raw.insert(r.name.to_string(), raw);
                    Polled::default()
                }),
            };
            let was_failing = failing.get(r.name.as_str()).copied().unwrap_or(false);
            match result {
                Ok(polled) => {
                    if r.kind != RouterKind::HomeAssistant {
                        let noted = parts
                            .get(r.name.as_str())
                            .is_some_and(|p| p.notes == polled.notes);
                        if was_failing || !parts.contains_key(r.name.as_str()) {
                            info!(router = %r.name, devices = polled.seen.len(), networks = polled.networks.len(), "router integration: devices read");
                        }
                        // REQ: T22.2 — reservations and networks are optional reads; say once
                        // when they stop (or start) working, rather than every poll.
                        if !noted && !polled.notes.is_empty() {
                            info!(router = %r.name, skipped = %polled.notes.join("; "), "router integration: some optional reads didn't work (names of connected devices still come through)");
                        }
                        parts.insert(r.name.to_string(), polled);
                    }
                    failing.insert(r.name.to_string(), false);
                }
                Err(e) => {
                    if !was_failing {
                        if resolver_pod {
                            info!(router = %r.name, error = %e, "router integration failed on this resolver pod (the controller reads the router)");
                        } else {
                            warn!(router = %r.name, error = %e, "router integration failed (keeping its last answer)");
                        }
                    }
                    failing.insert(r.name.to_string(), true);
                }
            }
        }
        match_home_assistant(&ha_names, &ha_raw, &mut parts);
        rebuild(&order, &parts, &view);
        rebuild_networks(&order, &parts, &networks);
        // A router that failed (it may still be booting) is asked again soon.
        let wait = if failing.values().any(|f| *f) {
            interval.min(15)
        } else {
            interval
        };
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(Duration::from_secs(u64::from(wait))) => {}
        }
    }
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
}

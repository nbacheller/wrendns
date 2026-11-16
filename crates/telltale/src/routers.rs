//! Router integrations (REQ: API-010 naming sources, M8 "router integrations"; T8.2): device
//! names and addresses read from the router's DHCP, so devices show up by name without
//! TelltaleDNS running DHCP itself.
//! - **UniFi** (UniFi OS consoles: UDM, UCG, Cloud Key Gen2+; and the classic Network
//!   application): the active clients (`stat/sta`), then the offline clients it still knows
//!   (v2 `clients/history`, `rest/user`), named by their UniFi alias, else their host name.
//!   An API key (`X-API-KEY`), or a local username and password.
//! - **OPNsense**: the DHCP leases (Dnsmasq, Kea, or ISC, whichever the box runs), with an
//!   API key and secret.
//!
//! Polled every `interval_secs`; the result replaces that router's part of the lease view
//! the naming falls back to (after configured device names and TelltaleDNS's own DHCP).
//! Never on the DNS path; a router that's down keeps its last answer and is logged.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use serde_json::Value;
use telltale_config::{RouterConfig, RouterKind};
use tracing::{debug, info, warn};

use crate::devices::{Lease, Leases};

/// Most bytes one answer may have.
const MAX_ANSWER: u64 = 16 << 20;

/// What a router reported, one entry per device.
pub(crate) type Seen = Vec<Device>;

/// One device a router reported: (MAC, IPv4 address, name).
pub(crate) type Device = (String, Ipv4Addr, Option<String>);

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

/// The client objects of a UniFi answer: `data` in the classic API, a bare array in v2.
fn unifi_rows(v: &Value) -> &[Value] {
    v.get("data")
        .and_then(Value::as_array)
        .or_else(|| v.as_array())
        .map_or(&[], Vec::as_slice)
}

/// One UniFi client object: its MAC, IPv4 address (current, else last, else reserved), and
/// name (the UniFi alias, else the host name).
fn unifi_client(c: &Value) -> Option<Device> {
    let mac = c.get("mac")?.as_str()?.to_ascii_lowercase();
    // A `fixed_ip` counts only while the reservation is on (`use_fixedip`); UniFi keeps the
    // field after it's turned off.
    let fixed = c
        .get("use_fixedip")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let ip: Ipv4Addr = ["ip", "last_ip", "fixed_ip"]
        .iter()
        .filter(|k| **k != "fixed_ip" || fixed)
        .filter_map(|k| c.get(*k).and_then(Value::as_str))
        .find_map(|s| s.parse().ok())?;
    let name = ["name", "hostname"]
        .iter()
        .filter_map(|k| c.get(*k).and_then(Value::as_str))
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_owned);
    Some((mac, ip, name))
}

/// UniFi clients in a `stat/sta` (or `rest/user`) answer.
pub(crate) fn unifi_clients(v: &Value) -> Seen {
    unifi_rows(v).iter().filter_map(unifi_client).collect()
}

/// UniFi's known clients that aren't connected now (v2 `clients/history`, `rest/user`): only
/// those with a name, the most recently seen first.
pub(crate) fn unifi_known(v: &Value) -> Seen {
    let mut rows: Vec<(u64, Device)> = unifi_rows(v)
        .iter()
        .filter_map(|c| {
            let seen = c.get("last_seen").and_then(Value::as_u64).unwrap_or(0);
            let client = unifi_client(c)?;
            client.2.is_some().then_some((seen, client))
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.0));
    rows.into_iter().map(|(_, c)| c).collect()
}

/// REQ: T8.2 — the connected clients, then the known ones UniFi has names for, so an offline
/// device's queries still show its name. A connected client keeps its address; a known one
/// only names it when it has none, and adds a device only for an address no one else holds
/// (an offline device's last address may since have gone to another one).
pub(crate) fn unifi_merge(mut active: Seen, known: Seen) -> Seen {
    let mut macs: HashMap<String, usize> = active
        .iter()
        .enumerate()
        .map(|(i, c)| (c.0.clone(), i))
        .collect();
    let mut ips: std::collections::HashSet<Ipv4Addr> = active.iter().map(|c| c.1).collect();
    for (mac, ip, name) in known {
        if let Some(&i) = macs.get(&mac) {
            if let Some(c) = active.get_mut(i)
                && c.2.is_none()
            {
                c.2 = name;
            }
            continue;
        }
        if !ips.insert(ip) {
            continue;
        }
        macs.insert(mac.clone(), active.len());
        active.push((mac, ip, name));
    }
    active
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

/// How to reach a UniFi Network API once signed in: the path prefix (`/proxy/network` on
/// UniFi OS consoles) and the header that authenticates (`x-api-key`, or the login cookie).
struct UnifiSession<'a> {
    base: &'a str,
    site: &'a str,
    prefix: &'static str,
    auth: (&'static str, String),
}

impl UnifiSession<'_> {
    /// `GET` one path under the site; the JSON answer, or why not.
    async fn get(
        &self,
        client: &telltale_filter::fetch::Client,
        path: &str,
    ) -> Result<Value, String> {
        let url = format!("{}{}{path}", self.base, self.prefix).replace("{site}", self.site);
        let req = http::Request::get(url.as_str())
            .header(self.auth.0, self.auth.1.as_str())
            .header("accept", "application/json")
            .body(Vec::new())
            .map_err(|e| e.to_string())?;
        let (status, _, v) = call(client, req).await?;
        if status.is_success() {
            Ok(v)
        } else {
            Err(format!("{url}: HTTP {status}"))
        }
    }

    /// The connected clients (`stat/sta`), then the known clients that are offline, so their
    /// names still show. The known clients are best effort: a console that can't list them
    /// (an older Network application has no v2 API) gives just the connected ones.
    async fn clients(&self, client: &telltale_filter::fetch::Client) -> Result<Seen, String> {
        let active = unifi_clients(&self.get(client, "/api/s/{site}/stat/sta").await?);
        let mut known = Seen::new();
        for path in [
            // Every client the console remembers, with its last address (Network 7+).
            "/v2/api/site/{site}/clients/history?onlyNonBlocked=true&includeUnifiDevices=false&withinHours=0",
            // The configured clients: aliases and fixed addresses.
            "/api/s/{site}/rest/user",
        ] {
            match self.get(client, path).await {
                Ok(v) => known.extend(unifi_known(&v)),
                Err(e) => debug!(error = %e, "router integration: UniFi known clients"),
            }
        }
        Ok(unifi_merge(active, known))
    }
}

/// One poll of a UniFi console or Network application.
async fn poll_unifi(
    client: &telltale_filter::fetch::Client,
    c: &RouterConfig,
) -> Result<Seen, String> {
    let base = c.url.trim_end_matches('/');
    let site = c.site.as_deref().unwrap_or("default");
    if let Some(key) = secret(c.api_key_file.as_ref())? {
        let s = UnifiSession {
            base,
            site,
            prefix: "/proxy/network",
            auth: ("x-api-key", key),
        };
        return s.clients(client).await;
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
        let s = UnifiSession {
            base,
            site,
            prefix,
            auth: ("cookie", cookies(&headers)),
        };
        return s.clients(client).await;
    }
    Err(format!(
        "{base}: neither a UniFi OS console nor a Network application"
    ))
}

/// One poll of an OPNsense box.
async fn poll_opnsense(
    client: &telltale_filter::fetch::Client,
    c: &RouterConfig,
) -> Result<Seen, String> {
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
            return Ok(opnsense_leases(&v));
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

/// The leases view from every router's last answer.
fn rebuild(parts: &HashMap<String, Seen>, view: &ArcSwap<Leases>) {
    let mut m = Leases::new();
    for seen in parts.values() {
        for (mac, ip, name) in seen {
            m.insert(
                *ip,
                Lease {
                    mac: mac.clone(),
                    ip: *ip,
                    hostname: name.clone(),
                    expires: 0,
                },
            );
        }
    }
    view.store(Arc::new(m));
}

/// Polls every `[[router]]` until `stop`. `resolver_pod`: a Helm resolver pod, which has the
/// routers' settings but not their key files (ADR-120), logs its failures as info; the
/// controller, which serves the names in the UI, warns.
pub(crate) async fn run(
    routers: Vec<RouterConfig>,
    view: Arc<ArcSwap<Leases>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    resolver_pod: bool,
) {
    if routers.is_empty() {
        return;
    }
    let resolver: Arc<dyn telltale_filter::fetch::Resolve> =
        Arc::new(telltale_filter::fetch::SystemResolver);
    let mut parts: HashMap<String, Seen> = HashMap::new();
    let mut failing: HashMap<String, bool> = HashMap::new();
    let interval = routers
        .iter()
        .map(|r| r.interval_secs.max(30))
        .min()
        .unwrap_or(300);
    loop {
        for r in &routers {
            let client = if r.tls_insecure_skip_verify {
                telltale_filter::fetch::Client::insecure(Arc::clone(&resolver))
            } else if let Some(p) = &r.tls_ca {
                telltale_filter::fetch::Client::with_ca_file(Arc::clone(&resolver), p.as_str())
            } else {
                telltale_filter::fetch::Client::new(Arc::clone(&resolver), &[])
            };
            // Like a failed poll, a TLS setting that can't load (a node without the CA file, ADR-120)
            // is logged once until it works.
            let client = match client {
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
            // REQ: T8.2 — a console whose certificate names something other than `url`'s host.
            let client = client.with_server_name(
                r.tls_server_name
                    .as_ref()
                    .map(telltale_config::SafeString::as_str),
            );
            let result = match r.kind {
                RouterKind::Unifi => poll_unifi(&client, r).await,
                RouterKind::Opnsense => poll_opnsense(&client, r).await,
            };
            let was_failing = failing.get(r.name.as_str()).copied().unwrap_or(false);
            match result {
                Ok(seen) => {
                    if was_failing || !parts.contains_key(r.name.as_str()) {
                        info!(router = %r.name, devices = seen.len(), "router integration: devices read");
                    }
                    parts.insert(r.name.to_string(), seen);
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
        rebuild(&parts, &view);
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

    /// REQ: T8.2 — UniFi's offline known clients keep their names: v2 history (a bare array)
    /// and `rest/user` give the named ones, most recently seen first; a connected client keeps
    /// its address and only takes a name it lacks; an offline client never takes an address a
    /// connected one holds.
    #[test]
    fn unifi_offline_clients_named() {
        let active = unifi_clients(&serde_json::json!({"data": [
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
             "mac": "aa:bb:cc:00:00:17", "display_name": "Spare phone", "name": "Spare phone",
             "last_seen": 150, "status": "offline", "type": "WIRELESS", "fingerprint": {"has_override": false}}
        ]);
        let users = serde_json::json!({"meta": {"rc": "ok"}, "data": [
            {"mac": "aa:bb:cc:00:00:14", "fixed_ip": "192.168.1.40", "use_fixedip": true, "name": "Printer"},
            {"mac": "aa:bb:cc:00:00:15", "name": "No address"},
            {"mac": "aa:bb:cc:00:00:16", "fixed_ip": "192.168.1.41", "use_fixedip": false, "name": "Reservation off"}
        ]});
        let mut known = unifi_known(&history);
        known.extend(unifi_known(&users));
        assert_eq!(
            unifi_merge(active, known),
            vec![
                (
                    "aa:bb:cc:00:00:01".into(),
                    Ipv4Addr::new(192, 168, 1, 20),
                    Some("Kitchen tablet".into())
                ),
                (
                    "aa:bb:cc:00:00:02".into(),
                    Ipv4Addr::new(192, 168, 1, 21),
                    Some("Living room TV".into())
                ),
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
}

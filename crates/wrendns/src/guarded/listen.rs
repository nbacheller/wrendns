// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-902, DNS-001, DNS-901, CLU-004 (T27.14c; ADR-914, ADR-956, ADR-1090, ADR-1098;
//! `docs/design/listener-editor.md` sections 1, 2.6 and 4) — the `listen` row's applier: the node's
//! whole DNS listener list, replaced as a list.
//!
//! The check judges a value without touching a socket: the shape (unknown fields refused, and the two
//! fields that are not this row's refused with a sentence that names where each is set), the
//! listener rules of the configuration check, the certificate files, the ports that belong to the
//! node's other servers, the port-53 rule, the gate each new listener gets by default, and the
//! weakening rules (a) to (c) of design section 4. Stage binds the new sockets next to the running ones
//! through the `Host` hooks of T27.14a, and returns the node's own probes (T27.14b) as the proof.
//!
//! Everything that reads the machine (the interface list, the host's address facts, the certificate
//! files, the supervisor) goes through [`Env`], so the check table runs over fixtures.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{Value, json};
use wrendns_api::BoxFuture;
use wrendns_api::guarded::{GuardedCheck, GuardedListenerLine};
use wrendns_api::problem::{Code, Problem};
use wrendns_config::{
    Config, HostFacts, ListenProto, Listener, SafeString, TlsFiles, is_public_address, is_wildcard,
};

use super::appliers::ListenAccess;
use super::dns_proof::{self, DnsProbe};
use super::engine::{Applier, CheckCx, Checked, Staged, WindowGuard};
use super::host::{Host, Member};
use crate::credential_rules::PathRules;
use crate::server::WindowError;

/// The `listen` row's applier.
pub(crate) struct Listen;

/// What the check reads from the machine, so a test can give it fixtures.
pub(crate) struct Env {
    /// The host's address facts (what a wildcard's default gate resolves to).
    pub(crate) host: HostFacts,
    /// The addresses of the interfaces that are up; `None` when the list cannot be read.
    pub(crate) local: Option<Vec<IpAddr>>,
    /// `systemd`, `docker`, `kubernetes` or `none`.
    pub(crate) supervisor: String,
    /// Unix seconds now.
    pub(crate) now: u64,
}

impl Env {
    /// The machine's own facts.
    pub(crate) fn read() -> Self {
        Self {
            host: crate::gate_host::read(),
            local: wrendns_net::local_addrs()
                .ok()
                .filter(|l| !l.is_empty())
                .map(|l| l.into_iter().filter(|a| a.up).map(|a| a.ip).collect()),
            supervisor: super::restart::detect_process().kind,
            now: super::now_secs(),
        }
    }
}

fn bad(why: impl Into<String>) -> Problem {
    Problem::new(Code::InvalidConfig, format!("`listeners`: {}", why.into()))
}

pub(crate) fn proto_word(p: ListenProto) -> &'static str {
    match p {
        ListenProto::Udp => "udp",
        ListenProto::Tcp => "tcp",
        ListenProto::Dot => "dot",
        ListenProto::Doh => "doh",
        ListenProto::Doh3 => "doh3",
        ListenProto::Doq => "doq",
    }
}

fn name(l: &Listener) -> String {
    format!("{}://{}", proto_word(l.proto), l.addr)
}

/// The words a person reads for a protocol.
fn proto_label(p: ListenProto) -> &'static str {
    match p {
        ListenProto::Udp => "UDP",
        ListenProto::Tcp => "TCP",
        ListenProto::Dot => "DoT",
        ListenProto::Doh => "DoH",
        ListenProto::Doh3 => "DoH3",
        ListenProto::Doq => "DoQ",
    }
}

/// The sockets that cannot share a port: plain UDP shares one (`SO_REUSEPORT`), TCP-based listeners
/// share nothing with each other, and QUIC listeners share nothing either (design 2.3).
const fn class(p: ListenProto) -> u8 {
    match p {
        ListenProto::Udp => 0,
        ListenProto::Tcp | ListenProto::Dot | ListenProto::Doh => 1,
        ListenProto::Doh3 | ListenProto::Doq => 2,
    }
}

fn family(ip: IpAddr) -> u8 {
    if ip.to_canonical().is_ipv4() { 4 } else { 6 }
}

/// Two addresses overlap when they share a port and a family, and are the same address or one is a
/// wildcard (design 2.6 rule 1).
fn overlaps(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port()
        && family(a.ip()) == family(b.ip())
        && (a.ip().to_canonical() == b.ip().to_canonical()
            || is_wildcard(a.ip())
            || is_wildcard(b.ip()))
}

/// Whether a listener bound to `bound` answers on `address`: the same address, or either a wildcard
/// of the same family (the port is not part of the question).
fn serves_address(bound: IpAddr, address: IpAddr) -> bool {
    family(bound) == family(address)
        && (bound.to_canonical() == address.to_canonical()
            || is_wildcard(bound)
            || is_wildcard(address))
}

/// Whether a listener bound to `bound` answers on every address `address` stood for: the same
/// address, or `bound` a wildcard of the same family. A specific address never covers a wildcard.
fn covers_address(bound: IpAddr, address: IpAddr) -> bool {
    family(bound) == family(address)
        && (bound.to_canonical() == address.to_canonical() || is_wildcard(bound))
}

// ---- the value ----------------------------------------------------------------------------

/// The listeners a `listen` value names. A field that is not the row's is refused with a sentence
/// that says where it is set.
#[allow(clippy::too_many_lines)] // one pass over each listener's fields, in the order the value lists them
pub(crate) fn parse(v: &Value) -> Result<Vec<Listener>, Problem> {
    let o = v
        .as_object()
        .ok_or_else(|| bad("the value must be an object with a `listeners` list"))?;
    if let Some(k) = o.keys().find(|k| k.as_str() != "listeners") {
        return Err(bad(format!("`{k}` isn't a field here")));
    }
    let list = o
        .get("listeners")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("must be a list"))?;
    let mut out: Vec<Listener> = Vec::new();
    for l in list {
        let o = l
            .as_object()
            .ok_or_else(|| bad("each entry must be an object"))?;
        for k in o.keys() {
            match k.as_str() {
                "proto"
                | "addr"
                | "tls"
                | "path"
                | "maxConnections"
                | "maxConnectionsPerAddress" => {}
                "proxyProtocol" | "proxy_protocol" => {
                    return Err(bad(
                        "`proxyProtocol` is set in the configuration file only: a PROXY listener trusts the address in each connection's header, so turning it on here would let any client choose its own address",
                    ));
                }
                "requireClientId" | "require_client_id" => {
                    return Err(bad(
                        "`requireClientId` isn't set here: the device key setting of a listener is Settings, System, Listener access (the `listen-access` setting)",
                    ));
                }
                other => return Err(bad(format!("`{other}` isn't a field here"))),
            }
        }
        let proto: ListenProto = o
            .get("proto")
            .cloned()
            .and_then(|p| serde_json::from_value(p).ok())
            .ok_or_else(|| bad("`proto` must be udp, tcp, dot, doh, doh3 or doq"))?;
        let addr: SocketAddr = o
            .get("addr")
            .and_then(Value::as_str)
            .and_then(|a| a.trim().parse().ok())
            .ok_or_else(|| bad("`addr` must look like 203.0.113.5:853 or [2001:db8::5]:853"))?;
        let who = format!("{}://{addr}", proto_word(proto));
        if addr.port() == 0 {
            return Err(bad(format!("{who}: the port must be 1 to 65535")));
        }
        let tls = match o.get("tls") {
            None | Some(Value::Null) => None,
            Some(Value::Object(t)) => {
                if let Some(k) = t.keys().find(|k| !matches!(k.as_str(), "cert" | "key")) {
                    return Err(bad(format!("{who}: `tls.{k}` isn't a field here")));
                }
                let get = |k: &str| {
                    t.get(k)
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .and_then(|s| SafeString::new(s).ok())
                };
                Some(TlsFiles {
                    cert: get("cert")
                        .ok_or_else(|| bad(format!("{who}: `tls.cert` must be a path")))?,
                    key: get("key")
                        .ok_or_else(|| bad(format!("{who}: `tls.key` must be a path")))?,
                })
            }
            Some(_) => return Err(bad(format!("{who}: `tls` must be an object or null"))),
        };
        let path = match o.get("path") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.trim().is_empty() => None,
            Some(Value::String(s)) => {
                Some(SafeString::new(s.trim()).map_err(|e| bad(format!("{who}: `path` {e}")))?)
            }
            Some(_) => return Err(bad(format!("{who}: `path` must be text"))),
        };
        let limit = |k: &str| -> Result<Option<u32>, Problem> {
            match o.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(n) => n
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .map(Some)
                    .ok_or_else(|| bad(format!("{who}: `{k}` must be a whole number"))),
            }
        };
        let (max_connections, max_connections_per_address) =
            (limit("maxConnections")?, limit("maxConnectionsPerAddress")?);
        if proto.needs_tls() && tls.is_none() {
            return Err(bad(format!(
                "{who}: `tls` (a certificate and a key) is required for dot, doh, doh3 and doq"
            )));
        }
        if !proto.needs_tls() && tls.is_some() {
            return Err(bad(format!(
                "{who}: `tls` is only for dot, doh, doh3 and doq"
            )));
        }
        if let Some(p) = &path {
            if !proto.is_http() {
                return Err(bad(format!("{who}: `path` is only for doh and doh3")));
            }
            if !p.starts_with('/') {
                return Err(bad(format!("{who}: `path` must start with `/`")));
            }
        }
        if proto == ListenProto::Udp
            && (max_connections.is_some() || max_connections_per_address.is_some())
        {
            return Err(bad(format!("{who}: the connection limits aren't for udp")));
        }
        if max_connections == Some(0) {
            return Err(bad(format!("{who}: `maxConnections` must be at least 1")));
        }
        if out.iter().any(|x| x.proto == proto && x.addr == addr) {
            return Err(bad(format!("{who} appears twice")));
        }
        out.push(Listener {
            proto,
            addr,
            path,
            tls,
            proxy_protocol: false,
            max_connections,
            max_connections_per_address,
            require_client_id: None,
        });
    }
    Ok(out)
}

/// The list as JSON in this row's shape.
pub(crate) fn to_value(list: &[Listener]) -> Value {
    json!({"listeners": list.iter().map(|l| {
        let mut o = serde_json::Map::new();
        o.insert("proto".into(), json!(proto_word(l.proto)));
        o.insert("addr".into(), json!(l.addr.to_string()));
        if let Some(t) = &l.tls {
            o.insert("tls".into(), json!({"cert": t.cert.as_str(), "key": t.key.as_str()}));
        }
        if let Some(p) = &l.path {
            o.insert("path".into(), json!(p.as_str()));
        }
        if let Some(n) = l.max_connections {
            o.insert("maxConnections".into(), json!(n));
        }
        if let Some(n) = l.max_connections_per_address {
            o.insert("maxConnectionsPerAddress".into(), json!(n));
        }
        Value::Object(o)
    }).collect::<Vec<_>>()})
}

/// What `list` runs as: a listener the node already runs keeps its device key setting and its PROXY
/// flag (they are not this row's); a new one starts on its default (design 4).
pub(crate) fn merged(list: Vec<Listener>, running: &[Listener]) -> Vec<Listener> {
    merged_with(list, running, None)
}

/// [`merged`], and a new listener on an address the node's stored `listen-access` value still has a
/// line for takes that line's setting: the reload overlays the stored value after this row, so the
/// preview, the probe and the result must judge the same gate (a line left by a hand edit or a failed prune; a kept change drops the lines of the removed
/// listeners).
pub(crate) fn merged_with(
    list: Vec<Listener>,
    running: &[Listener],
    access: Option<&Value>,
) -> Vec<Listener> {
    let lines = access
        .and_then(|v| ListenAccess::lines(v).ok())
        .unwrap_or_default();
    list.into_iter()
        .map(|mut l| {
            if let Some(r) = running
                .iter()
                .find(|r| r.proto == l.proto && r.addr == l.addr)
            {
                l.require_client_id = r.require_client_id;
                l.proxy_protocol = r.proxy_protocol;
            } else if l.proto.needs_tls()
                && let Some(line) = lines
                    .iter()
                    .find(|x| x.proto == l.proto && x.addr == l.addr)
            {
                l.require_client_id = line.setting;
            }
            l
        })
        .collect()
}

fn served_path(l: &Listener) -> Option<&str> {
    if l.proto.is_http() {
        Some(
            l.path
                .as_ref()
                .map_or("/dns-query", |p| p.as_str())
                .trim_end_matches('/'),
        )
    } else {
        None
    }
}

/// Whether two listeners of one protocol and address carry the same settings.
fn same_settings(a: &Listener, b: &Listener) -> bool {
    a.tls == b.tls
        && served_path(a) == served_path(b)
        && a.max_connections == b.max_connections
        && a.max_connections_per_address == b.max_connections_per_address
}

// ---- certificates -------------------------------------------------------------------------

/// What the certificate check found in one cert and key pair.
#[derive(Debug, Clone)]
pub(crate) struct CertInfo {
    pub(crate) names: Vec<String>,
    pub(crate) days_left: i64,
}

impl CertInfo {
    fn describe(&self) -> String {
        let names = if self.names.is_empty() {
            "no names".to_owned()
        } else {
            format!("covers {}", self.names.join(", "))
        };
        if self.days_left < 0 {
            format!("{names}; expired {} day(s) ago", -self.days_left)
        } else {
            format!("{names}; expires in {} day(s)", self.days_left)
        }
    }
}

/// REQ: API-902 (design 1.2) — one certificate and key pair: each path absolute, a regular file and
/// not a symlink, not a path the T23.2 rules deny, readable; the certificate parses and the key
/// matches it. The contents are never returned.
pub(crate) fn check_cert(rules: &PathRules, t: &TlsFiles, now: u64) -> Result<CertInfo, String> {
    for (what, p) in [("certificate", t.cert.as_str()), ("key", t.key.as_str())] {
        let path = std::path::Path::new(p);
        if !path.is_absolute() {
            return Err(format!("the {what} path `{p}` must be absolute"));
        }
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| format!("the {what} `{p}` can't be read: {e}"))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "the {what} `{p}` is a symbolic link: name the file itself"
            ));
        }
        if !meta.is_file() {
            return Err(format!("the {what} `{p}` isn't a regular file"));
        }
        rules.check(p, false)?;
        std::fs::File::open(path)
            .map_err(|e| format!("the {what} `{p}` can't be read by this node: {e}"))?;
    }
    wrendns_net::CertStore::load(t.cert.as_str(), t.key.as_str())
        .map_err(|e| format!("`{}` and `{}` can't be used together: {e}", t.cert, t.key))?;
    let days_left = crate::probes::cert_expiry(t.cert.as_str(), now)?.1;
    let names = crate::probes::cert_identity(t.cert.as_str()).map_or_else(|_| Vec::new(), |i| i.1);
    Ok(CertInfo { names, days_left })
}

// ---- the check ----------------------------------------------------------------------------

/// Whether a socket on `l` is reachable from the internet (design 4 rule c): a specific address by
/// ADR-1090's public test; a wildcard when the host holds a public IPv4 address, or its interface
/// list cannot be read (fail closed).
fn reachable_from_internet(l: &Listener, host: HostFacts) -> bool {
    if is_wildcard(l.addr.ip()) {
        host.public_ipv4 != Some(false)
    } else {
        is_public_address(l.addr.ip())
    }
}

/// REQ: API-902 (design 4) — why a change weakens, or `None`: (a) TLS removed or downgraded on an
/// address that stays served; (b) a gated encrypted listener replaced by an ungated one; (c) a socket
/// added that is reachable from the internet and answers without a device key.
pub(crate) fn weakening_reason(
    running: &[Listener],
    new: &[Listener],
    host: HostFacts,
) -> Option<String> {
    let has = |list: &[Listener], l: &Listener| {
        list.iter().any(|x| x.proto == l.proto && x.addr == l.addr)
    };
    // (a) an encrypted listener is gone from an address that a plain listener still serves.
    for o in running.iter().filter(|o| o.proto.needs_tls()) {
        if has(new, o) {
            continue;
        }
        let still_encrypted = new
            .iter()
            .any(|n| n.proto.needs_tls() && covers_address(n.addr.ip(), o.addr.ip()));
        let plain_stays = new
            .iter()
            .any(|n| !n.proto.needs_tls() && serves_address(n.addr.ip(), o.addr.ip()));
        if plain_stays && !still_encrypted {
            return Some(format!(
                "removes {} while plain DNS stays on {}: the address is served without encryption",
                name(o),
                o.addr.ip()
            ));
        }
    }
    // (b) a gated encrypted listener removed, and an ungated one of its protocol added.
    for o in running
        .iter()
        .filter(|o| o.proto.needs_tls() && o.gated(host))
    {
        if has(new, o) {
            continue;
        }
        if let Some(n) = new
            .iter()
            .find(|n| n.proto == o.proto && !has(running, n) && !n.gated(host))
        {
            return Some(format!(
                "replaces {}, which answers only a known device key, with {}, which does not",
                name(o),
                name(n)
            ));
        }
    }
    // (c) added, reachable from the internet, no device key.
    for n in new.iter().filter(|n| !has(running, n)) {
        if reachable_from_internet(n, host) && !n.gated(host) {
            return Some(if is_wildcard(n.addr.ip()) {
                format!(
                    "adds {} on {}, which binds every address on a host that has a public IPv4 address (or whose addresses could not be read), so it answers anyone on the internet without a device key",
                    proto_label(n.proto),
                    n.addr
                )
            } else {
                format!(
                    "adds {} on {}, which answers anyone on the internet without a device key",
                    proto_label(n.proto),
                    n.addr
                )
            });
        }
    }
    None
}

/// The ports that belong to the node's other servers, with the setting that names each.
fn internal_ports(cfg: &Config) -> Vec<(SocketAddr, &'static str, &'static str)> {
    let mut v = vec![(cfg.api.listen, "the web UI's", "[api] listen")];
    if let Some(a) = cfg.api.http_redirect {
        v.push((a, "the HTTP to HTTPS redirect's", "[api] http_redirect"));
    }
    if cfg.telemetry.metrics.enabled {
        v.push((
            cfg.telemetry.metrics.listen,
            "the metrics endpoint's",
            "[telemetry.metrics] listen",
        ));
    }
    if let Ok(a) = cfg.cluster.listen.as_str().parse::<SocketAddr>() {
        v.push((a, "the cluster port's", "[cluster] listen"));
    }
    v
}

fn old_has(running: &[Listener], l: &Listener) -> bool {
    running
        .iter()
        .any(|x| x.proto == l.proto && x.addr == l.addr)
}

/// A line is `kept` when the node already runs the same listener with the same settings.
fn status(running: &[Listener], l: &Listener) -> &'static str {
    match running
        .iter()
        .find(|x| x.proto == l.proto && x.addr == l.addr)
    {
        None => "added",
        Some(r) if same_settings(r, l) => "kept",
        Some(_) => "changed",
    }
}

/// The dry run, over what the machine says ([`Env`]) and the cluster's members.
#[allow(clippy::too_many_lines)] // one ordered list of checks, as design 2.6 and 4 list them
pub(crate) fn evaluate(
    cfg: &Config,
    node: &str,
    value: &Value,
    members: &[Member],
    site: &str,
    env: &Env,
    access: Option<&Value>,
) -> Result<Checked, Problem> {
    if members
        .iter()
        .any(|m| m.witness && (m.id == node || m.name == node))
    {
        return Err(Problem::new(
            Code::InvalidConfig,
            "a witness serves no DNS: it has no listeners to change",
        ));
    }
    let running = &cfg.listen;
    let new = merged_with(parse(value)?, running, access);
    let host = env.host;
    let mut out = Checked::default();
    // The empty list, and the port-53 rule per family and transport (only where the node runs it).
    if new.is_empty() {
        out.would_disconnect = true;
        out.disconnect_detail = Some(
            "this leaves the node with no DNS listener: add the new listener first, then remove the old one in a second change".to_owned(),
        );
        return Ok(out);
    }
    for (proto, label) in [(ListenProto::Udp, "UDP"), (ListenProto::Tcp, "TCP")] {
        for (fam, fam_label) in [(4_u8, "IPv4"), (6, "IPv6")] {
            let on_53 = |list: &[Listener]| {
                list.iter()
                    .any(|l| l.proto == proto && l.addr.port() == 53 && family(l.addr.ip()) == fam)
            };
            if on_53(running) && !on_53(&new) {
                out.would_disconnect = true;
                out.disconnect_detail = Some(format!(
                    "this leaves no {label} listener on port 53 for {fam_label}: clients ask on port 53, so add the new listener first and remove the old one in a second change (moving DNS off port 53 is done in the configuration file)"
                ));
                return Ok(out);
            }
        }
    }
    // Two listeners that cannot share a port.
    for (i, a) in new.iter().enumerate() {
        for b in &new[i + 1..] {
            if class(a.proto) == class(b.proto) && class(a.proto) != 0 && overlaps(a.addr, b.addr) {
                return Err(bad(format!(
                    "{} overlaps {} on the same port: the second could never bind (change one address or port)",
                    name(a),
                    name(b)
                )));
            }
        }
    }
    // The ports of the node's other servers, for what the change adds or changes.
    let others = internal_ports(cfg);
    for l in new.iter().filter(|l| status(running, l) != "kept") {
        if let Some((_, who, setting)) = others.iter().find(|(a, _, _)| overlaps(l.addr, *a)) {
            return Err(Problem::new(
                Code::InvalidConfig,
                format!(
                    "`listeners`: {}: port {} is {who} ({setting})",
                    name(l),
                    l.addr.port()
                ),
            ));
        }
    }
    // Certificates, once per distinct pair.
    let rules = {
        // The listeners' own keys and the web UI's key are the files a listener may name.
        let mut c = cfg.clone();
        c.listen.clear();
        c.api.tls = None;
        PathRules::of(&c)
    };
    let mut warnings: Vec<String> = Vec::new();
    let mut checks: Vec<GuardedCheck> = Vec::new();
    let mut certs: Vec<(TlsFiles, Result<CertInfo, String>)> = Vec::new();
    for l in &new {
        let Some(t) = &l.tls else { continue };
        // A listener the node already runs as it is is judged by a warning, not a refusal: its files
        // are the node's business today, and a change elsewhere must not wait for them.
        let kept = status(running, l) == "kept";
        let pos = certs.iter().position(|(c, _)| c == t);
        let r = match pos {
            Some(i) => certs[i].1.clone(),
            None => check_cert(&rules, t, env.now),
        };
        if let Err(why) = &r {
            if !kept {
                return Err(Problem::new(
                    Code::InvalidConfig,
                    format!("`listeners`: {}: {why}", name(l)),
                ));
            }
            if pos.is_none() {
                warnings.push(format!(
                    "{} is kept, but its certificate can't be used now: {why}.",
                    name(l)
                ));
            }
        }
        if pos.is_none() {
            certs.push((t.clone(), r));
        }
    }
    let warn_days = i64::from(cfg.probe.cert_warn_days);
    for (t, r) in &certs {
        if let Ok(i) = r {
            checks.push(GuardedCheck {
                name: format!("certificate {}", t.cert.as_str()),
                ok: true,
                detail: i.describe(),
            });
            if i.days_left < 0 {
                warnings.push(format!(
                    "The certificate {} has expired: clients refuse a listener that uses it.",
                    t.cert.as_str()
                ));
            } else if i.days_left < warn_days {
                warnings.push(format!(
                    "The certificate {} expires in {} day(s).",
                    t.cert.as_str(),
                    i.days_left
                ));
            }
        }
    }
    checks.push(GuardedCheck {
        name: "ports".to_owned(),
        ok: true,
        detail: "no listener takes a port of the web UI, the redirect, the metrics endpoint or the cluster".to_owned(),
    });
    // Each line, its gate sentence, and the warnings that go with it.
    let mut lines: Vec<GuardedListenerLine> = Vec::new();
    let (mut adds, mut removes, mut keeps) = (Vec::new(), Vec::new(), 0_usize);
    for l in &new {
        let st = status(running, l);
        let gate = l.proto.needs_tls().then(|| {
            let d = l.default_gate(host);
            let g = l.gated(host);
            let word = if g {
                "answers only a known device key"
            } else {
                "open to the allowed networks"
            };
            match l.require_client_id {
                Some(_) => format!("{}: {word} (set under Listener access)", name(l)),
                None => format!("{}: {word} (default: {})", name(l), d.describe()),
            }
        });
        if st == "added" && l.proto.needs_tls() && l.gated(host) && l.require_client_id.is_none() {
            warnings.push(format!(
                "{} is gated by default: devices without a device key are refused on this listener.",
                name(l)
            ));
        }
        if st == "added" {
            adds.push(format!("{} on {}", proto_label(l.proto), l.addr));
        } else if st == "kept" {
            keeps += 1;
        }
        let explain = if st == "added" {
            running
                .iter()
                .find(|r| {
                    class(r.proto) == class(l.proto)
                        && class(l.proto) != 0
                        && overlaps(r.addr, l.addr)
                        && (is_wildcard(r.addr.ip()) || is_wildcard(l.addr.ip()))
                })
                .map(|r| {
                    format!(
                        "overlaps {} on the same port: tried on a temporary port first, and bound for real when you confirm (the wildcard closes for a few milliseconds)",
                        name(r)
                    )
                })
        } else if st == "changed" {
            Some("new settings are tried on a temporary port first, then swapped onto the real port when you confirm (a few milliseconds without it)".to_owned())
        } else {
            None
        };
        let certificate = l.tls.as_ref().and_then(|t| {
            certs
                .iter()
                .find(|(c, _)| c == t)
                .and_then(|(_, r)| r.as_ref().ok())
                .map(CertInfo::describe)
        });
        lines.push(GuardedListenerLine {
            change: st.to_owned(),
            listener: name(l),
            gate,
            certificate,
            proof_port: None,
            note: explain,
        });
    }
    // Removed listeners, and an explicit device key setting that goes with them.
    for r in running.iter().filter(|r| !old_has(&new, r)) {
        removes.push(format!("{} on {}", proto_label(r.proto), r.addr));
        let dropped = r.require_client_id.map(|on| {
            let same_proto_new: Vec<String> = new
                .iter()
                .filter(|n| n.proto == r.proto && !old_has(running, n))
                .map(|n| {
                    format!(
                        "{} starts on its default ({})",
                        name(n),
                        if n.gated(host) { "on" } else { "off" }
                    )
                })
                .collect();
            let tail = if same_proto_new.is_empty() {
                String::new()
            } else {
                format!("; {}", same_proto_new.join(", "))
            };
            format!(
                "Listener access for {} was set to {}{tail}",
                name(r),
                if on { "on" } else { "off" }
            )
        });
        if let Some(d) = &dropped {
            warnings.push(d.clone());
        }
        lines.push(GuardedListenerLine {
            change: "removed".to_owned(),
            listener: name(r),
            gate: None,
            certificate: None,
            proof_port: None,
            note: dropped,
        });
    }
    let mut removed_ips: Vec<IpAddr> = Vec::new();
    for r in running.iter().filter(|r| !old_has(&new, r)) {
        let ip = r.addr.ip().to_canonical();
        if !removed_ips.contains(&ip) {
            removed_ips.push(ip);
            warnings.push(format!(
                "Clients that send queries to {} stop getting answers on a removed listener when you confirm. Point them (your router's DHCP DNS option) at the new address first; you can add the new listener now and remove the old one in a later change.",
                r.addr.ip()
            ));
        }
    }
    // The machine, the platform and the cluster.
    if matches!(env.supervisor.as_str(), "docker" | "kubernetes") {
        warnings.push(
            "This node runs in Docker or Kubernetes: published ports and Service ports are not changed by this."
                .to_owned(),
        );
    }
    if let Some(local) = &env.local {
        for l in new.iter().filter(|l| status(running, l) == "added") {
            let ip = l.addr.ip().to_canonical();
            if !is_wildcard(ip) && !local.iter().any(|x| x.to_canonical() == ip) {
                warnings.push(format!(
                    "{} is on no interface of this host: the bind fails unless the address is floating (a VIP). Bind the wildcard instead, or allow non-local binds.",
                    l.addr.ip()
                ));
            }
        }
    }
    if !site.is_empty() {
        let others_up = members
            .iter()
            .any(|m| m.up && !m.witness && m.site == site && m.id != node && m.name != node);
        if !members.is_empty() && !others_up {
            warnings.push(format!(
                "This node is the only healthy resolver in site {site}: clients there have no other one while the change settles."
            ));
        }
    }
    // The weakening rules.
    let weak = weakening_reason(running, &new, host);
    if let Some(w) = &weak {
        warnings.push(format!("This change weakens security: it {w}."));
    }
    let mut effect = String::new();
    if !adds.is_empty() {
        effect.push_str("Adds ");
        effect.push_str(&adds.join(", "));
        effect.push_str(". ");
    }
    if !removes.is_empty() || !adds.is_empty() || keeps < new.len() {
        effect.push_str("Keeps every current listener until you confirm. ");
    }
    if !removes.is_empty() {
        effect.push_str("Removes ");
        effect.push_str(&removes.join(", "));
        effect.push_str(" when you confirm. ");
    }
    if effect.is_empty() {
        effect = format!(
            "Changes no listener on {node}; the node asks each listener a test question and nothing else changes. "
        );
    }
    effect.push_str("The node asks every new listener a test question itself before you can confirm; that proves it works on this machine, not that your devices can reach it.");
    out.effect = effect;
    // The same sentence twice (UDP and TCP on one address that is not local, two pairs that share a
    // certificate) is said once.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    warnings.retain(|w| seen.insert(w.clone()));
    out.warnings = warnings;
    out.host_facts = Some(host);
    out.checks = checks;
    out.listeners = lines;
    out.weakening = weak.is_some();
    Ok(out)
}

impl Applier for Listen {
    fn current(&self, cfg: &Config) -> Value {
        to_value(&cfg.listen)
    }

    fn check(&self, cx: &CheckCx<'_>) -> Result<Checked, Problem> {
        evaluate(
            cx.cfg,
            cx.node,
            cx.value,
            &cx.host.members(),
            &cx.host.site(),
            &Env::read(),
            cx.access,
        )
    }

    fn overlay(&self, cfg: &mut Config, value: &Value) {
        let Ok(list) = parse(value) else { return };
        cfg.listen = merged(list, &cfg.listen);
    }

    fn stage(
        &self,
        host: Arc<dyn Host>,
        node: String,
        value: Value,
        access: Option<Value>,
        reviewed: Option<HostFacts>,
    ) -> BoxFuture<Result<Staged, Problem>> {
        Box::pin(async move {
            let running = host.running_config();
            let list = merged_with(parse(&value)?, &running.listen, access.as_ref());
            // The gates are judged on the facts the review rested on: a host whose addresses moved
            // between the check and the stage is reviewed again.
            let facts = crate::gate_host::read();
            if reviewed.is_some_and(|r| r != facts) {
                return Err(Problem::new(
                    Code::PreviewStale,
                    "this host's addresses changed since the preview, so the review no longer holds",
                )
                .hint("Preview the change again."));
            }
            let staged = host
                .stage_listeners(list.clone())
                .await
                .map_err(|e| Problem::new(Code::Conflict, e.detail))?;
            // The node's own query to each socket the change binds; a change that binds nothing is
            // proved by the listeners that stay still answering (design 2.2).
            let mut probes: Vec<DnsProbe> = dns_proof::probes_for(&staged, &list, facts);
            if probes.is_empty() {
                probes = list
                    .iter()
                    .filter(|l| !l.proxy_protocol)
                    .map(|l| dns_proof::probe_of_kept(l, facts))
                    .collect();
            }
            let digest = super::hex(
                blake3::hash(&serde_json::to_vec(&value).unwrap_or_default()).as_bytes(),
            );
            Ok(Staged {
                guard: Arc::new(ListenGuard::new(
                    host,
                    node,
                    digest,
                    facts,
                    crate::gate_host::read,
                )),
                proof_addr: None,
                new_address: None,
                pending_proxies: None,
                dns_probes: probes,
            })
        })
    }
}

/// What stays open while a listener change waits: it commits (adopts the staged sockets, closes the
/// removed listeners) or aborts (closes only what the change opened).
pub(crate) struct ListenGuard {
    host: Arc<dyn Host>,
    node: String,
    /// Digest of the value, for a replica to wait until the entry has come back through the primary.
    digest: String,
    /// The facts the staged gates were bound with.
    facts: HostFacts,
    read_facts: fn() -> HostFacts,
    reason: Arc<Mutex<&'static str>>,
}

impl ListenGuard {
    pub(crate) fn new(
        host: Arc<dyn Host>,
        node: String,
        digest: String,
        facts: HostFacts,
        read_facts: fn() -> HostFacts,
    ) -> Self {
        Self {
            host,
            node,
            digest,
            facts,
            read_facts,
            reason: Arc::new(Mutex::new(crate::server::COMMIT_FAILED)),
        }
    }
}

fn set_reason(m: &Mutex<&'static str>, e: &WindowError) -> Problem {
    *m.lock().unwrap_or_else(PoisonError::into_inner) = e.reason;
    Problem::new(Code::Conflict, e.to_string())
}

impl WindowGuard for ListenGuard {
    fn commit(&self) -> BoxFuture<Result<(), Problem>> {
        let host = Arc::clone(&self.host);
        let (node, digest) = (self.node.clone(), self.digest.clone());
        let reason = Arc::clone(&self.reason);
        Box::pin(async move {
            // On a replica the entry comes back through the primary; adoption makes the order of
            // that reload and this one irrelevant, but the wait keeps the answer honest.
            let _ = host
                .wait_applied(&node, wrendns_config::guarded::LISTEN, Some(digest))
                .await;
            // The reload adopts the staged sockets and closes the removed listeners (T27.14a); a
            // listener the file now sets cancels the window.
            if !host.reload().await {
                host.abort_listeners().await;
                return Err(Problem::unavailable(
                    "the node couldn't apply the new listeners",
                ));
            }
            host.commit_listeners()
                .await
                .map_err(|e| set_reason(&reason, &e))
        })
    }

    fn abort(&self) -> BoxFuture<()> {
        let host = Arc::clone(&self.host);
        Box::pin(async move { host.abort_listeners().await })
    }

    fn stale(&self) -> Option<String> {
        ((self.read_facts)() != self.facts).then(|| {
            "this host's addresses changed since the preview: cancel and review the change again"
                .to_owned()
        })
    }

    fn failure_reason(&self) -> &'static str {
        *self.reason.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

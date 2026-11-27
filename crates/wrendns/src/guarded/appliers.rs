//! REQ: API-902, CLU-004 (T27.13; ADR-956 §1) — what each registry row does on this node.
//!
//! The registry (`wrendns_config::guarded`) is data; an [`Applier`] is the behaviour behind a row:
//! its dry-run check, how its stored value enters the merged configuration, and (for a `window`
//! row) how its new sockets are bound next to the old ones. T27.14 to T27.17 add a row, a check
//! and an apply step each, here. This task adds none of the real ones: it builds the framework and,
//! under the cargo feature `e2e` only, three test rows (an `immediate`, a `window` and a `staged`
//! one) so the tests and the Playwright suite can drive every path.

use std::sync::{Arc, OnceLock};

use serde_json::Value;
use wrendns_api::problem::{Code, Problem};
use wrendns_config::Config;
use wrendns_config::guarded::{self, Mode};
use wrendns_store::state::State;

use super::engine::{Applier, CheckCx, Checked, NoOp, RowDef};
use super::store::{self, EntryState, Stored};

/// The rows a production node has, each with its applier. The registry's rows that have an
/// applier here; `restart-now` is the engine's own.
pub(crate) fn rows() -> Vec<RowDef> {
    guarded::rows()
        .into_iter()
        .filter_map(|r| {
            applier_for(r.id).map(|a| RowDef {
                row: *r,
                applier: a,
            })
        })
        .collect()
}

fn applier_for(id: &str) -> Option<Arc<dyn Applier>> {
    match id {
        guarded::RESTART_NOW => Some(Arc::new(NoOp)),
        guarded::API_HTTP_REDIRECT => Some(Arc::new(HttpRedirect)),
        guarded::LISTEN_ACCESS => Some(Arc::new(ListenAccess)),
        guarded::LISTEN => Some(Arc::new(super::listen::Listen)),
        #[cfg(feature = "e2e")]
        "e2e-immediate" | "e2e-file" => Some(Arc::new(test::Immediate)),
        #[cfg(feature = "e2e")]
        "e2e-window" => Some(Arc::new(test::Window)),
        #[cfg(feature = "e2e")]
        "e2e-probe" => Some(Arc::new(test::Probe)),
        #[cfg(feature = "e2e")]
        "e2e-staged" => Some(Arc::new(test::StagedRow)),
        _ => None,
    }
}

/// REQ: API-003, API-902 (T24.44, ADR-1053) — `api-http-redirect`: `{address}`, a socket address such as
/// `0.0.0.0:80`, or empty or null for off. `staged`: the listener opens with the API at the next
/// start. It needs `[api] tls` (the end-to-end build has none, so there it is a warning).
pub(crate) struct HttpRedirect;

impl HttpRedirect {
    /// The address in a value: `None` is off.
    fn address(v: &Value) -> Result<Option<std::net::SocketAddr>, Problem> {
        let bad = |why: &str| Problem::new(Code::InvalidConfig, format!("`address`: {why}"));
        match v.get("address") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
            Some(Value::String(s)) => {
                let a: std::net::SocketAddr = s.trim().parse().map_err(|_| {
                    bad("must look like 0.0.0.0:80 or [::]:80, or be empty for off")
                })?;
                if a.port() == 0 {
                    return Err(bad("the port must be 1 to 65535"));
                }
                Ok(Some(a))
            }
            Some(_) => Err(bad("must be text")),
        }
    }
}

impl Applier for HttpRedirect {
    fn current(&self, cfg: &Config) -> Value {
        serde_json::json!({"address": cfg.api.http_redirect.map(|a| a.to_string())})
    }
    fn check(&self, cx: &CheckCx<'_>) -> Result<Checked, Problem> {
        let Some(addr) = Self::address(cx.value)? else {
            return Ok(Checked {
                effect: format!(
                    "Turns the HTTP to HTTPS redirect off on {} at its next start.",
                    cx.node
                ),
                restart_required: true,
                ..Checked::default()
            });
        };
        let mut warnings = Vec::new();
        if cx.cfg.api.tls.is_none() {
            if cfg!(feature = "e2e") {
                warnings.push(
                    "[api] tls is off on this test build; a real node refuses this.".to_owned(),
                );
            } else {
                return Err(Problem::new(
                    Code::InvalidConfig,
                    "the redirect sends browsers to HTTPS, so [api] tls has to be set first",
                ));
            }
        }
        if wrendns_config::addrs_clash(addr, cx.cfg.api.listen) {
            return Err(Problem::new(
                Code::InvalidConfig,
                "`address` is the API's own address; use another port",
            ));
        }
        if addr.port() < 1024 {
            warnings.push(
                "Port below 1024 needs CAP_NET_BIND_SERVICE (the systemd unit grants it; Docker and Kubernetes publish the port themselves). If the bind fails it is logged and nothing else is affected."
                    .to_owned(),
            );
        }
        Ok(Checked {
            effect: format!(
                "Opens a plain-HTTP listener on {addr} at {}'s next start. It answers every request with a 308 to the HTTPS address (and /livez, /readyz, /healthz), and serves nothing else.",
                cx.node
            ),
            restart_required: true,
            warnings,
            ..Checked::default()
        })
    }
    fn overlay(&self, cfg: &mut Config, value: &Value) {
        // A stored address whose TLS was turned off since stays unused (the file's `[api]`
        // would otherwise fail validation).
        if cfg.api.tls.is_some()
            && let Ok(a) = Self::address(value)
        {
            cfg.api.http_redirect = a;
        }
    }
}

/// REQ: DNS-901, API-902 (T27.14, ADR-1090 point 1) — `listen-access`: the known-ID gate of every
/// listener, `{"listeners": [{"proto", "addr", "require_client_id"}]}` with `require_client_id`
/// `null` (the default: on for a public address, off otherwise), `true` or `false`. The value names
/// every listener this node runs and no other; a plain UDP or TCP listener can't carry a key, so its
/// setting is always `null`. `immediate`: it moves no address and leaves the API alone; the reload rebinds a listener whose effective gate changes.
///
/// What the default resolves to is `wrendns_config::default_gate`, with the host's address facts
/// (`crate::gate_host`): the same function the bind, the probes, the API and the health report use.
pub(crate) struct ListenAccess;

/// One listener's line in a `listen-access` value.
pub(super) struct GateLine {
    pub(super) proto: wrendns_config::ListenProto,
    pub(super) addr: std::net::SocketAddr,
    pub(super) setting: Option<bool>,
}

impl GateLine {
    fn name(&self) -> String {
        format!("{}://{}", proto_word(self.proto), self.addr)
    }
}

fn proto_word(p: wrendns_config::ListenProto) -> &'static str {
    use wrendns_config::ListenProto as P;
    match p {
        P::Udp => "udp",
        P::Tcp => "tcp",
        P::Dot => "dot",
        P::Doh => "doh",
        P::Doh3 => "doh3",
        P::Doq => "doq",
    }
}

fn gate_word(on: bool) -> &'static str {
    if on {
        "answers only a known device key"
    } else {
        "open to the allowed networks"
    }
}

fn setting_word(s: Option<bool>) -> &'static str {
    match s {
        None => "default",
        Some(true) => "on",
        Some(false) => "off",
    }
}

impl ListenAccess {
    pub(super) fn lines(v: &Value) -> Result<Vec<GateLine>, Problem> {
        let bad = |why: String| Problem::new(Code::InvalidConfig, format!("`listeners`: {why}"));
        let list = v
            .get("listeners")
            .and_then(Value::as_array)
            .ok_or_else(|| bad("must be a list".to_owned()))?;
        let mut out: Vec<GateLine> = Vec::new();
        for l in list {
            let o = l
                .as_object()
                .ok_or_else(|| bad("each entry must be an object".to_owned()))?;
            if let Some(k) = o
                .keys()
                .find(|k| !matches!(k.as_str(), "proto" | "addr" | "require_client_id"))
            {
                return Err(bad(format!("`{k}` isn't a field here")));
            }
            let proto: wrendns_config::ListenProto = o
                .get("proto")
                .cloned()
                .and_then(|p| serde_json::from_value(p).ok())
                .ok_or_else(|| bad("`proto` must be udp, tcp, dot, doh, doh3 or doq".to_owned()))?;
            let addr: std::net::SocketAddr = o
                .get("addr")
                .and_then(Value::as_str)
                .and_then(|a| a.parse().ok())
                .ok_or_else(|| bad("`addr` must look like 203.0.113.5:853".to_owned()))?;
            let setting = match o.get("require_client_id") {
                None | Some(Value::Null) => None,
                Some(Value::Bool(b)) => Some(*b),
                Some(_) => {
                    return Err(bad(
                        "`require_client_id` must be null, true or false".to_owned()
                    ));
                }
            };
            let line = GateLine {
                proto,
                addr,
                setting,
            };
            if out.iter().any(|x| x.proto == proto && x.addr == addr) {
                return Err(bad(format!("{} appears twice", line.name())));
            }
            out.push(line);
        }
        Ok(out)
    }
}

impl Applier for ListenAccess {
    fn current(&self, cfg: &Config) -> Value {
        serde_json::json!({"listeners": cfg.listen.iter().map(|l| serde_json::json!({
            "proto": proto_word(l.proto),
            "addr": l.addr.to_string(),
            "require_client_id": l.require_client_id,
        })).collect::<Vec<_>>()})
    }

    #[allow(clippy::too_many_lines)] // one ordered list of checks
    fn check(&self, cx: &CheckCx<'_>) -> Result<Checked, Problem> {
        let lines = Self::lines(cx.value)?;
        // The facts the reload that applies this will use, not the ones from the last bind: when
        // the host's addresses changed in between, the weakening is judged on what will happen.
        let host = crate::gate_host::read();
        let bad = |why: String| Problem::new(Code::InvalidConfig, format!("`listeners`: {why}"));
        // Exactly the listeners this node runs: the setting is per listener, nothing is added or
        // removed here (the listeners themselves are the `listen` setting's).
        for line in &lines {
            if !cx
                .cfg
                .listen
                .iter()
                .any(|l| l.proto == line.proto && l.addr == line.addr)
            {
                return Err(bad(format!(
                    "{} isn't a listener {} runs",
                    line.name(),
                    cx.node
                )));
            }
            if line.setting.is_some() && !line.proto.needs_tls() {
                return Err(bad(format!(
                    "{} can't carry a device key (only DoT, DoH, DoH3 and DoQ can), so it has no setting here",
                    line.name()
                )));
            }
        }
        if let Some(l) = cx
            .cfg
            .listen
            .iter()
            .find(|l| !lines.iter().any(|x| x.proto == l.proto && x.addr == l.addr))
        {
            return Err(bad(format!(
                "{}://{} is missing; name every listener",
                proto_word(l.proto),
                l.addr
            )));
        }
        let mut changes: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        for l in &cx.cfg.listen {
            let Some(line) = lines
                .iter()
                .find(|x| x.proto == l.proto && x.addr == l.addr)
            else {
                continue;
            };
            if line.setting == l.require_client_id {
                continue;
            }
            let d = l.default_gate(host);
            let (now, public) = (l.gated(host), d.public_exposure());
            let after = wrendns_config::gate::effective_gate(
                l.proto.needs_tls(),
                line.setting,
                l.addr.ip(),
                host,
            );
            changes.push(format!(
                "{}: {} ({}) becomes {} ({})",
                line.name(),
                setting_word(l.require_client_id),
                gate_word(now),
                setting_word(line.setting),
                gate_word(after),
            ));
            if now && !after && public {
                warnings.push(format!(
                    "{} is on a public address. With the device key off, only [access] allowed_networks keeps it from being an open resolver for the whole internet; a mistake in that list makes it one.",
                    line.name()
                ));
            } else if now && !after {
                warnings.push(format!(
                    "{} will answer a query without a device key, from any address the allowed networks let in.",
                    line.name()
                ));
            }
            if !now && after {
                warnings.push(format!(
                    "{} will refuse every query that carries no known device key, from any address, your own network included, until each device uses its key (a configured `id:` match key of the key shape).",
                    line.name()
                ));
            }
            if line.setting.is_none() && wrendns_config::is_wildcard(l.addr.ip()) && !d.on() {
                warnings.push(format!(
                    "{} binds every address and this host has no public IPv4 address, so the default is off. If it is reachable from the internet (an address added later, IPv6, a forwarded port), set it on.",
                    line.name()
                ));
            }
        }
        let defaults: Vec<String> = cx
            .cfg
            .listen
            .iter()
            .filter(|l| l.proto.needs_tls())
            .map(|l| {
                format!(
                    "{}://{}: the default is {}",
                    proto_word(l.proto),
                    l.addr,
                    l.default_gate(host).describe()
                )
            })
            .collect();
        let mut effect = if changes.is_empty() {
            format!("Changes no listener's device key setting on {}.", cx.node)
        } else {
            format!(
                "Changes the device key setting on {} (a reload applies it; a DoT, DoH, DoH3 or DoQ listener whose effective gate changes is closed and bound again, ending its open connections, and, if its certificate cannot be loaded, is closed when the gate was turned on and keeps its gate when it was turned off): {}.",
                cx.node,
                changes.join("; ")
            )
        };
        if !defaults.is_empty() {
            effect.push_str(" For reference, ");
            effect.push_str(&defaults.join("; "));
            effect.push('.');
        }
        // REQ: DNS-901 — a gate that was on and is off afterwards, judged with the host's facts (the
        // row's own `weakens` cannot see them).
        let weakening =
            wrendns_config::guarded::listen_gate_weakened(&self.current(cx.cfg), cx.value, host);
        Ok(Checked {
            effect,
            warnings,
            weakening,
            ..Checked::default()
        })
    }

    fn overlay(&self, cfg: &mut Config, value: &Value) {
        let Ok(lines) = Self::lines(value) else {
            return;
        };
        for l in &mut cfg.listen {
            if l.proto.needs_tls()
                && let Some(line) = lines
                    .iter()
                    .find(|x| x.proto == l.proto && x.addr == l.addr)
            {
                l.require_client_id = line.setting;
            }
        }
    }
}

/// The production rows, built once (the merge path asks for an applier without an engine).
fn table() -> &'static [RowDef] {
    static TABLE: OnceLock<Vec<RowDef>> = OnceLock::new();
    TABLE.get_or_init(rows)
}

/// Puts the stored guarded values that are in force into `cfg` (REQ: API-902, ADR-956 §2).
///
/// Only this node's entries, only those that are `active` or on `probation` (a `staged` entry
/// waits for the next start), never when `WRENDNS_IGNORE_GUARDED` is set, never one a local clear
/// is suppressing, and never a field a file sets: the file wins (ADR-040, ADR-957).
pub(crate) fn overlay(cfg: &mut Config, own: &Config, entries: &[Stored], state: Option<&State>) {
    let Some(me) = super::this_node() else { return };
    overlay_with(cfg, own, entries, state, table(), &me, super::ignored());
}

/// [`overlay`] with the rows, the node's name and the ignore switch passed in.
pub(crate) fn overlay_with(
    cfg: &mut Config,
    own: &Config,
    entries: &[Stored],
    state: Option<&State>,
    defs: &[RowDef],
    me: &str,
    ignored: bool,
) {
    if ignored {
        return;
    }
    let suppressed = state.map(store::suppressed).unwrap_or_default();
    // REQ: API-902 (T27.14c, design 4) — `listen` is overlaid before `listen-access`, whatever order
    // the entries are stored in, so the gate lines apply to the list the node runs.
    let mut mine: Vec<&Stored> = entries.iter().filter(|e| e.node == me).collect();
    mine.sort_by_key(|e| e.id != guarded::LISTEN);
    for e in mine {
        if !matches!(e.state, EntryState::Active | EntryState::Probation) {
            continue;
        }
        if suppressed.get(&e.id).is_some_and(|d| *d == e.digest()) {
            continue;
        }
        // A confirmed listener that couldn't bind at this start runs on the file's value.
        if super::probation::fell_back(&e.id) {
            continue;
        }
        let Some(def) = defs.iter().find(|d| d.row.id == e.id) else {
            // A row this build doesn't have (an entry from a newer node): ignored (CLU-010).
            continue;
        };
        if def.row.mode == Mode::Action {
            continue;
        }
        let by_file = def.row.paths.iter().any(|p| {
            own.file_set
                .iter()
                .any(|k| k == p || k.strip_prefix(p).is_some_and(|r| r.starts_with('.')))
        });
        if by_file {
            continue;
        }
        def.applier.overlay(cfg, &e.value);
    }
}

/// The test rows' appliers: they exist only in a build with the cargo feature `e2e`, and in the
/// unit tests of this crate.
#[cfg(any(test, feature = "e2e"))]
pub(crate) mod test {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use serde_json::Value;
    use wrendns_api::BoxFuture;
    use wrendns_api::problem::{Code, Problem};
    use wrendns_config::Config;

    use super::super::engine::{Applier, CheckCx, Checked, Staged, WindowGuard};
    use super::super::host::{Host, ProofSocket};
    use std::sync::Arc;

    fn label(v: &Value) -> Result<String, Problem> {
        let l = v.get("label").and_then(Value::as_str).unwrap_or("");
        if l.is_empty() || l.len() > 40 || l.chars().any(char::is_control) {
            return Err(Problem::new(
                Code::InvalidConfig,
                "`label` must be 1 to 40 characters",
            ));
        }
        Ok(l.to_owned())
    }

    /// `e2e-immediate`: `{label, weaken?}`.
    pub(crate) struct Immediate;
    impl Applier for Immediate {
        fn current(&self, _cfg: &Config) -> Value {
            Value::Null
        }
        fn check(&self, cx: &CheckCx<'_>) -> Result<Checked, Problem> {
            let l = label(cx.value)?;
            Ok(Checked {
                effect: format!("Sets the test label to `{l}` on {} at once.", cx.node),
                ..Checked::default()
            })
        }
    }

    /// `e2e-staged`: `{label, fail?}`; `fail` makes the simulated start unhealthy.
    pub(crate) struct StagedRow;
    impl Applier for StagedRow {
        fn current(&self, _cfg: &Config) -> Value {
            Value::Null
        }
        fn check(&self, cx: &CheckCx<'_>) -> Result<Checked, Problem> {
            let l = label(cx.value)?;
            Ok(Checked {
                effect: format!("Stages the test label `{l}` for {}'s next start.", cx.node),
                restart_required: true,
                ..Checked::default()
            })
        }
    }

    /// `e2e-window`: `{port}`: a temporary parallel listener on `127.0.0.1:<port>` that serves the
    /// API for the window; the confirming request has to arrive there.
    pub(crate) struct Window;

    struct Guard(Arc<dyn ProofSocket>);
    impl WindowGuard for Guard {
        fn commit(&self) -> BoxFuture<Result<(), Problem>> {
            self.0.close();
            Box::pin(std::future::ready(Ok(())))
        }
        fn abort(&self) -> BoxFuture<()> {
            self.0.close();
            Box::pin(std::future::ready(()))
        }
    }

    /// `e2e-probe`: `{fail?}`: nothing is bound; the node asks its own first UDP listener (or, with
    /// `fail`, a closed port) the probe question, and the change is confirmed when that answers.
    pub(crate) struct Probe;

    struct NoSocket;
    impl WindowGuard for NoSocket {
        fn commit(&self) -> BoxFuture<Result<(), Problem>> {
            Box::pin(std::future::ready(Ok(())))
        }
        fn abort(&self) -> BoxFuture<()> {
            Box::pin(std::future::ready(()))
        }
    }

    impl Applier for Probe {
        fn current(&self, _cfg: &Config) -> Value {
            Value::Null
        }
        fn check(&self, cx: &CheckCx<'_>) -> Result<Checked, Problem> {
            let fail = cx.value.get("fail").and_then(Value::as_bool) == Some(true);
            Ok(Checked {
                effect: format!(
                    "Asks the node's own DNS listener a test question for the confirmation window{}.",
                    if fail {
                        " (aimed at a closed port, so it fails)"
                    } else {
                        ""
                    }
                ),
                ..Checked::default()
            })
        }
        fn stage(
            &self,
            host: Arc<dyn Host>,
            _node: String,
            value: Value,
            _access: Option<Value>,
            _facts: Option<wrendns_config::HostFacts>,
        ) -> BoxFuture<Result<Staged, Problem>> {
            Box::pin(async move {
                let fail = value.get("fail").and_then(Value::as_bool) == Some(true);
                let addr = if fail {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1)
                } else {
                    host.running_config()
                        .listen
                        .iter()
                        .find(|l| l.proto == wrendns_config::ListenProto::Udp)
                        .map(|l| crate::probes::reachable(l.addr))
                        .ok_or_else(|| {
                            Problem::new(Code::Conflict, "the node has no UDP listener")
                        })?
                };
                Ok(Staged {
                    guard: Arc::new(NoSocket),
                    proof_addr: None,
                    new_address: None,
                    pending_proxies: None,
                    dns_probes: vec![super::super::dns_proof::DnsProbe {
                        proto: wrendns_config::ListenProto::Udp,
                        addr,
                        path: None,
                        gated: false,
                        evidence: None,
                    }],
                })
            })
        }
    }

    fn port(v: &Value) -> Result<u16, Problem> {
        v.get("port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p >= 1024)
            .ok_or_else(|| Problem::new(Code::InvalidConfig, "`port` must be 1024 to 65535"))
    }

    impl Applier for Window {
        fn current(&self, _cfg: &Config) -> Value {
            Value::Null
        }
        fn check(&self, cx: &CheckCx<'_>) -> Result<Checked, Problem> {
            let p = port(cx.value)?;
            Ok(Checked {
                effect: format!(
                    "Opens a test listener on 127.0.0.1:{p} next to the current one, for the confirmation window."
                ),
                proof_port: Some(p),
                ..Checked::default()
            })
        }
        fn stage(
            &self,
            host: Arc<dyn Host>,
            _node: String,
            value: Value,
            _access: Option<Value>,
            _facts: Option<wrendns_config::HostFacts>,
        ) -> BoxFuture<Result<Staged, Problem>> {
            Box::pin(async move {
                let p = port(&value)?;
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), p);
                let sock = host.proof_socket(addr).await.map_err(|why| {
                    Problem::new(Code::Conflict, format!("couldn't bind {addr}: {why}"))
                })?;
                let bound = sock.addr();
                Ok(Staged {
                    guard: Arc::new(Guard(sock)),
                    proof_addr: Some(bound),
                    new_address: Some(format!("http://{bound}/")),
                    pending_proxies: None,
                    dns_probes: Vec::new(),
                })
            })
        }
    }
}

/// The value an entry of `id` holds for this node, if it is in force (for tests and the CLI).
#[allow(dead_code)]
pub(crate) fn value_in_force(entries: &[Stored], node: &str, id: &str) -> Option<Value> {
    entries
        .iter()
        .find(|e| e.node == node && e.id == id)
        .filter(|e| matches!(e.state, EntryState::Active | EntryState::Probation))
        .map(|e| e.value.clone())
}

#[cfg(test)]
mod redirect_tests {
    use serde_json::json;
    use wrendns_api::auth::Actor;
    use wrendns_api::guarded::GuardedCaller;

    use super::*;

    fn caller() -> GuardedCaller {
        GuardedCaller {
            actor: Actor {
                name: "admin".to_owned(),
                kind: "session",
                remote: None,
                reason: None,
            },
            username: "admin".to_owned(),
            session: None,
            signed_in_at: None,
            arrived_on: None,
            remote: None,
            remote_under_pending: None,
            tls: false,
        }
    }

    fn check(cfg: &Config, value: &Value) -> Result<Checked, Problem> {
        let (options, c) = (Value::Null, caller());
        HttpRedirect.check(&CheckCx {
            cfg,
            node: "pi-a",
            value,
            options: &options,
            caller: &c,
            host: &super::super::host::StubHost::default(),
            access: None,
        })
    }

    fn with_tls() -> Config {
        let mut cfg = Config::default();
        cfg.api.tls = Some(wrendns_config::ApiTls {
            self_signed: true,
            ..wrendns_config::ApiTls::default()
        });
        cfg
    }

    // REQ: API-003, API-902 (T24.44, ADR-1053) — the dry run: a good address stages for the next
    // start and says what it opens; empty turns it off; a bad address, port 0, the API's own
    // address, and (outside the end-to-end build) no TLS are refused.
    #[test]
    fn api_003_redirect_dry_run() {
        let cfg = with_tls();
        let ok = check(&cfg, &json!({"address": "0.0.0.0:80"})).unwrap();
        assert!(ok.restart_required && ok.effect.contains("0.0.0.0:80"));
        assert!(
            ok.warnings
                .iter()
                .any(|w| w.contains("CAP_NET_BIND_SERVICE"))
        );
        let high = check(&cfg, &json!({"address": "0.0.0.0:8080"})).unwrap();
        assert_eq!(high.warnings, Vec::<String>::new());
        let off = check(&cfg, &json!({"address": ""})).unwrap();
        assert!(off.restart_required && off.effect.contains("off"));
        assert!(check(&cfg, &json!({"address": null})).is_ok());
        for bad in [
            "80",
            "host:80",
            "0.0.0.0:0",
            "0.0.0.0:8053",
            "0.0.0.0:99999",
        ] {
            assert!(check(&cfg, &json!({"address": bad})).is_err(), "{bad}");
        }
        assert!(check(&cfg, &json!({"address": 80})).is_err());
        #[cfg(not(feature = "e2e"))]
        assert!(check(&Config::default(), &json!({"address": "0.0.0.0:80"})).is_err());
    }

    // REQ: API-003, API-902 (T24.44) — the stored value enters the merged configuration only next
    // to `[api] tls`, (the file wins before this runs).
    #[test]
    fn api_003_redirect_overlay_needs_tls() {
        let mut cfg = with_tls();
        HttpRedirect.overlay(&mut cfg, &json!({"address": "0.0.0.0:80"}));
        assert_eq!(cfg.api.http_redirect, Some("0.0.0.0:80".parse().unwrap()));
        HttpRedirect.overlay(&mut cfg, &json!({"address": ""}));
        assert_eq!(cfg.api.http_redirect, None);
        let mut plain = Config::default();
        HttpRedirect.overlay(&mut plain, &json!({"address": "0.0.0.0:80"}));
        assert_eq!(plain.api.http_redirect, None);
        assert_eq!(HttpRedirect.current(&cfg), json!({"address": null}));
    }
}

#[cfg(test)]
pub(crate) mod listen_access_tests {
    use serde_json::json;
    use wrendns_api::auth::Actor;
    use wrendns_api::guarded::GuardedCaller;
    use wrendns_config::{ListenProto, Listener, SafeString, TlsFiles};

    use super::*;

    fn caller() -> GuardedCaller {
        GuardedCaller {
            actor: Actor {
                name: "admin".to_owned(),
                kind: "session",
                remote: None,
                reason: None,
            },
            username: "admin".to_owned(),
            session: None,
            signed_in_at: None,
            arrived_on: None,
            remote: None,
            remote_under_pending: None,
            tls: false,
        }
    }

    fn listener(proto: ListenProto, addr: &str, gate: Option<bool>) -> Listener {
        Listener {
            proto,
            addr: addr.parse().unwrap(),
            path: None,
            tls: proto.needs_tls().then(|| TlsFiles {
                cert: SafeString::new("/c.pem").unwrap(),
                key: SafeString::new("/k.pem").unwrap(),
            }),
            proxy_protocol: false,
            max_connections: None,
            max_connections_per_address: None,
            require_client_id: gate,
        }
    }

    /// A public DoT listener, a LAN DoH one, a wildcard DoQ one and a plain UDP one.
    pub(crate) fn cfg() -> Config {
        Config {
            listen: vec![
                listener(ListenProto::Dot, "203.0.113.5:853", None),
                listener(ListenProto::Doh, "192.168.1.2:443", None),
                listener(ListenProto::Doq, "0.0.0.0:853", None),
                listener(ListenProto::Udp, "192.168.1.2:53", None),
            ],
            ..Config::default()
        }
    }

    #[allow(clippy::needless_pass_by_value)] // callers write the three states inline
    pub(crate) fn value(dot: Value, doh: Value, doq: Value) -> Value {
        json!({"listeners": [
            {"proto": "dot", "addr": "203.0.113.5:853", "require_client_id": dot},
            {"proto": "doh", "addr": "192.168.1.2:443", "require_client_id": doh},
            {"proto": "doq", "addr": "0.0.0.0:853", "require_client_id": doq},
            {"proto": "udp", "addr": "192.168.1.2:53", "require_client_id": null},
        ]})
    }

    /// A host with private IPv4 addresses only, unless a test says otherwise.
    fn check(cfg: &Config, v: &Value) -> Result<Checked, Problem> {
        check_on(
            wrendns_config::HostFacts {
                public_ipv4: Some(false),
                global_ipv6: false,
            },
            cfg,
            v,
        )
    }

    fn check_on(
        host: wrendns_config::HostFacts,
        cfg: &Config,
        v: &Value,
    ) -> Result<Checked, Problem> {
        let (options, c) = (Value::Null, caller());
        crate::gate_host::with_facts(host, || {
            ListenAccess.check(&CheckCx {
                cfg,
                node: "pi-a",
                value: v,
                options: &options,
                caller: &c,
                host: &super::super::host::StubHost::default(),
                access: None,
            })
        })
    }

    // REQ: DNS-901, API-902 (T27.14) — the value now in force names every listener with its stored
    // setting, and is the shape a change is judged against.
    #[test]
    fn dns_901_listen_access_current_lists_every_listener() {
        let mut c = cfg();
        c.listen[0].require_client_id = Some(true);
        let cur = ListenAccess.current(&c);
        assert_eq!(cur["listeners"].as_array().unwrap().len(), 4);
        assert_eq!(cur["listeners"][0]["require_client_id"], json!(true));
        assert_eq!(cur["listeners"][1]["require_client_id"], Value::Null);
        // Unchanged: no change is described, and the defaults are explained per listener.
        let ok = check(&c, &cur).unwrap();
        assert!(ok.effect.contains("Changes no listener"), "{}", ok.effect);
        assert!(ok.effect.contains("because the address is public"));
        assert!(ok.effect.contains("because the address is not public"));
        assert!(
            ok.effect
                .contains("binds every address and this host has no public IPv4 address"),
            "{}",
            ok.effect
        );
        assert_eq!(ok.warnings, Vec::<String>::new());
    }

    // REQ: DNS-901 (ADR-1090 point 1) — turning the gate off on a public listener is flagged with
    // the open-resolver warning, and is a weakening; turning it on warns about refused devices.
    #[test]
    fn dns_901_listen_access_off_on_public_warns_and_weakens() {
        let c = cfg();
        let off = value(json!(false), Value::Null, Value::Null);
        let r = check(&c, &off).unwrap();
        assert!(
            r.warnings.iter().any(|w| w.contains("open resolver")),
            "{:?}",
            r.warnings
        );
        assert!(r.effect.contains("dot://203.0.113.5:853"));
        assert!(r.weakening);
        // On for a LAN listener: not a weakening, but a warning that keyless devices are refused.
        let on = value(Value::Null, json!(true), Value::Null);
        let r = check(&c, &on).unwrap();
        assert!(r.warnings.iter().any(|w| w.contains("refuse every query")));
        assert!(!r.weakening);
        // A wildcard bind put back to the default says why that is off.
        let mut c2 = cfg();
        c2.listen[2].require_client_id = Some(true);
        let back = value(Value::Null, Value::Null, Value::Null);
        let r = check(&c2, &back).unwrap();
        assert!(r.warnings.iter().any(|w| w.contains("binds every address")));
    }

    // REQ: DNS-901 (ADR-1090 point 2) — the wildcard listener's default follows the host: on with
    // a public IPv4 address (or an unreadable interface list), off with private IPv4 only; the
    // review says why, and turning the gate off then is a weakening with the open-resolver warning.
    #[test]
    fn dns_901_listen_access_wildcard_follows_the_host() {
        use wrendns_config::HostFacts;
        let public = HostFacts {
            public_ipv4: Some(true),
            global_ipv6: false,
        };
        let c = cfg();
        let cur = ListenAccess.current(&c);
        let off = value(Value::Null, Value::Null, json!(false));
        let r = check_on(public, &c, &off).unwrap();
        assert!(r.weakening, "wildcard gated by the default, then off");
        assert!(
            r.warnings.iter().any(|w| w.contains("open resolver")),
            "{:?}",
            r.warnings
        );
        let same = check_on(public, &c, &cur).unwrap();
        assert!(
            same.effect.contains("this host has a public IPv4 address"),
            "{}",
            same.effect
        );
        for facts in [
            HostFacts::UNKNOWN,
            HostFacts {
                public_ipv4: Some(true),
                global_ipv6: true,
            },
        ] {
            assert!(check_on(facts, &c, &off).unwrap().weakening);
        }
        let private = HostFacts {
            public_ipv4: Some(false),
            global_ipv6: true,
        };
        let r = check_on(private, &c, &off).unwrap();
        assert!(!r.weakening, "a wildcard that was never gated");
        let none = check_on(private, &c, &cur).unwrap();
        assert!(
            none.effect
                .contains("global IPv6 address, which does not turn the default on"),
            "{}",
            none.effect
        );
    }

    // REQ: DNS-901 — what is refused: a listener the node doesn't run, a missing one, a key on a
    // plain transport (named without any flag advice), a repeated one, a stray field and bad types.
    #[test]
    fn dns_901_listen_access_validation() {
        let c = cfg();
        let good = value(Value::Null, Value::Null, Value::Null);
        assert!(check(&c, &good).is_ok());
        let mut udp_set = good.clone();
        udp_set["listeners"][3]["require_client_id"] = json!(true);
        let e = check(&c, &udp_set).unwrap_err();
        assert!(
            e.detail.contains("can't carry a device key"),
            "{}",
            e.detail
        );
        assert!(!e.detail.contains("require_client_id"), "{}", e.detail);
        let mut missing = good.clone();
        missing["listeners"].as_array_mut().unwrap().pop();
        assert!(
            check(&c, &missing)
                .unwrap_err()
                .detail
                .contains("is missing")
        );
        let mut extra = good.clone();
        extra["listeners"]
            .as_array_mut()
            .unwrap()
            .push(json!({"proto": "dot", "addr": "203.0.113.9:853"}));
        assert!(
            check(&c, &extra)
                .unwrap_err()
                .detail
                .contains("isn't a listener")
        );
        let mut twice = good.clone();
        let first = twice["listeners"][0].clone();
        twice["listeners"].as_array_mut().unwrap().push(first);
        assert!(check(&c, &twice).unwrap_err().detail.contains("twice"));
        let mut stray = good.clone();
        stray["listeners"][0]["tls"] = json!({});
        assert!(check(&c, &stray).is_err());
        for bad in [
            json!({"listeners": "x"}),
            json!({}),
            json!({"listeners": [1]}),
            json!({"listeners": [{"proto": "ftp", "addr": "1.2.3.4:5"}]}),
            json!({"listeners": [{"proto": "dot", "addr": "nope"}]}),
        ] {
            assert!(check(&c, &bad).is_err(), "{bad}");
        }
        let mut stringly = good;
        stringly["listeners"][0]["require_client_id"] = json!("yes");
        assert!(check(&c, &stringly).is_err());
    }

    // REQ: DNS-901 (ADR-1090 point 1) — the stored value enters the merged configuration per
    // listener (null is the default, true and false are explicit), never on a plain transport, and
    // a listener it doesn't name is untouched.
    #[test]
    fn dns_901_listen_access_overlay() {
        let mut c = cfg();
        ListenAccess.overlay(&mut c, &value(json!(false), json!(true), Value::Null));
        assert_eq!(c.listen[0].require_client_id, Some(false));
        assert_eq!(c.listen[1].require_client_id, Some(true));
        assert_eq!(c.listen[2].require_client_id, None);
        assert!(
            !c.listen[0].gated(wrendns_config::HostFacts::UNKNOWN),
            "an explicit false opens a public listener"
        );
        let mut udp = value(Value::Null, Value::Null, Value::Null);
        udp["listeners"][3]["require_client_id"] = json!(true);
        ListenAccess.overlay(&mut c, &udp);
        assert_eq!(c.listen[3].require_client_id, None);
        let mut d = cfg();
        ListenAccess.overlay(
            &mut d,
            &json!({"listeners": [
                {"proto": "dot", "addr": "203.0.113.5:853", "require_client_id": true},
                {"proto": "dot", "addr": "203.0.113.99:853", "require_client_id": false},
            ]}),
        );
        assert_eq!(d.listen[0].require_client_id, Some(true));
        assert_eq!(d.listen[1].require_client_id, None);
        ListenAccess.overlay(&mut d, &json!({"listeners": 3}));
        assert_eq!(d.listen[0].require_client_id, Some(true));
    }
}

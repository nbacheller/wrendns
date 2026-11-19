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
        #[cfg(feature = "e2e")]
        "e2e-immediate" | "e2e-file" => Some(Arc::new(test::Immediate)),
        #[cfg(feature = "e2e")]
        "e2e-window" => Some(Arc::new(test::Window)),
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
        if addr == cx.cfg.api.listen {
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
    for e in entries.iter().filter(|e| e.node == me) {
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

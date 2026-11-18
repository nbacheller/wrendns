//! REQ: API-902, CLU-004 (T27.13; ADR-956 §1) — what each registry row does on this node.
//!
//! The registry (`telltale_config::guarded`) is data; an [`Applier`] is the behaviour behind a row:
//! its dry-run check, how its stored value enters the merged configuration, and (for a `window`
//! row) how its new sockets are bound next to the old ones. T27.14 to T27.17 add a row, a check
//! and an apply step each, here. This task adds none of the real ones: it builds the framework and,
//! under the cargo feature `e2e` only, three test rows (an `immediate`, a `window` and a `staged`
//! one) so the tests and the Playwright suite can drive every path.

use std::sync::{Arc, OnceLock};

use serde_json::Value;
use telltale_config::Config;
use telltale_config::guarded::{self, Mode};
use telltale_store::state::State;

use super::engine::{Applier, NoOp, RowDef};
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
        #[cfg(feature = "e2e")]
        "e2e-immediate" => Some(Arc::new(test::Immediate)),
        #[cfg(feature = "e2e")]
        "e2e-window" => Some(Arc::new(test::Window)),
        #[cfg(feature = "e2e")]
        "e2e-staged" => Some(Arc::new(test::StagedRow)),
        _ => None,
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
/// waits for the next start), never when `TELLTALE_IGNORE_GUARDED` is set, never one a local clear
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
    use telltale_api::BoxFuture;
    use telltale_api::problem::{Code, Problem};
    use telltale_config::Config;

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

//! REQ: API-902, API-006, AGT-009 (T27.13; ADR-914, ADR-956, ADR-957) — the guarded settings.
//!
//! The settings that can lock every admin out, put credentials on the wire, re-encrypt or lose
//! the secret store, or replace a node's configuration are not edited through the ordinary
//! kinds: each has a *registry row* here, and one framework (`wrendns/src/guarded/`) does the
//! preview, the typed phrase, the confirmation window, the staging, the audit and the recovery
//! for all of them. A row is data plus pure functions; what it does to a running node is the
//! node's `Applier` for that ID. T27.14 to T27.17 add a row, a dry-run check and an apply step
//! each: nothing else.
//!
//! This module is pure (no I/O): the registry, the `weakens` rules of ADR-914 as functions over
//! the old and new value, and the table of the paths ADR-914 calls guarded, so a test can fail
//! when one is missing from both the registry and the list of rows still to come.

use serde_json::Value;

/// How a change to a guarded setting takes effect (ADR-956 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Applied live as pending and kept only if confirmed through the new address (§3).
    Window,
    /// Written, then applied by the same reload the API uses. No window.
    Immediate,
    /// Written as staged, applied at the next start (§4); the node restarts only on the admin's
    /// explicit "Restart now" (§4a).
    Staged,
    /// An operation, not a value: its own transactional steps, the same preview, phrase, audit
    /// and agent rules.
    Action,
}

impl Mode {
    /// The word the API and the audit log use.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Window => "window",
            Self::Immediate => "immediate",
            Self::Staged => "staged",
            Self::Action => "action",
        }
    }
}

/// What a confirming request has to prove (ADR-956 §3, "proof hook"). A `window` row has one; a
/// row with no proof is not a `window` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proof {
    /// The request (or the node's own probe) arrived on the new socket.
    NewSocket,
    /// The TLS handshake used the new certificate.
    NewCert,
    /// The request passes under the new proxy list, and shows the client address now seen.
    ProxyList,
}

impl Proof {
    /// The word the API uses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NewSocket => "new_socket",
            Self::NewCert => "new_cert",
            Self::ProxyList => "proxy_list",
        }
    }
}

/// One guarded setting.
#[derive(Debug, Clone, Copy)]
pub struct Row {
    /// The setting's name in the API and in the phrase (`listen`, `secrets-key`).
    pub id: &'static str,
    /// What the control is called.
    pub label: &'static str,
    /// The configuration paths it covers (dotted; empty for an action with no path).
    pub paths: &'static [&'static str],
    pub mode: Mode,
    /// For a `window` row: what a confirmation must prove.
    pub proof: Option<Proof>,
    /// Whether `new` is weaker than `old` (ADR-914's list): such a change is marked in red and
    /// needs a sign-in within the last 10 minutes. Pure.
    pub weakens: fn(old: &Value, new: &Value) -> bool,
    /// Compiled only under the cargo feature `e2e`: a row the tests use (never a release).
    pub test_only: bool,
}

/// A setting that never weakens anything.
pub fn never(_old: &Value, _new: &Value) -> bool {
    false
}

/// The ID of the restart action (ADR-956 §4a).
pub const RESTART_NOW: &str = "restart-now";

/// The registry's rows in a build: the framework's own, and with the cargo feature `e2e` the
/// test rows. T27.14 to T27.17 add theirs to [`REAL`].
pub fn rows() -> Vec<&'static Row> {
    #[allow(unused_mut)] // extended only in a build with the `e2e` feature
    let mut v: Vec<&'static Row> = REAL.iter().collect();
    #[cfg(feature = "e2e")]
    v.extend(TEST.iter());
    v
}

/// The row with this ID, if the build has one.
pub fn row(id: &str) -> Option<&'static Row> {
    rows().into_iter().find(|r| r.id == id)
}

/// Whether this build compiled the test rows in (a release must say `false`).
pub const TEST_ROWS_COMPILED: bool = cfg!(feature = "e2e");

/// The rows that are always there.
static REAL: &[Row] = &[
    // REQ: API-902 (ADR-956 §4a) — the restart action has no configuration path.
    Row {
        id: RESTART_NOW,
        label: "Restart now",
        paths: &[],
        mode: Mode::Action,
        proof: None,
        weakens: never,
        test_only: false,
    },
    // REQ: API-003, API-902 (T24.44, ADR-1053) — the plain-HTTP redirect listener. `staged`: it is
    // opened with the API at the next start, never rebinding a live socket; a bind failure only
    // logs. It sends browsers to HTTPS and serves nothing else, so it never weakens anything.
    Row {
        id: API_HTTP_REDIRECT,
        label: "HTTP to HTTPS redirect",
        paths: &["api.http_redirect"],
        mode: Mode::Staged,
        proof: None,
        weakens: never,
        test_only: false,
    },
    // REQ: DNS-901, API-902 (T27.14, ADR-1090 point 1) — the known-ID gate of each DoT, DoH, DoH3
    // and DoQ listener: unset (the default), `true` or `false`. `immediate`: it moves no
    // address and touches no API socket, so it cannot lock an admin out; a reload applies it (a
    // listener whose effective gate changes is closed and bound again; when its certificate cannot
    // be loaded it fails closed: a gate turned on closes the old ungated socket, a gate turned off
    // keeps the old gated one) and a failed reload, or a listener left closed or not as configured,
    // puts the previous value back. Turning a listener's gate
    // off weakens it (a red mark and a sign-in within 10 minutes). The listeners themselves (address,
    // port, protocol, TLS) are the `listen` row's, still to come.
    Row {
        id: LISTEN_ACCESS,
        label: "Listener access (device key required)",
        paths: &["listen.require_client_id"],
        mode: Mode::Immediate,
        proof: None,
        // The rule needs the host's address facts (what a wildcard listener's default resolves
        // to), which a pure `fn(old, new)` cannot see: the applier's `check` reports the weakening
        // with `listen_gate_weakened(old, new, host)` (REQ: DNS-901, ADR-1090 point 2).
        weakens: never,
        test_only: false,
    },
    // REQ: API-902, DNS-001, DNS-901, CLU-004 (T27.14c; ADR-914, ADR-956, ADR-1090, ADR-1098) — the
    // node's DNS listeners, the whole list replaced as a list. `window`: a new listener is bound next
    // to the running ones and kept only when the node's own test query to it is answered and the admin
    // confirms. It never touches an API socket. Weakening depends on the host's address facts, which a
    // pure `fn(old, new)` cannot see, so the applier's `check` sets it (design 4, rules a to c). It is
    // listed after `listen-access`, so `covering("listen.require_client_id")` finds that row first.
    Row {
        id: LISTEN,
        label: "Listeners",
        paths: &["listen"],
        mode: Mode::Window,
        proof: Some(Proof::NewSocket),
        weakens: never,
        test_only: false,
    },
];

/// The ID of the DNS listeners row (T27.14c).
pub const LISTEN: &str = "listen";

/// The ID of the HTTP-to-HTTPS redirect row (T24.44, ADR-1053).
pub const API_HTTP_REDIRECT: &str = "api-http-redirect";

/// The ID of the known-ID gate row (T27.14, DNS-901).
pub const LISTEN_ACCESS: &str = "listen-access";

/// REQ: DNS-901 (ADR-1090 point 1) — the effective gate of each listener in a `listen-access`
/// value (`{"listeners": [{"proto", "addr", "require_client_id"}]}`), keyed by `proto://addr`:
/// an explicit setting wins, unset follows `crate::default_gate` (the host's address facts are
/// passed in), and only an encrypted DNS transport can carry a key at all.
pub fn gate_map(
    v: &Value,
    host: crate::gate::HostFacts,
) -> std::collections::BTreeMap<String, bool> {
    let mut out = std::collections::BTreeMap::new();
    let Some(list) = v.get("listeners").and_then(Value::as_array) else {
        return out;
    };
    for l in list {
        let (Some(proto), Some(addr)) = (
            l.get("proto").and_then(Value::as_str),
            l.get("addr").and_then(Value::as_str),
        ) else {
            continue;
        };
        let Ok(sa) = addr.parse::<std::net::SocketAddr>() else {
            continue;
        };
        let ip = sa.ip();
        let carries = matches!(proto, "dot" | "doh" | "doh3" | "doq");
        let on = crate::gate::effective_gate(
            carries,
            l.get("require_client_id").and_then(Value::as_bool),
            ip,
            host,
        );
        // Keyed by the parsed address, so `[2001:db8:0::5]:853` and `[2001:db8::5]:853` are one listener.
        out.insert(format!("{proto}://{sa}"), on);
    }
    out
}

/// A listener whose gate was on and is off in `new` (DNS-901): the change opens it to every query
/// the access rules allow. A listener `new` doesn't name keeps its gate.
pub fn listen_gate_weakened(old: &Value, new: &Value, host: crate::gate::HostFacts) -> bool {
    let (before, after) = (gate_map(old, host), gate_map(new, host));
    after
        .iter()
        .any(|(k, on)| !on && before.get(k).copied().unwrap_or(false))
}

/// The rows the end-to-end tests use. They exist only in a build with the cargo feature `e2e`
/// (the e2e server is built with it, the release binary is not).
#[cfg(feature = "e2e")]
static TEST: &[Row] = &[
    // A row whose path the end-to-end server's file sets (`[telemetry.metrics] listen`): the control
    // is locked and shows "set by file" (ADR-040, ADR-956 §2).
    Row {
        id: "e2e-file",
        label: "Test setting (set by file)",
        paths: &["telemetry.metrics.listen"],
        mode: Mode::Immediate,
        proof: None,
        weakens: never,
        test_only: true,
    },
    Row {
        id: "e2e-immediate",
        label: "Test setting (immediate)",
        paths: &[],
        mode: Mode::Immediate,
        proof: None,
        weakens: weakens_flag,
        test_only: true,
    },
    Row {
        id: "e2e-window",
        label: "Test setting (confirm window)",
        paths: &[],
        mode: Mode::Window,
        proof: Some(Proof::NewSocket),
        weakens: never,
        test_only: true,
    },
    // T27.14b: a window row proved by the node's own DNS probe, not by a request on a new socket.
    Row {
        id: "e2e-probe",
        label: "Test setting (DNS probe proof)",
        paths: &[],
        mode: Mode::Window,
        proof: Some(Proof::NewSocket),
        weakens: never,
        test_only: true,
    },
    Row {
        id: "e2e-staged",
        label: "Test setting (needs a restart)",
        paths: &[],
        mode: Mode::Staged,
        proof: None,
        weakens: never,
        test_only: true,
    },
];

/// The test rows' rule: a value that says `"weaken": true` weakens.
#[cfg(feature = "e2e")]
fn weakens_flag(_old: &Value, new: &Value) -> bool {
    new.get("weaken").and_then(Value::as_bool) == Some(true)
}

/// The task that adds a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task {
    T27_14,
    T27_15,
    T27_16,
    T27_17,
}

/// One guarded setting ADR-914 and ADR-956 §1 name: its ID, the mode it will have, the
/// configuration paths it covers, and the task that adds its registry row. When the row exists
/// in [`rows`] the test checks that it agrees with this table; until then this is the record that
/// the path is guarded and has an owner.
#[derive(Debug, Clone, Copy)]
pub struct Planned {
    pub id: &'static str,
    pub mode: Mode,
    pub paths: &'static [&'static str],
    pub task: Task,
}

/// Every setting ADR-914 calls guarded, with the paths it covers (ADR-956 §1).
pub static PLANNED: &[Planned] = &[
    Planned {
        id: "api-address",
        mode: Mode::Window,
        paths: &["api.listen"],
        task: Task::T27_14,
    },
    Planned {
        id: "api-tls",
        mode: Mode::Window,
        paths: &["api.tls"],
        task: Task::T27_14,
    },
    Planned {
        id: "trusted-proxies",
        mode: Mode::Window,
        paths: &["api.trusted_proxies"],
        task: Task::T27_14,
    },
    Planned {
        id: "secret-file-dirs",
        mode: Mode::Immediate,
        paths: &["node.secret_file_dirs"],
        task: Task::T27_15,
    },
    Planned {
        id: "allow-secrets-over-http",
        mode: Mode::Immediate,
        paths: &["api.allow_secrets_over_http"],
        task: Task::T27_15,
    },
    Planned {
        id: "allow-insecure-basic",
        mode: Mode::Immediate,
        paths: &["auth.allow_insecure_basic"],
        task: Task::T27_15,
    },
    Planned {
        id: "secrets-key",
        mode: Mode::Staged,
        paths: &["node.secrets_key_file", "node.secrets_previous_key_file"],
        task: Task::T27_15,
    },
    Planned {
        id: "cluster-init",
        mode: Mode::Action,
        paths: &["cluster.init", "cluster.name", "cluster.listen"],
        task: Task::T27_16,
    },
    Planned {
        id: "cluster-join",
        mode: Mode::Action,
        paths: &["cluster.join_url", "cluster.bootstrap_secret_file"],
        task: Task::T27_16,
    },
    Planned {
        id: "cluster-leave",
        mode: Mode::Action,
        paths: &[],
        task: Task::T27_16,
    },
    Planned {
        id: "cluster-git",
        mode: Mode::Action,
        paths: &["cluster.git"],
        task: Task::T27_16,
    },
    Planned {
        id: "node-identity",
        mode: Mode::Staged,
        paths: &["node.name"],
        task: Task::T27_17,
    },
    Planned {
        id: "data-dir",
        mode: Mode::Staged,
        paths: &["node.data_dir"],
        task: Task::T27_17,
    },
    Planned {
        id: "watchdog",
        mode: Mode::Immediate,
        paths: &["watchdog"],
        task: Task::T27_17,
    },
    Planned {
        id: "file-paths",
        mode: Mode::Immediate,
        paths: &[
            "dnssec.trust_anchors_file",
            "identify.signatures_file",
            "local.hosts_files",
            "zone.file",
        ],
        task: Task::T27_17,
    },
];

/// Settings ADR-956 §1(b) keeps file-only: each can lock every admin out, and a guarded change
/// would need its own `would_lock_out_admins` dry run and recovery story. They never appear in
/// the registry.
pub static FILE_ONLY: &[&str] = &[
    "auth.oidc.disable_local_login",
    "auth.oidc.allowed_admin_networks",
    // The window itself is read from the file: a guarded change can't lengthen its own window.
    "api.confirm_window_secs",
];

/// The guarded ID that covers a configuration path (a path inside a covered section counts), from
/// the registry and the rows still to come.
pub fn covering(path: &str) -> Option<&'static str> {
    let hit = |p: &str| path == p || path.strip_prefix(p).is_some_and(|r| r.starts_with('.'));
    for r in rows() {
        if r.paths.iter().any(|p| hit(p)) {
            return Some(r.id);
        }
    }
    PLANNED
        .iter()
        .find(|p| p.paths.iter().any(|x| hit(x)))
        .map(|p| p.id)
}

/// REQ: API-902 (ADR-956 §2, ADR-040) — which of the guarded paths the configuration files (and the
/// environment layered over them) set, from the merged TOML tables: each present path, dotted. A
/// field a file sets wins over a guarded entry, and its control is locked. A path inside an array of
/// tables (`zone.file`) counts when any element has it.
pub fn explicit_paths(root: &toml::Table) -> Vec<String> {
    fn present(v: &toml::Value, segs: &[&str]) -> bool {
        let Some((first, rest)) = segs.split_first() else {
            return true;
        };
        match v {
            toml::Value::Table(t) => t.get(*first).is_some_and(|c| present(c, rest)),
            toml::Value::Array(a) => a.iter().any(|e| present(e, segs)),
            _ => false,
        }
    }
    let mut out: Vec<String> = Vec::new();
    let all = rows()
        .into_iter()
        .flat_map(|r| r.paths.iter().copied())
        .chain(PLANNED.iter().flat_map(|p| p.paths.iter().copied()));
    for path in all {
        let segs: Vec<&str> = path.split('.').collect();
        let hit = root.get(segs[0]).is_some_and(|v| present(v, &segs[1..]));
        if hit && !out.iter().any(|o| o == path) {
            out.push(path.to_owned());
        }
    }
    out
}

/// The phrase an admin types to confirm a change to `id` on `node` (ADR-914: the node ID and the
/// setting, for example `pi-a listen`; the restart action's is `<node> restart`).
pub fn phrase(node: &str, id: &str) -> String {
    if id == RESTART_NOW {
        format!("{node} restart")
    } else {
        format!("{node} {id}")
    }
}

// ---------------------------------------------------------------------------------------------
// ADR-914's weakening rules, as pure functions over the old and new value (JSON, as the API
// carries them). T27.14 to T27.17 point their rows' `weakens` at these.

fn strings(v: &Value) -> Vec<&str> {
    match v {
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
        Value::String(s) if !s.is_empty() => vec![s.as_str()],
        _ => Vec::new(),
    }
}

/// An entry in `new` that `old` doesn't have: adding a directory to `secret_file_dirs`, or an
/// entry to `trusted_proxies`.
pub fn entry_added(old: &Value, new: &Value) -> bool {
    let old = strings(old);
    strings(new).into_iter().any(|n| !old.contains(&n))
}

/// A switch turned on (`allow_secrets_over_http`, `allow_insecure_basic`).
pub fn turned_on(old: &Value, new: &Value) -> bool {
    old.as_bool() != Some(true) && new.as_bool() == Some(true)
}

/// The watchdog turned off (`watchdog.enabled`, or the whole section replaced by one that is).
pub fn watchdog_turned_off(old: &Value, new: &Value) -> bool {
    let on = |v: &Value| match v {
        Value::Bool(b) => *b,
        Value::Object(o) => o.get("enabled").and_then(Value::as_bool).unwrap_or(true),
        _ => true,
    };
    on(old) && !on(new)
}

/// Whether an address (`ip:port`, or an `ip`) is loopback only.
fn loopback(addr: &str) -> bool {
    let host = addr
        .rsplit_once(':')
        .map_or(addr, |(h, _)| h)
        .trim_matches(|c| c == '[' || c == ']');
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// `api.listen` moved from loopback only to a wider address.
pub fn listen_widened(old: &Value, new: &Value) -> bool {
    match (old.as_str(), new.as_str()) {
        (Some(o), Some(n)) => loopback(o) && !loopback(n),
        _ => false,
    }
}

/// TLS removed or downgraded on the API (`api.tls`: set, then null; or a provided certificate
/// replaced by a self-signed one) or on a DoT, DoH or DoQ listener (a listener list in which a
/// TLS protocol's address is gone from the TLS set or its protocol is now plain).
pub fn tls_removed_or_downgraded(old: &Value, new: &Value) -> bool {
    // The API's TLS: an object (`self_signed`, or `cert` and `key`) or null.
    if old.is_object() || new.is_object() || (old.is_null() && new.is_null()) {
        let own = |v: &Value| v.get("cert").is_some_and(|c| !c.is_null());
        let any = |v: &Value| v.is_object();
        return (any(old) && !any(new)) || (own(old) && !own(new) && any(new));
    }
    // The listeners: an array of `{proto, addr}`.
    let tls_addrs = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter(|l| {
                        matches!(
                            l.get("proto").and_then(Value::as_str),
                            Some("dot" | "doh" | "doh3" | "doq")
                        )
                    })
                    .filter_map(|l| l.get("addr").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let (old_tls, new_tls) = (tls_addrs(old), tls_addrs(new));
    // An address that served TLS and does not now, but is still served (so: plain).
    let served = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|l| l.get("addr").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let now_served = served(new);
    old_tls
        .iter()
        .any(|a| !new_tls.contains(a) && now_served.contains(a))
}

/// A role removed from `auth.totp_required_roles` (T27.6).
pub fn role_removed(old: &Value, new: &Value) -> bool {
    let new = strings(new);
    strings(old).into_iter().any(|o| !new.contains(&o))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // REQ: API-902 (ADR-914, ADR-956 §1) — every path ADR-914 calls guarded is in the registry or
    // in the list of rows still to come, under one ID, with the mode ADR-956 §1 gives it.
    #[test]
    fn api_902_registry_covers_every_guarded_path() {
        // The paths ADR-914 names, written out (a rename of a configuration field fails here).
        let adr_914: &[(&str, &str)] = &[
            ("node.secrets_key_file", "secrets-key"),
            ("node.secrets_previous_key_file", "secrets-key"),
            ("node.secret_file_dirs", "secret-file-dirs"),
            ("api.allow_secrets_over_http", "allow-secrets-over-http"),
            ("auth.allow_insecure_basic", "allow-insecure-basic"),
            ("listen", "listen"),
            ("listen.addr", "listen"),
            ("listen.tls", "listen"),
            ("api.listen", "api-address"),
            ("api.tls", "api-tls"),
            ("api.trusted_proxies", "trusted-proxies"),
            ("cluster.init", "cluster-init"),
            ("cluster.join_url", "cluster-join"),
            ("cluster.git", "cluster-git"),
            ("node.name", "node-identity"),
            ("node.data_dir", "data-dir"),
            ("watchdog", "watchdog"),
            ("watchdog.enabled", "watchdog"),
            ("dnssec.trust_anchors_file", "file-paths"),
            ("identify.signatures_file", "file-paths"),
            ("local.hosts_files", "file-paths"),
            ("zone.file", "file-paths"),
        ];
        for (path, id) in adr_914 {
            assert_eq!(
                covering(path),
                Some(*id),
                "`{path}` is guarded (ADR-914) and must be covered by `{id}`"
            );
        }
        // Each planned row names paths that exist in the schema document.
        let schema = include_str!("../../../docs/config-schema.json");
        for p in PLANNED {
            for path in p.paths {
                let leaf = path.rsplit('.').next().unwrap_or(path);
                assert!(
                    schema.contains(&format!("\"{leaf}\"")),
                    "planned row `{}` names `{path}`, which the schema doesn't have",
                    p.id
                );
            }
        }
        // IDs are unique, and a row that exists agrees with the plan.
        let mut seen = std::collections::BTreeSet::new();
        for id in PLANNED
            .iter()
            .map(|p| p.id)
            .chain(rows().iter().map(|r| r.id))
        {
            if !PLANNED.iter().any(|p| p.id == id) {
                continue; // a framework row (restart-now) or a test row
            }
            assert!(
                seen.insert(id) || rows().iter().any(|r| r.id == id),
                "{id} twice"
            );
        }
        for r in rows() {
            if let Some(p) = PLANNED.iter().find(|p| p.id == r.id) {
                assert_eq!(p.mode, r.mode, "row `{}` has the wrong mode", r.id);
                assert_eq!(p.paths, r.paths, "row `{}` covers other paths", r.id);
            }
            // A window row proves something; any other row doesn't need to.
            assert_eq!(
                r.mode == Mode::Window,
                r.proof.is_some(),
                "`{}`: a window row needs a proof hook, and only a window row has one",
                r.id
            );
        }
    }

    // REQ: API-902 (ADR-040) — the paths a file sets are found in the merged tables, nested and in
    // arrays of tables, so a guarded control can show "set by file".
    #[test]
    fn api_902_explicit_paths_from_the_files() {
        let t: toml::Table = toml::from_str(
            "[node]
data_dir = \"/x\"
[api]
listen = \"127.0.0.1:1\"
[[zone]]
name = \"a\"
file = \"z.zone\"
[[listen]]
proto = \"udp\"
addr = \"127.0.0.1:5\"
",
        )
        .unwrap();
        let p = explicit_paths(&t);
        for want in ["node.data_dir", "api.listen", "zone.file", "listen"] {
            assert!(p.iter().any(|x| x == want), "{want} in {p:?}");
        }
        for not in ["api.tls", "node.secrets_key_file", "watchdog"] {
            assert!(!p.iter().any(|x| x == not), "{not} in {p:?}");
        }
    }

    // REQ: API-902 (ADR-957) — a docs check: every guarded ID (the registry's and the ones still to
    // come) appears in docs/recovery.md, with the three ways back and the environment switch.
    #[test]
    fn api_902_recovery_doc_lists_every_guarded_id() {
        let doc = include_str!("../../../docs/recovery.md");
        let ids = rows()
            .into_iter()
            .filter(|r| !r.test_only)
            .map(|r| r.id)
            .chain(PLANNED.iter().map(|p| p.id));
        for id in ids {
            assert!(
                doc.contains(&format!("`{id}`")),
                "docs/recovery.md doesn't mention `{id}`"
            );
        }
        for needle in [
            "wrendns guarded list",
            "wrendns guarded clear",
            "WRENDNS_IGNORE_GUARDED",
            "guarded-probation",
            "Restart now",
        ] {
            assert!(
                doc.contains(needle),
                "docs/recovery.md doesn't mention {needle}"
            );
        }
    }

    // REQ: API-902 (ADR-956 §1(b)) — the two sign-in lockout settings are file-only.
    #[test]
    fn api_902_lockout_settings_are_file_only() {
        for path in FILE_ONLY {
            assert_eq!(
                covering(path),
                None,
                "`{path}` must stay out of the registry"
            );
            assert!(rows().iter().all(|r| !r.paths.contains(path)));
            assert!(PLANNED.iter().all(|p| !p.paths.contains(path)));
        }
        assert!(FILE_ONLY.contains(&"auth.oidc.disable_local_login"));
        assert!(FILE_ONLY.contains(&"auth.oidc.allowed_admin_networks"));
    }

    // REQ: API-902 (T27.14c) — the `listen` row is in the registry (it left the plan): a `window`
    // row over `listen` proved by the new socket, whose weakening is the applier's, not a pure rule.
    #[test]
    fn api_902_listen_row_is_real_and_agrees_with_the_plan() {
        let r = row(LISTEN).expect("the row exists");
        assert_eq!(r.mode, Mode::Window);
        assert_eq!(r.paths, ["listen"]);
        assert_eq!(r.proof, Some(Proof::NewSocket));
        assert!(!r.test_only);
        assert!(PLANNED.iter().all(|p| p.id != LISTEN), "left the plan");
        assert_eq!(covering("listen"), Some(LISTEN));
        assert_eq!(covering("listen.addr"), Some(LISTEN));
        assert_eq!(covering("listen.tls"), Some(LISTEN));
        // The gate stays the other row's.
        assert_eq!(covering("listen.require_client_id"), Some(LISTEN_ACCESS));
        assert!(!(r.weakens)(&json!({}), &json!({"listeners": []})));
    }

    // REQ: DNS-901, API-902 (T27.14) — the `listen-access` row is `immediate`, covers the listener
    // gate's path, and "weakens" exactly when a gate that was on is off afterwards.
    #[test]
    fn dns_901_listen_access_row_and_weakening() {
        let r = row(LISTEN_ACCESS).expect("the row exists");
        assert_eq!(r.mode, Mode::Immediate);
        assert_eq!(r.paths, ["listen.require_client_id"]);
        assert!(r.proof.is_none());
        assert_eq!(covering("listen.require_client_id"), Some(LISTEN_ACCESS));
        assert_eq!(
            covering("listen.addr"),
            Some("listen"),
            "the address stays the listen row's"
        );
        let l = |proto: &str, addr: &str, g: Value| json!({"proto": proto, "addr": addr, "require_client_id": g});
        let v = |a: Value, b: Value| json!({"listeners": [a, b]});
        let public = "203.0.113.5:853";
        let lan = "192.168.1.2:853";
        let base = v(l("dot", public, Value::Null), l("dot", lan, Value::Null));
        // Unset: on for the public one, off for the LAN one; udp can't carry a key.
        let host = crate::gate::HostFacts::UNKNOWN;
        let m = gate_map(&base, host);
        assert!(m["dot://203.0.113.5:853"]);
        assert!(!m["dot://192.168.1.2:853"]);
        let udp = gate_map(
            &json!({"listeners": [l("udp", "203.0.113.5:53", json!(true))]}),
            host,
        );
        assert!(!udp["udp://203.0.113.5:53"]);
        // Public turned off: weakens. Explicit true to unset on a public address: still on.
        let off = v(l("dot", public, json!(false)), l("dot", lan, Value::Null));
        assert!(listen_gate_weakened(&base, &off, host));
        let pinned = v(l("dot", public, json!(true)), l("dot", lan, Value::Null));
        assert!(!listen_gate_weakened(&pinned, &base, host));
        assert!(listen_gate_weakened(&pinned, &off, host));
        // LAN turned on, and a public one left off: not weakening.
        let lan_on = v(l("dot", public, Value::Null), l("dot", lan, json!(true)));
        assert!(!listen_gate_weakened(&base, &lan_on, host));
        assert!(!listen_gate_weakened(&off, &off, host));
        // Nothing to compare: not weakening.
        assert!(!listen_gate_weakened(&Value::Null, &off, host));
        assert!(!listen_gate_weakened(&base, &Value::Null, host));
        // The row's own `weakens` is `never`: the applier reports it with the host's facts.
        assert!(!(r.weakens)(&base, &off));
    }

    // REQ: DNS-901 — a non-canonical spelling of the same address is the same listener, so turning
    // its gate off still counts as a weakening.
    #[test]
    fn dns_901_non_canonical_address_still_weakens() {
        let l =
            |addr: &str, g: Value| json!({"proto": "dot", "addr": addr, "require_client_id": g});
        let base = json!({"listeners": [l("[2001:db8::5]:853", Value::Null)]});
        let off = json!({"listeners": [l("[2001:db8:0::5]:853", json!(false))]});
        let host = crate::gate::HostFacts::UNKNOWN;
        assert!(gate_map(&base, host)["dot://[2001:db8::5]:853"]);
        assert!(listen_gate_weakened(&base, &off, host));
    }

    // REQ: API-902 (ADR-956 §1(a)) — `node.data_dir` is guarded, and staged.
    #[test]
    fn api_902_data_dir_is_guarded_and_staged() {
        let p = PLANNED.iter().find(|p| p.id == "data-dir");
        assert!(p.is_some_and(|p| p.mode == Mode::Staged && p.paths == ["node.data_dir"]));
        assert_eq!(covering("node.data_dir"), Some("data-dir"));
    }

    // REQ: API-902 (ADR-914) — every weakening case, and the changes that are not.
    #[test]
    fn api_902_weakens_table() {
        // Adding a directory to secret_file_dirs; narrowing is not weakening.
        assert!(entry_added(
            &json!(["/run/secrets"]),
            &json!(["/run/secrets", "/etc"])
        ));
        assert!(!entry_added(
            &json!(["/run/secrets", "/etc"]),
            &json!(["/run/secrets"])
        ));
        assert!(!entry_added(
            &json!(["/run/secrets"]),
            &json!(["/run/secrets"])
        ));
        // Turning on allow_secrets_over_http or allow_insecure_basic; turning off is not.
        assert!(turned_on(&json!(false), &json!(true)));
        assert!(turned_on(&json!(null), &json!(true)));
        assert!(!turned_on(&json!(true), &json!(true)));
        assert!(!turned_on(&json!(true), &json!(false)));
        // Adding a trusted_proxies entry; removing one is not.
        assert!(entry_added(&json!([]), &json!(["10.0.0.0/8"])));
        assert!(!entry_added(&json!(["10.0.0.0/8"]), &json!([])));
        // Turning off the watchdog.
        assert!(watchdog_turned_off(
            &json!({"enabled": true}),
            &json!({"enabled": false})
        ));
        assert!(watchdog_turned_off(&json!(true), &json!(false)));
        assert!(!watchdog_turned_off(
            &json!({"enabled": false}),
            &json!({"enabled": true})
        ));
        assert!(!watchdog_turned_off(
            &json!({"enabled": true}),
            &json!({"enabled": true})
        ));
        // Moving api.listen from loopback only to a wider address.
        assert!(listen_widened(
            &json!("127.0.0.1:8053"),
            &json!("0.0.0.0:8053")
        ));
        assert!(listen_widened(
            &json!("[::1]:8053"),
            &json!("192.168.1.2:8053")
        ));
        assert!(!listen_widened(
            &json!("0.0.0.0:8053"),
            &json!("127.0.0.1:8053")
        ));
        assert!(!listen_widened(
            &json!("192.168.1.2:8053"),
            &json!("0.0.0.0:8053")
        ));
        assert!(!listen_widened(
            &json!("127.0.0.1:8053"),
            &json!("127.0.0.1:9000")
        ));
        // Removing or downgrading TLS on the API.
        assert!(tls_removed_or_downgraded(
            &json!({"self_signed": true}),
            &json!(null)
        ));
        assert!(tls_removed_or_downgraded(
            &json!({"cert": "c.pem", "key": "k.pem"}),
            &json!({"self_signed": true})
        ));
        assert!(!tls_removed_or_downgraded(
            &json!(null),
            &json!({"self_signed": true})
        ));
        assert!(!tls_removed_or_downgraded(
            &json!({"self_signed": true}),
            &json!({"cert": "c.pem", "key": "k.pem"})
        ));
        // ... and on a DoT, DoH or DoQ listener (still served, now plain, or gone from TLS).
        let dot = json!([{"proto": "dot", "addr": "0.0.0.0:853"}]);
        let plain = json!([{"proto": "tcp", "addr": "0.0.0.0:853"}]);
        assert!(tls_removed_or_downgraded(&dot, &plain));
        assert!(!tls_removed_or_downgraded(&plain, &dot));
        assert!(!tls_removed_or_downgraded(&dot, &dot));
        assert!(
            !tls_removed_or_downgraded(&dot, &json!([])),
            "removing a listener isn't a downgrade"
        );
        // Removing a role from auth-policy's totp_required_roles (T27.6).
        assert!(role_removed(
            &json!(["admin", "operator"]),
            &json!(["admin"])
        ));
        assert!(!role_removed(
            &json!(["admin"]),
            &json!(["admin", "operator"])
        ));
    }

    // REQ: API-902 — the phrase is the node ID and the setting (ADR-914); the restart's is its own.
    #[test]
    fn api_902_phrase_forms() {
        assert_eq!(phrase("pi-a", "listen"), "pi-a listen");
        assert_eq!(phrase("pi-a", RESTART_NOW), "pi-a restart");
    }

    // REQ: API-902 (ADR-956 §3) — a release build has no test rows.
    #[cfg(not(feature = "e2e"))]
    #[test]
    fn api_902_test_row_absent_in_release() {
        assert!(!std::hint::black_box(TEST_ROWS_COMPILED));
        assert!(
            rows()
                .iter()
                .all(|r| !r.test_only && !r.id.starts_with("e2e-"))
        );
        assert!(row("e2e-window").is_none());
        assert!(
            row(RESTART_NOW).is_some(),
            "the restart action is a real row"
        );
    }

    #[cfg(feature = "e2e")]
    #[test]
    fn api_902_test_rows_are_marked() {
        assert!(TEST_ROWS_COMPILED);
        assert!(rows().iter().filter(|r| r.test_only).count() == 5);
        let w = row("e2e-window").unwrap_or_else(|| unreachable!());
        assert_eq!(w.proof, Some(Proof::NewSocket));
    }
}

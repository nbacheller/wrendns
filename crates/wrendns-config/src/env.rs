//! Environment-variable overrides: `WRENDNS_<SECTION>_<KEY>=value`.
//!
//! REQ: OPS-005 — precedence is defaults < files < env < CLI flags (`spec/08` §5).
//!
//! Variable names are resolved against the *schema* (the serialized defaults), so keys that
//! contain underscores work: `WRENDNS_CACHE_MAX_TTL` → `cache.max_ttl`,
//! `WRENDNS_TELEMETRY_QLOG_RETENTION_DAYS` → `telemetry.qlog.retention_days`.
//! Keys of `[node]` may omit the section: `WRENDNS_ROLE` → `node.role`.
//! Values are coerced to the type of the field they override.
//!
//! Unknown `WRENDNS_*` variables are warnings, not errors: Kubernetes injects
//! `WRENDNS_PORT`, `WRENDNS_SERVICE_HOST`, ... for any Service named `wrendns`, and a
//! hard error would crash-loop the pod.

use toml::{Table, Value};

use crate::ConfigError;

pub const ENV_PREFIX: &str = "WRENDNS_";

/// Variables consumed by the binary itself rather than mapped onto the schema.
const RESERVED: &[&str] = &[
    "CONFIG",
    "NODE_CONFIG",
    "LOG",
    "LOG_FORMAT",
    "BOOTSTRAP_ADMIN_USER",
    "BOOTSTRAP_ADMIN_PASSWORD",
    "BOOTSTRAP_ADMIN_PASSWORD_HASH",
    "NODE_IPS",
    // How it was installed, for the update status (ADR-046; image, Helm, install.sh).
    "INSTALL",
    // T6.14 — the Kubernetes node and pod (downward API, set by the Helm charts).
    "KUBE_NODE",
    "POD",
    // REQ: FLT-017 — the workload watcher's test hook (a pods file instead of an API server).
    "KUBERNETES_FIXTURE",
    // REQ: CLU-014 — the drill test hooks (the gap between drills, the "came back" check, how
    // long missing parts are retried).
    "DRILL_GAP_SECS",
    "DRILL_RETURN_SECS",
    "DRILL_RETRY_SECS",
    "DRILL_IGNORE_HEALTH",
    // REQ: OPS-014, API-014 (ADR-903 §3) — the node's secrets key and the one before a rotation.
    "SECRETS_KEY",
    "SECRETS_PREVIOUS_KEY",
    // REQ: OPS-014 (ADR-903) — set by the Helm chart when the data directory isn't kept across
    // restarts (persistence off): stored secrets would be lost (`secrets_ephemeral`).
    "DATA_EPHEMERAL",
    // REQ: T24.27 — read by the binary outside the config. The supervisor the restart goes
    // through (T27.13, set by the unit, bundles and chart), the guarded-entries escape hatch,
    // the `wrendns ctl`/`support` API token, the DNSSEC library-log switch, and the `exec://`
    // plugin's socket and upstream name (set for a child, but a plugin that starts a `wrendns`
    // sees them too). Test hooks: the simulation seeds and the matcher's walk switch. Keys the
    // schema has (`WRENDNS_DRAIN_DELAY_SECS` = `node.drain_delay_secs`) are not listed: they
    // already resolve.
    "SUPERVISOR",
    "IGNORE_GUARDED",
    "TOKEN",
    "LOG_DNSSEC_LIBRARY",
    "PLUGIN_SOCKET",
    "UPSTREAM",
    "SIM_SCHEDULES",
    "SIM_SEED",
    "TEST_WALK",
    // REQ: FLT-901 (T24.29) - the memory limit a category selection is checked against, in bytes,
    // when the cgroup and the machine's RAM are not what the node should plan with (a test, or a
    // measurement on a stand-in for a smaller node).
    "MEMORY_LIMIT",
    // REQ: FLT-901 - the cluster test's fake source (read only by a build with the `e2e` feature).
    "E2E_CATALOG_BASE",
];

/// REQ: OPS-014, API-014 (ADR-903 §3) — variables a process this one starts (an `exec://`
/// plugin, the self-update's checks and restart) never inherits: the secrets keys, the
/// bootstrap admin's password, and the API token `wrendns ctl` reads.
pub const NEVER_INHERITED: &[&str] = &[
    "WRENDNS_SECRETS_KEY",
    "WRENDNS_SECRETS_PREVIOUS_KEY",
    "WRENDNS_BOOTSTRAP_ADMIN_PASSWORD",
    "WRENDNS_BOOTSTRAP_ADMIN_PASSWORD_HASH",
    "WRENDNS_TOKEN",
];

/// Applies matching variables onto `root`, using `defaults` for path resolution and types.
/// Returns warnings; errors are pushed to `errors`.
pub(crate) fn apply(
    root: &mut Table,
    defaults: &Table,
    vars: &[(String, String)],
    errors: &mut Vec<ConfigError>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut sorted: Vec<&(String, String)> = vars
        .iter()
        .filter(|(k, _)| k.starts_with(ENV_PREFIX))
        .collect();
    sorted.sort();
    for (name, raw) in sorted {
        let rest = &name[ENV_PREFIX.len()..];
        if RESERVED.contains(&rest) {
            continue;
        }
        let parts: Vec<String> = rest
            .to_ascii_lowercase()
            .split('_')
            .map(str::to_owned)
            .collect();
        let path = resolve(defaults, &parts).or_else(|| {
            let node = defaults.get("node")?.as_table()?;
            resolve(node, &parts).map(|mut p| {
                p.insert(0, "node".to_owned());
                p
            })
        });
        let Some(path) = path else {
            warnings.push(format!("ignoring unknown environment variable {name}"));
            continue;
        };
        let dotted = path.join(".");
        let Some(template) = lookup(defaults, &path) else {
            continue;
        };
        match coerce(raw, template) {
            Ok(v) => set(root, &path, v),
            Err(msg) => errors.push(ConfigError::new(format!("{dotted} (from {name})"), msg)),
        }
    }
    warnings
}

/// Greedy longest-key-first match of `parts` (already lowercase) against nested tables.
fn resolve(table: &Table, parts: &[String]) -> Option<Vec<String>> {
    for take in (1..=parts.len()).rev() {
        let key = parts[..take].join("_");
        let Some(value) = table.get(&key) else {
            continue;
        };
        let rest = &parts[take..];
        if rest.is_empty() {
            if is_leaf(value) {
                return Some(vec![key]);
            }
        } else if let Value::Table(inner) = value
            && let Some(mut tail) = resolve(inner, rest)
        {
            tail.insert(0, key);
            return Some(tail);
        }
    }
    None
}

/// A key that env can set: not a table, and not an array of tables (e.g. `[[listen]]`).
fn is_leaf(value: &Value) -> bool {
    match value {
        Value::Table(_) => false,
        Value::Array(items) => !items.iter().any(Value::is_table),
        _ => true,
    }
}

fn lookup<'a>(table: &'a Table, path: &[String]) -> Option<&'a Value> {
    let (last, init) = path.split_last()?;
    let mut t = table;
    for k in init {
        t = t.get(k)?.as_table()?;
    }
    t.get(last)
}

fn set(root: &mut Table, path: &[String], value: Value) {
    let Some((last, init)) = path.split_last() else {
        return;
    };
    let mut t = root;
    for k in init {
        let entry = t
            .entry(k.clone())
            .or_insert_with(|| Value::Table(Table::new()));
        if !entry.is_table() {
            *entry = Value::Table(Table::new());
        }
        let Value::Table(inner) = entry else {
            return;
        };
        t = inner;
    }
    t.insert(last.clone(), value);
}

fn coerce(raw: &str, template: &Value) -> Result<Value, String> {
    let raw_t = raw.trim();
    match template {
        Value::String(_) => Ok(Value::String(raw.to_owned())),
        Value::Integer(_) => raw_t
            .parse::<i64>()
            .map(Value::Integer)
            .map_err(|_| format!("expected an integer, got `{raw}`")),
        Value::Float(_) => raw_t
            .parse::<f64>()
            .map(Value::Float)
            .map_err(|_| format!("expected a number, got `{raw}`")),
        Value::Boolean(_) => match raw_t.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(Value::Boolean(true)),
            "false" | "0" | "no" | "off" => Ok(Value::Boolean(false)),
            _ => Err(format!("expected a boolean, got `{raw}`")),
        },
        Value::Array(_) => {
            // Accept a TOML inline array (`["a", "b"]`) or a comma-separated list of strings.
            if raw_t.starts_with('[') {
                let doc: Table = toml::from_str(&format!("v = {raw_t}"))
                    .map_err(|e| format!("invalid TOML array `{raw}`: {e}"))?;
                doc.get("v")
                    .cloned()
                    .ok_or_else(|| format!("invalid TOML array `{raw}`"))
            } else if raw_t.is_empty() {
                Ok(Value::Array(Vec::new()))
            } else {
                Ok(Value::Array(
                    raw_t
                        .split(',')
                        .map(|s| Value::String(s.trim().to_owned()))
                        .collect(),
                ))
            }
        }
        Value::Datetime(_) | Value::Table(_) => {
            Err("this key cannot be set from the environment".to_owned())
        }
    }
}

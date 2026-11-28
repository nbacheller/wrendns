//! Configuration schema, validation, env overrides, and migrations.
//!
//! Part of WrenDNS. See `spec/02-architecture.md` §2 and `spec/08` §5.
//!
//! ```no_run
//! let loaded = wrendns_config::Loader::new()
//!     .file("/etc/wrendns/wrendns.toml")
//!     .process_env()
//!     .load()
//!     .map_err(|errs| errs.into_iter().map(|e| e.to_string()).collect::<Vec<_>>());
//! ```

// REQ: NFR-003 — no unsafe outside wrendns-net.
#![forbid(unsafe_code)]

pub mod categories;
pub mod cmdb;
pub mod credentials;
pub mod discovery;
pub mod dns_provider;
mod env;
pub mod gate;
pub mod guarded;
pub mod location;
pub mod mute;
pub mod safesearch;
pub mod schedule;
pub mod schema;
pub mod secret_refs;
pub mod services;
pub mod shared;
mod types;
mod validate;

use std::fmt;
use std::path::Path;

use toml::{Table, Value};

pub use cmdb::CmdbConfig;
pub use discovery::{
    CredentialRole, DiscoveryConfig, DiscoverySubnet, SnmpAgent, SnmpCredential, SnmpTable,
    SnmpVersion, UnifiReads,
};
pub use dns_provider::{DnsProviderConfig, DnsProviderKind};
pub use env::{ENV_PREFIX, NEVER_INHERITED};
pub use gate::{DefaultGate, HostFacts, default_gate, gate_warnings, is_wildcard};
pub use location::{LocationConfig, LocationNet, LocationVisibility, device_label};
pub use schema::*;
pub use types::{ByteSize, Cidr, SafeString, SourceSpec, parse_rfc3339, parse_source};
pub use validate::{
    MAX_LISTS, MAX_PUBLIC_URL, MatchKey, UPSTREAM_SCHEMES, addrs_clash, check_public_url,
    dnstap_address_ok, otlp_errors, probe_target, provider_errors as oidc_provider_errors,
    sink_errors, valid_list_name,
};

/// A config problem located by its key path (e.g. `upstream[1].url`, `cache.bogus`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {message}")]
pub struct ConfigError {
    /// Dotted key path, with `[n]` for array elements. A file name for I/O and syntax errors.
    pub path: String,
    pub message: String,
}

impl ConfigError {
    pub fn new(path: impl Into<String>, message: impl fmt::Display) -> Self {
        Self {
            path: path.into(),
            message: message.to_string(),
        }
    }
}

/// A successfully loaded config plus non-fatal warnings.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub config: Config,
    pub warnings: Vec<String>,
}

/// Builds a [`Config`] from layered sources.
///
/// REQ: OPS-005 — precedence: built-in defaults < files (in the order added; later wins) <
/// environment variables. Tables merge key by key; arrays and scalars replace.
#[derive(Debug)]
pub struct Loader {
    layers: Vec<(String, Result<String, String>)>,
    env: Vec<(String, String)>,
    host: HostFacts,
}

impl Default for Loader {
    fn default() -> Self {
        Self::new()
    }
}

impl Loader {
    pub fn new() -> Self {
        Self {
            layers: Vec::new(),
            env: Vec::new(),
            host: HostFacts::UNKNOWN,
        }
    }

    /// REQ: DNS-901 — the host's address facts, for the warnings about a listener's gate (the
    /// config crate makes no system call). Unset means unreadable, which fails closed.
    #[must_use]
    pub fn host_facts(mut self, host: HostFacts) -> Self {
        self.host = host;
        self
    }

    /// Adds a TOML file layer. A read failure is reported by [`Loader::load`].
    #[must_use]
    pub fn file(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read file: {e}"));
        self.layers.push((path.display().to_string(), text));
        self
    }

    /// Adds an in-memory TOML layer; `origin` names it in errors.
    #[must_use]
    pub fn toml_str(mut self, origin: impl Into<String>, text: impl Into<String>) -> Self {
        self.layers.push((origin.into(), Ok(text.into())));
        self
    }

    /// Uses these variables as the environment (for tests and embedding).
    #[must_use]
    pub fn env<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.env = vars
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self
    }

    /// Uses the process environment (non-UTF-8 variables are skipped).
    #[must_use]
    pub fn process_env(mut self) -> Self {
        self.env = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        self
    }

    /// Merges, applies env overrides, deserializes, and validates. Returns every error found.
    pub fn load(self) -> Result<Loaded, Vec<ConfigError>> {
        let mut errors = Vec::new();
        let defaults = Table::try_from(Config::default())
            .map_err(|e| vec![ConfigError::new("<defaults>", e)])?;

        let mut root = Table::new();
        for (origin, text) in &self.layers {
            match text {
                Err(msg) => errors.push(ConfigError::new(origin.clone(), msg)),
                Ok(text) => match text.parse::<Table>() {
                    Ok(t) => merge(&mut root, t),
                    Err(e) => {
                        errors.push(ConfigError::new(origin.clone(), e.to_string().trim_end()));
                    }
                },
            }
        }
        let mut warnings = env::apply(&mut root, &defaults, &self.env, &mut errors);
        if !errors.is_empty() {
            return Err(errors);
        }

        let file_set = explicit_keys(&root);
        let config = match serde_path_to_error::deserialize::<_, Config>(Value::Table(root)) {
            Ok(mut c) => {
                c.file_set = file_set;
                c
            }
            Err(e) => {
                let path = e.path().to_string();
                let path = if path == "." {
                    "<root>".to_owned()
                } else {
                    path
                };
                // toml appends an "in `table`" context line; the path already says that.
                let msg = e.into_inner().to_string();
                let msg = msg.lines().next().unwrap_or_default().trim_end();
                return Err(vec![ConfigError::new(path, msg)]);
            }
        };

        warnings.extend(validate::validate(&config, self.host, &mut errors));
        if errors.is_empty() {
            Ok(Loaded { config, warnings })
        } else {
            Err(errors)
        }
    }
}

/// REQ: API-010 (ADR-914) — the keys of the sections the API can change that the layers set
/// explicitly (`special.ddr_name`, ...), so an API value for one of them can be refused or
/// overridden by the file.
fn explicit_keys(root: &Table) -> Vec<String> {
    let mut keys = Vec::new();
    // REQ: DNS-006, DNS-011, FLT-004, OPS-011, OPS-012, CLU-014 (T27.2, T27.11, ADR-1006) and
    // OBS-016, OBS-020, OBS-019 (T27.5, ADR-1007) — the sections the API and UI edit: a field a
    // file sets is read-only there (ADR-040).
    for section in [
        "special",
        "local",
        "clients",
        "discovery",
        "cmdb",
        "cache",
        "support",
        "updates",
        "dnssec",
        "filter",
        "drill",
        "access",
        "slo",
        "probe",
        "upstream_check",
    ] {
        if let Some(Value::Table(t)) = root.get(section) {
            keys.extend(t.keys().map(|k| format!("{section}.{k}")));
        }
    }
    // REQ: OBS-013, OBS-003, OBS-020 (T27.5, ADR-1007) — the node-managed parts of `[telemetry]`.
    if let Some(Value::Table(tel)) = root.get("telemetry") {
        for section in ["anomaly", "qlog", "metrics", "dnstap"] {
            if let Some(Value::Table(t)) = tel.get(section) {
                keys.extend(t.keys().map(|k| format!("telemetry.{section}.{k}")));
            }
        }
    }
    // REQ: API-902 (T27.13, ADR-956 §2) — the guarded settings a file sets: the file wins over a
    // guarded entry, and the control is locked.
    keys.extend(guarded::explicit_paths(root));
    keys
}

/// Deep-merges `over` into `base`: tables merge recursively, everything else replaces.
fn merge(base: &mut Table, over: Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(Value::Table(b)), Value::Table(o)) => merge(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

/// Validates a config built in code (the files plus entries made through the API,
/// ADR-040). Returns the warnings, or every error.
pub fn validate_config(config: &Config) -> Result<Vec<String>, Vec<ConfigError>> {
    let mut errors = Vec::new();
    let warnings = validate::validate(config, HostFacts::UNKNOWN, &mut errors);
    if errors.is_empty() {
        Ok(warnings)
    } else {
        Err(errors)
    }
}

/// JSON Schema for `wrendns.toml` (`wrendns config schema`), for editor completion.
pub fn json_schema() -> schemars::Schema {
    schemars::schema_for!(Config)
}

//! REQ: API-016, OBS-010, OBS-006 (T23.11, ADR-903 sections 6-7, ADR-984) - event sinks and the
//! OTLP export as node-managed kinds: `[[telemetry.sink]]` entries (by name) and the one
//! `[telemetry.otlp]` destination made through the API or UI, stored in `state.db` on the primary
//! (or a standalone node) and replicated to every member as the manifest's `node_managed` blob
//! (`node_managed.rs`).
//!
//! - **Admin only.** An operator is refused (403) and an agent never writes one (no scope; the
//!   agent forbidden list is the default). A forwarded write without a role (an older node) is
//!   refused (409 `upgrade_required`), as credential writes are.
//! - **The files win.** A sink the configuration files define is read-only here (409
//!   `set_by_file`), and so is the OTLP export when the files set an `endpoint`, `headers` or
//!   `header_refs`: ADR-040's rule.
//! - **Credentials are names.** A sink's `token_ref` and OTLP's `header_refs` name stored secrets
//!   (422 `secret_missing` when none has the name). The API takes no file path for a credential
//!   (`token_file`, `tls_ca`), no inline header value and no password in a URL: those are set in
//!   the configuration file (ADR-921's reason: a path the API can set is a path an admin can
//!   point at any readable file, and a value in the body would sit in the audit log and the blob).
//! - **A file sink is a file name.** It is written under `<data_dir>/sinks/` on every node, so
//!   the API can't point the process at another file.
//! - **Bounds.** At most 16 sinks, a buffer of at most a million events and kept batches of at most
//!   1 GiB, so that a body can't make a node allocate without limit.

use wrendns_api::ManagedKind;
use wrendns_api::ManagedWrite;
use wrendns_api::auth::Role;
use wrendns_api::model::{OtlpEntry, OtlpHeader, SinkEntry, SinkList};
use wrendns_api::problem::{Code, Problem};
use wrendns_config::{Config, OtlpConfig, SinkConfig, SinkKind};

use crate::api_backend::{ManagedPlan, secret_references};
use crate::http::Sources;
use crate::managed::Entries;

/// Body fields of a sink the files set (a path to a credential or a CA).
const FILE_FIELDS: [&str; 2] = ["token_file", "tls_ca"];
/// The most sinks the UI can add (each has a thread and a buffer).
const MAX_SINKS: usize = 16;
/// The largest event buffer a sink made through the API may ask for.
const MAX_BUFFER: u32 = 100_000;
/// The largest set of kept batches a sink made through the API may ask for.
const MAX_SPILL: u64 = 1 << 30;
/// Headers the export sets itself (`content-encoding` when `compression = "gzip"`).
const RESERVED_HEADERS: [&str; 7] = [
    "content-type",
    "content-encoding",
    "content-length",
    "host",
    "user-agent",
    "transfer-encoding",
    "connection",
];

/// Who may change one: an admin, through the API (never an agent). A write whose role an older
/// node didn't send is refused until that node is upgraded.
pub(crate) fn may_change(role: Option<Role>, agent: Option<&str>) -> Result<(), Problem> {
    if agent.is_some() {
        return Err(Problem::new(
            Code::AgentNotAllowed,
            "agents can't change event sinks or the OTLP export",
        )
        .hint("Ask an admin to make this change in the UI."));
    }
    match role {
        Some(Role::Admin) => Ok(()),
        None => Err(Problem::new(
            Code::UpgradeRequired,
            "this change needs an admin, and the node it was made on is too old to say who made it",
        )
        .hint("Upgrade that node first, or make the change on the primary.")),
        Some(_) => Err(Problem::new(
            Code::Forbidden,
            "only an admin can add, change or remove an event sink or the OTLP export",
        )
        .hint("Ask an admin to make this change.")),
    }
}

/// A sink's name through the API: letters, digits, `.`, `_` and `-`, starting with a letter or digit.
fn valid_sink_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b.first().is_some_and(u8::is_ascii_alphanumeric)
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// A file sink's file name through the API: no directory part, nothing hidden, and not a name the
/// sink's own bookkeeping uses.
fn valid_file_name(n: &str) -> bool {
    valid_sink_name(n)
        && !n.starts_with('.')
        && ![".spill", ".pos", ".tmp"]
            .iter()
            .any(|ext| n.to_ascii_lowercase().ends_with(ext))
        // `a` rotates to `a.1`, `a.2`: another sink's file can't be named like that.
        && !n
            .rsplit_once('.')
            .is_some_and(|(_, e)| !e.is_empty() && e.bytes().all(|c| c.is_ascii_digit()))
}

/// REQ: API-016 (T23.11) — the API's limits, applied again to a sink that arrives by another
/// road (a replicated blob, a stored row): the file name, the sizes, no password in an address.
pub(crate) fn stored_limits(s: &SinkConfig) -> Result<(), String> {
    if s.kind == SinkKind::File {
        if !s.path.as_deref().is_some_and(valid_file_name) {
            return Err("`path` isn't a plain file name".into());
        }
    } else if s.path.is_some() {
        return Err("`path`: only a file sink has one".into());
    }
    if s.max_buffer > MAX_BUFFER {
        return Err(format!("`max_buffer`: at most {MAX_BUFFER} events"));
    }
    if s.spill_max_bytes.is_some_and(|b| b.bytes() > MAX_SPILL) {
        return Err("`spill_max_bytes`: at most 1 GiB".into());
    }
    for (f, v) in [("url", s.url.as_deref()), ("address", s.address.as_deref())] {
        if v.is_some_and(|v| wrendns_config::credentials::redact_url(v).is_some()) {
            return Err(format!("`{f}`: a password in an address"));
        }
    }
    Ok(())
}

/// The most sinks a node takes from the API (and from a replicated blob).
pub(crate) const fn max_sinks() -> usize {
    MAX_SINKS
}

/// 422 when `value` is a URL that carries a credential (a password, a secret query value).
fn no_url_credentials(field: &str, value: Option<&str>) -> Result<(), Problem> {
    if value.is_some_and(|v| wrendns_config::credentials::redact_url(v).is_some()) {
        return Err(Problem::new(
            Code::InvalidConfig,
            format!("`{field}`: a password in an address is set in the configuration file, not through the API"),
        )
        .hint("Store the secret (Settings -> Integrations & secrets) and name it in `token_ref`, or send it as a header."));
    }
    Ok(())
}

/// Parses an API body into a sink, named by the path. Paths to credentials, a directory in a
/// file name, passwords in URLs and unbounded sizes are refused.
pub(crate) fn parse_sink(name: &str, body: &serde_json::Value) -> Result<SinkConfig, Problem> {
    let Some(obj) = body.as_object() else {
        return Err(Problem::invalid(
            "the body must be a JSON object (a sink's fields)",
        ));
    };
    for f in FILE_FIELDS {
        if obj.get(f).is_some_and(|v| !v.is_null()) {
            return Err(Problem::new(
                Code::InvalidConfig,
                format!("`{f}`: a sink's file paths are set in the configuration file, not through the API"),
            )
            .hint("Store the token (Settings -> Integrations & secrets) and name it in `token_ref`."));
        }
    }
    if let Some(n) = obj.get("name").and_then(serde_json::Value::as_str)
        && n != name
    {
        return Err(Problem::invalid(format!(
            "the body's name `{n}` isn't the path's `{name}`"
        )));
    }
    let mut v = body.clone();
    v["name"] = serde_json::Value::String(name.to_owned());
    let s = serde_json::from_value::<SinkConfig>(v)
        .map_err(|e| Problem::new(Code::InvalidConfig, format!("sink `{name}`: {e}")))?;
    no_url_credentials("url", s.url.as_deref())?;
    no_url_credentials("address", s.address.as_deref())?;
    if s.kind == SinkKind::File {
        let ok = s.path.as_deref().is_some_and(valid_file_name);
        if !ok {
            return Err(Problem::new(
                Code::InvalidConfig,
                "`path`: a file sink made here is a file name (letters, digits, `.`, `_`, `-`), written under the node's data directory in `sinks/`",
            ));
        }
    } else if s.path.is_some() {
        return Err(Problem::new(
            Code::InvalidConfig,
            "`path`: only a file sink has one",
        ));
    }
    if s.max_buffer > MAX_BUFFER {
        return Err(Problem::new(
            Code::InvalidConfig,
            format!("`max_buffer`: at most {MAX_BUFFER} events"),
        ));
    }
    if s.spill_max_bytes.is_some_and(|b| b.bytes() > MAX_SPILL) {
        return Err(Problem::new(
            Code::InvalidConfig,
            "`spill_max_bytes`: at most 1 GiB",
        ));
    }
    let errs = wrendns_config::sink_errors(&s);
    if !errs.is_empty() {
        return Err(Problem::new(Code::InvalidConfig, errs.join("; ")));
    }
    Ok(s)
}

/// Parses an API body into the OTLP export. Inline headers, trace settings and credentials in the
/// URL are refused (they are set in the configuration file).
pub(crate) fn parse_otlp(body: &serde_json::Value) -> Result<OtlpConfig, Problem> {
    let Some(obj) = body.as_object() else {
        return Err(Problem::invalid(
            "the body must be a JSON object (the export's fields)",
        ));
    };
    if obj
        .get("headers")
        .is_some_and(|v| v.as_object().is_none_or(|m| !m.is_empty()))
    {
        return Err(Problem::new(
            Code::InvalidConfig,
            "`headers`: a header's value is a secret: store it (Settings -> Integrations & secrets) and name it in `header_refs`",
        ));
    }
    for f in ["traces_sample_every", "traces_slow_ms"] {
        if obj
            .get(f)
            .is_some_and(|v| !v.is_null() && v.as_u64() != Some(0))
        {
            return Err(Problem::new(
                Code::InvalidConfig,
                format!(
                    "`{f}`: trace export is set in the configuration file (it is read at start)"
                ),
            ));
        }
    }
    let o = serde_json::from_value::<OtlpConfig>(body.clone())
        .map_err(|e| Problem::new(Code::InvalidConfig, format!("OTLP export: {e}")))?;
    let Some(endpoint) = o.endpoint.as_deref().filter(|e| !e.is_empty()) else {
        return Err(Problem::new(
            Code::InvalidConfig,
            "`endpoint`: the collector's address is required (DELETE the entry to turn the export off)",
        ));
    };
    no_url_credentials("endpoint", Some(endpoint))?;
    for h in o.header_refs.keys() {
        if RESERVED_HEADERS.contains(&h.to_ascii_lowercase().as_str()) {
            return Err(Problem::new(
                Code::InvalidConfig,
                format!(
                    "`header_refs.{h}`: the export sets this header itself (content-type, content-length, content-encoding when compression is gzip, host, user-agent, transfer-encoding and connection are reserved)"
                ),
            ));
        }
    }
    let errs = wrendns_config::otlp_errors(&o);
    if !errs.is_empty() {
        return Err(Problem::new(Code::InvalidConfig, errs.join("; ")));
    }
    Ok(o)
}

/// REQ: API-016 - plans a `PUT` or `DELETE` of a sink or of the OTLP export.
pub(crate) fn plan(
    src: &Sources,
    state: &wrendns_store::state::State,
    w: &ManagedWrite,
) -> Result<ManagedPlan, Problem> {
    may_change(w.role, w.agent.as_deref())?;
    match w.kind {
        ManagedKind::Sink => plan_sink(src, state, w),
        ManagedKind::Otlp => plan_otlp(src, state, w),
        _ => Err(Problem::internal("not a telemetry kind")),
    }
}

fn plan_sink(
    src: &Sources,
    state: &wrendns_store::state::State,
    w: &ManagedWrite,
) -> Result<ManagedPlan, Problem> {
    let name = w.name.trim().to_owned();
    if !valid_sink_name(&name) {
        return Err(Problem::invalid(
            "the name is 1-64 letters, digits, `.`, `_` or `-`, starting with a letter or digit",
        ));
    }
    let file = src.file_config.load_full();
    if file.telemetry.sink.iter().any(|s| s.name.as_str() == name) {
        return Err(Problem::new(
            Code::SetByFile,
            format!("sink `{name}` is defined in the configuration files, which win: it's read-only here"),
        )
        .hint("Change it in the configuration file. The UI shows it as set by file."));
    }
    let mut entries: Entries = crate::managed::entries(state);
    let before_cfg: Config =
        crate::managed::merge(&file, &entries).unwrap_or_else(|_| (*file).clone());
    let find = |c: &Config| {
        c.telemetry
            .managed_sink
            .iter()
            .find(|s| s.name.as_str() == name)
            .and_then(|s| serde_json::to_value(s).ok())
    };
    let before = find(&before_cfg);
    let (body, stored_body) = if let Some(v) = &w.body {
        let s = parse_sink(&name, v)?;
        if before.is_none() && entries.sinks.len() >= MAX_SINKS {
            return Err(Problem::new(
                Code::InvalidConfig,
                format!("at most {MAX_SINKS} event sinks can be made in the UI"),
            ));
        }
        let text = serde_json::to_string(&s).map_err(|e| Problem::internal(e.to_string()))?;
        entries.sinks.retain(|(n, _)| *n != name);
        entries.sinks.push((name.clone(), s));
        (Some(v.clone()), Some(text))
    } else {
        if before.is_none() {
            return Err(Problem::not_found(format!("no sink is named `{name}`")));
        }
        entries.sinks.retain(|(n, _)| *n != name);
        (None, None)
    };
    let merged = crate::managed::merge(&file, &entries)
        .map_err(|errs| Problem::new(Code::InvalidConfig, errs.join("; ")))?;
    let after = find(&merged);
    // OPS-014 (ADR-903 section 4) - the reference names a stored secret; one pointed at another
    // kind's secret is a redirect, audited as such.
    let redirect = match &body {
        Some(b) => secret_references(src, w, &name, &before_cfg, b)?,
        None => None,
    };
    let mut warnings = wrendns_config::validate_config(&merged).unwrap_or_default();
    if src.cluster.is_some() {
        // REQ: CLU-010 - a member older than this feature ignores the blob.
        warnings.push(
            "members older than this version ignore event sinks made in the UI until they're upgraded."
                .to_owned(),
        );
        if body
            .as_ref()
            .is_some_and(|b| b.get("token_ref").is_some_and(|t| !t.is_null()))
        {
            warnings.push(
                "resolver pods hold no stored secrets: a sink that names a stored token isn't started on them."
                    .to_owned(),
            );
        }
    }
    if redirect.is_some() {
        warnings.push(format!(
            "This points `{name}`'s token at a secret another entry uses: the change is audited as credential.redirect and raises the credential_redirected alert."
        ));
    }
    Ok(ManagedPlan {
        name,
        before,
        after,
        body: stored_body,
        recent_queries: 0,
        impact: "Started, changed or stopped on every node within seconds, without a restart. A removed sink sends what it holds and ends, and the batches it kept on disk are deleted.".to_owned(),
        warnings,
        also: Vec::new(),
        candidate: merged,
        redirect,
        node: None,
    })
}

fn plan_otlp(
    src: &Sources,
    state: &wrendns_store::state::State,
    w: &ManagedWrite,
) -> Result<ManagedPlan, Problem> {
    let file = src.file_config.load_full();
    if file.telemetry.otlp_set_by_file() {
        return Err(Problem::new(
            Code::SetByFile,
            "the configuration files set the OTLP destination (endpoint, headers or header_refs), which wins: it's read-only here",
        )
        .hint("Change it in the configuration file. The UI shows it as set by file."));
    }
    let mut entries: Entries = crate::managed::entries(state);
    let before_cfg: Config =
        crate::managed::merge(&file, &entries).unwrap_or_else(|_| (*file).clone());
    let find = |c: &Config| {
        c.telemetry
            .managed_otlp
            .as_ref()
            .and_then(|o| serde_json::to_value(o).ok())
    };
    let before = find(&before_cfg);
    let (stored_body, redirect) = if let Some(v) = &w.body {
        let o = parse_otlp(v)?;
        let redirect = otlp_references(src, &before_cfg, &o)?;
        let text = serde_json::to_string(&o).map_err(|e| Problem::internal(e.to_string()))?;
        // REQ: OBS-006 (issue #155) - gzip waits until every member's build reads the field
        // (the same feature gate as the dnstap settings; plain JSON is never held).
        if o.compression != wrendns_config::OtlpCompression::None
            && let Err(why) = crate::upgrade_gate::enforce(
                src.cluster.as_deref(),
                wrendns_cluster::gate::Feature::OtlpCompression,
            )
        {
            return Err(Problem::new(Code::UpgradeRequired, why)
                .hint("Upgrade the member named, then make this change again."));
        }
        entries.otlp = Some(o);
        (Some(text), redirect)
    } else {
        if before.is_none() {
            return Err(Problem::not_found("the API sets no OTLP export"));
        }
        entries.otlp = None;
        (None, None)
    };
    let merged = crate::managed::merge(&file, &entries)
        .map_err(|errs| Problem::new(Code::InvalidConfig, errs.join("; ")))?;
    let after = find(&merged);
    let mut warnings = wrendns_config::validate_config(&merged).unwrap_or_default();
    if src.cluster.is_some() {
        warnings.push(
            "members older than this version ignore the OTLP export made in the UI until they're upgraded."
                .to_owned(),
        );
    }
    if redirect.is_some() {
        warnings.push(
            "This points a header at a secret another entry uses: the change is audited as credential.redirect and raises the credential_redirected alert."
                .to_owned(),
        );
    }
    Ok(ManagedPlan {
        name: crate::managed::OTLP_NAME.to_owned(),
        before,
        after,
        body: stored_body,
        recent_queries: 0,
        impact: "Applied on every node at its next export, without a restart; the headers are read for every export.".to_owned(),
        warnings,
        also: Vec::new(),
        candidate: merged,
        redirect,
        node: None,
    })
}

/// OPS-014 (ADR-903 section 4) - each header reference names a stored secret (422
/// `secret_missing`), and one changed to a secret another kind uses is a redirect (the audit
/// detail returned).
fn otlp_references(
    src: &Sources,
    current: &Config,
    o: &OtlpConfig,
) -> Result<Option<serde_json::Value>, Problem> {
    let used = wrendns_config::secret_refs::references(current);
    let before = current.telemetry.otlp_effective().header_refs.clone();
    let mut redirect = None;
    for (header, secret) in &o.header_refs {
        let secret = secret.as_str();
        if !src.secrets.exists(secret) {
            return Err(Problem::new(
                Code::SecretMissing,
                format!(
                    "`header_refs.{header}`: no stored secret is named `{secret}` on this node"
                ),
            )
            .hint(
                "Set the secret first (Settings -> Integrations & secrets), then name it here.",
            ));
        }
        let was = before.get(header).map(ToString::to_string);
        let others: Vec<&str> = used
            .iter()
            .filter(|r| r.name == secret && r.kind != "otlp")
            .map(|r| r.kind)
            .collect();
        if was.as_deref() != Some(secret) && !others.is_empty() && redirect.is_none() {
            redirect = Some(serde_json::json!({
                "kind": "otlp",
                "name": "default",
                "field": format!("header_refs.{header}"),
                "from": was,
                "to": secret,
                "secretUsedBy": others,
            }));
        }
    }
    Ok(redirect)
}

/// A readable token, as the list shows it.
fn token_view(src: &Sources, s: &SinkConfig) -> (&'static str, Option<String>, Option<bool>) {
    if let Some(r) = s.token_ref.as_ref() {
        (
            "stored",
            Some(r.to_string()),
            Some(src.secrets.readable(r.as_str()).is_ok()),
        )
    } else if s.token_file.is_some() {
        (
            "file",
            None,
            Some(
                crate::secrets::Credential::of(s.token_file.as_ref(), None)
                    .resolve(Some(&src.secrets))
                    .is_ok(),
            ),
        )
    } else {
        ("none", None, None)
    }
}

/// `GET /api/v1/config/entries?kind=sink`: one sink as the generic entry editor reads it (the
/// files' are read-only there; a UI sink's file name is its `path`).
pub(crate) fn config_entry(
    cfg: &Config,
    s: &SinkConfig,
    from_file: bool,
) -> wrendns_api::model::ConfigEntry {
    let mut definition = serde_json::to_value(s).unwrap_or_default();
    if let Some(u) = definition.get("url").and_then(serde_json::Value::as_str) {
        definition["url"] = serde_json::Value::String(wrendns_config::credentials::url_shown(u));
    }
    if !from_file && s.kind == SinkKind::File {
        let dir = std::path::Path::new(cfg.node.data_dir.as_str()).join("sinks");
        if let Some(n) = s
            .path
            .as_ref()
            .and_then(|p| std::path::Path::new(p.as_str()).strip_prefix(&dir).ok())
            .and_then(|p| p.to_str())
        {
            definition["path"] = serde_json::Value::String(n.to_owned());
        }
    }
    let set_by_file = if from_file {
        ["token_file", "tls_ca"]
            .into_iter()
            .filter(|k| definition.get(*k).is_some_and(|v| !v.is_null()))
            .map(str::to_owned)
            .collect()
    } else {
        Vec::new()
    };
    wrendns_api::model::ConfigEntry {
        kind: "sink".to_owned(),
        name: s.name.to_string(),
        source: if from_file { "file" } else { "added" }.to_owned(),
        definition: Some(definition),
        redacted: Vec::new(),
        credential_issues: Vec::new(),
        set_by_file,
        answering: None,
    }
}

/// `GET /api/v1/sinks`: the sinks in effect on this node, the files' first.
pub(crate) fn list(src: &Sources) -> SinkList {
    let cfg = src.config.load_full();
    let t = &cfg.telemetry;
    let dir = std::path::Path::new(cfg.node.data_dir.as_str()).join("sinks");
    let states = src.sinks.states();
    let drops = src.sinks.drops();
    let entry = |s: &SinkConfig, from_file: bool| -> SinkEntry {
        let mut definition = serde_json::to_value(s).unwrap_or_default();
        let mut location = match s.kind {
            SinkKind::File => s.path.as_ref().map(ToString::to_string).unwrap_or_default(),
            SinkKind::Syslog => s
                .address
                .as_ref()
                .map(|a| wrendns_config::credentials::url_shown(a.as_str()))
                .unwrap_or_default(),
            SinkKind::Webhook => s
                .url
                .as_ref()
                .map(|u| wrendns_config::credentials::url_shown(u.as_str()))
                .unwrap_or_default(),
        };
        // A file sink made in the UI shows (and edits) its file name; the files' show the path.
        if !from_file && s.kind == SinkKind::File {
            let full = std::path::Path::new(&location);
            if let Some(n) = full.strip_prefix(&dir).ok().and_then(|p| p.to_str()) {
                definition["path"] = serde_json::Value::String(n.to_owned());
            }
        }
        // A URL's password is never in the definition.
        if let Some(u) = definition.get("url").and_then(serde_json::Value::as_str) {
            definition["url"] =
                serde_json::Value::String(wrendns_config::credentials::url_shown(u));
        }
        if let Some(a) = definition
            .get("address")
            .and_then(serde_json::Value::as_str)
        {
            definition["address"] =
                serde_json::Value::String(wrendns_config::credentials::url_shown(a));
        }
        if location.is_empty() {
            "-".clone_into(&mut location);
        }
        let (token_source, token, token_readable) = token_view(src, s);
        let st = states.iter().find(|x| x.name == s.name.as_str());
        let (running, reason) = match st {
            Some(x) => (x.running, x.reason.clone()),
            None => (false, Some("not applied on this node yet".to_owned())),
        };
        SinkEntry {
            name: s.name.to_string(),
            kind: match s.kind {
                SinkKind::File => "file",
                SinkKind::Syslog => "syslog",
                SinkKind::Webhook => "webhook",
            }
            .to_owned(),
            source: if from_file { "file" } else { "api" }.to_owned(),
            location,
            definition,
            token_source: token_source.to_owned(),
            token,
            token_readable,
            running,
            reason,
            dropped: drops
                .iter()
                .find(|(n, _)| n == s.name.as_str())
                .map_or(0, |(_, d)| *d),
        }
    };
    let mut items: Vec<SinkEntry> = t.sink.iter().map(|s| entry(s, true)).collect();
    items.extend(t.managed_sink.iter().map(|s| entry(s, false)));
    SinkList {
        items,
        files_dir: dir.to_string_lossy().into_owned(),
    }
}

/// `GET /api/v1/otlp`: the OTLP export in effect on this node.
pub(crate) fn otlp_entry(src: &Sources) -> OtlpEntry {
    let cfg = src.config.load_full();
    let t = &cfg.telemetry;
    let o = t.otlp_effective();
    let source = if t.otlp_set_by_file() {
        "file"
    } else if t.managed_otlp.is_some() {
        "api"
    } else {
        "none"
    };
    let mut headers: Vec<OtlpHeader> = o
        .headers
        .keys()
        .map(|k| OtlpHeader {
            name: k.to_string(),
            source: "inline".to_owned(),
            secret: None,
            readable: None,
            value: Some(wrendns_config::credentials::MARKER.to_owned()),
        })
        .collect();
    headers.extend(o.header_refs.iter().map(|(k, n)| OtlpHeader {
        name: k.to_string(),
        source: "stored".to_owned(),
        secret: Some(n.to_string()),
        readable: Some(src.secrets.readable(n.as_str()).is_ok()),
        value: None,
    }));
    let pod_skips = cfg.cluster.ephemeral && !o.header_refs.is_empty();
    let (active, reason) = match (&o.endpoint, pod_skips) {
        (None, _) => (false, None),
        (Some(_), true) => (
            false,
            Some("this resolver pod holds no stored secrets: an export that needs one isn't made here".to_owned()),
        ),
        (Some(_), false) => (true, None),
    };
    OtlpEntry {
        source: source.to_owned(),
        endpoint: o
            .endpoint
            .as_ref()
            .map(|e| wrendns_config::credentials::url_shown(e.as_str())),
        interval_secs: o.interval_secs,
        headers,
        traces_sample_every: o.traces_sample_every,
        traces_slow_ms: o.traces_slow_ms,
        compression: o.compression.as_str().to_owned(),
        active,
        reason,
    }
}

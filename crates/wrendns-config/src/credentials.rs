//! REQ: API-014, OPS-011, AGT-010 (ADR-903 §4) — the credential fields of the configuration, and
//! the one redaction every read surface applies before a body leaves the node: the API's entry
//! listings and write responses, the audit log, the stored idempotency responses, the TOML to keep
//! a change in Git, forward logging, `wrendns config check --print`, the pin and version diffs,
//! and so every MCP read tool and resource, which read those routes.
//!
//! A credential comes back as [`MARKER`]; a URL keeps its host, with only its credentials replaced
//! (`https://me:<redacted>@doh.example/dns-query`; a password-less user name, and the values of
//! query parameters such as `token`, are replaced too). A write that sends the marker back
//! keeps the stored value, but only while the entry's destination is unchanged
//! ([`restore_markers`]): a credential is never sent to a new place without being typed again.

use serde_json::Value;

use crate::Config;
use crate::SafeString;

/// What a credential reads as wherever it is shown.
pub const MARKER: &str = "<redacted>";

/// Which part of a field is the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// The whole value (each value, for a map or a list).
    Whole,
    /// The password in a URL's user information (`scheme://user:password@host`).
    UrlPassword,
}

/// One credential field, by its path in the configuration: `[]` is each entry of an array of
/// tables, `[*]` each item of a list, and `.*` each value of a map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Credential {
    pub path: &'static str,
    pub part: Part,
}

/// REQ: API-014 — every credential field. `api_014_credential_paths_cover_secret_class` fails when
/// a field the support package classes `secret` is in neither this table nor [`NOT_CREDENTIALS`].
pub const PATHS: &[Credential] = &[
    Credential {
        path: "upstream[].headers.*",
        part: Part::Whole,
    },
    Credential {
        path: "upstream[].args[*]",
        part: Part::Whole,
    },
    Credential {
        path: "upstream[].url",
        part: Part::UrlPassword,
    },
    Credential {
        path: "upstream[].proxy",
        part: Part::UrlPassword,
    },
    Credential {
        path: "upstream[].relay",
        part: Part::UrlPassword,
    },
    Credential {
        path: "alerts.destination[].url",
        part: Part::UrlPassword,
    },
    // REQ: API-014 (review of T23.1) — every other field the support package classes `url`: a
    // password in any of them is redacted the same way (`api_014_credential_paths_cover_url_class`).
    Credential {
        path: "list[].url",
        part: Part::UrlPassword,
    },
    Credential {
        path: "router[].url",
        part: Part::UrlPassword,
    },
    Credential {
        path: "cluster.git.repo",
        part: Part::UrlPassword,
    },
    Credential {
        path: "cluster.join_url",
        part: Part::UrlPassword,
    },
    Credential {
        path: "telemetry.otlp.endpoint",
        part: Part::UrlPassword,
    },
    Credential {
        path: "telemetry.ship.to",
        part: Part::UrlPassword,
    },
    Credential {
        path: "telemetry.sink[].url",
        part: Part::UrlPassword,
    },
    Credential {
        path: "updates.index_url",
        part: Part::UrlPassword,
    },
    Credential {
        path: "auth.oidc.public_url",
        part: Part::UrlPassword,
    },
    Credential {
        path: "auth.oidc.provider[].issuer",
        part: Part::UrlPassword,
    },
    Credential {
        path: "auth.oidc.provider[].client_secret",
        part: Part::Whole,
    },
    Credential {
        path: "telemetry.otlp.headers.*",
        part: Part::Whole,
    },
];

/// Fields the support package keeps out (class `secret`) that aren't credentials, and why: they
/// stay visible in the API, where an operator needs them to recognize an entry.
pub const NOT_CREDENTIALS: &[(&str, &str)] = &[
    (
        "alerts.destination[].username",
        "a mail account's name: identifies the login, grants nothing without the password",
    ),
    (
        "router[].username",
        "a router account's name: grants nothing without the password or key file",
    ),
    (
        "discovery.snmp_credential[].user",
        "a USM user name: names the account, grants nothing without the authentication password",
    ),
    (
        "auth.oidc.provider[].client_id",
        "an OAuth client's public identifier (it travels in every browser redirect)",
    ),
];

/// Fields that say where an entry's credential goes (ADR-903 §4). The scheme is part of `url`.
/// REQ: API-014 (review of T23.2, ADR-903 note 21) — also what proves the other end is that
/// place (`tls_insecure_skip_verify`, `spki_pins`: turning verification off sends the credential
/// to whoever is on the path) and how it is sent (an alert destination's `type`).
pub const DESTINATION_FIELDS: &[&str] = &[
    "url",
    "proxy",
    "host",
    "tls_server_name",
    "tls_ca",
    "bootstrap",
    "tls_insecure_skip_verify",
    "spki_pins",
    "type",
];

/// REQ: API-014 (ADR-903 §4, T23.2) — the file paths an API entry may set (`kind` as the API
/// names it), and whether the file holds a credential: such a file is changed by an admin only,
/// and must sit under `[node] secret_file_dirs`. Every path is held to the denied prefixes.
/// `api_014_api_paths_cover_path_fields` checks the list against the schema.
pub const API_PATHS: &[(&str, &str, bool)] = &[
    ("upstream", "tls_ca", false),
    ("upstream", "tls_client_cert", false),
    ("upstream", "tls_client_key", true),
    ("alert_destination", "token_file", true),
    ("alert_destination", "password_file", true),
    ("alert_destination", "user_key_file", true),
    ("alert_destination", "tls_ca", false),
    ("list", "path", false),
];

/// A field as compared for a change: absent, `null`, `""`, `[]` and `{}` are the same.
fn normalized(v: Option<&Value>) -> Value {
    match v {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(s)) if s.is_empty() => Value::Null,
        Some(Value::Array(a)) if a.is_empty() => Value::Null,
        Some(Value::Object(m)) if m.is_empty() => Value::Null,
        Some(other) => other.clone(),
    }
}

/// Whether `key` names a reference to a stored secret (`token_ref`, `header_refs`; T23.3).
fn is_reference(key: &str) -> bool {
    key.ends_with("_ref") || key.ends_with("_refs")
}

/// REQ: API-014 (T23.2) — whether an entry (`kind` as the API names it) holds a credential: a
/// value in a credential field (a header, an argument, a URL's password; the marker too, which
/// stands for a stored value), a file holding one, or a reference to a stored secret.
#[must_use]
pub fn holds_credential(kind: &str, entry: &Value) -> bool {
    let mut probe = entry.clone();
    let mut found = false;
    for (path, part) in entry_paths(kind) {
        visit(&mut probe, &segments(path), "", &mut |_, leaf| {
            found |= match (part, &*leaf) {
                (Part::Whole, Value::String(s)) => !s.is_empty(),
                (Part::UrlPassword, Value::String(s)) => !url_edits(s).is_empty(),
                _ => false,
            };
        });
    }
    let file = API_PATHS
        .iter()
        .any(|(k, f, cred)| *cred && *k == kind && normalized(entry.get(*f)) != Value::Null);
    let reference = entry.as_object().is_some_and(|m| {
        m.iter()
            .any(|(k, v)| is_reference(k) && normalized(Some(v)) != Value::Null)
    });
    found || file || reference
}

/// REQ: API-014 (T23.2) — the first destination field ([`DESTINATION_FIELDS`]) `after` sets
/// differently from `before`. A URL is compared without its password (and with its scheme).
#[must_use]
pub fn destination_change(before: &Value, after: &Value) -> Option<&'static str> {
    DESTINATION_FIELDS
        .iter()
        .find(|f| destination(before.get(**f)) != destination(after.get(**f)))
        .copied()
}

/// REQ: API-014 (T23.2) — the credential-file and secret-reference fields (`*_file`, `*_ref`,
/// an upstream's `tls_client_key`) `after` sets differently from `before` (`None`: a new entry).
#[must_use]
pub fn reference_changes(kind: &str, before: Option<&Value>, after: &Value) -> Vec<String> {
    let mut keys: Vec<String> = API_PATHS
        .iter()
        .filter(|(k, _, cred)| *cred && *k == kind)
        .map(|(_, f, _)| (*f).to_owned())
        .collect();
    for v in [before, Some(after)].into_iter().flatten() {
        if let Some(m) = v.as_object() {
            keys.extend(
                m.keys()
                    .filter(|k| is_reference(k) || k.ends_with("_file"))
                    .cloned(),
            );
        }
    }
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|k| {
            normalized(before.and_then(|b| b.get(k.as_str()))) != normalized(after.get(k.as_str()))
        })
        .collect()
}

/// REQ: API-014 (T23.2) — whether an upstream URL runs a program on the node or talks to a
/// local socket (`exec://`, `unix://`): only an admin sets one up.
#[must_use]
pub fn runs_program(url: &str) -> bool {
    let u = url.trim().to_ascii_lowercase();
    u.starts_with("exec://") || u.starts_with("unix://")
}

/// REQ: API-014 (T23.2) — whether an upstream write creates, or switches to, one that
/// [`runs_program`], or changes which program (its URL) or command line (`args`) an existing one
/// runs. Other changes to such an upstream (its weight, timeout) aren't.
#[must_use]
pub fn program_change(before: Option<&Value>, after: &Value) -> bool {
    if !runs_program(after.get("url").and_then(Value::as_str).unwrap_or_default()) {
        return false;
    }
    let Some(before) = before else {
        return true;
    };
    ["url", "args"]
        .iter()
        .any(|f| normalized(before.get(*f)) != normalized(after.get(*f)))
}

/// The configuration path of an API entry kind's array (`upstream` → `upstream[]`).
#[must_use]
pub fn entry_prefix(kind: &str) -> Option<&'static str> {
    match kind {
        "upstream" => Some("upstream[]"),
        "alert_destination" => Some("alerts.destination[]"),
        "list" => Some("list[]"),
        // REQ: API-016 (review of T23.7) — a router's URL can carry a password, as a list's can.
        "router" => Some("router[]"),
        // REQ: API-016 (T23.11) — a sink's URL can carry a password, as a router's can.
        "sink" => Some("telemetry.sink[]"),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seg<'a> {
    Key(&'a str),
    /// Each element of an array.
    Each,
    /// Each value of a map.
    AnyKey,
}

fn segments(path: &str) -> Vec<Seg<'_>> {
    let mut out = Vec::new();
    for part in path.split('.') {
        if part == "*" {
            out.push(Seg::AnyKey);
        } else if let Some(k) = part.strip_suffix("[]").or_else(|| part.strip_suffix("[*]")) {
            out.push(Seg::Key(k));
            out.push(Seg::Each);
        } else {
            out.push(Seg::Key(part));
        }
    }
    out
}

/// The paths of [`PATHS`] under an entry kind, relative to one entry (`headers.*`, `args[*]`,
/// `url`).
fn entry_paths(kind: &str) -> Vec<(&'static str, Part)> {
    let Some(prefix) = entry_prefix(kind) else {
        return Vec::new();
    };
    PATHS
        .iter()
        .filter_map(|c| {
            c.path
                .strip_prefix(prefix)
                .and_then(|p| p.strip_prefix('.'))
                .map(|p| (p, c.part))
        })
        .collect()
}

/// Calls `f` with every value at `segs` under `v` and its concrete path.
fn visit(v: &mut Value, segs: &[Seg<'_>], here: &str, f: &mut dyn FnMut(&str, &mut Value)) {
    let Some((first, rest)) = segs.split_first() else {
        f(here, v);
        return;
    };
    let join = |k: &str| {
        if here.is_empty() {
            k.to_owned()
        } else {
            format!("{here}.{k}")
        }
    };
    match first {
        Seg::Key(k) => {
            if let Some(inner) = v.get_mut(*k) {
                visit(inner, rest, &join(k), f);
            }
        }
        Seg::Each => {
            if let Value::Array(items) = v {
                for (i, item) in items.iter_mut().enumerate() {
                    visit(item, rest, &format!("{here}[{i}]"), f);
                }
            }
        }
        Seg::AnyKey => {
            if let Value::Object(m) = v {
                for (k, item) in m.iter_mut() {
                    visit(item, rest, &join(k), f);
                }
            }
        }
    }
}

/// `scheme://user:password@host...` → where the password starts and ends. Conservative: the user
/// information runs to the last `@` before any `?` or `#`, so a password with a stray `/` is
/// still found.
fn password_span(url: &str) -> Option<(usize, usize)> {
    let start = url.find("://")? + 3;
    let stop = url[start..]
        .find(['?', '#'])
        .map_or(url.len(), |i| start + i);
    let at = start + url[start..stop].rfind('@')?;
    let colon = start + url[start..at].find(':')?;
    (colon + 1 < at).then_some((colon + 1, at))
}

/// `(from, to)` of the user name of `url` when it has no password: a token can be the user name
/// (`https://ghp_…@github.com/org/repo.git`).
fn user_span(url: &str) -> Option<(usize, usize)> {
    let start = url.find("://")? + 3;
    let stop = url[start..]
        .find(['?', '#'])
        .map_or(url.len(), |i| start + i);
    let at = start + url[start..stop].rfind('@')?;
    let end = match url[start..at].find(':') {
        Some(i) => start + i,
        None => at,
    };
    (end > start).then_some((start, end))
}

/// Query parameters whose values are credentials (ADR-903 §4, amended): a list URL can carry its
/// token there (`https://lists.example/ads.txt?token=…`).
const SECRET_QUERY_PARAMS: &[&str] = &[
    "token",
    "key",
    "apikey",
    "api_key",
    "access_token",
    "auth",
    "sig",
    "signature",
    "password",
];

/// `(from, to)` of each secret query value in `url` (the name is kept).
fn secret_query_spans(url: &str) -> Vec<(usize, usize)> {
    let end = url.find('#').unwrap_or(url.len());
    let Some(q) = url[..end].find('?') else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut pos = q + 1;
    for seg in url[q + 1..end].split('&') {
        let seg_start = pos;
        pos += seg.len() + 1;
        let Some(eq) = seg.find('=') else {
            continue;
        };
        let name = &seg[..eq];
        if eq + 1 < seg.len()
            && SECRET_QUERY_PARAMS
                .iter()
                .any(|p| name.eq_ignore_ascii_case(p))
        {
            out.push((seg_start + eq + 1, seg_start + seg.len()));
        }
    }
    out
}

/// The spans of `url` that are credentials, in order: the password, else the user name, and each
/// secret query value.
fn url_edits(url: &str) -> Vec<(usize, usize)> {
    let mut edits = Vec::new();
    match password_span(url) {
        Some(span) => edits.push(span),
        None => edits.extend(user_span(url)),
    }
    edits.extend(secret_query_spans(url));
    edits.sort_unstable();
    edits
}

/// REQ: API-014 — `url` with its credentials replaced by [`MARKER`]: the password (or, without
/// one, the user name) and the secret query values. `None` when it holds none.
#[must_use]
pub fn redact_url(url: &str) -> Option<String> {
    let edits = url_edits(url);
    if edits.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(url.len());
    let mut last = 0;
    for (from, to) in edits {
        out.push_str(&url[last..from]);
        out.push_str(MARKER);
        last = to;
    }
    out.push_str(&url[last..]);
    Some(out)
}

/// `url` with any password replaced by [`MARKER`] (unchanged when it has none).
#[must_use]
pub fn url_shown(url: &str) -> String {
    redact_url(url).unwrap_or_else(|| url.to_owned())
}

fn url_has_marker(url: &str) -> bool {
    url_edits(url).iter().any(|&(a, b)| &url[a..b] == MARKER)
}

/// Redacts the leaf `v`; true when it held a credential (or already the marker).
fn redact_leaf(v: &mut Value, part: Part) -> bool {
    let Value::String(s) = v else {
        return false;
    };
    match part {
        Part::Whole if !s.is_empty() => {
            MARKER.clone_into(s);
            true
        }
        Part::Whole => false,
        Part::UrlPassword => match redact_url(s) {
            Some(r) => {
                *s = r;
                true
            }
            None => false,
        },
    }
}

/// REQ: API-014 — redacts one API entry's definition (`kind` as `GET /config/entries` names it)
/// in place; returns the paths redacted, relative to the entry (`headers.Authorization`,
/// `args[1]`, `url`), for `ConfigEntry.redacted`.
pub fn redact_entry(kind: &str, v: &mut Value) -> Vec<String> {
    let mut out = Vec::new();
    for (path, part) in entry_paths(kind) {
        visit(v, &segments(path), "", &mut |p, leaf| {
            if redact_leaf(leaf, part) {
                out.push(p.to_owned());
            }
        });
    }
    out
}

/// REQ: API-014 — redacts a whole configuration (or its shared part) as JSON, in place; returns
/// the concrete paths redacted (`upstream[0].headers.Authorization`).
pub fn redact_json(v: &mut Value) -> Vec<String> {
    let mut out = Vec::new();
    for c in PATHS {
        visit(v, &segments(c.path), "", &mut |p, leaf| {
            if redact_leaf(leaf, c.part) {
                out.push(p.to_owned());
            }
        });
    }
    out
}

/// Calls `f` with every value at `segs` under `v` and its JSON Pointer (RFC 6901).
fn visit_ptr(v: &Value, segs: &[Seg<'_>], here: &str, f: &mut dyn FnMut(&str, &Value)) {
    let Some((first, rest)) = segs.split_first() else {
        f(here, v);
        return;
    };
    let esc = |k: &str| format!("{here}/{}", k.replace('~', "~0").replace('/', "~1"));
    match first {
        Seg::Key(k) => {
            if let Some(inner) = v.get(*k) {
                visit_ptr(inner, rest, &esc(k), f);
            }
        }
        Seg::Each => {
            if let Value::Array(items) = v {
                for (i, item) in items.iter().enumerate() {
                    visit_ptr(item, rest, &format!("{here}/{i}"), f);
                }
            }
        }
        Seg::AnyKey => {
            if let Value::Object(m) = v {
                for (k, item) in m {
                    visit_ptr(item, rest, &esc(k), f);
                }
            }
        }
    }
}

/// REQ: API-014, CLU-013 — the JSON Pointers of credentials that differ between two whole
/// configurations `a` and `b` although they read the same redacted (a header's value, or only
/// a URL's password, changed). A diff of the redacted sides can't see these, so a pin's diff
/// lists them with the marker as the value: the change shows, the values don't.
#[must_use]
pub fn hidden_changes(a: &Value, b: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for c in PATHS {
        visit_ptr(b, &segments(c.path), "", &mut |ptr, new| {
            let Some(old) = a.pointer(ptr) else {
                return;
            };
            if old == new {
                return;
            }
            let (mut x, mut y) = (old.clone(), new.clone());
            if redact_leaf(&mut x, c.part) && redact_leaf(&mut y, c.part) && x == y {
                out.push(ptr.to_owned());
            }
        });
    }
    out
}

fn marker() -> SafeString {
    SafeString::from(MARKER)
}

fn redact_url_field(s: &mut SafeString) {
    if let Some(r) = redact_url(s).and_then(|r| SafeString::new(r).ok()) {
        *s = r;
    }
}

/// REQ: API-014 — the same redaction on a typed configuration (`wrendns config check --print`
/// keeps the files' key order this way). `api_014_typed_and_json_redaction_agree` holds the two
/// to the same table.
pub fn redact_config(c: &mut Config) {
    for u in &mut c.upstream {
        for v in u.headers.values_mut() {
            if !v.is_empty() {
                *v = marker();
            }
        }
        for a in &mut u.args {
            if !a.is_empty() {
                *a = marker();
            }
        }
        redact_url_field(&mut u.url);
        for p in [&mut u.proxy, &mut u.relay].into_iter().flatten() {
            redact_url_field(p);
        }
    }
    for d in &mut c.alerts.destination {
        redact_url_field(&mut d.url);
    }
    for l in &mut c.list {
        if let Some(u) = &mut l.url {
            redact_url_field(u);
        }
    }
    for r in &mut c.router {
        redact_url_field(&mut r.url);
    }
    if let Some(g) = &mut c.cluster.git {
        redact_url_field(&mut g.repo);
    }
    redact_url_field(&mut c.auth.oidc.public_url);
    for p in &mut c.auth.oidc.provider {
        redact_url_field(&mut p.issuer);
        if let Some(s) = &mut p.client_secret
            && !s.is_empty()
        {
            *s = marker();
        }
    }
    for v in c.telemetry.otlp.headers.values_mut() {
        if !v.is_empty() {
            *v = marker();
        }
    }
    for s in &mut c.telemetry.sink {
        if let Some(u) = &mut s.url {
            redact_url_field(u);
        }
    }
    for u in [
        &mut c.cluster.join_url,
        &mut c.telemetry.otlp.endpoint,
        &mut c.telemetry.ship.to,
        &mut c.updates.index_url,
    ]
    .into_iter()
    .flatten()
    {
        redact_url_field(u);
    }
}

/// Whether the leaf `v` holds a credential's value (not empty, not the marker).
fn holds_value(v: &Value, part: Part) -> bool {
    let Value::String(s) = v else {
        return false;
    };
    match part {
        Part::Whole => !s.is_empty() && s != MARKER,
        Part::UrlPassword => !url_edits(s).is_empty() && !url_has_marker(s),
    }
}

/// REQ: API-014 — whether an entry body (`kind` as the API names it) sets any credential field
/// to a value (so storing it keyed needs the node key). A `<redacted>` sent back is no value: a
/// body of markers only holds nothing secret.
#[must_use]
pub fn has_credential(kind: &str, body: &Value) -> bool {
    let mut probe = body.clone();
    let mut found = false;
    for (path, part) in entry_paths(kind) {
        visit(&mut probe, &segments(path), "", &mut |_, leaf| {
            found |= holds_value(leaf, part);
        });
    }
    found
}

/// Every place `body` sends the marker back, relative to the entry.
fn markers(kind: &str, body: &mut Value) -> Vec<(String, Part)> {
    let mut out = Vec::new();
    for (path, part) in entry_paths(kind) {
        visit(body, &segments(path), "", &mut |p, leaf| {
            let hit = match (part, &*leaf) {
                (Part::Whole, Value::String(s)) => s == MARKER,
                (Part::UrlPassword, Value::String(s)) => url_has_marker(s),
                _ => false,
            };
            if hit {
                out.push((p.to_owned(), part));
            }
        });
    }
    out
}

/// REQ: API-014, OPS-014 — the concrete paths in a whole configuration (as JSON) of every
/// credential that reads [`MARKER`]: a value, or a URL's password. A redacted copy
/// (`config check --print`) shows these; files that hold one are refused at load.
#[must_use]
pub fn marker_paths(config: &Value) -> Vec<String> {
    let mut probe = config.clone();
    let mut out = Vec::new();
    for c in PATHS {
        visit(&mut probe, &segments(c.path), "", &mut |p, leaf| {
            let hit = match (c.part, &*leaf) {
                (Part::Whole, Value::String(s)) => s == MARKER,
                (Part::UrlPassword, Value::String(s)) => url_has_marker(s),
                _ => false,
            };
            if hit {
                out.push(p.to_owned());
            }
        });
    }
    out
}

/// REQ: API-014 — whether an entry body sends [`MARKER`] back anywhere (checks refuse it: they
/// never resolve markers).
#[must_use]
pub fn has_marker(kind: &str, body: &Value) -> bool {
    let mut probe = body.clone();
    !markers(kind, &mut probe).is_empty()
}

/// A destination field as compared: absent, null, empty, `[]` and `false` are the same; a URL
/// without its password.
fn destination(v: Option<&Value>) -> Value {
    match v {
        None | Some(Value::Null | Value::Bool(false)) => Value::Null,
        Some(Value::String(s)) if s.is_empty() => Value::Null,
        Some(Value::Array(a)) if a.is_empty() => Value::Null,
        Some(Value::String(s)) => Value::String(url_shown(s)),
        Some(other) => other.clone(),
    }
}

/// The value at a concrete path from [`redact_entry`] (`headers.Authorization`, `args[1]`).
fn at<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for part in path.split('.') {
        let (key, index) = match part.split_once('[') {
            Some((k, i)) => (k, i.trim_end_matches(']').parse::<usize>().ok()),
            None => (part, None),
        };
        cur = cur.get(key)?;
        if let Some(i) = index {
            cur = cur.get(i)?;
        }
    }
    Some(cur)
}

fn at_mut<'a>(v: &'a mut Value, path: &str) -> Option<&'a mut Value> {
    let mut cur = v;
    for part in path.split('.') {
        let (key, index) = match part.split_once('[') {
            Some((k, i)) => (k, i.trim_end_matches(']').parse::<usize>().ok()),
            None => (part, None),
        };
        cur = cur.get_mut(key)?;
        if let Some(i) = index {
            cur = cur.get_mut(i)?;
        }
    }
    Some(cur)
}

/// Why a marker can't be kept: the write has to carry the credential itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reentry {
    /// The entry's field with the marker (`headers.Authorization`).
    pub field: String,
    /// One sentence on why.
    pub why: String,
}

/// REQ: API-014 (ADR-903 §4, the marker rule) — a write that sends [`MARKER`] back keeps the
/// current value only while the entry's destination fields are unchanged; `current` is the entry
/// in effect now (its definition, unredacted). Replaces each marker in `body` with the current
/// value, or says which field must be typed again (422 `credential_reentry_required`): the
/// destination changed, or there is no current value.
pub fn restore_markers(
    kind: &str,
    body: &mut Value,
    current: Option<&Value>,
) -> Result<(), Reentry> {
    let found = markers(kind, body);
    let Some((first, _)) = found.first() else {
        return Ok(());
    };
    let Some(current) = current else {
        return Err(Reentry {
            field: first.clone(),
            why: format!("`{first}` is `{MARKER}`, and there is no stored value to keep"),
        });
    };
    for f in DESTINATION_FIELDS {
        if destination(body.get(*f)) != destination(current.get(*f)) {
            return Err(Reentry {
                field: first.clone(),
                why: format!(
                    "`{first}` is `{MARKER}`, and `{f}` changed: a credential isn't sent to a new destination without being entered again"
                ),
            });
        }
    }
    for (path, part) in found {
        // A URL with the marker keeps its password only while the URL itself is the same
        // (it's replaced whole by the stored one): a field that isn't a destination (a relay)
        // is held to that too.
        if part == Part::UrlPassword
            && destination(at(body, &path)) != destination(at(current, &path))
        {
            return Err(Reentry {
                field: path.clone(),
                why: format!(
                    "`{path}` sends `{MARKER}` for its password, and the URL changed: a credential isn't sent to a new destination without being entered again"
                ),
            });
        }
        let value = at(current, &path).filter(|v| holds_value(v, part));
        let Some(value) = value.cloned() else {
            return Err(Reentry {
                field: path.clone(),
                why: format!("`{path}` is `{MARKER}`, and there is no stored value to keep"),
            });
        };
        if let Some(slot) = at_mut(body, &path) {
            *slot = value;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn upstream() -> Value {
        json!({
            "name": "nextdns",
            "url": "https://me:hunter2@doh.example/dns-query",
            "headers": {"Authorization": "Bearer s3cret", "X-Device": "pi"},
            "args": ["--token", "abc"],
            "proxy": "socks5://p:pw@10.0.0.1:1080",
            "tls_server_name": "doh.example"
        })
    }

    #[test]
    fn api_014_urls_keep_user_and_host() {
        assert_eq!(
            redact_url("https://me:hunter2@doh.example/q?x=1").as_deref(),
            Some("https://me:<redacted>@doh.example/q?x=1")
        );
        assert_eq!(redact_url("https://doh.example/q"), None);
        // REQ: API-014 (ADR-903 §4, amended) — without a password the user name is the credential
        // (a token can be the user name).
        assert_eq!(
            redact_url("https://me@doh.example/q").as_deref(),
            Some("https://<redacted>@doh.example/q"),
            "no password: the user name is redacted"
        );
        assert_eq!(
            redact_url("https://ghp_xxx@github.com/org/repo.git").as_deref(),
            Some("https://<redacted>@github.com/org/repo.git")
        );
        assert_eq!(
            redact_url("https://me:@doh.example/q").as_deref(),
            Some("https://<redacted>:@doh.example/q"),
            "empty password: the user name is still the credential"
        );
        // REQ: API-014 — secret query values, whatever the URL's other parts.
        assert_eq!(
            redact_url("https://lists.example/ads.txt?token=SECRET&x=1").as_deref(),
            Some("https://lists.example/ads.txt?token=<redacted>&x=1")
        );
        assert_eq!(
            redact_url("https://h.example/a?x=1&API_KEY=k#frag").as_deref(),
            Some("https://h.example/a?x=1&API_KEY=<redacted>#frag"),
            "parameter names are case-insensitive"
        );
        assert_eq!(redact_url("https://h.example/a?tokens=1&q=token"), None);
        assert_eq!(redact_url("https://h.example/a?token="), None, "empty");
        // A stray `/` in a password is still covered.
        assert_eq!(
            redact_url("https://me:a/b@h.example/").as_deref(),
            Some("https://me:<redacted>@h.example/")
        );
        assert_eq!(redact_url("udp://9.9.9.9:53"), None);
    }

    #[test]
    fn api_014_entry_redaction_lists_paths() {
        let mut v = upstream();
        let mut paths = redact_entry("upstream", &mut v);
        paths.sort();
        assert_eq!(
            paths,
            [
                "args[0]",
                "args[1]",
                "headers.Authorization",
                "headers.X-Device",
                "proxy",
                "url"
            ]
        );
        let text = v.to_string();
        for planted in ["hunter2", "s3cret", "abc", ":pw@"] {
            assert!(!text.contains(planted), "{planted}: {text}");
        }
        assert_eq!(v["tls_server_name"], "doh.example");
        assert_eq!(
            redact_entry("record", &mut json!({"url": "https://a:b@c/"})),
            Vec::<String>::new()
        );
    }

    #[test]
    fn api_014_whole_config_json() {
        let mut v = json!({
            "upstream": [upstream()],
            "alerts": {"destination": [{"name": "hook", "url": "https://u:p4ss@hook.example/"}]},
            "auth": {"oidc": {"provider": [{"id": "kc", "client_secret": "cl13nt"}]}},
            "telemetry": {"otlp": {"headers": {"api-key": "0tlp"}}}
        });
        let paths = redact_json(&mut v);
        assert!(paths.contains(&"upstream[0].headers.Authorization".to_owned()));
        let text = v.to_string();
        for planted in ["hunter2", "s3cret", "p4ss", "cl13nt", "0tlp"] {
            assert!(!text.contains(planted), "{planted}: {text}");
        }
    }

    #[test]
    fn api_014_redacted_marker_rule() {
        let current = upstream();
        let mut shown = current.clone();
        redact_entry("upstream", &mut shown);
        // Sent back unchanged: every value is kept.
        let mut body = shown.clone();
        restore_markers("upstream", &mut body, Some(&current)).unwrap();
        assert_eq!(body, current);
        // A new URL host: re-entry.
        let mut moved = shown.clone();
        moved["url"] = json!("https://me:<redacted>@evil.example/dns-query");
        let e = restore_markers("upstream", &mut moved, Some(&current)).unwrap_err();
        assert!(e.why.contains("`url` changed"), "{e:?}");
        // A new TLS name: re-entry too.
        let mut renamed = shown.clone();
        renamed["tls_server_name"] = json!("other.example");
        assert!(restore_markers("upstream", &mut renamed, Some(&current)).is_err());
        // No current entry, or no current value at that place.
        assert!(restore_markers("upstream", &mut shown.clone(), None).is_err());
        let mut extra = shown.clone();
        extra["headers"]["X-New"] = json!(MARKER);
        let e = restore_markers("upstream", &mut extra, Some(&current)).unwrap_err();
        assert_eq!(e.field, "headers.X-New");
        // Nothing to restore: nothing checked.
        let mut plain = json!({"url": "https://new.example/"});
        restore_markers("upstream", &mut plain, None).unwrap();
        assert!(has_marker("upstream", &shown));
        assert!(!has_marker("upstream", &current));
        assert!(has_credential("upstream", &current));
        assert!(!has_credential(
            "upstream",
            &json!({"url": "tls://9.9.9.9"})
        ));
    }

    /// REQ: API-014 — a password in any URL field of the configuration is redacted (a list's
    /// URL through the entries too), and a relay sent back with the marker but a new host needs
    /// the credential again.
    #[test]
    fn api_014_url_passwords_in_every_url_field() {
        let mut v = json!({
            "list": [{"name": "ads", "url": "https://l:l1stpw@lists.example/ads.txt"}],
            "router": [{"name": "r", "url": "https://r:r0uterpw@10.0.0.1/"}],
            "cluster": {"git": {"repo": "https://g:g1tpw@git.example/r.git"}, "join_url": "https://j:j01npw@p:8443"},
            "telemetry": {"otlp": {"endpoint": "http://o:0tlpendpw@otel:4318"},
                          "ship": {"to": "https://s:sh1ppw@ship.example/"},
                          "sink": [{"name": "k", "url": "https://k:s1nkpw@sink.example/"}]},
            "updates": {"index_url": "https://i:1ndexpw@updates.example/"},
            "auth": {"oidc": {"public_url": "https://a:publ1cpw@dns.example/",
                              "provider": [{"id": "kc", "issuer": "https://b:1ssuerpw@kc.example/"}]}}
        });
        let paths = redact_json(&mut v);
        assert_eq!(paths.len(), 10, "{paths:?}");
        let text = v.to_string();
        assert!(!text.contains("pw@"), "{text}");
        assert!(
            text.contains("https://l:<redacted>@lists.example/ads.txt"),
            "{text}"
        );
        let mut list = json!({"name": "ads", "url": "https://l:l1stpw@lists.example/ads.txt"});
        assert_eq!(redact_entry("list", &mut list), ["url"]);
        // A relay isn't a destination field, but its URL is held to its own host.
        let current =
            json!({"url": "odoh://doh.example/q", "relay": "https://u:r3lay@relay.example/"});
        let mut moved =
            json!({"url": "odoh://doh.example/q", "relay": "https://u:<redacted>@evil.example/"});
        let e = restore_markers("upstream", &mut moved, Some(&current)).unwrap_err();
        assert_eq!(e.field, "relay", "{e:?}");
        let mut same =
            json!({"url": "odoh://doh.example/q", "relay": "https://u:<redacted>@relay.example/"});
        restore_markers("upstream", &mut same, Some(&current)).unwrap();
        assert_eq!(same, current);
    }

    /// REQ: API-014 — a body whose credentials are all `<redacted>` holds no value (so it needs
    /// no node key to be kept keyed).
    #[test]
    fn api_014_markers_are_not_credentials() {
        let mut shown = upstream();
        redact_entry("upstream", &mut shown);
        assert!(!has_credential("upstream", &shown));
        shown["headers"]["X-New"] = json!("typed");
        assert!(has_credential("upstream", &shown));
    }

    /// REQ: API-014, CLU-013 — a credential that changed reads the same on both sides once
    /// redacted; `hidden_changes` finds it by its pointer.
    #[test]
    fn api_014_hidden_changes_found_by_pointer() {
        let a = json!({"upstream": [upstream()]});
        let mut b = a.clone();
        b["upstream"][0]["headers"]["Authorization"] = json!("Bearer other");
        b["upstream"][0]["url"] = json!("https://me:other@doh.example/dns-query");
        b["upstream"][0]["tls_server_name"] = json!("x.example");
        let mut got = hidden_changes(&a, &b);
        got.sort();
        assert_eq!(
            got,
            ["/upstream/0/headers/Authorization", "/upstream/0/url"]
        );
        assert_eq!(hidden_changes(&a, &a), Vec::<String>::new());
    }

    /// REQ: API-014 — `config check --print` (typed) and the API (JSON) redact the same fields.
    #[test]
    fn api_014_typed_and_json_redaction_agree() {
        let toml = r#"
[[upstream]]
name = "nextdns"
url = "https://me:hunter2@doh.example/dns-query"
headers = { Authorization = "Bearer s3cret" }
proxy = "socks5://p:pw0@10.0.0.1:1080"
[[upstream]]
name = "plug"
url = "exec:///usr/local/bin/plugin"
args = ["--token", "4rg"]
[[upstream_group]]
name = "default"
members = ["nextdns", "plug"]
[[alerts.destination]]
name = "hook"
type = "webhook"
url = "https://u:p4ss@hook.example/"
[[list]]
name = "ads"
url = "https://l:l1stpw@lists.example/ads.txt"
[telemetry.otlp]
endpoint = "http://o:0tlpendpw@otel:4318"
headers = { api-key = "0tlp" }
[updates]
index_url = "https://i:1ndexpw@updates.example/index.json"
[auth.oidc]
public_url = "https://dns.example.com"
[[auth.oidc.provider]]
id = "kc"
issuer = "https://b:1ssuerpw@kc.example/realms/home"
client_id = "wrendns"
client_secret = "cl13nt"
"#;
        let mut cfg = crate::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .map_err(|e| format!("{e:?}"))
            .unwrap()
            .config;
        let mut by_json = serde_json::to_value(&cfg).unwrap();
        redact_json(&mut by_json);
        redact_config(&mut cfg);
        let typed = serde_json::to_value(&cfg).unwrap();
        assert_eq!(typed, by_json);
        let text = toml::to_string(&cfg).unwrap();
        for planted in [
            "hunter2", "s3cret", "pw0", "4rg", "p4ss", "0tlp", "cl13nt", "l1stpw", "1ndexpw",
            "1ssuerpw",
        ] {
            assert!(!text.contains(planted), "{planted}: {text}");
        }
    }

    /// REQ: API-014 (T23.2) — what makes a change admin-only: who holds a credential, where it
    /// goes, which file or secret it comes from, and which program an upstream runs.
    #[test]
    fn api_014_credential_rule_helpers() {
        // Holding a credential: a value, a marker, a credential file, or a reference.
        assert!(holds_credential("upstream", &upstream()));
        assert!(holds_credential(
            "upstream",
            &json!({"url": "https://d.example/", "headers": {"A": MARKER}})
        ));
        assert!(holds_credential(
            "upstream",
            &json!({"url": "tls://9.9.9.9", "tls_client_key": "/run/secrets/k.pem"})
        ));
        assert!(holds_credential(
            "alert_destination",
            &json!({"type": "ntfy", "url": "https://ntfy.sh/t", "token_file": "/run/secrets/t"})
        ));
        assert!(holds_credential(
            "alert_destination",
            &json!({"type": "ntfy", "url": "https://ntfy.sh/t", "token_ref": "ntfy"})
        ));
        // REQ: OBS-010 (T24.43) - a pushover destination's user key is a credential too.
        assert!(holds_credential(
            "alert_destination",
            &json!({"type": "pushover", "url": "", "user_key_ref": "po-user"})
        ));
        assert!(holds_credential(
            "alert_destination",
            &json!({"type": "pushover", "user_key_file": "/run/secrets/u"})
        ));
        assert!(!holds_credential(
            "upstream",
            &json!({"url": "tls://9.9.9.9", "tls_ca": "/etc/ca.pem", "headers": {}})
        ));
        assert!(!holds_credential(
            "list",
            &json!({"url": "https://l.example/a.txt"})
        ));
        // Where it goes: a new host or scheme, not a new password.
        let a = json!({"url": "https://me:pw@doh.example/q", "tls_server_name": "doh.example"});
        let pw = json!({"url": "https://me:other@doh.example/q", "tls_server_name": "doh.example"});
        let host = json!({"url": "https://me:pw@evil.example/q", "tls_server_name": "doh.example"});
        let scheme = json!({"url": "h3://me:pw@doh.example/q", "tls_server_name": "doh.example"});
        assert_eq!(destination_change(&a, &pw), None);
        assert_eq!(destination_change(&a, &host), Some("url"));
        assert_eq!(destination_change(&a, &scheme), Some("url"));
        assert_eq!(
            destination_change(&a, &json!({"url": "https://me:pw@doh.example/q"})),
            Some("tls_server_name")
        );
        // Turning verification off, or changing the pins, is a destination change; absent and
        // `false` are the same.
        let mut skip = a.clone();
        skip["tls_insecure_skip_verify"] = json!(true);
        assert_eq!(
            destination_change(&a, &skip),
            Some("tls_insecure_skip_verify")
        );
        skip["tls_insecure_skip_verify"] = json!(false);
        assert_eq!(destination_change(&a, &skip), None);
        let mut pins = a.clone();
        pins["spki_pins"] = json!(["sha256/abc"]);
        assert_eq!(destination_change(&a, &pins), Some("spki_pins"));
        let mail = json!({"type": "email", "url": "smtp://mail.example"});
        let hook = json!({"type": "webhook", "url": "smtp://mail.example"});
        assert_eq!(destination_change(&mail, &hook), Some("type"));
        // Which file or secret: absent and empty are the same.
        let d = json!({"type": "ntfy", "url": "https://ntfy.sh/t", "token_file": "/run/secrets/t"});
        assert_eq!(
            reference_changes("alert_destination", Some(&d), &d),
            Vec::<String>::new()
        );
        let mut moved = d.clone();
        moved["token_file"] = json!("/run/secrets/other");
        assert_eq!(
            reference_changes("alert_destination", Some(&d), &moved),
            ["token_file"]
        );
        assert_eq!(
            reference_changes("alert_destination", None, &json!({"password_file": ""})),
            Vec::<String>::new()
        );
        assert_eq!(
            reference_changes(
                "upstream",
                None,
                &json!({"url": "x", "tls_client_key": "/k"})
            ),
            ["tls_client_key"]
        );
        assert_eq!(
            reference_changes("alert_destination", Some(&d), &json!({"token_ref": "n"})),
            ["token_file", "token_ref"]
        );
        // Which program.
        let plug = json!({"url": "exec:///usr/local/bin/p", "args": ["--x"]});
        assert!(program_change(None, &plug));
        assert!(!program_change(Some(&plug), &plug));
        let mut weight = plug.clone();
        weight["weight"] = json!(5);
        assert!(!program_change(Some(&plug), &weight));
        let mut args = plug.clone();
        args["args"] = json!(["--y"]);
        assert!(program_change(Some(&plug), &args));
        assert!(program_change(
            Some(&json!({"url": "tls://9.9.9.9"})),
            &json!({"url": "UNIX:///run/p.sock"})
        ));
        assert!(!program_change(None, &json!({"url": "tls://9.9.9.9"})));
    }
}

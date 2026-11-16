//! REQ: API-014, OPS-011, AGT-010 (ADR-167 §4) — the credential fields of the configuration, and
//! the one redaction every read surface applies before a body leaves the node: the API's entry
//! listings and write responses, the audit log, the stored idempotency responses, the TOML to keep
//! a change in Git, forward logging, `telltale config check --print`, the pin and version diffs,
//! and so every MCP read tool and resource, which read those routes.
//!
//! A credential comes back as [`MARKER`]; a URL keeps its user and host, with only the password
//! replaced (`https://me:<redacted>@doh.example/dns-query`). A write that sends the marker back
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
        "auth.oidc.provider[].client_id",
        "an OAuth client's public identifier (it travels in every browser redirect)",
    ),
];

/// Fields that say where an entry's credential goes (ADR-167 §4). The scheme is part of `url`.
pub const DESTINATION_FIELDS: &[&str] = &[
    "url",
    "proxy",
    "host",
    "tls_server_name",
    "tls_ca",
    "bootstrap",
];

/// The configuration path of an API entry kind's array (`upstream` → `upstream[]`).
#[must_use]
pub fn entry_prefix(kind: &str) -> Option<&'static str> {
    match kind {
        "upstream" => Some("upstream[]"),
        "alert_destination" => Some("alerts.destination[]"),
        "list" => Some("list[]"),
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

/// REQ: API-014 — `url` with the password of its user information replaced by [`MARKER`]; `None`
/// when it has no password.
#[must_use]
pub fn redact_url(url: &str) -> Option<String> {
    let (from, to) = password_span(url)?;
    Some(format!("{}{MARKER}{}", &url[..from], &url[to..]))
}

/// `url` with any password replaced by [`MARKER`] (unchanged when it has none).
#[must_use]
pub fn url_shown(url: &str) -> String {
    redact_url(url).unwrap_or_else(|| url.to_owned())
}

fn url_has_marker(url: &str) -> bool {
    password_span(url).is_some_and(|(a, b)| &url[a..b] == MARKER)
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

/// REQ: API-014 — the same redaction on a typed configuration (`telltale config check --print`
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
        Part::UrlPassword => password_span(s).is_some() && !url_has_marker(s),
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

/// REQ: API-014 — whether an entry body sends [`MARKER`] back anywhere (checks refuse it: they
/// never resolve markers).
#[must_use]
pub fn has_marker(kind: &str, body: &Value) -> bool {
    let mut probe = body.clone();
    !markers(kind, &mut probe).is_empty()
}

/// A destination field as compared: absent, null, empty, and `[]` are the same; a URL without its
/// password.
fn destination(v: Option<&Value>) -> Value {
    match v {
        None | Some(Value::Null) => Value::Null,
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

/// REQ: API-014 (ADR-167 §4, the marker rule) — a write that sends [`MARKER`] back keeps the
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
        assert_eq!(redact_url("https://me@doh.example/q"), None, "no password");
        assert_eq!(redact_url("https://me:@doh.example/q"), None, "empty");
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
client_id = "telltale"
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
}

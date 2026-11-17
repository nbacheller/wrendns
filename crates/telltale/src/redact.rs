//! REQ: API-014, AGT-010 (ADR-903 §4) — the credential table (`telltale_config::credentials`)
//! applied wherever this node copies a configuration body: the entry listings (again on a
//! replica, after decoding the primary's), write responses and both audit records, the stored
//! idempotency response, the TOML to keep a change in Git, and forward logging. The MCP read
//! tools and resources read the same routes, so they get the same.

use telltale_api::ManagedKind;
use telltale_api::model::{ConfigChange, ConfigEntry, ListInfo};
use telltale_config::credentials;

/// The API's name for an entry kind (as `GET /config/entries` and the audit log name it).
pub(crate) const fn api_kind(kind: ManagedKind) -> &'static str {
    match kind {
        ManagedKind::Record => "record",
        ManagedKind::Forward => "forward",
        ManagedKind::Rule => "rule",
        ManagedKind::Upstream => "upstream",
        ManagedKind::UpstreamGroup => "upstream_group",
        ManagedKind::List => "list",
        ManagedKind::Group => "group",
        ManagedKind::AlertDestination => "alert_destination",
        ManagedKind::AlertRule => "alert_rule",
        ManagedKind::Schedule => "schedule",
        ManagedKind::AnomalyMute => "anomaly_mute",
        ManagedKind::RateLimit => "ratelimit",
        ManagedKind::Exclusions => "exclusions",
        ManagedKind::Simulate => "simulate",
        ManagedKind::Rollout => "rollout_settings",
        ManagedKind::KubernetesMap => "kubernetes_map",
    }
}

/// A write's body as it may be shown (logged, kept in Git's TOML).
pub(crate) fn body(
    kind: ManagedKind,
    body: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    body.map(|b| {
        let mut b = b.clone();
        credentials::redact_entry(api_kind(kind), &mut b);
        b
    })
}

/// REQ: API-014 — the entries of `GET /config/entries`, each definition redacted and its
/// `redacted` paths listed. Run again on a replica over the primary's answer (an older primary
/// sends them as they are).
pub(crate) fn entries(items: &mut [ConfigEntry]) {
    for e in items {
        if let Some(d) = &mut e.definition {
            for p in credentials::redact_entry(&e.kind, d) {
                if !e.redacted.contains(&p) {
                    e.redacted.push(p);
                }
            }
        }
    }
}

/// REQ: API-014, ADR-905 — a list as a replica shows the primary's (`Read::Lists`): its source
/// and error are redacted again, as `GET /lists` redacts them on the primary (an older primary
/// sends them as they are). An error can quote a URL, so each URL in it loses its password too.
pub(crate) fn lists(items: &mut [ListInfo]) {
    for l in items {
        l.source = credentials::url_shown(&l.source);
        if let Some(e) = &mut l.error {
            *e = e
                .split(' ')
                .map(credentials::url_shown)
                .collect::<Vec<_>>()
                .join(" ");
        }
    }
}

/// REQ: API-014 — a write's answer: the entry before and after, and the TOML to keep it in Git.
pub(crate) fn change(kind: ManagedKind, c: &mut ConfigChange) {
    for v in [&mut c.before, &mut c.after].into_iter().flatten() {
        credentials::redact_entry(api_kind(kind), v);
    }
    if let Some(t) = &mut c.keep_in_git {
        *t = toml_text(t);
    }
}

/// Explains the marker in TOML for Git.
pub(crate) const GIT_NOTE: &str = "# `<redacted>` stands for a credential that isn't shown: put the value there (or use a *_file).\n";

/// What replaces TOML that can't be read back (so can't be checked for credentials).
pub(crate) const UNREADABLE_TOML: &str = "# The primary's TOML for Git couldn't be checked for credentials, so it isn't shown: copy the entry from the files or the UI instead.\n";

/// REQ: API-014 — TOML (to keep a change in Git, from an older primary) with its credentials
/// redacted; unchanged when it has none. Text that doesn't parse can't be checked, so only
/// its leading comments and a note are kept.
pub(crate) fn toml_text(text: &str) -> String {
    let head: String = text
        .lines()
        .take_while(|l| l.starts_with('#'))
        .flat_map(|l| [l, "\n"])
        .collect();
    let parsed = toml::from_str::<toml::Table>(text)
        .ok()
        .and_then(|t| serde_json::to_value(&t).ok());
    let Some(mut v) = parsed else {
        return format!("{head}{UNREADABLE_TOML}");
    };
    let before = v.clone();
    credentials::redact_json(&mut v);
    if v == before {
        return text.to_owned();
    }
    let Some(rendered) = toml::Value::try_from(&v)
        .ok()
        .and_then(|t| toml::to_string(&t).ok())
    else {
        return format!("{head}{UNREADABLE_TOML}");
    };
    format!("{head}{GIT_NOTE}{rendered}")
}

/// What both audit records of a configuration write keep: the entry before and after (redacted:
/// the backend's answer is), and the version.
pub(crate) fn audit_detail(kind: ManagedKind, c: &serde_json::Value) -> serde_json::Value {
    let mut before = c["before"].clone();
    let mut after = c["after"].clone();
    for v in [&mut before, &mut after] {
        credentials::redact_entry(api_kind(kind), v);
    }
    serde_json::json!({ "before": before, "after": after, "configVersion": c["configVersion"] })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: API-014 — TOML from an older primary loses its credentials and keeps its comments.
    #[test]
    fn api_014_keep_in_git_text_from_an_older_primary() {
        let t = "# Add to the configuration in Git.\n[[upstream]]\nname = \"x\"\nurl = \"https://doh.example/q\"\n\n[upstream.headers]\nAuthorization = \"Bearer s3cret\"\n";
        let out = toml_text(t);
        assert!(!out.contains("s3cret"), "{out}");
        assert!(
            out.starts_with("# Add to the configuration in Git.\n"),
            "{out}"
        );
        assert!(out.contains(GIT_NOTE), "{out}");
        let plain = "# Remove the [[list]] `ads` from the configuration in Git.\n";
        assert_eq!(toml_text(plain), plain);
        // Unreadable: the comments and a note, never the text.
        let bad = "# Add to the configuration in Git.\n[[upstream]\nheaders = { Authorization = \"Bearer s3cret\" }\n";
        let out = toml_text(bad);
        assert!(!out.contains("s3cret"), "{out}");
        assert_eq!(
            out,
            format!("# Add to the configuration in Git.\n{UNREADABLE_TOML}")
        );
    }
}

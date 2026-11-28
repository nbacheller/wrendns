//! REQ: OPS-014 (ADR-903 §1–2) — references to stored secrets. A credential that can come from a
//! file can also name a secret entered in the UI: each such field has a sibling `<field>_ref`
//! holding the secret's name (`api_key_ref = "unifi"`), and at most one of the inline value, the
//! `_file` and the `_ref` is set. The values live in the node's encrypted store, never here.

use serde_json::Value;

use crate::Config;

/// The longest secret name.
pub const NAME_MAX: usize = 63;

/// REQ: OPS-014 (ADR-903 §2) — a stored secret's name: `^[a-z0-9][a-z0-9._-]{0,62}$`.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    let ok = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !b.is_empty()
        && b.len() <= NAME_MAX
        && b.first().is_some_and(|c| ok(*c))
        && b.iter().all(|c| ok(*c) || matches!(c, b'.' | b'_' | b'-'))
}

/// One credential field that a stored secret can fill: the entry kind (as the API and
/// `usedBy` name it), the field, and its inline, file and reference keys in the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredField {
    pub kind: &'static str,
    /// The credential's name (`api_key`, `token`).
    pub field: &'static str,
    /// The inline key, where the schema has one (`client_secret`).
    pub inline: Option<&'static str>,
    pub file: &'static str,
    pub reference: &'static str,
}

const fn f(
    kind: &'static str,
    field: &'static str,
    inline: Option<&'static str>,
    file: &'static str,
    reference: &'static str,
) -> StoredField {
    StoredField {
        kind,
        field,
        inline,
        file,
        reference,
    }
}

/// REQ: OPS-014 (ADR-903 §2) — every field a stored secret can fill (besides OTLP's
/// `header_refs`, a map). `ops_014_stored_fields_name_real_keys` holds it to the schema.
pub const STORED_FIELDS: &[StoredField] = &[
    f("router", "api_key", None, "api_key_file", "api_key_ref"),
    f(
        "router",
        "api_secret",
        None,
        "api_secret_file",
        "api_secret_ref",
    ),
    f("router", "password", None, "password_file", "password_ref"),
    f(
        "alert_destination",
        "token",
        None,
        "token_file",
        "token_ref",
    ),
    f(
        "alert_destination",
        "password",
        None,
        "password_file",
        "password_ref",
    ),
    f(
        "alert_destination",
        "user_key",
        None,
        "user_key_file",
        "user_key_ref",
    ),
    f(
        "oidc_provider",
        "client_secret",
        Some("client_secret"),
        "client_secret_file",
        "client_secret_ref",
    ),
    f("sink", "token", None, "token_file", "token_ref"),
    f(
        "git",
        "credentials",
        None,
        "credentials_file",
        "credentials_ref",
    ),
    f(
        "git",
        "webhook_secret",
        None,
        "webhook_secret_file",
        "webhook_secret_ref",
    ),
];

/// The fields of `kind` a stored secret can fill.
pub fn fields_of(kind: &str) -> impl Iterator<Item = &'static StoredField> + '_ {
    STORED_FIELDS.iter().filter(move |s| s.kind == kind)
}

/// One reference to a stored secret in a configuration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Reference {
    /// The entry kind (`router`, `alert_destination`, `oidc_provider`, `sink`, `git`, `otlp`).
    pub kind: &'static str,
    /// The entry's name (`unifi`; `default` for the Git source and OTLP).
    pub entry: String,
    /// The reference's key (`api_key_ref`, `header_refs.api-key`).
    pub field: String,
    /// The secret's name.
    pub name: String,
}

/// REQ: OPS-014 — every reference `cfg` makes to a stored secret, sorted.
#[must_use]
pub fn references(cfg: &Config) -> Vec<Reference> {
    let mut out = Vec::new();
    let mut add =
        |kind: &'static str, entry: &str, field: &str, name: Option<&crate::SafeString>| {
            if let Some(n) = name.filter(|n| !n.trim().is_empty()) {
                out.push(Reference {
                    kind,
                    entry: entry.to_owned(),
                    field: field.to_owned(),
                    name: n.trim().to_owned(),
                });
            }
        };
    for r in &cfg.router {
        add("router", &r.name, "api_key_ref", r.api_key_ref.as_ref());
        add(
            "router",
            &r.name,
            "api_secret_ref",
            r.api_secret_ref.as_ref(),
        );
        add("router", &r.name, "password_ref", r.password_ref.as_ref());
    }
    // REQ: CLD-904 (T36.10b) - a DNS provider's credential is a reference only (no inline value and
    // no file), so it has no row in `STORED_FIELDS`.
    for p in &cfg.dns_provider {
        add(
            "dns_provider",
            &p.name,
            "credential_ref",
            p.credential_ref.as_ref(),
        );
    }
    for d in &cfg.alerts.destination {
        add(
            "alert_destination",
            &d.name,
            "token_ref",
            d.token_ref.as_ref(),
        );
        add(
            "alert_destination",
            &d.name,
            "password_ref",
            d.password_ref.as_ref(),
        );
        add(
            "alert_destination",
            &d.name,
            "user_key_ref",
            d.user_key_ref.as_ref(),
        );
    }
    for p in cfg
        .auth
        .oidc
        .provider
        .iter()
        .chain(&cfg.auth.oidc.managed_provider)
    {
        add(
            "oidc_provider",
            &p.id,
            "client_secret_ref",
            p.client_secret_ref.as_ref(),
        );
    }
    for s in cfg.telemetry.all_sinks() {
        add("sink", &s.name, "token_ref", s.token_ref.as_ref());
    }
    for (h, n) in &cfg.telemetry.otlp_effective().header_refs {
        add("otlp", "default", &format!("header_refs.{h}"), Some(n));
    }
    add(
        "otlp",
        "default",
        "tls_ca_ref",
        cfg.telemetry.otlp_effective().tls_ca_ref.as_ref(),
    );
    if let Some(g) = &cfg.cluster.git {
        add(
            "git",
            "default",
            "credentials_ref",
            g.credentials_ref.as_ref(),
        );
        add(
            "git",
            "default",
            "webhook_secret_ref",
            g.webhook_secret_ref.as_ref(),
        );
    }
    out.sort();
    out
}

/// Whether a field of an entry's JSON is set (absent, `null` and `""` are not).
fn set(v: &Value, key: &str) -> bool {
    match v.get(key) {
        None | Some(Value::Null) => false,
        Some(Value::String(s)) => !s.trim().is_empty(),
        Some(_) => true,
    }
}

/// REQ: OPS-014 (ADR-903 §2, decision 4) — the credential fields of `kind` the files' entry
/// `file` sets inline or by file: they win, and the API can't set, drop or replace them.
#[must_use]
pub fn set_by_file(kind: &str, file: &Value) -> Vec<&'static StoredField> {
    fields_of(kind)
        .filter(|s| s.inline.is_some_and(|i| set(file, i)) || set(file, s.file))
        .collect()
}

/// REQ: OPS-014 (ADR-903 §2, decision 4) — an API body for an entry the files also define:
/// each credential field the files set inline or by file is carried over from them when the body
/// leaves it out (an override that changes other fields), and the first one the body sets,
/// drops or replaces otherwise is returned (409 `set_by_file`). `body` must be an object.
pub fn carry_file_credentials(
    kind: &str,
    file: &Value,
    body: &mut Value,
) -> Result<(), &'static StoredField> {
    for s in set_by_file(kind, file) {
        let keys: Vec<&str> = s.inline.into_iter().chain([s.file, s.reference]).collect();
        // An explicit `null` or `""` for a key the files set drops it: refused, not carried over
        // with a 200 that says the change applied.
        if keys
            .iter()
            .any(|k| set(file, k) && body.get(*k).is_some() && !set(body, k))
        {
            return Err(s);
        }
        let sent: Vec<&str> = keys.iter().copied().filter(|k| set(body, k)).collect();
        if sent.is_empty() {
            if let Some(m) = body.as_object_mut() {
                for k in &keys {
                    match file.get(*k) {
                        Some(v) if set(file, k) => {
                            m.insert((*k).to_owned(), v.clone());
                        }
                        _ => {
                            m.remove(*k);
                        }
                    }
                }
            }
            continue;
        }
        let same = keys.iter().all(|k| {
            let (a, b) = (set(file, k), set(body, k));
            a == b && (!a || file.get(*k) == body.get(*k))
        });
        if !same {
            return Err(s);
        }
    }
    Ok(())
}

/// REQ: OPS-014 (ADR-903 §2, decision 4) — the same on a typed entry the API overrides: each
/// credential the files' entry sets inline or by file replaces whatever the override has for it
/// (an override stored before the files set it). The merged configuration then holds one source
/// per field. Returns the fields taken from the files.
pub fn prefer_file_credentials<T>(kind: &str, file: &T, over: &mut T) -> Vec<&'static str>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let (Ok(fv), Ok(mut ov)) = (serde_json::to_value(file), serde_json::to_value(&*over)) else {
        return Vec::new();
    };
    let mut taken = Vec::new();
    for s in set_by_file(kind, &fv) {
        let keys: Vec<&str> = s.inline.into_iter().chain([s.file, s.reference]).collect();
        let differs = keys.iter().any(|k| fv.get(*k) != ov.get(*k));
        if !differs {
            continue;
        }
        if let Some(m) = ov.as_object_mut() {
            for k in &keys {
                match fv.get(*k) {
                    Some(v) if set(&fv, k) => {
                        m.insert((*k).to_owned(), v.clone());
                    }
                    _ => {
                        m.remove(*k);
                    }
                }
            }
        }
        taken.push(s.field);
    }
    if !taken.is_empty()
        && let Ok(t) = serde_json::from_value(ov)
    {
        *over = t;
    }
    taken
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_014_secret_names() {
        for ok in [
            "unifi",
            "router.unifi.api_key",
            "a",
            "0-x_y.z",
            &"a".repeat(63),
        ] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            "Unifi",
            "-x",
            ".x",
            "a b",
            "a/b",
            "a\u{0}",
            &"a".repeat(64),
            "é",
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    /// Every key the table names is a field of its kind's schema.
    #[test]
    fn ops_014_stored_fields_name_real_keys() {
        let schema = serde_json::to_value(crate::json_schema()).unwrap();
        let defs = &schema["$defs"];
        let def = |k: &str| match k {
            "router" => "RouterConfig",
            "alert_destination" => "AlertDestination",
            "oidc_provider" => "OidcProvider",
            "sink" => "SinkConfig",
            _ => "GitSourceConfig",
        };
        for s in STORED_FIELDS {
            let props = &defs[def(s.kind)]["properties"];
            for k in s.inline.into_iter().chain([s.file, s.reference]) {
                assert!(props.get(k).is_some(), "{}: {k}", s.kind);
            }
        }
        assert!(
            defs["OtlpConfig"]["properties"]
                .get("header_refs")
                .is_some()
        );
    }

    /// REQ: OPS-014 (decision 4) — a body that leaves a file-set credential out gets it carried
    /// over; one that changes it, drops it for a reference, or adds a reference beside it, is
    /// refused.
    #[test]
    fn ops_014_carry_file_credentials() {
        let file = serde_json::json!({"name": "n", "type": "ntfy", "url": "https://n/t", "token_file": "/run/secrets/t"});
        let mut b = serde_json::json!({"type": "ntfy", "url": "https://n/t2"});
        carry_file_credentials("alert_destination", &file, &mut b).unwrap();
        assert_eq!(b["token_file"], "/run/secrets/t");
        let mut same = b.clone();
        carry_file_credentials("alert_destination", &file, &mut same).unwrap();
        for bad in [
            serde_json::json!({"token_ref": "t"}),
            serde_json::json!({"token_file": "/run/secrets/other"}),
            serde_json::json!({"token_file": "/run/secrets/t", "token_ref": "t"}),
            // Dropped explicitly.
            serde_json::json!({"token_file": null}),
            serde_json::json!({"token_file": ""}),
        ] {
            let mut b = bad.clone();
            let e = carry_file_credentials("alert_destination", &file, &mut b).unwrap_err();
            assert_eq!(e.field, "token", "{bad}");
        }
        // A `null` for a key the files don't set is no drop.
        let mut n = serde_json::json!({"token_ref": null, "token": ""});
        carry_file_credentials("alert_destination", &file, &mut n).unwrap();
        assert_eq!(n["token_file"], "/run/secrets/t");
        // A field the files don't set is the API's to set.
        let mut pw = serde_json::json!({"password_ref": "smtp"});
        carry_file_credentials("alert_destination", &file, &mut pw).unwrap();
        assert_eq!(pw["password_ref"], "smtp");
    }
}

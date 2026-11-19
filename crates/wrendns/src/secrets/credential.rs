//! REQ: OPS-014 (ADR-903 §2) — the one place a credential is read: inline in the files, from a
//! `*_file`, or from the store by `*_ref`. The files win (decision 4): validation allows one of
//! the three per field, and should an entry still carry more (an override stored before the
//! files set the field), the inline value, then the file, is used.
//!
//! An integration whose stored secret can't be read reports itself "not configured: secret
//! `<name>` can't be read on this node (<reason>)", logged once until the reason changes.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use wrendns_config::SafeString;
use zeroize::Zeroizing;

use super::store::SecretStore;
use super::value::SecretValue;

/// Where a credential's value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// Inline in the configuration files.
    Inline,
    /// A `*_file`, read when used.
    File,
    /// A stored secret (`*_ref`).
    Stored,
    /// Not set.
    None,
}

impl Source {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::File => "file",
            Self::Stored => "stored",
            Self::None => "none",
        }
    }
}

/// A credential's value and where it came from.
#[derive(Debug)]
pub(crate) struct Resolved {
    pub(crate) value: SecretValue,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the integrations' status reads report it (T23.7, T23.10, T23.11)"
        )
    )]
    pub(crate) source: Source,
}

/// One credential field as the configuration gives it.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Credential<'a> {
    pub(crate) inline: Option<&'a str>,
    pub(crate) file: Option<&'a str>,
    pub(crate) reference: Option<&'a str>,
}

fn some(s: Option<&SafeString>) -> Option<&str> {
    s.map(SafeString::as_str).filter(|s| !s.trim().is_empty())
}

impl<'a> Credential<'a> {
    /// A field with a file and a reference (no inline value).
    pub(crate) fn of(file: Option<&'a SafeString>, reference: Option<&'a SafeString>) -> Self {
        Self {
            inline: None,
            file: some(file),
            reference: some(reference),
        }
    }

    /// A field with an inline value too (`client_secret`).
    pub(crate) fn with_inline(mut self, inline: Option<&'a SafeString>) -> Self {
        self.inline = some(inline);
        self
    }

    /// Where the value would come from, without reading it.
    pub(crate) fn source(&self) -> Source {
        if self.inline.is_some() {
            Source::Inline
        } else if self.file.is_some() {
            Source::File
        } else if self.reference.is_some() {
            Source::Stored
        } else {
            Source::None
        }
    }

    /// REQ: OPS-014 (ADR-903 §2) — the value: `Ok(None)` when the field isn't set, `Err` with
    /// why it can't be read (a file's error, or "not configured: secret ... can't be read").
    pub(crate) fn resolve(&self, store: Option<&SecretStore>) -> Result<Option<Resolved>, String> {
        match self.source() {
            Source::None => Ok(None),
            Source::Inline => Ok(self.inline.map(|v| Resolved {
                value: SecretValue::from_text(Zeroizing::new(v.to_owned())),
                source: Source::Inline,
            })),
            Source::File => {
                let path = self.file.unwrap_or_default();
                let text = std::fs::read_to_string(path)
                    .map(Zeroizing::new)
                    .map_err(|e| format!("{path}: {e}"))?;
                Ok(Some(Resolved {
                    value: SecretValue::from_text(text),
                    source: Source::File,
                }))
            }
            Source::Stored => {
                let name = self.reference.unwrap_or_default();
                let got = match store {
                    Some(s) => s.get(name).map_err(|e| e.to_string()),
                    None => Err("this process has no secrets store".to_owned()),
                };
                match got {
                    Ok(value) => {
                        forget(name);
                        Ok(Some(Resolved {
                            value,
                            source: Source::Stored,
                        }))
                    }
                    Err(why) => {
                        let text = not_configured(name, &why);
                        log_once(name, &text);
                        Err(text)
                    }
                }
            }
        }
    }
}

/// REQ: OPS-014 (ADR-903 §3) — the words an integration reports when its stored secret can't
/// be read.
pub(crate) fn not_configured(name: &str, why: &str) -> String {
    format!("not configured: secret `{name}` can't be read on this node ({why})")
}

fn logged() -> &'static Mutex<HashMap<String, String>> {
    static L: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    L.get_or_init(Mutex::default)
}

/// Logs `text` for the secret `name` once, until it changes (or the secret is read again).
fn log_once(name: &str, text: &str) {
    let mut m = logged().lock().unwrap_or_else(PoisonError::into_inner);
    if m.get(name).map(String::as_str) != Some(text) {
        tracing::warn!("{text}");
        m.insert(name.to_owned(), text.to_owned());
    }
}

fn forget(name: &str) {
    let mut m = logged().lock().unwrap_or_else(PoisonError::into_inner);
    if m.remove(name).is_some() {
        tracing::info!("secret `{name}` can be read again");
    }
}

/// Linux's `O_NONBLOCK` (the same on x86-64, ARM and AArch64): opening a FIFO doesn't wait for a
/// writer.
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0o4000;

/// REQ: OPS-014 (ADR-903 §2) — whether this node can read the file at `path`, without reading
/// it: opened read-only (non-blocking) and closed. A path that isn't a regular file is "not
/// usable"; `stat` alone can't tell readability.
pub(crate) fn readable(path: &str) -> Result<(), String> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.custom_flags(O_NONBLOCK);
    }
    let f = o.open(path).map_err(|e| format!("{path}: {e}"))?;
    let meta = f.metadata().map_err(|e| format!("{path}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{path}: not usable (not a regular file)"));
    }
    Ok(())
}

/// One credential field of this node's configuration, as status reads show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldStatus {
    /// The entry kind (`router`, `alert_destination`, ...).
    pub(crate) kind: &'static str,
    pub(crate) entry: String,
    /// The credential (`api_key`, `token`, `header:api-key`).
    pub(crate) field: String,
    pub(crate) source: Source,
    /// The file, or the stored secret's name.
    pub(crate) at: Option<String>,
    /// `Ok`, or why it can't be read on this node.
    pub(crate) readable: Result<(), String>,
}

/// REQ: OPS-014 (ADR-903 §4 `credentials`) — every credential field `cfg` sets that a stored
/// secret could fill, with its source and whether this node can read it (files opened without
/// reading; stored secrets judged by their row, not decrypted).
#[allow(clippy::too_many_lines)] // one block per kind of entry
pub(crate) fn fields(
    cfg: &wrendns_config::Config,
    store: Option<&SecretStore>,
) -> Vec<FieldStatus> {
    let mut out = Vec::new();
    let mut add = |kind: &'static str, entry: &str, field: &str, c: Credential<'_>| {
        let source = c.source();
        let (at, readable) = match source {
            Source::None => return,
            Source::Inline => (None, Ok(())),
            Source::File => {
                let p = c.file.unwrap_or_default();
                (Some(p.to_owned()), readable(p))
            }
            Source::Stored => {
                let n = c.reference.unwrap_or_default();
                let r = match store {
                    Some(s) => s.readable(n).map_err(|e| e.to_string()),
                    None => Err("no secrets store".to_owned()),
                };
                (Some(n.to_owned()), r)
            }
        };
        out.push(FieldStatus {
            kind,
            entry: entry.to_owned(),
            field: field.to_owned(),
            source,
            at,
            readable,
        });
    };
    for r in &cfg.router {
        add(
            "router",
            &r.name,
            "api_key",
            Credential::of(r.api_key_file.as_ref(), r.api_key_ref.as_ref()),
        );
        add(
            "router",
            &r.name,
            "api_secret",
            Credential::of(r.api_secret_file.as_ref(), r.api_secret_ref.as_ref()),
        );
        add(
            "router",
            &r.name,
            "password",
            Credential::of(r.password_file.as_ref(), r.password_ref.as_ref()),
        );
    }
    for d in &cfg.alerts.destination {
        add(
            "alert_destination",
            &d.name,
            "token",
            Credential::of(d.token_file.as_ref(), d.token_ref.as_ref()),
        );
        add(
            "alert_destination",
            &d.name,
            "password",
            Credential::of(d.password_file.as_ref(), d.password_ref.as_ref()),
        );
        add(
            "alert_destination",
            &d.name,
            "user_key",
            Credential::of(d.user_key_file.as_ref(), d.user_key_ref.as_ref()),
        );
    }
    for p in &cfg.auth.oidc.provider {
        add(
            "oidc_provider",
            &p.id,
            "client_secret",
            Credential::of(p.client_secret_file.as_ref(), p.client_secret_ref.as_ref())
                .with_inline(p.client_secret.as_ref()),
        );
    }
    for s in cfg.telemetry.all_sinks() {
        add(
            "sink",
            &s.name,
            "token",
            Credential::of(s.token_file.as_ref(), s.token_ref.as_ref()),
        );
    }
    let o = cfg.telemetry.otlp_effective();
    for h in o.headers.keys() {
        add(
            "otlp",
            "default",
            &format!("header:{h}"),
            Credential::default().with_inline(o.headers.get(h)),
        );
    }
    for (h, n) in &o.header_refs {
        add(
            "otlp",
            "default",
            &format!("header:{h}"),
            Credential::of(None, Some(n)),
        );
    }
    if let Some(g) = &cfg.cluster.git {
        add(
            "git",
            "default",
            "credentials",
            Credential::of(g.credentials_file.as_ref(), g.credentials_ref.as_ref()),
        );
        add(
            "git",
            "default",
            "webhook_secret",
            Credential::of(
                g.webhook_secret_file.as_ref(),
                g.webhook_secret_ref.as_ref(),
            ),
        );
    }
    out
}

/// REQ: OPS-014 (ADR-903 §2) — the load warnings for references to secrets this node doesn't
/// store: DNS never depends on the store, so a missing one is a warning, not an error.
pub(crate) fn missing_references(cfg: &wrendns_config::Config, store: &SecretStore) -> Vec<String> {
    if cfg.cluster.ephemeral {
        return Vec::new();
    }
    wrendns_config::secret_refs::references(cfg)
        .into_iter()
        .filter(|r| !store.exists(&r.name))
        .map(|r| {
            format!(
                "{} `{}`: {} names the stored secret `{}`, which isn't set on this node",
                r.kind, r.entry, r.field, r.name
            )
        })
        .collect()
}

/// Logs [`missing_references`] that weren't logged at the last start or reload.
pub(crate) fn warn_missing(cfg: &wrendns_config::Config, store: &SecretStore) {
    static LAST: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    let now = missing_references(cfg, store);
    let mut last = LAST
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    for w in now.iter().filter(|w| !last.contains(w)) {
        tracing::warn!("config: {w}");
    }
    *last = now;
}

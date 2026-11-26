//! REQ: OPS-014, NFR-005 (ADR-903 §2) — a secret's value in memory: printed as `<redacted>`
//! everywhere (`Debug`, `Display`), never serialized, and wiped when dropped. The claim covers our
//! own buffers only: what the HTTP, TLS and protobuf layers copy isn't wiped (`docs/secrets.md`).

use std::fmt;

use wrendns_config::credentials::MARKER;
use zeroize::Zeroizing;

/// The largest value stored (UTF-8 bytes, after trimming).
pub(crate) const MAX_VALUE: usize = 8 * 1024;

/// A secret's value.
pub(crate) struct SecretValue(Zeroizing<String>);

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(MARKER)
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(MARKER)
    }
}

impl SecretValue {
    /// The value, for the one place that sends it.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    /// A value read from a file (or an inline one from the files), surrounding space trimmed.
    /// The rules for stored values don't apply: the files keep working as they did.
    pub(crate) fn from_text(text: Zeroizing<String>) -> Self {
        let t = text.trim();
        if t.len() == text.len() {
            return Self(text);
        }
        Self(Zeroizing::new(t.to_owned()))
    }

    /// REQ: OPS-014 (ADR-903 §2) — a value to store, of kind `kind`: UTF-8, trimmed, not empty, at
    /// most [`MAX_VALUE`] bytes, no control characters (`text`), and not the redaction marker.
    pub(crate) fn new(kind: Kind, raw: Zeroizing<String>) -> Result<Self, ValueError> {
        let v = Self::from_text(raw);
        if v.0.is_empty() {
            return Err(ValueError::Empty);
        }
        if v.0.len() > MAX_VALUE {
            return Err(ValueError::TooLong);
        }
        match kind {
            Kind::Text if v.0.chars().any(char::is_control) => return Err(ValueError::Control),
            // REQ: CLD-920 (ADR-1097 point 1) — PEM blocks only; the line breaks are kept.
            Kind::Pem if !is_pem(&v.0) => return Err(ValueError::NotPem),
            _ => {}
        }
        if v.0.as_str() == MARKER {
            return Err(ValueError::Marker);
        }
        Ok(v)
    }

    /// A value decrypted into `buf` (the caller wipes `buf`).
    pub(crate) fn from_bytes(buf: &[u8]) -> Option<Self> {
        let s = std::str::from_utf8(buf).ok()?;
        Some(Self(Zeroizing::new(s.to_owned())))
    }
}

/// What a stored secret holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// One line of text: a token, a password, an API key.
    Text,
    /// REQ: CLD-920 — one or more PEM blocks, with their line breaks: a certificate chain, a key.
    /// Never returned by any API, MCP or `ctl` path.
    Pem,
}

impl Kind {
    /// `text` or `pem` (PEM blocks, with their line breaks).
    pub(crate) fn parse(s: &str) -> Result<Self, ValueError> {
        match s {
            "text" => Ok(Self::Text),
            "pem" => Ok(Self::Pem),
            _ => Err(ValueError::Kind),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Pem => "pem",
        }
    }
}

/// REQ: CLD-920 — whether `text` is one or more well-formed PEM blocks and nothing else: each
/// `-----BEGIN <label>-----`, base64 lines, `-----END <label>-----`, with blank lines between.
/// Line breaks (`\n` or `\r\n`) are the only control characters allowed.
fn is_pem(text: &str) -> bool {
    let mut open: Option<&str> = None;
    let mut blocks = 0usize;
    let mut body = false;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.chars().any(char::is_control) {
            return false;
        }
        let line = line.trim_end();
        if let Some(label) = open {
            if let Some(end) = line
                .strip_prefix("-----END ")
                .and_then(|l| l.strip_suffix("-----"))
            {
                if end != label || !body {
                    return false;
                }
                open = None;
                blocks += 1;
            } else if line.is_empty()
                || !line
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            {
                return false;
            } else {
                body = true;
            }
        } else if line.is_empty() {
            // Blank lines between blocks.
        } else if let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        {
            if label.is_empty() || !label.bytes().all(|b| b.is_ascii_uppercase() || b == b' ') {
                return false;
            }
            open = Some(label);
            body = false;
        } else {
            return false;
        }
    }
    open.is_none() && blocks > 0
}

/// Why a value can't be stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueError {
    Empty,
    TooLong,
    Control,
    Marker,
    Kind,
    NotPem,
    Name,
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "the value is empty",
            Self::TooLong => "the value is longer than 8 KiB",
            Self::Control => {
                "the value holds a control character (a line break, a tab): a text secret is one line"
            }
            Self::Marker => "`<redacted>` is what a hidden value reads as, not a value",
            Self::Kind => "the kind must be `text` or `pem`",
            Self::NotPem => {
                "a `pem` secret holds PEM blocks only (-----BEGIN ...----- to -----END ...-----), and nothing else"
            }
            Self::Name => {
                "a secret's name is lowercase letters, digits, `.`, `_` or `-`, starting with a letter or digit, at most 63"
            }
        })
    }
}

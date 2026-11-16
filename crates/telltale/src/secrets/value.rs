//! REQ: OPS-014, NFR-005 (ADR-167 §2) — a secret's value in memory: printed as `<redacted>`
//! everywhere (`Debug`, `Display`), never serialized, and wiped when dropped. The claim covers our
//! own buffers only: what the HTTP, TLS and protobuf layers copy isn't wiped (`docs/secrets.md`).

use std::fmt;

use telltale_config::credentials::MARKER;
use zeroize::Zeroizing;

/// The largest value stored (UTF-8 bytes, after trimming).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the write API (`PUT`/`DELETE /api/v1/secrets`, T23.4) and replication (T23.5) use it"
    )
)]
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

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the write API (`PUT`/`DELETE /api/v1/secrets`, T23.4) and replication (T23.5) use it"
        )
    )]
    /// REQ: OPS-014 (ADR-167 §2) — a value to store, of kind `kind`: UTF-8, trimmed, not empty, at
    /// most [`MAX_VALUE`] bytes, no control characters (`text`), and not the redaction marker.
    pub(crate) fn new(kind: Kind, raw: Zeroizing<String>) -> Result<Self, ValueError> {
        let v = Self::from_text(raw);
        if v.0.is_empty() {
            return Err(ValueError::Empty);
        }
        if v.0.len() > MAX_VALUE {
            return Err(ValueError::TooLong);
        }
        if kind == Kind::Text && v.0.chars().any(char::is_control) {
            return Err(ValueError::Control);
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
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the write API (`PUT`/`DELETE /api/v1/secrets`, T23.4) and replication (T23.5) use it"
    )
)]
pub(crate) enum Kind {
    /// One line of text: a token, a password, an API key.
    Text,
}

impl Kind {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the write API (`PUT`/`DELETE /api/v1/secrets`, T23.4) and replication (T23.5) use it"
        )
    )]
    /// `text`; `pem` is reserved (PEM blocks, with their line breaks) and not taken yet.
    pub(crate) fn parse(s: &str) -> Result<Self, ValueError> {
        match s {
            "text" => Ok(Self::Text),
            "pem" => Err(ValueError::KindReserved),
            _ => Err(ValueError::Kind),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
        }
    }
}

/// Why a value can't be stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the write API (`PUT`/`DELETE /api/v1/secrets`, T23.4) and replication (T23.5) use it"
    )
)]
pub(crate) enum ValueError {
    Empty,
    TooLong,
    Control,
    Marker,
    Kind,
    KindReserved,
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
            Self::Kind => "the kind must be `text`",
            Self::KindReserved => "the kind `pem` isn't available yet: use `text`",
            Self::Name => {
                "a secret's name is lowercase letters, digits, `.`, `_` or `-`, starting with a letter or digit, at most 63"
            }
        })
    }
}

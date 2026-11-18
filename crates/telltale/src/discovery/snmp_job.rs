//! REQ: DSC-004, DSC-007 (T25.6, ADR-908, ADR-1001) — the SNMP jobs on the worker channel: what the
//! main process asks (`snmp_probe`, `snmp_poll`: an agent's address, its credential, the tables) and
//! what the worker answers (the capability record, one statistic per walk, and rows in batches).
//!
//! A credential travels in the job, over the worker's stdin pipe and nowhere else (ADR-908
//! "Credentials"): it is a [`Secret`] that redacts its `Debug`, is zeroized when dropped, and is
//! written as hex so that any bytes survive. The import worker never gets one (it takes no SNMP job).

use std::net::Ipv4Addr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use telltale_config::SnmpTable;
use zeroize::Zeroizing;

/// The job op that reads an agent's capabilities (the Test button, and a first poll).
pub(crate) const OP_PROBE: &str = "snmp_probe";
/// The job op that polls an agent's tables.
pub(crate) const OP_POLL: &str = "snmp_poll";

/// Rows the worker sends per frame: well inside the 1 MiB JSON frame cap.
pub(crate) const ROWS_PER_FRAME: usize = 400;
/// The most rows the main process takes from one job (a table is capped at 5,000 rows, ADR-908).
pub(crate) const MAX_ROWS_PER_JOB: usize = 60_000;
/// The longest a poll runs inside the worker, in seconds (the supervisor's limit is above it).
pub(crate) const POLL_TIME_CAP_SECS: u64 = 100;

/// A secret in a job: zeroized on drop, redacted in `Debug`, hex on the wire.
#[derive(Clone, Default)]
pub(crate) struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        // Not constant time: only tests compare secrets; no reply is ever checked with this.
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for Secret {}

fn to_hex(bytes: &[u8]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(bytes.len().saturating_mul(2)));
    for b in bytes {
        s.push(char::from(
            b"0123456789abcdef"
                .get(usize::from(b >> 4))
                .copied()
                .unwrap_or(b'0'),
        ));
        s.push(char::from(
            b"0123456789abcdef"
                .get(usize::from(b & 0x0f))
                .copied()
                .unwrap_or(b'0'),
        ));
    }
    s
}

fn from_hex(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() / 2));
    for pair in text.as_bytes().chunks(2) {
        let hi = char::from(*pair.first()?).to_digit(16)?;
        let lo = char::from(*pair.get(1)?).to_digit(16)?;
        out.push(u8::try_from(hi.checked_mul(16)?.checked_add(lo)?).ok()?);
    }
    Some(out)
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&to_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(d)?);
        let bytes = from_hex(&text).ok_or_else(|| serde::de::Error::custom("not hex"))?;
        Ok(Self(bytes))
    }
}

/// How the worker signs in to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "version", rename_all = "lowercase")]
pub(crate) enum AuthSpec {
    V2c {
        community: Secret,
    },
    V3 {
        user: String,
        auth_protocol: String,
        auth_password: Secret,
        /// `aes-128` for authPriv; none for authNoPriv.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        priv_protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        priv_password: Option<Secret>,
    },
}

/// What one part of a table group answered: the alternative that did (none: no alternative did).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Choice {
    pub(crate) part: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) alt: Option<String>,
}

/// The request of an `snmp_probe` or `snmp_poll` job. The destination was checked by the main
/// process (ADR-907); the worker holds no policy of its own about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SnmpRequest {
    pub(crate) agent: String,
    pub(crate) address: Ipv4Addr,
    pub(crate) port: u16,
    pub(crate) auth: AuthSpec,
    pub(crate) tables: Vec<SnmpTable>,
    pub(crate) max_repetitions: u32,
    /// The capabilities the main process already knows. Left out, a poll probes first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) known: Option<Vec<Choice>>,
}

/// The capability record of an agent (ADR-908): what it answered when it was probed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Capability {
    /// `v2c`, `authNoPriv` or `authPriv`.
    pub(crate) level: String,
    /// The v3 engine ID, in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) engine_id: Option<String>,
    /// sysObjectID, when the agent answered it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sys_object_id: Option<String>,
    /// One choice per part of every requested table.
    pub(crate) choices: Vec<Choice>,
}

/// One walk, as the status shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WalkStat {
    pub(crate) part: String,
    pub(crate) alt: String,
    /// Rows read (varbinds, over every column).
    pub(crate) rows: u32,
    /// `end`, `row_cap`, `time_cap` or `error`.
    pub(crate) stop: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

/// The answer of an `snmp_probe` or `snmp_poll` job (rows come before it, in `rows` messages).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SnmpResult {
    /// Set when this job probed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) capability: Option<Capability>,
    #[serde(default)]
    pub(crate) walks: Vec<WalkStat>,
    /// SNMP requests sent.
    pub(crate) requests: u32,
    /// Exchanges that timed out after their retries.
    pub(crate) timeouts: u32,
    pub(crate) elapsed_ms: u64,
    /// IPv6 entries counted and left out.
    #[serde(default)]
    pub(crate) ipv6_ignored: u32,
    /// Entries skipped as malformed or not bindings.
    #[serde(default)]
    pub(crate) skipped: u32,
    /// Why the poll ended early, when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) aborted: Option<String>,
}

/// REQ: DSC-004 — the text of an error from the agent exchange, with no address, name or byte of
/// the reply in it (ADR-908: errors carry no input byte).
pub(crate) fn error_text(e: &telltale_snmp::AgentError) -> String {
    use telltale_snmp::AgentError as E;
    match e {
        E::Timeout => "no reply (timeout)".to_owned(),
        E::Io(k) => format!("socket error ({k:?})"),
        E::Decode(_) => "a reply that does not decode".to_owned(),
        E::Usm(u) => format!("v3 security check failed ({u:?})"),
        E::ReportRefused => "the agent answered with a report that was refused".to_owned(),
        E::NoEngine => "no v3 engine ID".to_owned(),
        E::Status(s) => format!("the agent answered error-status {s}"),
        E::BadRequest => "the request cannot be built (a v3 user needs authentication)".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DSC-007 (`dsc_007_secret_debug_redacted`) — a secret in a job is redacted in `Debug`
    /// output, whole-job `Debug` included, and survives the wire as hex.
    #[test]
    fn dsc_007_secret_debug_redacted() {
        let req = SnmpRequest {
            agent: "gw".into(),
            address: Ipv4Addr::new(10, 0, 0, 1),
            port: 161,
            auth: AuthSpec::V3 {
                user: "u".into(),
                auth_protocol: "sha".into(),
                auth_password: Secret::new(b"planted-auth-password".to_vec()),
                priv_protocol: Some("aes-128".into()),
                priv_password: Some(Secret::new(b"planted-priv-password".to_vec())),
            },
            tables: vec![SnmpTable::Arp],
            max_repetitions: 10,
            known: None,
        };
        let shown = format!("{req:?}");
        assert!(!shown.contains("planted"), "{shown}");
        assert!(shown.contains("redacted"));
        let wire = serde_json::to_string(&req).unwrap();
        assert!(!wire.contains("planted"), "hex, not text: {wire}");
        let back: SnmpRequest = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, req);
        let AuthSpec::V3 { auth_password, .. } = back.auth else {
            panic!("v3")
        };
        assert_eq!(auth_password.expose(), b"planted-auth-password");
    }

    /// REQ: DSC-007 — a secret that isn't hex is refused, and any byte value round-trips.
    #[test]
    fn dsc_007_secret_hex_round_trips_every_byte() {
        let all: Vec<u8> = (0..=255u8).collect();
        let s = Secret::new(all.clone());
        let json = serde_json::to_string(&s).unwrap();
        let back: Secret = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), all.as_slice());
        assert!(serde_json::from_str::<Secret>("\"xyz\"").is_err());
        assert!(serde_json::from_str::<Secret>("\"abc\"").is_err());
    }
}

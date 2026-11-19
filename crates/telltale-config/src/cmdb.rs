//! REQ: DSC-901, DSC-906 (T31.2, ADR-1005 section 1) — `[cmdb]`: the configuration-item database's
//! switch and its thresholds. Off by default. It runs on the node `[discovery]` designates (the
//! named node, else the primary or the standalone node), even when `[discovery]` is off, and only
//! reads: nothing it holds reaches DNS answers, client matching, `identify` or policy (DSC-901).
//! The section is a shared one, edited through the admin-only `cmdb` kind (no agent scope).
//! `[[cmdb.precedence]]` (T31.3) is added to this section by that task.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// REQ: DSC-906 — `disappear_after_days`: shortest.
pub const DISAPPEAR_MIN_DAYS: u32 = 1;
/// REQ: DSC-906 — `disappear_after_days`: longest.
pub const DISAPPEAR_MAX_DAYS: u32 = 365;
/// REQ: DSC-906 — `disappear_after_days`: default (ADR-1004 section 8).
pub const DISAPPEAR_DEFAULT_DAYS: u32 = 14;
/// REQ: DSC-906 — `detect_settle_secs`: shortest.
pub const SETTLE_MIN_SECS: u32 = 60;
/// REQ: DSC-906 — `detect_settle_secs`: longest (a day).
pub const SETTLE_MAX_SECS: u32 = 86_400;
/// REQ: DSC-906 — `detect_settle_secs`: default (ten minutes).
pub const SETTLE_DEFAULT_SECS: u32 = 600;
/// REQ: DSC-906 — `unconfirmed_alert_hours`: shortest.
pub const ALERT_MIN_HOURS: u32 = 1;
/// REQ: DSC-906 — `unconfirmed_alert_hours`: longest (a month).
pub const ALERT_MAX_HOURS: u32 = 720;
/// REQ: DSC-906 — `unconfirmed_alert_hours`: default.
pub const ALERT_DEFAULT_HOURS: u32 = 24;
/// REQ: DSC-906 — `plan_expiry_days`: shortest.
pub const PLAN_MIN_DAYS: u32 = 1;
/// REQ: DSC-906 — `plan_expiry_days`: longest.
pub const PLAN_MAX_DAYS: u32 = 365;
/// REQ: DSC-906 — `plan_expiry_days`: default.
pub const PLAN_DEFAULT_DAYS: u32 = 30;
/// REQ: DSC-906 — `history_days`: shortest.
pub const HISTORY_MIN_DAYS: u32 = 1;
/// REQ: DSC-906 — `history_days`: longest (two years).
pub const HISTORY_MAX_DAYS: u32 = 730;
/// REQ: DSC-906 — `history_days`: default (ADR-1005 section 5).
pub const HISTORY_DEFAULT_DAYS: u32 = 90;
/// REQ: DSC-906 — `macd_retention_days`: shortest.
pub const MACD_MIN_DAYS: u32 = 1;
/// REQ: DSC-906 — `macd_retention_days`: longest (five years).
pub const MACD_MAX_DAYS: u32 = 1_825;
/// REQ: DSC-906 — `macd_retention_days`: default (ADR-1005 section 5).
pub const MACD_DEFAULT_DAYS: u32 = 365;

fn d_disappear() -> u32 {
    DISAPPEAR_DEFAULT_DAYS
}
fn d_settle() -> u32 {
    SETTLE_DEFAULT_SECS
}
fn d_alert() -> u32 {
    ALERT_DEFAULT_HOURS
}
fn d_plan() -> u32 {
    PLAN_DEFAULT_DAYS
}
fn d_history() -> u32 {
    HISTORY_DEFAULT_DAYS
}
fn d_macd() -> u32 {
    MACD_DEFAULT_DAYS
}

/// REQ: DSC-901, DSC-906 — the CMDB section (`[cmdb]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct CmdbConfig {
    /// Turn the CMDB on. Off by default: nothing starts, nothing is stored. It needs client
    /// addresses and names, so it cannot be on at `telemetry.qlog.privacy_level` 2 or 3.
    pub enabled: bool,
    /// How many days a device with a class 1 to 3 presence source must have been gone before a
    /// `delete` change is raised (it must also have been seen on at least 3 different days).
    #[serde(default = "d_disappear")]
    pub disappear_after_days: u32,
    /// How long a changed value must hold (and across two batches) before a change is raised,
    /// in seconds.
    #[serde(default = "d_settle")]
    pub detect_settle_secs: u32,
    /// How long a change may stay unconfirmed before one alert is raised through the event
    /// sinks, in hours. Off at privacy level 1 and above.
    #[serde(default = "d_alert")]
    pub unconfirmed_alert_hours: u32,
    /// How long an approved planned change waits to be seen at its source before it expires,
    /// in days.
    #[serde(default = "d_plan")]
    pub plan_expiry_days: u32,
    /// How long merged-value history is kept, in days.
    #[serde(default = "d_history")]
    pub history_days: u32,
    /// How long change records are kept, in days.
    #[serde(default = "d_macd")]
    pub macd_retention_days: u32,
    /// Forbid approving your own request.
    #[serde(default)]
    pub require_second_approver: bool,
}

impl Default for CmdbConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            disappear_after_days: DISAPPEAR_DEFAULT_DAYS,
            detect_settle_secs: SETTLE_DEFAULT_SECS,
            unconfirmed_alert_hours: ALERT_DEFAULT_HOURS,
            plan_expiry_days: PLAN_DEFAULT_DAYS,
            history_days: HISTORY_DEFAULT_DAYS,
            macd_retention_days: MACD_DEFAULT_DAYS,
            require_second_approver: false,
        }
    }
}

impl CmdbConfig {
    /// True when the section is left at its defaults (it is then not serialized, CLU-010).
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Loader};

    fn load(toml: &str) -> Result<Config, Vec<crate::ConfigError>> {
        Loader::new().toml_str("t", toml).load().map(|l| l.config)
    }

    /// REQ: DSC-901 (`dsc_901_cmdb_is_off_by_default`) — the section is off and is not serialized
    /// at its defaults, so a node that never set it carries no `cmdb` key (CLU-010).
    #[test]
    fn dsc_901_cmdb_is_off_by_default() {
        let c = Config::default();
        assert!(!c.cmdb.enabled);
        assert!(c.cmdb.is_default());
        let v = serde_json::to_value(&c).unwrap();
        assert!(v.get("cmdb").is_none(), "a default section is left out");
    }

    /// REQ: DSC-906 — the documented defaults (ADR-1005 section 1).
    #[test]
    fn dsc_906_defaults_are_the_documented_ones() {
        let d = CmdbConfig::default();
        assert_eq!(
            (
                d.disappear_after_days,
                d.detect_settle_secs,
                d.unconfirmed_alert_hours,
                d.plan_expiry_days,
                d.history_days,
                d.macd_retention_days,
                d.require_second_approver
            ),
            (14, 600, 24, 30, 90, 365, false)
        );
    }

    /// REQ: DSC-906 — a section round-trips through TOML, and a field left out takes its default.
    #[test]
    fn dsc_906_round_trips() {
        let c = load("[cmdb]\nenabled = true\nhistory_days = 30\n").unwrap();
        assert!(c.cmdb.enabled);
        assert_eq!(c.cmdb.history_days, 30);
        assert_eq!(c.cmdb.disappear_after_days, 14);
        let text = toml::to_string(&c.cmdb).unwrap();
        let back: CmdbConfig = toml::from_str(&text).unwrap();
        assert_eq!(back, c.cmdb);
    }

    /// REQ: DSC-906 — every threshold is checked against its range.
    #[test]
    fn dsc_906_ranges_are_checked() {
        for (field, bad) in [
            ("disappear_after_days", "0"),
            ("detect_settle_secs", "5"),
            ("unconfirmed_alert_hours", "0"),
            ("plan_expiry_days", "9999"),
            ("history_days", "0"),
            ("macd_retention_days", "100000"),
        ] {
            let errs = load(&format!("[cmdb]\n{field} = {bad}\n")).unwrap_err();
            assert!(
                errs.iter().any(|e| e.to_string().contains(field)),
                "{field}: {errs:?}"
            );
        }
        assert!(
            load("[cmdb]\nunknown = 1\n").is_err(),
            "unknown fields are refused"
        );
    }

    /// REQ: DSC-906 (ADR-1005 section 12; owner question 7) — `enabled` is a validation error at
    /// privacy level 2 and above, and fine at 0 and 1 (names are hashed at 1).
    #[test]
    fn dsc_906_enabled_is_refused_at_privacy_level_two() {
        for level in [2, 3] {
            let errs = load(&format!(
                "[telemetry.qlog]\nprivacy_level = {level}\n[cmdb]\nenabled = true\n"
            ))
            .unwrap_err();
            assert!(errs.iter().any(|e| e.to_string().contains("cmdb.enabled")));
        }
        for level in [0, 1] {
            load(&format!(
                "[telemetry.qlog]\nprivacy_level = {level}\n[cmdb]\nenabled = true\n"
            ))
            .unwrap();
        }
    }
}

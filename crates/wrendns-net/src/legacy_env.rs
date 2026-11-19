//! Pre-rename environment variables (ADR-1028; REQ: OPS-005).
//!
//! Until the release after the rename, `TELLTALE_*` still works: [`adopt`] copies each one to its
//! `WRENDNS_*` name unless that is already set (the new name wins) and removes the old one, so
//! the rest of the program, and every child it starts, sees only the new names. It lives here
//! because `set_var` and `remove_var` are `unsafe` (edition 2024) and this is the one crate that
//! may use `unsafe`.

use std::ffi::OsString;

/// The pre-rename prefix.
pub const LEGACY_PREFIX: &str = "TELLTALE_";
/// The prefix that replaced it.
pub const PREFIX: &str = "WRENDNS_";

/// One legacy variable found in the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adoption {
    /// `TELLTALE_X`.
    pub legacy: String,
    /// `WRENDNS_X`.
    pub name: String,
    /// The legacy value (copied to `name` unless `shadowed`).
    pub value: OsString,
    /// `name` was already set, so the legacy value is ignored.
    pub shadowed: bool,
}

/// What to do with `vars`: one [`Adoption`] per `TELLTALE_*` variable, in name order.
#[must_use]
pub fn plan(vars: &[(OsString, OsString)]) -> Vec<Adoption> {
    let has = |n: &str| vars.iter().any(|(k, _)| k.to_str() == Some(n));
    let mut out: Vec<Adoption> = vars
        .iter()
        .filter_map(|(k, v)| {
            let legacy = k.to_str()?;
            let rest = legacy.strip_prefix(LEGACY_PREFIX)?;
            let name = format!("{PREFIX}{rest}");
            Some(Adoption {
                legacy: legacy.to_owned(),
                shadowed: has(&name),
                name,
                value: v.clone(),
            })
        })
        .collect();
    out.sort_by(|a, b| a.legacy.cmp(&b.legacy));
    out
}

/// Applies [`plan`] to the process environment and returns what it found, for the caller to
/// warn about. Call it first thing in `main`, before any thread starts and before the command
/// line is parsed (clap reads some variables).
pub fn adopt() -> Vec<Adoption> {
    let vars: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let found = plan(&vars);
    for a in &found {
        // SAFETY: `main` calls this before it spawns any thread or reads the environment, so
        // nothing can read or write the environment concurrently.
        unsafe {
            if !a.shadowed {
                std::env::set_var(&a.name, &a.value);
            }
            std::env::remove_var(&a.legacy);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    /// REQ: OPS-005 — an old name is adopted; the new name wins when both are set.
    #[test]
    fn ops_005_legacy_env_names_are_adopted() {
        let p = plan(&env(&[
            ("TELLTALE_ROLE", "all"),
            ("TELLTALE_LOG", "debug"),
            ("WRENDNS_LOG", "info"),
            ("PATH", "/bin"),
            ("TELLTALEX", "no underscore, not ours"),
        ]));
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].legacy, "TELLTALE_LOG");
        assert_eq!(p[0].name, "WRENDNS_LOG");
        assert!(p[0].shadowed, "WRENDNS_LOG is set, so it wins");
        assert_eq!(p[1].name, "WRENDNS_ROLE");
        assert!(!p[1].shadowed);
        assert_eq!(p[1].value, OsString::from("all"));
    }
}

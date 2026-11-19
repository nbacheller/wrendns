//! Pre-rename names that still work for one release (ADR-1028, spec/10 T33.2): the `telltale`
//! command, `/etc/telltale/telltale.toml`, `/var/lib/telltale`, and the `TELLTALE_*` variables
//! (`wrendns_net::legacy_env`). Each use says so once, with the way to migrate; the
//! `deploy/systemd/migrate-from-telltale.sh` script does it for a native install
//! (docs/running.md, "Upgrading to WrenDNS").
//!
//! REQ: OPS-005, OPS-006.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use tracing::warn;

/// The configuration file the pre-rename packages installed.
pub(crate) const LEGACY_CONFIG: &str = "/etc/telltale/telltale.toml";
/// The data directory the pre-rename packages used.
pub(crate) const LEGACY_DATA_DIR: &str = "/var/lib/telltale";
/// The data directory now.
pub(crate) const DATA_DIR: &str = "/var/lib/wrendns";

/// True when the program was started under the old command name (a symlink the packages and
/// images keep for one release).
pub(crate) fn is_legacy_command(argv0: Option<&OsStr>) -> bool {
    argv0
        .map(Path::new)
        .and_then(Path::file_stem)
        .is_some_and(|s| s == "telltale")
}

/// The warning printed once when started as `telltale`.
pub(crate) const COMMAND_WARNING: &str =
    "warning: the `telltale` command is now `wrendns`; the old name works for this release only";

/// The warning logged when the pre-rename configuration file is read.
pub(crate) fn config_warning(new: &str) -> String {
    format!(
        "reading the pre-rename configuration file; move it to {new} with          deploy/systemd/migrate-from-telltale.sh (docs/running.md, \"Upgrading to WrenDNS\")"
    )
}

/// The default configuration file: the new path if it exists, else the old one (with a warning
/// the caller logs), else none.
pub(crate) fn default_config(new: &str, exists: impl Fn(&Path) -> bool) -> Option<(PathBuf, bool)> {
    if exists(Path::new(new)) {
        return Some((PathBuf::from(new), false));
    }
    exists(Path::new(LEGACY_CONFIG)).then(|| (PathBuf::from(LEGACY_CONFIG), true))
}

/// When `data_dir` is the new default, that directory doesn't exist yet and the old one does,
/// the node keeps using the old one. Returns the directory to use, and whether it is the old one.
pub(crate) fn data_dir(configured: &str, exists: impl Fn(&Path) -> bool) -> Option<&'static str> {
    (configured == DATA_DIR && !exists(Path::new(DATA_DIR)) && exists(Path::new(LEGACY_DATA_DIR)))
        .then_some(LEGACY_DATA_DIR)
}

/// Applies [`data_dir`] to a loaded configuration, saying so when `warnings` is set.
pub(crate) fn adopt_data_dir(cfg: &mut wrendns_config::Config, warnings: bool) {
    if let Some(old) = data_dir(cfg.node.data_dir.as_str(), Path::exists) {
        if warnings {
            warn!(
                "{LEGACY_DATA_DIR} exists and {DATA_DIR} doesn't, so the node keeps using it; \
                 move it with deploy/systemd/migrate-from-telltale.sh (docs/running.md, \
                 \"Upgrading to WrenDNS\")"
            );
        }
        cfg.node.data_dir = wrendns_config::SafeString::from(old);
    }
}

/// The Kubernetes label that named a workload's group before the rename.
const LEGACY_GROUP_LABEL: &str = "telltaledns.io/group";

/// REQ: FLT-017 (ADR-1028) — a workload's group label: `configured` (`[kubernetes] label`), and,
/// while it is the default, the pre-rename `LEGACY_GROUP_LABEL` too, so namespaces and pods
/// labelled before the rename keep their groups. The configured label wins.
pub(crate) fn group_label<'a>(
    labels: &'a std::collections::BTreeMap<String, String>,
    configured: &str,
) -> Option<&'a String> {
    labels.get(configured).or_else(|| {
        (configured == wrendns_config::KubernetesConfig::default().label.as_str())
            .then(|| labels.get(LEGACY_GROUP_LABEL))
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: OPS-006 — the old command name is recognised by its file name, with or without `.exe`.
    #[test]
    fn ops_006_legacy_command_name() {
        assert!(is_legacy_command(Some(OsStr::new(
            "/usr/local/bin/telltale"
        ))));
        assert!(is_legacy_command(Some(OsStr::new("telltale"))));
        assert!(!is_legacy_command(Some(OsStr::new(
            "/usr/local/bin/wrendns"
        ))));
        assert!(!is_legacy_command(Some(OsStr::new(
            "telltale-x86_64-linux-test"
        ))));
        assert!(!is_legacy_command(None));
    }

    /// REQ: OPS-006 — the old configuration file is read only when the new one is absent.
    #[test]
    fn ops_006_legacy_config_only_when_new_is_absent() {
        let new = "/etc/wrendns/wrendns.toml";
        let only = |p: &'static str| move |x: &Path| x == Path::new(p);
        assert_eq!(
            default_config(new, only(new)),
            Some((PathBuf::from(new), false))
        );
        assert_eq!(
            default_config(new, only(LEGACY_CONFIG)),
            Some((PathBuf::from(LEGACY_CONFIG), true))
        );
        assert_eq!(default_config(new, |_| false), None);
        assert_eq!(
            default_config(new, |_| true),
            Some((PathBuf::from(new), false)),
            "both present: the new one"
        );
    }

    /// REQ: FLT-017 — the pre-rename group label is read only while `[kubernetes] label` is the
    /// default, and the configured label wins.
    #[test]
    fn flt_017_legacy_group_label() {
        let default = wrendns_config::KubernetesConfig::default()
            .label
            .to_string();
        let map = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let old = map(&[(LEGACY_GROUP_LABEL, "kids")]);
        assert_eq!(
            group_label(&old, &default).map(String::as_str),
            Some("kids")
        );
        assert_eq!(
            group_label(&old, "my.org/group"),
            None,
            "a custom label is exact"
        );
        let both = map(&[(LEGACY_GROUP_LABEL, "kids"), (default.as_str(), "work")]);
        assert_eq!(
            group_label(&both, &default).map(String::as_str),
            Some("work")
        );
    }

    /// REQ: OPS-006 — the old data directory is kept only for the default setting, only while the
    /// new one doesn't exist.
    #[test]
    fn ops_006_legacy_data_dir() {
        let old_only = |p: &Path| p == Path::new(LEGACY_DATA_DIR);
        assert_eq!(data_dir(DATA_DIR, old_only), Some(LEGACY_DATA_DIR));
        assert_eq!(data_dir(DATA_DIR, |_| true), None, "the new one exists");
        assert_eq!(
            data_dir("/srv/dns", old_only),
            None,
            "an explicit setting is never changed"
        );
        assert_eq!(data_dir(DATA_DIR, |_| false), None, "a fresh install");
    }
}

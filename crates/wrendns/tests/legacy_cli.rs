//! REQ: OPS-005, OPS-006 (ADR-1028) — the pre-rename command name and environment variables work
//! for one release, each with a warning that says what to use instead.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_wrendns")
}

#[test]
fn ops_005_a_pre_rename_variable_is_adopted_with_a_warning() {
    let out = Command::new(bin())
        .arg("--version")
        .env("TELLTALE_LOG", "debug")
        .env("WRENDNS_ROLE", "all")
        .env("TELLTALE_ROLE", "resolver")
        .output()
        .unwrap();
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("TELLTALE_LOG is now WRENDNS_LOG; the old name works for this release only"),
        "{err}"
    );
    assert!(
        err.contains("TELLTALE_ROLE is now WRENDNS_ROLE (both are set, so the new one is used)"),
        "{err}"
    );
}

#[test]
fn ops_005_new_names_alone_are_silent() {
    let out = Command::new(bin())
        .arg("--version")
        .env("WRENDNS_LOG", "debug")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).is_empty());
}

#[cfg(unix)]
#[test]
fn ops_006_the_pre_rename_command_name_warns_and_works() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("telltale");
    std::os::unix::fs::symlink(bin(), &old).unwrap();
    let out = Command::new(&old).arg("--version").output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("the `telltale` command is now `wrendns`"),
        "{err}"
    );
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("wrendns "));
}

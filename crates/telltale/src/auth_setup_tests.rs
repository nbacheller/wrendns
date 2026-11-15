// REQ: moved out of `auth_setup.rs` so the test code is a file of its own (CodeQL ignores test paths).
use super::*;

fn cfg(dir: &Path) -> Config {
    let mut c = Config::default();
    c.node.data_dir = telltale_config::SafeString::new(dir.to_string_lossy()).unwrap();
    c
}

// REQ: API-003 — the setup token survives restarts until the first admin exists.
#[test]
fn api_003_setup_token_is_kept_private_and_reused_across_restarts() {
    let dir = std::env::temp_dir().join(format!("tt-auth-{}", crypto::random_id()));
    let c = cfg(&dir);
    let a = open(&c).unwrap();
    let t1 = a.setup_token().unwrap().unwrap();
    let file = dir.join(SETUP_TOKEN_FILE);
    let mode =
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&file).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o600);
    drop(a);
    let a = open(&c).unwrap();
    assert_eq!(
        a.setup_token().unwrap().as_deref(),
        Some(t1.as_str()),
        "same token after a restart"
    );
    a.setup(&t1, "root", "correct horse battery", now())
        .unwrap();
    assert!(!file.exists());
    drop(a);
    let a = open(&c).unwrap();
    assert!(!a.setup_required().unwrap());
    assert!(!file.exists(), "no new token once set up");
    let _ = std::fs::remove_dir_all(&dir);
}

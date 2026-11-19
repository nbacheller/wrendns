// REQ: moved out of `auth_setup.rs` so the test code is a file of its own (CodeQL ignores test paths).
use super::*;

/// A secrets store for `c` that reads no environment.
fn store(c: &Config) -> crate::secrets::SecretStore {
    crate::secrets::SecretStore::with_env(c, std::sync::Arc::new(|_: &str| None), true, false)
}

fn cfg(dir: &Path) -> Config {
    let mut c = Config::default();
    c.node.data_dir = wrendns_config::SafeString::new(dir.to_string_lossy()).unwrap();
    c
}

// REQ: API-003 — the setup token survives restarts until the first admin exists.
#[test]
fn api_003_setup_token_is_kept_private_and_reused_across_restarts() {
    let dir = std::env::temp_dir().join(format!("tt-auth-{}", crypto::random_id()));
    let c = cfg(&dir);
    let a = open(&c, &store(&c)).unwrap();
    let t1 = a.setup_token().unwrap().unwrap();
    let file = dir.join(SETUP_TOKEN_FILE);
    let mode =
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&file).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o600);
    drop(a);
    let a = open(&c, &store(&c)).unwrap();
    assert_eq!(
        a.setup_token().unwrap().as_deref(),
        Some(t1.as_str()),
        "same token after a restart"
    );
    a.setup(&t1, "root", "correct horse battery", now())
        .unwrap();
    assert!(!file.exists());
    drop(a);
    let a = open(&c, &store(&c)).unwrap();
    assert!(!a.setup_required().unwrap());
    assert!(!file.exists(), "no new token once set up");
    let _ = std::fs::remove_dir_all(&dir);
}

// REQ: API-003 (ADR-972) — an offline reset sets the new password, ends only that user's UI
// sessions, rejects the old password, and is audited under the system actor.
#[test]
fn api_003_reset_password_offline_ends_sessions_and_audits() {
    let dir = std::env::temp_dir().join(format!("tt-reset-{}", crypto::random_id()));
    let c = cfg(&dir);
    let a = open(&c, &store(&c)).unwrap();
    let t = a.setup_token().unwrap().unwrap();
    a.setup(&t, "root", "correct horse battery", now()).unwrap();
    let hash = crypto::hash_password("the first alice password").unwrap();
    let alice = a
        .state()
        .create_user("alice", &hash, "viewer", false, now())
        .unwrap();
    let root = a.state().user_by_name("root").unwrap().unwrap();
    let ip = std::net::IpAddr::from([127, 0, 0, 1]);
    a.start_session(&alice, ip, now()).unwrap();
    a.start_session(&alice, ip, now()).unwrap();
    a.start_session(&root, ip, now()).unwrap();

    let ended = reset_in(
        Arc::clone(a.state()),
        settings(&c),
        "Alice",
        "a brand new password",
        now(),
    )
    .unwrap();
    assert_eq!(ended, 2, "both of alice's sessions end");
    let u = a.state().user_by_name("alice").unwrap().unwrap();
    assert!(crypto::verify_password(
        "a brand new password",
        &u.password_hash
    ));
    assert!(!crypto::verify_password(
        "the first alice password",
        &u.password_hash
    ));
    assert_eq!(
        a.state().delete_user_sessions(alice.id, None).unwrap(),
        0,
        "nothing left to end"
    );
    let rows = a
        .state()
        .audit_page(None, 5, Some("user.password"), None)
        .unwrap();
    assert!(
        rows.iter().any(|e| e.target == "alice"
            && e.actor == "auth reset-password"
            && e.actor_kind == "system"),
        "the reset is audited: {rows:?}"
    );
    assert!(
        reset_in(
            Arc::clone(a.state()),
            settings(&c),
            "nobody",
            "a brand new password",
            now()
        )
        .is_err(),
        "an unknown user is refused"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// REQ: API-003 (ADR-972) — a reset refuses while `wrendns run` holds the data directory, and
// changes nothing.
#[test]
fn api_003_reset_password_refuses_a_running_node() {
    let dir = std::env::temp_dir().join(format!("tt-reset-held-{}", crypto::random_id()));
    let c = cfg(&dir);
    drop(open(&c, &store(&c)).unwrap());
    let held = crate::datadir::lock(&dir, Duration::ZERO).unwrap();
    assert!(!reset_password(&c, "root").unwrap(), "refused while held");
    drop(held);
    let _ = std::fs::remove_dir_all(&dir);
}

// REQ: API-003 (ADR-972) — a data directory with no `state.db` (a mistyped `-c`) is refused, and
// nothing is created there.
#[test]
fn api_003_reset_password_refuses_a_missing_state() {
    let dir = std::env::temp_dir().join(format!("tt-reset-none-{}", crypto::random_id()));
    let c = cfg(&dir);
    assert!(
        !reset_password(&c, "root").unwrap(),
        "refused without state"
    );
    assert!(!dir.exists(), "no directory is created for a wrong path");
}

// REQ: API-004 (ADR-987) — start-up says what the break-glass path leaves open.
#[test]
fn api_004_break_glass_notice_covers_unset_empty_and_listed() {
    let net = wrendns_config::Cidr {
        addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        prefix: 8,
    };
    assert!(break_glass_notice(false, None).is_none());
    let (warn, text) = break_glass_notice(true, None).unwrap();
    assert!(warn && text.contains("loopback"));
    let (warn, text) = break_glass_notice(true, Some(&[])).unwrap();
    assert!(warn && text.contains("empty"));
    let (warn, text) = break_glass_notice(true, Some(&[net])).unwrap();
    assert!(!warn && text.contains("1 listed"));
}

//! REQ: OPS-014, NFR-005 (T23.3, ADR-903 §2–3) — the encrypted secrets store and the node key:
//! where the key comes from and when one is made, the locked state, the associated data, rotation
//! (at start and offline, crash-safe), reading a credential, and what never shows a value or a
//! key.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use wrendns_config::Config;
use wrendns_store::state::State;
use zeroize::Zeroizing;

use super::cli::{Until, rotate_key};
use super::credential::Credential;
use super::store::{EnvFn, RowHealth, SecretStore, StoreError, StoreState, open};
use super::value::{Kind, SecretValue, ValueError};
use super::*;

fn cfg_in(dir: &Path) -> Config {
    let mut c = Config::default();
    c.node.data_dir = wrendns_config::SafeString::new(dir.to_str().unwrap()).unwrap();
    c
}

fn env(pairs: &[(&str, &str)]) -> EnvFn {
    let m: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    Arc::new(move |k: &str| m.get(k).cloned())
}

fn store(c: &Config, e: &EnvFn) -> SecretStore {
    SecretStore::with_env(c, Arc::clone(e), true, false)
}

fn value(v: &str) -> SecretValue {
    SecretValue::new(Kind::Text, Zeroizing::new(v.to_owned())).unwrap()
}

fn put(s: &SecretStore, name: &str, v: &str) {
    s.put(name, Kind::Text, &value(v), 0, "root", "local", 100)
        .unwrap();
}

fn read(s: &SecretStore, name: &str) -> String {
    s.get(name).unwrap().expose().to_owned()
}

fn key_id(text: &str) -> String {
    hex(&NodeKey::parse(text, KeySource::Env).unwrap().key_id())
}

/// The bytes of `state.db` and its WAL.
fn db_bytes(dir: &Path) -> Vec<u8> {
    let mut all = std::fs::read(dir.join("state.db")).unwrap_or_default();
    all.extend(std::fs::read(dir.join("state.db-wal")).unwrap_or_default());
    all
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// REQ: OPS-014 (AC1) — a full member's first start makes `secrets.key` (0600) while the table is
/// empty; the next start reads the same key and the value stored under it. A resolver pod makes
/// none, and holds no secrets.
#[test]
fn ops_014_first_start_creates_key_0600() {
    let tmp = tempfile::tempdir().unwrap();
    let c = cfg_in(tmp.path());
    let none = env(&[]);
    let s = store(&c, &none);
    assert_eq!(s.status().state, StoreState::Starting);
    let k = s.keys().unwrap();
    let file = tmp.path().join(KEY_FILE);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(matches!(k.current.source(), KeySource::DataDir(_)));
    assert!(k.warnings.is_empty(), "{:?}", k.warnings);
    assert_eq!(s.status().state, StoreState::Ready);
    put(&s, "unifi", "key-1");
    let again = store(&c, &none);
    assert_eq!(again.keys().unwrap().current.key_id(), k.current.key_id());
    assert_eq!(read(&again, "unifi"), "key-1");

    let pod_dir = tempfile::tempdir().unwrap();
    let mut pod = cfg_in(pod_dir.path());
    pod.cluster.ephemeral = true;
    let p = store(&pod, &none);
    assert!(p.keys().is_err());
    assert_eq!(p.status().state, StoreState::Ephemeral);
    assert!(!pod_dir.path().join(KEY_FILE).exists(), "pods make none");
    assert!(matches!(
        p.put("x", Kind::Text, &value("v"), 0, "root", "local", 1),
        Err(StoreError::Ephemeral)
    ));
    assert!(
        health_reasons_of(&p).is_empty(),
        "a pod never reports locked"
    );
}

fn health_reasons_of(s: &SecretStore) -> Vec<String> {
    store::health_reasons(&s.status())
        .into_iter()
        .map(|r| r.code)
        .collect()
}

/// REQ: OPS-014 (AC2) — `WRENDNS_SECRETS_KEY` wins over `[node] secrets_key_file`, which wins
/// over the data directory's key; with either set, no `secrets.key` is made. A value stored under
/// one key is read under that key only.
#[test]
#[allow(clippy::many_single_char_names)] // one store per source
fn ops_014_env_and_file_key_override_win() {
    let tmp = tempfile::tempdir().unwrap();
    let env_key = NodeKey::generate().unwrap();
    let file_key = NodeKey::generate().unwrap();
    let kf = tmp.path().join("mounted.key");
    std::fs::write(&kf, file_key.as_str()).unwrap();
    let mut c = cfg_in(tmp.path());
    c.node.secrets_key_file = wrendns_config::SafeString::new(kf.to_str().unwrap()).unwrap();
    let both = env(&[(KEY_VAR, env_key.as_str())]);
    let s = store(&c, &both);
    let k = s.keys().unwrap();
    assert_eq!(*k.current.source(), KeySource::Env);
    assert_eq!(hex(&k.current.key_id()), key_id(&env_key));
    put(&s, "token", "from-env");
    let f = store(&c, &env(&[]));
    let fk = f.keys().unwrap();
    assert!(matches!(fk.current.source(), KeySource::File(_)));
    assert_eq!(hex(&fk.current.key_id()), key_id(&file_key));
    assert_eq!(f.get("token").unwrap_err(), store::Unavailable::Unreadable);
    assert!(
        !tmp.path().join(KEY_FILE).exists(),
        "a configured key: none made"
    );
    // The variable alone, over the data directory.
    let plain = cfg_in(tmp.path());
    let e = store(&plain, &both);
    assert_eq!(*e.keys().unwrap().current.source(), KeySource::Env);
    assert_eq!(read(&e, "token"), "from-env");
    assert!(!tmp.path().join(KEY_FILE).exists());
}

/// REQ: OPS-014 (AC4) — `secrets.key` gone while rows exist: the store is locked, no key is made,
/// writes are refused with 503 `secrets_locked`, and status reads still list the secrets. A wrong
/// key (no row decrypts) locks it too. A locked replica whose rows are all the cluster's heals with
/// a new key; one with rows of its own doesn't.
#[test]
fn ops_014_missing_key_with_rows_locks_not_generates() {
    let tmp = tempfile::tempdir().unwrap();
    let c = cfg_in(tmp.path());
    let none = env(&[]);
    let s = store(&c, &none);
    put(&s, "unifi", "k");
    std::fs::remove_file(tmp.path().join(KEY_FILE)).unwrap();
    let locked = store(&c, &none);
    assert!(locked.keys().is_err());
    let st = locked.status();
    assert_eq!(st.state, StoreState::Locked);
    assert!(st.reason.as_deref().unwrap().contains("missing"), "{st:?}");
    assert!(!tmp.path().join(KEY_FILE).exists(), "not generated");
    assert_eq!(st.live(), 1, "status reads work");
    let err = locked
        .put("other", Kind::Text, &value("v"), 0, "root", "local", 1)
        .unwrap_err();
    assert!(matches!(err, StoreError::Locked(_)), "{err:?}");
    let p = err.problem();
    assert_eq!(
        (p.status, p.code),
        (503, wrendns_api::problem::Code::SecretsLocked)
    );
    assert!(matches!(
        locked.get("unifi"),
        Err(store::Unavailable::Locked(_))
    ));
    assert_eq!(health_reasons_of(&locked), ["secrets_locked"]);
    assert!(
        locked.heal_as_replica().is_err(),
        "a row made here isn't dropped"
    );

    // A different key: nothing decrypts, locked; the rows stay.
    std::fs::write(
        tmp.path().join(KEY_FILE),
        NodeKey::generate().unwrap().as_str(),
    )
    .unwrap();
    let wrong = store(&c, &none);
    let st = wrong.status_loaded();
    assert_eq!(st.state, StoreState::Locked);
    assert!(
        st.reason.as_deref().unwrap().contains("none of the 1"),
        "{st:?}"
    );
    assert_eq!(st.count(RowHealth::Unreadable), 1);

    // The replica's self-heal: every row the cluster's.
    let state = State::open(&tmp.path().join("state.db")).unwrap();
    let mut row = state.secret_row("unifi").unwrap().unwrap();
    row.origin = "cluster".into();
    state.put_secret_row(&row, 1).unwrap();
    let replica = store(&c, &none);
    assert_eq!(replica.status_loaded().state, StoreState::Locked);
    assert_eq!(replica.heal_as_replica().unwrap().rows, 1);
    assert_eq!(replica.status().state, StoreState::Ready);
    assert_eq!(replica.status().live(), 0);
    put(&replica, "unifi", "fetched again");
}

impl SecretStore {
    /// The status after a load (tests).
    fn status_loaded(&self) -> store::Status {
        let _ = self.keys();
        self.status()
    }
}

/// REQ: OPS-014 (AC3, the store's part) — a configured key that can't be read locks the store,
/// whatever the table holds, and a key mounted later unlocks it at the next retry.
#[test]
fn ops_014_configured_key_unreadable_is_locked() {
    let tmp = tempfile::tempdir().unwrap();
    let mut c = cfg_in(tmp.path());
    let kf = tmp.path().join("not-yet.key");
    c.node.secrets_key_file = wrendns_config::SafeString::new(kf.to_str().unwrap()).unwrap();
    let s = store(&c, &env(&[]));
    assert_eq!(s.status_loaded().state, StoreState::Locked);
    assert!(!tmp.path().join(KEY_FILE).exists());
    std::fs::write(&kf, NodeKey::generate().unwrap().as_str()).unwrap();
    s.load_now();
    assert_eq!(s.status().state, StoreState::Ready);
    // A key that isn't one: locked again, with why.
    std::fs::write(&kf, "not a key").unwrap();
    s.load_now();
    let st = s.status();
    assert_eq!(st.state, StoreState::Locked);
    assert!(st.reason.unwrap().contains("not a WrenDNS secrets key"));
}

/// REQ: OPS-014, NFR-005 (AC5) — the associated data binds a ciphertext to its key, kind, name and
/// stamp: moved to another name, given another kind or stamp, it fails, and the store calls the
/// row corrupt.
#[test]
fn ops_014_row_swap_fails_aad() {
    let tmp = tempfile::tempdir().unwrap();
    let c = cfg_in(tmp.path());
    let none = env(&[]);
    let s = store(&c, &none);
    put(&s, "a", "value-a");
    put(&s, "b", "value-b");
    let keys = s.keys().unwrap();
    let state = State::open(&tmp.path().join("state.db")).unwrap();
    let a = state.secret_row("a").unwrap().unwrap();
    let b = state.secret_row("b").unwrap().unwrap();
    assert_eq!(open(&keys.current, &a).unwrap().expose(), "value-a");
    // a's ciphertext under b's name (and b's stamp, or a's).
    for swapped in [
        wrendns_store::state::SecretRow {
            nonce: a.nonce.clone(),
            ciphertext: a.ciphertext.clone(),
            ..b.clone()
        },
        wrendns_store::state::SecretRow {
            name: "b".into(),
            ..a.clone()
        },
        wrendns_store::state::SecretRow {
            kind: "pem".into(),
            ..a.clone()
        },
        // The boundary between kind and name moved (`text`+`a` read as `tex`+`ta`): the same
        // bytes without the lengths.
        wrendns_store::state::SecretRow {
            kind: "tex".into(),
            name: "ta".into(),
            ..a.clone()
        },
        wrendns_store::state::SecretRow {
            kind: "te".into(),
            name: "xta".into(),
            ..a.clone()
        },
        wrendns_store::state::SecretRow {
            kind: String::new(),
            name: "texta".into(),
            ..a.clone()
        },
        wrendns_store::state::SecretRow {
            kind: "texta".into(),
            name: String::new(),
            ..a.clone()
        },
        wrendns_store::state::SecretRow {
            stamp: wrendns_store::state::Stamp {
                epoch: a.stamp.epoch,
                seq: a.stamp.seq + 1,
            },
            ..a.clone()
        },
        wrendns_store::state::SecretRow {
            stamp: wrendns_store::state::Stamp {
                epoch: a.stamp.epoch + 1,
                seq: a.stamp.seq,
            },
            ..a.clone()
        },
    ] {
        assert_eq!(
            open(&keys.current, &swapped).unwrap_err(),
            RowHealth::Corrupt,
            "{}/{}/{:?}",
            swapped.name,
            swapped.kind,
            swapped.stamp
        );
    }
    // In the table: b now holds a's ciphertext.
    state
        .put_secret_row(
            &wrendns_store::state::SecretRow {
                nonce: a.nonce.clone(),
                ciphertext: a.ciphertext.clone(),
                ..b
            },
            1,
        )
        .unwrap();
    let again = store(&c, &none);
    assert_eq!(again.get("b").unwrap_err(), store::Unavailable::Corrupt);
    assert_eq!(read(&again, "a"), "value-a");
    let st = again.status();
    assert_eq!(
        (st.count(RowHealth::Readable), st.count(RowHealth::Corrupt)),
        (1, 1)
    );
    // Moved in the table to a name the boundary shift makes (`tex`/`ta`): corrupt, not `a`'s.
    state
        .put_secret_row(
            &wrendns_store::state::SecretRow {
                kind: "tex".into(),
                name: "ta".into(),
                ..a.clone()
            },
            1,
        )
        .unwrap();
    let shifted = store(&c, &none);
    assert_eq!(shifted.get("ta").unwrap_err(), store::Unavailable::Corrupt);
    assert_eq!(read(&shifted, "a"), "value-a");
}

/// REQ: OPS-014, CLU-004 — a reload that changes the key settings while a load holds the store
/// (the upkeep's retry, a read) finishes: `configure` never waits on the store, and the next use
/// reads the new settings. Before, the two took their locks in opposite orders and hung.
#[test]
fn ops_014_reconfigure_during_load_no_deadlock() {
    let tmp = tempfile::tempdir().unwrap();
    let a = cfg_in(tmp.path());
    let mut b = cfg_in(tmp.path());
    b.node.secrets_key_file =
        wrendns_config::SafeString::new(tmp.path().join("nope.key").to_str().unwrap()).unwrap();
    let s = Arc::new(store(&a, &env(&[])));
    let (done, wait) = std::sync::mpsc::channel();
    let loader = Arc::clone(&s);
    let d1 = done.clone();
    std::thread::spawn(move || {
        for _ in 0..300 {
            loader.load_now();
            let _ = loader.status();
        }
        let _ = d1.send(());
    });
    let conf = Arc::clone(&s);
    std::thread::spawn(move || {
        for i in 0..300 {
            conf.configure(if i % 2 == 0 { &b } else { &a });
        }
        let _ = done.send(());
    });
    for _ in 0..2 {
        wait.recv_timeout(std::time::Duration::from_secs(60))
            .expect("configure and a load deadlocked");
    }
    // The last settings win at the next use: a missing key file locks, the data key doesn't.
    let mut locked = cfg_in(tmp.path());
    locked.node.secrets_key_file =
        wrendns_config::SafeString::new(tmp.path().join("nope.key").to_str().unwrap()).unwrap();
    s.configure(&locked);
    assert!(s.keys().is_err());
    assert_eq!(s.status().state, StoreState::Locked);
    s.configure(&cfg_in(tmp.path()));
    assert!(s.keys().is_ok());
    assert_eq!(s.status().state, StoreState::Ready);
}

/// REQ: OPS-014 — `wrendns secrets status` writes nothing: a pending `secrets.key.new` stays
/// (it may be a `rotate-key` running now) and is reported, rows under the previous key are
/// counted as readable but not re-encrypted, and a node with nothing stored gets no database.
#[test]
fn ops_014_status_is_read_only() {
    // Nothing stored yet: no database, no key made.
    let empty = tempfile::tempdir().unwrap();
    let mut out = Vec::new();
    let _ = cli::status(&cfg_in(empty.path()), env(&[]), &mut out).unwrap();
    assert!(!empty.path().join("state.db").exists());
    assert!(!empty.path().join(KEY_FILE).exists());

    let tmp = tempfile::tempdir().unwrap();
    let c = cfg_in(tmp.path());
    let none = env(&[]);
    let s = store(&c, &none);
    put(&s, "git", "v");
    drop(s);
    rotate_key(&c, &none, Until::NewKeyWritten).unwrap();
    let new_file = tmp.path().join(NEW_KEY_FILE);
    let mut out = Vec::new();
    assert!(cli::status(&c, Arc::clone(&none), &mut out).unwrap());
    let text = String::from_utf8(out).unwrap();
    assert!(new_file.exists(), "a status read left it: {text}");
    assert!(text.contains("secrets.key.new"), "{text}");

    // The previous key: counted, not re-encrypted.
    let k1 = NodeKey::generate().unwrap();
    let k2 = NodeKey::generate().unwrap();
    let other = tempfile::tempdir().unwrap();
    let c2 = cfg_in(other.path());
    let s = store(&c2, &env(&[(KEY_VAR, k1.as_str())]));
    put(&s, "one", "v1");
    drop(s);
    let both = env(&[(KEY_VAR, k2.as_str()), (PREVIOUS_KEY_VAR, k1.as_str())]);
    let mut out = Vec::new();
    assert!(cli::status(&c2, both, &mut out).unwrap());
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("1 stored secret(s) under it"), "{text}");
    assert!(text.contains("1 readable"), "{text}");
    let row = State::open(&other.path().join("state.db"))
        .unwrap()
        .secret_row("one")
        .unwrap()
        .unwrap();
    assert_eq!(hex(&row.key_id), key_id(&k1), "not re-encrypted");
}

/// REQ: OPS-014 (ADR-903 §3) — a previous-key file removed after the rotation, with the setting
/// left, is a warning, not a locked store.
#[test]
fn ops_014_missing_previous_key_file_warns() {
    let tmp = tempfile::tempdir().unwrap();
    let mut c = cfg_in(tmp.path());
    let s = store(&c, &env(&[]));
    put(&s, "x", "v");
    drop(s);
    c.node.secrets_previous_key_file =
        wrendns_config::SafeString::new(tmp.path().join("old.key").to_str().unwrap()).unwrap();
    let s = store(&c, &env(&[]));
    let k = s.keys().unwrap();
    assert!(k.previous.is_none());
    assert!(
        k.warnings.iter().any(|w| w.contains("old.key")),
        "{:?}",
        k.warnings
    );
    assert_eq!(s.status().state, StoreState::Ready);
    assert_eq!(read(&s, "x"), "v");
}

/// REQ: OPS-014 (ADR-903 §3) — the replica's self-heal clears rows only when a new key fixes the
/// lock: not when `secrets.key` is there but can't be read (here a directory), where it would drop
/// them and stay locked.
#[test]
fn ops_014_heal_not_for_unreadable_key_file() {
    let tmp = tempfile::tempdir().unwrap();
    let c = cfg_in(tmp.path());
    let none = env(&[]);
    let s = store(&c, &none);
    put(&s, "unifi", "k");
    drop(s);
    let state = State::open(&tmp.path().join("state.db")).unwrap();
    let mut row = state.secret_row("unifi").unwrap().unwrap();
    row.origin = "cluster".into();
    state.put_secret_row(&row, 1).unwrap();
    std::fs::remove_file(tmp.path().join(KEY_FILE)).unwrap();
    std::fs::create_dir(tmp.path().join(KEY_FILE)).unwrap();
    let replica = store(&c, &none);
    assert_eq!(replica.status_loaded().state, StoreState::Locked);
    let err = replica.heal_as_replica().unwrap_err();
    assert!(err.contains("doesn't fix"), "{err}");
    assert_eq!(state.secret_row_count().unwrap(), 1, "rows kept");
}

/// REQ: OPS-014 (AC6) — with the previous key given, rows under it are re-encrypted under the
/// current one at start, in one transaction; afterwards neither `state.db` nor its WAL holds the
/// old ciphertext, and the previous key can go.
#[test]
fn ops_014_previous_key_reencrypts_at_start() {
    let tmp = tempfile::tempdir().unwrap();
    let c = cfg_in(tmp.path());
    let k1 = NodeKey::generate().unwrap();
    let k2 = NodeKey::generate().unwrap();
    let long = "x".repeat(200);
    let s = store(&c, &env(&[(KEY_VAR, k1.as_str())]));
    put(&s, "one", &long);
    put(&s, "two", "second");
    drop(s);
    let state = State::open(&tmp.path().join("state.db")).unwrap();
    let old = state.secret_row("one").unwrap().unwrap();
    drop(state);
    assert!(contains(&db_bytes(tmp.path()), &old.ciphertext));
    let rotated = store(
        &c,
        &env(&[(KEY_VAR, k2.as_str()), (PREVIOUS_KEY_VAR, k1.as_str())]),
    );
    assert_eq!(read(&rotated, "one"), long);
    assert_eq!(read(&rotated, "two"), "second");
    let state = State::open(&tmp.path().join("state.db")).unwrap();
    let new = state.secret_row("one").unwrap().unwrap();
    assert_eq!(hex(&new.key_id), key_id(&k2));
    assert_eq!(new.stamp, old.stamp, "the stamp is kept");
    let bytes = db_bytes(tmp.path());
    assert!(!contains(&bytes, &old.ciphertext), "old ciphertext left");
    assert!(!contains(&bytes, &old.key_id), "old key_id left");
    // The previous key is no longer needed.
    let after = store(&c, &env(&[(KEY_VAR, k2.as_str())]));
    assert_eq!(read(&after, "two"), "second");
}

/// REQ: OPS-014 (AC6) — `wrendns secrets rotate-key`: a crash after `secrets.key.new` is written
/// leaves the old key in use (the new one goes at the next start); a crash after the
/// re-encryption commits finishes the rename at the next start; a whole rotation leaves no
/// ciphertext under the old key in the file or the WAL.
#[test]
fn ops_014_rotate_key_crash_safe() {
    let tmp = tempfile::tempdir().unwrap();
    let c = cfg_in(tmp.path());
    let none = env(&[]);
    let s = store(&c, &none);
    let long = "y".repeat(300);
    put(&s, "git", &long);
    drop(s);
    let first = std::fs::read_to_string(tmp.path().join(KEY_FILE)).unwrap();
    let new_file = tmp.path().join(NEW_KEY_FILE);

    // 1. Crashed before re-encrypting.
    rotate_key(&c, &none, Until::NewKeyWritten).unwrap();
    assert!(new_file.exists());
    let s = store(&c, &none);
    assert_eq!(read(&s, "git"), long);
    assert!(!new_file.exists(), "the unused new key went");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(KEY_FILE)).unwrap(),
        first
    );
    drop(s);

    // 2. Crashed after the commit, before the rename.
    let r = rotate_key(&c, &none, Until::Committed).unwrap();
    assert_eq!(r.reencrypted, 1);
    assert!(new_file.exists());
    let s = store(&c, &none);
    assert_eq!(read(&s, "git"), long);
    assert!(!new_file.exists(), "renamed into place");
    assert_eq!(hex(&s.keys().unwrap().current.key_id()), r.to);
    drop(s);

    // 3. A whole rotation.
    let state = State::open(&tmp.path().join("state.db")).unwrap();
    let before = state.secret_row("git").unwrap().unwrap();
    drop(state);
    let r = rotate_key(&c, &none, Until::Done).unwrap();
    assert_eq!((r.reencrypted, r.skipped), (1, 0));
    assert!(!new_file.exists());
    let s = store(&c, &none);
    assert_eq!(read(&s, "git"), long);
    assert_eq!(hex(&s.keys().unwrap().current.key_id()), r.to);
    let bytes = db_bytes(tmp.path());
    assert!(!contains(&bytes, &before.ciphertext), "old ciphertext left");
    assert!(!contains(&bytes, &before.key_id), "old key_id left");

    // Never under a running server.
    let running = crate::datadir::lock(tmp.path(), std::time::Duration::ZERO).unwrap();
    let err = rotate_key(&c, &none, Until::Done).unwrap_err();
    assert!(err.contains("stop it first"), "{err}");
    drop(running);
    // A key from the environment isn't rotated here.
    let k = NodeKey::generate().unwrap();
    let err = rotate_key(&c, &env(&[(KEY_VAR, k.as_str())]), Until::Done).unwrap_err();
    assert!(err.contains("PREVIOUS_KEY"), "{err}");
}

/// REQ: OPS-014 (AC9) — an integration whose stored secret can't be read on this node says it
/// isn't configured, and why: not stored, another key's, damaged, the store locked, or a resolver
/// pod. An alert destination's test fails that way before anything is sent.
#[tokio::test]
#[allow(clippy::many_single_char_names)] // a store per node, an error per case
async fn ops_014_unreadable_secret_integration_not_configured() {
    let tmp = tempfile::tempdir().unwrap();
    let c = cfg_in(tmp.path());
    let k1 = NodeKey::generate().unwrap();
    let s = store(&c, &env(&[(KEY_VAR, k1.as_str())]));
    put(&s, "ntfy", "tk_1");
    put(&s, "other", "x");
    let name = wrendns_config::SafeString::new("ntfy").unwrap();
    let resolved = Credential::of(None, Some(&name))
        .resolve(Some(&s))
        .unwrap()
        .unwrap();
    assert_eq!(
        (resolved.value.expose(), resolved.source),
        ("tk_1", Source::Stored)
    );
    // Another key: "ntfy" is unreadable here (the other row is re-entered, so the store isn't
    // locked).
    let k2 = NodeKey::generate().unwrap();
    let other = store(&c, &env(&[(KEY_VAR, k2.as_str())]));
    let fresh = wrendns_store::state::State::open(&tmp.path().join("state.db")).unwrap();
    let row = fresh.secret_row("other").unwrap().unwrap();
    let keys = other.keys().unwrap();
    let sealed = store::seal(&keys.current, &row.kind, &row.name, row.stamp, &value("x")).unwrap();
    fresh
        .put_secret_row(
            &wrendns_store::state::SecretRow {
                key_id: sealed.key_id,
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext,
                ..row
            },
            1,
        )
        .unwrap();
    other.load_now();
    assert_eq!(other.status().state, StoreState::Ready);
    let e = Credential::of(None, Some(&name))
        .resolve(Some(&other))
        .unwrap_err();
    assert!(
        e.starts_with("not configured: secret `ntfy` can't be read on this node (")
            && e.contains("a key this node doesn't have"),
        "{e}"
    );
    let missing = wrendns_config::SafeString::new("gone").unwrap();
    let e = Credential::of(None, Some(&missing))
        .resolve(Some(&other))
        .unwrap_err();
    assert!(e.contains("no secret of that name"), "{e}");

    let d: wrendns_config::AlertDestination = toml::from_str(
        r#"
name = "phone"
type = "ntfy"
url = "https://ntfy.invalid/topic"
token_ref = "ntfy"
"#,
    )
    .unwrap();
    let e = crate::alerts::send_test(&d, "pi", &other)
        .await
        .unwrap_err();
    assert!(e.starts_with("not configured: secret `ntfy`"), "{e}");

    let pod_dir = tempfile::tempdir().unwrap();
    let mut pod = cfg_in(pod_dir.path());
    pod.cluster.ephemeral = true;
    let p = store(&pod, &env(&[]));
    let e = Credential::of(None, Some(&name))
        .resolve(Some(&p))
        .unwrap_err();
    assert!(e.contains("full members"), "{e}");
    // A file still wins, and is read as before.
    let f = tmp.path().join("token");
    std::fs::write(&f, " from-file \n").unwrap();
    let fp = wrendns_config::SafeString::new(f.to_str().unwrap()).unwrap();
    let r = Credential::of(Some(&fp), Some(&name))
        .resolve(Some(&p))
        .unwrap()
        .unwrap();
    assert_eq!((r.value.expose(), r.source), ("from-file", Source::File));
}

/// REQ: OPS-014, NFR-005 (AC11) — a value prints as `<redacted>` (`Debug`, `Display`, inside a
/// resolved credential), and neither a key nor the store's `Debug` shows key material.
#[test]
#[allow(clippy::many_single_char_names)] // one of each thing that must not show a value
fn ops_014_secret_value_debug_redacted() {
    let v = value("hunter2-planted");
    assert_eq!(format!("{v:?}"), "<redacted>");
    assert_eq!(format!("{v}"), "<redacted>");
    let r = credential::Resolved {
        value: value("hunter2-planted"),
        source: Source::Stored,
    };
    assert!(!format!("{r:?}").contains("hunter2"), "{r:?}");
    let text = NodeKey::generate().unwrap();
    let k = NodeKey::parse(&text, KeySource::Env).unwrap();
    let body = text.trim_start_matches("ttsk1:");
    assert!(!format!("{k:?}").contains(body));
    let tmp = tempfile::tempdir().unwrap();
    let s = store(&cfg_in(tmp.path()), &env(&[(KEY_VAR, text.as_str())]));
    put(&s, "x", "hunter2-planted");
    let d = format!("{s:?} {:?} {:?}", s.keys().unwrap(), s.status());
    assert!(!d.contains(body) && !d.contains("hunter2"), "{d}");
}

/// A `tracing` writer into a shared buffer.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// REQ: OPS-014 (AC12) — the key variables never show: not in `config check --print` (even with
/// `--show-secrets`), not in a support package, not in the log of loading, rotating or using the
/// store, and not in any `Debug`.
#[test]
fn ops_014_key_vars_never_logged() {
    let text = NodeKey::generate().unwrap();
    let previous = NodeKey::generate().unwrap();
    let (body, prev_body) = (
        text.trim_start_matches("ttsk1:").to_owned(),
        previous.trim_start_matches("ttsk1:").to_owned(),
    );
    let leaks = |s: &str| s.contains(&body) || s.contains(&prev_body);
    let tmp = tempfile::tempdir().unwrap();
    let loaded = wrendns_config::Loader::new()
        .toml_str(
            "t.toml",
            format!("[node]\ndata_dir = \"{}\"\n", tmp.path().display()),
        )
        .env(vec![
            (KEY_VAR.to_owned(), text.to_string()),
            (PREVIOUS_KEY_VAR.to_owned(), previous.to_string()),
        ])
        .load()
        .unwrap();
    assert!(
        !loaded.warnings.iter().any(|w| leaks(w)),
        "{:?}",
        loaded.warnings
    );
    let cfg = loaded.config;
    for show in [false, true] {
        let printed = crate::printed_config(&cfg, show).unwrap();
        assert!(!leaks(&printed), "{printed}");
    }
    // Captured on this thread; tried again if another test's thread registered the log's call
    // sites first (tracing caches their interest), so the check never passes on an empty log.
    let mut log = String::new();
    for _ in 0..5 {
        let out = Captured::default();
        let w = out.clone();
        let sub = tracing_subscriber::fmt()
            .with_writer(move || w.clone())
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::with_default(sub, || {
            tracing::callsite::rebuild_interest_cache();
            let e = env(&[
                (KEY_VAR, text.as_str()),
                (PREVIOUS_KEY_VAR, previous.as_str()),
            ]);
            let s = store(&cfg, &e);
            put(&s, "x", "v");
            let _ = format!("{s:?} {:?}", s.keys().unwrap());
            let bad = env(&[(KEY_VAR, "ttsk1:not-base64!")]);
            let _ = store(&cfg, &bad).keys();
        });
        log = String::from_utf8_lossy(&out.0.lock().unwrap()).into_owned();
        assert!(!leaks(&log), "{log}");
        if log.contains("secrets key loaded") && log.contains("secrets store locked") {
            break;
        }
    }
    assert!(
        log.contains("secrets key loaded") && log.contains("secrets store locked"),
        "{log}"
    );
    let req = wrendns_api::model::SupportPackageRequest {
        level: Some("none".into()),
        reveal: Vec::new(),
        query_sample: 0,
        keep_map: false,
        cluster: false,
    };
    let (pkg, _) = crate::support::offline(&cfg, &req).unwrap();
    let files = wrendns_support::archive::read_tar_gz(&pkg.archive).unwrap();
    assert_ne!(files.len(), 0);
    for f in files {
        assert!(!leaks(&String::from_utf8_lossy(&f.data)), "{}", f.path);
    }
}

/// REQ: OPS-014 (AC13) — values to store: trimmed; empty, control characters (a line break, a
/// tab, NUL), over 8 KiB, and the redaction marker refused; names and kinds checked.
#[test]
fn ops_014_control_chars_and_empty_refused() {
    let v = |s: &str| SecretValue::new(Kind::Text, Zeroizing::new(s.to_owned()));
    assert_eq!(v("  tok en \n").unwrap().expose(), "tok en");
    for (bad, why) in [
        ("", ValueError::Empty),
        ("   \n\t ", ValueError::Empty),
        ("a\nb", ValueError::Control),
        ("a\tb", ValueError::Control),
        ("a\u{0}b", ValueError::Control),
        ("a\u{7f}b", ValueError::Control),
        ("<redacted>", ValueError::Marker),
    ] {
        assert_eq!(v(bad).unwrap_err(), why, "{bad:?}");
    }
    assert!(v(&"a".repeat(8 * 1024)).is_ok());
    assert_eq!(
        v(&"a".repeat(8 * 1024 + 1)).unwrap_err(),
        ValueError::TooLong
    );
    assert_eq!(Kind::parse("text").unwrap(), Kind::Text);
    assert_eq!(Kind::parse("pem").unwrap(), Kind::Pem);
    assert_eq!(Kind::parse("blob").unwrap_err(), ValueError::Kind);
    let tmp = tempfile::tempdir().unwrap();
    let s = store(&cfg_in(tmp.path()), &env(&[]));
    for bad in ["", "Upper", "a b", "../x", "-x"] {
        assert!(
            matches!(
                s.put(bad, Kind::Text, &value("v"), 0, "root", "local", 1),
                Err(StoreError::Invalid(ValueError::Name))
            ),
            "{bad}"
        );
    }
}

/// REQ: OPS-014 (ADR-903 §2) — at most 128 live secrets (replacing one is fine), stamps only go
/// up, a delete leaves a tombstone, and the head changes with every change but holds no value.
#[test]
fn ops_014_limits_tombstones_and_head() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(&cfg_in(tmp.path()), &env(&[]));
    for i in 0..store::MAX_SECRETS {
        put(&s, &format!("s{i}"), "v");
    }
    assert!(matches!(
        s.put("one-more", Kind::Text, &value("v"), 0, "root", "local", 1),
        Err(StoreError::Full)
    ));
    put(&s, "s0", "replaced");
    let (h1, d1) = s.head();
    let gone = s.delete("s1", 0, "root", 200).unwrap().unwrap();
    assert!(gone.deleted && gone.stamp > h1);
    assert!(s.delete("s1", 0, "root", 200).unwrap().is_none());
    let (h2, d2) = s.head();
    assert!(h2 > h1 && d2 != d1);
    assert!(!s.exists("s1"));
    put(&s, "one-more", "fits now");
    assert!(
        s.head().0 > h2,
        "a new value after a delete gets a new stamp"
    );
    assert_eq!(s.get("s1").unwrap_err(), store::Unavailable::NotSet);
    let st = State::open(&tmp.path().join("state.db")).unwrap();
    let tomb = st.secret_row("s1").unwrap().unwrap();
    assert!(tomb.deleted && tomb.ciphertext.is_empty() && tomb.key_id.is_empty());
    // The digest is over names, kinds and stamps only.
    let (_, d) = store::head_of(st.secret_rows().unwrap().iter());
    assert_eq!(d, s.head().1);
}

/// REQ: OPS-014, OBS-015 — `secrets_ephemeral` when secrets are stored in a data directory that
/// isn't kept (Helm persistence off), and only then.
#[test]
fn ops_014_ephemeral_data_dir_health() {
    let tmp = tempfile::tempdir().unwrap();
    let c = cfg_in(tmp.path());
    let s = SecretStore::with_env(&c, env(&[]), true, true);
    let _ = s.keys();
    assert!(health_reasons_of(&s).is_empty(), "nothing stored yet");
    put(&s, "x", "v");
    assert_eq!(health_reasons_of(&s), ["secrets_ephemeral"]);
}

/// REQ: OPS-014 (ADR-903 §2) — the readable check opens a file without reading it: a missing or
/// unreadable path, and one that isn't a regular file (a FIFO isn't waited on), aren't usable.
#[test]
fn ops_014_readable_check_opens_without_reading() {
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("token");
    std::fs::write(&f, "t").unwrap();
    assert!(credential::readable(f.to_str().unwrap()).is_ok());
    assert!(credential::readable(tmp.path().join("nope").to_str().unwrap()).is_err());
    let e = credential::readable(tmp.path().to_str().unwrap()).unwrap_err();
    assert!(e.contains("not a regular file"), "{e}");
}

/// REQ: OPS-014 (ADR-903 §4 `credentials`) — every credential field with its source and whether
/// this node can read it, and the warning for a reference to a secret this node doesn't store.
#[test]
fn ops_014_credential_fields_and_missing_references() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("ha.token");
    std::fs::write(&file, "t").unwrap();
    let cfg: Config = toml::from_str(&format!(
        r#"
[node]
data_dir = "{d}"
[[router]]
name = "unifi"
type = "unifi"
url = "https://192.168.1.1"
api_key_ref = "unifi"
[[router]]
name = "ha"
type = "home_assistant"
url = "http://ha:8123"
api_key_file = "{f}"
[[alerts.destination]]
name = "phone"
type = "ntfy"
url = "https://ntfy.sh/t"
token_ref = "ntfy"
"#,
        d = tmp.path().display(),
        f = file.display()
    ))
    .unwrap();
    let s = store(&cfg, &env(&[]));
    put(&s, "unifi", "k");
    let f = credential::fields(&cfg, Some(&s));
    let shown: Vec<(&str, &str, &str, bool)> = f
        .iter()
        .map(|x| {
            (
                x.entry.as_str(),
                x.field.as_str(),
                x.source.as_str(),
                x.readable.is_ok(),
            )
        })
        .collect();
    assert_eq!(
        shown,
        [
            ("unifi", "api_key", "stored", true),
            ("ha", "api_key", "file", true),
            ("phone", "token", "stored", false),
        ]
    );
    let w = credential::missing_references(&cfg, &s);
    assert_eq!(w.len(), 1);
    assert!(w[0].contains("`ntfy`"), "{w:?}");
    let mut out = Vec::new();
    assert!(cli::status(&cfg, env(&[]), &mut out).unwrap());
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("store: ready") && text.contains("unifi"),
        "{text}"
    );
    assert!(text.contains("NOT readable"), "{text}");
    assert!(!text.contains("ttsk1:"), "{text}");
}

/// REQ: OPS-014 — the key file is made whole or not at all: a leftover temporary file from a
/// crash is replaced, and an existing key is never replaced.
#[test]
fn ops_014_key_file_made_whole() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join(KEY_FILE);
    std::fs::write(tmp.path().join("secrets.key.tmp"), "ttsk1:trunc").unwrap();
    create_key_file(&file).unwrap();
    assert!(!tmp.path().join("secrets.key.tmp").exists());
    let first = std::fs::read_to_string(&file).unwrap();
    NodeKey::parse(&first, KeySource::DataDir(file.clone())).unwrap();
    create_key_file(&file).unwrap();
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        first,
        "never replaced"
    );
}

/// REQ: API-014 — the idempotency digest is keyed (another node's key gives another digest), and
/// its subkey isn't the store's.
#[test]
fn api_014_idempotency_digest_is_keyed() {
    let a = NodeKey::parse(&NodeKey::generate().unwrap(), KeySource::Env).unwrap();
    let b = NodeKey::parse(&NodeKey::generate().unwrap(), KeySource::Env).unwrap();
    let req = b"PUT /upstreams/x {\"headers\":{\"Authorization\":\"Bearer s3cret\"}}";
    assert_eq!(a.idempotency_digest(req), a.idempotency_digest(req));
    assert_ne!(a.idempotency_digest(req), b.idempotency_digest(req));
    assert_ne!(
        a.idempotency_digest(req),
        blake3::hash(req).to_hex().to_string()
    );
    assert_ne!(*a.subkey(AEAD_CONTEXT), *a.subkey(IDEMPOTENCY_CONTEXT));
}

/// A cluster row as a primary lists it, for a test that displaces a local row.
fn cluster_row(name: &str, v: &str, epoch: u64) -> super::store::Remote {
    super::store::Remote {
        name: name.into(),
        kind: "text".into(),
        stamp: wrendns_store::state::Stamp { epoch, seq: 1 },
        deleted: false,
        held: false,
        updated: 100,
        updated_by: "root".into(),
        value: Some(value(v)),
    }
}

/// REQ: OPS-014 (AC6; CLU-015 ADR-917 point 4) — a shadow row is sealed under the node key like a
/// row: a rotation re-encrypts it, nothing under the old key stays in the file, and the purge
/// that restores it reads the same value.
#[test]
fn ops_014_shadow_rows_follow_key_rotation() {
    let tmp = tempfile::tempdir().unwrap();
    let c = cfg_in(tmp.path());
    let none = env(&[]);
    let s = store(&c, &none);
    put(&s, "sh", "shadow-value-44");
    s.apply_remote(&[cluster_row("sh", "cluster-over-shadow", 1)], 1, true, 100)
        .unwrap();
    assert_eq!(s.status().shadows, vec!["sh".to_owned()]);
    let state = State::open(&tmp.path().join("state.db")).unwrap();
    let before = state.secret_shadows().unwrap().remove(0);
    drop(state);
    drop(s);
    rotate_key(&c, &none, Until::Done).unwrap();
    let state = State::open(&tmp.path().join("state.db")).unwrap();
    let after = state.secret_shadows().unwrap().remove(0);
    drop(state);
    assert_ne!(
        after.key_id, before.key_id,
        "re-encrypted under the new key"
    );
    assert_eq!(after.stamp, before.stamp, "the stamp is kept");
    let bytes = db_bytes(tmp.path());
    assert!(!contains(&bytes, &before.ciphertext), "old ciphertext left");
    assert!(!contains(&bytes, &before.key_id), "old key_id left");
    let s = store(&c, &none);
    assert_eq!(s.purge_cluster().unwrap(), (0, 1));
    assert_eq!(read(&s, "sh"), "shadow-value-44");
}

/// REQ: OPS-014 (AC6; CLU-015 ADR-917 point 4) — a previous key re-encrypts the shadow rows at
/// the start too, in the same step as the rows.
#[test]
fn ops_014_shadow_reencrypted_at_start() {
    let tmp = tempfile::tempdir().unwrap();
    let c = cfg_in(tmp.path());
    let k1 = NodeKey::generate().unwrap();
    let k2 = NodeKey::generate().unwrap();
    let s = store(&c, &env(&[(KEY_VAR, k1.as_str())]));
    put(&s, "sh", "shadow-value-45");
    s.apply_remote(&[cluster_row("sh", "cluster-under-k1", 1)], 1, true, 100)
        .unwrap();
    drop(s);
    let state = State::open(&tmp.path().join("state.db")).unwrap();
    let old = state.secret_shadows().unwrap().remove(0);
    drop(state);
    let rotated = store(
        &c,
        &env(&[(KEY_VAR, k2.as_str()), (PREVIOUS_KEY_VAR, k1.as_str())]),
    );
    let _ = rotated.keys().unwrap();
    let state = State::open(&tmp.path().join("state.db")).unwrap();
    let new = state.secret_shadows().unwrap().remove(0);
    drop(state);
    assert_eq!(
        hex(&new.key_id),
        key_id(k2.as_str()),
        "under the current key"
    );
    assert_eq!(new.stamp, old.stamp, "the stamp is kept");
    let bytes = db_bytes(tmp.path());
    assert!(!contains(&bytes, &old.ciphertext), "old ciphertext left");
    assert!(!contains(&bytes, &old.key_id), "old key_id left");
    assert_eq!(rotated.purge_cluster().unwrap(), (0, 1));
    assert_eq!(read(&rotated, "sh"), "shadow-value-45");
}

const PEM_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIPlantedKeyBytes0123456789abcdefghijkLMNOP\nQRSTUV+/=\n-----END PRIVATE KEY-----";
const PEM_CERT: &str =
    "-----BEGIN CERTIFICATE-----\nMIIBplantedcertbytes0123456789\n-----END CERTIFICATE-----";

fn pem(s: &str) -> Result<SecretValue, ValueError> {
    SecretValue::new(Kind::Pem, Zeroizing::new(s.to_owned()))
}

/// REQ: CLD-920 (ADR-1097 point 1) — the `pem` kind takes PEM blocks only, with their line breaks,
/// within the 8 KiB limit; anything else is refused with the reason; the value prints `<redacted>`.
#[test]
fn cld_920_pem_kind_takes_pem_blocks_only() {
    let chain = format!("{PEM_CERT}\n\n{PEM_KEY}\n");
    let v = pem(&chain).unwrap();
    assert_eq!(v.expose(), chain.trim(), "line breaks kept, ends trimmed");
    assert_eq!(format!("{v:?} {v}"), "<redacted> <redacted>");
    assert!(pem(&chain.replace('\n', "\r\n")).is_ok(), "CRLF files");
    for (bad, why) in [
        ("", ValueError::Empty),
        ("   \n ", ValueError::Empty),
        ("plain text", ValueError::NotPem),
        ("-----BEGIN CERTIFICATE-----\nAAAA", ValueError::NotPem),
        (
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END PRIVATE KEY-----",
            ValueError::NotPem,
        ),
        (
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
            ValueError::NotPem,
        ),
        (
            "-----BEGIN CERTIFICATE-----\nAA AA\n-----END CERTIFICATE-----",
            ValueError::NotPem,
        ),
        (
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\nextra text",
            ValueError::NotPem,
        ),
        (
            "-----BEGIN CERTIFICATE-----\nAA\u{0}AA\n-----END CERTIFICATE-----",
            ValueError::NotPem,
        ),
        ("<redacted>", ValueError::NotPem),
    ] {
        assert_eq!(pem(bad).unwrap_err(), why, "{bad:?}");
    }
    // A block of exactly `n` bytes: full 64-character lines, then one shorter line.
    let big = |n: usize| {
        let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
        let rest = n - s.len() - "-----END CERTIFICATE-----".len();
        for _ in 0..rest / 65 {
            s.push_str(&"A".repeat(64));
            s.push('\n');
        }
        s.push_str(&"A".repeat(rest % 65 - 1));
        s.push('\n');
        s.push_str("-----END CERTIFICATE-----");
        s
    };
    assert_eq!(big(8 * 1024).len(), 8 * 1024);
    assert!(pem(&big(8 * 1024)).is_ok());
    assert_eq!(pem(&big(8 * 1024 + 1)).unwrap_err(), ValueError::TooLong);
}

/// REQ: CLD-920 (ADR-1097 point 1) — a `pem` secret is stored encrypted as a row of kind `pem`,
/// but a credential field can't be given it (so it can't be sent to another service), and a
/// backup export leaves it out.
#[test]
fn cld_920_pem_is_stored_but_never_handed_out() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(&cfg_in(tmp.path()), &env(&[]));
    put(&s, "plain", "token");
    s.put(
        "loc.key",
        Kind::Pem,
        &pem(PEM_KEY).unwrap(),
        0,
        "root",
        "local",
        100,
    )
    .unwrap();
    assert!(s.exists("loc.key"));
    assert_eq!(
        s.get("loc.key").unwrap_err(),
        super::store::Unavailable::WrongKind
    );
    assert_eq!(read(&s, "plain"), "token");
    let e = s.export_rows().unwrap();
    assert_eq!(e.rows.len(), 1, "only the text secret is exported");
    assert_eq!(e.rows[0].name, "plain");
    // Left out on purpose, so it is not counted as an unreadable (damaged) row.
    assert_eq!((e.unreadable, e.pem_kept), (0, 1));
    // `readable` agrees with `get` for a credential field.
    assert_eq!(
        s.readable("loc.key").unwrap_err(),
        super::store::Unavailable::WrongKind
    );
    assert!(s.readable("plain").is_ok());
    let shown = format!("{s:?} {:?}", s.status());
    assert!(!shown.contains("PlantedKeyBytes"), "{shown}");
}

/// REQ: CLU-015, CLD-920 - a `pem` row goes through replication like a text row: the primary's
/// page carries it with its value, the replica re-encrypts it under its own key as kind `pem`,
/// still refuses it to a credential field, leaves it out of its own backup export, and passes it
/// on in its own page (so a later primary has it).
#[test]
fn cld_920_pem_row_replicates_to_a_replica() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let primary = store(&cfg_in(a.path()), &env(&[]));
    let replica = store(&cfg_in(b.path()), &env(&[]));
    put(&primary, "plain", "token");
    primary
        .put(
            "loc.key",
            Kind::Pem,
            &pem(PEM_KEY).unwrap(),
            1,
            "root",
            "cluster",
            100,
        )
        .unwrap();
    let page = primary.export_page(None, 1 << 20).unwrap();
    let sent = page.items.iter().find(|r| r.name == "loc.key").unwrap();
    assert_eq!(sent.kind, "pem");
    assert_eq!(sent.value.as_ref().unwrap().expose(), PEM_KEY);
    replica.apply_remote(&page.items, 1, true, 100).unwrap();
    assert!(replica.exists("loc.key"));
    let info = replica.status();
    let row = info.secrets.iter().find(|r| r.name == "loc.key").unwrap();
    assert_eq!(row.kind, "pem");
    assert_eq!(row.health, super::store::RowHealth::Readable);
    assert_eq!(
        replica.get("loc.key").unwrap_err(),
        super::store::Unavailable::WrongKind
    );
    assert_eq!(read(&replica, "plain"), "token");
    let e = replica.export_rows().unwrap();
    assert_eq!((e.rows.len(), e.pem_kept), (1, 1));
    let again = replica.export_page(None, 1 << 20).unwrap();
    let relayed = again.items.iter().find(|r| r.name == "loc.key").unwrap();
    assert_eq!(relayed.value.as_ref().unwrap().expose(), PEM_KEY);
    assert_eq!(
        again.head, page.head,
        "the replica holds what the primary does"
    );
}

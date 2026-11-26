//! REQ: API-007, OPS-014 (T23.9, ADR-903 §8) — backups that carry the stored secrets under a
//! passphrase: the archive's format, a restore on another node, and every way it must refuse.

use std::collections::HashMap;
use std::sync::Arc;

use super::cli::{Source, create as cli_create, restore as cli_restore};
use super::*;
use crate::secrets::SecretStore;
use crate::secrets::store::EnvFn;
use crate::secrets::value::Kind;
use crate::secrets::{SecretValue, process_env};

/// A change to a recorded key derivation.
type Edit = fn(&mut passphrase::Kdf);

const PASS: &str = "correct horse battery staple";
const UNIFI: &str = "planted-unifi-key-7d21c4";
const NTFY: &str = "planted-ntfy-token-90ab";

fn env(pairs: &[(&str, &str)]) -> EnvFn {
    let m: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    Arc::new(move |k: &str| m.get(k).cloned())
}

fn value(v: &str) -> SecretValue {
    SecretValue::new(Kind::Text, Zeroizing::new(v.to_owned())).unwrap()
}

fn config_in(root: &Path, extra: &str) -> (PathBuf, wrendns_config::Config) {
    let data = root.join("data");
    fs::create_dir_all(&data).unwrap();
    let conf = root.join("etc/wrendns.toml");
    fs::create_dir_all(conf.parent().unwrap()).unwrap();
    fs::write(
        &conf,
        format!(
            "[node]\nname = \"pi\"\ndata_dir = \"{}\"\n{extra}",
            data.display()
        ),
    )
    .unwrap();
    let cfg = wrendns_config::Loader::new()
        .file(&conf)
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    (conf, cfg)
}

/// A node holding `unifi` and `ntfy` (stamped in epoch 3), and one deleted secret.
fn node_with_secrets(root: &Path) -> (Vec<PathBuf>, wrendns_config::Config) {
    let (conf, cfg) = config_in(root, "");
    let store = SecretStore::with_env(&cfg, env(&[]), true, false);
    for (n, v) in [
        ("unifi", UNIFI),
        ("ntfy", NTFY),
        ("gone", "deleted-value-1"),
    ] {
        store
            .put(n, Kind::Text, &value(v), 3, "root", "local", 1_700_000_000)
            .unwrap();
    }
    store.delete("gone", 3, "root", 1_700_000_100).unwrap();
    (vec![conf], cfg)
}

fn export_of(cfg: &wrendns_config::Config, pass: &str) -> SecretsExport {
    let store = SecretStore::read_only(cfg, env(&[]));
    store.load_now();
    let e = store.export_rows().unwrap();
    SecretsExport {
        passphrase: Zeroizing::new(pass.to_owned()),
        rows: e.rows,
        unreadable: e.unreadable,
        pem_kept: e.pem_kept,
    }
}

/// The whole tar stream of an archive, decompressed.
fn raw_tar(archive: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    zstd::stream::Decoder::new(BufReader::new(File::open(archive).unwrap()))
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// A copy of `archive` with the manifest changed by `edit` (every entry kept as it is).
fn rewrite(archive: &Path, out: &Path, edit: impl FnOnce(&mut Manifest)) {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let m = read_archive(archive, |name, r| {
        let mut b = Vec::new();
        r.read_to_end(&mut b).map_err(|e| e.to_string())?;
        files.push((name.to_owned(), b));
        Ok(())
    })
    .unwrap();
    let mut m2 = m;
    edit(&mut m2);
    let mut enc =
        zstd::stream::Encoder::new(BufWriter::new(File::create(out).unwrap()), 3).unwrap();
    enc.include_checksum(true).unwrap();
    let mut tar = TarWriter {
        out: enc,
        entries: Vec::new(),
    };
    for (name, bytes) in &files {
        tar.entry_bytes(name, bytes).unwrap();
    }
    m2.entries = tar.entries.clone();
    tar.bytes("manifest.json", &serde_json::to_vec_pretty(&m2).unwrap())
        .unwrap();
    let mut w = tar.finish().unwrap().finish().unwrap();
    w.flush().unwrap();
}

fn needle_forms(v: &str) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    let hex = v.bytes().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    vec![
        v.as_bytes().to_vec(),
        base64::engine::general_purpose::STANDARD
            .encode(v)
            .into_bytes(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(v)
            .into_bytes(),
        hex.into_bytes(),
    ]
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A restoring node's store, to read the secrets back.
fn restored_store(root: &Path, extra: &str, e: EnvFn) -> (SecretStore, PathBuf) {
    let (conf, cfg) = config_in(root, extra);
    let _ = conf;
    (
        SecretStore::with_env(&cfg, e, false, false),
        root.join("data"),
    )
}

fn plain_keys(e: &dyn Fn(&str) -> Option<String>) -> RestoreKeys<'_> {
    RestoreKeys { cfg: None, env: e }
}

// REQ: API-007 (AC1, AC5, AC8) — without a passphrase nothing of a secret is in the archive (raw,
// base64 or hex, in the compressed file or the tar stream), the manifest says how many were left
// out, and the format stays version 1.
#[test]
fn api_007_backup_without_passphrase_omits_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(tmp.path());
    let out = tmp.path().join("b.ttbk");
    let c = create(&files, &cfg, false, &out).unwrap();
    assert!(!c.secrets.included);
    assert_eq!(c.secrets.count, 2, "two live secrets were left out");
    let m = show(&out).unwrap();
    assert_eq!(m.version, 1, "no secrets: still version 1");
    let s = m.secrets.as_ref().unwrap();
    assert!(!s.included && s.count == 2 && s.omitted_reason.as_deref() == Some("no passphrase"));
    assert!(!paths(&m).contains(&"data/secrets.enc"));
    let (compressed, tar) = (fs::read(&out).unwrap(), raw_tar(&out));
    for v in [UNIFI, NTFY, "deleted-value-1"] {
        for n in needle_forms(v) {
            assert!(!contains(&compressed, &n) && !contains(&tar, &n), "{v}");
        }
    }
}

fn paths(m: &Manifest) -> Vec<&str> {
    m.entries.iter().map(|e| e.path.as_str()).collect()
}

// REQ: API-007 (AC8) — with a passphrase the values are in the archive only as ciphertext: the
// planted values (raw, base64, hex) and the passphrase appear nowhere, and `secrets.enc` is
// version 2.
#[test]
fn api_007_planted_secret_absent_from_plaintext() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(tmp.path());
    let out = tmp.path().join("b.ttbk");
    let export = export_of(&cfg, PASS);
    assert_eq!(export.rows.len(), 2);
    let c = create_with(&files, &cfg, false, &out, Some(&export)).unwrap();
    assert!(c.secrets.included && c.secrets.count == 2);
    let m = show(&out).unwrap();
    assert_eq!(m.version, 2);
    assert!(paths(&m).contains(&"data/secrets.enc"));
    let (compressed, tar) = (fs::read(&out).unwrap(), raw_tar(&out));
    for v in [UNIFI, NTFY, PASS] {
        for n in needle_forms(v) {
            assert!(!contains(&compressed, &n), "{v} in the file");
            assert!(!contains(&tar, &n), "{v} in the tar stream");
        }
    }
    // The manifest records the cost, the cipher, a nonce and an id: never the key or the passphrase.
    let s = m.secrets.unwrap();
    let k = s.kdf.unwrap();
    assert_eq!(
        (k.alg.as_str(), k.m_kib, k.t, k.p),
        ("argon2id", 19_456, 2, 1)
    );
    assert_eq!(s.aead.as_deref(), Some("chacha20-poly1305"));
    assert!(s.nonce.is_some() && s.backup_id.is_some());
}

// REQ: API-007 (AC5) — a passphrase with nothing stored makes no `secrets.enc`: version 1.
#[test]
fn api_007_no_secrets_stays_v1() {
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = config_in(tmp.path(), "");
    let files = vec![files];
    let export = export_of(&cfg, PASS);
    assert!(export.rows.is_empty());
    let out = tmp.path().join("b.ttbk");
    let c = create_with(&files, &cfg, false, &out, Some(&export)).unwrap();
    assert!(!c.secrets.included);
    let m = show(&out).unwrap();
    assert_eq!(m.version, 1);
    assert_eq!(
        m.secrets.unwrap().omitted_reason.as_deref(),
        Some("none stored")
    );
}

// REQ: API-007 (AC2, AC11) — a backup with a passphrase restores on another node: the values come
// back under that node's own key (a new data-directory key here), re-stamped from the start of
// epoch 0 as local rows, with their update time and author kept.
#[test]
fn api_007_roundtrip_with_passphrase() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
    let out = tmp.path().join("b.ttbk");
    create_with(&files, &cfg, false, &out, Some(&export_of(&cfg, PASS))).unwrap();

    let new = tmp.path().join("new");
    let none = env(&[]);
    let r = restore_with(
        &out,
        Some(&new.join("data")),
        Some(&new.join("etc")),
        false,
        &SecretsMode::Passphrase(Zeroizing::new(PASS.to_owned())),
        &plain_keys(&*none),
    )
    .unwrap();
    let rs = r.secrets.unwrap();
    assert_eq!(rs.count, 2);
    assert!(rs.key_source.ends_with("secrets.key"), "{}", rs.key_source);
    assert_eq!(rs.key_id.len(), 16);
    assert!(
        !new.join("data/secrets.enc").exists(),
        "the encrypted file isn't kept"
    );
    assert!(new.join("data/secrets.key").exists());
    assert_eq!(
        fs::read_dir(new.join("data"))
            .unwrap()
            .filter(|e| {
                let n = e.as_ref().unwrap().file_name();
                let n = n.to_string_lossy().into_owned();
                n.ends_with("-wal") || n.ends_with("-shm")
            })
            .count(),
        0,
        "no write-ahead log left behind"
    );

    // The restoring node reads them under its own key.
    let (store, _) = restored_store(&new, "", env(&[]));
    store.load_now();
    assert_eq!(store.get("unifi").unwrap().expose(), UNIFI);
    assert_eq!(store.get("ntfy").unwrap().expose(), NTFY);
    assert!(
        store.get("gone").is_err(),
        "a deleted secret isn't restored"
    );
    // Re-stamped (AC11): epoch 0, from 1, as local rows; the old stamps (epoch 3) are gone.
    let state = wrendns_store::state::State::open(&new.join("data/state.db")).unwrap();
    let mut rows = state.secret_rows().unwrap();
    rows.sort_by_key(|r| r.stamp);
    assert_eq!(
        rows.iter()
            .map(|r| (r.stamp.epoch, r.stamp.seq))
            .collect::<Vec<_>>(),
        [(0, 1), (0, 2)]
    );
    assert!(
        rows.iter()
            .all(|r| r.origin == "local" && !r.deleted && r.updated_by == "root")
    );
    assert!(rows.iter().all(|r| r.updated == 1_700_000_000));
    // The next change on the restored node goes on from there.
    assert_eq!(state.next_secret_stamp(0).unwrap().seq, 3);
}

// REQ: API-007 (AC11) — restoring over a node that already has stamps in a later epoch: the
// restored rows are not below what the node holds (the counter is the database's).
#[test]
fn api_007_restore_restamps() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
    let out = tmp.path().join("b.ttbk");
    create_with(&files, &cfg, false, &out, Some(&export_of(&cfg, PASS))).unwrap();
    // The source stamped in epoch 3; what comes back doesn't carry that epoch.
    let src = wrendns_store::state::State::open(&tmp.path().join("old/data/state.db")).unwrap();
    assert!(
        src.secret_rows()
            .unwrap()
            .iter()
            .all(|r| r.stamp.epoch == 3)
    );
    drop(src);
    let new = tmp.path().join("new");
    let none = env(&[]);
    restore_with(
        &out,
        Some(&new.join("data")),
        Some(&new.join("etc")),
        false,
        &SecretsMode::Passphrase(Zeroizing::new(PASS.to_owned())),
        &plain_keys(&*none),
    )
    .unwrap();
    let state = wrendns_store::state::State::open(&new.join("data/state.db")).unwrap();
    assert!(
        state
            .secret_rows()
            .unwrap()
            .iter()
            .all(|r| r.stamp.epoch == 0)
    );
}

// REQ: API-007 (AC3) — a wrong passphrase is "wrong passphrase or damaged archive", and nothing
// is moved: no file, no key.
#[test]
fn api_007_wrong_passphrase_moves_nothing() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
    let out = tmp.path().join("b.ttbk");
    create_with(&files, &cfg, false, &out, Some(&export_of(&cfg, PASS))).unwrap();
    let new = tmp.path().join("new");
    let none = env(&[]);
    let e = restore_with(
        &out,
        Some(&new.join("data")),
        Some(&new.join("etc")),
        false,
        &SecretsMode::Passphrase(Zeroizing::new("another passphrase!".to_owned())),
        &plain_keys(&*none),
    )
    .unwrap_err();
    assert_eq!(e, "wrong passphrase or damaged archive");
    let left: Vec<_> = fs::read_dir(new.join("data"))
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name())
                .filter(|n| n != "wrendns.lock")
                .collect()
        })
        .unwrap_or_default();
    assert!(left.is_empty(), "nothing moved or generated: {left:?}");
    assert_eq!(fs::read_dir(new.join("etc")).map_or(0, Iterator::count), 0);
    // Too short is refused too, before any key derivation.
    let e = restore_with(
        &out,
        Some(&new.join("data")),
        Some(&new.join("etc")),
        false,
        &SecretsMode::Passphrase(Zeroizing::new("short".to_owned())),
        &plain_keys(&*none),
    )
    .unwrap_err();
    assert!(e.contains("at least 12"), "{e}");
}

// REQ: API-007 (AC4) — a version 2 archive with no passphrase is refused before anything moves;
// `--skip-secrets` restores everything else and says how many were skipped.
#[test]
fn api_007_v2_without_passphrase_refused_unless_skip() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
    let out = tmp.path().join("b.ttbk");
    create_with(&files, &cfg, false, &out, Some(&export_of(&cfg, PASS))).unwrap();
    let new = tmp.path().join("new");
    let none = env(&[]);
    let e = restore_with(
        &out,
        Some(&new.join("data")),
        Some(&new.join("etc")),
        false,
        &SecretsMode::Unspecified,
        &plain_keys(&*none),
    )
    .unwrap_err();
    assert!(
        e.contains("--secrets-passphrase-file") && e.contains("--skip-secrets"),
        "{e}"
    );
    assert!(!new.join("data/state.db").exists() && !new.join("etc").exists());
    let r = restore_with(
        &out,
        Some(&new.join("data")),
        Some(&new.join("etc")),
        false,
        &SecretsMode::Skip,
        &plain_keys(&*none),
    )
    .unwrap();
    assert_eq!((r.secrets.is_none(), r.secrets_skipped), (true, 2));
    assert!(!new.join("data/secrets.enc").exists());
    assert!(!new.join("data/secrets.key").exists(), "no key was needed");
    let db = rusqlite::Connection::open(new.join("data/state.db")).unwrap();
    let n: i64 = db
        .query_row("SELECT count(*) FROM secrets", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

// REQ: API-007 (AC5) — an archive made before this task (version 1, a manifest with no `secrets`
// block) restores as it always did, with or without a passphrase given.
#[test]
fn api_007_v1_archive_still_restores() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
    let first = tmp.path().join("first.ttbk");
    create(&files, &cfg, false, &first).unwrap();
    let out = tmp.path().join("v1.ttbk");
    rewrite(&first, &out, |m| m.secrets = None);
    let m = show(&out).unwrap();
    assert_eq!((m.version, m.secrets.is_none()), (1, true));
    for mode in [
        SecretsMode::Unspecified,
        SecretsMode::Passphrase(Zeroizing::new(PASS.to_owned())),
        SecretsMode::Skip,
    ] {
        let new = tmp.path().join(format!("new-{}", rand_suffix(&mode)));
        let none = env(&[]);
        let r = restore_with(
            &out,
            Some(&new.join("data")),
            Some(&new.join("etc")),
            false,
            &mode,
            &plain_keys(&*none),
        )
        .unwrap();
        assert!(r.secrets.is_none() && r.secrets_skipped == 0);
        assert!(new.join("data/state.db").exists());
    }
}

fn rand_suffix(m: &SecretsMode) -> &'static str {
    match m {
        SecretsMode::Unspecified => "u",
        SecretsMode::Skip => "s",
        SecretsMode::Passphrase(_) => "p",
    }
}

// REQ: API-007 (AC5) — a manifest from an older build has no `secrets` field and reads as none.
#[test]
fn api_007_old_manifest_without_secrets_block_parses() {
    let json = r#"{"format":"telltale-backup","version":1,"telltale_version":"0.7.0","created":1,
        "node":"pi","data_dir":"/d","config_files":[],"includes_qlog":false,
        "cluster_member":false,"entries":[]}"#;
    let m: Manifest = serde_json::from_str(json).unwrap();
    assert!(m.secrets.is_none() && !m.has_secrets());
}

// REQ: API-007 (AC6) — the cost a manifest asks for is bounded on restore (m <= 256 MiB, t <= 10,
// p <= 8, a known algorithm, a salt) and refused before any derivation: a hostile archive can't
// make the node spend memory or time.
#[test]
fn api_007_kdf_params_bounded() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
    let first = tmp.path().join("first.ttbk");
    create_with(&files, &cfg, false, &first, Some(&export_of(&cfg, PASS))).unwrap();
    let cases: [(&str, Edit); 6] = [
        ("memory", |k| k.m_kib = 262_145),
        ("passes", |k| k.t = 11),
        ("lanes", |k| k.p = 9),
        ("zero", |k| k.t = 0),
        ("algorithm", |k| k.alg = "argon2d".into()),
        ("salt", |k| k.salt = "00".into()),
    ];
    for (what, edit) in cases {
        let bad = tmp.path().join(format!("bad-{what}.ttbk"));
        rewrite(&first, &bad, |m| {
            edit(m.secrets.as_mut().unwrap().kdf.as_mut().unwrap());
        });
        let new = tmp.path().join(format!("new-{what}"));
        let none = env(&[]);
        let started = std::time::Instant::now();
        let e = restore_with(
            &bad,
            Some(&new.join("data")),
            Some(&new.join("etc")),
            false,
            &SecretsMode::Passphrase(Zeroizing::new(PASS.to_owned())),
            &plain_keys(&*none),
        )
        .unwrap_err();
        assert!(e.contains("key derivation"), "{what}: {e}");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "{what}: refused before deriving"
        );
        assert!(!new.join("data/state.db").exists(), "{what}");
        // The same archive restores with --skip-secrets: the bound concerns only the derivation.
        restore_with(
            &bad,
            Some(&new.join("data")),
            Some(&new.join("etc")),
            false,
            &SecretsMode::Skip,
            &plain_keys(&*none),
        )
        .unwrap();
    }
    // The bounds themselves are accepted.
    let ok = passphrase::Kdf {
        alg: "argon2id".into(),
        version: 0x13,
        m_kib: 262_144,
        t: 10,
        p: 8,
        salt: "00".repeat(16),
    };
    passphrase::check_kdf(&ok).unwrap();
}

// REQ: API-007 (AC7) — one key derivation at a time: while one holds the slot a second backup
// with a passphrase is `Busy` (the API says 429), and the slot is free again after.
#[test]
fn api_007_concurrent_backup_kdf_429() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(tmp.path());
    let export = export_of(&cfg, PASS);
    let out = tmp.path().join("b.ttbk");
    let held = passphrase::kdf_slot_for_tests();
    let e = create_with(&files, &cfg, false, &out, Some(&export)).unwrap_err();
    assert_eq!(e, BackupError::Busy);
    assert!(!out.exists(), "no partial file");
    assert!(
        !out.with_extension("ttbk.partial").exists(),
        "no partial file"
    );
    drop(held);
    create_with(&files, &cfg, false, &out, Some(&export)).unwrap();
}

// REQ: API-007 (AC7) — and the same on restore.
#[test]
fn api_007_restore_kdf_slot_is_shared() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
    let out = tmp.path().join("b.ttbk");
    create_with(&files, &cfg, false, &out, Some(&export_of(&cfg, PASS))).unwrap();
    let held = passphrase::kdf_slot_for_tests();
    let new = tmp.path().join("new");
    let none = env(&[]);
    let e = restore_with(
        &out,
        Some(&new.join("data")),
        Some(&new.join("etc")),
        false,
        &SecretsMode::Passphrase(Zeroizing::new(PASS.to_owned())),
        &plain_keys(&*none),
    )
    .unwrap_err();
    assert!(e.contains("another key derivation"), "{e}");
    assert!(!new.join("data/state.db").exists());
    drop(held);
}

// REQ: API-007 (AC10, ADR-903 §8) — restore reads the node's key from the same places the server
// does: a key file named by the configuration (`-c`) wins over making one in the data directory,
// no `secrets.key` is generated, and it says which source and key it used.
#[test]
fn api_007_restore_uses_configured_key_source() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
    let out = tmp.path().join("b.ttbk");
    create_with(&files, &cfg, false, &out, Some(&export_of(&cfg, PASS))).unwrap();

    let new = tmp.path().join("new");
    let key_file = tmp.path().join("node.key");
    let key = crate::secrets::NodeKey::generate().unwrap();
    fs::write(&key_file, format!("{}\n", key.as_str())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let extra = format!("secrets_key_file = \"{}\"\n", key_file.display());
    let (_, new_cfg) = config_in(&new, &extra);
    let none = env(&[]);
    let r = restore_with(
        &out,
        Some(&new.join("data")),
        Some(&new.join("etc")),
        true,
        &SecretsMode::Passphrase(Zeroizing::new(PASS.to_owned())),
        &RestoreKeys {
            cfg: Some(&new_cfg),
            env: &*none,
        },
    )
    .unwrap();
    let rs = r.secrets.unwrap();
    assert_eq!(rs.key_source, key_file.display().to_string());
    assert!(!new.join("data/secrets.key").exists(), "nothing generated");
    let store = SecretStore::with_env(&new_cfg, env(&[]), false, false);
    store.load_now();
    assert_eq!(store.get("unifi").unwrap().expose(), UNIFI);
    assert_eq!(
        rs.key_id,
        store.status().key_id.unwrap(),
        "the key_id it printed is the node's"
    );

    // The environment's key is used when it's set, and a configured key that can't be read stops the
    // restore before anything moves (no key is made in its place).
    let other = tmp.path().join("other");
    let missing = format!(
        "secrets_key_file = \"{}\"\n",
        tmp.path().join("nope.key").display()
    );
    let (_, bad_cfg) = config_in(&other, &missing);
    let e = restore_with(
        &out,
        Some(&other.join("data")),
        Some(&other.join("etc")),
        true,
        &SecretsMode::Passphrase(Zeroizing::new(PASS.to_owned())),
        &RestoreKeys {
            cfg: Some(&bad_cfg),
            env: &*none,
        },
    )
    .unwrap_err();
    assert!(e.contains("nope.key"), "{e}");
    assert!(!other.join("data/secrets.key").exists());
    assert!(!other.join("data/state.db").exists());

    let env_key = crate::secrets::NodeKey::generate().unwrap();
    let third = tmp.path().join("third");
    let e3 = env(&[(crate::secrets::KEY_VAR, env_key.as_str())]);
    let r3 = restore_with(
        &out,
        Some(&third.join("data")),
        Some(&third.join("etc")),
        false,
        &SecretsMode::Passphrase(Zeroizing::new(PASS.to_owned())),
        &RestoreKeys {
            cfg: None,
            env: &*e3,
        },
    )
    .unwrap();
    assert_eq!(r3.secrets.unwrap().key_source, "the environment");
    assert!(!third.join("data/secrets.key").exists());
    let (store, _) = restored_store(&third, "", Arc::clone(&e3));
    store.load_now();
    assert_eq!(store.get("ntfy").unwrap().expose(), NTFY);
    let _ = process_env;
}

// REQ: API-007 — a damaged `secrets.enc` (a bit flipped, with the manifest's hash made to match)
// is the same refusal as a wrong passphrase, and the manifest's id is bound into the cipher.
#[test]
fn api_007_damaged_or_swapped_secrets_file_is_refused() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
    let first = tmp.path().join("first.ttbk");
    create_with(&files, &cfg, false, &first, Some(&export_of(&cfg, PASS))).unwrap();
    let none = env(&[]);
    let try_restore = |archive: &Path, name: &str| {
        let new = tmp.path().join(name);
        let r = restore_with(
            archive,
            Some(&new.join("data")),
            Some(&new.join("etc")),
            false,
            &SecretsMode::Passphrase(Zeroizing::new(PASS.to_owned())),
            &plain_keys(&*none),
        );
        (r.map(|_| ()), new)
    };
    // A bit flipped in the ciphertext.
    let mut files_in = Vec::new();
    let m = read_archive(&first, |n, r| {
        let mut b = Vec::new();
        r.read_to_end(&mut b).map_err(|e| e.to_string())?;
        files_in.push((n.to_owned(), b));
        Ok(())
    })
    .unwrap();
    let flipped = tmp.path().join("flipped.ttbk");
    {
        let mut enc =
            zstd::stream::Encoder::new(BufWriter::new(File::create(&flipped).unwrap()), 3).unwrap();
        enc.include_checksum(true).unwrap();
        let mut tar = TarWriter {
            out: enc,
            entries: Vec::new(),
        };
        for (n, b) in &files_in {
            let mut b = b.clone();
            if n == "data/secrets.enc" {
                b[3] ^= 1;
            }
            tar.entry_bytes(n, &b).unwrap();
        }
        let mut m2 = m.clone();
        m2.entries = tar.entries.clone();
        tar.bytes("manifest.json", &serde_json::to_vec(&m2).unwrap())
            .unwrap();
        tar.finish().unwrap().finish().unwrap().flush().unwrap();
    }
    let (r, new) = try_restore(&flipped, "n1");
    assert_eq!(r.unwrap_err(), "wrong passphrase or damaged archive");
    assert!(!new.join("data/state.db").exists());
    // The backup id changed in the manifest: the associated data no longer matches.
    let swapped = tmp.path().join("swapped.ttbk");
    rewrite(&first, &swapped, |m| {
        m.secrets.as_mut().unwrap().backup_id = Some("00".repeat(16));
    });
    let (r, _) = try_restore(&swapped, "n2");
    assert_eq!(r.unwrap_err(), "wrong passphrase or damaged archive");
    // A manifest that claims version 1 with secrets, or version 2 without, is damaged.
    let lying = tmp.path().join("lying.ttbk");
    rewrite(&first, &lying, |m| m.version = 1);
    assert!(show(&lying).unwrap_err().contains("secrets block"));
}

// REQ: API-007 (ADR-903 §8) — a passphrase shorter than 12 characters makes no backup.
#[test]
fn api_007_short_passphrase_refused_on_create() {
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(tmp.path());
    let out = tmp.path().join("b.ttbk");
    let export = export_of(&cfg, "elevenchars");
    let e = create_with(&files, &cfg, false, &out, Some(&export)).unwrap_err();
    assert!(e.to_string().contains("at least 12"), "{e}");
    assert!(!out.exists());
    // Twelve characters is enough; the count is of characters, not bytes.
    check_passphrase("twelve chars").unwrap();
    check_passphrase("ééééééééééé").unwrap_err();
    check_passphrase("éééééééééééé").unwrap();
}

// REQ: API-007 (ADR-903 §8) — the backup warns when the configuration files or UI-made rows hold
// a credential inline (copied as it is), and names none of its value.
#[test]
fn api_007_inline_credentials_warned_not_named() {
    let tmp = tempfile::tempdir().unwrap();
    let (conf, cfg) = config_in(
        tmp.path(),
        "[[upstream]]\nname = \"u\"\nurl = \"https://dns.example/dns-query\"\n[upstream.headers]\nAuthorization = \"Bearer planted-inline-header-55\"\n",
    );
    let out = tmp.path().join("b.ttbk");
    let c = create(&[conf], &cfg, false, &out).unwrap();
    assert_eq!(c.warnings.len(), 1, "{:?}", c.warnings);
    assert!(
        c.warnings[0].contains("1 entry in the configuration files")
            && c.warnings[0].contains("0 made in the UI or API"),
        "{:?}",
        c.warnings
    );
    assert!(!c.warnings[0].contains("planted-inline-header"));
    // Nothing inline: no warning.
    let (conf2, cfg2) = config_in(&tmp.path().join("b"), "");
    let c2 = create(&[conf2], &cfg2, false, &tmp.path().join("c.ttbk")).unwrap();
    assert!(c2.warnings.is_empty(), "{:?}", c2.warnings);
}

// REQ: API-007 — the CLI: a passphrase file, the first line only, and the same refusals.
#[test]
fn api_007_cli_create_and_restore() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
    let pass_file = tmp.path().join("pass.txt");
    fs::write(&pass_file, format!("{PASS}\nignored second line\n")).unwrap();
    let out = tmp.path().join("b.ttbk");
    cli_create(
        &files,
        &cfg,
        false,
        &out,
        Some(&Source::File(pass_file.clone())),
    )
    .unwrap();
    let m = show(&out).unwrap();
    assert!(m.has_secrets() && m.secrets.as_ref().unwrap().count == 2);
    let new = tmp.path().join("new");
    // No passphrase: refused; a file with the wrong one: refused; the right one: restored.
    let e = cli_restore(
        &out,
        Some(&new.join("data")),
        Some(&new.join("etc")),
        false,
        None,
        false,
        None,
    )
    .unwrap_err();
    assert!(e.contains("--skip-secrets"), "{e}");
    let wrong = tmp.path().join("wrong.txt");
    fs::write(&wrong, "not the passphrase\n").unwrap();
    let e = cli_restore(
        &out,
        Some(&new.join("data")),
        Some(&new.join("etc")),
        false,
        None,
        false,
        Some(&Source::File(wrong)),
    )
    .unwrap_err();
    assert!(e.contains("wrong passphrase"), "{e}");
    cli_restore(
        &out,
        Some(&new.join("data")),
        Some(&new.join("etc")),
        false,
        None,
        false,
        Some(&Source::File(pass_file.clone())),
    )
    .unwrap();
    let (store, _) = restored_store(&new, "", env(&[]));
    store.load_now();
    assert_eq!(store.get("unifi").unwrap().expose(), UNIFI);
    // A short passphrase file is refused on create.
    let short = tmp.path().join("short.txt");
    fs::write(&short, "short\n").unwrap();
    let e = cli_create(
        &files,
        &cfg,
        false,
        &tmp.path().join("c.ttbk"),
        Some(&Source::File(short)),
    )
    .unwrap_err();
    assert!(e.contains("at least 12"), "{e}");
    // The passphrase file is never an archive entry: the file isn't read into the backup.
    assert!(!contains(&fs::read(&out).unwrap(), PASS.as_bytes()));
}

// REQ: API-007, NFR-005 — nothing prints a passphrase or a value: `Debug` of the pieces.
#[test]
fn api_007_debug_never_shows_passphrase_or_values() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, cfg) = node_with_secrets(tmp.path());
    let export = export_of(&cfg, PASS);
    let text = format!("{export:?} {:?}", export.rows);
    assert!(
        !text.contains(PASS) && !text.contains(UNIFI) && !text.contains(NTFY),
        "{text}"
    );
    let plain = passphrase::PlainRow {
        name: "a".into(),
        kind: "text".into(),
        value: serde_json::from_str("\"planted-plain-1\"").unwrap(),
        updated: 1,
        updated_by: "x".into(),
    };
    assert!(!format!("{plain:?}").contains("planted-plain-1"));
}

/// A copy of `archive` with the bytes of the files changed by `edit` (the manifest's hashes and
/// sizes made to match, as someone without the passphrase could do), the manifest by `meta`, and
/// `add` entries put in.
fn rewrite_files(
    archive: &Path,
    out: &Path,
    edit: impl Fn(&str, &mut Vec<u8>),
    meta: impl FnOnce(&mut Manifest),
    add: &[(&str, &[u8])],
) {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let m = read_archive(archive, |name, r| {
        let mut b = Vec::new();
        r.read_to_end(&mut b).map_err(|e| e.to_string())?;
        files.push((name.to_owned(), b));
        Ok(())
    })
    .unwrap();
    let mut m2 = m;
    let mut enc =
        zstd::stream::Encoder::new(BufWriter::new(File::create(out).unwrap()), 3).unwrap();
    enc.include_checksum(true).unwrap();
    let mut tar = TarWriter {
        out: enc,
        entries: Vec::new(),
    };
    for (name, bytes) in &mut files {
        edit(name, bytes);
        tar.entry_bytes(name, bytes).unwrap();
    }
    for (name, bytes) in add {
        tar.entry_bytes(name, bytes).unwrap();
    }
    m2.entries = tar.entries.clone();
    meta(&mut m2);
    tar.bytes("manifest.json", &serde_json::to_vec_pretty(&m2).unwrap())
        .unwrap();
    tar.finish().unwrap().finish().unwrap().flush().unwrap();
}

// REQ: API-007 (ADR-965 §10) — nothing in the archive can be changed without the passphrase: the
// configuration (a router's URL, with the hashes made to match), a data file, an added entry and
// the node's name are all part of what the cipher authenticates, so each is the same refusal as
// a wrong passphrase and moves nothing; `--skip-secrets` of the same archive still restores.
#[test]
fn api_007_edited_archive_is_refused() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
    let first = tmp.path().join("first.ttbk");
    create_with(&files, &cfg, false, &first, Some(&export_of(&cfg, PASS))).unwrap();
    let none = env(&[]);
    let attempt = |archive: &Path, name: &str, mode: &SecretsMode| {
        let new = tmp.path().join(name);
        let r = restore_with(
            archive,
            Some(&new.join("data")),
            Some(&new.join("etc")),
            false,
            mode,
            &plain_keys(&*none),
        );
        (r.map(|_| ()), new)
    };
    let pass = || SecretsMode::Passphrase(Zeroizing::new(PASS.to_owned()));
    // The unedited archive restores (the rewrite itself changes nothing the cipher binds).
    let same = tmp.path().join("same.ttbk");
    rewrite_files(&first, &same, |_, _| {}, |_| {}, &[]);
    let (r, _) = attempt(&same, "ok", &pass());
    r.unwrap();
    // A configuration file pointed at another host.
    let edited = tmp.path().join("conf.ttbk");
    rewrite_files(
        &first,
        &edited,
        |n, b| {
            if n.starts_with("config/") {
                b.extend_from_slice(b"\n# router url = https://attacker.example\n");
            }
        },
        |_| {},
        &[],
    );
    let (r, new) = attempt(&edited, "n1", &pass());
    assert_eq!(r.unwrap_err(), "wrong passphrase or damaged archive");
    assert!(!new.join("data/state.db").exists() && !new.join("etc/wrendns.toml").exists());
    // A data file.
    let data = tmp.path().join("data.ttbk");
    rewrite_files(
        &first,
        &data,
        |n, b| {
            if n == "data/state.db" {
                b.push(0);
            }
        },
        |_| {},
        &[],
    );
    let (r, _) = attempt(&data, "n2", &pass());
    assert_eq!(r.unwrap_err(), "wrong passphrase or damaged archive");
    // An entry added.
    let added = tmp.path().join("added.ttbk");
    rewrite_files(
        &first,
        &added,
        |_, _| {},
        |_| {},
        &[("data/anomaly.json", b"{}")],
    );
    let (r, _) = attempt(&added, "n3", &pass());
    assert_eq!(r.unwrap_err(), "wrong passphrase or damaged archive");
    // The node's name.
    let renamed = tmp.path().join("node.ttbk");
    rewrite_files(
        &first,
        &renamed,
        |_, _| {},
        |m| m.node = "other".into(),
        &[],
    );
    let (r, _) = attempt(&renamed, "n4", &pass());
    assert_eq!(r.unwrap_err(), "wrong passphrase or damaged archive");
    // Without the secrets the edited archive is the owner's to restore, as any backup is.
    let (r, _) = attempt(&edited, "n5", &SecretsMode::Skip);
    r.unwrap();
}

// REQ: API-007 (ADR-965 §6) — without `-c`, the key settings are those of the archive's own
// configuration files (the ones the restored server starts with): a `secrets_key_file` in them
// is the key the rows are sealed under, no `secrets.key` is made beside it, and one that can't
// be read stops the restore before anything moves.
#[test]
fn api_007_restore_reads_key_settings_from_the_archive() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let key_file = tmp.path().join("node.key");
    let (files, cfg) = node_with_secrets(&tmp.path().join("a"));
    let mut text = fs::read_to_string(&files[0]).unwrap();
    text += &[
        "secrets_key_file = \"",
        &key_file.display().to_string(),
        "\"
",
    ]
    .concat();
    fs::write(&files[0], text).unwrap();
    let out = tmp.path().join("a.ttbk");
    create_with(&files, &cfg, false, &out, Some(&export_of(&cfg, PASS))).unwrap();
    let none = env(&[]);
    let pass = || SecretsMode::Passphrase(Zeroizing::new(PASS.to_owned()));
    // The file is missing: refused, nothing made or moved.
    let miss = tmp.path().join("miss");
    let e = restore_with(
        &out,
        Some(&miss.join("data")),
        Some(&miss.join("etc")),
        false,
        &pass(),
        &plain_keys(&*none),
    )
    .unwrap_err();
    assert!(e.contains("node.key"), "{e}");
    assert!(!miss.join("data/secrets.key").exists());
    assert!(!miss.join("data/state.db").exists());
    // The file is there: the rows are sealed under it.
    let key = crate::secrets::NodeKey::generate().unwrap();
    fs::write(&key_file, format!("{}\n", key.as_str())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let new = tmp.path().join("new");
    let r = restore_with(
        &out,
        Some(&new.join("data")),
        Some(&new.join("etc")),
        false,
        &pass(),
        &plain_keys(&*none),
    )
    .unwrap();
    assert_eq!(
        r.secrets.unwrap().key_source,
        key_file.display().to_string()
    );
    assert!(!new.join("data/secrets.key").exists(), "nothing generated");
    let extra = format!("secrets_key_file = \"{}\"\n", key_file.display());
    let (_, new_cfg) = config_in(&new, &extra);
    let store = SecretStore::with_env(&new_cfg, env(&[]), false, false);
    store.load_now();
    assert_eq!(store.get("unifi").unwrap().expose(), UNIFI);
}

// REQ: API-007, OPS-014 (ADR-965 §6) — a key the restore makes is the data directory's owner's
// (restore runs as root for a service user: a root-owned key would lock the service out of its
// own secrets), and one made for a restore that then fails is removed again.
#[cfg(unix)]
#[test]
fn api_007_restore_key_owner_and_cleanup() {
    use std::os::unix::fs::MetadataExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let none = env(&[]);
    let keys_cfg = plain_keys(&*none);
    // Dropped without `keep`: no stray key.
    let d1 = tmp.path().join("d1");
    fs::create_dir_all(&d1).unwrap();
    let (_k, guard) = restore_keys(&d1, &keys_cfg, &[], None).unwrap();
    assert!(d1.join("secrets.key").exists());
    drop(guard);
    assert!(!d1.join("secrets.key").exists(), "removed with the failure");
    // Kept: stays; and a key that was there already is never removed.
    let (_k, mut guard) = restore_keys(&d1, &keys_cfg, &[], None).unwrap();
    guard.keep();
    drop(guard);
    assert!(d1.join("secrets.key").exists());
    let (_k, guard) = restore_keys(&d1, &keys_cfg, &[], None).unwrap();
    drop(guard);
    assert!(d1.join("secrets.key").exists(), "an existing key stays");
    // Owner: only root can give a file to another uid.
    let me = fs::metadata("/proc/self").map_or(1, |m| m.uid());
    if me != 0 {
        return;
    }
    let d2 = tmp.path().join("d2");
    fs::create_dir_all(&d2).unwrap();
    std::os::unix::fs::chown(&d2, Some(4242), Some(4343)).unwrap();
    let (_k, mut guard) = restore_keys(&d2, &keys_cfg, &[], Some((4242, 4343))).unwrap();
    guard.keep();
    let md = fs::metadata(d2.join("secrets.key")).unwrap();
    assert_eq!((md.uid(), md.gid()), (4242, 4343));
    assert_eq!(md.mode() & 0o777, 0o600);
}

// REQ: API-007 (ADR-965 §6) — the whole restore, as root into a directory another user owns: the
// restored files and the key made for them are that user's.
#[cfg(unix)]
#[test]
fn api_007_restore_as_root_gives_the_key_to_the_data_owner() {
    use std::os::unix::fs::MetadataExt as _;
    if fs::metadata("/proc/self").map_or(1, |m| m.uid()) != 0 {
        return;
    }
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
    let out = tmp.path().join("b.ttbk");
    create_with(&files, &cfg, false, &out, Some(&export_of(&cfg, PASS))).unwrap();
    let new = tmp.path().join("new");
    fs::create_dir_all(new.join("data")).unwrap();
    std::os::unix::fs::chown(new.join("data"), Some(4242), Some(4343)).unwrap();
    let none = env(&[]);
    restore_with(
        &out,
        Some(&new.join("data")),
        Some(&new.join("etc")),
        false,
        &SecretsMode::Passphrase(Zeroizing::new(PASS.to_owned())),
        &plain_keys(&*none),
    )
    .unwrap();
    for f in ["secrets.key", "state.db"] {
        let md = fs::metadata(new.join("data").join(f)).unwrap();
        assert_eq!((md.uid(), md.gid()), (4242, 4343), "{f}");
    }
}

const PEM_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIPlantedKeyBytes0123456789abcdefghijkLMNOP\n-----END PRIVATE KEY-----";

/// An export that carries one hand-made row, as a planted archive could.
fn export_with_row(cfg: &wrendns_config::Config, name: &str, kind: Kind, v: &str) -> SecretsExport {
    let mut e = export_of(cfg, PASS);
    e.rows.push(ExportRow {
        name: name.to_owned(),
        kind: kind.as_str().to_owned(),
        value: SecretValue::new(kind, Zeroizing::new(v.to_owned())).unwrap(),
        updated: 1_700_000_000,
        updated_by: "root".to_owned(),
    });
    e
}

/// REQ: CLD-920, DSC-908 (ADR-1097 point 1) - a restore refuses a `pem` row and a name the
/// certificate issuer keeps for itself, whoever made the archive: the restoring node is standalone
/// and cannot judge the cluster's gate, and a key stays on its node. Nothing is restored.
#[test]
fn cld_920_restore_refuses_pem_rows_and_issuer_names() {
    let _serial = test_lock();
    for (name, kind, v) in [
        ("loc.key", Kind::Pem, PEM_KEY),
        ("cert.cluster.key", Kind::Text, "planted-text-1"),
        ("acme.account", Kind::Text, "planted-text-2"),
        ("cert.home.chain", Kind::Text, "planted-text-3"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
        let out = tmp.path().join("b.ttbk");
        create_with(
            &files,
            &cfg,
            false,
            &out,
            Some(&export_with_row(&cfg, name, kind, v)),
        )
        .unwrap();
        let new = tmp.path().join("new");
        let none = env(&[]);
        let err = restore_with(
            &out,
            Some(&new.join("data")),
            Some(&new.join("etc")),
            false,
            &SecretsMode::Passphrase(Zeroizing::new(PASS.to_owned())),
            &plain_keys(&*none),
        )
        .unwrap_err();
        assert!(
            err.contains(name) && err.contains("nothing was restored"),
            "{name}: {err}"
        );
        assert!(!err.contains("PlantedKeyBytes") && !err.contains("planted-text"));
        assert!(!new.join("data").join("state.db").exists(), "{name}");
    }
}

/// REQ: CLD-920 - a backup counts a `pem` secret it leaves out on purpose apart from the secrets
/// it could not read: its own warning, and no "couldn't be read" for it.
#[test]
fn cld_920_backup_warning_separates_pem_kept_from_unreadable() {
    let _serial = test_lock();
    let tmp = tempfile::tempdir().unwrap();
    let (files, cfg) = node_with_secrets(&tmp.path().join("old"));
    let store = SecretStore::with_env(&cfg, env(&[]), true, false);
    store
        .put(
            "loc.key",
            Kind::Pem,
            &SecretValue::new(Kind::Pem, Zeroizing::new(PEM_KEY.to_owned())).unwrap(),
            0,
            "root",
            "local",
            1_700_000_000,
        )
        .unwrap();
    let out = tmp.path().join("b.ttbk");
    let c = create_with(&files, &cfg, false, &out, Some(&export_of(&cfg, PASS))).unwrap();
    let said = c.warnings.join(" | ");
    assert!(
        said.contains("1 stored PEM secret(s)") && said.contains("never put in a backup"),
        "{said}"
    );
    assert!(!said.contains("couldn't be read"), "{said}");
    assert!(!said.contains("PlantedKeyBytes"), "{said}");
}

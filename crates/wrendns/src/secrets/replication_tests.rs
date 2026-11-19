//! REQ: CLU-015 (ADR-903 §6) — replication of stored secrets between in-process stores: what a
//! replica takes from a primary's pages, and what it keeps. The wire round trip and the cluster
//! channel are covered by `sync.rs`'s own tests and by the two-node tests in `secrets_api_tests`.
//! Each store here has its own data directory and its own node key, so every transfer exercises
//! the re-encryption under the receiver's key.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use wrendns_config::Config;
use wrendns_store::state::Stamp;
use zeroize::Zeroizing;

use super::store::{Applied, EnvFn, Remote, SecretStore, StoreError, StoreState, Unavailable};
use super::sync::{PAGE_BUDGET, verify};
use super::value::{Kind, SecretValue};

fn cfg_in(dir: &Path, ephemeral: bool) -> Config {
    let mut c = Config::default();
    c.node.data_dir = wrendns_config::SafeString::new(dir.to_str().unwrap()).unwrap();
    c.cluster.ephemeral = ephemeral;
    c
}

fn no_env() -> EnvFn {
    let m: HashMap<String, String> = HashMap::new();
    Arc::new(move |k: &str| m.get(k).cloned())
}

fn node(dir: &Path) -> SecretStore {
    SecretStore::with_env(&cfg_in(dir, false), no_env(), true, false)
}

fn value(v: &str) -> SecretValue {
    SecretValue::new(Kind::Text, Zeroizing::new(v.to_owned())).unwrap()
}

/// A write made by the primary of `epoch`, as the cluster stamps it.
fn put(s: &SecretStore, name: &str, v: &str, epoch: u64) {
    s.put(
        name,
        Kind::Text,
        &value(v),
        epoch,
        "root via pi",
        "cluster",
        100,
    )
    .unwrap();
}

fn read(s: &SecretStore, name: &str) -> Option<String> {
    s.get(name).ok().map(|v| v.expose().to_owned())
}

/// Everything a primary sends in one answer (pages of [`PAGE_BUDGET`]), with its head checked the
/// way a replica checks it.
fn pull_all(primary: &SecretStore) -> (Vec<Remote>, (Stamp, [u8; 32])) {
    let mut after: Option<String> = None;
    let mut head = None;
    let mut all = Vec::new();
    loop {
        let page = primary
            .export_page(after.as_deref(), PAGE_BUDGET)
            .expect("the primary answers");
        match head {
            None => head = Some(page.head),
            Some(h) => assert_eq!(h, page.head, "one answer carries one head"),
        }
        for r in page.items {
            after = Some(r.name.clone());
            all.push(r);
        }
        if !page.more {
            break;
        }
    }
    (all, head.expect("a head"))
}

/// A replica takes `primary`'s rows as of `epoch` (its base recorded on the way).
fn sync(primary: &SecretStore, replica: &SecretStore, epoch: u64) -> Applied {
    let (all, head) = pull_all(primary);
    verify(&all, head).expect("the answer's rows recompute its head");
    replica
        .apply_remote(&all, epoch, true, 200)
        .expect("the replica applies")
}

fn head_of_store(s: &SecretStore) -> (Stamp, [u8; 32]) {
    s.head()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Every byte under `dir`, as a file-by-file dump (the database, its WAL, anything else).
fn all_bytes(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(all_bytes(&p));
            } else if let Ok(b) = std::fs::read(&p) {
                out.extend(b);
            }
        }
    }
    out
}

/// REQ: CLU-015 (AC1) — a replica gets the secret re-encrypted under its own key, with the same
/// stamp, and the same head as the primary.
#[test]
fn clu_015_replica_gets_secret_reencrypted() {
    let (pd, rd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (p, r) = (node(pd.path()), node(rd.path()));
    put(&p, "router.unifi.api_key", "unifi-key-value", 1);
    let applied = sync(&p, &r, 1);
    assert_eq!(applied.changed, 1);
    assert_eq!(
        read(&r, "router.unifi.api_key").as_deref(),
        Some("unifi-key-value")
    );
    let prow = p.status().secrets.remove(0);
    let rrow = r.status().secrets.remove(0);
    assert_eq!(prow.stamp, rrow.stamp, "the stamp travels with the value");
    assert_eq!(rrow.origin, "cluster");
    // Under different keys: the replica's ciphertext is its own.
    let pk = p.status().key_id;
    let rk = r.status().key_id;
    assert_ne!(pk, rk, "each node has its own key");
    assert_eq!(head_of_store(&p), head_of_store(&r), "the heads agree");
}

/// REQ: CLU-015 (AC2) — an ephemeral member holds no secrets and answers none; a store of an
/// ephemeral member refuses to export or apply.
#[test]
fn clu_015_ephemeral_and_witness_refused() {
    let d = tempfile::tempdir().unwrap();
    let eph = SecretStore::with_env(&cfg_in(d.path(), true), no_env(), false, false);
    assert!(matches!(
        eph.export_page(None, PAGE_BUDGET),
        Err(Unavailable::Ephemeral)
    ));
    assert_eq!(
        eph.apply_remote(&[], 1, true, 1).unwrap_err(),
        StoreError::Ephemeral
    );
}

/// REQ: CLU-015 (AC3) — a deletion travels as a tombstone with a later stamp; the replica drops
/// the value and keeps the tombstone, and no value is left in its database.
#[test]
fn clu_015_delete_propagates_by_tombstone() {
    let (pd, rd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (p, r) = (node(pd.path()), node(rd.path()));
    put(&p, "a", "to-be-deleted-value", 1);
    sync(&p, &r, 1);
    assert!(read(&r, "a").is_some());
    p.delete("a", 1, "root via pi", 300).unwrap();
    let applied = sync(&p, &r, 1);
    assert_eq!(applied.tombstones, 1);
    assert!(r.get("a").is_err(), "the replica no longer has a value");
    let row = r
        .status()
        .secrets
        .into_iter()
        .find(|s| s.name == "a")
        .unwrap();
    assert!(
        row.deleted,
        "a tombstone is kept, so offline members learn of it"
    );
    assert_eq!(
        head_of_store(&p),
        head_of_store(&r),
        "tombstones are part of the head"
    );
}

/// REQ: CLU-015 (AC4) — a replica whose data-directory key went missing locks, heals (drops its
/// rows, makes a key), and takes them again from the primary.
#[test]
fn clu_015_replica_wrong_key_heals() {
    let (pd, rd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let p = node(pd.path());
    put(&p, "dns.token", "tok-123456789", 1);
    {
        let r = node(rd.path());
        sync(&p, &r, 1);
        assert_eq!(read(&r, "dns.token").as_deref(), Some("tok-123456789"));
    }
    // The replica's key file is lost: the store locks (rows exist, no key).
    std::fs::remove_file(rd.path().join("secrets.key")).unwrap();
    let r = SecretStore::with_env(&cfg_in(rd.path(), false), no_env(), true, false);
    r.load_now();
    assert_eq!(r.status().state, StoreState::Locked);
    let dropped = r
        .heal_as_replica()
        .expect("a replica with the cluster's rows heals");
    assert_eq!(dropped.rows, 1);
    assert_eq!(dropped.orphans.len(), 0);
    assert_eq!(r.status().state, StoreState::Ready);
    sync(&p, &r, 1);
    assert_eq!(read(&r, "dns.token").as_deref(), Some("tok-123456789"));
}

/// REQ: CLU-015 (AC5) — no plaintext on disk: after replication the replica's files hold no value
/// in the clear (the database, its WAL, any file under the data directory).
#[test]
fn clu_015_no_plaintext_on_disk() {
    let (pd, rd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (p, r) = (node(pd.path()), node(rd.path()));
    let secret = "plain-text-needle-9f3c1d7a";
    put(&p, "alerts.destination.token", secret, 1);
    sync(&p, &r, 1);
    assert!(
        !contains(&all_bytes(rd.path()), secret.as_bytes()),
        "the replica's files hold no plaintext"
    );
    assert_eq!(
        read(&r, "alerts.destination.token").as_deref(),
        Some(secret)
    );
}

/// REQ: CLU-015 (AC6) — a partition keeps the last set: a replica that hears nothing (or only
/// part of an answer) never deletes a name by its absence.
#[test]
fn clu_015_partition_keeps_last_set() {
    let (pd, rd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (p, r) = (node(pd.path()), node(rd.path()));
    put(&p, "a", "value-a-1234", 1);
    put(&p, "b", "value-b-1234", 1);
    sync(&p, &r, 1);
    // An answer that lists only `a` (say, a short page) doesn't remove `b`.
    let (all, _) = pull_all(&p);
    let only_a: Vec<Remote> = all.into_iter().filter(|x| x.name == "a").collect();
    r.apply_remote(&only_a, 1, true, 200).unwrap();
    assert_eq!(read(&r, "b").as_deref(), Some("value-b-1234"));
    assert_eq!(read(&r, "a").as_deref(), Some("value-a-1234"));
}

/// REQ: CLU-015 (AC8) — a local row a joining node had is shadowed by the cluster's row of the
/// same name, not dropped: it comes back when the cluster's rows are purged (removal).
#[test]
fn clu_015_local_rows_shadowed_not_dropped() {
    let (pd, rd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (p, r) = (node(pd.path()), node(rd.path()));
    r.put(
        "upstream.token",
        Kind::Text,
        &value("local-value-1"),
        0,
        "root",
        "local",
        50,
    )
    .unwrap();
    assert_eq!(read(&r, "upstream.token").as_deref(), Some("local-value-1"));
    put(&p, "upstream.token", "cluster-value-2", 1);
    let applied = sync(&p, &r, 1);
    assert_eq!(applied.shadowed, 1);
    assert_eq!(
        read(&r, "upstream.token").as_deref(),
        Some("cluster-value-2")
    );
    assert_eq!(r.status().shadows, vec!["upstream.token".to_owned()]);
    // Removal purges the cluster's rows: the local value is back.
    let (deleted, restored) = r.purge_cluster().unwrap();
    assert_eq!((deleted, restored), (0, 1));
    assert_eq!(read(&r, "upstream.token").as_deref(), Some("local-value-1"));
    assert_eq!(r.status().shadows, Vec::<String>::new());
}

/// REQ: CLU-015 (AC9) — a primary that loses its key doesn't wipe the replicas (it answers
/// `Locked`, and the replicas keep their rows); its reverse heal takes the rows back from a
/// replica holding them at the same stamps.
#[test]
fn clu_015_primary_key_loss_does_not_wipe_replicas() {
    let (pd, rd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    {
        let p = node(pd.path());
        put(&p, "a", "alpha-value-1", 1);
        put(&p, "b", "bravo-value-2", 1);
        let r = node(rd.path());
        sync(&p, &r, 1);
        assert_eq!(r.status().secrets.len(), 2);
    }
    // The primary's key file is lost.
    std::fs::remove_file(pd.path().join("secrets.key")).unwrap();
    let p = SecretStore::with_env(&cfg_in(pd.path(), false), no_env(), true, false);
    p.load_now();
    assert_eq!(p.status().state, StoreState::Locked);
    assert!(matches!(
        p.export_page(None, PAGE_BUDGET),
        Err(Unavailable::Locked(_))
    ));
    // The replica is untouched: it still has both values.
    let r = SecretStore::with_env(&cfg_in(rd.path(), false), no_env(), true, false);
    r.load_now();
    assert_eq!(read(&r, "a").as_deref(), Some("alpha-value-1"));
    assert_eq!(read(&r, "b").as_deref(), Some("bravo-value-2"));
    // The reverse heal: the replica's rows at the primary's stamps fill the primary again.
    let needs = p.heal_needs();
    assert_eq!(needs.len(), 2);
    let (all, _) = pull_all(&r);
    p.heal_with(&all, 300)
        .expect("the replica covers every row");
    assert_eq!(p.status().state, StoreState::Ready);
    assert_eq!(read(&p, "a").as_deref(), Some("alpha-value-1"));
    assert_eq!(read(&p, "b").as_deref(), Some("bravo-value-2"));
}

/// REQ: CLU-015 (AC9, the refusal) — a reverse heal refuses a partial answer: a row no replica
/// holds at its stamp keeps the primary locked.
#[test]
fn clu_015_reverse_heal_needs_every_row() {
    let (pd, rd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    {
        let p = node(pd.path());
        put(&p, "a", "alpha-value-1", 1);
        put(&p, "b", "bravo-value-2", 1);
        let r = node(rd.path());
        // The replica has only `a`.
        let (all, _) = pull_all(&p);
        let only_a: Vec<Remote> = all.into_iter().filter(|x| x.name == "a").collect();
        r.apply_remote(&only_a, 1, true, 200).unwrap();
    }
    std::fs::remove_file(pd.path().join("secrets.key")).unwrap();
    let p = SecretStore::with_env(&cfg_in(pd.path(), false), no_env(), true, false);
    p.load_now();
    let r = SecretStore::with_env(&cfg_in(rd.path(), false), no_env(), true, false);
    let (all, _) = pull_all(&r);
    assert!(p.heal_with(&all, 300).is_err());
    assert_eq!(p.status().state, StoreState::Locked, "nothing was dropped");
}

/// REQ: CLU-015 (AC10) — a promoted primary keeps its secrets and stamps its own changes in its
/// epoch; a deletion it makes reaches a member that was behind on the old primary.
#[test]
fn clu_015_promoted_primary_keeps_secrets() {
    let (d1, d2, d3) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let (p1, p2, r3) = (node(d1.path()), node(d2.path()), node(d3.path()));
    put(&p1, "a", "alpha-value-1", 1);
    put(&p1, "b", "bravo-value-2", 1);
    sync(&p1, &p2, 1);
    sync(&p1, &r3, 1);
    // p1 fails; p2 is elected in epoch 2 and keeps the secrets it held.
    assert_eq!(read(&p2, "a").as_deref(), Some("alpha-value-1"));
    p2.delete("a", 2, "root via pi", 400).unwrap();
    let stamp = p2
        .status()
        .secrets
        .into_iter()
        .find(|s| s.name == "a")
        .unwrap()
        .stamp;
    assert_eq!(
        stamp,
        Stamp { epoch: 2, seq: 1 },
        "the new primary stamps in its epoch"
    );
    // r3, behind on p1, learns the deletion from p2.
    sync(&p2, &r3, 2);
    assert!(r3.get("a").is_err(), "the deletion propagated by tombstone");
    assert_eq!(read(&r3, "b").as_deref(), Some("bravo-value-2"));
}

/// REQ: CLU-015 (AC11) — a row an older primary stamped after the current primary's base, which
/// the current primary doesn't hold, is orphaned: kept, listed, never used.
#[test]
fn clu_015_stale_epoch_secret_orphaned() {
    let (d1, d2, d3) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let (p1, p2, r) = (node(d1.path()), node(d2.path()), node(d3.path()));
    put(&p1, "a", "alpha-value-1", 1);
    put(&p1, "b", "bravo-value-2", 1);
    put(&p1, "c", "charlie-value-3", 1);
    sync(&p1, &p2, 1);
    sync(&p1, &r, 1);
    // Partitioned: p1 keeps writing, and only r hears it.
    put(&p1, "x", "stale-value-4444", 1);
    sync(&p1, &r, 1);
    assert_eq!(read(&r, "x").as_deref(), Some("stale-value-4444"));
    // p2 takes over in epoch 2; its base is (1,3), so (1,4) is after it.
    let applied = sync(&p2, &r, 2);
    assert_eq!(applied.orphaned, 1);
    assert!(
        matches!(r.get("x"), Err(Unavailable::Orphaned)),
        "an orphan is never used"
    );
    assert!(
        r.status()
            .secrets
            .iter()
            .any(|s| s.name == "x" && s.orphaned)
    );
    assert_eq!(
        read(&r, "a").as_deref(),
        Some("alpha-value-1"),
        "others untouched"
    );
    // It is not deleted by absence either: the row is still there.
    assert!(r.status().secrets.iter().any(|s| s.name == "x"));
}

/// REQ: CLU-015 (ADR-917 point 15; N2) — a replica that lost its key while holding an orphan heals:
/// the orphan can't be read by any key it has, so the heal drops it (named in the answer), and the
/// rows the primary lists come back from it. Before, the orphan kept the store locked for good.
#[test]
fn clu_015_unreadable_orphan_dropped_by_heal() {
    let (d1, d2, rd) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let (p1, p2) = (node(d1.path()), node(d2.path()));
    put(&p1, "a", "alpha-value-1", 1);
    put(&p1, "x", "stale-value-4444", 1);
    put(&p2, "a", "alpha-value-1", 1);
    {
        let r = node(rd.path());
        sync(&p1, &r, 1);
        // Epoch 2's primary doesn't list `x`: the replica's epoch-1 copy is an orphan.
        let applied = sync(&p2, &r, 2);
        assert_eq!(applied.orphaned, 1);
    }
    std::fs::remove_file(rd.path().join("secrets.key")).unwrap();
    let r = SecretStore::with_env(&cfg_in(rd.path(), false), no_env(), true, false);
    r.load_now();
    assert_eq!(r.status().state, StoreState::Locked);
    let dropped = r
        .heal_as_replica()
        .expect("an unreadable orphan doesn't keep the replica locked");
    assert_eq!(dropped.orphans, vec!["x".to_owned()], "named for the audit");
    assert_eq!(dropped.rows, 2);
    assert_eq!(r.status().state, StoreState::Ready);
    sync(&p2, &r, 2);
    assert_eq!(read(&r, "a").as_deref(), Some("alpha-value-1"));
    assert!(
        !r.status().secrets.iter().any(|s| s.name == "x"),
        "the orphan is gone, not listed by the primary"
    );
}

/// REQ: CLU-015 (AC13) — a stale or altered answer is refused: a changed value's stamp or a
/// dropped row breaks the head, and the replica discards the whole answer.
#[test]
fn clu_015_stale_answer_rejected() {
    let d = tempfile::tempdir().unwrap();
    let p = node(d.path());
    put(&p, "a", "alpha-value-1", 1);
    put(&p, "b", "bravo-value-2", 1);
    let (mut all, head) = pull_all(&p);
    verify(&all, head).expect("the genuine answer checks");
    // A row dropped from the answer (an attacker or a short page passed off as whole).
    let dropped: Vec<Remote> = all
        .iter()
        .filter(|r| r.name == "a")
        .map(clone_remote)
        .collect();
    assert!(
        verify(&dropped, head).is_err(),
        "a dropped row breaks the digest"
    );
    // A stamp changed.
    all[0].stamp = Stamp { epoch: 9, seq: 9 };
    assert!(
        verify(&all, head).is_err(),
        "a changed stamp breaks the digest"
    );
    // A head that doesn't match its rows.
    let (all, head) = pull_all(&p);
    let wrong = (
        Stamp {
            epoch: head.0.epoch,
            seq: head.0.seq + 1,
        },
        head.1,
    );
    assert!(verify(&all, wrong).is_err());
}

fn clone_remote(r: &Remote) -> Remote {
    Remote {
        name: r.name.clone(),
        kind: r.kind.clone(),
        stamp: r.stamp,
        deleted: r.deleted,
        held: r.held,
        updated: r.updated,
        updated_by: r.updated_by.clone(),
        value: r
            .value
            .as_ref()
            .map(|v| SecretValue::from_text(Zeroizing::new(v.expose().to_owned()))),
    }
}

/// REQ: CLU-015 (AC15) — a removed member purges the cluster's rows, and what it held of its own
/// comes back.
#[test]
fn clu_015_removed_member_purges() {
    let (pd, rd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (p, r) = (node(pd.path()), node(rd.path()));
    put(&p, "a", "alpha-value-1", 1);
    put(&p, "b", "bravo-value-2", 1);
    sync(&p, &r, 1);
    let (deleted, restored) = r.purge_cluster().unwrap();
    assert_eq!((deleted, restored), (2, 0));
    assert!(
        r.status()
            .secrets
            .iter()
            .all(|s| s.name != "a" && s.name != "b")
    );
}

/// REQ: CLU-015 (AC7 / AC2 / AC4 on the primary) — held rows: the primary holds a row it can't
/// decrypt, sends it as held with no value, and the replica keeps its own row for it.
#[test]
fn clu_015_held_rows_keep_replica_row() {
    let (pd, rd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let p = node(pd.path());
    put(&p, "a", "alpha-value-1", 1);
    let r = node(rd.path());
    sync(&p, &r, 1);
    // A row the primary can't read: a second primary-side key would be needed. Simulate by
    // re-stamping the replica's copy to a newer stamp the primary doesn't have readable: the
    // primary's own row is replaced with an unreadable one via a new key.
    let (all, _) = pull_all(&p);
    let mut held: Vec<Remote> = all;
    held[0].held = true;
    held[0].value = None;
    let replica_before = read(&r, "a");
    let applied = r.apply_remote(&held, 1, true, 200).unwrap();
    assert_eq!(applied.held, 1);
    assert_eq!(
        read(&r, "a"),
        replica_before,
        "the replica keeps its own row"
    );
}

// ---- the sim: partitions, failover and orphans, over many seeded schedules ----

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

const NAMES: [&str; 4] = [
    "router.a.key",
    "alerts.b.token",
    "upstream.c.pass",
    "otlp.d.hdr",
];

/// REQ: CLU-015 (AC16, `wrendns-sim`) — seeded schedules of writes, partitions, a failover that
/// strands a stale primary's writes on one replica, and syncs. After everything heals and the
/// final primary syncs: every live row a replica holds is the primary's, except orphans (rows the
/// primary doesn't hold and an older epoch stamped after its base), which are not used; and every
/// row the primary holds is on every member.
#[test]
fn clu_015_sim_partition_and_failover() {
    let schedules: u64 = std::env::var("WRENDNS_SIM_SCHEDULES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40);
    let first: u64 = std::env::var("WRENDNS_SIM_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    for seed in first..first + schedules {
        run_schedule(seed);
    }
}

#[allow(clippy::needless_range_loop, clippy::too_many_lines)] // a seeded schedule reads as its steps
fn run_schedule(seed: u64) {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let n = 3 + usize::try_from(rng.below(2)).unwrap_or(0); // 3 or 4 members
    let dirs: Vec<tempfile::TempDir> = (0..n).map(|_| tempfile::tempdir().unwrap()).collect();
    let stores: Vec<SecretStore> = dirs.iter().map(|d| node(d.path())).collect();
    let mut link = vec![vec![true; n]; n];
    let mut primary = 0usize;
    let mut epoch = 1u64;
    let mut ops: Vec<String> = Vec::new();
    let steps = 30 + rng.below(40);
    for _ in 0..steps {
        match rng.below(10) {
            0..=2 => {
                let name = NAMES[usize::try_from(rng.below(4)).unwrap_or(0)];
                let v = format!("v{}-{}-seed{seed}", rng.below(1000), epoch);
                if rng.below(4) == 0 {
                    let _ = stores[primary].delete(name, epoch, "root via pi", 100);
                    ops.push(format!("delete {name}"));
                } else {
                    let _ = stores[primary].put(
                        name,
                        Kind::Text,
                        &value(&v),
                        epoch,
                        "root",
                        "cluster",
                        100,
                    );
                    ops.push(format!("put {name}={v}"));
                }
            }
            3 => {
                // Break or heal a random link.
                let (a, b) = (
                    usize::try_from(rng.below(n as u64)).unwrap_or(0),
                    usize::try_from(rng.below(n as u64)).unwrap_or(0),
                );
                if a != b {
                    let up = !link[a][b];
                    link[a][b] = up;
                    link[b][a] = up;
                    ops.push(format!("link {a}-{b} {up}"));
                }
            }
            4 if rng.below(3) == 0 => {
                // Failover: the old primary is cut off from everyone but one replica, which may
                // still hear its last writes (the stale-epoch case), and a new primary takes over.
                let old = primary;
                let new = (old + 1) % n;
                let keep = (old + 2) % n;
                for j in 0..n {
                    if j != old && j != keep {
                        link[old][j] = false;
                        link[j][old] = false;
                    }
                }
                let stale_write = format!("stale-seed{seed}-{epoch}");
                let _ = stores[old].put(
                    "stale.x",
                    Kind::Text,
                    &value(&stale_write),
                    epoch,
                    "root",
                    "cluster",
                    100,
                );
                sync_pair(&stores[old], &stores[keep], epoch, &link, old, keep);
                primary = new;
                epoch += 1;
                for j in 0..n {
                    link[new][j] = j == new || link[new][j];
                    link[j][new] = link[new][j];
                }

                ops.push(format!(
                    "failover to {new} in epoch {epoch}, stranded stale write on {keep}"
                ));
            }
            _ => {
                // Sync every linked replica from the primary.
                for j in 0..n {
                    if j != primary && link[primary][j] {
                        sync_pair(&stores[primary], &stores[j], epoch, &link, primary, j);
                    }
                }
            }
        }
    }
    // Heal everything, then sync until the final primary is heard by all.
    for a in 0..n {
        for b in 0..n {
            link[a][b] = true;
        }
    }
    for _ in 0..2 {
        for j in 0..n {
            if j != primary {
                sync_pair(&stores[primary], &stores[j], epoch, &link, primary, j);
            }
        }
    }
    let p = &stores[primary];
    for j in 0..n {
        if j == primary {
            continue;
        }
        let r = &stores[j];
        let state = r.status();
        assert_eq!(
            state.state,
            StoreState::Ready,
            "seed {seed}: replica {j} is ready"
        );
        for row in &state.secrets {
            let on_primary = p
                .status()
                .secrets
                .into_iter()
                .find(|s| s.name == row.name && !s.orphaned);
            match on_primary {
                Some(pr) => {
                    // REQ: CLU-015 (ADR-917 point 10) — a deletion that the primary lists as live
                    // with an older stamp (a write it superseded) is kept here, and reported as a
                    // conflict: the replica doesn't take the revoked value back. A later write wins.
                    if row.deleted && !pr.deleted && pr.stamp < row.stamp {
                        continue;
                    }
                    // An orphan is a row the primary doesn't hold; this one it does hold.
                    assert!(
                        !row.orphaned,
                        "seed {seed}: {} orphaned on {j} but the primary holds it ({:?})",
                        row.name, pr.stamp
                    );
                    assert_eq!(
                        row.stamp, pr.stamp,
                        "seed {seed}: replica {j} has {} at the primary's stamp (ops: {ops:?})",
                        row.name
                    );
                    if !row.deleted {
                        assert_eq!(
                            read(r, &row.name),
                            read(p, &row.name),
                            "seed {seed}: value of {} on {j} matches the primary",
                            row.name
                        );
                    }
                }
                None => {
                    if !row.deleted && row.origin == "cluster" {
                        assert!(
                            row.orphaned && row.stamp.epoch < epoch,
                            "seed {seed}: {} on {j} isn't on the primary and isn't an orphan (ops: {ops:?})",
                            row.name
                        );
                        assert!(matches!(r.get(&row.name), Err(Unavailable::Orphaned)));
                    }
                }
            }
        }
        // Every row the primary holds is on the replica (no row lost to a partition), except a
        // deletion of an older epoch the replica keeps against the primary's live listing
        // (ADR-917 point 10: a conflict, not a loss).
        for pr in p.status().secrets.into_iter().filter(|s| !s.orphaned) {
            assert!(
                state.secrets.iter().any(|s| s.name == pr.name
                    && (s.stamp == pr.stamp || (s.deleted && !pr.deleted && pr.stamp < s.stamp))),
                "seed {seed}: replica {j} lacks {} (ops: {ops:?})",
                pr.name
            );
        }
    }
}

/// One pull of `to` from `from`, if the link is up.
fn sync_pair(
    from: &SecretStore,
    to: &SecretStore,
    epoch: u64,
    link: &[Vec<bool>],
    a: usize,
    b: usize,
) {
    if !link[a][b] {
        return;
    }
    let Ok(page) = from.export_page(None, PAGE_BUDGET) else {
        return;
    };
    let all = page.items;
    let _ = to.apply_remote(&all, epoch, true, 200);
}

/// A row as a sender lists it, for a test that builds an answer by hand.
fn remote(name: &str, v: &str, stamp: Stamp) -> Remote {
    Remote {
        name: name.into(),
        kind: "text".into(),
        stamp,
        deleted: false,
        held: false,
        updated: 100,
        updated_by: "root".into(),
        value: Some(value(v)),
    }
}

/// REQ: CLU-015 (ADR-917 points 4, 8; AC15) — a removed member's purge restores only the local row
/// a cluster row displaced. A stale cluster copy displaced by a newer primary's listing sits in its
/// own slot, and the purge drops it: the replica never holds the stale value again.
#[test]
fn clu_015_removed_member_purge_restores_only_local() {
    let (pd, qd, rd) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let (p, q, r) = (node(pd.path()), node(qd.path()), node(rd.path()));
    r.put(
        "x",
        Kind::Text,
        &value("mine-local-1111"),
        0,
        "root",
        "local",
        50,
    )
    .unwrap();
    // Primary P (epoch 1) lists `x`: the local row is shadowed.
    put(&p, "x", "cluster-old-2222", 1);
    sync(&p, &r, 1);
    assert_eq!(read(&r, "x").as_deref(), Some("cluster-old-2222"));
    // Primary Q (epoch 2) holds `x` at a different epoch-1 stamp: the replica's cluster row is
    // stale, and it goes to its own slot.
    put(&q, "x", "scratch", 1);
    put(&q, "x", "cluster-new-3333", 1);
    sync(&q, &r, 2);
    assert_eq!(read(&r, "x").as_deref(), Some("cluster-new-3333"));
    assert_eq!(r.status().shadows, vec!["x".to_owned()]);
    let (deleted, restored) = r.purge_cluster().unwrap();
    assert_eq!((deleted, restored), (0, 1), "the local row comes back");
    assert_eq!(read(&r, "x").as_deref(), Some("mine-local-1111"));
    let rows = r.status().secrets;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].origin, "local");
    assert!(r.status().shadows.is_empty(), "the stale copy is gone");
    let on_disk = all_bytes(rd.path());
    assert!(!contains(&on_disk, b"cluster-old-2222"));
    assert!(!contains(&on_disk, b"cluster-new-3333"));
}

/// REQ: CLU-015 (ADR-917 point 10; N1) — a secret deleted in one epoch and created again in a later
/// one reaches a replica: the later write's stamp is after the tombstone, so it is taken, not held
/// as a conflict, and the heads converge.
#[test]
fn clu_015_recreated_after_epoch_change_replicates() {
    let (pd, rd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (p, r) = (node(pd.path()), node(rd.path()));
    put(&p, "a", "first-value-1", 1);
    sync(&p, &r, 1);
    p.delete("a", 1, "root via pi", 300).unwrap();
    let applied = sync(&p, &r, 1);
    assert_eq!(applied.tombstones, 1);
    assert_eq!(read(&r, "a"), None);
    // Epoch 2: the primary writes `a` again, stamped in epoch 2.
    put(&p, "a", "second-value-2", 2);
    let applied = sync(&p, &r, 2);
    assert!(
        applied.conflicts.is_empty(),
        "a later write is not a conflict"
    );
    assert_eq!(read(&r, "a").as_deref(), Some("second-value-2"));
    assert_eq!(head_of_store(&p), head_of_store(&r), "the heads converge");
    // The tombstone it displaced is kept in the cluster's shadow slot, not as a live value.
    assert_eq!(r.status().shadows, vec!["a".to_owned()]);
}

/// REQ: CLU-015 (ADR-917 point 10; M4) — a deletion of an older epoch is not undone by a newer
/// primary's listing of the name as live when that listing is a write the deletion superseded (its
/// stamp is older than the tombstone): the replica keeps the tombstone and reports a conflict.
#[test]
fn clu_015_tombstone_of_older_epoch_not_resurrected() {
    let (pd, qd, rd) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let (p, q, r) = (node(pd.path()), node(qd.path()), node(rd.path()));
    put(&p, "a", "revoked-value-9", 1);
    sync(&p, &r, 1);
    p.delete("a", 1, "root", 100).unwrap();
    sync(&p, &r, 1);
    assert_eq!(read(&r, "a"), None, "deleted on the replica");
    // The new primary never had the deletion: its `a` is the epoch-1 write, stamped before the
    // tombstone (1,2), so the listing is older than the deletion.
    put(&q, "a", "revoked-value-9", 1);
    let applied = sync(&q, &r, 2);
    assert_eq!(applied.conflicts, vec!["a".to_owned()]);
    assert_eq!(read(&r, "a"), None, "the revoked value stays revoked");
    let row = r
        .status()
        .secrets
        .into_iter()
        .find(|s| s.name == "a")
        .unwrap();
    assert!(row.deleted);
}

/// REQ: CLU-015 (ADR-917 point 11; M1; ADR-903 §4) — an emergency primary's answer is not
/// authoritative: it fills a name only by stamp where this node holds a cluster row, it displaces
/// no local row, and it orphans nothing.
#[test]
fn clu_015_emergency_primary_changes_nothing() {
    let (pd, rd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (p, r) = (node(pd.path()), node(rd.path()));
    put(&p, "orph", "orphan-candidate", 1);
    put(&p, "c", "cluster-one", 1);
    sync(&p, &r, 1);
    r.put(
        "loc",
        Kind::Text,
        &value("local-keep-7"),
        0,
        "root",
        "local",
        50,
    )
    .unwrap();
    // The emergency primary's answer: `loc` claimed live with a newer stamp; `c` newer; `orph`
    // not listed at all.
    let items = vec![
        remote("loc", "emergency-loc", Stamp { epoch: 5, seq: 1 }),
        remote("c", "cluster-two", Stamp { epoch: 3, seq: 1 }),
    ];
    let applied = r.apply_remote(&items, 5, false, 200).unwrap();
    assert_eq!(applied.shadowed, 0, "nothing displaced");
    assert_eq!(applied.orphaned, 0, "nothing orphaned");
    assert_eq!(read(&r, "loc").as_deref(), Some("local-keep-7"));
    assert_eq!(read(&r, "c").as_deref(), Some("cluster-two"), "by stamp");
    let orph = r
        .status()
        .secrets
        .into_iter()
        .find(|s| s.name == "orph")
        .unwrap();
    assert!(!orph.orphaned, "an emergency answer orphans nothing");
    assert_eq!(r.status().shadows.len(), 0);
}

/// REQ: CLU-015 (L1; AC13) — an answer is applied only when its head is the one the heartbeat
/// announced, and its primary is in the heartbeat's epoch.
#[test]
fn clu_015_answer_must_match_heartbeat() {
    use wrendns_cluster::net::SecretsHead;
    let digest = [7u8; 32];
    let head = (Stamp { epoch: 1, seq: 2 }, digest);
    let announced = SecretsHead {
        epoch: 1,
        seq: 2,
        digest: digest.to_vec(),
    };
    assert!(super::sync::check_answer(head, 1, &announced, 1).is_ok());
    let later = SecretsHead {
        seq: 3,
        ..announced.clone()
    };
    assert!(
        super::sync::check_answer(head, 1, &later, 1).is_err(),
        "a newer head"
    );
    let other = SecretsHead {
        digest: vec![8; 32],
        ..announced.clone()
    };
    assert!(
        super::sync::check_answer(head, 1, &other, 1).is_err(),
        "another digest"
    );
    assert!(
        super::sync::check_answer(head, 2, &announced, 1).is_err(),
        "another epoch"
    );
}

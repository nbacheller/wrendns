//! REQ: API-007 (ADR-939, ADR-988, ADR-989), DSC-002 (ADR-988) — the Pi-hole import worker run
//! for real: the built `telltale pihole-import-worker` binary, started with a cleared
//! environment as the server starts it, under its real memory limit (1 GiB `RLIMIT_DATA`).
//!
//! In a release build the global allocator is mimalloc, which reserves a 1 GiB arena before
//! `main`; Linux counts that against `RLIMIT_DATA`, so a worker started without the allocator's
//! environment could not allocate once hardened and answered `"<path>: <path>"` (SQLite's null
//! handle). These tests run the binary the way CI's release build does (`cargo test --release`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test helpers, not runtime code

use std::path::Path;
use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_telltale");

/// A gravity.db with the tables the import reads, and a few rows.
fn gravity_db(path: &Path) {
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch(
        r#"
        CREATE TABLE "group"(id INTEGER PRIMARY KEY, enabled INTEGER, name TEXT, date_added INTEGER, date_modified INTEGER, description TEXT);
        CREATE TABLE adlist(id INTEGER PRIMARY KEY, address TEXT, enabled INTEGER, date_added INTEGER, date_modified INTEGER, comment TEXT);
        CREATE TABLE adlist_by_group(adlist_id INTEGER, group_id INTEGER);
        CREATE TABLE domainlist(id INTEGER PRIMARY KEY, type INTEGER, domain TEXT, enabled INTEGER, date_added INTEGER, date_modified INTEGER, comment TEXT);
        CREATE TABLE domainlist_by_group(domainlist_id INTEGER, group_id INTEGER);
        CREATE TABLE client(id INTEGER PRIMARY KEY, ip TEXT, date_added INTEGER, date_modified INTEGER, comment TEXT);
        CREATE TABLE client_by_group(client_id INTEGER, group_id INTEGER);
        INSERT INTO "group" VALUES (0, 1, 'Default', 0, 0, 'd'), (1, 1, 'Kids', 0, 0, 'k');
        INSERT INTO adlist VALUES (1, 'https://lists.example/kids.txt', 1, 0, 0, 'kids');
        INSERT INTO adlist_by_group VALUES (1, 1);
        INSERT INTO domainlist VALUES (1, 1, 'denied.example', 1, 0, 0, 'deny');
        INSERT INTO domainlist_by_group VALUES (1, 0);
        INSERT INTO client VALUES (1, '192.168.1.50', 0, 0, 'tablet');
        INSERT INTO client_by_group VALUES (1, 1);
        "#,
    )
    .unwrap();
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A zip with one stored entry (a Teleporter archive keeps its `gravity.db` this way).
fn zip_of(name: &str, data: &[u8]) -> Vec<u8> {
    let crc = crc32(data);
    let len = u32::try_from(data.len()).unwrap();
    let nlen = u16::try_from(name.len()).unwrap();
    let mut z = Vec::new();
    z.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    z.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // version, flags, stored, time, date
    z.extend_from_slice(&crc.to_le_bytes());
    z.extend_from_slice(&len.to_le_bytes());
    z.extend_from_slice(&len.to_le_bytes());
    z.extend_from_slice(&nlen.to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z.extend_from_slice(name.as_bytes());
    z.extend_from_slice(data);
    let central = u32::try_from(z.len()).unwrap();
    z.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    z.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // versions, flags, stored, time, date
    z.extend_from_slice(&crc.to_le_bytes());
    z.extend_from_slice(&len.to_le_bytes());
    z.extend_from_slice(&len.to_le_bytes());
    z.extend_from_slice(&nlen.to_le_bytes());
    z.extend_from_slice(&[0u8; 12]); // extra, comment, disk, internal attributes
    z.extend_from_slice(&0u32.to_le_bytes()); // external attributes
    z.extend_from_slice(name.as_bytes());
    let end = u32::try_from(z.len()).unwrap();
    z.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    z.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
    z.extend_from_slice(&(end - central).to_le_bytes());
    z.extend_from_slice(&central.to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z
}

/// Runs the worker as the server does (an empty environment, plus the spawn preparation when
/// `prepared`) and returns its answer.
fn run(args: &[&Path], prepared: bool) -> Value {
    let mut cmd = Command::new(BIN);
    cmd.arg("pihole-import-worker");
    for a in args {
        cmd.arg(a);
    }
    cmd.env_clear();
    if prepared {
        telltale_net::worker::prepare_spawn(&mut cmd).unwrap();
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "the worker exits 0 with its answer");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "the worker's answer is JSON ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

/// REQ: API-007 (`api_007_import_worker_reads_gravity_db_under_its_limit`) — a gravity.db is
/// converted by the hardened worker.
#[test]
fn api_007_import_worker_reads_gravity_db_under_its_limit() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("gravity.db");
    gravity_db(&db);
    let answer = run(&[&db], true);
    assert_eq!(answer["ok"], true, "{answer}");
    let toml = answer["toml"].as_str().unwrap();
    assert!(toml.contains("Kids"), "{toml}");
    assert!(toml.contains("denied.example"), "{toml}");
}

/// REQ: API-007 (`api_007_import_worker_unpacks_teleporter_in_its_scratch_dir`, ADR-989) — a
/// Teleporter archive is unpacked into the directory the server gives, not a system `/tmp`, and
/// nothing is left behind.
#[test]
fn api_007_import_worker_unpacks_teleporter_in_its_scratch_dir() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("src.db");
    gravity_db(&db);
    let zip = dir.path().join("teleporter.zip");
    std::fs::write(&zip, zip_of("gravity.db", &std::fs::read(&db).unwrap())).unwrap();
    let scratch = dir.path().join("scratch");
    std::fs::create_dir(&scratch).unwrap();
    let answer = run(&[&zip, Path::new("--scratch"), &scratch], true);
    assert_eq!(answer["ok"], true, "{answer}");
    assert!(answer["toml"].as_str().unwrap().contains("Kids"));
    assert_eq!(
        std::fs::read_dir(&scratch).unwrap().count(),
        0,
        "the unpacked gravity.db is removed"
    );
}

/// REQ: DSC-002, API-007 (`dsc_002_worker_without_allocator_env_refuses_clearly`, ADR-988) — a
/// worker started without the spawn preparation holds the allocator's 1 GiB arena, which no
/// limit of 1 GiB or less can contain: it refuses to run and names the cause, instead of
/// answering with a bare path from a failed allocation.
#[test]
fn dsc_002_worker_without_allocator_env_refuses_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("gravity.db");
    gravity_db(&db);
    let answer = run(&[&db], false);
    assert_eq!(answer["ok"], false, "{answer}");
    let why = answer["error"].as_str().unwrap();
    assert!(why.contains("MIMALLOC_ARENA_RESERVE"), "{why}");
}

//! REQ: NFR-001 (ADR-170) — the release profile builds some crates for size (`opt-level = "s"`): the
//! ones off the DNS path. This keeps that list honest:
//!
//! - no crate that runs per query (the `wrendns-*` hot-path crates, `wrendns-config` among them,
//!   whose client lookup is per query, and the runtime and data-structure crates they lean on) is on
//!   it: a 2026-11 benchmark showed `wrendns-config` at `"s"` changes `ClientTable::identify` and the
//!   query handler and loses about 10% of cache-hot throughput;
//! - every entry is exactly `opt-level = "s"`; and
//! - every entry still names a package in `Cargo.lock`: a dependency update that changes a version
//!   (an entry written `name@version`) would otherwise leave cargo with only a warning, and the
//!   saving would be gone without anyone noticing, and a name that is now in two versions is
//!   ambiguous to cargo.

#![allow(clippy::unwrap_used)]

use toml::{Table, Value};

const MANIFEST: &str = include_str!("../../../Cargo.toml");
const LOCK: &str = include_str!("../../../Cargo.lock");

/// Crates that run per query (or hold what does), by name. Extend it when a crate joins the DNS path.
const HOT: &[&str] = &[
    "wrendns",
    "wrendns-proto",
    "wrendns-net",
    "wrendns-cache",
    "wrendns-filter",
    "wrendns-policy",
    "wrendns-telemetry",
    "wrendns-upstream",
    "wrendns-config",
    "wrendns-store",
    // Not per query, but kept at the release opt-level on purpose: the rollup store's queries (the
    // dashboard's lists) were 10 to 38% slower with SQLite's C code at -Os, and the wrapper's effect
    // was within noise for a saving too small to matter.
    "rusqlite",
    "libsqlite3-sys",
    "mimalloc",
    "tokio",
    "mio",
    "socket2",
    "bytes",
    "hashbrown",
    "ahash",
    "memchr",
    "aho-corasick",
    "regex-automata",
    "fst",
    "arc-swap",
    "parking_lot",
    "crossbeam-channel",
    "rustls",
    "ring",
    "blake3",
    "xxhash-rust",
    "zstd",
    "zstd-sys",
];

/// The release profile's per-package entries: the spec as written, and its `opt-level`.
fn overrides() -> Vec<(String, Option<String>)> {
    let manifest: Table = MANIFEST.parse().unwrap();
    let release = manifest["profile"]["release"].as_table().unwrap();
    let Some(packages) = release.get("package").and_then(Value::as_table) else {
        return Vec::new();
    };
    packages
        .iter()
        .map(|(spec, v)| {
            let t = v.as_table().unwrap();
            assert_eq!(
                t.len(),
                t.keys().filter(|k| *k == "opt-level").count(),
                "{spec}: only opt-level may be set per package here"
            );
            (
                spec.clone(),
                t.get("opt-level")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            )
        })
        .collect()
}

fn locked() -> Vec<(String, String)> {
    let lock: Table = LOCK.parse().unwrap();
    lock["package"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["name"].as_str().unwrap().to_owned(),
                p["version"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn nfr_001_size_optimized_crates_are_off_the_dns_path() {
    let entries = overrides();
    assert!(
        !entries.is_empty(),
        "expected the size-optimized crates in [profile.release.package.*]"
    );
    for (spec, level) in &entries {
        let name = spec.split('@').next().unwrap();
        assert!(
            !HOT.contains(&name),
            "{name} is on the DNS path and must keep the release profile's opt-level"
        );
        assert_eq!(
            level.as_deref(),
            Some("s"),
            "{spec}: expected opt-level = \"s\""
        );
    }
}

#[test]
fn nfr_001_every_size_override_names_a_locked_package() {
    let locked = locked();
    for (spec, _) in overrides() {
        let (name, version) = match spec.split_once('@') {
            Some((n, v)) => (n, Some(v)),
            None => (spec.as_str(), None),
        };
        let versions: Vec<&str> = locked
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect();
        match version {
            Some(v) => assert!(
                versions.contains(&v),
                "{spec}: Cargo.lock has {name} at {versions:?}; update the entry to the locked version"
            ),
            None => assert_eq!(
                versions.len(),
                1,
                "{spec}: Cargo.lock has {name} at {versions:?}; a bare name must match exactly one version, so write name@version"
            ),
        }
    }
}

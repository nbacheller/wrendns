//! `wrendns backup create | restore | show` (REQ: API-007; T6.7, ADR-063): one archive with
//! the configuration files and the node's local data, to move a setup to a new machine or
//! keep a copy (Teleporter parity).
//!
//! A `.ttbk` is a tar stream, zstd-compressed with zstd's frame checksum:
//! - `config/<name>`: the configuration files the node was started with;
//! - `data/state.db`: users, API tokens, devices and names made in the UI, and the audit log,
//!   copied consistently while the server runs (`VACUUM INTO`), without sessions;
//! - `data/rollups.db` (statistics history) and `data/anomaly.json` (learned baselines);
//! - `data/qlog/...` (and `data/qlog-nodes/...`): the query log, only with `--include-qlog`;
//! - `data/secrets.enc`, only when a passphrase was given (REQ: API-007, T23.9, ADR-903 §8): the
//!   node's stored secrets, encrypted under a key made from it ([`passphrase`]);
//! - `manifest.json`, last: the format version, where things came from, and every entry's
//!   size and BLAKE3 hash.
//!
//! Lists, compiled snapshots, and the cache are rebuilt, so they aren't included. Neither is
//! the cluster identity (`cluster/`, with the CA key). Restore checks every hash before
//! anything is moved into place.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub(crate) mod cli;
mod passphrase;

pub(crate) use passphrase::{
    BackupError, ExportRow, Exported, SecretsExport, SecretsInfo, check_passphrase, kdf_busy,
};
#[cfg(test)]
pub(crate) use passphrase::{kdf_slot_for_tests, test_lock};

/// `manifest.json`'s `format`.
const FORMAT: &str = "telltale-backup"; // rebrand:keep
/// A backup without secrets stays version 1 (builds before T23.9 restore it); one with
/// `data/secrets.enc` is version 2, which they refuse (ADR-903 §8).
const VERSION: u32 = 1;
const VERSION_SECRETS: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Entry {
    pub path: String,
    pub size: u64,
    pub blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ConfigFile {
    /// Its name in the archive (`config/<name>`).
    pub name: String,
    /// Where it was read from.
    pub original: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub format: String,
    pub version: u32,
    pub telltale_version: String, // rebrand:keep
    /// Unix seconds.
    pub created: u64,
    pub node: String,
    pub data_dir: String,
    pub config_files: Vec<ConfigFile>,
    pub includes_qlog: bool,
    /// The node was a cluster member (its identity isn't in the backup).
    pub cluster_member: bool,
    pub entries: Vec<Entry>,
    /// REQ: API-007 (T23.9) — what the backup holds of the stored secrets (absent in archives
    /// made before it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<SecretsInfo>,
}

impl Manifest {
    /// The backup carries secrets (`data/secrets.enc`).
    pub(crate) fn has_secrets(&self) -> bool {
        self.secrets.as_ref().is_some_and(|s| s.included)
    }
}

// ------------------------------------------------------------------ tar (ustar + GNU names)

fn octal(field: &mut [u8], n: u64) {
    let s = format!("{n:0width$o}", width = field.len() - 1);
    field[..s.len()].copy_from_slice(s.as_bytes());
}

fn header(name: &str, size: u64, typeflag: u8) -> [u8; 512] {
    let mut h = [0u8; 512];
    let n = name.as_bytes();
    h[..n.len().min(100)].copy_from_slice(&n[..n.len().min(100)]);
    octal(&mut h[100..108], 0o600);
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], 0);
    h[156] = typeflag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
    h
}

struct TarWriter<W: Write> {
    out: W,
    entries: Vec<Entry>,
}

impl<W: Write> TarWriter<W> {
    fn pad(&mut self, size: u64) -> io::Result<()> {
        let rem = (size % 512) as usize;
        if rem != 0 {
            self.out.write_all(&[0u8; 512][..512 - rem])?;
        }
        Ok(())
    }

    fn head(&mut self, name: &str, size: u64) -> io::Result<()> {
        if name.len() > 99 {
            // GNU long name: a 'L' entry whose data is the name.
            let mut long = name.as_bytes().to_vec();
            long.push(0);
            self.out
                .write_all(&header("././@LongLink", long.len() as u64, b'L'))?;
            self.out.write_all(&long)?;
            self.pad(long.len() as u64)?;
        }
        self.out.write_all(&header(name, size, b'0'))
    }

    /// Streams `src` as `name`, hashing it. Exactly the size seen at open is copied: query
    /// log segments only grow, so that prefix is consistent.
    fn file(&mut self, name: &str, src: &Path) -> io::Result<()> {
        let mut f = File::open(src)?;
        let size = f.metadata()?.len();
        self.head(name, size)?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut left = size;
        while left > 0 {
            let want = usize::try_from(left.min(buf.len() as u64)).unwrap_or(buf.len());
            let n = f.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::other(format!(
                    "{} shrank while being read",
                    src.display()
                )));
            }
            hasher.update(&buf[..n]);
            self.out.write_all(&buf[..n])?;
            left -= n as u64;
        }
        self.pad(size)?;
        self.entries.push(Entry {
            path: name.to_owned(),
            size,
            blake3: hasher.finalize().to_hex().to_string(),
        });
        Ok(())
    }

    fn bytes(&mut self, name: &str, data: &[u8]) -> io::Result<()> {
        self.head(name, data.len() as u64)?;
        self.out.write_all(data)?;
        self.pad(data.len() as u64)
    }

    /// An entry made from memory, hashed into the manifest like a file.
    fn entry_bytes(&mut self, name: &str, data: &[u8]) -> io::Result<()> {
        self.bytes(name, data)?;
        self.entries.push(Entry {
            path: name.to_owned(),
            size: data.len() as u64,
            blake3: blake3::hash(data).to_hex().to_string(),
        });
        Ok(())
    }

    fn finish(mut self) -> io::Result<W> {
        self.out.write_all(&[0u8; 1024])?;
        Ok(self.out)
    }
}

// ------------------------------------------------------------------ create

/// What `create` wrote.
#[derive(Debug)]
pub(crate) struct Created {
    pub path: PathBuf,
    pub entries: usize,
    pub bytes: u64,
    /// What the archive holds of the stored secrets.
    pub secrets: SecretsInfo,
    /// Things to tell whoever made it (inline credentials copied as they are, secrets that
    /// couldn't be read).
    pub warnings: Vec<String>,
}

/// A consistent copy of an SQLite database (works while the server writes to it), with the
/// `strip` statements run on the copy before it is vacuumed (what never goes into a backup).
fn sqlite_copy(src: &Path, dst: &Path, strip: &[&str]) -> Result<(), String> {
    let db = rusqlite::Connection::open_with_flags(
        src,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("{}: {e}", src.display()))?;
    // ADR-124 — VACUUM builds a temporary database: in memory, since a container's root
    // filesystem is read-only and has no /tmp.
    db.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|e| format!("{}: {e}", src.display()))?;
    db.execute("VACUUM INTO ?1", [dst.to_string_lossy()])
        .map_err(|e| format!("{}: {e}", src.display()))?;
    if !strip.is_empty() {
        let copy = rusqlite::Connection::open(dst).map_err(|e| e.to_string())?;
        copy.pragma_update(None, "temp_store", "MEMORY")
            .map_err(|e| e.to_string())?;
        for sql in strip {
            // A table that isn't there (an older schema) is fine.
            let _ = copy.execute(sql, []);
        }
        copy.execute_batch("VACUUM").map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(p),
                Ok(t) if t.is_file() => out.push(p),
                _ => {}
            }
        }
    }
    out.sort();
    out
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The default archive name: `wrendns-<node>-<UTC time>.ttbk`.
pub(crate) fn default_name(node: &str) -> PathBuf {
    let secs = unix_now();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days.cast_signed() + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let node = crate::pihole::slug(node, 40);
    PathBuf::from(format!(
        "wrendns-{}-{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z.ttbk",
        if node.is_empty() { "node" } else { &node },
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

/// Writes a backup of the node configured by `files` / `cfg` to `out` (owner-only), without the
/// stored secrets.
#[cfg(test)]
pub(crate) fn create(
    files: &[PathBuf],
    cfg: &wrendns_config::Config,
    include_qlog: bool,
    out: &Path,
) -> Result<Created, String> {
    create_with(files, cfg, include_qlog, out, None).map_err(|e| e.to_string())
}

/// REQ: API-007 (T23.9, ADR-903 §8) — [`create`], with the stored secrets sealed under a
/// passphrase into `data/secrets.enc` when `secrets` is given (and holds any).
pub(crate) fn create_with(
    files: &[PathBuf],
    cfg: &wrendns_config::Config,
    include_qlog: bool,
    out: &Path,
    secrets: Option<&SecretsExport>,
) -> Result<Created, BackupError> {
    let data = PathBuf::from(cfg.node.data_dir.as_str());
    let stage = data.join(format!(".backup-{}", std::process::id()));
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(&stage).map_err(|e| format!("{}: {e}", stage.display()))?;
    let result = write_archive(files, cfg, &data, &stage, include_qlog, out, secrets);
    let _ = fs::remove_dir_all(&stage);
    result
}

/// The most query log a backup through the API holds in memory (the CLI has no such limit).
pub(crate) const API_QLOG_MAX: u64 = 256 << 20;

/// The size of the query log under `data` (what `include_qlog` would add).
pub(crate) fn qlog_bytes(data: &Path) -> u64 {
    ["qlog", "qlog-nodes"]
        .iter()
        .flat_map(|d| files_under(&data.join(d)))
        .filter_map(|f| fs::metadata(f).ok())
        .map(|m| m.len())
        .sum()
}

/// How many live secrets the database at `src` holds (0 for a database without the table).
fn live_secret_count(src: &Path) -> usize {
    let Ok(db) = rusqlite::Connection::open_with_flags(
        src,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        return 0;
    };
    db.query_row("SELECT count(*) FROM secrets WHERE deleted = 0", [], |r| {
        r.get::<_, i64>(0)
    })
    .map_or(0, |n| usize::try_from(n).unwrap_or(0))
}

/// `entry` without the fields that name a stored secret or a file: what is left holds a
/// credential only when it sits in the entry itself.
fn inline_credential(kind: &str, entry: &serde_json::Value) -> bool {
    let mut probe = entry.clone();
    if let Some(m) = probe.as_object_mut() {
        m.retain(|k, _| {
            !(k.ends_with("_ref")
                || k.ends_with("_refs")
                || k.ends_with("_file")
                || k == "tls_client_key")
        });
    }
    wrendns_config::credentials::holds_credential(kind, &probe)
}

/// REQ: API-007 (ADR-903 §8) — the entries of the configuration files and the UI-made (`managed`)
/// rows that hold a credential inline. A backup copies them as they are; stored secrets and
/// credential files are the ways to keep one out of it.
fn inline_credentials(cfg: &wrendns_config::Config, state_copy: Option<&Path>) -> (usize, usize) {
    let mut in_files = 0;
    if let Ok(v) = serde_json::to_value(cfg) {
        for (kind, list) in [
            ("upstream", v.get("upstream")),
            ("list", v.get("list")),
            ("alert_destination", v.pointer("/alerts/destination")),
        ] {
            if let Some(a) = list.and_then(serde_json::Value::as_array) {
                in_files += a.iter().filter(|e| inline_credential(kind, e)).count();
            }
        }
    }
    // The other kinds the settings pages hold (routers, OIDC providers, sinks, OTLP, Git).
    in_files += crate::secrets::credential::fields(cfg, None)
        .iter()
        .filter(|f| {
            f.source == crate::secrets::Source::Inline
                && !matches!(f.kind, "upstream" | "list" | "alert_destination")
        })
        .count();
    let mut managed = 0;
    if let Some(p) = state_copy
        && let Ok(db) = rusqlite::Connection::open_with_flags(
            p,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        && let Ok(mut q) = db.prepare("SELECT kind, body FROM managed")
        && let Ok(rows) = q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
    {
        for (kind, body) in rows.flatten() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body)
                && inline_credential(&kind, &v)
            {
                managed += 1;
            }
        }
    }
    (in_files, managed)
}

fn write_archive(
    files: &[PathBuf],
    cfg: &wrendns_config::Config,
    data: &Path,
    stage: &Path,
    include_qlog: bool,
    out: &Path,
    secrets: Option<&SecretsExport>,
) -> Result<Created, BackupError> {
    let tmp = out.with_extension("ttbk.partial");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let file = opts
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    let result = write_into(
        file,
        files,
        cfg,
        (data, stage, include_qlog),
        (out, &tmp),
        secrets,
    );
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[allow(clippy::too_many_lines)] // one archive, written in order
fn write_into(
    file: File,
    files: &[PathBuf],
    cfg: &wrendns_config::Config,
    (data, stage, include_qlog): (&Path, &Path, bool),
    (out, tmp): (&Path, &Path),
    secrets: Option<&SecretsExport>,
) -> Result<Created, BackupError> {
    let mut enc = zstd::stream::Encoder::new(BufWriter::new(file), 6).map_err(|e| e.to_string())?;
    enc.include_checksum(true).map_err(|e| e.to_string())?;
    let mut tar = TarWriter {
        out: enc,
        entries: Vec::new(),
    };
    let err = |e: io::Error| e.to_string();

    let mut config_files = Vec::new();
    let mut names: BTreeMap<String, usize> = BTreeMap::new();
    for f in files {
        let base = f.file_name().map_or_else(
            || "wrendns.toml".into(),
            |n| n.to_string_lossy().into_owned(),
        );
        let n = names.entry(base.clone()).or_default();
        *n += 1;
        let name = if *n == 1 { base } else { format!("{n}-{base}") };
        tar.file(&format!("config/{name}"), f)
            .map_err(|e| format!("{}: {e}", f.display()))?;
        config_files.push(ConfigFile {
            name,
            original: fs::canonicalize(f)
                .unwrap_or_else(|_| f.clone())
                .display()
                .to_string(),
        });
    }

    let mut stored = 0;
    let mut state_copy = None;
    for (db, strip) in [
        // REQ: OPS-014 (ADR-903 §8) — sessions and retry records never; nor the secrets store
        // (rows, shadows, tombstones and its stamp): its values are encrypted under this node's
        // key, which no backup holds. They travel only as `data/secrets.enc`, under a
        // passphrase. REQ: CLU-015 (ADR-917 point 4) — shadows included.
        (
            "state.db",
            &[
                "DELETE FROM sessions",
                "DELETE FROM idempotency",
                "DELETE FROM secrets",
                "DELETE FROM secrets_shadow",
                "DELETE FROM meta WHERE key = 'secrets_stamp'",
            ][..],
        ),
        ("rollups.db", &[][..]),
    ] {
        let src = data.join(db);
        if src.exists() {
            let copy = stage.join(db);
            if db == "state.db" {
                stored = live_secret_count(&src);
            }
            sqlite_copy(&src, &copy, strip)?;
            tar.file(&format!("data/{db}"), &copy).map_err(err)?;
            if db == "state.db" {
                state_copy = Some(copy);
            }
        }
    }
    let anomaly = data.join("anomaly.json");
    if anomaly.exists() {
        tar.file("data/anomaly.json", &anomaly).map_err(err)?;
    }
    if include_qlog {
        for dir in ["qlog", "qlog-nodes"] {
            for f in files_under(&data.join(dir)) {
                let Ok(rel) = f.strip_prefix(data) else {
                    continue;
                };
                let rel = rel.to_string_lossy().replace('\\', "/");
                tar.file(&format!("data/{rel}"), &f)
                    .map_err(|e| format!("{}: {e}", f.display()))?;
            }
        }
    }

    let mut warnings = Vec::new();
    let (in_files, managed) = inline_credentials(cfg, state_copy.as_deref());
    if in_files + managed > 0 {
        warnings.push(format!(
            "{in_files} entr{} in the configuration files and {managed} made in the UI or API hold a credential inline: a backup copies them as they are, so keep it as private as the files (stored secrets and credential files keep a credential out of it)",
            if in_files + managed == 1 { "y" } else { "ies" }
        ));
    }
    let secrets_info = match secrets {
        Some(x) if !x.rows.is_empty() => {
            // The version is the one a backup with secrets has (ADR-965 §10): the binding covers
            // every entry written so far (all but `secrets.enc`).
            let bind = passphrase::binding(
                FORMAT,
                VERSION_SECRETS,
                cfg.node.name.as_str(),
                &tar.entries,
            );
            let (ct, info) = passphrase::seal(x, &bind)?;
            tar.entry_bytes(passphrase::ENTRY, &ct).map_err(err)?;
            if x.unreadable > 0 {
                warnings.push(format!(
                    "{} stored secret(s) couldn't be read on this node (another key, or damaged) and were left out",
                    x.unreadable
                ));
            }
            // REQ: CLD-920 - said apart: these were left out on purpose, not because they failed.
            if x.pem_kept > 0 {
                warnings.push(format!(
                    "{} stored PEM secret(s) (certificate keys) are never put in a backup: they stay on the node that holds them",
                    x.pem_kept
                ));
            }
            info
        }
        Some(x) => SecretsInfo::omitted(
            x.unreadable,
            if x.unreadable > 0 {
                "none of the stored secrets could be read on this node"
            } else if x.pem_kept > 0 {
                "only certificate keys are stored, and they never leave the node"
            } else {
                "none stored"
            },
        ),
        None => SecretsInfo::omitted(stored, "no passphrase"),
    };

    let manifest = Manifest {
        format: FORMAT.into(),
        version: if secrets_info.included {
            VERSION_SECRETS
        } else {
            VERSION
        },
        telltale_version: crate::build_info::VERSION.into(), // rebrand:keep
        created: unix_now(),
        node: cfg.node.name.to_string(),
        data_dir: data.display().to_string(),
        config_files,
        includes_qlog: include_qlog,
        cluster_member: data.join("cluster").join("cluster.json").exists(),
        entries: tar.entries.clone(),
        secrets: Some(secrets_info.clone()),
    };
    let json = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    tar.bytes("manifest.json", &json).map_err(err)?;
    let entries = tar.entries.len();
    let enc = tar.finish().map_err(err)?;
    let mut w = enc.finish().map_err(err)?;
    w.flush().map_err(err)?;
    drop(w);
    fs::rename(tmp, out).map_err(|e| format!("{}: {e}", out.display()))?;
    let bytes = fs::metadata(out).map_or(0, |m| m.len());
    Ok(Created {
        path: out.to_path_buf(),
        entries,
        bytes,
        secrets: secrets_info,
        warnings,
    })
}

// ------------------------------------------------------------------ read

/// An archive path is `config/<name>`, `data/<relative path>`, or `manifest.json`, with no
/// `..`, absolute, or empty parts.
fn safe(path: &str) -> bool {
    let p = Path::new(path);
    let ok_parts = p.components().all(|c| matches!(c, Component::Normal(_)));
    ok_parts
        && (path == "manifest.json"
            || path
                .strip_prefix("config/")
                .is_some_and(|n| !n.is_empty() && !n.contains('/'))
            || path.strip_prefix("data/").is_some_and(|n| !n.is_empty()))
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Reads the archive, calling `sink(path, reader)` for each file in order; returns the
/// manifest. Each entry's size and hash are checked against the manifest at the end.
fn read_archive(
    archive: &Path,
    mut sink: impl FnMut(&str, &mut dyn Read) -> Result<(), String>,
) -> Result<Manifest, String> {
    let f = File::open(archive).map_err(|e| format!("{}: {e}", archive.display()))?;
    let mut r = zstd::stream::Decoder::new(BufReader::new(f))
        .map_err(|e| format!("{}: not a WrenDNS backup ({e})", archive.display()))?;
    let mut seen: BTreeMap<String, (u64, String)> = BTreeMap::new();
    let mut manifest: Option<Manifest> = None;
    let mut long: Option<String> = None;
    let bad = |what: &str| format!("{}: corrupt backup ({what})", archive.display());
    loop {
        let mut h = [0u8; 512];
        r.read_exact(&mut h).map_err(|e| bad(&e.to_string()))?;
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let size = u64::from_str_radix(cstr(&h[124..136]).trim(), 8).map_err(|_| bad("size"))?;
        let pad = (512 - size % 512) % 512;
        let mut body = (&mut r).take(size);
        match h[156] {
            b'L' => {
                // T10.7 — bounded: a path, not a way to fill memory.
                if size > MAX_LONG_NAME {
                    return Err(bad("path too long"));
                }
                let mut name = Vec::new();
                body.read_to_end(&mut name)
                    .map_err(|e| bad(&e.to_string()))?;
                long = Some(cstr(&name));
            }
            b'0' | 0 => {
                let name = long.take().unwrap_or_else(|| cstr(&h[..100]));
                if !safe(&name) {
                    return Err(bad(&format!("unexpected path `{name}`")));
                }
                if name == "manifest.json" {
                    if size > MAX_MANIFEST {
                        return Err(bad("manifest too large"));
                    }
                    let mut json = Vec::new();
                    body.read_to_end(&mut json)
                        .map_err(|e| bad(&e.to_string()))?;
                    manifest =
                        Some(serde_json::from_slice(&json).map_err(|e| bad(&e.to_string()))?);
                } else {
                    let mut hashing = HashingReader {
                        inner: &mut body,
                        hasher: blake3::Hasher::new(),
                        count: 0,
                    };
                    sink(&name, &mut hashing)?;
                    io::copy(&mut hashing, &mut io::sink()).map_err(|e| bad(&e.to_string()))?;
                    seen.insert(
                        name,
                        (
                            hashing.count,
                            hashing.hasher.finalize().to_hex().to_string(),
                        ),
                    );
                }
            }
            _ => return Err(bad("unexpected entry type")),
        }
        io::copy(&mut body, &mut io::sink()).map_err(|e| bad(&e.to_string()))?;
        io::copy(&mut (&mut r).take(pad), &mut io::sink()).map_err(|e| bad(&e.to_string()))?;
    }
    // Reading to the end lets zstd check its frame checksum.
    io::copy(&mut r, &mut io::sink()).map_err(|e| bad(&e.to_string()))?;
    let m = manifest.ok_or_else(|| bad("no manifest"))?;
    if m.format != FORMAT {
        return Err(bad("not a WrenDNS backup"));
    }
    if m.version > VERSION_SECRETS {
        return Err(format!(
            "{}: made by a newer WrenDNS (backup format {}); upgrade to restore it",
            archive.display(),
            m.version
        ));
    }
    let want: BTreeMap<String, (u64, String)> = m
        .entries
        .iter()
        .map(|e| (e.path.clone(), (e.size, e.blake3.clone())))
        .collect();
    if want != seen {
        return Err(bad("contents don't match the manifest"));
    }
    // REQ: API-007 (ADR-903 §8) — version 2 is exactly the archives that hold `secrets.enc`.
    if m.has_secrets() != want.contains_key(passphrase::ENTRY)
        || m.has_secrets() != (m.version >= VERSION_SECRETS)
    {
        return Err(bad("the secrets block doesn't match the contents"));
    }
    Ok(m)
}

struct HashingReader<'a, R: Read> {
    inner: &'a mut R,
    hasher: blake3::Hasher,
    count: u64,
}

impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }
}

/// `wrendns backup show`: checks the archive and returns its manifest.
pub(crate) fn show(archive: &Path) -> Result<Manifest, String> {
    read_archive(archive, |_, _| Ok(()))
}

// ------------------------------------------------------------------ restore

/// The longest path entry and manifest an archive may hold (T10.7).
const MAX_LONG_NAME: u64 = 4096;
const MAX_MANIFEST: u64 = 16 << 20;

/// REQ: API-007 (T10.7) — a directory the archive recorded (where it came from), used when
/// the command doesn't name one: only an absolute path below the root, with no `..`. An archive
/// is data; it doesn't get to pick an arbitrary place to write.
fn recorded_dir(dir: &str, flag: &str) -> Result<PathBuf, String> {
    use std::path::Component;
    let p = PathBuf::from(dir);
    let plain = p.is_absolute()
        && p.components().count() > 1
        && p.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
    if plain {
        Ok(p)
    } else {
        Err(format!(
            "the backup records `{dir}` as its directory; name one with {flag}"
        ))
    }
}

/// REQ: API-007 (T23.9) — what restore does with the secrets of a version 2 backup.
pub(crate) enum SecretsMode {
    /// Nothing was said: a backup that holds secrets is refused before anything moves.
    Unspecified,
    /// `--skip-secrets`: restore everything else.
    Skip,
    /// Open them with this passphrase and store them under this node's key.
    Passphrase(Zeroizing<String>),
}

/// The stored secrets a restore put back.
#[derive(Debug)]
pub(crate) struct RestoredSecrets {
    pub count: usize,
    /// Where the node's key came from (never the key).
    pub key_source: String,
    pub key_id: String,
}

/// Where `restore` put things.
#[derive(Debug)]
pub(crate) struct Restored {
    pub manifest: Manifest,
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub files: usize,
    /// Secrets stored again (a passphrase was given).
    pub secrets: Option<RestoredSecrets>,
    /// Secrets the backup holds that `--skip-secrets` left out.
    pub secrets_skipped: usize,
}

/// Restores `archive`: data into `data_dir` (default: where it came from) and config files
/// into `config_dir` (default: the first config file's directory). Nothing is moved into
/// place until every entry checks out; existing files are only replaced with `force`.
#[cfg(test)]
pub(crate) fn restore(
    archive: &Path,
    data_dir: Option<&Path>,
    config_dir: Option<&Path>,
    force: bool,
) -> Result<Restored, String> {
    restore_with(
        archive,
        data_dir,
        config_dir,
        force,
        &SecretsMode::Unspecified,
        &RestoreKeys {
            cfg: None,
            env: &crate::secrets::process_env,
        },
    )
}

/// Where a restore finds the node's secrets key: the configuration's (`-c`) key settings and the
/// environment; without a configuration only the environment and the data directory's own key.
pub(crate) struct RestoreKeys<'a> {
    pub cfg: Option<&'a wrendns_config::Config>,
    pub env: &'a dyn Fn(&str) -> Option<String>,
}

/// REQ: API-007 (T23.9, ADR-903 §8) — [`restore`], with `secrets` saying what to do with the
/// backup's stored secrets and `key_cfg` where the node's key comes from. A configured key that
/// can't be read stops the restore (nothing is generated in its place), before anything moves.
pub(crate) fn restore_with(
    archive: &Path,
    data_dir: Option<&Path>,
    config_dir: Option<&Path>,
    force: bool,
    secrets: &SecretsMode,
    key_cfg: &RestoreKeys<'_>,
) -> Result<Restored, String> {
    // The manifest comes last, so read once to learn the defaults (and check everything).
    let m = show(archive)?;
    if m.has_secrets() {
        let n = m.secrets.as_ref().map_or(0, |x| x.count);
        match secrets {
            SecretsMode::Unspecified => {
                return Err(format!(
                    "this backup holds {n} stored secret(s) encrypted with a passphrase: give it with --secrets-passphrase-file FILE (or --secrets-passphrase-stdin, --secrets-passphrase-prompt), or restore without them with --skip-secrets. Nothing was restored."
                ));
            }
            SecretsMode::Passphrase(p) => {
                passphrase::check_passphrase(p)?;
                if let Some(k) = m.secrets.as_ref().and_then(|x| x.kdf.as_ref()) {
                    passphrase::check_kdf(k)?;
                }
            }
            SecretsMode::Skip => {}
        }
    }
    let data_dir = match data_dir {
        Some(d) => d.to_path_buf(),
        None => recorded_dir(&m.data_dir, "--data-dir")?,
    };
    let config_dir = match config_dir {
        Some(d) => d.to_path_buf(),
        None => match m
            .config_files
            .first()
            .and_then(|c| Path::new(&c.original).parent())
        {
            Some(d) => recorded_dir(&d.to_string_lossy(), "--config-dir")?,
            None => PathBuf::from("/etc/wrendns"),
        },
    };
    let target = |path: &str| -> PathBuf {
        match path.strip_prefix("config/") {
            Some(n) => config_dir.join(n),
            None => data_dir.join(path.strip_prefix("data/").unwrap_or(path)),
        }
    };
    let existing: Vec<String> = m
        .entries
        .iter()
        .filter(|e| e.path != passphrase::ENTRY)
        .map(|e| target(&e.path))
        .filter(|p| p.exists())
        .map(|p| p.display().to_string())
        .collect();
    if !existing.is_empty() && !force {
        return Err(format!(
            "these files exist (stop WrenDNS, then use --force to replace them): {}",
            existing.join(", ")
        ));
    }
    fs::create_dir_all(&data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;
    fs::create_dir_all(&config_dir).map_err(|e| format!("{}: {e}", config_dir.display()))?;
    // REQ: CLU-008 (T6.14) — never restore under a running server.
    let _lock = match crate::datadir::lock(&data_dir, std::time::Duration::ZERO) {
        Ok(l) => Some(l),
        Err(crate::datadir::LockError::Held(holder)) => {
            return Err(format!(
                "WrenDNS is running on {} ({holder}); stop it first",
                data_dir.display()
            ));
        }
        Err(crate::datadir::LockError::Io(_)) => None,
    };
    let stage = data_dir.join(format!(".restore-{}", std::process::id()));
    let _ = fs::remove_dir_all(&stage);
    let result = restore_staged(archive, &m, &stage, &target, &data_dir, (secrets, key_cfg));
    let _ = fs::remove_dir_all(&stage);
    let (files, restored) = result?;
    let secrets_skipped = match secrets {
        SecretsMode::Skip if m.has_secrets() => m.secrets.as_ref().map_or(0, |x| x.count),
        _ => 0,
    };
    Ok(Restored {
        manifest: m,
        data_dir,
        config_dir,
        files,
        secrets: restored,
        secrets_skipped,
    })
}

/// A data-directory key this restore made, removed again if the restore fails before anything
/// moves (a stray key would be there for the next start to find, sealing nothing).
struct NewKey(Option<PathBuf>);

impl NewKey {
    /// The restore went on: the key stays.
    fn keep(&mut self) {
        self.0 = None;
    }
}

impl Drop for NewKey {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = fs::remove_file(p);
        }
    }
}

/// REQ: API-007 (ADR-903 §8, ADR-965 §6) — the node's keys for a restore into `data_dir`: from
/// the environment and the key settings (`-c`'s, else those of the archive's own configuration
/// files, staged in `config_files`: the ones the restored server starts with), else the data
/// directory's own key (made when there is none, and owned like the data directory). A source
/// that is configured but can't be read is an error: nothing is generated in its place. The
/// guard removes a key this call made unless [`NewKey::keep`] is called.
fn restore_keys(
    data_dir: &Path,
    key_cfg: &RestoreKeys<'_>,
    config_files: &[PathBuf],
    owner: Option<(u32, u32)>,
) -> Result<(crate::secrets::Keys, NewKey), String> {
    let staged_cfg;
    let cfg = match key_cfg.cfg {
        Some(c) => Some(c),
        None if !config_files.is_empty() => {
            staged_cfg = crate::server::load_files_quiet(config_files).ok_or_else(|| {
                "the backup's configuration files don't load here, so the key settings in them can't be read: give the configuration with -c FILE, or restore with --skip-secrets".to_owned()
            })?;
            Some(&staged_cfg)
        }
        None => None,
    };
    let mut paths = cfg.map_or_else(
        || crate::secrets::KeyPaths {
            data_dir: data_dir.to_path_buf(),
            key_file: String::new(),
            previous_file: String::new(),
            ephemeral: false,
        },
        crate::secrets::KeyPaths::of,
    );
    if paths.ephemeral {
        return Err("this configuration is a resolver pod's, which holds no stored secrets: restore onto a full member, or use --skip-secrets".to_owned());
    }
    // The key belongs to the node the data is restored onto.
    paths.data_dir = data_dir.to_path_buf();
    let made = paths.uses_data_key(key_cfg.env) && !paths.data_key().exists();
    let keys = crate::secrets::load(&paths, key_cfg.env, true)?;
    let mut guard = NewKey(None);
    if made {
        let key = paths.data_key();
        guard.0 = Some(key.clone());
        // Run as root for a service user, the key would be root's and the service couldn't
        // read it: it is the data directory's owner's, as the restored files are.
        #[cfg(unix)]
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(&key, Some(uid), Some(gid))
                .map_err(|e| format!("{}: {e}", key.display()))?;
        }
    }
    #[cfg(not(unix))]
    let _ = owner;
    Ok((keys, guard))
}

fn restore_staged(
    archive: &Path,
    m: &Manifest,
    stage: &Path,
    target: &dyn Fn(&str) -> PathBuf,
    data_dir: &Path,
    (secrets, key_cfg): (&SecretsMode, &RestoreKeys<'_>),
) -> Result<(usize, Option<RestoredSecrets>), String> {
    // Extract to staging; read_archive checks every hash against the manifest.
    let mut staged = Vec::new();
    let again = read_archive(archive, |path, r| {
        let p = stage.join(path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        io::copy(r, &mut f).map_err(|e| format!("{}: {e}", p.display()))?;
        staged.push(path.to_owned());
        Ok(())
    })?;
    if again != *m {
        return Err(format!(
            "{}: changed while being restored",
            archive.display()
        ));
    }
    // REQ: API-007 (T23.9) — the secrets come out of `secrets.enc` before anything moves: a wrong
    // passphrase, a key that can't be had, or a bad row leaves the machine as it was.
    let mut restored = None;
    let mut key_guard = None;
    // Owned like the data directory (restore usually runs as root for a service user).
    #[cfg(unix)]
    let owner = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(data_dir).ok().map(|md| (md.uid(), md.gid()))
    };
    #[cfg(not(unix))]
    let owner: Option<(u32, u32)> = None;
    if let (true, SecretsMode::Passphrase(pass)) = (m.has_secrets(), secrets)
        && let Some(info) = &m.secrets
    {
        let enc = fs::read(stage.join(passphrase::ENTRY))
            .map_err(|e| format!("{}: {e}", passphrase::ENTRY))?;
        let bind = passphrase::binding(&m.format, m.version, &m.node, &m.entries);
        let rows = passphrase::open(&enc, info, pass, &bind)?;
        let config_files: Vec<PathBuf> = staged
            .iter()
            .filter(|p| p.starts_with("config/"))
            .map(|p| stage.join(p))
            .collect();
        let (keys, new_key) = restore_keys(data_dir, key_cfg, &config_files, owner)?;
        key_guard = Some(new_key);
        let db = stage.join("data/state.db");
        if let Some(parent) = db.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        passphrase::store_rows(&db, &rows, &keys)?;
        if !staged.iter().any(|p| p == "data/state.db") {
            staged.push("data/state.db".to_owned());
        }
        restored = Some(RestoredSecrets {
            count: rows.len(),
            key_source: keys.current.source().to_string(),
            key_id: crate::secrets::hex(&keys.current.key_id()),
        });
    }
    // REQ: API-902 (ADR-956 §4) — a restore brings the guarded entries back and starts the node with
    // them on probation: an address that isn't this machine's must not lock it out for good.
    let restored_db = stage.join("data/state.db");
    if restored_db.is_file() {
        crate::guarded::store::mark_restored(&restored_db);
    }
    // From here files move: a key made for them stays.
    if let Some(g) = key_guard.as_mut() {
        g.keep();
    }
    for path in staged.iter().filter(|p| *p != passphrase::ENTRY) {
        let to = target(path);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let from = stage.join(path);
        if fs::rename(&from, &to).is_err() {
            // Config files may live on another filesystem.
            fs::copy(&from, &to).map_err(|e| format!("{}: {e}", to.display()))?;
        }
        #[cfg(unix)]
        if let Some((uid, gid)) = owner {
            let _ = std::os::unix::fs::chown(&to, Some(uid), Some(gid));
        }
    }
    Ok((staged.len(), restored))
}

#[cfg(test)]
mod secret_tests;
#[cfg(test)]
mod tests;

//! REQ: DSC-902, DSC-906 (T31.2, ADR-1005 sections 2, 3 and 5) - `cmdb.db`: the CMDB's own SQLite
//! database (WAL, mode 0600), never the telemetry database (ADR-006).
//!
//! Two kinds of table share the file. **Authored** data cannot be rebuilt from the sources and is
//! replicated to the standby nodes: the CI registry (`ci`, `ci_key`, `ci_seen`), the manual links
//! and unlinks (`pin`), the merge redirects (`alias`) and the port aliases (`port_alias`). Each row
//! carries a stamp `(epoch, seq)` set by the single writer, and a delete leaves a tombstone in
//! `tomb`. **Derived** data is rebuilt from the sources and stays on the node: the source records
//! (`record`, `seen`, `addr`) and the merge proposals (`proposal`).
//!
//! The store holds no policy. It runs the statements the engine asks for (`telltale` crate,
//! `cmdb`), on one writer connection (one immediate transaction per batch) and one reader
//! connection for the API. Nothing here is on the DNS path.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params, params_from_iter};
use serde::{Deserialize, Serialize};

/// The file name under the data directory.
pub const FILE_NAME: &str = "cmdb.db";
/// The standby copy of the authored tables a replica keeps (applied only if it becomes designated).
pub const STANDBY_NAME: &str = "cmdb-standby.db";
/// The writer's page cache, in KiB (the RSS budget, ADR-1005 section 2: the whole CMDB gets 8 MiB
/// at its caps, and the index takes about 4).
const CACHE_KIB: i64 = 512;
/// The page size of a new database.
const PAGE_SIZE: i64 = 16_384;
/// The reader's page cache, in KiB.
const READER_CACHE_KIB: i64 = 128;

/// Errors from the CMDB database.
#[derive(Debug, thiserror::Error)]
pub enum CmdbError {
    #[error("cmdb database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("cmdb database: {0}")]
    Io(#[from] std::io::Error),
    #[error("cmdb database: {0}")]
    Bad(String),
}

/// A result of this module.
pub type Result<T> = std::result::Result<T, CmdbError>;

/// The schema, applied in order; `meta.schema` records how many ran. T31.3 and T31.4 append their
/// tables (manual values, pins on attributes, mutes, MACD, history) as later migrations.
const MIGRATIONS: &[&str] = &[
    // 1: the registry, the pins, the aliases and the derived records (T31.2).
    "CREATE TABLE ci (
        id TEXT PRIMARY KEY,
        ty TEXT NOT NULL,
        kind TEXT,
        name TEXT,
        parent TEXT,
        flags INTEGER NOT NULL DEFAULT 0,
        first_seen INTEGER NOT NULL,
        epoch INTEGER NOT NULL,
        seq INTEGER NOT NULL
    ) WITHOUT ROWID;
    CREATE INDEX ci_parent ON ci(parent) WHERE parent IS NOT NULL;
    CREATE INDEX ci_ty ON ci(ty);
    CREATE TABLE ci_key (
        kind TEXT NOT NULL,
        value TEXT NOT NULL,
        ci TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        seq INTEGER NOT NULL,
        PRIMARY KEY (kind, value, ci)
    ) WITHOUT ROWID;
    CREATE INDEX ci_key_ci ON ci_key(ci);
    CREATE UNIQUE INDEX ci_key_mac ON ci_key(value) WHERE kind = 'mac';
    CREATE TABLE ci_seen (
        ci TEXT PRIMARY KEY,
        last_seen INTEGER NOT NULL,
        days_seen INTEGER NOT NULL,
        day INTEGER NOT NULL,
        epoch INTEGER NOT NULL,
        seq INTEGER NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE pin (
        kind TEXT NOT NULL,
        a TEXT NOT NULL,
        b TEXT NOT NULL,
        at INTEGER NOT NULL,
        by TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT '',
        epoch INTEGER NOT NULL,
        seq INTEGER NOT NULL,
        PRIMARY KEY (kind, a, b)
    ) WITHOUT ROWID;
    CREATE TABLE alias (
        old TEXT PRIMARY KEY,
        new TEXT NOT NULL,
        until INTEGER NOT NULL,
        epoch INTEGER NOT NULL,
        seq INTEGER NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE port_alias (
        device TEXT NOT NULL,
        source TEXT NOT NULL,
        raw TEXT NOT NULL,
        port TEXT NOT NULL,
        learned INTEGER NOT NULL DEFAULT 1,
        epoch INTEGER NOT NULL,
        seq INTEGER NOT NULL,
        PRIMARY KEY (device, source, raw)
    ) WITHOUT ROWID;
    CREATE TABLE tomb (
        tbl TEXT NOT NULL,
        pk TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        seq INTEGER NOT NULL,
        PRIMARY KEY (tbl, pk)
    ) WITHOUT ROWID;
    CREATE TABLE record (
        rid INTEGER PRIMARY KEY,
        source TEXT NOT NULL,
        skey TEXT NOT NULL,
        ty TEXT NOT NULL,
        attrs TEXT NOT NULL,
        hash INTEGER NOT NULL,
        first_seen INTEGER NOT NULL,
        last_changed INTEGER NOT NULL,
        state TEXT NOT NULL DEFAULT 'present',
        missed INTEGER NOT NULL DEFAULT 0,
        mac TEXT,
        serial TEXT,
        devkey TEXT,
        host TEXT,
        net TEXT,
        owner TEXT,
        port TEXT,
        ici TEXT,
        dci TEXT,
        link TEXT NOT NULL DEFAULT 'none',
        UNIQUE (source, skey)
    );
    CREATE INDEX record_source ON record(source, state);
    CREATE INDEX record_mac ON record(mac) WHERE mac IS NOT NULL;
    CREATE INDEX record_serial ON record(serial) WHERE serial IS NOT NULL;
    CREATE INDEX record_devkey ON record(devkey) WHERE devkey IS NOT NULL;
    CREATE INDEX record_hostnet ON record(host, net) WHERE host IS NOT NULL;
    CREATE INDEX record_owner ON record(owner) WHERE owner IS NOT NULL;
    CREATE INDEX record_dci ON record(dci) WHERE dci IS NOT NULL;
    CREATE INDEX record_ici ON record(ici) WHERE ici IS NOT NULL;
    CREATE TABLE seen (
        rid INTEGER PRIMARY KEY,
        last_seen INTEGER NOT NULL
    );
    CREATE TABLE addr (
        ip TEXT NOT NULL,
        rid INTEGER NOT NULL,
        cls INTEGER NOT NULL,
        PRIMARY KEY (ip, rid)
    ) WITHOUT ROWID;
    CREATE INDEX addr_rid ON addr(rid);
    CREATE TABLE proposal (
        id INTEGER PRIMARY KEY,
        kind TEXT NOT NULL,
        a TEXT NOT NULL,
        b TEXT NOT NULL,
        rule TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT '',
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        state TEXT NOT NULL DEFAULT 'open',
        UNIQUE (kind, a, b)
    );",
];

/// The tables that are authored (replicated), with their columns and the columns of the primary
/// key. A column list is the only text that ever reaches a statement from replication, so the
/// names are checked against it.
pub const REPLICATED: &[(&str, &[&str], &[&str])] = &[
    (
        "ci",
        &["id", "ty", "kind", "name", "parent", "flags", "first_seen"],
        &["id"],
    ),
    ("ci_key", &["kind", "value", "ci"], &["kind", "value", "ci"]),
    ("ci_seen", &["ci", "last_seen", "days_seen", "day"], &["ci"]),
    (
        "pin",
        &["kind", "a", "b", "at", "by", "reason"],
        &["kind", "a", "b"],
    ),
    ("alias", &["old", "new", "until"], &["old"]),
    (
        "port_alias",
        &["device", "source", "raw", "port", "learned"],
        &["device", "source", "raw"],
    ),
];

/// One CI registry row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiRow {
    pub id: String,
    /// `device`, `interface`, `network`, `node`, `service` or `upstream`.
    pub ty: String,
    /// For an interface: `nic` or `port`.
    pub kind: Option<String>,
    pub name: Option<String>,
    /// The device an interface belongs to.
    pub parent: Option<String>,
    pub flags: i64,
    pub first_seen: i64,
}

/// `flags`: the CI has no key and no source that confirms it (ADR-1004 section 4).
pub const FLAG_UNCONFIRMED: i64 = 1;
/// `flags`: a port seen by one source that no alias joins to another source's port.
pub const FLAG_UNMAPPED_PORT: i64 = 2;

/// The CI-level times (ADR-1005 section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenRow {
    pub last_seen: i64,
    /// Distinct days a presence source saw the CI, at most 32.
    pub days_seen: i64,
    /// The day (Unix seconds / 86,400) `days_seen` last advanced.
    pub day: i64,
}

/// A record as it is written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordWrite {
    pub source: String,
    pub skey: String,
    pub ty: String,
    pub attrs: String,
    pub hash: u64,
    pub seen: i64,
    pub mac: Option<String>,
    pub serial: Option<String>,
    pub devkey: Option<String>,
    pub host: Option<String>,
    pub net: Option<String>,
    pub owner: Option<String>,
    pub port: Option<String>,
    /// Class 1 to 3 address bindings: `(address, class)`.
    pub addrs: Vec<(String, u8)>,
}

/// A record as it is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordRow {
    pub rid: i64,
    pub source: String,
    pub skey: String,
    pub ty: String,
    pub attrs: String,
    pub hash: u64,
    pub first_seen: i64,
    pub last_changed: i64,
    pub last_seen: i64,
    pub state: String,
    pub mac: Option<String>,
    pub serial: Option<String>,
    pub devkey: Option<String>,
    pub host: Option<String>,
    pub net: Option<String>,
    pub owner: Option<String>,
    pub port: Option<String>,
    pub ici: Option<String>,
    pub dci: Option<String>,
    pub link: String,
}

const RECORD_COLS: &str = "r.rid, r.source, r.skey, r.ty, r.attrs, r.hash, r.first_seen, \
     r.last_changed, COALESCE(s.last_seen, r.last_changed), r.state, r.mac, r.serial, r.devkey, \
     r.host, r.net, r.owner, r.port, r.ici, r.dci, r.link";
const RECORD_FROM: &str = "record r LEFT JOIN seen s ON s.rid = r.rid";

// -- the attributes' storage form --------------------------------------------------------------

/// The attribute JSON is stored zstd-compressed with a primer of the names it repeats in every
/// record (a raw-content dictionary, no training), so a record of about 500 bytes of JSON takes
/// well under that on disk (AC 5, DSC-906). A text value is plain JSON (a row written before this
/// form, or one that did not shrink) and is read as it is.
const ATTR_PRIMER: &[u8] = b"{\"addresses\":[\"\"],\"ap\":\"\",\"attached_owner\":\"\",\"attached_port\":\"\",\"client_ids\":[\"\"],\"description\":\"\",\"device_key\":\"\",\"firmware\":\"\",\"hostname\":\"\",\"kind\":\"\",\"lldp\":[\"\"],\"mac\":\"aa:bb:cc:dd:ee:ff\",\"member_of\":[\"\"],\"model\":\"\",\"name\":\"\",\"namespace\":\"\",\"network\":\"\",\"owner\":\"\",\"port\":\"\",\"port_id\":\"\",\"role\":\"client\",\"serial\":\"\",\"vlan\":10,\"workload\",\"primary\",\"replica\",\"switch\",\"access point\",\"gateway\",\"192.168.\",\"10.0.\",\"fd00::\",\"home.arpa\",\".local\"}";

/// The most a record's attributes can inflate to (well above the cap on what is written).
const ATTRS_INFLATE_MAX: usize = 64 * 1024;

struct Codec {
    comp: zstd::bulk::Compressor<'static>,
    decomp: zstd::bulk::Decompressor<'static>,
}

fn codec() -> &'static Mutex<Option<Codec>> {
    static CODEC: std::sync::OnceLock<Mutex<Option<Codec>>> = std::sync::OnceLock::new();
    CODEC.get_or_init(|| {
        let made = (|| {
            Some(Codec {
                comp: zstd::bulk::Compressor::with_dictionary(3, ATTR_PRIMER).ok()?,
                decomp: zstd::bulk::Decompressor::with_dictionary(ATTR_PRIMER).ok()?,
            })
        })();
        Mutex::new(made)
    })
}

/// A record's attributes as stored.
fn encode_attrs(json: &str) -> SqlValue {
    let packed = {
        let mut g = codec().lock().unwrap_or_else(PoisonError::into_inner);
        g.as_mut()
            .and_then(|c| c.comp.compress(json.as_bytes()).ok())
    };
    match packed {
        Some(b) if b.len() < json.len() => SqlValue::Blob(b),
        _ => SqlValue::Text(json.to_owned()),
    }
}

/// The attribute JSON of a stored value.
fn decode_attrs(v: ValueRef<'_>) -> String {
    match v {
        ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
        ValueRef::Blob(b) => {
            let out = {
                let mut g = codec().lock().unwrap_or_else(PoisonError::into_inner);
                g.as_mut()
                    .and_then(|c| c.decomp.decompress(b, ATTRS_INFLATE_MAX).ok())
            };
            out.map_or_else(
                || "{}".to_owned(),
                |o| String::from_utf8_lossy(&o).into_owned(),
            )
        }
        _ => "{}".to_owned(),
    }
}

fn record_of(r: &Row<'_>) -> rusqlite::Result<RecordRow> {
    Ok(RecordRow {
        rid: r.get(0)?,
        source: r.get(1)?,
        skey: r.get(2)?,
        ty: r.get(3)?,
        attrs: decode_attrs(r.get_ref(4)?),
        hash: u64::from_ne_bytes(r.get::<_, i64>(5)?.to_ne_bytes()),
        first_seen: r.get(6)?,
        last_changed: r.get(7)?,
        last_seen: r.get(8)?,
        state: r.get(9)?,
        mac: r.get(10)?,
        serial: r.get(11)?,
        devkey: r.get(12)?,
        host: r.get(13)?,
        net: r.get(14)?,
        owner: r.get(15)?,
        port: r.get(16)?,
        ici: r.get(17)?,
        dci: r.get(18)?,
        link: r.get(19)?,
    })
}

/// A manual decision (ADR-1004 section 4, rule R1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    /// `nic_device` (a = MAC, b = device CI), `rec_device` (a = `source\x1fkey`, b = device CI)
    /// or `rec_never` (a = `source\x1fkey`, b = device CI or `*`).
    pub kind: String,
    pub a: String,
    pub b: String,
    pub at: i64,
    pub by: String,
    pub reason: String,
}

/// A merge proposal (ADR-1004 section 4): a disagreement or a hostname match that is not applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Proposal {
    pub id: i64,
    /// `level_disagreement`, `host_network` or `ambiguous_record`.
    pub kind: String,
    pub a: String,
    pub b: String,
    pub rule: String,
    pub detail: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub state: String,
}

/// A row of a replicated table, on the wire between the designated node and a standby.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireRow {
    /// The table.
    pub t: String,
    pub e: i64,
    pub s: i64,
    /// A tombstone: the row `d` names (by its key columns) was deleted.
    #[serde(default)]
    pub del: bool,
    pub d: serde_json::Map<String, serde_json::Value>,
}

/// The database: one writer connection and one reader connection on the same file.
#[derive(Debug)]
pub struct CmdbDb {
    path: PathBuf,
    w: Mutex<Connection>,
    r: Mutex<Connection>,
}

fn tune(conn: &Connection) -> Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    // Records are about 800 bytes: bigger pages waste less at the end of each (only a new file
    // takes the size; an existing one keeps its own).
    conn.pragma_update(None, "page_size", PAGE_SIZE)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "cache_size", -CACHE_KIB)?;
    Ok(())
}

/// Creates the file with mode 0600 before SQLite does (the WAL and the shared-memory file take
/// their mode from it).
fn create_private(path: &Path) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).map(|_| ())
}

impl CmdbDb {
    /// Opens (creating if needed) `path` and applies pending migrations.
    pub fn open(path: &Path) -> Result<Self> {
        create_private(path)?;
        let w = Connection::open(path)?;
        tune(&w)?;
        let r = Connection::open(path)?;
        tune(&r)?;
        // The reader (the API's pages) needs little cache.
        r.pragma_update(None, "cache_size", -READER_CACHE_KIB)?;
        let db = Self {
            path: path.to_path_buf(),
            w: Mutex::new(w),
            r: Mutex::new(r),
        };
        db.migrate()?;
        Ok(db)
    }

    /// The file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn wconn(&self) -> MutexGuard<'_, Connection> {
        self.w.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn migrate(&self) -> Result<()> {
        let mut conn = self.wconn();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            [],
        )?;
        loop {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let done: usize = tx
                .query_row("SELECT value FROM meta WHERE key = 'schema'", [], |r| {
                    r.get::<_, String>(0)
                })
                .optional()?
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let Some(sql) = MIGRATIONS.get(done) else {
                break;
            };
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO meta (key, value) VALUES ('schema', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [done.saturating_add(1).to_string()],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Runs `f` in one immediate transaction on the writer connection. The stamp counter is kept
    /// across transactions in `meta`; a failure rolls everything back.
    pub fn write<T>(&self, f: impl FnOnce(&Ops<'_>) -> Result<T>) -> Result<T> {
        let mut conn = self.wconn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (epoch, seq) = stamp_of(&tx)?;
        let ops = Ops {
            c: &tx,
            epoch,
            seq: Cell::new(seq),
            writable: true,
        };
        let out = f(&ops)?;
        // The stamp counter is written only when a row was stamped: a batch that changed nothing
        // writes nothing (the write-volume bound of a stable network).
        if ops.seq.get() != seq {
            tx.execute(
                "INSERT INTO meta (key, value) VALUES ('seq', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [ops.seq.get().to_string()],
            )?;
        }
        tx.commit()?;
        Ok(out)
    }

    /// Runs `f` on the reader connection (WAL: it sees the last committed state).
    pub fn read<T>(&self, f: impl FnOnce(&Ops<'_>) -> Result<T>) -> Result<T> {
        let conn = self.r.lock().unwrap_or_else(PoisonError::into_inner);
        let ops = Ops {
            c: &conn,
            epoch: 0,
            seq: Cell::new(0),
            writable: false,
        };
        f(&ops)
    }

    /// `PRAGMA wal_checkpoint(TRUNCATE)`; `false` when another connection kept it from finishing.
    pub fn checkpoint(&self) -> Result<bool> {
        let conn = self.wconn();
        let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
        Ok(busy == 0)
    }

    /// Rows inserted, updated or deleted through the writer connection since it opened (the
    /// write-volume test counts them).
    pub fn total_changes(&self) -> u64 {
        self.wconn().total_changes()
    }

    /// Sets the WAL auto-checkpoint, in pages (0 turns it off). The write-volume test turns it off
    /// so the WAL's size is the bytes written; production keeps SQLite's default.
    pub fn set_autocheckpoint(&self, pages: i64) -> Result<()> {
        self.wconn()
            .pragma_update(None, "wal_autocheckpoint", pages)?;
        Ok(())
    }

    /// The size of the database file and its WAL, in bytes.
    pub fn disk_bytes(&self) -> u64 {
        let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
        let mut wal = self.path.clone().into_os_string();
        wal.push("-wal");
        size(&self.path).saturating_add(size(Path::new(&wal)))
    }

    /// Bytes SQLite has written to the file and its WAL (page writes), for the write-volume test:
    /// the page count of the database plus the WAL's frames is not a counter, so the test reads the
    /// sizes instead. See [`CmdbDb::disk_bytes`].
    pub fn page_size(&self) -> i64 {
        self.wconn()
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .unwrap_or(4096)
    }
}

fn meta_i64(c: &Connection, key: &str) -> rusqlite::Result<Option<i64>> {
    Ok(
        c.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| {
            r.get::<_, String>(0)
        })
        .optional()?
        .and_then(|v| v.parse().ok()),
    )
}

fn stamp_of(c: &Connection) -> rusqlite::Result<(i64, i64)> {
    Ok((
        meta_i64(c, "epoch")?.unwrap_or(1),
        meta_i64(c, "seq")?.unwrap_or(0),
    ))
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// The statements, on a connection: a transaction (writes) or the reader.
#[derive(Debug)]
pub struct Ops<'a> {
    c: &'a Connection,
    epoch: i64,
    seq: Cell<i64>,
    writable: bool,
}

impl Ops<'_> {
    fn stamp(&self) -> (i64, i64) {
        let s = self.seq.get().saturating_add(1);
        self.seq.set(s);
        (self.epoch, s)
    }

    fn need_write(&self) -> Result<()> {
        if self.writable {
            Ok(())
        } else {
            Err(CmdbError::Bad("a read connection cannot write".into()))
        }
    }

    // -- meta ------------------------------------------------------------------------------

    /// A value from `meta`.
    pub fn meta_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .c
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    /// Sets a value in `meta`.
    pub fn meta_set(&self, key: &str, value: &str) -> Result<()> {
        self.need_write()?;
        self.c.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// The writer's current stamp `(epoch, seq)`.
    pub fn head(&self) -> Result<(i64, i64)> {
        Ok(stamp_of(self.c)?)
    }

    /// This transaction's epoch (the writer's).
    pub fn epoch(&self) -> i64 {
        self.epoch
    }

    /// Starts a new epoch (a node that becomes the writer after a failover, ADR-1005 section 6).
    pub fn set_epoch(&self, epoch: i64) -> Result<()> {
        self.meta_set("epoch", &epoch.to_string())
    }

    // -- the registry ----------------------------------------------------------------------

    /// One CI.
    pub fn ci_get(&self, id: &str) -> Result<Option<CiRow>> {
        Ok(self
            .c
            .query_row(
                "SELECT id, ty, kind, name, parent, flags, first_seen FROM ci WHERE id = ?1",
                [id],
                ci_of,
            )
            .optional()?)
    }

    /// Writes a CI (insert, or replace the row).
    pub fn ci_put(&self, ci: &CiRow) -> Result<()> {
        self.need_write()?;
        let (e, s) = self.stamp();
        self.c.execute(
            "INSERT INTO ci (id, ty, kind, name, parent, flags, first_seen, epoch, seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET ty = excluded.ty, kind = excluded.kind,
               name = excluded.name, parent = excluded.parent, flags = excluded.flags,
               first_seen = excluded.first_seen, epoch = excluded.epoch, seq = excluded.seq",
            params![
                ci.id,
                ci.ty,
                ci.kind,
                ci.name,
                ci.parent,
                ci.flags,
                ci.first_seen,
                e,
                s
            ],
        )?;
        self.c
            .execute("DELETE FROM tomb WHERE tbl = 'ci' AND pk = ?1", [&ci.id])?;
        Ok(())
    }

    /// Deletes a CI with its keys, its times, its port aliases and the pins that name it, leaving
    /// tombstones for the standbys. Records that were linked to it are unlinked.
    pub fn ci_delete(&self, id: &str) -> Result<()> {
        self.need_write()?;
        for key in self.keys_of(id)? {
            self.key_del(&key.0, &key.1, id)?;
        }
        let (e, s) = self.stamp();
        self.c.execute("DELETE FROM ci WHERE id = ?1", [id])?;
        self.tomb(("ci", id), (e, s))?;
        if self.c.execute("DELETE FROM ci_seen WHERE ci = ?1", [id])? > 0 {
            let (e, s) = self.stamp();
            self.tomb(("ci_seen", id), (e, s))?;
        }
        let aliases: Vec<(String, String, String)> = {
            let mut st = self.c.prepare(
                "SELECT device, source, raw FROM port_alias WHERE device = ?1 OR port = ?1",
            )?;
            st.query_map([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        for (device, source, raw) in aliases {
            self.port_alias_del(&device, &source, &raw)?;
        }
        self.c.execute(
            "UPDATE record SET dci = NULL, link = 'none' WHERE dci = ?1",
            [id],
        )?;
        self.c
            .execute("UPDATE record SET ici = NULL WHERE ici = ?1", [id])?;
        Ok(())
    }

    fn tomb(&self, key: (&str, &str), stamp: (i64, i64)) -> Result<()> {
        self.c.execute(
            "INSERT INTO tomb (tbl, pk, epoch, seq) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(tbl, pk) DO UPDATE SET epoch = excluded.epoch, seq = excluded.seq",
            params![key.0, key.1, stamp.0, stamp.1],
        )?;
        Ok(())
    }

    /// The number of CIs, and of those of one type.
    pub fn ci_count(&self, ty: Option<&str>) -> Result<i64> {
        Ok(match ty {
            Some(t) => self
                .c
                .query_row("SELECT COUNT(*) FROM ci WHERE ty = ?1", [t], |r| r.get(0))?,
            None => self
                .c
                .query_row("SELECT COUNT(*) FROM ci", [], |r| r.get(0))?,
        })
    }

    /// The CIs of a device (its interfaces).
    pub fn ci_children(&self, parent: &str) -> Result<Vec<CiRow>> {
        let mut st = self.c.prepare(
            "SELECT id, ty, kind, name, parent, flags, first_seen FROM ci WHERE parent = ?1
             ORDER BY first_seen, id",
        )?;
        Ok(st
            .query_map([parent], ci_of)?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// A page of CIs for the API: filtered by type and by a text that matches the name, the id,
    /// a key, or a linked record's name, after the cursor `after` (an id), at most `limit`.
    pub fn ci_list(
        &self,
        ty: Option<&str>,
        q: Option<&str>,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<CiRow>> {
        self.ci_list_in(ty, false, true, q, after, limit)
    }

    /// [`Ops::ci_list`], optionally leaving the interfaces out (the default list shows a device
    /// with its interfaces under it).
    pub fn ci_list_in(
        &self,
        ty: Option<&str>,
        top_level: bool,
        by_name: bool,
        q: Option<&str>,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<CiRow>> {
        let mut sql = String::from(
            "SELECT c.id, c.ty, c.kind, c.name, c.parent, c.flags, c.first_seen FROM ci c WHERE 1 = 1",
        );
        let mut args: Vec<SqlValue> = Vec::new();
        if let Some(t) = ty {
            sql.push_str(" AND c.ty = ?");
            args.push(SqlValue::Text(t.to_owned()));
        }
        if top_level {
            sql.push_str(" AND c.ty != 'interface'");
        }
        if let Some(a) = after {
            sql.push_str(" AND c.id > ?");
            args.push(SqlValue::Text(a.to_owned()));
        }
        if let Some(q) = q.map(str::trim).filter(|q| !q.is_empty()) {
            let like = format!("%{}%", like_escape(&q.to_ascii_lowercase()));
            // `by_name` false (privacy level 1): ids, MACs, keys and addresses only, so a search cannot
            // confirm that a name exists (ADR-1005 section 12).
            if by_name {
                sql.push_str(
                    " AND (lower(COALESCE(c.name, '')) LIKE ? ESCAPE '\\' OR c.id LIKE ? ESCAPE '\\'
                   OR EXISTS (SELECT 1 FROM ci_key k WHERE k.ci = c.id AND k.value LIKE ? ESCAPE '\\')
                   OR EXISTS (SELECT 1 FROM ci i JOIN ci_key k ON k.ci = i.id
                      WHERE i.parent = c.id AND k.value LIKE ? ESCAPE '\\')
                   OR EXISTS (SELECT 1 FROM record r WHERE (r.dci = c.id OR r.ici = c.id)
                      AND r.host LIKE ? ESCAPE '\\')
                   OR EXISTS (SELECT 1 FROM record r JOIN addr a ON a.rid = r.rid
                      WHERE (r.dci = c.id OR r.ici = c.id) AND a.ip LIKE ? ESCAPE '\\'))",
                );
                for _ in 0..6 {
                    args.push(SqlValue::Text(like.clone()));
                }
            } else {
                sql.push_str(
                    " AND (c.id LIKE ? ESCAPE '\\'
                   OR EXISTS (SELECT 1 FROM ci_key k WHERE k.ci = c.id AND k.value LIKE ? ESCAPE '\\')
                   OR EXISTS (SELECT 1 FROM ci i JOIN ci_key k ON k.ci = i.id
                      WHERE i.parent = c.id AND k.value LIKE ? ESCAPE '\\')
                   OR EXISTS (SELECT 1 FROM record r JOIN addr a ON a.rid = r.rid
                      WHERE (r.dci = c.id OR r.ici = c.id) AND a.ip LIKE ? ESCAPE '\\'))",
                );
                for _ in 0..4 {
                    args.push(SqlValue::Text(like.clone()));
                }
            }
        }
        sql.push_str(" ORDER BY c.id LIMIT ?");
        args.push(SqlValue::Integer(limit.clamp(1, 500)));
        let mut st = self.c.prepare(&sql)?;
        Ok(st
            .query_map(params_from_iter(args), ci_of)?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// CIs oldest-seen first among those eligible for eviction: no present record points at them.
    /// The caller decides what else makes a CI authored.
    pub fn ci_eviction_candidates(&self, limit: i64) -> Result<Vec<String>> {
        let mut st = self.c.prepare(
            "SELECT c.id FROM ci c LEFT JOIN ci_seen s ON s.ci = c.id
             WHERE NOT EXISTS (SELECT 1 FROM record r WHERE (r.dci = c.id OR r.ici = c.id)
                               AND r.state = 'present')
               AND NOT EXISTS (SELECT 1 FROM ci i WHERE i.parent = c.id)
             ORDER BY (c.flags & 1) DESC, COALESCE(s.last_seen, c.first_seen), c.id
             LIMIT ?1",
        )?;
        Ok(st
            .query_map([limit], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    // -- keys ------------------------------------------------------------------------------

    /// The CIs holding a key.
    pub fn key_find(&self, kind: &str, value: &str) -> Result<Vec<String>> {
        let mut st = self
            .c
            .prepare("SELECT ci FROM ci_key WHERE kind = ?1 AND value = ?2 ORDER BY ci")?;
        Ok(st
            .query_map(params![kind, value], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// Adds a key to a CI (idempotent).
    pub fn key_add(&self, kind: &str, value: &str, ci: &str) -> Result<()> {
        self.need_write()?;
        if self
            .c
            .query_row(
                "SELECT 1 FROM ci_key WHERE kind = ?1 AND value = ?2 AND ci = ?3",
                params![kind, value, ci],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Ok(());
        }
        let (e, s) = self.stamp();
        self.c.execute(
            "INSERT INTO ci_key (kind, value, ci, epoch, seq) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![kind, value, ci, e, s],
        )?;
        Ok(())
    }

    /// Removes a key from a CI.
    pub fn key_del(&self, kind: &str, value: &str, ci: &str) -> Result<()> {
        self.need_write()?;
        if self.c.execute(
            "DELETE FROM ci_key WHERE kind = ?1 AND value = ?2 AND ci = ?3",
            params![kind, value, ci],
        )? > 0
        {
            let (e, s) = self.stamp();
            self.tomb(("ci_key", &format!("{kind}\x1f{value}\x1f{ci}")), (e, s))?;
        }
        Ok(())
    }

    /// Every `(kind, value)` a CI holds.
    pub fn keys_of(&self, ci: &str) -> Result<Vec<(String, String)>> {
        let mut st = self
            .c
            .prepare("SELECT kind, value FROM ci_key WHERE ci = ?1 ORDER BY kind, value")?;
        Ok(st
            .query_map([ci], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }

    // -- CI-level times --------------------------------------------------------------------

    /// A CI's times.
    pub fn seen_get(&self, ci: &str) -> Result<Option<SeenRow>> {
        Ok(self
            .c
            .query_row(
                "SELECT last_seen, days_seen, day FROM ci_seen WHERE ci = ?1",
                [ci],
                |r| {
                    Ok(SeenRow {
                        last_seen: r.get(0)?,
                        days_seen: r.get(1)?,
                        day: r.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    /// Writes a CI's times.
    pub fn seen_put(&self, ci: &str, row: SeenRow) -> Result<()> {
        self.need_write()?;
        let (e, s) = self.stamp();
        self.c.execute(
            "INSERT INTO ci_seen (ci, last_seen, days_seen, day, epoch, seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(ci) DO UPDATE SET last_seen = excluded.last_seen,
               days_seen = excluded.days_seen, day = excluded.day,
               epoch = excluded.epoch, seq = excluded.seq",
            params![ci, row.last_seen, row.days_seen, row.day, e, s],
        )?;
        Ok(())
    }

    // -- records ---------------------------------------------------------------------------

    /// The record a source holds under a key.
    pub fn record_get(&self, source: &str, skey: &str) -> Result<Option<RecordRow>> {
        Ok(self
            .c
            .query_row(
                &format!(
                    "SELECT {RECORD_COLS} FROM {RECORD_FROM} WHERE r.source = ?1 AND r.skey = ?2"
                ),
                params![source, skey],
                record_of,
            )
            .optional()?)
    }

    /// One record by id.
    pub fn record_by_id(&self, rid: i64) -> Result<Option<RecordRow>> {
        Ok(self
            .c
            .query_row(
                &format!("SELECT {RECORD_COLS} FROM {RECORD_FROM} WHERE r.rid = ?1"),
                [rid],
                record_of,
            )
            .optional()?)
    }

    /// Inserts or replaces a record: its content, keys and addresses. Returns the row id and the
    /// previous row (its old keys are seeds for the next resolution). The link columns are kept
    /// until the engine rewrites them. `first_seen` only moves earlier.
    pub fn record_upsert(&self, w: &RecordWrite) -> Result<(i64, Option<RecordRow>)> {
        self.need_write()?;
        let old = self.record_get(&w.source, &w.skey)?;
        let hash = i64::from_ne_bytes(w.hash.to_ne_bytes());
        let rid = if let Some(o) = &old {
            self.c.execute(
                "UPDATE record SET ty = ?2, attrs = ?3, hash = ?4, first_seen = MIN(first_seen, ?5),
                   last_changed = ?5, state = 'present', missed = 0, mac = ?6, serial = ?7, devkey = ?8,
                   host = ?9, net = ?10, owner = ?11, port = ?12 WHERE rid = ?1",
                params![
                    o.rid, w.ty, encode_attrs(&w.attrs), hash, w.seen, w.mac, w.serial, w.devkey, w.host, w.net,
                    w.owner, w.port
                ],
            )?;
            o.rid
        } else {
            self.c.execute(
                "INSERT INTO record (source, skey, ty, attrs, hash, first_seen, last_changed, state,
                   mac, serial, devkey, host, net, owner, port)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 'present', ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    w.source, w.skey, w.ty, encode_attrs(&w.attrs), hash, w.seen, w.mac, w.serial, w.devkey,
                    w.host, w.net, w.owner, w.port
                ],
            )?;
            self.c.last_insert_rowid()
        };
        self.c.execute(
            "INSERT INTO seen (rid, last_seen) VALUES (?1, ?2)
             ON CONFLICT(rid) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen)",
            params![rid, w.seen],
        )?;
        self.c.execute("DELETE FROM addr WHERE rid = ?1", [rid])?;
        for (ip, cls) in &w.addrs {
            self.c.execute(
                "INSERT OR IGNORE INTO addr (ip, rid, cls) VALUES (?1, ?2, ?3)",
                params![ip, rid, cls],
            )?;
        }
        Ok((rid, old))
    }

    /// Sets a record's link columns (only when they change).
    pub fn record_link(
        &self,
        rid: i64,
        ici: Option<&str>,
        dci: Option<&str>,
        link: &str,
    ) -> Result<bool> {
        self.need_write()?;
        Ok(self.c.execute(
            "UPDATE record SET ici = ?2, dci = ?3, link = ?4
             WHERE rid = ?1 AND (ici IS NOT ?2 OR dci IS NOT ?3 OR link != ?4)",
            params![rid, ici, dci, link],
        )? > 0)
    }

    /// Sets a record's state (`present` or `absent`); either way the misses start again.
    pub fn record_state(&self, rid: i64, state: &str) -> Result<()> {
        self.need_write()?;
        self.c.execute(
            "UPDATE record SET state = ?2, missed = 0 WHERE rid = ?1",
            params![rid, state],
        )?;
        Ok(())
    }

    /// Deletes a record with its times and addresses.
    pub fn record_delete(&self, rid: i64) -> Result<()> {
        self.need_write()?;
        self.c.execute("DELETE FROM seen WHERE rid = ?1", [rid])?;
        self.c.execute("DELETE FROM addr WHERE rid = ?1", [rid])?;
        self.c.execute("DELETE FROM record WHERE rid = ?1", [rid])?;
        Ok(())
    }

    /// Flushes `last_seen` for records, in the one transaction (the batched write).
    pub fn seen_flush(&self, rows: &[(i64, i64)]) -> Result<()> {
        self.need_write()?;
        let mut st = self.c.prepare(
            "INSERT INTO seen (rid, last_seen) VALUES (?1, ?2)
             ON CONFLICT(rid) DO UPDATE SET last_seen = excluded.last_seen
             WHERE excluded.last_seen > last_seen",
        )?;
        for (rid, at) in rows {
            st.execute(params![rid, at])?;
        }
        Ok(())
    }

    /// The records that carry any of these keys (each list is looked up with an index).
    pub fn records_by_keys(
        &self,
        macs: &[String],
        serials: &[String],
        devkeys: &[String],
    ) -> Result<Vec<RecordRow>> {
        let mut out: Vec<RecordRow> = Vec::new();
        for (col, vals) in [("mac", macs), ("serial", serials), ("devkey", devkeys)] {
            for chunk in vals.chunks(200) {
                let marks = vec!["?"; chunk.len()].join(",");
                let sql =
                    format!("SELECT {RECORD_COLS} FROM {RECORD_FROM} WHERE r.{col} IN ({marks})");
                let mut st = self.c.prepare(&sql)?;
                let rows = st.query_map(params_from_iter(chunk.iter()), record_of)?;
                for r in rows {
                    out.push(r?);
                }
            }
        }
        out.sort_by_key(|r| r.rid);
        out.dedup_by_key(|r| r.rid);
        Ok(out)
    }

    /// The records linked to a CI at either level.
    pub fn records_of_ci(&self, ci: &str) -> Result<Vec<RecordRow>> {
        let mut st = self.c.prepare(&format!(
            "SELECT {RECORD_COLS} FROM {RECORD_FROM} WHERE r.dci = ?1 OR r.ici = ?1
             ORDER BY r.source, r.skey"
        ))?;
        Ok(st
            .query_map([ci], record_of)?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// The records of one source, by key order.
    pub fn records_of_source(&self, source: &str) -> Result<Vec<RecordRow>> {
        let mut st = self.c.prepare(&format!(
            "SELECT {RECORD_COLS} FROM {RECORD_FROM} WHERE r.source = ?1 ORDER BY r.skey"
        ))?;
        Ok(st
            .query_map([source], record_of)?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// Port records whose owner (the device record's key) is one of `owners`.
    pub fn records_by_owner(&self, owners: &[String]) -> Result<Vec<RecordRow>> {
        let mut out: Vec<RecordRow> = Vec::new();
        for chunk in owners.chunks(200) {
            let marks = vec!["?"; chunk.len()].join(",");
            let mut st = self.c.prepare(&format!(
                "SELECT {RECORD_COLS} FROM {RECORD_FROM} WHERE r.owner IN ({marks})"
            ))?;
            for r in st.query_map(params_from_iter(chunk.iter()), record_of)? {
                out.push(r?);
            }
        }
        out.sort_by_key(|r| r.rid);
        Ok(out)
    }

    /// The records of one type that carry no MAC, serial or device key (the keyless ones) and an
    /// address in the list.
    pub fn keyless_by_addr(&self, ips: &[String]) -> Result<Vec<RecordRow>> {
        let mut out: Vec<RecordRow> = Vec::new();
        for chunk in ips.chunks(200) {
            let marks = vec!["?"; chunk.len()].join(",");
            let mut st = self.c.prepare(&format!(
                "SELECT {RECORD_COLS} FROM {RECORD_FROM}
                 WHERE r.rid IN (SELECT rid FROM addr WHERE ip IN ({marks}))
                   AND r.mac IS NULL AND r.serial IS NULL AND r.devkey IS NULL
                   AND r.owner IS NULL AND r.ty = 'device'"
            ))?;
            for r in st.query_map(params_from_iter(chunk.iter()), record_of)? {
                out.push(r?);
            }
        }
        out.sort_by_key(|r| r.rid);
        out.dedup_by_key(|r| r.rid);
        Ok(out)
    }

    /// The keyed records (class 1 to 3 bindings) that hold an address: `(record, class)`.
    pub fn addr_holders(&self, ip: &str) -> Result<Vec<(RecordRow, u8)>> {
        let mut st = self.c.prepare(&format!(
            "SELECT {RECORD_COLS}, a.cls FROM addr a JOIN record r ON r.rid = a.rid
             LEFT JOIN seen s ON s.rid = r.rid WHERE a.ip = ?1
               AND (r.mac IS NOT NULL OR r.serial IS NOT NULL OR r.devkey IS NOT NULL)
             ORDER BY r.rid"
        ))?;
        let rows = st.query_map([ip], |r| {
            let rec = record_of(r)?;
            let cls: i64 = r.get(20)?;
            Ok((rec, u8::try_from(cls).unwrap_or(9)))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The addresses a record holds.
    pub fn addrs_of(&self, rid: i64) -> Result<Vec<String>> {
        let mut st = self
            .c
            .prepare("SELECT ip FROM addr WHERE rid = ?1 ORDER BY ip")?;
        Ok(st
            .query_map([rid], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// Records sharing a hostname and a network with `host` and `net` (for rule R5).
    pub fn records_by_hostnet(&self, host: &str, net: &str) -> Result<Vec<RecordRow>> {
        let mut st = self.c.prepare(&format!(
            "SELECT {RECORD_COLS} FROM {RECORD_FROM} WHERE r.host = ?1 AND r.net = ?2 AND r.ty = 'device'
             ORDER BY r.rid"
        ))?;
        Ok(st
            .query_map(params![host, net], record_of)?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// `(total, present)` records.
    pub fn record_counts(&self) -> Result<(i64, i64)> {
        Ok(self.c.query_row(
            "SELECT COUNT(*), COALESCE(SUM(state = 'present'), 0) FROM record",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    /// Records per source and state.
    pub fn record_counts_by_source(&self) -> Result<Vec<(String, i64, i64)>> {
        let mut st = self.c.prepare(
            "SELECT source, COUNT(*), COALESCE(SUM(state = 'present'), 0) FROM record
             GROUP BY source ORDER BY source",
        )?;
        Ok(st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// The oldest `absent` records, to make room (oldest `last_seen` first).
    pub fn oldest_absent_records(&self, limit: i64) -> Result<Vec<i64>> {
        let mut st = self.c.prepare(
            "SELECT r.rid FROM record r LEFT JOIN seen s ON s.rid = r.rid
             WHERE r.state = 'absent' ORDER BY COALESCE(s.last_seen, r.last_changed), r.rid LIMIT ?1",
        )?;
        Ok(st
            .query_map([limit], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// The oldest `absent` record of a CI.
    pub fn oldest_absent_of_ci(&self, ci: &str) -> Result<Option<i64>> {
        Ok(self
            .c
            .query_row(
                "SELECT r.rid FROM record r LEFT JOIN seen s ON s.rid = r.rid
                 WHERE (r.dci = ?1 OR r.ici = ?1) AND r.state = 'absent'
                 ORDER BY COALESCE(s.last_seen, r.last_changed), r.rid LIMIT 1",
                [ci],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// How many records a CI holds at its own level: an interface holds the records of its MAC, a
    /// device the records linked to it that name no interface (the 8-per-CI cap counts these).
    pub fn record_count_at_level(&self, ci: &str) -> Result<i64> {
        Ok(self.c.query_row(
            "SELECT COUNT(*) FROM record WHERE ici = ?1 OR (dci = ?1 AND ici IS NULL)",
            [ci],
            |r| r.get(0),
        )?)
    }

    /// The oldest `absent` record a CI holds at its own level.
    pub fn oldest_absent_at_level(&self, ci: &str) -> Result<Option<i64>> {
        Ok(self
            .c
            .query_row(
                "SELECT r.rid FROM record r LEFT JOIN seen s ON s.rid = r.rid
                 WHERE (r.ici = ?1 OR (r.dci = ?1 AND r.ici IS NULL)) AND r.state = 'absent'
                 ORDER BY COALESCE(s.last_seen, r.last_changed), r.rid LIMIT 1",
                [ci],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// How many records a CI holds.
    pub fn record_count_of_ci(&self, ci: &str) -> Result<i64> {
        Ok(self.c.query_row(
            "SELECT COUNT(*) FROM record WHERE dci = ?1 OR ici = ?1",
            [ci],
            |r| r.get(0),
        )?)
    }

    /// Records older than the cutoffs, by state: derived-only records not seen since `weak_before`
    /// (Unix seconds) and imports not seen since `import_before` (the ADR-924 retention).
    pub fn records_expired(
        &self,
        before: i64,
        include_like: &str,
        exclude_like: &str,
    ) -> Result<Vec<i64>> {
        let mut st = self.c.prepare(
            "SELECT r.rid FROM record r LEFT JOIN seen s ON s.rid = r.rid
             WHERE r.state = 'absent' AND COALESCE(s.last_seen, r.last_changed) < ?1
               AND r.source LIKE ?2 AND r.source NOT LIKE ?3",
        )?;
        Ok(st
            .query_map(params![before, include_like, exclude_like], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    // -- pins ------------------------------------------------------------------------------

    /// Sets a pin (replacing the same key). A `nic_device` and a `rec_device` pin are one per
    /// subject: a new one replaces the old.
    pub fn pin_set(&self, pin: &Pin) -> Result<()> {
        self.need_write()?;
        if pin.kind == "nic_device" || pin.kind == "rec_device" {
            let old: Vec<String> = {
                let mut st = self
                    .c
                    .prepare("SELECT b FROM pin WHERE kind = ?1 AND a = ?2 AND b != ?3")?;
                st.query_map(params![pin.kind, pin.a, pin.b], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?
            };
            for b in old {
                self.pin_del(&pin.kind, &pin.a, &b)?;
            }
        }
        let (e, s) = self.stamp();
        self.c.execute(
            "INSERT INTO pin (kind, a, b, at, by, reason, epoch, seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(kind, a, b) DO UPDATE SET at = excluded.at, by = excluded.by,
               reason = excluded.reason, epoch = excluded.epoch, seq = excluded.seq",
            params![pin.kind, pin.a, pin.b, pin.at, pin.by, pin.reason, e, s],
        )?;
        self.c.execute(
            "DELETE FROM tomb WHERE tbl = 'pin' AND pk = ?1",
            [format!("{}\x1f{}\x1f{}", pin.kind, pin.a, pin.b)],
        )?;
        Ok(())
    }

    /// Removes a pin.
    pub fn pin_del(&self, kind: &str, a: &str, b: &str) -> Result<()> {
        self.need_write()?;
        if self.c.execute(
            "DELETE FROM pin WHERE kind = ?1 AND a = ?2 AND b = ?3",
            params![kind, a, b],
        )? > 0
        {
            let (e, s) = self.stamp();
            self.tomb(("pin", &format!("{kind}\x1f{a}\x1f{b}")), (e, s))?;
        }
        Ok(())
    }

    /// Every pin.
    pub fn pins(&self) -> Result<Vec<Pin>> {
        let mut st = self
            .c
            .prepare("SELECT kind, a, b, at, by, reason FROM pin ORDER BY kind, a, b")?;
        Ok(st
            .query_map([], |r| {
                Ok(Pin {
                    kind: r.get(0)?,
                    a: r.get(1)?,
                    b: r.get(2)?,
                    at: r.get(3)?,
                    by: r.get(4)?,
                    reason: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// The pins that name a CI as their target, or a MAC that belongs to it.
    pub fn pins_naming(&self, ci: &str) -> Result<Vec<Pin>> {
        Ok(self
            .pins()?
            .into_iter()
            .filter(|p| p.b == ci)
            .collect::<Vec<_>>())
    }

    /// Re-points the pins whose target is `from` at `to` (a merge).
    pub fn pins_retarget(&self, from: &str, to: &str) -> Result<()> {
        self.need_write()?;
        for p in self.pins()?.into_iter().filter(|p| p.b == from) {
            self.pin_del(&p.kind, &p.a, &p.b)?;
            self.pin_set(&Pin {
                b: to.to_owned(),
                ..p
            })?;
        }
        Ok(())
    }

    // -- aliases ---------------------------------------------------------------------------

    /// Records that `old` was merged into `new` until `until`.
    pub fn alias_set(&self, old: &str, new: &str, until: i64) -> Result<()> {
        self.need_write()?;
        let (e, s) = self.stamp();
        self.c.execute(
            "INSERT INTO alias (old, new, until, epoch, seq) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(old) DO UPDATE SET new = excluded.new, until = excluded.until,
               epoch = excluded.epoch, seq = excluded.seq",
            params![old, new, until, e, s],
        )?;
        // Aliases that pointed at the one now merged follow it.
        self.c.execute(
            "UPDATE alias SET new = ?2, epoch = ?3, seq = ?4 WHERE new = ?1 AND old != ?1",
            params![old, new, e, s],
        )?;
        Ok(())
    }

    /// Where an id leads now: the id itself when it is live, or the CI it was merged into
    /// (following at most 8 redirects), or `None` when it is neither.
    pub fn resolve_id(&self, id: &str, now: i64) -> Result<Option<String>> {
        let mut cur = id.to_owned();
        for _ in 0..8 {
            if self.ci_get(&cur)?.is_some() {
                return Ok(Some(cur));
            }
            let next: Option<String> = self
                .c
                .query_row(
                    "SELECT new FROM alias WHERE old = ?1 AND until > ?2",
                    params![cur, now],
                    |r| r.get(0),
                )
                .optional()?;
            match next {
                Some(n) => cur = n,
                None => return Ok(None),
            }
        }
        Ok(None)
    }

    /// Drops the aliases whose time has passed.
    pub fn alias_expire(&self, now: i64) -> Result<usize> {
        self.need_write()?;
        // A replica expires them on its own clock, so no tombstone is needed.
        Ok(self
            .c
            .execute("DELETE FROM alias WHERE until <= ?1", [now])?)
    }

    /// The aliases, newest first.
    pub fn aliases(&self) -> Result<Vec<(String, String, i64)>> {
        let mut st = self
            .c
            .prepare("SELECT old, new, until FROM alias ORDER BY until DESC, old")?;
        Ok(st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }

    // -- port aliases ----------------------------------------------------------------------

    /// The port CI a source's raw port id is aliased to on a device.
    pub fn port_alias_get(&self, device: &str, source: &str, raw: &str) -> Result<Option<String>> {
        Ok(self
            .c
            .query_row(
                "SELECT port FROM port_alias WHERE device = ?1 AND source = ?2 AND raw = ?3",
                params![device, source, raw],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Sets a port alias.
    pub fn port_alias_set(
        &self,
        device: &str,
        source: &str,
        raw: &str,
        port: &str,
        learned: bool,
    ) -> Result<()> {
        self.need_write()?;
        let (e, s) = self.stamp();
        self.c.execute(
            "INSERT INTO port_alias (device, source, raw, port, learned, epoch, seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(device, source, raw) DO UPDATE SET port = excluded.port,
               learned = excluded.learned, epoch = excluded.epoch, seq = excluded.seq",
            params![device, source, raw, port, i64::from(learned), e, s],
        )?;
        Ok(())
    }

    /// Removes a port alias.
    pub fn port_alias_del(&self, device: &str, source: &str, raw: &str) -> Result<()> {
        self.need_write()?;
        if self.c.execute(
            "DELETE FROM port_alias WHERE device = ?1 AND source = ?2 AND raw = ?3",
            params![device, source, raw],
        )? > 0
        {
            let (e, s) = self.stamp();
            self.tomb(
                ("port_alias", &format!("{device}\x1f{source}\x1f{raw}")),
                (e, s),
            )?;
        }
        Ok(())
    }

    /// The port aliases of a device: `(source, raw, port)`.
    pub fn port_aliases_of(&self, device: &str) -> Result<Vec<(String, String, String)>> {
        let mut st = self.c.prepare(
            "SELECT source, raw, port FROM port_alias WHERE device = ?1 ORDER BY source, raw",
        )?;
        Ok(st
            .query_map([device], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }

    // -- proposals -------------------------------------------------------------------------

    /// Raises a proposal, or refreshes the open one; a dismissed or applied one stays as it is.
    pub fn proposal_raise(
        &self,
        kind: &str,
        a: &str,
        b: &str,
        rule: &str,
        detail: &str,
        now: i64,
    ) -> Result<()> {
        self.need_write()?;
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        self.c.execute(
            "INSERT INTO proposal (kind, a, b, rule, detail, first_seen, last_seen, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 'open')
             ON CONFLICT(kind, a, b) DO UPDATE SET last_seen = excluded.last_seen,
               rule = excluded.rule, detail = excluded.detail",
            params![kind, a, b, rule, detail, now],
        )?;
        Ok(())
    }

    /// Deletes the open proposal of a pair (reconciliation no longer finds it).
    pub fn proposal_drop_open(&self, kind: &str, a: &str, b: &str) -> Result<()> {
        self.need_write()?;
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        self.c.execute(
            "DELETE FROM proposal WHERE kind = ?1 AND a = ?2 AND b = ?3 AND state = 'open'",
            params![kind, a, b],
        )?;
        Ok(())
    }

    /// Closes the proposals of a pair (a person acted: `applied`, or `dismissed`).
    pub fn proposal_close(&self, kind: &str, a: &str, b: &str, state: &str) -> Result<()> {
        self.need_write()?;
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        self.c.execute(
            "UPDATE proposal SET state = ?4 WHERE kind = ?1 AND a = ?2 AND b = ?3",
            params![kind, a, b, state],
        )?;
        Ok(())
    }

    /// Deletes the open proposals no resolution has refreshed since `before`.
    pub fn proposal_sweep(&self, before: i64) -> Result<usize> {
        self.need_write()?;
        Ok(self.c.execute(
            "DELETE FROM proposal WHERE state = 'open' AND last_seen < ?1",
            [before],
        )?)
    }

    /// Proposals, newest first, optionally only those naming a CI.
    pub fn proposals(&self, state: Option<&str>, ci: Option<&str>) -> Result<Vec<Proposal>> {
        let mut st = self.c.prepare(
            "SELECT id, kind, a, b, rule, detail, first_seen, last_seen, state FROM proposal
             WHERE (?1 IS NULL OR state = ?1) AND (?2 IS NULL OR a = ?2 OR b = ?2)
             ORDER BY last_seen DESC, id DESC LIMIT 500",
        )?;
        Ok(st
            .query_map(params![state, ci], |r| {
                Ok(Proposal {
                    id: r.get(0)?,
                    kind: r.get(1)?,
                    a: r.get(2)?,
                    b: r.get(3)?,
                    rule: r.get(4)?,
                    detail: r.get(5)?,
                    first_seen: r.get(6)?,
                    last_seen: r.get(7)?,
                    state: r.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// The number of open proposals.
    pub fn proposal_count(&self) -> Result<i64> {
        Ok(self.c.query_row(
            "SELECT COUNT(*) FROM proposal WHERE state = 'open'",
            [],
            |r| r.get(0),
        )?)
    }

    // -- authored-ness ---------------------------------------------------------------------

    /// Whether a CI holds authored data: a pin that names it or one of its interfaces' MACs, or a
    /// merge alias that leads to it (ADR-1005 section 3). A registry row alone is not authored.
    /// T31.3 adds manual values, attribute pins and overrides, and T31.4 an open change record.
    pub fn ci_authored(&self, ci: &str) -> Result<bool> {
        let n: i64 = self.c.query_row(
            "SELECT
               (SELECT COUNT(*) FROM pin WHERE b = ?1)
             + (SELECT COUNT(*) FROM pin p JOIN ci_key k ON k.kind = 'mac' AND k.value = p.a
                  JOIN ci i ON i.id = k.ci WHERE p.kind = 'nic_device' AND (i.id = ?1 OR i.parent = ?1))
             + (SELECT COUNT(*) FROM alias WHERE new = ?1)",
            [ci],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    // -- replication -----------------------------------------------------------------------

    /// The rows (and tombstones) stamped after `after`, in stamp order, at most `limit` rows and
    /// `budget` bytes of JSON. `more` is true when there are further rows.
    pub fn export_after(
        &self,
        after: (i64, i64),
        limit: usize,
        budget: usize,
    ) -> Result<(Vec<WireRow>, bool)> {
        let mut all: Vec<WireRow> = Vec::new();
        for (table, cols, _) in REPLICATED {
            let sql = format!(
                "SELECT {}, epoch, seq FROM {table} WHERE epoch > ?1 OR (epoch = ?1 AND seq > ?2)
                 ORDER BY epoch, seq LIMIT ?3",
                cols.join(", ")
            );
            let mut st = self.c.prepare(&sql)?;
            let n = cols.len();
            let rows = st.query_map(
                params![
                    after.0,
                    after.1,
                    i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX)
                ],
                |r| {
                    let mut d = serde_json::Map::new();
                    for (i, c) in cols.iter().enumerate() {
                        d.insert((*c).to_owned(), json_of(r.get_ref(i)?));
                    }
                    Ok(WireRow {
                        t: (*table).to_owned(),
                        e: r.get(n)?,
                        s: r.get(n.saturating_add(1))?,
                        del: false,
                        d,
                    })
                },
            )?;
            for r in rows {
                all.push(r?);
            }
        }
        {
            let mut st = self.c.prepare(
                "SELECT tbl, pk, epoch, seq FROM tomb WHERE epoch > ?1 OR (epoch = ?1 AND seq > ?2)
                 ORDER BY epoch, seq LIMIT ?3",
            )?;
            let rows = st.query_map(
                params![
                    after.0,
                    after.1,
                    i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX)
                ],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )?;
            for r in rows {
                let (t, pk, e, s) = r?;
                let Some((_, cols, keys)) = REPLICATED.iter().find(|(n, _, _)| *n == t) else {
                    continue;
                };
                let parts: Vec<&str> = pk.split('\x1f').collect();
                let mut d = serde_json::Map::new();
                for (k, v) in keys.iter().zip(parts) {
                    if cols.contains(k) {
                        d.insert((*k).to_owned(), serde_json::Value::String(v.to_owned()));
                    }
                }
                all.push(WireRow {
                    t,
                    e,
                    s,
                    del: true,
                    d,
                });
            }
        }
        all.sort_by_key(|r| (r.e, r.s));
        let mut out = Vec::new();
        let mut bytes = 0usize;
        let mut more = false;
        for row in all {
            let size = serde_json::to_string(&row).map_or(0, |s| s.len());
            if out.len() >= limit || (bytes.saturating_add(size) > budget && !out.is_empty()) {
                more = true;
                break;
            }
            bytes = bytes.saturating_add(size);
            out.push(row);
        }
        Ok((out, more))
    }

    /// Applies rows from the designated node: a row newer than the local one replaces it, a
    /// tombstone newer than the row deletes it. Returns how many rows changed.
    pub fn import_rows(&self, rows: &[WireRow]) -> Result<usize> {
        self.need_write()?;
        let mut changed = 0usize;
        for row in rows {
            let Some((table, cols, keys)) = REPLICATED.iter().find(|(n, _, _)| *n == row.t) else {
                continue;
            };
            let key_vals: Vec<SqlValue> = keys.iter().map(|k| sql_of(row.d.get(*k))).collect();
            let where_: String = keys
                .iter()
                .enumerate()
                .map(|(i, k)| format!("{k} = ?{}", i.saturating_add(1)))
                .collect::<Vec<_>>()
                .join(" AND ");
            let local: Option<(i64, i64)> = self
                .c
                .query_row(
                    &format!("SELECT epoch, seq FROM {table} WHERE {where_}"),
                    params_from_iter(key_vals.iter()),
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if local.is_some_and(|l| l >= (row.e, row.s)) {
                continue;
            }
            // A tombstone at least as new as the row says it was deleted: it stays deleted.
            let pk_text = keys
                .iter()
                .map(|k| match row.d.get(*k) {
                    Some(serde_json::Value::String(s)) => s.clone(),
                    _ => String::new(),
                })
                .collect::<Vec<_>>()
                .join("\x1f");
            let tomb: Option<(i64, i64)> = self
                .c
                .query_row(
                    "SELECT epoch, seq FROM tomb WHERE tbl = ?1 AND pk = ?2",
                    params![table, pk_text],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if tomb.is_some_and(|t| t >= (row.e, row.s)) {
                continue;
            }
            if row.del {
                self.c.execute(
                    &format!("DELETE FROM {table} WHERE {where_}"),
                    params_from_iter(key_vals.iter()),
                )?;
                let pk = keys
                    .iter()
                    .map(|k| match row.d.get(*k) {
                        Some(serde_json::Value::String(s)) => s.clone(),
                        _ => String::new(),
                    })
                    .collect::<Vec<_>>()
                    .join("\x1f");
                if *table == "ci" {
                    // The CI's keys and times go with it; the tombstones of those rows follow.
                    if let Some(id) = row.d.get("id").and_then(serde_json::Value::as_str) {
                        self.c.execute("DELETE FROM ci_key WHERE ci = ?1", [id])?;
                        self.c.execute("DELETE FROM ci_seen WHERE ci = ?1", [id])?;
                    }
                }
                self.tomb((table, &pk), (row.e, row.s))?;
                changed = changed.saturating_add(1);
                continue;
            }
            let names = cols.join(", ");
            let marks: Vec<String> = (1..=cols.len().saturating_add(2))
                .map(|i| format!("?{i}"))
                .collect();
            let mut vals: Vec<SqlValue> = cols.iter().map(|c| sql_of(row.d.get(*c))).collect();
            vals.push(SqlValue::Integer(row.e));
            vals.push(SqlValue::Integer(row.s));
            self.c.execute(
                &format!(
                    "INSERT OR REPLACE INTO {table} ({names}, epoch, seq) VALUES ({})",
                    marks.join(", ")
                ),
                params_from_iter(vals.iter()),
            )?;
            changed = changed.saturating_add(1);
        }
        // The standby's head moves to the newest stamp applied, so the next fetch starts after it.
        if let Some(last) = rows.iter().map(|r| (r.e, r.s)).max() {
            let cur = stamp_of(self.c)?;
            if last > cur {
                self.meta_set("epoch", &last.0.to_string())?;
                self.meta_set("seq", &last.1.to_string())?;
                self.seq.set(last.1);
            }
        }
        Ok(changed)
    }

    /// The tables and counts of the authored data, for the status and the tests.
    pub fn authored_counts(&self) -> Result<Vec<(&'static str, i64)>> {
        let mut out = Vec::new();
        for (table, _, _) in REPLICATED {
            let n: i64 = self
                .c
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
            out.push((*table, n));
        }
        Ok(out)
    }

    /// Distinct tables named by tombstones (tests).
    pub fn tomb_tables(&self) -> Result<BTreeSet<String>> {
        let mut st = self.c.prepare("SELECT DISTINCT tbl FROM tomb")?;
        Ok(st
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// Keeps the `keep` newest tombstones (by stamp) and drops the rest, remembering the stamp of
    /// the newest one dropped as the floor: a standby whose head is older than the floor missed a
    /// deletion it can no longer be told about and has to resync in full. Tombstones are few (a
    /// deletion is rare), so the count bound covers weeks, not the hours a data-row sequence
    /// window would.
    pub fn tomb_sweep(&self, keep: i64) -> Result<usize> {
        self.need_write()?;
        let edge: Option<(i64, i64)> = self
            .c
            .query_row(
                "SELECT epoch, seq FROM tomb ORDER BY epoch DESC, seq DESC LIMIT 1 OFFSET ?1",
                [keep.max(0)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((e, s)) = edge else {
            return Ok(0);
        };
        let n = self.c.execute(
            "DELETE FROM tomb WHERE epoch < ?1 OR (epoch = ?1 AND seq <= ?2)",
            params![e, s],
        )?;
        if (e, s) > self.tomb_floor()? {
            self.meta_set("tomb_floor", &format!("{e},{s}"))?;
        }
        Ok(n)
    }

    /// The stamp of the newest tombstone that was swept (`(0, 0)` while none was).
    pub fn tomb_floor(&self) -> Result<(i64, i64)> {
        Ok(self
            .meta_get("tomb_floor")?
            .and_then(|v| {
                let (e, s) = v.split_once(',')?;
                Some((e.parse().ok()?, s.parse().ok()?))
            })
            .unwrap_or((0, 0)))
    }

    /// Empties a standby copy (the replicated tables, the tombstones and its stamp) so the next
    /// fetch starts from nothing. Used when the standby missed swept tombstones.
    pub fn reset_replica(&self) -> Result<()> {
        self.need_write()?;
        for (table, _, _) in REPLICATED {
            self.c.execute(&format!("DELETE FROM {table}"), [])?;
        }
        self.c.execute("DELETE FROM tomb", [])?;
        self.c.execute(
            "DELETE FROM meta WHERE key IN ('epoch', 'seq', 'tomb_floor')",
            [],
        )?;
        Ok(())
    }
}

fn ci_of(r: &Row<'_>) -> rusqlite::Result<CiRow> {
    Ok(CiRow {
        id: r.get(0)?,
        ty: r.get(1)?,
        kind: r.get(2)?,
        name: r.get(3)?,
        parent: r.get(4)?,
        flags: r.get(5)?,
        first_seen: r.get(6)?,
    })
}

fn json_of(v: ValueRef<'_>) -> serde_json::Value {
    match v {
        ValueRef::Integer(i) => serde_json::Value::from(i),
        ValueRef::Real(f) => serde_json::Value::from(f),
        ValueRef::Text(t) => serde_json::Value::String(String::from_utf8_lossy(t).into_owned()),
        // A blob and a null: no replicated column holds either.
        ValueRef::Null | ValueRef::Blob(_) => serde_json::Value::Null,
    }
}

fn sql_of(v: Option<&serde_json::Value>) -> SqlValue {
    match v {
        Some(serde_json::Value::String(s)) => SqlValue::Text(s.clone()),
        Some(serde_json::Value::Number(n)) => n.as_i64().map_or_else(
            || SqlValue::Real(n.as_f64().unwrap_or(0.0)),
            SqlValue::Integer,
        ),
        Some(serde_json::Value::Bool(b)) => SqlValue::Integer(i64::from(*b)),
        _ => SqlValue::Null,
    }
}

/// What the engine asks about a record before it decides whether to write it (ADR-1005 section 3:
/// a record is written only when its content hash changes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub rid: i64,
    pub hash: u64,
    pub state: String,
    /// Complete batches in a row that did not list it.
    pub missed: i64,
    pub ici: Option<String>,
    pub dci: Option<String>,
    /// The stored `last_seen`.
    pub last_seen: i64,
}

impl Ops<'_> {
    /// The record a source holds under a key, for the unchanged-or-not decision.
    pub fn record_probe(&self, source: &str, skey: &str) -> Result<Option<Probe>> {
        let mut st = self.c.prepare_cached(
            "SELECT r.rid, r.hash, r.state, r.missed, r.ici, r.dci, COALESCE(s.last_seen, r.last_changed)
             FROM record r LEFT JOIN seen s ON s.rid = r.rid WHERE r.source = ?1 AND r.skey = ?2",
        )?;
        Ok(st
            .query_row(params![source, skey], |r| {
                Ok(Probe {
                    rid: r.get(0)?,
                    hash: u64::from_ne_bytes(r.get::<_, i64>(1)?.to_ne_bytes()),
                    state: r.get(2)?,
                    missed: r.get(3)?,
                    ici: r.get(4)?,
                    dci: r.get(5)?,
                    last_seen: r.get(6)?,
                })
            })
            .optional()?)
    }

    /// The `present` records of a source and how often a complete batch missed them.
    pub fn present_of_source(&self, source: &str) -> Result<Vec<(i64, i64)>> {
        let mut st = self.c.prepare_cached(
            "SELECT rid, missed FROM record WHERE source = ?1 AND state = 'present'",
        )?;
        Ok(st
            .query_map([source], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// Sets how many complete batches in a row missed a record.
    pub fn record_set_missed(&self, rid: i64, missed: i64) -> Result<()> {
        self.need_write()?;
        self.c.execute(
            "UPDATE record SET missed = ?2 WHERE rid = ?1",
            params![rid, missed],
        )?;
        Ok(())
    }

    /// Calls `f` with every `(rid, last_seen)` of the `seen` table (the start-up read: two
    /// integers a row, nothing allocated).
    pub fn seen_each(&self, mut f: impl FnMut(i64, i64)) -> Result<()> {
        let mut st = self.c.prepare("SELECT rid, last_seen FROM seen")?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            f(r.get(0)?, r.get(1)?);
        }
        Ok(())
    }

    /// Every CI id of a type, oldest first (for the engine's sweeps).
    pub fn ci_ids(&self, ty: &str, limit: i64) -> Result<Vec<String>> {
        let mut st = self
            .c
            .prepare("SELECT id FROM ci WHERE ty = ?1 ORDER BY first_seen, id LIMIT ?2")?;
        Ok(st
            .query_map(params![ty, limit], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// `unconfirmed` CIs that no record is linked to and no CI has as its parent.
    pub fn ci_orphans(&self, flag: i64) -> Result<Vec<(String, i64)>> {
        let mut st = self.c.prepare(
            "SELECT c.id, COALESCE(s.last_seen, c.first_seen) FROM ci c
             LEFT JOIN ci_seen s ON s.ci = c.id
             WHERE (c.flags & ?1) != 0
               AND NOT EXISTS (SELECT 1 FROM record r WHERE r.dci = c.id OR r.ici = c.id)
               AND NOT EXISTS (SELECT 1 FROM ci i WHERE i.parent = c.id)",
        )?;
        Ok(st
            .query_map([flag], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// Moves the records linked to one CI to another (a merge), at the device level.
    pub fn records_relink_device(&self, from: &str, to: &str) -> Result<()> {
        self.need_write()?;
        self.c.execute(
            "UPDATE record SET dci = ?2 WHERE dci = ?1",
            params![from, to],
        )?;
        Ok(())
    }

    /// Moves the records linked to one port CI to another.
    pub fn records_relink_interface(&self, from: &str, to: &str) -> Result<()> {
        self.need_write()?;
        self.c.execute(
            "UPDATE record SET ici = ?2 WHERE ici = ?1",
            params![from, to],
        )?;
        Ok(())
    }

    /// Re-points the proposals that name `from` at `to`, dropping those that would name a pair
    /// twice or a CI with itself.
    pub fn proposals_retarget(&self, from: &str, to: &str) -> Result<()> {
        self.need_write()?;
        self.c.execute(
            "DELETE FROM proposal WHERE (a = ?1 AND b = ?2) OR (a = ?2 AND b = ?1)",
            params![from, to],
        )?;
        self.c
            .execute("DELETE FROM proposal WHERE a = ?1 OR b = ?1", [from])?;
        Ok(())
    }

    /// Deletes the open proposals that name any of `cis` and are not in `keep` (`kind`, `a`, `b`).
    pub fn proposals_prune(
        &self,
        cis: &[String],
        keep: &std::collections::HashSet<(String, String, String)>,
    ) -> Result<()> {
        self.need_write()?;
        for ci in cis {
            let rows: Vec<(i64, String, String, String)> = {
                let mut st = self.c.prepare(
                    "SELECT id, kind, a, b FROM proposal WHERE state = 'open' AND (a = ?1 OR b = ?1)",
                )?;
                st.query_map([ci], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            for (id, kind, a, b) in rows {
                if !keep.contains(&(kind, a, b)) {
                    self.c.execute("DELETE FROM proposal WHERE id = ?1", [id])?;
                }
            }
        }
        Ok(())
    }

    /// The MAC a nic CI holds (its `mac` key).
    pub fn mac_of(&self, ci: &str) -> Result<Option<String>> {
        Ok(self
            .c
            .query_row(
                "SELECT value FROM ci_key WHERE ci = ?1 AND kind = 'mac' LIMIT 1",
                [ci],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Port CIs of a device: `(id, name, flags)`.
    pub fn ports_of(&self, device: &str) -> Result<Vec<CiRow>> {
        let mut st = self.c.prepare(
            "SELECT id, ty, kind, name, parent, flags, first_seen FROM ci
             WHERE parent = ?1 AND kind = 'port' ORDER BY id",
        )?;
        Ok(st
            .query_map([device], ci_of)?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// The distinct source kinds (the text before the first `:`) of the records linked to a port
    /// CI.
    pub fn record_sources_of_ci(&self, ci: &str) -> Result<Vec<String>> {
        let mut st = self
            .c
            .prepare("SELECT DISTINCT source FROM record WHERE ici = ?1 OR dci = ?1")?;
        Ok(st
            .query_map([ci], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// Updates a CI's time row to the later of the two and the larger `days_seen` (a merge).
    pub fn seen_merge(&self, from: &str, to: &str) -> Result<()> {
        self.need_write()?;
        if let Some(f) = self.seen_get(from)? {
            let merged = match self.seen_get(to)? {
                Some(t) => SeenRow {
                    last_seen: t.last_seen.max(f.last_seen),
                    days_seen: t.days_seen.max(f.days_seen),
                    day: t.day.max(f.day),
                },
                None => f,
            };
            self.seen_put(to, merged)?;
        }
        Ok(())
    }
}

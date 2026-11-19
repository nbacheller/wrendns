//! REQ: NFR-001 (ADR-169) — the bundled SQLite is built without full-text search (FTS3, FTS5), the
//! R-tree index and the dbstat table (`.cargo/config.toml`), and keeps everything the store uses.
//! This runs against the SQLite the tests link, which is the one the image ships because the flags
//! come from the repository's cargo config, not from the image build.

#![allow(clippy::unwrap_used)]

use rusqlite::Connection;

fn compile_options(conn: &Connection) -> Vec<String> {
    let mut stmt = conn.prepare("PRAGMA compile_options").unwrap();
    stmt.query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn nfr_001_sqlite_is_built_without_the_modules_nothing_uses() {
    let conn = Connection::open_in_memory().unwrap();
    let options = compile_options(&conn);
    for gone in [
        "ENABLE_FTS3",
        "ENABLE_FTS3_PARENTHESIS",
        "ENABLE_FTS5",
        "ENABLE_RTREE",
        "ENABLE_DBSTAT_VTAB",
    ] {
        assert!(
            !options.iter().any(|o| o == gone),
            "{gone} is still compiled in: {options:?}"
        );
    }
    // The proof that they are really gone, not just unlisted.
    assert!(
        conn.execute_batch("CREATE VIRTUAL TABLE t USING fts5(x)")
            .is_err(),
        "fts5 still works"
    );
    assert!(
        conn.execute_batch("CREATE VIRTUAL TABLE t USING fts3(x)")
            .is_err(),
        "fts3 still works"
    );
    assert!(
        conn.execute_batch("CREATE VIRTUAL TABLE t USING rtree(id, a, b)")
            .is_err(),
        "rtree still works"
    );
    assert!(
        conn.query_row("SELECT count(*) FROM dbstat", [], |r| r.get::<_, i64>(0))
            .is_err(),
        "dbstat still works"
    );
}

#[test]
fn nfr_001_sqlite_keeps_what_the_store_relies_on() {
    let conn = Connection::open_in_memory().unwrap();
    let options = compile_options(&conn);
    for kept in [
        "DEFAULT_FOREIGN_KEYS",
        "ENABLE_STAT4",
        "ENABLE_COLUMN_METADATA",
        "THREADSAFE=1",
    ] {
        assert!(
            options.iter().any(|o| o == kept),
            "{kept} should still be compiled in: {options:?}"
        );
    }
    // Foreign keys are on by default, and the JSON functions are there.
    assert_eq!(
        conn.query_row("PRAGMA foreign_keys", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    let n: i64 = conn
        .query_row(r#"SELECT json_extract('{"a":7}', '$.a')"#, [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 7);
    // And ordinary tables and indexes work (the store's own tests cover its schema).
    conn.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT NOT NULL); CREATE INDEX t_name ON t(name); INSERT INTO t(name) VALUES ('a'), ('b');")
        .unwrap();
    let count: i64 = conn
        .query_row("SELECT count(*) FROM t WHERE name >= 'a'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

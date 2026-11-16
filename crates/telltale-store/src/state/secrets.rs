//! REQ: OPS-014 (ADR-167 §2) — the secrets entered in the UI, encrypted. One row per name: the
//! value as ChaCha20-Poly1305 ciphertext under the node's key (named by `key_id`), the stamp of
//! its last change, and whether it was deleted (a tombstone, kept so members that were offline
//! still learn of the deletion). Encryption is the caller's: this table never sees a value.
//!
//! The configuration's copy paths (`managed`, the entries listing, audit, backups) never read
//! this table.

use rusqlite::{OptionalExtension, params};

use super::{Result, State, checkpoint_truncate, i, u};

/// Tombstones are kept this long...
pub const TOMBSTONE_DAYS: u64 = 90;
/// ...and at most this many (the newest stay).
pub const MAX_TOMBSTONES: u64 = 512;

/// The meta key holding the last stamp handed out (`<epoch> <seq>`): a stamp is never reused,
/// a delete followed by a new value of the same name included.
const STAMP_KEY: &str = "secrets_stamp";

/// When a change was made: the cluster's epoch (0 on a standalone node) and a counter within it.
/// Ordered: a higher stamp is a later change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Stamp {
    pub epoch: u64,
    pub seq: u64,
}

/// One row. `key_id`, `nonce` and `ciphertext` are empty on a tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRow {
    pub name: String,
    /// `text` (`pem` is reserved).
    pub kind: String,
    pub key_id: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub stamp: Stamp,
    pub deleted: bool,
    /// `local` (made on this node) or `cluster` (the primary's, ADR-167 §6).
    pub origin: String,
    /// Unix seconds.
    pub updated: u64,
    pub updated_by: String,
}

const COLS: &str = "name, kind, key_id, nonce, ciphertext, stamp_epoch, stamp_seq, deleted, \
    origin, updated, updated_by";

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRow> {
    Ok(SecretRow {
        name: r.get(0)?,
        kind: r.get(1)?,
        key_id: r.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default(),
        nonce: r.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
        ciphertext: r.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default(),
        stamp: Stamp {
            epoch: u(r.get(5)?),
            seq: u(r.get(6)?),
        },
        deleted: r.get(7)?,
        origin: r.get(8)?,
        updated: u(r.get(9)?),
        updated_by: r.get(10)?,
    })
}

fn blob(b: &[u8]) -> Option<&[u8]> {
    (!b.is_empty()).then_some(b)
}

fn upsert(c: &rusqlite::Connection, s: &SecretRow) -> rusqlite::Result<()> {
    c.execute(
        &format!(
            "INSERT INTO secrets ({COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(name) DO UPDATE SET kind = excluded.kind, key_id = excluded.key_id,
               nonce = excluded.nonce, ciphertext = excluded.ciphertext,
               stamp_epoch = excluded.stamp_epoch, stamp_seq = excluded.stamp_seq,
               deleted = excluded.deleted, origin = excluded.origin, updated = excluded.updated,
               updated_by = excluded.updated_by"
        ),
        params![
            s.name,
            s.kind,
            blob(&s.key_id),
            blob(&s.nonce),
            blob(&s.ciphertext),
            i(s.stamp.epoch),
            i(s.stamp.seq),
            s.deleted,
            s.origin,
            i(s.updated),
            s.updated_by,
        ],
    )?;
    Ok(())
}

/// Tombstones older than [`TOMBSTONE_DAYS`] go, and all but the newest [`MAX_TOMBSTONES`].
fn prune(c: &rusqlite::Connection, now: u64) -> rusqlite::Result<usize> {
    let cutoff = now.saturating_sub(TOMBSTONE_DAYS * 86_400);
    let old = c.execute(
        "DELETE FROM secrets WHERE deleted = 1 AND updated < ?1",
        [i(cutoff)],
    )?;
    let over = c.execute(
        "DELETE FROM secrets WHERE deleted = 1 AND name NOT IN (
             SELECT name FROM secrets WHERE deleted = 1
             ORDER BY stamp_epoch DESC, stamp_seq DESC LIMIT ?1)",
        [i(MAX_TOMBSTONES)],
    )?;
    Ok(old + over)
}

impl State {
    /// Every row, tombstones included, by name.
    pub fn secret_rows(&self) -> Result<Vec<SecretRow>> {
        self.with(|c| {
            let mut st = c.prepare(&format!("SELECT {COLS} FROM secrets ORDER BY name"))?;
            st.query_map([], row)?.collect()
        })
    }

    /// One row (a tombstone too).
    pub fn secret_row(&self, name: &str) -> Result<Option<SecretRow>> {
        self.with(|c| {
            c.query_row(
                &format!("SELECT {COLS} FROM secrets WHERE name = ?1"),
                [name],
                row,
            )
            .optional()
        })
    }

    /// How many rows there are, tombstones included: a key is made only for an empty table.
    pub fn secret_row_count(&self) -> Result<u64> {
        self.with(|c| c.query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get::<_, i64>(0)))
            .map(u)
    }

    /// REQ: OPS-014 (ADR-167 §2) — the stamp for the next change in `epoch`: the next number in
    /// it, or the first of a later epoch. Kept in `meta` once handed out, so it's never handed out
    /// again (a failed write leaves a gap, never a repeat).
    pub fn next_secret_stamp(&self, epoch: u64) -> Result<Stamp> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let last = tx
                .query_row("SELECT value FROM meta WHERE key = ?1", [STAMP_KEY], |r| {
                    r.get::<_, String>(0)
                })
                .optional()?
                .and_then(|v| {
                    let (e, s) = v.split_once(' ')?;
                    Some(Stamp {
                        epoch: e.parse().ok()?,
                        seq: s.parse().ok()?,
                    })
                });
            // Rows replicated from elsewhere count too: a new stamp is above every one held.
            let held: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT stamp_epoch, stamp_seq FROM secrets
                     ORDER BY stamp_epoch DESC, stamp_seq DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let held = held.map(|(e, s)| Stamp {
                epoch: u(e),
                seq: u(s),
            });
            let top = last.max(held).unwrap_or_default();
            let next = if epoch > top.epoch {
                Stamp { epoch, seq: 1 }
            } else {
                Stamp {
                    epoch: top.epoch,
                    seq: top.seq.saturating_add(1),
                }
            };
            tx.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![STAMP_KEY, format!("{} {}", next.epoch, next.seq)],
            )?;
            tx.commit()?;
            Ok(next)
        })
    }

    /// Stores a row (a value or a tombstone) by name, replacing what was there. A tombstone also
    /// prunes old ones, and the WAL is truncated so the deleted value's pages don't linger there.
    pub fn put_secret_row(&self, s: &SecretRow, now: u64) -> Result<()> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            upsert(&tx, s)?;
            if s.deleted {
                prune(&tx, now)?;
            }
            tx.commit()?;
            if s.deleted {
                checkpoint_truncate(c)?;
            }
            Ok(())
        })
    }

    /// REQ: OPS-014 (ADR-167 §3) — re-encryption (a rotation): every row given replaces its own
    /// in one transaction, then the WAL is truncated, so no ciphertext under the old key is left
    /// in the file (`secure_delete`) or the WAL.
    pub fn replace_secret_rows(&self, rows: &[SecretRow]) -> Result<()> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            for s in rows {
                upsert(&tx, s)?;
            }
            tx.commit()?;
            checkpoint_truncate(c)
        })
    }

    /// REQ: OPS-014 (ADR-167 §3, the replica's self-heal) — drops every row; the caller has
    /// checked they are all the cluster's (a replica fetches them again).
    pub fn clear_secret_rows(&self) -> Result<usize> {
        self.with(|c| {
            let n = c.execute("DELETE FROM secrets", [])?;
            checkpoint_truncate(c)?;
            Ok(n)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(name: &str, stamp: Stamp) -> SecretRow {
        SecretRow {
            name: name.into(),
            kind: "text".into(),
            key_id: vec![1; 8],
            nonce: vec![2; 12],
            ciphertext: vec![3; 32],
            stamp,
            deleted: false,
            origin: "local".into(),
            updated: 100,
            updated_by: "root".into(),
        }
    }

    /// REQ: OPS-014 (ADR-167 §2) — stamps only go up, within an epoch and to a later one, and a
    /// delete then a new value of the same name takes a new stamp; tombstones keep no value and
    /// are pruned by age and count.
    #[test]
    fn ops_014_stamps_never_reused_and_tombstones_pruned() {
        let s = State::in_memory().unwrap();
        assert_eq!(s.secret_row_count().unwrap(), 0);
        let a = s.next_secret_stamp(0).unwrap();
        assert_eq!(a, Stamp { epoch: 0, seq: 1 });
        s.put_secret_row(&value("x", a), 100).unwrap();
        let b = s.next_secret_stamp(0).unwrap();
        assert!(b > a);
        let mut gone = value("x", b);
        gone.deleted = true;
        gone.key_id.clear();
        gone.nonce.clear();
        gone.ciphertext.clear();
        s.put_secret_row(&gone, 100).unwrap();
        let row = s.secret_row("x").unwrap().unwrap();
        assert!(row.deleted && row.ciphertext.is_empty() && row.key_id.is_empty());
        let c = s.next_secret_stamp(0).unwrap();
        assert!(c > b);
        assert_eq!(s.next_secret_stamp(3).unwrap(), Stamp { epoch: 3, seq: 1 });
        // An older epoch never goes back.
        assert_eq!(s.next_secret_stamp(1).unwrap(), Stamp { epoch: 3, seq: 2 });
        // A replicated row with a higher stamp counts.
        s.put_secret_row(&value("y", Stamp { epoch: 9, seq: 4 }), 100)
            .unwrap();
        assert_eq!(s.next_secret_stamp(9).unwrap(), Stamp { epoch: 9, seq: 5 });

        // Pruning: an old tombstone goes when another is written.
        let now = 200 * 86_400;
        let mut fresh = gone.clone();
        fresh.name = "z".into();
        fresh.updated = now;
        fresh.stamp = Stamp { epoch: 9, seq: 6 };
        s.put_secret_row(&fresh, now).unwrap();
        assert!(s.secret_row("x").unwrap().is_none(), "older than 90 days");
        assert!(s.secret_row("z").unwrap().is_some());
        assert_eq!(s.secret_rows().unwrap().len(), 2);
        assert_eq!(s.clear_secret_rows().unwrap(), 2);
        assert_eq!(s.secret_row_count().unwrap(), 0);
    }
}

//! Config made through the API/UI (REQ: API-002, API-010; ADR-040): named entries by kind
//! (`client` today), stored as JSON and merged with the config files at load. Every change
//! bumps one config version (`If-Match`, AGT-001 §7 optimistic concurrency). Idempotency keys
//! (AGT-003) keep the first response for 24 hours.

use rusqlite::{OptionalExtension, params};

use super::{Result, State, StateError, i, u};

/// One stored entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Managed {
    pub kind: String,
    pub name: String,
    /// JSON of the entry (the config section's fields).
    pub body: String,
    pub updated: u64,
    pub updated_by: String,
}

/// Why a write was refused.
#[derive(Debug, thiserror::Error)]
pub enum ManagedError {
    #[error("the configuration changed (version {current}); reload and try again")]
    VersionConflict { current: u64 },
    #[error("no {kind} named `{name}` was created through the API")]
    NotFound { kind: String, name: String },
    #[error(transparent)]
    State(#[from] StateError),
}

impl From<rusqlite::Error> for ManagedError {
    fn from(e: rusqlite::Error) -> Self {
        Self::State(StateError::Db(e))
    }
}

/// An idempotent response kept for replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    /// Hash of the request it answered (a different request with the same key is refused).
    pub request: Vec<u8>,
    pub status: u16,
    pub response: String,
}

const DAY: u64 = 86_400;

fn version(c: &rusqlite::Connection) -> rusqlite::Result<u64> {
    c.query_row(
        "SELECT value FROM meta WHERE key = 'config_version'",
        [],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .map(|v| v.and_then(|v| v.parse().ok()).unwrap_or(0))
}

impl State {
    /// The current config version (0 until the first API change).
    pub fn config_version(&self) -> Result<u64> {
        self.with(version)
    }

    /// REQ: API-902 (T27.13) — a node-local note in `meta` (the guarded framework's outcomes and
    /// suppressions; never replicated, never part of the configuration version).
    pub fn meta_get(&self, key: &str) -> Result<Option<String>> {
        self.with(|c| {
            c.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
                .optional()
        })
    }

    /// Every node-local note whose key starts with `prefix` (key and value), by key.
    pub fn meta_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT key, value FROM meta WHERE substr(key, 1, length(?1)) = ?1 ORDER BY key",
            )?;
            st.query_map([prefix], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect()
        })
    }

    /// Sets (or, with `None`, removes) a node-local note in `meta`.
    pub fn meta_set(&self, key: &str, value: Option<&str>) -> Result<()> {
        self.with(|c| {
            match value {
                Some(v) => c.execute(
                    "INSERT INTO meta (key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![key, v],
                ),
                None => c.execute("DELETE FROM meta WHERE key = ?1", [key]),
            }
            .map(|_| ())
        })
    }

    /// Every entry of `kind`, by name.
    pub fn managed(&self, kind: &str) -> Result<Vec<Managed>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT kind, name, body, updated, updated_by FROM managed WHERE kind = ?1 ORDER BY name",
            )?;
            st.query_map([kind], |r| {
                Ok(Managed {
                    kind: r.get(0)?,
                    name: r.get(1)?,
                    body: r.get(2)?,
                    updated: u(r.get(3)?),
                    updated_by: r.get(4)?,
                })
            })?
            .collect()
        })
    }

    /// Creates or replaces `name` (removing `rename_from` in the same transaction), if the
    /// version is still `expect` (when given). Returns the new version.
    #[allow(clippy::too_many_arguments)]
    pub fn put_managed(
        &self,
        kind: &str,
        name: &str,
        body: &str,
        rename_from: Option<&str>,
        expect: Option<u64>,
        now: u64,
        by: &str,
    ) -> std::result::Result<u64, ManagedError> {
        let conn = self.lock();
        let tx = conn.unchecked_transaction()?;
        let current = version(&tx)?;
        if let Some(v) = expect
            && v != current
        {
            return Err(ManagedError::VersionConflict { current });
        }
        if let Some(old) = rename_from.filter(|o| *o != name) {
            tx.execute(
                "DELETE FROM managed WHERE kind = ?1 AND name = ?2",
                params![kind, old],
            )?;
        }
        tx.execute(
            "INSERT INTO managed (kind, name, body, updated, updated_by) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(kind, name) DO UPDATE SET body = excluded.body,
                 updated = excluded.updated, updated_by = excluded.updated_by",
            params![kind, name, body, i(now), by],
        )?;
        let next = current + 1;
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'config_version'",
            [next.to_string()],
        )?;
        tx.commit()?;
        Ok(next)
    }

    /// REQ: API-007 (T24.18, ADR-940) — creates or replaces every `(kind, name, body)` in one
    /// transaction, if the version is still `expect` (when given). The version moves once for
    /// the whole batch, so a failed batch leaves nothing half-written.
    pub fn put_managed_batch(
        &self,
        rows: &[(&str, &str, &str)],
        expect: Option<u64>,
        now: u64,
        by: &str,
    ) -> std::result::Result<u64, ManagedError> {
        let conn = self.lock();
        let tx = conn.unchecked_transaction()?;
        let current = version(&tx)?;
        if let Some(v) = expect
            && v != current
        {
            return Err(ManagedError::VersionConflict { current });
        }
        for (kind, name, body) in rows {
            tx.execute(
                "INSERT INTO managed (kind, name, body, updated, updated_by) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(kind, name) DO UPDATE SET body = excluded.body,
                     updated = excluded.updated, updated_by = excluded.updated_by",
                params![kind, name, body, i(now), by],
            )?;
        }
        let next = current + 1;
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'config_version'",
            [next.to_string()],
        )?;
        tx.commit()?;
        Ok(next)
    }

    /// REQ: CLU-015 (T24.37, ADR-1016) — makes the entries of `kinds` exactly `rows`
    /// (`(kind, name, body)`, each kind among `kinds`) in one transaction: the rows this node
    /// holds that `rows` doesn't name are deleted, the others created or replaced. The version
    /// moves once. A promoted primary adopts the cluster's last published entries this way.
    pub fn replace_managed(
        &self,
        kinds: &[&str],
        rows: &[(&str, &str, &str)],
        now: u64,
        by: &str,
    ) -> std::result::Result<u64, ManagedError> {
        self.replace_managed_noted(kinds, rows, now, by, None)
            .map(Option::unwrap_or_default)
    }

    /// [`Self::replace_managed`] that also records `note` (a `meta` key and value) in the same
    /// transaction, and does nothing (`Ok(None)`) when `meta` already holds that value for the
    /// key: the check, the replacement and the record are one step. REQ: CLU-015 (T24.37).
    pub fn replace_managed_noted(
        &self,
        kinds: &[&str],
        rows: &[(&str, &str, &str)],
        now: u64,
        by: &str,
        note: Option<(&str, &str)>,
    ) -> std::result::Result<Option<u64>, ManagedError> {
        let conn = self.lock();
        let tx = conn.unchecked_transaction()?;
        if let Some((key, value)) = note {
            let held: Option<String> = tx
                .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
                .optional()?;
            if held.as_deref() == Some(value) {
                return Ok(None);
            }
        }
        let current = version(&tx)?;
        let mut have: Vec<(String, String)> = Vec::new();
        {
            let mut st = tx.prepare("SELECT kind, name, CASE WHEN json_valid(body) THEN COALESCE(json_extract(body, '$.node_only'), 0) ELSE 0 END FROM managed")?;
            let all = st.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)? == 1,
                ))
            })?;
            for r in all {
                let (k, n, pinned) = r?;
                // REQ: CLU-006 — a row pinned to this node (`node_only`) never travelled in the
                // blob, so replacing the shared rows with it must not delete the row.
                if kinds.contains(&k.as_str()) && !pinned {
                    have.push((k, n));
                }
            }
        }
        for (k, n) in &have {
            if !rows.iter().any(|(rk, rn, _)| rk == k && rn == n) {
                tx.execute(
                    "DELETE FROM managed WHERE kind = ?1 AND name = ?2",
                    params![k, n],
                )?;
            }
        }
        for (kind, name, body) in rows.iter().filter(|(k, _, _)| kinds.contains(k)) {
            tx.execute(
                "INSERT INTO managed (kind, name, body, updated, updated_by) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(kind, name) DO UPDATE SET body = excluded.body,
                     updated = excluded.updated, updated_by = excluded.updated_by",
                params![kind, name, body, i(now), by],
            )?;
        }
        if let Some((key, value)) = note {
            tx.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )?;
        }
        let next = current + 1;
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'config_version'",
            [next.to_string()],
        )?;
        tx.commit()?;
        Ok(Some(next))
    }

    /// REQ: CLU-015 (T24.40, ADR-1019) — adds `rows` (`(kind, name, body)`) that this node does not
    /// hold yet, in one transaction, and records `note` in the same step; a row already held is
    /// left as it is (the node's own row wins), and nothing else is touched. Does nothing
    /// (`Ok(None)`) when `meta` already holds the note's value. Returns the kinds of the rows added,
    /// one per row. The version moves once.
    pub fn insert_missing_managed_noted(
        &self,
        rows: &[(&str, &str, &str)],
        now: u64,
        by: &str,
        note: (&str, &str),
    ) -> std::result::Result<Option<Vec<String>>, ManagedError> {
        let conn = self.lock();
        let tx = conn.unchecked_transaction()?;
        let held: Option<String> = tx
            .query_row("SELECT value FROM meta WHERE key = ?1", [note.0], |r| {
                r.get(0)
            })
            .optional()?;
        if held.as_deref() == Some(note.1) {
            return Ok(None);
        }
        let current = version(&tx)?;
        let mut added = Vec::new();
        for (kind, name, body) in rows {
            let n = tx.execute(
                "INSERT INTO managed (kind, name, body, updated, updated_by) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(kind, name) DO NOTHING",
                params![kind, name, body, i(now), by],
            )?;
            if n > 0 {
                added.push((*kind).to_owned());
            }
        }
        tx.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![note.0, note.1],
        )?;
        let next = current + 1;
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'config_version'",
            [next.to_string()],
        )?;
        tx.commit()?;
        Ok(Some(added))
    }

    /// Deletes `name` if the version is still `expect` (when given). Returns the new version.
    pub fn delete_managed(
        &self,
        kind: &str,
        name: &str,
        expect: Option<u64>,
    ) -> std::result::Result<u64, ManagedError> {
        let conn = self.lock();
        let tx = conn.unchecked_transaction()?;
        let current = version(&tx)?;
        if let Some(v) = expect
            && v != current
        {
            return Err(ManagedError::VersionConflict { current });
        }
        let n = tx.execute(
            "DELETE FROM managed WHERE kind = ?1 AND name = ?2",
            params![kind, name],
        )?;
        if n == 0 {
            return Err(ManagedError::NotFound {
                kind: kind.to_owned(),
                name: name.to_owned(),
            });
        }
        let next = current + 1;
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'config_version'",
            [next.to_string()],
        )?;
        tx.commit()?;
        Ok(next)
    }

    /// The stored response for `key`, if it is younger than 24 hours.
    pub fn idempotent(&self, key: &str, now: u64) -> Result<Option<Replay>> {
        self.with(|c| {
            c.query_row(
                "SELECT request, status, response FROM idempotency WHERE key = ?1 AND created > ?2",
                params![key, i(now.saturating_sub(DAY))],
                |r| {
                    Ok(Replay {
                        request: r.get(0)?,
                        status: u16::try_from(r.get::<_, i64>(1)?).unwrap_or(500),
                        response: r.get(2)?,
                    })
                },
            )
            .optional()
        })
    }

    /// Keeps the response for `key` (expired keys are purged on the way).
    pub fn remember_idempotent(&self, key: &str, r: &Replay, now: u64) -> Result<()> {
        self.with(|c| {
            c.execute(
                "DELETE FROM idempotency WHERE created <= ?1",
                [i(now.saturating_sub(DAY))],
            )?;
            c.execute(
                "INSERT INTO idempotency (key, request, status, response, created)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(key) DO NOTHING",
                params![key, r.request, i64::from(r.status), r.response, i(now)],
            )?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_010_put_rename_delete_and_versions() {
        let s = State::in_memory().unwrap();
        assert_eq!(s.config_version().unwrap(), 0);
        let v1 = s
            .put_managed(
                "client",
                "tv",
                r#"{"match":["192.168.1.5"]}"#,
                None,
                Some(0),
                10,
                "admin",
            )
            .unwrap();
        assert_eq!(v1, 1);
        // Stale version: refused, nothing changes.
        assert!(matches!(
            s.put_managed("client", "tv", "{}", None, Some(0), 11, "admin"),
            Err(ManagedError::VersionConflict { current: 1 })
        ));
        // Rename in one step.
        let v2 = s
            .put_managed(
                "client",
                "Living room TV",
                r#"{"match":["192.168.1.5"]}"#,
                Some("tv"),
                None,
                12,
                "admin",
            )
            .unwrap();
        assert_eq!(v2, 2);
        let all = s.managed("client").unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(
            (all[0].name.as_str(), all[0].updated_by.as_str()),
            ("Living room TV", "admin")
        );
        assert_eq!(s.managed("group").unwrap().len(), 0);
        assert!(matches!(
            s.delete_managed("client", "tv", None),
            Err(ManagedError::NotFound { .. })
        ));
        assert_eq!(
            s.delete_managed("client", "Living room TV", Some(2))
                .unwrap(),
            3
        );
        assert_eq!(s.managed("client").unwrap().len(), 0);
    }

    #[test]
    fn agt_003_idempotency_keys_expire_after_a_day() {
        let s = State::in_memory().unwrap();
        let r = Replay {
            request: vec![1, 2],
            status: 200,
            response: "{}".into(),
        };
        s.remember_idempotent("k", &r, 1_000).unwrap();
        assert_eq!(s.idempotent("k", 1_000 + DAY - 1).unwrap(), Some(r.clone()));
        assert_eq!(s.idempotent("k", 1_000 + DAY).unwrap(), None);
        // The first response wins.
        let other = Replay {
            status: 500,
            ..r.clone()
        };
        s.remember_idempotent("k", &other, 1_001).unwrap();
        assert_eq!(
            s.idempotent("k", 1_002).unwrap().map(|x| x.status),
            Some(200)
        );
    }
}

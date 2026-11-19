//! REQ: DSC-902, DSC-903, DSC-906 (T31.2, ADR-1004, ADR-1005 sections 2 to 5) - the engine: one
//! ingested batch at a time over the store, with almost nothing in memory.
//!
//! The records are not held here: each is probed in the database by its `(source, key)` (an index
//! lookup) and compared by content hash, so a record that says the same thing again writes nothing.
//! What stays in memory is two integers per record (its `last_seen` and the value stored, in a
//! compact table), the CI times, and counters. The `last_seen` of an unchanged record is flushed in
//! one batched transaction every 15 minutes, for rows whose stored value is more than 6 hours old
//! (ADR-1005 section 3), so a stable network writes next to nothing. Everything runs on the CMDB
//! thread.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use telltale_store::cmdb::{CmdbDb, CmdbError, FLAG_UNCONFIRMED, SeenRow};

use super::apply::{Cx, Seeds, resolve_seeds};
use super::compact::Table;
use super::model::{
    ABSENT_AFTER, Caps, DAYS_SEEN_CAP, FLUSH_EVERY_SECS, FLUSH_STALE_SECS, LEARNING_SECS,
    SourceBatch, UNCONFIRMED_SECS, ci_num, ci_text, is_presence, prepare,
};

type Result<T> = std::result::Result<T, CmdbError>;

/// Derived-only records not seen for this long are removed (ADR-924, ADR-1005 section 5).
pub(crate) const RETENTION_SECS: i64 = 7 * 86_400;
/// Import rows are kept this long (`[discovery.import]`, ADR-910).
pub(crate) const IMPORT_RETENTION_SECS: i64 = 30 * 86_400;

fn t32(t: i64) -> u32 {
    u32::try_from(t.max(0)).unwrap_or(u32::MAX)
}

/// A record's times in memory: the newest `last_seen` and the value the database holds.
#[derive(Debug, Clone, Copy, Default)]
struct Times {
    last: u32,
    stored: u32,
}

/// A CI's times in memory (indexed by the CI's handle).
#[derive(Debug, Clone, Copy, Default)]
struct CiTime {
    last: u32,
    stored_last: u32,
    day: u32,
    days: u8,
    dirty: bool,
    loaded: bool,
}

/// CI ids as small handles. The table is keyed by the low 64 bits of the id; the full id is
/// checked.
#[derive(Debug, Default)]
struct CiInterner {
    ids: Vec<u128>,
    map: Table<u32>,
}

fn low64(n: u128) -> u64 {
    u64::try_from(n & u128::from(u64::MAX)).unwrap_or(0)
}

impl CiInterner {
    fn handle(&mut self, text: Option<&str>) -> u32 {
        let Some(n) = text.and_then(ci_num) else {
            return 0;
        };
        let key = low64(n);
        let hit = self
            .map
            .get(key)
            .copied()
            .filter(|h| self.ids.get(usize::try_from(*h).unwrap_or(0)) == Some(&n));
        if let Some(h) = hit {
            return h;
        }
        if self.ids.is_empty() {
            self.ids.push(0);
        }
        let h = u32::try_from(self.ids.len()).unwrap_or(u32::MAX);
        self.ids.push(n);
        // A different id with the same low 64 bits (one in 10^19) gets its own handle, unmapped.
        if !self.map.contains_key(key) {
            self.map.insert(key, h);
        }
        h
    }

    fn text(&self, h: u32) -> Option<String> {
        if h == 0 {
            return None;
        }
        self.ids.get(usize::try_from(h).ok()?).copied().map(ci_text)
    }
}

/// Counters the status and the metrics read.
#[derive(Debug, Default, Clone)]
pub(crate) struct Counters {
    pub(crate) batches: u64,
    pub(crate) records_written: u64,
    pub(crate) records_refused: u64,
    pub(crate) attrs_cut: u64,
    pub(crate) cis_created: u64,
    pub(crate) merged: u64,
    pub(crate) proposals_raised: u64,
    pub(crate) dropped_ci: u64,
    pub(crate) dropped_record: u64,
    pub(crate) flushed_rows: u64,
    pub(crate) errors: u64,
    pub(crate) batch_micros: u64,
}

/// The last batch of a source instance.
#[derive(Debug, Clone, Default)]
pub(crate) struct SourceStat {
    pub(crate) last_at: i64,
    pub(crate) records: usize,
    pub(crate) complete: bool,
    pub(crate) batches: u64,
}

/// What one ingested batch did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct IngestReport {
    pub(crate) records: usize,
    pub(crate) unchanged: usize,
    pub(crate) written: usize,
    pub(crate) refused: usize,
    pub(crate) cut: usize,
    pub(crate) went_absent: usize,
    pub(crate) dropped: usize,
}

/// An unchanged record: `(rid, seen, stored last_seen, interface CI, device CI)`.
type UnchangedRow = (i64, i64, i64, Option<String>, Option<String>);
/// A record written: `(rid, seen, interface CI, device CI)`.
type WrittenRow = (i64, i64, Option<String>, Option<String>);

/// What the write transaction of one batch decided, applied to memory after it commits.
#[derive(Default)]
struct Applied {
    created: u64,
    merged: u64,
    proposals: u64,
    dropped_ci: u64,
    dropped_new: usize,
    unchanged: Vec<UnchangedRow>,
    written: Vec<WrittenRow>,
    deleted: Vec<i64>,
    absent: usize,
}

/// The engine.
pub(crate) struct Engine {
    db: Arc<CmdbDb>,
    times: Table<Times>,
    cis: CiInterner,
    ci_times: Vec<CiTime>,
    pub(crate) counters: Counters,
    pub(crate) caps: Caps,
    sources: BTreeMap<String, SourceStat>,
    learning_until: i64,
    last_flush: i64,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cmdb::Engine")
    }
}

impl Engine {
    /// Opens the engine over a database and reads the times. An empty database starts the learning
    /// period at `now` (ADR-910, ADR-1004 section 8).
    pub(crate) fn open(db: &Arc<CmdbDb>, now: i64) -> Result<Self> {
        let records = db.read(|o| Ok(o.record_counts()?.0))?;
        let mut e = Self {
            db: Arc::clone(db),
            times: Table::with_capacity(usize::try_from(records).unwrap_or(0)),
            cis: CiInterner::default(),
            ci_times: Vec::new(),
            counters: Counters::default(),
            caps: Caps::default(),
            sources: BTreeMap::new(),
            learning_until: 0,
            last_flush: now,
        };
        // Two integers a row, read as they come.
        let reader = Arc::clone(db);
        reader.read(|o| {
            o.seen_each(|rid, last| {
                e.times.insert(
                    u64::try_from(rid).unwrap_or(0),
                    Times {
                        last: t32(last),
                        stored: t32(last),
                    },
                );
            })
        })?;
        let learning = db.write(|o| {
            if let Some(t) = o
                .meta_get("learning_until")?
                .and_then(|v| v.parse::<i64>().ok())
            {
                return Ok(t);
            }
            let t = now.saturating_add(LEARNING_SECS);
            o.meta_set("learning_until", &t.to_string())?;
            Ok(t)
        })?;
        e.learning_until = learning;
        Ok(e)
    }

    pub(crate) fn db(&self) -> &Arc<CmdbDb> {
        &self.db
    }

    /// Whether the 24 h learning period is running (no `add` or `delete` change is raised, T31.4).
    #[allow(dead_code)] // REQ: DSC-905 - read by T31.4's detector; the status shows the end now.
    pub(crate) fn learning(&self, now: i64) -> bool {
        now < self.learning_until
    }

    pub(crate) fn learning_until(&self) -> i64 {
        self.learning_until
    }

    /// Records held, and those present.
    #[cfg(test)]
    pub(crate) fn record_counts(&self) -> (usize, usize) {
        self.db
            .read(|o: &telltale_store::cmdb::Ops<'_>| o.record_counts())
            .map_or((0, 0), |(t, p)| {
                (
                    usize::try_from(t).unwrap_or(0),
                    usize::try_from(p).unwrap_or(0),
                )
            })
    }

    pub(crate) fn sources(&self) -> &BTreeMap<String, SourceStat> {
        &self.sources
    }

    /// What the engine keeps in memory, an estimate in bytes (the memory test reports it).
    pub(crate) fn index_bytes(&self) -> usize {
        self.times.capacity() * std::mem::size_of::<(u64, Times)>()
            + self.cis.ids.capacity() * 16
            + self.cis.map.capacity() * std::mem::size_of::<(u64, u32)>()
            + self.ci_times.capacity() * std::mem::size_of::<CiTime>()
    }

    // -- ingestion ---------------------------------------------------------------------------

    /// Ingests one batch: probes each record, writes those whose content changed, resolves the
    /// components they touch, marks the records a complete batch no longer lists, and keeps the
    /// times in memory. One write transaction.
    #[allow(clippy::too_many_lines)] // one flow: probe, cap, write, resolve, then update memory
    #[allow(clippy::needless_pass_by_value)] // the batch is the caller's to give: it is consumed
    pub(crate) fn ingest(&mut self, b: SourceBatch, now: i64) -> Result<IngestReport> {
        let started = std::time::Instant::now();
        let presence = is_presence(&b.source);
        let mut rep = IngestReport {
            records: b.records.len(),
            ..IngestReport::default()
        };
        let mut prepared = Vec::with_capacity(b.records.len());
        for rec in &b.records {
            match prepare(rec) {
                Some(p) => {
                    rep.cut = rep.cut.saturating_add(p.cut);
                    prepared.push(p);
                }
                None => rep.refused = rep.refused.saturating_add(1),
            }
        }
        let db = Arc::clone(&self.db);
        let caps = self.caps;
        let times = &self.times;
        let applied = db.write(|ops| {
            let mut ap = Applied::default();
            let mut cx = Cx::new(ops, now, caps)?;
            let mut seeds = Seeds::default();
            let mut listed: HashSet<i64> = HashSet::new();
            let mut revive: Vec<i64> = Vec::new();
            let mut reset: Vec<i64> = Vec::new();
            let mut changed: Vec<(&super::model::Prepared, bool)> = Vec::new();
            for p in &prepared {
                match ops.record_probe(&p.write.source, &p.write.skey)? {
                    Some(pr) if pr.hash == p.write.hash => {
                        listed.insert(pr.rid);
                        if pr.state == "absent" {
                            revive.push(pr.rid);
                        } else if pr.missed > 0 {
                            reset.push(pr.rid);
                        }
                        ap.unchanged
                            .push((pr.rid, p.write.seen, pr.last_seen, pr.ici, pr.dci));
                    }
                    Some(pr) => {
                        listed.insert(pr.rid);
                        changed.push((p, false));
                    }
                    None => changed.push((p, true)),
                }
            }
            // The cap on records: room is made from the oldest `absent` ones; a new record that
            // finds none is dropped and counted (ADR-1005 section 3).
            let new_count = i64::try_from(changed.iter().filter(|(_, n)| *n).count()).unwrap_or(0);
            let (total, _) = ops.record_counts()?;
            let mut evict = total.saturating_add(new_count).saturating_sub(caps.records);
            if evict > 0 {
                for rid in ops.oldest_absent_records(evict)? {
                    if let Some(row) = ops.record_by_id(rid)? {
                        seeds.add_row(&row);
                    }
                    ops.record_delete(rid)?;
                    ap.deleted.push(rid);
                    evict = evict.saturating_sub(1);
                }
            }
            for (p, is_new) in &changed {
                if *is_new && evict > 0 {
                    // No `absent` record to make room for it: it is dropped.
                    evict = evict.saturating_sub(1);
                    ap.dropped_new = ap.dropped_new.saturating_add(1);
                    continue;
                }
                let (rid, old) = ops.record_upsert(&p.write)?;
                seeds.add_write(&p.write, rid);
                if let Some(o) = &old {
                    seeds.add_row(o);
                }
                listed.insert(rid);
                ap.written.push((rid, p.write.seen, None, None));
            }
            for rid in &revive {
                ops.record_state(*rid, "present")?;
            }
            for rid in &reset {
                ops.record_set_missed(*rid, 0)?;
            }
            // A complete batch marks what it no longer lists: a miss, and `absent` at the second.
            if b.complete {
                for (rid, missed) in ops.present_of_source(&b.source)? {
                    if listed.contains(&rid) {
                        continue;
                    }
                    let m = missed.saturating_add(1);
                    if m >= i64::from(ABSENT_AFTER) {
                        ops.record_state(rid, "absent")?;
                        // The last time it was seen is kept when it leaves `present`.
                        if let Some(t) = times.get(u64::try_from(rid).unwrap_or(0)) {
                            ops.seen_flush(&[(rid, i64::from(t.last))])?;
                        }
                        ap.absent = ap.absent.saturating_add(1);
                    } else {
                        ops.record_set_missed(rid, m)?;
                    }
                }
            }
            resolve_seeds(&mut cx, &seeds)?;
            // At most 8 records per CI, counted at the CI's own level: the oldest `absent` goes,
            // else the newest written one is dropped and counted.
            let mut levels: Vec<String> = Vec::new();
            for (rid, _, _, _) in &ap.written {
                if let Some(r) = ops.record_by_id(*rid)?
                    && let Some(c) = r.ici.or(r.dci)
                    && !levels.contains(&c)
                {
                    levels.push(c);
                }
            }
            for ci in &levels {
                while ops.record_count_at_level(ci)? > caps.per_ci {
                    if let Some(rid) = ops.oldest_absent_at_level(ci)? {
                        ops.record_delete(rid)?;
                        ap.deleted.push(rid);
                        continue;
                    }
                    let newest = ap.written.iter().rev().find_map(|(rid, _, _, _)| {
                        ops.record_by_id(*rid).ok().flatten().filter(|r| {
                            r.ici.as_deref() == Some(ci.as_str())
                                || (r.ici.is_none() && r.dci.as_deref() == Some(ci.as_str()))
                        })
                    });
                    match newest {
                        Some(r) => {
                            ops.record_delete(r.rid)?;
                            ap.deleted.push(r.rid);
                            ap.dropped_new = ap.dropped_new.saturating_add(1);
                        }
                        None => break,
                    }
                }
            }
            // Links of what was written, now that the records are resolved.
            let mut kept = Vec::new();
            for (rid, seen, _, _) in std::mem::take(&mut ap.written) {
                if ap.deleted.contains(&rid) {
                    continue;
                }
                if let Some(r) = ops.record_by_id(rid)? {
                    kept.push((rid, seen, r.ici, r.dci));
                }
            }
            ap.written = kept;
            ap.created = cx.created;
            ap.merged = cx.merged;
            ap.proposals = cx.proposals;
            ap.dropped_ci = cx.dropped_ci;
            Ok(ap)
        })?;
        // The write is committed: memory follows.
        if !applied.deleted.is_empty() {
            let gone: HashSet<u64> = applied
                .deleted
                .iter()
                .filter_map(|r| u64::try_from(*r).ok())
                .collect();
            self.times.retain(|k, _| !gone.contains(k));
        }
        for (rid, seen, stored, ici, dci) in &applied.unchanged {
            let key = u64::try_from(*rid).unwrap_or(0);
            match self.times.get_mut(key) {
                Some(t) => t.last = t.last.max(t32(*seen)),
                None => self.times.insert(
                    key,
                    Times {
                        last: t32(*seen).max(t32(*stored)),
                        stored: t32(*stored),
                    },
                ),
            }
            if presence {
                self.touch(ici.as_deref(), *seen);
                self.touch(dci.as_deref(), *seen);
            }
        }
        rep.unchanged = applied.unchanged.len();
        for (rid, seen, ici, dci) in &applied.written {
            self.times.insert(
                u64::try_from(*rid).unwrap_or(0),
                Times {
                    last: t32(*seen),
                    stored: t32(*seen),
                },
            );
            if presence {
                self.touch(ici.as_deref(), *seen);
                self.touch(dci.as_deref(), *seen);
            }
        }
        rep.written = applied.written.len();
        rep.went_absent = applied.absent;
        rep.dropped = applied.dropped_new;
        let c = &mut self.counters;
        c.cis_created = c.cis_created.saturating_add(applied.created);
        c.merged = c.merged.saturating_add(applied.merged);
        c.proposals_raised = c.proposals_raised.saturating_add(applied.proposals);
        c.dropped_ci = c.dropped_ci.saturating_add(applied.dropped_ci);
        c.dropped_record = c
            .dropped_record
            .saturating_add(u64::try_from(applied.dropped_new).unwrap_or(u64::MAX));
        c.records_written = c
            .records_written
            .saturating_add(u64::try_from(rep.written).unwrap_or(u64::MAX));
        c.records_refused = c
            .records_refused
            .saturating_add(u64::try_from(rep.refused).unwrap_or(u64::MAX));
        c.attrs_cut = c
            .attrs_cut
            .saturating_add(u64::try_from(rep.cut).unwrap_or(u64::MAX));
        c.batches = c.batches.saturating_add(1);
        c.batch_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let st = self.sources.entry(b.source.clone()).or_default();
        st.last_at = now;
        st.records = rep.records;
        st.complete = b.complete;
        st.batches = st.batches.saturating_add(1);
        Ok(rep)
    }

    /// A presence source saw a CI: its newest time, and the day if it is a new one (the registry's
    /// `last_seen` and `days_seen`, which outlive the records, ADR-1005 section 3).
    fn touch(&mut self, ci: Option<&str>, at: i64) {
        let handle = self.cis.handle(ci);
        if handle == 0 {
            return;
        }
        let idx = usize::try_from(handle).unwrap_or(usize::MAX);
        if self.ci_times.len() <= idx {
            self.ci_times
                .resize(idx.saturating_add(1), CiTime::default());
        }
        if !self.ci_times.get(idx).is_some_and(|t| t.loaded) {
            let row = self
                .cis
                .text(handle)
                .and_then(|id| self.db.read(|o| o.seen_get(&id)).ok().flatten());
            let t = row.map_or_else(
                || CiTime {
                    loaded: true,
                    ..CiTime::default()
                },
                |r| CiTime {
                    last: t32(r.last_seen),
                    stored_last: t32(r.last_seen),
                    day: u32::try_from(r.day.max(0)).unwrap_or(0),
                    days: u8::try_from(r.days_seen.clamp(0, DAYS_SEEN_CAP)).unwrap_or(0),
                    dirty: false,
                    loaded: true,
                },
            );
            if let Some(slot) = self.ci_times.get_mut(idx) {
                *slot = t;
            }
        }
        if let Some(t) = self.ci_times.get_mut(idx) {
            t.last = t.last.max(t32(at));
            let day = t32(at) / 86_400;
            if day != t.day {
                t.day = day;
                t.days = t
                    .days
                    .saturating_add(1)
                    .min(u8::try_from(DAYS_SEEN_CAP).unwrap_or(32));
                t.dirty = true;
            }
        }
    }

    // -- the batched last_seen flush ----------------------------------------------------------

    /// Writes `last_seen` back in one transaction, every 15 minutes, for rows whose stored value
    /// is more than 6 hours old, and the CI rows whose day count advanced. Returns the rows written.
    pub(crate) fn flush(&mut self, now: i64, force: bool) -> Result<usize> {
        if !force && now.saturating_sub(self.last_flush) < FLUSH_EVERY_SECS {
            return Ok(0);
        }
        self.last_flush = now;
        let stale = if force { 0 } else { FLUSH_STALE_SECS };
        let recs: Vec<(u64, u32)> = self
            .times
            .iter()
            .filter(|(_, t)| t.last > t.stored && i64::from(t.last) - i64::from(t.stored) > stale)
            .map(|(k, t)| (*k, t.last))
            .collect();
        let mut cis: Vec<(usize, String, SeenRow)> = Vec::new();
        for (idx, t) in self.ci_times.iter().enumerate() {
            let due = t.dirty
                || (t.last > t.stored_last && i64::from(t.last) - i64::from(t.stored_last) > stale);
            if !t.loaded || !due {
                continue;
            }
            let h = u32::try_from(idx).unwrap_or(0);
            if let Some(id) = self.cis.text(h) {
                cis.push((
                    idx,
                    id,
                    SeenRow {
                        last_seen: i64::from(t.last),
                        days_seen: i64::from(t.days),
                        day: i64::from(t.day),
                    },
                ));
            }
        }
        if recs.is_empty() && cis.is_empty() {
            return Ok(0);
        }
        let rows: Vec<(i64, i64)> = recs
            .iter()
            .map(|(rid, at)| (i64::try_from(*rid).unwrap_or(0), i64::from(*at)))
            .collect();
        let db = Arc::clone(&self.db);
        db.write(|o| {
            o.seen_flush(&rows)?;
            for (_, id, row) in &cis {
                // A CI deleted meanwhile has no row to update.
                if o.ci_get(id)?.is_some() {
                    o.seen_put(id, *row)?;
                }
            }
            Ok(())
        })?;
        for (k, at) in &recs {
            if let Some(t) = self.times.get_mut(*k) {
                t.stored = *at;
            }
        }
        for (idx, _, row) in &cis {
            if let Some(t) = self.ci_times.get_mut(*idx) {
                t.stored_last = t32(row.last_seen);
                t.dirty = false;
            }
        }
        let n = recs.len().saturating_add(cis.len());
        self.counters.flushed_rows = self
            .counters
            .flushed_rows
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        Ok(n)
    }

    // -- retention ---------------------------------------------------------------------------

    /// Retention (ADR-1005 section 5): `absent` records age out (derived-only after 7 days,
    /// imports after 30), expired aliases go, and an `unconfirmed` CI with no record, no child and
    /// no authored data is removed after 30 days. The registry's `last_seen` and `days_seen`
    /// outlive the records.
    pub(crate) fn maintain(&mut self, now: i64) -> Result<usize> {
        let db = Arc::clone(&self.db);
        let caps = self.caps;
        let mut gone_rids: Vec<i64> = Vec::new();
        let n = db.write(|ops| {
            let mut cx = Cx::new(ops, now, caps)?;
            let mut seeds = Seeds::default();
            ops.alias_expire(now)?;
            let mut expired =
                ops.records_expired(now.saturating_sub(RETENTION_SECS), "%", "import:%")?;
            expired.extend(ops.records_expired(
                now.saturating_sub(IMPORT_RETENTION_SECS),
                "import:%",
                "",
            )?);
            for rid in &expired {
                if let Some(row) = ops.record_by_id(*rid)? {
                    seeds.add_row(&row);
                }
                ops.record_delete(*rid)?;
                gone_rids.push(*rid);
            }
            resolve_seeds(&mut cx, &seeds)?;
            let mut removed = 0usize;
            for (id, last) in ops.ci_orphans(FLAG_UNCONFIRMED)? {
                if last < now.saturating_sub(UNCONFIRMED_SECS) && !ops.ci_authored(&id)? {
                    ops.ci_delete(&id)?;
                    removed = removed.saturating_add(1);
                }
            }
            let (_, seq) = ops.head()?;
            ops.tomb_sweep(seq.saturating_sub(10_000))?;
            Ok(expired.len().saturating_add(removed))
        })?;
        if !gone_rids.is_empty() {
            let gone: HashSet<u64> = gone_rids
                .into_iter()
                .filter_map(|r| u64::try_from(r).ok())
                .collect();
            self.times.retain(|k, _| !gone.contains(k));
        }
        Ok(n)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::cmdb::model::{RecKind, Record};

    pub(crate) fn engine() -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(CmdbDb::open(&dir.path().join("cmdb.db")).unwrap());
        let e = Engine::open(&db, 1_000_000).unwrap();
        (dir, e)
    }

    pub(crate) fn host(source: &str, key: &str, mac: &str, at: i64) -> Record {
        let mut r = Record::new(source, key, RecKind::Device, at);
        r.text("mac", mac);
        r
    }

    pub(crate) fn batch(
        source: &str,
        records: Vec<Record>,
        complete: bool,
        at: i64,
    ) -> SourceBatch {
        SourceBatch {
            source: source.to_owned(),
            complete,
            records,
            at,
        }
    }
}

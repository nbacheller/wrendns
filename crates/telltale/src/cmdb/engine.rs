//! REQ: DSC-902, DSC-903, DSC-906 (T31.2, ADR-1004, ADR-1005 sections 2 to 5) - the engine: the
//! in-memory index over the store, one ingested batch at a time.
//!
//! What stays in memory is a compact index (a key hash, a content hash, two times, a state and the
//! two CI handles per record; the CI times), never the records: they are read from the database
//! for a page and for a resolution. A batch writes only the records whose content changed; the
//! `last_seen` of the others lives here and is flushed in one batched transaction every 15
//! minutes, for rows whose stored value is more than 6 hours old (ADR-1005 section 3), so a stable
//! network writes next to nothing. Everything runs on the CMDB thread.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use telltale_store::cmdb::{CmdbDb, CmdbError, FLAG_UNCONFIRMED, SeenRow};

use super::apply::{Cx, Seeds, resolve_seeds};
use super::model::{
    ABSENT_AFTER, DAYS_SEEN_CAP, FLUSH_EVERY_SECS, FLUSH_STALE_SECS, LEARNING_SECS,
    MAX_RECORDS, MAX_RECORDS_PER_CI, SourceBatch, UNCONFIRMED_SECS, ci_num, ci_text, is_presence,
    key_hash, prepare,
};

type Result<T> = std::result::Result<T, CmdbError>;

const PRESENT: u8 = 0;
const ABSENT: u8 = 1;
/// Derived-only records not seen for this long are removed (ADR-924, ADR-1005 section 5).
pub(crate) const RETENTION_SECS: i64 = 7 * 86_400;
/// Import rows are kept this long (`[discovery.import]`, ADR-910).
pub(crate) const IMPORT_RETENTION_SECS: i64 = 30 * 86_400;

fn t32(t: i64) -> u32 {
    u32::try_from(t.max(0)).unwrap_or(u32::MAX)
}

/// One record in the in-memory index.
#[derive(Debug, Clone, Copy)]
struct Seen {
    rid: i64,
    hash: u64,
    src: u16,
    last: u32,
    stored: u32,
    round: u32,
    dci: u32,
    ici: u32,
    state: u8,
    missed: u8,
}

/// A CI's times in memory.
#[derive(Debug, Clone, Copy, Default)]
struct CiTime {
    last: u32,
    stored_last: u32,
    day: u32,
    days: u8,
    dirty: bool,
}

/// CI ids as small handles (the index would otherwise keep 35 bytes of text per link).
#[derive(Debug, Default)]
struct CiInterner {
    ids: Vec<u128>,
    map: HashMap<u128, u32>,
}

impl CiInterner {
    fn handle(&mut self, text: Option<&str>) -> u32 {
        let Some(n) = text.and_then(ci_num) else {
            return 0;
        };
        if let Some(h) = self.map.get(&n) {
            return *h;
        }
        if self.ids.is_empty() {
            self.ids.push(0);
        }
        let h = u32::try_from(self.ids.len()).unwrap_or(u32::MAX);
        self.ids.push(n);
        self.map.insert(n, h);
        h
    }

    fn text(&self, h: u32) -> Option<String> {
        if h == 0 {
            return None;
        }
        self.ids
            .get(usize::try_from(h).ok()?)
            .copied()
            .map(ci_text)
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

/// The engine.
pub(crate) struct Engine {
    db: Arc<CmdbDb>,
    seen: HashMap<u64, Seen>,
    srcs: Vec<String>,
    src_ids: HashMap<String, u16>,
    cis: CiInterner,
    ci_times: HashMap<u32, CiTime>,
    round: u32,
    pub(crate) counters: Counters,
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
    /// Opens the engine over a database and reads the index. An empty database starts the learning
    /// period at `now` (ADR-910, ADR-1004 section 8).
    pub(crate) fn open(db: Arc<CmdbDb>, now: i64) -> Result<Self> {
        let mut e = Self {
            db: Arc::clone(&db),
            seen: HashMap::new(),
            srcs: Vec::new(),
            src_ids: HashMap::new(),
            cis: CiInterner::default(),
            ci_times: HashMap::new(),
            round: 0,
            counters: Counters::default(),
            sources: BTreeMap::new(),
            learning_until: 0,
            last_flush: now,
        };
        let mut rows = Vec::new();
        db.read(|o| o.record_index_each(|r| rows.push(r)))?;
        for r in rows {
            let src = e.src_id(&r.source);
            let kh = key_hash(&r.source, &r.skey);
            let dci = e.cis.handle(r.dci.as_deref());
            let ici = e.cis.handle(r.ici.as_deref());
            e.seen.insert(
                kh,
                Seen {
                    rid: r.rid,
                    hash: r.hash,
                    src,
                    last: t32(r.last_seen),
                    stored: t32(r.last_seen),
                    round: 0,
                    dci,
                    ici,
                    state: if r.state == "absent" { ABSENT } else { PRESENT },
                    missed: 0,
                },
            );
        }
        let learning = db.write(|o| {
            Ok(match o.meta_get("learning_until")?.and_then(|v| v.parse::<i64>().ok()) {
                Some(t) => t,
                None => {
                    let t = now.saturating_add(LEARNING_SECS);
                    o.meta_set("learning_until", &t.to_string())?;
                    t
                }
            })
        })?;
        e.learning_until = learning;
        Ok(e)
    }

    pub(crate) fn db(&self) -> &Arc<CmdbDb> {
        &self.db
    }

    /// Whether the 24 h learning period is running (no `add` or `delete` change is raised, T31.4).
    pub(crate) fn learning(&self, now: i64) -> bool {
        now < self.learning_until
    }

    pub(crate) fn learning_until(&self) -> i64 {
        self.learning_until
    }

    /// Records in the index, and those present.
    pub(crate) fn record_counts(&self) -> (usize, usize) {
        let present = self.seen.values().filter(|s| s.state == PRESENT).count();
        (self.seen.len(), present)
    }

    pub(crate) fn sources(&self) -> &BTreeMap<String, SourceStat> {
        &self.sources
    }

    fn src_id(&mut self, source: &str) -> u16 {
        if let Some(i) = self.src_ids.get(source) {
            return *i;
        }
        let i = u16::try_from(self.srcs.len()).unwrap_or(u16::MAX);
        self.srcs.push(source.to_owned());
        self.src_ids.insert(source.to_owned(), i);
        i
    }

    /// The in-memory index's size, for the memory test (an estimate, in bytes).
    pub(crate) fn index_bytes(&self) -> usize {
        self.seen.capacity()
            * (std::mem::size_of::<Seen>() + std::mem::size_of::<u64>() + 1)
            + self.cis.ids.capacity() * 16
            + self.cis.map.capacity() * 24
            + self.ci_times.capacity() * (std::mem::size_of::<CiTime>() + 5)
    }

    // -- ingestion ---------------------------------------------------------------------------

    /// Ingests one batch: writes the records whose content changed, resolves the components they
    /// touch, marks records a complete batch no longer lists, and keeps the rest in memory.
    #[allow(clippy::too_many_lines)] // one flow: classify, cap, write, resolve, then update memory
    pub(crate) fn ingest(&mut self, b: SourceBatch, now: i64) -> Result<IngestReport> {
        let started = std::time::Instant::now();
        self.round = self.round.wrapping_add(1).max(1);
        let round = self.round;
        let src = self.src_id(&b.source);
        let presence = is_presence(&b.source);
        let mut rep = IngestReport {
            records: b.records.len(),
            ..IngestReport::default()
        };
        let mut changed = Vec::new();
        let mut revive: Vec<i64> = Vec::new();
        let mut touch: Vec<(u32, u32, i64)> = Vec::new();
        for rec in &b.records {
            let Some(p) = prepare(rec) else {
                rep.refused = rep.refused.saturating_add(1);
                continue;
            };
            rep.cut = rep.cut.saturating_add(p.cut);
            match self.seen.get_mut(&p.key_hash) {
                Some(s) if s.hash == p.write.hash => {
                    s.last = s.last.max(t32(p.write.seen));
                    s.round = round;
                    s.missed = 0;
                    if s.state == ABSENT {
                        s.state = PRESENT;
                        revive.push(s.rid);
                    }
                    touch.push((s.dci, s.ici, p.write.seen));
                    rep.unchanged = rep.unchanged.saturating_add(1);
                }
                Some(s) => {
                    s.round = round;
                    s.missed = 0;
                    changed.push(p);
                }
                None => changed.push(p),
            }
        }
        // The cap on records: room is made from the oldest `absent` ones; a new record that finds
        // none is dropped and counted (ADR-1005 section 3).
        let new_count = changed
            .iter()
            .filter(|p| !self.seen.contains_key(&p.key_hash))
            .count();
        let total = self.seen.len().saturating_add(new_count);
        let cap = usize::try_from(MAX_RECORDS).unwrap_or(usize::MAX);
        let mut evict = total.saturating_sub(cap);
        // A complete batch marks what it no longer lists.
        let mut absent: Vec<(u64, i64)> = Vec::new();
        if b.complete {
            for (kh, s) in &self.seen {
                if s.src == src
                    && s.round != round
                    && s.state == PRESENT
                    && s.missed.saturating_add(1) >= ABSENT_AFTER
                {
                    absent.push((*kh, s.rid));
                }
            }
        }
        let db = Arc::clone(&self.db);
        let mut deleted: Vec<i64> = Vec::new();
        let mut dropped_new = 0usize;
        let (applied, written) = db.write(|ops| {
            let mut cx = Cx::new(ops, now)?;
            let mut seeds = Seeds::default();
            if evict > 0 {
                for rid in ops.oldest_absent_records(i64::try_from(evict).unwrap_or(i64::MAX))? {
                    if let Some(row) = ops.record_by_id(rid)? {
                        seeds.add_row(&row);
                    }
                    ops.record_delete(rid)?;
                    deleted.push(rid);
                    evict = evict.saturating_sub(1);
                }
            }
            let mut written: Vec<(u64, i64, i64, u64)> = Vec::new();
            for p in &changed {
                let is_new = !self.seen.contains_key(&p.key_hash);
                if is_new && evict > 0 {
                    // No `absent` record to make room for it: it is dropped.
                    evict = evict.saturating_sub(1);
                    dropped_new = dropped_new.saturating_add(1);
                    continue;
                }
                let (rid, old) = ops.record_upsert(&p.write)?;
                seeds.add_write(&p.write, rid);
                if let Some(o) = &old {
                    seeds.add_row(o);
                }
                written.push((p.key_hash, rid, p.write.seen, p.write.hash));
            }
            for rid in &revive {
                ops.record_state(*rid, "present")?;
            }
            for (_, rid) in &absent {
                ops.record_state(*rid, "absent")?;
            }
            resolve_seeds(&mut cx, &seeds)?;
            // At most 8 records per CI, counted at the CI's own level: the oldest `absent` goes,
            // else the newest written one is dropped and counted.
            let mut levels: Vec<String> = Vec::new();
            for (_, rid, _, _) in &written {
                if let Some(r) = ops.record_by_id(*rid)?
                    && let Some(c) = r.ici.or(r.dci)
                    && !levels.contains(&c)
                {
                    levels.push(c);
                }
            }
            for ci in &levels {
                while ops.record_count_at_level(ci)? > MAX_RECORDS_PER_CI {
                    if let Some(rid) = ops.oldest_absent_at_level(ci)? {
                        ops.record_delete(rid)?;
                        deleted.push(rid);
                        continue;
                    }
                    let newest = written.iter().rev().find_map(|(_, rid, _, _)| {
                        ops.record_by_id(*rid).ok().flatten().filter(|r| {
                            r.ici.as_deref() == Some(ci.as_str())
                                || (r.ici.is_none() && r.dci.as_deref() == Some(ci.as_str()))
                        })
                    });
                    match newest {
                        Some(r) => {
                            ops.record_delete(r.rid)?;
                            deleted.push(r.rid);
                            dropped_new = dropped_new.saturating_add(1);
                        }
                        None => break,
                    }
                }
            }
            let mut links = Vec::new();
            for (kh, rid, seen, hash) in &written {
                if deleted.contains(rid) {
                    continue;
                }
                if let Some(r) = ops.record_by_id(*rid)? {
                    links.push((*kh, *rid, *seen, *hash, r.dci, r.ici));
                }
            }
            Ok((
                (
                    cx.created,
                    cx.merged,
                    cx.proposals,
                    cx.dropped_ci,
                ),
                links,
            ))
        })?;
        // The write is committed: the index follows.
        if !deleted.is_empty() {
            let gone: std::collections::HashSet<i64> = deleted.iter().copied().collect();
            self.seen.retain(|_, s| !gone.contains(&s.rid));
        }
        for (kh, rid) in &absent {
            if let Some(s) = self.seen.get_mut(kh)
                && s.rid == *rid
            {
                s.state = ABSENT;
                s.missed = ABSENT_AFTER;
                rep.went_absent = rep.went_absent.saturating_add(1);
            }
        }
        // Records a complete batch missed once are counted, not yet absent.
        if b.complete {
            for s in self.seen.values_mut() {
                if s.src == src && s.round != round && s.state == PRESENT && s.missed < ABSENT_AFTER {
                    s.missed = s.missed.saturating_add(1);
                }
            }
        }
        for (kh, rid, seen, hash, dci, ici) in &written {
            let dh = self.cis.handle(dci.as_deref());
            let ih = self.cis.handle(ici.as_deref());
            self.seen.insert(
                *kh,
                Seen {
                    rid: *rid,
                    hash: *hash,
                    src,
                    last: t32(*seen),
                    stored: t32(*seen),
                    round,
                    dci: dh,
                    ici: ih,
                    state: PRESENT,
                    missed: 0,
                },
            );
            touch.push((dh, ih, *seen));
            rep.written = rep.written.saturating_add(1);
        }
        let (created, merged, proposals, dropped_ci) = applied;
        self.counters.cis_created = self.counters.cis_created.saturating_add(created);
        self.counters.merged = self.counters.merged.saturating_add(merged);
        self.counters.proposals_raised = self.counters.proposals_raised.saturating_add(proposals);
        self.counters.dropped_ci = self.counters.dropped_ci.saturating_add(dropped_ci);
        self.counters.dropped_record = self
            .counters
            .dropped_record
            .saturating_add(u64::try_from(dropped_new).unwrap_or(u64::MAX));
        self.counters.records_written = self
            .counters
            .records_written
            .saturating_add(u64::try_from(rep.written).unwrap_or(u64::MAX));
        self.counters.records_refused = self
            .counters
            .records_refused
            .saturating_add(u64::try_from(rep.refused).unwrap_or(u64::MAX));
        self.counters.attrs_cut = self
            .counters
            .attrs_cut
            .saturating_add(u64::try_from(rep.cut).unwrap_or(u64::MAX));
        self.counters.batches = self.counters.batches.saturating_add(1);
        rep.dropped = dropped_new;
        if presence {
            for (d, i, at) in touch {
                self.touch_ci(d, at);
                self.touch_ci(i, at);
            }
        }
        let st = self.sources.entry(b.source.clone()).or_default();
        st.last_at = now;
        st.records = rep.records;
        st.complete = b.complete;
        st.batches = st.batches.saturating_add(1);
        self.counters.batch_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        Ok(rep)
    }

    fn touch_ci(&mut self, handle: u32, at: i64) {
        if handle == 0 {
            return;
        }
        if !self.ci_times.contains_key(&handle) {
            let row = self
                .cis
                .text(handle)
                .and_then(|id| self.db.read(|o| o.seen_get(&id)).ok().flatten());
            let t = row.map_or_else(CiTime::default, |r| CiTime {
                last: t32(r.last_seen),
                stored_last: t32(r.last_seen),
                day: u32::try_from(r.day.max(0)).unwrap_or(0),
                days: u8::try_from(r.days_seen.clamp(0, DAYS_SEEN_CAP)).unwrap_or(0),
                dirty: false,
            });
            self.ci_times.insert(handle, t);
        }
        if let Some(t) = self.ci_times.get_mut(&handle) {
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
        let recs: Vec<(u64, i64, u32)> = self
            .seen
            .iter()
            .filter(|(_, s)| s.last > s.stored && i64::from(s.last) - i64::from(s.stored) > stale)
            .map(|(k, s)| (*k, s.rid, s.last))
            .collect();
        let mut cis: Vec<(u32, String, SeenRow)> = Vec::new();
        for (h, t) in &self.ci_times {
            if t.dirty || (t.last > t.stored_last && i64::from(t.last) - i64::from(t.stored_last) > stale) {
                if let Some(id) = self.cis.text(*h) {
                    cis.push((
                        *h,
                        id,
                        SeenRow {
                            last_seen: i64::from(t.last),
                            days_seen: i64::from(t.days),
                            day: i64::from(t.day),
                        },
                    ));
                }
            }
        }
        if recs.is_empty() && cis.is_empty() {
            return Ok(0);
        }
        let rows: Vec<(i64, i64)> = recs.iter().map(|(_, rid, at)| (*rid, i64::from(*at))).collect();
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
        for (k, _, at) in &recs {
            if let Some(s) = self.seen.get_mut(k) {
                s.stored = *at;
            }
        }
        for (h, _, row) in &cis {
            if let Some(t) = self.ci_times.get_mut(h) {
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
        let mut gone_rids: Vec<i64> = Vec::new();
        let n = db.write(|ops| {
            let mut cx = Cx::new(ops, now)?;
            let mut seeds = Seeds::default();
            ops.alias_expire(now)?;
            let mut expired = ops.records_expired(now.saturating_sub(RETENTION_SECS), "%", "import:%")?;
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
            let gone: std::collections::HashSet<i64> = gone_rids.into_iter().collect();
            self.seen.retain(|_, s| !gone.contains(&s.rid));
        }
        Ok(n)
    }

    /// Makes the in-memory view of one record's CI links current after the engine changed them
    /// outside a batch (a manual change).
    pub(crate) fn reload_links(&mut self, rids: &[i64]) {
        let db = Arc::clone(&self.db);
        let rows: Vec<_> = rids
            .iter()
            .filter_map(|rid| db.read(|o| o.record_by_id(*rid)).ok().flatten())
            .collect();
        for r in rows {
            let kh = key_hash(&r.source, &r.skey);
            let (d, i) = (
                self.cis.handle(r.dci.as_deref()),
                self.cis.handle(r.ici.as_deref()),
            );
            if let Some(s) = self.seen.get_mut(&kh) {
                s.dci = d;
                s.ici = i;
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::cmdb::model::{RecKind, Record};

    pub(crate) fn engine() -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(CmdbDb::open(&dir.path().join("cmdb.db")).unwrap());
        let e = Engine::open(db, 1_000_000).unwrap();
        (dir, e)
    }

    pub(crate) fn host(source: &str, key: &str, mac: &str, at: i64) -> Record {
        let mut r = Record::new(source, key, RecKind::Device, at);
        r.text("mac", mac);
        r
    }

    pub(crate) fn batch(source: &str, records: Vec<Record>, complete: bool, at: i64) -> SourceBatch {
        SourceBatch {
            source: source.to_owned(),
            complete,
            records,
            at,
        }
    }
}

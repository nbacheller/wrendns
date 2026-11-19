//! REQ: DSC-906 (T31.2, ADR-1005 section 6 as amended by ADR-1021) - the authored data on the
//! standby nodes.
//!
//! **Spike outcome (T31.2 step 1).** The ADR-917 secrets replication takes no non-secret writer: it
//! is the primary's (the single writer is whichever node is primary, and the CMDB's designated node
//! can be another node by name), its head rides on the primary's heartbeat, and its row, page and
//! store types are the secrets store's (`Stamp`, `Remote`, `StoreState`, an encrypted value). So the
//! fallback ADR-1005 section 6 names is used: **an authored-data snapshot in the cluster channel**.
//! Authored rows carry a stamp `(epoch, seq)` set by the one writer, and a delete leaves a
//! tombstone. A full member that is not the designated node asks the designated one over the mTLS
//! stream (`cmdb.fetch`, paged under 900 KiB) for the rows after its own head, every minute, and
//! keeps them in `cmdb-standby.db`. The designated node answers only full members. A node that
//! becomes designated seeds `cmdb.db` from its standby copy (the rows with a newer stamp win) and
//! starts a new epoch, so its writes outrank anything the old writer wrote. Derived data (source
//! records, proposals) is never copied: the sources rebuild it, under the 24 h learning period.
//!
//! Nothing here is on the DNS path, and a failure only backs off and logs (CLU-004).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use telltale_cluster::net::Cluster;
use telltale_store::cmdb::{CmdbDb, CmdbError, Ops, STANDBY_NAME, WireRow};
use tokio::sync::watch;

use crate::http::Sources;

/// The RPC a standby sends the designated node.
pub(crate) const KIND_FETCH: &str = "cmdb.fetch";
/// Encoded bytes per page (under the 1 MiB RPC limit).
pub(crate) const PAGE_BUDGET: usize = 900 * 1024;
/// Rows per page, at most.
pub(crate) const PAGE_ROWS: usize = 2_000;
/// How often a standby asks.
const TICK: Duration = Duration::from_secs(60);
/// How long one page may take.
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug, Default, Serialize, Deserialize)]
struct FetchReq {
    /// The newest stamp the asker has: the answer starts after it.
    #[serde(default)]
    after: (i64, i64),
}

#[derive(Debug, Serialize, Deserialize)]
struct FetchAns {
    /// The writer's newest stamp.
    head: (i64, i64),
    rows: Vec<WireRow>,
    #[serde(default)]
    more: bool,
}

type Result<T> = std::result::Result<T, CmdbError>;

fn standby_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(STANDBY_NAME)
}

/// A node that becomes designated seeds its database from the standby copy it holds, then starts a
/// new epoch. Idempotent: a row with a stamp not newer than the local one is skipped.
pub(crate) fn promote(db: &CmdbDb, data_dir: &Path, _now: i64) -> Result<usize> {
    let path = standby_path(data_dir);
    if !path.exists() {
        return Ok(0);
    }
    let standby = CmdbDb::open(&path)?;
    let mut after = (0, 0);
    let mut applied = 0usize;
    loop {
        let (rows, more) = standby.read(|o| o.export_after(after, PAGE_ROWS, PAGE_BUDGET))?;
        let Some(last) = rows.last().map(|r| (r.e, r.s)) else {
            break;
        };
        applied = applied.saturating_add(db.write(|o| o.import_rows(&rows))?);
        after = last;
        if !more {
            break;
        }
    }
    if applied > 0 {
        // The new writer's stamps outrank anything the old one still writes.
        db.write(|o| {
            let (e, _) = o.head()?;
            o.set_epoch(e.saturating_add(1))
        })?;
    }
    Ok(applied)
}

/// The designated node's answer to `cmdb.fetch`: the authored rows after the asker's head. Only a
/// full member may ask, and only the node that runs the CMDB answers.
pub(crate) async fn answer_fetch(
    src: Arc<Sources>,
    cluster: Arc<Cluster>,
    peer: String,
    body: Vec<u8>,
) -> std::result::Result<Vec<u8>, String> {
    let req: FetchReq = if body.is_empty() {
        FetchReq::default()
    } else {
        serde_json::from_slice(&body).map_err(|_| "bad cmdb.fetch request".to_owned())?
    };
    let full = !cluster.is_removed(&peer)
        && cluster
            .identity
            .registry()
            .iter()
            .any(|n| n.node_id == peer && !n.ephemeral && !n.witness);
    if !full {
        return Err("only a full member can read the CMDB's authored data".into());
    }
    let Some(db) = src.cmdb.db() else {
        return Err("this node does not run the CMDB".into());
    };
    tokio::task::spawn_blocking(move || {
        let head = db.read(|o: &Ops<'_>| o.head()).map_err(|e| e.to_string())?;
        let (rows, more) = db
            .read(|o| o.export_after(req.after, PAGE_ROWS, PAGE_BUDGET))
            .map_err(|e| e.to_string())?;
        serde_json::to_vec(&FetchAns { head, rows, more }).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("cmdb worker failed: {e}"))?
}

/// One pass of a standby: ask the peers for the rows after this node's head until the designated
/// one has answered, and keep them. Returns the rows applied.
pub(crate) async fn pull_once(src: &Arc<Sources>, cluster: &Arc<Cluster>) -> usize {
    let cfg = src.config.load_full();
    let data_dir = std::path::PathBuf::from(cfg.node.data_dir.as_str());
    let path = standby_path(&data_dir);
    let standby = {
        let path = path.clone();
        match tokio::task::spawn_blocking(move || CmdbDb::open(&path)).await {
            Ok(Ok(d)) => Arc::new(d),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "the CMDB's standby copy could not be opened");
                return 0;
            }
            Err(_) => return 0,
        }
    };
    let mut total = 0usize;
    // The designated node is the one that answers; ask them all (a node that does not run it
    // says so at once).
    let mut after = {
        let s = Arc::clone(&standby);
        tokio::task::spawn_blocking(move || s.read(|o: &Ops<'_>| o.head()).unwrap_or((0, 0)))
            .await
            .unwrap_or((0, 0))
    };
    loop {
        let body = serde_json::to_vec(&FetchReq { after }).unwrap_or_default();
        let answers = cluster.call_all(KIND_FETCH, &body, DEADLINE).await;
        let Some(ans) = answers.into_iter().find_map(|(_, a)| {
            a.ok()
                .and_then(|b| serde_json::from_slice::<FetchAns>(&b).ok())
        }) else {
            return total;
        };
        let more = ans.more;
        let last = ans.rows.last().map(|r| (r.e, r.s));
        let s = Arc::clone(&standby);
        let rows = ans.rows;
        let n = tokio::task::spawn_blocking(move || s.write(|o| o.import_rows(&rows)))
            .await
            .ok()
            .and_then(std::result::Result::ok)
            .unwrap_or(0);
        total = total.saturating_add(n);
        match last {
            Some(l) if more => after = l,
            _ => return total,
        }
    }
}

/// The standby task: on a full member that is not running the CMDB, while `[cmdb]` is on, a pass
/// every minute until the server stops.
pub(crate) fn spawn(src: Arc<Sources>, mut stop: watch::Receiver<bool>) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = tokio::time::sleep(TICK) => {}
                _ = stop.wait_for(|s| *s) => return,
            }
            let cfg = src.config.load_full();
            if !cfg.cmdb.enabled || cfg.cluster.ephemeral || src.cmdb.db().is_some() {
                continue;
            }
            if let Some(cluster) = src.cluster.clone() {
                let n = pull_once(&src, &cluster).await;
                if n > 0 {
                    tracing::debug!(rows = n, "the CMDB's standby copy took authored rows");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::redundant_closure_for_method_calls,
        clippy::manual_assert,
        clippy::type_complexity,
        clippy::assert_is_empty
    )]
    use super::*;
    use telltale_store::cmdb::{CiRow, Pin};

    fn seeded(path: &Path) -> CmdbDb {
        let db = CmdbDb::open(path).unwrap();
        db.write(|o| {
            for n in 0..3 {
                o.ci_put(&CiRow {
                    id: format!("ci_{n:032x}"),
                    ty: "device".into(),
                    kind: None,
                    name: Some(format!("dev{n}")),
                    parent: None,
                    flags: 0,
                    first_seen: 100 + n,
                })?;
                o.key_add("serial", &format!("sn-{n:04}"), &format!("ci_{n:032x}"))?;
            }
            o.pin_set(&Pin {
                kind: "nic_device".into(),
                a: "aa:bb:cc:00:00:01".into(),
                b: format!("ci_{:032x}", 0),
                at: 100,
                by: "alice".into(),
                reason: "same".into(),
            })?;
            o.alias_set(
                &format!("ci_{:032x}", 9),
                &format!("ci_{:032x}", 0),
                1_000_000,
            )?;
            Ok(())
        })
        .unwrap();
        db
    }

    /// REQ: DSC-906 (ADR-1021) - authored rows travel in stamped pages: a standby that applies them
    /// holds the same registry, keys, pins and aliases, a delete arrives as a tombstone, and a row
    /// is not applied twice.
    #[test]
    fn dsc_906_authored_rows_replicate_with_stamps_and_tombstones() {
        let dir = tempfile::tempdir().unwrap();
        let primary = seeded(&dir.path().join("p.db"));
        let standby = CmdbDb::open(&dir.path().join("s.db")).unwrap();
        let mut after = (0, 0);
        loop {
            let (rows, more) = primary
                .read(|o| o.export_after(after, 4, PAGE_BUDGET))
                .unwrap();
            let Some(last) = rows.last().map(|r| (r.e, r.s)) else {
                break;
            };
            standby.write(|o| o.import_rows(&rows)).unwrap();
            after = last;
            if !more {
                break;
            }
        }
        let counts = |d: &CmdbDb| d.read(|o| o.authored_counts()).unwrap();
        assert_eq!(counts(&primary), counts(&standby));
        assert_eq!(
            standby.read(|o| o.head()).unwrap(),
            primary.read(|o| o.head()).unwrap()
        );
        // A delete on the writer arrives as a tombstone and removes the row and its keys.
        primary
            .write(|o| o.ci_delete(&format!("ci_{:032x}", 1)))
            .unwrap();
        let (rows, _) = primary
            .read(|o| o.export_after(after, 100, PAGE_BUDGET))
            .unwrap();
        assert!(rows.iter().any(|r| r.del && r.t == "ci"), "{rows:?}");
        let again = standby.write(|o| o.import_rows(&rows)).unwrap();
        assert!(again > 0);
        assert!(
            standby
                .read(|o| o.ci_get(&format!("ci_{:032x}", 1)))
                .unwrap()
                .is_none()
        );
        assert!(
            standby
                .read(|o| o.keys_of(&format!("ci_{:032x}", 1)))
                .unwrap()
                .is_empty()
        );
        // The same rows again change nothing.
        assert_eq!(standby.write(|o| o.import_rows(&rows)).unwrap(), 0);
    }

    /// REQ: DSC-906 (ADR-1021) - a node that becomes designated seeds its database from its standby
    /// copy and starts a new epoch, so its writes outrank the old writer's.
    #[test]
    fn dsc_906_promote_seeds_the_database_and_starts_a_new_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let old_writer = seeded(&dir.path().join("w.db"));
        // The standby copy is cmdb-standby.db under the data directory.
        let standby = CmdbDb::open(&dir.path().join(STANDBY_NAME)).unwrap();
        let (rows, _) = old_writer
            .read(|o| o.export_after((0, 0), 1000, PAGE_BUDGET))
            .unwrap();
        standby.write(|o| o.import_rows(&rows)).unwrap();
        let (old_epoch, old_seq) = old_writer.read(|o| o.head()).unwrap();
        drop(standby);
        let fresh = CmdbDb::open(&dir.path().join("cmdb.db")).unwrap();
        let n = promote(&fresh, dir.path(), 0).unwrap();
        assert!(n >= 8, "{n}");
        assert_eq!(fresh.read(|o| o.pins()).unwrap().len(), 1);
        assert!(
            fresh
                .read(|o| o.ci_get(&format!("ci_{:032x}", 2)))
                .unwrap()
                .is_some()
        );
        let (e, s) = fresh.read(|o| o.head()).unwrap();
        assert!(e > old_epoch, "a new epoch: {e} over {old_epoch}");
        assert_eq!(s, old_seq);
        // A write now carries the new epoch and sorts after every old stamp.
        fresh
            .write(|o| {
                o.pin_set(&Pin {
                    kind: "rec_never".into(),
                    a: "x\x1fy".into(),
                    b: "*".into(),
                    at: 1,
                    by: "b".into(),
                    reason: String::new(),
                })
            })
            .unwrap();
        let (rows, _) = fresh
            .read(|o| o.export_after((old_epoch, old_seq), 10, PAGE_BUDGET))
            .unwrap();
        assert!(rows.iter().all(|r| (r.e, r.s) > (old_epoch, old_seq)));
        assert!(!rows.is_empty());
    }
}

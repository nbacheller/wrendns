//! REQ: CLU-015, CLU-004, CLU-005 (ADR-903 §6) — stored secrets on full members. The primary
//! answers `secrets.fetch` with its rows (values only over the mTLS cluster channel, never to a
//! file or a blob), paged under 900 KiB; a full replica pulls when the head a heartbeat announces
//! differs from its own, verifies the answer against that head and the digest of its rows, and
//! applies it (re-encrypted under its own key). A locked primary's rows can be refilled from a
//! replica (the reverse heal). `secrets.adopt` lets a node that joined a cluster hand its own
//! secrets to the primary.
//!
//! Nothing here gates manifest application, `applied`, or readiness (ADR-058, CLU-004): the sync
//! is its own task, its failures only back off and log, and it runs on blocking threads for the
//! store. An N-1 primary answers "unknown call", which just means nothing is fetched from it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use telltale_cluster::net::{Cluster, Member, SecretsHead, SecretsMark};
use telltale_store::state::Stamp;
use tokio::sync::watch;

use super::store::{Applied, Page, Remote, StoreState, Unavailable, head_from};
use super::value::{Kind, SecretValue};
use crate::http::Sources;

/// The RPC a replica sends the primary to read its rows.
pub(crate) const KIND_FETCH: &str = "secrets.fetch";
/// The RPC a joining node sends the primary with its own secrets.
pub(crate) const KIND_ADOPT: &str = "secrets.adopt";
/// The answer's error when the primary can't give its rows now (its store is locked).
pub(crate) const UNAVAILABLE: &str = "secrets_unavailable";
/// Encoded bytes per page (ADR-903 §6: under 900 KiB, so an answer fits a frame).
pub(crate) const PAGE_BUDGET: usize = 900 * 1024;
/// How long one page may take.
const FETCH_DEADLINE: Duration = Duration::from_secs(10);
/// How often the task looks.
const TICK: Duration = Duration::from_secs(5);
/// After a failed pull, the wait doubles from this to [`BACKOFF_MAX`].
const BACKOFF_MIN: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(600);
/// At most this many configuration fields reported as unreadable, and secret names reported.
const MAX_ISSUES: usize = 32;
const MAX_REFS: usize = 128;

#[derive(Debug, Default, Serialize, Deserialize)]
struct FetchReq {
    /// The last name the requester has; the answer starts after it.
    #[serde(default)]
    after: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HeadJson {
    epoch: u64,
    seq: u64,
    /// Hex BLAKE3 of the sorted `(name, kind, stamp, deleted)` list.
    digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ItemJson {
    name: String,
    kind: String,
    epoch: u64,
    seq: u64,
    #[serde(default)]
    deleted: bool,
    #[serde(default)]
    held: bool,
    #[serde(default)]
    updated: u64,
    #[serde(default)]
    updated_by: String,
    /// The value, for a live row the sender could read. It travels over the mTLS channel only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FetchAns {
    head: HeadJson,
    /// The epoch the answering primary is in (a replica's orphans are judged against it).
    primary_epoch: u64,
    items: Vec<ItemJson>,
    #[serde(default)]
    more: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdoptItem {
    name: String,
    kind: String,
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdoptReq {
    secrets: Vec<AdoptItem>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AdoptAns {
    /// Names taken as cluster rows.
    adopted: Vec<String>,
    /// Names the cluster already holds: this node keeps its own row, shadowed.
    conflicts: Vec<String>,
}

/// Per-node state of the sync task.
#[derive(Debug, Default)]
pub(crate) struct Progress {
    /// The primary head this node last applied (or that it matched).
    applied: Option<SecretsHead>,
    /// Live rows of the last applied answer that the primary holds but couldn't decrypt.
    held: u32,
    failures: u32,
    next_try: Option<Instant>,
    /// Epoch of the primary this node last adopted its own rows to.
    adopted_in: Option<u64>,
    heal_next: Option<Instant>,
    removed_purged: bool,
    init_done: bool,
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn full_member(cluster: &Cluster, node: &str) -> bool {
    cluster
        .identity
        .registry()
        .iter()
        .any(|n| n.node_id == node && !n.ephemeral && !n.witness)
}

/// The primary in the highest epoch this node has heard of (a heartbeat's view), when reachable.
fn primary_of_highest(cluster: &Cluster) -> Option<Member> {
    let reachable = cluster.reachable_peers();
    cluster
        .members()
        .into_iter()
        .filter(|m| m.primary && reachable.contains(&m.node_id))
        .max_by_key(|m| m.epoch)
}

/// Whether `peer` is the primary of the highest epoch as this node sees it (a replica answers a
/// reverse heal only for that primary).
fn is_current_primary(cluster: &Cluster, peer: &str) -> bool {
    let top = cluster
        .members()
        .into_iter()
        .filter(|m| m.primary)
        .map(|m| m.epoch)
        .max();
    cluster
        .members()
        .iter()
        .any(|m| m.node_id == peer && m.primary && Some(m.epoch) == top)
}

fn head_json(head: (Stamp, [u8; 32])) -> HeadJson {
    HeadJson {
        epoch: head.0.epoch,
        seq: head.0.seq,
        digest: crate::secrets::hex(&head.1),
    }
}

fn item_json(r: &Remote) -> ItemJson {
    ItemJson {
        name: r.name.clone(),
        kind: r.kind.clone(),
        epoch: r.stamp.epoch,
        seq: r.stamp.seq,
        deleted: r.deleted,
        held: r.held,
        updated: r.updated,
        updated_by: r.updated_by.clone(),
        value: r.value.as_ref().map(|v| v.expose().to_owned()),
    }
}

/// REQ: CLU-015 — a received row, checked: a valid name and kind, a value of the kind's rules for a
/// live row, none for a tombstone or a held row.
fn remote_of(it: ItemJson) -> Result<Remote, String> {
    if !telltale_config::secret_refs::valid_name(&it.name) {
        return Err(format!("a row has an invalid name `{}`", it.name));
    }
    let kind = Kind::parse(&it.kind).map_err(|e| format!("`{}`: {e}", it.name))?;
    let value = match (it.deleted, it.held, it.value) {
        (false, false, Some(v)) => Some(
            SecretValue::new(kind, zeroize::Zeroizing::new(v))
                .map_err(|e| format!("`{}`: {e}", it.name))?,
        ),
        (false, false, None) => return Err(format!("`{}` has no value", it.name)),
        (_, _, Some(_)) => return Err(format!("`{}` carries a value it shouldn't", it.name)),
        _ => None,
    };
    Ok(Remote {
        name: it.name,
        kind: kind.as_str().to_owned(),
        stamp: Stamp {
            epoch: it.epoch,
            seq: it.seq,
        },
        deleted: it.deleted,
        held: it.held,
        updated: it.updated,
        updated_by: it.updated_by,
        value,
    })
}

/// REQ: CLU-015 — a primary's answer to `secrets.fetch`. Only a full member gets one; the primary
/// answers as primary (with its base stamp), and a replica answers only the primary of the highest
/// epoch (a reverse heal). A locked store answers [`UNAVAILABLE`], so the requester keeps its rows.
pub(crate) async fn answer_fetch(
    src: Arc<Sources>,
    cluster: Arc<Cluster>,
    peer: String,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    if !full_member(&cluster, &peer) {
        return Err("only a full member can read stored secrets".into());
    }
    let req: FetchReq = if body.is_empty() {
        FetchReq::default()
    } else {
        serde_json::from_slice(&body).map_err(|_| "bad secrets.fetch request".to_owned())?
    };
    if !cluster.is_primary() && !is_current_primary(&cluster, &peer) {
        return Err("this node isn't the primary: it doesn't answer stored-secret reads".into());
    }
    let log = tracing::dispatcher::get_default(Clone::clone);
    tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&log, || build_answer(&src, &cluster, &req))
    })
    .await
    .map_err(|e| format!("secrets worker failed: {e}"))?
}

fn build_answer(src: &Sources, cluster: &Cluster, req: &FetchReq) -> Result<Vec<u8>, String> {
    let _ = src.secrets.keys();
    let page: Page = src
        .secrets
        .export_page(req.after.as_deref(), PAGE_BUDGET)
        .map_err(|e| match e {
            Unavailable::Locked(_) => UNAVAILABLE.to_owned(),
            other => other.to_string(),
        })?;
    let epoch = cluster.role().1;
    let ans = FetchAns {
        head: head_json(page.head),
        primary_epoch: epoch,
        items: page.items.iter().map(item_json).collect(),
        more: page.more,
    };
    serde_json::to_vec(&ans).map_err(|e| e.to_string())
}

/// REQ: CLU-015 (ADR-903 §6) — a joining node's rows, taken on the primary as cluster rows where
/// the cluster doesn't hold the name; the rest are conflicts (kept by the joiner, shadowed).
pub(crate) async fn answer_adopt(
    src: Arc<Sources>,
    cluster: Arc<Cluster>,
    peer: String,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    if !full_member(&cluster, &peer) {
        return Err("only a full member can hand over its secrets".into());
    }
    let req: AdoptReq = serde_json::from_slice(&zeroize::Zeroizing::new(body))
        .map_err(|_| "bad secrets.adopt request".to_owned())?;
    let epoch = cluster
        .primary_epoch()
        .map_err(|_| "this node isn't a primary that takes secrets".to_owned())?;
    let log = tracing::dispatcher::get_default(Clone::clone);
    let via = cluster
        .members()
        .into_iter()
        .find(|m| m.node_id == peer)
        .map(|m| m.site)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| peer.clone());
    tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&log, || {
            let now = crate::pipeline::unix_now();
            let mut ans = AdoptAns::default();
            let held: Vec<String> = src
                .secrets
                .status()
                .secrets
                .iter()
                .filter(|s| !s.deleted)
                .map(|s| s.name.clone())
                .collect();
            for it in req.secrets {
                if held.contains(&it.name) {
                    ans.conflicts.push(it.name);
                    continue;
                }
                let Ok(kind) = Kind::parse(&it.kind) else {
                    continue;
                };
                let Ok(value) = SecretValue::new(kind, zeroize::Zeroizing::new(it.value)) else {
                    continue;
                };
                match src.secrets.put(
                    &it.name,
                    kind,
                    &value,
                    epoch,
                    &format!("joined from {via}"),
                    "cluster",
                    now,
                ) {
                    Ok(_) => ans.adopted.push(it.name),
                    Err(_) => ans.conflicts.push(it.name),
                }
            }
            tracing::info!(
                adopted = ans.adopted.len(),
                conflicts = ans.conflicts.len(),
                "stored secrets taken from a joining node"
            );
            serde_json::to_vec(&ans).map_err(|e| e.to_string())
        })
    })
    .await
    .map_err(|e| format!("secrets worker failed: {e}"))?
}

/// REQ: CLU-015 — pulls every page of `target`'s rows, checking that each page carries the same
/// head and that the rows recompute it (a stale or changed answer is refused).
async fn fetch_all(
    cluster: &Cluster,
    target: &str,
) -> Result<(Vec<Remote>, (Stamp, [u8; 32]), u64), String> {
    let mut after: Option<String> = None;
    let mut head: Option<(Stamp, [u8; 32])> = None;
    let mut primary_epoch = 0;
    let mut all: Vec<Remote> = Vec::new();
    loop {
        let body = serde_json::to_vec(&FetchReq {
            after: after.clone(),
        })
        .map_err(|e| e.to_string())?;
        let raw = cluster
            .call(target, KIND_FETCH, body, FETCH_DEADLINE)
            .await
            .map_err(|e| {
                if e.contains("unknown call") {
                    "the primary is too old to share stored secrets".to_owned()
                } else {
                    e
                }
            })?;
        let ans: FetchAns = serde_json::from_slice(&zeroize::Zeroizing::new(raw))
            .map_err(|_| "the primary's answer isn't a secrets page".to_owned())?;
        let digest = unhex(&ans.head.digest)
            .and_then(|d| <[u8; 32]>::try_from(d).ok())
            .ok_or_else(|| "the answer's digest is malformed".to_owned())?;
        let this = (
            Stamp {
                epoch: ans.head.epoch,
                seq: ans.head.seq,
            },
            digest,
        );
        match head {
            None => {
                head = Some(this);
                primary_epoch = ans.primary_epoch;
            }
            Some(h) if h != this => {
                return Err("the primary's head changed while its rows were read: trying again later".into());
            }
            Some(_) => {}
        }
        for it in ans.items {
            let r = remote_of(it)?;
            after = Some(r.name.clone());
            all.push(r);
        }
        if !ans.more {
            break;
        }
        if after.is_none() {
            return Err("a page without rows says there are more".into());
        }
    }
    let head = head.ok_or_else(|| "no answer".to_owned())?;
    verify(&all, head)?;
    Ok((all, head, primary_epoch))
}

/// REQ: CLU-015 (ADR-903 §6) — an answer's rows must recompute the head it came with (the
/// highest stamp and the digest of the sorted `(name, kind, stamp, deleted)` list). A changed,
/// added or dropped row shows, and the answer is discarded whole.
pub(crate) fn verify(rows: &[Remote], head: (Stamp, [u8; 32])) -> Result<(), String> {
    let computed = head_from(
        rows.iter()
            .map(|r| (r.name.as_str(), r.kind.as_str(), r.stamp, r.deleted)),
    );
    if computed != head {
        return Err("the answer's rows don't match its head: discarded".into());
    }
    Ok(())
}

/// REQ: CLU-015 — the replica's pull: fetch, verify, apply. Returns how many rows were held.
async fn pull(src: &Arc<Sources>, cluster: &Cluster, target: &str) -> Result<(usize, u32), String> {
    let (all, _head, primary_epoch) = fetch_all(cluster, target).await?;
    let store = Arc::clone(&src.secrets);
    let now = crate::pipeline::unix_now();
    let applied: Applied = tokio::task::spawn_blocking(move || {
        store.apply_remote(&all, primary_epoch, now)
    })
    .await
    .map_err(|e| format!("secrets worker failed: {e}"))?
    .map_err(|e| e.to_string())?;
    Ok((applied.changed, u32::try_from(applied.held).unwrap_or(u32::MAX)))
}

/// REQ: CLU-015 — this node's secrets mark, as heartbeats carry it.
fn mark_of(src: &Sources, cluster: &Cluster, st: &Progress) -> SecretsMark {
    let (stamp, digest) = src.secrets.head();
    let head = SecretsHead {
        epoch: stamp.epoch,
        seq: stamp.seq,
        digest: digest.to_vec(),
    };
    let cfg = src.config.load();
    let fields = crate::secrets::credential::fields(&cfg, Some(&src.secrets));
    let mut issues: Vec<String> = fields
        .iter()
        .filter(|f| f.readable.is_err())
        .map(|f| format!("{} `{}` {}", f.kind, f.entry, f.field))
        .collect();
    issues.truncate(MAX_ISSUES);
    let mut refs: Vec<String> = crate::secrets_api::refs(src)
        .into_iter()
        .filter(|(_, u)| u.node.is_some())
        .map(|(name, _)| name)
        .collect();
    refs.sort();
    refs.dedup();
    refs.truncate(MAX_REFS);
    let is_primary = cluster.is_primary();
    SecretsMark {
        head: Some(head.clone()),
        applied: if is_primary {
            Some(head)
        } else {
            st.applied.clone()
        },
        unreadable: u32::try_from(src.secrets.unreadable_count()).unwrap_or(u32::MAX),
        held: if is_primary { 0 } else { st.held },
        credential_issues: issues,
        secret_refs: refs,
    }
}

fn backoff(failures: u32) -> Duration {
    let secs = BACKOFF_MIN.as_secs().saturating_mul(1u64 << failures.min(6));
    Duration::from_secs(secs).min(BACKOFF_MAX)
}

/// REQ: CLU-015 — the primary's reverse heal: a locked store (its data-directory key is missing,
/// and every row is the cluster's) is filled from a replica holding every row at its stamp.
async fn reverse_heal(src: &Arc<Sources>, cluster: &Cluster, st: &mut Progress) {
    if src.secrets.status().state != StoreState::Locked {
        return;
    }
    if st.heal_next.is_some_and(|t| Instant::now() < t) {
        return;
    }
    let needs = src.secrets.heal_needs();
    if needs.is_empty() {
        return;
    }
    let reachable = cluster.reachable_peers();
    let me = cluster.identity.meta.node_id.clone();
    for n in cluster.identity.registry() {
        if n.node_id == me || n.ephemeral || n.witness || !reachable.contains(&n.node_id) {
            continue;
        }
        let Ok((all, _, _)) = fetch_all(cluster, &n.node_id).await else {
            continue;
        };
        let covers = needs.iter().all(|(name, stamp, deleted)| {
            all.iter().any(|r| {
                r.name == *name
                    && r.stamp == *stamp
                    && r.deleted == *deleted
                    && (r.deleted || r.value.is_some())
            })
        });
        if !covers {
            continue;
        }
        let store = Arc::clone(&src.secrets);
        let now = crate::pipeline::unix_now();
        let done = tokio::task::spawn_blocking(move || store.heal_with(&all, now)).await;
        match done {
            Ok(Ok(a)) => {
                tracing::warn!(from = %n.node_id, filled = a.changed, "secrets store refilled from a replica");
                st.heal_next = None;
                return;
            }
            Ok(Err(e)) => tracing::warn!("secrets store refill refused: {e}"),
            Err(e) => tracing::warn!("secrets store refill failed: {e}"),
        }
    }
    st.heal_next = Some(Instant::now() + BACKOFF_MAX);
}

/// REQ: CLU-015 — a replica that has rows of its own (it joined a cluster after standing alone)
/// hands them to the primary once per primary epoch; the primary's answer marks conflicts.
async fn adopt_own(src: &Arc<Sources>, cluster: &Cluster, st: &mut Progress, primary: &Member) {
    if st.adopted_in == Some(primary.epoch) {
        return;
    }
    let store = Arc::clone(&src.secrets);
    let own = tokio::task::spawn_blocking(move || store.local_rows())
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
    let Ok(own) = own else { return };
    if own.is_empty() {
        st.adopted_in = Some(primary.epoch);
        return;
    }
    let req = AdoptReq {
        secrets: own
            .iter()
            .map(|(name, kind, v)| AdoptItem {
                name: name.clone(),
                kind: kind.as_str().to_owned(),
                value: v.expose().to_owned(),
            })
            .collect(),
    };
    let Ok(body) = serde_json::to_vec(&req) else {
        return;
    };
    drop(own);
    let body = zeroize::Zeroizing::new(body);
    match cluster
        .call(&primary.node_id, KIND_ADOPT, body.to_vec(), FETCH_DEADLINE)
        .await
    {
        Ok(raw) => {
            if let Ok(ans) = serde_json::from_slice::<AdoptAns>(&raw) {
                tracing::info!(
                    adopted = ans.adopted.len(),
                    conflicts = ans.conflicts.len(),
                    "this node's secrets were offered to the cluster"
                );
            }
            st.adopted_in = Some(primary.epoch);
        }
        Err(e) => tracing::debug!("secrets hand-over not taken yet: {e}"),
    }
}

/// REQ: CLU-015 — one step of a replica: pull the primary's rows when its head differs from ours,
/// at most once per head, backing off after a failure.
async fn fetch_if_due(src: &Arc<Sources>, cluster: &Cluster, st: &mut Progress) {
    let Some(primary) = primary_of_highest(cluster) else {
        return;
    };
    let Some(theirs) = primary.secrets.head.clone() else {
        return;
    };
    let (stamp, digest) = src.secrets.head();
    let mine = SecretsHead {
        epoch: stamp.epoch,
        seq: stamp.seq,
        digest: digest.to_vec(),
    };
    if mine == theirs {
        st.applied = Some(theirs);
        st.failures = 0;
        st.next_try = None;
        return;
    }
    if st.applied.as_ref() == Some(&theirs) {
        return;
    }
    if st.next_try.is_some_and(|t| Instant::now() < t) {
        return;
    }
    if src.secrets.status().state != StoreState::Ready {
        return;
    }
    adopt_own(src, cluster, st, &primary).await;
    match pull(src, cluster, &primary.node_id).await {
        Ok((changed, held)) => {
            tracing::info!(changed, held, "stored secrets replicated from the primary");
            st.applied = Some(theirs);
            st.held = held;
            st.failures = 0;
            st.next_try = None;
        }
        Err(e) => {
            st.failures = st.failures.saturating_add(1);
            st.next_try = Some(Instant::now() + backoff(st.failures));
            if st.failures == 1 || st.failures.is_multiple_of(10) {
                tracing::warn!(failures = st.failures, "stored secrets not replicated yet: {e}");
            }
        }
    }
}

/// REQ: CLU-015 (ADR-903 §6, removal) — a member the cluster removed drops the cluster's rows, and
/// its own rows (shadowed) come back, once.
fn purge_if_removed(src: &Arc<Sources>, cluster: &Cluster, st: &mut Progress) {
    if st.removed_purged || !cluster.is_removed(&cluster.identity.meta.node_id) {
        return;
    }
    st.removed_purged = true;
    match src.secrets.purge_cluster() {
        Ok((deleted, restored)) => {
            tracing::warn!(deleted, restored, "this node was removed from the cluster: its cluster secrets were purged");
            if let Some(auth) = src.auth.get() {
                let actor = telltale_api::auth::Actor {
                    name: "cluster".to_owned(),
                    kind: "system",
                    remote: None,
                    reason: Some("removed from the cluster".to_owned()),
                };
                let detail = serde_json::json!({ "deleted": deleted, "restored": restored });
                auth.record(&actor, "secrets.purge", "cluster", &detail);
            }
        }
        Err(e) => {
            st.removed_purged = false;
            tracing::error!("purging cluster secrets after removal failed: {e}");
        }
    }
}

/// REQ: CLU-015 (ADR-903 §6, `cluster init`) — a primary's rows made before the cluster existed
/// become the cluster's, once. Stored rows of a standalone node are then shared like any other.
async fn init_rows_once(src: &Arc<Sources>, st: &mut Progress) {
    if st.init_done {
        return;
    }
    let store = Arc::clone(&src.secrets);
    let has_local = tokio::task::spawn_blocking(move || {
        store
            .status()
            .secrets
            .iter()
            .any(|s| !s.deleted && s.origin == "local")
    })
    .await
    .unwrap_or(false);
    if !has_local {
        st.init_done = true;
        return;
    }
    let store = Arc::clone(&src.secrets);
    match tokio::task::spawn_blocking(move || store.adopt_as_cluster()).await {
        Ok(Ok(n)) => {
            tracing::info!(count = n, "stored secrets made cluster secrets at cluster init");
            st.init_done = true;
        }
        Ok(Err(e)) => tracing::warn!("stored secrets couldn't be made cluster secrets yet: {e}"),
        Err(e) => tracing::warn!("stored secrets adoption failed: {e}"),
    }
}

/// REQ: CLU-015 — one pass of the sync task: loads the store, purges after a removal, publishes
/// this node's secrets mark, then either refills (a primary) or adopts and pulls (a replica).
pub(crate) async fn tick(src: &Arc<Sources>, cluster: &Arc<Cluster>, st: &mut Progress) {
    if cluster.is_ephemeral() {
        return;
    }
    let s = Arc::clone(src);
    let _ = tokio::task::spawn_blocking(move || {
        let _ = s.secrets.keys();
    })
    .await;
    purge_if_removed(src, cluster, st);
    let mark = mark_of(src, cluster, st);
    cluster.set_secrets(mark);
    if cluster.is_primary() {
        init_rows_once(src, st).await;
        reverse_heal(src, cluster, st).await;
    } else {
        fetch_if_due(src, cluster, st).await;
    }
}

/// REQ: CLU-015 — a single pass with fresh state (tests drive the task this way).
pub(crate) async fn run_once(src: &Arc<Sources>, cluster: &Arc<Cluster>) {
    let mut st = Progress::default();
    tick(src, cluster, &mut st).await;
}

/// REQ: CLU-015 — the sync task: a pass every [`TICK`], until the server stops. It never waits on
/// the DNS path, and nothing it does changes the manifest.
pub(crate) fn spawn(src: Arc<Sources>, mut stop: watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut st = Progress::default();
        loop {
            tokio::select! {
                () = tokio::time::sleep(TICK) => {}
                _ = stop.wait_for(|s| *s) => return,
            }
            if let Some(cluster) = src.cluster.clone() {
                tick(&src, &cluster, &mut st).await;
            }
        }
    });
}

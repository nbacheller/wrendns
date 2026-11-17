//! REQ: CLU-015, CLU-004, CLU-005 (ADR-903 §6) — stored secrets on full members. The primary
//! answers `secrets.fetch` with its rows (values only over the mTLS cluster channel, never to a
//! file or a blob), paged under 900 KiB; a full replica pulls when the head a heartbeat announces
//! differs from its own, verifies the answer against that head and the digest of its rows, and
//! applies it (re-encrypted under its own key). A locked primary's rows can be refilled from a
//! replica (the reverse heal). `secrets.adopt` lets a node that joined a cluster hand its own
//! secrets to the primary.
//!
//! Nothing here gates manifest application, `applied`, or readiness (ADR-058, CLU-004): the sync
//! is its own task, its failures only back off and log. Everything that touches the store, the
//! registry, the credentials or a file runs on a blocking thread, never on the runtime that serves
//! TCP, DoT and DoH. An N-1 primary answers "unknown call", which just means nothing is fetched
//! from it. An emergency primary changes nothing: it answers non-authoritatively, and nothing
//! replaces its rows (ADR-903 §4, ADR-917 point 11).

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use telltale_cluster::net::{Cluster, Member, SecretsHead, SecretsMark};
use telltale_cluster::node::Role;
use telltale_store::state::Stamp;
use tokio::sync::watch;
use zeroize::Zeroizing;

use super::store::{Applied, Dropped, Page, Remote, StoreState, Unavailable, head_from};
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

#[derive(Serialize, Deserialize)]
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

impl fmt::Debug for ItemJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // REQ: CLU-015 (L2) — a row's value never reaches a log or a debug dump.
        f.debug_struct("ItemJson")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("stamp", &(self.epoch, self.seq))
            .field("deleted", &self.deleted)
            .field("held", &self.held)
            .field("updated", &self.updated)
            .field("updated_by", &self.updated_by)
            .field("value", &self.value.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// REQ: CLU-015 (ADR-917 point 11) — a primary's answer is authoritative unless it is an emergency
/// primary's. Absent (an older primary), it is authoritative.
fn authoritative_default() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
struct FetchAns {
    head: HeadJson,
    /// The epoch the answering primary is in (a replica's orphans are judged against it).
    primary_epoch: u64,
    items: Vec<ItemJson>,
    #[serde(default)]
    more: bool,
    /// False for an emergency primary's answer: a replica only fills rows by stamp from it.
    #[serde(default = "authoritative_default")]
    authoritative: bool,
}

#[derive(Serialize, Deserialize)]
struct AdoptItem {
    name: String,
    kind: String,
    value: String,
}

impl fmt::Debug for AdoptItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // REQ: CLU-015 (L2) — a joining node's value never reaches a log or a debug dump.
        f.debug_struct("AdoptItem")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AdoptReq {
    secrets: Vec<AdoptItem>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AdoptAns {
    /// Names taken as cluster rows.
    adopted: Vec<String>,
    /// Names the cluster already holds (live or deleted), or that were refused: this node keeps
    /// its own row, shadowed.
    conflicts: Vec<String>,
}

/// Per-node state of the sync task.
#[derive(Debug, Default, Clone)]
pub(crate) struct Progress {
    /// The primary head this node last applied (or that it matched).
    applied: Option<SecretsHead>,
    /// Live rows of the last applied answer that the primary holds but couldn't decrypt.
    held: u32,
    failures: u32,
    /// Answers that ran ahead of the heartbeat in a row (ADR-917 point 14).
    stale: u32,
    next_try: Option<Instant>,
    /// Epoch of the primary this node last adopted its own rows to.
    adopted_in: Option<u64>,
    heal_next: Option<Instant>,
    removed_purged: bool,
    init_done: bool,
}

/// What one pull changed.
#[derive(Debug, Default)]
struct Pulled {
    changed: usize,
    held: u32,
    /// Names a tombstone of an older epoch kept deleted against a listing (ADR-917 point 10).
    conflicts: Vec<String>,
}

/// One answer read to the end: its rows, the head it carried, and the primary's epoch.
struct Fetched {
    rows: Vec<Remote>,
    head: (Stamp, [u8; 32]),
    primary_epoch: u64,
    authoritative: bool,
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// REQ: CLU-015 (L3) — a full member is one the registry lists as neither ephemeral nor witness,
/// and the cluster hasn't removed. Reads the registry: call it on a blocking thread.
fn full_member(cluster: &Cluster, node: &str) -> bool {
    !cluster.is_removed(node)
        && cluster
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

/// REQ: CLU-015 (ADR-917 point 12) — an audit record for the secrets sync, by the cluster, with the
/// peer it concerns in `detail`. Nothing secret goes in: names and counts only.
pub(crate) fn audit(
    src: &Sources,
    reason: &str,
    action: &str,
    target: &str,
    detail: &serde_json::Value,
) {
    if let Some(auth) = src.auth.get() {
        let actor = telltale_api::auth::Actor {
            name: "cluster".to_owned(),
            kind: "system",
            remote: None,
            reason: Some(reason.to_owned()),
        };
        auth.record(&actor, action, target, detail);
    }
}

/// REQ: CLU-015 (ADR-917 point 15) — a heal that dropped rows, shadows or orphans is audited as
/// `secrets.heal`, with names and counts only. Nothing is written for a heal that dropped nothing.
pub(crate) fn audit_heal(src: &Sources, reason: &str, dropped: &Dropped) {
    if dropped.rows == 0 && dropped.shadows == 0 && dropped.orphans.is_empty() {
        return;
    }
    audit(src, reason, "secrets.heal", "cluster", &dropped.detail());
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
    let req: FetchReq = if body.is_empty() {
        FetchReq::default()
    } else {
        serde_json::from_slice(&body).map_err(|_| "bad secrets.fetch request".to_owned())?
    };
    let log = tracing::dispatcher::get_default(Clone::clone);
    tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&log, || {
            // The registry is read from disk: the membership checks run on this blocking thread.
            // A primary answers a full member. A replica keeps only its own registry entry, so it
            // answers only the primary of the highest epoch (a primary is always a full member): the
            // reverse heal (REQ: CLU-015, AC9) reads a replica's rows that way.
            let allowed = if cluster.is_primary() {
                full_member(&cluster, &peer)
            } else {
                is_current_primary(&cluster, &peer)
            };
            if !allowed {
                return Err("only a full member can read stored secrets".into());
            }
            build_answer(&src, &cluster, &req)
        })
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
    let (role, epoch) = cluster.role();
    let ans = FetchAns {
        head: head_json(page.head),
        primary_epoch: epoch,
        items: page.items.iter().map(item_json).collect(),
        more: page.more,
        // REQ: CLU-015 (ADR-917 point 11) — only a primary's own answer is authoritative.
        authoritative: matches!(role, Role::Primary),
    };
    serde_json::to_vec(&ans).map_err(|e| e.to_string())
}

/// REQ: CLU-015 (ADR-903 §6) — a joining node's rows, taken on the primary as cluster rows where
/// the cluster doesn't hold the name; the rest are conflicts (kept by the joiner, shadowed). Every
/// name taken or refused is audited.
pub(crate) async fn answer_adopt(
    src: Arc<Sources>,
    cluster: Arc<Cluster>,
    peer: String,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
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
            if !full_member(&cluster, &peer) {
                return Err("only a full member can hand over its secrets".into());
            }
            let now = crate::pipeline::unix_now();
            let reason = format!("joined from {via}");
            let mut ans = AdoptAns::default();
            // REQ: CLU-015 (ADR-917 point 12) — a name the cluster holds, live or deleted, is a
            // conflict: a tombstone is a revocation, not a free name.
            let held: BTreeSet<String> = src
                .secrets
                .status()
                .secrets
                .into_iter()
                .map(|s| s.name)
                .collect();
            for it in req.secrets {
                let name = it.name.clone();
                let refused = |ans: &mut AdoptAns| {
                    audit(
                        &src,
                        &reason,
                        "secret.adopt_conflict",
                        &name,
                        &serde_json::json!({ "peer": peer }),
                    );
                    ans.conflicts.push(name.clone());
                };
                if held.contains(&name) {
                    refused(&mut ans);
                    continue;
                }
                let Ok(kind) = Kind::parse(&it.kind) else {
                    refused(&mut ans);
                    continue;
                };
                let Ok(value) = SecretValue::new(kind, zeroize::Zeroizing::new(it.value)) else {
                    refused(&mut ans);
                    continue;
                };
                match src
                    .secrets
                    .put(&name, kind, &value, epoch, &reason, "cluster", now)
                {
                    Ok(_) => {
                        audit(
                            &src,
                            &reason,
                            "secret.adopt",
                            &name,
                            &serde_json::json!({ "peer": peer }),
                        );
                        ans.adopted.push(name);
                    }
                    Err(_) => refused(&mut ans),
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
async fn fetch_all(cluster: &Cluster, target: &str) -> Result<Fetched, String> {
    let mut after: Option<String> = None;
    let mut head: Option<(Stamp, [u8; 32])> = None;
    let mut primary_epoch = 0;
    let mut authoritative = true;
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
                authoritative = ans.authoritative;
            }
            Some(h) if h != this => {
                return Err(
                    "the primary's head changed while its rows were read: trying again later"
                        .into(),
                );
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
    Ok(Fetched {
        rows: all,
        head,
        primary_epoch,
        authoritative,
    })
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

/// REQ: CLU-015 (L1) — an answer is applied only when it is the head the heartbeat announced, and
/// its primary is in the epoch the heartbeat named. Anything else is a race (or a stale view):
/// the pull is retried later, and nothing is applied.
pub(crate) fn check_answer(
    head: (Stamp, [u8; 32]),
    answer_epoch: u64,
    announced: &SecretsHead,
    announced_epoch: u64,
) -> Result<(), String> {
    let (stamp, digest) = head;
    if stamp.epoch != announced.epoch
        || stamp.seq != announced.seq
        || digest.as_slice() != announced.digest.as_slice()
    {
        return Err(
            "the answer's head isn't the one the heartbeat announced: trying again later".into(),
        );
    }
    if answer_epoch != announced_epoch {
        return Err("the answer's primary epoch isn't the heartbeat's: trying again later".into());
    }
    Ok(())
}

/// Why a pull didn't apply: an answer ahead of the heartbeat that announced its head (a race, tried
/// again at the next pass, with no backoff), or a failure (backed off).
#[derive(Debug)]
enum PullError {
    Stale(String),
    Failed(String),
}

/// REQ: CLU-015 — the replica's pull: fetch, check the answer against the heartbeat, apply.
async fn pull(
    src: &Arc<Sources>,
    cluster: &Cluster,
    primary: &Member,
    announced: &SecretsHead,
) -> Result<Pulled, PullError> {
    let f = fetch_all(cluster, &primary.node_id)
        .await
        .map_err(PullError::Failed)?;
    check_answer(f.head, f.primary_epoch, announced, primary.epoch).map_err(PullError::Stale)?;
    let store = Arc::clone(&src.secrets);
    let now = crate::pipeline::unix_now();
    let (rows, epoch, authoritative) = (f.rows, f.primary_epoch, f.authoritative);
    let applied: Applied =
        tokio::task::spawn_blocking(move || store.apply_remote(&rows, epoch, authoritative, now))
            .await
            .map_err(|e| PullError::Failed(format!("secrets worker failed: {e}")))?
            .map_err(|e| PullError::Failed(e.to_string()))?;
    Ok(Pulled {
        changed: applied.changed,
        held: u32::try_from(applied.held).unwrap_or(u32::MAX),
        conflicts: applied.conflicts,
    })
}

/// REQ: CLU-015 — this node's secrets mark, as heartbeats carry it, and the head it announces.
/// Runs on a blocking thread (the store's lock, the credentials' files and the references).
fn mark_of(
    src: &Sources,
    cluster: &Cluster,
    applied: Option<SecretsHead>,
    held: u32,
) -> (SecretsMark, SecretsHead) {
    let (stamp, digest) = src.secrets.head();
    let mine = SecretsHead {
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
    let mark = SecretsMark {
        head: Some(mine.clone()),
        applied: if is_primary {
            Some(mine.clone())
        } else {
            applied
        },
        unreadable: u32::try_from(src.secrets.unreadable_count()).unwrap_or(u32::MAX),
        held: if is_primary { 0 } else { held },
        credential_issues: issues,
        secret_refs: refs,
    };
    (mark, mine)
}

fn backoff(failures: u32) -> Duration {
    let secs = BACKOFF_MIN
        .as_secs()
        .saturating_mul(1u64 << failures.min(6));
    Duration::from_secs(secs).min(BACKOFF_MAX)
}

/// REQ: CLU-015 — the primary's reverse heal: a locked store (its data-directory key is missing,
/// and every row is the cluster's) is filled from a replica holding every row at its stamp.
async fn reverse_heal(src: &Arc<Sources>, cluster: &Arc<Cluster>, st: &mut Progress) {
    if st.heal_next.is_some_and(|t| Instant::now() < t) {
        return;
    }
    // The store's state, its rows and the registry are read on a blocking thread.
    let (s, c) = (Arc::clone(src), Arc::clone(cluster));
    let Ok(Some((needs, peers))) = tokio::task::spawn_blocking(move || {
        if s.secrets.status().state != StoreState::Locked {
            return None;
        }
        let needs = s.secrets.heal_needs();
        if needs.is_empty() {
            return None;
        }
        let reachable = c.reachable_peers();
        let me = c.identity.meta.node_id.clone();
        let peers: Vec<String> = c
            .identity
            .registry()
            .into_iter()
            .filter(|n| {
                n.node_id != me && !n.ephemeral && !n.witness && reachable.contains(&n.node_id)
            })
            .map(|n| n.node_id)
            .collect();
        Some((needs, peers))
    })
    .await
    else {
        return;
    };
    for peer in &peers {
        let Ok(f) = fetch_all(cluster, peer).await else {
            continue;
        };
        let covers = needs.iter().all(|(name, stamp, deleted)| {
            f.rows.iter().any(|r| {
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
        let rows = f.rows;
        let (s, from) = (Arc::clone(src), peer.clone());
        let done = tokio::task::spawn_blocking(move || {
            let r = store.heal_with(&rows, now);
            if let Ok((_, dropped)) = &r {
                audit_heal(&s, &format!("refilled from replica {from}"), dropped);
            }
            r
        })
        .await;
        match done {
            Ok(Ok((a, _))) => {
                tracing::warn!(from = %peer, filled = a.changed, "secrets store refilled from a replica");
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
    drop(own);
    let Ok(encoded) = serde_json::to_vec(&req) else {
        return;
    };
    drop(req);
    // REQ: CLU-015 (L2) — the encoded request is handed to the channel as it is: it is moved, not
    // copied, out of the wrapper that zeroizes it.
    let mut encoded = Zeroizing::new(encoded);
    let body = std::mem::take(&mut *encoded);
    match cluster
        .call(&primary.node_id, KIND_ADOPT, body, FETCH_DEADLINE)
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
/// at most once per head, backing off after a failure. `mine` is this node's head and `ready` says
/// whether its store is usable; both were read on a blocking thread.
async fn fetch_if_due(
    src: &Arc<Sources>,
    cluster: &Cluster,
    st: &mut Progress,
    mine: &SecretsHead,
    ready: bool,
) {
    let Some(primary) = primary_of_highest(cluster) else {
        return;
    };
    let Some(theirs) = primary.secrets.head.clone() else {
        return;
    };
    if *mine == theirs {
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
    if !ready {
        return;
    }
    adopt_own(src, cluster, st, &primary).await;
    match pull(src, cluster, &primary, &theirs).await {
        Ok(p) => {
            tracing::info!(
                changed = p.changed,
                held = p.held,
                "stored secrets replicated from the primary"
            );
            for name in &p.conflicts {
                tracing::warn!(
                    secret = %name,
                    "a secret deleted here is listed as live by the primary: the deletion is kept; delete it again on the primary to settle it"
                );
                audit(
                    src,
                    "replicated from the primary",
                    "secret.conflict",
                    name,
                    &serde_json::json!({
                        "peer": primary.node_id,
                        "reason": "a deletion of an older epoch is kept against the primary's listing",
                    }),
                );
            }
            st.applied = Some(theirs);
            st.held = p.held;
            st.failures = 0;
            st.stale = 0;
            st.next_try = None;
        }
        Err(PullError::Stale(e)) => {
            // REQ: CLU-015 (ADR-917 point 14) — the primary's heartbeat is a pass behind its answer:
            // the next pass asks again, with no backoff. A run of them is visible at warn.
            st.stale = st.stale.saturating_add(1);
            if st.stale == 3 || st.stale.is_multiple_of(20) {
                tracing::warn!(
                    attempts = st.stale,
                    "stored secrets: the primary's answers keep running ahead of its heartbeat: {e}"
                );
            } else {
                tracing::debug!(
                    "stored secrets: the primary's answer is ahead of its heartbeat: {e}"
                );
            }
        }
        Err(PullError::Failed(e)) => {
            st.failures = st.failures.saturating_add(1);
            st.next_try = Some(Instant::now() + backoff(st.failures));
            if st.failures == 1 || st.failures.is_multiple_of(10) {
                tracing::warn!(
                    failures = st.failures,
                    "stored secrets not replicated yet: {e}"
                );
            }
        }
    }
}

/// REQ: CLU-015 (ADR-903 §6, removal) — a member the cluster removed drops the cluster's rows, and
/// its own rows (shadowed) come back, once. Runs on a blocking thread.
fn purge_if_removed(src: &Sources, cluster: &Cluster, st: &mut Progress) {
    if st.removed_purged || !cluster.is_removed(&cluster.identity.meta.node_id) {
        return;
    }
    st.removed_purged = true;
    match src.secrets.purge_cluster() {
        Ok((deleted, restored)) => {
            tracing::warn!(
                deleted,
                restored,
                "this node was removed from the cluster: its cluster secrets were purged"
            );
            let detail = serde_json::json!({ "deleted": deleted, "restored": restored });
            audit(
                src,
                "removed from the cluster",
                "secrets.purge",
                "cluster",
                &detail,
            );
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
            tracing::info!(
                count = n,
                "stored secrets made cluster secrets at cluster init"
            );
            st.init_done = true;
        }
        Ok(Err(e)) => tracing::warn!("stored secrets couldn't be made cluster secrets yet: {e}"),
        Err(e) => tracing::warn!("stored secrets adoption failed: {e}"),
    }
}

/// REQ: CLU-015 — one pass of the sync task: loads the store, purges after a removal, publishes
/// this node's secrets mark, then either refills (a primary), does nothing (an emergency primary,
/// ADR-903 §4), or adopts and pulls (a replica). The store, registry and file work is on blocking
/// threads (CLU-004): the runtime that serves the DNS listeners never waits on it.
pub(crate) async fn tick(src: &Arc<Sources>, cluster: &Arc<Cluster>, st: &mut Progress) {
    let (s, c) = (Arc::clone(src), Arc::clone(cluster));
    // REQ: CLU-015 (review N5) — the pass works on a copy: if it panics, `st` keeps what it was
    // (`init_done`, `removed_purged`, `adopted_in` and the backoff), and the next pass goes on.
    let mut work = st.clone();
    // REQ: CLU-004 — whether this node is ephemeral reads the registry from disk, so the pass's
    // file and store work all runs on this blocking thread.
    let joined = tokio::task::spawn_blocking(move || {
        if c.is_ephemeral() {
            return (work, None);
        }
        let _ = s.secrets.keys();
        purge_if_removed(&s, &c, &mut work);
        let (mark, mine) = mark_of(&s, &c, work.applied.clone(), work.held);
        let ready = s.secrets.status().state == StoreState::Ready;
        c.set_secrets(mark);
        (work, Some((mine, ready)))
    })
    .await;
    let (work, pass) = match joined {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("secrets sync pass failed: {e}");
            return;
        }
    };
    *st = work;
    let Some((mine, ready)) = pass else {
        return;
    };
    match cluster.role().0 {
        Role::Primary => {
            init_rows_once(src, st).await;
            reverse_heal(src, cluster, st).await;
        }
        // REQ: CLU-015 (ADR-917 point 11) — an emergency primary changes nothing: no hand-over of
        // its rows, no refill, no replacement of its key.
        Role::Emergency => {}
        Role::Replica => fetch_if_due(src, cluster, st, &mine, ready).await,
    }
}

/// REQ: CLU-015 — a single pass with fresh state (tests drive the task this way).
#[cfg(test)]
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

//! Automatic failover at runtime (REQ: CLU-005; ADR-056): runs [`crate::election`] over the
//! cluster channel.
//!
//! It's on when the cluster's failover mode is `auto` (set on the primary, carried in signed
//! manifests) and the registry has at least three voters (eligible nodes plus witnesses), this
//! node among them. Otherwise the cluster stays in manual mode (ADR-051) and nothing here
//! changes roles.
//!
//! - Votes travel as RPCs (`elect.ask`) on the streams. A candidate can only ask for itself:
//!   the peer ID comes from the stream's certificate.
//! - The ballot is written to disk (fsync) before a vote is answered.
//! - The primary publishes only while its lease is valid ([`Cluster::may_publish`]). A primary
//!   that can't renew stops publishing before anyone else can be elected. DNS keeps answering
//!   throughout (CLU-004): none of this is on the query path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::election::{Ask, Ballot, Elector, LEASE_MS, Out, Reply};
use crate::net::Cluster;
use crate::node::{Identity, Role};

/// The vote RPC.
pub const KIND: &str = "elect.ask";
/// REQ: CLU-005 (ADR-154, GitHub issue #3) — a Git-managed node asks an emergency primary to
/// hand over (automatic failover under the `GitOps` authority).
pub const HANDOVER_KIND: &str = "elect.handover";
/// How often the election advances.
const TICK: Duration = Duration::from_millis(250);
/// How long a vote request may take.
const ASK_DEADLINE: Duration = Duration::from_secs(2);
/// How often the registry and mode are re-read.
const RELOAD: Duration = Duration::from_secs(5);

/// The cluster's voters (eligible nodes and witnesses), sorted.
pub fn voters(id: &Identity) -> Vec<String> {
    let mut v: Vec<String> = id
        .registry()
        .into_iter()
        .filter(crate::node::NodeRecord::voter)
        .map(|n| n.node_id)
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Counts the electors built in this process (see `Elector::start_rounds_at`).
static ELECTOR_GEN: AtomicU64 = AtomicU64::new(0);

/// Whether automatic failover runs on this node: `auto` mode, three or more voters, and this
/// node one of them.
pub fn active(id: &Identity) -> bool {
    let v = voters(id);
    id.meta.failover == "auto" && v.len() >= 3 && v.contains(&id.meta.node_id)
}

/// REQ: CLU-005 (review 05-05) — leases are timed on the election clock, which never steps:
/// on the wall clock, NTP setting a Pi's time after boot made every lease it granted look
/// expired at once.
fn now_ms() -> u64 {
    crate::clock::now_ms()
}

/// This node's ballot on this process's election clock ([`Ballot::adopt`]). A ballot moved
/// from another clock is stored at once, so later reads don't extend its lease again.
fn load_ballot(cluster: &Cluster, now: u64) -> Ballot {
    let mut b = cluster.identity.ballot();
    if b.adopt(crate::clock::id(), now)
        && let Err(e) = cluster.identity.save_ballot(&b)
    {
        warn!("cluster: can't store this node's ballot: {e}");
    }
    b
}

/// Answers `peer`'s vote request. Without a running election (a witness, or a node in manual
/// mode) the stored ballot answers, with nothing applied.
pub fn answer(cluster: &Cluster, peer: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let ask: Ask = serde_json::from_slice(body).map_err(|e| format!("bad vote request: {e}"))?;
    if ask.candidate != peer {
        return Err("a node can only ask for votes for itself".into());
    }
    // REQ: CLU-005 (T10.7) — only a node the registry lists as eligible may stand: a resolver
    // pod or a witness asking is refused before the ballot moves (a granted vote would bind
    // this node to it for the epoch, and a high epoch would fence the primary).
    if !cluster
        .identity
        .registry()
        .iter()
        .any(|n| n.node_id == peer && n.eligible && !n.witness)
    {
        return Err("only an eligible node can ask for votes".into());
    }
    let now = now_ms();
    let mut guard = cluster
        .election
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (reply, ballot) = if let Some(el) = guard.as_mut() {
        let (reply, outs) = el.on_ask(&ask, now);
        let changed = outs.contains(&Out::Persist);
        (reply, changed.then(|| el.ballot.clone()))
    } else {
        let mut b = load_ballot(cluster, now);
        let before = b.clone();
        // A renewal: the asker is the primary this node follows, in the epoch it follows.
        let renewal = ask.epoch == cluster.role().1
            && cluster
                .members()
                .iter()
                .any(|m| m.primary && m.node_id == ask.candidate && m.epoch == ask.epoch);
        let reply = decide_without_election(&mut b, &ask, now, renewal);
        (reply, (b != before).then_some(b))
    };
    if let Some(b) = ballot {
        // Durable before the vote leaves this node.
        cluster.identity.save_ballot(&b)?;
    }
    drop(guard);
    if reply.granted && !ask.pre {
        cluster.note_vote(&ask.candidate, ask.epoch);
    }
    serde_json::to_vec(&reply).map_err(|e| e.to_string())
}

/// REQ: CLU-005 (ADR-960) — a node with no running election (manual mode, or not a voter)
/// grants no real vote: with `auto` just turned off on a primary that now writes without a
/// lease, a vote from here could make a second primary. A pre-vote changes nothing, so it is
/// still answered.
fn decide_without_election(b: &mut Ballot, ask: &Ask, now: u64, renewal: bool) -> Reply {
    // A renewal (`renewal`: the primary this node follows, in its current epoch) is granted: it is what
    // lets a primary that has just adopted `auto` get its lease, so it can publish the record
    // that turns the replicas to `auto`. A vote for a higher epoch is refused.
    if ask.pre || renewal {
        b.decide(ask, now, (0, 0))
    } else {
        Reply {
            round: ask.round,
            granted: false,
            epoch: b.epoch,
        }
    }
}

/// Whether a primary resumes its epoch under a new election (see `step`).
fn resumes_as_primary(role: Role, epoch: u64, can_lead: bool) -> bool {
    matches!(role, Role::Primary | Role::Emergency) && epoch > 0 && can_lead
}

/// REQ: CLU-005 (ADR-154, GitHub issue #3) — why an emergency primary refuses to hand over, on
/// plain facts (`None`: it agrees). `role` is this node's; `peer_can_take_over` is whether the
/// asker is an eligible voter, Git-managed, and up.
fn handover_refusal(
    auto: bool,
    gitops: bool,
    role: Role,
    peer_can_take_over: bool,
) -> Option<&'static str> {
    if !auto {
        Some("automatic failover is off: promote the node instead")
    } else if !gitops {
        Some("the configuration doesn't come from Git: nothing needs taking over")
    } else if role != Role::Emergency {
        Some("this node isn't an emergency primary")
    } else if !peer_can_take_over {
        Some(
            "only an eligible, Git-managed node that is up can ask an emergency primary to hand over",
        )
    } else {
        None
    }
}

/// REQ: CLU-005 (ADR-154, GitHub issue #3) — `peer`, a Git-managed eligible node, asks this
/// emergency primary to hand over. The primary stops renewing its lease; the nodes that aren't
/// Git-managed hold back ([`Cluster::defers_to_git_node`]), so the election picks `peer`. If no
/// one takes over within the give-up time the primary keeps its role (ADR-118). The peer ID
/// comes from the stream's certificate; its Git-managed claim is its Hello's, which only a
/// registry-eligible node (one that already holds the cluster key) could abuse.
pub fn answer_handover(cluster: &Cluster, peer: &str) -> Result<Vec<u8>, String> {
    let id = cluster.identity.reload();
    let now = crate::net::wall_ms();
    let eligible = id
        .registry()
        .iter()
        .any(|n| n.node_id == peer && n.eligible && !n.witness);
    let git_and_up = cluster
        .members()
        .iter()
        .any(|m| m.node_id == peer && m.config_source == "gitops" && m.up(now));
    if let Some(why) = handover_refusal(
        active(&id),
        id.meta.config_authority == "gitops",
        cluster.role().0,
        eligible && git_and_up,
    ) {
        return Err(why.to_owned());
    }
    cluster.start_handover(peer);
    Ok(b"handing over".to_vec())
}

/// REQ: CLU-005 (ADR-154, GitHub issue #3) — asks the emergency primary `primary` to hand over
/// to this (Git-managed) node.
pub async fn ask_handover(cluster: &Cluster, primary: &str) -> Result<(), String> {
    cluster
        .call(primary, HANDOVER_KIND, Vec::new(), ASK_DEADLINE)
        .await
        .map(|_| ())
}

/// The election loop: until `stop`, keeps this node's role in step with the votes.
pub async fn run(cluster: Arc<Cluster>, mut stop: watch::Receiver<bool>) {
    let (tx, mut rx) = mpsc::channel::<(String, Reply)>(64);
    let mut tick = tokio::time::interval(TICK);
    let mut id = cluster.identity.reload();
    let mut reloaded = tokio::time::Instant::now();
    let mut stamp = meta_stamp(&cluster);
    loop {
        let reply = tokio::select! {
            _ = stop.changed() => return,
            _ = tick.tick() => None,
            Some(r) = rx.recv() => Some(r),
        };
        // REQ: CLU-005 (ADR-960) — a change to `cluster.json` (`set-failover`, a signed record
        // adopted from the primary) is taken up on this tick, not at the next reload: a running
        // primary starts renewing its lease within one tick of the mode turning `auto`.
        let now_stamp = meta_stamp(&cluster);
        if reloaded.elapsed() >= RELOAD || now_stamp != stamp {
            id = cluster.identity.reload();
            reloaded = tokio::time::Instant::now();
            stamp = now_stamp;
        }
        let outs = step(&cluster, &id, reply, now_ms());
        dispatch(&cluster, &id, outs, &tx);
    }
}

/// When `cluster.json` last changed (one `stat` per tick, on the cluster task).
fn meta_stamp(cluster: &Cluster) -> Option<std::time::SystemTime> {
    std::fs::metadata(cluster.identity.dir.join("cluster.json"))
        .and_then(|m| m.modified())
        .ok()
}

/// One turn of the election, under its lock: returns what to send and do.
fn step(cluster: &Cluster, id: &Identity, reply: Option<(String, Reply)>, now: u64) -> Vec<Out> {
    let mut guard = cluster
        .election
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !active(id) {
        // Manual mode: roles change only by `promote` (ADR-051).
        *guard = None;
        drop(guard);
        cluster.set_lease_ok(true);
        return Vec::new();
    }
    let voters = voters(id);
    // Only a node holding the cluster key may stand: a winner must be able to sign.
    let can_lead = id.meta.eligible && !id.meta.witness && id.holds_ca();
    if guard
        .as_ref()
        .is_none_or(|e| e.voters != voters || e.eligible != can_lead)
    {
        let mut el = Elector::new(
            &id.meta.node_id,
            voters,
            can_lead,
            load_ballot(cluster, now),
        );
        // A reply to the previous elector may still arrive: number this one's rounds apart.
        el.start_rounds_at(1 + (ELECTOR_GEN.fetch_add(1, Ordering::Relaxed) << 20));
        // REQ: CLU-005 (ADR-947) — a node that isn't the primary waits one lease period before its
        // first try: no lease exists yet, so without the wait it would stand against a primary that is
        // up and about to take its lease. The primary itself doesn't wait: it stands at once and
        // takes the lease (waiting too let a replica win the race, in the three-node run).
        if !cluster.is_primary() {
            el.defer_first_try(now + LEASE_MS);
        }
        // REQ: CLU-005 (ADR-960) — a node stands only after it has seen a lease from another
        // primary lapse. A primary that never held a lease under `auto` is never deposed.
        el.stand_only_after_a_lease();
        // A primary resumes its epoch whenever its election starts: after a restart, and when
        // `auto` is turned on under it while it runs. It renews at once and writes again once a
        // majority grants it. A primary that is stale (a newer epoch exists) is refused by the
        // voters and steps down, as in any election.
        let (role, epoch) = cluster.role();
        if matches!(role, Role::Primary | Role::Emergency) && epoch > 0 && !can_lead {
            warn!(
                epoch,
                "cluster: this primary can't lead under automatic failover (not eligible, or without the cluster key) and stops publishing until another node is elected"
            );
        }
        if resumes_as_primary(role, epoch, can_lead) {
            el.resume(epoch);
            // The primary was writing in manual mode; it pauses for the first round (a lease it
            // never held can't be assumed) and says so once, not as a lost lease.
            cluster.begin_lease();
            info!(
                epoch,
                "cluster: this primary adopts automatic failover and renews its lease"
            );
        }
        info!(voters = el.voters.len(), can_lead, "automatic failover on");
        *guard = Some(el);
    }
    let Some(el) = guard.as_mut() else {
        return Vec::new();
    };
    let local = cluster.local_state();
    el.applied = (local.epoch, local.applied_seq);
    // REQ: OPS-010 (ADR-118) — in maintenance this node votes but doesn't stand; a primary
    // handing over stops renewing, unless no one took over within the give-up time.
    // REQ: CLU-005 (ADR-154) — and under the GitOps authority a node that isn't Git-managed
    // leaves the election to one that is, while one is up (it votes either way).
    // "A primary is up" is the election's own evidence, the lease this node granted that is still
    // running: a member's `primary` flag comes from its Hello, and stays stale when a node is
    // elected on a stream that was already open (CI hit it: the deference clock ran out while an
    // emergency primary held the lease, and a node that isn't Git-managed won the handover).
    let lease_held = el.ballot.lease_held_by_other(&el.id, now);
    el.standing = !cluster.in_maintenance() && !cluster.defers_to_git_node(id, lease_held);
    if el.leading().is_some() {
        cluster.give_up_handover(crate::net::wall_ms());
    }
    el.stepping_down = cluster.stepping_down();
    // ADR-051 — only voters' epochs count (see `Cluster::may_announce_epoch`).
    let seen = cluster
        .members()
        .iter()
        .filter(|m| cluster.may_announce_epoch(&m.node_id))
        .map(|m| m.epoch)
        .fold(cluster.role().1, u64::max);
    let mut outs = el.observe(seen);
    if let Some((from, r)) = reply {
        cluster.note_voter_reply(&from, r.granted, r.epoch);
        outs.extend(el.on_reply(&from, &r, now));
    }
    let jitter = rand::random::<u64>() % (LEASE_MS / 2);
    outs.extend(el.tick(now, jitter));
    // A primary writes only while its lease holds.
    cluster.set_lease_ok(!cluster.is_primary() || el.writable(now));
    cluster.set_failover_view(FailoverView {
        active: true,
        voters: el.voters.clone(),
        leading: el.leading(),
        lease_ms_left: match el.phase {
            crate::election::Phase::Leader { lease_until_ms, .. } => {
                lease_until_ms.saturating_sub(now)
            }
            _ => 0,
        },
        ballot_epoch: el.ballot.epoch,
        ballot_for: el.ballot.candidate.clone(),
    });
    // Durable before any request for votes leaves this node.
    if outs.contains(&Out::Persist)
        && let Err(e) = cluster.identity.save_ballot(&el.ballot)
    {
        warn!("cluster: can't store this node's ballot: {e}");
    }
    outs
}

/// Sends vote requests (their replies come back on `tx`) and applies role changes.
fn dispatch(
    cluster: &Arc<Cluster>,
    id: &Identity,
    outs: Vec<Out>,
    tx: &mpsc::Sender<(String, Reply)>,
) {
    for o in outs {
        match o {
            Out::Send { to, ask } => {
                let (c, tx) = (Arc::clone(cluster), tx.clone());
                tokio::spawn(async move {
                    let body = serde_json::to_vec(&ask).unwrap_or_default();
                    if let Ok(b) = c.call(&to, KIND, body, ASK_DEADLINE).await
                        && let Ok(r) = serde_json::from_slice::<Reply>(&b)
                    {
                        let _ = tx.send((to, r)).await;
                    }
                });
            }
            Out::Elected { epoch } => elected(cluster, id, epoch),
            Out::StepDown { epoch } => {
                cluster.set_lease_ok(false);
                cluster.event(
                    "stepped_down",
                    &id.meta.node_id,
                    if cluster.stepping_down() && cluster.in_maintenance() {
                        format!("handed over for maintenance: a newer epoch than {epoch} exists")
                    } else if cluster.stepping_down() {
                        format!(
                            "handed over to a Git-managed node: a newer epoch than {epoch} exists"
                        )
                    } else {
                        format!("a newer epoch than {epoch} exists")
                    },
                );
                // A handover asked for by a Git-managed node ends with the step-down, so a later
                // election doesn't find this node still refusing to renew.
                cluster.end_handover();
            }
            Out::Persist => {}
        }
    }
}

/// Becomes the primary of `epoch` after winning it.
fn elected(cluster: &Cluster, id: &Identity, epoch: u64) {
    if !id.holds_ca() {
        warn!(
            epoch,
            "cluster: won the election but doesn't hold the cluster key yet; staying a replica"
        );
        return;
    }
    // ADR-048 — a GitOps cluster's node that isn't GitOps-managed coordinates only.
    let gitops = id.meta.config_authority == "gitops";
    let role = if gitops && cluster.config_source() != "gitops" {
        Role::Emergency
    } else {
        Role::Primary
    };
    match cluster.set_role(role, epoch) {
        Ok(()) => {
            info!(epoch, ?role, "cluster: elected primary");
            cluster.event(
                "elected",
                &id.meta.node_id,
                format!("epoch {epoch} by vote"),
            );
        }
        Err(e) => warn!("cluster: elected but can't store the new role: {e}"),
    }
}

/// REQ: CLU-009 (T24.33) — the last vote reply a voter gave this node, on the wall clock.
#[derive(Debug, Clone, Default)]
pub struct VoterReply {
    /// When the reply came (Unix ms).
    pub at_ms: u64,
    pub granted: bool,
    /// The epoch the voter reported.
    pub epoch: u64,
    /// When it last granted a vote or lease renewal (Unix ms).
    pub last_grant_ms: Option<u64>,
}

/// What the Cluster page shows about the election (ADR-056).
#[derive(Debug, Clone, Default)]
pub struct FailoverView {
    pub active: bool,
    pub voters: Vec<String>,
    /// The epoch this node leads, when it's the elected primary.
    pub leading: Option<u64>,
    /// How long this primary's lease still runs (0 when it isn't leading).
    pub lease_ms_left: u64,
    pub ballot_epoch: u64,
    pub ballot_for: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: CLU-005 (ADR-960) — a node in manual mode refuses a real vote but answers a pre-vote.
    #[test]
    fn clu_005_t21_7_manual_mode_refuses_real_votes() {
        let ask = |pre| Ask {
            epoch: 2,
            candidate: "c".into(),
            round: 1,
            pre,
            applied: (0, 0),
        };
        let mut b = Ballot::default();
        let r = decide_without_election(&mut b, &ask(false), 1_000, false);
        assert!(!r.granted);
        assert_eq!(b, Ballot::default(), "the ballot moved");
        assert!(decide_without_election(&mut b, &ask(true), 1_000, false).granted);
        // A renewal (the caller found the asker to be the primary this node follows, in its
        // epoch) is granted even on an empty ballot, which is the state of a replica that never
        // voted; a vote for another epoch or another candidate is refused.
        let mk = |epoch, candidate: &str| Ask {
            epoch,
            candidate: candidate.into(),
            round: 1,
            pre: false,
            applied: (0, 0),
        };
        let mut b = Ballot::default();
        assert!(decide_without_election(&mut b, &mk(1, "a"), 1_000, true).granted);
        assert_eq!(b.epoch, 1);
        assert!(!decide_without_election(&mut b, &mk(2, "a"), 1_000, false).granted);
        assert!(!decide_without_election(&mut b, &mk(1, "c"), 1_000, false).granted);
    }

    // REQ: CLU-005 (ADR-960) — a primary resumes whatever its stored ballot says.
    #[test]
    fn clu_005_t21_7_a_primary_resumes_whatever_its_ballot() {
        assert!(resumes_as_primary(Role::Primary, 1, true));
        assert!(resumes_as_primary(Role::Emergency, 4, true));
        assert!(!resumes_as_primary(Role::Replica, 1, true));
        assert!(!resumes_as_primary(Role::Primary, 0, true));
        assert!(!resumes_as_primary(Role::Primary, 1, false));
    }

    /// REQ: CLU-005 (ADR-154, GitHub issue #3) — an emergency primary hands over only under
    /// automatic failover and the `GitOps` authority, only when it is an emergency primary, and
    /// only to an eligible, Git-managed node that is up; every refusal says why.
    #[test]
    fn clu_005_an_emergency_primary_hands_over_only_to_a_node_that_can_publish() {
        let emergency = Role::Emergency;
        assert_eq!(handover_refusal(true, true, emergency, true), None);
        let refusals = [
            handover_refusal(false, true, emergency, true),
            handover_refusal(true, false, emergency, true),
            handover_refusal(true, true, Role::Primary, true),
            handover_refusal(true, true, emergency, false),
        ];
        assert!(handover_refusal(true, true, Role::Replica, true).is_some());
        for (i, r) in refusals.iter().enumerate() {
            assert!(r.is_some(), "case {i} was agreed to");
            for (j, other) in refusals.iter().enumerate() {
                assert!(
                    i == j || r != other,
                    "cases {i} and {j} give the same reason"
                );
            }
        }
        // The reasons name the way out where there is one.
        assert!(refusals[0].is_some_and(|r| r.contains("promote")));
    }
}

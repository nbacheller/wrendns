// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: API-904, API-902, CLU-004 (T27.14g; ADR-956 §5 as amended 2026-11-26, ADR-977 point 5,
//! ADR-1098 point 3, ADR-1116) - the confirm the primary relays for a `listen` change on another node.
//!
//! The direct confirm stays the default: the admin's browser opens the node's own web UI and
//! confirms there. When it cannot (the node's API listens on loopback or a cluster-only network, or
//! the address is behind a shared Service), the primary may pass the confirm on, carrying the admin's
//! signed identity. It is deliberately narrow:
//!
//! - the setting is `listen` and no other (checked by the primary and again by the node);
//! - the target is a cluster member other than the primary, announcing the `guarded_confirm_relay`
//!   gate feature, and the change was applied by the same admin through this primary;
//! - the request carries the change's single-use confirm token as well as the admin's session, so a
//!   stolen session cookie alone cannot confirm;
//! - the primary audits before it sends (no audit row, no relay) and after;
//! - the node checks everything itself (the sender, the row, the binding to its pending change, the
//!   token, the assertion's lifetime, a single-use nonce, sign-in recency for a weakening change, and
//!   a cap of five refused relays per change), and then still needs its own DNS probes to answer;
//! - the window is not lengthened and an unconfirmed change rolls back as ever.
//!
//! A relay never proves that the admin can reach the node afterwards: the node's own probes are the
//! proof, as for a direct confirm.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::time::Instant;
use wrendns_api::auth::{Actor, RECENT_SIGN_IN_SECS};
use wrendns_api::guarded::{GuardedApplied, GuardedCaller, GuardedPreview, GuardedResult};
use wrendns_api::problem::{Code, Problem};
use wrendns_config::guarded::LISTEN;

use super::{Engine, Forwarded, ForwardedAnswer, ForwardedOp, Member, Pending, lock, problem_of};
use crate::guarded::assertion::{
    RELAY_PURPOSE, RELAY_SECS, RelayAssertion, RelayToken, SignedRelay,
};
use crate::guarded::{ct_eq, hex, now_secs, random_id};

/// Refused relays one pending change takes before the node stops looking at them (design note 2.7).
pub(crate) const RELAY_REFUSALS_ALLOWED: u32 = 5;
/// The most window changes the primary keeps track of for relaying.
const CARRIED_MAX: usize = 64;
/// The most forwarded previews whose weakening verdict the primary keeps.
const WEAK_MAX: usize = 256;
/// How long the primary keeps a forwarded preview's verdict (a preview lives 5 minutes).
const WEAK_KEEP: Duration = Duration::from_secs(600);

/// What a probe refusal's text starts with: the one refusal a relay does not count.
pub(super) const PROBE_REFUSAL: &str = "the node's own query to ";

/// How a confirm reached the node (`confirmedVia: "primary"` in the audit record).
pub(super) struct Via {
    pub(super) issuer: String,
    pub(super) nonce: String,
}

/// A window change the primary forwarded for another node, kept for its window.
#[derive(Clone)]
pub(super) struct Carried {
    node: String,
    setting: String,
    preview_id: String,
    admin: String,
    value_digest: String,
    token_hash: [u8; 32],
    weakening: bool,
    deadline: Instant,
}

/// The digest of a previewed value, as the primary and the node each compute it from the value the
/// admin sent: both sides see the same JSON, so the same bytes.
pub(crate) fn value_digest(value: &serde_json::Value) -> String {
    hex(blake3::hash(&serde_json::to_vec(value).unwrap_or_default()).as_bytes())
}

impl Engine {
    /// The primary notes whether a preview it forwarded was weakening, so the relay can ask for a
    /// recent sign-in for it (the node asks again, from its own pending change).
    pub(super) fn note_preview(&self, p: &GuardedPreview) {
        let now = Instant::now();
        let mut g = lock(&self.inner);
        g.relay_weak
            .retain(|_, (_, at)| now.duration_since(*at) < WEAK_KEEP);
        if g.relay_weak.len() >= WEAK_MAX {
            g.relay_weak.clear();
        }
        g.relay_weak
            .insert(p.preview_id.clone(), (p.weakening, now));
    }

    /// The primary keeps what it carried to another node, for the window: the pending ID, the preview,
    /// the node, the setting, the admin, the value's digest and the hash of the token (never the token).
    pub(super) fn carry(
        &self,
        c: &GuardedCaller,
        m: &Member,
        preview_id: &str,
        digest: String,
        done: &GuardedApplied,
    ) {
        if done.status != "pending" {
            return;
        }
        let (Some(pid), Some(token), Some(secs)) = (
            done.pending_id.clone(),
            done.confirm_token.as_deref(),
            done.deadline_secs,
        ) else {
            return;
        };
        let now = Instant::now();
        let mut g = lock(&self.inner);
        // A preview this primary never saw (it restarted since) is treated as weakening: the
        // conservative reading asks for the recent sign-in.
        let weakening = g.relay_weak.remove(preview_id).is_none_or(|(w, _)| w);
        g.carried.retain(|_, k| k.deadline > now);
        if g.carried.len() >= CARRIED_MAX
            && let Some(oldest) = g
                .carried
                .iter()
                .min_by_key(|(_, k)| k.deadline)
                .map(|(id, _)| id.clone())
        {
            g.carried.remove(&oldest);
        }
        g.carried.insert(
            pid,
            Carried {
                node: m.name.clone(),
                setting: done.setting.clone(),
                preview_id: preview_id.to_owned(),
                admin: c.username.clone(),
                value_digest: digest,
                token_hash: *blake3::hash(token.as_bytes()).as_bytes(),
                weakening,
                deadline: now + Duration::from_secs(secs),
            },
        );
    }

    /// REQ: API-904 - `POST /api/v1/guarded/pending/{id}/confirm-relay` (the route has checked that
    /// the caller is an admin's interactive session): the primary passes the admin's confirm of a
    /// `listen` change on another node on to that node.
    #[allow(clippy::too_many_lines)] // one ordered list of checks, then the send
    pub(crate) async fn relay_confirm(
        self: &Arc<Self>,
        c: &GuardedCaller,
        pending_id: &str,
        token: &str,
    ) -> Result<GuardedResult, Problem> {
        // Only the primary relays: a replica says who to ask (421).
        self.must_forward()?;
        let key = Self::failure_key(c, pending_id);
        self.blocked(&key)?;
        self.rate_limit(c)?;
        if !self.host.clustered() {
            return Err(self.refuse(
                c,
                LISTEN,
                Problem::new(
                    Code::RelayRefused,
                    "this node is not in a cluster: it confirms its own changes",
                ),
            ));
        }
        let now = Instant::now();
        let (carried, here) = {
            let mut g = lock(&self.inner);
            g.carried.retain(|_, held| held.deadline > now);
            (
                g.carried.get(pending_id).cloned(),
                g.pending.as_ref().is_some_and(|p| p.id == pending_id),
            )
        };
        let Some(held) = carried else {
            if here {
                return Err(self.refuse(
                    c,
                    LISTEN,
                    Problem::new(
                        Code::RelayRefused,
                        "that change is pending on this node itself: confirm it here, directly",
                    ),
                ));
            }
            return Err(Problem::not_found(
                "no change this node forwarded is pending under that ID (it may have rolled back)",
            ));
        };
        let refuse = |counted: bool, why: &str| {
            if counted {
                self.failed(&key);
            }
            self.refuse(c, &held.setting, Problem::new(Code::RelayRefused, why))
        };
        // The row: only `listen` is relayed, whatever the pending change is.
        if held.setting != LISTEN {
            return Err(refuse(
                false,
                "only a change to the DNS listeners can be confirmed through the primary",
            ));
        }
        if c.username.is_empty() || c.username != held.admin {
            return Err(refuse(
                true,
                "this change was made by another admin: only they can confirm it",
            ));
        }
        if !ct_eq(blake3::hash(token.as_bytes()).as_bytes(), &held.token_hash) {
            return Err(refuse(true, "the confirmation token is wrong"));
        }
        let left = super::remaining(held.deadline);
        if left == 0 {
            return Err(refuse(false, "the window for this change has ended"));
        }
        // Recency, asked again: the relay can come minutes after the apply.
        let unix_now = now_secs();
        if held.weakening
            && c.signed_in_at
                .is_none_or(|s| unix_now.saturating_sub(s) > RECENT_SIGN_IN_SECS)
        {
            return Err(self.refuse(
                c,
                &held.setting,
                Problem::new(
                    Code::ReauthRequired,
                    "this change weakens security: sign in again (within the last 10 minutes) to confirm it through the primary",
                ),
            ));
        }
        let Some(member) = self
            .host
            .members()
            .into_iter()
            .find(|member| member.name == held.node || member.id == held.node)
        else {
            return Err(Problem::new(
                Code::NodeUnknown,
                format!("no cluster node `{}`", held.node),
            ));
        };
        if member.is_primary || member.name == self.node || member.id == self.node {
            return Err(refuse(
                false,
                "the primary confirms its own changes itself: open it directly",
            ));
        }
        if !member.relay {
            return Err(self.refuse(
                c,
                &held.setting,
                Problem::new(
                    Code::UpgradeRequired,
                    format!(
                        "node {} runs a build that does not know {}; upgrade it first",
                        member.name,
                        wrendns_cluster::gate::Feature::GuardedConfirmRelay.what()
                    ),
                ),
            ));
        }
        let nonce = random_id(16);
        let assertion = RelayAssertion {
            purpose: RELAY_PURPOSE.to_owned(),
            setting: held.setting.clone(),
            node: member.name.clone(),
            pending_id: pending_id.to_owned(),
            preview_id: held.preview_id.clone(),
            value_digest: held.value_digest.clone(),
            admin: held.admin.clone(),
            role: "admin".to_owned(),
            session_digest: hex(
                &blake3::hash(c.session.as_deref().unwrap_or_default().as_bytes()).as_bytes()[..16],
            ),
            signed_in_at: c.signed_in_at,
            remote: c.remote.map(|r| r.to_string()),
            issuer: self.node.clone(),
            issued_at: (self.now)(),
            // Never past the window as this node last saw it.
            expires_at: (self.now)() + RELAY_SECS.min(left),
            nonce: nonce.clone(),
        };
        let signed: SignedRelay = self.host.relay_assertion(&assertion).ok_or_else(|| {
            Problem::new(
                Code::NotPrimary,
                "only the primary can sign a relayed confirm",
            )
        })?;
        // Audit first: no record, no relay. The token is in no record.
        let actor = Self::actor_of(c);
        let target = self.target_name(&held.setting);
        let detail = |outcome: &str, why: Option<&str>| {
            json!({
                "setting": held.setting, "node": member.name, "pendingId": pending_id,
                "previewId": held.preview_id, "valueDigest": held.value_digest,
                "nonce": nonce, "outcome": outcome, "detail": why,
                "confirmedFrom": c.remote.map(|r| r.to_string()),
            })
        };
        self.audit(
            &actor,
            "settings.guarded_confirm_relayed",
            &target,
            &detail("sent", None),
        )
        .map_err(|e| {
            Problem::unavailable(format!(
                "the audit log can'unix_now record the relay, so nothing was sent: {e}"
            ))
        })?;
        let fwd = Forwarded {
            op: ForwardedOp::ConfirmRelay {
                pending: pending_id.to_owned(),
                token: RelayToken(token.to_owned()),
                relay: signed,
            },
            assertion: None,
        };
        match self.host.forward(&member.name, fwd).await {
            Ok(ForwardedAnswer::Result(r)) => {
                self.audit_best_effort(
                    &actor,
                    "settings.guarded_confirm_relayed",
                    &target,
                    &detail("confirmed", None),
                );
                lock(&self.inner).carried.remove(pending_id);
                Ok(r)
            }
            Ok(ForwardedAnswer::RelayRefused {
                detail: why,
                hint,
                counted,
            }) => {
                self.audit_best_effort(
                    &actor,
                    "settings.guarded_confirm_relayed",
                    &target,
                    &detail("refused", Some(&why)),
                );
                if counted {
                    self.failed(&key);
                }
                Err(problem_of(Code::RelayRefused, why, hint, None))
            }
            Ok(ForwardedAnswer::Refused {
                code,
                detail: why,
                hint,
                retry_after,
            }) => {
                self.audit_best_effort(
                    &actor,
                    "settings.guarded_confirm_relayed",
                    &target,
                    &detail("refused", Some(&format!("{code:?}"))),
                );
                Err(problem_of(code, why, hint, retry_after))
            }
            Ok(_) => Err(Problem::internal("unexpected answer from the node")),
            Err(e) => {
                self.audit_best_effort(
                    &actor,
                    "settings.guarded_confirm_relayed",
                    &target,
                    &detail("failed", Some("the node did not answer")),
                );
                Err(e)
            }
        }
    }

    /// The node's side of a relayed confirm: every check is made here, on this node, and the
    /// primary's do not stand in for them. A failure is `relay_refused` with the reason, audited as
    /// `settings.guarded_refused`; the window runs on.
    pub(super) async fn handle_relay(
        self: &Arc<Self>,
        sender: &str,
        pending_id: &str,
        token: RelayToken,
        signed: SignedRelay,
    ) -> ForwardedAnswer {
        let hint = || {
            Some(
                "The change is still pending; it rolls back when the window ends. You can still confirm it directly at the node's own address."
                    .to_owned(),
            )
        };
        let refused = |detail: &str, counted: bool| ForwardedAnswer::RelayRefused {
            detail: detail.to_owned(),
            hint: hint(),
            counted,
        };
        let now = now_secs();
        // 1. The sender, the signature and the lifetime. Nothing about the pending change is trusted
        //    before this, and a refusal here is not counted against any change.
        let a = match signed.check(&*self.host, sender, now, &self.node) {
            Ok(a) => a.clone(),
            Err(r) => {
                self.audit_best_effort(
                    &Actor::system("cluster"),
                    "settings.guarded_refused",
                    &self.target_name(LISTEN),
                    &json!({"setting": LISTEN, "node": self.node, "code": "relay_refused", "relay": r.why()}),
                );
                return refused(r.why(), false);
            }
        };
        let who = Actor {
            name: format!("{} via {}", a.admin, a.issuer),
            kind: "session",
            remote: a.remote.clone(),
            reason: None,
        };
        // 2 to 8, under the lock, against the pending change.
        let verdict: Result<(), (&'static str, bool)> = {
            let mut g = lock(&self.inner);
            match g.pending.as_mut().filter(|p| p.id == pending_id) {
                None => Err((
                    "no change is pending under that ID on this node (it may have rolled back)",
                    false,
                )),
                Some(p) if p.relay_refusals >= RELAY_REFUSALS_ALLOWED => Err((
                    "too many relayed confirms were refused for this change; confirm it directly",
                    false,
                )),
                Some(p) => match relay_checks(p, &a, &token, now) {
                    Ok(()) => {
                        p.relay_nonces.insert(a.nonce.clone());
                        Ok(())
                    }
                    Err(why) => {
                        p.relay_refusals += 1;
                        Err((why, true))
                    }
                },
            }
        };
        if let Err((why, counted)) = verdict {
            self.audit_best_effort(
                &who,
                "settings.guarded_refused",
                &self.target_name(LISTEN),
                &json!({"setting": LISTEN, "node": self.node, "code": "relay_refused", "relay": why}),
            );
            return refused(why, counted);
        }
        // 9. The proof, exactly as for a direct confirm: every DNS probe answers now, and the host
        //    facts still match. The relay changes who delivers the admin's intent, not what proves it.
        let caller = GuardedCaller {
            actor: who,
            username: a.admin.clone(),
            session: Some(format!("relay:{}", a.session_digest)),
            signed_in_at: a.signed_in_at,
            arrived_on: None,
            remote: a.remote.as_deref().and_then(|r| r.parse().ok()),
            remote_under_pending: None,
            peer: None,
            tls: false,
        };
        let via = Via {
            issuer: a.issuer.clone(),
            nonce: a.nonce.clone(),
        };
        match self
            .confirm_via(&caller, pending_id, Some(token.0), Some(&via))
            .await
        {
            Ok(r) => ForwardedAnswer::Result(r),
            // A probe that has not answered yet is the admin's wait, not a fault: not counted.
            Err(e) if e.code == Code::Forbidden && e.detail.starts_with(PROBE_REFUSAL) => {
                ForwardedAnswer::RelayRefused {
                    detail: e.detail,
                    hint: e.hint,
                    counted: false,
                }
            }
            Err(e) => ForwardedAnswer::Refused {
                code: e.code,
                detail: e.detail,
                hint: e.hint,
                retry_after: e.retry_after,
            },
        }
    }
}

/// The checks 2 to 8 of the design note's list, against the pending change; `Err` is the reason.
fn relay_checks(
    p: &Pending,
    a: &RelayAssertion,
    token: &RelayToken,
    now: u64,
) -> Result<(), &'static str> {
    // 2. The row: the assertion and the pending change are both `listen`, whatever else they say.
    if a.setting != LISTEN || p.setting != LISTEN {
        return Err("only a change to the DNS listeners can be confirmed through the primary");
    }
    // 3. The binding: this pending change, its preview, its value and its admin.
    if a.pending_id != p.id
        || a.preview_id != p.preview_id
        || a.value_digest != p.value_digest
        || a.admin != p.admin
    {
        return Err("the relayed confirm is not for this change");
    }
    // 4. The token, in constant time; a successful confirm uses it up with the pending change.
    if !ct_eq(blake3::hash(token.0.as_bytes()).as_bytes(), &p.token_hash) {
        return Err("the confirmation token is wrong");
    }
    // 5. The window is still open on this node's monotonic clock (the lifetime was checked with the
    //    signature).
    if Instant::now() >= p.deadline {
        return Err("the window for this change has ended");
    }
    // 6. The nonce is new.
    if p.relay_nonces.contains(&a.nonce) {
        return Err("the relayed confirm was already used");
    }
    // 7. A weakening change needs a recent sign-in.
    if p.weakening
        && a.signed_in_at
            .is_none_or(|s| now.saturating_sub(s) > RECENT_SIGN_IN_SECS)
    {
        return Err("this change weakens security and the sign-in is older than 10 minutes");
    }
    Ok(())
}

//! REQ: API-902, CLU-004, CLU-010 (T27.13; ADR-956 §5, §4a) — what the primary signs to forward a
//! guarded request for another node.
//!
//! Every guarded setting is node-local. Only the **primary** forwards a request for node X (a
//! replica answers 421 with the primary's address), over the existing cluster channel, with an
//! assertion of the admin's identity, role and sign-in time, signed by the primary's cluster key,
//! short-lived and **single use** (it carries a nonce bound to the preview, the node, the setting
//! and the action; X keeps the used nonces for the assertion's lifetime and refuses a replay). X
//! checks it itself: its own checks do not stand in for the forwarding node's, and the forwarding
//! node's do not stand in for X's. X accepts the assertion only from the primary (the member that
//! already signs everything X trusts, ADR-005): a replica's signature is refused, so a compromised
//! replica can't turn on `allow-secrets-over-http` or widen `secret-file-dirs` on another node.

use serde::{Deserialize, Serialize};
use wrendns_api::guarded::{
    GuardedApplied, GuardedApplyRequest, GuardedPreview, GuardedPreviewRequest, GuardedResult,
};

use super::host::Host;

/// How long an assertion is good for, in seconds (ADR-956 §5: short-lived).
pub(crate) const ASSERTION_SECS: u64 = 60;

/// Who is asking, as the primary vouches for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Assertion {
    /// The admin's user name.
    pub(crate) admin: String,
    /// The audit actor name (`alice via pi-a` is made on the target from this).
    pub(crate) actor: String,
    /// Always `admin`: a forwarded request exists only for admin sessions.
    pub(crate) role: String,
    /// When the admin's session was created, if it is an interactive session.
    pub(crate) signed_in_at: Option<u64>,
    /// The admin's address as the primary saw it.
    pub(crate) remote: Option<String>,
    /// The node that signed: it must be the primary.
    pub(crate) issuer: String,
    /// The node the request is for.
    pub(crate) node: String,
    /// `preview`, `apply`, `cancel`, `restart-preview` or `restart-apply`.
    pub(crate) action: String,
    /// The setting (or the pending change's ID for a cancel).
    pub(crate) setting: String,
    /// The preview an apply is for (empty for the rest).
    pub(crate) preview_id: String,
    /// Single use.
    pub(crate) nonce: String,
    /// Unix seconds.
    pub(crate) expires: u64,
}

impl Assertion {
    /// The bytes that are signed (the fields in their fixed order).
    pub(crate) fn canonical(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// An assertion and the primary's signature over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Signed {
    pub(crate) assertion: Assertion,
    pub(crate) sig: Vec<u8>,
}

/// Why an assertion is refused (never the content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    Expired,
    WrongNode,
    WrongRequest,
    NotFromPrimary,
    BadSignature,
    NotAnAdmin,
    Replayed,
}

impl Refusal {
    pub(crate) const fn why(self) -> &'static str {
        match self {
            Self::Expired => "the forwarded request's assertion has expired",
            Self::WrongNode => "the forwarded request is for another node",
            Self::WrongRequest => "the assertion is for a different request",
            Self::NotFromPrimary => "only the primary forwards a guarded request",
            Self::BadSignature => "the forwarded request's signature is not the primary's",
            Self::NotAnAdmin => "a forwarded guarded request needs an admin",
            Self::Replayed => "the assertion was already used",
        }
    }
}

/// What a target expects of an assertion it was sent.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Expect<'a> {
    /// The connection the request came over (the peer's mTLS-authenticated name).
    pub(crate) sender: &'a str,
    pub(crate) now: u64,
    /// This node.
    pub(crate) me: &'a str,
    pub(crate) action: &'a str,
    pub(crate) setting: &'a str,
    pub(crate) preview_id: &'a str,
}

impl Signed {
    /// Checks everything about the assertion except the nonce (the engine keeps those): that it is
    /// for this node, this action, this setting and preview, not expired, an admin's, from the
    /// primary, and signed by the primary's key.
    pub(crate) fn check(&self, host: &dyn Host, want: &Expect<'_>) -> Result<&Assertion, Refusal> {
        let Expect {
            sender,
            now,
            me,
            action,
            setting,
            preview_id,
        } = *want;
        let a = &self.assertion;
        if a.node != me {
            return Err(Refusal::WrongNode);
        }
        if a.action != action || a.setting != setting || a.preview_id != preview_id {
            return Err(Refusal::WrongRequest);
        }
        if a.role != "admin" || a.admin.is_empty() {
            return Err(Refusal::NotAnAdmin);
        }
        if now > a.expires {
            return Err(Refusal::Expired);
        }
        // Only the primary forwards: the issuer must be the primary this node knows, and the
        // signature must verify under that node's key (so naming the primary doesn't help a
        // replica that signs with its own).
        // The connection the request arrived over (mTLS-authenticated) must be the primary's too:
        // a replica that holds the CA key can sign, but it can't send as the primary.
        if host.primary_name().as_deref() != Some(a.issuer.as_str()) || sender != a.issuer {
            return Err(Refusal::NotFromPrimary);
        }
        if !host.verify(&a.issuer, &a.canonical(), &self.sig) {
            return Err(Refusal::BadSignature);
        }
        Ok(a)
    }
}

/// What the primary sends to the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum ForwardedOp {
    Preview {
        id: String,
        req: GuardedPreviewRequest,
    },
    Apply {
        id: String,
        req: GuardedApplyRequest,
    },
    Cancel {
        pending: String,
    },
    /// A read of the target's own status (its supervisor, what is pending): it carries no value, so
    /// any member may ask and no assertion is needed.
    Status,
    /// REQ: API-902 (T27.14g0, ADR-1113) - a read of the target's own web UI and API settings and DNS
    /// listeners, for an admin. It carries no value, but its answer is admin-only, so it carries the
    /// primary's signed assertion (action `node_api`, setting `api`) like the other operations.
    NodeApi,
    /// REQ: API-904 (T27.14g, ADR-1116) - the admin's confirm of a `listen` change on this node,
    /// passed on by the primary: the change's pending ID, its single-use confirm token and the
    /// primary's signed [`RelayAssertion`]. It carries no [`Assertion`] (`assertion` is `None`):
    /// the relay's own assertion, of its own purpose, is the one that is checked.
    ConfirmRelay {
        pending: String,
        token: RelayToken,
        relay: SignedRelay,
    },
}

/// The confirm token on its way to the node. It never prints: the type's `Debug` hides it, so no log
/// line or audit detail that formats a request can leak it (ADR-956 §3: a token is never logged).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct RelayToken(pub(crate) String);

impl std::fmt::Debug for RelayToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelayToken(<hidden>)")
    }
}

/// A forwarded request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Forwarded {
    pub(crate) op: ForwardedOp,
    /// Absent only from a node that can't sign (a replica): the target then refuses it.
    pub(crate) assertion: Option<Signed>,
}

/// The target's answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case")]
pub(crate) enum ForwardedAnswer {
    Preview(GuardedPreview),
    Applied(GuardedApplied),
    Result(GuardedResult),
    Status(wrendns_api::guarded::GuardedNodeStatus),
    /// The answer to [`ForwardedOp::NodeApi`].
    NodeApi(wrendns_api::guarded::GuardedNodeApi),
    /// REQ: API-904 (T27.14g) - the node refused a relayed confirm. `counted` is false when the only
    /// reason is that one of its own DNS probes has not answered yet: the admin did nothing wrong, so
    /// the primary does not count it toward the session's failure block.
    RelayRefused {
        detail: String,
        hint: Option<String>,
        counted: bool,
    },
    /// The target refused: a problem's code and text, to be returned as is.
    Refused {
        code: wrendns_api::problem::Code,
        detail: String,
        hint: Option<String>,
        retry_after: Option<u64>,
    },
}

// ---- the relayed confirm (API-904, T27.14g; ADR-956 §5 as amended, ADR-1098 point 3, ADR-1116) ----

/// The longest a relayed-confirm assertion is good for, in seconds (design note 2.7).
pub(crate) const RELAY_SECS: u64 = 30;
/// The clock allowance the target gives an assertion, in seconds, on its own clock.
pub(crate) const RELAY_SKEW_SECS: u64 = 5;
/// The `purpose` of a relayed confirm; a forwarding [`Assertion`] has an `action` instead, so neither
/// can be used as the other.
pub(crate) const RELAY_PURPOSE: &str = "confirm";
/// Prefixed to the bytes the primary signs, so a signature over a forwarding assertion (or anything
/// else the cluster key signs) can never verify as a relayed confirm.
const RELAY_DOMAIN: &[u8] = b"wrendns/guarded/relayed-confirm/v1\0";

/// What the primary vouches for when it passes an admin's confirm on to the node holding the change.
/// It names the change as closely as the node can check (the pending ID, the preview, the digest of the
/// value), the admin and the session (by digest, never the session itself), and lives seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RelayAssertion {
    /// Always `confirm`.
    pub(crate) purpose: String,
    /// Always `listen`: the one row a confirm is relayed for.
    pub(crate) setting: String,
    /// The node holding the change.
    pub(crate) node: String,
    pub(crate) pending_id: String,
    pub(crate) preview_id: String,
    /// The digest of the previewed value (`engine::value_digest`).
    pub(crate) value_digest: String,
    pub(crate) admin: String,
    /// Always `admin`.
    pub(crate) role: String,
    /// The digest of the admin's session ID (never the session).
    pub(crate) session_digest: String,
    /// When the admin's session was created (Unix seconds).
    pub(crate) signed_in_at: Option<u64>,
    /// The browser's address as the primary saw it (reported by the primary, for the audit).
    pub(crate) remote: Option<String>,
    /// The node that signed: it must be the primary.
    pub(crate) issuer: String,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    /// 128 random bits, single use.
    pub(crate) nonce: String,
}

impl RelayAssertion {
    /// The bytes that are signed: a fixed prefix and the fields in their fixed order.
    pub(crate) fn canonical(&self) -> Vec<u8> {
        let mut v = RELAY_DOMAIN.to_vec();
        v.extend(serde_json::to_vec(self).unwrap_or_default());
        v
    }
}

/// A relayed-confirm assertion and the primary's signature over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignedRelay {
    pub(crate) assertion: RelayAssertion,
    pub(crate) sig: Vec<u8>,
}

/// Why a relayed confirm's assertion is refused (never the content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayRefusal {
    WrongPurpose,
    WrongNode,
    NotAnAdmin,
    NotFromPrimary,
    BadSignature,
    Lifetime,
    Expired,
    FromTheFuture,
}

impl RelayRefusal {
    pub(crate) const fn why(self) -> &'static str {
        match self {
            Self::WrongPurpose => "the assertion is not a relayed confirm",
            Self::WrongNode => "the relayed confirm is for another node",
            Self::NotAnAdmin => "a relayed confirm needs an admin",
            Self::NotFromPrimary => "only the primary relays a confirm",
            Self::BadSignature => "the relayed confirm's signature is not the primary's",
            Self::Lifetime => "the relayed confirm's assertion lives longer than 30 seconds",
            Self::Expired => "the relayed confirm's assertion has expired",
            Self::FromTheFuture => "the relayed confirm's assertion is dated in the future",
        }
    }
}

impl SignedRelay {
    /// The checks that need no pending change: the purpose, that it is for this node and an admin's,
    /// that it comes from the primary (the issuer, the connection it arrived over and the signature),
    /// and its lifetime on this node's clock (at most [`RELAY_SECS`] long, not past with a
    /// [`RELAY_SKEW_SECS`] allowance, not dated later than that allowance).
    pub(crate) fn check(
        &self,
        host: &dyn Host,
        sender: &str,
        now: u64,
        me: &str,
    ) -> Result<&RelayAssertion, RelayRefusal> {
        let a = &self.assertion;
        if a.purpose != RELAY_PURPOSE {
            return Err(RelayRefusal::WrongPurpose);
        }
        if a.node != me {
            return Err(RelayRefusal::WrongNode);
        }
        if a.role != "admin" || a.admin.is_empty() {
            return Err(RelayRefusal::NotAnAdmin);
        }
        if host.primary_name().as_deref() != Some(a.issuer.as_str()) || sender != a.issuer {
            return Err(RelayRefusal::NotFromPrimary);
        }
        if !host.verify(&a.issuer, &a.canonical(), &self.sig) {
            return Err(RelayRefusal::BadSignature);
        }
        if a.expires_at < a.issued_at || a.expires_at - a.issued_at > RELAY_SECS {
            return Err(RelayRefusal::Lifetime);
        }
        if now > a.expires_at.saturating_add(RELAY_SKEW_SECS) {
            return Err(RelayRefusal::Expired);
        }
        if a.issued_at > now.saturating_add(RELAY_SKEW_SECS) {
            return Err(RelayRefusal::FromTheFuture);
        }
        Ok(a)
    }
}

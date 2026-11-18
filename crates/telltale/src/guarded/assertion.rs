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
use telltale_api::guarded::{
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
    Status(telltale_api::guarded::GuardedNodeStatus),
    /// The target refused: a problem's code and text, to be returned as is.
    Refused {
        code: telltale_api::problem::Code,
        detail: String,
        hint: Option<String>,
        retry_after: Option<u64>,
    },
}

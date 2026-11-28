// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-919 (T36.10b step b3; ADR-1112 point 1) - the ownership ledger: which record sets the
//! node made itself, or an admin adopted. The node changes or deletes only those.
//!
//! The ledger is a node-managed kind (`dns_ledger`) in `state.db`: it survives a restart, and the
//! primary's rows ride the signed manifest's node-managed blob (names and times only, never a value
//! or a credential), so a replica promoted to primary seeds its own from the blob it inherited and
//! does not lose track of what is owned. An older build skips the kind. Only the primary writes
//! (the engine runs there; a replica forwards an Adopt to it).

use serde::{Deserialize, Serialize};
use wrendns_store::state::State;

use super::RecordType;

/// The managed kind of a ledger row.
pub(crate) const KIND: &str = "dns_ledger";

/// How the node came to own a record set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Owner {
    /// The node wrote it.
    Created,
    /// An admin took it over from whoever made it.
    Adopted,
}

impl Owner {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Adopted => "adopted",
        }
    }
}

/// One owned record set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Owned {
    pub(crate) provider: String,
    /// The record set's full name.
    pub(crate) name: String,
    pub(crate) rtype: RecordType,
    pub(crate) owner: Owner,
    /// Who made or adopted it (a user, or `system` with the cause).
    pub(crate) by: String,
    /// Unix seconds.
    pub(crate) at: u64,
    /// The provider's identifier of the write, when it gave one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) change_id: Option<String>,
}

/// The row's name: the provider, the type and the name, so rows sort by provider.
fn key(provider: &str, rtype: RecordType, name: &str) -> String {
    format!("{provider}/{}/{name}", rtype.as_str())
}

/// The ledger over a node's `state.db`. Every call is blocking (SQLite): the engine runs them on a
/// blocking thread.
#[derive(Debug)]
pub(crate) struct Ledger<'a>(pub(crate) &'a State);

impl Ledger<'_> {
    /// The row for this record set, if the node owns it.
    pub(crate) fn get(&self, provider: &str, rtype: RecordType, name: &str) -> Option<Owned> {
        let k = key(provider, rtype, name);
        self.0
            .managed(KIND)
            .ok()?
            .into_iter()
            .find(|m| m.name == k)
            .and_then(|m| serde_json::from_str(&m.body).ok())
    }

    /// Every record set the node owns at `provider`.
    pub(crate) fn list(&self, provider: &str) -> Vec<Owned> {
        let prefix = format!("{provider}/");
        self.0
            .managed(KIND)
            .unwrap_or_default()
            .into_iter()
            .filter(|m| m.name.starts_with(&prefix))
            .filter_map(|m| serde_json::from_str::<Owned>(&m.body).ok())
            .filter(|o| o.provider == provider)
            .collect()
    }

    /// Records ownership (replacing an older row of the same record set).
    pub(crate) fn put(&self, o: &Owned) -> Result<(), String> {
        let body = serde_json::to_string(o).map_err(|e| e.to_string())?;
        self.0
            .put_managed(
                KIND,
                &key(&o.provider, o.rtype, &o.name),
                &body,
                None,
                None,
                o.at,
                &o.by,
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    #[allow(
        dead_code,
        reason = "unused until the provider kinds (T36.10b b4) and their callers (T36.10d, T36.10e) land; the tests use it"
    )]
    /// Forgets the record set (it was deleted at the provider). Not an error when it was not there.
    pub(crate) fn remove(
        &self,
        provider: &str,
        rtype: RecordType,
        name: &str,
    ) -> Result<(), String> {
        match self
            .0
            .delete_managed(KIND, &key(provider, rtype, name), None)
        {
            Ok(_) | Err(wrendns_store::state::ManagedError::NotFound { .. }) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

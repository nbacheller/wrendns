//! REQ: API-902, CLU-004 (T27.13; ADR-956) — what the guarded engine needs from the node around it,
//! as a trait: the running configuration, the reload the API uses, the write of an entry through the
//! primary, the cluster channel for a forwarded request, the restart, and a listener for the
//! confirmation window's proof. The node implements it (`prod.rs`); the tests implement it with
//! fakes, so the state machine is tested without sockets, clocks or a cluster.

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::Value;
use telltale_api::BoxFuture;
use telltale_api::auth::Actor;
use telltale_api::problem::Problem;
use telltale_config::Config;

use super::assertion::{Forwarded, ForwardedAnswer, Signed};
use super::store::Stored;

/// A node of the cluster, as the primary sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Member {
    /// The node's ID.
    pub(crate) id: String,
    /// The name the phrase and the audit log use.
    pub(crate) name: String,
    pub(crate) is_primary: bool,
    pub(crate) up: bool,
}

/// A socket kept open for the confirmation window's proof. Dropping it closes it.
pub(crate) trait ProofSocket: Send + Sync {
    fn addr(&self) -> SocketAddr;
    /// Stops accepting; the sockets of the node itself are unaffected.
    fn close(&self);
}

/// The node around the engine.
pub(crate) trait Host: Send + Sync + 'static {
    /// The configuration the node runs (files plus what the UI stored).
    fn running_config(&self) -> Arc<Config>;
    /// The configuration files alone (what "set by file" is judged against).
    fn file_config(&self) -> Arc<Config>;
    /// Re-reads the files and `state.db` and applies them, as the API does after a change (ADR-040);
    /// answers whether it worked. A failed reload keeps the previous configuration (CLU-004).
    fn reload(&self) -> BoxFuture<bool>;
    /// Writes (`Some`) or removes (`None`) the guarded entry for `node`/`id`. On the primary and a
    /// standalone node that is `state.db`; on a replica it goes through the primary (the single
    /// writer, ADR-005), and answers `primary_unreachable` when it can't be reached.
    fn write_entry(
        &self,
        node: &str,
        id: &str,
        entry: Option<Stored>,
        by: &str,
    ) -> BoxFuture<Result<(), Problem>>;
    /// Whether this node is the primary (a standalone node is its own).
    fn is_primary(&self) -> bool;
    /// Whether the node is a cluster member.
    fn clustered(&self) -> bool;
    /// The cluster's members (empty when standalone).
    fn members(&self) -> Vec<Member>;
    /// The primary's name, when known.
    fn primary_name(&self) -> Option<String>;
    /// The primary's API address, for a 421 on a replica.
    fn primary_url(&self) -> Option<String>;
    /// Signs `bytes` with the cluster key (the primary only; a replica's signature is refused).
    fn sign(&self, bytes: &[u8]) -> Option<Vec<u8>>;
    /// Whether `sig` over `bytes` is `node`'s signature.
    fn verify(&self, node: &str, bytes: &[u8], sig: &[u8]) -> bool;
    /// Sends a forwarded request to `node` over the cluster channel and returns its answer.
    fn forward(&self, node: &str, req: Forwarded) -> BoxFuture<Result<ForwardedAnswer, Problem>>;
    /// Writes an audit record (`state.db`); an error means the log can't record it.
    fn audit(
        &self,
        actor: &Actor,
        action: &str,
        target: &str,
        detail: &Value,
    ) -> Result<(), String>;
    /// Starts a drain and exit with code 75 (ADR-956 §4a). Production sets the restart flag and
    /// wakes the main loop; the end-to-end build and the tests replace it.
    fn restart(&self) -> BoxFuture<()>;
    /// Binds a listener for the proof of a window change, serving the API tagged with the address it
    /// was reached on. A failed bind is an error naming why.
    fn proof_socket(&self, addr: SocketAddr) -> BoxFuture<Result<Arc<dyn ProofSocket>, String>>;
    /// The node's own probe of a DNS listener answers (what a `listen` confirmation also needs).
    fn probe_dns(&self, addr: SocketAddr) -> BoxFuture<bool> {
        let _ = addr;
        Box::pin(std::future::ready(true))
    }
    /// A signed assertion for a request the primary forwards: only the primary makes one.
    fn assertion(&self, a: &super::assertion::Assertion) -> Option<Signed> {
        let bytes = a.canonical();
        let sig = self.sign(&bytes)?;
        Some(Signed {
            assertion: a.clone(),
            sig,
        })
    }
}

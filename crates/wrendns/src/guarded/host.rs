//! REQ: API-902, CLU-004 (T27.13; ADR-956) — what the guarded engine needs from the node around it,
//! as a trait: the running configuration, the reload the API uses, the write of an entry through the
//! primary, the cluster channel for a forwarded request, the restart, and a listener for the
//! confirmation window's proof. The node implements it (`prod.rs`); the tests implement it with
//! fakes, so the state machine is tested without sockets, clocks or a cluster.

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::Value;
use wrendns_api::BoxFuture;
use wrendns_api::auth::Actor;
use wrendns_api::problem::Problem;
use wrendns_config::Config;

use super::assertion::{Forwarded, ForwardedAnswer, Signed};
use super::store::Stored;

/// A node of the cluster, as the primary sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent facts about one member
pub(crate) struct Member {
    /// The node's ID.
    pub(crate) id: String,
    /// The name the phrase and the audit log use.
    pub(crate) name: String,
    pub(crate) is_primary: bool,
    pub(crate) up: bool,
    /// The site label (display and "a site's only healthy resolver"); not an identity.
    pub(crate) site: String,
    /// A witness only votes: it serves no DNS.
    pub(crate) witness: bool,
    /// REQ: API-902 (T27.14g0) - the URL its web UI and API answer on, as it announced it (empty:
    /// none, an older build).
    pub(crate) api_url: String,
    /// REQ: API-902 (T27.14g0) - its build announces the per-node read of its web UI and API settings
    /// (the `MemberApiAddress` gate feature); an older member does not know it.
    pub(crate) node_api: bool,
    /// REQ: API-904 (T27.14g) - its build can take the confirm the primary relays (the
    /// `GuardedConfirmRelay` gate feature); an older member cannot decode the operation.
    pub(crate) relay: bool,
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
    /// REQ: OBS-007, API-905 (T40.13, review) - what the node will run after its next start (the files
    /// and its own entries, a staged one included): the baseline a dnstap change is judged against,
    /// as the ordinary write judges it. The running configuration by default.
    fn pending_config(&self) -> Arc<Config> {
        self.running_config()
    }
    /// Re-reads the files and `state.db` and applies them, as the API does after a change (ADR-040);
    /// answers whether it worked. A failed reload keeps the previous configuration (CLU-004).
    fn reload(&self) -> BoxFuture<bool>;
    /// REQ: DNS-901 — the encrypted listeners the configuration lists whose socket is closed or
    /// does not carry the configured settings, as the last apply recorded them (`proto://addr`).
    /// A change to `listen.require_client_id` is applied only when this is empty: a replica's
    /// replication path applies the entry before the engine's own reload does, so the reload's
    /// answer alone cannot tell. Empty by default (a host without listeners).
    fn listeners_not_applied(&self) -> Vec<String> {
        Vec::new()
    }
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
    /// REQ: OBS-007, API-905 (T40.13, review) - [`write_entry`](Self::write_entry) for an entry an
    /// ordinary write shares (the dnstap row): the write is refused with `preview_stale` when the
    /// entry the primary holds is not the one this node saw (`expect_at`: the time of its entry, or
    /// `None` for no entry), so a confirmed value never overwrites an ordinary change that was
    /// answered with success meanwhile. The default writes without the check.
    fn write_entry_expecting(
        &self,
        node: &str,
        id: &str,
        entry: Option<Stored>,
        by: &str,
        expect_at: Option<u64>,
    ) -> BoxFuture<Result<(), Problem>> {
        let _ = expect_at;
        self.write_entry(node, id, entry, by)
    }
    /// Whether this node is the primary (a standalone node is its own).
    fn is_primary(&self) -> bool;
    /// After [`write_entry`](Self::write_entry): waits until this node has the entry it just wrote
    /// (`Some(digest)` of its value, or `None` for a removal) in the configuration it follows, so a
    /// reload applies it. On the primary and a standalone node the write is the state, so it is
    /// already there; on a replica the entry travels through the primary and the replicated blob.
    /// `false` when it hasn't arrived in time.
    fn wait_applied(&self, node: &str, id: &str, digest: Option<String>) -> BoxFuture<bool> {
        let _ = (node, id, digest);
        Box::pin(std::future::ready(true))
    }
    /// Whether the node is a cluster member.
    fn clustered(&self) -> bool;
    /// The cluster's members (empty when standalone).
    fn members(&self) -> Vec<Member>;
    /// REQ: API-902 (T27.14g0) - the URL this node's web UI and API answer on, when it can name one.
    fn own_api_url(&self) -> Option<String> {
        None
    }
    /// This node's own site label (empty when it has none or isn't clustered).
    fn site(&self) -> String {
        String::new()
    }
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
    /// [`proof_socket`](Self::proof_socket) serving `tls` instead of the main listener's own
    /// (a `new_cert` window row's new certificate). `None` is the main listener's.
    fn proof_socket_with(
        &self,
        addr: SocketAddr,
        tls: Option<&wrendns_config::ApiTls>,
    ) -> BoxFuture<Result<Arc<dyn ProofSocket>, String>> {
        let _ = tls;
        self.proof_socket(addr)
    }
    /// REQ: API-902, OBS-020 (T27.14b) — the node's own probe of a DNS socket (ADR-107's client,
    /// one query), judged for a gated listener by the gate's refusal. A host without listeners
    /// answers as if the socket did.
    fn probe_dns(
        &self,
        probe: &super::dns_proof::DnsProbe,
    ) -> BoxFuture<Result<super::dns_proof::Kind, String>> {
        let _ = probe;
        Box::pin(std::future::ready(Ok(super::dns_proof::Kind::Answered)))
    }
    /// REQ: API-902, CLU-004 (T27.14a) — binds what `list` adds next to the running DNS listeners,
    /// and on proof ports what it changes (`docs/design/listener-editor.md` section 2.3). A failed
    /// bind closes everything staged and answers `bind_failed` with the address and the OS error.
    /// A host without listeners answers with an error.
    fn stage_listeners(
        &self,
        list: Vec<wrendns_config::Listener>,
    ) -> BoxFuture<Result<Vec<crate::server::StagedListener>, crate::server::WindowError>> {
        let _ = list;
        Box::pin(std::future::ready(Err(crate::server::WindowError {
            reason: "bind_failed",
            detail: "this node has no listeners to stage".to_owned(),
        })))
    }
    /// After the write and the reload: closes the proof ports; an error when a staged socket was
    /// not adopted (`commit_failed`) or the file took the listeners over (`cancelled`).
    fn commit_listeners(&self) -> BoxFuture<Result<(), crate::server::WindowError>> {
        Box::pin(std::future::ready(Ok(())))
    }
    /// Closes every staged and proof-port socket and nothing else.
    fn abort_listeners(&self) -> BoxFuture<()> {
        Box::pin(std::future::ready(()))
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
    /// REQ: API-904 (T27.14g) - a signed relayed-confirm assertion: only the primary makes one.
    fn relay_assertion(
        &self,
        a: &super::assertion::RelayAssertion,
    ) -> Option<super::assertion::SignedRelay> {
        let sig = self.sign(&a.canonical())?;
        Some(super::assertion::SignedRelay {
            assertion: a.clone(),
            sig,
        })
    }
}

/// What a test's node does on a reload, told the value of the entry now written.
#[cfg(test)]
pub(crate) type ReloadHook = Arc<dyn Fn(Option<Value>) -> BoxFuture<bool> + Send + Sync>;

/// A host with little behind it. By default it has nothing (the tests that only need a `CheckCx`);
/// the process tests give it the node's real listeners and a reload that applies what the engine
/// wrote.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct StubHost {
    /// The node's listeners, reached as the production host reaches them.
    pub(crate) listeners: Option<crate::server::ListenerHandle>,
    /// The configuration the node runs.
    pub(crate) cfg: std::sync::Mutex<Option<Arc<Config>>>,
    /// The node's reload, told the value of the entry now written (`None`: none or removed).
    pub(crate) on_reload: Option<ReloadHook>,
    /// The value of the entry the engine wrote last.
    pub(crate) entry: std::sync::Mutex<Option<Value>>,
}

#[cfg(test)]
impl Host for StubHost {
    fn running_config(&self) -> Arc<Config> {
        self.cfg
            .lock()
            .ok()
            .and_then(|c| c.clone())
            .unwrap_or_default()
    }
    fn file_config(&self) -> Arc<Config> {
        Arc::new(Config::default())
    }
    fn reload(&self) -> BoxFuture<bool> {
        match &self.on_reload {
            Some(f) => f(self.entry.lock().ok().and_then(|e| e.clone())),
            None => Box::pin(std::future::ready(true)),
        }
    }
    fn write_entry(
        &self,
        _node: &str,
        _id: &str,
        entry: Option<Stored>,
        _by: &str,
    ) -> BoxFuture<Result<(), Problem>> {
        if let Ok(mut e) = self.entry.lock() {
            *e = entry.map(|s| s.value);
        }
        Box::pin(std::future::ready(Ok(())))
    }
    fn stage_listeners(
        &self,
        list: Vec<wrendns_config::Listener>,
    ) -> BoxFuture<Result<Vec<crate::server::StagedListener>, crate::server::WindowError>> {
        match self.listeners.clone() {
            Some(h) => Box::pin(async move { h.stage(list).await }),
            None => Box::pin(std::future::ready(Err(crate::server::WindowError {
                reason: "bind_failed",
                detail: "this node has no listeners to stage".to_owned(),
            }))),
        }
    }
    fn commit_listeners(&self) -> BoxFuture<Result<(), crate::server::WindowError>> {
        match self.listeners.clone() {
            Some(h) => Box::pin(async move { h.commit().await }),
            None => Box::pin(std::future::ready(Ok(()))),
        }
    }
    fn abort_listeners(&self) -> BoxFuture<()> {
        match self.listeners.clone() {
            Some(h) => Box::pin(async move { h.abort().await }),
            None => Box::pin(std::future::ready(())),
        }
    }
    fn is_primary(&self) -> bool {
        true
    }
    fn clustered(&self) -> bool {
        false
    }
    fn members(&self) -> Vec<Member> {
        Vec::new()
    }
    fn primary_name(&self) -> Option<String> {
        None
    }
    fn primary_url(&self) -> Option<String> {
        None
    }
    fn sign(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn verify(&self, _node: &str, _bytes: &[u8], _sig: &[u8]) -> bool {
        false
    }
    fn forward(&self, _node: &str, _req: Forwarded) -> BoxFuture<Result<ForwardedAnswer, Problem>> {
        Box::pin(std::future::ready(Err(Problem::unavailable("stub"))))
    }
    fn audit(
        &self,
        _actor: &Actor,
        _action: &str,
        _target: &str,
        _detail: &Value,
    ) -> Result<(), String> {
        Ok(())
    }
    fn restart(&self) -> BoxFuture<()> {
        Box::pin(std::future::ready(()))
    }
    fn proof_socket(&self, _addr: SocketAddr) -> BoxFuture<Result<Arc<dyn ProofSocket>, String>> {
        Box::pin(std::future::ready(Err("stub".to_owned())))
    }
}

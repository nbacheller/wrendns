// SPDX-License-Identifier: AGPL-3.0-or-later
//! The host's address facts for the known-ID gate (REQ: DNS-901, ADR-1090 point 2).
//!
//! The config crate makes no system call: it takes a [`HostFacts`]. This module reads the
//! interface list (the `getifaddrs` wrapper of `wrendns-net`), keeps the facts the listeners were bound with, and tells whether the host's addresses have changed since.
//!
//! Evaluated: at start, and at every reload (a file reload, a SIGHUP, an API or replicated change).
//! An address that appears later is picked up at the next reload; until then the health report
//! says the gate may no longer match the host (`listener_gate_stale`).

use std::net::IpAddr;
use std::sync::Mutex;

use tracing::warn;
use wrendns_config::HostFacts;

/// The facts in force: what the listeners were last bound with.
static IN_FORCE: Mutex<Option<HostFacts>> = Mutex::new(None);

#[cfg(test)]
thread_local! {
    /// A test's own facts for this thread, so tests never depend on the machine's addresses.
    static OVERRIDE: std::cell::Cell<Option<HostFacts>> = const { std::cell::Cell::new(None) };
}

/// Runs `f` with these facts standing in for the machine's (this thread only).
#[cfg(test)]
pub(crate) fn with_facts<T>(facts: HostFacts, f: impl FnOnce() -> T) -> T {
    let before = OVERRIDE.with(|o| o.replace(Some(facts)));
    let out = f();
    OVERRIDE.with(|o| o.set(before));
    out
}

/// Reads the interface list now. An unreadable list (or one with no address at all, which is what
/// a platform without `getifaddrs` returns) fails closed: [`HostFacts::UNKNOWN`].
pub(crate) fn read() -> HostFacts {
    #[cfg(test)]
    if let Some(f) = OVERRIDE.with(std::cell::Cell::get) {
        return f;
    }
    match wrendns_net::local_addrs() {
        Ok(list) => {
            let ips: Vec<IpAddr> = list.iter().filter(|a| a.up).map(|a| a.ip).collect();
            HostFacts::from_addrs(&ips)
        }
        Err(e) => {
            warn!(
                "cannot read this host's interface addresses ({e}): a wildcard encrypted listener is treated as reachable from the internet, so require_client_id is on by default for it"
            );
            HostFacts::UNKNOWN
        }
    }
}

fn lock() -> std::sync::MutexGuard<'static, Option<HostFacts>> {
    IN_FORCE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Records the facts the listeners were just bound with (called by the bind only, after it
/// succeeded). A load, a failed reload or a read-only check never calls this, so the facts in
/// force always describe the sockets.
pub(crate) fn set_bound(f: HostFacts) {
    *lock() = Some(f);
    if f.public_ipv4.is_none() {
        warn!(
            "the host's interface list is unreadable or empty: failing closed for the gate default"
        );
    }
}

/// The facts the listeners were bound with (read once if nothing has bound yet).
pub(crate) fn facts() -> HostFacts {
    #[cfg(test)]
    if let Some(f) = OVERRIDE.with(std::cell::Cell::get) {
        return f;
    }
    let held = *lock();
    held.unwrap_or_else(|| {
        let f = read();
        *lock() = Some(f);
        f
    })
}

/// One encrypted listener as its socket is, recorded by the apply (never by the config).
#[derive(Debug, Clone)]
pub(crate) struct ListenerState {
    /// `proto://addr`, lower case ([`key`]).
    pub key: String,
    /// The gate of the running socket; `None` when nothing is bound for it.
    pub gated: Option<bool>,
    /// The host facts this listener was bound with.
    pub facts: HostFacts,
    /// Whether the running socket carries the settings the configuration asks for.
    pub matches: bool,
}

static LISTENERS: Mutex<Vec<ListenerState>> = Mutex::new(Vec::new());

fn states() -> std::sync::MutexGuard<'static, Vec<ListenerState>> {
    LISTENERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The name a listener goes by in health reasons and in this table.
pub(crate) fn key(l: &wrendns_config::Listener) -> String {
    format!("{:?}://{}", l.proto, l.addr).to_lowercase()
}

/// Records how the encrypted listeners are after an apply (also a partial one).
pub(crate) fn publish(v: Vec<ListenerState>) {
    *states() = v;
}

fn state_of(l: &wrendns_config::Listener) -> Option<ListenerState> {
    let k = key(l);
    states().iter().find(|s| s.key == k).cloned()
}

/// The host facts `l` was bound with (the facts in force when nothing is recorded for it).
pub(crate) fn facts_for(l: &wrendns_config::Listener) -> HostFacts {
    state_of(l).map_or_else(facts, |s| s.facts)
}

/// The gate `l` really has: the running socket's, not the configuration's. Without a socket (or
/// before any apply) it is what the configuration resolves to.
pub(crate) fn effective_gate(l: &wrendns_config::Listener) -> bool {
    state_of(l)
        .and_then(|s| s.gated)
        .unwrap_or_else(|| l.gated(facts_for(l)))
}

/// REQ: DNS-901 — `true` when the apply recorded `l` as closed: it is configured but nothing is
/// bound for it (a gate turned on that could not be applied closed the old socket). A listener
/// without a record (before any apply) is not reported closed.
pub(crate) fn is_closed(l: &wrendns_config::Listener) -> bool {
    l.proto.needs_tls() && state_of(l).is_some_and(|s| s.gated.is_none())
}

/// The listeners whose socket does not match the configuration: `(name, running)`.
pub(crate) fn mismatched(listen: &[wrendns_config::Listener]) -> Vec<(String, bool)> {
    listen
        .iter()
        .filter(|l| l.proto.needs_tls())
        .filter_map(|l| {
            let s = state_of(l)?;
            (!s.matches).then_some((s.key, s.gated.is_some()))
        })
        .collect()
}

/// Whether the apply recorded anything for `l` (a test reads it to see that a restored listener is
/// published even when the new list does not name it).
#[cfg(test)]
pub(crate) fn is_recorded(l: &wrendns_config::Listener) -> bool {
    state_of(l).is_some()
}

#[cfg(test)]
pub(crate) fn clear_listeners_for_test() {
    states().clear();
}

/// Serialises the tests that write the process-wide listener table (the bind's `publish`) or read
/// it (`effective_gate`, `facts_for`, `mismatched`, so also the probe targets): one lock for all.
#[cfg(test)]
static TABLE_TESTS: Mutex<()> = Mutex::new(());

/// The holder of the test lock; the table is emptied when it is taken and when it is dropped, so
/// a test starts with no foreign entries and leaves none behind (even when it panics).
#[cfg(test)]
pub(crate) struct TableGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

#[cfg(test)]
impl Drop for TableGuard {
    fn drop(&mut self) {
        states().clear();
    }
}

/// Takes the test lock (see [`TableGuard`]). Every test that binds an encrypted listener through
/// `Listeners::apply`, or reads the table, holds this for its whole length.
#[cfg(test)]
pub(crate) fn isolate() -> TableGuard {
    let g = TABLE_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    states().clear();
    TableGuard(g)
}

/// What the bind last recorded, ignoring any test override.
#[cfg(test)]
pub(crate) fn bound_for_test() -> Option<HostFacts> {
    *lock()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_901_override_stands_in_for_the_machine() {
        let f = HostFacts {
            public_ipv4: Some(true),
            global_ipv6: false,
        };
        assert_eq!(with_facts(f, facts), f);
        assert_eq!(with_facts(f, read), f);
    }
}

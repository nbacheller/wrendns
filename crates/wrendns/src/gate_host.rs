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

/// The facts as they are now, when they would change a gate default from what is in force.
pub(crate) fn changed_since_bind() -> Option<(HostFacts, HostFacts)> {
    let (bound, now) = (facts(), read());
    (bound.public_ipv4 != now.public_ipv4).then_some((bound, now))
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

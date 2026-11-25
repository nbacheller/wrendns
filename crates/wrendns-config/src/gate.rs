// SPDX-License-Identifier: AGPL-3.0-or-later
//! The known-ID gate's default, in one place (REQ: DNS-901, ADR-1090 points 1 and 2).
//!
//! This module is pure: it makes no system call. The host's address facts are passed in as a
//! [`HostFacts`], which the node builds from its interface list. Every place that reads the
//! effective gate of a listener (the bind, the probes, the API, the guarded row, the warnings, the
//! health reason) goes through [`default_gate`], so the answer is the same everywhere.

use std::net::IpAddr;

use crate::schema::{Config, Listener, is_public_address};

/// What the node knows about its own addresses.
///
/// REQ: DNS-901 (ADR-1090, owner decision 2026-11-25) — a wildcard bind is gated by default only
/// when the host holds a public IPv4 address; a global IPv6 address alone does not gate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFacts {
    /// The host holds a public IPv4 address on an interface that is up: `Some(true)` or
    /// `Some(false)`; `None` when the interface list could not be read (fail closed: a wildcard
    /// listener is then treated as if one existed).
    pub public_ipv4: Option<bool>,
    /// The host holds a global IPv6 address (only used for a warning).
    pub global_ipv6: bool,
}

impl HostFacts {
    /// The interface list could not be read.
    pub const UNKNOWN: Self = Self {
        public_ipv4: None,
        global_ipv6: false,
    };

    /// Builds the facts from the addresses of the interfaces that are up. An empty list is as
    /// good as unreadable (every host has a loopback address), so it is [`HostFacts::UNKNOWN`].
    #[must_use]
    pub fn from_addrs(addrs: &[IpAddr]) -> Self {
        if addrs.is_empty() {
            return Self::UNKNOWN;
        }
        let mut public_ipv4 = false;
        let mut global_ipv6 = false;
        for ip in addrs {
            // An IPv4-mapped IPv6 address is judged as the IPv4 address it carries.
            match ip.to_canonical() {
                IpAddr::V4(v4) => public_ipv4 |= is_public_address(IpAddr::V4(v4)),
                v6 @ IpAddr::V6(_) => global_ipv6 |= is_public_address(v6),
            }
        }
        Self {
            public_ipv4: Some(public_ipv4),
            global_ipv6,
        }
    }
}

/// Whether a bind address is a wildcard: `0.0.0.0`, `::` and the IPv4-mapped `::ffff:0.0.0.0`.
#[must_use]
pub fn is_wildcard(ip: IpAddr) -> bool {
    ip.to_canonical().is_unspecified()
}

/// What the unset `require_client_id` resolves to for a bind address, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultGate {
    /// A public address: on.
    PublicAddress,
    /// A wildcard bind on a host with a public IPv4 address: on.
    WildcardPublicIpv4,
    /// A wildcard bind and the interface list could not be read: on (fail closed).
    WildcardUnreadable,
    /// A wildcard bind on a host with no public IPv4 address: off.
    WildcardNoPublicIpv4 {
        /// The host does hold a global IPv6 address, which does not gate it.
        global_ipv6: bool,
    },
    /// A private, loopback or other non-public address: off.
    NotPublic,
}

impl DefaultGate {
    /// The default is on.
    #[must_use]
    pub fn on(self) -> bool {
        matches!(
            self,
            Self::PublicAddress | Self::WildcardPublicIpv4 | Self::WildcardUnreadable
        )
    }

    /// The listener is reached from public addresses (or might be: fail closed), so turning its
    /// gate off opens it to the internet's queries.
    #[must_use]
    pub fn public_exposure(self) -> bool {
        self.on()
    }

    /// The sentence the web UI and the guarded review show: what the default resolves to, and why.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::PublicAddress => "on, because the address is public",
            Self::WildcardPublicIpv4 => {
                "on, because it binds every address and this host has a public IPv4 address"
            }
            Self::WildcardUnreadable => {
                "on, because it binds every address and this host's interface list could not be read (assumed public)"
            }
            Self::WildcardNoPublicIpv4 { global_ipv6: false } => {
                "off, because it binds every address and this host has no public IPv4 address"
            }
            Self::WildcardNoPublicIpv4 { global_ipv6: true } => {
                "off, because it binds every address and this host has no public IPv4 address (it has a global IPv6 address, which does not turn the default on: set it on if it is reachable that way)"
            }
            Self::NotPublic => "off, because the address is not public",
        }
    }
}

/// The one function behind every read of the effective gate: what the unset setting resolves to.
#[must_use]
pub fn default_gate(ip: IpAddr, host: HostFacts) -> DefaultGate {
    if is_wildcard(ip) {
        return match host.public_ipv4 {
            Some(true) => DefaultGate::WildcardPublicIpv4,
            None => DefaultGate::WildcardUnreadable,
            Some(false) => DefaultGate::WildcardNoPublicIpv4 {
                global_ipv6: host.global_ipv6,
            },
        };
    }
    if is_public_address(ip) {
        DefaultGate::PublicAddress
    } else {
        DefaultGate::NotPublic
    }
}

/// The effective gate of a listener given its transport, setting and bind address: the rule
/// behind [`Listener::gated`], also used on a `listen-access` value (see
/// `guarded::gate_map`).
#[must_use]
pub fn effective_gate(
    proto_carries_key: bool,
    setting: Option<bool>,
    ip: IpAddr,
    host: HostFacts,
) -> bool {
    proto_carries_key && setting.unwrap_or_else(|| default_gate(ip, host).on())
}

impl Listener {
    /// REQ: DNS-901 — what the unset setting resolves to for this listener.
    #[must_use]
    pub fn default_gate(&self, host: HostFacts) -> DefaultGate {
        default_gate(self.addr.ip(), host)
    }

    /// REQ: DNS-901 — whether this listener answers only a known device key: only `dot`, `doh`,
    /// `doh3` and `doq` can carry one; an explicit setting wins, and unset follows
    /// [`default_gate`].
    #[must_use]
    pub fn gated(&self, host: HostFacts) -> bool {
        effective_gate(
            self.proto.needs_tls(),
            self.require_client_id,
            self.addr.ip(),
            host,
        )
    }

    /// REQ: DNS-901 — gated only because the setting is unset and the default is on (what an
    /// upgrade changes for an existing configuration).
    #[must_use]
    pub fn gated_by_default(&self, host: HostFacts) -> bool {
        self.require_client_id.is_none() && self.gated(host)
    }
}

/// REQ: DNS-901 (ADR-1090 points 1 and 2) — the warnings about one listener's gate, for the file
/// check, the start-up log and every reload. Warns for every explicit `false` on a listener that
/// is public or that a public address reaches (a wildcard bind on a host with a public IPv4
/// address, or on one whose interfaces could not be read), whether the file or the web UI set it;
/// for a wildcard listener left on its default that is off while the host has only a global IPv6
/// address; and for a listener that is not gated and is bound outside `[access] allowed_networks`.
#[must_use]
pub fn listener_warnings(cfg: &Config, l: &Listener, host: HostFacts, at: &str) -> Vec<String> {
    let mut out = Vec::new();
    let d = l.default_gate(host);
    if l.proto.needs_tls() {
        if l.require_client_id == Some(false) && d.public_exposure() {
            out.push(format!(
                "{at}: {:?} listener on address {} has require_client_id = false; only [access] allowed_networks keeps it from being an open resolver for the whole internet",
                l.proto,
                l.addr.ip()
            ));
            return out;
        }
        if l.require_client_id.is_none()
            && matches!(d, DefaultGate::WildcardNoPublicIpv4 { global_ipv6: true })
        {
            out.push(format!(
                "{at}: {:?} listener binds every address and this host has a global IPv6 address but no public IPv4 address, so require_client_id is not on by default; set it to true if the listener is reachable over IPv6 from the internet",
                l.proto
            ));
            return out;
        }
    }
    if !l.gated(host) && !is_wildcard(l.addr.ip()) {
        let outside = !cfg
            .access
            .allowed_networks
            .iter()
            .any(|n| n.contains(l.addr.ip().to_canonical()));
        if outside {
            if l.proto.needs_tls() {
                out.push(format!(
                    "{at}: {:?} listener on address {} with require_client_id = {}; only [access] allowed_networks keeps it from being an open resolver",
                    l.proto,
                    l.addr.ip(),
                    if l.require_client_id == Some(false) {
                        "false"
                    } else {
                        "unset"
                    }
                ));
            } else {
                out.push(format!(
                    "{at}: {:?} listener on address {} outside [access] allowed_networks; only allowed_networks keeps it from being an open resolver (udp and tcp cannot carry a device key)",
                    l.proto,
                    l.addr.ip()
                ));
            }
        }
    }
    out
}

/// [`listener_warnings`] for every listener of `cfg`.
#[must_use]
pub fn gate_warnings(cfg: &Config, host: HostFacts) -> Vec<String> {
    cfg.listen
        .iter()
        .enumerate()
        .flat_map(|(i, l)| listener_warnings(cfg, l, host, &format!("listen[{i}]")))
        .collect()
}

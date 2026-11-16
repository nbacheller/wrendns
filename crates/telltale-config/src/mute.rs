//! REQ: OBS-038 (ADR-161) — anomaly mutes as the engine needs them: each one's devices and groups
//! resolved into networks, its kinds, and its end time. Validation and the server share this, so
//! what `validate` accepts is what the engine receives.

use crate::Config;
use crate::schema::{AnomalyKind, AnomalyMuteConfig};
use crate::types::{Cidr, parse_rfc3339};

/// A mute ready to match addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMute {
    pub name: String,
    /// Every address or network it covers, sorted.
    pub nets: Vec<Cidr>,
    pub kinds: Vec<AnomalyKind>,
    /// Unix seconds; `None`: never.
    pub expires_unix: Option<u64>,
}

/// A device name's addresses and networks: the `match` entries that are an IP or a CIDR. A MAC
/// address or a client ID (`id:`) matches no network here.
fn device_nets(cfg: &Config, name: &str) -> Option<Vec<Cidr>> {
    let c = cfg
        .client
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case(name))?;
    Some(
        c.match_keys
            .iter()
            .filter(|k| !k.starts_with("id:"))
            .filter_map(|k| Cidr::parse(k).ok())
            .collect(),
    )
}

/// A group's networks and the addresses of the devices that name it.
fn group_nets(cfg: &Config, name: &str) -> Option<Vec<Cidr>> {
    let g = cfg.group.iter().find(|g| g.name.as_str() == name)?;
    let mut v: Vec<Cidr> = g.networks.clone();
    for c in cfg
        .client
        .iter()
        .filter(|c| c.groups.iter().any(|x| x.as_str() == name))
    {
        v.extend(
            c.match_keys
                .iter()
                .filter(|k| !k.starts_with("id:"))
                .filter_map(|k| Cidr::parse(k).ok()),
        );
    }
    Some(v)
}

/// What is wrong with one mute, as `(field, message)`; empty when it is fine.
#[must_use]
pub fn problems(cfg: &Config, m: &AnomalyMuteConfig) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if m.name.is_empty() || m.name.chars().count() > 64 {
        out.push(("name", "1 to 64 characters".to_owned()));
    }
    if m.devices.is_empty() && m.groups.is_empty() {
        out.push((
            "devices",
            "name at least one device or group: muting everyone is switching the anomaly engine off (`[telemetry.anomaly] enabled = false`)".to_owned(),
        ));
    }
    if m.kinds.is_empty() {
        out.push(("kinds", "name at least one kind of finding".to_owned()));
    }
    for d in &m.devices {
        let is_mac = d.len() == 17 && d.bytes().filter(|b| *b == b':').count() == 5;
        if is_mac {
            out.push((
                "devices",
                format!("`{d}` is a MAC address: a mute matches addresses, and a device's address changes with its lease. Name the device (`[[client]]`) or its IP"),
            ));
        } else if let Some(nets) = device_nets(cfg, d) {
            if nets.is_empty() {
                out.push((
                    "devices",
                    format!("device `{d}` has no IP or network in its `match` (a MAC address or client ID can't be muted by); add one, or give the IP here"),
                ));
            }
        } else if Cidr::parse(d).is_err() {
            out.push((
                "devices",
                format!("`{d}` is neither a device name nor an IP or CIDR"),
            ));
        }
    }
    for g in &m.groups {
        if g.as_str() == "default" {
            out.push((
                "groups",
                "`default` is whatever matches no other group, so it has no addresses to mute: name the devices".to_owned(),
            ));
        } else if let Some(nets) = group_nets(cfg, g) {
            if nets.is_empty() {
                out.push((
                    "groups",
                    format!("group `{g}` has no networks and no device naming it, so there is nothing to mute"),
                ));
            }
        } else {
            out.push(("groups", format!("unknown group `{g}`")));
        }
    }
    if let Some(e) = &m.expires
        && parse_rfc3339(e).is_none()
    {
        out.push((
            "expires",
            format!("`{e}` isn't an RFC 3339 time (2026-12-31T00:00:00Z)"),
        ));
    }
    if let Some(n) = &m.note
        && (n.chars().count() > 200 || n.chars().any(char::is_control))
    {
        out.push(("note", "at most 200 characters, on one line".to_owned()));
    }
    out
}

/// Every mute that resolves, ready for the engine. One with a problem is left out (validation
/// reports it; a node never applies a configuration that has problems).
#[must_use]
pub fn resolve(cfg: &Config) -> Vec<ResolvedMute> {
    cfg.anomaly_mute
        .iter()
        .filter(|m| problems(cfg, m).is_empty())
        .map(|m| {
            let mut nets: Vec<Cidr> = Vec::new();
            for d in &m.devices {
                match device_nets(cfg, d) {
                    Some(n) => nets.extend(n),
                    None => nets.extend(Cidr::parse(d)),
                }
            }
            for g in &m.groups {
                nets.extend(group_nets(cfg, g).unwrap_or_default());
            }
            nets.sort_by_key(|c| (c.addr, c.prefix));
            nets.dedup();
            let mut kinds = m.kinds.clone();
            kinds.sort();
            kinds.dedup();
            ResolvedMute {
                name: m.name.as_str().to_owned(),
                nets,
                kinds,
                expires_unix: m
                    .expires
                    .as_ref()
                    .and_then(|e| parse_rfc3339(e))
                    .and_then(|s| u64::try_from(s).ok()),
            }
        })
        .collect()
}

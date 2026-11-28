// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904, CLD-919 (T36.10b step b5; ADR-1084 as amended 2026-11-27, ADR-1115) - the
//! `delegated` kind: a DNS host with no usable API (`GoDaddy` and others) where the operator creates
//! one `_acme-challenge.<slug>.<domain>. CNAME <slug>.<validation zone>.` record by hand, once, and
//! the node writes the challenge TXT only in the validation zone, through the provider the entry's
//! `delegated_to` names.
//!
//! - **What to create** ([`expected`]): one record per location whose parent domain is the entry's
//!   zone or inside it (a location names no provider yet, so the zone decides, as the design says:
//!   the provider whose zone contains the location's domain).
//! - **Verification** ([`verify`]): the record is looked up at the zone's own authoritative servers,
//!   found through the configured upstreams (`crate::authoritative`), never in the node's own local
//!   data or cache: the node owns the location subtree and would answer itself. Every name server of
//!   the zone must answer with authority and with the expected target. The result is a reason to show
//!   on the card and, when it fails, a degraded health reason; it never changes a DNS answer
//!   (CLU-004) and the lookup runs off the DNS runtime.
//!
//! The last result of each entry is kept in memory on the node that ran the check (a read: it is not
//! replicated and nothing is written at any DNS host).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard, PoisonError};

use wrendns_api::model::{DnsProviderDelegation, DnsProviderDelegationRecord};
use wrendns_config::{Config, DnsProviderConfig, challenge_name, challenge_target};
use wrendns_proto::rtype;

use crate::authoritative::{self, Limits, LookupError, ServerReport, Upstreams};

/// One CNAME the operator creates at the DNS host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Expected {
    /// The location it is for; `None` for the template shown before any location uses the zone.
    pub(crate) location: Option<String>,
    /// `_acme-challenge.<slug>.<domain>`, lowercase, no trailing dot.
    pub(crate) name: String,
    /// `<slug>.<validation zone>`.
    pub(crate) target: String,
}

/// The result of checking one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Check {
    pub(crate) name: String,
    pub(crate) target: String,
    pub(crate) verified: bool,
    /// Why, in a sentence (also when it is verified: who answered).
    pub(crate) reason: String,
    /// When, Unix seconds.
    pub(crate) checked_at: u64,
}

/// The validation provider of `entry` (the one `delegated_to` names) and the records to create, one
/// per location in the entry's zone. With no such location, one template record with `<slug>` stands
/// in (the card shows it before any location exists).
pub(crate) fn expected<'a>(
    cfg: &'a Config,
    entry: &DnsProviderConfig,
) -> (Option<&'a DnsProviderConfig>, Vec<Expected>) {
    let validation = entry.validation_provider(&cfg.dns_provider);
    let vzone = validation.map_or_else(|| "<validation zone>".to_owned(), |v| v.zone.to_string());
    let zone = entry.zone.as_str();
    let mut out: Vec<Expected> = cfg
        .location
        .iter()
        .filter_map(|l| {
            let d = l.parent_domain(cfg)?;
            let inside = d == zone || d.ends_with(&format!(".{zone}"));
            inside.then(|| Expected {
                location: Some(l.slug.to_string()),
                name: challenge_name(l.slug.as_str(), &d),
                target: challenge_target(l.slug.as_str(), &vzone),
            })
        })
        .collect();
    if out.is_empty() {
        out.push(Expected {
            location: None,
            name: challenge_name("<slug>", zone),
            target: challenge_target("<slug>", &vzone),
        });
    }
    (validation, out)
}

/// The delegation of `entry` as the API shows it: the validation provider and each record to create,
/// with this node's latest check when it still matches what the entry expects now.
pub(crate) fn view(cfg: &Config, entry: &DnsProviderConfig) -> DnsProviderDelegation {
    let (validation, want) = expected(cfg, entry);
    let checks = latest(entry.name.as_str());
    DnsProviderDelegation {
        validation_provider: entry
            .delegated_to
            .as_ref()
            .map(|d| d.trim().to_owned())
            .unwrap_or_default(),
        validation_zone: validation.map(|v| v.zone.to_string()),
        records: want
            .iter()
            .map(|w| {
                let c = checks
                    .iter()
                    .find(|c| c.name == w.name && c.target == w.target);
                DnsProviderDelegationRecord {
                    location: w.location.clone(),
                    name: w.name.clone(),
                    target: w.target.clone(),
                    verified: c.map(|c| c.verified),
                    reason: c.map(|c| c.reason.clone()),
                    checked_at: c.map(|c| c.checked_at),
                }
            })
            .collect(),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What one name server's addresses said.
#[derive(Default)]
struct Verdict {
    /// An address answered with authority and the right target.
    good: bool,
    /// An address answered, and the answer was wrong (no CNAME, another target, no authority).
    wrong: bool,
    problems: Vec<String>,
}

/// Judges the answers of a zone's servers for the CNAME at `name`: verified only when every name
/// server answers with authority and has exactly the target. A server is good when at least one of
/// its addresses gave the right answer and none gave a wrong one (an unreachable second address of
/// a dual-stack server is not a wrong answer; a different target is). The reason names the servers
/// that are not good, and what they said.
pub(crate) fn judge(reports: &[ServerReport], name: &str, target: &str) -> (bool, String) {
    let mut by: BTreeMap<&str, Verdict> = BTreeMap::new();
    for r in reports {
        let v = by.entry(r.server.as_str()).or_default();
        match &r.outcome {
            Err(e) => v
                .problems
                .push(format!("could not be asked at {}: {e}", r.addr)),
            Ok(reply) if !reply.aa => {
                v.wrong = true;
                v.problems.push(format!(
                    "answered without authority at {} (it is not serving the zone)",
                    r.addr
                ));
            }
            Ok(reply) => {
                let found = reply.cnames(name);
                if found.len() == 1 && found[0] == target {
                    v.good = true;
                } else if found.is_empty() {
                    v.wrong = true;
                    let what = match reply.rcode {
                        0 => "has no CNAME there".to_owned(),
                        3 => "does not know the name (NXDOMAIN)".to_owned(),
                        c => format!("answered with response code {c}"),
                    };
                    v.problems.push(format!("{what} (asked at {})", r.addr));
                } else {
                    v.wrong = true;
                    v.problems.push(format!(
                        "has the CNAME pointing to {} instead of {target} (asked at {})",
                        found.join(", "),
                        r.addr
                    ));
                }
            }
        }
    }
    if by.is_empty() {
        return (false, "no name server was asked".to_owned());
    }
    let good = |v: &Verdict| v.good && !v.wrong;
    let total = by.len();
    let ok = by.values().filter(|v| good(v)).count();
    if ok == total {
        let names: Vec<&str> = by.keys().copied().collect();
        return (
            true,
            format!(
                "All {total} authoritative name server{} ({}) answer with the CNAME to {target}.",
                if total == 1 { "" } else { "s" },
                names.join(", ")
            ),
        );
    }
    let why: Vec<String> = by
        .iter()
        .filter(|(_, v)| !good(v))
        .map(|(server, v)| format!("{server} {}", v.problems.join("; ")))
        .collect();
    (
        false,
        format!(
            "{ok} of {total} authoritative name servers have the CNAME to {target}: {}.",
            why.join(". ")
        ),
    )
}

/// Looks the CNAME of `e` up at the authoritative servers of `zone` and judges the answers. A lookup
/// that could not be made (the upstreams did not answer, the zone has no usable server) is a
/// failed check with that reason, not an error: the card shows it.
pub(crate) async fn verify(up: &dyn Upstreams, limits: &Limits, zone: &str, e: &Expected) -> Check {
    let (verified, reason) =
        match authoritative::ask_all(up, zone, &e.name, rtype::CNAME, limits).await {
            Ok(reports) => judge(&reports, &e.name, &e.target),
            Err(LookupError::Timeout) => (
                false,
                "the authoritative name servers did not all answer in time".to_owned(),
            ),
            Err(err) => (false, format!("could not look the record up: {err}")),
        };
    Check {
        name: e.name.clone(),
        target: e.target.clone(),
        verified,
        reason,
        checked_at: now(),
    }
}

/// The latest checks of each entry, on this node.
fn store() -> MutexGuard<'static, HashMap<String, Vec<Check>>> {
    static M: std::sync::OnceLock<Mutex<HashMap<String, Vec<Check>>>> = std::sync::OnceLock::new();
    M.get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Keeps the latest checks of an entry (replacing the earlier ones).
pub(crate) fn record(entry: &str, checks: Vec<Check>) {
    store().insert(entry.to_owned(), checks);
}

/// The latest checks of an entry, for the card.
pub(crate) fn latest(entry: &str) -> Vec<Check> {
    store().get(entry).cloned().unwrap_or_default()
}

/// The entries whose latest check failed, with the reason of the first failed record: the health
/// reasons. An entry no longer configured is dropped, and so is a check of a record the entry no
/// longer expects (its settings changed since).
pub(crate) fn failures_among(cfg: &Config) -> Vec<(String, String)> {
    let mut s = store();
    s.retain(|n, _| {
        cfg.dns_provider
            .iter()
            .any(|p| p.is_delegated() && p.name.as_str() == n)
    });
    let mut out = Vec::new();
    for p in cfg.dns_provider.iter().filter(|p| p.is_delegated()) {
        let (_, want) = expected(cfg, p);
        let Some(checks) = s.get(p.name.as_str()) else {
            continue;
        };
        if let Some(c) = checks.iter().find(|c| {
            !c.verified
                && want
                    .iter()
                    .any(|w| w.name == c.name && w.target == c.target)
        }) {
            out.push((p.name.to_string(), format!("{}: {}", c.name, c.reason)));
        }
    }
    out.sort();
    out
}

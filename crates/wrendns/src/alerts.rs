//! Alerts (REQ: OBS-010, `spec/06` §8; T7.12): rules over the node's own read model (the same
//! data the API serves, federated in a cluster), checked every `[alerts] interval_secs` on the
//! primary (or a standalone node), sent to webhooks, ntfy, Gotify, Pushover, or Slack-compatible hooks
//! when a condition has held for the rule's `for_secs`, and again when it clears.
//!
//! Nothing here is on the DNS path: the task reads the API backend on a blocking thread and
//! sends from its own task, with a timeout per delivery. A failing destination is logged and
//! retried at the next change, never queued without bound.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};
use wrendns_api::Backend;
use wrendns_api::model::Step;
use wrendns_config::{AlertDestination, AlertKind, AlertRule, AlertWhen, Config};

/// What a rule sees right now: `(subject, summary)` pairs (one per upstream, node, list, ...).
pub(crate) type Observed = Vec<(String, String)>;

/// REQ: OPS-010 (ADR-118) — the nodes in maintenance at this evaluation: their conditions are
/// left out, and an alert about one that was firing resolves with "(maintenance)".
#[derive(Default)]
pub(crate) struct Paused {
    /// Node IDs.
    ids: HashSet<String>,
    /// How conditions name them: pod, site, or ID.
    labels: HashSet<String>,
    /// This node (standalone or the evaluating cluster node) is in maintenance.
    me: bool,
    /// The windows, labelled (the `maintenance` rule and the Alerts page).
    pub(crate) windows: Vec<wrendns_api::model::NodeMaintenance>,
    /// The same reads without the nodes in maintenance (cluster-wide shares such as
    /// SERVFAIL), when there are any and this is a cluster.
    without: Option<wrendns_api::Shared>,
}

impl std::fmt::Debug for Paused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paused")
            .field("ids", &self.ids)
            .field("me", &self.me)
            .finish_non_exhaustive()
    }
}

impl Paused {
    /// From the cluster view (or, standalone, this node's own window).
    pub(crate) fn new(
        view: &wrendns_api::model::ClusterView,
        local: Option<wrendns_api::model::NodeMaintenance>,
        standalone_label: &str,
    ) -> Self {
        let mut p = Self::default();
        if view.enabled {
            for n in &view.nodes {
                let Some(m) = &n.maintenance else { continue };
                let label = n.pod.clone().filter(|x| !x.is_empty()).unwrap_or_else(|| {
                    if n.site.is_empty() {
                        n.node_id.clone()
                    } else {
                        n.site.clone()
                    }
                });
                p.ids.insert(n.node_id.clone());
                p.labels.insert(label.clone());
                p.labels.insert(n.node_id.clone());
                if !n.site.is_empty() {
                    p.labels.insert(n.site.clone());
                }
                p.me |= n.this_node;
                let mut m = m.clone();
                m.node = Some(label);
                p.windows.push(m);
            }
        } else if let Some(mut m) = local {
            p.me = true;
            p.labels.insert("this node".to_owned());
            m.node = Some(standalone_label.to_owned());
            p.windows.push(m);
        }
        p
    }

    fn node(n: &wrendns_api::model::ClusterNode) -> bool {
        n.maintenance.is_some()
    }

    /// Whether `label` (a probe's or reason's node) is in maintenance.
    fn label(&self, label: &str) -> bool {
        self.labels.contains(label)
    }

    /// Whether an alert subject is about a node in maintenance: the node itself, or
    /// `<node>|<target>`.
    fn covers(&self, subject: &str) -> bool {
        self.label(subject)
            || subject
                .split_once('|')
                .is_some_and(|(node, _)| self.label(node))
    }
}

/// One alert to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Notice {
    pub(crate) rule: usize,
    pub(crate) subject: String,
    pub(crate) summary: String,
    /// `true` when it starts, `false` when it clears.
    pub(crate) firing: bool,
}

/// Which conditions hold since when, which alerts are out, and which one-off subjects (a
/// finding, a version) were already sent.
#[derive(Debug, Default)]
pub(crate) struct Engine {
    since: HashMap<(usize, String), u64>,
    firing: HashMap<(usize, String), String>,
    sent_once: HashSet<(usize, String)>,
    /// `sent_once` in the order sent, so the oldest go first past [`SENT_ONCE_CAP`].
    sent_order: std::collections::VecDeque<(usize, String)>,
}

/// One-off subjects remembered (REQ: OBS-010, review 04-10).
const SENT_ONCE_CAP: usize = 5000;

/// Conditions that go out once per subject and never "clear".
fn one_off(w: AlertWhen) -> bool {
    matches!(
        w,
        AlertWhen::Anomaly
            | AlertWhen::ChattyLoop
            | AlertWhen::UpdateAvailable
            | AlertWhen::NewDevice
            | AlertWhen::PlanPending
            | AlertWhen::RolloutFailed
            | AlertWhen::DrillReport
            | AlertWhen::CredentialRedirected
            | AlertWhen::SecretsExported
            | AlertWhen::GuardedSettingChanged
    )
}

impl Engine {
    /// One evaluation at `now` (Unix seconds): `observed[i]` is what rule `i` sees. Returns
    /// the alerts that start and clear. Pure, so it's tested without timers or HTTP.
    #[cfg(test)]
    pub(crate) fn step(
        &mut self,
        now: u64,
        rules: &[AlertRule],
        observed: &[Observed],
    ) -> Vec<Notice> {
        self.step_with(now, rules, observed, &Paused::default())
    }

    /// [`Engine::step`], with `paused` naming the nodes in maintenance: an alert about one of
    /// them that stops being seen resolves with "(maintenance)" (OPS-010).
    pub(crate) fn step_with(
        &mut self,
        now: u64,
        rules: &[AlertRule],
        observed: &[Observed],
        paused: &Paused,
    ) -> Vec<Notice> {
        let mut out = Vec::new();
        for (i, (rule, seen)) in rules.iter().zip(observed).enumerate() {
            if one_off(rule.when) {
                for (subject, summary) in seen {
                    if self.sent_once.insert((i, subject.clone())) {
                        self.sent_order.push_back((i, subject.clone()));
                        out.push(Notice {
                            rule: i,
                            subject: subject.clone(),
                            summary: summary.clone(),
                            firing: true,
                        });
                    }
                }
                // Bounded: keep the most recent few thousand. Forgetting only the oldest means
                // subjects still being observed (the last hour's) aren't sent again
                // (review 04-10: clearing the whole set re-sent all of them at once).
                while self.sent_order.len() > SENT_ONCE_CAP {
                    if let Some(old) = self.sent_order.pop_front() {
                        self.sent_once.remove(&old);
                    }
                }
                continue;
            }
            let now_subjects: HashSet<&str> = seen.iter().map(|(s, _)| s.as_str()).collect();
            for (subject, summary) in seen {
                let key = (i, subject.clone());
                let since = *self.since.entry(key.clone()).or_insert(now);
                if now.saturating_sub(since) >= u64::from(rule.for_secs)
                    && !self.firing.contains_key(&key)
                {
                    self.firing.insert(key, summary.clone());
                    out.push(Notice {
                        rule: i,
                        subject: subject.clone(),
                        summary: summary.clone(),
                        firing: true,
                    });
                }
            }
            // Cleared: not seen any more.
            self.since
                .retain(|(r, s), _| *r != i || now_subjects.contains(s.as_str()));
            let cleared: Vec<(usize, String)> = self
                .firing
                .keys()
                .filter(|(r, s)| *r == i && !now_subjects.contains(s.as_str()))
                .cloned()
                .collect();
            for key in cleared {
                if let Some(summary) = self.firing.remove(&key) {
                    // REQ: OPS-010 — not fixed: its node went into maintenance.
                    let summary = if rule.when != AlertWhen::Maintenance && paused.covers(&key.1) {
                        format!("{summary} (maintenance)")
                    } else {
                        summary
                    };
                    out.push(Notice {
                        rule: i,
                        subject: key.1,
                        summary,
                        firing: false,
                    });
                }
            }
        }
        out
    }
}

impl Engine {
    /// REQ: OBS-010 (T9.6) — the alerts firing now, for the status API.
    pub(crate) fn firing_now(&self, rules: &[AlertRule]) -> Vec<wrendns_api::model::FiringAlert> {
        let mut v: Vec<wrendns_api::model::FiringAlert> = self
            .firing
            .iter()
            .filter_map(|((r, subject), summary)| {
                Some(wrendns_api::model::FiringAlert {
                    rule: rules.get(*r)?.name.to_string(),
                    subject: subject.clone(),
                    summary: summary.clone(),
                })
            })
            .collect();
        v.sort_by(|a, b| (&a.rule, &a.subject).cmp(&(&b.rule, &b.subject)));
        v
    }
}

/// REQ: OBS-010 (T24.43) — the UI's page for a device (`new_device` alerts): the node's public
/// address and the Clients page of that address. None without a public address.
fn new_device_link(when: AlertWhen, public_url: &str, client: &str) -> Option<String> {
    let base = public_url.trim().trim_end_matches('/');
    (when == AlertWhen::NewDevice && base.starts_with("http") && !client.is_empty()).then(|| {
        format!(
            "{base}/#/clients?device={}",
            crate::kubernetes::encode(client)
        )
    })
}

/// REQ: OBS-010 (T9.6) — a test message to `d`, from `node`.
pub(crate) async fn send_test(
    d: &AlertDestination,
    node: &str,
    store: &crate::secrets::SecretStore,
) -> Result<(), String> {
    let n = Notice {
        rule: 0,
        subject: "test".to_owned(),
        summary: format!(
            "This is a test alert from WrenDNS on {node}. If you can read it, the destination `{}` works.",
            d.name.as_str()
        ),
        firing: true,
    };
    let client =
        wrendns_filter::fetch::Client::new(Arc::new(wrendns_filter::fetch::SystemResolver), &[])?;
    deliver(&client, d, "Test", &n, node, None, store).await
}

/// Records a delivery's outcome for the status API (the latest per destination).
fn record_delivery(sources: &crate::http::Sources, destination: &str, r: &Result<(), String>) {
    let mut s = sources
        .alerts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    s.deliveries.retain(|x| x.destination != destination);
    s.deliveries.push(wrendns_api::model::AlertDelivery {
        destination: destination.to_owned(),
        unix_seconds: crate::pipeline::unix_now(),
        ok: r.is_ok(),
        error: r.as_ref().err().cloned(),
    });
    s.deliveries
        .sort_by(|a, b| a.destination.cmp(&b.destination));
}

/// What `rule` sees now, read from `b` (blocking: run it on a blocking thread). `pending`:
/// agents' plans waiting for approval on this node, as `(id, summary)`; `redirects`: this node's
/// recent `credential.redirect` audit records, likewise; `exports`: its `backup.create` records
/// that carried secrets.
#[allow(clippy::too_many_lines)] // one arm per condition
fn observe(
    b: &dyn Backend,
    rule: &AlertRule,
    now: u64,
    pending: &[(String, String)],
    redirects: &[(String, String)],
    exports: &[(String, String)],
    m: &Paused,
) -> Observed {
    let node_label = |n: &wrendns_api::model::ClusterNode| {
        if let Some(pod) = n.pod.as_ref().filter(|p| !p.is_empty()) {
            pod.clone()
        } else if n.site.is_empty() {
            n.node_id.clone()
        } else {
            n.site.clone()
        }
    };
    match rule.when {
        // REQ: OBS-010 (T9.5) — the new conditions.
        // REQ: OPS-010 — nodes in maintenance are left out of every per-node condition.
        AlertWhen::SyncLag => b
            .cluster()
            .nodes
            .into_iter()
            .filter(|n| {
                !n.this_node && !n.witness && n.connected && n.config_lag > 0 && !Paused::node(n)
            })
            .map(|n| {
                let s = format!(
                    "{} is {} configuration version(s) behind the primary{}",
                    node_label(&n),
                    n.config_lag,
                    n.behind_seconds
                        .map_or(String::new(), |s| format!(" (for {s} s)"))
                );
                (node_label(&n), s)
            })
            .collect(),
        // REQ: OBS-010 (T24.5, fork #2) — a replica that hasn't reached its primary for
        // `threshold` seconds (default 60). Witnesses and resolver pods are left out; so are
        // nodes in maintenance.
        AlertWhen::PrimaryUnreachable => {
            let limit = rule.threshold.unwrap_or(60.0);
            b.cluster()
                .nodes
                .into_iter()
                .filter(|n| {
                    !n.this_node
                        && !n.ephemeral
                        && !n.witness
                        && n.up
                        && n.role == "replica"
                        && !Paused::node(n)
                })
                .filter_map(|n| {
                    let silent = n.primary_silent_seconds?;
                    (f64::from(u32::try_from(silent).unwrap_or(u32::MAX)) >= limit).then(|| {
                        let name = node_label(&n);
                        let s = format!(
                            "replica {name} hasn't reached its primary for {silent} s: it may be split off from the cluster"
                        );
                        (name, s)
                    })
                })
                .collect()
        }
        AlertWhen::NewDevice => {
            // REQ: OBS-025 — say what it looks like, when that's known.
            let ids: std::collections::HashMap<String, wrendns_api::model::DeviceIdentity> = b
                .identities()
                .into_iter()
                .map(|i| (i.client.clone(), i))
                .collect();
            b.new_devices(now.saturating_sub(3600))
                .into_iter()
                .map(|d| {
                    let who = d
                        .client_name
                        .clone()
                        .map_or_else(|| d.client.clone(), |n| format!("{n} ({})", d.client));
                    let like = ids
                        .get(&d.client)
                        .and_then(crate::identify::looks_like)
                        .map_or_else(String::new, |l| format!(", which {l}"));
                    (
                        d.client.clone(),
                        format!("a new device started using DNS: {who}{like}"),
                    )
                })
                .collect()
        }
        AlertWhen::DiskFull => {
            let limit = rule.threshold.unwrap_or(90.0);
            let c = b.cluster();
            let mut hosts: Vec<(String, wrendns_api::model::HostReport)> = c
                .nodes
                .iter()
                .filter(|n| !Paused::node(n))
                .filter_map(|n| n.host.clone().map(|h| (node_label(n), h)))
                .collect();
            if hosts.is_empty()
                && !c.enabled
                && !m.me
                && let Some(h) = c.host.clone()
            {
                hosts.push(("this node".to_owned(), h));
            }
            hosts
                .into_iter()
                .filter_map(|(name, h)| {
                    let used = h.latest.disk_used_percent?;
                    (used > limit).then(|| {
                        let free = h
                            .latest
                            .disk_free_bytes
                            .map_or(String::new(), |f| format!(", {} MiB free", f / (1 << 20)));
                        (
                            name.clone(),
                            format!(
                                "{name}'s data disk is {used:.0}% full{free} (threshold {limit}%)"
                            ),
                        )
                    })
                })
                .collect()
        }
        // REQ: API-014 (T23.2, ADR-903 §4) — once per change of where a credential goes.
        AlertWhen::CredentialRedirected => redirects.to_vec(),
        // REQ: API-007 (T23.9, ADR-903 §8) — a backup took the stored secrets out of the node.
        AlertWhen::SecretsExported => exports
            .iter()
            .filter(|(s, _)| !s.starts_with(GUARDED_PREFIX))
            .cloned()
            .collect(),
        // REQ: API-902 (T27.13, ADR-956 §6) — a guarded setting was changed, or its change ended.
        AlertWhen::GuardedSettingChanged => exports
            .iter()
            .filter(|(s, _)| s.starts_with(GUARDED_PREFIX))
            .cloned()
            .collect(),
        AlertWhen::PlanPending => pending
            .iter()
            .map(|(id, summary)| {
                (
                    id.clone(),
                    format!("an AI agent's change waits for approval: {summary}"),
                )
            })
            .collect(),
        AlertWhen::UpstreamDown => b
            .upstreams()
            .into_iter()
            .filter(|u| u.breaker == "open")
            .map(|u| {
                let s = format!(
                    "upstream {} ({}) isn't answering: its circuit breaker is open",
                    u.name, u.endpoint
                );
                (u.name, s)
            })
            .collect(),
        AlertWhen::NodeDown => {
            let c = b.cluster();
            c.nodes
                .into_iter()
                .filter(|n| !n.this_node && !n.ephemeral && !n.connected && !Paused::node(n))
                .map(|n| {
                    let name = if n.site.is_empty() {
                        n.node_id.clone()
                    } else {
                        n.site.clone()
                    };
                    let s = format!(
                        "cluster node {name} is unreachable (last seen {} s ago)",
                        n.last_seen_seconds_ago
                    );
                    (name, s)
                })
                .collect()
        }
        AlertWhen::ListFailing => b
            .lists()
            .into_iter()
            .filter(|l| l.enabled && l.error.is_some())
            .map(|l| {
                let s = format!(
                    "list {} fails to update: {}",
                    l.name,
                    l.error.as_deref().unwrap_or("unknown error")
                );
                (l.name, s)
            })
            .collect(),
        // REQ: OBS-023 (T12.3) — downloads fine, but the content stopped changing.
        AlertWhen::ListStale => b
            .lists()
            .into_iter()
            .filter(|l| l.enabled && l.error.is_none())
            .filter_map(|l| {
                let days = l.stale_days?;
                let s = format!(
                    "list {} hasn't changed in {days} days: its source may be abandoned",
                    l.name
                );
                Some((l.name, s))
            })
            .collect(),
        // REQ: OBS-013, OBS-014 — every node's findings (federated), except ones someone
        // already acknowledged.
        // REQ: OBS-036 — informational findings only for a rule that asks for them by kind.
        AlertWhen::Anomaly | AlertWhen::ChattyLoop => b
            .anomalies(now.saturating_sub(3600))
            .into_iter()
            .filter(|f| f.acknowledged.is_none())
            // REQ: OBS-038 — a finding a mute matched never alerts.
            .filter(|f| f.muted_by.is_none())
            .filter(|f| {
                if rule.when == AlertWhen::ChattyLoop {
                    f.kind == "chatty_loop"
                } else {
                    !f.informational
                }
            })
            .map(|f| {
                let who = f.client_name.clone().unwrap_or_else(|| f.client.clone());
                let key = format!(
                    "{}|{}|{}|{}",
                    f.kind,
                    f.client,
                    f.domain.as_deref().unwrap_or(""),
                    f.window_start
                );
                (key, format!("{who}: {}", f.detail))
            })
            .collect(),
        AlertWhen::ServfailRate => {
            // REQ: OPS-010 — the share of the nodes not in maintenance (a standalone node in
            // maintenance has none).
            if m.me && m.without.is_none() {
                return Vec::new();
            }
            let b = m.without.as_deref().unwrap_or(b);
            let buckets = b.timeseries(Step::Minute, now.saturating_sub(300), now);
            let total: u64 = buckets.iter().map(|x| u64::from(x.total)).sum();
            let servfail: u64 = buckets
                .iter()
                .map(|x| u64::from(x.by_rcode.get("SERVFAIL").copied().unwrap_or(0)))
                .sum();
            let threshold = rule.threshold.unwrap_or(5.0);
            #[allow(clippy::cast_precision_loss)] // query counts
            let pct = if total > 0 {
                servfail as f64 * 100.0 / total as f64
            } else {
                0.0
            };
            if total >= 50 && pct > threshold {
                vec![(
                    "servfail".to_owned(),
                    format!(
                        "SERVFAIL for {pct:.1}% of {total} queries in the last 5 minutes (threshold {threshold}%)"
                    ),
                )]
            } else {
                Vec::new()
            }
        }
        // REQ: OBS-020 (ADR-107) — every node's probes and certificates.
        AlertWhen::ProbeFailing => b
            .probes()
            .into_iter()
            .filter(|p| {
                p.skipped.is_none() && p.consecutive_failures >= crate::probes::FAILING_AFTER
            })
            .map(|p| {
                let node = p.node.clone().unwrap_or_else(|| "this node".to_owned());
                (node, p)
            })
            .filter(|(node, _)| !m.label(node))
            .map(|(node, p)| {
                (
                    format!("{node}|{}", p.target),
                    format!(
                        "{} on {node} doesn't answer its probe ({} in a row: {})",
                        p.target,
                        p.consecutive_failures,
                        p.error.as_deref().unwrap_or("no answer")
                    ),
                )
            })
            .collect(),
        AlertWhen::CertExpiring => {
            let days = rule.threshold.unwrap_or(14.0);
            b.probes()
                .into_iter()
                .filter_map(|p| {
                    let left = p.cert_days_left?;
                    #[allow(clippy::cast_precision_loss)] // days
                    let soon = (left as f64) < days;
                    let node = p.node.clone().unwrap_or_else(|| "this node".to_owned());
                    (soon && !m.label(&node)).then(|| {
                        let when = if left < 0 {
                            format!("expired {} day(s) ago", -left)
                        } else {
                            format!("expires in {left} day(s)")
                        };
                        (
                            format!("{node}|{}", p.target),
                            format!("the certificate of {} on {node} {when}", p.target),
                        )
                    })
                })
                .collect()
        }
        // REQ: OBS-016 (ADR-105) — an objective spending its error budget fast (every node).
        AlertWhen::SloBurn => {
            let s = b.slo_settings();
            if !s.enabled {
                return Vec::new();
            }
            let minutes = b.timeseries(
                Step::Minute,
                now.saturating_sub(wrendns_api::slo::MINUTE_SPAN_S),
                now + 1,
            );
            wrendns_api::slo::burning(&s, now, &minutes)
                .into_iter()
                .map(|(name, _, summary)| (name, summary))
                .collect()
        }
        // REQ: CLU-013 — once per failed version; and while pinned.
        AlertWhen::RolloutFailed => b
            .cluster()
            .rollout
            .and_then(|r| r.last_failure)
            .map(|f| {
                (
                    f.version.clone(),
                    format!(
                        "a staged rollout failed: version {} ({}); the cluster is pinned to the version before it",
                        f.version, f.reason
                    ),
                )
            })
            .into_iter()
            .collect(),
        AlertWhen::ClusterPinned => b
            .cluster()
            .rollout
            .and_then(|r| r.pinned)
            .map(|p| {
                (
                    "cluster".to_owned(),
                    format!(
                        "the cluster is pinned to version {} since {} by {}: {}",
                        p.to, p.since, p.by, p.reason
                    ),
                )
            })
            .into_iter()
            .collect(),
        // REQ: OPS-010 — once when a node enters maintenance, resolved when it leaves.
        AlertWhen::Maintenance => m
            .windows
            .iter()
            .map(|w| {
                let node = w.node.clone().unwrap_or_else(|| "this node".to_owned());
                let s = format!(
                    "{node} is in maintenance until {} ({}), started by {}; it keeps answering DNS",
                    time_text(now + w.seconds_left),
                    w.reason,
                    w.by
                );
                (node, s)
            })
            .collect(),
        AlertWhen::UpdateAvailable => {
            let u = b.system_info().update;
            match (u.state.as_str(), u.latest) {
                ("available", Some(v)) => vec![(
                    v.clone(),
                    format!("WrenDNS {v} is available. {}", u.how),
                )],
                _ => Vec::new(),
            }
        }
        // REQ: CLU-014 (owner 2026-10-19) — once per drill report, from every node, for reports
        // that ended in the last 2 hours (a restart doesn't send old ones again).
        AlertWhen::DrillReport => {
            let Ok(h) = tokio::runtime::Handle::try_current() else {
                return Vec::new();
            };
            let page = h.block_on(b.drills(20, 0)).unwrap_or_default();
            let since = i64::try_from(now).unwrap_or(i64::MAX) - 2 * 3600;
            page.items
                .into_iter()
                .filter(|d| d.status == "complete")
                .filter(|d| {
                    d.ended
                        .as_deref()
                        .and_then(wrendns_config::parse_rfc3339)
                        .is_some_and(|t| t >= since)
                })
                .map(|d| (d.id.clone(), drill_text(&d)))
                .collect()
        }
    }
}

/// REQ: CLU-014 — a drill report in one sentence (the `drill_report` alert).
fn drill_text(d: &wrendns_api::model::DrillSummary) -> String {
    let how = if d.by == "schedule" {
        "scheduled failover drill"
    } else {
        "failover drill"
    };
    let coverage = d
        .coverage_percent
        .map_or_else(String::new, |c| format!("; coverage {c:.0} %"));
    let missing = if d.missing_nodes.is_empty() {
        String::new()
    } else {
        format!(" (no answer from {})", d.missing_nodes.join(", "))
    };
    format!(
        "{how} on {} ({}): {} followed, {} stuck, {} quiet{coverage}{missing}. The report: Cluster → Drills.",
        d.node, d.targets, d.followed, d.stuck, d.quiet
    )
}

/// The message for a destination: (body, content type, extra headers).
fn render(
    d: &AlertDestination,
    token: Option<&str>,
    rule: &str,
    n: &Notice,
    node: &str,
) -> (String, &'static str, Vec<(String, String)>) {
    let state = if n.firing { "firing" } else { "resolved" };
    let title = if n.firing {
        format!("{rule}: {}", n.subject)
    } else {
        format!("Resolved: {rule}: {}", n.subject)
    };
    let text = if n.firing {
        n.summary.clone()
    } else {
        format!("Cleared: {}", n.summary)
    };
    match d.kind {
        AlertKind::Webhook => (
            serde_json::json!({
                "rule": rule, "status": state, "subject": n.subject, "summary": n.summary,
                "node": node, "time": crate::pipeline::unix_now(),
            })
            .to_string(),
            "application/json",
            Vec::new(),
        ),
        AlertKind::Ntfy => {
            let mut h = vec![
                ("Title".to_owned(), title),
                ("Priority".to_owned(), if n.firing { "high" } else { "default" }.to_owned()),
                ("Tags".to_owned(), if n.firing { "warning" } else { "white_check_mark" }.to_owned()),
            ];
            if let Some(t) = token {
                h.push(("Authorization".to_owned(), format!("Bearer {t}")));
            }
            (text, "text/plain", h)
        }
        AlertKind::Gotify => (
            serde_json::json!({ "title": title, "message": text, "priority": if n.firing { 8 } else { 4 } }).to_string(),
            "application/json",
            Vec::new(),
        ),
        AlertKind::Slack => (
            serde_json::json!({ "text": format!("*{title}*\n{text}") }).to_string(),
            "application/json",
            Vec::new(),
        ),
        // Sent by `deliver_email`, not as HTTP; REQ: OBS-010 (T24.43) — Pushover's form has two
        // secrets, and `deliver_pushover` builds it.
        AlertKind::Email | AlertKind::Pushover => (text, "text/plain", Vec::new()),
    }
}

/// REQ: OBS-010 (T24.43) — Pushover's own address, used when a destination's `url` is empty.
const PUSHOVER_URL: &str = "https://api.pushover.net/1/messages.json";
/// Pushover's limits, in characters: the title, the message, the supplementary URL.
const PUSHOVER_TITLE_MAX: usize = 250;
const PUSHOVER_MESSAGE_MAX: usize = 1024;
const PUSHOVER_LINK_MAX: usize = 512;

/// REQ: OBS-010 (T24.43) — `s` cut to at most `max` characters, ending in `…` when it was cut.
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// REQ: OBS-010 (T24.43) — a Pushover priority: the destination's choice, else 0 for a firing
/// alert and -1 (no sound) for a resolved one. 2 (emergency) needs a retry policy: never sent.
fn pushover_priority(d: &AlertDestination, firing: bool) -> i8 {
    let (set, default) = if firing {
        (d.priority_firing, 0)
    } else {
        (d.priority_resolved, -1)
    };
    set.unwrap_or(default).clamp(-2, 1)
}

/// REQ: OBS-010 (T24.43) — the `application/x-www-form-urlencoded` body of a Pushover message:
/// the rule and subject as the title, the summary with the node and the time as the message,
/// the priority, the device and sound when set, a link when there is one, and the timestamp.
/// Cut to Pushover's limits, so a long summary still goes out.
#[allow(clippy::too_many_arguments)] // the form's own fields
fn pushover_form(
    d: &AlertDestination,
    token: &str,
    user: &str,
    rule: &str,
    n: &Notice,
    node: &str,
    link: Option<&str>,
    now: u64,
) -> String {
    use crate::kubernetes::encode;
    let title = if n.firing {
        format!("{rule}: {}", n.subject)
    } else {
        format!("Resolved: {rule}: {}", n.subject)
    };
    let summary = if n.firing {
        n.summary.clone()
    } else {
        format!("Cleared: {}", n.summary)
    };
    // The node and the time stay when the summary is cut.
    let tail = format!("\nNode: {node}\nTime: {}", time_text(now));
    let room = PUSHOVER_MESSAGE_MAX.saturating_sub(tail.chars().count());
    let message = format!("{}{tail}", truncate_chars(&summary, room));
    let mut f: Vec<(&str, String)> = vec![
        ("token", token.to_owned()),
        ("user", user.to_owned()),
        ("title", truncate_chars(&title, PUSHOVER_TITLE_MAX)),
        ("message", truncate_chars(&message, PUSHOVER_MESSAGE_MAX)),
        ("priority", pushover_priority(d, n.firing).to_string()),
        ("timestamp", now.to_string()),
    ];
    if let Some(dev) = d.device.as_ref().filter(|x| !x.trim().is_empty()) {
        f.push(("device", dev.trim().to_owned()));
    }
    if let Some(snd) = d.sound.as_ref().filter(|x| !x.trim().is_empty()) {
        f.push(("sound", snd.trim().to_owned()));
    }
    // A link Pushover would refuse for its length is left out, not cut into a broken address.
    if let Some(l) = link.filter(|l| !l.is_empty() && l.chars().count() <= PUSHOVER_LINK_MAX) {
        f.push(("url", l.to_owned()));
    }
    f.iter()
        .map(|(k, v)| format!("{k}={}", encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// REQ: OBS-010 (T24.43) — what a Pushover answer means: `Ok` for 2xx with `status` 1, else the
/// failure as one line: the HTTP status and Pushover's `errors` (`{"status":0,"errors":[...]}`),
/// with `secrets` (the token, the user key) never shown, and cut so the deliveries list stays short.
fn pushover_outcome(status: u16, body: &[u8], secrets: &[&str]) -> Result<(), String> {
    let v: Option<serde_json::Value> = serde_json::from_slice(body).ok();
    let ok = (200..300).contains(&status)
        && v.as_ref()
            .is_none_or(|v| v.get("status").and_then(serde_json::Value::as_i64) != Some(0));
    if ok {
        return Ok(());
    }
    let errors: Vec<String> = v
        .as_ref()
        .and_then(|v| v.get("errors"))
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut out = format!("HTTP {status}");
    if !errors.is_empty() {
        out.push_str(": ");
        out.push_str(&errors.join("; "));
    }
    for t in secrets.iter().filter(|t| !t.is_empty()) {
        out = out.replace(t, wrendns_config::credentials::MARKER);
    }
    let out: String = out.chars().filter(|c| !c.is_control()).collect();
    Err(truncate_chars(&out, 300))
}

/// REQ: OBS-010 (T24.43) — an alert as a Pushover message.
async fn deliver_pushover(
    client: &wrendns_filter::fetch::Client,
    d: &AlertDestination,
    rule: &str,
    n: &Notice,
    node: &str,
    link: Option<&str>,
    store: &crate::secrets::SecretStore,
) -> Result<(), String> {
    // REQ: OPS-014 (ADR-903 §2) — both secrets from their files or the store.
    let token = crate::secrets::Credential::of(d.token_file.as_ref(), d.token_ref.as_ref())
        .resolve(Some(store))?
        .ok_or("pushover needs the application token (token_file or token_ref)")?
        .value;
    let user = crate::secrets::Credential::of(d.user_key_file.as_ref(), d.user_key_ref.as_ref())
        .resolve(Some(store))?
        .ok_or("pushover needs the user or group key (user_key_file or user_key_ref)")?
        .value;
    let (token, user) = (token.expose(), user.expose());
    let url = if d.url.trim().is_empty() {
        PUSHOVER_URL
    } else {
        d.url.as_str()
    };
    let form = pushover_form(
        d,
        token,
        user,
        rule,
        n,
        node,
        link,
        crate::pipeline::unix_now(),
    );
    let req = http::Request::post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("user-agent", "WrenDNS")
        .body(form.into_bytes())
        .map_err(|e| e.to_string())?;
    let resp = tokio::time::timeout(Duration::from_secs(10), client.request(req, 64 * 1024))
        .await
        .map_err(|_| "timed out".to_owned())?
        .map_err(|e| {
            // REQ: API-014 - an error that quotes the request never shows a secret.
            let mut m = e.message;
            for t in [token, user].iter().filter(|t| !t.is_empty()) {
                m = m.replace(*t, wrendns_config::credentials::MARKER);
            }
            m
        })?;
    pushover_outcome(resp.status().as_u16(), resp.body(), &[token, user])
}

/// REQ: OBS-010 (T9.4) — an alert as an email.
async fn deliver_email(
    d: &AlertDestination,
    rule: &str,
    n: &Notice,
    node: &str,
    store: &crate::secrets::SecretStore,
) -> Result<(), String> {
    let (host, port, security) = crate::smtp::parse_url(d.url.as_str())?;
    // REQ: OPS-014 (ADR-903 §2) — the password from its file or the store.
    let password =
        crate::secrets::Credential::of(d.password_file.as_ref(), d.password_ref.as_ref())
            .resolve(Some(store))?;
    let login = match (&d.username, password) {
        (Some(u), Some(p)) => Some((u.to_string(), p.value.expose().to_owned())),
        _ => None,
    };
    let extra_roots = match &d.tls_ca {
        Some(f) => {
            use rustls::pki_types::pem::PemObject as _;
            rustls::pki_types::CertificateDer::pem_file_iter(f.as_str())
                .map_err(|e| format!("{}: {e}", f.as_str()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("{}: {e}", f.as_str()))?
        }
        None => Vec::new(),
    };
    let subject = if n.firing {
        format!("[WrenDNS] {rule}: {}", n.subject)
    } else {
        format!("[WrenDNS] Resolved: {rule}: {}", n.subject)
    };
    let body = format!(
        "{}\n\nRule: {rule}\nStatus: {}\nSubject: {}\nNode: {node}\nTime: {}\n\n-- \nSent by WrenDNS alerts ([alerts] in the configuration).\n",
        if n.firing {
            n.summary.clone()
        } else {
            format!("Cleared: {}", n.summary)
        },
        if n.firing { "firing" } else { "resolved" },
        n.subject,
        crate::alerts::time_text(crate::pipeline::unix_now()),
    );
    let server = crate::smtp::Server {
        host,
        port,
        security,
        login,
        extra_roots,
    };
    let m = crate::smtp::Message {
        from: d.from.as_ref().map(ToString::to_string).unwrap_or_default(),
        to: d.to.iter().map(ToString::to_string).collect(),
        subject,
        body,
    };
    tokio::time::timeout(Duration::from_secs(60), crate::smtp::send(&server, &m))
        .await
        .map_err(|_| "timed out".to_owned())?
}

/// `2026-10-06 17:05:52 UTC`.
pub(crate) fn time_text(unix: u64) -> String {
    let t = wrendns_store::qlog::format_ts(unix.saturating_mul(1_000_000));
    t.get(..19)
        .map_or(t.clone(), |s| format!("{} UTC", s.replace('T', " ")))
}

/// Sends one alert to one destination.
async fn deliver(
    client: &wrendns_filter::fetch::Client,
    d: &AlertDestination,
    rule: &str,
    n: &Notice,
    node: &str,
    link: Option<&str>,
    store: &crate::secrets::SecretStore,
) -> Result<(), String> {
    if d.kind == AlertKind::Email {
        return deliver_email(d, rule, n, node, store).await;
    }
    if d.kind == AlertKind::Pushover {
        return deliver_pushover(client, d, rule, n, node, link, store).await;
    }
    // REQ: OPS-014 (ADR-903 §2) — the token from its file or the store.
    let token = crate::secrets::Credential::of(d.token_file.as_ref(), d.token_ref.as_ref())
        .resolve(Some(store))?
        .map(|r| r.value);
    let token = token.as_ref().map(crate::secrets::SecretValue::expose);
    let (body, ct, headers) = render(d, token, rule, n, node);
    let mut url = d.url.to_string();
    if d.kind == AlertKind::Gotify {
        // REQ: API-014 (ADR-903 §4) — the token is one query value, whatever it holds.
        url = format!(
            "{}/message?token={}",
            url.trim_end_matches('/'),
            crate::kubernetes::encode(token.unwrap_or_default())
        );
    }
    let mut req = http::Request::post(url)
        .header("content-type", ct)
        .header("user-agent", "WrenDNS");
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let req = req.body(body.into_bytes()).map_err(|e| e.to_string())?;
    let resp = tokio::time::timeout(Duration::from_secs(10), client.request(req, 64 * 1024))
        .await
        .map_err(|_| "timed out".to_owned())?
        .map_err(|e| match token.filter(|t| !t.is_empty()) {
            // REQ: API-014 — an error that quotes the request never shows the token.
            // The URL carries it percent-encoded: both forms go.
            Some(t) => e
                .message
                .replace(t, wrendns_config::credentials::MARKER)
                .replace(
                    &crate::kubernetes::encode(t),
                    wrendns_config::credentials::MARKER,
                ),
            None => e.message,
        })?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

/// REQ: OBS-010 (T9.6) — the status API's view after a check.
fn publish_status(
    sources: &crate::http::Sources,
    engine: &Engine,
    rules: &[AlertRule],
    cfg: &Config,
    primary: bool,
    paused: &Paused,
) {
    let mut s = sources
        .alerts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    s.evaluating = primary;
    // REQ: OPS-010 — the Alerts page says whose alerts are paused, until when.
    s.maintenance.clone_from(&paused.windows);
    s.firing = if s.evaluating {
        engine.firing_now(rules)
    } else {
        Vec::new()
    };
    let names: Vec<&str> = cfg
        .alerts
        .destination
        .iter()
        .map(|d| d.name.as_str())
        .collect();
    s.deliveries
        .retain(|x| names.contains(&x.destination.as_str()));
}

/// REQ: OBS-010 (T9.5) — plans waiting for approval on this node, as `(id, summary)`.
fn pending_plans(sources: &crate::http::Sources) -> Vec<(String, String)> {
    sources
        .auth
        .get()
        .map(|a| {
            a.plans()
                .list(None)
                .into_iter()
                .filter(|p| p.state == "pending")
                .map(|p| (p.id, format!("{} (by {})", p.summary, p.requested_by)))
                .collect()
        })
        .unwrap_or_default()
}

/// How far back the `credential_redirected` alert looks: a restart doesn't send older ones again.
const REDIRECT_WINDOW_SECS: u64 = 3600;

/// REQ: API-014 (T23.2, ADR-903 §4) — this node's `credential.redirect` audit records of the last
/// hour, as `(subject, summary)`: the subject is the record's sequence number, so each change
/// goes out once. Only the primary (or a standalone node) applies changes, and so records them.
pub(crate) fn recent_redirects(sources: &crate::http::Sources, now: u64) -> Vec<(String, String)> {
    let Some(auth) = sources.auth.get() else {
        return Vec::new();
    };
    let since = now.saturating_sub(REDIRECT_WINDOW_SECS);
    auth.state()
        .audit_page(
            None,
            50,
            Some(crate::credential_rules::REDIRECT_ACTION),
            None,
        )
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.action == crate::credential_rules::REDIRECT_ACTION && e.ts >= since)
        .map(|e| {
            let d: serde_json::Value = serde_json::from_str(&e.detail).unwrap_or_default();
            let field = d["field"].as_str().unwrap_or("url");
            // REQ: API-014 (review of T23.2) — only where it goes: a URL's scheme and host. Its
            // path can hold a secret (a Slack or webhook URL), and the alert reaches every
            // destination of the rule; the audit record has the rest.
            let to = match &d["to"] {
                serde_json::Value::String(s) => url_origin(s),
                serde_json::Value::Null => "nothing".to_owned(),
                other => other.to_string(),
            };
            (
                e.seq.to_string(),
                format!(
                    "{} changed where {} {}'s credential is sent: {field} is now {to}",
                    e.actor,
                    d["kind"].as_str().unwrap_or("entry").replace('_', " "),
                    e.target
                ),
            )
        })
        .collect()
}

/// REQ: API-007 (T23.9, ADR-903 §8) — this node's `backup.create` audit records of the last hour
/// that carried stored secrets (`secretsIncluded`), as `(subject, summary)`: the subject is the
/// record's sequence number, so each backup goes out once. The summary names who made it and how
/// many secrets, never a name or a value.
pub(crate) fn recent_exports(sources: &crate::http::Sources, now: u64) -> Vec<(String, String)> {
    let Some(auth) = sources.auth.get() else {
        return Vec::new();
    };
    let mut out = recent_guarded(auth, now);
    let since = now.saturating_sub(REDIRECT_WINDOW_SECS);
    out.extend(
        auth.state()
            .audit_page(None, 50, Some("backup.create"), None)
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.action == "backup.create" && e.ts >= since)
            .filter_map(|e| {
                let d: serde_json::Value = serde_json::from_str(&e.detail).unwrap_or_default();
                d["secretsIncluded"].as_bool().filter(|x| *x)?;
                Some((
                    e.seq.to_string(),
                    format!(
                        "{} made a backup that carries {} stored secret(s), encrypted with a passphrase",
                        e.actor,
                        d["count"].as_u64().unwrap_or(0)
                    ),
                ))
            }),
    );
    out
}

/// What marks a `(subject, summary)` pair as a guarded-setting event (they share the vector the
/// `secrets_exported` events travel in, so the condition's own arm picks them out).
const GUARDED_PREFIX: &str = "guarded:";

/// REQ: API-902 (T27.13, ADR-956 §6) — this node's `settings.guarded*` audit records of the last
/// hour as `(subject, summary)`: a change applied or staged, its outcome (confirmed, rolled back
/// with the reason) and an accepted restart, each once (the subject is the record's sequence
/// number). The summary names who, what and where, never a value: a rule's channels reach
/// people who aren't admins. Refusals and offline clears aren't events here.
pub(crate) fn recent_guarded(auth: &wrendns_api::auth::Auth, now: u64) -> Vec<(String, String)> {
    let since = now.saturating_sub(REDIRECT_WINDOW_SECS);
    auth.state()
        .audit_page(None, 50, Some("settings.guarded"), None)
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.ts >= since)
        .filter_map(|e| {
            let d: serde_json::Value = serde_json::from_str(&e.detail).unwrap_or_default();
            let setting = d["setting"].as_str().unwrap_or("a setting").to_owned();
            let node = d["node"].as_str().unwrap_or("this node");
            let what = match e.action.as_str() {
                "settings.guarded" => format!(
                    "{} {} the guarded setting `{setting}` on {node}{}",
                    e.actor,
                    match d["outcome"].as_str() {
                        Some("staged") => "staged a change to",
                        Some("confirmed") => "confirmed a change to",
                        _ => "changed",
                    },
                    if d["weakening"].as_bool() == Some(true) {
                        " (it weakens security)"
                    } else {
                        ""
                    }
                ),
                "settings.guarded_rolled_back" => format!(
                    "the change to the guarded setting `{setting}` on {node} was rolled back ({})",
                    d["reason"].as_str().unwrap_or("unknown")
                ),
                "settings.guarded_restart" => {
                    format!("{} restarted {node} to apply guarded changes", e.actor)
                }
                _ => return None,
            };
            Some((format!("{GUARDED_PREFIX}{}", e.seq), what))
        })
        .collect()
}

/// `scheme://host[:port]` of a URL, without its user information or path; anything else as is.
fn url_origin(s: &str) -> String {
    let Some(i) = s.find("://") else {
        return s.to_owned();
    };
    let rest = &s[i + 3..];
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    format!("{}://{host}", &s[..i])
}

/// REQ: OPS-010 — which nodes are in maintenance now (from heartbeats, or this node's own
/// window when standalone), and the reads without them.
async fn paused_now(
    sources: &Arc<crate::http::Sources>,
    backend: &wrendns_api::Shared,
    federated: Option<&Arc<crate::federated::Federated>>,
) -> Arc<Paused> {
    let (b, fed, src) = (Arc::clone(backend), federated.cloned(), Arc::clone(sources));
    let paused = tokio::task::spawn_blocking(move || {
        let now = crate::maintenance::now_ms();
        let mut paused = Paused::new(
            &b.cluster(),
            src.maintenance
                .current(now)
                .map(|w| crate::maintenance::api_window(&w.cluster_window(), now, None)),
            &crate::maintenance::label(&src),
        );
        if let Some(fed) = fed.filter(|_| !paused.ids.is_empty()) {
            paused.without = Some(Arc::new(fed.excluding(&paused.ids)));
        }
        paused
    })
    .await
    .unwrap_or_default();
    Arc::new(paused)
}

/// The alert task: every `interval_secs`, evaluate (on the primary or a standalone node) and
/// send what started or cleared.
#[allow(clippy::too_many_lines)] // one loop: read, observe, step, deliver
pub(crate) async fn run(
    sources: Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let local: wrendns_api::Shared = Arc::new(crate::api_backend::ApiBackend {
        src: Arc::clone(&sources),
    });
    let federated = sources.cluster.as_ref().map(|c| {
        Arc::new(crate::federated::Federated::new(
            local.clone(),
            Arc::clone(c),
        ))
    });
    let backend: wrendns_api::Shared = match &federated {
        Some(f) => Arc::clone(f) as wrendns_api::Shared,
        None => local,
    };
    let client = match wrendns_filter::fetch::Client::new(
        Arc::new(wrendns_filter::fetch::SystemResolver),
        &[],
    ) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            warn!("alerts disabled: {e}");
            return;
        }
    };
    let mut engine = Engine::default();
    let mut rules_for: Option<Vec<AlertRule>> = None;
    loop {
        let cfg: Arc<Config> = sources.config.load_full();
        let interval = Duration::from_secs(u64::from(cfg.alerts.interval_secs.max(5)));
        let rules: Vec<AlertRule> = cfg
            .alerts
            .rule
            .iter()
            .filter(|r| r.enabled)
            .cloned()
            .collect();
        // New rules: start over (indexes changed).
        if rules_for.as_ref() != Some(&rules) {
            engine = Engine::default();
            rules_for = Some(rules.clone());
        }
        let primary = sources.cluster.as_ref().is_none_or(|c| c.is_primary());
        let paused = paused_now(&sources, &backend, federated.as_ref()).await;
        if primary && !rules.is_empty() {
            let now = crate::pipeline::unix_now();
            let b = Arc::clone(&backend);
            let rs = rules.clone();
            let in_maintenance = Arc::clone(&paused);
            let pending = pending_plans(&sources);
            let redirects = recent_redirects(&sources, now);
            let exports = recent_exports(&sources, now);
            let observed = tokio::task::spawn_blocking(move || {
                rs.iter()
                    .map(|r| {
                        observe(
                            b.as_ref(),
                            r,
                            now,
                            &pending,
                            &redirects,
                            &exports,
                            &in_maintenance,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap_or_default();
            let node = crate::http::node_name(&cfg);
            for n in engine.step_with(now, &rules, &observed, &paused) {
                let rule = &rules[n.rule];
                info!(rule = %rule.name, subject = %n.subject, firing = n.firing, "alert");
                for to in &rule.to {
                    let Some(d) = cfg
                        .alerts
                        .destination
                        .iter()
                        .find(|d| d.name == *to)
                        .cloned()
                    else {
                        continue;
                    };
                    // REQ: OBS-010 (T24.43) - a new device's message links to it in the UI,
                    // when this node knows its address (`[auth.oidc] public_url`).
                    let link =
                        new_device_link(rule.when, cfg.auth.oidc.public_url.as_str(), &n.subject);
                    let (client, rname, n, node, src) = (
                        Arc::clone(&client),
                        rule.name.to_string(),
                        n.clone(),
                        node.clone(),
                        Arc::clone(&sources),
                    );
                    tokio::spawn(async move {
                        let r = deliver(
                            &client,
                            &d,
                            &rname,
                            &n,
                            &node,
                            link.as_deref(),
                            &src.secrets,
                        )
                        .await;
                        if let Err(e) = &r {
                            warn!(destination = %d.name, error = %e, "alert not delivered");
                        }
                        record_delivery(&src, d.name.as_str(), &r);
                    });
                }
            }
        }
        publish_status(&sources, &engine, &rules, &cfg, primary, &paused);
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(interval) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: CLU-014 (owner 2026-10-19) — a drill report goes out once (a one-off, like a failed
    // rollout), saying scheduled or not, the counts, coverage, and missing nodes.
    #[test]
    fn clu_014_drill_report_alert() {
        assert!(one_off(AlertWhen::DrillReport));
        let d = wrendns_api::model::DrillSummary {
            node: "home-pi".into(),
            targets: "everyone".into(),
            by: "schedule".into(),
            followed: 9,
            stuck: 1,
            quiet: 4,
            coverage_percent: Some(90.0),
            missing_nodes: vec!["wrendns-resolver-x".into()],
            ..Default::default()
        };
        let t = drill_text(&d);
        assert!(t.starts_with("scheduled failover drill on home-pi (everyone): 9 followed, 1 stuck, 4 quiet; coverage 90 %"), "{t}");
        assert!(t.contains("no answer from wrendns-resolver-x"), "{t}");
        let mut e = Engine::default();
        let rules = [rule(AlertWhen::DrillReport, 0)];
        let seen = vec![vec![("d1".to_owned(), t.clone())]];
        assert_eq!(e.step(100, &rules, &seen).len(), 1);
        assert!(e.step(200, &rules, &seen).is_empty(), "once");
    }

    fn rule(when: AlertWhen, for_secs: u32) -> AlertRule {
        AlertRule {
            name: wrendns_config::SafeString::new("r").unwrap(),
            when,
            for_secs,
            threshold: None,
            to: Vec::new(),
            enabled: true,
        }
    }

    fn seen(subjects: &[&str]) -> Observed {
        subjects
            .iter()
            .map(|s| ((*s).to_owned(), format!("{s} is down")))
            .collect()
    }

    /// REQ: OBS-010 — an alert starts once a condition has held `for_secs`, once per subject,
    /// and clears when it stops; one-off conditions go out once each.
    #[test]
    fn obs_010_alerts_start_after_for_and_clear() {
        let rules = vec![
            rule(AlertWhen::UpstreamDown, 60),
            rule(AlertWhen::Anomaly, 0),
        ];
        let mut e = Engine::default();
        assert!(
            e.step(1000, &rules, &[seen(&["quad9"]), seen(&[])])
                .is_empty(),
            "not for 60 s yet"
        );
        assert!(
            e.step(1030, &rules, &[seen(&["quad9"]), seen(&[])])
                .is_empty(),
            "still not"
        );
        let n = e.step(1060, &rules, &[seen(&["quad9"]), seen(&["tv-burst"])]);
        assert_eq!(n.len(), 2);
        assert!(n.iter().all(|x| x.firing));
        assert!(
            e.step(1090, &rules, &[seen(&["quad9"]), seen(&["tv-burst"])])
                .is_empty(),
            "sent once"
        );
        let n = e.step(1120, &rules, &[seen(&[]), seen(&["tv-burst"])]);
        assert_eq!(
            n,
            vec![Notice {
                rule: 0,
                subject: "quad9".into(),
                summary: "quad9 is down".into(),
                firing: false
            }]
        );
        // A blip shorter than `for_secs` never alerts.
        assert!(
            e.step(1150, &rules, &[seen(&["cloudflare"]), seen(&[])])
                .is_empty(),
            "too soon"
        );
        assert!(
            e.step(1180, &rules, &[seen(&[]), seen(&[])]).is_empty(),
            "never fired"
        );
        assert!(
            e.step(1300, &rules, &[seen(&["cloudflare"]), seen(&[])])
                .is_empty(),
            "the timer restarted"
        );
    }

    /// REQ: OBS-036 — the `anomaly` rule leaves informational findings out; `chatty_loop`
    /// takes only those.
    #[test]
    fn obs_036_chatty_loops_alert_only_by_kind() {
        let finding = |kind: &str, informational: bool| wrendns_api::model::AnomalyFinding {
            id: kind.into(),
            kind: kind.into(),
            client: "10.20.2.14".into(),
            client_name: None,
            domain: Some("ntp.org".into()),
            window_start: "2026-10-17T03:00:00.000Z".into(),
            window_seconds: 3600,
            observed: 1440.0,
            baseline: 2.5,
            spread: 98.0,
            threshold: 120.0,
            detail: format!("{kind} detail"),
            nodes: Vec::new(),
            acknowledged: None,
            rhythm: None,
            informational,
            muted_by: None,
        };
        let b = Stub {
            view: wrendns_api::model::ClusterView {
                enabled: false,
                cluster_id: None,
                name: None,
                this_node: None,
                newest_config_seq: 0,
                healthy: true,
                checks: Vec::new(),
                nodes: Vec::new(),
                events: Vec::new(),
                authority: None,
                conflicts: Vec::new(),
                failover: None,
                source: None,
                host: None,
                rollout: None,
            },
            probes: Vec::new(),
            findings: vec![finding("beacon", false), finding("chatty_loop", true)],
        };
        let o = |w: AlertWhen| observe(&b, &rule(w, 0), 1000, &[], &[], &[], &Paused::default());
        let anomaly = o(AlertWhen::Anomaly);
        let chatty = o(AlertWhen::ChattyLoop);
        assert_eq!(anomaly.len(), 1, "{anomaly:?}");
        assert!(anomaly.iter().all(|(k, _)| k.starts_with("beacon|")));
        assert_eq!(chatty.len(), 1, "{chatty:?}");
        assert!(chatty.iter().all(|(k, _)| k.starts_with("chatty_loop|")));
    }

    /// REQ: OBS-010 (review 04-10) — past the cap, only the oldest one-off subjects are
    /// forgotten: one still being observed isn't sent again.
    #[test]
    fn obs_010_one_off_alerts_forget_only_the_oldest() {
        let rules = vec![rule(AlertWhen::Anomaly, 0)];
        let mut e = Engine::default();
        let all: Vec<String> = (0..=SENT_ONCE_CAP)
            .map(|i| format!("finding-{i}"))
            .collect();
        for chunk in all.chunks(500) {
            let names: Vec<&str> = chunk.iter().map(String::as_str).collect();
            assert_eq!(e.step(0, &rules, &[seen(&names)]).len(), chunk.len());
        }
        let newest = format!("finding-{SENT_ONCE_CAP}");
        assert!(
            e.step(1, &rules, &[seen(&[newest.as_str()])]).is_empty(),
            "still remembered"
        );
        assert_eq!(
            e.step(2, &rules, &[seen(&["finding-0"])]).len(),
            1,
            "the oldest was forgotten"
        );
    }

    /// A read model with a cluster view and probes, nothing else.
    struct Stub {
        view: wrendns_api::model::ClusterView,
        probes: Vec<wrendns_api::model::ProbeResult>,
        findings: Vec<wrendns_api::model::AnomalyFinding>,
    }

    impl Backend for Stub {
        fn system_info(&self) -> wrendns_api::model::SystemInfo {
            unreachable!("not read by these rules")
        }
        fn cluster(&self) -> wrendns_api::model::ClusterView {
            self.view.clone()
        }
        fn probes(&self) -> Vec<wrendns_api::model::ProbeResult> {
            self.probes.clone()
        }
        fn anomalies(&self, _: u64) -> Vec<wrendns_api::model::AnomalyFinding> {
            self.findings.clone()
        }
        fn timeseries(&self, _: Step, _: u64, _: u64) -> Vec<wrendns_api::model::TimeBucket> {
            Vec::new()
        }
        fn top(
            &self,
            _: wrendns_api::model::TopKind,
            _: wrendns_api::model::Hour,
            _: usize,
            _: Option<std::net::IpAddr>,
        ) -> Vec<wrendns_api::model::TopItem> {
            Vec::new()
        }
        fn latency(
            &self,
            _: wrendns_api::model::LatencyBy,
            _: wrendns_api::model::Hour,
        ) -> Vec<wrendns_api::model::LatencyRow> {
            Vec::new()
        }
        fn queries(
            &self,
            _: &wrendns_api::model::QueryParams,
            _: u64,
            _: u64,
            _: usize,
        ) -> Result<wrendns_api::model::QueryPage, wrendns_api::problem::Problem> {
            Err(wrendns_api::problem::Problem::unavailable("stub"))
        }
        fn explain(
            &self,
            _: &wrendns_api::model::ExplainParams,
        ) -> Result<wrendns_api::model::Explanation, wrendns_api::problem::Problem> {
            Err(wrendns_api::problem::Problem::unavailable("stub"))
        }
        fn lists(&self) -> Vec<wrendns_api::model::ListInfo> {
            Vec::new()
        }
        fn groups(&self) -> Vec<wrendns_api::model::GroupInfo> {
            Vec::new()
        }
        fn clients(&self) -> Vec<wrendns_api::model::ClientInfo> {
            Vec::new()
        }
        fn upstreams(&self) -> Vec<wrendns_api::model::UpstreamInfo> {
            Vec::new()
        }
    }

    // REQ: OBS-010 (T24.5, fork #2) — a replica that hasn't reached its primary for `threshold`
    // seconds (default 60) raises one alert after `for_secs`; the boundary is exact; witnesses,
    // resolver pods and nodes out of contact are left out; the alert clears on reconnect and
    // doesn't repeat while the silence goes on.
    #[test]
    #[allow(clippy::too_many_lines)] // one scenario, step by step
    fn obs_010_t24_5_primary_unreachable_alert() {
        use wrendns_api::model::{ClusterNode, ClusterView};
        let node = |id: &str, silent: Option<u64>| ClusterNode {
            node_id: id.into(),
            site: id.into(),
            role: "replica".into(),
            connected: true,
            up: true,
            primary_silent_seconds: silent,
            ..ClusterNode::default()
        };
        let mut primary = node("primary", None);
        primary.role = "primary".into();
        primary.this_node = true;
        let stub = |nodes: Vec<ClusterNode>| Stub {
            view: ClusterView {
                enabled: true,
                cluster_id: None,
                name: None,
                this_node: None,
                newest_config_seq: 0,
                healthy: true,
                checks: Vec::new(),
                nodes,
                events: Vec::new(),
                authority: None,
                conflicts: Vec::new(),
                failover: None,
                source: None,
                rollout: None,
                host: None,
            },
            probes: Vec::new(),
            findings: Vec::new(),
        };
        let mut witness = node("witness", Some(600));
        witness.witness = true;
        let mut pod = node("pod", Some(600));
        pod.ephemeral = true;
        let mut away = node("away", Some(600));
        away.up = false;
        let rule = AlertRule {
            threshold: None,
            ..rule(AlertWhen::PrimaryUnreachable, 30)
        };
        let seen = |nodes: Vec<ClusterNode>| {
            observe(&stub(nodes), &rule, 1000, &[], &[], &[], &Paused::default())
        };
        // One second short of the default 60 s: nothing. Exactly 60 s: raised.
        assert!(
            seen(vec![primary.clone(), node("r1", Some(59))]).is_empty(),
            "one second short"
        );
        let at = seen(vec![primary.clone(), node("r1", Some(60))]);
        assert_eq!(
            at.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>(),
            ["r1"]
        );
        assert!(
            at[0].1.contains("hasn't reached its primary for 60 s"),
            "{}",
            at[0].1
        );
        // Witnesses, resolver pods and nodes out of contact never raise it.
        assert!(
            seen(vec![primary.clone(), witness, pod, away]).is_empty(),
            "left out"
        );
        // The rule's threshold replaces the default.
        let tight = AlertRule {
            threshold: Some(15.0),
            ..rule.clone()
        };
        let tight_seen = observe(
            &stub(vec![primary.clone(), node("r1", Some(15))]),
            &tight,
            1000,
            &[],
            &[],
            &[],
            &Paused::default(),
        );
        assert_eq!(tight_seen.len(), 1);
        // Held for for_secs before it goes out, once; still silent later: no repeat; contact
        // again: it clears.
        let mut engine = Engine::default();
        let rules = vec![rule.clone()];
        let obs = |silent: Option<u64>| vec![seen(vec![primary.clone(), node("r1", silent)])];
        assert!(engine.step(0, &rules, &obs(Some(60))).is_empty(), "not yet");
        assert!(
            engine.step(29, &rules, &obs(Some(89))).is_empty(),
            "for_secs not yet"
        );
        let fired = engine.step(30, &rules, &obs(Some(90)));
        assert_eq!(fired.len(), 1);
        assert!(fired[0].firing);
        assert!(
            engine.step(60, &rules, &obs(Some(120))).is_empty(),
            "no repeat"
        );
        let cleared = engine.step(65, &rules, &obs(None));
        assert_eq!(cleared.len(), 1);
        assert!(!cleared[0].firing, "reconnected: the alert clears");
    }

    /// REQ: OPS-010 (ADR-118) — a node in maintenance raises no `node_down` or probe alert;
    /// one that was firing resolves with "(maintenance)"; the `maintenance` rule fires while
    /// it lasts; after the window, `for_secs` counts from zero again.
    #[test]
    #[allow(clippy::too_many_lines)] // one scenario, step by step
    fn ops_010_alerts_skip_nodes_in_maintenance() {
        use wrendns_api::model::{ClusterNode, ClusterView, NodeMaintenance, ProbeResult};
        let node = |id: &str, connected: bool| ClusterNode {
            node_id: id.into(),
            site: id.into(),
            connected,
            up: connected,
            ..ClusterNode::default()
        };
        let mut me = node("pi", true);
        me.this_node = true;
        let view = |maint: bool| {
            let mut away = node("pi2", false);
            if maint {
                away.maintenance = Some(NodeMaintenance {
                    until: "2026-10-09T14:00:00Z".into(),
                    reason: "SD card swap".into(),
                    by: "alice".into(),
                    seconds_left: 1800,
                    ..NodeMaintenance::default()
                });
            }
            ClusterView {
                enabled: true,
                cluster_id: None,
                name: None,
                this_node: None,
                newest_config_seq: 0,
                healthy: true,
                checks: Vec::new(),
                nodes: vec![me.clone(), away, node("k3s", false)],
                events: Vec::new(),
                authority: None,
                conflicts: Vec::new(),
                failover: None,
                source: None,
                rollout: None,
                host: None,
            }
        };
        let probe = |who: &str| ProbeResult {
            node: Some(who.into()),
            target: "udp://127.0.0.1:53".into(),
            listener: true,
            consecutive_failures: 3,
            ..ProbeResult::default()
        };
        let stub = |maint: bool| Stub {
            view: view(maint),
            probes: vec![probe("pi2"), probe("k3s")],
            findings: Vec::new(),
        };
        let rules = vec![
            rule(AlertWhen::NodeDown, 60),
            rule(AlertWhen::ProbeFailing, 0),
            rule(AlertWhen::Maintenance, 0),
        ];
        let seen = |backend: &Stub, paused: &Paused| -> Vec<Observed> {
            rules
                .iter()
                .map(|r| observe(backend, r, 1000, &[], &[], &[], paused))
                .collect()
        };
        let subjects = |o: &Observed| o.iter().map(|(x, _)| x.clone()).collect::<Vec<_>>();
        // Before maintenance: both nodes are down and failing their probes.
        let before = stub(false);
        let quiet = Paused::new(&before.view, None, "pi");
        let observed = seen(&before, &quiet);
        assert_eq!(subjects(&observed[0]), ["pi2", "k3s"]);
        assert_eq!(
            subjects(&observed[1]),
            ["pi2|udp://127.0.0.1:53", "k3s|udp://127.0.0.1:53"]
        );
        assert_eq!(observed[2], Observed::new());
        let mut engine = Engine::default();
        engine.step_with(0, &rules, &observed, &quiet);
        assert_eq!(
            engine.step_with(60, &rules, &observed, &quiet).len(),
            2,
            "both node_down alerts fire"
        );
        // pi2 enters maintenance.
        let during = stub(true);
        let paused = Paused::new(&during.view, None, "pi");
        let observed = seen(&during, &paused);
        assert_eq!(subjects(&observed[0]), ["k3s"]);
        assert_eq!(subjects(&observed[1]), ["k3s|udp://127.0.0.1:53"]);
        assert_eq!(subjects(&observed[2]), ["pi2"]);
        assert!(
            observed[2][0].1.contains("SD card swap"),
            "{}",
            observed[2][0].1
        );
        let notices = engine.step_with(90, &rules, &observed, &paused);
        let resolved: Vec<&Notice> = notices.iter().filter(|x| !x.firing).collect();
        assert_eq!(
            resolved.len(),
            2,
            "node_down and the probe, both pi2's: {resolved:?}"
        );
        assert!(
            resolved
                .iter()
                .all(|x| x.subject.starts_with("pi2") && x.summary.ends_with("(maintenance)")),
            "{resolved:?}"
        );
        assert!(
            notices
                .iter()
                .any(|x| x.firing && x.rule == 2 && x.subject == "pi2")
        );
        // Maintenance ends with pi2 still down: node_down counts its 60 s from now.
        let after = stub(false);
        let observed = seen(&after, &quiet);
        let notices = engine.step_with(120, &rules, &observed, &quiet);
        assert!(
            notices.iter().any(|x| !x.firing && x.rule == 2),
            "the maintenance alert resolves"
        );
        assert!(
            !notices.iter().any(|x| x.firing && x.rule == 0),
            "not before for_secs"
        );
        let notices = engine.step_with(180, &rules, &observed, &quiet);
        assert!(
            notices
                .iter()
                .any(|x| x.firing && x.rule == 0 && x.subject == "pi2")
        );
    }

    /// REQ: OBS-010 — destination formats.
    #[test]
    fn obs_010_destination_formats() {
        let d = |kind| AlertDestination {
            name: wrendns_config::SafeString::new("d").unwrap(),
            kind,
            url: wrendns_config::SafeString::new("https://example.test/x").unwrap(),
            token_file: None,
            token_ref: None,
            from: None,
            to: Vec::new(),
            username: None,
            password_file: None,
            password_ref: None,
            tls_ca: None,
            user_key_file: None,
            user_key_ref: None,
            device: None,
            priority_firing: None,
            priority_resolved: None,
            sound: None,
        };
        let n = Notice {
            rule: 0,
            subject: "quad9".into(),
            summary: "quad9 is down".into(),
            firing: true,
        };
        let (body, ct, _) = render(&d(AlertKind::Webhook), None, "upstreams", &n, "pi");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            (v["status"].as_str(), v["subject"].as_str(), ct),
            (Some("firing"), Some("quad9"), "application/json")
        );
        let (body, ct, h) = render(&d(AlertKind::Ntfy), Some("tk"), "upstreams", &n, "pi");
        assert_eq!((body.as_str(), ct), ("quad9 is down", "text/plain"));
        assert!(h.contains(&("Title".into(), "upstreams: quad9".into())));
        assert!(h.contains(&("Authorization".into(), "Bearer tk".into())));
        let (body, _, _) = render(
            &d(AlertKind::Slack),
            None,
            "upstreams",
            &Notice { firing: false, ..n },
            "pi",
        );
        assert!(body.contains("Resolved: upstreams: quad9"), "{body}");
    }

    fn pushover(url: &str) -> AlertDestination {
        toml::from_str(&format!(
            "name = \"phone\"\ntype = \"pushover\"\nurl = \"{url}\"\n"
        ))
        .unwrap()
    }

    fn form_pairs(body: &str) -> HashMap<String, String> {
        body.split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| {
                let mut out = Vec::new();
                let b = v.as_bytes();
                let mut i = 0;
                while i < b.len() {
                    if b[i] == b'%' {
                        out.push(u8::from_str_radix(&v[i + 1..i + 3], 16).unwrap());
                        i += 3;
                    } else {
                        out.push(b[i]);
                        i += 1;
                    }
                }
                (k.to_owned(), String::from_utf8(out).unwrap())
            })
            .collect()
    }

    /// REQ: OBS-010 (T24.43) - the form: the fields Pushover wants, encoded, with the node and
    /// time in the message, the link only when known, and the device and sound only when set.
    #[test]
    fn obs_010_pushover_form_encoding() {
        let mut d = pushover("https://api.pushover.net/1/messages.json");
        let n = Notice {
            rule: 0,
            subject: "10.0.0.7".into(),
            summary: "a new device started using DNS: tv & co (10.0.0.7)".into(),
            firing: true,
        };
        let body = pushover_form(
            &d,
            "tok&1",
            "usr key",
            "new devices",
            &n,
            "node-a",
            None,
            1_700_000_000,
        );
        assert!(body.contains("token=tok%261&user=usr%20key&"), "{body}");
        let f = form_pairs(&body);
        assert_eq!(f["title"], "new devices: 10.0.0.7");
        assert!(
            f["message"].starts_with(
                "a new device started using DNS: tv & co (10.0.0.7)\nNode: node-a\nTime: 2023-11-14 22:13:20 UTC"
            ),
            "{}",
            f["message"]
        );
        assert_eq!(
            (f["priority"].as_str(), f["timestamp"].as_str()),
            ("0", "1700000000")
        );
        assert!(!f.contains_key("url") && !f.contains_key("device") && !f.contains_key("sound"));
        d.device = wrendns_config::SafeString::new("phone").ok();
        d.sound = wrendns_config::SafeString::new("siren").ok();
        let body = pushover_form(
            &d,
            "t",
            "u",
            "r",
            &n,
            "pi",
            Some("https://w.lan/#/clients?device=10.0.0.7"),
            1,
        );
        let f = form_pairs(&body);
        assert_eq!(
            (f["device"].as_str(), f["sound"].as_str(), f["url"].as_str()),
            ("phone", "siren", "https://w.lan/#/clients?device=10.0.0.7")
        );
        let r = pushover_form(
            &d,
            "t",
            "u",
            "r",
            &Notice { firing: false, ..n },
            "pi",
            None,
            1,
        );
        let f = form_pairs(&r);
        assert_eq!(f["title"], "Resolved: r: 10.0.0.7");
        assert!(f["message"].starts_with("Cleared: "), "{}", f["message"]);
    }

    /// REQ: OBS-010 (T24.43) - Pushover's limits: a title of 250, a message of 1024, a link of
    /// 512 characters; a cut ends in an ellipsis and keeps the node and time.
    #[test]
    fn obs_010_pushover_truncation() {
        assert_eq!(truncate_chars("abc", 3), "abc");
        assert_eq!(truncate_chars("abcd", 3), "ab…");
        assert_eq!(truncate_chars("ééééé", 4), "ééé…");
        let d = pushover("https://api.pushover.net/1/messages.json");
        let n = Notice {
            rule: 0,
            subject: "s".repeat(400),
            summary: "x".repeat(5000),
            firing: true,
        };
        let long_link = format!("https://w.lan/{}", "a".repeat(600));
        let f = form_pairs(&pushover_form(
            &d,
            "t",
            "u",
            "rule",
            &n,
            "node-a",
            Some(&long_link),
            1,
        ));
        assert_eq!(f["title"].chars().count(), 250);
        assert!(f["title"].ends_with('…'));
        assert_eq!(f["message"].chars().count(), 1024);
        assert!(
            f["message"].contains("…\nNode: node-a\nTime: 1970-01-01 00:00:01 UTC"),
            "{}",
            f["message"]
        );
        assert!(
            !f.contains_key("url"),
            "a link over 512 characters is left out"
        );
    }

    /// REQ: OBS-010 (T24.43) - firing 0 and resolved -1 by default, the destination's choice
    /// within -2..=1, and never 2 (emergency).
    #[test]
    fn obs_010_pushover_priority_mapping() {
        let mut d = pushover("https://api.pushover.net/1/messages.json");
        assert_eq!(
            (pushover_priority(&d, true), pushover_priority(&d, false)),
            (0, -1)
        );
        d.priority_firing = Some(1);
        d.priority_resolved = Some(-2);
        assert_eq!(
            (pushover_priority(&d, true), pushover_priority(&d, false)),
            (1, -2)
        );
        d.priority_firing = Some(2);
        assert_eq!(pushover_priority(&d, true), 1);
    }

    /// REQ: OBS-010 (T24.43) - a 4xx with `{"status":0,"errors":[...]}` is a failed delivery that
    /// shows the errors, never the token or the key; a 2xx with status 1 is delivered.
    #[test]
    fn obs_010_pushover_error_parsing() {
        assert_eq!(
            pushover_outcome(200, br#"{"status":1,"request":"r"}"#, &["t"]),
            Ok(())
        );
        assert_eq!(pushover_outcome(200, b"", &[]), Ok(()));
        let e = pushover_outcome(
            400,
            br#"{"user":"invalid","errors":["user identifier is invalid","token SECRET-T is bad"],"status":0,"request":"r"}"#,
            &["SECRET-T", "SECRET-U", ""],
        )
        .unwrap_err();
        assert_eq!(
            e,
            "HTTP 400: user identifier is invalid; token <redacted> is bad"
        );
        assert!(pushover_outcome(200, br#"{"status":0,"errors":["x"]}"#, &[]).is_err());
        assert_eq!(
            pushover_outcome(503, b"<html>", &[]).unwrap_err(),
            "HTTP 503"
        );
        let long = format!(r#"{{"status":0,"errors":["{}"]}}"#, "e".repeat(900));
        assert_eq!(
            pushover_outcome(400, long.as_bytes(), &[])
                .unwrap_err()
                .chars()
                .count(),
            300
        );
    }

    /// A fake Pushover: answers each request with the next `(status, body)` and keeps the
    /// content types and request bodies it saw.
    async fn fake_pushover(
        answers: Vec<(u16, &'static str)>,
    ) -> (String, Arc<std::sync::Mutex<Vec<(String, String)>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/1/messages.json", l.local_addr().unwrap());
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let keep = Arc::clone(&seen);
        tokio::spawn(async move {
            for (status, reply) in answers {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head_end, len) = loop {
                    let n = s.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break (0, 0);
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                        let len = head
                            .lines()
                            .find_map(|x| x.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (i + 4, len);
                    }
                };
                while buf.len() < head_end + len {
                    let n = s.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
                let ct = head
                    .lines()
                    .find_map(|x| x.strip_prefix("content-type:"))
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                let body = String::from_utf8_lossy(&buf[head_end..]).into_owned();
                keep.lock().unwrap().push((ct, body));
                let r = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = s.write_all(r.as_bytes()).await;
                let _ = s.shutdown().await;
            }
        });
        (url, seen)
    }

    /// REQ: OBS-010 (T24.43) - against a local fake Pushover: a firing alert and a resolved one
    /// are posted as a form with both secrets from their files, a 400 is a failed delivery that
    /// shows Pushover's errors but no secret, and a destination missing a secret says which.
    #[tokio::test]
    async fn obs_010_pushover_delivery_against_a_fake_server() {
        let (url, seen) = fake_pushover(vec![
            (200, r#"{"status":1,"request":"a"}"#),
            (200, r#"{"status":1,"request":"b"}"#),
            (
                400,
                r#"{"user":"invalid","errors":["user identifier is invalid"],"status":0,"request":"c"}"#,
            ),
        ])
        .await;
        let dir = tempfile::tempdir().unwrap();
        let tf = dir.path().join("app-token");
        let uf = dir.path().join("user-key");
        std::fs::write(&tf, "APPTOKEN123\n").unwrap();
        std::fs::write(&uf, "USERKEY456\n").unwrap();
        let mut cfg = Config::default();
        cfg.node.data_dir = wrendns_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
        let store = crate::secrets::SecretStore::new(&cfg);
        let mut d = pushover(&url);
        d.token_file = wrendns_config::SafeString::new(tf.to_str().unwrap()).ok();
        d.user_key_file = wrendns_config::SafeString::new(uf.to_str().unwrap()).ok();
        let client = wrendns_filter::fetch::Client::new(
            Arc::new(wrendns_filter::fetch::SystemResolver),
            &[],
        )
        .unwrap();
        let n = Notice {
            rule: 0,
            subject: "10.0.0.7".into(),
            summary: "a new device started using DNS: 10.0.0.7".into(),
            firing: true,
        };
        let link = new_device_link(AlertWhen::NewDevice, "https://w.lan/", "10.0.0.7");
        assert_eq!(
            link.as_deref(),
            Some("https://w.lan/#/clients?device=10.0.0.7")
        );
        assert_eq!(new_device_link(AlertWhen::NewDevice, "", "10.0.0.7"), None);
        assert_eq!(
            new_device_link(AlertWhen::Anomaly, "https://w.lan", "10.0.0.7"),
            None
        );
        deliver(
            &client,
            &d,
            "new devices",
            &n,
            "node-a",
            link.as_deref(),
            &store,
        )
        .await
        .unwrap();
        let cleared = Notice {
            firing: false,
            ..n.clone()
        };
        deliver(&client, &d, "new devices", &cleared, "node-a", None, &store)
            .await
            .unwrap();
        let e = deliver(&client, &d, "new devices", &n, "node-a", None, &store)
            .await
            .unwrap_err();
        assert_eq!(e, "HTTP 400: user identifier is invalid");
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 3);
        assert!(
            seen.iter()
                .all(|(ct, _)| ct == "application/x-www-form-urlencoded")
        );
        let fire = form_pairs(&seen[0].1);
        assert_eq!(
            (
                fire["token"].as_str(),
                fire["user"].as_str(),
                fire["priority"].as_str()
            ),
            ("APPTOKEN123", "USERKEY456", "0")
        );
        assert_eq!(fire["title"], "new devices: 10.0.0.7");
        assert_eq!(fire["url"], "https://w.lan/#/clients?device=10.0.0.7");
        assert!(
            fire["message"].contains("\nNode: node-a\nTime: "),
            "{}",
            fire["message"]
        );
        let back = form_pairs(&seen[1].1);
        assert_eq!(
            (back["priority"].as_str(), back["title"].as_str()),
            ("-1", "Resolved: new devices: 10.0.0.7")
        );
        assert!(!back.contains_key("url"));
        // A secret that is missing is said, and nothing is sent.
        d.user_key_file = None;
        let e = deliver(&client, &d, "r", &n, "pi", None, &store)
            .await
            .unwrap_err();
        assert!(e.contains("user or group key"), "{e}");
    }

    /// REQ: CLU-013 — `rollout_failed` goes out once per failed version; `cluster_pinned` fires
    /// while pinned (after its `for_secs`) and resolves when unpinned.
    #[test]
    fn clu_013_rollout_failed_and_cluster_pinned() {
        use wrendns_api::model::{ClusterPin, ClusterRollout, ClusterView, RolloutFailure};
        let view = |r: Option<ClusterRollout>| ClusterView {
            enabled: true,
            cluster_id: None,
            name: None,
            this_node: None,
            newest_config_seq: 0,
            healthy: true,
            checks: Vec::new(),
            nodes: Vec::new(),
            events: Vec::new(),
            authority: None,
            conflicts: Vec::new(),
            failover: None,
            source: None,
            rollout: r,
            host: None,
        };
        let pinned = |failed: &str| ClusterRollout {
            stage: "pinned".into(),
            pinned: Some(ClusterPin {
                to: "1.6".into(),
                since: "2026-10-10T12:00:00Z".into(),
                by: "the guard".into(),
                reason: "SERVFAIL 28%".into(),
                ..ClusterPin::default()
            }),
            last_failure: Some(RolloutFailure {
                version: failed.into(),
                reason: "SERVFAIL 28%".into(),
                at: "2026-10-10T12:00:00Z".into(),
            }),
            ..ClusterRollout::default()
        };
        let rules = vec![
            rule(AlertWhen::RolloutFailed, 0),
            rule(AlertWhen::ClusterPinned, 60),
        ];
        let seen = |r: Option<ClusterRollout>| -> Vec<Observed> {
            let b = Stub {
                view: view(r),
                probes: Vec::new(),
                findings: Vec::new(),
            };
            rules
                .iter()
                .map(|x| observe(&b, x, 1000, &[], &[], &[], &Paused::default()))
                .collect()
        };
        let mut e = Engine::default();
        let first = e.step(0, &rules, &seen(Some(pinned("1.7"))));
        assert_eq!(first.len(), 1, "{first:?}");
        assert!(
            first[0].summary.contains("version 1.7") && first[0].summary.contains("SERVFAIL 28%")
        );
        // Still pinned a minute later: the pin alert fires; the failure isn't sent again.
        let later = e.step(60, &rules, &seen(Some(pinned("1.7"))));
        assert_eq!(later.len(), 1, "{later:?}");
        assert_eq!(
            (later[0].rule, later[0].subject.as_str(), later[0].firing),
            (1, "cluster", true)
        );
        assert!(later[0].summary.contains("pinned to version 1.6"));
        // Unpinned: the pin alert resolves. A later failure of another version goes out.
        let cleared = e.step(120, &rules, &seen(None));
        assert_eq!(cleared.len(), 1);
        assert!(!cleared[0].firing);
        let again = e.step(180, &rules, &seen(Some(pinned("1.9"))));
        assert!(
            again.iter().any(|n| n.rule == 0 && n.subject == "1.9"),
            "{again:?}"
        );
    }
}

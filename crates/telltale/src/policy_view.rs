//! REQ: FLT-006, API-010, AGT-001 (T24.30, ADR-996) — a device's effective policy.
//!
//! The device is identified by [`crate::explain::resolve_identity`], which is the call Explain
//! makes (`ClientTable::identify`), and the settings are read from the group's compiled policy
//! (`ClientTable::primary_group`, the filter's list mask, the quick rules, the schedules and the
//! router the pipeline holds), so the panel and Explain cannot disagree about which group a device
//! is in. Nothing here runs on the query path: it is an API read that allocates freely.
//!
//! Sections are appended to a list the UI draws in order ([`telltale_api::policy_api`]); a later
//! feature adds a section here and nothing else changes (ADR-996, section 4).

use std::collections::BTreeMap;
use std::net::IpAddr;

use telltale_api::policy_api::{
    ClientPolicy, PRECEDENCE, PolicyItem, PolicyLink, PolicyRung, PolicySection,
};
use telltale_config::{Config, ScheduleAction, YoutubeRestrict};
use telltale_policy::{IdSource, RewriteTarget, RuleScope};
use telltale_proto::{NameBuf, build_query, class, parse_query};
use telltale_upstream::Question;

use crate::explain::{Resolved, State, mac_text, resolve_identity, source_name};

/// Who the policy is for.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct Subject {
    /// What was asked for (a name, an address, a workload).
    pub(crate) asked: String,
    /// The address identification runs on.
    pub(crate) ip: IpAddr,
    pub(crate) mac: Option<[u8; 6]>,
    pub(crate) client_id: Option<String>,
    /// The configured device asked for by name, to say when another one wins.
    pub(crate) wanted_device: Option<String>,
    /// The address is a stand-in (the device has no address yet).
    pub(crate) stand_in: bool,
    /// Another node's observations are being applied: this node's own neighbor table says
    /// nothing about the device (an observed absence of a MAC stays absent).
    #[serde(default)]
    pub(crate) observed: bool,
}

#[allow(clippy::unnecessary_wraps)] // the `link` fields are `Option`s: call sites pass it on
fn link(path: &str, key: &str, value: &str) -> Option<PolicyLink> {
    let mut params = BTreeMap::new();
    params.insert(key.to_owned(), value.to_owned());
    Some(PolicyLink {
        path: path.to_owned(),
        params,
    })
}

#[allow(clippy::unnecessary_wraps)] // as `link`
fn plain_link(path: &str) -> Option<PolicyLink> {
    Some(PolicyLink {
        path: path.to_owned(),
        params: BTreeMap::new(),
    })
}

fn item(label: impl Into<String>) -> PolicyItem {
    PolicyItem {
        label: label.into(),
        ..PolicyItem::default()
    }
}

/// `mon`, `weekdays`, ... as the windows list them, with their times.
fn window_text(s: &telltale_config::ScheduleConfig) -> String {
    let mut parts: Vec<String> = s
        .window
        .iter()
        .map(|w| {
            let days: Vec<&str> = w
                .days
                .iter()
                .map(telltale_config::SafeString::as_str)
                .collect();
            format!("{} {}-{}", days.join(", "), w.start, w.end)
        })
        .collect();
    if let Some(tz) = &s.tz {
        parts.push(format!("({tz})"));
    }
    parts.join("; ")
}

fn action_text(a: ScheduleAction) -> &'static str {
    match a {
        ScheduleAction::BlockAll => "blocks every name",
        ScheduleAction::EnableLists => "adds lists",
        ScheduleAction::BlockServices => "blocks services",
    }
}

/// The upstream group a query with no `[[route]]` of its own goes to for these client groups: the
/// router's own `select`, on a name no route names (the pipeline's call, and Explain's).
fn default_upstream(st: &State<'_>, groups: &[Box<str>]) -> Option<(String, bool)> {
    let name = NameBuf::from_presentation("policy-probe.invalid").ok()?;
    let mut buf = [0u8; 512];
    let len = build_query(&mut buf, 0, &name, 1, class::IN, true, None).ok()?;
    let q = parse_query(&buf[..len]).ok()?;
    st.dynamic
        .router
        .select(&Question::from_query(&q), groups)
        .map(|s| (s.group.name.clone(), s.routed))
}

/// The policy of `subject` at `now` (Unix seconds), as `st` and `cfg` hold it.
// REQ: FLT-006, API-010 (T24.30)
#[allow(clippy::too_many_lines)] // one section after another, in the order the panel draws them
pub(crate) fn build(st: &State<'_>, cfg: &Config, subject: &Subject, now: u64) -> ClientPolicy {
    let policy = &st.dynamic.policy;
    // The filter's table is the one its masks were built for (as in Explain).
    let clients = st.filter.map_or(&policy.clients, |f| &f.clients);
    let no_neighbors = telltale_policy::Neighbors::default();
    let Resolved {
        ident,
        key: matched,
        mac,
    } = resolve_identity(
        clients,
        if subject.observed {
            &no_neighbors
        } else {
            st.neighbors
        },
        st.workloads,
        subject.ip,
        subject.client_id.as_deref(),
        subject.mac,
    );
    let workload = (ident.source == IdSource::Workload)
        .then(|| st.workloads.load())
        .and_then(|t| t.get(subject.ip).map(|h| h.workload.text.to_string()));
    let device = clients
        .client(ident)
        .map(|c| c.name.to_string())
        .or_else(|| workload.clone());
    let group = clients.primary_group(ident);
    let group_ids = clients.group_ids(ident);
    let group_names: Vec<String> = clients
        .group_names(ident)
        .iter()
        .map(ToString::to_string)
        .collect();
    let identified_by = source_name(ident.source);
    let mut notes = Vec::new();
    if subject.stand_in {
        notes.push(
            "This device has no single address (it is matched by a MAC, a client ID or a network range), so its network is unknown: the group it gets depends on the address a member is seen at."
                .to_owned(),
        );
    }
    match (&subject.wanted_device, &device) {
        (Some(want), Some(got)) if !want.eq_ignore_ascii_case(got) => notes.push(format!(
            "A query with this device's keys is recognized as {got}, which ranks higher; that device's policy is shown."
        )),
        (Some(want), None) if subject.stand_in && subject.client_id.is_none() && subject.mac.is_none() => {
            notes.push(format!(
                "A query from a member address of {want}'s network is not recognized as {want}: a group network takes it first, so that network's policy is shown."
            ));
        }
        (Some(want), None) => notes.push(format!(
            "A query with {want}'s keys is not recognized as {want} (another rung, such as its network, takes it first), so the default or network policy is shown."
        )),
        _ => {}
    }
    if st.pause.is_paused(&group.name, || now) {
        notes.push(format!(
            "Blocking is paused for group {}; its lists and schedules don't block until it resumes.",
            group.name
        ));
    }
    let group_link = |g: &str| link("/groups", "group", g);

    let mut sections: Vec<PolicySection> = Vec::new();

    // Block response (the first group's).
    sections.push(PolicySection {
        id: "block".into(),
        title: "Block response".into(),
        summary: format!(
            "A blocked name is answered {} (TTL {} s, EDE {}).",
            crate::explain::block_answer_text(group.block.mode),
            group.block.ttl,
            group.block.ede_code
        ),
        items: vec![PolicyItem {
            label: format!("{:?}", group.block.mode).to_ascii_lowercase(),
            detail: Some(format!(
                "TTL {} s, EDE {}",
                group.block.ttl, group.block.ede_code
            )),
            from: Some(format!("group {}", group.name)),
            link: group_link(&group.name),
            ..PolicyItem::default()
        }],
        link: group_link(&group.name),
    });

    // Lists: what the filter enforces for this device (the same mask a query is checked against).
    let mut lists = Vec::new();
    let mut categories: Vec<PolicyItem> = Vec::new();
    // REQ: FLT-006 — services a schedule turns on now are blocked services too.
    let mut scheduled_services: Vec<PolicyItem> = Vec::new();
    if let Some(f) = st.filter {
        if let Some(snap) = f.matcher.snapshot() {
            let mask = f.mask(ident);
            for (i, l) in snap.manifest.lists.iter().enumerate() {
                let Ok(id) = u16::try_from(i) else { break };
                if !mask.contains(id) {
                    continue;
                }
                let scheduled = group_ids.iter().any(|g| {
                    st.schedules
                        .extras
                        .get(usize::from(*g))
                        .is_some_and(|e| e.contains(&l.name))
                });
                if let Some(svc) = telltale_config::services::of_list(&l.name) {
                    if scheduled {
                        scheduled_services.push(PolicyItem {
                            label: svc.name.clone(),
                            detail: Some(svc.category.clone()),
                            state: Some("in_effect".into()),
                            from: Some("a schedule that is on now".to_owned()),
                            link: plain_link("/groups"),
                            ..PolicyItem::default()
                        });
                    }
                    continue;
                }
                // REQ: FLT-901 — a category list is shown in the Categories section, by the
                // category it stands for.
                if let Some(label) = telltale_config::categories::label_of_list(&l.name) {
                    categories.push(PolicyItem {
                        label,
                        detail: Some(format!("list {}", l.name)),
                        state: Some("on".into()),
                        from: Some(format!("group {} ({})", group.name, group.content_summary)),
                        link: link("/lists", "list", &l.name),
                        ..PolicyItem::default()
                    });
                    continue;
                }
                lists.push(PolicyItem {
                    label: l.name.clone(),
                    state: Some(if scheduled { "in_effect" } else { "on" }.into()),
                    from: Some(if scheduled {
                        "a schedule that is on now".to_owned()
                    } else if group.lists.is_none() {
                        "every enabled list".to_owned()
                    } else {
                        format!("group {}", group.name)
                    }),
                    link: link("/lists", "list", &l.name),
                    ..PolicyItem::default()
                });
            }
        }
    } else {
        notes.push("No filter snapshot is loaded yet, so no list is enforced.".to_owned());
        for n in group.lists.iter().flatten() {
            lists.push(PolicyItem {
                label: n.to_string(),
                state: Some("on".into()),
                from: Some(format!("group {}", group.name)),
                link: link("/lists", "list", n),
                ..PolicyItem::default()
            });
        }
    }
    // Shadow lists are counted, never enforced (OBS-018): say which ones this device would meet.
    for n in &policy.shadow_lists {
        if let Some(label) = telltale_config::categories::label_of_list(n) {
            if group.cat_lists.iter().any(|x| **x == **n) {
                categories.push(PolicyItem {
                    label,
                    detail: Some(format!("list {n}: counted, never enforced")),
                    state: Some("shadow".into()),
                    from: Some(format!("group {}", group.name)),
                    link: link("/lists", "list", n),
                    ..PolicyItem::default()
                });
            }
            continue;
        }
        let uses = group
            .lists
            .as_ref()
            .is_none_or(|l| l.iter().any(|x| **x == **n));
        if uses {
            lists.push(PolicyItem {
                label: n.to_string(),
                state: Some("shadow".into()),
                detail: Some("counted, never enforced".into()),
                from: Some(format!("group {}", group.name)),
                link: link("/lists", "list", n),
                ..PolicyItem::default()
            });
        }
    }
    sections.push(PolicySection {
        id: "lists".into(),
        title: "Lists".into(),
        summary: if group.lists.is_none() {
            format!("Group {} uses every enabled list.", group.name)
        } else {
            format!("Group {} names the lists below.", group.name)
        },
        items: lists,
        link: plain_link("/lists"),
    });
    // REQ: FLT-901, FLT-902 (T24.29, ADR-996 section 4) — the group's content categories: the
    // extension point the policy panel was built with.
    sections.push(PolicySection {
        id: "categories".into(),
        title: "Categories".into(),
        summary: if categories.is_empty() {
            format!(
                "Group {} blocks no content category ({}).",
                group.name, group.content_summary
            )
        } else {
            format!(
                "Group {} filters by category: {}.",
                group.name, group.content_summary
            )
        },
        items: categories,
        link: group_link(&group.name),
    });

    // Blocked services, from every group the device is in.
    let mut services = Vec::new();
    for &g in group_ids {
        let Some(gr) = clients.groups().get(usize::from(g)) else {
            continue;
        };
        for id in &gr.services {
            let svc = telltale_config::services::find(id);
            services.push(PolicyItem {
                label: svc.map_or_else(|| id.to_string(), |s| s.name.clone()),
                detail: svc.map(|s| s.category.clone()),
                state: Some("on".into()),
                from: Some(format!("group {}", gr.name)),
                link: group_link(&gr.name),
                ..PolicyItem::default()
            });
        }
    }
    services.extend(scheduled_services);
    sections.push(PolicySection {
        id: "services".into(),
        title: "Blocked services".into(),
        summary: if services.is_empty() {
            "No service is blocked for this device.".into()
        } else {
            format!("{} services are blocked.", services.len())
        },
        items: services,
        link: plain_link("/groups"),
    });

    // SafeSearch and YouTube (the first group's).
    let youtube = |y: YoutubeRestrict| match y {
        YoutubeRestrict::Strict => "strict",
        YoutubeRestrict::Moderate => "moderate",
        YoutubeRestrict::Off => "left alone",
    };
    let mut ss = item("SafeSearch");
    ss.state = Some(
        if group.safe_search.is_some() {
            "on"
        } else {
            "off"
        }
        .into(),
    );
    ss.from = Some(format!("group {}", group.name));
    ss.link = group_link(&group.name);
    let mut items = vec![ss];
    if let Some(y) = group.safe_search {
        let mut yt = item("YouTube restricted mode");
        yt.detail = Some(youtube(y).to_owned());
        yt.state = Some(
            if y == YoutubeRestrict::Off {
                "off"
            } else {
                "on"
            }
            .into(),
        );
        yt.from = Some(format!("group {}", group.name));
        yt.link = group_link(&group.name);
        items.push(yt);
    }
    sections.push(PolicySection {
        id: "safe_search".into(),
        title: "SafeSearch and YouTube".into(),
        summary: if group.safe_search.is_some() {
            "Search engines are answered with their safe versions.".into()
        } else {
            "Search engines are not restricted.".into()
        },
        items,
        link: group_link(&group.name),
    });

    // Answer filtering: rebinding, answer addresses, IPv6.
    let mut answers = Vec::new();
    if let Some(a) = &group.answers {
        if a.private {
            let mut i = item("Rebinding protection");
            i.detail = Some("public names can't answer private addresses".into());
            i.state = Some("on".into());
            i.from = Some(format!("group {}", group.name));
            i.link = group_link(&group.name);
            answers.push(i);
        }
        for d in &a.deny {
            let mut i = item(format!("Refuse answers in {d}"));
            i.state = Some("on".into());
            i.from = Some(format!("group {}", group.name));
            i.link = group_link(&group.name);
            answers.push(i);
        }
    }
    if group.filter_aaaa {
        let mut i = item("No IPv6 addresses");
        i.state = Some("on".into());
        i.from = Some(format!("group {}", group.name));
        i.link = group_link(&group.name);
        answers.push(i);
    }
    if let Some(p) = group.dns64 {
        let mut i = item("DNS64");
        i.detail = Some(format!("prefix {p}"));
        i.state = Some("on".into());
        i.from = Some(format!("group {}", group.name));
        i.link = group_link(&group.name);
        answers.push(i);
    }
    sections.push(PolicySection {
        id: "answers".into(),
        title: "Answer filtering".into(),
        summary: if answers.is_empty() {
            "Answers are passed on as the upstream gave them.".into()
        } else {
            "Some answers are changed or refused.".into()
        },
        items: answers,
        link: group_link(&group.name),
    });

    // Rewrites (the first group's).
    let rewrites: Vec<PolicyItem> = group
        .rewrites
        .iter()
        .map(|r| {
            let name = format!("{}{}", if r.wildcard { "*." } else { "" }, r.name.display());
            let target = match &r.target {
                RewriteTarget::Addr(ip) => ip.to_string(),
                RewriteTarget::Name(n) => n.display().to_string(),
            };
            PolicyItem {
                label: name,
                detail: Some(format!("answers {target}")),
                from: Some(format!("group {}", group.name)),
                link: group_link(&group.name),
                ..PolicyItem::default()
            }
        })
        .collect();
    sections.push(PolicySection {
        id: "rewrites".into(),
        title: "Rewrites".into(),
        summary: if rewrites.is_empty() {
            "No name is rewritten.".into()
        } else {
            format!("{} names are answered locally.", rewrites.len())
        },
        items: rewrites,
        link: group_link(&group.name),
    });

    // Schedules of every group the device is in, and whether each is on at `now`.
    let compiled = telltale_config::schedule::compile(cfg);
    let at = i64::try_from(now).unwrap_or(i64::MAX);
    let mut schedules = Vec::new();
    for (gi, gname) in clients.group_names(ident).iter().enumerate() {
        let Some(gc) = cfg.group.iter().find(|g| g.name.as_str() == &**gname) else {
            continue;
        };
        for sname in &gc.schedules {
            let Some(sc) = cfg.schedule.iter().find(|s| s.name == *sname) else {
                continue;
            };
            let on = compiled
                .iter()
                .find(|c| c.name == sc.name.as_str())
                .is_some_and(|c| c.is_on(at));
            let mut what = action_text(sc.action).to_owned();
            if !sc.lists.is_empty() {
                what = format!(
                    "{what}: {}",
                    join(sc.lists.iter().map(telltale_config::SafeString::as_str))
                );
            }
            if !sc.services.is_empty() {
                what = format!(
                    "{what}: {}",
                    join(sc.services.iter().map(telltale_config::SafeString::as_str))
                );
            }
            // The query path applies a block-all schedule of the first group only (as Explain).
            let ignored = on && gi > 0 && sc.action == ScheduleAction::BlockAll;
            if ignored {
                what.push_str(" (only the first group's block-all schedule applies)");
            }
            schedules.push(PolicyItem {
                label: sc.name.to_string(),
                detail: Some(format!("{what}; {}", window_text(sc))),
                state: Some(
                    if ignored {
                        "not_applied"
                    } else if on {
                        "in_effect"
                    } else {
                        "not_in_effect"
                    }
                    .into(),
                ),
                from: Some(format!("group {gname}")),
                link: group_link(gname),
                ..PolicyItem::default()
            });
        }
    }
    sections.push(PolicySection {
        id: "schedules".into(),
        title: "Schedules".into(),
        summary: if schedules.is_empty() {
            "No schedule applies.".into()
        } else {
            format!(
                "{} of {} schedules are in effect now.",
                schedules
                    .iter()
                    .filter(|s| s.state.as_deref() == Some("in_effect"))
                    .count(),
                schedules.len()
            )
        },
        items: schedules,
        link: plain_link("/groups"),
    });

    // Quick rules that apply to this device: its own, its groups', and everyone's.
    let mut rules = Vec::new();
    for (i, r) in policy.quick.rules().iter().enumerate() {
        if !policy.quick.applies_to(i, ident, subject.ip, group_ids) {
            continue;
        }
        let expired = r.expires.is_some_and(|e| at >= e);
        let from =
            match &r.scope {
                RuleScope::Devices { .. } => "this device".to_owned(),
                RuleScope::Groups(ids) => format!(
                    "group {}",
                    join(ids.iter().filter_map(|g| {
                        clients.groups().get(usize::from(*g)).map(|g| &*g.name)
                    }))
                ),
                RuleScope::Everyone => "everyone".to_owned(),
            };
        rules.push(PolicyItem {
            label: format!("{} {}", if r.allow { "allow" } else { "block" }, r.domain),
            detail: r.note.as_deref().map(str::to_owned),
            state: Some(if expired { "expired" } else { "in_effect" }.into()),
            from: Some(from),
            until_unix_seconds: r.expires.and_then(|e| u64::try_from(e).ok()),
            link: link("/rules", "rule", &r.id),
        });
    }
    sections.push(PolicySection {
        id: "rules".into(),
        title: "Quick rules".into(),
        summary: if rules.is_empty() {
            "No quick rule applies.".into()
        } else {
            "Quick rules decide before any list.".into()
        },
        items: rules,
        link: plain_link("/rules"),
    });

    // Upstream: the group a query goes to, and the routes that send some names elsewhere.
    let mut upstream = Vec::new();
    if let Some((name, routed)) = default_upstream(st, clients.group_names(ident)) {
        upstream.push(PolicyItem {
            label: name.clone(),
            detail: Some(
                if routed {
                    "an explicit route matches every name for this device"
                } else {
                    "the default for names no route claims"
                }
                .into(),
            ),
            state: Some("on".into()),
            link: link("/upstreams", "group", &name),
            ..PolicyItem::default()
        });
    }
    for r in &cfg.route {
        let applies = r.match_group.is_empty()
            || r.match_group
                .iter()
                .any(|g| group_names.iter().any(|n| n == g.as_str()));
        if !applies || r.match_suffix.is_empty() {
            continue;
        }
        upstream.push(PolicyItem {
            label: join(
                r.match_suffix
                    .iter()
                    .map(telltale_config::SafeString::as_str),
            ),
            detail: Some(format!("goes to {}", r.upstream_group)),
            from: Some("a route".into()),
            link: link("/upstreams", "group", r.upstream_group.as_str()),
            ..PolicyItem::default()
        });
    }
    sections.push(PolicySection {
        id: "upstream".into(),
        title: "Upstream".into(),
        summary: "Where this device's queries are forwarded.".into(),
        items: upstream,
        link: plain_link("/upstreams"),
    });

    ClientPolicy {
        client: subject.asked.clone(),
        device,
        address: (!subject.stand_in).then(|| subject.ip.to_string()),
        mac: mac.map(mac_text),
        identified_by: identified_by.to_owned(),
        matched_key: matched.key.clone().or(workload),
        group: group.name.to_string(),
        group_from: if ident.source == IdSource::Workload {
            "kubernetes".to_owned()
        } else {
            matched.group_from.as_str().to_owned()
        },
        group_key: matched.group_key,
        groups: group_names,
        precedence: PRECEDENCE
            .iter()
            .map(|(source, label)| PolicyRung {
                source: (*source).to_owned(),
                label: (*label).to_owned(),
                matched: *source == identified_by,
            })
            .collect(),
        sections,
        notes,
        at_unix_seconds: now,
        node: None,
        missing_nodes: Vec::new(),
    }
}

fn join<'a>(it: impl IntoIterator<Item = &'a str>) -> String {
    it.into_iter().collect::<Vec<_>>().join(", ")
}

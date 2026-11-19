//! REQ: FLT-902, API-010 (T24.29, ADR-994, ADR-973, ADR-976, design 6.3) — who a filter profile
//! applies to, written as one change: the group's networks and router names, and the devices that
//! name it (managed `[[client]]` entries, API-010). A device selected in the profile editor is a
//! client whose `groups` include the profile; one taken out leaves the profile. The group and the
//! clients go to the store in **one transaction, one configuration version** (a half-applied
//! profile would leave a device filtered by the wrong group), and the dry run says what moves
//! first ("3 devices move from Default to Kids").
//!
//! A device several profiles select keeps all of them: the lists are the union and the settings
//! come from the group with the higher priority (ADR-973), and the plan says so.

use serde::Deserialize;
use wrendns_api::ManagedWrite;
use wrendns_api::problem::Problem;
use wrendns_config::{Cidr, ClientConfig, GroupConfig, MatchKey, SafeString};

use crate::api_backend::ManagedPlan;
use crate::http::Sources;
use crate::managed::Entries;

/// The body of `PUT /api/v1/groups/{name}/sources`: what is left out is not changed.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SourcesInput {
    /// Networks (CIDRs) whose devices belong to the group; replaces the current list.
    #[serde(default)]
    pub(crate) networks: Option<Vec<String>>,
    /// Router names (the label form) that belong to the group; replaces the current list.
    #[serde(default)]
    pub(crate) router_names: Option<Vec<String>>,
    /// The devices in the group; replaces the current members.
    #[serde(default)]
    pub(crate) devices: Option<Vec<DeviceInput>>,
}

/// A device that belongs to the group.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeviceInput {
    /// The name to give it (a configured device's name, or a new device's).
    pub(crate) name: String,
    /// How to recognize it (`aa:bb:..`, `192.168.1.5`, `id:kids-tablet`, `hostname:tv`); for a
    /// device that exists these are added to its keys.
    #[serde(default, rename = "match")]
    pub(crate) matches: Vec<String>,
}

fn problem(code: wrendns_api::problem::Code, msg: impl Into<String>) -> Problem {
    Problem::new(code, msg)
}

fn invalid(msg: impl Into<String>) -> Problem {
    problem(wrendns_api::problem::Code::InvalidConfig, msg)
}

/// The group's sources as JSON (the answer's `before` and `after`).
fn sources_json(g: &GroupConfig, devices: &[String]) -> serde_json::Value {
    serde_json::json!({
        "networks": g.networks.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "routerNames": g.router_names.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "devices": devices,
    })
}

fn members(cfg: &wrendns_config::Config, group: &str) -> Vec<String> {
    let mut v: Vec<String> = cfg
        .client
        .iter()
        .filter(|c| c.groups.iter().any(|g| g.as_str() == group))
        .map(|c| c.name.to_string())
        .collect();
    v.sort();
    v
}

/// Plans the change: validated against the merged configuration, with `also` holding the clients
/// to store beside the group.
#[allow(clippy::too_many_lines)] // networks, router names, devices, then the check and the words
pub(crate) fn plan(
    src: &Sources,
    state: &wrendns_store::state::State,
    w: &ManagedWrite,
) -> Result<ManagedPlan, Problem> {
    let name = w.name.trim().to_owned();
    let input: SourcesInput =
        serde_json::from_value(w.body.clone().ok_or_else(|| {
            invalid("give the group's sources: networks, routerNames and devices")
        })?)
        .map_err(|e| invalid(format!("sources: {e}")))?;
    let file = src.file_config.load_full();
    let mut entries: Entries = crate::managed::entries(state);
    let before_cfg = crate::managed::merge(&file, &entries).unwrap_or_else(|_| (*file).clone());
    // The entry to store starts from what is stored (else the files' group), never from the merged
    // group: `merge` has adopted the legacy ad list into a synthetic `content` and trimmed `lists`,
    // and those derived values are never written back (managed.rs).
    let base = entries
        .groups
        .iter()
        .find_map(|(n, o)| match o {
            crate::managed::Ovr::Set(g) if *n == name => Some(g.clone()),
            _ => None,
        })
        .or_else(|| file.group.iter().find(|g| g.name.as_str() == name).cloned());
    let mut group: GroupConfig = match base.or_else(|| {
        before_cfg
            .group
            .iter()
            .find(|g| g.name.as_str() == name)
            .cloned()
    }) {
        Some(g) => g,
        None if name == "default" => {
            toml::from_str("name = \"default\"").map_err(|e| Problem::internal(e.to_string()))?
        }
        None => return Err(Problem::not_found(format!("no group `{name}`"))),
    };
    let managed: Vec<String> = state
        .managed(crate::managed::CLIENT)
        .map_err(|e| Problem::internal(e.to_string()))?
        .into_iter()
        .map(|m| m.name)
        .collect();
    let is_managed = |n: &str| managed.iter().any(|m| m == n);
    let before_devices = members(&before_cfg, &name);
    let before = sources_json(&group, &before_devices);
    let table = wrendns_policy::ClientTable::from_config(&before_cfg);
    let mut warnings: Vec<String> = Vec::new();

    if let Some(nets) = &input.networks {
        group.networks = nets
            .iter()
            .map(|n| Cidr::parse(n).map_err(|e| invalid(format!("networks: {e}"))))
            .collect::<Result<_, _>>()?;
    }
    if let Some(names) = &input.router_names {
        group.router_names = names
            .iter()
            .map(|n| SafeString::new(n.trim().to_ascii_lowercase().replace(' ', "-")))
            .collect::<Result<_, _>>()
            .map_err(|e| invalid(format!("routerNames: {e}")))?;
    }

    // The clients to store beside the group, and what moves.
    let mut stored: Vec<ClientConfig> = Vec::new();
    let mut moved: Vec<(String, String)> = Vec::new(); // (device, group it leaves)
    let mut joined: Vec<(String, Vec<String>)> = Vec::new(); // (device, the groups it also has)
    let mut left: Vec<String> = Vec::new();
    if let Some(devs) = &input.devices {
        let want: Vec<String> = devs.iter().map(|d| d.name.trim().to_owned()).collect();
        for d in devs {
            let dname = d.name.trim();
            if dname.is_empty() {
                return Err(invalid("devices: a device needs a name"));
            }
            for k in &d.matches {
                MatchKey::parse(k).map_err(|e| invalid(format!("devices[{dname}].match: {e}")))?;
            }
            let existing = before_cfg.client.iter().find(|c| c.name.as_str() == dname);
            match existing {
                Some(c) if c.groups.iter().any(|g| g.as_str() == name) => {}
                Some(_) if !is_managed(dname) => {
                    return Err(problem(
                        wrendns_api::problem::Code::SetByFile,
                        format!("`{dname}` is defined in the config files"),
                    )
                    .hint("Add this group to its `groups` in the file; the API can't change a device a file defines."));
                }
                Some(c) => {
                    let mut c = c.clone();
                    let (was, _) = crate::api_backend::effective_groups_of(&table, &c);
                    let explicit = !c.groups.is_empty();
                    if explicit {
                        joined.push((dname.to_owned(), was.clone()));
                    } else {
                        moved.push((
                            dname.to_owned(),
                            was.first().cloned().unwrap_or_else(|| "default".to_owned()),
                        ));
                    }
                    c.groups
                        .push(SafeString::new(name.clone()).map_err(invalid)?);
                    for k in &d.matches {
                        if !c.match_keys.iter().any(|m| m.eq_ignore_ascii_case(k)) {
                            c.match_keys
                                .push(SafeString::new(k.trim()).map_err(invalid)?);
                        }
                    }
                    stored.push(c);
                }
                None => {
                    if d.matches.is_empty() {
                        return Err(invalid(format!(
                            "devices: `{dname}` is a new device: give `match` (its MAC, address or name)"
                        )));
                    }
                    let c = ClientConfig {
                        name: SafeString::new(dname).map_err(invalid)?,
                        match_keys: d
                            .matches
                            .iter()
                            .map(|k| SafeString::new(k.trim()))
                            .collect::<Result<_, _>>()
                            .map_err(invalid)?,
                        groups: vec![SafeString::new(name.clone()).map_err(invalid)?],
                        kind: None,
                    };
                    // Where the new device lands today: its address's network group, else default.
                    let (was, _) =
                        crate::api_backend::effective_groups_of(&table, &c.clone_without_groups());
                    // A device known only by a MAC is where its network puts it: default, as far
                    // as this change can tell.
                    moved.push((
                        dname.to_owned(),
                        was.first().cloned().unwrap_or_else(|| "default".to_owned()),
                    ));
                    stored.push(c);
                }
            }
        }
        // Members taken out: they leave the group (a device that only named it falls back to its
        // network's group or default).
        for current in &before_devices {
            if want.iter().any(|w| w == current) {
                continue;
            }
            let Some(c) = before_cfg
                .client
                .iter()
                .find(|c| c.name.as_str() == current)
            else {
                continue;
            };
            if !is_managed(current) {
                warnings.push(format!(
                    "`{current}` is defined in a config file, so it stays in this group (remove it from `groups` there)"
                ));
                continue;
            }
            let mut c = c.clone();
            c.groups.retain(|g| g.as_str() != name);
            left.push(current.clone());
            stored.push(c);
        }
    }

    // The merged configuration with the group and the clients, validated as a whole.
    entries
        .clients
        .retain(|c| !stored.iter().any(|s| s.name == c.name));
    entries.clients.extend(stored.iter().cloned());
    entries.groups.retain(|(n, _)| *n != name);
    entries
        .groups
        .push((name.clone(), crate::managed::Ovr::Set(group.clone())));
    if let Some(p) = cluster_content_gate(
        src,
        &serde_json::to_value(&group).map_err(|e| Problem::internal(e.to_string()))?,
    ) {
        return Err(p);
    }
    let merged = crate::managed::merge(&file, &entries).map_err(|errs| invalid(errs.join("; ")))?;
    warnings.extend(wrendns_config::validate_config(&merged).unwrap_or_default());
    let after_group = merged
        .group
        .iter()
        .find(|g| g.name.as_str() == name)
        .unwrap_or(&group);
    let after = sources_json(after_group, &members(&merged, &name));

    // The words: what moves, and what a device that is in several profiles means.
    let mut parts: Vec<String> = Vec::new();
    if !moved.is_empty() {
        let mut by_from: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        for (_, from) in &moved {
            *by_from.entry(from.as_str()).or_default() += 1;
        }
        for (from, n) in by_from {
            parts.push(format!(
                "{n} device{} move{} from {} to {name}",
                if n == 1 { "" } else { "s" },
                if n == 1 { "s" } else { "" },
                title(from)
            ));
        }
    }
    for (dev, also) in &joined {
        parts.push(format!(
            "{dev} is already in {}: with several groups the lists are the union and the settings come from the higher priority",
            also.iter().map(|g| title(g)).collect::<Vec<_>>().join(", ")
        ));
    }
    if !left.is_empty() {
        parts.push(format!(
            "{} leave{} {name}",
            left.join(", "),
            if left.len() == 1 { "s" } else { "" }
        ));
    }
    if input.networks.is_some() && after["networks"] != before["networks"] {
        parts.push("its networks change".to_owned());
    }
    let impact = if parts.is_empty() {
        "No device changes group.".to_owned()
    } else {
        format!("{}.", parts.join("; "))
    };
    let rows: Vec<(&'static str, String, Option<String>)> = stored
        .iter()
        .map(|c| {
            (
                crate::managed::CLIENT,
                c.name.to_string(),
                Some(serde_json::to_string(c).unwrap_or_default()),
            )
        })
        .collect();
    Ok(ManagedPlan {
        name,
        before: Some(before),
        after: Some(after),
        body: Some(serde_json::to_string(&group).unwrap_or_default()),
        recent_queries: 0,
        impact,
        warnings,
        also: rows,
        candidate: merged,
        redirect: None,
    })
}

/// REQ: FLT-901, FLT-902 (ADR-994 item 7, CLU-010) - the version gate for a group entry `body`, on
/// every route that stores one (a group write, a sources write): members are the cluster's plus
/// this node.
pub(crate) fn cluster_content_gate(src: &Sources, body: &serde_json::Value) -> Option<Problem> {
    let c = src.cluster.as_ref()?;
    let mut members: Vec<(String, String)> = c
        .members()
        .into_iter()
        .map(|m| (m.node_id, m.version))
        .collect();
    members.push((
        c.identity.meta.node_id.clone(),
        crate::build_info::VERSION.to_owned(),
    ));
    content_members_too_old(&members, crate::forward::GROUP_CONTENT_SINCE, body)
}

/// REQ: FLT-901, FLT-902 (T24.29, ADR-994 item 7, CLU-010) - a group entry that carries `content` or
/// `safe_search_engines` is refused (409 `members_too_old`) while any cluster member runs a version
/// that does not read them: that node would reject the group's configuration. `members` is (node ID,
/// version) for each member, this node included.
pub(crate) fn content_members_too_old(
    members: &[(String, String)],
    since: (u64, u64, u64),
    body: &serde_json::Value,
) -> Option<Problem> {
    let carries = body.get("content").is_some_and(|c| !c.is_null())
        || body
            .get("safe_search_engines")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|a| !a.is_empty());
    if !carries {
        return None;
    }
    let old: Vec<&str> = members
        .iter()
        .filter(|(_, v)| !crate::forward::version_at_least(v, since))
        .map(|(n, _)| n.as_str())
        .collect();
    if old.is_empty() {
        return None;
    }
    Some(
        problem(
            wrendns_api::problem::Code::MembersTooOld,
            format!(
                "content categories and per-engine safe search can't be set while {} runs an older version than this one: it can't read a group with those fields",
                old.join(", ")
            ),
        )
        .hint("Upgrade every node first (replicas first, then the primary), then make this change again."),
    )
}

/// `default` reads "Default" in a sentence; any other name is as written.
fn title(g: &str) -> String {
    if g == "default" {
        "Default".to_owned()
    } else {
        g.to_owned()
    }
}

trait WithoutGroups {
    fn clone_without_groups(&self) -> ClientConfig;
}

impl WithoutGroups for ClientConfig {
    fn clone_without_groups(&self) -> ClientConfig {
        let mut c = self.clone();
        c.groups.clear();
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wrendns_api::{ManagedKind, ManagedWrite};

    const FILES: &str = r#"
[[group]]
name = "default"
[[group]]
name = "kids"
networks = ["10.0.1.0/24"]
priority = 10
[[group]]
name = "teens"
priority = 5
[[client]]
name = "tv"
match = ["10.0.9.9"]
"#;

    fn setup() -> (Arc<Sources>, Arc<wrendns_store::state::State>) {
        let src = Arc::new(crate::http::tests::sources());
        let cfg = wrendns_config::Loader::new()
            .toml_str("t.toml", FILES)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config;
        src.file_config.store(Arc::new(cfg.clone()));
        src.config.store(Arc::new(cfg));
        (
            src,
            Arc::new(wrendns_store::state::State::in_memory().unwrap()),
        )
    }

    fn write(name: &str, body: serde_json::Value) -> ManagedWrite {
        ManagedWrite {
            kind: ManagedKind::GroupSources,
            name: name.into(),
            body: Some(body),
            dry_run: true,
            expect: None,
            by: "tester".into(),
            simulate: None,
            role: None,
            agent: None,
        }
    }

    /// REQ: FLT-901, FLT-902 (T24.29) - a sources write stores the group as it is stored or in the
    /// files, never the effective one: the `content.ads` the merge makes for an adopted ad list
    /// is derived and is not written back.
    #[test]
    fn flt_902_source_write_stores_no_derived_content() {
        let (src, state) = setup();
        let url = wrendns_config::categories::catalog()
            .source("hagezi-ads-pro")
            .map(|s| s.url.clone())
            .unwrap();
        let list = serde_json::json!({"name": "hagezi-pro", "url": url}).to_string();
        state
            .put_managed_batch(
                &[(crate::managed::LIST, "hagezi-pro", list.as_str())],
                None,
                1,
                "t",
            )
            .unwrap();
        // The effective kids group has the synthetic `content`; the stored entry must not.
        let entries = crate::managed::entries(&state);
        let merged = crate::managed::merge(&src.file_config.load_full(), &entries).unwrap();
        assert!(
            merged
                .group
                .iter()
                .any(|g| g.name.as_str() == "kids" && g.content.is_some()),
            "the merge adopts the ad list"
        );
        let plan = plan(
            &src,
            &state,
            &write("kids", serde_json::json!({"networks": ["10.0.2.0/24"]})),
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_str(plan.body.as_deref().unwrap()).unwrap();
        assert!(body.get("content").is_none(), "no derived content: {body}");
        assert_eq!(body["networks"], serde_json::json!(["10.0.2.0/24"]));
    }

    fn group_write(name: &str, body: serde_json::Value) -> ManagedWrite {
        ManagedWrite {
            kind: ManagedKind::Group,
            ..write(name, body)
        }
    }

    /// REQ: FLT-901 (T24.29, recheck item 3) - `PUT /groups/{name}` without `content` on a group
    /// that never set it stores none: the synthetic `content.ads` of an adopted ad list is derived.
    #[test]
    fn flt_901_group_put_stores_no_derived_content() {
        let (src, state) = setup();
        let url = wrendns_config::categories::catalog()
            .source("hagezi-ads-pro")
            .map(|s| s.url.clone())
            .unwrap();
        let list = serde_json::json!({"name": "hagezi-pro", "url": url}).to_string();
        state
            .put_managed_batch(
                &[(crate::managed::LIST, "hagezi-pro", list.as_str())],
                None,
                1,
                "t",
            )
            .unwrap();
        let p = crate::api_backend::plan_override(
            &src,
            &state,
            &group_write("kids", serde_json::json!({"name": "kids", "priority": 11})),
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_str(p.body.as_deref().unwrap()).unwrap();
        assert!(body.get("content").is_none(), "no derived content: {body}");
    }

    /// REQ: FLT-901 (T24.29, recheck item 2) - a group whose file sets `content` is not frozen by
    /// an override: a body that leaves it out stores the file's, and a stale stored copy loses to
    /// the file's current value on merge.
    #[test]
    fn flt_901_file_content_is_not_frozen_by_an_override() {
        let src = Arc::new(crate::http::tests::sources());
        let files = |ads: bool| {
            let t = format!(
                "[[group]]
name = \"default\"
[group.content]
ads = {ads}
[[group]]
name = \"kids\"
priority = 10
"
            );
            wrendns_config::Loader::new()
                .toml_str("t.toml", &t)
                .env(Vec::<(String, String)>::new())
                .load()
                .unwrap()
                .config
        };
        let state = Arc::new(wrendns_store::state::State::in_memory().unwrap());
        let v1 = files(true);
        src.file_config.store(Arc::new(v1.clone()));
        src.config.store(Arc::new(v1));
        let p = crate::api_backend::plan_override(
            &src,
            &state,
            &group_write(
                "default",
                serde_json::json!({"name": "default", "priority": 3}),
            ),
        )
        .unwrap();
        let stored = p.body.clone().unwrap();
        let g: wrendns_config::GroupConfig = serde_json::from_str(&stored).unwrap();
        assert!(
            g.content.as_ref().is_some_and(|c| c.ads),
            "the file's content is kept"
        );
        // The override is stored; then the file changes its content: the file's applies.
        state
            .put_managed_batch(
                &[(crate::managed::GROUP, "default", stored.as_str())],
                None,
                1,
                "t",
            )
            .unwrap();
        let v2 = files(false);
        let entries = crate::managed::entries(&state);
        let merged = crate::managed::merge(&v2, &entries).unwrap();
        let d = merged
            .group
            .iter()
            .find(|g| g.name.as_str() == "default")
            .unwrap();
        assert_eq!(d.priority, 3, "the override's other fields apply");
        assert!(
            d.content.as_ref().is_some_and(|c| !c.ads),
            "the file's current content wins over the stored copy"
        );
    }

    /// REQ: FLT-902, API-010 (T24.29) - the group and its devices are one change: one plan holds the
    /// group and the clients, they are stored in one transaction (the version moves once), and the
    /// plan says what moves.
    #[test]
    fn flt_902_source_write_is_one_transaction() {
        let (src, state) = setup();
        let body = serde_json::json!({
            "networks": ["10.0.2.0/24"],
            "devices": [
                {"name": "Maya iPad", "match": ["da:a1:19:00:00:01"]},
                {"name": "Lego Console", "match": ["10.0.3.4"]},
            ]
        });
        let plan = plan(&src, &state, &write("kids", body)).unwrap();
        assert_eq!(
            plan.also.len(),
            2,
            "both devices are stored beside the group"
        );
        assert_eq!(
            plan.impact,
            "2 devices move from Default to kids; its networks change."
        );
        assert_eq!(
            plan.after.as_ref().unwrap()["devices"],
            serde_json::json!(["Lego Console", "Maya iPad"])
        );
        assert_eq!(
            plan.after.as_ref().unwrap()["networks"],
            serde_json::json!(["10.0.2.0/24"])
        );
        // Stored together: the version moves once, and both kinds are there.
        let rows: Vec<(&str, &str, &str)> = plan
            .also
            .iter()
            .filter_map(|(k, n, b)| Some((*k, n.as_str(), b.as_deref()?)))
            .chain(std::iter::once((
                crate::managed::GROUP,
                "kids",
                plan.body.as_deref().unwrap(),
            )))
            .collect();
        let before = state.config_version().unwrap();
        let after = state.put_managed_batch(&rows, None, 1, "tester").unwrap();
        assert_eq!(
            after,
            before + 1,
            "one version for the group and its devices"
        );
        assert_eq!(state.managed(crate::managed::CLIENT).unwrap().len(), 2);
        assert_eq!(state.managed(crate::managed::GROUP).unwrap().len(), 1);
        // The merged configuration has the devices in the group.
        let entries = crate::managed::entries(&state);
        let merged = crate::managed::merge(&src.file_config.load_full(), &entries).unwrap();
        let kids: Vec<&str> = merged
            .client
            .iter()
            .filter(|c| c.groups.iter().any(|g| g.as_str() == "kids"))
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(kids.len(), 2);
    }

    /// REQ: FLT-902 (design 6.3, ADR-973) - a device already in another profile is not moved but
    /// joined, and the plan says the lists are the union and the settings come from the higher
    /// priority; a bad key, a missing key for a new device and a device a file defines are refused.
    #[test]
    fn flt_902_device_in_two_profiles_notice() {
        let (src, state) = setup();
        // Maya's iPad is in teens already.
        let teens =
            serde_json::json!({"devices": [{"name": "Maya iPad", "match": ["da:a1:19:00:00:01"]}]});
        let p = plan(&src, &state, &write("teens", teens)).unwrap();
        let rows: Vec<(&str, &str, &str)> = p
            .also
            .iter()
            .filter_map(|(k, n, b)| Some((*k, n.as_str(), b.as_deref()?)))
            .collect();
        state.put_managed_batch(&rows, None, 1, "t").unwrap();
        let kids = serde_json::json!({"devices": [{"name": "Maya iPad"}]});
        let p = plan(&src, &state, &write("kids", kids)).unwrap();
        assert!(
            p.impact.contains(
                "Maya iPad is already in teens: with several groups the lists are the union"
            ),
            "{}",
            p.impact
        );
        assert!(p.impact.contains("higher priority"));
        let stored: wrendns_config::ClientConfig =
            serde_json::from_str(p.also[0].2.as_deref().unwrap()).unwrap();
        let groups: Vec<&str> = stored
            .groups
            .iter()
            .map(wrendns_config::SafeString::as_str)
            .collect();
        assert_eq!(groups, ["teens", "kids"], "it keeps both");
        // Refusals.
        let err = |b: serde_json::Value, g: &str| plan(&src, &state, &write(g, b)).err().unwrap();
        assert!(
            err(
                serde_json::json!({"devices": [{"name": "New", "match": ["not-a-key!"]}]}),
                "kids"
            )
            .detail
            .contains("match")
        );
        assert!(
            err(serde_json::json!({"devices": [{"name": "New"}]}), "kids")
                .detail
                .contains("new device")
        );
        assert!(
            err(serde_json::json!({"networks": ["nope"]}), "kids")
                .detail
                .contains("networks")
        );
        let e = err(serde_json::json!({"devices": [{"name": "tv"}]}), "kids");
        assert_eq!(
            e.code,
            wrendns_api::problem::Code::SetByFile,
            "{}",
            e.detail
        );
        assert_eq!(
            err(serde_json::json!({}), "nobody").code,
            wrendns_api::problem::Code::NotFound
        );
        // Taking a device out: it leaves, and the others stay.
        let out = serde_json::json!({"devices": []});
        let p = plan(&src, &state, &write("teens", out)).unwrap();
        assert!(p.impact.contains("Maya iPad leaves teens"), "{}", p.impact);
    }
    /// REQ: FLT-901, FLT-902 (ADR-994 item 7, CLU-010) - a group entry with `content` (or per-engine
    /// safe search) waits for every member to read it; an entry without them never does.
    #[test]
    fn clu_901_content_waits_for_every_member() {
        let members = |v: &[&str]| -> Vec<(String, String)> {
            v.iter()
                .enumerate()
                .map(|(i, v)| (format!("n{i}"), (*v).to_owned()))
                .collect()
        };
        let since = crate::forward::GROUP_CONTENT_SINCE;
        let with = serde_json::json!({"content": {"level": "basic"}});
        let engines = serde_json::json!({"safe_search_engines": ["google"]});
        let plain = serde_json::json!({"block_mode": "nxdomain"});
        let old = members(&["0.8.0", "0.7.9"]);
        let e = content_members_too_old(&old, since, &with).unwrap();
        assert_eq!(e.code, wrendns_api::problem::Code::MembersTooOld);
        assert!(e.detail.contains("n1"), "{}", e.detail);
        assert!(content_members_too_old(&old, since, &engines).is_some());
        assert!(content_members_too_old(&old, since, &plain).is_none());
        assert!(
            content_members_too_old(&old, since, &serde_json::json!({"content": null})).is_none()
        );
        assert!(content_members_too_old(&members(&["0.8.0", "0.8.1"]), since, &with).is_none());
    }
}

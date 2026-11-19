//! REQ: FLT-901, FLT-902, AGT-001 (T24.29, ADR-994, ADR-995) — content categories and filter
//! profiles over the API: the catalog (`GET /categories`), what a selection costs
//! (`GET /categories/budget`), a group's content (`GET` and `PUT /groups/{name}/content`) and the
//! picker's networks and devices (`GET /profiles/devices`).
//!
//! The catalog is data compiled into the binary (`wrendns_config::categories`); the node's state
//! (what is downloaded, how big) is read from the lists, since a category source is a list named
//! `cat-<id>`. A content change that downloads lists is for people: an agent token plans it, and
//! only an operator-approved plan applies (ADR-994 item 8).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, RawQuery, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use wrendns_config::categories::{self as cat, Budget, CategoryKind};
use wrendns_config::{AdsTier, ContentLevel, GroupContent, SafeString};

use crate::auth::routes::principal;
use crate::auth::{Auth, Principal};
use crate::problem::{Code, Problem};
use crate::{Backend, Shared};

/// REQ: FLT-901 (ADR-994 item 8) — set on the in-process request `apply_plan` makes for a content
/// plan an operator approved, so the same write that an agent token is refused is let through.
/// Only the server adds it (a request extension, never a header).
#[derive(Debug, Clone, Copy)]
pub struct ApprovedContentPlan;

/// What the node knows that bounds a selection (read from the primary in a cluster: it fetches
/// and compiles, ADR-994 item 10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CategoryEnv {
    /// `[filter] entry_budget`.
    pub entry_budget: u64,
    /// `[filter] ads_tier`: `light`, `pro`, `pro_plus` or `ultimate`.
    pub ads_tier: String,
    /// `[filter] compile_memory`, the merge budget before it is scaled to the node.
    pub compile_memory_bytes: u64,
    /// The node's memory limit (its cgroup, else its RAM), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_limit_bytes: Option<u64>,
    /// This process's resident memory now, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_rss_bytes: Option<u64>,
    /// Which node these numbers are from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
}

impl Default for CategoryEnv {
    fn default() -> Self {
        Self {
            entry_budget: 1_000_000,
            ads_tier: "pro".to_owned(),
            compile_memory_bytes: 128 * 1024 * 1024,
            memory_limit_bytes: None,
            process_rss_bytes: None,
            node: None,
        }
    }
}

impl CategoryEnv {
    fn tier(&self) -> AdsTier {
        match self.ads_tier.as_str() {
            "light" => AdsTier::Light,
            "pro_plus" | "pro-plus" => AdsTier::ProPlus,
            "ultimate" => AdsTier::Ultimate,
            _ => AdsTier::Pro,
        }
    }
}

/// A group's content as the API shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupContentInfo {
    /// `off`, `basic` or `enhanced`; left out reads `off`, as in the TOML.
    #[serde(default = "off_level")]
    pub level: String,
    /// Category IDs (kept when the level is `off`).
    #[serde(default)]
    pub categories: Vec<String>,
    /// A tier per category.
    #[serde(default)]
    pub tiers: BTreeMap<String, String>,
    /// Ad block.
    #[serde(default)]
    pub ads: bool,
}

impl GroupContentInfo {
    /// From the config's field.
    pub fn from_config(c: &GroupContent) -> Self {
        Self {
            level: level_word(c.level).to_owned(),
            categories: c.categories.iter().map(ToString::to_string).collect(),
            tiers: c.tiers.clone(),
            ads: c.ads,
        }
    }

    /// Back to the config's type (`Err` names the problem).
    pub fn to_config(&self) -> Result<GroupContent, String> {
        Ok(GroupContent {
            level: parse_level(&self.level)?,
            categories: self
                .categories
                .iter()
                .map(|c| SafeString::new(c.clone()))
                .collect::<Result<_, _>>()?,
            tiers: self.tiers.clone(),
            ads: self.ads,
        })
    }
}

fn off_level() -> String {
    "off".to_owned()
}

fn level_word(l: ContentLevel) -> &'static str {
    match l {
        ContentLevel::Off => "off",
        ContentLevel::Basic => "basic",
        ContentLevel::Enhanced => "enhanced",
    }
}

fn parse_level(s: &str) -> Result<ContentLevel, String> {
    match s {
        "off" => Ok(ContentLevel::Off),
        "basic" => Ok(ContentLevel::Basic),
        "enhanced" => Ok(ContentLevel::Enhanced),
        other => Err(format!("`{other}`: the level is off, basic or enhanced")),
    }
}

/// What to change in a group's content: fields left out keep their current value.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentInput {
    /// `off`, `basic` or `enhanced`.
    #[serde(default)]
    pub level: Option<String>,
    /// Category IDs (`GET /api/v1/categories`); replaces the current list.
    #[serde(default)]
    pub categories: Option<Vec<String>>,
    /// A tier per category (`gambling` = `extended`); replaces the current tiers.
    #[serde(default)]
    pub tiers: Option<BTreeMap<String, String>>,
    /// Ad block on or off.
    #[serde(default)]
    pub ads: Option<bool>,
}

impl ContentInput {
    fn applied_to(&self, current: &GroupContentInfo) -> GroupContentInfo {
        GroupContentInfo {
            level: self.level.clone().unwrap_or_else(|| current.level.clone()),
            categories: self
                .categories
                .clone()
                .unwrap_or_else(|| current.categories.clone()),
            tiers: self.tiers.clone().unwrap_or_else(|| current.tiers.clone()),
            ads: self.ads.unwrap_or(current.ads),
        }
    }
}

// ----------------------------------------------------------------------------- the catalog view

/// A tier of a category.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TierView {
    pub id: String,
    pub name: String,
    /// The sources this tier adds or switches to.
    pub sources: Vec<String>,
}

/// One category.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CategoryView {
    pub id: String,
    pub name: String,
    /// One line for the info icon.
    pub description: String,
    /// `list` (a maintained list behind it) or `service` (a bundle turned on with `blockedServices`).
    pub kind: String,
    /// The sources always in use.
    pub sources: Vec<String>,
    /// `exclusive` or `additive`, when it has tiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_tier: Option<String>,
    /// `adsTier`: the size is the `[filter] ads_tier` setting, not a per-profile choice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier_from: Option<String>,
    pub tiers: Vec<TierView>,
    /// For a service category: the FLT-012 service IDs to put in `blockedServices`.
    pub services: Vec<String>,
    /// A warning the confirmation repeats (a category that blocks whole top-level domains).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warn: Option<String>,
    /// Entries with the default tier (distinct sources).
    pub entries: u64,
    /// Any source it can use is heavy.
    pub heavy: bool,
    /// Groups that select it now.
    pub groups: Vec<String>,
}

/// A group of categories in the picker.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CategoryGroupView {
    pub id: String,
    pub name: String,
    pub categories: Vec<CategoryView>,
}

/// Where a source stands on this node.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceState {
    /// The list the node keeps it in (`cat-<id>`, or a file's list with the same URL).
    pub list: String,
    /// False until a group uses it and it has downloaded.
    pub downloaded: bool,
    /// `unused` (no group selects it), `pending`, `ok` or `failed`.
    pub state: String,
    pub bytes: u64,
    pub lines: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_changed_unix_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// A list the config files define has this source's URL, so nothing is downloaded twice and
    /// the checkbox says "provided by list X, set by file".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provided_by: Option<String>,
    /// REQ: FLT-004 (T24.28, ADR-992) — names this source puts in the active snapshot, and how
    /// many of them no other enabled list has (zero while it is not downloaded and compiled).
    pub snapshot_entries: u64,
    pub unique_entries: u64,
    /// The lists that have the rest, most shared first (at most three).
    pub also_in: Vec<crate::model::ListShare>,
}

/// One source, with its licence and size.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceView {
    pub id: String,
    pub name: String,
    pub maintainer: String,
    pub url: String,
    pub format: String,
    /// SPDX identifier.
    pub licence: String,
    pub licence_url: String,
    /// A line shown next to the checkbox (CC BY-SA sources).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution: Option<String>,
    pub homepage: String,
    pub cadence: String,
    /// From the file's header when the catalog was built.
    pub entries: u64,
    pub bytes: u64,
    /// `light` or `heavy`.
    pub weight: String,
    /// How often this node refreshes it.
    pub refresh_seconds: u32,
    /// The catalog's check date and the maintainer's last push on it.
    pub checked: String,
    pub pushed: String,
    /// Categories that can use it.
    pub categories: Vec<String>,
    pub state: SourceState,
}

/// A preset (`basic`).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PresetView {
    pub id: String,
    pub name: String,
    pub description: String,
    pub categories: Vec<String>,
}

/// A category the catalog does not offer, and why.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NotOfferedView {
    pub name: String,
    pub group: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternative: Option<String>,
}

/// What one group selects.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupSelection {
    pub group: String,
    pub content: GroupContentInfo,
    /// The categories in effect (the level's, plus ads), catalog order.
    pub categories: Vec<String>,
    /// The sources they use.
    pub sources: Vec<String>,
    /// IDs this version does not know: ignored, and reported.
    pub unknown: Vec<String>,
}

/// The catalog and this node's state (REQ: FLT-901).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CategoriesView {
    pub catalog_version: String,
    pub groups: Vec<CategoryGroupView>,
    pub sources: Vec<SourceView>,
    pub presets: Vec<PresetView>,
    pub not_offered: Vec<NotOfferedView>,
    /// The attribution lines to show (CC BY-SA sources).
    pub attributions: Vec<String>,
    /// What each group selects now.
    pub selections: Vec<GroupSelection>,
    /// What all of them cost together (distinct sources).
    #[schema(value_type = Object)]
    pub total: Budget,
    pub node: CategoryEnv,
}

/// What a proposed selection costs.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BudgetView {
    /// The group the proposal is for, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// All groups' sources together, with the proposal in place.
    #[schema(value_type = Object)]
    pub total: Budget,
    /// The proposal's group alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub group_only: Option<Budget>,
    /// Sources the proposal adds that no group had selected.
    pub added: Vec<String>,
    /// Heavy sources among `added`: they ask for a confirmation that states the daily download.
    pub heavy_added: Vec<String>,
    /// The daily download of `heavyAdded`, in bytes.
    pub heavy_daily_download_bytes: u64,
    pub confirmation_required: bool,
    pub node: CategoryEnv,
}

/// A group's content, and what it makes the node do.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupContentView {
    pub group: String,
    pub content: GroupContentInfo,
    pub selection: GroupSelection,
    /// "Off", "Basic", "Enhanced (3 of 21)", with "Ad block" when on.
    pub summary: String,
    #[schema(value_type = Object)]
    pub budget: Budget,
}

/// A network or a device the picker offers (REQ: FLT-902).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSource {
    /// `network` or `device`.
    pub kind: String,
    /// The name to show: a network's name, a device's name or its address.
    pub label: String,
    /// What to write: a CIDR for a network, a configured device's name, or a seen device's address.
    pub id: String,
    /// A device class (`phone`, `tv`, ...), or `network`.
    pub icon: String,
    /// The keys the device can be selected by.
    #[serde(default)]
    pub keys: Vec<ProfileKey>,
    /// The group a device is in now (its effective group), or the group that holds a network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// A configured device (a `[[client]]`), as opposed to one only seen.
    #[serde(default)]
    pub configured: bool,
    /// Where the device is defined: `file` (read-only) or `api`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defined_in: Option<String>,
}

/// One way to recognize a device.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProfileKey {
    /// `mac`, `ip`, `name` (a router name), or `id` (a client ID).
    pub kind: String,
    /// As a `[[client]] match` key is written (`aa:bb:..`, `192.168.1.5`, `hostname:tv`).
    pub value: String,
    /// A MAC with the locally administered bit (a private Wi-Fi address, ADR-910): it may change.
    #[serde(default)]
    pub randomized: bool,
}

/// The picker's data.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProfileDevices {
    pub networks: Vec<ProfileSource>,
    pub devices: Vec<ProfileSource>,
}

/// REQ: FLT-902 (ADR-910) — the locally administered bit of a MAC's first byte.
pub fn mac_is_randomized(mac: &str) -> bool {
    mac.split([':', '-'])
        .next()
        .and_then(|b| u8::from_str_radix(b, 16).ok())
        .is_some_and(|b| b & 0x02 != 0)
}

// ----------------------------------------------------------------------------- building views

fn weight_word(w: cat::Weight) -> &'static str {
    match w {
        cat::Weight::Light => "light",
        cat::Weight::Heavy => "heavy",
    }
}

fn selection_of(name: &str, content: &GroupContent, tier: AdsTier) -> GroupSelection {
    let s = cat::selection(content, tier);
    GroupSelection {
        group: name.to_owned(),
        content: GroupContentInfo::from_config(content),
        categories: s.categories.iter().map(|c| c.id.clone()).collect(),
        sources: s.sources.iter().map(|x| x.id.clone()).collect(),
        unknown: s.unknown,
    }
}

/// Every group's content as config values (a group with none selects nothing).
fn group_contents(b: &dyn Backend) -> Vec<(String, GroupContent)> {
    b.groups_local()
        .into_iter()
        .map(|g| {
            let c = g
                .content
                .as_ref()
                .and_then(|c| c.to_config().ok())
                .unwrap_or_default();
            (g.name, c)
        })
        .collect()
}

fn budget_of(
    contents: &[(String, GroupContent)],
    env: &CategoryEnv,
) -> (Budget, Vec<&'static cat::Source>) {
    let mut ids = std::collections::BTreeSet::new();
    for (_, c) in contents {
        for s in cat::selection(c, env.tier()).sources {
            ids.insert(s.id.as_str());
        }
    }
    let sources: Vec<&'static cat::Source> = cat::catalog()
        .sources
        .iter()
        .filter(|s| ids.contains(s.id.as_str()))
        .collect();
    let b = cat::budget(
        &sources,
        env.entry_budget,
        env.memory_limit_bytes,
        env.compile_memory_bytes,
    );
    (b, sources)
}

/// The catalog with this node's state. `file_lists` are the lists the config files define:
/// `(name, url)`, for a source one of them already provides.
#[allow(clippy::too_many_lines)] // the catalog, its sources and the node's state, in one pass
pub fn catalog_view(b: &dyn Backend, env: &CategoryEnv) -> CategoriesView {
    let catalog = cat::catalog();
    let lists = b.lists();
    let contents = group_contents(b);
    let selections: Vec<GroupSelection> = contents
        .iter()
        .map(|(n, c)| selection_of(n, c, env.tier()))
        .collect();
    let file_lists: Vec<(String, String)> = b
        .config_entries(Some("list"))
        .into_iter()
        .filter(|e| e.source == "file")
        .filter_map(|e| {
            let url = e.definition?.get("url")?.as_str()?.to_owned();
            Some((e.name, url))
        })
        .collect();
    let used: std::collections::BTreeSet<&str> = selections
        .iter()
        .flat_map(|s| s.sources.iter().map(String::as_str))
        .collect();
    let sources: Vec<SourceView> = catalog
        .sources
        .iter()
        .map(|s| {
            let provided = file_lists
                .iter()
                .find(|(_, u)| cat::normalize_url(u) == cat::normalize_url(&s.url))
                .map(|(n, _)| n.clone());
            let list_name = provided.clone().unwrap_or_else(|| cat::list_name(&s.id));
            let info = lists.iter().find(|l| l.name == list_name);
            let state = SourceState {
                list: list_name,
                downloaded: info.is_some_and(|l| l.state == "ok"),
                state: match info {
                    Some(l) => l.state.clone(),
                    None if used.contains(s.id.as_str()) => "pending".to_owned(),
                    None => "unused".to_owned(),
                },
                bytes: info.map_or(0, |l| l.bytes),
                lines: info.map_or(0, |l| l.lines),
                last_changed_unix_seconds: info.and_then(|l| l.last_changed_unix_seconds),
                error: info.and_then(|l| l.error.clone()),
                provided_by: provided,
                snapshot_entries: info.map_or(0, |l| l.entries),
                unique_entries: info.map_or(0, |l| l.unique),
                also_in: info
                    .map(|l| l.overlap.iter().take(3).cloned().collect())
                    .unwrap_or_default(),
            };
            SourceView {
                id: s.id.clone(),
                name: s.name.clone(),
                maintainer: s.maintainer.clone(),
                url: s.url.clone(),
                format: format!("{:?}", s.format).to_lowercase(),
                licence: s.licence.clone(),
                licence_url: s.licence_url.clone(),
                attribution: s.attribution.clone(),
                homepage: s.homepage.clone(),
                cadence: format!("{:?}", s.cadence).to_lowercase(),
                entries: s.entries,
                bytes: s.bytes,
                weight: weight_word(s.weight).to_owned(),
                refresh_seconds: catalog.refresh_secs(s),
                checked: s.checked.clone(),
                pushed: s.pushed.clone(),
                categories: cat::categories_of_source(&s.id)
                    .iter()
                    .map(|c| c.id.clone())
                    .collect(),
                state,
            }
        })
        .collect();
    let groups = catalog
        .groups
        .iter()
        .map(|g| CategoryGroupView {
            id: g.id.clone(),
            name: g.name.clone(),
            categories: catalog
                .categories
                .iter()
                .filter(|c| c.group == g.id)
                .map(|c| category_view(c, &selections, env))
                .collect(),
        })
        .collect();
    let (total, _) = budget_of(&contents, env);
    CategoriesView {
        catalog_version: catalog.version.clone(),
        groups,
        sources,
        presets: catalog
            .presets
            .iter()
            .map(|p| PresetView {
                id: p.id.clone(),
                name: p.name.clone(),
                description: p.description.clone(),
                categories: p.categories.clone(),
            })
            .collect(),
        not_offered: catalog
            .not_offered
            .iter()
            .map(|n| NotOfferedView {
                name: n.name.clone(),
                group: n.group.clone(),
                reason: n.reason.clone(),
                alternative: n.alternative.clone(),
            })
            .collect(),
        attributions: catalog
            .sources
            .iter()
            .filter_map(|s| s.attribution.clone())
            .collect(),
        selections,
        total,
        node: env.clone(),
    }
}

fn category_view(
    c: &cat::Category,
    selections: &[GroupSelection],
    env: &CategoryEnv,
) -> CategoryView {
    let catalog = cat::catalog();
    let default_content = GroupContent::default();
    let default_sources: Vec<&cat::Source> = if c.kind == CategoryKind::List {
        catalog.category_sources(c, &default_content, env.tier())
    } else {
        Vec::new()
    };
    let all: Vec<&str> = catalog.all_source_ids(c);
    CategoryView {
        id: c.id.clone(),
        name: c.name.clone(),
        description: c.description.clone(),
        kind: match c.kind {
            CategoryKind::List => "list",
            CategoryKind::Service => "service",
        }
        .to_owned(),
        sources: c.sources.clone(),
        tier_kind: c.tier_kind.map(|k| {
            match k {
                cat::TierKind::Exclusive => "exclusive",
                cat::TierKind::Additive => "additive",
            }
            .to_owned()
        }),
        default_tier: c.default_tier.clone(),
        tier_from: c.tier_from.clone().map(|t| {
            if t == "ads_tier" {
                "adsTier".to_owned()
            } else {
                t
            }
        }),
        tiers: c
            .tier
            .iter()
            .map(|t| TierView {
                id: t.id.clone(),
                name: t.name.clone(),
                sources: t.sources.clone(),
            })
            .collect(),
        services: catalog
            .service_ids(c)
            .into_iter()
            .map(str::to_owned)
            .collect(),
        warn: c.warn.clone(),
        entries: default_sources.iter().map(|s| s.entries).sum(),
        heavy: all
            .iter()
            .filter_map(|id| catalog.source(id))
            .any(|s| catalog.is_heavy(s)),
        groups: selections
            .iter()
            .filter(|s| s.categories.contains(&c.id))
            .map(|s| s.group.clone())
            .collect(),
    }
}

/// The cost of `proposal` for `group` with every other group as it is.
fn proposal_budget(
    contents: &[(String, GroupContent)],
    group: &str,
    proposal: &GroupContent,
    env: &CategoryEnv,
) -> BudgetView {
    let mut with: Vec<(String, GroupContent)> = contents
        .iter()
        .filter(|(n, _)| n != group)
        .cloned()
        .collect();
    with.push((group.to_owned(), proposal.clone()));
    let (total, _) = budget_of(&with, env);
    let before: std::collections::BTreeSet<String> = {
        let (b, _) = budget_of(contents, env);
        b.sources.into_iter().collect()
    };
    let added: Vec<String> = total
        .sources
        .iter()
        .filter(|s| !before.contains(*s))
        .cloned()
        .collect();
    let catalog = cat::catalog();
    let heavy_added: Vec<String> = added
        .iter()
        .filter(|s| catalog.source(s).is_some_and(|x| catalog.is_heavy(x)))
        .cloned()
        .collect();
    let heavy_daily: u64 = heavy_added
        .iter()
        .filter_map(|s| catalog.source(s))
        .map(|s| {
            s.bytes
                .saturating_mul((86_400 / u64::from(catalog.refresh_secs(s).max(1))).max(1))
        })
        .sum();
    let group_sources = cat::selection(proposal, env.tier()).sources;
    let group_only = cat::budget(
        &group_sources,
        env.entry_budget,
        env.memory_limit_bytes,
        env.compile_memory_bytes,
    );
    let newly_over = total.over_budget
        && !{
            let (b, _) = budget_of(contents, env);
            b.over_budget
        };
    BudgetView {
        group: Some(group.to_owned()),
        confirmation_required: !heavy_added.is_empty() || newly_over,
        total,
        group_only: Some(group_only),
        added,
        heavy_added,
        heavy_daily_download_bytes: heavy_daily,
        node: env.clone(),
    }
}

// ----------------------------------------------------------------------------- the agent gate

/// REQ: FLT-901 (ADR-994 item 8) — a content change that downloads lists is for people: an agent
/// token may plan one (a dry run) but never apply it, unless this request is the replay of a plan
/// an operator approved. A heavy or over-budget selection is refused to an agent even as a plan:
/// the owner confirms the cost.
pub(crate) fn agent_gate(
    p: &Principal,
    ext: &axum::http::Extensions,
    dry_run: bool,
    budget: Option<&BudgetView>,
) -> Result<(), Problem> {
    if p.agent.is_none() || ext.get::<ApprovedContentPlan>().is_some() {
        return Ok(());
    }
    if !dry_run {
        return Err(Problem::new(
            Code::AgentNotAllowed,
            "an agent can plan a content change, not apply it",
        )
        .hint("Use plan_set_group_content; an operator approves the plan (Agent changes in the web UI) and apply_plan then replays it."));
    }
    if let Some(b) = budget
        && (b.confirmation_required || b.total.refused || b.total.over_budget)
    {
        return Err(Problem::new(
            Code::AgentNotAllowed,
            "this selection is heavy or over the entry budget, so an agent can't plan it",
        )
        .hint("A person confirms the cost in the web UI (Groups, Categories)."));
    }
    Ok(())
}

/// What a content write is checked against, and the budget it produced.
pub(crate) struct ContentCheck {
    pub(crate) budget: BudgetView,
}

/// Checks `content` for `group`: the catalog, the node's budget and the confirmation a heavy
/// selection needs (asked for with `confirm`; a dry run reports it instead).
pub(crate) fn check_content(
    backend: &dyn Backend,
    group: &str,
    info: &GroupContentInfo,
    confirm: bool,
    dry_run: bool,
) -> Result<ContentCheck, Problem> {
    let content = info
        .to_config()
        .map_err(|e| Problem::new(Code::InvalidConfig, format!("content: {e}")))?;
    let problems = cat::content_problems(&content);
    if !problems.is_empty() {
        let text: Vec<String> = problems
            .iter()
            .map(|(field, why)| format!("{field}: {why}"))
            .collect();
        return Err(Problem::new(Code::InvalidConfig, text.join("; "))
            .hint("`GET /api/v1/categories` lists the categories and their tiers."));
    }
    let env = backend.category_env();
    let contents = group_contents(backend);
    let budget = proposal_budget(&contents, group, &content, &env);
    // A selection already refused can still be reduced: refuse only a change that asks for more.
    let raises = budget.total.needed_bytes > budget_of(&contents, &env).0.needed_bytes;
    if budget.total.refused && raises {
        return Err(Problem::new(
            Code::BudgetRefused,
            budget
                .total
                .reasons
                .first()
                .cloned()
                .unwrap_or_else(|| "this node is too small for that selection".to_owned()),
        )
        .hint("Pick fewer or lighter categories, or use a node with more memory."));
    }
    if budget.confirmation_required && !confirm && !dry_run {
        let mb = budget.heavy_daily_download_bytes / 1_000_000;
        return Err(Problem::new(
            Code::ConfirmRequired,
            format!(
                "this selection is heavy: it adds {} entries ({} MB a day to download){}",
                budget.total.entries,
                mb,
                if budget.total.over_budget {
                    ", more than [filter] entry_budget"
                } else {
                    ""
                }
            ),
        )
        .hint("Send ?confirm=true to accept the cost."));
    }
    Ok(ContentCheck { budget })
}

/// REQ: FLT-901, FLT-902 — what `PUT /groups/{name}` does about `content`: a body that leaves it
/// out keeps the group's current content; one that changes it is checked like
/// `PUT /groups/{name}/content` (the catalog, the node's budget, the confirmation) and is a
/// person's (403 `agent_not_allowed` for an agent token, except as a dry run or an approved plan);
/// a group whose config file sets `content` can't change it here (409 `set_by_file`). Returns the
/// body to write.
pub(crate) async fn guard_group_put(
    backend: &Shared,
    ext: &axum::http::Extensions,
    name: &str,
    mut body: serde_json::Value,
    dry_run: bool,
    query: Option<&str>,
) -> Result<serde_json::Value, Problem> {
    let p = principal(ext)?;
    let confirm = wants_confirm(query);
    let dry_run = dry_run || is_dry_run(query);
    let has_content = body.get("content").is_some_and(|c| !c.is_null());
    if !has_content {
        // Left out: the backend keeps the content in the group's own entry (the files' when they
        // set it, else the stored one), never the effective group's, which can be derived.
        return Ok(body);
    }
    // The group's entry (its effective definition and what its files set): a cheap read, not the
    // profile list's statistics.
    let (bk, n) = (Arc::clone(backend), name.to_owned());
    let (current, file_sets) = crate::blocking(move || {
        let e = bk
            .config_entries(Some("group"))
            .into_iter()
            .find(|e| e.name == n);
        let current = e
            .as_ref()
            .and_then(|e| e.definition.as_ref())
            .and_then(|d| d.get("content"))
            .filter(|c| !c.is_null())
            .and_then(|c| serde_json::from_value::<GroupContentInfo>(c.clone()).ok());
        let file_sets = e
            .as_ref()
            .is_some_and(|e| e.set_by_file.iter().any(|k| k == "content"));
        Ok((current, file_sets))
    })
    .await?;
    let new: GroupContentInfo = serde_json::from_value(body["content"].clone())
        .map_err(|e| Problem::new(Code::InvalidConfig, format!("content: {e}")))?;
    let before = current.clone().unwrap_or_default();
    let norm = |c: &GroupContentInfo| {
        let mut c = c.clone();
        if c.level.is_empty() {
            "off".clone_into(&mut c.level);
        }
        c
    };
    if norm(&new) == norm(&before) {
        // The same content sent back (a GET then PUT): left out, so the backend keeps the entry's
        // own and a derived or file-set value isn't frozen into the override.
        if let Some(o) = body.as_object_mut() {
            o.remove("content");
        }
        return Ok(body);
    }
    agent_gate(&p, ext, dry_run, None)?;
    let (bk, n, nc) = (Arc::clone(backend), name.to_owned(), new.clone());
    let checked =
        crate::blocking(move || check_content(bk.as_ref(), &n, &nc, confirm, dry_run)).await?;
    agent_gate(&p, ext, dry_run, Some(&checked.budget))?;
    if file_sets {
        return Err(Problem::new(
            Code::SetByFile,
            format!("the config files set `content` for group `{name}`"),
        )
        .hint("Change it in the file; the API can't override a field a file sets."));
    }
    Ok(body)
}

fn wants_confirm(query: Option<&str>) -> bool {
    query.is_some_and(|q| {
        q.split('&')
            .any(|kv| matches!(kv, "confirm=true" | "confirm=1"))
    })
}

fn is_dry_run(query: Option<&str>) -> bool {
    query.is_some_and(|q| {
        q.split('&')
            .any(|kv| matches!(kv, "dryRun=true" | "dryRun=1"))
    })
}

// ----------------------------------------------------------------------------- the routes

pub(crate) fn read_routes(backend: Shared) -> Router {
    Router::new()
        .route("/api/v1/categories", get(categories))
        .route("/api/v1/categories/budget", get(categories_budget))
        .route("/api/v1/groups/{name}/content", get(get_group_content))
        .route("/api/v1/profiles/devices", get(profile_devices))
        .with_state(backend)
}

pub(crate) fn write_routes(backend: Shared, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/v1/groups/{name}/content", put(put_group_content))
        .route("/api/v1/groups/{name}/sources", put(put_group_sources))
        .with_state((backend, auth))
}

/// The content categories catalog (REQ: FLT-901).
///
/// Every category the catalog offers, grouped as the picker shows them, with its description,
/// tiers, entry counts and weight; every source with its maintainer, licence (an SPDX
/// identifier and a link), format, size and cadence, and what this node has done with it
/// (downloaded or not, how big, any error); the presets (`basic`); the categories not offered
/// and why; what each group selects now and what all of them cost together (distinct sources
/// counted once), against the node's memory limit and `[filter] entry_budget`. In a cluster the
/// numbers are the primary's, which downloads and compiles. Needs `config:read` for an agent.
#[utoipa::path(get, path = "/api/v1/categories", tag = "config",
    params(("view" = Option<String>, Query, description = "`compact`: IDs, names, tiers, sizes and licences without the prose and the links (for agents).")),
    responses((status = 200, body = CategoriesView, description = "The catalog and this node's state.")))]
pub(crate) async fn categories(State(b): State<Shared>, RawQuery(q): RawQuery) -> Response {
    let compact = query_pairs(&q.unwrap_or_default())
        .get("view")
        .is_some_and(|v| v == "compact");
    match crate::blocking(move || {
        let env = b.category_env();
        Ok(catalog_view(b.as_ref(), &env))
    })
    .await
    {
        Ok(v) if compact => Json(compact_view(&v)).into_response(),
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

/// REQ: AGT-001 (T24.29) - the catalog without the prose and the links: what an agent needs to
/// choose categories (IDs, names, kinds, tiers, sizes, licences, what each group selects, the
/// cost), small enough for a tool result.
fn compact_view(v: &CategoriesView) -> serde_json::Value {
    let keep = |o: &serde_json::Value, keys: &[&str]| {
        let mut m = serde_json::Map::new();
        for k in keys {
            if let Some(x) = o.get(*k) {
                m.insert((*k).to_owned(), x.clone());
            }
        }
        serde_json::Value::Object(m)
    };
    let full = serde_json::to_value(v).unwrap_or_default();
    let groups: Vec<serde_json::Value> = full["groups"]
        .as_array()
        .map(|gs| {
            gs.iter()
                .map(|g| {
                    let cats: Vec<serde_json::Value> = g["categories"]
                        .as_array()
                        .map(|cs| {
                            cs.iter()
                                .map(|c| {
                                    let mut m = keep(
                                        c,
                                        &[
                                            "id",
                                            "name",
                                            "kind",
                                            "tierKind",
                                            "defaultTier",
                                            "tierFrom",
                                            "entries",
                                            "heavy",
                                            "groups",
                                            "services",
                                        ],
                                    );
                                    m["tiers"] = c["tiers"]
                                        .as_array()
                                        .map(|t| t.iter().map(|x| x["id"].clone()).collect())
                                        .unwrap_or_default();
                                    m
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    serde_json::json!({"id": g["id"], "name": g["name"], "categories": cats})
                })
                .collect()
        })
        .unwrap_or_default();
    let sources: Vec<serde_json::Value> = full["sources"]
        .as_array()
        .map(|ss| {
            ss.iter()
                .map(|s| {
                    let mut m = keep(
                        s,
                        &["id", "name", "licence", "entries", "weight", "categories"],
                    );
                    m["state"] = s["state"]["state"].clone();
                    m
                })
                .collect()
        })
        .unwrap_or_default();
    serde_json::json!({
        "catalogVersion": full["catalogVersion"],
        "groups": groups,
        "sources": sources,
        "presets": full["presets"],
        "notOffered": full["notOffered"].as_array().map(|n| n.iter().map(|x| x["name"].clone()).collect::<Vec<_>>()),
        "selections": full["selections"],
        "total": full["total"],
        "node": full["node"],
    })
}

/// What a selection costs.
///
/// Entries, an estimate of the snapshot and compile memory, the daily download, and whether this
/// node may take it, for a proposed selection of one group (`group`, with `level`, `categories`
/// (comma separated), `tiers` (`gambling:extended,malware:full`) and `ads`; fields left out keep
/// the group's current value) or, with no `group`, for what the groups select now. Distinct
/// sources count once, across all groups. Nothing changes.
#[utoipa::path(get, path = "/api/v1/categories/budget", tag = "config",
    params(
        ("group" = Option<String>, Query, description = "The group the proposal is for (a name that does not exist yet is priced as a new group)."),
        ("level" = Option<String>, Query, description = "`off`, `basic` or `enhanced`."),
        ("categories" = Option<String>, Query, description = "Category IDs, comma separated."),
        ("tiers" = Option<String>, Query, description = "`category:tier` pairs, comma separated."),
        ("ads" = Option<bool>, Query, description = "Ad block.")),
    responses(
        (status = 200, body = BudgetView, description = "The cost."),
        (status = 422, body = Problem, description = "The proposal names something the catalog doesn't have.")))]
pub(crate) async fn categories_budget(State(b): State<Shared>, RawQuery(q): RawQuery) -> Response {
    let q = q.unwrap_or_default();
    match crate::blocking(move || budget_read(b.as_ref(), &q)).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

fn query_pairs(q: &str) -> BTreeMap<String, String> {
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), percent_decode(v)))
        .collect()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                if let Some(v) = s
                    .get(i + 1..i + 3)
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    out.push(v);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn budget_read(b: &dyn Backend, q: &str) -> Result<BudgetView, Problem> {
    let env = b.category_env();
    let contents = group_contents(b);
    let params = query_pairs(q);
    let Some(group) = params.get("group").filter(|g| !g.is_empty()) else {
        let (total, _) = budget_of(&contents, &env);
        return Ok(BudgetView {
            group: None,
            total,
            group_only: None,
            added: Vec::new(),
            heavy_added: Vec::new(),
            heavy_daily_download_bytes: 0,
            confirmation_required: false,
            node: env,
        });
    };
    let current = contents
        .iter()
        .find(|(n, _)| n == group)
        .map(|(_, c)| GroupContentInfo::from_config(c))
        // A group that does not exist yet is a new profile: priced as one more group.
        .unwrap_or_default();
    let input = ContentInput {
        level: params.get("level").cloned(),
        categories: params.get("categories").map(|v| {
            v.split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        }),
        tiers: params.get("tiers").map(|v| {
            v.split(',')
                .filter_map(|p| p.split_once(':'))
                .map(|(k, t)| (k.to_owned(), t.to_owned()))
                .collect()
        }),
        ads: params.get("ads").map(|v| v == "true" || v == "1"),
    };
    let info = input.applied_to(&current);
    let content = info
        .to_config()
        .map_err(|e| Problem::new(Code::InvalidConfig, format!("content: {e}")))?;
    let problems = cat::content_problems(&content);
    if !problems.is_empty() {
        let text: Vec<String> = problems.iter().map(|(f, w)| format!("{f}: {w}")).collect();
        return Err(Problem::new(Code::InvalidConfig, text.join("; ")));
    }
    Ok(proposal_budget(&contents, group, &content, &env))
}

/// A group's content (REQ: FLT-902).
///
/// The level, the categories, the tiers and the ad block switch of one group, which sources they
/// make the node use, and what that costs. A group with no content is `off` with nothing
/// selected. Needs `config:read` for an agent.
#[utoipa::path(get, path = "/api/v1/groups/{name}/content", tag = "config",
    params(("name" = String, Path, description = "The group.")),
    responses(
        (status = 200, body = GroupContentView, description = "The group's content."),
        (status = 404, body = Problem, description = "No such group.")))]
pub(crate) async fn get_group_content(
    State(b): State<Shared>,
    Path(name): Path<String>,
) -> Response {
    match crate::blocking(move || group_content_view(b.as_ref(), &name)).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

fn group_content_view(b: &dyn Backend, name: &str) -> Result<GroupContentView, Problem> {
    let env = b.category_env();
    let contents = group_contents(b);
    let Some((_, c)) = contents.iter().find(|(n, _)| n == name) else {
        return Err(Problem::not_found(format!("no group `{name}`")));
    };
    let (budget, _) = budget_of(&contents, &env);
    Ok(GroupContentView {
        group: name.to_owned(),
        content: GroupContentInfo::from_config(c),
        selection: selection_of(name, c, env.tier()),
        summary: cat::summary(Some(c)),
        budget,
    })
}

/// Set a group's content (REQ: FLT-902).
///
/// Changes the level, the categories, the tiers or the ad block of a group; fields left out keep
/// their current value. Checked against the catalog and what the node can hold: a selection the
/// node is too small for is refused (422 `budget_refused`, with the reason), and a heavy one, or
/// one over `[filter] entry_budget`, needs `?confirm=true` after the cost is shown (409
/// `confirm_required`; a dry run reports `confirmationRequired` instead). The node downloads
/// each source once however many groups select it and deletes it when the last one stops.
/// Operators change it; **an agent token is refused (403 `agent_not_allowed`) except for a
/// dry run, and `apply_plan` replays only a plan an operator approved**. A group whose config
/// file sets `content` is read-only here (409 `set_by_file`). In a cluster the primary stores it,
/// downloads and compiles. Supports `dryRun`, `If-Match` and `Idempotency-Key`.
#[utoipa::path(put, path = "/api/v1/groups/{name}/content", tag = "config",
    params(
        ("name" = String, Path, description = "The group."),
        ("confirm" = Option<bool>, Query, description = "Accept the cost of a heavy selection."),
        crate::config_api::DryRun),
    request_body = ContentInput,
    responses(
        (status = 200, body = crate::model::ConfigChange, description = "Applied (or, with dryRun, what would change); `budget` and `confirmationRequired` say what it costs."),
        (status = 403, body = Problem, description = "An agent token (`agent_not_allowed`)."),
        (status = 404, body = Problem, description = "No such group."),
        (status = 409, body = Problem, description = "`confirm_required` (heavy), or `set_by_file`."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version."),
        (status = 422, body = Problem, description = "The catalog doesn't have it (`invalid_config`), or this node is too small (`budget_refused`)."),
    ))]
#[allow(clippy::too_many_arguments)] // an extractor per input, like every config write
pub(crate) async fn put_group_content(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
    axum::extract::Query(q): axum::extract::Query<crate::config_api::DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<ContentInput>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let input = match crate::auth::routes::body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let p = match principal(&ext) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let dry_run = q.dry_run.unwrap_or(false) || is_dry_run(query.as_deref());
    let confirm = wants_confirm(query.as_deref());
    // An agent without an approved plan may plan (a dry run) and no more: refused before the
    // group is even looked at.
    if let Err(e) = agent_gate(&p, &ext, dry_run, None) {
        return e.into_response();
    }
    let (bk, gname) = (Arc::clone(&backend), name.clone());
    let prepared = crate::blocking(move || {
        let current = group_contents(bk.as_ref())
            .into_iter()
            .find(|(n, _)| *n == gname)
            .map(|(_, c)| GroupContentInfo::from_config(&c))
            .ok_or_else(|| Problem::not_found(format!("no group `{gname}`")))?;
        let info = input.applied_to(&current);
        let unchanged = info == current;
        let checked = check_content(bk.as_ref(), &gname, &info, confirm, dry_run)?;
        let entry = bk
            .config_entries(Some("group"))
            .into_iter()
            .find(|e| e.name == gname);
        Ok((info, checked, entry, unchanged))
    })
    .await;
    let (info, checked, entry, unchanged) = match prepared {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = agent_gate(&p, &ext, dry_run, Some(&checked.budget)) {
        return e.into_response();
    }
    // What the file already says is no change: only a different content is refused.
    if let Some(e) = &entry
        && !unchanged
        && e.set_by_file.iter().any(|k| k == "content")
    {
        return Problem::new(
            Code::SetByFile,
            format!("the config files set `content` for group `{name}`"),
        )
        .hint("Change it in the file; the API can't override a field a file sets.")
        .into_response();
    }
    // The whole group as it is, with the new content: a group write replaces the entry.
    let mut def = entry
        .and_then(|e| e.definition)
        .and_then(|d| match d {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();
    def.remove("name");
    def.insert(
        "content".to_owned(),
        serde_json::to_value(content_for_config(&info)).unwrap_or_default(),
    );
    let request = format!(
        "PUT /groups/{name}/content {}",
        serde_json::to_string(&info).unwrap_or_default()
    );
    let resp = crate::config_api::write_group_entry(
        backend,
        auth,
        headers,
        ext,
        crate::config_api::write_opts(&q, dry_run),
        request,
        name,
        serde_json::Value::Object(def),
    )
    .await;
    attach_budget(resp, &checked.budget).await
}

/// Set who a group applies to (REQ: FLT-902, API-010).
///
/// The group's networks (CIDRs) and router names, and the devices in it, as one change: a device
/// in `devices` is a named device (created if new, with its `match` keys) whose groups include
/// this one; a device that was a member and is not listed leaves the group. Fields left out are
/// not changed. The group and the devices are stored in one transaction under one configuration
/// version. The dry run says what moves ("3 devices move from Default to Kids") and what a device
/// that is also in another profile means (the lists are the union, the settings come from the
/// higher priority). A device a config file defines can't be moved (409 `set_by_file`). Operators
/// only; agent tokens are refused (403 `agent_not_allowed`). Supports `dryRun`, `If-Match` and
/// `Idempotency-Key`.
#[utoipa::path(put, path = "/api/v1/groups/{name}/sources", tag = "config",
    params(("name" = String, Path, description = "The group."), crate::config_api::DryRun),
    request_body = Object,
    responses(
        (status = 200, body = crate::model::ConfigChange, description = "Applied (or, with dryRun, what would change): `impact` says what moves."),
        (status = 403, body = Problem, description = "An agent token (`agent_not_allowed`)."),
        (status = 404, body = Problem, description = "No such group."),
        (status = 409, body = Problem, description = "A device is defined in a config file (`set_by_file`)."),
        (status = 412, body = Problem, description = "The configuration changed since the If-Match version."),
        (status = 422, body = Problem, description = "A network, name or key is wrong."),
    ))]
pub(crate) async fn put_group_sources(
    State((backend, auth)): State<(Shared, Arc<Auth>)>,
    Path(name): Path<String>,
    axum::extract::Query(q): axum::extract::Query<crate::config_api::DryRun>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    b: Result<Json<serde_json::Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let input = match crate::auth::routes::body(b) {
        Ok(i) => i,
        Err(p) => return p.into_response(),
    };
    let request = format!("PUT /groups/{name}/sources {input}");
    crate::config_api::write_group_sources(
        backend,
        auth,
        headers,
        ext,
        crate::config_api::write_opts(&q, q.dry_run.unwrap_or(false)),
        request,
        name,
        input,
    )
    .await
}

/// The config's JSON for `content` (`snake_case` keys, the level word).
fn content_for_config(info: &GroupContentInfo) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("level".into(), info.level.clone().into());
    if !info.categories.is_empty() {
        m.insert("categories".into(), info.categories.clone().into());
    }
    if !info.tiers.is_empty() {
        m.insert(
            "tiers".into(),
            serde_json::to_value(&info.tiers).unwrap_or_default(),
        );
    }
    if info.ads {
        m.insert("ads".into(), true.into());
    }
    serde_json::Value::Object(m)
}

/// Adds the budget to a successful write's JSON answer.
async fn attach_budget(resp: Response, budget: &BudgetView) -> Response {
    if !resp.status().is_success() {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 8 << 20).await else {
        return Problem::internal("the answer could not be read").into_response();
    };
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.insert(
            "budget".into(),
            serde_json::to_value(&budget.total).unwrap_or_default(),
        );
        o.insert(
            "confirmationRequired".into(),
            budget.confirmation_required.into(),
        );
        o.insert(
            "heavyDailyDownloadBytes".into(),
            budget.heavy_daily_download_bytes.into(),
        );
    }
    let mut r = Json(v).into_response();
    *r.status_mut() = parts.status;
    for (k, val) in &parts.headers {
        if k != axum::http::header::CONTENT_LENGTH && k != axum::http::header::CONTENT_TYPE {
            r.headers_mut().insert(k.clone(), val.clone());
        }
    }
    r
}

/// The picker's networks and devices (REQ: FLT-902).
///
/// The networks the Networks page names and the devices the Clients page knows (configured ones
/// and ones only seen), each with an icon (a device class), the keys it can be recognized by, a
/// flag on a MAC that is a private Wi-Fi address (it can change, so a profile may stop following
/// it), and the group it is in now. Needs `config:read` for an agent.
#[utoipa::path(get, path = "/api/v1/profiles/devices", tag = "config",
    responses((status = 200, body = ProfileDevices, description = "The picker's data.")))]
pub(crate) async fn profile_devices(State(b): State<Shared>) -> Response {
    match crate::blocking(move || Ok(b.profile_devices())).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

/// REQ: FLT-902 — what a group's `content` summary says (for the audit line and the profile list).
pub fn content_summary(c: Option<&GroupContentInfo>) -> String {
    cat::summary(c.and_then(|c| c.to_config().ok()).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: FLT-902 (ADR-910) — the locally administered bit marks a private Wi-Fi address.
    #[test]
    fn flt_902_picker_marks_randomised_mac() {
        assert!(mac_is_randomized("da:a1:19:00:00:01"));
        assert!(mac_is_randomized("DA-A1-19-00-00-01"));
        assert!(!mac_is_randomized("b8:27:eb:00:00:01"));
        assert!(!mac_is_randomized("not a mac"));
    }

    #[test]
    fn flt_901_query_decoding() {
        assert_eq!(percent_decode("a%2Cb+c"), "a,b c");
        let q = query_pairs("group=kids&categories=adult%2Cgambling&ads=true");
        assert_eq!(q["categories"], "adult,gambling");
        assert!(wants_confirm(Some("a=1&confirm=true")));
        assert!(!wants_confirm(Some("confirmed=true")));
        assert!(is_dry_run(Some("dryRun=true")));
    }
}

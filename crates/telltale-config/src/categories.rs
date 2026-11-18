//! Content categories (REQ: FLT-901, FLT-902; ADR-994, ADR-995; T24.29): a catalog of named
//! categories (adult content, gambling, malware, ad block, ...), each backed by one or more
//! maintained open lists, shipped as data (`presets/categories/*.toml`) and compiled into the
//! binary. The binary carries only the catalog (names, URLs, licences, sizes), never a list: a
//! node downloads a source from its maintainer while a group uses it.
//!
//! A group turns categories on with `content = { level, categories, tiers, ads }`. [`expand`]
//! adds each source a group uses as a managed list named `cat-<source-id>` (fetched once however
//! many groups use it, and gone when the last user goes), the way [`crate::services::expand`]
//! adds blocked services. Category lists are never part of a group's "every enabled list" default
//! (the policy layer names the lists each group wants, see [`group_lists`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::schema::{
    AdsTier, Config, ContentLevel, FilterList, GroupConfig, GroupContent, ListKind, ListMatch,
    ListMode,
};
use crate::types::{ByteSize, SafeString};

/// List names beginning with this belong to the catalog (users' lists can't define them).
pub const PREFIX: &str = "cat-";

const FILES: &[&str] = &[
    include_str!("../../../presets/categories/catalog.toml"),
    include_str!("../../../presets/categories/adult-sensitive.toml"),
    include_str!("../../../presets/categories/ai-crypto.toml"),
    include_str!("../../../presets/categories/culture-entertainment.toml"),
    include_str!("../../../presets/categories/networking.toml"),
    include_str!("../../../presets/categories/risky-domains.toml"),
    include_str!("../../../presets/categories/security-threats.toml"),
    include_str!("../../../presets/categories/privacy-ads.toml"),
    include_str!("../../../presets/categories/not-offered.toml"),
];

/// A group of categories in the picker ("Adult and Sensitive Content").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogGroup {
    pub id: String,
    pub name: String,
    pub order: u32,
}

/// `list` (a maintained list behind it) or `service` (an authored FLT-012 bundle, turned on with
/// the group's `blocked_services`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CategoryKind {
    #[default]
    List,
    Service,
}

/// How a category's tiers combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierKind {
    /// Exactly one tier's sources are active (a bigger list replaces a smaller one).
    Exclusive,
    /// A chosen tier's sources are added to the category's own.
    Additive,
}

/// One tier of a category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tier {
    pub id: String,
    pub name: String,
    pub sources: Vec<String>,
}

/// One category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Category {
    /// Lowercase letters, digits and `-`, used in `content.categories`.
    pub id: String,
    pub name: String,
    /// The [`CatalogGroup`] it sits in.
    pub group: String,
    /// One line for the info icon.
    pub description: String,
    #[serde(default)]
    pub kind: CategoryKind,
    /// Source IDs that are always active.
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub tier_kind: Option<TierKind>,
    #[serde(default)]
    pub default_tier: Option<String>,
    /// `ads_tier`: the tier is the `[filter]` setting of that name, not a per-group choice.
    #[serde(default)]
    pub tier_from: Option<String>,
    #[serde(default)]
    pub tier: Vec<Tier>,
    /// For `kind = "service"`: the FLT-012 services whose `category` is this.
    #[serde(default)]
    pub service_category: Option<String>,
    /// A warning the confirmation repeats (a category that blocks whole top-level domains).
    #[serde(default)]
    pub warn: Option<String>,
}

/// A list's syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Domains,
    Adblock,
    Hosts,
}

/// How often the maintainer publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cadence {
    Daily,
    Low,
}

/// Whether a source is heavy (above [`Measured::heavy_threshold`] entries).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Weight {
    Light,
    Heavy,
}

/// The file name changes, so the URL is found through a small JSON file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Resolve {
    MetaJson,
}

/// One downloadable source, with the facts checked when the catalog was built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub name: String,
    pub maintainer: String,
    pub url: String,
    pub format: Format,
    /// SPDX licence identifier.
    pub licence: String,
    pub licence_url: String,
    /// A line shown next to the checkbox (CC BY-SA sources).
    #[serde(default)]
    pub attribution: Option<String>,
    pub homepage: String,
    pub cadence: Cadence,
    /// From the file's own header when the catalog was built.
    pub entries: u64,
    pub bytes: u64,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    pub weight: Weight,
    #[serde(default)]
    pub resolve: Option<Resolve>,
    /// With `resolve`: a resolved URL must start with this, or it is refused.
    #[serde(default)]
    pub url_prefix: Option<String>,
    /// The day the licence, recency and archived flag were last checked (YYYY-MM-DD).
    pub checked: String,
    /// The maintainer's last push on that day.
    pub pushed: String,
    pub archived: bool,
}

/// A named selection of categories (`basic`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub id: String,
    pub name: String,
    pub description: String,
    pub categories: Vec<String>,
}

/// A category the catalog does not offer, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotOffered {
    pub name: String,
    pub group: String,
    pub reason: String,
    #[serde(default)]
    pub alternative: Option<String>,
}

/// What a Pi-class node was measured to need (design section 2.4); the budget rule reads these.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measured {
    /// Resident set of a node with no category list.
    pub baseline_rss_bytes: u64,
    /// Snapshot bytes per distinct domain.
    pub bytes_per_domain: u64,
    /// Compile peak = `min(source bytes x factor, merge budget)`.
    pub compile_peak_factor: f64,
    /// A source above this many entries is heavy.
    pub heavy_threshold: u64,
    pub light_refresh_secs: u32,
    pub heavy_refresh_secs: u32,
}

impl Default for Measured {
    fn default() -> Self {
        Self {
            baseline_rss_bytes: 32 * 1024 * 1024,
            bytes_per_domain: 12,
            compile_peak_factor: 2.0,
            heavy_threshold: 500_000,
            light_refresh_secs: 28_800,
            heavy_refresh_secs: 86_400,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct File {
    catalog_version: Option<String>,
    group: Vec<CatalogGroup>,
    category: Vec<Category>,
    source: Vec<Source>,
    preset: Vec<Preset>,
    not_offered: Vec<NotOffered>,
    measured: Option<Measured>,
}

/// The whole catalog.
#[derive(Debug, Clone, PartialEq)]
pub struct Catalog {
    pub version: String,
    pub groups: Vec<CatalogGroup>,
    pub categories: Vec<Category>,
    pub sources: Vec<Source>,
    pub presets: Vec<Preset>,
    pub not_offered: Vec<NotOffered>,
    pub measured: Measured,
}

impl Catalog {
    /// Parses catalog files (REQ: FLT-901; also the fuzz target's entry point). Groups sort by
    /// `order`; categories and sources keep file order.
    pub fn parse(files: &[&str]) -> Result<Self, String> {
        let mut out = Self {
            version: String::new(),
            groups: Vec::new(),
            categories: Vec::new(),
            sources: Vec::new(),
            presets: Vec::new(),
            not_offered: Vec::new(),
            measured: Measured::default(),
        };
        for (i, text) in files.iter().enumerate() {
            let f: File = toml::from_str(text).map_err(|e| format!("catalog file {i}: {e}"))?;
            if let Some(v) = f.catalog_version {
                out.version = v;
            }
            if let Some(m) = f.measured {
                out.measured = m;
            }
            out.groups.extend(f.group);
            out.categories.extend(f.category);
            out.sources.extend(f.source);
            out.presets.extend(f.preset);
            out.not_offered.extend(f.not_offered);
        }
        out.groups.sort_by_key(|g| g.order);
        Ok(out)
    }

    pub fn category(&self, id: &str) -> Option<&Category> {
        self.categories.iter().find(|c| c.id == id)
    }

    pub fn source(&self, id: &str) -> Option<&Source> {
        self.sources.iter().find(|s| s.id == id)
    }

    pub fn preset(&self, id: &str) -> Option<&Preset> {
        self.presets.iter().find(|p| p.id == id)
    }

    /// The source a `cat-<id>` list stands for.
    pub fn source_of_list(&self, list: &str) -> Option<&Source> {
        list.strip_prefix(PREFIX).and_then(|id| self.source(id))
    }

    /// Whether `source` is heavy by this catalog's threshold.
    pub fn is_heavy(&self, s: &Source) -> bool {
        s.entries > self.measured.heavy_threshold
    }

    /// How often `s` is refreshed: heavy sources, and ones their maintainer rarely changes, at
    /// most daily (ADR-995 item 6).
    pub fn refresh_secs(&self, s: &Source) -> u32 {
        if self.is_heavy(s) || s.cadence == Cadence::Low {
            self.measured.heavy_refresh_secs
        } else {
            self.measured.light_refresh_secs
        }
    }

    /// Every source ID a category can use (its own, and all its tiers').
    pub fn all_source_ids<'a>(&self, c: &'a Category) -> Vec<&'a str> {
        let mut out: Vec<&str> = c.sources.iter().map(String::as_str).collect();
        for t in &c.tier {
            out.extend(t.sources.iter().map(String::as_str));
        }
        out
    }

    /// The tier a category uses for `content`: the ads size for the ads category, else the group's
    /// choice, else the default. `None` for an additive category with no tier chosen.
    pub fn tier_for<'a>(
        &self,
        c: &'a Category,
        content: &GroupContent,
        ads_tier: AdsTier,
    ) -> Option<&'a Tier> {
        let want = if c.tier_from.as_deref() == Some("ads_tier") {
            Some(ads_tier.id().to_owned())
        } else {
            content
                .tiers
                .get(&c.id)
                .cloned()
                .or_else(|| c.default_tier.clone())
        }?;
        c.tier.iter().find(|t| t.id == want)
    }

    /// The sources a category adds for `content`, in order.
    pub fn category_sources<'a>(
        &'a self,
        c: &'a Category,
        content: &GroupContent,
        ads_tier: AdsTier,
    ) -> Vec<&'a Source> {
        let mut ids: Vec<&str> = c.sources.iter().map(String::as_str).collect();
        if let Some(t) = self.tier_for(c, content, ads_tier) {
            ids.extend(t.sources.iter().map(String::as_str));
        }
        ids.into_iter().filter_map(|id| self.source(id)).collect()
    }

    /// The FLT-012 services a service-kind category stands for.
    pub fn service_ids(&self, c: &Category) -> Vec<&'static str> {
        let Some(sc) = c.service_category.as_deref() else {
            return Vec::new();
        };
        crate::services::catalog()
            .iter()
            .filter(|s| s.category == sc)
            .map(|s| s.id.as_str())
            .collect()
    }

    /// Everything wrong with the catalog as written (a data mistake the tests catch).
    #[allow(clippy::too_many_lines)] // a flat list of independent checks
    pub fn problems(&self) -> Vec<String> {
        let mut p = Vec::new();
        let dup = |what: &str, ids: Vec<&str>, p: &mut Vec<String>| {
            let mut seen = BTreeSet::new();
            for id in ids {
                if !seen.insert(id) {
                    p.push(format!("{what} `{id}` is defined twice"));
                }
            }
        };
        dup(
            "group",
            self.groups.iter().map(|g| g.id.as_str()).collect(),
            &mut p,
        );
        dup(
            "category",
            self.categories.iter().map(|c| c.id.as_str()).collect(),
            &mut p,
        );
        dup(
            "source",
            self.sources.iter().map(|s| s.id.as_str()).collect(),
            &mut p,
        );
        dup(
            "preset",
            self.presets.iter().map(|s| s.id.as_str()).collect(),
            &mut p,
        );
        for c in &self.categories {
            let id = &c.id;
            if id.is_empty()
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                p.push(format!(
                    "category `{id}`: the ID is lowercase letters, digits and `-`"
                ));
            }
            if !self.groups.iter().any(|g| g.id == c.group) {
                p.push(format!("category `{id}`: no group `{}`", c.group));
            }
            match c.kind {
                CategoryKind::Service => {
                    if self.service_ids(c).is_empty() {
                        p.push(format!(
                            "category `{id}`: no services in its service category"
                        ));
                    }
                    if !c.sources.is_empty() || !c.tier.is_empty() {
                        p.push(format!(
                            "category `{id}`: a service category has no sources"
                        ));
                    }
                }
                CategoryKind::List => {
                    if c.sources.is_empty() && c.tier.is_empty() {
                        p.push(format!("category `{id}` is empty: no sources"));
                    }
                    for s in self.all_source_ids(c) {
                        if self.source(s).is_none() {
                            p.push(format!("category `{id}`: no source `{s}`"));
                        }
                    }
                    if !c.tier.is_empty() {
                        match c.tier_kind {
                            None => p.push(format!("category `{id}`: tiers need a tier_kind")),
                            Some(TierKind::Exclusive) => {
                                let ok = c
                                    .default_tier
                                    .as_deref()
                                    .is_some_and(|d| c.tier.iter().any(|t| t.id == d));
                                if !ok {
                                    p.push(format!(
                                        "category `{id}`: an exclusive tier set needs a default_tier that exists"
                                    ));
                                }
                            }
                            Some(TierKind::Additive) => {
                                if c.sources.is_empty() {
                                    p.push(format!(
                                        "category `{id}`: an additive tier needs a base source"
                                    ));
                                }
                                if c.default_tier.is_some() {
                                    p.push(format!(
                                        "category `{id}`: an additive tier is off by default"
                                    ));
                                }
                            }
                        }
                        let mut seen = BTreeSet::new();
                        for t in &c.tier {
                            if !seen.insert(&t.id) || t.sources.is_empty() {
                                p.push(format!(
                                    "category `{id}`: tier `{}` is empty or repeated",
                                    t.id
                                ));
                            }
                        }
                    }
                    if c.tier_from.as_deref().is_some_and(|t| t != "ads_tier") {
                        p.push(format!("category `{id}`: tier_from is only `ads_tier`"));
                    }
                }
            }
        }
        for g in &self.groups {
            if !self.categories.iter().any(|c| c.group == g.id) {
                p.push(format!("group `{}` has no categories", g.id));
            }
        }
        for s in &self.sources {
            let id = &s.id;
            if id.is_empty()
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                p.push(format!(
                    "source `{id}`: the ID is lowercase letters, digits and `-`"
                ));
            }
            if format!("{PREFIX}{id}").len() > 64 {
                p.push(format!(
                    "source `{id}`: its list name is over 64 characters"
                ));
            }
            if s.licence.trim().is_empty() {
                p.push(format!("source `{id}`: no SPDX licence"));
            }
            if !s.url.starts_with("https://") {
                p.push(format!("source `{id}`: the URL is not https"));
            }
            if !s.licence_url.starts_with("https://") || !s.homepage.starts_with("https://") {
                p.push(format!(
                    "source `{id}`: licence_url and homepage are https links"
                ));
            }
            if s.entries == 0 || s.bytes == 0 {
                p.push(format!(
                    "source `{id}`: entries and bytes are read from the file header"
                ));
            }
            let heavy = self.is_heavy(s);
            if heavy != (s.weight == Weight::Heavy) {
                p.push(format!(
                    "source `{id}`: weight says {:?} but {} entries is {}",
                    s.weight,
                    s.entries,
                    if heavy { "heavy" } else { "light" }
                ));
            }
            match (s.resolve, &s.url_prefix) {
                (Some(_), None) => p.push(format!("source `{id}`: `resolve` needs a url_prefix")),
                (None, Some(_)) => p.push(format!("source `{id}`: url_prefix without `resolve`")),
                (Some(_), Some(prefix)) => {
                    if !prefix.starts_with("https://") || !prefix.ends_with('/') {
                        p.push(format!(
                            "source `{id}`: url_prefix is an https URL ending in `/`"
                        ));
                    }
                }
                (None, None) => {}
            }
            if !self
                .categories
                .iter()
                .any(|c| self.all_source_ids(c).contains(&id.as_str()))
            {
                p.push(format!("source `{id}` is used by no category"));
            }
            if s.attribution.is_none() && s.licence.starts_with("CC-BY") {
                p.push(format!(
                    "source `{id}`: a CC BY licence needs an attribution line"
                ));
            }
        }
        for pr in &self.presets {
            for c in &pr.categories {
                match self.category(c) {
                    None => p.push(format!("preset `{}`: no category `{c}`", pr.id)),
                    Some(c) if c.kind == CategoryKind::Service => {
                        p.push(format!(
                            "preset `{}`: `{}` is a service category",
                            pr.id, c.id
                        ));
                    }
                    Some(_) => {}
                }
            }
        }
        for n in &self.not_offered {
            if n.reason.trim().is_empty() {
                p.push(format!("not offered `{}`: no reason", n.name));
            }
            if self
                .categories
                .iter()
                .any(|c| c.name.eq_ignore_ascii_case(&n.name))
            {
                p.push(format!("`{}` is both offered and not offered", n.name));
            }
        }
        p
    }
}

/// The catalog compiled into the binary. A broken data file is a build-time mistake that the
/// tests catch, so it yields an empty catalog rather than a panic.
pub fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        Catalog::parse(FILES).unwrap_or_else(|_| Catalog {
            version: String::new(),
            groups: Vec::new(),
            categories: Vec::new(),
            sources: Vec::new(),
            presets: Vec::new(),
            not_offered: Vec::new(),
            measured: Measured::default(),
        })
    })
}

/// The list a source compiles to when this node downloads it itself.
pub fn list_name(source_id: &str) -> String {
    format!("{PREFIX}{source_id}")
}

/// True for a list name the catalog owns.
pub fn is_category_list(name: &str) -> bool {
    name.starts_with(PREFIX)
}

/// The source a `cat-` list name stands for.
pub fn source_of_list(name: &str) -> Option<&'static Source> {
    catalog().source_of_list(name)
}

/// The categories that include this source (a source can back several: TIF backs malware,
/// phishing and scam), in catalog order.
pub fn categories_of_source(source_id: &str) -> Vec<&'static Category> {
    let c = catalog();
    c.categories
        .iter()
        .filter(|cat| c.all_source_ids(cat).contains(&source_id))
        .collect()
}

/// The category names a `cat-` list stands for, for a block reason ("Malware, Phishing or Scam").
pub fn label_of_list(list: &str) -> Option<String> {
    let src = source_of_list(list)?;
    let names: Vec<&str> = categories_of_source(&src.id)
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    let (tail, init) = names.split_last()?;
    Some(if init.is_empty() {
        (*tail).to_owned()
    } else {
        format!("{} or {tail}", init.join(", "))
    })
}

/// `https://Host/path` with the scheme and host lowercased and a lone trailing slash dropped:
/// two spellings of one URL are one source.
pub fn normalize_url(url: &str) -> String {
    let url = url.trim();
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let (host, path) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    let path = if path == "/" { "" } else { path };
    format!(
        "{}://{}{path}",
        scheme.to_ascii_lowercase(),
        host.to_ascii_lowercase()
    )
}

/// What a group selects.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Selection {
    /// List-kind categories in effect (the level's, plus `ads`), catalog order, each once.
    pub categories: Vec<&'static Category>,
    /// The distinct sources they use, in catalog order.
    pub sources: Vec<&'static Source>,
    /// IDs in `content.categories` this version does not know or cannot use (a service
    /// category belongs in `blocked_services`), in the order written.
    pub unknown: Vec<String>,
}

/// What `content` selects, with `ads_tier` as the ads size. `off` selects no category (the
/// list stays in `content.categories`); `ads` is independent of the level.
pub fn selection(content: &GroupContent, ads_tier: AdsTier) -> Selection {
    let cat = catalog();
    let mut ids: Vec<String> = match content.level {
        ContentLevel::Off => Vec::new(),
        ContentLevel::Basic => cat
            .preset("basic")
            .map(|p| p.categories.clone())
            .unwrap_or_default(),
        ContentLevel::Enhanced => content.categories.iter().map(ToString::to_string).collect(),
    };
    if content.ads {
        ids.push("ads".to_owned());
    }
    let mut out = Selection::default();
    let mut chosen: BTreeSet<&str> = BTreeSet::new();
    for id in &ids {
        match cat.category(id) {
            Some(c) if c.kind == CategoryKind::List => {
                chosen.insert(c.id.as_str());
            }
            _ => {
                if !out.unknown.contains(id) {
                    out.unknown.push(id.clone());
                }
            }
        }
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for c in &cat.categories {
        if !chosen.contains(c.id.as_str()) {
            continue;
        }
        out.categories.push(c);
        for s in cat.category_sources(c, content, ads_tier) {
            if seen.insert(s.id.as_str()) {
                out.sources.push(s);
            }
        }
    }
    // Catalog order of the sources, not of the first category that names them, so the compiled
    // snapshot doesn't change with the order a person ticked boxes.
    out.sources
        .sort_by_key(|s| cat.sources.iter().position(|x| x.id == s.id));
    out
}

/// What `g` selects (`None` content selects nothing).
pub fn group_selection(g: &GroupConfig, ads_tier: AdsTier) -> Selection {
    g.content
        .as_ref()
        .map(|c| selection(c, ads_tier))
        .unwrap_or_default()
}

/// The sources any group of `cfg` uses, distinct, in catalog order.
pub fn used_sources(cfg: &Config) -> Vec<&'static Source> {
    let cat = catalog();
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    for g in &cfg.group {
        for s in group_selection(g, cfg.filter.ads_tier).sources {
            ids.insert(s.id.as_str());
        }
    }
    cat.sources
        .iter()
        .filter(|s| ids.contains(s.id.as_str()))
        .collect()
}

/// Categories any group of `cfg` selects, catalog order, each once.
pub fn used_categories(cfg: &Config) -> Vec<&'static Category> {
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    for g in &cfg.group {
        for c in group_selection(g, cfg.filter.ads_tier).categories {
            ids.insert(c.id.as_str());
        }
    }
    catalog()
        .categories
        .iter()
        .filter(|c| ids.contains(c.id.as_str()))
        .collect()
}

/// A list the files (or the store) define that has a catalog source's URL: it provides that
/// source, so the category does not download it a second time (the bundles' `hagezi-pro`).
pub fn provider<'a>(cfg: &'a Config, source: &Source) -> Option<&'a FilterList> {
    let want = normalize_url(&source.url);
    cfg.list.iter().find(|l| {
        !is_category_list(l.name.as_str())
            && l.enabled
            && l.url
                .as_ref()
                .is_some_and(|u| normalize_url(u.as_str()) == want)
    })
}

/// The name of the list that carries `source` for `cfg`: a provider list, else `cat-<id>`.
pub fn list_for(cfg: &Config, source: &Source) -> String {
    provider(cfg, source).map_or_else(|| list_name(&source.id), |l| l.name.to_string())
}

/// The lists group `g` wants because of its categories (provider names or `cat-` names).
pub fn group_lists(cfg: &Config, g: &GroupConfig) -> Vec<String> {
    group_selection(g, cfg.filter.ads_tier)
        .sources
        .into_iter()
        .map(|s| list_for(cfg, s))
        .collect()
}

/// Category IDs in a group's selection that this version does not know, as `(group, id)`.
pub fn unknown_ids(cfg: &Config) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for g in &cfg.group {
        for id in group_selection(g, cfg.filter.ads_tier).unknown {
            out.push((g.name.to_string(), id));
        }
    }
    out
}

/// The categories of `cfg` that use `source_id`, for a list's "owned by" chip.
pub fn owners(cfg: &Config, source_id: &str) -> Vec<&'static Category> {
    let cat = catalog();
    let mut out = Vec::new();
    for g in &cfg.group {
        let Some(content) = &g.content else { continue };
        for c in group_selection(g, cfg.filter.ads_tier).categories {
            if cat
                .category_sources(c, content, cfg.filter.ads_tier)
                .iter()
                .any(|s| s.id == source_id)
                && !out.iter().any(|o: &&Category| o.id == c.id)
            {
                out.push(c);
            }
        }
    }
    out
}

/// `cfg` with a managed list for every source a group uses and no list provides already (once
/// each, in catalog order so the compiled snapshot doesn't change with group order). A `cat-`
/// entry of `cfg` that only sets `mode` (the person put a category list in shadow) keeps it.
pub fn expand(cfg: &Config) -> Config {
    let mut out = cfg.clone();
    let cat = catalog();
    let used = used_sources(cfg);
    // A bare `cat-` entry (mode only) of a source nobody uses any more is dropped, so it never
    // reaches the fetcher as a list with no source.
    out.list.retain(|l| !is_category_list(l.name.as_str()));
    for s in used {
        if provider(cfg, s).is_some() {
            continue;
        }
        let name = list_name(&s.id);
        let mode = cfg
            .list
            .iter()
            .find(|l| l.name.as_str() == name)
            .map_or(ListMode::Enforce, |l| l.mode);
        let (Ok(name), Ok(url)) = (SafeString::new(&name), SafeString::new(&s.url)) else {
            continue;
        };
        out.list.push(FilterList {
            name,
            url: Some(url),
            path: None,
            rules: Vec::new(),
            kind: ListKind::Block,
            match_mode: ListMatch::Subtree,
            enabled: true,
            mode,
            refresh_secs: Some(cat.refresh_secs(s)),
            max_bytes: s.max_bytes.map(ByteSize::from_bytes),
            stale_after_days: Some(if s.cadence == Cadence::Low { 0 } else { 3 }),
        });
    }
    out
}

/// `cfg` with every synthetic list the filter compiles: blocked services (`svc-`) and the
/// category sources groups use (`cat-`). What the fetcher, the compiler and the Lists page read.
pub fn expand_lists(cfg: &Config) -> Config {
    expand(&crate::services::expand(cfg))
}

/// What a selection costs and whether this node may take it (ADR-994 item 5).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Budget {
    /// Distinct sources, each counted once.
    pub sources: Vec<String>,
    pub entries: u64,
    /// Estimated snapshot size, `entries x bytes_per_domain`.
    pub snapshot_bytes: u64,
    /// Estimated compile peak, `min(source bytes x factor, merge budget)`.
    pub compile_peak_bytes: u64,
    pub baseline_rss_bytes: u64,
    /// What the node would need: baseline + snapshot + compile peak.
    pub needed_bytes: u64,
    /// The most the node may use for this (half its memory), when its limit is known.
    pub allowed_bytes: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
    /// `min(compile_memory, 25 % of the memory limit)`.
    pub merge_budget_bytes: u64,
    /// Heavy sources among them.
    pub heavy: Vec<String>,
    /// Sources that pass `entry_budget` on their own.
    pub over_budget_alone: Vec<String>,
    /// The worst-case download in a day (no conditional-GET saving).
    pub daily_download_bytes: u64,
    pub entry_budget: u64,
    /// Entries pass `entry_budget` (a warning).
    pub over_budget: bool,
    /// The node is too small: `needed_bytes` passes `allowed_bytes`.
    pub refused: bool,
    pub reasons: Vec<String>,
}

/// The cost of `sources` on a node with `memory_limit` bytes (`None`: unknown, then nothing is
/// refused) and `compile_memory` bytes of merge budget configured, against `entry_budget`.
pub fn budget(
    sources: &[&Source],
    entry_budget: u64,
    memory_limit: Option<u64>,
    compile_memory: u64,
) -> Budget {
    let cat = catalog();
    let m = &cat.measured;
    let mut seen = BTreeSet::new();
    let mut uniq: Vec<&Source> = Vec::new();
    for s in sources {
        if seen.insert(s.id.as_str()) {
            uniq.push(s);
        }
    }
    let entries: u64 = uniq.iter().map(|s| s.entries).sum();
    let bytes: u64 = uniq.iter().map(|s| s.bytes).sum();
    let snapshot = entries.saturating_mul(m.bytes_per_domain);
    let merge_budget = memory_limit.map_or(compile_memory, |l| compile_memory.min(l / 4));
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let raw_peak = (bytes as f64 * m.compile_peak_factor) as u64;
    let peak = raw_peak.min(merge_budget);
    let needed = m
        .baseline_rss_bytes
        .saturating_add(snapshot)
        .saturating_add(if uniq.is_empty() { 0 } else { peak });
    let allowed = memory_limit.map(|l| l / 2);
    let heavy: Vec<String> = uniq
        .iter()
        .filter(|s| cat.is_heavy(s))
        .map(|s| s.id.clone())
        .collect();
    let over_alone: Vec<String> = uniq
        .iter()
        .filter(|s| s.entries > entry_budget)
        .map(|s| s.id.clone())
        .collect();
    let daily = uniq
        .iter()
        .map(|s| {
            let per = 86_400 / u64::from(cat.refresh_secs(s).max(1));
            s.bytes.saturating_mul(per.max(1))
        })
        .sum();
    let refused = allowed.is_some_and(|a| needed > a);
    let over_budget = entries > entry_budget;
    let mut reasons = Vec::new();
    if refused {
        reasons.push(format!(
            "this node would need about {} MiB (baseline {} + snapshot {} + compile peak {}) and may use {} MiB of its {} MiB",
            needed >> 20,
            m.baseline_rss_bytes >> 20,
            snapshot >> 20,
            peak >> 20,
            allowed.unwrap_or(0) >> 20,
            memory_limit.unwrap_or(0) >> 20
        ));
    } else if over_budget {
        reasons.push(format!(
            "{entries} entries pass the entry budget of {entry_budget} (raise `[filter] entry_budget` on a larger node)"
        ));
    }
    Budget {
        sources: uniq.iter().map(|s| s.id.clone()).collect(),
        entries,
        snapshot_bytes: snapshot,
        compile_peak_bytes: peak,
        baseline_rss_bytes: m.baseline_rss_bytes,
        needed_bytes: needed,
        allowed_bytes: allowed,
        memory_limit_bytes: memory_limit,
        merge_budget_bytes: merge_budget,
        heavy,
        over_budget_alone: over_alone,
        daily_download_bytes: daily,
        entry_budget,
        over_budget,
        refused,
        reasons,
    }
}

/// `content` checked against the catalog: every problem, naming the field. Unknown IDs are not
/// a problem when a file is loaded (a newer node may have written them: ADR-994 item 7), but the
/// API refuses them with this.
pub fn content_problems(content: &GroupContent) -> Vec<(String, String)> {
    let cat = catalog();
    let mut p = Vec::new();
    for (i, id) in content.categories.iter().enumerate() {
        match cat.category(id) {
            None => p.push((
                format!("content.categories[{i}]"),
                format!("no category `{id}` (see GET /api/v1/categories)"),
            )),
            Some(c) if c.kind == CategoryKind::Service => p.push((
                format!("content.categories[{i}]"),
                format!(
                    "`{id}` is a bundle of services: turn it on with `blocked_services` instead"
                ),
            )),
            Some(c) if c.tier_from.is_some() => p.push((
                format!("content.categories[{i}]"),
                format!("`{id}` is the Ad Block checkbox: set `content.ads`"),
            )),
            Some(_) => {}
        }
    }
    for (id, tier) in &content.tiers {
        match cat.category(id) {
            Some(c) if c.tier_from.is_none() && c.tier.iter().any(|t| t.id == *tier) => {}
            Some(c) if c.tier_from.is_some() => p.push((
                format!("content.tiers.{id}"),
                "the size of Ad Block is `[filter] ads_tier`".to_owned(),
            )),
            Some(_) => p.push((
                format!("content.tiers.{id}"),
                format!("`{id}` has no tier `{tier}`"),
            )),
            None => p.push((format!("content.tiers.{id}"), format!("no category `{id}`"))),
        }
    }
    p
}

/// A one-line summary of what a group filters ("Basic", "Enhanced (3 of 21)", "Off"), for the
/// profile list and audit lines.
pub fn summary(content: Option<&GroupContent>) -> String {
    let Some(c) = content else {
        return "Off".to_owned();
    };
    let mut parts = Vec::new();
    match c.level {
        ContentLevel::Off => {}
        ContentLevel::Basic => parts.push("Basic".to_owned()),
        ContentLevel::Enhanced => {
            let total = catalog()
                .categories
                .iter()
                .filter(|x| x.kind == CategoryKind::List && x.tier_from.is_none())
                .count();
            parts.push(format!("Enhanced ({} of {total})", c.categories.len()));
        }
    }
    if c.ads {
        parts.push("Ad block".to_owned());
    }
    if parts.is_empty() {
        "Off".to_owned()
    } else {
        parts.join(", ")
    }
}

/// Groups of `cfg` keyed by name, for the budget across all groups.
pub fn per_group_sources(cfg: &Config) -> BTreeMap<String, Vec<&'static Source>> {
    cfg.group
        .iter()
        .map(|g| {
            (
                g.name.to_string(),
                group_selection(g, cfg.filter.ads_tier).sources,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids<T>(v: &[T], f: impl Fn(&T) -> &str) -> Vec<String> {
        v.iter().map(|x| f(x).to_owned()).collect()
    }

    /// REQ: FLT-901 — the catalog parses, and has no data mistake.
    #[test]
    fn flt_901_catalog_parses() {
        let c = Catalog::parse(FILES).unwrap();
        assert_eq!(c.version, "2026-11-18");
        assert!(
            c.categories.len() >= 20,
            "{} categories",
            c.categories.len()
        );
        assert!(c.sources.len() >= 30, "{} sources", c.sources.len());
        assert_eq!(c.problems(), Vec::<String>::new());
        assert_eq!(c, *catalog());
        // The seven UniFi-style groups the owner chose, plus Privacy and Ads (one of the
        // seven, Business & Professional, offers nothing and shows only under Not available).
        assert_eq!(
            ids(&c.groups, |g| g.id.as_str()),
            [
                "adult",
                "ai-crypto",
                "culture",
                "network",
                "risky",
                "security",
                "privacy"
            ]
        );
    }

    /// REQ: FLT-901 — every source has an SPDX licence, an https URL, a format and a cadence.
    #[test]
    fn flt_901_catalog_has_licence_and_url_for_every_source() {
        let spdx = ["GPL-3.0", "MIT", "CC-BY-SA-4.0"];
        for s in &catalog().sources {
            assert!(
                spdx.contains(&s.licence.as_str()),
                "{}: {}",
                s.id,
                s.licence
            );
            assert!(s.url.starts_with("https://"), "{}", s.id);
            assert!(s.licence_url.starts_with("https://"), "{}", s.id);
            assert!(s.entries > 0 && s.bytes > 0, "{}", s.id);
        }
        // The CC BY-SA source carries its attribution line.
        let ba = catalog().source("bonappetit-porn").unwrap();
        assert!(
            ba.attribution
                .as_deref()
                .is_some_and(|a| a.contains("CC BY-SA 4.0") && a.contains("Bon-Appetit"))
        );
    }

    /// REQ: FLT-901 — no category is empty (the catalog never offers a checkbox that does nothing).
    #[test]
    fn flt_901_no_empty_categories() {
        let c = catalog();
        for cat in &c.categories {
            match cat.kind {
                CategoryKind::List => assert!(!c.all_source_ids(cat).is_empty(), "{}", cat.id),
                CategoryKind::Service => assert!(!c.service_ids(cat).is_empty(), "{}", cat.id),
            }
        }
    }

    /// REQ: FLT-901 — every not-offered entry has a reason.
    #[test]
    fn flt_901_not_offered_have_reasons() {
        let c = catalog();
        assert!(c.not_offered.len() >= 15);
        for n in &c.not_offered {
            assert!(n.reason.len() > 10, "{}", n.name);
            assert_ne!(n.group, "");
        }
    }

    /// REQ: FLT-901 — source IDs are unique and a `cat-` list name fits the 64-character limit.
    #[test]
    fn flt_901_source_ids_unique() {
        let c = catalog();
        let mut seen = BTreeSet::new();
        for s in &c.sources {
            assert!(seen.insert(&s.id), "{}", s.id);
            assert!(list_name(&s.id).len() <= 64);
            assert!(crate::valid_list_name(&list_name(&s.id)), "{}", s.id);
        }
    }

    /// REQ: FLT-901 — a source's recorded size stays under 90 % of the list size cap that will
    /// apply to it (the `max_bytes` it carries, else `[filter] max_list_bytes`, 64 MiB).
    #[test]
    fn flt_901_bytes_cap_covers_source_size() {
        let default_cap = crate::FilterConfig::default().max_list_bytes.bytes();
        for s in &catalog().sources {
            let cap = s.max_bytes.unwrap_or(default_cap);
            assert!(
                s.bytes.saturating_mul(10) <= cap.saturating_mul(9),
                "{}: {} bytes against a cap of {cap}",
                s.id,
                s.bytes
            );
            assert!(cap <= 256 * 1024 * 1024, "{}", s.id);
        }
    }

    fn days(date: &str) -> i64 {
        let d: jiff::civil::Date = date.parse().unwrap();
        i64::from(d.since(jiff::civil::date(1970, 1, 1)).unwrap().get_days())
    }

    /// REQ: FLT-901 — the recorded facts are fresh against the catalog's own date (never the
    /// clock, never the network): checked within 90 days, a push within 90 days of the check,
    /// and not archived. `scripts/check-catalog.py` is the live check, run weekly.
    #[test]
    fn flt_901_catalog_recorded_metadata_fresh() {
        let c = catalog();
        let version = days(&c.version);
        for s in &c.sources {
            let (checked, pushed) = (days(&s.checked), days(&s.pushed));
            assert!(
                (0..=90).contains(&(version - checked)),
                "{}: checked {} is not within 90 days of {}",
                s.id,
                s.checked,
                c.version
            );
            assert!(
                (0..=90).contains(&(checked - pushed)),
                "{}: pushed {} is over 90 days before the check",
                s.id,
                s.pushed
            );
            assert!(!s.archived, "{} is archived", s.id);
        }
    }

    /// REQ: FLT-901 — the tiers are of a stated kind: gambling and the threat tiers are
    /// exclusive (one file), Adult's Extended is additive (it adds Bon-Appetit to the `HaGeZi` list).
    #[test]
    fn flt_901_tier_kinds() {
        let c = catalog();
        let k = |id: &str| c.category(id).unwrap().tier_kind;
        assert_eq!(k("gambling"), Some(TierKind::Exclusive));
        assert_eq!(k("malware"), Some(TierKind::Exclusive));
        assert_eq!(k("ads"), Some(TierKind::Exclusive));
        assert_eq!(k("adult"), Some(TierKind::Additive));
        let off = GroupContent {
            level: ContentLevel::Enhanced,
            categories: vec![SafeString::new("adult").unwrap()],
            ..GroupContent::default()
        };
        let plain: Vec<_> = selection(&off, AdsTier::Pro)
            .sources
            .iter()
            .map(|s| s.id.clone())
            .collect();
        assert_eq!(plain, ["hagezi-nsfw"]);
        let mut ext = off.clone();
        ext.tiers.insert("adult".into(), "extended".into());
        let both: Vec<_> = selection(&ext, AdsTier::Pro)
            .sources
            .iter()
            .map(|s| s.id.clone())
            .collect();
        assert_eq!(both, ["hagezi-nsfw", "bonappetit-porn"]);
        // Exclusive: the chosen size replaces the default one.
        let mut g = GroupContent {
            level: ContentLevel::Enhanced,
            categories: vec![SafeString::new("gambling").unwrap()],
            ..GroupContent::default()
        };
        let one = |g: &GroupContent| {
            selection(g, AdsTier::Pro)
                .sources
                .iter()
                .map(|s| s.id.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(one(&g), ["hagezi-gambling-medium"]);
        g.tiers.insert("gambling".into(), "extended".into());
        assert_eq!(one(&g), ["hagezi-gambling-full"]);
    }

    /// REQ: FLT-902 — Basic is the preset, Off selects nothing and keeps the selection,
    /// Enhanced uses the categories; ads is independent of the level.
    #[test]
    fn flt_902_levels_select_categories() {
        let named = |l: ContentLevel| GroupContent {
            level: l,
            categories: vec![SafeString::new("gambling").unwrap()],
            ..GroupContent::default()
        };
        let basic = selection(&named(ContentLevel::Basic), AdsTier::Pro);
        let b: Vec<&str> = basic.categories.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(b, ["adult", "malware", "phishing", "scam"]);
        assert!(!basic.sources.iter().any(|s| s.id.contains("gambling")));
        // The threat feed behind malware, phishing and scam is one source.
        assert_eq!(
            basic
                .sources
                .iter()
                .filter(|s| s.id == "hagezi-tif-mini")
                .count(),
            1
        );
        let off = named(ContentLevel::Off);
        assert_eq!(selection(&off, AdsTier::Pro).sources.len(), 0);
        assert_eq!(off.categories.len(), 1, "the selection is kept");
        let enh = selection(&named(ContentLevel::Enhanced), AdsTier::Pro);
        assert_eq!(enh.categories.len(), 1);
        let ads_only = GroupContent {
            ads: true,
            ..GroupContent::default()
        };
        let a = selection(&ads_only, AdsTier::Pro);
        assert_eq!(a.sources.len(), 1);
        assert_eq!(a.sources[0].id, "hagezi-ads-pro");
        assert_eq!(
            selection(&ads_only, AdsTier::Ultimate).sources[0].id,
            "hagezi-ads-ultimate"
        );
    }

    /// REQ: FLT-901 — the default Ad Block tier's URL is the one the bundles ship by hand, so
    /// it is adopted rather than downloaded twice.
    #[test]
    fn flt_901_ads_default_tier_is_the_bundles_hagezi_pro_url() {
        let s = catalog().source("hagezi-ads-pro").unwrap();
        assert_eq!(
            s.url,
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"
        );
    }

    fn cfg(toml: &str) -> Config {
        crate::Loader::new()
            .toml_str("t", toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config
    }

    /// REQ: FLT-901 — a source two groups share is one list, and a group that selects nothing
    /// gets none (`expand` is empty when no group selects a category).
    #[test]
    fn flt_901_expand_makes_one_list_per_distinct_source() {
        let c = cfg(
            "[[group]]\nname = \"kids\"\ncontent = { level = \"basic\" }\n\
             [[group]]\nname = \"teens\"\ncontent = { level = \"enhanced\", categories = [\"malware\", \"social\"] }\n",
        );
        let e = expand(&c);
        let names: Vec<&str> = e.list.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(
            names
                .iter()
                .filter(|n| **n == "cat-hagezi-tif-mini")
                .count(),
            1,
            "{names:?}"
        );
        assert!(names.contains(&"cat-hagezi-nsfw"));
        assert!(names.contains(&"cat-hagezi-social"));
        let plain = cfg("[[group]]\nname = \"kids\"\n");
        assert_eq!(expand(&plain).list.len(), 0);
        let off = cfg(
            "[[group]]\nname = \"kids\"\ncontent = { level = \"off\", categories = [\"adult\"] }\n",
        );
        assert_eq!(expand(&off).list.len(), 0);
    }

    /// REQ: FLT-901 — heavy sources refresh at most daily; light ones every 8 hours.
    #[test]
    fn flt_901_heavy_refresh_not_under_24h() {
        let c = catalog();
        for s in &c.sources {
            let r = c.refresh_secs(s);
            if c.is_heavy(s) || s.cadence == Cadence::Low {
                assert!(r >= 86_400, "{}", s.id);
            } else {
                assert_eq!(r, 28_800, "{}", s.id);
            }
        }
        assert!(c.is_heavy(c.source("hagezi-nrd7").unwrap()));
        assert!(c.is_heavy(c.source("hagezi-tif-full").unwrap()));
        assert!(!c.is_heavy(c.source("hagezi-tif-mini").unwrap()));
        let e = expand(&cfg(
            "[[group]]\nname = \"g\"\ncontent = { level = \"enhanced\", categories = [\"nrd\"] }\n",
        ));
        assert_eq!(e.list[0].refresh_secs, Some(86_400));
    }

    /// REQ: FLT-901 — the budget counts distinct sources once, not the sum over categories.
    #[test]
    fn flt_901_budget_union_not_sum() {
        let c = catalog();
        let tif = c.source("hagezi-tif-mini").unwrap();
        let b = budget(&[tif, tif, tif], 1_000_000, None, 128 << 20);
        assert_eq!(b.entries, 189_474);
        assert_eq!(b.sources, ["hagezi-tif-mini"]);
        // Three categories sharing the feed select it once.
        let cfgc = cfg(
            "[[group]]\nname = \"a\"\ncontent = { level = \"enhanced\", categories = [\"malware\", \"phishing\", \"scam\"] }\n",
        );
        assert_eq!(used_sources(&cfgc).len(), 1);
    }

    const MIB: u64 = 1 << 20;

    fn sel(ids: &[&str]) -> Vec<&'static Source> {
        let content = GroupContent {
            level: ContentLevel::Enhanced,
            categories: ids.iter().map(|i| SafeString::new(*i).unwrap()).collect(),
            ..GroupContent::default()
        };
        selection(&content, AdsTier::Pro).sources
    }

    /// REQ: FLT-901 — heavy sources are marked: NRD 7 days and full TIF pass the default budget
    /// alone.
    #[test]
    fn flt_901_heavy_requires_confirm() {
        let nrd = budget(&sel(&["nrd"]), 1_000_000, None, 128 * MIB);
        assert_eq!(nrd.heavy, ["hagezi-nrd7"]);
        assert_eq!(nrd.over_budget_alone, ["hagezi-nrd7"]);
        assert!(nrd.over_budget);
        assert!(
            nrd.daily_download_bytes >= 40_000_000,
            "{}",
            nrd.daily_download_bytes
        );
        let basic = budget(&sel(&["adult", "malware"]), 1_000_000, None, 128 * MIB);
        assert!(basic.heavy.is_empty() && !basic.over_budget);
    }

    /// REQ: FLT-901 — on a 128 MiB node Basic passes and NRD 7 days is refused, with the reason;
    /// the merge budget scales to the node.
    #[test]
    fn flt_901_over_budget_refused_on_small_node() {
        let basic = budget(
            &sel(&["adult", "malware", "phishing", "scam"]),
            1_000_000,
            Some(128 * MIB),
            128 * MIB,
        );
        assert!(!basic.refused, "{basic:?}");
        assert_eq!(basic.merge_budget_bytes, 32 * MIB);
        let nrd = budget(&sel(&["nrd"]), 1_000_000, Some(128 * MIB), 128 * MIB);
        assert!(nrd.refused, "{nrd:?}");
        assert!(nrd.reasons[0].contains("128 MiB"), "{:?}", nrd.reasons);
    }

    /// REQ: FLT-901 — the same selection on a 256 MiB node is allowed (with the entry-budget
    /// warning).
    #[test]
    fn flt_901_over_budget_allowed_with_warning_on_256_mib() {
        let nrd = budget(&sel(&["nrd"]), 1_000_000, Some(256 * MIB), 128 * MIB);
        assert!(!nrd.refused, "{nrd:?}");
        assert!(nrd.over_budget);
        assert_eq!(nrd.merge_budget_bytes, 64 * MIB);
        assert!(nrd.reasons[0].contains("entry budget"));
    }

    /// REQ: FLT-901 — the compile peak is the smaller of the source bytes times the factor and
    /// the node's merge budget.
    #[test]
    fn flt_901_compile_peak_estimate_scales_merge_budget() {
        let tif = catalog().source("hagezi-tif-mini").unwrap();
        let small = budget(&[tif], 1_000_000, None, 128 * MIB);
        let factor = catalog().measured.compile_peak_factor;
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let expect = (tif.bytes as f64 * factor) as u64;
        assert_eq!(small.compile_peak_bytes, expect);
        let tight = budget(&[tif], 1_000_000, Some(64 * MIB), 128 * MIB);
        assert_eq!(tight.merge_budget_bytes, 16 * MIB);
        assert!(tight.compile_peak_bytes <= 16 * MIB);
        assert_eq!(
            budget(&[], 1_000_000, Some(128 * MIB), 128 * MIB).compile_peak_bytes,
            0
        );
    }

    /// REQ: FLT-901 — a list a file defines with a catalog source's URL provides that source:
    /// no second download, and the group names that list.
    #[test]
    fn flt_901_provider_list_is_not_downloaded_twice() {
        let c = cfg(
            "[[list]]\nname = \"hagezi-pro\"\nurl = \"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt\"\n\
             [[group]]\nname = \"default\"\ncontent = { ads = true }\n",
        );
        let e = expand(&c);
        assert_eq!(e.list.len(), 1, "{:?}", e.list);
        assert_eq!(e.list[0].name.as_str(), "hagezi-pro");
        assert_eq!(group_lists(&c, &c.group[0]), ["hagezi-pro"]);
        assert_eq!(
            normalize_url("HTTPS://Raw.GitHubUserContent.com/a/b"),
            "https://raw.githubusercontent.com/a/b"
        );
    }

    /// REQ: FLT-901 — a service category in `content.categories` and an unknown tier are
    /// problems; an unknown ID is reported by `selection`, never fatal.
    #[test]
    fn flt_901_content_problems_and_unknown_ids() {
        let content = GroupContent {
            level: ContentLevel::Enhanced,
            categories: vec![
                SafeString::new("ai").unwrap(),
                SafeString::new("no-such").unwrap(),
                SafeString::new("adult").unwrap(),
            ],
            tiers: BTreeMap::from([("gambling".to_owned(), "huge".to_owned())]),
            ads: false,
        };
        let p = content_problems(&content);
        assert_eq!(p.len(), 3, "{p:?}");
        let s = selection(&content, AdsTier::Pro);
        assert_eq!(s.unknown, ["ai", "no-such"]);
        assert_eq!(s.categories.len(), 1);
    }

    /// REQ: FLT-901 — the services behind a service category exist.
    #[test]
    fn flt_901_service_categories_name_real_services() {
        let c = catalog();
        let ai = c.category("ai").unwrap();
        let ids = c.service_ids(ai);
        assert!(
            ids.contains(&"chatgpt") && ids.contains(&"claude"),
            "{ids:?}"
        );
    }
}

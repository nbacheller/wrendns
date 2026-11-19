//! REQ: DNS-019 (T24.12, ADR-904, ADR-914), DNS-023 (T24.13, ADR-901, ADR-914) — the shared
//! singleton kinds `special` (`[special]`), `local` (`[local]` without `hosts_files`), and
//! `clients` (`[clients]`, `mdns` only in M24).
//!
//! Each stores one whole set of editable fields through the API (fields left out take their
//! defaults, as the other one-entry kinds do), and the files win field by field (ADR-040,
//! ADR-914): a field the files set can't be changed here (409 `set_by_file`), a field left out
//! of a request keeps the file's value, and the UI shows "set by file". Admin-only fields
//! (`special.ddr_name`, `clients.mdns`) are checked on the server: an operator's change is 403
//! naming the field, and agents never change them (ADR-914, the admin-only tier).

use serde::Deserialize;
use serde_json::{Map, Value};
use telltale_api::ManagedKind;
use telltale_api::auth::Role;
use telltale_api::problem::{Code, Problem};
use telltale_config::{Config, DiscoveryConfig, LocalConfig, SpecialConfig};

use crate::managed::Entries;

/// The config section a kind edits.
pub(crate) fn section(kind: ManagedKind) -> &'static str {
    match kind {
        ManagedKind::Special => "special",
        ManagedKind::Local => "local",
        ManagedKind::Discovery => "discovery",
        ManagedKind::Filter => "filter",
        _ => "clients",
    }
}

/// True for the kinds in this module.
pub(crate) fn is_settings(kind: ManagedKind) -> bool {
    matches!(
        kind,
        ManagedKind::Special
            | ManagedKind::Local
            | ManagedKind::Clients
            | ManagedKind::Discovery
            | ManagedKind::Filter
    )
}

/// REQ: DSC-001 (T25.2, ADR-907) — the fields of `[discovery]` a kind's entry carries.
const DISCOVERY_KEYS: &[&str] = &[
    "enabled",
    "node",
    "worker_memory_mib",
    "subnet",
    // REQ: DSC-009 (T25.10, ADR-912) — the extra UniFi and Home Assistant reads.
    "unifi_reads",
    "unifi_all_users_within_hours",
    "home_assistant_all_devices",
];

/// The fields a kind's API entry carries (what the UI edits).
pub(crate) fn keys(kind: ManagedKind) -> &'static [&'static str] {
    match kind {
        ManagedKind::Special => &[
            "block_firefox_canary",
            "localhost",
            "private_ptr_nxdomain",
            "refuse_chaos",
            "block_icloud_private_relay",
            "single_label_nxdomain",
            "ddr_name",
        ],
        ManagedKind::Local => &[
            "device_domain",
            "device_ttl",
            "device_mdns",
            "auto_ptr",
            "default_ttl",
        ],
        ManagedKind::Discovery => DISCOVERY_KEYS,
        // REQ: FLT-901 (T24.29) - the two `[filter]` fields that bound the category selection.
        ManagedKind::Filter => &["entry_budget", "ads_tier"],
        _ => &["mdns"],
    }
}

/// The fields only an admin may change (ADR-914, the second tier). Other fields are the
/// ordinary role's (operators).
pub(crate) fn admin_keys(kind: ManagedKind) -> &'static [&'static str] {
    match kind {
        ManagedKind::Special => &["ddr_name"],
        ManagedKind::Clients => &["mdns"],
        // REQ: DSC-001 (T25.2, ADR-907) — every field of the network inventory is admin-only.
        ManagedKind::Discovery => DISCOVERY_KEYS,
        _ => &[],
    }
}

/// The editable fields of a kind as the configuration holds them now, as JSON: every key of
/// [`keys`] is present (`null` when unset), so a stored entry replaces every field.
pub(crate) fn section_json(kind: ManagedKind, cfg: &Config) -> Value {
    let full = match kind {
        ManagedKind::Special => serde_json::to_value(&cfg.special),
        ManagedKind::Local => serde_json::to_value(&cfg.local),
        ManagedKind::Discovery => serde_json::to_value(&cfg.discovery),
        ManagedKind::Filter => serde_json::to_value(&cfg.filter),
        _ => serde_json::to_value(&cfg.clients),
    }
    .unwrap_or(Value::Null);
    let mut out = Map::new();
    for k in keys(kind) {
        out.insert(
            (*k).to_owned(),
            full.get(*k).cloned().unwrap_or(Value::Null),
        );
    }
    Value::Object(out)
}

/// The dotted keys the files set for this kind's section (`special.ddr_name`), from
/// [`Config::file_set`].
fn file_set(kind: ManagedKind, own: &Config, k: &str) -> bool {
    let key = format!("{}.{k}", section(kind));
    own.file_set.contains(&key)
}

/// Parses an API body into the stored shape, with every key present. Unknown fields are
/// refused with the field's name (`querys`), and `hosts_files` is a path the files own.
fn normalize(kind: ManagedKind, body: &Value) -> Result<Value, Problem> {
    let bad = |e: serde_json::Error| Problem::new(Code::InvalidConfig, e.to_string());
    let mut cfg = Config::default();
    match kind {
        ManagedKind::Special => {
            cfg.special = serde_json::from_value::<SpecialConfig>(body.clone()).map_err(bad)?;
        }
        ManagedKind::Discovery => {
            cfg.discovery = serde_json::from_value::<DiscoveryConfig>(body.clone()).map_err(bad)?;
        }
        ManagedKind::Filter => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields, default)]
            struct FilterOnly {
                entry_budget: u64,
                ads_tier: telltale_config::AdsTier,
            }
            impl Default for FilterOnly {
                fn default() -> Self {
                    let f = telltale_config::FilterConfig::default();
                    Self {
                        entry_budget: f.entry_budget,
                        ads_tier: f.ads_tier,
                    }
                }
            }
            let f = serde_json::from_value::<FilterOnly>(body.clone()).map_err(|e| {
                let text = e.to_string();
                if text.contains("unknown field") {
                    Problem::invalid(format!(
                        "{text}: only `entry_budget` and `ads_tier` can be changed here"
                    ))
                    .hint("The other `[filter]` settings are in the configuration file.")
                } else {
                    bad(e)
                }
            })?;
            if f.entry_budget == 0 {
                return Err(Problem::new(
                    Code::InvalidConfig,
                    "`entry_budget` must be at least 1",
                ));
            }
            cfg.filter.entry_budget = f.entry_budget;
            cfg.filter.ads_tier = f.ads_tier;
        }
        ManagedKind::Local => {
            if body.get("hosts_files").is_some() {
                return Err(Problem::invalid(
                    "`hosts_files`: the hosts files are set in the configuration file, not here",
                )
                .hint("Edit `[local] hosts_files` in the file. The UI shows them read-only."));
            }
            // An empty domain is no domain: device names off (the UI and agents send "").
            let mut body = body.clone();
            if body.get("device_domain").and_then(Value::as_str) == Some("") {
                body["device_domain"] = Value::Null;
            }
            cfg.local = serde_json::from_value::<LocalConfig>(body).map_err(bad)?;
        }
        _ => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields, default)]
            struct MdnsOnly {
                mdns: bool,
            }
            let m = serde_json::from_value::<MdnsOnly>(body.clone()).map_err(|e| {
                let text = e.to_string();
                if text.contains("mdns_port") {
                    Problem::invalid("`mdns_port` is set in the configuration file, not here")
                        .hint("Only `mdns` can be changed here.")
                } else {
                    bad(e)
                }
            })?;
            cfg.clients.mdns = m.mdns;
        }
    }
    Ok(section_json(kind, &cfg))
}

/// A PUT body as stored: a field the files set and the body leaves out keeps the file's value
/// (as credentials do, OPS-014); a body that sets one to another value is refused (409
/// `set_by_file`). `file` is the section as the files give it.
pub(crate) fn prepare(
    kind: ManagedKind,
    body: &Value,
    file: &Value,
    own: &Config,
) -> Result<Value, Problem> {
    let Value::Object(obj) = body else {
        return Err(Problem::invalid("the body must be an object"));
    };
    let mut obj = obj.clone();
    // `hosts_files` comes back in the entry as read (shown read-only): the same list is fine.
    if kind == ManagedKind::Local
        && obj.get("hosts_files") == serde_json::to_value(&own.local.hosts_files).ok().as_ref()
    {
        obj.remove("hosts_files");
    }
    // `mdns_port` is the same: read-only here, as the file sets it.
    if kind == ManagedKind::Clients
        && obj.get("mdns_port") == serde_json::to_value(own.clients.mdns_port).ok().as_ref()
    {
        obj.remove("mdns_port");
    }
    for k in keys(kind) {
        if file_set(kind, own, k) && !obj.contains_key(*k) {
            obj.insert(
                (*k).to_owned(),
                file.get(*k).cloned().unwrap_or(Value::Null),
            );
        }
    }
    let stored = normalize(kind, &Value::Object(obj))?;
    for k in keys(kind) {
        if file_set(kind, own, k) && stored.get(*k) != file.get(*k) {
            return Err(Problem::new(
                Code::SetByFile,
                format!("`{k}` is set by the configuration files, which win: it can't be changed here"),
            )
            .hint(format!(
                "Change `{}.{k}` in the configuration file, or leave it out of the request (it is kept as the file sets it).",
                section(kind)
            )));
        }
    }
    Ok(stored)
}

/// The stored section's fields laid over the files' (`cfg` is the files' configuration until
/// this runs): a field the files set keeps the file's value (ADR-040). Returns the problems
/// with the stored values (merge errors, which make the node fall back to the files alone).
pub(crate) fn apply_stored(cfg: &mut Config, own: &Config, e: &Entries) -> Vec<String> {
    let mut errs = Vec::new();
    for (kind, stored) in [
        (ManagedKind::Special, &e.special),
        (ManagedKind::Local, &e.local),
        (ManagedKind::Clients, &e.clients_settings),
        (ManagedKind::Discovery, &e.discovery),
        (ManagedKind::Filter, &e.filter_settings),
    ] {
        let Some(stored) = stored else { continue };
        if let Err(why) = overlay(cfg, own, kind, stored) {
            errs.push(format!("{}: {why}", section(kind)));
        }
    }
    errs
}

fn overlay(
    cfg: &mut Config,
    own: &Config,
    kind: ManagedKind,
    stored: &Value,
) -> Result<(), String> {
    let mut cur = section_json(kind, cfg);
    if let (Value::Object(c), Value::Object(s)) = (&mut cur, stored) {
        for k in keys(kind) {
            if file_set(kind, own, k) {
                continue;
            }
            if let Some(v) = s.get(*k) {
                c.insert((*k).to_owned(), v.clone());
            }
        }
    }
    match kind {
        ManagedKind::Special => {
            cfg.special = serde_json::from_value(cur).map_err(|e| e.to_string())?;
        }
        ManagedKind::Discovery => {
            cfg.discovery = serde_json::from_value(cur).map_err(|e| e.to_string())?;
        }
        ManagedKind::Filter => {
            if let Some(n) = cur.get("entry_budget").and_then(Value::as_u64) {
                cfg.filter.entry_budget = n;
            }
            if let Some(t) = cur.get("ads_tier") {
                cfg.filter.ads_tier =
                    serde_json::from_value(t.clone()).map_err(|e| e.to_string())?;
            }
        }
        ManagedKind::Local => {
            let mut lj = serde_json::to_value(&cfg.local).map_err(|e| e.to_string())?;
            if let (Value::Object(l), Value::Object(c)) = (&mut lj, &cur) {
                for k in keys(kind) {
                    l.insert((*k).to_owned(), c.get(*k).cloned().unwrap_or(Value::Null));
                }
            }
            cfg.local = serde_json::from_value(lj).map_err(|e| e.to_string())?;
        }
        _ => {
            cfg.clients.mdns = cur.get("mdns").and_then(Value::as_bool).unwrap_or(false);
        }
    }
    Ok(())
}

/// The admin-only fields a change moves (ADR-914): `before` and `after` are the sections in
/// effect before and after. An agent never changes them; an operator's change is 403 naming
/// the field; a request from a node too old to say who asked is refused (409).
pub(crate) fn check_admin_fields(
    kind: ManagedKind,
    before: &Value,
    after: &Value,
    role: Option<Role>,
    agent: Option<&str>,
) -> Result<(), Problem> {
    if kind == ManagedKind::Clients && agent.is_some() {
        return Err(Problem::new(
            Code::AgentNotAllowed,
            "no agent can change `[clients]` (mdns turns on multicast listening on every node)",
        )
        .hint("Ask an admin to make this change in the UI."));
    }
    // REQ: FLT-901 (T24.29) — the budget decides what a node will download and hold.
    if kind == ManagedKind::Filter && agent.is_some() {
        return Err(Problem::new(
            Code::AgentNotAllowed,
            "no agent can change `[filter]` entry_budget or ads_tier: they decide what the node downloads and holds",
        )
        .hint("Ask an operator to make this change in the UI (Settings, Filtering)."));
    }
    // REQ: DSC-001 (T25.2, ADR-907) — no agent writes the network inventory's settings.
    if kind == ManagedKind::Discovery && agent.is_some() {
        return Err(Problem::new(
            Code::AgentNotAllowed,
            "no agent can change `[discovery]`: the network inventory reads the LAN's devices",
        )
        .hint("Ask an admin to make this change in the UI."));
    }
    let Some(field) = admin_keys(kind)
        .iter()
        .find(|k| before.get(**k) != after.get(**k))
    else {
        return Ok(());
    };
    let why = match kind {
        ManagedKind::Clients => "it turns on mDNS listening on every node of the cluster",
        ManagedKind::Discovery => {
            "the network inventory reads the devices on the LAN, from one node"
        }
        _ => "it is one name for the whole cluster, tied to every node's certificates",
    };
    if agent.is_some() {
        return Err(Problem::new(
            Code::AgentNotAllowed,
            format!("agents can't change `{field}`: {why}"),
        )
        .hint("Ask an admin to make this change in the UI."));
    }
    match role {
        Some(Role::Admin) => Ok(()),
        None => Err(Problem::new(
            Code::UpgradeRequired,
            format!(
                "this change to `{field}` needs an admin, and the node it was made on is too old to say who made it"
            ),
        )
        .hint("Upgrade that node first, or make the change on the primary.")),
        // LOW 3: a partial PUT that leaves out an API-set `ddr_name` resets it, so say how to keep it.
        Some(_) => Err(Problem::new(
            Code::Forbidden,
            format!("only an admin can change `{field}`: {why}"),
        )
        .hint(format!(
            "Ask an admin to make this change. A partial PUT that leaves out the current `{field}` resets it: include the current value, or GET the entry first."
        ))),
    }
}

/// REQ: DSC-001 (T25.2, ADR-907, CLU-010) — the first write of `[discovery]` is refused (409
/// `members_too_old`) while any member runs a version older than `since` (or one whose version can't
/// be read). `members` is (node ID, version) for each member.
pub(crate) fn members_too_old(
    members: &[(String, String)],
    since: (u64, u64, u64),
) -> Option<telltale_api::problem::Problem> {
    use telltale_api::problem::{Code, Problem};
    let old: Vec<&str> = members
        .iter()
        .filter(|(_, v)| !crate::forward::version_at_least(v, since))
        .map(|(n, _)| n.as_str())
        .collect();
    if old.is_empty() {
        return None;
    }
    Some(
        Problem::new(
            Code::MembersTooOld,
            format!(
                "the network inventory can't be turned on while {} runs an older version than this one: it can't read `[discovery]`",
                old.join(", ")
            ),
        )
        .hint("Upgrade every node first (replicas first, then the primary), then make this change again."),
    )
}

/// What a DELETE leaves stored: nothing (the files' fields apply again).
pub(crate) fn none_stored(entries: &Entries, kind: ManagedKind) -> bool {
    match kind {
        ManagedKind::Special => entries.special.is_none(),
        ManagedKind::Local => entries.local.is_none(),
        ManagedKind::Discovery => entries.discovery.is_none(),
        ManagedKind::Filter => entries.filter_settings.is_none(),
        _ => entries.clients_settings.is_none(),
    }
}

/// Sets (`Some`) or clears (`None`) the entry's stored section.
pub(crate) fn set_stored(entries: &mut Entries, kind: ManagedKind, v: Option<Value>) {
    match kind {
        ManagedKind::Special => entries.special = v,
        ManagedKind::Local => entries.local = v,
        ManagedKind::Discovery => entries.discovery = v,
        ManagedKind::Filter => entries.filter_settings = v,
        _ => entries.clients_settings = v,
    }
}

/// The human name of a kind's section, for messages.
pub(crate) fn noun(kind: ManagedKind) -> &'static str {
    match kind {
        ManagedKind::Special => "special names",
        ManagedKind::Local => "device-name settings",
        ManagedKind::Discovery => "network inventory settings",
        ManagedKind::Filter => "category settings",
        _ => "clients settings",
    }
}

/// The sentence the dry run says for a change to the section.
pub(crate) fn impact(kind: ManagedKind, put: bool) -> String {
    match (kind, put) {
        (ManagedKind::Special, true) => "Applies on the next query, on every node, with no restart. Names the switches turn on or off answer differently from then on; answers already cached stay until they expire.".into(),
        (ManagedKind::Special, false) => "The config file's special-name settings (or the defaults) apply again from the next query.".into(),
        // REQ: DSC-001 (T25.2) — the inventory starts or stops on the designated node at the reload.
        (ManagedKind::Discovery, true) => "Applies on the designated node within a few seconds, with no restart: the network inventory starts or stops there. Other nodes change nothing, and no device is read until it is on.".into(),
        (ManagedKind::Discovery, false) => "The config file's network inventory settings (or the defaults: off) apply again on the designated node within a few seconds.".into(),
        (ManagedKind::Filter, true) => "Applies within a few seconds on every node: the entry budget is what the Categories view warns against, and a new ad block size makes the primary download that list and compile it in the background.".into(),
        (ManagedKind::Filter, false) => "The config file's [filter] entry_budget and ads_tier (or the defaults: 1,000,000 and pro) apply again.".into(),
        (ManagedKind::Local, true) => "Device names in DNS change within about 10 seconds on every node, with no restart.".into(),
        (ManagedKind::Local, false) => "The config file's device-name settings (or the defaults) apply again within about 10 seconds.".into(),
        // REQ: DNS-023 (H1) — the mDNS listener starts once, at start-up (`restart_only_changes`):
        // a change here takes effect after a restart on every node.
        (_, true) => "Takes effect after a restart on every node: the mDNS listener starts once, at start-up, and device names only follow mDNS while it runs.".into(),
        (_, false) => "The config file's [clients] mdns (or off) applies after a restart on every node.".into(),
    }
}

/// `dry run` keys in a `Map` for kinds the tests check, kept here so the tests can build a
/// body the way the API does.
#[cfg(test)]
pub(crate) fn body_of(pairs: &[(&str, Value)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_config::Loader;

    fn cfg(toml: &str, path: &str) -> Config {
        Loader::new().toml_str(path, toml).load().unwrap().config
    }

    /// REQ: DNS-019 (T24.12) — the stored `[special]` section lays over the defaults, a field
    /// left out takes its default, and the files' `ddr_name` wins over an API value.
    #[test]
    fn dns_019_file_special_wins() {
        let file = cfg("[special]\nddr_name = \"dns.home.arpa\"\n", "file");
        let stored = normalize(
            ManagedKind::Special,
            &body_of(&[("block_icloud_private_relay", Value::Bool(false))]),
        )
        .unwrap();
        assert_eq!(stored["ddr_name"], Value::Null, "left out: the default");
        assert_eq!(stored["block_firefox_canary"], Value::Bool(true));
        let mut merged = file.clone();
        overlay(&mut merged, &file, ManagedKind::Special, &stored).unwrap();
        assert!(!merged.special.block_icloud_private_relay);
        assert_eq!(
            merged
                .special
                .ddr_name
                .as_ref()
                .map(telltale_config::SafeString::as_str),
            Some("dns.home.arpa"),
            "the file's ddr_name wins"
        );
    }

    /// REQ: DNS-019 (T24.12, ADR-914) — a file-set field: a body that sets another value is
    /// refused with 409 `set_by_file`; one that leaves it out keeps the file's value.
    #[test]
    fn dns_019_file_set_field_is_refused_or_kept() {
        let file = cfg("[special]\nlocalhost = false\n", "file");
        let fs = section_json(ManagedKind::Special, &file);
        let clash = prepare(
            ManagedKind::Special,
            &body_of(&[("localhost", Value::Bool(true))]),
            &fs,
            &file,
        )
        .unwrap_err();
        assert_eq!(clash.code_status(), axum_status_conflict());
        let kept = prepare(
            ManagedKind::Special,
            &body_of(&[("refuse_chaos", Value::Bool(false))]),
            &fs,
            &file,
        )
        .unwrap();
        assert_eq!(kept["localhost"], Value::Bool(false));
    }

    fn axum_status_conflict() -> axum::http::StatusCode {
        axum::http::StatusCode::CONFLICT
    }

    /// REQ: DNS-023 (T24.13) — a stored `[local]` is in the merged configuration, so the device
    /// name table (rebuilt every 10 s from `device_dns::Settings`) follows it with no restart.
    #[test]
    fn dns_023_local_settings_put_rebuilds_table() {
        let file = cfg("", "file");
        assert!(crate::device_dns::Settings::from_config(&file).is_none());
        let stored = normalize(
            ManagedKind::Local,
            &body_of(&[
                ("device_domain", Value::String("Home.ARPA.".into())),
                ("device_ttl", Value::from(30)),
            ]),
        )
        .unwrap();
        let mut merged = file.clone();
        overlay(&mut merged, &file, ManagedKind::Local, &stored).unwrap();
        let s = crate::device_dns::Settings::from_config(&merged).expect("names are on");
        assert_eq!(s.domain, "home.arpa");
        assert_eq!(s.ttl, 30);
    }

    /// REQ: DNS-019 (T24.12) — a stored `[special]` is in the merged configuration the next
    /// reload applies (no restart), and deleting it brings the file's back.
    #[test]
    fn dns_019_special_names_put_applies_without_restart() {
        let file = cfg("", "file");
        let stored = normalize(
            ManagedKind::Special,
            &body_of(&[("block_icloud_private_relay", Value::Bool(false))]),
        )
        .unwrap();
        let mut merged = file.clone();
        overlay(&mut merged, &file, ManagedKind::Special, &stored).unwrap();
        assert!(!merged.special.block_icloud_private_relay);
        let back = file.clone();
        assert!(
            back.special.block_icloud_private_relay,
            "the file's (default) applies again"
        );
    }

    /// REQ: DNS-019, DNS-023 (ADR-914) — the set-by-file marks come from the loader: a file's
    /// `[special]` and `[local]` keys are listed, and the entries the file leaves out aren't.
    #[test]
    fn dns_019_loader_marks_the_fields_the_files_set() {
        let file = cfg(
            "[special]\nddr_name = \"dns.example.com\"\n[local]\ndevice_domain = \"home.arpa\"\n",
            "file",
        );
        assert!(file.file_set.iter().any(|k| k == "special.ddr_name"));
        assert!(file.file_set.iter().any(|k| k == "local.device_domain"));
        assert!(!file.file_set.iter().any(|k| k == "clients.mdns"));
        let fs = section_json(ManagedKind::Special, &file);
        let clash = prepare(
            ManagedKind::Special,
            &body_of(&[("ddr_name", Value::String("other.example".into()))]),
            &fs,
            &file,
        )
        .unwrap_err();
        assert_eq!(clash.code_status(), axum::http::StatusCode::CONFLICT);
        let left_out = prepare(ManagedKind::Special, &body_of(&[]), &fs, &file).unwrap();
        assert_eq!(
            left_out["ddr_name"], "dns.example.com",
            "left out: the file's value"
        );
    }

    /// REQ: DNS-019 (T24.12, ADR-914) — `ddr_name` is admin-only on the server: an operator's
    /// change is refused naming the field, an admin's is allowed, agents never change it, and
    /// a change that leaves it alone is an operator's.
    #[test]
    fn dns_019_operator_cannot_set_ddr_name() {
        let before = serde_json::json!({ "ddr_name": null, "localhost": true });
        let after = serde_json::json!({ "ddr_name": "dns.example.com", "localhost": false });
        let e = check_admin_fields(
            ManagedKind::Special,
            &before,
            &after,
            Some(Role::Operator),
            None,
        )
        .unwrap_err();
        assert_eq!(e.code_status(), axum::http::StatusCode::FORBIDDEN);
        assert!(e.detail.contains("ddr_name"), "{}", e.detail);
        assert!(
            check_admin_fields(
                ManagedKind::Special,
                &before,
                &after,
                Some(Role::Admin),
                None
            )
            .is_ok()
        );
        assert!(
            check_admin_fields(
                ManagedKind::Special,
                &before,
                &after,
                Some(Role::Admin),
                Some("bot")
            )
            .is_err(),
            "an agent never"
        );
        let same = serde_json::json!({ "ddr_name": null, "localhost": false });
        assert!(
            check_admin_fields(
                ManagedKind::Special,
                &before,
                &same,
                Some(Role::Operator),
                None
            )
            .is_ok(),
            "only ddr_name is admin-only"
        );
    }

    /// REQ: DNS-023 (T24.13) — `[local]` refuses `local` as a domain (through the merged
    /// configuration's validation), and `hosts_files` can't be set here.
    #[test]
    fn dns_023_local_settings_refuses_local() {
        let file = cfg("", "file");
        let stored = normalize(
            ManagedKind::Local,
            &body_of(&[("device_domain", Value::String("local".into()))]),
        )
        .unwrap();
        let mut merged = file.clone();
        overlay(&mut merged, &file, ManagedKind::Local, &stored).unwrap();
        let errs = telltale_config::validate_config(&merged).unwrap_err();
        assert!(
            errs.iter().any(|e| e.to_string().contains("local")),
            "{errs:?}"
        );
        let hosts = normalize(
            ManagedKind::Local,
            &body_of(&[("hosts_files", Value::Array(vec![]))]),
        )
        .unwrap_err();
        assert!(hosts.detail.contains("hosts_files"));
    }

    /// REQ: DNS-023 (T24.13, ADR-914) — `[clients]` takes only `mdns`: `mdns_port` is refused
    /// by name, and an operator can't turn `mdns` on.
    #[test]
    fn dns_023_operator_cannot_switch_clients_mdns() {
        let port = normalize(
            ManagedKind::Clients,
            &body_of(&[("mdns_port", Value::from(5354))]),
        )
        .unwrap_err();
        assert!(port.detail.contains("mdns_port"), "{}", port.detail);
        let before = serde_json::json!({ "mdns": false });
        let after = serde_json::json!({ "mdns": true });
        let e = check_admin_fields(
            ManagedKind::Clients,
            &before,
            &after,
            Some(Role::Operator),
            None,
        )
        .unwrap_err();
        assert_eq!(e.code_status(), axum::http::StatusCode::FORBIDDEN);
        assert!(e.detail.contains("mdns"), "{}", e.detail);
        assert!(
            check_admin_fields(
                ManagedKind::Clients,
                &before,
                &after,
                Some(Role::Admin),
                None
            )
            .is_ok()
        );
        assert!(
            check_admin_fields(ManagedKind::Clients, &before, &after, None, Some("bot")).is_err(),
            "no agent scope writes mdns"
        );
    }
    /// REQ: FLT-901 (T24.29) - `[filter]` `entry_budget` and `ads_tier`: stored as one section, laid over
    /// the files' values field by field, a field the files set can't be changed (409), a zero budget
    /// or another `[filter]` key is refused, and no agent changes it.
    #[test]
    fn flt_901_filter_settings_overlay_and_refusals() {
        let own = cfg(
            "[filter]
ads_tier = \"light\"
",
            "t.toml",
        );
        let file = section_json(ManagedKind::Filter, &own);
        assert_eq!(file["entry_budget"], 1_000_000);
        // A body that leaves `ads_tier` out keeps the file's; one that changes it is refused.
        let ok = prepare(
            ManagedKind::Filter,
            &serde_json::json!({"entry_budget": 3_000_000}),
            &file,
            &own,
        )
        .unwrap();
        assert_eq!(ok["entry_budget"], 3_000_000);
        assert_eq!(ok["ads_tier"], "light");
        let e = prepare(
            ManagedKind::Filter,
            &serde_json::json!({"entry_budget": 3_000_000, "ads_tier": "ultimate"}),
            &file,
            &own,
        )
        .unwrap_err();
        assert_eq!(e.code, Code::SetByFile);
        // Laid over the files: the budget changes, the file's tier stays.
        let mut c = own.clone();
        overlay(&mut c, &own, ManagedKind::Filter, &ok).unwrap();
        assert_eq!(c.filter.entry_budget, 3_000_000);
        assert_eq!(c.filter.ads_tier, telltale_config::AdsTier::Light);
        // Refusals.
        let plain = Config::default();
        let none = section_json(ManagedKind::Filter, &plain);
        let zero = prepare(
            ManagedKind::Filter,
            &serde_json::json!({"entry_budget": 0}),
            &none,
            &plain,
        )
        .unwrap_err();
        assert!(zero.detail.contains("at least 1"), "{}", zero.detail);
        let other = prepare(
            ManagedKind::Filter,
            &serde_json::json!({"refresh_secs": 5}),
            &none,
            &plain,
        )
        .unwrap_err();
        assert!(other.detail.contains("entry_budget"), "{}", other.detail);
        let tier = prepare(
            ManagedKind::Filter,
            &serde_json::json!({"ads_tier": "huge"}),
            &none,
            &plain,
        )
        .unwrap_err();
        assert_eq!(
            tier.code_status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        let e = check_admin_fields(
            ManagedKind::Filter,
            &none,
            &ok,
            Some(Role::Operator),
            Some("bot"),
        )
        .unwrap_err();
        assert_eq!(e.code, Code::AgentNotAllowed);
        assert!(
            check_admin_fields(ManagedKind::Filter, &none, &ok, Some(Role::Operator), None).is_ok()
        );
    }
}

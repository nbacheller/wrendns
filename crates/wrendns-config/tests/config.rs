//! OPS-005 acceptance tests: unknown keys error with path; env overrides apply.

use wrendns_config::{
    AlertWhen, ByteSize, Config, ConfigError, Loader, Role, Strategy, TelemetryMode,
};

const EXAMPLE: &str = include_str!("../../../docs/examples/wrendns.toml");

fn load_str(toml: &str) -> Result<wrendns_config::Loaded, Vec<ConfigError>> {
    Loader::new()
        .toml_str("test.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
}

fn paths(errs: &[ConfigError]) -> Vec<&str> {
    errs.iter().map(|e| e.path.as_str()).collect()
}

#[test]
fn ops_005_defaults_are_valid() {
    let loaded = load_str("").unwrap();
    assert_eq!(loaded.config, Config::default());
    assert_eq!(loaded.config.listen.len(), 4);
    assert_eq!(loaded.config.node.data_dir.as_str(), "/var/lib/wrendns");
}

#[test]
fn ops_005_example_config_is_valid() {
    let loaded = load_str(EXAMPLE).unwrap();
    let c = &loaded.config;
    assert_eq!(c.upstream.len(), 3);
    assert_eq!(c.upstream_group[0].strategy, Strategy::Fastest);
    assert_eq!(c.cache.max_bytes, ByteSize::mib(32));
    assert_eq!(c.cluster.site.as_str(), "home-pi");
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
}

#[test]
fn ops_005_unknown_key_errors_with_path() {
    let errs = load_str("[cache]\nmax_ttl = 600\nbogus = 1\n").unwrap_err();
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].path, "cache.bogus");
    assert!(
        errs[0].message.contains("unknown field `bogus`"),
        "{}",
        errs[0]
    );
}

#[test]
fn ops_005_unknown_key_in_array_element_errors_with_path() {
    let errs = load_str(
        "[[upstream]]\nname = \"a\"\nurl = \"udp://9.9.9.9\"\n\n\
         [[upstream]]\nname = \"b\"\nurl = \"udp://1.1.1.1\"\ntimeout = 5\n",
    )
    .unwrap_err();
    assert_eq!(errs[0].path, "upstream[1].timeout");
}

#[test]
fn ops_005_unknown_top_level_key_errors_with_path() {
    let errs = load_str("cache_size = 5\n").unwrap_err();
    assert_eq!(errs[0].path, "cache_size");
}

#[test]
fn ops_005_type_error_has_path() {
    let errs = load_str("[telemetry.qlog]\nretention_days = \"thirty\"\n").unwrap_err();
    assert_eq!(errs[0].path, "telemetry.qlog.retention_days");
}

#[test]
fn ops_005_syntax_error_names_the_file() {
    let errs = load_str("[cache\n").unwrap_err();
    assert_eq!(errs[0].path, "test.toml");
}

#[test]
fn ops_005_control_characters_rejected() {
    let errs = load_str("[node]\nname = \"pi\\nevil\"\n").unwrap_err();
    assert_eq!(errs[0].path, "node.name");
    assert!(errs[0].message.contains("control character"));
}

#[test]
fn ops_005_env_override_applies() {
    let loaded = Loader::new()
        .toml_str("test.toml", "[cache]\nmax_ttl = 600\n")
        .env([
            ("WRENDNS_CACHE_MAX_TTL", "1200"),
            ("WRENDNS_ROLE", "resolver"),
            ("WRENDNS_CLUSTER_SITE", "home-pi"),
            ("WRENDNS_CLUSTER_ELIGIBLE", "false"),
            ("WRENDNS_TELEMETRY_MODE", "ship"),
            ("WRENDNS_TELEMETRY_QLOG_RETENTION_DAYS", "7"),
            ("WRENDNS_CACHE_MAX_BYTES", "64MiB"),
            ("UNRELATED", "x"),
        ])
        .load()
        .unwrap();
    let c = loaded.config;
    assert_eq!(c.cache.max_ttl, 1200, "env must beat the file");
    assert_eq!(c.node.role, Role::Resolver);
    assert_eq!(c.cluster.site.as_str(), "home-pi");
    assert!(!c.cluster.eligible);
    assert_eq!(c.telemetry.mode, TelemetryMode::Ship);
    assert_eq!(c.telemetry.qlog.retention_days, 7);
    assert_eq!(c.cache.max_bytes, ByteSize::mib(64));
}

#[test]
fn ops_005_env_override_bad_value_names_variable() {
    let errs = Loader::new()
        .env([("WRENDNS_CACHE_MAX_TTL", "soon")])
        .load()
        .unwrap_err();
    assert_eq!(errs[0].path, "cache.max_ttl (from WRENDNS_CACHE_MAX_TTL)");
}

#[test]
fn ops_005_env_override_invalid_enum_is_reported() {
    let errs = Loader::new()
        .env([("WRENDNS_ROLE", "boss")])
        .load()
        .unwrap_err();
    assert_eq!(errs[0].path, "node.role");
}

#[test]
fn ops_005_unknown_env_vars_warn_not_fail() {
    // Kubernetes service links for a Service named "wrendns".
    let loaded = Loader::new()
        .env([
            ("WRENDNS_SERVICE_HOST", "10.0.0.1"),
            ("WRENDNS_PORT", "udp://10.0.0.1:53"),
            ("WRENDNS_CONFIG", "/etc/wrendns/wrendns.toml"),
            // T6.14 — the Helm charts' downward-API variables are the binary's own.
            ("WRENDNS_KUBE_NODE", "k3s-1"),
            ("WRENDNS_POD", "wrendns-resolver-7d9f"),
            ("WRENDNS_NODE_IPS", "10.50.5.2"),
        ])
        .load()
        .unwrap();
    assert_eq!(loaded.config.node, Config::default().node);
    let unknown: Vec<_> = loaded
        .warnings
        .iter()
        .filter(|w| w.contains("unknown environment variable"))
        .collect();
    assert_eq!(
        unknown.len(),
        2,
        "WRENDNS_CONFIG, _KUBE_NODE, _POD, _NODE_IPS are reserved: {unknown:?}"
    );
}

#[test]
fn ops_005_layers_merge_tables_and_replace_arrays() {
    let loaded = Loader::new()
        .toml_str("base.toml", EXAMPLE)
        .toml_str(
            "node.toml",
            "[cache]\nmax_bytes = \"16MiB\"\n\n[[listen]]\nproto = \"udp\"\naddr = \"127.0.0.1:5353\"\n",
        )
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap();
    let c = loaded.config;
    assert_eq!(c.cache.max_bytes, ByteSize::mib(16));
    assert_eq!(c.cache.max_ttl, 86_400, "sibling keys survive the merge");
    assert_eq!(c.listen.len(), 1, "arrays replace");
    assert_eq!(c.upstream.len(), 3);
}

#[test]
fn ops_005_semantic_errors_are_all_reported() {
    let errs = load_str(
        r#"
[[listen]]
proto = "dot"
addr = "0.0.0.0:853"

[[upstream]]
name = "a"
url = "ftp://example.com"

[[upstream_group]]
name = "default"
members = ["a", "ghost"]

[[route]]
match_suffix = ["lan"]
upstream_group = "nope"

[cache]
min_ttl = 100
max_ttl = 10
"#,
    )
    .unwrap_err();
    let p = paths(&errs);
    for want in [
        "listen[0].tls",
        "upstream[0].url",
        "upstream_group[0].members[1]",
        "route[0].upstream_group",
        "cache.min_ttl",
    ] {
        assert!(p.contains(&want), "missing {want} in {p:?}");
    }
}

#[test]
fn ops_005_json_schema_rejects_unknown_fields() {
    let schema = serde_json::to_value(wrendns_config::json_schema()).unwrap();
    assert_eq!(
        schema["additionalProperties"],
        serde_json::Value::Bool(false)
    );
    assert!(schema["properties"]["cache"].is_object());
}

#[test]
fn flt_004_lists_parse_with_defaults() {
    let loaded = load_str(
        r#"
[[list]]
name = "hagezi-pro"
url = "https://example.com/pro.txt"

[[list]]
name = "my_allow"
kind = "allow"
match = "exact"
rules = ["good.example.com"]

[[list]]
name = "local-file"
path = "/etc/wrendns/block.txt"
enabled = false
refresh_secs = 3600
max_bytes = "1MiB"

[filter]
fetch_concurrency = 2
"#,
    )
    .unwrap();
    let c = &loaded.config;
    assert_eq!(c.list.len(), 3);
    assert_eq!(c.list[0].kind, wrendns_config::ListKind::Block);
    assert_eq!(c.list[0].match_mode, wrendns_config::ListMatch::Subtree);
    assert!(c.list[0].enabled);
    assert_eq!(c.list[1].kind, wrendns_config::ListKind::Allow);
    assert_eq!(c.list[1].match_mode, wrendns_config::ListMatch::Exact);
    assert!(!c.list[2].enabled);
    assert_eq!(c.list[2].max_bytes, Some(ByteSize::mib(1)));
    assert_eq!(c.filter.fetch_concurrency, 2);
    assert_eq!(c.filter.refresh_secs, 86_400);
    assert_eq!(c.filter.max_list_bytes, ByteSize::mib(64));
    assert!(
        !loaded.warnings.iter().any(|w| w.contains("list")),
        "{:?}",
        loaded.warnings
    );
}

#[test]
fn flt_004_list_validation_errors_have_paths() {
    let errs = load_str(
        r#"
[[list]]
name = "Bad Name"
url = "https://example.com/a.txt"

[[list]]
name = "two-sources"
url = "https://example.com/b.txt"
path = "/tmp/b.txt"

[[list]]
name = "no-source"

[[list]]
name = "ftp"
url = "ftp://example.com/c.txt"

[[list]]
name = "ftp"
url = "https://example.com/d.txt"
refresh_secs = 60

[filter]
fetch_concurrency = 0
max_list_bytes = "10B"
"#,
    )
    .unwrap_err();
    let p = paths(&errs);
    for want in [
        "list[0].name",
        "list[1]",
        "list[2]",
        "list[3].url",
        "list[4].name",
        "list[4].refresh_secs",
        "filter.fetch_concurrency",
        "filter.max_list_bytes",
    ] {
        assert!(p.contains(&want), "missing {want} in {p:?}");
    }
}

#[test]
fn flt_004_plain_http_list_warns() {
    let loaded = load_str("[[list]]\nname = \"a\"\nurl = \"http://example.com/a.txt\"\n").unwrap();
    let list_warnings: Vec<_> = loaded
        .warnings
        .iter()
        .filter(|w| w.contains("list["))
        .collect();
    assert_eq!(list_warnings.len(), 1, "{:?}", loaded.warnings);
    assert!(list_warnings[0].contains("list[0].url"));
}

#[test]
fn flt_005_groups_and_clients() {
    let loaded = load_str(
        r#"
[[list]]
name = "ads"
rules = ["||ads.example.com^"]

[[list]]
name = "adult"
rules = ["||adult.example.com^"]

[[group]]
name = "kids"
lists = ["ads", "adult"]
priority = 10

[[client]]
name = "Kids Tablet"
match = ["192.168.1.50", "AA-BB-CC-DD-EE-FF", "id:kids-tablet"]
groups = ["kids"]

[[client]]
name = "office"
match = ["10.0.5.0/24"]

[clients]
trust_edns_mac_from = ["192.168.1.1/32"]
"#,
    )
    .unwrap();
    let c = &loaded.config;
    assert_eq!(c.group[0].priority, 10);
    // No groups of its own: it takes its network's group, else `default` (ADR-050).
    assert_eq!(c.client[1].groups, Vec::<wrendns_config::SafeString>::new());
    assert_eq!(
        wrendns_config::MatchKey::parse("AA-BB-CC-DD-EE-FF").unwrap(),
        wrendns_config::MatchKey::Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    );
    assert!(c.clients.neighbor_table);
}

// REQ: FLT-006 (T24.9, ADR-973) — `hostname:` keys and group router names are label-form router
// names; a router name is in one group only, and a rule may name one.
#[test]
fn flt_006_router_names_are_labels() {
    use wrendns_config::MatchKey;
    assert_eq!(
        MatchKey::parse("hostname:Kitchen-Tablet").unwrap(),
        MatchKey::Hostname("kitchen-tablet".into())
    );
    assert!(
        MatchKey::parse("hostname:Kitchen Tablet").is_err(),
        "a label, not a name"
    );
    assert!(MatchKey::parse("hostname:-edge").is_err());
    assert!(MatchKey::parse("hostname:").is_err());
    // A group's router names are case-insensitive, as the keys are: `Kids-iPad` is `kids-ipad`,
    // so another group naming it in any case is the same duplicate.
    assert!(
        load_str(
            r#"
[[group]]
name = "kids"
router_names = ["Kids-iPad"]
"#
        )
        .is_ok()
    );
    let dup = load_str(
        r#"
[[group]]
name = "kids"
router_names = ["Kids-iPad"]

[[group]]
name = "guests"
router_names = ["kids-ipad"]
"#,
    )
    .err()
    .unwrap_or_default();
    assert!(
        dup.iter()
            .any(|e| e.to_string().contains("already a router name")),
        "a case-only duplicate is refused"
    );
    let errs = load_str(
        r#"
[[group]]
name = "kids"
router_names = ["kids-ipad", "Bad Name"]

[[group]]
name = "guests"
router_names = ["kids-ipad"]

[[client]]
name = "Tablet"
match = ["hostname:kitchen-tablet"]

[[rule]]
id = "no-games"
action = "block"
domain = "games.example"
devices = ["hostname:kitchen-tablet"]

[[rule]]
id = "bad-device"
action = "block"
domain = "ads.example"
devices = ["hostname:not a label"]
"#,
    )
    .unwrap_err();
    let text: Vec<String> = errs.iter().map(ToString::to_string).collect();
    assert!(
        text.iter().any(|e| e.contains("group[0].router_names[1]")),
        "{text:?}"
    );
    assert!(
        text.iter()
            .any(|e| e.contains("group[1].router_names[0]") && e.contains("`kids`")),
        "{text:?}"
    );
    assert!(
        text.iter().any(|e| e.contains("rule[1].devices[0]")),
        "{text:?}"
    );
    assert!(
        !text
            .iter()
            .any(|e| e.contains("rule[0].devices") || e.contains("client[0].match")),
        "{text:?}"
    );
}

// REQ: FLT-005 (ADR-050) — a network can belong to one group; colors are #rrggbb.
#[test]
fn flt_005_group_networks_validation() {
    let errs = load_str(
        r##"
[[group]]
name = "iot"
networks = ["10.20.2.0/24"]
color = "#22c55e"

[[group]]
name = "cameras"
networks = ["10.20.2.0/24", "192.168.7.0/24"]
color = "green"
"##,
    )
    .unwrap_err();
    let text: Vec<String> = errs.iter().map(ToString::to_string).collect();
    assert!(
        text.iter()
            .any(|e| e.contains("group[1].networks[0]") && e.contains("`iot`")),
        "{text:?}"
    );
    assert!(
        text.iter().any(|e| e.contains("group[1].color")),
        "{text:?}"
    );
    assert_eq!(text.len(), 2, "{text:?}");
}

#[test]
fn flt_006_client_validation_errors() {
    let errs = load_str(
        r#"
[[group]]
name = "kids"
lists = ["nope"]

[[client]]
name = "a"
match = ["192.168.1.50", "zz:zz:zz:zz:zz:zz", "id:Bad_ID", "hello"]
groups = ["ghosts"]

[[client]]
name = "A"
match = ["192.168.1.50"]
"#,
    )
    .unwrap_err();
    let p = paths(&errs);
    for want in [
        "group[0].lists[0]",
        "client[0].match[1]",
        "client[0].match[2]",
        "client[0].match[3]",
        "client[0].groups[0]",
        "client[1].name",
        "client[1].match[0]",
    ] {
        assert!(p.contains(&want), "missing {want} in {p:?}");
    }
}

#[test]
fn flt_008_block_modes() {
    let loaded = load_str(
        r#"
[[group]]
name = "kids"
block_mode = "custom_ip"
block_ips = ["192.168.1.2", "fd00::2"]
block_ttl = 300
ede = "filtered"
ede_text = false

[[group]]
name = "default"
block_mode = "nxdomain"
"#,
    )
    .unwrap();
    let g = &loaded.config.group;
    assert_eq!(g[0].block_mode, wrendns_config::BlockMode::CustomIp);
    assert_eq!(g[0].block_ips.len(), 2);
    assert_eq!(g[0].ede, wrendns_config::EdeKind::Filtered);
    assert!(!g[0].ede_text);
    assert_eq!(g[1].block_mode, wrendns_config::BlockMode::Nxdomain);
    assert_eq!(g[1].block_ttl, 60);
    assert!(g[1].ede_text);

    let errs = load_str("[[group]]\nname = \"x\"\nblock_mode = \"custom_ip\"\n").unwrap_err();
    assert_eq!(paths(&errs), vec!["group[0].block_ips"]);
    let errs = load_str("[[group]]\nname = \"x\"\nblock_mode = \"sinkhole\"\n").unwrap_err();
    assert_eq!(errs[0].path, "group[0].block_mode");
}

/// REQ: DOC-002/003 (T4.6) — the site's configuration reference is rendered from
/// docs/config-schema.json; this keeps it identical to `wrendns config schema`.
/// Regenerate with `UPDATE_SCHEMA=1 cargo test -p wrendns-config doc_002_committed_schema`.
#[test]
fn doc_002_committed_schema_matches_the_code() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/config-schema.json");
    let doc = serde_json::to_string_pretty(&wrendns_config::json_schema()).unwrap() + "\n";
    if std::env::var_os("UPDATE_SCHEMA").is_some() {
        std::fs::write(&path, &doc).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == doc,
        "docs/config-schema.json is out of date: run UPDATE_SCHEMA=1 cargo test -p wrendns-config doc_002_committed_schema"
    );
}

/// REQ: FLT-005 (T6.12, ADR-067) — quick rules: a valid one loads; each kind of mistake is
/// reported at its path.
#[test]
fn flt_005_quick_rules_validate() {
    let ok = load_str(
        r#"
[[group]]
name = "kids"
[[client]]
name = "Mom phone"
match = ["192.168.1.20"]
[[rule]]
id = "r1"
action = "allow"
domain = "game.example.com"
devices = ["Mom phone"]
expires = "2026-10-05T21:30:00Z"
note = "Mom's game"
[[rule]]
id = "r2"
action = "block"
domain = "videos.example.com"
groups = ["kids"]
[[rule]]
id = "r3"
action = "block"
domain = "ads.example.net"
devices = ["192.168.1.0/24"]
"#,
    )
    .unwrap();
    assert_eq!(ok.config.rule.len(), 3);
    assert_eq!(ok.config.rule[0].action, wrendns_config::RuleAction::Allow);

    let errs = load_str(
        r#"
[[rule]]
id = "a"
action = "block"
domain = "*.bad"
[[rule]]
id = "a"
action = "allow"
domain = "ok.example"
groups = ["nope"]
devices = ["Nobody"]
expires = "tomorrow"
"#,
    )
    .unwrap_err();
    let p = paths(&errs);
    for want in [
        "rule[0].domain",
        "rule[1].id",
        "rule[1].groups[0]",
        "rule[1].devices[0]",
        "rule[1].expires",
    ] {
        assert!(p.contains(&want), "{want} missing from {p:?}");
    }
}

/// REQ: OPS-012 (ADR-163) — the watchdog is on by default (60 s, restart, six an hour), and its
/// limits are checked at their paths.
#[test]
fn ops_012_watchdog_settings_and_limits() {
    let d = load_str("").unwrap().config.watchdog;
    assert!(d.enabled);
    assert_eq!(d.stall_secs, 60);
    assert_eq!(d.action, wrendns_config::WatchdogAction::Restart);
    assert_eq!(d.max_restarts_per_hour, 6);

    let set = load_str(
        "[watchdog]\nenabled = false\nstall_secs = 120\naction = \"dump\"\nmax_restarts_per_hour = 0\n",
    )
    .unwrap()
    .config
    .watchdog;
    assert!(!set.enabled);
    assert_eq!(set.stall_secs, 120);
    assert_eq!(set.action, wrendns_config::WatchdogAction::Dump);
    assert_eq!(set.max_restarts_per_hour, 0);

    for (toml, path) in [
        ("[watchdog]\nstall_secs = 19\n", "watchdog.stall_secs"),
        ("[watchdog]\nstall_secs = 601\n", "watchdog.stall_secs"),
        (
            "[watchdog]\nmax_restarts_per_hour = 61\n",
            "watchdog.max_restarts_per_hour",
        ),
    ] {
        let errs = load_str(toml).unwrap_err();
        assert!(paths(&errs).contains(&path), "{toml}: {:?}", paths(&errs));
    }
    assert!(load_str("[watchdog]\naction = \"explode\"\n").is_err());
    // Node-local: a replica keeps its own, and the cluster's shared settings don't carry it.
    assert!(wrendns_config::shared::NODE_LOCAL.contains(&"watchdog"));
}

/// REQ: FLT-012 (T7.9) — a group can only block services that exist, and `svc-` list names
/// are kept for them.
#[test]
fn flt_012_blocked_services_are_validated() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    assert!(
        load("[[group]]\nname = \"kids\"\nblocked_services = [\"tiktok\", \"roblox\"]\n").is_ok()
    );
    let err = format!(
        "{:?}",
        load("[[group]]\nname = \"kids\"\nblocked_services = [\"myspace\"]\n").unwrap_err()
    );
    assert!(err.contains("no service `myspace`"), "{err}");
    let err = format!(
        "{:?}",
        load("[[list]]\nname = \"svc-mine\"\nrules = [\"||x.example^\"]\n").unwrap_err()
    );
    assert!(err.contains("kept for blocked services"), "{err}");
}

/// REQ: FLT-901 (ADR-994 item 9) — the `cat-` list prefix is the catalog's: a list that defines a
/// source under that name is refused, a bare `cat-` entry may only set `mode`, and a group cannot
/// name a category list.
#[test]
fn flt_901_cat_prefix_reserved() {
    let load = |toml: &str| load_str(toml).map(|l| l.config);
    let err = format!(
        "{:?}",
        load(
            "[[list]]
name = \"cat-mine\"
url = \"https://example.com/x.txt\"
"
        )
        .unwrap_err()
    );
    assert!(err.contains("kept for category lists"), "{err}");
    let err = format!(
        "{:?}",
        load(
            "[[list]]
name = \"cat-hagezi-nsfw\"
rules = [\"||x.example^\"]
"
        )
        .unwrap_err()
    );
    assert!(err.contains("kept for category lists"), "{err}");
    // A bare entry sets the mode of a real category list (shadow) and nothing else.
    assert!(
        load(
            "[[list]]
name = \"cat-hagezi-nsfw\"
mode = \"shadow\"
"
        )
        .is_ok()
    );
    let err = format!(
        "{:?}",
        load(
            "[[list]]
name = \"cat-hagezi-nsfw\"
enabled = false
"
        )
        .unwrap_err()
    );
    assert!(err.contains("can only be set to `mode`"), "{err}");
    let err = format!(
        "{:?}",
        load(
            "[[group]]
name = \"kids\"
lists = [\"cat-hagezi-nsfw\"]
"
        )
        .unwrap_err()
    );
    assert!(err.contains("content.categories"), "{err}");
}

/// REQ: FLT-901, FLT-902 — a group's content: levels parse, a category id this version does
/// not know is a warning (version skew), a service bundle or an unknown tier is an error, and so
/// is an unknown safe-search engine.
#[test]
fn flt_902_content_and_engines_are_validated() {
    let ok = load_str(
        "[[group]]
name = \"kids\"
safe_search_engines = [\"google\", \"bing\"]
         content = { level = \"enhanced\", categories = [\"adult\", \"gambling\", \"from-the-future\"], tiers = { gambling = \"extended\" }, ads = true }
",
    )
    .unwrap();
    assert!(
        ok.warnings.iter().any(|w| w.contains("from-the-future")),
        "{:?}",
        ok.warnings
    );
    let c = ok.config.group[0].content.as_ref().unwrap();
    assert_eq!(c.level, wrendns_config::ContentLevel::Enhanced);
    assert!(c.ads);
    let bad = |toml: &str| format!("{:?}", load_str(toml).unwrap_err());
    let e = bad("[[group]]
name = \"g\"
content = { level = \"enhanced\", categories = [\"ai\"] }
");
    assert!(e.contains("bundle of services"), "{e}");
    let e = bad("[[group]]
name = \"g\"
content = { tiers = { gambling = \"huge\" } }
");
    assert!(e.contains("no tier `huge`"), "{e}");
    let e = bad("[[group]]
name = \"g\"
content = { tiers = { ads = \"light\" } }
");
    assert!(e.contains("ads_tier"), "{e}");
    let e = bad("[[group]]
name = \"g\"
safe_search_engines = [\"altavista\"]
");
    assert!(e.contains("no engine `altavista`"), "{e}");
    let e = bad("[[group]]
name = \"g\"
content = { level = \"loud\" }
");
    assert!(e.contains("level"), "{e}");
    let e = bad("[filter]
entry_budget = 0
");
    assert!(e.contains("entry_budget"), "{e}");
}

/// REQ: FLT-010 (T7.10) — schedules: known schedules, lists, and services; readable windows
/// and time zones.
#[test]
fn flt_010_schedules_are_validated() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = r#"
[[group]]
name = "kids"
schedules = ["bedtime"]
[[schedule]]
name = "bedtime"
action = "block_all"
tz = "UTC"
window = [{ days = ["weekdays"], start = "21:00", end = "07:00" }]
"#;
    assert!(load(ok).is_ok());
    for (bad, why) in [
        (
            ok.replace("schedules = [\"bedtime\"]", "schedules = [\"nap\"]"),
            "no schedule `nap`",
        ),
        (ok.replace("\"weekdays\"", "\"someday\""), "day `someday`"),
        (ok.replace("\"21:00\"", "\"9pm\""), "use HH:MM"),
        (
            ok.replace("\"UTC\"", "\"Mars/Base\""),
            "time zone `Mars/Base`",
        ),
        (
            ok.replace("\"block_all\"", "\"enable_lists\""),
            "needs at least one list",
        ),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: OBS-010 (T7.12) — alerts: rules name destinations that exist; http(s) URLs; a sane
/// interval and threshold.
#[test]
fn obs_010_alerts_are_validated() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = r#"
[alerts]
interval_secs = 30
[[alerts.destination]]
name = "phone"
type = "ntfy"
url = "https://ntfy.sh/my-dns"
[[alerts.rule]]
name = "upstreams"
when = "upstream_down"
for_secs = 60
to = ["phone"]
[[alerts.rule]]
name = "servfail"
when = "servfail_rate"
threshold = 10
to = ["phone"]
"#;
    assert!(load(ok).is_ok(), "{:?}", load(ok).err());
    for (bad, why) in [
        (
            ok.replace("to = [\"phone\"]\n[[", "to = [\"pager\"]\n[["),
            "no destination `pager`",
        ),
        (
            ok.replace("https://ntfy.sh", "ftp://ntfy.sh"),
            "http:// or https://",
        ),
        (
            ok.replace("interval_secs = 30", "interval_secs = 1"),
            "at least 5 seconds",
        ),
        (
            ok.replace("threshold = 10", "threshold = 150"),
            "from 0 to 100",
        ),
        (
            ok.replace("name = \"servfail\"", "name = \"upstreams\""),
            "must be unique",
        ),
        (
            ok.replace("\"upstream_down\"", "\"moon_phase\""),
            "moon_phase",
        ),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: OBS-016 (T11.1) — objectives below 100%, a threshold that is a histogram bucket bound,
/// a window the rollups hold; `slo_burn` is an alert condition.
#[test]
fn obs_016_slo_is_validated() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = r#"
[slo]
availability_target = 99.95
latency_target = 99.0
latency_ms = 100
window_days = 28
[[alerts.destination]]
name = "phone"
type = "ntfy"
url = "https://ntfy.sh/my-dns"
[[alerts.rule]]
name = "budget"
when = "slo_burn"
to = ["phone"]
"#;
    let cfg = load(ok).unwrap().config;
    assert_eq!((cfg.slo.latency_ms, cfg.slo.window_days), (100, 28));
    assert!(cfg.slo.enabled, "on by default");
    let d = wrendns_config::Config::default().slo;
    assert_eq!(
        (
            d.availability_target,
            d.latency_target,
            d.latency_ms,
            d.window_days
        ),
        (99.9, 99.0, 250, 30)
    );
    for (bad, why) in [
        (
            ok.replace("availability_target = 99.95", "availability_target = 100"),
            "up to (not including) 100",
        ),
        (
            ok.replace("latency_target = 99.0", "latency_target = 20"),
            "from 50",
        ),
        (
            ok.replace("latency_ms = 100", "latency_ms = 120"),
            "bucket bounds",
        ),
        (
            ok.replace("window_days = 28", "window_days = 365"),
            "from 1 to 90 days",
        ),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: OBS-018 (T11.5) — `mode = "shadow"` for block lists only; enforce by default.
#[test]
fn obs_018_shadow_mode_is_validated() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = "[[list]]\nname = \"candidate\"\nrules = [\"||shop.example^\"]\nmode = \"shadow\"\n";
    let cfg = load(ok).unwrap().config;
    assert_eq!(cfg.list[0].mode, wrendns_config::ListMode::Shadow);
    let plain = load("[[list]]\nname = \"x\"\nrules = [\"||a.example^\"]\n")
        .unwrap()
        .config;
    assert_eq!(plain.list[0].mode, wrendns_config::ListMode::Enforce);
    let err = format!(
        "{:?}",
        load(&format!("{ok}kind = \"allow\"\n")).unwrap_err()
    );
    assert!(err.contains("shadow is for block lists"), "{err}");
}

/// REQ: OBS-022 (T12.1) — exclusions: on by default but empty; names must be domain names
/// (`*.` and a trailing dot allowed), clients addresses or networks; off keeps the lists.
#[test]
fn obs_022_exclusions_are_validated() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let cfg = load("").unwrap().config;
    assert!(cfg.exclusions.enabled && !cfg.exclusions.active());
    let cfg = load(
        "[exclusions]\nnames = [\"*.ntp.org\", \"connectivitycheck.gstatic.com.\"]\nclients = [\"192.168.1.10\", \"fd00::/64\"]\n",
    )
    .unwrap()
    .config;
    assert!(cfg.exclusions.active());
    let off = load("[exclusions]\nenabled = false\nnames = [\"ntp.org\"]\n")
        .unwrap()
        .config;
    assert!(
        !off.exclusions.active(),
        "off keeps the list, excludes nothing"
    );
    for bad in [
        "[exclusions]\nnames = [\"not a name\"]\n",
        "[exclusions]\nnames = [\"\"]\n",
        "[exclusions]\nclients = [\"300.1.1.1\"]\n",
    ] {
        assert!(load(bad).is_err(), "{bad}");
    }
}

/// REQ: OBS-901 (T26.2, ADR-958 section 4) — `[map]` defaults and bounds: every out-of-range
/// value is refused with its field named, and red can't come before yellow.
#[test]
fn obs_901_map_config_defaults_and_bounds() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let m = load("").unwrap().config.map;
    assert!(m.enabled);
    assert_eq!(
        (
            m.event_rate,
            m.min_sample,
            m.warn_slow_pct,
            m.warn_error_pct,
            m.error_pct,
            m.warn_blocked_pct
        ),
        (200, 20, 10, 5, 25, 60)
    );
    assert_eq!(m.warn_latency_ms, None, "follows [slo] latency_ms");
    for (bad, field) in [
        (
            "[map]
event_rate = 9
",
            "map.event_rate",
        ),
        (
            "[map]
event_rate = 2001
",
            "map.event_rate",
        ),
        (
            "[map]
min_sample = 0
",
            "map.min_sample",
        ),
        (
            "[map]
warn_latency_ms = 0
",
            "map.warn_latency_ms",
        ),
        (
            "[map]
warn_slow_pct = 101
",
            "map.warn_slow_pct",
        ),
        (
            "[map]
warn_blocked_pct = 0
",
            "map.warn_blocked_pct",
        ),
        (
            "[map]
warn_error_pct = 30
",
            "map.error_pct",
        ),
        (
            "[map]
speed = 3
",
            "speed",
        ),
    ] {
        let err = format!("{:?}", load(bad).unwrap_err());
        assert!(err.contains(field), "{bad}: {err}");
    }
    assert!(
        load(
            "[map]
event_rate = 10
error_pct = 5
"
        )
        .is_ok()
    );
    assert!(
        load(
            "[map]
enabled = false
"
        )
        .is_ok()
    );
}

/// REQ: OPS-010 (T13.4) — maintenance lasts an hour unless a request says otherwise; the
/// default is a minute to a day; `maintenance` is an alert condition.
#[test]
fn ops_010_maintenance_default_and_alert_rule() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    assert_eq!(load("").unwrap().config.node.maintenance_default_secs, 3600);
    let cfg = load(
        "[node]\nmaintenance_default_secs = 7200\n[[alerts.destination]]\nname = \"phone\"\ntype = \"ntfy\"\nurl = \"https://ntfy.sh/my-dns\"\n[[alerts.rule]]\nname = \"maint\"\nwhen = \"maintenance\"\nfor_secs = 0\nto = [\"phone\"]\n",
    )
    .unwrap()
    .config;
    assert_eq!(cfg.node.maintenance_default_secs, 7200);
    assert_eq!(
        cfg.alerts.rule[0].when,
        wrendns_config::AlertWhen::Maintenance
    );
    for bad in [30, 86_401] {
        let e = load(&format!("[node]\nmaintenance_default_secs = {bad}\n"))
            .err()
            .map(|e| format!("{e:?}"))
            .unwrap_or_default();
        assert!(e.contains("maintenance_default_secs"), "{bad}: {e}");
    }
}

/// REQ: OBS-023 (T12.3) — lists go stale after 30 days unchanged by default; per list too.
#[test]
fn obs_023_stale_after_days() {
    let cfg = wrendns_config::Loader::new()
        .toml_str(
            "t.toml",
            "[[list]]\nname = \"slow\"\nurl = \"https://lists.example/slow.txt\"\nstale_after_days = 0\n",
        )
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    assert_eq!(cfg.filter.stale_after_days, 30);
    assert_eq!(cfg.list[0].stale_after_days, Some(0));
}

/// REQ: OBS-017 (T11.6) — exemplars on by default, traces off; traces need the collector.
#[test]
fn obs_017_traces_need_an_endpoint() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let cfg = load("").unwrap().config;
    assert!(cfg.telemetry.metrics.exemplars);
    assert_eq!(
        (
            cfg.telemetry.otlp.traces_sample_every,
            cfg.telemetry.otlp.traces_slow_ms
        ),
        (0, 0)
    );
    let err = format!(
        "{:?}",
        load("[telemetry.otlp]\ntraces_slow_ms = 500\n").unwrap_err()
    );
    assert!(err.contains("telemetry.otlp.traces_slow_ms"), "{err}");
    let cfg = load(
        "[telemetry.otlp]\nendpoint = \"http://otel:4318\"\ntraces_slow_ms = 500\ntraces_sample_every = 1000\n",
    )
    .unwrap()
    .config;
    assert_eq!(cfg.telemetry.otlp.traces_sample_every, 1000);
}

/// REQ: OBS-019 (T11.4) — second opinions: off by default; a reference group that exists; a
/// warning when the sample adds noticeable traffic.
#[test]
fn obs_019_upstream_check_is_validated() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    assert_eq!(
        wrendns_config::Config::default()
            .upstream_check
            .sample_every,
        0
    );
    let ok = r#"
[[upstream]]
name = "quad9"
url = "udp://9.9.9.9"
[[upstream_group]]
name = "reference"
members = ["quad9"]
[upstream_check]
sample_every = 1000
reference = "reference"
keep = 50
"#;
    let loaded = load(ok).unwrap();
    assert_eq!(loaded.config.upstream_check.keep, 50);
    assert!(
        loaded
            .warnings
            .iter()
            .all(|w| !w.contains("upstream_check"))
    );
    let busy = load(&ok.replace("sample_every = 1000", "sample_every = 10")).unwrap();
    assert!(
        busy.warnings.iter().any(|w| w.contains("asked twice")),
        "{:?}",
        busy.warnings
    );
    for (bad, why) in [
        (
            ok.replace("reference = \"reference\"", "reference = \"nope\""),
            "no upstream group `nope`",
        ),
        (ok.replace("keep = 50", "keep = 0"), "from 1 to 1000"),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: OBS-020 (T11.3) — probes: targets by IP with a scheme probes speak; a sane schedule;
/// `cert_expiring` thresholds in days.
#[test]
fn obs_020_probes_are_validated() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = r#"
[probe]
interval_secs = 60
timeout_ms = 1500
targets = ["udp://10.50.5.112:53", "https://[fd00::53]:443/dns-query"]
cert_warn_days = 21
[[alerts.destination]]
name = "phone"
type = "ntfy"
url = "https://ntfy.sh/my-dns"
[[alerts.rule]]
name = "certs"
when = "cert_expiring"
threshold = 30
to = ["phone"]
"#;
    let cfg = load(ok).unwrap().config;
    assert_eq!(cfg.probe.targets.len(), 2);
    assert!(
        wrendns_config::Config::default().probe.enabled,
        "on by default"
    );
    for (bad, why) in [
        (
            ok.replace("udp://10.50.5.112:53", "udp://dns.example:53"),
            "an IP address and port",
        ),
        (
            ok.replace("udp://10.50.5.112:53", "ftp://10.50.5.112:53"),
            "the scheme is",
        ),
        (
            ok.replace("udp://10.50.5.112:53", "udp://10.50.5.112:53/x"),
            "take a path",
        ),
        (
            ok.replace("interval_secs = 60", "interval_secs = 1"),
            "at least 5 seconds",
        ),
        (
            ok.replace("timeout_ms = 1500", "timeout_ms = 60000"),
            "from 100 to 10000",
        ),
        (
            ok.replace("threshold = 30", "threshold = 900"),
            "days from 1 to 365",
        ),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: OBS-010 (T7.13) — event sinks: each kind's required settings; known statuses.
#[test]
fn obs_010_sinks_are_validated() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = r#"
[[telemetry.sink]]
name = "file"
type = "file"
path = "/var/log/q.jsonl"
[[telemetry.sink]]
name = "siem"
type = "syslog"
address = "udp://10.0.0.2:514"
statuses = ["blocked"]
[[telemetry.sink]]
name = "hook"
type = "webhook"
url = "https://logs.example.net/in"
"#;
    assert!(load(ok).is_ok(), "{:?}", load(ok).err());
    for (bad, why) in [
        (
            ok.replace("path = \"/var/log/q.jsonl\"\n", ""),
            "needs `path`",
        ),
        (
            ok.replace("udp://10.0.0.2:514", "10.0.0.2"),
            "udp://host:port",
        ),
        (
            ok.replace("https://logs", "ftp://logs"),
            "http:// or https://",
        ),
        (
            ok.replace("\"blocked\"", "\"naughty\""),
            "unknown status `naughty`",
        ),
        (
            ok.replace("name = \"hook\"", "name = \"file\""),
            "must be unique",
        ),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: DNS-001 (review 01 q2) — a listener's connection caps parse, `0` per address means no
/// limit, and neither applies to a udp listener (or `max_connections = 0`).
#[test]
fn dns_001_listener_connection_caps() {
    let c = load_str(
        "[[listen]]\nproto = \"tcp\"\naddr = \"0.0.0.0:53\"\nmax_connections = 256\nmax_connections_per_address = 0\n",
    )
    .unwrap()
    .config;
    assert_eq!(c.listen[0].max_connections, Some(256));
    assert_eq!(c.listen[0].max_connections_per_address, Some(0));
    let plain = load_str("[[listen]]\nproto = \"tcp\"\naddr = \"0.0.0.0:53\"\n")
        .unwrap()
        .config;
    assert_eq!(
        plain.listen[0].max_connections_per_address, None,
        "unset = the default"
    );

    let errs = load_str(
        "[[listen]]\nproto = \"udp\"\naddr = \"0.0.0.0:53\"\nmax_connections = 5\nmax_connections_per_address = 5\n\n[[listen]]\nproto = \"tcp\"\naddr = \"0.0.0.0:53\"\nmax_connections = 0\n",
    )
    .unwrap_err();
    let p = paths(&errs);
    assert!(p.contains(&"listen[0].max_connections"), "{p:?}");
    assert!(
        p.contains(&"listen[0].max_connections_per_address"),
        "{p:?}"
    );
    assert!(p.contains(&"listen[1].max_connections"), "{p:?}");
}

/// REQ: FLT-003 (review 02-08) — `[filter] max_regexes` defaults to 1,000, 0 means no limit,
/// and an absurd value is refused.
#[test]
fn flt_003_max_regexes_setting() {
    assert_eq!(Config::default().filter.max_regexes, 1000);
    let c = load_str("[filter]\nmax_regexes = 0\n").unwrap().config;
    assert_eq!(c.filter.max_regexes, 0);
    let errs = load_str("[filter]\nmax_regexes = 100001\n").unwrap_err();
    assert!(paths(&errs).contains(&"filter.max_regexes"));
}

/// REQ: T8.2 — `[[router]]`: the credentials each kind needs, and `tls_server_name` (a host
/// name, only for https, and not with verification off).
#[test]
fn t8_2_routers_are_validated() {
    const UNIFI: &str = "[[router]]\nname = \"udm\"\ntype = \"unifi\"\nurl = \"https://192.168.1.1\"\napi_key_file = \"/k\"\n";
    let ok = load_str(&format!(
        "{UNIFI}tls_ca = \"/ca.pem\"\ntls_server_name = \"unifi.local\"\n"
    ))
    .unwrap();
    assert_eq!(
        ok.config.router[0]
            .tls_server_name
            .as_ref()
            .map(wrendns_config::SafeString::as_str),
        Some("unifi.local")
    );
    assert!(
        !ok.warnings.iter().any(|w| w.contains("router")),
        "{:?}",
        ok.warnings
    );

    let errs =
        load_str("[[router]]\nname = \"udm\"\ntype = \"unifi\"\nurl = \"https://192.168.1.1\"\n")
            .unwrap_err();
    assert_eq!(paths(&errs), ["router[0]"]);
    let errs = load_str(&format!("{UNIFI}tls_server_name = \"not a name\"\n")).unwrap_err();
    assert_eq!(paths(&errs), ["router[0].tls_server_name"]);
    let errs = load_str(&format!(
        "{UNIFI}tls_insecure_skip_verify = true\ntls_server_name = \"unifi.local\"\n"
    ))
    .unwrap_err();
    assert_eq!(paths(&errs), ["router[0].tls_server_name"]);
    let http = UNIFI.replace("https://", "http://");
    let errs = load_str(&format!("{http}tls_server_name = \"unifi.local\"\n")).unwrap_err();
    assert_eq!(paths(&errs), ["router[0].tls_server_name"]);
    // Verification off still loads, with a warning that points at the alternative.
    let off = load_str(&format!("{UNIFI}tls_insecure_skip_verify = true\n")).unwrap();
    assert!(
        off.warnings.iter().any(|w| w.contains("tls_server_name")),
        "{:?}",
        off.warnings
    );
}

/// REQ: API-012 (T22.3) — `type = "home_assistant"`: a token file, and none of the other kinds'
/// settings.
#[test]
fn api_012_home_assistant_router_is_validated() {
    const HA: &str =
        "[[router]]\nname = \"ha\"\ntype = \"home_assistant\"\nurl = \"http://192.0.2.20:8123\"\n";
    let ok = load_str(&format!("{HA}api_key_file = \"/run/secrets/ha-token\"\n")).unwrap();
    assert_eq!(
        ok.config.router[0].kind,
        wrendns_config::RouterKind::HomeAssistant
    );
    assert_eq!(paths(&load_str(HA).unwrap_err()), ["router[0]"]);
    for extra in [
        "username = \"u\"\n",
        "password_file = \"/p\"\n",
        "api_secret_file = \"/s\"\n",
        "site = \"default\"\n",
    ] {
        let errs = load_str(&format!("{HA}api_key_file = \"/t\"\n{extra}")).unwrap_err();
        assert_eq!(paths(&errs), ["router[0]"], "{extra}");
    }
}

/// REQ: DNS-023 (T22.1) — `[local] device_domain`: a domain name, not `local`; a sane TTL;
/// a warning when `device_mdns` has no listener.
#[test]
fn dns_023_device_domain_is_validated() {
    let ok = load_str("[local]\ndevice_domain = \"home.arpa\"\n").unwrap();
    assert_eq!(
        ok.config
            .local
            .device_domain
            .as_ref()
            .map(wrendns_config::SafeString::as_str),
        Some("home.arpa")
    );
    assert_eq!(ok.config.local.device_ttl, 60);
    assert!(load_str("[local]\ndevice_domain = \"lan.\"\n").is_ok());
    for bad in ["local", "LOCAL", "bad name", "-x.home.arpa", "", "a..b"] {
        let errs = load_str(&format!("[local]\ndevice_domain = \"{bad}\"\n")).unwrap_err();
        assert_eq!(paths(&errs), ["local.device_domain"], "{bad}");
    }
    let errs = load_str("[local]\ndevice_ttl = 0\n").unwrap_err();
    assert_eq!(paths(&errs), ["local.device_ttl"]);
    let w = load_str("[local]\ndevice_domain = \"home.arpa\"\ndevice_mdns = true\n").unwrap();
    assert!(
        w.warnings.iter().any(|x| x.contains("device_mdns")),
        "{:?}",
        w.warnings
    );
}

// REQ: FLT-017 (T15.1) — `[kubernetes]`: map rules name known groups and kinds; the section is
// shared but left out of the shared part while at its defaults (older replicas).
#[test]
fn flt_017_kubernetes_section() {
    let ok = load_str(
        r#"
[[group]]
name = "media"

[kubernetes]
enabled = true
namespaces = ["media", "home"]
default_group = "media"

[[kubernetes.map]]
namespace = "media*"
group = "media"

[[kubernetes.map]]
namespace = "jobs"
kind = "cronjob"
name = "backup"
group = "default"
"#,
    )
    .unwrap();
    let k = &ok.config.kubernetes;
    assert!(k.enabled);
    assert_eq!(k.label.as_str(), "wrendns.com/group");
    assert_eq!(k.map[0].key(), "media*/*/*");
    assert_eq!(k.map[1].key(), "jobs/cronjob/backup");
    let errs = load_str(
        "[kubernetes]\ndefault_group = \"nope\"\n[[kubernetes.map]]\nnamespace = \"a b\"\nkind = \"vm\"\ngroup = \"kids\"\n",
    )
    .unwrap_err();
    assert_eq!(
        paths(&errs),
        [
            "kubernetes.default_group",
            "kubernetes.map[0].namespace",
            "kubernetes.map[0].kind",
            "kubernetes.map[0].group"
        ]
    );
    let errs = load_str(
        "[[kubernetes.map]]\nnamespace = \"a\"\ngroup = \"default\"\n[[kubernetes.map]]\nnamespace = \"a\"\ngroup = \"default\"\n",
    )
    .unwrap_err();
    assert_eq!(paths(&errs), ["kubernetes.map[1]"]);
    let shared = wrendns_config::shared::shared_part(&Config::default());
    assert!(shared.get("kubernetes").is_none(), "defaults aren't sent");
    let shared = wrendns_config::shared::shared_part(&ok.config);
    assert!(shared.get("kubernetes").is_some());
}

// REQ: CLU-014 (owner 2026-10-19) — `[drill]`: a monthly schedule names its nodes, 15 to 300 s,
// an hour of the day, a known zone and group, not a group and devices both; the defaults
// (schedule off) aren't sent to the cluster.
#[test]
fn clu_014_drill_section() {
    let ok = load_str(
        "[[group]]\nname = \"iot\"\n[drill]\nschedule = \"monthly\"\nnodes = [\"home-pi\"]\ngroup = \"iot\"\nfor_secs = 45\nhour = 4\ntz = \"UTC\"\nmode = \"refused\"\n",
    )
    .unwrap();
    let d = &ok.config.drill;
    assert_eq!(d.schedule, wrendns_config::DrillSchedule::Monthly);
    assert_eq!((d.for_secs, d.hour), (45, 4));
    assert_eq!(d.mode, wrendns_config::DrillMode::Refused);
    let errs = load_str(
        "[drill]\nschedule = \"monthly\"\nfor_secs = 400\nhour = 24\ntz = \"Mars/Base\"\ngroup = \"nope\"\nclients = [\"tv\"]\n",
    )
    .unwrap_err();
    assert_eq!(
        paths(&errs),
        [
            "drill.for_secs",
            "drill.hour",
            "drill.tz",
            "drill.group",
            "drill.clients",
            "drill.nodes"
        ]
    );
    let shared = wrendns_config::shared::shared_part(&Config::default());
    assert!(shared.get("drill").is_none(), "defaults aren't sent");
}

/// REQ: DNS-022 — a stub zone on a `recursive://` upstream needs its name and its servers,
/// and isn't valid on another kind of upstream.
#[test]
fn dns_022_stub_zone_validates() {
    let ok = load_str(
        r#"
[[upstream]]
name = "corp"
url = "recursive://"
[upstream.recursive]
stub_zone = "corp.example"
stub_servers = ["10.0.0.53", "10.0.0.54"]
"#,
    )
    .unwrap();
    let r = &ok.config.upstream[0].recursive;
    assert_eq!(r.stub_zone.as_deref(), Some("corp.example"));
    assert_eq!(r.stub_servers.len(), 2);

    let errs = load_str(
        r#"
[[upstream]]
name = "no-servers"
url = "recursive://"
[upstream.recursive]
stub_zone = "corp.example"
[[upstream]]
name = "no-zone"
url = "recursive://"
[upstream.recursive]
stub_servers = ["10.0.0.53"]
[[upstream]]
name = "not-recursive"
url = "udp://10.0.0.53"
[upstream.recursive]
stub_zone = "corp.example"
stub_servers = ["10.0.0.53"]
"#,
    )
    .unwrap_err();
    let p = paths(&errs);
    for want in [
        "upstream[0].recursive.stub_servers",
        "upstream[1].recursive.stub_zone",
        "upstream[2].recursive",
    ] {
        assert!(p.contains(&want), "{want} missing from {p:?}");
    }
}

/// REQ: DNS-902, DNS-015 — `ecs` on a `recursive://` upstream is refused with the field named
/// (the recursor asks authoritative servers, which never get a client subnet); `strip` is the
/// default's own word and stays valid. The address settings are plain booleans, off by default.
#[test]
fn dns_902_ecs_is_refused_on_a_recursive_upstream() {
    let ok = load_str(
        r#"
[[upstream]]
name = "root"
url = "recursive://"
ecs = "strip"
[upstream.recursive]
allow_local_servers = true
allow_private_servers = true
"#,
    )
    .unwrap();
    let r = &ok.config.upstream[0].recursive;
    assert!(r.allow_local_servers && r.allow_private_servers);
    let d = wrendns_config::RecursiveConfig::default();
    assert!(!d.allow_local_servers && !d.allow_private_servers);
    for ecs in ["client", "203.0.113.0/24"] {
        let errs = load_str(&format!(
            r#"
[[upstream]]
name = "root"
url = "recursive://"
ecs = "{ecs}"
"#
        ))
        .unwrap_err();
        assert!(
            paths(&errs).contains(&"upstream[0].ecs"),
            "{ecs}: {:?}",
            paths(&errs)
        );
    }
}

/// REQ: OBS-038 (ADR-161) — anomaly mutes: a device or group and a kind each, names that exist
/// and have addresses, no mute for everyone, no MAC address, a readable end time; devices and
/// groups resolve to the networks the engine matches.
#[test]
fn obs_038_anomaly_mutes_are_validated_and_resolved() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let ok = r#"
[[client]]
name = "lg-tv"
match = ["192.168.1.20", "aa:bb:cc:dd:ee:ff"]
[[client]]
name = "mac-only"
match = ["aa:bb:cc:dd:ee:01"]
[[group]]
name = "iot"
networks = ["192.168.9.0/24"]
[[anomaly_mute]]
name = "tv-sweep"
devices = ["lg-tv", "10.0.0.7"]
groups = ["iot"]
kinds = ["nxdomain_storm", "chatty_loop"]
expires = "2026-12-31T00:00:00Z"
note = "hourly reverse-DNS sweep"
"#;
    let loaded = load(ok).unwrap();
    let r = wrendns_config::mute::resolve(&loaded.config);
    assert_eq!(r.len(), 1);
    let nets: Vec<String> = r[0]
        .nets
        .iter()
        .map(|c| format!("{}/{}", c.addr, c.prefix))
        .collect();
    assert_eq!(nets, ["10.0.0.7/32", "192.168.1.20/32", "192.168.9.0/24"]);
    assert_eq!(r[0].expires_unix, Some(1_798_675_200));
    for (bad, why) in [
        (
            ok.replace(
                "devices = [\"lg-tv\", \"10.0.0.7\"]\ngroups = [\"iot\"]",
                "",
            ),
            "switching the anomaly engine off",
        ),
        (
            ok.replace(
                "kinds = [\"nxdomain_storm\", \"chatty_loop\"]",
                "kinds = []",
            ),
            "at least one kind",
        ),
        (ok.replace("\"nxdomain_storm\"", "\"bogus\""), "bogus"),
        (
            ok.replace("devices = [\"lg-tv\"", "devices = [\"fridge\""),
            "neither a device name nor an IP",
        ),
        (
            ok.replace("devices = [\"lg-tv\"", "devices = [\"aa:bb:cc:dd:ee:ff\""),
            "is a MAC address",
        ),
        (
            ok.replace("devices = [\"lg-tv\"", "devices = [\"mac-only\""),
            "has no IP or network",
        ),
        (
            ok.replace("groups = [\"iot\"]", "groups = [\"default\"]"),
            "no addresses to mute",
        ),
        (
            ok.replace("groups = [\"iot\"]", "groups = [\"ghost\"]"),
            "unknown group `ghost`",
        ),
        (
            ok.replace("2026-12-31T00:00:00Z", "next week"),
            "isn't an RFC 3339 time",
        ),
        (
            format!(
                "{ok}\n[[anomaly_mute]]\nname = \"tv-sweep\"\ndevices = [\"10.0.0.8\"]\nkinds = [\"dga\"]\n"
            ),
            "used twice",
        ),
    ] {
        let err = format!("{:?}", load(&bad).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// Every field a stored secret can fill, set twice (with a bad name and an inline OTLP header).
const BOTH: &str = r#"
[[router]]
name = "unifi"
type = "unifi"
url = "https://192.168.1.1"
api_key_file = "/run/secrets/unifi"
api_key_ref = "unifi"
[[router]]
name = "opn"
type = "opnsense"
url = "https://opnsense.lan"
api_key_ref = "opn.key"
api_secret_file = "/run/secrets/opn"
api_secret_ref = "opn.secret"
[[alerts.destination]]
name = "phone"
type = "ntfy"
url = "https://ntfy.sh/t"
token_file = "/run/secrets/ntfy"
token_ref = "ntfy"
[[alerts.destination]]
name = "mail"
type = "email"
url = "smtp://smtp.example:587"
from = "a@example.com"
to = ["a@example.com"]
username = "a@example.com"
password_file = "/run/secrets/smtp"
password_ref = "smtp"
[[telemetry.sink]]
name = "splunk"
type = "webhook"
url = "https://hec.example/services/collector"
token_file = "/run/secrets/hec"
token_ref = "hec"
[telemetry.otlp]
endpoint = "https://otel.example"
headers = { api-key = "inline" }
header_refs = { api-key = "otlp", x-other = "Bad Name" }
[auth.oidc]
public_url = "https://dns.example.com"
[[auth.oidc.provider]]
id = "kc"
issuer = "https://kc.example/realms/home"
client_id = "wrendns"
client_secret = "inline"
client_secret_ref = "kc"
[cluster.git]
repo = "https://git.example/r.git"
path = "t.toml"
credentials_file = "/run/secrets/git"
credentials_ref = "git"
webhook_secret_file = "/run/secrets/hook"
webhook_secret_ref = "hook"
"#;

/// One each, by reference.
const REFS: &str = r#"
[[router]]
name = "unifi"
type = "unifi"
url = "https://192.168.1.1"
api_key_ref = "router.unifi.api_key"
[[router]]
name = "ha"
type = "home_assistant"
url = "http://ha:8123"
api_key_ref = "ha"
[[alerts.destination]]
name = "mail"
type = "email"
url = "smtp://smtp.example:587"
from = "a@example.com"
to = ["a@example.com"]
username = "a@example.com"
password_ref = "smtp"
"#;

/// REQ: OPS-014 (AC7, ADR-903 §2) — a credential comes from one of its inline value, its
/// `_file` and its `_ref`: two of them is an error at the reference's path, for every field a
/// stored secret can fill; a reference's name is checked; an OTLP header is in `headers` or
/// `header_refs`; `<redacted>` in the files is an error; and the fields a kind needs may come
/// from a reference.
#[test]
fn ops_014_file_inline_ref_mutually_exclusive() {
    let errs = load_str(BOTH).unwrap_err();
    let p = paths(&errs);
    for want in [
        "router[0].api_key_ref",
        "router[1].api_secret_ref",
        "alerts.destination[0].token_ref",
        "alerts.destination[1].password_ref",
        "telemetry.sink[0].token_ref",
        "telemetry.otlp.header_refs.api-key",
        "telemetry.otlp.header_refs.x-other",
        "auth.oidc.provider[0].client_secret_ref",
        "cluster.git.credentials_ref",
        "cluster.git.webhook_secret_ref",
    ] {
        assert!(p.contains(&want), "{want} not in {p:?}");
    }
    assert!(
        !p.contains(&"router[1]"),
        "OPNsense's key and secret may be references: {p:?}"
    );
    // One each, by reference: valid, and the kinds' needs are met.
    let loaded = load_str(REFS).unwrap();
    assert_eq!(
        loaded.config.router[0].api_key_ref.as_deref(),
        Some("router.unifi.api_key")
    );
    // Serialized only when set: a configuration without references reads as before.
    let plain = toml::to_string(&load_str("").unwrap().config).unwrap();
    assert!(
        !plain.contains("_ref =") && !plain.contains("header_refs"),
        "{plain}"
    );
    let back = toml::to_string(&loaded.config).unwrap();
    assert!(
        back.contains("api_key_ref = \"router.unifi.api_key\""),
        "{back}"
    );
    // The redaction marker is never a value.
    let errs = load_str(
        r#"
[[upstream]]
name = "doh"
url = "https://doh.example/dns-query"
headers = { Authorization = "<redacted>" }
[[upstream_group]]
name = "default"
members = ["doh"]
"#,
    )
    .unwrap_err();
    assert_eq!(paths(&errs), ["upstream[0].headers.Authorization"]);
    // A URL's password too, wherever a credential path has one (what `config check --print`
    // shows for it).
    let errs = load_str(
        r#"
[[alerts.destination]]
name = "hook"
type = "webhook"
url = "https://u:<redacted>@hooks.example/x"
[cluster.git]
repo = "https://git:<redacted>@git.example/cfg.git"
path = "wrendns/shared.toml"
"#,
    )
    .unwrap_err();
    let p = paths(&errs);
    for want in ["alerts.destination[0].url", "cluster.git.repo"] {
        assert!(p.contains(&want), "{want} not in {p:?}");
    }
}

/// REQ: T8.2, CLU-003 (ADR-166) — `offline_days`: 30 unless set, 0 turns offline names off,
/// more than a year is refused, and the default is not written back, so a node on an older
/// build (the section refuses fields it doesn't know) still reads the shared configuration.
#[test]
fn t8_2_router_offline_days() {
    const UNIFI: &str = "[[router]]\nname = \"udm\"\ntype = \"unifi\"\nurl = \"https://192.168.1.1\"\napi_key_file = \"/k\"\n";
    let default = load_str(UNIFI).unwrap();
    assert_eq!(default.config.router[0].offline_days, 30);
    let written = serde_json::to_value(&default.config.router[0]).unwrap();
    assert!(written.get("offline_days").is_none(), "{written}");

    let off = load_str(&format!("{UNIFI}offline_days = 0\n")).unwrap();
    assert_eq!(off.config.router[0].offline_days, 0);
    let written = serde_json::to_value(&off.config.router[0]).unwrap();
    assert_eq!(written["offline_days"], 0);

    let year = load_str(&format!("{UNIFI}offline_days = 365\n")).unwrap();
    assert_eq!(year.config.router[0].offline_days, 365);
    let errs = load_str(&format!("{UNIFI}offline_days = 366\n")).unwrap_err();
    assert_eq!(paths(&errs), ["router[0].offline_days"]);
}

/// REQ: OBS-010 (T27.1) — the Alerts form offers every `when` the server accepts (the `AlertWhen`
/// enum, read from its JSON Schema), and no other: `ui/src/lib/alert-conditions.ts` is compared
/// with the enum in both directions, so a new condition fails this test until the form offers it.
#[test]
fn obs_010_alert_conditions_match_ui() {
    const UI_LIST: &str = include_str!("../../../ui/src/lib/alert-conditions.ts");
    let schema = serde_json::to_value(schemars::schema_for!(AlertWhen)).unwrap();
    // Doc comments on the variants make schemars write `oneOf` with a `const` each; plain
    // variants give an `enum` array. Both are read.
    let mut server: Vec<String> = match (schema["enum"].as_array(), schema["oneOf"].as_array()) {
        (Some(values), _) => values
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        (None, Some(variants)) => variants
            .iter()
            .filter_map(|v| v["const"].as_str().map(str::to_owned))
            .collect(),
        (None, None) => panic!("AlertWhen is a string enum"),
    };
    server.sort();
    assert!(server.len() >= 22, "the schema lists the enum's values");

    // The array literal in the module: every quoted name between `alertConditions` and `];`.
    let body = UI_LIST
        .split_once("alertConditions")
        .and_then(|(_, rest)| rest.split_once("];"))
        .map(|(body, _)| body)
        .expect("ui/src/lib/alert-conditions.ts exports alertConditions");
    let mut ui: Vec<String> = body
        .split('\'')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, name)| name.to_owned())
        .collect();
    let listed = ui.len();
    ui.sort();
    ui.dedup();
    assert_eq!(listed, ui.len(), "no condition is listed twice");
    let missing: Vec<&String> = server.iter().filter(|c| !ui.contains(c)).collect();
    let unknown: Vec<&String> = ui.iter().filter(|c| !server.contains(c)).collect();
    assert!(missing.is_empty(), "the Alerts form lacks: {missing:?}");
    assert!(
        unknown.is_empty(),
        "the Alerts form offers what the server doesn't accept: {unknown:?}"
    );
}

/// REQ: OBS-013 (T27.5, ADR-1007) — the anomaly settings, the per-client series' cap and the query
/// log's upper bounds are checked by the server as the settings form shows them: a direct API
/// write of 0 or a huge value is refused with the field's path.
#[test]
fn obs_013_anomaly_metrics_and_qlog_bounds_are_validated() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    assert!(load("").is_ok(), "the defaults are valid");
    for (toml, path) in [
        (
            "[telemetry.anomaly]\nlearning_days = 0\n",
            "telemetry.anomaly.learning_days",
        ),
        (
            "[telemetry.anomaly]\nlearning_days = 91\n",
            "telemetry.anomaly.learning_days",
        ),
        (
            "[telemetry.anomaly]\nmax_clients = 0\n",
            "telemetry.anomaly.max_clients",
        ),
        (
            "[telemetry.anomaly]\nmax_clients = 100001\n",
            "telemetry.anomaly.max_clients",
        ),
        (
            "[telemetry.anomaly]\nnxdomain_per_minute = 0\n",
            "telemetry.anomaly.nxdomain_per_minute",
        ),
        (
            "[telemetry.anomaly]\nnxdomain_percent = 0\n",
            "telemetry.anomaly.nxdomain_percent",
        ),
        (
            "[telemetry.anomaly]\nnxdomain_percent = 500\n",
            "telemetry.anomaly.nxdomain_percent",
        ),
        (
            "[telemetry.metrics]\nper_client_cap = 0\n",
            "telemetry.metrics.per_client_cap",
        ),
        (
            "[telemetry.metrics]\nper_client_cap = 4294967295\n",
            "telemetry.metrics.per_client_cap",
        ),
        (
            "[telemetry.qlog]\nretention_days = 3651\n",
            "telemetry.qlog.retention_days",
        ),
        (
            "[telemetry.qlog]\nflush_interval_secs = 3601\n",
            "telemetry.qlog.flush_interval_secs",
        ),
        (
            "[telemetry.dnstap]\nbuffer = 99\n",
            "telemetry.dnstap.buffer",
        ),
        (
            "[telemetry.dnstap]\nsample_every = 0\n",
            "telemetry.dnstap.sample_every",
        ),
    ] {
        let errs = load(toml).unwrap_err();
        assert!(
            paths(&errs).contains(&path),
            "{toml}: expected {path}, got {:?}",
            paths(&errs)
        );
    }
    let ok = "[telemetry.anomaly]\nlearning_days = 90\nmax_clients = 100000\nnxdomain_per_minute = 1\nnxdomain_percent = 100\n[telemetry.metrics]\nper_client_cap = 10000\n[telemetry.qlog]\nretention_days = 3650\nflush_interval_secs = 3600\n[telemetry.dnstap]\nbuffer = 1000000\n";
    assert!(load(ok).is_ok(), "the bounds themselves are accepted");
    // REQ: OBS-007, API-905 (T40.13, review) - a file whose dnstap `buffer` is above the API's
    // ceiling still loads (it was valid before the ceiling), with a warning.
    let big = load("[telemetry.dnstap]\nbuffer = 2000000\n").expect("a large buffer still loads");
    assert!(
        big.warnings
            .iter()
            .any(|w| w.contains("telemetry.dnstap.buffer") && w.contains("2000000")),
        "{:?}",
        big.warnings
    );
    assert!(
        !load(ok)
            .unwrap()
            .warnings
            .iter()
            .any(|w| w.contains("dnstap")),
        "no warning at the ceiling"
    );
}

/// REQ: OBS-007, API-905 (T40.13) - the dnstap socket is a path with no control characters; a
/// relative path in a file written before the check still loads, with a warning.
#[test]
fn obs_007_dnstap_socket_is_a_clean_path() {
    let toml = |sock: &str| format!("[telemetry.dnstap]\nsocket = \"{sock}\"\n");
    // An empty or blank socket loads, with a warning (it meant no tap; review 5).
    assert!(
        load_str(&toml("  "))
            .expect("loads")
            .warnings
            .iter()
            .any(|w| w.contains("telemetry.dnstap.socket") && w.contains("empty"))
    );
    let bad = "/run/a\\u0007b";
    let errs = load_str(&toml(bad)).unwrap_err();
    assert!(
        paths(&errs).contains(&"telemetry.dnstap.socket"),
        "{bad}: {errs:?}"
    );
    let rel = load_str(&toml("dnstap.sock")).expect("still loads");
    assert!(
        rel.warnings
            .iter()
            .any(|w| w.contains("telemetry.dnstap.socket") && w.contains("absolute")),
        "{:?}",
        rel.warnings
    );
    assert!(
        !load_str(&toml("/run/dnstap.sock"))
            .unwrap()
            .warnings
            .iter()
            .any(|w| w.contains("dnstap"))
    );
}

/// REQ: OBS-007, API-905 (T40.13, review) - a dnstap address is `[tcp://]host:port` with a host name
/// or IP address; another scheme or a host with white space still loads from a file (it was valid
/// before the check) with a warning, and the API's check (`dnstap_address_ok`) refuses it.
#[test]
fn obs_007_dnstap_address_is_tcp_host_port() {
    for ok in [
        "tcp://192.0.2.5:6000",
        "192.0.2.5:6000",
        "collector.example.net:6000",
        "tcp://[2001:db8::5]:6000",
    ] {
        assert!(wrendns_config::dnstap_address_ok(ok), "{ok}");
        let toml = format!(
            "[telemetry.dnstap]
address = \"{ok}\"
"
        );
        assert!(
            !load_str(&toml)
                .unwrap()
                .warnings
                .iter()
                .any(|w| w.contains("telemetry.dnstap.address")),
            "{ok}"
        );
    }
    for bad in ["udp://h:53", "http://h:80", "bad host:53", "tcp://h /x:53"] {
        assert!(!wrendns_config::dnstap_address_ok(bad), "{bad}");
        let toml = format!(
            "[telemetry.dnstap]
address = \"{bad}\"
"
        );
        let loaded = load_str(&toml).expect("a file written before the check still loads");
        assert!(
            loaded
                .warnings
                .iter()
                .any(|w| w.contains("telemetry.dnstap.address")),
            "{bad}: {:?}",
            loaded.warnings
        );
    }
}

/// REQ: UPS-013 (T24.31, ADR-997) — an upstream's `source` reads as an address, `address:0`, or
/// a network; a port, a wildcard and nonsense are refused.
#[test]
fn ups_013_parse_source() {
    use wrendns_config::{SourceSpec, parse_source};
    assert!(matches!(
        parse_source("198.51.100.252"),
        Ok(SourceSpec::Addr(_))
    ));
    assert!(matches!(
        parse_source("198.51.100.252:0"),
        Ok(SourceSpec::Addr(_))
    ));
    assert!(matches!(
        parse_source("[fd00::2]:0"),
        Ok(SourceSpec::Addr(_))
    ));
    assert!(matches!(
        parse_source("198.51.100.0/24"),
        Ok(SourceSpec::Subnet(_))
    ));
    for bad in [
        "198.51.100.252:53",
        "0.0.0.0",
        "::",
        "0.0.0.0/0",
        "224.0.0.1",
        "fe80::1",
        "fe80::/64",
        "eth0",
        "",
    ] {
        assert!(parse_source(bad).is_err(), "{bad}");
    }
    let c = wrendns_config::Cidr::parse("198.51.100.252/24").unwrap();
    assert_eq!(c.network().to_string(), "198.51.100.0/24");
}

/// REQ: T24.27 — every `WRENDNS_*` variable the binary itself reads (the shipped unit,
/// bundles and chart set `WRENDNS_SUPERVISOR`) is known: none is warned about at start.
#[test]
fn t24_27_binary_env_vars_are_not_reported_unknown() {
    let loaded = Loader::new()
        .env([
            ("WRENDNS_SUPERVISOR", "systemd"),
            ("WRENDNS_IGNORE_GUARDED", "1"),
            ("WRENDNS_TOKEN", "t"),
            ("WRENDNS_LOG_DNSSEC_LIBRARY", "1"),
            // A schema key (`node.drain_delay_secs`): applied, not reported.
            ("WRENDNS_DRAIN_DELAY_SECS", "7"),
        ])
        .load()
        .unwrap();
    let unknown: Vec<_> = loaded
        .warnings
        .iter()
        .filter(|w| w.contains("unknown environment variable"))
        .collect();
    assert!(unknown.is_empty(), "{unknown:?}");
    assert_eq!(loaded.config.node.drain_delay_secs, 7);
}

/// REQ: OPS-004 - install.sh's own variables (a mirror, its key, the prefix) are in the
/// environment when the installer runs `wrendns`: known names, not warned about.
#[test]
fn ops_004_installer_env_vars_are_not_reported_unknown() {
    let loaded = Loader::new()
        .env([
            ("WRENDNS_RELEASE_URL", "http://127.0.0.1:8765"),
            ("WRENDNS_RELEASE_PUBKEY", "k"),
            ("WRENDNS_PREFIX", "/usr/local"),
        ])
        .load()
        .unwrap();
    let unknown: Vec<_> = loaded
        .warnings
        .iter()
        .filter(|w| w.contains("unknown environment variable"))
        .collect();
    assert!(unknown.is_empty(), "{unknown:?}");
}

/// REQ: OBS-010 (T24.43) - a `pushover` destination needs both secrets (a file or a stored
/// secret each), an https address (http only to this machine) or none, and a priority from -2 to 1.
#[test]
fn obs_010_pushover_destination_is_validated() {
    let load = |toml: &str| {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
    };
    let dest = |extra: &str| {
        format!("[[alerts.destination]]\nname = \"push\"\ntype = \"pushover\"\n{extra}\n")
    };
    // No url at all: Pushover's own. Both secrets by reference.
    let cfg = load(&dest("token_ref = \"pushover-app\"\nuser_key_ref = \"pushover-user\"\ndevice = \"phone\"\nsound = \"siren\"\npriority_firing = 1\npriority_resolved = -2"))
        .unwrap()
        .config;
    let d = &cfg.alerts.destination[0];
    assert_eq!(d.url.as_str(), "");
    assert_eq!(
        (d.priority_firing, d.priority_resolved),
        (Some(1), Some(-2))
    );
    // Files, and loopback http for a test server.
    for url in [
        "https://push.example/1/messages.json",
        "http://127.0.0.1:9/m",
        "http://localhost/m",
        "http://[::1]:9/m",
    ] {
        let t = dest(&format!(
            "url = \"{url}\"\ntoken_file = \"/run/secrets/a\"\nuser_key_file = \"/run/secrets/u\""
        ));
        assert!(load(&t).is_ok(), "{url}");
    }
    let both = "token_ref = \"a\"\nuser_key_ref = \"u\"\n";
    for (toml, why) in [
        (dest("user_key_ref = \"u\""), "application token"),
        (dest("token_ref = \"a\""), "user or group key"),
        (
            dest(&format!("url = \"http://push.example/m\"\n{both}")),
            "https://",
        ),
        (
            dest(&format!(
                "url = \"http://127.0.0.1.evil.example/m\"\n{both}"
            )),
            "https://",
        ),
        (
            dest(&format!(
                "url = \"http://localhost:80@evil.example/m\"\n{both}"
            )),
            "https://",
        ),
        (
            dest(&format!(
                "url = \"http://127.0.0.1@evil.example/m\"\n{both}"
            )),
            "https://",
        ),
        (dest(&format!("url = \"ftp://x\"\n{both}")), "https://"),
        (
            dest(&format!("priority_firing = 2\n{both}")),
            "from -2 to 1",
        ),
        (
            dest(&format!("priority_resolved = -3\n{both}")),
            "from -2 to 1",
        ),
        (
            dest("token_ref = \"a\"\ntoken_file = \"/x\"\nuser_key_ref = \"u\""),
            "not more",
        ),
        (
            dest("token_ref = \"a\"\nuser_key_ref = \"u\"\nuser_key_file = \"/x\""),
            "not more",
        ),
        (
            dest("token_ref = \"a\"\nuser_key_ref = \"Bad Name\""),
            "stored secret's name",
        ),
    ] {
        let err = format!("{:?}", load(&toml).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

// REQ: API-003 (T24.44, ADR-1053) — `[api] http_redirect` is off by default, is valid next to
// `[api] tls`, and is a validation error without it, on port 0, or on the API's own address.
#[test]
fn api_003_http_redirect_needs_tls() {
    assert!(load_str("").unwrap().config.api.http_redirect.is_none());
    let ok =
        load_str("[api]\ntls = { self_signed = true }\nhttp_redirect = \"0.0.0.0:80\"\n").unwrap();
    assert_eq!(
        ok.config.api.http_redirect,
        Some("0.0.0.0:80".parse().unwrap())
    );
    for (toml, why) in [
        ("[api]\nhttp_redirect = \"0.0.0.0:80\"\n", "needs [api] tls"),
        (
            "[api]\ntls = { self_signed = true }\nhttp_redirect = \"0.0.0.0:0\"\n",
            "1 to 65535",
        ),
        (
            "[api]\nlisten = \"0.0.0.0:8053\"\ntls = { self_signed = true }\nhttp_redirect = \"0.0.0.0:8053\"\n",
            "must differ",
        ),
        (
            "[api]\nlisten = \"[::]:8053\"\ntls = { self_signed = true }\nhttp_redirect = \"192.0.2.1:8053\"\n",
            "must differ",
        ),
    ] {
        let err = format!("{:?}", load_str(toml).unwrap_err());
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// REQ: DNS-901 (T36.2) — `require_client_id` is only for listeners that can carry a key.
#[test]
fn dns_901_require_client_id_needs_an_encrypted_listener() {
    let errs = load_str(
        "[[listen]]\nproto = \"udp\"\naddr = \"127.0.0.1:5353\"\nrequire_client_id = true\n",
    )
    .unwrap_err();
    assert_eq!(paths(&errs), vec!["listen[0].require_client_id"]);
    let errs = load_str(
        "[[listen]]\nproto = \"tcp\"\naddr = \"127.0.0.1:5353\"\nrequire_client_id = true\n",
    )
    .unwrap_err();
    assert_eq!(paths(&errs), vec!["listen[0].require_client_id"]);
    let tls = "tls = { cert = \"c.pem\", key = \"k.pem\" }";
    for proto in ["dot", "doh", "doh3", "doq"] {
        let l = load_str(&format!(
            "[[listen]]\nproto = \"{proto}\"\naddr = \"203.0.113.5:853\"\nrequire_client_id = true\n{tls}\n"
        ))
        .unwrap();
        assert_eq!(l.config.listen[0].require_client_id, Some(true), "{proto}");
        assert!(
            !l.warnings.iter().any(|w| w.contains("require_client_id")),
            "gated: no warning ({proto})"
        );
    }
}

/// REQ: DNS-901 (ADR-1090 point 1) — the startup check: an encrypted listener on a public
/// address with the gate explicitly off is warned about; a gated one, a LAN, loopback or
/// wildcard bind without a setting, and anything inside `allowed_networks` are not.
#[test]
fn dns_901_public_listener_without_the_gate_warns_at_startup() {
    let tls = "tls = { cert = \"c.pem\", key = \"k.pem\" }";
    let warns = |addr: &str, extra: &str| {
        load_str(&format!(
            "[[listen]]
proto = \"dot\"
addr = \"{addr}\"
{tls}
{extra}
"
        ))
        .unwrap()
        .warnings
        .into_iter()
        .filter(|w| w.contains("open resolver"))
        .count()
    };
    assert_eq!(warns("203.0.113.5:853", "require_client_id = false"), 1);
    assert_eq!(warns("[2001:db8::5]:853", "require_client_id = false"), 1);
    assert_eq!(warns("203.0.113.5:853", ""), 0, "gated by default");
    assert_eq!(warns("203.0.113.5:853", "require_client_id = true"), 0);
    assert_eq!(warns("192.168.1.2:853", ""), 0);
    assert_eq!(warns("127.0.0.1:853", ""), 0);
    assert_eq!(
        warns("192.168.1.2:853", "require_client_id = false"),
        0,
        "a private address with the gate off is inside the default allowed_networks"
    );
    // A wildcard bind left on its default is not warned about here (the loader's host facts are
    // unreadable, which gates it); an explicit false on it is (see the wildcard tests below).
    assert_eq!(warns("0.0.0.0:853", ""), 0);
    assert_eq!(warns("[::]:853", ""), 0);
    // Every explicit false on a public address warns, inside allowed_networks too.
    assert_eq!(
        warns(
            "203.0.113.5:853",
            "require_client_id = false
[access]
allowed_networks = [\"203.0.113.0/24\"]"
        ),
        1,
        "docs and code agree: every explicit false on a public listener warns"
    );
}

/// REQ: DNS-901 — a udp or tcp listener cannot be gated, so its warning never tells the
/// operator to set the flag (which is a configuration error there); `false` is accepted.
#[test]
fn dns_901_plain_listener_warning_names_no_flag() {
    for proto in ["udp", "tcp"] {
        let l = load_str(&format!(
            "[[listen]]
proto = \"{proto}\"
addr = \"203.0.113.5:53\"
require_client_id = false
"
        ))
        .unwrap();
        assert!(!l.config.listen[0].gated(wrendns_config::HostFacts::UNKNOWN));
        let w: Vec<_> = l
            .warnings
            .iter()
            .filter(|w| w.contains("open resolver"))
            .collect();
        assert_eq!(w.len(), 1, "{proto}: {:?}", l.warnings);
        assert!(!w[0].contains("require_client_id"), "{}", w[0]);
    }
}

/// REQ: DNS-901 (ADR-1090 point 1) — the public address test is conservative: only loopback,
/// RFC 1918, CGNAT, link-local and unique-local are private; a wildcard is not public.
#[test]
fn dns_901_is_public_address() {
    use std::net::IpAddr;
    let public = |s: &str| wrendns_config::is_public_address(s.parse::<IpAddr>().unwrap());
    for ip in [
        "203.0.113.5",
        "8.8.8.8",
        "1.1.1.1",
        "100.63.255.255",
        "100.128.0.0",
        "172.15.0.1",
        "172.32.0.1",
        "11.0.0.1",
        "192.169.0.1",
        "169.255.0.1",
        "2001:db8::5",
        "2606:4700::1",
        "fe00::1",
        "fec0::1",
        "::ffff:8.8.8.8",
    ] {
        assert!(public(ip), "{ip} is public");
    }
    for ip in [
        "127.0.0.1",
        "127.9.9.9",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "100.64.0.1",
        "100.127.255.255",
        "169.254.1.1",
        "::1",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "febf::1",
        "::ffff:192.168.1.1",
        "::ffff:127.0.0.1",
        "0.0.0.0",
        "::",
    ] {
        assert!(!public(ip), "{ip} is not public");
    }
}

/// REQ: DNS-901 (ADR-1090 point 1) — unset: on for a public bind, off for private, loopback and
/// wildcard; explicit false is honoured on a public bind; explicit true is honoured anywhere
/// that can carry a key; udp and tcp are never gated.
#[test]
fn dns_901_gate_default_explicit_and_transport() {
    let tls = "tls = { cert = \"c.pem\", key = \"k.pem\" }";
    let gate = |proto: &str, addr: &str, extra: &str| {
        let t = if proto == "udp" || proto == "tcp" {
            ""
        } else {
            tls
        };
        let l = load_str(&format!(
            "[[listen]]
proto = \"{proto}\"
addr = \"{addr}\"
{t}
{extra}
"
        ))
        .unwrap();
        let l = &l.config.listen[0];
        let private = wrendns_config::HostFacts {
            public_ipv4: Some(false),
            global_ipv6: false,
        };
        (l.gated(private), l.gated_by_default(private))
    };
    for proto in ["dot", "doh", "doh3", "doq"] {
        assert_eq!(gate(proto, "203.0.113.5:853", ""), (true, true), "{proto}");
        assert_eq!(
            gate(proto, "[2001:db8::5]:853", ""),
            (true, true),
            "{proto}"
        );
        assert_eq!(
            gate(proto, "192.168.1.2:853", ""),
            (false, false),
            "{proto}"
        );
        assert_eq!(gate(proto, "127.0.0.1:853", ""), (false, false), "{proto}");
        assert_eq!(gate(proto, "0.0.0.0:853", ""), (false, false), "{proto}");
        assert_eq!(
            gate(proto, "203.0.113.5:853", "require_client_id = false"),
            (false, false),
            "{proto}: explicit false honoured"
        );
        assert_eq!(
            gate(proto, "203.0.113.5:853", "require_client_id = true"),
            (true, false),
            "{proto}: explicit true is not by default"
        );
        assert_eq!(
            gate(proto, "192.168.1.2:853", "require_client_id = true"),
            (true, false),
            "{proto}: explicit true honoured on a private bind"
        );
    }
    for proto in ["udp", "tcp"] {
        assert_eq!(gate(proto, "203.0.113.5:53", ""), (false, false), "{proto}");
    }
}

/// Loads a DoT listener at `addr` with the host's facts passed in; returns the effective gate of
/// the default, whether it is gated by default, and the gate warnings.
fn wildcard(addr: &str, extra: &str, host: wrendns_config::HostFacts) -> (bool, bool, Vec<String>) {
    let loaded = Loader::new()
        .toml_str(
            "t.toml",
            format!(
                "[[listen]]
proto = \"dot\"
addr = \"{addr}\"
tls = {{ cert = \"c.pem\", key = \"k.pem\" }}
{extra}
"
            ),
        )
        .env(Vec::<(String, String)>::new())
        .host_facts(host)
        .load();
    let l = loaded.unwrap_or_else(|e| unreachable!("the listener must load: {e:?}"));
    let l0 = &l.config.listen[0];
    (
        l0.gated(host),
        l0.gated_by_default(host),
        l.warnings
            .into_iter()
            .filter(|w| w.contains("require_client_id"))
            .collect(),
    )
}

fn host(public_ipv4: Option<bool>, global_ipv6: bool) -> wrendns_config::HostFacts {
    wrendns_config::HostFacts {
        public_ipv4,
        global_ipv6,
    }
}

/// REQ: DNS-901 (ADR-1090 point 2) — a wildcard bind (`0.0.0.0`, `[::]`, `[::ffff:0.0.0.0]`) is gated by
/// default when the host holds a public IPv4 address.
#[test]
fn dns_901_wildcard_with_a_public_ipv4_on_the_host_is_gated() {
    for addr in ["0.0.0.0:853", "[::]:853", "[::ffff:0.0.0.0]:853"] {
        let (gated, by_default, warns) = wildcard(addr, "", host(Some(true), false));
        assert!(gated && by_default, "{addr}");
        assert!(warns.is_empty(), "{addr}: {warns:?}");
    }
}

/// REQ: DNS-901 (ADR-1090 point 2) — a wildcard bind on a host with private IPv4 addresses only is
/// not gated, and not warned about.
#[test]
fn dns_901_wildcard_with_only_private_ipv4_is_not_gated() {
    for addr in ["0.0.0.0:853", "[::]:853", "[::ffff:0.0.0.0]:853"] {
        let (gated, by_default, warns) = wildcard(addr, "", host(Some(false), false));
        assert!(!gated && !by_default, "{addr}");
        assert!(warns.is_empty(), "{addr}: {warns:?}");
    }
}

/// REQ: DNS-901 (ADR-1090 point 2) — a global IPv6 address alone does not gate a wildcard bind; the
/// node warns instead.
#[test]
fn dns_901_wildcard_with_only_a_global_ipv6_is_not_gated_and_warns() {
    for addr in ["0.0.0.0:853", "[::]:853", "[::ffff:0.0.0.0]:853"] {
        let (gated, _, warns) = wildcard(addr, "", host(Some(false), true));
        assert!(!gated, "{addr}");
        assert_eq!(warns.len(), 1, "{addr}: {warns:?}");
        assert!(warns[0].contains("global IPv6"), "{}", warns[0]);
    }
}

/// REQ: DNS-901 (ADR-1090 point 2) — an unreadable interface list fails closed: gated.
#[test]
fn dns_901_wildcard_with_an_unreadable_interface_list_is_gated() {
    let (gated, by_default, _) = wildcard("0.0.0.0:853", "", wrendns_config::HostFacts::UNKNOWN);
    assert!(gated && by_default);
    // An empty address list is as good as unreadable.
    assert_eq!(
        wrendns_config::HostFacts::from_addrs(&[]),
        wrendns_config::HostFacts::UNKNOWN
    );
}

/// REQ: DNS-901 — explicit values win over the wildcard rule, and an explicit false on a wildcard
/// listener that a public address reaches warns (public IPv4, or unreadable: fail closed).
#[test]
fn dns_901_wildcard_explicit_values_are_honoured() {
    for h in [
        host(Some(true), false),
        host(Some(false), true),
        wrendns_config::HostFacts::UNKNOWN,
    ] {
        let (gated, by_default, _) = wildcard("0.0.0.0:853", "require_client_id = true", h);
        assert!(gated && !by_default);
        let (gated, _, warns) = wildcard("0.0.0.0:853", "require_client_id = false", h);
        assert!(!gated);
        let reaches = h.public_ipv4 != Some(false);
        assert_eq!(warns.len(), usize::from(reaches), "{h:?}: {warns:?}");
    }
}

/// REQ: DNS-901 (ADR-1090 point 2) — the facts are made from the addresses of the interfaces: only
/// IPv4 addresses decide the public IPv4 fact, a mapped address counts as IPv4, a link-local or
/// unique-local IPv6 address is not global.
#[test]
fn dns_901_host_facts_from_addresses() {
    let f = |a: &[&str]| {
        let ips: Vec<std::net::IpAddr> = a.iter().map(|s| s.parse().unwrap()).collect();
        wrendns_config::HostFacts::from_addrs(&ips)
    };
    assert_eq!(
        f(&["127.0.0.1", "192.168.1.5", "100.64.0.9"]),
        host(Some(false), false)
    );
    assert_eq!(f(&["127.0.0.1", "203.0.113.5"]), host(Some(true), false));
    assert_eq!(
        f(&["127.0.0.1", "2001:db8::5", "fe80::1", "fd00::1"]),
        host(Some(false), true)
    );
    assert_eq!(
        f(&["127.0.0.1", "fe80::1", "fd00::1"]),
        host(Some(false), false)
    );
    assert_eq!(f(&["::ffff:203.0.113.5"]), host(Some(true), false));
}

/// REQ: DNS-901 — a mapped wildcard is a wildcard everywhere, and clashes like one.
#[test]
fn dns_901_mapped_wildcard_is_a_wildcard() {
    assert!(wrendns_config::is_wildcard("0.0.0.0".parse().unwrap()));
    assert!(wrendns_config::is_wildcard("::".parse().unwrap()));
    assert!(wrendns_config::is_wildcard(
        "::ffff:0.0.0.0".parse().unwrap()
    ));
    assert!(!wrendns_config::is_wildcard(
        "::ffff:1.2.3.4".parse().unwrap()
    ));
    assert!(wrendns_config::addrs_clash(
        "[::ffff:0.0.0.0]:853".parse().unwrap(),
        "203.0.113.5:853".parse().unwrap()
    ));
}

/// REQ: DNS-902 — a stub zone whose servers are loopback or link-local warns unless
/// `allow_local_servers` is set; private servers are fine inside a stub zone.
#[test]
fn dns_902_stub_zone_with_local_servers_warns() {
    let cfg = |servers: &str, extra: &str| {
        format!(
            "[[upstream]]
name = \"corp\"
url = \"recursive://\"
[upstream.recursive]
stub_zone = \"corp.example\"
stub_servers = {servers}
{extra}
"
        )
    };
    let w = load_str(&cfg("[\"127.0.0.2\"]", "")).unwrap().warnings;
    assert!(
        w.iter()
            .any(|m| m.contains("stub_servers") && m.contains("allow_local_servers")),
        "{w:?}"
    );
    let w = load_str(&cfg("[\"169.254.1.1\"]", "")).unwrap().warnings;
    assert!(w.iter().any(|m| m.contains("allow_local_servers")), "{w:?}");
    let w = load_str(&cfg("[\"127.0.0.2\"]", "allow_local_servers = true"))
        .unwrap()
        .warnings;
    assert!(
        !w.iter().any(|m| m.contains("allow_local_servers")),
        "{w:?}"
    );
    let w = load_str(&cfg("[\"10.0.0.53\"]", "")).unwrap().warnings;
    assert!(
        !w.iter().any(|m| m.contains("allow_local_servers")),
        "{w:?}"
    );
}

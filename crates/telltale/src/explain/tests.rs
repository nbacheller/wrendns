use std::collections::HashMap;
use std::sync::Arc;

use telltale_cache::{Cache, CachePolicy};
use telltale_filter::compile::{CompileOptions, ListData, ListInput, compile};
use telltale_filter::matcher::{Lookup, Matcher};
use telltale_filter::parse::ListOptions;
use telltale_filter::snapshot::Snapshot;
use telltale_net::{QueryHandler, RequestMeta, Response, Transport};
use telltale_policy::LocalData;
use telltale_proto::{EdnsOut, rtype};
use telltale_upstream::Router;

use super::*;
use crate::pipeline::{Handler, Pipeline, Policy, Settings};

const CONFIG: &str = r#"
[access]
allowed_networks = ["10.0.0.0/8", "127.0.0.0/8"]

[[upstream]]
name = "u"
url = "udp://127.0.0.1:9"
[[upstream]]
name = "lan-dns"
url = "udp://127.0.0.1:10"
[[upstream_group]]
name = "default"
members = ["u"]
[[upstream_group]]
name = "lan"
members = ["lan-dns"]
[[route]]
match_suffix = ["corp.example"]
upstream_group = "lan"

[[record]]
name = "nas.home.arpa"
type = "A"
value = "10.0.0.10"

[[list]]
name = "ads"
rules = ["||ads.example.com^", "||tracker.example.net^", "||corp.example^"]
[[list]]
name = "ok"
kind = "allow"
rules = ["ok.tracker.example.net"]
[[list]]
name = "strict"
rules = ["||social.example^"]

[[group]]
name = "default"
lists = ["ads", "ok"]

[[group]]
name = "kids"
lists = ["ads", "ok", "strict"]
block_mode = "nxdomain"
priority = 10

[[client]]
name = "tablet"
match = ["10.0.0.5", "aa:bb:cc:dd:ee:01"]
groups = ["kids"]
"#;

/// A pipeline over `CONFIG` with every list compiled, plus the list sources.
fn setup() -> (Arc<Pipeline>, HashMap<String, Vec<u8>>) {
    setup_with("")
}

/// The same, with `extra` appended to `CONFIG`.
fn setup_with(extra: &str) -> (Arc<Pipeline>, HashMap<String, Vec<u8>>) {
    let cfg = telltale_config::Loader::new()
        .toml_str("t.toml", format!("{CONFIG}{extra}"))
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    let (local, report) = LocalData::from_config(&cfg);
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let p = Pipeline::new(
        Settings::default(),
        Arc::new(Cache::new(CachePolicy::default())),
        Arc::new(Router::from_config(&cfg).unwrap()),
        Policy::from_config(&cfg, local),
    );
    let mut sources = HashMap::new();
    let inputs = cfg
        .list
        .iter()
        .map(|l| {
            let text: String = l.rules.iter().flat_map(|r| [r.as_str(), "\n"]).collect();
            sources.insert(l.name.to_string(), text.clone().into_bytes());
            ListInput {
                name: l.name.to_string(),
                options: ListOptions {
                    kind: l.kind,
                    match_mode: l.match_mode,
                },
                source_hash: telltale_filter::fetch::content_hash(text.as_bytes()),
                size: text.len() as u64,
                data: ListData::Bytes(text.into_bytes()),
            }
        })
        .collect();
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("snap");
    compile(inputs, &out, &CompileOptions::default()).unwrap();
    let snap = Arc::new(Snapshot::open(&out).unwrap());
    let m = Matcher::with_lookup(Some(snap), Lookup::Indexed).unwrap();
    p.set_filter(Some(Arc::new(m)));
    (p, sources)
}

fn ask(p: &Pipeline, sources: &HashMap<String, Vec<u8>>, name: &str, client: &str) -> Explanation {
    let req = Request {
        name,
        qtype: rtype::A,
        client: client.parse().unwrap(),
        mac: None,
        client_id: None,
    };
    p.explain(&req, |n| sources.get(n).cloned()).unwrap()
}

/// What the real pipeline does with the same query: answered now (with the response), or
/// deferred to an upstream.
fn served(p: &Arc<Pipeline>, name: &str, client: &str) -> Option<Vec<u8>> {
    let n = NameBuf::from_presentation(name).unwrap();
    let mut q = [0u8; 512];
    let len = build_query(&mut q, 7, &n, rtype::A, 1, true, Some(EdnsOut::new(1232))).unwrap();
    let meta = RequestMeta {
        peer: format!("{client}:1000").parse().unwrap(),
        local: None,
        transport: Transport::Udp,
        client_id: None,
    };
    let mut out = [0u8; 4096];
    match Handler(Arc::clone(p)).handle(&q[..len], &meta, &mut out) {
        Response::Ready(len) => Some(out[..len].to_vec()),
        _ => None,
    }
}

fn contains(msg: &[u8], needle: &[u8]) -> bool {
    msg.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn flt_013_explain_agrees_with_the_pipeline() {
    let (p, sources) = setup();
    let names = [
        "ads.example.com",
        "x.tracker.example.net",
        "ok.tracker.example.net",
        "social.example",
        "www.example.org",
        "nas.home.arpa",
        "host.corp.example",
        "localhost",
    ];
    for client in ["10.0.0.5", "10.0.0.9", "192.0.2.1"] {
        for name in names {
            let e = ask(&p, &sources, name, client);
            let answer = served(&p, name, client);
            let label = format!("{name} from {client}: {:?} ({})", e.outcome, e.summary);
            match e.outcome {
                Outcome::Resolved | Outcome::Allowed => {
                    assert!(
                        answer.is_none(),
                        "{label}: pipeline answered without forwarding"
                    );
                }
                Outcome::Blocked => {
                    let a = answer.unwrap_or_else(|| panic!("{label}: pipeline forwarded"));
                    let list = &e.block.as_ref().unwrap().list;
                    assert!(
                        contains(&a, format!("blocked by list {list}").as_bytes()),
                        "{label}"
                    );
                }
                Outcome::Local | Outcome::Special | Outcome::Refused => {
                    assert!(answer.is_some(), "{label}: pipeline forwarded");
                }
            }
        }
    }
}

#[test]
fn flt_013_explain_names_client_groups_rules_and_route() {
    let (p, sources) = setup();
    // The tablet (kids group) is blocked by `ads`, which also matches for the default group.
    let e = ask(&p, &sources, "x.ads.example.com", "10.0.0.5");
    assert_eq!(e.outcome, Outcome::Blocked);
    assert_eq!(e.client.device.as_deref(), Some("tablet"));
    assert_eq!(e.client.identified_by, "ip");
    assert_eq!(e.client.groups, ["kids"]);
    let block = e.block.as_ref().unwrap();
    assert_eq!(
        (block.list.as_str(), block.mode),
        ("ads", BlockMode::Nxdomain)
    );
    let rule = &e.filter.as_ref().unwrap().rules[0];
    assert!(rule.winner && rule.enabled);
    assert_eq!(rule.name.as_deref(), Some("ads.example.com"));
    assert_eq!(rule.lines[0].line, 1);
    assert_eq!(rule.lines[0].text, "||ads.example.com^");
    assert!(e.route.is_none(), "blocked queries aren't forwarded");

    // The allowlist wins for the tablet; the block rule is listed below it.
    let e = ask(&p, &sources, "ok.tracker.example.net", "10.0.0.5");
    assert_eq!(e.outcome, Outcome::Allowed);
    let rules = &e.filter.as_ref().unwrap().rules;
    assert_eq!((rules[0].list.as_str(), rules[0].winner), ("ok", true));
    assert_eq!((rules[1].list.as_str(), rules[1].winner), ("ads", false));
    assert_eq!(e.route.as_ref().unwrap().group, "default");

    // A name routed to the LAN group, blocked for nobody... except `ads` covers corp.example.
    let e = ask(&p, &sources, "host.corp.example", "10.0.0.9");
    assert_eq!(e.outcome, Outcome::Blocked);
    let e = ask(&p, &sources, "www.example.org", "10.0.0.9");
    assert_eq!(e.outcome, Outcome::Resolved);
    assert_eq!(e.client.identified_by, "default");
    assert_eq!(e.filter.as_ref().unwrap().rules.len(), 0);

    // Recognized by MAC at another address.
    let req = Request {
        name: "social.example",
        qtype: rtype::A,
        client: "10.0.0.77".parse().unwrap(),
        mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
        client_id: None,
    };
    let e = p.explain(&req, |n| sources.get(n).cloned()).unwrap();
    assert_eq!(e.client.identified_by, "neighbor_mac");
    assert_eq!(e.client.mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
    assert_eq!(e.outcome, Outcome::Blocked);

    // Outside allowed_networks.
    assert_eq!(
        ask(&p, &sources, "ads.example.com", "192.0.2.1").outcome,
        Outcome::Refused
    );
    assert_eq!(
        ask(&p, &sources, "nas.home.arpa", "10.0.0.9").outcome,
        Outcome::Local
    );
}

#[test]
fn flt_013_routes_and_pause_are_explained() {
    let (p, sources) = setup();
    // `strict` is only in the kids group: the default group doesn't use it.
    let e = ask(&p, &sources, "social.example", "10.0.0.9");
    assert_eq!(e.outcome, Outcome::Resolved);
    let r = &e.filter.as_ref().unwrap().rules[0];
    assert_eq!((r.list.as_str(), r.enabled), ("strict", false));
    // Pausing the kids group lets the tablet through, and says so.
    let until = unix_now() + 600;
    p.pause.pause_group("kids", until);
    let e = ask(&p, &sources, "social.example", "10.0.0.5");
    assert_eq!(e.outcome, Outcome::Resolved);
    assert_eq!(e.paused_until, Some(until));
    assert!(e.summary.contains("paused"), "{}", e.summary);
    assert!(served(&p, "social.example", "10.0.0.5").is_none());
}

#[test]
fn flt_013_explain_serializes_for_the_api() {
    let (p, sources) = setup();
    let e = ask(&p, &sources, "ads.example.com", "10.0.0.5");
    let v = serde_json::to_value(&e).unwrap();
    assert_eq!(v["outcome"], "blocked");
    assert_eq!(v["block"]["mode"], "nxdomain");
    assert_eq!(v["filter"]["rules"][0]["tier"], "block");
    assert_eq!(v["filter"]["rules"][0]["kind"], "domain");
    assert_eq!(v["filter"]["rules"][0]["scope"], "subtree");
    assert_eq!(v["client"]["groups"][0], "kids");
}

#[test]
fn flt_013_bad_names_are_errors() {
    let (p, sources) = setup();
    let req = Request {
        name: &"a".repeat(300),
        qtype: rtype::A,
        client: "10.0.0.5".parse().unwrap(),
        mac: None,
        client_id: None,
    };
    assert!(p.explain(&req, |n| sources.get(n).cloned()).is_err());
}

/// REQ: FLT-005, FLT-013 (T6.12, ADR-067) — explain names the quick rule that decides, before
/// the lists, and agrees with the pipeline.
#[test]
fn flt_005_explain_shows_quick_rules_first() {
    let (p, sources) = setup_with(
        r#"
[[rule]]
id = "tablet-ads"
action = "allow"
domain = "ads.example.com"
devices = ["tablet"]
note = "tablet game"

[[rule]]
id = "kids-org"
action = "block"
domain = "example.org"
groups = ["kids"]
"#,
    );
    let e = ask(&p, &sources, "ads.example.com", "10.0.0.5");
    assert_eq!(e.outcome, Outcome::Allowed, "{}", e.summary);
    assert!(
        e.summary.contains("quick rule (tablet game, for tablet)"),
        "{}",
        e.summary
    );
    assert!(
        served(&p, "ads.example.com", "10.0.0.5").is_none(),
        "the pipeline forwards it too"
    );
    // Another device: the list still blocks.
    assert_eq!(
        ask(&p, &sources, "ads.example.com", "10.0.0.9").outcome,
        Outcome::Blocked
    );

    let e = ask(&p, &sources, "www.example.org", "10.0.0.5");
    assert_eq!(e.outcome, Outcome::Blocked, "{}", e.summary);
    assert!(
        e.block
            .as_ref()
            .unwrap()
            .list
            .starts_with("quick rule: example.org, for kids")
    );
    let answer = served(&p, "www.example.org", "10.0.0.5").expect("the pipeline answers it");
    assert!(contains(&answer, b"quick rule"));
    assert_eq!(
        ask(&p, &sources, "www.example.org", "10.0.0.9").outcome,
        Outcome::Resolved
    );
}

/// REQ: FLT-010, FLT-013 — a block-everything schedule that's on shows up in the
/// explanation, as the pipeline applies it.
#[test]
fn flt_013_schedules_are_explained() {
    let extra = r#"
[[group]]
name = "night"
networks = ["10.0.3.0/24"]
schedules = ["always"]

[[schedule]]
name = "always"
action = "block_all"
tz = "UTC"
window = [{ days = ["daily"], start = "00:00", end = "23:59" }]
"#;
    let (p, sources) = setup_with(extra);
    let cfg = telltale_config::Loader::new()
        .toml_str("t.toml", format!("{CONFIG}{extra}"))
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    let compiled = telltale_config::schedule::compile(&cfg);
    let clients = telltale_policy::ClientTable::from_config(&cfg);
    p.schedules
        .store(Arc::new(crate::pipeline::ScheduleNow::compute(
            &cfg,
            &compiled,
            clients.groups(),
            1_791_237_600, // Monday 2026-10-05 22:00 UTC: inside the window
        )));
    p.set_filter(None);
    let answer = served(&p, "www.example.org", "10.0.3.5").expect("the pipeline blocks it");
    assert!(contains(&answer, b"blocked by schedule always"));
    let e = ask(&p, &sources, "www.example.org", "10.0.3.5");
    assert_eq!(e.outcome, Outcome::Blocked, "{}", e.summary);
    assert!(e.summary.contains("schedule always"), "{}", e.summary);
    // Other groups are unaffected, in both.
    assert!(served(&p, "www.example.org", "10.0.0.9").is_none());
    assert_eq!(
        ask(&p, &sources, "www.example.org", "10.0.0.9").outcome,
        Outcome::Resolved
    );
}

/// REQ: DNS-018, FLT-013 — a name in an authoritative zone is local data in the
/// explanation too, for the groups that see the zone.
#[test]
fn flt_013_zones_are_explained() {
    let extra = r#"
[[group]]
name = "office"
networks = ["10.0.4.0/24"]

[[zone]]
name = "corp.example"
groups = ["office"]
[[zone.record]]
name = "intranet.corp.example"
type = "A"
value = "10.10.0.5"
"#;
    let cfg = telltale_config::Loader::new()
        .toml_str("t.toml", format!("{CONFIG}{extra}"))
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    let (local, _) = LocalData::from_config(&cfg);
    let mut policy = Policy::from_config(&cfg, local);
    policy.zones = Arc::new(crate::server::load_zones(&cfg).unwrap());
    let p = Pipeline::new(
        Settings::default(),
        Arc::new(Cache::new(CachePolicy::default())),
        Arc::new(Router::from_config(&cfg).unwrap()),
        policy,
    );
    let sources = HashMap::new();
    let answer = served(&p, "intranet.corp.example", "10.0.4.5").expect("answered locally");
    assert!(contains(&answer, &[10, 10, 0, 5]));
    let e = ask(&p, &sources, "intranet.corp.example", "10.0.4.5");
    assert_eq!(e.outcome, Outcome::Local, "{}", e.summary);
    // Outside the office the zone isn't visible.
    assert_eq!(
        ask(&p, &sources, "intranet.corp.example", "10.0.0.9").outcome,
        Outcome::Resolved
    );
}

/// REQ: FLT-013, FLT-014, FLT-011 — list `$dnsrewrite` rules (which win over blocking), the
/// group's own rewrites, and safe search are in the explanation, and each outcome agrees with
/// what the pipeline does with the same query: answered locally, or sent on with a CNAME.
#[test]
fn flt_013_rewrites_and_safe_search_are_explained() {
    let extra = r#"
[[list]]
name = "rw"
rules = [
  "||rw.example^$dnsrewrite=192.0.2.55",
  "||both.example^",
  "||both.example^$dnsrewrite=NOERROR;A;192.0.2.66",
  "||nx.example^$dnsrewrite=NXDOMAIN",
  "||cn.example^$dnsrewrite=target.example",
]

[[group]]
name = "home"
networks = ["10.0.6.0/24"]
lists = ["rw"]
safe_search = true
[[group.rewrite]]
domain = "nas.lan.example"
answer = "192.168.1.10"
[[group.rewrite]]
domain = "tv.example"
answer = "cdn.example"
"#;
    let (p, sources) = setup_with(extra);
    let home = "10.0.6.5";
    // (name, outcome, text in the summary, bytes in the pipeline's local answer or None when
    // the query goes on to an upstream with a CNAME)
    let cases: [(&str, Outcome, &str, Option<&[u8]>); 7] = [
        (
            "www.rw.example",
            Outcome::Local,
            "192.0.2.55",
            Some(&[192, 0, 2, 55]),
        ),
        (
            "both.example",
            Outcome::Local,
            "192.0.2.66",
            Some(&[192, 0, 2, 66]),
        ),
        ("nx.example", Outcome::Local, "NXDOMAIN", Some(&[])),
        (
            "cn.example",
            Outcome::Resolved,
            "CNAME target.example",
            None,
        ),
        (
            "nas.lan.example",
            Outcome::Local,
            "192.168.1.10",
            Some(&[192, 168, 1, 10]),
        ),
        ("tv.example", Outcome::Resolved, "CNAME cdn.example", None),
        (
            "www.google.com",
            Outcome::Resolved,
            "forcesafesearch.google.com",
            None,
        ),
    ];
    for (name, outcome, text, local) in cases {
        let e = ask(&p, &sources, name, home);
        assert_eq!(e.outcome, outcome, "{name}: {}", e.summary);
        assert!(e.summary.contains(text), "{name}: {}", e.summary);
        let answer = served(&p, name, home);
        match (local, answer) {
            (Some(bytes), Some(a)) => assert!(
                bytes.is_empty() || contains(&a, bytes),
                "{name}: the pipeline's answer"
            ),
            (None, None) => {}
            (l, a) => panic!(
                "{name}: explain says {outcome:?} but the pipeline gave {a:?} (expected local: {l:?})"
            ),
        }
    }
    // The rcode answer really is NXDOMAIN in the pipeline.
    assert_eq!(served(&p, "nx.example", home).unwrap()[3] & 0x0F, 3);
    // A group without these lists, rewrites, or safe search sees none of it, in both.
    for name in ["www.rw.example", "nas.lan.example", "www.google.com"] {
        let e = ask(&p, &sources, name, "10.0.0.9");
        assert_eq!(e.outcome, Outcome::Resolved, "{name}: {}", e.summary);
        assert!(served(&p, name, "10.0.0.9").is_none(), "{name}");
    }
}

/// REQ: DNS-019 (ADR-904) — iCloud Private Relay, resolver.arpa, and (switched on)
/// single-label names are explained as special answers, and the pipeline answers them the
/// same way without forwarding; switched off, they resolve normally in both.
#[test]
fn dns_019_special_names_are_explained() {
    let rcode = |a: &[u8]| a[3] & 0x0F;
    let (p, sources) = setup_with("[special]\nsingle_label_nxdomain = true\n");
    for (name, text, rc) in [
        ("mask.icloud.com", "iCloud Private Relay", 3),
        ("mask-h2.icloud.com", "iCloud Private Relay", 3),
        ("_dns.resolver.arpa", "never forwarded", 0),
        ("printer", "single-label name", 3),
    ] {
        let e = ask(&p, &sources, name, "10.0.0.9");
        assert_eq!(e.outcome, Outcome::Special, "{name}: {}", e.summary);
        assert!(e.summary.contains(text), "{name}: {}", e.summary);
        let a = served(&p, name, "10.0.0.9").unwrap_or_else(|| panic!("{name}: forwarded"));
        assert_eq!(rcode(&a), rc, "{name}");
    }
    // A single-label name with a local record is still answered from it.
    let (p, sources) = setup_with(
        "[special]\nsingle_label_nxdomain = true\n[[record]]\nname = \"nas\"\ntype = \"A\"\nvalue = \"10.0.0.11\"\n",
    );
    assert_eq!(ask(&p, &sources, "nas", "10.0.0.9").outcome, Outcome::Local);
    let a = served(&p, "nas", "10.0.0.9").unwrap();
    assert!(contains(&a, &[10, 0, 0, 11]));

    let (p, sources) = setup_with("[special]\nblock_icloud_private_relay = false\n");
    for name in ["mask.icloud.com", "printer"] {
        let e = ask(&p, &sources, name, "10.0.0.9");
        assert_eq!(e.outcome, Outcome::Resolved, "{name}: {}", e.summary);
        assert!(
            served(&p, name, "10.0.0.9").is_none(),
            "{name}: not forwarded"
        );
    }
    // resolver.arpa has no switch: never forwarded.
    assert!(served(&p, "x.resolver.arpa", "10.0.0.9").is_some());
}

/// REQ: DNS-019 (T24.12, ADR-914) — a special-name outcome names the rule that answered, so the
/// UI can link it to its switch (the `special` field: `private_relay`, `single_label`,
/// `resolver_arpa`, `firefox_canary`, `localhost`). A name with no switch names none.
#[test]
fn dns_019_explain_names_the_special_rule() {
    let (p, sources) = setup_with("[special]\nsingle_label_nxdomain = true\n");
    for (name, key) in [
        ("mask.icloud.com", Some("private_relay")),
        ("printer", Some("single_label")),
        ("_dns.resolver.arpa", Some("resolver_arpa")),
        ("localhost", Some("localhost")),
        ("use-application-dns.net", Some("firefox_canary")),
        ("node.invalid", None),
        ("ads.example.com", None),
    ] {
        let e = ask(&p, &sources, name, "10.0.0.9");
        assert_eq!(e.special, key, "{name}: {}", e.summary);
    }
    let (p, sources) = setup_with("[special]\nblock_icloud_private_relay = false\n");
    assert_eq!(
        ask(&p, &sources, "mask.icloud.com", "10.0.0.9").special,
        None
    );
}

/// REQ: DNS-019 (T24.12, ADR-914) — the `ddr` name: a DDR query (SVCB for `_dns.resolver.arpa`)
/// is `ddr` while the node advertises designated resolvers, and `resolver_arpa` otherwise, with
/// or without a `ddr_name`. Any other SVCB query is `resolver_arpa` too.
#[test]
fn dns_019_special_key_names_ddr() {
    // A query message for `name` of type `qtype`: a header, the question, no answers.
    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            m.push(u8::try_from(label.len()).unwrap());
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m
    }
    let ddr = query("_dns.resolver.arpa", rtype::SVCB);
    let q = parse_query(&ddr).unwrap();
    assert_eq!(special_key(&q, Special::ResolverArpa, false), Some("ddr"));
    assert_eq!(
        special_key(&q, Special::ResolverArpa, true),
        Some("resolver_arpa"),
        "no designated resolver advertised: no DDR answer"
    );
    let other_bytes = query("resolver.arpa", rtype::A);
    let other = parse_query(&other_bytes).unwrap();
    assert_eq!(
        special_key(&other, Special::ResolverArpa, false),
        Some("resolver_arpa")
    );
    // Without encrypted listeners (so no advertised resolver), the explanation says resolver_arpa.
    let (p, sources) = setup_with("[special]\nddr_name = \"dns.home.arpa\"\n");
    let req = Request {
        name: "_dns.resolver.arpa",
        qtype: rtype::SVCB,
        client: "10.0.0.9".parse().unwrap(),
        mac: None,
        client_id: None,
    };
    let e = p.explain(&req, |n| sources.get(n).cloned()).unwrap();
    assert_eq!(e.special, Some("resolver_arpa"), "{}", e.summary);
}

// ---- T24.30 (ADR-996): a device's effective policy agrees with Explain.

const POLICY_EXTRA: &str = r#"
[[group]]
name = "iot"
networks = ["10.7.0.0/16"]
safe_search = true
blocked_services = ["tiktok"]

[[group]]
name = "night"
networks = ["10.0.3.0/24"]
schedules = ["bedtime"]

[[schedule]]
name = "bedtime"
action = "block_all"
tz = "UTC"
window = [{ days = ["daily"], start = "21:00", end = "07:00" }]

[[client]]
name = "phone"
match = ["aa:bb:cc:dd:ee:02"]
groups = ["kids"]

[[client]]
name = "printer"
match = ["10.8.0.0/24"]
groups = ["iot"]

[[client]]
name = "badge"
match = ["id:badge-1"]
groups = ["kids"]

[[rule]]
id = "r-tablet"
action = "block"
domain = "game.example"
devices = ["tablet"]
expires = "2026-11-18T22:00:00Z"
note = "homework"

[[rule]]
id = "r-kids"
action = "allow"
domain = "school.example"
groups = ["kids"]

[[rule]]
id = "r-all"
action = "block"
domain = "everyone.example"
"#;

fn policy_cfg() -> telltale_config::Config {
    telltale_config::Loader::new()
        .toml_str("t.toml", format!("{CONFIG}{POLICY_EXTRA}"))
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config
}

fn policy_of(
    p: &Pipeline,
    ip: &str,
    mac: Option<[u8; 6]>,
    client_id: Option<&str>,
    now: u64,
) -> telltale_api::policy_api::ClientPolicy {
    let cfg = policy_cfg();
    let subject = crate::policy_view::Subject {
        asked: ip.to_owned(),
        ip: ip.parse().unwrap(),
        mac,
        client_id: client_id.map(str::to_owned),
        wanted_device: None,
        stand_in: false,
    };
    p.with_explain_state(|st| crate::policy_view::build(st, &cfg, &subject, now))
}

fn explain_as(
    p: &Pipeline,
    sources: &HashMap<String, Vec<u8>>,
    ip: &str,
    mac: Option<[u8; 6]>,
    client_id: Option<&str>,
) -> Explanation {
    let req = Request {
        name: "www.example.org",
        qtype: rtype::A,
        client: ip.parse().unwrap(),
        mac,
        client_id,
    };
    p.explain(&req, |n| sources.get(n).cloned()).unwrap()
}

fn section<'a>(
    p: &'a telltale_api::policy_api::ClientPolicy,
    id: &str,
) -> &'a telltale_api::policy_api::PolicySection {
    p.sections.iter().find(|s| s.id == id).unwrap()
}

/// One row of the identification table: (ip, mac, client id) in; (identified by, group, matched
/// key, group from, group key) out.
type Case = (
    &'static str,
    Option<[u8; 6]>,
    Option<&'static str>,
    &'static str,
    &'static str,
    Option<&'static str>,
    &'static str,
    Option<&'static str>,
);

/// REQ: FLT-006, API-010 (T24.30) — a device matched by network and another matched by MAC (and a
/// client ID, a CIDR and an exact address) each get the right group and key, and the panel's answer
/// is Explain's for the same device: one identification, two readers.
#[test]
fn flt_006_policy_names_the_group_and_key_and_agrees_with_explain() {
    let (p, sources) = setup_with(POLICY_EXTRA);
    let mac = Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);
    let cases: [Case; 6] = [
        (
            "10.7.1.9",
            None,
            None,
            "default",
            "iot",
            None,
            "network",
            Some("10.7.0.0/16"),
        ),
        (
            "10.9.9.9",
            mac,
            None,
            "neighbor_mac",
            "kids",
            Some("aa:bb:cc:dd:ee:02"),
            "device",
            None,
        ),
        (
            "10.8.0.77",
            None,
            None,
            "cidr",
            "iot",
            Some("10.8.0.0/24"),
            "device",
            None,
        ),
        (
            "10.0.0.5",
            None,
            None,
            "ip",
            "kids",
            Some("10.0.0.5"),
            "device",
            None,
        ),
        (
            "10.9.9.9",
            None,
            Some("badge-1"),
            "client_id",
            "kids",
            Some("id:badge-1"),
            "device",
            None,
        ),
        (
            "203.0.113.9",
            None,
            None,
            "default",
            "default",
            None,
            "default",
            None,
        ),
    ];
    for (ip, mac, id, by, group, key, from, gkey) in cases {
        let pol = policy_of(&p, ip, mac, id, 1_795_035_000);
        let ex = explain_as(&p, &sources, ip, mac, id);
        let label = format!("{ip} {mac:?} {id:?}");
        assert_eq!(pol.identified_by, by, "{label}");
        assert_eq!(pol.group, group, "{label}");
        assert_eq!(pol.matched_key.as_deref(), key, "{label}");
        assert_eq!(pol.group_from, from, "{label}");
        assert_eq!(pol.group_key.as_deref(), gkey, "{label}");
        // Explain says the same, field by field.
        assert_eq!(pol.identified_by, ex.client.identified_by, "{label}");
        assert_eq!(pol.groups, ex.client.groups, "{label}");
        assert_eq!(pol.group, ex.client.group, "{label}");
        assert_eq!(pol.device, ex.client.device, "{label}");
        assert_eq!(pol.matched_key, ex.client.matched_key, "{label}");
        assert_eq!(pol.group_from, ex.client.group_from, "{label}");
        assert_eq!(pol.group_key, ex.client.group_key, "{label}");
        assert_eq!(
            pol.groups.first().map(String::as_str),
            Some(group),
            "{label}"
        );
        // The ladder marks exactly the rung that decided.
        let matched: Vec<&str> = pol
            .precedence
            .iter()
            .filter(|r| r.matched)
            .map(|r| r.source.as_str())
            .collect();
        assert_eq!(matched, [by], "{label}");
    }
}

/// REQ: FLT-006, API-010 (T24.30) — the network group's settings show as sections: its blocked
/// services, safe search, the lists in use, and the default upstream group, each with a link.
#[test]
fn flt_006_policy_sections_show_the_groups_settings() {
    let (p, _sources) = setup_with(POLICY_EXTRA);
    let pol = policy_of(&p, "10.7.1.9", None, None, 1_795_035_000);
    let ids: Vec<&str> = pol.sections.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "block",
            "lists",
            "services",
            "safe_search",
            "answers",
            "rewrites",
            "schedules",
            "rules",
            "upstream"
        ]
    );
    let svc = section(&pol, "services");
    assert_eq!(svc.items.len(), 1, "{svc:?}");
    assert_eq!(svc.items[0].label.to_ascii_lowercase(), "tiktok");
    assert_eq!(svc.items[0].from.as_deref(), Some("group iot"));
    assert_eq!(
        svc.items[0].link.as_ref().map(|l| l.path.as_str()),
        Some("/groups")
    );
    let ss = section(&pol, "safe_search");
    assert_eq!(ss.items[0].state.as_deref(), Some("on"));
    // The iot group names no lists, so it uses every enabled one; each links to Lists.
    let lists = section(&pol, "lists");
    assert!(lists.items.iter().any(|i| i.label == "ads"), "{lists:?}");
    assert!(
        lists
            .items
            .iter()
            .all(|i| i.link.as_ref().is_some_and(|l| l.path == "/lists"))
    );
    let up = section(&pol, "upstream");
    assert_eq!(up.items[0].label, "default");
    // The route for corp.example is listed beside it.
    assert!(
        up.items
            .iter()
            .any(|i| i.label == "corp.example" && i.detail.as_deref() == Some("goes to lan"))
    );
}

/// REQ: FLT-010, API-010 (T24.30) — a scheduled group's schedule is in effect at its start and not
/// a second before, and Explain (the pipeline's `ScheduleNow`) agrees at both times.
#[test]
fn flt_006_policy_schedule_flips_at_its_boundary() {
    let (p, sources) = setup_with(POLICY_EXTRA);
    let cfg = policy_cfg();
    let compiled = telltale_config::schedule::compile(&cfg);
    let clients = telltale_policy::ClientTable::from_config(&cfg);
    for (now, on) in [
        (1_795_035_599_u64, false),
        (1_795_035_600, true),
        (1_795_035_601, true),
    ] {
        let pol = policy_of(&p, "10.0.3.5", None, None, now);
        let sched = section(&pol, "schedules");
        assert_eq!(sched.items.len(), 1, "{sched:?}");
        assert_eq!(
            sched.items[0].state.as_deref(),
            Some(if on { "in_effect" } else { "not_in_effect" }),
            "at {now}"
        );
        // Explain, with the schedule state the ticker would hold at the same time.
        p.schedules
            .store(Arc::new(crate::pipeline::ScheduleNow::compute(
                &cfg,
                &compiled,
                clients.groups(),
                i64::try_from(now).unwrap(),
            )));
        let ex = explain_as(&p, &sources, "10.0.3.5", None, None);
        assert_eq!(
            ex.outcome == Outcome::Blocked,
            on,
            "at {now}: {}",
            ex.summary
        );
    }
}

/// REQ: FLT-005, FLT-006, API-010 (T24.30) — device-scoped, group-scoped and everyone rules show
/// for the devices they apply to, with their expiry, and not for the others; an expired one says so.
#[test]
fn flt_006_policy_rules_apply_by_scope_and_expiry() {
    let (p, _sources) = setup_with(POLICY_EXTRA);
    // The tablet (10.0.0.5, group kids): its own rule, its group's, and everyone's.
    let before = policy_of(&p, "10.0.0.5", None, None, 1_795_035_600);
    let rules = section(&before, "rules");
    let by: HashMap<&str, &telltale_api::policy_api::PolicyItem> =
        rules.items.iter().map(|i| (i.label.as_str(), i)).collect();
    let own = by["block game.example"];
    assert_eq!(own.state.as_deref(), Some("in_effect"));
    assert_eq!(own.from.as_deref(), Some("this device"));
    assert_eq!(own.until_unix_seconds, Some(1_795_039_200));
    assert_eq!(own.detail.as_deref(), Some("homework"));
    assert_eq!(
        own.link
            .as_ref()
            .and_then(|l| l.params.get("rule"))
            .map(String::as_str),
        Some("r-tablet")
    );
    assert_eq!(
        by["allow school.example"].from.as_deref(),
        Some("group kids")
    );
    assert_eq!(
        by["block everyone.example"].from.as_deref(),
        Some("everyone")
    );
    // After its expiry the device rule says expired (the sweep hasn't deleted it yet).
    let after = policy_of(&p, "10.0.0.5", None, None, 1_795_039_200);
    let own = section(&after, "rules")
        .items
        .iter()
        .find(|i| i.label == "block game.example")
        .unwrap();
    assert_eq!(own.state.as_deref(), Some("expired"));
    // Another device (default group, not the tablet) sees only the everyone rule.
    let other = policy_of(&p, "203.0.113.9", None, None, 1_795_035_600);
    let labels: Vec<&str> = section(&other, "rules")
        .items
        .iter()
        .map(|i| i.label.as_str())
        .collect();
    assert_eq!(labels, ["block everyone.example"]);
}

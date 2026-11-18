//! REQ: OBS-901 (T26.2, ADR-958) — the classification at every boundary, the merge of two nodes,
//! a missing node, the privacy collapse, and the caps.

use super::*;
use telltale_telemetry::map::{Entry, Recent};

fn th() -> Thresholds {
    Thresholds {
        min_sample: 20,
        warn_latency_ms: 250,
        warn_slow_pct: 10,
        warn_error_pct: 5,
        error_pct: 25,
        warn_blocked_pct: 60,
    }
}

/// 100 answers estimated from 20 real ones, with the given bad shares.
fn agg(slow: u64, error: u64, blocked: u64, limited: u64) -> Agg {
    Agg {
        sampled: 20,
        weighted: 100,
        slow,
        error,
        blocked,
        limited,
    }
}

fn health(c: &Agg, scope: Scope, facts: Facts) -> MapHealth {
    classify(c, &th(), scope, &facts).0
}

fn codes(c: &Agg, scope: Scope, facts: Facts) -> Vec<String> {
    classify(c, &th(), scope, &facts)
        .1
        .into_iter()
        .map(|r| r.code)
        .collect()
}

const OK: Facts = Facts {
    breaker: Breaker::Closed,
    anomaly: false,
    unreachable: false,
};

/// ADR-958 section 4: the error share's two lines, exact at the boundary.
#[test]
fn obs_901_classify_error_boundaries() {
    for scope in [Scope::Device, Scope::Edge, Scope::Upstream] {
        assert_eq!(health(&agg(0, 0, 0, 0), scope, OK), MapHealth::Green);
        assert_eq!(
            health(&agg(0, 4, 0, 0), scope, OK),
            MapHealth::Green,
            "4% is under 5%"
        );
        assert_eq!(
            health(&agg(0, 5, 0, 0), scope, OK),
            MapHealth::Yellow,
            "5% is yellow"
        );
        assert_eq!(health(&agg(0, 24, 0, 0), scope, OK), MapHealth::Yellow);
        assert_eq!(
            health(&agg(0, 25, 0, 0), scope, OK),
            MapHealth::Red,
            "25% is red"
        );
        assert_eq!(health(&agg(0, 100, 0, 0), scope, OK), MapHealth::Red);
    }
}

/// The slow share's line (10%), for every scope.
#[test]
fn obs_901_classify_slow_boundaries() {
    for scope in [Scope::Device, Scope::Edge, Scope::Upstream, Scope::Answer] {
        assert_eq!(
            health(&agg(9, 0, 0, 0), scope, OK),
            MapHealth::Green,
            "{scope:?}"
        );
        assert_eq!(
            health(&agg(10, 0, 0, 0), scope, OK),
            MapHealth::Yellow,
            "{scope:?}"
        );
    }
    // Slow is never red, however high.
    assert_eq!(
        health(&agg(100, 0, 0, 0), Scope::Device, OK),
        MapHealth::Yellow
    );
}

/// `min_sample` counts real events: 19 are idle whatever they say, 20 are coloured.
#[test]
fn obs_901_classify_idle() {
    let mut c = agg(0, 100, 0, 0);
    c.sampled = 19;
    assert_eq!(health(&c, Scope::Device, OK), MapHealth::Idle);
    assert_eq!(codes(&c, Scope::Device, OK), ["few_samples"]);
    c.sampled = 20;
    assert_eq!(health(&c, Scope::Device, OK), MapHealth::Red);
    assert_eq!(
        health(&Agg::default(), Scope::Edge, OK),
        MapHealth::Idle,
        "nothing at all is idle, not green"
    );
}

/// ADR-958 test plan: with N >= 20 one sampled SERVFAIL weighs N in the estimate but is one real
/// event, so it is idle, not red.
#[test]
fn obs_901_classify_single_failure() {
    for n in [20u64, 50, 400] {
        let c = Agg {
            sampled: 1,
            weighted: n,
            error: n,
            ..Agg::default()
        };
        assert_eq!(health(&c, Scope::Device, OK), MapHealth::Idle, "N = {n}");
    }
    // With enough real events behind it the same share is red.
    let c = Agg {
        sampled: 20,
        weighted: 400,
        error: 400,
        ..Agg::default()
    };
    assert_eq!(health(&c, Scope::Device, OK), MapHealth::Red);
}

/// Breakers are facts: open is red and half-open yellow, even with too few answers to colour.
#[test]
fn obs_901_classify_breaker_and_half_open() {
    let open = Facts {
        breaker: Breaker::Open,
        ..OK
    };
    let half = Facts {
        breaker: Breaker::HalfOpen,
        ..OK
    };
    let quiet = Agg::default();
    assert_eq!(health(&quiet, Scope::Upstream, open), MapHealth::Red);
    assert_eq!(codes(&quiet, Scope::Upstream, open), ["breaker_open"]);
    assert_eq!(health(&quiet, Scope::Upstream, half), MapHealth::Yellow);
    assert_eq!(
        health(&agg(0, 0, 0, 0), Scope::Upstream, half),
        MapHealth::Yellow
    );
    assert_eq!(
        codes(&agg(0, 0, 0, 0), Scope::Upstream, half),
        ["breaker_half_open"]
    );
    // A device's breaker means nothing.
    assert_eq!(
        health(&agg(0, 0, 0, 0), Scope::Device, open),
        MapHealth::Green
    );
    // Red from errors still names its reason first.
    assert_eq!(
        health(&agg(0, 30, 0, 0), Scope::Upstream, half),
        MapHealth::Red
    );
}

/// Rate limits and blocked shares are a device's; an edge and an answer kind ignore them.
#[test]
fn obs_901_classify_rate_limited_and_blocked() {
    assert_eq!(
        health(&agg(0, 0, 0, 1), Scope::Device, OK),
        MapHealth::Yellow
    );
    assert_eq!(codes(&agg(0, 0, 0, 1), Scope::Device, OK), ["rate_limited"]);
    assert_eq!(health(&agg(0, 0, 0, 1), Scope::Edge, OK), MapHealth::Green);
    assert_eq!(
        health(&agg(0, 0, 59, 0), Scope::Device, OK),
        MapHealth::Green
    );
    assert_eq!(
        health(&agg(0, 0, 60, 0), Scope::Device, OK),
        MapHealth::Yellow
    );
    assert_eq!(
        codes(&agg(0, 0, 60, 0), Scope::Device, OK),
        ["high_blocked"]
    );
    // Blocking is the intended outcome: an answer kind is never red or yellow for it.
    assert_eq!(
        health(&agg(0, 0, 100, 0), Scope::Answer, OK),
        MapHealth::Green
    );
    assert_eq!(
        health(&agg(0, 0, 100, 0), Scope::Edge, OK),
        MapHealth::Green
    );
    // Errors don't colour an answer kind (a cache hit can't fail).
    assert_eq!(
        health(&agg(0, 100, 0, 0), Scope::Answer, OK),
        MapHealth::Green
    );
}

/// The anomaly's yellow is the device's, and only where the caller passes it (level 0).
#[test]
fn obs_901_classify_anomaly() {
    let a = Facts {
        anomaly: true,
        ..OK
    };
    assert_eq!(
        health(&agg(0, 0, 0, 0), Scope::Device, a),
        MapHealth::Yellow
    );
    assert_eq!(codes(&agg(0, 0, 0, 0), Scope::Device, a), ["anomaly"]);
    assert_eq!(health(&agg(0, 0, 0, 0), Scope::Edge, a), MapHealth::Green);
}

/// An unreachable node is red whatever was sampled.
#[test]
fn obs_901_classify_unreachable() {
    let f = Facts {
        unreachable: true,
        ..OK
    };
    assert_eq!(health(&Agg::default(), Scope::Edge, f), MapHealth::Red);
    assert_eq!(codes(&Agg::default(), Scope::Edge, f), ["unreachable"]);
}

/// A parent takes the worst of its children and says how many are red and yellow; idle children
/// don't colour it, and all idle is idle.
#[test]
fn obs_901_classify_rollup() {
    use MapHealth::{Green, Idle, Red, Yellow};
    assert_eq!(rollup(&[]).0, Idle);
    assert_eq!(rollup(&[Idle, Idle]).0, Idle);
    assert_eq!(rollup(&[Idle, Green]).0, Green);
    assert_eq!(rollup(&[Green, Yellow, Idle]).0, Yellow);
    let (h, why) = rollup(&[Green, Yellow, Red, Red, Yellow, Yellow]);
    assert_eq!(h, Red);
    assert_eq!(why.map(|r| r.summary), Some("2 red, 3 yellow".to_owned()));
    assert!(rollup(&[Green, Green]).1.is_none());
}

// ---------------------------------------------------------------------------------------------
// The builder

fn client(last: u8) -> ClientKey {
    let mut ip = [0u8; 16];
    ip[10] = 0xff;
    ip[11] = 0xff;
    ip[12..].copy_from_slice(&[192, 168, 1, last]);
    ClientKey(ip)
}

fn counts(sampled: u32, weighted: u32, slow: u32, error: u32, blocked: u32) -> Counts {
    Counts {
        sampled,
        weighted,
        slow,
        error,
        blocked,
        limited: 0,
    }
}

fn entry(c: ClientKey, kind: AnswerKind, upstream: u16, n: Counts) -> Entry {
    Entry {
        client: c,
        group: 0,
        upstream,
        kind,
        c: n,
    }
}

fn part(node: &str, entries: Vec<Entry>) -> MapPart {
    MapPart {
        node: node.to_owned(),
        window: Window {
            window_secs: 60,
            sample_rate: 1,
            dropped: 0,
            privacy: 0,
            entries,
            other: Counts::default(),
            recent: Vec::new(),
        },
        upstreams: vec![
            PartUpstream {
                id: 1,
                name: "quad9".into(),
                breaker: "closed".into(),
                ip: None,
            },
            PartUpstream {
                id: 2,
                name: "cloudflare".into(),
                breaker: "closed".into(),
                ip: None,
            },
        ],
        level: "healthy".into(),
        reasons: Vec::new(),
        groups: vec!["default".into(), "kids".into()],
        anomalous: Vec::new(),
        answers_recorded: false,
        answers: Vec::new(),
    }
}

fn ctx(names: &dyn Fn(IpAddr) -> Option<String>) -> Context<'_> {
    Context {
        thresholds: th(),
        gateway: Gateway::Ok,
        networks: vec![
            Net {
                name: "LAN".into(),
                cidr: Cidr::parse("192.168.1.0/24").unwrap(),
            },
            Net {
                name: "IoT".into(),
                cidr: Cidr::parse("192.168.20.0/24").unwrap(),
            },
        ],
        device_name: names,
        now_unix_seconds: 1_791_072_000,
    }
}

fn no_names(_: IpAddr) -> Option<String> {
    None
}

fn find<'a>(s: &'a MapSnapshot, id: &str) -> &'a MapNode {
    s.nodes.iter().find(|n| n.id == id).unwrap_or_else(|| {
        panic!(
            "no node {id} in {:?}",
            s.nodes.iter().map(|n| &n.id).collect::<Vec<_>>()
        )
    })
}

fn edge<'a>(s: &'a MapSnapshot, from: &str, to: &str) -> &'a MapEdge {
    s.edges
        .iter()
        .find(|e| e.from == from && e.to == to)
        .unwrap_or_else(|| panic!("no edge {from} -> {to}"))
}

/// One node: gateway, networks, a device, the resolver, its answer kinds and upstreams, with the
/// edges between them and the numbers on them.
#[test]
fn obs_901_snapshot_shape() {
    let parts = MapParts {
        parts: vec![part(
            "pi1",
            vec![
                entry(client(7), AnswerKind::Cache, 0, counts(30, 300, 0, 0, 0)),
                entry(
                    client(7),
                    AnswerKind::Upstream,
                    1,
                    counts(20, 120, 20, 0, 0),
                ),
                entry(client(7), AnswerKind::Blocked, 0, counts(10, 60, 0, 0, 60)),
            ],
        )],
        missing: vec![],
        unseen: Vec::new(),
        pending: Vec::new(),
    };
    let names = |ip: IpAddr| (ip.to_string() == "192.168.1.7").then(|| "kitchen-tv".to_owned());
    let s = build(&parts, &ctx(&names), &Filter::default());
    assert_eq!(s.window_secs, 60);
    assert!(!s.partial && !s.truncated);
    let d = find(&s, "dev:192.168.1.7");
    assert_eq!(d.label, "kitchen-tv");
    assert_eq!(d.network.as_deref(), Some("LAN"));
    assert_eq!(d.count, 480);
    assert!((d.qps - 8.0).abs() < 1e-9, "480 over 60 s");
    let up = find(&s, "up:quad9");
    assert_eq!(up.count, 120);
    assert_eq!(
        find(&s, "up:cloudflare").health,
        MapHealth::Idle,
        "an upstream nobody used"
    );
    assert_eq!(find(&s, "gateway").health, MapHealth::Green);
    assert_eq!(find(&s, "res:pi1").kind, MapNodeKind::Resolver);
    assert_eq!(find(&s, "ans:pi1:cache").count, 300);
    let e = edge(&s, "dev:192.168.1.7", "res:pi1");
    assert_eq!((e.count, e.structural), (480, false));
    assert_eq!(edge(&s, "res:pi1", "up:quad9").count, 120);
    assert!(edge(&s, "net:LAN", "dev:192.168.1.7").structural);
    assert!(edge(&s, "gateway", "net:LAN").structural);
    // 20 slow of 120 on the quad9 edge is 16.7%: yellow.
    assert_eq!(edge(&s, "res:pi1", "up:quad9").health, MapHealth::Yellow);
    assert_eq!(edge(&s, "res:pi1", "up:quad9").slow_pct, 16.7);
    // 20 slow of 480 is 4% and 60 blocked is 12.5%: both under their lines, so the device is green.
    assert_eq!(d.health, MapHealth::Green, "{:?}", d.reasons);
}

/// ADR-958 test plan: the same device and edge on two nodes add up, the device is listed once,
/// each node is its own resolver, and an upstream both use is one node.
#[test]
fn obs_901_merge_two_nodes() {
    let a = part(
        "pi1",
        vec![entry(
            client(7),
            AnswerKind::Upstream,
            1,
            counts(20, 100, 0, 0, 0),
        )],
    );
    let b = part(
        "pi2",
        vec![
            entry(client(7), AnswerKind::Upstream, 1, counts(20, 200, 0, 0, 0)),
            entry(client(8), AnswerKind::Cache, 0, counts(25, 25, 0, 0, 0)),
        ],
    );
    let parts = MapParts {
        parts: vec![a, b],
        missing: vec![],
        unseen: Vec::new(),
        pending: Vec::new(),
    };
    let s = build(&parts, &ctx(&no_names), &Filter::default());
    let dev = find(&s, "dev:192.168.1.7");
    assert_eq!(
        dev.count, 300,
        "the device asked both nodes: one device, summed"
    );
    assert_eq!(dev.sampled, 40);
    assert_eq!(
        s.nodes.iter().filter(|n| n.id == "dev:192.168.1.7").count(),
        1
    );
    assert_eq!(edge(&s, "dev:192.168.1.7", "res:pi1").count, 100);
    assert_eq!(edge(&s, "dev:192.168.1.7", "res:pi2").count, 200);
    assert_eq!(
        find(&s, "up:quad9").count,
        300,
        "one upstream node, both nodes' flows"
    );
    assert_eq!(find(&s, "res:pi1").count, 100);
    assert_eq!(find(&s, "res:pi2").count, 225);
    assert_eq!(
        s.nodes
            .iter()
            .filter(|n| n.kind == MapNodeKind::Resolver)
            .count(),
        2
    );
    // The helper sums the same way.
    let totals = merged_totals(&parts);
    assert_eq!(
        totals[&(client(7), AnswerKind::Upstream, "quad9".to_owned())].weighted,
        300
    );
}

/// ADR-958 test plan: a node that did not answer is a red resolver with its reason, the
/// snapshot is `partial`, and `missingNodes` names it.
#[test]
fn obs_901_missing_node_is_red() {
    let parts = MapParts {
        parts: vec![part(
            "pi1",
            vec![entry(
                client(7),
                AnswerKind::Cache,
                0,
                counts(30, 30, 0, 0, 0),
            )],
        )],
        missing: vec!["pi2".into()],
        unseen: vec![],
        pending: Vec::new(),
    };
    let s = build(&parts, &ctx(&no_names), &Filter::default());
    assert!(s.partial);
    assert_eq!(s.missing_nodes, ["pi2"]);
    let r = find(&s, "res:pi2");
    assert_eq!(r.health, MapHealth::Red);
    assert_eq!(r.reasons[0].code, "unreachable");
    assert_eq!(s.health, MapHealth::Red, "the map's own colour follows");
    assert_ne!(find(&s, "res:pi1").health, MapHealth::Red);
    // A filter on the node leaves out the other node's gap.
    let f = Filter {
        node: Some("pi1".into()),
        ..Filter::default()
    };
    let s = build(&parts, &ctx(&no_names), &f);
    assert!(s.nodes.iter().all(|n| n.id != "res:pi2"));
}

/// A resolver takes its own ADR-104 level and the worst of what is downstream of it.
#[test]
fn obs_901_resolver_takes_its_level_and_its_children() {
    let mut p = part(
        "pi1",
        vec![entry(
            client(7),
            AnswerKind::Upstream,
            1,
            counts(20, 100, 0, 40, 0),
        )],
    );
    let s = build(
        &MapParts {
            parts: vec![p.clone()],
            missing: vec![],
            unseen: Vec::new(),
            pending: Vec::new(),
        },
        &ctx(&no_names),
        &Filter::default(),
    );
    assert_eq!(find(&s, "up:quad9").health, MapHealth::Red, "40% failing");
    let r = find(&s, "res:pi1");
    assert_eq!(r.health, MapHealth::Red, "an upstream below it is red");
    assert_eq!(r.reasons.last().map(|x| x.code.as_str()), Some("children"));
    // Its own level: degraded is yellow, severe red.
    p.window.entries.clear();
    p.level = "degraded".into();
    p.reasons = vec![("sync_lag".into(), "behind by 3 versions".into())];
    let one = |p: &MapPart| MapParts {
        parts: vec![p.clone()],
        missing: vec![],
        unseen: Vec::new(),
        pending: Vec::new(),
    };
    let s = build(&one(&p), &ctx(&no_names), &Filter::default());
    assert_eq!(find(&s, "res:pi1").health, MapHealth::Yellow);
    assert!(find(&s, "res:pi1").reasons[0].summary.contains("sync_lag"));
    p.level = "severe".into();
    let s = build(&one(&p), &ctx(&no_names), &Filter::default());
    assert_eq!(find(&s, "res:pi1").health, MapHealth::Red);
    // Healthy and unasked: green, not grey (it is serving).
    p.level = "healthy".into();
    p.reasons.clear();
    let s = build(&one(&p), &ctx(&no_names), &Filter::default());
    assert_eq!(find(&s, "res:pi1").health, MapHealth::Green);
}

/// An open breaker colours the upstream red and the resolver with it, with no traffic at all.
#[test]
fn obs_901_open_breaker_without_traffic() {
    let mut p = part("pi1", vec![]);
    p.upstreams[0].breaker = "open".into();
    p.upstreams[1].breaker = "half_open".into();
    let s = build(
        &MapParts {
            parts: vec![p],
            missing: vec![],
            unseen: Vec::new(),
            pending: Vec::new(),
        },
        &ctx(&no_names),
        &Filter::default(),
    );
    assert_eq!(find(&s, "up:quad9").health, MapHealth::Red);
    assert_eq!(find(&s, "up:cloudflare").health, MapHealth::Yellow);
    assert_eq!(edge(&s, "res:pi1", "up:quad9").health, MapHealth::Red);
    assert_eq!(find(&s, "res:pi1").health, MapHealth::Red);
}

/// The gateway is grey with no router integration, green when it is healthy, yellow on an error,
/// and never red.
#[test]
fn obs_901_gateway_states() {
    let parts = MapParts::default();
    let mk = |g: Gateway| {
        let mut c = ctx(&no_names);
        c.gateway = g;
        build(&parts, &c, &Filter::default())
    };
    assert_eq!(find(&mk(Gateway::None), "gateway").health, MapHealth::Idle);
    assert_eq!(
        find(&mk(Gateway::None), "gateway").reasons[0].code,
        "not_configured"
    );
    assert_eq!(find(&mk(Gateway::Ok), "gateway").health, MapHealth::Green);
    let e = mk(Gateway::Error("timeout".into()));
    assert_eq!(find(&e, "gateway").health, MapHealth::Yellow);
    assert!(find(&e, "gateway").reasons[0].summary.contains("timeout"));
}

/// A network takes the worst of its devices, grey when none has enough answers, and folds the
/// devices past the cap into `+N more` (which counts toward the network's colour).
#[test]
fn obs_901_network_rollup_and_fold() {
    let mut entries = Vec::new();
    // 210 devices in the LAN; the busiest has the failures.
    for i in 1..=210u32 {
        let mut c = client(0);
        c.0[14] = u8::try_from(i >> 8).unwrap_or(0);
        c.0[15] = u8::try_from(i & 0xff).unwrap_or(0);
        let n = if i == 210 { 1000 } else { 100 };
        let err = if i == 1 { 100 } else { 0 };
        entries.push(entry(
            c,
            AnswerKind::Upstream,
            1,
            counts(30, 100 + n, 0, err, 0),
        ));
    }
    let s = build(
        &MapParts {
            parts: vec![part("pi1", entries)],
            missing: vec![],
            unseen: Vec::new(),
            pending: Vec::new(),
        },
        &ctx(&no_names),
        &Filter::default(),
    );
    assert!(s.truncated);
    assert_eq!(
        s.nodes
            .iter()
            .filter(|n| n.kind == MapNodeKind::Device)
            .count(),
        crate::map::MAX_DEVICES
    );
    let more: Vec<&MapNode> = s
        .nodes
        .iter()
        .filter(|n| n.kind == MapNodeKind::More)
        .collect();
    assert_eq!(more.iter().map(|m| m.folded.unwrap_or(0)).sum::<u32>(), 10);
    // Device 1 (100 failing of 200) is among the quietest, so it is folded; the networks still
    // see it: the rollup covers every device, drawn or not.
    let nets: Vec<&MapNode> = s
        .nodes
        .iter()
        .filter(|n| n.kind == MapNodeKind::Network)
        .collect();
    assert!(
        nets.iter().any(|n| n.health == MapHealth::Red),
        "a folded failing device still colours its network: {:?}",
        nets.iter().map(|n| (&n.id, n.health)).collect::<Vec<_>>()
    );
}

/// A network with no device that has enough answers is grey, not green.
#[test]
fn obs_901_quiet_network_is_idle() {
    let s = build(
        &MapParts {
            parts: vec![part(
                "pi1",
                vec![entry(
                    client(7),
                    AnswerKind::Cache,
                    0,
                    counts(3, 3, 0, 0, 0),
                )],
            )],
            missing: vec![],
            unseen: Vec::new(),
            pending: Vec::new(),
        },
        &ctx(&no_names),
        &Filter::default(),
    );
    assert_eq!(find(&s, "net:LAN").health, MapHealth::Idle);
    assert_eq!(find(&s, "net:IoT").health, MapHealth::Idle);
    assert_eq!(find(&s, "dev:192.168.1.7").health, MapHealth::Idle);
}

/// ADR-958 section 7: the anomaly's yellow is only for privacy level 0; the privacy levels hide
/// devices at 2 and keep only totals at 3; no node carries an address then.
#[test]
#[allow(clippy::too_many_lines)]
fn obs_901_privacy_levels() {
    let base = |privacy: u8, entries: Vec<Entry>| {
        let mut p = part("pi1", entries);
        p.window.privacy = privacy;
        p.anomalous = vec!["192.168.1.7".into()];
        build(
            &MapParts {
                parts: vec![p],
                missing: vec![],
                unseen: Vec::new(),
                pending: Vec::new(),
            },
            &ctx(&no_names),
            &Filter::default(),
        )
    };
    let seen = vec![entry(
        client(7),
        AnswerKind::Cache,
        0,
        counts(30, 30, 0, 0, 0),
    )];
    // Level 0: yellow for the open finding. Level 1: devices shown, no anomaly colour.
    let s = base(0, seen.clone());
    assert_eq!(find(&s, "dev:192.168.1.7").health, MapHealth::Yellow);
    assert_eq!(find(&s, "dev:192.168.1.7").reasons[0].code, "anomaly");
    let s = base(1, seen);
    assert_eq!(find(&s, "dev:192.168.1.7").health, MapHealth::Green);
    assert_eq!(s.privacy, 1);
    // Level 2: the sampler kept no client; one hidden device, no address anywhere.
    let hidden = vec![
        entry(
            ClientKey::HIDDEN,
            AnswerKind::Cache,
            0,
            counts(30, 300, 0, 0, 0),
        ),
        entry(
            ClientKey::HIDDEN,
            AnswerKind::Upstream,
            1,
            counts(30, 300, 0, 0, 0),
        ),
    ];
    let s = base(2, hidden);
    let devs: Vec<&MapNode> = s
        .nodes
        .iter()
        .filter(|n| n.kind == MapNodeKind::Device)
        .collect();
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0].id, "dev:hidden");
    assert_eq!(devs[0].label, "devices hidden by privacy");
    assert!(devs.iter().all(|d| d.address.is_none()));
    assert_eq!(devs[0].count, 600);
    assert!(
        s.nodes
            .iter()
            .all(|n| n.address.is_none() && !n.id.starts_with("dev:192")),
        "no address in the map at level 2"
    );
    assert_eq!(s.privacy, 2);
    assert_eq!(
        devs[0]
            .reasons
            .iter()
            .filter(|r| r.code == "anomaly")
            .count(),
        0
    );
    // Level 3: totals only: the resolver is there with its count, nothing finer.
    let totals = vec![entry(
        ClientKey::HIDDEN,
        AnswerKind::Other,
        0,
        counts(30, 300, 0, 0, 0),
    )];
    let s = base(3, totals);
    assert_eq!(find(&s, "res:pi1").count, 300);
    assert_eq!(s.privacy, 3);
    assert_eq!(find(&s, "ans:pi1:cache").count, 0);
    // A hidden device can't be found by name.
    let mut p = part(
        "pi1",
        vec![entry(
            ClientKey::HIDDEN,
            AnswerKind::Cache,
            0,
            counts(30, 30, 0, 0, 0),
        )],
    );
    p.window.privacy = 2;
    let f = Filter {
        device: Some("kitchen".into()),
        ..Filter::default()
    };
    let s = build(
        &MapParts {
            parts: vec![p],
            missing: vec![],
            unseen: Vec::new(),
            pending: Vec::new(),
        },
        &ctx(&no_names),
        &f,
    );
    assert!(s.nodes.iter().all(|n| n.kind != MapNodeKind::Device));
}

/// The server's filters narrow the read: by network, group, device and node.
#[test]
fn obs_901_filters_narrow_the_map() {
    let mut other = client(7);
    other.0[14] = 20; // 192.168.20.7
    let mut kid = entry(client(9), AnswerKind::Cache, 0, counts(30, 30, 0, 0, 0));
    kid.group = 1;
    let parts = MapParts {
        parts: vec![
            part(
                "pi1",
                vec![
                    entry(client(7), AnswerKind::Cache, 0, counts(30, 30, 0, 0, 0)),
                    entry(other, AnswerKind::Cache, 0, counts(30, 30, 0, 0, 0)),
                    kid,
                ],
            ),
            part(
                "pi2",
                vec![entry(
                    client(7),
                    AnswerKind::Cache,
                    0,
                    counts(30, 70, 0, 0, 0),
                )],
            ),
        ],
        missing: vec![],
        unseen: Vec::new(),
        pending: Vec::new(),
    };
    let names = |ip: IpAddr| (ip.to_string() == "192.168.1.7").then(|| "Kitchen TV".to_owned());
    let devices = |f: Filter| -> Vec<String> {
        let s = build(&parts, &ctx(&names), &f);
        s.nodes
            .iter()
            .filter(|n| n.kind == MapNodeKind::Device)
            .map(|n| n.id.clone())
            .collect()
    };
    assert_eq!(devices(Filter::default()).len(), 3);
    assert_eq!(
        devices(Filter {
            network: Some("iot".into()),
            ..Filter::default()
        }),
        ["dev:192.168.20.7"]
    );
    assert_eq!(
        devices(Filter {
            group: Some("KIDS".into()),
            ..Filter::default()
        }),
        ["dev:192.168.1.9"]
    );
    assert_eq!(
        devices(Filter {
            device: Some("kitchen".into()),
            ..Filter::default()
        }),
        ["dev:192.168.1.7"]
    );
    assert_eq!(
        devices(Filter {
            device: Some("20.7".into()),
            ..Filter::default()
        }),
        ["dev:192.168.20.7"]
    );
    // Node: only that node's flows, and only its resolver.
    let f = Filter {
        node: Some("pi2".into()),
        ..Filter::default()
    };
    let s = build(&parts, &ctx(&names), &f);
    assert_eq!(devices(f.clone()), ["dev:192.168.1.7"]);
    assert_eq!(find(&s, "dev:192.168.1.7").count, 70);
    assert!(s.nodes.iter().all(|n| n.id != "res:pi1"));
    // A network filter leaves one network; a device filter only the networks it is in.
    let s = build(
        &parts,
        &ctx(&names),
        &Filter {
            network: Some("IoT".into()),
            ..Filter::default()
        },
    );
    let nets: Vec<&str> = s
        .nodes
        .iter()
        .filter(|n| n.kind == MapNodeKind::Network)
        .map(|n| n.label.as_str())
        .collect();
    assert_eq!(nets, ["IoT"]);
}

/// A busy device carries its last few lookups, no names; the same input gives the same snapshot.
#[test]
fn obs_901_recent_lookups_and_determinism() {
    let mut p = part(
        "pi1",
        vec![entry(
            client(7),
            AnswerKind::Cache,
            0,
            counts(30, 30, 0, 0, 0),
        )],
    );
    for i in 0..25u64 {
        p.window.recent.push(Recent {
            ts_us: 1_791_071_000_000_000 + i,
            client: client(7),
            upstream: 0,
            kind: AnswerKind::Cache,
            ms: 3,
            status: telltale_telemetry::Status::Cached as u8,
        });
    }
    let parts = MapParts {
        parts: vec![p],
        missing: vec![],
        unseen: Vec::new(),
        pending: Vec::new(),
    };
    let s = build(&parts, &ctx(&no_names), &Filter::default());
    let e = edge(&s, "dev:192.168.1.7", "res:pi1");
    assert_eq!(e.recent.len(), RECENT_PER_EDGE);
    assert_eq!(e.recent[0].status, "cached");
    assert_eq!(
        e.recent.last().map(|r| r.ts_unix_micros),
        Some(1_791_071_000_000_024)
    );
    assert_eq!(s, build(&parts, &ctx(&no_names), &Filter::default()));
    let text = serde_json::to_string(&s).unwrap();
    assert!(!text.contains("example"), "no domain name in the map");
}

/// The short version for agents: counts, the problems worst first, the busiest flows.
#[test]
fn obs_901_network_health_summary() {
    let parts = MapParts {
        parts: vec![part(
            "pi1",
            vec![
                entry(
                    client(7),
                    AnswerKind::Upstream,
                    1,
                    counts(30, 300, 0, 120, 0),
                ),
                entry(client(8), AnswerKind::Cache, 0, counts(30, 900, 0, 0, 0)),
            ],
        )],
        missing: vec!["pi2".into()],
        unseen: vec![],
        pending: Vec::new(),
    };
    let s = build(&parts, &ctx(&no_names), &Filter::default());
    let h = network_health(&s);
    assert_eq!(h.health, MapHealth::Red);
    assert!(h.partial && h.missing_nodes == ["pi2"]);
    assert!(h.problems.iter().all(|p| p.health != MapHealth::Green));
    assert_eq!(h.problems[0].health, MapHealth::Red, "red first");
    assert!(h.problems.iter().any(|p| p.id == "res:pi2"));
    assert_eq!(h.busiest.len(), 5);
    assert!(h.busiest.windows(2).all(|w| w[0].qps >= w[1].qps));
    assert_eq!(
        h.counts.green + h.counts.yellow + h.counts.red + h.counts.idle,
        u32::try_from(s.nodes.len()).unwrap()
    );
}

// ---------------------------------------------------------------------------------------------
// The world view (OBS-902, T26.5)

/// A GeoIP lookup from a table of /24 and /48 prefixes: `prefix -> country`; the markers' addresses
/// are looked up by their own address.
fn geo(table: &'static [(&'static str, &'static str)]) -> impl Fn(&[IpAddr]) -> GeoAnswer {
    move |ips: &[IpAddr]| GeoAnswer {
        state: GeoState::Ready,
        home: Some("NL".into()),
        countries: ips
            .iter()
            .map(|ip| {
                table
                    .iter()
                    .find(|(p, _)| {
                        p.parse::<IpAddr>()
                            .is_ok_and(|p| prefix_of(p) == prefix_of(*ip))
                    })
                    .map(|(_, cc)| (*cc).to_owned())
            })
            .collect(),
    }
}

const TABLE: &[(&str, &str)] = &[
    ("93.184.216.0", "us"),
    ("151.101.1.0", "US"),
    ("2606:4700::", "US"),
    ("185.60.216.0", "IE"),
    ("1.1.1.0", "AU"),
];

fn answer(addr: &str, weighted: u64, sampled: u64, slow: u64) -> AnswerPrefix {
    AnswerPrefix {
        addr: addr.parse().unwrap(),
        weighted,
        sampled,
        slow,
    }
}

fn world_parts(answers: Vec<Vec<AnswerPrefix>>) -> MapParts {
    MapParts {
        parts: answers
            .into_iter()
            .enumerate()
            .map(|(i, a)| {
                let mut p = part(
                    &format!("pi{i}"),
                    vec![entry(
                        client(7),
                        AnswerKind::Upstream,
                        1,
                        counts(30, 300, 0, 0, 0),
                    )],
                );
                p.answers_recorded = true;
                p.answers = a;
                p
            })
            .collect(),
        missing: vec![],
        unseen: Vec::new(),
        pending: Vec::new(),
    }
}

/// REQ: OBS-902 (T26.5, ADR-958 section 6) - the same prefix on two nodes adds, a /24 and an address
/// in it are one prefix, countries add up across prefixes, and the answering node's lookup places
/// them (uppercased). What no country knows is unlocated.
#[test]
fn obs_902_world_merges_prefixes_across_nodes() {
    let parts = world_parts(vec![
        vec![
            answer("93.184.216.34", 100, 10, 10),
            answer("151.101.1.69", 60, 6, 0),
            answer("10.9.9.9", 5, 1, 0),
        ],
        vec![
            answer("93.184.216.99", 40, 4, 0),
            answer("2606:4700::1111", 30, 3, 3),
            answer("185.60.216.35", 20, 2, 0),
        ],
    ]);
    let w = world(&parts, &th(), 1_791_072_000, None, &geo(TABLE));
    assert!(w.available, "{w:?}");
    assert_eq!(w.reason, None);
    assert_eq!(w.home_country.as_deref(), Some("NL"));
    let by: BTreeMap<&str, &WorldRegion> = w.regions.iter().map(|r| (r.cc.as_str(), r)).collect();
    // 93.184.216.0/24 (100 + 40), 151.101.1.0/24 (60) and 2606:4700::/48 (30) are all the US.
    assert_eq!(by["US"].count, 230);
    assert_eq!(by["IE"].count, 20);
    assert!(!by.contains_key("AU"), "no answer pointed there");
    // 600 lookups sampled over the two nodes (300 each); 250 placed, 5 + 345 not.
    assert_eq!(w.unlocated.count, 600 - 250);
    // Ranked busiest first; the rate is per second over the 60 s window.
    assert_eq!(w.regions[0].cc, "US");
    assert!((by["US"].qps - 3.83).abs() < 0.01, "{}", by["US"].qps);
    // 13 of the 230 US answers were slow: 5.7%, under the 10% line, so green.
    assert!(
        (by["US"].slow_pct - 5.7).abs() < 0.05,
        "{}",
        by["US"].slow_pct
    );
    assert_eq!(by["US"].health, MapHealth::Green);
    // The same prefixes on one node alone give the half of the sums.
    let one = world(
        &world_parts(vec![vec![answer("93.184.216.34", 100, 20, 10)]]),
        &th(),
        0,
        None,
        &geo(TABLE),
    );
    assert_eq!(one.regions[0].count, 100);
    // 10 of 100 slow is the line: yellow.
    assert_eq!(one.regions[0].health, MapHealth::Yellow);
    // Few real answers: idle, not green.
    let thin = world(
        &world_parts(vec![vec![answer("1.1.1.9", 500, 2, 0)]]),
        &th(),
        0,
        None,
        &geo(TABLE),
    );
    assert_eq!(thin.regions[0].health, MapHealth::Idle);
    // The cap: more than 256 prefixes keep the busiest.
    let many: Vec<AnswerPrefix> = (0u32..300)
        .map(|i| {
            answer(
                &format!("{}.{}.7.1", 20 + i / 256, i % 256),
                1000 - u64::from(i),
                20,
                0,
            )
        })
        .collect();
    let seen = std::sync::Mutex::new(0usize);
    let capped = world(
        &world_parts(vec![many]),
        &th(),
        0,
        None,
        &|ips: &[IpAddr]| {
            *seen.lock().unwrap() = ips.len();
            GeoAnswer {
                state: GeoState::Ready,
                home: None,
                countries: ips.iter().map(|_| Some("DE".to_owned())).collect(),
            }
        },
    );
    assert_eq!(
        *seen.lock().unwrap(),
        MAX_PREFIXES,
        "256 prefixes and no upstream address"
    );
    assert_eq!(capped.regions[0].cc, "DE");
    assert_eq!(capped.regions[0].count, (1000 - 255..=1000).sum::<u64>());
}

/// REQ: OBS-902 (T26.5, ADR-958 section 7) - at privacy level 3 nothing per event is kept, so every
/// answer is unlocated (`privacy`) and the addresses are not even looked up; levels 0 to 2 place
/// answers (an address says nothing about a device).
#[test]
fn obs_902_world_excludes_private_levels() {
    for level in 0u8..=3 {
        let mut parts = world_parts(vec![vec![answer("93.184.216.34", 100, 10, 0)]]);
        parts.parts[0].window.privacy = level;
        let asked = std::sync::Mutex::new(Vec::new());
        let locate = |ips: &[IpAddr]| {
            asked.lock().unwrap().extend_from_slice(ips);
            geo(TABLE)(ips)
        };
        let w = world(&parts, &th(), 0, None, &locate);
        if level >= 3 {
            assert!(!w.available, "level {level}");
            assert_eq!(w.reason.as_deref(), Some("privacy"));
            assert_eq!(w.regions.len(), 0);
            assert_eq!(w.unlocated.count, 300);
            assert_eq!(w.unlocated.reason.as_deref(), Some("privacy"));
            assert!(
                !asked
                    .lock()
                    .unwrap()
                    .contains(&"93.184.216.34".parse().unwrap()),
                "no answer address is looked up at level {level}"
            );
        } else {
            assert!(w.available, "level {level}: {w:?}");
            assert_eq!(w.regions[0].cc, "US");
        }
    }
}

/// REQ: OBS-902 (T26.5) - without a database the view says why: off, or missing; and it asks the
/// database nothing it cannot answer. While the answer address isn't recorded (ADR-970) it says
/// `address_not_recorded` and still has the upstream markers.
#[test]
fn obs_902_world_states_and_markers() {
    let mut parts = world_parts(vec![vec![]]);
    parts.parts[0].answers_recorded = false;
    parts.parts[0].upstreams[0].ip = Some("93.184.216.34".parse().unwrap());
    parts.parts[0].upstreams[1].ip = Some("10.0.0.53".parse().unwrap());
    // Off and missing: the state decides, nothing is placed, nothing is drawn.
    for (state, reason) in [
        (GeoState::Off, "geoip_off"),
        (GeoState::Missing, "geoip_missing"),
    ] {
        let st = state.clone();
        let w = world(&parts, &th(), 0, None, &move |_| GeoAnswer {
            state: st.clone(),
            ..GeoAnswer::default()
        });
        assert!(!w.available);
        assert_eq!(w.reason.as_deref(), Some(reason));
        assert!(w.markers.is_empty() && w.regions.is_empty());
        assert_eq!(w.unlocated.count, 300);
    }
    // Ready but the address is not recorded: markers only, unavailable for answers.
    let w = world(&parts, &th(), 0, None, &geo(TABLE));
    assert!(!w.available);
    assert_eq!(w.reason.as_deref(), Some("address_not_recorded"));
    assert_eq!(w.markers.len(), 1, "{:?}", w.markers);
    assert_eq!(w.markers[0].name, "quad9");
    assert_eq!(w.markers[0].cc.as_deref(), Some("US"));
    assert_eq!(
        w.unplaced_upstreams, 1,
        "the private address has no country"
    );
    assert_eq!(w.regions.len(), 0);
    assert_eq!(w.unlocated.count, 300);
    assert_eq!(w.unlocated.reason.as_deref(), Some("address_not_recorded"));
    // An open breaker makes the marker red.
    parts.parts[0].upstreams[0].breaker = "open".into();
    let w = world(&parts, &th(), 0, None, &geo(TABLE));
    assert_eq!(w.markers[0].health, MapHealth::Red);
}

/// REQ: OBS-902 (T26.5) - `node` narrows the world view to one node's prefixes and upstreams.
#[test]
fn obs_902_world_node_filter() {
    let parts = world_parts(vec![
        vec![answer("93.184.216.34", 100, 20, 0)],
        vec![answer("185.60.216.35", 40, 20, 0)],
    ]);
    let both = world(&parts, &th(), 0, None, &geo(TABLE));
    assert_eq!(both.regions.len(), 2);
    let one = world(&parts, &th(), 0, Some("PI1"), &geo(TABLE));
    assert_eq!(one.regions.len(), 1, "{one:?}");
    assert_eq!(one.regions[0].cc, "IE");
    assert_eq!(one.unlocated.count, 300 - 40);
    let none = world(&parts, &th(), 0, Some("nope"), &geo(TABLE));
    assert_eq!(none.regions.len(), 0);
}

/// An address maps to its /24 or /48.
#[test]
fn obs_902_prefix_of() {
    assert_eq!(
        prefix_of("93.184.216.34".parse().unwrap()),
        "93.184.216.0".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        prefix_of("2606:4700:4700:1:2:3:4:1111".parse().unwrap()),
        "2606:4700:4700::".parse::<IpAddr>().unwrap()
    );
}

/// REQ: OBS-901 (ADR-971) — a member the relay reports up but this node can't reach is an idle
/// resolver with its own reason; it is not red and does not make the map partial.
#[test]
fn obs_901_unseen_member_is_idle_not_red() {
    let parts = MapParts {
        parts: vec![part(
            "pi1",
            vec![entry(
                client(7),
                AnswerKind::Cache,
                0,
                counts(30, 30, 0, 0, 0),
            )],
        )],
        missing: vec![],
        unseen: vec!["pi2".into()],
        pending: Vec::new(),
    };
    let s = build(&parts, &ctx(&no_names), &Filter::default());
    assert!(!s.partial);
    let n = find(&s, "res:pi2");
    assert_eq!(n.health, MapHealth::Idle);
    assert_eq!(n.reasons[0].code, "not_reachable_from_here");
}

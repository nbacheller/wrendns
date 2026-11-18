//! Tests of the poller's main-process side (DSC-004, DSC-007, DSC-014, ADR-908, ADR-1002): the
//! request it builds, the board, a whole poll through a fake worker, and **Test**'s dry run and
//! cooldown. No packet is sent: a task answers the queued jobs the way the SNMP worker would.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::collections::VecDeque;

use telltale_config::Loader;

use super::super::runtime::Runtime;
use super::super::snmp_fixtures::{Clock, FakeMib, GATEWAY, SWITCH};
use super::super::snmp_poll;
use super::super::worker::JobResult;
use super::*;

fn config(dir: &std::path::Path, extra: &str) -> Config {
    std::fs::write(dir.join("comm"), "ttcomm\n").unwrap();
    std::fs::write(dir.join("auth"), "planted-auth-secret").unwrap();
    let toml = format!(
        "[node]\nsecret_file_dirs = [\"{d}\"]\n[discovery]\nenabled = true\n\
         [[discovery.subnet]]\ncidr = \"192.0.2.0/24\"\n\
         [[discovery.subnet]]\ncidr = \"192.168.20.0/24\"\n\
         [[discovery.snmp_credential]]\nname = \"v2\"\ncommunity_file = \"{d}/comm\"\n\
         [[discovery.snmp_credential]]\nname = \"v3\"\nversion = \"v3\"\nuser = \"u\"\nauth_protocol = \"sha\"\nauth_password_file = \"{d}/auth\"\npriv_protocol = \"aes-128\"\n\
         [[discovery.snmp_credential]]\nname = \"hostcred\"\nrole = \"host\"\ncommunity_file = \"{d}/comm\"\n\
         {extra}",
        d = dir.display()
    );
    Loader::new().toml_str("t", &toml).load().unwrap().config
}

fn agent_toml(name: &str, addr: &str, cred: &str) -> String {
    format!(
        "[[discovery.snmp_agent]]\nname = \"{name}\"\naddress = \"{addr}\"\ncredential = \"{cred}\"\n"
    )
}

/// REQ: DSC-004, DSC-007 — the request names a destination the poller checked and a credential it
/// read from its file; a refused destination, a credential outside the secret directories, a host
/// credential and a missing file are each refused with a reason that carries no path or secret.
#[test]
fn dsc_004_request_checks_destination_and_reads_the_credential() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        dir.path(),
        &format!(
            "{}{}",
            agent_toml("gateway", "192.0.2.1", "v3"),
            agent_toml("old", "192.0.2.2", "v2")
        ),
    );
    let ctx = PollerCtx::of(&cfg);
    let gw = ctx.agent("gateway").unwrap();
    let req = ctx.request(gw, None).unwrap();
    assert_eq!(req.address, Ipv4Addr::new(192, 0, 2, 1));
    match &req.auth {
        AuthSpec::V3 {
            user,
            auth_password,
            priv_protocol,
            priv_password,
            ..
        } => {
            assert_eq!(user, "u");
            assert_eq!(auth_password.expose(), b"planted-auth-secret");
            assert_eq!(priv_protocol.as_deref(), Some("aes-128"));
            assert!(
                priv_password.is_none(),
                "the auth password is used for both"
            );
        }
        other @ AuthSpec::V2c { .. } => panic!("{other:?}"),
    }
    let v2 = ctx.request(ctx.agent("old").unwrap(), None).unwrap();
    assert!(matches!(&v2.auth, AuthSpec::V2c { community } if community.expose() == b"ttcomm"));

    // A destination outside RFC 1918 and the host's own address are refused (ADR-907).
    let mut bad = gw.clone();
    bad.address = telltale_config::SafeString::new("8.8.8.8").unwrap();
    let e = ctx.request(&bad, None).unwrap_err();
    assert!(e.contains("destination refused"), "{e}");
    let mut own = gw.clone();
    own.address = telltale_config::SafeString::new("127.0.0.1").unwrap();
    assert!(ctx.request(&own, None).is_err());
    // A host credential is not an infrastructure credential.
    let mut host = gw.clone();
    host.credential = telltale_config::SafeString::new("hostcred").unwrap();
    assert!(
        ctx.request(&host, None)
            .unwrap_err()
            .contains("infrastructure")
    );
    // A credential file outside the secret directories (or missing) is refused, naming no path.
    let mut elsewhere = ctx.clone();
    elsewhere.secret_dirs = vec![PathBuf::from("/nonexistent-secret-dir")];
    let e = elsewhere.request(gw, None).unwrap_err();
    assert!(e.contains("secret_file_dirs"), "{e}");
    assert!(!e.contains(dir.path().to_str().unwrap()), "{e}");
    std::fs::remove_file(dir.path().join("auth")).unwrap();
    assert!(ctx.request(gw, None).is_err());
}

/// REQ: DSC-004, DSC-014 — an agent is waiting until it is polled, `error` after a failed poll,
/// `failing` after three in a row, and ok again once a poll works; the board keeps counts.
#[test]
fn dsc_014_agent_state_follows_its_polls() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), &agent_toml("gateway", "192.0.2.1", "v2"));
    let ctx = PollerCtx::of(&cfg);
    let board = AgentsBoard::default();
    board.configure(&ctx.agents);
    let state = |b: &AgentsBoard| b.snapshot().remove(0);
    assert_eq!(state(&board).state, "waiting");
    assert_eq!(
        state(&board)
            .tables
            .iter()
            .map(|t| t.state.as_str())
            .collect::<Vec<_>>(),
        ["unprobed"; 4]
    );
    board.record_failure("gateway", "no reply (timeout)", false, 100);
    let a = state(&board);
    assert_eq!((a.state.as_str(), a.consecutive_failures), ("error", 1));
    board.record_failure("gateway", "no reply (timeout)", false, 160);
    board.record_failure("gateway", "no reply (timeout)", false, 220);
    let a = state(&board);
    assert_eq!(a.state, "failing");
    assert_eq!((a.polls, a.failures), (3, 3));
    assert_eq!(a.last_error.as_deref(), Some("no reply (timeout)"));
    // A success resets the run.
    board.record_success(
        "gateway",
        &SnmpResult::default(),
        Interpreted::default(),
        vec![],
        300,
    );
    let a = state(&board);
    assert_eq!((a.state.as_str(), a.consecutive_failures), ("ok", 0));
    assert_eq!(a.last_success_unix, Some(300));
    assert_eq!(a.polls, 4);
    // A skipped agent (no usable credential) says so.
    board.record_failure("gateway", "a credential file can't be read", true, 400);
    assert_eq!(state(&board).state, "skipped");
}

/// REQ: DSC-004 (`dsc_004_snmp_test_dry_run_and_cooldown`, board part) — a test of an agent waits 60 s
/// after the last one, and a reconfigure keeps the cooldown of an agent that is still there.
#[test]
fn dsc_004_test_cooldown_is_sixty_seconds() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), &agent_toml("gateway", "192.0.2.1", "v2"));
    let ctx = PollerCtx::of(&cfg);
    let board = AgentsBoard::default();
    board.configure(&ctx.agents);
    assert_eq!(board.begin_test("gateway", 1_000), Ok(()));
    assert_eq!(board.begin_test("gateway", 1_001), Err(59));
    assert_eq!(board.begin_test("gateway", 1_059), Err(1));
    board.configure(&ctx.agents);
    assert_eq!(
        board.begin_test("gateway", 1_030),
        Err(30),
        "a reconfigure keeps it"
    );
    assert_eq!(board.begin_test("gateway", 1_060), Ok(()));
    assert_eq!(board.snapshot()[0].last_test_unix, Some(1_060));
}

/// REQ: DSC-004 — a test lists the OIDs without a packet: the probe root of every alternative of
/// every part of every table, and sysObjectID.
#[test]
fn dsc_004_the_oids_a_test_queries() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), &agent_toml("gateway", "192.0.2.1", "v2"));
    let agent = PollerCtx::of(&cfg).agents[0].clone();
    let oids = test_oids(&agent);
    let arp: Vec<&str> = oids
        .iter()
        .filter(|o| o.table == "arp")
        .map(|o| o.alternative.as_str())
        .collect();
    assert_eq!(arp, ["ipNetToPhysicalTable", "ipNetToMediaTable"]);
    let bridge = oids
        .iter()
        .find(|o| o.alternative == "dot1qTpFdbTable")
        .unwrap();
    assert_eq!(bridge.probe_oid, "1.3.6.1.2.1.17.7.1.2.2.1.2");
    assert_eq!(bridge.columns.len(), 2);
    assert!(oids.iter().any(|o| o.probe_oid == "1.3.6.1.2.1.1.2.0"));
    assert!(oids.iter().all(|o| !o.probe_oid.is_empty()));
}

/// Answers every queued job with `make(job)` until stopped. Stands in for the SNMP worker.
fn fake_worker(
    requests: Requests,
    make: impl Fn(&Job) -> Reply + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let next = requests.lock().unwrap().pop_front();
            match next {
                Some(Request { job, reply }) => {
                    if let Some(tx) = reply {
                        let _ = tx.send(Ok(make(&job)));
                    }
                }
                None => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
}

/// What the worker would answer for a gateway poll: the recorded-shape walk, polled through the
/// fake agent on a virtual clock.
fn worker_answer(text: &'static str) -> impl Fn(&Job) -> Reply + Send + 'static {
    move |job: &Job| {
        let req = job.snmp.clone().unwrap();
        let clock = Clock::new();
        let mut mib = FakeMib::from_walk(text, &clock);
        let probe_only = job.op == "snmp_probe";
        let o = snmp_poll::run(&mut mib, &mut clock.clone(), &req, probe_only);
        Reply {
            result: JobResult {
                id: job.id,
                ok: o.result.aborted.is_none(),
                op: job.op.clone(),
                error: o.result.aborted.clone(),
                snmp: Some(o.result),
            },
            rows: o.rows,
        }
    }
}

/// REQ: DSC-004, DSC-014 (e2e with a fake snmpd serving recorded walks, main-process side) — a poll of
/// the gateway and one of the switch go through the queue, the rows are interpreted, the observations
/// reach the inventory's channel, and the board shows each agent's tables, counts and capability.
#[tokio::test]
async fn dsc_004_a_poll_goes_from_queue_to_board_to_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        dir.path(),
        &format!(
            "{}{}",
            agent_toml("gateway", "192.0.2.1", "v2"),
            agent_toml("sw1", "192.0.2.2", "v2")
        ),
    );
    let ctx = Arc::new(PollerCtx::of(&cfg));
    let board = Arc::new(AgentsBoard::default());
    board.configure(&ctx.agents);
    let requests: Requests = Arc::new(Mutex::new(VecDeque::new()));
    let worker = fake_worker(Arc::clone(&requests), {
        let gw = worker_answer(GATEWAY);
        let sw = worker_answer(SWITCH);
        move |job: &Job| {
            let name = job.snmp.as_ref().unwrap().agent.clone();
            if name == "gateway" { gw(job) } else { sw(job) }
        }
    });
    let (tx, mut rx) = mpsc::channel::<PollOutput>(8);
    // The gateway first, so its interface MACs are known when the switch's uplinks are decided.
    for name in ["gateway", "sw1"] {
        let agent = ctx.agent(name).unwrap();
        poll_agent(&ctx, agent, &board, &requests, &tx).await;
    }
    worker.abort();
    let gw = rx.recv().await.unwrap();
    assert_eq!(gw.agent, "gateway");
    assert!(
        gw.observations.len() >= 98 / 2,
        "ARP entries of the listed subnets: {}",
        gw.observations.len()
    );
    let sw = rx.recv().await.unwrap();
    // The switch's port 23 hangs off the gateway (known by MAC after its poll): it is an uplink.
    let on_23 = sw
        .observations
        .iter()
        .any(|o| o.mac == Some([0x3c, 0x22, 0xfb, 0x01, 0x00, 0x1e]));
    assert!(
        !on_23,
        "port 23 is an uplink once the gateway's MACs are known"
    );
    let agents = board.snapshot();
    let g = &agents[0];
    assert_eq!((g.name.as_str(), g.state.as_str()), ("gateway", "ok"));
    let state_of = |a: &DiscoveryAgent, t: &str| {
        a.tables
            .iter()
            .find(|x| x.table == t)
            .map(|x| x.state.clone())
            .unwrap()
    };
    assert_eq!(state_of(g, "arp"), "answered");
    assert_eq!(
        state_of(g, "bridge"),
        "unanswered",
        "the gateway has no bridge MIB"
    );
    assert_eq!(state_of(g, "lldp"), "unanswered");
    assert_eq!(g.last_counts.as_ref().unwrap().ipv6_ignored, 81);
    assert_eq!(
        g.capability.as_ref().unwrap().sys_object_id.as_deref(),
        Some("1.3.6.1.4.1.8072.3.2.10")
    );
    let s = &agents[1];
    assert_eq!(state_of(s, "bridge"), "answered");
    assert!(s.last_counts.as_ref().unwrap().uplink_ports >= 2);
    assert!(
        s.tables
            .iter()
            .find(|t| t.table == "bridge")
            .unwrap()
            .rows
            .unwrap()
            > 0
    );
}

/// REQ: DSC-004, DSC-007 — a failed credential read marks the agent `skipped` without queuing
/// anything; a worker that answers with a failure marks it failed and merges nothing.
#[tokio::test]
async fn dsc_004_failed_polls_merge_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), &agent_toml("gateway", "192.0.2.1", "v2"));
    let ctx = Arc::new(PollerCtx::of(&cfg));
    let board = Arc::new(AgentsBoard::default());
    board.configure(&ctx.agents);
    let requests: Requests = Arc::new(Mutex::new(VecDeque::new()));
    let (tx, mut rx) = mpsc::channel::<PollOutput>(8);
    let agent = ctx.agent("gateway").unwrap();
    std::fs::remove_file(dir.path().join("comm")).unwrap();
    poll_agent(&ctx, agent, &board, &requests, &tx).await;
    assert_eq!(board.snapshot()[0].state, "skipped");
    assert!(requests.lock().unwrap().is_empty(), "nothing was queued");
    // The worker answers that the poll could not finish.
    std::fs::write(dir.path().join("comm"), "ttcomm").unwrap();
    let worker = fake_worker(Arc::clone(&requests), |job: &Job| Reply {
        result: JobResult {
            id: job.id,
            ok: false,
            op: job.op.clone(),
            error: Some("three timeouts in a row".into()),
            snmp: None,
        },
        rows: Vec::new(),
    });
    poll_agent(&ctx, agent, &board, &requests, &tx).await;
    worker.abort();
    let a = &board.snapshot()[0];
    assert_eq!(a.state, "error");
    assert_eq!(a.last_error.as_deref(), Some("three timeouts in a row"));
    assert!(rx.try_recv().is_err(), "a failed poll merges nothing");
}

/// REQ: DSC-004, DSC-007 — a request whose caller gave up is dropped by the supervisor, so a worker
/// that was down doesn't run a backlog of stale polls (checked on the queue's shape here).
#[test]
fn dsc_004_a_closed_reply_marks_a_stale_request() {
    let (tx, rx) = oneshot::channel::<Result<Reply, String>>();
    drop(rx);
    assert!(tx.is_closed());
}

/// REQ: DSC-004 (`dsc_004_snmp_test_dry_run_and_cooldown`) — **Test** through the runtime: a dry run
/// lists the OIDs and queues nothing; a real test goes ahead of the polls, records the capability
/// record, and a second test inside a minute is refused with the seconds left; an unknown agent is a
/// 404 and an off inventory is `discovery_not_here`. An address is never a name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dsc_004_snmp_test_dry_run_and_cooldown() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), &agent_toml("gateway", "192.0.2.1", "v2"));
    let rt = Runtime::default();
    let write = |agent: &str, dry_run: bool| telltale_api::SnmpTestWrite {
        agent: agent.into(),
        dry_run,
        by: "admin".into(),
        reason: None,
    };
    // Off: the node says so.
    let e = rt.snmp_test(write("gateway", true)).await.unwrap_err();
    assert_eq!(e.code, telltale_api::problem::Code::DiscoveryNotHere);

    rt.designate_for_tests(&cfg);
    let answerer = fake_worker(rt.requests(), worker_answer(GATEWAY));

    let e = rt.snmp_test(write("nope", false)).await.unwrap_err();
    assert_eq!(e.status, 404);
    assert!(
        e.hint.as_deref().is_some_and(|h| h.contains("gateway")),
        "{:?}",
        e.hint
    );

    // A dry run lists the OIDs, sends nothing and starts no cooldown.
    let dry = rt.snmp_test(write("gateway", true)).await.unwrap();
    assert!(dry.dry_run && dry.ok && dry.capability.is_none());
    assert!(
        dry.oids
            .iter()
            .any(|o| o.probe_oid == "1.3.6.1.2.1.4.35.1.4")
    );
    assert!(rt.requests().lock().unwrap().is_empty());
    assert_eq!(rt.status().agents[0].last_test_unix, None);

    // A real test records the capability record ...
    let first = rt.snmp_test(write("gateway", false)).await.unwrap();
    assert!(first.ok, "{first:?}");
    let cap = first.capability.unwrap();
    assert_eq!(cap.level, "v2c");
    let source = |part: &str| {
        cap.parts
            .iter()
            .find(|p| p.part == part)
            .and_then(|p| p.source.clone())
    };
    assert_eq!(source("arp").as_deref(), Some("ipNetToPhysicalTable"));
    assert_eq!(source("forwarding"), None);
    let status = rt.status();
    assert!(status.agents[0].capability.is_some());
    assert!(status.agents[0].last_test_unix.is_some());
    // ... and a second one right after it is refused, with the wait.
    let again = rt.snmp_test(write("gateway", false)).await.unwrap_err();
    assert_eq!(again.code, telltale_api::problem::Code::RateLimited);
    assert!(again.retry_after.is_some_and(|s| (1..=60).contains(&s)));
    // The dry run is still allowed.
    assert!(rt.snmp_test(write("gateway", true)).await.is_ok());
    answerer.abort();
    rt.stop();
}

//! REQ: DSC-002 (T25.3, ADR-908) — the discovery worker processes, run for real: the built
//! `telltale discovery-worker` binary, started with a cleared environment, driven over its stdin
//! and stdout with the frame protocol of ADR-908. The fault jobs (a panic, a hang, an allocation
//! past the memory limit) exist in debug builds only, so those tests are compiled out of release.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::assert_is_empty,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)] // test helpers, not runtime code

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_telltale");
const KIND_JSON: u8 = 1;

/// One frame on the wire: the length (kind byte plus payload), the kind, the payload.
fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len() + 1).unwrap();
    let mut out = len.to_be_bytes().to_vec();
    out.push(kind);
    out.extend_from_slice(body);
    out
}

fn json_frame(v: &Value) -> Vec<u8> {
    frame(KIND_JSON, v.to_string().as_bytes())
}

/// A running worker: its stdin, and a reader thread that hands each frame on a channel.
struct Worker {
    child: Child,
    frames: mpsc::Receiver<Value>,
}

impl Worker {
    fn start(args: &[&str]) -> Self {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // REQ: DSC-002 (ADR-988) - started as the supervisor starts it: the spawn preparation sets
        // the allocator's environment, without which a release worker can't run under its limit.
        telltale_net::worker::prepare_spawn(&mut cmd).unwrap();
        Self::spawn(&mut cmd)
    }

    /// Starts the worker as another user (`uid` and `gid`), as the systemd unit, the image and the
    /// Helm chart run it. Needs root to change the user.
    #[cfg(target_os = "linux")]
    fn start_as(args: &[&str], uid: u32) -> Self {
        use std::os::unix::process::CommandExt;
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env_clear()
            .uid(uid)
            .gid(uid)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        telltale_net::worker::prepare_spawn(&mut cmd).unwrap();
        Self::spawn(&mut cmd)
    }

    fn spawn(cmd: &mut Command) -> Self {
        let mut child = cmd.spawn().expect("the telltale binary starts");
        let mut out = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            loop {
                let mut head = [0u8; 5];
                if out.read_exact(&mut head).is_err() {
                    return;
                }
                let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
                let mut body = vec![0u8; len.saturating_sub(1)];
                if out.read_exact(&mut body).is_err() {
                    return;
                }
                if head[4] == KIND_JSON
                    && let Ok(v) = serde_json::from_slice::<Value>(&body)
                    && tx.send(v).is_err()
                {
                    return;
                }
            }
        });
        Self { child, frames: rx }
    }

    fn send(&mut self, bytes: &[u8]) {
        let stdin = self.child.stdin.as_mut().unwrap();
        // The worker may have exited already (a refused handshake); a broken pipe is the answer.
        let _ = stdin.write_all(bytes);
        let _ = stdin.flush();
    }

    fn next(&self, within: Duration) -> Option<Value> {
        self.frames.recv_timeout(within).ok()
    }

    fn hello(memory_mib: u32, build: &str) -> Value {
        json!({"t": "hello", "protocol": 1, "build": build, "memory_mib": memory_mib})
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// REQ: DSC-002 (`dsc_002_worker_starts_as_non_root`) — the worker starts, hardens itself and
/// answers its handshake as an unprivileged user. The systemd unit (`User=telltale`), the image
/// (`USER 65532`) and the Helm chart (`runAsUser: 65532`) all run it that way. Its `oom_score_adj` is
/// written before the process becomes not dumpable, so the write is still the process's own. The
/// test needs root to start the worker as another user, and skips when it isn't root.
#[cfg(target_os = "linux")]
#[test]
fn dsc_002_worker_starts_as_non_root() {
    let status = std::fs::read_to_string("/proc/self/status").expect("status");
    let root = status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .is_some_and(|l| l.split_whitespace().nth(1) == Some("0"));
    if !root {
        eprintln!("skipped: the test starts the worker as another user, which needs root");
        return;
    }
    let build = worker_build();
    let mut w = Worker::start_as(&["discovery-worker"], 65534);
    w.send(&json_frame(&Worker::hello(64, &build)));
    let reply = w.next(Duration::from_secs(10)).expect(
        "the non-root worker answers its hello (it exits with code 4 when it can't harden)",
    );
    assert_eq!(reply["t"], "hello");
    assert_eq!(reply["dumpable"], false, "a worker is not dumpable");
    assert_eq!(
        reply["oom_score_adj"], 1000,
        "the kernel kills the worker first"
    );
    assert_eq!(
        reply["data_bytes"],
        64u64 << 20,
        "RLIMIT_DATA is the asked-for size"
    );
    w.send(&json_frame(&json!({"t": "job", "id": 1, "op": "ping"})));
    let answer = w.next(Duration::from_secs(10)).expect("ping answer");
    assert_eq!(answer["ok"], true);
}

/// The worker's own build, as it answers a hello it refuses (the answer carries its build).
fn worker_build() -> String {
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(64, "not this build")));
    let reply = w
        .next(Duration::from_secs(10))
        .expect("the worker answers its hello");
    reply["build"].as_str().unwrap().to_owned()
}

/// The worker's hello reply to a matching hello, after its limits were applied.
fn limits_reply(memory_mib: u32) -> Value {
    let build = worker_build();
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(memory_mib, &build)));
    w.next(Duration::from_secs(10)).expect("hello reply")
}

/// REQ: DSC-002 (`dsc_002_worker_env_is_empty`) — the worker starts with no environment: the parent
/// cleared it, and the worker reports how many variables it sees: the one the spawn preparation
/// sets for the allocator (ADR-988), nothing else.
#[test]
fn dsc_002_worker_env_is_empty() {
    let reply = limits_reply(64);
    assert_eq!(reply["t"], "hello");
    assert_eq!(
        reply["env_vars"], 1,
        "the worker sees only the allocator's variable"
    );
    assert_eq!(reply["mode"], "snmp");
}

/// REQ: DSC-002 (`dsc_002_worker_oom_is_preferred`) — the worker asks the kernel to kill it first.
#[test]
fn dsc_002_worker_oom_is_preferred() {
    let reply = limits_reply(64);
    assert_eq!(
        reply["oom_score_adj"], 1000,
        "the kernel kills the worker first"
    );
}

/// REQ: DSC-002 (`dsc_002_worker_not_dumpable`) — the worker is not dumpable, and its memory limit
/// is the one asked for (`RLIMIT_DATA` on Linux). A ping after the handshake is answered.
#[test]
fn dsc_002_worker_not_dumpable() {
    let build = worker_build();
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(64, &build)));
    let reply = w.next(Duration::from_secs(10)).expect("hello reply");
    assert_eq!(reply["dumpable"], false, "a worker is not dumpable");
    if cfg!(target_os = "linux") {
        assert_eq!(
            reply["data_bytes"],
            64u64 << 20,
            "RLIMIT_DATA is the asked-for size"
        );
    }
    w.send(&json_frame(&json!({"t": "job", "id": 1, "op": "ping"})));
    let answer = w.next(Duration::from_secs(10)).expect("ping answer");
    assert_eq!(answer["t"], "result");
    assert_eq!(answer["ok"], true);
}

/// REQ: DSC-002 (`dsc_002_version_mismatch_refused`) — a parent of another build is refused: the
/// worker answers its own hello and exits with code 3, and nothing else runs.
#[test]
fn dsc_002_version_mismatch_refused() {
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(
        64,
        "a build that isn't this one",
    )));
    let reply = w
        .next(Duration::from_secs(10))
        .expect("the refusal names the worker's build");
    assert_eq!(reply["t"], "hello");
    assert_ne!(reply["build"], "a build that isn't this one");
    let status = w.child.wait().unwrap();
    assert_eq!(status.code(), Some(3));
}

/// REQ: DSC-002 (`dsc_002_oversized_frame_refused`) — a frame whose header claims more than 1 MiB of
/// JSON is refused from the header alone: the worker exits with code 2 without reading the body.
#[test]
fn dsc_002_oversized_frame_refused() {
    let mut w = Worker::start(&["discovery-worker"]);
    let claimed: u32 = (1 << 20) + 2;
    let mut head = claimed.to_be_bytes().to_vec();
    head.push(KIND_JSON);
    w.send(&head);
    let status = w.child.wait().unwrap();
    assert_eq!(status.code(), Some(2));
}

/// REQ: DSC-002 (`dsc_002_worker_panic_keeps_dns_answering`, the worker's part) — a worker that
/// panics ends as its own process; the test process, which stands for the DNS process, is
/// unaffected and can start the next worker.
#[cfg(debug_assertions)]
#[test]
fn dsc_002_worker_panic_ends_only_the_worker() {
    let build = worker_build();
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(64, &build)));
    let _ = w.next(Duration::from_secs(10)).expect("hello reply");
    w.send(&json_frame(
        &json!({"t": "job", "id": 9, "op": "fault", "kind": "panic"}),
    ));
    let status = w.child.wait().unwrap();
    assert!(!status.success(), "a panicking worker exits unsuccessfully");
    let mut next = Worker::start(&["discovery-worker"]);
    next.send(&json_frame(&Worker::hello(64, &build)));
    assert!(
        next.next(Duration::from_secs(10)).is_some(),
        "the next worker starts"
    );
}

/// REQ: DSC-002 (`dsc_002_worker_hang_times_out`) — a job that never answers is not answered in time,
/// and the supervisor's kill (here, the test's) ends the worker.
#[cfg(debug_assertions)]
#[test]
fn dsc_002_worker_hang_times_out() {
    let build = worker_build();
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(64, &build)));
    let _ = w.next(Duration::from_secs(10)).expect("hello reply");
    w.send(&json_frame(
        &json!({"t": "job", "id": 5, "op": "fault", "kind": "hang"}),
    ));
    assert!(
        w.next(Duration::from_secs(2)).is_none(),
        "a hung job gives no answer"
    );
    w.child.kill().unwrap();
    assert!(w.child.wait().is_ok());
}

/// REQ: DSC-002 (`dsc_002_worker_rlimit_aborts_alone`) — a worker that allocates past its memory
/// limit aborts, and only it: the test process carries on.
#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn dsc_002_worker_rlimit_aborts_alone() {
    let build = worker_build();
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(32, &build)));
    let reply = w.next(Duration::from_secs(10)).expect("hello reply");
    assert_eq!(reply["data_bytes"], 32u64 << 20);
    w.send(&json_frame(
        &json!({"t": "job", "id": 2, "op": "fault", "kind": "alloc"}),
    ));
    let status = w.child.wait().unwrap();
    assert!(
        !status.success(),
        "an allocation past RLIMIT_DATA aborts the worker"
    );
}

// ---------------------------------------------------------------------------------------------
// REQ: DSC-004, DSC-007 (T25.6, ADR-908) - the SNMP jobs through the real worker process, against a
// fake v2c agent on the loopback address that serves the recorded-shape walks of
// `tests/fixtures/snmp/` (synthetic, see `generate.py`). The worker holds no destination policy of
// its own (the main process checked it), so the loopback address is only ever a test's. No real
// device is asked, and no address outside this test process is used.
// ---------------------------------------------------------------------------------------------

mod fake_snmpd {
    use std::collections::BTreeMap;
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use telltale_snmp::ber;
    use telltale_snmp::oid::Oid;
    use telltale_snmp::pdu::{self, TAG_RESPONSE, Value, VarBind};
    use telltale_snmp::v2c;

    /// Parses `snmpwalk -On` lines into an ordered MIB.
    fn parse_walk(text: &str) -> BTreeMap<Oid, Value> {
        let mut out = BTreeMap::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let (oid, rest) = line.split_once(" = ").unwrap();
            let (typ, value) = rest
                .split_once(": ")
                .unwrap_or((rest.trim_end_matches(':'), ""));
            let v = match typ {
                "INTEGER" => Value::Integer(value.trim().parse().unwrap()),
                "STRING" => Value::OctetString(value.as_bytes().to_vec()),
                "Hex-STRING" => Value::OctetString(
                    value
                        .split_whitespace()
                        .map(|h| u8::from_str_radix(h, 16).unwrap())
                        .collect(),
                ),
                "OID" => Value::Oid(Oid::parse(value.trim().trim_start_matches('.')).unwrap()),
                other => panic!("walk type {other}"),
            };
            out.insert(Oid::parse(oid.trim_start_matches('.')).unwrap(), v);
        }
        out
    }

    pub(crate) struct Fake {
        pub(crate) addr: SocketAddr,
        /// When each datagram with a valid community arrived.
        pub(crate) arrivals: Arc<Mutex<Vec<Instant>>>,
        /// Datagrams of any kind received.
        pub(crate) datagrams: Arc<Mutex<u32>>,
        stop: Arc<AtomicBool>,
        join: Option<JoinHandle<()>>,
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(j) = self.join.take() {
                let _ = j.join();
            }
        }
    }

    pub(crate) fn start(walk: &str, community: &'static [u8]) -> Fake {
        let mib = parse_walk(walk);
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let arrivals = Arc::new(Mutex::new(Vec::new()));
        let datagrams = Arc::new(Mutex::new(0u32));
        let (s2, a2, d2) = (
            Arc::clone(&stop),
            Arc::clone(&arrivals),
            Arc::clone(&datagrams),
        );
        let join = thread::spawn(move || {
            let mut buf = vec![0u8; 65_536];
            while !s2.load(Ordering::Relaxed) {
                let Ok((n, from)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let at = Instant::now();
                *d2.lock().unwrap() += 1;
                let Some(msg) = buf.get(..n) else { continue };
                let Ok(tlv) = ber::read_message(msg) else {
                    continue;
                };
                let Ok(kids) = ber::children(tlv.content, 0, 3) else {
                    continue;
                };
                let [_v, c, p] = kids.as_slice() else {
                    continue;
                };
                if c.content != community {
                    continue;
                }
                a2.lock().unwrap().push(at);
                let Ok(pk) = ber::children(p.content, 2, 4) else {
                    continue;
                };
                let id = i32::try_from(ber::integer_value(pk[0].content).unwrap()).unwrap();
                let reps = usize::try_from(ber::integer_value(pk[2].content).unwrap()).unwrap();
                let oids: Vec<Oid> = pdu::decode_varbinds(pk[3].content)
                    .unwrap()
                    .into_iter()
                    .map(|v| v.oid)
                    .collect();
                let after = |o: &Oid, take: usize| -> Vec<VarBind> {
                    let v: Vec<VarBind> = mib
                        .range::<Oid, _>((std::ops::Bound::Excluded(o), std::ops::Bound::Unbounded))
                        .take(take)
                        .map(|(k, v)| VarBind {
                            oid: k.clone(),
                            value: v.clone(),
                        })
                        .collect();
                    if v.is_empty() {
                        vec![VarBind {
                            oid: o.clone(),
                            value: Value::EndOfMibView,
                        }]
                    } else {
                        v
                    }
                };
                let vbs: Vec<VarBind> = match p.tag {
                    0xa0 => oids
                        .iter()
                        .map(|o| VarBind {
                            oid: o.clone(),
                            value: mib.get(o).cloned().unwrap_or(Value::NoSuchInstance),
                        })
                        .collect(),
                    0xa1 => oids.iter().flat_map(|o| after(o, 1)).collect(),
                    0xa5 => oids.first().map(|o| after(o, reps)).unwrap_or_default(),
                    _ => continue,
                };
                if let Ok(reply) = pdu::encode_response(TAG_RESPONSE, id, 0, &vbs) {
                    let _ = sock.send_to(&v2c::encode(community, &reply), from);
                }
            }
        });
        Fake {
            addr,
            arrivals,
            datagrams,
            stop,
            join: Some(join),
        }
    }
}

const GATEWAY_WALK: &str = include_str!("fixtures/snmp/unifi-gateway.walk");
const SWITCH_WALK: &str = include_str!("fixtures/snmp/aruba-switch.walk");

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn snmp_job(id: u64, op: &str, agent: &str, port: u16, community: &[u8], tables: &[&str]) -> Value {
    json!({
        "t": "job", "id": id, "op": op,
        "snmp": {
            "agent": agent, "address": "127.0.0.1", "port": port,
            "auth": {"version": "v2c", "community": hex(community)},
            "tables": tables, "max_repetitions": 10
        }
    })
}

/// Sends a job and collects the `rows` frames and the result (or None on `within`).
fn run_snmp_job(w: &mut Worker, job: &Value, within: Duration) -> Option<(Vec<Value>, Value)> {
    w.send(&json_frame(job));
    let id = job["id"].clone();
    let mut rows = Vec::new();
    let deadline = std::time::Instant::now() + within;
    loop {
        let left = deadline.checked_duration_since(std::time::Instant::now())?;
        let f = w.next(left)?;
        match f["t"].as_str() {
            Some("rows") => {
                assert_eq!(f["id"], id);
                rows.extend(f["rows"].as_array().unwrap().iter().cloned());
            }
            Some("result") => return Some((rows, f)),
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

fn snmp_worker() -> Worker {
    let build = worker_build();
    let mut w = Worker::start(&["discovery-worker"]);
    w.send(&json_frame(&Worker::hello(64, &build)));
    let hello = w.next(Duration::from_secs(10)).expect("hello reply");
    assert_eq!(hello["t"], "hello");
    w
}

/// REQ: DSC-004 (e2e with a fake snmpd serving recorded walks) - the real worker probes and polls a
/// gateway-shaped agent over UDP: it finds which tables answer with one GETNEXT each, walks the
/// ARP and interface tables, and sends the rows in frames before the result. The rows are the
/// 98 IPv4 ARP entries (81 IPv6 ones counted, 10 incomplete skipped), and the requests are spaced at
/// least 50 ms apart (at most 20 a second).
#[test]
fn dsc_004_worker_polls_a_gateway_shaped_agent() {
    let fake = fake_snmpd::start(GATEWAY_WALK, b"ttcomm");
    let mut w = snmp_worker();
    let job = snmp_job(
        1,
        "snmp_poll",
        "gateway",
        fake.addr.port(),
        b"ttcomm",
        &["arp", "ifmib", "bridge", "lldp"],
    );
    let (rows, result) = run_snmp_job(&mut w, &job, Duration::from_secs(60)).expect("a result");
    assert_eq!(result["ok"], true, "{result}");
    let arp = rows.iter().filter(|r| r["k"] == "arp").count();
    assert_eq!(arp, 98);
    assert_eq!(result["snmp"]["ipv6_ignored"], 81);
    assert_eq!(result["snmp"]["skipped"], 10);
    let cap = &result["snmp"]["capability"];
    assert_eq!(cap["level"], "v2c");
    assert_eq!(cap["sys_object_id"], "1.3.6.1.4.1.8072.3.2.10");
    let alt = |part: &str| {
        cap["choices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["part"] == part)
            .and_then(|c| c["alt"].as_str())
            .map(str::to_owned)
    };
    assert_eq!(alt("arp").as_deref(), Some("ipNetToPhysicalTable"));
    assert_eq!(
        alt("forwarding"),
        None,
        "the gateway has no bridge MIB: probed, not assumed"
    );
    assert_eq!(alt("neighbours"), None);
    // The result's request count is what the agent saw.
    let arrivals = fake.arrivals.lock().unwrap().clone();
    assert_eq!(
        arrivals.len() as u64,
        result["snmp"]["requests"].as_u64().unwrap()
    );
    // Pacing on the wire: at least 50 ms between requests (a little under for scheduling), and
    // no second holds more than 20.
    for pair in arrivals.windows(2) {
        assert!(
            pair[1] - pair[0] >= Duration::from_millis(45),
            "gap {:?}",
            pair[1] - pair[0]
        );
    }
    for (i, t) in arrivals.iter().enumerate() {
        let n = arrivals[i..]
            .iter()
            .take_while(|u| **u < *t + Duration::from_secs(1))
            .count();
        assert!(n <= 21, "{n} requests inside one second");
    }
}

/// REQ: DSC-004 - a poll that is told what answered sends no probe, and a probe-only job sends no
/// walk; the switch-shaped agent gives forwarding, port, VLAN and LLDP rows.
#[test]
fn dsc_004_worker_probe_then_poll_a_switch_shaped_agent() {
    let fake = fake_snmpd::start(SWITCH_WALK, b"ttcomm");
    let mut w = snmp_worker();
    let probe = snmp_job(
        1,
        "snmp_probe",
        "sw1",
        fake.addr.port(),
        b"ttcomm",
        &["bridge", "lldp"],
    );
    let (rows, result) = run_snmp_job(&mut w, &probe, Duration::from_secs(30)).expect("a result");
    assert_eq!(result["ok"], true, "{result}");
    assert!(rows.is_empty(), "a probe reads no table");
    let probed = fake.arrivals.lock().unwrap().len();
    assert!(
        probed <= 8,
        "one GETNEXT per root and a GET of sysObjectID: {probed}"
    );
    let choices = result["snmp"]["capability"]["choices"].clone();
    let mut poll = snmp_job(
        2,
        "snmp_poll",
        "sw1",
        fake.addr.port(),
        b"ttcomm",
        &["bridge", "lldp"],
    );
    poll["snmp"]["known"] = choices;
    let (rows, result) = run_snmp_job(&mut w, &poll, Duration::from_secs(60)).expect("a result");
    assert_eq!(result["ok"], true, "{result}");
    assert!(
        result["snmp"]["capability"].is_null(),
        "no probe when the capabilities are given"
    );
    let count = |k: &str| rows.iter().filter(|r| r["k"] == k).count();
    assert_eq!(count("fdb"), 20);
    assert_eq!(count("port_if"), 24);
    assert_eq!(count("vlan_fdb"), 3);
    assert_eq!(count("lldp"), 3);
    assert_eq!(count("lldp_loc"), 24);
}

/// REQ: DSC-004 - an agent that does not answer ends the poll after three timeouts in a row, with
/// the reason, and the worker carries on (the next job is answered).
#[test]
fn dsc_004_worker_unanswered_agent_ends_after_three_timeouts() {
    // The right address, the wrong community: the fake drops every request.
    let fake = fake_snmpd::start(GATEWAY_WALK, b"other-community");
    let mut w = snmp_worker();
    let job = snmp_job(
        1,
        "snmp_poll",
        "gateway",
        fake.addr.port(),
        b"ttcomm",
        &["arp"],
    );
    let (rows, result) = run_snmp_job(&mut w, &job, Duration::from_secs(60)).expect("a result");
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"], "three timeouts in a row");
    assert_eq!(result["snmp"]["timeouts"], 3);
    assert!(rows.is_empty());
    // Every request of the three exchanges is retried twice: nine datagrams reached the fake.
    assert_eq!(*fake.datagrams.lock().unwrap(), 9);
    w.send(&json_frame(&json!({"t": "job", "id": 2, "op": "ping"})));
    assert_eq!(w.next(Duration::from_secs(10)).expect("ping")["ok"], true);
}

/// REQ: DSC-007 (`dsc_007_import_worker_gets_no_credentials`) - the import worker runs no SNMP job: it
/// refuses `snmp_poll` and `snmp_probe` as unknown ops without reading the request, and sends no
/// packet. The credential travels in the job only, never in the arguments of the SNMP worker.
#[test]
fn dsc_007_import_worker_gets_no_credentials() {
    let fake = fake_snmpd::start(GATEWAY_WALK, b"ttcomm");
    let build = worker_build();
    let mut w = Worker::start(&["discovery-worker", "--import"]);
    w.send(&json_frame(&Worker::hello(64, &build)));
    let hello = w.next(Duration::from_secs(10)).expect("hello reply");
    assert_eq!(hello["mode"], "import");
    for (id, op) in [(1u64, "snmp_poll"), (2, "snmp_probe")] {
        let job = snmp_job(id, op, "gateway", fake.addr.port(), b"ttcomm", &["arp"]);
        let (rows, result) =
            run_snmp_job(&mut w, &job, Duration::from_secs(10)).expect("a refusal");
        assert_eq!(
            (result["ok"].as_bool(), result["error"].as_str()),
            (Some(false), Some("unknown op"))
        );
        assert!(rows.is_empty());
    }
    assert_eq!(
        *fake.datagrams.lock().unwrap(),
        0,
        "no packet left the import worker"
    );
}

/// REQ: DSC-007 - the credential reaches the SNMP worker over stdin only: the process's arguments
/// hold none, and nothing the worker writes back (rows, results, hello) contains it, in text or hex.
#[cfg(target_os = "linux")]
#[test]
fn dsc_007_credentials_travel_over_stdin_only() {
    let secret: &'static [u8] = b"planted-community-7f3a9c";
    let fake = fake_snmpd::start(SWITCH_WALK, secret);
    let mut w = snmp_worker();
    let cmdline = std::fs::read(format!("/proc/{}/cmdline", w.child.id())).unwrap_or_default();
    let cmdline = String::from_utf8_lossy(&cmdline).to_string();
    let job = snmp_job(1, "snmp_poll", "sw1", fake.addr.port(), secret, &["bridge"]);
    let (rows, result) = run_snmp_job(&mut w, &job, Duration::from_secs(60)).expect("a result");
    assert_eq!(result["ok"], true, "{result}");
    let everything = format!("{cmdline}{rows:?}{result}");
    assert!(!everything.contains("planted-community"), "{everything}");
    assert!(!everything.contains(&hex(secret)), "the hex form either");
    assert!(cmdline.contains("discovery-worker") && !cmdline.contains("planted"));
}

/// REQ: DSC-004 - an SNMP job without a request, and one whose protocol is refused, are answered
/// `ok: false` with a reason, and the loop goes on.
#[test]
fn dsc_004_worker_refuses_a_bad_snmp_job() {
    let mut w = snmp_worker();
    w.send(&json_frame(
        &json!({"t": "job", "id": 1, "op": "snmp_poll"}),
    ));
    let r = w.next(Duration::from_secs(10)).expect("an answer");
    assert_eq!(r["ok"], false);
    assert!(
        r["error"].as_str().unwrap().contains("without a request"),
        "{r}"
    );
    let job = json!({
        "t": "job", "id": 2, "op": "snmp_probe",
        "snmp": {"agent": "x", "address": "127.0.0.1", "port": 9,
            "auth": {"version": "v3", "user": "u", "auth_protocol": "md5",
                     "auth_password": hex(b"a-long-password")},
            "tables": ["arp"], "max_repetitions": 10}
    });
    let (_, r) = run_snmp_job(&mut w, &job, Duration::from_secs(10)).expect("an answer");
    assert_eq!(r["ok"], false);
    assert!(
        r["error"].as_str().unwrap().contains("MD5 is refused"),
        "{r}"
    );
    w.send(&json_frame(&json!({"t": "job", "id": 3, "op": "ping"})));
    assert_eq!(w.next(Duration::from_secs(10)).expect("ping")["ok"], true);
}

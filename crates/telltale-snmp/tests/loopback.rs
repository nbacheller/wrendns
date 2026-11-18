//! REQ: DSC-003 — the client against fake agents on the loopback address. The fakes answer
//! v2c, and v3 with authNoPriv and authPriv, and they can send the replies a hostile or
//! rebooted agent would: a reply from another address, a reply in the wrong community, an
//! authenticated time-window Report, a reboot, and stale boots. No real device is used.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines
)]

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use telltale_snmp::agent::{Agent, AgentError, Security, Timing};
use telltale_snmp::ber;
use telltale_snmp::oid::Oid;
use telltale_snmp::pdu::{self, RequestKind, TAG_REPORT, TAG_RESPONSE, Value, VarBind};
use telltale_snmp::secret::SecretValue;
use telltale_snmp::usm::{self, AuthProto, Outgoing, PrivProto, UsmError, UsmUser};
use telltale_snmp::v2c;

const ENGINE: [u8; 13] = [
    0x80, 0x00, 0x00, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
];
const SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";

fn oid(s: &str) -> Oid {
    Oid::parse(s).unwrap_or_else(|| panic!("oid {s}"))
}

fn timing() -> Timing {
    Timing {
        timeout: Duration::from_millis(400),
        retries: 2,
    }
}

fn v3_user(priv_on: bool) -> UsmUser {
    UsmUser {
        name: b"ttuser".to_vec(),
        auth: Some((
            AuthProto::Sha256,
            SecretValue::new(b"authpass-1234".to_vec()),
        )),
        privacy: priv_on.then(|| {
            (
                PrivProto::Aes128,
                SecretValue::new(b"privpass-1234".to_vec()),
            )
        }),
    }
}

/// The request ID and the OIDs of a GET, GETNEXT or GETBULK PDU.
fn request_parts(pdu_tlv: ber::Tlv<'_>) -> Option<(i32, Vec<Oid>)> {
    if !matches!(pdu_tlv.tag, 0xa0 | 0xa1 | 0xa5) {
        return None;
    }
    let kids = ber::children(pdu_tlv.content, 2, 4).ok()?;
    let id = i32::try_from(ber::integer_value(kids.first()?.content).ok()?).ok()?;
    let vbs = pdu::decode_varbinds(kids.get(3)?.content).ok()?;
    Some((id, vbs.into_iter().map(|v| v.oid).collect()))
}

/// The answer to a request: sysName reads a string, anything else reads endOfMibView.
fn answer(oids: &[Oid]) -> Vec<VarBind> {
    oids.iter()
        .map(|o| {
            let value = if o.to_string() == SYS_NAME {
                Value::OctetString(b"tt-fake".to_vec())
            } else {
                Value::EndOfMibView
            };
            VarBind {
                oid: o.clone(),
                value,
            }
        })
        .collect()
}

/// Starts a fake v2c agent that answers every request with `community`. Returns its address.
fn fake_v2c(community: &'static [u8], stop: Arc<AtomicBool>) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let addr = sock.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let _ = sock.set_read_timeout(Some(Duration::from_millis(50)));
    thread::spawn(move || {
        let mut buf = vec![0u8; 65_536];
        while !stop.load(Ordering::Relaxed) {
            let Ok((n, from)) = sock.recv_from(&mut buf) else {
                continue;
            };
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
            let Some((id, oids)) = request_parts(*p) else {
                continue;
            };
            if c.content != community {
                continue;
            }
            let Ok(reply_pdu) = pdu::encode_response(TAG_RESPONSE, id, 0, &answer(&oids)) else {
                continue;
            };
            let _ = sock.send_to(&v2c::encode(community, &reply_pdu), from);
        }
    });
    addr
}

/// What the fake v3 agent does with its next authenticated request.
#[derive(Clone, Copy)]
enum Mode {
    /// Answer normally at the agent's boots and time.
    Normal,
    /// Send one authenticated Report with usmStatsNotInTimeWindows at the given boots and time,
    /// then answer normally.
    TimeReportOnce { boots: u32, time: u32 },
    /// After the time Report: answer only requests whose boots and time are inside the window.
    InWindowOnly,
    /// Drop every authenticated request (a transient outage); discovery still answers.
    Silent,
}

struct FakeV3 {
    boots: u32,
    time: u32,
    mode: Mode,
    /// Boots and time the discovery Report carries, when they differ from the real clock
    /// (RFC 3414 section 4 lets an agent send 0 and 0 there).
    discovery_clock: Option<(u32, u32)>,
}

/// Starts a fake v3 agent. `state` is shared so a test can change the boots while it runs.
fn fake_v3(
    priv_on: bool,
    state: Arc<std::sync::Mutex<FakeV3>>,
    stop: Arc<AtomicBool>,
) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let addr = sock.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let _ = sock.set_read_timeout(Some(Duration::from_millis(50)));
    thread::spawn(move || {
        let keys = v3_user(priv_on)
            .derive()
            .unwrap_or_else(|e| panic!("{e:?}"));
        // The same authentication key without privacy: a time-window Report is authNoPriv (RFC 3414
        // §3.2.7a), even when the request was authPriv.
        let auth_keys = v3_user(false).derive().unwrap_or_else(|e| panic!("{e:?}"));
        let mut buf = vec![0u8; 65_536];
        while !stop.load(Ordering::Relaxed) {
            let Ok((n, from)) = sock.recv_from(&mut buf) else {
                continue;
            };
            let Some(msg) = buf.get(..n) else { continue };
            let Ok(reply) = usm::parse(msg) else { continue };
            let (boots, time, mode) = match state.lock() {
                Ok(s) => (s.boots, s.time, s.mode),
                Err(_) => continue,
            };
            // After the time Report, an agent answers only requests inside its own window, so a
            // client that did not take the agent's clock gets no answer (RFC 3414 §3.2.7b).
            if matches!(mode, Mode::InWindowOnly)
                && (reply.boots != boots || reply.time.abs_diff(time) > 150)
            {
                continue;
            }
            if matches!(mode, Mode::Silent) && reply.flags & usm::LEVEL_MASK != 0 {
                continue;
            }
            if reply.flags & usm::LEVEL_MASK == 0 {
                // Engine discovery: a noAuthNoPriv Report that names the engine.
                let Ok(scoped_in) = ber::expect_tag(&reply.scoped, 0x30) else {
                    continue;
                };
                let Ok(kids) = ber::children(scoped_in.content, 1, 3) else {
                    continue;
                };
                let Some(pdu_in) = kids.get(2) else { continue };
                let Some((id, _)) = request_parts(*pdu_in) else {
                    continue;
                };
                let vbs = vec![VarBind {
                    oid: oid(usm::USM_STATS_UNKNOWN_ENGINE_ID),
                    value: Value::Integer(0),
                }];
                let Ok(pdu_out) = pdu::encode_response(TAG_REPORT, id, 0, &vbs) else {
                    continue;
                };
                let (d_boots, d_time) = state
                    .lock()
                    .ok()
                    .and_then(|s| s.discovery_clock)
                    .unwrap_or((boots, time));
                let out = Outgoing {
                    msg_id: reply.msg_id,
                    engine_id: &ENGINE,
                    boots: d_boots,
                    time: d_time,
                    user: &[],
                    reportable: true,
                };
                if let Ok(m) = usm::encode(&out, None, &scoped_response(&ENGINE, &pdu_out)) {
                    let _ = sock.send_to(&m, from);
                }
                continue;
            }
            if usm::verify(msg, &reply, &keys).is_err() {
                continue;
            }
            let plain = if reply.flags & 0x02 != 0 {
                match usm::decrypt(&reply, &keys) {
                    Ok(p) => p,
                    Err(_) => continue,
                }
            } else {
                reply.scoped.clone()
            };
            let Ok(scoped_in) = ber::expect_tag(&plain, 0x30) else {
                continue;
            };
            let Ok(kids) = ber::children(scoped_in.content, 1, 3) else {
                continue;
            };
            let Some(pdu_in) = kids.get(2) else { continue };
            let Some((id, oids)) = request_parts(*pdu_in) else {
                continue;
            };
            if let Mode::TimeReportOnce {
                boots: rb,
                time: rt,
            } = mode
            {
                if let Ok(mut s) = state.lock() {
                    // The agent's clock is the one its Report carried from now on.
                    s.mode = Mode::InWindowOnly;
                    s.boots = rb;
                    s.time = rt;
                }
                let vbs = vec![VarBind {
                    oid: oid(usm::USM_STATS_NOT_IN_TIME_WINDOW),
                    value: Value::Counter32(1),
                }];
                // The agent refuses the time before it decrypts, so its Report carries request ID 0
                // when the request was authPriv.
                let rid = if priv_on { 0 } else { id };
                if let Ok(pdu_out) = pdu::encode_response(TAG_REPORT, rid, 0, &vbs) {
                    let out = Outgoing {
                        msg_id: reply.msg_id,
                        engine_id: &ENGINE,
                        boots: rb,
                        time: rt,
                        user: b"ttuser",
                        reportable: false,
                    };
                    if let Ok(m) =
                        usm::encode(&out, Some(&auth_keys), &scoped_response(&ENGINE, &pdu_out))
                    {
                        let _ = sock.send_to(&m, from);
                    }
                }
                continue;
            }
            let Ok(pdu_out) = pdu::encode_response(TAG_RESPONSE, id, 0, &answer(&oids)) else {
                continue;
            };
            let out = Outgoing {
                msg_id: reply.msg_id,
                engine_id: &ENGINE,
                boots,
                time,
                user: b"ttuser",
                reportable: false,
            };
            if let Ok(m) = usm::encode(&out, Some(&keys), &scoped_response(&ENGINE, &pdu_out)) {
                let _ = sock.send_to(&m, from);
            }
        }
    });
    addr
}

/// A `ScopedPDU` around a response PDU.
fn scoped_response(engine: &[u8], pdu_bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(ber::octets(engine));
    body.extend(ber::octets(&[]));
    body.extend_from_slice(pdu_bytes);
    ber::sequence(&body)
}

fn state(boots: u32, time: u32, mode: Mode) -> Arc<std::sync::Mutex<FakeV3>> {
    Arc::new(std::sync::Mutex::new(FakeV3 {
        boots,
        time,
        mode,
        discovery_clock: None,
    }))
}

fn sys_name(resp: &telltale_snmp::pdu::Response) -> Option<Vec<u8>> {
    match resp.varbinds.first()?.value {
        Value::OctetString(ref b) => Some(b.clone()),
        _ => None,
    }
}

#[test]
fn dsc_003_v2c_get_round_trip() {
    let stop = Arc::new(AtomicBool::new(false));
    let addr = fake_v2c(b"ttcomm", stop.clone());
    let mut agent = Agent::new(
        addr,
        Security::V2c {
            community: SecretValue::new(b"ttcomm".to_vec()),
        },
        timing(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let resp = agent
        .request(RequestKind::Get, &[oid(SYS_NAME)], 0)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(sys_name(&resp).as_deref(), Some(&b"tt-fake"[..]));
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn dsc_003_v2c_wrong_community_is_dropped() {
    let stop = Arc::new(AtomicBool::new(false));
    let addr = fake_v2c(b"ttcomm", stop.clone());
    let mut agent = Agent::new(
        addr,
        Security::V2c {
            community: SecretValue::new(b"wrong".to_vec()),
        },
        timing(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let got = agent.request(RequestKind::Get, &[oid(SYS_NAME)], 0);
    assert!(matches!(got, Err(AgentError::Timeout)), "{got:?}");
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn dsc_003_reply_from_other_address_dropped() {
    // A forged reply from a second socket, sent before the real one, must not be the answer.
    let real = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let forger = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let real_addr = real.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let _ = real.set_read_timeout(Some(Duration::from_secs(3)));
    let server = thread::spawn(move || {
        let mut buf = vec![0u8; 4096];
        let Ok((n, client)) = real.recv_from(&mut buf) else {
            return;
        };
        let Some(msg) = buf.get(..n) else { return };
        let Ok(tlv) = ber::read_message(msg) else {
            return;
        };
        let Ok(kids) = ber::children(tlv.content, 0, 3) else {
            return;
        };
        let [_v, _c, p] = kids.as_slice() else { return };
        let Some((id, oids)) = request_parts(*p) else {
            return;
        };
        let bogus = VarBind {
            oid: oid(SYS_NAME),
            value: Value::OctetString(b"forged".to_vec()),
        };
        if let Ok(bad) = pdu::encode_response(TAG_RESPONSE, id, 0, std::slice::from_ref(&bogus)) {
            let _ = forger.send_to(&v2c::encode(b"ttcomm", &bad), client);
        }
        if let Ok(good) = pdu::encode_response(TAG_RESPONSE, id, 0, &answer(&oids)) {
            let _ = real.send_to(&v2c::encode(b"ttcomm", &good), client);
        }
    });
    let mut agent = Agent::new(
        real_addr,
        Security::V2c {
            community: SecretValue::new(b"ttcomm".to_vec()),
        },
        timing(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let resp = agent
        .request(RequestKind::Get, &[oid(SYS_NAME)], 0)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(sys_name(&resp).as_deref(), Some(&b"tt-fake"[..]));
    let _ = server.join();
}

fn v3_round_trip(priv_on: bool) {
    let stop = Arc::new(AtomicBool::new(false));
    let st = state(5, 1000, Mode::Normal);
    let addr = fake_v3(priv_on, st.clone(), stop.clone());
    let mut agent = Agent::new(
        addr,
        Security::V3 {
            user: v3_user(priv_on),
        },
        timing(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let resp = agent
        .request(RequestKind::Get, &[oid(SYS_NAME)], 0)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(sys_name(&resp).as_deref(), Some(&b"tt-fake"[..]));
    agent.end_round();
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn dsc_003_v3_auth_no_priv_round_trip() {
    v3_round_trip(false);
}

#[test]
fn dsc_003_v3_auth_priv_round_trip() {
    v3_round_trip(true);
}

#[test]
fn dsc_003_v3_reboot_is_accepted() {
    // The agent reboots (boots 5 to 6) between requests: an authenticated reply with higher
    // boots moves the clock, and the request still succeeds.
    let stop = Arc::new(AtomicBool::new(false));
    let st = state(5, 1000, Mode::Normal);
    let addr = fake_v3(false, st.clone(), stop.clone());
    let mut agent = Agent::new(
        addr,
        Security::V3 {
            user: v3_user(false),
        },
        timing(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let first = agent.request(RequestKind::Get, &[oid(SYS_NAME)], 0);
    assert!(first.is_ok(), "{first:?}");
    if let Ok(mut s) = st.lock() {
        s.boots = 6;
        s.time = 3;
    }
    let second = agent.request(RequestKind::Get, &[oid(SYS_NAME)], 0);
    assert!(second.is_ok(), "{second:?}");
    assert_eq!(agent.engine().map(|e| e.boots), Some(6));
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn dsc_003_v3_stale_boots_are_refused() {
    // Boots that go backwards are not in the window (RFC 3414 §3.2.7b).
    let stop = Arc::new(AtomicBool::new(false));
    let st = state(5, 1000, Mode::Normal);
    let addr = fake_v3(false, st.clone(), stop.clone());
    let mut agent = Agent::new(
        addr,
        Security::V3 {
            user: v3_user(false),
        },
        timing(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(agent.request(RequestKind::Get, &[oid(SYS_NAME)], 0).is_ok());
    if let Ok(mut s) = st.lock() {
        s.boots = 4;
    }
    let got = agent.request(RequestKind::Get, &[oid(SYS_NAME)], 0);
    assert!(
        matches!(got, Err(AgentError::Usm(UsmError::NotInTimeWindow))),
        "{got:?}"
    );
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn dsc_003_authenticated_time_report_never_moves_the_clock_back() {
    // An authenticated notInTimeWindow Report with lower boots is refused and the cached
    // clock stays (RFC 3414 §3.2.7b).
    let stop = Arc::new(AtomicBool::new(false));
    let st = state(
        5,
        1000,
        Mode::TimeReportOnce {
            boots: 4,
            time: 1200,
        },
    );
    let addr = fake_v3(false, st.clone(), stop.clone());
    let mut agent = Agent::new(
        addr,
        Security::V3 {
            user: v3_user(false),
        },
        timing(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let got = agent.request(RequestKind::Get, &[oid(SYS_NAME)], 0);
    assert!(
        matches!(got, Err(AgentError::Usm(UsmError::NotInTimeWindow))),
        "{got:?}"
    );
    // A failed exchange drops the cached engine; it is never the Report's older clock.
    assert_ne!(agent.engine().map(|e| e.boots), Some(4));
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn dsc_003_authenticated_time_report_resends_once() {
    time_report_resends_once(false);
}

#[test]
fn dsc_003_authenticated_time_report_resends_once_authpriv() {
    // An authPriv request gets its time-window Report at authNoPriv, with request ID 0 (RFC 3414
    // §3.2.7a). The Report still resyncs the clock, and the request is sent again.
    time_report_resends_once(true);
}

/// An authenticated notInTimeWindow Report takes the agent's clock, and the request is sent
/// again: the second attempt is answered.
fn time_report_resends_once(priv_on: bool) {
    let stop = Arc::new(AtomicBool::new(false));
    let st = state(
        5,
        1000,
        Mode::TimeReportOnce {
            boots: 5,
            time: 1200,
        },
    );
    let addr = fake_v3(priv_on, st.clone(), stop.clone());
    let mut agent = Agent::new(
        addr,
        Security::V3 {
            user: v3_user(priv_on),
        },
        timing(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let resp = agent
        .request(RequestKind::Get, &[oid(SYS_NAME)], 0)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(sys_name(&resp).as_deref(), Some(&b"tt-fake"[..]));
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn dsc_003_v3_user_without_auth_is_refused() {
    let user = UsmUser {
        name: b"ttuser".to_vec(),
        auth: None,
        privacy: None,
    };
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap_or_else(|_| panic!("addr"));
    let got = Agent::new(addr, Security::V3 { user }, timing());
    assert!(matches!(got, Err(AgentError::BadRequest)));
}

#[test]
fn dsc_003_rediscovery_behind_the_trusted_clock_still_recovers() {
    // The agent reports 0 and 0 in its discovery Report but real boots and time in
    // authenticated replies. After one timeout the engine is rediscovered; that clock is
    // behind the trusted one, so the agent keeps the trusted clock instead of being locked out.
    let stop = Arc::new(AtomicBool::new(false));
    let st = state(5, 1000, Mode::Normal);
    if let Ok(mut s) = st.lock() {
        s.discovery_clock = Some((0, 0));
    }
    let addr = fake_v3(false, st.clone(), stop.clone());
    let mut agent = Agent::new(
        addr,
        Security::V3 {
            user: v3_user(false),
        },
        timing(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let first = agent.request(RequestKind::Get, &[oid(SYS_NAME)], 0);
    assert!(first.is_ok(), "{first:?}");
    if let Ok(mut s) = st.lock() {
        s.mode = Mode::Silent;
    }
    let second = agent.request(RequestKind::Get, &[oid(SYS_NAME)], 0);
    assert!(matches!(second, Err(AgentError::Timeout)), "{second:?}");
    if let Ok(mut s) = st.lock() {
        s.mode = Mode::Normal;
    }
    let third = agent.request(RequestKind::Get, &[oid(SYS_NAME)], 0);
    assert!(third.is_ok(), "{third:?}");
    // The clock never went back to the discovery Report's 0.
    assert_eq!(agent.engine().map(|e| e.boots), Some(5));
    stop.store(true, Ordering::Relaxed);
}

/// The agent's clock runs behind the client's estimate by more than the 150 s window (a slow
/// clock or a paused VM). The estimate is aged by 400 s; the agent still reports `agent_time`.
fn slow_agent(agent_time: u32) -> (Result<(), AgentError>, Option<u32>) {
    let stop = Arc::new(AtomicBool::new(false));
    let st = state(
        5,
        1000,
        Mode::TimeReportOnce {
            boots: 5,
            time: agent_time,
        },
    );
    // The first request is answered normally; the Report is armed after it.
    if let Ok(mut s) = st.lock() {
        s.mode = Mode::Normal;
    }
    let addr = fake_v3(false, st.clone(), stop.clone());
    let mut agent = Agent::new(
        addr,
        Security::V3 {
            user: v3_user(false),
        },
        timing(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(agent.request(RequestKind::Get, &[oid(SYS_NAME)], 0).is_ok());
    agent.age_engine_estimate(Duration::from_secs(400));
    if let Ok(mut s) = st.lock() {
        s.mode = Mode::TimeReportOnce {
            boots: 5,
            time: agent_time,
        };
    }
    let got = agent
        .request(RequestKind::Get, &[oid(SYS_NAME)], 0)
        .map(|_| ());
    let time = agent.engine().map(|e| e.time);
    stop.store(true, Ordering::Relaxed);
    (got, time)
}

#[test]
fn dsc_003_agent_clock_behind_the_estimate_recovers() {
    // Last authenticated time was 1000; the agent is at 1010, the estimate at about 1400. The
    // authenticated Report is later than the last authenticated value, so the clock is taken
    // and the request is answered.
    let (got, time) = slow_agent(1010);
    assert!(got.is_ok(), "{got:?}");
    assert!(time.is_some_and(|t| t >= 1010), "{time:?}");
}

#[test]
fn dsc_003_agent_clock_never_goes_back_past_the_last_authenticated_value() {
    // The agent reports 990, older than the 1000 already received: refused, and the cached
    // clock is not that value.
    let (got, time) = slow_agent(990);
    assert!(
        matches!(got, Err(AgentError::Usm(UsmError::NotInTimeWindow))),
        "{got:?}"
    );
    assert!(time.is_none_or(|t| t >= 1000), "{time:?}");
}

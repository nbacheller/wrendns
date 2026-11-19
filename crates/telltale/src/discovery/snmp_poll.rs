//! REQ: DSC-004 (T25.6, ADR-908, ADR-1001) — one poll of one SNMP agent, in the discovery worker:
//! probe which tables answer (one GETNEXT on each root, never assumed), then walk the answering
//! tables within the caps (5,000 rows and 30 s per walk, at least 50 ms between requests, so at most
//! 20 a second; three timeouts in a row end the poll; the whole poll is capped too) and parse what
//! came back into typed rows.
//!
//! The poll takes its agent and its clock through traits, so the pacing and the caps are tested with
//! a virtual clock and recorded walks, and no packet leaves the test process.

use std::time::Duration;

use telltale_config::SnmpTable;
use telltale_snmp::agent::{Agent, AgentError, Security, Timing};
use telltale_snmp::oid::Oid;
use telltale_snmp::pdu::{RequestKind, Response, Value};
use telltale_snmp::secret::SecretValue;
use telltale_snmp::usm::{AuthProto, PrivProto, UsmUser};
use telltale_snmp::walk::{self, Bulk, Limits, MIN_GAP, Pacer, Stop, SystemPacer, WalkError};

use super::snmp_job::{
    AuthSpec, Capability, Choice, MAX_ROWS_PER_JOB, POLL_TIME_CAP_SECS, SnmpRequest, SnmpResult,
    WalkStat, error_text,
};
use super::snmp_tables::{self, AltId, PartDef, Row, SYS_OBJECT_ID, parts_of};

/// Consecutive timeouts that end a poll (ADR-908: a walk stops after 3 timeouts in a row).
pub(crate) const TIMEOUTS_IN_A_ROW: u32 = 3;

/// What a poll needs from an agent besides the walker's GETBULK: a GETNEXT and a GET (for the
/// capability probe), the round's key handling, and what the capability record shows.
pub(crate) trait Source: Bulk {
    /// One GETNEXT: the first object after `oid`.
    fn first_after(&mut self, oid: &Oid) -> Result<Response, AgentError>;
    /// One GET.
    fn get_one(&mut self, oid: &Oid) -> Result<Response, AgentError>;
    /// Starts a round (derives the v3 keys once).
    fn begin(&mut self) -> Result<(), AgentError> {
        Ok(())
    }
    /// Ends the round (drops the keys).
    fn end(&mut self) {}
    /// `v2c`, `authNoPriv` or `authPriv`.
    fn level(&self) -> String;
    /// The v3 engine ID in hex, once discovered.
    fn engine_id(&self) -> Option<String> {
        None
    }
}

impl Source for Agent {
    fn first_after(&mut self, oid: &Oid) -> Result<Response, AgentError> {
        self.request(RequestKind::GetNext, std::slice::from_ref(oid), 0)
    }

    fn get_one(&mut self, oid: &Oid) -> Result<Response, AgentError> {
        self.request(RequestKind::Get, std::slice::from_ref(oid), 0)
    }

    fn begin(&mut self) -> Result<(), AgentError> {
        self.begin_round()
    }

    fn end(&mut self) {
        self.end_round();
    }

    fn level(&self) -> String {
        Agent::level(self).to_owned()
    }

    fn engine_id(&self) -> Option<String> {
        self.engine().map(|e| hex(&e.id))
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// What a poll produced: the answer, and the rows that go in `rows` messages before it.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    pub(crate) result: SnmpResult,
    pub(crate) rows: Vec<Row>,
}

/// The poll's running state.
struct Run<'a, S: Source, P: Pacer> {
    src: &'a mut S,
    pacer: &'a mut P,
    start: std::time::Instant,
    requests: u32,
    timeouts: u32,
    in_a_row: u32,
    aborted: Option<String>,
    engine: Option<String>,
    /// Bytes of varbinds kept so far in this poll.
    bytes: usize,
}

impl<S: Source, P: Pacer> Run<'_, S, P> {
    /// The gap before a request that isn't the poll's first (ADR-908: at least 50 ms).
    fn gap(&mut self) {
        if self.requests > 0 {
            self.pacer.pause(MIN_GAP);
        }
    }

    /// Whether the poll must stop before another request.
    fn over(&mut self) -> bool {
        if self.aborted.is_some() {
            return true;
        }
        if self.pacer.now().saturating_duration_since(self.start)
            >= Duration::from_secs(POLL_TIME_CAP_SECS)
        {
            self.aborted = Some("the poll's time cap was reached".to_owned());
            return true;
        }
        false
    }

    /// Notes the outcome of one exchange: a timeout counts, three in a row end the poll.
    fn exchange<T>(&mut self, r: &Result<T, AgentError>) {
        match r {
            Err(AgentError::Timeout) => {
                self.timeouts = self.timeouts.saturating_add(1);
                self.in_a_row = self.in_a_row.saturating_add(1);
                if self.in_a_row >= TIMEOUTS_IN_A_ROW {
                    self.aborted = Some("three timeouts in a row".to_owned());
                }
            }
            Ok(_) => {
                self.in_a_row = 0;
                if self.engine.is_none() {
                    self.engine = self.src.engine_id();
                }
            }
            // REQ: DSC-004 - a refused credential (a USM Report), an unknown user or an undecodable
            // reply is the whole agent failing, not one table not answering: end the poll.
            Err(e) if credential_failure(e) => {
                self.aborted.get_or_insert_with(|| error_text(e));
            }
            Err(_) => {}
        }
    }

    /// One GETNEXT on `root`: whether the table answers (a row under the root).
    fn answers(&mut self, root: &Oid) -> Result<bool, String> {
        self.gap();
        let r = self.src.first_after(root);
        self.requests = self.requests.saturating_add(1);
        self.exchange(&r);
        match r {
            Ok(resp) => Ok(resp.error_status == 0
                && resp.varbinds.first().is_some_and(|vb| {
                    vb.oid.starts_with(root)
                        && !matches!(
                            vb.value,
                            Value::EndOfMibView | Value::NoSuchObject | Value::NoSuchInstance
                        )
                })),
            Err(AgentError::Status(_)) => Ok(false),
            Err(e) => Err(error_text(&e)),
        }
    }
}

/// Whether an error says the agent can't be read at all (wrong v3 credential, no engine, garbage),
/// as opposed to one table not answering.
fn credential_failure(e: &AgentError) -> bool {
    matches!(
        e,
        AgentError::ReportRefused
            | AgentError::Usm(_)
            | AgentError::NoEngine
            | AgentError::Decode(_)
    )
}

fn parse_root(text: &str) -> Option<Oid> {
    Oid::parse(text)
}

/// The most bytes of varbinds one poll keeps across its walks (ADR-908, bounded memory).
const POLL_BYTE_CAP: usize = 16 * 1024 * 1024;

/// The caps of one walk (ADR-908): 5,000 rows, 30 s, 4 MiB and a gap of 50 ms.
fn limits(max_repetitions: u32) -> Limits {
    Limits {
        max_repetitions: max_repetitions.clamp(5, 25),
        gap: MIN_GAP,
        ..Limits::default()
    }
}

/// REQ: DSC-004 — probes every requested table: for each part, the first alternative whose first
/// root answers one GETNEXT. `vlans` is probed only when the forwarding table is the Q-BRIDGE one
/// (the FDB IDs it maps are Q-BRIDGE's).
fn probe<S: Source, P: Pacer>(run: &mut Run<'_, S, P>, tables: &[SnmpTable]) -> Vec<Choice> {
    let mut choices: Vec<Choice> = Vec::new();
    for table in tables {
        for part in parts_of(*table) {
            if part.part == "vlans"
                && !choices
                    .iter()
                    .any(|c| c.part == "forwarding" && c.alt.as_deref() == Some(AltId::FdbQ.name()))
            {
                choices.push(Choice {
                    part: part.part.to_owned(),
                    alt: None,
                });
                continue;
            }
            let mut found: Option<&'static str> = None;
            for alt in part.alts {
                if run.over() {
                    break;
                }
                let Some(root) = alt.columns().first().and_then(|t| parse_root(t)) else {
                    continue;
                };
                if matches!(run.answers(&root), Ok(true)) {
                    found = Some(alt.name());
                    break;
                }
            }
            choices.push(Choice {
                part: part.part.to_owned(),
                alt: found.map(str::to_owned),
            });
        }
    }
    choices
}

/// sysObjectID, one GET (the capability record shows it).
fn sys_object_id<S: Source, P: Pacer>(run: &mut Run<'_, S, P>) -> Option<String> {
    let oid = Oid::parse(SYS_OBJECT_ID)?;
    if run.over() {
        return None;
    }
    run.gap();
    let r = run.src.get_one(&oid);
    run.requests = run.requests.saturating_add(1);
    run.exchange(&r);
    match r.ok()?.varbinds.into_iter().next()?.value {
        Value::Oid(o) => Some(o.to_string()),
        _ => None,
    }
}

/// Walks every column of one alternative and parses the result.
fn walk_alt<S: Source, P: Pacer>(
    run: &mut Run<'_, S, P>,
    part: &PartDef,
    alt: AltId,
    req: &SnmpRequest,
    out: &mut Outcome,
) {
    let mut lim = limits(req.max_repetitions);
    let mut columns: Vec<Vec<telltale_snmp::pdu::VarBind>> = Vec::new();
    let mut stop_label = "end";
    let mut total = 0u32;
    let mut error: Option<String> = None;
    for text in alt.columns() {
        if run.over() {
            break;
        }
        let Some(root) = parse_root(text) else {
            columns.push(Vec::new());
            continue;
        };
        lim.max_bytes = lim.max_bytes.min(POLL_BYTE_CAP.saturating_sub(run.bytes));
        run.gap();
        let w = walk::walk(&mut *run.src, &mut *run.pacer, &root, &lim);
        match w {
            Ok(walked) => {
                run.requests = run.requests.saturating_add(walked.requests);
                run.in_a_row = 0;
                run.bytes = run.bytes.saturating_add(walked.bytes);
                if run.bytes >= POLL_BYTE_CAP {
                    run.aborted
                        .get_or_insert_with(|| "the poll's byte cap was reached".to_owned());
                }
                total = total.saturating_add(u32::try_from(walked.rows.len()).unwrap_or(u32::MAX));
                match walked.stop {
                    Stop::EndOfView => {}
                    Stop::RowCap => stop_label = "row_cap",
                    Stop::TimeCap => stop_label = "time_cap",
                    Stop::ByteCap => stop_label = "byte_cap",
                }
                columns.push(walked.rows);
            }
            Err(WalkError::Agent(e)) => {
                // The walker doesn't say how many requests it sent before it failed: count one.
                run.requests = run.requests.saturating_add(1);
                error = Some(error_text(&e));
                if matches!(e, AgentError::Timeout) || credential_failure(&e) {
                    run.exchange::<()>(&Err(e));
                }
                stop_label = "error";
                columns.push(Vec::new());
                break;
            }
            Err(WalkError::NotIncreasing) => {
                error = Some("the agent's OIDs do not increase".to_owned());
                stop_label = "error";
                columns.push(Vec::new());
                break;
            }
        }
    }
    let parsed = snmp_tables::parse(alt, &columns);
    // The IPv6 entries counted are the ARP table's (the neighbour entries M25 leaves out); the agent's
    // own IPv6 addresses are not neighbours.
    if matches!(alt, AltId::ArpPhysical | AltId::ArpMedia) {
        out.result.ipv6_ignored = out.result.ipv6_ignored.saturating_add(parsed.ipv6_ignored);
    }
    out.result.skipped = out.result.skipped.saturating_add(parsed.skipped);
    let room = MAX_ROWS_PER_JOB.saturating_sub(out.rows.len());
    if parsed.rows.len() > room {
        out.result.aborted = Some("the job's row cap was reached".to_owned());
    }
    out.rows.extend(parsed.rows.into_iter().take(room));
    out.result.walks.push(WalkStat {
        part: part.part.to_owned(),
        alt: alt.name().to_owned(),
        rows: total,
        stop: stop_label.to_owned(),
        error,
    });
}

/// REQ: DSC-004 — runs one probe or poll. With `probe_only` only the capability record is made.
/// `known` in the request skips the probe of a poll; without it a poll probes first and returns
/// the record.
pub(crate) fn run<S: Source, P: Pacer>(
    src: &mut S,
    pacer: &mut P,
    req: &SnmpRequest,
    probe_only: bool,
) -> Outcome {
    let started = pacer.now();
    let mut out = Outcome::default();
    if let Err(e) = src.begin() {
        out.result.aborted = Some(error_text(&e));
        return out;
    }
    let mut r = Run {
        src,
        pacer,
        start: started,
        requests: 0,
        timeouts: 0,
        in_a_row: 0,
        aborted: None,
        engine: None,
        bytes: 0,
    };
    let choices = if let (Some(known), false) = (&req.known, probe_only) {
        known.clone()
    } else {
        let choices = probe(&mut r, &req.tables);
        let sys = sys_object_id(&mut r);
        out.result.capability = Some(Capability {
            level: r.src.level(),
            engine_id: r.engine.clone().or_else(|| r.src.engine_id()),
            sys_object_id: sys,
            choices: choices.clone(),
        });
        choices
    };
    if !probe_only {
        'tables: for table in &req.tables {
            for part in parts_of(*table) {
                if r.over() {
                    break 'tables;
                }
                let chosen = choices
                    .iter()
                    .find(|c| c.part == part.part)
                    .and_then(|c| c.alt.as_deref())
                    .and_then(AltId::from_name);
                match chosen {
                    Some(alt) => walk_alt(&mut r, part, alt, req, &mut out),
                    None => out.result.walks.push(WalkStat {
                        part: part.part.to_owned(),
                        alt: String::new(),
                        rows: 0,
                        stop: "skipped".to_owned(),
                        error: None,
                    }),
                }
            }
        }
    }
    r.src.end();
    out.result.requests = r.requests;
    out.result.timeouts = r.timeouts;
    out.result.aborted = out.result.aborted.take().or(r.aborted.take());
    out.result.elapsed_ms =
        u64::try_from(r.pacer.now().saturating_duration_since(started).as_millis())
            .unwrap_or(u64::MAX);
    out
}

/// REQ: DSC-004, DSC-003 — runs a job against a real agent: a connected UDP socket to the address
/// the main process checked, the credential from the job (never from a file or the environment),
/// and the real clock.
pub(crate) fn run_real(req: &SnmpRequest, probe_only: bool) -> Result<Outcome, String> {
    let security = match &req.auth {
        AuthSpec::V2c { community } => Security::V2c {
            community: SecretValue::new(community.expose().to_vec()),
        },
        AuthSpec::V3 {
            user,
            auth_protocol,
            auth_password,
            priv_protocol,
            priv_password,
        } => {
            let auth = AuthProto::parse(auth_protocol).map_err(|r| r.reason().to_owned())?;
            let privacy = match priv_protocol {
                Some(p) => {
                    let proto = PrivProto::parse(p).map_err(|r| r.reason().to_owned())?;
                    // The privacy password defaults to the authentication one (ADR-908).
                    let pw = priv_password.as_ref().unwrap_or(auth_password);
                    Some((proto, SecretValue::new(pw.expose().to_vec())))
                }
                None => None,
            };
            Security::V3 {
                user: UsmUser {
                    name: user.clone().into_bytes(),
                    auth: Some((auth, SecretValue::new(auth_password.expose().to_vec()))),
                    privacy,
                },
            }
        }
    };
    let target = std::net::SocketAddr::new(std::net::IpAddr::V4(req.address), req.port);
    // REQ: DSC-002, DSC-003 (ADR-1001) - the worker's seccomp filter refuses `bind`, so the socket is
    // made with `socket` and `connect` alone (the kernel picks the source port).
    let socket = telltale_net::worker::connected_udp_socket(target)
        .map_err(|e| format!("socket error ({:?})", e.kind()))?;
    let mut agent = Agent::with_socket(target, socket, security, Timing::default())
        .map_err(|e| error_text(&e))?;
    let mut pacer = SystemPacer;
    Ok(run(&mut agent, &mut pacer, req, probe_only))
}

#[cfg(test)]
#[path = "snmp_poll_tests.rs"]
mod tests;

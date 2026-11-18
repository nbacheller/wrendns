//! REQ: DSC-004, DSC-014 (T25.6, ADR-908, ADR-1001) — the infrastructure poller, the main process's
//! side. On the `telltale-inventory` thread's runtime it polls each `[[discovery.snmp_agent]]` in
//! turn: it checks the destination (ADR-907), reads the credential from its file (confined to
//! `[node] secret_file_dirs`), queues one `snmp_poll` job for the SNMP worker (credentials go over
//! its stdin pipe and nowhere else), turns the rows that come back into observations, and hands them
//! to the inventory. The worker does the packets; nothing here touches the network.
//!
//! The **Test** button shares the same board: it queues an `snmp_probe` and records the capability
//! record. A table the agent did not answer when probed is skipped until the next test.
//! Everything here runs off the DNS path, and a failure only shows on the board and in the logs.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use telltale_api::model::{
    AgentCapability, AgentCapabilityPart, DiscoveryAgent, DiscoveryAgentCounts,
    DiscoveryAgentTable, SnmpTestOid,
};
use telltale_config::{Config, CredentialRole, SnmpAgent, SnmpCredential, SnmpTable, SnmpVersion};
use telltale_snmp::creds::{self, CredError};
use telltale_snmp::dest;
use tokio::sync::{mpsc, oneshot};

use super::inventory::Observation;
use super::snmp_job::{
    AuthSpec, Capability, Choice, OP_POLL, Secret, SnmpRequest, SnmpResult, WalkStat,
};
use super::snmp_tables::{self, Context, InfraSet, Interpreted, Mac, PARTS, parts_of};
use super::sources::Ipv4Subnet;
use super::supervisor::{Board as WorkerBoard, Reply, Request, Requests};
use super::worker::Job;

/// Polls that failed in a row before an agent is `failing` (degraded health).
pub(crate) const FAILING_AFTER: u32 = 3;
/// A test of an agent waits this long after the last one (ADR-1002).
pub(crate) const TEST_COOLDOWN_SECS: u64 = 60;
/// The longest the poller waits for the worker's answer to one job.
const ANSWER_WAIT: Duration = Duration::from_secs(400);
/// How long an agent is left alone while the worker is down.
const WORKER_DOWN_WAIT_SECS: u64 = 10;
/// The first poll of the first agent comes this long after start, and each next one this much later.
const FIRST_POLL_SECS: u64 = 3;
const STAGGER_SECS: u64 = 5;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What the poller needs from the configuration, owned.
#[derive(Debug, Clone, Default)]
pub(crate) struct PollerCtx {
    pub(crate) agents: Vec<SnmpAgent>,
    pub(crate) credentials: Vec<SnmpCredential>,
    pub(crate) secret_dirs: Vec<PathBuf>,
    pub(crate) subnets: Vec<Ipv4Subnet>,
}

impl PollerCtx {
    /// The poller's view of `cfg`.
    pub(crate) fn of(cfg: &Config) -> Self {
        Self {
            agents: cfg.discovery.snmp_agents.clone(),
            credentials: cfg.discovery.snmp_credentials.clone(),
            secret_dirs: cfg
                .node
                .secret_file_dirs
                .iter()
                .map(|d| PathBuf::from(d.as_str()))
                .collect(),
            subnets: cfg
                .discovery
                .subnets
                .iter()
                .filter_map(|s| Ipv4Subnet::parse(&s.cidr.to_string()))
                .collect(),
        }
    }

    /// The configured agent with this name.
    pub(crate) fn agent(&self, name: &str) -> Option<&SnmpAgent> {
        self.agents.iter().find(|a| a.name.as_str() == name)
    }

    /// The longest an ARP binding from an agent may go without a refresh: twice the slowest
    /// agent's interval (one missed poll doesn't drop a host, ADR-908).
    pub(crate) fn arp_max_age_secs(&self) -> u64 {
        self.agents
            .iter()
            .map(|a| u64::from(a.interval_secs))
            .max()
            .map_or(super::thread::ROUTER_MAX_AGE_SECS, |i| {
                i.saturating_mul(2).max(super::thread::ROUTER_MAX_AGE_SECS)
            })
    }

    /// Builds the job request for `agent`: checks the destination (RFC 1918, not this host's own
    /// address; ADR-907) and reads the credential files (confined to `[node] secret_file_dirs`).
    /// Blocking (file reads, one UDP bind to learn whether the address is this host's). The error
    /// is in words and carries no path, address or secret.
    pub(crate) fn request(
        &self,
        agent: &SnmpAgent,
        known: Option<Vec<Choice>>,
    ) -> Result<SnmpRequest, String> {
        let ip: Ipv4Addr = agent
            .address
            .as_str()
            .parse()
            .map_err(|_| "the address is not an IPv4 literal".to_owned())?;
        let own: Vec<Ipv4Addr> = if crate::snmp_cli::is_own(ip) {
            vec![ip]
        } else {
            Vec::new()
        };
        dest::check_addr(ip, &own).map_err(|e| format!("destination refused ({e:?})"))?;
        let cred = self
            .credentials
            .iter()
            .find(|c| c.name.as_str() == agent.credential.as_str())
            .ok_or_else(|| "its credential is not configured".to_owned())?;
        if cred.role != CredentialRole::Infrastructure {
            return Err("its credential is not an infrastructure credential".to_owned());
        }
        let auth = self.auth(cred)?;
        Ok(SnmpRequest {
            agent: agent.name.as_str().to_owned(),
            address: ip,
            port: agent.port,
            auth,
            tables: agent.tables.clone(),
            max_repetitions: agent.max_repetitions,
            known,
        })
    }

    fn auth(&self, cred: &SnmpCredential) -> Result<AuthSpec, String> {
        let file = |f: Option<&telltale_config::SafeString>| -> Result<Secret, String> {
            let path = f
                .map(telltale_config::SafeString::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "a credential file is not named".to_owned())?;
            let v = creds::read_file(std::path::Path::new(path), &self.secret_dirs)
                .map_err(|e| cred_error_text(&e))?;
            Ok(Secret::new(v.expose().to_vec()))
        };
        match cred.version {
            SnmpVersion::V2c => Ok(AuthSpec::V2c {
                community: file(cred.community_file.as_ref())?,
            }),
            SnmpVersion::V3 => {
                let user = cred
                    .user
                    .as_ref()
                    .map(|u| u.as_str().to_owned())
                    .filter(|u| !u.is_empty())
                    .ok_or_else(|| "a v3 credential needs its user".to_owned())?;
                let auth_protocol = cred
                    .auth_protocol
                    .as_ref()
                    .map(|p| p.as_str().to_owned())
                    .ok_or_else(|| {
                        "a v3 credential needs its authentication protocol".to_owned()
                    })?;
                let auth_password = file(cred.auth_password_file.as_ref())?;
                let (priv_protocol, priv_password) = match &cred.priv_protocol {
                    Some(p) if !p.as_str().is_empty() => {
                        let pw = match &cred.priv_password_file {
                            Some(f) if !f.as_str().is_empty() => Some(file(Some(f))?),
                            _ => None,
                        };
                        (Some(p.as_str().to_owned()), pw)
                    }
                    _ => (None, None),
                };
                Ok(AuthSpec::V3 {
                    user,
                    auth_protocol,
                    auth_password,
                    priv_protocol,
                    priv_password,
                })
            }
        }
    }
}

/// A credential read failure in words, with no path (ADR-908: errors carry no input byte).
fn cred_error_text(e: &CredError) -> String {
    match e {
        CredError::InlineRefused => "an inline credential is refused".to_owned(),
        CredError::NotExactlyOne => "a credential names exactly one source".to_owned(),
        CredError::OutsideSecretDirs => {
            "a credential file is outside [node] secret_file_dirs, or missing".to_owned()
        }
        CredError::Unreadable => "a credential file can't be read".to_owned(),
    }
}

/// What a poll left for the inventory.
pub(crate) struct PollOutput {
    pub(crate) agent: String,
    pub(crate) observations: Vec<Observation>,
}

/// The capability record, as kept.
#[derive(Debug, Clone)]
struct CapRec {
    at: u64,
    cap: Capability,
}

/// The last poll, as kept.
#[derive(Debug, Clone, Default)]
struct PollRec {
    at: u64,
    ms: u64,
    requests: u32,
    timeouts: u32,
    walks: Vec<WalkStat>,
    counts: Interpreted,
    ipv6_ignored: u32,
}

#[derive(Debug, Clone, Default)]
struct AgentState {
    address: String,
    credential: String,
    interval: u32,
    tables: Vec<SnmpTable>,
    caps: Option<CapRec>,
    poll: Option<PollRec>,
    last_success: Option<u64>,
    last_error: Option<String>,
    in_a_row: u32,
    polls: u64,
    failures: u64,
    last_test: Option<u64>,
    skipped: bool,
}

#[derive(Debug, Default)]
struct Inner {
    agents: BTreeMap<String, AgentState>,
    /// The MACs of each agent's own interfaces (for the uplink rule).
    own_macs: BTreeMap<String, Vec<Mac>>,
}

/// The agents' board: the poller and the Test button write it, and the API and the metrics read it.
#[derive(Debug, Default)]
pub(crate) struct AgentsBoard {
    inner: Mutex<Inner>,
    view: ArcSwap<Vec<DiscoveryAgent>>,
}

impl AgentsBoard {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn publish(&self, inner: &Inner) {
        self.view.store(Arc::new(
            inner.agents.iter().map(|(n, s)| view_of(n, s)).collect(),
        ));
    }

    /// What the API shows.
    pub(crate) fn snapshot(&self) -> Vec<DiscoveryAgent> {
        (**self.view.load()).clone()
    }

    /// Resets the board to the configured agents (the thread starts, or the section changed). A
    /// test's cooldown is kept for an agent that is still there.
    pub(crate) fn configure(&self, agents: &[SnmpAgent]) {
        let mut g = self.lock();
        let old = std::mem::take(&mut g.agents);
        g.own_macs.clear();
        for a in agents {
            let name = a.name.as_str().to_owned();
            let last_test = old.get(&name).and_then(|o| o.last_test);
            g.agents.insert(
                name,
                AgentState {
                    address: a.address.as_str().to_owned(),
                    credential: a.credential.as_str().to_owned(),
                    interval: a.interval_secs,
                    tables: a.tables.clone(),
                    last_test,
                    ..AgentState::default()
                },
            );
        }
        self.publish(&g);
    }

    /// Empties the board (the inventory stops).
    pub(crate) fn clear(&self) {
        let mut g = self.lock();
        g.agents.clear();
        g.own_macs.clear();
        self.publish(&g);
    }

    /// The capability choices a poll can rely on (none: the first poll probes).
    pub(crate) fn known(&self, name: &str) -> Option<Vec<Choice>> {
        self.lock()
            .agents
            .get(name)
            .and_then(|s| s.caps.as_ref())
            .map(|c| c.cap.choices.clone())
    }

    /// Starts a test: refused with the seconds left when the last one was under a minute ago.
    pub(crate) fn begin_test(&self, name: &str, now: u64) -> Result<(), u64> {
        let mut g = self.lock();
        let Some(s) = g.agents.get_mut(name) else {
            return Ok(());
        };
        if let Some(t) = s.last_test {
            let wait = t.saturating_add(TEST_COOLDOWN_SECS);
            if now < wait {
                return Err(wait.saturating_sub(now).max(1));
            }
        }
        s.last_test = Some(now);
        self.publish(&g);
        Ok(())
    }

    /// Notes a probe's capability record. A probe that was cut short (it timed out) proves nothing
    /// and is not kept.
    pub(crate) fn record_probe(
        &self,
        name: &str,
        r: &SnmpResult,
        now: u64,
    ) -> Option<AgentCapability> {
        let mut g = self.lock();
        let s = g.agents.get_mut(name)?;
        let cap = r.capability.clone().filter(|_| r.aborted.is_none())?;
        let unanswered: Vec<(String, String)> = cap
            .choices
            .iter()
            .filter(|c| c.alt.is_none())
            .filter_map(|c| {
                PARTS
                    .iter()
                    .find(|p| p.part == c.part && s.tables.contains(&p.table))
                    .map(|p| (p.table.name().to_owned(), c.part.clone()))
            })
            .collect();
        for (table, part) in unanswered {
            // REQ: DSC-004 - a skipped table is logged once, when the probe finds it.
            tracing::info!(agent = name, table = %table, part = %part, "an SNMP table does not answer; it is skipped until the next test");
        }
        s.caps = Some(CapRec { at: now, cap });
        let view = capability_view(s);
        self.publish(&g);
        view
    }

    /// Notes a poll that could not run or failed.
    pub(crate) fn record_failure(&self, name: &str, why: &str, skipped: bool, now: u64) {
        let mut g = self.lock();
        let Some(s) = g.agents.get_mut(name) else {
            return;
        };
        let before = state_text(s);
        s.polls = s.polls.saturating_add(1);
        s.failures = s.failures.saturating_add(1);
        s.in_a_row = s.in_a_row.saturating_add(1);
        s.last_error = Some(why.to_owned());
        s.skipped = skipped;
        if let Some(p) = s.poll.as_mut() {
            p.at = now;
        } else {
            s.poll = Some(PollRec {
                at: now,
                ..PollRec::default()
            });
        }
        let after = state_text(s);
        // REQ: DSC-014 - logged once, when the state changes.
        if before != after {
            tracing::warn!(
                agent = name,
                state = after,
                reason = why,
                "SNMP agent poll failed"
            );
        }
        self.publish(&g);
    }

    /// Notes a poll that worked.
    pub(crate) fn record_success(
        &self,
        name: &str,
        result: &SnmpResult,
        counts: Interpreted,
        own_macs: Vec<Mac>,
        now: u64,
    ) {
        let mut g = self.lock();
        g.own_macs.insert(name.to_owned(), own_macs);
        let Some(s) = g.agents.get_mut(name) else {
            return;
        };
        let was_bad = s.in_a_row > 0;
        s.polls = s.polls.saturating_add(1);
        s.in_a_row = 0;
        s.skipped = false;
        s.last_success = Some(now);
        s.last_error = None;
        s.poll = Some(PollRec {
            at: now,
            ms: result.elapsed_ms,
            requests: result.requests,
            timeouts: result.timeouts,
            walks: result.walks.clone(),
            counts,
            ipv6_ignored: result.ipv6_ignored,
        });
        if let Some(c) = &result.capability {
            s.caps = Some(CapRec {
                at: now,
                cap: c.clone(),
            });
            for ch in c.choices.iter().filter(|ch| ch.alt.is_none()) {
                if let Some(p) = PARTS
                    .iter()
                    .find(|p| p.part == ch.part && s.tables.contains(&p.table))
                {
                    tracing::info!(
                        agent = name,
                        table = p.table.name(),
                        part = p.part,
                        "an SNMP table does not answer; it is skipped until the next test"
                    );
                }
            }
        }
        if was_bad {
            tracing::info!(agent = name, "SNMP agent poll works again");
        }
        self.publish(&g);
    }

    /// What the uplink rule counts as infrastructure: the agents' own MACs and names.
    pub(crate) fn infra(&self) -> InfraSet {
        let g = self.lock();
        InfraSet {
            macs: g.own_macs.values().flatten().copied().collect(),
            names: g.agents.keys().map(|n| n.to_ascii_lowercase()).collect(),
            unifi_macs: std::collections::HashSet::default(),
        }
    }
}

fn state_text(s: &AgentState) -> &'static str {
    if s.skipped {
        "skipped"
    } else if s.polls == 0 {
        "waiting"
    } else if s.in_a_row >= FAILING_AFTER {
        "failing"
    } else if s.in_a_row > 0 {
        "error"
    } else {
        "ok"
    }
}

fn capability_view(s: &AgentState) -> Option<AgentCapability> {
    let rec = s.caps.as_ref()?;
    let parts = PARTS
        .iter()
        .filter(|p| s.tables.contains(&p.table))
        .map(|p| AgentCapabilityPart {
            table: p.table.name().to_owned(),
            part: p.part.to_owned(),
            source: rec
                .cap
                .choices
                .iter()
                .find(|c| c.part == p.part)
                .and_then(|c| c.alt.clone()),
        })
        .collect();
    Some(AgentCapability {
        probed_unix: rec.at,
        level: rec.cap.level.clone(),
        engine_id: rec.cap.engine_id.clone(),
        sys_object_id: rec.cap.sys_object_id.clone(),
        parts,
    })
}

fn view_of(name: &str, s: &AgentState) -> DiscoveryAgent {
    let tables = s
        .tables
        .iter()
        .map(|t| {
            let main = parts_of(*t).next();
            let state = match (&s.caps, main) {
                (Some(rec), Some(m)) => {
                    if rec
                        .cap
                        .choices
                        .iter()
                        .any(|c| c.part == m.part && c.alt.is_some())
                    {
                        "answered"
                    } else {
                        "unanswered"
                    }
                }
                _ => "unprobed",
            };
            let walks: Vec<&WalkStat> = s
                .poll
                .iter()
                .flat_map(|p| p.walks.iter())
                .filter(|w| parts_of(*t).any(|p| p.part == w.part))
                .collect();
            let rows = (!walks.is_empty()).then(|| walks.iter().map(|w| w.rows).sum());
            let stop = walks
                .iter()
                .map(|w| w.stop.as_str())
                .find(|s| *s == "error" || *s == "row_cap" || *s == "time_cap")
                .or_else(|| walks.first().map(|w| w.stop.as_str()))
                .map(str::to_owned);
            let error = walks.iter().find_map(|w| w.error.clone());
            DiscoveryAgentTable {
                table: t.name().to_owned(),
                state: state.to_owned(),
                rows,
                stop,
                error,
            }
        })
        .collect();
    DiscoveryAgent {
        name: name.to_owned(),
        address: s.address.clone(),
        credential: s.credential.clone(),
        interval_secs: s.interval,
        state: state_text(s).to_owned(),
        last_poll_unix: s.poll.as_ref().map(|p| p.at),
        last_success_unix: s.last_success,
        last_duration_ms: s.poll.as_ref().filter(|p| p.ms > 0).map(|p| p.ms),
        last_error: s.last_error.clone(),
        consecutive_failures: s.in_a_row,
        polls: s.polls,
        failures: s.failures,
        last_requests: s.poll.as_ref().map(|p| p.requests),
        last_timeouts: s.poll.as_ref().map(|p| p.timeouts),
        tables,
        capability: capability_view(s),
        last_counts: s.poll.as_ref().map(|p| DiscoveryAgentCounts {
            arp_merged: p.counts.arp_merged,
            arp_outside_subnets: p.counts.arp_outside_subnets,
            ipv6_ignored: p.ipv6_ignored,
            own_merged: p.counts.own_merged,
            fdb_located: p.counts.fdb_located,
            fdb_uplink: p.counts.fdb_uplink,
            uplink_ports: p.counts.uplink_ports,
            lldp_merged: p.counts.lldp_merged,
        }),
        last_test_unix: s.last_test,
    }
}

/// REQ: DSC-004 (`dsc_004_snmp_test_dry_run_and_cooldown`) - the OIDs a test of `agent` queries:
/// for each requested table, each part and each alternative with the root the probe's one GETNEXT
/// starts from and the columns a poll walks. No packet is sent to learn it.
pub(crate) fn test_oids(agent: &SnmpAgent) -> Vec<SnmpTestOid> {
    let mut out = Vec::new();
    for table in &agent.tables {
        for part in parts_of(*table) {
            for alt in part.alts {
                out.push(SnmpTestOid {
                    table: table.name().to_owned(),
                    part: part.part.to_owned(),
                    alternative: alt.name().to_owned(),
                    probe_oid: alt
                        .columns()
                        .first()
                        .copied()
                        .unwrap_or_default()
                        .to_owned(),
                    columns: alt.columns().iter().map(|c| (*c).to_owned()).collect(),
                });
            }
        }
    }
    out.push(SnmpTestOid {
        table: "identity".to_owned(),
        part: "sysObjectID".to_owned(),
        alternative: "system".to_owned(),
        probe_oid: snmp_tables::SYS_OBJECT_ID.to_owned(),
        columns: Vec::new(),
    });
    out
}

/// Queues `req` as `op` for the SNMP worker and waits for its answer. `front` puts the job ahead of
/// the queue (a Test goes before the polls). Dropping the future cancels the wait; the supervisor
/// skips a request whose answer nobody waits for.
pub(crate) async fn run_job(
    requests: &Requests,
    op: &str,
    req: SnmpRequest,
    front: bool,
    wait: Duration,
) -> Result<Reply, String> {
    let (tx, rx) = oneshot::channel();
    let job = Job {
        id: 0,
        op: op.to_owned(),
        kind: String::new(),
        snmp: Some(req),
    };
    {
        let mut q = requests.lock().unwrap_or_else(PoisonError::into_inner);
        let item = Request {
            job,
            reply: Some(tx),
        };
        if front {
            q.push_front(item);
        } else {
            q.push_back(item);
        }
    }
    match tokio::time::timeout(wait, rx).await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => Err("the SNMP worker stopped before it answered".to_owned()),
        Err(_) => Err("the SNMP worker did not answer in time".to_owned()),
    }
}

/// One poll of one agent, end to end. The observations go to `out`; the board is updated.
async fn poll_agent(
    ctx: &PollerCtx,
    agent: &SnmpAgent,
    board: &AgentsBoard,
    requests: &Requests,
    out: &mpsc::Sender<PollOutput>,
) {
    let name = agent.name.as_str();
    let now = unix_now();
    let known = board.known(name);
    let req = match ctx.request(agent, known) {
        Ok(r) => r,
        Err(why) => {
            board.record_failure(name, &why, true, now);
            return;
        }
    };
    let reply = match run_job(requests, OP_POLL, req, false, ANSWER_WAIT).await {
        Ok(r) => r,
        Err(why) => {
            board.record_failure(name, &why, false, unix_now());
            return;
        }
    };
    let at = unix_now();
    let Some(result) = reply.result.snmp.clone() else {
        let why = reply
            .result
            .error
            .clone()
            .unwrap_or_else(|| "the worker refused the job".to_owned());
        board.record_failure(name, &why, false, at);
        return;
    };
    if !reply.result.ok {
        let why = reply
            .result
            .error
            .clone()
            .unwrap_or_else(|| "the poll did not finish".to_owned());
        board.record_failure(name, &why, false, at);
        return;
    }
    let infra = board.infra();
    let cx = Context {
        agent: name,
        subnets: &ctx.subnets,
        infra: &infra,
        now: at,
    };
    let interpreted = snmp_tables::interpret(&reply.rows, &cx);
    board.record_success(
        name,
        &result,
        interpreted.counts.clone(),
        interpreted.own_macs,
        at,
    );
    let _ = out
        .send(PollOutput {
            agent: name.to_owned(),
            observations: interpreted.observations,
        })
        .await;
}

/// REQ: DSC-004 - runs the poller until `stop` is set: each agent when it is due, one at a time
/// (the worker takes one job at a time), the first polls staggered so the agents don't all start
/// at once. While the SNMP worker is down an agent waits and no failure is counted.
pub(crate) async fn run(
    ctx: Arc<PollerCtx>,
    board: Arc<AgentsBoard>,
    requests: Requests,
    workers: WorkerBoard,
    out: mpsc::Sender<PollOutput>,
    stop: Arc<AtomicBool>,
) {
    let start = unix_now();
    let mut due: BTreeMap<String, u64> = BTreeMap::new();
    for (i, a) in ctx.agents.iter().enumerate() {
        let offset = FIRST_POLL_SECS.saturating_add(STAGGER_SECS.saturating_mul(i as u64));
        due.insert(a.name.as_str().to_owned(), start.saturating_add(offset));
    }
    while !stop.load(Ordering::Acquire) {
        let now = unix_now();
        let next = ctx
            .agents
            .iter()
            .filter(|a| due.get(a.name.as_str()).is_some_and(|d| *d <= now))
            .min_by_key(|a| due.get(a.name.as_str()).copied().unwrap_or(u64::MAX));
        let Some(agent) = next else {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };
        let worker_up = workers.load().iter().any(|w| w.worker == "snmp" && w.up);
        if !worker_up {
            due.insert(
                agent.name.as_str().to_owned(),
                now.saturating_add(WORKER_DOWN_WAIT_SECS),
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        poll_agent(&ctx, agent, &board, &requests, &out).await;
        due.insert(
            agent.name.as_str().to_owned(),
            unix_now().saturating_add(u64::from(agent.interval_secs)),
        );
    }
}

#[cfg(test)]
#[path = "poller_tests.rs"]
mod tests;

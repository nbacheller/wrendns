//! REQ: DSC-003 (T25.4, ADR-908) — `telltale snmp walk --agent <name> [--table ...]`: a local
//! diagnostic that reads one table from a configured SNMP agent and prints the rows. It takes
//! a configured agent's name only, never an address (ADR-907: nothing here reaches a host the
//! owner did not list), checks the destination like the poller does, reads its credential from
//! a file under `[node] secret_file_dirs`, and prints no credential. It is read-only like the
//! crate: GET-class PDUs only. The UI counterpart is T25.6's **Test**.
//!
//! Agents come from `[[discovery.snmp_agent]]` (T25.6): [`lookup`] turns a configured agent's name
//! into its address and credential files; everything after the lookup (destination check, credential
//! read, table roots with their fallbacks, the bounded walk, printing) is shared with the poller's
//! rules.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;

use clap::ValueEnum;
use telltale_config::{Config, CredentialRole, SnmpVersion};
use telltale_snmp::agent::{Agent, Security, Timing};
use telltale_snmp::creds;
use telltale_snmp::dest;
use telltale_snmp::oid::Oid;
use telltale_snmp::pdu::{Value, VarBind};
use telltale_snmp::secret::SecretValue;
use telltale_snmp::usm::{AuthProto, PrivProto, UsmUser};
use telltale_snmp::walk::{self, Bulk, Limits, Pacer, Stop, SystemPacer, WalkError};

/// The tables `--table` names (ADR-908 "Infrastructure polling").
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Table {
    Arp,
    Ifmib,
    Bridge,
    Lldp,
}

impl Table {
    /// The roots read for a table. Each group is a list of alternatives: the first one that
    /// answers any row is used and the rest are skipped (a fallback); every group is read.
    fn groups(self) -> &'static [&'static [&'static str]] {
        match self {
            // ipNetToPhysicalTable, else ipNetToMediaTable.
            Self::Arp => &[&["1.3.6.1.2.1.4.35", "1.3.6.1.2.1.4.22"]],
            // ifTable, ifXTable, and the agent's own addresses (ipAddressTable, else ipAddrTable).
            Self::Ifmib => &[
                &["1.3.6.1.2.1.2.2"],
                &["1.3.6.1.2.1.31.1.1"],
                &["1.3.6.1.2.1.4.34", "1.3.6.1.2.1.4.20"],
            ],
            // dot1qTpFdbTable, else dot1dTpFdbTable; ports through dot1dBasePortIfIndex.
            Self::Bridge => &[
                &["1.3.6.1.2.1.17.7.1.2.2", "1.3.6.1.2.1.17.4.3"],
                &["1.3.6.1.2.1.17.1.4"],
            ],
            // lldpRemTable.
            Self::Lldp => &[&["1.0.8802.1.1.2.1.4.1"]],
        }
    }
}

/// How an agent signs in. Credentials are named by file, never held inline (ADR-908).
#[derive(Debug, Clone)]
pub(crate) enum AgentAuth {
    V2c {
        community_file: PathBuf,
    },
    V3 {
        user: String,
        auth: String,
        auth_file: PathBuf,
        privacy: Option<(String, PathBuf)>,
    },
}

/// One configured agent, as `[[discovery.snmp_agent]]` and its credential resolve to.
#[derive(Debug, Clone)]
pub(crate) struct AgentSpec {
    pub(crate) name: String,
    pub(crate) address: SocketAddr,
    pub(crate) auth: AgentAuth,
}

/// Why the command stopped. Carries no secret.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CliError {
    /// `--agent` was an address, not a name.
    AddressNotAName,
    /// No configured agent has this name.
    NoSuchAgent(String),
    /// The destination is refused (ADR-907).
    Destination(String),
    /// The credential cannot be read.
    Credential(String),
    /// The exchange or the walk failed.
    Walk(String),
    /// Writing the output failed.
    Output,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddressNotAName => write!(
                f,
                "--agent takes a configured agent's name, not an address (REQ: DSC-003)"
            ),
            Self::NoSuchAgent(n) => write!(
                f,
                "no SNMP agent named `{n}` is configured (add one under [[discovery.snmp_agent]], or in Settings, Network inventory)"
            ),
            Self::Destination(m) => write!(f, "destination refused: {m}"),
            Self::Credential(m) => write!(f, "credential: {m}"),
            Self::Walk(m) => write!(f, "walk failed: {m}"),
            Self::Output => write!(f, "could not write the output"),
        }
    }
}

/// Finds a configured agent by name. A value that parses as an address is refused first, so a
/// typed IP never reaches the lookup (and never a socket).
pub(crate) fn lookup(cfg: &Config, name: &str) -> Result<AgentSpec, CliError> {
    if name.parse::<IpAddr>().is_ok() || name.parse::<SocketAddr>().is_ok() {
        return Err(CliError::AddressNotAName);
    }
    // REQ: DSC-004 (T25.6) - the one place a name becomes an address and credential files.
    let agent = cfg
        .discovery
        .snmp_agents
        .iter()
        .find(|a| a.name.as_str() == name)
        .ok_or_else(|| CliError::NoSuchAgent(name.to_owned()))?;
    let cred = cfg
        .discovery
        .snmp_credentials
        .iter()
        .find(|c| c.name.as_str() == agent.credential.as_str())
        .ok_or_else(|| CliError::Credential("the agent's credential is not configured".into()))?;
    if cred.role != CredentialRole::Infrastructure {
        return Err(CliError::Credential(
            "an agent takes an infrastructure credential".into(),
        ));
    }
    let ip: Ipv4Addr = agent
        .address
        .as_str()
        .parse()
        .map_err(|_| CliError::Destination("not an IPv4 address".into()))?;
    let file = |f: &Option<telltale_config::SafeString>| -> Result<PathBuf, CliError> {
        f.as_ref()
            .filter(|s| !s.trim().is_empty())
            .map(|s| PathBuf::from(s.as_str()))
            .ok_or_else(|| CliError::Credential("a credential file is not named".into()))
    };
    let auth = match cred.version {
        SnmpVersion::V2c => AgentAuth::V2c {
            community_file: file(&cred.community_file)?,
        },
        SnmpVersion::V3 => {
            let auth_file = file(&cred.auth_password_file)?;
            let privacy = match &cred.priv_protocol {
                Some(p) if !p.as_str().is_empty() => {
                    let pw = if cred.priv_password_file.is_some() {
                        file(&cred.priv_password_file)?
                    } else {
                        auth_file.clone()
                    };
                    Some((p.as_str().to_owned(), pw))
                }
                _ => None,
            };
            AgentAuth::V3 {
                user: cred
                    .user
                    .as_ref()
                    .map(|u| u.as_str().to_owned())
                    .unwrap_or_default(),
                auth: cred
                    .auth_protocol
                    .as_ref()
                    .map(|p| p.as_str().to_owned())
                    .unwrap_or_default(),
                auth_file,
                privacy,
            }
        }
    };
    Ok(AgentSpec {
        name: agent.name.as_str().to_owned(),
        address: SocketAddr::new(IpAddr::V4(ip), agent.port),
        auth,
    })
}

/// True when `addr` is one of this host's own addresses: a socket can be bound to it.
pub(crate) fn is_own(addr: Ipv4Addr) -> bool {
    UdpSocket::bind(SocketAddr::new(IpAddr::V4(addr), 0)).is_ok()
}

fn secret(path: &std::path::Path, dirs: &[PathBuf]) -> Result<SecretValue, CliError> {
    creds::read_file(path, dirs).map_err(|e| CliError::Credential(format!("{e:?}")))
}

/// Checks the destination and builds the agent (a connected socket) from its credential.
pub(crate) fn connect(
    spec: &AgentSpec,
    secret_dirs: &[PathBuf],
    own: &[Ipv4Addr],
) -> Result<Agent, CliError> {
    let IpAddr::V4(v4) = spec.address.ip() else {
        return Err(CliError::Destination("not an IPv4 address".into()));
    };
    dest::check_addr(v4, own).map_err(|e| CliError::Destination(format!("{e:?}")))?;
    let security = match &spec.auth {
        AgentAuth::V2c { community_file } => Security::V2c {
            community: secret(community_file, secret_dirs)?,
        },
        AgentAuth::V3 {
            user,
            auth,
            auth_file,
            privacy,
        } => {
            let auth_proto =
                AuthProto::parse(auth).map_err(|r| CliError::Credential(r.reason().into()))?;
            let privacy = match privacy {
                Some((proto, file)) => {
                    let p = PrivProto::parse(proto)
                        .map_err(|r| CliError::Credential(r.reason().into()))?;
                    Some((p, secret(file, secret_dirs)?))
                }
                None => None,
            };
            Security::V3 {
                user: UsmUser {
                    name: user.clone().into_bytes(),
                    auth: Some((auth_proto, secret(auth_file, secret_dirs)?)),
                    privacy,
                },
            }
        }
    };
    Agent::new(spec.address, security, Timing::default())
        .map_err(|e| CliError::Walk(format!("{e:?}")))
}

/// Walks the roots of `table` and returns the rows, with the reason each root stopped.
pub(crate) fn walk_table<B: Bulk, P: Pacer>(
    agent: &mut B,
    pacer: &mut P,
    table: Table,
    limits: &Limits,
) -> Result<Vec<(Vec<VarBind>, Stop)>, CliError> {
    let mut out = Vec::new();
    for group in table.groups() {
        for text in *group {
            let root = Oid::parse(text).ok_or_else(|| CliError::Walk("bad table root".into()))?;
            let walked = match walk::walk(agent, pacer, &root, limits) {
                Ok(w) => w,
                Err(WalkError::Agent(e)) => return Err(CliError::Walk(format!("{e:?}"))),
                Err(WalkError::NotIncreasing) => {
                    return Err(CliError::Walk("the agent's OIDs do not increase".into()));
                }
            };
            let answered = !walked.rows.is_empty();
            out.push((walked.rows, walked.stop));
            if answered {
                break;
            }
        }
    }
    Ok(out)
}

/// One printable value: untrusted device text is cut at 255 bytes and has control characters
/// replaced (ADR-908 "Untrusted strings"). No value is a credential.
fn show(v: &Value) -> String {
    fn text(b: &[u8]) -> String {
        let cut = b.get(..b.len().min(255)).unwrap_or(b);
        String::from_utf8_lossy(cut)
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect()
    }
    match v {
        Value::Integer(i) => format!("INTEGER: {i}"),
        Value::OctetString(b) => {
            if b.iter().all(|c| (0x20..0x7f).contains(c)) {
                format!("STRING: {}", text(b))
            } else {
                let hex: Vec<String> = b.iter().take(64).map(|c| format!("{c:02x}")).collect();
                format!("Hex-STRING: {}", hex.join(" "))
            }
        }
        Value::Oid(o) => format!("OID: {o}"),
        Value::Null => "NULL".into(),
        Value::IpAddress(a) => format!("IpAddress: {}", Ipv4Addr::from(*a)),
        Value::Counter32(n) => format!("Counter32: {n}"),
        Value::Gauge32(n) => format!("Gauge32: {n}"),
        Value::TimeTicks(n) => format!("Timeticks: {n}"),
        Value::Counter64(n) => format!("Counter64: {n}"),
        Value::NoSuchObject => "noSuchObject".into(),
        Value::NoSuchInstance => "noSuchInstance".into(),
        Value::EndOfMibView => "endOfMibView".into(),
        Value::Unknown(t) => format!("unknown tag 0x{t:02x}"),
    }
}

/// Prints the walked rows, then one line per root saying why it stopped.
pub(crate) fn print(
    walked: &[(Vec<VarBind>, Stop)],
    out: &mut impl Write,
) -> Result<usize, CliError> {
    let mut n = 0usize;
    for (rows, stop) in walked {
        for r in rows {
            writeln!(out, "{} = {}", r.oid, show(&r.value)).map_err(|_| CliError::Output)?;
            n = n.saturating_add(1);
        }
        let why = match stop {
            Stop::EndOfView => "end of table",
            Stop::RowCap => "row cap reached",
            Stop::TimeCap => "time cap reached",
        };
        writeln!(out, "# {} rows, {why}", rows.len()).map_err(|_| CliError::Output)?;
    }
    Ok(n)
}

/// `telltale snmp walk`.
pub(crate) fn run_walk(
    cfg: &Config,
    agent_name: &str,
    table: Table,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let spec = lookup(cfg, agent_name)?;
    let dirs: Vec<PathBuf> = cfg
        .node
        .secret_file_dirs
        .iter()
        .map(|d| PathBuf::from(d.as_str()))
        .collect();
    let own: Vec<Ipv4Addr> = match spec.address.ip() {
        IpAddr::V4(a) if is_own(a) => vec![a],
        _ => Vec::new(),
    };
    let mut agent = connect(&spec, &dirs, &own)?;
    writeln!(out, "# agent {}", spec.name).map_err(|_| CliError::Output)?;
    let walked = walk_table(&mut agent, &mut SystemPacer, table, &Limits::default())?;
    print(&walked, out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use telltale_snmp::agent::AgentError;
    use telltale_snmp::pdu::{Response, TAG_RESPONSE};

    /// A fake agent holding an ordered MIB; answers GETBULK like an agent.
    struct Fake(Vec<VarBind>);

    impl Bulk for Fake {
        fn bulk(&mut self, oid: &Oid, max: u32) -> Result<Response, AgentError> {
            let after: Vec<VarBind> = self
                .0
                .iter()
                .filter(|v| v.oid.arcs() > oid.arcs())
                .take(usize::try_from(max).unwrap_or(1))
                .cloned()
                .collect();
            let varbinds = if after.is_empty() {
                vec![VarBind {
                    oid: oid.clone(),
                    value: Value::EndOfMibView,
                }]
            } else {
                after
            };
            Ok(Response {
                tag: TAG_RESPONSE,
                request_id: 1,
                error_status: 0,
                error_index: 0,
                varbinds,
            })
        }
    }

    struct Clock(Instant);
    impl Pacer for Clock {
        fn now(&self) -> Instant {
            self.0
        }
        fn pause(&mut self, d: Duration) {
            self.0 += d;
        }
    }

    fn vb(oid: &str, v: Value) -> VarBind {
        VarBind {
            oid: Oid::parse(oid).unwrap(),
            value: v,
        }
    }

    /// REQ: DSC-003 — an address is not an agent name: refused before any lookup or socket.
    #[test]
    fn dsc_003_walk_cli_takes_agent_name_only() {
        use clap::CommandFactory;
        let cfg = Config::default();
        for addr in ["192.168.1.1", "10.0.0.1:161", "::1", "8.8.8.8"] {
            assert_eq!(
                lookup(&cfg, addr).err(),
                Some(CliError::AddressNotAName),
                "{addr}"
            );
        }
        // A name that is not configured is a lookup failure, not a connection.
        assert!(matches!(
            lookup(&cfg, "core-switch"),
            Err(CliError::NoSuchAgent(_))
        ));
        // The command line has no way to give an address: `snmp walk` takes --agent, --table
        // and --config, and nothing else.
        let cli = crate::Cli::command();
        let walk = cli
            .find_subcommand("snmp")
            .and_then(|s| s.find_subcommand("walk"))
            .expect("snmp walk exists");
        let mut ids: Vec<&str> = walk
            .get_arguments()
            .map(|a| a.get_id().as_str())
            .filter(|id| *id != "help" && *id != "version")
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, ["agent", "config", "table"]);
        assert!(walk.get_positionals().next().is_none());
    }

    /// REQ: DSC-003, ADR-907 — a destination outside RFC 1918, or the host's own address, is
    /// refused before a socket is opened; a credential outside `secret_file_dirs` is refused.
    #[test]
    fn dsc_003_walk_cli_refuses_bad_destinations_and_credentials() {
        let spec = |ip: [u8; 4], file: &str| AgentSpec {
            name: "a".into(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), 161),
            auth: AgentAuth::V2c {
                community_file: PathBuf::from(file),
            },
        };
        assert!(matches!(
            connect(&spec([8, 8, 8, 8], "/nope"), &[], &[]),
            Err(CliError::Destination(_))
        ));
        assert!(matches!(
            connect(&spec([127, 0, 0, 1], "/nope"), &[], &[]),
            Err(CliError::Destination(_))
        ));
        let own = [Ipv4Addr::new(192, 168, 1, 50)];
        assert!(matches!(
            connect(&spec([192, 168, 1, 50], "/nope"), &[], &own),
            Err(CliError::Destination(_))
        ));
        // A private destination with a credential file that is not under a configured dir.
        let err = connect(&spec([192, 168, 1, 2], "/etc/hostname"), &[], &[]).err();
        assert!(matches!(err, Some(CliError::Credential(_))), "{err:?}");
        // Neither error text carries a path or an address beyond what the caller typed.
        let text = err.map(|e| e.to_string()).unwrap_or_default();
        assert!(!text.contains("hostname"));
    }

    /// REQ: DSC-003, DSC-004 — `arp` reads ipNetToPhysicalTable, and ipNetToMediaTable only when
    /// the first answered nothing; rows print with the stop reason.
    #[test]
    fn dsc_003_walk_cli_table_roots_and_fallback() {
        let mut with_physical = Fake(vec![
            vb(
                "1.3.6.1.2.1.4.22.1.2.1.10.0.0.9",
                Value::OctetString(vec![1; 6]),
            ),
            vb(
                "1.3.6.1.2.1.4.35.1.4.1.1.10.0.0.9",
                Value::OctetString(vec![2; 6]),
            ),
        ]);
        let mut clock = Clock(Instant::now());
        let w = walk_table(
            &mut with_physical,
            &mut clock,
            Table::Arp,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(
            w.len(),
            1,
            "the fallback is not read when the first answers"
        );
        assert_eq!(w[0].0.len(), 1);

        let mut media_only = Fake(vec![vb(
            "1.3.6.1.2.1.4.22.1.2.1.10.0.0.9",
            Value::OctetString(vec![1; 6]),
        )]);
        let w = walk_table(&mut media_only, &mut clock, Table::Arp, &Limits::default()).unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].0.len(), 0);
        assert_eq!(w[1].0.len(), 1);

        let mut out = Vec::new();
        let n = print(&w, &mut out).unwrap();
        assert_eq!(n, 1);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("1.3.6.1.2.1.4.22.1.2.1.10.0.0.9 = Hex-STRING: 01 01"));
        assert!(text.contains("# 1 rows, end of table"));
    }

    /// REQ: DSC-003 — device text is cut and has control characters replaced when printed.
    #[test]
    fn dsc_003_walk_cli_prints_untrusted_text_safely() {
        let long = Value::OctetString(vec![b'a'; 1000]);
        assert!(show(&long).len() < 300);
        let ctl = Value::OctetString(b"a\x1b[2Jb".to_vec());
        assert!(!show(&ctl).contains('\x1b'));
    }
}

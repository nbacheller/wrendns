//! REQ: DSC-003 — interop with net-snmp (ADR-908). These tests need an `snmpd` the test can
//! reach: `TT_SNMPD_ADDR` (host:port, on an RFC 1918 address), `TT_SNMPD_USER`, `TT_SNMPD_AUTH`
//! (`SHA` or `SHA-256`), `TT_SNMPD_AUTH_FILE` (a file holding the authentication password),
//! `TT_SNMPD_SYSNAME` (the sysName the agent reports), and for authPriv also
//! `TT_SNMPD_PRIV_FILE`. CI runs them in a net-snmp container job; without the variables they
//! are skipped by `#[ignore]`. No password is printed.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::time::Duration;

use telltale_snmp::agent::{Agent, AgentError, Security, Timing};
use telltale_snmp::oid::Oid;
use telltale_snmp::pdu::{RequestKind, Value};
use telltale_snmp::secret::SecretValue;
use telltale_snmp::usm::{AuthProto, PrivProto, UsmUser};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn secret_from(name: &str) -> SecretValue {
    let path = env(name);
    let bytes = std::fs::read(path).unwrap_or_else(|_| panic!("{name} is unreadable"));
    SecretValue::new(bytes.trim_ascii_end().to_vec())
}

fn v3_agent(priv_on: bool, user_name: Option<&str>, auth_file: &str) -> Agent {
    let addr: SocketAddr = env("TT_SNMPD_ADDR")
        .parse()
        .unwrap_or_else(|_| panic!("TT_SNMPD_ADDR"));
    let auth = AuthProto::parse(&env("TT_SNMPD_AUTH")).unwrap_or_else(|r| panic!("{}", r.reason()));
    let privacy = priv_on.then(|| (PrivProto::Aes128, secret_from("TT_SNMPD_PRIV_FILE")));
    let user = UsmUser {
        name: user_name
            .map_or_else(|| env("TT_SNMPD_USER"), str::to_owned)
            .into_bytes(),
        auth: Some((auth, secret_from(auth_file))),
        privacy,
    };
    let timing = Timing {
        timeout: Duration::from_millis(1500),
        retries: 1,
    };
    // Only the scripts' throwaway ranges (deploy/snmp-e2e.sh uses 251, v3-e2e.sh 247) or loopback is ever a target.
    let ip = addr.ip();
    let ok = ip.is_loopback()
        || matches!(ip, std::net::IpAddr::V4(v4)
            if matches!(v4.octets().get(..3), Some(&[172, 30, 247 | 251])));
    assert!(
        ok,
        "TT_SNMPD_ADDR must be 172.30.247.0/24, 172.30.251.0/24 or loopback: {addr}"
    );
    Agent::new(addr, Security::V3 { user }, timing).unwrap_or_else(|e| panic!("{e:?}"))
}

fn sys_name_oid() -> Oid {
    Oid::parse("1.3.6.1.2.1.1.5.0").unwrap_or_else(|| panic!("oid"))
}

fn run(priv_on: bool) {
    let mut agent = v3_agent(priv_on, None, "TT_SNMPD_AUTH_FILE");
    let resp = agent
        .request(RequestKind::Get, &[sys_name_oid()], 0)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let got = match resp.varbinds.first().map(|v| &v.value) {
        Some(Value::OctetString(b)) => b.clone(),
        other => panic!("unexpected value kind: {other:?}"),
    };
    assert_eq!(got, env("TT_SNMPD_SYSNAME").into_bytes());
    agent.end_round();
}

/// A bounded walk of the system group over authPriv: engine discovery once, then several
/// requests inside one round (GETBULK included), every reply verified and decrypted.
#[test]
#[ignore = "needs a net-snmp agent: see the module comment"]
fn dsc_003_net_snmp_v3_walk() {
    use telltale_snmp::walk::{self, Limits, SystemPacer};
    let mut agent = v3_agent(true, None, "TT_SNMPD_AUTH_FILE");
    let system = Oid::parse("1.3.6.1.2.1.1").unwrap_or_else(|| panic!("oid"));
    let walked = walk::walk(&mut agent, &mut SystemPacer, &system, &Limits::default())
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(walked.stop, walk::Stop::EndOfView);
    assert!(walked.rows.len() >= 6, "rows: {}", walked.rows.len());
    agent.end_round();
}

/// A wrong authentication password never yields data: the reply (if any) fails its MAC, or the
/// agent drops the request.
#[test]
#[ignore = "needs a net-snmp agent: see the module comment"]
fn dsc_003_net_snmp_wrong_password_fails() {
    let mut agent = v3_agent(true, None, "TT_SNMPD_WRONG_FILE");
    let r = agent.request(RequestKind::Get, &[sys_name_oid()], 0);
    // The agent drops a request whose MAC fails, and sends nothing back.
    assert!(matches!(r, Err(AgentError::Timeout)), "{r:?}");
}

/// A user the agent does not have never yields data.
#[test]
#[ignore = "needs a net-snmp agent: see the module comment"]
fn dsc_003_net_snmp_unknown_user_fails() {
    let mut agent = v3_agent(true, Some("nosuchuser"), "TT_SNMPD_AUTH_FILE");
    let r = agent.request(RequestKind::Get, &[sys_name_oid()], 0);
    assert!(matches!(r, Err(AgentError::Timeout)), "{r:?}");
}

#[test]
#[ignore = "needs a net-snmp agent: see the module comment"]
fn dsc_003_net_snmp_auth_no_priv() {
    run(false);
}

#[test]
#[ignore = "needs a net-snmp agent: see the module comment"]
fn dsc_003_net_snmp_auth_priv() {
    run(true);
}

/// v2c against net-snmp: a GET of sysName, then a bounded walk of the system group.
#[test]
#[ignore = "needs a net-snmp agent: see the module comment"]
fn dsc_003_net_snmp_v2c_get_and_walk() {
    use telltale_snmp::walk::{self, Limits, SystemPacer};

    let addr: SocketAddr = env("TT_SNMPD_ADDR")
        .parse()
        .unwrap_or_else(|_| panic!("TT_SNMPD_ADDR"));
    let community = secret_from("TT_SNMPD_COMMUNITY_FILE");
    let timing = Timing {
        timeout: Duration::from_millis(1500),
        retries: 2,
    };
    let mut agent =
        Agent::new(addr, Security::V2c { community }, timing).unwrap_or_else(|e| panic!("{e:?}"));
    let sys_name = Oid::parse("1.3.6.1.2.1.1.5.0").unwrap_or_else(|| panic!("oid"));
    let resp = agent
        .request(RequestKind::Get, std::slice::from_ref(&sys_name), 0)
        .unwrap_or_else(|e| panic!("{e:?}"));
    match resp.varbinds.first().map(|v| &v.value) {
        Some(Value::OctetString(b)) => assert_eq!(b, &env("TT_SNMPD_SYSNAME").into_bytes()),
        other => panic!("unexpected value kind: {other:?}"),
    }
    let system = Oid::parse("1.3.6.1.2.1.1").unwrap_or_else(|| panic!("oid"));
    let walked = walk::walk(&mut agent, &mut SystemPacer, &system, &Limits::default())
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(walked.stop, walk::Stop::EndOfView);
    assert!(
        walked.rows.len() >= 6,
        "system group rows: {}",
        walked.rows.len()
    );
}

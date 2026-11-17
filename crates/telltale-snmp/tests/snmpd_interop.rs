//! REQ: DSC-003 — interop with net-snmp (ADR-908). These tests need an `snmpd` the test can
//! reach: `TT_SNMPD_ADDR` (host:port, on an RFC 1918 address), `TT_SNMPD_USER`, `TT_SNMPD_AUTH`
//! (`SHA` or `SHA-256`), `TT_SNMPD_AUTH_FILE` (a file holding the authentication password),
//! `TT_SNMPD_SYSNAME` (the sysName the agent reports), and for authPriv also
//! `TT_SNMPD_PRIV_FILE`. CI runs them in a net-snmp container job; without the variables they
//! are skipped by `#[ignore]`. No password is printed.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::time::Duration;

use telltale_snmp::agent::{Agent, Security, Timing};
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

fn run(priv_on: bool) {
    let addr: SocketAddr = env("TT_SNMPD_ADDR").parse().unwrap_or_else(|_| panic!("TT_SNMPD_ADDR"));
    let auth = AuthProto::parse(&env("TT_SNMPD_AUTH")).unwrap_or_else(|r| panic!("{}", r.reason()));
    let privacy = priv_on.then(|| (PrivProto::Aes128, secret_from("TT_SNMPD_PRIV_FILE")));
    let user = UsmUser {
        name: env("TT_SNMPD_USER").into_bytes(),
        auth: Some((auth, secret_from("TT_SNMPD_AUTH_FILE"))),
        privacy,
    };
    let timing = Timing {
        timeout: Duration::from_millis(1500),
        retries: 2,
    };
    let mut agent = Agent::new(addr, Security::V3 { user }, timing).unwrap_or_else(|e| panic!("{e:?}"));
    let sys_name = Oid::parse("1.3.6.1.2.1.1.5.0").unwrap_or_else(|| panic!("oid"));
    let resp = agent.request(RequestKind::Get, &[sys_name], 0).unwrap_or_else(|e| panic!("{e:?}"));
    let got = match resp.varbinds.first().map(|v| &v.value) {
        Some(Value::OctetString(b)) => b.clone(),
        other => panic!("unexpected value kind: {other:?}"),
    };
    assert_eq!(got, env("TT_SNMPD_SYSNAME").into_bytes());
    agent.end_round();
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

    let addr: SocketAddr = env("TT_SNMPD_ADDR").parse().unwrap_or_else(|_| panic!("TT_SNMPD_ADDR"));
    let community = secret_from("TT_SNMPD_COMMUNITY_FILE");
    let timing = Timing {
        timeout: Duration::from_millis(1500),
        retries: 2,
    };
    let mut agent = Agent::new(addr, Security::V2c { community }, timing).unwrap_or_else(|e| panic!("{e:?}"));
    let sys_name = Oid::parse("1.3.6.1.2.1.1.5.0").unwrap_or_else(|| panic!("oid"));
    let resp = agent.request(RequestKind::Get, std::slice::from_ref(&sys_name), 0).unwrap_or_else(|e| panic!("{e:?}"));
    match resp.varbinds.first().map(|v| &v.value) {
        Some(Value::OctetString(b)) => assert_eq!(b, &env("TT_SNMPD_SYSNAME").into_bytes()),
        other => panic!("unexpected value kind: {other:?}"),
    }
    let system = Oid::parse("1.3.6.1.2.1.1").unwrap_or_else(|| panic!("oid"));
    let walked = walk::walk(&mut agent, &mut SystemPacer, &system, &Limits::default()).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(walked.stop, walk::Stop::EndOfView);
    assert!(walked.rows.len() >= 6, "system group rows: {}", walked.rows.len());
}

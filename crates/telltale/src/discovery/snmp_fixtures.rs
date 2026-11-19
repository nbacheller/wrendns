//! Test support for the infrastructure poller (T25.6): the two recorded-shape walks (a Net-SNMP
//! gateway and an Aruba switch; synthetic, see `tests/fixtures/snmp/generate.py`), a fake agent that
//! answers GET, GETNEXT and GETBULK from a walk, and a virtual clock. No socket is opened.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, Instant};

use telltale_snmp::agent::AgentError;
use telltale_snmp::oid::Oid;
use telltale_snmp::pdu::{Response, TAG_RESPONSE, Value, VarBind};
use telltale_snmp::walk::{Bulk, Pacer};

use super::snmp_poll::Source;

pub(crate) const GATEWAY: &str = include_str!("../../tests/fixtures/snmp/unifi-gateway.walk");
pub(crate) const SWITCH: &str = include_str!("../../tests/fixtures/snmp/aruba-switch.walk");

/// Parses `snmpwalk -On` style lines (`.1.3.6... = TYPE: value`).
pub(crate) fn parse_walk(text: &str) -> Vec<VarBind> {
    let mut out: Vec<VarBind> = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (oid, rest) = line.split_once(" = ").expect("a walk line");
        let (typ, value) = rest
            .split_once(": ")
            .unwrap_or((rest.trim_end_matches(':'), ""));
        let value = match typ {
            "INTEGER" => Value::Integer(value.trim().parse().expect("integer")),
            "STRING" => Value::OctetString(value.as_bytes().to_vec()),
            "Hex-STRING" => Value::OctetString(
                value
                    .split_whitespace()
                    .map(|h| u8::from_str_radix(h, 16).expect("hex"))
                    .collect(),
            ),
            "OID" => Value::Oid(Oid::parse(value.trim().trim_start_matches('.')).expect("oid")),
            "Gauge32" => Value::Gauge32(value.trim().parse().expect("gauge")),
            other => panic!("walk type {other}"),
        };
        out.push(VarBind {
            oid: Oid::parse(oid.trim_start_matches('.')).expect("oid"),
            value,
        });
    }
    out.sort_by(|a, b| a.oid.cmp(&b.oid));
    out
}

/// A virtual clock shared by the poll and the fake agent: a pause moves it, nothing else does.
#[derive(Clone)]
pub(crate) struct Clock(Rc<Cell<Instant>>);

impl Clock {
    pub(crate) fn new() -> Self {
        Self(Rc::new(Cell::new(Instant::now())))
    }

    pub(crate) fn advance(&self, d: Duration) {
        self.0.set(self.0.get() + d);
    }
}

impl Pacer for Clock {
    fn now(&self) -> Instant {
        self.0.get()
    }

    fn pause(&mut self, d: Duration) {
        self.advance(d);
    }
}

/// What a fake agent does with each request.
#[derive(Clone, Copy, Default)]
pub(crate) enum Behaviour {
    #[default]
    Answer,
    /// Every exchange times out (after its retries).
    Silent,
    /// The first `n` exchanges answer, the rest time out.
    SilentAfter(u32),
    /// Every exchange gets a USM Report back (a wrong v3 credential).
    Refused,
    /// Each answer takes this long on the virtual clock.
    Slow(Duration),
}

/// A fake agent serving a sorted MIB. Every request is logged with the virtual time it arrived.
pub(crate) struct FakeMib {
    pub(crate) rows: Vec<VarBind>,
    pub(crate) clock: Clock,
    pub(crate) log: RefCell<Vec<(Instant, &'static str, Oid)>>,
    pub(crate) behaviour: Behaviour,
    pub(crate) level: &'static str,
    exchanges: u32,
    began: u32,
    ended: u32,
}

impl FakeMib {
    pub(crate) fn new(rows: Vec<VarBind>, clock: &Clock) -> Self {
        Self {
            rows,
            clock: clock.clone(),
            log: RefCell::new(Vec::new()),
            behaviour: Behaviour::Answer,
            level: "v2c",
            exchanges: 0,
            began: 0,
            ended: 0,
        }
    }

    pub(crate) fn from_walk(text: &str, clock: &Clock) -> Self {
        Self::new(parse_walk(text), clock)
    }

    /// Removes every row under `prefix` (a table the device doesn't serve).
    pub(crate) fn without(mut self, prefix: &str) -> Self {
        let p = Oid::parse(prefix).expect("prefix");
        self.rows.retain(|r| !r.oid.starts_with(&p));
        self
    }

    pub(crate) fn rounds(&self) -> (u32, u32) {
        (self.began, self.ended)
    }

    /// The requests that went to OIDs under `prefix`.
    pub(crate) fn requests_under(&self, prefix: &str) -> usize {
        let p = Oid::parse(prefix).expect("prefix");
        self.log
            .borrow()
            .iter()
            .filter(|(_, _, o)| o.starts_with(&p))
            .count()
    }

    fn gate(&mut self, kind: &'static str, oid: &Oid) -> Result<(), AgentError> {
        self.log
            .borrow_mut()
            .push((self.clock.now(), kind, oid.clone()));
        self.exchanges += 1;
        match self.behaviour {
            Behaviour::Silent => Err(AgentError::Timeout),
            Behaviour::Refused => Err(AgentError::ReportRefused),
            Behaviour::SilentAfter(n) if self.exchanges > n => Err(AgentError::Timeout),
            Behaviour::Slow(d) => {
                self.clock.advance(d);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn after(&self, oid: &Oid, max: usize) -> Vec<VarBind> {
        let v: Vec<VarBind> = self
            .rows
            .iter()
            .filter(|r| r.oid > *oid)
            .take(max)
            .cloned()
            .collect();
        if v.is_empty() {
            vec![VarBind {
                oid: oid.clone(),
                value: Value::EndOfMibView,
            }]
        } else {
            v
        }
    }

    fn response(varbinds: Vec<VarBind>) -> Response {
        Response {
            tag: TAG_RESPONSE,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds,
        }
    }
}

impl Bulk for FakeMib {
    fn bulk(&mut self, oid: &Oid, max: u32) -> Result<Response, AgentError> {
        self.gate("bulk", oid)?;
        Ok(Self::response(self.after(oid, max as usize)))
    }
}

impl Source for FakeMib {
    fn first_after(&mut self, oid: &Oid) -> Result<Response, AgentError> {
        self.gate("next", oid)?;
        Ok(Self::response(self.after(oid, 1)))
    }

    fn get_one(&mut self, oid: &Oid) -> Result<Response, AgentError> {
        self.gate("get", oid)?;
        let v = self
            .rows
            .iter()
            .find(|r| r.oid == *oid)
            .cloned()
            .unwrap_or(VarBind {
                oid: oid.clone(),
                value: Value::NoSuchInstance,
            });
        Ok(Self::response(vec![v]))
    }

    fn begin(&mut self) -> Result<(), AgentError> {
        self.began += 1;
        Ok(())
    }

    fn end(&mut self) {
        self.ended += 1;
    }

    fn level(&self) -> String {
        self.level.to_owned()
    }
}

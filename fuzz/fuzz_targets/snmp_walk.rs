//! REQ: DSC-003, DSC-004 — the bounded walker over replies that arrive as bytes (ADR-908).
//! The input is cut into datagrams; each one is decoded as a v2c reply and handed to the
//! walker as its next GETBULK answer. The walk must end within its caps, and must never loop
//! or panic on a reply that goes backwards.
#![no_main]

use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use telltale_snmp::agent::AgentError;
use telltale_snmp::oid::Oid;
use telltale_snmp::pdu::Response;
use telltale_snmp::v2c;
use telltale_snmp::walk::{self, Bulk, Limits, Pacer};

struct Replay {
    replies: Vec<Vec<u8>>,
    next: usize,
}

impl Bulk for Replay {
    fn bulk(&mut self, _oid: &Oid, _max_repetitions: u32) -> Result<Response, AgentError> {
        let Some(bytes) = self.replies.get(self.next) else {
            return Err(AgentError::Timeout);
        };
        self.next = self.next.saturating_add(1);
        v2c::decode(bytes).map(|d| d.response).map_err(AgentError::Decode)
    }
}

struct Clock {
    t: Instant,
}

impl Pacer for Clock {
    fn now(&self) -> Instant {
        self.t
    }

    fn pause(&mut self, d: Duration) {
        self.t = self.t.checked_add(d).unwrap_or(self.t);
    }
}

fuzz_target!(|data: &[u8]| {
    let replies: Vec<Vec<u8>> = data.chunks(97).map(<[u8]>::to_vec).collect();
    let Some(root) = Oid::parse("1.3.6.1.2.1") else { return };
    let mut agent = Replay { replies, next: 0 };
    let mut clock = Clock { t: Instant::now() };
    let _ = walk::walk(&mut agent, &mut clock, &root, &Limits::default());
});

//! SNMP for the network inventory (M25): a hand-written BER codec, the v2c and v3 USM read
//! client, and a bounded walker. Read `PDUs` only (DSC-003, ADR-908, ADR-911).
//!
//! The crate runs in the discovery worker process, off the DNS hot path. Its lints follow
//! ADR-908: no `unsafe`, and no indexing, unchecked arithmetic, panics or unreachable arms.

#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::unreachable
)]

pub mod aes_cfb;
pub mod agent;
pub mod ber;
pub mod creds;
pub mod dest;
pub mod oid;
pub mod pdu;
pub mod secret;
pub mod usm;
pub mod v2c;
pub mod walk;

pub use agent::{Agent, AgentError, Security, Timing};
pub use oid::Oid;
pub use pdu::{RequestKind, Response, Value, VarBind};
pub use secret::SecretValue;

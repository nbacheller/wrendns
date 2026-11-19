//! Cluster membership, PKI, snapshot replication, fencing, federation.
//!
//! Part of WrenDNS. See `spec/02-architecture.md` §2.

// REQ: NFR-003 — no unsafe outside wrendns-net.
#![forbid(unsafe_code)]

pub mod clock;
pub mod election;
pub mod failover;
pub mod net;
pub mod node;
pub mod pki;
pub mod removal;
pub mod renew;
pub mod rotation;
pub mod sync;
pub mod token;
pub mod wire;

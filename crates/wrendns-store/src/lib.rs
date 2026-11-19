//! Columnar query-log segment store and SQLite state.
//!
//! Part of WrenDNS. See `spec/02-architecture.md` §2 and `spec/06` §3–4.

// REQ: NFR-003 — no unsafe outside wrendns-net.
#![forbid(unsafe_code)]

pub mod cmdb;
pub mod qlog;
pub mod rollup;
pub mod state;

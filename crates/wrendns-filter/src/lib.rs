//! Blocklist parsers, rule compiler, FST/DFA snapshot format, and matcher.
//!
//! Part of WrenDNS. See `spec/02-architecture.md` §2.

// REQ: NFR-003 — no unsafe outside wrendns-net.
#![forbid(unsafe_code)]

pub mod compile;
pub mod explain;
pub mod fetch;
pub mod matcher;
pub mod parse;
pub mod rewrite;
pub mod snapshot;

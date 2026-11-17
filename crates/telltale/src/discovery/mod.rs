//! The network inventory (M25, ADR-907..913). It only reads: the local neighbour table, the
//! routers' and mDNS lease views, and scans the owner uploads. It never probes, sweeps or
//! schedules scans (ADR-907), and its data never reaches DNS names, policy or client matching
//! (ADR-910). Nothing starts it until `[discovery]` (T25.2) exists, so it is off by default.
//!
//! Module lints as in ADR-908: no `unsafe`, no indexing, no unchecked arithmetic, no panics.

#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::unreachable
)]
// REQ: DSC-001 — nothing spawns the thread until T25.2's `[discovery]` section exists.
#![allow(dead_code)]

pub(crate) mod inventory;
pub(crate) mod sources;
pub(crate) mod store;
pub(crate) mod thread;

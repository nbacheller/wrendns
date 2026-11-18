//! The network inventory (M25, ADR-907..913). It only reads: the local neighbour table, the
//! routers' and mDNS lease views, and scans the owner uploads. It never probes, sweeps or
//! schedules scans (ADR-907), and its data never reaches DNS names, policy or client matching
//! (ADR-910). `[discovery]` is the switch, and it is off by default (DSC-001).
//!
//! Module lints as in ADR-908: no `unsafe`, no indexing, no unchecked arithmetic, no panics.

#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::unreachable
)]
pub(crate) mod frames;
pub(crate) mod gate;
// REQ: DSC-008, DSC-009 — the readers of these modules are used by the API (T25.12) and the
// import parser (T25.11); until those land, the tests are their only callers.
#[allow(dead_code)]
pub(crate) mod inventory;
pub(crate) mod reads;
pub(crate) mod runtime;
// REQ: DSC-008, DSC-009 — the readers of these modules are used by the API (T25.12) and the
// import parser (T25.11); until those land, the tests are their only callers.
#[allow(dead_code)]
pub(crate) mod sources;
// REQ: DSC-008, DSC-009 — the readers of these modules are used by the API (T25.12) and the
// import parser (T25.11); until those land, the tests are their only callers.
#[allow(dead_code)]
pub(crate) mod store;
pub(crate) mod supervisor;
pub(crate) mod thread;
pub(crate) mod worker;

//! The CMDB (M31, ADR-1004, ADR-1005). One configuration item (CI) per real thing on the network,
//! built from every source that reports on it. It only reads (no SNMP SET, no write to a gateway,
//! no probe), runs on one thread of its own on the node `[discovery]` designates, and its data
//! never reaches DNS answers, client matching, `Neighbors`, `identify`, policy or device names in
//! DNS (DSC-901): no module outside this one and the API reads it (the test
//! `dsc_901_no_policy_code_reads_the_cmdb` guards that). `[cmdb]` is the switch, off by default.

#![forbid(unsafe_code)]

pub(crate) mod adapters;
pub(crate) mod apply;
pub(crate) mod engine;
pub(crate) mod inbox;
pub(crate) mod manual;
pub(crate) mod model;
pub(crate) mod replication;
pub(crate) mod resolve;
pub(crate) mod runtime;
pub(crate) mod thread;
pub(crate) mod view;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_manual;
#[cfg(test)]
mod tests_property;

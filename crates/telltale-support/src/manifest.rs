//! REQ: OPS-011 (ADR-156) — the manifest: every file, which collector made it, whether it is
//! whole, and how many values of each kind were removed or replaced in it (counts, never values).

use std::collections::BTreeMap;

use serde::Serialize;

use crate::Level;

/// How a file came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    /// Cut to fit the size cap (`note` says how).
    Truncated,
    /// Its collector was slow or failed (`note` says why); there is no file.
    Missing,
}

/// One file of the package.
#[derive(Debug, Clone, Serialize)]
pub struct FileEntry {
    pub path: String,
    pub collector: String,
    pub bytes: usize,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Values removed or replaced in this file, by kind.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub redactions: BTreeMap<String, u32>,
}

/// `MANIFEST.json`.
#[derive(Debug, Clone, Serialize)]
pub struct Manifest {
    pub package: &'static str,
    pub format: u32,
    /// When it was made (RFC 3339, UTC).
    pub created: String,
    pub level: Level,
    /// What the level means for reading the package.
    pub level_means: String,
    pub files: Vec<FileEntry>,
    /// Values removed or replaced in the whole package, by kind.
    pub redactions: BTreeMap<String, u32>,
    /// Configuration fields removed as secrets (their paths, never their values).
    pub config_fields_removed: Vec<String>,
    /// Configuration fields no class covered: removed too (a bug to report).
    pub config_fields_unclassified: Vec<String>,
    pub notes: Vec<String>,
}

impl Manifest {
    /// This manifest as pretty JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_owned())
    }
}

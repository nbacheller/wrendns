//! `inventory.json` (DSC-008, ADR-910): mode 0600, written atomically, at most once per 15 min
//! (once a minute after an import or a `public` pass), and never part of a backup. The backup
//! takes an explicit list of files, and `inventory.json` is not on it.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::inventory::{Entry, ImportRecord, Inventory, Mute};

/// The file name under the data directory.
pub(crate) const FILE_NAME: &str = "inventory.json";
/// The stored format version. A different one is refused (start empty, log).
const VERSION: u32 = 1;
/// The longest gap between saves in the ordinary case (ADR-910).
pub(crate) const WRITE_EVERY_SECS: u64 = 900;
/// The gap after an import or a `public` pass (ADR-910).
pub(crate) const FAST_WRITE_SECS: u64 = 60;

#[derive(Serialize, Deserialize)]
struct Stored {
    version: u32,
    learning_until: u64,
    entries: Vec<Entry>,
    imports: Vec<ImportRecord>,
    mutes: Vec<Mute>,
}

/// The inventory file's path under `data_dir`.
pub(crate) fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

/// Serialises an inventory.
pub(crate) fn to_json(inv: &Inventory) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&Stored {
        version: VERSION,
        learning_until: inv.learning_until(),
        entries: inv.entries().cloned().collect(),
        imports: inv.imports().to_vec(),
        mutes: inv.mutes().to_vec(),
    })
}

/// Parses an inventory. `None` when the bytes are not one of ours.
pub(crate) fn from_json(bytes: &[u8]) -> Option<Inventory> {
    let s: Stored = serde_json::from_slice(bytes).ok()?;
    if s.version != VERSION {
        return None;
    }
    Some(Inventory::restore(
        s.entries,
        s.imports,
        s.mutes,
        s.learning_until,
    ))
}

/// Loads the inventory. A missing or unreadable file is an empty start, which begins a new
/// learning period (ADR-910).
pub(crate) fn load(data_dir: &Path, now: u64) -> Inventory {
    match fs::read(path(data_dir)) {
        Ok(bytes) => from_json(&bytes).unwrap_or_else(|| {
            tracing::warn!("inventory.json is not readable; starting empty");
            Inventory::new(now)
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Inventory::new(now),
        Err(e) => {
            tracing::warn!(error = %e, "inventory.json could not be read; starting empty");
            Inventory::new(now)
        }
    }
}

/// Writes the inventory atomically: a 0600 temporary file, synced, then renamed over the old one.
pub(crate) fn save(data_dir: &Path, inv: &Inventory) -> io::Result<()> {
    let bytes = to_json(inv).map_err(io::Error::other)?;
    let target = path(data_dir);
    let tmp = data_dir.join(format!("{FILE_NAME}.tmp"));
    // A stale temporary file from a crash is replaced, never reused.
    let _ = fs::remove_file(&tmp);
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, &target)
}

/// Whether a save is due now: the inventory changed, and the gap since the last save has
/// passed (a minute when an import or `public` pass asked for one, else 15 minutes).
pub(crate) fn write_due(dirty: bool, now: u64, last_write: u64, fast: bool) -> bool {
    let gap = if fast {
        FAST_WRITE_SECS
    } else {
        WRITE_EVERY_SECS
    };
    dirty && now >= last_write.saturating_add(gap)
}

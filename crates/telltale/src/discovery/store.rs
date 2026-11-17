//! `inventory.json` (DSC-008, ADR-910): mode 0600, written atomically, at most once per 15 min
//! (once a minute after an import or a `public` pass), and never part of a backup. The backup
//! takes an explicit list of files, and `inventory.json` is not on it.

use std::fs::{self, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::inventory::{Entry, ImportRecord, Inventory, Mute};

/// The file name under the data directory.
pub(crate) const FILE_NAME: &str = "inventory.json";
/// Where a file this version cannot read is moved, so the owner's data is kept (DSC-008).
pub(crate) const QUARANTINE_NAME: &str = "inventory.json.bad";
/// The stored format version. A different one is refused (start empty, quarantine the file).
const VERSION: u32 = 1;
/// The longest gap between saves in the ordinary case (ADR-910).
pub(crate) const WRITE_EVERY_SECS: u64 = 900;
/// The gap after an import or a `public` pass (ADR-910).
pub(crate) const FAST_WRITE_SECS: u64 = 60;

/// The stored form, read back. Owned, because it is what the file parses into.
#[derive(Deserialize)]
struct Stored {
    version: u32,
    learning_until: u64,
    entries: Vec<Entry>,
    imports: Vec<ImportRecord>,
    mutes: Vec<Mute>,
}

/// The stored form, written. It borrows the inventory, so a save copies nothing (the review's
/// memory finding: no second copy of every entry while saving).
#[derive(Serialize)]
struct StoredRef<'a> {
    version: u32,
    learning_until: u64,
    entries: Vec<&'a Entry>,
    imports: &'a [ImportRecord],
    mutes: &'a [Mute],
}

fn stored_ref(inv: &Inventory) -> StoredRef<'_> {
    StoredRef {
        version: VERSION,
        learning_until: inv.learning_until(),
        entries: inv.entries().collect(),
        imports: inv.imports(),
        mutes: inv.mutes(),
    }
}

/// The inventory file's path under `data_dir`.
pub(crate) fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

/// Serialises an inventory.
pub(crate) fn to_json(inv: &Inventory) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&stored_ref(inv))
}

/// Parses an inventory. `None` when the bytes are not one of ours, or are another version.
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

/// Moves a file this version cannot read aside, so its data survives the next save (DSC-008).
fn quarantine(data_dir: &Path) {
    let from = path(data_dir);
    if let Err(e) = fs::rename(&from, data_dir.join(QUARANTINE_NAME)) {
        tracing::warn!(error = %e, "inventory.json could not be moved aside");
    }
}

/// Loads the inventory. A missing file is an empty start, which begins a new learning period
/// (ADR-910). A file that cannot be read, or is another version, is moved aside first.
pub(crate) fn load(data_dir: &Path, now: u64) -> Inventory {
    match fs::read(path(data_dir)) {
        Ok(bytes) => from_json(&bytes).unwrap_or_else(|| {
            tracing::warn!("inventory.json is not readable by this version; starting empty");
            quarantine(data_dir);
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
/// The entries are streamed through a buffer, not copied into a second structure first.
pub(crate) fn save(data_dir: &Path, inv: &Inventory) -> io::Result<()> {
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
    let f = opts.open(&tmp)?;
    let mut w = BufWriter::new(f);
    serde_json::to_writer(&mut w, &stored_ref(inv)).map_err(io::Error::other)?;
    w.flush()?;
    let f = w.into_inner().map_err(io::Error::from)?;
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

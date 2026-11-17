//! REQ: DSC-003 — the crate is read-only (ADR-908): it has no write PDU and no write tag. The
//! test reads the crate's own source, so a write PDU added later fails this test. The needles
//! are assembled at run time, so this file does not match them.

use std::fs;
use std::path::{Path, PathBuf};

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn dsc_003_no_write_pdu() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&src, &mut files);
    assert!(!files.is_empty(), "no sources found under {}", src.display());
    let needles = [
        concat!("Set", "Request"),
        concat!("set", "_request"),
        concat!("0x", "a3"),
        concat!("0x", "A3"),
        concat!("SNMP", "Set"),
    ];
    for file in &files {
        let text = fs::read_to_string(file).unwrap_or_default();
        for needle in needles {
            assert!(!text.contains(needle), "{} names a write PDU: {needle}", file.display());
        }
    }
}

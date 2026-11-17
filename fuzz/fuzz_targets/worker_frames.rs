//! REQ: DSC-002 (T25.3, ADR-908) — the frame reader between the main process and a discovery
//! worker must never panic, must refuse an over-cap frame before allocating its payload, and must
//! give back exactly the bytes it read: whatever a frame decodes to re-encodes to its own bytes.
//!
//! The frame code is included by path, so the fuzzer runs the same source the server builds.
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/telltale/src/discovery/frames.rs"]
#[allow(dead_code)]
mod frames;

fuzz_target!(|data: &[u8]| {
    let mut rd = data;
    let mut consumed = 0usize;
    while let Ok(frame) = frames::read_frame(&mut rd) {
        let bytes = frames::encode(&frame).expect("a frame that was read re-encodes");
        assert!(data[consumed..].starts_with(&bytes), "a frame re-encodes to different bytes");
        consumed += bytes.len();
    }
});

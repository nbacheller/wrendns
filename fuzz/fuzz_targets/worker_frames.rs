//! REQ: DSC-002 (T25.3, ADR-908) — the frame readers between the main process and a discovery
//! worker must never panic, must refuse an over-cap frame before allocating its payload, must give
//! back exactly the bytes they read (whatever a frame decodes to re-encodes to its own bytes), and
//! must agree with each other: the worker's synchronous reader (`read_frame`) and the main
//! process's async reader (`read_frame_async`, the side that reads untrusted bytes) return the same
//! frame or the same error for every input (REQ: DSC-002, ADR-929).
//!
//! The frame code is included by path, so the fuzzer runs the same source the server builds.
#![no_main]

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/wrendns/src/discovery/frames.rs"]
#[allow(dead_code)]
mod frames;

/// Polls a future that reads from a byte slice. Such a read never waits, so one poll finishes it.
fn ready<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => unreachable!("a read from a slice never waits"),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut sync_rd = data;
    let mut async_rd = data;
    let mut consumed = 0usize;
    loop {
        let sync = frames::read_frame(&mut sync_rd);
        let asynced = ready(frames::read_frame_async(&mut async_rd));
        assert_eq!(sync, asynced, "the two readers disagree");
        let Ok(frame) = sync else {
            break;
        };
        let bytes = frames::encode(&frame).expect("a frame that was read re-encodes");
        assert!(data[consumed..].starts_with(&bytes), "a frame re-encodes to different bytes");
        consumed += bytes.len();
    }
});

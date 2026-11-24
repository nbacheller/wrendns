// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: UPS-001 (fork #83) — the HTTP/1.1 response reader of a DoH upstream reads bytes from a
//! server that may be hostile: it must never panic, must never return a body over the DNS message
//! maximum, must never read more than its input cap, and must give the same answer however the
//! bytes arrive (all at once, or one at a time).
//!
//! The reader is included by path, so the fuzzer runs the same source the server builds.
#![no_main]

use std::future::Future;
use std::io;
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};

use libfuzzer_sys::fuzz_target;
use tokio::io::{AsyncRead, ReadBuf};

#[path = "../../crates/wrendns-upstream/src/http1.rs"]
#[allow(dead_code)]
mod http1;

/// Polls a future that reads from memory. Such a read never waits, so one poll finishes it.
fn ready<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => unreachable!("a read from memory never waits"),
    }
}

/// Hands out at most `step` bytes per read, and counts what it gave.
struct Trickle<'a> {
    data: &'a [u8],
    step: usize,
    given: usize,
}

impl AsyncRead for Trickle<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = self.step.min(buf.remaining()).min(self.data.len());
        let (head, rest) = self.data.split_at(n);
        buf.put_slice(head);
        self.data = rest;
        self.given += n;
        Poll::Ready(Ok(()))
    }
}

/// What a result says, without the text of an I/O error.
fn shape(r: &Result<http1::Response, http1::Error>) -> String {
    match r {
        Ok(r) => format!("{r:?}"),
        Err(http1::Error::Bad(why)) => format!("bad: {why}"),
        Err(http1::Error::Closed) => "closed".into(),
        Err(http1::Error::Io(_)) => "io".into(),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut whole = Trickle { data, step: usize::MAX, given: 0 };
    let a = ready(http1::read_response(&mut whole));
    let mut slow = Trickle { data, step: 1, given: 0 };
    let b = ready(http1::read_response(&mut slow));
    assert_eq!(shape(&a), shape(&b), "the answer depends on how the bytes arrive");
    for given in [whole.given, slow.given] {
        assert!(given <= http1::MAX_INPUT + 2048, "read past the input cap");
    }
    if let Ok(r) = &a {
        assert!(r.body.len() <= http1::MAX_BODY, "a body over the DNS message maximum");
    }
});

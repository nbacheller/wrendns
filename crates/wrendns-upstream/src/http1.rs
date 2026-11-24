// SPDX-License-Identifier: AGPL-3.0-or-later
//! A strict HTTP/1.1 response reader for DoH upstreams that do not speak HTTP/2.
//!
//! REQ: UPS-001, UPS-008 — the answer to one RFC 8484 request on a keep-alive connection. It
//! reads from an untrusted server, so every length is checked against a cap before anything is
//! allocated or read for it: the status line and headers together take at most [`MAX_HEAD`]
//! bytes, the body at most [`MAX_BODY`] (the DNS message maximum), and the whole response at
//! most [`MAX_INPUT`] bytes read, so a stream of tiny chunks ends too. Lines end in CRLF (a bare
//! LF is refused), header folding is refused, and anything the parser does not understand is an
//! error, never a guess: a status that is not three digits, a `Content-Length` that is not
//! plain digits or appears twice, both `Content-Length` and `Transfer-Encoding`, a transfer
//! coding other than `chunked`, a body with neither length nor chunks, a chunk that is not
//! followed by CRLF.
//!
//! This file takes nothing from the rest of the crate, so the fuzz target `http1_response`
//! includes it by path and runs the code the server builds.

use std::io;
use std::ops::Range;

use tokio::io::{AsyncRead, AsyncReadExt};

/// The DNS message maximum: the most a response body may carry.
pub(crate) const MAX_BODY: usize = 65_535;
/// The status line, headers and trailers together.
pub(crate) const MAX_HEAD: usize = 16 * 1024;
/// Everything read for one response, chunk framing included.
pub(crate) const MAX_INPUT: usize = MAX_HEAD + 4 * MAX_BODY;
/// A chunk-size line: the size and any extension.
const MAX_CHUNK_LINE: usize = 64;
/// Hex digits accepted for a chunk size (leading zeros included): at most 32 bits, so the value
/// fits a `usize` on every target before it is compared with anything.
const MAX_CHUNK_DIGITS: usize = 8;

/// Why a response could not be read.
#[derive(Debug)]
pub(crate) enum Error {
    /// The stream ended, or failed, before the first byte of the response: a kept-alive
    /// connection the server had already closed. The request may be sent again on a new one.
    Closed,
    /// The stream failed or ended part-way through the response.
    Io(io::Error),
    /// The server sent something this reader refuses.
    Bad(&'static str),
}

/// One response.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Response {
    pub status: u16,
    /// Empty unless the status is 200 (anything else is the caller's error; the body is not read).
    pub body: Vec<u8>,
    /// The connection may carry another request: HTTP/1.1 without `Connection: close` (or
    /// HTTP/1.0 with `keep-alive`), the whole body read and nothing sent beyond it.
    pub keep_alive: bool,
}

struct Input<'a, R> {
    rd: &'a mut R,
    buf: Vec<u8>,
    pos: usize,
    read: usize,
}

impl<R: AsyncRead + Unpin> Input<'_, R> {
    /// Reads more; ranges handed out earlier are no longer valid.
    async fn fill(&mut self) -> Result<(), Error> {
        if self.read >= MAX_INPUT {
            return Err(Error::Bad("response too large"));
        }
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let mut tmp = [0u8; 2048];
        let n = match self.rd.read(&mut tmp).await {
            Ok(n) => n,
            Err(e) if self.read == 0 => {
                let _ = e;
                return Err(Error::Closed);
            }
            Err(e) => return Err(Error::Io(e)),
        };
        if n == 0 {
            return Err(if self.read == 0 {
                Error::Closed
            } else {
                Error::Io(io::ErrorKind::UnexpectedEof.into())
            });
        }
        self.read = self.read.saturating_add(n);
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(())
    }

    fn avail(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// The next CRLF-ended line, at most `max` bytes without the CRLF, as a range of `buf`
    /// valid until the next [`fill`](Self::fill).
    async fn line(&mut self, max: usize) -> Result<Range<usize>, Error> {
        loop {
            let a = self.avail();
            if let Some(i) = a.iter().position(|b| *b == b'\n') {
                if i == 0 || a[i - 1] != b'\r' {
                    return Err(Error::Bad("line not ended by CRLF"));
                }
                if i - 1 > max {
                    return Err(Error::Bad("line too long"));
                }
                let r = self.pos..self.pos + i - 1;
                self.pos += i + 1;
                return Ok(r);
            }
            if a.len() > max.saturating_add(1) {
                return Err(Error::Bad("line too long"));
            }
            self.fill().await?;
        }
    }

    /// At least `n` bytes available (`n` is already checked against a cap).
    async fn need(&mut self, n: usize) -> Result<(), Error> {
        while self.avail().len() < n {
            self.fill().await?;
        }
        Ok(())
    }
}

fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A header value or reason phrase: visible ASCII, space and tab, and obs-text; no control
/// characters (a stray CR or NUL here is a smuggling attempt, not text).
fn is_text(b: u8) -> bool {
    b == b'\t' || (0x20..0x7f).contains(&b) || b >= 0x80
}

fn trim(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

/// A chunk size: 1 to [`MAX_CHUNK_DIGITS`] hex digits, in checked arithmetic.
fn chunk_size(hex: &[u8]) -> Option<usize> {
    if hex.is_empty() || hex.len() > MAX_CHUNK_DIGITS {
        return None;
    }
    hex.iter().try_fold(0usize, |n, d| {
        let v = usize::try_from(char::from(*d).to_digit(16)?).ok()?;
        n.checked_mul(16)?.checked_add(v)
    })
}

/// Whether a chunk of `size` bytes fits in the room left under [`MAX_BODY`] after `have` bytes.
/// Compares with the remaining room, so nothing is added to a peer-supplied number.
fn chunk_fits(have: usize, size: usize) -> bool {
    size <= MAX_BODY.saturating_sub(have)
}

fn digits(v: &[u8]) -> Option<usize> {
    if v.is_empty() || v.len() > 9 || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    v.iter().try_fold(0usize, |n, d| {
        n.checked_mul(10)?.checked_add(usize::from(d - b'0'))
    })
}

/// `HTTP/1.x SP 3DIGIT [SP reason]`: the status, and whether the version is 1.0.
fn status_line(l: &[u8]) -> Result<(u16, bool), Error> {
    if l.len() < 12 || !l.starts_with(b"HTTP/1.") || !matches!(l[7], b'0' | b'1') || l[8] != b' ' {
        return Err(Error::Bad("not an HTTP/1 status line"));
    }
    if !(l[9..12].iter().all(u8::is_ascii_digit)) || (l.len() > 12 && l[12] != b' ') {
        return Err(Error::Bad("bad status code"));
    }
    if !l[12..].iter().copied().all(is_text) {
        return Err(Error::Bad("bad reason phrase"));
    }
    let status = digits(&l[9..12])
        .and_then(|s| u16::try_from(s).ok())
        .unwrap_or(0);
    if status < 100 {
        return Err(Error::Bad("bad status code"));
    }
    Ok((status, l[7] == b'0'))
}

/// Reads one response from `rd`.
pub(crate) async fn read_response<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Response, Error> {
    let mut inp = Input {
        rd,
        buf: Vec::with_capacity(1024),
        pos: 0,
        read: 0,
    };
    let mut head = 0usize;

    let r = inp.line(MAX_HEAD).await?;
    head = head.saturating_add(r.len()).saturating_add(2);
    let (status, http10) = status_line(&inp.buf[r])?;

    let (mut length, mut chunked) = (None::<usize>, false);
    let (mut close, mut keep) = (false, false);
    let mut seen_te = false;
    loop {
        let r = inp.line(MAX_HEAD.saturating_sub(head)).await?;
        head = head.saturating_add(r.len()).saturating_add(2);
        if head > MAX_HEAD {
            return Err(Error::Bad("headers too large"));
        }
        let l = &inp.buf[r];
        if l.is_empty() {
            break;
        }
        if l[0] == b' ' || l[0] == b'\t' {
            return Err(Error::Bad("folded header"));
        }
        let Some(colon) = l.iter().position(|b| *b == b':') else {
            return Err(Error::Bad("header without a colon"));
        };
        let (name, value) = (&l[..colon], trim(&l[colon + 1..]));
        if name.is_empty() || !name.iter().copied().all(is_token) {
            return Err(Error::Bad("bad header name"));
        }
        if !value.iter().copied().all(is_text) {
            return Err(Error::Bad("bad header value"));
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            if length.is_some() {
                return Err(Error::Bad("repeated Content-Length"));
            }
            let n = digits(value).ok_or(Error::Bad("bad Content-Length"))?;
            if n > MAX_BODY {
                return Err(Error::Bad("body too large"));
            }
            length = Some(n);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if seen_te || !value.eq_ignore_ascii_case(b"chunked") {
                return Err(Error::Bad("unsupported Transfer-Encoding"));
            }
            seen_te = true;
            chunked = true;
        } else if name.eq_ignore_ascii_case(b"connection") {
            for t in value.split(|b| *b == b',') {
                let t = trim(t);
                close |= t.eq_ignore_ascii_case(b"close");
                keep |= t.eq_ignore_ascii_case(b"keep-alive");
            }
        }
    }

    // 1xx (including 101) is never answered to a plain request; anything but 200 is the
    // caller's error and its body is not read.
    if status != 200 {
        if status < 200 {
            return Err(Error::Bad("unexpected informational response"));
        }
        return Ok(Response {
            status,
            body: Vec::new(),
            keep_alive: false,
        });
    }

    let body = match (length, chunked) {
        (Some(_), true) => return Err(Error::Bad("Content-Length with Transfer-Encoding")),
        (Some(n), false) => {
            inp.need(n).await?;
            let body = inp
                .avail()
                .get(..n)
                .ok_or(Error::Bad("body too short"))?
                .to_vec();
            inp.pos = inp.pos.saturating_add(n);
            body
        }
        (None, true) => read_chunked(&mut inp, &mut head).await?,
        (None, false) => return Err(Error::Bad("no Content-Length and not chunked")),
    };
    Ok(Response {
        status,
        body,
        // Bytes after the body were not asked for: do not trust the connection with another.
        keep_alive: !close && (!http10 || keep) && inp.avail().is_empty(),
    })
}

async fn read_chunked<R: AsyncRead + Unpin>(
    inp: &mut Input<'_, R>,
    head: &mut usize,
) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    loop {
        let r = inp.line(MAX_CHUNK_LINE).await?;
        let l = &inp.buf[r];
        // The size, then any extension (`;name=value`), which is ignored.
        let size = l.split(|b| *b == b';').next().unwrap_or_default();
        let Some(size) = chunk_size(size) else {
            return Err(Error::Bad("bad chunk size"));
        };
        if size == 0 {
            break;
        }
        if !chunk_fits(body.len(), size) {
            return Err(Error::Bad("body too large"));
        }
        // `size` is at most MAX_BODY here, so the sum cannot overflow; checked all the same.
        let end = size.checked_add(2).ok_or(Error::Bad("bad chunk size"))?;
        inp.need(end).await?;
        let a = inp.avail();
        let (Some(data), Some(crlf)) = (a.get(..size), a.get(size..end)) else {
            return Err(Error::Bad("chunk truncated"));
        };
        if crlf != b"\r\n" {
            return Err(Error::Bad("chunk not followed by CRLF"));
        }
        body.extend_from_slice(data);
        inp.pos = inp.pos.saturating_add(end);
    }
    // Trailers: lines up to the empty one, counted with the headers.
    loop {
        let r = inp.line(MAX_HEAD.saturating_sub(*head)).await?;
        *head = head.saturating_add(r.len()).saturating_add(2);
        if *head > MAX_HEAD {
            return Err(Error::Bad("trailers too large"));
        }
        if r.is_empty() {
            return Ok(body);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(wire: &[u8]) -> Result<Response, Error> {
        let mut rd = wire;
        read_response(&mut rd).await
    }

    /// REQ: UPS-001 — Content-Length and chunked bodies; keep-alive follows the version and
    /// `Connection`.
    #[tokio::test]
    async fn ups_001_http1_parser_reads_both_body_forms() {
        let r = parse(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
            .await
            .unwrap();
        assert_eq!(
            (r.status, r.body.as_slice(), r.keep_alive),
            (200, &b"abc"[..], true)
        );
        let r = parse(b"HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n2\r\nab\r\n1;x=y\r\nc\r\n0\r\nT: v\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(r.body, b"abc");
        let r = parse(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        assert!(!r.keep_alive);
        let r = parse(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        assert!(!r.keep_alive, "HTTP/1.0 closes by default");
        let r = parse(b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        assert!(r.keep_alive);
        let r = parse(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naEXTRA")
            .await
            .unwrap();
        assert!(!r.keep_alive, "bytes after the body: not reused");
        let r = parse(b"HTTP/1.1 503 Busy\r\nContent-Length: 999999\r\n\r\n");
        assert!(
            r.await.is_err(),
            "an over-cap length is refused whatever the status"
        );
        let r = parse(b"HTTP/1.1 503 Busy\r\nContent-Length: 5\r\n\r\n")
            .await
            .unwrap();
        assert_eq!((r.status, r.body.len(), r.keep_alive), (503, 0, false));
    }

    /// REQ: UPS-001 — a table of bad responses: each is an error, none panics or reads past
    /// its cap.
    #[tokio::test]
    async fn ups_001_http1_parser_refuses_bad_input() {
        let big_head = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        let many = format!("HTTP/1.1 200 OK\r\n{}\r\n", "X: a\r\n".repeat(MAX_HEAD / 5));
        let big_body = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        let big_chunk = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            MAX_BODY + 1
        );
        let tiny = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            "1\r\nx\r\n".repeat(MAX_INPUT / 6 + 10)
        );
        let table: Vec<(&str, Vec<u8>)> = vec![
            ("empty", b"".to_vec()),
            ("garbage", b"\x00\x01\x02\r\n\r\n".to_vec()),
            ("http2 line", b"HTTP/2 200\r\n\r\n".to_vec()),
            ("version 1.2", b"HTTP/1.2 200 OK\r\n\r\n".to_vec()),
            ("short code", b"HTTP/1.1 20 OK\r\n\r\n".to_vec()),
            ("letters in code", b"HTTP/1.1 2x0 OK\r\n\r\n".to_vec()),
            ("no space after code", b"HTTP/1.1 200OK\r\n\r\n".to_vec()),
            ("bare LF", b"HTTP/1.1 200 OK\nContent-Length: 0\n\n".to_vec()),
            ("NUL in reason", b"HTTP/1.1 200 O\0K\r\nContent-Length: 0\r\n\r\n".to_vec()),
            ("informational", b"HTTP/1.1 100 Continue\r\n\r\n".to_vec()),
            ("switching", b"HTTP/1.1 101 Switching\r\n\r\n".to_vec()),
            ("folded header", b"HTTP/1.1 200 OK\r\nA: b\r\n c\r\nContent-Length: 0\r\n\r\n".to_vec()),
            ("no colon", b"HTTP/1.1 200 OK\r\nAbc\r\nContent-Length: 0\r\n\r\n".to_vec()),
            ("space in name", b"HTTP/1.1 200 OK\r\nA b: c\r\nContent-Length: 0\r\n\r\n".to_vec()),
            ("empty name", b"HTTP/1.1 200 OK\r\n: c\r\nContent-Length: 0\r\n\r\n".to_vec()),
            ("CR in value", b"HTTP/1.1 200 OK\r\nA: b\rc\r\nContent-Length: 0\r\n\r\n".to_vec()),
            ("negative length", b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n".to_vec()),
            ("signed length", b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx".to_vec()),
            ("hex length", b"HTTP/1.1 200 OK\r\nContent-Length: 0x10\r\n\r\n".to_vec()),
            ("length overflow", b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n".to_vec()),
            ("empty length", b"HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n".to_vec()),
            ("two lengths", b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx".to_vec()),
            ("length and chunked", b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec()),
            ("gzip coding", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n".to_vec()),
            ("no framing", b"HTTP/1.1 200 OK\r\n\r\nabc".to_vec()),
            ("truncated head", b"HTTP/1.1 200 OK\r\nContent-Len".to_vec()),
            ("truncated body", b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc".to_vec()),
            ("body over cap", big_body.into_bytes()),
            ("head over cap", big_head.into_bytes()),
            ("too many headers", many.into_bytes()),
            ("chunk over cap", big_chunk.into_bytes()),
            ("chunk size not hex", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n".to_vec()),
            ("chunk size empty", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\n".to_vec()),
            ("chunk size long", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n000000001\r\nx\r\n0\r\n\r\n".to_vec()),
            ("chunk bad end", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxyz\r\n0\r\n\r\n".to_vec()),
            ("chunk truncated", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab".to_vec()),
            ("no last chunk", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n".to_vec()),
            ("trailers never end", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nT: v\r\n".to_vec()),
            ("tiny chunks without end", tiny.into_bytes()),
        ];
        for (name, wire) in table {
            match parse(&wire).await {
                Err(_) => {}
                Ok(r) => panic!("{name}: accepted as {r:?}"),
            }
        }
        // Before any byte: a closed connection, which the caller may retry.
        assert!(matches!(parse(b"").await, Err(Error::Closed)));
    }

    /// REQ: UPS-001 — the bound check compares with the room left and never adds a peer-supplied
    /// size to anything, so it holds on a 32-bit `usize` too: `1 + usize::MAX` wraps to 0 and
    /// would pass an addition-based check.
    #[test]
    fn ups_001_chunk_bound_check_cannot_overflow() {
        assert!(chunk_fits(0, MAX_BODY));
        assert!(chunk_fits(MAX_BODY, 0));
        assert!(!chunk_fits(0, MAX_BODY + 1));
        assert!(!chunk_fits(1, MAX_BODY));
        for size in [
            usize::MAX,
            usize::MAX - 1,
            u32::MAX as usize,
            usize::MAX / 2,
        ] {
            for have in [0, 1, 2, MAX_BODY, usize::MAX] {
                assert!(!chunk_fits(have, size), "have {have}, size {size}");
            }
        }
        assert_eq!(chunk_size(b"ffffffff"), Some(u32::MAX as usize));
        assert_eq!(chunk_size(b"FFFF"), Some(MAX_BODY));
        assert_eq!(chunk_size(b"0000000a"), Some(10));
        assert_eq!(chunk_size(b"fffffffff"), None);
        assert_eq!(chunk_size(b""), None);
        assert_eq!(chunk_size(b"g"), None);
    }

    /// REQ: UPS-001 — chunk sizes and `Content-Length` values at and beyond the 32- and 64-bit
    /// bounds, and very long digit strings: each is refused as an error, none panics.
    #[tokio::test]
    async fn ups_001_http1_parser_refuses_huge_lengths_and_chunk_sizes() {
        let chunked = |size: &str| {
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size}\r\nx\r\n0\r\n\r\n")
                .into_bytes()
        };
        let length =
            |n: &str| format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\nx").into_bytes();
        let mut sizes = vec![
            format!("{:x}", usize::MAX),
            format!("{:x}", u32::MAX),
            format!("{:x}", u64::MAX),
            format!("{:X}", u64::MAX),
            format!("{:x}", u64::from(u32::MAX) + 1),
            format!("{:x}", usize::MAX - 1),
            "7fffffff".to_owned(),
            "80000000".to_owned(),
            "ffffffff".to_owned(),
            "fffffffe".to_owned(),
            "10000".to_owned(),
            "f".repeat(9),
            "f".repeat(16),
            "f".repeat(17),
            "0".repeat(9) + "1",
            "f".repeat(60),
            "1".repeat(100_000),
            "ffffffff;ext=1".to_owned(),
        ];
        sizes.push(format!("{:x};{}", u64::MAX, "e".repeat(40)));
        for size in &sizes {
            let short: String = size.chars().take(24).collect();
            assert!(parse(&chunked(size)).await.is_err(), "chunk size {short}");
        }
        // A second chunk that would take the body over the cap, with the sum wrapping on 32 bits.
        let two = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n{:x}\r\n",
            usize::MAX
        );
        assert!(parse(two.as_bytes()).await.is_err());
        let two = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\nffffffff\r\n";
        assert!(parse(two.as_bytes()).await.is_err());

        let mut lengths = vec![
            usize::MAX.to_string(),
            u32::MAX.to_string(),
            u64::MAX.to_string(),
            (u64::from(u32::MAX) + 1).to_string(),
            i32::MAX.to_string(),
            (MAX_BODY + 1).to_string(),
            "999999999".to_owned(),
            "1000000000".to_owned(),
            "9".repeat(10),
            "9".repeat(20),
            "9".repeat(100_000),
            "0".repeat(100_000),
        ];
        lengths.push(format!("{}", u128::MAX));
        for n in &lengths {
            let short: String = n.chars().take(24).collect();
            assert!(parse(&length(n)).await.is_err(), "Content-Length {short}");
        }
        // At the bound: accepted, and the body is what was sent.
        let ok = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {MAX_BODY}\r\n\r\n{}",
            "a".repeat(MAX_BODY)
        );
        assert_eq!(parse(ok.as_bytes()).await.unwrap().body.len(), MAX_BODY);
        let ok = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            MAX_BODY,
            "a".repeat(MAX_BODY)
        );
        assert_eq!(parse(ok.as_bytes()).await.unwrap().body.len(), MAX_BODY);
    }
}

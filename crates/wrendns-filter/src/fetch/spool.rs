//! A list download that streams to disk (REQ: FLT-901, FLT-004; T24.29, design 2.4).
//!
//! A heavy category source (NRD 7 days, full TIF) is about 40 MB. Collecting it first, then
//! hashing, checking and compressing it, would hold the list, its parse and its compressed copy
//! in memory at once, on the node (a Pi) that can least afford it. A [`Spool`] takes the body as
//! it arrives: every piece is hashed, counted, checked line by line in small blocks and written
//! through a zstd encoder to `<name>.src.zst.tmp`, so what is held is a 64 KiB block, whatever the
//! list's size. The checks that decide whether the copy is kept (empty or HTML body, too many
//! invalid lines, shrunk, unchanged) are the same ones a buffered body gets, made from the
//! counters at the end. The finished file is renamed over the stored copy only when they pass.

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use zstd::stream::write::Encoder;

use super::http::BodySink;
use super::store::ZSTD_LEVEL;
use crate::parse::{ListOptions, ParseStats, RpzReader, parse_list};

/// Complete lines are checked in blocks of about this many bytes.
const BLOCK: usize = 64 * 1024;
/// A block with no line break past this is checked as it is.
const MAX_LINE: usize = 1024 * 1024;

/// What a finished spool knows about the body it took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Spooled {
    /// BLAKE3 of the raw body, hex.
    pub(crate) hash: String,
    pub(crate) bytes: u64,
    pub(crate) lines: u64,
    pub(crate) rules: u64,
    pub(crate) invalid: u64,
    /// The first invalid line's reason, for the refusal message.
    pub(crate) first_invalid: String,
    /// The first bytes of the body, for the empty-body and HTML-page checks.
    pub(crate) head: Vec<u8>,
    /// The most bytes the spool held in memory at once (a block of complete lines, not the body).
    pub(crate) peak_held: usize,
}

pub(crate) struct Spool {
    path: PathBuf,
    /// REQ: FLT-906 - how each block of the body is checked.
    format: wrendns_config::ListFormat,
    enc: Option<Encoder<'static, BufWriter<File>>>,
    hasher: blake3::Hasher,
    bytes: u64,
    newlines: u64,
    last: Option<u8>,
    head: Vec<u8>,
    block: Vec<u8>,
    rules: u64,
    invalid: u64,
    first_invalid: String,
    peak_held: usize,
    /// REQ: FLT-906 - an RPZ is checked by one reader that keeps its state from block to block
    /// (the inherited owner, `$ORIGIN`, an open parenthesis), and its totals so far.
    rpz: Option<(RpzReader, ParseStats)>,
}

impl Spool {
    /// A spool writing `<path>` (a `.tmp` next to the stored source).
    pub(crate) fn new(path: PathBuf, format: wrendns_config::ListFormat) -> Self {
        Self {
            path,
            format,
            enc: None,
            hasher: blake3::Hasher::new(),
            bytes: 0,
            newlines: 0,
            last: None,
            head: Vec::new(),
            block: Vec::new(),
            rules: 0,
            invalid: 0,
            first_invalid: String::new(),
            peak_held: 0,
            rpz: (format == wrendns_config::ListFormat::Rpz)
                .then(|| (RpzReader::default(), ParseStats::default())),
        }
    }

    /// An RPZ reader's totals so far, as the spool's own.
    fn take_totals(stats: &ParseStats, rules: &mut u64, invalid: &mut u64, first: &mut String) {
        *rules = stats.rules;
        *invalid = stats.invalid;
        if first.is_empty()
            && let Some(x) = stats.samples.iter().find(|x| !x.unsupported)
        {
            first.clone_from(&x.reason);
        }
    }

    fn check_block(&mut self, complete: &[u8]) {
        if let Some((reader, stats)) = self.rpz.as_mut() {
            let text = complete.strip_suffix(b"\n").unwrap_or(complete);
            for line in text.split(|&b| b == b'\n') {
                reader.feed(line, stats, &mut |_, _| {});
            }
            Self::take_totals(
                stats,
                &mut self.rules,
                &mut self.invalid,
                &mut self.first_invalid,
            );
            return;
        }
        let opts = ListOptions {
            format: self.format,
            ..ListOptions::default()
        };
        let s = parse_list(complete, opts, |_, _| {});
        self.rules += s.rules;
        self.invalid += s.invalid;
        if self.first_invalid.is_empty()
            && let Some(x) = s.samples.iter().find(|x| !x.unsupported)
        {
            self.first_invalid.clone_from(&x.reason);
        }
    }

    /// Ends the body: flushes the encoder and returns what was learned. The temp file is left
    /// in place for [`Self::commit`] or [`Self::discard`].
    pub(crate) fn finish(mut self) -> io::Result<(Spooled, Self)> {
        let rest = std::mem::take(&mut self.block);
        if !rest.is_empty() {
            self.check_block(&rest);
        }
        if let Some((reader, stats)) = self.rpz.as_mut() {
            // An open parenthesis at the end of the body is read as far as it goes.
            reader.finish(stats, &mut |_, _| {});
            Self::take_totals(
                stats,
                &mut self.rules,
                &mut self.invalid,
                &mut self.first_invalid,
            );
        }
        if let Some(enc) = self.enc.take() {
            let mut w = enc.finish()?;
            w.flush()?;
            w.into_inner()
                .map_err(io::IntoInnerError::into_error)?
                .sync_all()?;
        }
        let lines = self.newlines + u64::from(self.last.is_some_and(|b| b != b'\n'));
        let done = Spooled {
            hash: self.hasher.finalize().to_hex().to_string(),
            bytes: self.bytes,
            lines,
            rules: self.rules,
            invalid: self.invalid,
            first_invalid: std::mem::take(&mut self.first_invalid),
            head: std::mem::take(&mut self.head),
            peak_held: self.peak_held,
        };
        Ok((done, self))
    }

    /// Renames the finished temp file over `dest`.
    pub(crate) fn commit(self, dest: &Path) -> io::Result<()> {
        fs::rename(&self.path, dest)
    }

    /// Deletes the temp file (the body failed a check, or nothing changed).
    pub(crate) fn discard(self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl BodySink for Spool {
    fn reset(&mut self) -> Result<(), String> {
        *self = Self::new(std::mem::take(&mut self.path), self.format);
        let file = File::create(&self.path).map_err(|e| format!("cannot store source: {e}"))?;
        let enc = Encoder::new(BufWriter::new(file), ZSTD_LEVEL)
            .map_err(|e| format!("cannot store source: {e}"))?;
        self.enc = Some(enc);
        Ok(())
    }

    #[allow(clippy::naive_bytecount)] // once per piece of a download; not worth a dependency
    fn chunk(&mut self, data: &[u8]) -> Result<(), String> {
        let Some(enc) = self.enc.as_mut() else {
            return Err("cannot store source: the spool was not started".to_owned());
        };
        enc.write_all(data)
            .map_err(|e| format!("cannot store source: {e}"))?;
        self.hasher.update(data);
        self.bytes += data.len() as u64;
        self.newlines += data.iter().filter(|&&b| b == b'\n').count() as u64;
        if let Some(&b) = data.last() {
            self.last = Some(b);
        }
        if self.head.len() < 64 {
            let take = (64 - self.head.len()).min(data.len());
            self.head.extend_from_slice(&data[..take]);
        }
        self.block.extend_from_slice(data);
        self.peak_held = self.peak_held.max(self.block.len());
        if self.block.len() >= BLOCK {
            // A body with no line break in a megabyte is not a list: check it as it is rather
            // than scanning an ever longer block for a newline.
            let end = self
                .block
                .iter()
                .rposition(|&b| b == b'\n')
                .or_else(|| (self.block.len() > MAX_LINE).then(|| self.block.len() - 1));
            if let Some(end) = end {
                let complete: Vec<u8> = self.block.drain(..=end).collect();
                self.check_block(&complete);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;
    use std::io::Read;

    /// REQ: FLT-901 (design 2.4) — a 20 MB body goes to disk as it arrives: the spool holds a
    /// block of lines, never the body, and the stored copy is the body, byte for byte.
    #[test]
    fn flt_901_fetch_streams_to_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("big.src.zst.tmp");
        let mut spool = Spool::new(path.clone(), wrendns_config::ListFormat::Auto);
        spool.reset().unwrap();
        let mut body = Vec::new();
        let mut i = 0u64;
        while body.len() < 20 * 1024 * 1024 {
            body.extend_from_slice(
                format!(
                    "host-{i}.example.com
"
                )
                .as_bytes(),
            );
            i += 1;
        }
        // Not a multiple of a line: pieces end mid-line, as network reads do.
        for piece in body.chunks(16 * 1024 - 7) {
            spool.chunk(piece).unwrap();
        }
        let (done, spool) = spool.finish().unwrap();
        assert_eq!(done.bytes, body.len() as u64);
        assert_eq!(done.lines, i);
        assert_eq!((done.rules, done.invalid), (i, 0));
        assert_eq!(done.hash, blake3::hash(&body).to_hex().to_string());
        assert!(
            done.peak_held <= BLOCK + 16 * 1024,
            "held {} bytes of a {} byte body",
            done.peak_held,
            body.len()
        );
        let dest = tmp.path().join("big.src.zst");
        spool.commit(&dest).unwrap();
        let mut back = Vec::new();
        zstd::stream::read::Decoder::new(File::open(&dest).unwrap())
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert_eq!(back, body);
        assert!(!path.exists(), "the temp file became the stored copy");
    }

    /// REQ: FLT-004 — invalid lines are counted block by block, a final line without a newline
    /// counts, and a discarded spool leaves nothing behind.
    #[test]
    fn flt_004_spool_counts_and_discards() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("x.tmp");
        let mut spool = Spool::new(path.clone(), wrendns_config::ListFormat::Auto);
        spool.reset().unwrap();
        spool
            .chunk(
                b"ads.example.com
{\"x\": 1}
last.example",
            )
            .unwrap();
        let (done, spool) = spool.finish().unwrap();
        assert_eq!(done.lines, 3);
        assert_eq!(done.rules, 2);
        assert_eq!(done.invalid, 1);
        assert_ne!(done.first_invalid, "");
        spool.discard();
        assert!(!path.exists());
    }

    /// A zone's head and enough records to fill a checked block, then `tail` ending the block.
    fn rpz_first_block(tail: &str) -> (String, u64) {
        let mut first = String::from(
            "$ORIGIN rpz.example.net.\n@ SOA ns.rpz.example.net. a.example.net. 1 2 3 4 5\n",
        );
        let mut n = 0u64;
        while first.len() < BLOCK {
            let _ = writeln!(first, "h{n}.example.com CNAME .");
            n += 1;
        }
        first.push_str(tail);
        (first, n)
    }

    fn rpz_check(first: &str, second: &[u8]) -> (u64, u64, String) {
        let tmp = tempfile::tempdir().unwrap();
        let mut spool = Spool::new(tmp.path().join("rpz.tmp"), wrendns_config::ListFormat::Rpz);
        spool.reset().unwrap();
        spool.chunk(first.as_bytes()).unwrap();
        spool.chunk(second).unwrap();
        let (done, spool) = spool.finish().unwrap();
        spool.discard();
        (done.rules, done.invalid, done.first_invalid)
    }

    /// REQ: FLT-906 - an RPZ record that leaves its owner out at the start of a checked block
    /// takes the owner the block before ended on, as it does in the compile.
    #[test]
    fn flt_906_spool_rpz_inherited_owner_across_blocks() {
        let (first, n) = rpz_first_block("own.example.com CNAME .\n");
        let (rules, invalid, why) =
            rpz_check(&first, b"\tIN A 192.0.2.1\nlast.example.com CNAME .\n");
        assert_eq!(invalid, 0, "{why}");
        assert_eq!(rules, n + 3);
    }

    /// REQ: FLT-906 - a parenthesised RPZ record split across the edge of a checked block.
    #[test]
    fn flt_906_spool_rpz_open_parenthesis_across_blocks() {
        let (first, n) = rpz_first_block("paren.example.com CNAME (\n");
        let (rules, invalid, why) = rpz_check(&first, b". )\nlast.example.com CNAME .\n");
        assert_eq!(invalid, 0, "{why}");
        assert_eq!(rules, n + 2);
    }
}

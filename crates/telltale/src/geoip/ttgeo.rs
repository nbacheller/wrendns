//! REQ: OBS-902 (T26.4, ADR-959 sections 4 and 5, ADR-1008) - the `.ttgeo` country database:
//! parsing and verifying the publisher's CSV, building the compact file, writing it atomically,
//! and looking an address up in it by positional reads.
//!
//! The file is a 40-byte header, a sorted IPv4 table (start `u32`, country `u16`, 6 bytes a row)
//! and a sorted IPv6 table (the first 64 bits `u64`, country `u16`, 10 bytes a row). The tables
//! have no end column, so the builder stores an explicit gap row (country 0) wherever one range
//! ends before the next begins: without it an address in a gap would resolve to the country
//! before it. A lookup is a binary search with `pread` through the OS page cache. Nothing of the
//! file is held on the heap and it is not memory-mapped (`unsafe` is allowed only in
//! `telltale-net`, AGENTS rule 7), so the resident set does not grow with the database.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// The file name inside `<data_dir>/geoip/`.
pub(crate) const FILE: &str = "country.ttgeo";
const MAGIC: [u8; 8] = *b"TTGEO\0\0\x01";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 40;
const REC4: u64 = 6;
const REC6: u64 = 10;
/// The largest file the node builds or reads (ADR-959 section 5).
pub(crate) const MAX_FILE: u64 = 16 * 1024 * 1024;
/// The longest CSV line read: a longer one is malformed, not buffered.
const MAX_LINE: usize = 256;

/// What a database must hold to be accepted (ADR-959 section 4). Tests use a small set; the
/// production values are [`Limits::PRODUCTION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) min_rows: u64,
    pub(crate) min_countries: usize,
    /// A new database may differ from the one it replaces by at most this percent of rows.
    pub(crate) max_change_pct: u64,
    /// Compressed bytes read from the network.
    pub(crate) max_download: u64,
    /// Uncompressed bytes parsed.
    pub(crate) max_inflated: u64,
}

impl Limits {
    pub(crate) const PRODUCTION: Self = Self {
        min_rows: 100_000,
        min_countries: 150,
        max_change_pct: 30,
        max_download: 32 * 1024 * 1024,
        max_inflated: 96 * 1024 * 1024,
    };
    /// A fake source in a test serves a handful of rows.
    pub(crate) const TEST: Self = Self {
        min_rows: 6,
        min_countries: 2,
        max_change_pct: 30,
        max_download: 32 * 1024 * 1024,
        max_inflated: 96 * 1024 * 1024,
    };
}

/// Why a download was not accepted. The code is shown to the admin; a response body never is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reject {
    /// A line that is not `start,end,CC` (the line number).
    Malformed(u64),
    Overlap,
    TooFewRows,
    TooFewCountries,
    MissingFamily,
    /// The row count differs from the database it would replace by more than the limit.
    SizeChanged,
    /// Truncated gzip, a bad CRC, or a stream that does not inflate.
    Corrupt,
    TooLarge,
    DigestMismatch,
}

impl Reject {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed_row",
            Self::Overlap => "overlapping_ranges",
            Self::TooFewRows => "too_few_rows",
            Self::TooFewCountries => "too_few_countries",
            Self::MissingFamily => "missing_family",
            Self::SizeChanged => "size_changed",
            Self::Corrupt => "corrupt_download",
            Self::TooLarge => "too_large",
            Self::DigestMismatch => "digest_mismatch",
        }
    }
}

/// A country code as two bytes packed in a `u16` (`NL` is `0x4E4C`); 0 is "unassigned".
pub(crate) fn pack(cc: [u8; 2]) -> u16 {
    u16::from_be_bytes(cc)
}

pub(crate) fn unpack(v: u16) -> Option<[u8; 2]> {
    (v != 0).then(|| v.to_be_bytes())
}

// ---------------------------------------------------------------------------------------------
// CRC-32 (the gzip trailer's and the file's)

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        // `i` is below 256, so the cast is exact.
        #[allow(clippy::cast_possible_truncation)]
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC_TABLE: [u32; 256] = crc_table();

/// An incremental CRC-32.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Crc(u32);

impl Crc {
    pub(crate) fn new() -> Self {
        Self(!0)
    }
    pub(crate) fn update(&mut self, data: &[u8]) {
        for &b in data {
            let low = self.0.to_le_bytes()[0];
            self.0 = CRC_TABLE[usize::from(low ^ b)] ^ (self.0 >> 8);
        }
    }
    pub(crate) fn finish(self) -> u32 {
        !self.0
    }
}

// ---------------------------------------------------------------------------------------------
// Parsing the CSV

/// The rows of a CSV as they are read.
#[derive(Debug, Default)]
pub(crate) struct Collector {
    v4: Vec<(u32, u32, u16)>,
    v6: Vec<(u128, u128, u16)>,
    countries: HashSet<u16>,
    lines: u64,
}

impl Collector {
    /// One line of the CSV: `start,end,CC`. Blank lines are skipped; anything else that does
    /// not parse rejects the file.
    pub(crate) fn push_line(&mut self, line: &str) -> Result<(), Reject> {
        self.lines += 1;
        let bad = Reject::Malformed(self.lines);
        let line = line.trim();
        if line.is_empty() {
            return Ok(());
        }
        let mut it = line.split(',').map(|f| f.trim().trim_matches('"'));
        let (Some(first), Some(last), Some(code), None) =
            (it.next(), it.next(), it.next(), it.next())
        else {
            return Err(bad);
        };
        let (Ok(start), Ok(end)) = (first.parse::<IpAddr>(), last.parse::<IpAddr>()) else {
            return Err(bad);
        };
        let cc = match code.as_bytes() {
            [c1, c2] if c1.is_ascii_alphabetic() && c2.is_ascii_alphabetic() => {
                pack([c1.to_ascii_uppercase(), c2.to_ascii_uppercase()])
            }
            _ => return Err(bad),
        };
        match (start, end) {
            (IpAddr::V4(lo), IpAddr::V4(hi)) => {
                let (lo, hi) = (u32::from(lo), u32::from(hi));
                if lo > hi {
                    return Err(bad);
                }
                self.v4.push((lo, hi, cc));
            }
            (IpAddr::V6(lo), IpAddr::V6(hi)) => {
                // A v4-mapped range is a v4 range.
                if let (Some(lo4), Some(hi4)) = (lo.to_ipv4_mapped(), hi.to_ipv4_mapped()) {
                    let (lo4, hi4) = (u32::from(lo4), u32::from(hi4));
                    if lo4 > hi4 {
                        return Err(bad);
                    }
                    self.v4.push((lo4, hi4, cc));
                } else {
                    let (lo, hi) = (u128::from(lo), u128::from(hi));
                    if lo > hi {
                        return Err(bad);
                    }
                    self.v6.push((lo, hi, cc));
                }
            }
            _ => return Err(bad),
        }
        self.countries.insert(cc);
        Ok(())
    }

    /// The rows read so far (before ranges are merged).
    pub(crate) fn rows(&self) -> u64 {
        (self.v4.len() + self.v6.len()) as u64
    }

    /// Sorts, checks and builds the tables. `previous_rows` is the source row count of the
    /// database this one replaces.
    pub(crate) fn finish(
        mut self,
        limits: &Limits,
        previous_rows: Option<u64>,
    ) -> Result<Table, Reject> {
        let rows = self.rows();
        if rows < limits.min_rows {
            return Err(Reject::TooFewRows);
        }
        if self.countries.len() < limits.min_countries {
            return Err(Reject::TooFewCountries);
        }
        if self.v4.is_empty() || self.v6.is_empty() {
            return Err(Reject::MissingFamily);
        }
        if let Some(prev) = previous_rows
            && prev > 0
            && rows.abs_diff(prev).saturating_mul(100) > prev.saturating_mul(limits.max_change_pct)
        {
            return Err(Reject::SizeChanged);
        }
        // The publisher's file is sorted already; sorting is only for a mirror's.
        if !self.v4.is_sorted_by_key(|r| r.0) {
            self.v4.sort_unstable_by_key(|r| r.0);
        }
        if !self.v6.is_sorted_by_key(|r| r.0) {
            self.v6.sort_unstable_by_key(|r| r.0);
        }
        if self.v4.windows(2).any(|w| w[1].0 <= w[0].1) {
            return Err(Reject::Overlap);
        }
        if self.v6.windows(2).any(|w| w[1].0 <= w[0].1) {
            return Err(Reject::Overlap);
        }
        // IPv4: merge contiguous ranges of one country, add the gap rows.
        let mut t4: Vec<(u32, u16)> = Vec::new();
        let mut expect: u64 = 0;
        let mut last: Option<(u64, u16)> = None; // (end + 1, cc) of the row just added
        for &(s, e, cc) in &self.v4 {
            if let Some((next, c)) = last
                && next == u64::from(s)
                && c == cc
            {
                expect = u64::from(e) + 1;
                last = Some((expect, cc));
                continue;
            }
            if u64::from(s) > expect {
                t4.push((u32::try_from(expect).unwrap_or(u32::MAX), 0));
            }
            t4.push((s, cc));
            expect = u64::from(e) + 1;
            last = Some((expect, cc));
        }
        if u32::try_from(expect).is_ok() {
            t4.push((u32::try_from(expect).unwrap_or(u32::MAX), 0));
        }
        // IPv6: ranges are cut to /64 (conservative: a range's first and last /64 are wholly its
        // own). A /64 two ranges share belongs to the earlier one.
        let mut t6: Vec<(u64, u16)> = Vec::new();
        let mut expect: u128 = 0;
        let mut last: Option<(u128, u16)> = None;
        for &(s, e, cc) in &self.v6 {
            let mut s_hi = s >> 64;
            let e_hi = e >> 64;
            if s_hi < expect {
                s_hi = expect;
            }
            if s_hi > e_hi {
                continue;
            }
            if let Some((next, c)) = last
                && next == s_hi
                && c == cc
            {
                expect = e_hi + 1;
                last = Some((expect, cc));
                continue;
            }
            if s_hi > expect {
                t6.push((u64::try_from(expect).unwrap_or(u64::MAX), 0));
            }
            t6.push((u64::try_from(s_hi).unwrap_or(u64::MAX), cc));
            expect = e_hi + 1;
            last = Some((expect, cc));
        }
        if u64::try_from(expect).is_ok() {
            t6.push((u64::try_from(expect).unwrap_or(u64::MAX), 0));
        }
        Ok(Table {
            v4: t4,
            v6: t6,
            source_rows: u32::try_from(rows).unwrap_or(u32::MAX),
        })
    }
}

/// The built tables, ready to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Table {
    v4: Vec<(u32, u16)>,
    v6: Vec<(u64, u16)>,
    pub(crate) source_rows: u32,
}

impl Table {
    /// The size of the file this table makes.
    pub(crate) fn file_len(&self) -> u64 {
        HEADER_LEN as u64 + self.v4.len() as u64 * REC4 + self.v6.len() as u64 * REC6
    }
}

// ---------------------------------------------------------------------------------------------
// The gzip CSV, streamed

/// Reads a gzip file of CSV lines into `c` without holding the uncompressed text: the inflater
/// keeps its own 32 KiB window and the lines are fed as they come out.
pub(crate) fn read_gzip_csv(data: &[u8], c: &mut Collector, max_out: u64) -> Result<(), Reject> {
    use miniz_oxide::inflate::stream::{InflateState, inflate};
    use miniz_oxide::{DataFormat, MZFlush, MZStatus};

    let body_start = gzip_header_len(data).ok_or(Reject::Corrupt)?;
    if data.len() < body_start + 8 {
        return Err(Reject::Corrupt);
    }
    let body_end = data.len() - 8;
    let want_crc = u32::from_le_bytes(data[body_end..body_end + 4].try_into().unwrap_or([0; 4]));
    let mut state = InflateState::new_boxed(DataFormat::Raw);
    let mut out = [0u8; 16 * 1024];
    let mut pos = body_start;
    let mut crc = Crc::new();
    let mut total: u64 = 0;
    let mut line: Vec<u8> = Vec::with_capacity(MAX_LINE);
    loop {
        let r = inflate(&mut state, &data[pos..body_end], &mut out, MZFlush::None);
        pos += r.bytes_consumed;
        let chunk = &out[..r.bytes_written];
        crc.update(chunk);
        total += chunk.len() as u64;
        if total > max_out {
            return Err(Reject::TooLarge);
        }
        for &b in chunk {
            if b == b'\n' {
                let text =
                    std::str::from_utf8(&line).map_err(|_| Reject::Malformed(c.lines + 1))?;
                c.push_line(text)?;
                line.clear();
            } else if line.len() >= MAX_LINE {
                return Err(Reject::Malformed(c.lines + 1));
            } else {
                line.push(b);
            }
        }
        match r.status {
            Ok(MZStatus::StreamEnd) => break,
            Ok(_) if r.bytes_consumed == 0 && r.bytes_written == 0 => return Err(Reject::Corrupt),
            Ok(_) => {}
            Err(_) => return Err(Reject::Corrupt),
        }
    }
    if !line.is_empty() {
        let text = std::str::from_utf8(&line).map_err(|_| Reject::Malformed(c.lines + 1))?;
        c.push_line(text)?;
    }
    if crc.finish() != want_crc {
        return Err(Reject::Corrupt);
    }
    Ok(())
}

/// The length of a gzip member's header (RFC 1952), or `None` when it isn't one.
fn gzip_header_len(d: &[u8]) -> Option<usize> {
    if d.len() < 18 || d[0] != 0x1f || d[1] != 0x8b || d[2] != 8 {
        return None;
    }
    let flg = d[3];
    let mut p = 10;
    if flg & 4 != 0 {
        let n = usize::from(u16::from_le_bytes([*d.get(p)?, *d.get(p + 1)?]));
        p += 2 + n;
    }
    for bit in [8u8, 16] {
        if flg & bit != 0 {
            while *d.get(p)? != 0 {
                p += 1;
            }
            p += 1;
        }
    }
    if flg & 2 != 0 {
        p += 2;
    }
    (p <= d.len()).then_some(p)
}

// ---------------------------------------------------------------------------------------------
// Writing

/// Where the database lives.
pub(crate) fn path(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

fn prev_path(dir: &Path) -> PathBuf {
    dir.join(format!("{FILE}.prev"))
}

fn tmp_path(dir: &Path) -> PathBuf {
    dir.join(format!("{FILE}.tmp"))
}

/// Writes the table to the temporary file and syncs it. `stop_after` ends the write early with
/// an error (a test's crash).
pub(crate) fn write_tmp(
    dir: &Path,
    t: &Table,
    month: u32,
    built_at: u64,
    stop_after: Option<u64>,
) -> io::Result<PathBuf> {
    if t.file_len() > MAX_FILE {
        return Err(io::Error::other("the database would be over 16 MiB"));
    }
    fs::create_dir_all(dir)?;
    let tmp = tmp_path(dir);
    let mut f = File::create(&tmp)?;
    f.write_all(&[0u8; HEADER_LEN])?;
    let mut crc = Crc::new();
    let mut written: u64 = 0;
    let mut put = |f: &mut File, bytes: &[u8]| -> io::Result<()> {
        if let Some(limit) = stop_after
            && written + bytes.len() as u64 > limit
        {
            return Err(io::Error::other("stopped (test)"));
        }
        crc.update(bytes);
        written += bytes.len() as u64;
        f.write_all(bytes)
    };
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    for &(s, cc) in &t.v4 {
        buf.extend_from_slice(&s.to_le_bytes());
        buf.extend_from_slice(&cc.to_le_bytes());
        if buf.len() >= 8 * 1024 - 16 {
            put(&mut f, &buf)?;
            buf.clear();
        }
    }
    for &(s, cc) in &t.v6 {
        buf.extend_from_slice(&s.to_le_bytes());
        buf.extend_from_slice(&cc.to_le_bytes());
        if buf.len() >= 8 * 1024 - 16 {
            put(&mut f, &buf)?;
            buf.clear();
        }
    }
    put(&mut f, &buf)?;
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(&MAGIC);
    h[8..12].copy_from_slice(&VERSION.to_le_bytes());
    h[12..16].copy_from_slice(&month.to_le_bytes());
    h[16..20].copy_from_slice(&u32::try_from(t.v4.len()).unwrap_or(u32::MAX).to_le_bytes());
    h[20..24].copy_from_slice(&u32::try_from(t.v6.len()).unwrap_or(u32::MAX).to_le_bytes());
    h[24..32].copy_from_slice(&built_at.to_le_bytes());
    h[32..36].copy_from_slice(&crc.finish().to_le_bytes());
    h[36..40].copy_from_slice(&t.source_rows.to_le_bytes());
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&h)?;
    f.sync_all()?;
    Ok(tmp)
}

/// Makes the temporary file the database: the current one stays as `.prev` until the next
/// success, and the swap is one rename, so a crash leaves the old database or the new one, never
/// neither.
pub(crate) fn publish(dir: &Path, tmp: &Path) -> io::Result<()> {
    let cur = path(dir);
    if cur.exists() {
        let prev = prev_path(dir);
        let _ = fs::remove_file(&prev);
        if fs::hard_link(&cur, &prev).is_err() {
            let _ = fs::copy(&cur, &prev);
        }
    }
    fs::rename(tmp, &cur)?;
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Removes the database, its previous copy and any half-written file.
pub(crate) fn remove_all(dir: &Path) -> io::Result<()> {
    for p in [path(dir), prev_path(dir), tmp_path(dir)] {
        match fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Reading

/// An open database: the file handle and the counts, and nothing else. A lookup reads a few
/// rows with `pread`; the operating system's page cache holds whatever is hot.
#[derive(Debug)]
pub(crate) struct Db {
    file: File,
    n4: u32,
    n6: u32,
    /// The month of the source, as `YYYYMM`.
    pub(crate) month: u32,
    /// When the file was built (Unix seconds).
    pub(crate) built_at: u64,
    pub(crate) source_rows: u32,
    pub(crate) size: u64,
}

/// Why a file could not be opened.
#[derive(Debug)]
pub(crate) enum OpenError {
    Missing,
    /// Not a database, truncated, or its checksum is wrong: it is ignored.
    Invalid,
    Io(io::Error),
}

#[cfg(unix)]
fn read_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.read_exact_at(buf, off)
}

#[cfg(windows)]
fn read_at(f: &File, buf: &mut [u8], mut off: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut done = 0;
    while done < buf.len() {
        let n = f.seek_read(&mut buf[done..], off)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        done += n;
        off += n as u64;
    }
    Ok(())
}

impl Db {
    /// Opens and verifies one file (header, size, checksum).
    pub(crate) fn open_file(p: &Path) -> Result<Self, OpenError> {
        let mut f = match File::open(p) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(OpenError::Missing),
            Err(e) => return Err(OpenError::Io(e)),
        };
        let size = f.metadata().map_err(OpenError::Io)?.len();
        if !(HEADER_LEN as u64..=MAX_FILE).contains(&size) {
            return Err(OpenError::Invalid);
        }
        let mut h = [0u8; HEADER_LEN];
        f.read_exact(&mut h).map_err(|_| OpenError::Invalid)?;
        let u32_at = |i: usize| u32::from_le_bytes(h[i..i + 4].try_into().unwrap_or([0; 4]));
        if h[..8] != MAGIC || u32_at(8) != VERSION {
            return Err(OpenError::Invalid);
        }
        let (n4, n6) = (u32_at(16), u32_at(20));
        let want = HEADER_LEN as u64 + u64::from(n4) * REC4 + u64::from(n6) * REC6;
        if want != size || n4 == 0 || n6 == 0 {
            return Err(OpenError::Invalid);
        }
        let mut crc = Crc::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = f.read(&mut chunk).map_err(OpenError::Io)?;
            if n == 0 {
                break;
            }
            crc.update(&chunk[..n]);
        }
        if crc.finish() != u32_at(32) {
            return Err(OpenError::Invalid);
        }
        Ok(Self {
            file: f,
            n4,
            n6,
            month: u32_at(12),
            built_at: u64::from_le_bytes(h[24..32].try_into().unwrap_or([0; 8])),
            source_rows: u32_at(36),
            size,
        })
    }

    /// Opens `<dir>/country.ttgeo`; when that is missing or fails its checksum, the previous
    /// copy (a crash between the two renames, or a damaged file) is used.
    pub(crate) fn open(dir: &Path) -> Result<Self, OpenError> {
        match Self::open_file(&path(dir)) {
            Ok(db) => Ok(db),
            Err(first) => match Self::open_file(&prev_path(dir)) {
                Ok(db) => Ok(db),
                Err(_) => Err(first),
            },
        }
    }

    /// The country of `ip`: `None` for an address in a gap or outside the table. Reads about
    /// 2 x log2(rows) small pieces of the file.
    pub(crate) fn lookup(&self, ip: IpAddr) -> io::Result<Option<[u8; 2]>> {
        match ip {
            IpAddr::V4(a) => self.lookup4(a),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => self.lookup4(v4),
                None => self.lookup6(a),
            },
        }
    }

    fn lookup4(&self, a: Ipv4Addr) -> io::Result<Option<[u8; 2]>> {
        let key = u64::from(u32::from(a));
        let mut rec = [0u8; 6];
        let (mut lo, mut hi) = (0u64, u64::from(self.n4));
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            read_at(&self.file, &mut rec, HEADER_LEN as u64 + mid * REC4)?;
            let start = u64::from(u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]));
            if start <= key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        self.country_at(lo, HEADER_LEN as u64, REC4, 4)
    }

    fn lookup6(&self, a: Ipv6Addr) -> io::Result<Option<[u8; 2]>> {
        let key = (u128::from(a) >> 64) as u64;
        let base = HEADER_LEN as u64 + u64::from(self.n4) * REC4;
        let mut rec = [0u8; 10];
        let (mut lo, mut hi) = (0u64, u64::from(self.n6));
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            read_at(&self.file, &mut rec, base + mid * REC6)?;
            let start = u64::from_le_bytes([
                rec[0], rec[1], rec[2], rec[3], rec[4], rec[5], rec[6], rec[7],
            ]);
            if start <= key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        self.country_at(lo, base, REC6, 8)
    }

    /// The country of the row before the first one that starts after the key (`lo`).
    fn country_at(
        &self,
        lo: u64,
        base: u64,
        rec: u64,
        cc_off: usize,
    ) -> io::Result<Option<[u8; 2]>> {
        if lo == 0 {
            return Ok(None);
        }
        let mut r = [0u8; 10];
        let len = usize::try_from(rec).unwrap_or(10);
        read_at(&self.file, &mut r[..len], base + (lo - 1) * rec)?;
        Ok(unpack(u16::from_le_bytes([r[cc_off], r[cc_off + 1]])))
    }
}

#[cfg(test)]
pub(crate) mod tests;

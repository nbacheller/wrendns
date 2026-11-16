//! REQ: OPS-011 (ADR-156) — the package is a `.tar.gz` built in memory: a small ustar writer and
//! a gzip wrapper around `miniz_oxide`'s deflate, so no archive crate is needed (about 100 lines).

use std::fmt;

/// A path the archive can't hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathError(pub String);

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "can't archive `{}`", self.0)
    }
}

impl std::error::Error for PathError {}

/// A ustar archive being built.
#[derive(Debug, Default)]
pub struct Tar {
    buf: Vec<u8>,
}

const BLOCK: usize = 512;

/// Writes `value` as zero-padded octal into `field`, NUL-terminated.
fn octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    // A value too big for the field keeps its low digits (sizes here are far below the limit).
    let bytes = text.as_bytes();
    let start = bytes.len().saturating_sub(digits);
    field[..digits].copy_from_slice(&bytes[start..]);
    field[digits] = 0;
}

/// `path` as `(prefix, name)` for ustar's 155 + 100 byte fields.
fn split_path(path: &str) -> Result<(&str, &str), PathError> {
    let bad = path.is_empty()
        || path.starts_with('/')
        || path.split('/').any(|p| p.is_empty() || p == "..")
        || !path.is_ascii()
        || path.bytes().any(|b| b < 0x20);
    if bad {
        return Err(PathError(path.to_owned()));
    }
    if path.len() <= 100 {
        return Ok(("", path));
    }
    // Split at a slash so the name fits 100 bytes and the prefix 155.
    path.match_indices('/')
        .map(|(i, _)| (&path[..i], &path[i + 1..]))
        .find(|(p, n)| p.len() <= 155 && n.len() <= 100)
        .ok_or_else(|| PathError(path.to_owned()))
}

impl Tar {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a regular file (mode 0644, no owner), modified at `mtime` (Unix seconds).
    pub fn add(&mut self, path: &str, data: &[u8], mtime: u64) -> Result<(), PathError> {
        let (prefix, name) = split_path(path)?;
        let mut h = [0u8; BLOCK];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        octal(&mut h[124..136], data.len() as u64);
        octal(&mut h[136..148], mtime);
        h[148..156].copy_from_slice(b"        ");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[329..337].copy_from_slice(b"0000000\0");
        h[337..345].copy_from_slice(b"0000000\0");
        h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        let text = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(text.as_bytes());
        self.buf.extend_from_slice(&h);
        self.buf.extend_from_slice(data);
        let pad = (BLOCK - data.len() % BLOCK) % BLOCK;
        self.buf.resize(self.buf.len() + pad, 0);
        Ok(())
    }

    /// The archive with its two closing blocks.
    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        self.buf.resize(self.buf.len() + 2 * BLOCK, 0);
        self.buf
    }
}

/// CRC-32 (IEEE, as gzip uses it).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut t = [0u32; 256];
        let mut i = 0u32;
        while i < 256 {
            let mut c = i;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 == 1 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            t[i as usize] = c;
            i += 1;
        }
        t
    };
    let mut c = !0u32;
    for &b in data {
        c = TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// `data` as a gzip stream (RFC 1952), compressed at level 6.
#[must_use]
pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    out.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
    out.extend_from_slice(&crc32(data).to_le_bytes());
    // The size modulo 2^32, as the format says.
    let size = u32::try_from(data.len() as u64 % (1 << 32)).unwrap_or(0);
    out.extend_from_slice(&size.to_le_bytes());
    out
}

/// A parsed archive entry (tests and the manifest check use it; the package never reads archives).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub data: Vec<u8>,
}

/// Reads a `.tar.gz` made by [`Tar`] and [`gzip`] back into its files; `None` if it isn't one.
#[must_use]
pub fn read_tar_gz(bytes: &[u8]) -> Option<Vec<Entry>> {
    if bytes.len() < 18 || bytes[..3] != [0x1f, 0x8b, 8] {
        return None;
    }
    let body = &bytes[10..bytes.len() - 8];
    let tar = miniz_oxide::inflate::decompress_to_vec(body).ok()?;
    let want = u32::from_le_bytes(bytes[bytes.len() - 8..bytes.len() - 4].try_into().ok()?);
    if crc32(&tar) != want {
        return None;
    }
    let mut out = Vec::new();
    let mut at = 0;
    while at + BLOCK <= tar.len() {
        let h = &tar[at..at + BLOCK];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let text = |r: std::ops::Range<usize>| {
            let f = &h[r];
            let end = f.iter().position(|&b| b == 0).unwrap_or(f.len());
            String::from_utf8_lossy(&f[..end]).into_owned()
        };
        let size = usize::from_str_radix(text(124..136).trim(), 8).ok()?;
        let (prefix, name) = (text(345..500), text(0..100));
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        at += BLOCK;
        let data = tar.get(at..at + size)?.to_vec();
        at += size.div_ceil(BLOCK) * BLOCK;
        out.push(Entry { path, data });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_011_a_tar_gz_reads_back_with_its_paths_and_bytes() {
        let mut t = Tar::new();
        t.add("MANIFEST.json", b"{}", 1_790_000_000).unwrap();
        t.add("logs/node.log", &vec![b'x'; 1500], 1_790_000_000)
            .unwrap();
        t.add("empty", b"", 0).unwrap();
        let gz = gzip(&t.finish());
        let files = read_tar_gz(&gz).unwrap();
        assert_eq!(files.len(), 3);
        assert_eq!(files[0].path, "MANIFEST.json");
        assert_eq!(files[1].data.len(), 1500);
        assert_eq!(files[2].data, b"");
    }

    #[test]
    fn ops_011_crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn ops_011_a_long_path_is_split_into_prefix_and_name() {
        let dir = "d".repeat(70);
        let path = format!("{dir}/{dir}/{}", "f".repeat(60));
        let mut t = Tar::new();
        t.add(&path, b"x", 0).unwrap();
        let files = read_tar_gz(&gzip(&t.finish())).unwrap();
        assert_eq!(files[0].path, path);
        // No slash to split at, and longer than 100 bytes.
        assert!(Tar::new().add(&"x".repeat(101), b"", 0).is_err());
    }

    #[test]
    fn ops_011_paths_that_escape_or_hide_are_refused() {
        for bad in ["", "/etc/passwd", "a/../b", "a//b", "tab\tname", "é.txt"] {
            assert!(Tar::new().add(bad, b"", 0).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ops_011_a_damaged_archive_is_not_read() {
        let mut t = Tar::new();
        t.add("a", b"hello", 0).unwrap();
        let mut gz = gzip(&t.finish());
        let n = gz.len();
        gz[n - 8] ^= 0xff; // the checksum
        assert!(read_tar_gz(&gz).is_none());
        assert!(read_tar_gz(b"not gzip at all, but long enough to try").is_none());
    }
}

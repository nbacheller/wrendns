//! REQ: OBS-902 (T26.4, ADR-959) - the `.ttgeo` builder, writer and lookup.

use std::net::IpAddr;

use super::*;

/// A fixture CSV with both families, the gaps the golden test probes, and enough countries.
pub(crate) fn csv() -> String {
    [
        "1.0.0.0,1.0.0.255,AU",
        "1.0.1.0,1.0.3.255,CN",
        // a gap: 1.0.4.0 to 1.0.7.255
        "1.0.8.0,1.0.8.255,CN",
        "1.0.9.0,1.0.9.255,CN",
        "8.8.8.0,8.8.8.255,US",
        "93.184.216.0,93.184.216.255,US",
        "255.255.255.0,255.255.255.255,AU",
        "2001:db8::,2001:db8:0:ffff:ffff:ffff:ffff:ffff,NL",
        "2606:4700::,2606:4700:ffff:ffff:ffff:ffff:ffff:ffff,US",
        "2a00::,2a00::ffff:ffff:ffff:ffff:ffff,DE",
    ]
    .join("\n")
}

pub(crate) fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    out.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
    let mut crc = Crc::new();
    crc.update(data);
    out.extend_from_slice(&crc.finish().to_le_bytes());
    out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_le_bytes());
    out
}

pub(crate) fn table_of(csv: &str) -> Result<Table, Reject> {
    let mut c = Collector::default();
    read_gzip_csv(&gzip(csv.as_bytes()), &mut c, 1 << 26)?;
    c.finish(&Limits::TEST, None)
}

fn build(dir: &Path) -> Db {
    let t = table_of(&csv()).unwrap();
    let tmp = write_tmp(dir, &t, 202_611, 1_000, None).unwrap();
    publish(dir, &tmp).unwrap();
    Db::open(dir).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[allow(clippy::unnecessary_wraps)] // compared with what `lookup` returns
fn cc(s: &str) -> Option<[u8; 2]> {
    let b = s.as_bytes();
    Some([b[0], b[1]])
}

/// REQ: OBS-902 (ADR-959 section 5) - range edges, gaps, IPv4, IPv6 and a v4-mapped address.
#[test]
fn obs_902_geoip_lookup_golden() {
    let dir = tempfile::tempdir().unwrap();
    let db = build(dir.path());
    let at = |s: &str| db.lookup(ip(s)).unwrap();
    // The edges of a range.
    assert_eq!(at("1.0.0.0"), cc("AU"));
    assert_eq!(at("1.0.0.255"), cc("AU"));
    assert_eq!(at("1.0.1.0"), cc("CN"));
    assert_eq!(at("1.0.3.255"), cc("CN"));
    // The gap after it: one past the end is nobody's, not the previous country.
    assert_eq!(at("1.0.4.0"), None);
    assert_eq!(at("1.0.7.255"), None);
    // Contiguous ranges of one country merged: no seam.
    assert_eq!(at("1.0.8.255"), cc("CN"));
    assert_eq!(at("1.0.9.0"), cc("CN"));
    assert_eq!(at("1.0.9.255"), cc("CN"));
    assert_eq!(at("1.0.10.0"), None);
    // Before the first range, and the very top of the space.
    assert_eq!(at("0.0.0.0"), None);
    assert_eq!(at("0.255.255.255"), None);
    assert_eq!(at("255.255.255.254"), cc("AU"));
    assert_eq!(at("255.255.255.255"), cc("AU"));
    assert_eq!(at("8.8.8.8"), cc("US"));
    assert_eq!(at("93.184.216.34"), cc("US"));
    // A private address is in no range.
    assert_eq!(at("192.168.1.10"), None);
    // IPv6: cut to /64, edges and gaps.
    assert_eq!(at("2001:db8::1"), cc("NL"));
    assert_eq!(at("2001:db8:0:ffff::1"), cc("NL"));
    assert_eq!(at("2001:db8:0:1:ffff:ffff:ffff:ffff"), cc("NL"));
    assert_eq!(at("2001:db8:1::"), None);
    assert_eq!(at("2001:db7:ffff:ffff::"), None);
    assert_eq!(at("2606:4700:4700::1111"), cc("US"));
    assert_eq!(at("2a00::1"), cc("DE"));
    assert_eq!(at("::1"), None);
    assert_eq!(at("fe80::1"), None);
    // A v4-mapped address is looked up as the IPv4 address it carries.
    assert_eq!(at("::ffff:8.8.8.8"), cc("US"));
    assert_eq!(at("::ffff:192.168.1.1"), None);
}

/// REQ: OBS-902 (ADR-959 section 5) - the database is not held on the heap: a lookup allocates
/// nothing, the open handle is a few words, and a lookup reads a handful of rows rather than the
/// file (about 2 x log2(rows) positional reads).
#[test]
fn obs_902_geoip_lookup_not_resident() {
    let dir = tempfile::tempdir().unwrap();
    let db = build(dir.path());
    // The handle is the file and a few counters, whatever the file's size.
    assert!(
        std::mem::size_of::<Db>() <= 64,
        "Db is {} bytes",
        std::mem::size_of::<Db>()
    );
    for addr in ["8.8.8.8", "2606:4700::1111", "::ffff:1.0.0.1", "10.0.0.1"] {
        let a = ip(addr);
        let info = allocation_counter::measure(|| {
            let _ = db.lookup(a);
        });
        assert_eq!(
            info.count_total, 0,
            "a lookup of {addr} allocated: {info:?}"
        );
    }
}

/// A big table: lookups stay exact and the handle stays small (nothing scales with the file).
#[test]
fn obs_902_geoip_large_table_lookups() {
    let dir = tempfile::tempdir().unwrap();
    // 60,000 /24s alternating two countries with a gap every third: 20,000 gaps.
    let mut lines = Vec::new();
    for i in 0u32..60_000 {
        if i % 3 == 2 {
            continue;
        }
        let base = 0x0100_0000u32 + i * 256;
        let (a, b) = (
            std::net::Ipv4Addr::from(base),
            std::net::Ipv4Addr::from(base + 255),
        );
        lines.push(format!("{a},{b},{}", if i % 2 == 0 { "AA" } else { "BB" }));
    }
    lines.push("2001:db8::,2001:db8::ffff,NL".to_owned());
    let t = table_of(&lines.join("\n")).unwrap();
    let tmp = write_tmp(dir.path(), &t, 202_611, 5, None).unwrap();
    publish(dir.path(), &tmp).unwrap();
    let db = Db::open(dir.path()).unwrap();
    assert!(db.size > 100_000, "{}", db.size);
    assert!(std::mem::size_of::<Db>() <= 64);
    for i in [0u32, 1, 2, 3, 4, 29_999, 30_000, 59_996, 59_997] {
        let a = std::net::Ipv4Addr::from(0x0100_0000u32 + i * 256 + 77);
        let want = if i % 3 == 2 {
            None
        } else if i % 2 == 0 {
            cc("AA")
        } else {
            cc("BB")
        };
        assert_eq!(db.lookup(IpAddr::V4(a)).unwrap(), want, "{a}");
    }
}

/// REQ: OBS-902 (ADR-959 section 5) - a crash while writing leaves the database as it was: the
/// half-written file is a temporary one that is never read, a crash between the two renames
/// leaves the previous copy to open, and a damaged database falls back to it.
#[test]
fn obs_902_geoip_atomic_write_after_crash() {
    let dir = tempfile::tempdir().unwrap();
    let db1 = build(dir.path());
    assert_eq!(db1.month, 202_611);
    let size1 = db1.size;
    drop(db1);

    // A second build that dies halfway: the current file is untouched and still opens.
    let t = table_of(&csv()).unwrap();
    let err = write_tmp(dir.path(), &t, 202_612, 2_000, Some(20)).unwrap_err();
    assert!(err.to_string().contains("stopped"));
    let db = Db::open(dir.path()).unwrap();
    assert_eq!((db.month, db.size), (202_611, size1));
    drop(db);
    // The half-written temporary file is never opened as the database, even if it is all there is.
    let only_tmp = tempfile::tempdir().unwrap();
    let _ = write_tmp(only_tmp.path(), &t, 202_612, 2_000, Some(20));
    assert!(matches!(Db::open(only_tmp.path()), Err(OpenError::Missing)));

    // A crash after the temporary file is complete but before the rename: the old one stands.
    let tmp = write_tmp(dir.path(), &t, 202_612, 2_000, None).unwrap();
    assert_eq!(Db::open(dir.path()).unwrap().month, 202_611);
    // The rename: the new one is current and the old one is kept as .prev.
    publish(dir.path(), &tmp).unwrap();
    assert_eq!(Db::open(dir.path()).unwrap().month, 202_612);
    assert_eq!(
        Db::open_file(&prev_path(dir.path())).unwrap().month,
        202_611
    );

    // A truncated or flipped current file is ignored and the previous copy is used.
    let cur = path(dir.path());
    let bytes = std::fs::read(&cur).unwrap();
    std::fs::write(&cur, &bytes[..bytes.len() - 7]).unwrap();
    assert_eq!(Db::open(dir.path()).unwrap().month, 202_611);
    let mut flipped = bytes.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x55;
    std::fs::write(&cur, &flipped).unwrap();
    assert_eq!(Db::open(dir.path()).unwrap().month, 202_611);
    // Both gone: missing.
    remove_all(dir.path()).unwrap();
    assert!(matches!(Db::open(dir.path()), Err(OpenError::Missing)));
}

/// REQ: OBS-902 (ADR-959 section 4) - each verification failure has its own code.
#[test]
fn obs_902_geoip_verification_rules() {
    let ok = csv();
    // Overlap: two ranges that share an address, in either order.
    let overlap = format!("{ok}\n1.0.0.128,1.0.1.10,AU");
    assert_eq!(table_of(&overlap).unwrap_err(), Reject::Overlap);
    let dup = format!("{ok}\n8.8.8.0,8.8.8.255,US");
    assert_eq!(table_of(&dup).unwrap_err(), Reject::Overlap);
    // Malformed rows.
    for bad in [
        "1.2.3.4,1.2.3.9",
        "1.2.3.4,1.2.3.9,USA",
        "1.2.3.9,1.2.3.4,US",
        "1.2.3.4,2001:db8::1,US",
        "nonsense,1.2.3.9,US",
        "1.2.3.4,1.2.3.9,U1",
        "1.2.3.4,1.2.3.9,US,extra",
    ] {
        let e = table_of(&format!("{ok}\n{bad}")).unwrap_err();
        assert!(matches!(e, Reject::Malformed(_)), "{bad}: {e:?}");
    }
    // Too few rows and too few countries.
    assert_eq!(
        table_of("1.0.0.0,1.0.0.255,AU").unwrap_err(),
        Reject::TooFewRows
    );
    let one_country = (0..10)
        .map(|i| format!("1.0.{i}.0,1.0.{i}.255,AU"))
        .chain(["2001:db8::,2001:db8::ffff,AU".to_owned()])
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(table_of(&one_country).unwrap_err(), Reject::TooFewCountries);
    // One family missing.
    let v4_only = (0..10)
        .map(|i| {
            format!(
                "1.0.{i}.0,1.0.{i}.255,{}",
                if i % 2 == 0 { "AU" } else { "NZ" }
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(table_of(&v4_only).unwrap_err(), Reject::MissingFamily);
    // The production limits are the ADR's.
    assert_eq!(Limits::PRODUCTION.min_rows, 100_000);
    assert_eq!(Limits::PRODUCTION.min_countries, 150);
    assert_eq!(Limits::PRODUCTION.max_download, 32 * 1024 * 1024);
    assert_eq!(Limits::PRODUCTION.max_inflated, 96 * 1024 * 1024);
    // The row count may change by 30% against the database it replaces.
    let mut c = Collector::default();
    read_gzip_csv(&gzip(ok.as_bytes()), &mut c, 1 << 20).unwrap();
    assert_eq!(c.rows(), 10);
    let e = c.finish(&Limits::TEST, Some(100)).unwrap_err();
    assert_eq!(e, Reject::SizeChanged);
    let mut c = Collector::default();
    read_gzip_csv(&gzip(ok.as_bytes()), &mut c, 1 << 20).unwrap();
    assert!(c.finish(&Limits::TEST, Some(12)).is_ok());
    // A mirror's unsorted file is sorted, not refused.
    let mut lines: Vec<&str> = ok.lines().collect();
    lines.reverse();
    assert!(table_of(&lines.join("\n")).is_ok());
}

/// REQ: OBS-902 (ADR-959 section 4) - the gzip is verified: truncated, a bad CRC, not gzip at
/// all, and an inflated size over the limit are each refused.
#[test]
fn obs_902_geoip_gzip_checks() {
    let good = gzip(csv().as_bytes());
    let mut c = Collector::default();
    read_gzip_csv(&good, &mut c, 1 << 20).unwrap();
    for cut in [good.len() - 1, good.len() - 9, good.len() / 2, 12] {
        let e = read_gzip_csv(&good[..cut], &mut Collector::default(), 1 << 20).unwrap_err();
        assert_eq!(e, Reject::Corrupt, "cut at {cut}");
    }
    let mut bad_crc = good.clone();
    let n = bad_crc.len();
    bad_crc[n - 8] ^= 1;
    assert_eq!(
        read_gzip_csv(&bad_crc, &mut Collector::default(), 1 << 20).unwrap_err(),
        Reject::Corrupt
    );
    assert_eq!(
        read_gzip_csv(
            b"not gzip at all, just text",
            &mut Collector::default(),
            1 << 20
        )
        .unwrap_err(),
        Reject::Corrupt
    );
    // Over the inflated limit (a small limit stands in for 96 MiB).
    assert_eq!(
        read_gzip_csv(&good, &mut Collector::default(), 50).unwrap_err(),
        Reject::TooLarge
    );
    // A line longer than any row is malformed, not buffered without bound.
    let long = format!("{}\n", "9".repeat(5_000));
    assert!(matches!(
        read_gzip_csv(&gzip(long.as_bytes()), &mut Collector::default(), 1 << 20).unwrap_err(),
        Reject::Malformed(_)
    ));
}

#[test]
fn obs_902_geoip_crc32_known_value() {
    let mut c = Crc::new();
    c.update(b"123456789");
    assert_eq!(c.finish(), 0xCBF4_3926);
}

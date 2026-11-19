//! REQ: OBS-902 (T26.4, ADR-959) - the downloader against a fake HTTPS source: nothing is fetched
//! while the toggle is off, a good file is downloaded and built, and each verification failure
//! keeps the old database and reports a code.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wrendns_config::SafeString;

use super::ttgeo::tests::{csv, gzip};
use super::*;

/// What the fake source answers for a path.
#[derive(Clone)]
enum Reply {
    Body(Vec<u8>),
    Status(u16),
    /// A redirect to `Location`.
    Redirect(String),
}

struct Source {
    url: String,
    hits: Arc<AtomicUsize>,
    replies: Arc<Mutex<HashMap<String, Reply>>>,
    cert: rustls::pki_types::CertificateDer<'static>,
}

impl Source {
    fn set(&self, path: &str, r: Reply) {
        self.replies.lock().unwrap().insert(path.to_owned(), r);
    }
}

/// An HTTPS server on 127.0.0.1 with a self-signed certificate the test trusts.
async fn source() -> Source {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let der = cert.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let replies: Arc<Mutex<HashMap<String, Reply>>> = Arc::default();
    let (task_hits, task_replies) = (Arc::clone(&hits), Arc::clone(&replies));
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let (counter, table) = (Arc::clone(&task_hits), Arc::clone(&task_replies));
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                let got = tls.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..got]).into_owned();
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
                counter.fetch_add(1, Ordering::SeqCst);
                let reply = table.lock().unwrap().get(&path).cloned();
                let out: Vec<u8> = match reply {
                    Some(Reply::Body(payload)) => {
                        let mut head = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/gzip\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            payload.len()
                        )
                        .into_bytes();
                        head.extend(payload);
                        head
                    }
                    Some(Reply::Redirect(to)) => format!(
                        "HTTP/1.1 302 Found\r\nlocation: {to}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    )
                    .into_bytes(),
                    Some(Reply::Status(code)) => format!(
                        "HTTP/1.1 {code} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    )
                    .into_bytes(),
                    None => b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        .to_vec(),
                };
                let _ = tls.write_all(&out).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Source {
        url: format!("https://127.0.0.1:{port}"),
        hits,
        replies,
        cert: der,
    }
}

fn service(src: &Source) -> Arc<GeoIp> {
    Arc::new(GeoIp::new(
        Options {
            limits: Limits::TEST,
            extra_roots: vec![src.cert.clone()],
        },
        0,
    ))
}

fn config(dir: &Path, url: Option<String>, enabled: bool) -> Config {
    let mut c = Config::default();
    c.node.data_dir = SafeString::new(dir.to_string_lossy().into_owned()).unwrap();
    c.map.geoip.enabled = enabled;
    c.map.geoip.source_url = url.map(|u| SafeString::new(u).unwrap());
    c
}

const NOW: u64 = 1_795_000_000; // 2026-11-18

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// REQ: OBS-902 (ADR-959 section 2) - with the toggle off nothing is requested and nothing is
/// written, however many times the task looks at the settings; the world view says it is off.
#[tokio::test]
async fn obs_902_geoip_off_makes_no_request() {
    let s = source().await;
    s.set("/db.csv.gz", Reply::Body(gzip(csv().as_bytes())));
    let dir = tempfile::tempdir().unwrap();
    let g = service(&s);
    let cfg = config(dir.path(), Some(format!("{}/db.csv.gz", s.url)), false);
    for i in 0..5 {
        g.tick(&cfg, NOW + i * 10_000).await;
    }
    // "Update now" with the toggle off is still only a request flag: the task doesn't act on it.
    g.request_update();
    g.tick(&cfg, NOW + 100_000).await;
    assert_eq!(s.hits.load(Ordering::SeqCst), 0, "a request was made");
    assert!(!dir.path().join("geoip").exists(), "something was written");
    let st = g.status(&cfg.map.geoip, NOW);
    assert_eq!(st.state, State::Off);
    assert!(matches!(
        g.locate(&cfg.map.geoip, &[ip("8.8.8.8")]),
        Err(Unavailable::Off)
    ));
}

/// REQ: OBS-902 (ADR-959 sections 3 and 5) - on, the node downloads from the HTTPS source, builds
/// the database, answers lookups from it, and does not fetch again within the day.
#[tokio::test]
async fn obs_902_geoip_download_and_build() {
    let s = source().await;
    s.set("/db.csv.gz", Reply::Body(gzip(csv().as_bytes())));
    let dir = tempfile::tempdir().unwrap();
    let g = service(&s);
    let cfg = config(dir.path(), Some(format!("{}/db.csv.gz", s.url)), true);
    // Before the first tick the status is "missing", not "ready".
    assert_eq!(g.status(&cfg.map.geoip, NOW).state, State::Missing);
    g.tick(&cfg, NOW).await;
    assert_eq!(s.hits.load(Ordering::SeqCst), 1);
    let st = g.status(&cfg.map.geoip, NOW);
    assert_eq!(st.state, State::Ready, "{st:?}");
    assert_eq!(st.rows, 10);
    assert_eq!(st.source_month, Some(202_611));
    assert!(st.size_bytes > 40 && st.last_error.is_none());
    assert!(st.next_check_at.unwrap() >= NOW + 86_400);
    let found = g
        .locate(
            &cfg.map.geoip,
            &[ip("8.8.8.8"), ip("2001:db8::7"), ip("10.0.0.1")],
        )
        .unwrap();
    assert_eq!(found, vec![Some(*b"US"), Some(*b"NL"), None]);
    assert!(dir.path().join("geoip").join(ttgeo::FILE).exists());
    // Within the day, and with this month's database, nothing more is asked.
    g.tick(&cfg, NOW + 3_600).await;
    g.tick(&cfg, NOW + 80_000).await;
    assert_eq!(s.hits.load(Ordering::SeqCst), 1);
    // A restart finds the file and does not download either.
    let g2 = service(&s);
    g2.tick(&cfg, NOW + 200_000).await;
    assert_eq!(s.hits.load(Ordering::SeqCst), 1);
    assert_eq!(g2.status(&cfg.map.geoip, NOW).state, State::Ready);
    // A new month and a due check: it fetches again.
    g2.tick(&cfg, NOW + 40 * 86_400).await;
    assert_eq!(s.hits.load(Ordering::SeqCst), 2);
    // Turning it off drops the handle (the file stays); turning it on finds it again.
    let off = config(
        dir.path(),
        cfg.map
            .geoip
            .source_url
            .as_ref()
            .map(|u| u.as_str().to_owned()),
        false,
    );
    g2.tick(&off, NOW + 41 * 86_400).await;
    assert!(matches!(
        g2.locate(&off.map.geoip, &[ip("8.8.8.8")]),
        Err(Unavailable::Off)
    ));
    assert!(dir.path().join("geoip").join(ttgeo::FILE).exists());
    g2.tick(&cfg, NOW + 41 * 86_400).await;
    assert!(g2.locate(&cfg.map.geoip, &[ip("8.8.8.8")]).is_ok());
    // "Delete database": the files go and nothing is fetched again until an admin asks.
    let hits = s.hits.load(Ordering::SeqCst);
    g2.delete().unwrap();
    assert!(!dir.path().join("geoip").join(ttgeo::FILE).exists());
    g2.tick(&cfg, NOW + 90 * 86_400).await;
    assert_eq!(s.hits.load(Ordering::SeqCst), hits);
    assert_eq!(g2.status(&cfg.map.geoip, NOW).state, State::Missing);
    assert!(matches!(
        g2.locate(&cfg.map.geoip, &[ip("8.8.8.8")]),
        Err(Unavailable::Missing)
    ));
    // Update now lifts it.
    assert!(g2.request_update());
    g2.tick(&cfg, NOW + 90 * 86_400).await;
    assert_eq!(s.hits.load(Ordering::SeqCst), hits + 1);
    assert_eq!(g2.status(&cfg.map.geoip, NOW).state, State::Ready);
}

/// REQ: OBS-902 (ADR-959 section 3) - the default source asks for this month's file and, when the
/// publisher has not put it out yet (404), for last month's, before the attempt counts as failed.
#[test]
fn obs_902_geoip_months_and_urls() {
    assert_eq!(month_of(NOW), 202_611);
    assert_eq!(month_of(0), 197_001);
    assert_eq!(month_of(1_782_864_000), 202_607);
    assert_eq!(prev_month(202_601), 202_512);
    assert_eq!(prev_month(202_611), 202_610);
    assert_eq!(
        default_url(202_601),
        "https://download.db-ip.com/free/dbip-country-lite-2026-01.csv.gz"
    );
    // Jitter is bounded and stable per node.
    assert!(GeoIp::jitter_of("node-a") < JITTER_MAX);
    assert_eq!(GeoIp::jitter_of("node-a"), GeoIp::jitter_of("node-a"));
    assert_ne!(GeoIp::jitter_of("node-a"), GeoIp::jitter_of("node-b"));
    // Failures back off from an hour, doubling, to a day at most.
    assert_eq!(BACKOFF_FIRST, 3_600);
    assert_eq!(CHECK_EVERY, 86_400);
}

/// REQ: OBS-902 (ADR-959 section 4) - every failure keeps the database it has and reports a code:
/// a truncated download, overlapping ranges, too few rows, a wrong digest, a redirect to plain
/// HTTP and an oversize body. A later good file is accepted.
#[tokio::test]
async fn obs_902_geoip_verification_failures() {
    let s = source().await;
    let good = gzip(csv().as_bytes());
    s.set("/good.csv.gz", Reply::Body(good.clone()));
    let dir = tempfile::tempdir().unwrap();
    let g = service(&s);
    let url = |p: &str| format!("{}/{p}", s.url);
    let mut cfg = config(dir.path(), Some(url("good.csv.gz")), true);
    g.tick(&cfg, NOW).await;
    assert_eq!(g.status(&cfg.map.geoip, NOW).state, State::Ready);
    let before = std::fs::read(dir.path().join("geoip").join(ttgeo::FILE)).unwrap();

    // Each case: the file the source serves, the setting, the code the status reports.
    let overlap = gzip(format!("{}\n1.0.0.128,1.0.1.10,AU", csv()).as_bytes());
    let few = gzip(b"1.0.0.0,1.0.0.255,AU\n2001:db8::,2001:db8::ffff,NL\n");
    let cases: Vec<(&str, Reply, Option<&str>, &str)> = vec![
        (
            "truncated",
            Reply::Body(good[..good.len() / 2].to_vec()),
            None,
            "corrupt_download",
        ),
        ("overlap", Reply::Body(overlap), None, "overlapping_ranges"),
        ("few", Reply::Body(few), None, "too_few_rows"),
        (
            "pinned",
            Reply::Body(good.clone()),
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
            "digest_mismatch",
        ),
        (
            "toohttp",
            Reply::Redirect("http://127.0.0.1:9/x".into()),
            None,
            "redirect_refused",
        ),
        ("gone", Reply::Status(404), None, "not_found"),
        ("busy", Reply::Status(503), None, "http_error"),
    ];
    let mut now = NOW + 40 * 86_400; // a new month: a check is due
    for (name, reply, pin, code) in cases {
        s.set(&format!("/{name}"), reply);
        cfg.map.geoip.source_url = Some(SafeString::new(url(name)).unwrap());
        cfg.map.geoip.sha256 = pin.map(|p| SafeString::new(p).unwrap());
        // The settings changed, so the source is fetched at once, whatever the backoff.
        g.tick(&cfg, now).await;
        let st = g.status(&cfg.map.geoip, now);
        // The old database still works, so the state stays ready and the error is shown beside it.
        assert_eq!(st.state, State::Ready, "{name}: {st:?}");
        assert_eq!(st.last_error.as_deref(), Some(code), "{name}");
        // The old database is intact and still answers.
        assert_eq!(
            std::fs::read(dir.path().join("geoip").join(ttgeo::FILE)).unwrap(),
            before,
            "{name}: the database changed"
        );
        assert!(g.locate(&cfg.map.geoip, &[ip("8.8.8.8")]).is_ok(), "{name}");
        assert!(
            st.next_check_at.is_some_and(|t| t > now),
            "{name}: backs off"
        );
        now += 100;
    }
    // A good file after the failures is accepted (the pin matches the real digest).
    let digest = hex(ring::digest::digest(&ring::digest::SHA256, &good).as_ref());
    cfg.map.geoip.source_url = Some(SafeString::new(url("good.csv.gz")).unwrap());
    cfg.map.geoip.sha256 = Some(SafeString::new(digest).unwrap());
    g.tick(&cfg, now).await;
    let st = g.status(&cfg.map.geoip, now);
    assert_eq!(st.state, State::Ready, "{st:?}");
    assert!(st.last_error.is_none());
}

/// REQ: OBS-902 (ADR-959 section 3) - a download over the size limit is refused, not buffered.
#[tokio::test]
async fn obs_902_geoip_oversize_download_is_refused() {
    let s = source().await;
    s.set("/big.csv.gz", Reply::Body(vec![7u8; 4096]));
    let dir = tempfile::tempdir().unwrap();
    let g = Arc::new(GeoIp::new(
        Options {
            limits: Limits {
                max_download: 1024,
                ..Limits::TEST
            },
            extra_roots: vec![s.cert.clone()],
        },
        0,
    ));
    let cfg = config(dir.path(), Some(format!("{}/big.csv.gz", s.url)), true);
    g.tick(&cfg, NOW).await;
    let st = g.status(&cfg.map.geoip, NOW);
    assert_eq!(st.state, State::Failed);
    assert_eq!(st.last_error.as_deref(), Some("too_large"));
    assert!(!dir.path().join("geoip").join(ttgeo::FILE).exists());
}

/// REQ: OBS-902 (ADR-959 section 5) - a crash while writing leaves the old database in place and
/// the status failed with `write_failed`.
#[tokio::test]
async fn obs_902_geoip_crash_during_write_keeps_the_old_database() {
    let s = source().await;
    s.set("/db.csv.gz", Reply::Body(gzip(csv().as_bytes())));
    let dir = tempfile::tempdir().unwrap();
    let g = service(&s);
    let mut cfg = config(dir.path(), Some(format!("{}/db.csv.gz", s.url)), true);
    g.tick(&cfg, NOW).await;
    let before = std::fs::read(dir.path().join("geoip").join(ttgeo::FILE)).unwrap();
    g.crash_next_write_after(30);
    cfg.map.geoip.source_url = Some(SafeString::new(format!("{}/db.csv.gz?again", s.url)).unwrap());
    s.set("/db.csv.gz?again", Reply::Body(gzip(csv().as_bytes())));
    g.tick(&cfg, NOW + 1).await;
    assert_eq!(
        g.status(&cfg.map.geoip, NOW).last_error.as_deref(),
        Some("write_failed")
    );
    assert_eq!(
        std::fs::read(dir.path().join("geoip").join(ttgeo::FILE)).unwrap(),
        before
    );
    assert!(g.locate(&cfg.map.geoip, &[ip("8.8.8.8")]).is_ok());
}

/// REQ: OBS-902 (T26.4 review) - a node with a working database whose later refresh failed is
/// still `ready`: the status carries the error, it does not call the database failed.
#[tokio::test]
async fn obs_902_geoip_failed_refresh_keeps_ready() {
    let s = source().await;
    s.set("/db.csv.gz", Reply::Body(gzip(csv().as_bytes())));
    let dir = tempfile::tempdir().unwrap();
    let g = service(&s);
    let cfg = config(dir.path(), Some(format!("{}/db.csv.gz", s.url)), true);
    g.tick(&cfg, NOW).await;
    assert_eq!(g.status(&cfg.map.geoip, NOW).state, State::Ready);
    s.set("/db.csv.gz", Reply::Status(500));
    g.tick(&cfg, NOW + 40 * 86_400).await;
    let st = g.status(&cfg.map.geoip, NOW + 40 * 86_400);
    assert_eq!(st.state, State::Ready, "{st:?}");
    assert!(st.last_error.is_some());
    assert!(g.locate(&cfg.map.geoip, &[ip("8.8.8.8")]).is_ok());
}

/// REQ: OBS-902 (T26.4 review) - a delete bumps the generation an attempt started under, so an
/// attempt that was running keeps nothing.
#[tokio::test]
async fn obs_902_geoip_delete_bumps_generation() {
    let g = GeoIp::default();
    let before = g.inner().generation;
    let _ = g.delete();
    assert_ne!(g.inner().generation, before);
}

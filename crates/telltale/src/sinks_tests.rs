//! REQ: API-016, OBS-010, OBS-006, NFR-007 (T23.11, ADR-984) - event sinks changed without a
//! restart: a sink added, changed or removed while the node runs, one that fails to build left
//! out alone, a name re-used for another collector never replaying the old one's kept events, a
//! drop counter that only grows, and the stored token or OTLP header read for every batch. The
//! collectors are local fakes on loopback; nothing reaches the network.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;

/// One request a fake collector took.
#[derive(Debug, Clone)]
struct Got {
    /// The request head, lower-cased.
    head: String,
    body: String,
}

/// A fake HTTP collector: answers 200 to everything and keeps what it was sent.
pub(crate) struct Collector {
    addr: SocketAddr,
    got: Arc<Mutex<Vec<Got>>>,
    stop: Arc<AtomicBool>,
}

impl Collector {
    pub(crate) fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let got = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (g, s) = (Arc::clone(&got), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((conn, _)) => {
                        let g = Arc::clone(&g);
                        std::thread::spawn(move || serve(conn, &g));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        Self { addr, got, stop }
    }

    fn url(&self) -> String {
        format!("http://{}/in", self.addr)
    }

    /// The collector's base URL (an OTLP endpoint).
    pub(crate) fn url_base(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The head of each request received, lower-cased, in order.
    pub(crate) fn heads(&self) -> Vec<String> {
        self.requests().into_iter().map(|g| g.head).collect()
    }

    /// Every event line received so far (JSON lines bodies).
    fn lines(&self) -> Vec<String> {
        self.got
            .lock()
            .unwrap()
            .iter()
            .flat_map(|g| g.body.lines().map(str::to_owned).collect::<Vec<_>>())
            .collect()
    }

    fn requests(&self) -> Vec<Got> {
        self.got.lock().unwrap().clone()
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Reads requests off one connection until it closes.
fn serve(mut conn: std::net::TcpStream, got: &Mutex<Vec<Got>>) {
    let _ = conn.set_nonblocking(false);
    let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            match conn.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        while buf.len() < head_end + 4 + len {
            match conn.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let body = String::from_utf8_lossy(&buf[head_end + 4..head_end + 4 + len]).into_owned();
        buf.drain(..head_end + 4 + len);
        got.lock().unwrap().push(Got { head, body });
        if conn
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
            .is_err()
        {
            return;
        }
    }
}

fn wait_for(mut f: impl FnMut() -> bool, secs: u64) -> bool {
    let until = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < until {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    f()
}

fn sink(toml: &str) -> SinkConfig {
    toml::from_str(toml).unwrap()
}

fn webhook(name: &str, url: &str, extra: &str) -> SinkConfig {
    sink(&format!(
        "name = \"{name}\"\ntype = \"webhook\"\nurl = \"{url}\"\nbatch = 1\nflush_secs = 1\nmax_buffer = 100\n{extra}"
    ))
}

/// A configuration holding exactly these sinks (as the node-managed ones) in `dir`.
fn config_with(dir: &std::path::Path, sinks: &[SinkConfig]) -> Config {
    let mut cfg = Config::default();
    cfg.node.data_dir = telltale_config::SafeString::new(dir.to_str().unwrap()).unwrap();
    cfg.telemetry.managed_sink = sinks.to_vec();
    cfg
}

/// The newest list of sinks the manager sent the aggregator.
fn latest(rx: &Receiver<Vec<Out>>) -> Vec<Out> {
    let mut last = Vec::new();
    while let Ok(v) = rx.try_recv() {
        last = v;
    }
    last
}

fn out<'a>(outs: &'a [Out], name: &str) -> &'a Out {
    outs.iter().find(|o| o.name == name).unwrap()
}

/// REQ: API-016, OBS-010 (T23.11, AC1) - a sink added while the node runs gets events from the
/// next batch on, with no restart; a sink the node already runs is left alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_016_sink_added_without_restart() {
    let (hook, dir) = (Collector::new(), tempfile::tempdir().unwrap());
    let (m, rx) = Manager::new();
    let rt = tokio::runtime::Handle::current();
    m.apply(&config_with(dir.path(), &[]), &rt, None);
    assert!(latest(&rx).is_empty(), "no sink yet");
    let a = webhook("hook", &hook.url(), "");
    m.apply(
        &config_with(dir.path(), std::slice::from_ref(&a)),
        &rt,
        None,
    );
    let outs = latest(&rx);
    assert_eq!(outs.len(), 1);
    let first_thread = Arc::clone(&m.inner.lock().unwrap().running[0].ctl);
    outs[0].tx.try_send(r#"{"n":1}"#.to_owned()).unwrap();
    assert!(
        wait_for(|| hook.lines().iter().any(|l| l.contains("\"n\":1")), 5),
        "the new sink delivered: {:?}",
        hook.lines()
    );
    assert_eq!(
        m.states(),
        vec![SinkState {
            name: "hook".into(),
            running: true,
            reason: None
        }]
    );
    // A second sink is added; the first keeps running (the same channel, the same thread).
    let file = dir.path().join("second.jsonl");
    let b = sink(&format!(
        "name = \"second\"\ntype = \"file\"\npath = \"{}\"\n",
        file.display()
    ));
    m.apply(&config_with(dir.path(), &[a, b]), &rt, None);
    let outs2 = latest(&rx);
    assert_eq!(outs2.len(), 2);
    assert!(
        Arc::ptr_eq(&first_thread, &m.inner.lock().unwrap().running[0].ctl),
        "the first sink was not restarted"
    );
    out(&outs2, "second")
        .tx
        .try_send(r#"{"n":2}"#.to_owned())
        .unwrap();
    assert!(
        wait_for(
            || std::fs::read_to_string(&file).is_ok_and(|t| t.contains("\"n\":2")),
            5
        ),
        "the file sink wrote"
    );
}

/// REQ: API-016, OBS-010 (T23.11, AC2) - a removed sink sends what it holds and stops within two
/// seconds, and the batches it kept on disk go with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_016_removed_sink_flushes_then_stops() {
    let (hook, dir) = (Collector::new(), tempfile::tempdir().unwrap());
    let (m, rx) = Manager::new();
    let rt = tokio::runtime::Handle::current();
    // A big batch and a long wait: the events are held, not yet sent.
    let a = sink(&format!(
        "name = \"hold\"\ntype = \"webhook\"\nurl = \"{}\"\nbatch = 500\nflush_secs = 60\nmax_buffer = 100\nspill_max_bytes = \"1MiB\"\n",
        hook.url()
    ));
    m.apply(
        &config_with(dir.path(), std::slice::from_ref(&a)),
        &rt,
        None,
    );
    let outs = latest(&rx);
    for i in 0..3 {
        outs[0].tx.try_send(format!("{{\"held\":{i}}}")).unwrap();
    }
    let spill = Spill::new(&a, dir.path().to_str().unwrap()).unwrap();
    assert!(spill.push(&["{\"kept\":1}".to_owned()]));
    assert!(spill.path.exists());
    std::thread::sleep(Duration::from_millis(1200));
    assert!(
        hook.lines().is_empty(),
        "nothing sent yet: {:?}",
        hook.lines()
    );

    let started = Instant::now();
    let rt2 = rt.clone();
    let dir_path = dir.path().to_owned();
    let m2 = Arc::clone(&m);
    tokio::task::spawn_blocking(move || m2.apply(&config_with(&dir_path, &[]), &rt2, None))
        .await
        .unwrap();
    assert!(
        started.elapsed() <= Duration::from_millis(2500),
        "stopped in {:?}",
        started.elapsed()
    );
    let lines = hook.lines();
    for i in 0..3 {
        assert!(
            lines.iter().any(|l| l.contains(&format!("\"held\":{i}"))),
            "held event {i} was flushed: {lines:?}"
        );
    }
    assert!(
        !lines.iter().any(|l| l.contains("kept")),
        "the kept batches were not sent on the way out: {lines:?}"
    );
    assert!(
        wait_for(|| !spill.path.exists() && !spill.pos.exists(), 2),
        "its kept batches were deleted"
    );
    assert_eq!(m.states().len(), 0);
}

/// REQ: API-016, OBS-010 (T23.11, AC3) - a sink that can't be built is reported and left out; the
/// others carry on, and so does the manager.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_016_failing_sink_build_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("good.jsonl");
    let bad = sink(
        "name = \"bad\"\ntype = \"syslog\"\naddress = \"tls://127.0.0.1:6514\"\ntls_ca = \"/nonexistent/ca.pem\"\n",
    );
    let good = sink(&format!(
        "name = \"good\"\ntype = \"file\"\npath = \"{}\"\n",
        file.display()
    ));
    let (m, rx) = Manager::new();
    let rt = tokio::runtime::Handle::current();
    m.apply(&config_with(dir.path(), &[bad, good]), &rt, None);
    let states = m.states();
    assert_eq!(states.len(), 2);
    let bad_state = states.iter().find(|s| s.name == "bad").unwrap();
    assert!(!bad_state.running);
    assert!(
        bad_state
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("TLS")),
        "{bad_state:?}"
    );
    assert!(states.iter().any(|s| s.name == "good" && s.running));
    let outs = latest(&rx);
    assert_eq!(outs.len(), 1, "only the sink that built is handed on");
    outs[0].tx.try_send("{\"ok\":true}".to_owned()).unwrap();
    assert!(wait_for(
        || std::fs::read_to_string(&file).is_ok_and(|t| t.contains("ok")),
        5
    ));
}

/// REQ: API-016, OBS-010 (T23.11, AC4) - a name re-used for another URL never replays the old
/// destination's kept events to the new one; a change that keeps the URL keeps them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_016_readded_sink_name_new_url_no_replay() {
    let (live, dir) = (Collector::new(), tempfile::tempdir().unwrap());
    let dead = "http://127.0.0.1:1/in";
    let data = dir.path().to_str().unwrap().to_owned();
    let (m, _rx) = Manager::new();
    let rt = tokio::runtime::Handle::current();
    let spill_of = |c: &SinkConfig| Spill::new(c, &data).unwrap();
    let a = webhook("hook", dead, "spill_max_bytes = \"1MiB\"\n");
    m.apply(
        &config_with(dir.path(), std::slice::from_ref(&a)),
        &rt,
        None,
    );
    let old = spill_of(&a);
    assert!(old.push(&["{\"old\":1}".to_owned()]));

    // The same URL with another batch size: a new thread, and the kept events stay.
    let a2 = webhook("hook", dead, "spill_max_bytes = \"1MiB\"\n").tap_batch(2);
    m.apply(
        &config_with(dir.path(), std::slice::from_ref(&a2)),
        &rt,
        None,
    );
    assert!(old.path.exists(), "same URL: the kept events stay");

    // The name now sends to another collector: the old events must not follow.
    let b = webhook("hook", &live.url(), "spill_max_bytes = \"1MiB\"\n");
    let m2 = Arc::clone(&m);
    let (rt2, dir_path) = (rt.clone(), dir.path().to_owned());
    tokio::task::spawn_blocking(move || {
        m2.apply(
            &config_with(&dir_path, std::slice::from_ref(&b)),
            &rt2,
            None,
        );
    })
    .await
    .unwrap();
    assert!(
        wait_for(|| !old.path.exists(), 3),
        "the old destination's kept events are gone"
    );
    std::thread::sleep(Duration::from_millis(2500));
    assert!(
        live.lines().is_empty(),
        "nothing was replayed to the new URL: {:?}",
        live.lines()
    );

    // Removed and added again with the first URL: it starts empty.
    let m3 = Arc::clone(&m);
    let (rt3, dir_path) = (rt.clone(), dir.path().to_owned());
    tokio::task::spawn_blocking(move || {
        m3.apply(&config_with(&dir_path, &[]), &rt3, None);
    })
    .await
    .unwrap();
    assert!(!spill_of(&a).path.exists());
}

trait TapBatch {
    fn tap_batch(self, n: u32) -> Self;
}
impl TapBatch for SinkConfig {
    fn tap_batch(mut self, n: u32) -> Self {
        self.batch = n;
        self
    }
}

/// REQ: NFR-007, OBS-010 (T23.11, AC6) - a sink's dropped-event count survives a reload, a
/// change of its settings, and its removal and return: the metric only ever grows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nfr_007_sink_drops_counted_across_reload() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("d.jsonl");
    let a = sink(&format!(
        "name = \"d\"\ntype = \"file\"\npath = \"{}\"\n",
        file.display()
    ));
    let (m, rx) = Manager::new();
    let rt = tokio::runtime::Handle::current();
    m.apply(
        &config_with(dir.path(), std::slice::from_ref(&a)),
        &rt,
        None,
    );
    let outs = latest(&rx);
    // What the aggregator does when a sink's buffer is full.
    outs[0].dropped.fetch_add(7, Ordering::Relaxed);
    assert_eq!(m.drops(), vec![("d".to_owned(), 7)]);
    // A reload that adds another sink: the count carries on.
    let other = sink(&format!(
        "name = \"e\"\ntype = \"file\"\npath = \"{}\"\n",
        dir.path().join("e.jsonl").display()
    ));
    m.apply(
        &config_with(dir.path(), &[a.clone(), other.clone()]),
        &rt,
        None,
    );
    assert_eq!(m.drops()[0], ("d".to_owned(), 7));
    // A change to its settings restarts it; the counter is the same one.
    let mut changed = a.clone();
    changed.keep = 9;
    m.apply(&config_with(dir.path(), &[changed, other]), &rt, None);
    let outs = latest(&rx);
    out(&outs, "d").dropped.fetch_add(3, Ordering::Relaxed);
    assert_eq!(m.drops()[0], ("d".to_owned(), 10));
    // Removed, then back: not reset.
    m.apply(&config_with(dir.path(), &[]), &rt, None);
    assert!(m.drops().is_empty(), "no sink, nothing to report");
    m.apply(&config_with(dir.path(), &[a]), &rt, None);
    assert_eq!(m.drops(), vec![("d".to_owned(), 10)]);
}

/// REQ: API-016, OBS-010 (ADR-903 section 7) - a resolver pod holds no stored secrets: a sink
/// that names one isn't started there (with its reason), and the others are.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_016_ephemeral_member_skips_sinks_that_need_stored_secrets() {
    let (hook, dir) = (Collector::new(), tempfile::tempdir().unwrap());
    let needs = webhook("needs", &hook.url(), "token_ref = \"hook-token\"\n");
    let plain = webhook("plain", &hook.url(), "");
    let mut cfg = config_with(dir.path(), &[needs, plain]);
    cfg.cluster.ephemeral = true;
    let (m, rx) = Manager::new();
    m.apply(&cfg, &tokio::runtime::Handle::current(), None);
    let states = m.states();
    let needs = states.iter().find(|s| s.name == "needs").unwrap();
    assert!(!needs.running);
    assert!(
        needs
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("stored secrets"))
    );
    assert!(states.iter().any(|s| s.name == "plain" && s.running));
    assert_eq!(latest(&rx).len(), 1);
}

/// REQ: OPS-014, API-016 (T23.11) - a webhook's stored token is read for every batch: a rotated
/// secret is sent from the next batch on, and the value is never in the sink's settings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_016_sink_token_ref_read_per_batch() {
    use crate::credential_tests::harness_toml;
    let hook = Collector::new();
    let h = harness_toml(
        "",
        None,
        vec![telltale_config::Cidr::parse("127.0.0.0/8").unwrap()],
        telltale_api::auth::Settings::default(),
    );
    let put = |v: &str| serde_json::json!({"value": v, "kind": "text"});
    let (s, _, out) = h
        .call(
            "PUT",
            "/api/v1/secrets/hook-token",
            Some(&put("first-token-3141")),
        )
        .await;
    assert_eq!(s, axum::http::StatusCode::OK, "{out}");
    let (s, _, out) = h
        .call(
            "PUT",
            "/api/v1/sinks/hook",
            Some(&serde_json::json!({
                "type": "webhook", "url": hook.url(), "batch": 1, "flush_secs": 1,
                "token_ref": "hook-token", "token_scheme": "Splunk"
            })),
        )
        .await;
    assert_eq!(s, axum::http::StatusCode::OK, "{out}");
    let cfg = h.src.config.load_full();
    let (m, rx) = Manager::new();
    m.apply(
        &cfg,
        &tokio::runtime::Handle::current(),
        Some(&h.src.secrets),
    );
    let outs = latest(&rx);
    outs[0].tx.try_send("{\"n\":1}".to_owned()).unwrap();
    assert!(wait_for(|| !hook.requests().is_empty(), 5));
    assert!(
        hook.requests()[0]
            .head
            .contains("authorization: splunk first-token-3141"),
        "{:?}",
        hook.requests()[0].head
    );
    let (s, _, _) = h
        .call(
            "PUT",
            "/api/v1/secrets/hook-token",
            Some(&put("second-token-2718")),
        )
        .await;
    assert_eq!(s, axum::http::StatusCode::OK);
    outs[0].tx.try_send("{\"n\":2}".to_owned()).unwrap();
    assert!(wait_for(|| hook.requests().len() >= 2, 5));
    assert!(
        hook.requests()[1]
            .head
            .contains("authorization: splunk second-token-2718"),
        "{:?}",
        hook.requests()[1].head
    );
    let (_, _, list) = h.call("GET", "/api/v1/sinks", None).await;
    let text = list.to_string();
    assert!(
        !text.contains("token-3141") && !text.contains("token-2718"),
        "{text}"
    );
}

/// REQ: API-016, OBS-010 (T23.11, review fix) - a webhook sink stopped while its collector
/// swallows requests doesn't hold up its replacement: the manager returns within the retire
/// wait, and the abandoned thread never touches the kept batches the new sink owns (an edit
/// that keeps the URL keeps the key).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_016_stopped_sink_against_blackhole_leaves_replacement_spill_alone() {
    // Accepts connections and never answers.
    let hole = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/in", hole.local_addr().unwrap());
    let held = Arc::new(Mutex::new(Vec::new()));
    let held_t = Arc::clone(&held);
    std::thread::spawn(move || {
        for c in hole.incoming().flatten() {
            held_t.lock().unwrap().push(c);
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let (m, rx) = Manager::new();
    let rt = tokio::runtime::Handle::current();
    let a = webhook("hole", &url, "spill_max_bytes = \"1MiB\"\n");
    m.apply(
        &config_with(dir.path(), std::slice::from_ref(&a)),
        &rt,
        None,
    );
    let outs = latest(&rx);
    for i in 0..10 {
        outs[0].tx.try_send(format!("{{\"n\":{i}}}")).unwrap();
    }
    std::thread::sleep(Duration::from_millis(500));

    // Same URL (same kept-batches key), another setting: the sink restarts.
    let b = webhook(
        "hole",
        &url,
        "spill_max_bytes = \"1MiB\"\nformat = \"json_array\"\n",
    );
    let started = Instant::now();
    let (m2, rt2, dir_path) = (Arc::clone(&m), rt.clone(), dir.path().to_owned());
    tokio::task::spawn_blocking(move || {
        m2.apply(
            &config_with(&dir_path, std::slice::from_ref(&b)),
            &rt2,
            None,
        );
    })
    .await
    .unwrap();
    assert!(
        started.elapsed() <= Duration::from_millis(3500),
        "the swap took {:?}",
        started.elapsed()
    );
    let spill = Spill::new(&a, dir.path().to_str().unwrap()).unwrap();
    assert!(spill.push(&["{\"mine\":1}".to_owned()]));
    // The straggler's request times out (15 s) and it ends; it must not have touched the files.
    assert!(
        wait_for(
            || {
                let inner = m.inner.lock().unwrap();
                inner
                    .stragglers
                    .iter()
                    .all(std::thread::JoinHandle::is_finished)
            },
            30
        ),
        "the abandoned thread ended"
    );
    let (events, _) = spill.take(100);
    assert_eq!(events, vec!["{\"mine\":1}".to_owned()]);
}

//! REQ: OBS-020 (T11.3, ADR-107, `spec/06` §9) — synthetic probes: every `[probe]
//! interval_secs`, this node asks each of its own DNS listeners a question through the
//! listener's protocol (UDP, TCP, DoT, DoH, DoH3, DoQ), plus any extra `[probe] targets` (a load
//! balancer's address), and reads each TLS listener's certificate expiry from its file.
//!
//! A probe is a real client of the listener (the upstream client, with certificate checks off
//! since it connects by IP), so it proves the whole path: socket, TLS, HTTP/2 or QUIC, the
//! pipeline. It asks `probe.wrendns.invalid`, which special-name handling answers NXDOMAIN
//! without an upstream; any well-formed answer is a success. The telemetry thread keeps those
//! queries out of the query log and analytics (`Record::is_probe`), and probes skip dnstap. They
//! still count in `wrendns_queries_total` like any query (a handful a minute).
//!
//! Runs on the runtime as its own task, a round at a time with a timeout per probe; DNS never
//! waits for it.
//!
//! With `[api] tls` (ADR-149) the web UI and API are checked too: a `GET /livez` over HTTPS, and
//! the certificate's expiry, SHA-256 fingerprint, and names. They aren't a DNS listener, so
//! they never count toward "isn't answering DNS".

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use wrendns_api::model::ProbeResult;
use wrendns_config::{Config, ListenProto};

/// The question every probe asks (see `wrendns_telemetry::event::PROBE_NAME`).
pub(crate) const PROBE_QNAME: &str = "probe.wrendns.invalid";
/// The `proto` of the web UI and API's check (ADR-149).
pub(crate) const API_PROTO: &str = "api";
/// REQ: API-003 (T24.44, ADR-1053) — the `proto` of the plain-HTTP redirect listener's checks.
pub(crate) const REDIRECT_PROTO: &str = "api-redirect";
/// Failures in a row that degrade the health level and fire `probe_failing`.
pub(crate) const FAILING_AFTER: u32 = 2;

/// One thing to probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// The URL the probe connects to (the upstream client's syntax).
    pub(crate) url: String,
    pub(crate) proto: &'static str,
    pub(crate) listener: bool,
    /// The listener's certificate file, for its expiry.
    pub(crate) cert: Option<String>,
    /// The certificate is the API's self-signed one (ADR-149).
    pub(crate) self_signed: bool,
    /// Why it isn't probed.
    pub(crate) skipped: Option<&'static str>,
}

/// The listener's address as a client reaches it: a wildcard bind is asked on loopback.
pub(crate) fn reachable(addr: SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, addr.port())
}

/// What to probe for `cfg`: its listeners, then the extra targets.
pub(crate) fn targets(cfg: &Config) -> Vec<Target> {
    let mut out: Vec<Target> = Vec::new();
    for l in &cfg.listen {
        let (scheme, proto) = match l.proto {
            ListenProto::Udp => ("udp", "udp"),
            ListenProto::Tcp => ("tcp", "tcp"),
            ListenProto::Dot => ("tls", "dot"),
            ListenProto::Doh => ("https", "doh"),
            ListenProto::Doh3 => ("h3", "doh3"),
            ListenProto::Doq => ("quic", "doq"),
        };
        let path = match l.proto {
            ListenProto::Doh | ListenProto::Doh3 => {
                l.path.as_deref().unwrap_or("/dns-query").to_owned()
            }
            _ => String::new(),
        };
        let url = format!("{scheme}://{}{path}", reachable(l.addr));
        if out.iter().any(|t| t.url == url) {
            continue;
        }
        out.push(Target {
            url,
            proto,
            listener: true,
            cert: l
                .tls
                .as_ref()
                .filter(|_| l.proto.needs_tls())
                .map(|t| t.cert.to_string()),
            self_signed: false,
            // REQ: DNS-901 — a gated listener refuses a query without a device key, and the probe
            // has none: probing it would fail every round and count as the node's own traffic.
            skipped: if l.proxy_protocol {
                Some("it requires a PROXY protocol header, which probes don't send")
            } else if crate::gate_host::effective_gate(l) {
                Some("it answers only a known device key, which probes don't have")
            } else {
                None
            },
        });
    }
    // REQ: API-003 (ADR-149) — the web UI and API over HTTPS, and their certificate.
    if cfg.api.enabled
        && let Some(tls) = &cfg.api.tls
    {
        let cert = match &tls.cert {
            Some(c) => c.to_string(),
            None => {
                crate::api_tls::self_signed_paths(std::path::Path::new(cfg.node.data_dir.as_str()))
                    .0
                    .to_string_lossy()
                    .into_owned()
            }
        };
        out.push(Target {
            url: format!("https://{}/livez", reachable(cfg.api.listen)),
            proto: API_PROTO,
            listener: true,
            cert: Some(cert),
            self_signed: tls.self_signed,
            skipped: None,
        });
    }
    // REQ: API-003 (T24.44, ADR-1053) — the redirect listener: `/livez` answers 200 and `/` is
    // redirected (308), both over plain HTTP.
    if cfg.api.enabled
        && cfg.api.tls.is_some()
        && let Some(addr) = cfg.api.http_redirect
    {
        for path in ["/livez", "/"] {
            out.push(Target {
                url: format!("http://{}{path}", reachable(addr)),
                proto: REDIRECT_PROTO,
                listener: true,
                cert: None,
                self_signed: false,
                skipped: None,
            });
        }
    }
    for t in &cfg.probe.targets {
        let Ok((scheme, _, _)) = wrendns_config::probe_target(t) else {
            continue;
        };
        let proto = match scheme {
            "udp" => "udp",
            "tcp" => "tcp",
            "tls" => "dot",
            "https" => "doh",
            "h3" => "doh3",
            _ => "doq",
        };
        out.push(Target {
            url: t.to_string(),
            proto,
            listener: false,
            cert: None,
            self_signed: false,
            skipped: None,
        });
    }
    out
}

/// Asks `url` the probe question once; the time it took, or why it failed.
async fn ask(url: &str, timeout: Duration) -> Result<Duration, String> {
    use wrendns_upstream::{Endpoint, Question, TlsOptions, Upstream, UpstreamOptions};
    let ep = Endpoint::parse(url)?;
    let opts = UpstreamOptions {
        timeout,
        pool_size: 1,
        idle_timeout: Duration::from_secs(1),
        // It connects by IP to this node's own listener; the certificate's expiry is checked
        // from its file instead.
        tls_insecure_skip_verify: true,
        self_probe: true,
        ..UpstreamOptions::default()
    };
    let up = Upstream::build(0, "probe", ep, &opts, &TlsOptions::default())?;
    let q = Question {
        name: wrendns_proto::NameBuf::from_presentation(PROBE_QNAME).map_err(|e| e.to_string())?,
        qtype: wrendns_proto::rtype::A,
        qclass: 1,
        dnssec_ok: false,
        checking_disabled: false,
        client_subnet: 0,
    };
    let start = Instant::now();
    match tokio::time::timeout(
        timeout + Duration::from_millis(500),
        up.exchange(&q, timeout),
    )
    .await
    {
        Ok(Ok(_)) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out".to_owned()),
    }
}

/// REQ: API-003 (ADR-149) — `GET` the web UI's `/livez` over HTTPS. Certificate checks are
/// off, as for the DNS probes: it connects by IP, and the certificate is read from its file.
async fn ask_https(url: &str, timeout: Duration) -> Result<Duration, String> {
    let client =
        wrendns_filter::fetch::Client::insecure(Arc::new(wrendns_filter::fetch::SystemResolver))?;
    let req = http::Request::get(url)
        .body(Vec::new())
        .map_err(|e| e.to_string())?;
    let start = Instant::now();
    match tokio::time::timeout(timeout, client.request(req, 4096)).await {
        Ok(Ok(r)) if r.status().is_success() => Ok(start.elapsed()),
        Ok(Ok(r)) => Err(format!("HTTP {}", r.status())),
        Ok(Err(e)) => Err(e.message),
        Err(_) => Err("timed out".to_owned()),
    }
}

/// REQ: API-003 (T24.44) — one plain `GET` of the redirect listener: `/` must answer 308 (with a
/// `Location` over `https://`), anything else (`/livez`) 200.
async fn ask_redirect(url: &str, timeout: Duration) -> Result<Duration, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rest = url
        .strip_prefix("http://")
        .ok_or("not an http:// address")?;
    let (hostport, path) = rest
        .split_once('/')
        .map_or((rest, "/"), |(h, _)| (h, &rest[h.len()..]));
    let want = if path == "/" { 308 } else { 200 };
    let start = Instant::now();
    let run = async {
        let mut tcp = tokio::net::TcpStream::connect(hostport)
            .await
            .map_err(|e| e.to_string())?;
        let req = format!("GET {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n");
        tcp.write_all(req.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while buf.len() < 4096 && !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tcp.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let head = String::from_utf8_lossy(&buf).into_owned();
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or("no HTTP answer")?;
        if status != want {
            return Err(format!("HTTP {status}, expected {want}"));
        }
        if want == 308 && !head.to_ascii_lowercase().contains("\r\nlocation: https://") {
            return Err("the redirect has no https:// Location".to_owned());
        }
        Ok(())
    };
    match tokio::time::timeout(timeout, run).await {
        Ok(Ok(())) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("timed out".to_owned()),
    }
}

/// A certificate file's expiry: (Unix seconds, days left), or why it can't be read.
pub(crate) fn cert_expiry(path: &str, now: u64) -> Result<(u64, i64), String> {
    let pem = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let (left, _) = wrendns_cluster::pki::validity(&pem).map_err(|e| e.to_string())?;
    Ok((now.saturating_add_signed(left), left.div_euclid(86_400)))
}

/// REQ: API-003 (ADR-149) — a certificate file's first certificate: its SHA-256 fingerprint
/// (as browsers show it: colon-separated uppercase hex) and the names it covers.
pub(crate) fn cert_identity(path: &str) -> Result<(String, Vec<String>), String> {
    let pem = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let digest = wrendns_cluster::pki::fingerprint(&pem).map_err(|e| e.to_string())?;
    let sha256 = digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let names = wrendns_cluster::pki::names(&pem).unwrap_or_default();
    Ok((sha256, names))
}

/// The probes' latest results and failure counts, for the API, health, alerts, and metrics.
#[derive(Debug, Default)]
pub(crate) struct Probes {
    latest: Mutex<Vec<ProbeResult>>,
    /// Failures since start, by target.
    failures: Mutex<BTreeMap<String, u64>>,
}

impl Probes {
    pub(crate) fn results(&self) -> Vec<ProbeResult> {
        self.latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn failures_total(&self, target: &str) -> u64 {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(target)
            .copied()
            .unwrap_or(0)
    }

    fn clear(&self) {
        self.latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Folds one round's outcomes into the results (`outcomes` in `targets` order).
    pub(crate) fn record(
        &self,
        targets: &[Target],
        outcomes: Vec<Option<Result<Duration, String>>>,
        now: u64,
    ) {
        let mut latest = self.latest.lock().unwrap_or_else(PoisonError::into_inner);
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let previous: Vec<ProbeResult> = std::mem::take(&mut *latest);
        for (t, outcome) in targets.iter().zip(outcomes) {
            let before = previous.iter().find(|p| p.target == t.url);
            let mut r = ProbeResult {
                node: None,
                target: t.url.clone(),
                proto: t.proto.to_owned(),
                listener: t.listener,
                checked_unix_seconds: now,
                last_ok_unix_seconds: before.and_then(|b| b.last_ok_unix_seconds),
                skipped: t.skipped.map(str::to_owned),
                ..ProbeResult::default()
            };
            match outcome {
                Some(Ok(took)) => {
                    r.ok = true;
                    r.latency_ms = Some((took.as_secs_f64() * 100_000.0).round() / 100.0);
                    r.last_ok_unix_seconds = Some(now);
                }
                Some(Err(e)) => {
                    r.error = Some(e);
                    r.consecutive_failures = before
                        .map_or(0, |b| b.consecutive_failures)
                        .saturating_add(1);
                    *failures.entry(t.url.clone()).or_default() += 1;
                }
                None => {}
            }
            if let Some(path) = &t.cert {
                match cert_expiry(path, now) {
                    Ok((at, days)) => {
                        r.cert_expires_unix_seconds = Some(at);
                        r.cert_days_left = Some(days);
                    }
                    Err(e) => r.cert_error = Some(e),
                }
                if let Ok((sha256, names)) = cert_identity(path) {
                    r.cert_sha256 = Some(sha256);
                    r.cert_names = names;
                }
                r.cert_self_signed = t.self_signed;
            }
            latest.push(r);
        }
    }

    /// One round: every target at once, each within the timeout.
    async fn round(&self, cfg: &Config) {
        let targets = targets(cfg);
        let timeout = Duration::from_millis(u64::from(cfg.probe.timeout_ms));
        let mut set = tokio::task::JoinSet::new();
        for (i, t) in targets.iter().enumerate() {
            if t.skipped.is_none() {
                let url = t.url.clone();
                if t.proto == API_PROTO {
                    set.spawn(async move { (i, ask_https(&url, timeout).await) });
                } else if t.proto == REDIRECT_PROTO {
                    set.spawn(async move { (i, ask_redirect(&url, timeout).await) });
                } else {
                    set.spawn(async move { (i, ask(&url, timeout).await) });
                }
            }
        }
        let mut outcomes: Vec<Option<Result<Duration, String>>> = vec![None; targets.len()];
        while let Some(done) = set.join_next().await {
            if let Ok((i, r)) = done
                && let Some(slot) = outcomes.get_mut(i)
            {
                *slot = Some(r);
            }
        }
        self.record(&targets, outcomes, crate::pipeline::unix_now());
    }
}

/// Starts the probes: a round every `[probe] interval_secs` once the listeners are bound,
/// following configuration reloads, until `stop`.
pub(crate) fn spawn(src: Arc<crate::http::Sources>, mut stop: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        // REQ: OBS-020 (T27.5) — until the listeners serve, the loop looks again every second
        // rather than waiting a whole interval: the first round follows the listeners' start.
        let mut served = false;
        loop {
            let cfg = src.config.load_full();
            if !cfg.probe.enabled {
                src.probes.clear();
            } else if src.readiness.serving() {
                // REQ: OPS-010 — probes keep measuring during maintenance.
                src.probes.round(&cfg).await;
                served = true;
            }
            let wait = if served || !cfg.probe.enabled {
                Duration::from_secs(u64::from(cfg.probe.interval_secs.max(5)))
            } else {
                Duration::from_secs(1)
            };
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                _ = stop.wait_for(|s| *s) => return,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> Config {
        wrendns_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config
    }

    // REQ: OBS-020 — what gets probed: each listener on the address a client reaches (loopback
    // for a wildcard bind), DoH on its path, PROXY-protocol listeners skipped, extra targets
    // after; the same address once.
    #[test]
    fn obs_020_targets_follow_the_listeners() {
        let c = cfg(r#"
[[listen]]
proto = "udp"
addr = "0.0.0.0:5353"
[[listen]]
proto = "udp"
addr = "[::]:5353"
[[listen]]
proto = "tcp"
addr = "192.168.1.2:53"
proxy_protocol = true
[[listen]]
proto = "doh"
addr = "0.0.0.0:443"
tls = { cert = "/etc/wrendns/cert.pem", key = "/etc/wrendns/key.pem" }
[probe]
targets = ["udp://10.50.5.112:53"]
"#);
        let t = targets(&c);
        let urls: Vec<&str> = t.iter().map(|t| t.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "udp://127.0.0.1:5353",
                "udp://[::1]:5353",
                "tcp://192.168.1.2:53",
                "https://127.0.0.1:443/dns-query",
                "udp://10.50.5.112:53"
            ]
        );
        assert!(t[2].skipped.is_some(), "PROXY protocol");
        assert_eq!(t[3].proto, "doh");
        assert_eq!(t[3].cert.as_deref(), Some("/etc/wrendns/cert.pem"));
        assert!(!t[4].listener);
    }

    // REQ: DNS-901 — a listener that needs a device key is not probed (the probe has none), but its
    // certificate is still listed for expiry.
    #[test]
    fn dns_901_a_gated_listener_is_not_probed() {
        let c = cfg(r#"
[[listen]]
proto = "doh"
addr = "0.0.0.0:443"
require_client_id = true
tls = { cert = "/etc/wrendns/cert.pem", key = "/etc/wrendns/key.pem" }
[[listen]]
proto = "dot"
addr = "0.0.0.0:853"
require_client_id = true
tls = { cert = "/etc/wrendns/cert.pem", key = "/etc/wrendns/key.pem" }
"#);
        let t = targets(&c);
        assert_eq!(t.len(), 2);
        assert!(t.iter().all(|t| t.skipped.is_some()));
        assert_eq!(t[0].cert.as_deref(), Some("/etc/wrendns/cert.pem"));
    }

    // REQ: API-003 (ADR-149) — with `[api] tls` the web UI is checked over HTTPS, with its
    // certificate (the self-signed one's path in the data directory); the check answers, and
    // the certificate's fingerprint and names are read.
    #[tokio::test]
    async fn api_003_the_web_ui_is_checked_over_https() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(&format!(
            "[node]\ndata_dir = {:?}\n[api]\nlisten = \"0.0.0.0:8053\"\ntls = {{ self_signed = true }}\n",
            dir.path().to_string_lossy()
        ));
        let t = targets(&c);
        let api = t.iter().find(|t| t.proto == API_PROTO).unwrap();
        assert_eq!(api.url, "https://127.0.0.1:8053/livez");
        assert!(api.self_signed && api.listener);
        assert!(api.cert.as_deref().unwrap().ends_with("api-tls/cert.pem"));

        c.api.listen = "127.0.0.1:0".parse().unwrap();
        let tls = crate::api_tls::setup(&c, c.api.tls.as_ref().unwrap()).unwrap();
        let app = axum::Router::new().route("/livez", axum::routing::get(|| async { "ok\n" }));
        let (_stop, rx) = tokio::sync::oneshot::channel::<()>();
        let addr = crate::api_tls::serve(c.api.listen, app, &tls, async {
            let _ = rx.await;
        })
        .await
        .unwrap();
        let url = format!("https://127.0.0.1:{}/livez", addr.port());
        assert!(ask_https(&url, Duration::from_secs(5)).await.is_ok());

        let p = Probes::default();
        let target = Target {
            url,
            cert: api.cert.clone(),
            ..api.clone()
        };
        p.record(&[target], vec![Some(Ok(Duration::from_millis(2)))], 100);
        let r = &p.results()[0];
        assert!(r.cert_self_signed);
        assert_eq!(
            r.cert_sha256.as_deref().map(str::len),
            Some(95),
            "32 bytes as AA:BB:…"
        );
        assert!(r.cert_names.iter().any(|n| n == "127.0.0.1"));
        assert!(
            r.cert_days_left.unwrap() > 365 * 100,
            "a self-signed one doesn't expire"
        );
    }

    // REQ: API-003 (T24.44) — with `[api] http_redirect` the redirect listener is checked over plain
    // HTTP: `/livez` must answer 200 and `/` must be redirected (308); without TLS there is no check.
    #[tokio::test]
    async fn api_003_the_http_redirect_is_checked() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(&format!(
            "[node]
data_dir = {:?}
[api]
listen = \"0.0.0.0:443\"
tls = {{ self_signed = true }}
http_redirect = \"0.0.0.0:80\"
",
            dir.path().to_string_lossy()
        ));
        let t: Vec<_> = targets(&c)
            .into_iter()
            .filter(|t| t.proto == REDIRECT_PROTO)
            .collect();
        assert_eq!(
            t.iter().map(|t| t.url.as_str()).collect::<Vec<_>>(),
            ["http://127.0.0.1:80/livez", "http://127.0.0.1:80/"]
        );
        // A tiny server that answers like the redirect listener.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = l.accept().await {
                // Strict like a real server: it answers only a request ended by CRLF CRLF, with
                // CRLF line ends, and then keeps the connection open (keep-alive).
                let mut raw = Vec::new();
                let mut buf = [0u8; 512];
                while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                }
                let head = String::from_utf8_lossy(&raw).into_owned();
                if !head.contains("\r\nHost: ") || head.replace("\r\n", "").contains('\n') {
                    continue;
                }
                let out = if head.starts_with("GET /livez ") {
                    "HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nok\n"
                } else {
                    "HTTP/1.1 308 Permanent Redirect\r\nlocation: https://127.0.0.1/\r\ncontent-length: 0\r\n\r\n"
                };
                let _ = s.write_all(out.as_bytes()).await;
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
        let to = Duration::from_secs(5);
        assert!(
            ask_redirect(&format!("http://127.0.0.1:{port}/livez"), to)
                .await
                .is_ok()
        );
        assert!(
            ask_redirect(&format!("http://127.0.0.1:{port}/"), to)
                .await
                .is_ok()
        );
        let mut plain = c.clone();
        plain.api.tls = None;
        assert!(targets(&plain).iter().all(|t| t.proto != REDIRECT_PROTO));
    }

    // REQ: OBS-020 — failures in a row count up and reset on success; the last success and the
    // failures since start are kept; an unreadable certificate says why.
    #[test]
    fn obs_020_results_track_failures() {
        let p = Probes::default();
        let t = vec![Target {
            url: "tls://127.0.0.1:853".into(),
            proto: "dot",
            listener: true,
            cert: Some("/nonexistent/cert.pem".into()),
            self_signed: false,
            skipped: None,
        }];
        p.record(&t, vec![Some(Ok(Duration::from_millis(3)))], 100);
        p.record(&t, vec![Some(Err("timed out".into()))], 130);
        p.record(&t, vec![Some(Err("timed out".into()))], 160);
        let r = &p.results()[0];
        assert_eq!((r.ok, r.consecutive_failures), (false, 2));
        assert_eq!(r.last_ok_unix_seconds, Some(100));
        assert!(r.cert_error.as_deref().unwrap().contains("/nonexistent"));
        assert_eq!(p.failures_total("tls://127.0.0.1:853"), 2);
        p.record(&t, vec![Some(Ok(Duration::from_millis(4)))], 190);
        let r = &p.results()[0];
        assert_eq!(
            (r.ok, r.consecutive_failures, r.latency_ms),
            (true, 0, Some(4.0))
        );
    }

    // REQ: OBS-020 — a real probe of a real listener, end to end over UDP, and a closed port
    // fails.
    #[tokio::test]
    async fn obs_020_a_probe_gets_an_answer() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                // NXDOMAIN, as the special-name handling answers.
                buf[2] |= 0x80;
                buf[3] = (buf[3] & 0xF0) | 3;
                let _ = sock.send_to(&buf[..n], peer).await;
            }
        });
        let took = ask(&format!("udp://{addr}"), Duration::from_secs(2)).await;
        assert!(took.is_ok(), "{took:?}");
        let closed = ask("tcp://127.0.0.1:9", Duration::from_millis(300)).await;
        assert!(closed.is_err());
    }
}

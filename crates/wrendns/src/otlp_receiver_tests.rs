//! REQ: OBS-006, OBS-017 (T7.17, issue #155) - the OTLP export against a local fake OTLP/HTTP
//! receiver (an in-process TCP listener on loopback): metrics, logs and traces arrive at the paths
//! a collector's `otlphttp` receiver serves (`/v1/metrics`, `/v1/logs`, `/v1/traces`), as JSON,
//! with the headers a collector expects, plain and gzip compressed, and the resource attributes
//! that join WrenDNS's signals with other sources. Nothing leaves the machine.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;

use crate::credential_tests::{Harness, harness_toml};

/// One request the receiver took.
#[derive(Debug, Clone)]
pub(crate) struct Req {
    /// The request head, lower-cased (request line and headers).
    pub(crate) head: String,
    /// The body as it came on the wire.
    pub(crate) raw: Vec<u8>,
}

impl Req {
    pub(crate) fn path(&self) -> &str {
        self.head.split_whitespace().nth(1).unwrap_or_default()
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        let key = format!("{name}:");
        self.head
            .lines()
            .find_map(|l| l.strip_prefix(&key))
            .map(str::trim)
    }

    /// The JSON the request carries, after undoing `Content-Encoding: gzip` the way a collector
    /// does.
    pub(crate) fn json(&self) -> Value {
        let bytes = if self.header("content-encoding") == Some("gzip") {
            assert!(
                self.raw.starts_with(&[0x1f, 0x8b]),
                "the body is a gzip member"
            );
            crate::archive::gunzip(&self.raw).expect("a valid gzip body (CRC and size checked)")
        } else {
            self.raw.clone()
        };
        serde_json::from_slice(&bytes).expect("a JSON body")
    }
}

/// A fake OTLP/HTTP receiver: answers 200 `{}` to every POST and keeps what it was sent.
pub(crate) struct Receiver {
    addr: SocketAddr,
    got: Arc<Mutex<Vec<Req>>>,
    stop: Arc<AtomicBool>,
}

impl Receiver {
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

    /// The base URL an exporter's `endpoint` is set to.
    pub(crate) fn url_base(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub(crate) fn requests(&self) -> Vec<Req> {
        self.got.lock().unwrap().clone()
    }

    /// The only request to `path`; panics when there is not exactly one.
    pub(crate) fn one(&self, path: &str) -> Req {
        let mut all: Vec<Req> = self
            .requests()
            .into_iter()
            .filter(|r| r.path() == path)
            .collect();
        assert_eq!(all.len(), 1, "one request to {path}: {all:?}");
        all.remove(0)
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn serve(mut conn: std::net::TcpStream, got: &Mutex<Vec<Req>>) {
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
        let raw = buf[head_end + 4..head_end + 4 + len].to_vec();
        buf.drain(..head_end + 4 + len);
        got.lock().unwrap().push(Req { head, raw });
        let reply =
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}";
        if conn.write_all(reply.as_bytes()).is_err() {
            return;
        }
    }
}

/// A node whose configuration files point the export at `rx`, with a header and `compression`.
pub(crate) fn node_for(rx: &Receiver, compression: &str) -> Harness {
    harness_toml(
        &format!(
            "[node]\nname = \"pi-a\"\n[telemetry.otlp]\nendpoint = \"{}\"\ninterval_secs = 5\ncompression = \"{compression}\"\nheaders = {{ \"x-api-key\" = \"collector-key-1\" }}\n",
            rx.url_base()
        ),
        None,
        vec![wrendns_config::Cidr::parse("127.0.0.0/8").unwrap()],
        wrendns_api::auth::Settings::default(),
    )
}

/// What every export request must carry, whatever the signal or the compression.
pub(crate) fn assert_collector_headers(r: &Req, gzip: bool) {
    assert!(r.head.starts_with("post "), "{}", r.head);
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.header("user-agent"), Some("wrendns"));
    assert_eq!(r.header("x-api-key"), Some("collector-key-1"));
    assert_eq!(
        r.header("content-encoding"),
        gzip.then_some("gzip"),
        "{}",
        r.head
    );
    // The length on the wire is the body's as sent (the compressed one for gzip).
    assert_eq!(
        r.header("content-length")
            .and_then(|v| v.parse::<usize>().ok()),
        Some(r.raw.len())
    );
}

/// The resource attributes WrenDNS's signals carry, so a backend can join them with others.
pub(crate) fn assert_resource(resource: &Value) {
    let get = |k: &str| {
        resource["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["key"] == k)
            .and_then(|a| a["value"]["stringValue"].as_str())
            .map(str::to_owned)
    };
    assert_eq!(get("service.name").as_deref(), Some("wrendns"));
    assert_eq!(get("host.name").as_deref(), Some("pi-a"));
    assert_eq!(get("service.instance.id").as_deref(), Some("pi-a"));
    assert!(get("service.version").is_some());
}

const EVENT: &str = r#"{"time":"t","tsUnixMicros":1700000000000000,"client":"192.168.1.5","name":"ads.example","qtype":"A","status":"blocked","rcode":"NOERROR","proto":"udp","list":"ads","totalMs":0.2}"#;

async fn metrics_and_logs(compression: &str) {
    let gzip = compression == "gzip";
    let rx = Receiver::new();
    let h = node_for(&rx, compression);
    let cfg = h.src.config.load_full();
    let client = crate::otlp::client().unwrap();
    let node = crate::http::node_name(&cfg);

    // Metrics: the real exposition, converted as the export task does, and sent by `post`.
    let text = crate::http::render(&h.src);
    let body = crate::otlp::metrics_body(&text, &crate::otlp::resource(&node), 1, 2).to_string();
    let url = format!("{}/v1/metrics", crate::otlp::endpoint(&cfg).unwrap());
    crate::otlp::post(&client, &url, &cfg, body, &h.src.secrets)
        .await
        .unwrap();
    let r = rx.one("/v1/metrics");
    assert_collector_headers(&r, gzip);
    let v = r.json();
    assert_resource(&v["resourceMetrics"][0]["resource"]);
    let metrics = v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        .as_array()
        .unwrap();
    assert!(
        metrics.iter().any(|m| m["name"]
            .as_str()
            .is_some_and(|n| n.starts_with("wrendns_"))),
        "WrenDNS's own metrics arrived"
    );

    // Logs: through the event sink's own request path (a webhook sink with format otlp_logs).
    let sink: wrendns_config::SinkConfig = toml::from_str(&format!(
        "name = \"otel\"\ntype = \"webhook\"\nformat = \"otlp_logs\"\nurl = \"{}/v1/logs\"\n",
        rx.url_base()
    ))
    .unwrap();
    let body = crate::sinks::webhook_body(&sink, &[EVENT.to_owned()], &node);
    crate::sinks::post(&client, &sink, body, None)
        .await
        .unwrap();
    let r = rx.one("/v1/logs");
    assert!(r.head.starts_with("post "));
    assert_eq!(r.header("content-type"), Some("application/json"));
    // An event sink has its own request path and settings: the export's compression is not its.
    assert_eq!(r.header("content-encoding"), None, "a sink's logs go plain");
    let v = r.json();
    assert_resource(&v["resourceLogs"][0]["resource"]);
    let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
    assert_eq!(rec["severityText"], "WARN");
    assert!(
        rec["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["key"] == "dns.question.name" && a["value"]["stringValue"] == "ads.example")
    );
}

/// REQ: OBS-006 (issue #155) - plain JSON: metrics and logs reach the receiver at the
/// collector's paths with the headers it expects and the resource attributes.
#[tokio::test]
async fn obs_006_receiver_gets_plain_metrics_and_logs() {
    metrics_and_logs("none").await;
}

/// REQ: OBS-006 (issue #155) - `compression = "gzip"`: the same JSON, gzip-framed, with
/// `Content-Encoding: gzip`; the receiver decodes it (CRC and size checked) to the same document.
#[tokio::test]
async fn obs_006_receiver_gets_gzip_metrics() {
    metrics_and_logs("gzip").await;
}

/// REQ: OBS-006 (issue #155) - the export task itself (not only `post`) sends the metrics
/// gzip-compressed when configured.
#[tokio::test]
async fn obs_006_export_task_sends_gzip() {
    let rx = Receiver::new();
    let h = node_for(&rx, "gzip");
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(crate::otlp::run(Arc::clone(&h.src), stop_rx));
    let mut got = false;
    for _ in 0..200 {
        if !rx.requests().is_empty() {
            got = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = stop_tx.send(true);
    let _ = task.await;
    assert!(got, "the first export arrived");
    let r = rx.requests().remove(0);
    assert_eq!(r.path(), "/v1/metrics");
    assert_collector_headers(&r, true);
    assert_resource(&r.json()["resourceMetrics"][0]["resource"]);
}

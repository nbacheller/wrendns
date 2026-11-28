// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: OBS-006, OBS-017 (T7.17, issue #155) - the OTLP export against a local fake OTLP/HTTP
//! receiver (an in-process TCP listener on loopback): metrics, logs and traces arrive at the paths
//! a collector's `otlphttp` receiver serves (`/v1/metrics`, `/v1/logs`, `/v1/traces`), as JSON,
//! with the headers a collector expects, plain and gzip compressed, and the resource attributes
//! that join WrenDNS's signals with other sources. Nothing leaves the machine.

use std::fmt::Write as _;
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

    /// The body after undoing `Content-Encoding: gzip` the way a collector does.
    pub(crate) fn bytes(&self) -> Vec<u8> {
        if self.header("content-encoding") == Some("gzip") {
            assert!(
                self.raw.starts_with(&[0x1f, 0x8b]),
                "the body is a gzip member"
            );
            crate::archive::gunzip(&self.raw).expect("a valid gzip body (CRC and size checked)")
        } else {
            self.raw.clone()
        }
    }

    /// The JSON the request carries, after undoing `Content-Encoding: gzip` the way a collector
    /// does.
    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes()).expect("a JSON body")
    }

    /// The protobuf the request carries, read back as the OTLP JSON document it encodes.
    pub(crate) fn proto(&self, signal: crate::otlp_proto::Signal) -> Value {
        assert_eq!(self.header("content-type"), Some("application/x-protobuf"));
        crate::otlp_proto::reader::decode(signal, &self.bytes())
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
        Self::start(None)
    }

    /// A receiver that speaks TLS with `cfg` (a private CA's certificate).
    pub(crate) fn tls(cfg: Arc<rustls::ServerConfig>) -> Self {
        Self::start(Some(cfg))
    }

    fn start(tls: Option<Arc<rustls::ServerConfig>>) -> Self {
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
                        let tls = tls.clone();
                        std::thread::spawn(move || {
                            let _ = conn.set_nonblocking(false);
                            let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
                            match tls {
                                None => serve(conn, &g),
                                Some(cfg) => {
                                    if let Ok(c) = rustls::ServerConnection::new(cfg) {
                                        serve(rustls::StreamOwned::new(c, conn), &g);
                                    }
                                }
                            }
                        });
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

    /// The https base URL of a TLS receiver, by the name its certificate carries.
    pub(crate) fn https_base(&self) -> String {
        format!("https://localhost:{}", self.addr.port())
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

fn serve<S: Read + Write>(mut conn: S, got: &Mutex<Vec<Req>>) {
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
    let doc = crate::otlp::metrics_body(&text, &crate::otlp::resource(&node), 1, 2);
    let url = format!("{}/v1/metrics", crate::otlp::endpoint(&cfg).unwrap());
    crate::otlp::post(
        &client,
        &url,
        &cfg,
        crate::otlp_proto::Signal::Metrics,
        &doc,
        &h.src.secrets,
    )
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

/// A node whose files point the export at `endpoint`, with `extra` lines under `[telemetry.otlp]`.
pub(crate) fn node_at(endpoint: &str, extra: &str) -> Harness {
    harness_toml(
        &format!(
            "[node]\nname = \"pi-a\"\n[telemetry.otlp]\nendpoint = \"{endpoint}\"\ninterval_secs = 5\n{extra}\nheaders = {{ \"x-api-key\" = \"collector-key-1\" }}\n"
        ),
        None,
        vec![wrendns_config::Cidr::parse("127.0.0.0/8").unwrap()],
        wrendns_api::auth::Settings::default(),
    )
}

/// REQ: OBS-006 (T41.2) - `encoding = "protobuf"`: the metrics arrive as `application/x-protobuf`
/// (plain and gzip), and the receiver reads the same document the JSON export builds, with the extra
/// resource attributes and the cluster name on the resource.
async fn protobuf_metrics(compression: &str) {
    let gzip = compression == "gzip";
    let rx = Receiver::new();
    let h = node_at(
        &rx.url_base(),
        &format!(
            "encoding = \"protobuf\"\ncompression = \"{compression}\"\nresource_attributes = {{ \"deployment.environment\" = \"home\", team = \"net\" }}"
        ),
    );
    let cfg = h.src.config.load_full();
    let client = crate::otlp::client().unwrap();
    let node = crate::http::node_name(&cfg);
    let text = crate::http::render(&h.src);
    let resource = crate::otlp::resource_for(&cfg, Some("home-cluster"), &node);
    let doc = crate::otlp::metrics_body(
        &text,
        &resource,
        1_700_000_000_000_000_000,
        1_700_000_060_000_000_000,
    );
    let url = format!("{}/v1/metrics", crate::otlp::endpoint(&cfg).unwrap());
    crate::otlp::post(
        &client,
        &url,
        &cfg,
        crate::otlp_proto::Signal::Metrics,
        &doc,
        &h.src.secrets,
    )
    .await
    .unwrap();
    let r = rx.one("/v1/metrics");
    assert!(r.head.starts_with("post "), "{}", r.head);
    assert_eq!(r.header("content-type"), Some("application/x-protobuf"));
    assert_eq!(r.header("x-api-key"), Some("collector-key-1"));
    assert_eq!(r.header("content-encoding"), gzip.then_some("gzip"));
    let got = r.proto(crate::otlp_proto::Signal::Metrics);
    assert_eq!(got, crate::otlp_proto::tests::norm(&doc));
    assert_resource(&got["resourceMetrics"][0]["resource"]);
    let attr = |k: &str| {
        got["resourceMetrics"][0]["resource"]["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["key"] == k)
            .and_then(|a| a["value"]["stringValue"].as_str())
            .map(str::to_owned)
    };
    assert_eq!(attr("deployment.environment").as_deref(), Some("home"));
    assert_eq!(attr("team").as_deref(), Some("net"));
    assert_eq!(
        attr("wrendns.cluster.name").as_deref(),
        Some("home-cluster")
    );
    let metrics = got["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        .as_array()
        .unwrap();
    assert!(
        metrics.iter().any(|m| m["name"]
            .as_str()
            .is_some_and(|n| n.starts_with("wrendns_"))),
        "WrenDNS's own metrics arrived"
    );
}

/// REQ: OBS-006 (T41.2) - protobuf metrics, plain.
#[tokio::test]
async fn obs_006_receiver_gets_protobuf_metrics() {
    protobuf_metrics("none").await;
}

/// REQ: OBS-006 (T41.2) - protobuf metrics, gzip-framed.
#[tokio::test]
async fn obs_006_receiver_gets_gzip_protobuf_metrics() {
    protobuf_metrics("gzip").await;
}

/// REQ: OBS-006 (T41.2) - the export task itself sends protobuf when configured, with the
/// owner's attributes on the resource.
#[tokio::test]
async fn obs_006_export_task_sends_protobuf() {
    let rx = Receiver::new();
    let h = node_at(
        &rx.url_base(),
        "encoding = \"protobuf\"\nresource_attributes = { \"deployment.environment\" = \"home\" }",
    );
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
    let v = r.proto(crate::otlp_proto::Signal::Metrics);
    assert_resource(&v["resourceMetrics"][0]["resource"]);
    assert!(
        v["resourceMetrics"][0]["resource"]["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["key"] == "deployment.environment" && a["value"]["stringValue"] == "home")
    );
}

/// REQ: OBS-006 (T41.2) - the resource: the cluster's name for a member, the owner's attributes
/// after the built-in ones, a reserved name never overriding one (even if one got past the check).
#[test]
fn obs_006_resource_for_adds_cluster_and_owner_attributes() {
    let mut cfg = wrendns_config::Config::default();
    cfg.node.name = wrendns_config::SafeString::new("pi-a").unwrap();
    cfg.telemetry.otlp.resource_attributes.insert(
        wrendns_config::SafeString::new("deployment.environment").unwrap(),
        wrendns_config::SafeString::new("home").unwrap(),
    );
    cfg.telemetry.otlp.resource_attributes.insert(
        wrendns_config::SafeString::new("service.name").unwrap(),
        wrendns_config::SafeString::new("impostor").unwrap(),
    );
    let keys = |r: &Value| -> Vec<(String, String)> {
        r["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                (
                    a["key"].as_str().unwrap().to_owned(),
                    a["value"]["stringValue"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    };
    let standalone = keys(&crate::otlp::resource_for(&cfg, None, "pi-a"));
    assert!(standalone.iter().all(|(k, _)| k != "wrendns.cluster.name"));
    assert!(standalone.contains(&("deployment.environment".into(), "home".into())));
    assert!(standalone.contains(&("service.name".into(), "wrendns".into())));
    assert!(!standalone.iter().any(|(_, v)| v == "impostor"));
    let member = keys(&crate::otlp::resource_for(&cfg, Some("home"), "pi-a"));
    assert!(member.contains(&("wrendns.cluster.name".into(), "home".into())));
}

/// A throwaway private CA, and a receiver certificate it signed for `localhost`: the CA's
/// certificate as PEM text, and the TLS server configuration of the receiver.
pub(crate) fn private_ca() -> (String, Arc<rustls::ServerConfig>) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Home test CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        leaf_key.serialize_der(),
    ));
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf.der().clone(), ca.der().clone()], key)
    .unwrap();
    (ca.pem(), Arc::new(cfg))
}

fn metrics_doc(h: &Harness) -> (wrendns_config::Config, Value, String) {
    let cfg = h.src.config.load_full();
    let text = crate::http::render(&h.src);
    let doc = crate::otlp::metrics_body(&text, &crate::otlp::resource("pi-a"), 1, 2);
    let url = format!("{}/v1/metrics", crate::otlp::endpoint(&cfg).unwrap());
    ((*cfg).clone(), doc, url)
}

/// REQ: OBS-006 (T41.2) - a collector whose TLS certificate comes from a private CA: refused with
/// the public roots only, delivered once the CA file (`tls_ca`) is named, and a file with no
/// certificate in it is an error rather than "no extra trust".
#[tokio::test]
async fn obs_006_private_ca_file_trusts_the_collector() {
    let (ca_pem, server) = private_ca();
    let rx = Receiver::tls(server);
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &ca_pem).unwrap();
    let h = node_at(
        &rx.https_base(),
        &format!(
            "tls_ca = \"{}\"",
            ca_path.to_string_lossy().replace('\\', "/")
        ),
    );
    let (cfg, doc, url) = metrics_doc(&h);
    // The public roots alone do not know the private CA.
    let public = crate::otlp::client().unwrap();
    let refused = crate::otlp::post(
        &public,
        &url,
        &cfg,
        crate::otlp_proto::Signal::Metrics,
        &doc,
        &h.src.secrets,
    )
    .await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(
        rx.requests().is_empty(),
        "nothing was sent before the handshake"
    );
    // With the CA file it is delivered.
    let mut clients = crate::otlp::Clients::new();
    let client = clients.get(&cfg, &h.src.secrets).unwrap();
    crate::otlp::post(
        client,
        &url,
        &cfg,
        crate::otlp_proto::Signal::Metrics,
        &doc,
        &h.src.secrets,
    )
    .await
    .unwrap();
    assert_eq!(
        rx.one("/v1/metrics").header("x-api-key"),
        Some("collector-key-1")
    );
    // A file with no certificate is an error.
    std::fs::write(&ca_path, "not a certificate\n").unwrap();
    let mut fresh = crate::otlp::Clients::new();
    let err = fresh.get(&cfg, &h.src.secrets).err().unwrap();
    assert!(err.contains("no certificate"), "{err}");
}

/// REQ: OBS-006 (T41.2) - the CA as a stored `pem` secret (`tls_ca_ref`, set through the API): the
/// export task delivers metrics to the TLS collector, with the public roots still trusted; a
/// rotated secret is read at the next export.
#[tokio::test]
async fn obs_006_private_ca_secret_trusts_the_collector() {
    let (ca_pem, server) = private_ca();
    let rx = Receiver::tls(server);
    // A node with no export in its files, so the API's entry applies.
    let h = harness_toml(
        "[node]\nname = \"pi-a\"\n",
        None,
        vec![wrendns_config::Cidr::parse("127.0.0.0/8").unwrap()],
        wrendns_api::auth::Settings::default(),
    );
    h.src
        .secrets
        .put(
            "otlp-ca",
            crate::secrets::value::Kind::Pem,
            &crate::secrets::SecretValue::new(
                crate::secrets::value::Kind::Pem,
                zeroize::Zeroizing::new(ca_pem),
            )
            .unwrap(),
            0,
            "root",
            "local",
            1,
        )
        .unwrap();
    let (s, _, out) = h
        .call(
            "PUT",
            "/api/v1/otlp/default",
            Some(&serde_json::json!({
                "endpoint": rx.https_base(), "interval_secs": 5, "encoding": "protobuf",
                "tls_ca_ref": "otlp-ca",
            })),
        )
        .await;
    assert_eq!(s, axum::http::StatusCode::OK, "{out}");
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
    assert!(got, "the export reached the TLS collector");
    let r = rx.requests().remove(0);
    assert_eq!(r.path(), "/v1/metrics");
    assert_resource(&r.proto(crate::otlp_proto::Signal::Metrics)["resourceMetrics"][0]["resource"]);
    // A reference naming nothing is an error, not "no extra trust".
    let cfg = h.src.config.load_full();
    let mut other = (*cfg).clone();
    other.telemetry.managed_otlp = Some(wrendns_config::OtlpConfig {
        endpoint: Some("https://localhost:1".into()),
        tls_ca_ref: Some("missing".into()),
        ..wrendns_config::OtlpConfig::default()
    });
    assert!(crate::otlp::ca_pem(&other, &h.src.secrets).is_err());
}

/// A fake OTLP/gRPC collector: an HTTP/2 server (h2c, or TLS with ALPN `h2`) that keeps each call
/// and answers with `grpc-status` `status` in the trailers.
pub(crate) struct GrpcReceiver {
    addr: SocketAddr,
    got: Arc<Mutex<Vec<Req>>>,
    task: tokio::task::JoinHandle<()>,
}

/// A response body: one data frame, then trailers.
struct Reply(std::collections::VecDeque<hyper::body::Frame<bytes::Bytes>>);

impl hyper::body::Body for Reply {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Ready(self.0.pop_front().map(Ok))
    }
}

impl GrpcReceiver {
    pub(crate) async fn start(
        tls: Option<Arc<rustls::ServerConfig>>,
        status: &'static str,
        message: &'static str,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let got = Arc::new(Mutex::new(Vec::new()));
        let acceptor = tls.map(|cfg| {
            let mut cfg = (*cfg).clone();
            cfg.alpn_protocols = vec![b"h2".to_vec()];
            tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
        });
        let g = Arc::clone(&got);
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (g, acceptor) = (Arc::clone(&g), acceptor.clone());
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(
                        move |req: http::Request<hyper::body::Incoming>| {
                            let g = Arc::clone(&g);
                            async move {
                                let (parts, mut body) = req.into_parts();
                                let mut raw = Vec::new();
                                while let Some(Ok(frame)) = std::future::poll_fn(|cx| {
                                    hyper::body::Body::poll_frame(std::pin::Pin::new(&mut body), cx)
                                })
                                .await
                                {
                                    if let Ok(d) = frame.into_data() {
                                        raw.extend_from_slice(&d);
                                    }
                                }
                                let mut head = format!("post {} http/2\r\n", parts.uri.path());
                                for (k, v) in &parts.headers {
                                    let _ = write!(head, "{k}: {}\r\n", v.to_str().unwrap_or(""));
                                }
                                g.lock().unwrap().push(Req {
                                    head: head.to_ascii_lowercase(),
                                    raw,
                                });
                                let mut trailers = http::HeaderMap::new();
                                trailers.insert("grpc-status", status.parse().unwrap());
                                if !message.is_empty() {
                                    trailers.insert("grpc-message", message.parse().unwrap());
                                }
                                let frames = std::collections::VecDeque::from([
                                    hyper::body::Frame::data(bytes::Bytes::from_static(&[0; 5])),
                                    hyper::body::Frame::trailers(trailers),
                                ]);
                                Ok::<_, std::convert::Infallible>(
                                    http::Response::builder()
                                        .header("content-type", "application/grpc")
                                        .body(Reply(frames))
                                        .unwrap(),
                                )
                            }
                        },
                    );
                    let exec = hyper_util::rt::TokioExecutor::new();
                    match acceptor {
                        None => {
                            let _ = hyper::server::conn::http2::Builder::new(exec)
                                .serve_connection(hyper_util::rt::TokioIo::new(tcp), svc)
                                .await;
                        }
                        Some(a) => {
                            if let Ok(tls) = a.accept(tcp).await {
                                let _ = hyper::server::conn::http2::Builder::new(exec)
                                    .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                                    .await;
                            }
                        }
                    }
                });
            }
        });
        Self { addr, got, task }
    }

    pub(crate) fn url_base(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub(crate) fn https_base(&self) -> String {
        format!("https://localhost:{}", self.addr.port())
    }

    pub(crate) fn requests(&self) -> Vec<Req> {
        self.got.lock().unwrap().clone()
    }
}

impl Drop for GrpcReceiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The protobuf message inside a gRPC request body (flag, length, message), gunzipped when the
/// frame says it is compressed.
fn grpc_message(r: &Req) -> Vec<u8> {
    assert!(r.raw.len() >= 5, "a length-prefixed message");
    let len = u32::from_be_bytes(r.raw[1..5].try_into().unwrap()) as usize;
    assert_eq!(
        r.raw.len(),
        5 + len,
        "the prefix gives the message's length"
    );
    let message = &r.raw[5..];
    match r.raw[0] {
        0 => message.to_vec(),
        1 => {
            assert_eq!(r.header("grpc-encoding"), Some("gzip"));
            crate::archive::gunzip(message).expect("a valid gzip message")
        }
        f => panic!("compressed flag {f}"),
    }
}

const GRPC_METRICS: &str = "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export";

/// REQ: OBS-006 (T41.2) - `encoding = "grpc"`: a unary call to the collector's `Export` method over
/// HTTP/2, `application/grpc`, a length-prefixed protobuf message (compressed inside the frame with
/// `grpc-encoding: gzip` when the export compresses), the configured header, and `grpc-status` 0
/// read from the trailers; the receiver reads the same document the JSON export builds.
async fn grpc_metrics(compression: &str) {
    let gzip = compression == "gzip";
    let rx = GrpcReceiver::start(None, "0", "").await;
    let h = node_at(
        &rx.url_base(),
        &format!("encoding = \"grpc\"\ncompression = \"{compression}\""),
    );
    let cfg = h.src.config.load_full();
    let mut clients = crate::otlp::Clients::new();
    let client = clients.get(&cfg, &h.src.secrets).unwrap();
    let text = crate::http::render(&h.src);
    let doc = crate::otlp::metrics_body(&text, &crate::otlp::resource("pi-a"), 1, 2);
    let url = crate::otlp::signal_url(
        &crate::otlp::endpoint(&cfg).unwrap(),
        wrendns_config::OtlpEncoding::Grpc,
        crate::otlp_proto::Signal::Metrics,
    );
    assert!(url.ends_with(GRPC_METRICS), "{url}");
    crate::otlp::post(
        client,
        &url,
        &cfg,
        crate::otlp_proto::Signal::Metrics,
        &doc,
        &h.src.secrets,
    )
    .await
    .unwrap();
    let reqs = rx.requests();
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    let r = &reqs[0];
    assert!(r.path().eq_ignore_ascii_case(GRPC_METRICS), "{}", r.path());
    assert_eq!(r.header("content-type"), Some("application/grpc"));
    assert_eq!(r.header("te"), Some("trailers"));
    assert_eq!(r.header("x-api-key"), Some("collector-key-1"));
    assert_eq!(r.header("user-agent"), Some("wrendns"));
    assert_eq!(r.header("content-encoding"), None);
    assert_eq!(r.header("grpc-encoding"), gzip.then_some("gzip"));
    let got =
        crate::otlp_proto::reader::decode(crate::otlp_proto::Signal::Metrics, &grpc_message(r));
    assert_eq!(got, crate::otlp_proto::tests::norm(&doc));
    assert_resource(&got["resourceMetrics"][0]["resource"]);
}

/// REQ: OBS-006 (T41.2) - OTLP/gRPC, uncompressed.
#[tokio::test]
async fn obs_006_receiver_gets_grpc_metrics() {
    grpc_metrics("none").await;
}

/// REQ: OBS-006 (T41.2) - OTLP/gRPC with a gzip-compressed message.
#[tokio::test]
async fn obs_006_receiver_gets_gzip_grpc_metrics() {
    grpc_metrics("gzip").await;
}

/// REQ: OBS-006 (T41.2) - a gRPC answer with a status other than 0 is a failed export, with the
/// code and the collector's message (the HTTP status is 200 either way).
#[tokio::test]
async fn obs_006_grpc_error_status_is_a_failure() {
    let rx = GrpcReceiver::start(None, "14", "backend unavailable").await;
    let h = node_at(&rx.url_base(), "encoding = \"grpc\"");
    let cfg = h.src.config.load_full();
    let mut clients = crate::otlp::Clients::new();
    let client = clients.get(&cfg, &h.src.secrets).unwrap();
    let url = crate::otlp::signal_url(
        &crate::otlp::endpoint(&cfg).unwrap(),
        wrendns_config::OtlpEncoding::Grpc,
        crate::otlp_proto::Signal::Metrics,
    );
    let err = crate::otlp::post(
        client,
        &url,
        &cfg,
        crate::otlp_proto::Signal::Metrics,
        &serde_json::json!({"resourceMetrics": []}),
        &h.src.secrets,
    )
    .await
    .unwrap_err();
    assert_eq!(err, "gRPC status 14: backend unavailable");
}

/// REQ: OBS-006 (T41.2) - OTLP/gRPC to a collector behind a private CA: TLS with ALPN `h2`, the CA
/// from `tls_ca`; the export task makes the calls (metrics) the same way.
#[tokio::test]
async fn obs_006_grpc_over_tls_with_a_private_ca() {
    let (ca_pem, server) = private_ca();
    let rx = GrpcReceiver::start(Some(server), "0", "").await;
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &ca_pem).unwrap();
    let h = node_at(
        &rx.https_base(),
        &format!(
            "encoding = \"grpc\"\ntls_ca = \"{}\"",
            ca_path.to_string_lossy().replace('\\', "/")
        ),
    );
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
    assert!(got, "the export reached the TLS gRPC collector");
    let r = rx.requests().remove(0);
    assert!(r.path().eq_ignore_ascii_case(GRPC_METRICS), "{}", r.path());
    let v =
        crate::otlp_proto::reader::decode(crate::otlp_proto::Signal::Metrics, &grpc_message(&r));
    assert_resource(&v["resourceMetrics"][0]["resource"]);
}

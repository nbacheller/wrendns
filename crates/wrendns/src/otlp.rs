//! OpenTelemetry export (REQ: OBS-006, `spec/06` §5; T7.17) over OTLP/HTTP with the JSON
//! encoding: every `interval_secs`, the same metrics `/metrics` serves are posted to
//! `<endpoint>/v1/metrics` (counters as cumulative monotonic sums, gauges, histograms with
//! their buckets). Query events as OpenTelemetry logs come from an event sink with
//! `format = "otlp_logs"` (`crate::sinks`), which uses [`logs_body`].
//!
//! Converting our own Prometheus exposition keeps the two exports identical by construction.
//! Off the DNS path: a background task, one request per interval, a 10 s timeout; a collector
//! that's down only costs that interval's points.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tracing::{debug, info, warn};

/// One sample line: labels and value.
#[derive(Debug, Clone, PartialEq)]
struct Sample {
    labels: Vec<(String, String)>,
    value: f64,
}

/// A metric family from the exposition.
#[derive(Debug, Clone, Default, PartialEq)]
struct Family {
    name: String,
    kind: String,
    help: String,
    samples: Vec<(String, Sample)>,
}

/// Parses one `name{a="b",c="d"} value` line.
fn sample(line: &str) -> Option<(String, Sample)> {
    let (head, value) = line.rsplit_once(' ')?;
    let value: f64 = match value {
        "+Inf" => f64::INFINITY,
        "-Inf" => f64::NEG_INFINITY,
        v => v.parse().ok()?,
    };
    let (name, labels) = match head.split_once('{') {
        Some((n, rest)) => (n, rest.strip_suffix('}')?),
        None => (head, ""),
    };
    let mut out = Vec::new();
    let mut rest = labels;
    while !rest.is_empty() {
        let (k, after) = rest.split_once("=\"")?;
        // The value ends at the first unescaped quote.
        let mut v = String::new();
        let mut chars = after.char_indices();
        let mut end = None;
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => {
                    if let Some((_, n)) = chars.next() {
                        v.push(match n {
                            'n' => '\n',
                            other => other,
                        });
                    }
                }
                '"' => {
                    end = Some(i);
                    break;
                }
                c => v.push(c),
            }
        }
        let end = end?;
        out.push((k.trim_start_matches(',').to_owned(), v));
        rest = after[end + 1..].trim_start_matches(',');
    }
    Some((name.to_owned(), Sample { labels: out, value }))
}

/// The exposition's families, in order.
fn parse(text: &str) -> Vec<Family> {
    let mut fams: Vec<Family> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let (n, h) = rest.split_once(' ').unwrap_or((rest, ""));
            fams.push(Family {
                name: n.to_owned(),
                help: h.to_owned(),
                kind: "untyped".into(),
                samples: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (n, k) = rest.split_once(' ').unwrap_or((rest, "untyped"));
            match fams.last_mut() {
                Some(f) if f.name == n => k.clone_into(&mut f.kind),
                _ => fams.push(Family {
                    name: n.to_owned(),
                    kind: k.to_owned(),
                    ..Family::default()
                }),
            }
        } else if !line.starts_with('#')
            && !line.trim().is_empty()
            && let Some(s) = sample(line)
            && let Some(f) = fams.last_mut()
        {
            f.samples.push(s);
        }
    }
    fams
}

fn attrs(labels: &[(String, String)]) -> Value {
    Value::Array(
        labels
            .iter()
            .map(|(k, v)| json!({"key": k, "value": {"stringValue": v}}))
            .collect(),
    )
}

/// A histogram series: `(upper bound, cumulative count)` buckets, the sum, the count.
type HistogramParts = (Vec<(f64, f64)>, f64, f64);

/// The OTLP `ResourceMetrics` JSON for `text` (Prometheus exposition).
pub(crate) fn metrics_body(text: &str, resource: &Value, start_ns: u64, now_ns: u64) -> Value {
    let (start, now) = (start_ns.to_string(), now_ns.to_string());
    let mut metrics = Vec::new();
    for f in parse(text) {
        match f.kind.as_str() {
            "histogram" => {
                // Group bucket/sum/count lines by their labels (minus `le`).
                let mut by: BTreeMap<Vec<(String, String)>, HistogramParts> = BTreeMap::new();
                for (name, s) in &f.samples {
                    let mut labels = s.labels.clone();
                    let le = labels
                        .iter()
                        .position(|(k, _)| k == "le")
                        .map(|i| labels.remove(i).1);
                    let e = by.entry(labels).or_default();
                    if name.ends_with("_bucket") {
                        let bound = match le.as_deref() {
                            Some("+Inf") | None => f64::INFINITY,
                            Some(b) => b.parse().unwrap_or(f64::INFINITY),
                        };
                        e.0.push((bound, s.value));
                    } else if name.ends_with("_sum") {
                        e.1 = s.value;
                    } else if name.ends_with("_count") {
                        e.2 = s.value;
                    }
                }
                let points: Vec<Value> = by
                    .into_iter()
                    .map(|(labels, (mut buckets, sum, count))| {
                        buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
                        // Cumulative → per bucket; the last (+Inf) closes the list.
                        let mut prev = 0.0;
                        let mut counts = Vec::new();
                        let mut bounds = Vec::new();
                        for (b, c) in &buckets {
                            counts.push(format!("{}", (c - prev).max(0.0).round()));
                            prev = *c;
                            if b.is_finite() {
                                bounds.push(*b);
                            }
                        }
                        if buckets.last().is_none_or(|(b, _)| b.is_finite()) {
                            counts.push(format!("{}", (count - prev).max(0.0).round()));
                        }
                        json!({
                            "attributes": attrs(&labels),
                            "startTimeUnixNano": start,
                            "timeUnixNano": now,
                            "count": format!("{}", count.round()),
                            "sum": sum,
                            "bucketCounts": counts,
                            "explicitBounds": bounds,
                        })
                    })
                    .collect();
                metrics.push(json!({
                    "name": f.name,
                    "description": f.help,
                    "histogram": {"aggregationTemporality": 2, "dataPoints": points},
                }));
            }
            kind => {
                let points: Vec<Value> = f
                    .samples
                    .iter()
                    .filter(|(_, s)| s.value.is_finite())
                    .map(|(_, s)| {
                        json!({
                            "attributes": attrs(&s.labels),
                            "startTimeUnixNano": start,
                            "timeUnixNano": now,
                            "asDouble": s.value,
                        })
                    })
                    .collect();
                if points.is_empty() {
                    continue;
                }
                let data = if kind == "counter" {
                    json!({"sum": {"aggregationTemporality": 2, "isMonotonic": true, "dataPoints": points}})
                } else {
                    json!({"gauge": {"dataPoints": points}})
                };
                let mut m = json!({"name": f.name, "description": f.help});
                if let (Some(m), Some(d)) = (m.as_object_mut(), data.as_object()) {
                    m.extend(d.clone());
                }
                metrics.push(m);
            }
        }
    }
    json!({"resourceMetrics": [{
        "resource": resource,
        "scopeMetrics": [{"scope": {"name": "wrendns", "version": crate::build_info::VERSION}, "metrics": metrics}],
    }]})
}

/// The resource: service and host.
pub(crate) fn resource(node: &str) -> Value {
    json!({"attributes": [
        {"key": "service.name", "value": {"stringValue": "wrendns"}},
        {"key": "service.version", "value": {"stringValue": crate::build_info::VERSION}},
        {"key": "host.name", "value": {"stringValue": node}},
        // REQ: OBS-006 (issue #155) - one instance per node, so a backend (and Home Assistant's
        // own signals, which carry `host.name` too) tells the nodes of a cluster apart.
        {"key": "service.instance.id", "value": {"stringValue": node}},
    ]})
}

/// REQ: OBS-006 (T41.2) - the resource of the metrics and traces the export sends: the node's
/// (see [`resource`]), the cluster's name when the node is a member (`wrendns.cluster.name`), and the
/// attributes the owner added (`resource_attributes`; the reserved names were refused when
/// they were set, and are skipped here too).
pub(crate) fn resource_for(
    cfg: &wrendns_config::Config,
    cluster: Option<&str>,
    node: &str,
) -> Value {
    let mut r = resource(node);
    let Some(list) = r["attributes"].as_array_mut() else {
        return r;
    };
    if let Some(name) = cluster.filter(|n| !n.is_empty()) {
        list.push(json!({"key": "wrendns.cluster.name", "value": {"stringValue": name}}));
    }
    for (k, v) in &cfg.telemetry.otlp_effective().resource_attributes {
        if wrendns_config::OTLP_RESERVED_ATTRIBUTES
            .iter()
            .any(|x| x.eq_ignore_ascii_case(k))
        {
            continue;
        }
        list.push(json!({"key": k.as_str(), "value": {"stringValue": v.as_str()}}));
    }
    r
}

/// The cluster's name for a node that is a member.
pub(crate) fn cluster_name(sources: &crate::http::Sources) -> Option<String> {
    sources
        .cluster
        .as_ref()
        .map(|c| c.identity.meta.cluster_name.clone())
}

/// REQ: OBS-006 — query events (the API's query-row JSON, one per line) as OTLP log records:
/// a one-line body, and the fields as attributes (`dns.question.name`, `client.address`, ...).
pub(crate) fn logs_body(lines: &[String], resource: &Value) -> String {
    let records: Vec<Value> = lines
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .map(|e| {
            let s = |k: &str| e.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
            let ts = e.get("tsUnixMicros").and_then(Value::as_u64).unwrap_or(0).saturating_mul(1000);
            let status = s("status");
            let blocked = status == "blocked";
            let mut a = vec![
                ("dns.question.name", s("name")),
                ("dns.question.type", s("qtype")),
                ("dns.response_code", s("rcode")),
                ("client.address", s("client")),
                ("network.transport", s("proto")),
                ("wrendns.status", status.clone()),
            ];
            for (k, f) in [("client.name", "clientName"), ("wrendns.group", "group"), ("wrendns.list", "list"), ("wrendns.rule", "rule"), ("wrendns.node", "node")] {
                let v = s(f);
                if !v.is_empty() {
                    a.push((k, v));
                }
            }
            let mut attributes: Vec<Value> = a
                .into_iter()
                .map(|(k, v)| json!({"key": k, "value": {"stringValue": v}}))
                .collect();
            if let Some(ms) = e.get("totalMs").and_then(Value::as_f64) {
                attributes.push(json!({"key": "wrendns.duration_ms", "value": {"doubleValue": ms}}));
            }
            json!({
                "timeUnixNano": ts.to_string(),
                "observedTimeUnixNano": ts.to_string(),
                "severityNumber": if blocked { 13 } else { 9 },
                "severityText": if blocked { "WARN" } else { "INFO" },
                "body": {"stringValue": format!("{} {} from {}: {}", s("qtype"), s("name"), s("client"), status)},
                "attributes": attributes,
            })
        })
        .collect();
    json!({"resourceLogs": [{
        "resource": resource,
        "scopeLogs": [{"scope": {"name": "wrendns", "version": crate::build_info::VERSION}, "logRecords": records}],
    }]})
    .to_string()
}

/// The collector's base URL (no trailing slash), when OTLP export is configured.
pub(crate) fn endpoint(cfg: &wrendns_config::Config) -> Option<String> {
    cfg.telemetry
        .otlp_effective()
        .endpoint
        .as_ref()
        .map(|e| e.trim_end_matches('/').to_owned())
}

/// The HTTP client with the built-in public roots only (the tests' default).
#[cfg(test)]
pub(crate) fn client() -> Option<wrendns_filter::fetch::Client> {
    match wrendns_filter::fetch::Client::new(Arc::new(wrendns_filter::fetch::SystemResolver), &[]) {
        Ok(c) => Some(c),
        Err(e) => {
            warn!("OTLP export disabled: {e}");
            None
        }
    }
}

/// REQ: OBS-006 (T41.2) - the private CA certificates (PEM text) the export trusts besides the
/// public roots: a stored `pem` secret (`tls_ca_ref`, read now so a rotated one applies) or the
/// file `tls_ca`; `None` when neither is set. `Err`: why they can't be read.
pub(crate) fn ca_pem(
    cfg: &wrendns_config::Config,
    store: &crate::secrets::SecretStore,
) -> Result<Option<String>, String> {
    let o = cfg.telemetry.otlp_effective();
    if let Some(name) = &o.tls_ca_ref {
        let v = store
            .get_pem(name.as_str())
            .map_err(|e| format!("tls_ca_ref `{name}`: {e}"))?;
        return Ok(Some(v.expose().to_owned()));
    }
    if let Some(path) = &o.tls_ca {
        return std::fs::read_to_string(path.as_str())
            .map(Some)
            .map_err(|e| format!("tls_ca {path}: {e}"));
    }
    Ok(None)
}

/// REQ: OBS-006 (T41.2) - the client for the export as configured now: the public roots plus the
/// private CA, if any. The client is rebuilt only when the CA's text changes.
pub(crate) struct Clients {
    built: Option<(Option<String>, wrendns_filter::fetch::Client)>,
}

impl Clients {
    pub(crate) fn new() -> Self {
        Self { built: None }
    }

    /// The client for `cfg`; `Err`: the CA can't be read or holds no certificate.
    pub(crate) fn get(
        &mut self,
        cfg: &wrendns_config::Config,
        store: &crate::secrets::SecretStore,
    ) -> Result<&wrendns_filter::fetch::Client, String> {
        let pem = ca_pem(cfg, store)?;
        if self.built.as_ref().is_none_or(|(p, _)| *p != pem) {
            let c = wrendns_filter::fetch::Client::with_extra_ca_pem(
                Arc::new(wrendns_filter::fetch::SystemResolver),
                pem.as_deref(),
            )?;
            self.built = Some((pem, c));
        }
        self.built
            .as_ref()
            .map(|(_, c)| c)
            .ok_or_else(|| "no client".to_owned())
    }
}

/// REQ: OBS-006 (T41.2) - where a signal goes: `<endpoint>/v1/metrics` (or `/v1/traces`) for
/// OTLP/HTTP, the collector service's `Export` method for gRPC.
pub(crate) fn signal_url(
    endpoint: &str,
    encoding: wrendns_config::OtlpEncoding,
    signal: crate::otlp_proto::Signal,
) -> String {
    use crate::otlp_proto::Signal;
    let endpoint = endpoint.trim_end_matches('/');
    match (encoding, signal) {
        (wrendns_config::OtlpEncoding::Grpc, Signal::Metrics) => {
            format!("{endpoint}/opentelemetry.proto.collector.metrics.v1.MetricsService/Export")
        }
        (wrendns_config::OtlpEncoding::Grpc, Signal::Traces) => {
            format!("{endpoint}/opentelemetry.proto.collector.trace.v1.TraceService/Export")
        }
        (_, Signal::Metrics) => format!("{endpoint}/v1/metrics"),
        (_, Signal::Traces) => format!("{endpoint}/v1/traces"),
    }
}

/// REQ: OBS-006 (T41.2) - the outcome of a gRPC call: the HTTP status must be 200 and
/// `grpc-status` (in the trailers, or in the head of a "trailers only" answer) must be 0.
fn grpc_result(
    head: &http::response::Parts,
    trailers: Option<&http::HeaderMap>,
) -> Result<(), String> {
    if !head.status.is_success() {
        return Err(format!("HTTP {}", head.status));
    }
    let pick = |name: &str| {
        trailers
            .and_then(|t| t.get(name))
            .or_else(|| head.headers.get(name))
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    match pick("grpc-status").as_deref() {
        Some("0") => Ok(()),
        Some(code) => Err(format!(
            "gRPC status {code}{}",
            pick("grpc-message").map_or_else(String::new, |m| format!(": {m}"))
        )),
        None => Err("no grpc-status in the answer: not a gRPC server".to_owned()),
    }
}

/// One OTLP/HTTP request with the configured headers and a 10 s timeout: the document `doc` of
/// `signal`, in the configured encoding (REQ: OBS-006, T41.2: JSON, or protobuf as
/// `application/x-protobuf`) and compression. `Err`: why it wasn't delivered.
pub(crate) async fn post(
    client: &wrendns_filter::fetch::Client,
    url: &str,
    cfg: &wrendns_config::Config,
    signal: crate::otlp_proto::Signal,
    doc: &Value,
    store: &crate::secrets::SecretStore,
) -> Result<(), String> {
    let o = cfg.telemetry.otlp_effective();
    let grpc = o.encoding == wrendns_config::OtlpEncoding::Grpc;
    let (content_type, body) = match o.encoding {
        wrendns_config::OtlpEncoding::Json => ("application/json", doc.to_string().into_bytes()),
        wrendns_config::OtlpEncoding::Protobuf => (
            "application/x-protobuf",
            crate::otlp_proto::encode(signal, doc),
        ),
        wrendns_config::OtlpEncoding::Grpc => {
            ("application/grpc", crate::otlp_proto::encode(signal, doc))
        }
    };
    let mut req = http::Request::post(url)
        .header("content-type", content_type)
        .header("user-agent", "WrenDNS");
    for (k, v) in &o.headers {
        req = req.header(k.as_str(), v.as_str());
    }
    // REQ: OPS-014 (ADR-903 §2) — headers whose values are stored secrets, read per request
    // (REQ: OBS-006, T23.11: so a rotated secret is sent from the next export on).
    for (k, name) in &o.header_refs {
        let v = crate::secrets::Credential::of(None, Some(name))
            .resolve(Some(store))?
            .map(|r| r.value);
        if let Some(v) = v {
            req = req.header(k.as_str(), v.expose());
        }
    }
    // REQ: OBS-006 (issue #155) - `compression = "gzip"`: the same body, gzip-framed. gRPC
    // compresses the message inside its frame (`grpc-encoding`), not the HTTP body.
    let gzip = o.compression == wrendns_config::OtlpCompression::Gzip;
    let body = if grpc {
        req = req.header("te", "trailers");
        let message = if gzip {
            req = req.header("grpc-encoding", "gzip");
            crate::archive::gzip(&body)
        } else {
            body
        };
        // The length-prefixed message: a compressed flag and a big-endian length.
        let mut framed = Vec::with_capacity(message.len() + 5);
        framed.push(u8::from(gzip));
        framed.extend_from_slice(
            &u32::try_from(message.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        framed.extend_from_slice(&message);
        framed
    } else if gzip {
        req = req.header("content-encoding", "gzip");
        crate::archive::gzip(&body)
    } else {
        body
    };
    let req = req.body(body).map_err(|e| e.to_string())?;
    if grpc {
        return match tokio::time::timeout(
            Duration::from_secs(10),
            client.request_h2(req, 64 * 1024),
        )
        .await
        {
            Ok(Ok((head, _, trailers))) => grpc_result(&head, trailers.as_ref()),
            Ok(Err(e)) => Err(e.message),
            Err(_) => Err("timed out".into()),
        };
    }
    match tokio::time::timeout(Duration::from_secs(10), client.request(req, 64 * 1024)).await {
        Ok(Ok(r)) if r.status().is_success() => Ok(()),
        Ok(Ok(r)) => Err(format!("HTTP {}", r.status())),
        Ok(Err(e)) => Err(e.message),
        Err(_) => Err("timed out".into()),
    }
}

/// The metrics export task. REQ: API-016, OBS-006 (T23.11, ADR-984) — it follows the
/// configuration: an endpoint added, changed or removed (in a file, or made in the UI) applies
/// without a restart, and the headers are read for every export.
pub(crate) async fn run(
    sources: Arc<crate::http::Sources>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut clients = Clients::new();
    let start_ns = crate::pipeline::unix_now().saturating_mul(1_000_000_000);
    let mut failing = false;
    let mut said_pod = false;
    loop {
        let cfg = sources.config.load_full();
        let o = cfg.telemetry.otlp_effective();
        let interval = Duration::from_secs(u64::from(o.interval_secs.max(5)));
        let endpoint = endpoint(&cfg);
        // A resolver pod holds no stored secrets: an export that needs one isn't made here.
        let pod_skips =
            cfg.cluster.ephemeral && (!o.header_refs.is_empty() || o.tls_ca_ref.is_some());
        if pod_skips && !said_pod {
            said_pod = true;
            info!(
                "this resolver pod holds no stored secrets: the OTLP export that needs one isn't made here"
            );
        }
        if endpoint.is_none() || pod_skips {
            tokio::select! {
                _ = stop.changed() => return,
                () = sources.otlp_changed.notified() => {}
            }
            continue;
        }
        drop(o);
        tokio::select! {
            _ = stop.changed() => return,
            // A change of settings starts the interval over with them.
            () = sources.otlp_changed.notified() => { failing = false; continue; }
            () = tokio::time::sleep(interval) => {}
        }
        // One snapshot for the address and the headers: a change that landed during the sleep
        // is picked up whole, never half (the old address with the new credentials).
        let cfg = sources.config.load_full();
        let Some(endpoint) = self::endpoint(&cfg) else {
            continue;
        };
        let url = signal_url(
            &endpoint,
            cfg.telemetry.otlp_effective().encoding,
            crate::otlp_proto::Signal::Metrics,
        );
        let text = crate::http::render(&sources);
        let now_ns = crate::pipeline::unix_now().saturating_mul(1_000_000_000);
        let doc = metrics_body(
            &text,
            &resource_for(
                &cfg,
                cluster_name(&sources).as_deref(),
                &crate::http::node_name(&cfg),
            ),
            start_ns,
            now_ns,
        );
        let client = match clients.get(&cfg, &sources.secrets) {
            Ok(c) => c,
            Err(why) => {
                if !failing {
                    warn!(error = %why, "OTLP metrics not delivered: the collector's CA can't be used (logged once until it works again)");
                }
                failing = true;
                continue;
            }
        };
        match post(
            client,
            &url,
            &cfg,
            crate::otlp_proto::Signal::Metrics,
            &doc,
            &sources.secrets,
        )
        .await
        {
            Ok(()) => {
                if failing {
                    debug!("OTLP export: delivered again");
                }
                failing = false;
            }
            Err(why) => {
                if !failing {
                    warn!(%url, error = %why, "OTLP metrics not delivered (logged once until it works again)");
                }
                failing = true;
            }
        }
    }
}

#[cfg(test)]
#[path = "otlp_receiver_tests.rs"]
pub(crate) mod receiver_tests;

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "# HELP wrendns_queries_total Queries.\n# TYPE wrendns_queries_total counter\nwrendns_queries_total{proto=\"udp\",status=\"cached\"} 42\n# HELP wrendns_cache_entries Entries.\n# TYPE wrendns_cache_entries gauge\nwrendns_cache_entries 7\n# HELP wrendns_query_duration_seconds Latency.\n# TYPE wrendns_query_duration_seconds histogram\nwrendns_query_duration_seconds_bucket{path=\"cache\",le=\"0.001\"} 3\nwrendns_query_duration_seconds_bucket{path=\"cache\",le=\"0.01\"} 5\nwrendns_query_duration_seconds_bucket{path=\"cache\",le=\"+Inf\"} 6\nwrendns_query_duration_seconds_sum{path=\"cache\"} 0.5\nwrendns_query_duration_seconds_count{path=\"cache\"} 6\n";

    /// REQ: OBS-006 — the exposition becomes OTLP: a monotonic cumulative sum, a gauge, and a
    /// histogram with per-bucket counts (one more than the bounds).
    #[test]
    fn obs_006_metrics_to_otlp() {
        let v = metrics_body(TEXT, &resource("pi"), 1, 2);
        let ms = &v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"];
        assert_eq!(ms[0]["name"], "wrendns_queries_total");
        assert_eq!(ms[0]["sum"]["isMonotonic"], true);
        let p = &ms[0]["sum"]["dataPoints"][0];
        assert_eq!(
            (
                p["asDouble"].as_f64(),
                p["attributes"][1]["value"]["stringValue"].as_str()
            ),
            (Some(42.0), Some("cached"))
        );
        assert_eq!(ms[1]["gauge"]["dataPoints"][0]["asDouble"], 7.0);
        let h = &ms[2]["histogram"]["dataPoints"][0];
        assert_eq!(h["bucketCounts"], json!(["3", "2", "1"]));
        assert_eq!(h["explicitBounds"], json!([0.001, 0.01]));
        assert_eq!(
            (h["count"].as_str(), h["sum"].as_f64()),
            (Some("6"), Some(0.5))
        );
        assert_eq!(
            h["attributes"],
            json!([{"key": "path", "value": {"stringValue": "cache"}}])
        );
        assert_eq!(
            v["resourceMetrics"][0]["resource"]["attributes"][2]["value"]["stringValue"],
            "pi"
        );
    }

    #[test]
    fn obs_006_label_values_unescape() {
        let (n, s) = sample(r#"m{a="x\"y",b="1,2"} 3"#).unwrap();
        assert_eq!(n, "m");
        assert_eq!(
            s.labels,
            vec![("a".into(), "x\"y".into()), ("b".into(), "1,2".into())]
        );
    }

    /// REQ: OBS-006 — query events as log records with attributes.
    #[test]
    fn obs_006_events_to_otlp_logs() {
        let line = r#"{"time":"t","tsUnixMicros":1700000000000000,"client":"192.168.1.5","name":"ads.example","qtype":"A","status":"blocked","rcode":"NOERROR","proto":"udp","list":"ads","totalMs":0.2}"#;
        let v: Value =
            serde_json::from_str(&logs_body(&[line.to_owned()], &resource("pi"))).unwrap();
        let r = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(r["timeUnixNano"], "1700000000000000000");
        assert_eq!(
            (
                r["severityText"].as_str(),
                r["body"]["stringValue"].as_str()
            ),
            (
                Some("WARN"),
                Some("A ads.example from 192.168.1.5: blocked")
            )
        );
        let has = |k: &str, val: &str| {
            r["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["key"] == k && a["value"]["stringValue"] == val)
        };
        assert!(
            has("dns.question.name", "ads.example")
                && has("wrendns.list", "ads")
                && has("client.address", "192.168.1.5")
        );
    }
}

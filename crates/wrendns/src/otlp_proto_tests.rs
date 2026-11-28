// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: OBS-006, OBS-017 (T41.2) - the protobuf encoder against the OTLP field numbers and wire
//! rules: a hand-checked byte string, and the export's own documents round-tripped through the
//! encoder and a reader.

use serde_json::{Value, json};

use super::reader::decode;
use super::{Signal, encode};

/// What the comparison has to normalize: `intValue` is a string in OTLP JSON and a number once
/// decoded, and an empty list (a point with no attributes) is nothing on the wire.
pub(crate) fn norm(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .filter(|(_, x)| x.as_array().is_none_or(|a| !a.is_empty()))
                .map(|(k, x)| {
                    let x = if k == "intValue" {
                        x.as_str()
                            .and_then(|s| s.parse::<i64>().ok())
                            .map_or_else(|| x.clone(), |n| json!(n))
                    } else {
                        norm(x)
                    };
                    (k.clone(), x)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
        other => other.clone(),
    }
}

/// REQ: OBS-006 - the wire bytes of the smallest request, written out by hand from the proto
/// files: `ExportMetricsServiceRequest.resource_metrics (1)` -> `ResourceMetrics.resource (1)` ->
/// `Resource.attributes (1)` -> `KeyValue.key (1)` = "a", `KeyValue.value (2)` ->
/// `AnyValue.string_value (1)` = "b".
#[test]
fn obs_006_protobuf_wire_bytes() {
    let doc = json!({"resourceMetrics": [{"resource": {"attributes": [
        {"key": "a", "value": {"stringValue": "b"}}
    ]}}]});
    assert_eq!(
        encode(Signal::Metrics, &doc),
        [
            0x0a, 0x0c, // resource_metrics, 12 bytes
            0x0a, 0x0a, // resource, 10 bytes
            0x0a, 0x08, // attributes, 8 bytes
            0x0a, 0x01, b'a', // key
            0x12, 0x03, 0x0a, 0x01, b'b', // value { string_value }
        ]
    );
}

/// REQ: OBS-006 - the scalar encodings: `fixed64` little-endian (a string in JSON), a varint
/// enum and a bool, a packed `repeated fixed64` and `repeated double`, and an `int64` that is
/// negative.
#[test]
fn obs_006_protobuf_scalars() {
    let doc = json!({"resourceMetrics": [{"scopeMetrics": [{"metrics": [{
        "name": "m",
        "sum": {"aggregationTemporality": 2, "isMonotonic": true, "dataPoints": [
            {"timeUnixNano": "258", "asDouble": 1.5}
        ]},
    }, {
        "name": "h",
        "histogram": {"dataPoints": [{
            "count": "3", "bucketCounts": ["1", "2"], "explicitBounds": [0.5],
            "attributes": [{"key": "n", "value": {"intValue": "-2"}}],
        }]},
    }]}]}]});
    let bytes = encode(Signal::Metrics, &doc);
    // The `time_unix_nano` (field 3, wire type 1) of 258 = 0x0102, little-endian.
    assert!(
        bytes
            .windows(9)
            .any(|w| w == [0x19, 0x02, 0x01, 0, 0, 0, 0, 0, 0]),
        "{bytes:02x?}"
    );
    // `bucket_counts` (field 6, wire type 2): 16 bytes, packed.
    assert!(
        bytes.windows(4).any(|w| w == [0x32, 0x10, 1, 0]),
        "{bytes:02x?}"
    );
    // `explicit_bounds` (field 7): 0.5 as a little-endian double.
    assert!(
        bytes
            .windows(10)
            .any(|w| w == [0x3a, 0x08, 0, 0, 0, 0, 0, 0, 0xe0, 0x3f]),
        "{bytes:02x?}"
    );
    // The negative `int_value` (field 3, varint): ten bytes of two's complement.
    assert!(
        bytes.windows(3).any(|w| w == [0x18, 0xfe, 0xff]),
        "{bytes:02x?}"
    );
    assert_eq!(decode(Signal::Metrics, &bytes), norm(&doc));
}

/// REQ: OBS-006 - the export's real metrics document (the exposition converted as the export task
/// does), encoded and read back, is the same document: no field of it is dropped.
#[test]
fn obs_006_protobuf_round_trips_the_metrics_document() {
    const TEXT: &str = "# HELP wrendns_queries_total Queries.\n# TYPE wrendns_queries_total counter\nwrendns_queries_total{proto=\"udp\",status=\"cached\"} 42\n# HELP wrendns_cache_entries Entries.\n# TYPE wrendns_cache_entries gauge\nwrendns_cache_entries 7\n# HELP wrendns_query_duration_seconds Latency.\n# TYPE wrendns_query_duration_seconds histogram\nwrendns_query_duration_seconds_bucket{path=\"cache\",le=\"0.001\"} 3\nwrendns_query_duration_seconds_bucket{path=\"cache\",le=\"0.01\"} 5\nwrendns_query_duration_seconds_bucket{path=\"cache\",le=\"+Inf\"} 6\nwrendns_query_duration_seconds_sum{path=\"cache\"} 0.5\nwrendns_query_duration_seconds_count{path=\"cache\"} 6\n";
    let mut resource = crate::otlp::resource("pi-a");
    if let Some(a) = resource["attributes"].as_array_mut() {
        a.push(json!({"key": "deployment.environment", "value": {"stringValue": "home"}}));
    }
    let doc = crate::otlp::metrics_body(
        TEXT,
        &resource,
        1_700_000_000_000_000_000,
        1_700_000_060_000_000_000,
    );
    let bytes = encode(Signal::Metrics, &doc);
    assert_eq!(decode(Signal::Metrics, &bytes), norm(&doc));
    // Smaller than the JSON it came from.
    assert!(bytes.len() < doc.to_string().len(), "{} bytes", bytes.len());
}

/// REQ: OBS-006 - a key the table does not list is left out, and a malformed value (a trace ID that
/// is not hex) is skipped rather than written wrong.
#[test]
fn obs_006_protobuf_skips_what_it_cannot_encode() {
    let doc = json!({"resourceSpans": [{"scopeSpans": [{"spans": [
        {"traceId": "zz", "name": "x", "unknownField": 1}
    ]}]}]});
    let back = decode(Signal::Traces, &encode(Signal::Traces, &doc));
    assert_eq!(
        back,
        json!({"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "x"}]}]}]})
    );
}

/// Wire bytes written without the encoder's table, from `opentelemetry/proto/*.proto`: a field's
/// tag is `number << 3 | wire type`; `ld` is a length-delimited field (wire type 2), `f64` a
/// `fixed64` or `double` (wire type 1, little-endian) and `vi` a varint (wire type 0).
fn ld(number: u8, body: &[u8]) -> Vec<u8> {
    assert!(number < 16 && body.len() < 128, "one-byte tag and length");
    let mut out = vec![number << 3 | 2, u8::try_from(body.len()).unwrap()];
    out.extend_from_slice(body);
    out
}

fn f64_field(number: u8, bits: u64) -> Vec<u8> {
    let mut out = vec![number << 3 | 1];
    out.extend_from_slice(&bits.to_le_bytes());
    out
}

fn vi(number: u8, v: u8) -> Vec<u8> {
    vec![number << 3, v]
}

fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

/// REQ: OBS-017, OBS-006 (T41.2) - a span's wire bytes from the proto file's numbers, not the
/// encoder's table (`Span`: `trace_id` 1, `span_id` 2, `parent_span_id` 4, `name` 5, `kind` 6,
/// `start_time_unix_nano` 7, `end_time_unix_nano` 8, `status` 15; `Status.code` 3;
/// `ScopeSpans.spans` 2; `ResourceSpans.scope_spans` 2; the request's `resource_spans` 1).
#[test]
fn obs_017_protobuf_span_wire_bytes() {
    let doc = json!({"resourceSpans": [{"scopeSpans": [{"spans": [{
        "traceId": "01".repeat(16), "spanId": "02".repeat(8), "parentSpanId": "03".repeat(8),
        "name": "s", "kind": 2, "startTimeUnixNano": "1", "endTimeUnixNano": "2",
        "status": {"code": 2},
    }]}]}]});
    let span = cat(&[
        ld(1, &[1; 16]),
        ld(2, &[2; 8]),
        ld(4, &[3; 8]),
        ld(5, b"s"),
        vi(6, 2),
        f64_field(7, 1),
        f64_field(8, 2),
        ld(15, &vi(3, 2)),
    ]);
    let want = ld(1, &ld(2, &ld(2, &span)));
    assert_eq!(encode(Signal::Traces, &doc), want);
}

/// REQ: OBS-006 (T41.2) - the three metric kinds' wire bytes from the proto file's numbers
/// (`Metric`: `name` 1, `gauge` 5, `sum` 7, `histogram` 9; `Gauge`/`Sum`/`Histogram`
/// `data_points` 1; `Sum.aggregation_temporality` 2, `is_monotonic` 3; `NumberDataPoint`
/// `time_unix_nano` 3, `as_double` 4; `HistogramDataPoint` `time_unix_nano` 3, `count` 4,
/// `sum` 5, `bucket_counts` 6, `explicit_bounds` 7; `ScopeMetrics.metrics` 2;
/// `ResourceMetrics.scope_metrics` 2).
#[test]
fn obs_006_protobuf_metric_kind_wire_bytes() {
    let doc = json!({"resourceMetrics": [{"scopeMetrics": [{"metrics": [
        {"name": "g", "gauge": {"dataPoints": [{"timeUnixNano": "2", "asDouble": 1.0}]}},
        {"name": "s", "sum": {"aggregationTemporality": 2, "isMonotonic": true,
            "dataPoints": [{"timeUnixNano": "2", "asDouble": 1.0}]}},
        {"name": "h", "histogram": {"aggregationTemporality": 2, "dataPoints": [{
            "timeUnixNano": "2", "count": "3", "sum": 1.0,
            "bucketCounts": ["1", "2"], "explicitBounds": [1.0]}]}},
    ]}]}]});
    let one = 1.0_f64.to_bits();
    let number_point = cat(&[f64_field(3, 2), f64_field(4, one)]);
    let gauge = cat(&[ld(1, b"g"), ld(5, &ld(1, &number_point))]);
    let sum = cat(&[
        ld(1, b"s"),
        ld(7, &cat(&[ld(1, &number_point), vi(2, 2), vi(3, 1)])),
    ]);
    let packed_counts = cat(&[1_u64.to_le_bytes().to_vec(), 2_u64.to_le_bytes().to_vec()]);
    let hist_point = cat(&[
        f64_field(3, 2),
        f64_field(4, 3),
        f64_field(5, one),
        ld(6, &packed_counts),
        ld(7, &one.to_le_bytes()),
    ]);
    let hist = cat(&[ld(1, b"h"), ld(9, &cat(&[ld(1, &hist_point), vi(2, 2)]))]);
    let scope_metrics = cat(&[ld(2, &gauge), ld(2, &sum), ld(2, &hist)]);
    // The three metrics together are longer than a one-byte length holds.
    let want = ld_long(1, &ld_long(2, &scope_metrics));
    assert_eq!(encode(Signal::Metrics, &doc), want);
}

/// A length-delimited field whose length takes one or two varint bytes.
fn ld_long(number: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![number << 3 | 2];
    let n = body.len();
    if n < 128 {
        out.push(u8::try_from(n).unwrap());
    } else {
        out.push(u8::try_from(n & 0x7f).unwrap() | 0x80);
        out.push(u8::try_from(n >> 7).unwrap());
    }
    out.extend_from_slice(body);
    out
}

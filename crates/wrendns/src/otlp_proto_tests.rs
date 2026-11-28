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

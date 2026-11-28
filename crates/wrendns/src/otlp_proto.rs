// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: OBS-006, OBS-017 (T41.2, ADR-1114, issue #155) - the OTLP protobuf encoding
//! (`application/x-protobuf`), written by hand: no protobuf crate joins the image.
//!
//! The export builds each request as the OTLP JSON document (`otlp.rs`, `traces.rs`); this module
//! turns that same document into the protobuf wire form with a table of the fields of
//! `opentelemetry/proto/{collector,metrics,trace,common,resource}/v1`, so the two encodings carry
//! the same content by construction. Only the fields the export writes are in the table; a key it
//! does not list is left out (never guessed).
//!
//! Off the DNS path: it runs in the export task, once per request.

use serde_json::Value;

/// The OTLP signal a request carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Signal {
    Metrics,
    Traces,
}

/// How a JSON value becomes wire bytes.
#[derive(Clone, Copy)]
enum Ty {
    /// A UTF-8 string (wire type 2).
    Str,
    /// A hex string that is bytes on the wire (trace and span IDs).
    Hex,
    /// A nested message.
    Msg(&'static [F]),
    /// `fixed64`: a JSON string or number.
    Fixed64,
    /// A varint: `int64` (a JSON string or number), an enum or a `uint32`.
    Varint,
    /// A `bool`.
    Bool,
    /// A `double`.
    Double,
    /// A packed `repeated fixed64` (a JSON array of strings or numbers).
    PackedFixed64,
    /// A packed `repeated double`.
    PackedDouble,
}

/// One field of a message: its JSON name, field number and type; `rep` when `repeated` (a JSON
/// array of values of the type).
struct F {
    json: &'static str,
    num: u32,
    rep: bool,
    ty: Ty,
}

const fn f(json: &'static str, num: u32, ty: Ty) -> F {
    F {
        json,
        num,
        rep: false,
        ty,
    }
}

const fn rep(json: &'static str, num: u32, ty: Ty) -> F {
    F {
        json,
        num,
        rep: true,
        ty,
    }
}

/// `AnyValue`: the one case of its `oneof` the JSON carries.
const ANY_VALUE: &[F] = &[
    f("stringValue", 1, Ty::Str),
    f("boolValue", 2, Ty::Bool),
    f("intValue", 3, Ty::Varint),
    f("doubleValue", 4, Ty::Double),
];
const KEY_VALUE: &[F] = &[f("key", 1, Ty::Str), f("value", 2, Ty::Msg(ANY_VALUE))];
const RESOURCE: &[F] = &[rep("attributes", 1, Ty::Msg(KEY_VALUE))];
const SCOPE: &[F] = &[f("name", 1, Ty::Str), f("version", 2, Ty::Str)];

const NUMBER_POINT: &[F] = &[
    f("startTimeUnixNano", 2, Ty::Fixed64),
    f("timeUnixNano", 3, Ty::Fixed64),
    f("asDouble", 4, Ty::Double),
    rep("attributes", 7, Ty::Msg(KEY_VALUE)),
];
const HISTOGRAM_POINT: &[F] = &[
    f("startTimeUnixNano", 2, Ty::Fixed64),
    f("timeUnixNano", 3, Ty::Fixed64),
    f("count", 4, Ty::Fixed64),
    f("sum", 5, Ty::Double),
    f("bucketCounts", 6, Ty::PackedFixed64),
    f("explicitBounds", 7, Ty::PackedDouble),
    rep("attributes", 9, Ty::Msg(KEY_VALUE)),
];
const GAUGE: &[F] = &[rep("dataPoints", 1, Ty::Msg(NUMBER_POINT))];
const SUM: &[F] = &[
    rep("dataPoints", 1, Ty::Msg(NUMBER_POINT)),
    f("aggregationTemporality", 2, Ty::Varint),
    f("isMonotonic", 3, Ty::Bool),
];
const HISTOGRAM: &[F] = &[
    rep("dataPoints", 1, Ty::Msg(HISTOGRAM_POINT)),
    f("aggregationTemporality", 2, Ty::Varint),
];
const METRIC: &[F] = &[
    f("name", 1, Ty::Str),
    f("description", 2, Ty::Str),
    f("gauge", 5, Ty::Msg(GAUGE)),
    f("sum", 7, Ty::Msg(SUM)),
    f("histogram", 9, Ty::Msg(HISTOGRAM)),
];
const SCOPE_METRICS: &[F] = &[
    f("scope", 1, Ty::Msg(SCOPE)),
    rep("metrics", 2, Ty::Msg(METRIC)),
];
const RESOURCE_METRICS: &[F] = &[
    f("resource", 1, Ty::Msg(RESOURCE)),
    rep("scopeMetrics", 2, Ty::Msg(SCOPE_METRICS)),
];
/// `ExportMetricsServiceRequest`.
const METRICS_REQUEST: &[F] = &[rep("resourceMetrics", 1, Ty::Msg(RESOURCE_METRICS))];

const STATUS: &[F] = &[f("message", 2, Ty::Str), f("code", 3, Ty::Varint)];
const SPAN: &[F] = &[
    f("traceId", 1, Ty::Hex),
    f("spanId", 2, Ty::Hex),
    f("parentSpanId", 4, Ty::Hex),
    f("name", 5, Ty::Str),
    f("kind", 6, Ty::Varint),
    f("startTimeUnixNano", 7, Ty::Fixed64),
    f("endTimeUnixNano", 8, Ty::Fixed64),
    rep("attributes", 9, Ty::Msg(KEY_VALUE)),
    f("status", 15, Ty::Msg(STATUS)),
];
const SCOPE_SPANS: &[F] = &[
    f("scope", 1, Ty::Msg(SCOPE)),
    rep("spans", 2, Ty::Msg(SPAN)),
];
const RESOURCE_SPANS: &[F] = &[
    f("resource", 1, Ty::Msg(RESOURCE)),
    rep("scopeSpans", 2, Ty::Msg(SCOPE_SPANS)),
];
/// `ExportTraceServiceRequest`.
const TRACES_REQUEST: &[F] = &[rep("resourceSpans", 1, Ty::Msg(RESOURCE_SPANS))];

/// The protobuf body for the OTLP JSON document `doc` of `signal`.
pub(crate) fn encode(signal: Signal, doc: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);
    message(
        &mut out,
        match signal {
            Signal::Metrics => METRICS_REQUEST,
            Signal::Traces => TRACES_REQUEST,
        },
        doc,
    );
    out
}

#[allow(clippy::cast_possible_truncation)] // the low seven bits, masked
fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn tag(out: &mut Vec<u8>, num: u32, wire: u8) {
    varint(out, u64::from(num) << 3 | u64::from(wire));
}

fn delimited(out: &mut Vec<u8>, num: u32, bytes: &[u8]) {
    tag(out, num, 2);
    varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// An unsigned number as OTLP JSON writes 64-bit integers (a string), or a plain number.
fn unsigned(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) => s.parse().ok(),
        other => other.as_u64(),
    }
}

/// A signed number likewise (`int64` is two's complement on the wire).
fn signed(v: &Value) -> Option<i64> {
    match v {
        Value::String(s) => s.parse().ok(),
        other => other.as_i64(),
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn message(out: &mut Vec<u8>, schema: &[F], v: &Value) {
    let Some(obj) = v.as_object() else {
        return;
    };
    for field in schema {
        let Some(val) = obj.get(field.json) else {
            continue;
        };
        if field.rep {
            for item in val.as_array().map_or(&[][..], Vec::as_slice) {
                one(out, field, item);
            }
        } else {
            one(out, field, val);
        }
    }
}

fn one(out: &mut Vec<u8>, f: &F, v: &Value) {
    match f.ty {
        Ty::Str => {
            if let Some(s) = v.as_str() {
                delimited(out, f.num, s.as_bytes());
            }
        }
        Ty::Hex => {
            if let Some(b) = v.as_str().and_then(unhex) {
                delimited(out, f.num, &b);
            }
        }
        Ty::Msg(schema) => {
            let mut inner = Vec::new();
            message(&mut inner, schema, v);
            delimited(out, f.num, &inner);
        }
        Ty::Fixed64 => {
            if let Some(n) = unsigned(v) {
                tag(out, f.num, 1);
                out.extend_from_slice(&n.to_le_bytes());
            }
        }
        Ty::Varint => {
            if let Some(n) = signed(v) {
                tag(out, f.num, 0);
                varint(out, n.cast_unsigned());
            } else if let Some(n) = unsigned(v) {
                tag(out, f.num, 0);
                varint(out, n);
            }
        }
        Ty::Bool => {
            if let Some(b) = v.as_bool() {
                tag(out, f.num, 0);
                varint(out, u64::from(b));
            }
        }
        Ty::Double => {
            if let Some(d) = v.as_f64() {
                tag(out, f.num, 1);
                out.extend_from_slice(&d.to_le_bytes());
            }
        }
        Ty::PackedFixed64 => {
            let items: Vec<u8> = v
                .as_array()
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .filter_map(unsigned)
                .flat_map(u64::to_le_bytes)
                .collect();
            if !items.is_empty() {
                delimited(out, f.num, &items);
            }
        }
        Ty::PackedDouble => {
            let items: Vec<u8> = v
                .as_array()
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .filter_map(Value::as_f64)
                .flat_map(f64::to_le_bytes)
                .collect();
            if !items.is_empty() {
                delimited(out, f.num, &items);
            }
        }
    }
}

#[cfg(test)]
#[path = "otlp_proto_tests.rs"]
pub(crate) mod tests;

/// A protobuf reader for the tests (and the receiver tests): decodes a body back to JSON by the
/// same field table, so a test can compare it with the JSON the export built.
#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::format_collect
)]
pub(crate) mod reader {
    use super::*;
    use serde_json::{Map, json};

    fn read_varint(b: &[u8], i: &mut usize) -> u64 {
        let (mut v, mut shift) = (0u64, 0);
        loop {
            let byte = b[*i];
            *i += 1;
            v |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return v;
            }
            shift += 7;
        }
    }

    /// Decodes `bytes` of `signal` into the JSON shape `encode` took (64-bit integers as
    /// strings, IDs as hex).
    pub(crate) fn decode(signal: Signal, bytes: &[u8]) -> Value {
        msg(
            match signal {
                Signal::Metrics => METRICS_REQUEST,
                Signal::Traces => TRACES_REQUEST,
            },
            bytes,
        )
    }

    fn msg(schema: &[F], b: &[u8]) -> Value {
        let mut obj = Map::new();
        let mut i = 0;
        while i < b.len() {
            let key = read_varint(b, &mut i);
            let (num, wire) = ((key >> 3) as u32, (key & 7) as u8);
            let field = schema
                .iter()
                .find(|f| f.num == num)
                .unwrap_or_else(|| panic!("field {num} is not in the table"));
            let val = match wire {
                0 => {
                    let v = read_varint(b, &mut i);
                    match field.ty {
                        Ty::Bool => json!(v != 0),
                        Ty::Varint => json!(v as i64),
                        _ => panic!("varint for {}", field.json),
                    }
                }
                1 => {
                    let raw: [u8; 8] = b[i..i + 8].try_into().unwrap();
                    i += 8;
                    match field.ty {
                        Ty::Fixed64 => json!(u64::from_le_bytes(raw).to_string()),
                        Ty::Double => json!(f64::from_le_bytes(raw)),
                        _ => panic!("fixed64 for {}", field.json),
                    }
                }
                2 => {
                    let len = read_varint(b, &mut i) as usize;
                    let body = &b[i..i + len];
                    i += len;
                    match field.ty {
                        Ty::Str => json!(String::from_utf8(body.to_vec()).unwrap()),
                        Ty::Hex => {
                            json!(body.iter().map(|x| format!("{x:02x}")).collect::<String>())
                        }
                        Ty::Msg(s) => msg(s, body),
                        Ty::PackedFixed64 => Value::Array(
                            body.chunks(8)
                                .map(|c| {
                                    json!(u64::from_le_bytes(c.try_into().unwrap()).to_string())
                                })
                                .collect(),
                        ),
                        Ty::PackedDouble => Value::Array(
                            body.chunks(8)
                                .map(|c| json!(f64::from_le_bytes(c.try_into().unwrap())))
                                .collect(),
                        ),
                        _ => panic!("length-delimited for {}", field.json),
                    }
                }
                other => panic!("wire type {other}"),
            };
            if field.rep {
                obj.entry(field.json)
                    .or_insert_with(|| Value::Array(Vec::new()))
                    .as_array_mut()
                    .unwrap()
                    .push(val);
            } else {
                obj.insert(field.json.to_owned(), val);
            }
        }
        Value::Object(obj)
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b4; ADR-1084 point 6) - the Route 53 provider and its signer: AWS's
//! published Signature Version 4 test-suite vectors, and create, update and delete against a local
//! server that replays Route 53's documented request and answer shapes (the namespace, the
//! `ChangeInfo`, the error documents). No live credential and no real endpoint: the provider's
//! endpoint is set only here.

#![allow(
    clippy::many_single_char_names,
    clippy::struct_excessive_bools,
    clippy::type_complexity,
    clippy::too_many_lines,
    clippy::format_push_string,
    clippy::format_collect,
    clippy::manual_let_else,
    clippy::single_match_else,
    clippy::doc_markdown
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use wrendns_config::DnsProviderConfig;
use zeroize::Zeroizing;

use super::route53::Route53;
use super::sigv4::{self, Request, Scope};
use super::xml;
use super::{DnsProvider, ProviderErrorKind, RecordSet, RecordType};
use crate::secrets::value::SecretValue;

const KEY_ID: &str = "AKIDEXAMPLE0000";
const KEY_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

// ---------------------------------------------------------------------------------------------
// The signer, against AWS's published test-suite vectors
// (https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html and the
// "aws-sig-v4-test-suite": credential AKIDEXAMPLE, 2015-08-30T12:36:00Z, us-east-1, `service`).
// ---------------------------------------------------------------------------------------------

fn suite_scope() -> Scope<'static> {
    Scope {
        access_key: "AKIDEXAMPLE",
        secret: KEY_SECRET,
        region: "us-east-1",
        service: "service",
        amz_date: "20150830T123600Z",
    }
}

fn suite(
    method: &str,
    query: &[(&str, &str)],
    headers: &[(&str, &str)],
    body: &[u8],
) -> sigv4::Signed {
    sigv4::sign(
        &Request {
            method,
            host: "example.amazonaws.com",
            path: "/",
            query,
            headers,
            body,
        },
        &suite_scope(),
    )
}

#[test]
fn cld_904_sigv4_matches_aws_test_vectors() {
    // get-vanilla
    let s = suite("GET", &[], &[], b"");
    assert_eq!(
        s.signature,
        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
    assert_eq!(
        s.authorization,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
    // post-vanilla
    assert_eq!(
        suite("POST", &[], &[], b"").signature,
        "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
    );
    // get-vanilla-query-order-key-case: parameters are sorted.
    assert_eq!(
        suite(
            "GET",
            &[("Param2", "value2"), ("Param1", "value1")],
            &[],
            b""
        )
        .signature,
        "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
    );
    // post-x-www-form-urlencoded: a signed content-type and a body hash.
    assert_eq!(
        suite(
            "POST",
            &[],
            &[("content-type", "application/x-www-form-urlencoded")],
            b"Param1=value1"
        )
        .signature,
        "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"
    );
}

/// The derived signing key of AWS's IAM documentation example.
#[test]
fn cld_904_sigv4_signing_key_matches_the_documented_example() {
    let k = sigv4::signing_key(KEY_SECRET, "20150830", "us-east-1", "iam");
    let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
    );
}

#[test]
fn cld_904_sigv4_dates_and_encoding() {
    assert_eq!(sigv4::amz_date(1_440_938_160), "20150830T123600Z");
    assert_eq!(sigv4::amz_date(0), "19700101T000000Z");
    assert_eq!(sigv4::amz_date(951_782_400 + 86_399), "20000229T235959Z");
    assert_eq!(sigv4::uri_encode("a b/c~d"), "a%20b%2Fc~d");
    assert_eq!(
        sigv4::canonical_query(&[("b", "2"), ("a", "1 2")]),
        "a=1%202&b=2"
    );
    assert_eq!(sigv4::encode_path(""), "/");
}

// ---------------------------------------------------------------------------------------------
// A local server that answers as Route 53 documents
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Req {
    method: String,
    /// Path without the query.
    path: String,
    /// Decoded query pairs.
    query: Vec<(String, String)>,
    headers: BTreeMap<String, String>,
    body: String,
}

type Reply = (u16, String, Vec<(String, String)>);
type Handler = Arc<dyn Fn(&Req) -> Reply + Send + Sync>;

fn unhex(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

async fn read_req(s: &mut tokio::net::TcpStream) -> Option<Req> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8(buf[..head_end].to_vec()).ok()?;
    let mut lines = head.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.split(' ');
    let method = parts.next()?.to_owned();
    let target = parts.next()?;
    let (path, q) = target.split_once('?').unwrap_or((target, ""));
    let query = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (unhex(k), unhex(v))
        })
        .collect();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(Req {
        method,
        path: path.to_owned(),
        query,
        headers,
        body: String::from_utf8(body).ok()?,
    })
}

/// Starts the server; returns its URL and the requests it received.
async fn serve(handler: Handler) -> (String, Arc<Mutex<Vec<Req>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<Req>>> = Arc::default();
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let (handler, log) = (Arc::clone(&handler), Arc::clone(&log));
            tokio::spawn(async move {
                let Some(req) = read_req(&mut s).await else {
                    return;
                };
                log.lock().unwrap().push(req.clone());
                let (status, body, extra) = handler(&req);
                let mut out = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: text/xml\r\ncontent-length: {}\r\nconnection: close\r\n",
                    body.len()
                );
                for (k, v) in extra {
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                out.push_str("\r\n");
                out.push_str(&body);
                let _ = s.write_all(out.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (url, seen)
}

const NS: &str = "https://route53.amazonaws.com/doc/2013-04-01/";

fn error_doc(code: &str, message: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<ErrorResponse xmlns=\"{NS}\"><Error><Type>Sender</Type><Code>{code}</Code><Message>{}</Message></Error><RequestId>b25f48e8-84fd-11e6-80d9-574e0c4664cb</RequestId></ErrorResponse>",
        xml::escape(message)
    )
}

/// Whether the request's signature is the one AWS's algorithm gives for it: the server side of
/// SigV4, recomputed from what arrived.
fn signature_ok(r: &Req) -> bool {
    let Some(a) = r.headers.get("authorization") else {
        return false;
    };
    let Some(rest) = a.strip_prefix("AWS4-HMAC-SHA256 Credential=") else {
        return false;
    };
    let (cred, rest) = rest.split_once(", SignedHeaders=").unwrap();
    let (signed, sig) = rest.split_once(", Signature=").unwrap();
    let c: Vec<&str> = cred.split('/').collect();
    assert_eq!(c[0], KEY_ID);
    assert_eq!(&c[2..], ["us-east-1", "route53", "aws4_request"]);
    let date = r.headers.get("x-amz-date").unwrap();
    assert!(date.starts_with(c[1]));
    let extra: Vec<(&str, &str)> = signed
        .split(';')
        .filter(|h| *h != "host" && *h != "x-amz-date")
        .map(|h| (h, r.headers.get(h).unwrap().as_str()))
        .collect();
    let q: Vec<(&str, &str)> = r
        .query
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let want = sigv4::sign(
        &Request {
            method: &r.method,
            host: r.headers.get("host").unwrap(),
            path: &r.path,
            query: &q,
            headers: &extra,
            body: r.body.as_bytes(),
        },
        &Scope {
            access_key: KEY_ID,
            secret: KEY_SECRET,
            region: "us-east-1",
            service: "route53",
            amz_date: date,
        },
    );
    want.signature == sig
}

#[derive(Debug, Clone)]
struct Stored {
    name: String,
    rtype: String,
    ttl: u32,
    values: Vec<String>,
    alias: bool,
    identifier: Option<String>,
}

/// A hosted zone with Route 53's documented behaviour for the calls the provider makes.
#[derive(Default)]
struct Zone {
    sets: Vec<Stored>,
    page: usize,
    /// Fail the next POST with this answer.
    fail_post: Option<Reply>,
}

fn sets_xml(sets: &[&Stored]) -> String {
    let mut s = String::new();
    for x in sets {
        s.push_str(&format!(
            "<ResourceRecordSet><Name>{}</Name><Type>{}</Type>",
            xml::escape(&x.name),
            x.rtype
        ));
        if let Some(i) = &x.identifier {
            s.push_str(&format!(
                "<SetIdentifier>{i}</SetIdentifier><Weight>10</Weight>"
            ));
        }
        if x.alias {
            s.push_str("<AliasTarget><HostedZoneId>Z1</HostedZoneId><DNSName>lb.example.org.</DNSName><EvaluateTargetHealth>false</EvaluateTargetHealth></AliasTarget>");
        } else {
            s.push_str(&format!("<TTL>{}</TTL><ResourceRecords>", x.ttl));
            for v in &x.values {
                s.push_str(&format!(
                    "<ResourceRecord><Value>{}</Value></ResourceRecord>",
                    xml::escape(v)
                ));
            }
            s.push_str("</ResourceRecords>");
        }
        s.push_str("</ResourceRecordSet>");
    }
    s
}

fn route53_handler(zone: &Arc<Mutex<Zone>>, private: bool) -> Handler {
    let zone = Arc::clone(zone);
    Arc::new(move |r: &Req| -> Reply {
        let ok = |b: String| (200u16, b, vec![]);
        if !signature_ok(r) {
            return (
                403,
                error_doc(
                    "SignatureDoesNotMatch",
                    &format!(
                        "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Authorization was: {} and the key is {KEY_SECRET} id {KEY_ID}",
                        r.headers.get("authorization").cloned().unwrap_or_default()
                    ),
                ),
                vec![],
            );
        }
        let q = |k: &str| r.query.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
        let mut z = zone.lock().unwrap();
        if r.path == "/2013-04-01/hostedzonesbyname" {
            return ok(format!(
                "<?xml version=\"1.0\"?>\n<ListHostedZonesByNameResponse xmlns=\"{NS}\"><HostedZones><HostedZone><Id>/hostedzone/ZPRIVATE</Id><Name>example.net.</Name><CallerReference>a</CallerReference><Config><PrivateZone>true</PrivateZone></Config><ResourceRecordSetCount>2</ResourceRecordSetCount></HostedZone><HostedZone><Id>/hostedzone/Z0123456789ABC</Id><Name>example.net.</Name><CallerReference>b</CallerReference><Config><PrivateZone>false</PrivateZone></Config><ResourceRecordSetCount>2</ResourceRecordSetCount></HostedZone></HostedZones><DNSName>example.net</DNSName><IsTruncated>false</IsTruncated><MaxItems>10</MaxItems></ListHostedZonesByNameResponse>"
            ));
        }
        if r.path == "/2013-04-01/hostedzone/Z0123456789ABC" && r.method == "GET" {
            return ok(format!(
                "<?xml version=\"1.0\"?>\n<GetHostedZoneResponse xmlns=\"{NS}\"><HostedZone><Id>/hostedzone/Z0123456789ABC</Id><Name>example.net.</Name><CallerReference>b</CallerReference><Config><PrivateZone>{private}</PrivateZone></Config><ResourceRecordSetCount>2</ResourceRecordSetCount></HostedZone><DelegationSet><NameServers><NameServer>ns-1.awsdns-01.org</NameServer></NameServers></DelegationSet></GetHostedZoneResponse>"
            ));
        }
        if r.path == "/2013-04-01/hostedzone/Z0123456789ABC/rrset" && r.method == "GET" {
            let mut sorted: Vec<&Stored> = z.sets.iter().collect();
            sorted.sort_by(|a, b| (&a.name, &a.rtype).cmp(&(&b.name, &b.rtype)));
            if let (Some(n), Some(t)) = (q("name"), q("type")) {
                sorted.retain(|s| (s.name.as_str(), s.rtype.as_str()) >= (n.as_str(), t.as_str()));
            }
            let max: usize = if z.page > 0 {
                z.page
            } else {
                q("maxitems").and_then(|m| m.parse().ok()).unwrap_or(100)
            };
            let truncated = sorted.len() > max;
            let next = sorted.get(max).map(|s| (s.name.clone(), s.rtype.clone()));
            sorted.truncate(max);
            let mut body = format!(
                "<?xml version=\"1.0\"?>\n<ListResourceRecordSetsResponse xmlns=\"{NS}\"><ResourceRecordSets>{}</ResourceRecordSets><IsTruncated>{truncated}</IsTruncated>",
                sets_xml(&sorted)
            );
            if let Some((n, t)) = next.filter(|_| truncated) {
                body.push_str(&format!(
                    "<NextRecordName>{n}</NextRecordName><NextRecordType>{t}</NextRecordType>"
                ));
            }
            body.push_str(&format!(
                "<MaxItems>{max}</MaxItems></ListResourceRecordSetsResponse>"
            ));
            return ok(body);
        }
        if r.path == "/2013-04-01/hostedzone/Z0123456789ABC/rrset/" && r.method == "POST" {
            if let Some(f) = z.fail_post.take() {
                return f;
            }
            assert!(r.headers["content-type"].starts_with("text/xml"));
            let doc = xml::parse(r.body.as_bytes()).expect("a request Route 53 would parse");
            assert_eq!(doc.name, "ChangeResourceRecordSetsRequest");
            let change = doc
                .child("ChangeBatch")
                .unwrap()
                .child("Changes")
                .unwrap()
                .child("Change")
                .unwrap();
            let action = change.text_at(&["Action"]).unwrap().to_owned();
            let rs = change.child("ResourceRecordSet").unwrap();
            let name = rs.text_at(&["Name"]).unwrap().to_owned();
            assert!(name.ends_with('.'), "names go with a trailing dot");
            let rtype = rs.text_at(&["Type"]).unwrap().to_owned();
            let ttl: u32 = rs.text_at(&["TTL"]).unwrap().parse().unwrap();
            let values: Vec<String> = rs
                .child("ResourceRecords")
                .unwrap()
                .all("ResourceRecord")
                .map(|v| v.text_at(&["Value"]).unwrap().to_owned())
                .collect();
            let pos = z
                .sets
                .iter()
                .position(|s| s.name == name && s.rtype == rtype);
            match (action.as_str(), pos) {
                ("UPSERT", Some(i)) => {
                    z.sets[i].ttl = ttl;
                    z.sets[i].values = values;
                }
                ("UPSERT", None) => z.sets.push(Stored {
                    name,
                    rtype,
                    ttl,
                    values,
                    alias: false,
                    identifier: None,
                }),
                ("DELETE", Some(i)) if z.sets[i].ttl == ttl && z.sets[i].values == values => {
                    z.sets.remove(i);
                }
                _ => {
                    return (
                        400,
                        error_doc(
                            "InvalidChangeBatch",
                            "Tried to delete resource record set but it was not found or the values do not match",
                        ),
                        vec![],
                    );
                }
            }
            return ok(format!(
                "<?xml version=\"1.0\"?>\n<ChangeResourceRecordSetsResponse xmlns=\"{NS}\"><ChangeInfo><Id>/change/C2682N5HXP0BZ4</Id><Status>PENDING</Status><SubmittedAt>2026-11-27T12:00:00.000Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>"
            ));
        }
        (
            404,
            error_doc("NoSuchHostedZone", "No hosted zone found"),
            vec![],
        )
    })
}

fn cfg(extra: &Value) -> DnsProviderConfig {
    let mut v = json!({
        "name": "aws", "kind": "route53", "zone": "example.net", "credential_ref": "aws",
        "hosted_zone_id": "Z0123456789ABC", "dry_run": false
    });
    for (k, x) in extra.as_object().cloned().unwrap_or_default() {
        v[k] = x;
    }
    serde_json::from_value(v).unwrap()
}

fn secret(v: &str) -> SecretValue {
    SecretValue::from_text(Zeroizing::new(v.to_owned()))
}

fn provider(extra: &Value, endpoint: &str) -> Route53 {
    Route53::new(
        &cfg(extra),
        Some(&secret(&format!("{KEY_ID}:{KEY_SECRET}"))),
    )
    .with_endpoint(endpoint)
}

fn txt(name: &str, ttl: u32, values: &[&str]) -> RecordSet {
    RecordSet {
        name: name.to_owned(),
        rtype: RecordType::Txt,
        ttl,
        values: values.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn seed(zone: &Arc<Mutex<Zone>>, name: &str, rtype: &str, ttl: u32, values: &[&str]) {
    zone.lock().unwrap().sets.push(Stored {
        name: name.to_owned(),
        rtype: rtype.to_owned(),
        ttl,
        values: values.iter().map(|s| (*s).to_owned()).collect(),
        alias: false,
        identifier: None,
    });
}

#[tokio::test]
async fn cld_904_route53_create_update_delete_against_recorded_api() {
    let zone: Arc<Mutex<Zone>> = Arc::default();
    seed(&zone, "www.example.net.", "A", 300, &["192.0.2.10"]);
    let (url, seen) = serve(route53_handler(&zone, false)).await;
    let p = provider(&json!({}), &url);

    // The zone lists the A set and nothing of the challenge yet.
    let l = p.list().await.unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].name, "www.example.net");
    assert_eq!(l[0].values, vec!["192.0.2.10".to_owned()]);

    // Create: the TXT value goes out quoted, with the trailing dot, signed.
    let c = p
        .ensure(&txt("_acme-challenge.example.net", 60, &["token-one"]))
        .await
        .unwrap();
    assert_eq!(c.id.as_deref(), Some("C2682N5HXP0BZ4"));
    {
        let z = zone.lock().unwrap();
        let s = z.sets.iter().find(|s| s.rtype == "TXT").unwrap();
        assert_eq!(s.name, "_acme-challenge.example.net.");
        assert_eq!(s.values, vec!["\"token-one\"".to_owned()]);
        assert_eq!(s.ttl, 60);
    }
    // It reads back as the value that was written.
    let l = p.list().await.unwrap();
    let t = l.iter().find(|s| s.rtype == RecordType::Txt).unwrap();
    assert_eq!(t.values, vec!["token-one".to_owned()]);
    assert_eq!(t.ttl, 60);

    // Update: two values, a new TTL.
    p.ensure(&txt(
        "_acme-challenge.example.net",
        120,
        &["token-one", "token-two"],
    ))
    .await
    .unwrap();
    assert_eq!(
        zone.lock()
            .unwrap()
            .sets
            .iter()
            .find(|s| s.rtype == "TXT")
            .unwrap()
            .values
            .len(),
        2
    );

    // Delete repeats the stored TTL and values, which Route 53 requires.
    p.delete("_acme-challenge.example.net", RecordType::Txt)
        .await
        .unwrap();
    assert!(zone.lock().unwrap().sets.iter().all(|s| s.rtype != "TXT"));
    // Deleting what is gone is not an error.
    p.delete("_acme-challenge.example.net", RecordType::Txt)
        .await
        .unwrap();

    let requests = seen.lock().unwrap().clone();
    assert!(
        requests.iter().all(signature_ok),
        "every request was signed correctly"
    );
    assert!(
        requests
            .iter()
            .all(|r| r.headers["authorization"].contains("host;x-amz-date")),
        "the signed headers"
    );
}

#[tokio::test]
async fn cld_904_route53_a_long_txt_value_and_quotes_round_trip() {
    let zone: Arc<Mutex<Zone>> = Arc::default();
    let (url, _) = serve(route53_handler(&zone, false)).await;
    let p = provider(&json!({}), &url);
    let value = format!("say \"hi\" \\ {}", "x".repeat(600));
    p.ensure(&txt("_acme-challenge.example.net", 60, &[&value]))
        .await
        .unwrap();
    {
        let z = zone.lock().unwrap();
        let stored = &z.sets[0].values[0];
        assert_eq!(
            stored.matches("\" \"").count(),
            2,
            "three strings of at most 255: {stored}"
        );
        assert!(stored.contains("\\\"hi\\\""), "{stored}");
    }
    let l = p.list().await.unwrap();
    assert_eq!(l[0].values, vec![value.clone()], "reads back exactly");
    // The delete matches the stored (chunked) text, not a re-quoted one.
    p.delete("_acme-challenge.example.net", RecordType::Txt)
        .await
        .unwrap();
    assert!(zone.lock().unwrap().sets.is_empty());
    // A value outside ASCII is refused, not mangled.
    let e = p
        .ensure(&txt("_acme-challenge.example.net", 60, &["caf\u{e9}"]))
        .await
        .unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Rejected);
}

#[tokio::test]
async fn cld_904_route53_pages_are_followed_and_bounded() {
    let zone: Arc<Mutex<Zone>> = Arc::default();
    for i in 0..7 {
        seed(
            &zone,
            &format!("h{i}.example.net."),
            "A",
            60,
            &["192.0.2.1"],
        );
    }
    zone.lock().unwrap().page = 3;
    let (url, seen) = serve(route53_handler(&zone, false)).await;
    let p = provider(&json!({}), &url);
    assert_eq!(p.list().await.unwrap().len(), 7);
    assert_eq!(seen.lock().unwrap().len(), 3, "three pages");
}

#[tokio::test]
async fn cld_904_route53_an_alias_or_routing_record_is_never_replaced() {
    let zone: Arc<Mutex<Zone>> = Arc::default();
    zone.lock().unwrap().sets.push(Stored {
        name: "app.example.net.".into(),
        rtype: "A".into(),
        ttl: 0,
        values: vec![],
        alias: true,
        identifier: None,
    });
    zone.lock().unwrap().sets.push(Stored {
        name: "w.example.net.".into(),
        rtype: "A".into(),
        ttl: 60,
        values: vec!["192.0.2.1".into()],
        alias: false,
        identifier: Some("blue".into()),
    });
    let (url, seen) = serve(route53_handler(&zone, false)).await;
    let p = provider(&json!({}), &url);
    // Listed as sets WrenDNS did not make, so the engine's ownership rule keeps its hands off them.
    let l = p.list().await.unwrap();
    assert_eq!(l.len(), 2);
    assert!(
        l.iter()
            .all(|s| s.values[0].contains("managed outside WrenDNS")),
        "{l:?}"
    );
    for name in ["app.example.net", "w.example.net"] {
        let e = p
            .ensure(&RecordSet {
                name: name.into(),
                rtype: RecordType::A,
                ttl: 60,
                values: vec!["192.0.2.9".into()],
            })
            .await
            .unwrap_err();
        assert_eq!(e.kind, ProviderErrorKind::Rejected, "{name}: {e}");
        assert!(p.delete(name, RecordType::A).await.is_err());
    }
    assert!(
        seen.lock().unwrap().iter().all(|r| r.method == "GET"),
        "no change request was sent"
    );
}

#[tokio::test]
async fn cld_904_route53_scope_reports_the_zone_and_a_private_one_is_noted() {
    let zone: Arc<Mutex<Zone>> = Arc::default();
    let (url, _) = serve(route53_handler(&zone, false)).await;
    let s = provider(&json!({}), &url).scope().await.unwrap();
    assert!(
        s.summary.contains("Z0123456789ABC") && s.summary.contains("example.net"),
        "{s:?}"
    );
    assert!(!s.broader_than_needed);
    assert!(s.notes.iter().any(|n| n.contains("IAM policy")), "{s:?}");
    let (url, _) = serve(route53_handler(&zone, true)).await;
    let s = provider(&json!({}), &url).scope().await.unwrap();
    assert!(
        s.notes.iter().any(|n| n.contains("private hosted zone")),
        "{s:?}"
    );
    // A zone ID that belongs to another zone is refused.
    let (url, _) = serve(Arc::new(|_r: &Req| -> Reply {
        (
            200,
            format!("<GetHostedZoneResponse xmlns=\"{NS}\"><HostedZone><Id>/hostedzone/Z1</Id><Name>other.org.</Name></HostedZone></GetHostedZoneResponse>"),
            vec![],
        )
    }))
    .await;
    // (The request is not signed for this server's check: it accepts anything.)
    let e = provider(&json!({}), &url).scope().await.unwrap_err();
    assert!(e.to_string().contains("other.org"), "{e}");
}

#[tokio::test]
async fn cld_904_route53_finds_the_public_zone_by_name() {
    let zone: Arc<Mutex<Zone>> = Arc::default();
    let (url, seen) = serve(route53_handler(&zone, false)).await;
    // No hosted zone ID configured: the zone is looked up, and the private one of the same name is skipped.
    let mut c = cfg(&json!({}));
    c.hosted_zone_id = None;
    let p = Route53::new(&c, Some(&secret(&format!("{KEY_ID}:{KEY_SECRET}")))).with_endpoint(&url);
    p.list().await.unwrap();
    p.list().await.unwrap();
    let r = seen.lock().unwrap().clone();
    assert_eq!(r[0].path, "/2013-04-01/hostedzonesbyname");
    assert!(r[1].path.contains("Z0123456789ABC"), "{:?}", r[1].path);
    assert_eq!(
        r.iter()
            .filter(|x| x.path.ends_with("hostedzonesbyname"))
            .count(),
        1,
        "the lookup is cached"
    );
}

/// Every way a call fails: the kind, and the key, the secret and the signature in no message.
#[tokio::test]
async fn cld_904_route53_errors_are_classified_and_never_show_the_credential() {
    let zone: Arc<Mutex<Zone>> = Arc::default();
    let (url, seen) = serve(route53_handler(&zone, false)).await;
    // A wrong secret: the server's SignatureDoesNotMatch echoes the Authorization header, the key
    // and its id in its message, as an unfriendly server could.
    let wrong = Route53::new(
        &cfg(&json!({})),
        Some(&secret(&format!("{KEY_ID}:not-the-right-secret-0123"))),
    )
    .with_endpoint(&url);
    let e = wrong.list().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::Unauthorized);
    let auth = seen.lock().unwrap()[0].headers["authorization"].clone();
    let sig = auth.rsplit("Signature=").next().unwrap().to_owned();
    // The provider's own scrub, then the engine's (the registry handle).
    let handle = crate::dns_provider::registry::Handle {
        provider: Arc::new(provider(&json!({}), &url)),
        secret: Some(secret(&format!("{KEY_ID}:not-the-right-secret-0123"))),
    };
    let e = handle.scrub(e);
    for text in [e.to_string(), format!("{e:?}")] {
        for needle in [KEY_SECRET, "not-the-right-secret", &sig, KEY_ID] {
            assert!(!text.contains(needle), "{needle} in {text}");
        }
    }
    // Each documented failure maps to its kind.
    for (status, code, kind) in [
        (
            403u16,
            "InvalidClientTokenId",
            ProviderErrorKind::Unauthorized,
        ),
        (403, "AccessDenied", ProviderErrorKind::Forbidden),
        (400, "Throttling", ProviderErrorKind::RateLimited),
        (
            400,
            "PriorRequestNotComplete",
            ProviderErrorKind::RateLimited,
        ),
        (400, "InvalidChangeBatch", ProviderErrorKind::Rejected),
        (500, "InternalError", ProviderErrorKind::Unavailable),
        (503, "ServiceUnavailable", ProviderErrorKind::Unavailable),
    ] {
        let code = code.to_owned();
        let (url, _) = serve(Arc::new(move |_r: &Req| -> Reply {
            (status, error_doc(&code, "a message"), vec![])
        }))
        .await;
        let e = provider(&json!({}), &url).list().await.unwrap_err();
        assert_eq!(e.kind, kind, "{status} {e}");
    }
    // A 429 with Retry-After carries it.
    let (url, _) = serve(Arc::new(|_r: &Req| -> Reply {
        (
            429,
            error_doc("Throttling", "Rate exceeded"),
            vec![("retry-after".into(), "17".into())],
        )
    }))
    .await;
    let e = provider(&json!({}), &url).list().await.unwrap_err();
    assert_eq!(e.kind, ProviderErrorKind::RateLimited);
    assert_eq!(e.retry_after, Some(std::time::Duration::from_secs(17)));
    // A body that is not XML, and one too large, are refused, not trusted.
    let (url, _) = serve(Arc::new(|_r: &Req| -> Reply {
        (200, "<a><b></a>".into(), vec![])
    }))
    .await;
    assert!(provider(&json!({}), &url).list().await.is_err());
    let (url, _) = serve(Arc::new(|_r: &Req| -> Reply {
        (
            200,
            format!("<a>{}</a>", "x".repeat(3 * 1024 * 1024)),
            vec![],
        )
    }))
    .await;
    assert!(
        provider(&json!({}), &url).list().await.is_err(),
        "the response is capped"
    );
}

#[tokio::test]
async fn cld_904_route53_a_credential_that_is_not_a_pair_is_refused_without_echoing_it() {
    let zone: Arc<Mutex<Zone>> = Arc::default();
    let (url, seen) = serve(route53_handler(&zone, false)).await;
    for bad in ["only-one-part-secret-value", ":", "id:"] {
        let p = Route53::new(&cfg(&json!({})), Some(&secret(bad))).with_endpoint(&url);
        let e = p.list().await.unwrap_err();
        assert_eq!(e.kind, ProviderErrorKind::Unauthorized);
        assert!(!e.to_string().contains(bad) || bad.len() < 3, "{e}");
    }
    let none = Route53::new(&cfg(&json!({})), None).with_endpoint(&url);
    assert_eq!(
        none.list().await.unwrap_err().kind,
        ProviderErrorKind::Unauthorized
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "nothing was sent without a usable credential"
    );
}

#[tokio::test]
async fn cld_904_route53_names_outside_the_plain_set_are_refused_before_a_request() {
    let zone: Arc<Mutex<Zone>> = Arc::default();
    let (url, seen) = serve(route53_handler(&zone, false)).await;
    let p = provider(&json!({}), &url);
    for bad in [
        "a b.example.net",
        "a\\052.example.net",
        "<x>.example.net",
        "",
    ] {
        assert!(p.ensure(&txt(bad, 60, &["v"])).await.is_err(), "{bad}");
        assert!(p.delete(bad, RecordType::Txt).await.is_err(), "{bad}");
    }
    assert!(seen.lock().unwrap().is_empty());
}

/// Through the write engine with the real provider: audit, ledger and a refused change, and the
/// credential in no audit row.
#[tokio::test]
async fn cld_904_route53_through_the_engine_with_the_audit_and_ledger() {
    use crate::credential_tests::harness;
    use crate::dns_provider::engine::{Outcome, Who, engine};
    use crate::dns_provider::ledger::Ledger;

    let h = harness("");
    let zone: Arc<Mutex<Zone>> = Arc::default();
    seed(&zone, "www.example.net.", "A", 300, &["192.0.2.10"]);
    let (url, _) = serve(route53_handler(&zone, false)).await;
    let c = cfg(&json!({ "max_writes_per_minute": 60, "max_writes_per_hour": 1000 }));
    let handle = crate::dns_provider::registry::Handle {
        provider: Arc::new(provider(&json!({}), &url)),
        secret: Some(secret(&format!("{KEY_ID}:{KEY_SECRET}"))),
    };
    let who = Who::User {
        name: "ada".into(),
        kind: "session",
        remote: None,
        reason: None,
    };
    let want = txt("_acme-challenge.example.net", 60, &["tok"]);
    let o = engine()
        .ensure(&h.auth, &c, &handle, &who, &want)
        .await
        .unwrap();
    assert!(matches!(o, Outcome::Written { .. }), "{o:?}");
    assert!(
        Ledger(h.auth.state())
            .get("aws", RecordType::Txt, "_acme-challenge.example.net")
            .is_some()
    );
    // A record the node did not make is not overwritten.
    let e = engine()
        .ensure(
            &h.auth,
            &c,
            &handle,
            &who,
            &RecordSet {
                name: "www.example.net".into(),
                rtype: RecordType::A,
                ttl: 60,
                values: vec!["192.0.2.99".into()],
            },
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains("not made by this node"), "{e}");
    // A failing write is reported with the credential scrubbed, in the audit too.
    zone.lock().unwrap().fail_post = Some((
        403,
        error_doc(
            "AccessDenied",
            &format!("User {KEY_ID} is not authorized; secret {KEY_SECRET}"),
        ),
        vec![],
    ));
    let e = engine()
        .ensure(
            &h.auth,
            &c,
            &handle,
            &who,
            &txt("_acme-challenge.example.net", 60, &["tok2"]),
        )
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("not allowed") || e.to_string().contains("403"),
        "{e}"
    );
    let audit = h.audit_text();
    assert!(audit.contains("dns_provider.ensure"));
    for needle in [KEY_SECRET, KEY_ID] {
        assert!(!audit.contains(needle), "{needle} in the audit log");
        assert!(!e.to_string().contains(needle), "{needle} in {e}");
    }
    // The delete goes through and forgets the row.
    let o = engine()
        .delete(
            &h.auth,
            &c,
            &handle,
            &who,
            "_acme-challenge.example.net",
            RecordType::Txt,
        )
        .await
        .unwrap();
    assert!(matches!(o, Outcome::Written { .. }), "{o:?}");
}

#[tokio::test]
async fn cld_904_route53_two_public_zones_of_one_name_need_the_zone_id() {
    let (url, _) = serve(Arc::new(|_r: &Req| -> Reply {
        let z = |id: &str| format!("<HostedZone><Id>/hostedzone/{id}</Id><Name>example.net.</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone>");
        (
            200,
            format!(
                "<ListHostedZonesByNameResponse xmlns=\"{NS}\"><HostedZones>{}{}</HostedZones></ListHostedZonesByNameResponse>",
                z("ZONEA"),
                z("ZONEB")
            ),
            vec![],
        )
    }))
    .await;
    let mut c = cfg(&json!({}));
    c.hosted_zone_id = None;
    let p = Route53::new(&c, Some(&secret(&format!("{KEY_ID}:{KEY_SECRET}")))).with_endpoint(&url);
    let e = p.list().await.unwrap_err();
    assert!(
        e.to_string().contains("more than one") && e.to_string().contains("hosted zone ID"),
        "{e}"
    );
}

#[tokio::test]
async fn cld_904_route53_scope_does_not_claim_types_it_did_not_check() {
    let zone: Arc<Mutex<Zone>> = Arc::default();
    let (url, _) = serve(route53_handler(&zone, false)).await;
    let s = provider(&json!({}), &url).scope().await.unwrap();
    assert_eq!(s.record_types, vec![RecordType::Txt]);
    assert!(s.summary.contains("NOT checked"), "{s:?}");
}

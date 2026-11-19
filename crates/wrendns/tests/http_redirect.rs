//! REQ: API-003 (T24.44, ADR-1053) — with `[api] tls` and `[api] http_redirect`, a plain-HTTP request
//! on the redirect address is answered with a 308 to the HTTPS address, a bad Host with a 400, and
//! the health probes as on the API port. DNS keeps answering whether or not the redirect binds.

#![allow(clippy::expect_used)] // test helpers

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// One raw request, tried up to three times (a busy host can stall one); the response's head
/// (status line and headers, lower-cased) and body.
fn get(port: u16, path: &str, host: &str) -> Option<(u16, String, String)> {
    (0..3).find_map(|_| get_once(port, path, host))
}

fn get_once(port: u16, path: &str, host: &str) -> Option<(u16, String, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(15))).ok()?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).ok()?;
    let mut raw = String::new();
    let _ = s.read_to_string(&mut raw);
    let (head, body) = raw.split_once("\r\n\r\n")?;
    let status = head.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, head.to_ascii_lowercase(), body.to_owned()))
}

struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(tmp: &std::path::Path, redirect: u16, api: u16, dns: u16) -> Node {
    let metrics = free_port();
    let cfg = tmp.join("t.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"[node]
data_dir = "{}"

[[listen]]
proto = "udp"
addr = "127.0.0.1:{dns}"

[[upstream]]
name = "nowhere"
url = "udp://127.0.0.1:9"

[[upstream_group]]
name = "default"
members = ["nowhere"]

[telemetry.metrics]
listen = "127.0.0.1:{metrics}"

[api]
listen = "127.0.0.1:{api}"
tls = {{ self_signed = true }}
http_redirect = "127.0.0.1:{redirect}"
"#,
            tmp.join("data").display()
        ),
    )
    .expect("write config");
    let log = std::fs::File::create(tmp.join("node.log")).expect("log");
    Node(
        Command::new(env!("CARGO_BIN_EXE_wrendns"))
            .args(["run", "-c"])
            .arg(&cfg)
            .stdout(log.try_clone().expect("log"))
            .stderr(log)
            .spawn()
            .expect("start"),
    )
}

#[test]
fn api_003_http_redirect_sends_browsers_to_https_and_answers_health() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (redirect, api, dns) = (free_port(), free_port(), free_port());
    let _node = start(tmp.path(), redirect, api, dns);
    let log = || std::fs::read_to_string(tmp.path().join("node.log")).unwrap_or_default();
    let begin = Instant::now();
    let livez = loop {
        if let Some(r) = get(redirect, "/livez", "localhost") {
            break r;
        }
        assert!(
            begin.elapsed() < Duration::from_secs(60),
            "the redirect never answered\n{}",
            log()
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(livez.0, 200);
    assert_eq!(livez.2, "ok\n");
    assert!(livez.1.contains("cache-control: no-store"), "{}", livez.1);
    // /healthz as on the API port; /readyz answers (200 once started, 503 with a reason before).
    assert_eq!(
        get(redirect, "/healthz", "localhost").map(|r| r.0),
        Some(200)
    );
    let ready = get(redirect, "/readyz", "localhost").expect("readyz").0;
    assert!(ready == 200 || ready == 503, "{ready}");
    // Everything else: a 308 to https on the API's port, with the path and query kept.
    let (status, head, _) =
        get(redirect, "/ui/settings?tab=system", "dns.example.com:80").expect("redirect");
    assert_eq!(status, 308);
    assert!(
        head.contains(&format!(
            "location: https://dns.example.com:{api}/ui/settings?tab=system"
        )),
        "{head}"
    );
    assert!(head.contains("cache-control: no-store"), "{head}");
    let (status, head, _) = get(redirect, "/", "[2001:db8::1]:80").expect("v6");
    assert_eq!(status, 308);
    assert!(
        head.contains(&format!("location: https://[2001:db8::1]:{api}/")),
        "{head}"
    );
    // A Host that could make an open redirect is refused.
    for bad in [
        "evil.example@dns.example.com",
        "dns.example.com/evil",
        "a b",
    ] {
        let r = get(redirect, "/", bad).expect("bad host");
        assert_eq!(r.0, 400, "{bad}");
        assert!(!r.1.contains("location:"), "{}", r.1);
    }
}

#[test]
fn api_003_a_failed_redirect_bind_leaves_the_api_and_dns_alone() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // The redirect address is already taken: the bind fails, and the node carries on.
    let taken = TcpListener::bind("127.0.0.1:0").expect("bind");
    let redirect = taken.local_addr().expect("addr").port();
    let (api, dns) = (free_port(), free_port());
    let _node = start(tmp.path(), redirect, api, dns);
    let log = || std::fs::read_to_string(tmp.path().join("node.log")).unwrap_or_default();
    let begin = Instant::now();
    loop {
        if log().contains("http_redirect") && log().contains("is not redirected") {
            break;
        }
        assert!(
            begin.elapsed() < Duration::from_secs(60),
            "no bind failure logged\n{}",
            log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // DNS still answers (a UDP socket on the DNS port is open: a query gets a reply).
    let s = UdpSocket::bind("127.0.0.1:0").expect("udp");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let q = [
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
    ];
    s.send_to(&q, ("127.0.0.1", dns)).expect("send");
    let mut buf = [0u8; 512];
    let n = s.recv(&mut buf).expect("DNS answered");
    assert!(n > 12 && buf[0..2] == [0x12, 0x34]);
}

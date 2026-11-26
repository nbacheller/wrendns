//! REQ: CLU-015, API-015 (T23.5 AC17, ADR-903 §6) — two real WrenDNS processes, a primary and
//! a replica, joined with a join token over the cluster's mTLS channel. A secret set on the
//! replica is forwarded to the primary and comes back to the replica (re-encrypted under its own
//! key); a delete on the primary reaches the replica; the replica's data directory holds no
//! plaintext; the replica still has the secret after a restart; the Cluster page shows it in sync.

#![allow(clippy::expect_used, clippy::unwrap_used)] // test helpers

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// The value planted: it must never be read back, and never be on the replica's disk.
const VALUE: &str = "two-process-secret-4f1e9c";
const ADMIN_PASSWORD: &str = "correct horse battery";

fn free_udp() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn free_tcp() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// The ports and paths one node needs.
struct Node {
    data: PathBuf,
    log: PathBuf,
    config: PathBuf,
    api: u16,
    metrics: u16,
}

/// Writes a node's configuration. The primary creates the cluster (`[cluster.init]`); a replica
/// joins it with a token, so it's a full member (a bootstrap-secret join is an ephemeral pod).
fn node(root: &Path, name: &str, site: &str, primary: bool) -> Node {
    let dir = root.join(name);
    let data = dir.join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    let (dns, api, metrics, cluster) = (free_udp(), free_tcp(), free_tcp(), free_tcp());
    let init = if primary {
        format!("\n[cluster.init]\nadvertise = [\"https://127.0.0.1:{cluster}\"]\n")
    } else {
        String::new()
    };
    let config = dir.join("wrendns.toml");
    std::fs::write(
        &config,
        format!(
            r#"[node]
data_dir = "{data}"
name = "{name}"

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

[cluster]
name = "home"
site = "{site}"
eligible = true
listen = "127.0.0.1:{cluster}"
config_source = "file"
{init}"#,
            data = data.display(),
        ),
    )
    .expect("config");
    Node {
        log: dir.join("log.txt"),
        data,
        config,
        api,
        metrics,
    }
}

/// A `wrendns` command with none of the test host's WrenDNS environment.
fn wrendns() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wrendns"));
    for (k, _) in std::env::vars() {
        if k.starts_with("WRENDNS_") {
            cmd.env_remove(k);
        }
    }
    cmd.stdin(Stdio::null());
    cmd
}

/// A command run to the end: its standard output, or a panic with its error output.
fn run_cli(n: &Node, args: &[&str]) -> String {
    let out = wrendns()
        .args(args)
        .arg("-c")
        .arg(&n.config)
        .output()
        .expect("run wrendns");
    assert!(
        out.status.success(),
        "wrendns {args:?}: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A running node, stopped when dropped. When the test fails, its log's tail is printed.
struct Running(Child, PathBuf);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        if std::thread::panicking() {
            let log = std::fs::read_to_string(&self.1).unwrap_or_default();
            let tail: Vec<&str> = log.lines().rev().take(30).collect();
            eprintln!(
                "--- {} (last lines)\n{}",
                self.1.display(),
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            );
        }
    }
}

fn start(n: &Node) -> Running {
    let log = std::fs::File::create(&n.log).expect("log");
    let child = wrendns()
        .args(["run", "-c"])
        .arg(&n.config)
        .env("WRENDNS_BOOTSTRAP_ADMIN_USER", "admin")
        .env("WRENDNS_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .stdout(Stdio::from(log.try_clone().expect("clone")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("start wrendns");
    Running(child, n.log.clone())
}

/// One HTTP/1.1 request on loopback: the status, the response headers and the body as text. A
/// status of 0 when nothing listens yet.
fn request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: Option<&Value>,
) -> (u16, String, String) {
    // Not listening yet: a status of 0, so the caller's wait loop tries again.
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return (0, String::new(), String::new());
    };
    s.set_read_timeout(Some(Duration::from_secs(20)))
        .expect("timeout");
    let payload = body.map(Value::to_string).unwrap_or_default();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        payload.len()
    );
    for (k, v) in headers {
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    if body.is_some() {
        req.push_str("Content-Type: application/json\r\n");
    }
    req.push_str("\r\n");
    req.push_str(&payload);
    s.write_all(req.as_bytes()).expect("write");
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, head.to_owned(), body.to_owned())
}

/// A signed-in admin on one node.
#[derive(Clone)]
struct Session {
    port: u16,
    cookie: String,
    csrf: String,
}

/// Signs the bootstrap admin in; `None` until the node answers.
fn sign_in(port: u16) -> Option<Session> {
    try_sign_in(port).ok()
}

/// Signs the bootstrap admin in, or says what the node answered: the HTTP status, 0 when nothing
/// listens yet (the process is still starting), 1 for a 200 without a cookie or a token.
fn try_sign_in(port: u16) -> Result<Session, u16> {
    let body = serde_json::json!({ "username": "admin", "password": ADMIN_PASSWORD });
    let (s, head, text) = request(port, "POST", "/api/v1/auth/login", &[], Some(&body));
    if s != 200 {
        return Err(s);
    }
    let cookie = head
        .lines()
        .find_map(|l| {
            l.strip_prefix("set-cookie: ")
                .or_else(|| l.strip_prefix("Set-Cookie: "))
        })
        .and_then(|c| c.split(';').next())
        .ok_or(1_u16)?
        .to_owned();
    let json: Value = serde_json::from_str(&text).map_err(|_| 1_u16)?;
    let csrf = json["csrfToken"].as_str().ok_or(1_u16)?.to_owned();
    Ok(Session { port, cookie, csrf })
}

/// The stage a node's startup has reached, from what its two listeners answer: "before the metrics
/// bind" (nothing on either port: the process is still starting early), "metrics up, API not" (the
/// auth store is opening, which hashes the bootstrap password with Argon2, before the API binds),
/// or "API up" (it answered a sign-in with the status in `last`).
fn stage(metrics: u16, last: u16) -> &'static str {
    if last != 0 {
        "API up (it answered and refused)"
    } else if request(metrics, "GET", "/healthz", &[], None).0 != 0 {
        "metrics up, API not (auth store opening)"
    } else {
        "before the metrics bind"
    }
}

/// The message of a sign-in timeout: the stage, what the node last answered, and its log's tail.
fn timeout_report(
    who: &str,
    node: &Running,
    tries: u32,
    secs: u64,
    last: u16,
    metrics: u16,
) -> String {
    let log = std::fs::read_to_string(&node.1).unwrap_or_default();
    let tail: Vec<&str> = log.lines().rev().take(12).collect();
    let age = std::fs::metadata(&node.1)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map_or_else(|| "unknown".to_owned(), |d| format!("{} s", d.as_secs()));
    format!(
        "timed out waiting for {who}'s sign-in: {tries} tries in {secs} s, last answer {last} (0 = nothing listening), stage: {}; the log was last written {age} ago, its last lines:\n{}",
        stage(metrics, last),
        tail.into_iter().rev().collect::<Vec<_>>().join("\n")
    )
}

/// Waits for a node's sign-in. A timeout names the stage the node reached (see `stage`), what it
/// last answered at a sign-in (0: nothing listened), and the last lines of its log with the log
/// file's age; a process that has exited fails at once instead of after the whole wait.
fn wait_sign_in(secs: u64, who: &str, node: &mut Running, port: u16, metrics: u16) -> Session {
    let until = Instant::now() + Duration::from_secs(secs);
    let mut tries = 0_u32;
    loop {
        let last = match try_sign_in(port) {
            Ok(s) => return s,
            Err(status) => status,
        };
        tries += 1;
        let exited = node.0.try_wait().ok().flatten();
        assert!(
            exited.is_none(),
            "{who} exited ({exited:?}) after {tries} sign-in tries; last answer {last}"
        );
        assert!(
            Instant::now() < until,
            "{}",
            timeout_report(who, node, tries, secs, last, metrics)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// A call with the session: writes carry the CSRF token.
fn call(s: &Session, method: &str, path: &str, body: Option<&Value>) -> (u16, String) {
    let mut headers = vec![("Cookie", s.cookie.clone())];
    if method != "GET" {
        headers.push(("X-CSRF-Token", s.csrf.clone()));
    }
    let (status, _, text) = request(s.port, method, path, &headers, body);
    (status, text)
}

/// A call on a node that has just joined. Its sessions end once, when the primary's accounts
/// arrive and replace the local admin, so a 401 signs in again and asks once more.
fn call_joined(s: &mut Session, method: &str, path: &str, body: Option<&Value>) -> (u16, String) {
    let (status, text) = call(s, method, path, body);
    if status != 401 {
        return (status, text);
    }
    match sign_in(s.port) {
        Some(again) => {
            *s = again;
            call(s, method, path, body)
        }
        None => (status, text),
    }
}

fn get_json(s: &Session, path: &str) -> Option<Value> {
    let (status, text) = call(s, "GET", path, None);
    if status != 200 {
        return None;
    }
    serde_json::from_str(&text).ok()
}

/// Polls `check` until it returns a value, or fails after `secs`.
fn wait_for<T>(secs: u64, what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    let until = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = check() {
            return v;
        }
        assert!(Instant::now() < until, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Every byte under `dir`, files and their names.
fn bytes_under(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(bytes_under(&p));
            } else if let Ok(b) = std::fs::read(&p) {
                out.extend(b);
            }
        }
    }
    out
}

/// REQ: CLU-015 (AC17) — set on the replica, forwarded, replicated back; deleted on the primary,
/// deleted on the replica; no plaintext on the replica's disk; kept across a restart.
#[test]
fn clu_015_two_processes_set_on_replica_replicates_back() {
    let root = tempfile::tempdir().expect("root");
    let p = node(root.path(), "primary", "k8s", true);
    let r = node(root.path(), "replica", "pi", false);
    // The primary creates the cluster on its first start; a token then brings the replica in.
    let mut pr = start(&p);
    let ps = wait_sign_in(60, "the primary", &mut pr, p.api, p.metrics);
    let text = run_cli(
        &p,
        &["cluster", "token", "create", "--eligible", "--ttl", "30m"],
    );
    let token = text
        .split_whitespace()
        .find(|w| w.starts_with("tt_join_"))
        .expect("a join token")
        .to_owned();
    run_cli(
        &r,
        &["cluster", "join", &token, "--site", "pi", "--eligible"],
    );
    let mut rr = start(&r);
    let mut rs = wait_sign_in(60, "the replica", &mut rr, r.api, r.metrics);
    wait_for(90, "the replica to join and be seen", || {
        let v = get_json(&ps, "/api/v1/cluster")?;
        let up = v["nodes"]
            .as_array()?
            .iter()
            .filter(|n| n["up"] == true)
            .count();
        (up >= 2).then_some(())
    });
    // Set on the replica: the primary stores it.
    let (s, body) = call_joined(
        &mut rs,
        "PUT",
        "/api/v1/secrets/unifi",
        Some(&serde_json::json!({ "value": VALUE, "kind": "text" })),
    );
    assert_eq!(s, 200, "{body}");
    assert!(!body.contains(VALUE), "the answer carries no value");
    wait_for(30, "the primary to hold it", || {
        let v = get_json(&ps, "/api/v1/secrets/unifi")?;
        (v["set"] == true).then_some(())
    });
    // Replicated back to the replica, under its own key.
    let meta = wait_for(90, "the replica to hold it", || {
        let (status, text) = call_joined(&mut rs, "GET", "/api/v1/secrets/unifi", None);
        let v: Value = (status == 200)
            .then(|| serde_json::from_str(&text).ok())
            .flatten()?;
        (v["set"] == true && v["origin"] == "cluster").then_some(v)
    });
    assert!(!meta.to_string().contains(VALUE), "metadata only");
    // The primary sees the replica in sync with its head.
    wait_for(60, "the replica in sync on the Cluster page", || {
        let v = get_json(&ps, "/api/v1/cluster")?;
        let node = v["nodes"]
            .as_array()?
            .iter()
            .find(|n| n["site"] == "pi")?
            .clone();
        (node["secrets"]["inSync"] == true).then_some(())
    });
    // Nothing of the value is on the replica's disk.
    let on_disk = bytes_under(&r.data);
    assert!(
        !on_disk.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()),
        "the replica's data directory holds no plaintext"
    );
    // The replica still has it after a restart (its own key, its own table).
    drop(rr);
    rr = start(&r);
    let rs = wait_sign_in(60, "the restarted replica", &mut rr, r.api, r.metrics);
    let again = wait_for(60, "the secret after a restart", || {
        let v = get_json(&rs, "/api/v1/secrets/unifi")?;
        (v["set"] == true).then_some(v)
    });
    assert_eq!(again["origin"], "cluster");
    // A delete on the primary reaches the replica by tombstone.
    let (s, body) = call(&ps, "DELETE", "/api/v1/secrets/unifi", None);
    assert_eq!(s, 200, "{body}");
    // A deleted name answers 404 (or a record that isn't set): the replica has lost it.
    wait_for(90, "the replica to lose it", || {
        let (status, text) = call(&rs, "GET", "/api/v1/secrets/unifi", None);
        let gone =
            status == 404 || serde_json::from_str::<Value>(&text).is_ok_and(|v| v["set"] != true);
        gone.then_some(())
    });
    drop(rr);
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b4) - what the REST-and-JSON provider kinds (Azure DNS, Cloudflare)
//! share: one bounded HTTP call through the existing client, the mapping of a status to a
//! [`ProviderErrorKind`], and the URL-encoding of the pieces a provider puts in a path or a form.
//!
//! Every call has a timeout and a response size cap, follows no redirect (the client never does),
//! and builds its errors from a status and a short provider message only: no header, URL or body is
//! echoed, so a credential, a token or a signature cannot reach an error through here.

use std::fmt::Write as _;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use wrendns_filter::fetch::{Client, SystemResolver};

use super::{ProviderError, ProviderErrorKind};

/// The longest one call may take.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// The most of a response that is read (a zone listing page is far below this).
pub(crate) const MAX_RESPONSE: u64 = 4 * 1024 * 1024;

/// What came back.
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
    pub(crate) retry_after: Option<Duration>,
    /// The provider's own request ID (`x-ms-request-id`, `cf-ray`), for the audit row.
    pub(crate) request_id: Option<String>,
}

impl Reply {
    pub(crate) fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The body as JSON, or why not (never the body itself).
    pub(crate) fn json(&self) -> Result<serde_json::Value, ProviderError> {
        serde_json::from_slice(&self.body).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Rejected,
                format!("the provider's answer ({}) was not JSON", self.status),
            )
        })
    }

    /// The error for a failed status, with `detail` (a provider message already picked out of the
    /// body) as its text.
    pub(crate) fn error(&self, detail: &str) -> ProviderError {
        let kind = match self.status {
            401 => ProviderErrorKind::Unauthorized,
            403 => ProviderErrorKind::Forbidden,
            429 => return ProviderError::rate_limited(self.retry_after),
            408 | 504 => ProviderErrorKind::Timeout,
            500..=599 => ProviderErrorKind::Unavailable,
            _ => ProviderErrorKind::Rejected,
        };
        let text = if detail.is_empty() {
            format!("HTTP {}", self.status)
        } else {
            format!("HTTP {}: {detail}", self.status)
        };
        ProviderError::new(kind, text)
    }
}

fn client() -> Result<Client, ProviderError> {
    static CLIENT: OnceLock<Result<Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| Client::new(Arc::new(SystemResolver), &[]))
        .clone()
        .map_err(|e| ProviderError::new(ProviderErrorKind::Unavailable, e))
}

/// Sends one request and reads the whole answer, within [`REQUEST_TIMEOUT`] and [`MAX_RESPONSE`].
/// `headers` may carry a credential: nothing here prints them.
pub(crate) async fn send(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
) -> Result<Reply, ProviderError> {
    let mut req = http::Request::builder().method(method).uri(url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req.body(body.unwrap_or_default()).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::Rejected,
            "the request could not be built",
        )
    })?;
    let client = client()?;
    let call = client.request(req, MAX_RESPONSE);
    match tokio::time::timeout(REQUEST_TIMEOUT, call).await {
        Err(_) => Err(ProviderError::new(ProviderErrorKind::Timeout, "")),
        Ok(Err(e)) => Err(ProviderError::new(
            if e.retryable {
                ProviderErrorKind::Unavailable
            } else {
                ProviderErrorKind::Rejected
            },
            e.message,
        )),
        Ok(Ok(resp)) => {
            let retry_after = resp
                .headers()
                .get(http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs);
            let request_id = ["x-ms-request-id", "cf-ray"]
                .iter()
                .find_map(|h| resp.headers().get(*h))
                .and_then(|v| v.to_str().ok())
                .map(|v| v.chars().filter(char::is_ascii_graphic).take(64).collect());
            Ok(Reply {
                request_id,
                status: resp.status().as_u16(),
                body: resp.into_body(),
                retry_after,
            })
        }
    }
}

/// Percent-encodes `s` for a path segment or a form value: letters, digits and `-_.~*` stay.
pub(crate) fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'*') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// A provider message from a JSON body: the first of `error.message`, `error` with
/// `error_description`, `errors[0].message` and `message` that is a string. Empty when none is.
pub(crate) fn message_of(body: &[u8]) -> String {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return String::new();
    };
    let s = |p: &[&str]| -> Option<String> {
        let mut cur = &v;
        for k in p {
            cur = match k.parse::<usize>() {
                Ok(i) => cur.get(i)?,
                Err(_) => cur.get(*k)?,
            };
        }
        cur.as_str().map(str::to_owned)
    };
    if let Some(m) = s(&["error", "message"]) {
        return m;
    }
    if let Some(d) = s(&["error_description"]) {
        return match s(&["error"]) {
            Some(e) => format!("{e}: {d}"),
            None => d,
        };
    }
    s(&["errors", "0", "message"])
        .or_else(|| s(&["message"]))
        .unwrap_or_default()
}

/// `body` with every occurrence of `secret` replaced by `<redacted>` (an answer that echoes a
/// credential or a token is cleaned before anything reads it).
pub(crate) fn cut_out(body: Vec<u8>, secret: &str) -> Vec<u8> {
    let s = secret.as_bytes();
    if s.len() < 3 || !body.windows(s.len()).any(|w| w == s) {
        return body;
    }
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        if body[i..].starts_with(s) {
            out.extend_from_slice(b"<redacted>");
            i += s.len();
        } else {
            out.push(body[i]);
            i += 1;
        }
    }
    out
}

/// SHA-256 of `s`, in hex (a cache key that stands for a credential without holding it).
pub(crate) fn fingerprint(s: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, s.as_bytes());
    let mut out = String::with_capacity(64);
    for b in d.as_ref() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A one-shot HTTP server for tests: it answers each request with what `handler` returns for
/// `(method, path-and-query, headers-and-body text)` and records every request. Local only.
#[cfg(test)]
pub(crate) mod replay {
    use std::fmt::Write as _;
    use std::sync::{Arc, Mutex, PoisonError};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// One request the server saw.
    #[derive(Debug, Clone)]
    pub(crate) struct Seen {
        pub(crate) method: String,
        pub(crate) target: String,
        pub(crate) head: String,
        pub(crate) body: String,
    }

    /// What the handler answers: a status, extra header lines and a body.
    pub(crate) struct Answer(
        pub(crate) u16,
        pub(crate) Vec<(String, String)>,
        pub(crate) String,
    );

    pub(crate) fn ok(body: &str) -> Answer {
        Answer(200, vec![], body.to_owned())
    }

    pub(crate) fn status(code: u16, body: &str) -> Answer {
        Answer(code, vec![], body.to_owned())
    }

    pub(crate) struct Server {
        pub(crate) base: String,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl Server {
        pub(crate) fn seen(&self) -> Vec<Seen> {
            self.seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    pub(crate) async fn start<F>(handler: F) -> Server
    where
        F: Fn(&Seen) -> Answer + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let log = Arc::clone(&seen);
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let (log, handler) = (Arc::clone(&log), Arc::clone(&handler));
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head_end, want) = loop {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                            let len = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            break (i + 4, len);
                        }
                    };
                    while buf.len() < head_end + want {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let body = String::from_utf8_lossy(&buf[head_end..]).into_owned();
                    let mut first = head.lines().next().unwrap_or("").split(' ');
                    let req = Seen {
                        method: first.next().unwrap_or("").to_owned(),
                        target: first.next().unwrap_or("").to_owned(),
                        head,
                        body,
                    };
                    let Answer(code, headers, text) = handler(&req);
                    log.lock().unwrap_or_else(PoisonError::into_inner).push(req);
                    let mut out = format!(
                        "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
                        text.len()
                    );
                    for (k, v) in headers {
                        let _ = write!(out, "{k}: {v}\r\n");
                    }
                    out.push_str("\r\n");
                    out.push_str(&text);
                    let _ = sock.write_all(out.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        Server { base, seen }
    }
}

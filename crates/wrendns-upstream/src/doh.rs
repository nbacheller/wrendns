//! DNS over HTTPS upstreams (RFC 8484) over HTTP/2, or HTTP/1.1 for servers that only speak that.
//!
//! REQ: UPS-001, UPS-008 — the TLS handshake offers `h2` then `http/1.1` and the server chooses.
//! With `h2`, one connection per upstream multiplexes every in-flight query as its own stream and
//! is re-established on failure. With `http/1.1` (or no protocol selected), each connection
//! carries one request at a time, kept alive between queries; concurrent queries use further
//! connections, at most `pool_size` of them, and one that finds all in use waits for one to be
//! free, within the query's own timeout.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use http::{HeaderName, HeaderValue, Method, Request};
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::conn::{BoxIo, Connect};
use crate::http1;
use crate::upstream::ExchangeError;

const DNS_MESSAGE: &str = "application/dns-message";

/// Opens a TLS connection and says whether the server selected HTTP/2.
pub(crate) type DohConnector = Connect<(BoxIo, bool)>;

pub(crate) struct Doh {
    connector: DohConnector,
    uri: String,
    /// REQ: UPS-011 (T9.9) — GET with `?dns=` instead of POST.
    get: bool,
    headers: Vec<(HeaderName, HeaderValue)>,
    /// The HTTP/2 connection; its lock also serializes the first connects, before it is known
    /// which protocol the server speaks.
    sender: Mutex<Option<SendRequest<Bytes>>>,
    h1: H1,
}

/// The HTTP/1.1 side: the request's path and header lines (built once), the idle connections and
/// the limit on how many are open.
struct H1 {
    path: String,
    /// `Host`, `Accept`, and the configured headers, each ending in CRLF.
    headers: Vec<u8>,
    idle: parking_lot::Mutex<Vec<(BoxIo, Instant)>>,
    permits: Arc<Semaphore>,
    max: usize,
    idle_timeout: Duration,
    /// A connection has been answered as HTTP/1.1 (and none since as HTTP/2).
    seen: AtomicBool,
}

/// One HTTP/1.1 connection checked out of the pool; its permit comes back when it is dropped.
struct H1Conn {
    io: BoxIo,
    reused: bool,
    _permit: OwnedSemaphorePermit,
}

enum Chan {
    H2(SendRequest<Bytes>),
    H1(H1Conn),
}

impl std::fmt::Debug for Doh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Doh")
            .field("uri", &self.uri)
            .finish_non_exhaustive()
    }
}

fn io_err(e: impl std::fmt::Display) -> ExchangeError {
    ExchangeError::Io(io::Error::other(e.to_string()))
}

impl Doh {
    /// `authority` is the HTTP host (the URL host, or `tls_server_name`); `pool_size` bounds the
    /// HTTP/1.1 connections and `idle_timeout` how long one may sit unused.
    pub(crate) fn new(
        connector: DohConnector,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
        get: bool,
        pool_size: usize,
        idle_timeout: Duration,
    ) -> Result<Self, String> {
        let mut hs = Vec::new();
        for (k, v) in headers {
            let name =
                HeaderName::try_from(k.as_str()).map_err(|e| format!("header `{k}`: {e}"))?;
            let value =
                HeaderValue::try_from(v.as_str()).map_err(|e| format!("header `{k}`: {e}"))?;
            hs.push((name, value));
        }
        let max = pool_size.max(1);
        Ok(Self {
            connector,
            uri: format!("https://{authority}{path}"),
            get,
            h1: H1 {
                path: path.to_owned(),
                headers: h1_headers(authority, get, &hs),
                idle: parking_lot::Mutex::new(Vec::new()),
                permits: Arc::new(Semaphore::new(max)),
                max,
                idle_timeout,
                seen: AtomicBool::new(false),
            },
            headers: hs,
            sender: Mutex::new(None),
        })
    }

    async fn h2_handshake(&self, io: BoxIo) -> Result<SendRequest<Bytes>, ExchangeError> {
        let (send, conn) = h2::client::handshake(io).await.map_err(io_err)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(send)
    }

    async fn h1_permit(&self) -> Result<OwnedSemaphorePermit, ExchangeError> {
        Arc::clone(&self.h1.permits)
            .acquire_owned()
            .await
            .map_err(io_err)
    }

    /// A connection to send one query on: the HTTP/2 one, or an HTTP/1.1 one (idle, or new).
    async fn acquire(&self, fresh: bool) -> Result<Chan, ExchangeError> {
        if !self.h1.seen.load(Ordering::Acquire) {
            // Until the server has shown which protocol it speaks, connects go one at a time, so
            // a burst of first queries doesn't open a handshake each.
            let mut guard = self.sender.lock().await;
            if !self.h1.seen.load(Ordering::Acquire) {
                if !fresh && let Some(s) = guard.as_ref() {
                    return Ok(Chan::H2(s.clone()));
                }
                let (io, h2) = (self.connector)().await?;
                if h2 {
                    let send = self.h2_handshake(io).await?;
                    *guard = Some(send.clone());
                    return Ok(Chan::H2(send));
                }
                *guard = None;
                self.h1.seen.store(true, Ordering::Release);
                drop(guard);
                return Ok(Chan::H1(H1Conn {
                    io,
                    reused: false,
                    _permit: self.h1_permit().await?,
                }));
            }
        }
        // HTTP/1.1: take a permit (at most `pool_size` connections), then an idle connection or
        // a new one.
        let permit = self.h1_permit().await?;
        if !fresh {
            while let Some(mut io) = self.h1.pop_idle() {
                // REQ: UPS-001 — an idle connection has nothing to read: a byte (or the end of
                // the stream) means the server sent something unasked, and the connection is
                // one answer behind. It is dropped, not reused.
                if idle_is_quiet(&mut io).await {
                    return Ok(Chan::H1(H1Conn {
                        io,
                        reused: true,
                        _permit: permit,
                    }));
                }
            }
        }
        let (io, h2) = (self.connector)().await?;
        if h2 {
            // The server now selects HTTP/2: go back to one multiplexed connection.
            let send = self.h2_handshake(io).await?;
            *self.sender.lock().await = Some(send.clone());
            self.h1.seen.store(false, Ordering::Release);
            return Ok(Chan::H2(send));
        }
        Ok(Chan::H1(H1Conn {
            io,
            reused: false,
            _permit: permit,
        }))
    }

    /// POSTs `query` (ID 0 per RFC 8484 §4.1) and returns the response body.
    pub(crate) async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, ExchangeError> {
        let body = Bytes::copy_from_slice(query);
        for attempt in 0..2 {
            match self.acquire(attempt > 0).await? {
                Chan::H2(sender) => match self.send(sender, body.clone()).await {
                    Ok(v) => return Ok(v),
                    // A broken connection (GOAWAY, reset) gets one retry on a new one.
                    Err(SendError::Connection(_)) if attempt == 0 => {}
                    Err(SendError::Connection(e) | SendError::Other(e)) => return Err(e),
                },
                Chan::H1(mut conn) => match self.h1_send(&mut conn.io, &body).await {
                    Ok((out, keep)) => {
                        if keep {
                            self.h1.put_idle(conn.io);
                        }
                        return Ok(out);
                    }
                    // A kept-alive connection the server closed meanwhile: once more, on a new
                    // one. A new connection that fails is the answer.
                    Err(SendError::Connection(_)) if conn.reused && attempt == 0 => {}
                    Err(SendError::Connection(e) | SendError::Other(e)) => return Err(e),
                },
            }
        }
        Err(io_err("DoH connection failed"))
    }

    /// One request and its response on an HTTP/1.1 connection; whether it may be kept.
    async fn h1_send(&self, io: &mut BoxIo, body: &[u8]) -> Result<(Vec<u8>, bool), SendError> {
        let req = self.h1.request(self.get, body);
        io.write_all(&req)
            .await
            .map_err(|e| SendError::Connection(e.into()))?;
        io.flush()
            .await
            .map_err(|e| SendError::Connection(e.into()))?;
        let resp = match http1::read_response(io).await {
            Ok(r) => r,
            Err(http1::Error::Closed) => {
                return Err(SendError::Connection(io_err("connection closed")));
            }
            Err(http1::Error::Io(e)) => return Err(SendError::Other(e.into())),
            Err(http1::Error::Bad(why)) => {
                tracing::debug!(why, "DoH over HTTP/1.1: refused the response");
                return Err(SendError::Other(ExchangeError::BadResponse));
            }
        };
        if resp.status != 200 {
            return Err(SendError::Other(io_err(format!("HTTP {}", resp.status))));
        }
        // REQ: UPS-001 — the connection goes back to the pool only if this body is the answer to
        // this query (same ID and question, as every transport checks); anything else means the
        // server and this connection are out of step, and it is closed.
        let keep = resp.keep_alive && answers(&resp.body, body);
        Ok((resp.body, keep))
    }

    async fn send(&self, sender: SendRequest<Bytes>, body: Bytes) -> Result<Vec<u8>, SendError> {
        let mut sender = sender
            .ready()
            .await
            .map_err(|e| SendError::Connection(io_err(e)))?;
        let builder = if self.get {
            // RFC 8484 §4.1: base64url without padding, in `dns=`.
            let sep = if self.uri.contains('?') { '&' } else { '?' };
            Request::builder()
                .method(Method::GET)
                .uri(format!("{}{sep}dns={}", self.uri, b64url(&body)))
                .header(http::header::ACCEPT, DNS_MESSAGE)
        } else {
            Request::builder()
                .method(Method::POST)
                .uri(&self.uri)
                .header(http::header::CONTENT_TYPE, DNS_MESSAGE)
                .header(http::header::ACCEPT, DNS_MESSAGE)
                .header(http::header::CONTENT_LENGTH, body.len())
        };
        let mut req = builder.body(()).map_err(|e| SendError::Other(io_err(e)))?;
        for (k, v) in &self.headers {
            req.headers_mut().insert(k.clone(), v.clone());
        }
        let (resp, mut stream) = sender
            .send_request(req, self.get)
            .map_err(|e| SendError::Connection(io_err(e)))?;
        if !self.get {
            stream
                .send_data(body, true)
                .map_err(|e| SendError::Connection(io_err(e)))?;
        }
        let resp = resp.await.map_err(|e| SendError::Connection(io_err(e)))?;
        if resp.status() != http::StatusCode::OK {
            return Err(SendError::Other(io_err(format!("HTTP {}", resp.status()))));
        }
        let mut body = resp.into_body();
        let mut out = Vec::with_capacity(512);
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(|e| SendError::Other(io_err(e)))?;
            let _ = body.flow_control().release_capacity(chunk.len());
            if out.len() + chunk.len() > usize::from(u16::MAX) {
                return Err(SendError::Other(ExchangeError::BadResponse));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

/// Whether `resp` is a DNS message that answers `query`.
fn answers(resp: &[u8], query: &[u8]) -> bool {
    let Some(&[hi, lo]) = query.first_chunk::<2>() else {
        return false;
    };
    crate::upstream::matches_query(resp, query, u16::from_be_bytes([hi, lo]))
}

/// True if nothing can be read from `io` right now: one non-blocking poll (a read attempt that
/// does not wait), so a pending byte, an end of stream or an error all say the connection is not
/// clean. Costs one failed `read` system call per reused query.
async fn idle_is_quiet(io: &mut BoxIo) -> bool {
    std::future::poll_fn(|cx| {
        let mut b = [0u8; 1];
        let mut rb = tokio::io::ReadBuf::new(&mut b);
        std::task::Poll::Ready(matches!(
            std::pin::Pin::new(&mut *io).poll_read(cx, &mut rb),
            std::task::Poll::Pending
        ))
    })
    .await
}

/// URL-safe base64 without padding (RFC 4648 §5).
fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            s.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    s
}

enum SendError {
    Connection(ExchangeError),
    Other(ExchangeError),
}

impl H1 {
    fn pop_idle(&self) -> Option<BoxIo> {
        let mut idle = self.idle.lock();
        let now = Instant::now();
        // Older than the idle timeout: dropped (closed), as the pooled DoT connections are.
        idle.retain(|(_, at)| now.duration_since(*at) < self.idle_timeout);
        idle.pop().map(|(io, _)| io)
    }

    fn put_idle(&self, io: BoxIo) {
        let mut idle = self.idle.lock();
        if idle.len() < self.max {
            idle.push((io, Instant::now()));
        }
    }

    /// The whole request: request line, headers, and (POST) the body, in one buffer.
    fn request(&self, get: bool, body: &[u8]) -> Vec<u8> {
        let mut r = Vec::with_capacity(self.path.len() + self.headers.len() + body.len() + 128);
        if get {
            // RFC 8484 §4.1: base64url without padding, in `dns=`.
            let sep = if self.path.contains('?') { '&' } else { '?' };
            r.extend_from_slice(b"GET ");
            r.extend_from_slice(self.path.as_bytes());
            r.extend_from_slice(format!("{sep}dns={}", b64url(body)).as_bytes());
        } else {
            r.extend_from_slice(b"POST ");
            r.extend_from_slice(self.path.as_bytes());
        }
        r.extend_from_slice(b" HTTP/1.1\r\n");
        r.extend_from_slice(&self.headers);
        if !get {
            r.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }
        r.extend_from_slice(b"\r\n");
        if !get {
            r.extend_from_slice(body);
        }
        r
    }
}

/// Headers that frame the message or the connection: never taken from the configuration.
const FRAMING: [&str; 9] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
    "expect",
];

/// The header lines of every HTTP/1.1 request: `Host`, `Accept`, `Content-Type` (POST), then the
/// configured headers. A configured `Accept` or `Content-Type` replaces ours; the framing ones
/// ([`FRAMING`]) are not sent, so a configured header can't break the request.
fn h1_headers(authority: &str, get: bool, custom: &[(HeaderName, HeaderValue)]) -> Vec<u8> {
    let has = |n: &HeaderName| custom.iter().any(|(k, _)| k == n);
    let mut h = Vec::new();
    h.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
    if !has(&http::header::ACCEPT) {
        h.extend_from_slice(format!("Accept: {DNS_MESSAGE}\r\n").as_bytes());
    }
    if !get && !has(&http::header::CONTENT_TYPE) {
        h.extend_from_slice(format!("Content-Type: {DNS_MESSAGE}\r\n").as_bytes());
    }
    for (k, v) in custom {
        if FRAMING.contains(&k.as_str()) {
            continue;
        }
        h.extend_from_slice(k.as_str().as_bytes());
        h.extend_from_slice(b": ");
        h.extend_from_slice(v.as_bytes());
        h.extend_from_slice(b"\r\n");
    }
    h
}

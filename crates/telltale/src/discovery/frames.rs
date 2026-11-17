//! REQ: DSC-002 (T25.3, ADR-908, ADR-913) — the frames between the main process and a discovery
//! worker. Each frame is a u32 big-endian length (the kind byte and the payload), one kind byte,
//! then the payload. JSON control and result frames are at most 1 MiB; binary chunk frames at
//! most 512 KiB. A frame over its cap is refused before anything is allocated for it, so a worker
//! can't make the main process allocate what it likes.

use std::io::{self, Read, Write};

/// The most a JSON frame may carry (ADR-908).
pub(crate) const JSON_MAX: usize = 1 << 20;
/// The most a binary chunk frame may carry (ADR-908).
pub(crate) const CHUNK_MAX: usize = 512 << 10;
/// The kind byte of a JSON frame.
pub(crate) const KIND_JSON: u8 = 1;
/// The kind byte of a binary chunk frame.
pub(crate) const KIND_CHUNK: u8 = 2;
/// The header: the length (4 bytes) and the kind (1 byte).
pub(crate) const HEADER: usize = 5;

/// One frame, read or to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Frame {
    Json(Vec<u8>),
    Chunk(Vec<u8>),
}

/// Why a frame was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FrameError {
    /// The length is zero: there is no kind byte.
    Empty,
    /// A payload bigger than its kind allows.
    Oversized { kind: u8, len: usize },
    /// A kind byte this version doesn't know.
    UnknownKind(u8),
    /// The stream ended inside a frame, or before one.
    Eof,
    /// Any other read or write failure.
    Io(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty frame"),
            Self::Oversized { kind, len } => {
                write!(f, "frame of kind {kind} is {len} bytes, over its cap")
            }
            Self::UnknownKind(k) => write!(f, "unknown frame kind {k}"),
            Self::Eof => write!(f, "end of stream"),
            Self::Io(e) => write!(f, "frame i/o: {e}"),
        }
    }
}

/// Checks a header: the payload length it announces, for `kind`, within its cap (the length
/// counts the kind byte, so a frame's length is its payload plus one).
pub(crate) fn check_header(len: u32, kind: u8) -> Result<usize, FrameError> {
    if len == 0 {
        return Err(FrameError::Empty);
    }
    let payload = usize::try_from(len.saturating_sub(1)).map_err(|_| FrameError::Oversized {
        kind,
        len: usize::MAX,
    })?;
    let cap = match kind {
        KIND_JSON => JSON_MAX,
        KIND_CHUNK => CHUNK_MAX,
        other => return Err(FrameError::UnknownKind(other)),
    };
    if payload > cap {
        return Err(FrameError::Oversized { kind, len: payload });
    }
    Ok(payload)
}

/// Encodes a frame, refusing a payload over its cap.
pub(crate) fn encode(frame: &Frame) -> Result<Vec<u8>, FrameError> {
    let (kind, body) = match frame {
        Frame::Json(b) => (KIND_JSON, b),
        Frame::Chunk(b) => (KIND_CHUNK, b),
    };
    // The length counts the kind byte; a body too long for a u32 can't be within any cap.
    let announced =
        u32::try_from(body.len().saturating_add(1)).map_err(|_| FrameError::Oversized {
            kind,
            len: body.len(),
        })?;
    check_header(announced, kind)?;
    let mut out = Vec::with_capacity(HEADER.saturating_add(body.len()));
    out.extend_from_slice(&announced.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    Ok(out)
}

/// Writes one frame.
pub(crate) fn write_frame<W: Write>(w: &mut W, frame: &Frame) -> Result<(), FrameError> {
    let bytes = encode(frame)?;
    w.write_all(&bytes)
        .and_then(|()| w.flush())
        .map_err(|e| FrameError::Io(e.to_string()))
}

/// Reads one frame. The header is checked before the payload is read or allocated.
pub(crate) fn read_frame<R: Read>(r: &mut R) -> Result<Frame, FrameError> {
    let mut head = [0u8; HEADER];
    read_exact(r, &mut head)?;
    let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let kind = head[4];
    // The kind byte is part of the length; a zero or unknown kind is refused before a payload read.
    let payload = check_header(len, kind)?;
    let mut body = vec![0u8; payload];
    read_exact(r, &mut body)?;
    Ok(match kind {
        KIND_JSON => Frame::Json(body),
        _ => Frame::Chunk(body),
    })
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), FrameError> {
    r.read_exact(buf).map_err(|e| io_error(&e))
}

fn io_error(e: &io::Error) -> FrameError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        FrameError::Eof
    } else {
        FrameError::Io(e.to_string())
    }
}

/// REQ: DSC-002 (ADR-908) — reads one frame from an async stream, with the same checks as
/// [`read_frame`]: the header is checked before the payload is allocated. The main process reads
/// the worker's bytes with this (the side that reads untrusted input), and the `worker_frames` fuzz
/// target runs it beside [`read_frame`], so both readers are fuzzed.
pub(crate) async fn read_frame_async<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Frame, FrameError> {
    use tokio::io::AsyncReadExt;
    let mut head = [0u8; HEADER];
    r.read_exact(&mut head).await.map_err(|e| io_error(&e))?;
    let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let kind = head[4];
    let payload = check_header(len, kind)?;
    let mut body = vec![0u8; payload];
    r.read_exact(&mut body).await.map_err(|e| io_error(&e))?;
    Ok(match kind {
        KIND_JSON => Frame::Json(body),
        _ => Frame::Chunk(body),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DSC-002 (`dsc_002_async_reader_agrees_with_sync`) — the main process's async reader
    /// refuses exactly what the worker's synchronous reader refuses, with the same error.
    #[tokio::test]
    async fn dsc_002_async_reader_agrees_with_sync() {
        let over_json = wire(u32::try_from(JSON_MAX + 2).unwrap(), KIND_JSON, &[]);
        let cases: [Vec<u8>; 5] = [
            wire(0, KIND_JSON, &[]),
            wire(2, 9, b"x"),
            over_json,
            wire(3, KIND_CHUNK, b"ab"),
            Vec::new(),
        ];
        for bytes in cases {
            let sync = read_frame(&mut &bytes[..]);
            let asynced = read_frame_async(&mut &bytes[..]).await;
            assert_eq!(sync, asynced, "{bytes:?}");
        }
    }

    fn wire(len: u32, kind: u8, body: &[u8]) -> Vec<u8> {
        let mut v = len.to_be_bytes().to_vec();
        v.push(kind);
        v.extend_from_slice(body);
        v
    }

    /// REQ: DSC-002 — a frame round-trips, JSON and chunk alike.
    #[test]
    fn dsc_002_frames_round_trip() {
        for f in [
            Frame::Json(b"{\"t\":\"hello\"}".to_vec()),
            Frame::Chunk(vec![1, 2, 3]),
        ] {
            let bytes = encode(&f).unwrap();
            assert_eq!(read_frame(&mut bytes.as_slice()).unwrap(), f);
        }
    }

    /// REQ: DSC-002 (`dsc_002_oversized_frame_refused`) — a JSON frame over 1 MiB and a chunk over
    /// 512 KiB are refused from the header alone, before any payload is read.
    #[test]
    fn dsc_002_oversized_frame_refused() {
        let json = wire(u32::try_from(JSON_MAX + 2).unwrap(), KIND_JSON, &[]);
        assert!(matches!(
            read_frame(&mut json.as_slice()),
            Err(FrameError::Oversized {
                kind: KIND_JSON,
                ..
            })
        ));
        let chunk = wire(u32::try_from(CHUNK_MAX + 2).unwrap(), KIND_CHUNK, &[]);
        assert!(matches!(
            read_frame(&mut chunk.as_slice()),
            Err(FrameError::Oversized {
                kind: KIND_CHUNK,
                ..
            })
        ));
        // A header claiming a 4 GiB payload is refused without reading a byte of it.
        let huge = wire(u32::MAX, KIND_JSON, &[]);
        assert!(matches!(
            read_frame(&mut huge.as_slice()),
            Err(FrameError::Oversized { .. })
        ));
        // The caps themselves are allowed.
        let at_cap = Frame::Json(vec![b' '; JSON_MAX]);
        assert!(encode(&at_cap).is_ok());
        assert!(encode(&Frame::Json(vec![b' '; JSON_MAX + 1])).is_err());
    }

    /// REQ: DSC-002 — a zero length, an unknown kind and a short stream are refused by name.
    #[test]
    fn dsc_002_bad_headers_refused() {
        assert_eq!(
            read_frame(&mut wire(0, KIND_JSON, &[]).as_slice()),
            Err(FrameError::Empty)
        );
        assert_eq!(
            read_frame(&mut wire(2, 9, b"x").as_slice()),
            Err(FrameError::UnknownKind(9))
        );
        assert_eq!(read_frame(&mut [0u8, 0].as_slice()), Err(FrameError::Eof));
        assert_eq!(
            read_frame(&mut wire(5, KIND_JSON, b"ab").as_slice()),
            Err(FrameError::Eof)
        );
        assert_eq!(read_frame(&mut [].as_slice()), Err(FrameError::Eof));
    }
}

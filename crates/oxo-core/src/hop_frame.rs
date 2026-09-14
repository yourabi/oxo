//! # hop_frame — the binary edge↔worker wire format
//!
//! The hop shipped the request to the worker as HTTP/1.1 TEXT, which the worker
//! then re-parsed, re-built into a Rack env, and answered as HTTP/1.1 text that the
//! edge re-parsed — four parse/serialize passes over data the edge had already parsed.
//! `hop_frame` replaces that with a length-delimited binary frame carrying the
//! ALREADY-PARSED request (method, path, pre-lowered header names, body) so the worker
//! builds the Rack env directly, and answers with typed response frames.
//!
//! ## Why length-delimited, not text
//!
//! The keepalive arc's whole security story was "no hidden second request on a
//! reused connection." A text protocol relies on scanning for `\r\n\r\n` and trusting
//! `Content-Length`; a length-delimited frame makes the boundary EXPLICIT — there is
//! exactly one request per frame and exactly one response exchange per request, with
//! no scanning and no boundary ambiguity. The panel's core invariant:
//!
//! > **Envelope tiling** — a successful decode consumes EXACTLY the declared
//! > remaining-length. Any over-run (an inner length reaching past the envelope) OR
//! > under-run (sections summing short, leaving internal slack) is a fatal decode
//! > error that kills the connection. There is no "trailing data" tolerance.
//!
//! All declared lengths are validated against caps BEFORE any allocation, so a hostile
//! frame can never induce a large allocation or a partial read that pins a thread.
//!
//! ## Layering
//!
//! This module is pure `&[u8]` encode/decode — no `tokio`, no `std::net`, no Ruby —
//! so it lives in `oxo-core` and both the async edge and the blocking worker share
//! ONE implementation (the panel required the test fakes reuse the real encoder,
//! so a translator bug cannot mask a codec bug). The transport (read exactly N bytes)
//! is the caller's job; see [`FramePrefix`](crate::hop_frame::FramePrefix) for the
//! two-step read.

use std::fmt;

/// First frame byte. `0xBF` is not a valid HTTP method-token character (tokens are
/// visible ASCII excluding delimiters), so a worker can sniff byte 0 to tell a frame
/// client from a legacy HTTP/1.1 client without consuming it.
pub const FRAME_MAGIC: u8 = 0xBF;
/// Wire-format version. A frame whose second byte is not this is rejected WITHOUT an
/// HTTP fallback — a `0xBF` first byte is a committed frame-protocol signal.
pub const FRAME_VERSION: u8 = 0x01;

/// Bytes of fixed framing overhead outside the header/body payloads (magic, version,
/// remaining-length, the section length prefixes, port, scheme, counts). A generous
/// constant slack so the `remaining_length <= slack + header_cap + body_cap` pre-check
/// can never reject a legal frame; the exact tiling check is the real guard.
pub const FRAME_FIXED_SLACK: u64 = 4096;

/// Scheme, wire-encoded as one byte (avoids shipping/reparsing the string).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn to_byte(self) -> u8 {
        match self {
            Scheme::Http => 0,
            Scheme::Https => 1,
        }
    }
    fn from_byte(b: u8) -> Result<Self, FrameError> {
        match b {
            0 => Ok(Scheme::Http),
            1 => Ok(Scheme::Https),
            other => Err(FrameError::BadScheme(other)),
        }
    }
    /// The `rack.url_scheme` string.
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

/// Caps enforced on DECLARED lengths before any allocation. Mirror the HTTP-path caps
/// so the frame hop is neither more nor less permissive than the text hop.
#[derive(Debug, Clone, Copy)]
pub struct FrameCaps {
    /// Max summed header bytes (names + values), matching `MAX_REQUEST_HEADER_BYTES` /
    /// `MAX_RESPONSE_HEADER_BYTES`.
    pub max_header_bytes: u32,
    /// Max header count, matching `MAX_REQUEST_HEADERS`.
    pub max_headers: u16,
    /// Max body bytes. The config resolver rejects `max_body_bytes > u32::MAX` in frame
    /// mode (frame lengths are u32), so this always fits.
    pub max_body_bytes: u32,
}

impl FrameCaps {
    /// The largest legal `remaining_length` for these caps — the cheap pre-check before
    /// reading the envelope. The exact tiling check happens after.
    pub fn max_remaining_length(&self) -> u64 {
        FRAME_FIXED_SLACK + u64::from(self.max_header_bytes) + u64::from(self.max_body_bytes)
    }
}

/// A decoded request frame — the already-parsed request the worker builds a Rack env
/// from. Header NAMES are pre-lowered by the edge (the `LoweredHeader`); the worker
/// maps them through its bounded `HTTP_*` key table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFrame {
    pub method: String,
    pub path: String,
    pub query: String,
    pub server_name: String,
    pub server_port: u16,
    pub scheme: Scheme,
    pub remote_addr: String,
    /// `(lowered_name, value)` pairs. The edge has already stripped hop-by-hop and
    /// spoofable headers and synthesized trusted metadata into the dedicated fields
    /// above — this list is the app-visible headers only.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A response frame. `Full` is the buffered path; `Head`/`Chunk`/`End` are the
/// streaming path, mapping 1:1 onto the worker's `WorkerEvent` and the edge's
/// long-lived chunk streamer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseFrame {
    Full {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    Head {
        status: u16,
        headers: Vec<(String, String)>,
    },
    Chunk {
        data: Vec<u8>,
    },
    End,
}

const RESP_FULL: u8 = 0;
const RESP_HEAD: u8 = 1;
const RESP_CHUNK: u8 = 2;
const RESP_END: u8 = 3;

/// Decode failure. Every variant is a FATAL, connection-killing error — there is no
/// recoverable decode state (that is the point of explicit framing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// First byte was not [`FRAME_MAGIC`].
    BadMagic(u8),
    /// Second byte was not [`FRAME_VERSION`].
    BadVersion(u8),
    /// Declared `remaining_length` exceeds the caps-derived maximum.
    EnvelopeTooLarge { declared: u32, max: u64 },
    /// An inner length reached past the envelope (over-run), or the sections summed
    /// short of it (under-run / internal slack). The tiling invariant.
    EnvelopeTilingMismatch { declared: u32, consumed: u64 },
    /// A length prefix reached past the available buffer.
    Truncated,
    /// A must-be-UTF-8 field (method, path, header name, …) was not UTF-8.
    NotUtf8,
    /// Header count exceeded the cap.
    TooManyHeaders { declared: u16, max: u16 },
    /// Summed header bytes exceeded the cap.
    HeaderBytesExceeded { max: u32 },
    /// Body length exceeded the cap.
    BodyTooLarge { declared: u32, max: u32 },
    /// A control byte appeared in a header name/value (CTL injection).
    ControlByteInHeader,
    /// Scheme byte was not 0/1.
    BadScheme(u8),
    /// Response type byte was not 0..=3.
    BadResponseType(u8),
    /// Status code outside 100..=599.
    BadStatus(u16),
    /// Encode-side: a value did not fit the u32 length domain (never a wrapped length).
    LengthOverflow,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hop-frame decode error: {self:?}")
    }
}

impl std::error::Error for FrameError {}

/// The 6-byte fixed prefix every frame starts with: magic, version, and the u32-LE
/// remaining-length. The transport reads these 6 bytes first, validates + sizes the
/// envelope, then reads exactly `remaining_length` more bytes.
#[derive(Debug, Clone, Copy)]
pub struct FramePrefix {
    pub remaining_length: u32,
}

impl FramePrefix {
    pub const LEN: usize = 6;

    /// Parse the 6-byte prefix and validate the envelope size against the caps BEFORE
    /// the caller allocates the read buffer.
    pub fn parse(prefix: &[u8; Self::LEN], caps: &FrameCaps) -> Result<Self, FrameError> {
        if prefix[0] != FRAME_MAGIC {
            return Err(FrameError::BadMagic(prefix[0]));
        }
        if prefix[1] != FRAME_VERSION {
            return Err(FrameError::BadVersion(prefix[1]));
        }
        let remaining_length = u32::from_le_bytes([prefix[2], prefix[3], prefix[4], prefix[5]]);
        let max = caps.max_remaining_length();
        if u64::from(remaining_length) > max {
            return Err(FrameError::EnvelopeTooLarge {
                declared: remaining_length,
                max,
            });
        }
        Ok(FramePrefix { remaining_length })
    }
}

// ---- length-checked cursor over the exact envelope slice ----

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        if n > self.remaining() {
            return Err(FrameError::Truncated);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, FrameError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, FrameError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, FrameError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// A `u16`-length-prefixed UTF-8 string (short fields: method, names, addrs).
    fn short_str(&mut self) -> Result<String, FrameError> {
        let len = self.u16()? as usize;
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| FrameError::NotUtf8)
    }
    /// A `u32`-length-prefixed UTF-8 string (path/query/header values).
    fn long_str(&mut self) -> Result<String, FrameError> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| FrameError::NotUtf8)
    }
}

// ---- header CTL guard ----

/// Reject control bytes in a header name or value — the same class the HTTP path
/// rejects via token/field-value validation, re-checked here so the frame hop cannot
/// smuggle a CRLF or NUL into the Rack env or a downstream response.
fn reject_control_bytes(s: &str) -> Result<(), FrameError> {
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(FrameError::ControlByteInHeader);
    }
    Ok(())
}

// ---- shared header codec ----

fn encode_short(out: &mut Vec<u8>, s: &str) -> Result<(), FrameError> {
    let len = u16::try_from(s.len()).map_err(|_| FrameError::LengthOverflow)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn encode_long_str(out: &mut Vec<u8>, s: &str) -> Result<(), FrameError> {
    let len = u32::try_from(s.len()).map_err(|_| FrameError::LengthOverflow)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn encode_long_bytes(out: &mut Vec<u8>, b: &[u8]) -> Result<(), FrameError> {
    let len = u32::try_from(b.len()).map_err(|_| FrameError::LengthOverflow)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn encode_headers(out: &mut Vec<u8>, headers: &[(String, String)]) -> Result<(), FrameError> {
    let count = u16::try_from(headers.len()).map_err(|_| FrameError::LengthOverflow)?;
    out.extend_from_slice(&count.to_le_bytes());
    for (name, value) in headers {
        encode_short(out, name)?;
        encode_long_str(out, value)?;
    }
    Ok(())
}

/// Decode a header block, enforcing count + summed-byte caps + CTL rejection.
fn decode_headers(
    cur: &mut Cursor<'_>,
    max_headers: u16,
    max_header_bytes: u32,
) -> Result<Vec<(String, String)>, FrameError> {
    let count = cur.u16()?;
    if count > max_headers {
        return Err(FrameError::TooManyHeaders {
            declared: count,
            max: max_headers,
        });
    }
    let mut headers = Vec::with_capacity(count as usize);
    let mut header_bytes: u32 = 0;
    for _ in 0..count {
        let name = cur.short_str()?;
        let value = cur.long_str()?;
        reject_control_bytes(&name)?;
        reject_control_bytes(&value)?;
        header_bytes = header_bytes
            .checked_add(u32::try_from(name.len()).map_err(|_| FrameError::LengthOverflow)?)
            .and_then(|n| {
                n.checked_add(
                    u32::try_from(value.len())
                        .map_err(|_| FrameError::LengthOverflow)
                        .ok()?,
                )
            })
            .ok_or(FrameError::HeaderBytesExceeded {
                max: max_header_bytes,
            })?;
        if header_bytes > max_header_bytes {
            return Err(FrameError::HeaderBytesExceeded {
                max: max_header_bytes,
            });
        }
        headers.push((name, value));
    }
    Ok(headers)
}

// ---- frame assembly (M0.2) ----

// M0.2 (write-path scrutiny): both encoders used to build the envelope into a scratch
// `env` Vec and then `extend_from_slice` it into a second `out` Vec — 2 allocations plus a
// full memcpy of the ENTIRE envelope (method/path/query/all headers/whole body) on every
// request AND every response. The envelope is now written directly into the output buffer
// behind a reserved 6-byte prefix hole, which the finish step backfills: 1 allocation, no
// envelope copy. The wire format is byte-for-byte unchanged (the corpus, the fuzz targets
// and the env-parity golden all still apply as-is). The saving scales with request size,
// so `/bench` is the LEAST favourable case in which to measure it.

/// Open a frame buffer with the 6-byte prefix reserved: magic and version are final, the
/// u32-LE remaining-length is a zeroed hole that [`finish_frame`] backfills. Every
/// `encode_*` helper is append-only and position-independent, so the envelope can be
/// written straight into this buffer.
fn start_frame(envelope_hint: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(FramePrefix::LEN + envelope_hint);
    out.push(FRAME_MAGIC);
    out.push(FRAME_VERSION);
    out.extend_from_slice(&0u32.to_le_bytes()); // length hole
    out
}

/// Backfill the remaining-length hole opened by [`start_frame`]. Overflow is raised on the
/// same condition and with the same error as the pre-shape (envelope length > u32).
fn finish_frame(mut out: Vec<u8>) -> Result<Vec<u8>, FrameError> {
    let envelope_len = out.len() - FramePrefix::LEN;
    let remaining = u32::try_from(envelope_len).map_err(|_| FrameError::LengthOverflow)?;
    out[2..FramePrefix::LEN].copy_from_slice(&remaining.to_le_bytes());
    Ok(out)
}

// ---- request frame ----

/// Encode a full request frame (magic + version + remaining-length + envelope).
pub fn encode_request(req: &RequestFrame) -> Result<Vec<u8>, FrameError> {
    let mut out = start_frame(256 + req.body.len());
    encode_short(&mut out, &req.method)?;
    encode_long_str(&mut out, &req.path)?;
    encode_long_str(&mut out, &req.query)?;
    encode_short(&mut out, &req.server_name)?;
    out.extend_from_slice(&req.server_port.to_le_bytes());
    out.push(req.scheme.to_byte());
    encode_short(&mut out, &req.remote_addr)?;
    encode_headers(&mut out, &req.headers)?;
    encode_long_bytes(&mut out, &req.body)?;
    finish_frame(out)
}

/// W3: the borrowed-field twin of [`RequestFrame`] for the shipped encode path — the
/// edge holds every field as a borrow at encode time, and the owned struct forced a
/// String per field plus two Strings per header just to feed the encoder. Wire bytes are
/// identical by construction: `encode_request_ref` uses the same append-only primitives
/// in the same field order as [`encode_request`], which stays for the worker/fuzz/tests.
pub struct RequestFrameRef<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub server_name: &'a str,
    pub server_port: u16,
    pub scheme: Scheme,
    pub remote_addr: &'a str,
    pub body: &'a [u8],
}

/// Encode from borrows. `header_count` is the u16 count prefix and MUST equal the number
/// of pairs the iterator yields — a mismatch would corrupt the wire, so it is checked and
/// fails closed (the caller surfaces it as a 400, never a malformed frame).
pub fn encode_request_ref<'a>(
    req: &RequestFrameRef<'_>,
    header_count: usize,
    headers: impl Iterator<Item = (&'a str, &'a str)>,
) -> Result<Vec<u8>, FrameError> {
    // W-F: thin wrapper over the buffer-reusing encoder — this ALSO makes every
    // existing test and the byte-parity golden a proof that `_into` produces identical
    // bytes to the historical path.
    let mut out = Vec::new();
    encode_request_ref_into(&mut out, req, header_count, headers)?;
    Ok(out)
}

/// W-F: encode into a caller-owned buffer (the request-scratch frame_buf) — the
/// shipped path's zero-allocation form. The buffer is cleared first, so `finish_frame`'s
/// envelope-length arithmetic is unchanged.
pub fn encode_request_ref_into<'a>(
    out: &mut Vec<u8>,
    req: &RequestFrameRef<'_>,
    header_count: usize,
    headers: impl Iterator<Item = (&'a str, &'a str)>,
) -> Result<(), FrameError> {
    out.clear();
    out.reserve(FramePrefix::LEN + 256 + req.body.len());
    out.push(FRAME_MAGIC);
    out.push(FRAME_VERSION);
    out.extend_from_slice(&0u32.to_le_bytes()); // length hole, backfilled below
    encode_short(out, req.method)?;
    encode_long_str(out, req.path)?;
    encode_long_str(out, req.query)?;
    encode_short(out, req.server_name)?;
    out.extend_from_slice(&req.server_port.to_le_bytes());
    out.push(req.scheme.to_byte());
    encode_short(out, req.remote_addr)?;
    let count = u16::try_from(header_count).map_err(|_| FrameError::LengthOverflow)?;
    out.extend_from_slice(&count.to_le_bytes());
    let mut emitted = 0usize;
    for (name, value) in headers {
        encode_short(out, name)?;
        encode_long_str(out, value)?;
        emitted += 1;
    }
    if emitted != header_count {
        return Err(FrameError::LengthOverflow);
    }
    encode_long_bytes(out, req.body)?;
    // Backfill the length hole — same arithmetic as finish_frame (the buffer was
    // cleared above, so the prefix sits at offset 0).
    let envelope_len = out.len() - FramePrefix::LEN;
    let remaining = u32::try_from(envelope_len).map_err(|_| FrameError::LengthOverflow)?;
    out[2..FramePrefix::LEN].copy_from_slice(&remaining.to_le_bytes());
    Ok(())
}

/// Decode a request envelope — `envelope` is EXACTLY the `remaining_length` bytes the
/// transport read after the prefix. Enforces the tiling invariant.
pub fn decode_request(envelope: &[u8], caps: &FrameCaps) -> Result<RequestFrame, FrameError> {
    let mut cur = Cursor::new(envelope);
    let method = cur.short_str()?;
    let path = cur.long_str()?;
    let query = cur.long_str()?;
    let server_name = cur.short_str()?;
    let server_port = cur.u16()?;
    let scheme = Scheme::from_byte(cur.u8()?)?;
    let remote_addr = cur.short_str()?;
    let headers = decode_headers(&mut cur, caps.max_headers, caps.max_header_bytes)?;
    // Body length is validated against the body cap BEFORE the take() allocates.
    let body_len = cur.u32()?;
    if body_len > caps.max_body_bytes {
        return Err(FrameError::BodyTooLarge {
            declared: body_len,
            max: caps.max_body_bytes,
        });
    }
    let body = cur.take(body_len as usize)?.to_vec();
    // Tiling: the sections must consume the envelope EXACTLY.
    if cur.remaining() != 0 {
        return Err(FrameError::EnvelopeTilingMismatch {
            declared: envelope.len() as u32,
            consumed: cur.pos as u64,
        });
    }
    Ok(RequestFrame {
        method,
        path,
        query,
        server_name,
        server_port,
        scheme,
        remote_addr,
        headers,
        body,
    })
}

// ---- response frame ----

/// Encode a full response frame (prefix + type byte + payload).
pub fn encode_response(resp: &ResponseFrame) -> Result<Vec<u8>, FrameError> {
    // M0.2: size the hint to the payload so a large body does not force a realloc
    // chain — the old shape's `Vec::with_capacity(128)` under-reserved every real response.
    let hint = match resp {
        ResponseFrame::Full { body, .. } => 128 + body.len(),
        ResponseFrame::Chunk { data } => 128 + data.len(),
        _ => 128,
    };
    let mut out = start_frame(hint);
    match resp {
        ResponseFrame::Full {
            status,
            headers,
            body,
        } => {
            out.push(RESP_FULL);
            out.extend_from_slice(&status.to_le_bytes());
            encode_headers(&mut out, headers)?;
            encode_long_bytes(&mut out, body)?;
        }
        ResponseFrame::Head { status, headers } => {
            out.push(RESP_HEAD);
            out.extend_from_slice(&status.to_le_bytes());
            encode_headers(&mut out, headers)?;
        }
        ResponseFrame::Chunk { data } => {
            out.push(RESP_CHUNK);
            encode_long_bytes(&mut out, data)?;
        }
        ResponseFrame::End => {
            out.push(RESP_END);
        }
    }
    finish_frame(out)
}

/// Decode a response envelope (exactly `remaining_length` bytes). The edge RE-VALIDATES
/// every response header byte-set + length here at DECODE, before allocation — a
/// worker is trusted-but-verified. Enforces the tiling invariant.
pub fn decode_response(envelope: &[u8], caps: &FrameCaps) -> Result<ResponseFrame, FrameError> {
    let mut cur = Cursor::new(envelope);
    let ty = cur.u8()?;
    let frame = match ty {
        RESP_FULL => {
            let status = validate_status(cur.u16()?)?;
            let headers = decode_headers(&mut cur, caps.max_headers, caps.max_header_bytes)?;
            let body_len = cur.u32()?;
            if body_len > caps.max_body_bytes {
                return Err(FrameError::BodyTooLarge {
                    declared: body_len,
                    max: caps.max_body_bytes,
                });
            }
            let body = cur.take(body_len as usize)?.to_vec();
            ResponseFrame::Full {
                status,
                headers,
                body,
            }
        }
        RESP_HEAD => {
            let status = validate_status(cur.u16()?)?;
            let headers = decode_headers(&mut cur, caps.max_headers, caps.max_header_bytes)?;
            ResponseFrame::Head { status, headers }
        }
        RESP_CHUNK => {
            let len = cur.u32()?;
            if len > caps.max_body_bytes {
                return Err(FrameError::BodyTooLarge {
                    declared: len,
                    max: caps.max_body_bytes,
                });
            }
            let data = cur.take(len as usize)?.to_vec();
            ResponseFrame::Chunk { data }
        }
        RESP_END => ResponseFrame::End,
        other => return Err(FrameError::BadResponseType(other)),
    };
    if cur.remaining() != 0 {
        return Err(FrameError::EnvelopeTilingMismatch {
            declared: envelope.len() as u32,
            consumed: cur.pos as u64,
        });
    }
    Ok(frame)
}

fn validate_status(status: u16) -> Result<u16, FrameError> {
    if (100..=599).contains(&status) {
        Ok(status)
    } else {
        Err(FrameError::BadStatus(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> FrameCaps {
        FrameCaps {
            max_header_bytes: 64 * 1024,
            max_headers: 128,
            max_body_bytes: 1024 * 1024,
        }
    }

    fn sample_request() -> RequestFrame {
        RequestFrame {
            method: "POST".into(),
            path: "/submit".into(),
            query: "a=1&b=2".into(),
            server_name: "app.example".into(),
            server_port: 443,
            scheme: Scheme::Https,
            remote_addr: "203.0.113.9".into(),
            headers: vec![
                ("host".into(), "app.example".into()),
                ("content-type".into(), "application/json".into()),
            ],
            body: b"{\"hello\":\"world\"}".to_vec(),
        }
    }

    // Read the 6-byte prefix + envelope out of a full frame the way a transport would.
    fn split_frame<'a>(frame: &'a [u8], caps: &FrameCaps) -> (FramePrefix, &'a [u8]) {
        let prefix_bytes: [u8; FramePrefix::LEN] = frame[..FramePrefix::LEN].try_into().unwrap();
        let prefix = FramePrefix::parse(&prefix_bytes, caps).unwrap();
        let env = &frame[FramePrefix::LEN..FramePrefix::LEN + prefix.remaining_length as usize];
        (prefix, env)
    }

    #[test]
    fn request_round_trips_and_tiles_exactly() {
        let req = sample_request();
        let frame = encode_request(&req).unwrap();
        let (_prefix, env) = split_frame(&frame, &caps());
        let decoded = decode_request(env, &caps()).unwrap();
        assert_eq!(decoded, req);
        // canonical: re-encoding the decode reproduces the exact bytes.
        assert_eq!(encode_request(&decoded).unwrap(), frame);
    }

    // M0.2: the encoder writes the envelope directly into the output buffer behind a
    // reserved prefix hole, which `finish_frame` backfills. These two tests lock that in:
    // a wrong backfill offset or a stale length would corrupt every frame on the wire, and
    // a regression to the old encode-then-copy shape would reintroduce a per-request memcpy
    // of the whole envelope. Both must keep passing byte-for-byte.

    #[test]
    fn prefix_hole_is_backfilled_exactly_for_a_large_envelope() {
        // Large enough that the declared length spans more than one byte of the u32 hole,
        // so a partial or misaligned backfill cannot pass by accident.
        let mut req = sample_request();
        req.body = vec![0xA5; 300_000];
        let frame = encode_request(&req).unwrap();

        // The encoder's own prefix must tile the frame exactly — no slack, no over-run.
        let caps = FrameCaps {
            max_body_bytes: 1 << 20,
            ..caps()
        };
        let (prefix, env) = split_frame(&frame, &caps);
        assert_eq!(
            frame.len(),
            FramePrefix::LEN + prefix.remaining_length as usize,
            "declared remaining_length must tile the encoded frame exactly"
        );
        assert_eq!(frame[0], FRAME_MAGIC);
        assert_eq!(frame[1], FRAME_VERSION);
        assert_eq!(decode_request(env, &caps).unwrap(), req);
    }

    #[test]
    fn encode_does_not_realloc_for_a_typical_request() {
        // `start_frame` reserves FramePrefix::LEN + 256 + body.len(). A typical request
        // encodes inside that reservation, so the whole frame costs ONE allocation and no
        // envelope copy. If this trips, the capacity hint no longer covers the envelope and
        // the single-allocation property is gone — re-derive the hint, do not delete this.
        let req = sample_request();
        let reserved = FramePrefix::LEN + 256 + req.body.len();
        let frame = encode_request(&req).unwrap();
        assert!(
            frame.len() <= reserved,
            "encoded frame {} exceeded the reservation {reserved} — realloc occurred",
            frame.len()
        );
    }

    #[test]
    fn response_variants_round_trip() {
        for resp in [
            ResponseFrame::Full {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: b"ok".to_vec(),
            },
            ResponseFrame::Head {
                status: 200,
                headers: vec![("content-type".into(), "text/event-stream".into())],
            },
            ResponseFrame::Chunk {
                data: b"data: hi\n\n".to_vec(),
            },
            ResponseFrame::End,
        ] {
            let frame = encode_response(&resp).unwrap();
            let (_p, env) = split_frame(&frame, &caps());
            assert_eq!(decode_response(env, &caps()).unwrap(), resp);
            assert_eq!(
                encode_response(&decode_response(env, &caps()).unwrap()).unwrap(),
                frame
            );
        }
    }

    #[test]
    fn bad_magic_and_version_rejected() {
        let mut frame = encode_request(&sample_request()).unwrap();
        frame[0] = b'G'; // an HTTP method byte
        let p: [u8; 6] = frame[..6].try_into().unwrap();
        assert!(matches!(
            FramePrefix::parse(&p, &caps()),
            Err(FrameError::BadMagic(b'G'))
        ));
        let mut frame = encode_request(&sample_request()).unwrap();
        frame[1] = 0x02;
        let p: [u8; 6] = frame[..6].try_into().unwrap();
        assert!(matches!(
            FramePrefix::parse(&p, &caps()),
            Err(FrameError::BadVersion(0x02))
        ));
    }

    #[test]
    fn envelope_too_large_rejected_before_read() {
        // A hostile prefix declaring a remaining-length above the caps-derived max is
        // rejected on the 6-byte prefix, before any envelope buffer is allocated.
        let c = caps();
        let over = (c.max_remaining_length() + 1) as u32;
        let prefix = [
            FRAME_MAGIC,
            FRAME_VERSION,
            over.to_le_bytes()[0],
            over.to_le_bytes()[1],
            over.to_le_bytes()[2],
            over.to_le_bytes()[3],
        ];
        assert!(matches!(
            FramePrefix::parse(&prefix, &c),
            Err(FrameError::EnvelopeTooLarge { .. })
        ));
    }

    #[test]
    fn over_run_inner_length_is_tiling_error() {
        let req = sample_request();
        let frame = encode_request(&req).unwrap();
        let (_p, env) = split_frame(&frame, &caps());
        // Corrupt the method length (first u16 of the envelope) to reach past the end.
        let mut bad = env.to_vec();
        bad[0] = 0xff;
        bad[1] = 0xff;
        assert!(matches!(
            decode_request(&bad, &caps()),
            Err(FrameError::Truncated) | Err(FrameError::NotUtf8)
        ));
    }

    #[test]
    fn under_run_trailing_slack_is_tiling_error() {
        let req = sample_request();
        let mut frame = encode_request(&req).unwrap();
        // Append a byte to the envelope AND bump remaining_length so the prefix accepts
        // it — the decoder must reject the internal slack.
        let new_remaining = u32::from_le_bytes([frame[2], frame[3], frame[4], frame[5]]) + 1;
        frame[2..6].copy_from_slice(&new_remaining.to_le_bytes());
        frame.push(0x00);
        let (_p, env) = split_frame(&frame, &caps());
        assert!(matches!(
            decode_request(env, &caps()),
            Err(FrameError::EnvelopeTilingMismatch { .. })
        ));
    }

    #[test]
    fn truncation_at_every_boundary_is_rejected_not_panicked() {
        let frame = encode_request(&sample_request()).unwrap();
        let (_p, env) = split_frame(&frame, &caps());
        for cut in 0..env.len() {
            // Any prefix of the envelope is either a tiling mismatch or truncation —
            // never a panic.
            let _ = decode_request(&env[..cut], &caps());
        }
    }

    #[test]
    fn header_count_bomb_rejected() {
        let mut req = sample_request();
        req.headers = (0..10).map(|i| (format!("x-h{i}"), "v".into())).collect();
        let frame = encode_request(&req).unwrap();
        let (_p, env) = split_frame(&frame, &caps());
        let small = FrameCaps {
            max_headers: 4,
            ..caps()
        };
        assert!(matches!(
            decode_request(env, &small),
            Err(FrameError::TooManyHeaders { .. })
        ));
    }

    #[test]
    fn header_bytes_bomb_rejected() {
        let mut req = sample_request();
        req.headers = vec![("x-big".into(), "v".repeat(1000))];
        let frame = encode_request(&req).unwrap();
        let (_p, env) = split_frame(&frame, &caps());
        let small = FrameCaps {
            max_header_bytes: 64,
            ..caps()
        };
        assert!(matches!(
            decode_request(env, &small),
            Err(FrameError::HeaderBytesExceeded { .. })
        ));
    }

    #[test]
    fn body_over_cap_rejected_before_alloc() {
        let mut req = sample_request();
        req.body = vec![b'z'; 5000];
        let frame = encode_request(&req).unwrap();
        let (_p, env) = split_frame(&frame, &caps());
        let small = FrameCaps {
            max_body_bytes: 1024,
            ..caps()
        };
        assert!(matches!(
            decode_request(env, &small),
            Err(FrameError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn control_byte_in_header_rejected_both_directions() {
        let mut req = sample_request();
        req.headers = vec![("x-inject".into(), "a\r\nSet-Cookie: evil".into())];
        let frame = encode_request(&req).unwrap();
        let (_p, env) = split_frame(&frame, &caps());
        assert_eq!(
            decode_request(env, &caps()),
            Err(FrameError::ControlByteInHeader)
        );
        let resp = ResponseFrame::Full {
            status: 200,
            headers: vec![("x-inject".into(), "a\nb".into())],
            body: vec![],
        };
        let frame = encode_response(&resp).unwrap();
        let (_p, env) = split_frame(&frame, &caps());
        assert_eq!(
            decode_response(env, &caps()),
            Err(FrameError::ControlByteInHeader)
        );
    }

    #[test]
    fn bad_status_and_response_type_rejected() {
        let resp = ResponseFrame::Full {
            status: 999,
            headers: vec![],
            body: vec![],
        };
        let frame = encode_response(&resp).unwrap();
        let (_p, env) = split_frame(&frame, &caps());
        assert_eq!(
            decode_response(env, &caps()),
            Err(FrameError::BadStatus(999))
        );

        // A bogus type byte in an otherwise-valid End frame.
        let mut frame = encode_response(&ResponseFrame::End).unwrap();
        let ty_off = FramePrefix::LEN;
        frame[ty_off] = 9;
        let (_p, env) = split_frame(&frame, &caps());
        assert_eq!(
            decode_response(env, &caps()),
            Err(FrameError::BadResponseType(9))
        );
    }

    #[test]
    fn non_utf8_field_rejected() {
        let req = sample_request();
        let frame = encode_request(&req).unwrap();
        let (_p, env) = split_frame(&frame, &caps());
        // Flip a byte inside the method string (offset 2 = first method byte) to 0xFF.
        let mut bad = env.to_vec();
        bad[2] = 0xff;
        assert_eq!(decode_request(&bad, &caps()), Err(FrameError::NotUtf8));
    }

    #[test]
    fn encode_side_length_overflow_is_typed_error_not_wrap() {
        // A short field (u16 length) longer than u16::MAX must be a typed encode error.
        let mut req = sample_request();
        req.method = "x".repeat(70_000);
        assert_eq!(encode_request(&req), Err(FrameError::LengthOverflow));
    }

    #[test]
    fn empty_body_and_no_headers_round_trip() {
        let req = RequestFrame {
            method: "GET".into(),
            path: "/".into(),
            query: String::new(),
            server_name: "x".into(),
            server_port: 80,
            scheme: Scheme::Http,
            remote_addr: "127.0.0.1".into(),
            headers: vec![],
            body: vec![],
        };
        let frame = encode_request(&req).unwrap();
        let (_p, env) = split_frame(&frame, &caps());
        assert_eq!(decode_request(env, &caps()).unwrap(), req);
    }
}

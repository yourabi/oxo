//! frame-mode worker path: the persistent binary-frame loop that replaces the
//! per-request HTTP-over-UDS connect/parse/shutdown.
//!
//! A frame client (the pooled edge) keeps ONE connection and sends many request frames
//! over it; this module reads a frame, dispatches it through the UNCHANGED `JobQueue`
//! (buffered or streaming exactly like the HTTP path), writes the response frame(s),
//! and loops until the peer closes (EOF) or a decode/IO error kills the connection.
//!
//! The HTTP one-shot path (`parser.rs`) is untouched and still serves any non-frame
//! client — the `handle_connection` sniff (peek byte 0) picks the path per connection.
//!
//! ## Scope note (panel)
//! The `without_gvl` unblock-function ("ubf") that would make the pooled Ruby worker
//! threads interruptible on `Thread#raise`/rack-timeout is DEFERRED to its own reviewed
//! segment. The persistent loop here does NOT regress shutdown: the edge always closes
//! its pooled connections first (the edge-idle-timeout-strictly-less-than-worker
//! invariant), so this loop sees EOF and exits cleanly; the Ruby-thread interrupt story
//! is identical to the pre-kill-only posture already recorded in
//! `docs/PERF_PATH.md`. A botched ubf is process-fatal (the panel's own HIGH), so it is
//! not shipped in the same pass as the frame transport.

use super::*;
use oxo_core::hop_frame::{
    self, FrameCaps, FramePrefix, RequestFrame, ResponseFrame, Scheme, FRAME_MAGIC,
};

/// Build the codec caps from the worker's configured limits, mirroring the HTTP-path
/// caps so the frame hop is neither more nor less permissive.
fn frame_caps(max_body: usize) -> FrameCaps {
    FrameCaps {
        max_header_bytes: MAX_HEADER_BYTES as u32,
        max_headers: MAX_HEADERS as u16,
        // The edge rejects `max_body_bytes > u32::MAX` in frame mode, so this fits; the
        // clamp is a belt in case a direct client configures an absurd worker cap.
        max_body_bytes: u32::try_from(max_body).unwrap_or(u32::MAX),
    }
}

/// Peek byte 0 (MSG_PEEK, non-consuming) and route: `0xBF` → the frame loop, anything
/// else → the untouched HTTP path. Returns `true` if this connection was handled as a
/// frame connection (so the caller need not run the HTTP path).
pub(super) fn try_handle_frame_connection(
    stream: &mut UnixStream,
    queue: &Arc<JobQueue>,
    max_body: usize,
    streaming: bool,
) -> std::io::Result<bool> {
    // MSG_PEEK (via libc — std's UnixStream::peek is still unstable) leaves byte 0 on
    // the socket, so an HTTP client's first byte stays put for parse_request and the
    // HTTP path is byte-identical (panel). Blocking recv: waits for ≥1 byte or EOF.
    let first = match peek_first_byte(stream)? {
        Some(b) => b,
        None => return Ok(true), // clean EOF (e.g. the supervisor's bare-connect probe)
    };
    if first != FRAME_MAGIC {
        return Ok(false); // hand back to the HTTP path
    }
    frame_loop(stream, queue, max_body, streaming);
    Ok(true)
}

/// Non-consuming peek of byte 0 via `recv(MSG_PEEK)`. `None` = clean EOF (peer closed
/// before sending anything). Blocks until ≥1 byte is available or EOF.
fn peek_first_byte(stream: &UnixStream) -> std::io::Result<Option<u8>> {
    use std::os::unix::io::AsRawFd;
    let mut byte = [0u8; 1];
    loop {
        let n = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                byte.as_mut_ptr() as *mut libc::c_void,
                1,
                libc::MSG_PEEK,
            )
        };
        if n > 0 {
            return Ok(Some(byte[0]));
        }
        if n == 0 {
            return Ok(None);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

/// The persistent frame loop. One request frame → one response exchange, repeated until
/// EOF or a fatal error. Every decode failure closes the connection (no recovery — the
/// point of explicit framing).
fn frame_loop(stream: &mut UnixStream, queue: &Arc<JobQueue>, max_body: usize, streaming: bool) {
    let caps = frame_caps(max_body);
    loop {
        let req = match read_request_frame(stream, &caps) {
            Ok(Some(req)) => req,
            Ok(None) => return, // clean EOF at a frame boundary
            Err(status) => {
                // A malformed frame gets one best-effort error response, then close —
                // there is no safe way to resynchronize a length-delimited stream.
                let _ =
                    write_full_response(stream, &WorkerResponse::text(status, error_body(status)));
                return;
            }
        };
        let worker_request = request_frame_to_worker_request(req);
        if streaming {
            let rx = dispatch_streaming_request(queue.clone(), worker_request);
            if write_streaming_frames(stream, rx).is_err() {
                return;
            }
        } else {
            let response = dispatch_buffered_request(queue.clone(), worker_request);
            if write_full_response(stream, &response).is_err() {
                return;
            }
        }
    }
}

/// Read exactly one request frame. `Ok(None)` = clean EOF before any prefix byte (the
/// peer closed at a frame boundary). `Err(status)` = a fatal protocol/cap error whose
/// HTTP-equivalent status the caller reports once before closing.
fn read_request_frame(
    stream: &mut UnixStream,
    caps: &FrameCaps,
) -> Result<Option<RequestFrame>, u16> {
    let mut prefix = [0u8; FramePrefix::LEN];
    match read_exact_or_eof(stream, &mut prefix) {
        Ok(true) => {}
        Ok(false) => return Ok(None), // EOF at a boundary — normal close
        Err(_) => return Err(400),
    }
    let parsed = FramePrefix::parse(&prefix, caps).map_err(frame_error_status)?;
    let mut envelope = vec![0u8; parsed.remaining_length as usize];
    stream.read_exact(&mut envelope).map_err(|_| 400u16)?;
    let frame = hop_frame::decode_request(&envelope, caps).map_err(frame_error_status)?;
    Ok(Some(frame))
}

/// Read exactly `buf.len()` bytes. `Ok(true)` = filled, `Ok(false)` = clean EOF with
/// ZERO bytes read (a frame boundary), `Err` = partial read / IO error.
fn read_exact_or_eof(stream: &mut UnixStream, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut read = 0;
    while read < buf.len() {
        match stream.read(&mut buf[read..]) {
            Ok(0) if read == 0 => return Ok(false),
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof mid-prefix",
                ))
            }
            Ok(n) => read += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Map a codec decode error to the HTTP status the equivalent HTTP-path rejection would
/// have used (so operator logs read consistently across hop modes).
fn frame_error_status(err: hop_frame::FrameError) -> u16 {
    use hop_frame::FrameError::*;
    match err {
        TooManyHeaders { .. } => 431,
        HeaderBytesExceeded { .. } => 431,
        BodyTooLarge { .. } | EnvelopeTooLarge { .. } => 413,
        _ => 400,
    }
}

fn error_body(status: u16) -> Vec<u8> {
    match status {
        413 => b"Payload Too Large".to_vec(),
        431 => b"Request Header Fields Too Large".to_vec(),
        _ => b"Bad Request".to_vec(),
    }
}

/// Convert a decoded request frame into the worker's `WorkerRequest`. The trusted
/// metadata (remote_addr, scheme, server name/port) arrives in dedicated frame fields;
/// the header list is app-visible headers only.
///
/// **Defense-in-depth (panel env-parity):** even though the edge already stripped
/// hop-by-hop and spoofable headers, the worker re-applies the SAME reserved-name drop
/// table as the HTTP `parse_request` path — a frame header named `x-oxo-*`,
/// `forwarded`, `x-real-ip`, `x-forwarded-*`, or `connection` can NEVER reach the Rack
/// env or override a trusted field, regardless of what the edge sent.
fn request_frame_to_worker_request(frame: RequestFrame) -> WorkerRequest {
    let mut app_headers = Vec::with_capacity(frame.headers.len());
    for (name, value) in frame.headers {
        // `name` is already lowered by the edge; re-lower defensively (a direct frame
        // client is untrusted).
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "host" => app_headers.push(("host".to_string(), value)),
            "connection" => {}
            // Centralized forwarding/real-IP denylist (single source of truth in oxo-core).
            n if is_client_forwarding_header(n) => {}
            // The frame path has NO named x-oxo consumption arms (trusted metadata arrives
            // in native RequestFrame fields), so this catch-all is the SOLE enforcer of the
            // reserved-namespace invariant: no x-oxo-* header may ever reach the Rack env.
            n if n.starts_with("x-oxo-") => {}
            _ => {
                if let Some(normalized) = normalize_header_name(&lower) {
                    app_headers.push((normalized, value));
                }
            }
        }
    }
    WorkerRequest {
        method: frame.method,
        path: frame.path,
        query: frame.query,
        server_name: frame.server_name,
        server_port: frame.server_port,
        url_scheme: match frame.scheme {
            Scheme::Http => "http".to_string(),
            Scheme::Https => "https".to_string(),
        },
        remote_addr: frame.remote_addr,
        headers: app_headers,
        body: frame.body,
    }
}

/// Write a buffered response as a single `Full` frame. Response header hygiene
/// (hop-by-hop strip, CTL rejection) is enforced by the codec's encode-side + the
/// edge's decode-side re-validation; here we drop the framing headers the frame owns.
fn write_full_response(stream: &mut UnixStream, response: &WorkerResponse) -> std::io::Result<()> {
    let headers = sanitize_response_headers(&response.headers);
    let frame = ResponseFrame::Full {
        status: response.status,
        headers,
        body: response.body.clone(),
    };
    write_frame(stream, &hop_frame::encode_response(&frame))
}

/// Stream `Head` → `Chunk`* → `End` frames from the worker events.
fn write_streaming_frames(
    stream: &mut UnixStream,
    rx: mpsc::Receiver<WorkerEvent>,
) -> std::io::Result<()> {
    let first = rx
        .recv()
        .unwrap_or_else(|_| WorkerEvent::Start(WorkerResponseHead::text(500)));
    let head = match first {
        WorkerEvent::Start(head) => head,
        WorkerEvent::Chunk(_) | WorkerEvent::End => WorkerResponseHead::text(500),
    };
    let head_frame = ResponseFrame::Head {
        status: head.status,
        headers: sanitize_response_headers(&head.headers),
    };
    write_frame(stream, &hop_frame::encode_response(&head_frame))?;
    for event in rx {
        match event {
            WorkerEvent::Start(_) => continue,
            WorkerEvent::Chunk(chunk) if chunk.is_empty() => continue,
            WorkerEvent::Chunk(chunk) => {
                write_frame(
                    stream,
                    &hop_frame::encode_response(&ResponseFrame::Chunk { data: chunk }),
                )?;
            }
            WorkerEvent::End => break,
        }
    }
    write_frame(stream, &hop_frame::encode_response(&ResponseFrame::End))
}

/// Drop the framing-owned headers (content-length / transfer-encoding / connection) and
/// any header the codec would reject anyway — the edge re-validates on decode, but a
/// well-formed frame keeps the wire clean.
fn sanitize_response_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, value)| {
            let lower = name.to_ascii_lowercase();
            // Framing headers are the host's to own — strip silently (intentional).
            if matches!(
                lower.as_str(),
                "content-length" | "transfer-encoding" | "connection"
            ) {
                return false;
            }
            // Invalid name/value (control byte, bare CR) is dropped to prevent response
            // splitting — warn so the loss is observable (a "\n" multi-value separator was
            // already split upstream in flatten_headers, so this only fires on hostile CTL).
            let valid_name = !name.is_empty() && name.bytes().all(|b| b > 0x20 && b < 0x7f);
            if !valid_name || !valid_response_header_value(value) {
                eprintln!("oxo-worker: dropping response header {name:?}: invalid name or value");
                return false;
            }
            true
        })
        .cloned()
        .collect()
}

fn write_frame(
    stream: &mut UnixStream,
    encoded: &Result<Vec<u8>, hop_frame::FrameError>,
) -> std::io::Result<()> {
    match encoded {
        Ok(bytes) => {
            stream.write_all(bytes)?;
            stream.flush()
        }
        // An un-encodable response (a header/body past the u32 domain) is a worker bug,
        // not a client input — close the connection rather than emit a torn frame.
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response frame encode failed",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxo_core::hop_frame::encode_request;

    fn caps() -> FrameCaps {
        frame_caps(1024 * 1024)
    }

    #[test]
    fn frame_converter_reapplies_reserved_name_drop_table() {
        // Even if a (hostile / buggy) frame carries spoofable identity headers, the
        // worker never lets them reach the app or override trusted fields.
        let frame = RequestFrame {
            method: "GET".into(),
            path: "/".into(),
            query: String::new(),
            server_name: "app.example".into(),
            server_port: 443,
            scheme: Scheme::Https,
            remote_addr: "203.0.113.9".into(),
            headers: vec![
                ("host".into(), "app.example".into()),
                ("x-oxo-remote-addr".into(), "10.0.0.1".into()),
                ("x-oxo-foo".into(), "injected".into()),
                ("x-forwarded-for".into(), "1.2.3.4".into()),
                ("forwarded".into(), "for=1.2.3.4".into()),
                ("x-real-ip".into(), "1.2.3.4".into()),
                ("client-ip".into(), "1.2.3.4".into()),
                ("true-client-ip".into(), "1.2.3.4".into()),
                ("cf-connecting-ip".into(), "1.2.3.4".into()),
                ("x-client-ip".into(), "1.2.3.4".into()),
                ("fastly-client-ip".into(), "1.2.3.4".into()),
                ("x-cluster-client-ip".into(), "1.2.3.4".into()),
                ("x-original-forwarded-for".into(), "1.2.3.4".into()),
                ("x-azure-clientip".into(), "1.2.3.4".into()),
                ("connection".into(), "keep-alive".into()),
                ("accept".into(), "text/html".into()),
            ],
            body: vec![],
        };
        let req = request_frame_to_worker_request(frame);
        assert_eq!(req.remote_addr, "203.0.113.9"); // native field, not spoofed
        assert!(req.headers.iter().any(|(k, _)| k == "host"));
        assert!(req.headers.iter().any(|(k, _)| k == "accept"));
        // No x-oxo-* (even an unknown one) reaches env — the catch-all is the sole
        // enforcer on the frame path (trusted metadata arrives as native fields).
        assert!(!req.headers.iter().any(|(k, _)| k.starts_with("x-oxo-")));
        assert!(!req
            .headers
            .iter()
            .any(|(k, _)| k.starts_with("x-forwarded-")));
        assert!(!req.headers.iter().any(|(k, _)| k == "forwarded"));
        assert!(!req.headers.iter().any(|(k, _)| k == "x-real-ip"));
        assert!(!req.headers.iter().any(|(k, _)| k == "connection"));
        // The whole Client-IP / CDN client-IP family is dropped on the frame path too.
        for spoof in [
            "client-ip",
            "true-client-ip",
            "cf-connecting-ip",
            "x-client-ip",
            "fastly-client-ip",
            "x-cluster-client-ip",
            "x-original-forwarded-for",
            "x-azure-clientip",
        ] {
            assert!(
                !req.headers.iter().any(|(k, _)| k == spoof),
                "{spoof} must be dropped"
            );
        }
    }

    #[test]
    fn read_request_frame_returns_none_at_clean_eof() {
        // A socketpair whose write end is closed with nothing sent = clean boundary EOF.
        let (a, mut b) = UnixStream::pair().unwrap();
        a.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(matches!(read_request_frame(&mut b, &caps()), Ok(None)));
    }

    #[test]
    fn read_request_frame_round_trips_a_real_frame() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let req = RequestFrame {
            method: "POST".into(),
            path: "/x".into(),
            query: String::new(),
            server_name: "h".into(),
            server_port: 80,
            scheme: Scheme::Http,
            remote_addr: "127.0.0.1".into(),
            headers: vec![("accept".into(), "*/*".into())],
            body: b"hi".to_vec(),
        };
        let bytes = encode_request(&req).unwrap();
        a.write_all(&bytes).unwrap();
        a.shutdown(std::net::Shutdown::Write).unwrap();
        let got = read_request_frame(&mut b, &caps()).unwrap().unwrap();
        assert_eq!(got, req);
        // Next read is a clean EOF (one frame, boundary close).
        assert!(matches!(read_request_frame(&mut b, &caps()), Ok(None)));
    }
}

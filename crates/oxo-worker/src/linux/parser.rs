use super::*;

#[derive(Debug)]
pub(super) struct ParseError {
    pub(super) status: u16,
    pub(super) message: String,
}

impl ParseError {
    fn bad(message: impl Into<String>) -> Self {
        Self {
            status: 400,
            message: message.into(),
        }
    }

    fn large(message: impl Into<String>) -> Self {
        Self {
            status: 413,
            message: message.into(),
        }
    }

    fn headers(message: impl Into<String>) -> Self {
        Self {
            status: 431,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct WorkerRequest {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) query: String,
    pub(super) server_name: String,
    pub(super) server_port: u16,
    pub(super) url_scheme: String,
    pub(super) remote_addr: String,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(super) struct WorkerResponse {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
}

impl WorkerResponse {
    pub(super) fn text(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![(
                "content-type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct WorkerResponseHead {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
}

impl WorkerResponseHead {
    pub(super) fn text(status: u16) -> Self {
        Self {
            status,
            headers: vec![(
                "content-type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
        }
    }
}

#[derive(Debug)]
pub(super) enum WorkerEvent {
    Start(WorkerResponseHead),
    Chunk(Vec<u8>),
    End,
}

pub(super) fn parse_request(
    stream: &mut UnixStream,
    max_body: usize,
) -> Result<WorkerRequest, ParseError> {
    // The worker remains a defense-in-depth HTTP boundary even when Pingora is
    // in front. Direct UDS clients still get the same strict one-shot parser.
    //
    // (panel HIGH): ONE BufReader serves BOTH the head and the body. The edge
    // sends head+body as a single coalesced write, so buffering only the head would
    // prefetch body bytes into the buffer and lose them ("short body" on every
    // body-bearing request). The byte-wise head loop below is unchanged — bare-LF
    // rejection and the incremental MAX_HEADER_BYTES cap keep their exact semantics;
    // reads just hit the buffer instead of costing one syscall per byte (the
    // profile's top worker-side syscall item). The connection is one-shot: any bytes
    // beyond the declared body were ignored before and are dropped with the buffer.
    let mut reader = std::io::BufReader::with_capacity(8 * 1024, stream);
    let head = read_head(&mut reader)?;
    let (method, target, version, headers) = parse_head(&head)?;
    if version != "HTTP/1.1" {
        return Err(ParseError::bad("only HTTP/1.1 is supported"));
    }
    if !target.starts_with('/') || target.starts_with("//") || target.contains("://") {
        return Err(ParseError::bad("only origin-form targets are supported"));
    }

    let host = headers
        .get("host")
        .ok_or_else(|| ParseError::bad("host header is required"))?
        .to_string();
    let content_length = match headers.get("content-length") {
        Some(v) => Some(parse_content_length(v)?),
        None => None,
    };
    if headers
        .get("content-type")
        .map(|v| v.to_ascii_lowercase().starts_with("application/grpc"))
        .unwrap_or(false)
    {
        return Err(ParseError::bad("gRPC is not supported by the Rack worker"));
    }
    let len = content_length.unwrap_or(0);
    if len > max_body {
        return Err(ParseError::large("payload too large"));
    }
    let mut body = vec![0u8; len];
    if len > 0 {
        // Through the SAME BufReader that read the head — the body bytes it
        // prefetched are consumed here, never discarded (panel HIGH).
        reader
            .read_exact(&mut body)
            .map_err(|_| ParseError::bad("short body"))?;
    }

    let (path, query) = split_target(&target);
    let mut server_name = parse_host_name(&host);
    let mut server_port = parse_host_port(&host).unwrap_or(80);
    let mut url_scheme = "http".to_string();
    let mut remote_addr = "127.0.0.1".to_string();
    let mut app_headers = Vec::new();

    // Reserved x-oxo-* fields are trusted hop metadata for Rack env
    // construction. They are consumed here and never forwarded as HTTP_* app
    // headers, while spoofable forwarding headers are dropped.
    for (name, value) in headers {
        match name.as_str() {
            "x-oxo-remote-addr" => remote_addr = value,
            "x-oxo-url-scheme" => {
                if value == "http" || value == "https" {
                    url_scheme = value;
                }
            }
            "x-oxo-server-name" => server_name = value,
            "x-oxo-server-port" => {
                if let Ok(port) = value.parse::<u16>() {
                    server_port = port;
                }
            }
            "host" => app_headers.push(("host".to_string(), value)),
            "connection" => {}
            // Any client header that could forge forwarding/real-IP identity is dropped via
            // the centralized oxo-core predicate (single source of truth; see its doc).
            n if is_client_forwarding_header(n) => {}
            // The x-oxo-* reserved namespace: the four trusted fields are consumed above;
            // any OTHER x-oxo-* header must still be dropped (never reach HTTP_* env), so
            // keep this dedicated catch-all AFTER the named arms.
            n if n.starts_with("x-oxo-") => {}
            _ => {
                if let Some(normalized) = normalize_header_name(&name) {
                    app_headers.push((normalized, value));
                }
            }
        }
    }

    Ok(WorkerRequest {
        method,
        path,
        query,
        server_name,
        server_port,
        url_scheme,
        remote_addr,
        headers: app_headers,
        body,
    })
}

// generic over Read so the caller's BufReader turns the historical
// one-syscall-per-byte loop into buffer hits. The LOGIC is byte-for-byte identical
// to the pre-loop: bare-LF rejection and the incremental MAX_HEADER_BYTES cap
// fire at exactly the same bytes.
fn read_head<R: Read>(stream: &mut R) -> Result<Vec<u8>, ParseError> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    let mut prev = 0u8;
    loop {
        let n = stream
            .read(&mut byte)
            .map_err(|_| ParseError::bad("read error"))?;
        if n == 0 {
            return Err(ParseError::bad("unterminated headers"));
        }
        let b = byte[0];
        if b == b'\n' && prev != b'\r' {
            return Err(ParseError::bad("bare LF in request head"));
        }
        head.push(b);
        if head.len() > MAX_HEADER_BYTES {
            return Err(ParseError::headers("headers too large"));
        }
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
        prev = b;
    }
}

fn parse_head(
    head: &[u8],
) -> Result<(String, String, String, HashMap<String, String>), ParseError> {
    let text = std::str::from_utf8(head).map_err(|_| ParseError::bad("non-utf8 request head"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| ParseError::bad("missing request line"))?;
    let parts: Vec<&str> = request_line.split(' ').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(ParseError::bad("malformed request line"));
    }
    if !valid_token(parts[0]) {
        return Err(ParseError::bad("malformed method"));
    }

    let mut headers = HashMap::new();
    let mut count = 0usize;
    for line in lines {
        if line.is_empty() {
            break;
        }
        count += 1;
        if count > MAX_HEADERS {
            return Err(ParseError::headers("too many headers"));
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(ParseError::bad("obsolete line folding"));
        }
        let Some((name, raw_value)) = line.split_once(':') else {
            return Err(ParseError::bad("malformed header"));
        };
        if name.is_empty() || name.trim_end() != name || !valid_token(name) {
            return Err(ParseError::bad("malformed header name"));
        }
        let name = name.to_ascii_lowercase();
        if headers.contains_key(&name) {
            return Err(ParseError::bad("duplicate header"));
        }
        let value = raw_value.trim_matches([' ', '\t']);
        if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(ParseError::bad("malformed header value"));
        }
        if matches!(
            name.as_str(),
            "transfer-encoding"
                | "expect"
                | "upgrade"
                | "trailer"
                | "te"
                | "keep-alive"
                | "proxy-connection"
                | "proxy-authenticate"
                | "proxy-authorization"
        ) {
            return Err(ParseError::bad(format!("{name} not allowed")));
        }
        if name == "connection"
            && value
                .split(',')
                .any(|token| !token.trim().eq_ignore_ascii_case("close"))
        {
            return Err(ParseError::bad("connection tokens are not allowed"));
        }
        headers.insert(name, value.to_string());
    }
    Ok((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
        headers,
    ))
}

pub(super) fn valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn parse_content_length(value: &str) -> Result<usize, ParseError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::bad("bad content-length"));
    }
    value
        .parse::<usize>()
        .map_err(|_| ParseError::bad("bad content-length"))
}

fn split_target(target: &str) -> (String, String) {
    match target.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (target.to_string(), String::new()),
    }
}

fn parse_host_name(host: &str) -> String {
    host.rsplit_once(':')
        .map(|(name, _)| name.to_string())
        .unwrap_or_else(|| host.to_string())
}

fn parse_host_port(host: &str) -> Option<u16> {
    host.rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    #[test]
    fn parser_rejects_transfer_encoding() {
        let mut pair =
            unix_pair_with(b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n");
        let err = parse_request(&mut pair, 1024).unwrap_err();
        assert_eq!(err.status, 400);
    }

    #[test]
    fn parser_strips_spoofable_identity_headers() {
        let mut pair = unix_pair_with(
            b"GET / HTTP/1.1\r\nHost: public.example:443\r\nX-Oxo-Remote-Addr: 203.0.113.9\r\nX-Oxo-Url-Scheme: https\r\nX-Oxo-Foo: injected\r\nX-Forwarded-For: 1.2.3.4\r\nForwarded: for=1.2.3.4\r\nX-Real-IP: 1.2.3.4\r\nClient-IP: 1.2.3.4\r\nTrue-Client-IP: 1.2.3.4\r\nCF-Connecting-IP: 1.2.3.4\r\nX-Client-IP: 1.2.3.4\r\nFastly-Client-IP: 1.2.3.4\r\nX-Cluster-Client-IP: 1.2.3.4\r\nX-Original-Forwarded-For: 1.2.3.4\r\nX-Azure-ClientIP: 1.2.3.4\r\n\r\n",
        );
        let req = parse_request(&mut pair, 1024).unwrap();
        assert_eq!(req.remote_addr, "203.0.113.9");
        assert_eq!(req.url_scheme, "https");
        assert!(!req.headers.iter().any(|(k, _)| k.contains("forwarded")));
        assert!(!req.headers.iter().any(|(k, _)| k == "x-real-ip"));
        // The whole Client-IP / CDN client-IP family must never reach the Rack env — Rails
        // ActionDispatch::RemoteIp default-trusts HTTP_CLIENT_IP, so any of these would spoof
        // request.remote_ip.
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
        // No x-oxo-* header (even an unknown one) may reach env — the four trusted fields
        // are consumed as native metadata; the catch-all drops the rest.
        assert!(!req.headers.iter().any(|(k, _)| k.starts_with("x-oxo-")));
    }

    fn unix_pair_with(bytes: &'static [u8]) -> UnixStream {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(bytes).unwrap();
        drop(a);
        b
    }

    // panel HIGH: the BufReader now serving head+body must never lose body bytes
    // it prefetched while reading the head. The edge sends head+body as ONE coalesced
    // write — the exact shape that a head-only buffer would break.
    #[test]
    fn parser_reads_head_and_body_from_single_coalesced_write() {
        let mut pair = unix_pair_with(
            b"POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world",
        );
        let req = parse_request(&mut pair, 1024).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, b"hello world");
    }

    #[test]
    fn parser_reads_body_split_across_buffer_boundary() {
        // Body deliberately larger than the 8 KiB BufReader capacity so the read_exact
        // path must combine buffered bytes with further raw reads.
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let body = vec![b'z'; 20 * 1024];
        let head = format!(
            "POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let writer = std::thread::spawn(move || {
            a.write_all(head.as_bytes()).unwrap();
            // First chunk lands with the head (prefetched into the buffer)...
            a.write_all(&body[..4096]).unwrap();
            // ...the rest arrives in later segments.
            a.write_all(&body[4096..]).unwrap();
            drop(a);
        });
        let req = parse_request(&mut b, 64 * 1024).unwrap();
        writer.join().unwrap();
        assert_eq!(req.body.len(), 20 * 1024);
        assert!(req.body.iter().all(|&c| c == b'z'));
    }

    #[test]
    fn parser_still_rejects_bare_lf_through_buffered_path() {
        let mut pair = unix_pair_with(b"GET / HTTP/1.1\nHost: x\r\n\r\n");
        let err = parse_request(&mut pair, 1024).unwrap_err();
        assert_eq!(err.status, 400);
        assert!(err.message.contains("bare LF"), "{}", err.message);
    }

    #[test]
    fn parser_still_caps_oversize_head_through_buffered_path() {
        // Build a head that exceeds MAX_HEADER_BYTES; the incremental cap must fire
        // even though bytes now arrive via the buffer.
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            let _ = a.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n");
            let filler = format!("x-fill: {}\r\n", "y".repeat(1024));
            for _ in 0..(MAX_HEADER_BYTES / 1024 + 2) {
                if a.write_all(filler.as_bytes()).is_err() {
                    return; // parser bailed and closed — expected
                }
            }
            let _ = a.write_all(b"\r\n");
        });
        let err = parse_request(&mut b, 1024).unwrap_err();
        assert_eq!(err.status, 431);
        drop(b);
        writer.join().unwrap();
    }
}

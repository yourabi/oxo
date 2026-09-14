use super::*;

pub(super) struct WorkerResponse {
    status: u16,
    header: ResponseHeader,
    body: Vec<u8>,
}

/// W-D: headers are collected INTO the request's bump arena (names, values,
/// lowercase twins, and the slice spine itself — zero heap events), then frozen to a
/// shared slice. The freeze happens before request_filter's first await, so only the
/// Sync `&'b [LoweredHeader<'b>]` crosses awaits (the Send-ness rule; `&Bump` itself
/// never does). W-B's pre-size is retained via with_capacity_in.
pub(super) fn collect_request_headers<'b>(
    session: &Session,
    bump: &'b bumpalo::Bump,
) -> Result<&'b [crate::LoweredHeader<'b>], u16> {
    let src = &session.req_header().headers;
    let mut out = bumpalo::collections::Vec::with_capacity_in(src.len(), bump);
    for (name, value) in src.iter() {
        out.push(crate::LoweredHeader::new_in(
            bump,
            name.as_str(),
            value.to_str().map_err(|_| 400u16)?,
        ));
    }
    Ok(out.into_bump_slice())
}

pub(super) fn validate_client_request(
    session: &Session,
    headers: &[crate::LoweredHeader<'_>],
    max_body_bytes: u64,
    public_server_name: Option<&str>,
) -> Result<Option<u64>, u16> {
    let req = session.req_header();
    let uri = &req.uri;
    let Some(path_and_query) = uri.path_and_query() else {
        return Err(400);
    };
    let is_http2 = req.version == Version::HTTP_2;
    let authority = uri.authority().map(|authority| authority.as_str());
    if !path_and_query.as_str().starts_with('/') {
        return Err(400);
    }
    if is_http2 {
        if let Some(scheme) = uri.scheme().map(|scheme| scheme.as_str()) {
            if !scheme.eq_ignore_ascii_case("https") {
                return Err(400);
            }
        }
        if authority.is_none() {
            return Err(400);
        }
    } else if uri.scheme().is_some() || authority.is_some() {
        return Err(400);
    }

    if req.method.as_str().eq_ignore_ascii_case("CONNECT") {
        return Err(400);
    }

    let mut host_count = 0usize;
    let mut host_value: Option<&str> = None;
    let mut header_bytes = 0usize;
    if headers.len() > MAX_REQUEST_HEADERS {
        return Err(431);
    }
    for h in headers {
        let value = h.value();
        header_bytes = accumulate_header_bytes(header_bytes, h.name(), value)?;
        let lower = h.lower();
        if lower == "host" {
            host_count += 1;
            host_value = Some(value);
        }
        if lower == "te" {
            if !(is_http2 && value.trim().eq_ignore_ascii_case("trailers")) {
                return Err(400);
            }
            continue;
        }
        if matches!(
            lower,
            "expect"
                | "trailer"
                | "transfer-encoding"
                | "http2-settings"
                | "keep-alive"
                | "proxy-connection"
        ) {
            return Err(400);
        }
        if lower == "connection" {
            for token in value.split(',') {
                // W2: compare case-insensitively without allocating a lowercase
                // String per token — same ASCII-only mapping as before.
                let token = token.trim();
                if !token.is_empty() && !token.eq_ignore_ascii_case("close") {
                    return Err(400);
                }
            }
        }
    }
    if host_count > 1 {
        return Err(400);
    }
    if is_http2 {
        if let (Some(host), Some(authority)) = (host_value, authority) {
            if !host.eq_ignore_ascii_case(authority) {
                return Err(400);
            }
        }
    } else if host_count != 1 {
        return Err(400);
    }
    if let Some(expected) = public_server_name {
        let presented = if is_http2 { authority } else { host_value }.ok_or(400u16)?;
        check_public_host(expected, presented, host_value)?;
    }

    let content_length = content_length(headers)?;
    if let Some(len) = content_length {
        if len > max_body_bytes {
            return Err(413);
        }
    }
    Ok(content_length)
}

// Shared per-header admission arithmetic for the three request validators
// (client / gRPC / Action Cable): reject invalid header names (400), then
// accumulate the running byte total (name + value + ~": " + CRLF overhead)
// and reject past MAX_REQUEST_HEADER_BYTES (431). One helper so the
// security-relevant caps cannot drift between validators. The pre-loop
// `headers.len() > MAX_REQUEST_HEADERS` count check intentionally stays
// inline at each call site: its position relative to route-specific checks
// (e.g. the gRPC authority `.ok_or(400)`) determines which status wins for
// requests that violate both, and that ordering is observable behavior.
fn accumulate_header_bytes(header_bytes: usize, name: &str, value: &str) -> Result<usize, u16> {
    if !is_valid_header_name(name.as_bytes()) {
        return Err(400);
    }
    let header_bytes = header_bytes
        .saturating_add(name.len())
        .saturating_add(value.len())
        .saturating_add(4);
    if header_bytes > MAX_REQUEST_HEADER_BYTES {
        return Err(431);
    }
    Ok(header_bytes)
}

// The public-FQDN gate (421 Misdirected Request) shared by the client and
// gRPC validators. `presented` is the route's authoritative name — each
// caller computes it under its own rules (client: `:authority` on H2, Host
// on H1, with its own 400 on absence; gRPC: the always-required
// `:authority`) — and any Host header must ALSO match, so an H2 request
// cannot smuggle a mismatched Host past the authority check.
fn check_public_host(expected: &str, presented: &str, host_value: Option<&str>) -> Result<(), u16> {
    if !host_matches_server_name(presented, expected) {
        return Err(421);
    }
    if let Some(host) = host_value {
        if !host_matches_server_name(host, expected) {
            return Err(421);
        }
    }
    Ok(())
}

fn host_matches_server_name(presented: &str, expected: &str) -> bool {
    let host = presented.trim();
    if let Some(rest) = host.strip_prefix('[') {
        if let Some((inside, _)) = rest.split_once(']') {
            return inside.eq_ignore_ascii_case(expected);
        }
    }
    let host_without_port = host.split_once(':').map(|(name, _)| name).unwrap_or(host);
    host_without_port.eq_ignore_ascii_case(expected)
}

pub(super) fn is_action_cable_upgrade_attempt(
    session: &Session,
    headers: &[crate::LoweredHeader<'_>],
) -> bool {
    session.req_header().uri.path() == "/cable"
        && headers
            .iter()
            .any(|h| h.lower() == "upgrade" && h.value().trim().eq_ignore_ascii_case("websocket"))
}

pub(super) fn is_native_grpc_request_attempt(headers: &[crate::LoweredHeader<'_>]) -> bool {
    headers
        .iter()
        .any(|h| h.lower() == "content-type" && crate::is_native_grpc_content_type(h.value()))
}

pub(super) fn validate_grpc_unary_request(
    session: &Session,
    headers: &[crate::LoweredHeader<'_>],
    max_body_bytes: u64,
    public_server_name: Option<&str>,
) -> Result<(), u16> {
    let req = session.req_header();
    if req.version != Version::HTTP_2 || req.method.as_str() != "POST" {
        return Err(400);
    }
    let uri = &req.uri;
    let Some(path_and_query) = uri.path_and_query() else {
        return Err(400);
    };
    if !path_and_query.as_str().starts_with('/') {
        return Err(400);
    }
    if let Some(scheme) = uri.scheme().map(|scheme| scheme.as_str()) {
        if !scheme.eq_ignore_ascii_case("https") {
            return Err(400);
        }
    }
    let authority = uri
        .authority()
        .map(|authority| authority.as_str())
        .ok_or(400u16)?;

    if headers.len() > MAX_REQUEST_HEADERS {
        return Err(431);
    }
    let mut header_bytes = 0usize;
    let mut host_count = 0usize;
    let mut host_value: Option<&str> = None;
    let mut content_type_count = 0usize;
    let mut saw_native_grpc = false;
    let mut saw_te_trailers = false;
    let mut grpc_timeout_count = 0usize;

    for h in headers {
        let value = h.value();
        header_bytes = accumulate_header_bytes(header_bytes, h.name(), value)?;

        match h.lower() {
            "host" => {
                host_count += 1;
                host_value = Some(value);
            }
            "content-type" => {
                content_type_count += 1;
                if crate::is_grpc_web_content_type(value) {
                    return Err(415);
                }
                saw_native_grpc = crate::is_native_grpc_content_type(value);
            }
            "te" => {
                if value.trim().eq_ignore_ascii_case("trailers") {
                    saw_te_trailers = true;
                } else {
                    return Err(400);
                }
            }
            "grpc-timeout" => {
                grpc_timeout_count += 1;
                if grpc_timeout_count > 1 || !crate::is_valid_grpc_timeout(value) {
                    return Err(400);
                }
            }
            "connection" | "upgrade" | "transfer-encoding" | "expect" | "trailer"
            | "http2-settings" | "keep-alive" | "proxy-connection" => return Err(400),
            _ => {}
        }
    }
    if host_count > 1 || content_type_count != 1 || !saw_native_grpc || !saw_te_trailers {
        return Err(400);
    }
    if let Some(host) = host_value {
        if !host.eq_ignore_ascii_case(authority) {
            return Err(400);
        }
    }
    if let Some(expected) = public_server_name {
        check_public_host(expected, authority, host_value)?;
    }
    if let Some(len) = content_length(headers)? {
        if len > max_body_bytes {
            return Err(413);
        }
    }
    Ok(())
}

pub(super) fn validate_action_cable_request(
    session: &Session,
    headers: &[crate::LoweredHeader<'_>],
    public_server_name: Option<&str>,
    url_scheme: &str,
    server_name: &str,
    server_port: u16,
) -> Result<(), u16> {
    let req = session.req_header();
    if req.version == Version::HTTP_2 {
        return Err(400);
    }
    if req.method.as_str() != "GET" || req.uri.path() != "/cable" {
        return Err(400);
    }
    if req.uri.scheme().is_some() || req.uri.authority().is_some() {
        return Err(400);
    }
    if headers.len() > MAX_REQUEST_HEADERS {
        return Err(431);
    }

    let mut header_bytes = 0usize;
    let mut host_count = 0usize;
    let mut host_value: Option<&str> = None;
    let mut connection_upgrade = false;
    let mut upgrade_websocket = false;
    let mut websocket_key = false;
    let mut websocket_version_13 = false;
    let mut action_cable_subprotocol = false;
    let mut origin_value: Option<&str> = None;

    for h in headers {
        let value = h.value();
        header_bytes = accumulate_header_bytes(header_bytes, h.name(), value)?;
        match h.lower() {
            "host" => {
                host_count += 1;
                host_value = Some(value);
            }
            "connection" => {
                connection_upgrade |= value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
            }
            "upgrade" => {
                upgrade_websocket = value.trim().eq_ignore_ascii_case("websocket");
            }
            "sec-websocket-key" => {
                websocket_key = is_valid_websocket_key(value);
            }
            "sec-websocket-version" => {
                websocket_version_13 = value.trim() == "13";
            }
            "sec-websocket-protocol" => {
                action_cable_subprotocol = value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("actioncable-v1-json"));
            }
            "origin" => {
                origin_value = Some(value);
            }
            "content-length" | "transfer-encoding" | "expect" | "trailer" | "http2-settings"
            | "keep-alive" | "proxy-connection" => return Err(400),
            _ => {}
        }
    }

    if host_count != 1 {
        return Err(400);
    }
    let host = host_value.ok_or(400u16)?;
    if let Some(expected) = public_server_name {
        if !host_matches_server_name(host, expected) {
            return Err(421);
        }
    }
    if !host_matches_server_name(host, server_name) {
        return Err(421);
    }
    if !connection_upgrade
        || !upgrade_websocket
        || !websocket_key
        || !websocket_version_13
        || !action_cable_subprotocol
    {
        return Err(400);
    }
    let Some(origin) = origin_value else {
        return Err(403);
    };
    if !origin_matches_edge(origin, url_scheme, server_name, server_port) {
        return Err(403);
    }
    Ok(())
}

fn is_valid_websocket_key(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() == 24
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

fn origin_matches_edge(
    origin: &str,
    url_scheme: &str,
    server_name: &str,
    server_port: u16,
) -> bool {
    let Some((scheme, rest)) = origin.trim().split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case(url_scheme) || rest.contains('/') {
        return false;
    }
    if !host_matches_server_name(rest, server_name) {
        return false;
    }
    match rest.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(']') => port
            .parse::<u16>()
            .map(|port| port == server_port)
            .unwrap_or(false),
        _ => matches!((url_scheme, server_port), ("http", 80) | ("https", 443)),
    }
}

pub(super) async fn read_complete_body(
    session: &mut Session,
    content_length: Option<u64>,
    max_body_bytes: u64,
) -> Result<Vec<u8>, u16> {
    if let Some(expected) = content_length {
        if expected == 0 {
            return Ok(Vec::new());
        }
        // Known length: read exactly `expected` bytes. `validate_client_request` has
        // already rejected `expected > max_body_bytes` with 413, so an over-read here
        // is a framing violation (downstream sent more than it declared) → 400.
        let expected = usize::try_from(expected).map_err(|_| 413u16)?;
        let mut body = Vec::with_capacity(expected);
        while body.len() < expected {
            match timeout(
                DOWNSTREAM_BODY_READ_TIMEOUT,
                session.downstream_session.read_body_or_idle(false),
            )
            .await
            {
                Ok(Ok(Some(chunk))) => {
                    if body.len() + chunk.len() > expected {
                        return Err(400);
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(Ok(None)) | Ok(Err(_)) => return Err(400),
                Err(_) => return Err(408),
            }
        }
        return Ok(body);
    }

    // No Content-Length. In HTTP/1.1 (Transfer-Encoding is already rejected upstream)
    // this means there is no request body, so an empty body is correct. In HTTP/2 the
    // body is delimited by END_STREAM and a body-bearing request legitimately omits
    // Content-Length — we MUST drain the DATA frames (bounded by max_body_bytes) or the
    // worker would silently see an empty body while the unread frames sit on the
    // stream. (D1: previously this returned an empty Vec unconditionally, dropping H2
    // request bodies.)
    if session.req_header().version != Version::HTTP_2 {
        return Ok(Vec::new());
    }
    let max_body = usize::try_from(max_body_bytes).unwrap_or(usize::MAX);
    // Reserve incrementally: never size the buffer from an attacker-influenced hint.
    let mut body: Vec<u8> = Vec::new();
    loop {
        // Use `read_request_body`, not `read_body_or_idle`: the latter, once the H2
        // body is done, parks in `idle()` until the client closes the connection
        // instead of returning `Ok(None)`, which would deadlock the owned hop (the
        // client is waiting for our response). `read_request_body` returns `Ok(None)`
        // at END_STREAM and releases H2 flow-control capacity per chunk.
        match timeout(
            DOWNSTREAM_BODY_READ_TIMEOUT,
            session.downstream_session.read_request_body(),
        )
        .await
        {
            Ok(Ok(Some(chunk))) => {
                if body.len().saturating_add(chunk.len()) > max_body {
                    return Err(413);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(Ok(None)) => break, // END_STREAM: the request body is complete.
            Ok(Err(_)) => return Err(400),
            Err(_) => return Err(408),
        }
    }
    Ok(body)
}

pub(super) fn build_worker_request(
    session: &Session,
    headers: Vec<(String, String)>,
    body: &[u8],
) -> Result<Vec<u8>, u16> {
    let req = session.req_header();
    let path = req
        .uri
        .path_and_query()
        .map(|path| path.as_str())
        .ok_or(400u16)?;
    let has_host = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"));
    let authority = req.uri.authority().map(|authority| authority.as_str());
    let mut request = Vec::new();
    request.extend_from_slice(req.method.as_str().as_bytes());
    request.extend_from_slice(b" ");
    request.extend_from_slice(path.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\n");
    if !has_host {
        if let Some(authority) = authority {
            append_header_line(&mut request, "Host", authority)?;
        }
    }
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        append_header_line(&mut request, &name, &value)?;
    }
    append_header_line(&mut request, "Content-Length", &body.len().to_string())?;
    append_header_line(&mut request, "Connection", "close")?;
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(body);
    Ok(request)
}

fn append_header_line(request: &mut Vec<u8>, name: &str, value: &str) -> Result<(), u16> {
    if !is_valid_header_name(name.as_bytes()) || has_invalid_header_value_bytes(value.as_bytes()) {
        return Err(400);
    }
    request.extend_from_slice(name.as_bytes());
    request.extend_from_slice(b": ");
    request.extend_from_slice(value.as_bytes());
    request.extend_from_slice(b"\r\n");
    Ok(())
}

enum WorkerSendError {
    Connect,
    AfterWrite(u16),
}

pub(super) async fn send_worker_request_to_pool(
    sockets: &[String],
    next_worker: &AtomicUsize,
    request: &[u8],
    session: &mut Session,
    long_lived: &Arc<LongLivedRegistry>,
    drain: watch::Receiver<bool>,
    // when false (default one-shot) oxo inserts `Connection: close` on the
    // downstream response exactly as before. When true (keepalive) it omits it and lets
    // pingora emit the correct Connection header from `set_keepalive`, so the connection
    // can be reused. Framing (Content-Length) is inserted regardless.
    keepalive_enabled: bool,
) -> Result<u16, u16> {
    if sockets.is_empty() {
        return Err(503);
    }
    let start = next_worker.fetch_add(1, Ordering::Relaxed) % sockets.len();
    for offset in 0..sockets.len() {
        let socket = &sockets[(start + offset) % sockets.len()];
        match send_worker_request(
            socket,
            request,
            session,
            long_lived,
            drain.clone(),
            keepalive_enabled,
        )
        .await
        {
            Ok(status) => return Ok(status),
            Err(WorkerSendError::Connect) => continue,
            Err(WorkerSendError::AfterWrite(status)) => return Err(status),
        }
    }
    Err(503)
}

async fn send_worker_request(
    socket: &str,
    request: &[u8],
    session: &mut Session,
    long_lived: &Arc<LongLivedRegistry>,
    drain: watch::Receiver<bool>,
    keepalive_enabled: bool,
) -> Result<u16, WorkerSendError> {
    // This is the first UDS acquisition point. All target, header, and body
    // validation has already succeeded. If drain begins in the small window
    // between request_filter and connect, reject before touching a worker UDS.
    // A failed connect is still pre-write, so may try another ready worker.
    // Once any write/read step starts, the request is never replayed.
    if *drain.borrow() {
        return Err(WorkerSendError::AfterWrite(503));
    }
    let mut stream = timeout(WORKER_CONNECT_TIMEOUT, UnixStream::connect(socket))
        .await
        .map_err(|_| WorkerSendError::Connect)?
        .map_err(|_| WorkerSendError::Connect)?;
    timeout(WORKER_WRITE_TIMEOUT, stream.write_all(request))
        .await
        .map_err(|_| WorkerSendError::AfterWrite(502))?
        .map_err(|_| WorkerSendError::AfterWrite(502))?;
    timeout(WORKER_WRITE_TIMEOUT, stream.shutdown())
        .await
        .map_err(|_| WorkerSendError::AfterWrite(502))?
        .map_err(|_| WorkerSendError::AfterWrite(502))?;

    read_worker_response_and_write(&mut stream, session, long_lived, drain, keepalive_enabled)
        .await
        .map_err(WorkerSendError::AfterWrite)
}

async fn read_worker_response_and_write(
    stream: &mut UnixStream,
    session: &mut Session,
    long_lived: &Arc<LongLivedRegistry>,
    drain: watch::Receiver<bool>,
    keepalive_enabled: bool,
) -> Result<u16, u16> {
    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    let header_end = loop {
        let n = read_worker_bytes_with_timeout(stream, &mut buf).await?;
        if n == 0 {
            return Err(502);
        }
        response.extend_from_slice(&buf[..n]);
        if response.len() > MAX_RESPONSE_BYTES {
            return Err(502);
        }
        match find_header_end(&response) {
            Some(header_end) if header_end > MAX_RESPONSE_HEADER_BYTES => return Err(502),
            Some(header_end) => break header_end,
            None if response.len() > MAX_RESPONSE_HEADER_BYTES => return Err(502),
            None => {}
        }
    };

    if worker_response_is_chunked(&response[..header_end])? {
        let (header, status) =
            parse_chunked_worker_response_head(&response[..header_end], keepalive_enabled)?;
        let body_start = header_end + 4;
        let initial = response.split_off(body_start);
        stream_chunked_worker_response(stream, session, header, initial, long_lived, drain).await?;
        Ok(status)
    } else {
        loop {
            let n = read_worker_bytes_with_timeout(stream, &mut buf).await?;
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buf[..n]);
            if response.len() > MAX_RESPONSE_BYTES {
                return Err(502);
            }
        }
        let worker_response = parse_worker_response(&response, keepalive_enabled)?;
        write_downstream_response(session, worker_response).await
    }
}

fn worker_response_is_chunked(head: &[u8]) -> Result<bool, u16> {
    let mut lines = head.split(|byte| *byte == b'\n');
    let _ = lines.next().ok_or(502u16)?;
    let mut chunked = false;
    for raw_line in lines {
        let line = strip_trailing_cr(raw_line);
        if line.is_empty() || line.starts_with(b" ") || line.starts_with(b"\t") {
            return Err(502);
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(502);
        };
        let name = &line[..colon];
        let value = trim_optional_whitespace(&line[colon + 1..]);
        if !is_valid_header_name(name) || has_invalid_header_value_bytes(value) {
            return Err(502);
        }
        let name_text = std::str::from_utf8(name).map_err(|_| 502u16)?;
        if name_text.eq_ignore_ascii_case("transfer-encoding") {
            let value_text = std::str::from_utf8(value).map_err(|_| 502u16)?;
            if value_text.eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else {
                return Err(502);
            }
        }
    }
    Ok(chunked)
}

fn parse_chunked_worker_response_head(
    head: &[u8],
    keepalive_enabled: bool,
) -> Result<(ResponseHeader, u16), u16> {
    let mut lines = head.split(|byte| *byte == b'\n');
    let status_line = strip_trailing_cr(lines.next().ok_or(502u16)?);
    let status = parse_status_line(status_line)?;
    let mut header = ResponseHeader::build(status, Some(8)).map_err(|_| 502u16)?;
    for raw_line in lines {
        let line = strip_trailing_cr(raw_line);
        if line.is_empty() || line.starts_with(b" ") || line.starts_with(b"\t") {
            return Err(502);
        }
        let colon = line.iter().position(|byte| *byte == b':').ok_or(502u16)?;
        let name = &line[..colon];
        let value = trim_optional_whitespace(&line[colon + 1..]);
        if !is_valid_header_name(name) || has_invalid_header_value_bytes(value) {
            return Err(502);
        }
        let name_text = std::str::from_utf8(name).map_err(|_| 502u16)?;
        if matches!(
            name_text.to_ascii_lowercase().as_str(),
            "connection" | "content-length" | "transfer-encoding"
        ) {
            continue;
        }
        let value_text = std::str::from_utf8(value).map_err(|_| 502u16)?;
        header
            .append_header(name_text.to_string(), value_text.to_string())
            .map_err(|_| 502u16)?;
    }
    // omit the explicit close under keepalive so pingora emits the correct
    // Connection header from set_keepalive; the streamed chunked body still frames
    // itself with a terminating 0-chunk, so a kept-alive connection is safe to reuse.
    if !keepalive_enabled {
        header
            .insert_header("Connection", "close")
            .map_err(|_| 502u16)?;
    }
    Ok((header, status))
}

async fn stream_chunked_worker_response(
    stream: &mut UnixStream,
    session: &mut Session,
    header: ResponseHeader,
    mut pending: Vec<u8>,
    long_lived: &Arc<LongLivedRegistry>,
    mut drain: watch::Receiver<bool>,
) -> Result<(), u16> {
    let mut admission = long_lived.try_admit().ok_or(503u16)?;
    let mut header = Some(header);
    let mut decoded = 0u64;
    loop {
        let Some(line_end) = read_until_crlf_or_drain(stream, &mut pending, &mut drain).await?
        else {
            finish_drained_chunked_response(session, &mut header, &mut admission).await?;
            return Ok(());
        };
        let size = parse_chunk_size(&pending[..line_end])?;
        pending.drain(..line_end + 2);
        if size == 0 {
            if !read_until_available_or_drain(stream, &mut pending, 2, &mut drain).await? {
                finish_drained_chunked_response(session, &mut header, &mut admission).await?;
                return Ok(());
            }
            if &pending[..2] != b"\r\n" {
                return Err(502);
            }
            if let Some(header) = header.take() {
                write_long_lived_header_with_timeout(session, header, false, &admission).await?;
            }
            write_long_lived_body_with_timeout(session, None, true, &admission).await?;
            admission.complete();
            return Ok(());
        }
        decoded = decoded.checked_add(size as u64).ok_or(502u16)?;
        if decoded > MAX_RESPONSE_BYTES as u64 || !admission.record_bytes(size as u64) {
            return Err(502);
        }
        if !read_until_available_or_drain(stream, &mut pending, size + 2, &mut drain).await? {
            finish_drained_chunked_response(session, &mut header, &mut admission).await?;
            return Ok(());
        }
        if &pending[size..size + 2] != b"\r\n" {
            return Err(502);
        }
        let chunk = pending[..size].to_vec();
        pending.drain(..size + 2);
        if let Some(header) = header.take() {
            write_long_lived_header_with_timeout(session, header, false, &admission).await?;
        }
        write_long_lived_body_with_timeout(session, Some(Bytes::from(chunk)), false, &admission)
            .await?;
    }
}

async fn finish_drained_chunked_response(
    session: &mut Session,
    header: &mut Option<ResponseHeader>,
    admission: &mut LongLivedAdmission,
) -> Result<(), u16> {
    if let Some(header) = header.take() {
        write_long_lived_header_with_timeout(session, header, false, admission).await?;
    }
    write_long_lived_body_with_timeout(session, None, true, admission).await?;
    admission.complete_drained();
    Ok(())
}

async fn read_until_crlf_or_drain(
    stream: &mut UnixStream,
    pending: &mut Vec<u8>,
    drain: &mut watch::Receiver<bool>,
) -> Result<Option<usize>, u16> {
    loop {
        if let Some(pos) = pending.windows(2).position(|window| window == b"\r\n") {
            return Ok(Some(pos));
        }
        if !read_more_worker_bytes_or_drain(stream, pending, drain).await? {
            return Ok(None);
        }
        if pending.len() > MAX_RESPONSE_HEADER_BYTES {
            return Err(502);
        }
    }
}

async fn read_until_available_or_drain(
    stream: &mut UnixStream,
    pending: &mut Vec<u8>,
    len: usize,
    drain: &mut watch::Receiver<bool>,
) -> Result<bool, u16> {
    while pending.len() < len {
        if !read_more_worker_bytes_or_drain(stream, pending, drain).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn read_more_worker_bytes_or_drain(
    stream: &mut UnixStream,
    pending: &mut Vec<u8>,
    drain: &mut watch::Receiver<bool>,
) -> Result<bool, u16> {
    let mut buf = [0u8; 8192];
    let Some(n) = read_worker_bytes_with_timeout_or_drain(stream, &mut buf, drain).await? else {
        return Ok(false);
    };
    if n == 0 {
        return Err(502);
    }
    pending.extend_from_slice(&buf[..n]);
    Ok(true)
}

async fn read_worker_bytes_with_timeout_or_drain(
    stream: &mut UnixStream,
    buf: &mut [u8],
    drain: &mut watch::Receiver<bool>,
) -> Result<Option<usize>, u16> {
    if *drain.borrow() {
        return Ok(None);
    }
    tokio::select! {
        changed = drain.changed() => {
            match changed {
                Ok(()) if *drain.borrow() => Ok(None),
                Ok(()) => read_worker_bytes_with_timeout(stream, buf).await.map(Some),
                Err(_) => read_worker_bytes_with_timeout(stream, buf).await.map(Some),
            }
        }
        read = timeout(WORKER_READ_TIMEOUT, stream.read(buf)) => {
            read.map_err(|_| 502u16)?.map(Some).map_err(|_| 502u16)
        }
    }
}

async fn read_worker_bytes_with_timeout(
    stream: &mut UnixStream,
    buf: &mut [u8],
) -> Result<usize, u16> {
    timeout(WORKER_READ_TIMEOUT, stream.read(buf))
        .await
        .map_err(|_| 502u16)?
        .map_err(|_| 502u16)
}

pub(super) enum DownstreamWriteError {
    Timeout,
    Other,
}

pub(super) async fn write_response_header_with_timeout(
    session: &mut Session,
    header: ResponseHeader,
    end: bool,
) -> Result<(), u16> {
    write_response_header_with_timeout_duration(session, header, end, DOWNSTREAM_WRITE_TIMEOUT)
        .await
        .map_err(|_| 502u16)
}

pub(super) async fn write_response_body_with_timeout(
    session: &mut Session,
    body: Option<Bytes>,
    end: bool,
) -> Result<(), u16> {
    write_response_body_with_timeout_duration(session, body, end, DOWNSTREAM_WRITE_TIMEOUT)
        .await
        .map_err(|_| 502u16)
}

pub(super) async fn write_long_lived_header_with_timeout(
    session: &mut Session,
    header: ResponseHeader,
    end: bool,
    admission: &LongLivedAdmission,
) -> Result<(), u16> {
    write_response_header_with_timeout_duration(
        session,
        header,
        end,
        admission.downstream_write_timeout(),
    )
    .await
    .map_err(|err| {
        admission.record_downstream_write_error(&err);
        502u16
    })
}

pub(super) async fn write_long_lived_body_with_timeout(
    session: &mut Session,
    body: Option<Bytes>,
    end: bool,
    admission: &LongLivedAdmission,
) -> Result<(), u16> {
    write_response_body_with_timeout_duration(
        session,
        body,
        end,
        admission.downstream_write_timeout(),
    )
    .await
    .map_err(|err| {
        admission.record_downstream_write_error(&err);
        502u16
    })
}

async fn write_response_header_with_timeout_duration(
    session: &mut Session,
    header: ResponseHeader,
    end: bool,
    duration: Duration,
) -> Result<(), DownstreamWriteError> {
    match timeout(
        duration,
        session.write_response_header(Box::new(header), end),
    )
    .await
    {
        Err(_) => Err(DownstreamWriteError::Timeout),
        Ok(Err(_)) => Err(DownstreamWriteError::Other),
        Ok(Ok(())) => Ok(()),
    }
}

async fn write_response_body_with_timeout_duration(
    session: &mut Session,
    body: Option<Bytes>,
    end: bool,
    duration: Duration,
) -> Result<(), DownstreamWriteError> {
    match timeout(duration, session.write_response_body(body, end)).await {
        Err(_) => Err(DownstreamWriteError::Timeout),
        Ok(Err(_)) => Err(DownstreamWriteError::Other),
        Ok(Ok(())) => Ok(()),
    }
}

fn parse_chunk_size(line: &[u8]) -> Result<usize, u16> {
    let text = std::str::from_utf8(line).map_err(|_| 502u16)?;
    let size = text.split(';').next().unwrap_or_default().trim();
    if size.is_empty() || !size.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(502);
    }
    usize::from_str_radix(size, 16).map_err(|_| 502u16)
}
fn parse_worker_response(bytes: &[u8], keepalive_enabled: bool) -> Result<WorkerResponse, u16> {
    let header_end = find_header_end(bytes).ok_or(502u16)?;
    if header_end > MAX_RESPONSE_HEADER_BYTES || bytes.len() > MAX_RESPONSE_BYTES {
        return Err(502);
    }
    let head = &bytes[..header_end];
    let body = bytes[header_end + 4..].to_vec();
    let mut lines = head.split(|byte| *byte == b'\n');
    let status_line = strip_trailing_cr(lines.next().ok_or(502u16)?);
    let status = parse_status_line(status_line)?;
    let mut header = ResponseHeader::build(status, Some(8)).map_err(|_| 502u16)?;
    for raw_line in lines {
        let line = strip_trailing_cr(raw_line);
        if line.is_empty() || line.starts_with(b" ") || line.starts_with(b"\t") {
            return Err(502);
        }
        let colon = line.iter().position(|byte| *byte == b':').ok_or(502u16)?;
        let name = &line[..colon];
        let value = trim_optional_whitespace(&line[colon + 1..]);
        if !is_valid_header_name(name) || has_invalid_header_value_bytes(value) {
            return Err(502);
        }
        let name_text = std::str::from_utf8(name).map_err(|_| 502u16)?;
        if matches!(
            name_text.to_ascii_lowercase().as_str(),
            "connection" | "content-length" | "transfer-encoding"
        ) {
            continue;
        }
        let value_text = std::str::from_utf8(value).map_err(|_| 502u16)?;
        header
            .append_header(name_text.to_string(), value_text.to_string())
            .map_err(|_| 502u16)?;
    }
    header
        .insert_header("Content-Length", body.len().to_string())
        .map_err(|_| 502u16)?;
    // keep the explicit close under one-shot (byte-identical to pre-); omit it
    // under keepalive and let pingora emit the Connection header from set_keepalive so
    // the Content-Length-framed response can be followed by another request.
    if !keepalive_enabled {
        header
            .insert_header("Connection", "close")
            .map_err(|_| 502u16)?;
    }
    Ok(WorkerResponse {
        status,
        header,
        body,
    })
}

async fn write_downstream_response(
    session: &mut Session,
    response: WorkerResponse,
) -> Result<u16, u16> {
    let status = response.status;
    write_response_header_with_timeout(session, response.header, false).await?;
    write_response_body_with_timeout(session, Some(Bytes::from(response.body)), true).await?;
    Ok(status)
}

fn parse_status_line(line: &[u8]) -> Result<u16, u16> {
    let text = std::str::from_utf8(line).map_err(|_| 502u16)?;
    let mut parts = text.split_whitespace();
    if parts.next() != Some("HTTP/1.1") {
        return Err(502);
    }
    let code = parts
        .next()
        .ok_or(502u16)?
        .parse::<u16>()
        .map_err(|_| 502u16)?;
    if !(100..=599).contains(&code) {
        return Err(502);
    }
    Ok(code)
}

fn content_length(headers: &[crate::LoweredHeader<'_>]) -> Result<Option<u64>, u16> {
    let mut seen = None;
    for h in headers {
        if h.lower() == "content-length" {
            if seen.is_some() {
                return Err(400);
            }
            let parsed = h.value().trim().parse::<u64>().map_err(|_| 400u16)?;
            seen = Some(parsed);
        }
    }
    Ok(seen)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn strip_trailing_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn trim_optional_whitespace(mut bytes: &[u8]) -> &[u8] {
    while matches!(bytes.first(), Some(b' ' | b'\t')) {
        bytes = &bytes[1..];
    }
    while matches!(bytes.last(), Some(b' ' | b'\t')) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn is_valid_header_name(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.iter().all(|byte| {
            let byte = *byte;
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    33 | 35 | 36 | 37 | 38 | 39 | 42 | 43 | 45 | 46 | 94 | 95 | 96 | 124 | 126
                )
        })
}

fn has_invalid_header_value_bytes(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .any(|byte| matches!(*byte, 0..=8 | 10..=31 | 127))
}

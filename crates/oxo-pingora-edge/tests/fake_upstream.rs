#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod support;
use support::{free_port, serial_test};

const RESPONSE_OK: &[u8] =
    b"HTTP/1.1 200 OK\r\nServer: fake-worker\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

#[test]
fn forwards_sanitized_request_to_recording_uds_worker() {
    let _guard = serial_test();
    let fixture = Fixture::new("sanitize");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"GET /hello?x=1 HTTP/1.1\r\n\
Host: app.test\r\n\
Accept: text/plain\r\n\
Forwarded: for=198.51.100.10\r\n\
X-Forwarded-For: 198.51.100.10\r\n\
X-Real-IP: 198.51.100.10\r\n\
X-Oxo-Remote-Addr: spoofed\r\n\
X-Request-ID: client-controlled\r\n\
Connection: close\r\n\
Proxy-Authorization: Basic secret\r\n\
\r\n",
    );

    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record one request")
        .expect("edge should connect to fake worker");
    let worker_text = String::from_utf8_lossy(&worker_request);
    assert!(String::from_utf8_lossy(&response).contains("200 OK"));
    assert!(response.ends_with(b"ok"));
    let lower = worker_text.to_ascii_lowercase();

    assert!(worker_text.starts_with("GET /hello?x=1 HTTP/1.1\r\n"));
    assert!(lower.contains("host: app.test\r\n"));
    assert!(lower.contains("accept: text/plain\r\n"));
    assert!(lower.contains("x-oxo-remote-addr: 127.0.0.1"));
    assert!(lower.contains("x-oxo-url-scheme: http\r\n"));
    assert!(lower.contains("x-oxo-server-name: localhost\r\n"));
    assert!(lower.contains(&format!("x-oxo-server-port: {port}\r\n")));
    assert!(lower.contains("connection: close\r\n"));
    assert!(lower.contains("x-oxo-request-id: oxo-"));
    assert!(!lower.contains("forwarded:"));
    assert!(!lower.contains("x-forwarded-for:"));
    assert!(!lower.contains("x-real-ip:"));
    assert!(!lower.contains("x-oxo-remote-addr: spoofed"));
    assert!(!lower.contains("x-request-id:"));
    assert!(!lower.contains("client-controlled"));
    assert!(!lower.contains("proxy-authorization:"));
}

#[test]
fn over_cap_body_returns_413_without_touching_upstream() {
    let _guard = serial_test();
    let fixture = Fixture::new("over-cap");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 5);
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"POST /upload HTTP/1.1\r\nHost: app.test\r\nContent-Length: 6\r\n\r\n123456",
    );
    assert!(String::from_utf8_lossy(&response).contains("413"));
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "body cap rejection must not acquire the worker UDS"
    );
}

#[test]
fn upgrade_request_is_rejected_without_touching_upstream() {
    let _guard = serial_test();
    let fixture = Fixture::new("upgrade");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"GET /cable HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    );
    assert!(String::from_utf8_lossy(&response).contains("400"));
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "unsupported upgrade must not acquire the worker UDS"
    );
}

#[test]
fn short_body_does_not_create_partial_worker_request() {
    let _guard = serial_test();
    let fixture = Fixture::new("short-body");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp_with_write_shutdown(
        port,
        b"POST /short HTTP/1.1\r\nHost: app.test\r\nContent-Length: 5\r\n\r\n12",
    );

    assert_client_error_or_close(&response);
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "short downstream body must not create a partial worker request"
    );
}

#[test]
fn post_body_reaches_worker_exactly_after_full_buffering() {
    let _guard = serial_test();
    let fixture = Fixture::new("post-body");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let body = b"name=codex&ok=1";
    let request = format!(
        "POST /submit HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    );
    let response = send_tcp(port, request.as_bytes());

    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record one request")
        .expect("edge should connect to fake worker");
    assert!(String::from_utf8_lossy(&response).contains("200 OK"));
    assert!(String::from_utf8_lossy(&worker_request).starts_with("POST /submit HTTP/1.1\r\n"));
    assert_eq!(worker_body(&worker_request), body);
}

#[test]
fn multipart_like_body_reaches_worker_exactly_after_full_buffering() {
    let _guard = serial_test();
    let fixture = Fixture::new("multipart-body");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 4096);
    wait_for_tcp(port);

    let body = b"--oxo\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nhello\r\n--oxo--\r\n";
    let mut request = Vec::new();
    write!(
        &mut request,
        "POST /upload HTTP/1.1\r\nHost: app.test\r\nContent-Type: multipart/form-data; boundary=oxo\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .unwrap();
    request.extend_from_slice(body);
    let response = send_tcp(port, &request);

    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record one request")
        .expect("edge should connect to fake worker");
    assert!(String::from_utf8_lossy(&response).contains("200 OK"));
    assert_eq!(worker_body(&worker_request), body);
}

#[test]
fn explicit_zero_content_length_without_body_reaches_worker() {
    let _guard = serial_test();
    let fixture = Fixture::new("zero-body-ok");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"POST /zero HTTP/1.1\r\nHost: app.test\r\nContent-Length: 0\r\n\r\n",
    );

    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record one request")
        .expect("edge should connect to fake worker");
    assert!(String::from_utf8_lossy(&response).contains("200 OK"));
    assert!(String::from_utf8_lossy(&worker_request).starts_with("POST /zero HTTP/1.1\r\n"));
    assert_eq!(worker_body(&worker_request), b"");
}

#[test]
fn content_length_zero_residue_does_not_become_second_worker_request() {
    let _guard = serial_test();
    let fixture = Fixture::new("cl0-residue");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 2);
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"POST /zero-residue HTTP/1.1\r\nHost: app.test\r\nContent-Length: 0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: app.test\r\n\r\n",
    );

    let response_text = String::from_utf8_lossy(&response);
    assert!(response_text.contains("200 OK"), "{response_text}");
    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("CL0 request should reach worker once")
        .expect("edge should connect to fake worker");
    let worker_text = String::from_utf8_lossy(&worker_request);
    assert!(
        worker_text.starts_with("POST /zero-residue HTTP/1.1\r\n"),
        "{worker_text}"
    );
    assert_eq!(worker_body(&worker_request), b"");
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "bytes after CL0 must not become a second worker request"
    );
}
#[test]
fn duplicate_content_length_is_rejected_before_worker_acquisition() {
    let _guard = serial_test();
    let fixture = Fixture::new("duplicate-cl");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"POST /dup HTTP/1.1\r\nHost: app.test\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
    );

    assert_client_error_or_close(&response);
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "duplicate Content-Length must not acquire the worker UDS"
    );
}

#[test]
fn transfer_encoding_is_rejected_before_worker_acquisition() {
    let _guard = serial_test();
    let fixture = Fixture::new("te");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"POST /chunked HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n",
    );

    assert_client_error_or_close(&response);
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "Transfer-Encoding must not acquire the worker UDS"
    );
}

#[test]
fn absolute_form_target_is_rejected_before_worker_acquisition() {
    let _guard = serial_test();
    let fixture = Fixture::new("absolute-form");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"GET http://app.test/absolute HTTP/1.1\r\nHost: app.test\r\n\r\n",
    );

    assert_client_error_or_close(&response);
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "absolute-form targets must not acquire the worker UDS"
    );
}

#[test]
fn grpc_and_sse_requests_are_stable_rejects_before_worker_acquisition() {
    let _guard = serial_test();
    for (label, request) in [
        (
            "grpc",
            b"POST /svc HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/grpc\r\n\r\n"
                .as_slice(),
        ),
        (
            "sse",
            b"GET /events HTTP/1.1\r\nHost: app.test\r\nAccept: text/event-stream\r\n\r\n"
                .as_slice(),
        ),
    ] {
        let fixture = Fixture::new(label);
        let listener = bind_worker_socket(&fixture.socket);
        let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
        let port = free_port();
        let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
        wait_for_tcp(port);

        let response = send_tcp(port, request);

        assert_client_error_or_close(&response);
        assert!(
            recorded.recv_timeout(Duration::from_millis(800)).is_err(),
            "{label} must not acquire the worker UDS"
        );
    }
}

#[test]
fn sse_opt_in_forwards_event_stream_request_to_worker() {
    let _guard = serial_test();
    let fixture = Fixture::new("sse-opt-in");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(
        listener,
        Some(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 12\r\nConnection: close\r\n\r\ndata: ready\n\n"
                .to_vec(),
        ),
    );
    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(port, &fixture.socket, 1024, &[("OXO_EDGE_SSE", "1")]);
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"GET /events HTTP/1.1\r\nHost: app.test\r\nAccept: text/event-stream\r\nLast-Event-ID: 42\r\n\r\n",
    );

    let response_text = String::from_utf8_lossy(&response);
    assert!(response_text.contains("200 OK"), "{response_text}");
    assert!(response_text.contains("data: ready"), "{response_text}");
    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("opted-in SSE should reach fake worker")
        .expect("edge should connect to fake worker");
    let worker_text = String::from_utf8_lossy(&worker_request);
    assert!(
        worker_text.starts_with("GET /events HTTP/1.1\r\n"),
        "{worker_text}"
    );
    assert!(
        worker_text
            .to_ascii_lowercase()
            .contains("accept: text/event-stream\r\n"),
        "{worker_text}"
    );
    assert!(
        worker_text
            .to_ascii_lowercase()
            .contains("last-event-id: 42\r\n"),
        "{worker_text}"
    );
}

#[test]
fn connect_and_h2c_are_rejected_before_worker_acquisition() {
    let _guard = serial_test();
    for (label, request) in [
        (
            "connect",
            b"CONNECT app.test:443 HTTP/1.1\r\nHost: app.test\r\n\r\n".as_slice(),
        ),
        (
            "h2c",
            b"GET /h2c HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n".as_slice(),
        ),
    ] {
        let fixture = Fixture::new(label);
        let listener = bind_worker_socket(&fixture.socket);
        let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
        let port = free_port();
        let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
        wait_for_tcp(port);

        let response = send_tcp(port, request);

        assert_client_error_or_close(&response);
        assert!(
            recorded.recv_timeout(Duration::from_millis(800)).is_err(),
            "{label} must not acquire the worker UDS"
        );
    }
}

#[test]
fn protocol_confusion_matrix_rejects_before_worker_acquisition() {
    let _guard = serial_test();
    for (label, request) in [
        (
            "websocket-sec-key-only",
            b"GET /cable HTTP/1.1\r\nHost: app.test\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\r\n".as_slice(),
        ),
        (
            "websocket-subprotocol-only",
            b"GET /cable HTTP/1.1\r\nHost: app.test\r\nSec-WebSocket-Protocol: actioncable-v1-json\r\n\r\n".as_slice(),
        ),
        (
            "sse-accept-parameter",
            b"GET /events HTTP/1.1\r\nHost: app.test\r\nAccept: text/html, text/event-stream; q=0.9\r\n\r\n".as_slice(),
        ),
        (
            "sse-last-event-id",
            b"GET /events HTTP/1.1\r\nHost: app.test\r\nLast-Event-ID: 42\r\n\r\n".as_slice(),
        ),
        (
            "grpc-web",
            b"POST /grpc HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: 5\r\n\r\nhello".as_slice(),
        ),
        (
            "grpc-parameter",
            b"POST /grpc HTTP/1.1\r\nHost: app.test\r\nContent-Type: Application/Grpc; charset=utf-8\r\nContent-Length: 5\r\n\r\nhello".as_slice(),
        ),
        (
            "h2-preface-on-h1-listener",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice(),
        ),
        (
            "h1-pseudo-protocol-header",
            b"GET /proto HTTP/1.1\r\nHost: app.test\r\n:protocol: websocket\r\n\r\n".as_slice(),
        ),
    ] {
        let fixture = Fixture::new(label);
        let listener = bind_worker_socket(&fixture.socket);
        let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
        let port = free_port();
        let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
        wait_for_tcp(port);

        let response = send_tcp(port, request);

        assert_client_error_or_close(&response);
        assert!(
            recorded.recv_timeout(Duration::from_millis(800)).is_err(),
            "{label} must reject before worker acquisition"
        );
    }
}

#[test]
fn app_listener_live_and_ready_paths_route_to_worker_not_admin() {
    let _guard = serial_test();
    for path in ["/live", "/ready"] {
        let fixture = Fixture::new(&format!("app-path-{}", &path[1..]));
        let listener = bind_worker_socket(&fixture.socket);
        let recorded = spawn_recording_worker(
            listener,
            Some(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\napp path".to_vec()),
        );
        let port = free_port();
        let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
        wait_for_tcp(port);

        let request = format!("GET {path} HTTP/1.1\r\nHost: app.test\r\n\r\n");
        let response = send_tcp(port, request.as_bytes());
        let response_text = String::from_utf8_lossy(&response);

        assert!(response_text.contains("app path"), "{response_text}");
        assert!(!response_text.contains("\"live\":true"), "{response_text}");
        let worker_request = recorded
            .recv_timeout(Duration::from_secs(2))
            .expect("app path must reach worker")
            .expect("edge should connect to fake worker");
        assert!(
            String::from_utf8_lossy(&worker_request)
                .starts_with(&format!("GET {path} HTTP/1.1\r\n")),
            "{}",
            String::from_utf8_lossy(&worker_request)
        );
    }
}
#[test]
fn oversized_request_headers_are_rejected_before_worker_acquisition() {
    let _guard = serial_test();
    let fixture = Fixture::new("oversized-request-header");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let mut request = b"GET /huge HTTP/1.1\r\nHost: app.test\r\nX-Huge: ".to_vec();
    request.extend(std::iter::repeat_n(b'a', 70 * 1024));
    request.extend_from_slice(b"\r\n\r\n");
    let response = send_tcp(port, &request);

    assert!(String::from_utf8_lossy(&response).contains("431"));
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "oversized request headers must not acquire the worker UDS"
    );
}

#[test]
fn legacy_public_bind_env_does_not_unlock_pingora() {
    let _guard = serial_test();
    let fixture = Fixture::new("legacy-public-bind-denied");
    let output = edge_output(
        "0.0.0.0:0",
        &fixture.socket,
        &[
            ("OXO_EDGE_MAX_BODY", "1024".to_string()),
            ("OXO_INSECURE_PUBLIC_BIND", "1".to_string()),
        ],
    );

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("non-loopback bind"));
}

#[test]
fn public_alpha_without_tls_is_rejected() {
    let _guard = serial_test();
    let fixture = Fixture::new("public-alpha-no-tls");
    let output = edge_output(
        "0.0.0.0:0",
        &fixture.socket,
        &[
            ("OXO_EDGE_MAX_BODY", "1024".to_string()),
            ("OXO_EDGE_PUBLIC_MODE", "alpha".to_string()),
            ("OXO_EDGE_PUBLIC_IDENTITY", "direct-public".to_string()),
            ("OXO_EDGE_SERVER_NAME", "app.test".to_string()),
        ],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("public mode requires TLS"), "{stderr}");
}

#[test]
fn missing_worker_socket_maps_to_503() {
    let _guard = serial_test();
    let fixture = Fixture::new("missing-worker");
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(port, b"GET /missing HTTP/1.1\r\nHost: app.test\r\n\r\n");

    assert!(String::from_utf8_lossy(&response).contains("503"));
}

#[test]
fn pool_retries_connect_failure_before_worker_write() {
    let _guard = serial_test();
    let fixture = Fixture::new("pool-connect-retry");
    let missing_socket = fixture.dir.join("missing.sock");
    let ready_socket = fixture.dir.join("ready.sock");
    let listener = bind_worker_socket(&ready_socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn_pool(port, &[&missing_socket, &ready_socket], 1024);
    wait_for_tcp(port);

    let response = send_tcp(port, b"GET /pool HTTP/1.1\r\nHost: app.test\r\n\r\n");

    assert!(String::from_utf8_lossy(&response).contains("200 OK"));
    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("ready worker should receive retried request")
        .expect("edge should connect to second worker");
    assert!(String::from_utf8_lossy(&worker_request).starts_with("GET /pool HTTP/1.1\r\n"));
}

#[test]
fn pool_does_not_replay_post_after_worker_write() {
    let _guard = serial_test();
    let fixture = Fixture::new("pool-no-post-replay");
    let bad_socket = fixture.dir.join("bad.sock");
    let good_socket = fixture.dir.join("good.sock");
    let bad_listener = bind_worker_socket(&bad_socket);
    let good_listener = bind_worker_socket(&good_socket);
    let bad_recorded = spawn_recording_worker(bad_listener, None);
    let good_recorded = spawn_recording_worker(good_listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn_pool(port, &[&bad_socket, &good_socket], 1024);
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"POST /submit HTTP/1.1\r\nHost: app.test\r\nContent-Length: 4\r\n\r\nbody",
    );

    assert!(String::from_utf8_lossy(&response).contains("502"));
    let bad_request = bad_recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("bad worker should receive the original request")
        .expect("edge should connect to bad worker");
    assert_eq!(worker_body(&bad_request), b"body");
    assert!(
        good_recorded
            .recv_timeout(Duration::from_millis(800))
            .is_err(),
        "POST must not be replayed to a second worker after the first worker write"
    );
}

#[test]
fn broken_worker_response_maps_to_502() {
    let _guard = serial_test();
    let fixture = Fixture::new("broken-worker");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, None);
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(port, b"GET /broken HTTP/1.1\r\nHost: app.test\r\n\r\n");

    assert!(String::from_utf8_lossy(&response).contains("502"));
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record the attempted request")
        .expect("edge should connect to fake worker");
}

#[test]
fn repeated_set_cookie_survives_worker_hop() {
    let _guard = serial_test();
    let fixture = Fixture::new("set-cookie");
    let listener = bind_worker_socket(&fixture.socket);
    let response = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; Path=/\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    let recorded = spawn_recording_worker(listener, Some(response.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(port, b"GET /cookies HTTP/1.1\r\nHost: app.test\r\n\r\n");
    let response_text = String::from_utf8_lossy(&response);

    assert!(response_text.contains("200 OK"));
    assert!(response_text.contains("Set-Cookie: a=1; Path=/"));
    assert!(response_text.contains("Set-Cookie: b=2; Path=/"));
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record the attempted request")
        .expect("edge should connect to fake worker");
}

#[cfg(feature = "tls-rustls")]
#[test]
fn tls_h1_and_h2_loopback_derive_https_and_canonical_worker_bytes() {
    let _guard = serial_test();
    for (label, http2, path) in [("tls-h1", false, "/tls-h1"), ("tls-h2", true, "/tls-h2")] {
        let fixture = Fixture::new(label);
        let (cert, key) = generate_tls_cert(&fixture.dir);
        let listener = bind_worker_socket(&fixture.socket);
        let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
        let port = free_port();
        let _edge = EdgeProcess::spawn_tls(port, &fixture.socket, 1024, &cert, &key);
        wait_for_tcp(port);

        let response = curl_https(port, http2, path);
        let worker_request = recorded
            .recv_timeout(Duration::from_secs(2))
            .expect("fake worker should record one TLS request")
            .expect("edge should connect to fake worker");
        let worker_text = String::from_utf8_lossy(&worker_request);
        let lower = worker_text.to_ascii_lowercase();

        assert!(
            response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/2 200"),
            "{response}"
        );
        assert!(worker_text.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
        assert!(lower.contains("host: app.test"));
        assert!(lower.contains("x-oxo-url-scheme: https\r\n"));
        assert!(lower.contains(&format!("x-oxo-server-port: {port}\r\n")));
        assert!(lower.contains("content-length: 0\r\n"));
    }
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_alpha_rejects_missing_identity_server_name_and_body_cap() {
    let _guard = serial_test();
    let fixture = Fixture::new("public-alpha-gates");
    let (cert, key) = generate_tls_cert(&fixture.dir);

    let missing_body_cap = edge_output(
        "0.0.0.0:0",
        &fixture.socket,
        &[
            ("OXO_EDGE_PUBLIC_MODE", "alpha".to_string()),
            ("OXO_EDGE_TLS", "1".to_string()),
            ("OXO_EDGE_TLS_CERT", cert.to_string_lossy().into_owned()),
            ("OXO_EDGE_TLS_KEY", key.to_string_lossy().into_owned()),
            ("OXO_EDGE_PUBLIC_IDENTITY", "direct-public".to_string()),
            ("OXO_EDGE_SERVER_NAME", "app.test".to_string()),
        ],
    );
    let stderr = String::from_utf8_lossy(&missing_body_cap.stderr);
    assert!(!missing_body_cap.status.success());
    assert!(stderr.contains("explicit request body cap"), "{stderr}");

    let missing_identity = edge_output(
        "0.0.0.0:0",
        &fixture.socket,
        &[
            ("OXO_EDGE_MAX_BODY", "1024".to_string()),
            ("OXO_EDGE_PUBLIC_MODE", "alpha".to_string()),
            ("OXO_EDGE_TLS", "1".to_string()),
            ("OXO_EDGE_TLS_CERT", cert.to_string_lossy().into_owned()),
            ("OXO_EDGE_TLS_KEY", key.to_string_lossy().into_owned()),
            ("OXO_EDGE_SERVER_NAME", "app.test".to_string()),
        ],
    );
    let stderr = String::from_utf8_lossy(&missing_identity.stderr);
    assert!(!missing_identity.status.success());
    assert!(stderr.contains("OXO_EDGE_PUBLIC_IDENTITY"), "{stderr}");

    let missing_server_name = edge_output(
        "0.0.0.0:0",
        &fixture.socket,
        &[
            ("OXO_EDGE_MAX_BODY", "1024".to_string()),
            ("OXO_EDGE_PUBLIC_MODE", "alpha".to_string()),
            ("OXO_EDGE_TLS", "1".to_string()),
            ("OXO_EDGE_TLS_CERT", cert.to_string_lossy().into_owned()),
            ("OXO_EDGE_TLS_KEY", key.to_string_lossy().into_owned()),
            ("OXO_EDGE_PUBLIC_IDENTITY", "direct-public".to_string()),
        ],
    );
    let stderr = String::from_utf8_lossy(&missing_server_name.stderr);
    assert!(!missing_server_name.status.success());
    assert!(stderr.contains("OXO_EDGE_SERVER_NAME"), "{stderr}");
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_alpha_tls_h2_serves_on_non_loopback_with_all_gates() {
    let _guard = serial_test();
    let fixture = Fixture::new("public-alpha-success");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn_public_alpha(port, &fixture.socket, 1024, &cert, &key);
    wait_for_tcp(port);

    let response = curl_https(port, true, "/public-alpha");
    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record one public-alpha request")
        .expect("edge should connect to fake worker");
    let worker_text = String::from_utf8_lossy(&worker_request);
    let lower = worker_text.to_ascii_lowercase();

    assert!(response.starts_with("HTTP/2 200"), "{response}");
    assert!(worker_text.starts_with("GET /public-alpha HTTP/1.1\r\n"));
    assert!(lower.contains("host: app.test"));
    assert!(lower.contains("x-oxo-url-scheme: https\r\n"));
    assert!(lower.contains(&format!("x-oxo-server-port: {port}\r\n")));
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_requires_private_loopback_admin_health() {
    let _guard = serial_test();
    let fixture = Fixture::new("public-smoke-beta-gates");
    let (cert, key) = generate_tls_cert(&fixture.dir);

    let missing_admin = edge_output(
        "0.0.0.0:0",
        &fixture.socket,
        &[
            ("OXO_EDGE_MAX_BODY", "1024".to_string()),
            ("OXO_EDGE_PUBLIC_MODE", "smoke-beta".to_string()),
            ("OXO_EDGE_TLS", "1".to_string()),
            ("OXO_EDGE_TLS_CERT", cert.to_string_lossy().into_owned()),
            ("OXO_EDGE_TLS_KEY", key.to_string_lossy().into_owned()),
            ("OXO_EDGE_PUBLIC_IDENTITY", "direct-public".to_string()),
            ("OXO_EDGE_SERVER_NAME", "app.test".to_string()),
            ("OXO_EDGE_MAX_IN_FLIGHT_REQUESTS", "128".to_string()),
        ],
    );
    let stderr = String::from_utf8_lossy(&missing_admin.stderr);
    assert!(!missing_admin.status.success());
    assert!(stderr.contains("OXO_EDGE_ADMIN_BIND"), "{stderr}");

    let public_admin = edge_output(
        "0.0.0.0:0",
        &fixture.socket,
        &[
            ("OXO_EDGE_MAX_BODY", "1024".to_string()),
            ("OXO_EDGE_PUBLIC_MODE", "smoke-beta".to_string()),
            ("OXO_EDGE_TLS", "1".to_string()),
            ("OXO_EDGE_TLS_CERT", cert.to_string_lossy().into_owned()),
            ("OXO_EDGE_TLS_KEY", key.to_string_lossy().into_owned()),
            ("OXO_EDGE_PUBLIC_IDENTITY", "direct-public".to_string()),
            ("OXO_EDGE_SERVER_NAME", "app.test".to_string()),
            ("OXO_EDGE_MAX_IN_FLIGHT_REQUESTS", "128".to_string()),
            ("OXO_EDGE_ADMIN_BIND", "0.0.0.0:0".to_string()),
        ],
    );
    let stderr = String::from_utf8_lossy(&public_admin.stderr);
    assert!(!public_admin.status.success());
    assert!(stderr.contains("loopback"), "{stderr}");
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_requires_global_in_flight_cap() {
    let _guard = serial_test();
    let fixture = Fixture::new("public-smoke-beta-global-cap-required");
    let (cert, key) = generate_tls_cert(&fixture.dir);

    let output = edge_output(
        "0.0.0.0:0",
        &fixture.socket,
        &[
            ("OXO_EDGE_MAX_BODY", "1024".to_string()),
            ("OXO_EDGE_PUBLIC_MODE", "smoke-beta".to_string()),
            ("OXO_EDGE_TLS", "1".to_string()),
            ("OXO_EDGE_TLS_CERT", cert.to_string_lossy().into_owned()),
            ("OXO_EDGE_TLS_KEY", key.to_string_lossy().into_owned()),
            ("OXO_EDGE_PUBLIC_IDENTITY", "direct-public".to_string()),
            ("OXO_EDGE_SERVER_NAME", "app.test".to_string()),
            ("OXO_EDGE_ADMIN_BIND", "127.0.0.1:0".to_string()),
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("OXO_EDGE_MAX_IN_FLIGHT_REQUESTS"),
        "{stderr}"
    );
    assert!(stderr.contains("explicit global request cap"), "{stderr}");
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_requires_configured_fqdn_in_certificate_san() {
    let _guard = serial_test();
    let fixture = Fixture::new("public-cert-san-mismatch");
    let (cert, key) = generate_tls_cert_for(&fixture.dir, "other.test");

    let output = edge_output(
        "0.0.0.0:0",
        &fixture.socket,
        &[
            ("OXO_EDGE_MAX_BODY", "1024".to_string()),
            ("OXO_EDGE_PUBLIC_MODE", "smoke-beta".to_string()),
            ("OXO_EDGE_TLS", "1".to_string()),
            ("OXO_EDGE_TLS_CERT", cert.to_string_lossy().into_owned()),
            ("OXO_EDGE_TLS_KEY", key.to_string_lossy().into_owned()),
            ("OXO_EDGE_PUBLIC_IDENTITY", "direct-public".to_string()),
            ("OXO_EDGE_SERVER_NAME", "app.test".to_string()),
            ("OXO_EDGE_MAX_IN_FLIGHT_REQUESTS", "128".to_string()),
            ("OXO_EDGE_ADMIN_BIND", "127.0.0.1:0".to_string()),
        ],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("subjectAltName"), "{stderr}");
    assert!(stderr.contains("app.test"), "{stderr}");
    assert!(stderr.contains("other.test"), "{stderr}");
}
#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_trusted_proxy_requires_cidrs() {
    let _guard = serial_test();
    let fixture = Fixture::new("trusted-proxy-cidrs-required");
    let (cert, key) = generate_tls_cert(&fixture.dir);

    let output = edge_output(
        "0.0.0.0:0",
        &fixture.socket,
        &[
            ("OXO_EDGE_MAX_BODY", "1024".to_string()),
            ("OXO_EDGE_PUBLIC_MODE", "smoke-beta".to_string()),
            ("OXO_EDGE_TLS", "1".to_string()),
            ("OXO_EDGE_TLS_CERT", cert.to_string_lossy().into_owned()),
            ("OXO_EDGE_TLS_KEY", key.to_string_lossy().into_owned()),
            ("OXO_EDGE_PUBLIC_IDENTITY", "trusted-proxy".to_string()),
            ("OXO_EDGE_SERVER_NAME", "app.test".to_string()),
            ("OXO_EDGE_MAX_IN_FLIGHT_REQUESTS", "128".to_string()),
            ("OXO_EDGE_ADMIN_BIND", "127.0.0.1:0".to_string()),
        ],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("OXO_EDGE_TRUSTED_PROXY_CIDRS"), "{stderr}");
}
/// (ROADMAP 1b): the TLS session-resumption POSTURE, pinned by a test instead of a guess.
///
/// Every bench cell is keepalive-ON, so handshake cost — the connection-churn regime where
/// nginx's mature ticket support lives — was never measured in either direction. And
/// pingora-core 0.8.1's rustls `TlsSettings::build` constructs the server config internally
/// with NO hook to customize resumption, so our posture is exactly rustls 0.23's default:
/// a stateful in-memory session cache backing TLS 1.3 tickets. This test asserts that that
/// default actually WORKS end to end: a client holding its session store reconnects and the
/// second handshake must be abbreviated (`HandshakeKind::Resumed`) — cheaper by one full
/// key-exchange + certificate flight. If a pingora upgrade ever silently changes the
/// posture, this fails loudly rather than regressing churn traffic in production.
///
/// The residual vs nginx — stateless tickets that survive a server RESTART — is impossible
/// without patching `TlsSettings::build` (fields private, config consumed internally) and is
/// recorded in ROADMAP 1b as a separate decision.
#[cfg(feature = "tls-rustls")]
#[test]
fn tls_session_resumption_second_handshake_is_resumed() {
    use std::io::{Read, Write};

    let _guard = serial_test();
    let fixture = Fixture::new("tls-resumption-posture");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    // Two TLS connections => two upstream dials (the fake worker closes its stream after
    // each response, so nothing is pooled) — the single-accept helper would 503 the second.
    let _recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 2);
    let port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        port,
        admin_port,
        &fixture.socket,
        1024,
        &cert,
        &key,
        &[],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);
    // Wait for WORKER readiness before the first measured handshake. Retrying the request
    // instead would break the measurement: even a 503 rides a completed TLS session whose
    // tickets the client stores, so attempt two would read Resumed for the wrong reason.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let ready = String::from_utf8_lossy(&send_tcp(
            admin_port,
            b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
        ))
        .into_owned();
        if ready.contains("\"ready\":true") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "edge never became ready: {ready}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // A no-verify client (self-signed server cert), with rustls's DEFAULT resumption store —
    // deliberately default, because the question is what a stock client gets from our server.
    #[derive(Debug)]
    struct NoVerify(rustls023::crypto::CryptoProvider);
    impl rustls023::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls023::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls023::pki_types::CertificateDer<'_>],
            _server_name: &rustls023::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls023::pki_types::UnixTime,
        ) -> Result<rustls023::client::danger::ServerCertVerified, rustls023::Error> {
            Ok(rustls023::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls023::pki_types::CertificateDer<'_>,
            _dss: &rustls023::DigitallySignedStruct,
        ) -> Result<rustls023::client::danger::HandshakeSignatureValid, rustls023::Error> {
            Ok(rustls023::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls023::pki_types::CertificateDer<'_>,
            _dss: &rustls023::DigitallySignedStruct,
        ) -> Result<rustls023::client::danger::HandshakeSignatureValid, rustls023::Error> {
            Ok(rustls023::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls023::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    let provider = rustls023::crypto::ring::default_provider();
    let config = rustls023::ClientConfig::builder_with_provider(provider.clone().into())
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    let config = std::sync::Arc::new(config);

    // One TLS connect + one HTTP round-trip. The round-trip matters beyond realism: TLS 1.3
    // session tickets arrive as POST-handshake messages, so a client that handshakes and
    // hangs up never stores a session — reading the response is what ingests the tickets.
    let connect = |cfg: std::sync::Arc<rustls023::ClientConfig>| {
        let name = rustls023::pki_types::ServerName::try_from("app.test").unwrap();
        let mut conn = rustls023::ClientConnection::new(cfg, name).expect("client conn");
        let mut tcp = std::net::TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        {
            let mut tls = rustls023::Stream::new(&mut conn, &mut tcp);
            tls.write_all(
                b"GET /public-smoke-beta HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n",
            )
            .expect("write request");
            let mut body = Vec::new();
            // Connection: close => EOF ends the read; a server skipping close_notify
            // surfaces as UnexpectedEof, which is fine — the bytes (and any tickets)
            // have been processed by then.
            match tls.read_to_end(&mut body) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
                Err(e) => panic!("tls read failed before response: {e}"),
            }
            assert!(
                body.starts_with(b"HTTP/1.1 200"),
                "expected a 200 through the edge, got: {}",
                String::from_utf8_lossy(&body[..body.len().min(80)])
            );
        }
        conn.handshake_kind()
    };

    let first = connect(std::sync::Arc::clone(&config));
    let second = connect(config);
    assert_eq!(
        first,
        Some(rustls023::HandshakeKind::Full),
        "first-contact handshake should be full"
    );
    assert_eq!(
        second,
        Some(rustls023::HandshakeKind::Resumed),
        "the second handshake must RESUME (abbreviated, no cert flight). If this fails after \
         a pingora upgrade, the server stopped sending/accepting session tickets and churn \
         traffic pays full handshakes — see ROADMAP 1b."
    );
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_tls_h2_serves_and_private_admin_reports_health() {
    let _guard = serial_test();
    let fixture = Fixture::new("public-smoke-beta-success");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let admin_port = free_port();
    // pin the thread count via env so the /ready assertion is deterministic
    // across gate machines (the default is nproc, which varies per host).
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        port,
        admin_port,
        &fixture.socket,
        1024,
        &cert,
        &key,
        &[
            ("OXO_EDGE_THREADS", "2"),
            // pin the accept fan-out too so its /ready line is asserted end to end.
            ("OXO_EDGE_LISTENER_TASKS", "4"),
        ],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let response = curl_https(port, true, "/public-smoke-beta");
    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record one public-smoke-beta request")
        .expect("edge should connect to fake worker");
    let worker_text = String::from_utf8_lossy(&worker_request);
    let lower = worker_text.to_ascii_lowercase();

    assert!(response.starts_with("HTTP/2 200"), "{response}");
    assert!(worker_text.starts_with("GET /public-smoke-beta HTTP/1.1\r\n"));
    assert!(lower.contains("host: app.test"));
    assert!(lower.contains("x-oxo-url-scheme: https\r\n"));
    assert!(lower.contains(&format!("x-oxo-server-port: {port}\r\n")));

    let ready = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(ready.starts_with("HTTP/1.1 200 OK"), "{ready}");
    assert!(ready.contains("\"ready\":true"), "{ready}");
    assert!(ready.contains("\"worker_count\":1"), "{ready}");
    assert!(ready.contains("\"edge_threads\":2"), "{ready}");
    // the accept fan-out is on /ready (never stderr-only) and really reached boot.
    assert!(ready.contains("\"listener_tasks\":4"), "{ready}");
    // the request-log posture is on /ready (never stderr-only); default rejections.
    assert!(ready.contains("\"request_log\":\"rejections\""), "{ready}");
    // the worker-hop posture is on /ready; this fake-worker test pins http (the
    // frame hop is proven end-to-end against the real worker in real_s1_e2e).
    assert!(ready.contains("\"worker_hop\":\"http\""), "{ready}");
    assert!(ready.contains("\"public_mode\":\"smoke-beta\""), "{ready}");
    assert!(ready.contains("\"operator_schema\":\"v86\""), "{ready}");
    assert!(ready.contains("\"in_flight\":0"), "{ready}");
    assert!(ready.contains("\"requests_total\":1"), "{ready}");
    assert!(ready.contains("\"responses_total\":1"), "{ready}");
    assert!(ready.contains("\"rejections_total\":0"), "{ready}");
    assert!(ready.contains("\"status_2xx_total\":1"), "{ready}");
    assert!(ready.contains("\"status_4xx_total\":0"), "{ready}");
    assert!(ready.contains("\"status_5xx_total\":0"), "{ready}");
    assert!(ready.contains("\"last_request_id\":\"oxo-"), "{ready}");
    assert!(ready.contains("\"last_response_status\":200"), "{ready}");
    assert!(ready.contains("\"last_rejection_status\":null"), "{ready}");
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_h2_without_content_length_forwards_body_to_worker() {
    // D1: an HTTP/2 request legitimately frames its body with END_STREAM and omits
    // Content-Length. The edge previously returned an empty body in that case, dropping
    // the request body and never draining the DATA frames. Send a POST with no
    // content-length header plus a DATA frame and assert the fake worker receives the body
    // with a synthesized Content-Length.
    let _guard = serial_test();
    let fixture = Fixture::new("public-h2-no-cl-body");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let admin_port = free_port();
    let _edge =
        EdgeProcess::spawn_public_smoke_beta(port, admin_port, &fixture.socket, 1024, &cert, &key);
    wait_for_tcp(port);

    // `curl -T -` uploads from stdin. Because the length of a pipe is unknown, curl cannot
    // set Content-Length, so over HTTP/2 it sends the body as DATA frames terminated by
    // END_STREAM with no content-length header — exactly the case D1 fixes.
    let output = curl_h2_upload_stdin(port, "app.test", "/h2-upload", b"h2-body-drain");
    assert!(
        output.status.success(),
        "curl h2 upload failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let worker_request = recorded
        .recv_timeout(Duration::from_secs(3))
        .expect("edge must forward the H2 no-Content-Length request to the worker")
        .expect("edge should connect to fake worker");
    let worker_text = String::from_utf8_lossy(&worker_request);
    let lower = worker_text.to_ascii_lowercase();
    assert!(
        worker_text.starts_with("PUT /h2-upload HTTP/1.1\r\n"),
        "{worker_text}"
    );
    assert!(lower.contains("content-length: 13\r\n"), "{worker_text}");
    assert!(worker_text.ends_with("h2-body-drain"), "{worker_text}");
}

#[cfg(feature = "tls-rustls")]
fn curl_h2_upload_stdin(port: u16, host: &str, path: &str, body: &[u8]) -> std::process::Output {
    use std::io::Write;
    let url = format!("https://{host}:{port}{path}");
    let resolve = format!("{host}:{port}:127.0.0.1");
    let mut child = Command::new("curl")
        .arg("--silent")
        .arg("--show-error")
        .arg("--insecure")
        .arg("--noproxy")
        .arg("*")
        .arg("--max-time")
        .arg("5")
        .arg("--http2")
        .arg("--resolve")
        .arg(&resolve)
        .arg("-T")
        .arg("-")
        .arg(&url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn curl h2 upload");
    child
        .stdin
        .take()
        .expect("curl stdin")
        .write_all(body)
        .expect("write upload body to curl");
    child.wait_with_output().expect("curl h2 upload output")
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_rejects_sse_before_worker_when_gate_is_off() {
    let _guard = serial_test();
    let fixture = Fixture::new("public-sse-gate-off");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let admin_port = free_port();
    let _edge =
        EdgeProcess::spawn_public_smoke_beta(port, admin_port, &fixture.socket, 1024, &cert, &key);
    wait_for_tcp(port);

    let response = curl_https_with_args(
        port,
        false,
        "app.test",
        "/events",
        &[
            "--header".to_string(),
            "Accept: text/event-stream".to_string(),
        ],
        false,
    );

    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "public SSE without the gate must not acquire the worker UDS"
    );
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_sse_forwards_event_stream_and_reports_long_lived_accounting() {
    let _guard = serial_test();
    let fixture = Fixture::new("public-sse-accounting");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_chunked_streaming_worker_many_with_content_type(
        listener,
        "text/event-stream",
        vec![b"data: one\n\n".to_vec(), b"data: two\n\n".to_vec()],
        Duration::ZERO,
        Duration::ZERO,
        1,
    );
    let port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        port,
        admin_port,
        &fixture.socket,
        1024,
        &cert,
        &key,
        &[
            ("OXO_EDGE_SSE", "1"),
            ("OXO_EDGE_LONG_LIVED_MAX_CONNECTIONS", "1"),
        ],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let response = curl_https_with_args(
        port,
        false,
        "app.test",
        "/events",
        &[
            "--header".to_string(),
            "Accept: text/event-stream".to_string(),
            "--header".to_string(),
            "Last-Event-ID: 43".to_string(),
            "--header".to_string(),
            "X-Forwarded-For: 198.51.100.10".to_string(),
        ],
        true,
    );

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("content-type: text/event-stream"),
        "{response}"
    );
    assert!(response.contains("data: one\n\n"), "{response}");
    assert!(response.contains("data: two\n\n"), "{response}");
    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("public SSE request should reach fake worker")
        .expect("edge should connect to fake worker");
    let lower = String::from_utf8_lossy(&worker_request).to_ascii_lowercase();
    assert!(lower.starts_with("get /events http/1.1\r\n"), "{lower}");
    assert!(lower.contains("host: app.test:"), "{lower}");
    assert!(lower.contains("accept: text/event-stream\r\n"), "{lower}");
    assert!(lower.contains("last-event-id: 43\r\n"), "{lower}");
    assert!(lower.contains("x-oxo-url-scheme: https\r\n"), "{lower}");
    assert!(!lower.contains("x-forwarded-for"), "{lower}");

    let ready = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(ready.contains("\"public_mode\":\"smoke-beta\""), "{ready}");
    assert!(ready.contains("\"long_lived_active\":0"), "{ready}");
    assert!(ready.contains("\"long_lived_accepted_total\":1"), "{ready}");
    assert!(
        ready.contains("\"long_lived_completed_total\":1"),
        "{ready}"
    );
    assert!(
        ready.contains("\"long_lived_cancelled_total\":0"),
        "{ready}"
    );
    assert!(
        ready.contains("\"long_lived_bytes_streamed_total\":22"),
        "{ready}"
    );
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_sse_memory_envelope_cancels_over_cap_stream() {
    let _guard = serial_test();
    let fixture = Fixture::new("public-sse-memory-cap");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_chunked_streaming_worker_many_with_content_type(
        listener,
        "text/event-stream",
        vec![b"four".to_vec()],
        Duration::ZERO,
        Duration::ZERO,
        1,
    );
    let port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        port,
        admin_port,
        &fixture.socket,
        1024,
        &cert,
        &key,
        &[
            ("OXO_EDGE_SSE", "1"),
            ("OXO_EDGE_LONG_LIVED_MAX_BUFFERED_BYTES", "3"),
        ],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let response = curl_https_with_args(
        port,
        false,
        "app.test",
        "/events",
        &[
            "--header".to_string(),
            "Accept: text/event-stream".to_string(),
        ],
        false,
    );

    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("over-cap public SSE request should reach fake worker")
        .expect("edge should connect to fake worker");
    let ready = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(ready.contains("\"long_lived_active\":0"), "{ready}");
    assert!(ready.contains("\"long_lived_accepted_total\":1"), "{ready}");
    assert!(
        ready.contains("\"long_lived_completed_total\":0"),
        "{ready}"
    );
    assert!(
        ready.contains("\"long_lived_cancelled_total\":1"),
        "{ready}"
    );
    assert!(
        ready.contains("\"long_lived_bytes_streamed_total\":4"),
        "{ready}"
    );
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_sse_downstream_disconnect_cancels_long_lived_admission() {
    let _guard = serial_test();
    let fixture = Fixture::new("public-sse-disconnect");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    // Keep the chunked stream intentionally unterminated so the client kill below
    // cannot race a valid zero-chunk completion.
    let response =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\ndata\r\n";
    let recorded = spawn_recording_worker_many_with_delay(
        listener,
        response.to_vec(),
        1,
        Duration::from_millis(700),
    );
    let port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        port,
        admin_port,
        &fixture.socket,
        1024,
        &cert,
        &key,
        &[("OXO_EDGE_SSE", "1")],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let (mut client, stdin) = tls_h1_start_request(
        port,
        b"GET /events HTTP/1.1\r\nHost: app.test\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
    );

    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("disconnect public SSE request should reach fake worker")
        .expect("edge should connect to fake worker");
    drop(stdin);
    let _ = client.kill();
    let _ = client.wait();

    let ready = wait_until_admin_contains(admin_port, "\"long_lived_cancelled_total\":1");
    assert!(ready.contains("\"long_lived_active\":0"), "{ready}");
    assert!(ready.contains("\"long_lived_accepted_total\":1"), "{ready}");
    assert!(
        ready.contains("\"long_lived_completed_total\":0"),
        "{ready}"
    );
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_direct_public_strips_spoofed_forwarding_before_worker() {
    let _guard = serial_test();
    let fixture = Fixture::new("direct-public-spoof-strip");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let admin_port = free_port();
    let _edge =
        EdgeProcess::spawn_public_smoke_beta(port, admin_port, &fixture.socket, 1024, &cert, &key);
    wait_for_tcp(port);

    let response = curl_https_with_args(
        port,
        false,
        "app.test",
        "/direct-public-spoof",
        &[
            "--header".to_string(),
            "X-Forwarded-For: 198.51.100.42".to_string(),
            "--header".to_string(),
            "Forwarded: for=198.51.100.42".to_string(),
            "--header".to_string(),
            "X-Real-IP: 198.51.100.42".to_string(),
            // The Client-IP / CDN client-IP family: Rails RemoteIp default-trusts CLIENT_IP.
            "--header".to_string(),
            "Client-IP: 198.51.100.42".to_string(),
            "--header".to_string(),
            "CF-Connecting-IP: 198.51.100.42".to_string(),
            "--header".to_string(),
            "True-Client-IP: 198.51.100.42".to_string(),
            "--header".to_string(),
            "X-Cluster-Client-IP: 198.51.100.42".to_string(),
        ],
        true,
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record one direct-public request")
        .expect("edge should connect to fake worker");
    let lower = String::from_utf8_lossy(&worker_request).to_ascii_lowercase();
    assert!(
        lower.contains("x-oxo-remote-addr: 127.0.0.1\r\n"),
        "{lower}"
    );
    assert!(!lower.contains("x-forwarded-for"), "{lower}");
    assert!(!lower.contains("forwarded:"), "{lower}");
    assert!(!lower.contains("x-real-ip"), "{lower}");
    // The Client-IP / CDN client-IP family never reaches the worker (would spoof remote_ip).
    for spoof in [
        "client-ip",
        "cf-connecting-ip",
        "true-client-ip",
        "x-cluster-client-ip",
    ] {
        assert!(!lower.contains(spoof), "{spoof} leaked to worker: {lower}");
    }
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_trusted_proxy_uses_x_forwarded_for_client_ip() {
    let _guard = serial_test();
    let fixture = Fixture::new("trusted-proxy-success");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        port,
        admin_port,
        &fixture.socket,
        1024,
        &cert,
        &key,
        &[
            ("OXO_EDGE_PUBLIC_IDENTITY", "trusted-proxy"),
            ("OXO_EDGE_TRUSTED_PROXY_CIDRS", "127.0.0.1/32"),
        ],
    );
    wait_for_tcp(port);

    let response = curl_https_with_args(
        port,
        false,
        "app.test",
        "/trusted-proxy",
        &[
            "--header".to_string(),
            "X-Forwarded-For: 198.51.100.42, 127.0.0.1".to_string(),
        ],
        true,
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record one trusted-proxy request")
        .expect("edge should connect to fake worker");
    let lower = String::from_utf8_lossy(&worker_request).to_ascii_lowercase();
    assert!(
        lower.contains("x-oxo-remote-addr: 198.51.100.42\r\n"),
        "{lower}"
    );
    assert!(!lower.contains("x-forwarded-for"), "{lower}");
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_fairness_limits_same_resolved_identity_and_reports_private_metrics() {
    let _guard = serial_test();
    let fixture = Fixture::new("trusted-proxy-fairness");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker_many_with_delay(
        listener,
        RESPONSE_OK.to_vec(),
        2,
        Duration::from_millis(800),
    );
    let port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        port,
        admin_port,
        &fixture.socket,
        1024,
        &cert,
        &key,
        &[
            ("OXO_EDGE_PUBLIC_IDENTITY", "trusted-proxy"),
            ("OXO_EDGE_TRUSTED_PROXY_CIDRS", "127.0.0.1/32"),
            ("OXO_EDGE_MAX_IN_FLIGHT_PER_IDENTITY", "1"),
        ],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let first_args = vec![
        "--header".to_string(),
        "X-Forwarded-For: 198.51.100.42, 127.0.0.1".to_string(),
    ];
    let first = thread::spawn(move || {
        curl_https_with_args(port, false, "app.test", "/fairness-one", &first_args, true)
    });
    let first_worker = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("first fairness request should reach worker")
        .expect("edge should connect to fake worker");
    let first_worker_text = String::from_utf8_lossy(&first_worker).to_ascii_lowercase();
    assert!(
        first_worker_text.contains("x-oxo-remote-addr: 198.51.100.42\r\n"),
        "{first_worker_text}"
    );

    let second_args = vec![
        "--header".to_string(),
        "X-Forwarded-For: 198.51.100.42, 127.0.0.1".to_string(),
    ];
    let second = curl_https_with_args(
        port,
        false,
        "app.test",
        "/fairness-same-identity",
        &second_args,
        false,
    );
    assert!(second.starts_with("HTTP/1.1 503"), "{second}");
    assert!(
        recorded.recv_timeout(Duration::from_millis(300)).is_err(),
        "same-identity saturation must reject before worker acquisition"
    );

    let third_args = vec![
        "--header".to_string(),
        "X-Forwarded-For: 198.51.100.77, 127.0.0.1".to_string(),
    ];
    let third = curl_https_with_args(
        port,
        false,
        "app.test",
        "/fairness-other-identity",
        &third_args,
        true,
    );
    assert!(third.starts_with("HTTP/1.1 200"), "{third}");
    let first_response = first.join().expect("first curl thread joins");
    assert!(
        first_response.starts_with("HTTP/1.1 200"),
        "{first_response}"
    );
    let third_worker = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("different identity should reach worker")
        .expect("edge should connect to fake worker");
    let third_worker_text = String::from_utf8_lossy(&third_worker).to_ascii_lowercase();
    assert!(
        third_worker_text.contains("x-oxo-remote-addr: 198.51.100.77\r\n"),
        "{third_worker_text}"
    );

    let ready = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(ready.contains("\"operator_schema\":\"v86\""), "{ready}");
    assert!(ready.contains("\"requests_total\":3"), "{ready}");
    assert!(ready.contains("\"responses_total\":2"), "{ready}");
    assert!(ready.contains("\"rejections_total\":1"), "{ready}");
    assert!(ready.contains("\"rate_limited_total\":1"), "{ready}");
    assert!(ready.contains("\"last_rejection_status\":503"), "{ready}");
    assert!(ready.contains("\"fairness_enabled\":true"), "{ready}");
    assert!(
        ready.contains("\"fairness_max_in_flight_per_identity\":1"),
        "{ready}"
    );
    assert!(ready.contains("\"fairness_in_flight\":0"), "{ready}");
    assert!(
        ready.contains("\"fairness_tracked_identities\":0"),
        "{ready}"
    );
    assert!(ready.contains("\"fairness_admitted_total\":2"), "{ready}");
    assert!(ready.contains("\"fairness_saturation_total\":1"), "{ready}");
    assert!(!ready.contains("198.51.100"), "{ready}");

    let metrics = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /metrics HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(metrics.starts_with("HTTP/1.1 200 OK"), "{metrics}");
    assert!(metrics.contains("Content-Type: text/plain"), "{metrics}");
    assert!(
        metrics.contains("oxo_edge_rate_limited_total 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("oxo_edge_fairness_saturation_total 1"),
        "{metrics}"
    );
    assert!(!metrics.contains("198.51.100"), "{metrics}");
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_global_in_flight_cap_overloads_before_identity_resolution() {
    let _guard = serial_test();
    let fixture = Fixture::new("global-in-flight-overload");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker_many_with_delay(
        listener,
        RESPONSE_OK.to_vec(),
        1,
        Duration::from_millis(800),
    );
    let port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        port,
        admin_port,
        &fixture.socket,
        1024,
        &cert,
        &key,
        &[("OXO_EDGE_MAX_IN_FLIGHT_REQUESTS", "1")],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let first = thread::spawn(move || {
        curl_https_with_args(port, false, "app.test", "/global-first", &[], true)
    });
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("first global-cap request should reach worker")
        .expect("edge should connect to fake worker");

    let second = curl_https_with_args(port, false, "app.test", "/global-second", &[], false);
    assert!(second.starts_with("HTTP/1.1 503"), "{second}");
    assert!(
        recorded.recv_timeout(Duration::from_millis(300)).is_err(),
        "global overload must reject before worker acquisition"
    );

    let first_response = first.join().expect("first curl thread joins");
    assert!(
        first_response.starts_with("HTTP/1.1 200"),
        "{first_response}"
    );

    let ready = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(ready.contains("\"operator_schema\":\"v86\""), "{ready}");
    assert!(ready.contains("\"requests_total\":2"), "{ready}");
    assert!(ready.contains("\"responses_total\":1"), "{ready}");
    assert!(ready.contains("\"rejections_total\":1"), "{ready}");
    assert!(ready.contains("\"rate_limited_total\":0"), "{ready}");
    assert!(ready.contains("\"overload_total\":1"), "{ready}");
    assert!(
        ready.contains("\"global_in_flight_enabled\":true"),
        "{ready}"
    );
    assert!(
        ready.contains("\"global_in_flight_max_requests\":1"),
        "{ready}"
    );
    assert!(ready.contains("\"global_in_flight_active\":0"), "{ready}");
    assert!(
        ready.contains("\"global_in_flight_admitted_total\":1"),
        "{ready}"
    );
    assert!(
        ready.contains("\"global_in_flight_max_active_observed\":1"),
        "{ready}"
    );
    assert!(
        ready.contains("\"slow_client_header_read_timeout_ms\":15000"),
        "{ready}"
    );
    // honesty annotations: the header-read timeout and max-connection-secs are
    // framework-unreachable (always not-enforced); the keepalive idle timeout is not
    // enforced here because keepalive reuse is off in this cell (one-shot).
    assert!(
        ready.contains("\"slow_client_header_read_timeout_enforced\":false"),
        "{ready}"
    );
    assert!(
        ready.contains("\"slow_client_keepalive_idle_timeout_enforced\":false"),
        "{ready}"
    );
    assert!(
        ready.contains("\"slow_client_max_connection_secs_enforced\":false"),
        "{ready}"
    );
    assert!(
        ready.contains("\"slow_client_pingora_tls_handshake_timeout_secs\":60"),
        "{ready}"
    );
    // posture fields: the serve-rails preset is not used in this cell.
    assert!(ready.contains("\"serve_rails_active\":false"), "{ready}");
    assert!(ready.contains("\"serve_rails_static\":\"off\""), "{ready}");

    let metrics = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /metrics HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(metrics.contains("oxo_edge_overload_total 1"), "{metrics}");
    assert!(
        metrics.contains("oxo_edge_global_in_flight_admitted_total 1"),
        "{metrics}"
    );
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_trusted_proxy_rejects_malformed_identity_before_worker() {
    let _guard = serial_test();
    for (label, extra_args, expected_status) in [
        (
            "trusted-proxy-missing-xff",
            Vec::<String>::new(),
            "HTTP/1.1 400",
        ),
        (
            "trusted-proxy-port-xff",
            vec![
                "--header".to_string(),
                "X-Forwarded-For: 198.51.100.42:1234".to_string(),
            ],
            "HTTP/1.1 400",
        ),
        (
            "trusted-proxy-forwarded-ambiguous",
            vec![
                "--header".to_string(),
                "X-Forwarded-For: 198.51.100.42".to_string(),
                "--header".to_string(),
                "Forwarded: for=198.51.100.42".to_string(),
            ],
            "HTTP/1.1 400",
        ),
        (
            "trusted-proxy-all-trusted-chain",
            vec![
                "--header".to_string(),
                "X-Forwarded-For: 127.0.0.1".to_string(),
            ],
            "HTTP/1.1 400",
        ),
    ] {
        let fixture = Fixture::new(label);
        let (cert, key) = generate_tls_cert(&fixture.dir);
        let listener = bind_worker_socket(&fixture.socket);
        let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
        let port = free_port();
        let admin_port = free_port();
        let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
            port,
            admin_port,
            &fixture.socket,
            1024,
            &cert,
            &key,
            &[
                ("OXO_EDGE_PUBLIC_IDENTITY", "trusted-proxy"),
                ("OXO_EDGE_TRUSTED_PROXY_CIDRS", "127.0.0.1/32"),
            ],
        );
        wait_for_tcp(port);

        let response = curl_https_with_args(
            port,
            false,
            "app.test",
            "/trusted-proxy-reject",
            &extra_args,
            false,
        );
        assert!(response.starts_with(expected_status), "{label}: {response}");
        assert!(
            recorded.recv_timeout(Duration::from_millis(800)).is_err(),
            "{label} must reject before worker acquisition"
        );
    }
}
#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_rejects_public_host_confusion_before_worker() {
    let _guard = serial_test();
    for (label, http2, host, path, extra_args, expected_status) in [
        (
            "public-h1-host-mismatch",
            false,
            "app.test",
            "/h1-host-mismatch",
            vec!["--header".to_string(), "Host: evil.test".to_string()],
            "HTTP/1.1 421",
        ),
        (
            "public-h2-authority-mismatch",
            true,
            "evil.test",
            "/h2-authority-mismatch",
            Vec::new(),
            "HTTP/2 421",
        ),
    ] {
        let fixture = Fixture::new(label);
        let (cert, key) = generate_tls_cert(&fixture.dir);
        let listener = bind_worker_socket(&fixture.socket);
        let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
        let port = free_port();
        let admin_port = free_port();
        let _edge = EdgeProcess::spawn_public_smoke_beta(
            port,
            admin_port,
            &fixture.socket,
            1024,
            &cert,
            &key,
        );
        wait_for_tcp(port);

        let response = curl_https_with_args(port, http2, host, path, &extra_args, false);

        assert!(response.starts_with(expected_status), "{response}");
        assert!(
            recorded.recv_timeout(Duration::from_millis(800)).is_err(),
            "{label} must reject before worker acquisition"
        );
    }
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_rejects_h2_abuse_before_worker() {
    let _guard = serial_test();
    let large_header = format!("X-Fill: {}", "a".repeat(70 * 1024));
    for (label, max_body, path, extra_args, expected_status) in [
        (
            "public-h2-grpc",
            1024,
            "/h2-grpc",
            vec![
                "--header".to_string(),
                "Content-Type: application/grpc".to_string(),
            ],
            "HTTP/2 415",
        ),
        (
            "public-h2-large-header",
            1024,
            "/h2-large-header",
            vec!["--header".to_string(), large_header.clone()],
            "curl-error:",
        ),
        (
            "public-h2-overcap-body",
            4,
            "/h2-overcap-body",
            vec![
                "--request".to_string(),
                "POST".to_string(),
                "--header".to_string(),
                "Content-Length: 5".to_string(),
            ],
            "curl-error:",
        ),
    ] {
        let fixture = Fixture::new(label);
        let (cert, key) = generate_tls_cert(&fixture.dir);
        let listener = bind_worker_socket(&fixture.socket);
        let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
        let port = free_port();
        let admin_port = free_port();
        let _edge = EdgeProcess::spawn_public_smoke_beta(
            port,
            admin_port,
            &fixture.socket,
            max_body,
            &cert,
            &key,
        );
        wait_for_tcp(port);

        let response = curl_https_with_args(port, true, "app.test", path, &extra_args, false);

        assert!(response.starts_with(expected_status), "{label}: {response}");
        assert!(
            recorded.recv_timeout(Duration::from_millis(800)).is_err(),
            "{label} must reject before worker acquisition"
        );
    }
}

#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_raw_h2_abuse_frames_do_not_acquire_worker() {
    let _guard = serial_test();
    for (label, frames) in [
        ("raw-h2-rapid-reset", h2_rapid_reset_frames()),
        ("raw-h2-continuation-flood", h2_continuation_flood_frames()),
        ("raw-h2-flow-control", h2_zero_window_update_frames()),
    ] {
        let fixture = Fixture::new(label);
        let (cert, key) = generate_tls_cert(&fixture.dir);
        let listener = bind_worker_socket(&fixture.socket);
        let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
        let port = free_port();
        let admin_port = free_port();
        let _edge = EdgeProcess::spawn_public_smoke_beta(
            port,
            admin_port,
            &fixture.socket,
            1024,
            &cert,
            &key,
        );
        wait_for_tcp(port);

        send_raw_h2_tls_frames(port, &frames);

        assert!(
            recorded.recv_timeout(Duration::from_millis(800)).is_err(),
            "{label} must not acquire the worker UDS"
        );
    }
}

// the sidecar (gRPC) fairness arm — a same-identity gRPC request under a
// saturated per-identity cap must return 503 counted as RATE LIMITED, and must
// fire BEFORE the long-lived gate or any sidecar connection. Guards the shared
// `admit()` pipeline against a swapped counter or reordered checks, which the
// rest of the suite (worker fairness-503, sidecar long-lived-503) cannot see.
#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_grpc_fairness_saturation_counts_rate_limited_before_long_lived() {
    let _guard = serial_test();
    let fixture = Fixture::new("grpc-fairness-rate-limited");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker_many_with_delay(
        listener,
        RESPONSE_OK.to_vec(),
        1,
        Duration::from_millis(800),
    );
    // Dummy gRPC sidecar bind: the fairness rejection must happen before
    // upstream_peer, so this listener must never see a connection.
    let grpc_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let grpc_bind = grpc_listener.local_addr().unwrap().to_string();
    let port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        port,
        admin_port,
        &fixture.socket,
        1024,
        &cert,
        &key,
        &[
            ("OXO_EDGE_PUBLIC_IDENTITY", "trusted-proxy"),
            ("OXO_EDGE_TRUSTED_PROXY_CIDRS", "127.0.0.1/32"),
            ("OXO_EDGE_MAX_IN_FLIGHT_PER_IDENTITY", "1"),
            ("OXO_EDGE_GRPC_BIND", &grpc_bind),
        ],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    // Park a first same-identity request in the slow worker so the identity's
    // single fairness slot is held while the gRPC request below arrives.
    let first_args = vec![
        "--header".to_string(),
        "X-Forwarded-For: 198.51.100.42, 127.0.0.1".to_string(),
    ];
    let first = thread::spawn(move || {
        curl_https_with_args(port, false, "app.test", "/hold-slot", &first_args, true)
    });
    let first_worker = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("first request should reach worker")
        .expect("edge should connect to fake worker");
    assert!(
        String::from_utf8_lossy(&first_worker)
            .to_ascii_lowercase()
            .contains("x-oxo-remote-addr: 198.51.100.42\r\n"),
        "first request should resolve the trusted-proxy identity"
    );

    let grpc_args = vec![
        "--request".to_string(),
        "POST".to_string(),
        "--header".to_string(),
        "Content-Type: application/grpc".to_string(),
        "--header".to_string(),
        "TE: trailers".to_string(),
        "--header".to_string(),
        "X-Forwarded-For: 198.51.100.42, 127.0.0.1".to_string(),
    ];
    let second = curl_https_with_args(port, true, "app.test", "/pkg.Echo/Ping", &grpc_args, false);
    assert!(second.starts_with("HTTP/2 503"), "{second}");

    let first_response = first.join().expect("first curl thread joins");
    assert!(
        first_response.starts_with("HTTP/1.1 200"),
        "{first_response}"
    );

    let ready = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(ready.contains("\"requests_total\":2"), "{ready}");
    assert!(ready.contains("\"responses_total\":1"), "{ready}");
    assert!(ready.contains("\"rejections_total\":1"), "{ready}");
    assert!(ready.contains("\"rate_limited_total\":1"), "{ready}");
    assert!(ready.contains("\"last_rejection_status\":503"), "{ready}");
    assert!(ready.contains("\"fairness_saturation_total\":1"), "{ready}");
    // Fairness fired BEFORE the long-lived gate: no long-lived admission was
    // attempted, so both long-lived outcome counters stay zero.
    assert!(ready.contains("\"long_lived_accepted_total\":0"), "{ready}");
    assert!(ready.contains("\"long_lived_rejected_total\":0"), "{ready}");
    grpc_listener.set_nonblocking(true).unwrap();
    assert!(
        grpc_listener.accept().is_err(),
        "fairness 503 must reject before any sidecar connection"
    );
}

// pin: a gRPC request violating BOTH the authority requirement and the
// header-count cap must keep returning 400 — in validate_grpc_unary_request
// the `:authority` check precedes the `headers.len() > MAX_REQUEST_HEADERS`
// check, and hoisting the count check (e.g. while unifying the validators'
// header-cap logic) would flip this observable status to 431.
#[cfg(feature = "tls-rustls")]
#[test]
fn public_smoke_beta_grpc_over_count_headers_without_authority_rejects_400() {
    let _guard = serial_test();
    let fixture = Fixture::new("grpc-400-before-431");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let grpc_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let grpc_bind = grpc_listener.local_addr().unwrap().to_string();
    let port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        port,
        admin_port,
        &fixture.socket,
        1024,
        &cert,
        &key,
        &[("OXO_EDGE_GRPC_BIND", &grpc_bind)],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    send_raw_h2_tls_frames(port, &h2_grpc_over_count_headers_without_authority_frames());

    let ready = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(ready.contains("\"requests_total\":1"), "{ready}");
    assert!(ready.contains("\"rejections_total\":1"), "{ready}");
    assert!(ready.contains("\"last_rejection_status\":400"), "{ready}");
    assert!(
        recorded.recv_timeout(Duration::from_millis(300)).is_err(),
        "gRPC rejection must not acquire the worker UDS"
    );
    grpc_listener.set_nonblocking(true).unwrap();
    assert!(
        grpc_listener.accept().is_err(),
        "gRPC rejection must not open a sidecar connection"
    );
}

#[test]
fn private_admin_reports_rejection_metrics_without_client_secret_values() {
    let _guard = serial_test();
    let fixture = Fixture::new("admin-rejection-metrics");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let admin_port = free_port();
    let admin_bind = format!("127.0.0.1:{admin_port}");
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[("OXO_EDGE_ADMIN_BIND", &admin_bind)],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let response = send_tcp(
        port,
        b"POST /grpc HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/grpc\r\nContent-Length: 0\r\nAuthorization: Bearer super-secret\r\nX-Request-ID: client-controlled\r\n\r\n",
    );
    let response_text = String::from_utf8_lossy(&response);
    assert!(response_text.contains("415"), "{response_text}");
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "gRPC rejection must not acquire the worker UDS"
    );

    let ready = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(ready.contains("\"operator_schema\":\"v86\""), "{ready}");
    assert!(ready.contains("\"public_mode\":\"loopback\""), "{ready}");
    assert!(ready.contains("\"in_flight\":0"), "{ready}");
    assert!(ready.contains("\"requests_total\":1"), "{ready}");
    assert!(ready.contains("\"responses_total\":0"), "{ready}");
    assert!(ready.contains("\"rejections_total\":1"), "{ready}");
    assert!(ready.contains("\"status_4xx_total\":1"), "{ready}");
    assert!(ready.contains("\"last_request_id\":\"oxo-"), "{ready}");
    assert!(ready.contains("\"last_response_status\":null"), "{ready}");
    assert!(ready.contains("\"last_rejection_status\":415"), "{ready}");
    assert!(!ready.contains("super-secret"), "{ready}");
    assert!(!ready.contains("client-controlled"), "{ready}");
}
#[test]
fn metrics_surface_matches_documentation() {
    let _guard = serial_test();
    let fixture = Fixture::new("metrics-surface");
    let _listener = bind_worker_socket(&fixture.socket);
    let port = free_port();
    let admin_port = free_port();
    let admin_bind = format!("127.0.0.1:{admin_port}");
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[("OXO_EDGE_ADMIN_BIND", &admin_bind)],
    );
    wait_for_tcp(admin_port);

    let response = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /metrics HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("metrics response body");
    assert_eq!(metric_names_from_text(body), metric_names_from_manifest());
}

fn metric_names_from_text(metrics: &str) -> BTreeSet<String> {
    metrics
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_whitespace().next())
        .map(ToOwned::to_owned)
        .collect()
}

fn metric_names_from_manifest() -> BTreeSet<String> {
    include_str!("../../../docs/metrics-manifest.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_whitespace().next())
        .map(ToOwned::to_owned)
        .collect()
}

#[test]
fn burst_smoke_records_success_metrics_without_counter_drift() {
    let _guard = serial_test();
    let fixture = Fixture::new("burst-smoke");
    let listener = bind_worker_socket(&fixture.socket);
    let burst_count = 16usize;
    let recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), burst_count);
    let port = free_port();
    let admin_port = free_port();
    let admin_bind = format!("127.0.0.1:{admin_port}");
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[("OXO_EDGE_ADMIN_BIND", &admin_bind)],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let started = Instant::now();
    for index in 0..burst_count {
        let request = format!("GET /burst/{index} HTTP/1.1\r\nHost: app.test\r\n\r\n");
        let response = send_tcp(port, request.as_bytes());
        let response_text = String::from_utf8_lossy(&response);
        assert!(response_text.contains("200 OK"), "{response_text}");
        assert!(response.ends_with(b"ok"), "{response_text}");
    }
    let elapsed = started.elapsed();
    eprintln!(
        "burst_smoke requests={burst_count} elapsed_ms={}",
        elapsed.as_millis()
    );

    for index in 0..burst_count {
        let worker_request = recorded
            .recv_timeout(Duration::from_secs(2))
            .expect("fake worker should record every burst request")
            .expect("edge should connect to fake worker");
        let worker_text = String::from_utf8_lossy(&worker_request);
        assert!(
            worker_text.starts_with(&format!("GET /burst/{index} HTTP/1.1\r\n")),
            "{worker_text}"
        );
        assert!(
            worker_text
                .to_ascii_lowercase()
                .contains("x-oxo-request-id: oxo-"),
            "{worker_text}"
        );
    }
    assert!(
        recorded.recv_timeout(Duration::from_millis(300)).is_err(),
        "worker should observe exactly the burst request count"
    );

    let ready = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(ready.contains("\"operator_schema\":\"v86\""), "{ready}");
    assert!(ready.contains("\"public_mode\":\"loopback\""), "{ready}");
    assert!(ready.contains("\"in_flight\":0"), "{ready}");
    assert!(
        ready.contains(&format!("\"requests_total\":{burst_count}")),
        "{ready}"
    );
    assert!(
        ready.contains(&format!("\"responses_total\":{burst_count}")),
        "{ready}"
    );
    assert!(ready.contains("\"rejections_total\":0"), "{ready}");
    assert!(
        ready.contains(&format!("\"status_2xx_total\":{burst_count}")),
        "{ready}"
    );
    assert!(ready.contains("\"status_4xx_total\":0"), "{ready}");
    assert!(ready.contains("\"status_5xx_total\":0"), "{ready}");
    assert!(ready.contains("\"last_response_status\":200"), "{ready}");
    assert!(ready.contains("\"last_rejection_status\":null"), "{ready}");
}
#[test]
fn malformed_worker_status_maps_to_502() {
    let _guard = serial_test();
    let fixture = Fixture::new("malformed-status");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(b"NOPE\r\n\r\n".to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(port, b"GET /bad-status HTTP/1.1\r\nHost: app.test\r\n\r\n");

    assert!(String::from_utf8_lossy(&response).contains("502"));
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record the attempted request")
        .expect("edge should connect to fake worker");
}

#[test]
fn invalid_worker_header_maps_to_502() {
    let _guard = serial_test();
    let fixture = Fixture::new("invalid-worker-header");
    let listener = bind_worker_socket(&fixture.socket);
    let response = b"HTTP/1.1 200 OK\r\nBad Header: nope\r\nContent-Length: 2\r\n\r\nok";
    let recorded = spawn_recording_worker(listener, Some(response.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(port, b"GET /bad-header HTTP/1.1\r\nHost: app.test\r\n\r\n");

    assert!(String::from_utf8_lossy(&response).contains("502"));
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record the attempted request")
        .expect("edge should connect to fake worker");
}

#[test]
fn oversized_worker_headers_map_to_502() {
    let _guard = serial_test();
    let fixture = Fixture::new("oversized-worker-header");
    let listener = bind_worker_socket(&fixture.socket);
    let mut worker_response = b"HTTP/1.1 200 OK\r\nX-Large: ".to_vec();
    worker_response.extend(std::iter::repeat_n(b'a', 70 * 1024));
    worker_response.extend_from_slice(b"\r\nContent-Length: 2\r\n\r\nok");
    let recorded = spawn_recording_worker(listener, Some(worker_response));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(port, b"GET /huge-header HTTP/1.1\r\nHost: app.test\r\n\r\n");

    assert!(String::from_utf8_lossy(&response).contains("502"));
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record the attempted request")
        .expect("edge should connect to fake worker");
}

#[test]
fn upstream_framing_headers_are_canonicalized_downstream() {
    let _guard = serial_test();
    let fixture = Fixture::new("framing-canonicalization");
    let listener = bind_worker_socket(&fixture.socket);
    let response = b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 999\r\n\r\nok";
    let recorded = spawn_recording_worker(listener, Some(response.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(port, b"GET /framing HTTP/1.1\r\nHost: app.test\r\n\r\n");
    let response_text = String::from_utf8_lossy(&response);
    let lower = response_text.to_ascii_lowercase();

    assert!(response_text.contains("200 OK"));
    assert!(!lower.contains("transfer-encoding:"));
    assert!(!lower.contains("connection: keep-alive"));
    assert!(lower.contains("content-length: 2"));
    assert!(lower.contains("connection: close"));
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record the attempted request")
        .expect("edge should connect to fake worker");
}

#[test]
fn chunked_worker_response_is_decoded_and_forwarded_downstream() {
    let _guard = serial_test();
    let fixture = Fixture::new("chunked-worker-response");
    let listener = bind_worker_socket(&fixture.socket);
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n4\r\none\n\r\n4\r\ntwo\n\r\n0\r\n\r\n";
    let recorded = spawn_recording_worker(listener, Some(response.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"GET /chunked-worker HTTP/1.1\r\nHost: app.test\r\n\r\n",
    );
    let response_text = String::from_utf8_lossy(&response);
    let lower = response_text.to_ascii_lowercase();

    assert!(response_text.contains("200 OK"), "{response_text}");
    assert!(response_text.contains("one\n"), "{response_text}");
    assert!(response_text.contains("two\n"), "{response_text}");
    assert!(!lower.contains("content-length:"), "{response_text}");
    assert!(!lower.contains("connection: keep-alive"), "{response_text}");
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record the attempted request")
        .expect("edge should connect to fake worker");
}

#[test]
fn malformed_chunked_worker_response_maps_to_502() {
    let _guard = serial_test();
    let fixture = Fixture::new("malformed-chunked-worker-response");
    let listener = bind_worker_socket(&fixture.socket);
    let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nok";
    let recorded = spawn_recording_worker(listener, Some(response.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"GET /malformed-chunked HTTP/1.1\r\nHost: app.test\r\n\r\n",
    );

    assert!(String::from_utf8_lossy(&response).contains("502"));
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record the attempted request")
        .expect("edge should connect to fake worker");
}

#[test]
fn long_lived_registry_reports_completed_chunked_response() {
    let _guard = serial_test();
    let fixture = Fixture::new("long-lived-complete");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_chunked_streaming_worker_many(
        listener,
        vec![b"one\n".to_vec(), b"two\n".to_vec()],
        Duration::ZERO,
        1,
    );
    let port = free_port();
    let admin_port = free_port();
    let admin_bind = format!("127.0.0.1:{admin_port}");
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[("OXO_EDGE_ADMIN_BIND", &admin_bind)],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let response = send_tcp(
        port,
        b"GET /long-lived-complete HTTP/1.1\r\nHost: app.test\r\n\r\n",
    );
    let response_text = String::from_utf8_lossy(&response);
    assert!(response_text.contains("200 OK"), "{response_text}");
    assert!(response_text.contains("one\n"), "{response_text}");
    assert!(response_text.contains("two\n"), "{response_text}");
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record the attempted request")
        .expect("edge should connect to fake worker");

    let ready = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(ready.contains("\"operator_schema\":\"v86\""), "{ready}");
    assert!(ready.contains("\"long_lived_active\":0"), "{ready}");
    assert!(ready.contains("\"long_lived_accepted_total\":1"), "{ready}");
    assert!(
        ready.contains("\"long_lived_completed_total\":1"),
        "{ready}"
    );
    assert!(
        ready.contains("\"long_lived_cancelled_total\":0"),
        "{ready}"
    );
    assert!(
        ready.contains("\"long_lived_bytes_streamed_total\":8"),
        "{ready}"
    );

    let metrics = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /metrics HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(
        metrics.contains("oxo_edge_long_lived_completed_total 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("oxo_edge_long_lived_bytes_streamed_total 8"),
        "{metrics}"
    );
}

#[test]
fn drain_finishes_chunked_worker_stream_with_clean_eof() {
    let _guard = serial_test();
    let fixture = Fixture::new("drain-chunked-clean-eof");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_chunked_streaming_worker_many_with_content_type(
        listener,
        "text/event-stream",
        vec![b"data: one\n\n".to_vec()],
        Duration::ZERO,
        Duration::from_secs(5),
        1,
    );
    let port = free_port();
    let admin_port = free_port();
    let admin_bind = format!("127.0.0.1:{admin_port}");
    let edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_ADMIN_BIND", &admin_bind),
            ("OXO_EDGE_DRAIN_GRACE_MS", "3000"),
            ("OXO_EDGE_SSE", "1"),
        ],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let client = thread::spawn(move || {
        send_tcp(
            port,
            b"GET /events HTTP/1.1\r\nHost: app.test\r\nAccept: text/event-stream\r\n\r\n",
        )
    });
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("drained stream should reach fake worker before edge signal")
        .expect("edge should connect to fake worker");

    unsafe {
        libc::kill(edge.child.id() as libc::pid_t, libc::SIGTERM);
    }

    let ready = wait_until_admin_contains(admin_port, "\"long_lived_drained_total\":1");
    assert!(
        ready.contains("\"long_lived_completed_total\":1"),
        "{ready}"
    );
    assert!(
        ready.contains("\"long_lived_cancelled_total\":0"),
        "{ready}"
    );

    let response = client.join().expect("client thread should finish");
    let response_text = String::from_utf8_lossy(&response);
    assert!(response_text.contains("200 OK"), "{response_text}");
    assert!(response_text.contains("data: one"), "{response_text}");
}

#[test]
fn post_drain_existing_h1_connection_does_not_acquire_worker_uds() {
    let _guard = serial_test();
    let fixture = Fixture::new("post-drain-no-uds");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let admin_port = free_port();
    let admin_bind = format!("127.0.0.1:{admin_port}");
    let edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_ADMIN_BIND", &admin_bind),
            ("OXO_EDGE_DRAIN_GRACE_MS", "3000"),
            ("OXO_EDGE_SSE", "1"),
        ],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("open downstream h1");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(b"GET /after-drain HTTP/1.1\r\n")
        .expect("write partial request before drain");
    thread::sleep(Duration::from_millis(100));

    unsafe {
        libc::kill(edge.child.id() as libc::pid_t, libc::SIGTERM);
    }
    let ready = wait_until_admin_contains(admin_port, "\"draining\":true");
    assert!(ready.contains("\"ready\":false"), "{ready}");

    let write_after_drain = stream.write_all(b"Host: app.test\r\n\r\n");
    if let Err(err) = write_after_drain {
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ),
            "unexpected post-drain write error: {err}"
        );
    }

    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    match stream.read(&mut buf) {
        Ok(n) => response.extend_from_slice(&buf[..n]),
        Err(err) => assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
            ),
            "unexpected post-drain read error: {err}"
        ),
    }
    if !response.is_empty() {
        let response_text = String::from_utf8_lossy(&response);
        assert!(response_text.contains("503"), "{response_text}");
    }
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "post-drain H1 work must not acquire the worker UDS"
    );
}
#[test]
fn long_lived_connection_cap_rejects_second_active_stream() {
    let _guard = serial_test();
    let fixture = Fixture::new("long-lived-cap");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_chunked_streaming_worker_many(
        listener,
        vec![b"hold\n".to_vec()],
        Duration::from_millis(900),
        2,
    );
    let port = free_port();
    let admin_port = free_port();
    let admin_bind = format!("127.0.0.1:{admin_port}");
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_ADMIN_BIND", &admin_bind),
            ("OXO_EDGE_LONG_LIVED_MAX_CONNECTIONS", "1"),
        ],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let first = thread::spawn(move || {
        send_tcp(
            port,
            b"GET /first-long-lived HTTP/1.1\r\nHost: app.test\r\n\r\n",
        )
    });
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record the first request")
        .expect("edge should connect to fake worker");
    thread::sleep(Duration::from_millis(150));

    let second = send_tcp(
        port,
        b"GET /second-long-lived HTTP/1.1\r\nHost: app.test\r\n\r\n",
    );
    let second_text = String::from_utf8_lossy(&second);
    assert!(second_text.contains("503"), "{second_text}");

    let first_response = first.join().expect("first request thread should finish");
    let first_text = String::from_utf8_lossy(&first_response);
    assert!(first_text.contains("200 OK"), "{first_text}");
    assert!(first_text.contains("hold\n"), "{first_text}");
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record the rejected stream request")
        .expect("edge should connect before rejecting saturated long-lived admission");

    let ready = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(ready.contains("\"long_lived_active\":0"), "{ready}");
    assert!(ready.contains("\"long_lived_accepted_total\":1"), "{ready}");
    assert!(
        ready.contains("\"long_lived_completed_total\":1"),
        "{ready}"
    );
    assert!(ready.contains("\"long_lived_rejected_total\":1"), "{ready}");
}

#[test]
fn long_lived_memory_envelope_cancels_over_cap_stream() {
    let _guard = serial_test();
    let fixture = Fixture::new("long-lived-memory-cap");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded =
        spawn_chunked_streaming_worker_many(listener, vec![b"four".to_vec()], Duration::ZERO, 1);
    let port = free_port();
    let admin_port = free_port();
    let admin_bind = format!("127.0.0.1:{admin_port}");
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_ADMIN_BIND", &admin_bind),
            ("OXO_EDGE_LONG_LIVED_MAX_BUFFERED_BYTES", "3"),
        ],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let response = send_tcp(
        port,
        b"GET /long-lived-memory-cap HTTP/1.1\r\nHost: app.test\r\n\r\n",
    );
    let response_text = String::from_utf8_lossy(&response);
    assert!(response_text.contains("502"), "{response_text}");
    recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fake worker should record the attempted request")
        .expect("edge should connect to fake worker");

    let ready = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(ready.contains("\"long_lived_active\":0"), "{ready}");
    assert!(ready.contains("\"long_lived_accepted_total\":1"), "{ready}");
    assert!(
        ready.contains("\"long_lived_completed_total\":0"),
        "{ready}"
    );
    assert!(
        ready.contains("\"long_lived_cancelled_total\":1"),
        "{ready}"
    );
    assert!(
        ready.contains("\"long_lived_bytes_streamed_total\":4"),
        "{ready}"
    );
}

#[test]
fn malformed_client_headers_are_rejected_before_worker_acquisition() {
    let _guard = serial_test();
    for (label, request) in [
        (
            "obs-fold",
            b"GET /fold HTTP/1.1\r\nHost: app.test\r\nX-Test: one\r\n two\r\n\r\n".as_slice(),
        ),
        (
            "space-before-colon",
            b"GET /space HTTP/1.1\r\nHost: app.test\r\nBad : nope\r\n\r\n".as_slice(),
        ),
        (
            "invalid-header-byte",
            b"GET /invalid HTTP/1.1\r\nHost: app.test\r\nBad\x01Name: nope\r\n\r\n".as_slice(),
        ),
        (
            "trailer",
            b"POST /trailer HTTP/1.1\r\nHost: app.test\r\nTrailer: X-Late\r\nContent-Length: 1\r\n\r\nx".as_slice(),
        ),
        (
            "duplicate-host",
            b"GET /dup-host HTTP/1.1\r\nHost: app.test\r\nHost: other.test\r\n\r\n".as_slice(),
        ),
        (
            "keep-alive",
            b"GET /keep-alive HTTP/1.1\r\nHost: app.test\r\nConnection: keep-alive\r\n\r\n".as_slice(),
        ),
        (
            "connection-token",
            b"GET /token HTTP/1.1\r\nHost: app.test\r\nConnection: X-Hop\r\nX-Hop: bad\r\n\r\n".as_slice(),
        ),
    ] {
        let fixture = Fixture::new(label);
        let listener = bind_worker_socket(&fixture.socket);
        let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
        let port = free_port();
        let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
        wait_for_tcp(port);

        let response = send_tcp(port, request);

        assert_client_error_or_close(&response);
        assert!(
            recorded.recv_timeout(Duration::from_millis(800)).is_err(),
            "{label} must not acquire the worker UDS"
        );
    }
}
struct Fixture {
    dir: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "oxo-pingora-edge-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.join("worker.sock");
        Self { dir, socket }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

// ---- static file serving (crenel integration) ----

/// Build a docroot under the fixture dir; returns its path as a string.
fn static_docroot(fixture: &Fixture, files: &[(&str, &[u8])]) -> String {
    let root = fixture.dir.join("public");
    for (rel, contents) in files {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdirs");
        fs::write(&path, contents).expect("write fixture file");
    }
    fs::create_dir_all(&root).expect("docroot");
    root.to_string_lossy().into_owned()
}

#[test]
fn static_mount_serves_asset_without_touching_worker() {
    let _guard = serial_test();
    let fixture = Fixture::new("static-hit");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let root = static_docroot(
        &fixture,
        &[
            ("assets/app-abc.css", b"body{color:#333}"),
            ("assets/app-abc.css.gz", b"\x1f\x8b\x08\x00FAKEGZ"),
        ],
    );
    let mounts =
        format!("/assets={root}/assets,cache-control=public%2Cmax-age=31536000%2Cimmutable");
    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[("OXO_EDGE_STATIC_MOUNTS", &mounts)],
    );
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"GET /assets/app-abc.css HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n",
    );
    let text = String::from_utf8_lossy(&response);
    let lower = text.to_ascii_lowercase();
    assert!(text.contains("200"), "{text}");
    assert!(text.ends_with("body{color:#333}"), "{text}");
    assert!(
        lower.contains("cache-control: public,max-age=31536000,immutable"),
        "{lower}"
    );
    assert!(lower.contains("x-content-type-options: nosniff"), "{lower}");
    assert!(lower.contains("etag: \""), "{lower}");
    assert!(lower.contains("vary: accept-encoding"), "{lower}");
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "static hit must never acquire the worker UDS"
    );

    // Sidecar negotiation through the same admission path.
    let gz = send_tcp(
        port,
        b"GET /assets/app-abc.css HTTP/1.1\r\nHost: app.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    );
    let gz_lower = String::from_utf8_lossy(&gz).to_ascii_lowercase();
    assert!(gz_lower.contains("content-encoding: gzip"), "{gz_lower}");
}

#[test]
fn static_fallthrough_miss_reaches_worker_under_same_admission() {
    let _guard = serial_test();
    let fixture = Fixture::new("static-fallthrough");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let root = static_docroot(&fixture, &[("hello.txt", b"static hello")]);
    let mounts = format!("/={root},fallthrough");
    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[("OXO_EDGE_STATIC_MOUNTS", &mounts)],
    );
    wait_for_tcp(port);

    // Static hit under the root mount: served by the edge.
    let hit = send_tcp(
        port,
        b"GET /hello.txt HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n",
    );
    assert!(String::from_utf8_lossy(&hit).ends_with("static hello"));
    assert!(
        recorded.recv_timeout(Duration::from_millis(500)).is_err(),
        "static hit must not touch the worker"
    );

    // Miss falls through to the Rack hop — the worker sees EXACTLY one request.
    let dynamic = send_tcp(
        port,
        b"GET /dynamic-route HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n",
    );
    assert!(String::from_utf8_lossy(&dynamic).contains("200 OK"));
    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("fallthrough miss must reach the worker")
        .expect("worker connection");
    assert!(String::from_utf8_lossy(&worker_request).starts_with("GET /dynamic-route HTTP/1.1"));
    assert!(
        recorded.recv_timeout(Duration::from_millis(500)).is_err(),
        "exactly one worker request per fallthrough miss (single admission)"
    );
}

#[test]
fn static_strict_mount_miss_is_engine_404_without_worker() {
    let _guard = serial_test();
    let fixture = Fixture::new("static-strict");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let root = static_docroot(&fixture, &[("assets/real.css", b"x")]);
    let mounts = format!("/assets={root}/assets");
    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[("OXO_EDGE_STATIC_MOUNTS", &mounts)],
    );
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"GET /assets/nope.css HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n",
    );
    assert!(String::from_utf8_lossy(&response).contains("404"));
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "strict-mount miss must not acquire the worker UDS"
    );
}

#[test]
fn static_hostile_paths_reject_before_worker_acquisition() {
    let _guard = serial_test();
    let fixture = Fixture::new("static-hostile");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let root = static_docroot(&fixture, &[("assets/real.css", b"x")]);
    let mounts = format!("/assets={root}/assets,cache-control=public;/={root},fallthrough");
    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[("OXO_EDGE_STATIC_MOUNTS", &mounts)],
    );
    wait_for_tcp(port);

    // Traversal in several encodings, NUL, bad escape: fixed 400, mount-independent,
    // never a worker fallthrough (the panel-F6 sanitizer-vs-fallthrough contract).
    for target in [
        "/assets/../secret.txt",
        "/%2e%2e/etc/passwd",
        "/assets/a%00.css",
        "/assets/a%zz.css",
        "/assets%2f..%2fsecret",
    ] {
        let request =
            format!("GET {target} HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n");
        let response = send_tcp(port, request.as_bytes());
        assert!(
            String::from_utf8_lossy(&response).contains("400"),
            "target {target}"
        );
    }
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "hostile static paths must never reach the worker"
    );
}

#[test]
fn static_capistrano_deploy_flip_serves_new_release() {
    let _guard = serial_test();
    let fixture = Fixture::new("static-capistrano");
    let listener = bind_worker_socket(&fixture.socket);
    let _recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));

    // Standard Capistrano shape: current -> releases/<n>; assets INSIDE each release
    // (the shared/ linked_dirs variant mounts shared/public/assets directly — that
    // layout is boot-audit-guided and needs no flip handling).
    let releases = fixture.dir.join("releases");
    for (release, body) in [("one", "release-one"), ("two", "release-two")] {
        let assets = releases.join(release).join("public/assets");
        fs::create_dir_all(&assets).expect("release assets");
        fs::write(assets.join("app.css"), body).expect("asset");
    }
    let current = fixture.dir.join("current");
    std::os::unix::fs::symlink(releases.join("one"), &current).expect("current symlink");

    let mounts = format!("/assets={}/public/assets", current.display());
    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[("OXO_EDGE_STATIC_MOUNTS", &mounts)],
    );
    wait_for_tcp(port);

    let request = b"GET /assets/app.css HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n";
    let before = send_tcp(port, request);
    assert!(
        String::from_utf8_lossy(&before).ends_with("release-one"),
        "pre-flip release"
    );

    // Deploy flip: retarget `current` atomically (symlink swap via rename).
    let staging = fixture.dir.join("current-staging");
    std::os::unix::fs::symlink(releases.join("two"), &staging).expect("staging symlink");
    fs::rename(&staging, &current).expect("atomic flip");

    // Deploy-coupled re-pin (panel F3): the very next request re-pins and serves the
    // new release — poll-until per WSL flake discipline, bounded.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let after = send_tcp(port, request);
        if String::from_utf8_lossy(&after).ends_with("release-two") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "flip never observed: {}",
            String::from_utf8_lossy(&after)
        );
        thread::sleep(Duration::from_millis(50));
    }
}

// ---- downstream HTTP/1.1 keepalive ----

/// One parsed response, framed by Content-Length (so the client reads EXACTLY one
/// response and leaves the connection positioned for the next request).
struct KaResponse {
    status: u16,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
}

impl KaResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// A keepalive-capable raw HTTP/1.1 client: it frames responses by Content-Length
/// instead of reading to EOF, so the same TCP connection can carry multiple requests.
/// None of the existing helpers do this (they read to EOF, which only terminates
/// because the one-shot edge closes the connection).
struct KaClient {
    stream: TcpStream,
    /// Bytes already read past the current response's end (pipelined/next-response
    /// prefix); consumed by the next `read_response`.
    carry: Vec<u8>,
}

impl KaClient {
    fn connect(port: u16) -> KaClient {
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        KaClient {
            stream,
            carry: Vec::new(),
        }
    }

    fn send(&mut self, request: &[u8]) {
        self.stream.write_all(request).expect("send request");
    }

    /// Read exactly one Content-Length-framed response. Panics on EOF before a full
    /// response (use `expect_closed` to assert a closed connection instead).
    fn read_response(&mut self) -> KaResponse {
        let mut buf = std::mem::take(&mut self.carry);
        let mut scratch = [0u8; 4096];
        // Accumulate until the header terminator is present.
        let header_end = loop {
            if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
                break pos;
            }
            let n = self
                .stream
                .read(&mut scratch)
                .expect("read response headers");
            assert!(n > 0, "connection closed mid-header");
            buf.extend_from_slice(&scratch[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
        let mut lines = head.lines();
        let status: u16 = lines
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .expect("status line");
        let mut headers = std::collections::HashMap::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }
        let content_length: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let body_start = header_end + 4;
        let want = body_start + content_length;
        while buf.len() < want {
            let n = self.stream.read(&mut scratch).expect("read response body");
            assert!(n > 0, "connection closed mid-body");
            buf.extend_from_slice(&scratch[..n]);
        }
        let body = buf[body_start..want].to_vec();
        self.carry = buf[want..].to_vec(); // keep any pipelined bytes for the next read
        KaResponse {
            status,
            headers,
            body,
        }
    }

    /// Assert the connection is closed (server sent FIN / RST) within the read timeout.
    fn expect_closed(&mut self) {
        if !self.carry.is_empty() {
            // Residual bytes after a response but before close are allowed; drain them.
        }
        let mut scratch = [0u8; 1024];
        loop {
            match self.stream.read(&mut scratch) {
                Ok(0) => return, // clean EOF
                Ok(_) => continue,
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return
                }
                Err(err) => panic!("unexpected error waiting for close: {err}"),
            }
        }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn keepalive_serves_two_requests_on_one_connection() {
    let _guard = serial_test();
    let fixture = Fixture::new("ka-two-req");
    let listener = bind_worker_socket(&fixture.socket);
    // Two responses queued: the fake worker answers each request the edge forwards.
    let recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 2);
    let port = free_port();
    let _edge =
        EdgeProcess::spawn_with_env(port, &fixture.socket, 1024, &[("OXO_EDGE_KEEPALIVE", "1")]);
    wait_for_tcp(port);

    let mut client = KaClient::connect(port);
    client.send(b"GET /one HTTP/1.1\r\nHost: app.test\r\n\r\n");
    let first = client.read_response();
    assert_eq!(first.status, 200);
    assert_eq!(first.body, b"ok");
    assert!(
        first
            .header("connection")
            .map(|v| v.eq_ignore_ascii_case("close"))
            != Some(true),
        "keepalive response must not carry Connection: close: {:?}",
        first.headers
    );
    // Second request on the SAME connection succeeds — proof of reuse.
    client.send(b"GET /two HTTP/1.1\r\nHost: app.test\r\n\r\n");
    let second = client.read_response();
    assert_eq!(second.status, 200);
    assert_eq!(second.body, b"ok");
    assert_eq!(
        recorded.recv_timeout(Duration::from_secs(2)).map(|_| ()),
        Ok(()),
        "worker saw the first request"
    );
    assert!(
        recorded.recv_timeout(Duration::from_secs(2)).is_ok(),
        "worker saw the second request"
    );
}

#[test]
fn keepalive_request_limit_enforced() {
    // operator N=3 total requests per connection -> exactly 3 succeed on one
    // socket, the 3rd carries Connection: close, and the connection then closes.
    let _guard = serial_test();
    let fixture = Fixture::new("ka-req-limit");
    let listener = bind_worker_socket(&fixture.socket);
    let _recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 3);
    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_KEEPALIVE", "1"),
            ("OXO_EDGE_MAX_REQUESTS_PER_CONNECTION", "3"),
        ],
    );
    wait_for_tcp(port);

    let mut client = KaClient::connect(port);
    // Requests 1 and 2 reuse the connection without a close signal.
    for _ in 0..2 {
        client.send(b"GET /r HTTP/1.1\r\nHost: app.test\r\n\r\n");
        let resp = client.read_response();
        assert_eq!(resp.status, 200);
        assert!(
            resp.header("connection")
                .map(|v| v.eq_ignore_ascii_case("close"))
                != Some(true),
            "requests below the limit must not signal close: {:?}",
            resp.headers
        );
    }
    // Request 3 is the last permitted; the server closes after it.
    client.send(b"GET /r HTTP/1.1\r\nHost: app.test\r\n\r\n");
    let third = client.read_response();
    assert_eq!(third.status, 200);
    assert_eq!(
        third
            .header("connection")
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("close"),
        "the Nth request must carry Connection: close"
    );
    client.expect_closed();
}

#[test]
fn keepalive_request_limit_n1_is_one_shot() {
    // N=1 with --keepalive is a genuine one-shot (Some(0) reuses) — identical to
    // the keepalive-disabled default.
    let _guard = serial_test();
    let fixture = Fixture::new("ka-req-limit-1");
    let listener = bind_worker_socket(&fixture.socket);
    let _recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_KEEPALIVE", "1"),
            ("OXO_EDGE_MAX_REQUESTS_PER_CONNECTION", "1"),
        ],
    );
    wait_for_tcp(port);

    let mut client = KaClient::connect(port);
    client.send(b"GET /one HTTP/1.1\r\nHost: app.test\r\n\r\n");
    let resp = client.read_response();
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.header("connection")
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("close"),
        "N=1 must be genuine one-shot even with --keepalive"
    );
    client.expect_closed();
}

#[test]
fn keepalive_request_limit_beats_idle_timeout() {
    // AC-b5: whichever bound fires first wins. With a short request limit and a long
    // idle, the connection closes at N regardless of the idle timeout.
    let _guard = serial_test();
    let fixture = Fixture::new("ka-limit-vs-idle");
    let listener = bind_worker_socket(&fixture.socket);
    let _recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 2);
    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_KEEPALIVE", "1"),
            ("OXO_EDGE_MAX_REQUESTS_PER_CONNECTION", "2"),
            ("OXO_EDGE_KEEPALIVE_IDLE_TIMEOUT_MS", "60000"),
        ],
    );
    wait_for_tcp(port);

    let mut client = KaClient::connect(port);
    client.send(b"GET /a HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(client.read_response().status, 200);
    client.send(b"GET /b HTTP/1.1\r\nHost: app.test\r\n\r\n");
    let second = client.read_response();
    assert_eq!(second.status, 200);
    assert_eq!(
        second
            .header("connection")
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("close"),
        "request 2 hits the limit and closes despite the 60s idle timeout"
    );
    let started = Instant::now();
    client.expect_closed();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "connection must close at the request limit, not wait for idle"
    );
}

#[test]
fn keepalive_static_two_hits_one_connection() {
    let _guard = serial_test();
    let fixture = Fixture::new("ka-static-two");
    let listener = bind_worker_socket(&fixture.socket);
    // Worker must never be touched by static hits.
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let root = static_docroot(&fixture, &[("a.css", b"body{}"), ("b.js", b"var x=1;")]);
    let mounts = format!("/assets={root}");
    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_KEEPALIVE", "1"),
            ("OXO_EDGE_STATIC_MOUNTS", &mounts),
        ],
    );
    wait_for_tcp(port);

    let mut client = KaClient::connect(port);
    client.send(b"GET /assets/a.css HTTP/1.1\r\nHost: app.test\r\n\r\n");
    let first = client.read_response();
    assert_eq!(first.status, 200);
    assert_eq!(first.body, b"body{}");
    // Second static hit on the SAME connection.
    client.send(b"GET /assets/b.js HTTP/1.1\r\nHost: app.test\r\n\r\n");
    let second = client.read_response();
    assert_eq!(second.status, 200);
    assert_eq!(second.body, b"var x=1;");
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "static hits must never acquire the worker UDS"
    );
}

#[test]
fn keepalive_disabled_is_default_one_shot() {
    let _guard = serial_test();
    let fixture = Fixture::new("ka-default-oneshot");
    let listener = bind_worker_socket(&fixture.socket);
    let _recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    // No OXO_EDGE_KEEPALIVE -> default one-shot.
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let mut client = KaClient::connect(port);
    client.send(b"GET /one HTTP/1.1\r\nHost: app.test\r\n\r\n");
    let first = client.read_response();
    assert_eq!(first.status, 200);
    assert_eq!(
        first
            .header("connection")
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("close"),
        "default (one-shot) response must carry Connection: close"
    );
    // The connection must close after one response.
    client.expect_closed();
}

#[test]
fn keepalive_pipelined_cl0_residue_same_read_closes() {
    // Security re-spec of content_length_zero_residue_does_not_become_second_worker_request
    // under keepalive: a CL:0 request with pipelined trailing bytes arriving in the SAME
    // read must NOT smuggle the trailing GET into a second worker request. Pingora's
    // reuse() refuses reuse on overread, so the connection closes and the residue is
    // dropped — never processed.
    let _guard = serial_test();
    let fixture = Fixture::new("ka-cl0-residue");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 2);
    let port = free_port();
    let _edge =
        EdgeProcess::spawn_with_env(port, &fixture.socket, 1024, &[("OXO_EDGE_KEEPALIVE", "1")]);
    wait_for_tcp(port);

    let mut client = KaClient::connect(port);
    // One write: the CL:0 request AND a full second request glued on (same read).
    client.send(
        b"POST /first HTTP/1.1\r\nHost: app.test\r\nContent-Length: 0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: app.test\r\n\r\n",
    );
    let first = client.read_response();
    assert_eq!(first.status, 200);
    // The connection must close (overread refused reuse); the smuggled GET is dropped.
    client.expect_closed();

    let first_worker = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("worker saw the first request")
        .expect("worker connection");
    assert!(String::from_utf8_lossy(&first_worker).starts_with("POST /first HTTP/1.1"));
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "the pipelined trailing GET must NEVER reach the worker as a second request"
    );
}

#[test]
fn keepalive_second_request_independently_validated() {
    // Per-request re-validation under reuse: request 1 succeeds, request 2 on the SAME
    // connection is independently front-door-validated and rejected (dup Content-Length
    // desync) — proof the reused connection does not bypass validation.
    let _guard = serial_test();
    let fixture = Fixture::new("ka-revalidate");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 2);
    let port = free_port();
    let _edge =
        EdgeProcess::spawn_with_env(port, &fixture.socket, 1024, &[("OXO_EDGE_KEEPALIVE", "1")]);
    wait_for_tcp(port);

    let mut client = KaClient::connect(port);
    client.send(b"GET /ok HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(client.read_response().status, 200);
    // Second request: duplicate Content-Length must be rejected before worker acquisition.
    client.send(
        b"POST /bad HTTP/1.1\r\nHost: app.test\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx",
    );
    let second = client.read_response();
    assert!(
        (400..500).contains(&second.status),
        "reused-connection request 2 must be independently rejected, got {}",
        second.status
    );
    // Only the first request ever reached the worker.
    assert!(recorded.recv_timeout(Duration::from_secs(2)).is_ok());
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "the rejected second request must not reach the worker"
    );
}

#[test]
fn keepalive_body_bearing_early_reject_closes() {
    // close_on_response invariant under keepalive: a body-bearing request rejected before
    // its body is drained (413 over-cap) closes the connection regardless of keepalive.
    let _guard = serial_test();
    let fixture = Fixture::new("ka-413-closes");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge =
        EdgeProcess::spawn_with_env(port, &fixture.socket, 5, &[("OXO_EDGE_KEEPALIVE", "1")]);
    wait_for_tcp(port);

    let mut client = KaClient::connect(port);
    client.send(b"POST /upload HTTP/1.1\r\nHost: app.test\r\nContent-Length: 6\r\n\r\n123456");
    let resp = client.read_response();
    assert_eq!(resp.status, 413);
    assert_eq!(
        resp.header("connection")
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("close"),
        "a body-bearing early reject must close even under keepalive"
    );
    client.expect_closed();
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "over-cap body must not reach the worker"
    );
}

#[test]
fn keepalive_idle_connection_closed_after_timeout() {
    let _guard = serial_test();
    let fixture = Fixture::new("ka-idle-close");
    let listener = bind_worker_socket(&fixture.socket);
    let _recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    // 1s idle bound (min after ms->s round-up).
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_KEEPALIVE", "1"),
            ("OXO_EDGE_KEEPALIVE_IDLE_TIMEOUT_MS", "1000"),
        ],
    );
    wait_for_tcp(port);

    let mut client = KaClient::connect(port);
    client.send(b"GET /one HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(client.read_response().status, 200);
    // Hold the connection idle; it must be closed within the idle bound + slack.
    let started = Instant::now();
    client.expect_closed();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "idle keepalive connection was not closed within the idle bound"
    );
}

#[test]
fn keepalive_drain_closes_idle_connection() {
    // AC7: an IDLE kept-alive connection during drain is closed within grace. Pingora's
    // drain aborts the idle between-request read (http_cleanup notify), so a connection
    // that completed one request and is parked waiting for the next is closed when drain
    // begins — the client need not send anything further. A long idle timeout ensures
    // ONLY drain (not the idle bound) can close it.
    let _guard = serial_test();
    let fixture = Fixture::new("ka-drain");
    let listener = bind_worker_socket(&fixture.socket);
    let _recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 1);
    let port = free_port();
    let admin_port = free_port();
    let admin_bind = format!("127.0.0.1:{admin_port}");
    let edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_KEEPALIVE", "1"),
            ("OXO_EDGE_ADMIN_BIND", &admin_bind),
            ("OXO_EDGE_KEEPALIVE_IDLE_TIMEOUT_MS", "60000"),
            ("OXO_EDGE_DRAIN_GRACE_MS", "3000"),
        ],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    // Establish a kept-alive connection with one completed request, then leave it idle.
    let mut client = KaClient::connect(port);
    client.send(b"GET /one HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(client.read_response().status, 200);

    // Begin drain; the idle connection must close well within the 60s idle bound.
    unsafe {
        libc::kill(edge.child.id() as libc::pid_t, libc::SIGTERM);
    }
    wait_until_admin_contains(admin_port, "\"draining\":true");

    let started = Instant::now();
    client.expect_closed();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "idle kept-alive connection was not closed by drain within grace"
    );
}

#[test]
fn slow_header_dribble_on_reused_connection() {
    // finding 4 (honest coupling): the keepalive idle timeout is a PER-READ gap bound,
    // NOT a total header-read deadline. On a reused connection whose session already carries
    // the keepalive timeout, a request dribbled with per-read gaps UNDER the idle window
    // still completes even though its TOTAL header time EXCEEDS the window. A single gap OVER
    // the window closes the connection (pingora returns Ok(None) = graceful keepalive close).
    // This pins exactly what the idle timeout does and does not bound.
    let _guard = serial_test();
    let fixture = Fixture::new("ka-dribble");
    let listener = bind_worker_socket(&fixture.socket);
    // Worker answers: conn-A req1, conn-A req2 (dribbled), conn-B req1 = 3 downstream reqs.
    let _recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 3);
    let port = free_port();
    // 2s idle: comfortably larger than the 1.2s per-read gaps, smaller than the 3.6s total.
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_KEEPALIVE", "1"),
            ("OXO_EDGE_KEEPALIVE_IDLE_TIMEOUT_MS", "2000"),
        ],
    );
    wait_for_tcp(port);

    // Connection A: request 1 completes normally so the session's keepalive timeout (2s) is
    // now armed for the reused request that follows.
    let mut conn_a = KaClient::connect(port);
    conn_a.send(b"GET /warm HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(conn_a.read_response().status, 200);
    // Request 2 dribbled: 4 chunks, 3 inter-chunk gaps of 1.2s each = 3.6s total header time
    // (> the 2s idle), but every individual gap (1.2s) stays under it. The request succeeds,
    // proving the idle timeout does NOT bound total within-request header time.
    let dribble_gap = Duration::from_millis(1200);
    let chunks: [&[u8]; 4] = [
        b"GET /dribble HTTP/1.1\r\n",
        b"Host: app.test\r\n",
        b"X-Pad: keep-reading\r\n",
        b"\r\n",
    ];
    let dribble_started = Instant::now();
    for (i, chunk) in chunks.iter().enumerate() {
        conn_a.send(chunk);
        if i + 1 < chunks.len() {
            std::thread::sleep(dribble_gap);
        }
    }
    assert!(
        dribble_started.elapsed() >= Duration::from_secs(2),
        "test invariant: total dribble time must exceed the 2s idle window to be meaningful"
    );
    assert_eq!(
        conn_a.read_response().status,
        200,
        "a dribble with sub-idle per-read gaps must complete even past the total idle window"
    );

    // Connection B: request 1 arms the 2s keepalive timeout, then a single gap OVER the idle
    // (no further bytes) makes pingora close the reused connection.
    let mut conn_b = KaClient::connect(port);
    conn_b.send(b"GET /warm HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(conn_b.read_response().status, 200);
    // Begin a second request but stall past the idle window; the connection must close.
    conn_b.send(b"GET /stall HTTP/1.1\r\n");
    let closed_started = Instant::now();
    conn_b.expect_closed();
    assert!(
        closed_started.elapsed() < Duration::from_secs(5),
        "a single read gap over the idle window must close the reused connection"
    );
}

#[test]
fn reject_pre_admission_is_un_metered_and_closes_connection() {
    // finding 2 (residual, CORRECTED behaviorally). Admission caps CONCURRENCY, not
    // request RATE. Two honest facts are pinned here:
    //  (1) a pre-admission reject (missing-Host 400 from validate_client_request, which runs
    //      BEFORE admit()) never acquires an admission slot -> admitted_total stays flat; and
    //  (2) pingora's respond_error -> write_error_response forces set_keepalive(None)
    //      (pingora-core-0.8.1 protocols/http/server.rs:539), so EVERY reject
    //      carries Connection: close and its connection cannot be reused for a second reject.
    //      Rejects are self-limiting (one per connection setup) -- NOT stormable on a single
    //      kept-alive connection -- so keepalive does not worsen the cheap-reject rate. A
    //      VALID connection still reuses normally (the intended handshake-tax win).
    let _guard = serial_test();
    let fixture = Fixture::new("ka-reject-meter");
    let listener = bind_worker_socket(&fixture.socket);
    // Only the two valid requests reach the worker; the rejects never do.
    let _recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 2);
    let port = free_port();
    let admin_port = free_port();
    let admin_bind = format!("127.0.0.1:{admin_port}");
    // Enable the global admission limiter on this loopback bind so admitted_total is live.
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_KEEPALIVE", "1"),
            ("OXO_EDGE_ADMIN_BIND", &admin_bind),
            ("OXO_EDGE_MAX_IN_FLIGHT_REQUESTS", "100"),
        ],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let read_ready = |admin_port: u16| -> String {
        String::from_utf8_lossy(&send_tcp(
            admin_port,
            b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
        ))
        .into_owned()
    };

    // Baseline: no request has been admitted yet, and the idle timeout is enforced because
    // keepalive reuse is ON here (the honesty annotation, live).
    let baseline = read_ready(admin_port);
    assert!(
        baseline.contains("\"global_in_flight_admitted_total\":0"),
        "{baseline}"
    );
    assert!(
        baseline.contains("\"slow_client_keepalive_idle_timeout_enforced\":true"),
        "idle timeout must report enforced when keepalive is on: {baseline}"
    );

    // Each pre-admission reject closes its OWN connection: 400 + Connection: close, then EOF.
    // A second reject cannot be pipelined onto the same connection.
    const REJECTS: usize = 4;
    for _ in 0..REJECTS {
        let mut client = KaClient::connect(port);
        client.send(b"GET /x HTTP/1.1\r\n\r\n");
        let resp = client.read_response();
        assert_eq!(
            resp.status, 400,
            "a missing-Host request must be rejected pre-admission"
        );
        assert_eq!(
            resp.header("connection")
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("close"),
            "a pre-admission reject must force the connection closed (respond_error one-shot)"
        );
        client.expect_closed();
    }

    // The rejects incremented rejections_total but NOT the admission counter.
    let after_rejects = read_ready(admin_port);
    assert!(
        after_rejects.contains(&format!("\"rejections_total\":{REJECTS}")),
        "each reject must be counted: {after_rejects}"
    );
    assert!(
        after_rejects.contains("\"global_in_flight_admitted_total\":0"),
        "pre-admission rejects must consume no admission slot: {after_rejects}"
    );

    // A VALID kept-alive connection admits AND reuses for a second valid request — the
    // intended handshake-tax win, and proof reuse is not collateral-damaged by the rejects.
    let mut ok = KaClient::connect(port);
    ok.send(b"GET /ok HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(ok.read_response().status, 200);
    ok.send(b"GET /ok2 HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(ok.read_response().status, 200);
    // Wait on the counter this actually asserts. Waiting on
    // global_in_flight_admitted_total and then asserting responses_total is a
    // race: admission is recorded when the request is let in, while
    // responses_total is recorded once the response is fully accounted for, so
    // the second can still be one behind. Observed failing on a Linux guest with
    // admitted_total=2, status_2xx_total=2 and in_flight=1 -- both 200s had been
    // produced and the client above had already asserted them, but only one was
    // counted yet. The product was correct; the read was early.
    let after_valid = wait_until_admin_contains(admin_port, "\"responses_total\":2");
    assert!(
        after_valid.contains("\"global_in_flight_admitted_total\":2"),
        "both valid requests must consume an admission slot: {after_valid}"
    );
}

#[test]
fn keepalive_reused_connection_desync_corpus() {
    // arc-close re-audit: the classic request-smuggling / desync vectors, each sent as
    // the SECOND request on a REUSED keepalive connection, proving the per-request front-door
    // validation (validate_client_request re-runs for every request even on a reused conn —
    // CTX is per-request) is not bypassed by reuse.
    //
    // PINNED disposition (verified behavior, ): every front-door reject goes through
    // pingora's respond_error -> write_error_response, which forces set_keepalive(None)
    // (pingora-core-0.8.1 protocols/http/server.rs:539). So each vector on a reused
    // connection is DETERMINISTICALLY: (1) a 4xx/413 reject, (2) with Connection: close,
    // (3) the connection then closes (EOF), and (4) the vector NEVER reaches the worker UDS.
    // This is strictly stronger than a "reject but keep serving" posture — every desync
    // vector TERMINATES its connection, so there is no reused-connection state a follow-up
    // request could exploit. The unread-request-body case (over-cap POST) is included to
    // pin the direction where a wrongly-reused reject WOULD be the smuggle.
    let _guard = serial_test();
    let fixture = Fixture::new("ka-desync-corpus");
    let listener = bind_worker_socket(&fixture.socket);
    // The worker only ever answers the legitimate warm-up GETs; if any smuggled vector
    // reached the UDS the recorder would see an extra request and the test would fail.
    let recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 64);
    let port = free_port();
    // max_body 5 so the body-bearing over-cap vector is rejected 413 before the worker.
    let _edge =
        EdgeProcess::spawn_with_env(port, &fixture.socket, 5, &[("OXO_EDGE_KEEPALIVE", "1")]);
    wait_for_tcp(port);

    // (label, request-2 vector, whether it carries an unread body). Bodyless vectors leave
    // no body on the wire; the body-bearing over-cap POST leaves 6 unread bytes.
    let vectors: &[(&str, &[u8], u16)] = &[
        (
            "transfer-encoding",
            b"GET /te HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\n\r\n",
            400,
        ),
        (
            "duplicate-content-length",
            b"GET /dupcl HTTP/1.1\r\nHost: app.test\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            400,
        ),
        (
            "connection-keepalive-token",
            b"GET /katoken HTTP/1.1\r\nHost: app.test\r\nConnection: keep-alive\r\n\r\n",
            400,
        ),
        (
            "absolute-form-target",
            b"GET http://app.test/abs HTTP/1.1\r\nHost: app.test\r\n\r\n",
            400,
        ),
        ("missing-host", b"GET /nohost HTTP/1.1\r\n\r\n", 400),
        (
            "duplicate-host",
            b"GET /duphost HTTP/1.1\r\nHost: app.test\r\nHost: evil.test\r\n\r\n",
            400,
        ),
        (
            "body-bearing-over-cap",
            b"POST /toobig HTTP/1.1\r\nHost: app.test\r\nContent-Length: 6\r\n\r\n123456",
            413,
        ),
    ];
    for (label, vector, want_status) in vectors {
        let mut client = KaClient::connect(port);
        // Warm the connection so the vector rides an already-reused session (request 2).
        client.send(b"GET /warm HTTP/1.1\r\nHost: app.test\r\n\r\n");
        assert_eq!(client.read_response().status, 200, "{label}: warm-up");
        // The smuggling vector as request 2 on the SAME connection.
        client.send(vector);
        let rejected = client.read_response();
        assert_eq!(
            rejected.status, *want_status,
            "{label}: front-door reject status on the reused connection"
        );
        assert_eq!(
            rejected
                .header("connection")
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("close"),
            "{label}: every desync reject must force Connection: close under reuse"
        );
        // The connection is terminated: no follow-up request can ride poisoned state.
        client.expect_closed();
    }

    // Only the 7 warm-up GETs (never a smuggled vector) reached the worker.
    let mut worker_hits = 0;
    while recorded.recv_timeout(Duration::from_millis(300)).is_ok() {
        worker_hits += 1;
    }
    assert_eq!(
        worker_hits,
        vectors.len(),
        "exactly the {} legitimate warm-up GETs reached the worker; no smuggled vector did",
        vectors.len()
    );
}

#[test]
fn check_config_reports_unenforced_knobs_and_stays_silent_by_default() {
    // finding 6: `--header-read-timeout-ms` and `--max-connection-secs` are parsed and
    // reported but have no pingora 0.8.1 enforcement seam. Both the boot path and
    // `--check-config` must tell the operator the truth where they configure. A stock config
    // (no inert knob set to a non-default value) stays silent — no noise.
    let _guard = serial_test();
    let fixture = Fixture::new("check-config-honesty");
    // The socket must exist for the (valid) config to construct before `--check-config`
    // returns; bind it without spawning a worker (no request is ever made).
    let _listener = bind_worker_socket(&fixture.socket);

    // Both inert knobs set to non-default values -> one NOT-ENFORCED line each, exit 0.
    let tuned = edge_check_config_output(
        "127.0.0.1:0",
        &fixture.socket,
        &[
            ("OXO_EDGE_HEADER_READ_TIMEOUT_MS", "5000".to_string()),
            ("OXO_EDGE_MAX_CONNECTION_SECS", "30".to_string()),
        ],
    );
    assert!(
        tuned.status.success(),
        "--check-config on a valid config must exit 0"
    );
    let stderr = String::from_utf8_lossy(&tuned.stderr);
    assert!(
        stderr.contains("NOT ENFORCED: --header-read-timeout-ms"),
        "{stderr}"
    );
    assert!(
        stderr.contains("NOT ENFORCED: --max-connection-secs"),
        "{stderr}"
    );

    // Stock config: no inert knob set -> no NOT-ENFORCED noise, still exit 0.
    let stock = edge_check_config_output("127.0.0.1:0", &fixture.socket, &[]);
    assert!(stock.status.success());
    let stock_stderr = String::from_utf8_lossy(&stock.stderr);
    assert!(
        !stock_stderr.contains("NOT ENFORCED"),
        "a stock config must not emit honesty noise: {stock_stderr}"
    );
}

/// the pool ceiling and the descriptor budget are posture lines a dry run prints,
/// and a ceiling that would crowd downstream connections is a WARNING (exit 0), never a
/// refusal. Expectations are derived from this process's own RLIMIT_NOFILE (the child
/// inherits it), never assumed: the gate guest's shell limit is not this test's to pick.
#[test]
fn check_config_prints_the_descriptor_budget_and_warns_on_a_crowding_ceiling() {
    use oxo_pingora_edge::fd_budget::{fd_budget, read_nofile_limits, Nofile};
    let _guard = serial_test();
    let fixture = Fixture::new("check-config-fd-budget");
    let _listener = bind_worker_socket(&fixture.socket);
    let limits = read_nofile_limits();

    // (a) stock: one worker, no admin bind -> ceiling max(512, 32) = 512 from the
    // default, and the fd-budget verdict the library computes for this process's limit.
    let expected = fd_budget(limits, 1, 1, 512, None).verdict.as_str();
    let stock = edge_check_config_output("127.0.0.1:0", &fixture.socket, &[]);
    assert!(stock.status.success(), "stock --check-config must exit 0");
    let stderr = String::from_utf8_lossy(&stock.stderr);
    assert!(
        stderr.contains("oxo_edge_config_notice frame-pool-idle: 512 (source: default;"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("oxo_edge_config_notice fd-budget: {expected} -- ")),
        "expected verdict {expected} for {limits:?}: {stderr}"
    );
    assert!(stderr.contains("(RLIMIT_NOFILE)"), "{stderr}");

    // (b) a ceiling equal to this process's soft limit cannot leave room for downstream
    // connections: the dry run WARNS with the remedy and still exits 0.
    match limits {
        Nofile::Limits { soft, .. } => {
            let crowded = edge_check_config_output(
                "127.0.0.1:0",
                &fixture.socket,
                &[("OXO_EDGE_FRAME_POOL_IDLE", soft.to_string())],
            );
            assert!(
                crowded.status.success(),
                "a crowding pool ceiling warns and never refuses boot"
            );
            let stderr = String::from_utf8_lossy(&crowded.stderr);
            assert!(
                stderr.contains(&format!(
                    "oxo_edge_config_notice frame-pool-idle: {soft} (source: env;"
                )),
                "{stderr}"
            );
            assert!(stderr.contains("oxo_edge_config_notice fd-budget: warn -- "), "{stderr}");
            assert!(stderr.contains("oxo_edge_config_warning fd-budget: "), "{stderr}");
            assert!(stderr.contains("OXO_EDGE_FRAME_POOL_IDLE to at most"), "{stderr}");
        }
        other => eprintln!("skipping the warn leg: the process descriptor limit is {other:?}, not a finite soft limit"),
    }

    // (c) the removed pool implementation refuses at --check-config too (before the
    // check lived in the pool constructor, after the dry-run return, and panicked).
    let refused = edge_check_config_output(
        "127.0.0.1:0",
        &fixture.socket,
        &[("OXO_EDGE_POOL", "pingora".to_string())],
    );
    assert!(
        !refused.status.success(),
        "OXO_EDGE_POOL=pingora must refuse"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("OXO_EDGE_POOL"), "{stderr}");
    assert!(
        !stderr.contains("panicked"),
        "the refusal is a config error, not a panic: {stderr}"
    );
}

// ---- --serve-rails ergonomics preset ----

/// Build a Rails-shaped app root under the fixture dir: `<root>/public[/assets]` with
/// one asset file and one bare public file. Returns the root path.
fn build_rails_root(fixture: &Fixture, with_assets: bool) -> PathBuf {
    let root = fixture.dir.join("app-current");
    let public = root.join("public");
    fs::create_dir_all(&public).unwrap();
    fs::write(public.join("hello.txt"), b"public-file").unwrap();
    if with_assets {
        let assets = public.join("assets");
        fs::create_dir_all(&assets).unwrap();
        fs::write(assets.join("app-cafe123.css"), b"body{color:teal}").unwrap();
    }
    root
}

#[test]
fn serve_rails_preset_serves_assets_keepalive_and_falls_through() {
    // AC-e1: ONE flag = static pair + keepalive + SSE. The asset is edge-served
    // without touching the worker, a dynamic path falls through to Rack, both ride the
    // SAME reused connection (keepalive proof), and /ready reports the resolved posture.
    let _guard = serial_test();
    let fixture = Fixture::new("serve-rails-full");
    let root = build_rails_root(&fixture, true);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 2);
    let port = free_port();
    let admin_port = free_port();
    let admin_bind = format!("127.0.0.1:{admin_port}");
    let root_env = root.to_string_lossy().into_owned();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_SERVE_RAILS", root_env.as_str()),
            ("OXO_EDGE_ADMIN_BIND", &admin_bind),
        ],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let mut client = KaClient::connect(port);
    // Asset: edge-served, immutable cache-control, never reaches the worker.
    client.send(b"GET /assets/app-cafe123.css HTTP/1.1\r\nHost: app.test\r\n\r\n");
    let asset = client.read_response();
    assert_eq!(asset.status, 200);
    assert_eq!(asset.body, b"body{color:teal}");
    assert!(
        asset
            .header("cache-control")
            .is_some_and(|v| v.contains("immutable")),
        "derived /assets mount must carry the immutable cache policy: {:?}",
        asset.headers
    );
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "the asset hit must not acquire the worker UDS"
    );
    // Dynamic path falls through to the worker on the SAME connection (keepalive), and
    // a second dynamic request proves reuse survives the static hit.
    client.send(b"GET /dynamic HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(client.read_response().status, 200);
    client.send(b"GET /dynamic2 HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(client.read_response().status, 200);
    assert!(recorded.recv_timeout(Duration::from_secs(2)).is_ok());
    assert!(recorded.recv_timeout(Duration::from_secs(2)).is_ok());

    // /ready posture (AC-e6): active, static dir named, idle timeout enforced.
    let ready = String::from_utf8_lossy(&send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    ))
    .into_owned();
    assert!(ready.contains("\"serve_rails_active\":true"), "{ready}");
    let expected_static = format!(
        "\"serve_rails_static\":\"{}\"",
        root.join("public").display()
    );
    assert!(ready.contains(&expected_static), "{ready}");
    assert!(
        ready.contains("\"slow_client_keepalive_idle_timeout_enforced\":true"),
        "{ready}"
    );
}

#[test]
fn serve_rails_missing_public_soft_disables_static() {
    // AC-e2 (owner decision): a root WITHOUT public/ boots with a helpful warning,
    // static serving off — the request path reaches the worker — while the keepalive
    // posture still applies. The warning + posture line are asserted on the
    // --check-config surface (panel P5a: emitted before the early return).
    let _guard = serial_test();
    let fixture = Fixture::new("serve-rails-no-public");
    let root = fixture.dir.join("api-app");
    fs::create_dir_all(&root).unwrap();
    let root_env = root.to_string_lossy().into_owned();
    // The worker socket must exist for a valid config to construct under --check-config;
    // the recording worker also serves the live-edge phase below.
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 2);

    let check = edge_check_config_output(
        "127.0.0.1:0",
        &fixture.socket,
        &[("OXO_EDGE_SERVE_RAILS", root_env.clone())],
    );
    assert!(check.status.success(), "soft-disable must not refuse boot");
    let stderr = String::from_utf8_lossy(&check.stderr);
    assert!(
        stderr.contains("oxo_edge_config_warning no static asset directory"),
        "{stderr}"
    );
    assert!(
        stderr.contains("serve-rails: keepalive=on sse=on static=off"),
        "the posture line must reach --check-config users: {stderr}"
    );

    // Live edge: static is off (the asset path reaches the worker) and keepalive is on.
    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[("OXO_EDGE_SERVE_RAILS", root_env.as_str())],
    );
    wait_for_tcp(port);
    let mut client = KaClient::connect(port);
    client.send(b"GET /assets/anything.css HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(
        client.read_response().status,
        200,
        "worker answers: static off"
    );
    assert!(
        recorded.recv_timeout(Duration::from_secs(2)).is_ok(),
        "with static soft-disabled the asset path must reach the worker"
    );
    client.send(b"GET /again HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(
        client.read_response().status,
        200,
        "keepalive posture still applies under static soft-disable"
    );
}

#[test]
fn serve_rails_missing_root_refuses_boot() {
    // AC-e2 / panel P3: a missing (typo'd) root is a fail-closed boot refusal
    // naming --serve-rails — UNCONDITIONALLY, even when --static-rails-preset overrides
    // the mounts (the root stays the posture anchor).
    let _guard = serial_test();
    let fixture = Fixture::new("serve-rails-typo-root");
    let missing = fixture.dir.join("does-not-exist");
    let missing_env = missing.to_string_lossy().into_owned();
    let good_override = build_rails_root(&fixture, true).join("public");

    let plain = edge_output(
        "127.0.0.1:0",
        &fixture.socket,
        &[("OXO_EDGE_SERVE_RAILS", missing_env.clone())],
    );
    assert!(!plain.status.success());
    let stderr = String::from_utf8_lossy(&plain.stderr);
    assert!(stderr.contains("--serve-rails"), "{stderr}");
    assert!(stderr.contains("missing or not a directory"), "{stderr}");

    let with_override = edge_output(
        "127.0.0.1:0",
        &fixture.socket,
        &[
            ("OXO_EDGE_SERVE_RAILS", missing_env),
            (
                "OXO_EDGE_STATIC_RAILS_PRESET",
                good_override.to_string_lossy().into_owned(),
            ),
        ],
    );
    assert!(
        !with_override.status.success(),
        "a typo'd root must refuse even when the static dir is overridden"
    );
    let stderr = String::from_utf8_lossy(&with_override.stderr);
    assert!(stderr.contains("--serve-rails"), "{stderr}");
}

#[test]
fn serve_rails_static_dir_override_wins() {
    // AC-e3: --static-rails-preset names the static dir explicitly; serve-rails
    // still sets the posture but derives no mounts of its own.
    let _guard = serial_test();
    let fixture = Fixture::new("serve-rails-override");
    let root = build_rails_root(&fixture, true); // has app-cafe123.css
    let override_public = fixture.dir.join("other-public");
    fs::create_dir_all(override_public.join("assets")).unwrap();
    fs::write(
        override_public.join("assets/theme-beef456.css"),
        b"body{color:plum}",
    )
    .unwrap();
    let listener = bind_worker_socket(&fixture.socket);
    let _recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 1);
    let port = free_port();
    let root_env = root.to_string_lossy().into_owned();
    let override_env = override_public.to_string_lossy().into_owned();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[
            ("OXO_EDGE_SERVE_RAILS", root_env.as_str()),
            ("OXO_EDGE_STATIC_RAILS_PRESET", override_env.as_str()),
        ],
    );
    wait_for_tcp(port);

    let mut client = KaClient::connect(port);
    // The override dir's asset is served...
    client.send(b"GET /assets/theme-beef456.css HTTP/1.1\r\nHost: app.test\r\n\r\n");
    let hit = client.read_response();
    assert_eq!(hit.status, 200);
    assert_eq!(hit.body, b"body{color:plum}");
    // ...and the serve-rails root's asset is NOT (strict /assets mount on the override
    // dir answers 404 itself — proof the derivation did not also mount the root).
    client.send(b"GET /assets/app-cafe123.css HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(
        client.read_response().status,
        404,
        "the serve-rails-derived dir must not be mounted when the override is present"
    );
}

#[test]
fn serve_rails_missing_assets_serves_fallthrough_only() {
    // AC-e2 / panel P1 (HIGH): root + public exist, public/assets does not (API-only
    // apps, pre-`assets:precompile` checkouts). Boot must NOT be refused: only the /
    // fallthrough mount is derived, public files still serve, /assets/* falls through to
    // the worker, and the operator is told to run assets:precompile.
    let _guard = serial_test();
    let fixture = Fixture::new("serve-rails-no-assets");
    let root = build_rails_root(&fixture, false);
    let root_env = root.to_string_lossy().into_owned();
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 1);

    let check = edge_check_config_output(
        "127.0.0.1:0",
        &fixture.socket,
        &[("OXO_EDGE_SERVE_RAILS", root_env.clone())],
    );
    assert!(
        check.status.success(),
        "missing public/assets must not refuse boot (panel P1)"
    );
    let stderr = String::from_utf8_lossy(&check.stderr);
    assert!(stderr.contains("assets:precompile"), "{stderr}");

    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[("OXO_EDGE_SERVE_RAILS", root_env.as_str())],
    );
    wait_for_tcp(port);

    let mut client = KaClient::connect(port);
    // public/ files serve statically through the fallthrough mount.
    client.send(b"GET /hello.txt HTTP/1.1\r\nHost: app.test\r\n\r\n");
    let public_file = client.read_response();
    assert_eq!(public_file.status, 200);
    assert_eq!(public_file.body, b"public-file");
    // /assets/* has no strict mount: the miss falls through to the worker.
    client.send(b"GET /assets/late.css HTTP/1.1\r\nHost: app.test\r\n\r\n");
    assert_eq!(client.read_response().status, 200);
    assert!(
        recorded.recv_timeout(Duration::from_secs(2)).is_ok(),
        "without public/assets the asset path must fall through to the worker"
    );
}

#[test]
fn serve_rails_sse_streams_and_explicit_env_off_beats_preset() {
    // AC-e5 (panel P6) + the env-beats-preset channel (panel P7, proven
    // out-of-process): under the preset an SSE request streams end-to-end; with
    // OXO_EDGE_SSE=0 + OXO_EDGE_KEEPALIVE=0 the same preset serves an SSE
    // reject and one-shot connections — explicit env wins over the preset.
    let _guard = serial_test();
    let fixture = Fixture::new("serve-rails-sse");
    let root = build_rails_root(&fixture, true);
    let root_env = root.to_string_lossy().into_owned();
    {
        let listener = bind_worker_socket(&fixture.socket);
        let recorded = spawn_recording_worker(
            listener,
            Some(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 12\r\nConnection: close\r\n\r\ndata: ready\n\n"
                    .to_vec(),
            ),
        );
        let port = free_port();
        let _edge = EdgeProcess::spawn_with_env(
            port,
            &fixture.socket,
            1024,
            &[("OXO_EDGE_SERVE_RAILS", root_env.as_str())],
        );
        wait_for_tcp(port);
        // CL-framed read (KaClient): under the preset's keepalive the edge may hold the
        // connection open after the bounded SSE response, so a read-to-EOF would stall.
        let mut client = KaClient::connect(port);
        client.send(b"GET /events HTTP/1.1\r\nHost: app.test\r\nAccept: text/event-stream\r\n\r\n");
        let response = client.read_response();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"data: ready\n\n");
        assert!(
            recorded.recv_timeout(Duration::from_secs(2)).is_ok(),
            "the preset must admit SSE to the worker"
        );
    }
    {
        let fixture = Fixture::new("serve-rails-sse-off");
        let root = build_rails_root(&fixture, true);
        let root_env = root.to_string_lossy().into_owned();
        let listener = bind_worker_socket(&fixture.socket);
        let recorded = spawn_recording_worker_many(listener, RESPONSE_OK.to_vec(), 1);
        let port = free_port();
        let _edge = EdgeProcess::spawn_with_env(
            port,
            &fixture.socket,
            1024,
            &[
                ("OXO_EDGE_SERVE_RAILS", root_env.as_str()),
                ("OXO_EDGE_SSE", "0"),
                ("OXO_EDGE_KEEPALIVE", "0"),
            ],
        );
        wait_for_tcp(port);
        // Explicit OXO_EDGE_SSE=0 beats the preset: SSE is a stable reject that
        // never reaches the worker.
        let response = send_tcp(
            port,
            b"GET /events HTTP/1.1\r\nHost: app.test\r\nAccept: text/event-stream\r\n\r\n",
        );
        assert!(
            !String::from_utf8_lossy(&response).contains("200 OK"),
            "explicit SSE=0 must beat the preset"
        );
        assert!(
            recorded.recv_timeout(Duration::from_millis(800)).is_err(),
            "the rejected SSE request must not reach the worker"
        );
        // Explicit OXO_EDGE_KEEPALIVE=0 beats the preset: one-shot close.
        let mut client = KaClient::connect(port);
        client.send(b"GET /one HTTP/1.1\r\nHost: app.test\r\n\r\n");
        let resp = client.read_response();
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.header("connection")
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("close"),
            "explicit KEEPALIVE=0 must beat the preset (one-shot)"
        );
        client.expect_closed();
    }
}

#[cfg(feature = "tls-rustls")]
#[test]
fn serve_rails_does_not_satisfy_public_mode_gates() {
    // AC-e4 (panel-reviewed fail-closed contract): the preset touches only
    // keepalive/sse/static — it must not flip max_body_explicit (or any other explicit
    // gate), so smoke-beta without an explicit body cap still refuses to boot.
    let _guard = serial_test();
    let fixture = Fixture::new("serve-rails-public-gate");
    let root = build_rails_root(&fixture, true);
    let (cert, key) = generate_tls_cert(&fixture.dir);

    let missing_body_cap = edge_output(
        "0.0.0.0:0",
        &fixture.socket,
        &[
            ("OXO_EDGE_SERVE_RAILS", root.to_string_lossy().into_owned()),
            ("OXO_EDGE_PUBLIC_MODE", "smoke-beta".to_string()),
            ("OXO_EDGE_TLS", "1".to_string()),
            ("OXO_EDGE_TLS_CERT", cert.to_string_lossy().into_owned()),
            ("OXO_EDGE_TLS_KEY", key.to_string_lossy().into_owned()),
            ("OXO_EDGE_PUBLIC_IDENTITY", "direct-public".to_string()),
            ("OXO_EDGE_SERVER_NAME", "app.test".to_string()),
        ],
    );
    assert!(!missing_body_cap.status.success());
    let stderr = String::from_utf8_lossy(&missing_body_cap.stderr);
    assert!(stderr.contains("explicit request body cap"), "{stderr}");
}

#[test]
fn serve_rails_check_config_pin_audit_catches_boot_refusals() {
    // AC-e6 (panel P10): --check-config now runs the static docroot pin audit, so a
    // dry-run refuses configurations real boot would refuse. An explicit
    // --static-rails-preset pointing at a missing dir passes spec parsing (explicit
    // config has no soft existence check) and previously sailed through --check-config;
    // the pin audit must now catch it.
    let _guard = serial_test();
    let fixture = Fixture::new("serve-rails-pin-audit");
    let missing_dir = fixture.dir.join("no-such-public");
    // The worker socket must exist for the config to be otherwise valid.
    let _listener = bind_worker_socket(&fixture.socket);

    let output = edge_check_config_output(
        "127.0.0.1:0",
        &fixture.socket,
        &[(
            "OXO_EDGE_STATIC_RAILS_PRESET",
            missing_dir.to_string_lossy().into_owned(),
        )],
    );
    assert!(
        !output.status.success(),
        "--check-config must refuse what real boot refuses (pin audit)"
    );

    // And a valid full layout passes, printing the posture line for dry-run users.
    let root = build_rails_root(&fixture, true);
    let ok = edge_check_config_output(
        "127.0.0.1:0",
        &fixture.socket,
        &[("OXO_EDGE_SERVE_RAILS", root.to_string_lossy().into_owned())],
    );
    assert!(ok.status.success());
    let stderr = String::from_utf8_lossy(&ok.stderr);
    assert!(
        stderr.contains("serve-rails: keepalive=on sse=on static="),
        "{stderr}"
    );
}

// M2 (bench-only native floor). These tests exist ONLY when the crate is built with
// `--features edge-bench`; in a shipped build the `/edge-bench` route and these tests are
// absent. They pin the two halves of the "never ships enabled" contract: the route answers
// natively (skipping the worker hop) ONLY when the boot flag is set, and falls through to
// the worker otherwise.
#[cfg(feature = "edge-bench")]
#[test]
fn edge_bench_route_answers_natively_when_flag_on() {
    let _guard = serial_test();
    let fixture = Fixture::new("edge-bench-on");
    let listener = bind_worker_socket(&fixture.socket);
    // The worker would answer "ok"; the native stub must make the request never reach it.
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024,
        &[("OXO_EDGE_NATIVE_BENCH", "1")],
    );
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"GET /edge-bench HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n",
    );
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.contains("200 OK"),
        "native /edge-bench must 200: {text}"
    );
    assert!(
        response.ends_with(b"oxo-bench-ok"),
        "native body must be byte-identical to /bench: {text}"
    );
    assert!(
        text.to_ascii_lowercase().contains("content-length: 16"),
        "framing must be explicit Content-Length: {text}"
    );
    // The defining property of the floor: Ruby/the worker hop is skipped entirely.
    assert!(
        recorded.recv_timeout(Duration::from_millis(800)).is_err(),
        "native /edge-bench must NOT touch the worker"
    );
}

#[cfg(feature = "edge-bench")]
#[test]
fn edge_bench_route_inert_and_falls_through_when_flag_off() {
    let _guard = serial_test();
    let fixture = Fixture::new("edge-bench-off");
    let listener = bind_worker_socket(&fixture.socket);
    let recorded = spawn_recording_worker(listener, Some(RESPONSE_OK.to_vec()));
    let port = free_port();
    // Feature compiled in, but the boot flag is unset: the route must be INERT — the
    // request falls through to the worker hop (observable inertness), not answered natively.
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024);
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"GET /edge-bench HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n",
    );
    // Worker dispatch WAS attempted (the inertness signal) and its "ok" body came back.
    let worker_request = recorded
        .recv_timeout(Duration::from_secs(2))
        .expect("flag-off /edge-bench must fall through to the worker")
        .expect("edge should connect to the worker");
    assert!(String::from_utf8_lossy(&worker_request).starts_with("GET /edge-bench HTTP/1.1\r\n"));
    assert!(
        response.ends_with(b"ok") && !response.ends_with(b"oxo-bench-ok"),
        "flag-off response must be the worker's, not the native body"
    );
}

struct EdgeProcess {
    child: Child,
}

impl EdgeProcess {
    fn spawn(port: u16, socket: &Path, max_body: u64) -> Self {
        Self::spawn_pool(port, &[socket], max_body)
    }

    fn spawn_with_env(port: u16, socket: &Path, max_body: u64, extra_env: &[(&str, &str)]) -> Self {
        Self::spawn_pool_with_env(port, &[socket], max_body, extra_env)
    }

    fn spawn_pool(port: u16, sockets: &[&Path], max_body: u64) -> Self {
        Self::spawn_pool_with_env(port, sockets, max_body, &[])
    }

    fn spawn_pool_with_env(
        port: u16,
        sockets: &[&Path],
        max_body: u64,
        extra_env: &[(&str, &str)],
    ) -> Self {
        let socket_list = sockets
            .iter()
            .map(|socket| socket.to_string_lossy())
            .collect::<Vec<_>>()
            .join(",");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
        cmd.env("OXO_EDGE_WORKER_HOP", "http"); // fake worker speaks HTTP; frame hop is proven by real_s1_e2e
        cmd.env("OXO_EDGE_BIND", format!("127.0.0.1:{port}"))
            .env("OXO_EDGE_WORKER_SOCKET", sockets[0])
            .env("OXO_EDGE_WORKER_SOCKETS", socket_list)
            .env("OXO_EDGE_MAX_BODY", max_body.to_string())
            .env("OXO_EDGE_SCHEME", "http")
            .env("OXO_EDGE_SERVER_NAME", "localhost")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in extra_env {
            cmd.env(name, value);
        }
        let child = cmd.spawn().expect("spawn oxo-pingora-edge");
        Self { child }
    }

    #[cfg(feature = "tls-rustls")]
    fn spawn_tls(port: u16, socket: &Path, max_body: u64, cert: &Path, key: &Path) -> Self {
        Self::spawn_tls_bind(
            format!("127.0.0.1:{port}"),
            socket,
            max_body,
            cert,
            key,
            &[],
        )
    }

    #[cfg(feature = "tls-rustls")]
    fn spawn_public_alpha(
        port: u16,
        socket: &Path,
        max_body: u64,
        cert: &Path,
        key: &Path,
    ) -> Self {
        Self::spawn_tls_bind(
            format!("0.0.0.0:{port}"),
            socket,
            max_body,
            cert,
            key,
            &[
                ("OXO_EDGE_PUBLIC_MODE", "alpha"),
                ("OXO_EDGE_PUBLIC_IDENTITY", "direct-public"),
            ],
        )
    }

    #[cfg(feature = "tls-rustls")]
    fn spawn_public_smoke_beta(
        port: u16,
        admin_port: u16,
        socket: &Path,
        max_body: u64,
        cert: &Path,
        key: &Path,
    ) -> Self {
        Self::spawn_public_smoke_beta_with_env(port, admin_port, socket, max_body, cert, key, &[])
    }

    #[cfg(feature = "tls-rustls")]
    fn spawn_public_smoke_beta_with_env(
        port: u16,
        admin_port: u16,
        socket: &Path,
        max_body: u64,
        cert: &Path,
        key: &Path,
        extra_env: &[(&str, &str)],
    ) -> Self {
        let admin_bind = format!("127.0.0.1:{admin_port}");
        let mut env = vec![
            ("OXO_EDGE_PUBLIC_MODE", "smoke-beta"),
            ("OXO_EDGE_PUBLIC_IDENTITY", "direct-public"),
            ("OXO_EDGE_ADMIN_BIND", admin_bind.as_str()),
            ("OXO_EDGE_MAX_IN_FLIGHT_REQUESTS", "128"),
        ];
        env.extend_from_slice(extra_env);
        Self::spawn_tls_bind(format!("0.0.0.0:{port}"), socket, max_body, cert, key, &env)
    }

    #[cfg(feature = "tls-rustls")]
    fn spawn_tls_bind(
        bind: String,
        socket: &Path,
        max_body: u64,
        cert: &Path,
        key: &Path,
        extra_env: &[(&str, &str)],
    ) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
        cmd.env("OXO_EDGE_WORKER_HOP", "http"); // fake worker speaks HTTP; frame hop is proven by real_s1_e2e
        cmd.env("OXO_EDGE_BIND", bind)
            .env("OXO_EDGE_WORKER_SOCKET", socket)
            .env("OXO_EDGE_MAX_BODY", max_body.to_string())
            .env("OXO_EDGE_TLS", "1")
            .env("OXO_EDGE_TLS_CERT", cert)
            .env("OXO_EDGE_TLS_KEY", key)
            .env("OXO_EDGE_TLS_H2", "1")
            .env("OXO_EDGE_SCHEME", "http")
            .env("OXO_EDGE_SERVER_NAME", "app.test")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in extra_env {
            cmd.env(name, value);
        }
        let child = cmd.spawn().expect("spawn TLS oxo-pingora-edge");
        Self { child }
    }
}

fn edge_output(bind: &str, socket: &Path, envs: &[(&str, String)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
    cmd.env("OXO_EDGE_WORKER_HOP", "http"); // fake worker speaks HTTP; frame hop is proven by real_s1_e2e
    cmd.env("OXO_EDGE_BIND", bind)
        .env("OXO_EDGE_WORKER_SOCKET", socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    for (name, value) in envs {
        cmd.env(name, value);
    }
    cmd.output().expect("run oxo-pingora-edge")
}

// run the edge with `--check-config`, which validates and returns Ok without binding,
// so a VALID config exits 0 (unlike `edge_output`, which is only used for fail-closed cases
// that exit on their own). Captures stderr for the config-honesty NOT-ENFORCED lines.
fn edge_check_config_output(bind: &str, socket: &Path, envs: &[(&str, String)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
    cmd.env("OXO_EDGE_WORKER_HOP", "http"); // fake worker speaks HTTP; frame hop is proven by real_s1_e2e
    cmd.arg("--check-config")
        .env("OXO_EDGE_BIND", bind)
        .env("OXO_EDGE_WORKER_SOCKET", socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    for (name, value) in envs {
        cmd.env(name, value);
    }
    cmd.output().expect("run oxo-pingora-edge --check-config")
}
impl Drop for EdgeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// Deliberately per-suite (RR3): the CN/SAN here is load-bearing in this suite's assertions.
#[cfg(feature = "tls-rustls")]
fn generate_tls_cert(dir: &Path) -> (PathBuf, PathBuf) {
    generate_tls_cert_for(dir, "app.test")
}

#[cfg(feature = "tls-rustls")]
fn generate_tls_cert_for(dir: &Path, dns_name: &str) -> (PathBuf, PathBuf) {
    let cert = dir.join(format!("{dns_name}.cert.pem"));
    let key = dir.join(format!("{dns_name}.key.pem"));
    let output = Command::new("openssl")
        .arg("req")
        .arg("-x509")
        .arg("-newkey")
        .arg("rsa:2048")
        .arg("-nodes")
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .arg("-subj")
        .arg(format!("/CN={dns_name}"))
        .arg("-addext")
        .arg(format!("subjectAltName=DNS:{dns_name},IP:127.0.0.1"))
        .arg("-days")
        .arg("1")
        .output()
        .expect("run openssl");
    assert!(
        output.status.success(),
        "openssl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    (cert, key)
}

#[cfg(feature = "tls-rustls")]
fn curl_https(port: u16, http2: bool, path: &str) -> String {
    curl_https_with_args(port, http2, "app.test", path, &[], true)
}

#[cfg(feature = "tls-rustls")]
fn curl_https_with_args(
    port: u16,
    http2: bool,
    host: &str,
    path: &str,
    extra_args: &[String],
    fail_on_http_error: bool,
) -> String {
    let url = format!("https://{host}:{port}{path}");
    let resolve = format!("{host}:{port}:127.0.0.1");
    let mut cmd = Command::new("curl");
    if fail_on_http_error {
        cmd.arg("--fail");
    }
    cmd.arg("--silent")
        .arg("--show-error")
        .arg("--insecure")
        .arg("--noproxy")
        .arg("*")
        .arg("--max-time")
        .arg("5")
        .arg("--dump-header")
        .arg("-")
        .arg("--resolve")
        .arg(resolve);
    if http2 {
        cmd.arg("--http2");
    } else {
        cmd.arg("--http1.1");
    }
    for arg in extra_args {
        cmd.arg(arg);
    }
    let output = cmd.arg(url).output().expect("run curl");
    if fail_on_http_error {
        assert!(
            output.status.success(),
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else if !output.status.success() && output.stdout.is_empty() {
        return format!("curl-error: {}", String::from_utf8_lossy(&output.stderr));
    }
    String::from_utf8_lossy(&output.stdout).into_owned()
}
#[cfg(feature = "tls-rustls")]
fn send_raw_h2_tls_frames(port: u16, frames: &[u8]) {
    let connect = format!("127.0.0.1:{port}");
    let mut child = Command::new("openssl")
        .arg("s_client")
        .arg("-quiet")
        .arg("-alpn")
        .arg("h2")
        .arg("-servername")
        .arg("app.test")
        .arg("-connect")
        .arg(connect)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn openssl s_client");

    if let Some(mut stdin) = child.stdin.take() {
        if let Err(err) = stdin.write_all(frames) {
            assert!(
                matches!(
                    err.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ),
                "write raw H2 frames: {err}"
            );
        }
        let _ = stdin.flush();
    }

    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if child.try_wait().expect("poll openssl s_client").is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(feature = "tls-rustls")]
fn h2_rapid_reset_frames() -> Vec<u8> {
    let mut frames = h2_preface_and_settings();
    let headers = hpack_post_headers_for_app_test(10);
    for index in 0..32u32 {
        let stream_id = index * 2 + 1;
        frames.extend(h2_frame(0x1, 0x4, stream_id, &headers));
        frames.extend(h2_frame(0x3, 0x0, stream_id, &[0, 0, 0, 8]));
    }
    frames
}

#[cfg(feature = "tls-rustls")]
fn h2_continuation_flood_frames() -> Vec<u8> {
    let mut frames = h2_preface_and_settings();
    frames.extend(h2_frame(0x1, 0x0, 1, &[0x83]));
    for _ in 0..128 {
        frames.extend(h2_frame(0x9, 0x0, 1, &[0; 64]));
    }
    frames
}

#[cfg(feature = "tls-rustls")]
fn h2_zero_window_update_frames() -> Vec<u8> {
    let mut frames = h2_preface_and_settings();
    frames.extend(h2_frame(0x8, 0x0, 0, &[0, 0, 0, 0]));
    frames
}

#[cfg(feature = "tls-rustls")]
fn h2_preface_and_settings() -> Vec<u8> {
    let mut frames = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    frames.extend(h2_frame(0x4, 0x0, 0, &[]));
    frames
}

// A gRPC-shaped H2 request that omits `:authority` AND exceeds the
// MAX_REQUEST_HEADERS count cap, for the 400-before-431 ordering pin.
#[cfg(feature = "tls-rustls")]
fn h2_grpc_over_count_headers_without_authority_frames() -> Vec<u8> {
    let mut frames = h2_preface_and_settings();
    // :method POST, :path /, :scheme https — static-table indexed; :authority
    // is deliberately absent.
    let mut headers = vec![0x83, 0x84, 0x87];
    headers.extend(hpack_literal_header("content-type", "application/grpc"));
    headers.extend(hpack_literal_header("te", "trailers"));
    for index in 0..101 {
        headers.extend(hpack_literal_header(&format!("x-fill-{index}"), "v"));
    }
    // END_STREAM | END_HEADERS on stream 1.
    frames.extend(h2_frame(0x1, 0x5, 1, &headers));
    frames
}

// HPACK literal header field without indexing, new name, no Huffman coding.
#[cfg(feature = "tls-rustls")]
fn hpack_literal_header(name: &str, value: &str) -> Vec<u8> {
    let mut bytes = vec![0x00];
    bytes.push(u8::try_from(name.len()).expect("short header name"));
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(u8::try_from(value.len()).expect("short header value"));
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

#[cfg(feature = "tls-rustls")]
fn hpack_post_headers_for_app_test(content_length: usize) -> Vec<u8> {
    let mut payload = vec![0x83, 0x84, 0x87, 0x01, 0x08];
    payload.extend_from_slice(b"app.test");
    payload.extend_from_slice(&[0x0f, 0x0d]);
    let len = content_length.to_string();
    payload.push(u8::try_from(len.len()).expect("small content-length"));
    payload.extend_from_slice(len.as_bytes());
    payload
}

#[cfg(feature = "tls-rustls")]
fn h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 0x00ff_ffff);
    let len = payload.len() as u32;
    let stream_id = stream_id & 0x7fff_ffff;
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.push(((len >> 16) & 0xff) as u8);
    frame.push(((len >> 8) & 0xff) as u8);
    frame.push((len & 0xff) as u8);
    frame.push(frame_type);
    frame.push(flags);
    frame.push(((stream_id >> 24) & 0xff) as u8);
    frame.push(((stream_id >> 16) & 0xff) as u8);
    frame.push(((stream_id >> 8) & 0xff) as u8);
    frame.push((stream_id & 0xff) as u8);
    frame.extend_from_slice(payload);
    frame
}
fn bind_worker_socket(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    listener
}

fn spawn_recording_worker(
    listener: UnixListener,
    response: Option<Vec<u8>>,
) -> Receiver<Option<Vec<u8>>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = read_http_request(&mut stream);
                    if let Some(response) = response {
                        let _ = stream.write_all(&response);
                    }
                    let _ = tx.send(Some(request));
                    return;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    rx
}

fn spawn_recording_worker_many(
    listener: UnixListener,
    response: Vec<u8>,
    count: usize,
) -> Receiver<Option<Vec<u8>>> {
    spawn_recording_worker_many_with_delay(listener, response, count, Duration::ZERO)
}

fn spawn_recording_worker_many_with_delay(
    listener: UnixListener,
    response: Vec<u8>,
    count: usize,
    response_delay: Duration,
) -> Receiver<Option<Vec<u8>>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut accepted = 0usize;
        while accepted < count {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = read_http_request(&mut stream);
                    let _ = tx.send(Some(request));
                    if !response_delay.is_zero() {
                        thread::sleep(response_delay);
                    }
                    let _ = stream.write_all(&response);
                    accepted += 1;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    rx
}
fn spawn_chunked_streaming_worker_many(
    listener: UnixListener,
    chunks: Vec<Vec<u8>>,
    hold_before_final: Duration,
    count: usize,
) -> Receiver<Option<Vec<u8>>> {
    spawn_chunked_streaming_worker_many_with_content_type(
        listener,
        "text/plain",
        chunks,
        Duration::ZERO,
        hold_before_final,
        count,
    )
}

fn spawn_chunked_streaming_worker_many_with_content_type(
    listener: UnixListener,
    content_type: &'static str,
    chunks: Vec<Vec<u8>>,
    delay_between_chunks: Duration,
    hold_before_final: Duration,
    count: usize,
) -> Receiver<Option<Vec<u8>>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut accepted = 0usize;
        while accepted < count {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = read_http_request(&mut stream);
                    let _ = tx.send(Some(request));
                    let chunks = chunks.clone();
                    thread::spawn(move || {
                        write_chunked_response(
                            stream,
                            content_type,
                            chunks,
                            delay_between_chunks,
                            hold_before_final,
                        );
                    });
                    accepted += 1;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    rx
}

fn write_chunked_response(
    mut stream: UnixStream,
    content_type: &str,
    chunks: Vec<Vec<u8>>,
    delay_between_chunks: Duration,
    hold_before_final: Duration,
) {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
    let _ = stream.write_all(header.as_bytes());
    let chunk_count = chunks.len();
    for (index, chunk) in chunks.into_iter().enumerate() {
        let header = format!("{:x}\r\n", chunk.len());
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(&chunk);
        let _ = stream.write_all(b"\r\n");
        let _ = stream.flush();
        if !delay_between_chunks.is_zero() && index + 1 < chunk_count {
            thread::sleep(delay_between_chunks);
        }
    }
    if !hold_before_final.is_zero() {
        thread::sleep(hold_before_final);
    }
    let _ = stream.write_all(b"0\r\n\r\n");
}
fn read_http_request(stream: &mut UnixStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(header_end) = find_header_end(&buf) {
            let body_len = content_length(&buf[..header_end]).unwrap_or(0);
            if buf.len() >= header_end + 4 + body_len {
                break;
            }
        }
    }
    buf
}

fn worker_body(request: &[u8]) -> &[u8] {
    let header_end = find_header_end(request).expect("worker request header terminator");
    &request[header_end + 4..]
}
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &[u8]) -> Option<usize> {
    for line in headers.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = String::from_utf8_lossy(&line[..colon]);
        if name.eq_ignore_ascii_case("content-length") {
            let value = String::from_utf8_lossy(&line[colon + 1..]);
            return value.trim().parse().ok();
        }
    }
    None
}

// Deliberately per-suite (RR3): startup deadlines/diagnostics are fixture-specific.
fn wait_for_tcp(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("edge did not bind to 127.0.0.1:{port}");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

// Deliberately per-suite (RR3): return type/read-timeout differ across suites.
fn send_tcp(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(err) => panic!("read edge response: {err}"),
        }
    }
    response
}

fn send_tcp_with_write_shutdown(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(request).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    read_tcp_response(stream)
}

fn read_tcp_response(mut stream: TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(err) => panic!("read edge response: {err}"),
        }
    }
    response
}

#[cfg(feature = "tls-rustls")]
fn tls_h1_start_request(port: u16, request: &[u8]) -> (Child, std::process::ChildStdin) {
    let mut child = Command::new("openssl")
        .arg("s_client")
        .arg("-quiet")
        .arg("-servername")
        .arg("app.test")
        .arg("-connect")
        .arg(format!("127.0.0.1:{port}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn openssl s_client");
    let mut stdin = child.stdin.take().expect("openssl stdin");
    stdin.write_all(request).expect("write openssl request");
    stdin.flush().expect("flush openssl request");
    (child, stdin)
}

fn wait_until_admin_contains(admin_port: u16, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last = String::new();
    while Instant::now() < deadline {
        last = String::from_utf8_lossy(&send_tcp(
            admin_port,
            b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
        ))
        .into_owned();
        if last.contains(needle) {
            return last;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("admin response never contained {needle:?}: {last}");
}

fn assert_client_error_or_close(response: &[u8]) {
    if response.is_empty() {
        return;
    }
    let response_text = String::from_utf8_lossy(response);
    assert!(
        response_text.starts_with("HTTP/1.1 4"),
        "expected client error or closed connection, got response bytes: {response_text:?}"
    );
}

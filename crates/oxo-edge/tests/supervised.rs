//! End-to-end tests for the supervised path: a real Ruby worker behind the edge.
//! Well-formed requests go through a proper hyper client (correct HTTP/1.1 framing);
//! malformed-framing and direct-to-worker cases use raw sockets. Requires `ruby`
//! (+ the `rack` gem) on PATH.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use oxo_core::{Config, WorkerKind};
use oxo_edge::{serve_listener, SupervisedRubyHandler};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn trivial_app() -> PathBuf {
    // <workspace>/crates/oxo-edge -> <workspace>/ruby/trivial_app.ru (no `..` segments)
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("ruby")
        .join("trivial_app.ru")
}

fn config(max_body: usize) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        worker: WorkerKind::Shim,
        app: trivial_app(),
        max_body_bytes: max_body,
        ..Default::default()
    }
}

struct TestServer {
    addr: SocketAddr,
    handler: Arc<SupervisedRubyHandler>,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn start(max_body: usize) -> TestServer {
        let cfg = config(max_body);
        let handler = Arc::new(
            SupervisedRubyHandler::spawn(&cfg)
                .await
                .expect("spawn ruby worker"),
        );
        let listener = TcpListener::bind(cfg.bind).await.expect("bind");
        let addr = listener.local_addr().unwrap();
        let h = handler.clone();
        let c = Arc::new(cfg);
        let task = tokio::spawn(async move {
            let _ = serve_listener(listener, c, h).await;
        });
        TestServer {
            addr,
            handler,
            task,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Drive the edge with a real HTTP/1.1 client (proper framing; no reliance on the
/// server closing the connection). Returns `(status, body)`.
async fn http(addr: SocketAddr, method: &str, path: &str, body: &[u8]) -> (u16, String) {
    let fut = async {
        let stream = TcpStream::connect(addr).await.expect("connect");
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .expect("handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "test")
            .body(Full::new(Bytes::copy_from_slice(body)))
            .expect("build request");
        let resp = sender.send_request(req).await.expect("send request");
        let status = resp.status().as_u16();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("collect")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    };
    tokio::time::timeout(Duration::from_secs(15), fut)
        .await
        .expect("http request timed out")
}

/// Raw write + read-to-EOF, bounded by a timeout. Used where the peer closes after one
/// response: the worker (Connection: close) and hyper on a malformed-request 4xx.
async fn raw(addr: SocketAddr, request: &[u8]) -> String {
    let fut = async {
        let mut s = TcpStream::connect(addr).await.expect("connect");
        s.write_all(request).await.expect("write");
        s.flush().await.ok();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).into_owned()
    };
    tokio::time::timeout(Duration::from_secs(8), fut)
        .await
        .unwrap_or_default()
}

fn raw_status(resp: &str) -> u16 {
    resp.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread")]
async fn get_root_returns_200_from_rack_app() {
    let srv = TestServer::start(1 << 20).await;
    let (status, body) = http(srv.addr, "GET", "/hello?x=1", b"").await;
    assert_eq!(status, 200, "body: {body}");
    assert!(body.contains("Hello from Oxo!"), "body: {body}");
    assert!(body.contains("PATH_INFO=/hello"), "body: {body}");
    assert!(body.contains("QUERY_STRING=x=1"), "body: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ruby_raise_returns_500_and_worker_survives() {
    let srv = TestServer::start(1 << 20).await;
    let (status, _) = http(srv.addr, "GET", "/raise", b"").await;
    assert_eq!(status, 500);
    // The worker (a separate process) must still answer the next request.
    let (status2, body2) = http(srv.addr, "GET", "/hello", b"").await;
    assert_eq!(status2, 200, "body: {body2}");
    assert!(body2.contains("Hello from Oxo!"));
}

#[tokio::test(flavor = "multi_thread")]
async fn post_echo_roundtrips_body() {
    let srv = TestServer::start(1 << 20).await;
    let payload = b"ping-12345";
    let (status, body) = http(srv.addr, "POST", "/echo", payload).await;
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body.as_bytes(), payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_body_returns_413() {
    let srv = TestServer::start(16).await; // 16-byte cap
    let (status, _) = http(srv.addr, "POST", "/echo", &b"x".repeat(100)).await;
    assert_eq!(status, 413);
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_worker_access_without_secret_is_forbidden() {
    let srv = TestServer::start(1 << 20).await;
    // Bypass the edge and hit the worker port directly — no shared secret.
    let worker = srv.handler.worker_addr();
    let resp = raw(
        worker,
        b"GET /hello HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        raw_status(&resp),
        403,
        "worker answered secret-less request: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_parser_rejects_transfer_encoding() {
    let srv = TestServer::start(1 << 20).await;
    // The worker is the back-end parser: it rejects Transfer-Encoding outright
    // (Content-Length-only framing) so it can never desync with the edge.
    let worker = srv.handler.worker_addr();
    let resp = raw(
        worker,
        b"GET /hello HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        raw_status(&resp),
        400,
        "worker accepted Transfer-Encoding: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_does_not_smuggle_on_te_cl_conflict() {
    let srv = TestServer::start(1 << 20).await;
    // Both Transfer-Encoding and Content-Length: the classic smuggling vector. hyper
    // normalizes it (TE takes precedence, per RFC 9112) and the edge re-emits canonical
    // framing to the worker, so there is no front/back desync — the client gets exactly
    // ONE well-formed response, never a smuggled second one. (The worker independently
    // rejects TE; see `worker_parser_rejects_transfer_encoding`.)
    let req = b"POST /hello HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n";
    let resp = raw(srv.addr, req).await;
    let responses = resp.matches("HTTP/1.1 ").count();
    assert_eq!(
        responses, 1,
        "expected exactly one response (no smuggling): {resp}"
    );
    assert!(raw_status(&resp) > 0, "no valid response: {resp}");
}

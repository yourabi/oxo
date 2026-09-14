//! edge-hardening tests — Ruby-free, fast, Windows-runnable.
//!
//! A tiny in-crate [`MockHandler`] implements [`RackHandler`] so these exercise the edge's
//! timeouts, slowloris defenses, connection cap, and header caps without spawning Ruby.
//! Each test builds a `Config` with one knob set and drives `serve_listener` on an
//! ephemeral loopback port.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use oxo_core::{Config, HandlerError, RackHandler, RackRequest, RackResponse};
use oxo_edge::serve_listener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;

/// A `RackHandler` with no Ruby: it can park on a gate (a `Semaphore` opened by the test),
/// sleep, and record entry/exit so tests can reason about concurrency. `entered` is bumped
/// *before* the gate so a test can detect that a request has reached the handler.
#[derive(Default)]
struct MockHandler {
    sleep: Duration,
    gate: Option<Arc<Semaphore>>,
    entered: Arc<AtomicUsize>,
    log: Arc<Mutex<Vec<(Instant, Instant)>>>,
}

impl RackHandler for MockHandler {
    async fn handle(&self, _req: RackRequest) -> Result<RackResponse, HandlerError> {
        self.entered.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();
        if let Some(g) = &self.gate {
            // Blocks until the test adds permits; the permit returns immediately (this is a
            // latch, not a concurrency limit).
            let _ = g.acquire().await;
        }
        if !self.sleep.is_zero() {
            tokio::time::sleep(self.sleep).await;
        }
        let end = Instant::now();
        self.log.lock().unwrap().push((start, end));
        Ok(RackResponse::text(200, Bytes::from_static(b"ok")))
    }
}

fn loopback0() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

struct TestServer {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start(config: Config, handler: MockHandler) -> TestServer {
    let listener = TcpListener::bind(config.bind).await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let _ = serve_listener(listener, Arc::new(config), Arc::new(handler)).await;
    });
    TestServer { addr, task }
}

/// GET `path` with a real hyper client; returns the status. Dropping the client at the end
/// closes the connection (so its server-side permit frees).
async fn http_get_status(addr: SocketAddr, path: &str) -> u16 {
    let io = TokioIo::new(TcpStream::connect(addr).await.expect("connect"));
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .uri(path)
        .header("host", "test")
        .body(Full::new(Bytes::new()))
        .expect("build request");
    let resp = sender.send_request(req).await.expect("send request");
    let status = resp.status().as_u16();
    let _ = resp.into_body().collect().await;
    status
}

/// Raw write + read-to-EOF, bounded by a timeout (used where the server closes the peer).
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

async fn wait_until<F: Fn() -> bool>(cond: F, deadline: Duration) -> bool {
    let start = Instant::now();
    loop {
        if cond() {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn defaults_still_serve_200() {
    let cfg = Config {
        bind: loopback0(),
        ..Default::default()
    };
    let srv = start(cfg, MockHandler::default()).await;
    assert_eq!(http_get_status(srv.addr, "/").await, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_handler_times_out_504() {
    let cfg = Config {
        bind: loopback0(),
        request_timeout_secs: 1,
        ..Default::default()
    };
    let h = MockHandler {
        sleep: Duration::from_secs(5),
        ..Default::default()
    };
    let srv = start(cfg, h).await;
    let started = Instant::now();
    assert_eq!(http_get_status(srv.addr, "/").await, 504);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "should 504 at ~1s, not wait out the 5s handler"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_body_does_not_reach_app_and_is_bounded() {
    let cfg = Config {
        bind: loopback0(),
        request_timeout_secs: 1,
        ..Default::default()
    };
    let h = MockHandler::default();
    let log = h.log.clone();
    let srv = start(cfg, h).await;

    // Valid head promising 1000 body bytes, but only 4 are ever sent.
    let fut = async {
        let mut s = TcpStream::connect(srv.addr).await.expect("connect");
        s.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nabcd")
            .await
            .expect("write");
        s.flush().await.ok();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await; // returns when the server gives up + closes
        String::from_utf8_lossy(&buf).into_owned()
    };
    let started = Instant::now();
    let resp = tokio::time::timeout(Duration::from_secs(6), fut)
        .await
        .unwrap_or_default();

    assert!(
        started.elapsed() < Duration::from_secs(4),
        "a slow body must be bounded by request_timeout, not hang"
    );
    assert_ne!(
        raw_status(&resp),
        200,
        "an incomplete/slow body must not be served: {resp:?}"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "the app handler must never run for an unread body"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn slowloris_header_closes_near_the_timeout() {
    let cfg = Config {
        bind: loopback0(),
        header_read_timeout_secs: 1,
        ..Default::default()
    };
    let srv = start(cfg, MockHandler::default()).await;

    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    // A partial head that never terminates (no final CRLF).
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
    s.flush().await.unwrap();

    let started = Instant::now();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(8), s.read_to_end(&mut buf)).await;
    let elapsed = started.elapsed();
    // Two-sided: closed because of the 1s timeout, not instantly and not never.
    assert!(
        elapsed >= Duration::from_millis(700),
        "closed too early ({elapsed:?}) — not the header_read_timeout"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "header_read_timeout did not close the slow head ({elapsed:?})"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_keepalive_closes_within_header_read_timeout() {
    let cfg = Config {
        bind: loopback0(),
        header_read_timeout_secs: 1,
        ..Default::default()
    };
    let srv = start(cfg, MockHandler::default()).await;

    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    // One complete request (keep-alive), then go idle — header_read_timeout re-arms for the
    // next head and must close the idle connection.
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    s.flush().await.unwrap();
    let started = Instant::now();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(8), s.read_to_end(&mut buf)).await;
    let elapsed = started.elapsed();

    assert!(
        String::from_utf8_lossy(&buf).contains(" 200"),
        "the first keep-alive request should be served: {:?}",
        String::from_utf8_lossy(&buf)
    );
    assert!(
        (Duration::from_millis(700)..Duration::from_secs(5)).contains(&elapsed),
        "idle keep-alive should close at ~header_read_timeout, got {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn connection_cap_blocks_until_a_permit_frees() {
    let gate = Arc::new(Semaphore::new(0));
    let entered = Arc::new(AtomicUsize::new(0));
    let h = MockHandler {
        gate: Some(gate.clone()),
        entered: entered.clone(),
        ..Default::default()
    };
    let cfg = Config {
        bind: loopback0(),
        max_connections: 1,
        ..Default::default()
    };
    let srv = start(cfg, h).await;
    let addr = srv.addr;

    // A occupies the single permit and parks its handler on the gate.
    let a = tokio::spawn(async move { http_get_status(addr, "/a").await });
    assert!(
        wait_until(
            || entered.load(Ordering::Relaxed) >= 1,
            Duration::from_secs(5)
        )
        .await,
        "connection A never reached the handler"
    );

    // While the only permit is held, accept() is parked — B cannot be served.
    let b = tokio::time::timeout(Duration::from_millis(700), http_get_status(addr, "/b")).await;
    assert!(
        b.is_err(),
        "B was served while the connection cap (1) was saturated"
    );

    // Release the gate → A finishes + frees the permit → traffic flows again.
    gate.add_permits(64);
    assert_eq!(a.await.unwrap(), 200);
    assert_eq!(http_get_status(addr, "/b2").await, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn too_many_headers_returns_431() {
    let cfg = Config {
        bind: loopback0(),
        max_header_count: 10,
        ..Default::default()
    };
    let srv = start(cfg, MockHandler::default()).await;

    let mut req = String::from("GET / HTTP/1.1\r\nHost: x\r\n");
    for i in 0..30 {
        req.push_str(&format!("X-H-{i}: v\r\n"));
    }
    req.push_str("\r\n");
    let resp = raw(srv.addr, req.as_bytes()).await;
    assert_eq!(
        raw_status(&resp),
        431,
        "expected 431 for a header flood over max_header_count: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn max_connection_secs_bounds_connection_lifetime() {
    // Isolate the absolute-lifetime deadline: disable the other two timeouts so only
    // max_connection_secs can close the connection. (This is the bound that also covers
    // response-write slowloris.)
    let cfg = Config {
        bind: loopback0(),
        max_connection_secs: 1,
        request_timeout_secs: 0,
        header_read_timeout_secs: 0,
        ..Default::default()
    };
    let srv = start(cfg, MockHandler::default()).await;

    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    s.flush().await.unwrap();
    let started = Instant::now();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(8), s.read_to_end(&mut buf)).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "max_connection_secs did not close the connection near its 1s deadline ({elapsed:?})"
    );
}

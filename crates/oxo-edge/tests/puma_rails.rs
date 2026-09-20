#![cfg(target_os = "linux")]

#[path = "../../../test/support/ruby.rs"]
mod ruby_fixture;

// Puma + real-Rails integration test for the supervised path.
//
// The Linux runner selects this test after installing the Rails bundle.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use oxo_core::Config;
use oxo_edge::{serve_listener, SupervisedRubyHandler};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn rails_app() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("test/fixtures/rails_app")
        .join("config.ru")
}

fn config() -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        app: rails_app(),
        // worker defaults to Puma; the rest are secure defaults.
        ..Default::default()
    }
}

async fn http(addr: SocketAddr, method: &str, path: &str) -> (u16, Vec<(String, String)>, String) {
    let fut = async {
        let io = TokioIo::new(TcpStream::connect(addr).await.expect("connect"));
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
            .body(Full::new(Bytes::new()))
            .expect("request");
        let resp = sender.send_request(req).await.expect("send");
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .filter_map(|(n, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (n.as_str().to_string(), v.to_string()))
            })
            .collect();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("collect")
            .to_bytes();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    };
    tokio::time::timeout(Duration::from_secs(30), fut)
        .await
        .expect("http timed out")
}

async fn raw(addr: SocketAddr, request: &[u8]) -> String {
    let fut = async {
        let mut s = TcpStream::connect(addr).await.expect("connect");
        s.write_all(request).await.expect("write");
        s.flush().await.ok();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).into_owned()
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
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
#[ignore = "requires the synthetic Rails bundle; selected by ruby test/run.rb workspace"]
async fn puma_serves_real_rails_through_the_edge() {
    let environment = ruby_fixture::command("ruby");
    for (name, _) in std::env::vars_os() {
        std::env::remove_var(name);
    }
    for (name, value) in environment.get_envs() {
        if let Some(value) = value {
            std::env::set_var(name, value);
        }
    }
    std::env::set_var(
        "BUNDLE_GEMFILE",
        rails_app().parent().unwrap().join("Gemfile"),
    );
    std::env::set_var("SECRET_KEY_BASE", ruby_fixture::test_secret());
    std::env::set_var("RAILS_ENV", "test");
    let cfg = config();
    let handler = Arc::new(
        SupervisedRubyHandler::spawn(&cfg)
            .await
            .expect("spawn puma+rails worker"),
    );
    let listener = TcpListener::bind(cfg.bind).await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_listener(listener, Arc::new(cfg), handler.clone()));

    // Real Rails routes/JSON through the edge.
    let (status, headers, body) = http(addr, "GET", "/hello?via=edge").await;
    assert_eq!(status, 200, "body: {body}");
    assert!(body.contains("Hello from Oxo + Rails"), "body: {body}");
    // A Rails-set header proves it's the real stack (ActionDispatch::RequestId), not the shim.
    assert!(
        headers.iter().any(|(k, _)| k == "x-request-id"),
        "no x-request-id; headers: {headers:?}"
    );

    // Multiple Set-Cookie headers survive the edge round-trip.
    let (_, cookie_headers, _) = http(addr, "GET", "/cookies").await;
    let cookies = cookie_headers
        .iter()
        .filter(|(k, _)| k == "set-cookie")
        .count();
    assert!(
        cookies >= 2,
        "expected >=2 Set-Cookie, got {cookies}: {cookie_headers:?}"
    );

    // Direct hit on the Puma worker without the secret is rejected by the gate.
    let resp = raw(
        handler.worker_addr(),
        b"GET /hello HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        raw_status(&resp),
        403,
        "worker answered secret-less request: {resp}"
    );

    // TE+CL conflict through the edge does not smuggle: exactly one response reaches us.
    let smug = raw(
        addr,
        b"POST /hello HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(
        smug.matches("HTTP/1.1 ").count(),
        1,
        "expected exactly one response (no smuggling) against the Puma backend: {smug}"
    );

    task.abort();
}

//! Narrated, test-backed demos of Oxo. Each flow is a `run_*` library function
//! that a thin binary prints and a flow test asserts, so the demo can never drift from
//! what CI exercises.

use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use oxo_core::{Config, WorkerKind};
use oxo_edge::{serve_listener, SupervisedRubyHandler};
use tokio::net::{TcpListener, TcpStream};

/// Print a narration line: what we're doing and *why*.
pub fn narrate(step: &str, why: &str) {
    println!("\n• {step}\n    why: {why}");
}

fn trivial_app() -> PathBuf {
    // examples/oxo-demos -> <workspace>/ruby/trivial_app.ru
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("ruby")
        .join("trivial_app.ru")
}

/// Boot the supervised handler on an ephemeral loopback port, serve the trivial Rack
/// app, make one request through the edge, and return the response body.
pub async fn run_hello_demo() -> Result<String, Box<dyn Error>> {
    narrate(
        "Resolve config (loopback, supervised)",
        "v1 defaults to a safe loopback bind; supervised isolates the edge from Ruby",
    );
    let cfg = Config {
        bind: "127.0.0.1:0".parse()?,
        worker: WorkerKind::Shim,
        app: trivial_app(),
        ..Default::default()
    };

    narrate(
        "Spawn + supervise a Ruby worker",
        "a separate process: a Ruby/native-gem crash is contained, not fatal to the edge",
    );
    let handler = Arc::new(SupervisedRubyHandler::spawn(&cfg).await?);

    let listener = TcpListener::bind(cfg.bind).await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(serve_listener(listener, Arc::new(cfg), handler));

    narrate(
        "GET /hello?demo=1 through the edge",
        "hyper edge -> loopback -> Ruby worker -> Rack app -> response",
    );
    let body = get(addr, "/hello?demo=1").await?;
    println!("\n--- response body ---\n{body}---------------------");

    server.abort();
    Ok(body)
}

async fn get(addr: SocketAddr, path: &str) -> Result<String, Box<dyn Error>> {
    let io = TokioIo::new(TcpStream::connect(addr).await?);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .uri(path)
        .header("host", "demo")
        .body(Full::new(Bytes::new()))?;
    let resp = sender.send_request(req).await?;
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

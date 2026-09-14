//! resilience tests for the supervised path — shim worker, Windows-runnable.
//!
//! Covers auto-respawn on request (the supervisor's race-free kill+reap+respawn), stderr
//! rotation / temp-file stability, and a clean `Drop` that both removes temp files and
//! does not wedge runtime teardown (the stdout-pipe regression).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use oxo_core::{Config, WorkerKind};
use oxo_edge::{serve_listener, SupervisedRubyHandler};
use tokio::net::{TcpListener, TcpStream};

fn trivial_app() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("ruby")
        .join("trivial_app.ru")
}

fn config() -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        worker: WorkerKind::Shim,
        app: trivial_app(),
        ..Default::default()
    }
}

/// GET `path` through the edge; returns the status (0 on any transport error).
async fn http_status(addr: SocketAddr, path: &str) -> u16 {
    let fut = async {
        let io = TokioIo::new(TcpStream::connect(addr).await.ok()?);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.ok()?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .method("GET")
            .uri(path)
            .header("host", "test")
            .body(Full::new(Bytes::new()))
            .ok()?;
        let resp = sender.send_request(req).await.ok()?;
        let status = resp.status().as_u16();
        let _ = resp.into_body().collect().await;
        Some(status)
    };
    tokio::time::timeout(Duration::from_secs(15), fut)
        .await
        .ok()
        .flatten()
        .unwrap_or(0)
}

async fn wait_for<F: Fn() -> bool>(cond: F, deadline: Duration) -> bool {
    let start = tokio::time::Instant::now();
    loop {
        if cond() {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn request_restart_respawns_a_fresh_worker_and_keeps_serving() {
    let cfg = config();
    let handler = Arc::new(SupervisedRubyHandler::spawn(&cfg).await.expect("spawn"));
    let listener = TcpListener::bind(cfg.bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_listener(listener, Arc::new(cfg), handler.clone()));

    assert_eq!(http_status(addr, "/hello").await, 200);
    let pid0 = handler.worker_pid();
    assert_ne!(pid0, 0, "captured pid should be non-zero");
    let stderr0 = handler
        .temp_files()
        .last()
        .cloned()
        .expect("a current stderr temp file");
    assert!(stderr0.exists(), "stderr file should exist while live");
    let tracked0 = handler.temp_files().len();

    handler.request_restart();

    let changed = wait_for(
        || {
            let p = handler.worker_pid();
            p != 0 && p != pid0
        },
        Duration::from_secs(15),
    )
    .await;
    assert!(changed, "worker pid did not change after request_restart");
    assert!(handler.respawn_count() >= 1, "respawn should be counted");
    assert!(!handler.is_degraded(), "a single restart must not degrade");

    // The new worker serves through the same edge.
    assert_eq!(http_status(addr, "/hello").await, 200);

    // Rotation: the previous generation's stderr file is gone, and the count of tracked
    // temp files is unchanged (stable script reused; only stderr rotates).
    assert!(
        !stderr0.exists(),
        "previous stderr file leaked (not rotated): {stderr0:?}"
    );
    assert_eq!(
        handler.temp_files().len(),
        tracked0,
        "tracked temp-file count grew across a respawn"
    );

    task.abort();
}

#[test]
fn drop_cleans_temp_files_and_does_not_wedge_teardown() {
    // Manage our own runtime so we can assert teardown actually completes — this is the
    // regression (a persistent child-stdout pipe read used to wedge runtime drop).
    let worker = std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let files = rt.block_on(async {
            let cfg = config();
            let handler = SupervisedRubyHandler::spawn(&cfg).await.expect("spawn");
            let files = handler.temp_files();
            for f in &files {
                assert!(f.exists(), "pre-drop temp file missing: {f:?}");
            }
            drop(handler); // synchronous temp-file cleanup + cooperative shutdown
            files
        });
        for f in &files {
            assert!(!f.exists(), "drop leaked a temp file: {f:?}");
        }
        drop(rt); // runtime teardown must not hang
    });

    let start = std::time::Instant::now();
    while !worker.is_finished() {
        if start.elapsed() > Duration::from_secs(30) {
            panic!("handler drop / runtime teardown wedged (v1 regression)");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    worker.join().expect("worker thread panicked");
}

//! crash-loop + diagnosable-boot tests (shim worker).
//!
//! This is its OWN test binary (separate process) so the global env knobs it sets — the
//! burst thresholds and the worker's `OXO_TEST_FAIL_FILE` boot-failure hook — cannot
//! perturb the other test binaries. A controlled boot failure is toggled by creating /
//! removing a flag file (the env var alone is inert; only the file's presence trips it).

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

async fn wait_for_status(addr: SocketAddr, path: &str, want: u16, deadline: Duration) -> bool {
    let start = tokio::time::Instant::now();
    loop {
        if http_status(addr, path).await == want {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn boot_failure_reports_stderr_then_crash_loop_degrades_and_self_heals() {
    let fail = std::env::temp_dir().join(format!("oxo_failhook_{}.flag", std::process::id()));
    let _ = std::fs::remove_file(&fail);
    // Safe in edition 2021; this is a dedicated test process.
    std::env::set_var("OXO_TEST_FAIL_FILE", &fail);
    std::env::set_var("OXO_RESPAWN_BURST", "3");
    std::env::set_var("OXO_RESPAWN_WINDOW_SECS", "60");
    std::env::set_var("OXO_RESPAWN_BACKOFF_CAP_SECS", "1");
    std::env::set_var("OXO_BOOT_TIMEOUT_SECS", "10");

    let cfg = config();

    // (A) Boot failure: the worker crashes before the port handshake. `spawn()` must
    //     return an error carrying the worker's captured stderr tail (diagnosable boot).
    std::fs::write(&fail, b"crash").unwrap();
    // `SupervisedRubyHandler` isn't `Debug`, so match rather than `expect_err`.
    let err = match SupervisedRubyHandler::spawn(&cfg).await {
        Ok(_) => panic!("worker must fail to boot while the flag file is present"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("failing boot"),
        "boot error should carry the worker stderr tail; got: {msg}"
    );

    // (B) Healthy start → crash loop → self-heal.
    std::fs::remove_file(&fail).ok();
    let handler = Arc::new(
        SupervisedRubyHandler::spawn(&cfg)
            .await
            .expect("initial healthy spawn"),
    );
    let listener = TcpListener::bind(cfg.bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_listener(listener, Arc::new(cfg), handler.clone()));

    assert_eq!(
        http_status(addr, "/hello").await,
        200,
        "healthy worker should serve"
    );

    // Induce a crash loop: every respawn now fails at boot.
    std::fs::write(&fail, b"crash").unwrap();
    handler.request_restart();

    // The supervisor throttles to the backoff cap and marks the worker degraded — it does
    // NOT busy-spin (the test would otherwise never reach here within the deadline).
    let degraded = wait_for(|| handler.is_degraded(), Duration::from_secs(15)).await;
    assert!(
        degraded,
        "supervisor should mark the worker degraded under a crash loop"
    );
    // Requests during the outage are 503 (retryable), distinct from a 500/502.
    assert_eq!(
        http_status(addr, "/hello").await,
        503,
        "crash-loop outage should surface as 503"
    );

    // Clear the cause → the next throttled respawn boots → back to 200 (self-heal).
    std::fs::remove_file(&fail).ok();
    assert!(
        wait_for_status(addr, "/hello", 200, Duration::from_secs(20)).await,
        "worker should self-heal once the crash cause is cleared"
    );
    assert!(
        !handler.is_degraded(),
        "degraded flag should clear after recovery"
    );
    assert!(
        handler.respawn_count() >= 1,
        "a successful respawn should be counted"
    );

    task.abort();
    let _ = std::fs::remove_file(&fail);
}

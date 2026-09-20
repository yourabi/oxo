//! Worker-kind-specific retry checks on reused frame connections.
//!
//! For async workers, completed request delivery followed by zero-response-byte EOF
//! is ambiguous: a killed reactor may have dispatched before closing the socket.
//! The edge must return terminal 502 without retry or sibling failover. The native
//! worker's distinct stale-reuse policy is checked in the same harness.

#![cfg(target_os = "linux")]

mod support;

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use support::{free_port, serial_test};

/// Prebuilt binary Full response with a six-byte prefix and bounded envelope.
fn canned_response_frame() -> Vec<u8> {
    let name = b"content-type";
    let value = b"text/plain";
    let body = b"ok";
    let mut env: Vec<u8> = Vec::new();
    env.push(0); // RESP_FULL
    env.extend_from_slice(&200u16.to_le_bytes());
    env.extend_from_slice(&1u16.to_le_bytes());
    env.extend_from_slice(&(name.len() as u16).to_le_bytes());
    env.extend_from_slice(name);
    env.extend_from_slice(&(value.len() as u32).to_le_bytes());
    env.extend_from_slice(value);
    env.extend_from_slice(&(body.len() as u32).to_le_bytes());
    env.extend_from_slice(body);
    let mut frame = vec![0xBF, 0x01];
    frame.extend_from_slice(&(env.len() as u32).to_le_bytes());
    frame.extend(env);
    frame
}

/// A killable pooled-frame fake worker: counts served requests; see `kill` for the
/// reactor-crash signature it simulates (close-after-read, zero response bytes).
struct FrameWorker {
    socket: PathBuf,
    served: Arc<AtomicUsize>,
    dead: Arc<AtomicBool>,
}

impl FrameWorker {
    fn spawn(socket: &Path) -> Self {
        let listener = UnixListener::bind(socket).expect("bind fake frame worker");
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let served = Arc::new(AtomicUsize::new(0));
        let dead = Arc::new(AtomicBool::new(false));
        let (served_t, dead_t) = (served.clone(), dead.clone());
        thread::spawn(move || {
            let response = canned_response_frame();
            while !dead_t.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        let served = served_t.clone();
                        let dead = dead_t.clone();
                        let response = response.clone();
                        let mut stream = stream;
                        thread::spawn(move || loop {
                            // Blocking reads: a mid-prefix timeout would corrupt framing.
                            let mut prefix = [0u8; 6];
                            if stream.read_exact(&mut prefix).is_err() {
                                return; // EOF or kill-switch shutdown
                            }
                            assert_eq!(prefix[0], 0xBF, "frame magic");
                            let len =
                                u32::from_le_bytes([prefix[2], prefix[3], prefix[4], prefix[5]]);
                            let mut envelope = vec![0u8; len as usize];
                            if stream.read_exact(&mut envelope).is_err() {
                                return;
                            }
                            // Killed reactor racing dispatch: the request was READ (the
                            // edge's write committed) but the connection closes with zero
                            // response bytes — the ambiguous signature the async kind must
                            // treat as terminal. Deliberately AFTER the read: closing
                            // before it would let the pool's liveness guard evict the
                            // corpse pre-checkout and turn the probe into a legal
                            // pre-commit failover.
                            if dead.load(Ordering::SeqCst) {
                                return;
                            }
                            if stream.write_all(&response).is_err() {
                                return;
                            }
                            served.fetch_add(1, Ordering::SeqCst);
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            socket: socket.to_path_buf(),
            served,
            dead,
        }
    }

    fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }

    /// The reactor-crash signature: acceptor stops and the socket file vanishes
    /// (reconnects fail). Pooled connections stay OPEN — each closes only after reading
    /// its next request, so the edge's pool liveness guard cannot evict the corpse
    /// before checkout and the reuse genuinely commits a write into the dead worker.
    fn kill(&self) {
        self.dead.store(true, Ordering::SeqCst);
        let _ = fs::remove_file(&self.socket);
    }
}

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "oxo-frame-replay-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        Self { dir }
    }

    fn socket(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn spawn_frame_edge(port: u16, sockets: &[&Path], worker_kind: Option<&str>) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
    cmd.env("OXO_EDGE_WORKER_HOP", "frame")
        .env("OXO_EDGE_THREADS", "1")
        // rr makes the warm/kill/probe request routing deterministic: request k starts
        // its candidate order at worker k % N.
        .env("OXO_WORKER_DISPATCH", "rr")
        .env("OXO_EDGE_BIND", format!("127.0.0.1:{port}"))
        .env("OXO_EDGE_MAX_BODY", "1024")
        .env("OXO_EDGE_SCHEME", "http")
        .env("OXO_EDGE_SERVER_NAME", "localhost");
    // Multi-socket wiring rides argv exactly as the service/bench pass it.
    for s in sockets {
        cmd.arg("--worker-socket").arg(s);
    }
    if let Some(kind) = worker_kind {
        cmd.env("OXO_WORKER_KIND", kind);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.spawn().expect("spawn frame edge")
}

fn wait_tcp(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("frame edge never bound :{port}");
}

/// One-shot HTTP request to the edge; returns the raw response bytes.
fn send_one_shot(port: u16, path: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect edge");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    buf
}

fn status_of(response: &[u8]) -> u16 {
    let text = String::from_utf8_lossy(response);
    text.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status line in: {text}"))
}

/// Warm both workers' pools (rr: request k -> worker k), then kill A. The probe request
/// (rr start = A) rides A's pooled connection into zero-byte EOF.
fn run_stale_probe(kind: Option<&str>, label: &str) -> (u16, usize, usize, Child) {
    let fixture = Fixture::new(label);
    let sock_a = fixture.socket("worker-a.sock");
    let sock_b = fixture.socket("worker-b.sock");
    let worker_a = FrameWorker::spawn(&sock_a);
    let worker_b = FrameWorker::spawn(&sock_b);
    let port = free_port();
    let edge = spawn_frame_edge(port, &[&sock_a, &sock_b], kind);
    wait_tcp(port);

    assert_eq!(status_of(&send_one_shot(port, "/hello")), 200, "warm A");
    assert_eq!(status_of(&send_one_shot(port, "/hello")), 200, "warm B");
    let deadline = Instant::now() + Duration::from_secs(5);
    while (worker_a.served() + worker_b.served()) < 2 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(worker_a.served(), 1, "rr warm: A serves request 1");
    assert_eq!(worker_b.served(), 1, "rr warm: B serves request 2");

    worker_a.kill();
    // The probe: rr start rotates back to A; its pooled connection is now a corpse.
    let status = status_of(&send_one_shot(port, "/hello"));
    thread::sleep(Duration::from_millis(200)); // let any (illegal) replay land at B
    (status, worker_a.served(), worker_b.served(), edge)
}

/// ASYNC KIND: the stale reused connection is a terminal 502 — no retry, no failover,
/// and above all NO REPLAY into the sibling.
#[test]
fn async_kind_stale_reuse_is_terminal_502_with_zero_sibling_replay() {
    let _guard = serial_test();
    let (status, served_a, served_b, mut edge) = run_stale_probe(Some("async"), "async");
    assert_eq!(served_a, 1, "dead worker A serves nothing more");
    assert_eq!(
        status, 502,
        "async kind: stale reuse must surface as 502, not a silently replayed 200"
    );
    assert_eq!(
        served_b, 1,
        "async kind: the sibling must NOT receive a replay of the dispatched request"
    );
    let _ = edge.kill();
    let _ = edge.wait();
}

/// The native-worker policy retries stale reuse and can fail over after reconnect failure.
#[test]
fn classic_default_stale_reuse_fails_over_to_sibling() {
    let _guard = serial_test();
    let (status, served_a, served_b, mut edge) = run_stale_probe(None, "classic");
    assert_eq!(served_a, 1, "dead worker A serves nothing more");
    assert_eq!(status, 200, "classic: failover serves the probe");
    assert_eq!(
        served_b, 2,
        "classic: the sibling served the failed-over request"
    );
    let _ = edge.kill();
    let _ = edge.wait();
}

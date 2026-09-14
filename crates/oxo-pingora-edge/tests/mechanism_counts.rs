//! M-A — Tier-1 mechanism gates: deterministic per-request COUNTS, not timing.
//!
//! The diagnosis proved the harness's timing tier cannot resolve 1%-class changes,
//! but its syscall attribution was exact (`getpid` 1.000/req, `openat2` 2.000/req,
//! 100% ENOENT over 65 526 calls). This suite pins those mechanisms as build-failing
//! assertions so a 1%-class regression (or win) is provable WITHOUT a guest, without
//! statistics, and without an MDE. The pinned numbers live in
//! `docs/perf-mechanism-counts.md`; changing an assertion requires a measurement in the
//! same commit.
//!
//! Method — the two-instance DELTA: each scenario runs one edge under
//! `strace -c -f` for N requests and a second for 3N, and asserts on
//! `count(3N) − count(N)`, which must equal `2N × per-request-count` EXACTLY.
//! Startup and shutdown syscalls cancel in the subtraction, so the assertions hold
//! with zero slack. strace is the PARENT of the edge (never `-p` attach), which keeps
//! the test working under Yama `ptrace_scope=1`.
//!
//! Only DETERMINISTIC syscalls are asserted (`getpid`, `newfstatat`, `openat2`). The
//! hop's `recvfrom`/`sendto`/`futex`/`epoll_wait` counts are timing-dependent (
//! measured 2 of 5 hop reads as EAGAIN) and are ledger-documented, never asserted.

#![cfg(target_os = "linux")]

mod support;

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use support::{free_port, serial_test};

const RESPONSE_OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

struct Fixture {
    dir: PathBuf,
    socket: PathBuf,
    docroot: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "oxo-mechanism-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let docroot = dir.join("public");
        fs::create_dir(&docroot).unwrap();
        Self {
            socket: dir.join("worker.sock"),
            dir,
            docroot,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn bind_worker_socket(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).expect("bind fake worker socket");
    // The edge fails closed on a group/world-accessible worker socket.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    listener
}

/// One-shot HTTP-over-UDS fake worker answering exactly `count` requests.
fn spawn_worker_many(listener: UnixListener, count: usize) -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut served = 0usize;
        while served < count {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 4096];
                    // One-shot requests are tiny (no body): a single read drains the head.
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(RESPONSE_OK);
                    served += 1;
                    let _ = tx.send(());
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
    });
    rx
}

struct StracedEdge {
    strace: Child,
    edge_pid: u32,
    summary_path: PathBuf,
    stderr_path: PathBuf,
}

/// Spawn the edge UNDER strace (`strace -c -f -o <file> <edge>`): strace is the parent,
/// so no ptrace attach is needed and Yama ptrace_scope=1 cannot break the test.
fn spawn_edge_under_strace(
    fixture: &Fixture,
    port: u16,
    label: &str,
    static_mounts: Option<String>,
) -> StracedEdge {
    spawn_edge_under_strace_hop(fixture, port, label, static_mounts, "http", false)
}

/// W3.5: hop/keepalive-parameterized variant so the FRAME hop's per-request syscall
/// ledger (the P1b instrument) runs under the same strace harness.
fn spawn_edge_under_strace_hop(
    fixture: &Fixture,
    port: u16,
    label: &str,
    static_mounts: Option<String>,
    hop: &str,
    keepalive: bool,
) -> StracedEdge {
    let summary_path = fixture.dir.join(format!("strace-{label}.txt"));
    let stderr_path = fixture.dir.join(format!("edge-{label}.stderr"));
    let stderr_file = fs::File::create(&stderr_path).expect("create edge stderr capture");
    let mut cmd = Command::new("strace");
    cmd.arg("-c")
        .arg("-f")
        .arg("-o")
        .arg(&summary_path)
        .arg(env!("CARGO_BIN_EXE_oxo-pingora-edge"))
        // the fake worker speaks the one-shot HTTP hop; the counted syscalls
        // (getpid, crenel's stat/open probes) are hop-independent. : the frame-hop
        // ledger passes "frame" + keepalive through the parameterized wrapper.
        .env("OXO_EDGE_WORKER_HOP", hop)
        // One traced thread: the nproc default (32 here) makes bind take >10s under
        // strace -f and adds untraced-thread noise; the counted syscalls are per-request,
        // not per-thread, so THREADS=1 changes nothing being asserted.
        .env("OXO_EDGE_THREADS", "1")
        .env("OXO_EDGE_BIND", format!("127.0.0.1:{port}"))
        .env("OXO_EDGE_WORKER_SOCKET", &fixture.socket)
        .env("OXO_EDGE_MAX_BODY", "1024")
        .env("OXO_EDGE_SCHEME", "http")
        .env("OXO_EDGE_SERVER_NAME", "localhost")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // The edge inherits this fd — its config notices / fail-closed error land here,
        // and wait_for_tcp prints the file on a boot failure instead of guessing.
        .stderr(Stdio::from(stderr_file));
    if keepalive {
        cmd.env("OXO_EDGE_KEEPALIVE", "1");
    }
    if let Some(mounts) = static_mounts {
        cmd.env("OXO_EDGE_STATIC_MOUNTS", mounts);
    }
    let strace = cmd.spawn().expect(
        "spawn strace — Tier-1 mechanism gates REQUIRE strace on the test host \
         (apt install strace); absence is an error, not a skip",
    );

    // The edge is strace's only child; resolve its pid for the deterministic SIGKILL.
    let edge_pid = wait_for_child_pid(strace.id());
    StracedEdge {
        strace,
        edge_pid,
        summary_path,
        stderr_path,
    }
}

fn wait_for_child_pid(parent: u32) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let children = fs::read_to_string(format!("/proc/{parent}/task/{parent}/children"))
            .unwrap_or_default();
        if let Some(first) = children.split_whitespace().next() {
            return first.parse().expect("child pid");
        }
        assert!(
            Instant::now() < deadline,
            "strace ({parent}) never spawned the edge child"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_tcp(port: u16, straced: &StracedEdge) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        // strace slows startup well beyond the plain-edge 5s budget; 20s with strace.
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let stderr = fs::read_to_string(&straced.stderr_path).unwrap_or_default();
    panic!("straced edge never bound 127.0.0.1:{port}; edge stderr:\n{stderr}");
}

fn send_one_shot(port: u16, path: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect edge");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    response
}

/// Drive exactly `n` one-shot requests, kill the edge (SIGKILL: zero shutdown
/// syscalls), reap strace, and parse its `-c` summary into name -> call count.
fn run_counted_requests(
    fixture: &Fixture,
    label: &str,
    n: usize,
    static_mounts: Option<String>,
) -> HashMap<String, u64> {
    let listener = bind_worker_socket(&fixture.socket);
    let served = spawn_worker_many(listener, n);
    let port = free_port();
    let mut straced = spawn_edge_under_strace(fixture, port, label, static_mounts);
    wait_for_tcp(port, &straced);

    for i in 0..n {
        let response = send_one_shot(port, "/hello");
        assert!(
            String::from_utf8_lossy(&response).contains("200 OK"),
            "request {i} did not complete 200 — counts would be meaningless"
        );
        served
            .recv_timeout(Duration::from_secs(5))
            .expect("fake worker served the request");
    }

    // SIGKILL the TRACEE (not strace): strace prints its -c summary on tracee death,
    // and a killed edge performs no shutdown syscalls to blur the delta.
    sigkill(straced.edge_pid as i32);
    let status = straced.strace.wait().expect("reap strace");
    // strace exits with the tracee's (signal-death) status; we only need the summary.
    let _ = status;
    let summary = fs::read_to_string(&straced.summary_path).expect("read strace summary");
    // clean up the socket for the next instance in the same fixture
    let _ = fs::remove_file(&fixture.socket);
    parse_strace_summary(&summary)
}

// Minimal FFI shim: SIGKILL to a pid. Avoids pulling the `libc` crate into dev-deps
// for one constant (SIGKILL = 9 on every Linux ABI this repo targets).
fn sigkill(pid: i32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    // SAFETY: kill(2) with a pid we own (our grandchild) and a valid signal number.
    unsafe {
        kill(pid, 9);
    }
}

/// Parse `strace -c` output: columns are `% time  seconds  usecs/call  calls  [errors]  syscall`.
fn parse_strace_summary(summary: &str) -> HashMap<String, u64> {
    let mut counts = HashMap::new();
    for line in summary.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Data rows start with a numeric %-time and end with the syscall name.
        if fields.len() < 5 || fields[0].parse::<f64>().is_err() {
            continue;
        }
        let name = fields[fields.len() - 1];
        if name == "total" {
            continue;
        }
        // `calls` is the 4th column; the optional `errors` column sits between it and the name.
        if let Ok(calls) = fields[3].parse::<u64>() {
            counts.insert(name.to_string(), calls);
        }
    }
    counts
}

fn delta(hi: &HashMap<String, u64>, lo: &HashMap<String, u64>, name: &str) -> i64 {
    *hi.get(name).unwrap_or(&0) as i64 - *lo.get(name).unwrap_or(&0) as i64
}

const N: usize = 25; // low run: 25 requests; high run: 75 — delta denominator = 50

/// PINNED (docs/perf-mechanism-counts.md): with the Rails-preset `/` FALLTHROUGH mount,
/// a dynamic request pays `newfstatat` ×1 (crenel `check_repin` — the deploy-flip
/// invalidation heartbeat, DELIBERATELY kept: the panel proved any probe-skipping
/// screen has circular invalidation because this stat is the only generation-advancer)
/// and `openat2` ×1 (M0 / crenel -serve-outcome-reuse threaded the dispatch
/// resolution through instead of discarding it — was ×2). getpid dropped to ×0 in M1
/// (pid cached in a OnceLock on first use; it was a per-request fetch of a process
/// constant).
#[test]
fn syscall_ledger_dynamic_route_with_root_fallthrough_mount() {
    let _guard = serial_test();
    let fixture = Fixture::new("syscalls-mounted");
    let mounts = format!("/={},fallthrough", fixture.docroot.display());

    let lo = run_counted_requests(&fixture, "mounted-lo", N, Some(mounts.clone()));
    let hi = run_counted_requests(&fixture, "mounted-hi", 3 * N, Some(mounts));

    let per_req = (2 * N) as i64;
    assert_eq!(
        delta(&hi, &lo, "getpid"),
        0,
        "getpid must be 0/request (M1: pid cached once, was 1/request)"
    );
    assert_eq!(
        delta(&hi, &lo, "newfstatat"),
        per_req,
        "crenel check_repin stays exactly 1/request — the deploy-flip heartbeat"
    );
    assert_eq!(
        delta(&hi, &lo, "openat2"),
        per_req,
        "crenel resolution must be exactly 1/request (M0 outcome reuse; was 2)"
    );
}

/// W3.5: the FRAME hop's per-request syscall ledger on the ladder-shaped path
/// (keepalive client, pooled worker connection) — the P1b instrument. Prints the full
/// per-request delta table (`--nocapture`) so each syscall-collapse lever names its
/// target concretely before claims freeze; the assertion pins only the reuse-path
/// invariant the collapse levers change (see below).
#[test]
fn syscall_ledger_frame_hop_keepalive_reuse_path() {
    let _guard = serial_test();

    let run = |label: &str, n: usize| -> HashMap<String, u64> {
        let fixture = Fixture::new(&format!("frame-ka-{label}"));
        let listener = bind_worker_socket(&fixture.socket);
        let served = spawn_frame_worker_many(listener);
        let port = free_port();
        let mut straced = spawn_edge_under_strace_hop(&fixture, port, label, None, "frame", true);
        wait_for_tcp(port, &straced);

        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect edge");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        for i in 0..n {
            stream
                .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            // Read headers byte-wise to the blank line, then exactly Content-Length.
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") {
                assert_eq!(stream.read(&mut byte).expect("read"), 1, "closed at {i}");
                buf.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
            assert!(head.contains("200"), "request {i}: {head}");
            let clen: usize = head
                .split("content-length:")
                .nth(1)
                .map(|t| {
                    t.trim_start()
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect::<String>()
                })
                .and_then(|d| d.parse().ok())
                .expect("content-length");
            let mut body = vec![0u8; clen];
            stream.read_exact(&mut body).expect("body");
            served.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        drop(stream);

        sigkill(straced.edge_pid as i32);
        let _ = straced.strace.wait().expect("reap strace");
        let summary = fs::read_to_string(&straced.summary_path).expect("read summary");
        let _ = fs::remove_file(&fixture.socket);
        parse_strace_summary(&summary)
    };

    let lo = run("lo", N);
    let hi = run("hi", 3 * N);
    let per = (2 * N) as f64;

    let mut rows: Vec<(String, f64)> = hi
        .iter()
        .map(|(name, hi_count)| {
            let d = *hi_count as i64 - *lo.get(name).unwrap_or(&0) as i64;
            (name.clone(), d as f64 / per)
        })
        .filter(|(_, v)| *v > 0.01)
        .collect();
    rows.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    let total: f64 = rows.iter().map(|(_, v)| v).sum();
    eprintln!("frame-hop keepalive syscalls/request (hi-lo delta over {per} requests):");
    for (name, v) in &rows {
        eprintln!("  {name:>16}: {v:.2}");
    }
    eprintln!("  {:>16}: {total:.2}", "TOTAL");

    // W3.5 POST-FOLD PIN. Before the fold: recvfrom 3.00/request (one was the
    // per-checkout MSG_PEEK probe), total 8.34. The probe now classifies via
    // reactor-cached readiness (try_read: syscall only when the fd already signalled),
    // so the reuse path pays recvfrom ~2 (the response-read class) and total ~7.2.
    // Raising either bound requires a measurement + ledger entry in the same commit.
    let recvfrom = delta(&hi, &lo, "recvfrom") as f64 / per;
    assert!(
        recvfrom <= 2.5,
        "checkout probe syscall came back? recvfrom {recvfrom:.2}/request (post-fold ~2.0)"
    );
    assert!(
        total <= 7.8,
        "frame-hop reuse-path syscalls regressed: {total:.2}/request (post-fold ~7.2)"
    );
}

/// PINNED: with NO static mounts the crenel probes must be exactly ZERO — the static
/// branch is never entered, so a dynamic request touches the filesystem zero times.
/// This is the control that localizes the probes to the mount table ('s method).
#[test]
fn syscall_ledger_dynamic_route_without_mounts_has_zero_fs_probes() {
    let _guard = serial_test();
    let fixture = Fixture::new("syscalls-unmounted");

    let lo = run_counted_requests(&fixture, "unmounted-lo", N, None);
    let hi = run_counted_requests(&fixture, "unmounted-hi", 3 * N, None);

    assert_eq!(delta(&hi, &lo, "getpid"), 0, "getpid stays 0/request (M1)");
    assert_eq!(
        delta(&hi, &lo, "newfstatat"),
        0,
        "no mounts => zero stat probes"
    );
    assert_eq!(
        delta(&hi, &lo, "openat2"),
        0,
        "no mounts => zero open probes"
    );
}

/// C6: a fake worker that speaks the 0xBF FRAME protocol — the SHIPPED default hop.
/// The pre-alloc ruler ran only the `http` hop, so every allocation claim on the
/// real path was unprovable guest-free (PERF_WINS_LEDGER.md:28-41, the known null).
/// The worker side needs no codec: framing is a 6-byte prefix (magic, version, u32-LE
/// envelope length) and the response bytes are identical every time, so they are
/// precomputed once. Keepalive loop — the frame hop POOLS connections, many requests
/// ride one stream.
fn canned_response_frame() -> Vec<u8> {
    canned_response_frame_with(&[("content-type", "text/plain")], b"ok")
}

/// W-A: parameterized so the header-rich ruler can exercise multi-header response
/// decode (2 Strings/header + the http-crate custom-name path) — the pinned rulers'
/// 1-header shape made per-header levers nearly invisible.
fn canned_response_frame_with(headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut env: Vec<u8> = Vec::new();
    env.push(0); // RESP_FULL
    env.extend_from_slice(&200u16.to_le_bytes());
    env.extend_from_slice(&(headers.len() as u16).to_le_bytes());
    for (name, value) in headers {
        env.extend_from_slice(&(name.len() as u16).to_le_bytes());
        env.extend_from_slice(name.as_bytes());
        env.extend_from_slice(&(value.len() as u32).to_le_bytes());
        env.extend_from_slice(value.as_bytes());
    }
    env.extend_from_slice(&(body.len() as u32).to_le_bytes());
    env.extend_from_slice(body);
    let mut frame = vec![0xBF, 0x01];
    frame.extend_from_slice(&(env.len() as u32).to_le_bytes());
    frame.extend(env);
    frame
}

// alloc-count rulers; : also the frame-hop syscall ledger (all builds).
fn spawn_frame_worker_many(listener: UnixListener) -> mpsc::Receiver<()> {
    spawn_frame_worker_serving(listener, canned_response_frame())
}

/// W-A: worker serving an arbitrary canned frame (the header-rich ruler's worker).
fn spawn_frame_worker_serving(listener: UnixListener, response: Vec<u8>) -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        // Thread per pooled connection, fully BLOCKING reads: a timeout-polling design
        // can lose bytes on a mid-prefix timeout (read_exact does not restart), which
        // would corrupt framing for every later request on that stream. The acceptor
        // runs until the fixture drops the listener path; each connection thread exits
        // on EOF when the edge dies.
        loop {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let tx = tx.clone();
            let response = response.clone();
            thread::spawn(move || loop {
                let mut prefix = [0u8; 6];
                if stream.read_exact(&mut prefix).is_err() {
                    return; // EOF: the pooled connection closed
                }
                assert_eq!(prefix[0], 0xBF, "frame magic");
                let len = u32::from_le_bytes([prefix[2], prefix[3], prefix[4], prefix[5]]);
                let mut envelope = vec![0u8; len as usize];
                if stream.read_exact(&mut envelope).is_err() {
                    return;
                }
                if stream.write_all(&response).is_err() {
                    return;
                }
                let _ = tx.send(());
            });
        }
    });
    rx
}

/// PINNED (bench-only `alloc-count` feature): allocation EVENTS per request, amortized
/// over 200 one-shot requests, must stay at or under the ledger budget. measured
/// alloc+memcpy at ~1µs of the 40µs front — this is a TRIPWIRE against an accidental
/// per-request allocation storm, not a µs claim.
#[cfg(feature = "alloc-count")]
#[test]
fn alloc_events_per_request_stay_under_pinned_budget() {
    let _guard = serial_test();
    let fixture = Fixture::new("alloc-count");
    let n = 200usize;
    let listener = bind_worker_socket(&fixture.socket);
    // n measured requests + 1 warm request.
    let served = spawn_worker_many(listener, n + 1);
    let port = free_port();
    let admin_port = free_port();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
    cmd.env("OXO_EDGE_WORKER_HOP", "http")
        .env("OXO_EDGE_THREADS", "1")
        .env("OXO_EDGE_BIND", format!("127.0.0.1:{port}"))
        .env("OXO_EDGE_ADMIN_BIND", format!("127.0.0.1:{admin_port}"))
        .env("OXO_EDGE_WORKER_SOCKET", &fixture.socket)
        .env("OXO_EDGE_MAX_BODY", "1024")
        .env("OXO_EDGE_SCHEME", "http")
        .env("OXO_EDGE_SERVER_NAME", "localhost")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut edge = cmd.spawn().expect("spawn alloc-count edge");

    let wait_admin = |port: u16| {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("admin bind never came up");
    };
    wait_admin(port);
    wait_admin(admin_port);

    let read_count = |admin_port: u16| -> u64 {
        let body = send_one_shot(admin_port, "/alloc-count");
        let text = String::from_utf8_lossy(&body);
        let tail = text
            .split("alloc_events_total\":")
            .nth(1)
            .expect("alloc-count admin route present (built with --features alloc-count?)");
        tail.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .expect("counter parses")
    };

    // Warm the request path once so one-time lazies don't land in the measured window.
    let warm = send_one_shot(port, "/hello");
    assert!(
        String::from_utf8_lossy(&warm).contains("200 OK"),
        "warm request failed: {}",
        String::from_utf8_lossy(&warm)
    );
    served.recv_timeout(Duration::from_secs(5)).unwrap();

    let before = read_count(admin_port);
    for i in 0..n {
        let response = send_one_shot(port, "/hello");
        assert!(
            String::from_utf8_lossy(&response).contains("200 OK"),
            "request {i} failed: {}",
            String::from_utf8_lossy(&response)
        );
        served.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    let after = read_count(admin_port);

    let per_request = (after - before) as f64 / n as f64;
    // M0.2: EMIT the measurement, don't just gate on it. This test is the project's
    // only guest-free allocation ruler; discarding the number made every alloc-affecting
    // change unmeasurable and left the budget the sole signal (which a win cannot trip).
    // `cargo test --features alloc-count alloc_events -- --nocapture` now reads out an A/B.
    eprintln!(
        "alloc_events_per_request={per_request:.2} (n={n}, delta={})",
        after - before
    );
    // PINNED BUDGET — see docs/perf-mechanism-counts.md for the measured value this
    // encodes (measured + ~15% headroom). Lowering is a win recorded in the ledger;
    // raising REQUIRES a measurement and a ledger entry in the same commit.
    const ALLOC_EVENTS_PER_REQUEST_BUDGET: f64 = 98.0; // measured 85.16 on 2026-07-31 (: shared collect/id trims) + ~15% headroom
    assert!(
        per_request <= ALLOC_EVENTS_PER_REQUEST_BUDGET,
        "alloc events/request regressed: measured {per_request:.1} > budget {ALLOC_EVENTS_PER_REQUEST_BUDGET}"
    );

    let _ = edge.kill();
    let _ = edge.wait();
}

/// C6: the SAME ruler on the SHIPPED hop. Everything the http-hop test asserts,
/// measured over the 0xBF frame path with pooled connections — the configuration every
/// production request actually takes. Until this test existed, the ledger's own note
/// (PERF_WINS_LEDGER.md:28-41) documented that no allocation-class change on the
/// default hop was provable without a guest.
#[cfg(feature = "alloc-count")]
#[test]
fn alloc_events_per_request_frame_hop_stay_under_pinned_budget() {
    let _guard = serial_test();
    let fixture = Fixture::new("alloc-count-frame");
    let n = 200usize;
    let listener = bind_worker_socket(&fixture.socket);
    let served = spawn_frame_worker_many(listener);
    let port = free_port();
    let admin_port = free_port();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
    cmd.env("OXO_EDGE_WORKER_HOP", "frame")
        .env("OXO_EDGE_THREADS", "1")
        .env("OXO_EDGE_BIND", format!("127.0.0.1:{port}"))
        .env("OXO_EDGE_ADMIN_BIND", format!("127.0.0.1:{admin_port}"))
        .env("OXO_EDGE_WORKER_SOCKET", &fixture.socket)
        .env("OXO_EDGE_MAX_BODY", "1024")
        .env("OXO_EDGE_SCHEME", "http")
        .env("OXO_EDGE_SERVER_NAME", "localhost")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut edge = cmd.spawn().expect("spawn alloc-count frame edge");

    let wait_tcp = |port: u16| {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("frame-hop edge never bound :{port}");
    };
    wait_tcp(port);
    wait_tcp(admin_port);

    let read_count = |admin_port: u16| -> u64 {
        let body = send_one_shot(admin_port, "/alloc-count");
        let text = String::from_utf8_lossy(&body);
        let tail = text
            .split("alloc_events_total\":")
            .nth(1)
            .expect("alloc-count admin route present (built with --features alloc-count?)");
        tail.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .expect("counter parses")
    };

    // Warm once: pool connect + one-time lazies stay out of the measured window.
    let warm = send_one_shot(port, "/hello");
    assert!(
        String::from_utf8_lossy(&warm).contains("200"),
        "warm frame request failed: {}",
        String::from_utf8_lossy(&warm)
    );
    served.recv_timeout(Duration::from_secs(5)).unwrap();

    let before = read_count(admin_port);
    for i in 0..n {
        let response = send_one_shot(port, "/hello");
        assert!(
            String::from_utf8_lossy(&response).contains("200"),
            "frame request {i} failed: {}",
            String::from_utf8_lossy(&response)
        );
        served.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    let after = read_count(admin_port);

    let per_request = (after - before) as f64 / n as f64;
    eprintln!(
        "frame_hop alloc_events_per_request={per_request:.2} (n={n}, delta={})",
        after - before
    );
    // PINNED BUDGET — measured in THIS commit (: post A1/A2, one-shot client
    // connections against the pooled frame hop) + ~15% headroom. Same contract as the
    // http-hop budget: lowering is a ledger win; raising requires a measurement + ledger
    // entry in the same commit.
    // ingest sweep: 87.2 → 62.2 measured (W1 −3.0 response headers, W2 −5.0
    // admission/telemetry, W3 −16.0 single-pass header pipeline). Ledger entries in
    // PERF_WINS_LEDGER.md; budget = measured + ~15%.
    const FRAME_ALLOC_EVENTS_PER_REQUEST_BUDGET: f64 = 61.0; // measured 53.22 on 2026-07-31 (+ Date-capacity fix) + ~15% headroom
    assert!(
        per_request <= FRAME_ALLOC_EVENTS_PER_REQUEST_BUDGET,
        "frame-hop alloc events/request regressed: measured {per_request:.1} > budget {FRAME_ALLOC_EVENTS_PER_REQUEST_BUDGET}"
    );

    let _ = edge.kill();
    let _ = edge.wait();
}

/// W0 (panel LOW-8): the SAME frame-hop ruler, denominated the way the bench ladder
/// actually pays — ONE client connection reused for all n requests (keepalive). The
/// one-shot ruler above stays as the historical series; this variant is the number the
/// scoreboard's per-request claims should be compared against, since one-shot spends a
/// per-CONNECTION alloc tail (accept, session, TLS-less handshake state) that keepalive
/// amortizes across the whole burst. No budget pin yet — records the first measured
/// value in the ledger and pins in the same commit that lowers the one-shot budget.
#[cfg(feature = "alloc-count")]
#[test]
fn alloc_events_per_request_frame_hop_keepalive_denomination() {
    let _guard = serial_test();
    let fixture = Fixture::new("alloc-count-frame-ka");
    let n = 200usize;
    let listener = bind_worker_socket(&fixture.socket);
    let served = spawn_frame_worker_many(listener);
    let port = free_port();
    let admin_port = free_port();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
    cmd.env("OXO_EDGE_WORKER_HOP", "frame")
        .env("OXO_EDGE_THREADS", "1")
        .env("OXO_EDGE_KEEPALIVE", "1")
        .env("OXO_EDGE_BIND", format!("127.0.0.1:{port}"))
        .env("OXO_EDGE_ADMIN_BIND", format!("127.0.0.1:{admin_port}"))
        .env("OXO_EDGE_WORKER_SOCKET", &fixture.socket)
        .env("OXO_EDGE_MAX_BODY", "1024")
        .env("OXO_EDGE_SCHEME", "http")
        .env("OXO_EDGE_SERVER_NAME", "localhost")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut edge = cmd.spawn().expect("spawn alloc-count keepalive frame edge");

    let wait_tcp = |port: u16| {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("keepalive frame edge never bound :{port}");
    };
    wait_tcp(port);
    wait_tcp(admin_port);

    let read_count = |admin_port: u16| -> u64 {
        let body = send_one_shot(admin_port, "/alloc-count");
        let text = String::from_utf8_lossy(&body);
        let tail = text
            .split("alloc_events_total\":")
            .nth(1)
            .expect("alloc-count admin route present (built with --features alloc-count?)");
        tail.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .expect("counter parses")
    };

    // One persistent connection for warm-up AND the measured burst.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect edge");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut read_one_response = |stream: &mut TcpStream, label: &str| {
        // Responses carry Content-Length (the frame worker's fixed body); read headers,
        // then exactly the body, leaving the stream positioned for the next response.
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            let got = stream.read(&mut byte).expect(label);
            assert!(got == 1, "{label}: connection closed mid-headers");
            buf.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&buf);
        assert!(head.contains("200"), "{label}: {head}");
        let clen: usize = head
            .to_ascii_lowercase()
            .split("content-length:")
            .nth(1)
            .map(|t| {
                t.trim_start()
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
            })
            .and_then(|d| d.parse().ok())
            .expect("content-length present under keepalive");
        let mut body = vec![0u8; clen];
        stream.read_exact(&mut body).expect(label);
    };

    let warm = b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n";
    stream.write_all(warm).unwrap();
    read_one_response(&mut stream, "warm");
    served.recv_timeout(Duration::from_secs(5)).unwrap();

    let before = read_count(admin_port);
    for i in 0..n {
        stream.write_all(warm).unwrap();
        read_one_response(&mut stream, &format!("keepalive request {i}"));
        served.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    let after = read_count(admin_port);

    let per_request = (after - before) as f64 / n as f64;
    eprintln!(
        "frame_hop KEEPALIVE alloc_events_per_request={per_request:.2} (n={n}, delta={})",
        after - before
    );
    // first pin (was sanity-only at introduction): measured 68.19 pre-sweep,
    // 50.18 post-W3 — the ladder-relevant number. Same raise/lower contract as the
    // one-shot budgets.
    const KEEPALIVE_ALLOC_EVENTS_PER_REQUEST_BUDGET: f64 = 50.0; // measured 43.14 on 2026-07-31 (+ Date-capacity fix) + ~15% headroom
    assert!(
        per_request <= KEEPALIVE_ALLOC_EVENTS_PER_REQUEST_BUDGET,
        "keepalive-denominated alloc events/request regressed: {per_request:.1} > {KEEPALIVE_ALLOC_EVENTS_PER_REQUEST_BUDGET}"
    );

    let _ = edge.kill();
    let _ = edge.wait();
}

/// W-A: the HEADER-RICH keepalive ruler. The two pinned rulers use a 1-request-
/// header / 1-response-header shape, on which per-header levers (the arena) read as
/// noise; this variant carries 8 request headers (4 mixed-case exercising the lowercase
/// branch, 4 already-lower) and 4 response headers (3 custom names exercising the
/// http-crate custom-name path). Baseline banked at introduction; pinned in W-H's
/// same-commit ratchet.
#[cfg(feature = "alloc-count")]
#[test]
fn alloc_events_per_request_frame_hop_header_rich() {
    let _guard = serial_test();
    let fixture = Fixture::new("alloc-count-frame-rich");
    let n = 200usize;
    let listener = bind_worker_socket(&fixture.socket);
    let served = spawn_frame_worker_serving(
        listener,
        canned_response_frame_with(
            &[
                ("content-type", "text/plain"),
                ("x-trace-out", "abc123"),
                ("x-cache-status", "MISS"),
                ("x-served-by", "oxo-test"),
            ],
            b"ok",
        ),
    );
    let port = free_port();
    let admin_port = free_port();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
    cmd.env("OXO_EDGE_WORKER_HOP", "frame")
        .env("OXO_EDGE_THREADS", "1")
        .env("OXO_EDGE_KEEPALIVE", "1")
        .env("OXO_EDGE_BIND", format!("127.0.0.1:{port}"))
        .env("OXO_EDGE_ADMIN_BIND", format!("127.0.0.1:{admin_port}"))
        .env("OXO_EDGE_WORKER_SOCKET", &fixture.socket)
        .env("OXO_EDGE_MAX_BODY", "1024")
        .env("OXO_EDGE_SCHEME", "http")
        .env("OXO_EDGE_SERVER_NAME", "localhost")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut edge = cmd.spawn().expect("spawn header-rich frame edge");

    let wait_tcp = |port: u16| {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("header-rich frame edge never bound :{port}");
    };
    wait_tcp(port);
    wait_tcp(admin_port);

    let read_count = |admin_port: u16| -> u64 {
        let body = send_one_shot(admin_port, "/alloc-count");
        let text = String::from_utf8_lossy(&body);
        let tail = text
            .split("alloc_events_total\":")
            .nth(1)
            .expect("alloc-count admin route present");
        tail.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .expect("counter parses")
    };

    // 8 request headers: 4 mixed-case (lowercase-branch), 4 already-lowercase.
    let request: &[u8] = b"GET /hello HTTP/1.1\r\n\
        Host: localhost\r\n\
        User-Agent: ruler/1\r\n\
        Accept: */*\r\n\
        X-Custom-Trace: t-1\r\n\
        accept-language: en\r\n\
        cache-control: no-store\r\n\
        x-req-tag: r-1\r\n\
        x-tenant: alpha\r\n\r\n";
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect edge");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut read_one_response = |stream: &mut TcpStream, label: &str| {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            let got = stream.read(&mut byte).expect(label);
            assert!(got == 1, "{label}: connection closed mid-headers");
            buf.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
        assert!(head.contains("200"), "{label}: {head}");
        let clen: usize = head
            .split("content-length:")
            .nth(1)
            .map(|t| {
                t.trim_start()
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
            })
            .and_then(|d| d.parse().ok())
            .expect("content-length present under keepalive");
        let mut body = vec![0u8; clen];
        stream.read_exact(&mut body).expect(label);
    };

    stream.write_all(request).unwrap();
    read_one_response(&mut stream, "warm");
    served.recv_timeout(Duration::from_secs(5)).unwrap();

    let before = read_count(admin_port);
    for i in 0..n {
        stream.write_all(request).unwrap();
        read_one_response(&mut stream, &format!("rich request {i}"));
        served.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    let after = read_count(admin_port);

    let per_request = (after - before) as f64 / n as f64;
    eprintln!(
        "frame_hop HEADER-RICH alloc_events_per_request={per_request:.2} (n={n}, delta={})",
        after - before
    );
    // W-H first pin: introduced at 84.19 (pre-arena), measured 67.15 post-arena
    // (W-B collect pre-size −1, W-D header arena −16). Budget = measured + ~15%.
    const HEADER_RICH_ALLOC_EVENTS_PER_REQUEST_BUDGET: f64 = 73.0; // measured 63.15 post Date-capacity fix
    assert!(
        per_request <= HEADER_RICH_ALLOC_EVENTS_PER_REQUEST_BUDGET,
        "header-rich alloc events/request regressed: {per_request:.1} > {HEADER_RICH_ALLOC_EVENTS_PER_REQUEST_BUDGET}"
    );

    let _ = edge.kill();
    let _ = edge.wait();
}

/// M-D (bench-only `edge-bench` feature): the known-effect ladder's dose knob.
/// Proves the injected spin (a) announces itself LOUDLY at boot (a dosed run must never
/// masquerade as clean), and (b) actually burns the calibrated CPU — measured as
/// utime+stime ticks across a fixed request count, dosed-vs-undosed, using the same
/// /proc accounting the bench itself trusts. 500µs × 100 requests = 50ms of injected
/// CPU ≈ 5 ticks at USER_HZ=100; the undosed control burns ~1-2 ticks for the same
/// requests, so the assertion has a wide deterministic margin.
#[cfg(feature = "edge-bench")]
#[test]
fn injected_spin_announces_itself_and_burns_cpu() {
    let _guard = serial_test();

    let stat_ticks = |pid: u32| -> u64 {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        let after = stat.rsplit(')').next().unwrap_or("");
        let fields: Vec<&str> = after.split_whitespace().collect();
        let utime: u64 = fields.get(11).and_then(|f| f.parse().ok()).unwrap_or(0);
        let stime: u64 = fields.get(12).and_then(|f| f.parse().ok()).unwrap_or(0);
        utime + stime
    };

    let run_requests = |label: &str, spin_us: Option<&str>| -> (u64, String) {
        let fixture = Fixture::new(&format!("spin-{label}"));
        let n = 100usize;
        let listener = bind_worker_socket(&fixture.socket);
        let served = spawn_worker_many(listener, n);
        let port = free_port();
        let stderr_path = fixture.dir.join("edge.stderr");
        let stderr_file = fs::File::create(&stderr_path).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
        cmd.env("OXO_EDGE_WORKER_HOP", "http")
            .env("OXO_EDGE_THREADS", "1")
            .env("OXO_EDGE_BIND", format!("127.0.0.1:{port}"))
            .env("OXO_EDGE_WORKER_SOCKET", &fixture.socket)
            .env("OXO_EDGE_MAX_BODY", "1024")
            .env("OXO_EDGE_SCHEME", "http")
            .env("OXO_EDGE_SERVER_NAME", "localhost")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file));
        if let Some(us) = spin_us {
            cmd.env("OXO_EDGE_INJECT_SPIN_US", us);
        }
        let mut edge = cmd.spawn().expect("spawn edge");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "edge never bound");
            thread::sleep(Duration::from_millis(50));
        }
        let before = stat_ticks(edge.id());
        for i in 0..n {
            let response = send_one_shot(port, "/hello");
            assert!(
                String::from_utf8_lossy(&response).contains("200 OK"),
                "request {i} failed under spin={spin_us:?}"
            );
            served.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        let ticks = stat_ticks(edge.id()).saturating_sub(before);
        let _ = edge.kill();
        let _ = edge.wait();
        let stderr = fs::read_to_string(&stderr_path).unwrap_or_default();
        (ticks, stderr)
    };

    let (undosed_ticks, undosed_stderr) = run_requests("off", None);
    let (dosed_ticks, dosed_stderr) = run_requests("on", Some("500"));

    assert!(
        dosed_stderr.contains("INJECTED-SPIN: 500 us"),
        "the dose must announce itself at boot; stderr:\n{dosed_stderr}"
    );
    assert!(
        !undosed_stderr.contains("INJECTED-SPIN"),
        "an undosed run must not carry the injection notice"
    );
    // 100 × 500µs = 50ms ≈ 5 ticks injected; require the dosed run to burn at least
    // 3 more ticks than the control (wide margin against scheduler jitter).
    assert!(
        dosed_ticks >= undosed_ticks + 3,
        "injected spin must burn measurable CPU: dosed {dosed_ticks} ticks vs undosed {undosed_ticks}"
    );
}

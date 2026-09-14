#![cfg(target_os = "linux")]

mod support;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use support::{body, s1_rejection_cases, send_uds_raw, status};

use oxo_core::hop_frame::{self, FrameCaps, FramePrefix, RequestFrame, ResponseFrame, Scheme};

static SEQ: AtomicU64 = AtomicU64::new(0);

// drive the real worker's frame path directly (bypassing the edge) to isolate the
// binary hop from the edge pool. Encode a request frame, write it, read the response
// frame(s) back.
fn frame_caps() -> FrameCaps {
    FrameCaps {
        max_header_bytes: 64 * 1024,
        max_headers: 100,
        max_body_bytes: 1024 * 1024,
    }
}

fn read_one_response_frame(stream: &mut UnixStream) -> ResponseFrame {
    let mut prefix = [0u8; FramePrefix::LEN];
    stream.read_exact(&mut prefix).expect("read frame prefix");
    let parsed = FramePrefix::parse(&prefix, &frame_caps()).expect("parse prefix");
    let mut envelope = vec![0u8; parsed.remaining_length as usize];
    stream.read_exact(&mut envelope).expect("read envelope");
    hop_frame::decode_response(&envelope, &frame_caps()).expect("decode response")
}

#[test]
fn worker_frame_path_round_trips_a_get_request() {
    let tmp = TempTree::new();
    let app = tmp.app(
        "frame-echo.ru",
        r#"
app = lambda do |env|
  body = [
    "method=#{env['REQUEST_METHOD']}",
    "path=#{env['PATH_INFO']}",
    "scheme=#{env['rack.url_scheme']}",
    "remote=#{env['REMOTE_ADDR']}",
    "reserved=#{env.key?('HTTP_X_OXO_REMOTE_ADDR')}",
    "xff=#{env.key?('HTTP_X_FORWARDED_FOR')}",
  ].join("\n")
  [200, { 'content-type' => 'text/plain' }, [body]]
end
run app
"#,
    );
    let socket = tmp.socket();
    let worker = Worker::start(&app, &socket, 2, 1024, false);

    let mut stream = UnixStream::connect(&worker.socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    // A frame carrying spoofable headers: the worker must drop them (env parity with the
    // HTTP path) and use the native trusted fields.
    let frame = RequestFrame {
        method: "GET".into(),
        path: "/env".into(),
        query: String::new(),
        server_name: "app.example".into(),
        server_port: 443,
        scheme: Scheme::Http,
        remote_addr: "203.0.113.9".into(),
        headers: vec![
            ("host".into(), "client.example".into()),
            ("x-oxo-remote-addr".into(), "spoofed".into()),
            ("x-forwarded-for".into(), "198.51.100.1".into()),
        ],
        body: vec![],
    };
    stream
        .write_all(&hop_frame::encode_request(&frame).unwrap())
        .unwrap();

    let response = read_one_response_frame(&mut stream);
    let (status, body) = match response {
        ResponseFrame::Full { status, body, .. } => (status, body),
        other => panic!("expected Full response frame, got {other:?}"),
    };
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("method=GET"), "{text}");
    assert!(text.contains("path=/env"), "{text}");
    assert!(text.contains("remote=203.0.113.9"), "{text}");
    // The spoofable headers were dropped — never reached the Rack env.
    assert!(text.contains("reserved=false"), "{text}");
    assert!(text.contains("xff=false"), "{text}");

    // A second frame on the SAME connection proves the persistent loop.
    stream
        .write_all(&hop_frame::encode_request(&frame).unwrap())
        .unwrap();
    let second = read_one_response_frame(&mut stream);
    assert!(matches!(second, ResponseFrame::Full { status: 200, .. }));
}

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "oxo-worker-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self { root }
    }

    fn app(&self, name: &str, code: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, code).unwrap();
        path
    }

    fn socket(&self) -> PathBuf {
        self.root.join("worker.sock")
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Worker {
    child: Child,
    socket: PathBuf,
    stdout: Option<thread::JoinHandle<Vec<u8>>>,
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
}

impl Worker {
    fn start(app: &Path, socket: &Path, threads: usize, max_body: usize, rack_lint: bool) -> Self {
        Self::start_with_env(app, socket, threads, max_body, rack_lint, &[])
    }

    fn start_with_env(
        app: &Path,
        socket: &Path,
        threads: usize,
        max_body: usize,
        rack_lint: bool,
        extra_env: &[(&str, &str)],
    ) -> Self {
        let mut cmd = worker_command(app, socket, threads, max_body, rack_lint);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in extra_env {
            cmd.env(name, value);
        }
        let mut child = cmd.spawn().expect("spawn worker");
        let stdout = child.stdout.take().expect("worker stdout");
        let stderr = child.stderr.take().expect("worker stderr");
        let stderr = Some(drain_reader(stderr));
        let reader = wait_for_worker_ready(&mut child, stdout);
        let stdout = Some(drain_reader(reader));
        Self {
            child,
            socket: socket.to_path_buf(),
            stdout,
            stderr,
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(stdout) = self.stdout.take() {
            let _ = stdout.join();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
    }
}

struct CommandRun {
    output: std::process::Output,
    timed_out: bool,
}

fn worker_command(
    app: &Path,
    socket: &Path,
    threads: usize,
    max_body: usize,
    rack_lint: bool,
) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo-worker"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("OXO_WORKER_APP", app)
        .env("OXO_WORKER_SOCKET", socket)
        .env("OXO_WORKER_THREADS", threads.to_string())
        .env("OXO_WORKER_MAX_BODY", max_body.to_string())
        .env("OXO_WORKER_RACK_LINT", if rack_lint { "1" } else { "0" });
    if let Some(libdir) = ruby_libdir() {
        cmd.env("LD_LIBRARY_PATH", libdir);
    }
    cmd
}

fn run_worker_for_failure(app: &Path, socket: &Path) -> CommandRun {
    let mut cmd = worker_command(app, socket, 1, 1024, false);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_with_timeout(cmd, Duration::from_secs(5))
}

fn run_with_timeout(mut cmd: Command, timeout: Duration) -> CommandRun {
    let start = Instant::now();
    let mut child = cmd.spawn().expect("spawn command");
    loop {
        if child.try_wait().expect("poll child").is_some() {
            return CommandRun {
                output: child.wait_with_output().expect("collect command output"),
                timed_out: false,
            };
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            return CommandRun {
                output: child.wait_with_output().expect("collect timed-out output"),
                timed_out: true,
            };
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn read_until_contains(stream: &mut UnixStream, needle: &[u8]) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut out = Vec::new();
    let mut buf = [0u8; 128];
    loop {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0, "stream closed before {:?}: {:?}", needle, out);
        out.extend_from_slice(&buf[..n]);
        if out.windows(needle.len()).any(|window| window == needle) {
            return out;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {:?}: {:?}",
            needle,
            out
        );
    }
}
fn wait_for_worker_ready(child: &mut Child, stdout: ChildStdout) -> BufReader<ChildStdout> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line).map(|_| (line, reader));
        let _ = tx.send(result);
    });

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().expect("poll worker during readiness") {
            panic!("worker exited before readiness with {status}");
        }
        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok(Ok((line, reader))) => {
                assert!(
                    line.starts_with("OXO_WORKER_READY="),
                    "worker did not report readiness; got {line:?}"
                );
                return reader;
            }
            Ok(Err(err)) => panic!("read worker readiness: {err}"),
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("worker did not report readiness before timeout");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("worker readiness reader disconnected");
            }
        }
    }
}

fn drain_reader<R>(mut reader: R) -> thread::JoinHandle<Vec<u8>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut out = Vec::new();
        let _ = reader.read_to_end(&mut out);
        out
    })
}

fn ruby_libdir() -> Option<String> {
    let out = Command::new("ruby")
        .args(["-rrbconfig", "-e", "print RbConfig::CONFIG['libdir']"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn rack_lint_env_and_internal_metadata_are_clean() {
    let tmp = TempTree::new();
    let app = tmp.app(
        "env.ru",
        r#"
app = lambda do |env|
  lines = []
  lines << "remote=#{env['REMOTE_ADDR']}"
  lines << "scheme=#{env['rack.url_scheme']}"
  lines << "server=#{env['SERVER_NAME']}:#{env['SERVER_PORT']}"
  lines << "multithread=#{env['rack.multithread']}"
  lines << "multiprocess=#{env['rack.multiprocess']}"
  lines << "xff=#{env.key?('HTTP_X_FORWARDED_FOR')}"
  lines << "reserved=#{env.key?('HTTP_X_OXO_REMOTE_ADDR')}"
  [200, { 'content-type' => 'text/plain' }, [lines.join("\n")]]
end
run app
"#,
    );
    let socket = tmp.socket();
    let worker = Worker::start(&app, &socket, 2, 1024, true);
    let resp = send_uds_raw(
        &worker.socket,
        b"GET /hello HTTP/1.1\r\nHost: public.example:443\r\nX-Oxo-Remote-Addr: 203.0.113.7\r\nX-Oxo-Url-Scheme: https\r\nX-Oxo-Server-Name: app.example\r\nX-Oxo-Server-Port: 443\r\nX-Forwarded-For: 1.2.3.4\r\nForwarded: for=1.2.3.4\r\nX-Real-IP: 1.2.3.4\r\n\r\n",
    );
    assert_eq!(status(&resp), 200, "{resp}");
    let body = body(&resp);
    assert!(body.contains("remote=203.0.113.7"), "{body}");
    assert!(body.contains("scheme=https"), "{body}");
    assert!(body.contains("server=app.example:443"), "{body}");
    assert!(body.contains("multithread=true"), "{body}");
    assert!(body.contains("multiprocess=false"), "{body}");
    assert!(body.contains("xff=false"), "{body}");
    assert!(body.contains("reserved=false"), "{body}");
}

#[test]
fn gvl_safe_queue_allows_slow_requests_to_overlap() {
    let tmp = TempTree::new();
    let app = tmp.app(
        "slow.ru",
        r#"
app = lambda do |_env|
  sleep 0.75
  [200, { 'content-type' => 'text/plain' }, ['ok']]
end
run app
"#,
    );
    let socket = tmp.socket();
    let worker = Worker::start(&app, &socket, 4, 1024, true);
    let start = Instant::now();
    let a_socket = worker.socket.clone();
    let b_socket = worker.socket.clone();
    let a = thread::spawn(move || send_uds_raw(&a_socket, b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"));
    let b = thread::spawn(move || send_uds_raw(&b_socket, b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n"));
    assert_eq!(status(&a.join().unwrap()), 200);
    assert_eq!(status(&b.join().unwrap()), 200);
    assert!(
        start.elapsed() < Duration::from_millis(1300),
        "two 750ms Ruby sleeps serialized instead of overlapping: {:?}",
        start.elapsed()
    );
}

#[test]
fn boot_census_reports_realized_thread_config() {
    // the census line is the realized-config guard — the wiring defect ran
    // every banked "t4" arm single-threaded with nothing in the record to catch it.
    // The line must be on stderr (pre-READY stdout is consumed by the readiness
    // scanner) and must reflect the env the worker actually parsed.
    let tmp = TempTree::new();
    let app = tmp.app(
        "census.ru",
        r#"
run lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
"#,
    );
    let socket = tmp.socket();
    let mut cmd = worker_command(&app, &socket, 3, 1024, false);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn worker");
    let stdout = child.stdout.take().expect("worker stdout");
    let stderr = child.stderr.take().expect("worker stderr");
    let stderr_drain = drain_reader(stderr);
    let reader = wait_for_worker_ready(&mut child, stdout);
    let stdout_drain = drain_reader(reader);
    let _ = child.kill();
    let _ = child.wait();
    let _ = stdout_drain.join();
    let err = String::from_utf8_lossy(&stderr_drain.join().expect("stderr drain")).into_owned();
    assert!(
        err.contains(
            "oxo-worker: census threads=3 multithread=true multiprocess=false streaming=false"
        ),
        "census line missing or wrong in worker stderr: {err:?}"
    );
}

#[test]
fn strict_parser_rejects_conformance_cases_before_app_call() {
    let tmp = TempTree::new();
    let count = tmp.root.join("count.txt");
    let app = tmp.app(
        "count.ru",
        &format!(
            r#"
COUNT = {:?}
app = lambda do |_env|
  n = (File.exist?(COUNT) ? File.read(COUNT).to_i : 0) + 1
  File.write(COUNT, n.to_s)
  [200, {{ 'content-type' => 'text/plain' }}, ['called']]
end
run app
"#,
            count.to_string_lossy()
        ),
    );
    let socket = tmp.socket();
    let worker = Worker::start(&app, &socket, 1, 4, false);
    for case in s1_rejection_cases() {
        let resp = send_uds_raw(&worker.socket, case.request);
        assert_eq!(
            status(&resp),
            case.status,
            "case {} request {:?} -> {resp}",
            case.name,
            case.request
        );
    }
    assert!(!count.exists(), "rejected requests must not call Rack");
}

#[test]
fn worker_refuses_unsafe_socket_paths() {
    let tmp = TempTree::new();
    let app = tmp.app(
        "ok.ru",
        r#"app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );

    let unsafe_dir = tmp.root.join("unsafe");
    fs::create_dir_all(&unsafe_dir).unwrap();
    fs::set_permissions(&unsafe_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let run = run_worker_for_failure(&app, &unsafe_dir.join("worker.sock"));
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(!run.timed_out, "worker hung on unsafe dir: {stderr}");
    assert!(
        !run.output.status.success(),
        "unsafe dir unexpectedly booted"
    );
    assert!(stderr.contains("private 0700 directory"), "{stderr}");

    let non_socket = tmp.root.join("not-a-socket.sock");
    fs::write(&non_socket, b"not a socket").unwrap();
    let run = run_worker_for_failure(&app, &non_socket);
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(!run.timed_out, "worker hung on non-socket path: {stderr}");
    assert!(
        !run.output.status.success(),
        "non-socket path unexpectedly booted"
    );
    assert!(stderr.contains("non-socket path"), "{stderr}");
}

#[test]
fn response_writer_canonicalizes_app_framing_and_preserves_cookies() {
    let tmp = TempTree::new();
    let app = tmp.app(
        "response.ru",
        r#"
app = lambda do |_env|
  [200,
   {
     'content-type' => 'text/plain',
     'content-length' => '999',
     'transfer-encoding' => 'chunked',
     'connection' => 'keep-alive',
     'set-cookie' => ['a=1; path=/', 'b=2; path=/'],
     'bad name' => 'nope',
     'x-bad' => "split\r\nnope"
   },
   ['hello']]
end
run app
"#,
    );
    let socket = tmp.socket();
    let worker = Worker::start(&app, &socket, 1, 1024, false);
    let resp = send_uds_raw(&worker.socket, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(status(&resp), 200, "{resp}");
    assert!(resp.contains("content-length: 5\r\n"), "{resp}");
    assert!(resp.contains("connection: close\r\n"), "{resp}");
    assert_eq!(resp.matches("set-cookie:").count(), 2, "{resp}");
    assert!(!resp.contains("chunked"), "{resp}");
    assert!(!resp.contains("999"), "{resp}");
    assert!(!resp.contains("bad name"), "{resp}");
    assert!(!resp.contains("split"), "{resp}");
}

// A bare Rack app (NOT Rails cookie middleware, which emits arrays — the pre-existing
// Array(v) path) returning the Rack-2 "\n"-joined multi-value string form. Before the fix
// the embedded "\n" made the whole value CTL-rejected and dropped, losing every cookie.
#[test]
fn response_writer_splits_rack2_newline_joined_multivalue_headers() {
    let tmp = TempTree::new();
    let app = tmp.app(
        "multivalue.ru",
        "\napp = lambda do |_env|\n  [200,\n   {\n     'content-type' => 'text/plain',\n     'set-cookie' => \"a=1; path=/\\nb=2; path=/\",\n     'x-empty' => \"\",\n     'x-double' => \"one\\n\\ntwo\"\n   },\n   ['hello']]\nend\nrun app\n",
    );
    let socket = tmp.socket();
    let worker = Worker::start(&app, &socket, 1, 1024, false);
    let resp = send_uds_raw(&worker.socket, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(status(&resp), 200, "{resp}");
    // Both cookies survive as two distinct wire lines; no embedded LF reaches the wire.
    assert_eq!(resp.matches("set-cookie:").count(), 2, "{resp}");
    assert!(resp.contains("set-cookie: a=1; path=/\r\n"), "{resp}");
    assert!(resp.contains("set-cookie: b=2; path=/\r\n"), "{resp}");
    // A legitimately empty value is preserved as exactly one (empty) line.
    assert!(resp.contains("x-empty: \r\n"), "{resp}");
    // Double-"\n" splits into exactly two lines, no spurious blank line.
    assert_eq!(resp.matches("x-double:").count(), 2, "{resp}");
    assert!(resp.contains("x-double: one\r\n"), "{resp}");
    assert!(resp.contains("x-double: two\r\n"), "{resp}");
}

// The frame hop (oxo's default) carries the SAME WorkerResponse.headers, so the split
// must also reach the decoded response frame the edge builds the client response from.
#[test]
fn frame_path_splits_rack2_newline_joined_set_cookie() {
    let tmp = TempTree::new();
    let app = tmp.app(
        "frame-multivalue.ru",
        "\napp = lambda do |_env|\n  [200, { 'set-cookie' => \"a=1; path=/\\nb=2; path=/\" }, ['hi']]\nend\nrun app\n",
    );
    let socket = tmp.socket();
    let worker = Worker::start(&app, &socket, 1, 1024, false);

    let mut stream = UnixStream::connect(&worker.socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let frame = RequestFrame {
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        server_name: "app.example".into(),
        server_port: 443,
        scheme: Scheme::Http,
        remote_addr: "203.0.113.9".into(),
        headers: vec![("host".into(), "app.example".into())],
        body: vec![],
    };
    stream
        .write_all(&hop_frame::encode_request(&frame).unwrap())
        .unwrap();

    let headers = match read_one_response_frame(&mut stream) {
        ResponseFrame::Full {
            status, headers, ..
        } => {
            assert_eq!(status, 200);
            headers
        }
        other => panic!("expected Full response frame, got {other:?}"),
    };
    let cookies: Vec<&String> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v)
        .collect();
    assert_eq!(
        cookies.len(),
        2,
        "both cookies must be separate frame headers: {headers:?}"
    );
    assert!(cookies.iter().any(|v| *v == "a=1; path=/"), "{headers:?}");
    assert!(cookies.iter().any(|v| *v == "b=2; path=/"), "{headers:?}");
}

#[test]
fn streaming_worker_flushes_callable_body_chunks_incrementally_when_enabled() {
    let tmp = TempTree::new();
    let app = tmp.app(
        "streaming.ru",
        r#"
class StreamingBody
  def call(out)
    out.write "one\n"
    out.flush
    sleep 0.6
    out.write "two\n"
  end
end

app = lambda do |_env|
  [200, { 'content-type' => 'text/plain' }, StreamingBody.new]
end
run app
"#,
    );
    let socket = tmp.socket();
    let worker = Worker::start_with_env(
        &app,
        &socket,
        1,
        1024,
        false,
        &[("OXO_WORKER_STREAMING", "1")],
    );

    let mut stream = UnixStream::connect(&worker.socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    stream.shutdown(std::net::Shutdown::Write).ok();

    let started = Instant::now();
    let mut response = read_until_contains(&mut stream, b"one\n");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "first chunk was buffered until after the streaming body slept: {:?}",
        started.elapsed()
    );
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    response.extend(rest);
    let response = String::from_utf8_lossy(&response);

    assert!(response.contains("HTTP/1.1 200 OK"), "{response}");
    assert!(
        response.contains("transfer-encoding: chunked\r\n"),
        "{response}"
    );
    assert!(
        !response.to_ascii_lowercase().contains("content-length"),
        "{response}"
    );
    assert!(response.contains("4\r\none\n\r\n"), "{response}");
    assert!(response.contains("4\r\ntwo\n\r\n"), "{response}");
    assert!(response.ends_with("0\r\n\r\n"), "{response}");
}

#[test]
fn streaming_worker_stops_producer_thread_when_consumer_disconnects() {
    // D7/D8: when the client disconnects mid-stream, the Rust side closes the Ruby queue so
    // the producer thread's blocked `<<` raises ClosedQueueError and it stops. Without that,
    // an unbounded infinite generator would run (and buffer into the Ruby heap) forever. The
    // app body's `ensure` writes a marker only when its iteration actually unwinds, so the
    // marker appearing after a disconnect proves the producer thread stopped rather than
    // leaked.
    let tmp = TempTree::new();
    let marker = tmp.root.join("producer-stopped.marker");
    let app = tmp.app(
        "infinite-stream.ru",
        &format!(
            r#"
class InfiniteBody
  def call(out)
    i = 0
    loop do
      out.write("chunk#{{i}}\n")
      out.flush
      i += 1
    end
  ensure
    File.write({marker:?}, "stopped")
  end
end
app = lambda {{ |_env| [200, {{ 'content-type' => 'text/plain' }}, InfiniteBody.new] }}
run app
"#,
            marker = marker.display().to_string(),
        ),
    );
    let socket = tmp.socket();
    let worker = Worker::start_with_env(
        &app,
        &socket,
        1,
        1024,
        false,
        &[("OXO_WORKER_STREAMING", "1")],
    );

    {
        let mut stream = UnixStream::connect(&worker.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        stream.shutdown(std::net::Shutdown::Write).ok();
        // Read the first chunk to confirm the stream started, then drop the stream to
        // disconnect mid-stream.
        let _ = read_until_contains(&mut stream, b"chunk0\n");
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "producer thread did not stop after client disconnect (marker not written)"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn invalid_app_status_is_normalized_to_500() {
    let tmp = TempTree::new();
    let app = tmp.app(
        "bad_status.ru",
        r#"
app = lambda { |_env| [42, { 'content-type' => 'text/plain' }, ['bad']] }
run app
"#,
    );
    let socket = tmp.socket();
    let worker = Worker::start(&app, &socket, 1, 1024, false);
    let resp = send_uds_raw(&worker.socket, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(status(&resp), 500, "{resp}");
}

#[test]
fn pipelined_extra_bytes_get_one_response_then_eof() {
    let tmp = TempTree::new();
    let app = tmp.app(
        "ok.ru",
        r#"
app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );
    let socket = tmp.socket();
    let worker = Worker::start(&app, &socket, 1, 1024, true);
    let resp = send_uds_raw(
        &worker.socket,
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nokGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n",
    );
    assert_eq!(status(&resp), 200, "{resp}");
    assert_eq!(resp.matches("HTTP/1.1 ").count(), 1, "{resp}");
}

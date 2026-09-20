#![cfg(target_os = "linux")]

#[path = "support/process.rs"]
mod process_fixture;
#[path = "../../../test/support/ruby.rs"]
mod ruby_fixture;

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod support;
use support::{free_port, serial_test};

#[test]
#[ignore = "requires test/fixtures/external_services/run.rb and owned local services"]
fn redis_clean_shutdown_closes_cable() {
    let config = ExternalConfig::load();
    let _guard = serial_test();
    config.ensure_started();
    let fixture = ExternalFixture::spawn(&config);
    let _restore = ServiceRestore::new(config.clone(), &["redis"]);

    let (mut stream, response) = connect_action_cable(fixture.edge_port, "http://app.example");
    assert!(response.starts_with("HTTP/1.1 101"), "{response}");
    subscribe_and_expect_confirmation(
        &mut stream,
        r#"{"channel":"EchoChannel","room":"fixture-clean"}"#,
    );

    config.compose_must(&["stop", "redis"]);
    assert_ws_disconnect_within(&mut stream, config.redis_timeout_with_slack());
    let ready = fixture.ready_json();
    assert!(ready.contains("\"long_lived_active\":0"), "{ready}");
    assert!(
        ready.contains("\"long_lived_cancelled_total\":1"),
        "{ready}"
    );
}

#[test]
#[ignore = "requires test/fixtures/external_services/run.rb and owned local services"]
fn redis_partition_closes_cable_within_client_timeout() {
    let config = ExternalConfig::load();
    let _guard = serial_test();
    config.ensure_started();
    let fixture = ExternalFixture::spawn(&config);
    let _restore = ServiceRestore::new(config.clone(), &["redis"]);

    let (mut stream, response) = connect_action_cable(fixture.edge_port, "http://app.example");
    assert!(response.starts_with("HTTP/1.1 101"), "{response}");
    subscribe_and_expect_confirmation(
        &mut stream,
        r#"{"channel":"EchoChannel","room":"fixture-partition"}"#,
    );

    config.compose_must(&["pause", "redis"]);
    assert_ws_disconnect_within(&mut stream, config.redis_timeout_with_slack());
    let http = fixture.send_app(b"GET /hello HTTP/1.1\r\nHost: app.example\r\n\r\n");
    assert_eq!(http.status, 200, "{}", http.text());
    let ready = fixture.ready_json();
    assert!(ready.contains("\"long_lived_active\":0"), "{ready}");
    assert!(
        ready.contains("\"long_lived_cancelled_total\":1"),
        "{ready}"
    );
}

#[test]
#[ignore = "requires test/fixtures/external_services/run.rb and owned local services"]
fn redis_recovery_restores_fanout() {
    let config = ExternalConfig::load();
    let _guard = serial_test();
    config.ensure_started();
    let fixture = ExternalFixture::spawn(&config);
    let _restore = ServiceRestore::new(config.clone(), &["redis"]);

    config.compose_must(&["stop", "redis"]);
    config.compose_must(&["start", "redis"]);
    wait_for_external_redis(&fixture, config.redis_timeout_with_slack());

    let (mut stream, response) = connect_action_cable(fixture.edge_port, "http://app.example");
    assert!(response.starts_with("HTTP/1.1 101"), "{response}");
    let identifier = r#"{"channel":"EchoChannel","room":"fixture-recovery"}"#;
    subscribe_and_expect_confirmation(&mut stream, identifier);
    send_action_cable_message(&mut stream, identifier, "redis-recovered-fixture");
    let text = read_text_until(
        &mut stream,
        "redis-recovered-fixture",
        Duration::from_secs(5),
    );
    assert!(text.contains("redis"), "{text}");
    write_ws_close(&mut stream);
}

#[test]
#[ignore = "requires test/fixtures/external_services/run.rb and owned local services"]
fn db_pool_exhaustion_degrades_503_and_recovers_while_sse_streams() {
    let config = ExternalConfig::load();
    let _guard = serial_test();
    config.ensure_started();
    let fixture = ExternalFixture::spawn(&config);

    let mut sse = TcpStream::connect(("127.0.0.1", fixture.edge_port)).unwrap();
    sse.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sse.write_all(
        b"GET /events HTTP/1.1\r\nHost: app.example\r\nAccept: text/event-stream\r\n\r\n",
    )
    .unwrap();
    let first_event = read_tcp_until_contains(&mut sse, b"data: one");
    assert!(String::from_utf8_lossy(&first_event).contains("text/event-stream"));

    let hold_port = fixture.edge_port;
    let holder = thread::spawn(move || {
        send_tcp(
            hold_port,
            b"GET /pressure/hold?hold_ms=1200 HTTP/1.1\r\nHost: app.example\r\n\r\n",
        )
    });
    ruby_fixture::wait_for_file(&fixture._root.root.join("pool-entered"));
    let saturated =
        fixture.send_app(b"GET /pressure/hold?hold_ms=0 HTTP/1.1\r\nHost: app.example\r\n\r\n");
    assert_eq!(saturated.status, 503, "{}", saturated.text());
    assert!(
        saturated
            .body_text()
            .contains("\"reason\":\"db_pool_exhausted\""),
        "{}",
        saturated.body_text()
    );
    fs::write(fixture._root.root.join("pool-release"), "release").unwrap();
    assert_eq!(holder.join().expect("holder joins").status, 200);
    let recovered = fixture.send_app(b"GET /pressure/db HTTP/1.1\r\nHost: app.example\r\n\r\n");
    assert_eq!(recovered.status, 200, "{}", recovered.text());
    let later_sse = read_tcp_until_contains(&mut sse, b"data: two");
    assert!(String::from_utf8_lossy(&later_sse).contains("data: two"));
}

#[test]
#[ignore = "requires test/fixtures/external_services/run.rb and owned local services"]
fn db_partition_yields_bounded_errors_without_worker_crash_loop() {
    let config = ExternalConfig::load();
    let _guard = serial_test();
    config.ensure_started();
    let fixture = ExternalFixture::spawn(&config);
    let _restore = ServiceRestore::new(config.clone(), &["postgres"]);

    config.compose_must(&["pause", "postgres"]);
    let partitioned = fixture.send_app_timeout(
        b"GET /pressure/db HTTP/1.1\r\nHost: app.example\r\n\r\n",
        config.db_timeout_with_slack(),
    );
    assert!(
        partitioned.status == 503 || partitioned.status == 504 || partitioned.status == 0,
        "{}",
        partitioned.text()
    );
    let ready_during = fixture.ready_json();
    assert!(ready_during.contains("\"live\":true"), "{ready_during}");

    config.compose_must(&["unpause", "postgres"]);
    wait_for_external_db(&fixture, config.db_timeout_with_slack());
    let recovered = fixture.send_app(b"GET /pressure/db HTTP/1.1\r\nHost: app.example\r\n\r\n");
    assert_eq!(recovered.status, 200, "{}", recovered.text());
}

#[derive(Clone)]
struct ExternalConfig {
    database_url: String,
    redis_url: String,
    project: String,
    env_file: PathBuf,
    compose_file: PathBuf,
    db_timeout_ms: u64,
    redis_timeout_ms: u64,
}

impl ExternalConfig {
    fn load() -> Self {
        let dir = PathBuf::from(std::env::var_os("OXO_TEST_EXTERNAL_DIR").expect(
            "run test/fixtures/external_services/run.rb; arbitrary service URLs are not accepted",
        ));
        assert!(
            dir.is_absolute() && !dir.is_symlink(),
            "owned fixture directory required"
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let manifest = fs::read_to_string(dir.join("owned.env")).expect("owned service manifest");
        let values: std::collections::HashMap<_, _> = manifest
            .lines()
            .map(|line| line.split_once('=').expect("manifest key=value"))
            .collect();
        let project = values["PROJECT"].to_string();
        assert!(
            project.starts_with("oxo-external-")
                && project
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        );
        assert_eq!(
            project,
            dir.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_ascii_lowercase()
                .replace(
                    |c: char| !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-',
                    ""
                )
        );
        let pg: u16 = values["PG_PORT"].parse().expect("owned PostgreSQL port");
        let redis: u16 = values["REDIS_PORT"].parse().expect("owned Redis port");
        let password = values["PASSWORD"];
        assert!(password.len() == 64 && password.bytes().all(|b| b.is_ascii_hexdigit()));
        Self {
            database_url: format!(
                "postgresql://oxo_test:{password}@127.0.0.1:{pg}/oxo_test?connect_timeout=2"
            ),
            redis_url: format!("redis://127.0.0.1:{redis}/0"),
            project,
            env_file: dir.join("compose.env"),
            compose_file: workspace_root().join("test/fixtures/external_services/compose.yaml"),
            db_timeout_ms: 750,
            redis_timeout_ms: 750,
        }
    }

    fn ensure_started(&self) {
        self.compose_must(&["start", "--wait", "postgres", "redis"]);
    }

    fn compose_must(&self, args: &[&str]) {
        let output = self.compose(args);
        assert!(
            output.status.success(),
            "owned compose {:?} failed\nstdout:\n{}\nstderr:\n{}",
            args,
            ruby_fixture::diagnostic(&output.stdout),
            ruby_fixture::diagnostic(&output.stderr)
        );
    }

    fn compose_allow_failure(&self, args: &[&str]) {
        let _ = self.compose(args);
    }

    fn compose(&self, args: &[&str]) -> std::process::Output {
        let mut command = ruby_fixture::command("docker");
        command
            .arg("compose")
            .arg("--file")
            .arg(&self.compose_file)
            .arg("--project-name")
            .arg(&self.project)
            .arg("--env-file")
            .arg(&self.env_file);
        command
            .args(args)
            .output()
            .expect("run owned compose command")
    }

    fn db_timeout_with_slack(&self) -> Duration {
        Duration::from_millis(self.db_timeout_ms + 2_500)
    }

    fn redis_timeout_with_slack(&self) -> Duration {
        Duration::from_millis(self.redis_timeout_ms + 2_500)
    }
}

struct ServiceRestore {
    config: ExternalConfig,
    services: Vec<String>,
}

impl ServiceRestore {
    fn new(config: ExternalConfig, services: &[&str]) -> Self {
        Self {
            config,
            services: services.iter().map(|service| service.to_string()).collect(),
        }
    }
}

impl Drop for ServiceRestore {
    fn drop(&mut self) {
        for service in &self.services {
            self.config
                .compose_allow_failure(&["unpause", service.as_str()]);
        }
        let mut args = vec!["start"];
        args.extend(self.services.iter().map(String::as_str));
        self.config.compose_allow_failure(&args);
    }
}

struct ExternalFixture {
    _root: FixtureDir,
    edge_port: u16,
    admin_port: u16,
    _worker: WorkerProcess,
    _cable: ActionCableProcess,
    _edge: EdgeProcess,
}

impl ExternalFixture {
    fn spawn(config: &ExternalConfig) -> Self {
        let root = FixtureDir::new("fixture-external-pressure");
        let rails_root = workspace_root().join("test/fixtures/rails_app");
        let app = rails_root.join("config.ru");
        let cable_port = free_port();
        let edge_port = free_port();
        let admin_port = free_port();
        let mut env = external_rails_env(&rails_root, config, edge_port);
        env.push((
            "OXO_TEST_POOL_ENTERED".into(),
            root.root.join("pool-entered").to_str().unwrap().into(),
        ));
        env.push((
            "OXO_TEST_POOL_RELEASE".into(),
            root.root.join("pool-release").to_str().unwrap().into(),
        ));
        let _worker = WorkerProcess::spawn_with_env(&app, &root.socket, &env);
        let _cable = ActionCableProcess::spawn_with_env(&rails_root, cable_port, &env);
        wait_for_tcp(cable_port, "Action Cable");
        let _edge = EdgeProcess::spawn(edge_port, admin_port, &root.socket, cable_port);
        wait_for_tcp(edge_port, "edge");
        wait_for_tcp(admin_port, "admin");
        wait_for_external_db_raw(edge_port, config.db_timeout_with_slack());
        wait_for_external_redis_raw(edge_port, config.redis_timeout_with_slack());
        Self {
            _root: root,
            edge_port,
            admin_port,
            _worker,
            _cable,
            _edge,
        }
    }

    fn send_app(&self, request: &[u8]) -> HttpResponse {
        send_tcp(self.edge_port, request)
    }

    fn send_app_timeout(&self, request: &[u8], timeout: Duration) -> HttpResponse {
        send_tcp_timeout(self.edge_port, request, timeout)
    }

    fn ready_json(&self) -> String {
        let response = send_tcp(
            self.admin_port,
            b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
        );
        assert_eq!(response.status, 200, "{}", response.text());
        response.body_text()
    }
}

fn external_rails_env(
    rails_root: &Path,
    config: &ExternalConfig,
    edge_port: u16,
) -> Vec<(String, String)> {
    vec![
        (
            "BUNDLE_GEMFILE".to_string(),
            rails_root.join("Gemfile").to_string_lossy().into_owned(),
        ),
        ("BUNDLE_WITH".to_string(), "external_services".to_string()),
        ("RAILS_ENV".to_string(), "production_external".to_string()),
        ("RACK_ENV".to_string(), "production_external".to_string()),
        (
            "SECRET_KEY_BASE".to_string(),
            ruby_fixture::test_secret().to_string(),
        ),
        ("DATABASE_URL".to_string(), config.database_url.clone()),
        ("REDIS_URL".to_string(), config.redis_url.clone()),
        ("OXO_CABLE_ADAPTER".to_string(), "redis".to_string()),
        (
            "OXO_ACTION_CABLE_URL".to_string(),
            format!("ws://app.example:{edge_port}/cable"),
        ),
        (
            "OXO_RAILS_ALLOWED_HOSTS".to_string(),
            "app.example".to_string(),
        ),
        ("OXO_DB_POOL_SIZE".to_string(), "1".to_string()),
        (
            "OXO_DB_POOL_TIMEOUT_MS".to_string(),
            config.db_timeout_ms.to_string(),
        ),
        ("OXO_REDIS_POOL_SIZE".to_string(), "1".to_string()),
        (
            "OXO_REDIS_POOL_TIMEOUT_MS".to_string(),
            config.redis_timeout_ms.to_string(),
        ),
        ("RAILS_LOG_LEVEL".to_string(), "warn".to_string()),
    ]
}

struct FixtureDir {
    root: PathBuf,
    socket: PathBuf,
}

impl FixtureDir {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "oxo-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("worker.sock");
        Self { root, socket }
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct WorkerProcess {
    child: Child,
}

impl WorkerProcess {
    fn spawn_with_env(app: &Path, socket: &Path, extra_env: &[(String, String)]) -> Self {
        let mut command = ruby_fixture::command(worker_binary());
        command
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("OXO_WORKER_APP", app)
            .env("OXO_WORKER_SOCKET", socket)
            .env("OXO_WORKER_THREADS", "4")
            .env("OXO_WORKER_MAX_BODY", "1048576")
            .env("OXO_WORKER_RACK_LINT", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in extra_env {
            command.env(name, value);
        }
        if let Some(libdir) = ruby_libdir() {
            command.env("LD_LIBRARY_PATH", libdir);
        }
        let child = command.spawn().expect("spawn oxo-worker");
        let process = Self { child };
        let deadline = Instant::now() + Duration::from_secs(30);
        while std::os::unix::net::UnixStream::connect(socket).is_err() {
            assert!(
                Instant::now() < deadline,
                "external fixture worker did not become ready"
            );
            thread::sleep(Duration::from_millis(20));
        }
        process
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        process_fixture::kill_tree(&mut self.child);
    }
}

struct ActionCableProcess {
    child: Child,
}

impl ActionCableProcess {
    fn spawn_with_env(rails_root: &Path, port: u16, extra_env: &[(String, String)]) -> Self {
        let bind = format!("tcp://127.0.0.1:{port}");
        let mut command = ruby_fixture::command("bundle");
        command
            .arg("exec")
            .arg("puma")
            .arg("cable.ru")
            .arg("-b")
            .arg(bind)
            .current_dir(rails_root)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in extra_env {
            command.env(name, value);
        }
        let child = command.spawn().expect("spawn Action Cable fixture");

        Self { child }
    }
}

impl Drop for ActionCableProcess {
    fn drop(&mut self) {
        process_fixture::kill_tree(&mut self.child);
    }
}

struct EdgeProcess {
    child: Child,
}

impl EdgeProcess {
    fn spawn(edge_port: u16, admin_port: u16, worker_socket: &Path, cable_port: u16) -> Self {
        let mut command = ruby_fixture::command(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
        command
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("OXO_EDGE_BIND", format!("127.0.0.1:{edge_port}"))
            .env("OXO_EDGE_WORKER_SOCKET", worker_socket)
            .env("OXO_EDGE_MAX_BODY", "1048576")
            .env("OXO_EDGE_SERVER_NAME", "app.example")
            .env(
                "OXO_EDGE_ACTION_CABLE_BIND",
                format!("127.0.0.1:{cable_port}"),
            )
            .env("OXO_EDGE_ADMIN_BIND", format!("127.0.0.1:{admin_port}"))
            .env("OXO_EDGE_LONG_LIVED_MAX_CONNECTIONS", "16")
            .env("OXO_EDGE_LONG_LIVED_MAX_BUFFERED_BYTES", "1048576")
            .env("OXO_EDGE_LONG_LIVED_DOWNSTREAM_WRITE_TIMEOUT_MS", "1000")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().expect("spawn oxo-pingora-edge");
        Self { child }
    }
}

impl Drop for EdgeProcess {
    fn drop(&mut self) {
        process_fixture::kill_tree(&mut self.child);
    }
}

fn wait_for_external_db(fixture: &ExternalFixture, timeout: Duration) {
    wait_for_external_db_raw(fixture.edge_port, timeout);
}

fn wait_for_external_db_raw(edge_port: u16, timeout: Duration) {
    wait_until(timeout, || {
        send_tcp_timeout(
            edge_port,
            b"GET /pressure/db HTTP/1.1\r\nHost: app.example\r\n\r\n",
            Duration::from_secs(2),
        )
        .status
            == 200
    });
}

fn wait_for_external_redis(fixture: &ExternalFixture, timeout: Duration) {
    wait_for_external_redis_raw(fixture.edge_port, timeout);
}

fn wait_for_external_redis_raw(edge_port: u16, timeout: Duration) {
    wait_until(timeout, || {
        send_tcp_timeout(
            edge_port,
            b"GET /pressure/redis HTTP/1.1\r\nHost: app.example\r\n\r\n",
            Duration::from_secs(2),
        )
        .status
            == 200
    });
}

fn wait_until<F>(timeout: Duration, mut predicate: F)
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        if predicate() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for external fixture"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn connect_action_cable(port: u16, origin: &str) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let request = format!(
        "GET /cable HTTP/1.1\r\n\
Host: app.example\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Protocol: actioncable-v1-json\r\n\
Origin: {origin}\r\n\
Cookie: oxo_cable_session=ok\r\n\
\r\n"
    );
    stream.write_all(request.as_bytes()).unwrap();
    let response = read_http_head(&mut stream);
    (stream, String::from_utf8_lossy(&response).into_owned())
}

fn subscribe_and_expect_confirmation(stream: &mut TcpStream, identifier: &str) {
    let subscribe = format!(
        r#"{{"command":"subscribe","identifier":"{}"}}"#,
        json_escape(identifier)
    );
    write_ws_text(stream, &subscribe);
    let confirmation = read_text_until(stream, "confirm_subscription", Duration::from_secs(5));
    assert!(confirmation.contains("EchoChannel"), "{confirmation}");
}

fn send_action_cable_message(stream: &mut TcpStream, identifier: &str, message: &str) {
    let data = format!(r#"{{"action":"speak","message":"{message}"}}"#);
    let frame = format!(
        r#"{{"command":"message","identifier":"{}","data":"{}"}}"#,
        json_escape(identifier),
        json_escape(&data)
    );
    write_ws_text(stream, &frame);
}

fn assert_ws_disconnect_within(stream: &mut TcpStream, timeout: Duration) {
    stream.set_read_timeout(Some(timeout)).unwrap();
    match read_ws_frame(stream) {
        Ok(WsFrame::Close) => {}
        Ok(frame) => panic!("websocket stayed open with frame {frame:?}"),
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
            ) => {}
        Err(err) => panic!("websocket did not disconnect within {timeout:?}: {err}"),
    }
}

#[derive(Debug)]
enum WsFrame {
    Text(String),
    Ping(Vec<u8>),
    Pong,
    Close,
}

fn read_text_until(stream: &mut TcpStream, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut seen = String::new();
    while Instant::now() < deadline {
        match read_ws_frame(stream) {
            Ok(WsFrame::Text(text)) => {
                seen.push_str(&text);
                if seen.contains(needle) {
                    return text;
                }
            }
            Ok(WsFrame::Ping(payload)) => write_ws_frame(stream, 0xA, &payload),
            Ok(WsFrame::Pong) => {}
            Ok(WsFrame::Close) => panic!("websocket closed before {needle}: {seen}"),
            Err(err) if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {}
            Err(err) => panic!("read websocket frame: {err}; seen={seen}"),
        }
    }
    panic!("timed out waiting for {needle}; seen={seen}");
}

fn read_ws_frame(stream: &mut TcpStream) -> std::io::Result<WsFrame> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head)?;
    let opcode = head[0] & 0x0f;
    let masked = head[1] & 0x80 != 0;
    let mut len = u64::from(head[1] & 0x7f);
    if len == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext)?;
        len = u64::from(u16::from_be_bytes(ext));
    } else if len == 127 {
        let mut ext = [0u8; 8];
        stream.read_exact(&mut ext)?;
        len = u64::from_be_bytes(ext);
    }
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask)?;
    }
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload)?;
    if masked {
        for (idx, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[idx % 4];
        }
    }
    match opcode {
        0x1 => Ok(WsFrame::Text(
            String::from_utf8_lossy(&payload).into_owned(),
        )),
        0x8 => Ok(WsFrame::Close),
        0x9 => Ok(WsFrame::Ping(payload)),
        0xA => Ok(WsFrame::Pong),
        _ => read_ws_frame(stream),
    }
}

fn write_ws_text(stream: &mut TcpStream, text: &str) {
    write_ws_frame(stream, 0x1, text.as_bytes());
}

fn write_ws_close(stream: &mut TcpStream) {
    write_ws_frame(stream, 0x8, &[]);
}

fn write_ws_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) {
    let mut frame = Vec::new();
    frame.push(0x80 | opcode);
    if payload.len() < 126 {
        frame.push(0x80 | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    let mask = [0x13u8, 0x37, 0x42, 0x99];
    frame.extend_from_slice(&mask);
    for (idx, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[idx % 4]);
    }
    stream.write_all(&frame).unwrap();
}

fn read_http_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0, "connection closed before HTTP response head");
        response.extend_from_slice(&buf[..n]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            return response;
        }
    }
}

fn read_tcp_until_contains(stream: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => panic!(
                "connection closed before response contained {:?}: {}",
                String::from_utf8_lossy(needle),
                String::from_utf8_lossy(&response)
            ),
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if response
                    .windows(needle.len())
                    .any(|window| window == needle)
                {
                    return response;
                }
            }
            Err(err) => panic!("read edge response before needle: {err}"),
        }
    }
}

fn send_tcp(port: u16, request: &[u8]) -> HttpResponse {
    send_tcp_timeout(port, request, Duration::from_secs(5))
}

fn send_tcp_timeout(port: u16, request: &[u8], timeout: Duration) -> HttpResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(timeout)).unwrap();
    stream.write_all(request).unwrap();
    stream.shutdown(Shutdown::Write).ok();
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(err) if matches!(err.kind(), ErrorKind::ConnectionReset | ErrorKind::TimedOut) => {
                break
            }
            Err(err) => panic!("read edge response: {err}"),
        }
    }
    HttpResponse::parse(response)
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
    raw: Vec<u8>,
}

impl HttpResponse {
    fn parse(raw: Vec<u8>) -> Self {
        let Some(header_end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
            return Self {
                status: 0,
                body: Vec::new(),
                raw,
            };
        };
        let head = String::from_utf8_lossy(&raw[..header_end]);
        let status = head
            .split("\r\n")
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|status| status.parse().ok())
            .unwrap_or(0);
        let body = raw[header_end + 4..].to_vec();
        Self { status, body, raw }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.raw).into_owned()
    }

    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn worker_binary() -> PathBuf {
    ruby_fixture::worker_binary()
}

fn ruby_libdir() -> Option<String> {
    let out = ruby_fixture::command("ruby")
        .args(["-rrbconfig", "-e", "print RbConfig::CONFIG['libdir']"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn wait_for_tcp(port: u16, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{label} did not bind to 127.0.0.1:{port}"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

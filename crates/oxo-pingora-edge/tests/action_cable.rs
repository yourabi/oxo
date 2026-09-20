#![cfg(target_os = "linux")]

#[path = "support/process.rs"]
mod process_fixture;
#[path = "../../../test/support/ruby.rs"]
mod ruby_fixture;

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
#[path = "support/acquisition.rs"]
mod acquisition;
use acquisition::AcquisitionObserver;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod support;
use support::{free_port, serial_test};

#[test]
fn standalone_rails_action_cable_accepts_cookie_origin_and_echoes_over_websocket() {
    let _guard = serial_test();
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let port = free_port();
    let _cable = ActionCableProcess::spawn(&rails_root, port);
    wait_for_tcp(port);

    let rejected =
        websocket_handshake_response(port, "http://evil.example", Some("oxo_cable_session=ok"));
    assert!(
        !String::from_utf8_lossy(&rejected).starts_with("HTTP/1.1 101"),
        "evil origin unexpectedly upgraded: {}",
        String::from_utf8_lossy(&rejected)
    );

    let (mut unauthorized_stream, unauthorized_response) =
        connect_action_cable(port, "http://app.example", None);
    if unauthorized_response.starts_with("HTTP/1.1 101") {
        let text = read_optional_text(&mut unauthorized_stream, Duration::from_secs(1));
        assert!(
            !text
                .as_deref()
                .unwrap_or_default()
                .contains("\"type\":\"welcome\""),
            "unauthenticated Action Cable connection received welcome: {text:?}"
        );
    }
    unauthorized_stream.shutdown(Shutdown::Both).ok();

    let (mut stream, response) =
        connect_action_cable(port, "http://app.example", Some("oxo_cable_session=ok"));
    assert!(
        response.starts_with("HTTP/1.1 101"),
        "expected websocket upgrade, got {response}"
    );
    assert!(
        response
            .to_ascii_lowercase()
            .contains("sec-websocket-protocol: actioncable-v1-json"),
        "missing Action Cable subprotocol: {response}"
    );

    let welcome = read_text_until(&mut stream, "\"type\":\"welcome\"", Duration::from_secs(5));
    assert!(welcome.contains("welcome"), "{welcome}");

    let identifier = r#"{"channel":"EchoChannel","room":"fixture"}"#;
    let subscribe = format!(
        r#"{{"command":"subscribe","identifier":"{}"}}"#,
        json_escape(identifier)
    );
    write_ws_text(&mut stream, &subscribe);
    let confirmation = read_text_until(
        &mut stream,
        "\"type\":\"confirm_subscription\"",
        Duration::from_secs(5),
    );
    assert!(
        confirmation.contains("confirm_subscription"),
        "{confirmation}"
    );

    let data = r#"{"action":"speak","message":"hello-fixture"}"#;
    let message = format!(
        r#"{{"command":"message","identifier":"{}","data":"{}"}}"#,
        json_escape(identifier),
        json_escape(data)
    );
    write_ws_text(&mut stream, &message);
    let echo = read_text_until(&mut stream, "hello-fixture", Duration::from_secs(5));
    assert!(echo.contains("standalone-action-cable"), "{echo}");
    assert!(echo.contains("hello-fixture"), "{echo}");

    write_ws_close(&mut stream);
}

#[test]
fn standalone_action_cable_file_bus_degrades_and_reconnects() {
    let _guard = serial_test();
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let state_path = temp_state_path("action-cable-file-bus");
    fs::write(&state_path, "up").expect("write redis fixture up state");
    let state_string = state_path.to_string_lossy().into_owned();
    let port = free_port();
    let _cable = ActionCableProcess::spawn_with_env(
        &rails_root,
        port,
        &[
            ("OXO_CABLE_ADAPTER", "oxo_file_bus"),
            ("OXO_REDIS_FIXTURE_STATE", state_string.as_str()),
            ("OXO_REDIS_POOL_SIZE", "1"),
            ("OXO_REDIS_POOL_TIMEOUT_MS", "100"),
        ],
    );
    wait_for_tcp(port);

    let (mut stream, response) =
        connect_action_cable(port, "http://app.example", Some("oxo_cable_session=ok"));
    assert!(response.starts_with("HTTP/1.1 101"), "{response}");
    let identifier = r#"{"channel":"EchoChannel","room":"redis-fixture"}"#;
    let subscribe = format!(
        r#"{{"command":"subscribe","identifier":"{}"}}"#,
        json_escape(identifier)
    );
    write_ws_text(&mut stream, &subscribe);
    let confirmation = read_text_until(&mut stream, "confirm_subscription", Duration::from_secs(5));
    assert!(confirmation.contains("EchoChannel"), "{confirmation}");

    let up_one = format!(
        r#"{{"command":"message","identifier":"{}","data":"{}"}}"#,
        json_escape(identifier),
        json_escape(r#"{"action":"speak","message":"redis-up-one"}"#)
    );
    write_ws_text(&mut stream, &up_one);
    let up_echo = read_text_until(&mut stream, "redis-up-one", Duration::from_secs(5));
    assert!(up_echo.contains("file-bus"), "{up_echo}");

    fs::write(&state_path, "down").expect("write redis fixture down state");
    let down = format!(
        r#"{{"command":"message","identifier":"{}","data":"{}"}}"#,
        json_escape(identifier),
        json_escape(r#"{"action":"speak","message":"redis-down"}"#)
    );
    write_ws_text(&mut stream, &down);
    if let Some(text) = read_optional_text(&mut stream, Duration::from_millis(400)) {
        assert!(!text.contains("redis-down"), "{text}");
    }

    fs::write(&state_path, "up").expect("write redis fixture recovery state");
    let up_two = format!(
        r#"{{"command":"message","identifier":"{}","data":"{}"}}"#,
        json_escape(identifier),
        json_escape(r#"{"action":"speak","message":"redis-up-two"}"#)
    );
    write_ws_text(&mut stream, &up_two);
    let recovered = read_text_until(&mut stream, "redis-up-two", Duration::from_secs(5));
    assert!(recovered.contains("file-bus"), "{recovered}");

    write_ws_close(&mut stream);
    let _ = fs::remove_file(&state_path);
}

#[test]
fn standalone_action_cable_file_bus_fans_out_across_two_runtimes() {
    let _guard = serial_test();
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let state_path = temp_state_path("action-cable-redis-fanout-state");
    let bus_path = temp_state_path("action-cable-redis-fanout-bus");
    fs::write(&state_path, "up").expect("write redis fixture up state");
    fs::write(&bus_path, "").expect("write redis fixture bus");
    let state_string = state_path.to_string_lossy().into_owned();
    let bus_string = bus_path.to_string_lossy().into_owned();
    let port_a = free_port();
    let port_b = free_port();
    let common_env = [
        ("OXO_CABLE_ADAPTER", "oxo_file_bus"),
        ("OXO_REDIS_FIXTURE_STATE", state_string.as_str()),
        ("OXO_REDIS_FIXTURE_BUS", bus_string.as_str()),
        ("OXO_REDIS_POOL_SIZE", "2"),
        ("OXO_REDIS_POOL_TIMEOUT_MS", "100"),
    ];
    let _cable_a = ActionCableProcess::spawn_with_env(&rails_root, port_a, &common_env);
    let _cable_b = ActionCableProcess::spawn_with_env(&rails_root, port_b, &common_env);
    wait_for_tcp(port_a);
    wait_for_tcp(port_b);

    let (mut stream_a, response_a) =
        connect_action_cable(port_a, "http://app.example", Some("oxo_cable_session=ok"));
    assert!(response_a.starts_with("HTTP/1.1 101"), "{response_a}");
    let (mut stream_b, response_b) =
        connect_action_cable(port_b, "http://app.example", Some("oxo_cable_session=ok"));
    assert!(response_b.starts_with("HTTP/1.1 101"), "{response_b}");

    let identifier = r#"{"channel":"EchoChannel","room":"redis-fanout-fixture"}"#;
    subscribe_and_expect_confirmation(&mut stream_a, identifier);
    subscribe_and_expect_confirmation(&mut stream_b, identifier);

    send_action_cable_message(&mut stream_a, identifier, "redis-fanout-fixture-message");
    let fanout = read_text_until(
        &mut stream_b,
        "redis-fanout-fixture-message",
        Duration::from_secs(5),
    );
    assert!(fanout.contains("file-bus"), "{fanout}");
    assert!(fanout.contains("redis-fanout-fixture-message"), "{fanout}");

    write_ws_close(&mut stream_a);
    write_ws_close(&mut stream_b);
    let _ = fs::remove_file(&state_path);
    let _ = fs::remove_file(&bus_path);
}

#[test]
fn pingora_edge_routes_action_cable_without_touching_worker_uds() {
    let _guard = serial_test();
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let cable_port = free_port();
    let _cable = ActionCableProcess::spawn(&rails_root, cable_port);
    wait_for_tcp(cable_port);

    let fixture = EdgeFixture::new("edge-action-cable");
    let worker_listener = bind_worker_socket(&fixture.socket);
    let worker_records = spawn_recording_worker(worker_listener);
    let edge_port = free_port();
    let _edge = EdgeProcess::spawn(edge_port, &fixture.socket, cable_port, &[]);
    wait_for_tcp(edge_port);

    let rejected = websocket_handshake_response(
        edge_port,
        "http://evil.example",
        Some("oxo_cable_session=ok"),
    );
    assert!(
        !String::from_utf8_lossy(&rejected).starts_with("HTTP/1.1 101"),
        "evil origin unexpectedly upgraded through edge: {}",
        String::from_utf8_lossy(&rejected)
    );

    let (mut stream, response) = connect_action_cable(
        edge_port,
        "http://app.example",
        Some("oxo_cable_session=ok"),
    );
    assert!(
        response.starts_with("HTTP/1.1 101"),
        "expected edge websocket upgrade, got {response}"
    );
    assert!(
        response
            .to_ascii_lowercase()
            .contains("sec-websocket-protocol: actioncable-v1-json"),
        "edge did not preserve Action Cable subprotocol: {response}"
    );

    let welcome = read_text_until(&mut stream, "\"type\":\"welcome\"", Duration::from_secs(5));
    assert!(welcome.contains("welcome"), "{welcome}");
    assert_pong(&mut stream);

    let identifier = r#"{"channel":"EchoChannel","room":"edge-fixture"}"#;
    subscribe_and_expect_confirmation(&mut stream, identifier);
    send_action_cable_message(&mut stream, identifier, "hello-through-edge");
    let echo = read_text_until(&mut stream, "hello-through-edge", Duration::from_secs(5));
    assert!(echo.contains("standalone-action-cable"), "{echo}");
    assert!(echo.contains("hello-through-edge"), "{echo}");

    assert!(
        worker_records
            .recv_timeout(Duration::from_millis(800))
            .is_err(),
        "Action Cable route must not acquire the Rack worker UDS"
    );
    write_ws_close(&mut stream);
}

#[test]
fn pingora_edge_long_lived_cap_rejects_second_action_cable_upgrade() {
    let _guard = serial_test();
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let cable_port = free_port();
    let _cable = ActionCableProcess::spawn(&rails_root, cable_port);
    wait_for_tcp(cable_port);

    let fixture = EdgeFixture::new("edge-action-cable-cap");
    let worker_listener = bind_worker_socket(&fixture.socket);
    let worker_records = spawn_recording_worker(worker_listener);
    let edge_port = free_port();
    let _edge = EdgeProcess::spawn(
        edge_port,
        &fixture.socket,
        cable_port,
        &[("OXO_EDGE_LONG_LIVED_MAX_CONNECTIONS", "1")],
    );
    wait_for_tcp(edge_port);

    let (mut first, first_response) = connect_action_cable(
        edge_port,
        "http://app.example",
        Some("oxo_cable_session=ok"),
    );
    assert!(
        first_response.starts_with("HTTP/1.1 101"),
        "{first_response}"
    );
    let _ = read_text_until(&mut first, "\"type\":\"welcome\"", Duration::from_secs(5));

    let rejected = websocket_handshake_response(
        edge_port,
        "http://app.example",
        Some("oxo_cable_session=ok"),
    );
    assert!(
        String::from_utf8_lossy(&rejected).contains("503"),
        "second Action Cable upgrade should be saturated, got {}",
        String::from_utf8_lossy(&rejected)
    );
    assert!(
        worker_records
            .recv_timeout(Duration::from_millis(800))
            .is_err(),
        "saturated Action Cable route must not acquire the Rack worker UDS"
    );
    write_ws_close(&mut first);
}
struct ActionCableProcess {
    child: Child,
}

impl ActionCableProcess {
    fn spawn(rails_root: &Path, port: u16) -> Self {
        Self::spawn_with_env(rails_root, port, &[])
    }

    fn spawn_with_env(rails_root: &Path, port: u16, extra_env: &[(&str, &str)]) -> Self {
        let gemfile = rails_root.join("Gemfile");
        let bind = format!("tcp://127.0.0.1:{port}");
        let mut command = ruby_fixture::command("bundle");
        command
            .arg("exec")
            .arg("puma")
            .arg("cable.ru")
            .arg("-b")
            .arg(bind)
            .current_dir(rails_root)
            .env("OXO_EDGE_WORKER_HOP", "http")
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("BUNDLE_GEMFILE", &gemfile)
            .env("RAILS_ENV", "development")
            .env("RACK_ENV", "development")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in extra_env {
            command.env(name, value);
        }
        let child = command
            .spawn()
            .expect("spawn standalone Action Cable fixture");

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
    fn spawn(port: u16, worker_socket: &Path, cable_port: u16, extra_env: &[(&str, &str)]) -> Self {
        let mut command = ruby_fixture::command(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
        command
            .env("OXO_EDGE_BIND", format!("127.0.0.1:{port}"))
            .env("OXO_EDGE_WORKER_SOCKET", worker_socket)
            .env("OXO_EDGE_MAX_BODY", "1024")
            .env("OXO_EDGE_SERVER_NAME", "app.example")
            .env("OXO_EDGE_PUBLIC_ORIGIN_PORT", "80")
            .env(
                "OXO_EDGE_ACTION_CABLE_BIND",
                format!("127.0.0.1:{cable_port}"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in extra_env {
            command.env(name, value);
        }
        let child = command.spawn().expect("spawn oxo-pingora-edge");
        Self { child }
    }
}

impl Drop for EdgeProcess {
    fn drop(&mut self) {
        process_fixture::kill_tree(&mut self.child);
    }
}

struct EdgeFixture {
    dir: PathBuf,
    socket: PathBuf,
}

impl EdgeFixture {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "oxo-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("create edge fixture runtime dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .expect("set runtime dir permissions");
        let socket = dir.join("worker.sock");
        Self { dir, socket }
    }
}

impl Drop for EdgeFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn bind_worker_socket(path: &Path) -> UnixListener {
    if path.exists() {
        fs::remove_file(path).unwrap();
    }
    let listener = UnixListener::bind(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    listener
}

fn spawn_recording_worker(listener: UnixListener) -> AcquisitionObserver {
    AcquisitionObserver::new(listener)
}

fn websocket_handshake_response(port: u16, origin: &str, cookie: Option<&str>) -> Vec<u8> {
    let (stream, response) = connect_action_cable(port, origin, cookie);
    stream.shutdown(Shutdown::Both).ok();
    response.into_bytes()
}

fn connect_action_cable(port: u16, origin: &str, cookie: Option<&str>) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let cookie_header = cookie
        .map(|cookie| format!("Cookie: {cookie}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET /cable HTTP/1.1\r\n\
Host: app.example\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Protocol: actioncable-v1-json\r\n\
Origin: {origin}\r\n\
{cookie_header}\
\r\n"
    );
    stream.write_all(request.as_bytes()).unwrap();
    let response = read_http_head(&mut stream);
    (stream, String::from_utf8_lossy(&response).into_owned())
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

fn read_text_until(stream: &mut TcpStream, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut seen = String::new();
    while Instant::now() < deadline {
        match read_ws_frame(stream) {
            Ok(WsFrame::Text(text)) => {
                seen.push_str(&text);
                if text.contains(needle) || seen.contains(needle) {
                    return text;
                }
            }
            Ok(WsFrame::Ping(payload)) => write_ws_frame(stream, 0xA, &payload),
            Ok(WsFrame::Pong(_)) => {}
            Ok(WsFrame::Close) => panic!("websocket closed before {needle}: {seen}"),
            Err(err) if err.kind() == ErrorKind::TimedOut => {}
            Err(err) if err.kind() == ErrorKind::WouldBlock => {}
            Err(err) => panic!("read websocket frame: {err}; seen={seen}"),
        }
    }
    panic!("timed out waiting for {needle}; seen={seen}");
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

fn assert_pong(stream: &mut TcpStream) {
    write_ws_frame(stream, 0x9, b"oxo-ping");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match read_ws_frame(stream) {
            Ok(WsFrame::Pong(payload)) if payload == b"oxo-ping" => return,
            Ok(WsFrame::Text(_)) | Ok(WsFrame::Ping(_)) | Ok(WsFrame::Pong(_)) => {}
            Ok(WsFrame::Close) => panic!("websocket closed before pong"),
            Err(err) if err.kind() == ErrorKind::TimedOut => {}
            Err(err) if err.kind() == ErrorKind::WouldBlock => {}
            Err(err) => panic!("read websocket pong: {err}"),
        }
    }
    panic!("timed out waiting for websocket pong");
}

fn read_optional_text(stream: &mut TcpStream, timeout: Duration) -> Option<String> {
    stream.set_read_timeout(Some(timeout)).unwrap();
    let frame = match read_ws_frame(stream) {
        Ok(WsFrame::Text(text)) => Some(text),
        Ok(WsFrame::Ping(payload)) => {
            write_ws_frame(stream, 0xA, &payload);
            None
        }
        Ok(WsFrame::Pong(_)) => None,
        Ok(WsFrame::Close) => None,
        Err(err) if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => None,
        Err(err) => panic!("read optional websocket frame: {err}"),
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    frame
}

enum WsFrame {
    Text(String),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
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
        0xA => Ok(WsFrame::Pong(payload)),
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

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn wait_for_tcp(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("Action Cable fixture did not bind to 127.0.0.1:{port}");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn temp_state_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("oxo-{label}-{}-{nanos}.txt", std::process::id()))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

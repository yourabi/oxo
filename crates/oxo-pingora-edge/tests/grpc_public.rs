#![cfg(all(target_os = "linux", feature = "tls-rustls"))]

#[path = "support/process.rs"]
mod process_fixture;
#[path = "../../../test/support/ruby.rs"]
mod ruby_fixture;

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[path = "support/acquisition.rs"]
mod acquisition;
use acquisition::AcquisitionObserver;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod support;
use support::free_port;

static SEQ: AtomicUsize = AtomicUsize::new(0);

#[test]
fn public_smoke_beta_routes_unary_grpc_to_sidecar_without_worker_uds() {
    let fixture = Fixture::new("public-unary-grpc");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded_worker = spawn_recording_worker(listener);
    let grpc_port = free_port();
    let _grpc = GrpcProcess::spawn(&rails_root, grpc_port);
    wait_for_tcp(grpc_port);
    let edge_port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta(
        edge_port,
        admin_port,
        &fixture.socket,
        grpc_port,
        1024 * 1024,
        &cert,
        &key,
    );
    wait_for_tcp(edge_port);

    let output = run_grpc_client(
        &fixture.dir,
        &rails_root,
        edge_port,
        &cert,
        "public-edge",
        "runner",
        None,
    );

    assert_success(&output, "public gRPC client");
    let stdout = ruby_fixture::diagnostic(&output.stdout);
    assert!(stdout.contains("message=pong:runner"), "{stdout}");
    assert!(stdout.contains("rails_env=test"), "{stdout}");
    assert!(stdout.contains("metadata=public-edge"), "{stdout}");
    assert!(stdout.contains("edge_server_name=app.example"), "{stdout}");
    assert!(stdout.contains("spoofed_forwarded_for="), "{stdout}");
    assert!(stdout.contains("request_id=oxo-"), "{stdout}");
    assert!(
        recorded_worker
            .recv_timeout(Duration::from_millis(800))
            .is_err(),
        "public gRPC route must not acquire the Rack worker UDS"
    );
}

#[test]
fn public_smoke_beta_maps_unary_grpc_status_trailers() {
    let fixture = Fixture::new("public-unary-grpc-status");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded_worker = spawn_recording_worker(listener);
    let grpc_port = free_port();
    let _grpc = GrpcProcess::spawn(&rails_root, grpc_port);
    wait_for_tcp(grpc_port);
    let edge_port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta(
        edge_port,
        admin_port,
        &fixture.socket,
        grpc_port,
        1024 * 1024,
        &cert,
        &key,
    );
    wait_for_tcp(edge_port);

    let output = run_grpc_client(
        &fixture.dir,
        &rails_root,
        edge_port,
        &cert,
        "public-edge",
        "invalid",
        None,
    );

    assert_success(&output, "public gRPC status client");
    let stdout = ruby_fixture::diagnostic(&output.stdout);
    assert!(stdout.contains("grpc_error_code=3"), "{stdout}");
    assert!(
        stdout.contains("grpc_error_class=GRPC::InvalidArgument"),
        "{stdout}"
    );
    assert!(stdout.contains("oxo invalid"), "{stdout}");
    assert!(
        recorded_worker
            .recv_timeout(Duration::from_millis(800))
            .is_err(),
        "public gRPC status path must not acquire the Rack worker UDS"
    );
}

#[test]
fn public_smoke_beta_preserves_unary_grpc_deadline_cancellation() {
    let fixture = Fixture::new("public-unary-grpc-deadline");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded_worker = spawn_recording_worker(listener);
    let grpc_port = free_port();
    let _grpc = GrpcProcess::spawn(&rails_root, grpc_port);
    wait_for_tcp(grpc_port);
    let edge_port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta(
        edge_port,
        admin_port,
        &fixture.socket,
        grpc_port,
        1024 * 1024,
        &cert,
        &key,
    );
    wait_for_tcp(edge_port);

    let output = run_grpc_client(
        &fixture.dir,
        &rails_root,
        edge_port,
        &cert,
        "public-edge",
        "sleep:1200",
        Some(150),
    );

    assert_success(&output, "public gRPC deadline client");
    let stdout = ruby_fixture::diagnostic(&output.stdout);
    assert!(stdout.contains("grpc_error_code=4"), "{stdout}");
    assert!(
        stdout.contains("grpc_error_class=GRPC::DeadlineExceeded"),
        "{stdout}"
    );
    assert!(
        recorded_worker
            .recv_timeout(Duration::from_millis(800))
            .is_err(),
        "public gRPC deadline path must not acquire the Rack worker UDS"
    );
}

#[test]
fn public_smoke_beta_rejects_invalid_grpc_before_worker_or_sidecar() {
    for (label, max_body, args, expected) in [
        (
            "grpc-h1",
            1024,
            vec![
                "--http1.1",
                "--request",
                "POST",
                "--header",
                "Content-Type: application/grpc",
                "--header",
                "TE: trailers",
            ],
            "HTTP/1.1 400",
        ),
        (
            "grpc-web",
            1024,
            vec![
                "--http2",
                "--request",
                "POST",
                "--header",
                "Content-Type: application/grpc-web+proto",
                "--header",
                "TE: trailers",
            ],
            "HTTP/2 415",
        ),
        (
            "grpc-missing-te",
            1024,
            vec![
                "--http2",
                "--request",
                "POST",
                "--header",
                "Content-Type: application/grpc",
            ],
            "HTTP/2 400",
        ),
        (
            "grpc-overcap",
            4,
            vec![
                "--http2",
                "--request",
                "POST",
                "--header",
                "Content-Type: application/grpc",
                "--header",
                "TE: trailers",
                "--data-binary",
                "0123456789",
            ],
            "HTTP/2 413",
        ),
    ] {
        let fixture = Fixture::new(label);
        let (cert, key) = generate_tls_cert(&fixture.dir);
        let listener = bind_worker_socket(&fixture.socket);
        let recorded_worker = spawn_recording_worker(listener);
        let edge_port = free_port();
        let admin_port = free_port();
        let grpc_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let grpc_port = grpc_listener.local_addr().unwrap().port();
        let sidecar = AcquisitionObserver::tcp(grpc_listener);
        let _edge = EdgeProcess::spawn_public_smoke_beta(
            edge_port,
            admin_port,
            &fixture.socket,
            grpc_port,
            max_body,
            &cert,
            &key,
        );
        wait_for_tcp(edge_port);

        let response = curl_grpc(edge_port, &args);

        assert!(response.starts_with(expected), "{label}: {response}");
        assert!(
            sidecar.recv_timeout(Duration::from_millis(200)).is_err(),
            "invalid request acquired the sidecar"
        );
        assert!(
            recorded_worker
                .recv_timeout(Duration::from_millis(800))
                .is_err(),
            "{label} must reject before Rack worker UDS acquisition"
        );
    }
}

#[test]
fn public_smoke_beta_routes_server_streaming_grpc_with_long_lived_accounting() {
    let fixture = Fixture::new("public-streaming-grpc");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded_worker = spawn_recording_worker(listener);
    let grpc_port = free_port();
    let _grpc = GrpcProcess::spawn(&rails_root, grpc_port);
    wait_for_tcp(grpc_port);
    let edge_port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta(
        edge_port,
        admin_port,
        &fixture.socket,
        grpc_port,
        1024 * 1024,
        &cert,
        &key,
    );
    wait_for_tcp(edge_port);
    wait_for_tcp(admin_port);

    let output = run_server_stream_client(
        &fixture.dir,
        &rails_root,
        edge_port,
        &cert,
        StreamRequest {
            metadata: "streaming-edge",
            message: "server",
            count: 3,
            delay_ms: 0,
            payload_bytes: 0,
            take: None,
        },
    );

    assert_success(&output, "public server-streaming gRPC client");
    let stdout = ruby_fixture::diagnostic(&output.stdout);
    assert!(stdout.contains("stream_count=3"), "{stdout}");
    assert!(
        stdout.contains("stream_message=stream:0:server"),
        "{stdout}"
    );
    assert!(
        stdout.contains("stream_message=stream:2:server"),
        "{stdout}"
    );
    assert!(stdout.contains("metadata=streaming-edge"), "{stdout}");
    let ready = wait_until_admin_contains(admin_port, "\"long_lived_completed_total\":1");
    assert!(ready.contains("\"long_lived_active\":0"), "{ready}");
    assert!(
        ready.contains("\"long_lived_cancelled_total\":0"),
        "{ready}"
    );
    assert!(
        recorded_worker
            .recv_timeout(Duration::from_millis(800))
            .is_err(),
        "public streaming gRPC route must not acquire the Rack worker UDS"
    );
}

#[test]
fn public_smoke_beta_streaming_grpc_envelope_overflow_records_single_outcome() {
    // An overflowing sidecar response invokes response_filter for its 200 header
    // and fail_to_proxy for its stream error. Count one response outcome and one
    // cancelled stream, without recording a second outcome or a completed stream.
    let fixture = Fixture::new("public-grpc-envelope-overflow");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded_worker = spawn_recording_worker(listener);
    let grpc_port = free_port();
    let _grpc = GrpcProcess::spawn(&rails_root, grpc_port);
    wait_for_tcp(grpc_port);
    let edge_port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        edge_port,
        admin_port,
        &fixture.socket,
        grpc_port,
        1024 * 1024,
        TlsIdentity {
            cert: &cert,
            key: &key,
        }, // Tiny long-lived byte envelope so the streamed response overflows immediately.
        &[("OXO_EDGE_LONG_LIVED_MAX_BUFFERED_BYTES", "8")],
    );
    wait_for_tcp(edge_port);
    wait_for_tcp(admin_port);

    // The payload exceeds the 8-byte envelope and interrupts the response. The
    // assertions below check the edge's counters after that interruption.
    let _output = run_server_stream_client(
        &fixture.dir,
        &rails_root,
        edge_port,
        &cert,
        StreamRequest {
            metadata: "envelope-edge",
            message: "server",
            count: 2,
            delay_ms: 0,
            payload_bytes: 256,
            take: None,
        },
    );

    let ready = wait_until_admin_contains(admin_port, "\"long_lived_cancelled_total\":1");
    assert!(
        ready.contains("\"long_lived_completed_total\":0"),
        "{ready}"
    );
    assert!(ready.contains("\"long_lived_active\":0"), "{ready}");
    // The response header already accounts for this request. The stream error
    // must not increment rejection or response counters a second time.
    assert!(ready.contains("\"responses_total\":1"), "{ready}");
    assert!(ready.contains("\"rejections_total\":0"), "{ready}");
    assert!(ready.contains("\"status_2xx_total\":1"), "{ready}");
    assert!(ready.contains("\"status_5xx_total\":0"), "{ready}");
    assert!(
        recorded_worker
            .recv_timeout(Duration::from_millis(800))
            .is_err(),
        "gRPC envelope-overflow route must not acquire the Rack worker UDS"
    );
}

#[test]
fn public_smoke_beta_routes_bidi_streaming_grpc_request_response_flow() {
    let fixture = Fixture::new("public-bidi-grpc");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded_worker = spawn_recording_worker(listener);
    let grpc_port = free_port();
    let _grpc = GrpcProcess::spawn(&rails_root, grpc_port);
    wait_for_tcp(grpc_port);
    let edge_port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta(
        edge_port,
        admin_port,
        &fixture.socket,
        grpc_port,
        1024 * 1024,
        &cert,
        &key,
    );
    wait_for_tcp(edge_port);
    wait_for_tcp(admin_port);

    let output = run_bidi_stream_client(
        &fixture.dir,
        &rails_root,
        edge_port,
        &cert,
        "bidi-edge",
        &["one", "two", "three"],
    );

    assert_success(&output, "public bidi gRPC client");
    let stdout = ruby_fixture::diagnostic(&output.stdout);
    assert!(stdout.contains("bidi_count=3"), "{stdout}");
    assert!(stdout.contains("bidi_message=bidi:0:one"), "{stdout}");
    assert!(stdout.contains("bidi_message=bidi:2:three"), "{stdout}");
    assert!(stdout.contains("metadata=bidi-edge"), "{stdout}");
    let ready = wait_until_admin_contains(admin_port, "\"long_lived_completed_total\":1");
    assert!(ready.contains("\"long_lived_active\":0"), "{ready}");
    assert!(
        recorded_worker
            .recv_timeout(Duration::from_millis(800))
            .is_err(),
        "public bidi gRPC route must not acquire the Rack worker UDS"
    );
}

#[test]
fn public_smoke_beta_routes_client_streaming_grpc_request_flow() {
    let fixture = Fixture::new("public-client-stream-grpc");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded_worker = spawn_recording_worker(listener);
    let grpc_port = free_port();
    let _grpc = GrpcProcess::spawn(&rails_root, grpc_port);
    wait_for_tcp(grpc_port);
    let edge_port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta(
        edge_port,
        admin_port,
        &fixture.socket,
        grpc_port,
        1024 * 1024,
        &cert,
        &key,
    );
    wait_for_tcp(edge_port);
    wait_for_tcp(admin_port);

    let output = run_client_stream_client(
        &fixture.dir,
        &rails_root,
        edge_port,
        &cert,
        "client-stream-edge",
        &["red", "green", "blue"],
    );

    assert_success(&output, "public client-streaming gRPC client");
    let stdout = ruby_fixture::diagnostic(&output.stdout);
    assert!(
        stdout.contains("collect_message=collect:0:red|1:green|2:blue"),
        "{stdout}"
    );
    assert!(stdout.contains("metadata=client-stream-edge"), "{stdout}");
    let ready = wait_until_admin_contains(admin_port, "\"long_lived_completed_total\":1");
    assert!(ready.contains("\"long_lived_active\":0"), "{ready}");
    assert!(
        recorded_worker
            .recv_timeout(Duration::from_millis(800))
            .is_err(),
        "public client-streaming gRPC route must not acquire the Rack worker UDS"
    );
}

#[test]
fn public_smoke_beta_streaming_grpc_cap_rejects_second_stream_before_sidecar() {
    let fixture = Fixture::new("public-streaming-grpc-cap");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let (cert, key) = generate_tls_cert(&fixture.dir);
    let listener = bind_worker_socket(&fixture.socket);
    let recorded_worker = spawn_recording_worker(listener);
    let target_grpc_port = free_port();
    let _grpc = GrpcProcess::spawn(&rails_root, target_grpc_port);
    wait_for_tcp(target_grpc_port);
    let grpc_port = free_port();
    let sidecar_proxy = TcpProxy::spawn(grpc_port, target_grpc_port);
    let edge_port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        edge_port,
        admin_port,
        &fixture.socket,
        grpc_port,
        1024 * 1024,
        TlsIdentity {
            cert: &cert,
            key: &key,
        },
        &[("OXO_EDGE_LONG_LIVED_MAX_CONNECTIONS", "1")],
    );
    wait_for_tcp(edge_port);
    wait_for_tcp(admin_port);

    let mut held_stream = spawn_server_stream_client(
        &fixture.dir,
        &rails_root,
        edge_port,
        &cert,
        StreamRequest {
            metadata: "streaming-edge",
            message: "held",
            count: 3,
            delay_ms: 750,
            payload_bytes: 0,
            take: None,
        },
    );
    let ready = wait_until_admin_contains(admin_port, "\"long_lived_active\":1");
    assert!(ready.contains("\"long_lived_accepted_total\":1"), "{ready}");
    sidecar_proxy.wait_until_accepted(1);
    assert_eq!(
        sidecar_proxy.accepted(),
        1,
        "held stream should be the only sidecar TCP acquisition before saturation"
    );

    let response = curl_grpc(edge_port, &valid_grpc_curl_args());

    assert!(response.starts_with("HTTP/2 503"), "{response}");
    let ready = wait_until_admin_contains(admin_port, "\"long_lived_rejected_total\":1");
    assert!(ready.contains("\"long_lived_active\":1"), "{ready}");
    thread::sleep(Duration::from_millis(200));
    assert_eq!(
        sidecar_proxy.accepted(),
        1,
        "saturated public streaming gRPC request must not acquire the sidecar TCP listener"
    );
    assert_success(&held_stream.wait(), "held public streaming gRPC client");
    let ready = wait_until_admin_contains(admin_port, "\"long_lived_completed_total\":1");
    assert!(ready.contains("\"long_lived_active\":0"), "{ready}");
    assert!(
        recorded_worker
            .recv_timeout(Duration::from_millis(800))
            .is_err(),
        "public streaming gRPC cap path must not acquire the Rack worker UDS"
    );
}

fn run_grpc_client(
    temp_dir: &Path,
    rails_root: &Path,
    port: u16,
    cert: &Path,
    metadata: &str,
    message: &str,
    deadline_ms: Option<u64>,
) -> Output {
    let client = temp_dir.join(format!(
        "grpc-client-{}.rb",
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(
        &client,
        r#"
require_relative File.join(ARGV.fetch(0), "grpc", "oxo_fixture")

target = "127.0.0.1:#{ARGV.fetch(1)}"
cert = File.read(ARGV.fetch(2))
metadata_value = ARGV.fetch(3)
message = ARGV.fetch(4)
deadline_ms = ARGV.fetch(5).to_i
creds = GRPC::Core::ChannelCredentials.new(cert)
channel_args = {
  "grpc.ssl_target_name_override" => "app.example",
  "grpc.default_authority" => "app.example"
}
stub = OxoGrpc::FixtureService.rpc_stub_class.new(
  target,
  creds,
  channel_args: channel_args
)
deadline = deadline_ms.positive? ? Time.now + (deadline_ms / 1000.0) : Time.now + 5

begin
  reply = stub.ping(
    OxoGrpc::PingRequest.new("message" => message),
    metadata: {
      "x-oxo-test" => metadata_value,
      "x-forwarded-for" => "198.51.100.10",
      "x-oxo-server-name" => "spoofed-client"
    },
    deadline: deadline
  )
  puts "message=#{reply["message"]}"
  puts "rails_env=#{reply["rails_env"]}"
  puts "metadata=#{reply["metadata"]}"
  puts "edge_server_name=#{reply["edge_server_name"]}"
  puts "spoofed_forwarded_for=#{reply["spoofed_forwarded_for"]}"
  puts "request_id=#{reply["request_id"]}"
  puts "service=#{reply["service"]}"
rescue GRPC::BadStatus => e
  puts "grpc_error_class=#{e.class}"
  puts "grpc_error_code=#{e.code}"
  puts "grpc_error_details=#{e.details}"
end
"#,
    )
    .unwrap();
    ruby_fixture::command("bundle")
        .current_dir(rails_root)
        .env("BUNDLE_GEMFILE", rails_root.join("Gemfile"))
        .env("RAILS_ENV", "test")
        .args([
            "exec",
            "ruby",
            client.to_str().expect("client path is utf-8"),
            rails_root.to_str().expect("rails root path is utf-8"),
            &port.to_string(),
            cert.to_str().expect("cert path is utf-8"),
            metadata,
            message,
            &deadline_ms.unwrap_or(0).to_string(),
        ])
        .output()
        .expect("run rails grpc client")
}

struct StreamRequest<'a> {
    metadata: &'a str,
    message: &'a str,
    count: u64,
    delay_ms: u64,
    payload_bytes: u64,
    take: Option<u64>,
}

fn run_server_stream_client(
    temp_dir: &Path,
    rails_root: &Path,
    port: u16,
    cert: &Path,
    request: StreamRequest<'_>,
) -> Output {
    let StreamRequest {
        metadata,
        message,
        count,
        delay_ms,
        payload_bytes,
        take,
    } = request;
    let mut client = spawn_server_stream_client(
        temp_dir,
        rails_root,
        port,
        cert,
        StreamRequest {
            metadata,
            message,
            count,
            delay_ms,
            payload_bytes,
            take,
        },
    );
    client.wait()
}

fn spawn_server_stream_client(
    temp_dir: &Path,
    rails_root: &Path,
    port: u16,
    cert: &Path,
    request: StreamRequest<'_>,
) -> ClientProcess {
    let StreamRequest {
        metadata,
        message,
        count,
        delay_ms,
        payload_bytes,
        take,
    } = request;
    let client = temp_dir.join(format!(
        "grpc-server-stream-client-{}.rb",
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(
        &client,
        r#"
require_relative File.join(ARGV.fetch(0), "grpc", "oxo_fixture")

target = "127.0.0.1:#{ARGV.fetch(1)}"
cert = File.read(ARGV.fetch(2))
metadata_value = ARGV.fetch(3)
message = ARGV.fetch(4)
count = ARGV.fetch(5).to_i
delay_ms = ARGV.fetch(6).to_i
payload_bytes = ARGV.fetch(7).to_i
take = ARGV.fetch(8).to_i
creds = GRPC::Core::ChannelCredentials.new(cert)
channel_args = {
  "grpc.ssl_target_name_override" => "app.example",
  "grpc.default_authority" => "app.example"
}
stub = OxoGrpc::FixtureService.rpc_stub_class.new(
  target,
  creds,
  channel_args: channel_args
)
request = OxoGrpc::PingRequest.new(
  "message" => message,
  "count" => count.to_s,
  "delay_ms" => delay_ms.to_s,
  "payload_bytes" => payload_bytes.to_s
)
seen = 0
begin
  stub.stream_pings(
    request,
    metadata: {
      "x-oxo-test" => metadata_value,
      "x-forwarded-for" => "198.51.100.10",
      "x-oxo-server-name" => "spoofed-client"
    },
    deadline: Time.now + 10
  ).each do |reply|
    puts "stream_message=#{reply["message"]}"
    puts "metadata=#{reply["metadata"]}"
    puts "request_id=#{reply["request_id"]}"
    puts "payload_bytes=#{reply["payload"].to_s.bytesize}"
    seen += 1
    break if take.positive? && seen >= take
  end
  puts "stream_count=#{seen}"
rescue GRPC::BadStatus => e
  puts "grpc_error_class=#{e.class}"
  puts "grpc_error_code=#{e.code}"
  puts "grpc_error_details=#{e.details}"
end
"#,
    )
    .unwrap();
    let args = vec![
        rails_root.to_string_lossy().into_owned(),
        port.to_string(),
        cert.to_string_lossy().into_owned(),
        metadata.to_string(),
        message.to_string(),
        count.to_string(),
        delay_ms.to_string(),
        payload_bytes.to_string(),
        take.unwrap_or(0).to_string(),
    ];
    spawn_rails_ruby(rails_root, &client, &args)
}

fn run_bidi_stream_client(
    temp_dir: &Path,
    rails_root: &Path,
    port: u16,
    cert: &Path,
    metadata: &str,
    messages: &[&str],
) -> Output {
    let client = temp_dir.join(format!(
        "grpc-bidi-client-{}.rb",
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(
        &client,
        r#"
require_relative File.join(ARGV.fetch(0), "grpc", "oxo_fixture")

target = "127.0.0.1:#{ARGV.fetch(1)}"
cert = File.read(ARGV.fetch(2))
metadata_value = ARGV.fetch(3)
messages = ARGV.drop(4)
creds = GRPC::Core::ChannelCredentials.new(cert)
channel_args = {
  "grpc.ssl_target_name_override" => "app.example",
  "grpc.default_authority" => "app.example"
}
stub = OxoGrpc::FixtureService.rpc_stub_class.new(
  target,
  creds,
  channel_args: channel_args
)
requests = messages.map { |message| OxoGrpc::PingRequest.new("message" => message) }
seen = 0
begin
  stub.bidi_pings(
    requests,
    metadata: {
      "x-oxo-test" => metadata_value,
      "x-forwarded-for" => "198.51.100.10",
      "x-oxo-server-name" => "spoofed-client"
    },
    deadline: Time.now + 10
  ).each do |reply|
    puts "bidi_message=#{reply["message"]}"
    puts "metadata=#{reply["metadata"]}"
    puts "request_id=#{reply["request_id"]}"
    seen += 1
  end
  puts "bidi_count=#{seen}"
rescue GRPC::BadStatus => e
  puts "grpc_error_class=#{e.class}"
  puts "grpc_error_code=#{e.code}"
  puts "grpc_error_details=#{e.details}"
end
"#,
    )
    .unwrap();
    let mut args = vec![
        rails_root.to_string_lossy().into_owned(),
        port.to_string(),
        cert.to_string_lossy().into_owned(),
        metadata.to_string(),
    ];
    args.extend(messages.iter().map(|message| message.to_string()));
    let mut process = spawn_rails_ruby(rails_root, &client, &args);
    process.wait()
}

fn run_client_stream_client(
    temp_dir: &Path,
    rails_root: &Path,
    port: u16,
    cert: &Path,
    metadata: &str,
    messages: &[&str],
) -> Output {
    let client = temp_dir.join(format!(
        "grpc-client-stream-client-{}.rb",
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(
        &client,
        r#"
require_relative File.join(ARGV.fetch(0), "grpc", "oxo_fixture")

target = "127.0.0.1:#{ARGV.fetch(1)}"
cert = File.read(ARGV.fetch(2))
metadata_value = ARGV.fetch(3)
messages = ARGV.drop(4)
creds = GRPC::Core::ChannelCredentials.new(cert)
channel_args = {
  "grpc.ssl_target_name_override" => "app.example",
  "grpc.default_authority" => "app.example"
}
stub = OxoGrpc::FixtureService.rpc_stub_class.new(
  target,
  creds,
  channel_args: channel_args
)
requests = messages.map { |message| OxoGrpc::PingRequest.new("message" => message) }
begin
  reply = stub.collect_pings(
    requests,
    metadata: {
      "x-oxo-test" => metadata_value,
      "x-forwarded-for" => "198.51.100.10",
      "x-oxo-server-name" => "spoofed-client"
    },
    deadline: Time.now + 10
  )
  puts "collect_message=#{reply["message"]}"
  puts "metadata=#{reply["metadata"]}"
  puts "request_id=#{reply["request_id"]}"
rescue GRPC::BadStatus => e
  puts "grpc_error_class=#{e.class}"
  puts "grpc_error_code=#{e.code}"
  puts "grpc_error_details=#{e.details}"
end
"#,
    )
    .unwrap();
    let mut args = vec![
        rails_root.to_string_lossy().into_owned(),
        port.to_string(),
        cert.to_string_lossy().into_owned(),
        metadata.to_string(),
    ];
    args.extend(messages.iter().map(|message| message.to_string()));
    let mut process = spawn_rails_ruby(rails_root, &client, &args);
    process.wait()
}

struct ClientProcess {
    child: Option<process_fixture::CapturedChild>,
}

impl ClientProcess {
    fn wait(&mut self) -> Output {
        let (output, timed_out) = self
            .child
            .take()
            .expect("live client")
            .wait(Duration::from_secs(20));
        assert!(
            !timed_out,
            "gRPC client timed out: {}",
            ruby_fixture::diagnostic(&output.stderr)
        );
        output
    }
}

fn spawn_rails_ruby(rails_root: &Path, script: &Path, args: &[String]) -> ClientProcess {
    let child = ruby_fixture::command("bundle")
        .current_dir(rails_root)
        .env("BUNDLE_GEMFILE", rails_root.join("Gemfile"))
        .env("RAILS_ENV", "test")
        .arg("exec")
        .arg("ruby")
        .arg(script)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rails grpc client");
    ClientProcess {
        child: Some(process_fixture::CapturedChild::new(child)),
    }
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        ruby_fixture::diagnostic(&output.stdout),
        ruby_fixture::diagnostic(&output.stderr)
    );
}

struct GrpcProcess {
    child: Child,
}

impl GrpcProcess {
    fn spawn(rails_root: &Path, port: u16) -> Self {
        let child = ruby_fixture::command("bundle")
            .current_dir(rails_root)
            .env("BUNDLE_GEMFILE", rails_root.join("Gemfile"))
            .env("RAILS_ENV", "test")
            .env("SECRET_KEY_BASE", ruby_fixture::test_secret())
            .env("OXO_GRPC_BIND", format!("127.0.0.1:{port}"))
            .args(["exec", "ruby", "bin/oxo-grpc"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn gruf gRPC fixture");

        Self { child }
    }
}

impl Drop for GrpcProcess {
    fn drop(&mut self) {
        process_fixture::kill_tree(&mut self.child);
    }
}

struct TlsIdentity<'a> {
    cert: &'a Path,
    key: &'a Path,
}

struct EdgeProcess {
    child: Child,
}

impl EdgeProcess {
    fn spawn_public_smoke_beta(
        port: u16,
        admin_port: u16,
        socket: &Path,
        grpc_port: u16,
        max_body: u64,
        cert: &Path,
        key: &Path,
    ) -> Self {
        Self::spawn_public_smoke_beta_with_env(
            port,
            admin_port,
            socket,
            grpc_port,
            max_body,
            TlsIdentity { cert, key },
            &[],
        )
    }

    fn spawn_public_smoke_beta_with_env(
        port: u16,
        admin_port: u16,
        socket: &Path,
        grpc_port: u16,
        max_body: u64,
        tls: TlsIdentity<'_>,
        extra_env: &[(&str, &str)],
    ) -> Self {
        let TlsIdentity { cert, key } = tls;
        let mut command = ruby_fixture::command(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
        command
            .env("OXO_EDGE_WORKER_HOP", "http")
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("OXO_EDGE_BIND", format!("0.0.0.0:{port}"))
            .env("OXO_EDGE_WORKER_SOCKET", socket)
            .env("OXO_EDGE_MAX_BODY", max_body.to_string())
            .env("OXO_EDGE_SERVER_NAME", "app.example")
            .env("OXO_EDGE_TLS", "1")
            .env("OXO_EDGE_TLS_CERT", cert)
            .env("OXO_EDGE_TLS_KEY", key)
            .env("OXO_EDGE_TLS_H2", "1")
            .env("OXO_EDGE_PUBLIC_MODE", "smoke-beta")
            .env("OXO_EDGE_PUBLIC_IDENTITY", "direct-public")
            .env("OXO_EDGE_MAX_IN_FLIGHT_REQUESTS", "128")
            .env("OXO_EDGE_ADMIN_BIND", format!("127.0.0.1:{admin_port}"))
            .env("OXO_EDGE_GRPC_BIND", format!("127.0.0.1:{grpc_port}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in extra_env {
            command.env(name, value);
        }
        let child = command.spawn().expect("spawn TLS oxo-pingora-edge");

        Self { child }
    }
}

impl Drop for EdgeProcess {
    fn drop(&mut self) {
        process_fixture::kill_tree(&mut self.child);
    }
}

struct TcpProxy {
    port: u16,
    shutdown: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TcpProxy {
    fn spawn(port: u16, target_port: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind TCP proxy");
        listener
            .set_nonblocking(true)
            .expect("set TCP proxy nonblocking");
        let shutdown = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicUsize::new(0));
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_accepted = Arc::clone(&accepted);
        let thread = thread::spawn(move || {
            let mut pairs = Vec::new();
            while !thread_shutdown.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((inbound, _)) => {
                        thread_accepted.fetch_add(1, Ordering::Relaxed);
                        match TcpStream::connect(("127.0.0.1", target_port)) {
                            Ok(outbound) => pairs.push(proxy_tcp_pair(inbound, outbound)),
                            Err(_) => break,
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            shutdown,
            accepted,
            thread: Some(thread),
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Relaxed)
    }

    fn wait_until_accepted(&self, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if self.accepted() >= expected {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "TCP proxy accepted {} connection(s), expected at least {expected}",
                    self.accepted()
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for TcpProxy {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct ProxyPair {
    sockets: [TcpStream; 2],
    threads: Vec<thread::JoinHandle<()>>,
}
impl Drop for ProxyPair {
    fn drop(&mut self) {
        for socket in &self.sockets {
            let _ = socket.shutdown(Shutdown::Both);
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}
fn proxy_tcp_pair(mut inbound: TcpStream, mut outbound: TcpStream) -> ProxyPair {
    let sockets = [inbound.try_clone().unwrap(), outbound.try_clone().unwrap()];
    let mut inbound_read = inbound.try_clone().expect("clone inbound TCP proxy");
    let mut outbound_write = outbound.try_clone().expect("clone outbound TCP proxy");
    let a = thread::spawn(move || {
        let _ = io::copy(&mut inbound_read, &mut outbound_write);
        let _ = outbound_write.shutdown(Shutdown::Write);
    });
    let b = thread::spawn(move || {
        let _ = io::copy(&mut outbound, &mut inbound);
        let _ = inbound.shutdown(Shutdown::Write);
    });
    ProxyPair {
        sockets,
        threads: vec![a, b],
    }
}

struct Fixture {
    dir: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "oxo-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("create fixture dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("fixture dir mode");
        let socket = dir.join("worker.sock");
        Self { dir, socket }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn bind_worker_socket(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    listener
}

fn spawn_recording_worker(listener: UnixListener) -> AcquisitionObserver {
    AcquisitionObserver::new(listener)
}

fn curl_grpc(port: u16, args: &[&str]) -> String {
    let url = format!("https://app.example:{port}/oxo.fixture.Fixture/Ping");
    let resolve = format!("app.example:{port}:127.0.0.1");
    let mut cmd = ruby_fixture::command("curl");
    cmd.arg("--silent")
        .arg("--show-error")
        .arg("--insecure")
        .arg("--noproxy")
        .arg("*")
        .arg("--max-time")
        .arg("5")
        .arg("--dump-header")
        .arg("-")
        .arg("--resolve")
        .arg(resolve);
    for arg in args {
        cmd.arg(arg);
    }
    let output = cmd.arg(url).output().expect("run curl");
    if !output.status.success() && output.stdout.is_empty() {
        return format!("curl-error: {}", ruby_fixture::diagnostic(&output.stderr));
    }
    ruby_fixture::diagnostic(&output.stdout)
}

fn valid_grpc_curl_args() -> Vec<&'static str> {
    vec![
        "--http2",
        "--request",
        "POST",
        "--header",
        "Content-Type: application/grpc",
        "--header",
        "TE: trailers",
    ]
}

fn send_tcp(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect TCP");
    stream.write_all(request).expect("write admin TCP request");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break
            }
            Err(err) => panic!("read admin TCP response: {err}"),
        }
    }
    response
}

fn wait_until_admin_contains(admin_port: u16, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = String::from_utf8_lossy(&send_tcp(
            admin_port,
            b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
        ))
        .into_owned();
        if response.contains(needle) {
            return response;
        }
        if Instant::now() >= deadline {
            panic!("admin response did not contain {needle}: {response}");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn generate_tls_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let cert = dir.join("app.example.cert.pem");
    let key = dir.join("app.example.key.pem");
    let output = ruby_fixture::command("openssl")
        .arg("req")
        .arg("-x509")
        .arg("-newkey")
        .arg("rsa:2048")
        .arg("-nodes")
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .arg("-subj")
        .arg("/CN=app.example")
        .arg("-addext")
        .arg("subjectAltName=DNS:app.example,IP:127.0.0.1")
        .arg("-days")
        .arg("1")
        .output()
        .expect("run openssl");
    assert!(
        output.status.success(),
        "openssl failed: {}",
        ruby_fixture::diagnostic(&output.stderr)
    );
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    (cert, key)
}

fn wait_for_tcp(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(_) => return,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Err(_) => panic!("process did not bind to 127.0.0.1:{port}"),
        }
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

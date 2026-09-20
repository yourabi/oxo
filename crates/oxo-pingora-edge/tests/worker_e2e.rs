#![cfg(target_os = "linux")]

#[path = "support/process.rs"]
mod process_fixture;
#[path = "../../../test/support/ruby.rs"]
mod ruby_fixture;

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "tls-rustls")]
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod support;
use support::{free_port, serial_test};

static SEQ: AtomicU64 = AtomicU64::new(0);

#[test]
fn rack_lint_env_is_clean_through_pingora_and_native_worker() {
    let _guard = serial_test();
    let fixture = Fixture::new("rack-lint");
    let app = fixture.app(
        "lint.ru",
        r#"
app = lambda do |env|
  body = [
    "method=#{env['REQUEST_METHOD']}",
    "scheme=#{env['rack.url_scheme']}",
    "server=#{env['SERVER_NAME']}:#{env['SERVER_PORT']}",
    "multithread=#{env['rack.multithread']}",
    "multiprocess=#{env['rack.multiprocess']}",
    "xff=#{env.key?('HTTP_X_FORWARDED_FOR')}",
    "reserved=#{env.key?('HTTP_X_OXO_REMOTE_ADDR')}"
  ].join("\n")
  [200, { 'content-type' => 'text/plain' }, [body]]
end
run app
"#,
    );
    let _worker = WorkerProcess::spawn(&app, &fixture.socket, 2, 16, true);
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 16, "lint.example", "https");
    wait_for_tcp(port);

    let response = send_tcp(
        port,
        b"GET /env HTTP/1.1\r\nHost: client.example\r\nX-Forwarded-For: 198.51.100.1\r\nX-Oxo-Remote-Addr: spoofed\r\n\r\n",
    );

    assert_eq!(response.status, 200, "{}", response.text());
    let text = response.body_text();
    assert!(text.contains("method=GET"), "{text}");
    assert!(text.contains("scheme=http"), "{text}");
    assert!(
        text.contains(&format!("server=lint.example:{port}")),
        "{text}"
    );
    assert!(text.contains("multithread=true"), "{text}");
    assert!(text.contains("multiprocess=false"), "{text}");
    assert!(text.contains("xff=false"), "{text}");
    assert!(text.contains("reserved=false"), "{text}");
}
#[test]
fn raw_rack_request_response_runs_through_pingora_and_native_worker() {
    let _guard = serial_test();
    let fixture = Fixture::new("raw-rack");
    let calls = fixture.root.join("calls.txt");
    let app = fixture.app(
        "rack.ru",
        &format!(
            r#"
CALLS = {:?}
app = lambda do |env|
  case env['PATH_INFO']
  when '/env'
    n = (File.exist?(CALLS) ? File.read(CALLS).to_i : 0) + 1
    File.write(CALLS, n.to_s)
    body = env['rack.input'].read
    lines = []
    lines << "method=#{{env['REQUEST_METHOD']}}"
    lines << "path=#{{env['PATH_INFO']}}"
    lines << "query=#{{env['QUERY_STRING']}}"
    lines << "body=#{{body}}"
    lines << "remote=#{{env['REMOTE_ADDR']}}"
    lines << "scheme=#{{env['rack.url_scheme']}}"
    lines << "server=#{{env['SERVER_NAME']}}:#{{env['SERVER_PORT']}}"
    lines << "multithread=#{{env['rack.multithread']}}"
    lines << "multiprocess=#{{env['rack.multiprocess']}}"
    lines << "xff=#{{env.key?('HTTP_X_FORWARDED_FOR')}}"
    lines << "reserved=#{{env.key?('HTTP_X_OXO_REMOTE_ADDR')}}"
    [200, {{ 'content-type' => 'text/plain' }}, [lines.join("\n")]]
  when '/cookies'
    [200,
     {{
       'content-type' => 'text/plain',
       'content-length' => '999',
       'transfer-encoding' => 'chunked',
       'connection' => 'keep-alive',
       'set-cookie' => ['a=1; Path=/', 'b=2; Path=/']
     }},
     ['cookies']]
  when '/boom'
    raise 'boom'
  else
    [200, {{ 'content-type' => 'text/plain' }}, ['ok']]
  end
end
run app
"#,
            calls.to_string_lossy()
        ),
    );
    let worker = WorkerProcess::spawn(&app, &fixture.socket, 2, 16, false);
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 16, "app.example", "https");
    wait_for_tcp(port);

    let body = b"name=guest";
    let request = format!(
        "POST /env?via=v9 HTTP/1.1\r\n\
Host: client.example\r\n\
Content-Type: text/plain\r\n\
Content-Length: {}\r\n\
Forwarded: for=198.51.100.1\r\n\
X-Forwarded-For: 198.51.100.1\r\n\
X-Real-IP: 198.51.100.1\r\n\
X-Oxo-Remote-Addr: spoofed\r\n\
\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    );
    let response = send_tcp(port, request.as_bytes());
    assert_eq!(response.status, 200, "{}", response.text());
    let text = response.body_text();
    assert!(text.contains("method=POST"), "{text}");
    assert!(text.contains("path=/env"), "{text}");
    assert!(text.contains("query=via=v9"), "{text}");
    assert!(text.contains("body=name=guest"), "{text}");
    assert!(text.contains("remote=127.0.0.1"), "{text}");
    assert!(text.contains("scheme=http"), "{text}");
    assert!(
        text.contains(&format!("server=app.example:{port}")),
        "{text}"
    );
    assert!(text.contains("multithread=true"), "{text}");
    assert!(text.contains("multiprocess=false"), "{text}");
    assert!(text.contains("xff=false"), "{text}");
    assert!(text.contains("reserved=false"), "{text}");

    let over_cap = send_tcp(
        port,
        b"POST /env HTTP/1.1\r\nHost: client.example\r\nContent-Length: 17\r\n\r\n12345678901234567",
    );
    assert_eq!(over_cap.status, 413, "{}", over_cap.text());
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "1",
        "over-cap request must not call Rack"
    );

    let cookies = send_tcp(
        port,
        b"GET /cookies HTTP/1.1\r\nHost: client.example\r\n\r\n",
    );
    assert_eq!(cookies.status, 200, "{}", cookies.text());
    assert_eq!(
        cookies.header_values("set-cookie").len(),
        2,
        "{}",
        cookies.text()
    );
    assert!(cookies.body_text().contains("cookies"));
    assert_eq!(cookies.header_value("content-length"), Some("7"));
    assert_eq!(cookies.header_value("connection"), Some("close"));
    assert!(
        !cookies.has_header("transfer-encoding"),
        "{}",
        cookies.text()
    );

    let boom = send_tcp(port, b"GET /boom HTTP/1.1\r\nHost: client.example\r\n\r\n");
    assert_eq!(boom.status, 500, "{}", boom.text());
    let next = send_tcp(port, b"GET /ok HTTP/1.1\r\nHost: client.example\r\n\r\n");
    assert_eq!(next.status, 200, "{}", next.text());

    drop(worker);
}

#[test]
fn streaming_rack_body_flushes_incrementally_through_pingora_and_native_worker() {
    let _guard = serial_test();
    let fixture = Fixture::new("streaming-rack");
    let release = fixture.root.join("stream-release");
    let app = fixture.app(
        "streaming.ru",
        r#"
class StreamingBody
  def call(out)
    out.write "one\n"
    out.flush
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
    until File.exist?(ENV.fetch("OXO_TEST_STREAM_RELEASE"))
      raise "stream release timed out" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.01
    end
    out.write "two\n"
  end
end

app = lambda do |_env|
  [200, { 'content-type' => 'text/plain' }, StreamingBody.new]
end
run app
"#,
    );
    let _worker = WorkerProcess::spawn_with_env(
        &app,
        &fixture.socket,
        2,
        1024,
        false,
        &[
            ("OXO_WORKER_STREAMING", "1"),
            ("OXO_TEST_STREAM_RELEASE", release.to_str().unwrap()),
        ],
    );
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024, "app.example", "https");
    wait_for_tcp(port);

    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(b"GET /stream HTTP/1.1\r\nHost: app.example\r\n\r\n")
        .unwrap();
    stream.shutdown(Shutdown::Write).ok();

    let mut raw = read_tcp_until_contains(&mut stream, b"one\n");
    fs::write(&release, "release").unwrap();
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    raw.extend(rest);

    let response = HttpResponse::parse(raw);
    assert_eq!(response.status, 200, "{}", response.text());
    assert!(response.text().contains("one\n"), "{}", response.text());
    assert!(response.text().contains("two\n"), "{}", response.text());
    assert!(
        !response.has_header("content-length"),
        "streamed response must not be materialized as a fixed-length downstream body: {}",
        response.text()
    );
}

#[test]
fn rails_action_controller_live_sse_flushes_incrementally_through_pingora() {
    let _guard = serial_test();
    let fixture = Fixture::new("rails-live-sse");
    let release = fixture.root.join("stream-release");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let app = rails_root.join("config.ru");
    let gemfile = rails_root.join("Gemfile");
    let worker_env = [
        ("OXO_TEST_STREAM_RELEASE", release.to_str().unwrap()),
        ("RAILS_ENV", "development"),
        (
            "BUNDLE_GEMFILE",
            gemfile.to_str().expect("utf-8 Gemfile path"),
        ),
        ("OXO_RAILS_ALLOWED_HOSTS", "app.example"),
        ("OXO_WORKER_STREAMING", "1"),
    ];
    let _worker =
        WorkerProcess::spawn_with_env(&app, &fixture.socket, 2, 1024 * 1024, false, &worker_env);
    let port = free_port();
    let _edge = EdgeProcess::spawn_with_env(
        port,
        &fixture.socket,
        1024 * 1024,
        "app.example",
        "https",
        &[("OXO_EDGE_SSE", "1")],
    );
    wait_for_tcp(port);

    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    stream
        .write_all(
            b"GET /events HTTP/1.1\r\nHost: app.example\r\nAccept: text/event-stream\r\nLast-Event-ID: 41\r\n\r\n",
        )
        .unwrap();
    stream.shutdown(Shutdown::Write).ok();

    let mut raw = read_tcp_until_contains(&mut stream, b"data: one\n\n");
    fs::write(&release, "release").unwrap();
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    raw.extend(rest);

    let response = HttpResponse::parse(raw);
    assert_eq!(response.status, 200, "{}", response.text());
    assert!(
        response
            .header_value("content-type")
            .is_some_and(|value| value.starts_with("text/event-stream")),
        "{}",
        response.text()
    );
    assert!(
        !response.has_header("content-length"),
        "SSE must not be materialized as a fixed-length body: {}",
        response.text()
    );
    let body = response.body_text();
    assert!(body.contains("event: oxo\n"), "{body}");
    assert!(body.contains("id: 41\n"), "{body}");
    assert!(body.contains("data: one\n\n"), "{body}");
    assert!(body.contains("data: two\n\n"), "{body}");
}

#[test]
fn rails_request_response_runs_through_pingora_and_native_worker() {
    let _guard = serial_test();
    let fixture = Fixture::new("rails-seed");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let app = rails_root.join("config.ru");
    let gemfile = rails_root.join("Gemfile");
    let worker_env = [
        ("RAILS_ENV", "development"),
        (
            "BUNDLE_GEMFILE",
            gemfile.to_str().expect("utf-8 Gemfile path"),
        ),
        ("OXO_RAILS_ALLOWED_HOSTS", "app.example"),
    ];
    let _worker =
        WorkerProcess::spawn_with_env(&app, &fixture.socket, 2, 1024 * 1024, false, &worker_env);
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024 * 1024, "app.example", "https");
    wait_for_tcp(port);

    let hello = send_tcp(
        port,
        b"GET /hello?via=v9 HTTP/1.1\r\nHost: app.example\r\n\r\n",
    );
    assert_eq!(hello.status, 200, "{}", hello.text());
    assert!(hello.body_text().contains("Hello from Oxo + Rails"));
    assert!(hello.body_text().contains("\"query\":\"via=v9\""));

    let redirect = send_tcp(
        port,
        b"GET /redirect-me HTTP/1.1\r\nHost: app.example\r\n\r\n",
    );
    assert_eq!(redirect.status, 302, "{}", redirect.text());
    let location = redirect.header_value("location").unwrap_or_default();
    assert!(
        location.starts_with("http://app.example/hello"),
        "unexpected redirect location: {location}"
    );

    let first_cookie = send_tcp(
        port,
        b"GET /signed-cookie HTTP/1.1\r\nHost: app.example\r\n\r\n",
    );
    assert_eq!(first_cookie.status, 200, "{}", first_cookie.text());
    assert!(first_cookie.body_text().contains("\"seen\":1"));
    let mut cookies = cookie_header_from(&first_cookie);
    assert!(
        cookies.contains("oxo_seen="),
        "missing signed cookie: {cookies}"
    );

    let second_cookie = send_tcp(
        port,
        format!("GET /signed-cookie HTTP/1.1\r\nHost: app.example\r\nCookie: {cookies}\r\n\r\n")
            .as_bytes(),
    );
    assert_eq!(second_cookie.status, 200, "{}", second_cookie.text());
    assert!(second_cookie.body_text().contains("\"seen\":2"));
    merge_response_cookies(&mut cookies, &second_cookie);

    let csrf = send_tcp(
        port,
        format!("GET /csrf-token HTTP/1.1\r\nHost: app.example\r\nCookie: {cookies}\r\n\r\n")
            .as_bytes(),
    );
    assert_eq!(csrf.status, 200, "{}", csrf.text());
    merge_response_cookies(&mut cookies, &csrf);
    let token = json_string_field(&csrf.body_text(), "csrf");
    let csrf_body = b"payload=ok";
    let csrf_post = send_tcp(
        port,
        format!(
            "POST /csrf-echo HTTP/1.1\r\nHost: app.example\r\nCookie: {cookies}\r\nX-CSRF-Token: {token}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}",
            csrf_body.len(),
            String::from_utf8_lossy(csrf_body)
        )
        .as_bytes(),
    );
    assert_eq!(csrf_post.status, 200, "{}", csrf_post.text());
    assert!(csrf_post.body_text().contains("payload=ok"));
    let missing_token = send_tcp(
        port,
        b"POST /csrf-echo HTTP/1.1\r\nHost: app.example\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(
        missing_token.status,
        422,
        "missing CSRF token accepted: {}",
        missing_token.text()
    );

    let multipart_body = b"--oxo\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--oxo--\r\n";
    let upload = send_tcp(
        port,
        format!(
            "POST /upload HTTP/1.1\r\nHost: app.example\r\nCookie: {cookies}\r\nContent-Type: multipart/form-data; boundary=oxo\r\nContent-Length: {}\r\n\r\n{}",
            multipart_body.len(),
            String::from_utf8_lossy(multipart_body)
        )
        .as_bytes(),
    );
    assert_eq!(upload.status, 200, "{}", upload.text());
    assert!(upload.body_text().contains("\"filename\":\"a.txt\""));
    assert!(upload.body_text().contains("\"size\":5"));

    let boom = send_tcp(
        port,
        b"GET /rails-boom HTTP/1.1\r\nHost: app.example\r\n\r\n",
    );
    assert_eq!(boom.status, 500, "{}", boom.text());
    let after_boom = send_tcp(
        port,
        b"GET /hello?after=boom HTTP/1.1\r\nHost: app.example\r\n\r\n",
    );
    assert_eq!(after_boom.status, 200, "{}", after_boom.text());

    let bad_port = free_port();
    let _bad_edge = EdgeProcess::spawn(
        bad_port,
        &fixture.socket,
        1024 * 1024,
        "evil.example",
        "https",
    );
    wait_for_tcp(bad_port);
    let disallowed = send_tcp(
        bad_port,
        b"GET /hello HTTP/1.1\r\nHost: evil.example\r\n\r\n",
    );
    assert_eq!(disallowed.status, 403, "{}", disallowed.text());
}
#[test]
fn rails_db_and_redis_pressure_fixture_degrades_and_recovers() {
    let _guard = serial_test();
    let fixture = Fixture::new("rails-fixture-db-redis-pressure");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let app = rails_root.join("config.ru");
    let gemfile = rails_root.join("Gemfile");
    let redis_state = fixture.root.join("redis-state.txt");
    let redis_state_string = redis_state.to_string_lossy().into_owned();
    let pool_entered = fixture.root.join("pool-entered");
    let pool_release = fixture.root.join("pool-release");
    let worker_env = [
        ("OXO_TEST_POOL_ENTERED", pool_entered.to_str().unwrap()),
        ("OXO_TEST_POOL_RELEASE", pool_release.to_str().unwrap()),
        ("RAILS_ENV", "development"),
        (
            "BUNDLE_GEMFILE",
            gemfile.to_str().expect("utf-8 Gemfile path"),
        ),
        ("OXO_RAILS_ALLOWED_HOSTS", "app.example"),
        ("OXO_DB_POOL_SIZE", "1"),
        ("OXO_DB_POOL_TIMEOUT_MS", "100"),
        ("OXO_REDIS_POOL_SIZE", "1"),
        ("OXO_REDIS_POOL_TIMEOUT_MS", "100"),
        ("OXO_REDIS_FIXTURE_STATE", redis_state_string.as_str()),
    ];
    let _worker =
        WorkerProcess::spawn_with_env(&app, &fixture.socket, 2, 1024 * 1024, false, &worker_env);
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 1024 * 1024, "app.example", "https");
    wait_for_tcp(port);

    let status = send_tcp(
        port,
        b"GET /pressure/status HTTP/1.1\r\nHost: app.example\r\n\r\n",
    );
    assert_eq!(status.status, 200, "{}", status.text());
    let status_body = status.body_text();
    assert!(status_body.contains("\"db_pool_size\":1"), "{status_body}");
    assert!(
        status_body.contains("\"redis_pool_size\":1"),
        "{status_body}"
    );

    let first = thread::spawn(move || {
        send_tcp(
            port,
            b"GET /pressure/db?hold_ms=900 HTTP/1.1\r\nHost: app.example\r\n\r\n",
        )
    });
    ruby_fixture::wait_for_file(&pool_entered);
    let saturated = send_tcp(
        port,
        b"GET /pressure/db?hold_ms=0 HTTP/1.1\r\nHost: app.example\r\n\r\n",
    );
    fs::write(&pool_release, "release").unwrap();
    let first = first.join().expect("first db pressure request joins");
    assert_eq!(first.status, 200, "{}", first.text());
    let first_body = first.body_text();
    assert!(first_body.contains("\"kind\":\"db\""), "{first_body}");
    assert!(first_body.contains("\"degraded\":false"), "{first_body}");
    assert_eq!(saturated.status, 503, "{}", saturated.text());
    let saturated_body = saturated.body_text();
    assert!(
        saturated_body.contains("\"reason\":\"db_pool_exhausted\""),
        "{saturated_body}"
    );

    let recovered_db = send_tcp(
        port,
        b"GET /pressure/db?hold_ms=0 HTTP/1.1\r\nHost: app.example\r\n\r\n",
    );
    assert_eq!(recovered_db.status, 200, "{}", recovered_db.text());

    fs::write(&redis_state, "down").expect("write redis fixture outage state");
    let redis_down = send_tcp(
        port,
        b"GET /pressure/redis?hold_ms=0 HTTP/1.1\r\nHost: app.example\r\n\r\n",
    );
    assert_eq!(redis_down.status, 503, "{}", redis_down.text());
    let redis_down_body = redis_down.body_text();
    assert!(
        redis_down_body.contains("\"reason\":\"redis_unavailable\""),
        "{redis_down_body}"
    );

    fs::write(&redis_state, "up").expect("write redis fixture recovery state");
    let redis_up = send_tcp(
        port,
        b"GET /pressure/redis?hold_ms=0 HTTP/1.1\r\nHost: app.example\r\n\r\n",
    );
    assert_eq!(redis_up.status, 200, "{}", redis_up.text());
    let redis_up_body = redis_up.body_text();
    assert!(
        redis_up_body.contains("\"degraded\":false"),
        "{redis_up_body}"
    );
}
#[cfg(feature = "tls-rustls")]
#[test]
fn rails_fixture_runs_through_public_smoke_beta_tls_h1_and_h2() {
    let _guard = serial_test();
    let fixture = Fixture::new("rails-public-smoke-beta");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let app = rails_root.join("config.ru");
    let gemfile = rails_root.join("Gemfile");
    let worker_env = [
        ("RAILS_ENV", "development"),
        (
            "BUNDLE_GEMFILE",
            gemfile.to_str().expect("utf-8 Gemfile path"),
        ),
        ("OXO_RAILS_ALLOWED_HOSTS", "app.example"),
    ];
    let _worker =
        WorkerProcess::spawn_with_env(&app, &fixture.socket, 2, 1024 * 1024, false, &worker_env);
    let (cert, key) = generate_tls_cert(&fixture.root);
    let port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta(
        port,
        admin_port,
        &fixture.socket,
        1024 * 1024,
        "app.example",
        &cert,
        &key,
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    for (http2, query) in [(false, "fixture-h1"), (true, "fixture-h2")] {
        let response = curl_https(port, http2, &format!("/hello?via={query}"));
        assert!(
            response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/2 200"),
            "{response}"
        );
        assert!(response.contains("Hello from Oxo + Rails"), "{response}");
        assert!(
            response.contains(&format!("\"query\":\"via={query}\"")),
            "{response}"
        );
    }

    let ready = send_tcp(
        admin_port,
        b"GET /ready HTTP/1.1\r\nHost: admin.local\r\n\r\n",
    )
    .text();
    assert!(ready.starts_with("HTTP/1.1 200 OK"), "{ready}");
    assert!(ready.contains("\"ready\":true"), "{ready}");
    assert!(ready.contains("\"worker_count\":1"), "{ready}");
    assert!(ready.contains("\"public_mode\":\"smoke-beta\""), "{ready}");
    assert!(ready.contains("\"requests_total\":2"), "{ready}");
    assert!(ready.contains("\"responses_total\":2"), "{ready}");
}

#[cfg(feature = "tls-rustls")]
#[test]
fn rails_action_controller_live_sse_flushes_incrementally_through_public_smoke_beta_tls_h1() {
    let _guard = serial_test();
    let fixture = Fixture::new("rails-public-sse");
    let release = fixture.root.join("stream-release");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let app = rails_root.join("config.ru");
    let gemfile = rails_root.join("Gemfile");
    let secret_key_base = ruby_fixture::test_secret();
    let worker_env = [
        ("OXO_TEST_STREAM_RELEASE", release.to_str().unwrap()),
        ("RAILS_ENV", "production"),
        (
            "BUNDLE_GEMFILE",
            gemfile.to_str().expect("utf-8 Gemfile path"),
        ),
        ("OXO_RAILS_ALLOWED_HOSTS", "app.example"),
        ("OXO_WORKER_STREAMING", "1"),
        ("SECRET_KEY_BASE", secret_key_base),
    ];
    let _worker =
        WorkerProcess::spawn_with_env(&app, &fixture.socket, 2, 1024 * 1024, false, &worker_env);
    let (cert, key) = generate_tls_cert(&fixture.root);
    let port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        port,
        admin_port,
        &fixture.socket,
        1024 * 1024,
        "app.example",
        TlsIdentity {
            cert: &cert,
            key: &key,
        },
        &[
            ("OXO_EDGE_SSE", "1"),
            ("OXO_EDGE_PUBLIC_ORIGIN_PORT", "443"),
        ],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    let (raw, _elapsed) = tls_h1_read_until_then_kill(
        port,
        "app.example",
        b"GET /events HTTP/1.1\r\nHost: app.example\r\nAccept: text/event-stream\r\nLast-Event-ID: 43\r\nConnection: close\r\n\r\n",
        b"data: one\n\n",
    );

    let response = String::from_utf8_lossy(&raw);
    assert!(response.contains("HTTP/1.1 200"), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("content-type: text/event-stream"),
        "{response}"
    );
    assert!(response.contains("event: oxo\n"), "{response}");
    assert!(response.contains("id: 43\n"), "{response}");
    assert!(response.contains("data: one\n\n"), "{response}");
    assert!(
        !response.contains("data: two\n\n"),
        "first read should complete before the delayed second event: {response}"
    );
    fs::write(&release, "release").unwrap();
}

#[cfg(feature = "tls-rustls")]
#[test]
fn rails_public_correctness_one_fqdn_tls_sni_host_and_security_metadata() {
    let _guard = serial_test();
    let fixture = Fixture::new("rails-fixture-public-correctness");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let app = rails_root.join("config.ru");
    let gemfile = rails_root.join("Gemfile");
    let secret_key_base = ruby_fixture::test_secret();
    let worker_env = [
        ("RAILS_ENV", "production"),
        (
            "BUNDLE_GEMFILE",
            gemfile.to_str().expect("utf-8 Gemfile path"),
        ),
        ("OXO_RAILS_ALLOWED_HOSTS", "app.example"),
        ("SECRET_KEY_BASE", secret_key_base),
    ];
    let _worker =
        WorkerProcess::spawn_with_env(&app, &fixture.socket, 2, 1024 * 1024, false, &worker_env);
    let (cert, key) = generate_tls_cert(&fixture.root);
    let port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        port,
        admin_port,
        &fixture.socket,
        1024 * 1024,
        "app.example",
        TlsIdentity {
            cert: &cert,
            key: &key,
        },
        &[("OXO_EDGE_PUBLIC_ORIGIN_PORT", "443")],
    );
    wait_for_tcp(port);
    wait_for_tcp(admin_port);

    for (http2, query, expected_status) in [
        (false, "fixture-h1", "HTTP/1.1 200"),
        (true, "fixture-h2", "HTTP/2 200"),
    ] {
        let response = curl_https_origin_verified(
            port,
            http2,
            &format!("/hello?via={query}"),
            &cert,
            &[],
            true,
        );
        assert!(response.starts_with(expected_status), "{response}");
        assert!(response.contains("Hello from Oxo + Rails"), "{response}");
        assert!(response.contains("\"scheme\":\"https\""), "{response}");
        assert!(response.contains("\"ssl\":true"), "{response}");
        assert!(response.contains("\"host\":\"app.example\""), "{response}");
        assert!(
            response.contains("\"host_with_port\":\"app.example\""),
            "{response}"
        );
        assert!(
            response.contains("\"server\":\"app.example:443\""),
            "{response}"
        );
        assert!(
            response.contains("\"base_url\":\"https://app.example\""),
            "{response}"
        );
    }

    let redirect = curl_https_origin_verified(port, false, "/redirect-me", &cert, &[], true);
    assert!(redirect.starts_with("HTTP/1.1 302"), "{redirect}");
    assert!(
        redirect
            .to_ascii_lowercase()
            .contains("location: https://app.example/hello?from=redirect"),
        "{redirect}"
    );

    let signed = curl_https_origin_verified(port, false, "/signed-cookie", &cert, &[], true);
    assert!(signed.contains("\"seen\":1"), "{signed}");
    assert_secure_set_cookie(&signed, "oxo_seen");
    let mut cookies = curl_cookie_header_from(&signed);

    let session_first =
        curl_https_origin_verified(port, false, "/session-cookie", &cert, &[], true);
    assert!(
        session_first.contains("\"session_seen\":1"),
        "{session_first}"
    );
    assert_secure_set_cookie(&session_first, "_oxo_session");
    merge_curl_response_cookies(&mut cookies, &session_first);

    let session_second = curl_https_origin_verified(
        port,
        false,
        "/session-cookie",
        &cert,
        &["--header".to_string(), format!("Cookie: {cookies}")],
        true,
    );
    assert!(
        session_second.contains("\"session_seen\":2"),
        "{session_second}"
    );
    merge_curl_response_cookies(&mut cookies, &session_second);

    let csrf = curl_https_origin_verified(
        port,
        false,
        "/csrf-token",
        &cert,
        &["--header".to_string(), format!("Cookie: {cookies}")],
        true,
    );
    let token = json_string_field(&csrf, "csrf");
    merge_curl_response_cookies(&mut cookies, &csrf);

    let csrf_post = curl_https_origin_verified(
        port,
        false,
        "/csrf-echo",
        &cert,
        &[
            "--request".to_string(),
            "POST".to_string(),
            "--header".to_string(),
            format!("Cookie: {cookies}"),
            "--header".to_string(),
            format!("X-CSRF-Token: {token}"),
            "--header".to_string(),
            "Content-Type: application/x-www-form-urlencoded".to_string(),
            "--data".to_string(),
            "payload=ok".to_string(),
        ],
        true,
    );
    assert!(
        csrf_post.contains("\"echoed\":\"payload=ok\""),
        "{csrf_post}"
    );
}
#[cfg(feature = "tls-rustls")]
#[test]
fn rails_trusted_proxy_remote_ip_uses_edge_identity_without_forwarding_headers() {
    let _guard = serial_test();
    let fixture = Fixture::new("rails-fixture-trusted-proxy-remote-ip");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let app = rails_root.join("config.ru");
    let gemfile = rails_root.join("Gemfile");
    let secret_key_base = ruby_fixture::test_secret();
    let worker_env = [
        ("RAILS_ENV", "production"),
        (
            "BUNDLE_GEMFILE",
            gemfile.to_str().expect("utf-8 Gemfile path"),
        ),
        ("OXO_RAILS_ALLOWED_HOSTS", "app.example"),
        ("SECRET_KEY_BASE", secret_key_base),
    ];
    let _worker =
        WorkerProcess::spawn_with_env(&app, &fixture.socket, 2, 1024 * 1024, false, &worker_env);
    let (cert, key) = generate_tls_cert(&fixture.root);
    let port = free_port();
    let admin_port = free_port();
    let _edge = EdgeProcess::spawn_public_smoke_beta_with_env(
        port,
        admin_port,
        &fixture.socket,
        1024 * 1024,
        "app.example",
        TlsIdentity {
            cert: &cert,
            key: &key,
        },
        &[
            ("OXO_EDGE_PUBLIC_ORIGIN_PORT", "443"),
            ("OXO_EDGE_PUBLIC_IDENTITY", "trusted-proxy"),
            ("OXO_EDGE_TRUSTED_PROXY_CIDRS", "127.0.0.1/32"),
        ],
    );
    wait_for_tcp(port);

    let response = curl_https_origin_verified(
        port,
        false,
        "/remote-ip",
        &cert,
        &[
            "--header".to_string(),
            "X-Forwarded-For: 198.51.100.77, 127.0.0.1".to_string(),
        ],
        true,
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.contains("\"remote_addr\":\"198.51.100.77\""),
        "{response}"
    );
    assert!(
        response.contains("\"remote_ip\":\"198.51.100.77\""),
        "{response}"
    );
    assert!(response.contains("\"x_forwarded_for\":false"), "{response}");
    assert!(response.contains("\"forwarded\":false"), "{response}");
}

#[cfg(feature = "tls-rustls")]
#[test]
fn rails_direct_public_client_ip_cannot_spoof_remote_ip() {
    let _guard = serial_test();
    let fixture = Fixture::new("rails-fixture-direct-public-client-ip-spoof");
    let rails_root = workspace_root().join("test/fixtures/rails_app");
    let app = rails_root.join("config.ru");
    let gemfile = rails_root.join("Gemfile");
    let secret_key_base = ruby_fixture::test_secret();
    let worker_env = [
        ("RAILS_ENV", "production"),
        (
            "BUNDLE_GEMFILE",
            gemfile.to_str().expect("utf-8 Gemfile path"),
        ),
        ("OXO_RAILS_ALLOWED_HOSTS", "app.example"),
        ("SECRET_KEY_BASE", secret_key_base),
    ];
    let _worker =
        WorkerProcess::spawn_with_env(&app, &fixture.socket, 2, 1024 * 1024, false, &worker_env);
    let (cert, key) = generate_tls_cert(&fixture.root);
    let port = free_port();
    let admin_port = free_port();
    // Direct-public mode (no trusted-proxy env): the edge sets REMOTE_ADDR from the peer.
    let _edge = EdgeProcess::spawn_public_smoke_beta(
        port,
        admin_port,
        &fixture.socket,
        1024 * 1024,
        "app.example",
        &cert,
        &key,
    );
    wait_for_tcp(port);

    let response = curl_https_origin_verified(
        port,
        false,
        "/remote-ip",
        &cert,
        &[
            "--header".to_string(),
            "Client-IP: 6.6.6.6".to_string(),
            "--header".to_string(),
            "CF-Connecting-IP: 6.6.6.6".to_string(),
            "--header".to_string(),
            "True-Client-IP: 6.6.6.6".to_string(),
        ],
        true,
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    // request.remote_ip is the loopback peer, NOT the spoofed Client-IP.
    assert!(
        !response.contains("6.6.6.6"),
        "Client-IP spoofed remote_ip: {response}"
    );
    assert!(
        response.contains("\"remote_ip\":\"127.0.0.1\""),
        "{response}"
    );
}

#[test]
fn edge_rejects_hostile_requests_before_real_worker_dependency() {
    let _guard = serial_test();
    let fixture = Fixture::new("reject-before-worker");
    let port = free_port();
    let _edge = EdgeProcess::spawn(port, &fixture.socket, 4, "app.example", "https");
    wait_for_tcp(port);

    let missing = send_tcp(port, b"GET /missing HTTP/1.1\r\nHost: app.example\r\n\r\n");
    assert_eq!(missing.status, 503, "{}", missing.text());

    for (label, request, expected_status) in [
        (
            "over-cap",
            b"POST /too-big HTTP/1.1\r\nHost: app.example\r\nContent-Length: 5\r\n\r\n12345".as_slice(),
            413,
        ),
        (
            "duplicate-content-length",
            b"POST /dup HTTP/1.1\r\nHost: app.example\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx".as_slice(),
            400,
        ),
        (
            "transfer-encoding",
            b"POST /chunked HTTP/1.1\r\nHost: app.example\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n".as_slice(),
            400,
        ),
        (
            "absolute-form",
            b"GET http://app.example/absolute HTTP/1.1\r\nHost: app.example\r\n\r\n".as_slice(),
            400,
        ),
        (
            "upgrade",
            b"GET /cable HTTP/1.1\r\nHost: app.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            400,
        ),
        (
            "grpc",
            b"POST /svc HTTP/1.1\r\nHost: app.example\r\nContent-Type: application/grpc\r\n\r\n".as_slice(),
            415,
        ),
        (
            "sse",
            b"GET /events HTTP/1.1\r\nHost: app.example\r\nAccept: text/event-stream\r\n\r\n".as_slice(),
            400,
        ),
    ] {
        let response = send_tcp(port, request);
        assert_eq!(
            response.status,
            expected_status,
            "{label} should reject before missing worker can become 503: {}",
            response.text()
        );
    }
}

struct Fixture {
    root: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Keep the socket path below Linux's 108-byte limit, including the NUL,
        // even with long fixture labels and PIDs. PID and SEQ distinguish live
        // fixtures; the truncated nonce reduces collisions across process reruns.
        let root = std::env::temp_dir().join(format!(
            "oxo-it-{label}-{}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
            nonce % 1_000_000_000
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("worker.sock");
        assert!(
            socket.as_os_str().len() < 100,
            "fixture socket path {} chars — would breach SUN_LEN at bind; shorten the label",
            socket.as_os_str().len()
        );
        Self { root, socket }
    }

    fn app(&self, name: &str, code: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, code).unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct WorkerProcess {
    _process: process_fixture::CapturedChild,
}

impl WorkerProcess {
    fn spawn(app: &Path, socket: &Path, threads: usize, max_body: usize, rack_lint: bool) -> Self {
        Self::spawn_with_env(app, socket, threads, max_body, rack_lint, &[])
    }

    fn spawn_with_env(
        app: &Path,
        socket: &Path,
        threads: usize,
        max_body: usize,
        rack_lint: bool,
        extra_env: &[(&str, &str)],
    ) -> Self {
        let mut cmd = ruby_fixture::command(worker_binary());
        cmd.env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("OXO_WORKER_APP", app)
            .env("OXO_WORKER_SOCKET", socket)
            .env("OXO_WORKER_THREADS", threads.to_string())
            .env("OXO_WORKER_MAX_BODY", max_body.to_string())
            .env("OXO_WORKER_RACK_LINT", if rack_lint { "1" } else { "0" })
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in extra_env {
            cmd.env(name, value);
        }
        if let Some(libdir) = ruby_libdir() {
            cmd.env("LD_LIBRARY_PATH", libdir);
        }

        let mut process =
            process_fixture::CapturedChild::new(cmd.spawn().expect("spawn oxo-worker"));
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if process.stdout().starts_with(b"OXO_WORKER_READY=") {
                break;
            }
            assert!(
                process.poll().is_none() && Instant::now() < deadline,
                "worker readiness failed: {}",
                ruby_fixture::diagnostic(&process.stderr())
            );
            thread::sleep(Duration::from_millis(10));
        }
        Self { _process: process }
    }
}

#[cfg(feature = "tls-rustls")]
struct TlsIdentity<'a> {
    cert: &'a Path,
    key: &'a Path,
}

struct EdgeProcess {
    _process: process_fixture::CapturedChild,
}

impl EdgeProcess {
    fn spawn(port: u16, socket: &Path, max_body: u64, server_name: &str, _scheme: &str) -> Self {
        Self::spawn_with_env(port, socket, max_body, server_name, _scheme, &[])
    }

    fn spawn_with_env(
        port: u16,
        socket: &Path,
        max_body: u64,
        server_name: &str,
        _scheme: &str,
        extra_env: &[(&str, &str)],
    ) -> Self {
        let mut cmd = ruby_fixture::command(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
        cmd.env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("OXO_EDGE_BIND", format!("127.0.0.1:{port}"))
            .env("OXO_EDGE_WORKER_SOCKET", socket)
            .env("OXO_EDGE_MAX_BODY", max_body.to_string())
            .env("OXO_EDGE_SERVER_NAME", server_name)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in extra_env {
            cmd.env(name, value);
        }
        let child = cmd.spawn().expect("spawn oxo-pingora-edge");
        Self::from_child(child)
    }

    #[cfg(feature = "tls-rustls")]
    fn spawn_public_smoke_beta(
        port: u16,
        admin_port: u16,
        socket: &Path,
        max_body: u64,
        server_name: &str,
        cert: &Path,
        key: &Path,
    ) -> Self {
        Self::spawn_public_smoke_beta_with_env(
            port,
            admin_port,
            socket,
            max_body,
            server_name,
            TlsIdentity { cert, key },
            &[],
        )
    }

    #[cfg(feature = "tls-rustls")]
    fn spawn_public_smoke_beta_with_env(
        port: u16,
        admin_port: u16,
        socket: &Path,
        max_body: u64,
        server_name: &str,
        tls: TlsIdentity<'_>,
        extra_env: &[(&str, &str)],
    ) -> Self {
        let TlsIdentity { cert, key } = tls;
        let mut cmd = ruby_fixture::command(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
        cmd.env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("OXO_EDGE_BIND", format!("0.0.0.0:{port}"))
            .env("OXO_EDGE_WORKER_SOCKET", socket)
            .env("OXO_EDGE_MAX_BODY", max_body.to_string())
            .env("OXO_EDGE_SERVER_NAME", server_name)
            .env("OXO_EDGE_TLS", "1")
            .env("OXO_EDGE_TLS_CERT", cert)
            .env("OXO_EDGE_TLS_KEY", key)
            .env("OXO_EDGE_TLS_H2", "1")
            .env("OXO_EDGE_PUBLIC_MODE", "smoke-beta")
            .env("OXO_EDGE_PUBLIC_IDENTITY", "direct-public")
            .env("OXO_EDGE_MAX_IN_FLIGHT_REQUESTS", "128")
            .env("OXO_EDGE_ADMIN_BIND", format!("127.0.0.1:{admin_port}"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in extra_env {
            cmd.env(name, value);
        }
        let child = cmd
            .spawn()
            .expect("spawn public smoke-beta oxo-pingora-edge");
        Self::from_child(child)
    }

    fn from_child(child: Child) -> Self {
        Self {
            _process: process_fixture::CapturedChild::new(child),
        }
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

fn wait_for_tcp(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("edge did not bind to 127.0.0.1:{port}");
        }
        thread::sleep(Duration::from_millis(25));
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
            Err(err) => panic!(
                "read edge response before needle: {}",
                ruby_fixture::diagnostic(err.to_string().as_bytes())
            ),
        }
    }
}
fn send_tcp(port: u16, request: &[u8]) -> HttpResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request).unwrap();
    stream.shutdown(Shutdown::Write).ok();
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(err) => panic!(
                "read edge response: {}",
                ruby_fixture::diagnostic(err.to_string().as_bytes())
            ),
        }
    }
    HttpResponse::parse(response)
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    raw: Vec<u8>,
}

impl HttpResponse {
    fn parse(raw: Vec<u8>) -> Self {
        let header_end = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("HTTP response header terminator");
        let head = String::from_utf8_lossy(&raw[..header_end]);
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|status| status.parse().ok())
            .unwrap_or(0);
        let mut headers = Vec::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        let body = raw[header_end + 4..].to_vec();
        Self {
            status,
            headers,
            body,
            raw,
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.raw).into_owned()
    }

    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn header_values(&self, name: &str) -> Vec<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter_map(|(header, value)| (header == &name).then_some(value.as_str()))
            .collect()
    }

    fn header_value(&self, name: &str) -> Option<&str> {
        self.header_values(name).into_iter().next()
    }

    fn has_header(&self, name: &str) -> bool {
        !self.header_values(name).is_empty()
    }
}

#[cfg(feature = "tls-rustls")]
fn generate_tls_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
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

#[cfg(feature = "tls-rustls")]
fn curl_https_origin_verified(
    port: u16,
    http2: bool,
    path: &str,
    ca_cert: &Path,
    extra_args: &[String],
    fail_on_http_error: bool,
) -> String {
    let url = format!("https://app.example{path}");
    let connect_to = format!("app.example:443:127.0.0.1:{port}");
    let mut cmd = ruby_fixture::command("curl");
    if fail_on_http_error {
        cmd.arg("--fail");
    }
    cmd.arg("--silent")
        .arg("--show-error")
        .arg("--noproxy")
        .arg("*")
        .arg("--max-time")
        .arg("10")
        .arg("--dump-header")
        .arg("-")
        .arg("--connect-to")
        .arg(connect_to)
        .arg("--cacert")
        .arg(ca_cert);
    if http2 {
        cmd.arg("--http2");
    } else {
        cmd.arg("--http1.1");
    }
    for arg in extra_args {
        cmd.arg(arg);
    }
    let output = cmd.arg(url).output().expect("run verified curl");
    if fail_on_http_error {
        assert!(
            output.status.success(),
            "curl failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            ruby_fixture::diagnostic(&output.stdout),
            ruby_fixture::diagnostic(&output.stderr)
        );
    }
    ruby_fixture::diagnostic(&output.stdout)
}

#[cfg(feature = "tls-rustls")]
fn tls_h1_read_until_then_kill(
    port: u16,
    host: &str,
    request: &[u8],
    needle: &[u8],
) -> (Vec<u8>, Duration) {
    let mut child = ruby_fixture::command("openssl")
        .arg("s_client")
        .arg("-quiet")
        .arg("-servername")
        .arg(host)
        .arg("-connect")
        .arg(format!("127.0.0.1:{port}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn openssl s_client");
    let mut stdin = child.stdin.take().expect("openssl stdin");
    let mut stdout = child.stdout.take().expect("openssl stdout");
    thread::scope(|scope| {
        let _process = process_fixture::CapturedChild::new(child);
        let needle = needle.to_vec();
        let (tx, rx) = mpsc::channel();
        scope.spawn(move || {
            let mut out = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                match stdout.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        out.extend_from_slice(&buf[..n]);
                        if out.windows(needle.len()).any(|window| window == needle) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(out);
        });

        stdin.write_all(request).expect("write openssl request");
        stdin.flush().expect("flush openssl request");
        let started = Instant::now();
        let output = rx.recv_timeout(Duration::from_secs(6)).unwrap_or_default();
        let elapsed = started.elapsed();
        drop(stdin);
        (output, elapsed)
    })
}

#[cfg(feature = "tls-rustls")]
fn curl_https(port: u16, http2: bool, path: &str) -> String {
    let url = format!("https://app.example:{port}{path}");
    let resolve = format!("app.example:{port}:127.0.0.1");
    let mut cmd = ruby_fixture::command("curl");
    cmd.arg("--fail")
        .arg("--silent")
        .arg("--show-error")
        .arg("--insecure")
        .arg("--noproxy")
        .arg("*")
        .arg("--max-time")
        .arg("10")
        .arg("--dump-header")
        .arg("-")
        .arg("--resolve")
        .arg(resolve);
    if http2 {
        cmd.arg("--http2");
    } else {
        cmd.arg("--http1.1");
    }
    let output = cmd.arg(url).output().expect("run curl");
    assert!(
        output.status.success(),
        "curl failed: {}",
        ruby_fixture::diagnostic(&output.stderr)
    );
    ruby_fixture::diagnostic(&output.stdout)
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn cookie_header_from(response: &HttpResponse) -> String {
    response
        .header_values("set-cookie")
        .into_iter()
        .filter_map(|value| value.split(';').next())
        .collect::<Vec<_>>()
        .join("; ")
}

fn merge_response_cookies(cookies: &mut String, response: &HttpResponse) {
    let next = cookie_header_from(response);
    if next.is_empty() {
        return;
    }
    if cookies.is_empty() {
        *cookies = next;
    } else {
        cookies.push_str("; ");
        cookies.push_str(&next);
    }
}

#[cfg(feature = "tls-rustls")]
fn curl_cookie_header_from(response: &str) -> String {
    response
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("set-cookie").then(|| {
                value
                    .trim()
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .to_string()
            })
        })
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(feature = "tls-rustls")]
fn merge_curl_response_cookies(cookies: &mut String, response: &str) {
    let next = curl_cookie_header_from(response);
    if next.is_empty() {
        return;
    }
    let mut jar = cookies
        .split("; ")
        .filter(|cookie| !cookie.is_empty())
        .map(|cookie| {
            let name = cookie
                .split_once('=')
                .map(|(name, _)| name)
                .unwrap_or(cookie);
            (name.to_string(), cookie.to_string())
        })
        .collect::<Vec<_>>();
    for cookie in next.split("; ").filter(|cookie| !cookie.is_empty()) {
        let name = cookie
            .split_once('=')
            .map(|(name, _)| name)
            .unwrap_or(cookie);
        if let Some((_, value)) = jar.iter_mut().find(|(existing, _)| existing == name) {
            *value = cookie.to_string();
        } else {
            jar.push((name.to_string(), cookie.to_string()));
        }
    }
    *cookies = jar
        .into_iter()
        .map(|(_, cookie)| cookie)
        .collect::<Vec<_>>()
        .join("; ");
}

#[cfg(feature = "tls-rustls")]
fn assert_secure_set_cookie(response: &str, cookie_name: &str) {
    let expected_prefix = format!("{cookie_name}=");
    let Some(line) = response.lines().find(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case("set-cookie") && value.trim().starts_with(&expected_prefix)
    }) else {
        panic!("missing Set-Cookie for {cookie_name}: {response}");
    };
    let lower = line.to_ascii_lowercase();
    assert!(lower.contains("; secure"), "{line}");
    assert!(lower.contains("; httponly"), "{line}");
}
fn json_string_field(body: &str, field: &str) -> String {
    let needle = format!("\"{field}\":\"");
    let start = body.find(&needle).expect("json field") + needle.len();
    let rest = &body[start..];
    let end = rest.find('"').expect("json string end");
    rest[..end].replace("\\/", "/")
}

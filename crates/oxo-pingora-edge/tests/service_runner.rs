#![cfg(target_os = "linux")]

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

mod support;
use support::free_port;

static SEQ: AtomicU64 = AtomicU64::new(0);

#[test]
fn service_runner_kills_ready_worker_when_edge_exits_during_boot() {
    let fixture = Fixture::new("edge-boot-failure");
    let app = fixture.app(
        "ok.ru",
        r#"
app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );

    let run = run_service_for_failure(&app, &fixture.socket);
    let stderr = String::from_utf8_lossy(&run.output.stderr);

    assert!(!run.timed_out, "runner hung after edge failure: {stderr}");
    assert!(
        !run.output.status.success(),
        "runner unexpectedly succeeded after edge failure"
    );
    assert!(stderr.contains("edge exited"), "{stderr}");
    assert_worker_socket_is_not_live(&fixture.socket);
}

#[test]
fn service_runner_starts_edge_with_ready_worker_socket_and_cleans_up_after_edge_exit() {
    let fixture = Fixture::new("fake-edge");
    let app = fixture.app(
        "ok.ru",
        r#"
app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );
    let record = fixture.root.join("edge-socket.txt");
    let fake_edge = fixture.root.join("fake-edge.sh");
    fs::write(
        &fake_edge,
        format!(
            "#!/bin/sh\nsocket=''\nprev=''\nfor arg in \"$@\"; do\n  if [ \"$prev\" = '--worker-socket' ]; then socket=\"$arg\"; fi\n  prev=\"$arg\"\ndone\nprintf '%s\\n' \"$socket\" > '{}'\nexit 42\n",
            record.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_edge, fs::Permissions::from_mode(0o700)).unwrap();

    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{}", free_port()));
    cmd.env("OXO_EDGE_BIN", &fake_edge);
    let run = run_with_timeout(cmd, Duration::from_secs(10));
    let stderr = String::from_utf8_lossy(&run.output.stderr);

    assert!(!run.timed_out, "runner hung after fake edge exit: {stderr}");
    assert!(
        !run.output.status.success(),
        "runner should report edge exit"
    );
    assert!(stderr.contains("edge exited"), "{stderr}");
    assert_eq!(
        fs::read_to_string(&record).unwrap().trim(),
        fixture.socket.to_string_lossy()
    );
    assert_worker_socket_is_not_live(&fixture.socket);
}

#[test]
fn service_runner_clears_edge_env_and_keeps_only_edge_contract() {
    let fixture = Fixture::new("edge-env");
    let app = fixture.app(
        "ok.ru",
        r#"
app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );
    let env_record = fixture.root.join("edge-env.txt");
    let args_record = fixture.root.join("edge-args.txt");
    let fake_edge = fixture.root.join("fake-edge-env.sh");
    fs::write(
        &fake_edge,
        format!(
            "#!/bin/sh\nenv | sort > '{}'\nprintf '%s\\n' \"$@\" > '{}'\nexit 42\n",
            env_record.display(),
            args_record.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_edge, fs::Permissions::from_mode(0o700)).unwrap();

    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{}", free_port()));
    cmd.env("OXO_EDGE_BIN", &fake_edge)
        .env("EDGE_ENV_RECORD", &env_record)
        .env("SECRET_KEY_BASE", "edge-must-not-see-this")
        .env("DATABASE_URL", "postgres://edge-must-not-see-this")
        .env("NOTIFY_SOCKET", fixture.root.join("notify.sock"));
    let run = run_with_timeout(cmd, Duration::from_secs(10));
    let stderr = String::from_utf8_lossy(&run.output.stderr);

    assert!(
        !run.timed_out,
        "runner hung after fake edge env exit: {stderr}"
    );
    assert!(
        !run.output.status.success(),
        "runner should report edge exit"
    );
    let env_dump = fs::read_to_string(&env_record).unwrap();
    let args_dump = fs::read_to_string(&args_record).unwrap();
    assert!(args_dump.contains("--http-bind"), "{args_dump}");
    assert!(args_dump.contains("--worker-socket"), "{args_dump}");
    assert!(
        args_dump.contains(&fixture.socket.to_string_lossy().to_string()),
        "{args_dump}"
    );
    assert!(!env_dump.contains("OXO_EDGE_BIND="), "{env_dump}");
    assert!(!env_dump.contains("OXO_EDGE_WORKER_SOCKETS="), "{env_dump}");
    assert!(!env_dump.contains("OXO_EDGE_WORKER_SOCKET="), "{env_dump}");
    assert!(!env_dump.contains("SECRET_KEY_BASE="), "{env_dump}");
    assert!(!env_dump.contains("DATABASE_URL="), "{env_dump}");
    assert!(!env_dump.contains("OXO_WORKER_APP="), "{env_dump}");
    assert!(!env_dump.contains("OXO_WORKER_BIN="), "{env_dump}");
    assert!(!env_dump.contains("NOTIFY_SOCKET="), "{env_dump}");
}

#[test]
fn service_runner_rejects_wrong_worker_ready_socket() {
    let fixture = Fixture::new("wrong-ready");
    let app = fixture.app(
        "ok.ru",
        r#"
app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );
    let fake_worker = fixture.root.join("fake-worker.sh");
    let wrong_socket = fixture.root.join("wrong.sock");
    fs::write(
        &fake_worker,
        format!(
            "#!/bin/sh\nprintf 'boot chatter before readiness\\n'\nprintf 'OXO_WORKER_READY={}\\n'\nsleep 30\n",
            wrong_socket.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_worker, fs::Permissions::from_mode(0o700)).unwrap();

    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{}", free_port()));
    cmd.env("OXO_WORKER_BIN", &fake_worker);
    let run = run_with_timeout(cmd, Duration::from_secs(10));
    let stderr = String::from_utf8_lossy(&run.output.stderr);

    assert!(
        !run.timed_out,
        "runner hung after wrong readiness: {stderr}"
    );
    assert!(
        !run.output.status.success(),
        "runner should reject wrong readiness socket"
    );
    assert!(stderr.contains("reported socket"), "{stderr}");
}

#[test]
fn service_runner_sends_ready_and_stopping_notifications() {
    let fixture = Fixture::new("notify");
    let app = fixture.app(
        "ok.ru",
        r#"
app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );
    let notify_socket = fixture.root.join("notify.sock");
    let notify = UnixDatagram::bind(&notify_socket).unwrap();
    notify
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{}", free_port()));
    cmd.env("NOTIFY_SOCKET", &notify_socket);
    let child = cmd.spawn().expect("spawn service runner");

    let ready = read_notify(&notify);
    assert!(ready.contains("READY=1"), "{ready}");

    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let stopping = read_notify(&notify);
    assert!(stopping.contains("STOPPING=1"), "{stopping}");

    let output = wait_child_output(child, Duration::from_secs(10));
    assert!(!output.timed_out, "runner hung after SIGTERM");
    assert!(
        output.output.status.success(),
        "runner should exit cleanly after SIGTERM: {:?}",
        output.output.status
    );
    assert_worker_socket_is_not_live(&fixture.socket);
}

#[test]
fn service_runner_allows_edge_term_handler_within_drain_grace_and_signals_grandchild() {
    let fixture = Fixture::new("drain-grace");
    let app = fixture.app(
        "ok.ru",
        r#"
app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );
    let record = fixture.root.join("edge-drain-record.txt");
    let fake_edge = fixture.root.join("fake-edge-drain.rb");
    let script = r#"#!/usr/bin/env ruby
require 'socket'
record = '__RECORD__'
bind = nil
ARGV.each_with_index do |arg, idx|
  bind = ARGV[idx + 1] if arg == '--http-bind' || arg == '--https-bind'
end
abort 'missing edge bind argument' if bind.nil?
host, port = bind.split(':', 2)
server = TCPServer.new(host, Integer(port))
grandchild = fork do
  Signal.trap('TERM') do
    File.open(record, 'a') { |f| f.puts 'grandchild-term' }
    exit! 0
  end
  loop { sleep 1 }
end
Signal.trap('TERM') do
  File.open(record, 'a') { |f| f.puts 'edge-term' }
  begin
    Process.wait(grandchild)
  rescue Errno::ECHILD
  end
  sleep 0.25
  File.open(record, 'a') { |f| f.puts 'edge-exit' }
  exit! 0
end
File.open(record, 'a') { |f| f.puts "edge-ready #{Process.pid} #{grandchild}" }
loop { sleep 1 }
"#
    .replace("__RECORD__", &ruby_single_quoted(&record));
    fs::write(&fake_edge, script).unwrap();
    fs::set_permissions(&fake_edge, fs::Permissions::from_mode(0o700)).unwrap();

    let port = free_port();
    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_EDGE_BIN", &fake_edge)
        .env("OXO_EDGE_DRAIN_GRACE_MS", "1000")
        .env("OXO_SERVICE_DRAIN_GRACE_MS", "4000");
    let child = cmd.spawn().expect("spawn service runner");
    wait_for_tcp(port);

    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let output = wait_child_output(child, Duration::from_secs(10));
    assert!(!output.timed_out, "runner hung during graceful drain");
    assert!(output.output.status.success(), "{:?}", output.output.status);

    let record = fs::read_to_string(&record).unwrap();
    assert!(record.contains("edge-term"), "{record}");
    assert!(record.contains("edge-exit"), "{record}");
    assert!(record.contains("grandchild-term"), "{record}");
    assert_worker_socket_is_not_live(&fixture.socket);
}

#[test]
fn service_runner_kills_edge_after_drain_grace_deadline() {
    let fixture = Fixture::new("drain-kill");
    let app = fixture.app(
        "ok.ru",
        r#"
app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );
    let record = fixture.root.join("edge-kill-record.txt");
    let fake_edge = fixture.root.join("fake-edge-ignore-term.rb");
    let script = r#"#!/usr/bin/env ruby
require 'socket'
record = '__RECORD__'
bind = nil
ARGV.each_with_index do |arg, idx|
  bind = ARGV[idx + 1] if arg == '--http-bind' || arg == '--https-bind'
end
abort 'missing edge bind argument' if bind.nil?
host, port = bind.split(':', 2)
server = TCPServer.new(host, Integer(port))
Signal.trap('TERM') do
  File.open(record, 'a') { |f| f.puts 'edge-term' }
  loop { sleep 1 }
end
File.open(record, 'a') { |f| f.puts "edge-ready #{Process.pid}" }
loop { sleep 1 }
"#
    .replace("__RECORD__", &ruby_single_quoted(&record));
    fs::write(&fake_edge, script).unwrap();
    fs::set_permissions(&fake_edge, fs::Permissions::from_mode(0o700)).unwrap();

    let port = free_port();
    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_EDGE_BIN", &fake_edge)
        .env("OXO_EDGE_DRAIN_GRACE_MS", "1000")
        .env("OXO_SERVICE_DRAIN_GRACE_MS", "4000");
    let child = cmd.spawn().expect("spawn service runner");
    wait_for_tcp(port);

    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let output = wait_child_output(child, Duration::from_secs(5));
    assert!(!output.timed_out, "runner did not enforce drain deadline");
    assert!(output.output.status.success(), "{:?}", output.output.status);

    let record = fs::read_to_string(&record).unwrap();
    assert!(record.contains("edge-term"), "{record}");
    assert!(!record.contains("edge-exit"), "{record}");
    assert_worker_socket_is_not_live(&fixture.socket);
}
#[test]
fn service_runner_second_sigterm_hard_stops_active_drain() {
    let fixture = Fixture::new("drain-second-signal");
    let app = fixture.app(
        "ok.ru",
        r#"
app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );
    let record = fixture.root.join("edge-second-signal-record.txt");
    let fake_edge = fixture.root.join("fake-edge-ignore-term-second.rb");
    let script = r#"#!/usr/bin/env ruby
require 'socket'
record = '__RECORD__'
bind = nil
ARGV.each_with_index do |arg, idx|
  bind = ARGV[idx + 1] if arg == '--http-bind' || arg == '--https-bind'
end
abort 'missing edge bind argument' if bind.nil?
host, port = bind.split(':', 2)
server = TCPServer.new(host, Integer(port))
Signal.trap('TERM') do
  File.open(record, 'a') { |f| f.puts "edge-term #{Time.now.to_f}" }
  loop { sleep 1 }
end
File.open(record, 'a') { |f| f.puts "edge-ready #{Process.pid}" }
loop { sleep 1 }
"#
    .replace("__RECORD__", &ruby_single_quoted(&record));
    fs::write(&fake_edge, script).unwrap();
    fs::set_permissions(&fake_edge, fs::Permissions::from_mode(0o700)).unwrap();

    let port = free_port();
    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_EDGE_BIN", &fake_edge)
        .env("OXO_EDGE_DRAIN_GRACE_MS", "3000")
        .env("OXO_SERVICE_DRAIN_GRACE_MS", "7000");
    let child = cmd.spawn().expect("spawn service runner");
    wait_for_tcp(port);

    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    thread::sleep(Duration::from_millis(200));
    let second_signal_at = Instant::now();
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let output = wait_child_output(child, Duration::from_secs(4));
    let elapsed = second_signal_at.elapsed();
    assert!(
        !output.timed_out,
        "runner ignored the second SIGTERM during drain"
    );
    assert!(output.output.status.success(), "{:?}", output.output.status);
    assert!(
        elapsed < Duration::from_secs(2),
        "second SIGTERM should force a prompt stop, took {elapsed:?}"
    );

    let record = fs::read_to_string(&record).unwrap();
    assert!(record.contains("edge-term"), "{record}");
    assert_worker_socket_is_not_live(&fixture.socket);
}
#[test]
fn service_runner_keeps_serving_after_one_worker_exits() {
    let fixture = Fixture::new("pool-worker-exit");
    let app = fixture.app(
        "pool-exit.ru",
        r#"
app = lambda do |env|
  if env['PATH_INFO'] == '/die'
    Process.kill('TERM', Process.pid)
    sleep 5
  end
  [200, { 'content-type' => 'text/plain' }, ["pid=#{Process.pid}\n"]]
end
run app
"#,
    );
    let port = free_port();
    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_WORKER_COUNT", "2");
    let child = cmd.spawn().expect("spawn service runner");
    wait_for_tcp(port);

    let _ = send_tcp(port, b"GET /die HTTP/1.1\r\nHost: app.test\r\n\r\n");
    for _ in 0..8 {
        let response = send_tcp(port, b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n");
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("200 OK"), "{text}");
    }

    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let output = wait_child_output(child, Duration::from_secs(10));
    assert!(!output.timed_out, "runner hung after pool SIGTERM");
    assert!(output.output.status.success(), "{:?}", output.output.status);
}
#[test]
fn service_runner_terminates_edge_when_worker_respawn_fails() {
    // D14: when a crashed worker cannot be respawned (spawn error, or the respawned worker
    // never signals readiness), the runner must tear down the edge before returning.
    // Previously the restart error propagated out of monitor_children with no sibling
    // cleanup, so the process-grouped edge child was orphaned and kept the public port
    // bound after the service process itself had exited.
    let fixture = Fixture::new("respawn-failure");
    let marker = fixture.root.join("respawn-marker");
    // A fake worker that signals readiness and binds its socket on the FIRST launch, then
    // self-exits after a short delay to force a respawn; on every later launch it fails
    // readiness (exits without printing OXO_WORKER_READY=), making restart_worker error.
    let fake_worker = fixture.root.join("fake-worker.rb");
    fs::write(
        &fake_worker,
        format!(
            "#!/usr/bin/env ruby\n\
             require 'socket'\n\
             marker = \"{marker}\"\n\
             socket = ENV.fetch(\"OXO_WORKER_SOCKET\")\n\
             if File.exist?(marker)\n\
             \x20 STDERR.puts \"fake-worker: forced respawn failure\"\n\
             \x20 exit 3\n\
             end\n\
             File.write(marker, \"1\")\n\
             File.unlink(socket) if File.exist?(socket)\n\
             server = UNIXServer.new(socket)\n\
             File.chmod(0o600, socket)\n\
             STDOUT.puts \"OXO_WORKER_READY=#{{socket}}\"\n\
             STDOUT.flush\n\
             Thread.new do\n\
             \x20 loop do\n\
             \x20\x20 begin; conn = server.accept; conn.close; rescue; break; end\n\
             \x20 end\n\
             end\n\
             sleep 2\n\
             exit 0\n",
            marker = marker.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_worker, fs::Permissions::from_mode(0o700)).unwrap();

    let app = fixture.app(
        "noop.ru",
        "run ->(env) { [200, { 'content-type' => 'text/plain' }, ['ok']] }\n",
    );
    let port = free_port();
    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_WORKER_BIN", &fake_worker);
    cmd.env("OXO_WORKER_COUNT", "1");
    let child = cmd.spawn().expect("spawn service runner");

    let output = wait_child_output(child, Duration::from_secs(30));
    assert!(
        !output.timed_out,
        "runner hung after worker respawn failure"
    );
    assert!(
        !output.output.status.success(),
        "runner must exit with failure when a worker respawn fails: {:?}",
        output.output.status
    );

    // The discriminating D14 assertion: the edge must NOT be orphaned. After the service
    // process has exited, its (process-grouped) edge child must be gone, so the public
    // port must no longer accept connections.
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_ok() {
        assert!(
            Instant::now() < deadline,
            "edge port {port} still accepts connections; edge was orphaned"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn service_runner_honors_shutdown_promptly_during_worker_restart() {
    // D13: a drain signal that arrives while a worker is being restarted must be honored
    // within roughly one monitor interval, not after the full ~15s readiness timeout. The
    // fake worker becomes ready then self-exits, and HANGS without signalling readiness on
    // respawn, so the runner is parked in wait_for_worker_ready when SIGTERM arrives — it
    // must still drain promptly.
    let fixture = Fixture::new("shutdown-during-restart");
    let marker = fixture.root.join("respawn-marker");
    let fake_worker = fixture.root.join("fake-worker.rb");
    fs::write(
        &fake_worker,
        format!(
            "#!/usr/bin/env ruby\n\
             require 'socket'\n\
             marker = \"{marker}\"\n\
             socket = ENV.fetch(\"OXO_WORKER_SOCKET\")\n\
             if File.exist?(marker)\n\
             \x20 sleep 3600\n\
             end\n\
             File.write(marker, \"1\")\n\
             File.unlink(socket) if File.exist?(socket)\n\
             server = UNIXServer.new(socket)\n\
             File.chmod(0o600, socket)\n\
             STDOUT.puts \"OXO_WORKER_READY=#{{socket}}\"\n\
             STDOUT.flush\n\
             Thread.new do\n\
             \x20 loop do\n\
             \x20\x20 begin; conn = server.accept; conn.close; rescue; break; end\n\
             \x20 end\n\
             end\n\
             sleep 1\n\
             exit 0\n",
            marker = marker.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_worker, fs::Permissions::from_mode(0o700)).unwrap();

    let app = fixture.app(
        "noop.ru",
        "run ->(env) { [200, { 'content-type' => 'text/plain' }, ['ok']] }\n",
    );
    let port = free_port();
    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_WORKER_BIN", &fake_worker);
    cmd.env("OXO_WORKER_COUNT", "1");
    cmd.env("OXO_EDGE_DRAIN_GRACE_MS", "1000");
    cmd.env("OXO_SERVICE_DRAIN_GRACE_MS", "4000");
    let child = cmd.spawn().expect("spawn service runner");
    wait_for_tcp(port);

    // Let the first worker self-exit (~1s) so the runner is parked in the respawn readiness
    // wait (the respawned worker hangs for 3600s).
    thread::sleep(Duration::from_millis(2000));

    let sigterm_at = Instant::now();
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let output = wait_child_output(child, Duration::from_secs(8));
    let elapsed = sigterm_at.elapsed();
    assert!(
        !output.timed_out,
        "runner did not exit within 8s of SIGTERM while parked in a respawn readiness wait"
    );
    assert!(
        elapsed < Duration::from_secs(6),
        "shutdown took {elapsed:?}; the restart readiness wait blocked the drain"
    );
}

#[test]
fn service_runner_starts_two_workers_and_routes_requests_to_both() {
    let fixture = Fixture::new("pool-e2e");
    let app = fixture.app(
        "pool.ru",
        r#"
app = lambda do |env|
  body = "pid=#{Process.pid}\nmultiprocess=#{env['rack.multiprocess']}\n"
  [200, { 'content-type' => 'text/plain' }, [body]]
end
run app
"#,
    );
    let port = free_port();
    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_WORKER_COUNT", "2");
    let child = cmd.spawn().expect("spawn service runner");
    wait_for_tcp(port);

    let mut pids = HashSet::new();
    for _ in 0..8 {
        let response = send_tcp(port, b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n");
        let body = response_body_text(&response);
        assert!(body.contains("multiprocess=true"), "{body}");
        let pid = body
            .lines()
            .find_map(|line| line.strip_prefix("pid="))
            .expect("pid line")
            .to_string();
        pids.insert(pid);
    }
    assert_eq!(
        pids.len(),
        2,
        "expected both workers to serve traffic: {pids:?}"
    );

    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let output = wait_child_output(child, Duration::from_secs(10));
    assert!(!output.timed_out, "runner hung after pool SIGTERM");
    assert!(output.output.status.success(), "{:?}", output.output.status);
    for socket in pool_sockets(&fixture.socket, 2) {
        assert_worker_socket_is_not_live(&socket);
    }
}
#[test]
fn service_runner_starts_optional_cable_with_clean_env_and_drains_process_group() {
    let fixture = Fixture::new("cable-runtime");
    let app = fixture.app(
        "ok.ru",
        r#"
app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );
    let record = fixture.root.join("cable-record.txt");
    let fake_cable = fixture.root.join("fake-cable.rb");
    let script = r#"#!/usr/bin/env ruby
require 'socket'
record = '__RECORD__'
File.open(record, 'a') do |f|
  ENV.to_h.sort.each { |key, value| f.puts "env:#{key}=#{value}" }
end
host, port = ENV.fetch('OXO_CABLE_BIND').split(':', 2)
server = TCPServer.new(host, Integer(port))
grandchild = fork do
  Signal.trap('TERM') do
    File.open(record, 'a') { |f| f.puts 'grandchild-term' }
    exit! 0
  end
  loop { sleep 1 }
end
Signal.trap('TERM') do
  File.open(record, 'a') { |f| f.puts 'cable-term' }
  begin
    Process.wait(grandchild)
  rescue Errno::ECHILD
  end
  exit! 0
end
File.open(record, 'a') { |f| f.puts "cable-ready #{Process.pid} #{grandchild}" }
loop do
  ready = IO.select([server], nil, nil, 0.1)
  next unless ready
  socket = server.accept
  socket.close
end
"#
    .replace("__RECORD__", &ruby_single_quoted(&record));
    fs::write(&fake_cable, script).unwrap();
    fs::set_permissions(&fake_cable, fs::Permissions::from_mode(0o700)).unwrap();

    let edge_port = free_port();
    let cable_port = free_port();
    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{edge_port}"));
    cmd.env("OXO_CABLE_ENABLED", "1")
        .env("OXO_CABLE_BIN", &fake_cable)
        .env("OXO_CABLE_BIND", format!("127.0.0.1:{cable_port}"))
        .env("OXO_CABLE_ALLOWED_ORIGINS", "http://app.example")
        .env("OXO_CABLE_MAX_CONNECTIONS", "8")
        .env("SECRET_KEY_BASE", "cable-secret")
        .env("REDIS_URL", "redis://127.0.0.1:6379/0")
        .env("DATABASE_URL", "postgres://edge-must-not-see-this")
        .env("OXO_EDGE_BIN", env!("CARGO_BIN_EXE_oxo-pingora-edge"));
    let child = cmd.spawn().expect("spawn service runner");
    wait_for_tcp(edge_port);
    wait_for_tcp(cable_port);

    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let output = wait_child_output(child, Duration::from_secs(10));
    assert!(!output.timed_out, "runner hung after cable SIGTERM");
    assert!(output.output.status.success(), "{:?}", output.output.status);

    let record = fs::read_to_string(&record).unwrap();
    assert!(record.contains("env:OXO_CABLE_BIND=127.0.0.1:"), "{record}");
    assert!(
        record.contains("env:OXO_CABLE_ALLOWED_ORIGINS=http://app.example"),
        "{record}"
    );
    assert!(
        record.contains("env:OXO_CABLE_MAX_CONNECTIONS=8"),
        "{record}"
    );
    assert!(
        record.contains("env:SECRET_KEY_BASE=cable-secret"),
        "{record}"
    );
    assert!(
        record.contains("env:REDIS_URL=redis://127.0.0.1:6379/0"),
        "{record}"
    );
    assert!(!record.contains("env:OXO_WORKER_SOCKET="), "{record}");
    assert!(!record.contains("env:OXO_EDGE_BIND="), "{record}");
    assert!(!record.contains("env:OXO_EDGE_WORKER_SOCKET="), "{record}");
    assert!(!record.contains("env:DATABASE_URL="), "{record}");
    assert!(record.contains("cable-term"), "{record}");
    assert!(record.contains("grandchild-term"), "{record}");
    assert_worker_socket_is_not_live(&fixture.socket);
}

#[test]
fn service_runner_rejects_non_loopback_cable_bind() {
    let fixture = Fixture::new("cable-bind-denied");
    let app = fixture.app(
        "ok.ru",
        r#"
app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );
    let fake_cable = fixture.root.join("fake-cable.sh");
    fs::write(&fake_cable, "#!/bin/sh\nsleep 30\n").unwrap();
    fs::set_permissions(&fake_cable, fs::Permissions::from_mode(0o700)).unwrap();

    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{}", free_port()));
    cmd.env("OXO_CABLE_ENABLED", "1")
        .env("OXO_CABLE_BIN", &fake_cable)
        .env("OXO_CABLE_BIND", "0.0.0.0:28080");
    let run = run_with_timeout(cmd, Duration::from_secs(5));
    let stderr = String::from_utf8_lossy(&run.output.stderr);

    assert!(!run.timed_out, "runner hung after denied cable bind");
    assert!(
        !run.output.status.success(),
        "runner should reject public cable bind"
    );
    assert!(
        stderr.contains("standalone Action Cable bind must be loopback-only"),
        "{stderr}"
    );
}
#[test]
fn service_runner_starts_optional_grpc_with_clean_env_and_drains_process_group() {
    let fixture = Fixture::new("grpc-runtime");
    let app = fixture.app(
        "ok.ru",
        r#"
app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );
    let record = fixture.root.join("grpc-record.txt");
    let fake_grpc = fixture.root.join("fake-grpc.rb");
    let script = r#"#!/usr/bin/env ruby
require 'socket'
record = '__RECORD__'
File.open(record, 'a') do |f|
  ENV.to_h.sort.each { |key, value| f.puts "env:#{key}=#{value}" }
end
host, port = ENV.fetch('OXO_GRPC_BIND').split(':', 2)
server = TCPServer.new(host, Integer(port))
grandchild = fork do
  Signal.trap('TERM') do
    File.open(record, 'a') { |f| f.puts 'grpc-grandchild-term' }
    exit! 0
  end
  loop { sleep 1 }
end
Signal.trap('TERM') do
  File.open(record, 'a') { |f| f.puts 'grpc-term' }
  begin
    Process.wait(grandchild)
  rescue Errno::ECHILD
  end
  exit! 0
end
File.open(record, 'a') { |f| f.puts "grpc-ready #{Process.pid} #{grandchild}" }
loop do
  ready = IO.select([server], nil, nil, 0.1)
  next unless ready
  socket = server.accept
  socket.close
end
"#
    .replace("__RECORD__", &ruby_single_quoted(&record));
    fs::write(&fake_grpc, script).unwrap();
    fs::set_permissions(&fake_grpc, fs::Permissions::from_mode(0o700)).unwrap();

    let edge_port = free_port();
    let grpc_port = free_port();
    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{edge_port}"));
    cmd.env("OXO_GRPC_ENABLED", "1")
        .env("OXO_GRPC_BIN", &fake_grpc)
        .env("OXO_GRPC_BIND", format!("127.0.0.1:{grpc_port}"))
        .env("OXO_GRPC_APP", "grpc_service")
        .env("OXO_GRPC_CONFIG", "grpc.yml")
        .env("OXO_GRPC_MAX_MESSAGE_BYTES", "1048576")
        .env("OXO_GRPC_DEADLINE_MS", "2500")
        .env("OXO_GRPC_ENV_ALLOW", "CUSTOM_GRPC_SECRET")
        .env("CUSTOM_GRPC_SECRET", "grpc-extra")
        .env("SECRET_KEY_BASE", "grpc-secret")
        .env("DATABASE_URL", "postgres://grpc-db")
        .env("REDIS_URL", "redis://127.0.0.1:6379/1")
        .env(
            "OXO_CABLE_ALLOWED_ORIGINS",
            "http://cable-must-not-see-this",
        )
        .env("OXO_EDGE_BIN", env!("CARGO_BIN_EXE_oxo-pingora-edge"));
    let mut child = cmd.spawn().expect("spawn service runner");
    // Dump the service's own output if it never binds. stderr is piped and was
    // never read, so this test could only ever say "edge did not bind" -- the
    // one thing already known -- while the actual cause sat unread in a pipe.
    wait_for_tcp_or_dump(edge_port, &mut child, "edge");
    wait_for_tcp_or_dump(grpc_port, &mut child, "grpc");

    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let output = wait_child_output(child, Duration::from_secs(10));
    assert!(!output.timed_out, "runner hung after grpc SIGTERM");
    assert!(output.output.status.success(), "{:?}", output.output.status);

    let record = fs::read_to_string(&record).unwrap();
    assert!(record.contains("env:OXO_GRPC_BIND=127.0.0.1:"), "{record}");
    assert!(record.contains("env:OXO_GRPC_APP=grpc_service"), "{record}");
    assert!(record.contains("env:OXO_GRPC_CONFIG=grpc.yml"), "{record}");
    assert!(
        record.contains("env:OXO_GRPC_MAX_MESSAGE_BYTES=1048576"),
        "{record}"
    );
    assert!(record.contains("env:OXO_GRPC_DEADLINE_MS=2500"), "{record}");
    assert!(
        record.contains("env:CUSTOM_GRPC_SECRET=grpc-extra"),
        "{record}"
    );
    assert!(
        record.contains("env:SECRET_KEY_BASE=grpc-secret"),
        "{record}"
    );
    assert!(
        record.contains("env:DATABASE_URL=postgres://grpc-db"),
        "{record}"
    );
    assert!(
        record.contains("env:REDIS_URL=redis://127.0.0.1:6379/1"),
        "{record}"
    );
    assert!(!record.contains("env:OXO_WORKER_SOCKET="), "{record}");
    assert!(!record.contains("env:OXO_EDGE_BIND="), "{record}");
    assert!(!record.contains("env:OXO_EDGE_WORKER_SOCKET="), "{record}");
    assert!(
        !record.contains("env:OXO_CABLE_ALLOWED_ORIGINS="),
        "{record}"
    );
    assert!(record.contains("grpc-term"), "{record}");
    assert!(record.contains("grpc-grandchild-term"), "{record}");
    assert_worker_socket_is_not_live(&fixture.socket);
}

#[test]
fn service_runner_rejects_non_loopback_grpc_bind() {
    let fixture = Fixture::new("grpc-bind-denied");
    let app = fixture.app(
        "ok.ru",
        r#"
app = lambda { |_env| [200, { 'content-type' => 'text/plain' }, ['ok']] }
run app
"#,
    );
    let fake_grpc = fixture.root.join("fake-grpc.sh");
    fs::write(&fake_grpc, "#!/bin/sh\nsleep 30\n").unwrap();
    fs::set_permissions(&fake_grpc, fs::Permissions::from_mode(0o700)).unwrap();

    let mut cmd = service_command(&app, &fixture.socket, &format!("127.0.0.1:{}", free_port()));
    cmd.env("OXO_GRPC_ENABLED", "1")
        .env("OXO_GRPC_BIN", &fake_grpc)
        .env("OXO_GRPC_BIND", "0.0.0.0:28081");
    let run = run_with_timeout(cmd, Duration::from_secs(5));
    let stderr = String::from_utf8_lossy(&run.output.stderr);

    assert!(!run.timed_out, "runner hung after denied grpc bind");
    assert!(
        !run.output.status.success(),
        "runner should reject public grpc bind"
    );
    assert!(
        stderr.contains("standalone gRPC bind must be loopback-only"),
        "{stderr}"
    );
}
struct Fixture {
    root: PathBuf,
    socket: PathBuf,
}

// ---- ACME renewal scheduler + reload restart (needs the acme feature) ----

#[cfg(feature = "acme")]
fn acme_state_with_pair(fixture: &Fixture) -> PathBuf {
    let state = fixture.root.join("acme-state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    // A placeholder pair so the tls-cert<->state coupling check passes; the
    // fake edge never actually reads it.
    fs::write(state.join("cert.pem"), b"placeholder-cert").unwrap();
    fs::write(state.join("key.pem"), b"placeholder-key").unwrap();
    state
}

#[cfg(feature = "acme")]
fn acme_service_command(fixture: &Fixture, app: &Path, bind: &str, state: &Path) -> Command {
    let mut cmd = service_command(app, &fixture.socket, bind);
    cmd.env("OXO_EDGE_ACME_STATE_PATH", state)
        .env("OXO_EDGE_SERVER_NAME", "app.example")
        .env("OXO_EDGE_ACME_ACCEPT_TERMS", "1")
        .env("OXO_EDGE_TLS_CERT", state.join("cert.pem"))
        .env("OXO_EDGE_TLS_KEY", state.join("key.pem"))
        .env("OXO_SERVICE_ACME_RENEW", "1")
        .env(
            "OXO_SERVICE_ACME_HTTP_BIND",
            format!("127.0.0.1:{}", free_port()),
        );
    cmd
}

#[cfg(feature = "acme")]
#[test]
fn service_acme_scheduler_spawns_renew_once_child_on_interval() {
    let fixture = Fixture::new("acme-schedule");
    let app = fixture.app(
        "ok.ru",
        "app = lambda { |_env| [200, {}, ['ok']] }\nrun app\n",
    );
    let state = acme_state_with_pair(&fixture);
    let renew_record = fixture.root.join("renew-invocations.txt");
    let boot_record = fixture.root.join("edge-boots.txt");
    let fake_edge = write_fake_acme_edge(&fixture, &renew_record, &boot_record, None);

    let port = free_port();
    let mut cmd = acme_service_command(&fixture, &app, &format!("127.0.0.1:{port}"), &state);
    cmd.env("OXO_EDGE_BIN", &fake_edge)
        .env("OXO_SERVICE_ACME_RENEW_INTERVAL_MS", "200");
    let child = cmd.spawn().expect("spawn service runner");
    wait_for_tcp(port);
    // Poll until at least two renewals have fired (robust to parallel-load
    // scheduling jitter), then stop the service.
    let deadline = Instant::now() + Duration::from_secs(15);
    while fs::read_to_string(&renew_record)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .count()
        < 2
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(50));
    }
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let out = wait_child_output(child, Duration::from_secs(10));
    assert!(!out.timed_out, "runner hung");

    let record = fs::read_to_string(&renew_record).unwrap_or_default();
    let invocations: Vec<&str> = record.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        invocations.len() >= 2,
        "expected >=2 renewal invocations at 200ms interval, got {}: {record}",
        invocations.len()
    );
    for line in &invocations {
        assert!(line.contains("--acme-renew-once"), "{line}");
        assert!(line.contains("--acme-state-path"), "{line}");
        assert!(line.contains("--fqdn app.example"), "{line}");
        assert!(line.contains("--acme-accept-terms"), "{line}");
        assert!(line.contains("--http-bind"), "{line}");
    }
    // The serving edge booted exactly once (renewal children never disturb it).
    let boots = fs::read_to_string(&boot_record).unwrap_or_default();
    assert_eq!(
        boots.lines().filter(|l| !l.is_empty()).count(),
        1,
        "serving edge must not be restarted by renewals: {boots}"
    );
}

#[cfg(feature = "acme")]
#[test]
fn service_acme_reload_marker_triggers_bounded_edge_restart() {
    let fixture = Fixture::new("acme-reload");
    let app = fixture.app(
        "ok.ru",
        "app = lambda { |_env| [200, {}, ['ok']] }\nrun app\n",
    );
    let state = acme_state_with_pair(&fixture);
    let renew_record = fixture.root.join("renew-invocations.txt");
    let boot_record = fixture.root.join("edge-boots.txt");
    // The fake renew child writes a marker (simulating a completed renewal) on
    // its FIRST invocation only, so the supervisor performs one restart.
    let fake_edge = write_fake_acme_edge(&fixture, &renew_record, &boot_record, Some(&state));

    let port = free_port();
    let mut cmd = acme_service_command(&fixture, &app, &format!("127.0.0.1:{port}"), &state);
    cmd.env("OXO_EDGE_BIN", &fake_edge)
        .env("OXO_SERVICE_ACME_RENEW_INTERVAL_MS", "200");
    let child = cmd.spawn().expect("spawn service runner");
    wait_for_tcp(port);
    // Poll until the reload restart has happened: the marker is consumed AND
    // the serving edge has booted a second time. Robust to parallel-load jitter.
    let deadline = Instant::now() + Duration::from_secs(15);
    let restarted = || {
        !state.join("reload-required.json").exists()
            && fs::read_to_string(&boot_record)
                .unwrap_or_default()
                .lines()
                .filter(|l| !l.is_empty())
                .count()
                >= 2
    };
    while !restarted() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let out = wait_child_output(child, Duration::from_secs(10));
    assert!(!out.timed_out, "runner hung");

    // Marker was consumed by the supervisor after a successful restart.
    assert!(
        !state.join("reload-required.json").exists(),
        "supervisor must delete the marker after a successful reload restart"
    );
    // The serving edge booted at least twice: once at start, once for reload.
    let boots = fs::read_to_string(&boot_record).unwrap_or_default();
    assert!(
        boots.lines().filter(|l| !l.is_empty()).count() >= 2,
        "reload marker must trigger a bounded edge restart: {boots}"
    );
}

/// A dual-role fake edge: as the serving edge it binds the http/https bind and
/// records each boot's PID; as a renewal child (argv has --acme-renew-once) it
/// records its argv and, if `marker_state` is set, writes a reload marker on
/// its first run to drive the restart path.
#[cfg(feature = "acme")]
fn write_fake_acme_edge(
    fixture: &Fixture,
    renew_record: &Path,
    boot_record: &Path,
    marker_state: Option<&Path>,
) -> PathBuf {
    let path = fixture.root.join("fake-acme-edge.rb");
    let marker_line = match marker_state {
        Some(state) => format!(
            "  flag = '{flag}'\n\
             \x20 unless File.exist?(flag)\n\
             \x20   File.write(flag, '1')\n\
             \x20   File.write('{marker}', '{{\"reload_required\":true,\"updated_at_epoch_seconds\":9999999999}}')\n\
             \x20 end\n",
            flag = ruby_single_quoted(&fixture.root.join("renew-marker-written.flag")),
            marker = ruby_single_quoted(&state.join("reload-required.json")),
        ),
        None => String::new(),
    };
    let script = format!(
        r#"#!/usr/bin/env ruby
require 'socket'
if ARGV.include?('--acme-renew-once')
  File.open('{renew}', 'a') {{ |f| f.puts ARGV.join(' ') }}
{marker}  exit 0
end
bind = nil
ARGV.each_with_index do |arg, idx|
  bind = ARGV[idx + 1] if arg == '--http-bind' || arg == '--https-bind'
end
abort 'missing edge bind argument' if bind.nil?
host, port = bind.split(':', 2)
server = TCPServer.new(host, Integer(port))
File.open('{boot}', 'a') {{ |f| f.puts Process.pid }}
Signal.trap('TERM') {{ exit! 0 }}
loop {{ sleep 1 }}
"#,
        renew = ruby_single_quoted(renew_record),
        boot = ruby_single_quoted(boot_record),
        marker = marker_line,
    );
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "oxo-service-runner-{label}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("worker.sock");
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

struct CommandRun {
    output: Output,
    timed_out: bool,
}

fn run_service_for_failure(app: &Path, socket: &Path) -> CommandRun {
    let cmd = service_command(app, socket, &format!("0.0.0.0:{}", free_port()));
    run_with_timeout(cmd, Duration::from_secs(10))
}

fn service_command(app: &Path, socket: &Path, bind: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo-pingora-service"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("OXO_SERVICE_ALLOW_BIN_OVERRIDES", "1")
        .env("OXO_WORKER_BIN", worker_binary())
        .env("OXO_EDGE_BIN", env!("CARGO_BIN_EXE_oxo-pingora-edge"))
        .env("OXO_WORKER_APP", app)
        .env("OXO_WORKER_SOCKET", socket)
        .env("OXO_WORKER_THREADS", "1")
        .env("OXO_WORKER_MAX_BODY", "1024")
        .env("OXO_EDGE_BIND", bind)
        .env("OXO_EDGE_MAX_BODY", "1024")
        .env("OXO_EDGE_SERVER_NAME", "localhost")
        .env("OXO_EDGE_SCHEME", "http")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(libdir) = ruby_libdir() {
        cmd.env("LD_LIBRARY_PATH", libdir);
    }
    cmd
}

fn run_with_timeout(mut cmd: Command, timeout: Duration) -> CommandRun {
    let start = Instant::now();
    let mut child = cmd.spawn().expect("spawn service runner");
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

fn assert_worker_socket_is_not_live(socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match UnixStream::connect(socket) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                let mut byte = [0u8; 1];
                if stream.read(&mut byte).is_ok() {
                    panic!("worker socket remained live at {}", socket.display());
                }
            }
            Err(_) => return,
        }
        if Instant::now() >= deadline {
            panic!("worker socket remained connectable at {}", socket.display());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn read_notify(socket: &UnixDatagram) -> String {
    let mut buf = [0u8; 4096];
    let n = socket.recv(&mut buf).expect("read notify datagram");
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

fn wait_child_output(mut child: std::process::Child, timeout: Duration) -> CommandRun {
    let start = Instant::now();
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
fn worker_binary() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_oxo-worker") {
        return PathBuf::from(path);
    }
    let target_dir = std::env::current_exe()
        .expect("current test exe")
        .parent()
        .and_then(|deps| deps.parent())
        .expect("target profile dir")
        .to_path_buf();
    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
        .args(["build", "-p", "oxo-worker", "--bin", "oxo-worker"])
        .status()
        .expect("build oxo-worker helper binary");
    assert!(status.success(), "cargo build -p oxo-worker failed");
    target_dir.join("oxo-worker")
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

// Wait for a bind, and on failure KILL the child and print everything it said.
// A timeout message that reports only the timeout is a dead end: it names the
// symptom the caller already knows and hides the diagnosis. The service writes
// its config notices and fail-closed errors to stderr, which is piped here.
fn wait_for_tcp_or_dump(port: u16, child: &mut Child, role: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let (out, err) = drain_child_output(child);
            panic!(
                "service exited ({status}) before {role} bound to 127.0.0.1:{port}
                    --- stdout ---
{out}
--- stderr ---
{err}"
            );
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let (out, err) = drain_child_output(child);
            panic!(
                "{role} did not bind to 127.0.0.1:{port} within 20s
                    --- stdout ---
{out}
--- stderr ---
{err}"
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn drain_child_output(child: &mut Child) -> (String, String) {
    use std::io::Read;
    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    (out, err)
}

// Deliberately per-suite (RR3): startup deadlines/diagnostics are fixture-specific.
//
// 20 s, not 10. This suite's gRPC fixture starts a sidecar BEFORE the edge:
// `spawn_grpc` runs ahead of `spawn_edge` and blocks in `wait_for_grpc_ready`,
// which the service allows GRPC_READY_TIMEOUT = 15 s to complete because that
// sidecar is a full Rails boot. A 10 s deadline on the EDGE was therefore
// shorter than the product's own budget for the step that must finish first, so
// the test could fail while the service was behaving exactly to spec -- and did,
// reproducibly, on 2 cores, on 16, and against the baked image.
//
// 20 s matches the Action Cable suite, which has the same sidecar-then-edge
// shape and a 15 s readiness allowance, and which passes. The deadline still
// bounds the test; it is now simply larger than what it waits on.
fn wait_for_tcp(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
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

// Deliberately per-suite (RR3): return type/read-timeout differ across suites.
fn send_tcp(port: u16, request: &[u8]) -> Vec<u8> {
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
            Err(err) => panic!("read edge response: {err}"),
        }
    }
    response
}

fn response_body_text(response: &[u8]) -> String {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response header terminator");
    String::from_utf8_lossy(&response[header_end + 4..]).into_owned()
}

fn pool_sockets(base: &Path, count: usize) -> Vec<PathBuf> {
    let parent = base.parent().expect("socket parent");
    let stem = base
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("worker");
    let extension = base.extension().and_then(|extension| extension.to_str());
    (0..count)
        .map(|id| match extension {
            Some(extension) if !extension.is_empty() => {
                parent.join(format!("{stem}-{id}.{extension}"))
            }
            _ => parent.join(format!("{stem}-{id}")),
        })
        .collect()
}

fn ruby_single_quoted(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
}

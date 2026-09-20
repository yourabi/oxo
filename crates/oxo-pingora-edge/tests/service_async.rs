#![cfg(target_os = "linux")]

#[path = "support/process.rs"]
mod process_fixture;
#[path = "../../../test/support/ruby.rs"]
mod ruby_fixture;

mod support;

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use support::{free_port, serial_test};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn which(bin: &str) -> Option<PathBuf> {
    let out = ruby_fixture::command("which").arg(bin).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!path.is_empty()).then(|| PathBuf::from(path))
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
        let root = std::env::temp_dir().join(format!(
            "oxo-svc-async-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let run = root.join("run");
        fs::create_dir_all(&run).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            socket: run.join("worker.sock"),
            root,
        }
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

/// The async service env: real bundle/ruby from PATH, the real worker script, the
/// small Rack/async bundle as app_root.
fn async_service_command(fixture: &Fixture, app: &Path, bind: &str) -> Command {
    let repo = repo_root();
    let bundle = which("bundle").expect("bundle on PATH (mise shims)");
    let ruby = which("ruby").expect("ruby on PATH");
    let mut cmd = ruby_fixture::command(env!("CARGO_BIN_EXE_oxo-pingora-service"));
    cmd.env("PATH", std::env::var_os("PATH").unwrap_or_default())
        // Tests point OXO_EDGE_BIN at the freshly built edge, which needs the
        // sibling-override gate; the ASYNC surface itself never consults it.
        .env("OXO_SERVICE_ALLOW_BIN_OVERRIDES", "1")
        .env("OXO_WORKER_KIND", "async")
        .env(
            "OXO_ASYNC_WORKER_SCRIPT",
            repo.join("ruby/oxo_async_worker.rb"),
        )
        .env(
            "OXO_ASYNC_WORKER_APP_ROOT",
            repo.join("test/fixtures/rack_async"),
        )
        .env("OXO_ASYNC_BUNDLE_BIN", &bundle)
        .env("OXO_ASYNC_RUBY_BIN", &ruby)
        .env("OXO_EDGE_BIN", env!("CARGO_BIN_EXE_oxo-pingora-edge"))
        .env("OXO_WORKER_APP", app)
        .env("OXO_WORKER_SOCKET", &fixture.socket)
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

fn ruby_libdir() -> Option<String> {
    let out = ruby_fixture::command("ruby")
        .args(["-rrbconfig", "-e", "print RbConfig::CONFIG['libdir']"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

struct CommandRun {
    output: std::process::Output,
    timed_out: bool,
}

/// Kill-on-drop guard: a panicking test (a failed wait_for_tcp especially) must not
/// leak its service tree into the next test's ports and sockets.
struct ServiceChild(process_fixture::CapturedChild);
impl ServiceChild {
    fn spawn(cmd: &mut Command) -> Self {
        Self(process_fixture::CapturedChild::new(
            cmd.spawn().expect("spawn async service"),
        ))
    }
    fn id(&self) -> u32 {
        self.0.id()
    }
    fn into_child(self) -> process_fixture::CapturedChild {
        self.0
    }
}
fn wait_child_output(child: process_fixture::CapturedChild, timeout: Duration) -> CommandRun {
    let (output, timed_out) = child.wait(timeout);
    CommandRun { output, timed_out }
}

fn wait_for_tcp(port: u16, budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "edge never bound :{port}");
        thread::sleep(Duration::from_millis(50));
    }
}

fn send_tcp(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect edge");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    buf
}

fn get(port: u16, path: &str) -> Vec<u8> {
    send_tcp(
        port,
        format!("GET {path} HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n").as_bytes(),
    )
}

fn status_of(response: &[u8]) -> u16 {
    String::from_utf8_lossy(response)
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn body_of(response: &[u8]) -> String {
    let text = String::from_utf8_lossy(response);
    text.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
}

fn term(child: &ServiceChild) {
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
}

/// Returns the worker PID. `/slow` acknowledges entry and waits for the test's
/// release file, yielding the fiber while the request remains in flight.
const PID_APP: &str = r#"
app = lambda do |env|
  if env['PATH_INFO'] == '/slow'
    File.write(File.join(__dir__, "entered-#{Process.pid}"), 'entered')
    sleep 0.01 until File.exist?(File.join(__dir__, 'release'))
  end
  [200, { 'content-type' => 'text/plain' }, ["pid=#{Process.pid}\n"]]
end
run app
"#;

fn collect_pids(port: u16, tries: usize) -> HashSet<String> {
    let mut pids = HashSet::new();
    for _ in 0..tries {
        let response = get(port, "/");
        if status_of(&response) == 200 {
            if let Some(pid) = body_of(&response)
                .lines()
                .find_map(|l| l.strip_prefix("pid=").map(str::to_string))
            {
                pids.insert(pid);
            }
        }
    }
    pids
}

// Real async workers: startup, request routing and shutdown.

/// Batched N=2 boot, routing to both reactors, clean SIGTERM close.
#[test]
fn async_service_boots_two_reactors_batched_and_routes_to_both() {
    let _guard = serial_test();
    let fixture = Fixture::new("boot2");
    let app = fixture.app("pid.ru", PID_APP);
    let port = free_port();
    let mut cmd = async_service_command(&fixture, &app, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_WORKER_COUNT", "2");
    let child = ServiceChild::spawn(&mut cmd);
    wait_for_tcp(port, Duration::from_secs(150));

    let pids = collect_pids(port, 12);
    assert_eq!(pids.len(), 2, "both reactors must serve: {pids:?}");

    term(&child);
    let run = wait_child_output(child.into_child(), Duration::from_secs(15));
    assert!(!run.timed_out, "service hung after SIGTERM");
    assert!(run.output.status.success(), "{:?}", run.output.status);
    let stderr = ruby_fixture::diagnostic(&run.output.stderr);
    assert!(
        !stderr.contains("drain_deadline_expired"),
        "idle drain must be silent: {stderr}"
    );
}

#[test]
fn async_service_kill9_surfaces_502_no_replay_and_respawns() {
    let _guard = serial_test();
    let fixture = Fixture::new("kill9");
    let app = fixture.app("pid.ru", PID_APP);
    let port = free_port();
    let mut cmd = async_service_command(&fixture, &app, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_WORKER_COUNT", "2");
    let child = ServiceChild::spawn(&mut cmd);
    wait_for_tcp(port, Duration::from_secs(150));

    let before = collect_pids(port, 12);
    assert_eq!(before.len(), 2, "need both reactors up: {before:?}");

    // Park one /slow request per reactor so the victim is guaranteed mid-request.
    let mut slow: Vec<thread::JoinHandle<(u16, String)>> = Vec::new();
    for _ in 0..2 {
        slow.push(thread::spawn(move || {
            let response = get(port, "/slow");
            (status_of(&response), body_of(&response))
        }));
    }
    await_entries(&fixture, 2);

    let victim = before.iter().next().unwrap().clone();
    unsafe {
        libc::kill(victim.parse::<i32>().unwrap(), libc::SIGKILL);
    }

    fs::write(fixture.root.join("release"), "release").unwrap();
    let survivor: Vec<u16> = (0..6).map(|_| status_of(&get(port, "/"))).collect();
    // At most one request may receive the killed worker's pooled connection
    // and fail with 502. Least-outstanding dispatch does not prescribe which
    // request receives it; subsequent requests must succeed after eviction.
    assert!(
        survivor.iter().all(|s| *s == 200 || *s == 502),
        "every post-kill request is either served or terminally 502 — never anything else: {survivor:?}"
    );
    let five_oh_twos = survivor.iter().filter(|s| **s == 502).count();
    assert!(
        five_oh_twos <= 1,
        "at most one request may use the dead worker connection; more than one means it was \
         not evicted: {survivor:?}"
    );
    if let Some(dead) = survivor.iter().position(|s| *s == 502) {
        assert!(
            survivor[dead + 1..].iter().all(|s| *s == 200),
            "surviving worker must keep serving after the dead connection is evicted, got {survivor:?}"
        );
    }

    // The request on the killed reactor must fail with 502 without replay.
    // The request on the surviving reactor must complete with 200.
    let mut statuses: Vec<u16> = slow.into_iter().map(|h| h.join().unwrap().0).collect();
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        vec![200, 502],
        "one in-flight dies terminal, one completes — a [200, 200] here IS the silent replay"
    );

    // The pool must contain two live PIDs, including a replacement for the victim.
    let deadline = Instant::now() + Duration::from_secs(45);
    let after = loop {
        let pids = collect_pids(port, 12);
        if pids.len() == 2 && !pids.contains(&victim) {
            break pids;
        }
        assert!(
            Instant::now() < deadline,
            "victim never respawned: last seen {pids:?}"
        );
        thread::sleep(Duration::from_millis(250));
    };
    assert!(
        !after.contains(&victim),
        "victim pid must be gone: {after:?}"
    );

    term(&child);
    let run = wait_child_output(child.into_child(), Duration::from_secs(15));
    assert!(!run.timed_out && run.output.status.success());
}

/// SIGTERM drains the edge before the workers. The in-flight request completes,
/// and the service exits successfully without a drain-expiry diagnostic.
#[test]
fn async_service_sigterm_under_load_drains_cleanly() {
    let _guard = serial_test();
    let fixture = Fixture::new("drain");
    let app = fixture.app("pid.ru", PID_APP);
    let port = free_port();
    let mut cmd = async_service_command(&fixture, &app, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_WORKER_COUNT", "1");
    // Allow time for the acknowledged request to finish after release. The
    // service grace must cover the edge and worker shutdown stages.
    cmd.env("OXO_WORKER_DRAIN_DEADLINE_MS", "3000");
    cmd.env("OXO_SERVICE_DRAIN_GRACE_MS", "8000");
    let child = ServiceChild::spawn(&mut cmd);
    wait_for_tcp(port, Duration::from_secs(150));
    assert_eq!(status_of(&get(port, "/")), 200);

    let slow = thread::spawn(move || status_of(&get(port, "/slow")));
    await_entries(&fixture, 1);
    term(&child);
    fs::write(fixture.root.join("release"), "release").unwrap();
    assert_eq!(
        slow.join().unwrap(),
        200,
        "in-flight request must complete across the staged drain"
    );
    let run = wait_child_output(child.into_child(), Duration::from_secs(15));
    assert!(!run.timed_out && run.output.status.success());
    let stderr = ruby_fixture::diagnostic(&run.output.stderr);
    assert!(
        !stderr.contains("drain_deadline_expired"),
        "clean drain is silent: {stderr}"
    );
}

/// A non-yielding application prevents the worker's drain fiber from running.
/// The supervisor must kill that worker and finish shutdown within the grace.
#[test]
fn async_service_kill_sweep_closes_a_pinned_reactor() {
    let _guard = serial_test();
    let fixture = Fixture::new("pinned");
    let app = fixture.app(
        "pin.ru",
        r#"
app = lambda do |env|
  if env['PATH_INFO'] == '/pin'
    File.write(File.join(__dir__, "entered-#{Process.pid}"), 'entered')
    loop { } # GVL-pinned: the reactor never yields again
  end
  [200, { 'content-type' => 'text/plain' }, ["ok"]]
end
run app
"#,
    );
    let port = free_port();
    let mut cmd = async_service_command(&fixture, &app, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_WORKER_COUNT", "1");
    let child = ServiceChild::spawn(&mut cmd);
    wait_for_tcp(port, Duration::from_secs(150));
    assert_eq!(status_of(&get(port, "/")), 200);

    // Pin the reactor, then TERM the service: the worker cannot run its drain.
    let pin = thread::spawn(move || get(port, "/pin"));
    await_entries(&fixture, 1);
    let started = Instant::now();
    term(&child);
    let run = wait_child_output(child.into_child(), Duration::from_secs(15));
    assert!(
        !run.timed_out,
        "KILL sweep must close a pinned reactor within the grace"
    );
    assert!(run.output.status.success(), "{:?}", run.output.status);
    let _ = pin.join().expect("pinned request thread joined");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "close took {:?}",
        started.elapsed()
    );
}

// Worker stubs: process arguments, readiness deadlines and output handling.

/// The spawn contract, recorded by a fake `bundle`: argv is exactly
/// `exec <ruby> <script> <socket>`, cwd is app_root, and the cleared env carries the
/// async contract (OXO_ASYNC=1, BUNDLE_GEMFILE) but never the classic-only knobs.
#[test]
fn async_spawn_contract_argv_cwd_and_env() {
    let _guard = serial_test();
    let fixture = Fixture::new("contract");
    let record = fixture.root.join("record.txt");
    let app_root = fixture.root.join("approot");
    fs::create_dir_all(&app_root).unwrap();
    fs::write(app_root.join("Gemfile"), "source 'https://rubygems.org'\n").unwrap();
    let ruby = which("ruby").expect("ruby on PATH");
    // The fake bundle records its invocation then execs a ruby one-liner that binds the
    // socket 0600, prints the READY line, and parks (the probe needs a real listener).
    let fake_bundle = fixture.root.join("fake-bundle.sh");
    fs::write(
        &fake_bundle,
        format!(
            "#!/bin/sh\n\
             {{ echo \"argv=$*\"; echo \"cwd=$(pwd)\"; echo \"async=$OXO_ASYNC\"; \
             echo \"gemfile=$BUNDLE_GEMFILE\"; echo \"threads=${{OXO_WORKER_THREADS:-unset}}\"; }} > {rec}\n\
             exec \"$2\" -rsocket -e 's=UNIXServer.new(ARGV[1]); File.chmod(0o600, ARGV[1]); \
             puts \"OXO_WORKER_READY=#{{ARGV[1]}}\"; $stdout.flush; sleep' -- \"$3\" \"$4\"\n",
            rec = record.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_bundle, fs::Permissions::from_mode(0o700)).unwrap();

    let app = fixture.app("ok.ru", "run ->(env) { [200, {}, ['ok']] }\n");
    let port = free_port();
    let mut cmd = async_service_command(&fixture, &app, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_ASYNC_BUNDLE_BIN", &fake_bundle);
    cmd.env("OXO_ASYNC_WORKER_APP_ROOT", &app_root);
    cmd.env("OXO_WORKER_COUNT", "1");
    let child = ServiceChild::spawn(&mut cmd);
    wait_for_tcp(port, Duration::from_secs(30));

    let recorded = fs::read_to_string(&record).expect("spawn record");
    let script = repo_root().join("ruby/oxo_async_worker.rb");
    assert!(
        recorded.contains(&format!(
            "argv=exec {} {} {}",
            ruby.display(),
            script.display(),
            fixture.socket.display()
        )),
        "argv shape: {recorded}"
    );
    assert!(
        recorded.contains(&format!(
            "cwd={}",
            app_root.canonicalize().unwrap().display()
        )),
        "cwd must be app_root: {recorded}"
    );
    assert!(
        recorded.contains("async=1"),
        "OXO_ASYNC injected: {recorded}"
    );
    assert!(
        recorded.contains(&format!("gemfile={}", app_root.join("Gemfile").display())),
        "BUNDLE_GEMFILE computed: {recorded}"
    );
    assert!(
        recorded.contains("threads=unset"),
        "classic-only knobs must NOT be forwarded: {recorded}"
    );

    term(&child);
    let _ = wait_child_output(child.into_child(), Duration::from_secs(10));
}

/// The readiness budget is config, not const: a worker that never says READY fails the
/// boot after the OVERRIDDEN budget (1.5 s), far under both kind defaults.
#[test]
fn async_ready_timeout_override_is_honored() {
    let _guard = serial_test();
    let fixture = Fixture::new("timeout");
    let app_root = fixture.root.join("approot");
    fs::create_dir_all(&app_root).unwrap();
    fs::write(app_root.join("Gemfile"), "source 'https://rubygems.org'\n").unwrap();
    let fake_bundle = fixture.root.join("mute-bundle.sh");
    fs::write(&fake_bundle, "#!/bin/sh\nexec sleep 600\n").unwrap();
    fs::set_permissions(&fake_bundle, fs::Permissions::from_mode(0o700)).unwrap();

    let app = fixture.app("ok.ru", "run ->(env) { [200, {}, ['ok']] }\n");
    let port = free_port();
    let mut cmd = async_service_command(&fixture, &app, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_ASYNC_BUNDLE_BIN", &fake_bundle);
    cmd.env("OXO_ASYNC_WORKER_APP_ROOT", &app_root);
    cmd.env("OXO_WORKER_COUNT", "1");
    cmd.env("OXO_WORKER_READY_TIMEOUT_MS", "1500");
    let started = Instant::now();
    let child = ServiceChild::spawn(&mut cmd);
    let run = wait_child_output(child.into_child(), Duration::from_secs(20));
    assert!(!run.timed_out, "must fail fast, not hang");
    assert!(
        !run.output.status.success(),
        "a mute worker must fail the boot"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1400) && elapsed < Duration::from_secs(10),
        "readiness budget must be the 1.5s override, took {elapsed:?}"
    );
}

#[test]
fn async_batched_boot_survives_a_chatty_sibling_stderr() {
    let _guard = serial_test();
    let fixture = Fixture::new("chatty");
    let app_root = fixture.root.join("approot");
    fs::create_dir_all(&app_root).unwrap();
    fs::write(app_root.join("Gemfile"), "source 'https://rubygems.org'\n").unwrap();
    let fake_bundle = fixture.root.join("chatty-bundle.sh");
    // Worker 0 dumps 100 KB of stderr BEFORE binding; worker 1 boots quietly. With
    // unpumped pipes the flood would block worker 0 pre-READY and wedge the pool.
    fs::write(
        &fake_bundle,
        "#!/bin/sh\n\
         if [ \"$OXO_WORKER_ID\" = \"0\" ]; then head -c 102400 /dev/zero | tr '\\0' 'x' 1>&2; fi\n\
         exec \"$2\" -rsocket -e 's=UNIXServer.new(ARGV[1]); File.chmod(0o600, ARGV[1]); \
         puts \"OXO_WORKER_READY=#{ARGV[1]}\"; $stdout.flush; sleep' -- \"$3\" \"$4\"\n",
    )
    .unwrap();
    fs::set_permissions(&fake_bundle, fs::Permissions::from_mode(0o700)).unwrap();

    let app = fixture.app("ok.ru", "run ->(env) { [200, {}, ['ok']] }\n");
    let port = free_port();
    let mut cmd = async_service_command(&fixture, &app, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_ASYNC_BUNDLE_BIN", &fake_bundle);
    cmd.env("OXO_ASYNC_WORKER_APP_ROOT", &app_root);
    cmd.env("OXO_WORKER_COUNT", "2");
    cmd.env("OXO_WORKER_READY_TIMEOUT_MS", "20000");
    // The supervisor forwards worker stderr. Discard it here so this case can
    // check startup while the worker emits more output than a pipe can buffer.
    cmd.stderr(Stdio::null());
    let child = ServiceChild::spawn(&mut cmd);
    wait_for_tcp(port, Duration::from_secs(30));
    term(&child);
    let run = wait_child_output(child.into_child(), Duration::from_secs(10));
    assert!(!run.timed_out && run.output.status.success());
}

fn await_entries(fixture: &Fixture, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let count = fs::read_dir(&fixture.root)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("entered-"))
            .count();
        if count == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "only {count}/{expected} workers acknowledged entry"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn async_warm_pool_relays_app_500_once_and_recovers() {
    let _guard = serial_test();
    let fixture = Fixture::new("relay-error");
    let app = fixture.app(
        "raise.ru",
        r#"
run ->(env) {
  if env['PATH_INFO'] == '/raise'
    path = File.join(__dir__, 'invocations')
    File.open(path, 'a+') do |f|
      f.flock(File::LOCK_EX)
      count = f.read.to_i + 1
      f.rewind; f.truncate(0); f.write(count.to_s)
    end
    raise 'synthetic application failure'
  end
  [200, { 'content-type' => 'text/plain' }, ['ok']]
}
"#,
    );
    let port = free_port();
    let admin = free_port();
    let mut cmd = async_service_command(&fixture, &app, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_WORKER_COUNT", "1")
        .env("OXO_EDGE_ADMIN_BIND", format!("127.0.0.1:{admin}"));
    let child = ServiceChild::spawn(&mut cmd);
    wait_for_tcp(port, Duration::from_secs(30));
    assert_eq!(status_of(&get(port, "/warm")), 200);
    assert_eq!(status_of(&get(port, "/warm")), 200);
    // Confirm reuse before the error request so the assertion exercises a
    // warm connection rather than one created during recovery.
    let health = body_of(&get(admin, "/pool-health"));
    assert!(health.contains("\"registered\":true"), "{health}");
    let reused: u64 = health
        .split("\"pool_reuse_total\":")
        .nth(1)
        .unwrap()
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(reused >= 1, "pool was not warm before the error");
    assert_eq!(status_of(&get(port, "/raise")), 500);
    assert_eq!(
        fs::read_to_string(fixture.root.join("invocations")).unwrap(),
        "1"
    );
    assert_eq!(status_of(&get(port, "/warm")), 200);
    term(&child);
    let run = wait_child_output(child.into_child(), Duration::from_secs(15));
    assert!(!run.timed_out && run.output.status.success());
}

#[test]
fn async_four_workers_have_private_sockets_and_serve_concurrent_requests() {
    let _guard = serial_test();
    let fixture = Fixture::new("four-workers");
    let app = fixture.app("pid.ru", PID_APP);
    let port = free_port();
    let admin = free_port();
    let mut cmd = async_service_command(&fixture, &app, &format!("127.0.0.1:{port}"));
    cmd.env("OXO_WORKER_COUNT", "4")
        .env("OXO_EDGE_ADMIN_BIND", format!("127.0.0.1:{admin}"));
    let child = ServiceChild::spawn(&mut cmd);
    wait_for_tcp(port, Duration::from_secs(60));
    let ready = body_of(&get(admin, "/ready"));
    assert!(ready.contains("\"worker_count\":4"), "{ready}");
    let sockets: Vec<_> = fs::read_dir(fixture.socket.parent().unwrap())
        .unwrap()
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "sock")
        })
        .collect();
    assert_eq!(sockets.len(), 4);
    for socket in sockets {
        assert_eq!(
            socket.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let jobs: Vec<_> = (0..40)
        .map(|_| thread::spawn(move || get(port, "/")))
        .collect();
    let mut pids = HashSet::new();
    for job in jobs {
        let response = job.join().expect("concurrent request completed");
        assert_eq!(status_of(&response), 200);
        pids.insert(body_of(&response));
    }
    assert!(
        pids.len() >= 2,
        "concurrent traffic must reach multiple workers"
    );
    term(&child);
    let run = wait_child_output(child.into_child(), Duration::from_secs(15));
    assert!(!run.timed_out && run.output.status.success());
}

#[test]
fn async_real_rails_preserves_binary_upload_cookies_large_body_and_reuse() {
    let _guard = serial_test();
    let fixture = Fixture::new("rails-async");
    let rails = repo_root().join("test/fixtures/rails_app");
    let port = free_port();
    let admin = free_port();
    let mut cmd = async_service_command(
        &fixture,
        &rails.join("config.ru"),
        &format!("127.0.0.1:{port}"),
    );
    cmd.env("OXO_ASYNC_WORKER_APP_ROOT", &rails)
        .env("BUNDLE_GEMFILE", rails.join("Gemfile"))
        .env("RAILS_ENV", "test")
        .env("OXO_WORKER_COUNT", "1")
        .env("OXO_EDGE_MAX_BODY", "1048576")
        .env("OXO_EDGE_ADMIN_BIND", format!("127.0.0.1:{admin}"));
    let child = ServiceChild::spawn(&mut cmd);
    wait_for_tcp(port, Duration::from_secs(60));
    let cookies = get(port, "/cookies");
    assert_eq!(status_of(&cookies), 200);
    assert_eq!(
        String::from_utf8_lossy(&cookies)
            .lines()
            .filter(|line| line.to_ascii_lowercase().starts_with("set-cookie:"))
            .count(),
        2
    );
    let large = get(port, "/fixture/large");
    assert_eq!(status_of(&large), 200);
    assert_eq!(body_of(&large), "a".repeat(262144));
    let bytes: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    let mut body = b"--oxo\r\nContent-Disposition: form-data; name=\"file\"; filename=\"data.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
    body.extend(&bytes);
    body.extend(b"\r\n--oxo--\r\n");
    let mut request = format!("POST /upload HTTP/1.1\r\nHost: app.test\r\nContent-Type: multipart/form-data; boundary=oxo\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    request.extend(body);
    let upload = send_tcp(port, &request);
    assert_eq!(status_of(&upload), 200);
    let uploaded = body_of(&upload);
    assert!(uploaded.contains("\"size\":1024"), "{uploaded}");
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(
        uploaded.contains(&format!("\"hex\":\"{hex}\"")),
        "binary bytes changed"
    );
    for _ in 0..20 {
        assert_eq!(status_of(&get(port, "/hello")), 200);
    }
    let health = body_of(&get(admin, "/pool-health"));
    let reused: u64 = health
        .split("\"pool_reuse_total\":")
        .nth(1)
        .unwrap()
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(reused >= 20, "warm connection was not reused: {health}");
    term(&child);
    let run = wait_child_output(child.into_child(), Duration::from_secs(15));
    assert!(!run.timed_out && run.output.status.success());
}

#![cfg(all(target_os = "linux", feature = "embedded"))]

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static SEQ: AtomicU64 = AtomicU64::new(0);

#[test]
fn embedded_handler_serves_trivial_rack_app() {
    let fixture = Fixture::new();
    let app = fixture.app(
        "embedded.ru",
        r#"
app = lambda do |env|
  [200, { 'content-type' => 'text/plain' }, ["embedded ok #{env['PATH_INFO']}"]]
end
run app
"#,
    );
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let mut server = EmbeddedServer::spawn(&app, &bind);

    let response = server.wait_for_response(
        port,
        b"GET /embedded HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let output = server.stop();

    assert!(
        response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200"),
        "response:\n{response}\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr
    );
    assert!(
        response.contains("embedded ok /embedded"),
        "response:\n{response}\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr
    );
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "oxo-embedded-runtime-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Self { root }
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

struct EmbeddedServer {
    child: Child,
    stdout: Option<thread::JoinHandle<Vec<u8>>>,
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
}

struct EmbeddedOutput {
    stdout: String,
    stderr: String,
}

impl EmbeddedServer {
    fn spawn(app: &Path, bind: &str) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo"));
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("OXO_HANDLER", "embedded")
            .env("OXO_BIND", bind)
            .env("OXO_APP", app)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(libdir) = ruby_libdir() {
            cmd.env("LD_LIBRARY_PATH", libdir);
        }
        let mut child = cmd.spawn().expect("spawn embedded oxo");
        let stdout = child.stdout.take().expect("embedded stdout");
        let stderr = child.stderr.take().expect("embedded stderr");
        Self {
            child,
            stdout: Some(drain_reader(stdout)),
            stderr: Some(drain_reader(stderr)),
        }
    }

    fn wait_for_response(&mut self, port: u16, request: &[u8]) -> String {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut last_response = String::new();
        let mut last_error = None;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("poll embedded server") {
                let output = self.take_output();
                panic!(
                    "embedded server exited before response with {status}\nlast_response:\n{last_response}\nlast_error:\n{}\nstdout:\n{}\nstderr:\n{}",
                    last_error.unwrap_or_default(),
                    output.stdout,
                    output.stderr
                );
            }
            match try_send_tcp(port, request) {
                Ok(response) if response.starts_with("HTTP/1.1 200") => return response,
                Ok(response) if response.starts_with("HTTP/1.0 200") => return response,
                Ok(response) => last_response = response,
                Err(err) => last_error = Some(err.to_string()),
            }
            thread::sleep(Duration::from_millis(25));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let output = self.take_output();
        panic!(
            "embedded server did not return 200 on port {port}\nlast_response:\n{last_response}\nlast_error:\n{}\nstdout:\n{}\nstderr:\n{}",
            last_error.unwrap_or_default(),
            output.stdout,
            output.stderr
        );
    }

    fn stop(mut self) -> EmbeddedOutput {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.take_output()
    }

    fn take_output(&mut self) -> EmbeddedOutput {
        let stdout = self
            .stdout
            .take()
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default();
        let stderr = self
            .stderr
            .take()
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default();
        EmbeddedOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        }
    }
}

impl Drop for EmbeddedServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = self.take_output();
    }
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

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
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

fn try_send_tcp(port: u16, request: &[u8]) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(request)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(String::from_utf8_lossy(&response).into_owned())
}

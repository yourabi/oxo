//! HTTP/2 resource hardening — behavioral tests with a real h2-over-TLS client.
//!
//! Proves the CVE-2023-44487 rapid-reset bound is enforced (the security AC), and that
//! the H1-only keepalive caps do NOT apply to H2 (the honest H1-only non-claim). Requires
//! the TLS feature + Linux + `openssl` on PATH (for cert generation).
#![cfg(all(target_os = "linux", feature = "tls-rustls"))]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

mod support;
use support::{free_port, serial_test};

// ---- edge process + cert helpers (per-suite, like the other integration files) ----

struct EdgeProcess {
    child: Child,
}

impl Drop for EdgeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_tls_h2_edge(
    port: u16,
    socket: &Path,
    cert: &Path,
    key: &Path,
    extra: &[(&str, &str)],
) -> EdgeProcess {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxo-pingora-edge"));
    cmd.env("OXO_EDGE_WORKER_HOP", "http"); // HTTP fake worker
    cmd.env("OXO_EDGE_BIND", format!("127.0.0.1:{port}"))
        .env("OXO_EDGE_WORKER_SOCKET", socket)
        .env("OXO_EDGE_MAX_BODY", "1048576")
        .env("OXO_EDGE_TLS", "1")
        .env("OXO_EDGE_TLS_CERT", cert)
        .env("OXO_EDGE_TLS_KEY", key)
        .env("OXO_EDGE_TLS_H2", "1")
        .env("OXO_EDGE_SERVER_NAME", "app.test")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (name, value) in extra {
        cmd.env(name, value);
    }
    let child = cmd.spawn().expect("spawn TLS/H2 edge");
    EdgeProcess { child }
}

fn generate_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let cert = dir.join("app.test.cert.pem");
    let key = dir.join("app.test.key.pem");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args(["-days", "2", "-nodes", "-subj", "/CN=app.test"])
        .args(["-addext", "subjectAltName=DNS:app.test"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("openssl must be on PATH");
    assert!(status.success(), "openssl cert generation failed");
    (cert, key)
}

fn temp_dir(label: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("oxo-h2-{label}-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn bind_worker(dir: &Path) -> (PathBuf, std::os::unix::net::UnixListener) {
    use std::os::unix::fs::PermissionsExt;
    let socket = dir.join("worker.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    (socket, listener)
}

/// Fake worker answering `count` fresh UDS connections with a fixed 200 (oxo opens a
/// new UDS per request, so N downstream requests => N accepts).
fn spawn_worker(listener: std::os::unix::net::UnixListener, count: usize) {
    use std::io::{Read, Write};
    std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut accepted = 0;
        while accepted < count {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                    accepted += 1;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
    });
}

fn wait_for_tcp(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "edge never bound {port}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ---- TLS/ALPN-h2 client ----

struct NoVerify;
impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

async fn tls_h2_connect(port: u16) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let server_name = ServerName::try_from("app.test").unwrap();
    connector
        .connect(server_name, tcp)
        .await
        .expect("tls handshake")
}

fn get_request() -> http::Request<()> {
    http::Request::builder()
        .method("GET")
        .uri("https://app.test/one")
        .header("host", "app.test")
        .body(())
        .unwrap()
}

// ---- tests ----

#[test]
fn h2_rapid_reset_flood_triggers_goaway() {
    // AC-c1: flooding HEADERS+RST_STREAM past --h2-max-reset-streams must trip the server's
    // pending-accept-reset bound (CVE-2023-44487) and tear the connection down (GOAWAY),
    // rather than accepting unbounded resets.
    let _guard = serial_test();
    let dir = temp_dir("rst-flood");
    let (socket, listener) = bind_worker(&dir);
    spawn_worker(listener, 0); // no request is expected to complete
    let (cert, key) = generate_cert(&dir);
    let port = free_port();
    let _edge = spawn_tls_h2_edge(
        port,
        &socket,
        &cert,
        &key,
        &[("OXO_EDGE_H2_MAX_RESET_STREAMS", "5")],
    );
    wait_for_tcp(port);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let torn_down = rt.block_on(async {
        let io = tls_h2_connect(port).await;
        let (mut send, conn) = h2::client::handshake(io).await.expect("h2 handshake");
        // Drive the connection on a task; it resolves (with an error) on GOAWAY.
        let conn_task = tokio::spawn(conn);

        // Flood: open a stream then immediately drop it (RST_STREAM) many times, well past
        // the configured limit of 5.
        for _ in 0..200 {
            // `ready()` consumes and returns the SendRequest; rebind it. An error means
            // the server already tore the connection down.
            send = match send.ready().await {
                Ok(s) => s,
                Err(_) => break,
            };
            match send.send_request(get_request(), true) {
                Ok((resp, _send_stream)) => {
                    // Drop the response future immediately => the stream is reset.
                    drop(resp);
                }
                Err(_) => break,
            }
        }

        // The connection driver must resolve with an error (GOAWAY / connection reset)
        // within a short window — proof the flood was bounded, not absorbed.
        matches!(
            tokio::time::timeout(Duration::from_secs(5), conn_task).await,
            Ok(Ok(Err(_)))
        )
    });
    assert!(
        torn_down,
        "rapid-reset flood must trigger a GOAWAY / connection teardown"
    );
}

#[test]
fn h2_connection_ignores_h1_keepalive_and_request_caps() {
    // AC-c3 (honest H1-only non-claim): the keepalive idle timeout and
    // --max-requests-per-connection are H1-only. An H2 connection serves MORE than the
    // configured H1 request cap and survives past the H1 idle window, because H2
    // multiplexes natively and set_keepalive/keepalive_request_limit are H2 no-ops.
    let _guard = serial_test();
    let dir = temp_dir("h2-h1only");
    let (socket, listener) = bind_worker(&dir);
    spawn_worker(listener, 4); // four downstream requests => four worker accepts
    let (cert, key) = generate_cert(&dir);
    let port = free_port();
    let _edge = spawn_tls_h2_edge(
        port,
        &socket,
        &cert,
        &key,
        &[
            ("OXO_EDGE_KEEPALIVE", "1"),
            ("OXO_EDGE_MAX_REQUESTS_PER_CONNECTION", "2"),
            ("OXO_EDGE_KEEPALIVE_IDLE_TIMEOUT_MS", "1000"),
        ],
    );
    wait_for_tcp(port);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let served = rt.block_on(async {
        let io = tls_h2_connect(port).await;
        let (mut send, conn) = h2::client::handshake(io).await.expect("h2 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut ok = 0;
        // Four sequential requests on ONE h2 connection — well past the H1 cap of 2, with
        // a pause exceeding the 1s H1 idle window between the 2nd and 3rd.
        for i in 0..4 {
            if i == 2 {
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
            send = send.ready().await.expect("stream ready");
            let (resp, _) = send
                .send_request(get_request(), true)
                .expect("send request");
            if let Ok(response) = resp.await {
                if response.status() == 200 {
                    ok += 1;
                }
            }
        }
        ok
    });
    assert_eq!(
        served, 4,
        "an H2 connection must serve more than the H1 request cap and survive the H1 idle window"
    );
}

//! Hyper HTTP/1.1 edge using the RackHandler interface.
//!
//! Normalize requests into RackRequest and serialize RackResponse values. Enforce
//! body, connection and header limits; remove underscore-bearing header names;
//! and reconstruct upstream framing rather than forwarding client framing.
//!
//! Handler and body-read deadlines are separate from the optional absolute
//! connection deadline covering response writes. TLS, HTTP/2 and public-exposure
//! policy belong to the separate oxo-pingora-edge implementation.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use oxo_core::{
    normalize_header_name, Config, HandlerError, RackHandler, RackRequest, RackResponse,
};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

pub mod supervised;
pub use supervised::SupervisedRubyHandler;

/// Bind and serve until an unrecoverable accept error. `handler` is shared across
/// per-connection tasks; on a multi-threaded runtime the handler future must be
/// `Send` (see [`oxo_core::RackHandler`]).
pub async fn serve<H>(config: Arc<Config>, handler: Arc<H>) -> std::io::Result<()>
where
    H: RackHandler + 'static,
{
    let listener = TcpListener::bind(config.bind).await?;
    serve_listener(listener, config, handler).await
}

/// Serve on an already-bound listener. Exposed so tests can bind `127.0.0.1:0`
/// for an ephemeral port in the Hyper path.
pub async fn serve_listener<H>(
    listener: TcpListener,
    config: Arc<Config>,
    handler: Arc<H>,
) -> std::io::Result<()>
where
    H: RackHandler + 'static,
{
    let local = listener.local_addr()?;
    eprintln!(
        "oxo: listening on http://{local} (handler={:?}, worker={:?}, env={:?})",
        config.handler, config.worker, config.env
    );
    log_hardening(&config, local);

    // One configured Builder, cloned per connection (it is `Clone`; `serve_connection`
    // borrows `&self`). The timer is always installed — `header_read_timeout` panics in
    // `serve_connection` without one.
    let builder = build_http1(&config);
    // `None` ⇒ unlimited. The permit is acquired BEFORE `accept` so the listener exerts
    // backpressure (stops accepting) at the cap rather than spawning unboundedly.
    let limiter =
        (config.max_connections > 0).then(|| Arc::new(Semaphore::new(config.max_connections)));
    let inflight = Arc::new(AtomicUsize::new(0));
    let mut accept_errors: u64 = 0;

    loop {
        let permit = match &limiter {
            Some(sem) => {
                if sem.available_permits() == 0 {
                    // Rate-limited: this only logs at the moment the cap is hit.
                    eprintln!(
                        "oxo: connection cap ({}) reached; pausing accept (in-flight={})",
                        config.max_connections,
                        inflight.load(Ordering::Relaxed)
                    );
                }
                // Never closed today; a bare `?` would silently kill the loop
                // if later shutdown code closes it, so assert the invariant.
                Some(
                    sem.clone()
                        .acquire_owned()
                        .await
                        .expect("connection semaphore is never closed"),
                )
            }
            None => None,
        };

        let (stream, _peer) = match listener.accept().await {
            Ok(pair) => {
                accept_errors = 0;
                pair
            }
            Err(e) if is_transient_accept_error(&e) => {
                // A transient error (EMFILE/ECONNABORTED/EINTR/…) must NOT kill the
                // listener — exactly the load exists to survive. Log (rate-limited),
                // back off briefly, and keep serving. The reserved permit drops here.
                accept_errors = accept_errors.saturating_add(1);
                if accept_errors == 1 || accept_errors.is_multiple_of(64) {
                    eprintln!("oxo: transient accept error (#{accept_errors}): {e}");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
            Err(e) => return Err(e),
        };

        let handler = handler.clone();
        let config = config.clone();
        let builder = builder.clone();
        let inflight = inflight.clone();
        tokio::spawn(async move {
            let _permit = permit; // held for the whole connection lifetime
            let _gauge = InflightGuard::new(inflight);
            let max_conn_secs = config.max_connection_secs;
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let handler = handler.clone();
                let config = config.clone();
                async move {
                    Ok::<Response<Full<Bytes>>, std::convert::Infallible>(
                        handle_one_timed(req, handler, config, local).await,
                    )
                }
            });
            let conn = builder.serve_connection(io, service);
            // The absolute connection-lifetime deadline is the only layer that bounds the
            // response-WRITE phase (write-slowloris) and total connection age; off ⇒ 0.
            let result = if max_conn_secs > 0 {
                match tokio::time::timeout(Duration::from_secs(max_conn_secs), conn).await {
                    Ok(r) => r,
                    Err(_) => {
                        eprintln!("oxo: connection exceeded max_connection_secs; closing");
                        Ok(())
                    }
                }
            } else {
                conn.await
            };
            if let Err(e) = result {
                eprintln!("oxo: connection error: {e}");
            }
        });
    }
}

/// Build the per-connection HTTP/1.1 server config from the hardening knobs. A timer is
/// installed unconditionally because `serve_connection` panics if `header_read_timeout` is
/// configured without one.
fn build_http1(config: &Config) -> http1::Builder {
    let mut b = http1::Builder::new();
    b.timer(TokioTimer::new());
    // Explicitly set either way: hyper's own default is 30s, so `0` must pass `None` to
    // truly disable it rather than silently inherit 30s.
    if config.header_read_timeout_secs > 0 {
        b.header_read_timeout(Some(Duration::from_secs(config.header_read_timeout_secs)));
    } else {
        b.header_read_timeout(None);
    }
    if config.max_header_count > 0 {
        b.max_headers(config.max_header_count);
    }
    if config.max_read_buf_bytes > 0 {
        // `Config` guarantees this is >= MIN_READ_BUF_BYTES, so this can't panic.
        b.max_buf_size(config.max_read_buf_bytes);
    }
    b.keep_alive(true);
    b
}

/// Increments an in-flight-connection gauge for its lifetime; decrements on drop (so it is
/// correct even if the connection task panics). The gauge backs the cap-saturation logs and
/// a future readiness endpoint.
struct InflightGuard(Arc<AtomicUsize>);

impl InflightGuard {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        InflightGuard(counter)
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Transient `accept` errors that must not tear down the listener. EMFILE/ENFILE have no
/// stable `ErrorKind`, so they are matched by raw OS code on Unix; on Windows the common
/// transients map to `ConnectionAborted`/`ConnectionReset`/`Interrupted`/`WouldBlock`.
fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionAborted | ConnectionReset | Interrupted | WouldBlock
    ) || matches!(e.raw_os_error(), Some(24) | Some(23)) // EMFILE / ENFILE (Unix)
}

/// One startup line naming the effective hardening config, a WARN naming any *disabled*
/// knob (so "turned off" is observable, not silent), and the unencrypted-public-bind WARN.
fn log_hardening(config: &Config, local: SocketAddr) {
    let conns = if config.max_connections == 0 {
        "unlimited".to_string()
    } else {
        config.max_connections.to_string()
    };
    eprintln!(
        "oxo: hardening: max_connections={conns}, header_read_timeout={}s, \
         request_timeout={}s, max_connection_secs={}, max_headers={}, max_read_buf_bytes={}, \
         max_body_bytes={}",
        config.header_read_timeout_secs,
        config.request_timeout_secs,
        config.max_connection_secs,
        config.max_header_count,
        config.max_read_buf_bytes,
        config.max_body_bytes,
    );
    let mut disabled = Vec::new();
    if config.header_read_timeout_secs == 0 {
        disabled.push("header_read_timeout");
    }
    if config.request_timeout_secs == 0 {
        disabled.push("request_timeout");
    }
    if config.max_connection_secs == 0 {
        disabled.push("max_connection_secs (no response-write/connection-age bound)");
    }
    if config.max_connections == 0 {
        disabled.push("max_connections");
    }
    if !disabled.is_empty() {
        eprintln!(
            "oxo: WARNING hardening knobs disabled: {}",
            disabled.join(", ")
        );
    }
    if config.is_public_bind() {
        eprintln!(
            "oxo: WARNING bound to non-loopback {local} with NO TLS (plaintext). Timeouts and \
             connection/slowloris caps are active, but traffic is unencrypted — run behind a \
             trusted TLS-terminating boundary, and set OXO_MAX_CONNECTION_SECS for internet \
             exposure. See docs/THREAT_MODEL.md."
        );
    }
}

/// Wrap [`handle_one`] in the per-request timeout. This bounds the handler **and** the
/// request-body read (which happens inside `handle_one` → `to_rack_request`), but NOT the
/// response-write phase (hyper writes after the service future resolves — see
/// `max_connection_secs`). It only *delivers* a 504 when the worker/handler is slow with
/// the body already read; a slow body is cancelled mid-read, so hyper tears the connection
/// down with `Connection: close` rather than sending a clean status.
async fn handle_one_timed<H: RackHandler>(
    req: Request<Incoming>,
    handler: Arc<H>,
    config: Arc<Config>,
    local: SocketAddr,
) -> Response<Full<Bytes>> {
    let secs = config.request_timeout_secs;
    let fut = handle_one(req, handler, config, local);
    if secs == 0 {
        return fut.await;
    }
    match tokio::time::timeout(Duration::from_secs(secs), fut).await {
        Ok(resp) => resp,
        Err(_) => {
            eprintln!("oxo: request exceeded {secs}s timeout (worker too slow) → 504");
            to_hyper(RackResponse::gateway_timeout())
        }
    }
}

async fn handle_one<H: RackHandler>(
    req: Request<Incoming>,
    handler: Arc<H>,
    config: Arc<Config>,
    local: SocketAddr,
) -> Response<Full<Bytes>> {
    let rack_req = match to_rack_request(req, config.max_body_bytes, local).await {
        Ok(r) => r,
        Err(resp) => return to_hyper(resp),
    };
    match handler.handle(rack_req).await {
        Ok(resp) => to_hyper(resp),
        Err(HandlerError::BodyTooLarge) => to_hyper(RackResponse::payload_too_large()),
        // Worker (re)starting → 503 retryable; unreachable → 502 (distinct from app 500).
        Err(HandlerError::WorkerUnavailable) => to_hyper(RackResponse::service_unavailable()),
        Err(HandlerError::WorkerUnreachable(e)) => {
            eprintln!("oxo: worker unreachable: {e}");
            to_hyper(RackResponse::bad_gateway())
        }
        Err(e) => {
            eprintln!("oxo: handler error: {e}");
            to_hyper(RackResponse::internal_error())
        }
    }
}

/// Parse + normalize a hyper request into a [`RackRequest`], enforcing the body cap.
async fn to_rack_request(
    req: Request<Incoming>,
    max_body: usize,
    local: SocketAddr,
) -> Result<RackRequest, RackResponse> {
    let (parts, body) = req.into_parts();
    let method = parts.method.as_str().to_string();
    let path = parts.uri.path().to_string();
    let query_string = parts.uri.query().unwrap_or("").to_string();

    let mut headers = Vec::new();
    let mut host_header: Option<String> = None;
    for (name, value) in parts.headers.iter() {
        if let Some(norm) = normalize_header_name(name.as_str()) {
            if let Ok(v) = value.to_str() {
                if norm == "host" {
                    host_header = Some(v.to_string());
                }
                headers.push((norm, v.to_string()));
            }
        }
    }

    let collected = match Limited::new(body, max_body).collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return Err(RackResponse::payload_too_large()),
    };

    let (server_name, server_port) = match host_header {
        Some(h) => match h.rsplit_once(':') {
            Some((name, port)) => (name.to_string(), port.parse().unwrap_or(local.port())),
            None => (h, local.port()),
        },
        None => (local.ip().to_string(), local.port()),
    };

    Ok(RackRequest {
        method,
        path,
        query_string,
        server_name,
        server_port,
        url_scheme: "http".to_string(),
        headers,
        body: collected,
    })
}

fn to_hyper(resp: RackResponse) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(resp.status);
    for (k, v) in resp.headers {
        // hyper sets framing headers itself from the Full body; never duplicate them.
        if k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        builder = builder.header(k, v);
    }
    builder
        .body(Full::new(resp.body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"Internal Server Error"))))
}

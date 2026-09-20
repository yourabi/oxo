//! Ruby-enabled in-process implementation. Initialize Ruby on the main thread;
//! run the edge runtime on a separate thread and exchange owned request data.
//! The runtime test targets Linux; native Windows Ruby runtime support is unavailable.

use std::process::ExitCode;
use std::sync::Arc;
use std::thread;

use bytes::Bytes;
use magnus::value::ReprValue;
use magnus::{RArray, RModule, RString, Ruby, Value};
use oxo_core::{Config, HandlerError, RackHandler, RackRequest, RackResponse};
use tokio::sync::{mpsc, oneshot};

/// A request handed to the Ruby thread together with its one-shot reply channel.
struct Job {
    req: RackRequest,
    reply: oneshot::Sender<RackResponse>,
}

/// The edge-facing handle. Holds only a channel `Sender` (which is `Send`) — never a
/// Ruby value — so it can live on the tokio runtime threads.
#[derive(Clone)]
pub struct EmbeddedRubyHandler {
    tx: mpsc::Sender<Job>,
}

impl RackHandler for EmbeddedRubyHandler {
    async fn handle(&self, req: RackRequest) -> Result<RackResponse, HandlerError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Job { req, reply })
            .await
            .map_err(|_| HandlerError::RubyError("ruby thread is gone".to_string()))?;
        // The Ruby thread replies on every path (a drop-guard turns any failure into a
        // 500), so a canceled receive means the thread itself died.
        rx.await
            .map_err(|_| HandlerError::RubyError("ruby thread dropped the reply".to_string()))
    }
}

/// Ruby-side helpers. All env construction and body materialization happen here, in
/// Ruby, so the Rust↔Ruby surface stays tiny: pass owned primitives in, get a
/// `[status, flat_headers, body_bytes]` array out — never a live Ruby object across
/// the channel.
const HELPER: &str = r#"
require 'rack'
require 'stringio'

module Oxo
  module_function

  def load(path)
    loaded = Rack::Builder.parse_file(path)   # Rack 3 returns the app; Rack 2 [app, opts]
    @app = loaded.is_a?(Array) ? loaded.first : loaded
    true
  end

  def handle(method, path, query, header_flat, body)
    input = StringIO.new(body.dup)
    input.set_encoding(Encoding::BINARY)       # rack.input must be ASCII-8BIT, rewindable
    env = {
      'REQUEST_METHOD' => method, 'SCRIPT_NAME' => '', 'PATH_INFO' => path,
      'QUERY_STRING' => query, 'SERVER_NAME' => '', 'SERVER_PORT' => '',
      'SERVER_PROTOCOL' => 'HTTP/1.1', 'rack.url_scheme' => 'http',
      'rack.input' => input, 'rack.errors' => $stderr,
      'rack.multithread' => false, 'rack.multiprocess' => false, 'rack.run_once' => false
    }
    i = 0
    while i < header_flat.length
      k = header_flat[i]; v = header_flat[i + 1]; i += 2
      if k == 'content-length' then env['CONTENT_LENGTH'] = v
      elsif k == 'content-type' then env['CONTENT_TYPE'] = v
      else env['HTTP_' + k.upcase.tr('-', '_')] = v end
    end

    status, headers, rbody = @app.call(env)

    buf = +''.b
    if rbody.respond_to?(:call) && !rbody.respond_to?(:each)
      collector = +''.b
      writer = Object.new
      writer.define_singleton_method(:write) { |s| collector << s.to_s.b; s.to_s.bytesize }
      writer.define_singleton_method(:<<) { |s| collector << s.to_s.b; writer }
      writer.define_singleton_method(:flush) { writer }
      writer.define_singleton_method(:close) {}
      rbody.call(writer)
      buf << collector
    else
      rbody.each { |part| buf << part.to_s.b }
    end
    rbody.close if rbody.respond_to?(:close)

    flat = []
    headers.each { |k, v| Array(v).each { |vv| flat << k.to_s; flat << vv.to_s } }
    [status.to_i, flat, buf]
  end
end
"#;

fn emap(e: magnus::Error) -> HandlerError {
    HandlerError::RubyError(e.to_string())
}

/// Runs on the **main thread** (top of stack). Inits Ruby, loads the app, moves the
/// tokio runtime + edge onto a separate thread, then services the Ruby request loop
/// here forever. Returns only if the edge thread ends or the channel closes.
pub fn run_embedded_server(config: Config) -> ExitCode {
    // Init the VM on the main thread, above any Ruby-calling code (the RUBY_INIT_STACK
    // contract). `Cleanup` must outlive all Ruby use, so it lives for this fn.
    let _cleanup = unsafe { magnus::embed::init() };
    let ruby = match Ruby::get() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("oxo: Ruby init failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = ruby.eval::<Value>(HELPER) {
        eprintln!("oxo: failed to define Ruby helpers: {e}");
        return ExitCode::FAILURE;
    }
    let app_path = config.app.to_string_lossy().to_string();
    match ruby.eval::<RModule>("Oxo") {
        Ok(m) => {
            if let Err(e) = m.funcall::<_, _, bool>("load", (app_path.as_str(),)) {
                eprintln!("oxo: failed to load rack app {app_path}: {e}");
                return ExitCode::FAILURE;
            }
        }
        Err(e) => {
            eprintln!("oxo: Ruby helper module missing: {e}");
            return ExitCode::FAILURE;
        }
    }

    let (tx, mut rx) = mpsc::channel::<Job>(1024);
    let handler = EmbeddedRubyHandler { tx };
    let edge_config = config.clone();

    // The runtime + edge run on their own thread; the Ruby VM keeps the main thread.
    let edge_thread = thread::Builder::new()
        .name("oxo-edge".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("oxo: building runtime: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                if let Err(e) = oxo_edge::serve(Arc::new(edge_config), Arc::new(handler)).await {
                    eprintln!("oxo: serve error: {e}");
                }
            });
        });
    if let Err(e) = edge_thread {
        eprintln!("oxo: spawning edge thread: {e}");
        return ExitCode::FAILURE;
    }

    // The Ruby request loop, on the main thread, holding the GVL for each call.
    while let Some(job) = rx.blocking_recv() {
        let guard = ReplyGuard(Some(job.reply));
        let resp = call_ruby(&ruby, &job.req).unwrap_or_else(|e| {
            eprintln!("oxo: embedded handler error: {e}");
            RackResponse::internal_error()
        });
        guard.fulfill(resp);
    }
    ExitCode::SUCCESS
}

/// Guarantees the edge always receives a reply for a job, even if `call_ruby` panics:
/// on drop without an explicit reply, it sends a 500.
struct ReplyGuard(Option<oneshot::Sender<RackResponse>>);

impl ReplyGuard {
    fn fulfill(mut self, resp: RackResponse) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(resp);
        }
    }
}

impl Drop for ReplyGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(RackResponse::internal_error());
        }
    }
}

/// One request → Ruby and back. Ruby exceptions surface as `magnus::Error` (converted
/// to a `HandlerError`, ultimately a 500) — they never unwind across the FFI boundary.
/// The response is fully materialized into owned Rust bytes here; no Ruby value
/// escapes this function.
fn call_ruby(ruby: &Ruby, req: &RackRequest) -> Result<RackResponse, HandlerError> {
    let flat = ruby.ary_new();
    for (k, v) in &req.headers {
        flat.push(k.as_str()).map_err(emap)?;
        flat.push(v.as_str()).map_err(emap)?;
    }
    let body = ruby.str_from_slice(&req.body);

    let module = ruby.eval::<RModule>("Oxo").map_err(emap)?;
    let result: RArray = module
        .funcall(
            "handle",
            (
                req.method.as_str(),
                req.path.as_str(),
                req.query_string.as_str(),
                flat,
                body,
            ),
        )
        .map_err(emap)?;

    let status: i64 = result.entry(0).map_err(emap)?;
    let flat_headers: RArray = result.entry(1).map_err(emap)?;
    let body_str: RString = result.entry(2).map_err(emap)?;
    // Copy out immediately while we hold the GVL; the slice is only valid until the
    // next allocation/GC.
    let body_bytes = unsafe { body_str.as_slice() }.to_vec();

    let mut headers = Vec::new();
    let n = flat_headers.len();
    let mut i = 0;
    while i + 1 < n {
        let k: String = flat_headers.entry(i as isize).map_err(emap)?;
        let v: String = flat_headers.entry((i + 1) as isize).map_err(emap)?;
        headers.push((k.to_ascii_lowercase(), v));
        i += 2;
    }

    Ok(RackResponse {
        status: status as u16,
        headers,
        body: Bytes::from(body_bytes),
    })
}

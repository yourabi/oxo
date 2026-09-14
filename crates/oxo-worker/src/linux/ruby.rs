use super::*;

// the Oxo helper module handle, resolved ONCE (both request paths previously
// paid a `const_get("Oxo")` funcall per request). Lazy registers the value with
// the GC; HELPER defines the module before init forces resolution at boot, so the
// expect is a boot-order invariant, not a runtime branch.
static OXO_MODULE: magnus::value::Lazy<RModule> = magnus::value::Lazy::new(|ruby| {
    ruby.eval::<RModule>("Oxo")
        .expect("Oxo helper module is defined by HELPER before first use")
});

pub(super) fn init_vm_and_load_app(ruby: &Ruby, config: &Config) -> Result<(), String> {
    if !config.app.is_file() {
        return Err(format!("rack app not found at {}", config.app.display()));
    }
    ruby.eval::<Value>(HELPER)
        .map_err(|e| format!("defining Ruby helpers: {e}"))?;
    let app_path = config.app.to_string_lossy().to_string();
    let module = ruby.get_inner(&OXO_MODULE);
    module
        .funcall::<_, _, bool>("load", (app_path.as_str(), config.rack_lint))
        .map_err(|e| format!("loading rack app {app_path}: {e}"))?;
    Ok(())
}

pub(super) fn start_ruby_threads(
    ruby: &Ruby,
    queue: Arc<JobQueue>,
    opts: Arc<WorkerOptions>,
    count: usize,
) -> Result<Vec<magnus::Thread>, String> {
    // These are Ruby VM threads, not Rust threads that may carry Ruby VALUEs
    // across a Rust queue. If one dies unexpectedly, the process exits rather
    // than silently shrinking Rack concurrency.
    let mut threads = Vec::with_capacity(count);
    for index in 0..count {
        let queue = queue.clone();
        let opts = opts.clone();
        let thread = ruby.thread_create_from_fn(move |ruby| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ruby_worker_loop(ruby, queue, opts)
            }));
            if result.is_err() {
                eprintln!("oxo-worker: Ruby worker thread {index} panicked; exiting");
                std::process::exit(70);
            }
        });
        threads.push(thread);
    }
    Ok(threads)
}

fn ruby_worker_loop(ruby: &Ruby, queue: Arc<JobQueue>, opts: Arc<WorkerOptions>) {
    while let Some(job) = queue.pop_without_gvl() {
        match job.reply {
            JobReply::Buffered(reply) => {
                let response = match call_ruby(ruby, &job.request, &opts) {
                    Ok(resp) => resp,
                    Err(e) => {
                        eprintln!("oxo-worker: rack error: {e}");
                        WorkerResponse::text(500, b"Internal Server Error".to_vec())
                    }
                };
                let _ = reply.send(response);
            }
            JobReply::Streaming(reply) => {
                if let Err(e) = call_ruby_streaming(ruby, &job.request, &opts, &reply) {
                    eprintln!("oxo-worker: streaming rack error: {e}");
                    send_stream_error(&reply, 500, b"Internal Server Error".to_vec());
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct WorkerOptions {
    pub(super) multithread: bool,
    pub(super) multiprocess: bool,
}

pub(super) fn send_stream_error(reply: &mpsc::SyncSender<WorkerEvent>, status: u16, body: Vec<u8>) {
    let _ = reply.send(WorkerEvent::Start(WorkerResponseHead::text(status)));
    let _ = reply.send(WorkerEvent::Chunk(body));
    let _ = reply.send(WorkerEvent::End);
}

pub(super) fn send_stream_event(reply: &mpsc::SyncSender<WorkerEvent>, event: WorkerEvent) -> bool {
    let reply = reply.clone();
    without_gvl(move || reply.send(event).is_ok())
}

fn call_ruby(
    ruby: &Ruby,
    req: &WorkerRequest,
    opts: &WorkerOptions,
) -> Result<WorkerResponse, magnus::Error> {
    let flat = ruby.ary_new();
    for (k, v) in &req.headers {
        flat.push(k.as_str())?;
        flat.push(v.as_str())?;
    }
    let body = ruby.str_from_slice(&req.body);
    let module = ruby.get_inner(&OXO_MODULE);
    let result: RArray = module.funcall(
        "handle",
        (
            req.method.as_str(),
            req.path.as_str(),
            req.query.as_str(),
            req.server_name.as_str(),
            req.server_port.to_string().as_str(),
            req.url_scheme.as_str(),
            req.remote_addr.as_str(),
            opts.multithread,
            opts.multiprocess,
            flat,
            body,
        ),
    )?;

    let status: i64 = result.entry(0)?;
    let flat_headers: RArray = result.entry(1)?;
    let body_str: RString = result.entry(2)?;
    let body = unsafe { body_str.as_slice() }.to_vec();
    let mut headers = Vec::new();
    let len = flat_headers.len();
    let mut i = 0;
    while i + 1 < len {
        let k: String = flat_headers.entry(i as isize)?;
        let v: String = flat_headers.entry((i + 1) as isize)?;
        headers.push((k, v));
        i += 2;
    }
    Ok(WorkerResponse {
        status: status as u16,
        headers,
        body,
    })
}

fn call_ruby_streaming(
    ruby: &Ruby,
    req: &WorkerRequest,
    opts: &WorkerOptions,
    reply: &mpsc::SyncSender<WorkerEvent>,
) -> Result<(), String> {
    let flat = ruby.ary_new();
    for (k, v) in &req.headers {
        flat.push(k.as_str()).map_err(|e| e.to_string())?;
        flat.push(v.as_str()).map_err(|e| e.to_string())?;
    }
    let body = ruby.str_from_slice(&req.body);
    let module = ruby.get_inner(&OXO_MODULE);
    let result: RArray = module
        .funcall(
            "handle_stream",
            (
                req.method.as_str(),
                req.path.as_str(),
                req.query.as_str(),
                req.server_name.as_str(),
                req.server_port.to_string().as_str(),
                req.url_scheme.as_str(),
                req.remote_addr.as_str(),
                opts.multithread,
                opts.multiprocess,
                flat,
                body,
            ),
        )
        .map_err(|e| e.to_string())?;

    let status: i64 = result.entry(0).map_err(|e| e.to_string())?;
    let flat_headers: RArray = result.entry(1).map_err(|e| e.to_string())?;
    let queue: Value = result.entry(2).map_err(|e| e.to_string())?;
    let mut headers = Vec::new();
    let len = flat_headers.len();
    let mut i = 0;
    while i + 1 < len {
        let k: String = flat_headers.entry(i as isize).map_err(|e| e.to_string())?;
        let v: String = flat_headers
            .entry((i + 1) as isize)
            .map_err(|e| e.to_string())?;
        headers.push((k, v));
        i += 2;
    }
    if !send_stream_event(
        reply,
        WorkerEvent::Start(WorkerResponseHead {
            status: status as u16,
            headers,
        }),
    ) {
        close_stream_queue(queue);
        return Ok(());
    }

    loop {
        let chunk: Value = queue.funcall("pop", ()).map_err(|e| e.to_string())?;
        if chunk.is_nil() {
            break;
        }
        let chunk = RString::try_convert(chunk).map_err(|e| e.to_string())?;
        let bytes = unsafe { chunk.as_slice() }.to_vec();
        if !send_stream_event(reply, WorkerEvent::Chunk(bytes)) {
            // The consumer (accept thread) has gone: the downstream write failed or the
            // event receiver was dropped. Close the Ruby queue so the producer thread's
            // blocked `<<` raises ClosedQueueError and it stops, instead of running (and
            // buffering) forever. (D7/D8)
            close_stream_queue(queue);
            return Ok(());
        }
    }
    let _ = send_stream_event(reply, WorkerEvent::End);
    Ok(())
}

/// Close the Ruby streaming queue so a producer thread blocked on `<<` unblocks with
/// ClosedQueueError. Runs under the GVL (the caller holds it) and ignores any error —
/// there is nothing to recover if the already-abandoned stream cannot be closed.
fn close_stream_queue(queue: Value) {
    let _ = queue.funcall::<_, _, Value>("close", ());
}
const HELPER: &str = r#"
require 'rack'
require 'stringio'
require 'thread'

module Oxo
  module_function

  # Max streaming chunks buffered ahead of the consumer before the producer blocks.
  # Matches the Rust-side sync_channel depth so backpressure is symmetric end to end.
  STREAM_QUEUE_LIMIT = 8

  # bounded, pre-seeded frozen key table for the per-header CGI key build —
  # 'HTTP_' + k.upcase.tr('-', '_') costs three string allocations per header on
  # every request. Header names are attacker-influenced, so the memo is a FIXED
  # table (puma's C parser caches a fixed common-header set for the same
  # memory-DoS reason); names outside the table fall back to the allocating path.
  HTTP_KEY_TABLE = %w[
    accept accept-encoding accept-language accept-charset authorization
    cache-control cookie host if-modified-since if-none-match if-match
    if-unmodified-since origin pragma range referer user-agent via date
    upgrade-insecure-requests x-request-id x-requested-with
    sec-fetch-dest sec-fetch-mode sec-fetch-site sec-fetch-user
  ].to_h { |k| [k.freeze, ('HTTP_' + k.upcase.tr('-', '_')).freeze] }.freeze

  def load(path, lint)
    loaded = Rack::Builder.parse_file(path)
    app = loaded.is_a?(Array) ? loaded.first : loaded
    @app = lint ? Rack::Lint.new(app) : app
    true
  end

  def build_env(method, path, query, server_name, server_port, scheme, remote_addr, multithread, multiprocess, header_flat, body)
    input = StringIO.new(body.dup)
    input.set_encoding(Encoding::BINARY)
    # Keep this env Rack::Lint-clean: S1 does not expose rack.hijack keys. The
    # streaming substrate owns body iteration internally rather than handing the
    # raw socket to Rack.
    env = {
      'REQUEST_METHOD' => method,
      'SCRIPT_NAME' => '',
      'PATH_INFO' => path,
      'QUERY_STRING' => query,
      'SERVER_NAME' => server_name,
      'SERVER_PORT' => server_port,
      'SERVER_PROTOCOL' => 'HTTP/1.1',
      'REMOTE_ADDR' => remote_addr,
      'rack.url_scheme' => scheme,
      'rack.input' => input,
      'rack.errors' => $stderr,
      'rack.multithread' => multithread,
      'rack.multiprocess' => multiprocess,
      'rack.run_once' => false
    }

    i = 0
    while i < header_flat.length
      k = header_flat[i]
      v = header_flat[i + 1]
      i += 2
      if k == 'content-length'
        env['CONTENT_LENGTH'] = v
      elsif k == 'content-type'
        env['CONTENT_TYPE'] = v
      else
        env[HTTP_KEY_TABLE[k] || ('HTTP_' + k.upcase.tr('-', '_'))] = v
      end
    end
    env
  end

  def flatten_headers(headers)
    # Rack represents repeated headers two ways: a Rack-3 Array of values, OR a single
    # value with the parts joined by "\n" (Rack 2, still emitted by e.g. multi-cookie apps).
    # Array(v) handles the first; we must also split on "\n" so a "\n"-joined Set-Cookie
    # becomes multiple wire lines instead of one value with an embedded LF (which the Rust
    # response sanitizer would CTL-reject and drop wholesale, losing every cookie).
    flat = []
    headers.each do |k, v|
      key = k.to_s
      Array(v).each do |vv|
        segs = vv.to_s.split("\n")
        segs << "" if segs.empty? # a legitimately empty value stays one (empty) line
        segs.each do |seg|
          next if seg.empty? && segs.length > 1 # drop spurious empties from "a\n\nb"/"a\n"
          flat << key
          flat << seg
        end
      end
    end
    flat
  end

  def each_body_part(rbody)
    begin
      if rbody.respond_to?(:call) && !rbody.respond_to?(:each)
        writer = Object.new
        writer.define_singleton_method(:write) do |s|
          str = s.to_s.b
          yield str
          str.bytesize
        end
        writer.define_singleton_method(:<<) { |s| yield s.to_s.b; writer }
        writer.define_singleton_method(:flush) { writer }
        writer.define_singleton_method(:close) {}
        rbody.call(writer)
      else
        rbody.each { |part| yield part.to_s.b }
      end
    ensure
      rbody.close if rbody.respond_to?(:close)
    end
  end

  def handle(method, path, query, server_name, server_port, scheme, remote_addr, multithread, multiprocess, header_flat, body)
    env = build_env(method, path, query, server_name, server_port, scheme, remote_addr, multithread, multiprocess, header_flat, body)
    status, headers, rbody = @app.call(env)
    buf = +''.b
    each_body_part(rbody) { |part| buf << part }
    [status.to_i, flatten_headers(headers), buf]
  end

  def handle_stream(method, path, query, server_name, server_port, scheme, remote_addr, multithread, multiprocess, header_flat, body)
    env = build_env(method, path, query, server_name, server_port, scheme, remote_addr, multithread, multiprocess, header_flat, body)
    status, headers, rbody = @app.call(env)
    # SizedQueue (not Queue) bounds producer memory: the producer blocks on `<<` once the
    # consumer falls STREAM_QUEUE_LIMIT chunks behind, instead of buffering the whole body
    # in the Ruby heap. When the consumer goes away (client disconnect / downstream write
    # failure) the Rust side calls `queue.close`, which makes that blocked `<<` raise
    # ClosedQueueError so the producer thread stops instead of leaking forever.
    queue = SizedQueue.new(STREAM_QUEUE_LIMIT)
    Thread.new do
      begin
        each_body_part(rbody) { |part| queue << part }
      rescue ClosedQueueError
        # Consumer went away and closed the queue; stop producing quietly.
      rescue => e
        warn "oxo-worker: streaming body error: #{e.class}: #{e.message}"
      ensure
        begin
          queue << nil
        rescue ClosedQueueError
          # Queue already closed by the consumer side; nothing to signal.
        end
      end
    end
    [status.to_i, flatten_headers(headers), queue]
  end
end
"#;

type NoGvlFunc = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type UbfFunc = unsafe extern "C" fn(*mut c_void);

extern "C" {
    fn rb_thread_call_without_gvl(
        func: NoGvlFunc,
        data1: *mut c_void,
        ubf: Option<UbfFunc>,
        data2: *mut c_void,
    ) -> *mut c_void;
}

pub(super) fn without_gvl<F, R>(func: F) -> R
where
    F: FnOnce() -> R,
{
    struct State<F, R> {
        func: Option<F>,
        result: Option<R>,
    }

    unsafe extern "C" fn trampoline<F, R>(ptr: *mut c_void) -> *mut c_void
    where
        F: FnOnce() -> R,
    {
        let state = &mut *(ptr as *mut State<F, R>);
        let func = state.func.take().unwrap();
        state.result = Some(func());
        std::ptr::null_mut()
    }

    let mut state = State {
        func: Some(func),
        result: None,
    };
    unsafe {
        rb_thread_call_without_gvl(
            trampoline::<F, R>,
            &mut state as *mut _ as *mut c_void,
            None,
            std::ptr::null_mut(),
        );
    }
    state.result.expect("without_gvl trampoline ran")
}

pub(super) fn park_forever_without_gvl() {
    without_gvl(|| loop {
        thread::park();
    })
}

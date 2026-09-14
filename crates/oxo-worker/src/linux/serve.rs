use super::*;

pub fn main_entry() -> ExitCode {
    match run_from_env() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("oxo-worker: {e}");
            ExitCode::FAILURE
        }
    }
}

pub fn run_from_env() -> Result<(), String> {
    let config = Config::from_env()?;
    run(config)
}

fn run(config: Config) -> Result<(), String> {
    // S1 deliberately initializes Ruby and loads the Rack app before creating
    // listeners or acceptor threads. Future process models depend on this
    // lifecycle boundary staying explicit.
    let _cleanup = unsafe { magnus::embed::init() };
    let ruby = Ruby::get().map_err(|e| format!("Ruby init failed: {e}"))?;
    init_vm_and_load_app(&ruby, &config)?;

    let queue = Arc::new(JobQueue::new(QUEUE_CAPACITY));
    let opts = Arc::new(WorkerOptions {
        multithread: config.threads > 1,
        multiprocess: config.multiprocess,
    });
    let _threads = start_ruby_threads(&ruby, queue.clone(), opts, config.threads)?;
    start_listener_and_threads(config, queue)?;

    park_forever_without_gvl();
    Ok(())
}

fn start_listener_and_threads(config: Config, queue: Arc<JobQueue>) -> Result<(), String> {
    prepare_socket(&config.socket)?;
    let listener = UnixListener::bind(&config.socket)
        .map_err(|e| format!("binding {}: {e}", config.socket.display()))?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod {}: {e}", config.socket.display()))?;
    // the realized-config census. Stderr, not stdout — the readiness scanner
    // consumes and discards pre-READY stdout, while stderr is pumped verbatim into the
    // service's stderr and lands in captured logs. The bench's per-arm gate asserts
    // this line matches what the arm requested (the wiring defect ran every banked
    // "t4" arm single-threaded with nothing in the record to catch it).
    eprintln!(
        "oxo-worker: census threads={} multithread={} multiprocess={} streaming={}",
        config.threads,
        config.threads > 1,
        config.multiprocess,
        config.streaming
    );
    println!("{READY_PREFIX}{}", config.socket.display());
    std::io::stdout().flush().ok();

    thread::Builder::new()
        .name("oxo-worker-accept".to_string())
        .spawn(move || accept_loop(listener, queue, config.max_body_bytes, config.streaming))
        .map_err(|e| format!("spawning accept loop: {e}"))?;
    Ok(())
}

fn prepare_socket(socket: &PathBuf) -> Result<(), String> {
    let parent = socket
        .parent()
        .ok_or_else(|| format!("socket path {} has no parent", socket.display()))?;
    if parent.exists() {
        let meta = fs::metadata(parent)
            .map_err(|e| format!("stat socket directory {}: {e}", parent.display()))?;
        if !meta.is_dir() {
            return Err(format!(
                "socket parent {} is not a directory",
                parent.display()
            ));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "refusing socket directory {} with group/other permissions {:o}; use a private 0700 directory",
                parent.display(),
                meta.permissions().mode() & 0o777
            ));
        }
    } else {
        fs::create_dir_all(parent)
            .map_err(|e| format!("creating socket directory {}: {e}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod socket directory {}: {e}", parent.display()))?;
    }

    match fs::symlink_metadata(socket) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(format!(
                    "refusing to unlink non-socket path {}",
                    socket.display()
                ));
            }
            let euid = unsafe { libc::geteuid() };
            if meta.uid() != euid {
                return Err(format!(
                    "refusing to unlink socket {} owned by uid {} (current uid {euid})",
                    socket.display(),
                    meta.uid()
                ));
            }
            fs::remove_file(socket)
                .map_err(|e| format!("removing stale socket {}: {e}", socket.display()))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("stat socket {}: {e}", socket.display())),
    }
    Ok(())
}

fn accept_loop(listener: UnixListener, queue: Arc<JobQueue>, max_body: usize, streaming: bool) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let queue = queue.clone();
                thread::spawn(move || {
                    // D10: a panic in the per-connection handler must be observable, not a
                    // silently dropped connection. Catch it and log; the socket closes as
                    // the stream unwinds. (The Ruby worker threads use the stronger
                    // exit(70) fail-fast because they carry Ruby VM state; a stray
                    // connection thread does not.)
                    let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        handle_connection(stream, queue, max_body, streaming)
                    }));
                    if handled.is_err() {
                        eprintln!("oxo-worker: connection handler panicked; connection dropped");
                    }
                });
            }
            Err(e) => eprintln!("oxo-worker: accept error: {e}"),
        }
    }
}

#[derive(Debug)]
pub(super) struct Job {
    pub(super) request: WorkerRequest,
    pub(super) reply: JobReply,
}

#[derive(Debug)]
pub(super) enum JobReply {
    Buffered(mpsc::Sender<WorkerResponse>),
    Streaming(mpsc::SyncSender<WorkerEvent>),
}

pub(super) struct QueueState {
    closed: bool,
    jobs: VecDeque<Job>,
}

pub(super) struct JobQueue {
    state: Mutex<QueueState>,
    available: Condvar,
    capacity: usize,
}

impl JobQueue {
    fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(QueueState {
                closed: false,
                jobs: VecDeque::new(),
            }),
            available: Condvar::new(),
            capacity,
        }
    }

    pub(super) fn push(&self, job: Job) -> bool {
        let mut state = lock_no_poison(&self.state);
        if state.closed || state.jobs.len() >= self.capacity {
            return false;
        }
        state.jobs.push_back(job);
        self.available.notify_one();
        true
    }

    fn pop_blocking(&self) -> Option<Job> {
        let mut state = lock_no_poison(&self.state);
        loop {
            if let Some(job) = state.jobs.pop_front() {
                return Some(job);
            }
            if state.closed {
                return None;
            }
            state = match self.available.wait(state) {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    pub(super) fn pop_without_gvl(self: &Arc<Self>) -> Option<Job> {
        // Idle Ruby workers must wait for Rust jobs without holding the GVL;
        // otherwise T>1 would only pretend to overlap blocking Rack requests.
        let queue = self.clone();
        without_gvl(move || queue.pop_blocking())
    }
}

pub(super) fn lock_no_poison<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn handle_connection(
    mut stream: UnixStream,
    queue: Arc<JobQueue>,
    max_body: usize,
    streaming: bool,
) {
    // sniff byte 0 (non-consuming peek). A frame client (the pooled edge) is
    // served by the persistent frame loop; anything else falls through to the
    // untouched one-shot HTTP/1.1 path below (defense-in-depth for direct UDS clients).
    match frame::try_handle_frame_connection(&mut stream, &queue, max_body, streaming) {
        Ok(true) => {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
        Ok(false) => {} // not a frame client — HTTP path
        Err(_) => {
            // Peek failed (dead connection) — nothing to serve.
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
    }
    match parse_request(&mut stream, max_body) {
        Ok(request) if streaming => {
            let rx = dispatch_streaming_request(queue, request);
            let _ = write_streaming_response(&mut stream, rx);
        }
        Ok(request) => {
            let response = dispatch_buffered_request(queue, request);
            let _ = write_response(&mut stream, response);
        }
        Err(err) => {
            let response = WorkerResponse::text(err.status, err.message.into_bytes());
            let _ = write_response(&mut stream, response);
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

pub(super) fn dispatch_buffered_request(
    queue: Arc<JobQueue>,
    request: WorkerRequest,
) -> WorkerResponse {
    let (tx, rx) = mpsc::channel();
    let job = Job {
        request,
        reply: JobReply::Buffered(tx),
    };
    if !queue.push(job) {
        return WorkerResponse::text(503, b"Service Unavailable".to_vec());
    }
    match rx.recv() {
        Ok(resp) => resp,
        Err(_) => WorkerResponse::text(500, b"Internal Server Error".to_vec()),
    }
}

pub(super) fn dispatch_streaming_request(
    queue: Arc<JobQueue>,
    request: WorkerRequest,
) -> mpsc::Receiver<WorkerEvent> {
    let (tx, rx) = mpsc::sync_channel(8);
    let job = Job {
        request,
        reply: JobReply::Streaming(tx.clone()),
    };
    if !queue.push(job) {
        let _ = tx.send(WorkerEvent::Start(WorkerResponseHead::text(503)));
        let _ = tx.send(WorkerEvent::Chunk(b"Service Unavailable".to_vec()));
        let _ = tx.send(WorkerEvent::End);
    }
    rx
}

fn write_streaming_response(
    stream: &mut UnixStream,
    rx: mpsc::Receiver<WorkerEvent>,
) -> std::io::Result<()> {
    let first = rx
        .recv()
        .unwrap_or_else(|_| WorkerEvent::Start(WorkerResponseHead::text(500)));
    let head = match first {
        WorkerEvent::Start(head) => head,
        WorkerEvent::Chunk(_) | WorkerEvent::End => WorkerResponseHead::text(500),
    };
    write_response_head(
        stream,
        head.status,
        &head.headers,
        ResponseBodyMode::Chunked,
    )?;
    for event in rx {
        match event {
            WorkerEvent::Start(_) => continue,
            WorkerEvent::Chunk(chunk) if chunk.is_empty() => continue,
            WorkerEvent::Chunk(chunk) => {
                write!(stream, "{:x}\r\n", chunk.len())?;
                stream.write_all(&chunk)?;
                stream.write_all(b"\r\n")?;
                stream.flush()?;
            }
            WorkerEvent::End => break,
        }
    }
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()
}

enum ResponseBodyMode {
    Fixed(usize),
    Chunked,
}

fn write_response_head(
    stream: &mut UnixStream,
    status: u16,
    headers: &[(String, String)],
    mode: ResponseBodyMode,
) -> std::io::Result<()> {
    let status = if (100..=999).contains(&status) {
        status
    } else {
        500
    };
    let mut head = format!("HTTP/1.1 {} {}\r\n", status, reason(status));
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        // Framing headers are the host's to own — strip silently (intentional).
        if matches!(
            lower.as_str(),
            "content-length" | "transfer-encoding" | "connection"
        ) {
            continue;
        }
        // A name/value that fails validation (e.g. a bare CR, control byte) is dropped to
        // prevent response splitting — but warn so the loss is observable in dev (a value's
        // "\n" multi-value separator was already split upstream in flatten_headers).
        if !valid_token(name) || !valid_response_header_value(value) {
            eprintln!("oxo-worker: dropping response header {name:?}: invalid name or value");
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    match mode {
        ResponseBodyMode::Fixed(len) => head.push_str(&format!("content-length: {len}\r\n")),
        ResponseBodyMode::Chunked => head.push_str("transfer-encoding: chunked\r\n"),
    }
    head.push_str("connection: close\r\n\r\n");
    stream.write_all(head.as_bytes())
}
fn write_response(stream: &mut UnixStream, response: WorkerResponse) -> std::io::Result<()> {
    // Rack apps may emit repeated safe headers, but the worker owns framing:
    // exactly one Content-Length, Connection: close, and no CTL-bearing header
    // names or values leave the process.
    write_response_head(
        stream,
        response.status,
        &response.headers,
        ResponseBodyMode::Fixed(response.body.len()),
    )?;
    stream.write_all(&response.body)?;
    stream.flush()
}

pub(super) fn valid_response_header_value(value: &str) -> bool {
    value.bytes().all(|b| b >= 0x20 && b != 0x7f)
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    #[test]
    fn response_writer_canonicalizes_framing() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let response = WorkerResponse {
            status: 200,
            headers: vec![
                ("Content-Length".to_string(), "999".to_string()),
                ("Transfer-Encoding".to_string(), "chunked".to_string()),
                ("Connection".to_string(), "keep-alive".to_string()),
                ("Set-Cookie".to_string(), "a=1".to_string()),
                ("X-Bad".to_string(), "split\r\nnope".to_string()),
            ],
            body: b"hello".to_vec(),
        };
        write_response(&mut a, response).unwrap();
        drop(a);
        let mut out = String::new();
        b.read_to_string(&mut out).unwrap();
        assert!(out.contains("content-length: 5\r\n"));
        assert!(out.contains("connection: close\r\n"));
        assert!(out.contains("Set-Cookie: a=1\r\n"));
        assert!(!out.contains("999"));
        assert!(!out.contains("chunked"));
        assert!(!out.contains("split"));
    }
}

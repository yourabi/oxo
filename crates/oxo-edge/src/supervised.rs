//! The supervised handler: spawn + **supervise** a separate Ruby worker process (a
//! stdlib shim or `bundle exec puma` serving real Rails) and proxy each request to it
//! over a fresh loopback connection. adds **auto-respawn** and **diagnosable boot**.
//!
//! Lifecycle: `spawn()` starts the first worker and a **supervisor task** that *solely
//! owns* the `Child`. The supervisor `wait()`s the worker; on death (or a `request_restart`)
//! it respawns with a sliding-window crash-loop throttle that *self-heals* a transient
//! outage (it never gives up permanently — it just slows to the backoff cap while the
//! state is `Restarting{degraded}`). `handle()` reads a single shared `WorkerState`
//! snapshot per request (so `addr`+`secret` are always a consistent pair), and retries
//! briefly across a respawn swap.
//!
//! Security/robustness invariants (see docs/THREAT_MODEL.md):
//! * Launcher resolved to an absolute path (`OXO_RUBY`/`OXO_BUNDLE`) — no
//!   bare-name spawn. Worker scripts/configs materialized from this binary, **once** per
//!   handler at stable paths; only the stderr file rotates per spawn (no temp leak).
//! * Worker binds `127.0.0.1` only. Per-worker 128-bit OS-RNG secret header (rotated each
//!   spawn). Worker stderr → a temp **file** (no pipe to drain → no teardown wedge), whose
//!   tail is captured into boot/crash errors.
//! * Drop signals cooperative shutdown (the supervisor reaps the child) + removes temp
//!   files; `kill_on_drop` is the backstop for abrupt runtime teardown.

use std::collections::VecDeque;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use oxo_core::{Config, HandlerError, RackHandler, RackRequest, RackResponse, WorkerKind};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;

const WORKER_RB: &str = include_str!("../../../ruby/oxo_worker.rb");
const PUMA_CONFIG_RB: &str = include_str!("../../../ruby/oxo_puma_config.rb");
const PUMA_RACKUP_RU: &str = include_str!("../../../ruby/oxo_puma_rackup.ru");

const SECRET_HEADER: &str = "x-oxo-secret";
/// `handle()` attempts (initial + retries) so a request crossing a respawn swap rides it.
const HANDLE_ATTEMPTS: u32 = 3;

/// The live worker target, read atomically per request. `Restarting` ⇒ 503.
#[derive(Clone)]
enum WorkerState {
    Live {
        addr: SocketAddr,
        secret: Arc<str>,
        #[allow(dead_code)]
        generation: u64,
    },
    Restarting {
        #[allow(dead_code)]
        degraded: bool,
    },
}

/// Worker scripts/configs materialized once per handler (stable across respawns).
#[derive(Clone)]
enum StablePaths {
    Shim { script: PathBuf },
    Puma { config: PathBuf, rackup: PathBuf },
}

impl StablePaths {
    fn materialize(worker: WorkerKind) -> Result<Self, HandlerError> {
        match worker {
            WorkerKind::Shim => {
                let script = temp_path("oxo_worker", "rb");
                std::fs::write(&script, WORKER_RB)
                    .map_err(|e| HandlerError::Worker(format!("writing worker script: {e}")))?;
                Ok(StablePaths::Shim { script })
            }
            WorkerKind::Puma => {
                let config = temp_path("oxo_puma_config", "rb");
                let rackup = temp_path("oxo_puma_rackup", "ru");
                std::fs::write(&config, PUMA_CONFIG_RB)
                    .map_err(|e| HandlerError::Worker(format!("writing puma config: {e}")))?;
                std::fs::write(&rackup, PUMA_RACKUP_RU)
                    .map_err(|e| HandlerError::Worker(format!("writing puma rackup: {e}")))?;
                Ok(StablePaths::Puma { config, rackup })
            }
        }
    }

    fn files(&self) -> Vec<&PathBuf> {
        match self {
            StablePaths::Shim { script } => vec![script],
            StablePaths::Puma { config, rackup } => vec![config, rackup],
        }
    }
}

/// One freshly-spawned, ready worker.
struct Spawned {
    child: Child,
    addr: SocketAddr,
    secret: Arc<str>,
    pid: u32,
    stderr_path: PathBuf,
}

pub struct SupervisedRubyHandler {
    state: Arc<Mutex<WorkerState>>,
    pid: Arc<AtomicU32>,
    respawns: Arc<AtomicU64>,
    degraded: Arc<AtomicBool>,
    restart: Arc<Notify>,
    shutdown_tx: watch::Sender<bool>,
    supervisor: Option<JoinHandle<()>>,
    stable: StablePaths,
    current_stderr: Arc<Mutex<PathBuf>>,
}

impl SupervisedRubyHandler {
    /// Spawn the first worker (ready, with a port handshake) and start the supervisor.
    pub async fn spawn(config: &Config) -> Result<Self, HandlerError> {
        let stable = StablePaths::materialize(config.worker)?;
        // No handler (and so no Drop) exists yet, so clean the stable files by hand if the
        // very first boot fails.
        let first = match spawn_worker(config, &stable).await {
            Ok(f) => f,
            Err(e) => {
                for p in stable.files() {
                    let _ = std::fs::remove_file(p);
                }
                return Err(e);
            }
        };

        let state = Arc::new(Mutex::new(WorkerState::Live {
            addr: first.addr,
            secret: first.secret.clone(),
            generation: 0,
        }));
        let pid = Arc::new(AtomicU32::new(first.pid));
        let respawns = Arc::new(AtomicU64::new(0));
        let degraded = Arc::new(AtomicBool::new(false));
        let restart = Arc::new(Notify::new());
        let current_stderr = Arc::new(Mutex::new(first.stderr_path.clone()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let sup = Supervisor {
            config: config.clone(),
            stable: stable.clone(),
            state: state.clone(),
            pid: pid.clone(),
            respawns: respawns.clone(),
            degraded: degraded.clone(),
            restart: restart.clone(),
            shutdown_rx,
            current_stderr: current_stderr.clone(),
            burst: BurstParams::from_env(config.worker),
        };
        let supervisor = tokio::spawn(sup.run(first.child, first.stderr_path));

        Ok(Self {
            state,
            pid,
            respawns,
            degraded,
            restart,
            shutdown_tx,
            supervisor: Some(supervisor),
            stable,
            current_stderr,
        })
    }

    /// The loopback address of the current live worker (diagnostics/tests).
    pub fn worker_addr(&self) -> SocketAddr {
        match &*self.state.lock().unwrap() {
            WorkerState::Live { addr, .. } => *addr,
            WorkerState::Restarting { .. } => SocketAddr::from(([127, 0, 0, 1], 0)),
        }
    }

    /// The current worker PID (captured at spawn; stable, unlike `Child::id()` after wait).
    pub fn worker_pid(&self) -> u32 {
        self.pid.load(Ordering::Relaxed)
    }

    /// How many times the worker has been respawned.
    pub fn respawn_count(&self) -> u64 {
        self.respawns.load(Ordering::Relaxed)
    }

    /// True when the crash-loop burst limit is exceeded (still retrying, but throttled).
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    /// Ask the supervisor to kill + reap the current worker and respawn it. The
    /// supervisor (sole owner of the `Child`) performs the kill, so this is race-free.
    pub fn request_restart(&self) {
        self.restart.notify_one();
    }

    /// Every temp file this handler owns (stable scripts + the current stderr) — for
    /// diagnostics and leak assertions. All are removed on drop.
    pub fn temp_files(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = self.stable.files().into_iter().cloned().collect();
        if let Ok(p) = self.current_stderr.lock() {
            files.push(p.clone());
        }
        files
    }
}

impl Drop for SupervisedRubyHandler {
    fn drop(&mut self) {
        // Cooperative shutdown: the supervisor observes this and kills+reaps the child.
        let _ = self.shutdown_tx.send(true);
        // Backstop for abrupt runtime teardown (kill_on_drop fires when the task drops).
        if let Some(h) = self.supervisor.take() {
            h.abort();
        }
        // Remove temp files synchronously (stable + the current rotating stderr).
        for p in self.stable.files() {
            let _ = std::fs::remove_file(p);
        }
        if let Ok(p) = self.current_stderr.lock() {
            let _ = std::fs::remove_file(&*p);
        }
    }
}

impl RackHandler for SupervisedRubyHandler {
    async fn handle(&self, req: RackRequest) -> Result<RackResponse, HandlerError> {
        for attempt in 0..HANDLE_ATTEMPTS {
            let last = attempt + 1 == HANDLE_ATTEMPTS;
            // Single-acquisition snapshot: addr+secret are always a consistent pair.
            let target = match &*self.state.lock().unwrap() {
                WorkerState::Live { addr, secret, .. } => Some((*addr, secret.clone())),
                WorkerState::Restarting { .. } => None,
            };
            let (addr, secret) = match target {
                Some(t) => t,
                None => {
                    if last {
                        return Err(HandlerError::WorkerUnavailable);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };

            match proxy_once(&req, addr, &secret).await {
                Ok(resp) => {
                    // A gate 403 means our secret was rotated out from under us mid-respawn
                    // (Puma keeps a stable port). Re-read the new secret and retry once.
                    if resp.status == 403
                        && resp
                            .headers
                            .iter()
                            .any(|(k, v)| k.as_str() == "x-oxo-gate" && v.as_str() == "denied")
                        && !last
                    {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                    return Ok(resp);
                }
                // Couldn't reach the worker (it may be mid-swap): retry, else 502.
                Err(HandlerError::WorkerUnreachable(_)) if !last => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(HandlerError::WorkerUnavailable)
    }
}

/// The supervisor task — the *sole* owner of the `Child`.
struct Supervisor {
    config: Config,
    stable: StablePaths,
    state: Arc<Mutex<WorkerState>>,
    pid: Arc<AtomicU32>,
    respawns: Arc<AtomicU64>,
    degraded: Arc<AtomicBool>,
    restart: Arc<Notify>,
    shutdown_rx: watch::Receiver<bool>,
    current_stderr: Arc<Mutex<PathBuf>>,
    burst: BurstParams,
}

impl Supervisor {
    async fn run(self, mut child: Child, mut stderr_path: PathBuf) {
        let Supervisor {
            config,
            stable,
            state,
            pid,
            respawns,
            degraded,
            restart,
            mut shutdown_rx,
            current_stderr,
            burst,
        } = self;

        let mut window: VecDeque<Instant> = VecDeque::new();
        let mut live_since = Instant::now();

        loop {
            enum Ev {
                Died,
                Restart,
                Shutdown,
            }
            let ev = tokio::select! {
                _ = child.wait() => Ev::Died,
                _ = restart.notified() => Ev::Restart,
                r = shutdown_rx.changed() => {
                    if r.is_err() || *shutdown_rx.borrow() { Ev::Shutdown } else { continue }
                }
            };
            match ev {
                Ev::Shutdown => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    return;
                }
                Ev::Restart => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                }
                Ev::Died => {
                    eprintln!(
                        "oxo: worker {} exited; respawning",
                        pid.load(Ordering::Relaxed)
                    );
                }
            }
            if *shutdown_rx.borrow() {
                return;
            }

            // A worker that stayed up past min-uptime was healthy → reset the burst window
            // (monotonic) so periodic recycles / one-off restarts don't look like a loop.
            if Instant::now().duration_since(live_since) >= burst.min_uptime {
                window.clear();
            }
            *state.lock().unwrap() = WorkerState::Restarting {
                degraded: degraded.load(Ordering::Relaxed),
            };

            // Respawn, counting EVERY attempt toward the sliding window — so a boot-failure
            // loop throttles too, not just rapid post-boot deaths. Keep retrying (self-heals
            // a transient outage); throttle to the backoff cap once a crash loop shows, but
            // never give up permanently.
            let mut attempt: u32 = 0;
            let spawned = loop {
                let now = Instant::now();
                while let Some(&front) = window.front() {
                    if now.duration_since(front) > burst.window {
                        window.pop_front();
                    } else {
                        break;
                    }
                }
                window.push_back(now);
                let is_degraded = window.len() >= burst.limit;
                let was_degraded = degraded.swap(is_degraded, Ordering::Relaxed);
                *state.lock().unwrap() = WorkerState::Restarting {
                    degraded: is_degraded,
                };
                if is_degraded && !was_degraded {
                    eprintln!(
                        "oxo: worker crash-loop ({} starts within {:?}); throttling respawns to {:?}",
                        window.len(),
                        burst.window,
                        burst.cap
                    );
                }
                // First healthy attempt is immediate; retries back off; a crash loop is
                // pinned at the cap.
                let delay = if is_degraded {
                    burst.cap
                } else if attempt == 0 {
                    Duration::ZERO
                } else {
                    burst.backoff(attempt)
                };
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    r = shutdown_rx.changed() => { let _ = r; }
                }
                if *shutdown_rx.borrow() {
                    return;
                }
                match spawn_worker(&config, &stable).await {
                    Ok(s) => break s,
                    Err(e) => {
                        eprintln!("oxo: respawn attempt {} failed: {e}", attempt + 1);
                        attempt = attempt.saturating_add(1);
                    }
                }
            };

            if *shutdown_rx.borrow() {
                // The just-spawned child's kill_on_drop fires when `spawned` drops here.
                let _ = std::fs::remove_file(&spawned.stderr_path);
                return;
            }

            // Rotate stderr (remove the previous generation's file) and publish the new
            // ready target. `spawn_worker` already waited for connectability.
            let _ = std::fs::remove_file(&stderr_path);
            stderr_path = spawned.stderr_path;
            *current_stderr.lock().unwrap() = stderr_path.clone();
            child = spawned.child;
            pid.store(spawned.pid, Ordering::Relaxed);
            let generation = respawns.fetch_add(1, Ordering::Relaxed) + 1;
            degraded.store(false, Ordering::Relaxed);
            live_since = Instant::now();
            *state.lock().unwrap() = WorkerState::Live {
                addr: spawned.addr,
                secret: spawned.secret,
                generation,
            };
            eprintln!(
                "oxo: worker respawned (pid {}, generation {})",
                spawned.pid, generation
            );
        }
    }
}

/// Spawn one worker, complete the `OXO_PORT=` handshake, and wait until it accepts.
/// On boot failure the error carries the worker's captured stderr tail.
async fn spawn_worker(config: &Config, stable: &StablePaths) -> Result<Spawned, HandlerError> {
    let app = std::path::absolute(&config.app)
        .map_err(|e| HandlerError::Worker(format!("resolving app path {:?}: {e}", config.app)))?;
    if !app.is_file() {
        return Err(HandlerError::Worker(format!(
            "rack app not found at {} (set OXO_APP or the config 'app')",
            app.display()
        )));
    }
    let secret: Arc<str> = generate_secret().into();
    let stderr_path = temp_path("oxo_worker_stderr", "log");
    let stderr_file = std::fs::File::create(&stderr_path)
        .map_err(|e| HandlerError::Worker(format!("creating worker stderr file: {e}")))?;

    let mut command = match (config.worker, stable) {
        (WorkerKind::Shim, StablePaths::Shim { script }) => {
            let ruby = resolve_exe("ruby", "OXO_RUBY")?;
            let mut c = Command::new(&ruby);
            c.arg(script);
            c
        }
        (
            WorkerKind::Puma,
            StablePaths::Puma {
                config: cfg,
                rackup,
            },
        ) => {
            let bundle = resolve_exe("bundle", "OXO_BUNDLE")?;
            let app_dir = app.parent().ok_or_else(|| {
                HandlerError::Worker("rack app path has no parent directory".to_string())
            })?;
            let port = pick_free_port()?;
            let mut c = Command::new(&bundle);
            c.arg("exec")
                .arg("puma")
                .arg("-C")
                .arg(cfg)
                .arg(rackup)
                .current_dir(app_dir)
                .env("OXO_PUMA_PORT", port.to_string());
            c
        }
        _ => {
            return Err(HandlerError::Worker(
                "worker/stable-paths mismatch".to_string(),
            ))
        }
    };
    command
        .env("OXO_WORKER_SECRET", &*secret)
        .env("OXO_WORKER_APP", &app)
        .env("OXO_WORKER_MAX_BODY", config.max_body_bytes.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(|e| {
        let _ = std::fs::remove_file(&stderr_path);
        HandlerError::Worker(format!("spawning {:?} worker: {e}", config.worker))
    })?;
    let captured_pid = child.id().unwrap_or(0);

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| HandlerError::Worker("worker stdout unavailable".to_string()))?;
    let mut lines = BufReader::new(stdout).lines();
    let read_port = async {
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if let Some(rest) = line.strip_prefix("OXO_PORT=") {
                        if let Ok(p) = rest.trim().parse::<u16>() {
                            break Some(p);
                        }
                    }
                }
                Ok(None) | Err(_) => break None,
            }
        }
    };
    let timeout = boot_timeout(config.worker);
    let port = match tokio::time::timeout(timeout, read_port).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            drop(lines);
            return Err(boot_error(
                &mut child,
                &stderr_path,
                config.worker,
                "exited before reporting a port",
            )
            .await);
        }
        Err(_) => {
            drop(lines);
            return Err(boot_error(
                &mut child,
                &stderr_path,
                config.worker,
                &format!("did not report a port within {}s", timeout.as_secs()),
            )
            .await);
        }
    };
    drop(lines);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    wait_until_connectable(addr, Duration::from_secs(10)).await;
    Ok(Spawned {
        child,
        addr,
        secret,
        pid: captured_pid,
        stderr_path,
    })
}

/// Build a boot-failure error carrying the worker's stderr tail. Ensures the child has
/// exited (so stderr is flushed) before reading, and removes the stderr file.
async fn boot_error(
    child: &mut Child,
    stderr_path: &Path,
    worker: WorkerKind,
    what: &str,
) -> HandlerError {
    match child.try_wait() {
        Ok(Some(_)) => {} // already exited → stderr flushed
        _ => {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }
    let tail = read_tail(stderr_path, 4096);
    let _ = std::fs::remove_file(stderr_path);
    if tail.trim().is_empty() {
        HandlerError::Worker(format!(
            "{worker:?} worker {what} (no stderr; on Windows, Norton/SONAR can suspend \
             children — docs/THREAT_MODEL.md)"
        ))
    } else {
        HandlerError::Worker(format!("{worker:?} worker {what}; stderr tail:\n{tail}"))
    }
}

fn read_tail(path: &Path, max: usize) -> String {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return String::new();
    }
    let start = buf.len().saturating_sub(max);
    String::from_utf8_lossy(&buf[start..]).into_owned()
}

/// One request → worker and back over a fresh one-shot connection. Connection-level
/// failures map to `WorkerUnreachable` (→ 502), distinct from a genuine app 500.
async fn proxy_once(
    req: &RackRequest,
    addr: SocketAddr,
    secret: &str,
) -> Result<RackResponse, HandlerError> {
    let target = if req.query_string.is_empty() {
        req.path.clone()
    } else {
        format!("{}?{}", req.path, req.query_string)
    };
    let mut builder = Request::builder()
        .method(req.method.as_str())
        .uri(target.as_str())
        .header("host", format!("127.0.0.1:{}", addr.port()))
        .header(SECRET_HEADER, secret);
    for (k, v) in &req.headers {
        if matches!(
            k.as_str(),
            "host" | "content-length" | "transfer-encoding" | "connection" | SECRET_HEADER
        ) {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_str());
    }
    let request = builder
        .body(Full::new(req.body.clone()))
        .map_err(|e| HandlerError::Worker(format!("building worker request: {e}")))?;

    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| HandlerError::WorkerUnreachable(e.to_string()))?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| HandlerError::WorkerUnreachable(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender
        .send_request(request)
        .await
        .map_err(|e| HandlerError::WorkerUnreachable(e.to_string()))?;
    let (parts, body) = resp.into_parts();
    let bytes = body
        .collect()
        .await
        .map_err(|e| HandlerError::WorkerUnreachable(e.to_string()))?
        .to_bytes();
    let mut headers = Vec::new();
    for (name, value) in parts.headers.iter() {
        if let Ok(v) = value.to_str() {
            headers.push((name.as_str().to_ascii_lowercase(), v.to_string()));
        }
    }
    Ok(RackResponse {
        status: parts.status.as_u16(),
        headers,
        body: bytes,
    })
}

/// Sliding-window crash-loop policy + backoff. Env-overridable for tests.
struct BurstParams {
    limit: usize,
    window: Duration,
    min_uptime: Duration,
    base: Duration,
    cap: Duration,
}

impl BurstParams {
    fn from_env(worker: WorkerKind) -> Self {
        let boot = boot_timeout(worker).as_secs();
        BurstParams {
            limit: env_u64("OXO_RESPAWN_BURST", 5) as usize,
            window: Duration::from_secs(env_u64("OXO_RESPAWN_WINDOW_SECS", (boot * 5).max(30))),
            min_uptime: Duration::from_secs(env_u64("OXO_RESPAWN_MIN_UPTIME_SECS", 10)),
            base: Duration::from_millis(200),
            cap: Duration::from_secs(env_u64("OXO_RESPAWN_BACKOFF_CAP_SECS", 5)),
        }
    }

    fn backoff(&self, attempt: u32) -> Duration {
        (self.base * 2u32.saturating_pow(attempt.min(6))).min(self.cap)
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
}

/// Resolve an executable to an absolute path: env override first, then a PATH search
/// (matching `.exe` on Windows). Never spawns a bare name (binary-planting).
fn resolve_exe(name: &str, env_override: &str) -> Result<PathBuf, HandlerError> {
    if let Ok(explicit) = std::env::var(env_override) {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Ok(p);
        }
    }
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let cand = dir.join(&exe);
            if cand.is_file() {
                return Ok(cand);
            }
        }
    }
    Err(HandlerError::Worker(format!(
        "could not find `{name}` on PATH (set {env_override} to an absolute path)"
    )))
}

/// A per-worker 128-bit token from the OS RNG — the primary local barrier in Puma mode.
fn generate_secret() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).expect("OS RNG (getrandom) must succeed");
    let mut s = String::with_capacity(32);
    for b in buf {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A temp path unique per process *and* per call (handlers + respawns must not collide).
fn temp_path(prefix: &str, ext: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "{prefix}_{}_{}.{ext}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Boot/handshake timeout: longer for Puma+Rails than the fast shim; env-overridable.
fn boot_timeout(worker: WorkerKind) -> Duration {
    if let Ok(s) = std::env::var("OXO_BOOT_TIMEOUT_SECS") {
        if let Ok(n) = s.trim().parse::<u64>() {
            return Duration::from_secs(n);
        }
    }
    match worker {
        WorkerKind::Shim => Duration::from_secs(20),
        WorkerKind::Puma => Duration::from_secs(60),
    }
}

/// Pick a free loopback port by binding and immediately releasing it.
fn pick_free_port() -> Result<u16, HandlerError> {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| HandlerError::Io(e.to_string()))?;
    let p = l
        .local_addr()
        .map_err(|e| HandlerError::Io(e.to_string()))?
        .port();
    Ok(p)
}

/// Poll-connect until the worker accepts or the deadline passes.
async fn wait_until_connectable(addr: SocketAddr, deadline: Duration) {
    let start = tokio::time::Instant::now();
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        if start.elapsed() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

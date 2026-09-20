//! Persistent Unix-socket connections carrying the binary `hop_frame` protocol.
//!
//! The pool stores `Arc<Mutex<WorkerConnection>>` under one process-wide idle
//! ceiling. Each idle connection has a watcher holding its lock until checkout,
//! eviction, drain, peer activity, or timeout. Checkout waits for that lock before
//! taking exclusive ownership. Watchers run individually by default; the optional
//! supervised reaper drives them in one task.
//!
//! The idle timeout is shorter than the worker connection lifetime, reducing the
//! race between checkout and a worker closing an idle connection. Retry eligibility
//! also depends on the worker kind and whether the request write completed; see
//! `WorkerKind` and `ExchangeError`. Async workers never retry a delivered request
//! after zero-response-byte EOF because execution may already have occurred.
//!
//! A connection returns to the pool only at a complete response frame boundary
//! with an empty read buffer. Surplus bytes, mid-stream errors, cancellation and
//! drain close it instead. An idle worker must never send unsolicited bytes.

use super::frame_pool::{ConnectionMeta, ConnectionPool, IdleCeilingSource};
use super::*;
use futures_util::stream::{FuturesUnordered, StreamExt};
#[cfg(test)]
use oxo_core::hop_frame::RequestFrame;
use oxo_core::hop_frame::{self, FrameCaps, FramePrefix, ResponseFrame, Scheme};
#[cfg(test)]
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicI32;
use std::sync::OnceLock;
use tokio::sync::Mutex as AsyncMutex;

/// Pool idle timeout. MUST stay strictly below the worker's connection lifetime so the
/// edge always closes an idle connection first (the timeout-ordering invariant).
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// A worker connection and its persistent read buffer. One `read_buf` can collect
/// the prefix and envelope together. Only an empty buffer may return to the pool.
pub(super) struct PooledConn {
    stream: UnixStream,
    rbuf: FrameReadBuffer,
}

impl PooledConn {
    fn new(stream: UnixStream) -> Self {
        PooledConn {
            stream,
            rbuf: FrameReadBuffer::new(),
        }
    }
}

/// Speculative frame read buffer. Unconsumed bytes live in `buf[pos..]`.
/// Socket reads append into spare capacity without zero-filling it first.
pub(super) struct FrameReadBuffer {
    buf: Vec<u8>,
    pos: usize,
}

/// Initial scratch capacity: comfortably above the common small-response envelope so
/// the whole frame lands in one read; large envelopes reserve exactly what the parsed
/// prefix declares (one growth + the kernel copy — bounded by the frame caps).
const FRAME_SCRATCH_TARGET: usize = 16 * 1024;

impl FrameReadBuffer {
    fn new() -> Self {
        FrameReadBuffer {
            buf: Vec::with_capacity(FRAME_SCRATCH_TARGET),
            pos: 0,
        }
    }

    fn available(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Any bytes left after a frame boundary. On a `Full` response or a clean `End`
    /// this means the worker spoke out of turn — the connection is dirty and must
    /// never be pooled.
    fn has_surplus(&self) -> bool {
        self.available() > 0
    }

    /// Reclaim consumed front space. Cheap in the common case (everything consumed →
    /// clear); a partial next frame during streaming moves at most one frame's bytes.
    fn compact(&mut self) {
        if self.pos == 0 {
            return;
        }
        if self.available() == 0 {
            self.buf.clear();
        } else {
            self.buf.copy_within(self.pos.., 0);
            let remaining = self.buf.len() - self.pos;
            self.buf.truncate(remaining);
        }
        self.pos = 0;
    }

    /// Fill until at least `needed` bytes are available, reading speculatively (each
    /// `read_buf` takes whatever the kernel has, up to spare capacity). `Ok(false)` only
    /// when `eof_ok_at_zero` and EOF arrived with ZERO bytes available — the
    /// stale-before-dispatch signal, valid only for an exchange's FIRST frame. EOF
    /// mid-frame (any bytes already present) is always `Err(502)`: response bytes were
    /// committed, so the never-replay rule applies.
    async fn fill_to(
        &mut self,
        stream: &mut UnixStream,
        needed: usize,
        eof_ok_at_zero: bool,
    ) -> Result<bool, u16> {
        while self.available() < needed {
            let shortfall = needed - self.available();
            let spare = self.buf.capacity() - self.buf.len();
            if spare < shortfall {
                // Reserve at least the shortfall; round small reservations up to the
                // scratch target so speculative reads stay large.
                self.buf.reserve(shortfall.max(FRAME_SCRATCH_TARGET));
            }
            let n = timeout(WORKER_READ_TIMEOUT, self.stream_read(stream))
                .await
                .map_err(|_| 502u16)?
                .map_err(|_| 502u16)?;
            if n == 0 {
                return if eof_ok_at_zero && self.available() == 0 {
                    Ok(false)
                } else {
                    Err(502)
                };
            }
        }
        Ok(true)
    }

    async fn stream_read(&mut self, stream: &mut UnixStream) -> std::io::Result<usize> {
        stream.read_buf(&mut self.buf).await
    }

    fn prefix_bytes(&self) -> [u8; FramePrefix::LEN] {
        let mut prefix = [0u8; FramePrefix::LEN];
        prefix.copy_from_slice(&self.buf[self.pos..self.pos + FramePrefix::LEN]);
        prefix
    }

    /// Whole-frame length if a complete frame sits in the buffer; `Ok(None)` if more
    /// bytes are needed; `Err` on a malformed prefix (same 502 the decode path yields).
    fn buffered_frame_len(&self, caps: &FrameCaps) -> Result<Option<usize>, u16> {
        if self.available() < FramePrefix::LEN {
            return Ok(None);
        }
        let parsed = FramePrefix::parse(&self.prefix_bytes(), caps).map_err(|_| 502u16)?;
        let total = FramePrefix::LEN + parsed.remaining_length as usize;
        Ok((self.available() >= total).then_some(total))
    }

    /// Decode the frame at the buffer front, consuming exactly `total` bytes (the
    /// envelope-tiling invariant is enforced by `decode_response` itself).
    fn decode_front(&mut self, total: usize, caps: &FrameCaps) -> Result<ResponseFrame, u16> {
        let envelope = &self.buf[self.pos + FramePrefix::LEN..self.pos + total];
        let frame = hop_frame::decode_response(envelope, caps).map_err(|_| 502u16)?;
        self.pos += total;
        Ok(frame)
    }

    /// Read one response frame. `Ok(None)` = clean EOF before any byte of the exchange
    /// (the stale signal) — only meaningful for the exchange's FIRST frame.
    async fn read_frame(
        &mut self,
        stream: &mut UnixStream,
        caps: &FrameCaps,
        first_of_exchange: bool,
    ) -> Result<Option<ResponseFrame>, u16> {
        self.compact();
        if !self
            .fill_to(stream, FramePrefix::LEN, first_of_exchange)
            .await?
        {
            return Ok(None);
        }
        let parsed = FramePrefix::parse(&self.prefix_bytes(), caps).map_err(|_| 502u16)?;
        let total = FramePrefix::LEN + parsed.remaining_length as usize;
        self.fill_to(stream, total, false).await?;
        Ok(Some(self.decode_front(total, caps)?))
    }

    /// Read one frame, aborting on drain — but a COMPLETE frame already in the buffer
    /// is processed WITHOUT another socket await (the #8 drain-boundary rule:
    /// drain interrupts socket waits, never buffered work). `Ok(None)` = drain fired.
    async fn read_frame_or_drain(
        &mut self,
        stream: &mut UnixStream,
        caps: &FrameCaps,
        drain: &mut watch::Receiver<bool>,
    ) -> Result<Option<ResponseFrame>, u16> {
        self.compact();
        if let Some(total) = self.buffered_frame_len(caps)? {
            return Ok(Some(self.decode_front(total, caps)?));
        }
        // Need the socket for at least part of this frame: drain may interrupt the
        // prefix wait (as configured); the envelope completion below is not interruptible.
        tokio::select! {
            biased;
            _ = drain.changed() => return Ok(None),
            filled = self.fill_to(stream, FramePrefix::LEN, false) => {
                filled?; // EOF mid-stream (no End frame) is a broken response: 502
            }
        }
        let parsed = FramePrefix::parse(&self.prefix_bytes(), caps).map_err(|_| 502u16)?;
        let total = FramePrefix::LEN + parsed.remaining_length as usize;
        self.fill_to(stream, total, false).await?;
        Ok(Some(self.decode_front(total, caps)?))
    }
}

/// The pooled UDS connections to the worker fleet, keyed by worker index.
pub(super) struct WorkerFramePool {
    pool: Arc<ConnectionPool<Arc<AsyncMutex<PooledConn>>>>,
    /// Monotonic per-connection id for the pool's LRU (NOT the fd — fds are reused after
    /// close, which would let a new connection collide with a stale LRU entry).
    next_id: AtomicI32,
    /// Count of reused connections that turned out stale and forced a fresh retry —
    /// observable on evidence to prove the retry carve-out fired, not silent 502s.
    pub(super) stale_evictions: AtomicU64,
    /// Checkouts served from the pool, counting actual connection reuse.
    pub(super) pool_reuse_total: AtomicU64,
    /// Checkout failures to obtain sole ownership after the bounded retry budget.
    /// An extra retained Arc can cause this fallback to a fresh connection. Retries
    /// that succeed are counted separately in `unwrap_retry_total`.
    pub(super) try_unwrap_fail_total: AtomicU64,
    /// Checkouts whose `Arc::try_unwrap` needed at least one retry but then succeeded —
    /// the tokio guard drop-order window (permit released before the guard's Arc field is
    /// dropped), not a leaked reference. Kept observable so the transient rate is visible
    /// rather than silently absorbed: a sharp rise here means lock-release/pickup
    /// contention worth looking at, even though reuse itself still succeeded.
    pub(super) unwrap_retry_total: AtomicU64,
    /// Connections handed to the reaper (checkin accepted). Reaper supervision counters
    /// (spawned/deaths — the "alive" observable) are process-wide statics: `reaper_counters`.
    pub(super) checkin_total: AtomicU64,
    /// Successful fresh connections after a pool miss or stale-reuse retry.
    pub(super) fresh_connect_total: AtomicU64,
    /// idle connections evicted by the pool because the idle set was over the
    /// ceiling. Counted by the watcher when its pickup sender is dropped without a
    /// pickup (the eviction arrives there; see `watch_idle_connection`). Shared with
    /// every watcher of this pool through the same `Arc` the reaper items carry -- per
    /// pool, not a process static, so concurrent test pools do not see each other's
    /// evictions.: the owned pool has no ghost entries, so every eviction is a live
    /// connection and every one is counted.
    pub(super) lru_evictions: Arc<AtomicU64>,
    /// Configured idle ceiling, exposed in the pool-health snapshot.
    idle_ceiling: usize,
    /// whether `idle_ceiling` came from `OXO_EDGE_FRAME_POOL_IDLE` or from
    /// `frame_pool::default_idle_ceiling`; on `/pool-health` as `frame_pool_idle_source`.
    idle_ceiling_source: IdleCeilingSource,
    /// how long `checkout` waits for a transient extra reference to clear
    /// (`UNWRAP_WAIT_BUDGET_DEFAULT` unless `OXO_EDGE_UNWRAP_WAIT_MS` said otherwise);
    /// on `/pool-health` as `unwrap_wait_budget_ms`.
    unwrap_wait_budget: Duration,
    /// wall time checkouts spent waiting in the unwrap loop, summed over the
    /// checkouts that retried or gave up (`unwrap_retry_total + try_unwrap_fail_total`
    /// is the count that pairs with it), and the largest single wait.
    unwrap_wait_ns: AtomicU64,
    unwrap_wait_max_ns: AtomicU64,
    /// Optional supervised reaper, initialized on first checkin inside the edge
    /// runtime. It drives the idle watchers without spawning a task per checkin.
    reaper_tx: OnceLock<tokio::sync::mpsc::UnboundedSender<WatchItem>>,
    /// Test-only leak injection for the reuse-collapse positive control: when armed, the
    /// NEXT checkin on THIS pool stashes an extra `Arc` clone of the connection in the slot
    /// below, reproducing the defect (a reference that never goes away) as opposed to
    /// the tokio guard drop-order window (a reference already on its way out). Keeping the
    /// clone alive in the slot is what makes it persistent. Per-pool rather than a global:
    /// `#[test]`s share a process and run concurrently, so a static arm is consumed by
    /// whichever pool checks in first (the same hazard `reaper_enabled` documents).
    #[cfg(test)]
    pub(super) leak_inject_arm: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    #[allow(clippy::type_complexity)]
    pub(super) leak_inject: std::sync::Mutex<Option<Arc<AsyncMutex<PooledConn>>>>,
    /// test-only: pin THIS pool's checkin path (1 = per-checkin spawn, 2 = reaper,
    /// 0 = follow `reaper_enabled`). `REAPER_TEST_FORCE` is process-wide and latched
    /// by three tests that never clear it, so a "spawn path" test could not otherwise be
    /// sure which path it ran.
    #[cfg(test)]
    pub(super) force_path: std::sync::atomic::AtomicU8,
}

/// Checkin message containing the guard and notification channels. Do not retain
/// another connection Arc: checkout requires sole ownership for `Arc::try_unwrap`.
struct WatchItem {
    meta: ConnectionMeta,
    guard: tokio::sync::OwnedMutexGuard<PooledConn>,
    notify_evicted: Arc<tokio::sync::Notify>,
    watch_use: tokio::sync::oneshot::Receiver<bool>,
    drain: watch::Receiver<bool>,
    /// the pool's eviction counter, so the reaper path counts like the spawn path.
    evictions: Arc<AtomicU64>,
}

/// Maximum checkout wait for the watcher to drop its final Arc reference.
/// Duration::ZERO permits one attempt without waiting. Longer budgets yield
/// before using bounded sleeps, allowing a descheduled holder to finish.
pub(super) const UNWRAP_WAIT_BUDGET_DEFAULT: Duration = Duration::from_millis(20);

/// Early retries yield; later retries sleep for a millisecond so a descheduled
/// guard holder can finish dropping its Arc without a busy loop.
const UNWRAP_YIELD_ATTEMPTS: usize = 64;
const UNWRAP_SLEEP_STEP: Duration = Duration::from_millis(1);

/// Pure parse of `OXO_EDGE_UNWRAP_WAIT_MS`: unset or empty is the default, `0` is
/// one attempt, a positive integer is milliseconds. Resolved once in
/// `platform::config::run_with_cli` and threaded into the pool; the pool reads no env.
pub(super) fn parse_unwrap_wait_ms(raw: Option<&str>) -> Result<Duration, String> {
    match raw.map(str::trim) {
        None | Some("") => Ok(UNWRAP_WAIT_BUDGET_DEFAULT),
        Some(v) => v
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|_| format!("OXO_EDGE_UNWRAP_WAIT_MS={v:?}: expected a whole number of milliseconds (0 = one attempt)")),
    }
}

impl WorkerFramePool {
    /// Construct a pool with one aggregate idle ceiling across the edge process.
    /// `run_with_cli` resolves the ceiling and its source, validates `OXO_EDGE_POOL`,
    /// and checks the process file-descriptor budget before `--check-config` returns.
    /// This constructor reads no environment variables, so the boot notice and
    /// `/pool-health` report the same resolved values.
    pub(super) fn from_ceiling(
        size: usize,
        source: IdleCeilingSource,
        unwrap_wait_budget: Duration,
    ) -> Self {
        Self::with_size(size.max(1), source, unwrap_wait_budget)
    }

    /// Test constructor with a fixed default idle ceiling and no environment reads.
    #[cfg(test)]
    pub(super) fn new(worker_count: usize) -> Self {
        // test-only: the stress instrument's measurement arm sets
        // OXO_EDGE_UNWRAP_WAIT_MS on the test binary to run the whole suite at a
        // different budget; production resolves the same variable in run_with_cli.
        Self::from_ceiling(
            super::frame_pool::default_idle_ceiling(worker_count),
            IdleCeilingSource::Default,
            Self::test_budget(),
        )
    }

    /// test-only: the budget every test constructor uses unless a test names its
    /// own; OXO_EDGE_UNWRAP_WAIT_MS on the test binary overrides it so the stress
    /// instrument's measurement arm can run the whole suite at a long budget.
    #[cfg(test)]
    fn test_budget() -> Duration {
        parse_unwrap_wait_ms(std::env::var("OXO_EDGE_UNWRAP_WAIT_MS").ok().as_deref())
            .expect("OXO_EDGE_UNWRAP_WAIT_MS on the test binary must parse")
    }

    /// test-only: one worker, default ceiling, an explicit unwrap budget.
    #[cfg(test)]
    pub(super) fn with_unwrap_budget(budget: Duration) -> Self {
        Self::from_ceiling(
            super::frame_pool::default_idle_ceiling(1),
            IdleCeilingSource::Default,
            budget,
        )
    }

    /// test-only: the two unwrap counters, for assertion messages. A checkout that
    /// returns None is the transient only if `try_unwrap_fail_total` moved; printing
    /// both on every checkout assertion is what makes a red run counter-confirmed
    /// instead of inferred.
    #[cfg(test)]
    pub(super) fn unwrap_diag(&self) -> String {
        format!(
            "try_unwrap_fail_total={} unwrap_retry_total={}",
            self.try_unwrap_fail_total.load(Ordering::Relaxed),
            self.unwrap_retry_total.load(Ordering::Relaxed),
        )
    }

    /// test-only: build a pool with an explicit ceiling, source `env`. Nothing in
    /// this file reads process env, so concurrent `#[test]`s cannot race each other.
    #[cfg(test)]
    pub(super) fn with_idle_ceiling(_worker_count: usize, idle: usize) -> Self {
        Self::with_size(idle.max(1), IdleCeilingSource::Env, Self::test_budget())
    }

    fn with_size(size: usize, source: IdleCeilingSource, unwrap_wait_budget: Duration) -> Self {
        Self {
            pool: Arc::new(ConnectionPool::new(size)),
            next_id: AtomicI32::new(1),
            stale_evictions: AtomicU64::new(0),
            pool_reuse_total: AtomicU64::new(0),
            try_unwrap_fail_total: AtomicU64::new(0),
            unwrap_retry_total: AtomicU64::new(0),
            checkin_total: AtomicU64::new(0),
            fresh_connect_total: AtomicU64::new(0),
            lru_evictions: Arc::new(AtomicU64::new(0)),
            idle_ceiling: size,
            idle_ceiling_source: source,
            unwrap_wait_budget,
            unwrap_wait_ns: AtomicU64::new(0),
            unwrap_wait_max_ns: AtomicU64::new(0),
            reaper_tx: OnceLock::new(),
            #[cfg(test)]
            leak_inject_arm: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            leak_inject: std::sync::Mutex::new(None),
            #[cfg(test)]
            force_path: std::sync::atomic::AtomicU8::new(0),
        }
    }

    /// Pool-health JSON for the admin endpoint, including reuse and reaper counters.
    pub(super) fn health_json(&self) -> String {
        // `pool_impl` identifies the implementation. `idle_high_water` is clipped at
        // ceiling + 1, so it describes the working set only below that bound. Lock
        // counters expose contention; `frame_pool_idle_source` identifies the setting.
        format!(
            "{{\"pool_reuse_total\":{},\"fresh_connect_total\":{},\"stale_evictions\":{},\"try_unwrap_fail_total\":{},\"unwrap_retry_total\":{},\"checkin_total\":{},\"lru_evictions\":{},\"frame_pool_idle\":{},\"pool_impl\":\"{}\",\"idle_high_water\":{},\"pool_lock_contended_total\":{},\"pool_lock_wait_ns\":{},\"frame_pool_idle_source\":\"{}\",\"unwrap_wait_budget_ms\":{},\"unwrap_wait_ns\":{},\"unwrap_wait_max_ns\":{}}}\n",
            self.pool_reuse_total.load(Ordering::Relaxed),
            self.fresh_connect_total.load(Ordering::Relaxed),
            self.stale_evictions.load(Ordering::Relaxed),
            self.try_unwrap_fail_total.load(Ordering::Relaxed),
            self.unwrap_retry_total.load(Ordering::Relaxed),
            self.checkin_total.load(Ordering::Relaxed),
            self.lru_evictions.load(Ordering::Relaxed),
            self.idle_ceiling,
            "owned",
            self.pool.idle_high_water(),
            self.pool.lock_contended_total.load(Ordering::Relaxed),
            self.pool.lock_wait_ns.load(Ordering::Relaxed),
            self.idle_ceiling_source.as_str(),
            self.unwrap_wait_budget.as_millis(),
            self.unwrap_wait_ns.load(Ordering::Relaxed),
            self.unwrap_wait_max_ns.load(Ordering::Relaxed),
        )
    }

    /// Try to check out a live pooled connection for `worker_idx`. Returns `None` if the
    /// pool is empty for that worker or the checked-out connection failed the liveness
    /// probe (in which case it is dropped/closed).
    async fn checkout(&self, worker_idx: usize) -> Option<PooledConn> {
        let key = worker_idx as u64;
        let mut arc = self.pool.get(&key)?;
        // Wait for the watcher task to release the lock (it drops the guard when `get`
        // fires its pickup notification), then take sole ownership.
        {
            let _ = arc.lock().await;
        }
        // A free lock does not imply that the watcher's Arc has been dropped.
        // `OwnedMutexGuard::drop` releases the semaphore before its `lock` field is
        // dropped, so a woken checkout can briefly observe two strong references.
        // Retry within a time budget to allow that drop, including thread descheduling.
        // Persistent extra references exhaust the budget and increment the failure
        // counter. Separate retry and wait counters expose transient contention.
        let mut attempts = 0usize;
        let mut started: Option<std::time::Instant> = None;
        let conn = loop {
            match Arc::try_unwrap(arc) {
                Ok(m) => break m.into_inner(),
                Err(back) => {
                    let t0 = *started.get_or_insert_with(std::time::Instant::now);
                    let waited = t0.elapsed();
                    if waited >= self.unwrap_wait_budget {
                        self.try_unwrap_fail_total.fetch_add(1, Ordering::Relaxed);
                        self.record_unwrap_wait(waited);
                        eprintln!(
                            "oxo_edge_pool_notice unwrap gave up after {} us (budget {} ms, {} attempts): the pooled connection is dropped and the request reconnects; try_unwrap_fail_total={} unwrap_retry_total={}",
                            waited.as_micros(),
                            self.unwrap_wait_budget.as_millis(),
                            attempts + 1,
                            self.try_unwrap_fail_total.load(Ordering::Relaxed),
                            self.unwrap_retry_total.load(Ordering::Relaxed),
                        );
                        return None;
                    }
                    arc = back;
                    attempts += 1;
                    if attempts <= UNWRAP_YIELD_ATTEMPTS {
                        tokio::task::yield_now().await;
                    } else {
                        tokio::time::sleep(UNWRAP_SLEEP_STEP).await;
                    }
                }
            }
        };
        if let Some(t0) = started {
            // Once per checkout that retried, never per attempt (the analyzers' 1e-4
            // tolerance is calibrated on checkouts).
            let waited = t0.elapsed();
            self.unwrap_retry_total.fetch_add(1, Ordering::Relaxed);
            self.record_unwrap_wait(waited);
            // Rare in production (~1 in 3 million check-ins); the measurement arm
            // reads these lines to size the budget.
            eprintln!(
                "oxo_edge_pool_notice unwrap recovered after {} us ({} attempts, budget {} ms)",
                waited.as_micros(),
                attempts,
                self.unwrap_wait_budget.as_millis(),
            );
        }
        if is_stream_live(&conn.stream) {
            self.pool_reuse_total.fetch_add(1, Ordering::Relaxed);
            Some(conn)
        } else {
            None // closed/dirty — drop it
        }
    }

    /// the wait a checkout spent in the unwrap loop, summed and as a running max.
    fn record_unwrap_wait(&self, waited: Duration) {
        let ns = u64::try_from(waited.as_nanos()).unwrap_or(u64::MAX);
        self.unwrap_wait_ns.fetch_add(ns, Ordering::Relaxed);
        self.unwrap_wait_max_ns.fetch_max(ns, Ordering::Relaxed);
    }

    /// Return a connection to the pool for reuse, spawning the watcher task. The caller
    /// guarantees the connection is at a clean frame boundary with an empty read buffer.
    fn checkin(&self, worker_idx: usize, conn: PooledConn, drain: watch::Receiver<bool>) {
        // Defense in depth for the put-back invariant: a connection with buffered
        // surplus is dirty ("an idle worker never speaks first") and is dropped here
        // even if a caller forgot the reusable check. A runtime guard rather than a
        // debug_assert so the SAME behavior holds (and is testable) in every build.
        if conn.rbuf.has_surplus() {
            return; // drop closes it
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let meta = ConnectionMeta::new(worker_idx as u64, id);
        let arc = Arc::new(AsyncMutex::new(conn));
        // Test-only injection of the exact defect: a PERSISTENT extra reference to the
        // pooled connection. The bounded retry at checkout must never resolve this, so the
        // tripwire still fires — the positive control that proves the retry narrowed the
        // counter to real reuse collapse instead of muting it. Inert in non-test builds.
        #[cfg(test)]
        if self.leak_inject_arm.swap(false, Ordering::Relaxed) {
            *self.leak_inject.lock().unwrap() = Some(arc.clone());
        }
        // Lock before put so the watcher owns the guard and `checkout` blocks on it.
        let guard = arc.clone().try_lock_owned().expect("freshly created mutex");
        let (notify_evicted, watch_use) = self.pool.put(&meta, arc);
        self.checkin_total.fetch_add(1, Ordering::Relaxed);
        // With `OXO_HOP_REAPER=1`, hand the watch future to the supervised reaper.
        // Otherwise spawn one watcher task per checkin.
        let use_reaper = {
            #[cfg(test)]
            {
                match self.force_path.load(Ordering::Relaxed) {
                    1 => false,
                    2 => true,
                    _ => reaper_enabled(),
                }
            }
            #[cfg(not(test))]
            {
                reaper_enabled()
            }
        };
        let evictions = self.lru_evictions.clone();
        if !use_reaper {
            let pool = self.pool.clone();
            tokio::spawn(async move {
                watch_idle_connection(
                    pool,
                    meta,
                    guard,
                    notify_evicted,
                    watch_use,
                    drain,
                    evictions,
                )
                .await;
            });
            return;
        }
        let tx = self.reaper_tx.get_or_init(|| {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            spawn_supervised_reaper(self, rx);
            tx
        });
        if let Err(send_err) = tx.send(WatchItem {
            meta,
            guard,
            notify_evicted,
            watch_use,
            drain,
            evictions,
        }) {
            // A closed reaper channel must not leave an unwatched idle connection in
            // the pool. Remove it before dropping the returned guard, which releases
            // the lock. The failure counter makes this condition observable.
            let item = send_err.0;
            self.pool.pop_closed(&item.meta);
        }
    }
}

/// Boot-time reaper toggle, read once. Disabled unless `OXO_HOP_REAPER=1`.
fn reaper_enabled() -> bool {
    // Test-only force: the reaper battery must exercise the reaper path regardless of
    // the default (env + OnceLock are process-wide and race across #[test]s).
    #[cfg(test)]
    if REAPER_TEST_FORCE.load(Ordering::Relaxed) {
        return true;
    }
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("OXO_HOP_REAPER").as_deref() == Ok("1"))
}

#[cfg(test)]
static REAPER_TEST_FORCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// supervisor for the per-pool reaper. Respawns the reaper on panic (a dead
/// reaper would silently void edge-closes-first and reopen the stale-reuse race);
/// deaths are counted and the spawn count is the "reaper alive" observable
/// (alive == spawned > deaths). The mpsc receiver survives panics behind an async mutex.
fn spawn_supervised_reaper(
    pool: &WorkerFramePool,
    rx: tokio::sync::mpsc::UnboundedReceiver<WatchItem>,
) {
    let conns = pool.pool.clone();
    // The receiver must SURVIVE a reaper panic (a panicking task drops what it owns) —
    // it lives behind an async mutex the supervisor re-locks on respawn.
    let rx = Arc::new(AsyncMutex::new(rx));
    reaper_counters().spawned.fetch_add(1, Ordering::Relaxed);
    tokio::spawn(async move {
        loop {
            let handle = tokio::spawn(run_reaper(conns.clone(), rx.clone()));
            match handle.await {
                Ok(()) => break, // clean exit: channel closed (pool dropped)
                Err(join_err) => {
                    reaper_counters().deaths.fetch_add(1, Ordering::Relaxed);
                    eprintln!("oxo_edge_hop_warning reaper died ({join_err}); respawning");
                    reaper_counters().spawned.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });
}

/// Process-wide reaper supervision counters (statics so watch futures and the supervisor
/// need no back-reference to the pool struct; one edge process has one logical reaper set).
pub(super) struct ReaperCounters {
    pub(super) spawned: AtomicU64,
    pub(super) deaths: AtomicU64,
}

pub(super) fn reaper_counters() -> &'static ReaperCounters {
    static C: OnceLock<ReaperCounters> = OnceLock::new();
    C.get_or_init(|| ReaperCounters {
        spawned: AtomicU64::new(0),
        deaths: AtomicU64::new(0),
    })
}

/// register the production pool for admin `/pool-health` reads. One edge process
/// has exactly one `WorkerFramePool` (proxy.rs constructs it once), so a process-wide
/// static is the same idiom as `reaper_counters`; tests build unregistered pools and
/// are unaffected. First registration wins (set-once); re-registration is a no-op.
static ADMIN_POOL: OnceLock<Arc<WorkerFramePool>> = OnceLock::new();

pub(super) fn register_admin_pool(pool: &Arc<WorkerFramePool>) {
    let _ = ADMIN_POOL.set(pool.clone());
}

/// The admin `/pool-health` body. `registered:false` (with zeroed counters absent)
/// distinguishes "no frame pool exists" (HTTP hop, or before proxy construction) from
/// "pool exists and has done nothing" — the reuse gate must never read an absent pool
/// as a clean 0/0 pass.
pub(super) fn admin_pool_health_json() -> String {
    match ADMIN_POOL.get() {
        Some(pool) => {
            let body = pool.health_json();
            format!(
                "{{\"registered\":true,{}",
                body.trim_start().trim_start_matches('{')
            )
        }
        None => "{\"registered\":false}\n".to_string(),
    }
}

/// the consolidated reaper — one task drives ALL idle-connection watch futures
/// via FuturesUnordered, same 4-arm select semantics per connection as the per-task
/// watcher it replaces. `biased` toward ready watch futures so a pickup release (guard
/// drop) is polled BEFORE new checkins are accepted — a pooled checkout's latency is
/// bounded by O(ready releases), never by the checkin queue depth (constraint; the
/// burst test pins the bound). Empty set = plain recv await (no busy loop). Drain: each
/// watch future fires its own drain arm; the reaper itself exits when the channel closes
/// (pool dropped), draining any remaining futures first.
async fn run_reaper(
    pool: Arc<ConnectionPool<Arc<AsyncMutex<PooledConn>>>>,
    rx: Arc<AsyncMutex<tokio::sync::mpsc::UnboundedReceiver<WatchItem>>>,
) {
    let mut rx = rx.lock().await; // sole consumer; the lock exists for panic-respawn only
    let mut watches = FuturesUnordered::new();
    loop {
        if watches.is_empty() {
            match rx.recv().await {
                Some(item) => {
                    #[cfg(test)]
                    reaper_test_panic_point();
                    watches.push(watch_item(pool.clone(), item))
                }
                None => return,
            }
        } else {
            tokio::select! {
                biased;
                Some(()) = watches.next() => {}
                item = rx.recv() => match item {
                    Some(item) => {
                        #[cfg(test)]
                        reaper_test_panic_point();
                        watches.push(watch_item(pool.clone(), item))
                    }
                    None => {
                        while watches.next().await.is_some() {}
                        return;
                    }
                },
            }
        }
    }
}

async fn watch_item(pool: Arc<ConnectionPool<Arc<AsyncMutex<PooledConn>>>>, item: WatchItem) {
    watch_idle_connection(
        pool,
        item.meta,
        item.guard,
        item.notify_evicted,
        item.watch_use,
        item.drain,
        item.evictions,
    )
    .await;
}

/// Test-only panic injection for the kill-the-reaper supervision test (constraint:
/// a dead reaper must respawn and reaping must resume). Inert in non-test builds.
#[cfg(test)]
pub(super) static REAPER_PANIC_INJECT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
fn reaper_test_panic_point() {
    if REAPER_PANIC_INJECT.swap(false, Ordering::Relaxed) {
        panic!("test-injected reaper panic");
    }
}

/// The per-idle-connection watcher: hold the lock and wait for the connection to be
/// picked up, evicted, drained, or to go bad (peer close / unexpected data / timeout).
async fn watch_idle_connection(
    pool: Arc<ConnectionPool<Arc<AsyncMutex<PooledConn>>>>,
    meta: ConnectionMeta,
    mut guard: tokio::sync::OwnedMutexGuard<PooledConn>,
    notify_evicted: Arc<tokio::sync::Notify>,
    watch_use: tokio::sync::oneshot::Receiver<bool>,
    mut drain: watch::Receiver<bool>,
    evictions: Arc<AtomicU64>,
) {
    let mut probe = [0u8; 1];
    tokio::select! {
        biased;
        picked = watch_use => {
            match picked {
                Ok(_) => {
                    // Picked up by checkout: release the lock, do NOT close.
                }
                Err(_) => {
                    // the sender was dropped WITHOUT a pickup. Both pools evict
                    // synchronously inside `put` and drop the victim's pickup sender
                    // (pingora in `pop_evicted`, the owned pool after its lock), so an
                    // eviction always arrives HERE under this biased ordering, and the
                    // `notify_evicted` arm below is unreachable for evictions. The
                    // first gate run found that: seven checkins at ceiling four
                    // counted zero. Count it and pop, the same as the arm below.
                    evictions.fetch_add(1, Ordering::Relaxed);
                    pool.pop_closed(&meta);
                }
            }
        }
        _ = notify_evicted.notified() => {
            // LRU-evicted (kept for a pool that signals eviction before dropping the
            // sender); counted the same way so the two arms cannot disagree.
            evictions.fetch_add(1, Ordering::Relaxed);
            pool.pop_closed(&meta);
        }
        _ = drain.changed() => {
            // Drain: proactively empty the idle pool.
            pool.pop_closed(&meta);
        }
        read = timeout(POOL_IDLE_TIMEOUT, guard.stream.read(&mut probe)) => {
            // Any of: peer closed (Ok(0)), unexpected data on an idle conn (Ok(>0)),
            // read error, or idle timeout (Err) → close.
            let _ = read;
            pool.pop_closed(&meta);
        }
    }
}

/// Non-blocking checkout probe: idle workers must not send unsolicited bytes.
/// `try_read` consults Tokio's cached readiness before issuing a socket read.
/// WouldBlock permits reuse; EOF or data discards the connection. Consuming a
/// dirty byte is harmless because that connection is closed.
///
/// Readiness can race peer activity. The exchange error classification handles
/// write failures and EOF after checkout; this probe alone cannot prove that a
/// peer will remain live through the next write.
fn is_stream_live(stream: &UnixStream) -> bool {
    let mut byte = [0u8; 1];
    match stream.try_read(&mut byte) {
        // WouldBlock: nothing pending → healthy idle connection (no syscall issued
        // when the reactor had no cached readiness).
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
        // 0 = peer closed; >0 = unexpected data; any other error = dead.
        _ => false,
    }
}

/// Build a request frame from borrowed session data, trusted metadata, sanitized
/// application headers and the buffered body. Identity uses native frame fields,
/// so reserved `x-oxo-*` headers are excluded. The keep-mask avoids an intermediate
/// owned header vector; tests compare the encoded bytes with the owned builder.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_request_frame_bytes_into(
    out: &mut Vec<u8>,
    session: &Session,
    raw_headers: &[crate::LoweredHeader<'_>],
    plan: &crate::FrameHeaderPlan,
    body: &[u8],
    url_scheme: &str,
    server_name: &str,
    server_port: u16,
    remote_addr: &str,
) -> Result<(), u16> {
    let req = session.req_header();
    let path_and_query = req.uri.path_and_query().ok_or(400u16)?;
    assemble_request_frame_bytes_into(
        out,
        req.method.as_str(),
        path_and_query.path(),
        path_and_query.query().unwrap_or(""),
        req.uri.authority().map(|a| a.as_str()),
        raw_headers,
        plan,
        body,
        url_scheme,
        server_name,
        server_port,
        remote_addr,
    )
}

/// Session-free encoding core for byte-parity tests against the owned builder.
#[allow(clippy::too_many_arguments)]
fn assemble_request_frame_bytes_into(
    out: &mut Vec<u8>,
    method: &str,
    path: &str,
    query: &str,
    authority: Option<&str>,
    raw_headers: &[crate::LoweredHeader<'_>],
    plan: &crate::FrameHeaderPlan,
    body: &[u8],
    url_scheme: &str,
    server_name: &str,
    server_port: u16,
    remote_addr: &str,
) -> Result<(), u16> {
    let scheme = match url_scheme {
        "https" => Scheme::Https,
        _ => Scheme::Http,
    };
    // Mirror the owned builder's Host synthesis: emitted FIRST (its `insert(0, …)`), only
    // when the post-strip survivor set lacks host AND the request carries an authority.
    let synth_host = if plan.has_host { None } else { authority };
    fn has_x_oxo_prefix(name: &str) -> bool {
        const PREFIX: &[u8] = b"x-oxo-";
        let b = name.as_bytes();
        b.len() >= PREFIX.len() && b[..PREFIX.len()].eq_ignore_ascii_case(PREFIX)
    }
    // The x-oxo skip is the owned builder's allocation-free defence pass. Sanitize
    // already strips the prefix, so in the active path it removes nothing; if a sanitize
    // regression ever let one through, the emitted count would fall short of the plan's
    // count and encode_request_ref FAILS CLOSED (400) — a leaked identity header can
    // never reach the worker, it can only break the request loudly.
    let survivors = raw_headers
        .iter()
        .enumerate()
        .filter(|(i, h)| plan.keeps(*i) && !has_x_oxo_prefix(h.name()))
        .map(|(_, h)| (h.name(), h.value()));
    // the scheduler-delay stamp — appended AFTER the defence pass on purpose:
    // this is the EDGE'S OWN header, in the reserved namespace the worker strips before
    // any app sees it (env-parity unaffected). Env-gated (OXO_HOP_STAMP=1,
    // diagnostic, rides the hop-timing feature); CLOCK_MONOTONIC nanos at frame build,
    // valid cross-process on one boot; the worker differences it at first read to
    // measure true dispatch-to-fiber-running delay.
    #[cfg(feature = "hop-timing")]
    let stamp: Option<String> = if crate::hop_timing::stamp_enabled() {
        Some(crate::hop_timing::monotonic_nanos().to_string())
    } else {
        None
    };
    #[cfg(not(feature = "hop-timing"))]
    let stamp: Option<String> = None;
    let stamp_hdr = stamp.as_deref().map(|v| ("x-oxo-ts0", v));
    let headers = synth_host
        .map(|a| ("host", a))
        .into_iter()
        .chain(survivors)
        .chain(stamp_hdr);
    let header_count =
        plan.survivor_count + usize::from(synth_host.is_some()) + usize::from(stamp.is_some());
    let frame_ref = hop_frame::RequestFrameRef {
        method,
        path,
        query,
        server_name,
        server_port,
        scheme,
        remote_addr,
        body,
    };
    hop_frame::encode_request_ref_into(out, &frame_ref, header_count, headers).map_err(|_| 400u16)
}

/// Test helper returning a fresh Vec for comparison with the reusable-buffer API.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn assemble_request_frame_bytes(
    method: &str,
    path: &str,
    query: &str,
    authority: Option<&str>,
    raw_headers: &[crate::LoweredHeader<'_>],
    plan: &crate::FrameHeaderPlan,
    body: &[u8],
    url_scheme: &str,
    server_name: &str,
    server_port: u16,
    remote_addr: &str,
) -> Result<Vec<u8>, u16> {
    let mut out = Vec::new();
    assemble_request_frame_bytes_into(
        &mut out,
        method,
        path,
        query,
        authority,
        raw_headers,
        plan,
        body,
        url_scheme,
        server_name,
        server_port,
        remote_addr,
    )?;
    Ok(out)
}

// Independent owned request builder for byte-parity tests. It accepts the same
// session fields as the borrowed pipeline, preserving a separate construction
// path for checking wire format and Rack environment parity.
#[cfg(test)]
fn assemble_request_frame_owned(
    method: &str,
    path: &str,
    query: &str,
    authority: Option<&str>,
    sanitized_headers: Vec<(String, String)>,
    body: Vec<u8>,
    metadata: &crate::TrustedHopMetadata,
) -> RequestFrame {
    let path = path.to_string();
    let query = query.to_string();
    let has_host = sanitized_headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"));
    // Identity travels in native fields. Strip any reserved metadata headers as
    // defense in depth even though sanitization already removes them.
    fn has_x_oxo_prefix(name: &str) -> bool {
        const PREFIX: &[u8] = b"x-oxo-";
        let b = name.as_bytes();
        b.len() >= PREFIX.len() && b[..PREFIX.len()].eq_ignore_ascii_case(PREFIX)
    }
    let mut headers = sanitized_headers;
    headers.retain(|(name, _)| !has_x_oxo_prefix(name));
    // Mirror the HTTP hop's Host synthesis from the authority when absent (H2-no-Host).
    if !has_host {
        if let Some(authority) = authority.map(|a| a.to_string()) {
            headers.insert(0, ("host".to_string(), authority));
        }
    }
    let scheme = match metadata.url_scheme.as_str() {
        "https" => Scheme::Https,
        _ => Scheme::Http,
    };
    RequestFrame {
        method: method.to_string(),
        path,
        query,
        server_name: metadata.server_name.clone(),
        server_port: metadata.server_port,
        scheme,
        remote_addr: metadata.remote_addr.clone(),
        headers,
        body,
    }
}

/// Caps for decoding the WORKER'S RESPONSE frames. These bound the response, so they use
/// the response limits (`MAX_RESPONSE_*`), NOT the request `max_body` — a response body
/// (or chunk) is legitimately far larger than an inbound request body cap. (Conflating
/// the two once capped a ~150-byte env-echo response at a 16-byte request limit → 502.)
fn response_frame_caps() -> FrameCaps {
    FrameCaps {
        max_header_bytes: MAX_RESPONSE_HEADER_BYTES as u32,
        max_headers: 100,
        max_body_bytes: u32::try_from(MAX_RESPONSE_BYTES).unwrap_or(u32::MAX),
    }
}

/// Per-worker in-flight gauges and dispatch selection, available in every build.
/// Detailed dispatch counters and histograms require `hop-timing`.
///
/// An RAII guard covers one committed worker attempt, from checkout to completion,
/// error or cancellation. Stale-reuse re-exchange retains the same guard. A
/// connection failure before commitment creates no guard for the failed worker.
pub(super) mod dispatch {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::OnceLock;
    use tokio::sync::Notify;

    pub const MAX_WORKERS: usize = 16;
    /// Depth histogram buckets: observed chosen-worker in-flight depth 0..=6, 7 = 7+.
    #[cfg(feature = "hop-timing")]
    pub const DEPTH_BUCKETS: usize = 8;

    pub struct Gauges {
        /// In every build: the least-outstanding selector's input.
        pub in_flight: [AtomicUsize; MAX_WORKERS],
        #[cfg(feature = "hop-timing")]
        pub dispatch_total: AtomicU64,
        #[cfg(feature = "hop-timing")]
        pub chosen_busy: AtomicU64,
        /// Chosen worker busy while >=1 other worker idle — the convoy signal.
        #[cfg(feature = "hop-timing")]
        pub bad_dispatch: AtomicU64,
        #[cfg(feature = "hop-timing")]
        pub depth_hist: [AtomicU64; DEPTH_BUCKETS],
    }

    pub fn gauges() -> &'static Gauges {
        static G: OnceLock<Gauges> = OnceLock::new();
        G.get_or_init(|| Gauges {
            in_flight: [const { AtomicUsize::new(0) }; MAX_WORKERS],
            #[cfg(feature = "hop-timing")]
            dispatch_total: AtomicU64::new(0),
            #[cfg(feature = "hop-timing")]
            chosen_busy: AtomicU64::new(0),
            #[cfg(feature = "hop-timing")]
            bad_dispatch: AtomicU64::new(0),
            #[cfg(feature = "hop-timing")]
            depth_hist: [const { AtomicU64::new(0) }; DEPTH_BUCKETS],
        })
    }

    /// Boot-time dispatch mode, resolved once.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum DispatchMode {
        Rr,
        LeastOutstanding,
        /// RR order, but when the RR choice is busy, promote the first idle worker (in RR
        /// order) to the front. Kills the provably-wrong busy-while-idle dispatches while
        /// preserving RR's rotation pattern.
        FreeFirst,
        /// pin each downstream HTTP/1.x connection to one worker (the Falcon
        /// discipline, source-verified in the addendum) with fewest-pins balanced
        /// assignment. The pin handling lives in send_worker_frame_to_pool; a bare
        /// candidate_order under this mode is the unkeyed-fallback order.
        Sticky,
    }

    static MODE: OnceLock<DispatchMode> = OnceLock::new();

    /// Boot-time initialization from the resolved config ladder (flag > env > default).
    /// First writer wins; the bench paths that bypass config fall back to `mode`'s
    /// env-or-default read.
    pub fn init_mode(m: DispatchMode) {
        let _ = MODE.set(m);
    }

    pub fn mode() -> DispatchMode {
        *MODE.get_or_init(|| match std::env::var("OXO_WORKER_DISPATCH").as_deref() {
            Ok("rr") => DispatchMode::Rr,
            Ok("free-first") => DispatchMode::FreeFirst,
            Ok("sticky") => DispatchMode::Sticky,
            // Least-outstanding is the default dispatch mode.
            _ => DispatchMode::LeastOutstanding,
        })
    }

    pub fn parse_mode(value: &str) -> Option<DispatchMode> {
        match value {
            "rr" => Some(DispatchMode::Rr),
            "least-outstanding" => Some(DispatchMode::LeastOutstanding),
            "free-first" => Some(DispatchMode::FreeFirst),
            "sticky" => Some(DispatchMode::Sticky),
            _ => None,
        }
    }

    // The optional per-worker cap bounds committed requests at K. Excess requests
    // park in a shared FIFO and repeat worker selection when capacity changes.
    //
    // No-lost-wakeup ordering, using SeqCst for the following atomic operations:
    // Writer (completion): decrement in_flight, then check PARKED and notify one waiter.
    // Waiter: increment PARKED, enable its Notified future, rescan in_flight for the
    // at-capacity worker set, then await only if that set is still full.
    //
    // If completion precedes the rescan, the waiter observes free capacity. If it
    // follows the rescan, the writer observes the registered waiter and notifies it.
    // Enabling before the rescan retains a permit even when notification precedes
    // the await. The uncapped path uses Relaxed in-flight counters.

    /// Requests currently parked (gauge; /ready + wake gating).
    pub static PARKED: AtomicUsize = AtomicUsize::new(0);
    /// Lifetime count of parking events, reported even without timing instrumentation.
    pub static PARK_TOTAL: AtomicU64 = AtomicU64::new(0);

    pub fn free_slot() -> &'static Notify {
        static N: OnceLock<Notify> = OnceLock::new();
        N.get_or_init(Notify::new)
    }

    static CAP: OnceLock<Option<usize>> = OnceLock::new();
    /// Latched when a cap is configured, enabling completion-side wake checks.
    /// The uncapped completion path reads only this Relaxed flag. Tests can set it
    /// directly because the cap configuration itself initializes once per process.
    static CAPPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    pub fn capped() -> bool {
        CAPPED.load(Ordering::Relaxed)
    }

    #[cfg(all(test, feature = "hop-timing"))]
    pub fn set_capped_for_tests(on: bool) {
        CAPPED.store(on, Ordering::SeqCst);
    }

    /// Boot-time initialization from the resolved config ladder (flag > env > default
    /// OFF). First writer wins, like `init_mode`.
    pub fn init_cap(k: Option<usize>) {
        if k.is_some() {
            CAPPED.store(true, Ordering::SeqCst);
        }
        let _ = CAP.set(k);
    }

    /// The resolved cap. Bench paths that bypass config fall back to the env read,
    /// mirroring `mode`. None = uncapped (the default).
    pub fn cap() -> Option<usize> {
        *CAP.get_or_init(|| {
            let k = std::env::var("OXO_EDGE_WORKER_CAP")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|k| *k >= 1);
            if k.is_some() {
                CAPPED.store(true, Ordering::SeqCst);
            }
            k
        })
    }

    /// park guard: decrements PARKED on every exit, including cancellation of the
    /// parked future (the same RAII discipline InFlightGuard uses for the gauges).
    pub struct ParkGuard;
    impl ParkGuard {
        pub fn enter() -> ParkGuard {
            PARKED.fetch_add(1, Ordering::SeqCst); // Register before checking capacity.
            PARK_TOTAL.fetch_add(1, Ordering::Relaxed);
            ParkGuard
        }
    }
    impl Drop for ParkGuard {
        fn drop(&mut self) {
            PARKED.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Check whether any worker in the failed pass's capacity mask has a free slot.
    /// Use SeqCst loads for the wakeup protocol rather than the Relaxed depth helper.
    pub fn any_admittable(mask: u32, k: usize) -> bool {
        let g = gauges();
        (0..MAX_WORKERS)
            .filter(|i| mask & (1u32 << i) != 0)
            .any(|i| g.in_flight[i].load(Ordering::SeqCst) < k)
    }

    // Sticky per-connection worker affinity, enabled only by Sticky mode.
    // Assign new keys to the worker with fewest pins, using in-flight depth and
    // worker index as tie-breakers. Re-pin only after connection failure, never
    // merely because the selected worker is full. Requests without an eligible
    // connection key use least-outstanding dispatch and a separate counter.

    /// Sticky lookup counters, available in every build.
    pub static STICKY_HIT_TOTAL: AtomicU64 = AtomicU64::new(0);
    pub static STICKY_MISS_TOTAL: AtomicU64 = AtomicU64::new(0);
    /// Requests without an eligible key use least-outstanding and count neither as hits nor misses.
    pub static STICKY_FALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);
    pub static STICKY_EVICT_TOTAL: AtomicU64 = AtomicU64::new(0);

    /// Per-worker pinned-connection counts used by assignment and exposed in /ready.
    pub static PIN_COUNTS: [AtomicUsize; MAX_WORKERS] =
        [const { AtomicUsize::new(0) }; MAX_WORKERS];

    const STICKY_SHARDS: usize = 16;
    /// Bound stored pins per shard. At capacity the shard clears and its pin counts
    /// are removed; a later request from those connections assigns a new pin.
    pub(super) const STICKY_SHARD_MAX: usize = 4096 / STICKY_SHARDS;

    type StickyShard = std::sync::Mutex<std::collections::HashMap<u64, u8>>;

    fn sticky_shards() -> &'static [StickyShard; STICKY_SHARDS] {
        static S: OnceLock<[StickyShard; STICKY_SHARDS]> = OnceLock::new();
        S.get_or_init(|| {
            std::array::from_fn(|_| std::sync::Mutex::new(std::collections::HashMap::new()))
        })
    }

    fn sticky_shard(key: u64) -> &'static StickyShard {
        &sticky_shards()[(key as usize) % STICKY_SHARDS]
    }

    /// Assignment lock: misses are once-per-connection rare, and holding one lock
    /// across the read-counts-then-increment makes the balance invariant (max−min
    /// pins <= 1 under concurrent misses) deterministic instead of probabilistic.
    fn assign_lock() -> &'static std::sync::Mutex<()> {
        static L: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        L.get_or_init(|| std::sync::Mutex::new(()))
    }

    pub fn sticky_note_fallback() {
        STICKY_FALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed);
    }

    /// First-pass resolution for a keyed request: a hit returns the stored pin; a
    /// miss assigns the fewest-pinned worker (in-flight depth, then index, as
    /// tie-breaks), records the pin, and returns it.
    pub fn sticky_lookup_or_assign(key: u64, n: usize) -> usize {
        let len = n.min(MAX_WORKERS);
        let shard = sticky_shard(key);
        {
            let map = shard.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(&idx) = map.get(&key) {
                let idx = idx as usize;
                if idx < len {
                    STICKY_HIT_TOTAL.fetch_add(1, Ordering::Relaxed);
                    return idx;
                }
                // Stored pin outside the live worker range (pure defense — worker
                // count is boot-fixed): fall through to a fresh assignment.
            }
        }
        STICKY_MISS_TOTAL.fetch_add(1, Ordering::Relaxed);
        let _assign = assign_lock().lock().unwrap_or_else(|e| e.into_inner());
        let g = gauges();
        let idx = (0..len)
            .min_by_key(|&i| {
                (
                    PIN_COUNTS[i].load(Ordering::Relaxed),
                    g.in_flight[i].load(Ordering::Relaxed),
                    i,
                )
            })
            .unwrap_or(0);
        let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= STICKY_SHARD_MAX {
            STICKY_EVICT_TOTAL.fetch_add(map.len() as u64, Ordering::Relaxed);
            for (_, old) in map.drain() {
                let old = old as usize;
                if old < MAX_WORKERS {
                    PIN_COUNTS[old].fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
        // A raced assignment for the SAME key lands here too (both serialized by the
        // assign lock): last write wins and the loser's count is corrected, so the
        // pin-count counts stay exact.
        if let Some(prev) = map.insert(key, idx as u8) {
            let prev = prev as usize;
            if prev < MAX_WORKERS {
                PIN_COUNTS[prev].fetch_sub(1, Ordering::Relaxed);
            }
        }
        PIN_COUNTS[idx].fetch_add(1, Ordering::Relaxed);
        idx
    }

    /// Reread affinity after parking. If the entry was cleared, insert the prior
    /// pin and update its count rather than assigning a different worker.
    pub fn sticky_reread(key: u64, prior: usize) -> usize {
        let shard = sticky_shard(key);
        let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&key) {
            Some(&idx) => idx as usize,
            None => {
                map.insert(key, prior as u8);
                PIN_COUNTS[prior.min(MAX_WORKERS - 1)].fetch_add(1, Ordering::Relaxed);
                prior
            }
        }
    }

    /// Move the pin after connection failure when another worker serves the request.
    /// Do nothing if the pin already changed. Capacity alone must not trigger this.
    pub fn sticky_repin(key: u64, from: usize, to: usize) {
        let shard = sticky_shard(key);
        let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
        if map.get(&key).copied() == Some(from as u8) {
            map.insert(key, to as u8);
            PIN_COUNTS[from.min(MAX_WORKERS - 1)].fetch_sub(1, Ordering::Relaxed);
            PIN_COUNTS[to.min(MAX_WORKERS - 1)].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Candidate order under a live pin: the pinned worker first, then the rotated
    /// rest — the returned order stays the Connect-failover sequence (this module's
    /// contract), so a dead pinned worker fails over exactly like today.
    pub fn sticky_order(pinned: usize, start: usize, n: usize) -> CandidateOrder {
        let len = n.min(MAX_WORKERS);
        let mut buf = [0usize; MAX_WORKERS];
        buf[0] = pinned.min(len.saturating_sub(1));
        let mut olen = 1usize;
        for o in 0..len {
            let i = (start + o) % len;
            if i != buf[0] {
                buf[olen] = i;
                olen += 1;
            }
        }
        CandidateOrder::Ordered { buf, len: olen }
    }

    /// Per-worker pin counts serialized for /ready.
    pub fn sticky_pins_json(n: usize) -> String {
        let len = n.min(MAX_WORKERS);
        let v: Vec<String> = (0..len)
            .map(|i| PIN_COUNTS[i].load(Ordering::Relaxed).to_string())
            .collect();
        format!("[{}]", v.join(","))
    }

    /// Number of distinct connection keys currently stored.
    pub fn sticky_entries() -> usize {
        sticky_shards()
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len())
            .sum()
    }

    /// Process-wide test serialization for everything touching the global gauges,
    /// pin store, or park statics — shared across test modules so hop-timing and
    /// plain builds cannot race each other's assertions.
    #[cfg(test)]
    pub fn test_serial_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The sticky store is process-global; tests serialize on test_serial_lock and
    /// reset here.
    #[cfg(test)]
    pub fn sticky_reset_for_tests() {
        for s in sticky_shards() {
            s.lock().unwrap_or_else(|e| e.into_inner()).clear();
        }
        for c in PIN_COUNTS.iter() {
            c.store(0, Ordering::SeqCst);
        }
    }

    pub fn mode_name(m: DispatchMode) -> &'static str {
        match m {
            DispatchMode::Rr => "rr",
            DispatchMode::LeastOutstanding => "least-outstanding",
            DispatchMode::FreeFirst => "free-first",
            DispatchMode::Sticky => "sticky",
        }
    }

    /// RAII in-flight guard for one worker attempt.
    pub struct InFlightGuard {
        idx: usize,
        /// requests already in flight on this worker when this one committed —
        /// the dispatch depth, exposed for the exchange-by-depth ledger (read only by
        /// the hop-timing build).
        #[cfg_attr(not(feature = "hop-timing"), allow(dead_code))]
        pub depth: usize,
    }

    impl InFlightGuard {
        /// Test-facing uncapped admission helper. Invoke once the worker attempt
        /// commits. Counter snapshots across workers are non-atomic observations;
        /// production admission uses try_acquire.
        #[cfg(all(test, feature = "hop-timing"))]
        pub fn acquire(idx: usize, worker_count: usize) -> InFlightGuard {
            Self::try_acquire(idx, worker_count, None).expect("uncapped acquire cannot fail")
        }

        /// Try to commit an attempt. Uncapped mode increments the gauge with Relaxed
        /// ordering. Capped mode uses SeqCst CAS and succeeds only below K. A lost race
        /// returns None so the caller can return its untouched connection to the pool.
        /// Record dispatch counters only on successful admission.
        pub fn try_acquire(
            idx: usize,
            worker_count: usize,
            k: Option<usize>,
        ) -> Option<InFlightGuard> {
            // Depth-reading modes reject worker counts beyond MAX_WORKERS at boot.
            // The index clamp keeps other counting paths within the shared array.
            let idx = idx.min(MAX_WORKERS - 1);
            let g = gauges();
            let depth = match k {
                None => g.in_flight[idx].fetch_add(1, Ordering::Relaxed),
                Some(kv) => {
                    let mut cur = g.in_flight[idx].load(Ordering::SeqCst);
                    loop {
                        if cur >= kv {
                            return None;
                        }
                        match g.in_flight[idx].compare_exchange(
                            cur,
                            cur + 1,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        ) {
                            Ok(prev) => break prev,
                            Err(now) => cur = now,
                        }
                    }
                }
            };
            #[cfg(feature = "hop-timing")]
            {
                g.dispatch_total.fetch_add(1, Ordering::Relaxed);
                g.depth_hist[depth.min(DEPTH_BUCKETS - 1)].fetch_add(1, Ordering::Relaxed);
                if depth > 0 {
                    g.chosen_busy.fetch_add(1, Ordering::Relaxed);
                    let any_idle = (0..worker_count.min(MAX_WORKERS))
                        .any(|i| i != idx && g.in_flight[i].load(Ordering::Relaxed) == 0);
                    if any_idle {
                        g.bad_dispatch.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            #[cfg(not(feature = "hop-timing"))]
            {
                let _ = worker_count;
            }
            Some(InFlightGuard { idx, depth })
        }
    }

    impl Drop for InFlightGuard {
        fn drop(&mut self) {
            // With a cap, decrement using SeqCst and notify parked work; otherwise use Relaxed.
            if capped() {
                gauges().in_flight[self.idx].fetch_sub(1, Ordering::SeqCst);
                if PARKED.load(Ordering::SeqCst) > 0 {
                    free_slot().notify_one();
                }
            } else {
                gauges().in_flight[self.idx].fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Candidate order for this dispatch: least-outstanding = ascending in-flight (RR-offset
    /// tie-break via stable sort on a rotated start); free-first = RR order with the first
    /// idle worker promoted when the RR choice is busy; RR = sequential from the rotated
    /// start. Failover semantics are unchanged in every mode: the returned order IS the
    /// Connect-failover sequence.
    ///
    /// A2: zero heap allocations per request. RR yields the rotation lazily (any n —
    /// rr is the one mode allowed >MAX_WORKERS); the gauge-sorted modes fill a stack
    /// buffer (n <= MAX_WORKERS enforced at boot by read_worker_dispatch's refusal).
    pub enum CandidateOrder {
        Rotated {
            start: usize,
            n: usize,
        },
        Ordered {
            buf: [usize; MAX_WORKERS],
            len: usize,
        },
    }

    impl CandidateOrder {
        pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
            let (rot, slice): (Option<(usize, usize)>, &[usize]) = match self {
                CandidateOrder::Rotated { start, n } => (Some((*start, *n)), &[]),
                CandidateOrder::Ordered { buf, len } => (None, &buf[..*len]),
            };
            let rotated = rot
                .map(|(start, n)| (0..n).map(move |o| (start + o) % n))
                .into_iter()
                .flatten();
            rotated.chain(slice.iter().copied())
        }
    }

    pub fn candidate_order(start: usize, n: usize) -> CandidateOrder {
        candidate_order_with(start, n, mode())
    }

    /// Pure form for unit tests (the env-backed mode is a process-wide OnceLock).
    pub fn candidate_order_with(start: usize, n: usize, m: DispatchMode) -> CandidateOrder {
        if matches!(m, DispatchMode::Rr) {
            return CandidateOrder::Rotated { start, n };
        }
        // Non-rr modes are refused at boot above MAX_WORKERS (config.rs); the clamp is
        // pure defense so a misconfigured caller degrades instead of panicking.
        let len = n.min(MAX_WORKERS);
        let mut buf = [0usize; MAX_WORKERS];
        for (o, slot) in buf.iter_mut().enumerate().take(len) {
            *slot = (start + o) % n;
        }
        let g = gauges();
        let depth = |i: usize| g.in_flight[i.min(MAX_WORKERS - 1)].load(Ordering::Relaxed);
        match m {
            DispatchMode::Rr => unreachable!("handled above"),
            // under Sticky, a request that reaches the generic selector is the
            // unkeyed fallback — it takes the least-outstanding order (the pin path
            // never calls this; it builds its order via sticky_order).
            DispatchMode::LeastOutstanding | DispatchMode::Sticky => {
                buf[..len].sort_by_key(|&i| depth(i))
            }
            DispatchMode::FreeFirst => {
                if len > 0 && depth(buf[0]) > 0 {
                    if let Some(pos) = buf[..len].iter().position(|&i| depth(i) == 0) {
                        // Rotate the idle worker to the front, preserving RR order of
                        // the rest — identical to the old remove+insert semantics.
                        buf[..=pos].rotate_right(1);
                    }
                }
            }
        }
        CandidateOrder::Ordered { buf, len }
    }

    #[cfg(feature = "hop-timing")]
    pub fn report_json() -> String {
        let g = gauges();
        let hist: Vec<String> = g
            .depth_hist
            .iter()
            .enumerate()
            .map(|(b, c)| format!("\"{b}\":{}", c.load(Ordering::Relaxed)))
            .collect();
        format!(
            "{{\"mode\":\"{}\",\"dispatch_total\":{},\"chosen_busy\":{},\"bad_dispatch\":{},\"depth_hist\":{{{}}}}}",
            mode_name(mode()),
            g.dispatch_total.load(Ordering::Relaxed),
            g.chosen_busy.load(Ordering::Relaxed),
            g.bad_dispatch.load(Ordering::Relaxed),
            hist.join(",")
        )
    }
}

/// Worker implementation behind this edge. The retry policy distinguishes a native
/// worker from an async reactor: after a completed request write, zero-response-byte
/// EOF is terminal for async workers because execution may already have occurred.
/// That error must not escape into sibling failover and replay the request.
pub mod worker_kind {
    use std::sync::OnceLock;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum WorkerKind {
        Classic,
        Async,
    }

    static KIND: OnceLock<WorkerKind> = OnceLock::new();

    /// Boot-time initialization from the resolved config (read_worker_kind fails closed
    /// on an unknown value). First writer wins; paths that bypass config fall back to
    /// `kind`'s env-or-default read.
    pub fn init_kind(k: WorkerKind) {
        let _ = KIND.set(k);
    }

    pub fn kind() -> WorkerKind {
        *KIND.get_or_init(|| match std::env::var("OXO_WORKER_KIND").as_deref() {
            Ok("async") => WorkerKind::Async,
            _ => WorkerKind::Classic,
        })
    }

    pub fn is_async() -> bool {
        kind() == WorkerKind::Async
    }

    pub fn parse_kind(value: &str) -> Option<WorkerKind> {
        match value {
            "classic" => Some(WorkerKind::Classic),
            "async" => Some(WorkerKind::Async),
            _ => None,
        }
    }
}

/// Send a pre-parsed request frame to the worker fleet, streaming the response
/// downstream. Mirrors `send_worker_request_to_pool`'s failover + drain contract, adds
/// pooled reuse with the stale-reuse retry carve-out.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_worker_frame_to_pool(
    pool: &WorkerFramePool,
    sockets: &[String],
    next_worker: &AtomicUsize,
    request_bytes: &[u8],
    session: &mut Session,
    long_lived: &Arc<LongLivedRegistry>,
    drain: watch::Receiver<bool>,
    keepalive_enabled: bool,
    sticky_key: Option<u64>,
) -> Result<u16, u16> {
    if sockets.is_empty() {
        return Err(503);
    }
    let caps = response_frame_caps();
    let cap = dispatch::cap();
    // resolve the sticky pin ONCE per request (mode-gated; any other mode pays
    // one enum compare and nothing else). An unkeyed request under sticky (H2,
    // absent addr/timing) takes the counted fallback path.
    let sticky = dispatch::mode() == dispatch::DispatchMode::Sticky;
    let mut pinned: Option<(u64, usize)> = None;
    if sticky {
        match sticky_key {
            Some(key) => {
                let idx = dispatch::sticky_lookup_or_assign(key, sockets.len());
                pinned = Some((key, idx));
            }
            None => dispatch::sticky_note_fallback(),
        }
    }
    let mut woken = false;
    // barging guard: with the cap on, a fresh arrival that finds anyone
    // parked joins the park FIRST — otherwise fresh requests (no wake latency) would
    // systematically outrace woken waiters and the FIFO would be fiction. One extra
    // load, on the capped path only.
    if let Some(kv) = cap {
        if dispatch::PARKED.load(Ordering::SeqCst) > 0 {
            // Any-worker mask with the REAL cap: proceed as soon as any slot exists
            // anywhere (the selection pass below will find it), else wait our turn.
            park_for_slot(u32::MAX, kv, &drain).await?;
        }
    }
    loop {
        let start = next_worker.fetch_add(1, Ordering::Relaxed) % sockets.len();
        // Select by the configured dispatch mode. Least-outstanding orders by
        // in-flight count with round-robin tie-breaking. A pinned request tries its
        // worker first; after parking, reread the pin in case it changed.
        let order = if let Some((key, prior)) = pinned {
            let idx = if woken {
                dispatch::sticky_reread(key, prior)
            } else {
                prior
            };
            pinned = Some((key, idx));
            dispatch::sticky_order(idx, start, sockets.len())
        } else {
            dispatch::candidate_order(start, sockets.len())
        };
        // track WHICH workers reported at-capacity this pass. A parked
        // waiter's wake re-scan is restricted to exactly this set — a connect-dead
        // worker's gauge is stuck at 0 and must never convince a waiter to spin.
        let mut at_capacity_mask: u32 = 0;
        // only a Connect failure ON THE PINNED worker licenses a re-pin to
        // whichever worker serves; AtCapacity never does (the cap must not herd pins).
        let mut pin_connect_failed = false;
        for idx in order.iter() {
            let socket = &sockets[idx];
            match send_to_worker(
                pool,
                idx,
                sockets.len(),
                socket,
                request_bytes,
                session,
                long_lived,
                drain.clone(),
                &caps,
                keepalive_enabled,
                cap,
            )
            .await
            {
                Ok(status) => {
                    if let Some((key, pidx)) = pinned {
                        if idx != pidx && pin_connect_failed {
                            dispatch::sticky_repin(key, pidx, idx);
                        }
                    }
                    return Ok(status);
                }
                Err(FrameSendError::Connect) => {
                    if pinned.is_some_and(|(_, p)| p == idx) {
                        pin_connect_failed = true;
                    }
                    continue; // try the next worker
                }
                Err(FrameSendError::AtCapacity) => {
                    at_capacity_mask |= 1u32 << idx.min(dispatch::MAX_WORKERS - 1);
                    continue;
                }
                Err(FrameSendError::AfterWrite(status)) => return Err(status),
            }
        }
        if at_capacity_mask == 0 {
            // Every candidate failed with Connect: the pre-exhaustion outcome.
            return Err(503);
        }
        // Some worker(s) are alive but full: park, then re-run the WHOLE selection on
        // wake (late binding — the woken request goes wherever is best now).
        let k = cap.unwrap_or(usize::MAX);
        park_for_slot(at_capacity_mask, k, &drain).await?;
        woken = true;
    }
}

/// Wait for a worker in mask to fall below K or for drain to return 503.
/// Enable notification before rechecking capacity, following the ordering above.
/// ParkGuard decrements the parked count on every exit, including cancellation.
/// The all-worker mask is used by the anti-barging check.
async fn park_for_slot(mask: u32, k: usize, drain: &watch::Receiver<bool>) -> Result<(), u16> {
    #[cfg(feature = "hop-timing")]
    let mut __ht_park = Some(crate::hop_timing::Timer::start());
    let _parked = dispatch::ParkGuard::enter(); // Register the parked request and increment its event counter.
    let mut drain_rx = drain.clone();
    loop {
        let notified = dispatch::free_slot().notified();
        tokio::pin!(notified);
        notified.as_mut().enable(); // Enable notification before rescanning capacity.
        if *drain_rx.borrow() {
            return Err(503); // drain re-check AFTER registration and on every wake
        }
        if dispatch::any_admittable(mask, k) {
            // Forward a wake when this request observes free capacity so another waiter
            // is not stranded by a notification consumed during a competing admission.
            if dispatch::PARKED.load(Ordering::SeqCst) > 1 {
                dispatch::free_slot().notify_one();
            }
            #[cfg(feature = "hop-timing")]
            if let Some(t) = __ht_park.take() {
                crate::hop_timing::record(crate::hop_timing::Seam::Park, t);
            }
            return Ok(());
        }
        tokio::select! {
            biased;
            _ = drain_rx.changed() => {
                if *drain_rx.borrow() {
                    return Err(503);
                }
            }
            _ = notified.as_mut() => {} // Recheck capacity after waking.
        }
    }
}

enum FrameSendError {
    Connect,
    AfterWrite(u16),
    /// this worker is at its admission cap — nothing was written, no connection
    /// was consumed; the caller may try the next candidate or park.
    AtCapacity,
}

#[allow(clippy::too_many_arguments)]
async fn send_to_worker(
    pool: &WorkerFramePool,
    worker_idx: usize,
    worker_count: usize,
    socket: &str,
    request_bytes: &[u8],
    session: &mut Session,
    long_lived: &Arc<LongLivedRegistry>,
    drain: watch::Receiver<bool>,
    caps: &FrameCaps,
    keepalive_enabled: bool,
    cap: Option<usize>,
) -> Result<u16, FrameSendError> {
    // Pre-write drain check (mirrors the HTTP hop): reject before touching a worker.
    if *drain.borrow() {
        return Err(FrameSendError::AfterWrite(503));
    }
    // cheap admission pre-check BEFORE any connection is minted — the common
    // at-capacity exit. The authoritative check is the CAS at the commit point below;
    // this one only avoids pointless checkout/connect work. (Connect still fails before
    // any guard exists, so the failover-never-counts-a-dead-idx invariant holds.)
    if let Some(kv) = cap {
        let idx = worker_idx.min(dispatch::MAX_WORKERS - 1);
        if dispatch::gauges().in_flight[idx].load(Ordering::SeqCst) >= kv {
            return Err(FrameSendError::AtCapacity);
        }
    }

    // 1. Try a pooled (reused) connection first, else connect fresh.
    // seam: "checkout" = obtain a worker connection (pool hit, or fresh connect on miss).
    #[cfg(feature = "hop-timing")]
    let __ht_checkout = crate::hop_timing::Timer::start();
    let (mut conn, reused) = match pool.checkout(worker_idx).await {
        Some(c) => (c, true),
        None => {
            let conn = PooledConn::new(connect_worker(socket).await?);
            // Count only successful fresh connections; refused sockets are connection errors.
            pool.fresh_connect_total.fetch_add(1, Ordering::Relaxed);
            (conn, false)
        }
    };
    #[cfg(feature = "hop-timing")]
    crate::hop_timing::record_checkout(__ht_checkout);
    // A connection exists and the attempt can commit. The RAII guard covers
    // success, errors, re-exchange and cancellation. With a cap, a failed CAS
    // returns the untouched connection to the pool and reports capacity; no
    // request bytes have been written and no worker execution can have occurred.
    let Some(_inflight) = dispatch::InFlightGuard::try_acquire(worker_idx, worker_count, cap)
    else {
        pool.checkin(worker_idx, conn, drain);
        return Err(FrameSendError::AtCapacity);
    };
    // whole-exchange duration keyed by the dispatch depth this request joined —
    // the stacking-hypothesis probe (does exchange time grow with queue position?).
    #[cfg(feature = "hop-timing")]
    let __ht_exchange = crate::hop_timing::Timer::start();
    #[cfg(feature = "hop-timing")]
    let __ht_depth = _inflight.depth;

    // 2. Write the request frame, then read+stream the response.
    #[cfg(feature = "hop-timing")]
    let __ht_lane = __ht_depth;
    #[cfg(not(feature = "hop-timing"))]
    let __ht_lane = 0usize;
    match exchange(
        &mut conn,
        request_bytes,
        session,
        long_lived,
        drain.clone(),
        caps,
        keepalive_enabled,
        __ht_lane,
    )
    .await
    {
        Ok((status, reusable)) => {
            // record the completed exchange into its depth lane (success only —
            // error paths would pollute the latency ledger with timeout constants).
            #[cfg(feature = "hop-timing")]
            crate::hop_timing::record_exchange_depth(__ht_depth, __ht_exchange);
            // Put the connection back ONLY if the exchange left it at a clean boundary
            // and we are not draining. Otherwise drop it (closes).
            if reusable && !*drain.borrow() {
                // seam: "checkin" = return the connection to the pool at a clean boundary.
                #[cfg(feature = "hop-timing")]
                let __ht_checkin = crate::hop_timing::Timer::start();
                pool.checkin(worker_idx, conn, drain);
                #[cfg(feature = "hop-timing")]
                crate::hop_timing::record(crate::hop_timing::Seam::Checkin, __ht_checkin);
            }
            Ok(status)
        }
        Err(ExchangeError::StaleBeforeDispatch { request_delivered })
            if reused && (!request_delivered || !worker_kind::is_async()) =>
        {
            // A reused connection can retry once after a failed request write.
            // After a completed write followed by zero-response-byte EOF, only the
            // classic worker policy permits retry. Async execution may already have
            // occurred, so that case returns terminal AfterWrite(502), with no retry
            // or sibling failover. Partial request frames are closed before dispatch.
            pool.stale_evictions.fetch_add(1, Ordering::Relaxed);
            // the re-exchange records no seam and no depth lane (its timings would
            // carry a reconnect), so it is COUNTED — otherwise it is silently missing from
            // every per-request denominator the analyzer computes.
            #[cfg(feature = "hop-timing")]
            crate::hop_timing::note_exchange_retry();
            let mut fresh = PooledConn::new(connect_worker(socket).await?);
            // Count a successful stale-retry reconnect as another fresh connection.
            pool.fresh_connect_total.fetch_add(1, Ordering::Relaxed);
            match exchange(
                &mut fresh,
                request_bytes,
                session,
                long_lived,
                drain.clone(),
                caps,
                keepalive_enabled,
                __ht_lane,
            )
            .await
            {
                Ok((status, reusable)) => {
                    if reusable && !*drain.borrow() {
                        pool.checkin(worker_idx, fresh, drain);
                    }
                    Ok(status)
                }
                Err(e) => Err(FrameSendError::AfterWrite(e.status())),
            }
        }
        Err(e) => Err(FrameSendError::AfterWrite(e.status())),
    }
}

async fn connect_worker(socket: &str) -> Result<UnixStream, FrameSendError> {
    timeout(WORKER_CONNECT_TIMEOUT, UnixStream::connect(socket))
        .await
        .map_err(|_| FrameSendError::Connect)?
        .map_err(|_| FrameSendError::Connect)
}

enum ExchangeError {
    /// Failed request write or EOF before any response bytes on a reused connection.
    /// `request_delivered` distinguishes those outcomes: false means the write failed;
    /// true means the complete write was followed by EOF. The latter is ambiguous
    /// for async workers and must not retry or fail over.
    StaleBeforeDispatch { request_delivered: bool },
    /// Any other error, after bytes may have been committed — never replayed.
    Status(u16),
}

impl ExchangeError {
    fn status(&self) -> u16 {
        match self {
            ExchangeError::StaleBeforeDispatch { .. } => 502,
            ExchangeError::Status(s) => *s,
        }
    }
}

/// One request→response exchange over a single connection. Returns the status and
/// whether the connection is left at a clean frame boundary (reusable).
// `depth_lane` is the admission depth this request joined; it keys the
// response-read linear histogram the same way the whole-exchange one is keyed, so the
// worker round trip can be separated from the header build and the downstream write
// inside one depth. Unused without the hop-timing feature (diagnostic recording).
#[allow(clippy::too_many_arguments)]
async fn exchange(
    conn: &mut PooledConn,
    request_bytes: &[u8],
    session: &mut Session,
    long_lived: &Arc<LongLivedRegistry>,
    drain: watch::Receiver<bool>,
    caps: &FrameCaps,
    keepalive_enabled: bool,
    #[cfg_attr(not(feature = "hop-timing"), allow(unused_variables))] depth_lane: usize,
) -> Result<(u16, bool), ExchangeError> {
    let PooledConn { stream, rbuf } = conn;
    // Write the whole request frame. A failure here on a reused connection is the
    // stale-before-dispatch case.
    // seam: "request_write" = write_all of the request frame to the worker socket.
    #[cfg(feature = "hop-timing")]
    let __ht_write = crate::hop_timing::Timer::start();
    timeout(WORKER_WRITE_TIMEOUT, stream.write_all(request_bytes))
        .await
        .map_err(|_| ExchangeError::StaleBeforeDispatch {
            request_delivered: false,
        })?
        .map_err(|_| ExchangeError::StaleBeforeDispatch {
            request_delivered: false,
        })?;
    #[cfg(feature = "hop-timing")]
    crate::hop_timing::record(crate::hop_timing::Seam::RequestWrite, __ht_write);

    // Read the first response frame. Empty-buffer EOF is classified separately
    // from partial response data, with retry eligibility determined by worker kind.
    // The response-read timer includes socket wait and worker execution time.
    #[cfg(feature = "hop-timing")]
    let __ht_read = crate::hop_timing::Timer::start();
    let first = match rbuf.read_frame(stream, caps, true).await {
        Ok(Some(frame)) => frame,
        // EOF, no response: the request WAS delivered — the ambiguous signature.
        Ok(None) => {
            return Err(ExchangeError::StaleBeforeDispatch {
                request_delivered: true,
            })
        }
        Err(status) => return Err(ExchangeError::Status(status)),
    };
    #[cfg(feature = "hop-timing")]
    crate::hop_timing::record_response_read(depth_lane, __ht_read);

    match first {
        ResponseFrame::Full {
            status,
            headers,
            body,
        } => {
            let header = build_response_header(status, headers, body.len(), keepalive_enabled)
                .map_err(ExchangeError::Status)?;
            write_response_header_with_timeout(session, header, false)
                .await
                .map_err(ExchangeError::Status)?;
            write_response_body_with_timeout(session, Some(Bytes::from(body)), true)
                .await
                .map_err(ExchangeError::Status)?;
            // A Full response leaves the connection at a frame boundary ONLY if the
            // buffer is empty behind it: surplus means the worker spoke out of turn —
            // serve the (well-formed) response but kill the connection, never pool it.
            Ok((status, !rbuf.has_surplus()))
        }
        ResponseFrame::Head { status, headers } => {
            let header = build_response_chunked_header(status, headers, keepalive_enabled)
                .map_err(ExchangeError::Status)?;
            stream_frames_downstream(
                stream, rbuf, session, header, status, long_lived, drain, caps,
            )
            .await
            .map_err(ExchangeError::Status)
        }
        // A response that opens with Chunk/End is a protocol violation.
        ResponseFrame::Chunk { .. } | ResponseFrame::End => Err(ExchangeError::Status(502)),
    }
}

/// Stream `Chunk`* → `End` frames to the downstream under long-lived admission, mirroring
/// `stream_chunked_worker_response`. Returns (status, reusable) — reusable iff the stream
/// ended cleanly with an `End` frame (not a drain/error mid-stream).
#[allow(clippy::too_many_arguments)]
async fn stream_frames_downstream(
    stream: &mut UnixStream,
    rbuf: &mut FrameReadBuffer,
    session: &mut Session,
    header: ResponseHeader,
    status: u16,
    long_lived: &Arc<LongLivedRegistry>,
    mut drain: watch::Receiver<bool>,
    caps: &FrameCaps,
) -> Result<(u16, bool), u16> {
    let mut admission = long_lived.try_admit().ok_or(503u16)?;
    let mut header = Some(header);
    let mut streamed = 0u64;
    loop {
        // Between chunks, honor drain: finish the response and stop reusing.
        if *drain.borrow() {
            if let Some(header) = header.take() {
                write_long_lived_header_with_timeout(session, header, false, &admission).await?;
            }
            write_long_lived_body_with_timeout(session, None, true, &admission).await?;
            admission.complete_drained();
            return Ok((status, false));
        }
        match rbuf.read_frame_or_drain(stream, caps, &mut drain).await? {
            Some(ResponseFrame::Chunk { data }) => {
                if data.is_empty() {
                    continue;
                }
                streamed = streamed.saturating_add(data.len() as u64);
                if streamed > MAX_RESPONSE_BYTES as u64
                    || !admission.record_bytes(data.len() as u64)
                {
                    return Err(502);
                }
                if let Some(header) = header.take() {
                    write_long_lived_header_with_timeout(session, header, false, &admission)
                        .await?;
                }
                write_long_lived_body_with_timeout(
                    session,
                    Some(Bytes::from(data)),
                    false,
                    &admission,
                )
                .await?;
            }
            Some(ResponseFrame::End) => {
                if let Some(header) = header.take() {
                    write_long_lived_header_with_timeout(session, header, false, &admission)
                        .await?;
                }
                write_long_lived_body_with_timeout(session, None, true, &admission).await?;
                admission.complete();
                // Clean End → reusable ONLY with an empty buffer behind it: a complete
                // extra frame (or partial bytes) after End is out-of-turn worker data.
                return Ok((status, !rbuf.has_surplus()));
            }
            // Drain fired mid-read.
            None => {
                if let Some(header) = header.take() {
                    write_long_lived_header_with_timeout(session, header, false, &admission)
                        .await?;
                }
                write_long_lived_body_with_timeout(session, None, true, &admission).await?;
                admission.complete_drained();
                return Ok((status, false));
            }
            // A second Head, or a Full mid-stream, is a protocol violation.
            Some(_) => return Err(502),
        }
    }
}

/// Write a native response using the frame hop's downstream framing and bounded
/// writes. `build_response_header` replaces upstream framing with Content-Length
/// and applies the configured keepalive policy. The optional `edge-bench` route
/// uses this helper to exercise the same downstream write path.
#[cfg(feature = "edge-bench")]
pub(super) async fn write_native_bench_response(
    session: &mut Session,
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    keepalive_enabled: bool,
) -> Result<(), u16> {
    let header = build_response_header(status, headers, body.len(), keepalive_enabled)?;
    write_response_header_with_timeout(session, header, false).await?;
    write_response_body_with_timeout(session, Some(Bytes::from(body)), true).await?;
    Ok(())
}

fn build_response_header(
    status: u16,
    headers: Vec<(String, String)>,
    body_len: usize,
    keepalive_enabled: bool,
) -> Result<ResponseHeader, u16> {
    // Reserve space for application headers plus Content-Length, Connection and
    // Pingora's downstream Date/Connection inserts to avoid growing the header map.
    let mut header = ResponseHeader::build(status, Some(headers.len() + 4)).map_err(|_| 502u16)?;
    for (name, value) in headers {
        if is_framing_header(&name) {
            continue;
        }
        header.append_header(name, value).map_err(|_| 502u16)?;
    }
    header
        .insert_header("Content-Length", body_len.to_string())
        .map_err(|_| 502u16)?;
    if !keepalive_enabled {
        header
            .insert_header("Connection", "close")
            .map_err(|_| 502u16)?;
    }
    Ok(header)
}

/// Build a chunked (streaming) downstream header from a decoded Head frame — mirrors the
/// HTTP hop's `parse_chunked_worker_response_head`: drop framing headers (pingora frames the
/// chunked body itself).: keepalive-aware like the HTTP hop — under keepalive the explicit
/// `Connection: close` is omitted; the chunked body still self-terminates with a 0-chunk, so
/// the kept-alive downstream connection is safe to reuse.
fn build_response_chunked_header(
    status: u16,
    headers: Vec<(String, String)>,
    keepalive_enabled: bool,
) -> Result<ResponseHeader, u16> {
    // Reserve space for application headers plus Content-Length, Connection and
    // Pingora's downstream Date/Connection inserts to avoid growing the header map.
    let mut header = ResponseHeader::build(status, Some(headers.len() + 4)).map_err(|_| 502u16)?;
    for (name, value) in headers {
        if is_framing_header(&name) {
            continue;
        }
        header.append_header(name, value).map_err(|_| 502u16)?;
    }
    if !keepalive_enabled {
        header
            .insert_header("Connection", "close")
            .map_err(|_| 502u16)?;
    }
    Ok(header)
}

fn is_framing_header(name: &str) -> bool {
    // case-insensitive compare without the per-header String that
    // to_ascii_lowercase allocated — eq_ignore_ascii_case is the same ASCII-only
    // mapping, applied during the comparison instead of up front.
    name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("connection")
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESERVED_PREFIX_CASES: &[(&str, bool)] = &[
        ("x-oxo-", true),
        ("x-oxo-a", true),
        ("X-OxO-Request-Id", true),
        ("x-oxo-remote-addr", true),
        ("x-oxo", false),
        ("x-oxox-a", false),
        ("x-real", false),
        ("host", false),
    ];

    #[test]
    fn frame_builder_rejects_reserved_headers_if_sanitizer_keeps_them() {
        // Deliberately bypass sanitization: parity between two already-sanitized
        // pipelines cannot exercise the frame builder's independent guard.
        let plan = crate::FrameHeaderPlan {
            keep: [1, 0],
            survivor_count: 1,
            has_host: false,
        };
        for &(name, reserved) in RESERVED_PREFIX_CASES {
            let headers = [crate::LoweredHeader::new(name.into(), "value".into())];
            let result = assemble_request_frame_bytes(
                "GET",
                "/",
                "",
                None,
                &headers,
                &plan,
                b"",
                "http",
                "localhost",
                80,
                "127.0.0.1",
            );
            if reserved {
                assert_eq!(result, Err(400), "{name}");
            } else {
                assert!(result.is_ok(), "{name}: {result:?}");
            }
        }
    }

    #[test]
    fn owned_frame_builder_strips_only_reserved_headers() {
        let metadata = crate::TrustedHopMetadata {
            remote_addr: "127.0.0.1".into(),
            url_scheme: "http".into(),
            server_name: "localhost".into(),
            server_port: 80,
            request_id: None,
        };
        for &(name, reserved) in RESERVED_PREFIX_CASES {
            let headers = vec![(name.to_string(), "value".to_string())];
            let expected = if reserved { vec![] } else { headers.clone() };
            let frame =
                assemble_request_frame_owned("GET", "/", "", None, headers, vec![], &metadata);
            assert_eq!(frame.headers, expected, "{name}");
        }
    }

    /// Compare full-frame bytes from the owned and borrowed construction paths over
    /// adversarial inputs. Header order matters to Rack environment construction, so
    /// wire changes must keep both encoders and their expected behavior consistent.
    #[test]
    fn frame_bytes_parity_old_vs_new_pipeline() {
        use crate::{LoweredHeader, ProtocolSupport, TrustedHopMetadata};

        struct Case {
            label: &'static str,
            method: &'static str,
            path: &'static str,
            query: &'static str,
            authority: Option<&'static str>,
            url_scheme: &'static str,
            headers: &'static [(&'static str, &'static str)],
            body: &'static [u8],
        }
        let cases = [
            Case {
                label: "typical H1",
                method: "GET",
                path: "/bench-mix",
                query: "slow=10&kind=io",
                authority: None,
                url_scheme: "http",
                headers: &[
                    ("Host", "bench.local"),
                    ("User-Agent", "parity/1"),
                    ("Accept", "*/*"),
                    ("Cookie", "a=1"),
                    ("Cookie", "b=2"),
                ],
                body: b"",
            },
            Case {
                label: "dup Cookie order + mixed-case names",
                method: "POST",
                path: "/submit",
                query: "",
                authority: None,
                url_scheme: "https",
                headers: &[
                    ("HOST", "x.example"),
                    ("COOKIE", "z=9"),
                    ("cookie", "a=1"),
                    ("Content-Type", "application/x-www-form-urlencoded"),
                ],
                body: b"k=v&k2=v2",
            },
            Case {
                label: "H2 no-Host: synthesized from authority, emitted first",
                method: "GET",
                path: "/",
                query: "",
                authority: Some("h2.example:8443"),
                url_scheme: "https",
                headers: &[("user-agent", "parity/2"), ("accept", "*/*")],
                body: b"",
            },
            Case {
                label: "no host, no authority: nothing synthesized",
                method: "GET",
                path: "/p",
                query: "q=1",
                authority: None,
                url_scheme: "http",
                headers: &[("accept", "text/html")],
                body: b"",
            },
            Case {
                label: "connection token strips a named header (mixed case, empty tokens)",
                method: "GET",
                path: "/t",
                query: "",
                authority: None,
                url_scheme: "http",
                headers: &[
                    ("Host", "t.local"),
                    ("Connection", " close , , X-Droppable "),
                    ("X-Droppable", "gone"),
                    ("X-Kept", "stays"),
                ],
                body: b"",
            },
            Case {
                label: "client-sent x-oxo-* and forwarding-class stripped; te stripped",
                method: "GET",
                path: "/id",
                query: "a=b&c=d",
                authority: None,
                url_scheme: "http",
                headers: &[
                    ("Host", "id.local"),
                    ("X-Oxo-Remote-Addr", "6.6.6.6"),
                    ("X-Forwarded-For", "1.2.3.4"),
                    ("te", "trailers"),
                    ("X-Real", "kept"),
                ],
                body: b"body",
            },
        ];

        for case in &cases {
            let lowered: Vec<LoweredHeader<'static>> = case
                .headers
                .iter()
                .map(|(n, v)| LoweredHeader::new(n.to_string(), v.to_string()))
                .collect();
            let protocols = ProtocolSupport::default();
            let metadata = TrustedHopMetadata {
                remote_addr: "203.0.113.7".to_string(),
                url_scheme: case.url_scheme.to_string(),
                server_name: "bench.local".to_string(),
                server_port: 8443,
                request_id: Some("oxo-1-1".to_string()),
            };

            // OLD pipeline (the oracle).
            let sanitized =
                crate::sanitize_lowered_worker_request_headers_bare(&lowered, protocols)
                    .unwrap_or_else(|e| panic!("{}: old sanitize rejected: {e:?}", case.label));
            let frame = assemble_request_frame_owned(
                case.method,
                case.path,
                case.query,
                case.authority,
                sanitized.headers,
                case.body.to_vec(),
                &metadata,
            );
            let old_bytes = hop_frame::encode_request(&frame)
                .unwrap_or_else(|e| panic!("{}: old encode failed: {e:?}", case.label));

            // NEW pipeline (the active path's session-free core).
            let plan = crate::sanitize_frame_headers(&lowered, protocols)
                .unwrap_or_else(|e| panic!("{}: new sanitize rejected: {e:?}", case.label));
            let new_bytes = assemble_request_frame_bytes(
                case.method,
                case.path,
                case.query,
                case.authority,
                &lowered,
                &plan,
                case.body,
                case.url_scheme,
                "bench.local",
                8443,
                "203.0.113.7",
            )
            .unwrap_or_else(|e| panic!("{}: new assemble failed: {e}", case.label));

            assert_eq!(
                old_bytes, new_bytes,
                "{}: frame bytes diverged between pipelines",
                case.label
            );
        }
    }

    /// Both pipelines must also REJECT identically — the plan fn's ladder is a verbatim
    /// copy, pinned here on one representative of each rejection.
    #[test]
    fn frame_plan_rejections_match_the_owned_sanitize() {
        use crate::{LoweredHeader, ProtocolSupport};
        let reject_cases: &[&[(&str, &str)]] = &[
            &[("Connection", "Upgrade"), ("Upgrade", "websocket")],
            &[("upgrade", "h2c")],
            &[("sec-websocket-key", "x")],
            &[("content-type", "application/grpc")],
            &[("accept", "text/event-stream")],
            &[("last-event-id", "5")],
        ];
        for case in reject_cases {
            let lowered: Vec<LoweredHeader<'static>> = case
                .iter()
                .map(|(n, v)| LoweredHeader::new(n.to_string(), v.to_string()))
                .collect();
            let old = crate::sanitize_lowered_worker_request_headers_bare(
                &lowered,
                ProtocolSupport::default(),
            )
            .err();
            let new = crate::sanitize_frame_headers(&lowered, ProtocolSupport::default()).err();
            assert_eq!(old, new, "rejection divergence for {case:?}");
            assert!(old.is_some(), "case must reject: {case:?}");
        }
    }

    // One-shot responses explicitly close the connection. Keepalive responses leave
    // Connection handling to Pingora's `set_keepalive` policy.
    #[test]
    fn response_header_omits_connection_close_only_under_keepalive() {
        let headers = vec![("content-type".to_string(), "text/plain".to_string())];

        // One-shot Full: explicit Connection: close + explicit Content-Length.
        let h = build_response_header(200, headers.clone(), 2, false).unwrap();
        assert_eq!(h.headers.get("connection").unwrap().as_bytes(), b"close");
        assert_eq!(h.headers.get("content-length").unwrap().as_bytes(), b"2");
        // Keepalive Full: NO explicit Connection header; Content-Length still explicit.
        let h = build_response_header(200, headers.clone(), 2, true).unwrap();
        assert!(
            h.headers.get("connection").is_none(),
            "keepalive must omit the explicit Connection: close"
        );
        assert_eq!(h.headers.get("content-length").unwrap().as_bytes(), b"2");

        // Chunked head mirrors the same conditional.
        let c = build_response_chunked_header(200, headers.clone(), false).unwrap();
        assert_eq!(c.headers.get("connection").unwrap().as_bytes(), b"close");
        let c = build_response_chunked_header(200, headers, true).unwrap();
        assert!(c.headers.get("connection").is_none());
    }

    // A fresh idle connection is reusable; a peer-closed or data-bearing one is not.
    // Poll until the reactor has observed peer activity before asserting the cached
    // readiness classification. Later activity can still race the request write.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn is_stream_live_distinguishes_healthy_closed_and_dirty() {
        let wait_not_live = |s: UnixStream, label: &'static str| async move {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if !is_stream_live(&s) {
                    return;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "{label}: reactor never observed the state change"
                );
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        };

        let (a, b) = UnixStream::pair().unwrap();
        assert!(is_stream_live(&a), "fresh idle connection is live");
        drop(b);
        // Peer closed: EOF becomes visible once the reactor records readiness.
        wait_not_live(a, "peer-closed").await;

        let (mut c, d) = UnixStream::pair().unwrap();
        c.write_all(b"x").await.unwrap();
        wait_not_live(d, "data-bearing").await;
    }

    // Round-trip: a checked-in live connection can be checked out and is the SAME fd.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn checkin_then_checkout_returns_the_same_connection() {
        let pool = WorkerFramePool::new(1);
        let (edge, _worker) = UnixStream::pair().unwrap();
        let fd = edge.as_raw_fd();
        let (_tx, drain) = watch::channel(false);
        pool.checkin(0, PooledConn::new(edge), drain);
        // Give the watcher task a moment to register the connection + park on the lock.
        tokio::time::sleep(Duration::from_millis(20)).await;
        // strict again (had wrapped this in a retry loop). A None here with
        // try_unwrap_fail_total moved is the unwrap transient; without it, a lost entry.
        let got = pool.checkout(0).await;
        assert!(
            got.is_some(),
            "pooled connection is checked out; {}",
            pool.unwrap_diag()
        );
        assert_eq!(
            got.unwrap().stream.as_raw_fd(),
            fd,
            "same connection returned"
        );
    }

    // Empty pool → None (a fresh connect is the caller's fallback).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn checkout_empty_pool_is_none() {
        let pool = WorkerFramePool::new(1);
        assert!(pool.checkout(0).await.is_none());
    }

    // The pool-health JSON exposes actual reuse. Incrementing pool_reuse_total
    // must be reflected in the snapshot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pool_health_json_reports_the_reuse_counters() {
        let pool = WorkerFramePool::new(1);
        let (edge, _worker) = UnixStream::pair().unwrap();
        let (_tx, drain) = watch::channel(false);
        pool.checkin(0, PooledConn::new(edge), drain);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let got = pool.checkout(0).await;
        assert!(
            got.is_some(),
            "pooled connection reused; {}",
            pool.unwrap_diag()
        );
        let json = pool.health_json();
        assert!(
            json.contains("\"pool_reuse_total\":1"),
            "reuse counted in the snapshot: {json}"
        );
        for key in [
            "fresh_connect_total",
            "stale_evictions",
            "try_unwrap_fail_total",
            "unwrap_retry_total",
            "checkin_total",
        ] {
            assert!(json.contains(&format!("\"{key}\":")), "key {key} in {json}");
        }
        // The admin wrapper distinguishes "no pool registered" from a quiet pool — the
        // reuse gate must never read an absent pool as a clean pass. (The production
        // registration happens in proxy construction; tests never register.)
        let unregistered = admin_pool_health_json();
        assert!(
            unregistered.contains("\"registered\":false")
                || unregistered.contains("\"registered\":true"),
            "admin wrapper always carries the registered marker: {unregistered}"
        );
    }

    // A pooled connection whose peer closed is NOT handed out (the watcher reaps it, and
    // the checkout liveness probe rejects any that slip through) — the stale-connection
    // guard at the pool layer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn peer_closed_pooled_connection_is_not_reused() {
        let pool = WorkerFramePool::new(1);
        let (edge, worker) = UnixStream::pair().unwrap();
        let (_tx, drain) = watch::channel(false);
        pool.checkin(0, PooledConn::new(edge), drain);
        tokio::time::sleep(Duration::from_millis(20)).await;
        // The worker dies.
        drop(worker);
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Either the watcher already reaped it (None) or checkout's liveness probe does.
        assert!(
            pool.checkout(0).await.is_none(),
            "a dead pooled connection is never reused"
        );
    }

    // Drain empties the idle pool: a checked-in connection is reaped when drain fires,
    // so a subsequent checkout finds nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_empties_the_idle_pool() {
        let pool = WorkerFramePool::new(1);
        let (edge, _worker) = UnixStream::pair().unwrap();
        let (tx, drain) = watch::channel(false);
        pool.checkin(0, PooledConn::new(edge), drain);
        tokio::time::sleep(Duration::from_millis(20)).await;
        tx.send(true).unwrap(); // drain
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            pool.checkout(0).await.is_none(),
            "drain reaped the idle connection"
        );
    }

    // Stress checkout and checkin across threads. A released OwnedMutexGuard can
    // briefly retain its Arc after waking checkout. Track the bounded retry outcome
    // so transient guard-drop contention is distinct from persistent retained Arcs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "race probe: measures the checkout handshake window; run explicitly"]
    async fn probe_checkout_handshake_try_unwrap_rate() {
        const KEYS: usize = 8;
        const ITERS: usize = 20_000;
        let pool = Arc::new(WorkerFramePool::new(KEYS));
        let (_tx, drain) = watch::channel(false);
        let mut tasks = Vec::new();
        for idx in 0..KEYS {
            let pool = pool.clone();
            let drain = drain.clone();
            tasks.push(tokio::spawn(async move {
                let mut peer_keepalive = Vec::new();
                let (edge, worker) = UnixStream::pair().unwrap();
                peer_keepalive.push(worker);
                let mut conn = PooledConn::new(edge);
                let mut reused = 0u64;
                for _ in 0..ITERS {
                    pool.checkin(idx, conn, drain.clone());
                    match pool.checkout(idx).await {
                        Some(c) => {
                            conn = c;
                            reused += 1;
                        }
                        None => {
                            // Lost this one (the point of the probe) — re-arm and continue
                            // so a single failure does not truncate the sample.
                            let (e, w) = UnixStream::pair().unwrap();
                            peer_keepalive.push(w);
                            conn = PooledConn::new(e);
                        }
                    }
                }
                reused
            }));
        }
        let mut reused_total = 0u64;
        for t in tasks {
            reused_total += t.await.unwrap();
        }
        let fails = pool.try_unwrap_fail_total.load(Ordering::Relaxed);
        let retries = pool.unwrap_retry_total.load(Ordering::Relaxed);
        let checkins = pool.checkin_total.load(Ordering::Relaxed);
        eprintln!(
            "PROBE checkins={checkins} reused={reused_total} transient_retries={retries} \
             ({:.6}%) persistent_fails={fails} ({:.6}%)",
            100.0 * retries as f64 / checkins.max(1) as f64,
            100.0 * fails as f64 / checkins.max(1) as f64,
        );
        assert!(reused_total > 0, "the probe must actually exercise reuse");
    }

    // The positive control for the probe above: an injected PERSISTENT extra reference —
    // the reuse-collapse defect — must still trip `try_unwrap_fail_total`. Without this,
    // the bounded retry would be indistinguishable from muting the alarm.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn leaked_reference_still_trips_the_reuse_tripwire() {
        let pool = WorkerFramePool::new(1);
        let (edge, _worker) = UnixStream::pair().unwrap();
        let (_tx, drain) = watch::channel(false);
        pool.leak_inject_arm.store(true, Ordering::Relaxed);
        pool.checkin(0, PooledConn::new(edge), drain);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let leaked = pool.leak_inject.lock().unwrap().clone();
        assert!(leaked.is_some(), "the injection armed and fired");

        assert!(
            pool.checkout(0).await.is_none(),
            "a connection with a live extra reference is never reused"
        );
        assert_eq!(
            pool.try_unwrap_fail_total.load(Ordering::Relaxed),
            1,
            "the reuse-collapse tripwire fires on a persistent extra reference"
        );
        assert_eq!(
            pool.unwrap_retry_total.load(Ordering::Relaxed),
            0,
            "a persistent reference is never counted as a resolved transient"
        );
        drop(leaked);
    }

    // ------------------------------------------------- unwrap budget

    /// A persistent extra reference fails after the budget, not before, with the exact
    /// counters the tripwire relies on. Only a LOWER bound on elapsed is asserted: the
    /// deadline guarantees it, and an upper bound is the flake class this segment removes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persistent_reference_fails_at_the_budget_with_exact_counters() {
        let budget = Duration::from_millis(30);
        let pool = WorkerFramePool::with_unwrap_budget(budget);
        let (edge, _worker) = UnixStream::pair().unwrap();
        let (_tx, drain) = watch::channel(false);
        pool.leak_inject_arm.store(true, Ordering::Relaxed);
        pool.checkin(0, PooledConn::new(edge), drain);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let leaked = pool.leak_inject.lock().unwrap().clone();
        assert!(leaked.is_some());
        let t0 = std::time::Instant::now();
        assert!(pool.checkout(0).await.is_none(), "{}", pool.unwrap_diag());
        let elapsed = t0.elapsed();
        assert!(elapsed >= budget, "gave up before the budget: {elapsed:?}");
        assert_eq!(pool.try_unwrap_fail_total.load(Ordering::Relaxed), 1);
        assert_eq!(pool.unwrap_retry_total.load(Ordering::Relaxed), 0);
        let waited = pool.unwrap_wait_ns.load(Ordering::Relaxed);
        assert!(
            waited >= budget.as_nanos() as u64,
            "unwrap_wait_ns {waited}"
        );
        assert_eq!(pool.unwrap_wait_max_ns.load(Ordering::Relaxed), waited);
        let json = pool.health_json();
        assert!(json.contains("\"unwrap_wait_budget_ms\":30"), "{json}");
        assert!(json.contains("\"unwrap_wait_ns\":"), "{json}");
        assert!(json.contains("\"unwrap_wait_max_ns\":"), "{json}");
        drop(leaked);
    }

    /// A reference that goes away DURING the budget is recovered: the checkout succeeds,
    /// counts one retry, and the wait is on the clock. The budget is 2 s against a 3 ms
    /// release, so this exercises the mechanism and not the margin.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reference_released_during_the_budget_is_recovered() {
        let pool = Arc::new(WorkerFramePool::with_unwrap_budget(Duration::from_secs(2)));
        let (edge, _worker) = UnixStream::pair().unwrap();
        let fd = edge.as_raw_fd();
        let (_tx, drain) = watch::channel(false);
        pool.leak_inject_arm.store(true, Ordering::Relaxed);
        pool.checkin(0, PooledConn::new(edge), drain);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let leaked = pool
            .leak_inject
            .lock()
            .unwrap()
            .take()
            .expect("armed and fired");
        let releaser = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(3)).await;
            drop(leaked);
        });
        let got = pool.checkout(0).await;
        assert!(
            got.is_some(),
            "recovered once the reference went away; {}",
            pool.unwrap_diag()
        );
        assert_eq!(got.unwrap().stream.as_raw_fd(), fd);
        assert_eq!(pool.unwrap_retry_total.load(Ordering::Relaxed), 1);
        assert_eq!(pool.try_unwrap_fail_total.load(Ordering::Relaxed), 0);
        assert!(pool.unwrap_wait_ns.load(Ordering::Relaxed) > 0);
        releaser.await.unwrap();
    }

    /// Budget zero is the pre-control: one attempt, then the silent fresh connect.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_budget_is_one_attempt() {
        let pool = WorkerFramePool::with_unwrap_budget(Duration::ZERO);
        let (edge, _worker) = UnixStream::pair().unwrap();
        let (_tx, drain) = watch::channel(false);
        pool.leak_inject_arm.store(true, Ordering::Relaxed);
        pool.checkin(0, PooledConn::new(edge), drain);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let leaked = pool.leak_inject.lock().unwrap().clone();
        assert!(pool.checkout(0).await.is_none());
        assert_eq!(pool.try_unwrap_fail_total.load(Ordering::Relaxed), 1);
        assert_eq!(pool.unwrap_retry_total.load(Ordering::Relaxed), 0);
        drop(leaked);
    }

    #[test]
    fn unwrap_wait_ms_parses_default_zero_and_refuses_junk() {
        assert_eq!(parse_unwrap_wait_ms(None), Ok(UNWRAP_WAIT_BUDGET_DEFAULT));
        assert_eq!(
            parse_unwrap_wait_ms(Some("")),
            Ok(UNWRAP_WAIT_BUDGET_DEFAULT)
        );
        assert_eq!(parse_unwrap_wait_ms(Some("0")), Ok(Duration::ZERO));
        assert_eq!(
            parse_unwrap_wait_ms(Some(" 250 ")),
            Ok(Duration::from_millis(250))
        );
        assert!(parse_unwrap_wait_ms(Some("junk")).is_err());
        assert!(parse_unwrap_wait_ms(Some("-1")).is_err());
    }

    // ------------------------------------------------- reaper battery

    /// Burst of checkins: reuse ACTUALLY occurs (fd identity + pool_reuse_total — the
    /// constraint that green tests must not mask silent fresh-connects), and a pooled
    /// checkout completes within a tight bound while many checkins are queued behind the
    /// one reaper (pickup release never gates on the checkin queue depth).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn burst_of_checkins_reuse_occurs_and_checkout_stays_bounded() {
        REAPER_TEST_FORCE.store(true, Ordering::Relaxed);
        let pool = WorkerFramePool::new(4);
        let (_tx, drain) = watch::channel(false);
        let (edge0, _worker0) = UnixStream::pair().unwrap();
        let fd0 = edge0.as_raw_fd();
        pool.checkin(0, PooledConn::new(edge0), drain.clone());
        // Burst: 24 more checkins across the other worker keys, queued at the reaper.
        // (Stays under this pool's explicit ceiling of 32 — the first live run of this
        // test burst 32+1 against it and LRU-evicted the connection under test.)
        let mut keep_peers = Vec::new();
        for i in 0..24u64 {
            let (e, w) = UnixStream::pair().unwrap();
            keep_peers.push(w);
            pool.checkin(1 + (i as usize % 3), PooledConn::new(e), drain.clone());
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        let reuse_before = pool.pool_reuse_total.load(Ordering::Relaxed);
        let stale_before = pool.stale_evictions.load(Ordering::Relaxed);
        let t0 = std::time::Instant::now();
        let got = tokio::time::timeout(Duration::from_millis(500), pool.checkout(0))
            .await
            .expect("checkout must not hang behind the checkin queue")
            .expect("pooled connection is checked out");
        let took = t0.elapsed();
        assert_eq!(got.stream.as_raw_fd(), fd0, "reuse occurred (same fd)");
        assert_eq!(
            pool.pool_reuse_total.load(Ordering::Relaxed),
            reuse_before + 1,
            "reuse counter observed the pooled checkout"
        );
        assert_eq!(
            pool.stale_evictions.load(Ordering::Relaxed),
            stale_before,
            "no stale eviction during the burst"
        );
        assert!(
            took < Duration::from_millis(200),
            "pooled checkout bounded under burst (took {took:?})"
        );
        assert_eq!(
            pool.checkin_total.load(Ordering::Relaxed),
            25,
            "all checkins reached the reaper"
        );
    }

    // ---- /: the eviction counter, reconciled against arithmetic ------------
    //
    // The owned pool evicts synchronously inside `put`, oldest first across all keys,
    // so N checkins at ceiling C with no await between them evict exactly N - C and the
    // evicted ids are out of the pool before the next statement. The counter is bumped
    // by the watcher when its pickup sender is found dropped (the victim's sender goes
    // in `put`, after the lock); a watcher that first polls after the eviction still
    // sees it. Assertions poll to a deadline, never a fixed sleep.
    async fn wait_for_evictions(pool: &WorkerFramePool, want: u64) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let got = pool.lru_evictions.load(Ordering::Relaxed);
            if got >= want {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "eviction counter reached {got}, wanted {want}"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    async fn evictions_are_exactly_n_minus_c(force_path: u8) {
        const C: usize = 4;
        const N: usize = C + 3;
        let pool = WorkerFramePool::with_idle_ceiling(N, C);
        pool.force_path.store(force_path, Ordering::Relaxed);
        let (_tx, drain) = watch::channel(false);
        let mut peers = Vec::new();
        // No await between these checkins: they all land in THIS thread's cache.
        for key in 0..N {
            let (e, w) = UnixStream::pair().unwrap();
            peers.push(w);
            pool.checkin(key, PooledConn::new(e), drain.clone());
        }
        wait_for_evictions(&pool, (N - C) as u64).await;
        assert_eq!(
            pool.lru_evictions.load(Ordering::Relaxed),
            (N - C) as u64,
            "exactly N - C evictions"
        );
        assert_eq!(pool.checkin_total.load(Ordering::Relaxed), N as u64);
        // Oldest first: the first N - C keys are gone, the newest is still pooled.
        for key in 0..(N - C) {
            assert!(
                pool.checkout(key).await.is_none(),
                "evicted key {key} must miss"
            );
        }
        assert!(
            pool.checkout(N - 1).await.is_some(),
            "the newest checkin survives"
        );
        let json = pool.health_json();
        assert!(
            json.contains(&format!("\"lru_evictions\":{}", N - C)),
            "{json}"
        );
        assert!(json.contains(&format!("\"frame_pool_idle\":{C}")), "{json}");
        // the test constructor pins the ceiling, so the value names the env
        // source; the default source is reachable only through `new` and is covered by
        // frame_pool::resolve_idle_ceiling_names_its_source.
        assert!(
            json.contains("\"frame_pool_idle_source\":\"env\""),
            "{json}"
        );
        drop(peers);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lru_evictions_count_exactly_on_the_spawn_path() {
        evictions_are_exactly_n_minus_c(1).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lru_evictions_count_exactly_on_the_reaper_path() {
        evictions_are_exactly_n_minus_c(2).await;
    }

    /// The ceiling is aggregate across threads: four checkins at ceiling one evict
    /// three connections. A barrier keeps all four submitting OS threads distinct.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lru_ceiling_is_aggregate_across_edge_threads() {
        let pool = Arc::new(WorkerFramePool::with_idle_ceiling(4, 1));
        pool.force_path.store(1, Ordering::Relaxed);
        let (_tx, drain) = watch::channel(false);
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let mut peers = Vec::new();
        let mut handles = Vec::new();
        for key in 0..4usize {
            let (e, w) = UnixStream::pair().unwrap();
            peers.push(w);
            let pool = pool.clone();
            let drain = drain.clone();
            let barrier = barrier.clone();
            handles.push(tokio::task::spawn_blocking(move || {
                barrier.wait();
                pool.checkin(key, PooledConn::new(e), drain);
                barrier.wait();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        wait_for_evictions(&pool, 3).await;
        assert_eq!(
            pool.lru_evictions.load(Ordering::Relaxed),
            3,
            "N - C across four threads"
        );
        assert_eq!(pool.checkin_total.load(Ordering::Relaxed), 4);
        let mut survivors = 0;
        for key in 0..4usize {
            if pool.checkout(key).await.is_some() {
                survivors += 1;
            }
        }
        assert_eq!(
            survivors, 1,
            "exactly one connection fits under an aggregate ceiling of 1"
        );
        drop(peers);
    }

    /// eviction crosses worker keys. Four idle connections on key 0 at ceiling 4,
    /// then one on key 1: key 0's oldest goes, key 1's stays.
    #[tokio::test(flavor = "current_thread")]
    async fn eviction_crosses_worker_keys() {
        let pool = WorkerFramePool::with_idle_ceiling(2, 4);
        pool.force_path.store(1, Ordering::Relaxed);
        let (_tx, drain) = watch::channel(false);
        let mut peers = Vec::new();
        for _ in 0..4 {
            let (e, w) = UnixStream::pair().unwrap();
            peers.push(w);
            pool.checkin(0, PooledConn::new(e), drain.clone());
        }
        let (e, w) = UnixStream::pair().unwrap();
        peers.push(w);
        pool.checkin(1, PooledConn::new(e), drain.clone());
        wait_for_evictions(&pool, 1).await;
        assert_eq!(pool.lru_evictions.load(Ordering::Relaxed), 1);
        assert!(pool.checkout(1).await.is_some(), "key 1 is pooled");
        let mut key0 = 0;
        while pool.checkout(0).await.is_some() {
            key0 += 1;
        }
        assert_eq!(key0, 3, "key 0 lost exactly its oldest");
        drop(peers);
    }

    /// Cross-thread pickup removes entries from capacity accounting. Refill the pool
    /// from a third thread, then verify that one additional checkin evicts exactly one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cross_thread_pickup_leaves_no_ghost() {
        let pool = Arc::new(WorkerFramePool::with_idle_ceiling(8, 4));
        pool.force_path.store(1, Ordering::Relaxed);
        let (_tx, drain) = watch::channel(false);
        let peers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let checkin_from_thread = |keys: Vec<usize>| {
            let pool = pool.clone();
            let drain = drain.clone();
            let peers = peers.clone();
            tokio::task::spawn_blocking(move || {
                for key in keys {
                    let (e, w) = UnixStream::pair().unwrap();
                    peers.lock().unwrap().push(w);
                    pool.checkin(key, PooledConn::new(e), drain.clone());
                }
            })
        };
        checkin_from_thread(vec![0, 1, 2, 3]).await.unwrap();
        // strict again (had tolerated a counted unwrap transient here). The
        // diagnostic in each message says whether a None was the transient.
        assert!(
            pool.checkout(0).await.is_some(),
            "key 0 was pooled; {}",
            pool.unwrap_diag()
        );
        assert!(
            pool.checkout(1).await.is_some(),
            "key 1 was pooled; {}",
            pool.unwrap_diag()
        );
        assert_eq!(
            pool.pool_reuse_total.load(Ordering::Relaxed),
            2,
            "two entries reused; {}",
            pool.unwrap_diag()
        );
        checkin_from_thread(vec![4, 5]).await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(
            pool.lru_evictions.load(Ordering::Relaxed),
            0,
            "idle is exactly at the ceiling"
        );
        checkin_from_thread(vec![6]).await.unwrap();
        wait_for_evictions(&pool, 1).await;
        assert_eq!(pool.lru_evictions.load(Ordering::Relaxed), 1);
        assert!(
            pool.checkout(2).await.is_none(),
            "the oldest survivor was the victim; {}",
            pool.unwrap_diag()
        );
        for key in [3usize, 4, 5, 6] {
            assert!(
                pool.checkout(key).await.is_some(),
                "key {key} still pooled; {}",
                pool.unwrap_diag()
            );
        }
        drop(peers);
    }

    /// an evicted connection is closed, not reachable, and its peer sees EOF.
    #[tokio::test(flavor = "current_thread")]
    async fn eviction_victim_is_closed_not_reused() {
        let pool = WorkerFramePool::with_idle_ceiling(2, 1);
        pool.force_path.store(1, Ordering::Relaxed);
        let (_tx, drain) = watch::channel(false);
        let (e0, w0) = UnixStream::pair().unwrap();
        pool.checkin(0, PooledConn::new(e0), drain.clone());
        let (e1, _w1) = UnixStream::pair().unwrap();
        pool.checkin(1, PooledConn::new(e1), drain.clone());
        wait_for_evictions(&pool, 1).await;
        assert!(
            pool.checkout(0).await.is_none(),
            "the victim is gone from the pool"
        );
        assert!(pool.checkout(1).await.is_some(), "the newest survives");
        // The victim's edge end was dropped by the pool and the watcher: the peer reads EOF.
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), w0.readable())
            .await
            .expect("peer becomes readable (EOF) once the edge end is closed");
        let _ = n;
        assert_eq!(
            w0.try_read(&mut buf).unwrap_or(0),
            0,
            "EOF on the evicted peer"
        );
    }

    /// Calibration: at a ceiling above the working set the counter stays at zero through
    /// a burst (the 512 arm in a session is this case by construction).
    #[tokio::test(flavor = "current_thread")]
    async fn lru_evictions_stay_zero_under_the_ceiling() {
        let pool = WorkerFramePool::with_idle_ceiling(4, 32);
        pool.force_path.store(1, Ordering::Relaxed);
        let (_tx, drain) = watch::channel(false);
        let mut peers = Vec::new();
        for i in 0..25usize {
            let (e, w) = UnixStream::pair().unwrap();
            peers.push(w);
            pool.checkin(i % 4, PooledConn::new(e), drain.clone());
        }
        tokio::task::yield_now().await;
        assert_eq!(pool.checkin_total.load(Ordering::Relaxed), 25);
        assert_eq!(pool.lru_evictions.load(Ordering::Relaxed), 0);
        assert!(pool.health_json().contains("\"lru_evictions\":0"));
        drop(peers);
    }

    /// Kill-the-reaper: a panicking reaper is respawned by the supervisor (deaths +
    /// spawned counters move), peer-closed connections are STILL never reused, and
    /// reaping/pooling resumes after the respawn.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn killed_reaper_respawns_and_reaping_resumes() {
        REAPER_TEST_FORCE.store(true, Ordering::Relaxed);
        let pool = WorkerFramePool::new(1);
        let (_tx, drain) = watch::channel(false);
        // First checkin spawns the reaper.
        let (e1, w1) = UnixStream::pair().unwrap();
        let fd1 = e1.as_raw_fd();
        pool.checkin(0, PooledConn::new(e1), drain.clone());
        tokio::time::sleep(Duration::from_millis(20)).await;
        let deaths_before = reaper_counters().deaths.load(Ordering::Relaxed);
        // Inject a panic on the NEXT item the reaper receives.: that item goes to
        // its OWN worker key, so the peer-closed check below can only ever meet e1.
        REAPER_PANIC_INJECT.store(true, Ordering::Relaxed);
        let (e2, _w2) = UnixStream::pair().unwrap();
        pool.checkin(1, PooledConn::new(e2), drain.clone());
        // poll for the death instead of sleeping a fixed 50 ms.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while reaper_counters().deaths.load(Ordering::Relaxed) == deaths_before {
            assert!(
                std::time::Instant::now() < deadline,
                "supervisor never observed the reaper death"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // Peer-closed conn from before the panic (its watch future died with the reaper,
        // so nothing will reap it) is never handed out AS LIVE.: this test went red
        // twice in the gates on a `Some` here, which the unwrap transient cannot produce.
        // Its own race: `is_stream_live` reads reactor-cached readiness, and under load
        // the reactor may not have recorded the peer's close yet, so the probe can pass
        // a connection the kernel already knows is closed. The contract at this layer is
        // therefore "refused by the probe, or dead on first read"; the second arm is
        // recorded when it happens so the rate of probe misses stays visible.
        drop(w1);
        match pool.checkout(0).await {
            None => {}
            Some(mut got) => {
                assert_eq!(got.stream.as_raw_fd(), fd1, "only e1 was pooled on key 0");
                let mut byte = [0u8; 1];
                let n = tokio::time::timeout(Duration::from_secs(2), got.stream.read(&mut byte))
                    .await
                    .expect("the first read on a peer-closed connection completes")
                    .unwrap_or(0);
                assert_eq!(
                    n, 0,
                    "a peer-closed connection handed out by the probe must be dead on first read"
                );
                eprintln!(
                    "killed_reaper: liveness probe passed a peer-closed connection (reactor \
                     readiness not yet recorded); it was dead on first read, as the contract requires"
                );
            }
        }
        // Reaping resumed: a fresh checkin on key 0 pools + checks out normally, and is
        // exactly e3 (key 0 is empty now; e2 lives on key 1).
        let (e3, _w3) = UnixStream::pair().unwrap();
        let fd3 = e3.as_raw_fd();
        pool.checkin(0, PooledConn::new(e3), drain);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let got = pool.checkout(0).await;
        assert!(
            got.is_some(),
            "pooling works after the respawn; {}",
            pool.unwrap_diag()
        );
        assert_eq!(
            got.unwrap().stream.as_raw_fd(),
            fd3,
            "the post-respawn checkin is what came out"
        );
    }

    /// Checkin racing drain: connections checked in while drain is firing are reaped,
    /// the pool empties (checkout → None), and nothing panics or leaks a lock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn checkin_racing_drain_empties_the_pool() {
        REAPER_TEST_FORCE.store(true, Ordering::Relaxed);
        let pool = Arc::new(WorkerFramePool::new(2));
        let (tx, drain) = watch::channel(false);
        let mut peers = Vec::new();
        for i in 0..8usize {
            let (e, w) = UnixStream::pair().unwrap();
            peers.push(w);
            pool.checkin(i % 2, PooledConn::new(e), drain.clone());
            if i == 3 {
                tx.send(true).unwrap(); // drain fires mid-burst
            }
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
        // Everything checked in before OR after the signal sees drain=true (watch
        // channels latch the value): the idle pool must be empty.
        assert!(pool.checkout(0).await.is_none(), "worker 0 pool drained");
        assert!(pool.checkout(1).await.is_none(), "worker 1 pool drained");
    }

    // ---------------------------------------------------------------- battery

    fn full_frame(body: &[u8]) -> Vec<u8> {
        hop_frame::encode_response(&ResponseFrame::Full {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: body.to_vec(),
        })
        .unwrap()
    }

    fn assert_full_with_body(frame: &ResponseFrame, body: &[u8]) {
        match frame {
            ResponseFrame::Full {
                status, body: got, ..
            } => {
                assert_eq!(*status, 200);
                assert_eq!(got, body);
            }
            other => panic!("expected Full, got {other:?}"),
        }
    }

    /// A frame delivered in one write, in two writes (prefix / envelope), and as a
    /// byte-dribble must decode identically — the buffered reader's arrival-pattern
    /// independence.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn buffered_read_decodes_any_arrival_pattern() {
        let caps = response_frame_caps();
        let bytes = full_frame(b"hello");

        // One write.
        let (mut w, mut edge) = UnixStream::pair().unwrap();
        w.write_all(&bytes).await.unwrap();
        let mut rbuf = FrameReadBuffer::new();
        let frame = rbuf
            .read_frame(&mut edge, &caps, true)
            .await
            .unwrap()
            .unwrap();
        assert_full_with_body(&frame, b"hello");
        assert!(!rbuf.has_surplus());

        // Two writes: prefix, then envelope.
        let (mut w, mut edge) = UnixStream::pair().unwrap();
        let (pfx, env) = bytes.split_at(FramePrefix::LEN);
        w.write_all(pfx).await.unwrap();
        let handle = tokio::spawn({
            let env = env.to_vec();
            async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                w.write_all(&env).await.unwrap();
                w
            }
        });
        let mut rbuf = FrameReadBuffer::new();
        let frame = rbuf
            .read_frame(&mut edge, &caps, true)
            .await
            .unwrap()
            .unwrap();
        assert_full_with_body(&frame, b"hello");
        drop(handle.await.unwrap());

        // Byte dribble.
        let (mut w, mut edge) = UnixStream::pair().unwrap();
        let handle = tokio::spawn({
            let bytes = bytes.clone();
            async move {
                for byte in bytes {
                    w.write_all(&[byte]).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                w
            }
        });
        let mut rbuf = FrameReadBuffer::new();
        let frame = rbuf
            .read_frame(&mut edge, &caps, true)
            .await
            .unwrap()
            .unwrap();
        assert_full_with_body(&frame, b"hello");
        drop(handle.await.unwrap());
    }

    /// Prefix split at EVERY offset 1..=5, each with and without a surplus byte riding
    /// behind the envelope: the frame decodes and the surplus is detected exactly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prefix_split_at_every_offset_with_and_without_surplus() {
        let caps = response_frame_caps();
        let bytes = full_frame(b"split-me");
        for split in 1..=5usize {
            for surplus in [false, true] {
                let (mut w, mut edge) = UnixStream::pair().unwrap();
                let (head, tail) = bytes.split_at(split);
                w.write_all(head).await.unwrap();
                let handle = tokio::spawn({
                    let mut rest = tail.to_vec();
                    if surplus {
                        rest.push(0xBF); // one out-of-turn byte behind the frame
                    }
                    async move {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        w.write_all(&rest).await.unwrap();
                        w
                    }
                });
                let mut rbuf = FrameReadBuffer::new();
                let frame = rbuf
                    .read_frame(&mut edge, &caps, true)
                    .await
                    .unwrap()
                    .unwrap();
                assert_full_with_body(&frame, b"split-me");
                // The dribbled surplus may or may not have arrived in the same kernel
                // window; poll briefly when expected.
                if surplus {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while !rbuf.has_surplus() && Instant::now() < deadline {
                        // one more speculative fill attempt: read whatever arrived
                        let _ =
                            timeout(Duration::from_millis(20), rbuf.stream_read(&mut edge)).await;
                    }
                    assert!(rbuf.has_surplus(), "split {split}: surplus byte detected");
                } else {
                    assert!(!rbuf.has_surplus(), "split {split}: clean boundary");
                }
                drop(handle.await.unwrap());
            }
        }
    }

    /// The never-replay boundary ( #9): EOF after a PARTIAL prefix is Err(502) —
    /// response bytes were committed, so this must NEVER classify as the retry-eligible
    /// stale signal. EOF at exactly zero bytes IS the stale signal (Ok(None)).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn eof_after_partial_prefix_is_502_never_stale() {
        let caps = response_frame_caps();

        // 3 prefix bytes then close → 502 (the never-replay side).
        let (mut w, mut edge) = UnixStream::pair().unwrap();
        w.write_all(&[0xBF, 0x01, 0x03]).await.unwrap();
        drop(w);
        let mut rbuf = FrameReadBuffer::new();
        assert_eq!(
            rbuf.read_frame(&mut edge, &caps, true).await.unwrap_err(),
            502,
            "partial prefix + EOF must be a committed-bytes error, not a stale signal"
        );

        // Zero bytes then close → Ok(None), the retry-eligible stale signal.
        let (w, mut edge) = UnixStream::pair().unwrap();
        drop(w);
        let mut rbuf = FrameReadBuffer::new();
        assert!(
            rbuf.read_frame(&mut edge, &caps, true)
                .await
                .unwrap()
                .is_none(),
            "EOF at zero bytes is the stale-before-dispatch signal"
        );
    }

    /// Surplus after a Full frame in the SAME kernel window: decoded response is
    /// served, but the boundary is dirty (exchange maps this to reusable=false).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn surplus_behind_full_frame_is_dirty() {
        let caps = response_frame_caps();
        let mut bytes = full_frame(b"ok");
        bytes.extend_from_slice(&full_frame(b"unsolicited")); // a whole extra frame
        let (mut w, mut edge) = UnixStream::pair().unwrap();
        w.write_all(&bytes).await.unwrap();
        let mut rbuf = FrameReadBuffer::new();
        let frame = rbuf
            .read_frame(&mut edge, &caps, true)
            .await
            .unwrap()
            .unwrap();
        assert_full_with_body(&frame, b"ok");
        assert!(
            rbuf.has_surplus(),
            "a complete extra frame behind Full must read as surplus (dirty, never pooled)"
        );
    }

    /// checkin refuses a dirty connection outright — the put-back invariant is
    /// machine-checked, not caller etiquette.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn checkin_refuses_surplus_carrying_connection() {
        let pool = WorkerFramePool::new(1);
        let (edge, _worker) = UnixStream::pair().unwrap();
        let mut conn = PooledConn::new(edge);
        conn.rbuf.buf.extend_from_slice(b"leftover");
        assert!(conn.rbuf.has_surplus(), "test setup: surplus expected");
        let (_tx, drain) = watch::channel(false);
        pool.checkin(0, conn, drain);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            pool.checkout(0).await.is_none(),
            "a surplus-carrying connection is never pooled"
        );
    }

    /// Envelope larger than the scratch target spills correctly (reserve + continue).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn envelope_larger_than_scratch_spills() {
        let caps = response_frame_caps();
        let big = vec![0x41u8; FRAME_SCRATCH_TARGET * 3];
        let bytes = full_frame(&big);
        let (mut w, mut edge) = UnixStream::pair().unwrap();
        let handle = tokio::spawn(async move {
            w.write_all(&bytes).await.unwrap();
            w
        });
        let mut rbuf = FrameReadBuffer::new();
        let frame = rbuf
            .read_frame(&mut edge, &caps, true)
            .await
            .unwrap()
            .unwrap();
        assert_full_with_body(&frame, &big);
        assert!(!rbuf.has_surplus());
        drop(handle.await.unwrap());
    }

    /// Streaming frames coalesced into ONE write: every frame after the first must be
    /// served from the buffer WITHOUT another socket await ( #8 — proven by never
    /// writing again and requiring completion within a timeout), and a drain signal
    /// that has already fired must not stop buffered frames from draining.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn coalesced_stream_frames_complete_without_socket_awaits() {
        let caps = response_frame_caps();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &hop_frame::encode_response(&ResponseFrame::Chunk {
                data: b"chunk-1".to_vec(),
            })
            .unwrap(),
        );
        bytes.extend_from_slice(&hop_frame::encode_response(&ResponseFrame::End).unwrap());
        let (mut w, mut edge) = UnixStream::pair().unwrap();
        w.write_all(&bytes).await.unwrap();
        // Note: w stays OPEN and silent — if the reader wrongly awaited the socket,
        // the timeouts below would fire.

        // Prime: the FIRST frame's speculative read pulls the coalesced End into
        // scratch — that is how frames become "buffered" in the real streaming flow.
        let mut rbuf = FrameReadBuffer::new();
        let chunk = rbuf
            .read_frame(&mut edge, &caps, true)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(chunk, ResponseFrame::Chunk { .. }));
        assert!(rbuf.has_surplus(), "End must be sitting in scratch");

        let (tx, mut drain) = watch::channel(false);
        tx.send(true).unwrap(); // drain has ALREADY fired

        let end = timeout(
            Duration::from_millis(200),
            rbuf.read_frame_or_drain(&mut edge, &caps, &mut drain),
        )
        .await
        .expect("buffered End must not await the socket")
        .unwrap()
        .expect("drain must not preempt a buffered complete frame");
        assert!(matches!(end, ResponseFrame::End));
        assert!(!rbuf.has_surplus());
    }

    /// Drain firing with a complete frame + a PARTIAL next frame buffered: the complete
    /// frame is served; the partial remainder reads as surplus (dirty boundary).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_with_partial_next_frame_marks_dirty() {
        let caps = response_frame_caps();
        let mut bytes = hop_frame::encode_response(&ResponseFrame::Chunk {
            data: b"prime".to_vec(),
        })
        .unwrap();
        bytes.extend_from_slice(&hop_frame::encode_response(&ResponseFrame::End).unwrap());
        bytes.extend_from_slice(&[0xBF, 0x01]); // partial next prefix
        let (mut w, mut edge) = UnixStream::pair().unwrap();
        w.write_all(&bytes).await.unwrap();

        // Prime scratch via the first frame's speculative read (as the real flow does).
        let mut rbuf = FrameReadBuffer::new();
        let chunk = rbuf
            .read_frame(&mut edge, &caps, true)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(chunk, ResponseFrame::Chunk { .. }));

        let (tx, mut drain) = watch::channel(false);
        tx.send(true).unwrap();

        let end = timeout(
            Duration::from_millis(200),
            rbuf.read_frame_or_drain(&mut edge, &caps, &mut drain),
        )
        .await
        .expect("no socket await needed")
        .unwrap()
        .expect("complete buffered frame drains");
        assert!(matches!(end, ResponseFrame::End));
        assert!(
            rbuf.has_surplus(),
            "partial next frame is surplus — the connection is dirty"
        );
    }
}

/// In-flight gauges must return to zero on every exit, or dispatch selection
/// biases away from a worker with a leaked count. Dedicated high worker indices
/// avoid collisions; global counters are checked with relative deltas.
#[cfg(all(test, feature = "hop-timing"))]
mod dispatch_tests {
    use super::dispatch::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn guard_returns_to_zero_on_drop_and_counts_convoys() {
        let g = gauges();
        let idx = 10;
        let base_busy = g.chosen_busy.load(Ordering::Relaxed);
        let base_bad = g.bad_dispatch.load(Ordering::Relaxed);

        // Normal completion: acquire -> depth 0 recorded -> drop -> zero.
        let guard = InFlightGuard::acquire(idx, 12);
        assert_eq!(g.in_flight[idx].load(Ordering::Relaxed), 1);
        drop(guard);
        assert_eq!(g.in_flight[idx].load(Ordering::Relaxed), 0);

        // Convoy accounting: second concurrent attempt on the SAME busy worker while
        // worker 11 idles => chosen_busy + bad_dispatch both increment.
        let g1 = InFlightGuard::acquire(idx, 12);
        let g2 = InFlightGuard::acquire(idx, 12);
        assert_eq!(g.in_flight[idx].load(Ordering::Relaxed), 2);
        assert_eq!(g.chosen_busy.load(Ordering::Relaxed), base_busy + 1);
        assert_eq!(g.bad_dispatch.load(Ordering::Relaxed), base_bad + 1);
        // Early-error path is the same Drop: dropping in any order returns to zero.
        drop(g1);
        drop(g2);
        assert_eq!(g.in_flight[idx].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn guard_returns_to_zero_on_future_cancellation() {
        // The hop future is dropped mid-exchange when a client disconnects; the guard's Drop
        // must still run. Model it exactly: a task acquires the guard, parks on a pending
        // await, and is aborted.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            let idx = 12;
            let g = gauges();
            let task = tokio::spawn(async move {
                let _guard = InFlightGuard::acquire(idx, 13);
                // Park forever; only cancellation can end this future.
                std::future::pending::<()>().await;
            });
            tokio::task::yield_now().await; // let the task run to its park point
            assert_eq!(
                g.in_flight[idx].load(Ordering::Relaxed),
                1,
                "guard held while parked"
            );
            task.abort();
            let _ = task.await; // JoinError::Cancelled — the drop has run
            assert_eq!(
                g.in_flight[idx].load(Ordering::Relaxed),
                0,
                "cancellation must release the gauge"
            );
        });
    }

    // A2: candidate_order returns an alloc-free CandidateOrder; tests materialize
    // via.iter.collect so the assertions stay byte-identical to the Vec era.
    fn order_vec(start: usize, n: usize, m: DispatchMode) -> Vec<usize> {
        candidate_order_with(start, n, m).iter().collect()
    }

    // The gauges are a process-wide OnceLock singleton, so the two tests that acquire
    // InFlightGuards MUST NOT run concurrently — one test's busy workers leak into the
    // other's sort assertions (a latent race the pre-suite dodged by timing).
    fn gauge_test_lock() -> std::sync::MutexGuard<'static, ()> {
        // delegates to the dispatch module's shared lock so the sticky test
        // module (plain cfg(test)) and this hop-timing module cannot race.
        super::dispatch::test_serial_lock()
    }

    #[test]
    fn candidate_order_rr_and_least_outstanding() {
        let _serial = gauge_test_lock();
        // RR: pure rotation from start.
        assert_eq!(order_vec(2, 4, DispatchMode::Rr), vec![2, 3, 0, 1]);
        // RR is the one mode allowed above MAX_WORKERS: the lazy rotation must cover
        // every index of a 20-wide field (the stack buffer would have truncated it).
        let wide = order_vec(18, 20, DispatchMode::Rr);
        assert_eq!(wide.len(), 20);
        assert_eq!(&wide[0..3], &[18, 19, 0]);
        // Least-outstanding: ascending in-flight, stable (RR-rotation) tie-break. Use the
        // dedicated index 13 as the loaded worker in a 14-wide hypothetical field: workers
        // 0..13 idle except 13 -> 13 must sort last despite rotation starting at 13.
        let _busy = InFlightGuard::acquire(13, 14);
        let order = order_vec(13, 14, DispatchMode::LeastOutstanding);
        assert_eq!(
            *order.last().unwrap(),
            13,
            "busy worker sorts last under LO"
        );
        assert_eq!(order[0], 0, "idle workers keep rotation order among ties");
    }

    #[test]
    fn candidate_order_free_first_promotes_first_idle_only_when_rr_choice_busy() {
        let _serial = gauge_test_lock();
        // Idle RR choice: rotation untouched. Like the LO test, only the dedicated high
        // indices (8..14) are asserted — low indices are shared gauge state across tests.
        let idle_order = order_vec(8, 14, DispatchMode::FreeFirst);
        assert_eq!(
            &idle_order[0..3],
            &[8, 9, 10],
            "idle RR choice keeps rotation"
        );
        // Busy RR choice at 10: first idle IN RR ORDER from the rotation is promoted to
        // the front; the rest of the sequence keeps rotation order (failover unchanged).
        let _busy10 = InFlightGuard::acquire(10, 14);
        let _busy11 = InFlightGuard::acquire(11, 14);
        let order = order_vec(10, 14, DispatchMode::FreeFirst);
        assert_eq!(order[0], 12, "first idle worker in RR order is promoted");
        assert_eq!(
            &order[1..4],
            &[10, 11, 13],
            "remaining sequence keeps rotation order"
        );
        // With 10..13 all busy the relative rotation order of the busy range is preserved
        // regardless of whether a (test-shared) low index gets promoted — failover among
        // the busy workers stays RR. (True all-busy = pure rotation by construction.)
        let _busy12 = InFlightGuard::acquire(12, 14);
        let _busy13 = InFlightGuard::acquire(13, 14);
        let busy_range: Vec<usize> = order_vec(10, 14, DispatchMode::FreeFirst)
            .into_iter()
            .filter(|&i| i >= 10)
            .collect();
        assert_eq!(
            busy_range,
            vec![10, 11, 12, 13],
            "busy-range failover order stays RR"
        );
    }

    // Tests touching in-flight or parked counters take the shared gauge_test_lock
    // because these counters are process-global.

    #[test]
    fn capped_try_acquire_enforces_k_and_raced_losers_get_none() {
        let _serial = gauge_test_lock();
        let idx = 13;
        let g1 = InFlightGuard::try_acquire(idx, 16, Some(2)).expect("slot 1");
        let g2 = InFlightGuard::try_acquire(idx, 16, Some(2)).expect("slot 2");
        assert!(
            InFlightGuard::try_acquire(idx, 16, Some(2)).is_none(),
            "over-cap admitted"
        );
        drop(g1);
        let g3 = InFlightGuard::try_acquire(idx, 16, Some(2)).expect("freed slot");
        drop(g2);
        drop(g3);
        assert_eq!(gauges().in_flight[idx].load(Ordering::SeqCst), 0);
    }

    #[test]
    fn capped_hammer_never_exceeds_k_and_ledger_counts_admits_only() {
        // 8 OS threads hammer one worker at K=3: the gauge must never exceed 3, and
        // dispatch_total must advance exactly once per ADMITTED request.
        let _serial = gauge_test_lock();
        let idx = 14;
        #[cfg(feature = "hop-timing")]
        let base_total = gauges().dispatch_total.load(Ordering::Relaxed);
        let admitted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let admitted = admitted.clone();
            let peak = peak.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..200 {
                    if let Some(_g) = InFlightGuard::try_acquire(idx, 16, Some(3)) {
                        admitted.fetch_add(1, Ordering::SeqCst);
                        let now = gauges().in_flight[idx].load(Ordering::SeqCst);
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::yield_now();
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert!(
            peak.load(Ordering::SeqCst) <= 3,
            "cap breached: {}",
            peak.load(Ordering::SeqCst)
        );
        assert_eq!(gauges().in_flight[idx].load(Ordering::SeqCst), 0);
        // The ledger delta is at least the admitted count (other tests' guard
        // acquisitions can interleave between the bracketing reads even under the
        // lock, via their spawned runtimes) -- the EXACT one-write-per-admit pin is
        // the deterministic test below.
        #[cfg(feature = "hop-timing")]
        assert!(
            gauges().dispatch_total.load(Ordering::Relaxed) - base_total
                >= admitted.load(Ordering::SeqCst) as u64,
            "ledger under-counted admitted requests"
        );
        let _ = admitted;
    }

    #[test]
    fn failed_cas_writes_nothing_to_the_ledger() {
        // Failed admission attempts leave dispatch counters unchanged; successes record once.
        let _serial = gauge_test_lock();
        let idx = 5;
        let base = gauges().dispatch_total.load(Ordering::Relaxed);
        let g1 = InFlightGuard::try_acquire(idx, 16, Some(1)).expect("slot");
        for _ in 0..5 {
            assert!(InFlightGuard::try_acquire(idx, 16, Some(1)).is_none());
        }
        drop(g1);
        assert_eq!(
            gauges().dispatch_total.load(Ordering::Relaxed) - base,
            1,
            "exactly one ledger write for one admitted request; failures write none"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn drop_wakes_a_parked_waiter_from_another_thread() {
        // Under parallel completion, a waiter on a full worker must wake when another
        // thread frees a slot. Enable the completion-side wake check first.
        let _serial = gauge_test_lock();
        set_capped_for_tests(true);
        let idx = 15;
        let g1 = InFlightGuard::try_acquire(idx, 16, Some(1)).expect("fill");
        let mask = 1u32 << idx;
        let waiter =
            tokio::spawn(async move { super::park_for_slot(mask, 1, &drain_stub()).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(PARKED.load(Ordering::SeqCst), 1, "waiter should be parked");
        drop(g1); // frees the slot from this thread; Drop must notify
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("waiter timed out -- lost wakeup")
            .expect("join");
        assert!(res.is_ok());
        assert_eq!(PARKED.load(Ordering::SeqCst), 0);
        set_capped_for_tests(false);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dead_worker_never_unparks_a_waiter() {
        // a connect-dead worker (gauge stuck at 0) is NOT in the at-capacity
        // mask, so the waiter must keep waiting even though that gauge reads < K.
        let _serial = gauge_test_lock();
        set_capped_for_tests(true);
        let capped_idx = 9;
        let g = InFlightGuard::try_acquire(capped_idx, 16, Some(1)).expect("fill");
        let mask = 1u32 << capped_idx;
        let waiter =
            tokio::spawn(async move { super::park_for_slot(mask, 1, &drain_stub()).await });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            PARKED.load(Ordering::SeqCst),
            1,
            "waiter must still be parked"
        );
        drop(g);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("waiter should admit once the CAPPED worker frees")
            .expect("join");
        set_capped_for_tests(false);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelled_waiter_forwards_the_wake() {
        // If waiter A is cancelled, its unconsumed completion notification must still reach waiter B.
        let _serial = gauge_test_lock();
        set_capped_for_tests(true);
        let idx = 11;
        let g1 = InFlightGuard::try_acquire(idx, 16, Some(1)).expect("fill");
        let mask = 1u32 << idx;
        let waiter_a =
            tokio::spawn(async move { super::park_for_slot(mask, 1, &drain_stub()).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let waiter_b =
            tokio::spawn(async move { super::park_for_slot(mask, 1, &drain_stub()).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(PARKED.load(Ordering::SeqCst), 2);
        waiter_a.abort(); // cancellation: ParkGuard must decrement, wake must forward
        let _ = waiter_a.await;
        assert_eq!(PARKED.load(Ordering::SeqCst), 1);
        drop(g1);
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), waiter_b)
            .await
            .expect("waiter B stranded -- wake was not forwarded")
            .expect("join");
        assert!(res.is_ok());
        set_capped_for_tests(false);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_wakes_every_parked_waiter_to_503() {
        let _serial = gauge_test_lock();
        set_capped_for_tests(true);
        let idx = 7;
        let g = InFlightGuard::try_acquire(idx, 16, Some(1)).expect("fill");
        let mask = 1u32 << idx;
        let (tx, rx) = tokio::sync::watch::channel(false);
        let r1 = rx.clone();
        let r2 = rx.clone();
        let w1 = tokio::spawn(async move { super::park_for_slot(mask, 1, &r1).await });
        let w2 = tokio::spawn(async move { super::park_for_slot(mask, 1, &r2).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(PARKED.load(Ordering::SeqCst), 2);
        tx.send(true).expect("drain");
        for w in [w1, w2] {
            let res = tokio::time::timeout(std::time::Duration::from_secs(5), w)
                .await
                .expect("parked waiter ignored drain")
                .expect("join");
            assert_eq!(res, Err(503));
        }
        assert_eq!(PARKED.load(Ordering::SeqCst), 0);
        drop(g);
        set_capped_for_tests(false);
    }

    #[test]
    fn uncapped_paths_are_untouched_by_default() {
        // Default-off no-op: with the wake gate unlatched, acquire/drop take the
        // original Relaxed path; the park statics stay untouched.
        let _serial = gauge_test_lock();
        assert!(!capped(), "test battery must not leak the latch");
        let g = InFlightGuard::acquire(6, 16);
        drop(g);
        assert_eq!(gauges().in_flight[6].load(Ordering::Relaxed), 0);
        assert_eq!(PARKED.load(Ordering::SeqCst), 0);
    }

    fn drain_stub() -> tokio::sync::watch::Receiver<bool> {
        static TX: std::sync::OnceLock<tokio::sync::watch::Sender<bool>> =
            std::sync::OnceLock::new();
        TX.get_or_init(|| tokio::sync::watch::channel(false).0)
            .subscribe()
    }
}

// Sticky-affinity tests run in all builds. Each takes the shared serial lock and
// resets the store because pin counts, shards and gauges are process-global.
#[cfg(test)]
mod sticky_tests {
    use super::dispatch::*;
    use std::sync::atomic::Ordering;

    fn fresh() -> std::sync::MutexGuard<'static, ()> {
        let guard = test_serial_lock();
        sticky_reset_for_tests();
        guard
    }

    #[test]
    fn parse_ladder_accepts_sticky() {
        assert_eq!(parse_mode("sticky"), Some(DispatchMode::Sticky));
        assert_eq!(mode_name(DispatchMode::Sticky), "sticky");
        assert_eq!(parse_mode("sticky-ish"), None);
    }

    #[test]
    fn sticky_order_is_pin_first_with_rotated_failover_tail() {
        // Pinned worker leads; the rest keep the RR rotation from `start` -- the
        // returned order IS the Connect-failover sequence, so a dead pin fails over.
        let order: Vec<usize> = sticky_order(2, 0, 4).iter().collect();
        assert_eq!(order, vec![2, 0, 1, 3]);
        let order: Vec<usize> = sticky_order(0, 3, 4).iter().collect();
        assert_eq!(order, vec![0, 3, 1, 2]);
        // Every worker exactly once.
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![0, 1, 2, 3]);
    }

    #[test]
    fn miss_assigns_fewest_pins_and_hit_returns_it() {
        let _serial = fresh();
        let miss0 = STICKY_MISS_TOTAL.load(Ordering::Relaxed);
        let hit0 = STICKY_HIT_TOTAL.load(Ordering::Relaxed);
        // Four distinct keys over four workers: index tie-break gives 0,1,2,3.
        let a = sticky_lookup_or_assign(1001, 4);
        let b = sticky_lookup_or_assign(1002, 4);
        let c = sticky_lookup_or_assign(1003, 4);
        let d = sticky_lookup_or_assign(1004, 4);
        let mut got = vec![a, b, c, d];
        got.sort_unstable();
        assert_eq!(got, vec![0, 1, 2, 3], "balanced distinct assignment");
        assert_eq!(STICKY_MISS_TOTAL.load(Ordering::Relaxed) - miss0, 4);
        // Hits return the stored pin without touching the counts.
        assert_eq!(sticky_lookup_or_assign(1001, 4), a);
        assert_eq!(sticky_lookup_or_assign(1004, 4), d);
        assert_eq!(STICKY_HIT_TOTAL.load(Ordering::Relaxed) - hit0, 2);
        assert_eq!(STICKY_MISS_TOTAL.load(Ordering::Relaxed) - miss0, 4);
        assert_eq!(sticky_entries(), 4);
        for c in PIN_COUNTS.iter().take(4) {
            assert_eq!(c.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn sequential_16_misses_land_4_4_4_4() {
        // The bench shape: 16 connections, 4 workers, zero gauges -- the
        // realized assignment vector must be exactly balanced.
        let _serial = fresh();
        for k in 0..16u64 {
            sticky_lookup_or_assign(2000 + k, 4);
        }
        for (i, c) in PIN_COUNTS.iter().enumerate().take(4) {
            assert_eq!(c.load(Ordering::Relaxed), 4, "worker {i}");
        }
        assert_eq!(sticky_entries(), 16);
    }

    #[test]
    fn concurrent_misses_stay_balanced() {
        // N threads pinning distinct keys concurrently -- the assign lock makes
        // the max-min <= 1 invariant deterministic, not probabilistic.
        let _serial = fresh();
        let mut handles = Vec::new();
        for t in 0..16u64 {
            handles.push(std::thread::spawn(move || {
                sticky_lookup_or_assign(3000 + t, 4)
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let counts: Vec<usize> = (0..4)
            .map(|i| PIN_COUNTS[i].load(Ordering::Relaxed))
            .collect();
        let max = *counts.iter().max().unwrap();
        let min = *counts.iter().min().unwrap();
        assert!(
            max - min <= 1,
            "unbalanced concurrent assignment: {counts:?}"
        );
        assert_eq!(counts.iter().sum::<usize>(), 16);
    }

    #[test]
    fn assignment_tiebreak_prefers_lower_in_flight() {
        // Equal pins everywhere; worker 0 busy (production try_acquire path) -- the
        // next miss must go to the idle worker 1, not index order.
        let _serial = fresh();
        let busy = InFlightGuard::try_acquire(0, 4, None).expect("uncapped");
        let idx = sticky_lookup_or_assign(4001, 4);
        assert_eq!(idx, 1, "depth tie-break must skip the busy worker");
        drop(busy);
    }

    #[test]
    fn repin_moves_on_connect_and_ignores_stale_from() {
        let _serial = fresh();
        let idx = sticky_lookup_or_assign(5001, 4);
        assert_eq!(idx, 0);
        // The Connect-failover re-pin: counts follow the pin.
        sticky_repin(5001, 0, 3);
        assert_eq!(sticky_lookup_or_assign(5001, 4), 3);
        assert_eq!(PIN_COUNTS[0].load(Ordering::Relaxed), 0);
        assert_eq!(PIN_COUNTS[3].load(Ordering::Relaxed), 1);
        // A stale re-pin (stored pin already moved) is a no-op.
        sticky_repin(5001, 0, 2);
        assert_eq!(sticky_lookup_or_assign(5001, 4), 3);
        assert_eq!(PIN_COUNTS[2].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn shard_clear_at_cap_evicts_counts_and_self_heals() {
        let _serial = fresh();
        let evict0 = STICKY_EVICT_TOTAL.load(Ordering::Relaxed);
        // Fill exactly one shard (keys congruent mod the shard count) to its cap.
        let shard_keys = |i: u64| 16 * i; // all land in shard 0
        for i in 0..STICKY_SHARD_MAX as u64 {
            sticky_lookup_or_assign(shard_keys(i), 4);
        }
        assert_eq!(sticky_entries(), STICKY_SHARD_MAX);
        let total_pins: usize = (0..4).map(|i| PIN_COUNTS[i].load(Ordering::Relaxed)).sum();
        assert_eq!(total_pins, STICKY_SHARD_MAX);
        // The next miss in that shard clears it, then records the one new pin.
        sticky_lookup_or_assign(shard_keys(STICKY_SHARD_MAX as u64), 4);
        assert_eq!(
            STICKY_EVICT_TOTAL.load(Ordering::Relaxed) - evict0,
            STICKY_SHARD_MAX as u64
        );
        assert_eq!(sticky_entries(), 1);
        let total_pins: usize = (0..4).map(|i| PIN_COUNTS[i].load(Ordering::Relaxed)).sum();
        assert_eq!(total_pins, 1, "cleared pins must release their counts");
    }

    #[test]
    fn reread_returns_stored_pin_and_restores_a_cleared_one() {
        let _serial = fresh();
        sticky_lookup_or_assign(6001, 4);
        sticky_repin(6001, 0, 2);
        assert_eq!(sticky_reread(6001, 0), 2, "re-read follows a moved pin");
        // A cleared entry (store reset models the shard clear) restores the prior
        // pin rather than re-running assignment.
        sticky_reset_for_tests();
        assert_eq!(sticky_reread(6001, 1), 1);
        assert_eq!(sticky_entries(), 1, "restored entry is stored again");
        assert_eq!(PIN_COUNTS[1].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn fallback_counts_its_own_lane() {
        // unkeyed requests are neither hits nor misses.
        let _serial = fresh();
        let f0 = STICKY_FALLBACK_TOTAL.load(Ordering::Relaxed);
        let h0 = STICKY_HIT_TOTAL.load(Ordering::Relaxed);
        let m0 = STICKY_MISS_TOTAL.load(Ordering::Relaxed);
        sticky_note_fallback();
        sticky_note_fallback();
        assert_eq!(STICKY_FALLBACK_TOTAL.load(Ordering::Relaxed) - f0, 2);
        assert_eq!(STICKY_HIT_TOTAL.load(Ordering::Relaxed), h0);
        assert_eq!(STICKY_MISS_TOTAL.load(Ordering::Relaxed), m0);
    }

    #[test]
    fn sticky_fallback_order_matches_least_outstanding() {
        // The unkeyed path under sticky mode sorts exactly like least-outstanding --
        // the default-off equivalence in selector terms.
        let _serial = fresh();
        let lo: Vec<usize> = candidate_order_with(1, 4, DispatchMode::LeastOutstanding)
            .iter()
            .collect();
        let st: Vec<usize> = candidate_order_with(1, 4, DispatchMode::Sticky)
            .iter()
            .collect();
        assert_eq!(lo, st);
    }

    #[test]
    fn at_capacity_pinned_worker_never_repins_p8() {
        // A full pinned worker can cause a request to run elsewhere without moving
        // the pin. Only connection failure permits re-pinning; capacity alone must
        // not shift connection affinity.
        let _serial = fresh();
        let pin = sticky_lookup_or_assign(8001, 4);
        assert_eq!(pin, 0);
        let full = InFlightGuard::try_acquire(0, 4, Some(1)).expect("fill to K=1");
        // The loop's view: pin-first order, pin at capacity, next candidate serves.
        assert!(
            InFlightGuard::try_acquire(0, 4, Some(1)).is_none(),
            "pinned worker reports at-capacity"
        );
        let served = InFlightGuard::try_acquire(1, 4, Some(1)).expect("failover slot");
        // AtCapacity is NOT a Connect failure: no sticky_repin call happens, and the
        // stored pin is unchanged for the connection's next request.
        assert_eq!(sticky_lookup_or_assign(8001, 4), 0, "pin must not move");
        assert_eq!(PIN_COUNTS[0].load(Ordering::Relaxed), 1);
        assert_eq!(PIN_COUNTS[1].load(Ordering::Relaxed), 0);
        drop(full);
        drop(served);
    }

    #[test]
    fn pins_json_shape() {
        let _serial = fresh();
        sticky_lookup_or_assign(7001, 4);
        sticky_lookup_or_assign(7002, 4);
        assert_eq!(sticky_pins_json(4), "[1,1,0,0]");
    }
}

//! the oxo-owned idle-connection pool, with ONE aggregate ceiling.
//!
//! measured why the pingora-pool ceiling did not mean what it said: pingora keeps
//! its LRU per thread (`RwLock<ThreadLocal<RefCell<LruCache>>>`), `put` trims only the
//! calling thread's cache, and a connection picked up on another thread leaves a ghost
//! entry behind. With 16 edge threads, 15 of every 16 cache entries were ghosts and a
//! per-thread ceiling of 8 -- nominally 128 idle connections -- evicted 13.8% of
//! check-ins. This pool has one ceiling, one ordering, and no ghosts: every entry is
//! removed by exactly one of `get`, eviction inside `put`, or `pop_closed`, all under
//! the same lock.
//!
//! The observable contract `frame_hop`'s watcher relies on is kept exactly as pingora
//! delivered it: `get` sends `true` on the connection's pickup channel AFTER the lock is
//! released; an eviction inside `put` `notify_one`s the victim's `Notify`, drops its
//! pickup sender (the watcher's `Err(watch_use)` arm) and drops the pool's reference to
//! the connection, all after the lock is released; `pop_closed` is idempotent. Pickup
//! within a key is FIFO, as pingora's `PoolNode::get_any` was, so the A/B varies
//! one thing.
//!
//! Lock discipline: one `std::sync::Mutex`, held for a few map operations and never
//! across an await (nothing here is async) or a channel send. `try_lock` first, so
//! contention is a counter (`lock_contended_total`, `lock_wait_ns`) and not a guess.
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::Instant;
use tokio::sync::{oneshot, Notify};

/// Same shape and constructor as `pingora_pool::ConnectionMeta`, so the watcher, the
/// reaper's `WatchItem` and every `pop_closed` call site in `frame_hop` are byte-identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ConnectionMeta {
    pub key: u64,
    pub id: i32,
}

impl ConnectionMeta {
    pub(super) fn new(key: u64, id: i32) -> Self {
        Self { key, id }
    }
}

struct Entry<S> {
    /// The ONLY pool-side reference to the connection. Never cloned: an extra clone is
    /// the reuse-collapse defect (`Arc::try_unwrap` fails at checkout).
    conn: S,
    /// Fires `true` on pickup; dropped un-sent on eviction.
    notify_use: oneshot::Sender<bool>,
    /// `notify_one` on eviction (a stored permit, so a late poll still sees it).
    notify_close: Arc<Notify>,
    id: i32,
}

struct Inner<S> {
    /// Insertion order, allocated under the lock. The ONLY ordering key: ids are
    /// allocated before the lock and are i32, which wraps.
    next_seq: u64,
    /// worker key -> seq -> entry. FIFO pickup is `pop_first`.
    by_key: HashMap<u64, BTreeMap<u64, Entry<S>>>,
    /// id -> seq, for `pop_closed` (the watcher only knows its meta).
    by_id: HashMap<i32, u64>,
    /// seq -> (key, id), oldest first. `order.len()` IS the idle count.
    order: BTreeMap<u64, (u64, i32)>,
    /// The largest idle count ever held after an insert. Recorded BEFORE the trim that
    /// follows, so it can read `size + 1` but never more: the ceiling CLIPS it. It
    /// measures the idle working set only on a pool whose ceiling exceeds that set;
    /// a reading of `size + 1` says "the ceiling is binding", not "the set is size + 1"
    /// (, correcting the wording).
    high_water: usize,
}

impl<S> Inner<S> {
    fn evict_oldest(&mut self) -> Option<Entry<S>> {
        let (seq, (key, id)) = self.order.pop_first()?;
        self.by_id.remove(&id);
        let e = self.by_key.get_mut(&key).and_then(|node| node.remove(&seq));
        if self.by_key.get(&key).is_some_and(|node| node.is_empty()) {
            self.by_key.remove(&key);
        }
        debug_assert!(e.is_some(), "order and by_key disagree at seq {seq}");
        e
    }

    /// Three structures, one truth: every mutation ends with them agreeing.
    fn check(&self) {
        debug_assert_eq!(
            self.by_key.values().map(|n| n.len()).sum::<usize>(),
            self.order.len(),
            "by_key and order disagree"
        );
        debug_assert_eq!(
            self.by_id.len(),
            self.order.len(),
            "by_id and order disagree"
        );
        if cfg!(debug_assertions) {
            for (seq, (key, id)) in &self.order {
                debug_assert!(
                    self.by_key.get(key).is_some_and(|n| n.contains_key(seq)),
                    "order entry seq {seq} (key {key}, id {id}) missing from by_key"
                );
                debug_assert_eq!(self.by_id.get(id), Some(seq), "by_id disagrees for id {id}");
            }
        }
    }
}

/// The owned pool. `S` is whatever the caller stores (frame_hop stores
/// `Arc<tokio::sync::Mutex<PooledConn>>`).
pub(super) struct ConnectionPool<S> {
    inner: Mutex<Inner<S>>,
    size: usize,
    /// Lock acquisitions that found the mutex held (a `try_lock` miss).
    pub(super) lock_contended_total: AtomicU64,
    /// Nanoseconds spent blocking after a `try_lock` miss, summed.
    pub(super) lock_wait_ns: AtomicU64,
}

impl<S> ConnectionPool<S> {
    pub(super) fn new(size: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                next_seq: 1,
                by_key: HashMap::new(),
                by_id: HashMap::new(),
                order: BTreeMap::new(),
                high_water: 0,
            }),
            size: size.max(1),
            lock_contended_total: AtomicU64::new(0),
            lock_wait_ns: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner<S>> {
        match self.inner.try_lock() {
            Ok(g) => g,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => {
                self.lock_contended_total.fetch_add(1, Ordering::Relaxed);
                let t0 = Instant::now();
                let g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
                self.lock_wait_ns
                    .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
                g
            }
        }
    }

    /// Any-of pickup for the key, oldest first. The pickup notification is sent AFTER
    /// the lock is released, as pingora's `release()` did.
    pub(super) fn get(&self, key: &u64) -> Option<S> {
        let entry = {
            let mut g = self.lock();
            let popped = g.by_key.get_mut(key).and_then(|node| node.pop_first());
            let (seq, e) = popped?;
            if g.by_key.get(key).is_some_and(|node| node.is_empty()) {
                g.by_key.remove(key);
            }
            g.order.remove(&seq);
            g.by_id.remove(&e.id);
            g.check();
            e
        };
        let _ = entry.notify_use.send(true);
        Some(entry.conn)
    }

    /// Insert, then trim to the ceiling from the oldest across ALL keys. The victim's
    /// channels and connection are touched only after the lock is released, in pingora's
    /// order: `notify_one`, then the pickup sender drops, then the pool's reference.
    pub(super) fn put(
        &self,
        meta: &ConnectionMeta,
        conn: S,
    ) -> (Arc<Notify>, oneshot::Receiver<bool>) {
        let (tx, rx) = oneshot::channel();
        let notify = Arc::new(Notify::new());
        let victim = {
            let mut g = self.lock();
            let seq = g.next_seq;
            g.next_seq += 1;
            g.order.insert(seq, (meta.key, meta.id));
            let dup = g.by_id.insert(meta.id, seq);
            debug_assert!(dup.is_none(), "duplicate pool id {}", meta.id);
            g.by_key.entry(meta.key).or_default().insert(
                seq,
                Entry {
                    conn,
                    notify_use: tx,
                    notify_close: notify.clone(),
                    id: meta.id,
                },
            );
            let offered = g.order.len();
            if offered > g.high_water {
                g.high_water = offered;
            }
            let v = if offered > self.size {
                g.evict_oldest()
            } else {
                None
            };
            g.check();
            v
        };
        if let Some(v) = victim {
            v.notify_close.notify_one();
            drop(v.notify_use);
            drop(v.conn);
        }
        (notify, rx)
    }

    /// Remove an entry the watcher is closing. Idempotent: an entry already picked up,
    /// evicted, or popped is a no-op, and a stale meta can never touch a newer entry
    /// because ids are monotonic.
    pub(super) fn pop_closed(&self, meta: &ConnectionMeta) {
        let removed = {
            let mut g = self.lock();
            let seq = g.by_id.remove(&meta.id);
            let e = seq.and_then(|s| {
                g.order.remove(&s);
                g.by_key.get_mut(&meta.key).and_then(|node| node.remove(&s))
            });
            if g.by_key.get(&meta.key).is_some_and(|node| node.is_empty()) {
                g.by_key.remove(&meta.key);
            }
            g.check();
            e
        };
        drop(removed);
    }

    /// Idle connections currently pooled (tests; production reads the high-water mark).
    #[cfg(test)]
    pub(super) fn idle_len(&self) -> usize {
        self.lock().order.len()
    }

    /// The largest idle set ever offered, before trimming.
    pub(super) fn idle_high_water(&self) -> usize {
        self.lock().high_water
    }
}

/// the idle ceiling the edge runs when `OXO_EDGE_FRAME_POOL_IDLE` is unset.
///
/// `max(512, workers x 32)`. 512 is the ceiling every measurement in the programme ran
/// under (through ); at 16 workers it is three times the idle working set
/// measured at 64 downstream connections (161-172) and above the ~340 a linear scaling
/// law predicts at 128. The old default, `workers x 8` = 128 at 16 workers, was below
/// that working set and evicted (po128: a live reconnect, +4.7% p99 at c64).
///
/// Cost at full occupancy: on the edge ~20 KiB per idle connection (the eager 16 KiB
/// frame buffer plus the socket), so 512 is about 10 MB and one fd each; on the worker
/// one fd each plus a parked OS thread (classic worker) or a fiber (async worker). The
/// 15 s idle timeout releases all of it when load stops. `workers x 32` past 16 workers
/// is an EXTRAPOLATION with no measurement behind it; it keeps the ratio the 16-worker
/// number has. Worker count is the proxy because it is the fleet size the operator
/// chose and the working set is at most one idle connection per worker per downstream
/// connection, whereas the thread count varies with the host. At 32 workers the
/// default reaches a 1024 soft `nofile` limit; since the boot-time descriptor
/// budget (`crate::fd_budget`) prints the ceiling against the process limit and warns
/// when the pool at its ceiling would leave fewer than 256 descriptors for downstream
/// connections.
///
/// Pure: no env read, no side effect. The env is read once, in
/// `platform::config::run_with_cli`, and the resolved value is threaded into the pool.
pub(super) fn default_idle_ceiling(worker_count: usize) -> usize {
    512usize.max(worker_count.max(1) * 32)
}

/// where the running ceiling came from, reported on `/pool-health` as
/// `frame_pool_idle_source` so a cell that meant to exercise the default can prove it
/// did, and one that meant to pin a value can prove that.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IdleCeilingSource {
    Env,
    Default,
}

impl IdleCeilingSource {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            IdleCeilingSource::Env => "env",
            IdleCeilingSource::Default => "default",
        }
    }
}

/// Pure resolution of the ceiling from the raw env value: a positive integer wins, and
/// anything else (unset, empty, junk, zero) falls to the default with its source named.
pub(super) fn resolve_idle_ceiling(
    raw: Option<&str>,
    worker_count: usize,
) -> (usize, IdleCeilingSource) {
    match raw
        .map(str::trim)
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
    {
        Some(n) => (n, IdleCeilingSource::Env),
        None => (
            default_idle_ceiling(worker_count),
            IdleCeilingSource::Default,
        ),
    }
}

/// the pool implementation selector. The pingora arm was the A/B control
/// and is gone; `OXO_EDGE_POOL` survives only so an old launcher or cell file that
/// asks for it fails with a message instead of silently running the other pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PoolImpl {
    Owned,
}

/// Pure parse of `OXO_EDGE_POOL`; `None`/empty/`owned` is the only accepted value.
/// Tested without touching process env.
pub(super) fn parse_pool_impl(raw: Option<&str>) -> Result<PoolImpl, String> {
    match raw.map(str::trim) {
        None | Some("") | Some("owned") => Ok(PoolImpl::Owned),
        Some("pingora") => Err(
            "OXO_EDGE_POOL=pingora: the pingora pool was the A/B control and was              removed; only owned remains"
                .to_string(),
        ),
        Some(other) => Err(format!("OXO_EDGE_POOL={other:?}: expected owned")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(key: u64, id: i32) -> ConnectionMeta {
        ConnectionMeta::new(key, id)
    }

    #[test]
    fn fifo_eviction_is_by_insertion_order_across_keys() {
        let pool: ConnectionPool<&'static str> = ConnectionPool::new(2);
        let (_n1, mut r1) = pool.put(&meta(101, 1), "v1");
        let (_n2, mut r2) = pool.put(&meta(102, 2), "v2");
        assert_eq!(pool.idle_len(), 2);
        let (_n3, mut r3) = pool.put(&meta(101, 3), "v3");
        // The oldest across keys (101/1) went, not the newest on the same key.
        assert!(matches!(
            r1.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert!(matches!(
            r2.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            r3.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(pool.idle_len(), 2);
        assert_eq!(
            pool.idle_high_water(),
            3,
            "offered set peaked at 3 before the trim"
        );
        // FIFO pickup within key 101 now yields (is gone), and 102 is untouched.
        assert_eq!(pool.get(&101), Some("v3"));
        assert_eq!(pool.get(&101), None);
        assert_eq!(pool.get(&102), Some("v2"));
        assert_eq!(pool.idle_len(), 0);
    }

    #[test]
    fn get_is_fifo_per_key_and_touches_no_other_key() {
        let pool: ConnectionPool<&'static str> = ConnectionPool::new(8);
        let (_a, mut ra) = pool.put(&meta(101, 1), "a");
        let (_b, mut rb) = pool.put(&meta(101, 2), "b");
        let (_c, mut rc) = pool.put(&meta(101, 3), "c");
        let (_d, mut rd) = pool.put(&meta(102, 4), "d");
        assert_eq!(pool.get(&101), Some("a"), "oldest first");
        assert_eq!(pool.get(&101), Some("b"));
        assert_eq!(ra.try_recv(), Ok(true));
        assert_eq!(rb.try_recv(), Ok(true));
        assert!(matches!(
            rc.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            rd.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(pool.idle_len(), 2);
        assert_eq!(pool.get(&102), Some("d"));
        assert_eq!(pool.get(&101), Some("c"));
        assert_eq!(pool.get(&999), None);
    }

    #[test]
    fn pop_closed_is_idempotent_and_never_hits_a_newer_entry() {
        let pool: ConnectionPool<&'static str> = ConnectionPool::new(8);
        let (_n, _r) = pool.put(&meta(7, 10), "old");
        pool.pop_closed(&meta(7, 10));
        pool.pop_closed(&meta(7, 10));
        assert_eq!(pool.idle_len(), 0);
        // After a get, a late pop from the watcher whose conn was picked up is a no-op.
        let (_n2, _r2) = pool.put(&meta(7, 11), "picked");
        assert_eq!(pool.get(&7), Some("picked"));
        pool.pop_closed(&meta(7, 11));
        // A newer entry under the same key and a stale meta: the newer one survives.
        let (_n3, _r3) = pool.put(&meta(7, 12), "newer");
        pool.pop_closed(&meta(7, 11));
        assert_eq!(pool.idle_len(), 1);
        assert_eq!(pool.get(&7), Some("newer"));
    }

    /// A scripted mix against a plain-Vec model: after every operation the size bound
    /// holds and the three internal structures agree (the `check()` debug asserts run
    /// on every mutation in a debug build; this also asserts the observable set).
    #[test]
    fn size_is_never_exceeded_and_structures_agree() {
        const SIZE: usize = 5;
        let pool: ConnectionPool<u32> = ConnectionPool::new(SIZE);
        let mut model: Vec<(u64, i32)> = Vec::new(); // insertion order, oldest first
        let mut receivers: HashMap<i32, oneshot::Receiver<bool>> = HashMap::new();
        let mut next_id = 1i32;
        // A deterministic pseudo-random script.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for step in 0..400 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let op = x % 3;
            let key = (x >> 8) % 4;
            match op {
                0 | 1 => {
                    let id = next_id;
                    next_id += 1;
                    let (_n, r) = pool.put(&meta(key, id), id as u32);
                    receivers.insert(id, r);
                    model.push((key, id));
                    if model.len() > SIZE {
                        let (_k, evicted) = model.remove(0);
                        let mut rr = receivers.remove(&evicted).unwrap();
                        assert!(
                            matches!(rr.try_recv(), Err(oneshot::error::TryRecvError::Closed)),
                            "step {step}: evicted id {evicted} must see a closed sender"
                        );
                    }
                }
                _ => {
                    let got = pool.get(&key);
                    let want = model
                        .iter()
                        .position(|(k, _)| *k == key)
                        .map(|i| model.remove(i));
                    match (got, want) {
                        (Some(v), Some((_k, id))) => {
                            assert_eq!(v, id as u32, "step {step}: FIFO pickup for key {key}");
                            let mut rr = receivers.remove(&id).unwrap();
                            assert_eq!(rr.try_recv(), Ok(true));
                        }
                        (None, None) => {}
                        (g, w) => panic!("step {step}: pool {g:?} vs model {w:?}"),
                    }
                }
            }
            assert!(pool.idle_len() <= SIZE, "step {step}: size exceeded");
            assert_eq!(
                pool.idle_len(),
                model.len(),
                "step {step}: idle count vs model"
            );
        }
        // Every survivor is reachable and in model order per key.
        for key in 0..4u64 {
            let mut expect: Vec<i32> = model
                .iter()
                .filter(|(k, _)| *k == key)
                .map(|(_, id)| *id)
                .collect();
            while let Some(v) = pool.get(&key) {
                assert_eq!(v, expect.remove(0) as u32);
            }
            assert!(expect.is_empty());
        }
        assert_eq!(pool.idle_len(), 0);
    }

    /// The ceiling is AGGREGATE across OS threads: four puts on four threads at size 1
    /// leave exactly one entry. pingora's per-thread LRU left all four.
    #[test]
    fn ceiling_is_aggregate_across_os_threads() {
        let pool: ConnectionPool<u32> = ConnectionPool::new(1);
        let barrier = std::sync::Barrier::new(4);
        let receivers = Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for i in 0..4i32 {
                let pool = &pool;
                let barrier = &barrier;
                let receivers = &receivers;
                s.spawn(move || {
                    barrier.wait();
                    let (_n, r) = pool.put(&meta(i as u64, i), i as u32);
                    receivers.lock().unwrap().push(r);
                    barrier.wait();
                });
            }
        });
        assert_eq!(pool.idle_len(), 1);
        let mut closed = 0;
        for r in receivers.into_inner().unwrap().iter_mut() {
            if matches!(r.try_recv(), Err(oneshot::error::TryRecvError::Closed)) {
                closed += 1;
            }
        }
        assert_eq!(
            closed, 3,
            "three of four evicted under an aggregate ceiling of 1"
        );
    }

    #[tokio::test]
    async fn evicted_watcher_sees_notify_and_closed_sender() {
        let pool: ConnectionPool<&'static str> = ConnectionPool::new(1);
        let (n1, r1) = pool.put(&meta(1, 1), "first");
        let (_n2, _r2) = pool.put(&meta(1, 2), "second");
        // Both signals reach a watcher that polls only now: the Notify stored a permit and
        // the sender is gone.
        tokio::time::timeout(std::time::Duration::from_secs(1), n1.notified())
            .await
            .expect("eviction notify permit was stored");
        assert!(r1.await.is_err(), "pickup sender dropped without a send");
    }

    #[test]
    fn contention_counters_move_under_a_held_lock() {
        let pool: ConnectionPool<u32> = ConnectionPool::new(4);
        assert_eq!(pool.lock_contended_total.load(Ordering::Relaxed), 0);
        let held = pool.inner.lock().unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|s| {
            let pool = &pool;
            let barrier = &barrier;
            s.spawn(move || {
                barrier.wait();
                // Blocks until the holder releases; counted as one contended acquisition.
                let (_n, _r) = pool.put(&meta(1, 1), 1);
            });
            barrier.wait();
            std::thread::sleep(std::time::Duration::from_millis(20));
            drop(held);
        });
        assert_eq!(pool.lock_contended_total.load(Ordering::Relaxed), 1);
        assert!(
            pool.lock_wait_ns.load(Ordering::Relaxed) >= 10_000_000,
            "waited ~20 ms"
        );
        assert_eq!(pool.idle_len(), 1);
    }

    #[test]
    fn pool_impl_parses_without_touching_env() {
        assert_eq!(parse_pool_impl(None), Ok(PoolImpl::Owned));
        assert_eq!(parse_pool_impl(Some("")), Ok(PoolImpl::Owned));
        assert_eq!(parse_pool_impl(Some(" owned ")), Ok(PoolImpl::Owned));
        let gone = parse_pool_impl(Some("pingora")).unwrap_err();
        assert!(gone.contains("A/B control"), "{gone}");
        assert!(parse_pool_impl(Some("threadlocal")).is_err());
    }

    /// the registered default, at the sizes the registration names.
    #[test]
    fn default_idle_ceiling_is_512_or_32_per_worker() {
        assert_eq!(
            default_idle_ceiling(0),
            512,
            "zero workers is treated as one"
        );
        assert_eq!(default_idle_ceiling(1), 512);
        assert_eq!(default_idle_ceiling(16), 512, "16 x 32 ties the floor");
        assert_eq!(default_idle_ceiling(17), 544, "first size where x32 wins");
        assert_eq!(default_idle_ceiling(64), 2048);
    }

    #[test]
    fn resolve_idle_ceiling_names_its_source() {
        let d = IdleCeilingSource::Default;
        assert_eq!(resolve_idle_ceiling(None, 16), (512, d));
        assert_eq!(resolve_idle_ceiling(Some(""), 16), (512, d));
        assert_eq!(resolve_idle_ceiling(Some("0"), 16), (512, d));
        assert_eq!(resolve_idle_ceiling(Some("junk"), 16), (512, d));
        assert_eq!(
            resolve_idle_ceiling(Some(" 128 "), 16),
            (128, IdleCeilingSource::Env)
        );
        assert_eq!(
            resolve_idle_ceiling(Some("8"), 1),
            (8, IdleCeilingSource::Env)
        );
        assert_eq!(IdleCeilingSource::Env.as_str(), "env");
        assert_eq!(IdleCeilingSource::Default.as_str(), "default");
    }
}

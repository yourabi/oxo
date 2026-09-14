use super::*;

#[derive(Debug)]
pub(super) struct IdentityFairnessLimiter {
    max_per_identity: Option<u64>,
    // keys are Arc<str> so the admission guard shares the map's allocation
    // instead of a second `to_string` per admitted request (Borrow<str> keeps
    // &str lookups working).
    active: Mutex<HashMap<Arc<str>, u64>>,
    admitted_total: AtomicU64,
    saturation_total: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct IdentityFairnessSnapshot {
    pub(super) enabled: bool,
    pub(super) max_per_identity: Option<u64>,
    pub(super) active_in_flight: u64,
    pub(super) tracked_identities: usize,
    pub(super) admitted_total: u64,
    pub(super) saturation_total: u64,
}

pub(super) struct IdentityAdmission {
    limiter: Arc<IdentityFairnessLimiter>,
    identity: Arc<str>,
}

impl Drop for IdentityAdmission {
    fn drop(&mut self) {
        let mut active = self
            .limiter
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match active.get_mut(&*self.identity) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                active.remove(&*self.identity);
            }
            None => {}
        }
    }
}

#[derive(Debug)]
pub(super) struct GlobalInFlightLimiter {
    // read by the worker-cap deadlock guard in config.rs (K x N < G).
    pub(super) max_requests: Option<u64>,
    active: AtomicU64,
    admitted_total: AtomicU64,
    overload_total: AtomicU64,
    max_active_observed: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GlobalInFlightSnapshot {
    pub(super) enabled: bool,
    pub(super) max_requests: Option<u64>,
    pub(super) active: u64,
    pub(super) admitted_total: u64,
    pub(super) overload_total: u64,
    pub(super) max_active_observed: u64,
}

pub(super) struct GlobalInFlightAdmission {
    limiter: Arc<GlobalInFlightLimiter>,
}

impl Drop for GlobalInFlightAdmission {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl GlobalInFlightLimiter {
    pub(super) fn new(max_requests: Option<u64>) -> Self {
        Self {
            max_requests,
            active: AtomicU64::new(0),
            admitted_total: AtomicU64::new(0),
            overload_total: AtomicU64::new(0),
            max_active_observed: AtomicU64::new(0),
        }
    }

    pub(super) fn acquire(self: &Arc<Self>) -> Result<Option<GlobalInFlightAdmission>, ()> {
        let Some(max_requests) = self.max_requests else {
            return Ok(None);
        };
        loop {
            let active = self.active.load(Ordering::Relaxed);
            if active >= max_requests {
                self.overload_total.fetch_add(1, Ordering::Relaxed);
                return Err(());
            }
            if self
                .active
                .compare_exchange_weak(active, active + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.admitted_total.fetch_add(1, Ordering::Relaxed);
                self.record_max_active(active + 1);
                return Ok(Some(GlobalInFlightAdmission {
                    limiter: Arc::clone(self),
                }));
            }
        }
    }

    pub(super) fn snapshot(&self) -> GlobalInFlightSnapshot {
        GlobalInFlightSnapshot {
            enabled: self.max_requests.is_some(),
            max_requests: self.max_requests,
            active: self.active.load(Ordering::Relaxed),
            admitted_total: self.admitted_total.load(Ordering::Relaxed),
            overload_total: self.overload_total.load(Ordering::Relaxed),
            max_active_observed: self.max_active_observed.load(Ordering::Relaxed),
        }
    }

    fn record_max_active(&self, active: u64) {
        let mut current = self.max_active_observed.load(Ordering::Relaxed);
        while active > current {
            match self.max_active_observed.compare_exchange_weak(
                current,
                active,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SlowClientPolicy {
    pub(super) header_read_timeout_ms: u64,
    pub(super) keepalive_idle_timeout_ms: u64,
    pub(super) max_connection_secs: Option<u64>,
    pub(super) pingora_tls_handshake_timeout_secs: u64,
    /// whether downstream HTTP/1.1 connection reuse is enabled. Opt-in; the
    /// default remains one-shot (`session.set_keepalive(None)`).
    pub(super) keepalive_enabled: bool,
    /// pingora `keepalive_request_limit` (a REUSE counter = operator total-requests
    /// N minus 1). `Some(N-1)` only when keepalive is enabled; `None` under one-shot
    /// (the connection already closes after one request, so the cap is inert).
    pub(super) keepalive_request_limit: Option<u32>,
}

/// HTTP/2 resource bounds handed to `H2Options` at boot. Reachable knobs only;
/// H2 connection idle-timeout and absolute-age are framework-blocked (honest non-claim).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct H2Policy {
    pub(super) max_concurrent_streams: u32,
    /// `max_pending_accept_reset_streams` — the CVE-2023-44487 rapid-reset bound.
    pub(super) max_reset_streams: usize,
}

impl SlowClientPolicy {
    /// The idle timeout handed to `session.set_keepalive(Some(_))`, in whole seconds.
    ///
    /// Pingora's `set_keepalive` takes SECONDS and maps `Some(0)` to
    /// `KeepaliveStatus::Infinite` (an unbounded between-request read = slowloris).
    /// The ms value is already boot-guarded non-zero, but the ms→s conversion must
    /// still never yield 0: round UP (so a sub-second config becomes a 1s bound) and
    /// floor at 1. This is the "no path yields Some(0)" guarantee (design D2).
    pub(super) fn keepalive_idle_secs(&self) -> u64 {
        self.keepalive_idle_timeout_ms.div_ceil(1000).max(1)
    }
}

impl IdentityFairnessLimiter {
    pub(super) fn new(max_per_identity: Option<u64>) -> Self {
        Self {
            max_per_identity,
            active: Mutex::new(HashMap::new()),
            admitted_total: AtomicU64::new(0),
            saturation_total: AtomicU64::new(0),
        }
    }

    pub(super) fn acquire(
        self: &Arc<Self>,
        identity: &str,
    ) -> Result<Option<IdentityAdmission>, ()> {
        let Some(max_per_identity) = self.max_per_identity else {
            return Ok(None);
        };
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // W2: when the identity is already tracked, clone the EXISTING map key
        // instead of allocating a fresh Arc<str> that HashMap::insert would discard
        // (insert keeps the old key on update). Zero-alloc while requests for an
        // identity OVERLAP; the entry is removed at zero in-flight, so strictly serial
        // load still allocates on each first-in-flight — a concurrency-dependent win,
        // labeled as such in the ledger.
        let (key, current) = match active.get_key_value(identity) {
            Some((existing, count)) => (Arc::clone(existing), *count),
            None => (Arc::from(identity), 0),
        };
        if current >= max_per_identity {
            self.saturation_total.fetch_add(1, Ordering::Relaxed);
            return Err(());
        }
        active.insert(Arc::clone(&key), current + 1);
        self.admitted_total.fetch_add(1, Ordering::Relaxed);
        Ok(Some(IdentityAdmission {
            limiter: Arc::clone(self),
            identity: key,
        }))
    }

    pub(super) fn snapshot(&self) -> IdentityFairnessSnapshot {
        let active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        IdentityFairnessSnapshot {
            enabled: self.max_per_identity.is_some(),
            max_per_identity: self.max_per_identity,
            active_in_flight: active.values().sum(),
            tracked_identities: active.len(),
            admitted_total: self.admitted_total.load(Ordering::Relaxed),
            saturation_total: self.saturation_total.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct LongLivedLimits {
    pub(super) max_connections: u64,
    pub(super) max_buffered_bytes: u64,
    pub(super) downstream_write_timeout: Duration,
}

#[derive(Debug)]
pub(super) struct LongLivedSnapshot {
    pub(super) active: u64,
    pub(super) accepted_total: u64,
    pub(super) completed_total: u64,
    pub(super) drained_total: u64,
    pub(super) cancelled_total: u64,
    pub(super) rejected_total: u64,
    pub(super) downstream_timeout_total: u64,
    pub(super) bytes_streamed_total: u64,
    pub(super) max_active_observed: u64,
    pub(super) max_connections: u64,
    pub(super) max_buffered_bytes: u64,
    pub(super) downstream_write_timeout_ms: u64,
}

#[derive(Debug)]
pub(super) struct LongLivedRegistry {
    limits: LongLivedLimits,
    active: AtomicU64,
    accepted_total: AtomicU64,
    completed_total: AtomicU64,
    drained_total: AtomicU64,
    cancelled_total: AtomicU64,
    rejected_total: AtomicU64,
    downstream_timeout_total: AtomicU64,
    bytes_streamed_total: AtomicU64,
    max_active_observed: AtomicU64,
}

pub(super) struct LongLivedAdmission {
    registry: Arc<LongLivedRegistry>,
    bytes_streamed: u64,
    completed: bool,
    drained: bool,
}

impl Drop for LongLivedAdmission {
    fn drop(&mut self) {
        self.registry.active.fetch_sub(1, Ordering::Relaxed);
        if self.completed {
            self.registry
                .completed_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.registry
                .cancelled_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl LongLivedRegistry {
    pub(super) fn new(limits: LongLivedLimits) -> Self {
        Self {
            limits,
            active: AtomicU64::new(0),
            accepted_total: AtomicU64::new(0),
            completed_total: AtomicU64::new(0),
            drained_total: AtomicU64::new(0),
            cancelled_total: AtomicU64::new(0),
            rejected_total: AtomicU64::new(0),
            downstream_timeout_total: AtomicU64::new(0),
            bytes_streamed_total: AtomicU64::new(0),
            max_active_observed: AtomicU64::new(0),
        }
    }

    pub(super) fn try_admit(self: &Arc<Self>) -> Option<LongLivedAdmission> {
        loop {
            let active = self.active.load(Ordering::Relaxed);
            if active >= self.limits.max_connections {
                self.rejected_total.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            if self
                .active
                .compare_exchange_weak(active, active + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.accepted_total.fetch_add(1, Ordering::Relaxed);
                self.record_max_active(active + 1);
                return Some(LongLivedAdmission {
                    registry: Arc::clone(self),
                    bytes_streamed: 0,
                    completed: false,
                    drained: false,
                });
            }
        }
    }

    pub(super) fn snapshot(&self) -> LongLivedSnapshot {
        LongLivedSnapshot {
            active: self.active.load(Ordering::Relaxed),
            accepted_total: self.accepted_total.load(Ordering::Relaxed),
            completed_total: self.completed_total.load(Ordering::Relaxed),
            drained_total: self.drained_total.load(Ordering::Relaxed),
            cancelled_total: self.cancelled_total.load(Ordering::Relaxed),
            rejected_total: self.rejected_total.load(Ordering::Relaxed),
            downstream_timeout_total: self.downstream_timeout_total.load(Ordering::Relaxed),
            bytes_streamed_total: self.bytes_streamed_total.load(Ordering::Relaxed),
            max_active_observed: self.max_active_observed.load(Ordering::Relaxed),
            max_connections: self.limits.max_connections,
            max_buffered_bytes: self.limits.max_buffered_bytes,
            downstream_write_timeout_ms: self.limits.downstream_write_timeout.as_millis() as u64,
        }
    }

    fn record_max_active(&self, active: u64) {
        let mut current = self.max_active_observed.load(Ordering::Relaxed);
        while active > current {
            match self.max_active_observed.compare_exchange_weak(
                current,
                active,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
    }
}

impl LongLivedAdmission {
    pub(super) fn record_bytes(&mut self, bytes: u64) -> bool {
        self.bytes_streamed = self.bytes_streamed.saturating_add(bytes);
        self.registry
            .bytes_streamed_total
            .fetch_add(bytes, Ordering::Relaxed);
        self.bytes_streamed <= self.registry.limits.max_buffered_bytes
    }

    pub(super) fn complete(&mut self) {
        self.completed = true;
    }

    pub(super) fn complete_drained(&mut self) {
        if !self.drained {
            self.registry.drained_total.fetch_add(1, Ordering::Relaxed);
            self.drained = true;
        }
        self.completed = true;
    }

    pub(super) fn downstream_write_timeout(&self) -> Duration {
        self.registry.limits.downstream_write_timeout
    }

    pub(super) fn record_downstream_write_error(&self, err: &DownstreamWriteError) {
        if matches!(err, DownstreamWriteError::Timeout) {
            self.registry
                .downstream_timeout_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(keepalive_idle_timeout_ms: u64) -> SlowClientPolicy {
        SlowClientPolicy {
            header_read_timeout_ms: 15_000,
            keepalive_idle_timeout_ms,
            max_connection_secs: None,
            pingora_tls_handshake_timeout_secs: 60,
            keepalive_enabled: true,
            keepalive_request_limit: Some(999),
        }
    }

    #[test]
    fn keepalive_idle_secs_rounds_up_and_floors_at_one() {
        // D2: the ms->s conversion must never yield 0 (Some(0)=Infinite=slowloris).
        // Sub-second values round up to a 1s bound; exact multiples stay exact.
        assert_eq!(policy(1).keepalive_idle_secs(), 1);
        assert_eq!(policy(500).keepalive_idle_secs(), 1);
        assert_eq!(policy(999).keepalive_idle_secs(), 1);
        assert_eq!(policy(1000).keepalive_idle_secs(), 1);
        assert_eq!(policy(1001).keepalive_idle_secs(), 2);
        assert_eq!(policy(1500).keepalive_idle_secs(), 2);
        assert_eq!(policy(15_000).keepalive_idle_secs(), 15);
        // The load-bearing guarantee: never zero on any representable ms value.
        for ms in [1u64, 499, 500, 999, 1000, 1001, u32::MAX as u64] {
            assert_ne!(policy(ms).keepalive_idle_secs(), 0, "ms={ms}");
        }
    }

    // at edge-threads>1 these three admission structures become cross-thread
    // load-bearing for the first time (the edge ran single-threaded through , so
    // every counter was effectively serialized). Each test hammers acquire/drop from
    // real OS threads (barrier-synchronized start) and asserts the cap is NEVER
    // exceeded, guards fully release, and saturation is counted — the invariants the
    // hardened front door's admission story rests on.

    const HAMMER_THREADS: usize = 8;
    const HAMMER_ITERS: usize = 1_000;

    #[test]
    fn global_in_flight_cap_holds_under_concurrent_threads() {
        let limiter = Arc::new(GlobalInFlightLimiter::new(Some(4)));

        // Deterministic overload first: saturate the cap from this thread and prove
        // the next acquire fails (overload_total is not left to scheduling luck).
        let held: Vec<_> = (0..4)
            .map(|_| limiter.acquire().unwrap().expect("cap not yet reached"))
            .collect();
        assert!(
            limiter.acquire().is_err(),
            "acquire beyond the cap must fail"
        );
        assert_eq!(limiter.snapshot().overload_total, 1);
        drop(held);

        let barrier = Arc::new(std::sync::Barrier::new(HAMMER_THREADS));
        let handles: Vec<_> = (0..HAMMER_THREADS)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..HAMMER_ITERS {
                        if let Ok(admission) = limiter.acquire() {
                            let admission = admission.expect("cap configured => Some guard");
                            std::thread::yield_now();
                            drop(admission);
                        }
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        let snapshot = limiter.snapshot();
        assert!(
            snapshot.max_active_observed <= 4,
            "global cap exceeded: {snapshot:?}"
        );
        assert_eq!(snapshot.active, 0, "leaked admission guard: {snapshot:?}");
        assert!(
            snapshot.overload_total >= 1,
            "contention never rejected: {snapshot:?}"
        );

        // Unlimited mode stays a no-op gate (Ok(None)) — no counter side effects.
        let unlimited = Arc::new(GlobalInFlightLimiter::new(None));
        assert!(unlimited.acquire().unwrap().is_none());
    }

    #[test]
    fn long_lived_registry_cap_holds_under_concurrent_threads() {
        let registry = Arc::new(LongLivedRegistry::new(LongLivedLimits {
            max_connections: 4,
            max_buffered_bytes: 1024,
            downstream_write_timeout: Duration::from_secs(1),
        }));

        // Deterministic rejection at the cap boundary.
        let held: Vec<_> = (0..4)
            .map(|_| registry.try_admit().expect("cap not yet reached"))
            .collect();
        assert!(
            registry.try_admit().is_none(),
            "admit beyond the cap must fail"
        );
        assert_eq!(registry.snapshot().rejected_total, 1);
        drop(held);

        let barrier = Arc::new(std::sync::Barrier::new(HAMMER_THREADS));
        let handles: Vec<_> = (0..HAMMER_THREADS)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..HAMMER_ITERS {
                        if let Some(mut admission) = registry.try_admit() {
                            admission.complete();
                            std::thread::yield_now();
                            drop(admission);
                        }
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        let snapshot = registry.snapshot();
        assert!(
            snapshot.max_active_observed <= 4,
            "long-lived cap exceeded: {snapshot:?}"
        );
        assert_eq!(snapshot.active, 0, "leaked admission guard: {snapshot:?}");
        assert!(snapshot.rejected_total >= 1, "{snapshot:?}");
        // Every accepted admission resolved exactly once (completed or cancelled) —
        // catches double-decrement/leak bugs in the Drop path.
        assert_eq!(
            snapshot.accepted_total,
            snapshot.completed_total + snapshot.cancelled_total,
            "{snapshot:?}"
        );
    }

    #[test]
    fn identity_fairness_cap_holds_under_concurrent_threads() {
        let limiter = Arc::new(IdentityFairnessLimiter::new(Some(3)));

        // Deterministic saturation for one identity while another stays admittable
        // (per-identity isolation, not a global cap).
        let held: Vec<_> = (0..3)
            .map(|_| limiter.acquire("10.0.0.1").unwrap().expect("under cap"))
            .collect();
        assert!(
            limiter.acquire("10.0.0.1").is_err(),
            "identity at cap must fail"
        );
        assert_eq!(limiter.snapshot().saturation_total, 1);
        let other = limiter
            .acquire("10.0.0.2")
            .unwrap()
            .expect("other identity unaffected");
        drop(other);
        drop(held);

        // Concurrent hammer over two identities; each thread mirrors its admissions in
        // a test-side counter and asserts the per-identity cap while guards are held
        // (counter <= real active, so counter > cap proves a real violation).
        let observed_a = Arc::new(AtomicU64::new(0));
        let observed_b = Arc::new(AtomicU64::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(HAMMER_THREADS));
        let handles: Vec<_> = (0..HAMMER_THREADS)
            .map(|thread| {
                let limiter = Arc::clone(&limiter);
                let barrier = Arc::clone(&barrier);
                let (identity, observed) = if thread % 2 == 0 {
                    ("10.0.0.1", Arc::clone(&observed_a))
                } else {
                    ("10.0.0.2", Arc::clone(&observed_b))
                };
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..HAMMER_ITERS {
                        if let Ok(admission) = limiter.acquire(identity) {
                            let admission = admission.expect("cap configured => Some guard");
                            let now = observed.fetch_add(1, Ordering::SeqCst) + 1;
                            assert!(now <= 3, "per-identity cap exceeded for {identity}: {now}");
                            std::thread::yield_now();
                            observed.fetch_sub(1, Ordering::SeqCst);
                            drop(admission);
                        }
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        // Drop-side decrement-or-remove: at zero the map entry disappears entirely
        // (no unbounded identity-table growth), and nothing stays in flight.
        let snapshot = limiter.snapshot();
        assert_eq!(snapshot.active_in_flight, 0, "{snapshot:?}");
        assert_eq!(snapshot.tracked_identities, 0, "{snapshot:?}");
        assert!(snapshot.admitted_total > 0, "{snapshot:?}");
    }
}

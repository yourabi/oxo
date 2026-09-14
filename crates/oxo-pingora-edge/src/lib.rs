use std::collections::BTreeSet;
use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use thiserror::Error;

#[cfg(feature = "acme")]
pub mod acme;
/// the boot-time descriptor budget (pure arithmetic, every target).
pub mod fd_budget;
pub mod service;

/// M-A Tier-1 mechanism gate: a counting wrapper around the System allocator.
///
/// Counts ALLOCATION EVENTS (`alloc` + `alloc_zeroed` + `realloc`), not bytes and not
/// frees — the gated quantity is "how many times per request does the edge hit the
/// allocator", a deterministic count that regresses in integer steps. Deallocations are
/// deliberately uncounted: every alloc has at most one dealloc, so counting both would
/// only double the number without adding information. Relaxed ordering is sufficient —
/// the counter is a monotonic statistic read amortized over hundreds of requests, never
/// a synchronization point.
///
/// The `#[global_allocator]` registration lives in the BINARY roots (`main.rs`,
/// `service_main.rs` is deliberately excluded — only the edge is gated), because Rust
/// allows exactly one registration per binary and a library must not claim it.
#[cfg(feature = "alloc-count")]
pub mod alloc_count {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Total allocation events since process start. Public so the admin route can read it.
    pub static ALLOCATION_EVENTS_TOTAL: AtomicU64 = AtomicU64::new(0);

    pub struct CountingSystemAlloc;

    // SAFETY: pure delegation to System; the counter increment allocates nothing.
    unsafe impl GlobalAlloc for CountingSystemAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOCATION_EVENTS_TOTAL.fetch_add(1, Ordering::Relaxed);
            System.alloc(layout)
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            System.dealloc(ptr, layout)
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            ALLOCATION_EVENTS_TOTAL.fetch_add(1, Ordering::Relaxed);
            System.alloc_zeroed(layout)
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            ALLOCATION_EVENTS_TOTAL.fetch_add(1, Ordering::Relaxed);
            System.realloc(ptr, layout, new_size)
        }
    }
}

/// M-C (BENCH-ONLY, never in a shipped build): in-edge wall-clock probes at the four
/// worker-hop seams — {checkout, request-write, response-read, checkin}. Task-clock perf
/// (/) measures ON-CPU work only and is BLIND to the off-CPU wait on the UDS/futex
/// round-trip; these probes capture that wall-time AND localize the edge's per-seam share.
///
/// Compiled ONLY under `--features hop-timing`: without the feature this module, its atomics,
/// the `/hop-timing` admin route, and the seam probe blocks in `frame_hop.rs` literally do not
/// exist in the binary (the same absence contract as `edge-bench`/`alloc-count`). Even WITH
/// the feature, recording is inert unless `OXO_HOP_TIMING=1` — `Timer::start()` returns a
/// None marker so the seams cost nothing (mirrors edge-bench's `OXO_EDGE_NATIVE_BENCH`
/// double-gate). The M-B clocksource preflight records whether `Instant::now` is a vDSO read
/// (cheap) or a syscall; the per-seam overhead A/A check in the plan bounds any perturbation.
#[cfg(feature = "hop-timing")]
pub mod hop_timing {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    use std::time::Instant;

    pub const SEAMS: usize = 6;
    // W0: "ingest" is APPENDED so the four original seam indices (and the key order in
    // every archived /hop-timing JSON since ) stay stable. Its span: request_filter entry
    // through collect → validate → admit → sanitize → client-body read → frame build+encode,
    // ending immediately before pool checkout. The end sits AFTER frame-bytes construction
    // deliberately — the single-pass encode is the segment's centerpiece, and a seam
    // ending at the dispatch match would leave it in an unattributed gap between ingest-end
    // and checkout-start. Count parity under the frame hop with sidecars idle:
    //   ingest == request_write − stale_retries + rejections_after_ingest… — in practice
    //   ingest counts every request that reached frame construction, so
    //   ingest == (checkout attempts) == request_write + (checkout failures).
    // The egress cost class (response-header build, decode, downstream write) sits after
    // response_read OUTSIDE all seams; it is attributed by the alloc ruler and syscall
    // ledger only.
    pub const SEAM_NAMES: [&str; SEAMS] = [
        "checkout",
        "request_write",
        "response_read",
        "checkin",
        "ingest",
        // time a request spends PARKED behind the per-worker admission cap
        // (append-only, the A3 precedent — archived JSONs stay parseable).
        "park",
    ];
    /// floor(log2 nanos) buckets: bucket i = [2^i, 2^(i+1)) ns; index 0 ≈ 1 ns.
    /// A3: 20 → 26 buckets. At 20, the top bucket started at ~0.5 ms and 's
    /// "request_write 3.2% ≥524 µs" anomaly was pure bucket SATURATION — unresolvable
    /// by construction. 26 buckets resolve to [2^25, 2^26) ns ≈ 33-67 ms, comfortably
    /// past every seam p99 ever measured (response_read loaded mean 3.9 ms), so tails
    /// land in real buckets. (The tail above the top bucket is still capped there;
    /// count/sum stay exact regardless.)
    pub const BUCKETS: usize = 26;

    #[derive(Copy, Clone)]
    pub enum Seam {
        Checkout = 0,
        RequestWrite = 1,
        ResponseRead = 2,
        Checkin = 3,
        Ingest = 4,
        Park = 5,
    }

    static COUNT: [AtomicU64; SEAMS] = [const { AtomicU64::new(0) }; SEAMS];
    static SUM_NANOS: [AtomicU64; SEAMS] = [const { AtomicU64::new(0) }; SEAMS];
    static HIST: [[AtomicU64; BUCKETS]; SEAMS] =
        [const { [const { AtomicU64::new(0) }; BUCKETS] }; SEAMS];

    /// Double-gate: the feature must be built AND the env set. Read once.
    fn enabled() -> bool {
        static ON: OnceLock<bool> = OnceLock::new();
        *ON.get_or_init(|| std::env::var("OXO_HOP_TIMING").as_deref() == Ok("1"))
    }

    /// A start marker; `None` when recording is disabled so the seam is a branch-and-drop.
    pub struct Timer(Option<Instant>);

    impl Timer {
        #[inline]
        pub fn start() -> Timer {
            if enabled() {
                Timer(Some(Instant::now()))
            } else {
                Timer(None)
            }
        }
    }

    /// the exchange-by-depth ledger. One 26-bucket histogram per dispatch depth
    /// lane (depth = requests already in flight on the chosen worker when this one was
    /// dispatched, clamped to the last lane). This is the stacking-hypothesis probe: if a
    /// whole-worker pause stacks behind a queue, exchange time grows with depth.
    pub const DEPTH_LANES: usize = 8;
    static DEPTH_HIST: [[AtomicU64; BUCKETS]; DEPTH_LANES] =
        [const { [const { AtomicU64::new(0) }; BUCKETS] }; DEPTH_LANES];
    static DEPTH_COUNT: [AtomicU64; DEPTH_LANES] = [const { AtomicU64::new(0) }; DEPTH_LANES];
    static DEPTH_SUM: [AtomicU64; DEPTH_LANES] = [const { AtomicU64::new(0) }; DEPTH_LANES];

    /// LINEAR-bin histograms with exact sums, beside the log2 ones. The log2 buckets
    /// cannot answer a question about a 2 ms difference at a 5-10 ms percentile: bucket 22
    /// is [4.19, 8.39) ms, wider than the quantity. These are 64 us bins to 32.768 ms —
    /// past the bench's 20 ms slow class — with a SATURATING top bin whose mass and sum are
    /// reported separately, so a percentile that lands in the saturated tail is refused by
    /// the analyzer instead of silently clamped (the -> lesson: a saturating top
    /// bucket made request_write's anomaly unresolvable by construction).
    ///
    /// `count` and `sum_nanos` are exact, which gives every bin-derived statistic a ground
    /// truth: the analyzer refuses a report whose bin-derived mean disagrees with the exact
    /// mean by more than half a bin, or whose per-lane counts disagree with the log2 ledger.
    pub const LIN_BINS: usize = 512;
    pub const LIN_BIN_US: u64 = 64;
    const LIN_BIN_NS: u64 = LIN_BIN_US * 1_000;

    pub struct Linear {
        bins: [AtomicU64; LIN_BINS],
        count: AtomicU64,
        sum: AtomicU64,
        over: AtomicU64,
        over_sum: AtomicU64,
    }

    impl Linear {
        const fn new() -> Linear {
            Linear {
                bins: [const { AtomicU64::new(0) }; LIN_BINS],
                count: AtomicU64::new(0),
                sum: AtomicU64::new(0),
                over: AtomicU64::new(0),
                over_sum: AtomicU64::new(0),
            }
        }

        #[inline]
        fn record(&self, nanos: u64) {
            self.count.fetch_add(1, Ordering::Relaxed);
            self.sum.fetch_add(nanos, Ordering::Relaxed);
            let bin = (nanos / LIN_BIN_NS) as usize;
            if bin < LIN_BINS {
                self.bins[bin].fetch_add(1, Ordering::Relaxed);
            } else {
                self.over.fetch_add(1, Ordering::Relaxed);
                self.over_sum.fetch_add(nanos, Ordering::Relaxed);
            }
        }

        fn json(&self) -> String {
            let c = self.count.load(Ordering::Relaxed);
            let sum = self.sum.load(Ordering::Relaxed);
            let over = self.over.load(Ordering::Relaxed);
            let over_sum = self.over_sum.load(Ordering::Relaxed);
            let mut bins = String::new();
            for (b, cell) in self.bins.iter().enumerate() {
                let v = cell.load(Ordering::Relaxed);
                if v > 0 {
                    if !bins.is_empty() {
                        bins.push(',');
                    }
                    bins.push_str(&format!("\"{b}\":{v}"));
                }
            }
            format!(
                "{{\"bin_us\":{LIN_BIN_US},\"count\":{c},\"sum_nanos\":{sum},\"over\":{over},\"over_sum_nanos\":{over_sum},\"bins\":{{{bins}}}}}"
            )
        }

        fn is_empty(&self) -> bool {
            self.count.load(Ordering::Relaxed) == 0
        }
    }

    /// Whole exchange (in-flight commit -> response fully written downstream) by depth lane.
    static EXCHANGE_LINEAR: [Linear; DEPTH_LANES] = [const { Linear::new() }; DEPTH_LANES];
    /// The worker round trip alone (request frame written -> first response frame read) by
    /// the SAME depth lane: the part that separates worker-side wait from the header build
    /// and the downstream TLS write that the whole-exchange span also contains.
    static RESPONSE_READ_LINEAR: [Linear; DEPTH_LANES] = [const { Linear::new() }; DEPTH_LANES];
    /// Checkout, not depth-keyed: it precedes admission, so no lane exists yet.
    static CHECKOUT_LINEAR: Linear = Linear::new();
    /// Stale-retry re-exchanges: those record no seam and no lane, so without this counter
    /// they would be silently missing from every denominator.
    static EXCHANGE_RETRY_TOTAL: AtomicU64 = AtomicU64::new(0);

    /// one stale-retry re-exchange happened (its timings are deliberately unrecorded).
    #[inline]
    pub fn note_exchange_retry() {
        if enabled() {
            EXCHANGE_RETRY_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// the response-read seam plus its linear lane, from one elapsed() read.
    #[inline]
    pub fn record_response_read(depth: usize, timer: Timer) {
        if let Some(start) = timer.0 {
            let nanos = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            let i = Seam::ResponseRead as usize;
            COUNT[i].fetch_add(1, Ordering::Relaxed);
            SUM_NANOS[i].fetch_add(nanos, Ordering::Relaxed);
            let b = (63 - (nanos | 1).leading_zeros() as usize).min(BUCKETS - 1);
            HIST[i][b].fetch_add(1, Ordering::Relaxed);
            RESPONSE_READ_LINEAR[depth.min(DEPTH_LANES - 1)].record(nanos);
        }
    }

    /// the checkout seam plus its linear histogram, from one elapsed() read.
    #[inline]
    pub fn record_checkout(timer: Timer) {
        if let Some(start) = timer.0 {
            let nanos = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            let i = Seam::Checkout as usize;
            COUNT[i].fetch_add(1, Ordering::Relaxed);
            SUM_NANOS[i].fetch_add(nanos, Ordering::Relaxed);
            let b = (63 - (nanos | 1).leading_zeros() as usize).min(BUCKETS - 1);
            HIST[i][b].fetch_add(1, Ordering::Relaxed);
            CHECKOUT_LINEAR.record(nanos);
        }
    }

    /// Record one whole-exchange duration into its dispatch-depth lane (log2 and linear).
    #[inline]
    pub fn record_exchange_depth(depth: usize, timer: Timer) {
        if let Some(start) = timer.0 {
            let nanos = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            let lane = depth.min(DEPTH_LANES - 1);
            DEPTH_COUNT[lane].fetch_add(1, Ordering::Relaxed);
            DEPTH_SUM[lane].fetch_add(nanos, Ordering::Relaxed);
            let b = (63 - (nanos | 1).leading_zeros() as usize).min(BUCKETS - 1);
            DEPTH_HIST[lane][b].fetch_add(1, Ordering::Relaxed);
            EXCHANGE_LINEAR[lane].record(nanos);
        }
    }

    /// the frame-stamp gate. When armed (env, read once), the edge appends an
    /// `x-oxo-ts0` header (CLOCK_MONOTONIC nanos at frame build) to each worker
    /// frame so the worker can measure true scheduler delay. Bench-only: the reserved
    /// namespace is stripped by the worker before any app sees it, and the flag rides
    /// the same collect_edge_env forwarding as OXO_HOP_TIMING.
    pub fn stamp_enabled() -> bool {
        static ON: OnceLock<bool> = OnceLock::new();
        *ON.get_or_init(|| std::env::var("OXO_HOP_STAMP").as_deref() == Ok("1"))
    }

    /// CLOCK_MONOTONIC nanos — the same clock id the worker reads with
    /// Process.clock_gettime(Process::CLOCK_MONOTONIC), valid cross-process on one boot.
    pub fn monotonic_nanos() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime with a valid clock id and out-pointer.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        (ts.tv_sec as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(ts.tv_nsec as u64)
    }

    /// Record one seam's elapsed wall-time. No-op when the timer was started disabled.
    #[inline]
    pub fn record(seam: Seam, timer: Timer) {
        if let Some(start) = timer.0 {
            let nanos = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            let i = seam as usize;
            COUNT[i].fetch_add(1, Ordering::Relaxed);
            SUM_NANOS[i].fetch_add(nanos, Ordering::Relaxed);
            // floor(log2(nanos)); nanos|1 avoids the leading_zeros==64 (all-zero) case.
            let b = (63 - (nanos | 1).leading_zeros() as usize).min(BUCKETS - 1);
            HIST[i][b].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// JSON snapshot for the `/hop-timing` admin route: per-seam count, sum, mean, and the
    /// non-empty log2 buckets. `enabled` reflects the env gate so a zeroed report is
    /// self-explaining (feature built but not armed).
    pub fn report_json() -> String {
        let mut s = String::from("{\"enabled\":");
        s.push_str(if enabled() { "true" } else { "false" });
        s.push_str(",\"seams\":{");
        for i in 0..SEAMS {
            let c = COUNT[i].load(Ordering::Relaxed);
            let sum = SUM_NANOS[i].load(Ordering::Relaxed);
            let mean = if c > 0 { sum as f64 / c as f64 } else { 0.0 };
            let mut buckets = String::new();
            for (b, cell) in HIST[i].iter().enumerate() {
                let v = cell.load(Ordering::Relaxed);
                if v > 0 {
                    if !buckets.is_empty() {
                        buckets.push(',');
                    }
                    buckets.push_str(&format!("\"{b}\":{v}"));
                }
            }
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!(
                "\"{}\":{{\"count\":{c},\"sum_nanos\":{sum},\"mean_nanos\":{mean:.1},\"log2_buckets\":{{{buckets}}}}}",
                SEAM_NAMES[i]
            ));
        }
        s.push('}');
        // the exchange-by-depth ledger (empty lanes elided).
        s.push_str(",\"exchange_by_depth\":{");
        let mut first_lane = true;
        for lane in 0..DEPTH_LANES {
            let c = DEPTH_COUNT[lane].load(Ordering::Relaxed);
            if c == 0 {
                continue;
            }
            let sum = DEPTH_SUM[lane].load(Ordering::Relaxed);
            let mean = sum as f64 / c as f64;
            let mut buckets = String::new();
            for (b, cell) in DEPTH_HIST[lane].iter().enumerate() {
                let v = cell.load(Ordering::Relaxed);
                if v > 0 {
                    if !buckets.is_empty() {
                        buckets.push(',');
                    }
                    buckets.push_str(&format!("\"{b}\":{v}"));
                }
            }
            if !first_lane {
                s.push(',');
            }
            first_lane = false;
            s.push_str(&format!(
                "\"{lane}\":{{\"count\":{c},\"mean_nanos\":{mean:.1},\"log2_buckets\":{{{buckets}}}}}"
            ));
        }
        s.push('}');
        // the linear ledgers (empty lanes elided, exact count and sum in every block).
        for (name, lanes) in [
            ("exchange_linear", &EXCHANGE_LINEAR),
            ("response_read_linear", &RESPONSE_READ_LINEAR),
        ] {
            s.push_str(&format!(",\"{name}\":{{"));
            let mut first = true;
            for (lane, hist) in lanes.iter().enumerate() {
                if hist.is_empty() {
                    continue;
                }
                if !first {
                    s.push(',');
                }
                first = false;
                s.push_str(&format!("\"{lane}\":{}", hist.json()));
            }
            s.push('}');
        }
        s.push_str(&format!(",\"checkout_linear\":{}", CHECKOUT_LINEAR.json()));
        s.push_str(&format!(
            ",\"exchange_retry_total\":{}",
            EXCHANGE_RETRY_TOTAL.load(Ordering::Relaxed)
        ));
        s.push_str("}\n");
        s
    }

    /// the linear bins' arithmetic, on a LOCAL Linear so no shared static and no
    /// env gate is involved (the armed-path parity test lives in hop_timing_tests, which
    /// owns the once-initialized `enabled()` gate).
    #[cfg(test)]
    mod linear_tests {
        use super::{Linear, LIN_BINS, LIN_BIN_NS};

        #[test]
        fn bins_edges_and_saturation() {
            let h = Linear::new();
            h.record(0); // bin 0
            h.record(LIN_BIN_NS - 1); // 63.999 us -> bin 0
            h.record(LIN_BIN_NS); // 64 us -> bin 1
            h.record(LIN_BIN_NS * (LIN_BINS as u64) - 1); // 32.767999 ms -> last bin
            h.record(LIN_BIN_NS * (LIN_BINS as u64)); // 32.768 ms -> saturates
            h.record(LIN_BIN_NS * (LIN_BINS as u64) * 3); // far above -> saturates
            let j = h.json();
            assert!(j.contains("\"bin_us\":64"), "bin width reported: {j}");
            assert!(j.contains("\"count\":6"), "every sample counted: {j}");
            assert!(j.contains("\"over\":2"), "two samples saturated: {j}");
            assert!(j.contains("\"0\":2"), "0 and 63.999 us share bin 0: {j}");
            assert!(j.contains("\"1\":1"), "64 us lands in bin 1: {j}");
            assert!(
                j.contains(&format!("\"{}\":1", LIN_BINS - 1)),
                "32.767999 ms lands in the last bin: {j}"
            );
            // exact ground truth: sum includes the saturated samples, over_sum only those
            let total: u64 = (LIN_BIN_NS - 1)
                + LIN_BIN_NS
                + (LIN_BIN_NS * LIN_BINS as u64 - 1)
                + LIN_BIN_NS * LIN_BINS as u64
                + LIN_BIN_NS * LIN_BINS as u64 * 3;
            assert!(
                j.contains(&format!("\"sum_nanos\":{total}")),
                "exact sum over ALL samples: {j}"
            );
            let over_sum = LIN_BIN_NS * LIN_BINS as u64 + LIN_BIN_NS * LIN_BINS as u64 * 3;
            assert!(
                j.contains(&format!("\"over_sum_nanos\":{over_sum}")),
                "the saturated mass carries its own sum: {j}"
            );
        }

        #[test]
        fn bin_derived_mean_is_within_half_a_bin_of_the_exact_mean() {
            // The invariant the analyzer refuses on: bin midpoints must reconstruct the
            // exact mean to within half a bin width when nothing saturated.
            let h = Linear::new();
            let vals = [1_000u64, 70_000, 130_000, 5_000_000, 12_345_678];
            for v in vals {
                h.record(v);
            }
            let exact = vals.iter().sum::<u64>() as f64 / vals.len() as f64;
            let mut est = 0.0f64;
            for v in vals {
                let bin = (v / LIN_BIN_NS) as f64;
                est += (bin + 0.5) * LIN_BIN_NS as f64;
            }
            est /= vals.len() as f64;
            assert!(
                (est - exact).abs() <= LIN_BIN_NS as f64 / 2.0,
                "bin-midpoint mean {est} vs exact {exact}"
            );
        }

        #[test]
        fn empty_is_elided_and_reports_zero() {
            let h = Linear::new();
            assert!(h.is_empty());
            let j = h.json();
            assert!(
                j.contains("\"count\":0") && j.contains("\"bins\":{}"),
                "{j}"
            );
        }
    }
}

/// M-C: deterministic coverage of the hop_timing accounting (the wired frame-hop proof
/// rides M-D's guest run, which reads /hop-timing under real worker traffic). Only compiled
/// with the feature; a single test so the once-initialized `enabled()` gate is deterministic.
#[cfg(all(test, feature = "hop-timing"))]
mod hop_timing_tests {
    use super::hop_timing::{
        note_exchange_retry, record, record_checkout, record_exchange_depth, record_response_read,
        report_json, Seam, Timer,
    };

    #[test]
    fn record_and_report_are_consistent() {
        // Arm the double-gate before the first Timer::start() so `enabled()` caches true.
        std::env::set_var("OXO_HOP_TIMING", "1");
        record(Seam::ResponseRead, Timer::start());
        record(Seam::ResponseRead, Timer::start());
        record(Seam::Checkout, Timer::start());
        record(Seam::Ingest, Timer::start());
        // the linear ledgers, recorded through the same entry points the edge uses.
        // Lane 3 is used by nothing else, so its counts are exact; the seam counts below
        // include these calls (record_response_read and record_checkout each write BOTH
        // the seam and the linear block from one elapsed() read, which is the parity the
        // analyzer refuses on).
        record_exchange_depth(3, Timer::start());
        record_exchange_depth(3, Timer::start());
        record_response_read(3, Timer::start());
        record_checkout(Timer::start());
        note_exchange_retry();
        let json = report_json();
        assert!(json.contains("\"enabled\":true"), "armed report: {json}");
        assert!(
            json.contains("\"response_read\":{\"count\":3,"),
            "response_read: two seam records plus one via record_response_read: {json}"
        );
        assert!(
            json.contains("\"checkout\":{\"count\":2,"),
            "checkout: one seam record plus one via record_checkout: {json}"
        );
        assert!(
            json.contains("\"checkin\":{\"count\":0,"),
            "unrecorded seam stays zero: {json}"
        );
        // W0: the fifth seam is APPENDED so the original four indices/key order are
        // stable for archived-JSON readers; ingest must both count and serialize LAST.
        assert!(
            json.contains("\"ingest\":{\"count\":1,"),
            "ingest counted once: {json}"
        );
        let (ci, ii) = (
            json.find("\"checkin\":").unwrap(),
            json.find("\"ingest\":").unwrap(),
        );
        assert!(
            ci < ii,
            "ingest must serialize after the four original seams: {json}"
        );
        assert!(json.contains("log2_buckets"), "histogram present: {json}");
        // per-lane count PARITY between the log2 ledger and the linear one — the
        // invariant that lets a bin-derived percentile be trusted at all.
        assert!(
            json.contains("\"exchange_by_depth\":{\"3\":{\"count\":2,"),
            "lane 3 counted twice in the log2 ledger: {json}"
        );
        assert!(
            json.contains("\"exchange_linear\":{\"3\":{\"bin_us\":64,\"count\":2,"),
            "lane 3 counted twice in the linear ledger: {json}"
        );
        assert!(
            json.contains("\"response_read_linear\":{\"3\":{\"bin_us\":64,\"count\":1,"),
            "the worker round trip is keyed by the same lane: {json}"
        );
        assert!(
            json.contains("\"checkout_linear\":{\"bin_us\":64,\"count\":1,"),
            "checkout is not depth-keyed (it precedes admission): {json}"
        );
        assert!(
            json.contains("\"exchange_retry_total\":1"),
            "a stale-retry re-exchange is counted, not silently unrecorded: {json}"
        );
        assert!(
            json.contains("\"sum_nanos\":"),
            "exact sums present: {json}"
        );
        // the report is one JSON object: exactly one closing brace after the last field
        assert!(json.trim_end().ends_with("}"), "well-formed: {json}");
        assert_eq!(
            json.matches("\"bin_us\":64").count(),
            3,
            "three linear blocks: two lanes plus checkout: {json}"
        );
    }
}

pub const DEFAULT_MAX_BODY_BYTES: u64 = 16 * 1024 * 1024;

/// Parsed edge CLI/env configuration. Several fields carry cross-field invariants that are
/// enforced later in `run_with_cli`, not by the type: `http_bind`/`https_bind` are mutually
/// exclusive (one listener); `acme_issue_once`/`acme_renew_once` are mutually exclusive; on a
/// non-loopback bind, public mode requires TLS, an explicit FQDN, a max-body cap, and an
/// identity policy, while smoke-beta also requires private admin health and a global request
/// cap. On a loopback bind, setting `public_mode`/`public_identity`/`trusted_proxy_cidrs`
/// fails closed (see `read_public_mode_gate`). Note the plural `worker_sockets` here vs the
/// singular `EdgeConfig::worker_socket` (the first of the resolved set): construct this via
/// `parse_from_args`, not field-by-field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EdgeCliConfig {
    pub worker_sockets: Vec<PathBuf>,
    pub max_body_bytes: Option<u64>,
    pub http_bind: Option<SocketAddr>,
    pub https_bind: Option<SocketAddr>,
    pub fqdn: Option<String>,
    pub public_origin_port: Option<u16>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_h2: Option<bool>,
    pub acme_state_path: Option<PathBuf>,
    pub acme_issue_once: bool,
    pub acme_renew_once: bool,
    pub acme_directory_url: Option<String>,
    pub acme_contacts: Vec<String>,
    pub acme_accept_terms: bool,
    pub acme_allow_production_directory: bool,
    pub public_mode: Option<String>,
    pub public_identity: Option<String>,
    pub trusted_proxy_cidrs: Vec<String>,
    pub max_in_flight_per_identity: Option<u64>,
    pub max_in_flight_requests: Option<u64>,
    pub header_read_timeout_ms: Option<u64>,
    pub keepalive_idle_timeout_ms: Option<u64>,
    pub max_connection_secs: Option<u64>,
    pub long_lived_max_connections: Option<u64>,
    pub long_lived_max_buffered_bytes: Option<u64>,
    pub long_lived_downstream_write_timeout_ms: Option<u64>,
    pub drain_grace_ms: Option<u64>,
    pub admin_bind: Option<SocketAddr>,
    pub action_cable_bind: Option<SocketAddr>,
    pub grpc_bind: Option<SocketAddr>,
    pub sse_enabled: Option<bool>,
    /// opt-in downstream HTTP/1.1 connection reuse (keepalive). `None`/`Some(false)`
    /// keeps today's one-shot model; `Some(true)` enables reuse bounded by the idle
    /// timeout. Default is OFF until a later milestone flips it after metal evidence.
    pub keepalive_enabled: Option<bool>,
    /// total requests a kept-alive connection may serve before it is closed
    /// (operator-facing semantics; N=1 means genuine one-shot). Default 1000 (nginx
    /// `keepalive_requests` parity). Only takes effect under `--keepalive`.
    pub max_requests_per_connection: Option<u64>,
    /// HTTP/2 max concurrent streams advertised in SETTINGS (default 100).
    pub h2_max_concurrent_streams: Option<u64>,
    /// HTTP/2 pending-accept RST_STREAM cap (CVE-2023-44487 rapid-reset; default 20).
    pub h2_max_reset_streams: Option<u64>,
    /// per-request stderr log posture (`off|rejections|all`). Default `rejections`
    /// (resolved at boot): the hot-path `response` line is off, the rejection-class
    /// forensic lines stay on. Validated by the boot resolver, not here.
    pub request_log: Option<String>,
    /// edge↔worker hop wire format (`frame|http`). Default `frame` (pooled binary
    /// pre-parsed frame); `http` keeps the one-shot HTTP/1.1 text hop for A/B
    /// benching and compat. Validated by the boot resolver.
    pub worker_hop: Option<String>,
    /// worker dispatch discipline (`least-outstanding|rr|free-first`). Default
    /// `least-outstanding` (the /causally-proven convoy fix — first
    /// full-scoreboard win vs bare puma at guest tier; guest = decision-grade for
    /// relative/algorithmic levers per the policy). `rr` restores the pre-
    /// busy-blind rotation; `free-first` is bench-tier (measured worse in M2).
    /// Validated by the boot resolver; refused for >16-worker fleets except `rr`.
    pub worker_dispatch: Option<String>,
    /// per-worker admission cap K ("dispatch-on-free"). None = uncapped, the
    /// shipped default; overflow beyond K parks in a shared edge-side FIFO and binds
    /// late. Validated by the boot resolver (>=1; K x workers must sit below the
    /// global in-flight cap when one is set).
    pub worker_cap: Option<u64>,
    /// Tokio worker threads for the Pingora proxy service (`ServerConf.threads`).
    /// The edge is a non-blocking event loop, so parallelism — TLS handshakes, parsing,
    /// proxying — is bounded by threads while concurrency comes from tasks; `None`
    /// defaults to nproc. Pingora's own default of 1 was the `/bench` ceiling.
    pub edge_threads: Option<u64>,
    /// parallel accept tasks per listening fd (`ServerConf.listener_tasks_per_fd`).
    /// Pingora defaults to 1 — a single accept task per socket, which serializes accepts
    /// under high connections/sec (the churn regime). `None` keeps that default; the knob
    /// exists so accept-rate saturation has a config answer short of SO_REUSEPORT fan-out,
    /// which would fragment the single-process security counters (ROADMAP 1b).
    pub listener_tasks: Option<u64>,
    /// Raw `PREFIX=DIR[,opts]` mount specs (static serving); parsed fail-closed by
    /// the edge boot path via crenel's canonical `MountSpec::parse`.
    pub static_mounts: Vec<String>,
    /// Rails sugar: expands to `/assets=<dir>/assets,cache-control=immutable…` (strict
    /// 404) + `/=<dir>,fallthrough`.
    pub static_rails_preset: Option<PathBuf>,
    /// ergonomics preset: the Rails app ROOT. Enables keepalive + SSE (each
    /// overridable by the explicit flags/env) and derives static mounts from
    /// `<root>/public` unless `static_rails_preset` names the dir explicitly. The root
    /// must exist (fail-closed); missing derived dirs degrade with logged warnings.
    pub serve_rails: Option<PathBuf>,
    /// (lever 2, "P3b"): production static-routing mode. `None`/`Some(false)` keeps
    /// today's DEV behavior — every GET/HEAD request calls `static_server.serve()`, which
    /// probes the filesystem (`newfstatat`+`openat2`) even for dynamic routes, so a
    /// freshly-deployed static file is served without a restart (Rails ergonomics). Under
    /// `Some(true)` (`--prod`) the edge enumerates the static docroots ONCE at boot into a
    /// first-path-segment pin set; at request time `serve()` is attempted only when the
    /// request's first path segment is pinned, so dynamic routes skip the two filesystem
    /// probe syscalls entirely. Trades hot-reload of newly-added static files for the
    /// eliminated per-request probe — the dev/prod tenet's first application. In its
    /// ONLY behavioral change is this serve() gate (asserted, so the 1p-vs-1 attribution
    /// stays clean); broader `--prod` hardening lands in .
    pub prod_enabled: Option<bool>,
    pub check_config: bool,
}

impl EdgeCliConfig {
    pub fn parse_from_args<I, S>(args: I) -> Result<Self, EdgeError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut args = args.into_iter().map(Into::into);
        let _program = args.next();
        Self::parse_flags(args)
    }

    pub fn parse_flags<I, S>(flags: I) -> Result<Self, EdgeError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut config = Self::default();
        let mut args = flags.into_iter().map(Into::into);
        while let Some(arg) = args.next() {
            let raw = cli_utf8("flag", arg)?;
            let (flag, inline) = match raw.split_once('=') {
                Some((flag, value)) => (flag.to_string(), Some(OsString::from(value))),
                None => (raw, None),
            };
            match flag.as_str() {
                "--check-config" => {
                    reject_inline_value(&flag, inline)?;
                    config.check_config = true;
                }
                "--sse" => {
                    reject_inline_value(&flag, inline)?;
                    config.sse_enabled = Some(true);
                }
                "--no-sse" => {
                    reject_inline_value(&flag, inline)?;
                    config.sse_enabled = Some(false);
                }
                "--serve-rails" => {
                    config.serve_rails =
                        Some(PathBuf::from(take_cli_value(&flag, inline, &mut args)?));
                }
                "--keepalive" => {
                    reject_inline_value(&flag, inline)?;
                    config.keepalive_enabled = Some(true);
                }
                "--no-keepalive" => {
                    reject_inline_value(&flag, inline)?;
                    config.keepalive_enabled = Some(false);
                }
                "--prod" => {
                    reject_inline_value(&flag, inline)?;
                    config.prod_enabled = Some(true);
                }
                "--no-prod" => {
                    reject_inline_value(&flag, inline)?;
                    config.prod_enabled = Some(false);
                }
                "--max-requests-per-connection" => {
                    config.max_requests_per_connection = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--h2-max-concurrent-streams" => {
                    config.h2_max_concurrent_streams = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--h2-max-reset-streams" => {
                    config.h2_max_reset_streams = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--edge-threads" => {
                    config.edge_threads = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--listener-tasks" => {
                    config.listener_tasks = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--request-log" => {
                    config.request_log = Some(cli_string_value(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--worker-hop" => {
                    config.worker_hop = Some(cli_string_value(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--worker-dispatch" => {
                    config.worker_dispatch = Some(cli_string_value(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--worker-cap" => {
                    config.worker_cap = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--tls-h2" => {
                    reject_inline_value(&flag, inline)?;
                    config.tls_h2 = Some(true);
                }
                "--no-tls-h2" => {
                    reject_inline_value(&flag, inline)?;
                    config.tls_h2 = Some(false);
                }
                "--worker-socket" => {
                    config
                        .worker_sockets
                        .push(PathBuf::from(take_cli_value(&flag, inline, &mut args)?));
                }
                "--static-mount" => {
                    config.static_mounts.push(cli_string_value(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--static-rails-preset" => {
                    config.static_rails_preset =
                        Some(PathBuf::from(take_cli_value(&flag, inline, &mut args)?));
                }
                "--max-body" => {
                    config.max_body_bytes = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--http-bind" => {
                    config.http_bind = Some(parse_socket_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--https-bind" => {
                    config.https_bind = Some(parse_socket_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--fqdn" => {
                    config.fqdn = Some(cli_string_value(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--public-origin-port" => {
                    config.public_origin_port = Some(parse_u16_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--tls-cert" => {
                    config.tls_cert =
                        Some(PathBuf::from(take_cli_value(&flag, inline, &mut args)?));
                }
                "--tls-key" => {
                    config.tls_key = Some(PathBuf::from(take_cli_value(&flag, inline, &mut args)?));
                }
                "--acme-state-path" => {
                    config.acme_state_path =
                        Some(PathBuf::from(take_cli_value(&flag, inline, &mut args)?));
                }
                "--acme-issue-once" => {
                    reject_inline_value(&flag, inline)?;
                    config.acme_issue_once = true;
                }
                "--acme-renew-once" => {
                    reject_inline_value(&flag, inline)?;
                    config.acme_renew_once = true;
                }
                "--acme-directory-url" => {
                    config.acme_directory_url = Some(cli_string_value(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--acme-contact" => {
                    config.acme_contacts.push(cli_string_value(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--acme-accept-terms" => {
                    reject_inline_value(&flag, inline)?;
                    config.acme_accept_terms = true;
                }
                "--acme-allow-production-directory" => {
                    reject_inline_value(&flag, inline)?;
                    config.acme_allow_production_directory = true;
                }
                "--public-mode" => {
                    config.public_mode = Some(cli_string_value(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--public-identity" => {
                    config.public_identity = Some(cli_string_value(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--trusted-proxy-cidr" => {
                    config.trusted_proxy_cidrs.push(cli_string_value(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--max-in-flight-per-identity" => {
                    config.max_in_flight_per_identity = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--max-in-flight-requests" => {
                    config.max_in_flight_requests = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--header-read-timeout-ms" => {
                    config.header_read_timeout_ms = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--keepalive-idle-timeout-ms" => {
                    config.keepalive_idle_timeout_ms = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--max-connection-secs" => {
                    config.max_connection_secs = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--long-lived-max-connections" => {
                    config.long_lived_max_connections = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--long-lived-max-buffered-bytes" => {
                    config.long_lived_max_buffered_bytes = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--long-lived-downstream-write-timeout-ms" => {
                    config.long_lived_downstream_write_timeout_ms = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--drain-grace-ms" => {
                    config.drain_grace_ms = Some(parse_u64_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--admin-bind" => {
                    config.admin_bind = Some(parse_socket_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--action-cable-bind" => {
                    config.action_cable_bind = Some(parse_socket_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                "--grpc-bind" => {
                    config.grpc_bind = Some(parse_socket_arg(
                        &flag,
                        take_cli_value(&flag, inline, &mut args)?,
                    )?);
                }
                _ => {
                    return Err(EdgeError::ConfigEnv {
                        name: "argv",
                        message: format!("unknown argument {flag}"),
                    })
                }
            }
        }
        Ok(config)
    }

    pub fn to_edge_args(&self) -> Vec<OsString> {
        let mut args = Vec::new();
        for socket in &self.worker_sockets {
            push_arg(
                &mut args,
                "--worker-socket",
                socket.as_os_str().to_os_string(),
            );
        }
        if let Some(bytes) = self.max_body_bytes {
            push_arg(&mut args, "--max-body", bytes.to_string());
        }
        if let Some(bind) = self.http_bind {
            push_arg(&mut args, "--http-bind", bind.to_string());
        }
        if let Some(bind) = self.https_bind {
            push_arg(&mut args, "--https-bind", bind.to_string());
        }
        if let Some(fqdn) = &self.fqdn {
            push_arg(&mut args, "--fqdn", fqdn);
        }
        if let Some(port) = self.public_origin_port {
            push_arg(&mut args, "--public-origin-port", port.to_string());
        }
        if let Some(path) = &self.tls_cert {
            push_arg(&mut args, "--tls-cert", path.as_os_str().to_os_string());
        }
        if let Some(path) = &self.tls_key {
            push_arg(&mut args, "--tls-key", path.as_os_str().to_os_string());
        }
        match self.tls_h2 {
            Some(true) => args.push(OsString::from("--tls-h2")),
            Some(false) => args.push(OsString::from("--no-tls-h2")),
            None => {}
        }
        if let Some(path) = &self.acme_state_path {
            push_arg(
                &mut args,
                "--acme-state-path",
                path.as_os_str().to_os_string(),
            );
        }
        if self.acme_issue_once {
            args.push(OsString::from("--acme-issue-once"));
        }
        if self.acme_renew_once {
            args.push(OsString::from("--acme-renew-once"));
        }
        if let Some(url) = &self.acme_directory_url {
            push_arg(&mut args, "--acme-directory-url", url);
        }
        for contact in &self.acme_contacts {
            push_arg(&mut args, "--acme-contact", contact);
        }
        if self.acme_accept_terms {
            args.push(OsString::from("--acme-accept-terms"));
        }
        if self.acme_allow_production_directory {
            args.push(OsString::from("--acme-allow-production-directory"));
        }
        if let Some(mode) = &self.public_mode {
            push_arg(&mut args, "--public-mode", mode);
        }
        if let Some(identity) = &self.public_identity {
            push_arg(&mut args, "--public-identity", identity);
        }
        for cidr in &self.trusted_proxy_cidrs {
            push_arg(&mut args, "--trusted-proxy-cidr", cidr);
        }
        if let Some(max) = self.max_in_flight_per_identity {
            push_arg(&mut args, "--max-in-flight-per-identity", max.to_string());
        }
        if let Some(max) = self.max_in_flight_requests {
            push_arg(&mut args, "--max-in-flight-requests", max.to_string());
        }
        if let Some(timeout_ms) = self.header_read_timeout_ms {
            push_arg(
                &mut args,
                "--header-read-timeout-ms",
                timeout_ms.to_string(),
            );
        }
        if let Some(timeout_ms) = self.keepalive_idle_timeout_ms {
            push_arg(
                &mut args,
                "--keepalive-idle-timeout-ms",
                timeout_ms.to_string(),
            );
        }
        if let Some(max_secs) = self.max_connection_secs {
            push_arg(&mut args, "--max-connection-secs", max_secs.to_string());
        }
        if let Some(max) = self.long_lived_max_connections {
            push_arg(&mut args, "--long-lived-max-connections", max.to_string());
        }
        if let Some(max) = self.long_lived_max_buffered_bytes {
            push_arg(
                &mut args,
                "--long-lived-max-buffered-bytes",
                max.to_string(),
            );
        }
        if let Some(timeout_ms) = self.long_lived_downstream_write_timeout_ms {
            push_arg(
                &mut args,
                "--long-lived-downstream-write-timeout-ms",
                timeout_ms.to_string(),
            );
        }
        if let Some(grace_ms) = self.drain_grace_ms {
            push_arg(&mut args, "--drain-grace-ms", grace_ms.to_string());
        }
        if let Some(bind) = self.admin_bind {
            push_arg(&mut args, "--admin-bind", bind.to_string());
        }
        if let Some(bind) = self.action_cable_bind {
            push_arg(&mut args, "--action-cable-bind", bind.to_string());
        }
        if let Some(bind) = self.grpc_bind {
            push_arg(&mut args, "--grpc-bind", bind.to_string());
        }
        // sse is tri-state like keepalive — Some(false) must round-trip as
        // --no-sse so an explicit override survives the service->edge argv hop and
        // beats the serve-rails preset on the child.
        match self.sse_enabled {
            Some(true) => args.push(OsString::from("--sse")),
            Some(false) => args.push(OsString::from("--no-sse")),
            None => {}
        }
        // forward the resolved keepalive posture explicitly in BOTH directions so
        // the env-cleared edge child never falls back to a different default than the
        // service runner resolved.
        match self.keepalive_enabled {
            Some(true) => args.push(OsString::from("--keepalive")),
            Some(false) => args.push(OsString::from("--no-keepalive")),
            None => {}
        }
        // forward the resolved prod (boot-pinned static routing) posture explicitly
        // in BOTH directions so the env-cleared edge child boot-pins its docroots iff the
        // service runner resolved --prod, and a Some(false) override beats any preset.
        match self.prod_enabled {
            Some(true) => args.push(OsString::from("--prod")),
            Some(false) => args.push(OsString::from("--no-prod")),
            None => {}
        }
        if let Some(max) = self.max_requests_per_connection {
            push_arg(&mut args, "--max-requests-per-connection", max.to_string());
        }
        if let Some(max) = self.h2_max_concurrent_streams {
            push_arg(&mut args, "--h2-max-concurrent-streams", max.to_string());
        }
        if let Some(max) = self.h2_max_reset_streams {
            push_arg(&mut args, "--h2-max-reset-streams", max.to_string());
        }
        if let Some(threads) = self.edge_threads {
            push_arg(&mut args, "--edge-threads", threads.to_string());
        }
        if let Some(tasks) = self.listener_tasks {
            push_arg(&mut args, "--listener-tasks", tasks.to_string());
        }
        if let Some(mode) = &self.request_log {
            push_arg(&mut args, "--request-log", mode);
        }
        if let Some(hop) = &self.worker_hop {
            push_arg(&mut args, "--worker-hop", hop);
        }
        if let Some(dispatch) = &self.worker_dispatch {
            push_arg(&mut args, "--worker-dispatch", dispatch);
        }
        if let Some(cap) = self.worker_cap {
            push_arg(&mut args, "--worker-cap", cap.to_string());
        }
        for spec in &self.static_mounts {
            push_arg(&mut args, "--static-mount", spec);
        }
        if let Some(path) = &self.static_rails_preset {
            push_arg(
                &mut args,
                "--static-rails-preset",
                path.as_os_str().to_os_string(),
            );
        }
        if let Some(path) = &self.serve_rails {
            push_arg(&mut args, "--serve-rails", path.as_os_str().to_os_string());
        }
        if self.check_config {
            args.push(OsString::from("--check-config"));
        }
        args
    }
}

fn push_arg<V>(args: &mut Vec<OsString>, flag: &str, value: V)
where
    V: Into<OsString>,
{
    args.push(OsString::from(flag));
    args.push(value.into());
}

fn reject_inline_value(flag: &str, inline: Option<OsString>) -> Result<(), EdgeError> {
    if inline.is_some() {
        return Err(EdgeError::ConfigEnv {
            name: "argv",
            message: format!("{flag} does not take a value"),
        });
    }
    Ok(())
}

fn take_cli_value<I>(
    flag: &str,
    inline: Option<OsString>,
    args: &mut I,
) -> Result<OsString, EdgeError>
where
    I: Iterator<Item = OsString>,
{
    inline
        .or_else(|| args.next())
        .ok_or_else(|| EdgeError::ConfigEnv {
            name: "argv",
            message: format!("{flag} requires a value"),
        })
}

fn cli_string_value(flag: &str, value: OsString) -> Result<String, EdgeError> {
    let value = cli_utf8(flag, value)?;
    if value.trim().is_empty() {
        return Err(EdgeError::ConfigEnv {
            name: "argv",
            message: format!("{flag} must not be empty"),
        });
    }
    Ok(value)
}

fn parse_socket_arg(flag: &str, value: OsString) -> Result<SocketAddr, EdgeError> {
    let raw = cli_string_value(flag, value)?;
    raw.parse().map_err(|err| EdgeError::ConfigEnv {
        name: "argv",
        message: format!("{flag} expected socket address: {err}"),
    })
}

fn parse_u16_arg(flag: &str, value: OsString) -> Result<u16, EdgeError> {
    let raw = cli_string_value(flag, value)?;
    raw.parse().map_err(|err| EdgeError::ConfigEnv {
        name: "argv",
        message: format!("{flag} expected integer port: {err}"),
    })
}

fn parse_u64_arg(flag: &str, value: OsString) -> Result<u64, EdgeError> {
    let raw = cli_string_value(flag, value)?;
    raw.parse().map_err(|err| EdgeError::ConfigEnv {
        name: "argv",
        message: format!("{flag} expected integer byte count: {err}"),
    })
}

fn cli_utf8(role: &str, value: OsString) -> Result<String, EdgeError> {
    value.into_string().map_err(|value| EdgeError::ConfigEnv {
        name: "argv",
        message: format!("{role} must be valid UTF-8: {value:?}"),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeConfig {
    pub bind: SocketAddr,
    pub worker_socket: PathBuf,
    pub worker_set: WorkerSet,
    pub max_body_bytes: u64,
    pub sse_enabled: bool,
}

impl EdgeConfig {
    // Convenience constructors used only by tests; production (`run_with_cli`) calls
    // `new_with_worker_sockets_and_public_alpha` directly with an explicit alpha flag.
    #[cfg(test)]
    pub fn new(
        bind: SocketAddr,
        worker_socket: impl Into<PathBuf>,
        max_body_bytes: u64,
    ) -> Result<Self, EdgeError> {
        Self::new_with_worker_sockets(bind, vec![worker_socket.into()], max_body_bytes)
    }

    #[cfg(test)]
    pub fn new_with_worker_sockets(
        bind: SocketAddr,
        worker_sockets: Vec<PathBuf>,
        max_body_bytes: u64,
    ) -> Result<Self, EdgeError> {
        Self::new_with_worker_sockets_and_public_alpha(bind, worker_sockets, max_body_bytes, false)
    }

    pub fn new_with_worker_sockets_and_public_alpha(
        bind: SocketAddr,
        worker_sockets: Vec<PathBuf>,
        max_body_bytes: u64,
        allow_public_alpha: bool,
    ) -> Result<Self, EdgeError> {
        if !bind.ip().is_loopback() && !allow_public_alpha {
            return Err(EdgeError::NonLoopbackBind { bind });
        }
        if max_body_bytes == 0 {
            return Err(EdgeError::ZeroMaxBody);
        }
        if worker_sockets.is_empty() {
            return Err(EdgeError::NoWorkersConfigured);
        }

        for worker_socket in &worker_sockets {
            validate_worker_socket_path(worker_socket)?;
        }
        let worker_socket = worker_sockets[0].clone();
        let worker_set = WorkerSet::ready(worker_sockets);

        Ok(Self {
            bind,
            worker_socket,
            worker_set,
            max_body_bytes,
            sse_enabled: false,
        })
    }

    pub fn with_sse_enabled(mut self, enabled: bool) -> Self {
        self.sse_enabled = enabled;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerSlotState {
    Ready,
    Draining,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSlot {
    pub id: u32,
    pub generation: u64,
    pub socket: PathBuf,
    pub state: WorkerSlotState,
    pub draining: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSet {
    slots: Vec<WorkerSlot>,
}

impl WorkerSet {
    pub fn single_ready(socket: PathBuf) -> Self {
        Self::ready(vec![socket])
    }

    pub fn ready(sockets: Vec<PathBuf>) -> Self {
        Self {
            slots: sockets
                .into_iter()
                .enumerate()
                .map(|(id, socket)| WorkerSlot {
                    id: id as u32,
                    generation: 1,
                    socket,
                    state: WorkerSlotState::Ready,
                    draining: false,
                })
                .collect(),
        }
    }

    pub fn ready_sockets(&self) -> Vec<&Path> {
        self.slots
            .iter()
            .filter(|slot| slot.state == WorkerSlotState::Ready && !slot.draining)
            .map(|slot| slot.socket.as_path())
            .collect()
    }

    pub fn configured_socket(&self) -> Option<&Path> {
        self.slots.first().map(|slot| slot.socket.as_path())
    }

    pub fn slots(&self) -> &[WorkerSlot] {
        &self.slots
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedHopMetadata {
    pub remote_addr: String,
    pub url_scheme: String,
    pub server_name: String,
    pub server_port: u16,
    pub request_id: Option<String>,
}

impl TrustedHopMetadata {
    pub fn headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![
            ("x-oxo-remote-addr".to_string(), self.remote_addr.clone()),
            ("x-oxo-url-scheme".to_string(), self.url_scheme.clone()),
            ("x-oxo-server-name".to_string(), self.server_name.clone()),
            (
                "x-oxo-server-port".to_string(),
                self.server_port.to_string(),
            ),
        ];
        if let Some(request_id) = &self.request_id {
            headers.push(("x-oxo-request-id".to_string(), request_id.clone()));
        }
        headers
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PublicIdentityPolicy {
    #[default]
    DirectPublic,
    TrustedProxy(TrustedProxyPolicy),
}

impl PublicIdentityPolicy {
    pub fn resolve_remote_addr<N, V>(
        &self,
        peer_addr: &str,
        headers: &[(N, V)],
    ) -> Result<String, IdentityRejection>
    where
        N: AsRef<str>,
        V: AsRef<str>,
    {
        match self {
            Self::DirectPublic => Ok(normalize_peer_addr(peer_addr)),
            Self::TrustedProxy(policy) => policy.resolve_remote_addr(peer_addr, headers),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedProxyPolicy {
    cidrs: Vec<IpCidr>,
}

impl TrustedProxyPolicy {
    pub fn parse_all(raw_cidrs: &[String]) -> Result<Self, String> {
        if raw_cidrs.is_empty() {
            return Err(
                "trusted-proxy identity requires at least one trusted proxy CIDR".to_string(),
            );
        }
        let cidrs = raw_cidrs
            .iter()
            .map(|raw| IpCidr::parse(raw))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { cidrs })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    pub fn resolve_remote_addr<N, V>(
        &self,
        peer_addr: &str,
        headers: &[(N, V)],
    ) -> Result<String, IdentityRejection>
    where
        N: AsRef<str>,
        V: AsRef<str>,
    {
        let peer_ip = parse_peer_ip(peer_addr).ok_or(IdentityRejection::MalformedImmediatePeer)?;
        self.resolve_remote_addr_core(
            peer_ip,
            headers
                .iter()
                .map(|(name, value)| (name.as_ref().to_ascii_lowercase(), value.as_ref())),
        )
    }

    /// W2: the frame-path variant — the proxy already holds `LoweredHeader`s whose
    /// lowercase names were computed once at collect time, so this resolves identity
    /// without the per-header `to_ascii_lowercase()` String the generic API pays.
    /// Same core, same match-arm order, same rejections.
    pub fn resolve_remote_addr_lowered(
        &self,
        peer_ip: IpAddr,
        headers: &[LoweredHeader<'_>],
    ) -> Result<String, IdentityRejection> {
        self.resolve_remote_addr_core(peer_ip, headers.iter().map(|h| (h.lower(), h.value())))
    }

    /// Shared identity-resolution core. `lowered_name` MUST be ASCII-lowercase — both
    /// wrappers guarantee it (one by allocating, one from LoweredHeader's invariant).
    fn resolve_remote_addr_core<'a, L>(
        &self,
        peer_ip: IpAddr,
        lowered_headers: impl Iterator<Item = (L, &'a str)>,
    ) -> Result<String, IdentityRejection>
    where
        L: AsRef<str>,
    {
        if !self.contains(peer_ip) {
            return Err(IdentityRejection::UntrustedImmediatePeer);
        }

        let mut x_forwarded_for = None;
        for (lower, value) in lowered_headers {
            match lower.as_ref() {
                // The canonical identity source. MUST stay above the forwarding-class guard
                // below (the predicate also matches "x-forwarded-for"); match-arm order is
                // load-bearing.
                "x-forwarded-for" => {
                    if x_forwarded_for.replace(value).is_some() {
                        return Err(IdentityRejection::DuplicateForwardedFor);
                    }
                }
                // Any OTHER forwarding / real-IP / CDN-client-IP header (forwarded, x-real-ip,
                // x-forwarded-proto, Client-IP, CF-Connecting-IP, …) is ambiguous in
                // trusted-proxy mode: a normalizing upstream presents only canonical XFF, so a
                // second forwarding channel is a spoof or misconfig. Fail closed.
                other if oxo_core::is_client_forwarding_header(other) => {
                    return Err(IdentityRejection::AmbiguousForwardingHeader);
                }
                _ => {}
            }
        }

        let chain = x_forwarded_for.ok_or(IdentityRejection::MissingForwardedFor)?;
        let mut parsed = Vec::new();
        for token in chain.split(',') {
            let token = token.trim();
            if token.is_empty() {
                return Err(IdentityRejection::MalformedForwardedFor);
            }
            let ip = token
                .parse::<IpAddr>()
                .map_err(|_| IdentityRejection::MalformedForwardedFor)?;
            parsed.push(ip);
        }

        for ip in parsed.iter().rev() {
            if !self.contains(*ip) {
                return Ok(ip.to_string());
            }
        }
        Err(IdentityRejection::NoUntrustedClientIp)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    fn parse(raw: &str) -> Result<Self, String> {
        let (network, prefix) = raw
            .split_once('/')
            .ok_or_else(|| format!("trusted proxy CIDR {raw:?} must include a prefix length"))?;
        let network = network
            .parse::<IpAddr>()
            .map_err(|_| format!("trusted proxy CIDR {raw:?} has an invalid IP address"))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| format!("trusted proxy CIDR {raw:?} has an invalid prefix length"))?;
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(format!(
                "trusted proxy CIDR {raw:?} prefix length must be <= {max}"
            ));
        }
        Ok(Self { network, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                prefix_match_u32(u32::from(network), u32::from(ip), self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                prefix_match_u128(u128::from(network), u128::from(ip), self.prefix)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityRejection {
    MalformedImmediatePeer,
    UntrustedImmediatePeer,
    MissingForwardedFor,
    DuplicateForwardedFor,
    AmbiguousForwardingHeader,
    MalformedForwardedFor,
    NoUntrustedClientIp,
}

impl IdentityRejection {
    pub fn status(&self) -> u16 {
        match self {
            Self::UntrustedImmediatePeer => 403,
            _ => 400,
        }
    }
}

/// Test-only re-export: the W2 DirectPublic fast path in proxy.rs pins its parity
/// against this exact function (the old pipeline), so the old behavior stays the oracle.
///
/// Gated on Linux as well as `test`: the only callers are the `platform::proxy` parity
/// tests, and `platform` is the Linux-only module — on the stub build this is dead code
/// and `-D warnings` rejects it.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn normalize_peer_addr_for_tests(peer_addr: &str) -> String {
    normalize_peer_addr(peer_addr)
}

fn normalize_peer_addr(peer_addr: &str) -> String {
    parse_peer_ip(peer_addr)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| peer_addr.to_string())
}

fn parse_peer_ip(peer_addr: &str) -> Option<IpAddr> {
    peer_addr
        .parse::<IpAddr>()
        .ok()
        .or_else(|| peer_addr.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
}

fn prefix_match_u32(network: u32, ip: u32, prefix: u8) -> bool {
    if prefix == 0 {
        true
    } else {
        let mask = u32::MAX << (32 - prefix);
        (network & mask) == (ip & mask)
    }
}

fn prefix_match_u128(network: u128, ip: u128, prefix: u8) -> bool {
    if prefix == 0 {
        true
    } else {
        let mask = u128::MAX << (128 - prefix);
        (network & mask) == (ip & mask)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedWorkerRequest {
    pub headers: Vec<(String, String)>,
    pub stripped_headers: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProtocolSupport {
    pub sse: bool,
}

/// a request header whose ASCII-lowercased name travels WITH the original.
/// Constructed only via `new`, so a name/lower mismatch is unrepresentable — the
/// anti-smuggling strip in `sanitize_*` and the validation ladder both key off
/// `lower`, and a parallel lowered array (or a re-lowercasing fork) would be a
/// smuggle/spoof seam.
#[derive(Debug, Clone)]
pub struct LoweredHeader<'a> {
    name: std::borrow::Cow<'a, str>,
    value: std::borrow::Cow<'a, str>,
    /// W3a: `None` when `name` is already lowercase (H2 always; most H1 clients) —
    /// `lower()` then borrows `name`. The name/lower agreement invariant is unchanged
    /// because `new` and `new_in` are the only constructors and both compute `lower`
    /// from `name` with the same predicate (pinned by `constructors_agree_on_lowering`).
    lower: Option<std::borrow::Cow<'a, str>>,
}

impl LoweredHeader<'static> {
    /// Owned constructor — the cold paths (HTTP hop generic entry, sidecars, tests, the
    /// byte-parity oracle). The hot frame path uses `LoweredHeader::new_in` — a plain
    /// code span, not an intra-doc link, because `new_in` is Linux-gated and the link
    /// would dangle when `cargo doc` runs on the non-Linux stub build.
    pub fn new(name: String, value: String) -> LoweredHeader<'static> {
        // Scalar equivalent: `for b in name.bytes() { if b.is_ascii_uppercase() { … } }`.
        // The iterator form lets LLVM vectorize the scan; either way it is a pure
        // byte-range test with no allocation on the (dominant) already-lowercase path.
        let lower = if name.bytes().any(|b| b.is_ascii_uppercase()) {
            Some(std::borrow::Cow::Owned(name.to_ascii_lowercase()))
        } else {
            None
        };
        LoweredHeader {
            name: std::borrow::Cow::Owned(name),
            value: std::borrow::Cow::Owned(value),
            lower,
        }
    }
}

impl<'a> LoweredHeader<'a> {
    /// W-D: arena constructor — name/value/lower live in the request's bump arena
    /// (zero heap events). Same lowering predicate as `new`; the lowercase twin is
    /// copied into the arena and lowered in place (no intermediate heap String).
    ///
    /// Linux-only, like its sole caller (the `platform` frame path) and like `bumpalo`
    /// itself, which is target-gated in the manifest. Without this gate the non-Linux
    /// stub build references an unlinked crate.
    #[cfg(target_os = "linux")]
    pub fn new_in(bump: &'a bumpalo::Bump, name: &str, value: &str) -> LoweredHeader<'a> {
        let lower = if name.bytes().any(|b| b.is_ascii_uppercase()) {
            let twin = bump.alloc_str(name);
            twin.make_ascii_lowercase();
            Some(std::borrow::Cow::Borrowed(&*twin))
        } else {
            None
        };
        LoweredHeader {
            name: std::borrow::Cow::Borrowed(bump.alloc_str(name)),
            value: std::borrow::Cow::Borrowed(bump.alloc_str(value)),
            lower,
        }
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn value(&self) -> &str {
        &self.value
    }
    pub fn lower(&self) -> &str {
        self.lower.as_deref().unwrap_or(&self.name)
    }
}

pub fn sanitize_worker_request_headers<N, V>(
    headers: &[(N, V)],
    metadata: &TrustedHopMetadata,
) -> Result<SanitizedWorkerRequest, RequestRejection>
where
    N: AsRef<str>,
    V: AsRef<str>,
{
    sanitize_worker_request_headers_with_protocols(headers, metadata, ProtocolSupport::default())
}

pub fn sanitize_worker_request_headers_with_protocols<N, V>(
    headers: &[(N, V)],
    metadata: &TrustedHopMetadata,
    protocols: ProtocolSupport,
) -> Result<SanitizedWorkerRequest, RequestRejection>
where
    N: AsRef<str>,
    V: AsRef<str>,
{
    let lowered: Vec<LoweredHeader<'static>> = headers
        .iter()
        .map(|(name, value)| {
            LoweredHeader::new(name.as_ref().to_string(), value.as_ref().to_string())
        })
        .collect();
    sanitize_lowered_worker_request_headers(&lowered, metadata, protocols)
}

pub fn sanitize_lowered_worker_request_headers(
    headers: &[LoweredHeader<'_>],
    metadata: &TrustedHopMetadata,
    protocols: ProtocolSupport,
) -> Result<SanitizedWorkerRequest, RequestRejection> {
    let mut sanitized = sanitize_lowered_worker_request_headers_bare(headers, protocols)?;
    // HTTP-hop-only tail: the metadata rides as x-oxo-* headers plus an explicit
    // one-shot connection: close. The FRAME hop must NOT get these — it carries the
    // metadata in native frame fields, and appending them here only to filter them out
    // in build_request_frame was ~12 wasted allocations per request (A1).
    sanitized.headers.extend(metadata.headers());
    sanitized
        .headers
        .push(("connection".to_string(), "close".to_string()));
    Ok(sanitized)
}

/// W3b: the frame path's allocation-free sanitize result — a keep-bitmask over the
/// input header indices instead of re-allocated survivor Strings. 128 bits covers the
/// validated maximum (MAX_REQUEST_HEADERS = 100; validate rejects larger requests with
/// 400 before sanitize runs), and the constructor fails closed on anything wider.
pub struct FrameHeaderPlan {
    keep: [u64; 2],
    pub survivor_count: usize,
    /// The post-strip survivor set contains a `host` header (the same presence test the
    /// owned frame builder ran on its survivor Vec) — the frame builder synthesizes one
    /// from the authority when this is false.
    pub has_host: bool,
}

impl FrameHeaderPlan {
    pub fn keeps(&self, index: usize) -> bool {
        index < 128 && (self.keep[index / 64] >> (index % 64)) & 1 == 1
    }
}

/// W3b: sanitize for the FRAME path — identical validation ladder, rejection set,
/// iteration order, and strip predicate as `sanitize_lowered_worker_request_headers_bare`
/// (the owned fn STAYS as the HTTP hop's path and the byte-parity oracle), but the result
/// is a keep-mask over the caller's `LoweredHeader` slice: zero per-header allocation.
/// The Connection-token membership test rescans the Connection header values with
/// `eq_ignore_ascii_case` instead of building a `BTreeSet<String>` — equivalent for a
/// membership test (dedup only mattered for set insertion), including multiple Connection
/// headers and empty tokens.
pub fn sanitize_frame_headers(
    headers: &[LoweredHeader<'_>],
    protocols: ProtocolSupport,
) -> Result<FrameHeaderPlan, RequestRejection> {
    if headers.len() > 128 {
        // Unreachable behind validate's MAX_REQUEST_HEADERS=100 rejection; fail closed
        // with the same status class the validate ladder uses rather than truncating.
        return Err(RequestRejection::UpgradeUnsupported);
    }
    // Pass 1 — the Connection-token pre-pass, exactly as the owned fn: Upgrade token is
    // terminal; other tokens mark hop-by-hop strips resolved via `connection_names_match`.
    for h in headers {
        if h.lower() == "connection" {
            for token in h.value().split(',') {
                let token = token.trim();
                if !token.is_empty() && token.eq_ignore_ascii_case("upgrade") {
                    return Err(RequestRejection::UpgradeUnsupported);
                }
            }
        }
    }
    let connection_names_match = |candidate: &str| -> bool {
        headers
            .iter()
            .filter(|h| h.lower() == "connection")
            .any(|h| {
                h.value()
                    .split(',')
                    .map(str::trim)
                    .any(|token| !token.is_empty() && token.eq_ignore_ascii_case(candidate))
            })
    };

    let mut keep = [0u64; 2];
    let mut survivor_count = 0usize;
    let mut has_host = false;
    for (i, h) in headers.iter().enumerate() {
        let value = h.value();
        let lower = h.lower();

        if lower == "upgrade" || lower.starts_with("sec-websocket-") {
            return Err(RequestRejection::UpgradeUnsupported);
        }
        if lower == "content-type" && is_grpc_content_type(value) {
            return Err(RequestRejection::GrpcUnsupported);
        }
        if !protocols.sse
            && ((lower == "accept" && accepts_event_stream(value)) || lower == "last-event-id")
        {
            return Err(RequestRejection::StreamingUnsupported);
        }

        if should_strip_header_scan(lower, &connection_names_match) {
            continue;
        }

        keep[i / 64] |= 1 << (i % 64);
        survivor_count += 1;
        if lower == "host" {
            has_host = true;
        }
    }

    Ok(FrameHeaderPlan {
        keep,
        survivor_count,
        has_host,
    })
}

/// The strip predicate with the Connection-token set replaced by a scan callback —
/// byte-for-byte the same classification as `should_strip_header`.
fn should_strip_header_scan(
    lower_name: &str,
    connection_names_match: &dyn Fn(&str) -> bool,
) -> bool {
    let hop_by_hop = matches!(
        lower_name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "x-request-id"
    );
    hop_by_hop
        || oxo_core::is_client_forwarding_header(lower_name)
        || lower_name.starts_with("x-oxo-")
        || connection_names_match(lower_name)
}

/// The shared sanitize core: strip/validate ONLY — no hop-specific header attachment.
/// The frame hop consumes this directly (its metadata travels as native frame fields).
pub fn sanitize_lowered_worker_request_headers_bare(
    headers: &[LoweredHeader<'_>],
    protocols: ProtocolSupport,
) -> Result<SanitizedWorkerRequest, RequestRejection> {
    let mut connection_tokens = BTreeSet::new();
    for h in headers {
        if h.lower() == "connection" {
            for token in h.value().split(',') {
                let token = token.trim().to_ascii_lowercase();
                if !token.is_empty() {
                    if token == "upgrade" {
                        return Err(RequestRejection::UpgradeUnsupported);
                    }
                    connection_tokens.insert(token);
                }
            }
        }
    }

    let mut clean = Vec::new();
    let mut stripped = Vec::new();
    for h in headers {
        let value = h.value();
        let lower = h.lower();

        if lower == "upgrade" || lower.starts_with("sec-websocket-") {
            return Err(RequestRejection::UpgradeUnsupported);
        }
        if lower == "content-type" && is_grpc_content_type(value) {
            return Err(RequestRejection::GrpcUnsupported);
        }
        if !protocols.sse
            && ((lower == "accept" && accepts_event_stream(value)) || lower == "last-event-id")
        {
            return Err(RequestRejection::StreamingUnsupported);
        }

        if should_strip_header(lower, &connection_tokens) {
            stripped.push(h.name().to_string());
            continue;
        }

        clean.push((h.name().to_string(), value.to_string()));
    }

    Ok(SanitizedWorkerRequest {
        headers: clean,
        stripped_headers: stripped,
    })
}

fn is_grpc_content_type(value: &str) -> bool {
    is_native_grpc_content_type(value) || is_grpc_web_content_type(value)
}

fn is_native_grpc_content_type(value: &str) -> bool {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type == "application/grpc" || media_type.starts_with("application/grpc+")
}

fn is_grpc_web_content_type(value: &str) -> bool {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type == "application/grpc-web" || media_type.starts_with("application/grpc-web+")
}

#[cfg(target_os = "linux")]
fn is_valid_grpc_timeout(value: &str) -> bool {
    let value = value.trim();
    if !(2..=9).contains(&value.len()) {
        return false;
    }
    let (digits, unit) = value.split_at(value.len() - 1);
    !digits.is_empty()
        && digits.len() <= 8
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && matches!(unit.as_bytes()[0], b'H' | b'M' | b'S' | b'm' | b'u' | b'n')
}

fn accepts_event_stream(value: &str) -> bool {
    value
        .to_ascii_lowercase()
        .split(',')
        .any(|part| part.split(';').next().unwrap_or_default().trim() == "text/event-stream")
}

fn should_strip_header(lower_name: &str, connection_tokens: &BTreeSet<String>) -> bool {
    // Hop-by-hop headers + our own x-request-id (the edge injects x-oxo-request-id).
    let hop_by_hop = matches!(
        lower_name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "x-request-id"
    );
    // The forwarding / real-IP / CDN-client-IP class (forwarded, x-real-ip, x-forwarded-*,
    // Client-IP, CF-Connecting-IP, …) via the centralized oxo-core denylist.
    hop_by_hop
        || oxo_core::is_client_forwarding_header(lower_name)
        || lower_name.starts_with("x-oxo-")
        || connection_tokens.contains(lower_name)
}

pub fn validate_worker_socket_path(path: &Path) -> Result<(), EdgeError> {
    platform::validate_worker_socket_path(path)
}

pub fn run_from_env() -> Result<(), EdgeError> {
    platform::run_from_env()
}

pub fn run_from_args<I, S>(args: I) -> Result<(), EdgeError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    platform::run_from_args(args)
}

pub fn fail_closed_main() -> Result<(), EdgeError> {
    run_from_args(std::env::args_os())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EdgeError {
    #[error("non-loopback bind {bind} requires explicit Pingora public-alpha mode")]
    NonLoopbackBind { bind: SocketAddr },
    #[error("worker socket path must be absolute: {path:?}")]
    WorkerSocketMustBeAbsolute { path: PathBuf },
    #[error("worker socket path has no parent directory: {path:?}")]
    WorkerSocketMissingParent { path: PathBuf },
    #[error("runtime directory is not available: {path:?}: {message}")]
    RuntimeDirUnavailable { path: PathBuf, message: String },
    #[error("runtime directory must not be a symlink: {path:?}")]
    RuntimeDirSymlink { path: PathBuf },
    #[error("runtime directory must be a directory: {path:?}")]
    RuntimeDirNotDirectory { path: PathBuf },
    #[error("runtime directory must be 0700, got {mode:o}: {path:?}")]
    RuntimeDirMode { path: PathBuf, mode: u32 },
    #[error("worker socket must not be a symlink: {path:?}")]
    WorkerSocketSymlink { path: PathBuf },
    #[error("worker socket path is not a socket: {path:?}")]
    WorkerSocketNotSocket { path: PathBuf },
    #[error("worker socket must be 0600, got {mode:o}: {path:?}")]
    WorkerSocketMode { path: PathBuf, mode: u32 },
    #[error("worker socket is not available: {path:?}: {message}")]
    WorkerSocketUnavailable { path: PathBuf, message: String },
    #[error("TLS {role} file is not available: {path:?}: {message}")]
    TlsFileUnavailable {
        role: &'static str,
        path: PathBuf,
        message: String,
    },
    #[error("TLS {role} file must not be a symlink: {path:?}")]
    TlsFileSymlink { role: &'static str, path: PathBuf },
    #[error("TLS {role} path must be a regular file: {path:?}")]
    TlsFileNotFile { role: &'static str, path: PathBuf },
    #[error("TLS private key must not be group/world accessible, got {mode:o}: {path:?}")]
    TlsPrivateKeyMode { path: PathBuf, mode: u32 },
    #[error("TLS certificate {path:?} is not valid for configured server name {server_name:?}: {message}")]
    TlsCertificateName {
        path: PathBuf,
        server_name: String,
        message: String,
    },
    #[error("max body bytes must be greater than zero")]
    ZeroMaxBody,
    #[error("at least one worker socket must be configured")]
    NoWorkersConfigured,
    #[error("Pingora edge is Linux-only in this milestone")]
    UnsupportedPlatform,
    #[error("missing or invalid edge configuration {name}: {message}")]
    ConfigEnv { name: &'static str, message: String },
    #[error("Pingora edge error: {message}")]
    Pingora { message: String },
    #[error("ACME error: {message}")]
    Acme { message: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestRejection {
    #[error("WebSocket/Upgrade is not supported in the request/response milestone")]
    UpgradeUnsupported,
    #[error("gRPC is not Rack-native and is not supported in this milestone")]
    GrpcUnsupported,
    #[error("streaming/SSE is not supported in the request/response milestone")]
    StreamingUnsupported,
}

#[cfg(target_os = "linux")]
mod platform;

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::EdgeError;
    use std::path::Path;

    pub fn run_from_env() -> Result<(), EdgeError> {
        Err(EdgeError::UnsupportedPlatform)
    }

    pub fn run_from_args<I, S>(_args: I) -> Result<(), EdgeError>
    where
        I: IntoIterator<Item = S>,
        S: Into<std::ffi::OsString>,
    {
        Err(EdgeError::UnsupportedPlatform)
    }

    pub fn validate_worker_socket_path(_path: &Path) -> Result<(), EdgeError> {
        Err(EdgeError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::path::PathBuf;

    fn metadata() -> TrustedHopMetadata {
        TrustedHopMetadata {
            remote_addr: "203.0.113.10".to_string(),
            url_scheme: "https".to_string(),
            server_name: "example.test".to_string(),
            server_port: 443,
            request_id: Some("edge-generated".to_string()),
        }
    }

    #[test]
    fn trusted_proxy_identity_resolves_canonical_x_forwarded_for_chain() {
        let policy = PublicIdentityPolicy::TrustedProxy(
            TrustedProxyPolicy::parse_all(&[
                "127.0.0.1/32".to_string(),
                "10.0.0.0/8".to_string(),
                "2001:db8:ffff::/48".to_string(),
            ])
            .unwrap(),
        );
        let headers = [("X-Forwarded-For", "198.51.100.42, 10.1.2.3")];
        assert_eq!(
            policy.resolve_remote_addr("127.0.0.1", &headers).unwrap(),
            "198.51.100.42"
        );

        let ipv6_headers = [("X-Forwarded-For", "2001:db8::42, 2001:db8:ffff::7")];
        assert_eq!(
            policy
                .resolve_remote_addr("127.0.0.1:443", &ipv6_headers)
                .unwrap(),
            "2001:db8::42"
        );
    }

    #[test]
    fn trusted_proxy_identity_rejects_ambiguous_or_malformed_identity() {
        let policy = PublicIdentityPolicy::TrustedProxy(
            TrustedProxyPolicy::parse_all(&["127.0.0.1/32".to_string()]).unwrap(),
        );
        assert_eq!(
            policy
                .resolve_remote_addr("203.0.113.10", &[("X-Forwarded-For", "198.51.100.1")])
                .unwrap_err(),
            IdentityRejection::UntrustedImmediatePeer
        );
        assert_eq!(
            policy
                .resolve_remote_addr(
                    "127.0.0.1",
                    &[
                        ("X-Forwarded-For", "198.51.100.1"),
                        ("X-Forwarded-For", "198.51.100.2"),
                    ],
                )
                .unwrap_err(),
            IdentityRejection::DuplicateForwardedFor
        );
        assert_eq!(
            policy
                .resolve_remote_addr(
                    "127.0.0.1",
                    &[
                        ("X-Forwarded-For", "198.51.100.1"),
                        ("Forwarded", "for=198.51.100.1"),
                    ],
                )
                .unwrap_err(),
            IdentityRejection::AmbiguousForwardingHeader
        );
        assert_eq!(
            policy
                .resolve_remote_addr("127.0.0.1", &[("X-Forwarded-For", "198.51.100.1:1234")])
                .unwrap_err(),
            IdentityRejection::MalformedForwardedFor
        );
        assert_eq!(
            policy
                .resolve_remote_addr("127.0.0.1", &[("X-Forwarded-For", "127.0.0.1")])
                .unwrap_err(),
            IdentityRejection::NoUntrustedClientIp
        );
    }

    #[test]
    fn edge_cli_parses_public_config_flags_and_round_trips_args() {
        let config = EdgeCliConfig::parse_from_args([
            "oxo-pingora-edge",
            "--worker-socket",
            "/tmp/oxo/worker.sock",
            "--max-body=2048",
            "--https-bind",
            "127.0.0.1:8443",
            "--fqdn",
            "app.example",
            "--public-origin-port",
            "443",
            "--tls-cert",
            "/etc/oxo/cert.pem",
            "--tls-key",
            "/etc/oxo/key.pem",
            "--no-tls-h2",
            "--acme-state-path",
            "/var/lib/oxo/acme",
            "--acme-renew-once",
            "--public-mode",
            "smoke-beta",
            "--public-identity",
            "direct-public",
            "--trusted-proxy-cidr",
            "127.0.0.1/32",
            "--max-in-flight-per-identity",
            "7",
            "--max-in-flight-requests",
            "21",
            "--header-read-timeout-ms",
            "15000",
            "--keepalive-idle-timeout-ms",
            "12000",
            "--max-connection-secs",
            "300",
            "--long-lived-max-connections",
            "9",
            "--long-lived-max-buffered-bytes",
            "4096",
            "--long-lived-downstream-write-timeout-ms",
            "2500",
            "--drain-grace-ms",
            "2000",
            "--admin-bind",
            "127.0.0.1:9000",
            "--action-cable-bind",
            "127.0.0.1:28080",
            "--grpc-bind",
            "127.0.0.1:28081",
            "--keepalive",
            "--max-requests-per-connection",
            "500",
            "--h2-max-concurrent-streams",
            "250",
            "--h2-max-reset-streams",
            "8",
            "--edge-threads",
            "4",
            "--request-log",
            "all",
            "--worker-dispatch",
            "rr",
            "--serve-rails",
            "/srv/app/current",
            "--static-rails-preset",
            "/srv/app/current/public",
            "--check-config",
        ])
        .unwrap();

        assert_eq!(
            config.worker_sockets,
            vec![PathBuf::from("/tmp/oxo/worker.sock")]
        );
        assert_eq!(config.max_body_bytes, Some(2048));
        assert_eq!(config.http_bind, None);
        assert_eq!(config.https_bind, Some("127.0.0.1:8443".parse().unwrap()));
        assert_eq!(config.fqdn.as_deref(), Some("app.example"));
        assert_eq!(config.public_origin_port, Some(443));
        assert_eq!(config.tls_cert, Some(PathBuf::from("/etc/oxo/cert.pem")));
        assert_eq!(config.tls_key, Some(PathBuf::from("/etc/oxo/key.pem")));
        assert_eq!(config.tls_h2, Some(false));
        assert_eq!(
            config.acme_state_path,
            Some(PathBuf::from("/var/lib/oxo/acme"))
        );
        assert!(config.acme_renew_once);
        assert_eq!(config.public_mode.as_deref(), Some("smoke-beta"));
        assert_eq!(config.worker_dispatch.as_deref(), Some("rr"));
        assert_eq!(config.public_identity.as_deref(), Some("direct-public"));
        assert_eq!(config.trusted_proxy_cidrs, vec!["127.0.0.1/32"]);
        assert_eq!(config.max_in_flight_per_identity, Some(7));
        assert_eq!(config.max_in_flight_requests, Some(21));
        assert_eq!(config.header_read_timeout_ms, Some(15000));
        assert_eq!(config.keepalive_idle_timeout_ms, Some(12000));
        assert_eq!(config.max_connection_secs, Some(300));
        assert_eq!(config.long_lived_max_connections, Some(9));
        assert_eq!(config.long_lived_max_buffered_bytes, Some(4096));
        assert_eq!(config.long_lived_downstream_write_timeout_ms, Some(2500));
        assert_eq!(config.drain_grace_ms, Some(2000));
        assert_eq!(config.admin_bind, Some("127.0.0.1:9000".parse().unwrap()));
        assert_eq!(
            config.action_cable_bind,
            Some("127.0.0.1:28080".parse().unwrap())
        );
        assert_eq!(config.grpc_bind, Some("127.0.0.1:28081".parse().unwrap()));
        assert_eq!(config.keepalive_enabled, Some(true));
        assert_eq!(config.max_requests_per_connection, Some(500));
        assert_eq!(config.h2_max_concurrent_streams, Some(250));
        assert_eq!(config.h2_max_reset_streams, Some(8));
        assert_eq!(config.edge_threads, Some(4));
        assert_eq!(config.request_log.as_deref(), Some("all"));
        assert_eq!(config.serve_rails, Some(PathBuf::from("/srv/app/current")));
        assert_eq!(
            config.static_rails_preset,
            Some(PathBuf::from("/srv/app/current/public"))
        );
        assert!(config.check_config);

        let round_trip = EdgeCliConfig::parse_from_args(
            std::iter::once(OsString::from("edge")).chain(config.to_edge_args()),
        )
        .unwrap();
        assert_eq!(round_trip, config);
    }

    #[test]
    fn keepalive_flag_tri_state_parses_and_round_trips() {
        // default (absent) stays None (=> one-shot); --keepalive / --no-keepalive
        // are explicit and both survive the argv round-trip.
        let default =
            EdgeCliConfig::parse_from_args(["edge", "--worker-socket", "/w.sock"]).unwrap();
        assert_eq!(default.keepalive_enabled, None);

        for (flag, expected) in [("--keepalive", Some(true)), ("--no-keepalive", Some(false))] {
            let config =
                EdgeCliConfig::parse_from_args(["edge", "--worker-socket", "/w.sock", flag])
                    .unwrap();
            assert_eq!(config.keepalive_enabled, expected, "flag {flag}");
            let round_trip = EdgeCliConfig::parse_from_args(
                std::iter::once(OsString::from("edge")).chain(config.to_edge_args()),
            )
            .unwrap();
            assert_eq!(round_trip.keepalive_enabled, expected, "round-trip {flag}");
        }
    }

    #[test]
    fn sse_flag_tri_state_parses_and_round_trips() {
        // sse gained --no-sse so an explicit override can beat the serve-rails
        // preset across the service->edge argv hop. Default (absent) stays None.
        let default =
            EdgeCliConfig::parse_from_args(["edge", "--worker-socket", "/w.sock"]).unwrap();
        assert_eq!(default.sse_enabled, None);

        for (flag, expected) in [("--sse", Some(true)), ("--no-sse", Some(false))] {
            let config =
                EdgeCliConfig::parse_from_args(["edge", "--worker-socket", "/w.sock", flag])
                    .unwrap();
            assert_eq!(config.sse_enabled, expected, "flag {flag}");
            let round_trip = EdgeCliConfig::parse_from_args(
                std::iter::once(OsString::from("edge")).chain(config.to_edge_args()),
            )
            .unwrap();
            assert_eq!(round_trip.sse_enabled, expected, "round-trip {flag}");
        }
    }

    #[test]
    fn prod_flag_tri_state_parses_and_round_trips() {
        // (lever 2): default (absent) stays None (=> dev live-probe); --prod /
        // --no-prod are explicit and both survive the service->edge argv round-trip so the
        // env-cleared edge child boot-pins iff the runner resolved --prod.
        let default =
            EdgeCliConfig::parse_from_args(["edge", "--worker-socket", "/w.sock"]).unwrap();
        assert_eq!(default.prod_enabled, None);

        for (flag, expected) in [("--prod", Some(true)), ("--no-prod", Some(false))] {
            let config =
                EdgeCliConfig::parse_from_args(["edge", "--worker-socket", "/w.sock", flag])
                    .unwrap();
            assert_eq!(config.prod_enabled, expected, "flag {flag}");
            let round_trip = EdgeCliConfig::parse_from_args(
                std::iter::once(OsString::from("edge")).chain(config.to_edge_args()),
            )
            .unwrap();
            assert_eq!(round_trip.prod_enabled, expected, "round-trip {flag}");
        }
    }

    #[test]
    fn prod_flag_rejects_inline_value() {
        // Tri-state booleans refuse `--prod=x` (the value is meaningless; use --no-prod).
        let err =
            EdgeCliConfig::parse_from_args(["edge", "--worker-socket", "/w.sock", "--prod=1"]);
        assert!(err.is_err(), "--prod=1 must be rejected");
    }

    #[test]
    fn edge_cli_rejects_unknown_flags() {
        let err = EdgeCliConfig::parse_from_args(["edge", "--definitely-unknown"])
            .expect_err("unknown flags must fail closed");
        assert!(err
            .to_string()
            .contains("unknown argument --definitely-unknown"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn edge_cli_rejects_unavailable_production_public_mode() {
        let err = platform::run_from_args([
            "edge",
            "--worker-socket",
            "/tmp/oxo-test-worker.sock",
            "--http-bind",
            "0.0.0.0:0",
            "--max-body",
            "1024",
            "--public-mode",
            "production",
            "--check-config",
        ])
        .expect_err("production mode must remain unavailable until explicitly shipped");
        let text = err.to_string();
        assert!(text.contains("OXO_EDGE_PUBLIC_MODE"), "{text}");
        assert!(text.contains("expected alpha or smoke-beta"), "{text}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn edge_socket_activation_env_markers_fail_closed() {
        assert_eq!(
            platform::socket_activation_env_name(|name| match name {
                "LISTEN_FDS" => Some(OsString::from("1")),
                _ => None,
            }),
            Some("LISTEN_FDS")
        );
        assert_eq!(
            platform::socket_activation_env_name(|name| match name {
                "LISTEN_PID" => Some(OsString::from("12345")),
                _ => None,
            }),
            Some("LISTEN_PID")
        );
        assert_eq!(
            platform::socket_activation_env_name(|name| match name {
                "LISTEN_FDNAMES" => Some(OsString::from("http:https")),
                _ => None,
            }),
            Some("LISTEN_FDNAMES")
        );
        assert_eq!(
            platform::socket_activation_env_name(|_| Some(OsString::new())),
            None
        );
        assert_eq!(platform::socket_activation_env_name(|_| None), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn edge_cli_rejects_public_only_flags_on_loopback_bind() {
        // D4: public-mode / public-identity / trusted-proxy-cidr are only honored on a
        // non-loopback bind. On a loopback bind they were silently discarded (identity
        // stayed DirectPublic, no fairness/SAN enforcement), so an operator who typed
        // `--public-identity trusted-proxy` got DirectPublic with no error. Fail closed.
        let err = platform::run_from_args([
            "edge",
            "--worker-socket",
            "/tmp/oxo-test-worker.sock",
            "--http-bind",
            "127.0.0.1:0",
            "--public-identity",
            "trusted-proxy",
            "--trusted-proxy-cidr",
            "10.0.0.0/8",
            "--check-config",
        ])
        .expect_err("public-identity on a loopback bind must fail closed, not be silently ignored");
        let text = err.to_string();
        assert!(text.contains("OXO_EDGE_PUBLIC_MODE"), "{text}");
        assert!(text.contains("loopback"), "{text}");

        // --public-mode on a loopback bind is likewise refused.
        let err = platform::run_from_args([
            "edge",
            "--worker-socket",
            "/tmp/oxo-test-worker.sock",
            "--http-bind",
            "127.0.0.1:0",
            "--public-mode",
            "smoke-beta",
            "--check-config",
        ])
        .expect_err("public-mode on a loopback bind must fail closed");
        assert!(err.to_string().contains("loopback"), "{err}");

        // the production-ACME consent flag is equally inert on a loopback
        // bind (production HTTP-01 can never validate a loopback host).
        let err = platform::run_from_args([
            "edge",
            "--worker-socket",
            "/tmp/oxo-test-worker.sock",
            "--http-bind",
            "127.0.0.1:0",
            "--acme-allow-production-directory",
            "--check-config",
        ])
        .expect_err("production-ACME consent on a loopback bind must fail closed");
        let text = err.to_string();
        assert!(
            text.contains("OXO_EDGE_ACME_ALLOW_PRODUCTION_DIRECTORY"),
            "{text}"
        );
        assert!(text.contains("loopback"), "{text}");

        // Control: fairness/long-lived caps are intentionally NOT in the fail-closed set
        // (they work on loopback). Setting them must pass the public-mode gate and reach
        // later validation — here the worker-socket runtime-dir check — rather than being
        // rejected as a public-only-flag contradiction.
        let err = platform::run_from_args([
            "edge",
            "--worker-socket",
            "/tmp/oxo-test-worker.sock",
            "--http-bind",
            "127.0.0.1:0",
            "--max-in-flight-per-identity",
            "8",
            "--long-lived-max-connections",
            "16",
            "--check-config",
        ])
        .expect_err("this config reaches worker-socket validation (/tmp is not 0700 in CI)");
        let text = err.to_string();
        assert!(
            !text.contains("OXO_EDGE_PUBLIC_MODE"),
            "fairness/long-lived on loopback must NOT trip the public-mode gate: {text}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn edge_cli_zero_identity_fairness_reports_cli_flag() {
        let err = platform::run_from_args([
            "edge",
            "--worker-socket",
            "/tmp/oxo-test-worker.sock",
            "--http-bind",
            "127.0.0.1:0",
            "--max-in-flight-per-identity",
            "0",
            "--check-config",
        ])
        .expect_err("zero per-identity fairness cap must fail closed");
        let text = err.to_string();
        assert!(text.contains("--max-in-flight-per-identity"), "{text}");
        assert!(
            !text.contains("OXO_EDGE_MAX_IN_FLIGHT_PER_IDENTITY"),
            "{text}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn edge_cli_zero_long_lived_config_reports_cli_flag() {
        let err = platform::run_from_args([
            "edge",
            "--worker-socket",
            "/tmp/oxo-test-worker.sock",
            "--http-bind",
            "127.0.0.1:0",
            "--long-lived-max-connections",
            "0",
            "--check-config",
        ])
        .expect_err("zero long-lived connection cap must fail closed");
        let text = err.to_string();
        assert!(text.contains("--long-lived-max-connections"), "{text}");
        assert!(
            !text.contains("OXO_EDGE_LONG_LIVED_MAX_CONNECTIONS"),
            "{text}"
        );
    }

    #[test]
    fn strips_spoofable_and_connection_token_headers() {
        let headers = vec![
            ("Host", "example.test"),
            ("Forwarded", "for=198.51.100.1"),
            ("X-Forwarded-For", "198.51.100.1"),
            ("X-Real-IP", "198.51.100.1"),
            // The Client-IP / CDN client-IP family: Rails RemoteIp default-trusts CLIENT_IP,
            // so any of these reaching the worker would spoof request.remote_ip.
            ("Client-IP", "198.51.100.1"),
            ("True-Client-IP", "198.51.100.1"),
            ("CF-Connecting-IP", "198.51.100.1"),
            ("X-Client-IP", "198.51.100.1"),
            ("Fastly-Client-IP", "198.51.100.1"),
            ("X-Cluster-Client-IP", "198.51.100.1"),
            ("X-Original-Forwarded-For", "198.51.100.1"),
            ("X-Azure-ClientIP", "198.51.100.1"),
            ("X-Oxo-Remote-Addr", "spoofed"),
            ("Proxy-Authorization", "Basic secret"),
            ("Connection", "keep-alive, X-Delete-Me"),
            ("X-Delete-Me", "client-token"),
            ("Accept", "text/html"),
        ];

        let sanitized = sanitize_worker_request_headers(&headers, &metadata()).unwrap();
        let names = sanitized
            .headers
            .iter()
            .map(|(name, _)| name.to_ascii_lowercase())
            .collect::<Vec<_>>();

        assert!(names.contains(&"host".to_string()));
        assert!(names.contains(&"accept".to_string()));
        assert!(names.contains(&"x-oxo-remote-addr".to_string()));
        assert!(names.contains(&"x-oxo-url-scheme".to_string()));
        assert!(names.contains(&"x-oxo-server-name".to_string()));
        assert!(names.contains(&"x-oxo-server-port".to_string()));
        assert!(names.contains(&"x-oxo-request-id".to_string()));
        assert!(sanitized
            .headers
            .iter()
            .any(|(name, value)| name == "connection" && value == "close"));
        assert!(!names.contains(&"forwarded".to_string()));
        assert!(!names.contains(&"x-forwarded-for".to_string()));
        assert!(!names.contains(&"x-real-ip".to_string()));
        assert!(!names.contains(&"proxy-authorization".to_string()));
        assert!(!names.contains(&"x-delete-me".to_string()));
        // No Client-IP / CDN client-IP header survives to the worker.
        for spoof in [
            "client-ip",
            "true-client-ip",
            "cf-connecting-ip",
            "x-client-ip",
            "fastly-client-ip",
            "x-cluster-client-ip",
            "x-original-forwarded-for",
            "x-azure-clientip",
        ] {
            assert!(
                !names.contains(&spoof.to_string()),
                "{spoof} must be stripped"
            );
        }
    }

    #[test]
    fn trusted_proxy_rejects_client_injected_cdn_ip_header() {
        // A trusted upstream presents only canonical X-Forwarded-For; a second forwarding /
        // client-IP channel (here CF-Connecting-IP) is a spoof/misconfig → fail closed.
        let policy = TrustedProxyPolicy::parse_all(&["10.0.0.0/8".to_string()]).unwrap();
        let err = policy
            .resolve_remote_addr(
                "10.1.2.3",
                &[
                    ("x-forwarded-for", "203.0.113.7"),
                    ("cf-connecting-ip", "203.0.113.9"),
                ],
            )
            .unwrap_err();
        assert_eq!(err, IdentityRejection::AmbiguousForwardingHeader);

        // A lone canonical X-Forwarded-For from the trusted peer still resolves.
        let ip = policy
            .resolve_remote_addr("10.1.2.3", &[("x-forwarded-for", "203.0.113.7")])
            .unwrap();
        assert_eq!(ip, "203.0.113.7");
    }

    #[test]
    fn rejects_unsupported_protocol_requests() {
        for headers in [
            vec![("Connection", "Upgrade")],
            vec![("Sec-WebSocket-Key", "abc")],
            vec![("Sec-WebSocket-Protocol", "actioncable-v1-json")],
        ] {
            assert_eq!(
                sanitize_worker_request_headers(&headers, &metadata()).unwrap_err(),
                RequestRejection::UpgradeUnsupported
            );
        }
        for content_type in [
            "application/grpc+proto",
            "Application/Grpc; charset=utf-8",
            "application/grpc-web+proto",
        ] {
            assert_eq!(
                sanitize_worker_request_headers(&[("Content-Type", content_type)], &metadata())
                    .unwrap_err(),
                RequestRejection::GrpcUnsupported
            );
        }
        assert!(sanitize_worker_request_headers(
            &[("Content-Type", "application/grpcish")],
            &metadata()
        )
        .is_ok());
        for headers in [
            vec![("Accept", "text/event-stream")],
            vec![("Accept", "text/html, text/event-stream; q=0.9")],
            vec![("Last-Event-ID", "42")],
        ] {
            assert_eq!(
                sanitize_worker_request_headers(&headers, &metadata()).unwrap_err(),
                RequestRejection::StreamingUnsupported
            );
        }
    }

    #[test]
    fn sse_protocol_support_allows_event_stream_headers() {
        let headers = [
            ("Accept", "text/html, text/event-stream; q=0.9"),
            ("Last-Event-ID", "42"),
        ];
        let sanitized = sanitize_worker_request_headers_with_protocols(
            &headers,
            &metadata(),
            ProtocolSupport { sse: true },
        )
        .unwrap();
        let pairs = sanitized
            .headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.as_str()))
            .collect::<Vec<_>>();

        assert!(pairs.contains(&("accept".to_string(), "text/html, text/event-stream; q=0.9")));
        assert!(pairs.contains(&("last-event-id".to_string(), "42")));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "x-oxo-request-id" && *value == "edge-generated"));
    }

    #[test]
    fn rejects_public_bind_variants_before_platform_checks() {
        let binds = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 8080),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8080),
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                8080,
            ),
        ];
        for bind in binds {
            let err = EdgeConfig::new(
                bind,
                absolute_test_path("worker.sock"),
                DEFAULT_MAX_BODY_BYTES,
            )
            .unwrap_err();
            assert_eq!(err, EdgeError::NonLoopbackBind { bind });
        }
    }

    fn absolute_test_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(name)
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_stub_is_unsupported() {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let err = EdgeConfig::new(
            bind,
            absolute_test_path("worker.sock"),
            DEFAULT_MAX_BODY_BYTES,
        )
        .unwrap_err();
        assert_eq!(err, EdgeError::UnsupportedPlatform);
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;
        use std::time::{SystemTime, UNIX_EPOCH};

        fn unique_dir(label: &str) -> PathBuf {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            std::env::temp_dir().join(format!(
                "oxo-pingora-edge-{label}-{}-{nonce}",
                std::process::id()
            ))
        }

        fn localhost() -> SocketAddr {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
        }

        #[test]
        fn requires_absolute_worker_socket_path() {
            let err = EdgeConfig::new(
                localhost(),
                PathBuf::from("worker.sock"),
                DEFAULT_MAX_BODY_BYTES,
            )
            .unwrap_err();
            assert_eq!(
                err,
                EdgeError::WorkerSocketMustBeAbsolute {
                    path: PathBuf::from("worker.sock")
                }
            );
        }

        #[test]
        fn validates_private_runtime_dir() {
            let dir = unique_dir("private-dir");
            fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            let socket = dir.join("worker.sock");

            let config = EdgeConfig::new(localhost(), &socket, DEFAULT_MAX_BODY_BYTES).unwrap();
            assert_eq!(config.worker_socket, socket);

            fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn rejects_world_accessible_runtime_dir() {
            let dir = unique_dir("open-dir");
            fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
            let socket = dir.join("worker.sock");

            let err = EdgeConfig::new(localhost(), &socket, DEFAULT_MAX_BODY_BYTES).unwrap_err();
            assert_eq!(
                err,
                EdgeError::RuntimeDirMode {
                    path: dir.clone(),
                    mode: 0o755
                }
            );

            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn validates_existing_socket_permissions() {
            let dir = unique_dir("socket-mode");
            fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            let socket = dir.join("worker.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();

            let err = EdgeConfig::new(localhost(), &socket, DEFAULT_MAX_BODY_BYTES).unwrap_err();
            assert_eq!(
                err,
                EdgeError::WorkerSocketMode {
                    path: socket.clone(),
                    mode: 0o666
                }
            );

            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
            EdgeConfig::new(localhost(), &socket, DEFAULT_MAX_BODY_BYTES).unwrap();

            drop(listener);
            fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn rejects_existing_non_socket() {
            let dir = unique_dir("not-socket");
            fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            let socket = dir.join("worker.sock");
            fs::write(&socket, b"not a socket").unwrap();

            let err = EdgeConfig::new(localhost(), &socket, DEFAULT_MAX_BODY_BYTES).unwrap_err();
            assert_eq!(
                err,
                EdgeError::WorkerSocketNotSocket {
                    path: socket.clone()
                }
            );

            fs::remove_dir_all(&dir).unwrap();
        }
    }
}

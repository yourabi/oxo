use super::*;

/// per-request stderr log posture. The hot-path `response` line cost a write
/// syscall + stderr lock + allocs per request (~the whole observable /bench cost of
/// logging); the rejection-class lines are the hardened front door's only per-request
/// forensic record. Default `Rejections` keeps forensics and drops only the hot-path
/// line — a blanket off would silence attack evidence for zero extra bench win.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RequestLogMode {
    Off,
    Rejections,
    All,
}

impl RequestLogMode {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            RequestLogMode::Off => "off",
            RequestLogMode::Rejections => "rejections",
            RequestLogMode::All => "all",
        }
    }

    fn logs_responses(self) -> bool {
        self == RequestLogMode::All
    }

    fn logs_rejections(self) -> bool {
        self != RequestLogMode::Off
    }
}

pub(super) struct EdgeTelemetry {
    worker_count: usize,
    /// effective Pingora proxy-service worker-thread count, queryable on /ready
    /// so the edge's real parallelism is not stderr-only.
    edge_threads: usize,
    /// parallel accept tasks per listening fd (also on /ready — never stderr-only).
    listener_tasks: usize,
    /// resolved request-log posture (also on /ready — never stderr-only).
    request_log: RequestLogMode,
    /// resolved edge↔worker hop wire format (also on /ready).
    worker_hop: WorkerHop,
    public_mode: Option<PublicMode>,
    started_at: Instant,
    in_flight: AtomicU64,
    requests_total: AtomicU64,
    responses_total: AtomicU64,
    rejections_total: AtomicU64,
    status_2xx_total: AtomicU64,
    status_4xx_total: AtomicU64,
    status_5xx_total: AtomicU64,
    status_other_total: AtomicU64,
    last_response_status: AtomicU64,
    last_rejection_status: AtomicU64,
    rate_limited_total: AtomicU64,
    // W2: the u64 sequence of the last request, 0 = none yet (the producer starts its
    // sequence at 1). Replaces a Mutex<Option<String>> that took a process-global lock and
    // cloned the id String on EVERY request to serve one admin field; the admin reader
    // reconstructs `oxo-{pid}-{seq}` from platform::cached_pid(), byte-identically.
    last_request_seq: AtomicU64,
    fairness: Arc<IdentityFairnessLimiter>,
    global_in_flight: Arc<GlobalInFlightLimiter>,
    slow_client: SlowClientPolicy,
    long_lived: Arc<LongLivedRegistry>,
    certificate_admin_json: Option<String>,
    drain: DrainState,
    /// static-serving counters (crenel). A default all-zero instance when static
    /// serving is not configured, so the /metrics surface is stable either way (the
    /// manifest freeze test compares exact lines).
    static_counters: Arc<crenel_pingora::Counters>,
    /// resolved serve-rails preset posture — queryable on /ready so the composite
    /// flag's outcome (incl. static soft-disable) is not stderr-only (panel P5b).
    serve_rails: ServeRailsPosture,
    /// (lever 2): true iff production static-routing is active (boot-pinned docroots).
    /// Queryable on /ready so an operator can confirm the edge is skipping the per-request
    /// filesystem probe on dynamic routes rather than live-probing (dev). False = dev.
    routing_pinned: bool,
}

pub(super) struct RequestObservation<'a> {
    telemetry: &'a EdgeTelemetry,
}

impl Drop for RequestObservation<'_> {
    fn drop(&mut self) {
        self.telemetry.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl EdgeTelemetry {
    // One constructor, one call site (run_edge); a params struct would just duplicate
    // the field list.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        worker_count: usize,
        edge_threads: usize,
        listener_tasks: usize,
        request_log: RequestLogMode,
        worker_hop: WorkerHop,
        public_mode: Option<PublicMode>,
        fairness: Arc<IdentityFairnessLimiter>,
        global_in_flight: Arc<GlobalInFlightLimiter>,
        slow_client: SlowClientPolicy,
        long_lived: Arc<LongLivedRegistry>,
        certificate_admin_json: Option<String>,
        drain: DrainState,
        static_counters: Arc<crenel_pingora::Counters>,
        serve_rails: ServeRailsPosture,
        routing_pinned: bool,
    ) -> Self {
        Self {
            worker_count,
            edge_threads,
            listener_tasks,
            request_log,
            worker_hop,
            public_mode,
            started_at: Instant::now(),
            in_flight: AtomicU64::new(0),
            requests_total: AtomicU64::new(0),
            responses_total: AtomicU64::new(0),
            rejections_total: AtomicU64::new(0),
            status_2xx_total: AtomicU64::new(0),
            status_4xx_total: AtomicU64::new(0),
            status_5xx_total: AtomicU64::new(0),
            status_other_total: AtomicU64::new(0),
            last_response_status: AtomicU64::new(0),
            last_rejection_status: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
            last_request_seq: AtomicU64::new(0),
            fairness,
            global_in_flight,
            slow_client,
            long_lived,
            certificate_admin_json,
            drain,
            static_counters,
            serve_rails,
            routing_pinned,
        }
    }

    pub(super) fn start_request(&self, request_sequence: u64) -> RequestObservation<'_> {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        self.last_request_seq
            .store(request_sequence, Ordering::Relaxed);
        RequestObservation { telemetry: self }
    }

    pub(super) fn record_response(&self, request_id: &str, status: u16) {
        self.responses_total.fetch_add(1, Ordering::Relaxed);
        self.last_response_status
            .store(u64::from(status), Ordering::Relaxed);
        self.record_status_class(status);
        // the hot-path line is emitted only under --request-log all; counters and
        // /ready fields above are unconditional.
        if self.request_log.logs_responses() {
            self.log_request_outcome(request_id, "response", status);
        }
    }

    pub(super) fn record_rejection(&self, request_id: &str, status: u16) {
        self.rejections_total.fetch_add(1, Ordering::Relaxed);
        self.last_rejection_status
            .store(u64::from(status), Ordering::Relaxed);
        self.record_status_class(status);
        if self.request_log.logs_rejections() {
            self.log_request_outcome(request_id, "rejection", status);
        }
    }

    pub(super) fn record_rate_limited(&self, request_id: &str) {
        self.rate_limited_total.fetch_add(1, Ordering::Relaxed);
        self.rejections_total.fetch_add(1, Ordering::Relaxed);
        self.last_rejection_status.store(503, Ordering::Relaxed);
        self.record_status_class(503);
        if self.request_log.logs_rejections() {
            self.log_request_outcome(request_id, "rate_limited", 503);
        }
    }

    pub(super) fn record_overloaded(&self, request_id: &str) {
        self.rejections_total.fetch_add(1, Ordering::Relaxed);
        self.last_rejection_status.store(503, Ordering::Relaxed);
        self.record_status_class(503);
        if self.request_log.logs_rejections() {
            self.log_request_outcome(request_id, "overloaded", 503);
        }
    }

    fn record_status_class(&self, status: u16) {
        match status {
            200..=299 => self.status_2xx_total.fetch_add(1, Ordering::Relaxed),
            400..=499 => self.status_4xx_total.fetch_add(1, Ordering::Relaxed),
            500..=599 => self.status_5xx_total.fetch_add(1, Ordering::Relaxed),
            _ => self.status_other_total.fetch_add(1, Ordering::Relaxed),
        };
    }

    fn log_request_outcome(&self, request_id: &str, outcome: &str, status: u16) {
        eprintln!(
            "{{\"event\":\"oxo_edge_request\",\"request_id\":\"{}\",\"outcome\":\"{}\",\"status\":{},\"public_mode\":\"{}\"}}",
            json_escape(request_id),
            outcome,
            status,
            self.public_mode.map(PublicMode::as_str).unwrap_or("loopback")
        );
    }

    fn ready(&self) -> bool {
        self.worker_count > 0 && !self.drain.is_draining()
    }

    fn ready_json(&self) -> String {
        let fairness = self.fairness.snapshot();
        let global = self.global_in_flight.snapshot();
        let long_lived = self.long_lived.snapshot();
        format!(
            r#"{{"live":true,"ready":{},"draining":{},"generation":1,"worker_count":{},"edge_threads":{},"listener_tasks":{},"request_log":"{}","worker_hop":"{}","worker_dispatch":"{}","public_mode":"{}","operator_schema":"v86","uptime_seconds":{},"in_flight":{},"requests_total":{},"responses_total":{},"rejections_total":{},"rate_limited_total":{},"overload_total":{},"global_in_flight_enabled":{},"global_in_flight_max_requests":{},"global_in_flight_active":{},"global_in_flight_admitted_total":{},"global_in_flight_max_active_observed":{},"slow_client_header_read_timeout_ms":{},"slow_client_header_read_timeout_enforced":{},"slow_client_keepalive_idle_timeout_ms":{},"slow_client_keepalive_idle_timeout_enforced":{},"slow_client_max_connection_secs":{},"slow_client_max_connection_secs_enforced":{},"slow_client_pingora_tls_handshake_timeout_secs":{},"serve_rails_active":{},"serve_rails_static":"{}","routing_pinned":{},"status_2xx_total":{},"status_4xx_total":{},"status_5xx_total":{},"status_other_total":{},"fairness_enabled":{},"fairness_max_in_flight_per_identity":{},"fairness_in_flight":{},"fairness_tracked_identities":{},"fairness_admitted_total":{},"fairness_saturation_total":{},"long_lived_active":{},"long_lived_max_connections":{},"long_lived_max_buffered_bytes":{},"long_lived_downstream_write_timeout_ms":{},"long_lived_max_active_observed":{},"long_lived_accepted_total":{},"long_lived_completed_total":{},"long_lived_drained_total":{},"long_lived_cancelled_total":{},"long_lived_rejected_total":{},"long_lived_downstream_timeout_total":{},"long_lived_bytes_streamed_total":{},"last_request_id":{},"last_response_status":{},"last_rejection_status":{},"worker_cap":{},"parked":{},"park_total":{},"sticky_hit_total":{},"sticky_miss_total":{},"sticky_fallback_total":{},"sticky_evict_total":{},"sticky_entries":{},"sticky_pins":{}{}}}"#,
            self.ready(),
            self.drain.is_draining(),
            self.worker_count,
            self.edge_threads,
            self.listener_tasks,
            self.request_log.as_str(),
            self.worker_hop.as_str(),
            super::frame_hop::dispatch::mode_name(super::frame_hop::dispatch::mode()),
            self.public_mode
                .map(PublicMode::as_str)
                .unwrap_or("loopback"),
            self.started_at.elapsed().as_secs(),
            self.in_flight.load(Ordering::Relaxed),
            self.requests_total.load(Ordering::Relaxed),
            self.responses_total.load(Ordering::Relaxed),
            self.rejections_total.load(Ordering::Relaxed),
            self.rate_limited_total.load(Ordering::Relaxed),
            global.overload_total,
            global.enabled,
            option_u64_json(global.max_requests),
            global.active,
            global.admitted_total,
            global.max_active_observed,
            self.slow_client.header_read_timeout_ms,
            // honesty: header-read timeout has no pingora 0.8.1 enforcement seam (always
            // false); the keepalive idle timeout is enforced iff keepalive reuse is on (under
            // one-shot the connection closes after one request, so the gap bound never
            // applies); max-connection-secs is likewise framework-unreachable (always false).
            false,
            self.slow_client.keepalive_idle_timeout_ms,
            self.slow_client.keepalive_enabled,
            option_u64_json(self.slow_client.max_connection_secs),
            false,
            self.slow_client.pingora_tls_handshake_timeout_secs,
            // posture: active + the resolved static docroot ("off" when the preset
            // is inactive or static serving soft-disabled). Path is json-escaped.
            self.serve_rails.active,
            json_escape(&self.serve_rails.static_descriptor),
            // posture: production static-routing active (boot-pinned) vs dev live-probe.
            self.routing_pinned,
            self.status_2xx_total.load(Ordering::Relaxed),
            self.status_4xx_total.load(Ordering::Relaxed),
            self.status_5xx_total.load(Ordering::Relaxed),
            self.status_other_total.load(Ordering::Relaxed),
            fairness.enabled,
            option_u64_json(fairness.max_per_identity),
            fairness.active_in_flight,
            fairness.tracked_identities,
            fairness.admitted_total,
            fairness.saturation_total,
            long_lived.active,
            long_lived.max_connections,
            long_lived.max_buffered_bytes,
            long_lived.downstream_write_timeout_ms,
            long_lived.max_active_observed,
            long_lived.accepted_total,
            long_lived.completed_total,
            long_lived.drained_total,
            long_lived.cancelled_total,
            long_lived.rejected_total,
            long_lived.downstream_timeout_total,
            long_lived.bytes_streamed_total,
            self.last_request_id_json(),
            status_json(self.last_response_status.load(Ordering::Relaxed)),
            status_json(self.last_rejection_status.load(Ordering::Relaxed)),
            // the per-worker admission cap and its park counters. NOTE the
            // documented meaning shift: when the cap is on, parked requests still hold
            // their global admission slot, so global_in_flight_active reads
            // "admitted, including parked".
            match super::frame_hop::dispatch::cap() {
                Some(k) => k.to_string(),
                None => "null".to_string(),
            },
            super::frame_hop::dispatch::PARKED.load(Ordering::Relaxed),
            super::frame_hop::dispatch::PARK_TOTAL.load(Ordering::Relaxed),
            // sticky-dispatch engagement receipts (P2/P3/P6). All zeros unless
            // worker_dispatch is "sticky"; sticky_pins is the realized per-worker
            // assignment vector the scored cells assert on.
            super::frame_hop::dispatch::STICKY_HIT_TOTAL.load(Ordering::Relaxed),
            super::frame_hop::dispatch::STICKY_MISS_TOTAL.load(Ordering::Relaxed),
            super::frame_hop::dispatch::STICKY_FALLBACK_TOTAL.load(Ordering::Relaxed),
            super::frame_hop::dispatch::STICKY_EVICT_TOTAL.load(Ordering::Relaxed),
            super::frame_hop::dispatch::sticky_entries(),
            super::frame_hop::dispatch::sticky_pins_json(self.worker_count),
            self.certificate_admin_json.as_deref().unwrap_or(""),
        )
    }

    fn last_request_id_json(&self) -> String {
        // Reconstructed from the stored sequence — `oxo-{pid}-{seq}` is digits and
        // hyphens, so no JSON escaping is needed; byte-identical to the string the
        // producer emitted (the producer-uniqueness contract on next_request_id).
        match self.last_request_seq.load(Ordering::Relaxed) {
            0 => "null".to_string(),
            seq => format!("\"oxo-{}-{seq}\"", super::cached_pid()),
        }
    }

    fn metrics_text(&self) -> String {
        let fairness = self.fairness.snapshot();
        let global = self.global_in_flight.snapshot();
        let long_lived = self.long_lived.snapshot();
        format!(
            "# TYPE oxo_edge_in_flight gauge
oxo_edge_in_flight {}
# TYPE oxo_edge_draining gauge
oxo_edge_draining {}
# TYPE oxo_edge_requests_total counter
oxo_edge_requests_total {}
# TYPE oxo_edge_responses_total counter
oxo_edge_responses_total {}
# TYPE oxo_edge_rejections_total counter
oxo_edge_rejections_total {}
# TYPE oxo_edge_rate_limited_total counter
oxo_edge_rate_limited_total {}
# TYPE oxo_edge_overload_total counter
oxo_edge_overload_total {}
# TYPE oxo_edge_global_in_flight_active gauge
oxo_edge_global_in_flight_active {}
# TYPE oxo_edge_global_in_flight_max_active_observed gauge
oxo_edge_global_in_flight_max_active_observed {}
# TYPE oxo_edge_global_in_flight_admitted_total counter
oxo_edge_global_in_flight_admitted_total {}
# TYPE oxo_edge_status_2xx_total counter
oxo_edge_status_2xx_total {}
# TYPE oxo_edge_status_4xx_total counter
oxo_edge_status_4xx_total {}
# TYPE oxo_edge_status_5xx_total counter
oxo_edge_status_5xx_total {}
# TYPE oxo_edge_status_other_total counter
oxo_edge_status_other_total {}
# TYPE oxo_edge_fairness_enabled gauge
oxo_edge_fairness_enabled {}
# TYPE oxo_edge_fairness_in_flight gauge
oxo_edge_fairness_in_flight {}
# TYPE oxo_edge_fairness_tracked_identities gauge
oxo_edge_fairness_tracked_identities {}
# TYPE oxo_edge_fairness_admitted_total counter
oxo_edge_fairness_admitted_total {}
# TYPE oxo_edge_fairness_saturation_total counter
oxo_edge_fairness_saturation_total {}
# TYPE oxo_edge_long_lived_active gauge
oxo_edge_long_lived_active {}
# TYPE oxo_edge_long_lived_max_active_observed gauge
oxo_edge_long_lived_max_active_observed {}
# TYPE oxo_edge_long_lived_accepted_total counter
oxo_edge_long_lived_accepted_total {}
# TYPE oxo_edge_long_lived_completed_total counter
oxo_edge_long_lived_completed_total {}
# TYPE oxo_edge_long_lived_drained_total counter
oxo_edge_long_lived_drained_total {}
# TYPE oxo_edge_long_lived_cancelled_total counter
oxo_edge_long_lived_cancelled_total {}
# TYPE oxo_edge_long_lived_rejected_total counter
oxo_edge_long_lived_rejected_total {}
# TYPE oxo_edge_long_lived_downstream_timeout_total counter
oxo_edge_long_lived_downstream_timeout_total {}
# TYPE oxo_edge_long_lived_bytes_streamed_total counter
oxo_edge_long_lived_bytes_streamed_total {}
{}",
            self.in_flight.load(Ordering::Relaxed),
            u8::from(self.drain.is_draining()),
            self.requests_total.load(Ordering::Relaxed),
            self.responses_total.load(Ordering::Relaxed),
            self.rejections_total.load(Ordering::Relaxed),
            self.rate_limited_total.load(Ordering::Relaxed),
            global.overload_total,
            global.active,
            global.max_active_observed,
            global.admitted_total,
            self.status_2xx_total.load(Ordering::Relaxed),
            self.status_4xx_total.load(Ordering::Relaxed),
            self.status_5xx_total.load(Ordering::Relaxed),
            self.status_other_total.load(Ordering::Relaxed),
            u8::from(fairness.enabled),
            fairness.active_in_flight,
            fairness.tracked_identities,
            fairness.admitted_total,
            fairness.saturation_total,
            long_lived.active,
            long_lived.max_active_observed,
            long_lived.accepted_total,
            long_lived.completed_total,
            long_lived.drained_total,
            long_lived.cancelled_total,
            long_lived.rejected_total,
            long_lived.downstream_timeout_total,
            long_lived.bytes_streamed_total,
            self.static_metrics_text(),
        )
    }

    /// static-serving block: crenel counter names re-prefixed into the frozen
    /// oxo_edge_* namespace. Emitted unconditionally (zeros when unconfigured).
    fn static_metrics_text(&self) -> String {
        self.static_counters
            .snapshot()
            .into_iter()
            .map(|(name, value)| {
                let name = name.replace("crenel_", "oxo_edge_static_");
                format!("# TYPE {name} counter\n{name} {value}\n")
            })
            .collect()
    }
}

fn status_json(status: u64) -> String {
    if status == 0 {
        "null".to_string()
    } else {
        status.to_string()
    }
}

fn option_u64_json(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped
}

pub(super) fn spawn_admin_health(
    bind: SocketAddr,
    telemetry: Arc<EdgeTelemetry>,
) -> Result<(), EdgeError> {
    let listener = TcpListener::bind(bind).map_err(|err| EdgeError::ConfigEnv {
        name: "OXO_EDGE_ADMIN_BIND",
        message: format!("failed to bind private admin health endpoint: {err}"),
    })?;
    thread::Builder::new()
        .name("oxo-admin-health".to_string())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => handle_admin_connection(stream, &telemetry),
                    Err(_) => break,
                }
            }
        })
        .map_err(|err| EdgeError::ConfigEnv {
            name: "OXO_EDGE_ADMIN_BIND",
            message: format!("failed to start private admin health endpoint: {err}"),
        })?;
    Ok(())
}

fn handle_admin_connection(mut stream: std::net::TcpStream, telemetry: &EdgeTelemetry) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 1024];
    let read = match stream.read(&mut buf) {
        Ok(0) | Err(_) => return,
        Ok(read) => read,
    };
    let request = String::from_utf8_lossy(&buf[..read]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let (status, content_type, body) = match path {
        "/live" => (
            "200 OK",
            "application/json",
            "{\"live\":true}\n".to_string(),
        ),
        "/ready" => ("200 OK", "application/json", telemetry.ready_json()),
        // B1 (graduation arc): frame-pool health counters in SHIPPED builds (MED-5).
        // Deliberately NOT a /ready field — /ready has a frozen operator schema; this is
        // the runtime read the contract-2 test and the M3 reuse gate (fresh/total ≤ 1%)
        // both depend on. `registered:false` = no frame pool exists (HTTP hop).
        "/pool-health" => (
            "200 OK",
            "application/json",
            super::frame_hop::admin_pool_health_json(),
        ),
        "/metrics" => (
            "200 OK",
            "text/plain; version=0.0.4",
            telemetry.metrics_text(),
        ),
        // M-A Tier-1 mechanism gate (bench-only feature): the running allocation-event
        // total, read amortized across a known request count by the mechanism-count tests.
        // Deliberately NOT a /ready field — /ready has a frozen operator schema and this
        // counter exists only in instrumented builds.
        #[cfg(feature = "alloc-count")]
        "/alloc-count" => (
            "200 OK",
            "application/json",
            format!(
                "{{\"alloc_events_total\":{}}}\n",
                crate::alloc_count::ALLOCATION_EVENTS_TOTAL.load(Ordering::Relaxed)
            ),
        ),
        // M-C (bench-only feature): per-seam wall-clock of the worker hop {checkout,
        // request-write, response-read, checkin}. Same rationale as /alloc-count — NOT a
        // /ready field (frozen operator schema); exists only in `--features hop-timing` builds
        // and reports zeros unless armed with OXO_HOP_TIMING=1.
        #[cfg(feature = "hop-timing")]
        "/hop-timing" => ("200 OK", "application/json", hop_timing_admin_json()),
        _ => (
            "404 Not Found",
            "application/json",
            "{\"error\":\"not_found\"}\n".to_string(),
        ),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

/// The `/hop-timing` admin body: the seam report with the dispatch-telemetry section
/// spliced in by reopening the ROOT object — strip exactly ONE trailing '}'.
///
/// the splice used `trim_end_matches('}')`, which stripped the ENTIRE trailing
/// brace run (the last seam's bucket + seam closes and the seams-map close, not just the
/// root), so every armed /hop-timing response since was complete-looking but
/// unparseable — three braces short. Nothing noticed for 13 versions because no
/// automated consumer parsed the JSON; the validated reader (hop_timing_read in
/// guest-capture-lib.sh) caught it as "TRUNCATED, curl rc=0, stable size" — a malformed
/// body, not a transport race. Archived files repair by inserting "}}}" before
/// `,"dispatch"`.
#[cfg(feature = "hop-timing")]
fn hop_timing_admin_json() -> String {
    let seams = crate::hop_timing::report_json();
    let trimmed = seams.trim_end();
    let base = trimmed.strip_suffix('}').unwrap_or(trimmed);
    format!(
        "{base},\"dispatch\":{}}}\n",
        frame_hop::dispatch::report_json()
    )
}

#[cfg(all(test, feature = "hop-timing"))]
mod hop_timing_admin_tests {
    #[test]
    fn spliced_hop_timing_body_is_balanced_json() {
        // Neither report emits braces inside string values, so brace balance is a sound
        // well-formedness proxy without pulling serde_json into this feature set.
        let body = super::hop_timing_admin_json();
        let opens = body.matches('{').count();
        let closes = body.matches('}').count();
        assert_eq!(
            opens,
            closes,
            "hop-timing admin body is {} closing brace(s) short — the splice bug: {body}",
            opens.saturating_sub(closes)
        );
        assert!(
            body.trim_end().ends_with('}'),
            "body must close its root object: {body}"
        );
    }
}

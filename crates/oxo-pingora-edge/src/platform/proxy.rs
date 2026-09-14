use super::*;

/// the edge↔worker hop wire format. `Frame` is the pooled binary pre-parsed hop
/// (default); `Http` is the one-shot HTTP/1.1 text hop, kept for A/B benching and
/// as a compat fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkerHop {
    Frame,
    Http,
}

impl WorkerHop {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            WorkerHop::Frame => "frame",
            WorkerHop::Http => "http",
        }
    }
}

pub(super) struct RunEdgeOptions {
    pub(super) server_name: String,
    pub(super) url_scheme: String,
    pub(super) listener: ListenerMode,
    pub(super) public_mode: Option<PublicMode>,
    pub(super) public_identity: crate::PublicIdentityPolicy,
    pub(super) fairness: Arc<IdentityFairnessLimiter>,
    pub(super) global_in_flight: Arc<GlobalInFlightLimiter>,
    pub(super) slow_client: SlowClientPolicy,
    pub(super) long_lived: Arc<LongLivedRegistry>,
    pub(super) admin_bind: Option<SocketAddr>,
    pub(super) action_cable_bind: Option<SocketAddr>,
    pub(super) grpc_bind: Option<SocketAddr>,
    pub(super) public_origin_port: Option<u16>,
    pub(super) certificate_admin_json: Option<String>,
    pub(super) drain_config: EdgeDrainConfig,
    /// resolved Pingora proxy-service worker-thread count (`ServerConf.threads`;
    /// pingora defaults it to 1, which single-threaded the edge — the ceiling).
    pub(super) edge_threads: usize,
    /// parallel accept tasks per listening fd (`ServerConf.listener_tasks_per_fd`;
    /// pingora defaults to 1 — a single accept task serializes accepts under churn).
    pub(super) listener_tasks: usize,
    /// resolved per-request stderr log posture (default Rejections).
    pub(super) request_log: RequestLogMode,
    /// resolved edge↔worker hop wire format (default Frame).
    pub(super) worker_hop: WorkerHop,
    pub(super) static_mounts: Vec<crenel_pingora::MountSpec>,
    /// the idle-pool ceiling and its source, resolved once in run_with_cli
    /// (beside the descriptor budget) and threaded here so the pool never reads env.
    pub(super) frame_pool_idle: (usize, super::frame_pool::IdleCeilingSource),
    /// checkout's unwrap wait budget, resolved once in run_with_cli.
    pub(super) unwrap_wait_budget: Duration,
    /// (lever 2): production static-routing. When true the static docroots are
    /// enumerated once at boot into a first-path-segment pin set, and a request whose
    /// first path segment is not pinned skips `static_server.serve()` (and its two
    /// filesystem probe syscalls) entirely. False = dev live-probe every request.
    pub(super) prod_enabled: bool,
    pub(super) h2_policy: H2Policy,
    /// resolved serve-rails preset posture for /ready (panel P5b).
    pub(super) serve_rails: ServeRailsPosture,
}

/// (lever 2): the first path segment of a request path or a mount prefix, used as the
/// prod static-routing pin key. Strips the leading `/`, returns up to (not including) the
/// next `/`. `"/bench"` → `"bench"`, `"/assets/app.js"` → `"assets"`, `"/"`/`""` → `""`.
/// Segment-boundary exact by construction, so a request for `/assetsfoo` yields
/// `"assetsfoo"` and can never match a pinned `"assets"`.
pub(super) fn first_path_segment(path: &str) -> &str {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    match trimmed.find('/') {
        Some(idx) => &trimmed[..idx],
        None => trimmed,
    }
}

/// (lever 2): the prod static-routing gate decision. `None` pin = dev (always a
/// candidate → probe every GET/HEAD, preserving static hot-reload). `Some(pin)` = prod: a
/// path is a candidate iff its first segment is pinned. A percent-encoded first segment
/// could decode to a pinned name, so it is treated as a candidate (probe conservatively)
/// rather than risk skipping a legitimately static file — the win is on plain dynamic
/// routes like `/bench`, which is exactly the hot path this cheaply rules out.
pub(super) fn is_static_candidate(
    prod_pin: Option<&std::collections::HashSet<String>>,
    path: &str,
) -> bool {
    match prod_pin {
        None => true,
        Some(pin) => {
            let seg = first_path_segment(path);
            seg.contains('%') || pin.contains(seg)
        }
    }
}

/// (lever 2): enumerate the static docroots ONCE at boot into the set of first path
/// segments that could resolve to a static file. For each mount: a non-root prefix (e.g.
/// `/assets`) pins its own first segment (`"assets"`) — the prefix alone decides
/// candidacy, no docroot walk needed; a root/fallthrough prefix (`/`) pins the empty
/// segment (the bare-root index) plus every top-level entry name under its docroot
/// (`favicon.ico`, `robots.txt`, `assets`, `packs`, …). At request time a path whose first
/// segment is absent from this set is definitely dynamic and skips `serve()`. Bounded: a
/// docroot with more than `MAX_PINNED_ENTRIES` top-level entries fails boot LOUD — prod
/// pinning is for the small Rails `public/` tree; a huge docroot should stay in dev
/// (fail-closed, never a silent fallback that would quietly re-probe every request).
pub(super) fn build_prod_pin_set(
    mounts: &[crenel_pingora::MountSpec],
) -> Result<std::collections::HashSet<String>, EdgeError> {
    const MAX_PINNED_ENTRIES: usize = 65_536;
    let mut pin = std::collections::HashSet::new();
    for mount in mounts {
        let seg = first_path_segment(&mount.prefix);
        if !seg.is_empty() {
            pin.insert(seg.to_string());
            continue;
        }
        // Root/fallthrough mount: the bare-root index plus each top-level docroot entry.
        pin.insert(String::new());
        let entries = std::fs::read_dir(&mount.docroot).map_err(|err| EdgeError::ConfigEnv {
            name: "OXO_EDGE_PROD",
            message: format!(
                "cannot enumerate static docroot {} for --prod boot pinning: {err}",
                mount.docroot.display()
            ),
        })?;
        for entry in entries {
            let entry = entry.map_err(|err| EdgeError::ConfigEnv {
                name: "OXO_EDGE_PROD",
                message: format!(
                    "cannot read a static docroot entry under {}: {err}",
                    mount.docroot.display()
                ),
            })?;
            if let Some(name) = entry.file_name().to_str() {
                pin.insert(name.to_string());
            }
            if pin.len() > MAX_PINNED_ENTRIES {
                return Err(EdgeError::ConfigEnv {
                    name: "OXO_EDGE_PROD",
                    message: format!(
                        "static docroot {} has more than {MAX_PINNED_ENTRIES} top-level \
                         entries; --prod boot pinning targets the small Rails public/ tree \
                         — run without --prod (dev live-probe) for a docroot this large",
                        mount.docroot.display()
                    ),
                });
            }
        }
    }
    Ok(pin)
}

pub(super) fn run_edge(edge: crate::EdgeConfig, options: RunEdgeOptions) -> Result<(), EdgeError> {
    let RunEdgeOptions {
        server_name,
        url_scheme,
        listener,
        public_mode,
        public_identity,
        fairness,
        global_in_flight,
        slow_client,
        long_lived,
        admin_bind,
        action_cable_bind,
        grpc_bind,
        public_origin_port,
        certificate_admin_json,
        drain_config,
        edge_threads,
        listener_tasks,
        request_log,
        worker_hop,
        static_mounts,
        prod_enabled,
        h2_policy,
        serve_rails,
        frame_pool_idle,
        unwrap_wait_budget,
    } = options;
    let bind = edge.bind.to_string();
    let drain = DrainState::new();
    // (lever 2): in prod mode, enumerate the static docroots ONCE here — before the
    // mounts are moved into the StaticServer — into a first-path-segment pin set. A `None`
    // pin (dev, or no mounts) keeps the live-probe behavior; `Some(set)` lets the
    // request path gate `serve()` so dynamic routes skip the fs probe. Built from the same
    // MountSpec list the StaticServer resolves, so the two can never disagree on docroots.
    let prod_pin = if prod_enabled && !static_mounts.is_empty() {
        Some(Arc::new(build_prod_pin_set(&static_mounts)?))
    } else {
        None
    };
    // static serving: built fail-closed BEFORE any listener exists (crenel's boot
    // audit rejects Capistrano-hostile symlink layouts with an actionable message).
    let static_server = if static_mounts.is_empty() {
        None
    } else {
        let server = crenel_pingora::StaticServer::new(crenel_pingora::StaticServerConfig {
            mounts: static_mounts,
            limits: crenel_pingora::Limits::default(),
        })
        .map_err(|err| EdgeError::ConfigEnv {
            name: "OXO_EDGE_STATIC_MOUNTS",
            message: err.to_string(),
        })?;
        Some(Arc::new(server))
    };
    let static_counters = static_server
        .as_ref()
        .map(|server| Arc::clone(&server.counters))
        .unwrap_or_default();
    // /: derive the keepalive posture before `slow_client` is passed to telemetry
    // (SlowClientPolicy is Copy, so it remains usable after). The idle seconds are
    // guaranteed >= 1 (never Some(0)/Infinite) by keepalive_idle_secs(). The reuse limit
    // is Some(N-1) only when keepalive is enabled (inert under one-shot).
    let keepalive_enabled = slow_client.keepalive_enabled;
    let keepalive_idle_secs = slow_client.keepalive_idle_secs();
    let keepalive_request_limit = slow_client.keepalive_request_limit;
    let telemetry = Arc::new(EdgeTelemetry::new(
        edge.worker_set.ready_sockets().len(),
        edge_threads,
        listener_tasks,
        request_log,
        worker_hop,
        public_mode,
        Arc::clone(&fairness),
        Arc::clone(&global_in_flight),
        slow_client,
        Arc::clone(&long_lived),
        certificate_admin_json,
        drain.clone(),
        static_counters,
        serve_rails,
        prod_pin.is_some(),
    ));
    if let Some(admin_bind) = admin_bind {
        spawn_admin_health(admin_bind, Arc::clone(&telemetry))?;
    }
    let proxy = EdgeProxy::new(
        edge,
        EdgeProxyOptions {
            server_name,
            url_scheme,
            public_mode,
            public_identity,
            fairness,
            global_in_flight,
            long_lived,
            telemetry,
            public_origin_port,
            action_cable_bind,
            grpc_bind,
            drain: drain.clone(),
            static_server,
            prod_pin,
            keepalive_enabled,
            keepalive_idle_secs,
            worker_hop,
            frame_pool_idle,
            unwrap_wait_budget,
        },
    );
    let conf = pingora::server::configuration::ServerConf {
        grace_period_seconds: Some(drain_config.grace_period_seconds),
        graceful_shutdown_timeout_seconds: Some(drain_config.graceful_shutdown_timeout_seconds),
        // pingora defaults `threads` to 1 per service, which ran the whole edge —
        // TLS, parsing, proxying — on one Tokio worker (the /bench ceiling). The
        // drain background service is unaffected (GenBackgroundService pins threads=1).
        threads: edge_threads,
        // (ROADMAP 1b): parallel accepts per listening fd. Server-wide, read by
        // pingora's run_service for every listener; default 1 preserves prior behavior.
        listener_tasks_per_fd: listener_tasks,
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();
    server.add_service(drain_background_service(drain.clone()));
    let mut service = http_proxy_service(&server.configuration, proxy);
    // cap total requests per kept-alive H1 connection via pingora's
    // keepalive_request_limit (a reuse counter). Only set under keepalive — under
    // one-shot the connection already closes after one request. `HttpServerOptions` is
    // `#[non_exhaustive]`, so build via Default then set the public field.
    if let Some(limit) = keepalive_request_limit {
        if let Some(app) = service.app_logic_mut() {
            let mut options = pingora::apps::HttpServerOptions::default();
            options.keepalive_request_limit = Some(limit);
            app.server_options = Some(options);
        }
    }
    // HTTP/2 resource bounds. Start from default_h2_options (64 KiB header list +
    // 100 concurrent streams) so we retain pingora's bounded defaults, then apply the
    // operator-tunable concurrent-streams and rapid-reset (CVE-2023-44487) caps. Inert
    // unless H2 is negotiated over TLS ALPN. H2 idle/absolute-age are framework-blocked
    // (pingora accept-loop has no idle timeout) — an honest non-claim, not set here.
    if let Some(app) = service.app_logic_mut() {
        let mut h2_options = pingora::protocols::http::v2::server::default_h2_options();
        h2_options.max_concurrent_streams(h2_policy.max_concurrent_streams);
        h2_options.max_pending_accept_reset_streams(h2_policy.max_reset_streams);
        app.h2_options = Some(h2_options);
    }
    match listener {
        ListenerMode::Plain => service.add_tcp(&bind),
        #[cfg(feature = "tls-rustls")]
        ListenerMode::Tls {
            cert_path,
            key_path,
            h2,
        } => {
            let cert_path = cert_path.to_string_lossy().into_owned();
            let key_path = key_path.to_string_lossy().into_owned();
            let mut settings = TlsSettings::intermediate(&cert_path, &key_path).map_err(|err| {
                EdgeError::Pingora {
                    message: err.to_string(),
                }
            })?;
            if h2 {
                settings.enable_h2();
            }
            service.add_tls_with_settings(&bind, None, settings);
        }
    }
    server.add_service(service);
    server.run_forever()
}

#[derive(Clone)]
struct EdgeProxy {
    worker_set: crate::WorkerSet,
    /// the ready-socket path list, materialized ONCE at construction (it was a
    /// fresh Vec<String> per request). Validity rests on WorkerSet being
    /// per-instance-immutable — the proxy receives a snapshot at boot and worker
    /// membership never changes within an EdgeProxy's lifetime. If worker state ever
    /// becomes dynamic (per-worker drain/respawn visible to a live proxy), this must
    /// become a generation-stamped swap rebuilt on ready transitions, with a
    /// kill-and-respawn routing test.
    worker_socket_paths: Arc<[String]>,
    /// W-C: the per-request scratch pool (arena + frame buffer). One checkout at
    /// the top of request_filter; RAII return resets and re-pools (scratch.rs).
    scratch_pool: Arc<super::scratch::ScratchPool>,
    max_body_bytes: u64,
    server_name: String,
    server_port: u16,
    url_scheme: String,
    upstream_generation: Arc<AtomicU64>,
    next_worker: Arc<AtomicUsize>,
    request_sequence: Arc<AtomicU64>,
    public_server_name: Option<String>,
    public_identity: crate::PublicIdentityPolicy,
    fairness: Arc<IdentityFairnessLimiter>,
    global_in_flight: Arc<GlobalInFlightLimiter>,
    long_lived: Arc<LongLivedRegistry>,
    sse_enabled: bool,
    telemetry: Arc<EdgeTelemetry>,
    action_cable_bind: Option<SocketAddr>,
    grpc_bind: Option<SocketAddr>,
    drain: DrainState,
    static_server: Option<Arc<crenel_pingora::StaticServer>>,
    /// (lever 2): production static-routing pin set. `None` = dev (attempt
    /// `static_server.serve()` on every GET/HEAD, the live-probe). `Some(set)` = prod:
    /// the boot-enumerated set of first path segments that could resolve static; a request
    /// whose first path segment is absent skips `serve()` and its two fs probe syscalls.
    /// Read-only after boot (an `Arc` so per-request lookup is a pointer deref + hash).
    prod_pin: Option<Arc<std::collections::HashSet<String>>>,
    // downstream HTTP/1.1 keepalive. When disabled (default) every request
    // forces `set_keepalive(None)` (one-shot). When enabled, the between-request idle
    // read is bounded by `keepalive_idle_secs` (never zero — the ms→s conversion rounds
    // up and floors at 1, so `set_keepalive(Some(_))` is never `Some(0)`/Infinite).
    keepalive_enabled: bool,
    keepalive_idle_secs: u64,
    /// which hop the request path uses.
    worker_hop: WorkerHop,
    /// the pooled UDS connections to the workers, keyed by worker index. Only used
    /// in `WorkerHop::Frame`; `Http` leaves it idle.
    worker_pool: Arc<frame_hop::WorkerFramePool>,
    /// M2 (BENCH-ONLY): resolved ONCE at construction (boot) from the
    /// `OXO_EDGE_NATIVE_BENCH` env — NOT a per-request read. Gates the `/edge-bench`
    /// native-floor stub. Compiled only under the `edge-bench` feature, so this field and
    /// its reader do not exist in the shipped edge binary (compile-time dead code).
    #[cfg(feature = "edge-bench")]
    native_bench_enabled: bool,
    /// M-D (BENCH-ONLY): calibrated per-request CPU injection for the known-effect
    /// ladder — the instrument that measures the timing gate's real MDE by injecting a
    /// KNOWN effect (0.5/1/2/5% of a cell) and recording the detection rate. A busy-spin,
    /// not a sleep: the gated metric is CPU µs/request, and a sleep adds latency without
    /// adding CPU. Resolved ONCE at boot from `OXO_EDGE_INJECT_SPIN_US`; compiled only
    /// under `edge-bench`, so the knob does not exist in shipped binaries.
    #[cfg(feature = "edge-bench")]
    inject_spin_us: Option<u64>,
}

struct EdgeProxyOptions {
    server_name: String,
    url_scheme: String,
    public_mode: Option<PublicMode>,
    public_identity: crate::PublicIdentityPolicy,
    fairness: Arc<IdentityFairnessLimiter>,
    global_in_flight: Arc<GlobalInFlightLimiter>,
    long_lived: Arc<LongLivedRegistry>,
    telemetry: Arc<EdgeTelemetry>,
    public_origin_port: Option<u16>,
    action_cable_bind: Option<SocketAddr>,
    grpc_bind: Option<SocketAddr>,
    drain: DrainState,
    static_server: Option<Arc<crenel_pingora::StaticServer>>,
    prod_pin: Option<Arc<std::collections::HashSet<String>>>,
    keepalive_enabled: bool,
    keepalive_idle_secs: u64,
    worker_hop: WorkerHop,
    frame_pool_idle: (usize, super::frame_pool::IdleCeilingSource),
    unwrap_wait_budget: Duration,
}

impl EdgeProxy {
    fn new(edge: crate::EdgeConfig, options: EdgeProxyOptions) -> Self {
        let EdgeProxyOptions {
            server_name,
            url_scheme,
            public_mode,
            public_identity,
            fairness,
            global_in_flight,
            long_lived,
            telemetry,
            public_origin_port,
            action_cable_bind,
            grpc_bind,
            drain,
            static_server,
            prod_pin,
            keepalive_enabled,
            keepalive_idle_secs,
            worker_hop,
            frame_pool_idle,
            unwrap_wait_budget,
        } = options;
        let public_server_name = public_mode.map(|_| server_name.clone());
        let worker_socket_paths: Arc<[String]> = edge
            .worker_set
            .ready_sockets()
            .into_iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        // one pool for every worker socket. Since the idle ceiling is one
        // AGGREGATE across the whole fleet (oxo's own pool); the default is
        // `frame_pool::default_idle_ceiling(workers)` = max(512, workers x 32),
        // registered in against the measured idle working set, and
        // `OXO_EDGE_FRAME_POOL_IDLE` pins it. Since the value arrives resolved
        // from run_with_cli, which also checked it against the process descriptor
        // limit (fd_budget.rs), so the receipt on /pool-health, the boot notice and the
        // live pool cannot disagree. Downstream concurrency is not known at boot (no
        // global in-flight cap by default), which is why the default is a measured
        // constant with a per-worker floor and not a function of load.
        let worker_pool = Arc::new(frame_hop::WorkerFramePool::from_ceiling(
            frame_pool_idle.0,
            frame_pool_idle.1,
            unwrap_wait_budget,
        ));
        // B1: register the (one-per-process) pool for admin /pool-health reads — the
        // runtime exposure of the shipped reuse counters (contract-2 test + M3 reuse gate).
        frame_hop::register_admin_pool(&worker_pool);
        Self {
            worker_set: edge.worker_set,
            worker_socket_paths,
            max_body_bytes: edge.max_body_bytes,
            server_name,
            server_port: public_origin_port.unwrap_or(edge.bind.port()),
            public_server_name,
            public_identity,
            fairness,
            global_in_flight,
            long_lived,
            url_scheme,
            upstream_generation: Arc::new(AtomicU64::new(1)),
            next_worker: Arc::new(AtomicUsize::new(0)),
            request_sequence: Arc::new(AtomicU64::new(1)),
            sse_enabled: edge.sse_enabled,
            telemetry,
            action_cable_bind,
            grpc_bind,
            drain,
            static_server,
            prod_pin,
            keepalive_enabled,
            keepalive_idle_secs,
            worker_hop,
            worker_pool,
            scratch_pool: Arc::new(super::scratch::ScratchPool::new()),
            // M2 (bench-only): boot-time resolve of the native-floor flag. Read ONCE
            // here, never per request. Inert unless OXO_EDGE_NATIVE_BENCH=1 AND this
            // binary was compiled with `--features edge-bench`.
            #[cfg(feature = "edge-bench")]
            native_bench_enabled: std::env::var("OXO_EDGE_NATIVE_BENCH")
                .map(|v| v.trim() == "1")
                .unwrap_or(false),
            // M-D (bench-only): boot-time resolve of the ladder's injection dose.
            // LOUD when set — a dosed run must never masquerade as a clean run.
            #[cfg(feature = "edge-bench")]
            inject_spin_us: {
                let spin = std::env::var("OXO_EDGE_INJECT_SPIN_US")
                    .ok()
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .filter(|&us| us > 0);
                if let Some(us) = spin {
                    eprintln!(
                        "oxo_edge_config_notice INJECTED-SPIN: {us} us CPU burned per \
                         request (known-effect ladder dose — NEVER a clean measurement)"
                    );
                }
                spin
            },
        }
    }

    /// apply the configured downstream connection posture at the start of every
    /// request. One-shot (default) forces `set_keepalive(None)`. Keepalive re-arms the
    /// bounded idle timeout each request (the value carries across the reuse loop via
    /// `HttpPersistentSettings`, but re-asserting here is explicit and cheap).
    /// `close_on_response_before_downstream_finish` (pingora default true) is never
    /// touched, so any response written before the request body is drained still closes
    /// the connection — smuggling immunity is preserved regardless of this setting.
    fn apply_keepalive_posture(&self, session: &mut Session) {
        if self.keepalive_enabled {
            session.set_keepalive(Some(self.keepalive_idle_secs));
        } else {
            session.set_keepalive(None);
        }
    }

    fn ready_worker_sockets(&self) -> &[String] {
        // cached at construction (see the field comment for the immutability
        // contract) — this was a per-request Vec<String> allocation.
        &self.worker_socket_paths
    }

    fn configured_worker_socket(&self) -> Option<String> {
        self.worker_set
            .configured_socket()
            .map(|path| path.to_string_lossy().into_owned())
    }

    // W2: returns the id AND its sequence so telemetry can store the u64 instead of
    // cloning the String under a global mutex on every request. PRODUCER UNIQUENESS: this
    // is the ONLY producer of request ids, and the format `oxo-{pid}-{sequence}` is
    // load-bearing — telemetry's last_request_id_json RECONSTRUCTS the id from the stored
    // sequence + cached_pid(), so any second id source (or format change) must revert
    // that reconstruction to storing the string. Pinned by the admin round-trip test
    // (fake_upstream asserts /ready's last_request_id matches the served id) and by
    // mechanism_counts' getpid == 0/request pin (M1: pid cached in platform mod).
    /// W-E: arena twin of `next_request_id` — same single producer, same format
    /// (the producer-uniqueness contract above governs BOTH), the string just lives in
    /// the request bump instead of the heap. The `&'b str` is Sync, so it legally
    /// crosses awaits to record_response; sidecar paths and the HTTP hop copy it with
    /// `to_string()` when it must outlive the request (cold, borrowck-forced).
    fn next_request_id_in<'b>(&self, bump: &'b bumpalo::Bump) -> (&'b str, u64) {
        let pid = super::cached_pid();
        let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed);
        (
            bumpalo::format!(in bump, "oxo-{}-{}", pid, sequence).into_bump_str(),
            sequence,
        )
    }

    // The Host value presented to every sidecar upstream (Action Cable and
    // gRPC alike): the public server name, with the port elided only when
    // it is the scheme default — matching what a direct client would send.
    fn public_upstream_host(&self) -> String {
        match (self.url_scheme.as_str(), self.server_port) {
            ("http", 80) | ("https", 443) => self.server_name.clone(),
            _ => format!("{}:{}", self.server_name, self.server_port),
        }
    }

    // The shared admission pipeline for every route: resolve the client
    // identity, acquire the per-identity fairness slot, and (for the
    // sidecar routes) a long-lived connection slot. `Ok(None)` means the
    // request was REJECTED and this method has already recorded telemetry
    // and written the error response — the caller must `return Ok(true)`
    // and nothing else. The `?` propagates only genuine respond_error I/O
    // failures. Reject semantics are load-bearing and identical for all
    // routes: identity rejection → record_rejection(status) + status;
    // fairness saturation → record_rate_limited + 503 (checked BEFORE the
    // long-lived cap); long-lived saturation → record_rejection(503) + 503.
    async fn admit(
        &self,
        session: &mut Session,
        raw_headers: &[crate::LoweredHeader<'_>],
        request_id: &str,
        want_long_lived: bool,
    ) -> pingora::Result<Option<Admission>> {
        let global_admission = match self.global_in_flight.acquire() {
            Ok(admission) => admission,
            Err(()) => {
                self.telemetry.record_overloaded(request_id);
                session.respond_error(503).await?;
                return Ok(None);
            }
        };
        // W2: branch on the identity policy FIRST. DirectPublic (the default and the
        // scoreboard config) never reads headers — the old path built a peer String, a
        // Vec of all header pairs, and re-parsed the String, all to compute ip.to_string().
        // Parity with normalize_peer_addr(session.client_addr().to_string()) is exact:
        //   no client addr        -> "127.0.0.1"           (old: default string, parsed)
        //   inet addr             -> ip.to_string()         (old: "ip:port" -> parse -> ip)
        //   unix/unparseable addr -> addr.to_string()       (old: parse fails -> passthrough)
        // TrustedProxy resolves from the already-lowered headers (no per-header lowercase
        // String) via resolve_remote_addr_lowered; rejection order (Malformed before
        // Untrusted) is preserved by parsing the peer first.
        let remote_addr = match &self.public_identity {
            crate::PublicIdentityPolicy::DirectPublic => {
                direct_public_remote_addr(session.client_addr())
            }
            crate::PublicIdentityPolicy::TrustedProxy(policy) => {
                let peer_ip = match session.client_addr() {
                    None => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                    Some(addr) => addr.as_inet().map(|inet| inet.ip()),
                };
                let resolved = peer_ip
                    .ok_or(crate::IdentityRejection::MalformedImmediatePeer)
                    .and_then(|ip| policy.resolve_remote_addr_lowered(ip, raw_headers));
                match resolved {
                    Ok(remote_addr) => remote_addr,
                    Err(rejection) => {
                        let status = rejection.status();
                        self.telemetry.record_rejection(request_id, status);
                        session.respond_error(status).await?;
                        return Ok(None);
                    }
                }
            }
        };
        let identity_admission = match self.fairness.acquire(&remote_addr) {
            Ok(admission) => admission,
            Err(()) => {
                self.telemetry.record_rate_limited(request_id);
                session.respond_error(503).await?;
                return Ok(None);
            }
        };
        let long_lived_admission = if want_long_lived {
            let Some(admission) = self.long_lived.try_admit() else {
                self.telemetry.record_rejection(request_id, 503);
                session.respond_error(503).await?;
                return Ok(None);
            };
            Some(admission)
        } else {
            None
        };
        Ok(Some(Admission {
            remote_addr,
            global_admission,
            identity_admission,
            long_lived_admission,
        }))
    }
}

/// W2: the DirectPublic identity, computed from the pingora client addr without the
/// old String round-trip (addr.to_string() → parse → ip.to_string()). Parity with
/// `normalize_peer_addr(&addr.to_string())` is EXACT and pinned by the tests below:
/// no addr → "127.0.0.1"; inet → the bare IP; unix/other → Display passthrough (what the
/// old parse-failure branch returned verbatim).
fn direct_public_remote_addr(addr: Option<&pingora::protocols::l4::socket::SocketAddr>) -> String {
    match addr {
        None => "127.0.0.1".to_string(),
        Some(addr) => match addr.as_inet() {
            Some(inet) => inet.ip().to_string(),
            None => addr.to_string(),
        },
    }
}

/// the sticky-dispatch connection key — pure core, so the gates and traps are
/// unit-testable without a live pingora session. None = the counted fallback path.
/// Panel-fixed rules: H2 is gated on PROTOCOL, not digest presence (pingora 0.8.1
/// returns a digest for H2 unconditionally, and pinning an H2 connection's many
/// concurrent streams to one worker would concentrate the bunching — P1); the
/// peer address keeps its ephemeral PORT (the normalized identity helpers strip it,
/// and every bench connection shares one client IP — P3); absent or epoch-degenerate
/// timing is refused rather than hashed (P3).
fn sticky_key_from_parts(
    is_h2: bool,
    peer: Option<&std::net::SocketAddr>,
    established_nanos: Option<u64>,
) -> Option<u64> {
    use std::hash::{Hash, Hasher};
    if is_h2 {
        return None;
    }
    let peer = peer?;
    let nanos = established_nanos.filter(|&n| n != 0)?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    peer.hash(&mut h);
    nanos.hash(&mut h);
    Some(h.finish())
}

/// Session wrapper for `sticky_key_from_parts`: raw client addr (with port) + the
/// first Some entry of the layered timing digest (TLS stacks carry one entry per
/// protocol layer; the first Some is the transport's established timestamp).
fn sticky_conn_key(session: &Session) -> Option<u64> {
    let nanos = session.digest().and_then(|d| {
        d.timing_digest
            .iter()
            .flatten()
            .next()
            .and_then(|t| t.established_ts.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as u64)
    });
    sticky_key_from_parts(
        session.is_http2(),
        session.client_addr().and_then(|a| a.as_inet()),
        nanos,
    )
}

#[cfg(test)]
mod direct_public_parity_tests {
    use super::direct_public_remote_addr;
    use pingora::protocols::l4::socket::SocketAddr as PingoraAddr;

    // Each case asserts BOTH the new value and the old pipeline's value
    // (normalize_peer_addr over the Display string), so a drift in either breaks here.
    #[test]
    fn no_client_addr_is_loopback() {
        assert_eq!(direct_public_remote_addr(None), "127.0.0.1");
    }

    #[test]
    fn inet_addr_yields_bare_ip_like_the_old_parse() {
        let std_addr: std::net::SocketAddr = "203.0.113.9:41822".parse().unwrap();
        let addr = PingoraAddr::Inet(std_addr);
        let new = direct_public_remote_addr(Some(&addr));
        let old = crate::normalize_peer_addr_for_tests(&addr.to_string());
        assert_eq!(new, "203.0.113.9");
        assert_eq!(new, old);
        // form, bracketed with port in Display, bare in identity.
        let std6: std::net::SocketAddr = "[2001:db8::7]:443".parse().unwrap();
        let addr6 = PingoraAddr::Inet(std6);
        let new6 = direct_public_remote_addr(Some(&addr6));
        assert_eq!(new6, "2001:db8::7");
        assert_eq!(
            new6,
            crate::normalize_peer_addr_for_tests(&addr6.to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_addr_passes_display_through_like_the_old_parse_failure() {
        let std_unix = std::os::unix::net::SocketAddr::from_pathname("/tmp/x.sock").unwrap();
        let addr = PingoraAddr::Unix(std_unix);
        let new = direct_public_remote_addr(Some(&addr));
        let old = crate::normalize_peer_addr_for_tests(&addr.to_string());
        assert_eq!(new, old, "unix Display must pass through unmodified");
    }
}

// the sticky connection key's gates and traps (panel P1/P3), on the pure core.
#[cfg(test)]
mod sticky_key_tests {
    use super::sticky_key_from_parts;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn h2_is_gated_on_protocol_even_with_full_identity() {
        // P1: pingora 0.8.1 hands H2 sessions a digest unconditionally, so the gate
        // must be the protocol, not digest presence — otherwise every stream of one
        // H2 connection pins to a single worker.
        let a = addr("10.0.0.1:50000");
        assert_eq!(sticky_key_from_parts(true, Some(&a), Some(123456789)), None);
        assert!(sticky_key_from_parts(false, Some(&a), Some(123456789)).is_some());
    }

    #[test]
    fn keys_differing_only_in_ephemeral_port_pin_independently() {
        // P3: every bench connection shares one client IP; the port carries the
        // identity, so it must survive into the key.
        let a = sticky_key_from_parts(false, Some(&addr("10.0.0.1:50000")), Some(42)).unwrap();
        let b = sticky_key_from_parts(false, Some(&addr("10.0.0.1:50001")), Some(42)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn same_parts_always_hash_to_the_same_key() {
        let a = sticky_key_from_parts(false, Some(&addr("10.0.0.1:50000")), Some(42)).unwrap();
        let b = sticky_key_from_parts(false, Some(&addr("10.0.0.1:50000")), Some(42)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn absent_or_degenerate_inputs_take_the_fallback_never_hash_defaults() {
        // P3: no address, no timing, or an epoch-zero timestamp must all refuse —
        // a degenerate key would silently share one pin across ALL connections.
        let a = addr("10.0.0.1:50000");
        assert_eq!(sticky_key_from_parts(false, None, Some(42)), None);
        assert_eq!(sticky_key_from_parts(false, Some(&a), None), None);
        assert_eq!(sticky_key_from_parts(false, Some(&a), Some(0)), None);
    }
}

// GUARD-HOLD CONTRACT (panel): the two `*_admission` fields are RAII
// guards whose Drop releases the fairness / long-lived slots. Every caller
// of `admit()` must keep them alive for the route's full admission span:
// the worker route binds `identity_admission` to a NAMED local (not `_`,
// which drops immediately) that lives to the end of `request_filter`,
// because the whole worker hop runs inside that function; the sidecar
// routes move both guards into `EdgeRequestContext`, because they return
// `Ok(false)` and the connection outlives `request_filter`. Discarding an
// `Admission` early releases the slot BEFORE the work it was meant to
// bound, silently defeating the per-identity cap.
struct Admission {
    remote_addr: String,
    global_admission: Option<GlobalInFlightAdmission>,
    identity_admission: Option<IdentityAdmission>,
    long_lived_admission: Option<LongLivedAdmission>,
}

#[derive(Default)]
enum EdgeRoute {
    #[default]
    Worker,
    ActionCable {
        bind: SocketAddr,
    },
    Grpc {
        bind: SocketAddr,
    },
}

#[derive(Default)]
struct EdgeRequestContext {
    route: EdgeRoute,
    request_id: Option<String>,
    _global_admission: Option<GlobalInFlightAdmission>,
    _identity_admission: Option<IdentityAdmission>,
    long_lived_admission: Option<LongLivedAdmission>,
    grpc_request_bytes: u64,
    grpc_response_bytes: u64,
    // D3: the sidecar (Ok(false)) path runs through Pingora's proxy loop, so both
    // `response_filter` (on the response header) and `fail_to_proxy` (on a mid-stream
    // error) can fire for one request. Record exactly one terminal telemetry outcome:
    // once set, later `record_*` calls for this request are skipped.
    outcome_recorded: bool,
}

#[async_trait]
impl ProxyHttp for EdgeProxy {
    type CTX = EdgeRequestContext;

    fn new_ctx(&self) -> Self::CTX {
        Self::CTX::default()
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        // owns the worker hop here. Returning `Ok(true)` after writing
        // Rack responses keeps malformed, oversized, or incomplete client
        // bodies from ever reaching Pingora's default upstream proxy loop
        // or opening the worker UDS early. Explicit protocol sidecar routes
        // such as Action Cable opt into their own validated path.
        //
        // one-shot (default) or bounded keepalive per config. Applied per request
        // because pingora invokes request_filter once per request even on a reused
        // connection (new_ctx is per-request, so there is no per-connection state).
        self.apply_keepalive_posture(session);
        // W-C: one scratch checkout per request; the guard is a local owned by this
        // future (travels with it across work-stealing), returned by RAII on every exit
        // path including cancellation. &Bump borrows from it are confined to the
        // synchronous prologue (Send-ness rule, scratch.rs header).
        let mut scratch_guard = self.scratch_pool.checkout();
        // Send-ness rule (scratch.rs header): `bump` is used ONLY in the synchronous
        // prologue below; everything that crosses an await is a Sync shared slice/str.
        let (bump, frame_buf) = scratch_guard.split();
        // W0 "ingest" seam: entry → collect → validate → admit → sanitize → body read
        // → frame build+encode. Recorded only on the frame path once request bytes exist;
        // every early return (rejection, static hit, sidecar route) drops the timer.
        #[cfg(feature = "hop-timing")]
        let __ht_ingest = crate::hop_timing::Timer::start();
        let (request_id, request_sequence) = self.next_request_id_in(bump);
        let _request_observation = self.telemetry.start_request(request_sequence);
        let raw_headers = match collect_request_headers(session, bump) {
            Ok(headers) => headers,
            Err(status) => {
                self.telemetry.record_rejection(request_id, status);
                session.respond_error(status).await?;
                return Ok(true);
            }
        };
        if self.drain.is_draining() {
            // under keepalive this is load-bearing, not a belt — a rejected
            // BODYLESS request would otherwise reuse the connection (close_on_response
            // only fires when a body is unread). Force close so the draining edge does
            // not keep serving new requests on this connection.
            session.set_keepalive(None);
            self.telemetry.record_rejection(request_id, 503);
            session.respond_error(503).await?;
            return Ok(true);
        }
        if let Some(action_cable_bind) = self.action_cable_bind {
            if is_action_cable_upgrade_attempt(session, raw_headers) {
                match validate_action_cable_request(
                    session,
                    raw_headers,
                    self.public_server_name.as_deref(),
                    &self.url_scheme,
                    &self.server_name,
                    self.server_port,
                ) {
                    Ok(()) => {}
                    Err(status) => {
                        self.telemetry.record_rejection(request_id, status);
                        session.respond_error(status).await?;
                        return Ok(true);
                    }
                }

                let Some(admission) = self.admit(session, raw_headers, request_id, true).await?
                else {
                    return Ok(true);
                };
                ctx.route = EdgeRoute::ActionCable {
                    bind: action_cable_bind,
                };
                ctx.request_id = Some(request_id.to_string());
                // Guards move into ctx: the upgraded connection outlives
                // request_filter (see the Admission guard-hold contract).
                ctx._global_admission = admission.global_admission;
                ctx._identity_admission = admission.identity_admission;
                ctx.long_lived_admission = admission.long_lived_admission;
                return Ok(false);
            }
        }
        if let Some(grpc_bind) = self.grpc_bind {
            if is_native_grpc_request_attempt(raw_headers) {
                match validate_grpc_unary_request(
                    session,
                    raw_headers,
                    self.max_body_bytes,
                    self.public_server_name.as_deref(),
                ) {
                    Ok(()) => {}
                    Err(status) => {
                        self.telemetry.record_rejection(request_id, status);
                        session.respond_error(status).await?;
                        return Ok(true);
                    }
                }

                let Some(admission) = self.admit(session, raw_headers, request_id, true).await?
                else {
                    return Ok(true);
                };
                ctx.route = EdgeRoute::Grpc { bind: grpc_bind };
                ctx.request_id = Some(request_id.to_string());
                // Guards move into ctx: the proxied stream outlives
                // request_filter (see the Admission guard-hold contract).
                ctx._global_admission = admission.global_admission;
                ctx._identity_admission = admission.identity_admission;
                ctx.long_lived_admission = admission.long_lived_admission;
                return Ok(false);
            }
        }
        let content_length = match validate_client_request(
            session,
            raw_headers,
            self.max_body_bytes,
            self.public_server_name.as_deref(),
        ) {
            Ok(content_length) => content_length,
            Err(status) => {
                self.telemetry.record_rejection(request_id, status);
                session.respond_error(status).await?;
                return Ok(true);
            }
        };

        let Some(admission) = self.admit(session, raw_headers, request_id, false).await? else {
            return Ok(true);
        };
        // Guard-hold contract: the whole worker hop below runs inside
        // request_filter, so the fairness guard must stay alive until this
        // function returns. Destructure with a NAMED `_identity_admission`
        // binding — a bare `_` (or dropping `admission` after taking
        // `remote_addr`) would release the per-identity slot before the
        // hop and defeat the fairness cap.
        let Admission {
            remote_addr,
            global_admission: _global_admission,
            identity_admission: _identity_admission,
            long_lived_admission: _,
        } = admission;

        // static serving: runs AFTER validate_client_request and AFTER admit(), so
        // every existing protection (header caps, host/421, 413, identity, global +
        // per-identity fairness) covers static requests too, and a fallthrough miss
        // continues into the worker hop below under the SAME admission — one slot per
        // request, no double-count. Classification happens only inside crenel (the
        // one-parser rule, panel F5); oxo never inspects the path.
        //
        // honor crenel's `reusable` verdict instead of discarding it. The flag IS
        // crenel's framing-completeness verdict (a torn/short/errored send yields
        // reusable=false), so a non-reusable static response forces the connection
        // closed. Under one-shot the request-entry set_keepalive(None) already made this
        // a no-op; under keepalive it is the correct per-response gate.
        // M2 (BENCH-ONLY native floor): answer `/edge-bench` with a canned body,
        // skipping the worker hop + Ruby entirely, to measure the fixed per-request edge
        // cost a native fast path would legitimately pay (TLS + parse + collect/lower headers
        // + validate + admit — all ABOVE this seam). Runs AFTER admission, so every cap still
        // covers it. Exact-match only: `/edge-bench/`, `//edge-bench`, `%2f…` all miss and
        // fall through to the worker hop (fails safe, one parser, no smuggling surface). The
        // query string is intentionally ignored (uri.path() drops it) — harmless for the
        // bench. Compiled only under `--features edge-bench` (absent from shipped builds) AND
        // gated by the boot-resolved flag, so it never ships enabled.
        // M-D (bench-only): the ladder dose burns its calibrated CPU on EVERY request
        // — /bench and /edge-bench alike — so both gated cells see the same injected
        // effect. Sits before the stub so the native path is dosed too.
        #[cfg(feature = "edge-bench")]
        if let Some(us) = self.inject_spin_us {
            let end = std::time::Instant::now() + std::time::Duration::from_micros(us);
            while std::time::Instant::now() < end {
                std::hint::spin_loop();
            }
        }

        #[cfg(feature = "edge-bench")]
        if self.native_bench_enabled && session.req_header().uri.path() == "/edge-bench" {
            // Byte-identical BODY to the `/bench` fixture ("oxo-bench-ok"); framing is
            // identical via the frame hop's exact build_response_header, and the Connection
            // posture uses self.keepalive_enabled so it matches the `/bench` frame path.
            let body = b"oxo-bench-ok".to_vec();
            let headers = vec![("Content-Type".to_string(), "text/plain".to_string())];
            match frame_hop::write_native_bench_response(
                session,
                200,
                headers,
                body,
                self.keepalive_enabled,
            )
            .await
            {
                Ok(()) => {
                    self.telemetry.record_response(request_id, 200);
                    return Ok(true);
                }
                Err(status) => {
                    self.telemetry.record_rejection(request_id, status);
                    session.respond_error(status).await?;
                    return Ok(true);
                }
            }
        }

        if let Some(static_server) = &self.static_server {
            let method = session.req_header().method.as_str();
            // (lever 2): in prod, a request whose first path segment was not
            // enumerated static at boot is definitely dynamic — skip `serve()` and the two
            // filesystem probe syscalls (`newfstatat`+`openat2`) it would fire, going
            // straight to the worker hop. In dev (`prod_pin` None) every GET/HEAD probes,
            // so a freshly deployed static file is served without a restart. A
            // percent-encoded first segment could decode to a pinned name, so we probe it
            // conservatively rather than risk skipping a legitimately static file; plain
            // segments (the dynamic hot path, e.g. `/bench`) take the exact pin lookup.
            let static_candidate =
                is_static_candidate(self.prod_pin.as_deref(), session.req_header().uri.path());
            if (method == "GET" || method == "HEAD") && static_candidate {
                match static_server.serve(session.as_downstream_mut()).await {
                    crenel_pingora::Served::Done { reusable } => {
                        if !reusable {
                            session.set_keepalive(None);
                        }
                        let status = session
                            .as_downstream()
                            .response_written()
                            .map(|resp| resp.status.as_u16())
                            .unwrap_or(0);
                        self.telemetry.record_response(request_id, status);
                        return Ok(true);
                    }
                    crenel_pingora::Served::NotStatic => {}
                }
            }
        }

        let protocols = crate::ProtocolSupport {
            sse: self.sse_enabled,
        };
        // A1 / W3: the frame hop sanitizes to a keep-PLAN over the collected
        // headers (zero survivor re-allocation; metadata rides as native frame fields and
        // is not even constructed here). Only the HTTP hop builds TrustedHopMetadata and
        // attaches x-oxo-* headers + connection: close.
        enum HopPrep {
            Frame(crate::FrameHeaderPlan),
            Http(Vec<(String, String)>),
        }
        let prep = match self.worker_hop {
            WorkerHop::Frame => {
                crate::sanitize_frame_headers(raw_headers, protocols).map(HopPrep::Frame)
            }
            WorkerHop::Http => {
                let metadata = crate::TrustedHopMetadata {
                    remote_addr: remote_addr.clone(),
                    url_scheme: self.url_scheme.clone(),
                    server_name: self.server_name.clone(),
                    server_port: self.server_port,
                    request_id: Some(request_id.to_string()),
                };
                crate::sanitize_lowered_worker_request_headers(raw_headers, &metadata, protocols)
                    .map(|sanitized| HopPrep::Http(sanitized.headers))
            }
        };
        let prep = match prep {
            Ok(prep) => prep,
            Err(crate::RequestRejection::GrpcUnsupported) => {
                self.telemetry.record_rejection(request_id, 415);
                session.respond_error(415).await?;
                return Ok(true);
            }
            Err(
                crate::RequestRejection::UpgradeUnsupported
                | crate::RequestRejection::StreamingUnsupported,
            ) => {
                self.telemetry.record_rejection(request_id, 400);
                session.respond_error(400).await?;
                return Ok(true);
            }
        };

        let body = match read_complete_body(session, content_length, self.max_body_bytes).await {
            Ok(body) => body,
            Err(status) => {
                self.telemetry.record_rejection(request_id, status);
                session.respond_error(status).await?;
                return Ok(true);
            }
        };
        // the hop wire format. `Frame` (default) ships the already-parsed request as
        // a binary frame over a pooled persistent UDS connection; `Http` keeps the
        // one-shot HTTP/1.1 text hop. Both consume the SAME sanitize classification, so
        // the worker's Rack env is identical either way (the env-parity guarantee —
        // W3 pins it with a full-frame byte-parity golden against the owned builder).
        let hop_result = match prep {
            HopPrep::Frame(plan) => {
                let request_bytes: &[u8] = match frame_hop::build_request_frame_bytes_into(
                    frame_buf,
                    session,
                    raw_headers,
                    &plan,
                    &body,
                    &self.url_scheme,
                    &self.server_name,
                    self.server_port,
                    &remote_addr,
                ) {
                    Ok(()) => frame_buf,
                    Err(status) => {
                        self.telemetry.record_rejection(request_id, status);
                        session.respond_error(status).await?;
                        return Ok(true);
                    }
                };
                // The ingest seam ends here — the request bytes exist; everything after
                // is hop work (checkout → write → read → checkin, each its own seam).
                #[cfg(feature = "hop-timing")]
                crate::hop_timing::record(crate::hop_timing::Seam::Ingest, __ht_ingest);
                // the connection key is derived only under sticky dispatch —
                // every other mode passes None and pays one enum compare.
                let sticky_key =
                    if frame_hop::dispatch::mode() == frame_hop::dispatch::DispatchMode::Sticky {
                        sticky_conn_key(session)
                    } else {
                        None
                    };
                frame_hop::send_worker_frame_to_pool(
                    &self.worker_pool,
                    self.ready_worker_sockets(),
                    &self.next_worker,
                    request_bytes,
                    session,
                    &self.long_lived,
                    self.drain.subscribe(),
                    self.keepalive_enabled,
                    sticky_key,
                )
                .await
            }
            HopPrep::Http(sanitized_headers) => {
                let worker_request = match build_worker_request(session, sanitized_headers, &body) {
                    Ok(request) => request,
                    Err(status) => {
                        self.telemetry.record_rejection(request_id, status);
                        session.respond_error(status).await?;
                        return Ok(true);
                    }
                };
                send_worker_request_to_pool(
                    self.ready_worker_sockets(),
                    &self.next_worker,
                    &worker_request,
                    session,
                    &self.long_lived,
                    self.drain.subscribe(),
                    self.keepalive_enabled,
                )
                .await
            }
        };
        let status = match hop_result {
            Ok(status) => status,
            Err(status) => {
                self.telemetry.record_rejection(request_id, status);
                session.respond_error(status).await?;
                return Ok(true);
            }
        };
        self.telemetry.record_response(request_id, status);
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        // D6: the per-request `group_key` bump and `idle_timeout = ZERO` below are two
        // independent ways of saying "never reuse a pooled connection for the sidecars".
        // `idle_timeout = ZERO` alone already forces a fresh connection every request;
        // the unique `group_key` is redundant with it, not a load-bearing
        // generation-fence. Keep both settings in sync if either is changed to enable
        // sidecar keep-alive later.
        if let EdgeRoute::ActionCable { bind } = ctx.route {
            let mut peer = HttpPeer::new(bind.to_string(), false, String::new());
            peer.group_key = self.upstream_generation.fetch_add(1, Ordering::Relaxed);
            peer.options.idle_timeout = Some(Duration::ZERO);
            return Ok(Box::new(peer));
        }
        if let EdgeRoute::Grpc { bind } = ctx.route {
            let mut peer = HttpPeer::new(bind.to_string(), false, String::new());
            peer.group_key = self.upstream_generation.fetch_add(1, Ordering::Relaxed);
            peer.options.set_http_version(2, 2);
            peer.options.max_h2_streams = 1;
            peer.options.idle_timeout = Some(Duration::ZERO);
            peer.options.read_timeout = Some(WORKER_READ_TIMEOUT);
            peer.options.write_timeout = Some(WORKER_WRITE_TIMEOUT);
            return Ok(Box::new(peer));
        }
        // Defensive trait implementation only. The accepted path handles
        // requests in `request_filter`; reaching this method means a future
        // change fell through to Pingora's transparent proxy machinery.
        let worker_socket = self
            .ready_worker_sockets()
            .first()
            .cloned()
            .or_else(|| self.configured_worker_socket())
            .unwrap_or_default();
        let mut peer = HttpPeer::new_uds(&worker_socket, false, String::new())?;
        peer.group_key = self.upstream_generation.fetch_add(1, Ordering::Relaxed);
        peer.options.idle_timeout = Some(Duration::ZERO);
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if matches!(
            ctx.route,
            EdgeRoute::ActionCable { .. } | EdgeRoute::Grpc { .. }
        ) {
            for name in [
                "forwarded",
                "x-forwarded-for",
                "x-forwarded-host",
                "x-forwarded-port",
                "x-forwarded-proto",
                "x-real-ip",
                "x-request-id",
                "x-oxo-remote-addr",
                "x-oxo-url-scheme",
                "x-oxo-server-name",
                "x-oxo-server-port",
                "x-oxo-request-id",
            ] {
                upstream_request.remove_header(name);
            }
            upstream_request
                .insert_header("host", self.public_upstream_host())
                .unwrap();
            upstream_request
                .insert_header("x-oxo-url-scheme", self.url_scheme.as_str())
                .unwrap();
            upstream_request
                .insert_header("x-oxo-server-name", self.server_name.as_str())
                .unwrap();
            upstream_request
                .insert_header("x-oxo-server-port", self.server_port.to_string())
                .unwrap();
            if let Some(request_id) = ctx.request_id.as_deref() {
                upstream_request
                    .insert_header("x-oxo-request-id", request_id)
                    .unwrap();
            }
        }
        Ok(())
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if matches!(ctx.route, EdgeRoute::Grpc { .. }) {
            if let Some(body) = body.as_ref() {
                ctx.grpc_request_bytes = ctx
                    .grpc_request_bytes
                    .saturating_add(u64::try_from(body.len()).unwrap_or(u64::MAX));
                if ctx.grpc_request_bytes > self.max_body_bytes {
                    return Err(pingora::Error::explain(
                        pingora::ErrorType::HTTPStatus(413),
                        "gRPC request body exceeds Oxo max body",
                    ));
                }
            }
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if matches!(
            ctx.route,
            EdgeRoute::ActionCable { .. } | EdgeRoute::Grpc { .. }
        ) {
            let status = upstream_response.status.as_u16();
            if !ctx.outcome_recorded {
                if let Some(request_id) = ctx.request_id.as_deref() {
                    self.telemetry.record_response(request_id, status);
                }
                ctx.outcome_recorded = true;
            }
            // D2: do NOT mark the long-lived admission complete on the 101 upgrade —
            // that is the START of the connection's life, not its end, so a session
            // later killed by timeout/cap/drain would still be counted as completed.
            // Completion is signalled at real teardown in `logging` (below).
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Option<Duration>>
    where
        Self::CTX: Send + Sync,
    {
        if matches!(ctx.route, EdgeRoute::Grpc { .. }) {
            if let Some(body) = body.as_ref() {
                ctx.grpc_response_bytes = ctx
                    .grpc_response_bytes
                    .saturating_add(u64::try_from(body.len()).unwrap_or(u64::MAX));
                if ctx.grpc_response_bytes > self.max_body_bytes {
                    return Err(pingora::Error::explain(
                        pingora::ErrorType::HTTPStatus(502),
                        "gRPC response body exceeds Oxo max body",
                    ));
                }
                if let Some(admission) = ctx.long_lived_admission.as_mut() {
                    if !admission.record_bytes(u64::try_from(body.len()).unwrap_or(u64::MAX)) {
                        return Err(pingora::Error::explain(
                            pingora::ErrorType::HTTPStatus(502),
                            "gRPC response body exceeds Oxo streaming envelope",
                        ));
                    }
                }
            }
            if _end_of_stream {
                if let Some(admission) = ctx.long_lived_admission.as_mut() {
                    admission.complete();
                }
            }
        }
        Ok(None)
    }

    async fn logging(
        &self,
        _session: &mut Session,
        error: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) where
        Self::CTX: Send + Sync,
    {
        // D2: a long-lived sidecar connection (Action Cable or gRPC) is complete only
        // when it tears down cleanly (`error.is_none()`). A clean upgraded-downstream
        // close surfaces here with no error; a fault (timeout, cap, RST, drain) carries
        // an error, so the admission stays not-complete and Drop counts it cancelled.
        if error.is_none()
            && matches!(
                ctx.route,
                EdgeRoute::ActionCable { .. } | EdgeRoute::Grpc { .. }
            )
        {
            if let Some(admission) = ctx.long_lived_admission.as_mut() {
                admission.complete();
            }
        }
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        error: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let code = match error.etype() {
            pingora::ErrorType::HTTPStatus(code) => *code,
            _ => match error.esource() {
                pingora::ErrorSource::Upstream => 502,
                pingora::ErrorSource::Downstream => 400,
                pingora::ErrorSource::Internal | pingora::ErrorSource::Unset => 500,
            },
        };
        // D3: only record a rejection if no terminal outcome was recorded yet. When a
        // sidecar response already succeeded through `response_filter` and then fails
        // mid-stream, `fail_to_proxy` must not double-count a second outcome.
        if !ctx.outcome_recorded {
            if let Some(request_id) = ctx.request_id.as_deref() {
                self.telemetry.record_rejection(request_id, code);
            }
            ctx.outcome_recorded = true;
        }
        let _ = session.respond_error(code).await;
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }
}

#[cfg(test)]
mod prod_routing_tests {
    use super::{build_prod_pin_set, first_path_segment, is_static_candidate};
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn first_path_segment_extracts_first_segment_boundary_exact() {
        assert_eq!(first_path_segment("/bench"), "bench");
        assert_eq!(first_path_segment("/assets/app.js"), "assets");
        assert_eq!(first_path_segment("/favicon.ico"), "favicon.ico");
        assert_eq!(first_path_segment("/"), "");
        assert_eq!(first_path_segment(""), "");
        // Boundary-exact: /assetsfoo must NOT collapse to "assets" (would falsely pin).
        assert_eq!(first_path_segment("/assetsfoo"), "assetsfoo");
        // No leading slash (defensive): treated as already-trimmed.
        assert_eq!(first_path_segment("bench"), "bench");
    }

    #[test]
    fn is_static_candidate_dev_pin_none_always_probes() {
        // Dev (None): every path is a candidate so static hot-reload is preserved.
        assert!(is_static_candidate(None, "/bench"));
        assert!(is_static_candidate(None, "/assets/app.js"));
        assert!(is_static_candidate(None, "/"));
    }

    #[test]
    fn is_static_candidate_prod_pins_gate_the_probe() {
        let pin: HashSet<String> = [
            "assets".to_string(),
            "favicon.ico".to_string(),
            String::new(),
        ]
        .into_iter()
        .collect();
        // Dynamic route: first segment "bench" absent → NOT a candidate → probe skipped.
        assert!(!is_static_candidate(Some(&pin), "/bench"));
        // Pinned prefix + pinned file → candidate.
        assert!(is_static_candidate(Some(&pin), "/assets/app.js"));
        assert!(is_static_candidate(Some(&pin), "/favicon.ico"));
        // Bare root (empty first segment) is pinned → candidate (index).
        assert!(is_static_candidate(Some(&pin), "/"));
        // Boundary-exact: /assetsfoo is not the pinned "assets".
        assert!(!is_static_candidate(Some(&pin), "/assetsfoo"));
        // Percent-encoded first segment probes conservatively (could decode to a pin).
        assert!(is_static_candidate(Some(&pin), "/%61ssets/app.js"));
    }

    /// A self-cleaning unique temp dir under the system temp root — avoids a `tempfile`
    /// dev-dep for one filesystem test. Uniqueness is pid + a process-local counter (the
    /// bench box forbids `Math.random`/wall-clock in some contexts; a counter is enough
    /// here since the dir is removed on drop).
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("oxo-{tag}-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).expect("create temp dir");
            TmpDir(dir)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn build_prod_pin_set_prefix_mount_pins_prefix_without_walking() {
        // A non-root prefix mount (e.g. /assets=<dir>): the prefix alone pins "assets";
        // the docroot need not even exist for the pin (no walk on prefix mounts).
        let mount = crenel_pingora::MountSpec::new("/assets", "/nonexistent-docroot-ok");
        let pin = build_prod_pin_set(std::slice::from_ref(&mount)).expect("prefix mount pins");
        assert!(pin.contains("assets"));
        assert_eq!(pin.len(), 1);
    }

    #[test]
    fn build_prod_pin_set_root_mount_enumerates_top_level_entries() {
        let tmp = TmpDir::new("root-enum");
        fs::write(tmp.0.join("favicon.ico"), b"x").unwrap();
        fs::write(tmp.0.join("robots.txt"), b"x").unwrap();
        fs::create_dir(tmp.0.join("packs")).unwrap();
        // A nested dynamic-looking path under public/ must NOT be pinned by name (only the
        // top-level segment "packs" is), and /bench (absent) stays a non-candidate.
        let mount = crenel_pingora::MountSpec::new("/", &tmp.0);
        let pin = build_prod_pin_set(std::slice::from_ref(&mount)).expect("root mount enumerates");
        assert!(pin.contains("favicon.ico"));
        assert!(pin.contains("robots.txt"));
        assert!(pin.contains("packs"));
        assert!(pin.contains(""), "bare-root index segment is pinned");
        assert!(!pin.contains("bench"), "a dynamic route is never pinned");
        // Gate behavior end-to-end: /bench skips, /favicon.ico probes.
        assert!(!is_static_candidate(Some(&pin), "/bench"));
        assert!(is_static_candidate(Some(&pin), "/favicon.ico"));
        assert!(is_static_candidate(Some(&pin), "/packs/app.js"));
    }

    #[test]
    fn build_prod_pin_set_empty_docroot_pins_only_bare_root() {
        // An empty public/ (API-only app, or pre-precompile): only the bare-root index is
        // pinned, so EVERY named route (all dynamic) skips the probe. The optimization's
        // best case, and it must not error.
        let tmp = TmpDir::new("empty");
        let mount = crenel_pingora::MountSpec::new("/", &tmp.0);
        let pin = build_prod_pin_set(std::slice::from_ref(&mount)).expect("empty docroot ok");
        assert_eq!(pin, HashSet::from([String::new()]));
        assert!(!is_static_candidate(Some(&pin), "/bench"));
        assert!(!is_static_candidate(Some(&pin), "/assets/app.js"));
    }

    #[test]
    fn build_prod_pin_set_missing_root_docroot_fails_loud() {
        // A root/fallthrough mount whose docroot cannot be read fails boot LOUD (fail-closed),
        // never a silent fallback that would quietly re-probe every request.
        let mount = crenel_pingora::MountSpec::new("/", "/definitely/not/a/real/docroot");
        let err = build_prod_pin_set(std::slice::from_ref(&mount));
        assert!(err.is_err(), "unreadable root docroot must error");
    }
}

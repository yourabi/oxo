use super::*;

#[cfg(feature = "tls-rustls")]
use super::fs_validate::validate_tls_file;

pub fn run_from_env() -> Result<(), EdgeError> {
    run_with_cli(crate::EdgeCliConfig::default())
}

pub fn run_from_args<I, S>(args: I) -> Result<(), EdgeError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let cli = crate::EdgeCliConfig::parse_from_args(args)?;
    run_with_cli(cli)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BindKind {
    Http,
    Https,
}

fn run_with_cli(cli: crate::EdgeCliConfig) -> Result<(), EdgeError> {
    reject_socket_activation_env()?;
    if cli.acme_issue_once && cli.acme_renew_once {
        return Err(EdgeError::ConfigEnv {
            name: "argv",
            message: "--acme-issue-once and --acme-renew-once are mutually exclusive".to_string(),
        });
    }
    if cli.acme_issue_once {
        return run_acme_issue_once(cli);
    }
    if cli.acme_renew_once {
        return run_acme_renew_once(cli);
    }
    let (bind, bind_kind) = read_bind(&cli)?;
    let worker_sockets = read_worker_sockets(&cli)?;
    // captured before `worker_sockets` moves into EdgeConfig; the pool ceiling and
    // the descriptor budget below are both sized on it.
    let worker_count = worker_sockets.len();
    let (max_body_bytes, max_body_explicit) = read_max_body(&cli)?;
    let listener = read_listener_mode(&cli, bind_kind)?;
    validate_future_acme_state_path(&cli)?;
    let (server_name, server_name_explicit) = read_server_name(&cli)?;
    let public_origin_port = read_public_origin_port(&cli)?;
    let public_mode = read_public_mode_gate(
        bind,
        &listener,
        &cli,
        max_body_explicit,
        server_name_explicit,
    )?;
    let public_identity = read_public_identity_policy(public_mode, &cli)?;
    let fairness = read_identity_fairness(public_mode, &cli)?;
    let global_in_flight = read_global_in_flight(public_mode, &cli, &fairness)?;
    // resolve the serve-rails preset EXACTLY ONCE (panel P4) and pass the result
    // into every consumer — the keepalive/SSE ladders, the mount derivation, the posture
    // line, and /ready — so precedence can never drift between readers. The plan's root
    // check is unconditional (P3): it runs even when --static-rails-preset overrides the
    // mounts, because the root is the posture anchor.
    let serve_rails_root = read_serve_rails(&cli)?;
    let static_rails_preset = read_static_rails_preset(&cli)?;
    let serve_rails_plan = match serve_rails_root {
        Some(root) => Some(plan_serve_rails(root, static_rails_preset.as_deref())?),
        None => None,
    };
    let serve_rails_active = serve_rails_plan.is_some();
    let slow_client = read_slow_client_policy(&cli, serve_rails_active)?;
    let long_lived = read_long_lived_registry(&cli)?;
    let drain_config = read_edge_drain_config(&cli)?;
    let edge_threads = read_edge_threads(&cli)?;
    let listener_tasks = read_listener_tasks(&cli)?;
    let (request_log, request_log_source) = read_request_log(&cli)?;
    let (worker_hop, worker_hop_source) = read_worker_hop(&cli, max_body_bytes)?;
    let (worker_dispatch, worker_dispatch_source) =
        read_worker_dispatch(&cli, worker_sockets.len())?;
    super::frame_hop::dispatch::init_mode(worker_dispatch);
    // the per-worker admission cap ("dispatch-on-free"). Resolved after the
    // global in-flight cap so the deadlock guard (K x workers must sit BELOW the
    // global cap, else parked requests holding global slots could starve the wakers)
    // can validate against the real resolved value. Default OFF.
    let worker_cap = read_worker_cap(&cli, worker_sockets.len(), global_in_flight.max_requests)?;
    super::frame_hop::dispatch::init_cap(worker_cap);
    // W0: worker kind gates the frame hop's stale-reuse retry (async reactors make
    // zero-byte EOF ambiguous under crash — the retry would silently replay). Parsed
    // fail-closed here; forwarded by the service supervisor as OXO_WORKER_KIND.
    let worker_kind = read_worker_kind()?;
    super::frame_hop::worker_kind::init_kind(worker_kind);
    validate_public_tls_identity(public_mode, &listener, &server_name)?;
    let admin_bind = read_admin_bind(public_mode, &cli)?;
    let action_cable_bind = read_action_cable_bind(&cli)?;
    let grpc_bind = read_grpc_bind(&cli)?;
    let sse_enabled = read_sse_enabled(&cli, serve_rails_active)?;
    let (prod_enabled, prod_source) = read_prod_enabled(&cli)?;
    let h2_policy = read_h2_policy(&cli)?;
    let static_mounts = read_static_mounts(&cli, static_rails_preset, serve_rails_plan.as_ref())?;
    let edge = crate::EdgeConfig::new_with_worker_sockets_and_public_alpha(
        bind,
        worker_sockets,
        max_body_bytes,
        public_mode.is_some(),
    )?
    .with_sse_enabled(sse_enabled);
    let url_scheme = listener.url_scheme().to_string();
    // config-surface honesty. `header_read_timeout_ms` and `max_connection_secs` are
    // parsed, forwarded, and reported on /ready but have NO pingora 0.8.1 enforcement seam.
    // Tell the operator the truth wherever they configure — on both the boot path AND
    // `--check-config` (which returns just below) — so a tuned-but-inert knob never reads as
    // a mitigation. Non-breaking: we warn, never reject.
    emit_unenforced_knob_warnings(&slow_client);
    // posture line (panel P5a): the resolved composite is stated where the operator
    // configures — deliberately BEFORE the --check-config return so dry-run users (the
    // natural verifiers of a preset) see exactly what the flag turned on.
    if let Some(plan) = &serve_rails_plan {
        eprintln!(
            "oxo_edge_config_notice serve-rails: keepalive={} sse={} static={}",
            if slow_client.keepalive_enabled {
                "on"
            } else {
                "off"
            },
            if sse_enabled { "on" } else { "off" },
            plan.static_descriptor()
        );
    }
    // posture line (enforced knob — this genuinely sets the Pingora runtime's
    // worker-thread count, unlike the NOT-ENFORCED set). Printed BEFORE the
    // --check-config return so dry-run users see the effective parallelism + source.
    eprintln!(
        "oxo_edge_config_notice edge-threads: {} (source: {}{})",
        edge_threads.threads,
        edge_threads.source,
        if edge_threads.threads > edge_threads.nproc {
            "; above nproc — oversubscription buys no event-loop parallelism"
        } else {
            ""
        },
    );
    // posture line (enforced knob — sets ServerConf.listener_tasks_per_fd, the
    // parallel-accept count per listening socket; also on /ready — never stderr-only).
    eprintln!(
        "oxo_edge_config_notice listener-tasks: {} (source: {})",
        listener_tasks.tasks, listener_tasks.source,
    );
    // posture line (enforced knob; also on /ready — never stderr-only).
    eprintln!(
        "oxo_edge_config_notice request-log: {} (source: {})",
        request_log.as_str(),
        request_log_source,
    );
    // posture line: the worker-hop wire format (also on /ready).
    eprintln!(
        "oxo_edge_config_notice worker-hop: {} (source: {})",
        worker_hop.as_str(),
        worker_hop_source,
    );
    // posture line: the dispatch discipline (enforced knob; also on /ready).
    eprintln!(
        "oxo_edge_config_notice worker-dispatch: {} (source: {})",
        super::frame_hop::dispatch::mode_name(worker_dispatch),
        worker_dispatch_source,
    );
    // posture line (lever 2, enforced knob; also on /ready). "dev" = every GET/HEAD
    // request probes the filesystem before falling through to the worker hop (a freshly
    // deployed static file appears without a restart). "prod" = static docroots are
    // enumerated once at boot into a first-path-segment pin set, and dynamic routes skip
    // the probe. The routing mode is stated where the operator configures so a dry-run
    // (--check-config) sees exactly which discipline is active.
    eprintln!(
        "oxo_edge_config_notice routing: {} (source: {})",
        if prod_enabled {
            "prod (boot-pinned static docroots; dynamic routes skip the fs probe)"
        } else {
            "dev (live fs probe every request; static hot-reload without restart)"
        },
        prod_source,
    );
    // /: the idle-pool ceiling and the descriptor budget, resolved ONCE here,
    // before the --check-config return, and threaded into the pool through
    // RunEdgeOptions -> EdgeProxyOptions -> WorkerFramePool::from_ceiling. Until
    // the pool read the env itself inside run_edge, so a dry run never printed the
    // ceiling, and nothing anywhere compared it with RLIMIT_NOFILE.
    let frame_pool_idle = super::frame_pool::resolve_idle_ceiling(
        std::env::var("OXO_EDGE_FRAME_POOL_IDLE").ok().as_deref(),
        worker_count,
    );
    if let Err(message) =
        super::frame_pool::parse_pool_impl(std::env::var("OXO_EDGE_POOL").ok().as_deref())
    {
        return Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_POOL",
            message,
        });
    }
    // checkout's unwrap wait budget, the one other pool knob, resolved here for
    // the same reason (the pool reads no env; the receipt cannot disagree).
    let unwrap_wait_budget = super::frame_hop::parse_unwrap_wait_ms(
        std::env::var("OXO_EDGE_UNWRAP_WAIT_MS").ok().as_deref(),
    )
    .map_err(|message| EdgeError::ConfigEnv {
        name: "OXO_EDGE_UNWRAP_WAIT_MS",
        message,
    })?;
    // posture line: the ceiling is a per-process fd and memory budget (about 20 KiB
    // and one fd per idle connection on the edge, one fd and a thread or fiber on the
    // worker), so it is printed like the other enforced knobs. adds the unwrap
    // wait budget to the same line.
    eprintln!(
        "oxo_edge_config_notice frame-pool-idle: {} (source: {}; aggregate across all \
         edge threads; about {} KiB of edge buffers and {} fds at full occupancy; unwrap \
         wait budget {} ms)",
        frame_pool_idle.0,
        frame_pool_idle.1.as_str(),
        frame_pool_idle.0.saturating_mul(20),
        frame_pool_idle.0,
        unwrap_wait_budget.as_millis(),
    );
    // posture line: the descriptor budget against the process limit. Refuses only
    // when the descriptors held before the first request exceed the soft limit; a pool
    // ceiling that would crowd downstream connections is a warning (see fd_budget.rs).
    let budget = crate::fd_budget::fd_budget(
        crate::fd_budget::read_nofile_limits(),
        1 + u64::from(admin_bind.is_some()),
        worker_count as u64,
        frame_pool_idle.0 as u64,
        global_in_flight.max_requests,
    );
    eprintln!("{}", budget.notice());
    if let Some(warning) = budget.warning() {
        eprintln!("{warning}");
    }
    if let Some(message) = budget.refusal() {
        return Err(EdgeError::ConfigEnv {
            name: "RLIMIT_NOFILE",
            message,
        });
    }
    if cli.check_config {
        // (panel P10): the docroot pin audit normally lives in run_edge, AFTER this
        // return — so --check-config would pass configurations real boot refuses. Build
        // (and discard) the StaticServer here so the dry-run catches missing or hostile
        // docroots exactly like boot does.
        if !static_mounts.is_empty() {
            // (lever 2): build (and discard) the prod pin set FIRST — a --prod dry-run
            // must catch an unreadable/oversized docroot exactly like boot does, before the
            // StaticServer::new below moves the mounts.
            if prod_enabled {
                super::proxy::build_prod_pin_set(&static_mounts)?;
            }
            crenel_pingora::StaticServer::new(crenel_pingora::StaticServerConfig {
                mounts: static_mounts,
                limits: crenel_pingora::Limits::default(),
            })
            .map_err(|err| EdgeError::ConfigEnv {
                name: "OXO_EDGE_STATIC_MOUNTS",
                message: err.to_string(),
            })?;
        }
        return Ok(());
    }
    let serve_rails_posture = serve_rails_plan
        .as_ref()
        .map(|plan| ServeRailsPosture {
            active: true,
            static_descriptor: plan.static_descriptor(),
        })
        .unwrap_or_default();
    let certificate_admin_json = read_certificate_admin_json(&cli)?;
    let run_options = RunEdgeOptions {
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
        edge_threads: edge_threads.threads,
        listener_tasks: listener_tasks.tasks,
        request_log,
        worker_hop,
        static_mounts,
        prod_enabled,
        h2_policy,
        serve_rails: serve_rails_posture,
        frame_pool_idle,
        unwrap_wait_budget,
    };
    run_edge(edge, run_options)
}

/// the single serve-rails resolution (panel P4). Computed ONCE in `run_with_cli`
/// and PASSED to every consumer (keepalive/SSE ladders, mount derivation, the posture
/// line, /ready) so the preset's precedence can never drift between readers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ServeRailsPlan {
    pub(super) root: PathBuf,
    /// The static docroot the derivation settled on; `None` = static serving
    /// soft-disabled (no `<root>/public`).
    static_dir: Option<PathBuf>,
    /// Include the strict immutable `/assets` mount (`<root>/public/assets` exists).
    /// When false the derivation pushes ONLY the `/` fallthrough mount — an API-only app
    /// or a pre-`assets:precompile` checkout must not be refused boot (panel P1, HIGH).
    static_assets: bool,
    /// An explicit `--static-rails-preset` dir overrides the derivation entirely; the
    /// preset then only sets posture (keepalive/SSE) and the root anchor check.
    static_overridden: bool,
}

impl ServeRailsPlan {
    /// The `static=<dir|off>` cell of the posture line and the /ready posture field.
    pub(super) fn static_descriptor(&self) -> String {
        match &self.static_dir {
            Some(dir) => dir.display().to_string(),
            None => "off".to_string(),
        }
    }
}

/// /ready posture snapshot (panel P5b) — threaded into telemetry so the resolved
/// preset state is queryable, not stderr-only. Default = preset inactive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ServeRailsPosture {
    pub(super) active: bool,
    pub(super) static_descriptor: String,
}

impl Default for ServeRailsPosture {
    fn default() -> Self {
        Self {
            active: false,
            static_descriptor: "off".to_string(),
        }
    }
}

fn read_serve_rails(cli: &crate::EdgeCliConfig) -> Result<Option<PathBuf>, EdgeError> {
    Ok(resolve_serve_rails(cli.serve_rails.clone(), env::var_os))
}

/// CLI wins; else the env twin; empty env = unset (house `optional_path_env` contract).
/// Injectable getenv (the `socket_activation_env_name` pattern) so unit tests never
/// mutate process-global env (panel P7).
fn resolve_serve_rails<F>(cli_value: Option<PathBuf>, mut getenv: F) -> Option<PathBuf>
where
    F: FnMut(&'static str) -> Option<OsString>,
{
    cli_value.or_else(|| {
        getenv("OXO_EDGE_SERVE_RAILS")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    })
}

/// derivation matrix (panel P1/P3/P8). The ROOT check is UNCONDITIONAL — the root
/// is the posture anchor even when `--static-rails-preset` overrides the mounts, so a
/// typo'd root can never silently degrade (P3). Checks are symlink-following `is_dir()`
/// (P8): Capistrano `current` symlinks resolve; a dangling symlink reads as missing.
/// Derived defaults degrade with logged warnings; explicit config stays fail-closed.
fn plan_serve_rails(
    root: PathBuf,
    explicit_static_dir: Option<&Path>,
) -> Result<ServeRailsPlan, EdgeError> {
    if !root.is_dir() {
        return Err(EdgeError::ConfigEnv {
            name: "--serve-rails",
            message: format!(
                "app root {} is missing or not a directory; point --serve-rails at the \
                 Rails application root (the directory that contains public/)",
                root.display()
            ),
        });
    }
    if let Some(dir) = explicit_static_dir {
        return Ok(ServeRailsPlan {
            root,
            static_dir: Some(dir.to_path_buf()),
            static_assets: true,
            static_overridden: true,
        });
    }
    let public = root.join("public");
    if !public.exists() {
        // Soft-disable (owner decision): a Rails app without public/ is valid; keepalive
        // and SSE posture still apply. Greppable prefix so operators can alert on it.
        eprintln!(
            "oxo_edge_config_warning no static asset directory at {}; static serving \
             off (--serve-rails); restart the edge after creating it",
            public.display()
        );
        return Ok(ServeRailsPlan {
            root,
            static_dir: None,
            static_assets: false,
            static_overridden: false,
        });
    }
    if !public.is_dir() {
        // A regular file (or symlink to one) at public/ is a broken layout, not a
        // missing default — fail closed naming the flag the operator actually used.
        return Err(EdgeError::ConfigEnv {
            name: "--serve-rails",
            message: format!(
                "{} exists but is not a directory; --serve-rails derives the static \
                 docroot from <root>/public",
                public.display()
            ),
        });
    }
    let static_assets = public.join("assets").is_dir();
    if !static_assets {
        // P1 (HIGH): API-only apps and pre-precompile checkouts have public/ but no
        // public/assets. The strict /assets mount would refuse boot at crenel's pin
        // audit — derive only the fallthrough mount instead and say why.
        eprintln!(
            "oxo_edge_config_warning no {} directory; serving {} without the \
             immutable /assets mount (run assets:precompile and restart to enable it)",
            public.join("assets").display(),
            public.display()
        );
    }
    Ok(ServeRailsPlan {
        root,
        static_dir: Some(public),
        static_assets,
        static_overridden: false,
    })
}

/// The explicit static-preset dir (CLI, else env twin) — resolved ONCE in `run_with_cli`
/// and shared by `plan_serve_rails` (override detection) and `read_static_mounts`.
fn read_static_rails_preset(cli: &crate::EdgeCliConfig) -> Result<Option<PathBuf>, EdgeError> {
    match &cli.static_rails_preset {
        Some(path) => Ok(Some(path.clone())),
        None => match env::var("OXO_EDGE_STATIC_RAILS_PRESET") {
            Ok(raw) if !raw.trim().is_empty() => Ok(Some(PathBuf::from(raw.trim()))),
            Ok(_) | Err(env::VarError::NotPresent) => Ok(None),
            Err(err) => Err(EdgeError::ConfigEnv {
                name: "OXO_EDGE_STATIC_RAILS_PRESET",
                message: err.to_string(),
            }),
        },
    }
}

/// static serving: parse `--static-mount` specs plus the Rails preset sugar via
/// crenel's canonical parser. CLI wins; env fallbacks follow the house pattern
/// (`OXO_EDGE_STATIC_MOUNTS` = semicolon-separated specs — specs use commas
/// internally). Fail-closed — a typo'd spec must stop the edge at boot, never silently
/// weaken policy. : derived specs are attributed to their SOURCE knob in parse
/// errors (panel P9), and the serve-rails plan contributes its derived mounts here.
fn read_static_mounts(
    cli: &crate::EdgeCliConfig,
    rails_preset: Option<PathBuf>,
    serve_rails: Option<&ServeRailsPlan>,
) -> Result<Vec<crenel_pingora::MountSpec>, EdgeError> {
    let mut raw_specs: Vec<(String, &'static str)> = cli
        .static_mounts
        .iter()
        .map(|spec| (spec.clone(), "OXO_EDGE_STATIC_MOUNTS"))
        .collect();
    if raw_specs.is_empty() {
        match env::var("OXO_EDGE_STATIC_MOUNTS") {
            Ok(raw) => {
                raw_specs = raw
                    .split(';')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(|part| (part.to_owned(), "OXO_EDGE_STATIC_MOUNTS"))
                    .collect();
            }
            Err(env::VarError::NotPresent) => {}
            Err(err) => {
                return Err(EdgeError::ConfigEnv {
                    name: "OXO_EDGE_STATIC_MOUNTS",
                    message: err.to_string(),
                })
            }
        }
    }
    let derived = match (&rails_preset, serve_rails) {
        // Explicit preset dir wins for the mounts (fail-closed as today: no existence
        // softening for explicit config), whether or not serve-rails is active.
        (Some(dir), _) => Some((dir.clone(), true, "--static-rails-preset")),
        // serve-rails derivation (already existence-checked by plan_serve_rails).
        (None, Some(plan)) => plan
            .static_dir
            .as_ref()
            .filter(|_| !plan.static_overridden)
            .map(|public| (public.clone(), plan.static_assets, "--serve-rails")),
        (None, None) => None,
    };
    if let Some((public_dir, with_assets, source)) = derived {
        let public_dir = public_dir.display();
        if with_assets {
            // Fingerprinted assets: strict 404 (no Rack probe traffic), immutable caching.
            raw_specs.push((
                format!(
                    "/assets={public_dir}/assets,cache-control=public%2Cmax-age=31536000%2Cimmutable"
                ),
                source,
            ));
        }
        // Rails public/ root: fallthrough (dynamic routes share the / path space).
        raw_specs.push((format!("/={public_dir},fallthrough"), source));
    }
    // M2 (diagnosis artifact): emit the RESOLVED mount table. Which prefixes are mounted
    // decides whether a dynamic route is a crenel *Candidate* — a `/` fallthrough mount has an
    // empty prefix, so its prefix-match is vacuously true and EVERY request becomes a candidate
    // (crenel then runs check_repin's stat + open_rel per request). That fact silently invalidated
    // a optimization premise; the mount table must be visible in the artifacts, not inferred
    // from reading this function. Operator-useful too: `static=<dir>` alone never showed the shape.
    if raw_specs.is_empty() {
        eprintln!("oxo_edge_config_notice static-mounts: (none)");
    } else {
        let table: Vec<&str> = raw_specs.iter().map(|(raw, _)| raw.as_str()).collect();
        eprintln!(
            "oxo_edge_config_notice static-mounts: {} mount(s): {}",
            table.len(),
            table.join(" | ")
        );
    }
    let mut mounts = Vec::with_capacity(raw_specs.len());
    for (raw, source) in raw_specs {
        mounts.push(crenel_pingora::MountSpec::parse(&raw).map_err(|message| {
            EdgeError::ConfigEnv {
                name: source,
                message,
            }
        })?);
    }
    Ok(mounts)
}

fn reject_socket_activation_env() -> Result<(), EdgeError> {
    if let Some(name) = socket_activation_env_name(env::var_os) {
        return Err(EdgeError::ConfigEnv {
            name,
            message: "systemd socket activation and inherited listener descriptors are not supported; configure explicit --http-bind/--https-bind or external port mapping instead".to_string(),
        });
    }
    Ok(())
}

pub fn socket_activation_env_name<F>(mut getenv: F) -> Option<&'static str>
where
    F: FnMut(&'static str) -> Option<OsString>,
{
    SOCKET_ACTIVATION_ENV
        .iter()
        .copied()
        .find(|name| getenv(name).is_some_and(|value| !value.as_os_str().is_empty()))
}

fn run_acme_issue_once(cli: crate::EdgeCliConfig) -> Result<(), EdgeError> {
    #[cfg(feature = "acme")]
    {
        let config = crate::acme::AcmeIssueConfig::from_edge_cli(&cli)?;
        let runtime = acme_runtime()?;
        runtime.block_on(crate::acme::issue_once_with_instant_acme(config))?;
        Ok(())
    }
    #[cfg(not(feature = "acme"))]
    {
        let _ = cli;
        Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_ACME_STATE_PATH",
            message:
                "ACME issuance requested but oxo-pingora-edge was built without the acme feature"
                    .to_string(),
        })
    }
}

fn run_acme_renew_once(cli: crate::EdgeCliConfig) -> Result<(), EdgeError> {
    #[cfg(feature = "acme")]
    {
        let config = crate::acme::AcmeIssueConfig::from_edge_cli(&cli)?;
        let runtime = acme_runtime()?;
        runtime.block_on(crate::acme::renew_once_with_instant_acme(config))?;
        Ok(())
    }
    #[cfg(not(feature = "acme"))]
    {
        let _ = cli;
        Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_ACME_STATE_PATH",
            message:
                "ACME renewal requested but oxo-pingora-edge was built without the acme feature"
                    .to_string(),
        })
    }
}

#[cfg(feature = "acme")]
fn acme_runtime() -> Result<tokio::runtime::Runtime, EdgeError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| EdgeError::Acme {
            message: format!("failed to build ACME runtime: {err}"),
        })
}
fn read_bind(cli: &crate::EdgeCliConfig) -> Result<(SocketAddr, BindKind), EdgeError> {
    match (cli.http_bind, cli.https_bind) {
        (Some(_), Some(_)) => Err(EdgeError::ConfigEnv {
            name: "argv",
            message: "--http-bind and --https-bind are mutually exclusive until the ACME dual-listener milestone".to_string(),
        }),
        (Some(bind), None) => Ok((bind, BindKind::Http)),
        (None, Some(bind)) => Ok((bind, BindKind::Https)),
        (None, None) => {
            let bind = read_env("OXO_EDGE_BIND")?
                .parse()
                .map_err(|err| EdgeError::ConfigEnv {
                    name: "OXO_EDGE_BIND",
                    message: format!("expected loopback socket address: {err}"),
                })?;
            let tls = env_bool("OXO_EDGE_TLS", false)?;
            Ok((bind, if tls { BindKind::Https } else { BindKind::Http }))
        }
    }
}

fn read_max_body(cli: &crate::EdgeCliConfig) -> Result<(u64, bool), EdgeError> {
    if let Some(max_body_bytes) = cli.max_body_bytes {
        return Ok((max_body_bytes, true));
    }
    match env::var("OXO_EDGE_MAX_BODY") {
        Ok(raw) => raw
            .parse()
            .map(|value| (value, true))
            .map_err(|err| EdgeError::ConfigEnv {
                name: "OXO_EDGE_MAX_BODY",
                message: format!("expected integer byte count: {err}"),
            }),
        Err(env::VarError::NotPresent) => Ok((crate::DEFAULT_MAX_BODY_BYTES, false)),
        Err(err) => Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_MAX_BODY",
            message: err.to_string(),
        }),
    }
}

fn read_server_name(cli: &crate::EdgeCliConfig) -> Result<(String, bool), EdgeError> {
    if let Some(name) = &cli.fqdn {
        if name.trim().is_empty() {
            return Err(EdgeError::ConfigEnv {
                name: "argv",
                message: "--fqdn must not be empty".to_string(),
            });
        }
        return Ok((name.clone(), true));
    }
    match env::var("OXO_EDGE_SERVER_NAME") {
        Ok(name) if !name.trim().is_empty() => Ok((name, true)),
        Ok(_) => Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_SERVER_NAME",
            message: "must not be empty".to_string(),
        }),
        Err(env::VarError::NotPresent) => Ok(("localhost".to_string(), false)),
        Err(err) => Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_SERVER_NAME",
            message: err.to_string(),
        }),
    }
}

fn read_public_origin_port(cli: &crate::EdgeCliConfig) -> Result<Option<u16>, EdgeError> {
    if let Some(port) = cli.public_origin_port {
        return Ok(Some(port));
    }
    match env::var("OXO_EDGE_PUBLIC_ORIGIN_PORT") {
        Ok(raw) if raw.trim().is_empty() => Ok(None),
        Ok(raw) => raw.parse().map(Some).map_err(|err| EdgeError::ConfigEnv {
            name: "OXO_EDGE_PUBLIC_ORIGIN_PORT",
            message: format!("expected integer port: {err}"),
        }),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_PUBLIC_ORIGIN_PORT",
            message: err.to_string(),
        }),
    }
}

fn validate_future_acme_state_path(cli: &crate::EdgeCliConfig) -> Result<(), EdgeError> {
    let path = match &cli.acme_state_path {
        Some(path) => Some(path.clone()),
        None => optional_path_env("OXO_EDGE_ACME_STATE_PATH")?,
    };
    if let Some(path) = path {
        if !path.is_absolute() {
            return Err(EdgeError::ConfigEnv {
                name: "OXO_EDGE_ACME_STATE_PATH",
                message: "ACME state path must be absolute".to_string(),
            });
        }
    }
    Ok(())
}

fn read_certificate_admin_json(cli: &crate::EdgeCliConfig) -> Result<Option<String>, EdgeError> {
    let Some(path) = cli
        .acme_state_path
        .clone()
        .or(optional_path_env("OXO_EDGE_ACME_STATE_PATH")?)
    else {
        return Ok(None);
    };
    #[cfg(feature = "acme")]
    {
        crate::acme::certificate_lifecycle_admin_json(&path)
            .map(Some)
            .map_err(EdgeError::from)
    }
    #[cfg(not(feature = "acme"))]
    {
        let _ = path;
        Ok(None)
    }
}

/// ladder: explicit CLI > explicit env > serve-rails preset (true) > default false.
/// `optional_bool_env` (not `env_bool`) so an explicitly-set `OXO_EDGE_SSE=0` beats
/// the preset while an UNSET env falls through to it.
fn read_sse_enabled(
    cli: &crate::EdgeCliConfig,
    serve_rails_active: bool,
) -> Result<bool, EdgeError> {
    match cli.sse_enabled {
        Some(value) => Ok(value),
        None => match optional_bool_env("OXO_EDGE_SSE")? {
            Some(value) => Ok(value),
            None => Ok(serve_rails_active),
        },
    }
}

/// ladder (lever 2): explicit CLI > explicit env > default false (DEV live-probe).
/// Unlike SSE, `--prod` has NO serve-rails coupling — serve-rails is the dev-ergonomics
/// preset (hot-reload), so it must never silently flip on production static-routing. The
/// returned source string feeds the boot posture line so an operator can tell an explicit
/// `--prod` from the default. Value = "is production static-routing (boot-pinned) on?".
fn read_prod_enabled(cli: &crate::EdgeCliConfig) -> Result<(bool, &'static str), EdgeError> {
    match cli.prod_enabled {
        Some(value) => Ok((value, "--prod")),
        None => match optional_bool_env("OXO_EDGE_PROD")? {
            Some(value) => Ok((value, "OXO_EDGE_PROD")),
            None => Ok((false, "default-dev")),
        },
    }
}

/// resolved Pingora proxy-service worker-thread count plus provenance — the
/// posture line states the source so an operator can tell an explicit pin from the
/// nproc default, and `nproc` is kept so above-nproc experimentation is flagged.
#[derive(Debug)]
pub(super) struct EdgeThreadsConfig {
    pub(super) threads: usize,
    pub(super) source: &'static str, // "default-nproc" | "--edge-threads" | "OXO_EDGE_THREADS"
    pub(super) nproc: usize,
}

/// resolved parallel-accept task count per listening fd, plus provenance.
#[derive(Debug)]
pub(super) struct ListenerTasksConfig {
    pub(super) tasks: usize,
    pub(super) source: &'static str, // "default" | "--listener-tasks" | "OXO_EDGE_LISTENER_TASKS"
}

/// ceiling for `--listener-tasks`. Each accept task is a long-lived Tokio task per
/// listening fd; beyond low double digits they only contend on the same accept queue, and
/// an unbounded typo would spawn a task storm at bootstrap. 64 covers any plausible
/// experiment on real hardware.
const MAX_LISTENER_TASKS: u64 = 64;

/// (ROADMAP 1b): parallel accepts per listening socket. Pingora's default of 1 means a
/// single task performs every accept — fine at steady keepalive traffic, the bottleneck
/// candidate under connection churn (the regime the ladder bench never measures). Default
/// stays 1 so behavior is unchanged unless an operator opts in; SO_REUSEPORT-style process
/// fan-out remains rejected because it would fragment the single-process security counters.
fn read_listener_tasks(cli: &crate::EdgeCliConfig) -> Result<ListenerTasksConfig, EdgeError> {
    let (value, name) = match cli.listener_tasks {
        Some(value) => (Some(value), "--listener-tasks"),
        None => (
            optional_u64_env("OXO_EDGE_LISTENER_TASKS")?,
            "OXO_EDGE_LISTENER_TASKS",
        ),
    };
    match value {
        None => Ok(ListenerTasksConfig {
            tasks: 1,
            source: "default",
        }),
        Some(0) => Err(EdgeError::ConfigEnv {
            name,
            message: "value must be greater than zero".to_string(),
        }),
        Some(v) if v > MAX_LISTENER_TASKS => Err(EdgeError::ConfigEnv {
            name,
            message: format!(
                "value must be at most {MAX_LISTENER_TASKS} (each is a long-lived accept                  task per listening socket; more only contend on the accept queue)"
            ),
        }),
        Some(v) => Ok(ListenerTasksConfig {
            tasks: v as usize,
            source: name,
        }),
    }
}

/// ceiling for `--edge-threads`. Tokio eagerly spawns this many OS threads at
/// bootstrap, so an unbounded typo (e.g. 1000000) would wedge/OOM the public front
/// door mid-boot with an unactionable panic instead of a named config error.
const MAX_EDGE_THREADS: u64 = 1024;

/// the edge is a non-blocking event loop — parallelism (TLS handshakes, parsing,
/// proxying) is bounded by worker threads while concurrency comes from tasks — so the
/// default is nproc, not a multiple (oversubscription only buys context-switch/cache
/// churn). Pingora's own default of 1 was the `/bench` ceiling. Values above nproc
/// (≤ the cap) are allowed for experimentation and flagged in the posture line.
fn read_edge_threads(cli: &crate::EdgeCliConfig) -> Result<EdgeThreadsConfig, EdgeError> {
    let (value, name) = match cli.edge_threads {
        Some(value) => (Some(value), "--edge-threads"),
        None => (optional_u64_env("OXO_EDGE_THREADS")?, "OXO_EDGE_THREADS"),
    };
    let nproc = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    match value {
        // (owner-approved flip, evidence): on hosts with <= 2 cores the
        // edge and the workers fight for the same cores, and the measured winner is
        // ONE edge thread (p2e1 beat the 2-edge-thread shape in all eight paired
        // comparisons: tail -0.8..-1.5 ms AND +5.6..+6.7% rps; the edge was the
        // most oversubscribed thread class at delay/cpu 2.33). Hosts with >= 3
        // cores keep the nproc default -- unmeasured territory stays unchanged.
        None if nproc <= 2 => Ok(EdgeThreadsConfig {
            threads: nproc.saturating_sub(1).max(1),
            source: "default-small-host",
            nproc,
        }),
        None => Ok(EdgeThreadsConfig {
            threads: nproc,
            source: "default-nproc",
            nproc,
        }),
        Some(0) => Err(EdgeError::ConfigEnv {
            name,
            message: "value must be greater than zero".to_string(),
        }),
        Some(v) if v > MAX_EDGE_THREADS => Err(EdgeError::ConfigEnv {
            name,
            message: format!(
                "value must be at most {MAX_EDGE_THREADS} (each edge worker thread is a \
                 real OS thread spawned eagerly at bootstrap)"
            ),
        }),
        Some(v) => Ok(EdgeThreadsConfig {
            threads: v as usize,
            source: name,
            nproc,
        }),
    }
}

/// resolve the per-request stderr log posture. Default `rejections` — the
/// hot-path `response` line off (its syscall+lock+allocs were the entire observable
/// /bench logging cost), the rejection-class forensic lines on (the hardened front
/// door's only per-request attack record; low-rate in production, off the hot path).
/// resolve the edge↔worker hop wire format. Default `frame` (the pooled binary
/// pre-parsed hop). In frame mode the codec's length fields are u32, so a
/// `max_body_bytes` above u32::MAX is rejected here with a named error rather than
/// silently truncated on the wire (the panel length-domain guard).
fn read_worker_hop(
    cli: &crate::EdgeCliConfig,
    max_body_bytes: u64,
) -> Result<(WorkerHop, &'static str), EdgeError> {
    let (value, name, source) = match &cli.worker_hop {
        Some(value) => (Some(value.clone()), "--worker-hop", "cli"),
        None => (
            optional_string_env("OXO_EDGE_WORKER_HOP")?,
            "OXO_EDGE_WORKER_HOP",
            "env",
        ),
    };
    let (hop, source) = match value.as_deref() {
        None => (WorkerHop::Frame, "default"),
        Some("frame") => (WorkerHop::Frame, source),
        Some("http") => (WorkerHop::Http, source),
        Some(other) => {
            return Err(EdgeError::ConfigEnv {
                name,
                message: format!("expected frame|http, got {other:?}"),
            })
        }
    };
    if hop == WorkerHop::Frame && max_body_bytes > u64::from(u32::MAX) {
        return Err(EdgeError::ConfigEnv {
            name,
            message: format!(
                "worker-hop=frame requires max-body <= {} (frame length fields are 32-bit); \
                 got {max_body_bytes}",
                u32::MAX
            ),
        });
    }
    Ok((hop, source))
}

/// W0: the worker kind behind this edge (env-only — the service supervisor forwards
/// it; there is no CLI twin because an operator never sets it directly on the edge).
/// Fails closed on an unknown value; default classic.
fn read_worker_kind() -> Result<super::frame_hop::worker_kind::WorkerKind, EdgeError> {
    use super::frame_hop::worker_kind::{parse_kind, WorkerKind};
    match optional_string_env("OXO_WORKER_KIND")?.as_deref() {
        None => Ok(WorkerKind::Classic),
        Some(v) => parse_kind(v).ok_or_else(|| EdgeError::ConfigEnv {
            name: "OXO_WORKER_KIND",
            message: format!("expected classic|async, got {v:?}"),
        }),
    }
}

/// M4: the dispatch-discipline ladder (flag > env > default least-outstanding).
/// Fail-closed guard (panel MED-9): the in-flight gauges have MAX_WORKERS=16 slots; a
/// larger fleet under a depth-reading mode would silently share slots and corrupt the
/// selector's input, so anything except `rr` is refused above 16 workers.
/// resolve the per-worker admission cap (flag > env > default OFF), fail-closed.
/// K = 0 is refused (use no flag for uncapped); with a global in-flight cap set,
/// K x worker_count must be strictly below it — parked requests hold global slots, so
/// an oversized K could fill the global cap with parked work and deadlock admission.
/// Without a global cap (the bench default) the constraint is vacuous and K stands.
fn read_worker_cap(
    cli: &crate::EdgeCliConfig,
    worker_count: usize,
    global_max: Option<u64>,
) -> Result<Option<usize>, EdgeError> {
    let (value, name) = match cli.worker_cap {
        Some(v) => (Some(v), "--worker-cap"),
        None => (
            optional_u64_env("OXO_EDGE_WORKER_CAP")?,
            "OXO_EDGE_WORKER_CAP",
        ),
    };
    let Some(k) = value else { return Ok(None) };
    if k == 0 {
        return Err(EdgeError::ConfigEnv {
            name,
            message: "worker cap must be >= 1 (omit the flag for uncapped)".to_string(),
        });
    }
    if worker_count > super::frame_hop::dispatch::MAX_WORKERS {
        return Err(EdgeError::ConfigEnv {
            name,
            message: format!(
                "worker cap supports at most {} workers (gauge slots); got {worker_count}",
                super::frame_hop::dispatch::MAX_WORKERS
            ),
        });
    }
    if let Some(g) = global_max {
        let total = k.saturating_mul(worker_count as u64);
        if total >= g {
            return Err(EdgeError::ConfigEnv {
                name,
                message: format!(
                    "worker cap {k} x {worker_count} workers = {total} must be strictly \
                     below the global in-flight cap {g} (parked requests hold global \
                     slots; an oversized cap deadlocks admission)"
                ),
            });
        }
    }
    Ok(Some(k as usize))
}

fn read_worker_dispatch(
    cli: &crate::EdgeCliConfig,
    worker_count: usize,
) -> Result<(super::frame_hop::dispatch::DispatchMode, &'static str), EdgeError> {
    use super::frame_hop::dispatch::{parse_mode, DispatchMode, MAX_WORKERS};
    let (value, name, source) = match &cli.worker_dispatch {
        Some(value) => (Some(value.clone()), "--worker-dispatch", "cli"),
        None => (
            optional_string_env("OXO_WORKER_DISPATCH")?,
            "OXO_WORKER_DISPATCH",
            "env",
        ),
    };
    let (mode, source) = match value.as_deref() {
        None => (DispatchMode::LeastOutstanding, "default"),
        Some(v) => match parse_mode(v) {
            Some(m) => (m, source),
            None => {
                return Err(EdgeError::ConfigEnv {
                    name,
                    message: format!("expected least-outstanding|rr|free-first|sticky, got {v:?}"),
                })
            }
        },
    };
    if mode != DispatchMode::Rr && worker_count > MAX_WORKERS {
        return Err(EdgeError::ConfigEnv {
            name,
            message: format!(
                "worker-dispatch={} supports at most {MAX_WORKERS} workers (in-flight                  gauge slots); got {worker_count}. Use rr for larger fleets.",
                super::frame_hop::dispatch::mode_name(mode)
            ),
        });
    }
    Ok((mode, source))
}

fn read_request_log(
    cli: &crate::EdgeCliConfig,
) -> Result<(RequestLogMode, &'static str), EdgeError> {
    let (value, name, source) = match &cli.request_log {
        Some(value) => (Some(value.clone()), "--request-log", "cli"),
        None => (
            optional_string_env("OXO_EDGE_REQUEST_LOG")?,
            "OXO_EDGE_REQUEST_LOG",
            "env",
        ),
    };
    match value.as_deref() {
        None => Ok((RequestLogMode::Rejections, "default")),
        Some("off") => Ok((RequestLogMode::Off, source)),
        Some("rejections") => Ok((RequestLogMode::Rejections, source)),
        Some("all") => Ok((RequestLogMode::All, source)),
        Some(other) => Err(EdgeError::ConfigEnv {
            name,
            message: format!("expected off|rejections|all, got {other:?}"),
        }),
    }
}

fn read_edge_drain_config(cli: &crate::EdgeCliConfig) -> Result<EdgeDrainConfig, EdgeError> {
    let (name, millis) = match cli.drain_grace_ms {
        Some(value) => ("--drain-grace-ms", value),
        None => match optional_u64_env("OXO_EDGE_DRAIN_GRACE_MS")? {
            Some(value) => ("OXO_EDGE_DRAIN_GRACE_MS", value),
            None => ("OXO_EDGE_DRAIN_GRACE_MS", DEFAULT_EDGE_DRAIN_GRACE_MS),
        },
    };
    EdgeDrainConfig::from_millis(name, millis)
}

fn read_grpc_bind(cli: &crate::EdgeCliConfig) -> Result<Option<SocketAddr>, EdgeError> {
    let bind = match cli.grpc_bind {
        Some(bind) => Some(bind),
        None => match env::var("OXO_EDGE_GRPC_BIND") {
            Ok(raw) if raw.trim().is_empty() => None,
            Ok(raw) => Some(
                raw.parse::<SocketAddr>()
                    .map_err(|err| EdgeError::ConfigEnv {
                        name: "OXO_EDGE_GRPC_BIND",
                        message: format!("expected loopback socket address: {err}"),
                    })?,
            ),
            Err(env::VarError::NotPresent) => None,
            Err(err) => {
                return Err(EdgeError::ConfigEnv {
                    name: "OXO_EDGE_GRPC_BIND",
                    message: err.to_string(),
                })
            }
        },
    };
    if let Some(bind) = bind {
        if !bind.ip().is_loopback() {
            return Err(EdgeError::ConfigEnv {
                name: "OXO_EDGE_GRPC_BIND",
                message: "gRPC sidecar bind must be loopback/private".to_string(),
            });
        }
    }
    Ok(bind)
}

fn read_env(name: &'static str) -> Result<String, EdgeError> {
    env::var(name).map_err(|err| EdgeError::ConfigEnv {
        name,
        message: err.to_string(),
    })
}

pub(super) enum ListenerMode {
    Plain,
    #[cfg(feature = "tls-rustls")]
    Tls {
        cert_path: PathBuf,
        key_path: PathBuf,
        h2: bool,
    },
}

impl ListenerMode {
    fn url_scheme(&self) -> &'static str {
        match self {
            ListenerMode::Plain => "http",
            #[cfg(feature = "tls-rustls")]
            ListenerMode::Tls { .. } => "https",
        }
    }

    fn is_tls(&self) -> bool {
        match self {
            ListenerMode::Plain => false,
            #[cfg(feature = "tls-rustls")]
            ListenerMode::Tls { .. } => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PublicMode {
    Alpha,
    SmokeBeta,
}

impl PublicMode {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "alpha" => Some(Self::Alpha),
            "smoke-beta" | "beta" => Some(Self::SmokeBeta),
            _ => None,
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::SmokeBeta => "smoke-beta",
        }
    }

    fn requires_admin_health(self) -> bool {
        matches!(self, Self::SmokeBeta)
    }
}

fn read_listener_mode(
    cli: &crate::EdgeCliConfig,
    bind_kind: BindKind,
) -> Result<ListenerMode, EdgeError> {
    let cli_requests_tls =
        matches!(bind_kind, BindKind::Https) || cli.tls_cert.is_some() || cli.tls_key.is_some();
    let env_tls_allowed = cli.http_bind.is_none()
        && cli.https_bind.is_none()
        && cli.tls_cert.is_none()
        && cli.tls_key.is_none();
    let tls_requested = cli_requests_tls || (env_tls_allowed && env_bool("OXO_EDGE_TLS", false)?);
    if !tls_requested {
        return Ok(ListenerMode::Plain);
    }
    #[cfg(not(feature = "tls-rustls"))]
    {
        Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_TLS",
            message: "TLS requested but oxo-pingora-edge was built without the tls-rustls feature"
                .to_string(),
        })
    }
    #[cfg(feature = "tls-rustls")]
    {
        let cert_path = match &cli.tls_cert {
            Some(path) => path.clone(),
            None => {
                optional_path_env("OXO_EDGE_TLS_CERT")?.ok_or_else(|| EdgeError::ConfigEnv {
                    name: "OXO_EDGE_TLS_CERT",
                    message: "TLS requires a certificate path".to_string(),
                })?
            }
        };
        let key_path = match &cli.tls_key {
            Some(path) => path.clone(),
            None => optional_path_env("OXO_EDGE_TLS_KEY")?.ok_or_else(|| EdgeError::ConfigEnv {
                name: "OXO_EDGE_TLS_KEY",
                message: "TLS requires a private key path".to_string(),
            })?,
        };
        validate_tls_file("certificate", &cert_path, false)?;
        validate_tls_file("private key", &key_path, true)?;
        let h2 = match cli.tls_h2 {
            Some(value) => value,
            None => env_bool("OXO_EDGE_TLS_H2", true)?,
        };
        Ok(ListenerMode::Tls {
            cert_path,
            key_path,
            h2,
        })
    }
}
/// like `env_bool` but preserves UNSET as `None` so a preset can supply the
/// default while an explicitly-set env value still wins. Empty string = unset (the
/// `optional_string_env` contract).
fn optional_bool_env(name: &'static str) -> Result<Option<bool>, EdgeError> {
    match env::var(name) {
        Ok(raw) if raw.trim().is_empty() => Ok(None),
        Ok(raw) => match raw.as_str() {
            "1" | "true" | "TRUE" | "yes" | "YES" => Ok(Some(true)),
            "0" | "false" | "FALSE" | "no" | "NO" => Ok(Some(false)),
            _ => Err(EdgeError::ConfigEnv {
                name,
                message: format!("expected boolean, got {raw:?}"),
            }),
        },
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(EdgeError::ConfigEnv {
            name,
            message: err.to_string(),
        }),
    }
}

fn env_bool(name: &'static str, default: bool) -> Result<bool, EdgeError> {
    match env::var(name) {
        Ok(raw) => match raw.as_str() {
            "1" | "true" | "TRUE" | "yes" | "YES" => Ok(true),
            "0" | "false" | "FALSE" | "no" | "NO" => Ok(false),
            _ => Err(EdgeError::ConfigEnv {
                name,
                message: format!("expected boolean, got {raw:?}"),
            }),
        },
        Err(env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(EdgeError::ConfigEnv {
            name,
            message: err.to_string(),
        }),
    }
}

fn read_worker_sockets(cli: &crate::EdgeCliConfig) -> Result<Vec<PathBuf>, EdgeError> {
    if !cli.worker_sockets.is_empty() {
        return Ok(cli.worker_sockets.clone());
    }
    match env::var("OXO_EDGE_WORKER_SOCKETS") {
        Ok(raw) => {
            let sockets = raw
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            if sockets.is_empty() {
                Err(EdgeError::ConfigEnv {
                    name: "OXO_EDGE_WORKER_SOCKETS",
                    message: "expected at least one comma-separated socket path".to_string(),
                })
            } else {
                Ok(sockets)
            }
        }
        Err(env::VarError::NotPresent) => {
            Ok(vec![PathBuf::from(read_env("OXO_EDGE_WORKER_SOCKET")?)])
        }
        Err(err) => Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_WORKER_SOCKETS",
            message: err.to_string(),
        }),
    }
}
fn read_public_mode_gate(
    bind: SocketAddr,
    listener: &ListenerMode,
    cli: &crate::EdgeCliConfig,
    max_body_explicit: bool,
    server_name_explicit: bool,
) -> Result<Option<PublicMode>, EdgeError> {
    if bind.ip().is_loopback() {
        // D4: public-mode gating (identity policy, trusted-proxy CIDR trust, FQDN/SAN
        // validation) only runs for a non-loopback bind. Historically a loopback bind
        // returned `Ok(None)` here WITHOUT inspecting these flags, so an operator who
        // typed `--public-mode smoke-beta --public-identity trusted-proxy
        // --trusted-proxy-cidr ...` on a loopback bind got silent DirectPublic
        // semantics with no error. Refuse instead of pretending. Note: TLS,
        // server-name, per-identity fairness, and long-lived caps DO take effect on
        // loopback (loopback TLS, loopback fairness/long-lived), so they are
        // deliberately NOT in this fail-closed set.
        let public_mode_set =
            cli.public_mode.is_some() || optional_string_env("OXO_EDGE_PUBLIC_MODE")?.is_some();
        let identity_set = cli.public_identity.is_some()
            || optional_string_env("OXO_EDGE_PUBLIC_IDENTITY")?.is_some();
        let cidrs_set = !cli.trusted_proxy_cidrs.is_empty()
            || optional_string_env("OXO_EDGE_TRUSTED_PROXY_CIDRS")?.is_some();
        if public_mode_set || identity_set || cidrs_set {
            return Err(EdgeError::ConfigEnv {
                name: "OXO_EDGE_PUBLIC_MODE",
                message: "public-mode, public-identity, and trusted-proxy-cidr are only \
                          honored on a non-loopback bind; refusing to start with any of \
                          them set on a loopback bind because they would be silently \
                          ignored"
                    .to_string(),
            });
        }
        // production-ACME consent on a loopback bind is equally inert —
        // production HTTP-01 can never validate a loopback host.
        let production_ack_set = cli.acme_allow_production_directory
            || env_bool("OXO_EDGE_ACME_ALLOW_PRODUCTION_DIRECTORY", false)?;
        if production_ack_set {
            return Err(EdgeError::ConfigEnv {
                name: "OXO_EDGE_ACME_ALLOW_PRODUCTION_DIRECTORY",
                message: "the production ACME consent flag is only honored for public \
                          issuance; refusing to start with it set on a loopback bind"
                    .to_string(),
            });
        }
        return Ok(None);
    }

    let raw_mode = match &cli.public_mode {
        Some(mode) => Some(mode.clone()),
        None => optional_string_env("OXO_EDGE_PUBLIC_MODE")?,
    };
    let Some(raw_mode) = raw_mode else {
        return Ok(None);
    };
    let mode = PublicMode::parse(&raw_mode).ok_or_else(|| EdgeError::ConfigEnv {
        name: "OXO_EDGE_PUBLIC_MODE",
        message: "expected alpha or smoke-beta for non-loopback Pingora bind".to_string(),
    })?;
    if !max_body_explicit {
        return Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_MAX_BODY",
            message: "public mode requires an explicit request body cap".to_string(),
        });
    }
    if !listener.is_tls() {
        return Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_TLS",
            message: "public mode requires TLS".to_string(),
        });
    }

    if !server_name_explicit {
        return Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_SERVER_NAME",
            message: "public mode requires an explicit server name".to_string(),
        });
    }
    Ok(Some(mode))
}

fn read_public_identity_policy(
    public_mode: Option<PublicMode>,
    cli: &crate::EdgeCliConfig,
) -> Result<crate::PublicIdentityPolicy, EdgeError> {
    if public_mode.is_none() {
        return Ok(crate::PublicIdentityPolicy::DirectPublic);
    }
    let identity = match &cli.public_identity {
        Some(identity) => Some(identity.clone()),
        None => optional_string_env("OXO_EDGE_PUBLIC_IDENTITY")?,
    };
    match identity.as_deref() {
        Some("direct-public") => Ok(crate::PublicIdentityPolicy::DirectPublic),
        Some("trusted-proxy") => {
            let cidrs = read_trusted_proxy_cidrs(cli)?;
            let policy = crate::TrustedProxyPolicy::parse_all(&cidrs).map_err(|message| {
                EdgeError::ConfigEnv {
                    name: "OXO_EDGE_TRUSTED_PROXY_CIDRS",
                    message,
                }
            })?;
            Ok(crate::PublicIdentityPolicy::TrustedProxy(policy))
        }
        Some(identity) => Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_PUBLIC_IDENTITY",
            message: format!("expected direct-public or trusted-proxy, got {identity:?}"),
        }),
        None => Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_PUBLIC_IDENTITY",
            message: "public mode requires direct-public or trusted-proxy identity policy"
                .to_string(),
        }),
    }
}

fn read_trusted_proxy_cidrs(cli: &crate::EdgeCliConfig) -> Result<Vec<String>, EdgeError> {
    if !cli.trusted_proxy_cidrs.is_empty() {
        return Ok(cli.trusted_proxy_cidrs.clone());
    }
    match optional_string_env("OXO_EDGE_TRUSTED_PROXY_CIDRS")? {
        Some(raw) => Ok(raw
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect()),
        None => Ok(Vec::new()),
    }
}

fn read_identity_fairness(
    public_mode: Option<PublicMode>,
    cli: &crate::EdgeCliConfig,
) -> Result<Arc<IdentityFairnessLimiter>, EdgeError> {
    let (configured, configured_name) = match cli.max_in_flight_per_identity {
        Some(value) => (Some(value), "--max-in-flight-per-identity"),
        None => (
            optional_u64_env("OXO_EDGE_MAX_IN_FLIGHT_PER_IDENTITY")?,
            "OXO_EDGE_MAX_IN_FLIGHT_PER_IDENTITY",
        ),
    };
    let max_per_identity = match configured {
        Some(0) => {
            return Err(EdgeError::ConfigEnv {
                name: configured_name,
                message: "max in-flight per identity must be greater than zero".to_string(),
            })
        }
        Some(value) => Some(value),
        None if public_mode.is_some() => Some(DEFAULT_PUBLIC_MAX_IN_FLIGHT_PER_IDENTITY),
        None => None,
    };
    Ok(Arc::new(IdentityFairnessLimiter::new(max_per_identity)))
}

fn read_global_in_flight(
    public_mode: Option<PublicMode>,
    cli: &crate::EdgeCliConfig,
    fairness: &Arc<IdentityFairnessLimiter>,
) -> Result<Arc<GlobalInFlightLimiter>, EdgeError> {
    let (configured, configured_name) = match cli.max_in_flight_requests {
        Some(value) => (Some(value), "--max-in-flight-requests"),
        None => (
            optional_u64_env("OXO_EDGE_MAX_IN_FLIGHT_REQUESTS")?,
            "OXO_EDGE_MAX_IN_FLIGHT_REQUESTS",
        ),
    };
    let max_requests = match configured {
        Some(0) => {
            return Err(EdgeError::ConfigEnv {
                name: configured_name,
                message: "global max in-flight requests must be greater than zero".to_string(),
            })
        }
        Some(value) => Some(value),
        None if matches!(public_mode, Some(PublicMode::SmokeBeta)) => {
            return Err(EdgeError::ConfigEnv {
                name: "OXO_EDGE_MAX_IN_FLIGHT_REQUESTS",
                message: "smoke-beta public mode requires an explicit global request cap"
                    .to_string(),
            })
        }
        None => None,
    };
    if let (Some(global), Some(per_identity)) = (max_requests, fairness.snapshot().max_per_identity)
    {
        if per_identity >= global {
            eprintln!(
                "oxo_edge_config_warning OXO_EDGE_MAX_IN_FLIGHT_REQUESTS={} can be monopolized by one identity because max_in_flight_per_identity={} is not lower",
                global, per_identity
            );
        }
    }
    Ok(Arc::new(GlobalInFlightLimiter::new(max_requests)))
}

fn read_slow_client_policy(
    cli: &crate::EdgeCliConfig,
    serve_rails_active: bool,
) -> Result<SlowClientPolicy, EdgeError> {
    let header_read_timeout_ms = required_nonzero_u64(
        cli.header_read_timeout_ms,
        "--header-read-timeout-ms",
        "OXO_EDGE_HEADER_READ_TIMEOUT_MS",
        DEFAULT_HEADER_READ_TIMEOUT_MS,
    )?;
    let keepalive_idle_timeout_ms = required_nonzero_u64(
        cli.keepalive_idle_timeout_ms,
        "--keepalive-idle-timeout-ms",
        "OXO_EDGE_KEEPALIVE_IDLE_TIMEOUT_MS",
        DEFAULT_KEEPALIVE_IDLE_TIMEOUT_MS,
    )?;
    let max_connection_secs = optional_nonzero_u64(
        cli.max_connection_secs,
        "--max-connection-secs",
        "OXO_EDGE_MAX_CONNECTION_SECS",
    )?;
    // opt-in keepalive. The edge binary resolves OXO_EDGE_KEEPALIVE directly
    // (like read_sse_enabled) so a directly-launched edge honors the env, not only the
    // service-runner argv path. ladder: explicit CLI > explicit env > serve-rails
    // preset (true) > default OFF (one-shot). An explicitly-set OXO_EDGE_KEEPALIVE=0
    // beats the preset; an unset env falls through to it.
    let keepalive_enabled = match cli.keepalive_enabled {
        Some(value) => value,
        None => match optional_bool_env("OXO_EDGE_KEEPALIVE")? {
            Some(value) => value,
            None => serve_rails_active,
        },
    };
    // total-requests-per-connection cap. Resolved always (for boot validation) but
    // only carried as a pingora reuse limit when keepalive is enabled — under one-shot the
    // connection already closes after one request, so the cap is inert.
    let max_requests_per_connection = required_nonzero_u64(
        cli.max_requests_per_connection,
        "--max-requests-per-connection",
        "OXO_EDGE_MAX_REQUESTS_PER_CONNECTION",
        DEFAULT_MAX_REQUESTS_PER_CONNECTION,
    )?;
    let reuse_limit = requests_per_connection_to_reuse_limit(
        max_requests_per_connection,
        "--max-requests-per-connection",
    )?;
    let keepalive_request_limit = keepalive_enabled.then_some(reuse_limit);
    Ok(SlowClientPolicy {
        header_read_timeout_ms,
        keepalive_idle_timeout_ms,
        max_connection_secs,
        pingora_tls_handshake_timeout_secs: PINGORA_TLS_HANDSHAKE_TIMEOUT_SECS,
        keepalive_enabled,
        keepalive_request_limit,
    })
}

/// the security knobs pingora 0.8.1 gives us NO seam to enforce. Each entry pairs the
/// operator-facing flag with the attack it does NOT bound. `render_unenforced_knobs`
/// resolves which of these the operator has actually configured to a non-default value; the
/// boot path and `--check-config` emit one honesty line per hit (see `emit_...`).
const UNENFORCED_KNOBS_HEADER_READ: (&str, &str) = (
    "--header-read-timeout-ms",
    "slow-header dribble (total within-request header time is unbounded)",
);
const UNENFORCED_KNOBS_MAX_CONNECTION: (&str, &str) =
    ("--max-connection-secs", "absolute connection age");

/// Resolved-value honesty check (covers BOTH the CLI and env channels, since it inspects the
/// already-resolved `SlowClientPolicy` rather than the raw flags). Returns the inert knobs the
/// operator set to a non-default value: `header_read_timeout_ms` differs from its default, or
/// `max_connection_secs` is set at all (its default is "no cap"). Default/unset knobs return
/// empty so a stock deployment emits no noise.
fn render_unenforced_knobs(slow_client: &SlowClientPolicy) -> Vec<(&'static str, &'static str)> {
    let mut set = Vec::new();
    if slow_client.header_read_timeout_ms != DEFAULT_HEADER_READ_TIMEOUT_MS {
        set.push(UNENFORCED_KNOBS_HEADER_READ);
    }
    if slow_client.max_connection_secs.is_some() {
        set.push(UNENFORCED_KNOBS_MAX_CONNECTION);
    }
    set
}

fn emit_unenforced_knob_warnings(slow_client: &SlowClientPolicy) {
    for (knob, effect) in render_unenforced_knobs(slow_client) {
        eprintln!(
            "oxo_edge_config_warning NOT ENFORCED: {knob} is parsed and reported but has no \
             pingora 0.8.1 enforcement seam; it does not bound {effect} (see docs non-claims)."
        );
    }
}

/// map operator "total requests per connection" N to pingora's
/// `keepalive_request_limit`, which is a REUSE counter (`Some(k)` permits k reuses = k+1
/// total requests; `Some(0)` = genuine one-shot). So N total requests = `Some(N - 1)`,
/// giving N=1 ⇒ `Some(0)` ⇒ one-shot with NO operator-visible off-by-one. N must be ≥1
/// (guaranteed by the caller's nonzero read) and `N - 1` must fit the u32 sink.
fn requests_per_connection_to_reuse_limit(n: u64, name: &'static str) -> Result<u32, EdgeError> {
    u32::try_from(n - 1).map_err(|_| EdgeError::ConfigEnv {
        name,
        message: "value is too large (total requests per connection minus one must fit in \
                  a 32-bit counter)"
            .to_string(),
    })
}

/// resolve the HTTP/2 resource bounds handed to `H2Options`. Both knobs are
/// nonzero-guarded; concurrent-streams must fit the h2 `u32` sink and reset-streams the
/// `usize` sink (no silent truncation).
fn read_h2_policy(cli: &crate::EdgeCliConfig) -> Result<H2Policy, EdgeError> {
    let concurrent = required_nonzero_u64(
        cli.h2_max_concurrent_streams,
        "--h2-max-concurrent-streams",
        "OXO_EDGE_H2_MAX_CONCURRENT_STREAMS",
        DEFAULT_H2_MAX_CONCURRENT_STREAMS,
    )?;
    let max_concurrent_streams = u32::try_from(concurrent).map_err(|_| EdgeError::ConfigEnv {
        name: "--h2-max-concurrent-streams",
        message: "value must fit in a 32-bit stream count".to_string(),
    })?;
    let reset = required_nonzero_u64(
        cli.h2_max_reset_streams,
        "--h2-max-reset-streams",
        "OXO_EDGE_H2_MAX_RESET_STREAMS",
        DEFAULT_H2_MAX_RESET_STREAMS,
    )?;
    let max_reset_streams = usize::try_from(reset).map_err(|_| EdgeError::ConfigEnv {
        name: "--h2-max-reset-streams",
        message: "value is too large for this platform".to_string(),
    })?;
    Ok(H2Policy {
        max_concurrent_streams,
        max_reset_streams,
    })
}

fn read_long_lived_registry(
    cli: &crate::EdgeCliConfig,
) -> Result<Arc<LongLivedRegistry>, EdgeError> {
    let max_connections = required_nonzero_u64(
        cli.long_lived_max_connections,
        "--long-lived-max-connections",
        "OXO_EDGE_LONG_LIVED_MAX_CONNECTIONS",
        DEFAULT_LONG_LIVED_MAX_CONNECTIONS,
    )?;
    let max_buffered_bytes = required_nonzero_u64(
        cli.long_lived_max_buffered_bytes,
        "--long-lived-max-buffered-bytes",
        "OXO_EDGE_LONG_LIVED_MAX_BUFFERED_BYTES",
        DEFAULT_LONG_LIVED_MAX_BUFFERED_BYTES,
    )?;
    let write_timeout_ms = required_nonzero_u64(
        cli.long_lived_downstream_write_timeout_ms,
        "--long-lived-downstream-write-timeout-ms",
        "OXO_EDGE_LONG_LIVED_DOWNSTREAM_WRITE_TIMEOUT_MS",
        DEFAULT_LONG_LIVED_DOWNSTREAM_WRITE_TIMEOUT.as_millis() as u64,
    )?;
    Ok(Arc::new(LongLivedRegistry::new(LongLivedLimits {
        max_connections,
        max_buffered_bytes,
        downstream_write_timeout: Duration::from_millis(write_timeout_ms),
    })))
}

fn required_nonzero_u64(
    cli_value: Option<u64>,
    cli_name: &'static str,
    env_name: &'static str,
    default: u64,
) -> Result<u64, EdgeError> {
    let (value, name) = match cli_value {
        Some(value) => (value, cli_name),
        None => (optional_u64_env(env_name)?.unwrap_or(default), env_name),
    };
    if value == 0 {
        return Err(EdgeError::ConfigEnv {
            name,
            message: "value must be greater than zero".to_string(),
        });
    }
    Ok(value)
}

fn optional_nonzero_u64(
    cli_value: Option<u64>,
    cli_name: &'static str,
    env_name: &'static str,
) -> Result<Option<u64>, EdgeError> {
    let (value, name) = match cli_value {
        Some(value) => (Some(value), cli_name),
        None => (optional_u64_env(env_name)?, env_name),
    };
    match value {
        Some(0) => Err(EdgeError::ConfigEnv {
            name,
            message: "value must be greater than zero".to_string(),
        }),
        value => Ok(value),
    }
}

fn validate_public_tls_identity(
    public_mode: Option<PublicMode>,
    _listener: &ListenerMode,
    server_name: &str,
) -> Result<(), EdgeError> {
    if public_mode.is_none() {
        return Ok(());
    }
    if !is_single_ascii_fqdn(server_name) {
        return Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_SERVER_NAME",
            message:
                "public mode requires a single ASCII DNS FQDN without wildcard, port, or IP literal"
                    .to_string(),
        });
    }
    #[cfg(feature = "tls-rustls")]
    if let ListenerMode::Tls { cert_path, .. } = _listener {
        validate_tls_certificate_name(cert_path, server_name)?;
    }
    Ok(())
}

fn is_single_ascii_fqdn(value: &str) -> bool {
    let name = value.trim_end_matches('.');
    if name.is_empty()
        || name.len() > 253
        || !name.is_ascii()
        || name.contains(':')
        || name.contains('*')
    {
        return false;
    }
    let mut label_count = 0usize;
    for label in name.split('.') {
        label_count += 1;
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || bytes.first() == Some(&b'-')
            || bytes.last() == Some(&b'-')
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return false;
        }
    }
    label_count >= 2
}

#[cfg(feature = "tls-rustls")]
fn validate_tls_certificate_name(cert_path: &Path, server_name: &str) -> Result<(), EdgeError> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::pem::parse_x509_pem;

    let pem_bytes = fs::read(cert_path).map_err(|err| EdgeError::TlsFileUnavailable {
        role: "certificate",
        path: cert_path.to_path_buf(),
        message: err.to_string(),
    })?;
    let (_, pem) = parse_x509_pem(&pem_bytes).map_err(|err| EdgeError::TlsCertificateName {
        path: cert_path.to_path_buf(),
        server_name: server_name.to_string(),
        message: format!("failed to parse certificate PEM: {err}"),
    })?;
    let cert = pem
        .parse_x509()
        .map_err(|err| EdgeError::TlsCertificateName {
            path: cert_path.to_path_buf(),
            server_name: server_name.to_string(),
            message: format!("failed to parse certificate: {err}"),
        })?;
    let san = cert
        .subject_alternative_name()
        .map_err(|err| EdgeError::TlsCertificateName {
            path: cert_path.to_path_buf(),
            server_name: server_name.to_string(),
            message: format!("invalid subjectAltName extension: {err}"),
        })?
        .ok_or_else(|| EdgeError::TlsCertificateName {
            path: cert_path.to_path_buf(),
            server_name: server_name.to_string(),
            message: "missing subjectAltName extension".to_string(),
        })?;
    let dns_names = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(name) => Some(*name),
            _ => None,
        })
        .collect::<Vec<_>>();
    if dns_names
        .iter()
        .any(|name| name.eq_ignore_ascii_case(server_name))
    {
        return Ok(());
    }
    Err(EdgeError::TlsCertificateName {
        path: cert_path.to_path_buf(),
        server_name: server_name.to_string(),
        message: format!(
            "subjectAltName DNS entries {:?} do not contain {:?}",
            dns_names, server_name
        ),
    })
}
fn read_admin_bind(
    public_mode: Option<PublicMode>,
    cli: &crate::EdgeCliConfig,
) -> Result<Option<SocketAddr>, EdgeError> {
    if let Some(bind) = cli.admin_bind {
        if !bind.ip().is_loopback() {
            return Err(EdgeError::ConfigEnv {
                name: "OXO_EDGE_ADMIN_BIND",
                message: "private admin health bind must be loopback".to_string(),
            });
        }
        return Ok(Some(bind));
    }
    match env::var("OXO_EDGE_ADMIN_BIND") {
        Ok(raw) => {
            let bind = raw
                .parse::<SocketAddr>()
                .map_err(|err| EdgeError::ConfigEnv {
                    name: "OXO_EDGE_ADMIN_BIND",
                    message: format!("expected loopback socket address: {err}"),
                })?;
            if !bind.ip().is_loopback() {
                return Err(EdgeError::ConfigEnv {
                    name: "OXO_EDGE_ADMIN_BIND",
                    message: "private admin health bind must be loopback".to_string(),
                });
            }
            Ok(Some(bind))
        }
        Err(env::VarError::NotPresent) => {
            if public_mode.is_some_and(PublicMode::requires_admin_health) {
                Err(EdgeError::ConfigEnv {
                    name: "OXO_EDGE_ADMIN_BIND",
                    message: "public smoke beta requires private admin health bind".to_string(),
                })
            } else {
                Ok(None)
            }
        }
        Err(err) => Err(EdgeError::ConfigEnv {
            name: "OXO_EDGE_ADMIN_BIND",
            message: err.to_string(),
        }),
    }
}

fn read_action_cable_bind(cli: &crate::EdgeCliConfig) -> Result<Option<SocketAddr>, EdgeError> {
    let bind = match cli.action_cable_bind {
        Some(bind) => Some(bind),
        None => match env::var("OXO_EDGE_ACTION_CABLE_BIND") {
            Ok(raw) if raw.trim().is_empty() => None,
            Ok(raw) => Some(
                raw.parse::<SocketAddr>()
                    .map_err(|err| EdgeError::ConfigEnv {
                        name: "OXO_EDGE_ACTION_CABLE_BIND",
                        message: format!("expected loopback socket address: {err}"),
                    })?,
            ),
            Err(env::VarError::NotPresent) => None,
            Err(err) => {
                return Err(EdgeError::ConfigEnv {
                    name: "OXO_EDGE_ACTION_CABLE_BIND",
                    message: err.to_string(),
                })
            }
        },
    };
    if let Some(bind) = bind {
        if !bind.ip().is_loopback() {
            return Err(EdgeError::ConfigEnv {
                name: "OXO_EDGE_ACTION_CABLE_BIND",
                message: "Action Cable sidecar bind must be loopback/private".to_string(),
            });
        }
    }
    Ok(bind)
}

fn optional_string_env(name: &'static str) -> Result<Option<String>, EdgeError> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(EdgeError::ConfigEnv {
            name,
            message: err.to_string(),
        }),
    }
}

fn optional_u64_env(name: &'static str) -> Result<Option<u64>, EdgeError> {
    optional_string_env(name)?.map_or(Ok(None), |raw| {
        raw.parse::<u64>()
            .map(Some)
            .map_err(|err| EdgeError::ConfigEnv {
                name,
                message: format!("expected integer, got {raw:?}: {err}"),
            })
    })
}

fn optional_path_env(name: &'static str) -> Result<Option<PathBuf>, EdgeError> {
    match env::var_os(name).filter(|value| !value.is_empty()) {
        Some(value) => Ok(Some(PathBuf::from(value))),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_threads_resolver_defaults_precedence_and_guards() {
        // every OXO_EDGE_THREADS scenario lives in this ONE test because env
        // vars are process-global and cargo runs tests in parallel threads.
        let nproc = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        let mut cli = crate::EdgeCliConfig::default();

        env::remove_var("OXO_EDGE_THREADS");
        let resolved = read_edge_threads(&cli).unwrap();
        // the default is host-size-dependent -- small hosts (<= 2 cores) get
        // nproc-1 (min 1, the measured p2e1 winner); larger hosts keep nproc.
        if nproc <= 2 {
            assert_eq!(resolved.threads, nproc.saturating_sub(1).max(1));
            assert_eq!(resolved.source, "default-small-host");
        } else {
            assert_eq!(resolved.threads, nproc);
            assert_eq!(resolved.source, "default-nproc");
        }
        assert_eq!(resolved.nproc, nproc);

        env::set_var("OXO_EDGE_THREADS", "3");
        let resolved = read_edge_threads(&cli).unwrap();
        assert_eq!(resolved.threads, 3);
        assert_eq!(resolved.source, "OXO_EDGE_THREADS");

        cli.edge_threads = Some(2);
        let resolved = read_edge_threads(&cli).unwrap();
        assert_eq!(resolved.threads, 2, "CLI must win over env");
        assert_eq!(resolved.source, "--edge-threads");
        env::remove_var("OXO_EDGE_THREADS");

        cli.edge_threads = Some(0);
        let err = read_edge_threads(&cli).expect_err("zero threads must fail closed");
        assert!(err.to_string().contains("--edge-threads"), "{err}");

        // Above the cap fails closed with a named error (an eager million-thread spawn
        // would otherwise wedge/OOM bootstrap); the cap itself is accepted.
        cli.edge_threads = Some(MAX_EDGE_THREADS + 1);
        let err = read_edge_threads(&cli).expect_err("absurd thread count must fail closed");
        assert!(err.to_string().contains("1024"), "{err}");
        cli.edge_threads = Some(MAX_EDGE_THREADS);
        assert_eq!(
            read_edge_threads(&cli).unwrap().threads,
            MAX_EDGE_THREADS as usize
        );
    }

    #[test]
    fn listener_tasks_resolver_defaults_precedence_and_guards() {
        // every OXO_EDGE_LISTENER_TASKS scenario in ONE test (env vars are
        // process-global and cargo runs tests in parallel threads — the rule).
        let mut cli = crate::EdgeCliConfig::default();

        env::remove_var("OXO_EDGE_LISTENER_TASKS");
        let resolved = read_listener_tasks(&cli).unwrap();
        assert_eq!(
            resolved.tasks, 1,
            "default must match pingora's own (no behavior change)"
        );
        assert_eq!(resolved.source, "default");

        env::set_var("OXO_EDGE_LISTENER_TASKS", "4");
        let resolved = read_listener_tasks(&cli).unwrap();
        assert_eq!(resolved.tasks, 4);
        assert_eq!(resolved.source, "OXO_EDGE_LISTENER_TASKS");

        cli.listener_tasks = Some(2);
        let resolved = read_listener_tasks(&cli).unwrap();
        assert_eq!(resolved.tasks, 2, "CLI must win over env");
        assert_eq!(resolved.source, "--listener-tasks");
        env::remove_var("OXO_EDGE_LISTENER_TASKS");

        cli.listener_tasks = Some(0);
        let err = read_listener_tasks(&cli).expect_err("zero accept tasks must fail closed");
        assert!(err.to_string().contains("--listener-tasks"), "{err}");

        cli.listener_tasks = Some(MAX_LISTENER_TASKS + 1);
        let err = read_listener_tasks(&cli).expect_err("absurd task count must fail closed");
        assert!(err.to_string().contains("64"), "{err}");
        cli.listener_tasks = Some(MAX_LISTENER_TASKS);
        assert_eq!(
            read_listener_tasks(&cli).unwrap().tasks,
            MAX_LISTENER_TASKS as usize
        );
    }

    #[test]
    fn worker_dispatch_resolver_defaults_precedence_and_guards() {
        // M4: one test for every scenario (env vars are process-global; parallel tests).
        use super::super::frame_hop::dispatch::DispatchMode;
        let mut cli = crate::EdgeCliConfig::default();

        env::remove_var("OXO_WORKER_DISPATCH");
        let (mode, source) = read_worker_dispatch(&cli, 4).unwrap();
        assert_eq!(mode, DispatchMode::LeastOutstanding, "default is LO");
        assert_eq!(source, "default");

        env::set_var("OXO_WORKER_DISPATCH", "rr");
        let (mode, source) = read_worker_dispatch(&cli, 4).unwrap();
        assert_eq!(mode, DispatchMode::Rr);
        assert_eq!(source, "env");

        cli.worker_dispatch = Some("least-outstanding".to_string());
        let (mode, source) = read_worker_dispatch(&cli, 4).unwrap();
        assert_eq!(
            mode,
            DispatchMode::LeastOutstanding,
            "CLI must win over env"
        );
        assert_eq!(source, "cli");
        env::remove_var("OXO_WORKER_DISPATCH");

        cli.worker_dispatch = Some("banana".to_string());
        let err = read_worker_dispatch(&cli, 4).expect_err("unknown mode fails closed");
        assert!(
            err.to_string().contains("least-outstanding|rr|free-first"),
            "{err}"
        );

        // Panel MED-9: depth-reading modes refuse fleets beyond the gauge slot count;
        // rr (depth-blind) is accepted at any size.
        cli.worker_dispatch = Some("least-outstanding".to_string());
        let err = read_worker_dispatch(&cli, 17).expect_err(">16 workers must fail closed");
        assert!(err.to_string().contains("at most 16"), "{err}");
        cli.worker_dispatch = Some("rr".to_string());
        assert!(
            read_worker_dispatch(&cli, 17).is_ok(),
            "rr is size-agnostic"
        );
    }

    #[test]
    fn worker_kind_resolver_defaults_and_fails_closed() {
        // W0: env scenarios in ONE test (process-global var, parallel test threads).
        use super::super::frame_hop::worker_kind::WorkerKind;

        env::remove_var("OXO_WORKER_KIND");
        assert_eq!(read_worker_kind().unwrap(), WorkerKind::Classic, "default");

        env::set_var("OXO_WORKER_KIND", "async");
        assert_eq!(read_worker_kind().unwrap(), WorkerKind::Async);

        env::set_var("OXO_WORKER_KIND", "classic");
        assert_eq!(read_worker_kind().unwrap(), WorkerKind::Classic);

        env::set_var("OXO_WORKER_KIND", "fibers");
        let err = read_worker_kind().expect_err("unknown kind fails closed");
        assert!(err.to_string().contains("classic|async"), "{err}");
        env::remove_var("OXO_WORKER_KIND");
    }

    #[test]
    fn request_log_resolver_defaults_precedence_and_guards() {
        // env scenarios in ONE test (process-global var, parallel test threads).
        let mut cli = crate::EdgeCliConfig::default();

        env::remove_var("OXO_EDGE_REQUEST_LOG");
        let (mode, source) = read_request_log(&cli).unwrap();
        assert_eq!(mode, RequestLogMode::Rejections);
        assert_eq!(source, "default");

        env::set_var("OXO_EDGE_REQUEST_LOG", "all");
        let (mode, source) = read_request_log(&cli).unwrap();
        assert_eq!(mode, RequestLogMode::All);
        assert_eq!(source, "env");

        cli.request_log = Some("off".to_string());
        let (mode, source) = read_request_log(&cli).unwrap();
        assert_eq!(mode, RequestLogMode::Off, "CLI must win over env");
        assert_eq!(source, "cli");
        env::remove_var("OXO_EDGE_REQUEST_LOG");

        cli.request_log = Some("verbose".to_string());
        let err = read_request_log(&cli).expect_err("unknown mode must fail closed");
        assert!(err.to_string().contains("off|rejections|all"), "{err}");
    }

    #[test]
    fn requests_per_connection_maps_total_to_reuse_count() {
        // operator "total requests" N -> pingora reuse counter N-1.
        // N=1 => Some(0) => genuine one-shot (no operator-visible off-by-one).
        assert_eq!(requests_per_connection_to_reuse_limit(1, "x").unwrap(), 0);
        assert_eq!(requests_per_connection_to_reuse_limit(2, "x").unwrap(), 1);
        assert_eq!(
            requests_per_connection_to_reuse_limit(1000, "x").unwrap(),
            999
        );
        // N-1 at the u32 ceiling is accepted; beyond it is rejected (no silent truncation).
        assert_eq!(
            requests_per_connection_to_reuse_limit(u32::MAX as u64 + 1, "x").unwrap(),
            u32::MAX
        );
        assert!(requests_per_connection_to_reuse_limit(u32::MAX as u64 + 2, "x").is_err());
        assert!(requests_per_connection_to_reuse_limit(u64::MAX, "x").is_err());
    }

    fn slow_client_policy_baseline() -> SlowClientPolicy {
        SlowClientPolicy {
            header_read_timeout_ms: DEFAULT_HEADER_READ_TIMEOUT_MS,
            keepalive_idle_timeout_ms: DEFAULT_KEEPALIVE_IDLE_TIMEOUT_MS,
            max_connection_secs: None,
            pingora_tls_handshake_timeout_secs: PINGORA_TLS_HANDSHAKE_TIMEOUT_SECS,
            keepalive_enabled: false,
            keepalive_request_limit: None,
        }
    }

    #[test]
    fn render_unenforced_knobs_names_only_set_inert_knobs() {
        // D-d1: a stock deployment (defaults) emits nothing — no noise.
        let base = slow_client_policy_baseline();
        assert!(render_unenforced_knobs(&base).is_empty());
        // A tuned header-read timeout is inert -> named (proves honesty covers non-default).
        let tuned_header = SlowClientPolicy {
            header_read_timeout_ms: 5_000,
            ..base
        };
        let names: Vec<_> = render_unenforced_knobs(&tuned_header)
            .into_iter()
            .map(|(knob, _)| knob)
            .collect();
        assert_eq!(names, vec!["--header-read-timeout-ms"]);
        // A set max-connection-secs is inert -> named (default is "no cap", so any value is
        // non-default).
        let capped = SlowClientPolicy {
            max_connection_secs: Some(30),
            ..base
        };
        let names: Vec<_> = render_unenforced_knobs(&capped)
            .into_iter()
            .map(|(knob, _)| knob)
            .collect();
        assert_eq!(names, vec!["--max-connection-secs"]);
        // Both set -> both named, in flag order.
        let both = SlowClientPolicy {
            header_read_timeout_ms: 5_000,
            max_connection_secs: Some(30),
            ..base
        };
        let names: Vec<_> = render_unenforced_knobs(&both)
            .into_iter()
            .map(|(knob, _)| knob)
            .collect();
        assert_eq!(
            names,
            vec!["--header-read-timeout-ms", "--max-connection-secs"]
        );
        // Explicitly setting the header timeout to its default value is NOT flagged (it did
        // not change the posture beyond baseline).
        let default_explicit = SlowClientPolicy {
            header_read_timeout_ms: DEFAULT_HEADER_READ_TIMEOUT_MS,
            ..base
        };
        assert!(render_unenforced_knobs(&default_explicit).is_empty());
    }

    #[test]
    fn max_requests_per_connection_zero_is_rejected_at_boot() {
        // N=0 is nonsensical (a connection must serve >=1 request). required_nonzero_u64
        // rejects it, naming the flag.
        let cli = crate::EdgeCliConfig {
            max_requests_per_connection: Some(0),
            ..Default::default()
        };
        let err = read_slow_client_policy(&cli, false).expect_err("N=0 must be rejected");
        match err {
            EdgeError::ConfigEnv { name, .. } => {
                assert_eq!(name, "--max-requests-per-connection")
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn h2_policy_defaults_and_guards() {
        // Unset -> pingora/h2 defaults (100 concurrent streams, 20 pending resets).
        let default = read_h2_policy(&crate::EdgeCliConfig::default()).unwrap();
        assert_eq!(default.max_concurrent_streams, 100);
        assert_eq!(default.max_reset_streams, 20);
        // Explicit values pass through.
        let set = read_h2_policy(&crate::EdgeCliConfig {
            h2_max_concurrent_streams: Some(250),
            h2_max_reset_streams: Some(5),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(set.max_concurrent_streams, 250);
        assert_eq!(set.max_reset_streams, 5);
        // Zero is rejected on both; over-u32 concurrent-streams is rejected (no truncation).
        assert!(read_h2_policy(&crate::EdgeCliConfig {
            h2_max_concurrent_streams: Some(0),
            ..Default::default()
        })
        .is_err());
        assert!(read_h2_policy(&crate::EdgeCliConfig {
            h2_max_reset_streams: Some(0),
            ..Default::default()
        })
        .is_err());
        assert!(read_h2_policy(&crate::EdgeCliConfig {
            h2_max_concurrent_streams: Some(u32::MAX as u64 + 1),
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn max_requests_per_connection_defaults_and_maps_under_keepalive() {
        // Default (unset) -> 1000 total -> Some(999) reuses, but only when keepalive is on.
        let with_ka = crate::EdgeCliConfig {
            keepalive_enabled: Some(true),
            ..Default::default()
        };
        assert_eq!(
            read_slow_client_policy(&with_ka, false)
                .unwrap()
                .keepalive_request_limit,
            Some(999)
        );
        // One-shot default: the cap is inert (None), so the connection just closes after 1.
        let one_shot = crate::EdgeCliConfig::default();
        assert_eq!(
            read_slow_client_policy(&one_shot, false)
                .unwrap()
                .keepalive_request_limit,
            None
        );
    }

    /// M3 mechanism gate — pins the ROOT CAUSE of the measured 3 futile syscalls/request.
    ///
    /// Run `guest-run-20260715-184626` measured, on the dynamic `/bench` route:
    /// `newfstatat` 1/req + `openat2` 2/req, with **100 % of the opens failing ENOENT**
    /// (65 526 calls / 65 526 errors) — and ZERO of either on `/edge-bench`, which returns
    /// before the static branch. The cause is below: `--serve-rails` derives a `/` mount, whose
    /// prefix-match is vacuously true, so EVERY request — including routes that can never be
    /// static — enters crenel as a Candidate and pays check_repin's stat + open_rel.
    ///
    /// This test does not assert the syscalls (that needs a kernel and lives in the guest
    /// profile); it pins the CONFIG SHAPE that causes them, deterministically and on every
    /// platform. It must FAIL LOUDLY when P3 is fixed — the fix belongs inside crenel
    /// (negative caching / repin cadence), and if it ever moves here instead, that is a second
    /// parser and a -F5 violation. Update this test only WITH a measurement that shows the
    /// probe count changed.
    #[test]
    fn serve_rails_derives_a_root_fallthrough_mount_making_every_request_a_static_candidate() {
        let cli = crate::EdgeCliConfig::default();
        let plan = ServeRailsPlan {
            root: PathBuf::from("/srv/app"),
            static_dir: Some(PathBuf::from("/srv/app/public")),
            static_assets: true,
            static_overridden: false,
        };

        let mounts = read_static_mounts(&cli, None, Some(&plan)).expect("derived mounts parse");

        // The `/` fallthrough mount is UNCONDITIONAL in the derived branch — this is the fact
        // that silently invalidated a optimization premise (a "route the dynamic path around
        // crenel" milestone that would have saved 0 µs, because the mount matches everything).
        let root = mounts
            .iter()
            .find(|spec| spec.prefix == "/")
            .expect("serve-rails must derive a `/` mount; if this is gone, P3's premise changed");
        assert_eq!(
            root.docroot,
            PathBuf::from("/srv/app/public"),
            "the `/` mount points at Rails public/"
        );
        assert!(
            matches!(root.on_miss, crenel_pingora::OnMiss::Fallthrough),
            "the `/` mount MUST fall through to Rails on miss — a strict 404 here would break \
             every dynamic route. Fallthrough is why the futile probes are invisible in behavior \
             and visible only in syscalls."
        );

        // An empty-prefix match is vacuously true: no path can fail to match `/`. Spelled out
        // so the reader does not have to re-derive why 3 syscalls/req are unavoidable TODAY.
        for dynamic in ["/bench", "/api/v1/orders", "/rails/anything"] {
            assert!(
                dynamic.starts_with(&root.prefix),
                "{dynamic} matches the `/` mount => Candidate => stat + 2x openat2 (both ENOENT)"
            );
        }
    }

    #[test]
    fn resolve_serve_rails_cli_wins_env_twin_empty_is_unset() {
        // P4/P7: the single resolver, unit-tested with injectable getenv — no
        // process-global env mutation. CLI beats env; empty env reads as unset.
        let cli = Some(PathBuf::from("/from/cli"));
        let resolved = resolve_serve_rails(cli, |_| Some(OsString::from("/from/env")));
        assert_eq!(resolved, Some(PathBuf::from("/from/cli")));

        let resolved = resolve_serve_rails(None, |name| {
            assert_eq!(name, "OXO_EDGE_SERVE_RAILS");
            Some(OsString::from("/from/env"))
        });
        assert_eq!(resolved, Some(PathBuf::from("/from/env")));

        assert_eq!(resolve_serve_rails(None, |_| Some(OsString::new())), None);
        assert_eq!(resolve_serve_rails(None, |_| None), None);
    }

    #[test]
    fn serve_rails_posture_ladder_explicit_cli_beats_preset() {
        // AC-e1 (CLI channel; the env channel is covered out-of-process in
        // fake_upstream per panel P7): the preset turns keepalive/SSE on, an explicit
        // --no-keepalive / --no-sse still wins.
        let unset = crate::EdgeCliConfig::default();
        assert!(
            read_slow_client_policy(&unset, true)
                .unwrap()
                .keepalive_enabled,
            "serve-rails preset must enable keepalive when nothing is explicit"
        );
        assert!(
            read_sse_enabled(&unset, true).unwrap(),
            "serve-rails preset must enable SSE when nothing is explicit"
        );
        let explicit_off = crate::EdgeCliConfig {
            keepalive_enabled: Some(false),
            sse_enabled: Some(false),
            ..Default::default()
        };
        assert!(
            !read_slow_client_policy(&explicit_off, true)
                .unwrap()
                .keepalive_enabled,
            "--no-keepalive must beat the preset"
        );
        assert!(
            !read_sse_enabled(&explicit_off, true).unwrap(),
            "--no-sse must beat the preset"
        );
        // Preset inactive: defaults stay off.
        assert!(
            !read_slow_client_policy(&unset, false)
                .unwrap()
                .keepalive_enabled
        );
        assert!(!read_sse_enabled(&unset, false).unwrap());
    }

    #[test]
    fn plan_serve_rails_directory_shape_matrix() {
        // AC-e2 unit coverage of the four shapes (integration re-proves them on a
        // spawned edge). Uses tempdir-per-shape; no env involved.
        let base = std::env::temp_dir().join(format!(
            "oxo-serve-rails-plan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();

        // Shape 1: missing root -> fail-closed refusal naming --serve-rails (P3), even
        // when an explicit static override is present (root stays the posture anchor).
        let missing_root = base.join("missing-root");
        for explicit in [None, Some(Path::new("/somewhere/else"))] {
            let err = plan_serve_rails(missing_root.clone(), explicit)
                .expect_err("missing root must refuse");
            match err {
                EdgeError::ConfigEnv { name, message } => {
                    assert_eq!(name, "--serve-rails");
                    assert!(message.contains("missing or not a directory"), "{message}");
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }

        // Shape 2: root exists, public/ missing -> soft-disable (static off), posture
        // still applies.
        let bare_root = base.join("bare-root");
        fs::create_dir_all(&bare_root).unwrap();
        let plan = plan_serve_rails(bare_root.clone(), None).unwrap();
        assert_eq!(plan.static_dir, None);
        assert_eq!(plan.static_descriptor(), "off");

        // Shape 3: public/ is a regular FILE -> broken layout, fail-closed (P8).
        let file_root = base.join("file-public");
        fs::create_dir_all(&file_root).unwrap();
        fs::write(file_root.join("public"), b"not a dir").unwrap();
        let err =
            plan_serve_rails(file_root.clone(), None).expect_err("file at public must refuse");
        match err {
            EdgeError::ConfigEnv { name, message } => {
                assert_eq!(name, "--serve-rails");
                assert!(message.contains("not a directory"), "{message}");
            }
            other => panic!("unexpected error: {other:?}"),
        }

        // Shape 4a: public/ without assets/ -> fallthrough-only derivation (P1, HIGH:
        // API-only apps must not be refused boot by the strict /assets mount).
        let api_root = base.join("api-only");
        fs::create_dir_all(api_root.join("public")).unwrap();
        let plan = plan_serve_rails(api_root.clone(), None).unwrap();
        assert!(!plan.static_assets);
        assert_eq!(plan.static_dir, Some(api_root.join("public")));
        let mounts = read_static_mounts(&crate::EdgeCliConfig::default(), None, Some(&plan))
            .expect("fallthrough-only derivation parses");
        assert_eq!(mounts.len(), 1, "only the / fallthrough mount is derived");

        // Shape 4b: full layout -> the standard pair.
        let full_root = base.join("full");
        fs::create_dir_all(full_root.join("public/assets")).unwrap();
        let plan = plan_serve_rails(full_root.clone(), None).unwrap();
        assert!(plan.static_assets);
        let mounts = read_static_mounts(&crate::EdgeCliConfig::default(), None, Some(&plan))
            .expect("pair derivation parses");
        assert_eq!(mounts.len(), 2, "assets + fallthrough pair is derived");

        // Override: explicit --static-rails-preset dir wins for the mounts; the plan
        // records the override and derives nothing of its own.
        let plan = plan_serve_rails(full_root.clone(), Some(&full_root.join("public"))).unwrap();
        assert!(plan.static_overridden);
        let mounts = read_static_mounts(
            &crate::EdgeCliConfig::default(),
            Some(full_root.join("public")),
            Some(&plan),
        )
        .unwrap();
        assert_eq!(mounts.len(), 2, "override dir produces the explicit pair");

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn derived_mount_parse_errors_name_their_source_knob() {
        // P9: a serve-rails root whose path contains a comma breaks MountSpec's
        // comma-separated grammar — the boot error must blame --serve-rails, not the
        // OXO_EDGE_STATIC_MOUNTS env var the operator never touched.
        let base = std::env::temp_dir().join(format!(
            "oxo-serve-rails-comma-{},{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(base.join("public/assets")).unwrap();
        let plan = plan_serve_rails(base.clone(), None).unwrap();
        let err = read_static_mounts(&crate::EdgeCliConfig::default(), None, Some(&plan))
            .expect_err("comma in derived docroot must fail spec parsing");
        match err {
            EdgeError::ConfigEnv { name, .. } => assert_eq!(name, "--serve-rails"),
            other => panic!("unexpected error: {other:?}"),
        }
        fs::remove_dir_all(&base).ok();
    }
}

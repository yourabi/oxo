use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::EdgeCliConfig;

const WORKER_READY_PREFIX: &str = "OXO_WORKER_READY=";
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(15);
const MONITOR_INTERVAL: Duration = Duration::from_millis(100);
const EDGE_READY_TIMEOUT: Duration = Duration::from_secs(15);
const CABLE_READY_TIMEOUT: Duration = Duration::from_secs(15);
const GRPC_READY_TIMEOUT: Duration = Duration::from_secs(15);
const CHILD_TERM_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_DRAIN_GRACE: Duration = Duration::from_secs(5);
const DEFAULT_EDGE_DRAIN_GRACE: Duration = Duration::from_secs(2);
const SIDECAR_DRAIN_WAIT: Duration = Duration::from_secs(1);
const WORKER_DRAIN_WAIT: Duration = Duration::from_secs(1);
const MAX_PRE_READY_OUTPUT_BYTES: usize = 64 * 1024;
#[cfg(feature = "acme")]
const DEFAULT_ACME_RENEW_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
#[cfg(feature = "acme")]
const DEFAULT_ACME_RENEW_TIMEOUT: Duration = Duration::from_secs(10 * 60);

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_SIGNAL_COUNT: AtomicUsize = AtomicUsize::new(0);

/// W2: how the worker pool is launched. Classic = the sibling `oxo-worker`
/// binary (the posture, unchanged). Async = `<bundle> exec <ruby> <script> <socket>`
/// with cwd `app_root` — every path absolute and validated at config time; deliberately
/// NOT routed through `configured_binary`/`OXO_SERVICE_ALLOW_BIN_OVERRIDES` (a new
/// explicit surface, not a loosening of the sibling-binary override gate). Naming the
/// interpreter explicitly (panel MED-7) means `bundle exec` never PATH-resolves `ruby`.
#[derive(Debug, Clone)]
pub enum WorkerLaunch {
    Classic,
    Async {
        bundle_bin: PathBuf,
        ruby_bin: PathBuf,
        script: PathBuf,
        app_root: PathBuf,
    },
}

impl WorkerLaunch {
    pub fn is_async(&self) -> bool {
        matches!(self, WorkerLaunch::Async { .. })
    }
}

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Classic only; `None` under async kind (the sibling default may not exist in an
    /// async deployment, so it is deliberately never resolved there).
    pub worker_bin: Option<PathBuf>,
    /// W2: the worker launch surface (see `WorkerLaunch`).
    pub worker_launch: WorkerLaunch,
    /// W2/W3: first-boot readiness budget. 15 s classic / 120 s async defaults
    /// (the async floor is the bench's empirically-forced cold-Rails-boot budget);
    /// `OXO_WORKER_READY_TIMEOUT_MS` overrides, zero rejected.
    pub worker_ready_timeout: Duration,
    /// W2/W3 (panel MED-5): respawn readiness budget (warm app; 30 s async
    /// default) — a crash-looping reactor must not blind the monitor for the full
    /// cold-boot budget per attempt. `OXO_WORKER_RESPAWN_READY_TIMEOUT_MS`.
    pub worker_respawn_ready_timeout: Duration,
    /// W2 (panel MED-10): the workers' TERM drain stage. Classic keeps the 1 s
    /// legacy constant; async DERIVES it as the worker's drain deadline + 150 ms
    /// margin, so the worker/supervisor pair cannot desynchronize.
    pub worker_drain_wait: Duration,
    pub edge_bin: PathBuf,
    pub worker_socket: PathBuf,
    pub worker_sockets: Vec<PathBuf>,
    pub worker_count: usize,
    pub edge_bind: SocketAddr,
    pub check_config: bool,
    pub cable_bin: Option<PathBuf>,
    pub cable_bind: Option<SocketAddr>,
    pub grpc_bin: Option<PathBuf>,
    pub grpc_bind: Option<SocketAddr>,
    pub drain_grace: Duration,
    pub edge_drain_grace: Duration,
    worker_env: Vec<(OsString, OsString)>,
    edge_env: Vec<(OsString, OsString)>,
    edge_args: Vec<OsString>,
    cable_env: Vec<(OsString, OsString)>,
    grpc_env: Vec<(OsString, OsString)>,
    #[cfg(feature = "acme")]
    acme_renew: Option<AcmeRenewConfig>,
}

/// Supervisor-side ACME renewal scheduling: the "daemon" is this supervisor
/// periodically spawning the existing one-shot `--acme-renew-once` verb as a
/// short-lived child (spawn-supervision model; the verb owns due-ness,
/// backoff, and rate-limit deferral, so extra checks are harmless).
#[cfg(feature = "acme")]
#[derive(Debug, Clone)]
struct AcmeRenewConfig {
    interval: Duration,
    timeout: Duration,
    state_dir: PathBuf,
    renew_args: Vec<OsString>,
}

impl ServiceConfig {
    pub fn from_env() -> Result<Self, ServiceError> {
        Self::from_cli(EdgeCliConfig::default())
    }

    pub fn from_args<I, S>(args: I) -> Result<Self, ServiceError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let cli = EdgeCliConfig::parse_from_args(args).map_err(service_cli_error)?;
        Self::from_cli(cli)
    }

    fn from_cli(edge_cli: EdgeCliConfig) -> Result<Self, ServiceError> {
        let allow_bin_overrides = env_bool("OXO_SERVICE_ALLOW_BIN_OVERRIDES", false)?;
        // W2: the worker kind decides the whole launch surface. Under async the
        // classic sibling-binary resolution is SKIPPED entirely (its default may not
        // exist in an async deployment and must not be able to fail the boot).
        let worker_launch = read_worker_launch()?;
        let worker_bin = match &worker_launch {
            WorkerLaunch::Classic => Some(configured_binary(
                "OXO_WORKER_BIN",
                "oxo-worker",
                allow_bin_overrides,
                "worker",
            )?),
            WorkerLaunch::Async { .. } => None,
        };
        let edge_bin = configured_binary(
            "OXO_EDGE_BIN",
            "oxo-pingora-edge",
            allow_bin_overrides,
            "edge",
        )?;
        let worker_socket = required_path("OXO_WORKER_SOCKET")?;
        // W2 (panel MED-9): the SERVICE owns the runtime dir. Created (or verified
        // 0700-exact) here, before anything spawns — the batched async boot must never
        // race per-worker dir creation, and `--check-config` reports a bad dir with
        // nothing spawned. The workers only VERIFY.
        ensure_runtime_dir(&worker_socket, edge_cli.check_config)?;
        let worker_ready_timeout = read_worker_ready_timeout(&worker_launch)?;
        let worker_respawn_ready_timeout = read_worker_respawn_ready_timeout(&worker_launch)?;
        let worker_drain_wait = read_worker_drain_wait(&worker_launch)?;
        // W2 (G13 + panel MED-11): a set-but-garbage frame-pool idle ceiling must
        // fail the boot, not silently run the default (the forwarding lives in
        // collect_edge_env; the validation lives here so --check-config covers it).
        validate_frame_pool_idle_env()?;
        validate_edge_pool_env()?;
        let worker_count = env_usize("OXO_WORKER_COUNT", 1)?;
        if worker_count == 0 {
            return Err(ServiceError::InvalidEnv {
                name: "OXO_WORKER_COUNT",
                message: "must be >= 1".to_string(),
            });
        }
        let worker_sockets = worker_socket_paths(&worker_socket, worker_count)?;
        let edge_bind = resolve_edge_bind(&edge_cli)?;
        let cable_enabled = env_bool("OXO_CABLE_ENABLED", false)?;
        let (cable_bin, cable_bind, cable_env) = if cable_enabled {
            let bind: SocketAddr = required_string("OXO_CABLE_BIND")?.parse().map_err(|err| {
                ServiceError::InvalidEnv {
                    name: "OXO_CABLE_BIND",
                    message: format!("expected loopback socket address: {err}"),
                }
            })?;
            if !bind.ip().is_loopback() {
                return Err(ServiceError::InvalidEnv {
                    name: "OXO_CABLE_BIND",
                    message: "standalone Action Cable bind must be loopback-only".to_string(),
                });
            }
            (
                Some(configured_binary(
                    "OXO_CABLE_BIN",
                    "oxo-cable",
                    allow_bin_overrides,
                    "cable",
                )?),
                Some(bind),
                collect_cable_env(bind)?,
            )
        } else {
            (None, None, Vec::new())
        };
        let grpc_enabled = env_bool("OXO_GRPC_ENABLED", false)?;
        let (grpc_bin, grpc_bind, grpc_env) = if grpc_enabled {
            let bind: SocketAddr = required_string("OXO_GRPC_BIND")?.parse().map_err(|err| {
                ServiceError::InvalidEnv {
                    name: "OXO_GRPC_BIND",
                    message: format!("expected loopback socket address: {err}"),
                }
            })?;
            if !bind.ip().is_loopback() {
                return Err(ServiceError::InvalidEnv {
                    name: "OXO_GRPC_BIND",
                    message: "standalone gRPC bind must be loopback-only".to_string(),
                });
            }
            (
                Some(configured_binary(
                    "OXO_GRPC_BIN",
                    "oxo-grpc",
                    allow_bin_overrides,
                    "grpc",
                )?),
                Some(bind),
                collect_grpc_env(bind)?,
            )
        } else {
            (None, None, Vec::new())
        };
        let worker_env = match &worker_launch {
            WorkerLaunch::Classic => collect_worker_env(&worker_socket)?,
            WorkerLaunch::Async { app_root, .. } => {
                collect_async_worker_env(&worker_socket, app_root)?
            }
        };
        let drain_grace = env_duration_ms("OXO_SERVICE_DRAIN_GRACE_MS", DEFAULT_DRAIN_GRACE)?;
        let (edge_drain_grace_ms, edge_drain_grace) = resolve_edge_drain_grace(&edge_cli)?;
        validate_drain_grace_hierarchy(drain_grace, edge_drain_grace, worker_drain_wait)?;
        let edge_args =
            collect_edge_args(&worker_sockets, edge_bind, &edge_cli, edge_drain_grace_ms)?;
        let edge_env = collect_edge_env(&worker_launch);
        // The renewal-scheduler gate must never be silently ignored: a binary
        // built without the acme feature rejects it outright.
        #[cfg(not(feature = "acme"))]
        if env_bool("OXO_SERVICE_ACME_RENEW", false)? {
            return Err(ServiceError::InvalidEnv {
                name: "OXO_SERVICE_ACME_RENEW",
                message: "this oxo-pingora-service binary was built without the acme feature"
                    .to_string(),
            });
        }
        #[cfg(feature = "acme")]
        let acme_renew = read_acme_renew_config(&edge_cli)?;
        Ok(Self {
            worker_bin,
            worker_launch,
            worker_ready_timeout,
            worker_respawn_ready_timeout,
            worker_drain_wait,
            edge_bin,
            worker_socket,
            worker_sockets,
            worker_count,
            edge_bind,
            check_config: edge_cli.check_config,
            cable_bin,
            cable_bind,
            grpc_bin,
            grpc_bind,
            drain_grace,
            edge_drain_grace,
            worker_env,
            edge_env,
            edge_args,
            cable_env,
            grpc_env,
            #[cfg(feature = "acme")]
            acme_renew,
        })
    }
}

#[cfg(feature = "acme")]
fn read_acme_renew_config(
    edge_cli: &EdgeCliConfig,
) -> Result<Option<AcmeRenewConfig>, ServiceError> {
    if !env_bool("OXO_SERVICE_ACME_RENEW", false)? {
        return Ok(None);
    }
    let http_bind: SocketAddr = required_string("OXO_SERVICE_ACME_HTTP_BIND")?
        .parse()
        .map_err(|err| ServiceError::InvalidEnv {
            name: "OXO_SERVICE_ACME_HTTP_BIND",
            message: format!(
                "expected a socket address for the renewal child's transient HTTP-01                  listener: {err}"
            ),
        })?;
    let state_dir = edge_cli
        .acme_state_path
        .clone()
        .or_else(|| optional_path("OXO_EDGE_ACME_STATE_PATH"))
        .ok_or(ServiceError::MissingEnv {
            name: "OXO_EDGE_ACME_STATE_PATH",
        })?;
    let fqdn = match edge_cli.fqdn.clone() {
        Some(fqdn) => fqdn,
        None => optional_string_env("OXO_EDGE_SERVER_NAME")?.ok_or(ServiceError::MissingEnv {
            name: "OXO_EDGE_SERVER_NAME",
        })?,
    };
    // The renew verb hard-requires accept-terms at RUNTIME; requiring it here
    // fails the SERVICE start instead of every 3am renewal child.
    let accept_terms = edge_cli.acme_accept_terms || env_bool("OXO_EDGE_ACME_ACCEPT_TERMS", false)?;
    if !accept_terms {
        return Err(ServiceError::InvalidEnv {
            name: "OXO_EDGE_ACME_ACCEPT_TERMS",
            message: "the ACME renewal scheduler requires --acme-accept-terms at service start                       (every renewal child would otherwise exit with a config error)"
                .to_string(),
        });
    }
    // Renewal rotates <state>/cert.pem + key.pem; the serving edge must load
    // exactly those paths or rotation silently never takes effect
    // (explicit-but-inert, which this repo fails closed on).
    let expected_cert = state_dir.join("cert.pem");
    let expected_key = state_dir.join("key.pem");
    let tls_cert = edge_cli
        .tls_cert
        .clone()
        .or_else(|| optional_path("OXO_EDGE_TLS_CERT"));
    let tls_key = edge_cli
        .tls_key
        .clone()
        .or_else(|| optional_path("OXO_EDGE_TLS_KEY"));
    if tls_cert.as_deref() != Some(expected_cert.as_path())
        || tls_key.as_deref() != Some(expected_key.as_path())
    {
        return Err(ServiceError::InvalidEnv {
            name: "OXO_EDGE_TLS_CERT",
            message: format!(
                "the ACME renewal scheduler rotates {} and {}; the serving edge must load                  exactly those paths via --tls-cert/--tls-key",
                expected_cert.display(),
                expected_key.display()
            ),
        });
    }
    let interval = env_duration_ms(
        "OXO_SERVICE_ACME_RENEW_INTERVAL_MS",
        DEFAULT_ACME_RENEW_INTERVAL,
    )?;
    let timeout = env_duration_ms(
        "OXO_SERVICE_ACME_RENEW_TIMEOUT_MS",
        DEFAULT_ACME_RENEW_TIMEOUT,
    )?;
    let mut renew_args: Vec<OsString> = vec![
        OsString::from("--acme-renew-once"),
        OsString::from("--acme-state-path"),
        state_dir.clone().into_os_string(),
        OsString::from("--fqdn"),
        OsString::from(&fqdn),
        OsString::from("--http-bind"),
        OsString::from(http_bind.to_string()),
        OsString::from("--acme-accept-terms"),
    ];
    // Only pass the directory when configured; the verb defaults to staging.
    let directory_url = edge_cli
        .acme_directory_url
        .clone()
        .or(optional_string_env("OXO_EDGE_ACME_DIRECTORY_URL")?);
    if let Some(url) = directory_url {
        renew_args.push(OsString::from("--acme-directory-url"));
        renew_args.push(OsString::from(url));
    }
    let contacts: Vec<String> = if !edge_cli.acme_contacts.is_empty() {
        edge_cli.acme_contacts.clone()
    } else {
        optional_string_env("OXO_EDGE_ACME_CONTACTS")?
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    for contact in contacts {
        renew_args.push(OsString::from("--acme-contact"));
        renew_args.push(OsString::from(contact));
    }
    if edge_cli.acme_allow_production_directory
        || env_bool("OXO_EDGE_ACME_ALLOW_PRODUCTION_DIRECTORY", false)?
    {
        renew_args.push(OsString::from("--acme-allow-production-directory"));
    }
    Ok(Some(AcmeRenewConfig {
        interval,
        timeout,
        state_dir,
        renew_args,
    }))
}
fn resolve_edge_drain_grace(cli: &EdgeCliConfig) -> Result<(u64, Duration), ServiceError> {
    let (name, millis) = match cli.drain_grace_ms {
        Some(value) => ("--drain-grace-ms", value),
        None => (
            "OXO_EDGE_DRAIN_GRACE_MS",
            env_usize(
                "OXO_EDGE_DRAIN_GRACE_MS",
                DEFAULT_EDGE_DRAIN_GRACE.as_millis() as usize,
            )? as u64,
        ),
    };
    if millis == 0 {
        return Err(ServiceError::InvalidEnv {
            name,
            message: "edge drain grace must be greater than zero".to_string(),
        });
    }
    let seconds = millis.saturating_add(999) / 1_000;
    Ok((millis, Duration::from_secs(seconds)))
}

fn validate_drain_grace_hierarchy(
    service_grace: Duration,
    edge_grace: Duration,
    worker_drain_wait: Duration,
) -> Result<(), ServiceError> {
    let required = edge_grace + SIDECAR_DRAIN_WAIT + worker_drain_wait;
    if required >= service_grace {
        return Err(ServiceError::InvalidEnv {
            name: "OXO_SERVICE_DRAIN_GRACE_MS",
            message: format!(
                "must be greater than OXO_EDGE_DRAIN_GRACE_MS ({:?}) + SIDECAR_DRAIN_WAIT ({:?}) + worker drain wait ({:?})",
                edge_grace, SIDECAR_DRAIN_WAIT, worker_drain_wait
            ),
        });
    }
    Ok(())
}

/// W2: `OXO_WORKER_KIND` (classic|async; default classic; typo fails closed)
/// plus, under async, the full validated launch surface.
fn read_worker_launch() -> Result<WorkerLaunch, ServiceError> {
    match optional_string_env("OXO_WORKER_KIND")?.as_deref() {
        None | Some("classic") => Ok(WorkerLaunch::Classic),
        Some("async") => {
            let script = required_path("OXO_ASYNC_WORKER_SCRIPT")?;
            validate_executable("async-worker-script", &script)?;
            let bundle_bin = required_path("OXO_ASYNC_BUNDLE_BIN")?;
            validate_executable("async-bundle", &bundle_bin)?;
            let ruby_bin = required_path("OXO_ASYNC_RUBY_BIN")?;
            validate_executable("async-ruby", &ruby_bin)?;
            let app_root = required_path("OXO_ASYNC_WORKER_APP_ROOT")?;
            if !app_root.is_absolute() {
                return Err(ServiceError::InvalidEnv {
                    name: "OXO_ASYNC_WORKER_APP_ROOT",
                    message: "must be an absolute directory".to_string(),
                });
            }
            if !app_root.is_dir() {
                return Err(ServiceError::InvalidEnv {
                    name: "OXO_ASYNC_WORKER_APP_ROOT",
                    message: format!("not a directory: {}", app_root.display()),
                });
            }
            Ok(WorkerLaunch::Async {
                bundle_bin,
                ruby_bin,
                script,
                app_root,
            })
        }
        Some(other) => Err(ServiceError::InvalidEnv {
            name: "OXO_WORKER_KIND",
            message: format!("expected classic|async, got {other:?}"),
        }),
    }
}

/// W2: readiness budgets. The async first-boot default is the bench's
/// empirically-forced 120 s cold-Rails floor (a 30 s ceiling killed a live run);
/// classic keeps the -era 15 s. Zero is rejected (panel MED-11's lenient-parse rule).
fn read_worker_ready_timeout(launch: &WorkerLaunch) -> Result<Duration, ServiceError> {
    let default = if launch.is_async() {
        Duration::from_secs(120)
    } else {
        WORKER_READY_TIMEOUT
    };
    read_nonzero_duration_ms("OXO_WORKER_READY_TIMEOUT_MS", default)
}

/// W2 (panel MED-5): the respawn budget covers a WARM app boot, not a cold one — a
/// crash-looping reactor must not blind the 100 ms monitor tick for 120 s per attempt.
fn read_worker_respawn_ready_timeout(launch: &WorkerLaunch) -> Result<Duration, ServiceError> {
    let default = if launch.is_async() {
        Duration::from_secs(30)
    } else {
        WORKER_READY_TIMEOUT
    };
    read_nonzero_duration_ms("OXO_WORKER_RESPAWN_READY_TIMEOUT_MS", default)
}

/// W2 (panel MED-10): async DERIVES the supervisor's worker drain stage from the
/// worker's own deadline (+150 ms margin) so the pair cannot desynchronize; the same
/// env var is forwarded to the worker (collect_async_worker_env). Classic keeps 1 s.
fn read_worker_drain_wait(launch: &WorkerLaunch) -> Result<Duration, ServiceError> {
    if !launch.is_async() {
        return Ok(WORKER_DRAIN_WAIT);
    }
    let deadline =
        read_nonzero_duration_ms("OXO_WORKER_DRAIN_DEADLINE_MS", Duration::from_millis(900))?;
    Ok(deadline + Duration::from_millis(150))
}

fn read_nonzero_duration_ms(
    name: &'static str,
    default: Duration,
) -> Result<Duration, ServiceError> {
    match optional_string_env(name)? {
        None => Ok(default),
        Some(raw) => {
            let millis: u64 = raw.parse().map_err(|_| ServiceError::InvalidEnv {
                name,
                message: format!("expected milliseconds, got {raw:?}"),
            })?;
            if millis == 0 {
                return Err(ServiceError::InvalidEnv {
                    name,
                    message: "must be greater than zero".to_string(),
                });
            }
            Ok(Duration::from_millis(millis))
        }
    }
}

/// W2 (G13 + panel MED-11): the frame-pool idle ceiling is forwarded to the edge
/// (collect_edge_env); a set-but-unparseable or zero value fails the boot here.
fn validate_frame_pool_idle_env() -> Result<(), ServiceError> {
    if let Some(raw) = optional_string_env("OXO_EDGE_FRAME_POOL_IDLE")? {
        let value: u64 = raw.parse().map_err(|_| ServiceError::InvalidEnv {
            name: "OXO_EDGE_FRAME_POOL_IDLE",
            message: format!("expected a positive integer, got {raw:?}"),
        })?;
        if value == 0 {
            return Err(ServiceError::InvalidEnv {
                name: "OXO_EDGE_FRAME_POOL_IDLE",
                message: "must be greater than zero".to_string(),
            });
        }
    }
    Ok(())
}

/// `OXO_EDGE_POOL` selected the edge's idle-pool implementation for the
/// A/B. The pingora arm was the control and is gone; only `owned` (or unset) is
/// accepted, and `pingora` is refused with a message that says why, so an old cell file
/// or launcher fails loudly rather than silently running the other pool.
fn validate_edge_pool_env() -> Result<(), ServiceError> {
    if let Some(raw) = optional_string_env("OXO_EDGE_POOL")? {
        match raw.trim() {
            "" | "owned" => {}
            "pingora" => {
                return Err(ServiceError::InvalidEnv {
                    name: "OXO_EDGE_POOL",
                    message:
                        "the pingora pool was the A/B control and was removed; only owned remains"
                            .to_string(),
                })
            }
            other => {
                return Err(ServiceError::InvalidEnv {
                    name: "OXO_EDGE_POOL",
                    message: format!("expected owned, got {other:?}"),
                })
            }
        }
    }
    Ok(())
}

/// W2 (panel MED-9): the service owns the socket runtime dir. Missing dir: created
/// (0700) in run mode; under `--check-config` a missing dir passes (it WOULD be
/// created) but a present dir with wrong permissions fails in both modes.
fn ensure_runtime_dir(worker_socket: &Path, check_config: bool) -> Result<(), ServiceError> {
    let parent = worker_socket
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| ServiceError::InvalidEnv {
            name: "OXO_WORKER_SOCKET",
            message: "socket path has no parent directory".to_string(),
        })?;
    if !parent.exists() {
        if check_config {
            return Ok(()); // would be created at boot; nothing to verify yet
        }
        fs::create_dir_all(parent).map_err(|err| ServiceError::InvalidEnv {
            name: "OXO_WORKER_SOCKET",
            message: format!("failed to create runtime dir {}: {err}", parent.display()),
        })?;
        // Mode bits are a Unix concept; the dir-ownership contract this enforces only
        // exists on the platforms that can express it. Windows builds the cross-platform
        // stub (see the `platform` module) and never reaches a running edge.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|err| {
                ServiceError::InvalidEnv {
                    name: "OXO_WORKER_SOCKET",
                    message: format!("failed to chmod runtime dir {}: {err}", parent.display()),
                }
            })?;
        }
        return Ok(());
    }
    let metadata = fs::metadata(parent).map_err(|err| ServiceError::InvalidEnv {
        name: "OXO_WORKER_SOCKET",
        message: format!("failed to stat runtime dir {}: {err}", parent.display()),
    })?;
    if !metadata.is_dir() {
        return Err(ServiceError::InvalidEnv {
            name: "OXO_WORKER_SOCKET",
            message: format!("runtime path {} is not a directory", parent.display()),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(ServiceError::InvalidEnv {
                name: "OXO_WORKER_SOCKET",
                message: format!(
                    "runtime dir {} is group/other-accessible ({mode:04o}); want 0700",
                    parent.display()
                ),
            });
        }
    }
    Ok(())
}

pub fn run_from_env() -> Result<(), ServiceError> {
    run_from_args(env::args_os())
}

pub fn run_from_args<I, S>(args: I) -> Result<(), ServiceError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let config = ServiceConfig::from_args(args)?;
    log_service_contract(&config);
    if config.check_config {
        return Ok(());
    }
    ServiceRunner::new(config).run()
}

struct ServiceRunner {
    config: ServiceConfig,
}

impl ServiceRunner {
    fn new(config: ServiceConfig) -> Self {
        Self { config }
    }

    fn run(self) -> Result<(), ServiceError> {
        install_signal_handlers();
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
        SHUTDOWN_SIGNAL_COUNT.store(0, Ordering::SeqCst);

        let Some(mut workers) = spawn_worker_pool(&self.config)? else {
            // A drain signal arrived while the worker pool was still booting; the partial
            // pool is already torn down, so exit gracefully (D13).
            notify_systemd("STOPPING=1\nSTATUS=Oxo draining during startup");
            return Ok(());
        };

        let mut cable = match spawn_cable(&self.config) {
            Ok(cable) => cable,
            Err(err) => {
                notify_systemd("STOPPING=1\nSTATUS=Oxo Action Cable spawn failed");
                terminate_workers(&mut workers);
                return Err(err);
            }
        };

        let mut grpc = match spawn_grpc(&self.config) {
            Ok(grpc) => grpc,
            Err(err) => {
                notify_systemd("STOPPING=1\nSTATUS=Oxo gRPC spawn failed");
                terminate_cable(cable.as_mut());
                terminate_workers(&mut workers);
                return Err(err);
            }
        };

        // The just-spawned edge loads whatever cert pair is on disk now, so a
        // reload marker written at or before this instant is already satisfied.
        #[cfg(feature = "acme")]
        let boot_epoch = now_epoch_seconds();
        let mut edge = match spawn_edge(&self.config) {
            Ok(edge) => edge,
            Err(err) => {
                notify_systemd("STOPPING=1\nSTATUS=Oxo edge spawn failed");
                terminate_grpc(grpc.as_mut());
                terminate_cable(cable.as_mut());
                terminate_workers(&mut workers);
                return Err(err);
            }
        };

        if let Err(err) = wait_for_edge_ready(&mut edge, self.config.edge_bind) {
            notify_systemd("STOPPING=1\nSTATUS=Oxo edge readiness failed");
            terminate_child(&mut edge);
            terminate_grpc(grpc.as_mut());
            terminate_cable(cable.as_mut());
            terminate_workers(&mut workers);
            return Err(err);
        }

        // Reconcile a marker left by a prior run: consume it if it predates
        // this boot (the fresh edge already serves the newest pair); if a
        // renewal landed DURING boot (marker newer than the spawn), run one
        // restart cycle instead of deleting a live signal.
        #[cfg(feature = "acme")]
        if let Some(acme) = self.config.acme_renew.as_ref() {
            if let Err(err) = reconcile_boot_marker(&mut edge, &self.config, acme, boot_epoch) {
                notify_systemd("STOPPING=1\nSTATUS=Oxo boot certificate reconcile failed");
                terminate_child(&mut edge);
                terminate_grpc(grpc.as_mut());
                terminate_cable(cable.as_mut());
                terminate_workers(&mut workers);
                return Err(err);
            }
        }

        notify_systemd(ready_status(cable.is_some(), grpc.is_some()));
        monitor_children(
            &mut workers,
            &mut edge,
            cable.as_mut(),
            grpc.as_mut(),
            &self.config,
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerSlotState {
    Booting,
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

impl WorkerSlot {
    fn ready(id: u32, generation: u64, socket: PathBuf) -> Self {
        Self {
            id,
            generation,
            socket,
            state: WorkerSlotState::Ready,
            draining: false,
        }
    }
}

struct ManagedWorker {
    slot: WorkerSlot,
    child: Child,
    crash_count: u32,
    last_started: Instant,
}

struct ManagedCable {
    child: Child,
}

struct ManagedGrpc {
    child: Child,
}

// Returns `Ok(None)` when a drain was requested mid-boot, so the runner exits gracefully
// instead of reporting a startup error (D13).
fn spawn_worker_pool(config: &ServiceConfig) -> Result<Option<Vec<ManagedWorker>>, ServiceError> {
    // W3: the async kind batches (N cold Rails boots overlap instead of
    // serializing — the bench-proven shape); classic stays strictly sequential,
    // behavior pinned identical by the shared attach/finish machinery.
    if config.worker_launch.is_async() {
        return spawn_worker_pool_batched(config);
    }
    let mut workers = Vec::with_capacity(config.worker_sockets.len());
    for id in 0..config.worker_sockets.len() {
        match spawn_ready_worker(config, id as u32, 1, config.worker_ready_timeout) {
            Ok(Some(worker)) => workers.push(worker),
            Ok(None) => {
                terminate_workers(&mut workers);
                return Ok(None);
            }
            Err(err) => {
                terminate_workers(&mut workers);
                return Err(err);
            }
        }
    }
    Ok(Some(workers))
}

/// W3 (panel MED-6): batched boot with a ROLLING per-pool deadline. All N children
/// spawn (readiness readers attached immediately — a sibling's chatty boot must never
/// deadlock on an unpumped pipe), then one poll loop watches every slot: each READY
/// resets the straggler clock (the bench's rolling-deadline design, upgraded from
/// socket-exists polling to the stdout handshake + connect probe), a dead child names
/// itself immediately, and D13 tears the partial pool down on a drain signal.
fn spawn_worker_pool_batched(
    config: &ServiceConfig,
) -> Result<Option<Vec<ManagedWorker>>, ServiceError> {
    struct BootSlot {
        id: u32,
        socket: PathBuf,
        child: Child,
        pending: PendingReady,
    }
    let n = config.worker_sockets.len();
    let mut booting: Vec<BootSlot> = Vec::with_capacity(n);
    let mut ready: Vec<Option<ManagedWorker>> = (0..n).map(|_| None).collect();
    let fail = |booting: &mut Vec<BootSlot>, ready: &mut Vec<Option<ManagedWorker>>| {
        for slot in booting.iter_mut() {
            terminate_child(&mut slot.child);
        }
        let mut done: Vec<ManagedWorker> = ready.iter_mut().filter_map(Option::take).collect();
        terminate_workers(&mut done);
    };
    for id in 0..n {
        let socket = config.worker_sockets[id].clone();
        let mut child = match spawn_worker_slot(config, id as u32, 1, &socket) {
            Ok(child) => child,
            Err(err) => {
                fail(&mut booting, &mut ready);
                return Err(err);
            }
        };
        let pending = match attach_worker_readiness(&mut child) {
            Ok(pending) => pending,
            Err(err) => {
                terminate_child(&mut child);
                fail(&mut booting, &mut ready);
                return Err(err);
            }
        };
        booting.push(BootSlot {
            id: id as u32,
            socket,
            child,
            pending,
        });
    }

    let mut deadline = Instant::now() + config.worker_ready_timeout;
    while !booting.is_empty() {
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            fail(&mut booting, &mut ready);
            return Ok(None); // D13: the caller lets the monitor run the graceful drain
        }
        let mut progressed = false;
        let mut i = 0;
        while i < booting.len() {
            let slot = &mut booting[i];
            match slot.child.try_wait().map_err(ServiceError::Wait) {
                Ok(Some(status)) => {
                    fail(&mut booting, &mut ready);
                    return Err(ServiceError::ChildExited {
                        role: "worker",
                        status,
                    });
                }
                Ok(None) => {}
                Err(err) => {
                    fail(&mut booting, &mut ready);
                    return Err(err);
                }
            }
            match slot.pending.rx.try_recv() {
                Ok(Ok((Some(line), reader))) => {
                    match finish_worker_ready(&line, reader, slot.id, 1, &slot.socket) {
                        Ok(ws) => {
                            let done = booting.remove(i);
                            ready[done.id as usize] = Some(ManagedWorker {
                                slot: ws,
                                child: done.child,
                                crash_count: 0,
                                last_started: Instant::now(),
                            });
                            progressed = true;
                            continue;
                        }
                        Err(err) => {
                            fail(&mut booting, &mut ready);
                            return Err(err);
                        }
                    }
                }
                Ok(Ok((None, _reader))) => {
                    fail(&mut booting, &mut ready);
                    return Err(ServiceError::WorkerReadyDisconnected);
                }
                Ok(Err(source)) => {
                    fail(&mut booting, &mut ready);
                    if source.to_string().contains("pre-ready output exceeded cap") {
                        return Err(ServiceError::WorkerReadinessOutputTooLarge);
                    }
                    return Err(ServiceError::WorkerReadyIo { source });
                }
                Err(mpsc::TryRecvError::Empty) => {
                    i += 1;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    fail(&mut booting, &mut ready);
                    return Err(ServiceError::WorkerReadyDisconnected);
                }
            }
        }
        if progressed {
            // Rolling: each READY proves the pool is making progress; stragglers get a
            // fresh window rather than sharing one global budget.
            deadline = Instant::now() + config.worker_ready_timeout;
        } else if Instant::now() >= deadline {
            fail(&mut booting, &mut ready);
            return Err(ServiceError::WorkerReadyTimeout);
        } else {
            thread::sleep(MONITOR_INTERVAL.min(Duration::from_millis(25)));
        }
    }
    let workers: Vec<ManagedWorker> = ready.into_iter().flatten().collect();
    debug_assert_eq!(workers.len(), n, "every slot must be ready or have failed");
    Ok(Some(workers))
}

fn spawn_ready_worker(
    config: &ServiceConfig,
    id: u32,
    generation: u64,
    timeout: Duration,
) -> Result<Option<ManagedWorker>, ServiceError> {
    let socket = config.worker_sockets[id as usize].clone();
    let mut child = spawn_worker_slot(config, id, generation, &socket)?;
    let pending = match attach_worker_readiness(&mut child) {
        Ok(pending) => pending,
        Err(err) => {
            terminate_child(&mut child);
            return Err(err);
        }
    };
    let Some(slot) = wait_for_worker_ready(&mut child, pending, id, generation, &socket, timeout)?
    else {
        return Ok(None);
    };
    Ok(Some(ManagedWorker {
        slot,
        child,
        crash_count: 0,
        last_started: Instant::now(),
    }))
}

fn spawn_worker_slot(
    config: &ServiceConfig,
    id: u32,
    generation: u64,
    socket: &Path,
) -> Result<Child, ServiceError> {
    // W2: the launch surface decides the command; EVERYTHING else — env_clear, the
    // per-slot vars, the process group, the readiness pipes — is shared verbatim, so
    // the async kind inherits the whole supervision contract, not a parallel copy.
    let (mut command, spawn_path) = match &config.worker_launch {
        WorkerLaunch::Classic => {
            let bin = config
                .worker_bin
                .as_ref()
                .expect("classic launch always resolves worker_bin (from_cli invariant)");
            (Command::new(bin), bin.clone())
        }
        WorkerLaunch::Async {
            bundle_bin,
            ruby_bin,
            script,
            app_root,
        } => {
            let mut c = Command::new(bundle_bin);
            // `<bundle> exec <ruby> <script> <socket>`: the interpreter is named
            // absolutely (panel MED-7 — `bundle exec ruby` would PATH-resolve it);
            // the socket rides argv because the worker's usage contract is ARGV[0]
            // (the env twin below is also set — both agree by construction).
            c.arg("exec").arg(ruby_bin).arg(script).arg(socket);
            c.current_dir(app_root);
            (c, bundle_bin.clone())
        }
    };
    configure_child_process(&mut command);
    command
        .env_clear()
        .envs(config.worker_env.iter().cloned())
        .env("OXO_WORKER_SOCKET", socket)
        .env("OXO_WORKER_ID", id.to_string())
        .env("OXO_WORKER_GENERATION", generation.to_string())
        .env("OXO_WORKER_POOL_SIZE", config.worker_count.to_string())
        .env(
            "OXO_WORKER_MULTIPROCESS",
            if config.worker_count > 1 { "1" } else { "0" },
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.spawn().map_err(|source| ServiceError::Spawn {
        role: "worker",
        path: spawn_path,
        source,
    })
}

#[cfg(target_os = "linux")]
fn configure_child_process(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(target_os = "linux"))]
fn configure_child_process(_command: &mut Command) {}
/// W3 (panel MED-6): the readiness reader, attachable AT SPAWN TIME. The batched
/// async boot must attach every child's pipes before waiting on any of them — a sibling
/// writing >64 KB of boot stderr with no pump would deadlock the whole pool — and the
/// classic sequential path consumes the exact same machinery so the two kinds cannot
/// drift.
struct PendingReady {
    rx: mpsc::Receiver<std::io::Result<(Option<String>, BufReader<std::process::ChildStdout>)>>,
}

fn attach_worker_readiness(worker: &mut Child) -> Result<PendingReady, ServiceError> {
    let stdout = worker
        .stdout
        .take()
        .ok_or(ServiceError::MissingWorkerStdout)?;
    let stderr = worker
        .stderr
        .take()
        .ok_or(ServiceError::MissingWorkerStderr)?;
    drain_stderr(stderr);

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut seen = 0usize;
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    let _ = tx.send(Ok((None, reader)));
                    break;
                }
                Ok(_) if line.starts_with(WORKER_READY_PREFIX) => {
                    let _ = tx.send(Ok((Some(line), reader)));
                    break;
                }
                Ok(_) => {
                    seen += line.len();
                    if seen > MAX_PRE_READY_OUTPUT_BYTES {
                        let _ =
                            tx.send(Err(std::io::Error::other("pre-ready output exceeded cap")));
                        break;
                    }
                }
                Err(source) => {
                    let _ = tx.send(Err(source));
                    break;
                }
            }
        }
    });
    Ok(PendingReady { rx })
}

/// The READY-line completion shared by both boot shapes: exact-socket assert, the
/// 0600/0700 path gate, a real connect probe, then hand the rest of stdout to the
/// parent. The caller owns child termination on error.
fn finish_worker_ready(
    line: &str,
    reader: BufReader<std::process::ChildStdout>,
    id: u32,
    generation: u64,
    expected_socket: &Path,
) -> Result<WorkerSlot, ServiceError> {
    let ready_socket = ready_socket_from_line(line)?;
    if ready_socket != expected_socket {
        return Err(ServiceError::WorkerReadyWrongSocket {
            expected: expected_socket.to_path_buf(),
            got: ready_socket,
        });
    }
    crate::validate_worker_socket_path(expected_socket).map_err(|err| {
        ServiceError::WorkerSocketInvalid {
            path: expected_socket.to_path_buf(),
            message: err.to_string(),
        }
    })?;
    probe_worker_socket(expected_socket)?;
    drain_stdout(reader);
    Ok(WorkerSlot::ready(
        id,
        generation,
        expected_socket.to_path_buf(),
    ))
}

// Returns `Ok(None)` when a drain was requested while waiting, so callers stop and let the
// monitor loop run the graceful shutdown path instead of blocking here (D13).
fn wait_for_worker_ready(
    worker: &mut Child,
    pending: PendingReady,
    id: u32,
    generation: u64,
    expected_socket: &Path,
    timeout: Duration,
) -> Result<Option<WorkerSlot>, ServiceError> {
    let rx = pending.rx;
    let deadline = Instant::now() + timeout;
    loop {
        // D13: honor a drain signal promptly instead of blocking up to the full readiness
        // timeout (15s). Terminate the pending child and report shutdown so the caller
        // stops restarting and the monitor loop runs the graceful drain.
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            terminate_child(worker);
            return Ok(None);
        }
        if let Some(status) = worker.try_wait().map_err(ServiceError::Wait)? {
            return Err(ServiceError::ChildExited {
                role: "worker",
                status,
            });
        }

        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok(Ok((Some(line), reader))) => {
                match finish_worker_ready(&line, reader, id, generation, expected_socket) {
                    Ok(slot) => return Ok(Some(slot)),
                    Err(err) => {
                        terminate_child(worker);
                        return Err(err);
                    }
                }
            }
            Ok(Ok((None, _reader))) => {
                terminate_child(worker);
                return Err(ServiceError::WorkerReadyDisconnected);
            }
            Ok(Err(source)) => {
                terminate_child(worker);
                if source.to_string().contains("pre-ready output exceeded cap") {
                    return Err(ServiceError::WorkerReadinessOutputTooLarge);
                }
                return Err(ServiceError::WorkerReadyIo { source });
            }
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {
                terminate_child(worker);
                return Err(ServiceError::WorkerReadyTimeout);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                terminate_child(worker);
                return Err(ServiceError::WorkerReadyDisconnected);
            }
        }
    }
}

fn ready_socket_from_line(line: &str) -> Result<PathBuf, ServiceError> {
    let Some(value) = line.strip_prefix(WORKER_READY_PREFIX) else {
        return Err(ServiceError::WorkerReadiness { line: line.into() });
    };
    Ok(PathBuf::from(value.trim_end_matches(['\r', '\n'])))
}

#[cfg(target_os = "linux")]
fn probe_worker_socket(socket: &Path) -> Result<(), ServiceError> {
    use std::os::unix::net::UnixStream;

    UnixStream::connect(socket)
        .map(|_| ())
        .map_err(|source| ServiceError::WorkerSocketProbe {
            path: socket.to_path_buf(),
            source,
        })
}

#[cfg(not(target_os = "linux"))]
fn probe_worker_socket(_socket: &Path) -> Result<(), ServiceError> {
    Ok(())
}
fn drain_stdout<R>(mut reader: R)
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut stdout = std::io::stdout().lock();
        let _ = std::io::copy(&mut reader, &mut stdout);
        let _ = stdout.flush();
    });
}

fn drain_stderr<R>(mut reader: R)
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut stderr = std::io::stderr().lock();
        let _ = std::io::copy(&mut reader, &mut stderr);
        let _ = stderr.flush();
    });
}

fn wait_for_edge_ready(edge: &mut Child, bind: SocketAddr) -> Result<(), ServiceError> {
    let deadline = Instant::now() + EDGE_READY_TIMEOUT;
    loop {
        if let Some(status) = edge.try_wait().map_err(ServiceError::Wait)? {
            return Err(ServiceError::ChildExited {
                role: "edge",
                status,
            });
        }
        if TcpStream::connect_timeout(&bind, Duration::from_millis(50)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            terminate_child(edge);
            return Err(ServiceError::EdgeReadyTimeout { bind });
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_cable_ready(cable: &mut Child, bind: SocketAddr) -> Result<(), ServiceError> {
    let deadline = Instant::now() + CABLE_READY_TIMEOUT;
    loop {
        if let Some(status) = cable.try_wait().map_err(ServiceError::Wait)? {
            return Err(ServiceError::ChildExited {
                role: "cable",
                status,
            });
        }
        if TcpStream::connect_timeout(&bind, Duration::from_millis(50)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            terminate_child(cable);
            return Err(ServiceError::CableReadyTimeout { bind });
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_grpc_ready(grpc: &mut Child, bind: SocketAddr) -> Result<(), ServiceError> {
    let deadline = Instant::now() + GRPC_READY_TIMEOUT;
    loop {
        if let Some(status) = grpc.try_wait().map_err(ServiceError::Wait)? {
            return Err(ServiceError::ChildExited {
                role: "grpc",
                status,
            });
        }
        if TcpStream::connect_timeout(&bind, Duration::from_millis(50)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            terminate_child(grpc);
            return Err(ServiceError::GrpcReadyTimeout { bind });
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn spawn_cable(config: &ServiceConfig) -> Result<Option<ManagedCable>, ServiceError> {
    let Some(cable_bin) = config.cable_bin.as_ref() else {
        return Ok(None);
    };
    let bind = config.cable_bind.ok_or(ServiceError::MissingEnv {
        name: "OXO_CABLE_BIND",
    })?;
    let mut command = Command::new(cable_bin);
    configure_child_process(&mut command);
    command
        .env_clear()
        .envs(config.cable_env.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().map_err(|source| ServiceError::Spawn {
        role: "cable",
        path: cable_bin.clone(),
        source,
    })?;
    wait_for_cable_ready(&mut child, bind)?;
    Ok(Some(ManagedCable { child }))
}

fn spawn_grpc(config: &ServiceConfig) -> Result<Option<ManagedGrpc>, ServiceError> {
    let Some(grpc_bin) = config.grpc_bin.as_ref() else {
        return Ok(None);
    };
    let bind = config.grpc_bind.ok_or(ServiceError::MissingEnv {
        name: "OXO_GRPC_BIND",
    })?;
    let mut command = Command::new(grpc_bin);
    configure_child_process(&mut command);
    command
        .env_clear()
        .envs(config.grpc_env.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().map_err(|source| ServiceError::Spawn {
        role: "grpc",
        path: grpc_bin.clone(),
        source,
    })?;
    wait_for_grpc_ready(&mut child, bind)?;
    Ok(Some(ManagedGrpc { child }))
}

fn ready_status(cable: bool, grpc: bool) -> &'static str {
    match (cable, grpc) {
        (true, true) => {
            "READY=1\nSTATUS=Oxo edge, workers, standalone Action Cable, and standalone gRPC are ready"
        }
        (true, false) => {
            "READY=1\nSTATUS=Oxo edge, workers, and standalone Action Cable are ready"
        }
        (false, true) => {
            "READY=1\nSTATUS=Oxo edge, workers, and standalone gRPC are ready"
        }
        (false, false) => "READY=1\nSTATUS=Oxo edge and workers are ready",
    }
}

fn spawn_edge(config: &ServiceConfig) -> Result<Child, ServiceError> {
    let mut command = Command::new(&config.edge_bin);
    configure_child_process(&mut command);
    command
        .env_clear()
        .envs(config.edge_env.iter().cloned())
        .args(config.edge_args.iter())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command.spawn().map_err(|source| ServiceError::Spawn {
        role: "edge",
        path: config.edge_bin.clone(),
        source,
    })
}

#[cfg(feature = "acme")]
struct ManagedRenew {
    child: Child,
    started: Instant,
}

#[cfg(feature = "acme")]
fn spawn_renew_child(
    config: &ServiceConfig,
    acme: &AcmeRenewConfig,
) -> Result<Child, ServiceError> {
    let mut command = Command::new(&config.edge_bin);
    configure_child_process(&mut command);
    command.env_clear();
    // Outbound TLS to the CA must keep working behind corporate MITM roots.
    for name in ["SSL_CERT_FILE", "SSL_CERT_DIR"] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .args(acme.renew_args.iter())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command.spawn().map_err(|source| ServiceError::Spawn {
        role: "acme-renew",
        path: config.edge_bin.clone(),
        source,
    })
}

#[cfg(feature = "acme")]
fn terminate_renew(renew: Option<&mut ManagedRenew>) {
    if let Some(managed) = renew {
        terminate_child(&mut managed.child);
    }
}

fn monitor_children(
    workers: &mut [ManagedWorker],
    edge: &mut Child,
    mut cable: Option<&mut ManagedCable>,
    mut grpc: Option<&mut ManagedGrpc>,
    config: &ServiceConfig,
) -> Result<(), ServiceError> {
    #[cfg(feature = "acme")]
    let mut renew: Option<ManagedRenew> = None;
    #[cfg(feature = "acme")]
    let mut next_renew_at = config
        .acme_renew
        .as_ref()
        .map(|acme| Instant::now() + acme.interval);
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            notify_systemd("STOPPING=1\nSTATUS=Oxo draining after shutdown signal");
            #[cfg(feature = "acme")]
            terminate_renew(renew.as_mut());
            drain_service(
                edge,
                cable.as_deref_mut(),
                grpc.as_deref_mut(),
                workers,
                config.drain_grace,
                config.edge_drain_grace,
                config.worker_drain_wait,
            );
            return Ok(());
        }
        if let Some(status) = edge.try_wait().map_err(ServiceError::Wait)? {
            notify_systemd("STOPPING=1\nSTATUS=Oxo edge exited");
            #[cfg(feature = "acme")]
            terminate_renew(renew.as_mut());
            terminate_grpc(grpc.as_deref_mut());
            terminate_cable(cable.as_deref_mut());
            terminate_workers(workers);
            return Err(ServiceError::ChildExited {
                role: "edge",
                status,
            });
        }
        if let Some(cable) = cable.as_deref_mut() {
            if let Some(status) = cable.child.try_wait().map_err(ServiceError::Wait)? {
                notify_systemd("STOPPING=1\nSTATUS=Oxo Action Cable exited");
                #[cfg(feature = "acme")]
                terminate_renew(renew.as_mut());
                terminate_child(edge);
                terminate_grpc(grpc.as_deref_mut());
                terminate_workers(workers);
                return Err(ServiceError::ChildExited {
                    role: "cable",
                    status,
                });
            }
        }
        if let Some(grpc) = grpc.as_deref_mut() {
            if let Some(status) = grpc.child.try_wait().map_err(ServiceError::Wait)? {
                notify_systemd("STOPPING=1\nSTATUS=Oxo gRPC exited");
                #[cfg(feature = "acme")]
                terminate_renew(renew.as_mut());
                terminate_child(edge);
                terminate_cable(cable.as_deref_mut());
                terminate_workers(workers);
                return Err(ServiceError::ChildExited {
                    role: "grpc",
                    status,
                });
            }
        }
        // D14: a worker restart that fails (spawn error, or the respawned worker never
        // signals readiness) must tear down every other child before returning, matching
        // the edge/cable/grpc exit branches above. The cleanup cannot run inside the
        // `iter_mut()` loop (it needs a fresh `&mut workers` borrow), so capture the
        // failure, break the loop, then clean up.
        let mut restart_failure = None;
        for worker in workers.iter_mut() {
            if let Some(status) = worker.child.try_wait().map_err(ServiceError::Wait)? {
                notify_systemd("STATUS=Oxo worker restarting");
                if let Err(err) = restart_worker(config, worker, status) {
                    restart_failure = Some(err);
                }
                break;
            }
        }
        if let Some(err) = restart_failure {
            notify_systemd("STOPPING=1\nSTATUS=Oxo worker restart failed");
            #[cfg(feature = "acme")]
            terminate_renew(renew.as_mut());
            terminate_child(edge);
            terminate_grpc(grpc.as_deref_mut());
            terminate_cable(cable.as_deref_mut());
            terminate_workers(workers);
            return Err(err);
        }
        #[cfg(feature = "acme")]
        if let Some(acme) = config.acme_renew.as_ref() {
            let mut reaped = false;
            if let Some(managed) = renew.as_mut() {
                match managed.child.try_wait().map_err(ServiceError::Wait)? {
                    Some(status) => {
                        if !status.success() {
                            eprintln!(
                                "oxo-pingora-service: ACME renewal child exited with {status}"
                            );
                        }
                        reaped = true;
                    }
                    None if managed.started.elapsed() >= acme.timeout => {
                        eprintln!(
                            "oxo-pingora-service: ACME renewal child exceeded \
                             OXO_SERVICE_ACME_RENEW_TIMEOUT_MS; terminating it"
                        );
                        terminate_child(&mut managed.child);
                        reaped = true;
                    }
                    None => {}
                }
            }
            if reaped {
                renew = None;
                // The reload marker is evaluated after EVERY reap (exit 0,
                // nonzero, or timeout-kill), so a child killed just after
                // writing the marker still triggers the restart. An
                // unrecoverable reload failure tears down the whole service
                // like any other fatal branch (no orphans).
                if let Err(err) = maybe_reload_edge(edge, config, acme) {
                    notify_systemd("STOPPING=1\nSTATUS=Oxo certificate reload failed");
                    terminate_grpc(grpc.as_deref_mut());
                    terminate_cable(cable.as_deref_mut());
                    terminate_workers(workers);
                    return Err(err);
                }
            } else if renew.is_none()
                && next_renew_at
                    .map(|at| Instant::now() >= at)
                    .unwrap_or(false)
                && !SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
            {
                match spawn_renew_child(config, acme) {
                    Ok(child) => {
                        renew = Some(ManagedRenew {
                            child,
                            started: Instant::now(),
                        });
                    }
                    Err(err) => {
                        // Not fatal: the serving edge is healthy; retry next interval.
                        eprintln!("oxo-pingora-service: failed to spawn ACME renewal child: {err}");
                    }
                }
                next_renew_at = Some(Instant::now() + acme.interval);
            }
        }
        thread::sleep(MONITOR_INTERVAL);
    }
}

fn restart_worker(
    config: &ServiceConfig,
    worker: &mut ManagedWorker,
    _status: ExitStatus,
) -> Result<(), ServiceError> {
    worker.slot.state = WorkerSlotState::Failed;
    // D13: a drain requested while a worker is crash-looping must be honored within roughly
    // one monitor interval, not after the whole backoff + readiness wait. Leaving the slot
    // Failed and returning `Ok(())` lets monitor_children's loop head run drain_service.
    if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        return Ok(());
    }
    worker.crash_count = if worker.last_started.elapsed() < Duration::from_secs(5) {
        worker.crash_count.saturating_add(1)
    } else {
        1
    };
    if !sleep_unless_shutdown(restart_backoff(worker.crash_count)) {
        return Ok(());
    }
    let generation = worker.slot.generation.saturating_add(1);
    let id = worker.slot.id;
    let socket = worker.slot.socket.clone();
    let mut child = spawn_worker_slot(config, id, generation, &socket)?;
    let pending = match attach_worker_readiness(&mut child) {
        Ok(pending) => pending,
        Err(err) => {
            terminate_child(&mut child);
            return Err(err);
        }
    };
    // W3 (panel MED-5): respawns run on the SHORTER warm-boot budget — a
    // crash-looping async reactor must not blind the monitor for the 120 s cold-boot
    // window per attempt (the two-reactor kill test pins that the survivor keeps
    // serving throughout).
    let slot = match wait_for_worker_ready(
        &mut child,
        pending,
        id,
        generation,
        &socket,
        config.worker_respawn_ready_timeout,
    ) {
        Ok(Some(slot)) => slot,
        Ok(None) => {
            // A drain was requested during the readiness wait; the child is already
            // terminated. Return so monitor_children runs the graceful drain.
            return Ok(());
        }
        Err(err) => {
            // wait_for_worker_ready terminates `child` on most failure paths, but not on a
            // readiness-pipe IO error; make sure the freshly spawned child never leaks.
            terminate_child(&mut child);
            return Err(err);
        }
    };
    worker.child = child;
    worker.slot = slot;
    worker.last_started = Instant::now();
    Ok(())
}

#[cfg(feature = "acme")]
fn acme_reload_err(err: crate::acme::AcmeError) -> ServiceError {
    ServiceError::AcmeReload {
        message: err.to_string(),
    }
}

#[cfg(feature = "acme")]
fn now_epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|dur| dur.as_secs())
        .unwrap_or(0)
}

/// At startup, reconcile any leftover reload marker. A marker at or before the
/// boot instant is already satisfied by the freshly booted edge, so consume it
/// without a restart; a marker newer than the boot instant means a renewal
/// completed while the edge was starting, so run one restart cycle.
#[cfg(feature = "acme")]
fn reconcile_boot_marker(
    edge: &mut Child,
    config: &ServiceConfig,
    acme: &AcmeRenewConfig,
    boot_epoch: u64,
) -> Result<(), ServiceError> {
    match crate::acme::reload_marker_updated_at(&acme.state_dir).map_err(acme_reload_err)? {
        None => Ok(()),
        Some(updated_at) if updated_at <= boot_epoch => {
            crate::acme::consume_reload_marker(&acme.state_dir).map_err(acme_reload_err)
        }
        Some(_) => restart_edge(edge, config, &acme.state_dir),
    }
}

/// After a renewal child reaps, act on the reload marker: if a restart is owed,
/// perform the bounded edge restart (Commit D). No marker → nothing to do.
#[cfg(feature = "acme")]
fn maybe_reload_edge(
    edge: &mut Child,
    config: &ServiceConfig,
    acme: &AcmeRenewConfig,
) -> Result<(), ServiceError> {
    if crate::acme::reload_marker_updated_at(&acme.state_dir)
        .map_err(acme_reload_err)?
        .is_none()
    {
        return Ok(());
    }
    restart_edge(edge, config, &acme.state_dir)
}

/// Deliberate, bounded edge restart to load a freshly renewed certificate
/// pair. The old edge is drained and reaped BEFORE respawning (so the monitor
/// loop's fatal edge-exit branch never observes this stop — we replace the
/// slot in place). The new pair is tried once, retried once on any failure
/// (a transient must not be misdiagnosed as a bad cert), and only then rolled
/// back to the retained pre-renewal pair. On success the marker is consumed;
/// on rollback it is deliberately left so the scheduler re-attempts. Every
/// step is SHUTDOWN-interruptible.
#[cfg(feature = "acme")]
fn restart_edge(
    edge: &mut Child,
    config: &ServiceConfig,
    state_dir: &Path,
) -> Result<(), ServiceError> {
    notify_systemd("STATUS=Oxo edge restarting for certificate reload");
    drain_edge_for_reload(edge, config.edge_drain_grace);

    // Try the new pair, then one same-pair retry before deciding it is bad.
    let mut booted = false;
    for _ in 0..2 {
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            return Ok(());
        }
        *edge = spawn_edge(config)?;
        if wait_for_edge_ready(edge, config.edge_bind).is_ok() {
            booted = true;
            break;
        }
        terminate_child(edge);
    }
    if booted {
        crate::acme::consume_reload_marker(state_dir).map_err(acme_reload_err)?;
        notify_systemd("STATUS=Oxo edge reloaded a renewed certificate");
        return Ok(());
    }

    // Both new-pair attempts failed: roll back to the retained pair. The marker
    // is NOT consumed (a restart is still owed once the operator intervenes).
    crate::acme::rollback_to_retained_pair(
        state_dir,
        now_epoch_seconds(),
        "edge failed to boot with the renewed certificate",
    )
    .map_err(acme_reload_err)?;
    if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        return Ok(());
    }
    *edge = spawn_edge(config)?;
    wait_for_edge_ready(edge, config.edge_bind)?;
    notify_systemd("STATUS=Oxo edge restarted on the rolled-back certificate");
    Ok(())
}

/// Backoff before the first respawn of a crashed worker; doubles per
/// consecutive fast crash.
const RESTART_BACKOFF_BASE: Duration = Duration::from_millis(100);
/// Cap on the doublings: 100ms << 5 = 3.2s worst-case wait per restart
/// attempt, keeping a crash-looping slot's monitor stall bounded.
const RESTART_BACKOFF_MAX_DOUBLINGS: u32 = 5;

fn restart_backoff(crash_count: u32) -> Duration {
    let doublings = crash_count
        .saturating_sub(1)
        .min(RESTART_BACKOFF_MAX_DOUBLINGS);
    RESTART_BACKOFF_BASE * (1u32 << doublings)
}

/// Sleep for `dur`, but wake early if a drain is requested. Returns `true` if the full
/// duration elapsed, `false` if `SHUTDOWN_REQUESTED` cut it short — the caller then bails
/// out of an in-progress restart so shutdown is honored within one monitor interval.
fn sleep_unless_shutdown(dur: Duration) -> bool {
    let deadline = Instant::now() + dur;
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            return false;
        }
        let now = Instant::now();
        if now >= deadline {
            return true;
        }
        thread::sleep(
            deadline
                .saturating_duration_since(now)
                .min(MONITOR_INTERVAL),
        );
    }
}

fn terminate_workers(workers: &mut [ManagedWorker]) {
    for worker in workers {
        terminate_child(&mut worker.child);
        worker.slot.state = WorkerSlotState::Stopped;
    }
}

fn terminate_cable(cable: Option<&mut ManagedCable>) {
    if let Some(cable) = cable {
        terminate_child(&mut cable.child);
    }
}

fn terminate_grpc(grpc: Option<&mut ManagedGrpc>) {
    if let Some(grpc) = grpc {
        terminate_child(&mut grpc.child);
    }
}

// Drain ordering is load-bearing: the edge (and the Cable/gRPC sidecars) are signalled and
// waited on BEFORE the workers are asked to terminate. The edge is the only thing accepting
// public traffic and routing it to the worker UDS sockets; stopping it first means in-flight
// clients see a clean edge shutdown instead of "connection refused" from a worker socket that
// vanished underneath the edge. Reordering this to kill workers first would reintroduce the
// mid-request failures this sequence exists to avoid.
#[cfg(feature = "acme")]
fn drain_edge_for_reload(edge: &mut Child, edge_grace: Duration) {
    request_child_term(edge);
    if !wait_child_until(edge, edge_grace) {
        force_child_shutdown(edge);
    }
}

fn drain_service(
    edge: &mut Child,
    cable: Option<&mut ManagedCable>,
    grpc: Option<&mut ManagedGrpc>,
    workers: &mut [ManagedWorker],
    grace: Duration,
    edge_grace: Duration,
    worker_drain_wait: Duration,
) {
    for worker in workers.iter_mut() {
        worker.slot.state = WorkerSlotState::Draining;
        worker.slot.draining = true;
    }

    request_child_term(edge);
    let service_deadline = Instant::now() + grace;
    let edge_deadline = bounded_stage_deadline(service_deadline, edge_grace);
    let edge_done = wait_child_until_deadline(edge, edge_deadline);

    let mut cable = cable;
    let mut grpc = grpc;
    if let Some(cable) = &mut cable {
        request_child_term(&mut cable.child);
    }
    if let Some(grpc) = &mut grpc {
        request_child_term(&mut grpc.child);
    }

    let sidecar_deadline = bounded_stage_deadline(service_deadline, SIDECAR_DRAIN_WAIT);
    let cable_done = match &mut cable {
        Some(cable) => wait_child_until_deadline(&mut cable.child, sidecar_deadline),
        None => true,
    };
    let grpc_done = match &mut grpc {
        Some(grpc) => wait_child_until_deadline(&mut grpc.child, sidecar_deadline),
        None => true,
    };

    for worker in workers.iter_mut() {
        request_child_term(&mut worker.child);
    }

    // W2 (panel MED-10): async derives this stage from the worker's own drain
    // deadline (+margin), so the supervisor never TERM-sweeps a worker that is still
    // inside its contracted in-flight drain.
    let worker_deadline = bounded_stage_deadline(service_deadline, worker_drain_wait);
    for worker in workers.iter_mut() {
        if wait_child_until_deadline(&mut worker.child, worker_deadline) {
            worker.slot.state = WorkerSlotState::Stopped;
        }
    }

    if !edge_done {
        force_child_shutdown(edge);
    }
    if !cable_done {
        if let Some(cable) = cable {
            force_child_shutdown(&mut cable.child);
        }
    }
    if !grpc_done {
        if let Some(grpc) = grpc {
            force_child_shutdown(&mut grpc.child);
        }
    }
    for worker in workers.iter_mut() {
        if !matches!(worker.child.try_wait(), Ok(Some(_))) {
            force_child_shutdown(&mut worker.child);
        }
        worker.slot.state = WorkerSlotState::Stopped;
    }
}

fn request_child_term(child: &mut Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    terminate_process_group(child, TerminationSignal::Term);
}

fn force_child_shutdown(child: &mut Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    terminate_process_group(child, TerminationSignal::Kill);
    let _ = child.kill();
    let _ = child.wait();
}

fn terminate_child(child: &mut Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    terminate_process_group(child, TerminationSignal::Term);
    if wait_child_until(child, CHILD_TERM_TIMEOUT) {
        return;
    }
    terminate_process_group(child, TerminationSignal::Kill);
    let _ = child.kill();
    let _ = child.wait();
}

enum TerminationSignal {
    Term,
    Kill,
}

#[cfg(target_os = "linux")]
fn terminate_process_group(child: &Child, signal: TerminationSignal) {
    let sig = match signal {
        TerminationSignal::Term => libc::SIGTERM,
        TerminationSignal::Kill => libc::SIGKILL,
    };
    let pgid = -(child.id() as libc::pid_t);
    unsafe {
        libc::kill(pgid, sig);
    }
}

#[cfg(not(target_os = "linux"))]
fn terminate_process_group(_child: &Child, _signal: TerminationSignal) {}

fn wait_child_until(child: &mut Child, timeout: Duration) -> bool {
    wait_child_until_deadline(child, Instant::now() + timeout)
}

fn bounded_stage_deadline(service_deadline: Instant, stage: Duration) -> Instant {
    let stage_deadline = Instant::now() + stage;
    if stage_deadline < service_deadline {
        stage_deadline
    } else {
        service_deadline
    }
}

fn wait_child_until_deadline(child: &mut Child, deadline: Instant) -> bool {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if SHUTDOWN_SIGNAL_COUNT.load(Ordering::SeqCst) > 1 => return false,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => return false,
        }
    }
}

#[cfg(target_os = "linux")]
fn install_signal_handlers() {
    unsafe extern "C" fn handle_signal(_signal: libc::c_int) {
        SHUTDOWN_SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    }

    unsafe {
        #[allow(function_casts_as_integer)]
        {
            libc::signal(libc::SIGTERM, handle_signal as usize);
            libc::signal(libc::SIGINT, handle_signal as usize);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn install_signal_handlers() {}

#[cfg(target_os = "linux")]
fn notify_systemd(message: &str) {
    use std::os::unix::net::UnixDatagram;

    let Some(socket) = env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    if socket.is_empty() {
        return;
    }
    if let Ok(datagram) = UnixDatagram::unbound() {
        let _ = datagram.send_to(message.as_bytes(), socket);
    }
}

#[cfg(not(target_os = "linux"))]
fn notify_systemd(_message: &str) {}

fn log_service_contract(config: &ServiceConfig) {
    eprintln!(
        "oxo_service_contract worker_count={} edge_bind={} cable_enabled={} grpc_enabled={} worker_env=[{}] edge_env=[{}] cable_env=[{}] grpc_env=[{}]",
        config.worker_count,
        config.edge_bind,
        config.cable_bind.is_some(),
        config.grpc_bind.is_some(),
        redacted_env_summary(&config.worker_env),
        redacted_env_summary(&config.edge_env),
        redacted_env_summary(&config.cable_env),
        redacted_env_summary(&config.grpc_env),
    );
    // children inherit this process's descriptor limit verbatim (no pre_exec,
    // no setrlimit anywhere), so the supervisor states it beside the contract. The
    // edge prints its own fd-budget against the same number at boot.
    #[cfg(target_os = "linux")]
    {
        use crate::fd_budget::Nofile;
        let limit = match crate::fd_budget::read_nofile_limits() {
            Nofile::Limits { soft, hard } => format!("soft={soft} hard={hard}"),
            Nofile::Unlimited => "unlimited".to_string(),
            Nofile::Unknown => "unknown".to_string(),
        };
        eprintln!(
            "oxo_service_contract nofile {limit} (RLIMIT_NOFILE; the edge and the workers inherit it; the edge prints oxo_edge_config_notice fd-budget against it)"
        );
    }
}

fn redacted_env_summary(envs: &[(OsString, OsString)]) -> String {
    envs.iter()
        .map(|(name, value)| {
            let name = name.to_string_lossy();
            format!("{}={}", name, redacted_env_value(&name, value.as_os_str()))
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn redacted_env_value(name: &str, value: &OsStr) -> &'static str {
    if value.to_string_lossy().is_empty() {
        "<empty>"
    } else if is_sensitive_env_name(name) {
        "<redacted>"
    } else {
        "<set>"
    }
}

fn is_sensitive_env_name(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    name.contains("SECRET")
        || name.contains("PASSWORD")
        || name.contains("TOKEN")
        || name.contains("CREDENTIAL")
        || name == "DATABASE_URL"
        || name == "REDIS_URL"
        || name == "RAILS_MASTER_KEY"
        || name.ends_with("_KEY")
}
// The operator-supplied extra-passthrough allowlist shared by the worker,
// cable, and gRPC child-env collectors. `allow_var` is double-duty: it is the
// env var read AND the `name` reported in InvalidEnv errors, so each collector
// must pass its OWN literal (OXO_APP_ENV_ALLOW / OXO_CABLE_ENV_ALLOW /
// OXO_GRPC_ENV_ALLOW).
fn apply_env_allowlist(
    envs: &mut Vec<(OsString, OsString)>,
    allow_var: &'static str,
) -> Result<(), ServiceError> {
    if let Ok(extra) = env::var(allow_var) {
        for name in extra
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            if !is_env_name_safe(name) {
                return Err(ServiceError::InvalidEnv {
                    name: allow_var,
                    message: format!("invalid env name {name:?}"),
                });
            }
            if is_edge_only_env_name(name) {
                return Err(ServiceError::InvalidEnv {
                    name: allow_var,
                    message: format!("edge-only env name {name:?} is not allowed"),
                });
            }
            push_optional_env(envs, name);
        }
    }
    Ok(())
}

fn collect_worker_env(worker_socket: &Path) -> Result<Vec<(OsString, OsString)>, ServiceError> {
    let mut envs = Vec::new();
    push_required_env(&mut envs, "OXO_WORKER_APP")?;
    push_env_value(&mut envs, "OXO_WORKER_SOCKET", worker_socket.as_os_str());
    push_optional_env(&mut envs, "OXO_WORKER_THREADS");
    push_optional_env(&mut envs, "OXO_WORKER_MAX_BODY");
    push_optional_env(&mut envs, "OXO_WORKER_RACK_LINT");
    push_optional_env(&mut envs, "OXO_WORKER_STREAMING");
    for name in default_worker_passthrough_env() {
        push_optional_env(&mut envs, name);
    }
    apply_env_allowlist(&mut envs, "OXO_APP_ENV_ALLOW")?;
    Ok(envs)
}

/// W2: the async worker's env — same allowlist discipline as classic
/// (`collect_worker_env` is the template), plus: `OXO_ASYNC=1` injected (the app
/// pins :fiber isolation under it); `BUNDLE_GEMFILE` = operator value else
/// `<app_root>/Gemfile`, must exist either way (a bundler boot without it dies with an
/// unhelpful stack, not a named knob); `OXO_WORKER_MAX_BODY` +
/// `OXO_WORKER_RACK_LINT` forwarded (panel MED-4: the worker READS them; dropping
/// them here would be the defect-#3 class again); the `OXO_DB*` family (redacted in
/// the contract log via is_sensitive_env_name); `OXO_WORKER_DRAIN_DEADLINE_MS`
/// (the worker's half of the MED-10 pairing). Classic-only knobs
/// (`OXO_WORKER_THREADS`, `OXO_WORKER_STREAMING`) are deliberately NOT
/// forwarded: explicit-but-inert is the fail-closed violation. Gem topology (panel
/// MED-7): the supported posture is a deployment-style vendored bundle rooted in
/// app_root, which needs no HOME; user-dir gem installs require the operator to
/// allowlist HOME/GEM_HOME/GEM_PATH deliberately via OXO_APP_ENV_ALLOW.
fn collect_async_worker_env(
    worker_socket: &Path,
    app_root: &Path,
) -> Result<Vec<(OsString, OsString)>, ServiceError> {
    let mut envs = Vec::new();
    push_required_env(&mut envs, "OXO_WORKER_APP")?;
    push_env_value(&mut envs, "OXO_WORKER_SOCKET", worker_socket.as_os_str());
    push_env_value(&mut envs, "OXO_ASYNC", OsStr::new("1"));
    // (BENCH-ONLY): the tail-hunt timing ledger's dump dir. Forwarded explicitly —
    // the env_clear rebuild would otherwise silently disarm it (defect-#3 class, and the
    // forwarding-contract tripwire test below enforces exactly this). Absent in
    // production; the worker's timing mode is a no-op without it.
    if let Some(dir) = optional_string_env("OXO_WORKER_TIMING_DIR")? {
        push_env_value(&mut envs, "OXO_WORKER_TIMING_DIR", OsStr::new(&dir));
    }
    // the ledger's tail-reservoir floor, forwarded beside the dir it belongs to
    // (the operator allowlist would also carry it, but a knob the worker READS belongs
    // in the explicit list — the same reason MAX_BODY and RACK_LINT are here). Unset
    // keeps the ledger's own default of 2^23 ns; sets 2 ms, because at a ~1 ms
    // service an 8.4 ms floor samples almost none of the distribution under test.
    push_optional_env(&mut envs, "OXO_WORKER_TAIL_NS");
    // the schedstat subsample rate for the consecutive-request ring. Unset or 0 or 1
    // disables sampling entirely; the segment registers 16. Same reasoning as TAIL_NS above:
    // a knob the worker READS belongs in the explicit list, not only the operator allowlist.
    push_optional_env(&mut envs, "OXO_WORKER_SCHED_SAMPLE_N");
    // the service-order ring's dump dir (BENCH-ONLY, a no-op without it) and the
    // fair-read mode. Since the worker's default is `yield2` and this env is the
    // production ROLLBACK LEVER: `OXO_WORKER_FAIR_READ=off` on the edge process
    // environment restores the pre-read loop; the worker's contract line receipts
    // the mode either way. Unset and empty both mean the default (an empty value is
    // never forwarded).
    if let Some(dir) = optional_string_env("OXO_WORKER_ORDER_DIR")? {
        push_env_value(&mut envs, "OXO_WORKER_ORDER_DIR", OsStr::new(&dir));
    }
    push_optional_env(&mut envs, "OXO_WORKER_FAIR_READ");
    // the worker's boot-time scheduling class (BENCH knob: nice:<n> | idle; the
    // worker no-ops without it and receipts the achieved value on its contract line).
    push_optional_env(&mut envs, "OXO_WORKER_SCHED");
    let gemfile = match optional_string_env("BUNDLE_GEMFILE")? {
        Some(explicit) => PathBuf::from(explicit),
        None => app_root.join("Gemfile"),
    };
    if !gemfile.is_file() {
        return Err(ServiceError::InvalidEnv {
            name: "BUNDLE_GEMFILE",
            message: format!(
                "gemfile not found at {} (operator value or <app_root>/Gemfile)",
                gemfile.display()
            ),
        });
    }
    push_env_value(&mut envs, "BUNDLE_GEMFILE", gemfile.as_os_str());
    push_optional_env(&mut envs, "OXO_WORKER_MAX_BODY");
    push_optional_env(&mut envs, "OXO_WORKER_RACK_LINT");
    push_optional_env(&mut envs, "OXO_WORKER_DRAIN_DEADLINE_MS");
    for name in [
        "OXO_DB",
        "OXO_DB_POOL_SIZE",
        "OXO_DB_HOST",
        "OXO_DB_PORT",
        "OXO_DB_NAME",
        "OXO_DB_USER",
        "OXO_DB_PASSWORD",
        "OXO_DB_SSLMODE",
    ] {
        push_optional_env(&mut envs, name);
    }
    for name in default_worker_passthrough_env() {
        push_optional_env(&mut envs, name);
    }
    apply_env_allowlist(&mut envs, "OXO_APP_ENV_ALLOW")?;
    Ok(envs)
}

fn collect_cable_env(bind: SocketAddr) -> Result<Vec<(OsString, OsString)>, ServiceError> {
    let mut envs = Vec::new();
    let bind = bind.to_string();
    push_env_value(&mut envs, "OXO_CABLE_BIND", OsStr::new(&bind));
    push_optional_env(&mut envs, "OXO_CABLE_APP");
    push_optional_env(&mut envs, "OXO_CABLE_RACKUP");
    push_optional_env(&mut envs, "OXO_CABLE_ALLOWED_ORIGINS");
    push_optional_env(&mut envs, "OXO_CABLE_MAX_CONNECTIONS");
    push_optional_env(&mut envs, "OXO_CABLE_IDLE_TIMEOUT_MS");
    for name in default_cable_passthrough_env() {
        push_optional_env(&mut envs, name);
    }
    apply_env_allowlist(&mut envs, "OXO_CABLE_ENV_ALLOW")?;
    Ok(envs)
}

fn collect_grpc_env(bind: SocketAddr) -> Result<Vec<(OsString, OsString)>, ServiceError> {
    let mut envs = Vec::new();
    let bind = bind.to_string();
    push_env_value(&mut envs, "OXO_GRPC_BIND", OsStr::new(&bind));
    push_optional_env(&mut envs, "OXO_GRPC_APP");
    push_optional_env(&mut envs, "OXO_GRPC_CONFIG");
    push_optional_env(&mut envs, "OXO_GRPC_MAX_MESSAGE_BYTES");
    push_optional_env(&mut envs, "OXO_GRPC_DEADLINE_MS");
    for name in default_grpc_passthrough_env() {
        push_optional_env(&mut envs, name);
    }
    apply_env_allowlist(&mut envs, "OXO_GRPC_ENV_ALLOW")?;
    Ok(envs)
}

fn collect_edge_env(worker_launch: &WorkerLaunch) -> Vec<(OsString, OsString)> {
    // M2 + M-D (BENCH-ONLY): the service `env_clear()`s the edge child, so forward
    // the native-floor boot flag and the ladder's injection dose explicitly. Gated by
    // `--features edge-bench` — in a shipped build this is `Vec::new()` and the vars are
    // neither forwarded nor read. The edge reads each ONCE at construction, never per
    // request; never set in production.
    #[allow(unused_mut)]
    let mut vars = Vec::new();
    #[cfg(feature = "edge-bench")]
    for name in ["OXO_EDGE_NATIVE_BENCH", "OXO_EDGE_INJECT_SPIN_US"] {
        if let Ok(value) = env::var(name) {
            vars.push((OsString::from(name), OsString::from(value)));
        }
    }
    // M-D (BENCH-ONLY): same trap, same fix. The run1+run2 hop-timing probes reported
    // `"enabled":false` with every seam at 0 because M-C armed them with an exported
    // OXO_HOP_TIMING=1 and assumed the edge would INHERIT it — but spawn_edge env_clear()s
    // and rebuilds the child env from exactly this list, so the var never arrived. Forward it
    // explicitly, like the native-floor flag above. Gated by `--features hop-timing`: in a
    // shipped build this is absent and the var is neither forwarded nor read.
    #[cfg(feature = "hop-timing")]
    if let Ok(value) = env::var("OXO_HOP_TIMING") {
        vars.push((OsString::from("OXO_HOP_TIMING"), OsString::from(value)));
    }
    // (BENCH-ONLY): the scheduler-delay frame stamp rides the same forwarding —
    // spawn_edge env_clear()s, so without this line the stamp env would silently no-op
    // (defect #3's exact class).
    #[cfg(feature = "hop-timing")]
    if let Ok(value) = env::var("OXO_HOP_STAMP") {
        vars.push((OsString::from("OXO_HOP_STAMP"), OsString::from(value)));
    }
    // B3 → M4 (SHIPPED): the dispatch env twin rides the same forwarding path —
    // spawn_edge env_clear()s, so without this line an operator's OXO_WORKER_DISPATCH
    // would silently no-op (defect #3's exact class).
    if let Ok(value) = env::var("OXO_WORKER_DISPATCH") {
        vars.push((OsString::from("OXO_WORKER_DISPATCH"), OsString::from(value)));
    }
    // (SHIPPED knob): the per-worker admission cap rides the same forwarding —
    // spawn_edge env_clear()s, so without this line an operator's or a bench cell's
    // OXO_EDGE_WORKER_CAP would silently no-op (defect #3's exact class).
    if let Ok(value) = env::var("OXO_EDGE_WORKER_CAP") {
        vars.push((OsString::from("OXO_EDGE_WORKER_CAP"), OsString::from(value)));
    }
    // B-1 (SHIPPED knob, unlike the bench-only vars above): the reaper fallback toggle
    // must reach the edge child or an operator's OXO_HOP_REAPER=0 silently no-ops —
    // and a T1 reaper A/B silently becomes an A/A (live-caught: the first read #2 did
    // exactly that, defect-#3's class again).
    if let Ok(value) = env::var("OXO_HOP_REAPER") {
        vars.push((OsString::from("OXO_HOP_REAPER"), OsString::from(value)));
    }
    // W2 (G13, SHIPPED knob): the frame-pool idle ceiling — the bench sets 512 for
    // async fleets (idle ceiling >= offered concurrency); without this line a
    // service-spawned edge silently runs the default and manufactures a connect storm.
    // Validated at from_cli (validate_frame_pool_idle_env); defect-#3's exact class.
    if let Ok(value) = env::var("OXO_EDGE_FRAME_POOL_IDLE") {
        vars.push((
            OsString::from("OXO_EDGE_FRAME_POOL_IDLE"),
            OsString::from(value),
        ));
    }
    // W0/W2 (SHIPPED knob): the worker kind gates the edge's stale-reuse retry —
    // under async, zero-byte EOF on a reused conn is terminal (the zero-replay
    // contract). Forwarded from the resolved launch, not the raw env, so the edge and
    // the supervisor can never disagree about the kind.
    if worker_launch.is_async() {
        vars.push((OsString::from("OXO_WORKER_KIND"), OsString::from("async")));
    }
    vars
}

fn collect_edge_args(
    worker_sockets: &[PathBuf],
    edge_bind: SocketAddr,
    cli: &EdgeCliConfig,
    edge_drain_grace_ms: u64,
) -> Result<Vec<OsString>, ServiceError> {
    let mut edge_cli = EdgeCliConfig {
        worker_sockets: worker_sockets.to_vec(),
        drain_grace_ms: Some(edge_drain_grace_ms),
        ..EdgeCliConfig::default()
    };
    let uses_tls = edge_uses_tls(cli)?;
    if uses_tls {
        edge_cli.https_bind = Some(edge_bind);
    } else {
        edge_cli.http_bind = Some(edge_bind);
    }
    edge_cli.max_body_bytes = cli
        .max_body_bytes
        .or(optional_u64_env("OXO_EDGE_MAX_BODY")?);
    edge_cli.fqdn = cli
        .fqdn
        .clone()
        .or(optional_string_env("OXO_EDGE_SERVER_NAME")?);
    edge_cli.public_origin_port = cli
        .public_origin_port
        .or(optional_u16_env("OXO_EDGE_PUBLIC_ORIGIN_PORT")?);
    if uses_tls {
        edge_cli.tls_cert = cli
            .tls_cert
            .clone()
            .or_else(|| optional_path("OXO_EDGE_TLS_CERT"));
        edge_cli.tls_key = cli
            .tls_key
            .clone()
            .or_else(|| optional_path("OXO_EDGE_TLS_KEY"));
        edge_cli.tls_h2 = cli.tls_h2.or(optional_bool_env("OXO_EDGE_TLS_H2")?);
    }
    edge_cli.acme_state_path = cli
        .acme_state_path
        .clone()
        .or_else(|| optional_path("OXO_EDGE_ACME_STATE_PATH"));
    edge_cli.acme_issue_once =
        cli.acme_issue_once || optional_bool_env("OXO_EDGE_ACME_ISSUE_ONCE")?.unwrap_or(false);
    edge_cli.acme_renew_once =
        cli.acme_renew_once || optional_bool_env("OXO_EDGE_ACME_RENEW_ONCE")?.unwrap_or(false);
    edge_cli.acme_directory_url = cli
        .acme_directory_url
        .clone()
        .or(optional_string_env("OXO_EDGE_ACME_DIRECTORY_URL")?);
    edge_cli.acme_contacts = if !cli.acme_contacts.is_empty() {
        cli.acme_contacts.clone()
    } else {
        optional_string_env("OXO_EDGE_ACME_CONTACTS")?
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    edge_cli.acme_accept_terms =
        cli.acme_accept_terms || optional_bool_env("OXO_EDGE_ACME_ACCEPT_TERMS")?.unwrap_or(false);
    edge_cli.public_mode = cli
        .public_mode
        .clone()
        .or(optional_string_env("OXO_EDGE_PUBLIC_MODE")?);
    edge_cli.public_identity = cli
        .public_identity
        .clone()
        .or(optional_string_env("OXO_EDGE_PUBLIC_IDENTITY")?);
    edge_cli.admin_bind = cli
        .admin_bind
        .or(optional_socket_addr_env("OXO_EDGE_ADMIN_BIND")?);
    edge_cli.action_cable_bind = cli
        .action_cable_bind
        .or(optional_socket_addr_env("OXO_EDGE_ACTION_CABLE_BIND")?)
        .or(optional_socket_addr_env("OXO_CABLE_BIND")?);
    edge_cli.grpc_bind = cli
        .grpc_bind
        .or(optional_socket_addr_env("OXO_EDGE_GRPC_BIND")?)
        .or(optional_socket_addr_env("OXO_GRPC_BIND")?);
    edge_cli.sse_enabled = cli.sse_enabled.or(optional_bool_env("OXO_EDGE_SSE")?);
    // opt-in downstream keepalive (CLI wins over env; default OFF).
    edge_cli.keepalive_enabled = cli
        .keepalive_enabled
        .or(optional_bool_env("OXO_EDGE_KEEPALIVE")?);
    // total requests per kept-alive connection (CLI wins; default resolved at boot).
    edge_cli.max_requests_per_connection = cli
        .max_requests_per_connection
        .or(optional_u64_env("OXO_EDGE_MAX_REQUESTS_PER_CONNECTION")?);
    // HTTP/2 resource bounds (CLI wins; defaults resolved at boot).
    edge_cli.h2_max_concurrent_streams = cli
        .h2_max_concurrent_streams
        .or(optional_u64_env("OXO_EDGE_H2_MAX_CONCURRENT_STREAMS")?);
    edge_cli.h2_max_reset_streams = cli
        .h2_max_reset_streams
        .or(optional_u64_env("OXO_EDGE_H2_MAX_RESET_STREAMS")?);
    // Pingora proxy-service worker threads (CLI wins; default = nproc at boot).
    edge_cli.edge_threads = cli.edge_threads.or(optional_u64_env("OXO_EDGE_THREADS")?);
    // parallel accept tasks per listening fd (CLI wins; default 1 = pingora's own).
    edge_cli.listener_tasks = cli
        .listener_tasks
        .or(optional_u64_env("OXO_EDGE_LISTENER_TASKS")?);
    // request-log posture (CLI wins; default `rejections` resolved at boot).
    edge_cli.request_log = cli
        .request_log
        .clone()
        .or(optional_string_env("OXO_EDGE_REQUEST_LOG")?);
    // worker-hop wire format (CLI wins; default `frame` resolved at boot).
    edge_cli.worker_hop = cli
        .worker_hop
        .clone()
        .or(optional_string_env("OXO_EDGE_WORKER_HOP")?);
    // static serving: CLI list wins; else semicolon-separated env specs (specs
    // contain commas internally, so ';' is the list separator).
    edge_cli.static_mounts = if !cli.static_mounts.is_empty() {
        cli.static_mounts.clone()
    } else {
        optional_string_env("OXO_EDGE_STATIC_MOUNTS")?
            .map(|value| {
                value
                    .split(';')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    edge_cli.static_rails_preset = cli
        .static_rails_preset
        .clone()
        .or(optional_string_env("OXO_EDGE_STATIC_RAILS_PRESET")?.map(PathBuf::from));
    // the serve-rails ergonomics preset (CLI wins; env twin). The composite's
    // expansion (keepalive/SSE/mount derivation) happens at edge boot, not here — the
    // service just forwards the resolved root.
    edge_cli.serve_rails = cli
        .serve_rails
        .clone()
        .or(optional_string_env("OXO_EDGE_SERVE_RAILS")?.map(PathBuf::from));
    // production static-routing (boot-pinned docroots) — CLI wins over env; default
    // OFF (dev live-probe). Forwarded to the edge child as --prod/--no-prod via to_edge_args.
    edge_cli.prod_enabled = cli.prod_enabled.or(optional_bool_env("OXO_EDGE_PROD")?);
    // D16: these edge-only knobs (trusted-proxy CIDRs, per-identity
    // fairness, long-lived caps) were never translated into edge child argv, and
    // `spawn_edge` clears the child env, so an operator who set them on
    // `oxo-pingora-service` launched an edge that silently fell back to defaults —
    // trusted-proxy identity was unusable and the edge would not boot. Forward them.
    edge_cli.trusted_proxy_cidrs = if !cli.trusted_proxy_cidrs.is_empty() {
        cli.trusted_proxy_cidrs.clone()
    } else {
        optional_string_env("OXO_EDGE_TRUSTED_PROXY_CIDRS")?
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    edge_cli.max_in_flight_per_identity = cli
        .max_in_flight_per_identity
        .or(optional_u64_env("OXO_EDGE_MAX_IN_FLIGHT_PER_IDENTITY")?);
    edge_cli.max_in_flight_requests = cli
        .max_in_flight_requests
        .or(optional_u64_env("OXO_EDGE_MAX_IN_FLIGHT_REQUESTS")?);
    edge_cli.header_read_timeout_ms = cli
        .header_read_timeout_ms
        .or(optional_u64_env("OXO_EDGE_HEADER_READ_TIMEOUT_MS")?);
    edge_cli.keepalive_idle_timeout_ms = cli
        .keepalive_idle_timeout_ms
        .or(optional_u64_env("OXO_EDGE_KEEPALIVE_IDLE_TIMEOUT_MS")?);
    edge_cli.max_connection_secs = cli
        .max_connection_secs
        .or(optional_u64_env("OXO_EDGE_MAX_CONNECTION_SECS")?);
    edge_cli.long_lived_max_connections = cli
        .long_lived_max_connections
        .or(optional_u64_env("OXO_EDGE_LONG_LIVED_MAX_CONNECTIONS")?);
    edge_cli.long_lived_max_buffered_bytes = cli
        .long_lived_max_buffered_bytes
        .or(optional_u64_env("OXO_EDGE_LONG_LIVED_MAX_BUFFERED_BYTES")?);
    edge_cli.long_lived_downstream_write_timeout_ms = cli
        .long_lived_downstream_write_timeout_ms
        .or(optional_u64_env(
            "OXO_EDGE_LONG_LIVED_DOWNSTREAM_WRITE_TIMEOUT_MS",
        )?);
    // D16 fail-closed cross-check: trusted-proxy CIDRs are only consumed when the
    // resolved identity policy is trusted-proxy. If a public mode is configured with
    // CIDRs but a non-trusted-proxy identity, the CIDRs would be silently ignored;
    // refuse rather than mislead the operator into thinking client IPs are trusted.
    if edge_cli.public_mode.is_some()
        && !edge_cli.trusted_proxy_cidrs.is_empty()
        && edge_cli.public_identity.as_deref() != Some("trusted-proxy")
    {
        return Err(ServiceError::InvalidEnv {
            name: "OXO_EDGE_TRUSTED_PROXY_CIDRS",
            message: "trusted-proxy CIDRs are configured but --public-identity is not \
                      trusted-proxy; the CIDRs would be silently ignored by the edge"
                .to_string(),
        });
    }
    Ok(edge_cli.to_edge_args())
}

fn resolve_edge_bind(cli: &EdgeCliConfig) -> Result<SocketAddr, ServiceError> {
    match (cli.http_bind, cli.https_bind) {
        (Some(_), Some(_)) => Err(ServiceError::InvalidEnv {
            name: "argv",
            message: "--http-bind and --https-bind are mutually exclusive until the ACME dual-listener milestone".to_string(),
        }),
        (Some(bind), None) | (None, Some(bind)) => Ok(bind),
        (None, None) => required_string("OXO_EDGE_BIND")?
            .parse()
            .map_err(|err| ServiceError::InvalidEnv {
                name: "OXO_EDGE_BIND",
                message: format!("expected socket address: {err}"),
            }),
    }
}

fn edge_uses_tls(cli: &EdgeCliConfig) -> Result<bool, ServiceError> {
    if cli.https_bind.is_some() || cli.tls_cert.is_some() || cli.tls_key.is_some() {
        Ok(true)
    } else if cli.http_bind.is_some() {
        Ok(false)
    } else {
        env_bool("OXO_EDGE_TLS", false)
    }
}

fn optional_string_env(name: &'static str) -> Result<Option<String>, ServiceError> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(ServiceError::InvalidEnv {
            name,
            message: err.to_string(),
        }),
    }
}

fn optional_bool_env(name: &'static str) -> Result<Option<bool>, ServiceError> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => match value.trim() {
            "1" | "true" | "TRUE" | "yes" | "YES" => Ok(Some(true)),
            "0" | "false" | "FALSE" | "no" | "NO" => Ok(Some(false)),
            _ => Err(ServiceError::InvalidEnv {
                name,
                message: "expected 0/1 or true/false".to_string(),
            }),
        },
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(ServiceError::InvalidEnv {
            name,
            message: err.to_string(),
        }),
    }
}

fn optional_u16_env(name: &'static str) -> Result<Option<u16>, ServiceError> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => {
            value
                .trim()
                .parse::<u16>()
                .map(Some)
                .map_err(|err| ServiceError::InvalidEnv {
                    name,
                    message: format!("expected integer port: {err}"),
                })
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(ServiceError::InvalidEnv {
            name,
            message: err.to_string(),
        }),
    }
}

fn optional_u64_env(name: &'static str) -> Result<Option<u64>, ServiceError> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => {
            value
                .trim()
                .parse::<u64>()
                .map(Some)
                .map_err(|err| ServiceError::InvalidEnv {
                    name,
                    message: format!("expected integer byte count: {err}"),
                })
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(ServiceError::InvalidEnv {
            name,
            message: err.to_string(),
        }),
    }
}

fn optional_socket_addr_env(name: &'static str) -> Result<Option<SocketAddr>, ServiceError> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => {
            value
                .trim()
                .parse::<SocketAddr>()
                .map(Some)
                .map_err(|err| ServiceError::InvalidEnv {
                    name,
                    message: format!("expected socket address: {err}"),
                })
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(ServiceError::InvalidEnv {
            name,
            message: err.to_string(),
        }),
    }
}

fn service_cli_error(err: crate::EdgeError) -> ServiceError {
    ServiceError::InvalidEnv {
        name: "argv",
        message: err.to_string(),
    }
}
fn default_cable_passthrough_env() -> &'static [&'static str] {
    &[
        "PATH",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "BUNDLE_GEMFILE",
        "RAILS_ENV",
        "RACK_ENV",
        "SECRET_KEY_BASE",
        "RAILS_MASTER_KEY",
        "REDIS_URL",
    ]
}

fn default_grpc_passthrough_env() -> &'static [&'static str] {
    &[
        "PATH",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "BUNDLE_GEMFILE",
        "RAILS_ENV",
        "RACK_ENV",
        "SECRET_KEY_BASE",
        "RAILS_MASTER_KEY",
        "DATABASE_URL",
        "REDIS_URL",
        "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
    ]
}

fn default_worker_passthrough_env() -> &'static [&'static str] {
    &[
        "PATH",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "BUNDLE_GEMFILE",
        "RAILS_ENV",
        "RACK_ENV",
        "SECRET_KEY_BASE",
        "RAILS_MASTER_KEY",
        "DATABASE_URL",
        "REDIS_URL",
        "MEMCACHE_SERVERS",
    ]
}

fn push_required_env(
    envs: &mut Vec<(OsString, OsString)>,
    name: &'static str,
) -> Result<(), ServiceError> {
    match env::var_os(name).filter(|value| !value.is_empty()) {
        Some(value) => {
            envs.push((OsString::from(name), value));
            Ok(())
        }
        None => Err(ServiceError::MissingEnv { name }),
    }
}

fn push_optional_env(envs: &mut Vec<(OsString, OsString)>, name: &str) {
    if let Some(value) = env::var_os(name).filter(|value| !value.is_empty()) {
        envs.push((OsString::from(name), value));
    }
}

fn push_env_value(envs: &mut Vec<(OsString, OsString)>, name: &str, value: &OsStr) {
    envs.push((OsString::from(name), value.to_os_string()));
}

fn is_env_name_safe(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn is_edge_only_env_name(name: &str) -> bool {
    matches!(
        name,
        "OXO_EDGE_BIND"
            | "OXO_EDGE_WORKER_SOCKET"
            | "OXO_EDGE_WORKER_SOCKETS"
            | "OXO_EDGE_MAX_BODY"
            | "OXO_EDGE_SERVER_NAME"
            | "OXO_EDGE_PUBLIC_ORIGIN_PORT"
            | "OXO_EDGE_TLS"
            | "OXO_EDGE_TLS_CERT"
            | "OXO_EDGE_TLS_KEY"
            | "OXO_EDGE_TLS_H2"
            | "OXO_EDGE_ACME_STATE_PATH"
            | "OXO_EDGE_ACME_ISSUE_ONCE"
            | "OXO_EDGE_ACME_RENEW_ONCE"
            | "OXO_EDGE_ACME_DIRECTORY_URL"
            | "OXO_EDGE_ACME_CONTACTS"
            | "OXO_EDGE_ACME_ACCEPT_TERMS"
            | "OXO_EDGE_ACME_ALLOW_PRODUCTION_DIRECTORY"
            | "OXO_EDGE_PUBLIC_MODE"
            | "OXO_EDGE_PUBLIC_IDENTITY"
            | "OXO_EDGE_ADMIN_BIND"
            | "OXO_EDGE_ACTION_CABLE_BIND"
            | "OXO_EDGE_GRPC_BIND"
            | "OXO_EDGE_DRAIN_GRACE_MS"
            | "OXO_EDGE_MAX_IN_FLIGHT_REQUESTS"
            | "OXO_EDGE_HEADER_READ_TIMEOUT_MS"
            | "OXO_EDGE_KEEPALIVE_IDLE_TIMEOUT_MS"
            | "OXO_EDGE_MAX_CONNECTION_SECS"
            | "OXO_EDGE_SSE"
            | "OXO_EDGE_KEEPALIVE"
            | "OXO_EDGE_MAX_REQUESTS_PER_CONNECTION"
            | "OXO_EDGE_H2_MAX_CONCURRENT_STREAMS"
            | "OXO_EDGE_H2_MAX_RESET_STREAMS"
            | "OXO_EDGE_THREADS"
            | "OXO_EDGE_LISTENER_TASKS"
            | "OXO_EDGE_REQUEST_LOG"
            | "OXO_EDGE_STATIC_MOUNTS"
            | "OXO_EDGE_STATIC_RAILS_PRESET"
            | "OXO_EDGE_SERVE_RAILS"
            | "OXO_EDGE_PROD"
            | "LISTEN_FDS"
            | "LISTEN_PID"
            | "LISTEN_FDNAMES"
    )
}

fn env_usize(name: &'static str, default: usize) -> Result<usize, ServiceError> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(default),
        Ok(value) => value
            .trim()
            .parse::<usize>()
            .map_err(|err| ServiceError::InvalidEnv {
                name,
                message: format!("expected unsigned integer: {err}"),
            }),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(ServiceError::InvalidEnv {
            name,
            message: err.to_string(),
        }),
    }
}

fn env_duration_ms(name: &'static str, default: Duration) -> Result<Duration, ServiceError> {
    let millis = env_usize(name, default.as_millis() as usize)?;
    Ok(Duration::from_millis(millis as u64))
}

fn worker_socket_paths(base: &Path, count: usize) -> Result<Vec<PathBuf>, ServiceError> {
    if count == 1 {
        return Ok(vec![base.to_path_buf()]);
    }
    let parent = base.parent().ok_or_else(|| ServiceError::InvalidEnv {
        name: "OXO_WORKER_SOCKET",
        message: format!("socket path {} has no parent", base.display()),
    })?;
    let stem = base
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("worker");
    let extension = base.extension().and_then(|extension| extension.to_str());
    let mut sockets = Vec::with_capacity(count);
    for id in 0..count {
        let file_name = match extension {
            Some(extension) if !extension.is_empty() => format!("{stem}-{id}.{extension}"),
            _ => format!("{stem}-{id}"),
        };
        sockets.push(parent.join(file_name));
    }
    Ok(sockets)
}
fn required_string(name: &'static str) -> Result<String, ServiceError> {
    env::var(name)
        .map_err(|_| ServiceError::MissingEnv { name })
        .and_then(|value| {
            if value.trim().is_empty() {
                Err(ServiceError::MissingEnv { name })
            } else {
                Ok(value)
            }
        })
}

fn env_bool(name: &'static str, default: bool) -> Result<bool, ServiceError> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(default),
        Ok(value) => match value.trim() {
            "1" | "true" | "TRUE" | "yes" | "YES" => Ok(true),
            "0" | "false" | "FALSE" | "no" | "NO" => Ok(false),
            _ => Err(ServiceError::InvalidEnv {
                name,
                message: "expected 0/1 or true/false".to_string(),
            }),
        },
        Err(env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(ServiceError::InvalidEnv {
            name,
            message: err.to_string(),
        }),
    }
}

fn configured_binary(
    env_name: &'static str,
    sibling_name: &str,
    allow_override: bool,
    role: &'static str,
) -> Result<PathBuf, ServiceError> {
    let path = match optional_path(env_name) {
        Some(path) if allow_override => path,
        Some(path) => {
            return Err(ServiceError::BinaryOverrideDenied {
                name: env_name,
                path,
            })
        }
        None => sibling_binary(sibling_name),
    };
    validate_executable(role, &path)?;
    Ok(path)
}

fn validate_executable(role: &'static str, path: &Path) -> Result<(), ServiceError> {
    if !path.is_absolute() {
        return Err(ServiceError::BinaryPathMustBeAbsolute {
            role,
            path: path.to_path_buf(),
        });
    }
    let metadata = fs::metadata(path).map_err(|source| ServiceError::BinaryUnavailable {
        role,
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(ServiceError::BinaryNotFile {
            role,
            path: path.to_path_buf(),
        });
    }
    validate_executable_permissions(role, path, &metadata)
}

#[cfg(target_os = "linux")]
fn validate_executable_permissions(
    role: &'static str,
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ServiceError> {
    use std::os::unix::fs::PermissionsExt;
    if path.to_string_lossy().starts_with("/mnt/") {
        return Ok(());
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(ServiceError::BinaryWritableByGroupOrOther {
            role,
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_executable_permissions(
    _role: &'static str,
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), ServiceError> {
    Ok(())
}
fn required_path(name: &'static str) -> Result<PathBuf, ServiceError> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(ServiceError::MissingEnv { name })
}

fn optional_path(name: &'static str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn sibling_binary(name: &str) -> PathBuf {
    let exe_name = format!("{name}{}", env::consts::EXE_SUFFIX);
    env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|parent| parent.join(&exe_name)))
        .unwrap_or_else(|| PathBuf::from(exe_name))
}

#[derive(Debug)]
pub enum ServiceError {
    MissingEnv {
        name: &'static str,
    },
    InvalidEnv {
        name: &'static str,
        message: String,
    },
    BinaryOverrideDenied {
        name: &'static str,
        path: PathBuf,
    },
    BinaryPathMustBeAbsolute {
        role: &'static str,
        path: PathBuf,
    },
    BinaryUnavailable {
        role: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    BinaryNotFile {
        role: &'static str,
        path: PathBuf,
    },
    BinaryWritableByGroupOrOther {
        role: &'static str,
        path: PathBuf,
        mode: u32,
    },
    Spawn {
        role: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    MissingWorkerStdout,
    MissingWorkerStderr,
    WorkerReadyIo {
        source: std::io::Error,
    },
    WorkerReadiness {
        line: String,
    },
    WorkerReadinessOutputTooLarge,
    WorkerReadyWrongSocket {
        expected: PathBuf,
        got: PathBuf,
    },
    WorkerReadyTimeout,
    WorkerReadyDisconnected,
    WorkerSocketInvalid {
        path: PathBuf,
        message: String,
    },
    WorkerSocketProbe {
        path: PathBuf,
        source: std::io::Error,
    },
    EdgeReadyTimeout {
        bind: SocketAddr,
    },
    CableReadyTimeout {
        bind: SocketAddr,
    },
    GrpcReadyTimeout {
        bind: SocketAddr,
    },
    ChildExited {
        role: &'static str,
        status: ExitStatus,
    },
    Wait(std::io::Error),
    #[cfg(feature = "acme")]
    AcmeReload {
        message: String,
    },
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::MissingEnv { name } => write!(f, "missing required {name}"),
            ServiceError::InvalidEnv { name, message } => write!(f, "invalid {name}: {message}"),
            ServiceError::BinaryOverrideDenied { name, path } => write!(
                f,
                "{name} override {} requires OXO_SERVICE_ALLOW_BIN_OVERRIDES=1",
                path.display()
            ),
            ServiceError::BinaryPathMustBeAbsolute { role, path } => {
                write!(f, "{role} binary path must be absolute: {}", path.display())
            }
            ServiceError::BinaryUnavailable { role, path, source } => write!(
                f,
                "{role} binary {} is unavailable: {source}",
                path.display()
            ),
            ServiceError::BinaryNotFile { role, path } => {
                write!(f, "{role} binary path is not a file: {}", path.display())
            }
            ServiceError::BinaryWritableByGroupOrOther { role, path, mode } => write!(
                f,
                "{role} binary {} must not be group/other writable, got mode {mode:o}",
                path.display()
            ),
            ServiceError::Spawn { role, path, source } => {
                write!(f, "spawning {role} {}: {source}", path.display())
            }
            ServiceError::MissingWorkerStdout => write!(f, "worker stdout was not piped"),
            ServiceError::MissingWorkerStderr => write!(f, "worker stderr was not piped"),
            ServiceError::WorkerReadyIo { source } => {
                write!(f, "reading worker readiness: {source}")
            }
            ServiceError::WorkerReadiness { line } => write!(
                f,
                "worker did not report readiness with {WORKER_READY_PREFIX}; got {line:?}"
            ),
            ServiceError::WorkerReadinessOutputTooLarge => write!(
                f,
                "worker emitted more than {MAX_PRE_READY_OUTPUT_BYTES} bytes before readiness"
            ),
            ServiceError::WorkerReadyWrongSocket { expected, got } => write!(
                f,
                "worker reported socket {}, expected {}",
                got.display(),
                expected.display()
            ),
            ServiceError::WorkerReadyTimeout => write!(
                f,
                "worker did not report readiness within {:?}",
                WORKER_READY_TIMEOUT
            ),
            ServiceError::WorkerReadyDisconnected => {
                write!(f, "worker readiness reader disconnected")
            }
            ServiceError::WorkerSocketInvalid { path, message } => write!(
                f,
                "worker socket {} failed validation: {message}",
                path.display()
            ),
            ServiceError::WorkerSocketProbe { path, source } => write!(
                f,
                "worker socket {} did not accept a probe: {source}",
                path.display()
            ),
            ServiceError::EdgeReadyTimeout { bind } => write!(
                f,
                "edge did not accept on {bind} within {:?}",
                EDGE_READY_TIMEOUT
            ),
            ServiceError::CableReadyTimeout { bind } => write!(
                f,
                "standalone Action Cable did not accept on {bind} within {:?}",
                CABLE_READY_TIMEOUT
            ),
            ServiceError::GrpcReadyTimeout { bind } => write!(
                f,
                "standalone gRPC did not accept on {bind} within {:?}",
                GRPC_READY_TIMEOUT
            ),
            ServiceError::ChildExited { role, status } => write!(f, "{role} exited with {status}"),
            ServiceError::Wait(source) => write!(f, "waiting for service child: {source}"),
            #[cfg(feature = "acme")]
            ServiceError::AcmeReload { message } => {
                write!(f, "ACME certificate reload failed: {message}")
            }
        }
    }
}

impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ServiceError::BinaryUnavailable { source, .. }
            | ServiceError::Spawn { source, .. }
            | ServiceError::WorkerReadyIo { source }
            | ServiceError::WorkerSocketProbe { source, .. }
            | ServiceError::Wait(source) => Some(source),
            _ => None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    // `apply_env_allowlist` serves all three role collectors, and its
    // `allow_var` is double-duty (env var read + InvalidEnv `name`). These two
    // tests pin that the cable and gRPC collectors report their OWN variable
    // for both reject arms. Each test mutates only its role-specific env var,
    // which no other test in this binary reads, so parallel test threads
    // cannot interfere.
    #[test]
    fn cable_env_allowlist_reports_its_own_name_for_both_reject_arms() {
        let bind: SocketAddr = "127.0.0.1:6001".parse().unwrap();
        env::set_var("OXO_CABLE_ENV_ALLOW", "not a name");
        let invalid = collect_cable_env(bind).unwrap_err();
        env::set_var("OXO_CABLE_ENV_ALLOW", "OXO_EDGE_TLS_KEY");
        let edge_only = collect_cable_env(bind).unwrap_err();
        env::remove_var("OXO_CABLE_ENV_ALLOW");
        match invalid {
            ServiceError::InvalidEnv { name, message } => {
                assert_eq!(name, "OXO_CABLE_ENV_ALLOW");
                assert!(message.contains("invalid env name"), "{message}");
            }
            other => panic!("unexpected error: {other}"),
        }
        match edge_only {
            ServiceError::InvalidEnv { name, message } => {
                assert_eq!(name, "OXO_CABLE_ENV_ALLOW");
                assert!(message.contains("edge-only env name"), "{message}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn grpc_env_allowlist_reports_its_own_name_for_both_reject_arms() {
        let bind: SocketAddr = "127.0.0.1:6002".parse().unwrap();
        env::set_var("OXO_GRPC_ENV_ALLOW", "not a name");
        let invalid = collect_grpc_env(bind).unwrap_err();
        env::set_var("OXO_GRPC_ENV_ALLOW", "OXO_EDGE_TLS_KEY");
        let edge_only = collect_grpc_env(bind).unwrap_err();
        env::remove_var("OXO_GRPC_ENV_ALLOW");
        match invalid {
            ServiceError::InvalidEnv { name, message } => {
                assert_eq!(name, "OXO_GRPC_ENV_ALLOW");
                assert!(message.contains("invalid env name"), "{message}");
            }
            other => panic!("unexpected error: {other}"),
        }
        match edge_only {
            ServiceError::InvalidEnv { name, message } => {
                assert_eq!(name, "OXO_GRPC_ENV_ALLOW");
                assert!(message.contains("edge-only env name"), "{message}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    // W2: every worker-kind/async-launch env scenario in ONE test (the vars are
    // process-global and no other test in this binary reads them).
    //
    // Unix-only: the fixture builds a 0700 runtime dir, and mode bits are the thing
    // `ensure_runtime_dir` checks. The Windows leg builds the stub, where there is
    // nothing to assert.
    #[cfg(unix)]
    #[test]
    fn worker_launch_resolver_fails_closed_and_validates_the_async_surface() {
        use std::os::unix::fs::PermissionsExt;

        for name in [
            "OXO_WORKER_KIND",
            "OXO_ASYNC_WORKER_SCRIPT",
            "OXO_ASYNC_BUNDLE_BIN",
            "OXO_ASYNC_RUBY_BIN",
            "OXO_ASYNC_WORKER_APP_ROOT",
        ] {
            env::remove_var(name);
        }
        assert!(
            matches!(read_worker_launch().unwrap(), WorkerLaunch::Classic),
            "default kind is classic"
        );
        env::set_var("OXO_WORKER_KIND", "classic");
        assert!(matches!(
            read_worker_launch().unwrap(),
            WorkerLaunch::Classic
        ));

        env::set_var("OXO_WORKER_KIND", "fibers");
        match read_worker_launch().expect_err("typo'd kind fails closed") {
            ServiceError::InvalidEnv { name, message } => {
                assert_eq!(name, "OXO_WORKER_KIND");
                assert!(message.contains("classic|async"), "{message}");
            }
            other => panic!("unexpected error: {other}"),
        }

        // async requires the full surface, every path absolute + validated.
        env::set_var("OXO_WORKER_KIND", "async");
        assert!(
            read_worker_launch().is_err(),
            "async without the surface must fail"
        );

        let dir = std::env::temp_dir().join(format!("launch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let exec = |name: &str| {
            let p = dir.join(name);
            fs::write(&p, "#!/bin/sh\n").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            p
        };
        let script = exec("worker.rb");
        let bundle = exec("bundle");
        let ruby = exec("ruby");
        let app_root = dir.join("app");
        fs::create_dir_all(&app_root).unwrap();
        env::set_var("OXO_ASYNC_WORKER_SCRIPT", &script);
        env::set_var("OXO_ASYNC_BUNDLE_BIN", &bundle);
        env::set_var("OXO_ASYNC_RUBY_BIN", &ruby);
        env::set_var("OXO_ASYNC_WORKER_APP_ROOT", &app_root);
        match read_worker_launch().unwrap() {
            WorkerLaunch::Async {
                bundle_bin,
                ruby_bin,
                script: s,
                app_root: root,
            } => {
                assert_eq!(bundle_bin, bundle);
                assert_eq!(ruby_bin, ruby);
                assert_eq!(s, script);
                assert_eq!(root, app_root);
            }
            other => panic!("expected async launch, got {other:?}"),
        }

        // A relative script path is refused (the absolute-path posture, unchanged).
        env::set_var("OXO_ASYNC_WORKER_SCRIPT", "relative/worker.rb");
        assert!(read_worker_launch().is_err(), "relative script refused");
        env::set_var("OXO_ASYNC_WORKER_SCRIPT", &script);

        // collect_async_worker_env: injected/forwarded contents + the Gemfile gate.
        env::set_var("OXO_WORKER_APP", "config.ru");
        env::set_var("OXO_WORKER_MAX_BODY", "1048576");
        env::set_var("OXO_DB_POOL_SIZE", "2");
        env::set_var("OXO_WORKER_SCHED", "nice:19");
        env::set_var("OXO_WORKER_TAIL_NS", "2000000");
        env::set_var("OXO_WORKER_SCHED_SAMPLE_N", "16");
        env::remove_var("BUNDLE_GEMFILE");
        let sock = dir.join("run").join("worker.sock");
        let missing = collect_async_worker_env(&sock, &app_root)
            .expect_err("missing Gemfile must fail with the named knob");
        match missing {
            ServiceError::InvalidEnv { name, .. } => assert_eq!(name, "BUNDLE_GEMFILE"),
            other => panic!("unexpected error: {other}"),
        }
        fs::write(app_root.join("Gemfile"), "source 'https://rubygems.org'\n").unwrap();
        let envs = collect_async_worker_env(&sock, &app_root).unwrap();
        let get = |k: &str| {
            envs.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.to_string_lossy().to_string())
        };
        assert_eq!(get("OXO_ASYNC").as_deref(), Some("1"), "injected");
        assert_eq!(
            get("BUNDLE_GEMFILE"),
            Some(app_root.join("Gemfile").to_string_lossy().to_string()),
            "computed from app_root"
        );
        assert_eq!(get("OXO_WORKER_MAX_BODY").as_deref(), Some("1048576"));
        assert_eq!(get("OXO_DB_POOL_SIZE").as_deref(), Some("2"));
        assert_eq!(
            get("OXO_WORKER_SCHED").as_deref(),
            Some("nice:19"),
            "the scheduling knob is forwarded verbatim"
        );
        env::remove_var("OXO_WORKER_SCHED");
        assert_eq!(
            get("OXO_WORKER_TAIL_NS").as_deref(),
            Some("2000000"),
            "the ledger's reservoir floor is forwarded beside the dir it belongs to"
        );
        assert_eq!(
            get("OXO_WORKER_SCHED_SAMPLE_N").as_deref(),
            Some("16"),
            "the ring's subsample rate is forwarded beside the ledger's own knobs"
        );
        env::remove_var("OXO_WORKER_TAIL_NS");
        env::remove_var("OXO_WORKER_SCHED_SAMPLE_N");
        assert!(
            get("OXO_WORKER_THREADS").is_none(),
            "classic-only knobs are NOT forwarded (explicit-but-inert is fail-closed's enemy)"
        );

        // The edge env carries the kind only under async (the W0 zero-replay gate).
        let async_launch = read_worker_launch().unwrap();
        let edge_env = collect_edge_env(&async_launch);
        assert!(
            edge_env
                .iter()
                .any(|(n, v)| n == "OXO_WORKER_KIND" && v == "async"),
            "edge must learn the kind: {edge_env:?}"
        );
        assert!(
            !collect_edge_env(&WorkerLaunch::Classic)
                .iter()
                .any(|(n, _)| n == "OXO_WORKER_KIND"),
            "classic forwards no kind"
        );

        for name in [
            "OXO_WORKER_KIND",
            "OXO_ASYNC_WORKER_SCRIPT",
            "OXO_ASYNC_BUNDLE_BIN",
            "OXO_ASYNC_RUBY_BIN",
            "OXO_ASYNC_WORKER_APP_ROOT",
            "OXO_WORKER_APP",
            "OXO_WORKER_MAX_BODY",
            "OXO_DB_POOL_SIZE",
        ] {
            env::remove_var(name);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    // W2 (live-caught): the async launch surface must REFUSE a group/other-writable
    // script — the service EXECUTES it, so it is the same injection surface as a binary.
    //
    // This test deliberately builds its fixture under /tmp, NOT under the repo: on WSL
    // the repo lives at /mnt/c/... and `validate_executable_permissions` early-returns
    // for /mnt/ paths (drvfs reports meaningless modes), so every WSL-run test silently
    // skipped the permission check. A live guest (real ext4, 664 from the staged tar)
    // caught it instead — at the cost of a campaign phase. Pin it here so the security
    // property is exercised on every machine.
    //
    // Linux-gated to match `validate_executable_permissions`, which is itself
    // `#[cfg(target_os = "linux")]`: on macOS the non-Linux stub accepts any mode (so the
    // refusal never fires), and on Windows `std::os::unix` does not exist at all.
    #[cfg(target_os = "linux")]
    #[test]
    fn async_script_must_not_be_group_or_other_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("perm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(
            !dir.starts_with("/mnt/"),
            "fixture must live off /mnt so the permission check actually runs (got {})",
            dir.display()
        );
        let script = dir.join("worker.rb");
        fs::write(&script, "# worker\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o664)).unwrap();

        let err = validate_executable("async-worker-script", &script)
            .expect_err("a group-writable script must be refused");
        let text = err.to_string();
        assert!(text.contains("group/other writable"), "{text}");
        assert!(text.contains("664"), "the error must name the mode: {text}");

        // 0644 (the correct deployed posture) passes.
        fs::set_permissions(&script, fs::Permissions::from_mode(0o644)).unwrap();
        validate_executable("async-worker-script", &script)
            .expect("0644 is the supported script posture");

        let _ = fs::remove_dir_all(&dir);
    }

    // W2: timeout/drain knobs — defaults per kind, overrides, zero rejected — in
    // ONE test (shared process-global vars).
    #[test]
    fn worker_timeout_and_drain_knobs_default_per_kind_and_reject_zero() {
        let classic = WorkerLaunch::Classic;
        let async_launch = WorkerLaunch::Async {
            bundle_bin: PathBuf::from("/x/bundle"),
            ruby_bin: PathBuf::from("/x/ruby"),
            script: PathBuf::from("/x/w.rb"),
            app_root: PathBuf::from("/x/app"),
        };

        for name in [
            "OXO_WORKER_READY_TIMEOUT_MS",
            "OXO_WORKER_RESPAWN_READY_TIMEOUT_MS",
            "OXO_WORKER_DRAIN_DEADLINE_MS",
            "OXO_EDGE_FRAME_POOL_IDLE",
        ] {
            env::remove_var(name);
        }
        assert_eq!(
            read_worker_ready_timeout(&classic).unwrap(),
            WORKER_READY_TIMEOUT
        );
        assert_eq!(
            read_worker_ready_timeout(&async_launch).unwrap(),
            Duration::from_secs(120),
            "async first boot = the bench's cold-Rails floor"
        );
        assert_eq!(
            read_worker_respawn_ready_timeout(&async_launch).unwrap(),
            Duration::from_secs(30),
            "respawn budget covers a WARM boot"
        );
        assert_eq!(read_worker_drain_wait(&classic).unwrap(), WORKER_DRAIN_WAIT);
        assert_eq!(
            read_worker_drain_wait(&async_launch).unwrap(),
            Duration::from_millis(1050),
            "derived: 900ms worker deadline + 150ms margin"
        );

        env::set_var("OXO_WORKER_READY_TIMEOUT_MS", "0");
        assert!(
            read_worker_ready_timeout(&async_launch).is_err(),
            "zero rejected"
        );
        env::set_var("OXO_WORKER_READY_TIMEOUT_MS", "45000");
        assert_eq!(
            read_worker_ready_timeout(&async_launch).unwrap(),
            Duration::from_secs(45)
        );
        env::remove_var("OXO_WORKER_READY_TIMEOUT_MS");

        env::set_var("OXO_WORKER_DRAIN_DEADLINE_MS", "400");
        assert_eq!(
            read_worker_drain_wait(&async_launch).unwrap(),
            Duration::from_millis(550),
            "the pair moves together"
        );
        env::remove_var("OXO_WORKER_DRAIN_DEADLINE_MS");

        env::set_var("OXO_EDGE_FRAME_POOL_IDLE", "banana");
        assert!(
            validate_frame_pool_idle_env().is_err(),
            "garbage pool-idle fails the boot, never silently defaults (G13/MED-11)"
        );
        env::set_var("OXO_EDGE_FRAME_POOL_IDLE", "0");
        assert!(validate_frame_pool_idle_env().is_err());
        env::set_var("OXO_EDGE_FRAME_POOL_IDLE", "512");
        assert!(validate_frame_pool_idle_env().is_ok());
        env::remove_var("OXO_EDGE_FRAME_POOL_IDLE");
    }

    // W2 (panel MED-4): enumerate the async worker script's actual ENV reads
    // against the forwarded/per-slot/self-set contract, so the NEXT knob added to the
    // worker cannot silently diverge from the service's env_clear rebuild.
    #[test]
    fn async_worker_env_reads_are_covered_by_the_forwarding_contract() {
        let script_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ruby/oxo_async_worker.rb");
        let source = fs::read_to_string(&script_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", script_path.display()));
        let mut reads = std::collections::BTreeSet::new();
        for cap in source.match_indices("ENV[\"") {
            let rest = &source[cap.0 + 5..];
            if let Some(end) = rest.find('"') {
                reads.insert(rest[..end].to_string());
            }
        }
        assert!(
            !reads.is_empty(),
            "expected ENV reads in the worker script (parser broken?)"
        );
        // The contract: forwarded by collect_async_worker_env, injected per-slot by
        // spawn_worker_slot, or self-set by the worker before app load.
        let covered: std::collections::BTreeSet<&str> = [
            "OXO_WORKER_APP",
            "OXO_WORKER_MAX_BODY",
            "OXO_WORKER_RACK_LINT",
            "OXO_WORKER_DRAIN_DEADLINE_MS",
            "OXO_WORKER_SOCKET",
            "OXO_WORKER_ID",
            "OXO_WORKER_GENERATION",
            "OXO_WORKER_POOL_SIZE",
            "OXO_WORKER_MULTIPROCESS",
            "OXO_ASYNC",
            "OXO_WORKER_TIMING_DIR", // forwarded by collect_async_worker_env
            "OXO_WORKER_ORDER_DIR",  // forwarded by collect_async_worker_env
            "OXO_WORKER_FAIR_READ",  // forwarded by collect_async_worker_env; : the rollback lever
            "OXO_WORKER_SCHED",      // forwarded by collect_async_worker_env (nice:<n> | idle)
            "OXO_WORKER_TAIL_NS", // forwarded by collect_async_worker_env (ledger reservoir floor)
            "OXO_WORKER_SCHED_SAMPLE_N", // forwarded by collect_async_worker_env (ring subsample rate)
            "BUNDLE_GEMFILE",
        ]
        .into_iter()
        .collect();
        let uncovered: Vec<_> = reads
            .iter()
            .filter(|r| r.starts_with("OXO_") || r.starts_with("BUNDLE_"))
            .filter(|r| !covered.contains(r.as_str()))
            .collect();
        assert!(
            uncovered.is_empty(),
            "worker script reads env the service does not forward (defect-#3 class): {uncovered:?}"
        );
    }

    #[test]
    fn redacted_env_summary_never_logs_secret_values() {
        let envs = vec![
            (
                OsString::from("SECRET_KEY_BASE"),
                OsString::from("super-secret"),
            ),
            (
                OsString::from("DATABASE_URL"),
                OsString::from("postgres://user:pass@db/app"),
            ),
            (
                OsString::from("RAILS_MASTER_KEY"),
                OsString::from("master-key"),
            ),
            (OsString::from("RAILS_ENV"), OsString::from("production")),
        ];

        let summary = redacted_env_summary(&envs);

        assert!(summary.contains("SECRET_KEY_BASE=<redacted>"), "{summary}");
        assert!(summary.contains("DATABASE_URL=<redacted>"), "{summary}");
        assert!(summary.contains("RAILS_MASTER_KEY=<redacted>"), "{summary}");
        assert!(summary.contains("RAILS_ENV=<set>"), "{summary}");
        assert!(!summary.contains("super-secret"), "{summary}");
        assert!(!summary.contains("postgres://"), "{summary}");
        assert!(!summary.contains("master-key"), "{summary}");
        assert!(!summary.contains("production"), "{summary}");
    }

    #[test]
    fn edge_drain_grace_rejects_zero_cli_value() {
        let cli = EdgeCliConfig::parse_from_args(["oxo-pingora-service", "--drain-grace-ms", "0"])
            .unwrap();
        let err =
            resolve_edge_drain_grace(&cli).expect_err("zero edge drain grace must fail closed");
        assert!(err.to_string().contains("--drain-grace-ms"), "{err}");
    }

    #[test]
    fn service_drain_grace_must_fit_edge_sidecar_and_worker_windows() {
        let err = validate_drain_grace_hierarchy(
            Duration::from_secs(4),
            Duration::from_secs(2),
            WORKER_DRAIN_WAIT,
        )
        .expect_err("2s edge + 1s sidecar + 1s worker must not fit in 4s service grace");
        let text = err.to_string();
        assert!(text.contains("OXO_SERVICE_DRAIN_GRACE_MS"), "{text}");
        assert!(text.contains("OXO_EDGE_DRAIN_GRACE_MS"), "{text}");
        validate_drain_grace_hierarchy(
            Duration::from_secs(5),
            Duration::from_secs(2),
            WORKER_DRAIN_WAIT,
        )
        .expect("default 5s service grace leaves a 1s margin");
        // W2 (panel MED-10): the async-derived worker stage widens the requirement.
        validate_drain_grace_hierarchy(
            Duration::from_secs(5),
            Duration::from_secs(2),
            Duration::from_millis(2100),
        )
        .expect_err("a wider derived worker drain must re-tighten the hierarchy");
    }

    #[test]
    fn edge_only_config_names_are_not_role_passthrough_defaults() {
        let edge_only = [
            "OXO_EDGE_TLS_CERT",
            "OXO_EDGE_TLS_KEY",
            "OXO_EDGE_ACME_STATE_PATH",
            "OXO_EDGE_ACME_ISSUE_ONCE",
            "OXO_EDGE_ACME_RENEW_ONCE",
            "OXO_EDGE_ACME_DIRECTORY_URL",
            "OXO_EDGE_ACME_CONTACTS",
            "OXO_EDGE_ACME_ACCEPT_TERMS",
            "OXO_EDGE_ACME_ALLOW_PRODUCTION_DIRECTORY",
            "OXO_EDGE_PUBLIC_MODE",
            "OXO_EDGE_PUBLIC_ORIGIN_PORT",
            "OXO_EDGE_ACTION_CABLE_BIND",
            "OXO_EDGE_GRPC_BIND",
            "OXO_EDGE_DRAIN_GRACE_MS",
            "OXO_EDGE_MAX_IN_FLIGHT_REQUESTS",
            "OXO_EDGE_HEADER_READ_TIMEOUT_MS",
            "OXO_EDGE_KEEPALIVE_IDLE_TIMEOUT_MS",
            "OXO_EDGE_MAX_CONNECTION_SECS",
            "OXO_EDGE_KEEPALIVE",
            "OXO_EDGE_THREADS",
            "OXO_EDGE_LISTENER_TASKS",
            "OXO_EDGE_REQUEST_LOG",
            "OXO_EDGE_STATIC_MOUNTS",
            "OXO_EDGE_STATIC_RAILS_PRESET",
            "OXO_EDGE_SERVE_RAILS",
            "LISTEN_FDS",
            "LISTEN_PID",
            "LISTEN_FDNAMES",
        ];
        for name in edge_only {
            assert!(is_edge_only_env_name(name));
            assert!(!default_worker_passthrough_env().contains(&name));
            assert!(!default_cable_passthrough_env().contains(&name));
            assert!(!default_grpc_passthrough_env().contains(&name));
        }
        assert!(!is_edge_only_env_name("SECRET_KEY_BASE"));
    }

    #[test]
    fn service_collects_resolved_edge_args_without_edge_env() {
        let cli = EdgeCliConfig::parse_from_args([
            "oxo-pingora-service",
            "--https-bind",
            "127.0.0.1:9443",
            "--fqdn",
            "app.example",
            "--public-origin-port",
            "443",
            "--tls-cert",
            "/etc/oxo/cert.pem",
            "--tls-key",
            "/etc/oxo/key.pem",
            "--acme-state-path",
            "/var/lib/oxo/acme",
            "--acme-renew-once",
            "--acme-directory-url",
            "https://acme-staging-v02.api.letsencrypt.org/directory",
            "--acme-contact",
            "mailto:ops@app.example",
            "--acme-accept-terms",
            "--public-mode",
            "smoke-beta",
            "--public-identity",
            "direct-public",
            "--max-in-flight-requests",
            "128",
            "--admin-bind",
            "127.0.0.1:9900",
            "--action-cable-bind",
            "127.0.0.1:28080",
            "--grpc-bind",
            "127.0.0.1:28081",
            "--static-mount",
            "/assets=/srv/app/shared/public/assets,cache-control=public%2Cmax-age=31536000",
            "--static-rails-preset",
            "/srv/app/current/public",
            "--serve-rails",
            "/srv/app/current",
        ])
        .unwrap();
        let sockets = vec![
            PathBuf::from("/tmp/oxo/worker-0.sock"),
            PathBuf::from("/tmp/oxo/worker-1.sock"),
        ];
        let args = collect_edge_args(&sockets, "127.0.0.1:9443".parse().unwrap(), &cli, 2000)
            .expect("edge args");
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");

        assert!(
            rendered.contains("--worker-socket /tmp/oxo/worker-0.sock"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--worker-socket /tmp/oxo/worker-1.sock"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--https-bind 127.0.0.1:9443"),
            "{rendered}"
        );
        assert!(rendered.contains("--fqdn app.example"), "{rendered}");
        assert!(rendered.contains("--public-origin-port 443"), "{rendered}");
        assert!(
            rendered.contains("--tls-cert /etc/oxo/cert.pem"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--tls-key /etc/oxo/key.pem"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--acme-state-path /var/lib/oxo/acme"),
            "{rendered}"
        );
        assert!(rendered.contains("--acme-renew-once"), "{rendered}");
        assert!(
            rendered.contains(
                "--acme-directory-url https://acme-staging-v02.api.letsencrypt.org/directory"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains("--acme-contact mailto:ops@app.example"),
            "{rendered}"
        );
        assert!(rendered.contains("--acme-accept-terms"), "{rendered}");
        assert!(
            rendered.contains(
                "--static-mount /assets=/srv/app/shared/public/assets,cache-control=public%2Cmax-age=31536000"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains("--static-rails-preset /srv/app/current/public"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--serve-rails /srv/app/current"),
            "{rendered}"
        );
        assert!(rendered.contains("--public-mode smoke-beta"), "{rendered}");
        assert!(
            rendered.contains("--public-identity direct-public"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--max-in-flight-requests 128"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--admin-bind 127.0.0.1:9900"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--action-cable-bind 127.0.0.1:28080"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--grpc-bind 127.0.0.1:28081"),
            "{rendered}"
        );
        assert!(rendered.contains("--drain-grace-ms 2000"), "{rendered}");
        // M-D: under `--features hop-timing`, the sibling hop_timing test sets
        // OXO_HOP_TIMING=1 (process env is shared across parallel tests) and
        // collect_edge_env() now CORRECTLY forwards it — that forwarding is the defect-#3
        // fix, not leakage. The invariant here is "no env beyond the sanctioned bench
        // vars", not "empty".
        assert!(collect_edge_env(&WorkerLaunch::Classic)
            .iter()
            .all(|(k, _)| k == "OXO_HOP_TIMING"
                || k == "OXO_HOP_REAPER"
                || k == "OXO_WORKER_DISPATCH"
                || k == "OXO_EDGE_FRAME_POOL_IDLE"));
    }

    #[test]
    fn edge_pool_env_accepts_owned_and_refuses_the_removed_pingora_arm() {
        // the A/B selector survives only as a refusal. Process env is shared
        // across parallel tests: set, check, restore, and the accepted value is the
        // default so a leak changes nothing.
        env::set_var("OXO_EDGE_POOL", "owned");
        assert!(validate_edge_pool_env().is_ok());
        env::set_var("OXO_EDGE_POOL", "pingora");
        let err = validate_edge_pool_env().unwrap_err();
        env::remove_var("OXO_EDGE_POOL");
        assert!(format!("{err:?}").contains("A/B control"), "{err:?}");
        assert!(validate_edge_pool_env().is_ok());
    }

    #[test]
    fn collect_edge_env_forwards_the_reaper_toggle() {
        // B-1: OXO_HOP_REAPER is a SHIPPED operational knob — the service must
        // forward it through env_clear() or an operator's =0 silently no-ops (and a
        // bench A/B silently becomes an A/A, which is exactly what the first campaign
        // read did). Process env is shared across parallel tests: set, check, restore.
        env::set_var("OXO_HOP_REAPER", "0");
        let forwarded = collect_edge_env(&WorkerLaunch::Classic)
            .iter()
            .any(|(k, v)| k == "OXO_HOP_REAPER" && v == "0");
        env::remove_var("OXO_HOP_REAPER");
        assert!(forwarded, "reaper toggle must reach the edge child");
    }

    #[test]
    fn service_forwards_trusted_proxy_and_long_lived_edge_args() {
        // D16: collect_edge_args historically never forwarded trusted-proxy CIDRs,
        // per-identity fairness, or the three long-lived caps, so a service configured
        // with those knobs launched an edge child that silently fell back to
        // defaults/disabled (trusted-proxy identity unusable). Assert each round-trips
        // with the OPERATOR-SUPPLIED value, not merely that a flag is present.
        let cli = EdgeCliConfig::parse_from_args([
            "oxo-pingora-service",
            "--https-bind",
            "0.0.0.0:8443",
            "--fqdn",
            "app.example",
            "--max-body",
            "1048576",
            "--tls-cert",
            "/etc/oxo/cert.pem",
            "--tls-key",
            "/etc/oxo/key.pem",
            "--public-mode",
            "smoke-beta",
            "--public-identity",
            "trusted-proxy",
            "--trusted-proxy-cidr",
            "10.0.0.0/8",
            "--trusted-proxy-cidr",
            "192.168.0.0/16",
            "--max-in-flight-per-identity",
            "7",
            "--max-in-flight-requests",
            "19",
            "--header-read-timeout-ms",
            "15000",
            "--keepalive-idle-timeout-ms",
            "12000",
            "--max-connection-secs",
            "300",
            "--long-lived-max-connections",
            "33",
            "--long-lived-max-buffered-bytes",
            "4242",
            "--long-lived-downstream-write-timeout-ms",
            "9000",
        ])
        .unwrap();
        let sockets = vec![PathBuf::from("/tmp/oxo/worker-0.sock")];
        let args = collect_edge_args(&sockets, "0.0.0.0:8443".parse().unwrap(), &cli, 2000)
            .expect("edge args");
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            rendered.contains("--trusted-proxy-cidr 10.0.0.0/8"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--trusted-proxy-cidr 192.168.0.0/16"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--max-in-flight-per-identity 7"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--max-in-flight-requests 19"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--header-read-timeout-ms 15000"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--keepalive-idle-timeout-ms 12000"),
            "{rendered}"
        );
        assert!(rendered.contains("--max-connection-secs 300"), "{rendered}");
        assert!(
            rendered.contains("--long-lived-max-connections 33"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--long-lived-max-buffered-bytes 4242"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--long-lived-downstream-write-timeout-ms 9000"),
            "{rendered}"
        );
        assert!(rendered.contains("--drain-grace-ms 2000"), "{rendered}");
    }

    #[test]
    fn service_rejects_trusted_proxy_cidrs_without_trusted_proxy_identity() {
        // D16 fail-closed cross-check: CIDRs set under a public mode while the identity
        // policy is direct-public means the CIDRs would be silently ignored by the edge.
        let cli = EdgeCliConfig::parse_from_args([
            "oxo-pingora-service",
            "--https-bind",
            "0.0.0.0:8443",
            "--fqdn",
            "app.example",
            "--max-body",
            "1048576",
            "--tls-cert",
            "/etc/oxo/cert.pem",
            "--tls-key",
            "/etc/oxo/key.pem",
            "--public-mode",
            "smoke-beta",
            "--public-identity",
            "direct-public",
            "--trusted-proxy-cidr",
            "10.0.0.0/8",
        ])
        .unwrap();
        let err = collect_edge_args(
            &[PathBuf::from("/tmp/oxo/worker-0.sock")],
            "0.0.0.0:8443".parse().unwrap(),
            &cli,
            2000,
        )
        .expect_err("trusted-proxy CIDRs with direct-public identity must fail closed");
        assert!(
            err.to_string().contains("OXO_EDGE_TRUSTED_PROXY_CIDRS"),
            "{err}"
        );
    }
}

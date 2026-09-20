//! # oxo-core — the seam
//!
//! This crate holds the *contract* that the rest of Oxo is built around, and
//! nothing else: no `hyper`, no `tokio`-specific machinery, no Ruby. Keeping it
//! dependency-light means it is trivial to test and impossible to accidentally
//! couple the request/response vocabulary to one transport or one handler.
//!
//! The three load-bearing pieces:
//!
//! * [`RackRequest`] / [`RackResponse`] — plain, owned Rust values. Crucially, a
//! `RackResponse` is **never** a live Ruby `VALUE`: the embedded handler fully
//! materializes the Ruby response into owned bytes *under the GVL* before it
//! crosses any thread boundary. (See `docs/CONCEPTS.md`.)
//! * [`RackHandler`] — the one-method async trait that both handlers implement.
//! The edge calls it; an `enum Handler` in the binary picks the implementation.
//! * [`Config`] — parsed once, at startup, with **parse-time guards** so an unsafe
//! configuration fails loudly instead of booting. The most important guard is the
//! loopback bind fence ([`ConfigError::PublicBindRequiresOptIn`]).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// the binary edge↔worker hop wire format (shared by the tokio edge and the
/// blocking worker so a single implementation defines the contract).
pub mod hop_frame;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// The non-secret public surface most callers want in one `use`.
pub mod prelude {
    pub use crate::{
        Config, ConfigError, Env, HandlerError, HandlerKind, RackHandler, RackRequest,
        RackResponse, WorkerKind,
    };
}

/// Rack's conventional development port.
pub const DEFAULT_PORT: u16 = 9292;

/// A hard cap on the buffered request body. Because every request body is fully
/// buffered into owned bytes (so it is `Send` across the handler boundary and so the
/// Ruby-side `rack.input` can be built under the GVL), an uncapped body would be an
/// unbounded-allocation footgun — especially on the supervised loopback hop, where
/// the bytes live in the edge *and* in flight to the worker.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

// Hyper edge limits used by oxo-edge. Zero means disabled, unlimited or the
// Hyper default, as appropriate. Pingora configures its limits separately.

/// Max concurrent connections (a `tokio::sync::Semaphore`). Sized to a small multiple of
/// real backend concurrency (Puma serves ~5; the shim serves 1) — NOT an abstract large
/// number, which would make the cap a deep latency-amplifying queue instead of a shield.
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;

/// Time allowed to read a request head (`hyper` `header_read_timeout`). Re-arms per head,
/// so it also bounds an idle keep-alive connection awaiting its next request.
pub const DEFAULT_HEADER_READ_TIMEOUT_SECS: u64 = 15;

/// Per-request budget for the handler **plus** the request-body read (NOT the response
/// write). On elapse the edge returns 504; a slow body is torn down by hyper.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Absolute connection-lifetime deadline (the only bound that also covers the
/// response-write phase and total connection age). **Disabled by default** because an
/// always-on absolute cap severs legitimate long-lived keep-alive; enable it for any
/// non-loopback deployment.
pub const DEFAULT_MAX_CONNECTION_SECS: u64 = 0;

/// Max header count (`hyper` `max_headers`); over-limit ⇒ hyper returns 431.
pub const DEFAULT_MAX_HEADER_COUNT: usize = 100;

/// Connection read-buffer ceiling (`hyper` `max_buf_size`): approximately caps the header
/// section AND governs body-read chunking — not an exact header-byte limit. A non-zero
/// value below this floor would panic `hyper`, so it is rejected at parse time.
pub const DEFAULT_MAX_READ_BUF_BYTES: usize = 64 * 1024;
/// `hyper`'s hard minimum for `max_buf_size`; a smaller non-zero value panics.
pub const MIN_READ_BUF_BYTES: usize = 8192;

/// A request after the edge has parsed and **normalized** it: header names are
/// lowercased and any underscore-bearing names have been dropped (see
/// [`normalize_header_name`]), and the body is fully buffered.
#[derive(Debug, Clone)]
pub struct RackRequest {
    /// `REQUEST_METHOD`, e.g. `"GET"`.
    pub method: String,
    /// `PATH_INFO`, e.g. `"/users/1"`.
    pub path: String,
    /// `QUERY_STRING` — `""` when absent (never missing, per the Rack SPEC).
    pub query_string: String,
    /// `SERVER_NAME`.
    pub server_name: String,
    /// `SERVER_PORT`.
    pub server_port: u16,
    /// `rack.url_scheme` for the Hyper request model. The current
    /// Pingora path derives trusted scheme from listener state separately.
    pub url_scheme: String,
    /// Header `(name, value)` pairs; names lowercased, underscore names already dropped.
    pub headers: Vec<(String, String)>,
    /// Fully-buffered, owned request body. has no streaming `rack.input`.
    pub body: Bytes,
}

/// A response from a handler. Owned bytes only — see the crate docs on why this is
/// never a live Ruby `VALUE`.
#[derive(Debug, Clone)]
pub struct RackResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl RackResponse {
    /// A `text/plain` response with a correct `content-length`.
    pub fn text(status: u16, body: impl Into<Bytes>) -> Self {
        let body = body.into();
        RackResponse {
            status,
            headers: vec![
                (
                    "content-type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                ),
                ("content-length".to_string(), body.len().to_string()),
            ],
            body,
        }
    }

    /// The canonical 500 the edge/handlers fall back to. Constructing this is always
    /// infallible, which is what lets the embedded handler guarantee a reply on every
    /// path (including when the Ruby app raises).
    pub fn internal_error() -> Self {
        Self::text(500, Bytes::from_static(b"Internal Server Error"))
    }

    /// The 413 returned when a body exceeds [`Config::max_body_bytes`].
    pub fn payload_too_large() -> Self {
        Self::text(413, Bytes::from_static(b"Payload Too Large"))
    }

    /// The 502 returned when the worker can't be reached (dead / connection reset) —
    /// distinct from a genuine application 500.
    pub fn bad_gateway() -> Self {
        Self::text(502, Bytes::from_static(b"Bad Gateway (worker unreachable)"))
    }

    /// The 503 returned while the worker is (re)starting. Carries `Retry-After` so an
    /// upstream load balancer / orchestrator treats it as temporary.
    pub fn service_unavailable() -> Self {
        let mut r = Self::text(
            503,
            Bytes::from_static(b"Service Unavailable (worker restarting)"),
        );
        r.headers.push(("retry-after".to_string(), "1".to_string()));
        r
    }

    /// The 504 returned when a request exceeds the per-request timeout. It is delivered
    /// only when the *worker/handler* is the slow party (the request body was already
    /// read) — a slow request *body* is cancelled mid-read and hyper tears the connection
    /// down instead. 504 (not 408) because the slow side is the upstream worker, matching
    /// [`Self::bad_gateway`]/[`Self::service_unavailable`].
    pub fn gateway_timeout() -> Self {
        Self::text(
            504,
            Bytes::from_static(b"Gateway Timeout (worker too slow)"),
        )
    }
}

/// Errors a handler can return. Note these are *recoverable* application-level
/// errors that become HTTP responses; they are never Ruby exceptions unwinding
/// across the FFI boundary (the embedded handler converts those on the Ruby thread).
#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    #[error("request body exceeds the configured limit")]
    BodyTooLarge,
    #[error("the Ruby application raised: {0}")]
    RubyError(String),
    #[error("supervised worker error: {0}")]
    Worker(String),
    #[error("i/o error: {0}")]
    Io(String),
    /// The worker is (re)starting — map to 503 (retryable).
    #[error("the worker is restarting")]
    WorkerUnavailable,
    /// The worker could not be reached (connect failed / connection reset) — map to 502,
    /// distinct from a genuine application 500.
    #[error("could not reach the worker: {0}")]
    WorkerUnreachable(String),
}

/// The seam: one async method, implemented by both the supervised and embedded
/// handlers and dispatched by an `enum Handler` in the binary (static dispatch — no
/// `async_trait`, no `Box<dyn>`).
///
/// The returned future is **explicitly `Send`**. The edge serves each connection on
/// a multi-threaded `tokio` task, so the future must be able to cross threads. This
/// bound is the whole reason the embedded handler hands work to a dedicated
/// Ruby-owning thread over a channel rather than touching the `!Send` Ruby handle
/// across the `.await`.
pub trait RackHandler: Send + Sync {
    fn handle(
        &self,
        req: RackRequest,
    ) -> impl std::future::Future<Output = Result<RackResponse, HandlerError>> + Send;
}

/// Which handler the binary should wire up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HandlerKind {
    /// Default. Spawn + supervise a separate Ruby worker; isolate the edge from the
    /// Ruby/C blast radius. No `libruby` link.
    Supervised,
    /// In-process Ruby via Magnus. Requires the `embedded` build of the binary and a
    /// matching Ruby ABI. Shared-fate with the edge — for trusted/single-tenant use.
    Embedded,
}

/// Runtime environment. `Production` opts *into* its configuration explicitly so a
/// production process can never silently inherit development defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Env {
    Development,
    Production,
}

/// Which supervised worker to run. Only meaningful for [`HandlerKind::Supervised`]
/// (the embedded handler ignores it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkerKind {
    /// Run Puma in the worker (default) — serves real Rails apps. Needs `puma` in the
    /// app's bundle and a working native-gem toolchain.
    Puma,
    /// Run the stdlib HTTP shim — dependency-light (no extra gems) and the fallback
    /// where Puma's C extension can't build (e.g. a Windows box without a devkit).
    Shim,
}

/// Fully-resolved, validated configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub env: Env,
    pub bind: SocketAddr,
    pub handler: HandlerKind,
    /// Which supervised worker to run (Puma by default). Ignored unless `handler` is
    /// [`HandlerKind::Supervised`].
    pub worker: WorkerKind,
    /// Path to the Rack app (`.ru`) the handler serves.
    pub app: PathBuf,
    pub max_body_bytes: usize,
    /// Max concurrent connections; `0` = unlimited. See [`DEFAULT_MAX_CONNECTIONS`].
    pub max_connections: usize,
    /// Head-read + idle-keepalive timeout in seconds; `0` = disabled.
    pub header_read_timeout_secs: u64,
    /// Per-request (handler + body-read) timeout in seconds; `0` = disabled.
    pub request_timeout_secs: u64,
    /// Absolute connection-lifetime deadline in seconds; `0` = disabled (the default).
    pub max_connection_secs: u64,
    /// Max header count; `0` = hyper default. See [`DEFAULT_MAX_HEADER_COUNT`].
    pub max_header_count: usize,
    /// Connection read-buffer ceiling in bytes; `0` = hyper default. Non-zero values must
    /// be ≥ [`MIN_READ_BUF_BYTES`]. See [`DEFAULT_MAX_READ_BUF_BYTES`].
    pub max_read_buf_bytes: usize,
    /// True only when the operator explicitly opted into a non-loopback bind.
    pub allow_public_bind: bool,
}

impl Config {
    /// Whether the Hyper listener is bound to a non-loopback interface.
    pub fn is_public_bind(&self) -> bool {
        !self.bind.ip().is_loopback()
    }
}

impl Default for Config {
    /// The same defaults [`Config::from_env_pairs`] applies with an empty environment:
    /// development, a loopback bind on [`DEFAULT_PORT`], the supervised Puma worker, and
    /// the secure-by-default hardening knobs. Lets call sites build a `Config` with
    /// `..Default::default` so adding a field does not churn every literal.
    fn default() -> Self {
        Config {
            env: Env::Development,
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_PORT),
            handler: HandlerKind::Supervised,
            worker: WorkerKind::Puma,
            app: PathBuf::from("ruby/trivial_app.ru"),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            header_read_timeout_secs: DEFAULT_HEADER_READ_TIMEOUT_SECS,
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
            max_connection_secs: DEFAULT_MAX_CONNECTION_SECS,
            max_header_count: DEFAULT_MAX_HEADER_COUNT,
            max_read_buf_bytes: DEFAULT_MAX_READ_BUF_BYTES,
            allow_public_bind: false,
        }
    }
}

/// The optional JSON config file (`OXO_CONFIG`). Every field is optional and is
/// overridden by the corresponding environment variable.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    env: Option<Env>,
    bind: Option<String>,
    handler: Option<HandlerKind>,
    worker: Option<WorkerKind>,
    app: Option<String>,
    max_body_bytes: Option<usize>,
    max_connections: Option<usize>,
    header_read_timeout_secs: Option<u64>,
    request_timeout_secs: Option<u64>,
    max_connection_secs: Option<u64>,
    max_header_count: Option<usize>,
    max_read_buf_bytes: Option<usize>,
}

/// Configuration errors. Each one is a *boot refusal*: it is better to fail at
/// startup than to serve from an unsafe configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid bind address {0:?}: {1}")]
    InvalidBind(String, String),
    #[error("production requires an explicit {0} (set {1})")]
    ProductionMustSpecify(&'static str, &'static str),
    #[error(
        "refusing to bind non-loopback address {0} without OXO_INSECURE_PUBLIC_BIND=1 — \
         this Hyper listener is plaintext and requires a trusted TLS-terminating boundary"
    )]
    PublicBindRequiresOptIn(SocketAddr),
    #[error("invalid config file {0}: {1}")]
    InvalidConfigFile(String, String),
    #[error("invalid value for {0}: {1:?}")]
    InvalidValue(&'static str, String),
}

impl Config {
    /// Resolve configuration from the process environment.
    pub fn from_env() -> Result<Config, ConfigError> {
        Self::from_env_pairs(std::env::vars())
    }

    /// Resolve and validate configuration. Precedence is **env var > JSON file >
    /// default**. Testable without touching the real process environment.
    pub fn from_env_pairs<I, K, V>(pairs: I) -> Result<Config, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let env: HashMap<String, String> = pairs
            .into_iter()
            .map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string()))
            .collect();
        let get = |k: &str| {
            env.get(k)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };

        // 1. Optional JSON file is the base layer.
        let mut file = FileConfig::default();
        if let Some(path) = get("OXO_CONFIG") {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| ConfigError::InvalidConfigFile(path.clone(), e.to_string()))?;
            file = serde_json::from_str(&text)
                .map_err(|e| ConfigError::InvalidConfigFile(path, e.to_string()))?;
        }

        // 2. Environment.
        let app_env = match get("OXO_ENV").as_deref() {
            Some("production") => Env::Production,
            Some("development") => Env::Development,
            Some(other) => return Err(ConfigError::InvalidValue("OXO_ENV", other.to_string())),
            None => file.env.unwrap_or(Env::Development),
        };

        // 3. Bind + handler. Track whether they were explicitly provided so production
        // can refuse to default them.
        let bind_str = get("OXO_BIND").or_else(|| file.bind.clone());
        let handler_kind = match get("OXO_HANDLER").as_deref() {
            Some("supervised") => Some(HandlerKind::Supervised),
            Some("embedded") => Some(HandlerKind::Embedded),
            Some(other) => return Err(ConfigError::InvalidValue("OXO_HANDLER", other.to_string())),
            None => file.handler,
        };
        // Worker has a sensible default (Puma), so unlike bind/handler it is not subject
        // to the production-must-specify guard.
        let worker = match get("OXO_WORKER").as_deref() {
            Some("puma") => WorkerKind::Puma,
            Some("shim") => WorkerKind::Shim,
            Some(other) => return Err(ConfigError::InvalidValue("OXO_WORKER", other.to_string())),
            None => file.worker.unwrap_or(WorkerKind::Puma),
        };

        if app_env == Env::Production {
            if bind_str.is_none() {
                return Err(ConfigError::ProductionMustSpecify(
                    "bind address",
                    "OXO_BIND or the config file 'bind'",
                ));
            }
            if handler_kind.is_none() {
                return Err(ConfigError::ProductionMustSpecify(
                    "handler",
                    "OXO_HANDLER or the config file 'handler'",
                ));
            }
        }

        let bind: SocketAddr = match bind_str {
            Some(s) => s.parse().map_err(|e: std::net::AddrParseError| {
                ConfigError::InvalidBind(s, e.to_string())
            })?,
            None => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_PORT),
        };
        let handler = handler_kind.unwrap_or(HandlerKind::Supervised);

        let allow_public_bind = matches!(
            get("OXO_INSECURE_PUBLIC_BIND").as_deref(),
            Some("1") | Some("true")
        );

        // 4. The bind fence: a non-loopback bind requires an explicit, loud opt-in.
        if !bind.ip().is_loopback() && !allow_public_bind {
            return Err(ConfigError::PublicBindRequiresOptIn(bind));
        }

        let app = get("OXO_APP")
            .or_else(|| file.app.clone())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("ruby/trivial_app.ru"));

        let max_body_bytes = match get("OXO_MAX_BODY_BYTES") {
            Some(s) => s
                .parse()
                .map_err(|_| ConfigError::InvalidValue("OXO_MAX_BODY_BYTES", s))?,
            None => file.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES),
        };

        // 5. The edge-hardening knobs (env > file > default; `0` is a valid sentinel).
        let max_connections = match get("OXO_MAX_CONNECTIONS") {
            Some(s) => s
                .parse()
                .map_err(|_| ConfigError::InvalidValue("OXO_MAX_CONNECTIONS", s))?,
            None => file.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
        };
        let header_read_timeout_secs = match get("OXO_HEADER_READ_TIMEOUT_SECS") {
            Some(s) => s
                .parse()
                .map_err(|_| ConfigError::InvalidValue("OXO_HEADER_READ_TIMEOUT_SECS", s))?,
            None => file
                .header_read_timeout_secs
                .unwrap_or(DEFAULT_HEADER_READ_TIMEOUT_SECS),
        };
        let request_timeout_secs = match get("OXO_REQUEST_TIMEOUT_SECS") {
            Some(s) => s
                .parse()
                .map_err(|_| ConfigError::InvalidValue("OXO_REQUEST_TIMEOUT_SECS", s))?,
            None => file
                .request_timeout_secs
                .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
        };
        let max_connection_secs = match get("OXO_MAX_CONNECTION_SECS") {
            Some(s) => s
                .parse()
                .map_err(|_| ConfigError::InvalidValue("OXO_MAX_CONNECTION_SECS", s))?,
            None => file
                .max_connection_secs
                .unwrap_or(DEFAULT_MAX_CONNECTION_SECS),
        };
        let max_header_count = match get("OXO_MAX_HEADER_COUNT") {
            Some(s) => s
                .parse()
                .map_err(|_| ConfigError::InvalidValue("OXO_MAX_HEADER_COUNT", s))?,
            None => file.max_header_count.unwrap_or(DEFAULT_MAX_HEADER_COUNT),
        };
        let max_read_buf_bytes = match get("OXO_MAX_READ_BUF_BYTES") {
            Some(s) => s
                .parse()
                .map_err(|_| ConfigError::InvalidValue("OXO_MAX_READ_BUF_BYTES", s))?,
            None => file
                .max_read_buf_bytes
                .unwrap_or(DEFAULT_MAX_READ_BUF_BYTES),
        };
        // hyper's max_buf_size panics below MIN_READ_BUF_BYTES; refuse it at parse time
        // (0 stays valid — it means "leave hyper's default").
        if max_read_buf_bytes != 0 && max_read_buf_bytes < MIN_READ_BUF_BYTES {
            return Err(ConfigError::InvalidValue(
                "OXO_MAX_READ_BUF_BYTES",
                format!("must be 0 or >= {MIN_READ_BUF_BYTES}, got {max_read_buf_bytes}"),
            ));
        }

        Ok(Config {
            env: app_env,
            bind,
            handler,
            worker,
            app,
            max_body_bytes,
            max_connections,
            header_read_timeout_secs,
            request_timeout_secs,
            max_connection_secs,
            max_header_count,
            max_read_buf_bytes,
            allow_public_bind,
        })
    }
}

/// Defensive CGI header-name handling. After CGI-ization (uppercase, `-`→`_`,
/// `HTTP_` prefix), a client header whose name already contains an underscore could
/// forge a dashed header — e.g. `X_Forwarded_For` and `X-Forwarded-For` both become
/// `HTTP_X_FORWARDED_FOR`, letting a client impersonate a proxy-set value. We drop
/// underscore-bearing names at the edge (nginx's `underscores_in_headers off`
/// default). Returns the lowercased name to keep, or `None` to drop.
pub fn normalize_header_name(name: &str) -> Option<String> {
    if name.contains('_') {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// Central predicate for client headers that can forge forwarding identity.
/// Apply it before constructing Rack HTTP_* fields: trusted identity arrives
/// through edge metadata or native frame fields, never client forwarding headers.
///
/// Rails RemoteIp reads Client-IP and X-Forwarded-For, so both must be covered.
/// Application headers remain allowed; additional provider-specific identity
/// headers require review when integrating a new proxy or consumer.
///
/// Input must be ASCII-lowercase. Reserved x-oxo-* headers are a separate class
/// removed at each caller, not by this predicate.
pub fn is_client_forwarding_header(name: &str) -> bool {
    matches!(
        name,
        "forwarded"
            | "x-real-ip"
            | "client-ip"
            | "true-client-ip"
            | "cf-connecting-ip"
            | "cf-pseudo-ipv4"
            | "x-client-ip"
            | "fastly-client-ip"
            | "fly-client-ip"
            | "x-cluster-client-ip"
            | "x-original-forwarded-for"
            | "x-original-for"
            | "x-appengine-user-ip"
            | "x-azure-clientip"
            | "x-azure-socketip"
            | "x-proxyuser-ip"
            | "x-forwarded"
    ) || name.starts_with("x-forwarded-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(kv: &[(&str, &str)]) -> Vec<(String, String)> {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn client_forwarding_header_covers_the_family_but_not_app_or_oxo() {
        // The full Rails-trusted + CDN/provider client-IP family is dropped.
        for h in [
            "forwarded",
            "x-real-ip",
            "client-ip",
            "true-client-ip",
            "cf-connecting-ip",
            "cf-pseudo-ipv4",
            "x-client-ip",
            "fastly-client-ip",
            "fly-client-ip",
            "x-cluster-client-ip",
            "x-original-forwarded-for",
            "x-original-for",
            "x-appengine-user-ip",
            "x-azure-clientip",
            "x-azure-socketip",
            "x-proxyuser-ip",
            "x-forwarded",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
        ] {
            assert!(is_client_forwarding_header(h), "must drop {h}");
        }
        // Ordinary app headers pass through — an allowlist would be infeasible.
        for h in [
            "host",
            "user-agent",
            "accept",
            "authorization",
            "content-type",
            "x-app-ip",     // app header that merely contains "ip"
            "x-request-id", // handled elsewhere, not a forwarding header
        ] {
            assert!(!is_client_forwarding_header(h), "must not drop {h}");
        }
        // The x-oxo-* reserved namespace is a SEPARATE class (dropped by its own arm).
        assert!(!is_client_forwarding_header("x-oxo-remote-addr"));
        assert!(!is_client_forwarding_header("x-oxo-foo"));
    }

    #[test]
    fn development_defaults_to_loopback_supervised() {
        let c = Config::from_env_pairs(pairs(&[])).unwrap();
        assert_eq!(c.env, Env::Development);
        assert_eq!(c.handler, HandlerKind::Supervised);
        assert!(c.bind.ip().is_loopback());
        assert_eq!(c.bind.port(), DEFAULT_PORT);
        assert!(!c.is_public_bind());
        assert_eq!(c.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(c.worker, WorkerKind::Puma); // worker defaults to Puma
    }

    #[test]
    fn hardening_knobs_default_to_secure_values() {
        let c = Config::from_env_pairs(pairs(&[])).unwrap();
        assert_eq!(c.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(c.header_read_timeout_secs, DEFAULT_HEADER_READ_TIMEOUT_SECS);
        assert_eq!(c.request_timeout_secs, DEFAULT_REQUEST_TIMEOUT_SECS);
        assert_eq!(c.max_connection_secs, DEFAULT_MAX_CONNECTION_SECS); // 0 = disabled
        assert_eq!(c.max_header_count, DEFAULT_MAX_HEADER_COUNT);
        assert_eq!(c.max_read_buf_bytes, DEFAULT_MAX_READ_BUF_BYTES);
    }

    #[test]
    fn config_default_matches_empty_env() {
        // Pins Config::default to the from_env defaults so a Default regression (e.g. a
        // hardening knob silently dropping to 0) is caught.
        assert_eq!(
            Config::default(),
            Config::from_env_pairs(pairs(&[])).unwrap()
        );
    }

    #[test]
    fn hardening_knobs_parse_from_env() {
        let c = Config::from_env_pairs(pairs(&[
            ("OXO_MAX_CONNECTIONS", "8"),
            ("OXO_HEADER_READ_TIMEOUT_SECS", "3"),
            ("OXO_REQUEST_TIMEOUT_SECS", "7"),
            ("OXO_MAX_CONNECTION_SECS", "120"),
            ("OXO_MAX_HEADER_COUNT", "40"),
            ("OXO_MAX_READ_BUF_BYTES", "16384"),
        ]))
        .unwrap();
        assert_eq!(c.max_connections, 8);
        assert_eq!(c.header_read_timeout_secs, 3);
        assert_eq!(c.request_timeout_secs, 7);
        assert_eq!(c.max_connection_secs, 120);
        assert_eq!(c.max_header_count, 40);
        assert_eq!(c.max_read_buf_bytes, 16384);
    }

    #[test]
    fn zero_sentinels_are_accepted() {
        let c = Config::from_env_pairs(pairs(&[
            ("OXO_MAX_CONNECTIONS", "0"),
            ("OXO_HEADER_READ_TIMEOUT_SECS", "0"),
            ("OXO_REQUEST_TIMEOUT_SECS", "0"),
            ("OXO_MAX_HEADER_COUNT", "0"),
            ("OXO_MAX_READ_BUF_BYTES", "0"),
        ]))
        .unwrap();
        assert_eq!(c.max_connections, 0);
        assert_eq!(c.max_read_buf_bytes, 0); // 0 = leave hyper default (not rejected)
    }

    #[test]
    fn max_read_buf_below_floor_is_rejected() {
        let err = Config::from_env_pairs(pairs(&[("OXO_MAX_READ_BUF_BYTES", "4096")])).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue("OXO_MAX_READ_BUF_BYTES", _)),
            "got {err:?}"
        );
    }

    #[test]
    fn non_loopback_bind_is_fenced_without_optin() {
        let err = Config::from_env_pairs(pairs(&[("OXO_BIND", "0.0.0.0:80")])).unwrap_err();
        assert!(
            matches!(err, ConfigError::PublicBindRequiresOptIn(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn non_loopback_bind_allowed_with_explicit_optin() {
        let c = Config::from_env_pairs(pairs(&[
            ("OXO_BIND", "0.0.0.0:8080"),
            ("OXO_INSECURE_PUBLIC_BIND", "1"),
        ]))
        .unwrap();
        assert!(c.is_public_bind());
        assert!(c.allow_public_bind);
    }

    #[test]
    fn worker_kind_parses_and_defaults_to_puma() {
        assert_eq!(
            Config::from_env_pairs(pairs(&[])).unwrap().worker,
            WorkerKind::Puma
        );
        assert_eq!(
            Config::from_env_pairs(pairs(&[("OXO_WORKER", "shim")]))
                .unwrap()
                .worker,
            WorkerKind::Shim
        );
        let err = Config::from_env_pairs(pairs(&[("OXO_WORKER", "nope")])).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue("OXO_WORKER", _)),
            "got {err:?}"
        );
    }

    #[test]
    fn production_must_specify_bind_and_handler() {
        let err = Config::from_env_pairs(pairs(&[("OXO_ENV", "production")])).unwrap_err();
        assert!(
            matches!(err, ConfigError::ProductionMustSpecify("bind address", _)),
            "got {err:?}"
        );

        let err = Config::from_env_pairs(pairs(&[
            ("OXO_ENV", "production"),
            ("OXO_BIND", "127.0.0.1:9292"),
        ]))
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::ProductionMustSpecify("handler", _)),
            "got {err:?}"
        );
    }

    #[test]
    fn production_boots_when_fully_specified() {
        let c = Config::from_env_pairs(pairs(&[
            ("OXO_ENV", "production"),
            ("OXO_BIND", "127.0.0.1:9292"),
            ("OXO_HANDLER", "supervised"),
        ]))
        .unwrap();
        assert_eq!(c.env, Env::Production);
        assert_eq!(c.handler, HandlerKind::Supervised);
    }

    #[test]
    fn underscore_header_names_are_dropped() {
        // The forgery vector: X_Forwarded_For must not survive to become HTTP_X_FORWARDED_FOR.
        assert_eq!(normalize_header_name("X_Forwarded_For"), None);
        assert_eq!(normalize_header_name("Host"), Some("host".to_string()));
        assert_eq!(
            normalize_header_name("X-Forwarded-For"),
            Some("x-forwarded-for".to_string())
        );
    }

    #[test]
    fn text_response_sets_content_length() {
        let r = RackResponse::text(200, Bytes::from_static(b"hello"));
        assert_eq!(r.status, 200);
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "content-length" && v == "5"));
    }
}

use super::EdgeError;
use bytes::Bytes;
use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::http::{ResponseHeader, Version};
#[cfg(feature = "tls-rustls")]
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::proxy::{http_proxy_service, FailToProxy, ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;
use tokio::time::timeout;

// Owned-hop limits and timeouts. The worker-hop timeouts are deliberately asymmetric
// and load-bearing for the pool retry policy: connecting to a local UDS is fast, so a
// short `WORKER_CONNECT_TIMEOUT` lets `send_worker_request_to_pool` treat a slow connect
// as "this worker is unavailable" and try the next one — the ONLY point where a request
// is retried. Once any byte is written (`WORKER_WRITE_TIMEOUT`) or a response is being
// read (`WORKER_READ_TIMEOUT`, generous because it bounds worst-case Rack response time),
// the request is never replayed, so those must be long enough not to abort a healthy
// slow request. `DEFAULT_LONG_LIVED_MAX_BUFFERED_BYTES` mirrors `MAX_RESPONSE_BYTES` so
// the streaming and buffered paths share one response-size ceiling.
const MAX_REQUEST_HEADERS: usize = 100;
const MAX_REQUEST_HEADER_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const DOWNSTREAM_BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
const DOWNSTREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const WORKER_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_PUBLIC_MAX_IN_FLIGHT_PER_IDENTITY: u64 = 64;
const DEFAULT_HEADER_READ_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_KEEPALIVE_IDLE_TIMEOUT_MS: u64 = 15_000;
// total requests a kept-alive connection may serve (nginx keepalive_requests parity).
const DEFAULT_MAX_REQUESTS_PER_CONNECTION: u64 = 1_000;
// HTTP/2 resource bounds. Concurrent-streams matches pingora's default_h2_options;
// reset-streams matches h2 0.3.27's CVE-2023-44487-patched default.
const DEFAULT_H2_MAX_CONCURRENT_STREAMS: u64 = 100;
const DEFAULT_H2_MAX_RESET_STREAMS: u64 = 20;
const PINGORA_TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 60;
const WORKER_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Cache the process ID once for request identifiers and telemetry.
pub(crate) fn cached_pid() -> u32 {
    static CACHED_PID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *CACHED_PID.get_or_init(std::process::id)
}
const WORKER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_LONG_LIVED_MAX_CONNECTIONS: u64 = 128;
const DEFAULT_LONG_LIVED_MAX_BUFFERED_BYTES: u64 = MAX_RESPONSE_BYTES as u64;
const DEFAULT_LONG_LIVED_DOWNSTREAM_WRITE_TIMEOUT: Duration = DOWNSTREAM_WRITE_TIMEOUT;
const SOCKET_ACTIVATION_ENV: [&str; 3] = ["LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES"];

mod config;
mod drain;
mod fairness;
mod frame_hop;
mod frame_pool;
mod fs_validate;
mod proxy;
mod scratch;
mod telemetry;
mod worker_wire;

// Facade: exactly today's crate-root surface. The depth-1 `pub(super) use`
// reproduces the pub(super) visibility of socket_activation_env_name
// so the crate-root tail tests keep resolving `platform::…` paths unchanged.
pub use config::{run_from_args, run_from_env};
// Consumed only by the crate-root #[cfg(test)] suite; inert otherwise.
#[cfg_attr(not(test), allow(unused_imports))]
pub use config::socket_activation_env_name;
pub use fs_validate::validate_worker_socket_path;

// Internal prelude: every submodule does `use super::*;`, so the shared
// imports and consts above plus each sibling's pub(super) items resolve
// exactly as they did in the single inline module. Nothing here is exported
// beyond the platform tree.
use self::config::*;
use self::drain::*;
use self::fairness::*;
use self::proxy::*;
use self::telemetry::*;
use self::worker_wire::*;

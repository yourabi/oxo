# Oxo Architecture

Oxo combines a Pingora HTTP edge with supervised Rack workers. The edge owns
public protocol handling and admission; workers execute the Rails/Rack app.
Public exposure requires explicit `alpha` or `smoke-beta` configuration.
`production` public mode is unavailable. See the [threat model](THREAT_MODEL.md)
for enforced boundaries and limitations, and [correctness tests](../test/README.md)
for executable coverage and fixture setup.

## Components

```text
client
 -> oxo-pingora-edge
      -> private Unix sockets -> Rack worker processes -> Rails/Rack
      -> loopback TCP -> standalone Action Cable runtime
      -> loopback TCP -> standalone gRPC runtime

oxo-pingora-service owns child startup, readiness, monitoring and shutdown.
An independent loopback admin listener exposes health and aggregate counters.
```

The Linux Pingora edge supports HTTP/1.1 and, with `tls-rustls`, TLS and HTTP/2.
The native `oxo-worker` embeds Ruby through Magnus. Alternatively,
`OXO_WORKER_KIND=async` selects the fiber-based `ruby/oxo_async_worker.rb` runtime.
Each worker process has its own socket and Ruby VM.

The workspace also contains the Hyper HTTP/1.1 `oxo-edge` implementation and
the `oxo` launcher. Its `RackHandler` can use a supervised TCP worker or the
in-process `oxo-embedded` handler. These are separate paths: Hyper-specific
limits do not establish equivalent enforcement in Pingora.

## Rack request path

The Pingora `request_filter` owns the Rack exchange so the edge can validate and
buffer a request before acquiring a worker connection:

1. Collect parsed headers and validate target, framing, protocol, host and limits.
2. Resolve client identity and acquire applicable admission guards.
3. Handle eligible static or sidecar routes separately.
4. For Rack requests, sanitize headers and buffer the complete bounded body.
5. Encode the worker request, select a worker and acquire its connection.
6. Send the request, read a bounded worker response and write it downstream.
7. Release admission and connection resources on completion, error or cancellation.

The Rack path returns `Ok(true)` to skip Pingora's normal upstream proxy loop.
Sidecar routes return to that loop and retain admission guards in request context
for the connection's lifetime. A static fallthrough retains the same admission
guard rather than admitting the request twice.

HTTP/1 requests use explicit, unambiguous body framing. HTTP/2 can end a body
without Content-Length; the edge buffers it and derives the worker body length.
Malformed, oversized or incomplete Rack requests do not acquire a worker
connection. Idle pooled worker sockets can already exist independently of that
request.

## Worker protocols

The default `frame` hop uses `oxo-core::hop_frame`: a six-byte magic/version/length
prefix followed by a bounded binary envelope. Request method, target, identity,
headers and body are encoded fields. Decoders check nested lengths against the
envelope before dispatch. Response frames represent complete bodies or, for the
native streaming worker, response start, chunks and end.

Each pooled connection carries sequential exchanges with one request in flight.
An idle watcher detects closure, unexpected data, eviction, drain and timeout.
Only a complete response boundary with no buffered surplus can return to the
pool. Errors or cancellation discard the connection. The idle ceiling is
aggregate across the edge process; `/pool-health` reports the configured ceiling
and actual reuse counters. An optional supervised reaper can drive the watchers
in one task.

The `http` hop is a separate one-shot HTTP/1.1 path. It reconstructs Host,
Content-Length, Connection and trusted metadata, then closes after one exchange.
The native worker accepts this direct HTTP form as well as binary frames. Its
parser rejects unsupported transfer coding, ambiguous headers and malformed
targets. The async worker accepts binary frames only.

Identity is transported in binary fields or reserved `x-oxo-*` HTTP metadata.
It becomes Rack's REMOTE_ADDR, scheme and server name/port, never a client
`HTTP_X_OXO_*` variable. Both workers filter forwarding identity headers again
before constructing the Rack environment.

## Worker execution and dispatch

The native worker initializes Ruby on the main thread and loads the app before
starting its Ruby thread pool and socket listener. Rust parses requests and
queues owned data. Queue waits release the GVL; Ruby objects stay on Ruby threads.
Blocking I/O can overlap, while Ruby bytecode remains subject to the process GVL.

The async worker assigns a fiber to each connection. Scheduler-aware I/O yields
to other fibers. Rails apps must use ActiveSupport fiber isolation so concurrent
requests do not share thread-local request state. It buffers response bodies and
does not implement the native worker's opt-in response streaming mode.

`OXO_WORKER_COUNT` sets process parallelism. The default dispatch policy is
least-outstanding, with round-robin tie-breaking; other selectable policies are
validated at startup. Per-attempt RAII guards maintain the in-flight counts.
An optional per-worker cap parks excess requests at the edge and reselects a
worker when capacity is available. Cancellation releases the parked and active
counts. Connection affinity, when selected, is local to an eligible HTTP/1
connection; it is not distributed application-session affinity.

## Failures and response ownership

Connect failures can try another configured worker before request execution.
Frame retry policy also distinguishes worker kind and whether the write completed.
For async workers, a completed request write followed by zero-response-byte EOF
is terminal: the app may have run, so neither retry nor sibling failover is allowed.
The native path retains its distinct stale-connection retry policy. Tests cover
both policies in [frame_replay.rs](../crates/oxo-pingora-edge/tests/frame_replay.rs).

An unreachable worker normally maps to 503; a broken worker exchange maps to 502.
Ruby app exceptions become 500 responses when the worker can still construct a
valid response. After downstream response bytes have been sent, an error can
require closing the connection rather than replacing its status.

Servers own response framing. Application framing headers are removed; buffered
responses get a computed Content-Length and the configured downstream connection
policy. Repeated Set-Cookie values remain separate. Native streaming responses
use bounded event queues and protocol-specific framing, with downstream write
timeouts and long-lived accounting.

Request bodies stay in memory within configured caps, with rewindable StringIO
for rack.input. There is no request-body tempfile spill or Rack hijack support.

## Static files and sidecars

Static files use crenel and its Pingora adapter. The `--serve-rails` preset derives
public-directory mounts and enables keepalive/SSE defaults; explicit settings
take precedence. Missing assets can omit the strict assets mount without
preventing an API-only app from starting. Invalid explicit docroots fail checks.
The preset does not satisfy explicit public-exposure requirements.

Without `--prod`, static lookup can discover newly deployed files. With `--prod`,
the edge records top-level static path segments at boot and skips lookup for
unmatched dynamic paths. Newly introduced top-level names require a restart.
This static-routing flag does not enable public `production` mode.

Validated HTTP/1 `/cable` upgrades with the Action Cable subprotocol and matching
Origin can route to a standalone loopback Cable child. They bypass the Rack
worker. Generic WebSocket proxying and in-app Rack hijack are unsupported.
The test suite distinguishes file-bus simulation from real Redis checks.

SSE uses the native worker's response streaming substrate:
`OXO_EDGE_SSE=1` admits event-stream requests and `OXO_WORKER_STREAMING=1` enables
incremental Rack responses, including Rails ActionController::Live.

Native gRPC routes over TLS/H2 to a separate loopback gRPC child. Unary,
server-streaming, client-streaming and bidi traffic use that sidecar route with
long-lived accounting. gRPC does not execute through Rack; gRPC-Web is unsupported.

## Lifecycle and certificates

The service starts workers with cleared, allowlisted environments and per-worker
socket identity. Readiness requires the expected stdout handshake, socket checks
and a connection probe. App logs use stderr. Async workers boot concurrently;
native workers boot sequentially. Exited workers restart with bounded backoff.

Shutdown signals the edge first, then drains and terminates child process groups
with a bounded escalation to KILL. This bounds cleanup; it does not guarantee
zero dropped in-flight requests. Listener ownership uses direct binds, and
socket-activation environment markers are rejected. Workers are spawned rather
than forked after Ruby preload.

With `acme`, one-shot issuance and renewal use a separate HTTP-01 challenge
listener. The service can schedule renewal children and respond to certificate
reload markers by restarting the edge. It retains the previous certificate pair
for rollback. This is a bounded restart, not in-process or zero-drop TLS reload.
Production ACME directory consent is separate from public application mode.

## Platform and build boundaries

The toolchain is pinned in [rust-toolchain.toml](../rust-toolchain.toml).
The Pingora and native Ruby worker runtimes target Linux. Default Windows builds
provide Ruby-free stubs; they do not establish native Windows Ruby runtime support.
Build and test requirements are documented in the [test guide](../test/README.md).

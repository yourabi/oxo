# Oxo Concepts

This file teaches the vocabulary used in the Pingora + Oxo-worker line. It
explains the terms that appear in the request-path code and operator docs.

## Rack

Rack is the Ruby web-server interface Rails is built on. A Rack app responds to:

```ruby
status, headers, body = app.call(env)
```

The `env` hash describes the request. The app returns a numeric status, response
headers, and a body object. The body may be enumerable, closable, or callable in
older streaming patterns.

Oxo's worker owns the server side of this contract:

* build a Rack::Lint-clean `env`;
* provide binary, rewindable `rack.input`;
* call `app.call(env)`;
* materialize default responses into owned bytes;
* stream callable/enumerable response chunks when `OXO_WORKER_STREAMING=1`;
* call `close` on the response body when available.

Current S1 request bodies stay fully in memory up to the configured cap, and
`rack.input` is a rewindable `StringIO`. adds opt-in Rack response
streaming; tempfile spill and protocol-specific streaming ownership remain later
resource/protocol milestones.

## Rack Env Construction

Rack has special variables that are not normal HTTP headers:

* `REQUEST_METHOD`, `PATH_INFO`, `QUERY_STRING`;
* `SERVER_NAME`, `SERVER_PORT`, `SERVER_PROTOCOL`;
* `REMOTE_ADDR`;
* `rack.url_scheme`, `rack.input`, `rack.errors`;
* `rack.multithread`, `rack.multiprocess`, `rack.run_once`.

Oxo treats trusted hop metadata as internal data, not client headers. The
edge/worker consume reserved `x-oxo-*` fields to set `REMOTE_ADDR`, scheme,
server name, and server port. Those fields are not exposed to the Rack app as
`HTTP_X_OXO_*`.

`Content-Type` and `Content-Length` become Rack's special `CONTENT_TYPE` and
`CONTENT_LENGTH`. Other safe app headers become `HTTP_*` variables.

## Ruby GVL And Threads

MRI Ruby has a Global VM Lock. Ruby bytecode in one process does not run in true
CPU parallelism, even with multiple Ruby threads. Threads are still useful for
IO-bound Rails requests because blocking database/cache/network operations can
release the GVL or wait outside active Ruby execution.

Oxo's S1 worker uses fixed Ruby threads. The Rust queue wait happens through
`rb_thread_call_without_gvl`, so idle Ruby worker threads can block for jobs
without freezing the VM. The S1 tests prove two slow Rack requests can overlap;
they do not prove CPU-bound Ruby parallelism.

## Magnus Embedding

Magnus links Rust to `libruby`. Ruby must be initialized before Oxo starts
Ruby worker threads, listener threads, or runtimes that might call into Ruby.
Ruby `VALUE`s are not sent through Rust queues. The queue carries owned Rust
strings and bytes, then a Ruby thread rebuilds Ruby objects when it calls Rack.

This matters because live Ruby objects are tied to Ruby's VM and GC rules.
Oxo crosses thread/process boundaries with plain owned data instead.

 rejects native Windows Ruby/Magnus runtime support for the current accepted
matrix. The default Windows build links no Ruby; forcing the embedded Magnus
feature under native MSVC with the observed MinGW/UCRT Ruby fails in
`rb-sys`/bindgen. Linux/WSL remains the Ruby runtime evidence surface.

## Pingora Edge

Pingora is the intended public edge. Eventually it should own public protocol
parsing, TLS, timeouts, header/body caps, public bind policy, trusted client-IP
capture, and routing to the worker tier.

The current Pingora line is Linux-only. proves the owned buffered hop against
a fake UDS worker, proves the hop against one real S1 worker and Rails seed,
 adds a spawn-supervised worker pool around that path, adds public-edge
H1/security preflight, adds TLS/H1+H2 behind `tls-rustls`, adds explicit
public-bind alpha, and records a constrained production-candidate RC for the
tested matrix. audits the public-production path and keeps `production`
mode unavailable. reconciles docs/comments only. adds bounded migration
docs and a NO-GO production re-audit. Production mode remains unavailable;
smoke-beta remains the maximum public exposure claim. It does not provide Linux
metal capacity evidence, production TLS operations beyond the rehearsal
envelope, broad proxy-header trust, sticky sessions, or broad Rails deployment
compatibility.

## `request_filter`

`ProxyHttp::request_filter` is a Pingora hook that runs after Pingora has parsed
the downstream request headers. Oxo uses it as the whole fake-worker request
path in:

1. collect parsed headers;
2. reject unsupported targets/framing/protocols and over-cap request headers;
3. buffer the complete declared body, with ordinary `Content-Length: 0` treated as empty;
4. open the fixed UDS;
5. write a canonical worker request;
6. parse a bounded worker response;
7. write that response downstream;
8. return `Ok(true)` so Pingora does not run its default upstream proxy loop.

This design was chosen because the default proxy loop can acquire/connect the
upstream before Oxo has proven the full request body.

## Owned Buffered UDS Hop

"Owned" means Oxo writes and parses the worker-hop bytes itself instead of
asking Pingora to transparently proxy them. "Buffered" means the full declared
request body is held by the edge before the worker socket is opened.

The property Oxo wants is simple and strict:

```text
bad or incomplete client request -> no worker UDS connection exists
```

That is why the current edge rejects short bodies, duplicate `Content-Length`,
duplicate Host, `Transfer-Encoding`, trailers, malformed headers, absolute-form
targets, ambiguous keep-alive/connection-token cases, CONNECT, h2c, Upgrade,
gRPC, SSE markers by default, and over-cap request headers before acquiring the worker UDS.

## One-Shot UDS Worker Hop

S1 speaks HTTP/1.1 over a Unix-domain socket, but with a narrower contract than a
public HTTP server:

* one connection carries one request and one response;
* no keep-alive pooling;
* no pipelining;
* `Connection: close` is always forced;
* the socket lives in a private runtime directory.

One-shot connections reduce internal request-smuggling ambiguity. If the edge
and worker ever disagree about request framing, there is no second request
waiting behind the first on a reused backend connection.

## Trusted Hop Metadata

Internet clients can spoof `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, and even
reserved `X-Oxo-*` names. In direct-public mode, Oxo strips those inbound
names. Only the edge or an internal trusted hop synthesizes the reserved
`x-oxo-*` metadata that feeds Rack identity fields. also strips inbound
request IDs and generates an edge-owned `x-oxo-request-id`. derives
trusted Rack scheme from listener state instead of `OXO_EDGE_SCHEME`.

 adds trusted-proxy identity for public smoke-beta mode. It trusts only an
immediate peer inside configured CIDRs, accepts only canonical `X-Forwarded-For`,
rejects malformed or ambiguous chains before worker acquisition, and still strips
forwarding headers before Rack. This is not broad proxy-header trust.

 adds a per-identity concurrent admission cap keyed by that trusted edge
identity. Saturation returns `503` before body buffering or worker acquisition,
and only aggregate counters are exported on the private admin listener. This is not
distributed rate limiting, token-bucket policy, public admin, or long-lived
protocol fairness.

## Loopback Service Runner

The `oxo-pingora-service` binary is a loopback lifecycle owner for a
spawn-supervised worker pool. It starts one or more `oxo-worker` children with
cleared worker environments, exact per-worker sockets, worker ids, generations,
pool size, and Rack multiprocess truth.

The edge receives `OXO_EDGE_WORKER_SOCKETS`, selects ready sockets
round-robin only after request validation/body buffering, and may retry another
socket only if connect fails before worker write. If bytes may have reached a
worker, the request is not replayed. The runner respawns exited workers with
bounded backoff. provides bounded Unix TERM/KILL cleanup, but not sticky
sessions, zero-drop request drain, recycle, hot reload, socket activation,
inherited listener descriptors, or public health. keeps direct binds and
high-port external mapping as the accepted deploy shape.
Optional standalone Cable gets a separate loopback bind and cable-only env; it is
not part of the Rack worker UDS hop. adds a private admin operator schema and
redacted service-runner startup env summaries; adds a constrained RC audit
and behavioral burst stress evidence. Those diagnostics are private and do not
expose app secrets. Admin exposure/authentication design remains unresolved, so
loopback/private admin is the only documented operator-safe state.

## Response Framing

Rack apps and fake workers may provide framing headers such as `Content-Length`,
`Transfer-Encoding`, or `Connection`. Oxo does not trust those at the hop
boundary. It computes one `Content-Length`, strips `Transfer-Encoding`, and
forces `Connection: close`.

Repeated safe headers such as `Set-Cookie` must remain repeated. Collapsing them
would change application behavior.

## Action Cable And WebSockets

Rails Action Cable uses WebSockets and raw socket ownership. supports the
recommended standalone topology first: a separate Rails/Puma Cable runtime,
supervised by `oxo-pingora-service` when `OXO_CABLE_ENABLED=1`, with a
loopback-only `OXO_CABLE_BIND` and cable-specific cleared environment.

This is separate from Rack request/response. S1 still does not expose
`rack.hijack`. adds the public Pingora route for the standalone topology
only: validated H1 `GET /cable` WebSocket upgrades with the Action Cable
subprotocol and FQDN-tied Origin route to the loopback Cable sidecar without
acquiring the Rack worker UDS. The local redis-fixture adapter can fan out
across two Cable runtimes for tests. Generic WebSocket proxying, external Redis
deployment, in-app Action Cable, slow-client limits, and zero-drop WebSocket
drain remain later protocol work.
## SSE And Streaming Rack Bodies

 adds an opt-in Rack body streaming substrate: callable/enumerable Rack
responses can flush chunks through the worker UDS and Pingora edge before the
response completes. Request bodies are still buffered.

 adds loopback Server-Sent Events / Rails `ActionController::Live` support on
top of that substrate. `OXO_EDGE_SSE=1` admits event-stream request headers,
and `OXO_WORKER_STREAMING=1` lets Rails live responses flush incrementally.
 proves the same path in public smoke-beta with long-lived accounting,
memory-envelope cancellation, downstream disconnect cancellation, and real Rails
TLS first-event flush evidence. Request-body streaming, zero-drop long-lived
drain, production slow-client fairness, and per-identity public long-lived
accounting remain later protocol work.

## gRPC

gRPC is adjacent to the edge/runtime problem but not Rack-native. Ruby gRPC uses
`GRPC::RpcServer` and HTTP/2 ports. The protocol uses HTTP/2 pseudo-headers,
DATA frames, `te: trailers`, and response trailers.

 supervises a separate standalone loopback gRPC runtime child with a clean env,
readiness probe, monitor ownership, and process-group drain cleanup. proves a
Rails-owned gruf unary service can run in that child and answer a real gRPC
client call with metadata. routes public smoke-beta native unary gRPC over
TLS/H2 to that standalone loopback gruf sidecar without acquiring the Rack
worker UDS. The public unary path validates `application/grpc`, `te: trailers`,
authority/Host, body caps, and configured sidecar bind before proxying; it
preserves status/trailer behavior and deadline/cancellation semantics through
the gRPC client/server path. uses the same sidecar route for public
smoke-beta server-streaming, client-streaming, and bidi gRPC calls under the
aggregate long-lived admission/accounting substrate.

Oxo still does not make gRPC Rack-native, support gRPC-Web, or claim
production gRPC. Rails/Rack support does not imply gRPC hosting.

## Prefork And Process Supervision

Puma gets parallelism from processes times threads. accepts a different
Oxo-owned model: spawn-supervised `oxo-worker` processes, each with its
own private UDS, coordinated by `oxo-pingora-service` and reached only after
the edge has validated and buffered the request. `OXO_WORKER_COUNT` controls
the process count; Rack `rack.multiprocess` is false for one worker and true for
more than one worker.

The attempted raw prefork path after Ruby preload is fenced as a NO-GO because
it did not satisfy the CRuby/Magnus fork safety gate. does not claim
CRuby-sanctioned prefork, copy-on-write preload savings, Puma cluster or
phased-restart parity, sticky sessions, zero-drop drain, worker recycle, or
cross-host clustering.

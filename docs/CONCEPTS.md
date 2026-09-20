# Oxo Concepts

These terms describe the current request path. See [architecture](ARCHITECTURE.md)
for component ownership and [the threat model](THREAT_MODEL.md) for limits.

## Rack and the request environment

A Rack application returns a status, headers and body:

```ruby
status, headers, body = app.call(env)
```

Oxo constructs env, supplies binary rewindable rack.input, calls the app, handles
response framing and closes the response body when supported. Request bodies are
buffered in memory within configured caps. The native worker can stream responses
when enabled; the async worker buffers them.

Rack identity fields include REQUEST_METHOD, PATH_INFO, QUERY_STRING,
SERVER_NAME, SERVER_PORT, SERVER_PROTOCOL, REMOTE_ADDR and rack.url_scheme.
Content-Type and Content-Length become CONTENT_TYPE and CONTENT_LENGTH;
other permitted app headers become HTTP_* entries. Trusted edge metadata sets
identity fields separately from client-controlled headers.

## Native and async workers

The native worker embeds Ruby through Magnus. Requests cross Rust queues as
owned strings and bytes, never Ruby VALUEs. Ruby initializes on the main thread;
worker threads wait outside the GVL when no job is available. The GVL prevents
parallel Ruby bytecode execution within one process, but blocking I/O can overlap.

The async worker uses one fiber per connection on a Ruby async reactor.
Scheduler-aware waits let other fibers progress. Rails must use fiber isolation
for request-local state. Multiple worker processes provide separate Ruby VMs;
OXO_WORKER_COUNT controls that process count and rack.multiprocess reflects it.

The in-process oxo-embedded handler differs from a supervised worker: Ruby native
faults share the edge's process and can terminate it. Ruby exception handling does
not contain native faults. Linux is the Ruby runtime target; Windows default
builds are Ruby-free stubs.

## Owned buffered worker hop

The Pingora request_filter owns the Rack exchange. It validates headers, admits
the request, sanitizes identity and buffers the complete bounded body before
acquiring a worker connection. It then writes the worker protocol itself and
returns Ok(true), bypassing Pingora's ordinary upstream proxy loop.

This gives the per-request boundary:

```text
invalid or incomplete Rack request -> no worker connection acquisition or dispatch
```

Existing idle pool connections are independent of an individual request.
Static hits and sidecar routes have their own response paths under admission.

## Binary frames and one-shot HTTP

The default binary frame hop carries already-parsed request fields over pooled
Unix sockets. A six-byte prefix identifies the protocol version and envelope
length. Nested lengths must fit exactly. Each connection carries sequential
exchanges with one in-flight request, and only a clean response boundary is reusable.

The optional HTTP hop reconstructs a narrow HTTP/1.1 request and closes the
connection after one exchange. The native worker supports both forms; the async
worker supports frames. Downstream HTTP keepalive is a separate setting from
worker connection pooling.

## Trusted identity and admission

Direct-public identity comes from the client socket. Trusted-proxy mode requires
explicit CIDRs and validates the immediate peer and canonical X-Forwarded-For.
Forwarding headers and reserved x-oxo-* client fields are removed before Rack
environment construction. The edge generates its own request ID.

Admission guards bound concurrent requests. Global and per-identity limits are
distinct from a request-rate limiter. Guards stay alive until the operation they
account for ends, including sidecar connections that outlive request_filter.
Aggregate health and counters use a separate loopback admin listener.

## Dispatch and supervision

The service owns worker startup, readiness, restart and shutdown. Each worker
has a private socket and a cleared, allowlisted environment. Least-outstanding
dispatch is the default. Optional per-worker admission parks excess requests at
the edge and chooses again when a worker becomes available.

A failed connect can try another worker before execution. Retry after writing
request bytes requires the worker-specific frame policy. Async workers never
replay a delivered request after zero-response-byte EOF, because execution may
already have happened. Connection-affinity mode refers to eligible HTTP/1
connections, not application sessions across hosts or restarts.

Shutdown uses bounded process-group TERM/KILL cleanup. Workers are spawned rather
than forked after Ruby preload. Cleanup does not promise zero-drop drain or
phased restarts.

## Streaming and sidecars

Native worker streaming sends Rack body chunks through a bounded queue. With
OXO_EDGE_SSE=1 and OXO_WORKER_STREAMING=1, Rails ActionController::Live can flush
events through that path. Request bodies remain buffered.

Action Cable uses a standalone loopback runtime reached by validated /cable
WebSocket upgrades. gRPC uses a separate HTTP/2 sidecar for unary and streaming
calls. These connections bypass Rack and retain long-lived admission guards.
Generic WebSockets, Rack hijack and gRPC-Web are unsupported.

Response framing belongs to the server: compute buffered Content-Length, apply
the downstream keepalive policy and preserve repeated Set-Cookie values.
After partial output, failure can require closing the connection instead of
sending a replacement error response.

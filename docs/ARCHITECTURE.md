# Oxo Architecture

This document explains Oxo's topology, request paths, failure paths, and why
the pieces are shaped this way.

## Product Goal

Oxo's target shape is:

```text
internet client
 -> Pingora front edge
 -> Oxo-owned Rack worker runtime
 -> Rails/Rack application
```

The goal is to replace the usual
`nginx -> Puma -> Rails` deployment with a
single Oxo-owned serving stack: Pingora owns the public edge, while Oxo's
worker owns Rack/Rails execution. This should eventually give Rails apps a
secure internet-facing path without depending on nginx or Puma.

That goal is now a production-candidate RC only for the constrained tested
matrix; it is not a blanket production or speed-superiority claim. The current
implementation has:

* a shipped Linux S1 Magnus worker that can run Rack apps over a private UDS;
* a Linux direct-S1 Rails fixture smoke that runs in CI by default;
* a Linux Pingora fake-upstream edge conformance gate through;
* a Linux Pingora -> real S1 worker -> Rack/Rails E2E gate through;
* a Linux loopback service runner through with a spawn-supervised worker pool, ready-worker scheduling, respawn/backoff, process-group shutdown, and systemd-style notification;
* a public-edge security preflight that keeps public bind denied while hardening request IDs, H1 rejects, request-header caps, and CL0 compatibility;
* loopback TLS/H1+H2 support behind `tls-rustls`, with listener-derived Rack scheme and H2 authority-to-Host worker-hop canonicalization;
* public bind alpha behind explicit Pingora alpha mode, TLS, direct-public identity, body cap, and server-name gates;
* public edge smoke-beta behind explicit smoke-beta mode, private loopback admin health, minimal telemetry, and Rails TLS/H1+H2 smoke evidence;
* hostile public H2/TLS abuse floor with public Host/authority enforcement and H2 reject-before-worker cases;
* / controlled ACME HTTP-01 issuance plus certificate lifecycle state, with no worker acquisition from challenge handling and no production/hot-reload claim;
* one-FQDN public Rails correctness: public FQDN/certificate SAN validation plus verified TLS/SNI, strict-host Rails production-environment settings, HTTPS Rack metadata, secure cookies/session, CSRF, redirects, and URL generation;
* public HTTP/H2 hardening floor: raw TLS/H2 abuse rejects before worker acquisition, CL0 residue no-second-worker proof, and owned-path wait timeouts;
* trusted-proxy identity: explicit trusted CIDRs, immediate-peer trust, canonical `X-Forwarded-For`, direct-public spoof stripping, and Rails `RemoteIp` proof;
* per-identity fairness/private observability: concurrent admission caps keyed by resolved public identity, `503` saturation before worker acquisition, private aggregate `/ready` fairness counters, and private aggregate `/metrics`;
* DB/Redis pressure fixture: Rails-side bounded pressure pools, controlled Redis-like outage/recovery, and standalone Action Cable `oxo_redis_fixture` evidence;
* long-lived response substrate: aggregate admission, per-response byte envelope, downstream write timeout, and private counters for existing chunked worker responses;
* public Action Cable route: validated H1 `/cable` WebSocket upgrades route to standalone loopback Cable without touching the Rack worker UDS, with local redis-fixture fanout across two Cable runtimes;
* public SSE/Rails live: public smoke-beta `OXO_EDGE_SSE=1` routes event-stream requests through the owned worker hop with long-lived accounting, memory-envelope cancellation, downstream disconnect cancellation, and real Rails TLS first-event flush evidence;
* bounded Unix lifecycle/drain contract with configurable drain grace, edge-first TERM, process-group KILL escalation, and no-orphan evidence;
* standalone Action Cable process support: optional loopback Cable child, cable-specific cleared env, process-group drain cleanup, and Rails WebSocket fixture proof;
* loopback SSE/Rails live support: opt-in event-stream admission and Rails `ActionController::Live` incremental flush proof;
* supervised standalone gRPC runtime substrate: optional loopback gRPC child, clean env, readiness probe, monitor ownership, and process-group drain cleanup;
* Rails/gruf unary gRPC fixture: the service runner supervises a Rails-owned gruf child and a real gRPC client verifies unary request/metadata/response behavior;
* public native streaming gRPC: server-streaming, client-streaming, and bidi calls route to the standalone loopback gruf sidecar under aggregate long-lived admission/accounting;
* reload/recycle/socket-activation decision: explicit direct binds and high-port external mapping are the shipped model, `LISTEN_*` socket-activation env markers fail closed, and the accepted reload shape is bounded restart only;
* cluster model verdict: spawn-supervised `oxo-worker` processes are the accepted concurrency model; raw fork-after-Ruby-preload, CRuby-prefork, copy-on-write preload, and Puma cluster parity remain non-claims;
* Windows Magnus verdict: native Windows Ruby/Magnus runtime support is rejected; Windows remains a Ruby-free default workspace/stub build surface;
* public-production audit: production mode remains unavailable after audit,
 and `smoke-beta` stays the highest public exposure claim;
* deep document reconciliation: live docs and Oxo-owned comments are
 reconciled after without changing runtime behavior or expanding claims;
* migration and production re-audit: bounded migration docs exist, production
 mode remains unavailable, and Linux metal soak/capacity evidence is the only
 intended remaining gate before a later narrow production-mode review;
* private operator hardening: admin `/ready` schema, generated-id outcome logs, and redacted service-runner env summaries;
* benchmark/stress and RC closeout: a functional burst smoke, benchmark report, and production-candidate audit for the tested matrix only;
* a Linux legacy embedded runtime smoke for the old `oxo`/`oxo-embedded` path;
* older - hyper/Puma code kept as shipped history and reference material.

## Operator Topology

```text
smoke-beta Rails HTTP request/response rehearsal

client
 -> Pingora edge (smoke-beta TLS/H1+H2, direct-public or configured trusted-proxy identity, private admin health)
 -> Oxo-owned buffered UDS worker hop
 -> spawn-supervised S1 Rack worker pool
 -> Rails/Rack app
```

Standalone Action Cable and standalone gruf/gRPC are separate loopback sidecar
children supervised beside the Rack worker pool. SSE/Rails live uses the opt-in
Rack response streaming substrate; proves that path for public smoke-beta
SSE, while / prove public smoke-beta native gRPC only to the standalone
loopback gruf sidecar.

## Why The Edge Owns The Buffered Hop

Pingora's default `ProxyHttp` path is good for normal proxying, but showed it
connects to the upstream and forwards headers before the downstream body is fully
proven. That violated Oxo's worker-hop rule: malformed or incomplete bodies
must not create any worker-side request.

 therefore makes `request_filter` the owner of the Rack request/response hop:

1. Pingora parses the downstream request.
2. Oxo validates origin-form target and hostile headers.
3. Oxo checks `Content-Length` against `OXO_EDGE_MAX_BODY`.
4. Oxo buffers exactly the declared body.
5. Only then does Oxo open the fixed configured UDS.
6. Oxo writes one canonical HTTP/1.1 request upstream.
7. Oxo parses one bounded worker response and writes it downstream.
8. `request_filter` returns `Ok(true)`, so the default upstream proxy loop is not used.

The `upstream_peer` implementation remains as a defensive fallback required by
the Pingora trait, not as the normal data path.

## Normal Request Flow Today

### GET Through Pingora Fake Worker

```text
client GET /hello
 -> Pingora accepts loopback TCP
 -> request_filter collects headers
 -> strips Forwarded / X-Forwarded-* / X-Real-IP / X-Oxo-* / hop-by-hop
 -> adds edge-owned x-oxo-* metadata
 -> builds GET /hello HTTP/1.1 with Content-Length: 0 and Connection: close
 -> opens fake-worker UDS
 -> writes request and reads fake response
 -> canonicalizes response framing
 -> returns response to client
```

### POST Through Pingora Fake Worker

```text
client POST /submit with Content-Length: N
 -> request_filter validates headers and N <= OXO_EDGE_MAX_BODY
 -> reads exactly N bytes from downstream body API with an explicit timeout
 -> rejects if downstream ends early or sends more than N through the parsed body stream
 -> opens fake-worker UDS only after body is complete, with an explicit connect timeout
 -> writes one worker request with computed Content-Length: N and a bounded write
 -> reads one bounded response with an explicit worker read timeout
```

### Rack/Rails Flow

```text
client request
 -> Pingora owned buffered hop
 -> S1 worker UDS
 -> worker parser repeats strict worker-hop validation
 -> Rust acceptor dispatches to Ruby thread queue
 -> Ruby thread builds Rack env
 -> app.call(env)
 -> response body is fully materialized
 -> worker writes canonical HTTP/1.1 response and closes
 -> Pingora writes response to client
```

The duplicate validation is intentional. Pingora is the public edge, but the S1
worker is still a security boundary because it accepts bytes over a local socket.

## Rejection And Failure Paths

### Over-Cap Body

```text
Content-Length > OXO_EDGE_MAX_BODY
 -> Pingora edge returns 413
 -> no UDS connection is opened
```

The S1 worker also enforces its own `OXO_WORKER_MAX_BODY` before Rack is
called.

### Short Or Incomplete Body

```text
declared Content-Length: 5, downstream sends 2 bytes and ends
 -> request_filter sees early EOF / missing body bytes
 -> returns client error or closed connection
 -> no UDS connection is opened
```

This is the specific failure that fixes.

### Smuggling-Class Request

```text
TE, duplicate Content-Length, duplicate Host, trailers, obs-fold, whitespace
before colon, absolute-form target, invalid header bytes, ambiguous keep-alive or
connection-token headers, CONNECT, h2c, Upgrade, gRPC, SSE unless explicitly enabled, oversized request headers
 -> rejected by the Pingora edge before UDS acquisition
```

The worker has its own strict parser for the S1 direct path and for defense in
depth now that connects Pingora to S1 in the E2E harness.

### Missing Worker

```text
valid edge request
 -> body fully validated and buffered
 -> UnixStream::connect(configured_socket) fails
 -> edge returns 503
```

`503` means the configured worker is not ready/reachable, not that the app threw.

### Broken Worker Response

```text
worker accepts connection but resets, sends malformed status/header, or exceeds header cap
 -> edge returns 502
```

`502` means the upstream worker hop broke after the edge had a valid client
request.

### Rack App Exception

In the real S1 worker, Ruby exceptions are caught in the worker thread and become
`500 Internal Server Error`. A later request should still work if the worker
process remains healthy.

## Worker-Hop ABI

The S1 worker hop is deliberately narrow:

* HTTP/1.1 only.
* Origin-form targets only.
* Exactly one `Host`.
* `Content-Length` only; no `Transfer-Encoding`, trailers, `Expect`, or `Upgrade`.
* One request per UDS connection; the worker always closes.
* Body cap enforced before Rack is called.
* Spoofable `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, and reserved client
 `x-oxo-*` headers are stripped from Rack `HTTP_*`.
* Trusted internal metadata uses reserved `x-oxo-*` fields and becomes
 `REMOTE_ADDR`, scheme, server name, and server port.
* Response framing is canonicalized by default: app/worker `Content-Length`,
 `Transfer-Encoding`, and `Connection` are replaced with one computed
 `Content-Length` and `Connection: close`.
* adds an explicit streaming variant behind `OXO_WORKER_STREAMING=1`:
 Rack body chunks become chunked worker-hop bytes and the edge decodes them
 before writing downstream.

Pingora must preserve this ABI until a later protocol milestone explicitly
changes it.

## S1 Resource Policy

The accepted S1 worker model keeps buffered requests and now has two response
modes:

* request bodies are fully buffered in memory up to `OXO_WORKER_MAX_BODY`;
* `rack.input` is a rewindable Ruby `StringIO` over those body bytes;
* default Rack response bodies are fully materialized before the worker writes a
 fixed-length HTTP response;
* with `OXO_WORKER_STREAMING=1`, Rack callable/enumerable body chunks are
 streamed through a bounded worker event queue and chunked worker-hop response;
* no `rack.hijack`, request-body streaming, or memory-superiority claim is made;
* tempfile spill for large request bodies is deferred to a later
 body/resource/streaming milestone.

## Worker And Performance Model

S1 is one standalone Linux process that embeds Ruby through Magnus. It starts in
this order:

1. read env config;
2. initialize Ruby on the main thread;
3. load the Rack app;
4. start fixed Ruby worker threads;
5. bind the private UDS listener;
6. accept one-shot worker-hop requests.

Requests are parsed and body-capped in Rust, then queued to Ruby worker threads.
The queue wait happens without holding the Ruby GVL, so idle Ruby threads do not
freeze the VM while waiting for work. Ruby code itself still does not execute in
parallel inside one MRI process under the GVL. Threads matter for blocking IO:
Rails requests waiting on databases, caches, or external APIs can overlap, but
CPU-bound Ruby work remains serialized by MRI.

The current model is not a full Puma replacement yet because Puma commonly uses
both processes and threads. Oxo's process-level story is deferred: the raw
S2a `libc::fork` after embedded Ruby preload path is a NO-GO until CRuby-safe
fork plumbing or another cluster model is reviewed.

The one-shot UDS connection is a deliberate security/performance trade:

* simpler internal parser state;
* no pooled worker connection containing a hidden second request;
* clear `Connection: close` contract;
* extra connect/write/read work per request.

The benchmark report records a small functional burst stress result and a
future comparative method. It is not a speedup or production-superiority claim;
any claim against nginx+Puma or relevant alternatives still needs a separate
reviewed benchmark milestone.

## Deferred Protocol Paths

### WebSocket / Action Cable

 supports the standalone Action Cable topology as a separate Rails/Puma
runtime supervised beside the Rack worker pool. The Rails fixture proves
WebSocket upgrade with the Action Cable subprotocol, allowed-origin checks,
fixture cookie gating, subscription confirmation, and channel echo.

 adds the public Pingora route for that topology only. A validated H1
`GET /cable` Upgrade with the `actioncable--json` subprotocol, matching Host,
and FQDN-tied Origin can route to the loopback Cable sidecar. The route strips
spoofable public-boundary headers, preserves the Action Cable subprotocol and
ping/pong bytes, uses the aggregate long-lived admission cap, and does not
acquire the Rack worker UDS. The S1 worker still exposes no `rack.hijack`, and
generic WebSocket proxying remains unsupported. also proves local
redis-fixture fanout across two standalone Cable runtimes; adds a separate
dev-host container Redis pressure tier. Neither tier proves external-cloud Redis
deployment or capacity.

### SSE And Rails Live Streaming

 ships the shared Rack body streaming substrate for opt-in callable/enumerable
responses. adds loopback SSE/Rails live support: `OXO_EDGE_SSE=1`
allows event-stream request headers, and `OXO_WORKER_STREAMING=1` lets Rails
`ActionController::Live` flush events incrementally through the worker UDS and
Pingora edge. lifts that path into public smoke-beta for the tested matrix,
with long-lived accounting, memory-envelope cancellation, downstream disconnect
cancellation, and real Rails TLS first-event flush evidence. Zero-drop
long-lived drain, request-body streaming, and production slow-client fairness
remain future work.

### gRPC

The Rack worker path still rejects gRPC as unsupported. Ruby gRPC is not
Rack-native; it uses a `GRPC::RpcServer`, HTTP/2, pseudo-headers, DATA frames,
and trailers. adds supervision for one standalone loopback gRPC runtime child
beside the edge and workers. proves a Rails-owned gruf unary service can run
inside that child and answer a real gRPC client call.

 adds the public Pingora route for native unary gRPC to that standalone
sidecar only. Public smoke-beta TLS/H2 `application/grpc` requests with
`te: trailers` route to the loopback gruf child without acquiring the Rack
worker UDS. The route strips spoofable public-boundary headers, synthesizes
trusted Oxo metadata, preserves gRPC status/trailer behavior, propagates
deadlines/cancellation, and rejects invalid gRPC before the worker path.
extends that sidecar route to server-streaming, client-streaming, and bidi gRPC
under aggregate long-lived admission/accounting. Rack gRPC, gRPC-Web, production
gRPC and gRPC-specific external DB/Redis pressure remain separate future gates; they
are not implied by Rack support.

## Toolchain Policy

The Pingora line pins Rust/Cargo `1.96.0` exactly. This records a policy choice
made after Pingora 0.8.1 failed the old Rust 1.79 gate through transitive
edition-2024 dependencies. It is not a benchmark or production-readiness claim.

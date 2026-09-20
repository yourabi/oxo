# Correctness tests

The Linux integration suite runs real Rack/Rails applications through the native
worker, the async worker, the supervised Puma path, and the Pingora edge. Fixtures
live under `test/fixtures`; they contain synthetic data and generate temporary
secrets and TLS keys for each run.

## Run locally

Use Linux, Rust 1.98.1, Ruby 3.3 or a compatible newer Ruby, Bundler 4.0.13,
OpenSSL, and curl built with HTTP/2. The native worker needs Ruby development
headers and its shared library. The runner uses the existing toolchain; it does
not install system packages or change host configuration.

From the repository root:

```sh
BUNDLE_IGNORE_CONFIG=1 BUNDLE_FROZEN=1 BUNDLE_GEMFILE="$PWD/test/fixtures/rails_app/Gemfile" bundle install
BUNDLE_IGNORE_CONFIG=1 BUNDLE_FROZEN=1 BUNDLE_GEMFILE="$PWD/test/fixtures/rack_async/Gemfile" bundle install
ruby test/run.rb workspace
ruby test/run.rb conformance
ruby test/run.rb tls
```

The two Gemfile locks pin the complete dependency graphs. Rails' bundle includes
async for its real async-worker smoke test; the small Rack/async bundle keeps
protocol and supervisor checks independent of Rails boot. PostgreSQL and Redis
client gems are present in the Rails lock, but only the explicit external tier
starts database services.

`CARGO_TARGET_DIR` may select an isolated build directory. The runner builds
`oxo-worker` first and selects its exact absolute path; no test launches nested
Cargo or searches for another checkout's worker. If running individual Cargo
targets directly, prebuild the worker and set `OXO_TEST_WORKER_BIN` when needed.

The normal Cargo suite marks the Puma/Rails and direct-worker/Rails cases ignored
with a dependency reason. `test/run.rb workspace` explicitly runs both after the
workspace suite. The five external cases are also explicitly ignored until their
owned launcher selects them. Missing prerequisites in a selected tier fail the
run. An ignored test or a feature-gated zero-test target is not passing coverage.

## Coverage and configuration

| Test target | Coverage | Runner |
| --- | --- | --- |
| `puma_rails` | Real Rails requests through the supervised Puma path | `workspace` |
| `worker_e2e` | Rack environment, request/response framing, Rails middleware, streaming, simulated pool pressure and request rejection | `workspace`; `tls` also checks HTTPS, HTTP/2 and client identity |
| `service_async` | Worker startup, routing, socket permissions, crash recovery, shutdown, connection reuse, application errors and real Rails requests | `workspace` |
| `action_cable` | WebSocket handshake, channel echo, simulated fanout, edge routing and connection limits | `workspace` |
| `grpc_public` | Unary and streaming RPCs, status trailers, deadlines, request rejection and stream limits | `tls` |
| `worker_uds` | Native worker protocol and Rails requests | `workspace` |
| `service_runner` | Process supervision and the Rails/gruf sidecar | `workspace` |
| `fixture_harness` | Upstream observation, observer failure, bounded child output and redaction | `workspace` |
| `external_pressure` | Real PostgreSQL/Redis outages, pool exhaustion and recovery | External-services launcher below |

The `conformance` command runs 58 Ruby checks: 30 protocol, 14 lifecycle,
six worker configuration, three Rack environment parity, and five diagnostic
privacy and process-cleanup checks. The `tls` command runs 21 Rust tests:
nine gRPC tests and twelve worker/edge tests. Seven of the worker/edge tests
also run in `workspace`; the remaining tests require `tls-rustls`.

Rails development tests preserve request middleware and CSRF protection. The
request test checks both a valid token and rejection of a missing token. Production
TLS tests preserve forced HTTPS, strict hosts, secure cookies, sessions, redirects
and verified certificate/SNI behavior. Rails test mode is used only for cases that
do not claim CSRF rejection or production HTTPS behavior.

Two Cable cases use a **file-backed simulated message bus**, not Redis. The
default pool-pressure test likewise uses simulated connection pools. The
PostgreSQL/Redis tier below uses real services and is counted separately.

Streaming and pool tests wait for observable fixture progress. The streaming
fixture cannot produce its second chunk until the client receives the first;
pool saturation starts only after checkout is acknowledged. Negative upstream
observers record `accept`, remain armed through the request, and fail on observer
failure. A controlled connection test proves that they detect acquisition.

The drain-expiry test verifies an error frame and eventual exit after cooperative
application work finishes. It does **not** prove immediate application cancellation.
Likewise a gRPC client deadline proves the client's result and edge accounting,
not that arbitrary application work has stopped. External database partition
tests permit a bounded client timeout and verify recovery after reconnection.

## Real PostgreSQL and Redis

On an existing local Docker/Compose installation:

```sh
ruby test/fixtures/external_services/run.rb
```

This command creates a unique disposable Compose project, random test credentials,
a project-owned volume, and dynamically assigned loopback ports. It selects the
five external tests, which stop or pause only those services. Teardown unpauses
the project, removes containers and volumes, and checks for leftover containers.
The launcher accepts no developer database URL or arbitrary Compose project.
It requires the default local Docker socket and does not install a daemon/plugin.

`postgres:17.6-alpine` and `redis:7.4.5-alpine` are the selected image version tags.
These are correctness fixtures, with no public port or production data.

## CI and diagnostics

CI runs Windows cross-platform tests, embedded-Ruby smoke tests and supply-chain
checks. Linux runs the workspace plus the explicit Rails/Puma cases, all conformance
scripts, a separate TLS/gRPC job, and a separate owned external-services job.
Windows reports that the Linux-only integration targets are not selected.

Each runner command owns a Linux process session. Surviving descendants are
reported as a cleanup failure before the runner terminates them, including
children that create their own process groups.

The runner prints Cargo's passed/failed/ignored counts and a bounded,
redacted output tail. Ruby fixture children receive a minimal explicit environment
and synthetic home; ambient Ruby/Bundler settings and application secrets are not
inherited. Temporary logs, credentials and fixture state are not source artifacts.
The runner redacts generated secrets and local paths. Review output from commands
run outside it before sharing logs.

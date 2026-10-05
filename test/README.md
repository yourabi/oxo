# Correctness tests

The integration suite runs on Linux and macOS: real Rack/Rails applications through
the native worker, the async worker, the supervised Puma path, and the Pingora edge. Fixtures
live under `test/fixtures`; they contain synthetic data and generate temporary
secrets and TLS keys for each run.

## Run locally

Use Linux or macOS, Rust 1.98.1, Ruby 4.0 or newer, Bundler 4.0.13 (the lockfiles'
version; a newer Bundler switches to it), OpenSSL, and curl built with HTTP/2
(macOS's system curl qualifies). The native worker needs Ruby development headers
and its shared library (`RbConfig::CONFIG['ENABLE_SHARED']` is `yes` for mise,
rbenv and Homebrew rubies). The runner uses the existing toolchain; it does
not install system packages or change host configuration.

From the repository root:

```sh
BUNDLE_IGNORE_CONFIG=1 BUNDLE_FROZEN=1 BUNDLE_GEMFILE="$PWD/test/fixtures/rails_app/Gemfile" bundle install
BUNDLE_IGNORE_CONFIG=1 BUNDLE_FROZEN=1 BUNDLE_GEMFILE="$PWD/test/fixtures/rack_async/Gemfile" bundle install
ruby test/run.rb workspace
ruby test/run.rb conformance
ruby test/run.rb tls
```

The two Gemfile locks pin the complete dependency graphs for `x86_64-linux` and
`arm64-darwin`. Rails' bundle includes
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

## macOS notes

macOS runs the same Rust and Ruby code as Linux; the differences below are the
kernel's, and the suite accounts for them.

- Unix socket paths are limited to 104 bytes and the per-user `$TMPDIR` is about
  49 bytes long, so socket-bearing fixtures build their trees under `/tmp` (each
  still in its own 0700 directory). `OXO_WORKER_SOCKET` paths follow the same
  length discipline; the worker reports an over-long path at bind.
- A fresh shell or launchd job has a 256-descriptor soft limit. The edge boots with
  an `fd-budget` warning, not a refusal; `ulimit -n 4096` before running the suite
  matches the Linux defaults.
- The listen backlog is clamped to `kern.ipc.somaxconn` (128 by default), so accept
  bursts beyond it are retried by clients rather than queued.
- The strace-based `mechanism_counts` gates and the Docker-owned external-services
  tier stay Linux-only. `OXO_WORKER_SCHED=idle` needs util-linux `chrt` and is
  refused at boot on macOS; the async worker's procfs timing samples record as
  unavailable rather than failing.
- Static files: crenel resolves beneath the pinned docroot with `O_RESOLVE_BENEATH`
  (the macOS counterpart of `openat2`), and on case-folding APFS volumes a hit is
  served only when the on-disk name matches the request byte for byte, so
  `/Assets/App.js` misses exactly as it does on Linux. No case-sensitive volume is
  needed.

## CI and diagnostics

CI runs Windows cross-platform tests and supply-chain checks. Linux and macOS each
run the workspace plus the explicit Rails/Puma cases, all conformance scripts, the
embedded-Ruby smoke test and a separate TLS/gRPC job; the owned external-services
job is Linux only. Windows reports that the native integration targets are not
selected.

Each runner command owns a process session (a procfs census on Linux, `getsid`
on macOS). Surviving descendants are reported as a cleanup failure before the
runner terminates them, including children that create their own process groups.

The runner prints Cargo's passed/failed/ignored counts and a bounded,
redacted output tail. Ruby fixture children receive a minimal explicit environment
and synthetic home; ambient Ruby/Bundler settings and application secrets are not
inherited. Temporary logs, credentials and fixture state are not source artifacts.
The runner redacts generated secrets and local paths. Review output from commands
run outside it before sharing logs.

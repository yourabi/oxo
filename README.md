# Oxo

**The oxidized exoskeleton for Rack.** Oxo is a Rust + Ruby application server
that puts a hardened [Pingora](https://github.com/cloudflare/pingora) edge in
front of a Rust-owned Ruby worker runtime:

```text
internet client
 -> Pingora front edge        (TLS, HTTP/1.1 + HTTP/2, request hardening, admission)
 -> Oxo-owned Rack worker     (buffered UDS hop, Rack env construction)
 -> Rails / Rack application
```

The goal is to replace the usual `nginx -> Puma -> Rails` stack with a single
Oxo-owned serving path: Pingora owns the public edge, and Oxo owns Rack/Rails
execution — giving Rails apps a secure internet-facing path without a separate
nginx or Puma tier.

## Status

Oxo is **early / alpha**. It is a production-candidate RC only for a constrained,
tested matrix — not a blanket production-readiness or performance-superiority
claim. Public bind is gated behind explicit `alpha` and `smoke-beta` modes. Read
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before exposing anything to the
internet.

## Workspace

| Crate | Purpose |
|-------|---------|
| `oxo-core` | Configuration, validation, shared types. |
| `oxo-edge` | Supervised worker runtime (Puma or a dependency-light stdlib shim). |
| `oxo-pingora-edge` | The Pingora-based public edge, worker hop, admission, ACME. |
| `oxo-worker` | The Linux Rack worker (request parsing, UDS serving). |
| `oxo-embedded` | Embedded-Ruby integration via [Magnus](https://github.com/matsadler/magnus) / rb-sys. |
| `oxo` | The `oxo` binary. |

The Ruby worker sources live in [`ruby/`](ruby/); a runnable example is in
[`examples/oxo-demos`](examples/oxo-demos).

## Build

```sh
cargo build --workspace
cargo test  --workspace
```

The edge and worker crates target Linux. The embedded-Ruby crate needs a working
Ruby toolchain (rb-sys / Magnus). See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
and [`docs/CONCEPTS.md`](docs/CONCEPTS.md) for topology, request/failure paths,
and the vocabulary used across the code.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in the work by
you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.

//! # oxo-embedded — the in-process Ruby handler (Magnus)
//!
//! **Blast-radius warning.** Unlike the supervised handler (a separate process), the
//! embedded handler links `libruby` and runs C-extension gems *in the edge's own
//! process*. A memory fault, `rb_bug`, native-gem segfault, or C-stack overflow on
//! the Ruby side is therefore **fatal to the edge** — it shares fate. Catching Ruby
//! *exceptions* at the Magnus boundary does **not** protect against C-level faults.
//! Use embedded only in trusted/single-tenant contexts; supervised is the default for
//! internet-facing deployment. (See `docs/ARCHITECTURE.md`.)
//!
//! **The init ceremony.** Ruby's VM must be initialized on the process **main thread,
//! at the top of the stack**, before any other thread or runtime exists
//! (`ruby_init`/`RUBY_INIT_STACK` records the stack bottom the GC scans). The Magnus
//! `Ruby` handle is also `!Send + !Sync`. Both facts are why `run_embedded_server`
//! takes over `main`: it inits Ruby on the main thread, moves
//! the tokio runtime + edge onto a *separate* thread, and runs the Ruby request loop
//! here — the edge reaches Ruby only by sending owned data over a channel.
//!
//! All of the above lives behind the `ruby` Cargo feature; the default build of this
//! crate links no Ruby and is essentially empty. adds a Linux runtime smoke for
//! this legacy embedded handler, but that test is not evidence for the standalone
//! `oxo-worker` S1 contract.

#[cfg(feature = "ruby")]
mod imp;

#[cfg(feature = "ruby")]
pub use imp::{run_embedded_server, EmbeddedRubyHandler};

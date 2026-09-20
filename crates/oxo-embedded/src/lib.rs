//! In-process Ruby handler using Magnus.
//!
//! Ruby and C extensions share the edge process: native faults are fatal to the
//! edge even when Ruby exceptions are caught. A supervised worker provides a
//! separate process boundary.
//!
//! Initialize Ruby on the main thread at the top of the stack, before starting
//! other threads. Ruby's GC needs that stack boundary and the Magnus handle is
//! neither Send nor Sync. The Tokio edge runs on another thread and sends owned
//! request data to the main-thread Ruby loop.
//!
//! The `ruby` feature enables this implementation. The default build links no
//! Ruby. Its tests cover this handler separately from the standalone worker.

#[cfg(feature = "ruby")]
mod imp;

#[cfg(feature = "ruby")]
pub use imp::{run_embedded_server, EmbeddedRubyHandler};

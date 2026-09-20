//! Oxo — "Puma in Rust".
//!
//! Resolves [`Config`] (with parse-time guards), then runs the configured handler:
//! * **supervised** (default): build a tokio runtime, spawn + supervise a Ruby
//! worker, and serve.
//! * **embedded**: delegate to `oxo_embedded::run_embedded_server`, which *must*
//! own `main` — it initializes the Ruby VM on this (main) thread at the top of the
//! stack and moves the runtime onto a separate thread (see that crate's docs).

use std::process::ExitCode;
use std::sync::Arc;

use oxo_core::{Config, HandlerKind};
use oxo_edge::{serve, SupervisedRubyHandler};

fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("oxo: configuration error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match config.handler {
        HandlerKind::Supervised => run_supervised(config),
        HandlerKind::Embedded => run_embedded(config),
    }
}

fn run_supervised(config: Config) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("oxo: building runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async move {
        let handler = match SupervisedRubyHandler::spawn(&config).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("oxo: failed to start the Ruby worker: {e}");
                return ExitCode::FAILURE;
            }
        };
        match serve(Arc::new(config), Arc::new(handler)).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("oxo: serve error: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

#[cfg(feature = "embedded")]
fn run_embedded(config: Config) -> ExitCode {
    // Delegated so the Ruby VM is initialized on the main thread, at the top of the
    // stack, before any runtime exists.
    oxo_embedded::run_embedded_server(config)
}

#[cfg(not(feature = "embedded"))]
fn run_embedded(_config: Config) -> ExitCode {
    eprintln!(
        "oxo: this binary was built without embedded support. Rebuild with \
         `--features embedded`, or set OXO_HANDLER=supervised."
    );
    ExitCode::FAILURE
}

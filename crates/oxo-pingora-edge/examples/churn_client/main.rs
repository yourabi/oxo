//! churn driver: timed TLS connection-churn load with VERIFIED resumption counts.
//! See `churn.rs` for the driver itself and its usage.
//!
//! This target is a directory example (`examples/churn_client/main.rs`) rather than a
//! single file so the Linux-only body can live in a `#[cfg]`-gated module: the driver
//! needs the `rustls023` dev-dependency, which is target-gated with the rest of the
//! Linux-only edge, but Cargo builds every example on every host under `--all-targets`.

#[cfg(target_os = "linux")]
mod churn;

fn main() {
    #[cfg(target_os = "linux")]
    churn::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("churn_client is Linux-only: it drives the Linux-only Pingora edge.");
        std::process::exit(1);
    }
}

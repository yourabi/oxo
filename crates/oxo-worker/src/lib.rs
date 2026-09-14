#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{main_entry, run_from_env, Config};

#[cfg(not(target_os = "linux"))]
pub fn main_entry() -> std::process::ExitCode {
    eprintln!("oxo-worker: the standalone Magnus UDS worker is Linux-only in S1");
    std::process::ExitCode::FAILURE
}

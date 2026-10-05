#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use native::{main_entry, run_from_env, Config};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn main_entry() -> std::process::ExitCode {
    eprintln!("oxo-worker: the standalone Magnus UDS worker requires Linux or macOS");
    std::process::ExitCode::FAILURE
}

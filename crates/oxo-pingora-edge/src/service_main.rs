fn main() -> std::process::ExitCode {
    match oxo_pingora_edge::service::run_from_args(std::env::args_os()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("oxo-pingora-service: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

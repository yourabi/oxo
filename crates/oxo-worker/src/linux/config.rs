use super::*;

#[derive(Debug, Clone)]
pub struct Config {
    pub app: PathBuf,
    pub socket: PathBuf,
    pub threads: usize,
    pub max_body_bytes: usize,
    pub rack_lint: bool,
    pub multiprocess: bool,
    pub streaming: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let app = env_path("OXO_WORKER_APP")?;
        let socket = env_path("OXO_WORKER_SOCKET")?;
        let threads = env_usize("OXO_WORKER_THREADS", 1)?;
        if threads == 0 {
            return Err("OXO_WORKER_THREADS must be >= 1".to_string());
        }
        let max_body_bytes = env_usize("OXO_WORKER_MAX_BODY", DEFAULT_MAX_BODY_BYTES)?;
        let rack_lint = env_bool("OXO_WORKER_RACK_LINT", false)?;
        let multiprocess = env_bool("OXO_WORKER_MULTIPROCESS", false)?;
        let streaming = env_bool("OXO_WORKER_STREAMING", false)?;
        Ok(Self {
            app,
            socket,
            threads,
            max_body_bytes,
            rack_lint,
            multiprocess,
            streaming,
        })
    }
}

fn env_path(name: &str) -> Result<PathBuf, String> {
    std::env::var_os(name)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} is required"))
}

fn env_usize(name: &str, default: usize) -> Result<usize, String> {
    match std::env::var(name) {
        Ok(s) if !s.trim().is_empty() => s
            .trim()
            .parse::<usize>()
            .map_err(|_| format!("{name} must be an unsigned integer")),
        _ => Ok(default),
    }
}

fn env_bool(name: &str, default: bool) -> Result<bool, String> {
    match std::env::var(name) {
        Ok(s) if !s.trim().is_empty() => match s.trim() {
            "1" | "true" | "TRUE" | "yes" | "YES" => Ok(true),
            "0" | "false" | "FALSE" | "no" | "NO" => Ok(false),
            _ => Err(format!("{name} must be 0/1 or true/false")),
        },
        _ => Ok(default),
    }
}

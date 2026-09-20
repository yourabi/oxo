//! Isolated Ruby commands, generated test secrets and bounded diagnostics.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

pub fn test_secret() -> &'static str {
    static SECRET: OnceLock<String> = OnceLock::new();
    SECRET.get_or_init(|| {
        let mut bytes = [0u8; 64];
        File::open("/dev/urandom")
            .expect("test entropy")
            .read_exact(&mut bytes)
            .expect("read test entropy");
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    })
}

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

pub fn command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    clean_environment(&mut command);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
}

pub fn clean_environment(command: &mut Command) {
    // This directory contains no settings or credentials. Each suite's fixtures
    // own mutable data separately; Bundler must not discover a user's config.
    let home = std::env::var_os("OXO_TEST_HOME_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("oxo-test-home-{}", std::process::id()));
    fs::create_dir_all(&home).expect("create synthetic home");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))
            .expect("protect synthetic home");
    }
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("BUNDLE_IGNORE_CONFIG", "1")
        .env("BUNDLE_APP_CONFIG", home.join("bundle"))
        .env("BUNDLE_USER_HOME", home.join("bundle-user"))
        .env("SECRET_KEY_BASE", test_secret())
        .env("LANG", "C.UTF-8");
}

pub fn worker_binary() -> PathBuf {
    let path = std::env::var_os("OXO_TEST_WORKER_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // Integration executables live in <target>/<profile>/deps. The runner
            // prebuilds the worker in the same profile; never invoke nested Cargo.
            let executable = std::env::current_exe().expect("current integration executable");
            executable
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("oxo-worker")
        });
    assert!(
        path.is_absolute() && path.is_file(),
        "prebuild oxo-worker or set OXO_TEST_WORKER_BIN to its absolute path"
    );
    path
}

pub fn diagnostic(bytes: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(&bytes[..bytes.len().min(64 * 1024)]).into_owned();
    for (value, label) in [
        (workspace_root().into_os_string(), "<workspace>"),
        (std::env::var_os("HOME").unwrap_or_default(), "<home>"),
        (
            std::env::var_os("USERPROFILE").unwrap_or_default(),
            "<home>",
        ),
    ] {
        let value = value.to_string_lossy();
        if !value.is_empty() {
            text = text.replace(value.as_ref(), label);
        }
    }
    text.replace(test_secret(), "<test-secret>")
}

pub fn wait_for_file(path: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !path.is_file() {
        assert!(
            std::time::Instant::now() < deadline,
            "fixture did not acknowledge entry"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

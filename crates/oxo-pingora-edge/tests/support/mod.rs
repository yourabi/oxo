// Shared leaf helpers for the edge integration suites — ONLY what a literal
// diff proved byte-identical across suites. Deliberately NOT shared:
// wait_for_tcp (per-fixture startup budgets differ: 5s edge-only vs 20s for
// slow Puma/gruf fixtures on constrained hosts), generate_tls_cert (per-suite CN/SAN is
// load-bearing in assertions), send_tcp (return types and read timeouts
// differ). Each test binary compiles this module independently and uses a
// subset, hence the dead_code allow.
#![allow(dead_code)]

use std::net::TcpListener;
use std::sync::{Mutex, MutexGuard};

pub static TEST_LOCK: Mutex<()> = Mutex::new(());

pub fn serial_test() -> MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

/// Base for fixture trees that will hold a Unix socket. macOS's per-user `$TMPDIR` is
/// about 49 bytes and `sockaddr_un` holds 104, so fixtures there live under `/tmp`;
/// each fixture still creates its own 0700 directory beneath the base.
pub fn socket_fixture_base() -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        std::path::PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    }
}

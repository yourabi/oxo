#![cfg(target_os = "linux")]
#[path = "support/acquisition.rs"]
mod acquisition;
#[path = "support/process.rs"]
mod process;
#[path = "../../../test/support/ruby.rs"]
mod ruby_fixture;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::process::Stdio;
use std::time::Duration;

#[test]
fn acquisition_witness_detects_accept_without_waiting_for_request_bytes() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let observer = acquisition::AcquisitionObserver::tcp(listener);
    assert!(observer.recv_timeout(Duration::from_millis(30)).is_err());
    let _held_open = TcpStream::connect(addr).unwrap();
    assert!(observer.recv_timeout(Duration::from_secs(1)).is_ok());
    // It remains armed after observing an event, with no fixed lifetime timeout.
    let _second = TcpStream::connect(addr).unwrap();
    assert!(observer.recv_timeout(Duration::from_secs(1)).is_ok());
}

#[test]
fn broken_negative_observer_cannot_be_reported_as_no_acquisition() {
    let observer = acquisition::AcquisitionObserver::observe(|| {
        Err(io::Error::other("synthetic observer failure"))
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        observer.recv_timeout(Duration::from_secs(1))
    }));
    assert!(result.is_err(), "observer failure must fail the test");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        observer.recv_timeout(Duration::from_secs(1))
    }));
    assert!(result.is_err(), "early disconnection must fail the test");
}

#[test]
fn chatty_failing_child_is_drained_and_retained_output_is_bounded() {
    let mut command = ruby_fixture::command("ruby");
    command
        .args([
            "-e",
            "$stdout.write('x' * 200000); $stderr.write('y' * 200000); exit 7",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = process::CapturedChild::new(command.spawn().unwrap());
    let (output, timed_out) = child.wait(Duration::from_secs(10));
    assert!(!timed_out);
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout.len(), 65536);
    assert_eq!(output.stderr.len(), 65536);
}

#[test]
fn fixture_failure_renderer_removes_generated_secret_and_workspace() {
    let output = format!(
        "{} {}",
        ruby_fixture::workspace_root().display(),
        ruby_fixture::test_secret()
    );
    let rendered = ruby_fixture::diagnostic(output.as_bytes());
    assert_eq!(rendered, "<workspace> <test-secret>");
}

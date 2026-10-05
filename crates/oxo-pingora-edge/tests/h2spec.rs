use std::env;
use std::process::Command;

#[test]
fn h2spec_manual_gate_runs_against_configured_smoke_beta_endpoint() {
    if env::var("OXO_TEST_H2SPEC").as_deref() != Ok("1") {
        eprintln!("skipping h2spec manual gate; set OXO_TEST_H2SPEC=1 to run");
        return;
    }

    let port = env::var("OXO_TEST_H2SPEC_PORT")
        .expect("OXO_TEST_H2SPEC_PORT must name the smoke-beta TLS listener port");
    let host = env::var("OXO_TEST_H2SPEC_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let output = Command::new("h2spec")
        .args(["-h", &host, "-p", &port, "-tls", "-k"])
        .output()
        .expect("h2spec must be installed on PATH for OXO_TEST_H2SPEC=1");

    eprintln!("h2spec status: {}", output.status);
    eprintln!(
        "h2spec stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    eprintln!(
        "h2spec stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "h2spec reported failures; triage every failure"
    );
}

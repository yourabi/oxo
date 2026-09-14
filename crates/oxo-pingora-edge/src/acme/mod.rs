use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::{EdgeCliConfig, EdgeError};

const HTTP01_PREFIX: &str = "/.well-known/acme-challenge/";
const LETS_ENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";
const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

mod challenge;
mod issue;
mod state;

// Facade: exactly the pre-split pub surface, re-exported unchanged.
pub use challenge::{Http01ChallengeServer, Http01ChallengeStore};
pub use issue::{
    issue_once_with_instant_acme, issue_once_with_issuer, renew_once_with_instant_acme,
    renew_once_with_issuer, AcmeIssueConfig, AcmeRenewalOutcome, AcmeRenewalPolicy,
    IssuedCertificate,
};
pub use state::{
    certificate_lifecycle_admin_json, consume_reload_marker, reload_marker_updated_at,
    rollback_to_retained_pair, CertificateLifecycleStatus,
};

// Internal prelude: submodules do `use super::*;` so the shared imports and
// consts plus each sibling's pub(super) items resolve as in the single file.
use self::challenge::*;
use self::issue::*;
use self::state::*;

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("invalid ACME configuration: {message}")]
    InvalidConfig { message: String },
    #[error("invalid ACME challenge: {message}")]
    InvalidChallenge { message: String },
    #[error("invalid ACME issuance: {message}")]
    InvalidIssuance { message: String },
    #[error("ACME challenge store lock was poisoned")]
    PoisonedChallengeStore,
    #[error("failed to bind ACME challenge listener {bind}: {detail}")]
    BindChallenge { bind: SocketAddr, detail: String },
    #[error("ACME IO while trying to {action}: {detail}")]
    Io {
        action: &'static str,
        detail: String,
    },
    #[error("ACME JSON while trying to {action}: {detail}")]
    Json {
        action: &'static str,
        detail: String,
    },
    #[cfg(feature = "acme")]
    #[error("instant-acme: {detail}")]
    InstantAcme { detail: String },
}

impl From<AcmeError> for EdgeError {
    fn from(err: AcmeError) -> Self {
        EdgeError::Acme {
            message: err.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("oxo-acme-{label}-{}-{nonce}", std::process::id()))
    }

    fn free_loopback_bind() -> SocketAddr {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap()
    }

    fn http_get(addr: SocketAddr, host: &str, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn http01_listener_serves_exact_host_and_token_only() {
        let store = Http01ChallengeStore::default();
        store
            .provision("abc_DEF-123", "abc_DEF-123.thumbprint")
            .unwrap();
        let server = Http01ChallengeServer::start(
            free_loopback_bind(),
            "app.example".to_string(),
            store.clone(),
        )
        .unwrap();

        let ok = http_get(
            server.local_addr(),
            "app.example",
            "/.well-known/acme-challenge/abc_DEF-123",
        );
        assert!(ok.contains("200 OK"), "{ok}");
        assert!(ok.ends_with("abc_DEF-123.thumbprint"), "{ok}");

        let wrong_host = http_get(
            server.local_addr(),
            "evil.example",
            "/.well-known/acme-challenge/abc_DEF-123",
        );
        assert!(wrong_host.contains("403 Forbidden"), "{wrong_host}");

        let traversal = http_get(
            server.local_addr(),
            "app.example",
            "/.well-known/acme-challenge/../abc_DEF-123",
        );
        assert!(traversal.contains("404 Not Found"), "{traversal}");
    }

    #[test]
    fn fake_issuer_persists_single_fqdn_certificate_without_worker_socket() {
        let state_dir = unique_dir("state");
        let config = AcmeIssueConfig {
            fqdn: "app.example".to_string(),
            http_bind: free_loopback_bind(),
            state_dir: state_dir.clone(),
            directory_url: "http://127.0.0.1/fake-directory".to_string(),
            contacts: vec!["mailto:ops@app.example".to_string()],
            terms_of_service_agreed: true,
        };

        let issued = issue_once_with_issuer(config, |store, addr, fqdn| {
            store
                .provision("fakeToken_123", "fakeToken_123.fakeThumb")
                .unwrap();
            let response = http_get(addr, fqdn, "/.well-known/acme-challenge/fakeToken_123");
            assert!(response.contains("200 OK"), "{response}");
            assert!(response.ends_with("fakeToken_123.fakeThumb"), "{response}");
            Ok(IssuedCertificate {
                fqdn: fqdn.to_string(),
                certificate_pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
                    .to_string(),
                private_key_pem: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n"
                    .to_string(),
                not_after_epoch_seconds: Some(10_000),
            })
        })
        .unwrap();

        assert_eq!(issued.fqdn, "app.example");
        assert!(fs::read_to_string(state_dir.join("cert.pem"))
            .unwrap()
            .contains("BEGIN CERTIFICATE"));
        assert!(fs::read_to_string(state_dir.join("key.pem"))
            .unwrap()
            .contains("BEGIN PRIVATE KEY"));
        assert!(fs::read_to_string(state_dir.join("last-issue.json"))
            .unwrap()
            .contains("managed certificate lifecycle"));
        fs::remove_dir_all(state_dir).unwrap();
    }

    fn renewal_config(state_dir: PathBuf) -> AcmeIssueConfig {
        AcmeIssueConfig {
            fqdn: "app.example".to_string(),
            http_bind: free_loopback_bind(),
            state_dir,
            directory_url: "http://127.0.0.1/fake-directory".to_string(),
            contacts: vec!["mailto:ops@app.example".to_string()],
            terms_of_service_agreed: true,
        }
    }

    fn short_policy() -> AcmeRenewalPolicy {
        AcmeRenewalPolicy {
            renew_before_seconds: 100,
            retry_base_seconds: 10,
            retry_max_seconds: 60,
            retry_jitter_seconds: 0,
            rate_limit_floor_seconds: 300,
        }
    }

    #[test]
    fn renewal_skips_until_window_and_reports_expiry_telemetry() {
        let state_dir = unique_dir("renewal-not-due");
        let config = renewal_config(state_dir.clone());
        let policy = short_policy();
        let first = renew_once_with_issuer(
            config.clone(),
            policy.clone(),
            1_000,
            |_store, _addr, fqdn| {
                Ok(IssuedCertificate {
                    fqdn: fqdn.to_string(),
                    certificate_pem:
                        "-----BEGIN CERTIFICATE-----\nfirst\n-----END CERTIFICATE-----\n"
                            .to_string(),
                    private_key_pem:
                        "-----BEGIN PRIVATE KEY-----\nfirst\n-----END PRIVATE KEY-----\n"
                            .to_string(),
                    not_after_epoch_seconds: Some(10_000),
                })
            },
        )
        .unwrap();
        assert!(matches!(first, AcmeRenewalOutcome::Renewed { .. }));

        let second = renew_once_with_issuer(config, policy, 1_100, |_store, _addr, _fqdn| {
            panic!("not-due renewal must not contact the issuer")
        })
        .unwrap();
        let AcmeRenewalOutcome::NotDue { status } = second else {
            panic!("expected not-due outcome: {second:?}");
        };
        assert!(status.cert_present);
        assert_eq!(status.not_after_epoch_seconds, Some(10_000));
        assert_eq!(status.seconds_until_expiry, Some(8_900));
        assert_eq!(status.next_renewal_epoch_seconds, Some(9_900));
        assert!(!status.renewal_due);
        fs::remove_dir_all(state_dir).unwrap();
    }

    #[test]
    fn renewal_retains_old_certificate_and_marks_bounded_restart_required() {
        let state_dir = unique_dir("renewal-retain");
        let config = renewal_config(state_dir.clone());
        let policy = short_policy();
        renew_once_with_issuer(
            config.clone(),
            policy.clone(),
            1_000,
            |_store, _addr, fqdn| {
                Ok(IssuedCertificate {
                    fqdn: fqdn.to_string(),
                    certificate_pem: "old-cert".to_string(),
                    private_key_pem: "old-key".to_string(),
                    not_after_epoch_seconds: Some(1_050),
                })
            },
        )
        .unwrap();
        let renewed = renew_once_with_issuer(config, policy, 1_001, |_store, _addr, fqdn| {
            Ok(IssuedCertificate {
                fqdn: fqdn.to_string(),
                certificate_pem: "new-cert".to_string(),
                private_key_pem: "new-key".to_string(),
                not_after_epoch_seconds: Some(2_000),
            })
        })
        .unwrap();
        assert!(matches!(renewed, AcmeRenewalOutcome::Renewed { .. }));
        assert_eq!(
            fs::read_to_string(state_dir.join("cert.pem")).unwrap(),
            "new-cert"
        );
        assert_eq!(
            fs::read_to_string(state_dir.join("key.pem")).unwrap(),
            "new-key"
        );
        assert_eq!(
            fs::read_to_string(state_dir.join("retained").join("1001-cert.pem")).unwrap(),
            "old-cert"
        );
        assert_eq!(
            fs::read_to_string(state_dir.join("retained").join("1001-key.pem")).unwrap(),
            "old-key"
        );
        let reload = fs::read_to_string(state_dir.join("reload-required.json")).unwrap();
        assert!(reload.contains("bounded-restart"), "{reload}");
        assert!(reload.contains("\"plaintext_fallback\": false"), "{reload}");
        fs::remove_dir_all(state_dir).unwrap();
    }

    #[test]
    fn renewal_failure_persists_rate_limit_backoff_without_plaintext_fallback() {
        let state_dir = unique_dir("renewal-failure");
        let config = renewal_config(state_dir.clone());
        let policy = short_policy();
        renew_once_with_issuer(
            config.clone(),
            policy.clone(),
            1_000,
            |_store, _addr, fqdn| {
                Ok(IssuedCertificate {
                    fqdn: fqdn.to_string(),
                    certificate_pem: "stable-cert".to_string(),
                    private_key_pem: "stable-key".to_string(),
                    not_after_epoch_seconds: Some(1_050),
                })
            },
        )
        .unwrap();
        let err = renew_once_with_issuer(
            config.clone(),
            policy.clone(),
            1_001,
            |_store, _addr, _fqdn| {
                Err(AcmeError::InvalidIssuance {
                    message: "429 rate limit from fake CA".to_string(),
                })
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("429"));
        assert_eq!(
            fs::read_to_string(state_dir.join("cert.pem")).unwrap(),
            "stable-cert"
        );
        let failure = fs::read_to_string(state_dir.join("last-failure.json")).unwrap();
        assert!(failure.contains("rate_limited"), "{failure}");
        assert!(
            failure.contains("\"next_attempt_epoch_seconds\": 1301"),
            "{failure}"
        );
        assert!(
            failure.contains("\"plaintext_fallback\": false"),
            "{failure}"
        );
        let deferred = renew_once_with_issuer(config, policy, 1_100, |_store, _addr, _fqdn| {
            panic!("backoff must prevent issuer contact")
        })
        .unwrap();
        let AcmeRenewalOutcome::Deferred { status } = deferred else {
            panic!("expected deferred outcome: {deferred:?}");
        };
        assert_eq!(status.last_error_kind.as_deref(), Some("rate_limited"));
        assert_eq!(status.backoff_until_epoch_seconds, Some(1_301));
        fs::remove_dir_all(state_dir).unwrap();
    }

    #[test]
    fn certificate_lifecycle_admin_json_reports_private_status() {
        let state_dir = unique_dir("admin-json");
        let config = renewal_config(state_dir.clone());
        let policy = short_policy();
        renew_once_with_issuer(config, policy, 1_000, |_store, _addr, fqdn| {
            Ok(IssuedCertificate {
                fqdn: fqdn.to_string(),
                certificate_pem: "admin-cert".to_string(),
                private_key_pem: "admin-key".to_string(),
                not_after_epoch_seconds: Some(2_000),
            })
        })
        .unwrap();
        let json = certificate_lifecycle_admin_json(&state_dir).unwrap();
        assert!(json.contains("\"cert_present\":true"), "{json}");
        assert!(
            json.contains("\"cert_not_after_epoch_seconds\":2000"),
            "{json}"
        );
        assert!(json.contains("\"cert_reload_required\":true"), "{json}");
        assert!(
            json.contains("\"cert_reload_strategy\":\"bounded-restart\""),
            "{json}"
        );
        assert!(json.contains("\"cert_plaintext_fallback\":false"), "{json}");
        fs::remove_dir_all(state_dir).unwrap();
    }
    #[test]
    fn rejects_wildcard_ip_unicode_and_production_directory() {
        for fqdn in [
            "*.example.com",
            "127.0.0.1",
            "t\u{e9}st.example",
            "localhost",
        ] {
            assert!(validate_single_ascii_fqdn(fqdn).is_err(), "{fqdn}");
        }
        assert!(validate_directory_url_policy(LETS_ENCRYPT_PRODUCTION_DIRECTORY, false).is_err());
        assert!(validate_directory_url_policy(
            "https://acme-v02.api.letsencrypt.org/directory/",
            false
        )
        .is_err());
        assert!(validate_directory_url_policy("http://127.0.0.1.evil/directory", false).is_err());
        assert!(validate_directory_url_policy("http://127.0.0.1:14000/directory", false).is_ok());
        assert!(validate_directory_url_policy("http://[::1]:14000/directory", false).is_ok());
        assert!(validate_directory_url_policy(LETS_ENCRYPT_STAGING_DIRECTORY, false).is_ok());
        // the production directory unlocks ONLY behind the explicit consent flag.
        assert!(validate_directory_url_policy(LETS_ENCRYPT_PRODUCTION_DIRECTORY, true).is_ok());
        assert!(validate_directory_url_policy(
            "https://acme-v02.api.letsencrypt.org/directory/",
            true
        )
        .is_ok());
        // Consent does not widen anything else.
        assert!(validate_directory_url_policy("http://127.0.0.1.evil/directory", true).is_err());
    }

    #[test]
    fn cert_key_pair_leaves_previous_pair_intact_when_key_staging_fails() {
        // D18: the certificate and key are both staged before either is renamed into place,
        // so a failure during staging cannot swap in a new cert while the old key remains.
        // Force key staging to fail (its parent directory does not exist) and assert the
        // existing cert.pem is untouched — a naive "write cert, then write key" would have
        // already committed the new cert and left it paired with the old key.
        let dir = unique_dir("acme-pair-atomic");
        fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("missing-dir").join("key.pem");
        fs::write(&cert, b"OLD-CERT").unwrap();

        let err = write_cert_key_pair(&cert, b"NEW-CERT", &key, b"NEW-KEY")
            .expect_err("staging the key into a missing directory must fail");
        assert!(matches!(err, AcmeError::Io { .. }), "{err:?}");

        // Staging failed before any rename, so the live certificate is still the old one.
        assert_eq!(fs::read(&cert).unwrap(), b"OLD-CERT");
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- Commit B: production-directory consent + account pinning ----

    fn acme_cli(extra: &[&str]) -> EdgeCliConfig {
        let mut flags: Vec<String> = [
            "--http-bind",
            "203.0.113.10:80",
            "--fqdn",
            "app.example",
            "--acme-state-path",
            "/tmp/oxo-acme-cli-test",
            "--acme-contact",
            "mailto:ops@app.example",
            "--acme-accept-terms",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        flags.extend(extra.iter().map(|s| s.to_string()));
        EdgeCliConfig::parse_flags(flags).expect("test flags parse")
    }

    #[test]
    fn edge_cli_rejects_production_directory_without_ack() {
        let cli = acme_cli(&["--acme-directory-url", LETS_ENCRYPT_PRODUCTION_DIRECTORY]);
        let err = AcmeIssueConfig::from_edge_cli(&cli).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("--acme-allow-production-directory"), "{text}");
    }

    #[test]
    fn edge_cli_accepts_production_directory_with_ack() {
        let cli = acme_cli(&[
            "--acme-directory-url",
            LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            "--acme-allow-production-directory",
        ]);
        let config = AcmeIssueConfig::from_edge_cli(&cli).expect("consented production config");
        assert_eq!(config.directory_url, LETS_ENCRYPT_PRODUCTION_DIRECTORY);
    }

    #[test]
    fn edge_cli_rejects_production_ack_without_production_directory() {
        // Explicit-but-inert fails closed: consent while pointing at staging is
        // a misconfiguration, not a no-op.
        let cli = acme_cli(&["--acme-allow-production-directory"]);
        let err = AcmeIssueConfig::from_edge_cli(&cli).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("not the production"), "{text}");
    }

    #[test]
    fn edge_cli_rejects_production_ack_on_loopback_http_bind() {
        let cli = acme_cli(&[
            "--acme-directory-url",
            LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            "--acme-allow-production-directory",
            "--http-bind",
            "127.0.0.1:80",
        ]);
        let err = AcmeIssueConfig::from_edge_cli(&cli).unwrap_err();
        assert!(err.to_string().contains("loopback"), "{err}");
    }

    #[test]
    fn account_directory_mismatch_fails_closed() {
        let dir = unique_dir("acme-account-pin");
        fs::create_dir_all(&dir).unwrap();
        let account = dir.join("account.json");
        fs::write(
            &account,
            format!("{{\"directory\": {LETS_ENCRYPT_STAGING_DIRECTORY:?}}}"),
        )
        .unwrap();
        // Same directory (modulo trailing slash) is fine.
        ensure_account_directory_matches(&account, &format!("{LETS_ENCRYPT_STAGING_DIRECTORY}/"))
            .expect("same directory accepted");
        // The staging->production flip with the same state dir must fail closed
        // BEFORE any issuer contact: the credentials pin the old directory.
        let err = ensure_account_directory_matches(&account, LETS_ENCRYPT_PRODUCTION_DIRECTORY)
            .unwrap_err();
        assert!(err.to_string().contains("fresh --acme-state-path"), "{err}");
        // An account file that does not record its directory is also rejected.
        fs::write(&account, "{}").unwrap();
        assert!(
            ensure_account_directory_matches(&account, LETS_ENCRYPT_STAGING_DIRECTORY).is_err()
        );
        // No account yet = a new account will be created against the configured
        // directory; nothing to check.
        fs::remove_file(&account).unwrap();
        ensure_account_directory_matches(&account, LETS_ENCRYPT_PRODUCTION_DIRECTORY)
            .expect("absent account is fine");
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- Commit D: supervisor reload marker + rollback surface ----

    #[test]
    fn reload_marker_round_trips_and_consumes() {
        let dir = unique_dir("acme-marker");
        // prepare() creates the state dir 0700; no marker yet.
        let state = AcmeStatePaths::prepare(&dir).unwrap();
        assert_eq!(reload_marker_updated_at(&dir).unwrap(), None);
        let (cert, key) = real_pair("app.example");
        state
            .persist(
                &IssuedCertificate {
                    fqdn: "app.example".to_string(),
                    certificate_pem: cert,
                    private_key_pem: key,
                    not_after_epoch_seconds: Some(9_000_000),
                },
                &AcmeRenewalPolicy::default(),
                1_000,
            )
            .unwrap();
        assert_eq!(reload_marker_updated_at(&dir).unwrap(), Some(1_000));
        consume_reload_marker(&dir).unwrap();
        assert_eq!(reload_marker_updated_at(&dir).unwrap(), None);
        // Idempotent: consuming an absent marker is fine.
        consume_reload_marker(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rollback_restores_retained_pair_and_makes_next_tick_due() {
        let dir = unique_dir("acme-rollback");
        let policy = AcmeRenewalPolicy::default();
        let state = AcmeStatePaths::prepare(&dir).unwrap();

        // First issuance = the OLD pair (long-lived; far-future renewal).
        let (old_cert, old_key) = real_pair("app.example");
        state
            .persist(
                &IssuedCertificate {
                    fqdn: "app.example".to_string(),
                    certificate_pem: old_cert.clone(),
                    private_key_pem: old_key.clone(),
                    not_after_epoch_seconds: Some(100_000_000),
                },
                &policy,
                1_000,
            )
            .unwrap();
        // Second issuance = the NEW pair; retains the OLD pair + its metadata.
        let (new_cert, new_key) = real_pair("app.example");
        state
            .persist(
                &IssuedCertificate {
                    fqdn: "app.example".to_string(),
                    certificate_pem: new_cert.clone(),
                    private_key_pem: new_key,
                    not_after_epoch_seconds: Some(200_000_000),
                },
                &policy,
                2_000,
            )
            .unwrap();
        assert!(fs::read_to_string(dir.join("cert.pem"))
            .unwrap()
            .contains(new_cert.lines().next().unwrap()));

        // Roll back: the new edge failed to boot on the new pair.
        rollback_to_retained_pair(&dir, 3_000, "edge failed to boot").unwrap();

        // cert.pem is the OLD pair again, committed as a matched pair.
        let restored = fs::read_to_string(dir.join("cert.pem")).unwrap();
        assert_eq!(restored, old_cert);
        validate_issued_pair(
            &restored,
            &fs::read_to_string(dir.join("key.pem")).unwrap(),
            "app.example",
        )
        .expect("rolled-back pair is matched");
        // reload-failure.json records the rollback.
        assert!(dir.join("reload-failure.json").exists());
        // status() must describe the OLD cert (not the discarded new one) AND
        // the recorded failure makes the next scheduler tick attempt promptly
        // rather than reporting NotDue for ~30 days.
        let status = state.status(4_000, &policy).unwrap();
        assert_eq!(status.not_after_epoch_seconds, Some(100_000_000));
        assert_eq!(
            status.last_error_kind.as_deref(),
            Some("reload-rolled-back")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- Commit A: issued-pair validation + marker-first persist + latch ----

    fn real_pair(fqdn: &str) -> (String, String) {
        let pair = rcgen::generate_simple_self_signed(vec![fqdn.to_string()])
            .expect("generate self-signed test pair");
        (pair.cert.pem(), pair.signing_key.serialize_pem())
    }

    #[test]
    fn issued_pair_validation_accepts_matching_pair() {
        let (cert, key) = real_pair("app.example");
        validate_issued_pair(&cert, &key, "app.example").expect("matching pair validates");
    }

    #[test]
    fn issued_pair_validation_rejects_unparseable_cert() {
        let (_, key) = real_pair("app.example");
        let err = validate_issued_pair("not a certificate", &key, "app.example").unwrap_err();
        assert!(
            err.to_string().contains("invalid issued certificate"),
            "{err}"
        );
    }

    #[test]
    fn issued_pair_validation_rejects_unparseable_key() {
        let (cert, _) = real_pair("app.example");
        let err = validate_issued_pair(
            &cert,
            "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n",
            "app.example",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("private key PEM did not parse"),
            "{err}"
        );
    }

    #[test]
    fn issued_pair_validation_rejects_san_mismatch() {
        let (cert, key) = real_pair("other.example");
        let err = validate_issued_pair(&cert, &key, "app.example").unwrap_err();
        assert!(err.to_string().contains("SAN does not cover"), "{err}");
    }

    #[test]
    fn issued_pair_validation_rejects_key_cert_mismatch() {
        let (cert, _) = real_pair("app.example");
        let (_, other_key) = real_pair("app.example");
        let err = validate_issued_pair(&cert, &other_key, "app.example").unwrap_err();
        assert!(err.to_string().contains("does not correspond"), "{err}");
    }

    #[test]
    fn persist_writes_reload_marker_before_pair_swap() {
        // Simulate a renewal child dying between marker-write and pair-swap by
        // making the pair swap fail (cert.pem exists as a DIRECTORY, so the
        // rename cannot commit). Marker-first ordering means the restart signal
        // survives; pair-first ordering would instead leave a swapped pair with
        // no marker and a NotDue status — a silent 30-day stall.
        let dir = unique_dir("acme-marker-first");
        let state = AcmeStatePaths::prepare(&dir).unwrap();
        fs::create_dir_all(dir.join("cert.pem")).unwrap();
        let issued = IssuedCertificate {
            fqdn: "app.example".to_string(),
            certificate_pem: "NEW-CERT".to_string(),
            private_key_pem: "NEW-KEY".to_string(),
            not_after_epoch_seconds: Some(10_000),
        };
        let err = state
            .persist(&issued, &AcmeRenewalPolicy::default(), 1_000)
            .expect_err("pair swap over a directory must fail");
        assert!(matches!(err, AcmeError::Io { .. }), "{err:?}");
        // The marker committed BEFORE the failed swap…
        let status = state.status(2_000, &AcmeRenewalPolicy::default()).unwrap();
        assert!(status.reload_required, "marker must exist: {status:?}");
        // …and issuance metadata did not, so the next cycle self-heals by re-issuing.
        assert!(!dir.join("last-issue.json").exists());
        assert!(status.renewal_due, "{status:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_certificate_failures_latch_after_three() {
        let dir = unique_dir("acme-invalid-latch");
        let config = |bind: SocketAddr| AcmeIssueConfig {
            fqdn: "app.example".to_string(),
            http_bind: bind,
            state_dir: dir.clone(),
            directory_url: "http://127.0.0.1/fake-directory".to_string(),
            contacts: vec![],
            terms_of_service_agreed: true,
        };
        let mut now = 1_000_000u64;
        for _ in 0..3 {
            let err = renew_once_with_issuer(
                config(free_loopback_bind()),
                AcmeRenewalPolicy::default(),
                now,
                |_, _, _| {
                    Err(AcmeError::InvalidIssuance {
                        message: "invalid issued certificate: test".to_string(),
                    })
                },
            )
            .expect_err("issuer failure propagates");
            assert!(
                err.to_string().contains("invalid issued certificate"),
                "{err}"
            );
            // Step far past the rate-limit floor + backoff so only the LATCH,
            // not residual backoff, can stop the next attempt.
            now += 1_000_000;
        }
        let outcome = renew_once_with_issuer(
            config(free_loopback_bind()),
            AcmeRenewalPolicy::default(),
            now,
            |_, _, _| -> Result<IssuedCertificate, AcmeError> {
                panic!("issuer must not be contacted after the invalid-certificate latch")
            },
        )
        .expect("latched renewal defers without issuer contact");
        assert!(matches!(outcome, AcmeRenewalOutcome::Deferred { .. }));
        // Operator remedy: clearing last-failure.json unlatches the scheduler.
        fs::remove_file(dir.join("last-failure.json")).unwrap();
        let outcome = renew_once_with_issuer(
            config(free_loopback_bind()),
            AcmeRenewalPolicy::default(),
            now + 1_000_000,
            |_, _, fqdn| {
                Ok(IssuedCertificate {
                    fqdn: fqdn.to_string(),
                    certificate_pem: "CERT-AFTER-CLEAR".to_string(),
                    private_key_pem: "KEY-AFTER-CLEAR".to_string(),
                    not_after_epoch_seconds: Some(now + 10_000_000),
                })
            },
        )
        .expect("cleared latch issues again");
        assert!(matches!(outcome, AcmeRenewalOutcome::Renewed { .. }));
        let _ = fs::remove_dir_all(&dir);
    }
}

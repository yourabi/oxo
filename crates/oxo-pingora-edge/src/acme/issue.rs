use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeIssueConfig {
    pub fqdn: String,
    pub http_bind: SocketAddr,
    pub state_dir: PathBuf,
    pub directory_url: String,
    pub contacts: Vec<String>,
    pub terms_of_service_agreed: bool,
}

impl AcmeIssueConfig {
    pub fn from_edge_cli(cli: &EdgeCliConfig) -> Result<Self, EdgeError> {
        let fqdn = cli
            .fqdn
            .clone()
            .or_else(|| optional_string_env("OXO_EDGE_SERVER_NAME"))
            .ok_or_else(|| EdgeError::ConfigEnv {
                name: "OXO_EDGE_SERVER_NAME",
                message: "ACME issuance requires --fqdn for one ASCII FQDN".to_string(),
            })?;
        let fqdn = validate_single_ascii_fqdn(&fqdn).map_err(|err| EdgeError::ConfigEnv {
            name: "OXO_EDGE_SERVER_NAME",
            message: err.to_string(),
        })?;

        if cli.https_bind.is_some() {
            return Err(EdgeError::ConfigEnv {
                name: "argv",
                message: "--acme-issue-once uses an ACME-only HTTP listener; pass --http-bind, not --https-bind".to_string(),
            });
        }
        let http_bind = cli
            .http_bind
            .or_else(|| optional_socket_env("OXO_EDGE_BIND"))
            .ok_or_else(|| EdgeError::ConfigEnv {
                name: "OXO_EDGE_BIND",
                message: "ACME issuance requires --http-bind".to_string(),
            })?;

        let state_dir = cli
            .acme_state_path
            .clone()
            .or_else(|| optional_path_env("OXO_EDGE_ACME_STATE_PATH"))
            .ok_or_else(|| EdgeError::ConfigEnv {
                name: "OXO_EDGE_ACME_STATE_PATH",
                message: "ACME issuance requires --acme-state-path".to_string(),
            })?;
        if !state_dir.is_absolute() {
            return Err(EdgeError::ConfigEnv {
                name: "OXO_EDGE_ACME_STATE_PATH",
                message: "ACME state path must be absolute".to_string(),
            });
        }

        let directory_url = cli
            .acme_directory_url
            .clone()
            .or_else(|| optional_string_env("OXO_EDGE_ACME_DIRECTORY_URL"))
            .unwrap_or_else(|| LETS_ENCRYPT_STAGING_DIRECTORY.to_string());
        let allow_production = cli.acme_allow_production_directory
            || optional_bool_env("OXO_EDGE_ACME_ALLOW_PRODUCTION_DIRECTORY").unwrap_or(false);
        validate_directory_url_policy(&directory_url, allow_production).map_err(|message| {
            EdgeError::ConfigEnv {
                name: "OXO_EDGE_ACME_DIRECTORY_URL",
                message,
            }
        })?;
        // Explicit-but-inert fails closed : consent for the
        // production directory while pointing anywhere else is a misconfiguration.
        if allow_production
            && directory_url.trim_end_matches('/') != LETS_ENCRYPT_PRODUCTION_DIRECTORY
        {
            return Err(EdgeError::ConfigEnv {
                name: "OXO_EDGE_ACME_ALLOW_PRODUCTION_DIRECTORY",
                message: "--acme-allow-production-directory is set but the configured ACME \
                          directory is not the production Let's Encrypt directory"
                    .to_string(),
            });
        }
        // Production HTTP-01 validation can never reach a loopback listener.
        if allow_production && http_bind.ip().is_loopback() {
            return Err(EdgeError::ConfigEnv {
                name: "OXO_EDGE_ACME_ALLOW_PRODUCTION_DIRECTORY",
                message: "production ACME issuance cannot validate over a loopback --http-bind; \
                          bind a publicly reachable address"
                    .to_string(),
            });
        }

        let contacts = if !cli.acme_contacts.is_empty() {
            cli.acme_contacts.clone()
        } else {
            optional_string_env("OXO_EDGE_ACME_CONTACTS")
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|part| !part.is_empty())
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        for contact in &contacts {
            if contact.trim().is_empty() || contact.bytes().any(|byte| byte.is_ascii_control()) {
                return Err(EdgeError::ConfigEnv {
                    name: "OXO_EDGE_ACME_CONTACTS",
                    message: "ACME contacts must be non-empty printable URI strings".to_string(),
                });
            }
        }

        let terms_of_service_agreed = cli.acme_accept_terms
            || optional_bool_env("OXO_EDGE_ACME_ACCEPT_TERMS").unwrap_or(false);
        if !terms_of_service_agreed {
            return Err(EdgeError::ConfigEnv {
                name: "OXO_EDGE_ACME_ACCEPT_TERMS",
                message: "ACME issuance requires --acme-accept-terms".to_string(),
            });
        }

        Ok(Self {
            fqdn,
            http_bind,
            state_dir,
            directory_url,
            contacts,
            terms_of_service_agreed,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCertificate {
    pub fqdn: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub not_after_epoch_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeRenewalPolicy {
    pub renew_before_seconds: u64,
    pub retry_base_seconds: u64,
    pub retry_max_seconds: u64,
    pub retry_jitter_seconds: u64,
    pub rate_limit_floor_seconds: u64,
}

impl Default for AcmeRenewalPolicy {
    fn default() -> Self {
        Self {
            renew_before_seconds: 30 * 24 * 60 * 60,
            retry_base_seconds: 60,
            retry_max_seconds: 6 * 60 * 60,
            retry_jitter_seconds: 300,
            rate_limit_floor_seconds: 60 * 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeRenewalOutcome {
    Renewed {
        issued: IssuedCertificate,
        status: CertificateLifecycleStatus,
    },
    NotDue {
        status: CertificateLifecycleStatus,
    },
    Deferred {
        status: CertificateLifecycleStatus,
    },
}

pub fn renew_once_with_issuer<F>(
    config: AcmeIssueConfig,
    policy: AcmeRenewalPolicy,
    now_epoch_seconds: u64,
    issuer: F,
) -> Result<AcmeRenewalOutcome, AcmeError>
where
    F: FnOnce(&Http01ChallengeStore, SocketAddr, &str) -> Result<IssuedCertificate, AcmeError>,
{
    let state = AcmeStatePaths::prepare(&config.state_dir)?;
    let status = state.status(now_epoch_seconds, &policy)?;
    if status
        .backoff_until_epoch_seconds
        .is_some_and(|backoff_until| backoff_until > now_epoch_seconds)
    {
        return Ok(AcmeRenewalOutcome::Deferred { status });
    }
    if invalid_certificate_latched(&status) {
        return Ok(AcmeRenewalOutcome::Deferred { status });
    }
    if !status.renewal_due {
        return Ok(AcmeRenewalOutcome::NotDue { status });
    }
    // Skip-and-defer when another issuing process (e.g. a manual
    // --acme-issue-once) holds the state-dir lock; the next tick retries.
    let lock = try_issuance_lock(&config.state_dir)?;
    if matches!(lock, IssuanceLock::Busy) {
        return Ok(AcmeRenewalOutcome::Deferred { status });
    }
    let _lock = lock;

    match issue_once_with_state_and_issuer(&state, &config, &policy, now_epoch_seconds, issuer) {
        Ok(issued) => {
            let status = state.status(now_epoch_seconds, &policy)?;
            Ok(AcmeRenewalOutcome::Renewed { issued, status })
        }
        Err(err) => {
            let message = err.to_string();
            let kind = classify_acme_failure(&message);
            state.record_failure(now_epoch_seconds, &policy, kind, &message, None)?;
            Err(err)
        }
    }
}

/// Deterministic post-issuance validation failures latch after 3 consecutive
/// occurrences: each retry is a SUCCESSFUL, then discarded, CA issuance and
/// burns the duplicate-certificate rate budget, so the operator must clear
/// `last-failure.json` (after fixing the cause) to re-enable issuer contact.
fn invalid_certificate_latched(status: &CertificateLifecycleStatus) -> bool {
    status.last_error_kind.as_deref() == Some("invalid-certificate") && status.failure_count >= 3
}

/// Cross-process issuance serialization: the supervisor's renewal child and a
/// runbook-mandated manual `--acme-issue-once` may otherwise interleave state
/// writes. The lock is advisory, scoped to the state dir, held for the whole
/// issuance (released on drop — including when a hung child is PG-killed).
pub(super) enum IssuanceLock {
    Held(#[allow(dead_code)] fs::File),
    Busy,
}

pub(super) fn try_issuance_lock(state_dir: &Path) -> Result<IssuanceLock, AcmeError> {
    let path = state_dir.join(".issuance.lock");
    let file = fs::File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|source| AcmeError::Io {
            action: "open ACME issuance lock",
            detail: source.to_string(),
        })?;
    match file.try_lock() {
        Ok(()) => Ok(IssuanceLock::Held(file)),
        Err(fs::TryLockError::WouldBlock) => Ok(IssuanceLock::Busy),
        Err(fs::TryLockError::Error(source)) => Err(AcmeError::Io {
            action: "acquire ACME issuance lock",
            detail: source.to_string(),
        }),
    }
}

pub fn issue_once_with_issuer<F>(
    config: AcmeIssueConfig,
    issuer: F,
) -> Result<IssuedCertificate, AcmeError>
where
    F: FnOnce(&Http01ChallengeStore, SocketAddr, &str) -> Result<IssuedCertificate, AcmeError>,
{
    let state = AcmeStatePaths::prepare(&config.state_dir)?;
    let lock = try_issuance_lock(&config.state_dir)?;
    if matches!(lock, IssuanceLock::Busy) {
        return Err(AcmeError::InvalidIssuance {
            message: "another ACME issuance is in progress for this state directory".to_string(),
        });
    }
    let _lock = lock;
    issue_once_with_state_and_issuer(
        &state,
        &config,
        &AcmeRenewalPolicy::default(),
        now_epoch_seconds(),
        issuer,
    )
}

fn issue_once_with_state_and_issuer<F>(
    state: &AcmeStatePaths,
    config: &AcmeIssueConfig,
    policy: &AcmeRenewalPolicy,
    now_epoch_seconds: u64,
    issuer: F,
) -> Result<IssuedCertificate, AcmeError>
where
    F: FnOnce(&Http01ChallengeStore, SocketAddr, &str) -> Result<IssuedCertificate, AcmeError>,
{
    let store = Http01ChallengeStore::default();
    let server =
        Http01ChallengeServer::start(config.http_bind, config.fqdn.clone(), store.clone())?;
    let issued = issuer(&store, server.local_addr(), &config.fqdn)?;
    if issued.fqdn != config.fqdn {
        return Err(AcmeError::InvalidIssuance {
            message: format!(
                "issuer returned certificate for {:?}, expected {:?}",
                issued.fqdn, config.fqdn
            ),
        });
    }
    state.persist(&issued, policy, now_epoch_seconds)?;
    state.clear_failure()?;
    store.clear()?;
    Ok(issued)
}

#[cfg(feature = "acme")]
pub async fn issue_once_with_instant_acme(
    config: AcmeIssueConfig,
) -> Result<IssuedCertificate, AcmeError> {
    use instant_acme::{
        Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
        RetryPolicy,
    };

    let state = AcmeStatePaths::prepare(&config.state_dir)?;
    let lock = try_issuance_lock(&config.state_dir)?;
    if matches!(lock, IssuanceLock::Busy) {
        return Err(AcmeError::InvalidIssuance {
            message: "another ACME issuance is in progress for this state directory".to_string(),
        });
    }
    let _lock = lock;
    ensure_account_directory_matches(&state.account_json, &config.directory_url)?;
    let store = Http01ChallengeStore::default();
    let _server =
        Http01ChallengeServer::start(config.http_bind, config.fqdn.clone(), store.clone())?;
    let account = if state.account_json.exists() {
        let bytes = fs::read(&state.account_json).map_err(|source| AcmeError::Io {
            action: "read ACME account credentials",
            detail: source.to_string(),
        })?;
        let credentials: AccountCredentials =
            serde_json::from_slice(&bytes).map_err(|source| AcmeError::Json {
                action: "decode ACME account credentials",
                detail: source.to_string(),
            })?;
        Account::builder()
            .map_err(instant_error)?
            .from_credentials(credentials)
            .await
            .map_err(instant_error)?
    } else {
        let contacts = config
            .contacts
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let new_account = NewAccount {
            contact: &contacts,
            terms_of_service_agreed: config.terms_of_service_agreed,
            only_return_existing: false,
        };
        let (account, credentials) = Account::builder()
            .map_err(instant_error)?
            .create(&new_account, config.directory_url.clone(), None)
            .await
            .map_err(instant_error)?;
        let json = serde_json::to_vec_pretty(&credentials).map_err(|source| AcmeError::Json {
            action: "encode ACME account credentials",
            detail: source.to_string(),
        })?;
        write_file_private(&state.account_json, &json, 0o600)?;
        account
    };

    let identifiers = [Identifier::Dns(config.fqdn.clone())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(instant_error)?;
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authorization = result.map_err(instant_error)?;
        let mut challenge = authorization
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| AcmeError::InvalidIssuance {
                message: "ACME order did not offer http-01".to_string(),
            })?;
        let token = challenge.token.clone();
        let key_authorization = challenge.key_authorization().as_str().to_string();
        store.provision(&token, &key_authorization)?;
        challenge.set_ready().await.map_err(instant_error)?;
    }

    let retry = RetryPolicy::new();
    match order.poll_ready(&retry).await.map_err(instant_error)? {
        OrderStatus::Ready => {}
        status => {
            return Err(AcmeError::InvalidIssuance {
                message: format!("ACME order was not ready after http-01: {status:?}"),
            })
        }
    }
    let private_key_pem = order.finalize().await.map_err(instant_error)?;
    let certificate_pem = order
        .poll_certificate(&retry)
        .await
        .map_err(instant_error)?;
    // CA-returned material is validated BEFORE it can reach persistence.
    // This is the real-network seam; injected test issuers are trusted doubles
    // by construction and bypass this (see issue_once_with_state_and_issuer).
    validate_issued_pair(&certificate_pem, &private_key_pem, &config.fqdn)?;
    let issued = IssuedCertificate {
        fqdn: config.fqdn.clone(),
        not_after_epoch_seconds: certificate_not_after_epoch_seconds(&certificate_pem)?,
        certificate_pem,
        private_key_pem,
    };
    state.persist(&issued, &AcmeRenewalPolicy::default(), now_epoch_seconds())?;
    state.clear_failure()?;
    store.clear()?;
    Ok(issued)
}

#[cfg(feature = "acme")]
pub async fn renew_once_with_instant_acme(
    config: AcmeIssueConfig,
) -> Result<AcmeRenewalOutcome, AcmeError> {
    let state = AcmeStatePaths::prepare(&config.state_dir)?;
    let policy = AcmeRenewalPolicy::default();
    let now = now_epoch_seconds();
    let status = state.status(now, &policy)?;
    if status
        .backoff_until_epoch_seconds
        .is_some_and(|backoff_until| backoff_until > now)
    {
        return Ok(AcmeRenewalOutcome::Deferred { status });
    }
    if invalid_certificate_latched(&status) {
        return Ok(AcmeRenewalOutcome::Deferred { status });
    }
    if !status.renewal_due {
        return Ok(AcmeRenewalOutcome::NotDue { status });
    }
    let lock = try_issuance_lock(&config.state_dir)?;
    if matches!(lock, IssuanceLock::Busy) {
        return Ok(AcmeRenewalOutcome::Deferred { status });
    }
    let _lock = lock;
    match issue_once_with_instant_acme(config).await {
        Ok(issued) => {
            let status = state.status(now_epoch_seconds(), &policy)?;
            Ok(AcmeRenewalOutcome::Renewed { issued, status })
        }
        Err(err) => {
            let message = err.to_string();
            let kind = classify_acme_failure(&message);
            state.record_failure(now, &policy, kind, &message, None)?;
            Err(err)
        }
    }
}

#[cfg(feature = "acme")]
fn instant_error(err: instant_acme::Error) -> AcmeError {
    AcmeError::InstantAcme {
        detail: err.to_string(),
    }
}

/// Validate CA-returned material before it can ever be persisted: the pair
/// must parse, the leaf must cover the configured FQDN, and the private key
/// must correspond to the leaf's public key. A pair that fails here never
/// reaches disk (the pair-intact invariant extends to bad material). Kept
/// aligned with the edge-side serving check (`validate_tls_certificate_name`)
/// so a pair this accepts cannot be one the edge then refuses to load.
pub(super) fn validate_issued_pair(
    cert_pem: &str,
    key_pem: &str,
    fqdn: &str,
) -> Result<(), AcmeError> {
    let pems = x509_parser::pem::Pem::iter_from_buffer(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| invalid_issued(format!("certificate PEM did not parse: {err}")))?;
    let leaf_pem = pems
        .first()
        .ok_or_else(|| invalid_issued("certificate PEM contained no certificates".to_string()))?;
    let leaf = leaf_pem
        .parse_x509()
        .map_err(|err| invalid_issued(format!("leaf certificate DER did not parse: {err}")))?;
    let san_match = leaf
        .extensions()
        .iter()
        .filter_map(|ext| match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => Some(san),
            _ => None,
        })
        .flat_map(|san| san.general_names.iter())
        .any(|name| {
            matches!(
                name,
                x509_parser::extensions::GeneralName::DNSName(dns)
                    if dns.eq_ignore_ascii_case(fqdn)
            )
        });
    if !san_match {
        return Err(invalid_issued(format!(
            "leaf certificate SAN does not cover {fqdn:?}"
        )));
    }
    let key = rcgen::KeyPair::from_pem(key_pem)
        .map_err(|err| invalid_issued(format!("private key PEM did not parse: {err}")))?;
    // rcgen's public_key_raw is the raw key material — the same bytes the
    // SPKI BitString carries — so this proves key<->cert correspondence
    // without a second crypto stack.
    if key.public_key_raw() != leaf.public_key().subject_public_key.data.as_ref() {
        return Err(invalid_issued(
            "private key does not correspond to the leaf certificate public key".to_string(),
        ));
    }
    Ok(())
}

// The "invalid issued certificate:" prefix is load-bearing: classify_acme_failure
// keys the invalid-certificate failure class (rate-limit floor + retry latch) off it.
fn invalid_issued(detail: String) -> AcmeError {
    AcmeError::InvalidIssuance {
        message: format!("invalid issued certificate: {detail}"),
    }
}

// supersedes the blanket production reject: the production Let's
// Encrypt directory is permitted ONLY behind the explicit consent flag; the
// rest of the posture (HTTPS or loopback fake-CA) is unchanged.
pub(super) fn validate_directory_url_policy(
    url: &str,
    allow_production: bool,
) -> Result<(), String> {
    if url.trim_end_matches('/') == LETS_ENCRYPT_PRODUCTION_DIRECTORY {
        if allow_production {
            return Ok(());
        }
        return Err(
            "the production Let's Encrypt directory requires explicit consent: pass \
             --acme-allow-production-directory (OXO_EDGE_ACME_ALLOW_PRODUCTION_DIRECTORY=1) \
             and review certificate lifecycle limits in docs/THREAT_MODEL.md"
                .to_string(),
        );
    }
    if !(url.starts_with("https://") || is_loopback_http_directory(url)) {
        return Err("ACME directory URL must be HTTPS, except loopback fake-CA tests".to_string());
    }
    Ok(())
}

/// instant-acme account credentials pin the directory they were created
/// against; `from_credentials` talks to THAT directory regardless of what is
/// configured. Fail closed on mismatch — otherwise a staging-created account
/// keeps issuing staging certs after the operator flips to production, with
/// every internal signal green.
pub(super) fn ensure_account_directory_matches(
    account_json: &Path,
    configured_directory: &str,
) -> Result<(), AcmeError> {
    let Some(value) = read_json_if_present(account_json)? else {
        return Ok(());
    };
    match value.get("directory").and_then(serde_json::Value::as_str) {
        Some(stored)
            if stored.trim_end_matches('/') == configured_directory.trim_end_matches('/') =>
        {
            Ok(())
        }
        Some(stored) => Err(AcmeError::InvalidConfig {
            message: format!(
                "account.json was created against ACME directory {stored:?} but \
                 {configured_directory:?} is configured; use a fresh --acme-state-path for the \
                 new directory (or delete account.json to create a new account there)"
            ),
        }),
        None => Err(AcmeError::InvalidConfig {
            message: "account.json does not record its ACME directory; delete it so a new \
                      account is created against the configured directory"
                .to_string(),
        }),
    }
}

fn is_loopback_http_directory(url: &str) -> bool {
    for prefix in ["http://127.0.0.1", "http://[::1]"] {
        if let Some(rest) = url.strip_prefix(prefix) {
            return rest.is_empty() || rest.starts_with('/') || rest.starts_with(':');
        }
    }
    false
}

fn optional_string_env(name: &'static str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn optional_path_env(name: &'static str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn optional_socket_env(name: &'static str) -> Option<SocketAddr> {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<SocketAddr>().ok())
}

fn optional_bool_env(name: &'static str) -> Option<bool> {
    match env::var(name).ok()?.trim() {
        "1" | "true" | "TRUE" | "yes" | "YES" => Some(true),
        "0" | "false" | "FALSE" | "no" | "NO" => Some(false),
        _ => None,
    }
}

fn classify_acme_failure(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("invalid issued certificate") {
        // Deterministic post-issuance validation failure: every retry burns a
        // SUCCESSFUL (then discarded) CA issuance against the duplicate-cert
        // rate limit, so this class gets the rate-limit floor and, after 3
        // consecutive failures, the renewal latch (see renew_once_*).
        "invalid-certificate"
    } else if lower.contains("rate") || lower.contains("429") {
        "rate_limited"
    } else {
        "transient"
    }
}

pub(super) fn next_attempt_after_failure(
    now_epoch_seconds: u64,
    failure_count: u64,
    policy: &AcmeRenewalPolicy,
    kind: &str,
    retry_after_epoch_seconds: Option<u64>,
) -> u64 {
    let exponent = failure_count.saturating_sub(1).min(20);
    let multiplier = 1u64.checked_shl(exponent as u32).unwrap_or(u64::MAX);
    let base = policy
        .retry_base_seconds
        .saturating_mul(multiplier)
        .min(policy.retry_max_seconds);
    let jitter = deterministic_jitter(
        now_epoch_seconds,
        failure_count,
        policy.retry_jitter_seconds,
    );
    let mut next = now_epoch_seconds
        .saturating_add(base)
        .saturating_add(jitter);
    if kind == "rate_limited" || kind == "invalid-certificate" {
        next = next.max(now_epoch_seconds.saturating_add(policy.rate_limit_floor_seconds));
    }
    if let Some(retry_after) = retry_after_epoch_seconds {
        next = next.max(retry_after);
    }
    next
}

fn deterministic_jitter(now_epoch_seconds: u64, failure_count: u64, jitter_seconds: u64) -> u64 {
    if jitter_seconds == 0 {
        return 0;
    }
    let mixed = now_epoch_seconds
        .wrapping_mul(6364136223846793005)
        .wrapping_add(failure_count.wrapping_mul(1442695040888963407));
    mixed % (jitter_seconds + 1)
}

pub(super) fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(feature = "acme")]
pub(super) fn certificate_not_after_epoch_seconds(pem: &str) -> Result<Option<u64>, AcmeError> {
    use x509_parser::pem::parse_x509_pem;

    let (_, pem) = parse_x509_pem(pem.as_bytes()).map_err(|err| AcmeError::InvalidIssuance {
        message: format!("failed to parse issued certificate PEM: {err}"),
    })?;
    let cert = pem.parse_x509().map_err(|err| AcmeError::InvalidIssuance {
        message: format!("failed to parse issued certificate: {err}"),
    })?;
    let timestamp = cert.validity().not_after.timestamp();
    if timestamp < 0 {
        return Err(AcmeError::InvalidIssuance {
            message: "issued certificate not_after is before the Unix epoch".to_string(),
        });
    }
    Ok(Some(timestamp as u64))
}

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateLifecycleStatus {
    pub cert_present: bool,
    pub not_after_epoch_seconds: Option<u64>,
    pub seconds_until_expiry: Option<u64>,
    pub renewal_due: bool,
    pub next_renewal_epoch_seconds: Option<u64>,
    pub reload_required: bool,
    pub reload_strategy: Option<String>,
    pub plaintext_fallback: bool,
    pub failure_count: u64,
    pub last_error_kind: Option<String>,
    pub last_error_message: Option<String>,
    pub backoff_until_epoch_seconds: Option<u64>,
}

impl CertificateLifecycleStatus {
    pub fn admin_json_fields(&self) -> String {
        format!(
            ",\"cert_present\":{},\"cert_not_after_epoch_seconds\":{},\"cert_seconds_until_expiry\":{},\"cert_renewal_due\":{},\"cert_next_renewal_epoch_seconds\":{},\"cert_reload_required\":{},\"cert_reload_strategy\":{},\"cert_plaintext_fallback\":{},\"cert_failure_count\":{},\"cert_last_error_kind\":{},\"cert_last_error_message\":{},\"cert_backoff_until_epoch_seconds\":{}",
            self.cert_present,
            option_u64_json(self.not_after_epoch_seconds),
            option_u64_json(self.seconds_until_expiry),
            self.renewal_due,
            option_u64_json(self.next_renewal_epoch_seconds),
            self.reload_required,
            option_string_json(self.reload_strategy.as_deref()),
            self.plaintext_fallback,
            self.failure_count,
            option_string_json(self.last_error_kind.as_deref()),
            option_string_json(self.last_error_message.as_deref()),
            option_u64_json(self.backoff_until_epoch_seconds),
        )
    }
}

pub fn certificate_lifecycle_admin_json(state_dir: &Path) -> Result<String, AcmeError> {
    let state = AcmeStatePaths::prepare(state_dir)?;
    let status = state.status(now_epoch_seconds(), &AcmeRenewalPolicy::default())?;
    Ok(status.admin_json_fields())
}

pub(super) struct AcmeStatePaths {
    pub(super) account_json: PathBuf,
    pub(super) cert_pem: PathBuf,
    pub(super) key_pem: PathBuf,
    pub(super) last_issue_json: PathBuf,
    pub(super) last_failure_json: PathBuf,
    pub(super) reload_required_json: PathBuf,
    pub(super) retained_dir: PathBuf,
}

impl AcmeStatePaths {
    pub(super) fn prepare(state_dir: &Path) -> Result<Self, AcmeError> {
        if !state_dir.is_absolute() {
            return Err(AcmeError::InvalidConfig {
                message: "ACME state path must be absolute".to_string(),
            });
        }
        match fs::symlink_metadata(state_dir) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(AcmeError::InvalidConfig {
                        message: format!(
                            "ACME state directory must not be a symlink: {}",
                            state_dir.display()
                        ),
                    });
                }
                if !metadata.is_dir() {
                    return Err(AcmeError::InvalidConfig {
                        message: format!(
                            "ACME state path must be a directory: {}",
                            state_dir.display()
                        ),
                    });
                }
                validate_private_dir_mode(state_dir, &metadata)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(state_dir).map_err(|source| AcmeError::Io {
                    action: "create ACME state directory",
                    detail: source.to_string(),
                })?;
                set_path_mode(state_dir, 0o700)?;
            }
            Err(source) => {
                return Err(AcmeError::Io {
                    action: "inspect ACME state directory",
                    detail: source.to_string(),
                })
            }
        }
        Ok(Self {
            account_json: state_dir.join("account.json"),
            cert_pem: state_dir.join("cert.pem"),
            key_pem: state_dir.join("key.pem"),
            last_issue_json: state_dir.join("last-issue.json"),
            last_failure_json: state_dir.join("last-failure.json"),
            reload_required_json: state_dir.join("reload-required.json"),
            retained_dir: state_dir.join("retained"),
        })
    }

    pub(super) fn persist(
        &self,
        issued: &IssuedCertificate,
        policy: &AcmeRenewalPolicy,
        now_epoch_seconds: u64,
    ) -> Result<(), AcmeError> {
        let not_after_epoch_seconds = match issued.not_after_epoch_seconds {
            Some(value) => Some(value),
            None => certificate_not_after_epoch_seconds(&issued.certificate_pem)?,
        };
        // the reload marker is written FIRST, before the pair swap. Under
        // the supervisor's at-least-once restart contract a marker with the
        // OLD pair still on disk only causes a harmless restart, while a NEW
        // pair with no marker (a renewal child killed between pair-commit and
        // marker-write) would silently serve the stale in-memory cert until
        // expiry — status() would report NotDue off the new pair's metadata.
        let reload = serde_json::json!({
            "reload_required": true,
            "strategy": "bounded-restart",
            "plaintext_fallback": false,
            "updated_at_epoch_seconds": now_epoch_seconds,
            "reason": "certificate material changed"
        });
        write_file_private(
            &self.reload_required_json,
            serde_json::to_string_pretty(&reload)
                .map_err(|source| AcmeError::Json {
                    action: "encode ACME reload metadata",
                    detail: source.to_string(),
                })?
                .as_bytes(),
            0o644,
        )?;
        self.retain_existing(now_epoch_seconds)?;
        write_cert_key_pair(
            &self.cert_pem,
            issued.certificate_pem.as_bytes(),
            &self.key_pem,
            issued.private_key_pem.as_bytes(),
        )?;
        let next_renewal_epoch_seconds = not_after_epoch_seconds
            .map(|not_after| not_after.saturating_sub(policy.renew_before_seconds));
        let meta = serde_json::json!({
            "fqdn": issued.fqdn,
            "certificate": "cert.pem",
            "private_key": "key.pem",
            "not_after_epoch_seconds": not_after_epoch_seconds,
            "renew_before_seconds": policy.renew_before_seconds,
            "next_renewal_epoch_seconds": next_renewal_epoch_seconds,
            "issued_at_epoch_seconds": now_epoch_seconds,
            "claim": "managed certificate lifecycle; no production mode or zero-drop reload claim"
        });
        write_file_private(
            &self.last_issue_json,
            serde_json::to_string_pretty(&meta)
                .map_err(|source| AcmeError::Json {
                    action: "encode ACME issue metadata",
                    detail: source.to_string(),
                })?
                .as_bytes(),
            0o644,
        )
    }

    fn retain_existing(&self, now_epoch_seconds: u64) -> Result<(), AcmeError> {
        if !(self.cert_pem.exists() || self.key_pem.exists()) {
            return Ok(());
        }
        fs::create_dir_all(&self.retained_dir).map_err(|source| AcmeError::Io {
            action: "create ACME retained certificate directory",
            detail: source.to_string(),
        })?;
        set_path_mode(&self.retained_dir, 0o700)?;
        if self.cert_pem.exists() {
            copy_file_private(
                &self.cert_pem,
                &self
                    .retained_dir
                    .join(format!("{now_epoch_seconds}-cert.pem")),
                0o644,
            )?;
        }
        if self.key_pem.exists() {
            copy_file_private(
                &self.key_pem,
                &self
                    .retained_dir
                    .join(format!("{now_epoch_seconds}-key.pem")),
                0o600,
            )?;
        }
        // retain the metadata alongside the pair so a supervisor rollback
        // can restore last-issue.json to describe what is actually on disk —
        // otherwise status() would keep reporting the DISCARDED cert's renewal
        // schedule and go NotDue-blind while the rolled-back cert ages out.
        if self.last_issue_json.exists() {
            copy_file_private(
                &self.last_issue_json,
                &self
                    .retained_dir
                    .join(format!("{now_epoch_seconds}-last-issue.json")),
                0o644,
            )?;
        }
        Ok(())
    }

    pub(super) fn status(
        &self,
        now_epoch_seconds: u64,
        policy: &AcmeRenewalPolicy,
    ) -> Result<CertificateLifecycleStatus, AcmeError> {
        let issue = read_json_if_present(&self.last_issue_json)?;
        let failure = read_json_if_present(&self.last_failure_json)?;
        let reload = read_json_if_present(&self.reload_required_json)?;
        let cert_present = self.cert_pem.exists() && self.key_pem.exists();
        let not_after_epoch_seconds = issue
            .as_ref()
            .and_then(|value| json_u64(value, "not_after_epoch_seconds"))
            .or_else(|| {
                if cert_present {
                    fs::read_to_string(&self.cert_pem)
                        .ok()
                        .and_then(|pem| certificate_not_after_epoch_seconds(&pem).ok().flatten())
                } else {
                    None
                }
            });
        let seconds_until_expiry =
            not_after_epoch_seconds.map(|not_after| not_after.saturating_sub(now_epoch_seconds));
        let next_renewal_epoch_seconds = issue
            .as_ref()
            .and_then(|value| json_u64(value, "next_renewal_epoch_seconds"))
            .or_else(|| {
                not_after_epoch_seconds
                    .map(|not_after| not_after.saturating_sub(policy.renew_before_seconds))
            });
        let backoff_until_epoch_seconds = failure
            .as_ref()
            .and_then(|value| json_u64(value, "next_attempt_epoch_seconds"));
        let renewal_due = !cert_present
            || next_renewal_epoch_seconds
                .map(|next| now_epoch_seconds >= next)
                .unwrap_or(true);
        Ok(CertificateLifecycleStatus {
            cert_present,
            not_after_epoch_seconds,
            seconds_until_expiry,
            renewal_due,
            next_renewal_epoch_seconds,
            reload_required: reload
                .as_ref()
                .and_then(|value| value.get("reload_required"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            reload_strategy: reload
                .as_ref()
                .and_then(|value| json_string(value, "strategy")),
            plaintext_fallback: reload
                .as_ref()
                .and_then(|value| value.get("plaintext_fallback"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            failure_count: failure
                .as_ref()
                .and_then(|value| json_u64(value, "failure_count"))
                .unwrap_or(0),
            last_error_kind: failure
                .as_ref()
                .and_then(|value| json_string(value, "kind")),
            last_error_message: failure
                .as_ref()
                .and_then(|value| json_string(value, "message")),
            backoff_until_epoch_seconds,
        })
    }

    pub(super) fn record_failure(
        &self,
        now_epoch_seconds: u64,
        policy: &AcmeRenewalPolicy,
        kind: &str,
        message: &str,
        retry_after_epoch_seconds: Option<u64>,
    ) -> Result<(), AcmeError> {
        let previous = read_json_if_present(&self.last_failure_json)?;
        let failure_count = previous
            .as_ref()
            .and_then(|value| json_u64(value, "failure_count"))
            .unwrap_or(0)
            .saturating_add(1);
        let next_attempt_epoch_seconds = next_attempt_after_failure(
            now_epoch_seconds,
            failure_count,
            policy,
            kind,
            retry_after_epoch_seconds,
        );
        let failure = serde_json::json!({
            "kind": kind,
            "message": message,
            "failure_count": failure_count,
            "failed_at_epoch_seconds": now_epoch_seconds,
            "next_attempt_epoch_seconds": next_attempt_epoch_seconds,
            "plaintext_fallback": false,
        });
        write_file_private(
            &self.last_failure_json,
            serde_json::to_string_pretty(&failure)
                .map_err(|source| AcmeError::Json {
                    action: "encode ACME failure metadata",
                    detail: source.to_string(),
                })?
                .as_bytes(),
            0o644,
        )
    }

    pub(super) fn clear_failure(&self) -> Result<(), AcmeError> {
        match fs::remove_file(&self.last_failure_json) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(AcmeError::Io {
                action: "clear ACME failure metadata",
                detail: source.to_string(),
            }),
        }
    }
}

fn validate_private_dir_mode(path: &Path, metadata: &fs::Metadata) -> Result<(), AcmeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(AcmeError::InvalidConfig {
                message: format!(
                    "ACME state directory must be 0700, got {mode:o}: {}",
                    path.display()
                ),
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (path, metadata);
    Ok(())
}

fn set_path_mode(path: &Path, mode: u32) -> Result<(), AcmeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
            AcmeError::Io {
                action: "set ACME state permissions",
                detail: source.to_string(),
            }
        })?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

fn copy_file_private(source: &Path, target: &Path, mode: u32) -> Result<(), AcmeError> {
    let bytes = fs::read(source).map_err(|source| AcmeError::Io {
        action: "read ACME retained source file",
        detail: source.to_string(),
    })?;
    write_file_private(target, &bytes, mode)
}

pub(super) fn read_json_if_present(path: &Path) -> Result<Option<serde_json::Value>, AcmeError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|source| AcmeError::Json {
                action: "decode ACME state metadata",
                detail: source.to_string(),
            }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(AcmeError::Io {
            action: "read ACME state metadata",
            detail: source.to_string(),
        }),
    }
}

fn json_u64(value: &serde_json::Value, key: &str) -> Option<u64> {
    value.get(key).and_then(serde_json::Value::as_u64)
}

fn json_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

fn option_u64_json(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn option_string_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", json_escape(value)))
        .unwrap_or_else(|| "null".to_string())
}

/// Write `bytes` to a sibling temp file (`<path>.tmp.<pid>`), fsync it, and chmod it, then
/// return the temp path WITHOUT renaming it into place. Callers rename it to commit.
fn stage_private(path: &Path, bytes: &[u8], mode: u32) -> Result<PathBuf, AcmeError> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|source| AcmeError::Io {
                action: "open ACME state temp file",
                detail: source.to_string(),
            })?;
        file.write_all(bytes).map_err(|source| AcmeError::Io {
            action: "write ACME state temp file",
            detail: source.to_string(),
        })?;
        file.sync_all().map_err(|source| AcmeError::Io {
            action: "sync ACME state temp file",
            detail: source.to_string(),
        })?;
    }
    set_path_mode(&tmp, mode)?;
    Ok(tmp)
}

pub(super) fn write_file_private(path: &Path, bytes: &[u8], mode: u32) -> Result<(), AcmeError> {
    let tmp = stage_private(path, bytes, mode)?;
    fs::rename(&tmp, path).map_err(|source| AcmeError::Io {
        action: "rename ACME state temp file",
        detail: source.to_string(),
    })
}

/// Write a certificate and its private key so a crash can never leave a new cert paired
/// with the old key (or vice versa). Both files are fully staged (write + fsync + chmod)
/// BEFORE either is renamed into place, so a failure or crash during staging leaves the
/// previous pair untouched; the two commits are then back-to-back renames with no fallible
/// work between them, shrinking the mismatch window to the gap between two syscalls. (D18)
pub(super) fn write_cert_key_pair(
    cert_path: &Path,
    cert_bytes: &[u8],
    key_path: &Path,
    key_bytes: &[u8],
) -> Result<(), AcmeError> {
    let cert_tmp = stage_private(cert_path, cert_bytes, 0o644)?;
    let key_tmp = stage_private(key_path, key_bytes, 0o600)?;
    fs::rename(&cert_tmp, cert_path).map_err(|source| AcmeError::Io {
        action: "rename ACME certificate temp file",
        detail: source.to_string(),
    })?;
    fs::rename(&key_tmp, key_path).map_err(|source| AcmeError::Io {
        action: "rename ACME private key temp file",
        detail: source.to_string(),
    })
}

// ---- supervisor reload surface (crate-public; consumed by service.rs) ----

/// The reload marker's `updated_at_epoch_seconds` if a restart is owed, else
/// None. An unparseable-but-present marker counts as owed with timestamp 0 so
/// the supervisor still acts on it.
pub fn reload_marker_updated_at(state_dir: &Path) -> Result<Option<u64>, AcmeError> {
    let state = AcmeStatePaths::prepare(state_dir)?;
    match read_json_if_present(&state.reload_required_json)? {
        None => Ok(None),
        Some(value) => Ok(Some(
            json_u64(&value, "updated_at_epoch_seconds").unwrap_or(0),
        )),
    }
}

/// Delete the reload marker. The supervisor OWNS deletion and only calls this
/// after a restart cycle has successfully loaded the new pair.
pub fn consume_reload_marker(state_dir: &Path) -> Result<(), AcmeError> {
    let state = AcmeStatePaths::prepare(state_dir)?;
    match fs::remove_file(&state.reload_required_json) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(AcmeError::Io {
            action: "remove ACME reload marker",
            detail: source.to_string(),
        }),
    }
}

/// Roll the on-disk cert/key back to the newest retained (pre-renewal) pair
/// after a failed reload restart. The pair is validated and committed through
/// the SAME atomic `write_cert_key_pair` used for issuance (never two loose
/// copies — a crash between them would brick every boot), `last-issue.json` is
/// restored from the retained metadata so `status()` describes what is on disk
/// (otherwise the scheduler goes NotDue-blind), and `reload-failure.json` +
/// a failure record are written so the next tick re-attempts promptly.
pub fn rollback_to_retained_pair(
    state_dir: &Path,
    now_epoch_seconds: u64,
    reason: &str,
) -> Result<(), AcmeError> {
    let state = AcmeStatePaths::prepare(state_dir)?;
    let epoch =
        newest_retained_epoch(&state.retained_dir)?.ok_or_else(|| AcmeError::InvalidConfig {
            message: "no retained certificate pair is available to roll back to".to_string(),
        })?;
    let cert_path = state.retained_dir.join(format!("{epoch}-cert.pem"));
    let key_path = state.retained_dir.join(format!("{epoch}-key.pem"));
    let cert = fs::read(&cert_path).map_err(|source| AcmeError::Io {
        action: "read retained certificate for rollback",
        detail: source.to_string(),
    })?;
    let key = fs::read(&key_path).map_err(|source| AcmeError::Io {
        action: "read retained private key for rollback",
        detail: source.to_string(),
    })?;
    let cert_str = String::from_utf8_lossy(&cert);
    let key_str = String::from_utf8_lossy(&key);
    let fqdn = read_json_if_present(&state.last_issue_json)?
        .as_ref()
        .and_then(|value| json_string(value, "fqdn"))
        .unwrap_or_default();
    // Validate the retained pair before committing it (a corrupt retained pair
    // must not be swapped in on top of a failing new one).
    validate_issued_pair(&cert_str, &key_str, &fqdn)?;
    write_cert_key_pair(&state.cert_pem, &cert, &state.key_pem, &key)?;
    // Restore the retained metadata so status() describes the rolled-back cert.
    let retained_meta = state.retained_dir.join(format!("{epoch}-last-issue.json"));
    match fs::read(&retained_meta) {
        Ok(bytes) => write_file_private(&state.last_issue_json, &bytes, 0o644)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // No retained metadata: delete last-issue.json so status() falls
            // back to parsing the (rolled-back) cert.pem directly.
            let _ = fs::remove_file(&state.last_issue_json);
        }
        Err(source) => {
            return Err(AcmeError::Io {
                action: "read retained issue metadata for rollback",
                detail: source.to_string(),
            })
        }
    }
    let failure = serde_json::json!({
        "failed_at_epoch_seconds": now_epoch_seconds,
        "reason": reason,
        "rolled_back": true,
    });
    write_file_private(
        &state
            .last_failure_json
            .with_file_name("reload-failure.json"),
        serde_json::to_string_pretty(&failure)
            .map_err(|source| AcmeError::Json {
                action: "encode ACME reload failure record",
                detail: source.to_string(),
            })?
            .as_bytes(),
        0o644,
    )?;
    // Record a failure so the scheduler re-attempts promptly rather than
    // reporting the rolled-back cert as NotDue until it expires.
    state.record_failure(
        now_epoch_seconds,
        &AcmeRenewalPolicy::default(),
        "reload-rolled-back",
        reason,
        None,
    )
}

fn newest_retained_epoch(retained_dir: &Path) -> Result<Option<u64>, AcmeError> {
    let entries = match fs::read_dir(retained_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(AcmeError::Io {
                action: "list ACME retained directory",
                detail: source.to_string(),
            })
        }
    };
    let mut newest: Option<u64> = None;
    for entry in entries {
        let entry = entry.map_err(|source| AcmeError::Io {
            action: "read ACME retained directory entry",
            detail: source.to_string(),
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(epoch_str) = name.strip_suffix("-cert.pem") else {
            continue;
        };
        let Ok(epoch) = epoch_str.parse::<u64>() else {
            continue;
        };
        // Only consider epochs with BOTH cert and key retained.
        if retained_dir.join(format!("{epoch}-key.pem")).exists()
            && newest.map(|current| epoch > current).unwrap_or(true)
        {
            newest = Some(epoch);
        }
    }
    Ok(newest)
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped
}

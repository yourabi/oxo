use super::*;

pub fn validate_worker_socket_path(path: &Path) -> Result<(), EdgeError> {
    if !path.is_absolute() {
        return Err(EdgeError::WorkerSocketMustBeAbsolute {
            path: path.to_path_buf(),
        });
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| EdgeError::WorkerSocketMissingParent {
            path: path.to_path_buf(),
        })?;
    validate_runtime_dir(parent)?;
    validate_socket_if_present(path)
}

fn validate_runtime_dir(path: &Path) -> Result<(), EdgeError> {
    let metadata = fs::symlink_metadata(path).map_err(|err| EdgeError::RuntimeDirUnavailable {
        path: path.to_path_buf(),
        message: err.to_string(),
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(EdgeError::RuntimeDirSymlink {
            path: path.to_path_buf(),
        });
    }
    if !file_type.is_dir() {
        return Err(EdgeError::RuntimeDirNotDirectory {
            path: path.to_path_buf(),
        });
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o700 {
        return Err(EdgeError::RuntimeDirMode {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(feature = "tls-rustls")]
pub(super) fn validate_tls_file(
    role: &'static str,
    path: &Path,
    private_key: bool,
) -> Result<(), EdgeError> {
    let metadata = fs::symlink_metadata(path).map_err(|err| EdgeError::TlsFileUnavailable {
        role,
        path: path.to_path_buf(),
        message: err.to_string(),
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(EdgeError::TlsFileSymlink {
            role,
            path: path.to_path_buf(),
        });
    }
    if !file_type.is_file() {
        return Err(EdgeError::TlsFileNotFile {
            role,
            path: path.to_path_buf(),
        });
    }
    if private_key {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(EdgeError::TlsPrivateKeyMode {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    Ok(())
}

fn validate_socket_if_present(path: &Path) -> Result<(), EdgeError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(EdgeError::WorkerSocketUnavailable {
                path: path.to_path_buf(),
                message: err.to_string(),
            })
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(EdgeError::WorkerSocketSymlink {
            path: path.to_path_buf(),
        });
    }
    if !file_type.is_socket() {
        return Err(EdgeError::WorkerSocketNotSocket {
            path: path.to_path_buf(),
        });
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(EdgeError::WorkerSocketMode {
            path: PathBuf::from(path),
            mode,
        });
    }
    Ok(())
}

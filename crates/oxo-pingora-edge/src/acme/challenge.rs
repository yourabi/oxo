use super::*;

#[derive(Debug, Clone)]
pub struct Http01ChallengeStore {
    inner: Arc<Mutex<BTreeMap<String, String>>>,
}

impl Default for Http01ChallengeStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl Http01ChallengeStore {
    pub fn provision(&self, token: &str, key_authorization: &str) -> Result<(), AcmeError> {
        validate_http01_token(token)?;
        if key_authorization.is_empty()
            || key_authorization
                .bytes()
                .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
        {
            return Err(AcmeError::InvalidChallenge {
                message: "key authorization must be a single non-empty line".to_string(),
            });
        }
        self.inner
            .lock()
            .map_err(|_| AcmeError::PoisonedChallengeStore)?
            .insert(token.to_string(), key_authorization.to_string());
        Ok(())
    }

    pub fn answer(&self, token: &str) -> Result<Option<String>, AcmeError> {
        validate_http01_token(token)?;
        Ok(self
            .inner
            .lock()
            .map_err(|_| AcmeError::PoisonedChallengeStore)?
            .get(token)
            .cloned())
    }

    pub fn clear(&self) -> Result<(), AcmeError> {
        self.inner
            .lock()
            .map_err(|_| AcmeError::PoisonedChallengeStore)?
            .clear();
        Ok(())
    }
}

pub struct Http01ChallengeServer {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Http01ChallengeServer {
    pub fn start(
        bind: SocketAddr,
        fqdn: String,
        store: Http01ChallengeStore,
    ) -> Result<Self, AcmeError> {
        let fqdn = validate_single_ascii_fqdn(&fqdn)?;
        let listener = TcpListener::bind(bind).map_err(|source| AcmeError::BindChallenge {
            bind,
            detail: source.to_string(),
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|source| AcmeError::Io {
                action: "set ACME challenge listener nonblocking",
                detail: source.to_string(),
            })?;
        let local_addr = listener.local_addr().map_err(|source| AcmeError::Io {
            action: "read ACME challenge listener address",
            detail: source.to_string(),
        })?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("oxo-acme-http01".to_string())
            .spawn(move || {
                while !thread_stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => handle_http01_connection(stream, &fqdn, &store),
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|source| AcmeError::Io {
                action: "spawn ACME challenge listener",
                detail: source.to_string(),
            })?;
        Ok(Self {
            local_addr,
            stop,
            thread: Some(thread),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for Http01ChallengeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.local_addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn handle_http01_connection(mut stream: TcpStream, fqdn: &str, store: &Http01ChallengeStore) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 4096];
    let read = match stream.read(&mut buf) {
        Ok(0) | Err(_) => return,
        Ok(read) => read,
    };
    let request = String::from_utf8_lossy(&buf[..read]);
    let (status, body) = match parse_http01_request(&request, fqdn) {
        Ok(token) => match store.answer(&token) {
            Ok(Some(answer)) => ("200 OK", answer),
            Ok(None) => ("404 Not Found", "not found\n".to_string()),
            Err(_) => ("400 Bad Request", "bad request\n".to_string()),
        },
        Err(Http01RequestError::Method) => {
            ("405 Method Not Allowed", "method not allowed\n".to_string())
        }
        Err(Http01RequestError::Host) => ("403 Forbidden", "forbidden\n".to_string()),
        Err(Http01RequestError::Path) => ("404 Not Found", "not found\n".to_string()),
        Err(Http01RequestError::Malformed) => ("400 Bad Request", "bad request\n".to_string()),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Http01RequestError {
    Method,
    Host,
    Path,
    Malformed,
}

fn parse_http01_request(request: &str, fqdn: &str) -> Result<String, Http01RequestError> {
    let mut lines = request.lines();
    let request_line = lines.next().ok_or(Http01RequestError::Malformed)?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().ok_or(Http01RequestError::Malformed)?;
    let target = request_parts.next().ok_or(Http01RequestError::Malformed)?;
    let version = request_parts.next().ok_or(Http01RequestError::Malformed)?;
    if request_parts.next().is_some() || version != "HTTP/1.1" {
        return Err(Http01RequestError::Malformed);
    }
    if method != "GET" {
        return Err(Http01RequestError::Method);
    }
    let host = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim())
        .ok_or(Http01RequestError::Host)?;
    if !host_matches_fqdn(host, fqdn) {
        return Err(Http01RequestError::Host);
    }
    let Some(token) = target.strip_prefix(HTTP01_PREFIX) else {
        return Err(Http01RequestError::Path);
    };
    if token.contains('?') || token.contains('/') || validate_http01_token(token).is_err() {
        return Err(Http01RequestError::Path);
    }
    Ok(token.to_string())
}

fn host_matches_fqdn(host: &str, fqdn: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let fqdn = fqdn.trim_end_matches('.').to_ascii_lowercase();
    if host == fqdn {
        return true;
    }
    host.strip_prefix(&(fqdn + ":"))
        .is_some_and(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

pub(super) fn validate_single_ascii_fqdn(value: &str) -> Result<String, AcmeError> {
    let fqdn = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if fqdn.is_empty() || fqdn.len() > 253 {
        return Err(AcmeError::InvalidConfig {
            message: "FQDN must be a non-empty ASCII DNS name up to 253 bytes".to_string(),
        });
    }
    if !fqdn.is_ascii() || fqdn.starts_with("*.") || fqdn.parse::<std::net::IpAddr>().is_ok() {
        return Err(AcmeError::InvalidConfig {
            message: "ACME accepts one ASCII DNS FQDN only: no wildcard, IP, or Unicode input"
                .to_string(),
        });
    }
    let labels = fqdn.split('.').collect::<Vec<_>>();
    if labels.len() < 2 {
        return Err(AcmeError::InvalidConfig {
            message: "FQDN must contain at least two DNS labels".to_string(),
        });
    }
    for label in labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(AcmeError::InvalidConfig {
                message: format!("invalid DNS label {label:?} in ACME FQDN"),
            });
        }
    }
    Ok(fqdn)
}

fn validate_http01_token(token: &str) -> Result<(), AcmeError> {
    if token.is_empty()
        || token.len() > 256
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AcmeError::InvalidChallenge {
            message: "HTTP-01 token must use non-empty base64url token grammar without padding"
                .to_string(),
        });
    }
    Ok(())
}

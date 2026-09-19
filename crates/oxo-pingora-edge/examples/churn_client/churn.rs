//! churn driver: timed TLS connection-churn load with VERIFIED resumption counts.
//!
//! `openssl s_time` cannot tell you whether its `-reuse` leg actually resumed (TLS 1.3
//! tickets are post-handshake; silent full handshakes look identical in its output), so
//! the churn benchmark drives this client instead: every connection reports rustls's
//! `HandshakeKind`, and the summary counts Full vs Resumed — a leg that claims resumption
//! but measured full handshakes is visible, not assumed away.
//!
//! Usage: churn_client <host:port> <seconds> <full|resumed> [sni]
//!   full    — a FRESH client config per connection: every handshake is Full.
//!   resumed — ONE shared config (rustls default in-memory session store): connection 1
//!             is Full, the rest resume via ticket.
//! One short HTTP/1.1 GET per connection (Connection: close), response read to EOF —
//! reading the response is what ingests TLS 1.3 tickets.
//!
//! Output: one JSON line on stdout.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct NoVerify(rustls::crypto::CryptoProvider);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config() -> Arc<rustls::ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ClientConfig::builder_with_provider(provider.clone().into())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    Arc::new(config)
}

/// Entry point, invoked from the Linux-only arm of `main.rs`.
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: churn_client <host:port> <seconds> <full|resumed> [sni]");
        std::process::exit(2);
    }
    let addr = args[1].clone();
    let secs: u64 = args[2].parse().expect("seconds");
    let mode = args[3].as_str();
    let sni = args.get(4).cloned().unwrap_or_else(|| "localhost".into());
    assert!(mode == "full" || mode == "resumed", "mode: full|resumed");

    let shared = client_config();
    let request = format!("GET /bench HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n");

    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut hs_ms: Vec<f64> = Vec::with_capacity(65536);
    let (mut n_full, mut n_resumed, mut n_err) = (0u64, 0u64, 0u64);
    let started = Instant::now();

    while Instant::now() < deadline {
        // full-churn = a fresh config (empty session store) per connection.
        let cfg = if mode == "full" {
            client_config()
        } else {
            Arc::clone(&shared)
        };
        let name = rustls::pki_types::ServerName::try_from(sni.clone()).expect("sni");
        let mut conn = rustls::ClientConnection::new(cfg, name).expect("client conn");
        let t0 = Instant::now();
        let mut tcp = match std::net::TcpStream::connect(&addr) {
            Ok(t) => t,
            Err(_) => {
                n_err += 1;
                continue;
            }
        };
        tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        // Drive the handshake to completion before timing stops: the first write flushes it.
        if tls.write_all(request.as_bytes()).is_err() {
            n_err += 1;
            continue;
        }
        let hs_elapsed = t0.elapsed().as_secs_f64() * 1000.0;
        let mut body = Vec::new();
        match tls.read_to_end(&mut body) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            Err(_) => {
                n_err += 1;
                continue;
            }
        }
        match conn.handshake_kind() {
            Some(rustls::HandshakeKind::Resumed) => n_resumed += 1,
            Some(_) => n_full += 1,
            None => n_err += 1,
        }
        hs_ms.push(hs_elapsed);
    }
    let wall = started.elapsed().as_secs_f64();

    hs_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| -> f64 {
        if hs_ms.is_empty() {
            return f64::NAN;
        }
        let idx = ((hs_ms.len() as f64 - 1.0) * p).round() as usize;
        hs_ms[idx]
    };
    let conns = n_full + n_resumed;
    println!(
        "{{\"mode\":\"{mode}\",\"addr\":\"{addr}\",\"wall_secs\":{wall:.3},\"conns\":{conns},\
         \"cps\":{:.1},\"full\":{n_full},\"resumed\":{n_resumed},\"errors\":{n_err},\
         \"hs_p50_ms\":{:.3},\"hs_p99_ms\":{:.3}}}",
        conns as f64 / wall,
        pct(0.50),
        pct(0.99),
    );
}

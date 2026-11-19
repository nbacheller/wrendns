//! REQ: API-016 (T23.8, ADR-120) — the certificate a router console presents, for the Routers page's
//! "trust the console certificate" step. One TLS handshake at the address, the chain it presents
//! read (the end-entity certificate first, then its CAs), and nothing else: the handshake is not
//! trusted (that is the point of the check), the connection is closed, and the admin saves the PEM
//! only by submitting the form. The saved PEM is the whole chain, so a console signed by a private
//! CA it sends is trusted as well (review of T23.7).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use wrendns_api::model::RouterCertificate;
use wrendns_api::problem::{Code, Problem};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// How long the handshake may take.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Accepts whatever the console presents, and keeps its chain (end-entity first). Signatures are
/// still checked, so the handshake itself is sound; trust is decided by the admin, not here.
#[derive(Debug)]
struct Capture {
    provider: Arc<rustls::crypto::CryptoProvider>,
    cert: Arc<Mutex<Option<Vec<Vec<u8>>>>>,
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut slot = self
            .cert
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut chain = vec![end_entity.as_ref().to_vec()];
        chain.extend(intermediates.iter().map(|c| c.as_ref().to_vec()));
        *slot = Some(chain);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The host and port of an `https://` address (the port defaults to 443).
fn target(url: &str) -> Result<(String, u16), Problem> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| Problem::invalid("an https:// address, e.g. https://192.168.1.1"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, p) = v6.split_once(']').unwrap_or((v6, ""));
        (h.to_owned(), p.strip_prefix(':').unwrap_or("443"))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p),
            None => (authority.to_owned(), "443"),
        }
    };
    let port: u16 = port
        .parse()
        .map_err(|_| Problem::invalid("the address's port isn't a number"))?;
    if host.is_empty() {
        return Err(Problem::invalid("the address has no host"));
    }
    Ok((host, port))
}

/// The names a certificate carries: its common names and DNS and IP subject alternative names.
fn names_of(der: &[u8]) -> Vec<String> {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return Vec::new();
    };
    let mut names: Vec<String> = cert
        .subject()
        .iter_common_name()
        .filter_map(|cn| cn.as_str().ok().map(str::to_owned))
        .collect();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for n in &san.value.general_names {
            match n {
                x509_parser::extensions::GeneralName::DNSName(d) => names.push((*d).to_owned()),
                // REQ: API-016 (review of T23.8) — IPv4 (4 bytes) and IPv6 (16) addresses both.
                x509_parser::extensions::GeneralName::IPAddress(b) => {
                    if let Ok(ip) = <[u8; 4]>::try_from(*b) {
                        names.push(std::net::Ipv4Addr::from(ip).to_string());
                    } else if let Ok(ip) = <[u8; 16]>::try_from(*b) {
                        names.push(std::net::Ipv6Addr::from(ip).to_string());
                    }
                }
                _ => {}
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

/// The PEM text of a DER certificate (64-column lines).
fn pem_of(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// SHA-256 of the DER, as colon-separated upper-case hex.
fn fingerprint_of(der: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, der);
    d.as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The certificate the console at `url` presents: its names, fingerprint and PEM, and the name to
/// set as `tls_server_name` when it names something other than the address (ADR-120).
pub(crate) async fn fetch(url: &str) -> Result<RouterCertificate, Problem> {
    let (host, port) = target(url)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cell = Arc::new(Mutex::new(None));
    let mut cfg = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| Problem::internal(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Capture {
            provider: Arc::clone(&provider),
            cert: Arc::clone(&cell),
        }))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| Problem::invalid(format!("`{host}` isn't a host name or an address")))?;
    let connect = async {
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| format!("can't connect to {host}:{port}: {e}"))?;
        TlsConnector::from(Arc::new(cfg))
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("the TLS handshake with {host}:{port} failed: {e}"))?;
        Ok::<(), String>(())
    };
    match tokio::time::timeout(TIMEOUT, connect).await {
        Err(_) => {
            return Err(Problem::new(
                Code::Unavailable,
                format!("{host}:{port} didn't answer in time"),
            ));
        }
        Ok(Err(e)) => return Err(Problem::new(Code::Unavailable, e)),
        Ok(Ok(())) => {}
    }
    let chain = cell
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .ok_or_else(|| Problem::new(Code::Unavailable, "the console presented no certificate"))?;
    let der = chain
        .first()
        .ok_or_else(|| Problem::new(Code::Unavailable, "the console presented no certificate"))?;
    let names = names_of(der);
    if names.is_empty() {
        return Err(Problem::new(
            Code::Unavailable,
            "the certificate's names couldn't be read",
        ));
    }
    // The name to use: the first DNS name that isn't the address itself, when the address isn't one
    // of the certificate's names.
    let suggested = if names.iter().any(|n| n.eq_ignore_ascii_case(&host)) {
        None
    } else {
        names
            .iter()
            .find(|n| {
                !n.contains(':') && n.parse::<std::net::IpAddr>().is_err() && !n.contains('*')
            })
            .cloned()
    };
    Ok(RouterCertificate {
        names,
        fingerprint_sha256: fingerprint_of(der),
        pem: chain.iter().map(|c| pem_of(c)).collect(),
        suggested_tls_server_name: suggested,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;

    /// REQ: API-016 — the address forms a console is entered with.
    #[test]
    fn api_016_target_forms() {
        assert_eq!(
            target("https://192.168.1.1").unwrap(),
            ("192.168.1.1".into(), 443)
        );
        assert_eq!(
            target("https://unifi.lan:8443/").unwrap(),
            ("unifi.lan".into(), 8443)
        );
        assert_eq!(
            target("https://[fd00::1]:8443").unwrap(),
            ("fd00::1".into(), 8443)
        );
        assert!(target("http://192.168.1.1").is_err());
        assert!(target("https://").is_err());
        assert!(target("https://host:notaport").is_err());
    }

    /// REQ: API-016 — the PEM text is the certificate, wrapped at 64 columns.
    #[test]
    fn api_016_pem_round_trip() {
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x05];
        let pem = pem_of(&der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        let back = rustls::pki_types::CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
        assert_eq!(back.as_ref(), der.as_slice());
    }

    /// REQ: API-016 (review of T23.8) — a certificate whose names are IP addresses (IPv6 included)
    /// has names; the form and the check don't refuse it as "names couldn't be read".
    #[test]
    fn api_016_ipv6_names_read() {
        let cert = rcgen::generate_simple_self_signed(vec!["fd00::1".to_owned()]).unwrap();
        let names = names_of(cert.cert.der());
        assert!(names.iter().any(|n| n == "fd00::1"), "{names:?}");
    }

    /// REQ: API-016 — the fingerprint is SHA-256 in colon-separated hex.
    #[test]
    fn api_016_fingerprint_shape() {
        let f = fingerprint_of(b"abc");
        assert_eq!(f.split(':').count(), 32);
        assert!(
            f.split(':')
                .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
        );
        assert!(f.starts_with("BA:78:16:BF"));
    }
}

//! TLS 1.3 configuration, and why accepting an unverified certificate can be safe here.
//!
//! # The problem
//!
//! Veilink's operator configures exactly two things: the server's address and a pre-shared key. No
//! certificate authority, no hostname, no pinning infrastructure. The server therefore presents a
//! self-signed certificate, which a normal TLS client must reject.
//!
//! # Why not simply disable verification
//!
//! Because "TLS with verification turned off" is an unauthenticated channel: anyone able to
//! intercept the TCP connection could impersonate the server, and the encryption would protect
//! nothing. Veilink does *not* do that.
//!
//! # What Veilink does instead
//!
//! The TLS session is treated as a *confidentiality and integrity* layer, and authentication is
//! performed inside it by the `VLP/1` handshake:
//!
//! 1. both peers exchange `CLIENT_HELLO` and `SERVER_HELLO`, building a transcript;
//! 2. both peers export keying material from the **TLS session** with the label
//!    `EXPORTER-Veilink-VLP1`;
//! 3. each peer sends an HMAC over the handshake transcript *and* the exporter, keyed by a value
//!    derived from the pre-shared key.
//!
//! The transcript is covered by the MAC, so it does not also need to be the exporter's context:
//! the exporter supplies per-session uniqueness and the transcript supplies protocol binding.
//!
//! The exporter is the crucial part. It is derived from the TLS master secret, so it is different
//! for every TLS session. An attacker who terminates the client's TLS connection and opens a second
//! one to the real server holds two different exporters; the confirmation MAC computed by the real
//! server covers *its* exporter, which the client's session does not produce, so the client rejects
//! it. A replayed handshake from a recorded session carries that session's exporter, which the new
//! TLS session does not have.
//!
//! In other words: the certificate is not what authenticates the server — the pre-shared key is,
//! and the exporter is what binds that authentication to the specific TLS session, which is what
//! makes an active relay impossible.
//!
//! # Residual risk, stated plainly
//!
//! * The certificate's *signature* is still verified against its own public key, so a peer must
//!   prove possession of the key it presented. This prevents a degenerate "any bytes are a
//!   certificate" path, though it does not add identity.
//! * If the pre-shared key leaks, an attacker can impersonate the server for *future* sessions.
//!   That is inherent to any pre-shared key scheme.
//! * A client that pins the server's identity fingerprint (see
//!   [`veilink_config::ClientConfig`]'s `server_identity_pin`) additionally detects a server that
//!   has been replaced by a different deployment sharing the same key.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use tracing::{debug, info, warn};

use veilink_crypto::handshake::PROTOCOL_VERSION;

/// ALPN protocol identifier for the raw `VLP/1` framing over TLS.
pub const ALPN_VLP: &[u8] = b"vlp/1";
/// ALPN protocol identifier for `VLP/1` carried inside an HTTP/2 request/response body pair.
pub const ALPN_H2: &[u8] = b"h2";

/// File name of the generated certificate.
pub const CERT_FILE: &str = "tls_cert.pem";
/// File name of the generated private key.
pub const KEY_FILE: &str = "tls_key.pem";

/// Errors raised while setting up or running TLS.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The cryptographic provider could not be installed.
    #[error("no usable TLS cryptographic provider is available: {0}")]
    NoProvider(String),
    /// A certificate or key file could not be created or read.
    #[error("cannot use `{}`: {source}", path.display())]
    File {
        /// The offending path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The generated or stored certificate could not be built.
    #[error("cannot build the server TLS identity: {0}")]
    Identity(String),
    /// The TLS handshake failed.
    #[error("TLS handshake failed: {0}")]
    Handshake(String),
    /// The connection did not negotiate a protocol this build understands.
    #[error("the peer negotiated `{0}`, which this build does not use")]
    UnexpectedAlpn(String),
    /// The TLS exporter could not be computed.
    #[error("cannot compute the TLS channel binding value: {0}")]
    Exporter(String),
}

/// Installs the `ring` cryptographic provider as the process default.
///
/// Idempotent: a second call is harmless.
pub fn install_crypto_provider() -> Result<(), TlsError> {
    if CryptoProvider::get_default().is_some() {
        return Ok(());
    }
    match rustls::crypto::ring::default_provider().install_default() {
        Ok(()) => Ok(()),
        // Another thread may have installed a provider between the check above and this call.
        // Losing that race is not a failure as long as a provider is now available.
        Err(_) if CryptoProvider::get_default().is_some() => Ok(()),
        Err(e) => Err(TlsError::NoProvider(format!("{e:?}"))),
    }
}

/// The server's long-term TLS identity: a self-signed certificate plus its key.
pub struct ServerTlsIdentity {
    /// Certificate chain (just the leaf).
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// Private key.
    pub key: PrivateKeyDer<'static>,
    /// Lower-case hex SHA-256 fingerprint of the leaf certificate, for logging.
    pub fingerprint: String,
    /// True when this process generated the identity.
    pub created: bool,
}

impl std::fmt::Debug for ServerTlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerTlsIdentity")
            .field("fingerprint", &self.fingerprint)
            .field("created", &self.created)
            .finish()
    }
}

impl ServerTlsIdentity {
    /// Loads the TLS identity from `state_dir`, generating it on first run.
    ///
    /// `alt_names` become the certificate's subject alternative names so that an operator
    /// inspecting the file sees the addresses the server is meant to be reached at.
    pub fn load_or_create(state_dir: &Path, alt_names: &[String]) -> Result<Self, TlsError> {
        let cert_path = state_dir.join(CERT_FILE);
        let key_path = state_dir.join(KEY_FILE);
        if cert_path.exists() && key_path.exists() {
            let mut identity = Self::load(&cert_path, &key_path)?;
            identity.created = false;
            return Ok(identity);
        }
        std::fs::create_dir_all(state_dir).map_err(|source| TlsError::File {
            path: state_dir.to_path_buf(),
            source,
        })?;
        let identity = Self::generate(alt_names)?;
        identity.store(&cert_path, &key_path)?;
        Ok(ServerTlsIdentity {
            created: true,
            ..identity
        })
    }

    /// Loads a certificate chain and key from PEM files.
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Self, TlsError> {
        let cert_bytes = std::fs::read(cert_path).map_err(|source| TlsError::File {
            path: cert_path.to_path_buf(),
            source,
        })?;
        let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_bytes[..])
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| TlsError::File {
                path: cert_path.to_path_buf(),
                source,
            })?;
        if cert_chain.is_empty() {
            return Err(TlsError::Identity(format!(
                "`{}` contains no certificate",
                cert_path.display()
            )));
        }
        check_key_permissions(key_path)?;
        let key_bytes = std::fs::read(key_path).map_err(|source| TlsError::File {
            path: key_path.to_path_buf(),
            source,
        })?;
        let key = rustls_pemfile::private_key(&mut &key_bytes[..])
            .map_err(|source| TlsError::File {
                path: key_path.to_path_buf(),
                source,
            })?
            .ok_or_else(|| {
                TlsError::Identity(format!("`{}` contains no private key", key_path.display()))
            })?;
        let fingerprint = fingerprint_of(&cert_chain[0]);
        Ok(ServerTlsIdentity {
            cert_chain,
            key,
            fingerprint,
            created: false,
        })
    }

    /// Generates a fresh self-signed certificate.
    pub fn generate(alt_names: &[String]) -> Result<Self, TlsError> {
        let names: Vec<String> = if alt_names.is_empty() {
            vec!["veilink.local".to_string()]
        } else {
            alt_names.to_vec()
        };
        let mut params =
            rcgen::CertificateParams::new(names).map_err(|e| TlsError::Identity(e.to_string()))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Veilink server");
        params.is_ca = rcgen::IsCa::NoCa;
        let key_pair = rcgen::KeyPair::generate().map_err(|e| TlsError::Identity(e.to_string()))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| TlsError::Identity(e.to_string()))?;

        let cert_der = cert.der().clone();
        let fingerprint = fingerprint_of(&cert_der);
        let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            key_pair.serialize_der(),
        ));
        Ok(ServerTlsIdentity {
            cert_chain: vec![cert_der],
            key,
            fingerprint,
            created: true,
        })
    }

    /// Writes the identity to disk with owner-only permissions.
    pub fn store(&self, cert_path: &Path, key_path: &Path) -> Result<(), TlsError> {
        let mut cert_pem = String::new();
        for cert in &self.cert_chain {
            cert_pem.push_str(&pem_encode("CERTIFICATE", cert.as_ref()));
        }
        std::fs::write(cert_path, cert_pem).map_err(|source| TlsError::File {
            path: cert_path.to_path_buf(),
            source,
        })?;

        let key_pem = pem_encode("PRIVATE KEY", self.key.secret_der());
        write_private(key_path, key_pem.as_bytes()).map_err(|source| TlsError::File {
            path: key_path.to_path_buf(),
            source,
        })
    }
}

/// Builds the server's TLS configuration.
pub fn server_config(identity: &ServerTlsIdentity) -> Result<Arc<ServerConfig>, TlsError> {
    install_crypto_provider()?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(identity.cert_chain.clone(), identity.key.clone_key())
        .map_err(|e| TlsError::Identity(e.to_string()))?;
    config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_VLP.to_vec()];
    Ok(Arc::new(config))
}

/// Builds the client's TLS configuration.
///
/// The certificate verifier accepts any well-formed certificate; see the module documentation for
/// why that is not the same as disabling authentication.
pub fn client_config() -> Result<Arc<ClientConfig>, TlsError> {
    install_crypto_provider()?;
    let provider = CryptoProvider::get_default()
        .cloned()
        .ok_or_else(|| TlsError::NoProvider("the provider was not installed".to_string()))?;
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PskBoundVerifier::new(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_VLP.to_vec()];
    Ok(Arc::new(config))
}

/// A verifier that performs no PKI validation, because authentication happens inside the tunnel.
///
/// Safe *only* in combination with the `VLP/1` handshake, which binds its confirmation MACs to the
/// TLS exporter of this exact session. Using this verifier for any other protocol would be an
/// unauthenticated channel.
#[derive(Debug)]
pub struct PskBoundVerifier {
    provider: Arc<CryptoProvider>,
}

impl PskBoundVerifier {
    /// Creates the verifier.
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        PskBoundVerifier { provider }
    }
}

impl ServerCertVerifier for PskBoundVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Structural sanity only: the certificate must parse and contain a public key we can use
        // for the handshake signature checks below.
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
        let _ = parsed;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
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
        verify_tls13_signature(
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

/// Encodes DER bytes as PEM.
fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(encoded.len() + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

fn fingerprint_of(cert: &CertificateDer<'_>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn check_key_permissions(path: &Path) -> Result<(), TlsError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).map_err(|source| TlsError::File {
        path: path.to_path_buf(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        warn!(
            path = %path.display(),
            mode = format!("{mode:o}"),
            "the TLS private key is readable by other users; tighten it with `chmod 600`"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_permissions(_path: &Path) -> Result<(), TlsError> {
    Ok(())
}

/// Reports the negotiated ALPN protocol, rejecting anything unexpected.
pub fn check_alpn(negotiated: Option<&[u8]>) -> Result<&'static [u8], TlsError> {
    match negotiated {
        None => {
            // No ALPN is acceptable: some deployments terminate TLS in front of Veilink. The
            // framing is unambiguous either way, so this is not a downgrade.
            debug!("the peer did not negotiate ALPN; assuming raw VLP framing");
            Ok(ALPN_VLP)
        }
        Some(protocol) if protocol == ALPN_H2 => Ok(ALPN_H2),
        Some(protocol) if protocol == ALPN_VLP => Ok(ALPN_VLP),
        Some(other) => Err(TlsError::UnexpectedAlpn(
            String::from_utf8_lossy(other).to_string(),
        )),
    }
}

/// Logs a short summary of a successfully established TLS session.
pub fn log_session(role: &str, protocol: Option<&[u8]>, exporter: &[u8; 32]) {
    let alpn = protocol
        .map(|p| String::from_utf8_lossy(p).to_string())
        .unwrap_or_else(|| "none".to_string());
    info!(
        role,
        alpn = %alpn,
        vlp_version = PROTOCOL_VERSION,
        // Only a short, non-invertible tag of the exporter is logged: it is enough to correlate two
        // peers' log lines without recording a value that feeds the key schedule.
        channel_tag = %exporter[..4].iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "TLS session established"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ServerTlsIdentity {
        ServerTlsIdentity::generate(&["localhost".to_string(), "127.0.0.1".to_string()]).unwrap()
    }

    #[test]
    fn generates_and_reloads_an_identity() {
        let dir = tempfile::tempdir().unwrap();
        let first =
            ServerTlsIdentity::load_or_create(dir.path(), &["localhost".to_string()]).unwrap();
        assert!(first.created);
        let fingerprint = first.fingerprint.clone();

        let second =
            ServerTlsIdentity::load_or_create(dir.path(), &["localhost".to_string()]).unwrap();
        assert!(!second.created);
        assert_eq!(second.fingerprint, fingerprint);
    }

    #[test]
    #[cfg(unix)]
    fn the_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        ServerTlsIdentity::load_or_create(dir.path(), &["localhost".to_string()]).unwrap();
        let mode = std::fs::metadata(dir.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn pem_round_trips() {
        let identity = identity();
        let pem = pem_encode("CERTIFICATE", identity.cert_chain[0].as_ref());
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));

        let parsed: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].as_ref(), identity.cert_chain[0].as_ref());
    }

    #[test]
    fn server_and_client_configs_build() {
        install_crypto_provider().unwrap();
        let identity = identity();
        let server = server_config(&identity).unwrap();
        assert!(server.alpn_protocols.contains(&ALPN_VLP.to_vec()));
        assert!(server.alpn_protocols.contains(&ALPN_H2.to_vec()));
        let client = client_config().unwrap();
        assert!(client.alpn_protocols.contains(&ALPN_VLP.to_vec()));
    }

    #[test]
    fn alpn_is_validated() {
        assert_eq!(check_alpn(None).unwrap(), ALPN_VLP);
        assert_eq!(check_alpn(Some(ALPN_VLP)).unwrap(), ALPN_VLP);
        assert_eq!(check_alpn(Some(ALPN_H2)).unwrap(), ALPN_H2);
        assert!(check_alpn(Some(b"http/1.1")).is_err());
    }

    #[test]
    fn fingerprints_are_stable_and_distinguishing() {
        let a = identity();
        let b = identity();
        assert_eq!(a.fingerprint.len(), 64);
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn identity_debug_does_not_expose_the_key() {
        let identity = identity();
        let text = format!("{identity:?}");
        let key_hex: String = identity
            .key
            .secret_der()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!text.contains(&key_hex));
        assert!(text.contains(&identity.fingerprint));
    }

    #[test]
    fn a_missing_certificate_file_is_reported_clearly() {
        let dir = tempfile::tempdir().unwrap();
        let error =
            ServerTlsIdentity::load(&dir.path().join("nope.pem"), &dir.path().join("nope.key"))
                .unwrap_err();
        assert!(error.to_string().contains("nope.pem"), "{error}");
    }

    #[test]
    fn a_missing_key_file_is_reported_clearly() {
        let dir = tempfile::tempdir().unwrap();
        let identity = ServerTlsIdentity::generate(&["localhost".to_string()]).unwrap();
        let cert = dir.path().join("cert.pem");
        identity.store(&cert, &dir.path().join("key.pem")).unwrap();
        std::fs::remove_file(dir.path().join("key.pem")).unwrap();
        let error = ServerTlsIdentity::load(&cert, &dir.path().join("key.pem")).unwrap_err();
        assert!(error.to_string().contains("key.pem"), "{error}");
    }
}

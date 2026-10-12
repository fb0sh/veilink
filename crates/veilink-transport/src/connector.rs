//! Establishing secure connections in both roles.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::debug;
use veilink_crypto::kdf::EXPORTER_LABEL;

use crate::tls::{check_alpn, client_config, server_config, ServerTlsIdentity, TlsError};

/// A TLS-protected connection plus the values the protocol needs from it.
pub struct SecureConnection {
    /// The TLS stream, which implements the protocol's duplex requirements.
    pub stream: tokio_rustls::client::TlsStream<TcpStream>,
    /// The TLS exporter value for this session.
    ///
    /// It is the channel binding that makes the pre-shared key authentication apply to *this* TLS
    /// session and no other. It must never be reused, cached, or derived from anything but the live
    /// TLS connection.
    pub exporter: [u8; 32],
    /// The negotiated ALPN protocol.
    pub alpn: Option<Vec<u8>>,
}

impl std::fmt::Debug for SecureConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureConnection")
            .field(
                "alpn",
                &self
                    .alpn
                    .as_ref()
                    .map(|a| String::from_utf8_lossy(a).to_string()),
            )
            .field("exporter", &"<redacted>")
            .finish()
    }
}

/// A TLS-protected connection accepted by a server.
pub struct AcceptedConnection {
    /// The TLS stream.
    pub stream: tokio_rustls::server::TlsStream<TcpStream>,
    /// The TLS exporter value for this session.
    pub exporter: [u8; 32],
    /// The negotiated ALPN protocol.
    pub alpn: Option<Vec<u8>>,
}

impl std::fmt::Debug for AcceptedConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptedConnection")
            .field(
                "alpn",
                &self
                    .alpn
                    .as_ref()
                    .map(|a| String::from_utf8_lossy(a).to_string()),
            )
            .field("exporter", &"<redacted>")
            .finish()
    }
}

/// Computes the exporter of a live TLS session.
///
/// The label is fixed by the protocol and the context is empty: per-session uniqueness comes from
/// the TLS master secret, and protocol binding comes from the transcript being covered by the
/// confirmation MAC.
fn export(connection: &impl ExporterSource) -> Result<[u8; 32], TlsError> {
    connection.export()
}

/// Anything that can produce the TLS exporter value for its connection.
pub trait ExporterSource {
    /// Computes the 32-byte exporter.
    fn export(&self) -> Result<[u8; 32], TlsError>;
}

impl ExporterSource for rustls::ClientConnection {
    fn export(&self) -> Result<[u8; 32], TlsError> {
        let mut out = [0u8; 32];
        self.export_keying_material(&mut out, EXPORTER_LABEL, None)
            .map_err(|e| TlsError::Exporter(e.to_string()))?;
        Ok(out)
    }
}

impl ExporterSource for rustls::ServerConnection {
    fn export(&self) -> Result<[u8; 32], TlsError> {
        let mut out = [0u8; 32];
        self.export_keying_material(&mut out, EXPORTER_LABEL, None)
            .map_err(|e| TlsError::Exporter(e.to_string()))?;
        Ok(out)
    }
}

/// Connects to `addr` and completes a TLS 1.3 handshake.
pub async fn connect(
    addr: SocketAddr,
    server_name: &str,
    timeout: Duration,
) -> Result<SecureConnection, TlsError> {
    let config = client_config()?;
    connect_with(addr, server_name, config, timeout).await
}

/// Connects using an explicit client configuration.
pub async fn connect_with(
    addr: SocketAddr,
    server_name: &str,
    config: Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> Result<SecureConnection, TlsError> {
    let socket = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| TlsError::Handshake(format!("connecting to {addr} timed out")))?
        .map_err(|e| TlsError::Handshake(e.to_string()))?;
    socket.set_nodelay(true).ok();

    let name: rustls::pki_types::ServerName<'static> =
        rustls::pki_types::ServerName::try_from(server_name.to_string()).map_err(|e| {
            TlsError::Handshake(format!(
                "`{server_name}` is not a valid TLS server name: {e}"
            ))
        })?;

    let connector = TlsConnector::from(config);
    let stream = tokio::time::timeout(timeout, connector.connect(name, socket))
        .await
        .map_err(|_| TlsError::Handshake("the TLS handshake timed out".to_string()))?
        .map_err(|e| TlsError::Handshake(e.to_string()))?;

    let (_, connection) = stream.get_ref();
    let alpn = connection.alpn_protocol().map(|p| p.to_vec());
    check_alpn(alpn.as_deref())?;
    let exporter = export(connection)?;
    debug!(alpn = ?alpn, "TLS handshake complete (client)");
    Ok(SecureConnection {
        stream,
        exporter,
        alpn,
    })
}

/// Accepts a TLS connection on an already-accepted TCP socket.
pub async fn accept(
    socket: TcpStream,
    acceptor: &TlsAcceptor,
    timeout: Duration,
) -> Result<AcceptedConnection, TlsError> {
    socket.set_nodelay(true).ok();
    let stream = tokio::time::timeout(timeout, acceptor.accept(socket))
        .await
        .map_err(|_| TlsError::Handshake("the TLS handshake timed out".to_string()))?
        .map_err(|e| TlsError::Handshake(e.to_string()))?;

    let (_, connection) = stream.get_ref();
    let alpn = connection.alpn_protocol().map(|p| p.to_vec());
    check_alpn(alpn.as_deref())?;
    let exporter = export(connection)?;
    Ok(AcceptedConnection {
        stream,
        exporter,
        alpn,
    })
}

/// Builds the server's TLS acceptor.
pub fn acceptor(identity: &ServerTlsIdentity) -> Result<TlsAcceptor, TlsError> {
    Ok(TlsAcceptor::from(server_config(identity)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_tls_session_yields_a_usable_exporter() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let identity = ServerTlsIdentity::generate(&["localhost".to_string()]).unwrap();
        let acceptor = acceptor(&identity).unwrap();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut accepted = accept(socket, &acceptor, Duration::from_secs(5))
                .await
                .unwrap();
            accepted.stream.write_all(b"pong").await.unwrap();
            accepted.exporter
        });

        let mut client = connect(addr, "localhost", Duration::from_secs(5))
            .await
            .unwrap();
        let mut buf = [0u8; 4];
        client.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        let server_exporter = server.await.unwrap();
        assert_eq!(
            client.exporter, server_exporter,
            "both peers must derive the same exporter"
        );
        assert_ne!(client.exporter, [0u8; 32]);
    }

    #[tokio::test]
    async fn each_session_has_a_different_exporter() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let identity = ServerTlsIdentity::generate(&["localhost".to_string()]).unwrap();
        let acceptor = acceptor(&identity).unwrap();

        let server = tokio::spawn(async move {
            let mut exporters = Vec::new();
            for _ in 0..2 {
                let (socket, _) = listener.accept().await.unwrap();
                let accepted = accept(socket, &acceptor, Duration::from_secs(5))
                    .await
                    .unwrap();
                exporters.push(accepted.exporter);
                // Keep the stream alive until the client has read its exporter.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            exporters
        });

        let first = connect(addr, "localhost", Duration::from_secs(5))
            .await
            .unwrap();
        let second = connect(addr, "localhost", Duration::from_secs(5))
            .await
            .unwrap();
        assert_ne!(
            first.exporter, second.exporter,
            "two TLS sessions shared an exporter, which would break channel binding"
        );
        let exporters = server.await.unwrap();
        assert_ne!(exporters[0], exporters[1]);
        assert_eq!(exporters[0], first.exporter);
    }

    #[tokio::test]
    async fn alpn_negotiates_h2_first() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let identity = ServerTlsIdentity::generate(&["localhost".to_string()]).unwrap();
        let acceptor = acceptor(&identity).unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            accept(socket, &acceptor, Duration::from_secs(5))
                .await
                .unwrap()
        });
        let client = connect(addr, "localhost", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(client.alpn.as_deref(), Some(crate::tls::ALPN_H2));
        let accepted = server.await.unwrap();
        assert_eq!(accepted.alpn, client.alpn);
    }

    #[tokio::test]
    async fn connecting_to_a_closed_port_fails() {
        // Bind and immediately drop so the port is certainly closed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let error = connect(addr, "localhost", Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(matches!(error, TlsError::Handshake(_)), "{error}");
    }
}

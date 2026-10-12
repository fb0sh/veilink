//! Outbound TCP egress: resolve, authorise, connect, forward.
//!
//! The order of operations matters and is enforced here:
//!
//! 1. check the destination port against the allow-list;
//! 2. resolve the name *remotely* (or accept an IPv4 literal);
//! 3. check **every** resolved address against the egress policy;
//! 4. connect to a checked address — never to a name, never re-resolved;
//! 5. splice bytes between the tunnel stream and the target socket with correct half-close.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tracing::{debug, info};

use veilink_protocol::duplex::{splice, BoxStream, BufStream, SpliceOutcome};

use crate::policy::{EgressPolicy, PolicyDeny};
use crate::resolver::{ResolveError, Resolver};

/// Errors raised while establishing an outbound connection.
#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    /// The destination was refused by policy.
    #[error("outbound destination refused: {0}")]
    Denied(#[from] PolicyDeny),
    /// The name could not be resolved.
    #[error("remote DNS resolution failed: {0}")]
    Resolve(#[from] ResolveError),
    /// The TCP connection could not be established.
    #[error("cannot connect to {target}: {source}")]
    Connect {
        /// The address that was attempted.
        target: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// Every address resolved, but none could be reached.
    #[error("none of the {attempted} resolved address(es) for `{host}` could be reached: {last}")]
    Unreachable {
        /// The requested host.
        host: String,
        /// How many addresses were tried.
        attempted: usize,
        /// Last error observed.
        last: String,
    },
    /// The address list was empty.
    #[error("`{0}` resolved to no usable IPv4 address")]
    NoAddress(String),
}

/// The server's outbound connection engine.
pub struct Egress {
    resolver: Arc<Resolver>,
    policy: EgressPolicy,
    connect_timeout: Duration,
}

impl std::fmt::Debug for Egress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Egress")
            .field("policy", &self.policy)
            .field("connect_timeout", &self.connect_timeout)
            .finish_non_exhaustive()
    }
}

impl Egress {
    /// Builds an egress engine.
    pub fn new(resolver: Arc<Resolver>, policy: EgressPolicy, connect_timeout: Duration) -> Self {
        Egress {
            resolver,
            policy,
            connect_timeout,
        }
    }

    /// The policy in force.
    pub fn policy(&self) -> &EgressPolicy {
        &self.policy
    }

    /// Resolves `host` and returns the authorised addresses.
    pub async fn authorised_addresses(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Vec<Ipv4Addr>, EgressError> {
        self.policy.check_port(port)?;
        let addresses = self.resolver.resolve_ipv4(host).await?;
        if addresses.is_empty() {
            return Err(EgressError::NoAddress(host.to_string()));
        }
        let authorised = self.policy.filter_addresses(port, &addresses)?;
        Ok(authorised)
    }

    /// Connects to `host:port` after policy checks.
    ///
    /// The socket is always opened against an address that was checked, so a DNS answer that
    /// changes between the check and the connect cannot be used to reach a denied destination.
    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, EgressError> {
        let addresses = self.authorised_addresses(host, port).await?;
        let mut last_error = String::new();
        let attempts = addresses.len();
        for address in addresses {
            let target = SocketAddr::new(std::net::IpAddr::V4(address), port);
            match tokio::time::timeout(self.connect_timeout, TcpStream::connect(target)).await {
                Ok(Ok(stream)) => {
                    stream.set_nodelay(true).ok();
                    debug!(%target, "outbound connection established");
                    return Ok(stream);
                }
                Ok(Err(source)) => {
                    last_error = source.to_string();
                    debug!(%target, error = %source, "outbound connection failed");
                }
                Err(_) => {
                    last_error = format!("timed out after {}ms", self.connect_timeout.as_millis());
                    debug!(%target, "outbound connection timed out");
                }
            }
        }
        Err(EgressError::Unreachable {
            host: host.to_string(),
            attempted: attempts,
            last: last_error,
        })
    }

    /// Connects to `host:port` and splices it against `stream` until both directions finish.
    pub async fn forward(
        &self,
        host: &str,
        port: u16,
        stream: BoxStream,
    ) -> Result<SpliceOutcome, EgressError> {
        let socket = self.connect(host, port).await?;
        let mut tunnel_side = BufStream::with_limit(stream, 256 * 1024);
        let mut target_side = BufStream::with_limit(socket, 256 * 1024);
        let outcome = splice(&mut tunnel_side, &mut target_side)
            .await
            .map_err(|source| EgressError::Connect {
                target: SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
                source,
            })?;
        info!(
            uploaded = outcome.a_to_b,
            downloaded = outcome.b_to_a,
            "stream finished"
        );
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use veilink_config::DnsConfig;

    fn resolver() -> Arc<Resolver> {
        Arc::new(
            Resolver::new(&DnsConfig {
                servers: vec!["127.0.0.1:53".to_string()],
                ..DnsConfig::default()
            })
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn denies_loopback_by_default() {
        let egress = Egress::new(
            resolver(),
            EgressPolicy::strict(),
            Duration::from_millis(500),
        );
        let err = egress.connect("127.0.0.1", 80).await.unwrap_err();
        assert!(matches!(err, EgressError::Denied(_)), "{err}");
        assert!(err.to_string().contains("loopback"), "{err}");
    }

    #[tokio::test]
    async fn denies_metadata_address() {
        let egress = Egress::new(
            resolver(),
            EgressPolicy::strict(),
            Duration::from_millis(500),
        );
        let err = egress.connect("169.254.169.254", 80).await.unwrap_err();
        assert!(matches!(err, EgressError::Denied(_)));
    }

    #[tokio::test]
    async fn denied_port_short_circuits_before_resolution() {
        let egress = Egress::new(
            resolver(),
            EgressPolicy::new(true, vec![443]),
            Duration::from_millis(500),
        );
        let err = egress.connect("127.0.0.1", 22).await.unwrap_err();
        assert!(matches!(
            err,
            EgressError::Denied(PolicyDeny::PortNotAllowed(22))
        ));
    }

    #[tokio::test]
    async fn connects_and_splices_to_a_local_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 5];
            socket.read_exact(&mut buf).await.unwrap();
            socket.write_all(&buf).await.unwrap();
            socket.shutdown().await.unwrap();
        });

        let egress = Egress::new(
            resolver(),
            // The target really is on loopback, so the testing escape hatch is required here.
            EgressPolicy::new(true, Vec::new()),
            Duration::from_secs(5),
        );
        let (client, server) = tokio::io::duplex(4096);
        let server = Box::new(server) as BoxStream;
        let task =
            tokio::spawn(async move { egress.forward("127.0.0.1", addr.port(), server).await });

        let mut client = client;
        client.write_all(b"hello").await.unwrap();
        client.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello");

        let outcome = task.await.unwrap().unwrap();
        assert_eq!(outcome.a_to_b, 5);
        assert_eq!(outcome.b_to_a, 5);
    }

    #[tokio::test]
    async fn rejects_ipv6_literals_through_resolution_path() {
        let egress = Egress::new(
            resolver(),
            EgressPolicy::new(true, Vec::new()),
            Duration::from_millis(500),
        );
        let err = egress.connect("::1", 80).await.unwrap_err();
        assert!(
            matches!(err, EgressError::Resolve(ResolveError::InvalidName(_))),
            "{err}"
        );
    }
}

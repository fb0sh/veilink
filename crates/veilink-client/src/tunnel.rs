//! Tunnel abstraction and route selection.
//!
//! The proxy loop never knows *how* a byte pipe to the target is obtained. Two implementations
//! exist:
//!
//! * [`DirectTunnel`] connects from the local host with the system resolver — used for targets that
//!   do not match the whitelist and for every target when the whitelist is empty;
//! * the `VLP/1` session tunnel in [`veilink-protocol`], used for whitelisted targets, which
//!   resolves the name remotely and carries the stream inside the encrypted tunnel.
//!
//! **Fail-closed rule.** When a target matches the whitelist and the remote tunnel is missing or
//! broken, [`Router::open`] returns [`RouteError::TunnelUnavailable`]. It never silently falls back
//! to a direct connection: that would leak the very traffic the user asked to protect, to the
//! precise destination the user did not want contacted locally.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, warn};

use crate::routing::{RouteError, RouteSelection};
use veilink_protocol::duplex::BoxStream;

/// A boxed, sendable future, used to keep [`Tunnel`] object-safe without an async-trait dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A source of byte pipes to remote targets.
pub trait Tunnel: Send + Sync + 'static {
    /// Short name used in logs, for example `direct` or `vlp`.
    fn name(&self) -> &'static str;

    /// Opens a bidirectional stream to `host:port`.
    fn open<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<BoxStream>>;

    /// Whether the tunnel can currently open streams.
    ///
    /// A remote tunnel reports `false` while the outer session is down. The router uses this to fail
    /// closed instead of queueing a request that would never complete.
    fn is_ready(&self) -> bool {
        true
    }
}

/// The local direct-connect tunnel.
#[derive(Debug, Clone)]
pub struct DirectTunnel {
    connect_timeout: Duration,
}

impl DirectTunnel {
    /// Creates a direct tunnel with the given connect timeout.
    pub fn new(connect_timeout: Duration) -> Self {
        DirectTunnel { connect_timeout }
    }
}

impl Tunnel for DirectTunnel {
    fn name(&self) -> &'static str {
        "direct"
    }

    fn open<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<BoxStream>> {
        let timeout = self.connect_timeout;
        Box::pin(async move {
            // `TcpStream::connect` with a `(&str, u16)` performs the DNS lookup on Tokio's blocking
            // pool, i.e. through the system resolver — exactly the semantics DIRECT must have.
            let stream =
                tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host, port)))
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("direct connection to {host}:{port} timed out"),
                        )
                    })??;
            stream.set_nodelay(true).ok();
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

/// Selects between the direct tunnel and an optional remote tunnel.
pub struct Router {
    direct: DirectTunnel,
    remote: Option<Arc<dyn Tunnel>>,
}

impl Router {
    /// Creates a router with a direct tunnel and an optional remote tunnel.
    pub fn new(direct: DirectTunnel, remote: Option<Arc<dyn Tunnel>>) -> Self {
        Router { direct, remote }
    }

    /// The remote tunnel, if any.
    pub fn remote(&self) -> Option<&Arc<dyn Tunnel>> {
        self.remote.as_ref()
    }

    /// Installs or replaces the remote tunnel.
    ///
    /// Called when a hot reload changes the server endpoint or the authentication key, or when a
    /// session is re-established after a reconnect.
    pub fn set_remote(&mut self, remote: Option<Arc<dyn Tunnel>>) {
        self.remote = remote;
    }

    /// Opens a stream according to `selection`.
    pub async fn open(
        &self,
        selection: &RouteSelection,
        host: &str,
        port: u16,
    ) -> Result<BoxStream, RouteError> {
        match selection {
            RouteSelection::Direct => {
                debug!(tunnel = "direct", port, "opening direct connection");
                self.direct.open(host, port).await.map_err(|source| {
                    debug!(tunnel = "direct", error = %source, "direct connection failed");
                    RouteError::TunnelConnect {
                        tunnel: "direct",
                        target: format!("{host}:{port}"),
                        source,
                    }
                })
            }
            RouteSelection::Proxy { rule } => {
                let Some(remote) = self.remote.as_ref() else {
                    warn!(
                        rule = %rule,
                        "target matched the whitelist but no secure tunnel is configured; \
                         refusing to fall back to DIRECT"
                    );
                    return Err(RouteError::TunnelUnavailable {
                        target: format!("{host}:{port}"),
                    });
                };
                if !remote.is_ready() {
                    warn!(
                        rule = %rule,
                        "target matched the whitelist but the secure tunnel is down; \
                         refusing to fall back to DIRECT"
                    );
                    return Err(RouteError::TunnelUnavailable {
                        target: format!("{host}:{port}"),
                    });
                }
                debug!(tunnel = remote.name(), port, "opening tunnel stream");
                let name = remote.name();
                remote.open(host, port).await.map_err(|source| {
                    debug!(tunnel = name, error = %source, "tunnel stream failed");
                    RouteError::TunnelConnect {
                        tunnel: name,
                        target: format!("{host}:{port}"),
                        source,
                    }
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Extracts the error from a route attempt, since `BoxStream` is deliberately not `Debug`.
    async fn open_err(router: &Router, selection: &RouteSelection) -> RouteError {
        match router.open(selection, "example.com", 443).await {
            Ok(_) => panic!("expected the route to fail"),
            Err(e) => e,
        }
    }

    struct FailingTunnel;

    impl Tunnel for FailingTunnel {
        fn name(&self) -> &'static str {
            "failing"
        }
        fn open<'a>(&'a self, _host: &'a str, _port: u16) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async { Err(io::Error::other("tunnel is broken")) })
        }
    }

    struct EchoTunnel;

    impl Tunnel for EchoTunnel {
        fn name(&self) -> &'static str {
            "echo"
        }
        fn open<'a>(&'a self, _host: &'a str, _port: u16) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async {
                let (client, mut server) = tokio::io::duplex(1024);
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    let n = server.read(&mut buf).await.unwrap();
                    server.write_all(&buf[..n]).await.unwrap();
                });
                Ok(Box::new(client) as BoxStream)
            })
        }
    }

    #[tokio::test]
    async fn proxy_route_without_tunnel_fails_closed() {
        let router = Router::new(DirectTunnel::new(Duration::from_secs(1)), None);
        let selection = RouteSelection::Proxy {
            rule: "DOMAIN,x".into(),
        };
        let err = open_err(&router, &selection).await;
        assert!(matches!(err, RouteError::TunnelUnavailable { .. }));
        assert!(err.to_string().contains("refusing to fall back"));
    }

    #[tokio::test]
    async fn direct_route_uses_local_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
        });

        let router = Router::new(DirectTunnel::new(Duration::from_secs(5)), None);
        let mut stream = router
            .open(&RouteSelection::Direct, "127.0.0.1", addr.port())
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn proxy_route_uses_the_remote_tunnel_when_ready() {
        let router = Router::new(
            DirectTunnel::new(Duration::from_secs(1)),
            Some(Arc::new(EchoTunnel)),
        );
        let selection = RouteSelection::Proxy {
            rule: "DOMAIN,x".into(),
        };
        let mut stream = router.open(&selection, "example.com", 443).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn tunnel_errors_surface_without_downgrade() {
        let router = Router::new(
            DirectTunnel::new(Duration::from_secs(1)),
            Some(Arc::new(FailingTunnel)),
        );
        let selection = RouteSelection::Proxy {
            rule: "DOMAIN,x".into(),
        };
        let err = open_err(&router, &selection).await;
        assert!(err.to_string().contains("tunnel is broken"), "{err}");
        assert!(matches!(err, RouteError::TunnelConnect { .. }));
    }
}

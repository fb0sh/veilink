//! Helpers for building valid Veilink configurations and running the client inside tests.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::sync::oneshot;

use veilink_client::{ClientContext, ClientRuntime};
use veilink_config::{ClientConfig, ClientSettings, LimitsConfig, LogConfig};

/// A deterministic but high-entropy key usable in tests.
///
/// It is a fixed value on purpose: tests must be reproducible, and this key protects nothing.
pub const TEST_KEY: &str = "9f8c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5";

/// A second, different key, for negative authentication tests.
pub const TEST_KEY_OTHER: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00123456789abcdeffedcba9876543210";

/// Returns a currently free loopback port.
///
/// There is an unavoidable race between closing the probe socket and binding the real listener, but
/// on an ephemeral port range this is reliable in practice and keeps the tests independent.
pub fn free_listen_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("cannot bind a probe socket");
    let addr = listener.local_addr().expect("no local address");
    drop(listener);
    addr
}

/// Builds validated client settings listening on `listen` with the given whitelist rules.
pub fn client_settings_with_listen(
    listen: SocketAddr,
    rules: &[&str],
    server: &str,
) -> ClientSettings {
    let mut yaml = format!("server: \"{server}\"\nkey: \"{TEST_KEY}\"\nlisten: \"{listen}\"\n");
    if !rules.is_empty() {
        yaml.push_str("whitelist:\n");
        for rule in rules {
            yaml.push_str(&format!("  - \"{rule}\"\n"));
        }
    }
    let mut config = ClientConfig::from_yaml(&yaml).expect("test configuration must parse");
    // Keep the state directory inside a temporary location so tests never touch the real one.
    config.state_dir = Some(std::env::temp_dir().join("veilink-tests-state"));
    config.validate().expect("test configuration must validate")
}

/// Builds validated client settings on a free port with the given whitelist rules.
pub fn client_settings(rules: &[&str]) -> ClientSettings {
    client_settings_with_listen(free_listen_addr(), rules, "127.0.0.1:9")
}

/// Client settings with a short connect timeout and small limits, suitable for fast tests.
pub fn client_settings_fast(rules: &[&str]) -> ClientSettings {
    let mut settings = client_settings(rules);
    settings.limits = LimitsConfig {
        connect_timeout_ms: 2_000,
        idle_timeout_ms: 10_000,
        max_connections: 256,
        max_streams_per_session: 256,
        ..LimitsConfig::default()
    };
    settings.log = LogConfig::default();
    settings
}

/// A client runtime running in the background.
pub struct RunningClient {
    /// The address applications should use as their HTTP proxy.
    pub addr: SocketAddr,
    /// Shared runtime context, for hot-reload and statistics assertions.
    pub context: Arc<ClientContext>,
    shutdown: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl RunningClient {
    /// Starts the client runtime.
    pub async fn start(settings: ClientSettings) -> Self {
        let runtime = ClientRuntime::bind(&settings)
            .await
            .expect("the client must bind its listen address");
        let addr = runtime.local_addr().expect("listen address");
        let context = runtime.context();
        let (tx, rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = runtime
                .run(async {
                    let _ = rx.await;
                })
                .await;
        });
        RunningClient {
            addr,
            context,
            shutdown: Some(tx),
            handle,
        }
    }

    /// The proxy URL to hand to `curl -x`.
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Stops the client runtime.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), self.handle).await;
    }
}

/// Formats an IPv4 socket address as `host:port`.
pub fn authority(addr: SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(v4) => format!("{v4}:{}", addr.port()),
        IpAddr::V6(v6) => format!("[{v6}]:{}", addr.port()),
    }
}

/// The loopback address as a `String`.
pub fn loopback() -> String {
    Ipv4Addr::LOCALHOST.to_string()
}

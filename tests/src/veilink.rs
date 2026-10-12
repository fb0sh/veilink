//! Helpers that start real Veilink servers and clients inside a test process.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use veilink_client::uplink::{default_padding, run_uplink, UplinkConfig};
use veilink_client::ClientContext;
use veilink_config::{ClientConfig, ServerConfig, Transport};
use veilink_crypto::Psk;
use veilink_server::runtime::{ServerContext, ServerRuntime};

/// Binds a server, retrying on a fresh port when the probe address was taken by another test in
/// the same binary.
async fn bind_server_with_retry(settings: &veilink_config::ServerSettings) -> ServerRuntime {
    let mut candidate = settings.clone();
    let mut last = None;
    for attempt in 0..16 {
        match ServerRuntime::bind(&candidate).await {
            Ok(runtime) => return runtime,
            Err(error) => {
                last = Some(error);
                if attempt < 15 {
                    candidate.listen = super::settings::free_listen_addr();
                }
            }
        }
    }
    panic!(
        "the server could not bind any of 16 probed ports (last tried {}): {}",
        candidate.listen,
        last.expect("at least one attempt")
    );
}

/// A running Veilink server.
pub struct RunningServer {
    /// The address the server listens on.
    pub addr: SocketAddr,
    /// Shared server context.
    pub context: Arc<ServerContext>,
    /// State directory, kept alive for the lifetime of the server.
    _state: tempfile::TempDir,
    shutdown: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl RunningServer {
    /// Starts a server on a free loopback port.
    ///
    /// `allow_private_targets` is enabled because the test origin lives on `127.0.0.1`; production
    /// defaults deny that.
    pub async fn start(key: &Psk, transport: Transport) -> Self {
        RunningServer::start_with_dns(key, transport, None).await
    }

    /// Starts a server on a specific address, for reconnection tests.
    pub async fn start_at(key: &Psk, transport: Transport, listen: SocketAddr) -> Self {
        RunningServer::start_inner(key, transport, None, Some(listen)).await
    }

    /// Starts a server, optionally using a private DNS resolver.
    pub async fn start_with_dns(
        key: &Psk,
        transport: Transport,
        dns_server: Option<SocketAddr>,
    ) -> Self {
        RunningServer::start_inner(key, transport, dns_server, None).await
    }

    async fn start_inner(
        key: &Psk,
        transport: Transport,
        dns_server: Option<SocketAddr>,
        listen: Option<SocketAddr>,
    ) -> Self {
        let state = tempfile::tempdir().expect("temp dir");
        let listen = listen.unwrap_or_else(super::settings::free_listen_addr);
        let mut yaml = format!(
            "listen: \"{listen}\"\nkey: \"{}\"\ntransport: {}\nallow_private_targets: true\nstate_dir: \"{}\"\n",
            key.to_base64url().as_str(),
            transport,
            state.path().display()
        );
        if let Some(dns) = dns_server {
            yaml.push_str(&format!("dns:\n  servers: [\"{dns}\"]\n"));
        }
        let settings = ServerConfig::from_yaml(&yaml)
            .expect("server yaml")
            .validate()
            .expect("server settings");
        let runtime = bind_server_with_retry(&settings).await;
        let addr = runtime.local_addr().expect("server addr");
        let context = runtime.context();
        let (tx, rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = runtime
                .run(async {
                    let _ = rx.await;
                })
                .await;
        });
        RunningServer {
            addr,
            context,
            _state: state,
            shutdown: Some(tx),
            handle,
        }
    }

    /// Stops the server.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let handle = std::mem::replace(&mut self.handle, tokio::spawn(async {}));
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// A running Veilink client with an active uplink.
pub struct RunningTunnelClient {
    /// The proxy address applications should use.
    pub addr: SocketAddr,
    /// Shared client context.
    pub context: Arc<ClientContext>,
    shutdown: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
    uplink_stop: Option<oneshot::Sender<()>>,
    uplink: tokio::task::JoinHandle<()>,
}

impl RunningTunnelClient {
    /// Starts a client whose uplink points at `server`.
    pub async fn start(
        key: &Psk,
        server: SocketAddr,
        rules: &[&str],
        transport: Transport,
        server_name: &str,
    ) -> Self {
        let listen = super::settings::free_listen_addr();
        let mut yaml = format!(
            "server: \"{server}\"\nkey: \"{}\"\nlisten: \"{listen}\"\ntransport: {transport}\nserver_name: \"{server_name}\"\n",
            key.to_base64url().as_str()
        );
        if !rules.is_empty() {
            yaml.push_str("whitelist:\n");
            for rule in rules {
                yaml.push_str(&format!("  - \"{rule}\"\n"));
            }
        }
        let mut config = ClientConfig::from_yaml(&yaml).expect("client yaml");
        config.state_dir = Some(std::env::temp_dir().join("veilink-e2e-state"));
        let settings = config.validate().expect("client settings");
        RunningTunnelClient::start_with_settings(settings).await
    }

    /// Starts a client from settings that were built by hand.
    pub async fn start_with_settings(mut settings: veilink_config::ClientSettings) -> Self {
        // The probe port may have been taken by another test in this binary; retry on a fresh one.
        let runtime = super::settings::bind_client_with_retry(&settings).await;
        settings.listen = runtime.local_addr().expect("client addr");
        let addr = settings.listen;
        let context = runtime.context();
        let (tx, rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = runtime
                .run(async {
                    let _ = rx.await;
                })
                .await;
        });

        let uplink_config = UplinkConfig::from_settings(&settings);
        let psk = settings.psk.duplicate();
        let padding = default_padding();
        let (uplink_stop, uplink_rx) = oneshot::channel();
        let uplink = tokio::spawn({
            let context = context.clone();
            async move {
                run_uplink(context, psk, uplink_config, padding, async move {
                    let _ = uplink_rx.await;
                })
                .await;
            }
        });

        RunningTunnelClient {
            addr,
            context,
            shutdown: Some(tx),
            handle,
            uplink_stop: Some(uplink_stop),
            uplink,
        }
    }

    /// Waits until the secure session is established.
    pub async fn wait_ready(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self
                .context
                .router
                .load()
                .remote()
                .map(|t| t.is_ready())
                .unwrap_or(false)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the secure session was never established");
    }

    /// Stops the client and its uplink.
    pub async fn stop(mut self) {
        if let Some(tx) = self.uplink_stop.take() {
            let _ = tx.send(());
        }
        let uplink = std::mem::replace(&mut self.uplink, tokio::spawn(async {}));
        let _ = tokio::time::timeout(Duration::from_secs(5), uplink).await;
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let handle = std::mem::replace(&mut self.handle, tokio::spawn(async {}));
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }
}

impl Drop for RunningTunnelClient {
    fn drop(&mut self) {
        if let Some(tx) = self.uplink_stop.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

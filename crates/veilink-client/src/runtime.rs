//! The client runtime: shared context, listener and supervision of the tunnel session.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use veilink_config::{ClientSettings, LimitsConfig};
use veilink_rules::RuleEngine;

use crate::proxy;
use crate::routing::RouteSelection;
use crate::stats::Stats;
use crate::tunnel::{DirectTunnel, Router, Tunnel};

/// Shared state visible to every connection handler.
///
/// The rule set and the router are both hot-swappable, which is what lets a configuration reload
/// change routing for *new* requests without disturbing requests that are already in flight.
pub struct ClientContext {
    /// The active whitelist.
    pub rules: RuleEngine,
    /// The route selector, including the optional remote tunnel.
    pub router: ArcSwap<Router>,
    /// Resource limits.
    pub limits: LimitsConfig,
    /// Whether target domains may be written to the log.
    pub log_domains: bool,
    /// Runtime counters.
    pub stats: Stats,
}

impl ClientContext {
    /// Builds a context with a direct tunnel and no remote tunnel yet.
    pub fn new(settings: &ClientSettings) -> Self {
        let direct = DirectTunnel::new(Duration::from_millis(settings.limits.connect_timeout_ms));
        ClientContext {
            rules: RuleEngine::new(settings.rules.clone()),
            router: ArcSwap::from_pointee(Router::new(direct, None)),
            limits: settings.limits.clone(),
            log_domains: settings.log.log_domains,
            stats: Stats::new(),
        }
    }

    /// Installs or replaces the remote tunnel.
    pub fn set_remote_tunnel(&self, tunnel: Option<Arc<dyn Tunnel>>) {
        let mut router = Router::new(
            DirectTunnel::new(Duration::from_millis(self.limits.connect_timeout_ms)),
            tunnel,
        );
        // Preserve the previously installed tunnel if the new one is `None` and the caller is only
        // refreshing routing.
        if router.remote().is_none() {
            if let Some(existing) = self.router.load().remote() {
                router.set_remote(Some(existing.clone()));
            }
        }
        self.router.store(Arc::new(router));
    }

    /// Replaces the whitelist atomically.
    pub fn set_rules(&self, rules: veilink_rules::RuleSet) {
        self.rules.replace(rules);
    }

    /// Records a routing decision in the counters.
    pub fn count_route(&self, selection: &RouteSelection) {
        match selection {
            RouteSelection::Direct => self.stats.inc(&self.stats.requests_direct),
            RouteSelection::Proxy { .. } => self.stats.inc(&self.stats.requests_proxied),
        }
    }
}

/// The local proxy listener.
pub struct ClientRuntime {
    listener: TcpListener,
    ctx: Arc<ClientContext>,
    max_connections: usize,
}

impl ClientRuntime {
    /// Binds the local proxy listener.
    pub async fn bind(settings: &ClientSettings) -> io::Result<Self> {
        let listener = TcpListener::bind(settings.listen).await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot bind the local proxy to {}: {e}", settings.listen),
            )
        })?;
        Ok(ClientRuntime {
            listener,
            ctx: Arc::new(ClientContext::new(settings)),
            max_connections: settings.limits.max_connections,
        })
    }

    /// The address the listener is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Shared context, for installing a tunnel or triggering a reload.
    pub fn context(&self) -> Arc<ClientContext> {
        self.ctx.clone()
    }

    /// Runs the accept loop until `shutdown` resolves.
    pub async fn run<F>(self, shutdown: F) -> io::Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        let ClientRuntime {
            listener,
            ctx,
            max_connections,
        } = self;
        let permits = Arc::new(Semaphore::new(max_connections.max(1)));
        info!(
            listen = %listener.local_addr()?,
            max_connections,
            "local proxy listening"
        );

        tokio::pin!(shutdown);
        loop {
            let accepted = tokio::select! {
                biased;
                _ = &mut shutdown => {
                    info!("shutdown requested; no longer accepting proxy connections");
                    return Ok(());
                }
                accepted = listener.accept() => accepted,
            };

            let (socket, peer) = match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    // Transient accept errors (EMFILE, ECONNABORTED) must not kill the listener.
                    warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            let permit = match permits.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    debug!(%peer, "connection limit reached; refusing connection");
                    drop(socket);
                    continue;
                }
            };

            let ctx = ctx.clone();
            ctx.stats.inc(&ctx.stats.connections_total);
            ctx.stats.inc(&ctx.stats.connections_active);
            tokio::spawn(async move {
                let outcome = proxy::serve(socket, ctx.clone()).await;
                debug!(?outcome, "connection finished");
                ctx.stats.dec(&ctx.stats.connections_active);
                drop(permit);
            });
        }
    }
}

/// Logs the periodic statistics summary.
pub fn spawn_stats_reporter(
    ctx: Arc<ClientContext>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let snap = ctx.stats.snapshot();
            info!(
                connections_active = snap.connections_active,
                connections_total = snap.connections_total,
                requests_direct = snap.requests_direct,
                requests_proxied = snap.requests_proxied,
                requests_rejected = snap.requests_rejected,
                bytes_up = snap.bytes_up,
                bytes_down = snap.bytes_down,
                frames_sent = snap.frames_sent,
                frames_received = snap.frames_received,
                cover_bytes_sent = snap.cover_bytes_sent,
                session_connects = snap.session_connects,
                "client statistics"
            );
        }
    })
}

/// Logs a fatal runtime error before exiting.
pub fn report_fatal(error: &io::Error) {
    error!(error = %error, "client runtime stopped");
}

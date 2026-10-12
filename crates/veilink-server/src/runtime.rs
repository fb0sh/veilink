//! The server runtime: accept authenticated sessions and relay their streams.
//!
//! One task runs the accept loop; each accepted connection gets a task that performs the TLS
//! handshake and the `VLP/1` handshake and then relays streams until the session ends.
//!
//! Nothing is read from a peer before authentication completes. A failed handshake closes the
//! connection immediately; there is no unauthenticated mode, no fallback, and no diagnostic that
//! would tell an attacker whether the pre-shared key was close.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use veilink_config::{ServerSettings, Transport as TransportKind};
use veilink_crypto::{Identity, Psk};
use veilink_protocol::codec::{BucketedPadding, PaddingPolicy};
use veilink_protocol::session::{start_session, IncomingStream, Role, Session, SessionConfig};
use veilink_protocol::stats::Stats;
use veilink_protocol::OpenStatus;

use crate::egress::{Egress, EgressError};
use crate::policy::EgressPolicy;
use crate::resolver::Resolver;

/// Shared state for the server runtime.
pub struct ServerContext {
    /// Authentication key.
    pub psk: Psk,
    /// Long-term identity, advertised in the handshake.
    pub identity: Arc<Identity>,
    /// Outbound connection engine.
    pub egress: Arc<Egress>,
    /// Session tunables.
    pub session: SessionConfig,
    /// Padding policy. The server uses the same buckets as the client so that both directions of a
    /// session have the same size distribution.
    pub padding: Arc<dyn PaddingPolicy>,
    /// Resource limits.
    pub limits: veilink_config::LimitsConfig,
    /// Whether target host names may be logged.
    pub log_domains: bool,
    /// Counters.
    pub stats: Stats,
}

impl std::fmt::Debug for ServerContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerContext")
            .field("identity", &self.identity.fingerprint_hex())
            .field("policy", self.egress.policy())
            .finish_non_exhaustive()
    }
}

impl ServerContext {
    /// Builds the context from validated settings.
    pub fn new(settings: &ServerSettings) -> Result<Self, ServerError> {
        let identity = Identity::load_or_create(&settings.state_dir)?;
        let resolver = Arc::new(Resolver::new(&settings.dns)?);
        let policy = EgressPolicy::new(
            settings.allow_private_targets,
            settings.allowed_ports.clone(),
        );
        let egress = Arc::new(Egress::new(
            resolver,
            policy,
            Duration::from_millis(settings.limits.connect_timeout_ms),
        ));
        Ok(ServerContext {
            psk: settings.psk.duplicate(),
            identity: Arc::new(identity),
            egress,
            session: SessionConfig {
                max_streams: settings.limits.max_streams_per_session,
                idle_timeout: Duration::from_millis(settings.limits.idle_timeout_ms.max(60_000)),
                ..SessionConfig::default()
            },
            padding: Arc::new(BucketedPadding::new()),
            limits: settings.limits.clone(),
            log_domains: settings.log.log_domains,
            stats: Stats::new(),
        })
    }
}

/// Errors raised while starting the server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The identity could not be loaded or created.
    #[error(transparent)]
    Identity(#[from] veilink_crypto::IdentityError),
    /// The DNS resolver could not be created.
    #[error(transparent)]
    Resolver(#[from] crate::resolver::ResolveError),
    /// The TLS identity could not be loaded or created.
    #[error(transparent)]
    Tls(#[from] veilink_transport::TlsError),
    /// The listen socket could not be bound.
    #[error("cannot bind {address}: {source}")]
    Bind {
        /// The requested address.
        address: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// A per-address connection rate limiter rejected the peer.
    #[error("the connection rate limit was exceeded")]
    RateLimited,
    /// The `VLP/1` handshake failed. The reason is deliberately not carried into the error, since
    /// it is only ever logged at debug level.
    #[error("the session handshake was rejected")]
    Handshake,
}

/// A simple per-remote-address connection rate limiter.
///
/// It exists so that an unauthenticated peer cannot exhaust the connection table by opening TLS
/// handshakes as fast as the network allows.
#[derive(Debug)]
struct RateLimiter {
    limit: u32,
    window: Duration,
    entries: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    fn new(limit: u32, window: Duration) -> Self {
        RateLimiter {
            limit,
            window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Records an attempt and reports whether it is allowed.
    fn allow(&self, address: IpAddr) -> bool {
        if self.limit == 0 {
            return true;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return true;
        };
        let now = Instant::now();
        // Opportunistically drop stale entries so the map cannot grow without bound.
        if entries.len() > 4096 {
            entries.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let entry = entries.entry(address).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 1);
            return true;
        }
        entry.1 += 1;
        entry.1 <= self.limit
    }
}

/// The listening server.
pub struct ServerRuntime {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    ctx: Arc<ServerContext>,
    transport: TransportKind,
    limiter: Arc<RateLimiter>,
    connections: Arc<Semaphore>,
    active: Arc<AtomicU64>,
}

impl ServerRuntime {
    /// Binds the listener and prepares the TLS acceptor.
    pub async fn bind(settings: &ServerSettings) -> Result<Self, ServerError> {
        let ctx = Arc::new(ServerContext::new(settings)?);
        let tls_identity = veilink_transport::ServerTlsIdentity::load_or_create(
            &settings.state_dir,
            &veilink_config::certificate_alt_names(settings.listen),
        )?;
        if tls_identity.created {
            info!(
                fingerprint = %tls_identity.fingerprint,
                "generated a new TLS identity"
            );
        }
        let acceptor = veilink_transport::acceptor(&tls_identity)?;
        let listener =
            TcpListener::bind(settings.listen)
                .await
                .map_err(|source| ServerError::Bind {
                    address: settings.listen,
                    source,
                })?;

        if settings.allow_private_targets {
            warn!(
                "`allow_private_targets` is enabled: the server will connect to loopback, private \
                 and link-local addresses. This is intended for testing only."
            );
        }

        Ok(ServerRuntime {
            listener,
            acceptor,
            ctx,
            transport: settings.transport,
            limiter: Arc::new(RateLimiter::new(
                settings.limits.accept_rate_per_second,
                Duration::from_secs(1),
            )),
            connections: Arc::new(Semaphore::new(settings.limits.max_connections.max(1))),
            active: Arc::new(AtomicU64::new(0)),
        })
    }

    /// The bound address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Shared context.
    pub fn context(&self) -> Arc<ServerContext> {
        self.ctx.clone()
    }

    /// Runs the accept loop until `shutdown` resolves.
    pub async fn run<F>(self, shutdown: F) -> io::Result<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let ServerRuntime {
            listener,
            acceptor,
            ctx,
            transport,
            limiter,
            connections,
            active,
        } = self;

        info!(
            listen = %listener.local_addr()?,
            transport = %transport,
            identity = %ctx.identity.fingerprint_hex(),
            "authentication required: no proxy request is read before the VLP/1 handshake completes"
        );

        let shutting_down = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = shutting_down.clone();
        tokio::spawn(async move {
            shutdown.await;
            flag.store(true, Ordering::Relaxed);
        });
        // Sessions watch this so that a graceful shutdown closes them instead of leaving the peer
        // waiting on a socket that will never be answered.
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut connections_set: JoinSet<()> = JoinSet::new();

        loop {
            // Reap finished connection tasks so the set does not grow without bound.
            while connections_set.try_join_next().is_some() {}

            if shutting_down.load(Ordering::Relaxed) {
                info!("shutdown requested; no longer accepting connections");
                let _ = shutdown_tx.send(true);
                let deadline = Duration::from_secs(5);
                let _ = tokio::time::timeout(deadline, async {
                    while connections_set.join_next().await.is_some() {}
                })
                .await;
                info!("all sessions closed");
                return Ok(());
            }
            let accepted =
                tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
            let (socket, peer) = match accepted {
                Err(_) => continue,
                Ok(Ok(pair)) => pair,
                Ok(Err(error)) => {
                    warn!(error = %error, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            if !limiter.allow(peer.ip()) {
                debug!(%peer, "connection rate limit exceeded");
                ctx.stats.inc(&ctx.stats.connections_rejected);
                drop(socket);
                continue;
            }

            let permit = match connections.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    debug!(%peer, "connection limit reached; refusing connection");
                    ctx.stats.inc(&ctx.stats.connections_rejected);
                    drop(socket);
                    continue;
                }
            };

            let ctx = ctx.clone();
            let acceptor = acceptor.clone();
            let active = active.clone();
            let shutdown_rx = shutdown_rx.clone();
            ctx.stats.inc(&ctx.stats.connections_total);
            ctx.stats.inc(&ctx.stats.connections_active);
            active.fetch_add(1, Ordering::Relaxed);
            connections_set.spawn(async move {
                if let Err(error) =
                    serve_connection(socket, peer, acceptor, ctx.clone(), transport, shutdown_rx)
                        .await
                {
                    debug!(%peer, %error, "connection ended with an error");
                }
                ctx.stats.dec(&ctx.stats.connections_active);
                drop(permit);
            });
        }
    }
}

/// Handles one accepted connection.
async fn serve_connection(
    socket: tokio::net::TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    ctx: Arc<ServerContext>,
    transport: TransportKind,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    // The transport is selected by configuration rather than guessed: the client and the server are
    // operated by the same person, and an ALPN mismatch is reported explicitly instead of being
    // silently downgraded to the other framing.
    let (session, _driver) = match transport {
        TransportKind::Tls => {
            let accepted =
                veilink_transport::accept(socket, &acceptor, Duration::from_secs(15)).await?;
            veilink_transport::tls::log_session(
                "server",
                accepted.alpn.as_deref(),
                &accepted.exporter,
            );
            let session = handshake(accepted.stream, accepted.exporter, &ctx).await?;
            (session, None)
        }
        TransportKind::H2 => {
            let tunnel =
                veilink_transport::http2::accept(socket, &acceptor, Duration::from_secs(15))
                    .await?;
            veilink_transport::tls::log_session(
                "server",
                Some(veilink_transport::ALPN_H2),
                &tunnel.exporter,
            );
            let session = handshake(tunnel.duplex, tunnel.exporter, &ctx).await?;
            let driver = tunnel.driver;
            let watcher = session.clone();
            tokio::spawn(async move {
                watcher.wait_closed().await;
                driver.abort();
            });
            (session, Some(()))
        }
    };

    debug!(%peer, session = format!("{:#x}", session.session_id()), "authenticated session");
    relay_streams(session, ctx, shutdown).await;
    Ok(())
}

async fn handshake<D>(
    duplex: D,
    exporter: [u8; 32],
    ctx: &Arc<ServerContext>,
) -> Result<Session, ServerError>
where
    D: veilink_protocol::duplex::Duplex + 'static,
{
    start_session(
        duplex,
        Role::Server,
        &ctx.psk,
        exporter,
        ctx.identity.public_bytes(),
        ctx.session.clone(),
        ctx.padding.clone(),
    )
    .await
    .map_err(|error| {
        ctx.stats.inc(&ctx.stats.auth_failures);
        // Failed handshakes are expected when someone probes the port; they are logged at debug
        // level with no detail that would help an attacker.
        debug!(error = %error, "session handshake rejected");
        ServerError::Handshake
    })
}

/// Serves streams until the session ends.
async fn relay_streams(
    session: Session,
    ctx: Arc<ServerContext>,
    mut shutdown: watch::Receiver<bool>,
) {
    let Some(mut incoming) = session.incoming_streams() else {
        warn!("session has no stream receiver");
        return;
    };
    if *shutdown.borrow() {
        session.close("server shutting down").await;
        return;
    }
    let mut handlers = Vec::new();
    loop {
        let next = tokio::select! {
            biased;
            _ = session.wait_closed() => {
                debug!("session closed; stopping the relay");
                break;
            }
            _ = shutdown.changed() => {
                info!("server shutting down; closing the session");
                session.close("server shutting down").await;
                break;
            }
            next = incoming.recv() => next,
        };
        let Some(stream) = next else {
            break;
        };
        let session = session.clone();
        let ctx = ctx.clone();
        handlers.push(tokio::spawn(async move {
            serve_stream(session, ctx, stream).await;
        }));
    }

    // Give in-flight streams a moment to finish, then let them be cancelled with the session.
    for handler in handlers {
        let _ = tokio::time::timeout(Duration::from_secs(5), handler).await;
    }
}

/// Opens the outbound connection for one stream and splices it.
async fn serve_stream(session: Session, ctx: Arc<ServerContext>, incoming: IncomingStream) {
    let IncomingStream { stream, host, port } = incoming;
    let stream_id = stream.id();

    ctx.stats.inc(&ctx.stats.streams_total);
    ctx.stats.inc(&ctx.stats.streams_active);

    // Connect first and answer afterwards: `OPEN_RESULT(Ok)` promises the client that the outbound
    // connection exists, and the client's `open_stream` returns on that promise.
    let socket = match ctx.egress.connect(&host, port).await {
        Ok(socket) => socket,
        Err(error) => {
            let (status, detail) = classify(&error);
            if matches!(error, EgressError::Denied(_)) {
                ctx.stats.inc(&ctx.stats.egress_denied);
            }
            debug!(stream_id, %error, "outbound connection refused");
            let _ = session.respond_open(stream_id, status, &detail);
            ctx.stats.dec(&ctx.stats.streams_active);
            return;
        }
    };

    if session.respond_open(stream_id, OpenStatus::Ok, "").is_err() {
        ctx.stats.dec(&ctx.stats.streams_active);
        return;
    }
    if ctx.log_domains {
        info!(stream_id, host = %host, port, "stream opened");
    } else {
        info!(stream_id, port, "stream opened");
    }

    let mut target_side = veilink_protocol::duplex::BufStream::with_limit(socket, 256 * 1024);
    let mut tunnel_side = veilink_protocol::duplex::BufStream::with_limit(
        Box::new(stream) as veilink_protocol::duplex::BoxStream,
        256 * 1024,
    );
    match veilink_protocol::duplex::splice(&mut tunnel_side, &mut target_side).await {
        Ok(outcome) => {
            ctx.stats.add(&ctx.stats.bytes_up, outcome.a_to_b);
            ctx.stats.add(&ctx.stats.bytes_down, outcome.b_to_a);
            info!(
                stream_id,
                uploaded = outcome.a_to_b,
                downloaded = outcome.b_to_a,
                "stream finished"
            );
        }
        Err(error) => {
            debug!(stream_id, %error, "stream ended with an I/O error");
            session.reset_stream(stream_id, 1, &error.to_string());
        }
    }
    ctx.stats.dec(&ctx.stats.streams_active);
}

/// Maps an egress failure onto a protocol status.
fn classify(error: &EgressError) -> (OpenStatus, String) {
    match error {
        EgressError::Denied(deny) => (OpenStatus::PolicyDenied, deny.to_string()),
        EgressError::Resolve(_) => (OpenStatus::ResolveFailed, error.to_string()),
        EgressError::Connect { .. } | EgressError::Unreachable { .. } => {
            (OpenStatus::ConnectFailed, error.to_string())
        }
        EgressError::NoAddress(_) => (OpenStatus::ResolveFailed, error.to_string()),
    }
}

/// Convenience: builds the egress policy from settings without starting a runtime.
pub fn policy_from_settings(settings: &ServerSettings) -> EgressPolicy {
    EgressPolicy::new(
        settings.allow_private_targets,
        settings.allowed_ports.clone(),
    )
}

/// Spawns the periodic statistics reporter.
pub fn spawn_stats_reporter(
    ctx: Arc<ServerContext>,
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
                connections_rejected = snap.connections_rejected,
                streams_active = snap.streams_active,
                streams_total = snap.streams_total,
                dns_queries = snap.dns_queries,
                dns_failures = snap.dns_failures,
                egress_denied = snap.egress_denied,
                auth_failures = snap.auth_failures,
                "server statistics"
            );
        }
    })
}

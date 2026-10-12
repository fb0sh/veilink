//! The client's connection to the server: session establishment, the tunnel, and reconnection.
//!
//! # Fail-closed reconnect
//!
//! The uplink is the only path to the server. While it is down, every whitelisted request fails
//! with a gateway error; nothing is ever rerouted to a direct connection. That is enforced in
//! [`crate::tunnel::Router`], and this module is responsible for the other half of the contract:
//! telling the router *promptly* that the tunnel is gone, so that requests are refused instead of
//! queueing behind a dead session.
//!
//! # Reconnection
//!
//! Reconnection uses exponential backoff with jitter, capped at a maximum delay, and it is reset by
//! a successfully established session. Non-idempotent requests are never replayed: a stream that
//! was open when the session died is failed, not retried, because the client cannot know whether
//! the origin already acted on it.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use veilink_config::Transport as TransportKind;
use veilink_crypto::Psk;
use veilink_privacy::cover::{ActivityClock, CoverEngine, SessionCoverSink};
use veilink_privacy::padding::BudgetedPadding;
use veilink_privacy::scheduler::PrivacyScheduler;
use veilink_protocol::codec::PaddingPolicy;
use veilink_protocol::session::{start_session, Role, Session, SessionConfig};
use veilink_protocol::stats::Stats;

use crate::runtime::ClientContext;
use veilink_protocol::duplex::BoxStream;

use crate::tunnel::{BoxFuture, Tunnel};

/// A [`Tunnel`] backed by an established `VLP/1` session.
pub struct VlpTunnel {
    session: Session,
    stats: Arc<Stats>,
}

impl std::fmt::Debug for VlpTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlpTunnel")
            .field("session_id", &format!("{:#x}", self.session.session_id()))
            .finish()
    }
}

impl VlpTunnel {
    /// Wraps an established session.
    pub fn new(session: Session, stats: Arc<Stats>) -> Self {
        VlpTunnel { session, stats }
    }

    /// The underlying session, for the supervisor.
    pub fn session(&self) -> &Session {
        &self.session
    }
}

impl Tunnel for VlpTunnel {
    fn name(&self) -> &'static str {
        "vlp"
    }

    fn is_ready(&self) -> bool {
        !self.session.is_closed()
    }

    fn open<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = self.session.open_stream(host, port).await.map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("the server refused a stream to {host}:{port}: {e}"),
                )
            })?;
            self.stats.inc(&self.stats.streams_total);
            self.stats.inc(&self.stats.streams_active);
            Ok(Box::new(CountedStream {
                inner: stream,
                stats: self.stats.clone(),
            }) as BoxStream)
        })
    }
}

/// Wraps a tunnel stream so that byte counters and the active-stream gauge stay accurate even when
/// the stream is dropped in the middle of a transfer.
struct CountedStream {
    inner: veilink_protocol::VlpStream,
    stats: Arc<Stats>,
}

impl Drop for CountedStream {
    fn drop(&mut self) {
        self.stats.dec(&self.stats.streams_active);
    }
}

impl tokio::io::AsyncRead for CountedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &result {
            let read = buf.filled().len().saturating_sub(before);
            if read > 0 {
                self.stats.add(&self.stats.bytes_down, read as u64);
            }
        }
        result
    }
}

impl tokio::io::AsyncWrite for CountedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(written)) = &result {
            if *written > 0 {
                self.stats.add(&self.stats.bytes_up, *written as u64);
            }
        }
        result
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// How the uplink should behave.
#[derive(Debug, Clone)]
pub struct UplinkConfig {
    /// Server endpoint.
    pub server: veilink_config::Endpoint,
    /// TLS server name.
    pub server_name: String,
    /// Outer transport.
    pub transport: TransportKind,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Session handshake timeout.
    pub handshake_timeout: Duration,
    /// Session tunables.
    pub session: SessionConfig,
    /// Initial reconnection delay.
    pub reconnect_initial: Duration,
    /// Maximum reconnection delay.
    pub reconnect_max: Duration,
    /// Optional pinned server identity fingerprint. When set, a server presenting any other
    /// identity is refused.
    pub expected_identity: Option<Vec<u8>>,
}

impl UplinkConfig {
    /// Builds an uplink configuration from validated client settings.
    pub fn from_settings(settings: &veilink_config::ClientSettings) -> Self {
        UplinkConfig {
            server: settings.server.clone(),
            server_name: settings.server_name.clone(),
            transport: settings.transport,
            connect_timeout: Duration::from_millis(settings.limits.connect_timeout_ms),
            handshake_timeout: Duration::from_secs(15),
            session: SessionConfig {
                max_streams: settings.limits.max_streams_per_session,
                idle_timeout: Duration::from_millis(settings.limits.idle_timeout_ms.max(60_000)),
                // Strict Privacy: batch outbound frames and pace them with jitter.
                scheduler: Arc::new(PrivacyScheduler::strict()),
                schedule_max_delay: Duration::from_millis(50),
                ..SessionConfig::default()
            },
            reconnect_initial: Duration::from_millis(500),
            reconnect_max: Duration::from_secs(60),
            expected_identity: settings.expected_identity.clone(),
        }
    }
}

/// The outcome of one connection attempt.
#[derive(Debug)]
pub enum UplinkError {
    /// The server address could not be resolved.
    Resolve(String),
    /// The secure transport failed.
    Transport(String),
    /// The protocol handshake failed.
    Handshake(String),
    /// The server's identity did not match the pinned value.
    IdentityMismatch {
        /// The identity the server presented.
        observed: [u8; 32],
    },
    /// The session ended.
    Closed(String),
}

impl std::fmt::Display for UplinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UplinkError::Resolve(m) => write!(f, "cannot resolve the server address: {m}"),
            UplinkError::Transport(m) => write!(f, "secure transport failed: {m}"),
            UplinkError::Handshake(m) => write!(f, "protocol handshake failed: {m}"),
            UplinkError::IdentityMismatch { observed } => write!(
                f,
                "the server presented the identity fingerprint {} ({}), which does not match the \
                 pinned value",
                observed
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                observed[..4]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            ),
            UplinkError::Closed(m) => write!(f, "the session ended: {m}"),
        }
    }
}

impl std::error::Error for UplinkError {}

/// Resolves the server endpoint to socket addresses.
pub async fn resolve_endpoint(
    endpoint: &veilink_config::Endpoint,
    timeout: Duration,
) -> Result<Vec<std::net::SocketAddr>, UplinkError> {
    if let Some(addr) = endpoint.socket_addr() {
        return Ok(vec![addr]);
    }
    let lookup = tokio::time::timeout(timeout, tokio::net::lookup_host(endpoint.authority()))
        .await
        .map_err(|_| UplinkError::Resolve("the lookup timed out".to_string()))?
        .map_err(|e| UplinkError::Resolve(e.to_string()))?;
    let addresses: Vec<std::net::SocketAddr> = lookup.collect();
    if addresses.is_empty() {
        return Err(UplinkError::Resolve(format!(
            "`{}` resolved to no address",
            endpoint.host
        )));
    }
    // Prefer IPv4: the first release has no IPv6 egress, and a server reached over IPv6 would be
    // unable to reach IPv4-only targets in the same way.
    let mut sorted = addresses;
    sorted.sort_by_key(|a| !a.is_ipv4());
    Ok(sorted)
}

/// Establishes one session.
pub async fn connect_once(
    config: &UplinkConfig,
    psk: &Psk,
    padding: Arc<dyn PaddingPolicy>,
    stats: &Stats,
) -> Result<Session, UplinkError> {
    let addresses = resolve_endpoint(&config.server, config.connect_timeout).await?;
    let mut last_error = String::new();
    for address in addresses {
        match connect_to(address, config, psk, padding.clone()).await {
            Ok(session) => {
                stats.inc(&stats.session_established);
                return Ok(session);
            }
            Err(UplinkError::IdentityMismatch { observed }) => {
                // A pinned identity mismatch is not something to retry against another address.
                return Err(UplinkError::IdentityMismatch { observed });
            }
            Err(error) => {
                last_error = error.to_string();
                debug!(%address, %error, "connection attempt failed");
            }
        }
    }
    Err(UplinkError::Transport(last_error))
}

async fn connect_to(
    address: std::net::SocketAddr,
    config: &UplinkConfig,
    psk: &Psk,
    padding: Arc<dyn PaddingPolicy>,
) -> Result<Session, UplinkError> {
    match config.transport {
        TransportKind::Tls => {
            let secure =
                veilink_transport::connect(address, &config.server_name, config.connect_timeout)
                    .await
                    .map_err(|e| UplinkError::Transport(e.to_string()))?;
            veilink_transport::tls::log_session("client", secure.alpn.as_deref(), &secure.exporter);
            let (session, identity) =
                handshake(secure.stream, secure.exporter, psk, config, padding).await?;
            check_identity(config, &identity)?;
            Ok(session)
        }
        TransportKind::H2 => {
            let tunnel = veilink_transport::http2::connect(
                address,
                &config.server_name,
                config.connect_timeout,
            )
            .await
            .map_err(|e| UplinkError::Transport(e.to_string()))?;
            veilink_transport::tls::log_session(
                "client",
                Some(veilink_transport::ALPN_H2),
                &tunnel.exporter,
            );
            let (session, identity) =
                handshake(tunnel.duplex, tunnel.exporter, psk, config, padding).await?;
            check_identity(config, &identity)?;
            // The HTTP/2 driver must outlive the session; keep it in a detached task that ends with
            // the session.
            let driver = tunnel.driver;
            let session_for_watch = session.clone();
            tokio::spawn(async move {
                session_for_watch.wait_closed().await;
                driver.abort();
            });
            Ok(session)
        }
    }
}

/// Runs the `VLP/1` handshake with the transcript-bound exporter.
async fn handshake<D>(
    duplex: D,
    exporter: [u8; 32],
    psk: &Psk,
    config: &UplinkConfig,
    padding: Arc<dyn PaddingPolicy>,
) -> Result<(Session, [u8; 32]), UplinkError>
where
    D: veilink_protocol::duplex::Duplex + 'static,
{
    let session = start_session(
        duplex,
        Role::Client,
        psk,
        exporter,
        [0u8; 32],
        config.session.clone(),
        padding,
    )
    .await
    .map_err(|e| UplinkError::Handshake(e.to_string()))?;
    // The identity is authenticated by the handshake, so the pin check can rely on it.
    let identity = session.server_identity().unwrap_or([0u8; 32]);
    Ok((session, identity))
}

/// Checks the server's advertised identity against the pin.
///
/// The pin is a fingerprint (`SHA-256` of the public key), not the public key itself, so the
/// advertised key is hashed first. Comparing the pin against the raw key would reject every server,
/// including the correct one, which is exactly what an earlier version of this function did.
fn check_identity(config: &UplinkConfig, public_key: &[u8; 32]) -> Result<(), UplinkError> {
    match &config.expected_identity {
        Some(pin) => {
            let fingerprint = veilink_crypto::fingerprint_of(public_key);
            if veilink_crypto::fingerprint_matches_pin(pin, &fingerprint) {
                Ok(())
            } else {
                Err(UplinkError::IdentityMismatch {
                    observed: fingerprint,
                })
            }
        }
        None => Ok(()),
    }
}

/// The reconnection policy.
#[derive(Debug, Clone)]
pub struct Backoff {
    current: Duration,
    initial: Duration,
    maximum: Duration,
}

impl Backoff {
    /// Creates a policy with jitter applied on each step.
    pub fn new(initial: Duration, maximum: Duration) -> Self {
        Backoff {
            current: initial,
            initial,
            maximum,
        }
    }

    /// Resets to the initial delay after a success.
    pub fn reset(&mut self) {
        self.current = self.initial;
    }

    /// Returns the next delay, including jitter, and advances.
    pub fn next_delay(&mut self) -> Duration {
        let base = self.current;
        // Full jitter, so that many clients that lost the same server do not reconnect in lockstep.
        let jitter = veilink_crypto::random_below(base.as_millis().max(2) as u64)
            .map(|v| Duration::from_millis(v / 2))
            .unwrap_or(Duration::ZERO);
        let delay = base / 2 + jitter;
        self.current = (self.current * 2).min(self.maximum);
        delay
    }
}

/// Runs the uplink: connect, install, supervise, reconnect, until `shutdown` resolves.
pub async fn run_uplink<F>(
    ctx: Arc<ClientContext>,
    psk: Psk,
    config: UplinkConfig,
    padding: Arc<dyn PaddingPolicy>,
    shutdown: F,
) where
    F: Future<Output = ()> + Send + 'static,
{
    let stats = ctx.stats.clone();
    let mut backoff = Backoff::new(config.reconnect_initial, config.reconnect_max);
    let mut attempts: u64 = 0;
    // A flag the shutdown watcher sets, so the cooperative checks in the loop share one signal
    // without racing on the future itself.
    let shutting_down = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watcher_flag = shutting_down.clone();
    tokio::spawn(async move {
        shutdown.await;
        watcher_flag.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    loop {
        if shutting_down.load(std::sync::atomic::Ordering::Relaxed) {
            info!("uplink shutting down");
            return;
        }

        attempts += 1;
        stats.inc(&stats.session_connects);
        match connect_once(&config, &psk, padding.clone(), &stats).await {
            Ok(session) => {
                let session_id = session.session_id();
                info!(
                    session_id = format!("{session_id:#x}"),
                    transport = %config.transport,
                    "secure session established"
                );
                info!("privacy mode: strict");
                backoff.reset();
                attempts = 0;
                let tunnel = Arc::new(VlpTunnel::new(session.clone(), stats.clone()));
                ctx.set_remote_tunnel(Some(tunnel as Arc<dyn Tunnel>));

                // Report the session's counters into the client statistics while it lives.
                let reporter = tokio::spawn(session_reporter(session.clone(), stats.clone()));
                // Strict Privacy: authenticated cover traffic while the session is idle.
                let cover = {
                    let engine = Arc::new(CoverEngine::new());
                    let sink = Arc::new(SessionCoverSink::new(
                        session.clone(),
                        Arc::new(ActivityClock::default()),
                    ));
                    // The engine observes the same clock the sink maintains, so "idle" means the
                    // same thing to both.
                    let clock = sink.clock().clone();
                    let session_watch = session.clone();
                    tokio::spawn(async move {
                        engine
                            .run(sink, clock, async move {
                                session_watch.wait_closed().await;
                            })
                            .await;
                    })
                };

                loop {
                    if shutting_down.load(std::sync::atomic::Ordering::Relaxed) {
                        session.close("client shutting down").await;
                        reporter.abort();
                        cover.abort();
                        info!("uplink shutting down");
                        return;
                    }
                    if tokio::time::timeout(Duration::from_millis(200), session.wait_closed())
                        .await
                        .is_ok()
                    {
                        reporter.abort();
                        cover.abort();
                        let reason = session
                            .close_reason()
                            .unwrap_or_else(|| "unknown".to_string());
                        warn!(reason = %reason, "secure session ended");
                        break;
                    }
                }
                // The tunnel is now unusable; the router reports it as not ready, so whitelisted
                // requests fail closed until a new session is established.
                ctx.clear_remote_tunnel();
            }
            Err(error) => {
                stats.inc(&stats.session_failures);
                if attempts == 1 || attempts % 10 == 0 {
                    warn!(attempt = attempts, %error, "cannot establish a secure session");
                } else {
                    debug!(attempt = attempts, %error, "cannot establish a secure session");
                }
            }
        }

        let delay = backoff.next_delay();
        debug!(delay_ms = delay.as_millis(), "waiting before reconnecting");
        tokio::time::sleep(delay).await;
    }
}

/// Periodically folds a session's counters into the client statistics.
async fn session_reporter(session: Session, stats: Arc<Stats>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut previous = SessionCounters::default();
    loop {
        ticker.tick().await;
        if session.is_closed() {
            return;
        }
        let current = SessionCounters::from(&session.stats());
        stats.add(
            &stats.frames_sent,
            current.frames_sent - previous.frames_sent,
        );
        stats.add(
            &stats.frames_received,
            current.frames_received - previous.frames_received,
        );
        stats.add(
            &stats.frames_rejected,
            current.frames_rejected - previous.frames_rejected,
        );
        stats.add(
            &stats.cover_frames_sent,
            current.cover_sent - previous.cover_sent,
        );
        stats.add(
            &stats.cover_bytes_sent,
            current.cover_bytes - previous.cover_bytes,
        );
        stats.add(
            &stats.streams_total,
            current.streams_opened - previous.streams_opened,
        );
        stats.add(
            &stats.auth_failures,
            current.frames_rejected - previous.frames_rejected,
        );
        previous = current;
    }
}

#[derive(Default, Clone, Copy)]
struct SessionCounters {
    frames_sent: u64,
    frames_received: u64,
    frames_rejected: u64,
    streams_opened: u64,
    cover_sent: u64,
    cover_bytes: u64,
}

impl From<&veilink_protocol::SessionStatsSnapshot> for SessionCounters {
    fn from(value: &veilink_protocol::SessionStatsSnapshot) -> Self {
        SessionCounters {
            frames_sent: value.frames_sent,
            frames_received: value.frames_received,
            frames_rejected: value.frames_rejected,
            streams_opened: value.streams_opened,
            cover_sent: value.cover_sent,
            cover_bytes: value.cover_bytes,
        }
    }
}

/// The default padding policy used by the client.
///
/// Padding is bucketed and bounded by the shared resource budget, so a large transfer cannot spend
/// unbounded bandwidth on padding.
pub fn default_padding() -> Arc<dyn PaddingPolicy> {
    Arc::new(BudgetedPadding::with_default_budget())
}
